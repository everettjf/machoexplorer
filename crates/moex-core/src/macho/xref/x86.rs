//! x86 and x86-64 instructions as the sweep sees them.

use super::{bit, Cond, Def, Flow, Groups, Mem, MemUse, Reg, Step, Target};
use capstone::arch::x86::{X86Insn, X86OpMem, X86Operand, X86OperandType, X86Reg};
use capstone::arch::{ArchDetail, DetailsArchInsn};
use capstone::{Insn, InsnDetail, RegId};
use std::sync::OnceLock;

/// The forms of each general register, in machine encoding order:
/// 64-bit, 32-bit, 16-bit, low byte, high byte (0: none).
const FAMILIES: [[u32; 5]; 16] = {
    use X86Reg::*;
    [
        [X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AL, X86_REG_AH],
        [X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CL, X86_REG_CH],
        [X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DL, X86_REG_DH],
        [X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BL, X86_REG_BH],
        [X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL, 0],
        [X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL, 0],
        [X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL, 0],
        [X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL, 0],
        [X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B, 0],
        [X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B, 0],
        [X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B, 0],
        [X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B, 0],
        [X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B, 0],
        [X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B, 0],
        [X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B, 0],
        [X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B, 0],
    ]
};

/// Width of a register form in bytes.
const WIDTHS: [u8; 5] = [8, 4, 2, 1, 1];

/// The stack pointer is never an address the sweep cares about.
const STACK_POINTER: Reg = 4;

/// The general register behind a Capstone register and the width of that
/// form in bytes.
fn gpr(reg: RegId) -> Option<(Reg, u8)> {
    static TABLE: OnceLock<Vec<Option<(Reg, u8)>>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = vec![None; X86Reg::X86_REG_ENDING as usize];
        for (number, family) in FAMILIES.iter().enumerate() {
            for (id, width) in family.iter().zip(WIDTHS) {
                if let Some(slot) = table.get_mut(*id as usize).filter(|_| *id != 0) {
                    *slot = Some((number as Reg, width));
                }
            }
        }
        table
    });
    table
        .get(reg.0 as usize)
        .copied()
        .flatten()
        .filter(|(number, _)| *number != STACK_POINTER)
}

/// A memory operand whose address depends on at most one register.
fn memory(mem: &X86OpMem, next: u64) -> Option<Mem> {
    if mem.segment().0 != 0 || mem.index().0 != 0 {
        return None;
    }
    let base = mem.base().0 as u32;
    let disp = mem.disp() as u64;
    if base == X86Reg::X86_REG_RIP || base == X86Reg::X86_REG_EIP {
        Some(Mem {
            base: None,
            offset: next.wrapping_add(disp),
        })
    } else if base == 0 {
        Some(Mem {
            base: None,
            offset: disp,
        })
    } else {
        match gpr(mem.base()) {
            Some((reg, 4 | 8)) => Some(Mem {
                base: Some(reg),
                offset: disp,
            }),
            _ => None,
        }
    }
}

pub(super) fn step(insn: &Insn<'_>, detail: &InsnDetail<'_>) -> Step {
    let mut step = Step::default();
    let ArchDetail::X86Detail(arch) = detail.arch_detail() else {
        return step;
    };
    let ops: Vec<X86Operand> = arch.operands().collect();
    let id = insn.id().0;
    let is = |i: X86Insn| id == i as u32;
    let next = insn.address().wrapping_add(insn.len() as u64);
    let reg_at = |i: usize| match ops.get(i).map(|op| &op.op_type) {
        Some(X86OperandType::Reg(r)) => gpr(*r),
        _ => None,
    };
    let imm_at = |i: usize| match ops.get(i).map(|op| &op.op_type) {
        Some(X86OperandType::Imm(v)) => Some(*v as u64),
        _ => None,
    };

    for reg in detail.regs_write() {
        if let Some((r, _)) = gpr(*reg) {
            step.writes |= bit(r);
        }
        step.flags |= reg.0 as u32 == X86Reg::X86_REG_EFLAGS;
    }
    // `cmp eax, 5`
    if let (true, 2, Some((reg, 4 | 8)), Some(imm)) =
        (is(X86Insn::X86_INS_CMP), ops.len(), reg_at(0), imm_at(1))
    {
        step.compare = Some((reg, imm));
        step.flags = true;
        return step;
    }
    for op in &ops {
        if let (X86OperandType::Reg(r), true) =
            (&op.op_type, op.access.is_some_and(|a| a.is_writable()))
        {
            if let Some((r, _)) = gpr(*r) {
                step.writes |= bit(r);
            }
        }
    }

    // The memory operand. `lea` only computes its address and the
    // multi-byte `nop` does not touch it.
    let lea = is(X86Insn::X86_INS_LEA);
    if !is(X86Insn::X86_INS_NOP) {
        for op in &ops {
            if let X86OperandType::Mem(mem) = &op.op_type {
                let usage = if lea {
                    MemUse::Address
                } else if op.access.is_some_and(|a| a.is_writable()) {
                    MemUse::Store
                } else {
                    MemUse::Load
                };
                step.mem = memory(mem, next).map(|m| (m, usage));
                break;
            }
        }
    }

    // `loop*` are jumps although Capstone leaves them out of the group.
    let groups = Groups::of(detail);
    let loops =
        is(X86Insn::X86_INS_LOOP) || is(X86Insn::X86_INS_LOOPE) || is(X86Insn::X86_INS_LOOPNE);
    step.flow = if groups.call {
        Flow::Call
    } else if groups.jump || loops {
        Flow::Jump {
            conditional: !(is(X86Insn::X86_INS_JMP) || is(X86Insn::X86_INS_LJMP)),
        }
    } else if groups.ret {
        Flow::Return
    } else {
        Flow::None
    };
    if step.flow != Flow::None {
        step.target = match ops.first().map(|op| &op.op_type) {
            // `ljmp seg:off` has two immediates and no address here.
            Some(X86OperandType::Imm(target)) if ops.len() == 1 => Target::Address(*target as u64),
            Some(X86OperandType::Reg(r)) => match gpr(*r) {
                Some((reg, 4 | 8)) => Target::Reg(reg),
                _ => Target::None,
            },
            Some(X86OperandType::Mem(_)) if step.mem.is_some() => Target::Mem,
            _ => Target::None,
        };
        step.cond = if is(X86Insn::X86_INS_JA) {
            Some(Cond::Above)
        } else if is(X86Insn::X86_INS_JBE) {
            Some(Cond::NotAbove)
        } else if is(X86Insn::X86_INS_JAE) {
            Some(Cond::NotBelow)
        } else if is(X86Insn::X86_INS_JB) {
            Some(Cond::Below)
        } else {
            None
        };
        return step;
    }

    // Only whole (64-bit) and zero-extending (32-bit) writes are followed.
    let Some((dst, width @ (4 | 8))) = reg_at(0) else {
        return step;
    };
    step.dst = Some(dst);
    step.narrow = width == 4;
    step.def = if lea {
        if step.mem.is_some() {
            Def::Lea
        } else {
            Def::None
        }
    } else if is(X86Insn::X86_INS_MOV) || is(X86Insn::X86_INS_MOVABS) {
        match (ops.len(), ops.get(1).map(|op| &op.op_type)) {
            (2, Some(X86OperandType::Imm(imm))) => Def::Const(*imm as u64),
            (2, Some(X86OperandType::Reg(src))) => match gpr(*src) {
                Some((src, 4 | 8)) => Def::Copy { src },
                _ => Def::None,
            },
            (2, Some(X86OperandType::Mem(_))) if step.mem.is_some() => Def::Load {
                size: width,
                signed: false,
            },
            _ => Def::None,
        }
    } else if is(X86Insn::X86_INS_ADD) || is(X86Insn::X86_INS_SUB) {
        match (ops.len(), imm_at(1), reg_at(1)) {
            (2, Some(imm), _) => Def::Add {
                src: dst,
                imm: if is(X86Insn::X86_INS_SUB) {
                    imm.wrapping_neg()
                } else {
                    imm
                },
            },
            // `add rax, rcx`
            (2, None, Some((src, 8))) if width == 8 && is(X86Insn::X86_INS_ADD) => Def::AddReg {
                a: dst,
                b: src,
                shift: 0,
            },
            _ => Def::None,
        }
    } else if is(X86Insn::X86_INS_MOVSXD) {
        // `movsxd rax, dword ptr [rcx + rax*4]`: an entry of a table of
        // 32-bit values.
        match ops.get(1).map(|op| &op.op_type) {
            Some(X86OperandType::Mem(mem))
                if width == 8 && mem.segment().0 == 0 && mem.scale() == 4 && mem.disp() == 0 =>
            {
                match (gpr(mem.base()), gpr(mem.index())) {
                    (Some((base, 8)), Some((index, 8))) => Def::LoadIndex {
                        base,
                        index,
                        size: 4,
                        signed: true,
                    },
                    _ => Def::None,
                }
            }
            _ => Def::None,
        }
    } else if is(X86Insn::X86_INS_POP) {
        Def::Pop
    } else {
        Def::None
    };
    step
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers() {
        let r = |id: u32| gpr(RegId(id as capstone::RegIdInt));
        assert_eq!(r(X86Reg::X86_REG_RAX), Some((0, 8)));
        assert_eq!(r(X86Reg::X86_REG_EAX), Some((0, 4)));
        assert_eq!(r(X86Reg::X86_REG_AX), Some((0, 2)));
        assert_eq!(r(X86Reg::X86_REG_AH), Some((0, 1)));
        assert_eq!(r(X86Reg::X86_REG_BL), Some((3, 1)));
        assert_eq!(r(X86Reg::X86_REG_EDI), Some((7, 4)));
        assert_eq!(r(X86Reg::X86_REG_R8D), Some((8, 4)));
        assert_eq!(r(X86Reg::X86_REG_R15), Some((15, 8)));
        assert_eq!(r(X86Reg::X86_REG_RSP), None);
        assert_eq!(r(X86Reg::X86_REG_ESP), None);
        assert_eq!(r(X86Reg::X86_REG_RIP), None);
        assert_eq!(r(X86Reg::X86_REG_XMM0), None);
        assert_eq!(r(X86Reg::X86_REG_INVALID), None);
        assert_eq!(r(X86Reg::X86_REG_ENDING + 5), None);
    }
}
