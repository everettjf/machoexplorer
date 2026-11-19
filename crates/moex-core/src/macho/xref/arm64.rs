//! AArch64 instructions as the sweep sees them.

use super::{bit, Cond, Def, Flow, Groups, Mem, MemUse, Reg, RegSet, Step, Target};
use capstone::arch::arm64::{
    Arm64CC, Arm64Extender, Arm64Insn, Arm64Operand, Arm64OperandType, Arm64Reg, Arm64Shift,
};
use capstone::arch::{ArchDetail, DetailsArchInsn};
use capstone::{Insn, InsnDetail, RegId};

/// The general register behind a Capstone register and whether it is the
/// 32-bit form. `sp` and the zero register are not tracked.
fn gpr(reg: RegId) -> Option<(Reg, bool)> {
    let id = reg.0 as u32;
    if (Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X28).contains(&id) {
        Some(((id - Arm64Reg::ARM64_REG_X0) as Reg, false))
    } else if (Arm64Reg::ARM64_REG_W0..=Arm64Reg::ARM64_REG_W30).contains(&id) {
        Some(((id - Arm64Reg::ARM64_REG_W0) as Reg, true))
    } else if id == Arm64Reg::ARM64_REG_X29 {
        Some((29, false))
    } else if id == Arm64Reg::ARM64_REG_X30 {
        Some((30, false))
    } else {
        None
    }
}

/// The immediate of an operand with its `lsl` applied.
fn shifted(op: &Arm64Operand) -> Option<u64> {
    let Arm64OperandType::Imm(imm) = op.op_type else {
        return None;
    };
    match op.shift {
        Arm64Shift::Invalid => Some(imm as u64),
        Arm64Shift::Lsl(n) => (imm as u64).checked_shl(n),
        _ => None,
    }
}

/// Size in bytes and signedness of what a load instruction reads into a
/// general register of the given width.
fn load_size(id: u32, narrow: bool) -> Option<(u8, bool)> {
    use Arm64Insn::*;
    const LOADS: [(Arm64Insn, u8, bool); 12] = [
        (ARM64_INS_LDR, 0, false),
        (ARM64_INS_LDUR, 0, false),
        (ARM64_INS_LDRB, 1, false),
        (ARM64_INS_LDURB, 1, false),
        (ARM64_INS_LDRH, 2, false),
        (ARM64_INS_LDURH, 2, false),
        (ARM64_INS_LDRSB, 1, true),
        (ARM64_INS_LDURSB, 1, true),
        (ARM64_INS_LDRSH, 2, true),
        (ARM64_INS_LDURSH, 2, true),
        (ARM64_INS_LDRSW, 4, true),
        (ARM64_INS_LDURSW, 4, true),
    ];
    let (_, size, signed) = LOADS.iter().find(|l| l.0 as u32 == id)?;
    Some(match size {
        // The register decides.
        0 => (if narrow { 4 } else { 8 }, false),
        n => (*n, *signed),
    })
}

/// The unsigned comparison a condition code tests.
fn unsigned(cc: Arm64CC) -> Option<Cond> {
    match cc {
        Arm64CC::ARM64_CC_HI => Some(Cond::Above),
        Arm64CC::ARM64_CC_LS => Some(Cond::NotAbove),
        Arm64CC::ARM64_CC_HS => Some(Cond::NotBelow),
        Arm64CC::ARM64_CC_LO => Some(Cond::Below),
        _ => None,
    }
}

pub(super) fn step(insn: &Insn<'_>, detail: &InsnDetail<'_>) -> Step {
    let mut step = Step::default();
    let ArchDetail::Arm64Detail(arch) = detail.arch_detail() else {
        return step;
    };
    let id = insn.id().0;
    let is = |i: Arm64Insn| id == i as u32;
    // The crate turns the system register of `mrs`/`msr` into an enum that
    // does not list every register, which is undefined behaviour for the
    // others (a panic in debug builds). Their operands are never looked
    // at; whatever they write is unknown afterwards.
    if is(Arm64Insn::ARM64_INS_MRS) || is(Arm64Insn::ARM64_INS_MSR) {
        step.writes = RegSet::MAX;
        step.flags = true;
        return step;
    }
    step.flags = arch.update_flags()
        || detail
            .regs_write()
            .iter()
            .any(|reg| reg.0 as u32 == Arm64Reg::ARM64_REG_NZCV);
    let ops: Vec<Arm64Operand> = arch.operands().collect();
    let reg_at = |i: usize| match ops.get(i).map(|op| &op.op_type) {
        Some(Arm64OperandType::Reg(r)) => gpr(*r),
        _ => None,
    };
    let imm_at = |i: usize| match ops.get(i).map(|op| &op.op_type) {
        Some(Arm64OperandType::Imm(v)) => Some(*v as u64),
        _ => None,
    };

    // The memory operand: `[base, #disp]`, or a literal's address.
    // `indexed`: `[base, index, lsl #shift]` instead.
    let mut stores = false;
    let mut indexed: Option<(Reg, Reg, u32)> = None;
    for op in &ops {
        if let Arm64OperandType::Mem(mem) = &op.op_type {
            let writable = op.access.is_some_and(|a| a.is_writable());
            stores |= writable;
            if mem.index().0 != 0 {
                // The index as it is, or the zero-extended 32-bit form.
                let shift = match op.shift {
                    Arm64Shift::Invalid => Some(0),
                    Arm64Shift::Lsl(n) => Some(n),
                    _ => None,
                };
                let index = match (gpr(mem.index()), op.ext) {
                    (Some((index, false)), Arm64Extender::ARM64_EXT_INVALID) => Some(index),
                    (Some((index, true)), Arm64Extender::ARM64_EXT_UXTW) => Some(index),
                    _ => None,
                };
                if let (Some((base, false)), Some(index), Some(shift), 0) =
                    (gpr(mem.base()), index, shift, mem.disp())
                {
                    indexed = Some((base, index, shift));
                }
            } else {
                if let Some((base, false)) = gpr(mem.base()) {
                    let usage = if writable {
                        MemUse::Store
                    } else {
                        MemUse::Load
                    };
                    step.mem = Some((
                        Mem {
                            base: Some(base),
                            offset: mem.disp() as i64 as u64,
                        },
                        usage,
                    ));
                }
            }
            break;
        }
    }

    let groups = Groups::of(detail);
    let compare_branch = is(Arm64Insn::ARM64_INS_CBZ)
        || is(Arm64Insn::ARM64_INS_CBNZ)
        || is(Arm64Insn::ARM64_INS_TBZ)
        || is(Arm64Insn::ARM64_INS_TBNZ);
    step.flow = if groups.call {
        Flow::Call
    } else if groups.jump {
        let unconditional = matches!(
            arch.cc(),
            Arm64CC::ARM64_CC_INVALID | Arm64CC::ARM64_CC_AL | Arm64CC::ARM64_CC_NV
        );
        Flow::Jump {
            conditional: compare_branch || !unconditional,
        }
    } else if groups.ret {
        Flow::Return
    } else {
        Flow::None
    };

    // Capstone's list of written registers, plus what it is known to miss:
    // operands it has no access information for (LSE atomics) and the
    // destination of flag-setting arithmetic, which it reports as read.
    // The first operand is the destination of everything that is neither a
    // store nor a branch.
    for reg in detail.regs_write() {
        if let Some((r, _)) = gpr(*reg) {
            step.writes |= bit(r);
        }
    }
    for (i, op) in ops.iter().enumerate() {
        if let Arm64OperandType::Reg(r) = op.op_type {
            let assume_written = op.access.is_none()
                || op.access.is_some_and(|a| a.is_writable())
                || (i == 0 && !stores && step.flow == Flow::None);
            if let (true, Some((r, _))) = (assume_written, gpr(r)) {
                step.writes |= bit(r);
            }
        }
    }

    // Comparisons only set flags; Capstone lists their first operand as
    // written because they are aliases of `subs`/`adds`/`ands` into xzr.
    if [
        Arm64Insn::ARM64_INS_CMP,
        Arm64Insn::ARM64_INS_CMN,
        Arm64Insn::ARM64_INS_TST,
        Arm64Insn::ARM64_INS_CCMP,
        Arm64Insn::ARM64_INS_CCMN,
    ]
    .into_iter()
    .any(is)
    {
        step.writes = 0;
        step.flags = true;
        if let (true, 2, Some((reg, _)), Some(imm)) = (
            is(Arm64Insn::ARM64_INS_CMP),
            ops.len(),
            reg_at(0),
            ops.get(1).and_then(shifted),
        ) {
            step.compare = Some((reg, imm));
        }
        return step;
    }

    if step.flow != Flow::None {
        // The label is the last operand (`tbz w0, #3, label`); an indirect
        // branch names its register first (`braa x16, x17`).
        step.target = match (ops.last().map(|op| &op.op_type), reg_at(0)) {
            (Some(Arm64OperandType::Imm(target)), _) => Target::Address(*target as u64),
            (_, Some((reg, false))) if ops.len() <= 2 => Target::Reg(reg),
            _ => Target::None,
        };
        step.mem = None;
        // `b.hi` and the like; `cbz` and `tbz` do not look at the flags.
        if !compare_branch {
            step.cond = unsigned(arch.cc());
        }
        return step;
    }

    let Some((dst, narrow)) = reg_at(0) else {
        return step;
    };
    step.dst = Some(dst);
    step.narrow = narrow;
    step.def = if is(Arm64Insn::ARM64_INS_ADRP) {
        imm_at(1).map_or(Def::None, Def::Page)
    } else if is(Arm64Insn::ARM64_INS_ADR) {
        imm_at(1).map_or(Def::None, Def::Address)
    } else if is(Arm64Insn::ARM64_INS_ADD) || is(Arm64Insn::ARM64_INS_SUB) {
        // `add x10, x10, x11, lsl #2`: the second register as it is or
        // shifted left.
        let shifted_reg = ops.get(2).and_then(|op| {
            let shift = match (op.shift, op.ext) {
                (Arm64Shift::Invalid, Arm64Extender::ARM64_EXT_INVALID) => 0,
                (Arm64Shift::Lsl(n), Arm64Extender::ARM64_EXT_INVALID) if n < 8 => n as u8,
                _ => return None,
            };
            match op.op_type {
                Arm64OperandType::Reg(r) => match gpr(r) {
                    Some((reg, false)) => Some((reg, shift)),
                    _ => None,
                },
                _ => None,
            }
        });
        match (ops.len(), reg_at(1), ops.get(2).and_then(shifted)) {
            (3, Some((src, _)), Some(imm)) => Def::Add {
                src,
                imm: if is(Arm64Insn::ARM64_INS_SUB) {
                    imm.wrapping_neg()
                } else {
                    imm
                },
            },
            (3, Some((a, false)), None) if !narrow && is(Arm64Insn::ARM64_INS_ADD) => {
                match shifted_reg {
                    Some((b, shift)) => Def::AddReg { a, b, shift },
                    None => Def::None,
                }
            }
            _ => Def::None,
        }
    } else if is(Arm64Insn::ARM64_INS_CSEL) || is(Arm64Insn::ARM64_INS_CSNEG) {
        // `csel x16, x16, xzr, ls`: the register when it is in range,
        // otherwise zero. `csneg` gives minus zero.
        let zero = matches!(
            ops.get(2).map(|op| &op.op_type),
            Some(Arm64OperandType::Reg(r))
                if [Arm64Reg::ARM64_REG_XZR, Arm64Reg::ARM64_REG_WZR].contains(&(r.0 as u32))
        );
        step.cond = match arch.cc() {
            Arm64CC::ARM64_CC_LS => Some(Cond::NotAbove),
            Arm64CC::ARM64_CC_LO => Some(Cond::Below),
            _ => None,
        };
        match (ops.len(), reg_at(1), zero && step.cond.is_some()) {
            (3, Some((src, _)), true) => Def::Clamp { src },
            _ => {
                step.cond = None;
                Def::None
            }
        }
    } else if is(Arm64Insn::ARM64_INS_MOV) || is(Arm64Insn::ARM64_INS_MOVZ) {
        // `mov` with an immediate is the alias of movz/movn/orr and comes
        // with the final value.
        match (ops.len(), reg_at(1), ops.get(1).and_then(shifted)) {
            (2, Some((src, _)), _) => Def::Copy { src },
            (2, None, Some(imm)) => Def::Const(imm),
            _ => Def::None,
        }
    } else if is(Arm64Insn::ARM64_INS_MOVN) {
        match (ops.len(), ops.get(1).and_then(shifted)) {
            (2, Some(imm)) => Def::Const(!imm),
            _ => Def::None,
        }
    } else if is(Arm64Insn::ARM64_INS_MOVK) {
        match (ops.len(), ops.get(1)) {
            (2, Some(op)) => match (&op.op_type, op.shift) {
                (Arm64OperandType::Imm(imm), Arm64Shift::Lsl(shift)) => Def::MovK {
                    imm16: *imm as u64,
                    shift,
                },
                (Arm64OperandType::Imm(imm), Arm64Shift::Invalid) => Def::MovK {
                    imm16: *imm as u64,
                    shift: 0,
                },
                _ => Def::None,
            },
            _ => Def::None,
        }
    } else if let Some((size, signed)) = load_size(id, narrow) {
        // `ldr x0, label` reads the literal at the label.
        if let (2, Some(literal)) = (ops.len(), imm_at(1)) {
            step.mem = Some((
                Mem {
                    base: None,
                    offset: literal,
                },
                MemUse::Load,
            ));
        }
        // A sign-extending load fills the whole register.
        step.narrow = narrow && !signed;
        match indexed {
            _ if step.mem.is_some() => Def::Load { size, signed },
            // An entry of a table of such values.
            Some((base, index, shift)) if 1u32.checked_shl(shift) == Some(u32::from(size)) => {
                Def::LoadIndex {
                    base,
                    index,
                    size,
                    signed,
                }
            }
            _ => Def::None,
        }
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
        assert_eq!(r(Arm64Reg::ARM64_REG_X0), Some((0, false)));
        assert_eq!(r(Arm64Reg::ARM64_REG_W0), Some((0, true)));
        assert_eq!(r(Arm64Reg::ARM64_REG_X28), Some((28, false)));
        assert_eq!(r(Arm64Reg::ARM64_REG_W30), Some((30, true)));
        assert_eq!(r(Arm64Reg::ARM64_REG_X29), Some((29, false)));
        assert_eq!(r(Arm64Reg::ARM64_REG_X30), Some((30, false)));
        assert_eq!(r(Arm64Reg::ARM64_REG_SP), None);
        assert_eq!(r(Arm64Reg::ARM64_REG_XZR), None);
        assert_eq!(r(Arm64Reg::ARM64_REG_WZR), None);
        assert_eq!(r(Arm64Reg::ARM64_REG_D0), None);
    }

    #[test]
    fn load_sizes() {
        let l = |i: Arm64Insn, narrow| load_size(i as u32, narrow);
        assert_eq!(l(Arm64Insn::ARM64_INS_LDR, false), Some((8, false)));
        assert_eq!(l(Arm64Insn::ARM64_INS_LDUR, true), Some((4, false)));
        assert_eq!(l(Arm64Insn::ARM64_INS_LDRB, true), Some((1, false)));
        assert_eq!(l(Arm64Insn::ARM64_INS_LDRSH, false), Some((2, true)));
        assert_eq!(l(Arm64Insn::ARM64_INS_LDRSW, false), Some((4, true)));
        assert_eq!(l(Arm64Insn::ARM64_INS_LDP, false), None);
    }
}
