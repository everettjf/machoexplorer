//! PowerPC instructions as the sweep sees them: direct branches and calls
//! only. Registers are not followed (addresses are built with `lis` /
//! `addi` pairs and position-independent `bcl` sequences, which the sweep
//! does not model), so there are no data references and no indirect branch
//! targets for these slices.

use super::{Flow, Groups, Step, Target};
use capstone::arch::ppc::{PpcInsn, PpcOperand};
use capstone::arch::{ArchDetail, DetailsArchInsn};
use capstone::{Insn, InsnDetail};

pub(super) fn step(insn: &Insn<'_>, detail: &InsnDetail<'_>) -> Step {
    let mut step = Step::default();
    let ArchDetail::PpcDetail(arch) = detail.arch_detail() else {
        return step;
    };
    let id = insn.id().0;
    let is = |i: PpcInsn| id == i as u32;
    let groups = Groups::of(detail);
    let call = groups.call || is(PpcInsn::PPC_INS_BL) || is(PpcInsn::PPC_INS_BLA);
    let plain = is(PpcInsn::PPC_INS_B) || is(PpcInsn::PPC_INS_BA);
    if !(call || plain || groups.jump) {
        return step;
    }
    // The label is the last operand; `blr`, `bctr` and the like have none.
    let Some(PpcOperand::Imm(target)) = arch.operands().last() else {
        return step;
    };
    step.flow = if call {
        Flow::Call
    } else {
        Flow::Jump {
            conditional: !plain,
        }
    };
    step.target = Target::Address(target as u64);
    step
}
