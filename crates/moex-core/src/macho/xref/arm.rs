//! 32-bit ARM and Thumb instructions as the sweep sees them: direct
//! branches and calls only. Registers are not followed (addresses are
//! built with `movw`/`movt` or literal pools plus `add pc`, which the
//! sweep does not model), so there are no data references and no indirect
//! branch targets for these slices.

use super::{Flow, Step, Target};
use capstone::arch::arm::{ArmCC, ArmInsn, ArmOperandType};
use capstone::arch::{ArchDetail, DetailsArchInsn};
use capstone::{Insn, InsnDetail};

pub(super) fn step(insn: &Insn<'_>, detail: &InsnDetail<'_>) -> Step {
    let mut step = Step::default();
    let ArchDetail::ArmDetail(arch) = detail.arch_detail() else {
        return step;
    };
    let id = insn.id().0;
    let is = |i: ArmInsn| id == i as u32;
    let compare_branch = is(ArmInsn::ARM_INS_CBZ) || is(ArmInsn::ARM_INS_CBNZ);
    let call = is(ArmInsn::ARM_INS_BL) || is(ArmInsn::ARM_INS_BLX);
    if !(call || compare_branch || is(ArmInsn::ARM_INS_B)) {
        return step;
    }
    // The label is the last operand; `blx r3` has none.
    let Some(ArmOperandType::Imm(target)) = arch.operands().last().map(|op| op.op_type) else {
        return step;
    };
    step.flow = if call {
        Flow::Call
    } else {
        Flow::Jump {
            conditional: compare_branch
                || !matches!(arch.cc(), ArmCC::ARM_CC_AL | ArmCC::ARM_CC_INVALID),
        }
    };
    step.target = Target::Address(target as u32 as u64);
    step
}
