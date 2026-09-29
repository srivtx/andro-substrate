//! Array construction: `new-array`, `filled-new-array` and `fill-array-data`.
//!
//! # `filled-new-array` is a call
//!
//! It is easy to read as an array operation and it is not: it takes its elements
//! out of the register file, stores them, and leaves a reference behind which the
//! following `move-result-object` normally re-reads. That is the same shape as a
//! call, and the same arity problem — the packed form's trailing zero nibbles are
//! indistinguishable from trailing `v0` arguments, so the prototype is again the
//! only authority. See [`crate::lower::invoke`] for the full argument.
//!
//! # `fill-array-data` reads a payload
//!
//! The 32-bit branch offset names a `fill-array-data-payload` in the same
//! instruction stream. The IR keeps that as a [`Label`] pointing at the payload
//! and puts the bytes in an [`IrOp::Payload`] elsewhere in the body;
//! `Function::new` checks that the label lands on a payload and that nothing else
//! does. That check is what stops a linear sweep's "the widths still add up" from
//! being mistaken for a correctness argument: a branch into the middle of a
//! payload decodes cleanly and runs nothing.

use dexcore::insn::Instruction;

use crate::ir::{Inst, IrOp, Label, ObjectReg, Origin, Reg};

use super::{unhandled, Ctx, LowerError, LowerResult};

/// Lower one instruction of the array-construction family.
pub fn lower(
    op: u8,
    insn: &Instruction,
    at: u32,
    ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let origin = Origin::at(at);
    use Instruction as I;
    match insn {
        // ---- `35c` — the packed form of `filled-new-array`.
        I::F35C { a, index, regs, .. } => {
            let last = regs.iter().rposition(|r| *r != 0).map_or(0, |i| i + 1);
            out.push(Inst::new(
                IrOp::FilledNewArray {
                    type_index: u32::from(*index),
                    args: regs[..last]
                        .iter()
                        .map(|r| Reg(u16::from(*r)))
                        .collect::<Vec<_>>()
                        .into(),
                    ranged: false,
                    declared: *a,
                },
                origin,
            ));
        }

        // ---- `3rc` — the range form, whose count is exact.
        I::F3RC { a, index, first_reg, reg_count, .. } => {
            let end = u32::from(*first_reg) + u32::from(*reg_count);
            if end > u32::from(u16::MAX) + 1 {
                return Err(LowerError::BadRegisterRange {
                    at,
                    first: u32::from(*first_reg),
                    count: u32::from(*reg_count),
                });
            }
            out.push(Inst::new(
                IrOp::FilledNewArray {
                    type_index: u32::from(*index),
                    args: (u32::from(*first_reg)..end)
                        .map(|r| Reg(r as u16))
                        .collect::<Vec<_>>()
                        .into(),
                    ranged: true,
                    declared: *a,
                },
                origin,
            ));
        }

        // ---- `31t` — `fill-array-data`.
        I::F31T { a, offset, .. } => out.push(Inst::new(
            IrOp::FillArrayData {
                array: ObjectReg::new(u16::from(*a)),
                payload: Label(ctx.target(at, i64::from(*offset))?.offset()),
            },
            origin,
        )),

        _ => return Err(unhandled(op, "arrays", at)),
    }
    
    Ok(())
}
