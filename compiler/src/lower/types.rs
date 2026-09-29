//! Type tests, allocation and array length.
//!
//! # `check-cast` is in place
//!
//! `check-cast vA, type` tests the value **already in `vA`** and throws if it
//! fails; it does not produce a value. The IR says so — [`IrOp::CheckCast`] has
//! no destination — because a lowering that gave it one would have to invent a
//! register, and the natural choice (`dst = src`) is a self-assignment that
//! `codegen` would have to special-case away. Keeping it in place also keeps the
//! trap on the instruction that is supposed to raise it, which is what the
//! oracle's exception model expects.

use dexcore::insn::Instruction;

use crate::ir::{I32Reg, Inst, IrOp, ObjectReg, Origin};

use super::{unhandled, Ctx, LowerResult};

/// Lower one instruction of the type and allocation family.
pub fn lower(
    op: u8,
    insn: &Instruction,
    at: u32,
    _ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let origin = Origin::at(at);
    use Instruction as I;
    match insn {
        // ---- `21c` — `check-cast` and `new-instance`.
        I::F21C { a, index, .. } => {
            out.push(Inst::new(match op {
                0x1f => IrOp::CheckCast { object: ObjectReg::new(u16::from(*a)), index: u32::from(*index) },
                0x22 => IrOp::NewInstance { dst: ObjectReg::new(u16::from(*a)), index: u32::from(*index) },
                _ => return Err(unhandled(op, "types", at)),
            }
            , origin));
        }

        // ---- `22c` — `instance-of` and `new-array`.
        I::F22C { a, b, index, .. } => {
            out.push(Inst::new(match op {
                0x20 => IrOp::InstanceOf {
                    dst: I32Reg::new(u16::from(*a)),
                    object: ObjectReg::new(u16::from(*b)),
                    index: u32::from(*index),
                },
                0x23 => IrOp::NewArray {
                    dst: ObjectReg::new(u16::from(*a)),
                    type_index: u32::from(*index),
                    size: I32Reg::new(u16::from(*b)),
                },
                _ => return Err(unhandled(op, "types", at)),
            }
            , origin));
        }

        // ---- `12x` — `array-length`.
        I::F12X { a, b, .. } => {
            out.push(Inst::new(
                IrOp::ArrayLength { dst: I32Reg::new(u16::from(*a)), array: ObjectReg::new(u16::from(*b)) },
                origin,
            ))
        }

        _ => return Err(unhandled(op, "types", at)),
    }
    
    Ok(())
}
