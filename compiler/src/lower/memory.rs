//! Array element access and field access.
//!
//! # The two ambiguities
//!
//! Both families read an element whose class **the instruction does not state**,
//! and both are recorded rather than resolved:
//!
//! * *32 bits.* `aget`/`aput` are specified over "one 32-bit element", which is
//!   an `int` in an `int[]` and a `float` in a `float[]`. The same is true of
//!   `iget`/`iput` on a `float` field. The array, or the field's declared type,
//!   decides; the instruction does not, and the `field_ids`/`type_ids` entries
//!   that would decide are in the file, not in the instruction. So
//!   [`WordClass::Unresolved`], and a class is filled in by whoever has the pool
//!   in hand.
//! * *64 bits.* `aget-wide` and `iget-wide` cover both `long` and `double`, and
//!   do not say which. [`WideClass::Unresolved`] for the same reason.
//!
//! The *sub-word* forms do not have this problem: `aget-boolean`, `aget-byte`,
//! `aget-char` and `aget-short` are unambiguously 32-bit integers, and differ
//! only in how they widen. That difference is [`Narrow`], and it is the whole
//! content of those sixteen opcodes. Getting the sign wrong on a `char` turns
//! every `char` in a real APK into a plausible negative number, so it is a
//! named field rather than an implied detail.

use dexcore::insn::Instruction;

use crate::ir::{
    FieldRef, I32Reg, Inst, IrOp, Narrow, ObjectReg, Origin, WideClass, WordClass,
};

use super::{unhandled, Ctx, LowerResult};

/// Lower one instruction of the memory family.
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
        // ---- `23x` array element access.
        I::F23X { a, b, c, .. } => {
            let (dst, array, index) = (I32Reg::new(u16::from(*a)), ObjectReg::new(u16::from(*b)), I32Reg::new(u16::from(*c)));
            out.push(Inst::new(match op {
                0x44 => IrOp::AgetWord {
                    dst: dst.reg(),
                    array,
                    index,
                    class: WordClass::Unresolved,
                },
                0x45 => {
                    IrOp::AgetWide { dst: dst.reg(), array, index, class: WideClass::Unresolved }
                }
                0x46 => IrOp::AgetObject { dst: ObjectReg::new(u16::from(*a)), array, index },
                0x47 => IrOp::AgetNarrow { dst, array, index, narrow: Narrow::Boolean },
                0x48 => IrOp::AgetNarrow { dst, array, index, narrow: Narrow::SByte },
                0x49 => IrOp::AgetNarrow { dst, array, index, narrow: Narrow::Char },
                0x4a => IrOp::AgetNarrow { dst, array, index, narrow: Narrow::Short },

                0x4b => {
                    IrOp::AputWord { array, index, value: dst.reg(), class: WordClass::Unresolved }
                }
                0x4c => IrOp::AputWide {
                    array,
                    index,
                    value: dst.reg(),
                    class: WideClass::Unresolved,
                },
                0x4d => IrOp::AputObject { array, index, value: ObjectReg::new(u16::from(*a)) },
                0x4e => IrOp::AputNarrow { array, index, value: dst, narrow: Narrow::Boolean },
                0x4f => IrOp::AputNarrow { array, index, value: dst, narrow: Narrow::SByte },
                0x50 => IrOp::AputNarrow { array, index, value: dst, narrow: Narrow::Char },
                0x51 => IrOp::AputNarrow { array, index, value: dst, narrow: Narrow::Short },
                _ => return Err(unhandled(op, "memory", at)),
            }
            , origin));
        }

        // ---- `22c` instance field access.
        I::F22C { a, b, index, .. } => {
            let object = ObjectReg::new(u16::from(*b));
            let field = FieldRef { index: u32::from(*index) };
            out.push(Inst::new(match op {
                0x52 => IrOp::IgetWord {
                    dst: I32Reg::new(u16::from(*a)).reg(),
                    object,
                    field,
                    class: WordClass::Unresolved,
                },
                0x53 => {
                    IrOp::IgetWide { dst: I32Reg::new(u16::from(*a)).reg(), object, field, class: WideClass::Unresolved }
                }
                0x54 => IrOp::IgetObject { dst: ObjectReg::new(u16::from(*a)), object, field },
                0x55 => IrOp::IgetNarrow { dst: I32Reg::new(u16::from(*a)), object, field, narrow: Narrow::Boolean },
                0x56 => IrOp::IgetNarrow { dst: I32Reg::new(u16::from(*a)), object, field, narrow: Narrow::SByte },
                0x57 => IrOp::IgetNarrow { dst: I32Reg::new(u16::from(*a)), object, field, narrow: Narrow::Char },
                0x58 => IrOp::IgetNarrow { dst: I32Reg::new(u16::from(*a)), object, field, narrow: Narrow::Short },

                0x59 => IrOp::IputWord {
                    object,
                    field,
                    value: I32Reg::new(u16::from(*a)).reg(),
                    class: WordClass::Unresolved,
                },
                0x5a => IrOp::IputWide {
                    object,
                    field,
                    value: I32Reg::new(u16::from(*a)).reg(),
                    class: WideClass::Unresolved,
                },
                0x5b => IrOp::IputObject { object, field, value: ObjectReg::new(u16::from(*a)) },
                0x5c => IrOp::IputNarrow { object, field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Boolean },
                0x5d => IrOp::IputNarrow { object, field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::SByte },
                0x5e => IrOp::IputNarrow { object, field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Char },
                0x5f => IrOp::IputNarrow { object, field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Short },
                _ => return Err(unhandled(op, "memory", at)),
            }
            , origin));
        }

        // ---- `21c` static field access.
        I::F21C { a, index, .. } => {
            let field = FieldRef { index: u32::from(*index) };
            out.push(Inst::new(match op {
                0x60 => IrOp::SgetWord {
                    dst: I32Reg::new(u16::from(*a)).reg(),
                    field,
                    class: WordClass::Unresolved,
                },
                0x61 => {
                    IrOp::SgetWide { dst: I32Reg::new(u16::from(*a)).reg(), field, class: WideClass::Unresolved }
                }
                0x62 => IrOp::SgetObject { dst: ObjectReg::new(u16::from(*a)), field },
                0x63 => IrOp::SgetNarrow { dst: I32Reg::new(u16::from(*a)), field, narrow: Narrow::Boolean },
                0x64 => IrOp::SgetNarrow { dst: I32Reg::new(u16::from(*a)), field, narrow: Narrow::SByte },
                0x65 => IrOp::SgetNarrow { dst: I32Reg::new(u16::from(*a)), field, narrow: Narrow::Char },
                0x66 => IrOp::SgetNarrow { dst: I32Reg::new(u16::from(*a)), field, narrow: Narrow::Short },

                0x67 => IrOp::SputWord {
                    field,
                    value: I32Reg::new(u16::from(*a)).reg(),
                    class: WordClass::Unresolved,
                },
                0x68 => IrOp::SputWide {
                    field,
                    value: I32Reg::new(u16::from(*a)).reg(),
                    class: WideClass::Unresolved,
                },
                0x69 => IrOp::SputObject { field, value: ObjectReg::new(u16::from(*a)) },
                0x6a => IrOp::SputNarrow { field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Boolean },
                0x6b => IrOp::SputNarrow { field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::SByte },
                0x6c => IrOp::SputNarrow { field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Char },
                0x6d => IrOp::SputNarrow { field, value: I32Reg::new(u16::from(*a)), narrow: Narrow::Short },
                _ => return Err(unhandled(op, "memory", at)),
            }
            , origin));
        }

        _ => return Err(unhandled(op, "memory", at)),
    }
    
    Ok(())
}
