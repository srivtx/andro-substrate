//! The constant family: immediates and pool references.
//!
//! Everything here produces a destination and no source, which is what makes it
//! the easiest family to get wrong: an off-by-one in a shift is not a crash, it
//! is a plausible wrong number that only a program that depends on the value
//! would notice. So the three shifts the format defines are computed here, once,
//! explicitly — and the oracle's arithmetic spot-checks in
//! `lower::tests::differential` pin the two of them that are not identity.

use dexcore::insn::Instruction;

use crate::ir::{
    I32Reg, Inst, IrOp, ObjectReg, Origin, Reg, UnsupportedReason, WideClass,
};

use super::{unhandled, Ctx, LowerResult};

/// Lower one instruction of the constant family.
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
        // ---- `11n` — a signed four-bit literal.
        I::F11N { a, literal, .. } => out.push(Inst::new(
            IrOp::ConstI32 { dst: I32Reg::new(u16::from(*a)), value: i32::from(*literal) },
            origin,
        )),

        // ---- `21s` — a signed 16-bit literal, in either width.
        //
        // The two opcodes in this format differ in more than width: the 32-bit
        // form's value is an `int` and the 64-bit form's is a `long` or a
        // `double`'s bit pattern. Keying on the format alone would turn every
        // `const-wide/16` in a real APK into a 32-bit constant.
        I::F21S { a, literal, .. } => {
            let dst = u16::from(*a);
            match op {
                0x13 => out.push(Inst::new(
                    IrOp::ConstI32 { dst: I32Reg::new(dst), value: i32::from(*literal) },
                    origin,
                )),
                0x16 => out.push(Inst::new(
                    IrOp::ConstWide {
                        dst: Reg(dst),
                        bits: i64::from(*literal) as u64,
                        class: WideClass::Unresolved,
                    },
                    origin,
                )),
                _ => return Err(unhandled(op, "consts", at)),
            }
        }

        // ---- `31i` — a signed 32-bit literal, in either width.
        //
        // `const-wide/32` **sign**-extends the 32 bits into 64; it does not
        // zero-extend, and the difference is the whole sign of a negative
        // literal written by hand.
        I::F31I { a, literal, .. } => {
            let dst = u16::from(*a);
            match op {
                0x14 => out.push(Inst::new(
                    IrOp::ConstI32 { dst: I32Reg::new(dst), value: *literal },
                    origin,
                )),
                0x17 => out.push(Inst::new(
                    IrOp::ConstWide {
                        dst: Reg(dst),
                        bits: i64::from(*literal) as u64,
                        class: WideClass::Unresolved,
                    },
                    origin,
                )),
                _ => return Err(unhandled(op, "consts", at)),
            }
        }

        // ---- `21h` — sixteen bits, shifted into the high half.
        I::F21H { a, literal, .. } => {
            // The stored value is a signed 16-bit literal *shifted left by 16*,
            // so the effective constant is `literal << 16` and the sign is
            // carried into bit 31. `wrapping_shl` rather than `<<` because the
            // shift is on a value whose top bit may be set and a debug build
            // must not panic on a perfectly legal instruction.
            let value = i32::from(*literal).wrapping_shl(16);
            if op == 0x15 {
                out.push(Inst::new(IrOp::ConstI32 { dst: I32Reg::new(u16::from(*a)), value }, origin));
            } else {
                out.push(Inst::new(
                    IrOp::ConstWide {
                        dst: Reg(u16::from(*a)),
                        bits: (i64::from(*literal) << 16) as u64,
                        class: WideClass::Unresolved,
                    },
                    origin,
                ));
            }
        }

        // ---- `51l` — a full 64-bit literal.
        I::F51L { a, literal, .. } => out.push(Inst::new(
            IrOp::ConstWide {
                dst: Reg(u16::from(*a)),
                bits: *literal as u64,
                class: WideClass::Unresolved,
            },
            origin,
        )),

        // ---- `21c` — a pool reference.
        I::F21C { a, index, .. } => {
            let dst = ObjectReg::new(u16::from(*a));
            match op {
                0x1a => out.push(Inst::new(
                    IrOp::ConstString { dst, index: u32::from(*index) },
                    origin,
                )),
                0x1c => {
                    out.push(Inst::new(IrOp::ConstClass { dst, index: u32::from(*index) }, origin))
                }
                // `const-method-handle` and `const-method-type`.
                //
                // Refused, and the reason is the shape of the *result*: a
                // `MethodHandle` is a callable and a `MethodType` is a
                // signature, and both carry identity — two handles for the same
                // method are equal, and two different ones are not. The handle
                // model in `IR.md` allocates offsets and nothing else, so
                // neither object has anywhere to live that survives a
                // `MethodHandle::equals`. This is a *host* gap, not a
                // compilation gap: `hostgen` (A5) is where a fabricated handle
                // and the table that can invoke it belong, and when that table
                // exists these two become `ConstMethodHandle` and
                // `ConstMethodType` with no change to `ir.rs`. The oracle
                // refuses the same two opcodes with the same reasoning, which is
                // the agreement that matters.
                0xfe => out.push(Inst::new(
                    IrOp::Unsupported { reason: UnsupportedReason::MethodHandle },
                    origin,
                )),
                0xff => out.push(Inst::new(
                    IrOp::Unsupported { reason: UnsupportedReason::MethodType },
                    origin,
                )),
                _ => return Err(unhandled(op, "consts", at)),
            }
            
        }

        // ---- `31c` — a 32-bit string index.
        I::F31C { a, index, .. } => {
            out.push(Inst::new(IrOp::ConstString { dst: ObjectReg::new(u16::from(*a)), index: *index }, origin))
        }

        _ => return Err(unhandled(op, "consts", at)),
    }
    
    Ok(())
}
