//! Arithmetic, bitwise, shift, conversion, narrowing and comparison.
//!
//! # The two-address form collapses; the immediate form does not
//!
//! Dalvik writes the same operation three ways. The **two-address** form
//! (`vA = vA op vB`) becomes the three-address form with `dst` and `a` naming
//! the same register, because WebAssembly has no two-address instruction and
//! `local.get dst; local.get a; local.get b; i32.add` is one instruction either
//! way. The **immediate** form keeps its immediate, as an `…Lit` variant,
//! because WebAssembly is a *stack* machine: `local.get a; i32.const 5;
//! i32.add` is exactly `a + 5`. Expanding it into a `ConstI32` would invent a
//! register the input never had, and the register file's layout is the one thing
//! in this IR a consumer has to agree with the calling convention on exactly.
//!
//! One consequence worth stating: **no lowering in this module ever needs a
//! scratch register.** That is not an accident, it is why the immediate forms
//! are kept. An earlier draft of this file expanded them and needed one, and had
//! nowhere defensible to put it — a gap in [`IR.md`], which fixes the convention
//! for parameters and results and says nothing about temporaries. Keeping the
//! immediate removes the question.
//!
//! # The semantics that are not the machine's
//!
//! Four of these mean something other than their WebAssembly counterparts, and
//! getting any of them wrong produces a plausible number rather than a trap:
//!
//! * **Shift counts are masked.** The rule is `count & 31` and `count & 63`.
//!   `i32.shl` already masks to 32, and `i64.shl` masks to 64, so for counts
//!   that fit they agree — but a Java program that shifts by 32 is shifting by
//!   0, and a compiler that emits the instruction without the mask gets `x`
//!   instead of `x * 2^32`'s truncated self, which is at least the right answer.
//!   The `…Lit` shift variants make the mask the compiler's to apply and the
//!   value's to verify.
//! * **Integer division is not WebAssembly's.** A zero divisor throws, and so
//!   does `i32::MIN / -1`, which overflows in the language. `codegen` must test
//!   before it divides.
//! * **Float-to-integer conversion saturates; WebAssembly truncates.** See
//!   [`IrOp::F32ToI32`].
//! * **`int-to-char` zero-extends** and `int-to-byte` and `int-to-short`
//!   sign-extend. One bit of difference between two neighbouring instructions.

use dexcore::insn::Instruction;

use crate::ir::{F32Reg, F64Reg, I32Reg, I64Reg, Inst, IrOp, Origin};

use super::{unhandled, Ctx, LowerResult};

/// Lower one instruction of the arithmetic family.
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
        // ---- `12x`. Two thirds of the family: the unary operators, the twelve
        // conversions, and the two-address binary forms.
        I::F12X { a, b, .. } => {
            let (a, b) = (u16::from(*a), u16::from(*b));
            out.push(Inst::new(match op {
                0x7b => IrOp::NegI32 { dst: I32Reg::new(a), src: I32Reg::new(b) },
                0x7c => IrOp::NotI32 { dst: I32Reg::new(a), src: I32Reg::new(b) },
                0x7d => IrOp::NegI64 { dst: I64Reg::new(a), src: I64Reg::new(b) },
                0x7e => IrOp::NotI64 { dst: I64Reg::new(a), src: I64Reg::new(b) },
                0x7f => IrOp::NegF32 { dst: F32Reg::new(a), src: F32Reg::new(b) },
                0x80 => IrOp::NegF64 { dst: F64Reg::new(a), src: F64Reg::new(b) },

                0x81 => IrOp::I32ToI64 { dst: I64Reg::new(a), src: I32Reg::new(b) },
                0x82 => IrOp::I32ToF32 { dst: F32Reg::new(a), src: I32Reg::new(b) },
                0x83 => IrOp::I32ToF64 { dst: F64Reg::new(a), src: I32Reg::new(b) },
                0x84 => IrOp::I64ToI32 { dst: I32Reg::new(a), src: I64Reg::new(b) },
                0x85 => IrOp::I64ToF32 { dst: F32Reg::new(a), src: I64Reg::new(b) },
                0x86 => IrOp::I64ToF64 { dst: F64Reg::new(a), src: I64Reg::new(b) },
                0x87 => IrOp::F32ToI32 { dst: I32Reg::new(a), src: F32Reg::new(b) },
                0x88 => IrOp::F32ToI64 { dst: I64Reg::new(a), src: F32Reg::new(b) },
                0x89 => IrOp::F32ToF64 { dst: F64Reg::new(a), src: F32Reg::new(b) },
                0x8a => IrOp::F64ToI32 { dst: I32Reg::new(a), src: F64Reg::new(b) },
                0x8b => IrOp::F64ToI64 { dst: I64Reg::new(a), src: F64Reg::new(b) },
                0x8c => IrOp::F64ToF32 { dst: F32Reg::new(a), src: F64Reg::new(b) },

                // `int-to-byte` sign-extends from 8 bits; `int-to-short`
                // sign-extends from 16; `int-to-char` **zero**-extends from 16,
                // so `0xFFFF` is 65535 and not -1.
                0x8d => IrOp::I32ToByte { dst: I32Reg::new(a), src: I32Reg::new(b) },
                0x8e => IrOp::I32ToChar { dst: I32Reg::new(a), src: I32Reg::new(b) },
                0x8f => IrOp::I32ToShort { dst: I32Reg::new(a), src: I32Reg::new(b) },

                // ---- the two-address binary forms.
                0xb0 => IrOp::AddI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb1 => IrOp::SubI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb2 => IrOp::MulI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb3 => IrOp::DivI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb4 => IrOp::RemI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb5 => IrOp::AndI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb6 => IrOp::OrI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb7 => IrOp::XorI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb8 => IrOp::ShlI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xb9 => IrOp::ShrI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xba => IrOp::UShrI32 { dst: I32Reg::new(a), a: I32Reg::new(a), b: I32Reg::new(b) },
                0xbb => IrOp::AddI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xbc => IrOp::SubI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xbd => IrOp::MulI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xbe => IrOp::DivI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xbf => IrOp::RemI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc0 => IrOp::AndI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc1 => IrOp::OrI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc2 => IrOp::XorI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc3 => IrOp::ShlI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc4 => IrOp::ShrI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc5 => IrOp::UShrI64 { dst: I64Reg::new(a), a: I64Reg::new(a), b: I64Reg::new(b) },
                0xc6 => IrOp::AddF32 { dst: F32Reg::new(a), a: F32Reg::new(a), b: F32Reg::new(b) },
                0xc7 => IrOp::SubF32 { dst: F32Reg::new(a), a: F32Reg::new(a), b: F32Reg::new(b) },
                0xc8 => IrOp::MulF32 { dst: F32Reg::new(a), a: F32Reg::new(a), b: F32Reg::new(b) },
                0xc9 => IrOp::DivF32 { dst: F32Reg::new(a), a: F32Reg::new(a), b: F32Reg::new(b) },
                0xca => IrOp::RemF32 { dst: F32Reg::new(a), a: F32Reg::new(a), b: F32Reg::new(b) },
                0xcb => IrOp::AddF64 { dst: F64Reg::new(a), a: F64Reg::new(a), b: F64Reg::new(b) },
                0xcc => IrOp::SubF64 { dst: F64Reg::new(a), a: F64Reg::new(a), b: F64Reg::new(b) },
                0xcd => IrOp::MulF64 { dst: F64Reg::new(a), a: F64Reg::new(a), b: F64Reg::new(b) },
                0xce => IrOp::DivF64 { dst: F64Reg::new(a), a: F64Reg::new(a), b: F64Reg::new(b) },
                0xcf => IrOp::RemF64 { dst: F64Reg::new(a), a: F64Reg::new(a), b: F64Reg::new(b) },

                _ => return Err(unhandled(op, "arith", at)),
            }, origin));
        }

        // ---- `23x`. The four comparisons, then the three-address binary forms.
        I::F23X { a, b, c, .. } => {
            let (a, b, c) = (u16::from(*a), u16::from(*b), u16::from(*c));
            out.push(Inst::new(match op {
                0x2d => IrOp::CmpF32L { dst: I32Reg::new(a), a: F32Reg::new(b), b: F32Reg::new(c) },
                0x2e => IrOp::CmpF32G { dst: I32Reg::new(a), a: F32Reg::new(b), b: F32Reg::new(c) },
                0x2f => IrOp::CmpF64L { dst: I32Reg::new(a), a: F64Reg::new(b), b: F64Reg::new(c) },
                0x30 => IrOp::CmpF64G { dst: I32Reg::new(a), a: F64Reg::new(b), b: F64Reg::new(c) },
                0x31 => IrOp::CmpLong { dst: I32Reg::new(a), a: I64Reg::new(b), b: I64Reg::new(c) },
                _ => three(op, I32Reg::new(a), b, c),
            }, origin));
        }

        // ---- `22s`, a signed 16-bit immediate.
        I::F22S { a, b, literal, .. } => {
            let (a, b) = (u16::from(*a), u16::from(*b));
            out.push(Inst::new(lit(op, I32Reg::new(a), I32Reg::new(b), i32::from(*literal)), origin))
        }

        // ---- `22b`, a signed 8-bit immediate.
        I::F22B { a, b, literal, .. } => {
            let (a, b) = (u16::from(*a), u16::from(*b));
            out.push(Inst::new(lit(op, I32Reg::new(a), I32Reg::new(b), i32::from(*literal)), origin))
        }

        _ => return Err(unhandled(op, "arith", at)),
    }
    Ok(())
}

/// The three-address form of a binary operation.
///
/// `a` and `b` arrive as the raw register numbers the encoding carries, because
/// the 64-bit and floating-point arms need a register type the instruction does
/// not supply — only the opcode says what class the registers hold. That is the
/// same situation as [`crate::ir::WideClass`] and it is resolved the same way:
/// by the opcode, which is the only evidence there is.
fn three(op: u8, dst: I32Reg, a: u16, b: u16) -> IrOp {
    let (a32, b32) = (I32Reg::new(a), I32Reg::new(b));
    let (a64, b64) = (I64Reg::new(a), I64Reg::new(b));
    let (a32f, b32f) = (F32Reg::new(a), F32Reg::new(b));
    let (a64f, b64f) = (F64Reg::new(a), F64Reg::new(b));
    match op {
        0x90 => IrOp::AddI32 { dst, a: a32, b: b32 },
        0x91 => IrOp::SubI32 { dst, a: a32, b: b32 },
        0x92 => IrOp::MulI32 { dst, a: a32, b: b32 },
        0x93 => IrOp::DivI32 { dst, a: a32, b: b32 },
        0x94 => IrOp::RemI32 { dst, a: a32, b: b32 },
        0x95 => IrOp::AndI32 { dst, a: a32, b: b32 },
        0x96 => IrOp::OrI32 { dst, a: a32, b: b32 },
        0x97 => IrOp::XorI32 { dst, a: a32, b: b32 },
        0x98 => IrOp::ShlI32 { dst, a: a32, b: b32 },
        0x99 => IrOp::ShrI32 { dst, a: a32, b: b32 },
        0x9a => IrOp::UShrI32 { dst, a: a32, b: b32 },

        0x9b => IrOp::AddI64 { dst: dst.long(), a: a64, b: b64 },
        0x9c => IrOp::SubI64 { dst: dst.long(), a: a64, b: b64 },
        0x9d => IrOp::MulI64 { dst: dst.long(), a: a64, b: b64 },
        0x9e => IrOp::DivI64 { dst: dst.long(), a: a64, b: b64 },
        0x9f => IrOp::RemI64 { dst: dst.long(), a: a64, b: b64 },
        0xa0 => IrOp::AndI64 { dst: dst.long(), a: a64, b: b64 },
        0xa1 => IrOp::OrI64 { dst: dst.long(), a: a64, b: b64 },
        0xa2 => IrOp::XorI64 { dst: dst.long(), a: a64, b: b64 },
        0xa3 => IrOp::ShlI64 { dst: dst.long(), a: a64, b: b64 },
        0xa4 => IrOp::ShrI64 { dst: dst.long(), a: a64, b: b64 },
        0xa5 => IrOp::UShrI64 { dst: dst.long(), a: a64, b: b64 },

        0xa6 => IrOp::AddF32 { dst: dst.f32(), a: a32f, b: b32f },
        0xa7 => IrOp::SubF32 { dst: dst.f32(), a: a32f, b: b32f },
        0xa8 => IrOp::MulF32 { dst: dst.f32(), a: a32f, b: b32f },
        0xa9 => IrOp::DivF32 { dst: dst.f32(), a: a32f, b: b32f },
        0xaa => IrOp::RemF32 { dst: dst.f32(), a: a32f, b: b32f },

        0xab => IrOp::AddF64 { dst: dst.f64(), a: a64f, b: b64f },
        0xac => IrOp::SubF64 { dst: dst.f64(), a: a64f, b: b64f },
        0xad => IrOp::MulF64 { dst: dst.f64(), a: a64f, b: b64f },
        0xae => IrOp::DivF64 { dst: dst.f64(), a: a64f, b: b64f },
        0xaf => IrOp::RemF64 { dst: dst.f64(), a: a64f, b: b64f },

        // Reached only if a caller sends a comparison here by mistake; the
        // comparison arm in `lower` catches them first. An unclaimed opcode
        // never becomes a wrong instruction: it becomes this, which
        // `Function::new` accepts and a coverage test fails on.
        _ => IrOp::Unsupported { reason: crate::ir::UnsupportedReason::UnassignedSlot },
    }
}

/// The immediate form, given the destination register, the source register and
/// the literal.
///
/// `rsub` is the only reversed one, and it is *not* a subtraction with swapped
/// operands at the IR level: the result of `lit - a` is not `-a + lit` in
/// wrapping arithmetic for every pair, and the specification gives it its own
/// operation. [`IrOp::RsubI32Lit`] is that operation and `codegen` pushes the
/// literal first.
fn lit(op: u8, dst: I32Reg, a: I32Reg, value: i32) -> IrOp {
    match op {
        0xd0 | 0xd8 => IrOp::AddI32Lit { dst, a, lit: value },
        0xd1 | 0xd9 => IrOp::RsubI32Lit { dst, a, lit: value },
        0xd2 | 0xda => IrOp::MulI32Lit { dst, a, lit: value },
        0xd3 | 0xdb => IrOp::DivI32Lit { dst, a, lit: value },
        0xd4 | 0xdc => IrOp::RemI32Lit { dst, a, lit: value },
        0xd5 | 0xdd => IrOp::AndI32Lit { dst, a, lit: value },
        0xd6 | 0xde => IrOp::OrI32Lit { dst, a, lit: value },
        0xd7 | 0xdf => IrOp::XorI32Lit { dst, a, lit: value },
        0xe0 => IrOp::ShlI32Lit { dst, a, lit: value },
        0xe1 => IrOp::ShrI32Lit { dst, a, lit: value },
        0xe2 => IrOp::UShrI32Lit { dst, a, lit: value },
        _ => IrOp::Unsupported { reason: crate::ir::UnsupportedReason::UnassignedSlot },
    }
}

/// The class of a register, restated.
///
/// Not a coercion in the sense the rest of the crate forbids: the encoding says
/// only a register *number*, and the opcode is the sole evidence of what class it
/// holds. Naming that in one place, at the point where the opcode has already
/// decided, is how the tables above stay readable; the alternative is a cast at
/// every one of ninety sites.
trait Widen {
    /// The same register number, read as a 64-bit integer register.
    fn long(self) -> I64Reg;
    /// The same register number, read as an `f32` register.
    fn f32(self) -> F32Reg;
    /// The same register number, read as an `f64` register.
    fn f64(self) -> F64Reg;
}

impl Widen for I32Reg {
    fn long(self) -> I64Reg {
        I64Reg::new(self.index())
    }
    fn f32(self) -> F32Reg {
        F32Reg::new(self.index())
    }
    fn f64(self) -> F64Reg {
        F64Reg::new(self.index())
    }
}
