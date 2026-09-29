//! The arithmetic family: opcodes `0x2d`–`0x31` (comparisons), `0x7b`–`0x8f`
//! (unary and conversions), `0x90`–`0xaf` (three-address), `0xb0`–`0xcf`
//! (two-address) and `0xd0`–`0xe2` (immediate).
//!
//! # The shape of the table
//!
//! Three groups of opcodes lower to three groups of [`IrOp`] variants, and the
//! grouping is the whole design:
//!
//! * the **two-address** forms collapse into the three-address ones, with the
//!   destination and the left operand naming the same register, because
//!   WebAssembly has no two-address instruction;
//! * the **immediate** forms keep their immediate, because WebAssembly is a
//!   stack machine and `local.get; i32.const 5; i32.shl` is exactly
//!   `vA << 5`. Expanding them would invent a register the input never had, and
//!   the register file's layout is the one thing every consumer has to agree
//!   with the calling convention on;
//! * the **class** of every operand comes from the opcode and nowhere else, so
//!   an `i64` operation cannot be handed an `i32` register — that is a `rustc`
//!   error, not a runtime surprise.
//!
//! [`differential`](super::differential) checks the *selection* of these against
//! the oracle's own arithmetic primitives.

use crate::lower::tests::prelude::*;

lowering_cases! {
    at 0,
    {
        cmpl_float: 0x2d => IrOp::CmpF32L { dst: I(1), a: F(2), b: F(3) },
            "yields -1, 0 or 1, and **-1 when either operand is NaN**. The `-1 for NaN` is the entire difference from `cmpg`, and it is the reason the two exist";
        cmpg_float: 0x2e => IrOp::CmpF32G { dst: I(1), a: F(2), b: F(3) },
            "as `cmpl-float`, but **+1 for NaN**. A compiler emits one or the other according to which way the source-level comparison is written, and getting it backwards inverts every NaN test";
        cmpl_double: 0x2f => IrOp::CmpF64L { dst: I(1), a: D(2), b: D(3) },
            "as `cmpl-float`, over `f64`";
        cmpg_double: 0x30 => IrOp::CmpF64G { dst: I(1), a: D(2), b: D(3) },
            "as `cmpg-float`, over `f64`";
        cmp_long: 0x31 => IrOp::CmpLong { dst: I(1), a: L(2), b: L(3) },
            "a signed `long` comparison yielding -1, 0 or 1. WebAssembly's `i64.lt_s` is a predicate and not a three-way value, so `codegen` builds the difference and applies a sign";
        neg_int: 0x7b => IrOp::NegI32 { dst: I(1), src: I(2) },
            "negation, wrapping: `i32::MIN` negates to itself rather than trapping, which is `i32.sub v, 0, v` and **not** `i32.neg`, which has no such exception";
        not_int: 0x7c => IrOp::NotI32 { dst: I(1), src: I(2) },
            "bitwise complement, `i32.xor` with -1";
        neg_long: 0x7d => IrOp::NegI64 { dst: L(1), src: L(2) },
            "as `neg-int`, over `i64`";
        not_long: 0x7e => IrOp::NotI64 { dst: L(1), src: L(2) },
            "as `not-int`, over `i64`";
        neg_float: 0x7f => IrOp::NegF32 { dst: F(1), src: F(2) },
            "negating a NaN is itself, and `f32.neg` agrees; the only difference from the integer form is that nothing wraps and nothing throws";
        neg_double: 0x80 => IrOp::NegF64 { dst: D(1), src: D(2) },
            "as `neg-float`, over `f64`";
        int_to_long: 0x81 => IrOp::I32ToI64 { dst: L(1), src: I(2) },
            "sign-extending widening, which is `i64.extend_i32_s` and not the unsigned form: a negative `int` must stay negative";
        int_to_float: 0x82 => IrOp::I32ToF32 { dst: F(1), src: I(2) },
            "rounding to nearest; an `i32` beyond 2^24 is not representable, and rounding rather than truncating is the language's rule and `f32.convert_i32_s`'s";
        int_to_double: 0x83 => IrOp::I32ToF64 { dst: D(1), src: I(2) },
            "every `i32` is representable as an `f64`, so this is exact";
        long_to_int: 0x84 => IrOp::I64ToI32 { dst: I(1), src: L(2) },
            "**truncating**: the low 32 bits, which is `i32.wrap_i64` and neither `trunc` nor a trap";
        long_to_float: 0x85 => IrOp::I64ToF32 { dst: F(1), src: L(2) },
            "rounding to nearest";
        long_to_double: 0x86 => IrOp::I64ToF64 { dst: D(1), src: L(2) },
            "rounding to nearest";
        float_to_int: 0x87 => IrOp::F32ToI32 { dst: I(1), src: F(2) },
            "**saturating**: NaN becomes 0, +inf becomes the maximum and -inf the minimum. `i32.trunc_f32_s` traps on all three, so this is not the instruction of the same name and `codegen` has to build the saturating sequence";
        float_to_long: 0x88 => IrOp::F32ToI64 { dst: L(1), src: F(2) },
            "as `float-to-int`, into 64 bits";
        float_to_double: 0x89 => IrOp::F32ToF64 { dst: D(1), src: F(2) },
            "exact: every `f32` is an `f64`";
        double_to_int: 0x8a => IrOp::F64ToI32 { dst: I(1), src: D(2) },
            "as `float-to-int`, from `f64`";
        double_to_long: 0x8b => IrOp::F64ToI64 { dst: L(1), src: D(2) },
            "as `float-to-int`, from `f64` into 64 bits";
        double_to_float: 0x8c => IrOp::F64ToF32 { dst: F(1), src: D(2) },
            "rounding to nearest, and the one conversion that can lose precision rather than range";
        int_to_byte: 0x8d => IrOp::I32ToByte { dst: I(1), src: I(2) },
            "the low 8 bits, **sign**-extended: `0xFF` is -1";
        int_to_char: 0x8e => IrOp::I32ToChar { dst: I(1), src: I(2) },
            "the low 16 bits, **zero**-extended: `0xFFFF` is 65535 and not -1. This is the one bit of difference between two neighbouring instructions, and getting it wrong turns every `char` in a real APK into a plausible negative number";
        int_to_short: 0x8f => IrOp::I32ToShort { dst: I(1), src: I(2) },
            "the low 16 bits, **sign**-extended: `0xFFFF` is -1 again, the opposite of `int-to-char`";
        add_Add_int: 0x90 => IrOp::AddI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: wrapping addition; WebAssembly's `i32.add` is the same operation, so `codegen` has nothing to add";
        add_Sub_int: 0x91 => IrOp::SubI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: wrapping subtraction, the same as `i32.sub`";
        add_Mul_int: 0x92 => IrOp::MulI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: wrapping multiplication, the same as `i32.mul`";
        add_Div_int: 0x93 => IrOp::DivI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: a zero divisor **throws**, and so does the overflow of the most negative value by -1; `i32.div_s` traps on both, so the check comes first";
        add_Rem_int: 0x94 => IrOp::RemI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: a zero divisor throws; the sign of the result is the dividend's, and the overflow case is 0 rather than a trap";
        add_And_int: 0x95 => IrOp::AndI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: bitwise and, the same as `i32.and`";
        add_Or_int: 0x96 => IrOp::OrI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: bitwise or, the same as `i32.or`";
        add_Xor_int: 0x97 => IrOp::XorI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: bitwise exclusive or, the same as `i32.xor`";
        add_Shl_int: 0x98 => IrOp::ShlI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: the shift count is masked to five bits, which is `i32.shl`'s own rule and therefore the one case where the machine and the language already agree";
        add_Shr_int: 0x99 => IrOp::ShrI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: arithmetic right shift, which is `i32.shr_s` and **not** `i32.shr_u`; the two differ for every negative operand";
        ushr_int: 0x9a => IrOp::UShrI32 { dst: I(1), a: I(2), b: I(3) },
            "`add-int` family: logical right shift, which is `i32.shr_u` and not `i32.shr_s`";
        add_long: 0x9b => IrOp::AddI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        sub_long: 0x9c => IrOp::SubI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        mul_long: 0x9d => IrOp::MulI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        div_long: 0x9e => IrOp::DivI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        rem_long: 0x9f => IrOp::RemI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        and_long: 0xa0 => IrOp::AndI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        or_long: 0xa1 => IrOp::OrI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        xor_long: 0xa2 => IrOp::XorI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        shl_long: 0xa3 => IrOp::ShlI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        shr_long: 0xa4 => IrOp::ShrI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        ushr_long: 0xa5 => IrOp::UShrI64 { dst: L(1), a: L(2), b: L(3) },
            "as the 32-bit form, over `i64`; the shift count is masked to six bits, which `i64.shl` does not do for a count of 64 or more";
        add_float: 0xa6 => IrOp::AddF32 { dst: F(1), a: F(2), b: F(3) },
            "over `f32`; nothing here throws, and a zero divisor for the division is an infinity or a NaN rather than an exception — which is the whole difference from the integer division above";
        sub_float: 0xa7 => IrOp::SubF32 { dst: F(1), a: F(2), b: F(3) },
            "over `f32`; nothing here throws, and a zero divisor for the division is an infinity or a NaN rather than an exception — which is the whole difference from the integer division above";
        mul_float: 0xa8 => IrOp::MulF32 { dst: F(1), a: F(2), b: F(3) },
            "over `f32`; nothing here throws, and a zero divisor for the division is an infinity or a NaN rather than an exception — which is the whole difference from the integer division above";
        div_float: 0xa9 => IrOp::DivF32 { dst: F(1), a: F(2), b: F(3) },
            "over `f32`; nothing here throws, and a zero divisor for the division is an infinity or a NaN rather than an exception — which is the whole difference from the integer division above";
        rem_float: 0xaa => IrOp::RemF32 { dst: F(1), a: F(2), b: F(3) },
            "over `f32`; nothing here throws, and a zero divisor for the division is an infinity or a NaN rather than an exception — which is the whole difference from the integer division above";
        add_double: 0xab => IrOp::AddF64 { dst: D(1), a: D(2), b: D(3) },
            "as the `f32` form, over `f64`";
        sub_double: 0xac => IrOp::SubF64 { dst: D(1), a: D(2), b: D(3) },
            "as the `f32` form, over `f64`";
        mul_double: 0xad => IrOp::MulF64 { dst: D(1), a: D(2), b: D(3) },
            "as the `f32` form, over `f64`";
        div_double: 0xae => IrOp::DivF64 { dst: D(1), a: D(2), b: D(3) },
            "as the `f32` form, over `f64`";
        rem_double: 0xaf => IrOp::RemF64 { dst: D(1), a: D(2), b: D(3) },
            "as the `f32` form, over `f64`";
        add_int_2addr: 0xb0 => IrOp::AddI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        sub_int_2addr: 0xb1 => IrOp::SubI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        mul_int_2addr: 0xb2 => IrOp::MulI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        div_int_2addr: 0xb3 => IrOp::DivI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        rem_int_2addr: 0xb4 => IrOp::RemI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        and_int_2addr: 0xb5 => IrOp::AndI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        or_int_2addr: 0xb6 => IrOp::OrI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        xor_int_2addr: 0xb7 => IrOp::XorI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        shl_int_2addr: 0xb8 => IrOp::ShlI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        shr_int_2addr: 0xb9 => IrOp::ShrI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        ushr_int_2addr: 0xba => IrOp::UShrI32 { dst: I(1), a: I(1), b: I(2) },
            "the two-address form `vA = vA op vB` collapses to the three-address operation with the destination and the left operand naming the same register, because WebAssembly has no two-address instruction and the register file's layout is the one thing a consumer has to agree on exactly";
        add_long_2addr: 0xbb => IrOp::AddI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        sub_long_2addr: 0xbc => IrOp::SubI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        mul_long_2addr: 0xbd => IrOp::MulI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        div_long_2addr: 0xbe => IrOp::DivI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        rem_long_2addr: 0xbf => IrOp::RemI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        and_long_2addr: 0xc0 => IrOp::AndI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        or_long_2addr: 0xc1 => IrOp::OrI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        xor_long_2addr: 0xc2 => IrOp::XorI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        shl_long_2addr: 0xc3 => IrOp::ShlI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        shr_long_2addr: 0xc4 => IrOp::ShrI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        ushr_long_2addr: 0xc5 => IrOp::UShrI64 { dst: L(1), a: L(1), b: L(2) },
            "as the 32-bit two-address form, over `i64`";
        add_float_2addr: 0xc6 => IrOp::AddF32 { dst: F(1), a: F(1), b: F(2) },
            "as the 32-bit two-address form, over `f32`";
        sub_float_2addr: 0xc7 => IrOp::SubF32 { dst: F(1), a: F(1), b: F(2) },
            "as the 32-bit two-address form, over `f32`";
        mul_float_2addr: 0xc8 => IrOp::MulF32 { dst: F(1), a: F(1), b: F(2) },
            "as the 32-bit two-address form, over `f32`";
        div_float_2addr: 0xc9 => IrOp::DivF32 { dst: F(1), a: F(1), b: F(2) },
            "as the 32-bit two-address form, over `f32`";
        rem_float_2addr: 0xca => IrOp::RemF32 { dst: F(1), a: F(1), b: F(2) },
            "as the 32-bit two-address form, over `f32`";
        add_double_2addr: 0xcb => IrOp::AddF64 { dst: D(1), a: D(1), b: D(2) },
            "as the 32-bit two-address form, over `f64`";
        sub_double_2addr: 0xcc => IrOp::SubF64 { dst: D(1), a: D(1), b: D(2) },
            "as the 32-bit two-address form, over `f64`";
        mul_double_2addr: 0xcd => IrOp::MulF64 { dst: D(1), a: D(1), b: D(2) },
            "as the 32-bit two-address form, over `f64`";
        div_double_2addr: 0xce => IrOp::DivF64 { dst: D(1), a: D(1), b: D(2) },
            "as the 32-bit two-address form, over `f64`";
        rem_double_2addr: 0xcf => IrOp::RemF64 { dst: D(1), a: D(1), b: D(2) },
            "as the 32-bit two-address form, over `f64`";
        add_int_lit16: 0xd0 => IrOp::AddI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. wrapping addition; WebAssembly's `i32.add` is the same operation, so `codegen` has nothing to add";
        rsub_int_lit16: 0xd1 => IrOp::RsubI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. `rsub` is the only reversed form: the literal is the *left* operand, so the result is `lit - vB` and the destination is not an operand of the operation. It gets its own IR variant rather than being written as a subtraction with swapped operands, which is not the same thing in wrapping arithmetic";
        mul_int_lit16: 0xd2 => IrOp::MulI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. wrapping multiplication, the same as `i32.mul`";
        div_int_lit16: 0xd3 => IrOp::DivI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. a zero divisor **throws**, and so does the overflow of the most negative value by -1; `i32.div_s` traps on both, so the check comes first";
        rem_int_lit16: 0xd4 => IrOp::RemI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. a zero divisor throws; the sign of the result is the dividend's, and the overflow case is 0 rather than a trap";
        and_int_lit16: 0xd5 => IrOp::AndI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. bitwise and, the same as `i32.and`";
        or_int_lit16: 0xd6 => IrOp::OrI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. bitwise or, the same as `i32.or`";
        xor_int_lit16: 0xd7 => IrOp::XorI32Lit { dst: I(1), a: I(2), lit: 0x1234 },
            "a signed 16-bit immediate. WebAssembly is a stack machine, so `local.get; i32.const 0x1234; i32.add` **is** this operation: the immediate stays an immediate and no register is invented for it. bitwise exclusive or, the same as `i32.xor`";
        add_int_lit8: 0xd8 => IrOp::AddI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. wrapping addition; WebAssembly's `i32.add` is the same operation, so `codegen` has nothing to add";
        rsub_int_lit8: 0xd9 => IrOp::RsubI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. as `rsub-int/lit16`, with an 8-bit immediate";
        mul_int_lit8: 0xda => IrOp::MulI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. wrapping multiplication, the same as `i32.mul`";
        div_int_lit8: 0xdb => IrOp::DivI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. a zero divisor **throws**, and so does the overflow of the most negative value by -1; `i32.div_s` traps on both, so the check comes first";
        rem_int_lit8: 0xdc => IrOp::RemI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. a zero divisor throws; the sign of the result is the dividend's, and the overflow case is 0 rather than a trap";
        and_int_lit8: 0xdd => IrOp::AndI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. bitwise and, the same as `i32.and`";
        or_int_lit8: 0xde => IrOp::OrI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. bitwise or, the same as `i32.or`";
        xor_int_lit8: 0xdf => IrOp::XorI32Lit { dst: I(1), a: I(2), lit: 5 },
            "a signed 8-bit immediate, sign-extended on the way into the 32-bit operand. bitwise exclusive or, the same as `i32.xor`";
        shl_int_lit8: 0xe0 => IrOp::ShlI32Lit { dst: I(1), a: I(2), lit: 5 },
            "the shift count is the immediate, and it is **masked to five bits** before use: a Java program that shifts by 32 is shifting by 0. `i32.shl` happens to agree for a count that fits, and the variant still names the mask so `codegen` does not have to know it was there";
        shr_int_lit8: 0xe1 => IrOp::ShrI32Lit { dst: I(1), a: I(2), lit: 5 },
            "as `shl-int/lit8`, but the shift is **arithmetic**: `i32.shr_s` and not `i32.shr_u`, which differ for every negative operand";
        ushr_int_lit8: 0xe2 => IrOp::UShrI32Lit { dst: I(1), a: I(2), lit: 5 },
            "as `shl-int/lit8`, but the shift is **logical**: `i32.shr_u` and not `i32.shr_s`";
    }
}
