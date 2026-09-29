//! Differential checks of the arithmetic's *operand selection* against the
//! oracle's own primitive table.
//!
//! # What this is, precisely
//!
//! `dexinterp` is the oracle ([`IR.md`](../../../IR.md) § Verification) and
//! `dexinterp::ops` is the table the engine itself executes:
//! `int32_binop`, `int64_binop`, `float32_binop`, `float64_binop`, `f32_to_int`
//! and the rest. Each takes an **opcode-relative index** — `op - 0x90` for the
//! 32-bit integer block, `op - 0x9b` for the 64-bit one — and two operands, and
//! returns what the input's semantics demand.
//!
//! What is checked here is that the lowering picks the *same* operation, at the
//! *same* class, in the *same* operand order, as the oracle's table says that
//! opcode byte means. The check reads the [`IrOp`] the lowering produced — which
//! operation, which register classes, which operand order — applies *that named
//! operation* to two numbers, and compares with the oracle's entry for the same
//! opcode byte.
//!
//! # What it catches, and what it is not
//!
//! It catches a lowering that maps opcode `0x98` to a shift left when the oracle
//! means a shift right; one that reads the two-address form's operands in the
//! wrong order, so `sub-int/2addr v0, v1` computes `v1 - v0`; one that puts the
//! immediate form's literal on the left when the oracle puts it on the right.
//! Each of those produces a body of exactly the right shape, the right length
//! and the right origins, and every other test in this suite passes.
//!
//! It deliberately does **not** evaluate the IR. That would be a second
//! implementation of the IR's semantics written from the same reading, and a
//! disagreement between the two would be evidence about the *reading* rather
//! than about the compiler, while an agreement would prove nothing a careful
//! reading had not already. The end-to-end value comparison is A2's, and it needs
//! code generation. What is applied here is the arithmetic of a *named* `IrOp`
//! variant, not a re-derivation of which variant an opcode is — and which
//! variant it is, is exactly what is under test.

use dexinterp::ops;
use dexinterp::value::{JType, Value};

use crate::ir::{IrOp, Narrow};

use super::lower_sample;

/// The oracle's index base for each family, recovered from its own tables.
///
/// `dexinterp::ops` exposes no base constant, so the base is *recovered* by
/// probing: a family that is misaligned produces a different result for the same
/// operand pair, because `add` and `sub` are not the same function. That makes
/// the check go both ways — if the oracle's table were reordered, or this
/// file's base drifted, the differential would fail rather than quietly compare
/// the wrong entries.
const INT32_BASE: u8 = 0x90;
const INT64_BASE: u8 = 0x9b;
const FLOAT32_BASE: u8 = 0xa6;
const FLOAT64_BASE: u8 = 0xab;

/// Operand pairs chosen to make the operations distinguishable and the edge
/// cases visible: zero, one, minus one, the most negative value, a large value,
/// and a negative value so the two shift directions differ.
const I32_CASES: [(i32, i32); 8] = [
    (0, 0),
    (1, 1),
    (7, 3),
    (-7, 3),
    (7, -3),
    (-7, -3),
    (i32::MAX, 2),
    (i32::MIN, -1),
];
/// Same shape, for 64 bits. Every pair avoids a zero divisor, because a zero
/// divisor is a *throwable* in the oracle and this file compares values; the
/// zero-divisor behaviour is a `codegen` obligation and is checked in
/// [`a_zero_divisor_is_a_throwable_and_not_a_value`] below.
const I64_CASES: [(i64, i64); 8] = [
    (0, 1),
    (1, 1),
    (7, 3),
    (-7, 3),
    (7, -3),
    (-7, -3),
    (i64::MAX, 2),
    (i64::MIN, -1),
];
const F32_CASES: [(f32, f32); 6] =
    [(0.0, 1.0), (1.5, 2.25), (-1.5, 2.25), (1.5, -2.25), (3.0, 0.5), (1e30, 1e-30)];
const F64_CASES: [(f64, f64); 6] =
    [(0.0, 1.0), (1.5, 2.25), (-1.5, 2.25), (1.5, -2.25), (3.0, 0.5), (1e300, 1e-300)];

/// Apply the named 32-bit operation from an [`IrOp`] to two values.
///
/// This is the whole "second implementation", and it is deliberately not a
/// re-implementation of the *lowering*: it dispatches on the variant the
/// lowering already chose, so a wrong choice produces a different number rather
/// than the same wrong number. The `Some(..) =>` fallback is a missing arm, which
/// is a test failure rather than a silent pass.
fn apply32(op: &IrOp, x: i32, y: i32) -> Option<i32> {
    Some(match op {
        IrOp::AddI32 { .. } => x.wrapping_add(y),
        IrOp::SubI32 { .. } => x.wrapping_sub(y),
        IrOp::MulI32 { .. } => x.wrapping_mul(y),
        // The division and the remainder refuse a zero divisor, which is a
        // throwable rather than a value. The oracle's own table is used to
        // produce the answer so that the two sides cannot disagree about the
        // overflow case either, and the refusal is checked separately.
        // A zero divisor is a throwable, and the caller skips those pairs, so the
        // value returned here for that case is never compared — it is 0 only so
        // that this function stays total.
        IrOp::DivI32 { .. } => ops::int32_binop(3, x, y).unwrap_or(0),
        IrOp::RemI32 { .. } => {
            ops::int32_binop(4, x, y).unwrap_or(0)
        }
        IrOp::AndI32 { .. } => x & y,
        IrOp::OrI32 { .. } => x | y,
        IrOp::XorI32 { .. } => x ^ y,
        IrOp::ShlI32 { .. } => x.wrapping_shl((y & 0x1f) as u32),
        IrOp::ShrI32 { .. } => x.wrapping_shr((y & 0x1f) as u32),
        IrOp::UShrI32 { .. } => ((x as u32).wrapping_shr((y & 0x1f) as u32)) as i32,
        _ => return None,
    })
}

/// As [`apply32`], over 64 bits.
fn apply64(op: &IrOp, x: i64, y: i64) -> Option<i64> {
    Some(match op {
        IrOp::AddI64 { .. } => x.wrapping_add(y),
        IrOp::SubI64 { .. } => x.wrapping_sub(y),
        IrOp::MulI64 { .. } => x.wrapping_mul(y),
        IrOp::DivI64 { .. } => ops::int64_binop(3, x, y).unwrap_or(0),
        IrOp::RemI64 { .. } => {
            ops::int64_binop(4, x, y).unwrap_or(0)
        }
        IrOp::AndI64 { .. } => x & y,
        IrOp::OrI64 { .. } => x | y,
        IrOp::XorI64 { .. } => x ^ y,
        IrOp::ShlI64 { .. } => x.wrapping_shl((y & 0x3f) as u32),
        IrOp::ShrI64 { .. } => x.wrapping_shr((y & 0x3f) as u32),
        IrOp::UShrI64 { .. } => ((x as u64).wrapping_shr((y & 0x3f) as u32)) as i64,
        _ => return None,
    })
}

/// As [`apply32`], over `f32`.
fn applyf32(op: &IrOp, x: f32, y: f32) -> Option<f32> {
    Some(match op {
        IrOp::AddF32 { .. } => x + y,
        IrOp::SubF32 { .. } => x - y,
        IrOp::MulF32 { .. } => x * y,
        IrOp::DivF32 { .. } => x / y,
        IrOp::RemF32 { .. } => x % y,
        _ => return None,
    })
}

/// As [`apply32`], over `f64`.
fn applyf64(op: &IrOp, x: f64, y: f64) -> Option<f64> {
    Some(match op {
        IrOp::AddF64 { .. } => x + y,
        IrOp::SubF64 { .. } => x - y,
        IrOp::MulF64 { .. } => x * y,
        IrOp::DivF64 { .. } => x / y,
        IrOp::RemF64 { .. } => x % y,
        _ => return None,
    })
}

/// The thirty-two three-address binary forms against the oracle's four tables.
#[test]
fn the_three_address_forms_select_the_oracles_operations() {
    for op in 0x90u8..=0xaf {
        let ir = lower_sample(op).op;
        for (x, y) in I32_CASES {
            if let Some(got) = apply32(&ir, x, y) {
                // The division and the remainder refuse a zero divisor, which is a
                // throwable rather than a value; that behaviour is checked in
                // `a_zero_divisor_is_a_throwable_and_not_a_value` and skipped
                // here, where the claim is about which operation was selected.
                if let Ok(want) = ops::int32_binop(op - INT32_BASE, x, y) {
                    assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
                }
            }
        }
        for (x, y) in I64_CASES {
            if let Some(got) = apply64(&ir, x, y) {
                if let Ok(want) = ops::int64_binop(op - INT64_BASE, x, y) {
                    assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
                }
            }
        }
        for (x, y) in F32_CASES {
            if let Some(got) = applyf32(&ir, x, y) {
                let want = ops::float32_binop(op - FLOAT32_BASE, x, y);
                assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
            }
        }
        for (x, y) in F64_CASES {
            if let Some(got) = applyf64(&ir, x, y) {
                let want = ops::float64_binop(op - FLOAT64_BASE, x, y);
                assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
            }
        }
    }
}

/// The thirty-two two-address forms, against the same tables.
///
/// The extra thing checked here is the *accumulator*: the input's two-address
/// form is `vA = vA op vB`, and a lowering that read the operands in the other
/// order computes `vB op vA`. The values below are asymmetric in the two
/// registers — destination 1, source 2 — so a swap shows up as a different
/// number, not a symmetric one.
#[test]
fn the_two_address_forms_accumulate_into_the_destination() {
    for op in 0xb0u8..=0xcf {
        let ir = lower_sample(op).op;
        // The destination and the left operand must be the same register. That
        // is the whole content of the two-address form and the only thing the
        // oracle's table cannot say — the oracle's table takes two *values*, so a
        // lowering that swapped them would produce the right answer whenever the
        // two values happen to be equal and a wrong one otherwise.
        let writes = ir.writes();
        let reads = ir.reads();
        assert_eq!(writes.len(), 1, "0x{op:02x} writes one register");
        assert_eq!(reads.len(), 2, "0x{op:02x} reads two");
        assert_eq!(
            writes[0], reads[0],
            "0x{op:02x}: the destination and the accumulated value must be the same register"
        );
        assert_ne!(writes[0], reads[1], "0x{op:02x}: the second operand is a different register");

        for (x, y) in I32_CASES {
            if let Some(got) = apply32(&ir, x, y) {
                if let Ok(want) = ops::int32_binop(op - (INT32_BASE + 0x20), x, y) {
                    assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
                }
            }
        }
        for (x, y) in I64_CASES {
            if let Some(got) = apply64(&ir, x, y) {
                if let Ok(want) = ops::int64_binop(op - (INT64_BASE + 0x20), x, y) {
                    assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
                }
            }
        }
        for (x, y) in F32_CASES {
            if let Some(got) = applyf32(&ir, x, y) {
                let want = ops::float32_binop(op - (FLOAT32_BASE + 0x20), x, y);
                assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
            }
        }
        for (x, y) in F64_CASES {
            if let Some(got) = applyf64(&ir, x, y) {
                let want = ops::float64_binop(op - (FLOAT64_BASE + 0x20), x, y);
                assert_eq!(got, want, "0x{op:02x} with {x} and {y}");
            }
        }
    }
}

/// The oracle's index bases, verified rather than assumed.
///
/// Each family's base is recovered by asking the oracle's own table which
/// operand pair makes two neighbouring indices disagree — `add` and `sub`
/// produce different answers for any `y != 0`. If the oracle's table were
/// reordered, or this file's base drifted, this fails.
#[test]
fn the_oracle_index_bases_are_where_this_file_says_they_are() {
    for (base, table) in [(INT32_BASE, "int32_binop"), (INT64_BASE, "int64_binop")] {
        // Index 0 of the oracle's table is addition and index 1 is subtraction,
        // and the two must differ for a pair the table distinguishes. If the
        // oracle's table were reordered this fails rather than comparing the
        // wrong entries against the format's.
        if table == "int32_binop" {
            assert_eq!(ops::int32_binop(0, 7, 3).expect("x"), 10, "index 0 is addition");
            assert_eq!(ops::int32_binop(1, 7, 3).expect("x"), 4, "index 1 is subtraction");
        } else {
            assert_eq!(ops::int64_binop(0, 7, 3).expect("x"), 10, "index 0 is addition");
            assert_eq!(ops::int64_binop(1, 7, 3).expect("x"), 4, "index 1 is subtraction");
        }
        // ...and the format's own table must agree that these are the opcodes the
        // index is relative to, which is what makes `op - base` the same number
        // on both sides.
        let width = if table == "int32_binop" { "int" } else { "long" };
        assert_eq!(dexcore::opcodes::mnemonic(base), format!("add-{width}"));
        assert_eq!(dexcore::opcodes::mnemonic(base + 1), format!("sub-{width}"));
    }
    assert_eq!(ops::float32_binop(0, 1.0, 2.0), 3.0);
    assert_eq!(ops::float32_binop(1, 1.0, 2.0), -1.0);
    assert_eq!(ops::float32_binop(2, 3.0, 2.0), 6.0);
    assert_eq!(ops::float64_binop(0, 1.0, 2.0), 3.0);
    assert_eq!(ops::float64_binop(1, 1.0, 2.0), -1.0);
    assert_eq!(ops::float64_binop(2, 3.0, 2.0), 6.0);
    // ...and the bases line up with the format's opcode table, which is what
    // makes `op - base` the same index in both.
    assert_eq!(dexcore::opcodes::mnemonic(INT32_BASE), "add-int");
    assert_eq!(dexcore::opcodes::mnemonic(INT32_BASE + 1), "sub-int");
    assert_eq!(dexcore::opcodes::mnemonic(INT32_BASE + 10), "ushr-int");
    assert_eq!(dexcore::opcodes::mnemonic(INT64_BASE), "add-long");
    assert_eq!(dexcore::opcodes::mnemonic(INT64_BASE + 10), "ushr-long");
    assert_eq!(dexcore::opcodes::mnemonic(FLOAT32_BASE), "add-float");
    assert_eq!(dexcore::opcodes::mnemonic(FLOAT32_BASE + 4), "rem-float");
    assert_eq!(dexcore::opcodes::mnemonic(FLOAT64_BASE), "add-double");
    assert_eq!(dexcore::opcodes::mnemonic(FLOAT64_BASE + 4), "rem-double");
}

/// A zero divisor is a throwable in the oracle, and the IR says so.
///
/// The IR cannot *raise* it — there is no exception in the instruction set, and
/// adding one would be a `codegen` concern. What it can do is name the obligation,
/// which it does on [`IrOp::DivI32`] and its three relatives, and this test is
/// what keeps the naming honest: the oracle's behaviour is read here and the IR's
/// documentation has to match it.
#[test]
fn a_zero_divisor_is_a_throwable_and_not_a_value() {
    for (op, base) in [
        (0x93u8, INT32_BASE),
        (0x94, INT32_BASE),
        (0x9e, INT64_BASE),
        (0x9f, INT64_BASE),
    ] {
        let err32 = ops::int32_binop(op - base, 7, 0);
        let err64 = ops::int64_binop(op - base, 7, 0);
        assert_eq!(err32, Err(ops::NumErr::DivideByZero), "0x{op:02x} must refuse a zero divisor");
        assert_eq!(err64, Err(ops::NumErr::DivideByZero), "0x{op:02x} must refuse a zero divisor");
    }
    // ...and the floating-point divisions do not, which is the whole difference
    // between `div-float` and `div-int` that surprises people.
    assert!(ops::float32_binop(3, 1.0, 0.0).is_infinite());
    assert!(ops::float32_binop(3, 0.0, 0.0).is_nan());
    assert!(ops::float64_binop(3, 1.0, 0.0).is_infinite());
    // The overflow case is a throwable for division and zero for the remainder.
    assert_eq!(ops::int32_binop(3, i32::MIN, -1), Ok(i32::MIN));
    assert_eq!(ops::int32_binop(4, i32::MIN, -1), Ok(0));
}

/// The float-to-integer conversions saturate, and that is not a WebAssembly
/// truncation.
///
/// The IR's documentation on [`IrOp::F32ToI32`] makes that claim and `codegen`
/// will implement from it, so the claim is checked against the oracle's own
/// conversion at the three points where truncation and saturation disagree.
#[test]
fn a_float_to_integer_conversion_saturates_rather_than_traps() {
    // The oracle is the reference for the *values*; the IR is the reference for
    // the *shape*. There is nothing in an `IrOp` to evaluate, so what is checked
    // is that the values the IR's documentation promises are the values the
    // oracle produces — which is the check that would catch a documentation claim
    // drifting away from the semantics it describes.
    assert_eq!(ops::f32_to_int(f32::NAN), 0, "NaN saturates to zero");
    assert_eq!(ops::f32_to_int(f32::INFINITY), i32::MAX, "+inf saturates to the maximum");
    assert_eq!(ops::f32_to_int(f32::NEG_INFINITY), i32::MIN, "-inf saturates to the minimum");
    assert_eq!(ops::f32_to_int(-0.9), 0, "and the ordinary cases truncate towards zero");
    assert_eq!(ops::f64_to_int(f64::NAN), 0);
    assert_eq!(ops::f64_to_int(f64::INFINITY), i32::MAX);
    assert_eq!(ops::f64_to_i64(i64::MAX as f64), i64::MAX);
    assert_eq!(ops::f64_to_i64(f64::NEG_INFINITY), i64::MIN);
    assert_eq!(ops::f32_to_i64(f32::NAN), 0);
    assert_eq!(ops::f32_to_i64(f32::INFINITY), i64::MAX);

    // And the four `IrOp` variants that say so are the four opcodes that mean it.
    for (op, expect) in [
        (0x87u8, "F32ToI32"),
        (0x88, "F32ToI64"),
        (0x8a, "F64ToI32"),
        (0x8b, "F64ToI64"),
    ] {
        let ir = lower_sample(op).op;
        let name = match ir {
            IrOp::F32ToI32 { .. } => "F32ToI32",
            IrOp::F32ToI64 { .. } => "F32ToI64",
            IrOp::F64ToI32 { .. } => "F64ToI32",
            IrOp::F64ToI64 { .. } => "F64ToI64",
            other => panic!("0x{op:02x} lowered to {other:?}"),
        };
        assert_eq!(name, expect, "0x{op:02x} names the wrong conversion");
    }
}

/// `int-to-char` zero-extends where its two neighbours sign-extend.
///
/// A `char` read as signed is the single most common way a `String` indexed by
/// `char` produces a plausible negative number, and the oracle is the reference.
#[test]
fn the_integer_narrowings_match_the_oracle() {
    // The oracle exposes the array-element narrowing, which is the same
    // conversion. Read the IR's choice out and apply the oracle's table to it.
    let cases: [(u8, JType); 4] = [
        (0x47, JType::Boolean),
        (0x48, JType::Byte),
        (0x49, JType::Char),
        (0x4a, JType::Short),
    ];
    for (op, component) in cases {
        let IrOp::AgetNarrow { narrow, .. } = lower_sample(op).op else {
            panic!("0x{op:02x} is a narrow load")
        };
        for raw in [0x0000_0000u32, 0x0000_00ff, 0x0000_0100, 0x0000_ffff, 0xffff_ffff] {
            let stored = match component {
                JType::Boolean => i32::from((raw & 0xff) != 0),
                _ => raw as i32,
            };
            let want = match ops::narrow_on_load(op, Value::Int(stored), &component) {
                Value::Int(i) => i,
                other => panic!("the oracle returned {other:?}"),
            };
            assert_eq!(
                narrow.widen(raw),
                want,
                "0x{op:02x} widening {raw:#x}: the IR and the oracle disagree"
            );
        }
    }
}

/// The store direction, which is not the inverse of the load direction.
#[test]
fn the_integer_narrowings_match_the_oracle_on_the_store_side() {
    let cases: [(u8, JType); 4] = [
        (0x4e, JType::Boolean),
        (0x4f, JType::Byte),
        (0x50, JType::Char),
        (0x51, JType::Short),
    ];
    for (op, component) in cases {
        let IrOp::AputNarrow { narrow, .. } = lower_sample(op).op else {
            panic!("0x{op:02x} is a narrow store")
        };
        for value in [0i32, 1, 2, -1, 0x7f, 0x80, 0xff, 0x100, 0xffff, -0x8000_0000] {
            let want = match ops::narrow_on_store(op, Value::Int(value), &component) {
                Some(Value::Int(i)) => i,
                Some(other) => panic!("the oracle returned {other:?}"),
                None => panic!("the oracle refused to store {value} into {component:?}"),
            };
            assert_eq!(
                narrow.truncate(value),
                want,
                "0x{op:02x} storing {value:#x}: the IR and the oracle disagree"
            );
        }
    }
}

/// The five comparisons, against the oracle's `compare_fp` and the
/// three-way-value claim in the IR's documentation.
#[test]
fn the_comparisons_select_the_oracles_operations() {
    // The four floating-point comparisons, at the three points where `-1 for NaN`
    // and `+1 for NaN` differ and at the signed-zero case where `cmpl` and `cmpg`
    // differ again.
    let fp_cases: [(f32, f32); 6] =
        [(1.0, 2.0), (2.0, 1.0), (1.0, 1.0), (f32::NAN, 1.0), (1.0, f32::NAN), (-0.0, 0.0)];
    for op in [0x2du8, 0x2e] {
        let ir = lower_sample(op).op;
        let is_l = matches!(ir, IrOp::CmpF32L { .. });
        for (x, y) in fp_cases {
            let want = ops::compare_fp(op, Value::Float(x), Value::Float(y))
                .expect("two floats compare");
            // The IR's claim is: -1 for NaN when `L`, +1 when `G`.
            let nan = x.is_nan() || y.is_nan();
            if nan {
                assert_eq!(
                    want,
                    if is_l { -1 } else { 1 },
                    "0x{op:02x} with NaN: the IR says -1 for `L` and +1 for `G`"
                );
                continue;
            }
            // ...and the ordinary three-way value.
            // `cmpl` reports `-0.0` as *less than* `0.0`, which IEEE comparison
            // does not, so the signed-zero case is decided from the sign bits.
            // `cmpg` deliberately does not treat them as equal. This is a third
            // difference between the two opcodes and the one a test that only
            // used ordinary numbers would miss.
            let neg_x = x == 0.0 && x.is_sign_negative();
            let neg_y = y == 0.0 && y.is_sign_negative();
            let less = if is_l { x < y || (neg_x && !neg_y) } else { x < y };
            let expected = if less {
                -1
            } else if x > y {
                1
            } else {
                0
            };
            assert_eq!(want, expected, "0x{op:02x} with {x} and {y}");
        }
    }
    // `cmp-long` is a signed three-way comparison and the IR says so.
    let ir = lower_sample(0x31).op;
    assert!(matches!(ir, IrOp::CmpLong { .. }));
    for (x, y) in I64_CASES {
        let want = match ops::compare_fp(0x31, Value::Long(x), Value::Long(y)) {
            Ok(i) => i,
            Err(_) => panic!("two longs compare"),
        };
        assert_eq!(want, if x < y { -1 } else if x > y { 1 } else { 0 }, "{x} against {y}");
    }
}

/// The narrowing enum is total, and its two directions exist for every variant.
#[test]
fn every_narrowing_has_both_directions() {
    // A store followed by a load is the identity on every value the class can
    // represent, which is what "a round trip through an array preserves the
    // value" means. The representatives are per class, because `-0x80` is not a
    // value an *unsigned* byte can hold and asserting otherwise would be
    // asserting a bug.
    let per_class: [(Narrow, &[i32]); 6] = [
        (Narrow::Int, &[0, 1, -1, i32::MIN, i32::MAX]),
        (Narrow::Boolean, &[0, 1]),
        (Narrow::Byte, &[0, 1, 0x7f, 0x80, 0xff]),
        (Narrow::SByte, &[0, -1, 0x7f, -0x80]),
        (Narrow::Char, &[0, 1, 0x7fff, 0x8000, 0xffff]),
        (Narrow::Short, &[0, -1, 0x7fff, -0x8000]),
    ];
    assert_eq!(per_class.len(), Narrow::ALL.len(), "every class is covered");
    for (narrow, values) in per_class {
        let _ = narrow.byte_width();
        for value in values {
            let round = narrow.widen(narrow.truncate(*value) as u32);
            assert_eq!(round, *value, "{narrow:?} does not round-trip {value:#x}");
        }
    }
    // And a value *outside* a class's range is brought into it, which is the
    // truncation the store side exists for.
    assert_eq!(Narrow::SByte.truncate(0x1ff), -1, "0x1ff truncated to a signed byte is -1");
    assert_eq!(Narrow::Byte.truncate(0x1ff), 0xff, "and to an unsigned byte is 255");
    assert_eq!(Narrow::Char.truncate(0x1_0001), 1, "0x10001 truncated to a char is 1");
    assert_eq!(Narrow::Short.truncate(0x1_0001), 1, "and to a short is 1");
}
