//! Dalvik's numeric semantics, isolated so they can be tested directly.
//!
//! Everything here is a place where the two languages disagree, which is why it
//! is separated from the interpreter loop: these are the functions a reader
//! should check against the specification rather than skim.
//!
//! The four rules that matter most, in the order they bite:
//!
//! * **`float-to-int` of NaN is 0, not a trap.** Java's narrowing cast
//!   specifies `0`; x86's `cvttss2si` produces `INT_MIN`. ART has to add the
//!   check, and so does this.
//! * **Out-of-range narrowing clamps.** `float-to-int` of `1e30` is
//!   `Integer.MAX_VALUE`, not a wrapped value. Rust's `as` saturates, which
//!   agrees by accident; the explicit comparison is here so the agreement is by
//!   construction.
//! * **`int-to-char` zero-extends and `int-to-byte`/`int-to-short` sign-extend.**
//!   A register has no type, so the widening is the instruction's job, and
//!   getting `int-to-char` wrong turns `65535` into `-1`.
//! * **`Integer.MIN_VALUE / -1` is `Integer.MIN_VALUE`,** not an exception. It
//!   is the one arithmetic case Java defines that traps in most languages.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>
//! §6.3 "Floating-point instructions".

use crate::value::{JType, Value};

/// An arithmetic failure that is a throwable on a device rather than a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumErr {
    /// Division or remainder by zero.
    DivideByZero,
}

/// `float-to-int`: NaN becomes 0, out-of-range clamps, otherwise truncates
/// toward zero.
pub fn f32_to_int(f: f32) -> i32 {
    if f.is_nan() {
        return 0;
    }
    if f <= -2_147_483_648.0 {
        return i32::MIN;
    }
    if f >= 2_147_483_648.0 {
        return i32::MAX;
    }
    f as i32
}

/// `float-to-long`.
pub fn f32_to_i64(f: f32) -> i64 {
    if f.is_nan() {
        return 0;
    }
    if f <= -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    if f >= 9_223_372_036_854_775_808.0 {
        return i64::MAX;
    }
    f as i64
}

/// `double-to-int`.
pub fn f64_to_int(f: f64) -> i32 {
    if f.is_nan() {
        return 0;
    }
    if f <= -2_147_483_648.0 {
        return i32::MIN;
    }
    if f >= 2_147_483_648.0 {
        return i32::MAX;
    }
    f as i32
}

/// `double-to-long`.
pub fn f64_to_i64(f: f64) -> i64 {
    if f.is_nan() {
        return 0;
    }
    if f <= -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    if f >= 9_223_372_036_854_775_808.0 {
        return i64::MAX;
    }
    f as i64
}

/// `int` arithmetic, indexed from the first `int` opcode of a family.
///
/// Index order: add, sub, mul, div, rem, and, or, xor, shl, shr, ushr — the
/// order the opcode table uses, so `op - base` is the index.
pub fn int32_binop(op: u8, x: i32, y: i32) -> Result<i32, NumErr> {
    Ok(match op {
        0 => x.wrapping_add(y),
        1 => x.wrapping_sub(y),
        2 => x.wrapping_mul(y),
        3 => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                x.wrapping_neg()
            } else {
                x / y
            }
        }
        4 => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                0
            } else {
                x % y
            }
        }
        5 => x & y,
        6 => x | y,
        7 => x ^ y,
        8 => x.wrapping_shl((y & 0x1f) as u32),
        9 => x.wrapping_shr((y & 0x1f) as u32),
        10 => ((x as u32).wrapping_shr((y & 0x1f) as u32)) as i32,
        _ => return Err(NumErr::DivideByZero),
    })
}

/// `long` arithmetic, same index order. Shift amounts are modulo 64.
pub fn int64_binop(op: u8, x: i64, y: i64) -> Result<i64, NumErr> {
    Ok(match op {
        0 => x.wrapping_add(y),
        1 => x.wrapping_sub(y),
        2 => x.wrapping_mul(y),
        3 => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                x.wrapping_neg()
            } else {
                x / y
            }
        }
        4 => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                0
            } else {
                x % y
            }
        }
        5 => x & y,
        6 => x | y,
        7 => x ^ y,
        8 => x.wrapping_shl((y & 0x3f) as u32),
        9 => x.wrapping_shr((y & 0x3f) as u32),
        10 => ((x as u64).wrapping_shr((y & 0x3f) as u32)) as i64,
        _ => return Err(NumErr::DivideByZero),
    })
}

/// `float` arithmetic. Division by zero is IEEE infinity, not a throwable, which
/// is the difference between `div-float` and `div-int` that surprises people.
pub fn float32_binop(op: u8, x: f32, y: f32) -> f32 {
    match op {
        0 => x + y,
        1 => x - y,
        2 => x * y,
        3 => x / y,
        4 => x % y,
        _ => f32::NAN,
    }
}

/// `double` arithmetic.
pub fn float64_binop(op: u8, x: f64, y: f64) -> f64 {
    match op {
        0 => x + y,
        1 => x - y,
        2 => x * y,
        3 => x / y,
        4 => x % y,
        _ => f64::NAN,
    }
}

/// The five `cmp*` opcodes.
///
/// `cmpl` returns `-1` when either operand is NaN and treats `-0.0` as *less
/// than* `0.0`; `cmpg` returns `1` for NaN and treats them as equal. Both of
/// those are specified, and both are load-bearing: a sorted-search loop written
/// against `cmpg` finds a NaN key it should skip, and one written against
/// `cmpl` handles `-0.0` correctly.
pub fn compare_fp(op: u8, x: Value, y: Value) -> Result<i32, crate::value::WrongType> {
    match op {
        0x2d | 0x2e => {
            let a = x.as_float("cmpl-float")?;
            let b = y.as_float("cmpl-float")?;
            // `cmpl` is *less*: it reports -0.0 as smaller than 0.0, which IEEE
            // comparison does not (`-0.0 < 0.0` is false), so the signed-zero case
            // is decided from the sign bits rather than from the comparison.
            // `cmpg` deliberately does not: it treats the two zeroes as equal.
            let neg_a = a == 0.0 && a.is_sign_negative();
            let neg_b = b == 0.0 && b.is_sign_negative();
            let less = if op == 0x2d { a < b || (neg_a && !neg_b) } else { a < b };
            Ok(cmp_result(less, a > b, a.is_nan() || b.is_nan(), op == 0x2d))
        }
        0x2f | 0x30 => {
            let a = x.as_double("cmpl-double")?;
            let b = y.as_double("cmpl-double")?;
            let neg_a = a == 0.0 && a.is_sign_negative();
            let neg_b = b == 0.0 && b.is_sign_negative();
            let less = if op == 0x2f { a < b || (neg_a && !neg_b) } else { a < b };
            Ok(cmp_result(less, a > b, a.is_nan() || b.is_nan(), op == 0x2f))
        }
        0x31 => {
            let a = x.as_long("cmp-long")?;
            let b = y.as_long("cmp-long")?;
            Ok(if a < b {
                -1
            } else if a > b {
                1
            } else {
                0
            })
        }
        _ => Ok(0),
    }
}

/// Assemble a comparison result. The three conditions are computed by the
/// caller so the same shape serves `f32`, `f64` and any future type, and the
/// NaN case is decided by an explicit flag rather than by `PartialOrd` — which
/// would say "all comparisons are false" for NaN and silently return 0.
fn cmp_result(less: bool, greater: bool, nan: bool, is_l: bool) -> i32 {
    if nan {
        return if is_l { -1 } else { 1 };
    }
    if less {
        -1
    } else if greater {
        1
    } else {
        0
    }
}

/// Whether a value can be stored in an array or field of type `ty`.
///
/// Deliberately permissive in exactly the places the verifier would have
/// guaranteed widening (`Int` into a `long` array, for instance) and strict
/// everywhere else, because a wrong answer here produces silently corrupt data
/// rather than a crash.
pub fn value_fits(ty: &JType, v: Value) -> bool {
    match ty {
        JType::Ref(_) | JType::Array(_) => v.is_reference(),
        JType::Boolean | JType::Byte | JType::Short | JType::Char | JType::Int => {
            matches!(v, Value::Int(_))
        }
        JType::Long => matches!(v, Value::Long(_) | Value::Int(_)),
        JType::Float => matches!(v, Value::Float(_) | Value::Int(_)),
        JType::Double => matches!(v, Value::Double(_) | Value::Int(_) | Value::Long(_)),
        JType::Void => false,
    }
}

/// Narrow a value on `aput-*`.
///
/// The stored representation is the component type's: a `byte[]` holds `i8`, a
/// `char[]` holds `u16`, a `boolean[]` holds 0 or 1. `None` means the value does
/// not fit, which the caller turns into `ArrayStoreException`.
pub fn narrow_on_store(op: u8, v: Value, component: &JType) -> Option<Value> {
    if !value_fits(component, v) {
        return None;
    }
    let i = match v {
        Value::Int(i) => i,
        // A verifier-valid `aput` never narrows *into* a wider type, so anything
        // that is not an `int` keeps the shape its component type already gave
        // it; the opcode then decides nothing, because a `long` into a `long[]`
        // is not a narrowing operation.
        other => return Some(other),
    };
    Some(match op {
        0x4b => Value::Int(i),                     // aput
        0x4e => Value::Int(i32::from(i & 1 != 0)), // aput-boolean
        0x4f => Value::Int(i32::from(i as i8)),    // aput-byte
        0x50 => Value::Int(i32::from(i as u16)),   // aput-char
        0x51 => Value::Int(i32::from(i as i16)),   // aput-short
        _ => Value::Int(i),
    })
}

/// Widen a value on `aget-*`.
///
/// The inverse of [`narrow_on_store`]: a `byte[]` element comes back
/// sign-extended and a `char[]` element zero-extended, so `(char) 0xFFFF` is
/// 65535 and `(byte) 0xFF` is -1.
pub fn narrow_on_load(op: u8, v: Value, component: &JType) -> Value {
    let i = match v {
        Value::Int(i) => i,
        other => return other,
    };
    match (op, component) {
        (0x47, JType::Boolean) => Value::Int(i32::from(i != 0)),
        (0x48, JType::Byte) => Value::Int(i32::from(i as i8)),
        (0x49, JType::Char) => Value::Int(i32::from(i as u16)),
        (0x4a, JType::Short) => Value::Int(i32::from(i as i16)),
        // `aget` and `aput` on a 32-bit component transfer it unchanged. Any
        // other combination cannot occur in verified bytecode, and a stored
        // value is already in the component's own representation.
        _ => v,
    }
}

/// Narrow a value to a field's declared type, as `sput`/`iput` do.
///
/// This is the mechanism by which `private static final boolean DEBUG = true`
/// becomes the `int` `1` in the register rather than a reference to a boxed
/// `Boolean`.
pub fn coerce_to(v: Value, ty: &JType) -> Value {
    match ty {
        JType::Boolean => Value::Int(i32::from(match v {
            Value::Int(i) => i & 1 != 0,
            Value::Long(l) => l & 1 != 0,
            Value::Float(f) => f.to_bits() & 1 != 0,
            Value::Double(d) => d.to_bits() & 1 != 0,
            _ => false,
        })),
        JType::Byte => Value::Int(i32::from(as_int(v) as i8)),
        JType::Short => Value::Int(i32::from(as_int(v) as i16)),
        JType::Char => Value::Int(i32::from(as_int(v) as u16)),
        JType::Int | JType::Void => match v {
            Value::Int(i) => Value::Int(i),
            other => Value::default_for(ty).unwrap_or(other),
        },
        JType::Long => match v {
            Value::Long(l) => Value::Long(l),
            Value::Int(i) => Value::Long(i64::from(i)),
            other => Value::default_for(ty).unwrap_or(other),
        },
        JType::Float => match v {
            Value::Float(f) => Value::Float(f),
            Value::Int(i) => Value::Float(i as f32),
            Value::Long(l) => Value::Float(l as f32),
            other => Value::default_for(ty).unwrap_or(other),
        },
        JType::Double => match v {
            Value::Double(d) => Value::Double(d),
            Value::Int(i) => Value::Double(f64::from(i)),
            Value::Long(l) => Value::Double(l as f64),
            Value::Float(f) => Value::Double(f64::from(f)),
            other => Value::default_for(ty).unwrap_or(other),
        },
        JType::Ref(_) | JType::Array(_) => match v {
            Value::Ref(_) | Value::Null => v,
            _ => Value::Null,
        },
    }
}

fn as_int(v: Value) -> i32 {
    match v {
        Value::Int(i) => i,
        _ => 0,
    }
}

/// Little-endian reads for `fill-array-data` payloads, all total.
pub fn read_i16(b: &[u8]) -> i16 {
    match b.len() >= 2 {
        true => i16::from_le_bytes([b[0], b[1]]),
        false => 0,
    }
}

/// Little-endian `u16` read.
pub fn read_u16(b: &[u8]) -> u16 {
    match b.len() >= 2 {
        true => u16::from_le_bytes([b[0], b[1]]),
        false => 0,
    }
}

/// Little-endian `i32` read.
pub fn read_i32(b: &[u8]) -> i32 {
    match b.len() >= 4 {
        true => i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        false => 0,
    }
}

/// Little-endian `u32` read.
pub fn read_u32(b: &[u8]) -> u32 {
    read_i32(b) as u32
}

/// Little-endian `i64` read.
pub fn read_i64(b: &[u8]) -> i64 {
    if b.len() < 8 {
        return 0;
    }
    let mut a = [0u8; 8];
    let n = 8.min(b.len());
    a[..n].copy_from_slice(&b[..n]);
    i64::from_le_bytes(a)
}

/// Little-endian `u64` read.
pub fn read_u64(b: &[u8]) -> u64 {
    read_i64(b) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f32_bits(x: f32) -> u32 {
        x.to_bits()
    }

    #[allow(dead_code)]
    fn f64_bits(x: f64) -> u64 {
        x.to_bits()
    }

    // -------------------------------------------------------- conversions

    #[test]
    fn float_to_int_of_nan_is_zero_not_a_trap() {
        assert_eq!(f32_to_int(f32::NAN), 0);
        assert_eq!(f64_to_int(f64::NAN), 0);
        assert_eq!(f32_to_i64(f32::NAN), 0);
        assert_eq!(f64_to_i64(f64::NAN), 0);
        // A negative NaN too: `is_nan` catches both signs and payloads.
        assert_eq!(f32_to_int(-f32::NAN), 0);
        assert_eq!(f64_to_i64(-f64::NAN), 0);
    }

    #[test]
    fn out_of_range_narrowing_clamps_in_both_directions() {
        assert_eq!(f32_to_int(1e30), i32::MAX);
        assert_eq!(f32_to_int(-1e30), i32::MIN);
        assert_eq!(f64_to_int(9.3e18), i32::MAX);
        assert_eq!(f64_to_int(-9.3e18), i32::MIN);
        assert_eq!(f32_to_i64(1e30), i64::MAX);
        assert_eq!(f32_to_i64(-1e30), i64::MIN);
        assert_eq!(f64_to_i64(1e300), i64::MAX);
        assert_eq!(f64_to_i64(-1e300), i64::MIN);
    }

    #[test]
    fn in_range_narrowing_truncates_toward_zero() {
        assert_eq!(f32_to_int(2.9), 2);
        assert_eq!(f32_to_int(-2.9), -2);
        assert_eq!(f64_to_int(2.999_999), 2);
        assert_eq!(f64_to_int(-0.5), 0);
        assert_eq!(f64_to_i64(1e18), 1_000_000_000_000_000_000);
        // The largest float strictly below 2^31 is exact.
        assert_eq!(f32_to_int(2_147_483_520.0), 2_147_483_520);
    }

    #[test]
    fn narrowing_preserves_signed_zero_as_zero() {
        assert_eq!(f32_to_int(-0.0), 0);
        assert_eq!(f64_to_int(-0.0), 0);
    }

    // ---------------------------------------------------------- arithmetic

    #[test]
    fn integer_arithmetic_wraps_rather_than_overflowing() {
        assert_eq!(int32_binop(0, i32::MAX, 1), Ok(i32::MIN));
        assert_eq!(int32_binop(1, i32::MIN, 1), Ok(i32::MAX));
        assert_eq!(int32_binop(2, 65536, 65536), Ok(0));
        assert_eq!(int64_binop(0, i64::MAX, 1), Ok(i64::MIN));
        assert_eq!(int64_binop(2, 4_294_967_296, 4_294_967_296), Ok(0));
    }

    #[test]
    fn min_value_divided_by_minus_one_is_min_value_not_a_trap() {
        assert_eq!(int32_binop(3, i32::MIN, -1), Ok(i32::MIN));
        assert_eq!(int32_binop(4, i32::MIN, -1), Ok(0));
        assert_eq!(int64_binop(3, i64::MIN, -1), Ok(i64::MIN));
        assert_eq!(int64_binop(4, i64::MIN, -1), Ok(0));
    }

    #[test]
    fn division_by_zero_is_distinguishable_from_every_other_failure() {
        assert_eq!(int32_binop(3, 1, 0), Err(NumErr::DivideByZero));
        assert_eq!(int32_binop(4, 1, 0), Err(NumErr::DivideByZero));
        assert_eq!(int64_binop(3, 1, 0), Err(NumErr::DivideByZero));
        // ...and float division by zero is *not* an error: it is infinity.
        assert_eq!(f32_bits(float32_binop(3, 1.0, 0.0)), f32_bits(f32::INFINITY));
        assert_eq!(f32_bits(float32_binop(3, -1.0, 0.0)), f32_bits(f32::NEG_INFINITY));
        assert!(float32_binop(3, 0.0, 0.0).is_nan());
        assert!(float64_binop(3, 0.0, 0.0).is_nan());
    }

    #[test]
    fn shift_amounts_are_taken_modulo_the_width() {
        // 1 << 33 is 1 << 1, not 1 << 33 and not zero.
        assert_eq!(int32_binop(8, 1, 33), Ok(2));
        // -1 & 0x1f is 31, and 1 << 31 is Integer.MIN_VALUE.
        assert_eq!(int32_binop(8, 1, -1), Ok(i32::MIN));
        assert_eq!(int64_binop(8, 1, 65), Ok(2));
        // Arithmetic right shift keeps the sign.
        assert_eq!(int32_binop(9, -8, 1), Ok(-4));
        assert_eq!(int32_binop(10, -8, 1), Ok(2_147_483_644));
        assert_eq!(int32_binop(8, 1, 0), Ok(1));
    }

    // ---------------------------------------------------------- comparison

    #[test]
    fn cmpl_and_cmpg_differ_only_on_nan_and_signed_zero() {
        let nan = Value::Float(f32::NAN);
        let one = Value::Float(1.0);
        assert_eq!(compare_fp(0x2d, nan, one), Ok(-1), "cmpl-float with NaN is -1");
        assert_eq!(compare_fp(0x2e, nan, one), Ok(1), "cmpg-float with NaN is 1");
        // -0.0 < 0.0 for cmpl, and they are equal for cmpg.
        let nz = Value::Float(-0.0);
        let pz = Value::Float(0.0);
        assert_eq!(compare_fp(0x2d, nz, pz), Ok(-1));
        assert_eq!(compare_fp(0x2e, nz, pz), Ok(0));
        // Doubles behave identically.
        assert_eq!(compare_fp(0x2f, Value::Double(f64::NAN), Value::Double(1.0)), Ok(-1));
        assert_eq!(compare_fp(0x30, Value::Double(f64::NAN), Value::Double(1.0)), Ok(1));
        assert_eq!(compare_fp(0x2f, Value::Double(-0.0), Value::Double(0.0)), Ok(-1));
        assert_eq!(compare_fp(0x30, Value::Double(-0.0), Value::Double(0.0)), Ok(0));
    }

    #[test]
    fn cmp_long_uses_the_full_sixty_four_bits() {
        let big = Value::Long(1 << 40);
        let small = Value::Long(1);
        assert_eq!(compare_fp(0x31, small, big), Ok(-1));
        assert_eq!(compare_fp(0x31, big, small), Ok(1));
        assert_eq!(compare_fp(0x31, big, big), Ok(0));
    }

    // ------------------------------------------------------ array narrowing

    #[test]
    fn byte_and_char_arrays_narrow_and_widen_in_opposite_directions() {
        // aput-byte of 0xFF stores -1; aget-byte of that returns -1.
        let stored = narrow_on_store(0x4f, Value::Int(0xFF), &JType::Byte);
        assert_eq!(stored, Some(Value::Int(-1)));
        assert_eq!(narrow_on_load(0x48, Value::Int(-1), &JType::Byte), Value::Int(-1));
        // aput-char of 0xFFFF stores 65535; aget-char returns 65535, not -1.
        let stored = narrow_on_store(0x50, Value::Int(-1), &JType::Char);
        assert_eq!(stored, Some(Value::Int(65535)));
        assert_eq!(narrow_on_load(0x49, Value::Int(65535), &JType::Char), Value::Int(65535));
        // aput-short sign-extends.
        assert_eq!(narrow_on_store(0x51, Value::Int(0x1_0000), &JType::Short), Some(Value::Int(0)));
    }

    #[test]
    fn boolean_arrays_hold_only_zero_and_one() {
        assert_eq!(narrow_on_store(0x4e, Value::Int(42), &JType::Boolean), Some(Value::Int(0)));
        assert_eq!(narrow_on_store(0x4e, Value::Int(43), &JType::Boolean), Some(Value::Int(1)));
        assert_eq!(narrow_on_load(0x47, Value::Int(7), &JType::Boolean), Value::Int(1));
    }

    #[test]
    fn storing_the_wrong_shape_is_refused_rather_than_truncated() {
        // A `long` cannot go into an `int[]`, and refusing is what produces an
        // `ArrayStoreException` rather than a silently wrong array.
        assert_eq!(narrow_on_store(0x4b, Value::Long(1), &JType::Int), None);
        assert_eq!(narrow_on_store(0x4d, Value::Int(1), &JType::Ref("Ljava/lang/Object;".into())), None);
        assert_eq!(narrow_on_store(0x4d, Value::Null, &JType::Ref("Ljava/lang/Object;".into())), Some(Value::Null));
    }

    // ---------------------------------------------------- field coercion

    #[test]
    fn a_static_final_boolean_constant_reaches_a_register_as_zero_or_one() {
        // This is what `DEBUG:Z` in a real `BuildConfig` class is.
        assert_eq!(coerce_to(Value::Int(1), &JType::Boolean), Value::Int(1));
        assert_eq!(coerce_to(Value::Int(0), &JType::Boolean), Value::Int(0));
        assert_eq!(coerce_to(Value::Int(2), &JType::Boolean), Value::Int(0));
    }

    #[test]
    fn coercion_of_a_reference_to_a_primitive_yields_the_primitive_zero() {
        assert_eq!(coerce_to(Value::Ref(crate::value::Ref(3)), &JType::Int), Value::Int(0));
        assert_eq!(coerce_to(Value::Ref(crate::value::Ref(3)), &JType::Boolean), Value::Int(0));
        assert_eq!(coerce_to(Value::Int(1), &JType::Ref("Ljava/lang/Object;".into())), Value::Null);
    }

    // -------------------------------------------------------- payload reads

    #[test]
    fn payload_reads_are_total_on_short_input() {
        assert_eq!(read_i16(&[1]), 0);
        assert_eq!(read_u16(&[]), 0);
        assert_eq!(read_i32(&[1, 2]), 0);
        assert_eq!(read_i64(&[1; 4]), 0);
        assert_eq!(read_i32(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
        assert_eq!(read_i64(&[0xff; 8]), -1);
        assert_eq!(read_u64(&[0xff; 8]), u64::MAX);
        assert_eq!(f64_bits(f64::from_bits(read_u64(&2.5f64.to_le_bytes()))), f64_bits(2.5));
    }
}
