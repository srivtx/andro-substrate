//! Per-family semantic tests: hand-assembled methods with exact expected
//! results.
//!
//! Where [`coverage.rs`](coverage.rs) proves that every opcode *runs*, this suite
//! proves that a representative of every family runs *correctly*. The expected
//! values are hand-computed from the Dalvik specification rather than from the
//! interpreter, so a mistake in one is a mistake in the other and the test fails.
//!
//! The families are in the order the specification introduces them: constants,
//! moves, the unary conversions, binary arithmetic, arrays, fields, calls,
//! control flow, payloads, and monitors.

mod common;

use std::collections::BTreeMap;

use common::*;
use dexcore::writer::{ClassDef, CodeBody, FieldDef, MethodDef};
use dexcore::model::access;

use dexinterp::host::HostValue;
use dexinterp::{Config, Termination, Value};

/// Declare one method per case, emit, and check each against its expected
/// result. Each case runs in a *fresh* interpreter, so the heap and the counters
/// cannot leak between them.
fn check(cases: &[(&str, CodeBody, Value)], ret: &str) {
    let mut s = Synthetic::new();
    for (n, b, _) in cases {
        s.declare(n, &[], ret, b.registers_size, b.outs_size);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(move |_i| {
            cases.iter().map(|(n, b, _)| (n.to_string(), b.clone())).collect::<BTreeMap<_, _>>()
        })
        .expect("emit");
    for (n, _, want) in cases {
        let mut vm = vm(&bytes, Config::default(), None).expect("open");
        let sig = format!("(){ret}");
        assert_eq!(call0(&mut vm, n, &sig).unwrap(), *want, "{n}");
    }
}

/// A body with a `const/4 v0, #lit; return v0` preamble, for the simple cases.
fn ret4(lit: i32) -> CodeBody {
    let mut e = Emit::new();
    e.const4(0, lit as i8);
    e.op11x(0x0f, 0);
    e.code(2, 0, 0)
}

// ============================================================== constants

#[test]
fn constants_of_every_width_land_in_the_right_register() {
    let mut a = Emit::new();
    a.const4(0, -1);
    a.op11x(0x0f, 0);
    let mut b = Emit::new();
    b.const16(0x13, 0, -32768);
    b.op11x(0x0f, 0);
    let mut c = Emit::new();
    c.const32(0x14, 0, i32::MIN);
    c.op11x(0x0f, 0);
    // `const/high16` puts a 16-bit literal in the *high* half.
    let mut d = Emit::new();
    d.const_high16(0x15, 0, 0x7fff);
    d.op11x(0x0f, 0);
    let mut e = Emit::new();
    e.const4(0, -8);
    e.op11x(0x0f, 0);
    let mut f = Emit::new();
    f.op11x(0x0e, 0);
    let mut g = Emit::new();
    g.nop();
    g.const4(0, 3);
    g.op11x(0x0f, 0);

    let cases = [
        ("k4m1", a, Value::Int(-1)),
        ("k4m8", e, Value::Int(-8)),
        ("k16", b, Value::Int(-32768)),
        ("k32", c, Value::Int(i32::MIN)),
        ("kHigh16", d, Value::Int(0x7fff_0000u32 as i32)),
        ("kVoid", f, Value::Void),
        ("kNop", g, Value::Int(3)),
    ];
    let owned: Vec<(String, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (n.to_string(), e.clone().code(4, 0, 0), *v))
        .collect();
    let refs: Vec<(&str, CodeBody, Value)> =
        owned.iter().map(|(n, b, v)| (n.as_str(), b.clone(), *v)).collect();
    check(&refs, "I");
}

#[test]
fn wide_constants_sign_extend_and_occupy_two_registers() {
    let mut s = Synthetic::new();
    for n in ["wmin", "whigh", "w32", "w16", "wfull"] {
        s.declare(n, &[], "J", 4, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.const_wide(0x18, 0, i64::MIN);
            a.op11x(0x10, 0);
            out.insert("wmin".to_string(), a.code(4, 0, 0));
            // `const-wide/high16` shifts a *signed* 16-bit literal left 16.
            let mut b = Emit::new();
            b.const_high16(0x19, 0, -1);
            b.op11x(0x10, 0);
            out.insert("whigh".to_string(), b.code(4, 0, 0));
            // `const-wide/32` sign-extends 32 bits into 64.
            let mut c = Emit::new();
            c.const32(0x17, 0, -1);
            c.op11x(0x10, 0);
            out.insert("w32".to_string(), c.code(4, 0, 0));
            let mut d = Emit::new();
            d.const16(0x16, 0, -2);
            d.op11x(0x10, 0);
            out.insert("w16".to_string(), d.code(4, 0, 0));
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 0x0123_4567_89ab_cdef);
            e.op11x(0x10, 0);
            out.insert("wfull".to_string(), e.code(4, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "wmin", "()J").unwrap(), Value::Long(i64::MIN));
    assert_eq!(call0(&mut vm, "whigh", "()J").unwrap(), Value::Long(-65536));
    assert_eq!(call0(&mut vm, "w32", "()J").unwrap(), Value::Long(-1));
    assert_eq!(call0(&mut vm, "w16", "()J").unwrap(), Value::Long(-2));
    assert_eq!(
        call0(&mut vm, "wfull", "()J").unwrap(),
        Value::Long(0x0123_4567_89ab_cdef)
    );
}

// ================================================================== moves

#[test]
fn wide_moves_copy_both_words_and_narrow_moves_copy_one() {
    let mut s = Synthetic::new();
    for n in ["mv16", "mvFrom16", "mvObjFrom16", "mvObj16", "mvWide16"] {
        s.declare(n, &[], "I", 4, 0);
    }
    s.declare("mvWide", &[], "J", 4, 0);
    s.declare("mvWide16", &[], "J", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut b = Emit::new();
            b.const16(0x13, 1, 7);
            b.const16(0x13, 2, 9);
            b.op32x(0x03, 3, 2); // move/16 v3, v2
            b.op11x(0x0f, 3);
            out.insert("mv16".to_string(), b.code(4, 0, 0));
            let mut c = Emit::new();
            c.const4(0, 5);
            c.op22x(0x02, 1, 0); // move/from16 v1, v0
            c.op11x(0x0f, 1);
            out.insert("mvFrom16".to_string(), c.code(4, 0, 0));
            // `move-object/from16` is a reference move, but the register holds an
            // int here and the engine must not care: a register has no type.
            let mut d = Emit::new();
            d.const4(0, 3);
            d.op22x(0x08, 1, 0);
            d.op11x(0x0f, 1);
            out.insert("mvObjFrom16".to_string(), d.code(4, 0, 0));
            let mut e = Emit::new();
            e.const4(0, 4);
            e.op32x(0x09, 1, 0);
            e.op11x(0x0f, 1);
            out.insert("mvObj16".to_string(), e.code(4, 0, 0));
            let mut f = Emit::new();
            f.const_wide(0x18, 0, 0x0102_0304_0506_0708);
            f.op12x(0x04, 2, 0); // move-wide v2, v0
            f.op11x(0x10, 2);
            out.insert("mvWide".to_string(), f.code(4, 0, 0));
            let mut g = Emit::new();
            g.const_wide(0x18, 0, -3);
            g.op22x(0x05, 2, 0); // move-wide/from16 v2, v0
            g.op11x(0x10, 2);
            out.insert("mvWide16".to_string(), g.code(4, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "mv16", "()I").unwrap(), Value::Int(9));
    assert_eq!(call0(&mut vm, "mvFrom16", "()I").unwrap(), Value::Int(5));
    assert_eq!(call0(&mut vm, "mvObjFrom16", "()I").unwrap(), Value::Int(3));
    assert_eq!(call0(&mut vm, "mvObj16", "()I").unwrap(), Value::Int(4));
    assert_eq!(
        call0(&mut vm, "mvWide", "()J").unwrap(),
        Value::Long(0x0102_0304_0506_0708)
    );
    assert_eq!(call0(&mut vm, "mvWide16", "()J").unwrap(), Value::Long(-3));
}

// ============================================================ 12x: unary

#[test]
fn the_narrowing_conversions_follow_the_java_rules() {
    let cases = [
        // `int-to-char` is the one that goes wrong silently: as a sign extension
        // it turns 65535 into -1 and every `Character` comparison inverts.
        ("toByte", int_conv(0x8d, 0xFF), Value::Int(-1)),
        ("toChar", int_conv(0x8e, -1), Value::Int(65535)),
        ("toShort", int_conv(0x8f, 0x1_0000), Value::Int(0)),
        ("notInt", int_conv(0x7c, 0), Value::Int(-1)),
        ("negMin", int_conv(0x7b, i32::MIN), Value::Int(i32::MIN)),
        ("longToInt", long_conv(0x84, 0x1_0000_0007), Value::Int(7)),
        ("intToLong", long_conv(0x81, -5), Value::Long(-5)),
        ("intToFloat", long_conv(0x82, 1 << 24), Value::Float(1.6777216e7)),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&refs, "I");
}

fn int_conv(op: u8, literal: i32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, literal);
    a.op12x(op, 1, 0);
    a.op11x(0x0f, 1);
    a
}

fn long_conv(op: u8, literal: i64) -> Emit {
    let mut a = Emit::new();
    a.const_wide(0x18, 0, literal);
    a.op12x(op, 2, 0);
    a.op11x(0x0f, 2);
    a
}

#[test]
fn float_to_int_of_nan_is_zero_and_out_of_range_clamps() {
    let nan32 = f32::NAN.to_bits();
    let nan64 = f64::NAN.to_bits() as i64;
    let cases = [
        ("f2iNan", f2i(0x87, nan32), Value::Int(0)),
        ("f2iBig", f2i(0x87, 1e30f32.to_bits()), Value::Int(i32::MAX)),
        ("f2iSmall", f2i(0x87, (-1e30f32).to_bits()), Value::Int(i32::MIN)),
        ("f2iTrunc", f2i(0x87, 2.9f32.to_bits()), Value::Int(2)),
        ("f2iNeg", f2i(0x87, (-2.9f32).to_bits()), Value::Int(-2)),
        ("d2iNan", d2i(nan64), Value::Int(0)),
        ("d2iBig", d2i(1e300f64.to_bits() as i64), Value::Int(i32::MAX)),
        ("d2iTrunc", d2i((-2.9f64).to_bits() as i64), Value::Int(-2)),
        ("f2lNan", f2l(0x88, nan32), Value::Long(0)),
        ("f2lBig", f2l(0x88, 1e30f32.to_bits()), Value::Long(i64::MAX)),
        ("d2lNeg", d2l((-1e300f64).to_bits() as i64), Value::Long(i64::MIN)),
        ("f2d", f2d(nan32), Value::Double(f64::from(f32::NAN))),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&refs, "I");
    // The wide cases need a `()J` signature to be returned faithfully.
    let wide: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .filter(|(n, _, _)| matches!(*n, "f2lNan" | "f2lBig" | "d2lNeg"))
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&wide, "J");
}

fn f2i(op: u8, bits: u32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, bits as i32);
    a.op12x(0x82, 0, 0); // int-to-float v0, v0
    a.op12x(op, 1, 0);
    a.op11x(0x0f, 1);
    a
}

fn f2l(op: u8, bits: u32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, bits as i32);
    a.op12x(0x82, 0, 0);
    a.op12x(op, 1, 0);
    a.op11x(0x10, 1);
    a
}

fn d2i(bits: i64) -> Emit {
    let mut a = Emit::new();
    a.const_wide(0x18, 0, bits);
    a.op12x(0x86, 0, 0); // long-to-double
    a.op12x(0x8a, 1, 0); // double-to-int
    a.op11x(0x0f, 1);
    a
}

fn d2l(bits: i64) -> Emit {
    let mut a = Emit::new();
    a.const_wide(0x18, 0, bits);
    a.op12x(0x86, 0, 0);
    a.op12x(0x8b, 1, 0); // double-to-long
    a.op11x(0x10, 1);
    a
}

fn f2d(bits: u32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, bits as i32);
    a.op12x(0x82, 0, 0);
    a.op12x(0x89, 1, 0); // float-to-double
    a.op11x(0x0e, 1);
    a
}

#[test]
fn negating_a_float_flips_the_sign_bit_and_keeps_nan() {
    // Each method returns the resulting *bit pattern*, because comparing two
    // NaNs with `==` is false and would make the assertion vacuous.
    let cases = [
        ("negNan", fneg(f32::NAN.to_bits()), Value::Int(!f32::NAN.to_bits() as i32)),
        ("negZero", fneg(0.0f32.to_bits()), Value::Int((-0.0f32).to_bits() as i32)),
        ("negOne", fneg(1.5f32.to_bits()), Value::Int((-1.5f32).to_bits() as i32)),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(4, 0, 0), *v))
        .collect();
    check(&refs, "I");
}

fn fneg(bits: u32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, bits as i32);
    a.op12x(0x82, 0, 0);
    a.op12x(0x7f, 1, 0); // neg-float v1, v0
    a.op12x(0x87, 1, 1); // float-to-int, which preserves the low 32 bits
    a.op11x(0x0f, 1);
    a
}

#[test]
fn long_negation_and_complement_are_sixty_four_bit() {
    let cases = [
        ("lNegMin", long_conv(0x7d, i64::MIN), Value::Int(i64::MIN as i32)),
        ("lNot", long_conv(0x7e, 0), Value::Int(-1)),
        ("lToFloat", long_conv(0x85, 1 << 40), Value::Int(0)),
        ("intToFloat2", int_conv(0x82, 1 << 24), Value::Float(1.6777216e7)),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&refs, "I");
    // And the wide forms themselves.
    let wide = [
        ("lNegMinW", long_conv(0x7d, i64::MIN), Value::Long(i64::MIN)),
        ("lNotW", long_conv(0x7e, 0), Value::Long(-1)),
    ];
    let wide: Vec<(&str, CodeBody, Value)> = wide
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&wide, "J");
}

// ========================================================== 23x/22b/22s/2addr

#[test]
fn integer_arithmetic_wraps_and_division_by_zero_throws() {
    let mut s = Synthetic::new();
    for n in [
        "addWrap", "mulWrap", "minDiv", "minRem", "divZero", "remZero",
        "rsub16", "rsub8", "shlMask", "shrArith", "ushr", "divLit16Zero",
        "andLit8", "orLit16", "xorLit8", "addLit16", "mulLit16", "divLit8",
    ] {
        s.declare(n, &[], "I", 6, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut push = |n: &str, e: Emit| {
                out.insert(n.to_string(), e.code(6, 0, 0));
            };
            push("addWrap", bin23(0x90, i32::MAX, 1));
            push("mulWrap", bin23(0x92, 65536, 65536));
            // Integer.MIN_VALUE / -1 is Integer.MIN_VALUE, not an exception.
            push("minDiv", bin23(0x93, i32::MIN, -1));
            push("minRem", bin23(0x94, i32::MIN, -1));
            push("divZero", bin23(0x93, 1, 0));
            push("remZero", bin23(0x94, 1, 0));
            // `rsub-int` is *literal* minus register: the reversed one.
            push("rsub16", lit16(0xd1, 10, 3));
            push("rsub8", lit8(0xd9, 10, 3));
            // Shifts mask the amount: 1 << 33 is 1 << 1.
            push("shlMask", lit8(0xe0, 1, 33));
            push("shrArith", lit8(0xe1, -8, 1));
            push("ushr", lit8(0xe2, -8, 1));
            push("divLit16Zero", lit16(0xd3, 1, 0));
            push("divLit8", lit8(0xdb, 7, 2));
            push("andLit8", lit8(0xdd, 0b1100, 0b1010));
            push("orLit16", lit16(0xd6, 0b1100, 0b0011));
            push("xorLit8", lit8(0xdf, 0xff, 0x0f));
            push("addLit16", lit16(0xd0, 7, 300));
            push("mulLit16", lit16(0xd2, 7, 300));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let want: &[(&str, Value)] = &[
        ("addWrap", Value::Int(i32::MIN)),
        ("mulWrap", Value::Int(0)),
        ("minDiv", Value::Int(i32::MIN)),
        ("minRem", Value::Int(0)),
        ("rsub16", Value::Int(-7)),
        ("rsub8", Value::Int(-7)),
        ("shlMask", Value::Int(2)),
        ("shrArith", Value::Int(-4)),
        ("ushr", Value::Int(2_147_483_644)),
        ("andLit8", Value::Int(0b1000)),
        ("orLit16", Value::Int(0b1111)),
        ("xorLit8", Value::Int(0xf0)),
        ("addLit16", Value::Int(307)),
        ("mulLit16", Value::Int(2100)),
        ("divLit8", Value::Int(3)),
    ];
    for (n, v) in want {
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), *v, "{n}");
    }
    for n in ["divZero", "remZero", "divLit16Zero"] {
        assert_eq!(
            thrown_class(&call0(&mut vm, n, "()I")),
            "Ljava/lang/ArithmeticException;",
            "{n}"
        );
    }
}

fn bin23(op: u8, x: i32, y: i32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, x);
    a.const32(0x14, 1, y);
    a.op23x(op, 2, 0, 1);
    a.op11x(0x0f, 2);
    a
}

fn lit16(op: u8, x: i32, y: i16) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, x);
    a.op22s(op, 1, 0, y);
    a.op11x(0x0f, 1);
    a
}

fn lit8(op: u8, x: i32, y: i8) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, x);
    a.op22b(op, 1, 0, y);
    a.op11x(0x0f, 1);
    a
}

#[test]
fn two_address_forms_update_the_first_operand_in_place() {
    let mut s = Synthetic::new();
    for n in ["a2add", "a2sub", "a2shl", "a2long", "a2double", "a2rem"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut push = |n: &str, e: Emit| {
                out.insert(n.to_string(), e.code(8, 0, 0));
            };
            // `add-int/2addr v0, v1` is v0 = v0 + v1: the first operand is both
            // source and destination.
            let mut a = Emit::new();
            a.const4(0, 10);
            a.const4(1, -3);
            a.op12x(0xb0, 0, 1);
            a.op11x(0x0f, 0);
            push("a2add", a);
            let mut b = Emit::new();
            b.const4(0, 10);
            b.const4(1, 3);
            b.op12x(0xb1, 0, 1);
            b.op11x(0x0f, 0);
            push("a2sub", b);
            // The shift amount is the *second* register, masked to five bits.
            let mut c = Emit::new();
            c.const4(0, 1);
            c.const4(1, 33);
            c.op12x(0xb8, 0, 1);
            c.op11x(0x0f, 0);
            push("a2shl", c);
            // A wide 2addr writes two registers, and the high word must become
            // the pad rather than a stale value.
            let mut d = Emit::new();
            d.const_wide(0x18, 0, 0x1_0000_0000);
            d.const_wide(0x18, 2, 5);
            d.op12x(0xbb, 0, 2);
            d.op12x(0x84, 4, 0); // long-to-int, keeping the low word
            d.op11x(0x0f, 4);
            push("a2long", d);
            // 2.5 * 2.0 as doubles, then to an int.
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 2.5f64.to_bits() as i64);
            e.const_wide(0x18, 2, 2.0f64.to_bits() as i64);
            e.op12x(0x86, 0, 0);
            e.op12x(0x86, 2, 2);
            e.op12x(0xcc, 0, 2);
            e.op12x(0x8a, 4, 0);
            e.op11x(0x0f, 4);
            push("a2double", e);
            // `rem-int/2addr` by zero throws like its three-register form.
            let mut f = Emit::new();
            f.const4(0, 5);
            f.const4(1, 0);
            f.op12x(0xb4, 0, 1);
            f.op11x(0x0f, 0);
            push("a2rem", f);
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "a2add", "()I").unwrap(), Value::Int(7));
    assert_eq!(call0(&mut vm, "a2sub", "()I").unwrap(), Value::Int(7));
    assert_eq!(call0(&mut vm, "a2shl", "()I").unwrap(), Value::Int(2));
    assert_eq!(call0(&mut vm, "a2long", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "a2double", "()I").unwrap(), Value::Int(5));
    assert_eq!(
        thrown_class(&call0(&mut vm, "a2rem", "()I")),
        "Ljava/lang/ArithmeticException;"
    );
}

#[test]
fn long_and_double_arithmetic_really_is_sixty_four_bit() {
    let mut s = Synthetic::new();
    s.declare("lAdd", &[], "J", 8, 0);
    s.declare("lWrap", &[], "J", 8, 0);
    s.declare("lShl", &[], "J", 8, 0);
    s.declare("lDiv", &[], "J", 8, 0);
    s.declare("dAdd", &[], "D", 8, 0);
    s.declare("dWrap", &[], "D", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.const_wide(0x18, 0, i64::MAX);
            a.const_wide(0x18, 2, 1);
            a.op23x(0x9b, 4, 0, 2); // add-long
            a.op11x(0x10, 4);
            out.insert("lAdd".to_string(), a.code(8, 0, 0));
            let mut b = Emit::new();
            b.const_wide(0x18, 0, i64::MAX);
            b.const_wide(0x18, 2, 1);
            b.op23x(0x9b, 4, 0, 2);
            b.op11x(0x10, 4);
            out.insert("lWrap".to_string(), b.code(8, 0, 0));
            // A long shift masks to six bits, not five: 1 << 65 is 1 << 1.
            let mut c = Emit::new();
            c.const_wide(0x18, 0, 1);
            c.const_wide(0x18, 2, 65);
            c.op23x(0xa3, 4, 0, 2); // shl-long
            c.op11x(0x10, 4);
            out.insert("lShl".to_string(), c.code(8, 0, 0));
            let mut d = Emit::new();
            d.const_wide(0x18, 0, -7);
            d.const_wide(0x18, 2, 2);
            d.op23x(0x9e, 4, 0, 2); // div-long, truncating toward zero
            d.op11x(0x10, 4);
            out.insert("lDiv".to_string(), d.code(8, 0, 0));
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 0.5f64.to_bits() as i64);
            e.const_wide(0x18, 2, 0.25f64.to_bits() as i64);
            e.op23x(0xab, 4, 0, 2); // add-double
            e.op11x(0x10, 4);
            out.insert("dAdd".to_string(), e.code(8, 0, 0));
            let mut f = Emit::new();
            f.const_wide(0x18, 0, f64::MAX.to_bits() as i64);
            f.const_wide(0x18, 2, f64::MAX.to_bits() as i64);
            f.op23x(0xab, 4, 0, 2); // infinity, not a trap
            f.op11x(0x10, 4);
            out.insert("dWrap".to_string(), f.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "lAdd", "()J").unwrap(), Value::Long(i64::MIN));
    assert_eq!(call0(&mut vm, "lWrap", "()J").unwrap(), Value::Long(i64::MIN));
    assert_eq!(call0(&mut vm, "lShl", "()J").unwrap(), Value::Long(2));
    // Truncation toward zero, so -7 / 2 is -3 and not -4.
    assert_eq!(call0(&mut vm, "lDiv", "()J").unwrap(), Value::Long(-3));
    match call0(&mut vm, "dAdd", "()D").unwrap() {
        Value::Double(d) => assert_eq!(d, 0.75),
        other => panic!("{other:?}"),
    }
    match call0(&mut vm, "dWrap", "()D").unwrap() {
        Value::Double(d) => assert!(d.is_infinite() && d > 0.0, "expected +inf, got {d}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn float_arithmetic_follows_ieee_rather_than_the_integer_rules() {
    // 1.0 / 0.0 is infinity, *not* an exception: the difference between
    // `div-float` and `div-int`, and the reason the float family cannot share
    // the integer path. Zero over zero, and a remainder against zero, are the
    // two cases that produce a NaN rather than a number.
    check_f32(&[
        ("fdivInf", fbin23(0xa9, 1, 0).code(8, 0, 0), Fp::Inf),
        ("fdivNegInf", fbin23(0xa9, -1, 0).code(8, 0, 0), Fp::NegInf),
        ("fdivNan", fbin23(0xa9, 0, 0).code(8, 0, 0), Fp::Nan),
        ("fremNan", fbin23(0xaa, -1, 0).code(8, 0, 0), Fp::Nan),
        ("fsubZero", fbin23(0xa8, 0, 0).code(8, 0, 0), Fp::Val(0.0)),
        ("fmulNegZero", fbin23(0xa7, -0, 1).code(8, 0, 0), Fp::Val(-0.0)),
    ]);
}

fn fbin23(op: u8, x: i32, y: i32) -> Emit {
    let mut a = Emit::new();
    a.const4(0, x as i8);
    a.const4(1, y as i8);
    a.op12x(0x82, 0, 0);
    a.op12x(0x82, 1, 1);
    a.op23x(op, 2, 0, 1);
    a.op11x(0x0f, 2);
    a
}

/// A float expectation, with NaN named rather than compared: `f32::NAN != f32::NAN`,
/// so a case that must produce a NaN cannot be written as an equality.
#[derive(Clone, Copy, Debug)]
enum Fp {
    Nan,
    Inf,
    NegInf,
    Val(f32),
}

impl Fp {
    fn matches(self, got: f32) -> bool {
        match self {
            Fp::Nan => got.is_nan(),
            Fp::Inf => got == f32::INFINITY,
            Fp::NegInf => got == f32::NEG_INFINITY,
            Fp::Val(v) => got == v,
        }
    }
}

/// Run `F`-returning cases, each in a fresh interpreter.
fn check_f32(cases: &[(&str, CodeBody, Fp)]) {
    let mut s = Synthetic::new();
    for (n, b, _) in cases {
        s.declare(n, &[], "F", b.registers_size, b.outs_size);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(move |_i| {
            cases.iter().map(|(n, b, _)| (n.to_string(), b.clone())).collect::<BTreeMap<_, _>>()
        })
        .expect("emit");
    for (n, _, want) in cases {
        let mut vm = vm(&bytes, Config::default(), None).expect("open");
        match call0(&mut vm, n, "()F").unwrap() {
            Value::Float(got) => assert!(want.matches(got), "{n}: {got} is not {want:?}"),
            other => panic!("{n}: expected a float, got {other:?}"),
        }
    }
}

#[test]
fn cmpl_and_cmpg_differ_on_nan_and_on_signed_zero() {
    let cases = [
        ("cmplNan", cmpf_nan(0x2d), Value::Int(-1)),
        ("cmpgNan", cmpf_nan(0x2e), Value::Int(1)),
        ("cmplNegZero", cmpf_neg_zero(0x2d), Value::Int(-1)),
        ("cmpgNegZero", cmpf_neg_zero(0x2e), Value::Int(0)),
        ("cmplLess", cmpf(0x2d, 1, 2), Value::Int(-1)),
        ("cmpgGreater", cmpf(0x2e, 3, 2), Value::Int(1)),
        ("cmpLongLow", cmplong(1, 1 << 40), Value::Int(-1)),
        ("cmpLongHigh", cmplong(1 << 40, 1), Value::Int(1)),
        ("cmpLongEq", cmplong(9, 9), Value::Int(0)),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(8, 0, 0), *v))
        .collect();
    check(&refs, "I");
}

/// `cmp*` on two floats taken from small ints, which `int-to-float` converts
/// exactly.
fn cmpf(op: u8, x: i32, y: i32) -> Emit {
    let mut a = Emit::new();
    a.const4(0, x as i8);
    a.const4(1, y as i8);
    a.op12x(0x82, 0, 0);
    a.op12x(0x82, 1, 1);
    a.op23x(op, 2, 0, 1);
    a.op11x(0x0f, 2);
    a
}

/// `cmp*` where the first operand is a NaN, made by dividing zero by itself.
///
/// There is no `const-float`, and a float *bit pattern* pushed through
/// `int-to-float` is a number, not a reinterpretation, so `0.0f/0.0f` is both
/// the only route to a NaN here and the route real code uses.
fn cmpf_nan(op: u8) -> Emit {
    let mut a = Emit::new();
    a.const4(0, 0);
    a.const4(1, 0);
    a.op12x(0x82, 0, 0);
    a.op12x(0x82, 1, 1);
    a.op23x(0xa9, 0, 0, 1); // div-float v0, v0, v1 -> NaN
    a.const4(1, 1);
    a.op12x(0x82, 1, 1); // v1 = 1.0f
    a.op23x(op, 2, 0, 1);
    a.op11x(0x0f, 2);
    a
}

/// `cmp*` on `-0.0f` and `+0.0f`. Negating zero is the only way to get the
/// negative zero, and it is the case `cmpg` is specified to get wrong.
fn cmpf_neg_zero(op: u8) -> Emit {
    let mut a = Emit::new();
    a.const4(0, 0);
    a.const4(1, 0);
    a.op12x(0x82, 0, 0);
    a.op12x(0x82, 1, 1);
    a.op12x(0x7f, 0, 0); // neg-float v0, v0 -> -0.0f
    a.op23x(op, 2, 0, 1);
    a.op11x(0x0f, 2);
    a
}

fn cmplong(x: i64, y: i64) -> Emit {
    let mut a = Emit::new();
    a.const_wide(0x18, 0, x);
    a.const_wide(0x18, 2, y);
    a.op23x(0x31, 4, 0, 2);
    a.op11x(0x0f, 4);
    a
}

// ================================================================ arrays

#[test]
fn arrays_narrow_on_store_and_widen_on_load() {
    let mut s = Synthetic::new();
    for n in ["byteArr", "charArr", "boolArr", "arrLen", "oobLo", "oobHi", "negSize", "arrStore", "lenNeg", "arrNull"] {
        s.declare(n, &[], "I", 10, 0);
    }
    s.declare("wideArr", &[], "J", 10, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty_b = ty_at(idx, "[B");
            let ty_c = ty_at(idx, "[C");
            let ty_z = ty_at(idx, "[Z");
            let ty_j = ty_at(idx, "[J");
            let ty_i = ty_at(idx, "[I");

            let mut a = Emit::new();
            a.const4(0, 1);
            a.op22c(0x23, 4, 0, ty_b);
            a.const16(0x13, 1, 0xFF);
            a.const4(0, 0);
            a.op23x(0x4f, 1, 4, 0); // aput-byte of 0xFF
            a.op23x(0x48, 2, 4, 0); // aget-byte
            a.op11x(0x0f, 2);
            out.insert("byteArr".to_string(), a.code(10, 0, 0));

            let mut b = Emit::new();
            b.const4(0, 1);
            b.op22c(0x23, 4, 0, ty_c);
            b.const16(0x13, 1, -1);
            b.const4(0, 0);
            b.op23x(0x50, 1, 4, 0); // aput-char of -1
            b.op23x(0x49, 2, 4, 0); // aget-char
            b.op11x(0x0f, 2);
            out.insert("charArr".to_string(), b.code(10, 0, 0));

            let mut c = Emit::new();
            c.const4(0, 1);
            c.op22c(0x23, 4, 0, ty_z);
            c.const16(0x13, 1, 42);
            c.const4(0, 0);
            c.op23x(0x4e, 1, 4, 0); // aput-boolean of 42
            c.op23x(0x47, 2, 4, 0); // aget-boolean
            c.op11x(0x0f, 2);
            out.insert("boolArr".to_string(), c.code(10, 0, 0));

            let mut d = Emit::new();
            d.const4(0, 1);
            d.op22c(0x23, 4, 0, ty_j);
            d.const_wide(0x18, 1, -7);
            d.const4(0, 0);
            d.op23x(0x4c, 1, 4, 0); // aput-wide
            d.op23x(0x45, 5, 4, 0); // aget-wide
            d.op11x(0x10, 5);
            out.insert("wideArr".to_string(), d.code(10, 0, 0));

            let mut e = Emit::new();
            e.const4(0, 4);
            e.op22c(0x23, 4, 0, ty_i);
            e.op12x(0x21, 1, 4); // array-length
            e.op11x(0x0f, 1);
            out.insert("arrLen".to_string(), e.code(10, 0, 0));

            let mut f = Emit::new();
            f.const4(0, 1);
            f.op22c(0x23, 4, 0, ty_i);
            f.const4(1, -1);
            f.op23x(0x44, 2, 4, 1);
            f.op11x(0x0f, 2);
            out.insert("oobLo".to_string(), f.code(10, 0, 0));

            let mut g = Emit::new();
            g.const4(0, 1);
            g.op22c(0x23, 4, 0, ty_i);
            g.const4(1, 1);
            g.op23x(0x44, 2, 4, 1);
            g.op11x(0x0f, 2);
            out.insert("oobHi".to_string(), g.code(10, 0, 0));

            let mut h = Emit::new();
            h.const16(0x13, 0, -1);
            h.op22c(0x23, 4, 0, ty_i);
            h.op11x(0x0f, 4);
            out.insert("negSize".to_string(), h.code(10, 0, 0));

            // Storing a `long` into an `int[]` is refused, not truncated.
            let mut i = Emit::new();
            i.const4(0, 1);
            i.op22c(0x23, 4, 0, ty_i);
            i.const_wide(0x18, 1, 5);
            i.const4(0, 0);
            i.op23x(0x4b, 1, 4, 0);
            i.op11x(0x0f, 1);
            out.insert("arrStore".to_string(), i.code(10, 0, 0));

            // array-length on null. The null is read out of a field nobody
            // wrote: fields start zeroed, and an `int` zero is not a reference.
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            let mut j = Emit::new();
            j.op21c(0x22, 0, ty_at(idx, HOST));
            j.op22c(0x54, 0, 0, f_o);
            j.op12x(0x21, 1, 0);
            j.op11x(0x0f, 1);
            out.insert("arrNull".to_string(), j.code(10, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "byteArr", "()I").unwrap(), Value::Int(-1));
    assert_eq!(call0(&mut vm, "charArr", "()I").unwrap(), Value::Int(65535));
    // A `boolean[]` holds only 0 and 1, so 42 becomes 0.
    assert_eq!(call0(&mut vm, "boolArr", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "wideArr", "()J").unwrap(), Value::Long(-7));
    assert_eq!(call0(&mut vm, "arrLen", "()I").unwrap(), Value::Int(4));
    for n in ["oobLo", "oobHi"] {
        assert_eq!(
            thrown_class(&call0(&mut vm, n, "()I")),
            "Ljava/lang/ArrayIndexOutOfBoundsException;",
            "{n}"
        );
    }
    for n in ["negSize", "arrNull"] {
        assert_eq!(
            thrown_class(&call0(&mut vm, n, "()I")),
            if n == "negSize" {
                "Ljava/lang/NegativeArraySizeException;"
            } else {
                "Ljava/lang/NullPointerException;"
            },
            "{n}"
        );
    }
    assert_eq!(
        thrown_class(&call0(&mut vm, "arrStore", "()I")),
        "Ljava/lang/ArrayStoreException;"
    );
}

#[test]
fn a_multi_dimensional_array_is_an_array_of_nulls() {
    let mut s = Synthetic::new();
    s.declare("inner", &[], "I", 10, 0);
    s.declare("outer", &[], "I", 10, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty_ii = ty_at(idx, "[[I");
            let ty_i = ty_at(idx, "[I");
            // `int[][]` of length 1, then fill element 0 with a new `int[]`.
            let mut a = Emit::new();
            a.const4(0, 1);
            a.op22c(0x23, 4, 0, ty_ii);
            a.const4(1, 2);
            a.op22c(0x23, 5, 1, ty_i);
            a.const4(0, 0);
            a.op23x(0x4d, 5, 4, 0); // aput-object
            a.const4(0, 0);
            a.op23x(0x46, 6, 4, 0); // aget-object
            a.op12x(0x21, 7, 6); // array-length of the inner array
            a.op11x(0x0f, 7);
            out.insert("inner".to_string(), a.code(10, 0, 0));
            // Before it is filled, the element is null, and `array-length` on it
            // throws rather than reporting zero.
            let mut b = Emit::new();
            b.const4(0, 1);
            b.op22c(0x23, 4, 0, ty_ii);
            b.const4(0, 0);
            b.op23x(0x46, 5, 4, 0);
            b.op12x(0x21, 6, 5);
            b.op11x(0x0f, 6);
            out.insert("outer".to_string(), b.code(10, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "inner", "()I").unwrap(), Value::Int(2));
    assert_eq!(
        thrown_class(&call0(&mut vm, "outer", "()I")),
        "Ljava/lang/NullPointerException;"
    );
}

#[test]
fn filled_new_array_builds_the_array_in_one_instruction() {
    let mut s = Synthetic::new();
    s.declare_static("getInt", &[], "I", 2, 0);
    for n in ["fna", "fnar", "fnaObj", "fnaDbl"] {
        s.declare(n, &[], "I", 10, 4);
    }
    s.declare("fnaDbl", &[], "D", 10, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty_i = ty_at(idx, "[I");
            let ty_d = ty_at(idx, "[D");
            // filled-new-array {v0, v1}, [I   -- the count is in `A`.
            let mut a = Emit::new();
            a.const4(0, 7);
            a.const4(1, 8);
            a.op35c(0x24, 2, ty_i, &[0, 1]);
            a.op11x(0x0c, 0); // move-result-object
            a.const4(1, 0);
            a.op23x(0x44, 2, 0, 1); // aget v2, v0, v1
            a.op11x(0x0f, 2);
            out.insert("fna".to_string(), a.code(10, 0, 4));
            // The range form: `v0` is the size and the elements run from `v1`,
            // so a two-element array reads its *second* element back.
            let mut b = Emit::new();
            b.const4(0, 7);
            b.const4(1, 2);
            b.const4(2, 8);
            b.op3rc(0x25, 2, ty_i, 1);
            b.op11x(0x0c, 3);
            b.const4(1, 1);
            b.op23x(0x44, 4, 3, 1);
            b.op11x(0x0f, 4);
            out.insert("fnar".to_string(), b.code(10, 0, 4));
            // A `double[]` in one instruction, proving the high words land: an
            // implementation that only moved the low half would return 0.
            let mut c = Emit::new();
            c.const_wide(0x18, 0, 1.5f64.to_bits() as i64);
            c.const4(2, 1);
            c.op35c(0x25, 2, ty_d, &[0, 2]);
            c.op11x(0x0b, 0); // move-result-wide
            c.op11x(0x0f, 0); // return-wide
            out.insert("fnaDbl".to_string(), c.code(10, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "fna", "()I").unwrap(), Value::Int(7));
    assert_eq!(call0(&mut vm, "fnar", "()I").unwrap(), Value::Int(9));
    assert_eq!(call0(&mut vm, "fnaDbl", "()D").unwrap(), Value::Double(1.5));
}

#[test]
fn fill_array_data_reads_little_endian_at_the_components_width() {
    let mut s = Synthetic::new();
    for n in ["fillByte", "fillShort", "fillInt", "fillLong", "fillChar", "fillFloat", "fillDouble"] {
        s.declare(n, &[], "I", 12, 0);
    }
    s.declare("fillLong", &[], "J", 12, 0);
    s.declare("fillDouble", &[], "D", 12, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut push = |n: &str, ty: &str, width: u16, data: Vec<u8>, read: u8, wide: bool| {
                let t = ty_at(idx, ty);
                let mut a = Emit::new();
                a.const4(0, 2);
                a.op22c(0x23, 4, 0, t);
                // The payload offset is measured from the `fill-array-data`
                // instruction, which is why the offset is back-patched once the
                // payload's position is known.
                let fill_at = a.here() as i64;
                a.op31t(0x26, 4, 0);
                a.const4(1, 1); // read index 1, the second element
                a.op23x(read, 5, 4, 1);
                if wide {
                    a.op11x(0x10, 5);
                } else {
                    a.op11x(0x0f, 5);
                }
                let payload_at = a.here() as i64;
                a.fill_array_data_payload(width, &data);
                a.patch_i32(fill_at as usize * 2 + 2, (payload_at - fill_at) as i32);
                out.insert(n.to_string(), a.code(12, 0, 0));
            };
            push("fillByte", "[B", 1, vec![0x01, 0xFF], 0x48, false);
            push("fillShort", "[S", 2, vec![0x01, 0x02, 0xFF, 0xFF], 0x4a, false);
            push("fillInt", "[I", 4, vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44], 0x44, false);
            push("fillLong", "[J", 8, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], 0x45, true);
            push("fillChar", "[C", 2, vec![0x01, 0x02, 0xFF, 0xFF], 0x49, false);
            push("fillFloat", "[F", 4, 1.5f32.to_le_bytes().to_vec().into_iter().chain(2.5f32.to_le_bytes().to_vec()).collect(), 0x44, false);
            push("fillDouble", "[D", 8, 1.5f64.to_le_bytes().to_vec().into_iter().chain(2.5f64.to_le_bytes().to_vec()).collect(), 0x45, true);
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // The second element of each payload, read at the component's width.
    assert_eq!(call0(&mut vm, "fillByte", "()I").unwrap(), Value::Int(-1), "byte 0xFF sign-extends");
    assert_eq!(call0(&mut vm, "fillShort", "()I").unwrap(), Value::Int(-1));
    assert_eq!(call0(&mut vm, "fillInt", "()I").unwrap(), Value::Int(0x4433_2211));
    assert_eq!(call0(&mut vm, "fillChar", "()I").unwrap(), Value::Int(65535), "char zero-extends");
    assert_eq!(
        call0(&mut vm, "fillLong", "()J").unwrap(),
        Value::Long(i64::from_le_bytes([9, 10, 11, 12, 13, 14, 15, 16]))
    );
    assert_eq!(call0(&mut vm, "fillFloat", "()I").unwrap(), Value::Int(2.5f32.to_bits() as i32));
    match call0(&mut vm, "fillDouble", "()D").unwrap() {
        Value::Double(d) => assert_eq!(d, 2.5),
        other => panic!("{other:?}"),
    }
}

// ================================================================ fields

#[test]
fn instance_and_static_fields_round_trip() {
    let mut s = Synthetic::new();
    for n in ["fI", "fJ", "fSStat", "fSWrite", "fObj", "fNeg"] {
        s.declare(n, &[], "I", 8, 0);
    }
    s.declare("fJ", &[], "J", 8, 0);
    s.declare("fObj", &[], "Ljava/lang/Object;", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty = ty_at(idx, HOST);
            let f_i = field_at(idx, HOST, "i", "I");
            let f_j = field_at(idx, HOST, "j", "J");
            let f_s = field_at(idx, HOST, "S", "I");
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");

            let mut a = Emit::new();
            a.op21c(0x22, 0, ty);
            a.const32(0x14, 1, 99);
            a.op22c(0x59, 1, 0, f_i);
            a.op22c(0x52, 2, 0, f_i);
            a.op11x(0x0f, 2);
            out.insert("fI".to_string(), a.code(8, 0, 0));

            let mut b = Emit::new();
            b.op21c(0x22, 0, ty);
            b.const_wide(0x18, 2, -5);
            b.op22c(0x5a, 2, 0, f_j);
            b.op22c(0x53, 4, 0, f_j);
            b.op11x(0x10, 4);
            out.insert("fJ".to_string(), b.code(8, 0, 0));

            // A static field nobody wrote is zero, not `Uninit`.
            let mut c = Emit::new();
            c.op21c(0x60, 1, f_s);
            c.op11x(0x0f, 1);
            out.insert("fSStat".to_string(), c.code(8, 0, 0));

            let mut d = Emit::new();
            d.const32(0x14, 1, 4321);
            d.op21c(0x67, 1, f_s); // sput v1, S
            d.op21c(0x60, 2, f_s);
            d.op11x(0x0f, 2);
            out.insert("fSWrite".to_string(), d.code(8, 0, 0));

            // A reference field round-trips a real object.
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty);
            e.op21c(0x1a, 1, string_at(idx, "hello"));
            e.op22c(0x5b, 1, 0, f_o);
            e.op22c(0x54, 2, 0, f_o);
            e.op11x(0x0f, 0);
            out.insert("fObj".to_string(), e.code(8, 0, 0));

            // `iput-byte` narrows on store, `iget-short` widens on load.
            let mut f = Emit::new();
            f.op21c(0x22, 0, ty);
            f.const16(0x13, 1, 0x1FF);
            f.op22c(0x5e, 1, 0, field_at(idx, HOST, "sh", "S")); // iput-short
            f.op22c(0x5a, 2, 0, field_at(idx, HOST, "by", "B")); // iget-byte of another
            f.const16(0x13, 3, 0xFF);
            f.op22c(0x5d, 3, 0, field_at(idx, HOST, "by", "B")); // iput-byte of 0xFF
            f.op22c(0x56, 4, 0, field_at(idx, HOST, "by", "B")); // iget-byte
            f.op11x(0x0f, 4);
            out.insert("fNeg".to_string(), f.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "fI", "()I").unwrap(), Value::Int(99));
    assert_eq!(call0(&mut vm, "fJ", "()J").unwrap(), Value::Long(-5));
    assert_eq!(call0(&mut vm, "fSStat", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "fSWrite", "()I").unwrap(), Value::Int(4321));
    assert_eq!(call0(&mut vm, "fObj", "()Ljava/lang/Object;").unwrap(), Value::Int(0));
    // `iput-byte` of 0xFF stores -1, and `iget-byte` reads -1: a field is
    // narrowed on the way in and widened on the way out, exactly like an array.
    assert_eq!(call0(&mut vm, "fNeg", "()I").unwrap(), Value::Int(-1));
}

#[test]
fn a_field_access_on_a_null_receiver_throws() {
    let mut s = Synthetic::new();
    for n in ["igetNull", "iputNull", "arrayOob", "invokeNull", "sgetOk"] {
        s.declare(n, &[], "I", 6, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let f_i = field_at(idx, HOST, "i", "I");
            let ty_i = ty_at(idx, "[I");

            // A null reference has to be manufactured: an untouched register is
            // *uninitialised*, not null, and an `int` is not null either. An
            // object field nobody wrote is.
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, HOST));
            a.op22c(0x54, 1, 0, f_o);
            a.op22c(0x52, 2, 1, f_i);
            a.op11x(0x0f, 2);
            out.insert("igetNull".to_string(), a.code(6, 0, 0));

            let mut b = Emit::new();
            b.op21c(0x22, 0, ty_at(idx, HOST));
            b.op22c(0x54, 1, 0, f_o);
            b.const4(2, 5);
            b.op22c(0x59, 2, 1, f_i);
            b.op11x(0x0f, 2);
            out.insert("iputNull".to_string(), b.code(6, 0, 0));

            // A zero-length array is not null: index 0 of it is out of bounds.
            let mut c = Emit::new();
            c.const4(0, 0);
            c.op22c(0x23, 4, 0, ty_i);
            c.const4(1, 0);
            c.op23x(0x44, 2, 4, 1);
            c.op11x(0x0f, 2);
            out.insert("arrayOob".to_string(), c.code(6, 0, 0));

            let mut d = Emit::new();
            d.op21c(0x22, 0, ty_at(idx, HOST));
            d.op22c(0x54, 1, 0, f_o);
            d.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[1, 0]);
            d.op11x(0x0a, 2);
            d.op11x(0x0f, 2);
            out.insert("invokeNull".to_string(), d.code(6, 0, 2));

            let mut e = Emit::new();
            e.op21c(0x60, 1, field_at(idx, HOST, "S", "I"));
            e.op11x(0x0f, 1);
            out.insert("sgetOk".to_string(), e.code(6, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    for n in ["igetNull", "iputNull", "invokeNull"] {
        assert_eq!(
            thrown_class(&call0(&mut vm, n, "()I")),
            "Ljava/lang/NullPointerException;",
            "{n}"
        );
    }
    assert_eq!(
        thrown_class(&call0(&mut vm, "arrayOob", "()I")),
        "Ljava/lang/ArrayIndexOutOfBoundsException;"
    );
    assert_eq!(call0(&mut vm, "sgetOk", "()I").unwrap(), Value::Int(0));
}

#[test]
fn a_field_of_a_class_with_no_bytecode_goes_to_the_shim() {
    let rec = Recorder::new();
    rec.field("Landroid/view/WindowManager$LayoutParams;->screenBrightness:F", HostValue::Float(0.5));
    rec.field("Lorg/x/R;->id:I", HostValue::Int(2130903040));
    let mut s = Synthetic::new();
    s.declare("layoutField", &[], "F", 6, 0);
    s.declare("appStatic", &[], "I", 4, 0);
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_field("Landroid/view/WindowManager$LayoutParams;", "screenBrightness", "F");
        w.add_field("Lorg/x/R;", "id", "I");
    }
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            // A field whose declaring class is not in the dex and not builtin: the
            // shim owns it, and the engine must not invent a slot for it.
            // A real object of the declaring class, so the field access is
            // well formed and only the *storage* is the shim's business.
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, "Landroid/view/WindowManager$LayoutParams;"));
            a.op22c(0x52, 1, 0, field_at(idx, "Landroid/view/WindowManager$LayoutParams;", "screenBrightness", "F"));
            a.op11x(0x0f, 1);
            out.insert("layoutField".to_string(), a.code(6, 0, 0));
            // A static field of an app's own class *is* the engine's business.
            let mut b = Emit::new();
            b.op21c(0x60, 0, field_at(idx, "Lorg/x/R;", "id", "I"));
            b.op11x(0x0f, 0);
            out.insert("appStatic".to_string(), b.code(4, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec.clone())).expect("open");
    match call0(&mut vm, "layoutField", "()F").unwrap() {
        Value::Float(f) => assert_eq!(f, 0.5),
        other => panic!("{other:?}"),
    }
    let s = vm.stats();
    assert_eq!(s.framework_field_accesses, 1);
    assert!(rec.log().contains(&"Landroid/view/WindowManager$LayoutParams;->screenBrightness:F".to_string()));
}

// ================================================================ calls

#[test]
fn move_result_reads_the_value_the_callee_returned() {
    let mut s = Synthetic::new();
    s.declare_static("getInt", &[], "I", 2, 0);
    s.declare_static("getLong", &[], "J", 4, 0);
    s.declare_static("getObject", &[], "Ljava/lang/Object;", 2, 0);
    for n in ["callInt", "callLong", "callObj"] {
        s.declare(n, &[], "I", 8, 4);
    }
    s.declare("callLong", &[], "J", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.op35c(0x71, 0, method_at(idx, HOST, "getInt", &[], "I"), &[]);
            a.op11x(0x0a, 0);
            a.op11x(0x0f, 0);
            out.insert("callInt".to_string(), a.code(8, 0, 4));
            let mut b = Emit::new();
            b.op35c(0x71, 0, method_at(idx, HOST, "getLong", &[], "J"), &[]);
            b.op11x(0x0b, 0);
            b.op11x(0x10, 0);
            out.insert("callLong".to_string(), b.code(8, 0, 4));
            let mut c = Emit::new();
            c.op35c(0x71, 0, method_at(idx, HOST, "getObject", &[], "Ljava/lang/Object;"), &[]);
            c.op11x(0x0c, 0);
            c.op11x(0x0f, 0);
            out.insert("callObj".to_string(), c.code(8, 0, 4));
            out
        })
        .expect("emit");
    // No host, so every call is a `NotImplemented` stub returning the declared
    // type's zero value. That is the rule the whole study depends on: it is what
    // lets a real app run to completion before the shim exists.
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "callInt", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "callLong", "()J").unwrap(), Value::Long(0));
    assert_eq!(call0(&mut vm, "callObj", "()I").unwrap(), Value::Int(0));
    let st = vm.stats();
    assert_eq!(st.framework_calls, 3);
    assert_eq!(st.framework_calls_unimplemented, 3);
    assert!(st.shim_log.iter().all(|r| !r.implemented));
}

#[test]
fn a_host_answers_a_call_and_the_result_reaches_move_result() {
    let rec = Recorder::new();
    rec.answer("Ljava/lang/String;->length()I", HostValue::Int(11));
    let mut s = Synthetic::new();
    s.declare("strlen", &[], "I", 6, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "hello"));
            a.op35c(0x6e, 2, method_at(idx, "Ljava/lang/String;", "length", &[], "I"), &[0]);
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            BTreeMap::from([("strlen".to_string(), a.code(6, 0, 2))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec.clone())).expect("open");
    assert_eq!(call0(&mut vm, "strlen", "()I").unwrap(), Value::Int(11));
    assert_eq!(rec.log(), vec!["Ljava/lang/String;->length()I"]);
    let st = vm.stats();
    assert_eq!(st.framework_calls, 1);
    assert_eq!(st.framework_calls_unimplemented, 0, "the host answered, so nothing was guessed");
}

#[test]
fn a_host_can_return_a_string_and_the_app_can_read_it_back() {
    let rec = Recorder::new();
    rec.answer(
        "Lcom/x/Provider;->get(Ljava/lang/String;)Ljava/lang/String;",
        HostValue::Str("from the shim".to_string()),
    );
    let mut s = Synthetic::new();
    s.declare("query", &[], "I", 8, 4);
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_method("Lcom/x/Provider;", "get", &["Ljava/lang/String;"], "Ljava/lang/String;");
    }
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.const4(0, 0);
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Lcom/x/Provider;", "get", &["Ljava/lang/String;"], "Ljava/lang/String;"),
                &[0, 0],
            );
            a.op11x(0x0c, 1);
            // Store it in a field so the harness can read the object out.
            a.const4(0, 0);
            a.op22c(0x22, 2, 0, 0);
            a.op22c(0x5b, 1, 2, field_at(idx, HOST, "o", "Ljava/lang/Object;"));
            // Return its length, which the shim can compute for us.
            a.op35c(0x6e, 2, method_at(idx, "Ljava/lang/String;", "length", &[], "I"), &[1]);
            a.op11x(0x0a, 2);
            a.op11x(0x0f, 2);
            BTreeMap::from([("query".to_string(), a.code(8, 0, 4))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec)).expect("open");
    // `String.length` is declined, so this is 0, and the *string object* is still
    // a real one the harness can read.
    assert_eq!(call0(&mut vm, "query", "()I").unwrap(), Value::Int(0));
    let st = vm.stats();
    assert!(st.framework_calls >= 2);
}

#[test]
fn a_thrown_string_is_a_real_object_and_the_handler_clause_is_matched_by_class() {
    let rec = Recorder::new();
    rec.answer("Ljava/lang/String;->length()I", HostValue::Int(3));
    rec.throw(
        "Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;",
        "Ljava/lang/IllegalStateException;",
        "no",
    );
    let mut s = Synthetic::new();
    for n in ["uncaught", "wrongClause"] {
        s.declare(n, &[], "I", 12, 8);
    }
    s.declare("caught", &[], "Ljava/lang/String;", 12, 8);
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_type("Ljava/lang/IllegalStateException;");
    }
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let rep = method_at(
                idx,
                "Ljava/lang/String;",
                "replace",
                &["Ljava/lang/CharSequence;", "Ljava/lang/CharSequence;"],
                "Ljava/lang/String;",
            );
            // try { throw } catch (RuntimeException e) { ... }
            // Units 0..8 are protected -- including the `throw` at unit 8 -- and
            // the handler starts at unit 9.
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.op21c(0x1a, 1, string_at(idx, "b"));
            a.op35c(0x6e, 3, rep, &[0, 1]);
            a.op11x(0x0c, 2);
            a.op11x(0x11, 2);
            a.op21c(0x1a, 3, string_at(idx, "hello"));
            a.op11x(0x0d, 4); // move-exception v4
            a.op11x(0x11, 3);
            out.insert(
                "caught".to_string(),
                a.code_tries(12, 0, 8, vec![catches(0, 9, &[("Ljava/lang/RuntimeException;", 9)], None)]),
            );

            // A `catch (Error)` clause does *not* catch a RuntimeException, so
            // the same call is uncaught here. The hierarchy has to be walked the
            // right way for both to be right.
            let mut b = Emit::new();
            b.op21c(0x1a, 0, string_at(idx, "a"));
            b.op21c(0x1a, 1, string_at(idx, "b"));
            b.op35c(0x6e, 3, rep, &[0, 1]);
            b.op11x(0x0c, 2);
            b.op11x(0x11, 2);
            b.const4(1, 0);
            b.op11x(0x0f, 1);
            out.insert(
                "wrongClause".to_string(),
                b.code_tries(12, 0, 8, vec![catches(0, 9, &[("Ljava/lang/Error;", 9)], Some(12))]),
            );

            // No try table at all.
            let mut c = Emit::new();
            c.op21c(0x1a, 0, string_at(idx, "a"));
            c.op21c(0x1a, 1, string_at(idx, "b"));
            c.op35c(0x6e, 3, rep, &[0, 1]);
            c.op11x(0x0c, 2);
            c.op11x(0x11, 2);
            out.insert("uncaught".to_string(), c.code(12, 0, 8));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec)).expect("open");
    let got = call0(&mut vm, "caught", "()Ljava/lang/String;").unwrap();
    assert_eq!(vm.string_value(got), Some("hello"));
    assert_eq!(vm.stats().exceptions_caught, 1);
    assert_termination(
        &call0(&mut vm, "uncaught", "()I"),
        Termination::ExceptionRaised,
    );
    // `catch (Error)` must not catch a `RuntimeException`, so the catch-all
    // after it is the clause that runs.
    assert_eq!(call0(&mut vm, "wrongClause", "()I").unwrap(), Value::Int(0));
    assert_eq!(
        thrown_class(&call0(&mut vm, "uncaught", "()I")),
        "Ljava/lang/IllegalStateException;"
    );
}

#[test]
fn a_typed_clause_is_matched_through_the_exception_hierarchy() {
    // The shim raises a `NoSuchMethodError`; the clause names `Ljava/lang/Error;`,
    // four levels up the hierarchy. If the hierarchy walk is wrong this does not
    // match, and this is the shape real apps use for optional dependencies.
    let rec = Recorder::new();
    rec.throw("Ljava/lang/String;->length()I", "Ljava/lang/NoSuchMethodError;", "gone");
    let mut s = Synthetic::new();
    s.declare("hierarchy", &[], "I", 10, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.op35c(0x6e, 2, method_at(idx, "Ljava/lang/String;", "length", &[], "I"), &[0]);
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            a.const16(0x13, 1, 42); // the handler: unit 7
            a.op11x(0x0f, 1);
            BTreeMap::from([("hierarchy".to_string(), a.code_tries(10, 0, 2, vec![catches(0, 3, &[("Ljava/lang/Error;", 7)], None)]))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec)).expect("open");
    assert_eq!(call0(&mut vm, "hierarchy", "()I").unwrap(), Value::Int(42));
}

#[test]
fn a_catch_all_clause_catches_anything() {
    let rec = Recorder::new();
    rec.throw("Ljava/lang/String;->length()I", "Ljava/lang/Error;", "boom");
    let mut s = Synthetic::new();
    s.declare("catchAll", &[], "I", 10, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.op35c(0x6e, 2, method_at(idx, "Ljava/lang/String;", "length", &[], "I"), &[0]);
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            a.const4(1, 7);
            a.op11x(0x0f, 1);
            // The invoke is at unit 2 (the `const-string` takes two), so the
            // protected range has to cover it and not just the first unit.
            BTreeMap::from([("catchAll".to_string(), a.code_tries(10, 0, 2, vec![catch_all(0, 3, 7)]))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec)).expect("open");
    assert_eq!(call0(&mut vm, "catchAll", "()I").unwrap(), Value::Int(7));
}

#[test]
fn virtual_dispatch_picks_the_subclass_through_the_vtable() {
    let mut s = Synthetic::new();
    s.declare("callV", &[], "I", 8, 4);
    intern_standard(&mut s);
    let mut sub = ClassDef::extending_object(SUB);
    sub = sub.with_field(FieldDef::instance("u", "I"));
    let mut e = Emit::new();
    e.const32(0x14, 0, 77);
    e.op11x(0x0f, 0);
    sub = sub.with_method(MethodDef::concrete("vMeth", &["I"], "I", access::ACC_PUBLIC, e.code(2, 2, 0)));
    s.class(sub);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, SUB));
            a.op35c(0x70, 2, method_at(idx, SUB, "<init>", &[], "V"), &[0]);
            a.const4(1, 5);
            a.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[0, 1]);
            a.op11x(0x0a, 2);
            a.op11x(0x0f, 2);
            BTreeMap::from([("callV".to_string(), a.code(8, 0, 4))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // 77 + 5, computed in `Lu;.vMeth`: a host stub would give 0, and a
    // mis-resolved vtable would give something else entirely.
    assert_eq!(call0(&mut vm, "callV", "()I").unwrap(), Value::Int(82));
    let prog = vm.program();
    let base = *prog.by_descriptor.get(HOST).expect("host class");
    let sub = *prog.by_descriptor.get(SUB).expect("subclass");
    let base_entry = prog.vtable_lookup(base, "vMeth", "(I)I");
    let sub_entry = prog.vtable_lookup(sub, "vMeth", "(I)I");
    assert!(base_entry.is_some() && sub_entry.is_some());
    assert_ne!(
        base_entry.map(|e| format!("{e:?}")),
        sub_entry.map(|e| format!("{e:?}")),
        "the override replaced the slot rather than adding a second one"
    );
}

#[test]
fn an_interface_method_is_dispatched_to_the_implementation() {
    let mut s = Synthetic::new();
    s.declare("callI", &[], "I", 8, 4);
    intern_standard(&mut s);
    // An interface with one method, and a class that implements it.
    let iface = ClassDef::new(IFACE, Some("Ljava/lang/Object;".to_string()))
        .with_method(MethodDef::abstract_("size", &[], "I"));
    s.class(iface);
    let mut impl_class = ClassDef::extending_object("Lj;");
    impl_class.interfaces.push(IFACE.to_string());
    let mut e = Emit::new();
    e.const32(0x14, 0, 21);
    e.op11x(0x0f, 0);
    impl_class = impl_class.with_method(MethodDef::concrete(
        "size",
        &[],
        "I",
        access::ACC_PUBLIC,
        e.code(2, 1, 0),
    ));
    s.class(impl_class);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, "Lj;"));
            a.const4(1, 0);
            a.op35c(0x72, 2, method_at(idx, IFACE, "size", &[], "I"), &[0, 1]);
            a.op11x(0x0a, 2);
            a.op11x(0x0f, 2);
            BTreeMap::from([("callI".to_string(), a.code(8, 0, 4))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "callI", "()I").unwrap(), Value::Int(21));
}

#[test]
fn invoke_super_starts_at_the_superclass_and_does_not_recurse() {
    let mut s = Synthetic::new();
    s.declare("callSuper", &[], "I", 8, 4);
    intern_standard(&mut s);
    // The override, which would give 999 if it were reached.
    let mut e = Emit::new();
    e.const32(0x14, 0, 999);
    e.op11x(0x0f, 0);
    let mut sub = ClassDef::extending_object(SUB);
    sub = sub.with_method(MethodDef::concrete("superMeth", &["I"], "I", access::ACC_PUBLIC, e.code(2, 2, 0)));
    s.class(sub);
    // The superclass body, which is what `invoke-super` must find.
    let mut f = Emit::new();
    f.const4(0, 7);
    f.op12x(0xb0, 0, 1);
    f.op11x(0x0f, 0);
    let mut parent = ClassDef::extending_object("Lp;");
    parent = parent.with_field(FieldDef::instance("p", "I"));
    parent =
        parent.with_method(MethodDef::concrete("superMeth", &["I"], "I", access::ACC_PUBLIC, f.code(2, 2, 0)));
    s.class(parent);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, SUB));
            a.op35c(0x70, 2, method_at(idx, SUB, "<init>", &[], "V"), &[0]);
            a.const4(1, 3);
            a.op35c(0x6f, 2, method_at(idx, SUB, "superMeth", &["I"], "I"), &[0, 1]);
            a.op11x(0x0a, 2);
            a.op11x(0x0f, 2);
            BTreeMap::from([("callSuper".to_string(), a.code(8, 0, 4))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // 7 + 3 from the superclass, not 999 from the override.
    assert_eq!(call0(&mut vm, "callSuper", "()I").unwrap(), Value::Int(10));
}

#[test]
fn a_method_the_file_does_not_declare_is_a_real_no_such_method_error() {
    // Apps detect optional dependencies by catching `NoSuchMethodError`, so this
    // has to be a *throwable*, not a lookup failure.
    let mut s = Synthetic::new();
    s.declare("missing", &[], "I", 6, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.const4(0, 0);
            a.op35c(0x6e, 1, method_at(idx, HOST, "notThere", &["I"], "I"), &[0]);
            a.op11x(0x0a, 0);
            a.op11x(0x0f, 0);
            BTreeMap::from([("missing".to_string(), a.code(6, 0, 2))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(
        thrown_class(&call0(&mut vm, "missing", "()I")),
        "Ljava/lang/NoSuchMethodError;"
    );
}

#[test]
fn an_argument_count_mismatch_is_reported_rather_than_truncating_the_window() {
    let mut s = Synthetic::new();
    s.declare_static("sum", &["I", "I"], "I", 4, 0);
    s.declare("callSum", &[], "I", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.op23x(0x90, 0, 1, 2);
            a.op11x(0x0f, 0);
            out.insert("sum".to_string(), a.code(4, 2, 0));
            let mut b = Emit::new();
            b.const4(0, 1);
            b.const4(1, 2);
            b.op35c(0x71, 3, method_at(idx, HOST, "sum", &["I", "I"], "I"), &[0, 1]);
            b.op11x(0x0a, 2);
            b.op11x(0x0f, 2);
            out.insert("callSum".to_string(), b.code(8, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // The real body is found, so this is the body's own arithmetic.
    assert_eq!(call0(&mut vm, "callSum", "()I").unwrap(), Value::Int(3));
    // Called with the wrong arity from outside, the window check fires.
    assert_eq!(
        malformed_kind(&vm.invoke_method(HOST, "sum", "(II)I", &[Value::Int(1)])),
        "type_mismatch"
    );
    assert_eq!(
        malformed_kind(&vm.invoke_method(HOST, "sum", "(II)I", &[Value::Int(1), Value::Int(2), Value::Int(3)])),
        "type_mismatch"
    );
}

#[test]
fn a_recursive_method_runs_to_a_finite_depth() {
    let mut s = Synthetic::new();
    s.declare_static("recurses", &["I"], "I", 4, 2);
    s.declare("countdown", &[], "I", 8, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            // `recurses(n)` is n == 0 ? 0 : recurses(n - 1) + 1, so it builds a
            // frame per level and returns the depth it reached.
            // The parameter arrives in the argument window at the *end* of the
            // register file, so with four registers it is v3 and not v0.
            let mut a = Emit::new();
            // 0,1 if-nez v3 -> unit 4; 2 const/4 v0, 0; 3 return v0;
            // 4,5 add-int/lit8 v0, v3, #-1
            a.op21t(0x39, 3, 4);
            a.const4(0, 0);
            a.op11x(0x0f, 0);
            a.op22b(0xd8, 0, 3, -1);
            a.op35c(0x71, 1, method_at(idx, HOST, "recurses", &["I"], "I"), &[0]);
            a.op11x(0x0a, 0);
            a.op22b(0xd8, 0, 0, 1);
            a.op11x(0x0f, 0);
            out.insert("recurses".to_string(), a.code(4, 0, 2));
            let mut b = Emit::new();
            b.const4(0, 5);
            b.op35c(0x71, 1, method_at(idx, HOST, "recurses", &["I"], "I"), &[0]);
            b.op11x(0x0a, 1);
            b.op11x(0x0f, 1);
            out.insert("countdown".to_string(), b.code(8, 0, 2));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "countdown", "()I").unwrap(), Value::Int(5));
    let st = vm.stats();
    assert_eq!(st.max_call_depth, 7, "six frames plus the caller");
}

// ============================================================ control flow

#[test]
fn every_two_register_conditional_takes_the_branch_it_should() {
    // 0: v0 = 1, v1 = 1
    // 2,3: if-XX v0, v1, +4  -> target 6
    // 4: v2 = 1              (the not-taken value)
    // 5: return v2
    // 6: v2 = 2              (the taken value)
    // 7: return v2
    let want_taken = [("ifEq", 0x32, true), ("ifNe", 0x33, false), ("ifLt", 0x34, false), ("ifGe", 0x35, true), ("ifGt", 0x36, false), ("ifLe", 0x37, true)];
    let mut s = Synthetic::new();
    for (n, _, _) in want_taken {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            for (n, op, _) in want_taken {
                let mut a = Emit::new();
                a.const4(0, 1);
                a.const4(1, 1);
                a.op22t(op, 0, 1, 4);
                a.const4(2, 1);
                a.op11x(0x0f, 2);
                a.const4(2, 2);
                a.op11x(0x0f, 2);
                out.insert(n.to_string(), a.code(8, 0, 0));
            }
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    for (n, _, taken) in want_taken {
        let want = if taken { 2 } else { 1 };
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), Value::Int(want), "{n}");
    }
}

#[test]
fn every_one_register_conditional_takes_the_branch_it_should() {
    // 0,1: v0 = x            (`const` is two units)
    // 2,3: if-XXz v0, +4  -> target 6
    // 4: v1 = 1              (the not-taken value)
    // 5: return v1
    // 6: v1 = 2              (the taken value)
    // 7: return v1
    let cases = [("ifEqz", 0x38, 0i32, true), ("ifNez", 0x39, 0, false), ("ifLtz", 0x3a, -1, true), ("ifGez", 0x3b, -1, false), ("ifGtz", 0x3c, 1, true), ("ifLez", 0x3d, -1, true)];
    let mut s = Synthetic::new();
    for (n, _, _, _) in cases {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            for (n, op, x, _) in cases {
                let mut a = Emit::new();
                a.const32(0x14, 0, x);
                a.op21t(op, 0, 4);
                a.const4(1, 1);
                a.op11x(0x0f, 1);
                a.const4(1, 2);
                a.op11x(0x0f, 1);
                out.insert(n.to_string(), a.code(8, 0, 0));
            }
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    for (n, _, _, taken) in cases {
        let want = if taken { 2 } else { 1 };
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), Value::Int(want), "{n}");
    }
}

#[test]
fn all_three_goto_widths_skip_exactly_one_instruction() {
    // 0,1: v0 = 7
    // 2..:  goto* +3/+4/+5, past the `const/16` it skips
    //       v0 = 9
    //       return v0
    let mut s = Synthetic::new();
    for n in ["go8", "go16", "go32", "back8", "back16", "back32"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            // The branch sits at unit 2 in all three cases, but it is 1, 2 and
            // 3 units wide, so the offset that clears the following `const/16`
            // is 3, 4 and 5. Using one number for all three would test the
            // widths only by accident.
            let fwd = |out: &mut BTreeMap<String, CodeBody>, n: &str, width: u16, f: &dyn Fn(&mut Emit, i64)| {
                let mut a = Emit::new();
                a.const16(0x13, 0, 7);
                f(&mut a, 2 + width as i64);
                a.const16(0x13, 0, 9);
                a.op11x(0x0f, 0);
                out.insert(n.to_string(), a.code(8, 0, 0));
            };
            fwd(&mut out, "go8", 1, &|a, off| {
                a.op10t(0x28, off as i8);
            });
            fwd(&mut out, "go16", 2, &|a, off| {
                a.op20t(0x29, off as i16);
            });
            fwd(&mut out, "go32", 3, &|a, off| {
                a.op30t(0x2a, off as i32);
            });
            // A backward `goto` makes a loop, so the bodies are separate.
            let mut b = Emit::new();
            b.const4(0, 3); // v0 = counter
            b.const4(1, 0); // v1 = sum
            b.op12x(0xb0, 1, 0); // 2: sum += counter
            b.op22b(0xd8, 0, 0, -1); // 3: counter -= 1
            b.op10t(0x28, -3); // 4: back to unit 2
            b.op11x(0x0f, 1); // 5
            out.insert("back8".to_string(), b.code(8, 0, 0));
            let mut c = Emit::new();
            c.const4(0, 3);
            c.const4(1, 0);
            c.op12x(0xb0, 1, 0);
            c.op22b(0xd8, 0, 0, -1);
            c.op20t(0x29, -3);
            c.op11x(0x0f, 1);
            out.insert("back16".to_string(), c.code(8, 0, 0));
            let mut d = Emit::new();
            d.const4(0, 3);
            d.const4(1, 0);
            d.op12x(0xb0, 1, 0);
            d.op22b(0xd8, 0, 0, -1);
            d.op30t(0x2a, -3);
            d.op11x(0x0f, 1);
            out.insert("back32".to_string(), d.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    for n in ["go8", "go16", "go32"] {
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), Value::Int(7), "{n}");
    }
    for n in ["back8", "back16", "back32"] {
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), Value::Int(6), "{n}");
    }
}

#[test]
fn a_packed_switch_dispatches_on_a_dense_range_and_falls_through_otherwise() {
    // 0: v0 = key
    // 1: packed-switch v0, +9  -> payload at 10
    // 4: v1 = 100            (the default: the fall-through)
    // 5: return v1
    // 6: v1 = 1
    // 7: return v1
    // 8: v1 = 2
    // 9: return v1
    // 10: payload(first_key = 5, targets = [5, 7]) -- relative to unit 1
    let make = |key: i32| {
        let mut a = Emit::new();
        a.const4(0, key as i8);
        let sw = a.here() as i64;
        a.op31t(0x2b, 0, 0);
        a.const16(0x13, 1, 100); // the default: the fall-through
        a.op11x(0x0f, 1);
        let t_five = a.here() as i64;
        a.const4(1, 1);
        a.op11x(0x0f, 1);
        let t_six = a.here() as i64;
        a.const4(1, 2);
        a.op11x(0x0f, 1);
        let payload = a.here() as i64;
        a.packed_switch_payload(5, &[(t_five - sw) as i32, (t_six - sw) as i32]);
        a.patch_i32(sw as usize * 2 + 2, (payload - sw) as i32);
        a.code(8, 0, 0)
    };
    let mut s = Synthetic::new();
    for n in ["pswFirst", "pswSecond", "pswMiss", "pswBelow"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            BTreeMap::from([
                ("pswFirst".to_string(), make(5)),
                ("pswSecond".to_string(), make(6)),
                ("pswMiss".to_string(), make(-1)),
                ("pswBelow".to_string(), make(1)),
            ])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "pswFirst", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "pswSecond", "()I").unwrap(), Value::Int(2));
    assert_eq!(call0(&mut vm, "pswMiss", "()I").unwrap(), Value::Int(100));
    assert_eq!(call0(&mut vm, "pswBelow", "()I").unwrap(), Value::Int(100));
}

#[test]
fn a_sparse_switch_dispatches_on_arbitrary_keys() {
    // The same shape, with keys that are not contiguous: 1, 100, 10000.
    let make = |key: i32| {
        let mut a = Emit::new();
        a.const32(0x14, 0, key);
        let sw = a.here() as i64;
        a.op31t(0x2c, 0, 0);
        a.const32(0x14, 1, 0);
        a.op11x(0x0f, 1);
        let t_one = a.here() as i64;
        a.const4(1, 1);
        a.op11x(0x0f, 1);
        let t_hundred = a.here() as i64;
        a.const16(0x13, 1, 100);
        a.op11x(0x0f, 1);
        let t_tenk = a.here() as i64;
        a.const32(0x14, 1, 10000);
        a.op11x(0x0f, 1);
        let payload = a.here() as i64;
        // Targets are relative to the `sparse-switch`, and are captured as they
        // are emitted: `const` is the four-unit jumbo form, so a hand-counted
        // offset is off by two units by the time the third target is written.
        a.sparse_switch_payload(
            &[1, 100, 10000],
            &[(t_one - sw) as i32, (t_hundred - sw) as i32, (t_tenk - sw) as i32],
        );
        a.patch_i32(sw as usize * 2 + 2, (payload - sw) as i32);
        a.code(8, 0, 0)
    };
    let mut s = Synthetic::new();
    for n in ["sswOne", "sswHundred", "sswTenK", "sswMiss"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            BTreeMap::from([
                ("sswOne".to_string(), make(1)),
                ("sswHundred".to_string(), make(100)),
                ("sswTenK".to_string(), make(10000)),
                ("sswMiss".to_string(), make(2)),
            ])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "sswOne", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "sswHundred", "()I").unwrap(), Value::Int(100));
    assert_eq!(call0(&mut vm, "sswTenK", "()I").unwrap(), Value::Int(10000));
    assert_eq!(call0(&mut vm, "sswMiss", "()I").unwrap(), Value::Int(0));
}

// ============================================================ types and casts

#[test]
fn const_class_instance_of_and_check_cast_agree_about_the_hierarchy() {
    let mut s = Synthetic::new();
    for n in ["isStr", "isFile", "castOk", "castBad", "castNull", "clsName", "mtName"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_type("Ljava/io/File;");
    }
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty_str = ty_at(idx, "Ljava/lang/String;");
            let ty_file = ty_at(idx, "Ljava/io/File;");
            let ty_exc = ty_at(idx, "Ljava/lang/RuntimeException;");
            let ty_mt = ty_at(idx, "Ljava/lang/reflect/MethodType;");

            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "x"));
            a.op22c(0x20, 1, 0, ty_str); // instance-of v1, v0, String
            a.op11x(0x0f, 1);
            out.insert("isStr".to_string(), a.code(8, 0, 0));

            // A class the substrate has never heard of: `instance-of` is false
            // rather than an error, because the object is provably not one.
            let mut b = Emit::new();
            b.op21c(0x1a, 0, string_at(idx, "x"));
            b.op22c(0x20, 1, 0, ty_file);
            b.op11x(0x0f, 1);
            out.insert("isFile".to_string(), b.code(8, 0, 0));

            let mut c = Emit::new();
            c.op21c(0x1a, 0, string_at(idx, "x"));
            c.op21c(0x1f, 0, ty_str);
            c.const4(1, 1);
            c.op11x(0x0f, 1);
            out.insert("castOk".to_string(), c.code(8, 0, 0));

            let mut d = Emit::new();
            d.op21c(0x1a, 0, string_at(idx, "x"));
            d.op21c(0x1f, 0, ty_exc);
            d.const4(1, 1);
            d.op11x(0x0f, 1);
            out.insert("castBad".to_string(), d.code(8, 0, 0));

            // `check-cast` on null always succeeds: there is no object to fail.
            // The null is a field of a fresh object -- fields start zeroed, and
            // an `int` zero in v0 would be a type error, not a null.
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.op22c(0x54, 0, 0, f_o);
            e.op21c(0x1f, 0, ty_str);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            out.insert("castNull".to_string(), e.code(8, 0, 0));

            // `const-class` produces a real `Ljava/lang/Class;`, and casting it
            // to `Ljava/lang/Class;` succeeds.
            let mut f = Emit::new();
            f.op21c(0x1c, 0, ty_str);
            f.op21c(0x1f, 0, ty_at(idx, "Ljava/lang/Class;"));
            f.const4(1, 1);
            f.op11x(0x0f, 1);
            out.insert("clsName".to_string(), f.code(8, 0, 0));

            // `const-method-type` produces a real `MethodType`.
            let mut g = Emit::new();
            g.op21c(0xff, 0, proto_at(idx, &["I"], "Ljava/lang/String;") as u16);
            g.op21c(0x1f, 0, ty_mt);
            g.const4(1, 1);
            g.op11x(0x0f, 1);
            out.insert("mtName".to_string(), g.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "isStr", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "isFile", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "castOk", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "castNull", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "clsName", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "mtName", "()I").unwrap(), Value::Int(1));
    assert_eq!(
        thrown_class(&call0(&mut vm, "castBad", "()I")),
        "Ljava/lang/ClassCastException;"
    );
}

#[test]
fn a_string_constant_is_a_real_object_with_the_right_characters() {
    let mut s = Synthetic::new();
    s.declare("len", &[], "I", 6, 2);
    s.declare("jumbo", &[], "Ljava/lang/Object;", 6, 0);
    intern_standard(&mut s);
    {
        // 40 000 characters, so the string needs a `const-string/jumbo`.
        let big = "x".repeat(40_000);
        s.writer().add_string(&big);
    }
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "hello ☃"));
            a.op35c(0x6e, 2, method_at(idx, "Ljava/lang/String;", "length", &[], "I"), &[0]);
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            out.insert("len".to_string(), a.code(6, 0, 2));
            // `const-string/jumbo` with a 32-bit index.
            let big = "x".repeat(40_000);
            let mut b = Emit::new();
            b.op31c(0x1b, 0, string_at(idx, &big) as u32);
            b.op11x(0x0f, 0);
            out.insert("jumbo".to_string(), b.code(6, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // The shim declines `String.length`, so this is 0 -- but the *string object*
    // exists and is real, which is the part that matters for the study.
    assert_eq!(call0(&mut vm, "len", "()I").unwrap(), Value::Int(0));
    let jumbo = call0(&mut vm, "jumbo", "()Ljava/lang/Object;").unwrap();
    assert_eq!(vm.string_value(jumbo).map(|s| s.len()), Some(40_000), "a jumbo string is 40 000 characters");
    let st = vm.stats();
    // At least the two strings themselves: a `const-string` of any width has to
    // reach the heap as an object, not a tagged immediate.
    assert!(st.allocations >= 2, "both const-string forms allocated a real object: {}", st.allocations);
}

// ============================================================== monitors

#[test]
fn monitors_are_reentrant_and_an_unbalanced_exit_is_reported() {
    let mut s = Synthetic::new();
    for n in ["reentrant", "unbalanced", "enterNull", "exitNull"] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let ty = ty_at(idx, HOST);

            // enter, enter, exit, exit -- both entries succeed.
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty);
            a.op11x(0x1d, 0);
            a.op11x(0x1d, 0);
            a.op11x(0x1e, 0);
            a.op11x(0x1e, 0);
            a.const4(1, 1);
            a.op11x(0x0f, 1);
            out.insert("reentrant".to_string(), a.code(8, 0, 0));

            // Two entries, one exit.
            let mut b = Emit::new();
            b.op21c(0x22, 0, ty);
            b.op11x(0x1d, 0);
            b.op11x(0x1d, 0);
            b.op11x(0x1e, 0);
            b.const4(1, 1);
            b.op11x(0x0f, 1);
            out.insert("unbalanced".to_string(), b.code(8, 0, 0));

            let mut c = Emit::new();
            c.const4(0, 0);
            c.op11x(0x1d, 0);
            c.const4(1, 1);
            c.op11x(0x0f, 1);
            out.insert("enterNull".to_string(), c.code(8, 0, 0));

            let mut d = Emit::new();
            d.op21c(0x22, 0, ty);
            d.op11x(0x1d, 0);
            d.const4(0, 0);
            d.op11x(0x1e, 0);
            d.const4(1, 1);
            d.op11x(0x0f, 1);
            out.insert("exitNull".to_string(), d.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "reentrant", "()I").unwrap(), Value::Int(1));
    // The second `exit` releases a monitor the frame still holds, and the
    // imbalance is reported rather than ignored.
    assert_eq!(malformed_kind(&call0(&mut vm, "unbalanced", "()I")), "type_mismatch");
    assert_eq!(
        thrown_class(&call0(&mut vm, "enterNull", "()I")),
        "Ljava/lang/NullPointerException;"
    );
    assert_eq!(
        thrown_class(&call0(&mut vm, "exitNull", "()I")),
        "Ljava/lang/NullPointerException;"
    );
}

#[test]
fn the_returned_register_counters_describe_the_run() {
    let mut s = Synthetic::new();
    s.declare("work", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.const4(0, 0);
            a.op22c(0x23, 4, 0, ty_at(idx, "[I"));
            for i in 1..8 {
                a.const4(1, i);
                a.const4(2, i - 1);
                a.op23x(0x4b, 1, 4, 2);
            }
            a.op12x(0x21, 0, 4);
            a.op11x(0x0f, 0);
            BTreeMap::from([("work".to_string(), a.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "work", "()I").unwrap(), Value::Int(7));
    let st = vm.stats();
    assert_eq!(st.instructions_executed, 26, "{}", summary(&st));
    assert_eq!(st.allocations, 1);
    assert!(st.bytes_allocated > 0);
    assert_eq!(st.live_objects, 1);
    assert_eq!(st.method_invocations, 1);
    assert_eq!(st.max_call_depth, 1);
    assert_eq!(st.budget_exhausted, false);
    assert_eq!(st.instruction_budget, Config::default().instruction_budget);
    assert_eq!(st.executed(0x23), true, "new-array ran");
    assert_eq!(st.opcode_counts[0x23], 1);
    assert_eq!(st.opcode_counts[0x4b], 7, "aput ran seven times");
}
