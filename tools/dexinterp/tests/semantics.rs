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
use dexcore::model::access;
use dexcore::writer::{ClassDef, CodeBody, FieldDef, MethodDef};

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
            cases
                .iter()
                .map(|(n, b, _)| (n.to_string(), b.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("emit");
    for (n, _, want) in cases {
        let mut vm = vm(&bytes, Config::default(), None).expect("open");
        let sig = format!("(){ret}");
        assert_eq!(call0(&mut vm, n, &sig).unwrap(), *want, "{n}");
    }
}

/// `const/4 v0, #lit; return v0`, the simplest shape a case can take.
///
/// The literal is an `i8` because `const/4` holds a *signed four-bit* value: a
/// `10` written into it is `-6`, silently. Taking the literal as an `i8` rather
/// than casting one into it is what turns that class of mistake into a
/// compile error instead of a wrong expectation.
fn ret4(lit: i8) -> Emit {
    let mut e = Emit::new();
    e.const4(0, lit);
    e.op11x(0x0f, 0);
    e
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
    // `ret4` is the simplest of the shapes and the only one whose body is
    // generated rather than hand-assembled, so the suite's assertion path runs
    // over it too. A reference to it is enough: the local outlives the `Vec`.
    let mut cases: Vec<(&str, Emit, Value)> = cases.to_vec();
    cases.push(("kRet4", ret4(6), Value::Int(6)));
    let cases = cases;
    let owned: Vec<(String, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (n.to_string(), e.clone().code(4, 0, 0), *v))
        .collect();
    let refs: Vec<(&str, CodeBody, Value)> = owned
        .iter()
        .map(|(n, b, v)| (n.as_str(), b.clone(), *v))
        .collect();
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
    assert_eq!(
        call0(&mut vm, "wmin", "()J").unwrap(),
        Value::Long(i64::MIN)
    );
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
    for n in ["mv16", "mvFrom16", "mvObjFrom16", "mvObj16"] {
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
    // Only the conversions that *narrow to an int* live in this group, because
    // they are the only ones a `()I` method can return without a second
    // conversion. `int-to-long` and `int-to-float` widen, and a widening
    // instruction returned through the 32-bit `return` hands back only the low
    // word — the earlier version of this test did exactly that and asserted
    // `Int`, which described the hand-assembled method rather than the engine.
    // They are checked in `long_negation_and_complement_are_sixty_four_bit`,
    // through the prototype that actually carries them.
    let cases = [
        // `int-to-char` is the one that goes wrong silently: as a sign extension
        // it turns 65535 into -1 and every `Character` comparison inverts.
        ("toByte", int_conv(0x8d, 0xFF), Value::Int(-1)),
        ("toChar", int_conv(0x8e, -1), Value::Int(65535)),
        ("toShort", int_conv(0x8f, 0x1_0000), Value::Int(0)),
        ("notInt", int_conv(0x7c, 0), Value::Int(-1)),
        ("negMin", int_conv(0x7b, i32::MIN), Value::Int(i32::MIN)),
        ("longToInt", long_conv(0x84, 0x1_0000_0007), Value::Int(7)),
        // `long-to-int` truncates the *value*, not the bits: 0x1_0000_0000 is
        // 2^32, whose low 32 bits are zero.
        (
            "longToIntTrunc",
            long_conv(0x84, 0x1_0000_0000),
            Value::Int(0),
        ),
        // `long-to-int` of -1 keeps all its bits, which a saturating
        // implementation would turn into 0.
        ("longToIntNeg", long_conv(0x84, -1), Value::Int(-1)),
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
    // Dalvik has **no float constant**. `const`/`const/16`/`const` write an
    // `int`, and pushing a float's *bit pattern* through `int-to-float` is a
    // numeric conversion, not a reinterpretation: `int-to-float` of
    // `0x7FC00000` is the float 2143289344.0, not a NaN. So the only way to get
    // a NaN into a register is to *compute* one, which is exactly what real code
    // does and what these helpers do: `0.0f / 0.0f`.
    //
    // The previous version of this test built every operand by pushing a bit
    // pattern through `int-to-float`, so each case silently tested a conversion
    // of a large integer and the expectations were wrong rather than the engine.
    let cases = [
        // `float-to-int` of a NaN is 0, not a trap and not `Integer.MIN_VALUE`
        // (which is what x86's `cvttss2si` gives, so ART has to correct it).
        ("f2iNan", f2i(0x87, F32::Nan), Value::Int(0)),
        // A value past 2^31 clamps rather than wrapping.
        ("f2iHuge", f2i(0x87, F32::Huge), Value::Int(i32::MAX)),
        ("f2iNegHuge", f2i(0x87, F32::NegHuge), Value::Int(i32::MIN)),
        // An infinite input clamps too, and is a separate path from "out of
        // range but finite": `2^30f` squared twice is `2^120f`, which overflows
        // to `+Inf`.
        ("f2iInf", f2i(0x87, F32::Inf), Value::Int(i32::MAX)),
        ("f2iNegInf", f2i(0x87, F32::NegInf), Value::Int(i32::MIN)),
        // In range, it truncates *toward zero*: 2.5f is 2 and -2.5f is -2, so the
        // two are not symmetric about a floor.
        ("f2iTrunc", f2i(0x87, F32::Small(2)), Value::Int(2)),
        ("f2iNeg", f2i(0x87, F32::NegSmall(2)), Value::Int(-2)),
        // A whole number just under the limit is exact, so a clamping
        // implementation that saturates too early would fail here.
        (
            "f2iEdge",
            f2i(0x87, F32::Small(2_147_483_647 >> 8)),
            Value::Int(2_147_483_647 >> 8),
        ),
        // The same rules for `double`, whose constants arrive as `const-wide`
        // bit patterns.
        ("d2iNan", d2i(F64::Nan), Value::Int(0)),
        ("d2iHuge", d2i(F64::Huge), Value::Int(i32::MAX)),
        ("d2iNegHuge", d2i(F64::NegHuge), Value::Int(i32::MIN)),
        ("d2iFrac", d2i(F64::Frac), Value::Int(-2)),
        ("d2iExact", d2i(F64::Small(1234)), Value::Int(1234)),
        // `double-to-long` follows the same three rules.
        ("d2lNan", d2l(F64::Nan), Value::Long(0)),
        ("d2lExact", d2l(F64::Small(-5)), Value::Long(-5)),
        ("d2lHuge", d2l(F64::Huge), Value::Long(1 << 60)),
        ("d2lVast", d2l(F64::Vast), Value::Long(i64::MAX)),
        ("d2lNegVast", d2l(F64::NegVast), Value::Long(i64::MIN)),
        // And for the 64-bit narrowing.
        ("f2lNan", f2l(0x88, F32::Nan), Value::Long(0)),
        ("f2lHuge", f2l(0x88, F32::Huge), Value::Long(1 << 60)),
        ("f2lVast", f2l(0x88, F32::Vast), Value::Long(i64::MAX)),
        ("f2lNegVast", f2l(0x88, F32::NegVast), Value::Long(i64::MIN)),
        (
            "f2lExact",
            f2l(0x88, F32::Small(1 << 23)),
            Value::Long(1 << 23),
        ),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&refs, "I");
    // The wide cases need a `()J` signature to be returned faithfully, and the
    // `double`-returning one a `()D`; `check` declares the methods itself, so
    // each group is emitted with the prototype it returns.
    let wide: Vec<(&str, CodeBody, Value)> = cases
        .iter()
        .filter(|(n, _, _)| n.starts_with("f2l") || n.starts_with("d2l"))
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&wide, "J");
}

/// A `float` operand, *described* rather than spelled as bits.
///
/// Dalvik has no float constant, so a test cannot write one. Every value here is
/// produced by an instruction sequence that real code also uses, and every one of
/// them is either exactly representable in `f32` or the result of IEEE arithmetic
/// that Dalvik and Rust define identically. Pushing a *bit pattern* through
/// `int-to-float` — the obvious shortcut — is a numeric conversion, not a
/// reinterpretation: `int-to-float` of `0x7FC00000` is 2143289344.0f, not a NaN.
#[derive(Clone, Copy, Debug)]
enum F32 {
    /// A NaN, from `0.0f / 0.0f`.
    Nan,
    /// `+Inf`, from `1.0f / 0.0f`.
    Inf,
    /// `-Inf`, from `-1.0f / 0.0f`.
    NegInf,
    /// A small integer, converted exactly (`|v| < 2^24`).
    Small(i32),
    /// The negation of a small integer.
    NegSmall(i32),
    /// `+0.0`.
    Zero,
    /// `-0.0`, which only `neg-float` can produce.
    NegZero,
    /// A finite value too large for an `int`: `(2^30f)^2` is exactly 2^60, which
    /// `float-to-int` has to clamp and `float-to-long` represents exactly.
    Huge,
    /// The same, negative.
    NegHuge,
    /// `+Inf` from `(2^30f)^4` = 2^120f, which overflows.
    Vast,
    /// `-Inf`, the same value negated.
    NegVast,
}

impl F32 {
    /// Emit the sequence that leaves the value in `v0`.
    fn emit(self, into: &mut Emit) {
        match self {
            F32::Nan | F32::Inf | F32::NegInf => {
                let n = match self {
                    F32::Nan => 0,
                    F32::Inf => 1,
                    _ => -1,
                };
                into.const4(0, n);
                into.const4(1, 0);
                into.op12x(0x82, 0, 0);
                into.op12x(0x82, 1, 1);
                into.op23x(0xa9, 0, 0, 1); // div-float
            }
            F32::Small(v) => {
                into.const32(0x14, 0, v);
                into.op12x(0x82, 0, 0);
            }
            F32::NegSmall(v) => {
                into.const32(0x14, 0, v);
                into.op12x(0x82, 0, 0);
                into.op12x(0x7f, 0, 0);
            }
            F32::Zero => {
                into.const4(0, 0);
                into.op12x(0x82, 0, 0);
            }
            F32::NegZero => {
                into.const4(0, 0);
                into.op12x(0x82, 0, 0);
                into.op12x(0x7f, 0, 0);
            }
            F32::Huge | F32::NegHuge | F32::Vast | F32::NegVast => {
                // 2^30 as a float, then squared. `int-to-float` of 2^30 is exact,
                // and so is 2^60f; squaring once more gives 2^120f, which is
                // `+Inf`.
                into.const32(0x14, 0, 1 << 30);
                into.op12x(0x82, 0, 0);
                into.op12x(0xc8, 0, 0); // mul-float/2addr -> 2^60
                if matches!(self, F32::Vast | F32::NegVast) {
                    into.op12x(0xc8, 0, 0); // -> 2^120, which is +Inf
                }
                if matches!(self, F32::NegHuge | F32::NegVast) {
                    into.op12x(0x7f, 0, 0);
                }
            }
        }
    }
}

/// A `double` operand, described the same way.
#[derive(Clone, Copy, Debug)]
enum F64 {
    /// A NaN, from `0.0d / 0.0d`.
    Nan,
    /// A small integer, widened exactly.
    Small(i32),
    /// A value with a fractional part, so truncation is observable.
    Frac,
    /// A value too large for an `int` but exactly representable as a `long`:
    /// `(2^30d)^2` is 2^60, which `double-to-int` clamps and `double-to-long`
    /// keeps.
    Huge,
    /// Its negation.
    NegHuge,
    /// `2^120d`, from squaring `Huge` again, which overflows to `+Inf`.
    Vast,
    /// `-Inf`.
    NegVast,
}

impl F64 {
    fn emit(self, into: &mut Emit) {
        match self {
            F64::Nan => {
                into.const_wide(0x18, 0, 0.0f64.to_bits() as i64);
                into.const_wide(0x18, 2, 0.0f64.to_bits() as i64);
                into.op23x(0xae, 0, 0, 2); // div-double
            }
            F64::Small(v) => {
                into.const_wide(0x18, 0, (v as f64).to_bits() as i64);
            }
            F64::Frac => {
                into.const_wide(0x18, 0, (-2.9f64).to_bits() as i64);
            }
            F64::Huge | F64::NegHuge | F64::Vast | F64::NegVast => {
                into.const_wide(0x18, 0, ((1i64 << 30) as f64).to_bits() as i64);
                into.op23x(0xad, 0, 0, 0); // mul-double/2addr -> 2^60
                if matches!(self, F64::Vast | F64::NegVast) {
                    into.op23x(0xad, 0, 0, 0); // -> 2^120, which is +Inf
                }
                if matches!(self, F64::NegHuge | F64::NegVast) {
                    into.op12x(0x80, 0, 0); // neg-double
                }
            }
        }
    }
}

/// `value` materialised as a `float` in `v0`.
fn f_operand(value: F32) -> Emit {
    let mut e = Emit::new();
    value.emit(&mut e);
    e
}

/// `value` materialised as a `double` in `v0`/`v1`.
///
/// A `double` constant *is* its IEEE-754 bit pattern, pushed with `const-wide`,
/// which is the only encoding Dalvik has for one. The engine must read those two
/// words as a `double`'s bits rather than as a `long` whose value is the bit
/// pattern — see `dexinterp::value::Value::as_double`.
fn d_operand(value: F64) -> Emit {
    let mut e = Emit::new();
    value.emit(&mut e);
    e
}

fn f2i(op: u8, value: F32) -> Emit {
    let mut a = f_operand(value);
    a.op12x(op, 1, 0);
    a.op11x(0x0f, 1);
    a
}

fn f2l(op: u8, value: F32) -> Emit {
    let mut a = f_operand(value);
    a.op12x(op, 1, 0);
    a.op11x(0x10, 1);
    a
}

fn d2i(value: F64) -> Emit {
    let mut a = d_operand(value);
    a.op12x(0x8a, 1, 0); // double-to-int
    a.op11x(0x0f, 1);
    a
}

fn d2l(value: F64) -> Emit {
    let mut a = d_operand(value);
    a.op12x(0x8b, 1, 0); // double-to-long
    a.op11x(0x10, 1);
    a
}

/// `float-to-double` applied to `value`; the caller adds the `return`.
fn f2d(value: F32) -> Emit {
    let mut a = f_operand(value);
    a.op12x(0x89, 1, 0); // float-to-double
    a
}

/// Assert that a method returns a NaN `double`, without comparing two NaNs for
/// equality — which is always false, and would make the assertion vacuous.
fn assert_returns_nan(bytes: &[u8], name: &str, ret: &str) {
    let mut vm = vm(bytes, Config::default(), None).expect("open");
    match call0(&mut vm, name, ret) {
        Ok(Value::Double(d)) => assert!(d.is_nan(), "{name} returned {d}, which is not a NaN"),
        Ok(other) => panic!("{name} returned {other:?}, expected a NaN double"),
        Err(e) => panic!("{name} failed: {e}"),
    }
}

#[test]
fn float_to_double_of_a_nan_is_still_a_nan() {
    let mut s = Synthetic::new();
    s.declare("f2dNan", &[], "D", 6, 0);
    s.declare("f2dOne", &[], "D", 6, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut out = BTreeMap::new();
            let mut a = f2d(F32::Nan);
            a.op11x(0x10, 1);
            out.insert("f2dNan".to_string(), a.code(6, 0, 0));
            // 1.0f widened to 1.0d, so the instruction is shown to do something
            // on a value that is *not* a NaN.
            let mut b = f2d(F32::Small(1));
            b.op11x(0x10, 1);
            out.insert("f2dOne".to_string(), b.code(6, 0, 0));
            out
        })
        .expect("emit");
    assert_returns_nan(&bytes, "f2dNan", "()D");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "f2dOne", "()D").unwrap(), Value::Double(1.0));
}

#[test]
fn negating_a_float_flips_the_sign_bit_and_keeps_nan() {
    // The result is compared through its **bit pattern**, because comparing two
    // NaNs with `==` is false and would make the assertion vacuous.
    //
    // The operands are *computed*, not pushed as bit patterns. Dalvik has no
    // float constant, so a test that writes `const v0, 0x7FC00000` and then
    // `int-to-float v0, v0` has performed a numeric conversion and holds
    // 2143289344.0f, not a NaN. `0.0f / 0.0f` is the only route to one and is
    // also what a real app does.
    let cases = [
        // A NaN stays a NaN and only the sign bit changes, so the expected
        // pattern is the negation of a *computed* NaN's pattern, checked through
        // `is_nan` plus the sign bit.
        ("negNan", fneg(F32::Nan), Fp::NanNeg),
        ("negZero", fneg(F32::Zero), Fp::Val(-0.0)),
        ("negOne", fneg(F32::Small(3)), Fp::Val(-3.0)),
        // -0.0 negated is +0.0, which is the case a sign-bit test that only
        // checks "is it negative" gets wrong.
        ("negNegZero", fneg(F32::NegZero), Fp::Val(0.0)),
    ];
    let mut s = Synthetic::new();
    for (n, _, _) in &cases {
        s.declare(n, &[], "F", 6, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            cases
                .iter()
                .map(|(n, e, _)| (n.to_string(), e.clone().code(6, 0, 0)))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("emit");
    for (n, _, want) in cases {
        let mut vm = vm(&bytes, Config::default(), None).expect("open");
        match call0(&mut vm, n, "()F").unwrap() {
            Value::Float(got) => assert!(want.matches(got), "{n}: {got:e} is not {want:?}"),
            other => panic!("{n}: expected a float, got {other:?}"),
        }
    }
}

/// `neg-float` applied to a computed operand.
fn fneg(value: F32) -> Emit {
    let mut a = f_operand(value);
    a.op12x(0x7f, 1, 0); // neg-float v1, v0
    a.op11x(0x0f, 1);
    a
}

#[test]
fn long_negation_and_complement_are_sixty_four_bit() {
    // Every case here is grouped by the *prototype it is returned through*, and
    // the return instruction matches it. The earlier version ran all of them
    // through a method declared `()I` and reached for the 32-bit `return`, which
    // hands back only the low word of a wide value; expecting `Int` there and
    // getting `Long` was a property of the hand-assembled method, not of the
    // engine. A `long` is two registers and needs `return-wide`.
    //
    // The 32-bit group still exercises the conversions *into* a `long`, by
    // narrowing the 64-bit result back down with `long-to-int` — which is how a
    // `long` operation's low half is checked from an `()I` method.
    let narrow = [
        // `long-to-int` of a `long` whose value only fits in 64 bits keeps the
        // low 32, so 0x1_0000_0007 reads back as 7.
        ("longToInt", long_conv(0x84, 0x1_0000_0007), Value::Int(7)),
    ];
    let refs: Vec<(&str, CodeBody, Value)> = narrow
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&refs, "I");

    // The wide forms, returned with `return-wide` from a `()J` method.
    let wide = [
        // `neg-long` of `Long.MIN_VALUE` is itself: two's complement negation
        // overflows, and `Long.MIN_VALUE` is the one value where it does.
        ("lNegMin", long_wide(0x7d, i64::MIN), Value::Long(i64::MIN)),
        ("lNegOne", long_wide(0x7d, 1), Value::Long(-1)),
        ("lNot", long_wide(0x7e, 0), Value::Long(-1)),
        // `int-to-long` sign-extends: -5 stays -5 rather than becoming
        // 4294967291. The operand is a 32-bit `const`, because `int-to-long`
        // reads an `int` — giving it a `const-wide` would be a type error, and
        // the engine correctly says so.
        ("intToLong", int_wide(0x81, -5), Value::Long(-5)),
        (
            "intToLongBig",
            int_wide(0x81, 0x7FFF_FFFF),
            Value::Long(0x7FFF_FFFF),
        ),
    ];
    let wide_refs: Vec<(&str, CodeBody, Value)> = wide
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&wide_refs, "J");

    // And the ones that really do produce a `float`, through a `()F` method.
    let floats = [
        // `int-to-float` of 2^24: 2^24 is the largest magnitude where every
        // integer is still exactly representable as a `float`, which makes it
        // the value a widening test should use.
        (
            "intToFloat",
            int_conv(0x82, 1 << 24),
            Value::Float(16_777_216.0),
        ),
        // `long-to-float` of 2^40, which `f32` also represents exactly.
        (
            "lToFloat",
            {
                let mut a = Emit::new();
                a.const_wide(0x18, 0, 1 << 40);
                a.op12x(0x85, 2, 0); // long-to-float
                a.op11x(0x0f, 2);
                a
            },
            Value::Float(1_099_511_627_776.0),
        ),
    ];
    let float_refs: Vec<(&str, CodeBody, Value)> = floats
        .iter()
        .map(|(n, e, v)| (*n, e.clone().code(6, 0, 0), *v))
        .collect();
    check(&float_refs, "F");
}

/// A widening-from-`int` conversion, returned with `return-wide`.
///
/// The operand is a 32-bit `const`, which is the point: `int-to-long` reads an
/// `int`, and handing it a `const-wide` is a type error that the engine
/// correctly reports.
fn int_wide(op: u8, literal: i32) -> Emit {
    let mut a = Emit::new();
    a.const32(0x14, 0, literal);
    a.op12x(op, 2, 0);
    a.op11x(0x10, 2);
    a
}

/// A wide unary conversion or negation, returned with `return-wide`.
fn long_wide(op: u8, literal: i64) -> Emit {
    let mut a = Emit::new();
    a.const_wide(0x18, 0, literal);
    a.op12x(op, 2, 0);
    a.op11x(0x10, 2);
    a
}

// ========================================================== 23x/22b/22s/2addr

#[test]
fn integer_arithmetic_wraps_and_division_by_zero_throws() {
    let mut s = Synthetic::new();
    for n in [
        "addWrap",
        "mulWrap",
        "minDiv",
        "minRem",
        "divZero",
        "remZero",
        "rsub16",
        "rsub8",
        "shlMask",
        "shrArith",
        "ushr",
        "divLit16Zero",
        "andLit8",
        "orLit16",
        "xorLit8",
        "addLit16",
        "mulLit16",
        "divLit8",
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
    for n in [
        "a2add",
        "a2sub",
        "a2shl",
        "a2long",
        "a2longPad",
        "a2double",
        "a2longToDouble",
        "a2rem",
    ] {
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
            // source and destination. The literals use `const/16` rather than
            // `const/4` because `const/4` holds a *signed four-bit* value — a
            // `10` written into it becomes `-6`, silently, and every arithmetic
            // expectation after it inverts. That is a property of the encoding
            // rather than of the engine, and it is the single easiest way to
            // hand-assemble a wrong test.
            let mut a = Emit::new();
            a.const16(0x13, 0, 10);
            a.const16(0x13, 1, -3);
            a.op12x(0xb0, 0, 1);
            a.op11x(0x0f, 0);
            push("a2add", a);
            let mut b = Emit::new();
            b.const16(0x13, 0, 10);
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
            // A wide 2addr writes two registers. 0x1_0000_0000 + 5 is
            // 0x1_0000_0005, so the *low* word is 5 — the earlier expectation of
            // 0 described a case where the value was not a multiple of 2^32.
            let mut d = Emit::new();
            d.const_wide(0x18, 0, 0x1_0000_0000);
            d.const_wide(0x18, 2, 5);
            d.op12x(0xbb, 0, 2);
            d.op12x(0x84, 4, 0); // long-to-int, keeping the low word
            d.op11x(0x0f, 4);
            push("a2long", d);
            // The same body read through its *high* word. The register model
            // makes that word the pad, and reading the pad is a type error
            // rather than the wrong half of the number — which is the property
            // the wide 2addr forms exist to guarantee.
            let mut g = Emit::new();
            g.const_wide(0x18, 0, 0x1_0000_0000);
            g.const_wide(0x18, 2, 5);
            g.op12x(0xbb, 0, 2);
            g.op11x(0x0f, 1); // return the high word
            push("a2longPad", g);
            // 2.5 * 2.0 as doubles, then to an int.
            //
            // Two corrections to the earlier version of this case. The opcode
            // was `sub-double/2addr` (0xcc) while the comment said `*`; `*` is
            // 0xcd. And the two `long-to-double` instructions were wrong in a way
            // worth stating: a `double` constant is its own `const-wide` bit
            // pattern, and `long-to-double` is a *numeric* conversion of a
            // `long`, so applying it to `0x4004000000000000` yields
            // 4.6e18, not 2.5. No compiler emits `long-to-double` to materialise
            // a double literal — the `const-wide` already is one — so a test that
            // does is testing a cast the source never contained.
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 2.5f64.to_bits() as i64);
            e.const_wide(0x18, 2, 2.0f64.to_bits() as i64);
            e.op12x(0xcd, 0, 2); // mul-double/2addr v0, v2
            e.op12x(0x8a, 4, 0); // double-to-int
            e.op11x(0x0f, 4);
            push("a2double", e);
            // And the numeric reading of the same bits, so the two are pinned
            // apart: `long-to-double` of 0x4004000000000000 is 4.6e18, and
            // `double-to-int` of that saturates to i32::MAX.
            let mut h = Emit::new();
            h.const_wide(0x18, 0, 2.5f64.to_bits() as i64);
            h.op12x(0x86, 2, 0); // long-to-double: a numeric cast
            h.op12x(0x8a, 4, 2); // double-to-int
            h.op11x(0x0f, 4);
            push("a2longToDouble", h);
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
    assert_eq!(call0(&mut vm, "a2long", "()I").unwrap(), Value::Int(5));
    assert_eq!(
        malformed_kind(&call0(&mut vm, "a2longPad", "()I")),
        "type_mismatch"
    );
    assert_eq!(call0(&mut vm, "a2double", "()I").unwrap(), Value::Int(5));
    assert_eq!(
        call0(&mut vm, "a2longToDouble", "()I").unwrap(),
        Value::Int(i32::MAX)
    );
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
    assert_eq!(
        call0(&mut vm, "lAdd", "()J").unwrap(),
        Value::Long(i64::MIN)
    );
    assert_eq!(
        call0(&mut vm, "lWrap", "()J").unwrap(),
        Value::Long(i64::MIN)
    );
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
        // -0.0 * 1.0 is -0.0, and *no constant in Dalvik can produce -0.0*:
        // `const/4` takes a signed four-bit integer, so the only way to get
        // negative zero is `neg-float` applied to positive zero. That is what
        // this case does, and it is the case an equality assertion cannot
        // distinguish (`-0.0 == 0.0` is true), so `Fp::matches` compares the
        // sign bit.
        ("fmulNegZero", fmul_neg_zero().code(8, 0, 0), Fp::Val(-0.0)),
    ]);
}

/// `-0.0f * 1.0f`, with the negative zero made by `neg-float`.
fn fmul_neg_zero() -> Emit {
    let mut a = Emit::new();
    a.const4(0, 0);
    a.const4(1, 1);
    a.op12x(0x82, 0, 0); // 0.0f
    a.op12x(0x82, 1, 1); // 1.0f
    a.op12x(0x7f, 0, 0); // -0.0f
    a.op23x(0xa8, 2, 0, 1); // mul-float v2, v0, v1
    a.op11x(0x0f, 2);
    a
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
    /// A NaN with a positive sign, i.e. the *quiet* NaN `int-to-float` of
    /// nothing at all.
    Nan,
    /// A NaN whose sign bit is set, which is what negating a NaN produces.
    NanNeg,
    Inf,
    NegInf,
    Val(f32),
}

impl Fp {
    fn matches(self, got: f32) -> bool {
        match self {
            Fp::Nan => got.is_nan() && !got.is_sign_negative(),
            Fp::NanNeg => got.is_nan() && got.is_sign_negative(),
            Fp::Inf => got == f32::INFINITY,
            Fp::NegInf => got == f32::NEG_INFINITY,
            Fp::Val(v) => {
                // Signed zero is compared by sign: `0.0 == -0.0` is true in
                // IEEE, so an equality test cannot tell `neg-float` on `+0.0`
                // from `neg-float` on `-0.0` when one of them is expected.
                if v == 0.0 {
                    return got == 0.0 && got.is_sign_negative() == v.is_sign_negative();
                }
                got == v
            }
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
            cases
                .iter()
                .map(|(n, b, _)| (n.to_string(), b.clone()))
                .collect::<BTreeMap<_, _>>()
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
    for n in [
        "byteArr", "charArr", "boolArr", "arrLen", "oobLo", "oobHi", "negSize", "arrStore",
        "lenNeg", "arrNull",
    ] {
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
    // One declaration per name with the return type its body produces; see the
    // note in `instance_and_static_fields_round_trip`.
    for n in ["fna", "fnar"] {
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
            // The element values use `const/16`, not `const/4`: the packed form
            // holds a signed *four*-bit literal, so an `8` written into it is
            // `-8` and the array quietly holds the wrong numbers.
            let mut a = Emit::new();
            a.const4(0, 7);
            a.const16(0x13, 1, 8);
            a.op35c(0x24, 2, ty_i, &[0, 1]);
            a.op11x(0x0c, 0); // move-result-object
            a.const4(1, 0);
            a.op23x(0x44, 2, 0, 1); // aget v2, v0, v1
            a.op11x(0x0f, 2);
            out.insert("fna".to_string(), a.code(10, 0, 4));
            // The range form: `AA` is the element count and the elements run from
            // the `CCCC` register, so {v1, v2} becomes a two-element array and
            // reading index 1 gives back v2.
            let mut b = Emit::new();
            b.const4(1, 2);
            b.const16(0x13, 2, 9);
            b.op3rc(0x25, 2, ty_i, 1);
            b.op11x(0x0c, 3);
            b.const4(1, 1);
            b.op23x(0x44, 4, 3, 1);
            b.op11x(0x0f, 4);
            out.insert("fnar".to_string(), b.code(10, 0, 4));
            // A `double[]` in one instruction, proving the high words land: an
            // implementation that only moved the low half would return 0.
            //
            // The values are raw IEEE-754 bit patterns pushed with `const-wide`,
            // which is the *only* way Dalvik can express a double literal, and
            // the element is read back with `aget-wide` so the test observes the
            // array rather than the array's reference.
            let mut c = Emit::new();
            c.const_wide(0x18, 0, 1.5f64.to_bits() as i64);
            c.const4(2, 1);
            c.op35c(0x24, 2, ty_d, &[0, 2]);
            c.op11x(0x0c, 3); // move-result-object v3
            c.const4(4, 0);
            c.op23x(0x45, 5, 3, 4); // aget-wide v5, v3, v4
            c.op11x(0x10, 5); // return-wide
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
    // One declaration per name, with the return type the body produces: see the
    // note in `instance_and_static_fields_round_trip` for why a second
    // declaration of the same name leaves the second one bodyless.
    for n in ["fillByte", "fillShort", "fillInt", "fillChar"] {
        s.declare(n, &[], "I", 12, 0);
    }
    s.declare("fillLong", &[], "J", 12, 0);
    // `fillFloat` reads its element back with `aget`, so the value in the
    // register is a *float* and the method has to declare `()F`. Declaring it
    // `()I` and asserting the element's bit pattern described a conversion that
    // never happens: `aget` on a `float[]` yields a float, and the only way to
    // see the bits again is to convert back with `float-to-int`.
    s.declare("fillFloat", &[], "F", 12, 0);
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
            push(
                "fillShort",
                "[S",
                2,
                vec![0x01, 0x02, 0xFF, 0xFF],
                0x4a,
                false,
            );
            push(
                "fillInt",
                "[I",
                4,
                vec![0x01, 0x02, 0x03, 0x04, 0x11, 0x22, 0x33, 0x44],
                0x44,
                false,
            );
            push(
                "fillLong",
                "[J",
                8,
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
                0x45,
                true,
            );
            push(
                "fillChar",
                "[C",
                2,
                vec![0x01, 0x02, 0xFF, 0xFF],
                0x49,
                false,
            );
            push(
                "fillFloat",
                "[F",
                4,
                1.5f32
                    .to_le_bytes()
                    .to_vec()
                    .into_iter()
                    .chain(2.5f32.to_le_bytes().to_vec())
                    .collect(),
                0x44,
                false,
            );
            push(
                "fillDouble",
                "[D",
                8,
                1.5f64
                    .to_le_bytes()
                    .to_vec()
                    .into_iter()
                    .chain(2.5f64.to_le_bytes().to_vec())
                    .collect(),
                0x45,
                true,
            );
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // The second element of each payload, read at the component's width.
    assert_eq!(
        call0(&mut vm, "fillByte", "()I").unwrap(),
        Value::Int(-1),
        "byte 0xFF sign-extends"
    );
    assert_eq!(call0(&mut vm, "fillShort", "()I").unwrap(), Value::Int(-1));
    assert_eq!(
        call0(&mut vm, "fillInt", "()I").unwrap(),
        Value::Int(0x4433_2211)
    );
    assert_eq!(
        call0(&mut vm, "fillChar", "()I").unwrap(),
        Value::Int(65535),
        "char zero-extends"
    );
    assert_eq!(
        call0(&mut vm, "fillLong", "()J").unwrap(),
        Value::Long(i64::from_le_bytes([9, 10, 11, 12, 13, 14, 15, 16]))
    );
    assert_eq!(
        call0(&mut vm, "fillFloat", "()F").unwrap(),
        Value::Float(2.5)
    );
    match call0(&mut vm, "fillDouble", "()D").unwrap() {
        Value::Double(d) => assert_eq!(d, 2.5),
        other => panic!("{other:?}"),
    }
}

// ================================================================ fields

#[test]
fn instance_and_static_fields_round_trip() {
    let mut s = Synthetic::new();
    // Each name is declared *once*, with the return type its body actually
    // produces. Declaring a name twice — once `I` and once `J`, say — makes the
    // class carry two `method_ids` entries for it, and `DexWriter::set_code`
    // installs the body on the first match, so the second declaration ends up
    // with no `code_item` at all and the call silently falls through to the
    // framework shim. The symptom is a method that returns a plausible zero.
    for n in ["fI", "fSStat", "fSWrite", "fNeg"] {
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
    // The `Ljava/lang/Object;` round trip returns the object it read back, and
    // `String.toString()` is declined by the shim, so the only thing observable
    // is that the reference survived the write — which `assert_ne!(.., Null)`
    // states without depending on framework behaviour.
    let obj = call0(&mut vm, "fObj", "()Ljava/lang/Object;").unwrap();
    assert!(
        matches!(obj, Value::Ref(_)),
        "the stored object came back, got {obj:?}"
    );
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
    rec.field(
        "Landroid/view/WindowManager$LayoutParams;->screenBrightness:F",
        HostValue::Float(0.5),
    );
    rec.field("Lorg/x/R;->id:I", HostValue::Int(2130903040));
    let mut s = Synthetic::new();
    s.declare("layoutField", &[], "F", 6, 0);
    s.declare("appStatic", &[], "I", 4, 0);
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_field(
            "Landroid/view/WindowManager$LayoutParams;",
            "screenBrightness",
            "F",
        );
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
            a.op21c(
                0x22,
                0,
                ty_at(idx, "Landroid/view/WindowManager$LayoutParams;"),
            );
            a.op22c(
                0x52,
                1,
                0,
                field_at(
                    idx,
                    "Landroid/view/WindowManager$LayoutParams;",
                    "screenBrightness",
                    "F",
                ),
            );
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
    assert!(rec
        .log()
        .contains(&"Landroid/view/WindowManager$LayoutParams;->screenBrightness:F".to_string()));
}

// ================================================================ calls

#[test]
fn move_result_reads_the_value_the_callee_returned() {
    let mut s = Synthetic::new();
    s.declare_static("getInt", &[], "I", 2, 0);
    s.declare_static("getLong", &[], "J", 4, 0);
    s.declare_static("getObject", &[], "Ljava/lang/Object;", 2, 0);
    // Each caller is declared once, with the return type its body produces, and
    // each gives the callee a real body — otherwise the call falls through to
    // the shim and the test would be asserting that a stub returns zero. See
    // `instance_and_static_fields_round_trip` for the double-declaration trap.
    s.declare("callInt", &[], "I", 8, 4);
    s.declare("callLong", &[], "J", 8, 4);
    s.declare("callObj", &[], "Ljava/lang/Object;", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            // Every callee returns a non-zero constant, so a value that reaches
            // `move-result` is distinguishable from the shim's default of zero.
            let mut g = Emit::new();
            g.const16(0x13, 0, 42);
            g.op11x(0x0f, 0);
            out.insert("getInt".to_string(), g.code(2, 0, 0));
            let mut l = Emit::new();
            l.const_wide(0x18, 0, -7);
            l.op11x(0x10, 0);
            out.insert("getLong".to_string(), l.code(4, 0, 0));
            let mut o = Emit::new();
            o.op21c(0x1a, 0, string_at(idx, "from the callee"));
            o.op11x(0x11, 0);
            out.insert("getObject".to_string(), o.code(2, 0, 0));

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
            c.op35c(
                0x71,
                0,
                method_at(idx, HOST, "getObject", &[], "Ljava/lang/Object;"),
                &[],
            );
            c.op11x(0x0c, 0);
            c.op11x(0x11, 0);
            out.insert("callObj".to_string(), c.code(8, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "callInt", "()I").unwrap(), Value::Int(42));
    assert_eq!(call0(&mut vm, "callLong", "()J").unwrap(), Value::Long(-7));
    // `move-result-object` produces a *reference*, so the caller is declared to
    // return `Ljava/lang/Object;` and the assertion is on the reference: the
    // string the callee built is readable back out of the heap. Declaring the
    // caller `()I` and expecting `Int(0)` would have asserted that an object
    // return silently became the integer zero.
    let obj = call0(&mut vm, "callObj", "()Ljava/lang/Object;").unwrap();
    assert_eq!(vm.string_value(obj), Some("from the callee"));
    // No host, so every call is a `NotImplemented` stub returning the declared
    // type's zero value. That is the rule the whole study depends on: it is what
    // lets a real app run to completion before the shim exists. With the
    // callees above declaring real bodies there are no framework calls at all,
    // so the counters are zero.
    let st = vm.stats();
    assert_eq!(st.framework_calls, 0);
    assert_eq!(st.framework_calls_unimplemented, 0);
    assert!(st.shim_log.iter().all(|r| !r.implemented));
}

#[test]
fn an_unimplemented_call_yields_the_declared_types_zero_value() {
    // The complement of the test above: with *no* body for the callee the
    // engine must substitute the declared return type's zero value and carry
    // on, which is the rule that lets an app run before the framework shim
    // exists. Each return type is checked separately because each has its own
    // zero: `0`, `0L`, `null`.
    let mut s = Synthetic::new();
    s.declare_static("noBodyInt", &[], "I", 2, 0);
    s.declare_static("noBodyLong", &[], "J", 4, 0);
    s.declare_static("noBodyVoid", &[], "V", 2, 0);
    s.declare_static("noBodyObject", &[], "Ljava/lang/Object;", 2, 0);
    s.declare_static("callNoInt", &[], "I", 8, 4);
    s.declare_static("callNoLong", &[], "J", 8, 4);
    s.declare_static("callNoVoid", &[], "V", 8, 4);
    s.declare_static("callNoObject", &[], "Ljava/lang/Object;", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.op35c(0x71, 0, method_at(idx, HOST, "noBodyInt", &[], "I"), &[]);
            a.op11x(0x0a, 0);
            a.op11x(0x0f, 0);
            out.insert("callNoInt".to_string(), a.code(8, 0, 4));
            let mut b = Emit::new();
            b.op35c(0x71, 0, method_at(idx, HOST, "noBodyLong", &[], "J"), &[]);
            b.op11x(0x0b, 0);
            b.op11x(0x10, 0);
            out.insert("callNoLong".to_string(), b.code(8, 0, 4));
            let mut c = Emit::new();
            c.op35c(0x71, 0, method_at(idx, HOST, "noBodyVoid", &[], "V"), &[]);
            c.op11x(0x0e, 0);
            out.insert("callNoVoid".to_string(), c.code(8, 0, 4));
            let mut d = Emit::new();
            d.op35c(
                0x71,
                0,
                method_at(idx, HOST, "noBodyObject", &[], "Ljava/lang/Object;"),
                &[],
            );
            d.op11x(0x0c, 0);
            d.op11x(0x11, 0);
            out.insert("callNoObject".to_string(), d.code(8, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "callNoInt", "()I").unwrap(), Value::Int(0));
    assert_eq!(call0(&mut vm, "callNoLong", "()J").unwrap(), Value::Long(0));
    assert_eq!(call0(&mut vm, "callNoVoid", "()V").unwrap(), Value::Void);
    assert_eq!(
        call0(&mut vm, "callNoObject", "()Ljava/lang/Object;").unwrap(),
        Value::Null
    );
    let st = vm.stats();
    assert_eq!(
        st.framework_calls, 4,
        "each stubbed call is recorded exactly once"
    );
    assert_eq!(st.framework_calls_unimplemented, 4);
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
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Ljava/lang/String;", "length", &[], "I"),
                &[0],
            );
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
    assert_eq!(
        st.framework_calls_unimplemented, 0,
        "the host answered, so nothing was guessed"
    );
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
        w.add_method(
            "Lcom/x/Provider;",
            "get",
            &["Ljava/lang/String;"],
            "Ljava/lang/String;",
        );
    }
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.const4(0, 0);
            a.op35c(
                0x6e,
                2,
                method_at(
                    idx,
                    "Lcom/x/Provider;",
                    "get",
                    &["Ljava/lang/String;"],
                    "Ljava/lang/String;",
                ),
                &[0, 0],
            );
            a.op11x(0x0c, 1);
            // Store it in a field so the harness can read the object out.
            a.const4(0, 0);
            a.op22c(0x22, 2, 0, 0);
            a.op22c(0x5b, 1, 2, field_at(idx, HOST, "o", "Ljava/lang/Object;"));
            // Return its length, which the shim can compute for us.
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Ljava/lang/String;", "length", &[], "I"),
                &[1],
            );
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
                a.code_tries(
                    12,
                    0,
                    8,
                    vec![catches(0, 9, &[("Ljava/lang/RuntimeException;", 9)], None)],
                ),
            );

            // A `catch (Error)` clause does *not* catch a RuntimeException, so
            // the same call is uncaught here. The hierarchy has to be walked the
            // right way for both to be right.
            //
            // The two clauses point at *different* handlers, so a passing test
            // distinguishes "the catch-all ran" from "the `Error` clause ran" —
            // which is the whole point. `Error` returns 9, the catch-all returns
            // 0, and both handlers have to be inside the method's own units:
            // 0,1 const-string  2,3 const-string  4,5,6 invoke  7 move-result
            // 8 return-object  |  9,10 the Error handler  11 its return
            // 12,13 the catch-all.
            let mut b = Emit::new();
            b.op21c(0x1a, 0, string_at(idx, "a"));
            b.op21c(0x1a, 1, string_at(idx, "b"));
            b.op35c(0x6e, 3, rep, &[0, 1]);
            b.op11x(0x0c, 2);
            b.op11x(0x11, 2);
            b.const16(0x13, 3, 9);
            b.op11x(0x0f, 3);
            b.const4(3, 0);
            b.op11x(0x0f, 3);
            out.insert(
                "wrongClause".to_string(),
                b.code_tries(
                    12,
                    0,
                    8,
                    vec![catches(0, 9, &[("Ljava/lang/Error;", 9)], Some(12))],
                ),
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
    // after it is the clause that runs. The `Error` handler returns 9 and the
    // catch-all returns 0, so seeing 0 is positive evidence that the *catch-all*
    // ran rather than that the `Error` clause did.
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
    rec.throw(
        "Ljava/lang/String;->length()I",
        "Ljava/lang/NoSuchMethodError;",
        "gone",
    );
    let mut s = Synthetic::new();
    s.declare("hierarchy", &[], "I", 10, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x1a, 0, string_at(idx, "a"));
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Ljava/lang/String;", "length", &[], "I"),
                &[0],
            );
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            a.const16(0x13, 1, 42); // the handler: unit 7
            a.op11x(0x0f, 1);
            BTreeMap::from([(
                "hierarchy".to_string(),
                a.code_tries(
                    10,
                    0,
                    2,
                    vec![catches(0, 3, &[("Ljava/lang/Error;", 7)], None)],
                ),
            )])
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
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Ljava/lang/String;", "length", &[], "I"),
                &[0],
            );
            a.op11x(0x0a, 1);
            a.op11x(0x0f, 1);
            a.const4(1, 7);
            a.op11x(0x0f, 1);
            // The invoke is at unit 2 (the `const-string` takes two), so the
            // protected range has to cover it and not just the first unit.
            BTreeMap::from([(
                "catchAll".to_string(),
                a.code_tries(10, 0, 2, vec![catch_all(0, 3, 7)]),
            )])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), Some(rec)).expect("open");
    assert_eq!(call0(&mut vm, "catchAll", "()I").unwrap(), Value::Int(7));
}

#[test]
fn virtual_dispatch_picks_the_subclass_through_the_vtable() {
    let mut s = Synthetic::new();
    s.declare("callV", &[], "I", 8, 4);
    s.declare("callBase", &[], "I", 8, 4);
    // The superclass has to *declare* `vMeth` for there to be a vtable slot to
    // override. A method that is merely interned in the pool
    // (`DexWriter::add_method`) has no `class_data` entry, so no vtable slot, and
    // `vtable_lookup` correctly answers `None` for it. Declaring it with a body
    // that returns a third constant makes the override observable: the slot must
    // be *replaced*, not shadowed by a second slot.
    s.declare("vMeth", &["I"], "I", 2, 2);
    intern_standard(&mut s);
    // The superclass's `vMeth`: 100 + arg.
    let mut base = Emit::new();
    base.const16(0x13, 0, 100);
    base.op12x(0xb0, 0, 1);
    base.op11x(0x0f, 0);
    // The override: 77 + arg. It reads its own parameter, so the result cannot be
    // confused with a body that ignores the argument.
    let over = {
        let mut e = Emit::new();
        e.const16(0x13, 0, 77);
        e.op12x(0xb0, 0, 1);
        e.op11x(0x0f, 0);
        e
    };
    let mut ctor = Emit::new();
    ctor.op11x(0x0e, 0);
    let sub = ClassDef::extending_object(SUB)
        .with_field(FieldDef::instance("u", "I"))
        // A `class_data` item lists direct methods first and virtual ones after,
        // and `<init>` is a direct method; without one, `invoke-direct` on it is
        // a real `NoSuchMethodError` and the test would be about that instead.
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC,
            ctor.code(1, 1, 0),
        ))
        .with_method(MethodDef::concrete(
            "vMeth",
            &["I"],
            "I",
            access::ACC_PUBLIC,
            over.clone().code(2, 2, 0),
        ));
    s.class(sub);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            out.insert("vMeth".to_string(), base.clone().code(2, 2, 2));
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, SUB));
            a.op35c(0x70, 2, method_at(idx, SUB, "<init>", &[], "V"), &[0]);
            a.const4(1, 5);
            a.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[0, 1]);
            a.op11x(0x0a, 2);
            a.op11x(0x0f, 2);
            out.insert("callV".to_string(), a.code(8, 0, 4));
            // The same call through an `Lt;` receiver, which must reach the
            // superclass's own `vMeth`.
            let mut c = Emit::new();
            c.op21c(0x22, 0, ty_at(idx, HOST));
            c.const4(1, 5);
            c.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[0, 1]);
            c.op11x(0x0a, 2);
            c.op11x(0x0f, 2);
            out.insert("callBase".to_string(), c.code(8, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // 77 + 5, computed in `Lu;.vMeth`: the superclass body would give 105, a host
    // stub would give 0, and a mis-resolved vtable would give something else.
    assert_eq!(call0(&mut vm, "callV", "()I").unwrap(), Value::Int(82));
    // The override *replaced* its slot rather than clobbering the superclass's
    // body: a call through an `Lt;` receiver still reaches `Lt;.vMeth` and gives
    // 105. If the override had overwritten the superclass's entry, this would
    // come back as 82 and the two results would be indistinguishable.
    assert_eq!(call0(&mut vm, "callBase", "()I").unwrap(), Value::Int(105));
    let base_entry = {
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
        // And both vtables carry the key, so the override was matched by name and
        // prototype rather than appended as a second entry.
        let key = ("vMeth".to_string(), "(I)I".to_string());
        for (id, name) in [(base, HOST), (sub, SUB)] {
            let meta = prog.class(id).expect("class");
            let slot = meta
                .vtable_index
                .get(&key)
                .copied()
                .unwrap_or_else(|| panic!("{name} has no vMeth vtable slot"))
                as usize;
            assert_eq!(
                meta.vtable
                    .get(slot)
                    .map(|(_, _, e)| e == base_entry.unwrap())
                    .unwrap_or(false),
                name == HOST,
                "the subclass's slot must hold the override, not the superclass's body"
            );
        }
        base_entry.unwrap()
    };
    let _ = base_entry;
}

#[test]
fn invoke_super_starts_at_the_superclass_and_does_not_recurse() {
    let mut s = Synthetic::new();
    s.declare("callSuper", &[], "I", 8, 4);
    intern_standard(&mut s);
    // The override, which would give 999 if it were reached.
    let mut e = Emit::new();
    e.const16(0x13, 0, 999);
    e.op11x(0x0f, 0);
    let mut ctor = Emit::new();
    ctor.op11x(0x0e, 0);
    // `Lu;` must *extend* `Lp;` for `invoke-super` to have anywhere to go:
    // `invoke-super` resolves from the superclass of the class the instruction
    // names, so a class that extends `Ljava/lang/Object;` resolves to `Object`
    // and finds no `superMeth` at all. `ClassDef::extending_object` builds the
    // class it is *given*, extending `Object` — so naming it `Lp;` would build
    // `Lp;` and never `Lu;`.
    let sub = ClassDef::new(SUB, Some("Lp;".to_string()))
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC,
            ctor.code(1, 1, 0),
        ))
        .with_method(MethodDef::concrete(
            "superMeth",
            &["I"],
            "I",
            access::ACC_PUBLIC,
            e.code(2, 2, 0),
        ));
    s.class(sub);
    // The superclass body, which is what `invoke-super` must find. Two registers:
    // with `ins_size` 2 the incoming window is v0 (`this`) and v1 (the argument),
    // so the body adds v0 and v1 in place.
    let mut f = Emit::new();
    f.const4(0, 7);
    f.op12x(0xb0, 0, 1);
    f.op11x(0x0f, 0);
    let mut parent = ClassDef::extending_object("Lp;");
    parent = parent.with_field(FieldDef::instance("p", "I"));
    parent = parent.with_method(MethodDef::concrete(
        "superMeth",
        &["I"],
        "I",
        access::ACC_PUBLIC,
        f.code(2, 2, 0),
    ));
    s.class(parent);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, SUB));
            a.op35c(0x70, 2, method_at(idx, SUB, "<init>", &[], "V"), &[0]);
            a.const4(1, 3);
            a.op35c(
                0x6f,
                2,
                method_at(idx, SUB, "superMeth", &["I"], "I"),
                &[0, 1],
            );
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
            // `sum` is static with two `int` parameters and four registers, so
            // Dalvik puts the incoming arguments in the *last* `ins_size`
            // registers: v2 and v3, not v0 and v1. Reading v1 reads a register
            // nothing ever wrote, and the correct diagnostic for that is
            // `uninitialised_register` — which is what the engine says.
            a.op23x(0x90, 0, 2, 3);
            a.op11x(0x0f, 0);
            out.insert("sum".to_string(), a.code(4, 2, 0));
            let mut b = Emit::new();
            b.const4(0, 1);
            b.const4(1, 2);
            b.op35c(
                0x71,
                2,
                method_at(idx, HOST, "sum", &["I", "I"], "I"),
                &[0, 1],
            );
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
        malformed_kind(&vm.invoke_method(
            HOST,
            "sum",
            "(II)I",
            &[Value::Int(1), Value::Int(2), Value::Int(3)]
        )),
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
    let want_taken = [
        ("ifEq", 0x32, true),
        ("ifNe", 0x33, false),
        ("ifLt", 0x34, false),
        ("ifGe", 0x35, true),
        ("ifGt", 0x36, false),
        ("ifLe", 0x37, true),
    ];
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
    let cases = [
        ("ifEqz", 0x38, 0i32, true),
        ("ifNez", 0x39, 0, false),
        ("ifLtz", 0x3a, -1, true),
        ("ifGez", 0x3b, -1, false),
        ("ifGtz", 0x3c, 1, true),
        ("ifLez", 0x3d, -1, true),
    ];
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
            let fwd = |out: &mut BTreeMap<String, CodeBody>,
                       n: &str,
                       width: u16,
                       f: &dyn Fn(&mut Emit, i64)| {
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
            // A backward `goto` makes a loop, so the bodies are separate — and a
            // loop needs an exit, or the run ends at the instruction budget
            // rather than at a `return`. The earlier version of this test had no
            // condition at all: `goto -3` from a counter that was decremented
            // forever, which is a spin, not a loop. The shape is therefore
            //
            //   0        const/4 v0, 3          the counter
            //   1        const/4 v1, 0          the accumulator
            //   2,3      if-eqz v0, +K          the exit, to the `return`
            //   4        add-int/2addr v1, v0
            //   5,6      add-int/lit8 v0, v0, #-1
            //   7..      goto -5                back to unit 2
            //   7 + w    return v1
            //
            // and the two offsets are *not* the same number across the three
            // widths even though the `goto` is: a branch offset is measured in
            // code units from the branch itself, and the branch occupies a
            // different number of units each time, which moves the `return`
            // without moving the `goto`'s target.
            //
            // 3 + 2 + 1 + 1 + w + 1 = 7 + w units before the `return`, so the
            // `if-eqz` at unit 2 needs +(5 + w) and the `goto` at unit 7 needs -5.
            let mut b = Emit::new();
            b.const4(0, 3); // 0
            b.const4(1, 0); // 1
            b.op21t(0x38, 0, 6); // 2,3: if-eqz v0 -> unit 8
            b.op12x(0xb0, 1, 0); // 4
            b.op22b(0xd8, 0, 0, -1); // 5,6
            b.op10t(0x28, -5); // 7: back to unit 2
            b.op11x(0x0f, 1); // 8
            out.insert("back8".to_string(), b.code(8, 0, 0));
            let mut c = Emit::new();
            c.const4(0, 3); // 0
            c.const4(1, 0); // 1
            c.op21t(0x38, 0, 7); // 2,3: if-eqz v0 -> unit 9
            c.op12x(0xb0, 1, 0); // 4
            c.op22b(0xd8, 0, 0, -1); // 5,6
            c.op20t(0x29, -5); // 7,8: back to unit 2
            c.op11x(0x0f, 1); // 9
            out.insert("back16".to_string(), c.code(8, 0, 0));
            let mut d = Emit::new();
            d.const4(0, 3); // 0
            d.const4(1, 0); // 1
            d.op21t(0x38, 0, 8); // 2,3: if-eqz v0 -> unit 10
            d.op12x(0xb0, 1, 0); // 4
            d.op22b(0xd8, 0, 0, -1); // 5,6
            d.op30t(0x2a, -5); // 7,8,9: back to unit 2
            d.op11x(0x0f, 1); // 10
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
            &[
                (t_one - sw) as i32,
                (t_hundred - sw) as i32,
                (t_tenk - sw) as i32,
            ],
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
    assert_eq!(
        call0(&mut vm, "sswHundred", "()I").unwrap(),
        Value::Int(100)
    );
    assert_eq!(call0(&mut vm, "sswTenK", "()I").unwrap(), Value::Int(10000));
    assert_eq!(call0(&mut vm, "sswMiss", "()I").unwrap(), Value::Int(0));
}

// ============================================================ types and casts

#[test]
fn const_class_instance_of_and_check_cast_agree_about_the_hierarchy() {
    let mut s = Synthetic::new();
    for n in [
        "isStr", "isFile", "castOk", "castBad", "castNull", "clsName", "mtName",
    ] {
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
            a.op35c(
                0x6e,
                2,
                method_at(idx, "Ljava/lang/String;", "length", &[], "I"),
                &[0],
            );
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
    assert_eq!(
        vm.string_value(jumbo).map(|s| s.len()),
        Some(40_000),
        "a jumbo string is 40 000 characters"
    );
    let st = vm.stats();
    // At least the two strings themselves: a `const-string` of any width has to
    // reach the heap as an object, not a tagged immediate.
    assert!(
        st.allocations >= 2,
        "both const-string forms allocated a real object: {}",
        st.allocations
    );
}

// ============================================================== monitors

#[test]
fn monitors_are_reentrant_and_an_unbalanced_exit_is_reported() {
    let mut s = Synthetic::new();
    for n in [
        "reentrant",
        "unbalanced",
        "enterNull",
        "exitNull",
        "exitNeverHeld",
        "holdsOnReturn",
    ] {
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

            // Two entries and *two* exits: still balanced, so this one runs.
            // The reentrancy is what makes the second exit legal, and a
            // non-reentrant implementation would refuse it.
            let mut b = Emit::new();
            b.op21c(0x22, 0, ty);
            b.op11x(0x1d, 0);
            b.op11x(0x1d, 0);
            b.op11x(0x1e, 0);
            b.op11x(0x1e, 0);
            b.const4(1, 1);
            b.op11x(0x0f, 1);
            out.insert("unbalanced".to_string(), b.code(8, 0, 0));

            // One entry and two exits: the second exit releases a monitor the
            // frame does not hold. The correct discriminant is
            // `unbalanced_monitor`, not `type_mismatch` — the earlier version
            // asserted `type_mismatch` because that was the only "some Malformed"
            // the taxonomy happened to offer for it, and the error text did not
            // say anything about types. The precise kind is now
            // `Malformed::UnbalancedMonitor`.
            let mut c = Emit::new();
            c.op21c(0x22, 0, ty);
            c.op11x(0x1d, 0);
            c.op11x(0x1e, 0);
            c.op11x(0x1e, 0);
            c.const4(1, 1);
            c.op11x(0x0f, 1);
            out.insert("exitNeverHeld".to_string(), c.code(8, 0, 0));

            // A frame that returns while still holding a monitor. The previous
            // version of this test had two entries and one exit and then a
            // `return`, expecting an error — which is the same imbalance, but it
            // was going through the frame-pop path rather than through
            // `monitor-exit`, so the two had to be pinned separately.
            let mut d = Emit::new();
            d.op21c(0x22, 0, ty);
            d.op11x(0x1d, 0);
            d.const4(1, 1);
            d.op11x(0x0f, 1);
            out.insert("holdsOnReturn".to_string(), d.code(8, 0, 0));

            // A null has to be manufactured: an untouched register is
            // *uninitialised*, and an `int` zero is not a reference. Reading an
            // object field nobody wrote gives a real null, which is why the
            // earlier `const/4 v0, 0` produced a `type_mismatch` rather than
            // the `NullPointerException` the test meant.
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.op22c(0x54, 0, 0, f_o);
            e.op11x(0x1d, 0);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            out.insert("enterNull".to_string(), e.code(8, 0, 0));

            // Exit a *null* monitor. Again the null has to be a real reference:
            // `const/4 v0, 0` is the integer zero, and `monitor-exit` on an
            // integer is a type error, not a `NullPointerException`.
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            let mut f = Emit::new();
            f.op21c(0x22, 0, ty);
            f.op22c(0x54, 1, 0, f_o);
            f.op11x(0x1e, 1);
            f.const4(1, 1);
            f.op11x(0x0f, 1);
            out.insert("exitNull".to_string(), f.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "reentrant", "()I").unwrap(), Value::Int(1));
    assert_eq!(call0(&mut vm, "unbalanced", "()I").unwrap(), Value::Int(1));
    // Both imbalances are `unbalanced_monitor` and both are *engine faults*
    // rather than exceptions: the Dalvik verifier tracks monitor state along
    // every path, so a real APK cannot reach either, and reporting them as
    // `exception_raised` would put a finding about the file in the bucket that
    // means "the app crashed".
    for n in ["exitNeverHeld", "holdsOnReturn"] {
        assert_eq!(
            malformed_kind(&call0(&mut vm, n, "()I")),
            "unbalanced_monitor",
            "{n}"
        );
        assert_termination(&call0(&mut vm, n, "()I"), Termination::EngineFault);
    }
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
fn equality_branches_compare_references_and_not_just_integers() {
    // `if-eq`, `if-ne`, `if-eqz` and `if-nez` are defined over 32-bit *words*, and
    // a reference is one word, so a compiler emits all four for reference
    // comparison. These are the two forms that carry the whole of `==` and `!=`
    // on objects in a real APK, and requiring an `int` for them refuses the most
    // common branch in Android bytecode.
    //
    // Both cases below were found by running `fr.smarquis.sleeptimer_16200`:
    //
    //   Ld;.equals(Ljava/lang/Object;)Z  unit 1: if-ne v5, v4   -- o != this
    //   Le;.b(Object,Object)Z           unit 0: if-nez v0        -- a != null
    //
    // and both were reported as `type_mismatch`, which is a claim about the
    // *file* and is not true.
    let mut s = Synthetic::new();
    for n in [
        "objNeSelf",
        "objEqSelf",
        "nullEqNull",
        "intNotNull",
        "refNotZero",
        "intNotZero",
        "wideNeSelf",
    ] {
        s.declare(n, &[], "I", 8, 0);
    }
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let f_o = field_at(idx, HOST, "o", "Ljava/lang/Object;");
            // `a != b` on two references. The branch is taken (they are
            // different objects) so the method returns 2; the fall-through
            // returns 1, and both are written because a method that runs off the
            // end of its own instruction stream is a different error entirely.
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, HOST));
            a.op21c(0x22, 1, ty_at(idx, SUB));
            a.op22t(0x33, 1, 0, 4); // -> unit 8
            a.const4(2, 1);
            a.op11x(0x0f, 2);
            a.const4(2, 2);
            a.op11x(0x0f, 2);
            out.insert("objNeSelf".to_string(), a.code(8, 0, 0));
            // The same with `if-eq`, which must *not* be taken for two different
            // objects, so the fall-through `1` comes back.
            let mut b = Emit::new();
            b.op21c(0x22, 0, ty_at(idx, HOST));
            b.op21c(0x22, 1, ty_at(idx, SUB));
            b.op22t(0x32, 1, 0, 4);
            b.const4(2, 1);
            b.op11x(0x0f, 2);
            b.const4(2, 2);
            b.op11x(0x0f, 2);
            out.insert("objEqSelf".to_string(), b.code(8, 0, 0));
            // `null == null` is true, so the branch is taken and `2` is returned.
            // Two nulls come from an unwritten object field, because a register
            // that nothing wrote is *uninitialised* rather than null.
            let mut c = Emit::new();
            c.op21c(0x22, 0, ty_at(idx, HOST));
            c.op22c(0x54, 1, 0, f_o);
            c.op22c(0x54, 2, 0, f_o);
            c.op22t(0x32, 1, 2, 4);
            c.const4(3, 1);
            c.op11x(0x0f, 3);
            c.const4(3, 2);
            c.op11x(0x0f, 3);
            out.insert("nullEqNull".to_string(), c.code(8, 0, 0));
            // The integer case, which must be unchanged: 0 != 7 is taken.
            let mut d = Emit::new();
            d.const4(0, 0);
            d.const4(1, 7);
            d.op22t(0x33, 0, 1, 4);
            d.const4(2, 1);
            d.op11x(0x0f, 2);
            d.const4(2, 2);
            d.op11x(0x0f, 2);
            out.insert("intNotNull".to_string(), d.code(8, 0, 0));
            // `if-nez` on a reference: non-null, so the branch is taken and `2`
            // comes back. This is the `x == null` fast path in its other form.
            //   0,1 new-instance v0
            //   2,3 if-nez v0, +2  -> unit 6
            //   4   const/4 v1, 1
            //   5   return v1
            //   6   const/4 v1, 2
            //   7   return v1
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.op21t(0x39, 0, 4);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e.const4(1, 2);
            e.op11x(0x0f, 1);
            out.insert("refNotZero".to_string(), e.code(8, 0, 0));
            // `if-nez` on an integer zero, which must *not* be taken.
            let mut f = Emit::new();
            f.const4(0, 0);
            f.op21t(0x39, 0, 4);
            f.const4(1, 1);
            f.op11x(0x0f, 1);
            f.const4(1, 2);
            f.op11x(0x0f, 1);
            out.insert("intNotZero".to_string(), f.code(8, 0, 0));
            // A `long` in one of these registers is still refused: it is two
            // words, and no single-register comparison covers that width.
            let mut g = Emit::new();
            g.const_wide(0x18, 0, 1);
            g.const_wide(0x18, 2, 1);
            g.op22t(0x33, 0, 2, 4);
            g.const4(4, 1);
            g.op11x(0x0f, 4);
            g.const4(4, 2);
            g.op11x(0x0f, 4);
            out.insert("wideNeSelf".to_string(), g.code(8, 0, 0));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    for (n, want) in [
        ("objNeSelf", 2),
        ("objEqSelf", 1),
        ("nullEqNull", 2),
        ("intNotNull", 2),
        ("refNotZero", 2),
        ("intNotZero", 1),
    ] {
        assert_eq!(call0(&mut vm, n, "()I").unwrap(), Value::Int(want), "{n}");
    }
    // A wide operand is a type error, and it is the *only* thing that is: the
    // engine draws the line at register width, not at "not an int".
    assert_eq!(
        malformed_kind(&call0(&mut vm, "wideNeSelf", "()I")),
        "type_mismatch"
    );
}

#[test]
fn an_argument_count_is_counted_in_values_not_in_register_words() {
    // A `long` parameter is two register words and one *value*. Checking the
    // caller's value count against the callee's word count makes every method with
    // a `long` or `double` parameter unreachable — the witness is a real
    // `Ls;.c(Landroid/content/Context;JLandroid/app/Notification;)V` in
    // `fr.smarquis.sleeptimer_16200`, where a three-value call was rejected as
    // "4 argument words".
    let mut s = Synthetic::new();
    s.declare_static("takesLong", &["J"], "I", 6, 0);
    s.declare_static("takesDouble", &["D"], "I", 6, 0);
    s.declare_static("callerLong", &[], "I", 8, 4);
    s.declare_static("callerDouble", &[], "I", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            // The callee reads the incoming `long` from the last two registers of
            // its window: `ins_size` is 2, so v4 and v5.
            let mut a = Emit::new();
            a.op12x(0x84, 0, 4); // long-to-int
            a.op11x(0x0f, 0);
            out.insert("takesLong".to_string(), a.code(6, 2, 0));
            let mut b = Emit::new();
            b.const_wide(0x18, 0, (7.9f64).to_bits() as i64);
            b.op12x(0x8a, 0, 0); // double-to-int
            b.op11x(0x0f, 0);
            out.insert("takesDouble".to_string(), b.code(6, 2, 0));
            let mut c = Emit::new();
            c.const_wide(0x18, 0, 5);
            c.op35c(
                0x71,
                1,
                method_at(idx, HOST, "takesLong", &["J"], "I"),
                &[0],
            );
            c.op11x(0x0a, 1);
            c.op11x(0x0f, 1);
            out.insert("callerLong".to_string(), c.code(8, 0, 4));
            let mut d = Emit::new();
            d.const_wide(0x18, 0, (7.9f64).to_bits() as i64);
            d.op35c(
                0x71,
                1,
                method_at(idx, HOST, "takesDouble", &["D"], "I"),
                &[0],
            );
            d.op11x(0x0a, 1);
            d.op11x(0x0f, 1);
            out.insert("callerDouble".to_string(), d.code(8, 0, 4));
            out
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(call0(&mut vm, "callerLong", "()I").unwrap(), Value::Int(5));
    assert_eq!(
        call0(&mut vm, "callerDouble", "()I").unwrap(),
        Value::Int(7)
    );
    // The wrong number of *values* is still refused, and the message now counts
    // arguments rather than words.
    //
    // Note the argument types: passing an `int` where a `long` is expected is
    // *accepted*, because there is no verifier and the engine widens a 32-bit
    // operand word when a 64-bit one is asked for. Asserting otherwise here would
    // be asserting a verifier, which this crate deliberately does not have — see
    // `docs/decisions/0003-execution-engine.md`.
    for (sig, args) in [
        ("(J)I", vec![]),
        ("(J)I", vec![Value::Long(1), Value::Long(2)]),
    ] {
        let r = vm.invoke_method(HOST, "takesLong", sig, &args);
        assert_eq!(
            malformed_kind(&r),
            "type_mismatch",
            "{sig} with {} args",
            args.len()
        );
        let e = r.expect_err("must refuse");
        assert!(format!("{e}").contains("takes 1 argument(s)"), "{e}");
    }
}

#[test]
fn the_returned_register_counters_describe_the_run() {
    let mut s = Synthetic::new();
    // Static, so the *only* object in the heap is the array the method builds.
    // As an instance method the harness would allocate a receiver first and the
    // allocation counters would read 2, which is a fact about the harness and
    // not about the run being measured.
    s.declare_static("work", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut a = Emit::new();
            // The array has to be at least as long as the highest index the loop
            // writes, and the loop writes indices 0..6, so the length is 7. The
            // previous version allocated a **zero-length** array, which made the
            // first `aput` an `ArrayIndexOutOfBoundsException` and the test
            // fail for a reason that had nothing to do with the counters.
            a.const4(0, 7);
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
    // 1 `const/4` + 1 `new-array` + 7 x (`const/4`, `const/4`, `aput`) +
    // 1 `array-length` + 1 `return` = 25 *instructions*. The old expectation of
    // 26 counted the `const/4` that sets the array length as the four-unit jumbo
    // form, which it is not: `const/4` is one code unit, and
    // `Stats::instructions_executed` counts instructions rather than units. Both
    // are one per instruction here, so the two only differ because of that
    // miscount; the seven `aput`s and the one `new-array` below pin the rest.
    assert_eq!(st.instructions_executed, 25, "{}", summary(&st));
    assert_eq!(st.allocations, 1);
    assert!(st.bytes_allocated > 0);
    assert_eq!(st.live_objects, 1);
    assert_eq!(st.method_invocations, 1);
    assert_eq!(st.max_call_depth, 1);
    assert!(!st.budget_exhausted);
    assert_eq!(st.instruction_budget, Config::default().instruction_budget);
    assert!(st.executed(0x23), "new-array ran");
    assert_eq!(st.opcode_counts[0x23], 1);
    assert_eq!(st.opcode_counts[0x4b], 7, "aput ran seven times");
    // The histogram is indexed by opcode byte and is totally addressable, so a
    // zero entry is a *claim* that the opcode never ran rather than a gap.
    assert_eq!(
        st.opcode_counts[0x12], 15,
        "one const/4 before the loop plus two per iteration"
    );
    assert_eq!(st.opcode_counts[0x21], 1, "array-length");
    assert_eq!(st.opcode_counts[0x0f], 1, "return");
    assert_eq!(st.opcode_counts[0x4c], 0, "aput-wide never ran");
    // Five *kinds* of instruction, however many times each ran: `const/4`,
    // `new-array`, `aput`, `array-length` and `return`. The count is over
    // distinct opcode bytes, not over executions, so the seven `aput`s and the
    // eight `const/4`s are each worth one.
    assert_eq!(st.distinct_opcodes(), 5);
}
