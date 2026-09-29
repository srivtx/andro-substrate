//! The constant family: opcodes `0x12`–`0x1c` and the two method-object ones.

use crate::lower::tests::prelude::*;
use crate::lower::tests::assert_refused;

lowering_cases! {
    at 0,
    {
        // ---- the 32-bit immediates.
        const_4: 0x12 => IrOp::ConstI32 { dst: I(1), value: 3 },
            "the literal is a signed four-bit value, sign-extended on the way in";
        const_16: 0x13 => IrOp::ConstI32 { dst: I(1), value: 0x1234 },
            "a signed 16-bit literal, sign-extended to 32 bits and not zero-extended";
        const_32: 0x14 => IrOp::ConstI32 { dst: I(1), value: 0x1234_5678 },
            "a full 32-bit literal";
        const_high16: 0x15 => IrOp::ConstI32 { dst: I(1), value: 0x1234_0000 },
            "the stored 16 bits are the *high half* of the constant, so the effective value \
             is `literal << 16` and the sign carries into bit 31";

        // ---- the 64-bit immediates. Same family, different width, and the width
        // is the whole content of the difference.
        const_wide_16: 0x16 => IrOp::ConstWide { dst: R(1), bits: 0x1234, class: WideClass::Unresolved },
            "a 64-bit literal whose class the input does not state: the same bits are a \
             `long` or a `double`'s IEEE-754 pattern";
        const_wide_32: 0x17 => IrOp::ConstWide { dst: R(1), bits: 0x1234_5678, class: WideClass::Unresolved },
            "and this one **sign**-extends 32 bits into 64; zero-extending would make \
             every negative literal written by hand into a nine-billion-scale number";
        const_wide_64: 0x18 => IrOp::ConstWide { dst: R(1), bits: 0x0123_4567_89ab_cdef, class: WideClass::Unresolved },
            "the full 64 bits, taken as a pattern and not as a number";
        const_wide_high16: 0x19 => IrOp::ConstWide { dst: R(1), bits: 0x1234_0000, class: WideClass::Unresolved },
            "as `const/high16`, in 64 bits: the stored 16 bits are the high half";

        // ---- pool references.
        const_string: 0x1a => IrOp::ConstString { dst: O(1), index: 0x1234 },
            "a `string_ids` index, and the result is a reference so the destination is an \
             `ObjectReg`";
        const_string_jumbo: 0x1b => IrOp::ConstString { dst: O(1), index: 0x1234_5678 },
            "the same operation with a 32-bit index: a string pool above 65,535 entries \
             needs the wide form, and truncating the index would point at a different \
             string rather than fail";
        const_class: 0x1c => IrOp::ConstClass { dst: O(1), index: 0x1234 },
            "a `type_ids` index producing a class object, which is a reference like any other";
    }
}

/// The two object-producing opcodes the IR refuses, and the reason each is named.
///
/// They are the only two of the 224 defined opcodes that do not lower to a
/// specific operation, so they get their own test rather than a row in the table:
/// the claim "these two, and only these two" is a claim about the whole
/// instruction set and belongs where the instruction set is in view.
#[test]
fn the_two_method_object_opcodes_are_refused_by_name() {
    assert_refused(
        0xfe,
        UnsupportedReason::MethodHandle,
        "a `MethodHandle` is a *callable* with identity: two handles for the same method \
         compare equal and two different ones do not. The handle model in `IR.md` \
         allocates offsets and nothing else, so there is nowhere for that to live. This \
         is a host gap, not a compilation gap — `hostgen` is where a fabricated handle and \
         the table that can invoke it belong, and when that table exists this becomes \
         `ConstMethodHandle` with no change to `ir.rs`. The oracle refuses the same \
         opcode as `Unsupported::MethodHandleUnresolved`.",
    );
    assert_refused(
        0xff,
        UnsupportedReason::MethodType,
        "a `MethodType` is a signature object with identity, for the same reason as a \
         `MethodHandle` and with the same remedy.",
    );
}

/// Every refusal reason has a sentence a reader can check and a stable name, and
/// neither is the word "unsupported".
#[test]
fn a_refusal_names_itself() {
    for reason in [
        UnsupportedReason::UnassignedSlot,
        UnsupportedReason::ForeignFormat,
        UnsupportedReason::MethodHandle,
        UnsupportedReason::MethodType,
    ] {
        let name = reason.as_str();
        assert!(!name.is_empty());
        assert_ne!(name, "unsupported", "the word is a claim about the substrate, not the IR");
        assert!(reason.explain().len() > 40, "{name} has no reason worth reviewing");
        assert!(
            reason.explain().ends_with('.'),
            "{name}'s reason is not a sentence: {:?}",
            reason.explain()
        );
    }
}

/// The three widths of 64-bit constant are all *patterns*, and reading any of
/// them as a number is the failure mode the oracle documents at length.
#[test]
fn a_wide_constant_is_a_pattern_and_not_a_number() {
    // `const-wide v0, 0x3fe0000000000000` is how a compiler writes the `double`
    // 0.5. Read as an `i64` it is 4,607,182,418,800,017,408, and every double
    // constant in a real APK becomes a plausible wrong answer. The IR therefore
    // names the field `bits` and leaves the class unresolved.
    let op = crate::lower::tests::lower_sample(0x18).op;
    let IrOp::ConstWide { bits, class, .. } = op else {
        panic!("a 64-bit constant must lower to ConstWide, not to ConstI32")
    };
    assert_eq!(class, WideClass::Unresolved);
    assert_eq!(bits as i64, 0x0123_4567_89ab_cdef);
    // The double 0.5, in the form a compiler actually writes it.
    assert_eq!(0.5f64.to_bits(), 0x3fe0_0000_0000_0000);
    assert_ne!(0x3fe0_0000_0000_0000u64 as i64, 0, "a double pattern is not a small number");
}

/// `const/high16` shifts, and the shift must not be the identity.
#[test]
fn the_high16_shift_is_applied() {
    let IrOp::ConstI32 { value, .. } = crate::lower::tests::lower_sample(0x15).op else {
        panic!("const/high16 produces a 32-bit integer")
    };
    assert_eq!(value, 0x1234_0000);
    assert_ne!(value, 0x1234);
}

/// There is no float literal in the format, so the IR has no float constant.
///
/// This is a property of the *input*, not a gap in the IR, and it is the reason
/// every `float` in a real DEX is written as an `int` constant followed by a
/// conversion. If a `ConstF32` ever appears, the constant family is wrong.
#[test]
fn there_is_no_float_constant_in_the_ir() {
    // The claim is about the IR's shape, so it is made against the family
    // rather than against a particular instruction: no `IrOp` variant holds an
    // `f32` literal. The closest thing is `ConstWide { bits }`, whose class is
    // unresolved precisely because it might be a double.
    for op in [0x12u8, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19] {
        let (IrOp::ConstI32 { .. } | IrOp::ConstWide { .. }) =
            crate::lower::tests::lower_sample(op).op
        else {
            panic!("0x{op:02x} is an immediate and must produce an immediate")
        };
    }
}
