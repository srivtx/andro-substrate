//! The memory family: opcodes `0x44`–`0x51` (array elements) and `0x52`–`0x6d`
//! (instance and static fields).
//!
//! # What these thirty-six opcodes have in common
//!
//! Every one of them reads or writes a value whose class **the instruction does
//! not state**, and there are exactly two ways that happens:
//!
//! * *32 bits.* `aget`/`aput` are specified over "one 32-bit element", which is
//!   an `int` in an `int[]` and a `float` in a `float[]`; `iget`/`iput` on a
//!   `float` field say the same. The array or the field decides, and the answer
//!   is in the file rather than in the instruction, so the IR records
//!   [`WordClass::Unresolved`].
//! * *64 bits.* `aget-wide` and `iget-wide` cover both a `long` and a `double`,
//!   so [`WideClass::Unresolved`].
//!
//! The *sub-word* forms have no such problem: `aget-boolean` through
//! `aget-short` are unambiguously 32-bit integers and differ only in how they
//! widen. That difference is [`Narrow`], and it is the whole content of sixteen
//! opcodes. Getting its sign wrong produces a plausible negative number rather
//! than a trap, which is why it is a named field and not an implied detail.

use crate::lower::tests::prelude::*;
use crate::lower::tests::field;

lowering_cases! {
    at 0,
    {
        aget: 0x44 => IrOp::AgetWord { dst: R(1), array: O(2), index: I(3), class: WordClass::Unresolved },
            "one 32-bit element whose class is the *array's* component type rather than the instruction's: it is an `int` in an `int[]` and a `float` in a `float[]`, and the instruction does not say. Recorded as unresolved rather than guessed";
        aget_wide: 0x45 => IrOp::AgetWide { dst: R(1), array: O(2), index: I(3), class: WideClass::Unresolved },
            "one 64-bit element, and the same ambiguity one width up: a `long` or a `double`. The *element width* is known — 8 bytes — so `codegen` emits a class-agnostic 64-bit load";
        aget_object: 0x46 => IrOp::AgetObject { dst: O(1), array: O(2), index: I(3) },
            "a reference element, which is unambiguous and lands in an `ObjectReg`";
        aget_boolean: 0x47 => IrOp::AgetNarrow { dst: I(1), array: O(2), index: I(3), narrow: Narrow::Boolean },
            "a `boolean` element, **zero**-extended from one byte. A stored `0xFF` is 255, not -1";
        aget_byte: 0x48 => IrOp::AgetNarrow { dst: I(1), array: O(2), index: I(3), narrow: Narrow::SByte },
            "a `byte` element, **sign**-extended from one byte: `0xFF` is -1. One bit of difference from the boolean above, and the two are adjacent opcodes";
        aget_char: 0x49 => IrOp::AgetNarrow { dst: I(1), array: O(2), index: I(3), narrow: Narrow::Char },
            "a `char` element, **zero**-extended from two bytes: `0xFFFF` is 65535";
        aget_short: 0x4a => IrOp::AgetNarrow { dst: I(1), array: O(2), index: I(3), narrow: Narrow::Short },
            "a `short` element, **sign**-extended from two bytes: `0xFFFF` is -1 again";
        aput: 0x4b => IrOp::AputWord { array: O(2), index: I(3), value: R(1), class: WordClass::Unresolved },
            "the store, with the value first in the encoding and the array second; the operand order in the IR is the *semantic* one, so a transposed lowering fails this table";
        aput_wide: 0x4c => IrOp::AputWide { array: O(2), index: I(3), value: R(1), class: WideClass::Unresolved },
            "as `aget-wide`, storing";
        aput_object: 0x4d => IrOp::AputObject { array: O(2), index: I(3), value: O(1) },
            "a reference element store";
        aput_boolean: 0x4e => IrOp::AputNarrow { array: O(2), index: I(3), value: I(1), narrow: Narrow::Boolean },
            "a `boolean` element store: truncated to one byte, and the value's low bit is what the specification says is stored";
        aput_byte: 0x4f => IrOp::AputNarrow { array: O(2), index: I(3), value: I(1), narrow: Narrow::SByte },
            "a `byte` element store: truncated to one byte, keeping the low 8 bits";
        aput_char: 0x50 => IrOp::AputNarrow { array: O(2), index: I(3), value: I(1), narrow: Narrow::Char },
            "a `char` element store: truncated to two bytes";
        aput_short: 0x51 => IrOp::AputNarrow { array: O(2), index: I(3), value: I(1), narrow: Narrow::Short },
            "a `short` element store: truncated to two bytes";
        iget: 0x52 => IrOp::IgetWord { dst: R(1), object: O(2), field: field(), class: WordClass::Unresolved },
            "a 32-bit field whose class is the field's declared type, not the instruction's — the same ambiguity as `aget`, and resolvable only from the `field_ids` entry";
        iget_wide: 0x53 => IrOp::IgetWide { dst: R(1), object: O(2), field: field(), class: WideClass::Unresolved },
            "a 64-bit field: a `long` or a `double`, and the instruction does not say";
        iget_object: 0x54 => IrOp::IgetObject { dst: O(1), object: O(2), field: field() },
            "a reference field";
        iget_boolean: 0x55 => IrOp::IgetNarrow { dst: I(1), object: O(2), field: field(), narrow: Narrow::Boolean },
            "a `boolean` field, zero-extended from one byte";
        iget_byte: 0x56 => IrOp::IgetNarrow { dst: I(1), object: O(2), field: field(), narrow: Narrow::SByte },
            "a `byte` field, sign-extended from one byte";
        iget_char: 0x57 => IrOp::IgetNarrow { dst: I(1), object: O(2), field: field(), narrow: Narrow::Char },
            "a `char` field, zero-extended from two bytes";
        iget_short: 0x58 => IrOp::IgetNarrow { dst: I(1), object: O(2), field: field(), narrow: Narrow::Short },
            "a `short` field, sign-extended from two bytes";
        iput: 0x59 => IrOp::IputWord { object: O(2), field: field(), value: R(1), class: WordClass::Unresolved },
            "the store, with the value in the `A` field of the encoding and the receiver in `B`";
        iput_wide: 0x5a => IrOp::IputWide { object: O(2), field: field(), value: R(1), class: WideClass::Unresolved },
            "a 64-bit field store";
        iput_object: 0x5b => IrOp::IputObject { object: O(2), field: field(), value: O(1) },
            "a reference field store";
        iput_boolean: 0x5c => IrOp::IputNarrow { object: O(2), field: field(), value: I(1), narrow: Narrow::Boolean },
            "a `boolean` field store";
        iput_byte: 0x5d => IrOp::IputNarrow { object: O(2), field: field(), value: I(1), narrow: Narrow::SByte },
            "a `byte` field store";
        iput_char: 0x5e => IrOp::IputNarrow { object: O(2), field: field(), value: I(1), narrow: Narrow::Char },
            "a `char` field store";
        iput_short: 0x5f => IrOp::IputNarrow { object: O(2), field: field(), value: I(1), narrow: Narrow::Short },
            "a `short` field store";
        sget: 0x60 => IrOp::SgetWord { dst: R(1), field: field(), class: WordClass::Unresolved },
            "a 32-bit static field";
        sget_wide: 0x61 => IrOp::SgetWide { dst: R(1), field: field(), class: WideClass::Unresolved },
            "a 64-bit static field";
        sget_object: 0x62 => IrOp::SgetObject { dst: O(1), field: field() },
            "a reference static field";
        sget_boolean: 0x63 => IrOp::SgetNarrow { dst: I(1), field: field(), narrow: Narrow::Boolean },
            "a `boolean` static field, zero-extended";
        sget_byte: 0x64 => IrOp::SgetNarrow { dst: I(1), field: field(), narrow: Narrow::SByte },
            "a `byte` static field, sign-extended";
        sget_char: 0x65 => IrOp::SgetNarrow { dst: I(1), field: field(), narrow: Narrow::Char },
            "a `char` static field, zero-extended";
        sget_short: 0x66 => IrOp::SgetNarrow { dst: I(1), field: field(), narrow: Narrow::Short },
            "a `short` static field, sign-extended";
        sput: 0x67 => IrOp::SputWord { field: field(), value: R(1), class: WordClass::Unresolved },
            "a 32-bit static field store";
        sput_wide: 0x68 => IrOp::SputWide { field: field(), value: R(1), class: WideClass::Unresolved },
            "a 64-bit static field store";
        sput_object: 0x69 => IrOp::SputObject { field: field(), value: O(1) },
            "a reference static field store";
        sput_boolean: 0x6a => IrOp::SputNarrow { field: field(), value: I(1), narrow: Narrow::Boolean },
            "a `boolean` static field store";
        sput_byte: 0x6b => IrOp::SputNarrow { field: field(), value: I(1), narrow: Narrow::SByte },
            "a `byte` static field store";
        sput_char: 0x6c => IrOp::SputNarrow { field: field(), value: I(1), narrow: Narrow::Char },
            "a `char` static field store";
        sput_short: 0x6d => IrOp::SputNarrow { field: field(), value: I(1), narrow: Narrow::Short },
            "a `short` static field store";
    }
}

/// The six narrowings are six different things, and the load and store
/// directions are not inverses of one another.
///
/// This is a table rather than prose because the failure it prevents is silent:
/// a `char` read as signed and a `short` read as unsigned both produce a number,
/// and only a program that depends on the difference notices. The boolean case is
/// the sharp one — a stored `0xFF` reads back as **1**, not 255, because a
/// boolean array holds 0 or 1 and the oracle reads it as `raw != 0`.
#[test]
fn the_narrowings_differ_in_both_directions() {
    let loads = [
        (Narrow::Int, 0xffff_ffffu32, -1i32, "a full word is not extended at all"),
        (Narrow::Boolean, 0xff, 1i32, "a boolean element is 0 or 1, so 0xff reads as 1"),
        (Narrow::Boolean, 0x00, 0i32, "and 0 reads as 0"),
        (Narrow::Byte, 0xff, 255i32, "an unsigned byte is zero-extended"),
        (Narrow::SByte, 0xff, -1i32, "a signed byte is sign-extended"),
        (Narrow::Char, 0xffff, 65535i32, "a char is zero-extended"),
        (Narrow::Short, 0xffff, -1i32, "a short is sign-extended"),
    ];
    for (narrow, raw, want, why) in loads {
        assert_eq!(narrow.widen(raw), want, "{why}: {narrow:?}.widen({raw:#x})");
    }
    let stores = [
        (Narrow::Int, -1i32, -1i32, "a full word is not truncated"),
        (Narrow::Boolean, 0xff, 1i32, "a boolean store keeps the low bit"),
        (Narrow::Boolean, 2, 0i32, "and 2 stores as 0"),
        (Narrow::Byte, 0x1ff, 0xff, "an unsigned byte keeps the low 8 bits"),
        (Narrow::SByte, 0x1ff, -1i32, "a signed byte keeps the low 8 bits, sign included"),
        (Narrow::Char, 0x1_0001, 1i32, "a char keeps the low 16 bits"),
        (Narrow::Short, 0x1_0001, 1i32, "a short keeps the low 16 bits, sign included"),
    ];
    for (narrow, value, want, why) in stores {
        assert_eq!(narrow.truncate(value), want, "{why}: {narrow:?}.truncate({value:#x})");
    }
    assert_eq!(Narrow::Boolean.byte_width(), 1);
    assert_eq!(Narrow::Byte.byte_width(), 1);
    assert_eq!(Narrow::Char.byte_width(), 2);
    assert_eq!(Narrow::Int.byte_width(), 4);
    // The load and store sides of one element class must name the same class, or
    // a round trip through an array changes the value.
    for op in 0x47u8..=0x4a {
        let IrOp::AgetNarrow { narrow, .. } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is a narrow load")
        };
        let store = 0x4e + (op - 0x47);
        let IrOp::AputNarrow { narrow: back, .. } = crate::lower::tests::lower_sample(store).op
        else {
            panic!("0x{store:02x} is the matching narrow store")
        };
        assert_eq!(narrow, back, "0x{op:02x} and 0x{store:02x} disagree on the element class");
    }
}

/// An instance field and a static field of the same declared class must produce
/// the same *shape* of operation, differing only in the receiver.
#[test]
fn the_static_and_instance_forms_differ_only_in_the_receiver() {
    for (inst_op, stat_op) in [(0x52u8, 0x60u8), (0x53, 0x61), (0x54, 0x62), (0x59, 0x67), (0x5a, 0x68), (0x5b, 0x69)] {
        let a = crate::lower::tests::lower_sample(inst_op).op;
        let b = crate::lower::tests::lower_sample(stat_op).op;
        let a_reads = a.reads().len();
        let b_reads = b.reads().len();
        assert_eq!(
            a_reads,
            b_reads + 1,
            "0x{inst_op:02x} and 0x{stat_op:02x} should differ by exactly the receiver"
        );
        // ...and the field index must survive both.
        let field_of = |op: &IrOp| -> Option<u32> {
            match op {
                IrOp::IgetWord { field, .. }
                | IrOp::IgetWide { field, .. }
                | IrOp::IgetObject { field, .. }
                | IrOp::IputWord { field, .. }
                | IrOp::IputWide { field, .. }
                | IrOp::IputObject { field, .. }
                | IrOp::SgetWord { field, .. }
                | IrOp::SgetWide { field, .. }
                | IrOp::SgetObject { field, .. }
                | IrOp::SputWord { field, .. }
                | IrOp::SputWide { field, .. }
                | IrOp::SputObject { field, .. } => Some(field.index),
                _ => None,
            }
        };
        assert_eq!(
            field_of(&a),
            field_of(&b),
            "0x{inst_op:02x} and 0x{stat_op:02x} name different fields"
        );
    }
}
