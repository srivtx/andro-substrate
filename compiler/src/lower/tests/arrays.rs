//! The array-construction family: `filled-new-array` (both forms) and
//! `fill-array-data` — opcodes `0x24`–`0x26`.

use crate::lower::tests::prelude::*;

/// The sample argument list for the packed form, as a boxed slice.
fn box_args() -> Box<[Reg]> {
    Box::from([R(1), R(2), R(3)])
}
/// The sample argument list for the range form.
fn range_args() -> Box<[Reg]> {
    Box::from([R(4), R(5), R(6)])
}

lowering_cases! {
    at 10,
    {
        filled_new_array: 0x24 => IrOp::FilledNewArray {
            type_index: 0x1234, args: box_args(), ranged: false, declared: 3 },
            "reads as an array operation and is a **call**: it takes its elements out of the \
             register file, stores them, and the array reference arrives in the same implicit \
             result slot a call's does, which the following `move-result-object` normally \
             re-reads. There is deliberately no destination: the instruction's count field \
             holds the *argument* count, and reading it as a destination would write the \
             array over a live argument. The packed form's arguments are zero-padded to five \
             nibbles, and zero is a legal register, so the trimmed list is a hint and the \
             array's prototype is the truth";
        filled_new_array_range: 0x25 => IrOp::FilledNewArray {
            type_index: 0x1234, args: range_args(), ranged: true, declared: 3 },
            "the same operation over a contiguous register range, whose count **is** exact — \
             so the list needs no trimming and `ranged` records that it does not";
        fill_array_data: 0x26 => IrOp::FillArrayData { array: O(1), payload: RESOLVED },
            "copies a payload's bytes into an existing array. The label names data, and \
             `Function::new` checks that nothing but a switch or this instruction ever \
             names a payload — which is what stops a linear sweep's \"the widths still add \
             up\" from being mistaken for a correctness argument";
    }
}

/// The two argument forms must be told apart, because only one of them can be
/// trusted for its length.
///
/// This is the property that makes a call into a miscompile rather than an
/// error: reading three nibbles as three arguments when the fourth is a real
/// `v0` argument drops it silently.
#[test]
fn the_two_argument_forms_are_told_apart() {
    let IrOp::FilledNewArray { args, ranged, declared, .. } =
        crate::lower::tests::lower_sample(0x24).op
    else {
        panic!("filled-new-array is FilledNewArray")
    };
    assert!(!ranged, "the packed form is padded, not ranged");
    assert_eq!(declared, 3, "the count field is recorded even though it is not trusted");
    assert_eq!(args.len(), 3);
    assert_eq!(args.as_ref(), crate::lower::tests::packed_args().as_ref());

    let IrOp::FilledNewArray { args, ranged, .. } =
        crate::lower::tests::lower_sample(0x25).op
    else {
        panic!("filled-new-array/range is FilledNewArray")
    };
    assert!(ranged, "the range form carries an exact count");
    assert_eq!(args.as_ref(), crate::lower::tests::ranged_args().as_ref());
}

/// The trailing zero nibbles of a packed form are padding, and a lowering that
/// kept them would allocate a longer array than the target's type allows.
#[test]
fn the_packed_padding_is_trimmed() {
    // Five nibbles, three of them non-zero. The list must be three long, not five.
    let IrOp::FilledNewArray { args, .. } = crate::lower::tests::lower_sample(0x24).op else {
        panic!("filled-new-array is FilledNewArray")
    };
    assert_eq!(args.len(), 3, "two trailing zero nibbles are padding");
    assert!(!args.contains(&R(0)), "a zero register here would mean the padding was kept");
}

/// The array type index is the *array* type. A lowering that read the element
/// type would allocate a differently-shaped object.
#[test]
fn the_type_index_is_the_array_type() {
    for op in [0x24u8, 0x25] {
        let IrOp::FilledNewArray { type_index, .. } = crate::lower::tests::lower_sample(op).op
        else {
            panic!("0x{op:02x} is FilledNewArray")
        };
        assert_eq!(type_index, 0x1234);
    }
}
