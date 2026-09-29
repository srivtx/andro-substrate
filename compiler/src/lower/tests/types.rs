//! The type-test and allocation family: opcodes `0x1f`–`0x23`.

use crate::lower::tests::prelude::*;

lowering_cases! {
    at 0,
    {
        check_cast: 0x1f => IrOp::CheckCast { object: O(1), index: 0x1234 },
            "a cast tests the value **already in** the register and throws on failure; it \
             produces nothing, so the IR has no destination for it. Giving it one would mean \
             inventing a register, and the natural choice — the register it already holds — \
             is a self-assignment `codegen` would have to special-case away";
        instance_of: 0x20 => IrOp::InstanceOf { dst: I(1), object: O(2), index: 0x1234 },
            "yields 1 or 0, so the destination is a 32-bit integer and never a reference. \
             The zero result is indistinguishable from the integer 0, which is what the \
             input specifies and what the oracle implements";
        array_length: 0x21 => IrOp::ArrayLength { dst: I(1), array: O(2) },
            "the length is an `int` and the operand is an array, which is a reference — the \
             two are different types and the IR will not let them be confused";
        new_instance: 0x22 => IrOp::NewInstance { dst: O(1), index: 0x1234 },
            "allocates an object with **uninitialised** fields, and the IR says so: there is \
             no implicit zeroing here, because a `float` field's zero is 0.0 and not 0 and \
             zeroing a 64-bit field with a 32-bit store is a bug that reads back as a \
             plausible wrong number";
        new_array: 0x23 => IrOp::NewArray { dst: O(1), type_index: 0x1234, size: I(2) },
            "the index names the **array** type, not the element type: `[I` and not `I`. A \
             lowering that read the element type would allocate a differently-typed object \
             and every element store would then be a type error";
    }
}

/// A cast has no destination, and a class test does. The distinction is the
/// whole reason [`IrOp::CheckCast`] and [`IrOp::InstanceOf`] are two variants
/// rather than one with an optional destination.
#[test]
fn a_cast_is_in_place_and_a_class_test_is_not() {
    let IrOp::CheckCast { object, .. } = crate::lower::tests::lower_sample(0x1f).op else {
        panic!("check-cast is CheckCast")
    };
    assert_eq!(object.index(), 1);
    assert!(
        crate::lower::tests::lower_sample(0x1f).op.writes().is_empty(),
        "check-cast must not write a register: a spurious write would clobber the value the \
         rest of the method is about to use"
    );

    let inst = crate::lower::tests::lower_sample(0x20);
    assert_eq!(inst.op.writes(), vec![R(1)], "instance-of writes exactly one destination");
    assert_eq!(inst.op.reads(), vec![R(2)], "instance-of reads exactly the object");
}

/// The three type-reading opcodes all name a `type_ids` index, and all three
/// must carry it through unconverted.
#[test]
fn a_type_index_is_carried_through() {
    for op in [0x1fu8, 0x20, 0x22, 0x23] {
        let index = match crate::lower::tests::lower_sample(op).op {
            IrOp::CheckCast { index, .. }
            | IrOp::InstanceOf { index, .. }
            | IrOp::NewInstance { index, .. }
            | IrOp::NewArray { type_index: index, .. } => index,
            other => panic!("0x{op:02x} lowered to {other:?}"),
        };
        assert_eq!(index, 0x1234, "0x{op:02x} lost or mangled the type index");
    }
}
