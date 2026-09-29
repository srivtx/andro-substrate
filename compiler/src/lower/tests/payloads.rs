//! The three data payloads.
//!
//! # A payload is not an instruction
//!
//! The format calls them pseudo-instructions and a linear sweep decodes them as
//! if they were. They are not: they are data that happens to be addressed like
//! an instruction, and there are exactly two ways to reach one — a branch from
//! the switch that reads it, and falling into it from above. The first is legal;
//! the second is a malformed file, and the oracle reports it as
//! `Malformed::BadPayload`.
//!
//! The IR keeps the distinction by giving a payload its own [`IrOp::Payload`]
//! rather than letting it share the instruction space, and by requiring
//! `Function::new` to see that nothing but a [`IrOp::Switch`] or an
//! [`IrOp::FillArrayData`] names one. [`a_payload_is_data_not_an_instruction`]
//! checks the IR's half of that; the other half is the function builder's.

use crate::lower::tests::prelude::*;

/// A packed-switch payload with `n` targets.
fn packed(n: usize) -> dexcore::insn::Payload {
    dexcore::insn::Payload::PackedSwitch(dexcore::insn::PackedSwitch {
        ident: 0x0100,
        first_key: 7,
        targets: vec![3; n],
    })
}

/// A sparse-switch payload with `n` keys.
fn sparse(n: usize) -> dexcore::insn::Payload {
    dexcore::insn::Payload::SparseSwitch(dexcore::insn::SparseSwitch {
        ident: 0x0200,
        keys: (0..n).map(|k| k as i32).collect(),
        targets: vec![3; n],
    })
}

/// A fill-array-data payload.
fn fill(width: u16, count: u32) -> dexcore::insn::Payload {
    dexcore::insn::Payload::FillArrayData(dexcore::insn::FillArrayData {
        ident: 0x0300,
        element_width: width,
        size: count,
        data: vec![0xab; width as usize * count as usize],
    })
}

/// A payload is identified by the full 16-bit ident unit rather than by an
/// opcode byte, so these three are not in the `lowering_cases!` table — there is
/// no `u8` to key them on. The tests below are the same kind of assertion, one
/// per payload, written out.
#[test]
fn the_packed_switch_payload_lowers_to_a_packed_switch() {
    let op = lower_payload(packed(3));
    let IrOp::Payload { payload } = &op else { panic!("not a payload") };
    let Payload::PackedSwitch { first_key, targets } = &**payload else {
        panic!("a packed switch stays a packed switch")
    };
    assert_eq!(*first_key, 7, "the first key is the value of the first target");
    assert_eq!(targets.as_ref(), &[3, 3, 3]);
    assert_eq!(payload.units(), 4 + 2 * 3, "ident, size, first_key and one unit per target word");
}

#[test]
fn the_sparse_switch_payload_lowers_to_a_sparse_switch() {
    let op = lower_payload(sparse(4));
    let IrOp::Payload { payload } = &op else { panic!("not a payload") };
    let Payload::SparseSwitch { keys, targets } = &**payload else {
        panic!("a sparse switch stays a sparse switch")
    };
    assert_eq!(keys.as_ref(), &[0, 1, 2, 3], "the keys stay in ascending order");
    assert_eq!(targets.len(), keys.len(), "one target per key");
    assert_eq!(payload.units(), 2 + 4 * 4, "ident, size, then two units per key/target pair");
}

#[test]
fn the_fill_array_data_payload_lowers_to_its_bytes() {
    let op = lower_payload(fill(2, 5));
    let IrOp::Payload { payload } = &op else { panic!("not a payload") };
    let Payload::FillArrayData { element_width, element_count, data } = &**payload else {
        panic!("fill-array-data stays fill-array-data")
    };
    assert_eq!(*element_width, 2, "`element_width` is the array's *component* width");
    assert_eq!(*element_count, 5);
    assert_eq!(data.len(), 10, "`element_width * element_count` is the byte count");
    assert!(data.iter().all(|b| *b == 0xab), "the bytes are carried through verbatim");
    assert_eq!(payload.units(), 4 + 5, "ident, width, count, then the data padded to units");
}

#[test]
fn the_three_payloads_are_told_apart() {
    // The idents are the only thing distinguishing them, and a decoder that
    // collapsed them would read a switch table as an array initialiser — which
    // runs, and produces numbers.
    for (ident, p) in
        [(0x0100u16, packed(2)), (0x0200, sparse(2)), (0x0300, fill(1, 2))]
    {
        assert_eq!(dexcore::opcodes::PayloadKind::from_unit(ident).is_some(), true);
        let IrOp::Payload { .. } = lower_payload(p) else { panic!("0x{ident:04x} is a payload") };
    }
}

/// Lower a payload and return its single instruction's operation.
fn lower_payload(p: dexcore::insn::Payload) -> IrOp {
    let mut out = Vec::new();
    crate::lower::tests::lower_one(
        &dexcore::insn::Instruction::Payload(p),
        10,
        &crate::lower::tests::unit_ctx(),
        &mut out,
    )
    .expect("a payload lowers");
    assert_eq!(out.len(), 1, "a payload is one IR item");
    assert_eq!(out[0].origin, crate::ir::Origin::at(10), "and it keeps its position");
    out.into_iter().next().expect("one item").op
}

/// Every payload's code-unit width, computed two ways, must agree.
///
/// This is worth its own test because `dexcore` computes it twice and the two
/// disagree: `PayloadKind::width_units` says a packed switch is `4 + size` units
/// and a sparse one is `2 + 2*size`, but each array element is a 32-bit word, so
/// the real widths are `4 + 2*targets` and `2 + 4*keys`. Both are a factor of two
/// short on the array half, and the error is invisible to a linear sweep — the
/// remainder decodes as more instructions and the widths still sum to
/// `insns_size`. A real eight-target packed switch in a real F-Droid app is where
/// this was found. The lowering uses the width the *encoder* wrote, which is
/// `dexcore::insn::Payload::width`.
#[test]
fn a_payloads_width_counts_32_bit_words() {
    for n in [0usize, 1, 2, 4, 8, 17] {
        let p = packed(n);
        let expected = 4 + 2 * n as u32;
        assert_eq!(
            p.width() as u32 / 2,
            expected,
            "a packed switch with {n} targets is {expected} code units, not {}",
            dexcore::opcodes::PayloadKind::PackedSwitch.width_units(n as u32)
        );

        let p = sparse(n);
        let expected = 2 + 4 * n as u32;
        assert_eq!(
            p.width() as u32 / 2,
            expected,
            "a sparse switch with {n} keys is {expected} code units, not {}",
            dexcore::opcodes::PayloadKind::SparseSwitch.width_units(n as u32)
        );
    }
}

/// A payload produces exactly one instruction, and it is not executable.
#[test]
fn a_payload_is_data_not_an_instruction() {
    for p in [packed(3), sparse(4), fill(2, 5)] {
        let op = lower_payload(p);
        assert!(matches!(op, IrOp::Payload { .. }));
        assert!(!op.is_terminator());
        assert!(!op.ends_block(), "data cannot be a block boundary");
        assert!(op.reads().is_empty());
        assert!(op.writes().is_empty());
        assert!(op.labels().is_empty(), "a payload is named, never naming");
    }
}

/// The three payloads keep their three different shapes.
#[test]
fn the_three_payloads_keep_their_shapes() {
    let mut out = Vec::new();
    crate::lower::tests::lower_one(
        &dexcore::insn::Instruction::Payload(packed(3)),
        0,
        &crate::lower::tests::unit_ctx(),
        &mut out,
    )
    .expect("lowered");
    let IrOp::Payload { payload } = &out[0].op else { panic!("not a payload") };
    let Payload::PackedSwitch { first_key, targets } = &**payload else {
        panic!("a packed switch stays a packed switch")
    };
    assert_eq!(*first_key, 7);
    assert_eq!(targets.as_ref(), &[3, 3, 3]);
    assert_eq!(payload.units(), 4 + 2 * 3);

    let mut out = Vec::new();
    crate::lower::tests::lower_one(
        &dexcore::insn::Instruction::Payload(sparse(4)),
        0,
        &crate::lower::tests::unit_ctx(),
        &mut out,
    )
    .expect("lowered");
    let IrOp::Payload { payload } = &out[0].op else { panic!("not a payload") };
    let Payload::SparseSwitch { keys, targets } = &**payload else {
        panic!("a sparse switch stays a sparse switch")
    };
    assert_eq!(keys.as_ref(), &[0, 1, 2, 3]);
    assert_eq!(targets.len(), 4);
    assert_eq!(payload.units(), 2 + 4 * 4);

    let mut out = Vec::new();
    crate::lower::tests::lower_one(
        &dexcore::insn::Instruction::Payload(fill(4, 3)),
        0,
        &crate::lower::tests::unit_ctx(),
        &mut out,
    )
    .expect("lowered");
    let IrOp::Payload { payload } = &out[0].op else { panic!("not a payload") };
    let Payload::FillArrayData { element_width, element_count, data } = &**payload else {
        panic!("fill-array-data stays fill-array-data")
    };
    assert_eq!(*element_width, 4);
    assert_eq!(*element_count, 3);
    assert_eq!(data.len(), 12, "`element_width * element_count` is the byte count");
    assert_eq!(payload.units(), 4 + 6);
}

/// An odd number of payload bytes still occupies a whole code unit, or the walk
/// after it would start half an instruction in.
#[test]
fn an_odd_payload_is_padded_to_a_whole_code_unit() {
    for count in [1u32, 3, 5, 7] {
        let p = fill(1, count);
        let units = p.width() as u32 / 2;
        assert_eq!(units * 2, u32::from(p.width()), "a payload width is always even");
        assert_eq!(units, 4 + count.div_ceil(2));
    }
}

/// The switch targets stay relative to the switching instruction, which is the
/// one addressing mode in the format that is not a code-unit offset from the
/// start of the stream.
///
/// A lowering that pre-computed them would have to know where the switch ends
/// up, which is `codegen`'s decision and not this one's — so the IR keeps the
/// input's arithmetic and says so on the field.
#[test]
fn switch_targets_stay_relative_to_the_switch() {
    let op = lower_payload(packed(2));
    let IrOp::Payload { payload } = &op else { panic!("not a payload") };
    let Payload::PackedSwitch { targets, .. } = &**payload else { panic!("not packed") };
    assert_eq!(
        targets.as_ref(),
        &[3, 3],
        "the targets are carried through unchanged, in the input's own addressing"
    );
}
