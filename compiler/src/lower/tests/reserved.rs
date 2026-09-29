//! The instruction space the format does not fill: the 32 unassigned slots and
//! the eight foreign encodings a decoder can produce.
//!
//! # The claim under test
//!
//! Every one of them becomes a *typed* [`IrOp::Unsupported`], positioned in the
//! body at the offset of the instruction it replaces, with a reason that names
//! itself. None of them becomes nothing, and none of them becomes a real
//! operation — which is the second half of the claim and the more important one,
//! because an unassigned slot that lowered to a plausible `i32.add` would be
//! worse than a refusal by a wide margin.

use crate::lower::tests::prelude::*;
use crate::lower::tests::{assert_lowers, assert_refused, unit_ctx};

/// The 32 opcode slots the format leaves unassigned, in ascending order.
pub const UNASSIGNED: [u8; 32] = [
    0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x73, 0x79, 0x7a, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
    0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
];

/// The eight foreign encodings, paired with a sample of each so the test covers
/// the shape as well as the byte.
pub fn foreign_encodings() -> Vec<dexcore::insn::Instruction> {
    foreign_samples().into_iter().map(|(_, i)| i).collect()
}

/// The eight foreign encodings and a sample of each.
fn foreign_samples() -> Vec<(u8, dexcore::insn::Instruction)> {
    let pairs: [(u8, dexcore::insn::Instruction); 8] = [
        (
            0x00,
            dexcore::insn::Instruction::F20BC { op: 0x00, a: 1, index: 0x1234 },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F22CS { op: 0x00, a: 1, b: 2, index: 0x1234 },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F35MS {
                op: 0x00,
                a: 3,
                g: 0,
                index: 0x1234,
                first_reg: 4,
                reg_count: 3,
            },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F35MI {
                op: 0x00,
                a: 3,
                g: 0,
                index: 0x1234,
                regs: [1, 2, 3, 0, 0],
            },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F3RMS {
                op: 0x00,
                a: 3,
                index: 0x1234,
                first_reg: 4,
                reg_count: 3,
            },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F3RMI {
                op: 0x00,
                a: 3,
                index: 0x1234,
                first_reg: 4,
                reg_count: 3,
            },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F52C { op: 0x00, a: 1, b: 2, index: 0x1234_5678 },
        ),
        (
            0x00,
            dexcore::insn::Instruction::F5RC { op: 0x00, index: 0x1234_5678, first_reg: 4, reg_count: 3 },
        ),
    ];
    pairs.to_vec()
}

#[test]
fn every_unassigned_slot_becomes_a_named_refusal() {
    for op in UNASSIGNED {
        assert_refused(
            op,
            UnsupportedReason::UnassignedSlot,
            "a slot the format does not assign; reaching one means the file is not the \
             format it claims to be",
        );
    }
}

#[test]
fn an_unassigned_slot_is_not_a_crash_and_not_a_wrong_answer() {
    for op in UNASSIGNED {
        let inst = crate::lower::tests::lower_sample(op);
        assert_eq!(inst.op, IrOp::Unsupported { reason: UnsupportedReason::UnassignedSlot });
        assert!(inst.op.is_terminator(), "control must not fall through a refused instruction");
        assert!(inst.op.reads().is_empty());
        assert!(inst.op.writes().is_empty(), "a refusal must not appear to write anything");
        assert!(inst.op.labels().is_empty());
    }
}

#[test]
fn every_foreign_encoding_becomes_a_named_refusal() {
    for (op, insn) in foreign_samples() {
        let mut out = Vec::new();
        crate::lower::tests::lower_one(&insn, 3, &unit_ctx(), &mut out).unwrap_or_else(|e| {
            panic!("foreign encoding 0x{op:02x} must be refused, not fail to lower: {e}")
        });
        assert_eq!(out.len(), 1, "a refused encoding is still one IR item");
        assert_eq!(
            out[0].op,
            IrOp::Unsupported { reason: UnsupportedReason::ForeignFormat },
            "foreign encoding 0x{op:02x} ({}) lowered to the wrong thing",
            dexcore::insn::Instruction::mnemonic(&insn)
        );
        assert_eq!(out[0].origin, crate::ir::Origin::at(3));
    }
}

#[test]
fn the_two_refusals_are_kept_apart() {
    // Both are findings about the *file*, and they are different findings.
    // Merging them would make the refusal count unreadable: "40 foreign files"
    // says something quite different from "40 corrupt files".
    assert_ne!(
        UnsupportedReason::UnassignedSlot,
        UnsupportedReason::ForeignFormat
    );
    assert_ne!(UnsupportedReason::UnassignedSlot.as_str(), UnsupportedReason::ForeignFormat.as_str());
    assert!(UnsupportedReason::UnassignedSlot.explain().contains("unassigned"));
    assert!(UnsupportedReason::ForeignFormat.explain().contains("not part of"));
}

#[test]
fn there_are_exactly_thirty_two_unassigned_slots() {
    // The number is checked against `dexcore`'s own table, so the two cannot
    // drift apart: a change to the format's table is a change to this list or a
    // test failure.
    let theirs: Vec<u8> = dexcore::opcodes::OPCODES
        .iter()
        .filter(|o| !o.valid)
        .map(|o| o.opcode)
        .collect();
    assert_eq!(theirs.len(), 32, "the format leaves 32 slots unassigned");
    assert_eq!(theirs, UNASSIGNED.to_vec());
    // ...and every one of them declares a width, so a linear walk over corrupt
    // data still advances. A slot with no width would hang the lowering, and the
    // lowering is what runs on hostile input.
    for op in UNASSIGNED {
        assert_eq!(dexcore::opcodes::width_of(op), 2, "0x{op:02x} must still advance the walk");
    }
}

#[test]
fn there_are_nine_foreign_formats_of_which_eight_are_reachable() {
    // `40sc` and `41c` have a `Format` variant in `dexcore` and no
    // `Instruction` variant, so `decode_one` has no arm for them and a file
    // containing one cannot be decoded past it. Saying so out loud keeps "nine
    // foreign formats" and "eight refusals" from drifting apart silently.
    assert_eq!(crate::lower::reserved::FOREIGN_FORMATS.len(), 9);
    assert_eq!(crate::lower::reserved::FOREIGN_VARIANTS.len(), 8);
    assert_eq!(crate::lower::reserved::UNREACHABLE_FORMATS, ["40sc", "41c"]);
    assert_eq!(foreign_samples().len(), 8);
    // Every reachable one is one `dexcore` can actually produce.
    for (op, insn) in foreign_samples() {
        assert!(crate::lower::reserved::is_foreign(&insn), "0x{op:02x} should be foreign");
        assert_eq!(
            dexcore::insn::Instruction::mnemonic(&insn),
            "foreign",
            "a foreign encoding must not borrow a real opcode's name"
        );
    }
}

#[test]
fn a_refused_instruction_still_carries_its_position() {
    // The whole point of refusing rather than dropping: a dropped instruction is
    // indistinguishable from one nobody thought about, and a refusal with an
    // origin is a line in a report that names a place in a method.
    for op in [0x3eu8, 0x73, 0xf9] {
        let mut out = Vec::new();
        crate::lower::tests::lower_one(
            &crate::lower::tests::sample(op).expect("unassigned slots decode"),
            17,
            &unit_ctx(),
            &mut out,
        )
        .expect("an unassigned slot is refused, not an error");
        assert_eq!(out[0].origin, crate::ir::Origin::at(17));
    }
}

#[test]
fn an_unassigned_slot_lowers_even_when_it_is_reached_by_falling_through() {
    // A refusal is a *result*, not a failure. The caller gets a body it can count
    // rather than an error it has to unwind, because "this method has three
    // instructions `codegen` cannot compile" is a finding and "lowering threw" is
    // not.
    let insn = dexcore::insn::Instruction::Unused { op: 0x73 };
    let mut out = Vec::new();
    crate::lower::tests::lower_one(&insn, 0, &unit_ctx(), &mut out)
        .expect("an unassigned slot is a refusal, not an error");
    assert_eq!(out.len(), 1);
    assert!(matches!(out[0].op, IrOp::Unsupported { .. }));
}

/// The eight foreign encodings and the 32 unassigned slots are the whole of the
/// reserved space, and this test fails if either list grows without a reviewable
/// reason.
#[test]
fn the_reserved_space_is_exactly_these_forty() {
    assert_eq!(UNASSIGNED.len() + foreign_samples().len(), 40);
    // Nothing in the space is a *real* operation.
    for op in UNASSIGNED {
        let IrOp::Unsupported { .. } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is unassigned and must not lower to an operation")
        };
    }
    // ...and the two object-producing opcodes that *are* defined bring the
    // opcode-byte total to 34, with the eight foreign encodings on the format
    // axis rather than the opcode-byte one. 42 in all.
    let mut refused = 0u32;
    for op in 0u8..=255 {
        let Some(insn) = crate::lower::tests::sample(op) else { continue };
        let mut out = Vec::new();
        crate::lower::tests::lower_one(&insn, 0, &unit_ctx(), &mut out).expect("every opcode lowers");
        if matches!(out[0].op, IrOp::Unsupported { .. }) {
            refused += 1;
        }
    }
    assert_eq!(refused, 34, "32 unassigned slots + the two method-object opcodes");
    assert_eq!(
        refused as usize + foreign_encodings().len(),
        42,
        "and 42 in all once the foreign encodings are counted on the format axis"
    );
    assert_lowers(0x00, IrOp::Nop, "sanity: the first slot is a real operation");
}
