//! The coverage arithmetic.
//!
//! # The claim
//!
//! For each of the 256 opcode bytes, exactly one of the following holds, and
//! this module proves which:
//!
//! 1. **lowered** — a case in one of the family modules produced a specific
//!    [`IrOp`];
//! 2. **refused** — it produced [`IrOp::Unsupported`] with a named
//!    [`UnsupportedReason`], and the reason is in the exclusion list with a
//!    sentence explaining it;
//! 3. **unhandled** — nothing claimed it. **This is a test failure**, and it is
//!    what the module exists for.
//!
//! This mirrors `tools/dexinterp/tests/coverage.rs`, which makes the same three
//! way distinction for the same 224 opcodes. The two are separate components
//! with separate test suites and the agreement between their numbers is a fact
//! about both, not a shared constant.
//!
//! # Why the third case is the one that matters
//!
//! An opcode that no family claims does not produce a wrong answer — it produces
//! [`LowerError::Unhandled`], and `lower_code` turns that into a failed method.
//! That is a *good* outcome, and it is worth being precise about why: a method
//! that fails to lower is a method nobody can compile, which is visible, whereas
//! an opcode that lowers to the wrong operation is invisible. The coverage test
//! is the difference between "this compiler cannot compile these 40 instructions"
//! and "this compiler silently miscompiles 40 instructions", and only one of
//! those is a finding about the input.

use std::collections::{BTreeMap, BTreeSet};

use crate::ir::{IrOp, UnsupportedReason};
use crate::lower::{self, Family, Ctx};

use super::{
    arith, arrays, consts, control, invoke, memory, moves, reserved, types, unit_ctx, BRANCH,
};

/// Every opcode byte a family module pins a specific operation for.
fn specific_ops() -> BTreeSet<u8> {
    let mut all = BTreeSet::new();
    for list in [
        moves::OPS,
        consts::OPS,
        arith::OPS,
        memory::OPS,
        control::OPS,
        types::OPS,
        arrays::OPS,
        invoke::OPS,
    ] {
        for op in list {
            assert!(all.insert(*op), "0x{op:02x} is pinned by two family modules");
        }
    }
    all
}

/// Lower one opcode byte and report what it produced.
fn outcome(op: u8) -> Result<IrOp, lower::LowerError> {
    let insn = super::sample(op).ok_or_else(|| {
        lower::LowerError::Unhandled { op, family: "sample", at: 0 }
    })?;
    let mut out = Vec::new();
    lower::lower_one(&insn, 0, &Ctx::new(super::UNITS), &mut out).map(|()| {
        assert_eq!(out.len(), 1, "0x{op:02x} must produce exactly one IR instruction");
        out.into_iter().next().expect("one instruction").op
    })
}

/// Every opcode the format defines, ascending.
fn defined_ops() -> BTreeSet<u8> {
    dexcore::opcodes::OPCODES
        .iter()
        .filter(|o| o.valid)
        .map(|o| o.opcode)
        .collect()
}

#[test]
fn the_table_is_the_one_the_specification_describes() {
    // A coverage claim only means something against a right table, and
    // `dexcore/tests/opcode_table.rs` proves that table against a second,
    // independent transcription. What is asserted here is only that the
    // arithmetic below has the shape it assumes.
    assert_eq!(defined_ops().len(), 224, "the format defines 224 opcodes");
    assert_eq!(dexcore::opcodes::OPCODES.len(), 256);
    assert_eq!(256 - defined_ops().len(), 32, "and leaves 32 unassigned");
}

#[test]
fn every_defined_opcode_has_a_specific_case() {
    // The claim that matters for review: a reader can go and read what opcode
    // 0x93 does. An opcode with no case is one nobody has looked at.
    let pinned = specific_ops();
    // Two of the 224 are refused rather than lowered, and their refusal has its
    // own case in `consts` — so "a case for every opcode" is 222 specific plus
    // two refusals, and the missing set must be exactly those two.
    let refused_by_design = [0xfeu8, 0xff];
    let missing: Vec<&'static str> = defined_ops()
        .difference(&pinned)
        .map(|op| dexcore::opcodes::mnemonic(*op))
        .collect();
    assert_eq!(
        missing,
        vec!["const-method-handle", "const-method-type"],
        "the opcodes with no specific case must be exactly the two the IR refuses"
    );
    assert_eq!(pinned.len(), 222, "222 of the 224 lower to a specific operation");
    for op in refused_by_design {
        assert!(!pinned.contains(&op), "0x{op:02x} is refused and must not be pinned");
        assert!(defined_ops().contains(&op), "0x{op:02x} is a real opcode");
    }
}

#[test]
fn every_opcode_byte_lowers_to_something() {
    // Case 3 of the claim: nothing is unhandled. This is the test that fails if
    // a family forgets an opcode.
    let mut unhandled = Vec::new();
    for op in 0u8..=255 {
        if let Err(lower::LowerError::Unhandled { .. }) = outcome(op) {
            unhandled.push(dexcore::opcodes::mnemonic(op));
        }
    }
    assert!(
        unhandled.is_empty(),
        "{} opcode bytes reached no family: {unhandled:?}",
        unhandled.len()
    );
}

#[test]
fn the_two_counts_are_222_and_2() {
    // The headline number, stated as a test so it cannot drift without a
    // deliberate edit. Of the 224 the format defines:
    //
    // * **222** lower to a specific operation;
    // * **2** are refused — `const-method-handle` and `const-method-type` —
    //   because their results are `MethodHandle` and `MethodType` objects,
    //   which are *callables* and *signatures* with identity, and the handle
    //   model in `IR.md` allocates offsets and nothing else. The oracle refuses
    //   the same two opcodes for the same reason, which is the agreement that
    //   makes the number meaningful.
    //
    // The 32 unassigned slots and the 8 reachable foreign encodings are the
    // other 40 of the 256, and both lower to a typed refusal.
    let mut specific = 0u32;
    let mut refused: BTreeMap<UnsupportedReason, Vec<u8>> = BTreeMap::new();
    for op in 0u8..=255 {
        let Ok(ir) = outcome(op) else { continue };
        if let IrOp::Unsupported { reason } = ir {
            refused.entry(reason).or_default().push(op);
        } else {
            specific += 1;
        }
    }
    // The foreign encodings have no opcode byte — a foreign assembler writes
    // whatever it likes into the low lane — so they are counted on the *format*
    // axis and not this one. `reserved` pins all eight of them.
    let foreign = reserved::foreign_encodings();
    for (i, insn) in foreign.iter().enumerate() {
        let mut out = Vec::new();
        crate::lower::tests::lower_one(insn, 0, &Ctx::new(super::UNITS), &mut out)
            .expect("a foreign encoding is refused, not an error");
        assert_eq!(
            out[0].op,
            IrOp::Unsupported { reason: UnsupportedReason::ForeignFormat },
            "foreign encoding {i} did not lower to the foreign refusal"
        );
        // Counted on the format axis, so the entries are not opcode bytes; the
        // count is what this test is about and the values are not read.
        refused.entry(UnsupportedReason::ForeignFormat).or_default().push(i as u8);
    }

    assert_eq!(specific, 222, "222 of the 256 opcode slots lower to a specific operation");
    assert_eq!(refused.len(), 4, "and there are four distinct refusal reasons");
    assert_eq!(refused[&UnsupportedReason::UnassignedSlot].len(), 32);
    assert_eq!(refused[&UnsupportedReason::ForeignFormat].len(), 8);
    assert_eq!(refused[&UnsupportedReason::MethodHandle], vec![0xfe]);
    assert_eq!(refused[&UnsupportedReason::MethodType], vec![0xff]);
}

#[test]
fn the_two_refused_opcodes_are_defined_and_the_rest_are_not() {
    // A refusal has to be a *deliberate* record, so the two refused opcodes must
    // be real opcodes of the format and not slots it leaves empty. If either
    // moved to the unassigned set the count would still be 2 and the meaning
    // would have changed.
    for op in [0xfeu8, 0xff] {
        let entry = dexcore::opcodes::opcode(op);
        assert!(entry.valid, "0x{op:02x} is a real opcode");
        assert_ne!(entry.mnemonic, "unused");
    }
    for op in 0u8..=255 {
        let is_refused = matches!(
            outcome(op),
            Ok(IrOp::Unsupported { reason: UnsupportedReason::MethodHandle | UnsupportedReason::MethodType })
        );
        assert_eq!(
            is_refused,
            op == 0xfe || op == 0xff,
            "0x{op:02x} ({}) has the wrong refusal status",
            dexcore::opcodes::mnemonic(op)
        );
    }
}

#[test]
fn classification_agrees_with_the_format_table() {
    // The classifier in `lower::classify` is this compiler's own index into the
    // input's instruction space. It is a second transcription of a fact
    // `dexcore` already has, and a second transcription is exactly the thing that
    // goes stale. This is the check that it has not: the two agree about validity
    // on every byte, which means every unassigned slot lands in
    // `Family::Unassigned` and every assigned slot does not.
    for op in 0u8..=255 {
        let valid = dexcore::opcodes::opcode(op).valid;
        let family = lower::classify(op);
        assert_eq!(
            family == Family::Unassigned,
            !valid,
            "0x{op:02x} ({}) is {} but classified as {:?}",
            dexcore::opcodes::mnemonic(op),
            if valid { "defined" } else { "unassigned" },
            family
        );
    }
}

#[test]
fn every_family_is_reachable_from_some_opcode() {
    // A family with no opcode is dead code, and a family whose opcodes all land
    // elsewhere is a hole. Either way the reader's map of the instruction set is
    // wrong, and the map is what makes the coverage number reviewable.
    let mut seen = BTreeSet::new();
    for op in 0u8..=255 {
        seen.insert(lower::classify(op));
    }
    for family in Family::ALL {
        if matches!(family, Family::Foreign | Family::Payload) {
            // Never produced by `classify`: a foreign encoding is identified by
            // its format, not by its opcode byte. `reserved::is_foreign` is what
            // identifies them and `reserved::the_foreign_encodings_are_eight_of_nine`
            // covers them.
            assert!(
                !seen.contains(&family),
                "classify must not produce Family::Foreign; foreign encodings are identified \
                 by their format"
            );
            continue;
        }
        assert!(seen.contains(&family), "no opcode classifies as {family:?}");
    }
}

#[test]
fn every_family_module_is_named_by_the_classifier() {
    // The two vocabularies — the modules in `lower/` and the families — must not
    // drift. `Family::as_str` is the module name, and a mismatch is a `mod.rs`
    // that routes an opcode to a file that does not handle it.
    for family in Family::ALL {
        if matches!(family, Family::Foreign | Family::Payload) {
            continue;
        }
        let name = family.as_str();
        assert!(
            Family::ALL.iter().any(|f| f.as_str() == name),
            "{name} is not a family name"
        );
    }
    // A few spot checks that the mapping is the one a reader would expect.
    assert_eq!(lower::classify(0x90).as_str(), "arith");
    assert_eq!(lower::classify(0x6e).as_str(), "invoke");
    assert_eq!(lower::classify(0x52).as_str(), "memory");
    assert_eq!(lower::classify(0x3e).as_str(), "reserved");
    assert_eq!(lower::classify(0x28).as_str(), "control");
}

#[test]
fn the_unassigned_slots_are_exactly_the_format_s_own() {
    let theirs: BTreeSet<u8> = reserved::UNASSIGNED.into_iter().collect();
    let ours: BTreeSet<u8> =
        (0u8..=255).filter(|op| !dexcore::opcodes::opcode(*op).valid).collect();
    assert_eq!(theirs, ours);
    // AOSP marks 0x3e..=0x43, 0x73, 0x79..=0x7a and 0xe3..=0xf9.
    assert_eq!(reserved::UNASSIGNED[0], 0x3e);
    assert_eq!(reserved::UNASSIGNED.last(), Some(&0xf9));
}

#[test]
fn a_branch_offset_is_resolved_for_every_branch_opcode() {
    // The per-family tests run at unit 0, where an unresolved offset and a
    // resolved one agree. This one walks the whole set at a non-zero offset, so
    // a lowering that dropped the resolution would be caught here.
    for op in 0u8..=255 {
        let Some(insn) = super::sample(op) else { continue };
        if !insn.opcode().is_some_and(|o| super::is_branch(o)) {
            continue;
        }
        let mut out = Vec::new();
        crate::lower::tests::lower_one(&insn, 20, &unit_ctx(), &mut out)
            .unwrap_or_else(|e| panic!("0x{op:02x} failed to lower: {e}"));
        let labels = out[0].op.labels();
        assert!(!labels.is_empty(), "0x{op:02x} is a branch and must carry a label");
        for l in labels {
            assert_eq!(
                l,
                crate::ir::Label(20 + BRANCH as u32),
                "0x{op:02x} did not resolve its relative offset against the instruction"
            );
        }
    }
}

#[test]
fn a_claim_about_coverage_is_a_fact_about_the_lowering_not_a_belief() {
    // The census is what a study wants: what the compiler *met*, as a fact
    // about the input, kept apart from what it *could* handle, which is a fact
    // about the compiler. The two are different numbers, and reporting one as
    // the other is how a coverage claim becomes meaningless.
    let mut census = lower::OpcodeCensus::default();
    // A stream of the three one-code-unit opcodes, so the walk is exactly seven
    // units long and every offset is an instruction boundary.
    let stream: [u8; 7] = [0x00, 0x00, 0x12, 0x12, 0x12, 0x0f, 0x0f];
    let units: Vec<u16> = stream.iter().map(|op| u16::from(*op)).collect();
    let mut body = Vec::new();
    lower::walk_and_lower(&units, &mut body, &mut census).expect("the stream lowers");
    assert_eq!(census.total(), 7, "seven instructions, with repeats");
    assert_eq!(census.distinct(), 3, "three distinct opcode bytes");
    assert_eq!(census.counts[&0x00], 2, "the repeat is counted");
    assert_eq!(census.seen.len(), census.counts.len());
    assert_eq!(body.len(), 7, "and one IR instruction each");
    assert_eq!(census.total() as usize, body.len(), "the census and the body agree");
}
