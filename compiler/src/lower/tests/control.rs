//! The control family: returns, jumps, branches, the two switches, `throw` and
//! the monitors — opcodes `0x0e`–`0x11`, `0x1d`–`0x1e`, `0x27`–`0x2c` and
//! `0x32`–`0x3d`.
//!
//! # Relative offsets become absolute labels here, and nowhere else
//!
//! Every offset in the input is measured in code units **from the branching
//! instruction**. The IR's [`Label`] is an absolute code-unit offset, so this
//! family is the only place the two meet, and it does the arithmetic once with a
//! checked `i64` addition. The per-opcode tests run at code unit 0, where a
//! correct resolution and an unresolved one happen to agree; [`branch_offsets_are
//! _resolved`] runs them at unit 10, where they do not, which is what makes the
//! "resolved" claim testable rather than assumed.

use crate::lower::tests::prelude::*;
use crate::lower::tests::{assert_lowers_at, unit_ctx, RESOLVED, UNITS};

lowering_cases! {
    at 10,
    {
        // ---- returns.
        return_void: 0x0e => IrOp::ReturnVoid,
            "no operand and no result; the only instruction of the family that ends a \
             block without reading a register";
        return_i32: 0x0f => IrOp::ReturnI32 { src: I(1) },
            "the returned value is 32 bits, so the source is an `I32Reg` and cannot be a \
             `long` register";
        return_wide: 0x10 => IrOp::ReturnWide { src: R(1), class: WideClass::Unresolved },
            "one opcode for both 64-bit return types; the method's own signature says which, \
             and the signature is not in the instruction";
        return_object: 0x11 => IrOp::ReturnObject { src: O(1) },
            "a reference return, and the source is an `ObjectReg`";

        // ---- monitors and throw.
        monitor_enter: 0x1d => IrOp::MonitorEnter { object: O(1) },
            "the operand is a reference; the lock itself is a runtime structure, so the IR \
             carries no lock state and the depth count is `codegen`'s to keep";
        monitor_exit: 0x1e => IrOp::MonitorExit { object: O(1) },
            "an unbalanced exit is a file defect the oracle reports as \
             `Malformed::UnbalancedMonitor`; the IR does not check balance, because a \
             monitor's state is not static";
        throw: 0x27 => IrOp::Throw { exception: O(1) },
            "throws the reference in the register, and ends the block";

        // ---- jumps, at three widths.
        goto: 0x28 => IrOp::Jump { target: RESOLVED },
            "an 8-bit relative offset in code units, resolved to an absolute label";
        goto_16: 0x29 => IrOp::Jump { target: RESOLVED },
            "the same operation at 16 bits of offset; the width is an encoding detail and \
             the IR has one `Jump`";
        goto_32: 0x2a => IrOp::Jump { target: RESOLVED },
            "and at 32 bits, which is the widest a branch can be and the reason a `goto/32` \
             exists at all";

        // ---- the two table-driven dispatches.
        packed_switch: 0x2b => IrOp::Switch { kind: SwitchKind::Packed, reg: I(1), payload: RESOLVED },
            "dispatches on a contiguous run of values by `value - first_key`; the label names \
             the *payload*, which is data, and `Function::new` checks that nothing else \
             names it";
        sparse_switch: 0x2c => IrOp::Switch { kind: SwitchKind::Sparse, reg: I(1), payload: RESOLVED },
            "dispatches on an arbitrary set of values by key search; the two differ only in \
             how `codegen` will search, so the kind is a named field rather than a variant";

        // ---- two-register comparisons. The first two are over 32-bit *words*
        // and may be comparing references.
        if_eq: 0x32 => IrOp::BrEq { a: Word::Unresolved(R(1)), b: Word::Unresolved(R(2)), target: RESOLVED },
            "specified over a 32-bit word, and a reference is one word: d8 emits this for both \
             integer equality and object identity. The IR cannot tell which without a \
             verifier, so it says `Unresolved` rather than guessing, and both lower to the \
             same `i32.eq` anyway";
        if_ne: 0x33 => IrOp::BrNe { a: Word::Unresolved(R(1)), b: Word::Unresolved(R(2)), target: RESOLVED },
            "as `if-eq`, negated";
        if_lt: 0x34 => IrOp::BrLt { a: I(1), b: I(2), target: RESOLVED },
            "the ordering forms are integer-only in the input and stay integer-only here: \
             a reference has no order, and one that compared by heap offset would be a \
             silent miscompile of any sorted collection";
        if_ge: 0x35 => IrOp::BrGe { a: I(1), b: I(2), target: RESOLVED },
            "as `if-lt`, negated";
        if_gt: 0x36 => IrOp::BrGt { a: I(1), b: I(2), target: RESOLVED },
            "as `if-lt`, other way round";
        if_le: 0x37 => IrOp::BrLe { a: I(1), b: I(2), target: RESOLVED },
            "as `if-lt`, negated";

        // ---- one-register comparisons.
        if_eqz: 0x38 => IrOp::BrEqZ { a: Word::Unresolved(R(1)), target: RESOLVED },
            "`x == null` is written exactly this way, so this opcode is a reference test as \
             often as it is an integer one";
        if_nez: 0x39 => IrOp::BrNeZ { a: Word::Unresolved(R(1)), target: RESOLVED },
            "`x != null`, and the null check that every real APK is full of";
        if_ltz: 0x3a => IrOp::BrLtZ { a: I(1), target: RESOLVED },
            "signed, so `-1` is less than zero and `i32.lt_s` with 0 is the operation — \
             not `i32.lt_u`, which says `-1` is greater";
        if_gez: 0x3b => IrOp::BrGeZ { a: I(1), target: RESOLVED },
            "as `if-ltz`, negated";
        if_gtz: 0x3c => IrOp::BrGtZ { a: I(1), target: RESOLVED },
            "as `if-ltz`, other way round";
        if_lez: 0x3d => IrOp::BrLeZ { a: I(1), target: RESOLVED },
            "as `if-ltz`, negated";
    }
}

/// The resolved-offset claim, tested where an unresolved one would differ.
///
/// Every branch sample carries a *relative* offset of 1. Placed at code unit 0
/// the correct answer and the wrong one are both 1, so the per-opcode tests
/// cannot tell them apart. Placed at unit 10 the correct answer is 11 and an
/// unresolved offset would be 1, which is a different label and therefore a
/// different block.
#[test]
fn branch_offsets_are_resolved_against_the_instruction() {
    let targets = [
        (0x28u8, IrOp::Jump { target: RESOLVED }),
        (0x32, IrOp::BrEq { a: Word::Unresolved(R(1)), b: Word::Unresolved(R(2)), target: RESOLVED }),
        (0x38, IrOp::BrEqZ { a: Word::Unresolved(R(1)), target: RESOLVED }),
        (0x3a, IrOp::BrLtZ { a: I(1), target: RESOLVED }),
        (0x2b, IrOp::Switch { kind: SwitchKind::Packed, reg: I(1), payload: RESOLVED }),
    ];
    for (op, expected) in targets {
        assert_lowers_at(op, 10, expected, "a relative offset is resolved against the branch");
        assert_ne!(RESOLVED, Label(1), "the sample offset must not equal the resolved label");
    }
}

/// A branch offset that leaves the code item is refused, not wrapped.
///
/// A wrapped branch lands in the middle of a method and produces a plausible
/// wrong answer, which is the specific failure this compiler exists to make
/// impossible.
#[test]
fn an_out_of_range_branch_is_refused() {
    for op in [0x28u8, 0x29, 0x2a, 0x32, 0x38, 0x2b, 0x26] {
        let err = crate::lower::tests::lower_sample_err(op, UNITS - 1);
        let LowerError::BadTarget { at, units, .. } = err else {
            panic!("0x{op:02x} at the end of a code item must report a bad target, got {err:?}")
        };
        assert_eq!(at, UNITS - 1);
        assert_eq!(units, UNITS);
    }
}

/// A negative offset that runs below the code item is refused too, which is the
/// other direction and the one an `i32` cast would get wrong.
#[test]
fn a_backwards_branch_past_the_start_is_refused() {
    let insn = dexcore::insn::Instruction::F21T { op: 0x38, a: 1, offset: -30 };
    let mut out = Vec::new();
    let err = crate::lower::tests::lower_one(&insn, 0, &crate::lower::tests::unit_ctx(), &mut out)
        .expect_err("a branch below unit 0 must be refused");
    let LowerError::BadTarget { resolved, .. } = err else {
        panic!("expected a bad target, got {err:?}")
    };
    assert_eq!(resolved, -30);
    assert!(out.is_empty(), "a refused instruction appends nothing");
}

/// Every branch, jump and switch is a block terminator, and no other instruction
/// in this family is.
#[test]
fn the_branch_family_marks_the_block_ends() {
    let ending = [
        0x28u8, 0x29, 0x2a, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x2b, 0x2c,
    ];
    for op in ending {
        assert!(
            crate::lower::tests::lower_sample(op).op.ends_block(),
            "0x{op:02x} transfers control and must end a block"
        );
    }
    // The returns and the throw end a block too, and are terminators besides.
    for op in [0x0eu8, 0x0f, 0x10, 0x11, 0x27] {
        let inst = crate::lower::tests::lower_sample(op);
        assert!(inst.op.is_terminator(), "0x{op:02x} is a terminator");
        assert!(inst.op.ends_block(), "0x{op:02x} ends a block");
    }
    // The monitors do not.
    for op in [0x1du8, 0x1e] {
        assert!(
            !crate::lower::tests::lower_sample(op).op.ends_block(),
            "0x{op:02x} falls through and must not end a block"
        );
    }
}

/// A branch's label is reachable, a return's is not, and `codegen` needs the
/// difference to build blocks.
#[test]
fn only_control_transfer_carries_a_label() {
    // At unit 10, so the label is the *resolved* one and not the raw offset.
    let at_label = |op: u8| -> Vec<Label> {
        let insn = crate::lower::tests::sample(op).expect("samples decode");
        let mut out = Vec::new();
        crate::lower::tests::lower_one(&insn, 10, &unit_ctx(), &mut out).expect("lowers");
        out[0].op.labels()
    };
    assert_eq!(at_label(0x28), vec![RESOLVED]);
    assert_eq!(at_label(0x3a), vec![RESOLVED]);
    assert_eq!(
        at_label(0x2b),
        vec![RESOLVED],
        "a switch's label names its payload, which is data"
    );
    assert!(crate::lower::tests::lower_sample(0x0e).op.labels().is_empty());
    assert!(crate::lower::tests::lower_sample(0x1d).op.labels().is_empty());
}
