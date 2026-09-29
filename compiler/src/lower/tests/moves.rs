//! The move, result, exception and return families: opcodes `0x00`–`0x11`.

use crate::lower::tests::prelude::*;
use crate::lower::tests::{ RESOLVED};

lowering_cases! {
    at 0,
    {
        // ---- `10x` and the three short moves.
        nop_is_preserved: 0x00 => IrOp::Nop,
            "a `nop` is a padding unit and a branch target; dropping it would move every \
             label after it";

        move_12x: 0x01 => IrOp::MoveI32 { dst: I(1), src: I(2) },
            "`12x` moves one 32-bit word, so the destination is an `I32Reg`";
        move_from16: 0x02 => IrOp::MoveI32 { dst: I(1), src: I(2) },
            "the wider register operand changes the encoding's width, not the operation";
        move_16: 0x03 => IrOp::MoveI32 { dst: I(3), src: I(2) },
            "a **two**-code-unit `32x` whose destination is the high byte of the first unit, \
             which `dexcore` hands back whole: reading it as a register number would address \
             `0x0303` and not register 3";
        move_wide_12x: 0x04 => IrOp::MoveWide { dst: R(1), src: R(2), class: WideClass::Unresolved },
            "a `long` and a `double` are both moved by this opcode and the input does not \
             say which, so the class is recorded as unresolved rather than guessed";
        move_wide_from16: 0x05 => IrOp::MoveWide { dst: R(1), src: R(2), class: WideClass::Unresolved },
            "as above, at the wider encoding width";
        move_wide_16: 0x06 => IrOp::MoveWide { dst: R(3), src: R(2), class: WideClass::Unresolved },
            "as above, and the destination register is 3: `dexcore` hands back the whole \
             first code unit in `a`, and the shift to the high byte happens here";
        move_object_12x: 0x07 => IrOp::MoveObject { dst: O(1), src: O(2) },
            "a reference moves as a handle, so the operands are `ObjectReg` and can never \
             be handed an integer register";
        move_object_from16: 0x08 => IrOp::MoveObject { dst: O(1), src: O(2) },
            "as above, at the wider encoding width";
        move_object_16: 0x09 => IrOp::MoveObject { dst: O(3), src: O(2) },
            "as above, with the `32x` register extraction applied";

        // ---- the results of the immediately preceding call or allocation.
        move_result: 0x0a => IrOp::MoveResultI32 { dst: I(1) },
            "the result is 32 bits wide, so the destination is an `I32Reg`";
        move_result_wide: 0x0b => IrOp::MoveResultWide { dst: R(1), class: WideClass::Unresolved },
            "there is no `move-result-float` or `move-result-double` in the format; one \
             opcode covers both 64-bit classes and says which by the callee's return type, \
             which is not in the instruction";
        move_result_object: 0x0c => IrOp::MoveResultObject { dst: O(1) },
            "a reference result";
        move_exception: 0x0d => IrOp::MoveException { dst: O(1) },
            "the exception in flight is always a reference, so the destination is an \
             `ObjectReg` and not an integer register";

    }
}

/// The `32x` normalisation, checked on its own because it is the one place the
/// lowering reads a field of `Instruction` for something other than its value.
#[test]
fn the_wide_register_is_extracted_from_the_code_unit() {
    // `dexcore` reports `a` as the whole first code unit, so the raw value is
    // `0x0301` for `move/16 v3, v1`. Reading it as a register number would
    // address register 769; the oracle applies the same shift, and the two agree
    // only because both do.
    let insn = crate::lower::tests::sample(0x03).expect("move/16 has a decoded form");
    let Instruction::F32X { a, b, .. } = insn else {
        panic!("move/16 is a 32x instruction, so it decodes to F32X")
    };
    assert_eq!(a, 0x0303, "the sample must carry the whole code unit for this test to mean anything");
    assert_eq!(crate::lower::move_reg::wide_dst_register(a), 3, "the high byte is the register");
    assert_eq!(b, 2);

    let inst = crate::lower::tests::lower_sample(0x03);
    assert_eq!(inst.op, IrOp::MoveI32 { dst: I(3), src: I(2) });
}

/// Every move opcode's operands must come from the instruction and nowhere else.
#[test]
fn a_move_does_not_invent_a_register() {
    for op in [0x01u8, 0x02, 0x04, 0x05, 0x07, 0x08] {
        let inst = crate::lower::tests::lower_sample(op);
        let regs = inst.op.reads().into_iter().chain(inst.op.writes()).collect::<Vec<_>>();
        assert!(
            regs.iter().all(|r| r.0 <= 2),
            "0x{op:02x} names a register the sample did not: {regs:?}"
        );
    }
}

/// The one instruction of this family that produces a result rather than a move.
#[test]
fn a_result_is_not_a_move() {
    // The distinction matters to `codegen`: a `MoveResult*` reads an implicit
    // slot that the preceding call wrote, and a `Move*` reads a register. Folding
    // them together would make every call's result land in the wrong local.
    let inst = crate::lower::tests::lower_sample(0x0a);
    assert!(matches!(inst.op, IrOp::MoveResultI32 { .. }));
    assert!(inst.op.reads().is_empty(), "a move-result reads no register");
    assert_eq!(inst.op.writes(), vec![R(1)]);

    let inst = crate::lower::tests::lower_sample(0x01);
    assert!(matches!(inst.op, IrOp::MoveI32 { .. }));
    assert_eq!(inst.op.reads(), vec![R(2)]);
}

/// Every return is a terminator, and no other move-family instruction is.
#[test]
fn only_the_returns_end_a_block() {
    for op in [0x0eu8, 0x0f, 0x10, 0x11] {
        assert!(
            crate::lower::tests::lower_sample(op).op.is_terminator(),
            "0x{op:02x} is a return and must be a terminator"
        );
    }
    for op in [0x00u8, 0x01, 0x0a, 0x0b, 0x0c, 0x0d] {
        assert!(
            !crate::lower::tests::lower_sample(op).op.is_terminator(),
            "0x{op:02x} is not a return and must not be a terminator"
        );
    }
}

/// The resolved branch label, referenced so the constant is not dead: a sample
/// control instruction at unit 0 resolves to [`RESOLVED`], and the control tests
/// rely on that being 11 rather than 1.
#[test]
fn the_resolved_label_is_not_the_raw_offset() {
    assert_eq!(RESOLVED, Label(11));
    assert_ne!(RESOLVED, Label(1));
}
