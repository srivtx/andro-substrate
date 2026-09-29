//! The instruction space the format does not fill: unassigned slots and foreign
//! encodings.
//!
//! # Nothing here lowers to nothing
//!
//! Every one of the 32 unassigned slots and every foreign encoding becomes an
//! [`IrOp::Unsupported`] carrying a named reason, positioned in the body at the
//! offset of the instruction it replaces. That is the whole point of the module:
//! an input instruction with no IR representation must be *present* in the output
//! as a refusal, because an absent instruction is indistinguishable from an
//! instruction nobody thought about, and that is how a plausible wrong answer
//! ships.
//!
//! # The two reasons are kept apart on purpose
//!
//! [`UnsupportedReason::UnassignedSlot`] and [`UnsupportedReason::ForeignFormat`]
//! are different claims about the *file*, and merging them would make the
//! refusal count unreadable:
//!
//! * an **unassigned slot** means the file is not the format it claims to be —
//!   a corrupt or hostile `classes.dex`, and a finding about the input;
//! * a **foreign encoding** means the file is a valid variant from the wider
//!   ecosystem — a third-party obfuscator, or a runtime-extended format — and
//!   is also a finding about the input, but a *different* one, and one that a
//!   future format extension would resolve.
//!
//! Neither is a substrate limitation, and the reason's `explain()` says so in a
//! sentence a reader can check. The oracle keeps the same two apart, as
//! `Unsupported::UnusedOpcode` and `Unsupported::ForeignFormat`, which is the
//! agreement that makes a coverage number comparable between the two components.

use dexcore::insn::Instruction;

use crate::ir::{Inst, IrOp, Origin, UnsupportedReason};

use super::{Ctx, LowerResult};

/// Lower one unassigned instruction slot.
pub fn unassigned(
    op: u8,
    at: u32,
    _ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let _ = op;
    out.push(Inst::new(
        IrOp::Unsupported { reason: UnsupportedReason::UnassignedSlot },
        Origin::at(at),
    ));
    Ok(())
}

/// Lower one foreign instruction encoding.
pub fn foreign(
    op: u8,
    at: u32,
    _ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let _ = op;
    out.push(Inst::new(
        IrOp::Unsupported { reason: UnsupportedReason::ForeignFormat },
        Origin::at(at),
    ));
    Ok(())
}

/// The nine encodings the wider ecosystem uses and the format proper does not
/// assign, as the [`dexcore::insn::Instruction`] variants that carry them.
///
/// Two of the nine — `40sc` and `41c` — have a [`dexcore::opcodes::Format`]
/// variant but no `Instruction` variant, so `decode_one` can never produce them
/// and there is nothing to lower. They are listed here so that the count "nine
/// foreign formats" and the count "eight lowerable foreign encodings" cannot
/// drift apart silently; `lower::tests::coverage` asserts both numbers.
pub const FOREIGN_FORMATS: [&str; 9] =
    ["20bc", "22cs", "35mi", "35ms", "3rmi", "3rms", "40sc", "41c", "52c"];

/// The eight of those nine that a decoder can actually produce, as the
/// `Instruction` variant names.
pub const FOREIGN_VARIANTS: [&str; 8] =
    ["F20BC", "F22CS", "F35MI", "F35MS", "F3RMI", "F3RMS", "F52C", "F5RC"];

/// The encodings with a format but no decoder output, and therefore nothing to
/// lower. `decode_one` matches on `Format` and these two have no arm, so a file
/// containing one cannot be decoded past it — which is itself a finding, and one
/// A3's pool reader would hit rather than this lowering.
pub const UNREACHABLE_FORMATS: [&str; 2] = ["40sc", "41c"];

/// Whether an instruction is one of the foreign encodings.
pub fn is_foreign(insn: &Instruction) -> bool {
    matches!(
        insn,
        Instruction::F20BC { .. }
            | Instruction::F22CS { .. }
            | Instruction::F35MS { .. }
            | Instruction::F35MI { .. }
            | Instruction::F3RMS { .. }
            | Instruction::F3RMI { .. }
            | Instruction::F52C { .. }
            | Instruction::F5RC { .. }
    )
}
