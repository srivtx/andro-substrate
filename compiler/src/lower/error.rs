//! Typed lowering failures.
//!
//! The compiler has one non-negotiable: **no panics on untrusted input**. A
//! malformed or hostile DEX must degrade to a value that can be reported, never
//! to a panic and never to a silently wrong lowering. Every fallible step of
//! `lower` therefore returns one of the variants below.
//!
//! The distinctions matter, and they are the same distinctions the oracle keeps:
//!
//! * [`LowerError::Undecodable`] is a *file* problem — the instruction stream
//!   could not be read. The oracle calls this `Malformed::BadCode`.
//! * [`LowerError::Unhandled`] is a *compiler* problem — the instruction decoded
//!   fine but no family claimed it. It is a bug, it should never appear in a
//!   green run, and `lower::tests::coverage` fails the build if it ever does.
//! * [`LowerError::BadFrame`] is a *method* problem — a code item whose header
//!   and instruction stream disagree.

use std::fmt;

use crate::ir::FunctionError;

/// A lowering failure.
#[derive(Debug, Clone, PartialEq)]
pub enum LowerError {
    /// The instruction stream could not be decoded at a code-unit offset.
    Undecodable {
        /// The offset at which decoding failed, in code units.
        at: u32,
        /// What `dexcore` reported.
        detail: String,
    },

    /// The instruction decoded but no opcode family claimed it.
    ///
    /// This is the variant that makes the coverage test possible. An opcode
    /// that reaches here has been decoded and then *dropped*, which is how an
    /// untested instruction turns into a plausible wrong answer; keeping it as a
    /// typed error means the omission is loud, named and located.
    Unhandled {
        /// The opcode byte, for the report.
        op: u8,
        /// The family that was asked to handle it, if the classifier named one.
        family: &'static str,
        /// The code-unit offset.
        at: u32,
    },

    /// A branch, switch or handler offset that leaves the code item, or
    /// overflows while being resolved.
    BadTarget {
        /// The instruction making the reference.
        at: u32,
        /// The relative offset it carried.
        offset: i64,
        /// The absolute offset it resolved to.
        resolved: i64,
        /// The code item's length, in code units.
        units: u32,
    },

    /// A contiguous register range whose end overflows, or that starts past the
    /// end of the register file.
    BadRegisterRange {
        /// The instruction's code-unit offset.
        at: u32,
        /// The first register of the range.
        first: u32,
        /// The number of registers.
        count: u32,
    },

    /// A payload, or a try table, that does not decode.
    ///
    /// The reason is a `String` rather than a `&'static str` because the two
    /// places that raise it both have something specific to say — a `try_item`'s
    /// own `handler_off`, for one, which is the number a reader of a
    /// disassembly has to work from and which is the only clue to which of
    /// several identically-worded failures this is.
    BadPayload {
        /// The code-unit offset, or 0 for a try table, which has no position in
        /// the instruction stream.
        at: u32,
        /// What is wrong with it.
        why: String,
    },

    /// The function that came out of lowering does not describe a possible
    /// frame, or violates one of the invariants [`Function::new`] checks.
    ///
    /// Forwarded rather than swallowed: the IR is the layer that knows what a
    /// coherent frame is, and a lowerer that produced an incoherent one has to
    /// say so with the IR's own words.
    BadFunction(Box<FunctionError>),
}

impl From<FunctionError> for LowerError {
    fn from(e: FunctionError) -> LowerError {
        LowerError::BadFunction(Box::new(e))
    }
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LowerError::Undecodable { at, detail } => {
                write!(f, "@{at}: the instruction stream does not decode: {detail}")
            }
            LowerError::Unhandled { op, family, at } => write!(
                f,
                "@{at}: opcode 0x{op:02x} reached the lowering with no handler; the \
                 `{family}` family does not claim it"
            ),
            LowerError::BadTarget { at, offset, resolved, units } => write!(
                f,
                "@{at}: a branch offset of {offset} resolves to {resolved}, which is \
                 outside the {units} code units of the code item"
            ),
            LowerError::BadRegisterRange { at, first, count } => write!(
                f,
                "@{at}: the register range v{first}..+{count} does not fit a 16-bit \
                 register file"
            ),
            LowerError::BadPayload { at, why } => write!(f, "@{at}: payload: {why}"),
            LowerError::BadFunction(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LowerError {}

/// A result whose error is a [`LowerError`].
pub type LowerResult<T> = Result<T, LowerError>;
