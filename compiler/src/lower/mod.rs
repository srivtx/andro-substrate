//! Dalvik to IR lowering.
//!
//! This is **the only module in the compiler that knows what a Dalvik opcode
//! means**. [`crate::ir`] deliberately contains no opcode byte, no instruction
//! format and no field layout; everything specific to the input format is here,
//! split so that each family is one file and one `match`:
//!
//! | module | family |
//! |---|---|
//! | [`move`] | register-to-register moves, results, exceptions |
//! | [`consts`] | the literal and pool-constant family |
//! | [`arith`] | arithmetic, bitwise, shift, conversion, comparison |
//! | [`memory`] | array element and field access |
//! | [`invoke`] | the fourteen call forms |
//! | [`control`] | branches, jumps, switches, returns, throw, monitors |
//! | [`types`] | casts, allocation, length |
//! | [`arrays`] | `new-array`, `filled-new-array`, `fill-array-data` |
//! | [`payload`] | the three data payloads |
//! | [`reserved`] | the unassigned instruction slots and the foreign encodings |
//! | [`tries`] | the try/catch table |
//!
//! # The shape of the lowering
//!
//! [`lower_code`] walks a code item's code units once, in order, decoding each
//! instruction with `dexcore` and turning it into zero or more [`Inst`]s through
//! [`lower_one`]. Two properties make the result checkable, and
//! `lower::tests::structural` checks both of them on real files:
//!
//! 1. **Every source instruction is covered.** The body starts at code unit 0
//!    and its [`Origin`]s never go backwards, so a dropped instruction is a gap
//!    in the origins rather than a silently shorter body.
//! 2. **Every instruction produces at least one `Inst`.** An input instruction
//!    that cannot be represented becomes [`IrOp::Unsupported`] with a named
//!    [`UnsupportedReason`], never nothing.
//!
//! # The two normalisations
//!
//! * **Two-address and immediate arithmetic becomes three-address.** A `2addr`
//!   form's destination *is* its left operand; an immediate form becomes a
//!   [`IrOp::ConstI32`] followed by the three-address operation. WebAssembly has
//!   neither form.
//! * **`32x` operands are re-extracted.** `dexcore` hands back the whole first
//!   code unit where the format specifies a register byte, so the destination
//!   register is `(a >> 8) & 0xff`. The oracle applies the same shift, and for
//!   the same reason; see [`move`].
//!
//! # Verification
//!
//! `dexinterp` is the oracle ([`IR.md`](../../IR.md) § Verification). A2 owns
//! the end-to-end equality test this layer exists to make possible. What is
//! checkable here, and is checked, is:
//!
//! * **structural equivalence** on real F-Droid fixtures: the body is in source
//!   order, every instruction is covered, and the operands on an [`IrOp`] are
//!   the operands of the instruction it came from
//!   (`lower::tests::structural`);
//! * **a total opcode table**: every one of the 256 opcode bytes, and every
//!   foreign encoding, either lowers to a named [`IrOp`] or to
//!   [`IrOp::Unsupported`] with a reason
//!   (`lower::tests::coverage`);
//! * **operand-selection differentials** against the oracle's own arithmetic
//!   primitives (`lower::tests::differential`).

use std::collections::BTreeSet;

use dexcore::insn::Instruction;
use dexcore::model::CodeItem;
use dexcore::reader::DexReader;

use crate::ir::{ClassCtx, Frame, Function, Inst, IrOp, Origin, TryRegion, UnsupportedReason};

pub mod arith;
pub mod arrays;
pub mod consts;
pub mod control;
pub mod error;
pub mod invoke;
pub mod memory;
pub mod move_reg;
pub mod payload;
pub mod reserved;
pub mod tries;
pub mod types;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;

pub use error::{LowerError, LowerResult};

/// The opcode families, which is the shape of this module: one variant per
/// [`types::*`] module, and the classifier below is the only thing that maps an
/// opcode byte onto one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    /// `move` and its two wider forms.
    Move,
    /// `move-result` and its forms, and `move-exception`.
    MoveResult,
    /// The return family.
    Return,
    /// The immediate family and the pool constants.
    Const,
    /// The unary operators, the conversions and the narrowings.
    Convert,
    /// The binary operators, in all three of their shapes.
    Binary,
    /// The three-register comparisons that produce -1, 0 or 1.
    Compare,
    /// The conditional branches and the unconditional jumps.
    Branch,
    /// The two table-driven dispatches.
    Switch,
    /// `throw` and the two monitor operations.
    Exception,
    /// `check-cast` and `instance-of`.
    TypeTest,
    /// `new-instance`, `new-array` and `array-length`.
    Allocate,
    /// The array element loads and stores.
    ArrayLoad,
    /// The instance and static field loads and stores.
    FieldLoad,
    /// `filled-new-array`.
    NewArrayFilled,
    /// `fill-array-data`.
    ArrayFill,
    /// The fourteen call forms.
    Invoke,
    /// The three data payloads.
    Payload,
    /// An instruction slot the input format leaves unassigned.
    Unassigned,
    /// An encoding from the wider ecosystem but not from the input format.
    ///
    /// **Never returned by [`classify`]**, because a foreign encoding is
    /// identified by its *format* rather than by its opcode byte: a foreign
    /// assembler writes whatever byte it likes into the low lane, so
    /// classifying on it would be classifying on noise. `lower_one` routes these
    /// to [`reserved::foreign`] by matching the `Instruction` variant.
    Foreign,
}

impl Family {
    /// Every family, for the coverage test.
    pub const ALL: [Family; 20] = [
        Family::Move,
        Family::MoveResult,
        Family::Return,
        Family::Const,
        Family::Convert,
        Family::Binary,
        Family::Compare,
        Family::Branch,
        Family::Switch,
        Family::Exception,
        Family::TypeTest,
        Family::Allocate,
        Family::ArrayLoad,
        Family::FieldLoad,
        Family::NewArrayFilled,
        Family::ArrayFill,
        Family::Invoke,
        Family::Payload,
        Family::Unassigned,
        Family::Foreign,
    ];

    /// The module that handles this family. Used in the `Unhandled` error so a
    /// gap names the place that should have caught it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Family::Move => "move",
            Family::MoveResult => "move-result",
            Family::Return => "return",
            Family::Const => "consts",
            Family::Convert => "arith",
            Family::Binary => "arith",
            Family::Compare => "arith",
            Family::Branch => "control",
            Family::Switch => "control",
            Family::Exception => "control",
            Family::TypeTest => "types",
            Family::Allocate => "types",
            Family::ArrayLoad => "memory",
            Family::FieldLoad => "memory",
            Family::NewArrayFilled => "arrays",
            Family::ArrayFill => "arrays",
            Family::Invoke => "invoke",
            Family::Payload => "payload",
            Family::Unassigned => "reserved",
            Family::Foreign => "reserved",
        }
    }
}

/// Classify an opcode byte. Total: every one of the 256 values names a family.
///
/// This is *the* `DexOpcode -> IrOp` table's first half — the map from the
/// input's own numbering onto this compiler's families — and it is
/// cross-checked against `dexcore`'s table by
/// `lower::tests::coverage::classification_agrees_with_the_format_table`,
/// which asserts the two disagree about validity on no opcode at all.
pub const fn classify(op: u8) -> Family {
    match op {
        // ---- moves, results, exceptions, returns
        0x00..=0x09 => Family::Move,
        0x0a..=0x0c => Family::MoveResult,
        0x0d => Family::MoveResult,
        0x0e..=0x11 => Family::Return,

        // ---- constants
        0x12..=0x19 => Family::Const,
        0x1a..=0x1b => Family::Const,
        0x1c => Family::Const,
        0xfe..=0xff => Family::Const,

        // ---- exceptions, monitors, types, allocation
        0x1d..=0x1e => Family::Exception,
        0x1f..=0x20 => Family::TypeTest,
        0x21..=0x23 => Family::Allocate,

        // ---- arrays and fields
        0x24..=0x25 => Family::NewArrayFilled,
        0x26 => Family::ArrayFill,
        0x27 => Family::Exception,
        0x28..=0x2a => Family::Branch,
        0x2b..=0x2c => Family::Switch,
        0x44..=0x51 => Family::ArrayLoad,
        0x52..=0x5f => Family::FieldLoad,
        0x60..=0x6d => Family::FieldLoad,

        // ---- unary, conversions, comparisons, binary arithmetic
        0x2d..=0x31 => Family::Compare,
        0x32..=0x3d => Family::Branch,
        0x7b..=0x8f => Family::Convert,
        0x90..=0xcf => Family::Binary,
        0xd0..=0xe2 => Family::Binary,

        // ---- calls
        0x6e..=0x72 => Family::Invoke,
        0x74..=0x78 => Family::Invoke,
        0xfa..=0xfd => Family::Invoke,

        // ---- the slots the format leaves unassigned
        0x3e..=0x43 => Family::Unassigned,
        0x73 => Family::Unassigned,
        0x79..=0x7a => Family::Unassigned,
        0xe3..=0xf9 => Family::Unassigned,

        // No wildcard arm, and that is deliberate: `rustc` then proves the table
        // covers all 256 opcode bytes, so a range added to `dexcore`'s table
        // without one here is a compile error rather than a silent fall-through
        // to a wrong family. `Family::Foreign` is absent on purpose — see its
        // documentation.
    }
}

/// One instruction that did not become a real [`IrOp`].
///
/// The IR records the rejection in the body, at the right [`Origin`], and this
/// is the report side of the same fact: a method that lowered cleanly has none
/// of these, and a method that did not has exactly as many as there were
/// instructions `codegen` will have to trap on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refusal {
    /// Where in the source method the rejected instruction was.
    pub origin: Origin,
    /// Why.
    pub reason: UnsupportedReason,
}

/// A lowered method, plus the refusals as a list.
#[derive(Debug, Clone, PartialEq)]
pub struct Lowered {
    /// The function.
    pub function: Function,
    /// The instructions that became [`IrOp::Unsupported`].
    pub refusals: Vec<Refusal>,
}

impl Lowered {
    /// True when every instruction in the method became a real operation.
    pub fn is_complete(&self) -> bool {
        self.refusals.is_empty()
    }
}

/// Lower one decoded method body.
///
/// The four code-item header fields and the instruction stream are taken
/// separately, so a caller that already has them does not have to re-read the
/// file. `tries` must already be decoded, by [`tries::decode_tries`].
pub fn lower_code(
    ctx: ClassCtx,
    item: &CodeItem,
    units: &[u16],
    tries: Vec<TryRegion>,
) -> LowerResult<Lowered> {
    let frame = Frame::new(item.registers_size, item.ins_size, item.outs_size, item.insns_size);
    if item.insns_off % 2 != 0 {
        // A code item's instruction stream is 4-byte aligned by construction, so
        // an odd offset means the caller handed us something else. Refusing is
        // right and cheap; misreading it would not be.
        return Err(LowerError::Undecodable {
            at: 0,
            detail: format!("code item's insns_off {} is not 2-byte aligned", item.insns_off),
        });
    }
    let taken = units.len().min(item.insns_size as usize);
    let code = Ctx::new(item.insns_size);
    let mut body: Vec<Inst> = Vec::new();
    let mut refusals: Vec<Refusal> = Vec::new();
    let mut at = 0usize;
    while at < taken {
        let (insn, width) = dexcore::decode_one(units, at)
            .map_err(|e| LowerError::Undecodable { at: at as u32, detail: e.to_string() })?;
        // The width `dexcore` reports is the format's declared width, and two of
        // those are wrong. Both overrides are documented where they are used;
        // the oracle applies the same two, which is why they are here and not in
        // `dexcore`: a fix to a shared file would change the oracle's behaviour
        // mid-study, and the study's numbers are taken against the oracle as it
        // stands.
        let width = corrected_width(&insn, width);
        if width == 0 {
            return Err(LowerError::Undecodable {
                at: at as u32,
                detail: "an instruction of zero width would stop the walk advancing".into(),
            });
        }
        let before = body.len();
        lower_one(&insn, at as u32, &code, &mut body)?;
        if body.len() == before {
            // Defensive, and the reason [`IrOp::Unsupported`] exists: an
            // instruction that produces nothing is a hole, and a hole is not
            // detectable downstream.
            return Err(LowerError::Unhandled {
                op: insn.opcode().unwrap_or(0),
                family: "lower",
                at: at as u32,
            });
        }
        for inst in &body[before..] {
            if let IrOp::Unsupported { reason } = inst.op {
                refusals.push(Refusal { origin: inst.origin, reason });
            }
        }
        at += width;
    }

    let function = Function::new(ctx, frame, body, tries)?;
    Ok(Lowered { function, refusals })
}

/// The code units an instruction really occupies, given the width `dexcore`
/// reports for it.
///
/// Two of the 224 widths in `dexcore`'s table disagree with the encoding, and
/// both disagreements are load-bearing — a linear walk that takes them at face
/// value desynchronises from that point on, and every branch target after it is
/// wrong:
///
/// * **`32x` is 2 code units, not 3.** `Format::F32X::code_units` derives the
///   width from the first digit of the AOSP format name, and `32x` starts with
///   a `3` that is a *nibble count* in the name and not a width. `move/16`,
///   `move-wide/16` and `move-object/16` are all `AA|op BBBB`.
/// * **A payload's width follows from its own contents.** `PayloadKind`
///   documents a packed switch as `4 + size` units and a sparse one as
///   `2 + 2*size`, but each array element is a 32-bit word, so the real widths
///   are `4 + 2*targets` and `2 + 4*keys`. `dexcore::insn::Payload::width`
///   agrees with this; the two sources disagree, and this is the one the
///   lowering uses because it is the one the encoder wrote.
///
/// Both are defects in a file this component does not own, and both are reported
/// rather than patched; see the report.
fn corrected_width(insn: &Instruction, reported: usize) -> usize {
    match insn {
        Instruction::F32X { .. } => 2,
        Instruction::Payload(p) => p.width() as usize / 2,
        _ => reported,
    }
}

/// Lower one decoded instruction into `out`.
///
/// `at` is the instruction's code-unit offset, which becomes the [`Origin`] of
/// everything this produces and the base every relative offset resolves
/// against.
///
/// The contract is absolute: **this always appends at least one [`Inst`]**. An
/// instruction with no representation becomes [`IrOp::Unsupported`] with a
/// named reason, and an instruction no family claims becomes
/// [`LowerError::Unhandled`], which the coverage test fails on. There is no
/// third outcome, and in particular there is no path that appends nothing.
pub fn lower_one(
    insn: &Instruction,
    at: u32,
    ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    // A payload is data, not an instruction, and it has no opcode byte.
    if let Instruction::Payload(p) = insn {
        return payload::lower(p, at, ctx, out);
    }
    // The foreign encodings are identified by their *format*, not by their
    // opcode byte, because a foreign assembler writes whatever byte it likes
    // into the low lane.
    if let Some(op) = insn.opcode() {
        match insn {
            Instruction::Unused { .. } => return reserved::unassigned(op, at, ctx, out),
            Instruction::F20BC { .. }
            | Instruction::F22CS { .. }
            | Instruction::F35MS { .. }
            | Instruction::F35MI { .. }
            | Instruction::F3RMS { .. }
            | Instruction::F3RMI { .. }
            | Instruction::F52C { .. }
            | Instruction::F5RC { .. } => return reserved::foreign(op, at, ctx, out),
            _ => {}
        }
        return dispatch(classify(op), op, insn, at, ctx, out);
    }
    Err(LowerError::Unhandled { op: 0, family: "lower", at })
}

/// Hand an instruction to the family that claims it.
fn dispatch(
    family: Family,
    op: u8,
    insn: &Instruction,
    at: u32,
    ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    match family {
        Family::Move | Family::MoveResult => move_reg::lower(op, insn, at, ctx, out),
        Family::Return | Family::Branch | Family::Switch | Family::Exception => {
            control::lower(op, insn, at, ctx, out)
        }
        Family::Const => consts::lower(op, insn, at, ctx, out),
        Family::Convert | Family::Binary | Family::Compare => arith::lower(op, insn, at, ctx, out),
        Family::TypeTest | Family::Allocate => types::lower(op, insn, at, ctx, out),
        Family::ArrayLoad | Family::FieldLoad => memory::lower(op, insn, at, ctx, out),
        Family::NewArrayFilled | Family::ArrayFill => arrays::lower(op, insn, at, ctx, out),
        Family::Invoke => invoke::lower(op, insn, at, ctx, out),
        // `Payload`, `Unassigned` and `Foreign` are never routed here: the
        // first two are decided by the `Instruction` variant and the third by
        // the format, all before `classify` runs. The catch-all is a backstop
        // that turns a mistake into a named error rather than into silence.
        _ => Err(LowerError::Unhandled { op, family: family.as_str(), at }),
    }
}

/// What a family module needs beyond the instruction itself.
///
/// The code item's length, and nothing else. It is here because the branch
/// offsets are *relative* and the IR's labels are *absolute*, so turning one
/// into the other needs a bound — and because passing it as one value means every
/// family module has the same signature, so `dispatch` below is a flat table
/// rather than eight near-identical blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctx {
    /// The code item's `insns_size`: every [`Label`] is relative to this.
    pub units: u32,
}

impl Ctx {
    /// A context for a code item of `units` code units.
    pub const fn new(units: u32) -> Ctx {
        Ctx { units }
    }

    /// Resolve a relative branch offset at instruction `at` to an absolute label.
    ///
    /// The arithmetic is done in `i64` and every step is checked, because the
    /// offset in the encoding is a signed 32-bit value and the position is a
    /// `u32` code-unit index: their sum can leave the code item, and a silently
    /// wrapped branch lands in the middle of a method and produces a plausible
    /// wrong answer.
    pub fn target(&self, at: u32, offset: i64) -> LowerResult<crate::ir::Label> {
        let resolved = i64::from(at) + offset;
        if resolved < 0 || resolved >= i64::from(self.units) {
            return Err(LowerError::BadTarget {
                at,
                offset,
                resolved,
                units: self.units,
            });
        }
        Ok(crate::ir::Label(resolved as u32))
    }
}

/// The error every family module returns for an opcode it does not claim.
///
/// One helper, so the message is identical wherever a gap appears, and so that
/// the family name in it is the *module* name — which is what a reader needs in
/// order to know which file to open.
pub(crate) fn unhandled(op: u8, module: &'static str, at: u32) -> LowerError {
    LowerError::Unhandled { op, family: module, at }
}

/// Every opcode byte that any instruction in the stream used.
///
/// This is the lowering's own coverage record, and it is what a study wants: a
/// count of what the compiler *actually met*, as a fact about the input, next to
/// the count of what it *could* handle, which is a fact about the compiler. The
/// two are different numbers and conflating them is how a coverage claim becomes
/// meaningless.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpcodeCensus {
    /// The opcode bytes seen, ascending.
    pub seen: BTreeSet<u8>,
    /// How many times each was seen.
    pub counts: std::collections::BTreeMap<u8, u32>,
}

impl OpcodeCensus {
    /// Record one instruction's opcode.
    pub fn record(&mut self, insn: &Instruction) {
        if let Some(op) = insn.opcode() {
            *self.counts.entry(op).or_insert(0) += 1;
            self.seen.insert(op);
        }
    }

    /// How many distinct opcode bytes were seen.
    pub fn distinct(&self) -> usize {
        self.seen.len()
    }

    /// Total instructions counted, including repeats.
    pub fn total(&self) -> u32 {
        self.counts.values().sum()
    }
}

/// Walk a code item's instruction stream, recording the census and handing each
/// instruction to [`lower_one`].
///
/// This is [`lower_code`]'s loop factored out, because the verification wants
/// the census of a *file* — every method, thousands of instructions, the actual
/// d8 output — and not just of the handful of methods a synthetic test can
/// write by hand.
pub fn walk_and_lower(
    units: &[u16],
    out: &mut Vec<Inst>,
    census: &mut OpcodeCensus,
) -> LowerResult<()> {
    let ctx = Ctx::new(units.len() as u32);
    let mut at = 0usize;
    while at < units.len() {
        let (insn, width) = dexcore::decode_one(units, at)
            .map_err(|e| LowerError::Undecodable { at: at as u32, detail: e.to_string() })?;
        let width = corrected_width(&insn, width);
        if width == 0 {
            return Err(LowerError::Undecodable {
                at: at as u32,
                detail: "an instruction of zero width would stop the walk advancing".into(),
            });
        }
        census.record(&insn);
        lower_one(&insn, at as u32, &ctx, out)?;
        at += width;
    }
    Ok(())
}

/// Lower one method straight out of a DEX file.
///
/// The convenience entry point for `codegen` (A2) and the reachability pass
/// (A4): it reads the code item, decodes its try table and lowers the body. It
/// takes a [`ClassCtx`] rather than a `DexMethod` so that a host-synthesised
/// method and an app method take the same path.
pub fn lower_method(
    dex: &DexReader<'_>,
    ctx: ClassCtx,
    code_off: u32,
) -> LowerResult<Lowered> {
    let item = dex.code_item(code_off).map_err(|e| LowerError::Undecodable {
        at: 0,
        detail: format!("code_item at {code_off}: {e}"),
    })?;
    let bytes = dex
        .code_units(code_off)
        .map_err(|e| LowerError::Undecodable { at: 0, detail: format!("code units: {e}") })?;
    let units = units_of(bytes, item.insns_size)?;
    let tries = tries::decode_tries(dex, &item)?;
    lower_code(ctx, &item, &units, tries)
}

/// Reinterpret an instruction stream as little-endian code units, truncating to
/// a whole number of units and never past `insns_size`.
fn units_of(bytes: &[u8], insns_size: u32) -> LowerResult<Vec<u16>> {
    let take = (bytes.len()).min(insns_size as usize * 2);
    let take = take - (take % 2);
    let mut out = Vec::with_capacity(take / 2);
    for pair in bytes[..take].chunks_exact(2) {
        out.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    Ok(out)
}
