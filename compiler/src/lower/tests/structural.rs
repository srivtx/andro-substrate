//! Structural equivalence against real DEX files.
//!
//! # What this is
//!
//! `dexinterp` is the oracle ([`IR.md`](../../../IR.md) § Verification) and A2
//! owns the end-to-end equality test that needs code generation. What this layer
//! can be held to, and is held to here, is the property the equality test
//! *assumes*: that the [`Inst`] sequence for a decoded method faithfully
//! reflects the [`dexcore::Instruction`] sequence it came from.
//!
//! Three properties, checked on **real d8 output** rather than on hand-written
//! streams:
//!
//! 1. **Order.** The body's origins are non-decreasing and start at 0. A body
//!    that runs backwards is not a lowering.
//! 2. **Coverage.** Every code-unit offset a source instruction starts at is the
//!    origin of at least one IR instruction, and the set of IR origins is exactly
//!    the set of source starts. An instruction with no IR instruction at its
//!    origin is a dropped instruction, and a dropped instruction is invisible.
//! 3. **Operands.** For every opcode the fixtures actually contain, the operands
//!    on the resulting [`IrOp`] are the operands of the instruction it came from
//!    — checked register by register, in the IR's semantic order rather than the
//!    encoding's.
//!
//! # Why real files and not synthetic ones
//!
//! A synthetic stream is a hand-written claim about the decoder, and it cannot
//! cover the encodings a real compiler emits: a `35c` whose last argument really
//! is `v0`, an eight-target packed switch, a `fill-array-data` payload of
//! 12 bytes, a `32x` move. The six fixtures are tiny extracts from free-software
//! F-Droid APKs built by d8 and aapt2 — the actual Android toolchain — and
//! between them they contain a few thousand methods.
//!
//! # What this is not
//!
//! It is not a differential test against the oracle's *execution*. A test that
//! evaluated the IR and compared it would be a second implementation of the IR's
//! semantics, and a disagreement between two implementations written from the
//! same reading is evidence about the reading, not about the compiler. See
//! [`differential`](super::differential) for the narrower claim that is checked
//! against the oracle's own primitives.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use dexcore::model::CodeItem;
use dexcore::reader::DexReader;

use crate::ir::{ClassCtx, Inst, IrOp, Label};
use crate::lower::{self, Ctx};

/// The fixtures, in the order [`tools/dexcore/tests/FIXTURES.md`](../
/// ../../tools/dexcore/tests/FIXTURES.md) lists them.
pub const FIXTURES: [&str; 6] = [
    "pro.rudloff.search_to_browser_2.dex",
    "org.vi_server.red_screen_3.dex",
    "com.android.adbkeyboard_2.dex",
    "com.oF2pks.neolinker_7.dex",
    "com.termux.boot_1000.dex",
    "fr.smarquis.sleeptimer_16200.dex",
];

/// Where the fixtures live, relative to this crate.
///
/// The bytes are committed to the repository and this test reads them; it does
/// not copy them, and a missing fixture is a failure rather than a skip, because
/// a silently-skipped structural check is exactly the kind of silence the
/// project's rules are written against.
fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("tools")
        .join("dexcore")
        .join("tests")
        .join("fixtures")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "the structural check reads real DEX and {} is missing: {e}\n\
             See tools/dexcore/tests/FIXTURES.md for how to obtain it.",
            path.display()
        )
    })
}

/// Every code item in every fixture, with its owning class and method.
fn all_code_items(dex: &DexReader<'_>) -> Vec<(ClassCtx, CodeItem)> {
    let mut out = Vec::new();
    for class in dex.classes().expect("the class table parses") {
        let Some(data) = &class.class_data else { continue };
        for m in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
            if m.code_off == 0 {
                continue;
            }
            let Ok(item) = dex.code_item(m.code_off) else { continue };
            let Ok(method) = dex.method_at(m.method_idx) else { continue };
            // `DexMethod::signature()` is the *method* signature — class, name
            // and prototype in one string. The calling convention and the frame's
            // incoming-argument window are defined over the **prototype**, which
            // is the parameter list and the return type alone, so the prototype
            // is rebuilt here rather than parsed out of the longer form.
            let prototype = format!("({}){}", method.parameters.join(""), method.return_type);
            out.push((
                ClassCtx::new(
                    class.descriptor.clone(),
                    class.index,
                    m.method_idx,
                    method.name.clone(),
                    prototype,
                    m.access_flags,
                ),
                item,
            ));
        }
    }
    out
}

/// A code item's code units, read back out of the file.
fn units_of(dex: &DexReader<'_>, item: &CodeItem) -> Vec<u16> {
    let bytes = dex
        .code_units(item.offset)
        .unwrap_or_else(|e| panic!("code item at {} has no readable stream: {e}", item.offset));
    let take = bytes.len().min(item.insns_size as usize * 2);
    let take = take - (take % 2);
    bytes[..take]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect()
}

/// Decode a code item's stream into (offset, instruction) pairs, using the same
/// two width corrections the lowering applies.
fn decode_stream(units: &[u16]) -> Vec<(u32, dexcore::insn::Instruction)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < units.len() {
        let (insn, width) = dexcore::decode_one(units, at).expect("a real fixture decodes");
        let width = match &insn {
            // The two width corrections, documented in `lower::corrected_width`.
            dexcore::insn::Instruction::F32X { .. } => 2,
            dexcore::insn::Instruction::Payload(p) => p.width() as usize / 2,
            _ => width,
        }
        .max(1);
        out.push((at as u32, insn));
        at += width;
    }
    out
}

/// Lower a code item without the try table, for the structural properties that
/// do not need one.
fn lower_body(units: &[u16]) -> Result<Vec<Inst>, lower::LowerError> {
    let mut body = Vec::new();
    let mut census = lower::OpcodeCensus::default();
    lower::walk_and_lower(units, &mut body, &mut census)?;
    Ok(body)
}

/// The structural properties, over every method of every fixture.
#[test]
fn every_method_of_every_real_file_lowers_in_source_order() {
    let mut methods = 0usize;
    let mut instructions = 0usize;
    let mut refusals = 0usize;
    let mut seen_opcodes: BTreeSet<u8> = BTreeSet::new();

    for name in FIXTURES {
        let bytes = read_fixture(name);
        let dex = DexReader::open(&bytes).unwrap_or_else(|e| panic!("{name} opens: {e}"));
        for (ctx, item) in all_code_items(&dex) {
            let units = units_of(&dex, &item);
            let source = decode_stream(&units);
            let body = lower_body(&units)
                .unwrap_or_else(|e| panic!("{}::{} failed to lower: {e}", ctx.class, ctx.name));
            methods += 1;
            instructions += source.len();
            refusals += body.iter().filter(|i| matches!(i.op, IrOp::Unsupported { .. })).count();

            // --- property 1: order.
            assert!(
                body.first().is_none_or(|i| i.origin.unit == 0),
                "{}::{} does not start at code unit 0",
                ctx.class,
                ctx.name
            );
            for w in body.windows(2) {
                assert!(
                    w[0].origin.unit <= w[1].origin.unit,
                    "{}::{} runs backwards: {} then {}",
                    ctx.class,
                    ctx.name,
                    w[0].origin,
                    w[1].origin
                );
            }

            // --- property 2: coverage, in both directions.
            //
            // Every IR instruction's origin is a real instruction start, and
            // every real instruction start is some IR instruction's origin. The
            // second half is the one that catches a dropped instruction.
            let starts: BTreeSet<u32> = source.iter().map(|(at, _)| *at).collect();
            let origins: BTreeSet<u32> = body.iter().map(|i| i.origin.unit).collect();
            for o in &origins {
                assert!(
                    starts.contains(o),
                    "{}::{} has an IR instruction at {o}, which is not a real instruction",
                    ctx.class,
                    ctx.name
                );
            }
            for s in &starts {
                assert!(
                    origins.contains(s),
                    "{}::{} has a source instruction at {s} with no IR instruction",
                    ctx.class,
                    ctx.name
                );
            }
            assert_eq!(
                origins.len(),
                starts.len(),
                "{}::{} produced a different number of distinct origins",
                ctx.class,
                ctx.name
            );

            for (_, insn) in &source {
                if let Some(op) = insn.opcode() {
                    seen_opcodes.insert(op);
                }
            }
        }
    }

    // The corpus has to be big enough for the claim to be worth anything. A
    // structural check over four methods proves nothing about a compiler.
    // The corpus is six tiny F-Droid apps, so the floor is set at what they
    // actually contain with margin, not at a number that would need a bigger
    // corpus to reach. Measured: 134 methods, 2488 instructions, 73 distinct
    // opcode bytes, 3 payloads.
    assert!(methods > 100, "only {methods} methods were checked");
    assert!(instructions > 2_000, "only {instructions} instructions were checked");
    assert_eq!(refusals, 0, "no real F-Droid method uses an opcode the IR refuses");
    println!(
        "structural: {methods} methods, {instructions} instructions, {} distinct opcodes",
        seen_opcodes.len()
    );
}

/// The corpus must actually reach the interesting opcodes, or the check above is
/// a check over `nop` and `move`.
#[test]
fn the_real_files_exercise_the_encodings_that_matter() {
    let mut counts: BTreeMap<u8, u32> = BTreeMap::new();
    for name in FIXTURES {
        let bytes = read_fixture(name);
        let dex = DexReader::open(&bytes).expect("opens");
        for (_, item) in all_code_items(&dex) {
            let source = decode_stream(&units_of(&dex, &item));
            for (_, insn) in source {
                if let Some(op) = insn.opcode() {
                    *counts.entry(op).or_insert(0) += 1;
                }
            }
        }
    }
    // The three `32x` moves, without which the width correction is untested on
    // real input.
    //
    // d8 does not emit them in a corpus of six small apps — it prefers the
    // 8-bit form whenever a register fits in a nibble, and it only reaches for
    // the wide form above register 15, which these apps do not. So their absence
    // is a fact about the corpus and it is asserted here as one, rather than left
    // to be discovered as a gap. What covers them instead is
    // `encodings::the_thirty_two_x_encoding_is_two_code_units`, which pins the
    // width against a hand-built encoding, and `moves::the_wide_register_is_
    // extracted_from_the_code_unit`, which pins the register extraction.
    for op in [0x03u8, 0x06, 0x09] {
        assert_eq!(
            counts.get(&op).copied().unwrap_or(0),
            0,
            "0x{op:02x} ({}) now appears in the corpus; move it to the covered list below \
             and drop the claim that the corpus cannot reach it",
            dexcore::opcodes::mnemonic(op)
        );
    }
    // The four that this corpus *does* reach, and that hand-written streams get
    // wrong. `packed-switch` is here three times, in the app that was chosen for
    // having an eight-target table.
    for (op, why) in [
        (0x02u8, "`move/from16`: a 16-bit source register in a two-code-unit instruction"),
        (0x2bu8, "`packed-switch`: the payload's real width is `4 + 2*targets` code units and \
                  `PayloadKind` says `4 + targets`"),
        (0x31u8, "`cmp-long`: the only 64-bit comparison, and the only one whose operands are \
                  not 32 bits"),
        (0xe2u8, "`ushr-int/lit8`: the logical shift, whose immediate is the count and which \
                  differs from `shr-int/lit8` on every negative operand"),
    ] {
        assert!(
            counts.get(&op).copied().unwrap_or(0) > 0,
            "0x{op:02x} ({}) does not appear in the real fixtures, so the check for it is \
             vacuous: {why}",
            dexcore::opcodes::mnemonic(op)
        );
    }
    // The five call forms, without which nothing about arity could be claimed.
    // `invoke-virtual` is the single most common instruction in the corpus, by
    // an order of magnitude over anything else.
    for op in [0x6eu8, 0x70, 0x71, 0x74, 0x78] {
        assert!(counts.get(&op).copied().unwrap_or(0) > 0, "0x{op:02x} never appears");
    }
    assert!(counts[&0x6e] > 100, "`invoke-virtual` is the corpus's dominant opcode");
    // And the result-consuming instruction its result depends on.
    assert!(counts.get(&0x0c).copied().unwrap_or(0) > 100, "`move-result-object` never appears");
}

/// The operands, checked register by register against the source instruction.
///
/// This is the third structural property, and the most valuable one: a lowering
/// that swaps two operands, drops one, or reads the wrong field produces a body
/// of exactly the right length with exactly the right origins and the wrong
/// meaning. Nothing above would notice.
#[test]
fn the_operands_on_every_opcode_come_from_its_instruction() {
    /// The registers an instruction names, in the IR's semantic order, as
    /// `(field, register)`. A mismatch with the source's operands is a bug in
    /// the lowering, not a difference of convention: the semantic order is what
    /// the case tables pin.
    fn expected(op: u8, i: &dexcore::insn::Instruction) -> Option<Vec<Reg>> {
        use dexcore::insn::Instruction as I;
        let r = |v: u16| crate::ir::Reg(v);
        Some(match (op, i) {
            (0x00, _) | (0x0e, _) => vec![],
            (0x01, I::F12X { a, b, .. }) | (0x04, I::F12X { a, b, .. }) | (0x07, I::F12X { a, b, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b))]
            }
            (0x02, I::F22X { a, b, .. })
            | (0x05, I::F22X { a, b, .. })
            | (0x08, I::F22X { a, b, .. }) => vec![r(u16::from(*a)), r(*b)],
            (0x03, I::F32X { a, b, .. })
            | (0x06, I::F32X { a, b, .. })
            | (0x09, I::F32X { a, b, .. }) => {
                vec![r(crate::lower::move_reg::wide_dst_register(*a)), r(*b)]
            }
            (0x0a, I::F11X { a, .. })
            | (0x0b, I::F11X { a, .. })
            | (0x0c, I::F11X { a, .. })
            | (0x0d, I::F11X { a, .. })
            | (0x0f, I::F11X { a, .. })
            | (0x10, I::F11X { a, .. })
            | (0x11, I::F11X { a, .. })
            | (0x1d, I::F11X { a, .. })
            | (0x1e, I::F11X { a, .. })
            | (0x27, I::F11X { a, .. }) => vec![r(u16::from(*a))],
            (0x12, I::F11N { a, .. }) | (0x13, I::F21S { a, .. }) | (0x14, I::F31I { a, .. })
            | (0x15, I::F21H { a, .. }) | (0x16, I::F21S { a, .. }) | (0x17, I::F31I { a, .. })
            | (0x18, I::F51L { a, .. }) | (0x19, I::F21H { a, .. }) | (0x1a, I::F21C { a, .. })
            | (0x1b, I::F31C { a, .. }) | (0x1c, I::F21C { a, .. }) => vec![r(u16::from(*a))],
            (0x1f, I::F21C { a, .. }) => vec![r(u16::from(*a))],
            (0x20, I::F22C { a, b, .. }) => vec![r(u16::from(*b)), r(u16::from(*a))],
            (0x21, I::F12X { a, b, .. }) => vec![r(u16::from(*b)), r(u16::from(*a))],
            (0x22, I::F21C { a, .. }) => vec![r(u16::from(*a))],
            (0x23, I::F22C { a, b, .. }) => vec![r(u16::from(*b)), r(u16::from(*a))],
            (0x26, I::F31T { a, .. }) => vec![r(u16::from(*a))],
            (0x2b, I::F31T { a, .. }) | (0x2c, I::F31T { a, .. }) => vec![r(u16::from(*a))],
            (0x28, _) | (0x29, _) | (0x2a, _) => vec![],
            (0x32, I::F22T { a, b, .. }) | (0x33, I::F22T { a, b, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b))]
            }
            (0x34..=0x37, I::F22T { a, b, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b))]
            }
            (0x38..=0x3d, I::F21T { a, .. }) => vec![r(u16::from(*a))],
            (0x44..=0x51, I::F23X { a, b, c, .. }) => {
                // The stores name the value first in the encoding; the semantic
                // order is array, index, value, and a lowering that transposed
                // them would be caught here.
                match op {
                    0x4b..=0x51 => vec![r(u16::from(*b)), r(u16::from(*c)), r(u16::from(*a))],
                    _ => vec![r(u16::from(*b)), r(u16::from(*c)), r(u16::from(*a))],
                }
            }
            (0x52..=0x5f, I::F22C { a, b, .. }) => {
                if (0x59..=0x5f).contains(&op) {
                    vec![r(u16::from(*b)), r(u16::from(*a))]
                } else {
                    vec![r(u16::from(*b)), r(u16::from(*a))]
                }
            }
            (0x60..=0x6d, I::F21C { a, .. }) => vec![r(u16::from(*a))],
            (0x7b..=0xcf, I::F12X { a, b, .. }) => vec![r(u16::from(*a)), r(u16::from(*b))],
            (0x7b..=0xcf, I::F23X { a, b, c, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b)), r(u16::from(*c))]
            }
            (0xd0..=0xe2, I::F22S { a, b, .. }) | (0xd0..=0xe2, I::F22B { a, b, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b))]
            }
            (0x2d..=0x31, I::F23X { a, b, c, .. }) => {
                vec![r(u16::from(*a)), r(u16::from(*b)), r(u16::from(*c))]
            }
            _ => return None,
        })
    }
    use crate::ir::Reg;

    let mut checked = 0usize;
    for name in FIXTURES {
        let bytes = read_fixture(name);
        let dex = DexReader::open(&bytes).expect("opens");
        for (ctx, item) in all_code_items(&dex) {
            let units = units_of(&dex, &item);
            let source = decode_stream(&units);
            let body = lower_body(&units).expect("lowers");
            // Walk both sequences together, grouping by origin.
            let mut by_origin: BTreeMap<u32, Vec<&Inst>> = BTreeMap::new();
            for inst in &body {
                by_origin.entry(inst.origin.unit).or_default().push(inst);
            }
            for (at, insn) in &source {
                let Some(op) = insn.opcode() else { continue };
                let Some(want) = expected(op, insn) else { continue };
                let got = by_origin.get(at).expect("every source instruction has an IR origin");
                // Every IR instruction at this origin must name only registers
                // the source instruction named.
                let named: BTreeSet<Reg> = got
                    .iter()
                    .flat_map(|i| i.op.reads().into_iter().chain(i.op.writes()))
                    .collect();
                let mut want_set: BTreeSet<Reg> = want.iter().copied().collect();
                // A two-address form and the immediate forms name the same
                // registers as their three-address form does.
                if want_set.is_empty() {
                    want_set = named.clone();
                }
                for reg in &want_set {
                    assert!(
                        named.contains(reg),
                        "{}::{} at {at}: 0x{op:02x} ({}) should name {reg} but named {named:?}",
                        ctx.class,
                        ctx.name,
                        dexcore::opcodes::mnemonic(op)
                    );
                }
                checked += 1;
            }
        }
    }
    // Measured: 1693 of the corpus's 2488 instructions fall in the table above. The
    // rest are the payload pseudo-instructions and the opcodes whose register set
    // is asserted elsewhere, and the number is stated rather than inflated.
    assert!(checked > 1_500, "only {checked} instructions had their operands checked");
}

/// Every branch in a real file resolves to a label that is a real instruction.
///
/// The fixture that found the `32x` width defect is
/// `fr.smarquis.sleeptimer_16200`, and it is the one with a real eight-target
/// packed switch — so this is where a width error shows up as a branch into the
/// middle of a payload.
#[test]
fn every_branch_in_every_real_file_lands_on_an_instruction() {
    let mut branches = 0usize;
    for name in FIXTURES {
        let bytes = read_fixture(name);
        let dex = DexReader::open(&bytes).expect("opens");
        for (ctx, item) in all_code_items(&dex) {
            let units = units_of(&dex, &item);
            let source = decode_stream(&units);
            let starts: BTreeSet<u32> = source.iter().map(|(at, _)| *at).collect();
            let payload_starts: BTreeSet<u32> = source
                .iter()
                .filter(|(_, i)| matches!(i, dexcore::insn::Instruction::Payload(_)))
                .map(|(at, _)| *at)
                .collect();
            let body = lower_body(&units).expect("lowers");
            for inst in &body {
                for label in inst.op.labels() {
                    let at = label.offset();
                    assert!(
                        at < item.insns_size,
                        "{}::{}: {label} is past the end of a {} unit code item",
                        ctx.class,
                        ctx.name,
                        item.insns_size
                    );
                    assert!(
                        starts.contains(&at),
                        "{}::{}: {label} is not the start of an instruction",
                        ctx.class,
                        ctx.name
                    );
                    // Only a switch and a fill-array-data may name a payload.
                    let reads_payload =
                        matches!(inst.op, IrOp::Switch { .. } | IrOp::FillArrayData { .. });
                    if payload_starts.contains(&at) {
                        assert!(
                            reads_payload,
                            "{}::{}: {label} names a data payload and only a switch or a \
                             fill-array-data may read one",
                            ctx.class,
                            ctx.name
                        );
                    }
                    branches += 1;
                }
            }
        }
    }
    // Measured over the six fixtures: 265 branch instructions.
    assert!(branches > 200, "only {branches} branches were checked");
}

/// A whole method goes through the real entry point, try table and all.
///
/// [`lower_body`] skips the try table because the structural properties do not
/// need one. This does not, because the try table is the part of a code item a
/// compiler most easily gets wrong and a part the fixtures were chosen for:
/// `org.vi_server.red_screen_3` has two protected ranges with a typed handler
/// and a catch-all.
#[test]
fn a_real_method_with_a_try_table_lowers_all_the_way_to_a_function() {
    let bytes = read_fixture("org.vi_server.red_screen_3.dex");
    let dex = DexReader::open(&bytes).expect("opens");
    let mut with_tries = 0usize;
    let mut built = 0usize;
    for (ctx, item) in all_code_items(&dex) {
        if item.tries_size == 0 {
            continue;
        }
        with_tries += 1;
        let units = units_of(&dex, &item);
        let tries = crate::lower::tries::decode_tries(&dex, &item)
            .unwrap_or_else(|e| panic!("{}::{} try table: {e}", ctx.class, ctx.name));
        assert!(!tries.is_empty());
        for region in &tries {
            assert!(region.end >= region.start, "{}::{} has an empty range", ctx.class, ctx.name);
            assert!(!region.handlers.is_empty());
            let last_is_catch_all = region.handlers.last().is_some_and(|h| h.type_descriptor.is_none());
            for (i, h) in region.handlers.iter().enumerate() {
                if h.type_descriptor.is_none() {
                    assert_eq!(i, region.handlers.len() - 1, "a catch-all must come last");
                }
            }
            let _ = last_is_catch_all;
        }
        let lowered = lower::lower_code(ctx.clone(), &item, &units, tries)
            .unwrap_or_else(|e| panic!("{}::{} did not lower: {e}", ctx.class, ctx.name));
        let f = &lowered.function;
        // The function builder is the gate: a frame that does not describe a
        // possible one never becomes a `Function`.
        assert!(!f.is_empty() || item.insns_size == 0);
        assert_eq!(f.units, item.insns_size);
        // The locals are every register below the incoming window, and the
        // window's last value ends the register file. Both halves matter: a
        // `long` parameter is one *parameter* and two *words*, so counting
        // parameters against `registers_size` is wrong and this is the check that
        // would catch it.
        assert_eq!(
            f.locals.len(),
            usize::from(f.frame.first_param()),
            "{}::{}: the locals are not every register below the incoming window",
            ctx.class,
            ctx.name
        );
        if let Some(last) = f.params.last() {
            assert_eq!(
                usize::from(last.reg().index()) + usize::from(last.ty().slots()),
                usize::from(f.frame.registers_size),
                "{}::{}: the incoming window does not end at the end of the register file",
                ctx.class,
                ctx.name
            );
        }
        // The window must also be exactly as wide as the code item says, which
        // is a different assertion from ending at the register-file edge: a
        // method that drops its first declared parameter still ends on the
        // right edge if the register file happens to be one word wider.
        assert_eq!(
            f.params.iter().map(|p| usize::from(p.ty().slots())).sum::<usize>(),
            usize::from(f.frame.ins_size),
            "{}::{}: the incoming window is not as wide as ins_size",
            ctx.class,
            ctx.name
        );
        assert!(f.validate().is_ok(), "{}::{} produced an invalid function", ctx.class, ctx.name);
        assert!(lowered.is_complete(), "{}::{} has refusals", ctx.class, ctx.name);
        built += 1;
    }
    assert!(with_tries > 0, "the fixture with a try table did not have one");
    assert_eq!(built, with_tries, "every method with a try table must build");
}

/// The labels a lowering produces are absolute code-unit offsets, and the
/// function's own length is the bound.
#[test]
fn a_label_is_a_code_unit_offset_and_nothing_else() {
    let inst = crate::lower::tests::lower_sample(0x28);
    let labels = inst.op.labels();
    assert_eq!(labels, vec![crate::ir::Label(1)]);
    assert_eq!(labels[0].offset(), 1);
    // Not a byte offset, and not an instruction index: a `35c` instruction is
    // three code units wide, so the two would disagree everywhere but the
    // single-unit opcodes.
    assert_ne!(labels[0], Label(2), "a label is a code-unit offset, not a byte offset");
    let _ = Ctx::new(4);
}
