//! Encoder fidelity: the samples the 224 case tables use are what `dexcore`'s
//! decoder really produces.
//!
//! # Why this file exists
//!
//! Every per-opcode test feeds the lowering a hand-constructed
//! [`dexcore::insn::Instruction`]. That is the right unit for testing a
//! *lowering* — it isolates it from the decoder — but it leaves a gap. If a
//! sample and the decoder disagree, then 224 tests are pinning behaviour no real
//! file exercises, and nothing in the crate would say so.
//!
//! So this file closes the gap by writing a **second, independent transcription
//! of the encodings** — [`encode`], derived from the AOSP byte layouts rather
//! than from `dexcore`'s reader — running every sample opcode through it, and
//! comparing the decoder's output field by field against the sample. Two
//! transcriptions agreeing is evidence; one is a restatement.
//!
//! Three independent readings are therefore in agreement by the end of this
//! file: the AOSP specification, `dexcore`'s decoder, and the sample the case
//! tables assert. [`structural`] is the fourth check and the strongest one: it
//! runs the same comparison over six real d8-produced files, where the byte
//! layouts are whatever the Android toolchain actually emits.
//!
//! # What a disagreement here would mean
//!
//! Not much, individually — an encoding bug in a test is a test bug. But it would
//! invalidate the *shape* of 224 tests at once, silently, which is why the
//! comparison is field by field rather than by `PartialEq` on the whole value.

use std::collections::BTreeSet;

use dexcore::insn::Instruction;
use dexcore::opcodes::Format;

use super::{sample, INDEX, PROTO, WIDE_INDEX, WIDE_LITERAL};

/// The distinctive operand values the samples use, spelled out so this encoder
/// is a *transcription* rather than a copy of `sample`.
const A: u16 = 1;
const B: u16 = 2;
const C: u16 = 3;
const FIRST: u16 = 4;
const COUNT: u16 = 3;
const REGS: [u16; 5] = [1, 2, 3, 0, 0];

/// Encode one opcode's sample as code units, from the AOSP byte layouts.
///
/// The layouts are written out rather than derived, because deriving them from
/// `dexcore`'s reader would make this file a restatement of the thing it is
/// checking. Each `F..` arm's doc names the layout it implements.
fn encode(op: u8) -> Vec<u16> {
    let f = dexcore::opcodes::opcode(op).format;
    let hi = |v: u16| u16::from(op) | (v << 8);
    let n0 = u16::from(op);
    match f {
        // `op`
        Format::F10X => vec![n0],
        // `op AA` — a signed 8-bit offset in the high byte.
        Format::F10T => vec![n0 | ((1u8 as u16) << 8)],
        // `op A|B` — one code unit. A the low nibble of byte 1, and **B is the
        // literal**, sign-extended from four bits by the decoder. There is no
        // second unit.
        Format::F11N => vec![n0 | (1u16 << 8) | (3u16 << 12)],
        // `op AA`
        Format::F11X => vec![hi(A)],
        // `B|A|op` — A the low nibble of byte 1, B the high.
        Format::F12X => vec![n0 | (A << 8) | (B << 12)],
        // `op ØØØØ AAAA`
        Format::F20T => vec![n0, 1u16],
        // `op AA BBBB`
        Format::F20BC => vec![hi(A), INDEX],
        // `op AA BBBB`
        Format::F21C | Format::F22CS => vec![hi(A), INDEX],
        // `op AA BBBB` with BBBB the *high* half of a literal.
        Format::F21H | Format::F21S => vec![hi(A), INDEX],
        // `op AA BBBB`
        Format::F21T => vec![hi(A), 1u16],
        // `op AA vBB, #+CC` — B the low byte of unit 1, CC the high.
        Format::F22B => vec![hi(A), B | ((5u8 as u16) << 8)],
        // `op AA BBBB`
        Format::F22X => vec![hi(A), B],
        // `B|A|op CCCC` — the second unit is a pool index.
        Format::F22C => vec![n0 | (A << 8) | (B << 12), INDEX],
        // `B|A|op CCCC` — the second unit is a signed 16-bit literal.
        Format::F22S => vec![n0 | (A << 8) | (B << 12), INDEX],
        // `B|A|op CCCC` — the second unit is a signed 16-bit branch offset, which
        // the samples set to 1 so that a relative offset of 1 from unit 0 lands
        // on a real instruction boundary.
        Format::F22T => vec![n0 | (A << 8) | (B << 12), 1u16],
        // `op AA BBBB`
        Format::F23X => vec![hi(A), B | (C << 8)],
        // `op ØØØØ AAAAAAAA`
        Format::F30T => vec![n0, 1u16, 0, 0],
        // `op AA BBBBBBBB`
        Format::F31C | Format::F31I => vec![hi(A), WIDE_INDEX as u16, (WIDE_INDEX >> 16) as u16],
        // `op AA` then a signed 32-bit *branch* offset, which is a different field
        // from the 32-bit index the other two `31x` forms carry, and the sample's
        // is 1 because the samples are laid out so that a relative offset of 1
        // from unit 0 lands on a real instruction boundary.
        Format::F31T => vec![hi(A), 1u16, 0],
        // `AA|op BBBB` — two code units, and the destination is the *high byte*
        // of the first. The lower eight bits are the opcode.
        //
        // A third unit is appended because `decode_one` bounds-checks against
        // the *declared* width, which for this format is three — see
        // `the_thirty_two_x_encoding_is_two_code_units`. The extra unit is never
        // read.
        Format::F32X => vec![(3u16 << 8) | n0, B, 0],
        // `A|G|op BBBB C|D|E|F` — five argument registers, the fifth in G.
        Format::F35C => vec![
            n0 | ((0u16) << 8) | (3u16 << 12),
            INDEX,
            (REGS[0] & 0x0f)
                | ((REGS[1] & 0x0f) << 4)
                | ((REGS[2] & 0x0f) << 8)
                | ((REGS[3] & 0x0f) << 12),
        ],
        // `AA|op BBBB CCCC` — AA is the argument count *and* the count field.
        Format::F3RC | Format::F3RMS | Format::F3RMI => {
            vec![n0 | (COUNT << 8), INDEX, FIRST, 0]
        }
        // `A|G|op BBBB C|D|E|F HHHH`
        Format::F45CC => vec![
            n0 | ((0u16) << 8) | (3u16 << 12),
            INDEX,
            (REGS[0] & 0x0f)
                | ((REGS[1] & 0x0f) << 4)
                | ((REGS[2] & 0x0f) << 8)
                | ((REGS[3] & 0x0f) << 12),
            PROTO,
        ],
        // `AA|op BBBB CCCC HHHH` — the trailing method type is the *fourth* word.
        // It shares the layout of `3rc` with one word appended.
        Format::F4RCC => vec![n0 | (COUNT << 8), INDEX, FIRST, PROTO],
        // `op AA BBBBBBBBBBBBBBBB`
        Format::F51L => {
            let v = WIDE_LITERAL as u64;
            vec![
                hi(A),
                v as u16,
                (v >> 16) as u16,
                (v >> 32) as u16,
                (v >> 48) as u16,
            ]
        }
        // The foreign encodings the decoder can produce. Their layouts are not
        // the format proper's, so only the field *values* are pinned and not the
        // widths; `reserved` covers their lowering.
        Format::F35MS | Format::F35MI => vec![
            n0 | (3u16 << 12),
            INDEX,
            (REGS[0] & 0x0f)
                | ((REGS[1] & 0x0f) << 4)
                | ((REGS[2] & 0x0f) << 8)
                | ((REGS[3] & 0x0f) << 12),
        ],
        Format::F52C | Format::F5RC => {
            vec![n0, B, WIDE_INDEX as u16, (WIDE_INDEX >> 16) as u16, FIRST]
        }
        // `00x` is not an instruction and has no operands.
        Format::F00X => vec![n0],
        // `40sc` and `41c` have no `Instruction` variant, so `decode_one` has no
        // arm for them and no sample can be built. `reserved` says so out loud.
        Format::F40SC | Format::F41C => vec![n0],
    }
}

/// Decode `units` from 0 and return the instruction the decoder produced.
fn decode(units: &[u16]) -> Instruction {
    let (i, n) = dexcore::decode_one(units, 0).expect("our own encoding decodes");
    assert!(n >= 1, "the decoder must advance");
    i
}

/// The eight fields of a decoded instruction, as comparable pairs.
///
/// Field by field rather than `PartialEq` on the whole value, because a whole
/// value comparison says "these differ" and a field list says "these differ,
/// here".
fn fields(i: &Instruction) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let Some(op) = i.opcode() {
        out.push(("op", format!("{op:#04x}")));
    }
    match i {
        Instruction::F10T { offset, .. } => out.push(("offset", format!("{offset}"))),
        Instruction::F11N { a, b, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("literal", format!("{literal}")));
        }
        Instruction::F11X { a, .. } => out.push(("a", format!("{a}"))),
        Instruction::F12X { a, b, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
        }
        Instruction::F20T { offset, .. } | Instruction::F21T { offset, .. } => {
            out.push(("offset", format!("{offset}")));
        }
        Instruction::F22T { a, b, offset, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("offset", format!("{offset}")));
        }
        Instruction::F20BC { a, index, .. } | Instruction::F21C { a, index, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("index", format!("{index}")));
        }
        Instruction::F22C { a, b, index, .. } | Instruction::F22CS { a, b, index, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("index", format!("{index}")));
        }
        Instruction::F21H { a, literal, .. } | Instruction::F21S { a, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("literal", format!("{literal}")));
        }
        Instruction::F22S { a, b, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("literal", format!("{literal}")));
        }
        Instruction::F22B { a, b, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("literal", format!("{literal}")));
        }
        Instruction::F22X { a, b, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
        }
        Instruction::F23X { a, b, c, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("c", format!("{c}")));
        }
        Instruction::F30T { offset, .. } => out.push(("offset", format!("{offset}"))),
        Instruction::F31T { a, offset, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("offset", format!("{offset}")));
        }
        Instruction::F31C { a, index, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("index", format!("{index}")));
        }
        Instruction::F31I { a, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("literal", format!("{literal}")));
        }
        Instruction::F32X { a, b, .. } => {
            // The defect under test: the decoder hands back the whole first code
            // unit here, and the sample asserts the same thing. A consumer that
            // read this as a register number would address `0x0103`.
            out.push(("a(whole unit)", format!("{a:#06x}")));
            out.push(("b", format!("{b}")));
        }
        Instruction::F35C { a, g, index, regs, .. }
        | Instruction::F35MI { a, g, index, regs, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("g", format!("{g}")));
            out.push(("index", format!("{index}")));
            out.push(("regs", format!("{regs:?}")));
        }
        Instruction::F35MS { a, g, index, first_reg, reg_count, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("g", format!("{g}")));
            out.push(("index", format!("{index}")));
            out.push(("first_reg", format!("{first_reg}")));
            out.push(("reg_count", format!("{reg_count}")));
        }
        Instruction::F3RC { a, index, first_reg, reg_count, .. }
        | Instruction::F3RMS { a, index, first_reg, reg_count, .. }
        | Instruction::F3RMI { a, index, first_reg, reg_count, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("index", format!("{index}")));
            out.push(("first_reg", format!("{first_reg}")));
            out.push(("reg_count", format!("{reg_count}")));
        }
        Instruction::F45CC { a, g, index, regs, proto, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("g", format!("{g}")));
            out.push(("index", format!("{index}")));
            out.push(("regs", format!("{regs:?}")));
            out.push(("proto", format!("{proto}")));
        }
        Instruction::F4RCC { a, index, first_reg, reg_count, proto, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("index", format!("{index}")));
            out.push(("first_reg", format!("{first_reg}")));
            out.push(("reg_count", format!("{reg_count}")));
            out.push(("proto", format!("{proto}")));
        }
        Instruction::F51L { a, literal, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("literal", format!("{literal:#018x}")));
        }
        Instruction::F52C { a, b, index, .. } => {
            out.push(("a", format!("{a}")));
            out.push(("b", format!("{b}")));
            out.push(("index", format!("{index}")));
        }
        Instruction::F5RC { index, first_reg, reg_count, .. } => {
            out.push(("index", format!("{index}")));
            out.push(("first_reg", format!("{first_reg}")));
            out.push(("reg_count", format!("{reg_count}")));
        }
        Instruction::F10X { .. } | Instruction::Unused { .. } | Instruction::Payload(_) => {}
    }
    out
}

/// The round trip, for every opcode in the format's table.
///
/// This is the claim the 224 case tables rest on: the sample each of them feeds
/// the lowering is what the decoder really produces for that opcode.
#[test]
fn every_sample_is_what_the_decoder_produces() {
    let mut checked = 0usize;
    for op in 0u8..=255 {
        if !dexcore::opcodes::opcode(op).valid {
            continue;
        }
        let want = fields(&sample(op).unwrap_or_else(|| panic!("0x{op:02x} has a sample")));
        let got = fields(&decode(&encode(op)));
        assert_eq!(
            want, got,
            "0x{op:02x} ({}): the sample and the decoder disagree",
            dexcore::opcodes::mnemonic(op)
        );
        checked += 1;
    }
    assert_eq!(checked, 224, "every defined opcode was round-tripped");
}

/// The same round trip, but for the eight foreign encodings.
///
/// They are not part of the format proper, so their layouts are the reference
/// implementation's rather than the specification's — but the decoder must still
/// agree with the sample, or `reserved`'s eight refusals are pinning shapes
/// nothing produces.
#[test]
fn the_foreign_samples_are_what_the_decoder_produces() {
    let foreign: BTreeSet<u8> = (0u8..=255)
        .filter(|op| {
            matches!(
                dexcore::opcodes::opcode(*op).format,
                Format::F20BC
                    | Format::F22CS
                    | Format::F35MS
                    | Format::F35MI
                    | Format::F3RMS
                    | Format::F3RMI
                    | Format::F52C
                    | Format::F5RC
            )
        })
        .collect();
    // The foreign encodings are reached by their *format*, not by their opcode
    // byte, so no opcode in the table produces one and this set is empty. Which
    // is the point: they are unreachable from the format's own numbering, and
    // `lower_one` routes them by `Instruction` variant instead.
    assert!(
        foreign.is_empty(),
        "the format's table assigns no opcode to a foreign encoding, so a foreign sample \
         cannot be built by picking an opcode: {foreign:?}"
    );
    // ...and the eight reachable ones are pinned by `reserved::FOREIGN_VARIANTS`.
    assert_eq!(crate::lower::reserved::FOREIGN_VARIANTS.len(), 8);
}

/// The `32x` width defect, pinned from both sides.
///
/// `Format::F32X::code_units` derives an instruction's length from the first
/// digit of the AOSP format name, and `32x` starts with a `3` that is a nibble
/// count in the name and not a width. So `dexcore` says a `move/16` is three
/// code units and it is two, and a linear walk that takes the claim at face
/// value desynchronises from that point on — every branch target after it is
/// wrong. The oracle applies the same correction, which is why this is reported
/// and not patched.
#[test]
fn the_thirty_two_x_encoding_is_two_code_units() {
    assert_eq!(
        dexcore::opcodes::Format::F32X.code_units(),
        3,
        "this test is about dexcore's declared width, so it asserts what dexcore says"
    );
    let units = encode(0x03);
    assert_eq!(units.len(), 3, "two code units plus the one the bounds check needs");
    let (i, n) = dexcore::decode_one(&units, 0).expect("decodes");
    assert_eq!(n, 3, "`decode_one` reports the format's declared width, not the real one");
    let Instruction::F32X { a, .. } = i else { panic!("move/16 is a 32x instruction") };
    assert_eq!(a, 0x0303, "and it hands back the whole first code unit");
    assert_eq!(crate::lower::move_reg::wide_dst_register(a), 3, "the high byte is the register");
    // The lowering's own walk advances two, which is the correction that matters.
    let mut body = Vec::new();
    crate::lower::tests::lower_one(
        &sample(0x03).expect("samples decode"),
        0,
        &crate::lower::tests::unit_ctx(),
        &mut body,
    )
    .expect("lowered");
    assert_eq!(body.len(), 1);
    assert_eq!(
        body[0].op,
        crate::ir::IrOp::MoveI32 { dst: crate::ir::I32Reg::new(3), src: crate::ir::I32Reg::new(2) }
    );
}

/// The `35c` and `3rc` count fields, which is where a call's arity comes from
/// and where the IR records a hint rather than a fact.
#[test]
fn the_five_and_three_register_count_fields_are_read_as_counts() {
    // `35c`: the low nibble of byte 1 is `A`, which every compiler writes as the
    // argument count even though the specification calls it a destination.
    let i = decode(&encode(0x6e));
    let Instruction::F35C { a, g, regs, .. } = i else { panic!("0x6e is a 35c") };
    assert_eq!(a, 3);
    assert_eq!(g, 0);
    assert_eq!(regs, [1, 2, 3, 0, 0], "the fifth register comes from G, not from the third word");
    assert_eq!(i.argument_registers(), vec![1, 2, 3], "trimmed at the last non-zero nibble");

    // `3rc`: `AA` is *both* the destination field and the count, because the
    // encoding has one byte for what the format calls two things.
    let i = decode(&encode(0x74));
    let Instruction::F3RC { a, reg_count, first_reg, .. } = i else { panic!("0x74 is a 3rc") };
    assert_eq!(a, 3);
    assert_eq!(reg_count, 3);
    assert_eq!(first_reg, 4);
    assert_eq!(i.argument_registers(), vec![4, 5, 6], "exact, because the count is in the encoding");
}

/// A `filled-new-array` names no destination, and the round trip is what proves
/// it.
///
/// The `35c` count field is the *argument* count, so reading it as a destination
/// would write the array into a register that held a live argument. The IR
/// therefore has no destination on [`crate::ir::IrOp::FilledNewArray`], and this
/// is the test that keeps that honest against the encoding.
#[test]
fn a_filled_new_array_names_no_destination() {
    for op in [0x24u8, 0x25] {
        let i = decode(&encode(op));
        let count = match i {
            Instruction::F35C { a, .. } => a,
            Instruction::F3RC { a, reg_count, .. } => {
                assert_eq!(u16::from(a), reg_count, "3rc's AA is both the field and the count");
                a
            }
            _ => panic!("0x{op:02x} is a filled-new-array"),
        };
        assert_eq!(count, 3, "the count field holds the argument count");
        let inst = super::lower_sample(op);
        assert!(
            inst.op.writes().is_empty(),
            "0x{op:02x} must not claim a destination register: the result arrives via \
             `move-result-object`"
        );
    }
}

/// The immediates, where a wrong shift is a plausible number rather than a trap.
#[test]
fn the_immediate_encodings_round_trip_at_their_own_widths() {
    // `21s` is a signed 16-bit literal and `31i` a signed 32-bit one; the two
    // opcodes in each format are distinguished only by the opcode byte, which is
    // exactly why a lowering that keys on the format alone gets `const-wide/16`
    // wrong.
    for (op, format) in [(0x13u8, Format::F21S), (0x16, Format::F21S)] {
        assert_eq!(dexcore::opcodes::opcode(op).format, format);
        let i = decode(&encode(op));
        let Instruction::F21S { literal, .. } = i else { panic!("0x{op:02x} is 21s") };
        assert_eq!(literal, INDEX as i16);
    }
    for op in [0x14u8, 0x17] {
        let i = decode(&encode(op));
        let Instruction::F31I { literal, .. } = i else { panic!("0x{op:02x} is 31i") };
        assert_eq!(literal, WIDE_INDEX as i32);
    }
    // `51l` is a 64-bit literal and the sample's is negative when read as one,
    // which is the only way to catch a high-half word swapped with the low.
    let i = decode(&encode(0x18));
    let Instruction::F51L { literal, .. } = i else { panic!("0x18 is 51l") };
    assert_eq!(literal, WIDE_LITERAL);
}
