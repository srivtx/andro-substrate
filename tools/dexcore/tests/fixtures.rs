//! Integration tests against real DEX and AXML files.
//!
//! These are the tests that matter most for the rest of andro-substrate: the
//! decoder has to agree byte-for-byte with what a production Android toolchain
//! emits, and the reader has to survive hostile input without panicking.
//!
//! Every "expected" value in this file was taken from
//! [androguard](https://github.com/androguard/androguard)'s disassembly of the
//! same fixture bytes, so these are genuine cross-implementation checks rather
//! than tests that restate this crate's own behaviour.

mod common;

use common::FIXTURES;
use dexcore::error::Error;
use dexcore::insn::Instruction;
use dexcore::model::map_type;
use dexcore::{decode_all, axml, DexReader};

/// Every fixture: `(fixture, reader)`.
fn open_all() -> Vec<(&'static common::Fixture, DexReader<'static>)> {
    FIXTURES
        .iter()
        .map(|f| (f, DexReader::open(f.dex).expect("fixture must open")))
        .collect()
}

// ---------------------------------------------------------------- header

#[test]
fn every_fixture_header_has_the_invariants_the_spec_demands() {
    for (f, dex) in open_all() {
        let h = dex.header();
        assert_eq!(h.header_size, 0x70, "{}: header_size", f.name);
        assert_eq!(h.endian_tag, 0x1234_5678, "{}: endian_tag", f.name);
        assert_eq!(&h.version, f.dex_version.as_bytes(), "{}: version", f.name);
        assert_eq!(h.file_size as usize, f.dex.len(), "{}: file_size", f.name);
        assert_eq!(h.file_size % 4, 0, "{}: file_size is 4-aligned", f.name);
        assert_eq!(h.data_off % 4, 0, "{}: data_off is 4-aligned", f.name);
        assert_eq!(h.map_off % 4, 0, "{}: map_off is 4-aligned", f.name);
        assert_ne!(h.map_off, 0, "{}: map_off is never zero", f.name);
        assert_eq!(h.link_size, 0, "{}: no link section", f.name);
        assert_eq!(h.link_off, 0, "{}: no link section", f.name);
        assert_eq!(
            h.data_off + h.data_size,
            h.file_size,
            "{}: data section runs to end of file",
            f.name
        );
        assert_eq!(h.data_size % 4, 0, "{}: data_size is 4-aligned", f.name);
    }
}

#[test]
fn every_fixture_passes_its_own_checksum_and_signature() {
    for (f, dex) in open_all() {
        // If either of these failed, a real Android tool would reject the file,
        // so this doubles as a check that our Adler-32 and SHA-1 agree with
        // whatever produced the fixture.
        dex.verify_integrity()
            .unwrap_or_else(|e| panic!("{}: integrity check failed: {e}", f.name));
    }
}

#[test]
fn header_round_trips_through_bytes() {
    for (f, dex) in open_all() {
        let h = dex.header();
        let bytes = h.to_bytes();
        assert_eq!(bytes[0..8], f.dex[0..8], "{}: magic and version", f.name);
        let reparsed = dexcore::DexHeader::parse(f.dex).unwrap();
        assert_eq!(reparsed, *h, "{}: header round-trips", f.name);
        assert_eq!(reparsed.to_bytes(), bytes, "{}: serialised header", f.name);
    }
}

#[test]
fn a_mutated_byte_is_caught_by_the_integrity_check() {
    let (f, _dex) = open_all().into_iter().next().unwrap();
    let mut bytes = f.dex.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let reader = DexReader::open(&bytes).unwrap();
    assert!(
        matches!(reader.verify_integrity(), Err(Error::ChecksumMismatch { .. })),
        "{}: a flipped byte must be detected",
        f.name
    );
}

// -------------------------------------------------------------- map list

#[test]
fn every_map_list_is_ordered_by_offset_and_never_overlaps() {
    for (f, dex) in open_all() {
        let map = dex.map_list().unwrap();
        assert!(!map.is_empty(), "{}: map_list is never empty", f.name);
        assert_eq!(map[0].item_type, map_type::HEADER_ITEM);
        assert_eq!(map[0].offset, 0);
        assert_eq!(map.last().unwrap().item_type, map_type::MAP_LIST);
        assert_eq!(map.last().unwrap().offset, dex.header().map_off);

        let mut prev_end = 0u32;
        for entry in &map {
            assert!(entry.unused == 0, "{}: map_item.unused must be zero", f.name);
            assert!(entry.size > 0, "{}: zero-size map entries are omitted", f.name);
            assert!(
                entry.offset >= prev_end,
                "{}: map entry 0x{:04x} at {} overlaps or precedes the previous end {prev_end}",
                f.name,
                entry.item_type,
                entry.offset
            );
            assert!(
                (entry.offset as usize) < f.dex.len(),
                "{}: map entry 0x{:04x} points past the file",
                f.name,
                entry.item_type
            );
            prev_end = entry.offset;
        }
    }
}

#[test]
fn every_map_entry_names_a_known_type() {
    for (f, dex) in open_all() {
        for entry in dex.map_list().unwrap() {
            assert_ne!(
                map_type::name(entry.item_type),
                "unknown",
                "{}: map_list names unrecognised type 0x{:04x}",
                f.name,
                entry.item_type
            );
        }
    }
}

#[test]
fn map_agrees_with_the_header_section_pointers() {
    for (f, dex) in open_all() {
        let map = dex.map_list().unwrap();
        let find = |t: u16| map.iter().find(|e| e.item_type == t).copied();
        let h = dex.header();
        // Every section the header declares must also appear in the map, with
        // the same offset and count.
        for (item_type, size, off) in [
            (map_type::STRING_ID_ITEM, h.string_ids_size, h.string_ids_off),
            (map_type::TYPE_ID_ITEM, h.type_ids_size, h.type_ids_off),
            (map_type::PROTO_ID_ITEM, h.proto_ids_size, h.proto_ids_off),
            (map_type::FIELD_ID_ITEM, h.field_ids_size, h.field_ids_off),
            (map_type::METHOD_ID_ITEM, h.method_ids_size, h.method_ids_off),
            (map_type::CLASS_DEF_ITEM, h.class_defs_size, h.class_defs_off),
        ] {
            if size == 0 {
                assert!(find(item_type).is_none(), "{}: empty section must be absent from map", f.name);
                continue;
            }
            let e = find(item_type).unwrap_or_else(|| {
                panic!("{}: header declares a {} the map omits", f.name, map_type::name(item_type))
            });
            assert_eq!((e.size, e.offset), (size, off), "{}: {}", f.name, map_type::name(item_type));
        }
    }
}

// ----------------------------------------------------------------- pools

#[test]
fn pools_are_sorted_as_the_specification_requires() {
    for (f, dex) in open_all() {
        // string_ids: sorted by the UTF-16 code point values of the contents.
        let strings = dex.strings().unwrap();
        for w in strings.windows(2) {
            let key = |s: &dexcore::DexString| s.value.encode_utf16().collect::<Vec<_>>();
            assert!(
                key(&w[0]) < key(&w[1]),
                "{}: string_ids out of order: {:?} then {:?}",
                f.name,
                w[0].value,
                w[1].value
            );
        }

        // type_ids: sorted by string_id index.
        let types = dex.types().unwrap();
        let by_index: Vec<u32> = (0..types.len() as u32)
            .map(|i| types[i as usize].descriptor_idx)
            .collect();
        assert!(by_index.windows(2).all(|w| w[0] < w[1]), "{}: type_ids out of order", f.name);

        // field_ids: (class, name, type).
        let mut prev = None;
        for i in 0..dex.field_count() {
            let fd = dex.field_at(i).unwrap();
            let key = (fd.class_idx, fd.name_idx, fd.type_idx);
            if let Some(p) = prev {
                assert!(p < key, "{}: field_ids out of order at {i}", f.name);
            }
            prev = Some(key);
        }

        // method_ids: (class, name, proto).
        let mut prev = None;
        for i in 0..dex.method_count() {
            let m = dex.method_at(i).unwrap();
            let key = (m.class_idx, m.name_idx, m.proto_idx);
            if let Some(p) = prev {
                assert!(p < key, "{}: method_ids out of order at {i}", f.name);
            }
            prev = Some(key);
        }
    }
}

#[test]
fn every_string_round_trips_through_mutf8_exactly() {
    for (f, dex) in open_all() {
        for s in dex.strings().unwrap() {
            // utf16_size counts UTF-16 code units, not bytes and not characters.
            assert_eq!(s.utf16_size as usize, s.value.encode_utf16().count(), "{}", f.name);
            // Re-encoding the decoded value must reproduce the stored bytes
            // exactly, which is only true if the codec is MUTF-8 and not UTF-8:
            // U+0000 would come back as a bare zero, and an astral character
            // would come back as a four-byte sequence.
            let stored = &f.dex[s.string_data_off as usize..];
            let hdr = mutf8_prefix_len(stored);
            let want = dexcore::mutf8::encode(&s.value);
            assert_eq!(
                &stored[hdr..hdr + want.len()],
                &want[..],
                "{}: string {:?} does not round-trip through MUTF-8",
                f.name,
                s.value
            );
            // `encode` already appends the terminator, so its last byte is the
            // NUL that ends the string_data_item.
            assert_eq!(*want.last().unwrap(), 0, "{}: MUTF-8 strings end in NUL", f.name);
        }
    }
}

fn mutf8_prefix_len(b: &[u8]) -> usize {
    let mut i = 0;
    while b[i] & 0x80 != 0 {
        i += 1;
    }
    i + 1
}

#[test]
fn protos_resolve_to_signatures() {
    for (f, dex) in open_all() {
        for p in dex.protos().unwrap() {
            let sig = p.signature();
            assert!(sig.starts_with('('), "{}: bad proto {sig}", f.name);
            assert_eq!(
                sig[1..sig.len() - 1].len(),
                p.parameters.iter().map(|t| t.len()).sum::<usize>() + p.return_type.len(),
                "{}: proto signature {sig} does not match its type list",
                f.name
            );
            assert_eq!(p.shorty.len(), p.parameters.len() + 1, "{}: shorty width", f.name);
            assert!(
                !p.parameters.iter().any(|t| t == "V"),
                "{}: a type_list must never contain void",
                f.name
            );
        }
    }
}

#[test]
fn classes_and_their_superclasses_resolve() {
    for (f, dex) in open_all() {
        let classes = dex.classes().unwrap();
        assert_eq!(classes.len() as u32, dex.class_def_count(), "{}: class count", f.name);
        // A class_def must never precede its own superclass in the same file.
        let mut seen_descriptors = std::collections::HashSet::new();
        for c in &classes {
            if !c.superclass.is_empty() {
                if let Some(parent) = classes.iter().find(|p| p.descriptor == c.superclass) {
                    assert!(
                        parent.index < c.index,
                        "{}: {} precedes its superclass {}",
                        f.name,
                        c.descriptor,
                        c.superclass
                    );
                }
            }
            for i in &c.interfaces {
                if let Some(iface) = classes.iter().find(|p| p.descriptor == *i) {
                    assert!(iface.index < c.index, "{}: {} precedes its interface", f.name, c.descriptor);
                }
            }
            // Method and field lists are sorted by increasing pool index.
            for list in [&c.class_data.as_ref().map(|d| &d.direct_methods[..]), &c.class_data.as_ref().map(|d| &d.virtual_methods[..])]
                .into_iter()
                .flatten()
            {
                assert!(
                    list.windows(2).all(|w| w[0].method_idx < w[1].method_idx),
                    "{}: {} methods are not sorted by method_idx",
                    f.name,
                    c.descriptor
                );
            }
            seen_descriptors.insert(c.descriptor.clone());
        }
    }
}

// ------------------------------------------------------------ instructions

/// Ground truth from androguard's disassembly of the same bytes.
#[test]
fn decodes_a_known_method_exactly() {
    let f = FIXTURES.iter().find(|f| f.name == "fr.smarquis.sleeptimer_16200").unwrap();
    let dex = DexReader::open(f.dex).unwrap();
    let idx = dex.find_class("La;").unwrap().unwrap();
    let class = dex.class_def(idx).unwrap();
    let data = class.class_data.unwrap();

    // La;->hasNext ()Z
    let has_next = data
        .virtual_methods
        .iter()
        .find(|m| dex.method_at(m.method_idx).unwrap().name == "hasNext")
        .copied()
        .expect("La;->hasNext must be present");
    let info = dex.method_at(has_next.method_idx).unwrap();
    assert_eq!(info.name, "hasNext");
    assert_eq!(info.signature(), "La;.hasNext()Z");
    assert_eq!(info.class, "La;");

    let code = dex.code_item(has_next.code_off).unwrap();
    assert_eq!(code.registers_size, 2);
    assert_eq!(code.ins_size, 1);
    assert_eq!(code.outs_size, 1);
    assert_eq!(code.insns_size, 14);

    let units: Vec<u16> = code_raw(f.dex, &code).chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    assert_eq!(
        units.iter().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>(),
        vec![
            0x52, 0x10, 0x00, 0x00, 0x54, 0x11, 0x01, 0x00, 0x6e, 0x10, 0x5f, 0x00, 0x01, 0x00,
            0x0a, 0x01, 0x35, 0x10, 0x04, 0x00, 0x12, 0x11, 0x0f, 0x01, 0x12, 0x01, 0x0f, 0x01,
        ],
        "the fixture bytes themselves must match what was recorded"
    );

    let all = decode_all(&units).unwrap();
    assert_eq!(all.len(), 9);
    assert_eq!(
        all.iter().map(|l| l.instruction.mnemonic()).collect::<Vec<_>>(),
        vec![
            "iget", "iget-object", "invoke-virtual", "move-result", "if-ge", "const/4", "return",
            "const/4", "return",
        ]
    );
    // Offsets must tile the stream exactly, with no gaps.
    assert_eq!(
        all.iter().map(|l| l.unit_offset).collect::<Vec<_>>(),
        vec![0, 2, 4, 7, 8, 10, 11, 12, 13]
    );

    // Operand-by-operand, against androguard's rendering:
    //   iget v0, v1, La;->a I
    assert_eq!(
        all[0].instruction,
        Instruction::F22C { op: 0x52, a: 0, b: 1, index: 0 }
    );
    //   iget-object v1, v1, La;->b Ld;
    assert_eq!(
        all[1].instruction,
        Instruction::F22C { op: 0x54, a: 1, b: 1, index: 1 }
    );
    //   invoke-virtual v1, Ld;->a()I
    assert_eq!(
        all[2].instruction,
        Instruction::F35C { op: 0x6e, a: 1, g: 0, index: 95, regs: [1, 0, 0, 0, 0] }
    );
    assert_eq!(all[2].instruction.index_operand(), Some(95));
    //   move-result v1
    assert_eq!(all[3].instruction, Instruction::F11X { op: 0x0a, a: 1 });
    //   if-ge v0, v1, +0004
    assert_eq!(
        all[4].instruction,
        Instruction::F22T { op: 0x35, a: 0, b: 1, offset: 4 }
    );
    //   const/4 v1, 1
    assert_eq!(all[5].instruction, Instruction::F11N { op: 0x12, a: 1, b: 1, literal: 1 });
    //   return v1
    assert_eq!(all[6].instruction, Instruction::F11X { op: 0x0f, a: 1 });
    //   const/4 v1, 0
    assert_eq!(all[7].instruction, Instruction::F11N { op: 0x12, a: 1, b: 0, literal: 0 });
    assert_eq!(all[8].instruction, Instruction::F11X { op: 0x0f, a: 1 });
}

#[test]
fn decodes_a_method_with_a_throw_and_a_32_bit_literal() {
    let f = FIXTURES.iter().find(|f| f.name == "fr.smarquis.sleeptimer_16200").unwrap();
    let dex = DexReader::open(f.dex).unwrap();
    let class = dex.class_def(dex.find_class("La;").unwrap().unwrap()).unwrap();
    let data = class.class_data.unwrap();

    // La;->remove ()V
    let rm = data.virtual_methods.iter().find(|m| {
        dex.method_at(m.method_idx).unwrap().name == "remove"
    }).copied().unwrap();
    let code = dex.code_item(rm.code_off).unwrap();
    let units = to_units(code_raw(f.dex, &code));
    let all = decode_all(&units).unwrap();

    assert_eq!(
        all.iter().map(|l| l.instruction.mnemonic()).collect::<Vec<_>>(),
        vec!["new-instance", "const-string", "invoke-direct", "throw"]
    );
    assert_eq!(all[3].instruction, Instruction::F11X { op: 0x27, a: 1 });

    // `const-string v0, "Operation is not supported for read-only collection"`
    match all[1].instruction {
        Instruction::F21C { op: 0x1a, a, index } => {
            assert_eq!(a, 0);
            assert_eq!(
                dex.string(index as u32).unwrap().value,
                "Operation is not supported for read-only collection"
            );
        }
        ref other => panic!("expected const-string, got {other:?}"),
    }
    // `new-instance v1, UnsupportedOperationException`
    match all[0].instruction {
        Instruction::F21C { op: 0x22, a, index } => {
            assert_eq!(a, 1);
            assert_eq!(dex.type_name(index as u32).unwrap(), "Ljava/lang/UnsupportedOperationException;");
        }
        ref other => panic!("expected new-instance, got {other:?}"),
    }
}

#[test]
fn decodes_an_8_bit_literal_and_an_interface_call() {
    let f = FIXTURES.iter().find(|f| f.name == "fr.smarquis.sleeptimer_16200").unwrap();
    let dex = DexReader::open(f.dex).unwrap();
    let class = dex.class_def(dex.find_class("La;").unwrap().unwrap()).unwrap();
    let data = class.class_data.unwrap();
    let nx = data.virtual_methods.iter().find(|m| {
        dex.method_at(m.method_idx).unwrap().name == "next"
    }).copied().unwrap();
    let code = dex.code_item(nx.code_off).unwrap();
    let all = decode_all(&to_units(code_raw(f.dex, &code))).unwrap();

    // Index by mnemonic rather than by a hard-coded position, so the
    // assertions stay meaningful if the fixture is ever re-extracted.
    let at = |m: &str| {
        all.iter().find(|l| l.instruction.mnemonic() == m).unwrap_or_else(|| {
            panic!("expected a {m} in the method")
        })
    };
    //   add-int/lit8 v1, v0, 1
    assert_eq!(
        at("add-int/lit8").instruction,
        Instruction::F22B { op: 0xd8, a: 1, b: 0, literal: 1 }
    );
    //   iput v1, v2, La;->a I
    assert_eq!(
        at("iput").instruction,
        Instruction::F22C { op: 0x59, a: 1, b: 2, index: 0 }
    );
    //   invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;
    let iface_call = all
        .iter()
        .find(|l| l.instruction.mnemonic() == "invoke-interface")
        .unwrap();
    match iface_call.instruction {
        Instruction::F35C { op, a, index, regs, .. } => {
            assert_eq!(op, 0x72, "invoke-interface");
            assert_eq!(a, 2, "A is the argument count d8 writes");
            assert_eq!(&regs[..2], &[2, 0]);
            assert_eq!(dex.method_at(index as u32).unwrap().signature(), "Ljava/util/List;.get(I)Ljava/lang/Object;");
        }
        ref other => panic!("expected invoke-interface, got {other:?}"),
    }
    //   if-eqz v0, +000f
    assert_eq!(
        at("if-eqz").instruction,
        Instruction::F21T { op: 0x38, a: 0, offset: 0x0f }
    );
}

/// Walk every instruction of every method in every fixture and assert that the
/// decoded stream tiles each `code_item` exactly.
///
/// This is the strongest single property a linear instruction walker can have,
/// and it is what would break first if any opcode's width were wrong.
#[test]
fn every_method_in_every_fixture_decodes_to_an_exact_tiling() {
    let mut methods = 0usize;
    let mut instructions = 0usize;
    for (f, dex) in open_all() {
        for ci in 0..dex.class_def_count() {
            let class = dex.class_def(ci).unwrap();
            let data = match class.class_data {
                Some(d) => d,
                None => continue,
            };
            for m in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
                if m.code_off == 0 {
                    continue;
                }
                let code = dex.code_item(m.code_off).unwrap();
                let units = to_units(code_raw(f.dex, &code));
                assert_eq!(
                    units.len() as u32,
                    code.insns_size,
                    "{}: insns_size disagrees with the slice length",
                    f.name
                );
                let all = decode_all(&units).unwrap_or_else(|e| {
                    panic!(
                        "{}: {} failed to decode: {e}",
                        f.name,
                        dex.method_at(m.method_idx).unwrap().signature()
                    )
                });
                // Offsets strictly increase, start at 0, and the widths sum to
                // exactly insns_size.
                let mut total = 0u32;
                for (i, l) in all.iter().enumerate() {
                    assert_eq!(l.unit_offset, total, "{}: gap or overlap at instruction {i}", f.name);
                    total += l.instruction.width() as u32 / 2;
                }
                assert_eq!(total, code.insns_size, "{}: stream does not end exactly", f.name);
                methods += 1;
                instructions += all.len();
            }
        }
    }
    assert!(methods > 100, "expected a meaningful number of methods, got {methods}");
    assert!(instructions > 1000, "expected a meaningful number of instructions, got {instructions}");
}

#[test]
fn every_decoded_operand_register_is_inside_the_frame() {
    for (f, dex) in open_all() {
        for ci in 0..dex.class_def_count() {
            let class = dex.class_def(ci).unwrap();
            let data = match class.class_data {
                Some(d) => d,
                None => continue,
            };
            for m in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
                if m.code_off == 0 {
                    continue;
                }
                let code = dex.code_item(m.code_off).unwrap();
                let regs = code.registers_size as u32;
                for l in decode_all(&to_units(code_raw(f.dex, &code))).unwrap() {
                    for r in registers_of(&l.instruction) {
                        assert!(
                            r < regs,
                            "{}: instruction {} names v{r} but registers_size is {regs}",
                            f.name,
                            l.instruction.mnemonic()
                        );
                    }
                }
            }
        }
    }
}

/// Every register operand of an instruction, for frame checking.
///
/// Only the formats whose register operands are unambiguous are listed: the
/// packed `35c` nibbles and the invoke ranges are checked separately, because
/// their arity comes from the target method's prototype rather than from the
/// instruction.
fn registers_of(i: &Instruction) -> Vec<u32> {
    use Instruction::*;
    match i {
        // In `11n` the `b` field is the literal nibble, not a register.
        F11N { a, .. } => vec![*a as u32],
        F12X { a, b, .. } | F22B { a, b, .. } | F22C { a, b, .. }
        | F22S { a, b, .. } | F22T { a, b, .. } => vec![*a as u32, *b as u32],
        F23X { a, b, c, .. } => vec![*a as u32, *b as u32, *c as u32],
        F11X { a, .. } | F21C { a, .. } | F21H { a, .. } | F21S { a, .. } | F21T { a, .. }
        | F22X { a, .. } | F31C { a, .. } | F31I { a, .. } | F31T { a, .. } | F51L { a, .. } => {
            vec![*a as u32]
        }
        F32X { a, b, .. } => vec![*a as u32, *b as u32],
        _ => Vec::new(),
    }
}

fn to_units(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

fn code_raw<'a>(dex: &'a [u8], code: &dexcore::CodeItem) -> &'a [u8] {
    &dex[code.insns_off as usize..(code.insns_off + code.insns_size * 2) as usize]
}

// ------------------------------------------------------------------- AXML

#[test]
fn every_manifest_parses_into_a_tree_with_the_expected_root() {
    for f in FIXTURES {
        let doc = axml::parse(f.axml).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(doc.root.name, "manifest", "{}: root element", f.name);
        assert!(
            doc.package_name().is_some(),
            "{}: manifest must carry a package attribute",
            f.name
        );
        assert!(
            doc.namespaces.iter().any(|(p, u)| p == "android" && u == "http://schemas.android.com/apk/res/android"),
            "{}: the android namespace must be declared",
            f.name
        );
        // A well-formed manifest always has application, and usually
        // uses-sdk, and this corpus always has a launcher activity.
        assert!(!doc.find_all("application").is_empty(), "{}: application", f.name);
        assert!(!doc.find_all("uses-sdk").is_empty(), "{}: uses-sdk", f.name);
    }
}

#[test]
fn a_manifest_yields_the_expected_element_names_and_attributes() {
    // Every expectation below is the literal content of the fixture, cross-checked
    // against androguard's AXMLPrinter rendering of the same bytes.
    let f = FIXTURES.iter().find(|f| f.name == "com.android.adbkeyboard_2").unwrap();
    let doc = axml::parse(f.axml).unwrap();

    assert_eq!(doc.root.name, "manifest");
    assert_eq!(doc.package_name().as_deref(), Some("com.android.adbkeyboard"));
    // The package attribute carries no namespace prefix; the framework ones do.
    assert_eq!(doc.root.attribute_value("package").as_deref(), Some("com.android.adbkeyboard"));
    assert_eq!(doc.root.attribute_value("android:versionCode").as_deref(), Some("2"));
    assert_eq!(doc.root.attribute_value("android:versionName").as_deref(), Some("2.0"));
    assert_eq!(doc.root.attribute_value("android:compileSdkVersion").as_deref(), Some("29"));
    assert_eq!(doc.root.attribute_value("android:compileSdkVersionCodename").as_deref(), Some("10"));
    assert!(doc.root.attribute("platformBuildVersionName").is_some());
    // The `package` attribute has no namespace, so it is unprefixed.
    assert_eq!(doc.root.attribute("package").unwrap().resource_id, None);

    let sdk = &doc.find_all("uses-sdk")[0];
    assert_eq!(sdk.attribute_value("android:minSdkVersion").as_deref(), Some("15"));
    assert_eq!(sdk.attribute_value("android:targetSdkVersion").as_deref(), Some("29"));

    let app = &doc.find_all("application")[0];
    // A resource reference decodes to Reference, not to a string, so asking for
    // the text gives the canonical "@7f030000" form.
    assert_eq!(app.attribute_value("android:label").as_deref(), Some("@7f030000"));
    assert_eq!(app.attribute_value("android:icon").as_deref(), Some("@7f010000"));
    // AAPT2 stores booleans as 0xFFFFFFFF for true and 0x00000000 for false,
    // both under TYPE_INT_BOOLEAN (0x12). This one is 0xFFFFFFFF, i.e. true.
    assert_eq!(app.attribute_value("android:allowBackup").as_deref(), Some("1"));
    assert_eq!(
        app.attribute("android:allowBackup").unwrap().value,
        dexcore::axml::AttributeValue::Int(1)
    );
    assert!(matches!(app.attribute("android:icon").unwrap().value, dexcore::axml::AttributeValue::Reference(0x7f01_0000)));

    // This APK declares an input-method service, not an activity.
    assert_eq!(app.children_named("activity").count(), 0);
    let service = &app.children_named("service").next().unwrap();
    assert_eq!(service.attribute_value("android:name").as_deref(), Some("com.android.adbkeyboard.AdbIME"));
    assert_eq!(service.attribute_value("android:permission").as_deref(), Some("android.permission.BIND_INPUT_METHOD"));

    // Nesting: intent-filter is a child of the service, and action a child of
    // the filter.
    let filters = service.find_all("intent-filter");
    assert_eq!(filters.len(), 1);
    assert_eq!(
        filters[0].find_all("action")[0].attribute_value("android:name").as_deref(),
        Some("android.view.InputMethod")
    );
    let meta = &service.find_all("meta-data")[0];
    assert_eq!(meta.attribute_value("android:name").as_deref(), Some("android.view.im"));
    assert_eq!(meta.attribute_value("android:resource").as_deref(), Some("@7f050000"));
}

#[test]
fn manifests_with_deeper_nesting_parse_completely() {
    // com.termux.boot has uses-permission elements, a receiver, a service and a
    // provider, so it exercises more of the tree than the shallow fixture does.
    let f = FIXTURES.iter().find(|f| f.name == "com.termux.boot_1000").unwrap();
    let doc = axml::parse(f.axml).unwrap();
    assert_eq!(doc.package_name().as_deref(), Some("com.termux.boot"));
    assert_eq!(doc.root.attribute_value("android:sharedUserId").as_deref(), Some("com.termux"));

    let perms: Vec<String> = doc
        .find_all("uses-permission")
        .iter()
        .map(|p| p.attribute_value("android:name").unwrap_or_default())
        .collect();
    assert!(perms.iter().any(|p| p == "android.permission.RECEIVE_BOOT_COMPLETED"), "{perms:?}");
    assert!(perms.iter().any(|p| p == "android.permission.WAKE_LOCK"), "{perms:?}");

    let app = &doc.find_all("application")[0];
    let activity = &app.children_named("activity").next().unwrap();
    assert_eq!(activity.attribute_value("android:name").as_deref(), Some("com.termux.boot.BootActivity"));
    let filter = &activity.find_all("intent-filter")[0];
    assert_eq!(filter.find_all("action")[0].attribute_value("android:name").as_deref(), Some("android.intent.action.MAIN"));
    assert_eq!(filter.find_all("category")[0].attribute_value("android:name").as_deref(), Some("android.intent.category.LAUNCHER"));
    assert!(app.children_named("receiver").count() >= 1);
    assert!(app.children_named("service").count() >= 1);
    // A false boolean is a distinct value from a true one.
    let recv = &app.children_named("receiver").next().unwrap();
    assert_eq!(recv.attribute_value("android:exported").as_deref(), Some("0"));
}

#[test]
fn a_float_attribute_decodes_from_its_bit_pattern() {
    // android:platformBuildVersionName is stored as a float by aapt2, which is
    // why androguard renders it as "2.000000".
    let f = FIXTURES.iter().find(|f| f.name == "com.android.adbkeyboard_2").unwrap();
    let doc = axml::parse(f.axml).unwrap();
    // This attribute is not in the android namespace, so it is unprefixed.
    let v = &doc.root.attribute("platformBuildVersionName").unwrap().value;
    assert!(matches!(v, dexcore::axml::AttributeValue::Float(_)), "got {v:?}");
    assert_eq!(v.as_text().unwrap(), "2");
}

#[test]
fn framework_resource_ids_survive_the_resource_map() {
    let f = FIXTURES.iter().find(|f| f.name == "com.android.adbkeyboard_2").unwrap();
    let doc = axml::parse(f.axml).unwrap();

    // The resource map is a parallel array over the string pool, so the id for
    // an attribute is looked up by that attribute's *name* index.
    let name_idx = doc.strings.strings.iter().position(|s| s == "versionCode").unwrap();
    assert_eq!(doc.strings.resource_ids[name_idx], 0x0101_021b, "android.R.attr.versionCode");
    let attr = doc.root.attribute("android:versionCode").expect("must be present");
    assert_eq!(attr.resource_id, Some(0x0101_021b));
    assert_eq!(attr.value, dexcore::axml::AttributeValue::Int(2));

    // A well-known set of framework ids, to catch an off-by-one in the map.
    for (name, id) in [
        ("label", 0x0101_0001u32),
        ("icon", 0x0101_0002),
        ("name", 0x0101_0003),
        ("permission", 0x0101_0006),
        ("minSdkVersion", 0x0101_020c),
        ("versionCode", 0x0101_021b),
        ("targetSdkVersion", 0x0101_0270),
        ("allowBackup", 0x0101_0280),
    ] {
        let i = doc.strings.strings.iter().position(|s| s == name).unwrap();
        assert_eq!(doc.strings.resource_ids[i], id, "android.R.attr.{name}");
    }
    // The map covers only the framework attribute names, so ordinary strings
    // have no id.
    let pkg = doc.strings.strings.iter().position(|s| s == "package").unwrap();
    assert!(pkg >= doc.strings.resource_ids.len());
}

#[test]
fn axml_rejects_truncated_and_corrupt_input() {
    let f = FIXTURES.iter().find(|f| f.name == "com.termux.boot_1000").unwrap();
    // Truncation at many lengths must always produce a typed error, never a
    // panic and never a hang.
    for cut in [0, 1, 4, 7, 8, 16, 32, 64, 128, 512, 1024, 2000, 3000, f.axml.len() - 1] {
        let r = axml::parse(&f.axml[..cut.min(f.axml.len())]);
        assert!(r.is_err(), "truncating to {cut} bytes should fail, not parse");
    }
    // Corrupting the root chunk type must be rejected too.
    let mut bad = f.axml.to_vec();
    bad[0] = 0x00;
    bad[1] = 0x00;
    assert!(matches!(axml::parse(&bad), Err(Error::BadAxmlMagic { .. })));
    // A chunk claiming an enormous size must be rejected.
    let mut bad = f.axml.to_vec();
    bad[4..8].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    assert!(matches!(axml::parse(&bad), Err(Error::BadChunkSize { .. })));
}

// -------------------------------------------------------------- negative

#[test]
fn a_truncated_dex_is_a_typed_error_not_a_panic() {
    let (f, _) = open_all().into_iter().next().unwrap();
    for cut in [0, 1, 8, 32, 64, 111, 112, 200, 700, 1500, f.dex.len() - 1] {
        let n = cut.min(f.dex.len());
        match DexReader::open(&f.dex[..n]) {
            Ok(_) => panic!("truncating {} to {n} bytes should not parse", f.name),
            Err(e) => {
                // Every failure has to be one of the typed variants; the point is
                // that it is a value, not a panic and not a zeroed result.
                let kind = e.kind();
                assert!(!kind.is_empty());
                assert!(
                    matches!(kind, "truncated" | "bad_magic" | "section_out_of_range" | "index_out_of_range"),
                    "{}: unexpected error kind {kind} at {n} bytes: {e}",
                    f.name
                );
            }
        }
    }
}

#[test]
fn a_dex_with_a_corrupt_magic_is_rejected() {
    let (f, _) = open_all().into_iter().next().unwrap();
    // Each must be 8 bytes, so that the terminating NUL is replaced too;
    // a 7-byte prefix would leave a perfectly valid magic behind.
    let bad_magics: [&[u8]; 4] = [b"xxxxxxx", b"DEX\n035\0", b"dex\n037X", b"zip\n035\0"];
    for bad_magic in bad_magics {
        let mut bytes = f.dex.to_vec();
        let n = bad_magic.len().min(bytes.len());
        bytes[..n].copy_from_slice(&bad_magic[..n]);
        assert!(
            matches!(DexReader::open(&bytes), Err(Error::BadMagic { .. })),
            "magic {bad_magic:?} must be rejected"
        );
    }
}

#[test]
fn a_dex_with_absurd_section_sizes_is_rejected_without_allocating() {
    let (f, _) = open_all().into_iter().next().unwrap();
    for (offset, value, label) in [
        (56usize, u32::MAX, "string_ids_size"),
        (64, u32::MAX, "type_ids_size"),
        (72, u32::MAX, "proto_ids_size"),
        (80, u32::MAX, "field_ids_size"),
        (88, u32::MAX, "method_ids_size"),
        (96, u32::MAX, "class_defs_size"),
        (32, u32::MAX, "file_size"),
    ] {
        let mut bytes = f.dex.to_vec();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let r = DexReader::open(&bytes);
        assert!(r.is_err(), "{label} = u32::MAX must be rejected");
        // And the reader must not have tried to allocate for it.
        if let Ok(reader) = r {
            let _ = reader.strings();
        }
    }
}

#[test]
fn a_dex_with_a_zero_offset_for_a_non_empty_section_is_rejected() {
    let (f, _) = open_all().into_iter().next().unwrap();
    let mut bytes = f.dex.to_vec();
    bytes[60..64].copy_from_slice(&0u32.to_le_bytes()); // string_ids_off = 0
    assert!(matches!(DexReader::open(&bytes), Err(Error::MissingSection("string_ids"))));
}

#[test]
fn out_of_range_pool_indices_are_typed_errors() {
    let f = FIXTURES.iter().find(|f| f.name == "org.vi_server.red_screen_3").unwrap();
    let dex = DexReader::open(f.dex).unwrap();
    let n = dex.string_count();
    assert!(matches!(dex.string(n), Err(Error::IndexOutOfRange { pool: "string_ids", .. })));
    assert!(matches!(dex.type_at(u32::MAX), Err(Error::IndexOutOfRange { pool: "type_ids", .. })));
    assert!(matches!(dex.method_at(u32::MAX), Err(Error::IndexOutOfRange { pool: "method_ids", .. })));
    assert!(matches!(dex.field_at(u32::MAX), Err(Error::IndexOutOfRange { pool: "field_ids", .. })));
    assert!(matches!(dex.class_def(u32::MAX), Err(Error::IndexOutOfRange { pool: "class_defs", .. })));
}

#[test]
fn a_wrong_endian_tag_is_rejected() {
    let (f, _) = open_all().into_iter().next().unwrap();
    let mut bytes = f.dex.to_vec();
    bytes[40..44].copy_from_slice(&0x7856_3412u32.to_le_bytes());
    assert!(matches!(DexReader::open(&bytes), Err(Error::BadEndianTag(_))));
}

#[test]
fn a_wrong_header_size_is_rejected() {
    let (f, _) = open_all().into_iter().next().unwrap();
    let mut bytes = f.dex.to_vec();
    bytes[36..40].copy_from_slice(&0x60u32.to_le_bytes());
    assert!(matches!(DexReader::open(&bytes), Err(Error::BadHeaderSize(0x60))));
}

#[test]
fn random_bytes_are_rejected_rather_than_misparsed() {
    // Deterministic pseudo-random input, so a failure is reproducible.
    let mut state = 0x1234_5678u32;
    let mut next = || {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        (state >> 16) as u8
    };
    for len in [0usize, 1, 7, 16, 112, 113, 512, 4096] {
        let bytes: Vec<u8> = (0..len).map(|_| next()).collect();
        // Whatever happens, it must be a value, never a panic.
        let _ = DexReader::open(&bytes);
        let _ = axml::parse(&bytes);
        let _ = dexcore::decode_all(
            &bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn mutf8_rejects_malformed_sequences() {
    use dexcore::mutf8;
    // A 4-byte UTF-8 sequence is legal UTF-8 but illegal MUTF-8.
    assert!(matches!(mutf8::decode(&[0xf0, 0x9f, 0x98, 0x80, 0]), Err(Error::BadMutf8 { .. })));
    // A 3-byte overlong form of ASCII.
    assert!(matches!(mutf8::decode(&[0xe0, 0x81, 0x81, 0]), Err(Error::BadMutf8 { .. })));
    // Truncated sequences at every offset.
    for b in [0xc2u8, 0xe0, 0xed] {
        assert!(mutf8::decode(&[b]).is_err());
        assert!(mutf8::decode(&[b, 0x80]).is_err() || b == 0xc2);
    }
    // No terminator.
    assert!(mutf8::decode(b"abc").is_err());
    // Valid input still round-trips.
    let (s, n) = mutf8::decode(&mutf8::encode("caf\u{e9} \u{1f600}")).unwrap();
    assert_eq!(s, "caf\u{e9} \u{1f600}");
    assert_eq!(n, mutf8::encode("caf\u{e9} \u{1f600}").len() - 1);
}
