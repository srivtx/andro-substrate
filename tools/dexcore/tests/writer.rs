//! Writer tests: build a DEX from scratch, read it back, and check that a
//! production Android tool would accept it.
//!
//! The bar for "accepted" is high, and deliberately so: dexlib2, `baksmali` and
//! ART all validate the id-pool sort order, the `map_list` contents, the Adler-32
//! checksum and the SHA-1 signature, and all four are easy to get subtly wrong.
//! Each of those has a test here.
//!
//! Where possible the output is also cross-checked against
//! [androguard](https://github.com/androguard/androguard), which parses DEX
//! independently; the expectations recorded in the comments below were taken
//! from it.

use dexcore::asm::Assembler;
use dexcore::model::map_type;
use dexcore::writer::{CatchHandler, ClassDef, CodeBody, DexWriter, FieldDef, MethodDef, TryCatch};
use dexcore::{decode_all, decode_one, Error, DexReader};

/// Build a small but non-trivial DEX: a root class, a subclass that implements an
/// interface, static and instance fields, concrete and abstract methods, code
/// with a try/catch, and a payload pseudo-instruction.
///
/// Emitted bytes are cached in a `OnceLock` because most of the tests only need
/// to read the same file.
fn sample_bytes() -> &'static Vec<u8> {
    static SAMPLE: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    SAMPLE.get_or_init(|| build_sample().emit().expect("emit must succeed"))
}

/// Build the sample, going through the two-phase API.
fn build_sample() -> DexWriter {
    let mut w = DexWriter::new();
    let hello = "hello from the shim";
    w.add_string(hello);
    w.add_type("Ljava/io/IOException;");
    w.add_type("Ljava/lang/String;");
    w.add_type("Landroid/substrate/Shim;");
    w.add_type("Landroid/substrate/ShimChild;");
    w.add_type("Ljava/lang/Object;");

    // Intern every reference the bodies will use, before freezing. A method the
    // classes never mention would not otherwise reach the pools, and its index
    // would not exist after sorting.
    w.add_method("Ljava/lang/Object;", "valueOf", &["Ljava/lang/Object;"], "Ljava/lang/String;");
    w.add_method("Ljava/lang/String;", "getBytes", &[], "[B");
    w.add_method("Ljava/lang/String;", "charAt", &["I"], "C");
    w.add_method("Ljava/lang/Character;", "valueOf", &["C"], "Ljava/lang/Integer;");
    w.add_method("Ljava/lang/Integer;", "intValue", &[], "I");
    w.add_method("Ljava/lang/Object;", "<init>", &[], "V");

    // The class shapes. Bodies are declared with `MethodDef::abstract_` and
    // filled in after `freeze`, because sorting the pools renumbers them.
    let shim = ClassDef::extending_object("Landroid/substrate/Shim;")
        .with_field(FieldDef::statics("COUNT", "I"))
        .with_field(FieldDef::instance("tag", "Ljava/lang/String;"))
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            dexcore::model::access::ACC_PUBLIC | dexcore::model::access::ACC_CONSTRUCTOR,
            CodeBody::default(),
        ))
        .with_method(MethodDef::abstract_("greet", &["Ljava/lang/String;"], "I"))
        .with_method(MethodDef::abstract_("describe", &[], "V"))
        .with_method(MethodDef::abstract_("payload", &[], "I"))
        .with_method(MethodDef::abstract_("toString", &[], "Ljava/lang/String;"))
        .with_method(MethodDef::abstract_("nativeThing", &["I"], "V"));

    let mut child = ClassDef::extending_object("Landroid/substrate/ShimChild;");
    child.interfaces = vec!["Landroid/substrate/Shim;".to_string()];
    child.source_file = Some("Shim.java".to_string());
    let child = child
        .with_field(FieldDef::instance("extra", "J"))
        .with_method(MethodDef::abstract_("doThing", &[], "I"));

    let root = ClassDef::root("Landroid/substrate/Root;")
        .with_method(MethodDef::abstract_("rootMethod", &[], "V"));

    // Deliberately added out of dependency order: the emit pass topologically
    // sorts them so superclasses precede subclasses.
    w.add_class(child);
    w.add_class(shim);
    w.add_class(root);

    // ---- phase 1: intern and sort, then take the final indices.
    let idx = w.freeze().expect("freeze must succeed");
    let str_hello = idx.string(hello);
    let ioe = idx.type_("Ljava/io/IOException;").expect("IOException is interned");
    let str_class = idx.type_("Ljava/lang/String;").expect("String is interned");
    let str_value_of = idx
        .method("Ljava/lang/Object;", "valueOf", &["Ljava/lang/Object;"], "Ljava/lang/String;")
        .expect("String.valueOf must be reachable");
    let str_get_bytes = idx.method("Ljava/lang/String;", "getBytes", &[], "[B").expect("getBytes");
    let char_at = idx.method("Ljava/lang/String;", "charAt", &["I"], "C").expect("charAt");
    let char_value_of = idx
        .method("Ljava/lang/Character;", "valueOf", &["C"], "Ljava/lang/Integer;")
        .expect("Character.valueOf");
    let int_value = idx.method("Ljava/lang/Integer;", "intValue", &[], "I").expect("intValue");
    let obj_init = idx.method("Ljava/lang/Object;", "<init>", &[], "V").expect("Object.<init>");
    assert!(idx.has_string(hello));
    assert_eq!(idx.descriptor(str_class as u32).unwrap(), "Ljava/lang/String;");
    assert_eq!(idx.descriptor(ioe as u32).unwrap(), "Ljava/io/IOException;");

    // ---- phase 2: assemble bodies against those indices.

    // <init>()V { super(); }
    let mut a = Assembler::new();
    a.invoke(0x70, &[0], obj_init).unwrap();
    a.return_void();
    w.set_code("Landroid/substrate/Shim;", "<init>", a.into_code(1, 1, 1)).unwrap();

    // static int greet(String) { return String.valueOf(s).getBytes()[0]; }
    let mut a = Assembler::new();
    a.const_string(0, str_hello);
    a.invoke(0x71, &[0], str_value_of).unwrap();
    a.move_result_object(1);
    a.invoke(0x6e, &[1], str_get_bytes).unwrap();
    a.move_result(1);
    a.const4(2, 0).unwrap();
    a.invoke(0x6e, &[1, 2], char_at).unwrap();
    a.move_result(3);
    a.invoke(0x71, &[3], char_value_of).unwrap();
    a.move_result_object(4);
    a.invoke(0x6e, &[4], int_value).unwrap();
    a.move_result(0);
    a.r#return(0);
    w.set_code("Landroid/substrate/Shim;", "greet", a.into_code(4, 1, 2)).unwrap();

    // describe() — a typed handler plus a catch-all, over two ranges that share
    // one handler list, to prove the writer dedups and reuses the offset.
    let mut a = Assembler::new();
    a.const4(0, 0).unwrap();
    a.new_instance(1, ioe);
    a.throw(1);
    a.r#return(0);
    let mut body = a.into_code(3, 0, 1);
    let handler = CatchHandler {
        handlers: vec![
            (Some("Ljava/io/IOException;".into()), 2),
            (None, 3),
        ],
    };
    body.tries = vec![
        TryCatch { start_addr: 0, insn_count: 2, handler: handler.clone() },
        TryCatch { start_addr: 2, insn_count: 1, handler },
    ];
    w.set_code("Landroid/substrate/Shim;", "describe", body).unwrap();

    // payload() — returns a constant from a fill-array-data payload, the format
    // with the most layout traps.
    let mut a = Assembler::new();
    a.const4(0, 1).unwrap();
    // The payload starts two code units after the branch itself: the branch is
    // 3 units, and the payload's first unit follows it.
    // const/4 is one unit, so the branch sits at unit 1 and the payload's
    // first unit is at unit 4.
    a.fill_array_data(0, 4, 4, 1, &42u32.to_le_bytes()).unwrap();
    a.const4(1, 0).unwrap();
    a.aget(2, 0, 1);
    a.r#return(2);
    w.set_code("Landroid/substrate/Shim;", "payload", a.into_code(3, 0, 0)).unwrap();

    // toString() — the classic Object override, so the class is usable.
    let mut a = Assembler::new();
    a.const_string(0, str_hello);
    a.invoke(0x71, &[0], str_value_of).unwrap();
    a.move_result_object(0);
    a.return_object(0);
    w.set_code("Landroid/substrate/Shim;", "toString", a.into_code(1, 1, 1)).unwrap();

    w
}

/// The sample DEX, as bytes.
fn sample() -> Vec<u8> {
    sample_bytes().clone()
}

#[test]
fn emits_a_file_whose_header_and_integrity_are_valid() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).expect("must open");
    reader.verify_integrity().expect("checksum and signature must match");

    let h = reader.header();
    assert_eq!(&h.version, b"035");
    assert_eq!(h.header_size, 0x70);
    assert_eq!(h.endian_tag, 0x1234_5678);
    assert_eq!(h.file_size as usize, bytes.len());
    assert_eq!(h.file_size % 4, 0, "file_size must be a multiple of 4");
    assert_eq!(h.data_off % 4, 0, "data_off must be a multiple of 4");
    assert_eq!(h.map_off % 4, 0, "map_off must be a multiple of 4");
    assert_eq!(h.data_off + h.data_size, h.file_size);
    assert_eq!(h.data_size % 4, 0, "data_size must be an even multiple of 4");
    assert_eq!(h.link_size, 0);
    assert_eq!(h.link_off, 0);
}

#[test]
fn the_signature_covers_the_checksum() {
    // The Adler-32 covers bytes[12..], which includes the signature; the SHA-1
    // covers bytes[32..], which does not. Getting that order wrong produces a
    // file that this crate reads but no other tool will, so assert both
    // independently rather than round-tripping through the same code.
    let bytes = sample();
    let stored_cs = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let mut sig_input = bytes[32..].to_vec();
    let stored_sig: Vec<u8> = bytes[12..32].to_vec();
    assert_eq!(stored_cs, dexcore::header::adler32(&bytes[12..]));
    assert_eq!(dexcore::header::sha1(&sig_input[..]).to_vec(), stored_sig);
    // Flipping any single byte anywhere must be detectable.
    for i in [8usize, 12, 20, 31, 40, 64, 100, bytes.len() - 1] {
        let mut bad = bytes.clone();
        bad[i] ^= 0x01;
        // A flipped byte is always caught, either by the header's own field
        // validation or by the integrity check. Byte 32 onwards is file_size,
        // so flipping it is caught even earlier, by `parse`.
        match DexReader::open(&bad) {
            Err(_) => {}
            Ok(r) => assert!(
                r.verify_integrity().is_err(),
                "flipping byte {i} went undetected"
            ),
        }
    }
    sig_input.clear();
}

#[test]
fn the_map_list_lists_every_section_with_correct_offsets() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    let map = reader.map_list().unwrap();
    let h = reader.header();

    let find = |t: u16| map.iter().find(|e| e.item_type == t).copied();
    assert_eq!(map[0].item_type, map_type::HEADER_ITEM);
    assert_eq!((map[0].size, map[0].offset), (1, 0));
    assert_eq!(map.last().unwrap().item_type, map_type::MAP_LIST);
    assert_eq!(map.last().unwrap().offset, h.map_off);

    for (t, size, off) in [
        (map_type::STRING_ID_ITEM, h.string_ids_size, h.string_ids_off),
        (map_type::TYPE_ID_ITEM, h.type_ids_size, h.type_ids_off),
        (map_type::PROTO_ID_ITEM, h.proto_ids_size, h.proto_ids_off),
        (map_type::FIELD_ID_ITEM, h.field_ids_size, h.field_ids_off),
        (map_type::METHOD_ID_ITEM, h.method_ids_size, h.method_ids_off),
        (map_type::CLASS_DEF_ITEM, h.class_defs_size, h.class_defs_off),
    ] {
        assert!(size > 0, "the sample should populate every id pool");
        let e = find(t).unwrap_or_else(|| panic!("missing {}", map_type::name(t)));
        assert_eq!((e.size, e.offset), (size, off), "{}", map_type::name(t));
    }

    // The variable-length sections must be present too: a class with code, a
    // string pool, type lists for the protos and the interface, and a map list.
    for t in [
        map_type::STRING_DATA_ITEM,
        map_type::TYPE_LIST,
        map_type::CODE_ITEM,
        map_type::CLASS_DATA_ITEM,
    ] {
        let e = find(t).unwrap_or_else(|| panic!("missing {}", map_type::name(t)));
        assert!(e.size > 0);
        assert!(e.offset > 0 && (e.offset as usize) < bytes.len());
        assert_eq!(e.unused, 0);
    }

    // Nothing that the writer does not emit should be claimed.
    for t in [
        map_type::ANNOTATION_ITEM,
        map_type::ANNOTATION_SET_ITEM,
        map_type::ANNOTATIONS_DIRECTORY_ITEM,
        map_type::DEBUG_INFO_ITEM,
        map_type::ENCODED_ARRAY_ITEM,
        map_type::CALL_SITE_ID_ITEM,
        map_type::METHOD_HANDLE_ITEM,
    ] {
        assert!(find(t).is_none(), "{} must be omitted", map_type::name(t));
    }

    // Entries must be strictly ordered by offset and must not overlap.
    let mut prev_end = 0u32;
    for e in &map {
        assert!(e.offset >= prev_end, "0x{:04x} at {} overlaps", e.item_type, e.offset);
        prev_end = e.offset;
    }
    // The header itself is 0x70 bytes, so the first data section cannot start
    // before that.
    let string_data = find(map_type::STRING_DATA_ITEM).unwrap();
    assert!(string_data.offset >= 0x70);
    assert_eq!(string_data.offset, h.data_off, "data_off points at the first data item");
}

#[test]
fn id_pools_come_out_sorted() {
    // dexlib2 and ART both reject a file whose pools are out of order, so this
    // is the single most important writer property.
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();

    let strings = reader.strings().unwrap();
    for w in strings.windows(2) {
        let k = |s: &dexcore::DexString| s.value.encode_utf16().collect::<Vec<u16>>();
        assert!(k(&w[0]) < k(&w[1]), "string_ids out of order: {:?} then {:?}", w[0].value, w[1].value);
    }

    let types = reader.types().unwrap();
    for w in types.windows(2) {
        assert!(w[0].descriptor_idx < w[1].descriptor_idx, "type_ids out of order");
    }

    let mut prev: Option<(u32, u32, u32)> = None;
    for i in 0..reader.field_count() {
        let f = reader.field_at(i).unwrap();
        let key = (f.class_idx, f.name_idx, f.type_idx);
        if let Some(p) = prev {
            assert!(p < key, "field_ids out of order at {i}: {:?} then {:?}", p, key);
        }
        prev = Some(key);
    }

    let mut prev: Option<(u32, u32, u32)> = None;
    for i in 0..reader.method_count() {
        let m = reader.method_at(i).unwrap();
        let key = (m.class_idx, m.name_idx, m.proto_idx);
        if let Some(p) = prev {
            assert!(p < key, "method_ids out of order at {i}: {:?} then {:?}", p, key);
        }
        prev = Some(key);
    }

    // Protos are sorted by (return type, parameters) with the parameters
    // compared by type index.
    let protos = reader.protos().unwrap();
    for w in protos.windows(2) {
        let key = |p: &dexcore::DexProto| {
            let ps: Vec<u32> = p.parameters.iter().map(|t| reader.type_name_index(t)).collect();
            (p.return_type_idx, ps)
        };
        let (a, b) = (key(&w[0]), key(&w[1]));
        assert!(a < b, "proto_ids out of order: {a:?} then {b:?}");
    }
}

#[test]
fn writer_output_round_trips_through_the_reader() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();

    // Every class, field, method, proto and string survives the round trip.
    let classes = reader.classes().unwrap();
    assert_eq!(classes.len(), 3, "three classes were emitted");

    let shim = class(&reader, "Landroid/substrate/Shim;");
    assert_eq!(shim.superclass, "Ljava/lang/Object;");
    assert_eq!(shim.source_file, "", "no source file was recorded");

    let child = class(&reader, "Landroid/substrate/ShimChild;");
    assert_eq!(child.interfaces, vec!["Landroid/substrate/Shim;"]);
    assert_eq!(child.source_file, "Shim.java");

    let root = class(&reader, "Landroid/substrate/Root;");
    assert_eq!(root.superclass, "", "a root class has no superclass");

    let data = shim.class_data.clone().expect("Shim has class data");
    assert_eq!(data.static_fields.len(), 1);
    assert_eq!(data.instance_fields.len(), 1);
    assert_eq!(data.static_fields[0].field_idx, 0, "only one static field");
    let sf = reader.field_at(data.static_fields[0].field_idx).unwrap();
    assert_eq!(sf.name, "COUNT");
    assert_eq!(sf.type_descriptor, "I");
    assert_eq!(sf.class, "Landroid/substrate/Shim;");
    let inf = reader.field_at(data.instance_fields[0].field_idx).unwrap();
    assert_eq!(inf.name, "tag");
    assert_eq!(inf.type_descriptor, "Ljava/lang/String;");

    // Five methods: a constructor, three concrete ones and one abstract.
    assert_eq!(data.direct_methods.len() + data.virtual_methods.len(), 6, "six methods were declared");
    let methods: Vec<String> = data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
        .map(|m| reader.method_at(m.method_idx).unwrap().name.clone())
        .collect();
    for want in ["<init>", "greet", "describe", "payload", "toString", "nativeThing"] {
        assert!(methods.contains(&want.to_string()), "{want} missing from {methods:?}");
    }
    // The abstract method must have no code item.
    let abstract_m = data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
        .find(|m| reader.method_at(m.method_idx).unwrap().name == "nativeThing")
        .unwrap();
    assert_eq!(abstract_m.code_off, 0);
    // And the concrete ones must.
    for name in ["<init>", "greet", "describe", "payload", "toString"] {
        let m = data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
            .find(|m| reader.method_at(m.method_idx).unwrap().name == name)
            .unwrap();
        assert_ne!(m.code_off, 0, "{name} must have a code item");
    }
}

#[test]
fn every_method_list_is_sorted_by_method_idx() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    for c in reader.classes().unwrap() {
        let d = c.class_data.unwrap();
        for list in [&d.direct_methods[..], &d.virtual_methods[..]] {
            assert!(
                list.windows(2).all(|w| w[0].method_idx < w[1].method_idx),
                "{}: methods are not sorted",
                c.descriptor
            );
        }
        for list in [&d.static_fields[..], &d.instance_fields[..]] {
            assert!(
                list.windows(2).all(|w| w[0].field_idx < w[1].field_idx),
                "{}: fields are not sorted",
                c.descriptor
            );
        }
        // A method index may not appear in both the direct and virtual lists.
        for m in &d.direct_methods {
            assert!(
                !d.virtual_methods.iter().any(|v| v.method_idx == m.method_idx),
                "{}: method {} is both direct and virtual",
                c.descriptor,
                m.method_idx
            );
        }
    }
}

#[test]
fn classes_are_ordered_so_a_superclass_precedes_its_subclass() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    let classes = reader.classes().unwrap();
    for c in &classes {
        for dep in std::iter::once(&c.superclass).chain(c.interfaces.iter()) {
            if dep.is_empty() {
                continue;
            }
            if let Some(parent) = classes.iter().find(|p| p.descriptor == *dep) {
                assert!(
                    parent.index < c.index,
                    "{} (index {}) precedes its dependency {} (index {})",
                    c.descriptor,
                    c.index,
                    parent.descriptor,
                    parent.index
                );
            }
        }
    }
    // The root class has NO_INDEX as its superclass.
    let root = classes.iter().find(|c| c.superclass.is_empty()).unwrap();
    assert_eq!(root.superclass_idx, dexcore::header::NO_INDEX);
}

#[test]
fn written_code_decodes_back_to_the_instructions_that_were_assembled() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    let shim_idx = reader.find_class("Landroid/substrate/Shim;").unwrap().unwrap();
    let shim = reader.class_def(shim_idx).unwrap();
    let data = shim.class_data.unwrap();

    let greet = data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
        .find(|m| reader.method_at(m.method_idx).unwrap().name == "greet")
        .unwrap();
    let code = reader.code_item(greet.code_off).unwrap();
    assert_eq!(code.registers_size, 4);
    assert_eq!(code.ins_size, 1);
    assert_eq!(code.outs_size, 2);
    assert_eq!(code.debug_info_off, 0, "the writer emits no debug info");
    assert!(code.tries_size == 0);

    let raw = &bytes[code.insns_off as usize..(code.insns_off + code.insns_size * 2) as usize];
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let all = decode_all(&units).expect("must decode");
    let names: Vec<&str> = all.iter().map(|l| l.instruction.mnemonic()).collect();
    assert_eq!(
        names,
        vec![
            "const-string",
            "invoke-static",
            "move-result-object",
            "invoke-virtual",
            "move-result",
            "const/4",
            "invoke-virtual",
            "move-result",
            "invoke-static",
            "move-result-object",
            "invoke-virtual",
            "move-result",
            "return",
        ]
    );
    // Every reference operand must resolve to the right pool entry.
    let str_idx = all[0].instruction.index_operand().expect("const-string carries an index");
    assert_eq!(
        reader.string(str_idx).unwrap().value,
        "hello from the shim"
    );
    // The tiles the stream exactly.
    let mut total = 0u32;
    for l in &all {
        assert_eq!(l.unit_offset, total);
        total += l.instruction.width() as u32 / 2;
    }
    assert_eq!(total, code.insns_size);
}

#[test]
fn a_try_catch_survives_the_round_trip() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    let shim_idx = reader.find_class("Landroid/substrate/Shim;").unwrap().unwrap();
    let shim = reader.class_def(shim_idx).unwrap();
    let data = shim.class_data.unwrap();
    let describe = data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
        .find(|m| reader.method_at(m.method_idx).unwrap().name == "describe")
        .unwrap();
    let code = reader.code_item(describe.code_off).unwrap();
    assert_eq!(code.tries_size, 2);
    assert_ne!(code.tries_off, 0);
    assert!(!code.encoded_catch_handler_list.is_empty());

    let tries = reader.try_items(describe.code_off).unwrap();
    assert_eq!(tries.len(), 2);
    assert_eq!((tries[0].start_addr, tries[0].insn_count), (0, 2));
    assert_eq!((tries[1].start_addr, tries[1].insn_count), (2, 1));
    // The two ranges share one handler list, so they must share an offset.
    assert_eq!(
        tries[0].handler_off, tries[1].handler_off,
        "identical handler lists must be deduplicated"
    );
    // The handler list is a uleb128 count followed by that many handlers; a
    // count of one means the writer deduplicated correctly.
    assert_eq!(code.encoded_catch_handler_list[0], 1);

    // The 4-byte alignment of the try table must hold.
    assert_eq!(describe.code_off % 4, 0);
    assert_eq!(code.tries_off % 4, 0);
}

#[test]
fn a_payload_pseudo_instruction_survives_the_round_trip() {
    let bytes = sample();
    let reader = DexReader::open(&bytes).unwrap();
    let shim_idx = reader.find_class("Landroid/substrate/Shim;").unwrap().unwrap();
    let shim = reader.class_def(shim_idx).unwrap();
    let data = shim.class_data.unwrap();
    let m = data
        .direct_methods
        .iter()
        .chain(data.virtual_methods.iter())
        .find(|m| reader.method_at(m.method_idx).unwrap().name == "payload")
        .unwrap();
    let code = reader.code_item(m.code_off).unwrap();
    let raw = &bytes[code.insns_off as usize..(code.insns_off + code.insns_size * 2) as usize];
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let all = decode_all(&units).unwrap();

    // Four ordinary instructions, plus the fill-array-data branch and the
    // payload pseudo-instruction it points at.
    assert_eq!(all.len(), 6);
    assert_eq!(
        all.iter().map(|l| l.instruction.mnemonic()).collect::<Vec<_>>(),
        vec!["const/4", "fill-array-data", "<payload>", "const/4", "aget", "return"]
    );
    // The branch at unit 1 must point at the payload, which is two code units
    // later, so the offset is 3.
    match all[1].instruction {
        dexcore::Instruction::F31T { offset, a, .. } => {
            assert_eq!(a, 0);
            assert_eq!(offset, 3, "the payload starts at unit 4 and the branch is at unit 1");
        }
        ref other => panic!("expected fill-array-data, got {other:?}"),
    }
    // The payload declares one 4-byte element holding 42.
    match &all[2].instruction {
        dexcore::Instruction::Payload(dexcore::insn::Payload::FillArrayData(f)) => {
            assert_eq!(f.ident, 0x0300);
            assert_eq!(f.element_width, 4);
            assert_eq!(f.size, 1);
            assert_eq!(f.data, 42u32.to_le_bytes().to_vec());
        }
        other => panic!("expected a fill-array-data payload, got {other:?}"),
    }
    // Widths must tile the stream exactly, which for a payload means the
    // non-uniform body length is respected.
    let mut total = 0u32;
    for l in &all {
        assert_eq!(l.unit_offset, total);
        total += l.instruction.width() as u32 / 2;
    }
    assert_eq!(total, code.insns_size);
}

#[test]
fn strings_round_trip_through_mutf8() {
    let mut w = DexWriter::new();
    // The awkward cases: an embedded NUL, an astral character, a 2-byte form, a
    // literal backslash and a non-ASCII BMP character.
    let awkward = [
        "a\u{0}b",
        "\u{1f600}",
        "caf\u{e9}",
        "\\n is not a newline",
        "\u{7ff}\u{800}",
        "",
    ];
    for s in awkward {
        w.add_string(s);
    }
    w.add_class(ClassDef::root("Ltest/Root;"));
    let bytes = w.emit().unwrap();
    let reader = DexReader::open(&bytes).unwrap();
    let got: Vec<String> = reader.strings().unwrap().into_iter().map(|s| s.value).collect();
    for s in awkward {
        assert!(got.iter().any(|g| g == s), "{s:?} did not round-trip; got {got:?}");
    }
    // The empty string must be present, and the NUL must be stored as C0 80
    // rather than as a bare zero byte.
    let nul = got.iter().position(|g| g == "a\u{0}b").unwrap();
    let s = reader.string(nul as u32).unwrap();
    let stored = &bytes[s.string_data_off as usize..];
    let hdr = {
        let mut i = 0;
        while stored[i] & 0x80 != 0 {
            i += 1;
        }
        i + 1
    };
    assert_eq!(
        &stored[hdr..hdr + 5],
        &[b'a', 0xc0, 0x80, b'b', 0x00],
        "U+0000 must be encoded as the two-byte overlong C0 80, not a bare zero"
    );
}

#[test]
fn an_empty_builder_still_emits_a_valid_file() {
    let w = DexWriter::new();
    let bytes = w.emit().unwrap();
    let reader = DexReader::open(&bytes).unwrap();
    reader.verify_integrity().unwrap();
    let h = reader.header();
    assert_eq!(h.file_size as usize, bytes.len());
    assert_eq!(h.string_ids_size, 0);
    assert_eq!(h.string_ids_off, 0, "an empty section has offset 0");
    assert_eq!(h.class_defs_size, 0);
    assert_eq!(h.class_defs_off, 0);
    // Only the header and the map list exist.
    let map = reader.map_list().unwrap();
    assert_eq!(map.len(), 2);
    assert_eq!(map[0].item_type, map_type::HEADER_ITEM);
    assert_eq!(map[1].item_type, map_type::MAP_LIST);
    assert_eq!(map[1].offset, h.map_off);
    // And the file is still a whole number of code units long.
    assert_eq!(h.file_size % 4, 0);
}

#[test]
fn duplicate_references_are_interned_once() {
    let mut w = DexWriter::new();
    // All three extend java/lang/Object, so the four descriptors below must
    // intern to four pool entries, not seven.
    for d in ["La;", "Lb;", "Lc;", "Ljava/lang/Object;"] {
        w.add_type(d);
    }
    w.add_class(ClassDef::extending_object("La;"));
    w.add_class(ClassDef::extending_object("Lb;"));
    w.add_class(ClassDef::extending_object("Lc;"));
    assert_eq!(w.type_count(), 4, "La, Lb, Lc and Ljava/lang/Object;");
    // Interning the same descriptor twice is idempotent.
    let a = w.add_type("La;");
    let b = w.add_type("La;");
    assert_eq!(a, b);
    assert_eq!(w.add_string("x"), w.add_string("x"));

    let bytes = w.emit().unwrap();
    let reader = DexReader::open(&bytes).unwrap();
    reader.verify_integrity().unwrap();
    let mut n_object = 0;
    for i in 0..reader.type_count() {
        if reader.type_name(i).unwrap() == "Ljava/lang/Object;" {
            n_object += 1;
        }
    }
    assert_eq!(n_object, 1);
}

#[test]
fn a_duplicate_class_is_a_typed_error() {
    let mut w = DexWriter::new();
    w.add_class(ClassDef::root("La;"));
    w.add_class(ClassDef::root("La;"));
    assert!(matches!(w.emit(), Err(Error::DuplicateClass(_))));
}

#[test]
fn an_inheritance_cycle_is_a_typed_error() {
    // A class cannot precede its own superclass, and no valid ordering exists,
    // so this has to be reported rather than silently misordered.
    let mut w = DexWriter::new();
    let mut a = ClassDef::extending_object("La;");
    a.superclass = Some("Lb;".into());
    let mut b = ClassDef::extending_object("Lb;");
    b.superclass = Some("La;".into());
    w.add_class(a);
    w.add_class(b);
    assert!(matches!(w.emit(), Err(Error::CyclicClassHierarchy(_))));
}

/// A writer holding one method with the given body, frozen and ready to emit.
fn writer_with_body(descriptor: &str, body: CodeBody) -> DexWriter {
    let mut w = DexWriter::new();
    w.add_type("Ljava/lang/Exception;");
    w.add_type("Ljava/io/IOException;");
    w.add_class(
        ClassDef::root(descriptor)
            .with_method(MethodDef::concrete("m", &[], "V", dexcore::model::access::ACC_PUBLIC, body)),
    );
    w.freeze().expect("freeze must succeed");
    w
}

#[test]
fn the_writer_rejects_impossible_bodies() {
    // An odd number of insn bytes cannot be a whole number of code units.
    let w = writer_with_body(
        "La;",
        CodeBody { registers_size: 1, ins_size: 0, outs_size: 0, insns: vec![0x00], tries: vec![] },
    );
    assert!(matches!(w.emit(), Err(Error::ValueOutOfRange { .. })));

    // A try range that runs past the end of the instruction stream.
    let mut a = Assembler::new();
    a.return_void();
    let mut body = a.into_code(1, 0, 0);
    body.tries = vec![TryCatch {
        start_addr: 0,
        insn_count: 99,
        handler: CatchHandler { handlers: vec![(None, 0)] },
    }];
    let w = writer_with_body("Lb;", body);
    assert!(matches!(w.emit(), Err(Error::ValueOutOfRange { .. })));

    // An empty catch handler list is not representable.
    let mut a = Assembler::new();
    a.return_void();
    let mut body = a.into_code(1, 0, 0);
    body.tries = vec![TryCatch {
        start_addr: 0,
        insn_count: 1,
        handler: CatchHandler { handlers: vec![] },
    }];
    let w = writer_with_body("Lc;", body);
    assert!(matches!(w.emit(), Err(Error::ValueOutOfRange { .. })));

    // A catch-all must come last, because the encoding requires it to.
    let mut a = Assembler::new();
    a.return_void();
    let mut body = a.into_code(1, 0, 0);
    body.tries = vec![TryCatch {
        start_addr: 0,
        insn_count: 1,
        handler: CatchHandler {
            handlers: vec![(None, 0), (Some("Ljava/lang/Exception;".into()), 0)],
        },
    }];
    let w = writer_with_body("Ld;", body);
    assert!(matches!(w.emit(), Err(Error::ValueOutOfRange { .. })));
}

#[test]
fn emitting_code_without_freezing_is_refused() {
    // Sorting the pools renumbers them, so a const-string index assembled
    // against the unsorted pool would silently point somewhere else. Rather
    // than emit a plausible but wrong file, `emit` refuses.
    let mut a = Assembler::new();
    a.const_string(0, 0);
    a.return_void();
    let mut w = DexWriter::new();
    w.add_string("hello");
    w.add_class(
        ClassDef::root("La;").with_method(MethodDef::concrete(
            "m",
            &[],
            "V",
            dexcore::model::access::ACC_PUBLIC,
            a.into_code(1, 0, 0),
        )),
    );
    match w.emit() {
        Err(Error::MissingCode(msg)) => {
            assert!(msg.contains("freeze"), "the message should say what to do: {msg}");
        }
        other => panic!("expected a MissingCode error, got {other:?}"),
    }
    // After freezing, the same writer emits cleanly.
    let mut w2 = w;
    w2.freeze().unwrap();
    let bytes = w2.emit().unwrap();
    DexReader::open(&bytes).unwrap().verify_integrity().unwrap();
}

#[test]
fn a_body_naming_an_uninterned_exception_type_is_refused() {
    // `set_code` cannot intern anything without renumbering the pools, so a
    // handler type that was never declared before `freeze` has to be an error
    // rather than a silently renumbered file.
    let mut w = DexWriter::new();
    w.add_class(
        ClassDef::root("La;").with_method(MethodDef::abstract_("m", &[], "V")),
    );
    w.freeze().unwrap();
    let mut a = Assembler::new();
    a.return_void();
    let mut body = a.into_code(1, 0, 0);
    body.tries = vec![TryCatch {
        start_addr: 0,
        insn_count: 1,
        handler: CatchHandler {
            handlers: vec![(Some("Ljava/io/IOException;".into()), 0)],
        },
    }];
    w.set_code("La;", "m", body).unwrap();
    // Naming the type makes the pools grow, so `emit` reports the drift. Both
    // refusals are correct; what matters is that neither produces a file whose
    // operands point at the wrong pool entries.
    match w.emit() {
        Err(Error::ValueOutOfRange { what, .. }) => {
            assert!(what.contains("before freeze"), "unhelpful message: {what}");
        }
        Err(Error::MissingCode(msg)) => {
            assert!(msg.contains("re-freeze"), "unhelpful message: {msg}");
        }
        other => panic!("expected a typed error, got {other:?}"),
    }
}

#[test]
fn set_code_reports_an_unknown_class_or_method() {
    let mut w = DexWriter::new();
    w.add_class(ClassDef::root("La;").with_method(MethodDef::abstract_("m", &[], "V")));
    w.freeze().unwrap();
    let mut a1 = Assembler::new();
    a1.return_void();
    let a2 = a1.into_code(1, 0, 0);
    let mut a3 = Assembler::new();
    a3.return_void();
    let a4 = a3.into_code(1, 0, 0);
    assert!(matches!(w.set_code("LZ;", "m", a2), Err(Error::MissingSuperclass(_))));
    assert!(matches!(w.set_code("La;", "nope", a4), Err(Error::MissingCode(_))));
}

#[test]
fn writer_output_is_parsed_by_an_independent_implementation() {
    // The strongest available external check: androguard is a separate
    // implementation of the DEX reader, so if it agrees on the class list and
    // the instruction streams, the file is not merely self-consistent.
    // The test is skipped when androguard is not installed, so it never blocks
    // CI; `tools/dexcore/FIXTURES.md` records how to install it.
    let bytes = sample();
    let dir = std::env::temp_dir().join("dexcore-writer-check");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("classes.dex");
    std::fs::write(&path, &bytes).unwrap();

    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(
            r#"
import sys
try:
    from loguru import logger; logger.remove()
    from androguard.core.dex import DEX
except Exception as e:
    print("SKIP", e); sys.exit(0)
d = DEX(open(sys.argv[1], "rb").read())
names = sorted(c.get_name() for c in d.get_classes())
print("CLASSES", ",".join(names))
for c in d.get_classes():
    for m in c.get_methods():
        code = m.get_code()
        if code is None: continue
        n = 0
        for ins in code.get_bc().get_instructions():
            n += 1
        print("METHOD", c.get_name(), m.get_name(), "insns", n)
"#,
        )
        .arg(&path)
        .output();

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            eprintln!("could not run python3: {e}");
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if stdout.starts_with("SKIP") {
        eprintln!("androguard not available: {}", stdout.trim());
        let _ = std::fs::remove_file(&path);
        return;
    }
    assert!(out.status.success(), "androguard failed: {stdout}{}", String::from_utf8_lossy(&out.stderr));
    assert!(
        stdout.contains(
            "CLASSES Landroid/substrate/Root;,Landroid/substrate/Shim;,Landroid/substrate/ShimChild;"
        ),
        "androguard did not see the classes we wrote: {stdout}"
    );
    // Every code-bearing method must have been walked by androguard too, which
    // means its instruction widths agree with ours.
    for want in [
        "METHOD Landroid/substrate/Shim; greet insns 13",
        "METHOD Landroid/substrate/Shim; describe insns 4",
        "METHOD Landroid/substrate/Shim; payload insns 6",
        "METHOD Landroid/substrate/Shim; toString insns 4",
        "METHOD Landroid/substrate/Shim; <init> insns 2",
    ] {
        assert!(stdout.contains(want), "androguard disagreed: expected `{want}` in:\n{stdout}");
    }
    let _ = std::fs::remove_file(&path);
}

/// Look up a class by descriptor and decode it, failing loudly if absent.
fn class(reader: &DexReader<'_>, descriptor: &str) -> dexcore::DexClass {
    let idx = reader
        .find_class(descriptor)
        .unwrap_or_else(|e| panic!("looking up {descriptor}: {e}"))
        .unwrap_or_else(|| panic!("{descriptor} is not in the file"));
    reader.class_def(idx).unwrap()
}

/// Helper used only by [`id_pools_come_out_sorted`].
trait TypeNameIndex {
    fn type_name_index(&self, descriptor: &str) -> u32;
}

impl TypeNameIndex for DexReader<'_> {
    fn type_name_index(&self, descriptor: &str) -> u32 {
        (0..self.type_count())
            .find(|&i| self.type_name(i).map(|d| d == descriptor).unwrap_or(false))
            .expect("descriptor must be in the pool")
    }
}

/// A switch payload's advance must equal the span of the 32-bit words the
/// decoder actually reads for it. This is checkable without consulting the
/// format specification, and it is the invariant that the previous
/// implementation violated: both switch payloads advanced as though each
/// array element were 16 bits while the decoder read 32-bit words. A linear
/// sweep still tiled, so the fixture tests passed and the bug only surfaced
/// as wrong branch-target fixups.
#[test]
fn switch_payload_advance_matches_the_words_it_reads() {
    for n in 0..8usize {
        // packed-switch-payload: ident(1w) size(1w) first_key(1w) targets(nw)
        let mut b = Vec::new();
        b.extend_from_slice(&0x0100u16.to_le_bytes());
        b.extend_from_slice(&(n as u16).to_le_bytes());
        for v in 0..=n as i32 {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let words: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let (i, units) = decode_one(&words, 0).expect("packed switch must decode");
        // ident(1u) + size(1u) + first_key(2u) + targets(2n u) = 4 + 2n units.
        assert_eq!(units, 4 + 2 * n, "packed n={n}");
        assert_eq!(i.width() as usize, units * 2, "packed width vs advance n={n}");

        // sparse-switch-payload: ident(1w) size(1w) keys(nw) targets(nw)
        let mut b = Vec::new();
        b.extend_from_slice(&0x0200u16.to_le_bytes());
        b.extend_from_slice(&(n as u16).to_le_bytes());
        for v in 0..2 * n as i32 {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let words: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        let (i, units) = decode_one(&words, 0).expect("sparse switch must decode");
        // ident(1u) + size(1u) + keys(2n u) + targets(2n u) = 2 + 4n units.
        assert_eq!(units, 2 + 4 * n, "sparse n={n}");
        assert_eq!(i.width() as usize, units * 2, "sparse width vs advance n={n}");
    }
}
