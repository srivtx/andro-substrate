//! Opcode table conformance.
//!
//! The table in [`dexcore::opcodes`] is a transcription of the AOSP Dalvik
//! bytecode specification. These tests check it three independent ways, so that
//! a typo in any one of them is caught rather than being restated back at
//! itself:
//!
//! 1. Every format's width must equal the leading digit of its AOSP identifier,
//!    which *is* the instruction length by definition of the naming scheme.
//! 2. Every opcode's declared width must agree with its format.
//! 3. The format, mnemonic and validity of every opcode must match a
//!    transcription of the specification table kept here, separately from the
//!    one in the crate.

use dexcore::opcodes::{self, Format, PayloadKind, RefKind};

/// The AOSP format identifier of each format, as written in the specification.
///
/// This is deliberately a second, independent transcription: if the table in
/// `opcodes.rs` had a mis-typed format, the two would disagree.
const SPEC_FORMATS: &[(&str, Format)] = &[
    ("00x", Format::F00X),
    ("10x", Format::F10X),
    ("10t", Format::F10T),
    ("11n", Format::F11N),
    ("11x", Format::F11X),
    ("12x", Format::F12X),
    ("20t", Format::F20T),
    ("20bc", Format::F20BC),
    ("21c", Format::F21C),
    ("21h", Format::F21H),
    ("21s", Format::F21S),
    ("21t", Format::F21T),
    ("22b", Format::F22B),
    ("22x", Format::F22X),
    ("22c", Format::F22C),
    ("22s", Format::F22S),
    ("22t", Format::F22T),
    ("22cs", Format::F22CS),
    ("23x", Format::F23X),
    ("30t", Format::F30T),
    ("31c", Format::F31C),
    ("31i", Format::F31I),
    ("31t", Format::F31T),
    ("32x", Format::F32X),
    ("35c", Format::F35C),
    ("35mi", Format::F35MI),
    ("35ms", Format::F35MS),
    ("3rc", Format::F3RC),
    ("3rmi", Format::F3RMI),
    ("3rms", Format::F3RMS),
    ("40sc", Format::F40SC),
    ("41c", Format::F41C),
    ("45cc", Format::F45CC),
    ("4rcc", Format::F4RCC),
    ("51l", Format::F51L),
    ("52c", Format::F52C),
    ("5rc", Format::F5RC),
];

/// `(opcode, AOSP format identifier, mnemonic, is a pool reference)`, taken from
/// the specification's opcode table.
///
/// `R` marks the opcodes whose operand is a pool index; the pool is named in
/// [`REF_POOL`].
const SPEC_TABLE: &[(u8, &str, &str, RefKind)] = &[
    (0x00, "10x", "nop", RefKind::None),
    (0x01, "12x", "move", RefKind::None),
    (0x02, "22x", "move/from16", RefKind::None),
    (0x03, "32x", "move/16", RefKind::None),
    (0x04, "12x", "move-wide", RefKind::None),
    (0x05, "22x", "move-wide/from16", RefKind::None),
    (0x06, "32x", "move-wide/16", RefKind::None),
    (0x07, "12x", "move-object", RefKind::None),
    (0x08, "22x", "move-object/from16", RefKind::None),
    (0x09, "32x", "move-object/16", RefKind::None),
    (0x0a, "11x", "move-result", RefKind::None),
    (0x0b, "11x", "move-result-wide", RefKind::None),
    (0x0c, "11x", "move-result-object", RefKind::None),
    (0x0d, "11x", "move-exception", RefKind::None),
    (0x0e, "10x", "return-void", RefKind::None),
    (0x0f, "11x", "return", RefKind::None),
    (0x10, "11x", "return-wide", RefKind::None),
    (0x11, "11x", "return-object", RefKind::None),
    (0x12, "11n", "const/4", RefKind::None),
    (0x13, "21s", "const/16", RefKind::None),
    (0x14, "31i", "const", RefKind::None),
    (0x15, "21h", "const/high16", RefKind::None),
    (0x16, "21s", "const-wide/16", RefKind::None),
    (0x17, "31i", "const-wide/32", RefKind::None),
    (0x18, "51l", "const-wide", RefKind::None),
    (0x19, "21h", "const-wide/high16", RefKind::None),
    (0x1a, "21c", "const-string", RefKind::String),
    (0x1b, "31c", "const-string/jumbo", RefKind::String),
    (0x1c, "21c", "const-class", RefKind::Type),
    (0x1d, "11x", "monitor-enter", RefKind::None),
    (0x1e, "11x", "monitor-exit", RefKind::None),
    (0x1f, "21c", "check-cast", RefKind::Type),
    (0x20, "22c", "instance-of", RefKind::Type),
    (0x21, "12x", "array-length", RefKind::None),
    (0x22, "21c", "new-instance", RefKind::Type),
    (0x23, "22c", "new-array", RefKind::Type),
    (0x24, "35c", "filled-new-array", RefKind::Type),
    (0x25, "3rc", "filled-new-array/range", RefKind::Type),
    (0x26, "31t", "fill-array-data", RefKind::None),
    (0x27, "11x", "throw", RefKind::None),
    (0x28, "10t", "goto", RefKind::None),
    (0x29, "20t", "goto/16", RefKind::None),
    (0x2a, "30t", "goto/32", RefKind::None),
    (0x2b, "31t", "packed-switch", RefKind::None),
    (0x2c, "31t", "sparse-switch", RefKind::None),
    (0x2d, "23x", "cmpl-float", RefKind::None),
    (0x2e, "23x", "cmpg-float", RefKind::None),
    (0x2f, "23x", "cmpl-double", RefKind::None),
    (0x30, "23x", "cmpg-double", RefKind::None),
    (0x31, "23x", "cmp-long", RefKind::None),
    (0x32, "22t", "if-eq", RefKind::None),
    (0x33, "22t", "if-ne", RefKind::None),
    (0x34, "22t", "if-lt", RefKind::None),
    (0x35, "22t", "if-ge", RefKind::None),
    (0x36, "22t", "if-gt", RefKind::None),
    (0x37, "22t", "if-le", RefKind::None),
    (0x38, "21t", "if-eqz", RefKind::None),
    (0x39, "21t", "if-nez", RefKind::None),
    (0x3a, "21t", "if-ltz", RefKind::None),
    (0x3b, "21t", "if-gez", RefKind::None),
    (0x3c, "21t", "if-gtz", RefKind::None),
    (0x3d, "21t", "if-lez", RefKind::None),
    (0x3e, "10x", "unused", RefKind::None),
    (0x3f, "10x", "unused", RefKind::None),
    (0x40, "10x", "unused", RefKind::None),
    (0x41, "10x", "unused", RefKind::None),
    (0x42, "10x", "unused", RefKind::None),
    (0x43, "10x", "unused", RefKind::None),
    (0x44, "23x", "aget", RefKind::None),
    (0x45, "23x", "aget-wide", RefKind::None),
    (0x46, "23x", "aget-object", RefKind::None),
    (0x47, "23x", "aget-boolean", RefKind::None),
    (0x48, "23x", "aget-byte", RefKind::None),
    (0x49, "23x", "aget-char", RefKind::None),
    (0x4a, "23x", "aget-short", RefKind::None),
    (0x4b, "23x", "aput", RefKind::None),
    (0x4c, "23x", "aput-wide", RefKind::None),
    (0x4d, "23x", "aput-object", RefKind::None),
    (0x4e, "23x", "aput-boolean", RefKind::None),
    (0x4f, "23x", "aput-byte", RefKind::None),
    (0x50, "23x", "aput-char", RefKind::None),
    (0x51, "23x", "aput-short", RefKind::None),
    (0x52, "22c", "iget", RefKind::Field),
    (0x53, "22c", "iget-wide", RefKind::Field),
    (0x54, "22c", "iget-object", RefKind::Field),
    (0x55, "22c", "iget-boolean", RefKind::Field),
    (0x56, "22c", "iget-byte", RefKind::Field),
    (0x57, "22c", "iget-char", RefKind::Field),
    (0x58, "22c", "iget-short", RefKind::Field),
    (0x59, "22c", "iput", RefKind::Field),
    (0x5a, "22c", "iput-wide", RefKind::Field),
    (0x5b, "22c", "iput-object", RefKind::Field),
    (0x5c, "22c", "iput-boolean", RefKind::Field),
    (0x5d, "22c", "iput-byte", RefKind::Field),
    (0x5e, "22c", "iput-char", RefKind::Field),
    (0x5f, "22c", "iput-short", RefKind::Field),
    (0x60, "21c", "sget", RefKind::Field),
    (0x61, "21c", "sget-wide", RefKind::Field),
    (0x62, "21c", "sget-object", RefKind::Field),
    (0x63, "21c", "sget-boolean", RefKind::Field),
    (0x64, "21c", "sget-byte", RefKind::Field),
    (0x65, "21c", "sget-char", RefKind::Field),
    (0x66, "21c", "sget-short", RefKind::Field),
    (0x67, "21c", "sput", RefKind::Field),
    (0x68, "21c", "sput-wide", RefKind::Field),
    (0x69, "21c", "sput-object", RefKind::Field),
    (0x6a, "21c", "sput-boolean", RefKind::Field),
    (0x6b, "21c", "sput-byte", RefKind::Field),
    (0x6c, "21c", "sput-char", RefKind::Field),
    (0x6d, "21c", "sput-short", RefKind::Field),
    (0x6e, "35c", "invoke-virtual", RefKind::Method),
    (0x6f, "35c", "invoke-super", RefKind::Method),
    (0x70, "35c", "invoke-direct", RefKind::Method),
    (0x71, "35c", "invoke-static", RefKind::Method),
    (0x72, "35c", "invoke-interface", RefKind::Method),
    (0x73, "10x", "unused", RefKind::None),
    (0x74, "3rc", "invoke-virtual/range", RefKind::Method),
    (0x75, "3rc", "invoke-super/range", RefKind::Method),
    (0x76, "3rc", "invoke-direct/range", RefKind::Method),
    (0x77, "3rc", "invoke-static/range", RefKind::Method),
    (0x78, "3rc", "invoke-interface/range", RefKind::Method),
    (0x79, "10x", "unused", RefKind::None),
    (0x7a, "10x", "unused", RefKind::None),
    (0x7b, "12x", "neg-int", RefKind::None),
    (0x7c, "12x", "not-int", RefKind::None),
    (0x7d, "12x", "neg-long", RefKind::None),
    (0x7e, "12x", "not-long", RefKind::None),
    (0x7f, "12x", "neg-float", RefKind::None),
    (0x80, "12x", "neg-double", RefKind::None),
    (0x81, "12x", "int-to-long", RefKind::None),
    (0x82, "12x", "int-to-float", RefKind::None),
    (0x83, "12x", "int-to-double", RefKind::None),
    (0x84, "12x", "long-to-int", RefKind::None),
    (0x85, "12x", "long-to-float", RefKind::None),
    (0x86, "12x", "long-to-double", RefKind::None),
    (0x87, "12x", "float-to-int", RefKind::None),
    (0x88, "12x", "float-to-long", RefKind::None),
    (0x89, "12x", "float-to-double", RefKind::None),
    (0x8a, "12x", "double-to-int", RefKind::None),
    (0x8b, "12x", "double-to-long", RefKind::None),
    (0x8c, "12x", "double-to-float", RefKind::None),
    (0x8d, "12x", "int-to-byte", RefKind::None),
    (0x8e, "12x", "int-to-char", RefKind::None),
    (0x8f, "12x", "int-to-short", RefKind::None),
    (0x90, "23x", "add-int", RefKind::None),
    (0x91, "23x", "sub-int", RefKind::None),
    (0x92, "23x", "mul-int", RefKind::None),
    (0x93, "23x", "div-int", RefKind::None),
    (0x94, "23x", "rem-int", RefKind::None),
    (0x95, "23x", "and-int", RefKind::None),
    (0x96, "23x", "or-int", RefKind::None),
    (0x97, "23x", "xor-int", RefKind::None),
    (0x98, "23x", "shl-int", RefKind::None),
    (0x99, "23x", "shr-int", RefKind::None),
    (0x9a, "23x", "ushr-int", RefKind::None),
    (0x9b, "23x", "add-long", RefKind::None),
    (0x9c, "23x", "sub-long", RefKind::None),
    (0x9d, "23x", "mul-long", RefKind::None),
    (0x9e, "23x", "div-long", RefKind::None),
    (0x9f, "23x", "rem-long", RefKind::None),
    (0xa0, "23x", "and-long", RefKind::None),
    (0xa1, "23x", "or-long", RefKind::None),
    (0xa2, "23x", "xor-long", RefKind::None),
    (0xa3, "23x", "shl-long", RefKind::None),
    (0xa4, "23x", "shr-long", RefKind::None),
    (0xa5, "23x", "ushr-long", RefKind::None),
    (0xa6, "23x", "add-float", RefKind::None),
    (0xa7, "23x", "sub-float", RefKind::None),
    (0xa8, "23x", "mul-float", RefKind::None),
    (0xa9, "23x", "div-float", RefKind::None),
    (0xaa, "23x", "rem-float", RefKind::None),
    (0xab, "23x", "add-double", RefKind::None),
    (0xac, "23x", "sub-double", RefKind::None),
    (0xad, "23x", "mul-double", RefKind::None),
    (0xae, "23x", "div-double", RefKind::None),
    (0xaf, "23x", "rem-double", RefKind::None),
    (0xb0, "12x", "add-int/2addr", RefKind::None),
    (0xb1, "12x", "sub-int/2addr", RefKind::None),
    (0xb2, "12x", "mul-int/2addr", RefKind::None),
    (0xb3, "12x", "div-int/2addr", RefKind::None),
    (0xb4, "12x", "rem-int/2addr", RefKind::None),
    (0xb5, "12x", "and-int/2addr", RefKind::None),
    (0xb6, "12x", "or-int/2addr", RefKind::None),
    (0xb7, "12x", "xor-int/2addr", RefKind::None),
    (0xb8, "12x", "shl-int/2addr", RefKind::None),
    (0xb9, "12x", "shr-int/2addr", RefKind::None),
    (0xba, "12x", "ushr-int/2addr", RefKind::None),
    (0xbb, "12x", "add-long/2addr", RefKind::None),
    (0xbc, "12x", "sub-long/2addr", RefKind::None),
    (0xbd, "12x", "mul-long/2addr", RefKind::None),
    (0xbe, "12x", "div-long/2addr", RefKind::None),
    (0xbf, "12x", "rem-long/2addr", RefKind::None),
    (0xc0, "12x", "and-long/2addr", RefKind::None),
    (0xc1, "12x", "or-long/2addr", RefKind::None),
    (0xc2, "12x", "xor-long/2addr", RefKind::None),
    (0xc3, "12x", "shl-long/2addr", RefKind::None),
    (0xc4, "12x", "shr-long/2addr", RefKind::None),
    (0xc5, "12x", "ushr-long/2addr", RefKind::None),
    (0xc6, "12x", "add-float/2addr", RefKind::None),
    (0xc7, "12x", "sub-float/2addr", RefKind::None),
    (0xc8, "12x", "mul-float/2addr", RefKind::None),
    (0xc9, "12x", "div-float/2addr", RefKind::None),
    (0xca, "12x", "rem-float/2addr", RefKind::None),
    (0xcb, "12x", "add-double/2addr", RefKind::None),
    (0xcc, "12x", "sub-double/2addr", RefKind::None),
    (0xcd, "12x", "mul-double/2addr", RefKind::None),
    (0xce, "12x", "div-double/2addr", RefKind::None),
    (0xcf, "12x", "rem-double/2addr", RefKind::None),
    (0xd0, "22s", "add-int/lit16", RefKind::None),
    (0xd1, "22s", "rsub-int", RefKind::None),
    (0xd2, "22s", "mul-int/lit16", RefKind::None),
    (0xd3, "22s", "div-int/lit16", RefKind::None),
    (0xd4, "22s", "rem-int/lit16", RefKind::None),
    (0xd5, "22s", "and-int/lit16", RefKind::None),
    (0xd6, "22s", "or-int/lit16", RefKind::None),
    (0xd7, "22s", "xor-int/lit16", RefKind::None),
    (0xd8, "22b", "add-int/lit8", RefKind::None),
    (0xd9, "22b", "rsub-int/lit8", RefKind::None),
    (0xda, "22b", "mul-int/lit8", RefKind::None),
    (0xdb, "22b", "div-int/lit8", RefKind::None),
    (0xdc, "22b", "rem-int/lit8", RefKind::None),
    (0xdd, "22b", "and-int/lit8", RefKind::None),
    (0xde, "22b", "or-int/lit8", RefKind::None),
    (0xdf, "22b", "xor-int/lit8", RefKind::None),
    (0xe0, "22b", "shl-int/lit8", RefKind::None),
    (0xe1, "22b", "shr-int/lit8", RefKind::None),
    (0xe2, "22b", "ushr-int/lit8", RefKind::None),
    (0xe3, "10x", "unused", RefKind::None),
    (0xe4, "10x", "unused", RefKind::None),
    (0xe5, "10x", "unused", RefKind::None),
    (0xe6, "10x", "unused", RefKind::None),
    (0xe7, "10x", "unused", RefKind::None),
    (0xe8, "10x", "unused", RefKind::None),
    (0xe9, "10x", "unused", RefKind::None),
    (0xea, "10x", "unused", RefKind::None),
    (0xeb, "10x", "unused", RefKind::None),
    (0xec, "10x", "unused", RefKind::None),
    (0xed, "10x", "unused", RefKind::None),
    (0xee, "10x", "unused", RefKind::None),
    (0xef, "10x", "unused", RefKind::None),
    (0xf0, "10x", "unused", RefKind::None),
    (0xf1, "10x", "unused", RefKind::None),
    (0xf2, "10x", "unused", RefKind::None),
    (0xf3, "10x", "unused", RefKind::None),
    (0xf4, "10x", "unused", RefKind::None),
    (0xf5, "10x", "unused", RefKind::None),
    (0xf6, "10x", "unused", RefKind::None),
    (0xf7, "10x", "unused", RefKind::None),
    (0xf8, "10x", "unused", RefKind::None),
    (0xf9, "10x", "unused", RefKind::None),
    (0xfa, "45cc", "invoke-polymorphic", RefKind::Proto),
    (0xfb, "4rcc", "invoke-polymorphic/range", RefKind::Proto),
    (0xfc, "35c", "invoke-custom", RefKind::CallSite),
    (0xfd, "3rc", "invoke-custom/range", RefKind::CallSite),
    (0xfe, "21c", "const-method-handle", RefKind::MethodHandle),
    (0xff, "21c", "const-method-type", RefKind::MethodProto),
];

/// Expected width in bytes, derived from the leading digit of the AOSP format
/// identifier. This is the definition of the naming scheme, not a lookup table,
/// so it is an independent check on [`Format::width`].
fn spec_width(format_name: &str) -> u16 {
    let lead = format_name.as_bytes()[0] - b'0';
    lead as u16 * 2
}

#[test]
fn format_names_round_trip() {
    for (name, format) in SPEC_FORMATS {
        assert_eq!(format.name(), *name, "format {name} has the wrong name()");
    }
    // `Format::ALL` must list every variant exactly once, which the assert on
    // the lengths below enforces.
    assert_eq!(SPEC_FORMATS.len(), Format::ALL.len());
    for (name, format) in SPEC_FORMATS {
        assert!(
            Format::ALL.contains(format),
            "format {name} is missing from Format::ALL"
        );
    }
}

#[test]
fn every_format_width_equals_its_leading_digit() {
    for (name, format) in SPEC_FORMATS {
        assert_eq!(
            format.width(),
            spec_width(name),
            "format {name} declares width {} but its leading digit implies {}",
            format.width(),
            spec_width(name)
        );
        assert_eq!(format.code_units(), spec_width(name) / 2, "format {name} code units");
    }
}

#[test]
fn every_opcode_matches_the_specification_table() {
    assert_eq!(SPEC_TABLE.len(), 256, "the transcription must cover every opcode");
    for &(op, format_name, mnemonic, ref_kind) in SPEC_TABLE {
        let e = opcodes::opcode(op);
        assert_eq!(e.opcode, op, "table is not identity-ordered at {op:#04x}");
        assert_eq!(
            e.format.name(),
            format_name,
            "opcode {op:#04x} ({mnemonic}) has format {} but the spec says {format_name}",
            e.format.name()
        );
        assert_eq!(e.mnemonic, mnemonic, "opcode {op:#04x} mnemonic");
        assert_eq!(e.ref_kind, ref_kind, "opcode {op:#04x} ({mnemonic}) pool reference");
        assert_eq!(e.valid, mnemonic != "unused", "opcode {op:#04x} validity");
    }
}

#[test]
fn every_opcode_width_is_consistent_with_its_format() {
    for &(op, format_name, mnemonic, _) in SPEC_TABLE {
        let e = opcodes::opcode(op);
        assert_eq!(
            e.width,
            spec_width(format_name),
            "opcode {op:#04x} ({mnemonic}) width"
        );
        assert_eq!(e.width, e.format.width());
    }
}

#[test]
fn every_defined_opcode_is_two_to_ten_bytes_and_unused_ones_still_advance() {
    let mut defined = 0;
    let mut unused = 0;
    for &e in opcodes::OPCODES.iter() {
        if e.valid {
            defined += 1;
            assert!((2..=10).contains(&e.width), "{:#04x} {} width {}", e.opcode, e.mnemonic, e.width);
            assert_ne!(e.mnemonic, "unused", "{:#04x}", e.opcode);
        } else {
            unused += 1;
            // A linear walk over corrupt data must keep making progress, so even
            // an unused opcode has to declare a width.
            assert_eq!(e.width, 2, "{:#04x} must be 2 bytes", e.opcode);
            assert_eq!(e.format, Format::F10X);
        }
    }
    assert_eq!(defined, 224, "the specification defines 224 opcodes");
    assert_eq!(unused, 32, "the specification leaves 32 unused");
    assert_eq!(defined + unused, 256);
}

#[test]
fn the_unused_opcodes_are_exactly_the_specified_ranges() {
    // AOSP marks 0x3e..=0x43, 0x73, 0x79..=0x7a and 0xe3..=0xf9 as unused.
    let unused: Vec<u8> = opcodes::OPCODES.iter().filter(|o| !o.valid).map(|o| o.opcode).collect();
    let mut expected: Vec<u8> = Vec::new();
    expected.extend(0x3e..=0x43);
    expected.push(0x73);
    expected.extend(0x79..=0x7a);
    expected.extend(0xe3..=0xf9);
    assert_eq!(unused, expected);
}

#[test]
fn payload_idents_match_the_specification() {
    assert_eq!(PayloadKind::from_unit(0x0100), Some(PayloadKind::PackedSwitch));
    assert_eq!(PayloadKind::from_unit(0x0200), Some(PayloadKind::SparseSwitch));
    assert_eq!(PayloadKind::from_unit(0x0300), Some(PayloadKind::FillArrayData));
    assert_eq!(PayloadKind::from_unit(0x0000), None);
    assert_eq!(PayloadKind::from_unit(0x0a10), None, "an ordinary opcode is not a payload");
    assert_eq!(PayloadKind::PackedSwitch.ident(), 0x0100);
    assert_eq!(PayloadKind::SparseSwitch.ident(), 0x0200);
    assert_eq!(PayloadKind::FillArrayData.ident(), 0x0300);
}

#[test]
fn payload_widths_follow_the_specified_layouts() {
    // packed: ident, size, first_key, targets => 4 + n units
    assert_eq!(PayloadKind::PackedSwitch.width_units(0), 4);
    assert_eq!(PayloadKind::PackedSwitch.width_units(7), 11);
    // sparse: ident, size, keys, targets => 2 + 2n units
    assert_eq!(PayloadKind::SparseSwitch.width_units(0), 2);
    assert_eq!(PayloadKind::SparseSwitch.width_units(5), 12);
    // fill: ident, element_width, size, data => 4 + n units, where the caller
    // rounds the byte count up to a whole code unit
    assert_eq!(PayloadKind::FillArrayData.width_units(0), 4);
    assert_eq!(PayloadKind::FillArrayData.width_units(6), 10);
}

#[test]
fn lookup_helpers_agree_with_the_table() {
    for e in opcodes::OPCODES.iter() {
        assert_eq!(opcodes::mnemonic(e.opcode), e.mnemonic);
        assert_eq!(opcodes::width_of(e.opcode), e.width);
        assert_eq!(opcodes::opcode(e.opcode), e);
    }
    assert_eq!(opcodes::mnemonic(0x6e), "invoke-virtual");
    assert_eq!(opcodes::width_of(0x18), 10);
    assert_eq!(opcodes::width_of(0x00), 2);
}
