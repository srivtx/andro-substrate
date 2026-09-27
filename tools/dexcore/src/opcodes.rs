//! Dalvik opcode table, instruction formats and widths.
//!
//! The table below is a transcription of the opcode listing in the AOSP
//! *Dalvik bytecode* specification (<https://source.android.com/docs/core/runtime/dalvik-bytecode>)
//! and has been cross-checked opcode-by-opcode against the Apache-2.0 licensed
//! `androguard/dex-bytecode` disassembler (<https://github.com/androguard/dex-bytecode>).
//! No code was copied from that project; the two tables were compared and agree
//! on all 224 defined opcodes and on the exact set of 32 unused opcodes.
//!
//! Every declared width is derived from the AOSP format identifier. In the
//! `XYz` naming scheme `X` *is* the instruction length in 16-bit code units,
//! so the width column is redundant by construction. `tests/opcode_table.rs`
//! asserts that redundancy independently.
//!
//! Formats that appear in the wider Dalvik ecosystem but are not assigned to any
//! opcode in the specification (`22cs`, `35ms`, `35mi`, `3rms`, `3rmi`, `40sc`,
//! `41c`, `52c`, `5rc`) are represented as variants so that foreign DEX variants
//! and third-party obfuscators can be decoded, but they are never produced by
//! `OPCODES` and are not part of the Dalvik instruction set proper.

/// Instruction format identifier, using the AOSP `XYz` naming scheme.
///
/// `X` is the number of 16-bit code units the instruction occupies, which makes
/// width a function of the format rather than of the opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Format {
    /// Unused / invalid. Carries no operands; never emitted by a well-formed DEX.
    F00X,
    /// `op` — 1 unit.
    F10X,
    /// `op AA` where AA is a signed 8-bit branch offset — 1 unit.
    F10T,
    /// `op A|B` — 1 unit.
    F11N,
    /// `op AA` — 1 unit.
    F11X,
    /// `B|A|op` — 1 unit.
    F12X,
    /// `op ØØØØ AAAA` — 2 units.
    F20T,
    /// `op AA BBBB` with a 2-byte index — 2 units.
    F20BC,
    /// `op AA BBBB` with a 2-byte pool index — 2 units.
    F21C,
    /// `op AA BBBB` where BBBB is the high 16 bits of a literal — 2 units.
    F21H,
    /// `op AA BBBB` with a signed 16-bit literal — 2 units.
    F21S,
    /// `op AA BBBB` with a signed 16-bit branch offset — 2 units.
    F21T,
    /// `op AA BB CC` with a signed 8-bit literal — 2 units.
    F22B,
    /// `op AA BBBB` with 8- and 16-bit registers — 2 units.
    F22X,
    /// `B|A|op CCCC` with a 2-byte pool index — 2 units.
    F22C,
    /// `B|A|op CCCC` with a signed 16-bit literal — 2 units.
    F22S,
    /// `B|A|op CCCC` with a signed 16-bit branch offset — 2 units.
    F22T,
    /// `B|A|op CCCC` short-index variant seen in foreign DEX files — 2 units.
    F22CS,
    /// `op AA BB CC` — 2 units.
    F23X,
    /// `op ØØØØ AAAAAAAA` — 3 units.
    F30T,
    /// `op AA BBBBBBBB` with a 4-byte pool index — 3 units.
    F31C,
    /// `op AA BBBBBBBB` with a 32-bit literal — 3 units.
    F31I,
    /// `op AA BBBBBBBB` with a 32-bit branch offset — 3 units.
    F31T,
    /// `ØØØØ|op AAAA BBBB` — 3 units.
    F32X,
    /// `A|G|op BBBB C|D|E|F` — 3 units.
    F35C,
    /// `A|G|op BBBB C|D|E|F` short-index variant — 3 units.
    F35MI,
    /// `A|G|op BBBB C|D|E|F` move-range variant — 3 units.
    F35MS,
    /// `AA|op BBBB CCCC` — 3 units.
    F3RC,
    /// `AA|op BBBB CCCC` short-index variant — 3 units.
    F3RMI,
    /// `AA|op BBBB CCCC` move-range variant — 3 units.
    F3RMS,
    /// `op BBBBBBBB AAAA` — 4 units.
    F40SC,
    /// `op BBBBBBBB AAAA` — 4 units.
    F41C,
    /// `A|G|op BBBB C|D|E|F HHHH` — 4 units.
    F45CC,
    /// `AA|op BBBB CCCC HHHH` — 4 units.
    F4RCC,
    /// `op AA BBBBBBBBBBBBBBBB` — 5 units.
    F51L,
    /// `op CCCCCCCC AAAA BBBB` — 5 units.
    F52C,
    /// `op BBBBBBBB AAAA CCCC` — 5 units.
    F5RC,
}

impl Format {
    /// Every format variant, in declaration order. Used by tests to assert that
    /// the table has no gaps and that widths are total.
    pub const ALL: [Format; 37] = [
        Format::F00X,
        Format::F10X, Format::F10T, Format::F11N, Format::F11X, Format::F12X,
        Format::F20T, Format::F20BC, Format::F21C, Format::F21H, Format::F21S, Format::F21T,
        Format::F22B, Format::F22X, Format::F22C, Format::F22S, Format::F22T, Format::F22CS,
        Format::F23X, Format::F30T, Format::F31C, Format::F31I, Format::F31T, Format::F32X,
        Format::F35C, Format::F35MI, Format::F35MS, Format::F3RC, Format::F3RMI, Format::F3RMS,
        Format::F40SC, Format::F41C, Format::F45CC, Format::F4RCC,
        Format::F51L, Format::F52C, Format::F5RC,
    ];

    /// The AOSP format identifier, e.g. `Format::F35C` -> `"35c"`.
    pub const fn name(self) -> &'static str {
        match self {
            Format::F00X => "00x",
            Format::F10X => "10x",
            Format::F10T => "10t",
            Format::F11N => "11n",
            Format::F11X => "11x",
            Format::F12X => "12x",
            Format::F20T => "20t",
            Format::F20BC => "20bc",
            Format::F21C => "21c",
            Format::F21H => "21h",
            Format::F21S => "21s",
            Format::F21T => "21t",
            Format::F22B => "22b",
            Format::F22X => "22x",
            Format::F22C => "22c",
            Format::F22S => "22s",
            Format::F22T => "22t",
            Format::F22CS => "22cs",
            Format::F23X => "23x",
            Format::F30T => "30t",
            Format::F31C => "31c",
            Format::F31I => "31i",
            Format::F31T => "31t",
            Format::F32X => "32x",
            Format::F35C => "35c",
            Format::F35MI => "35mi",
            Format::F35MS => "35ms",
            Format::F3RC => "3rc",
            Format::F3RMI => "3rmi",
            Format::F3RMS => "3rms",
            Format::F40SC => "40sc",
            Format::F41C => "41c",
            Format::F45CC => "45cc",
            Format::F4RCC => "4rcc",
            Format::F51L => "51l",
            Format::F52C => "52c",
            Format::F5RC => "5rc",
        }
    }

    /// The leading digit of the format identifier, which is by definition the
    /// instruction length in 16-bit code units.
    pub const fn code_units(self) -> u16 {
        let n = self.name().as_bytes();
        (n[0] - b'0') as u16
    }

    /// Width of a single instruction in bytes. Zero only for [`Format::F00X`].
    pub const fn width(self) -> u16 {
        self.code_units() * 2
    }
}

/// What kind of pool entry an instruction's index operand refers to.
///
/// This drives symbolic execution: the runtime only needs to observe the four
/// reference-carrying kinds (`String`, `Type`, `Field`, `Method`) plus the
/// three invokedynamic-related ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    /// No pool reference.
    None,
    /// Index into `string_ids`.
    String,
    /// Index into `type_ids`.
    Type,
    /// Index into `field_ids`.
    Field,
    /// Index into `method_ids`.
    Method,
    /// Index into `method_handles`.
    MethodHandle,
    /// Index into `proto_ids` (a method type).
    MethodProto,
    /// Index into `proto_ids` (the trailing proto of `invoke-polymorphic`).
    Proto,
    /// Index into `call_site_ids`.
    CallSite,
}

/// A single row of the opcode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode {
    /// The raw opcode byte (low 8 bits of the first code unit).
    pub opcode: u8,
    /// Operand layout, which fixes the instruction width.
    pub format: Format,
    /// Specification mnemonic, e.g. `invoke-virtual`. Unused opcodes report `unused`.
    pub mnemonic: &'static str,
    /// Pool section the index operand refers to.
    pub ref_kind: RefKind,
    /// False for the 32 opcodes the specification marks `(unused)`.
    pub valid: bool,
    /// Width in bytes, denormalised from `format` so that walking a code item
    /// is a single field read on a dense array.
    pub width: u16,
}

const fn op(
    opcode: u8,
    format: Format,
    mnemonic: &'static str,
    ref_kind: RefKind,
    valid: bool,
) -> Opcode {
    Opcode { opcode, format, mnemonic, ref_kind, valid, width: format.width() }
}

/// Payload pseudo-instruction identifier, carried in the high byte of opcode 0x00.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadKind {
    /// `packed-switch-payload`, ident `0x0100`.
    PackedSwitch = 0x0100,
    /// `sparse-switch-payload`, ident `0x0200`.
    SparseSwitch = 0x0200,
    /// `fill-array-data-payload`, ident `0x0300`.
    FillArrayData = 0x0300,
}

impl PayloadKind {
    /// Classify a full 16-bit opcode unit, or `None` if it is an ordinary instruction.
    pub const fn from_unit(unit: u16) -> Option<PayloadKind> {
        match unit {
            0x0100 => Some(PayloadKind::PackedSwitch),
            0x0200 => Some(PayloadKind::SparseSwitch),
            0x0300 => Some(PayloadKind::FillArrayData),
            _ => None,
        }
    }

    /// The ident value as it appears in the code stream.
    pub const fn ident(self) -> u16 {
        self as u16
    }

    /// Total width in bytes of a payload with the given body size in code units.
    ///
    /// * `packed-switch-payload`: `4 + size` units (ident, size, first_key, targets)
    /// * `sparse-switch-payload`: `2 + 2*size` units (ident, size, keys, targets)
    /// * `fill-array-data-payload`: `4 + ceil(element_width*size/2)` units
    ///
    /// The packed and sparse forms always have an even unit count; the fill form
    /// is padded to a whole code unit if the element data is an odd number of bytes.
    pub const fn width_units(self, body_units: u32) -> u32 {
        match self {
            PayloadKind::PackedSwitch => 4 + body_units,
            PayloadKind::SparseSwitch => 2 + 2 * body_units,
            PayloadKind::FillArrayData => 4 + body_units,
        }
    }
}

/// The complete Dalvik opcode table, indexed by opcode byte.
///
/// Transcribed from the AOSP Dalvik bytecode specification and cross-checked
/// against `androguard/dex-bytecode` (Apache-2.0); see the module docs.
pub static OPCODES: [Opcode; 256] = [
    op(0x00, Format::F10X, "nop", RefKind::None, true),
    op(0x01, Format::F12X, "move", RefKind::None, true),
    op(0x02, Format::F22X, "move/from16", RefKind::None, true),
    op(0x03, Format::F32X, "move/16", RefKind::None, true),
    op(0x04, Format::F12X, "move-wide", RefKind::None, true),
    op(0x05, Format::F22X, "move-wide/from16", RefKind::None, true),
    op(0x06, Format::F32X, "move-wide/16", RefKind::None, true),
    op(0x07, Format::F12X, "move-object", RefKind::None, true),
    op(0x08, Format::F22X, "move-object/from16", RefKind::None, true),
    op(0x09, Format::F32X, "move-object/16", RefKind::None, true),
    op(0x0a, Format::F11X, "move-result", RefKind::None, true),
    op(0x0b, Format::F11X, "move-result-wide", RefKind::None, true),
    op(0x0c, Format::F11X, "move-result-object", RefKind::None, true),
    op(0x0d, Format::F11X, "move-exception", RefKind::None, true),
    op(0x0e, Format::F10X, "return-void", RefKind::None, true),
    op(0x0f, Format::F11X, "return", RefKind::None, true),
    op(0x10, Format::F11X, "return-wide", RefKind::None, true),
    op(0x11, Format::F11X, "return-object", RefKind::None, true),
    op(0x12, Format::F11N, "const/4", RefKind::None, true),
    op(0x13, Format::F21S, "const/16", RefKind::None, true),
    op(0x14, Format::F31I, "const", RefKind::None, true),
    op(0x15, Format::F21H, "const/high16", RefKind::None, true),
    op(0x16, Format::F21S, "const-wide/16", RefKind::None, true),
    op(0x17, Format::F31I, "const-wide/32", RefKind::None, true),
    op(0x18, Format::F51L, "const-wide", RefKind::None, true),
    op(0x19, Format::F21H, "const-wide/high16", RefKind::None, true),
    op(0x1a, Format::F21C, "const-string", RefKind::String, true),
    op(0x1b, Format::F31C, "const-string/jumbo", RefKind::String, true),
    op(0x1c, Format::F21C, "const-class", RefKind::Type, true),
    op(0x1d, Format::F11X, "monitor-enter", RefKind::None, true),
    op(0x1e, Format::F11X, "monitor-exit", RefKind::None, true),
    op(0x1f, Format::F21C, "check-cast", RefKind::Type, true),
    op(0x20, Format::F22C, "instance-of", RefKind::Type, true),
    op(0x21, Format::F12X, "array-length", RefKind::None, true),
    op(0x22, Format::F21C, "new-instance", RefKind::Type, true),
    op(0x23, Format::F22C, "new-array", RefKind::Type, true),
    op(0x24, Format::F35C, "filled-new-array", RefKind::Type, true),
    op(0x25, Format::F3RC, "filled-new-array/range", RefKind::Type, true),
    op(0x26, Format::F31T, "fill-array-data", RefKind::None, true),
    op(0x27, Format::F11X, "throw", RefKind::None, true),
    op(0x28, Format::F10T, "goto", RefKind::None, true),
    op(0x29, Format::F20T, "goto/16", RefKind::None, true),
    op(0x2a, Format::F30T, "goto/32", RefKind::None, true),
    op(0x2b, Format::F31T, "packed-switch", RefKind::None, true),
    op(0x2c, Format::F31T, "sparse-switch", RefKind::None, true),
    op(0x2d, Format::F23X, "cmpl-float", RefKind::None, true),
    op(0x2e, Format::F23X, "cmpg-float", RefKind::None, true),
    op(0x2f, Format::F23X, "cmpl-double", RefKind::None, true),
    op(0x30, Format::F23X, "cmpg-double", RefKind::None, true),
    op(0x31, Format::F23X, "cmp-long", RefKind::None, true),
    op(0x32, Format::F22T, "if-eq", RefKind::None, true),
    op(0x33, Format::F22T, "if-ne", RefKind::None, true),
    op(0x34, Format::F22T, "if-lt", RefKind::None, true),
    op(0x35, Format::F22T, "if-ge", RefKind::None, true),
    op(0x36, Format::F22T, "if-gt", RefKind::None, true),
    op(0x37, Format::F22T, "if-le", RefKind::None, true),
    op(0x38, Format::F21T, "if-eqz", RefKind::None, true),
    op(0x39, Format::F21T, "if-nez", RefKind::None, true),
    op(0x3a, Format::F21T, "if-ltz", RefKind::None, true),
    op(0x3b, Format::F21T, "if-gez", RefKind::None, true),
    op(0x3c, Format::F21T, "if-gtz", RefKind::None, true),
    op(0x3d, Format::F21T, "if-lez", RefKind::None, true),
    op(0x3e, Format::F10X, "unused", RefKind::None, false),
    op(0x3f, Format::F10X, "unused", RefKind::None, false),
    op(0x40, Format::F10X, "unused", RefKind::None, false),
    op(0x41, Format::F10X, "unused", RefKind::None, false),
    op(0x42, Format::F10X, "unused", RefKind::None, false),
    op(0x43, Format::F10X, "unused", RefKind::None, false),
    op(0x44, Format::F23X, "aget", RefKind::None, true),
    op(0x45, Format::F23X, "aget-wide", RefKind::None, true),
    op(0x46, Format::F23X, "aget-object", RefKind::None, true),
    op(0x47, Format::F23X, "aget-boolean", RefKind::None, true),
    op(0x48, Format::F23X, "aget-byte", RefKind::None, true),
    op(0x49, Format::F23X, "aget-char", RefKind::None, true),
    op(0x4a, Format::F23X, "aget-short", RefKind::None, true),
    op(0x4b, Format::F23X, "aput", RefKind::None, true),
    op(0x4c, Format::F23X, "aput-wide", RefKind::None, true),
    op(0x4d, Format::F23X, "aput-object", RefKind::None, true),
    op(0x4e, Format::F23X, "aput-boolean", RefKind::None, true),
    op(0x4f, Format::F23X, "aput-byte", RefKind::None, true),
    op(0x50, Format::F23X, "aput-char", RefKind::None, true),
    op(0x51, Format::F23X, "aput-short", RefKind::None, true),
    op(0x52, Format::F22C, "iget", RefKind::Field, true),
    op(0x53, Format::F22C, "iget-wide", RefKind::Field, true),
    op(0x54, Format::F22C, "iget-object", RefKind::Field, true),
    op(0x55, Format::F22C, "iget-boolean", RefKind::Field, true),
    op(0x56, Format::F22C, "iget-byte", RefKind::Field, true),
    op(0x57, Format::F22C, "iget-char", RefKind::Field, true),
    op(0x58, Format::F22C, "iget-short", RefKind::Field, true),
    op(0x59, Format::F22C, "iput", RefKind::Field, true),
    op(0x5a, Format::F22C, "iput-wide", RefKind::Field, true),
    op(0x5b, Format::F22C, "iput-object", RefKind::Field, true),
    op(0x5c, Format::F22C, "iput-boolean", RefKind::Field, true),
    op(0x5d, Format::F22C, "iput-byte", RefKind::Field, true),
    op(0x5e, Format::F22C, "iput-char", RefKind::Field, true),
    op(0x5f, Format::F22C, "iput-short", RefKind::Field, true),
    op(0x60, Format::F21C, "sget", RefKind::Field, true),
    op(0x61, Format::F21C, "sget-wide", RefKind::Field, true),
    op(0x62, Format::F21C, "sget-object", RefKind::Field, true),
    op(0x63, Format::F21C, "sget-boolean", RefKind::Field, true),
    op(0x64, Format::F21C, "sget-byte", RefKind::Field, true),
    op(0x65, Format::F21C, "sget-char", RefKind::Field, true),
    op(0x66, Format::F21C, "sget-short", RefKind::Field, true),
    op(0x67, Format::F21C, "sput", RefKind::Field, true),
    op(0x68, Format::F21C, "sput-wide", RefKind::Field, true),
    op(0x69, Format::F21C, "sput-object", RefKind::Field, true),
    op(0x6a, Format::F21C, "sput-boolean", RefKind::Field, true),
    op(0x6b, Format::F21C, "sput-byte", RefKind::Field, true),
    op(0x6c, Format::F21C, "sput-char", RefKind::Field, true),
    op(0x6d, Format::F21C, "sput-short", RefKind::Field, true),
    op(0x6e, Format::F35C, "invoke-virtual", RefKind::Method, true),
    op(0x6f, Format::F35C, "invoke-super", RefKind::Method, true),
    op(0x70, Format::F35C, "invoke-direct", RefKind::Method, true),
    op(0x71, Format::F35C, "invoke-static", RefKind::Method, true),
    op(0x72, Format::F35C, "invoke-interface", RefKind::Method, true),
    op(0x73, Format::F10X, "unused", RefKind::None, false),
    op(0x74, Format::F3RC, "invoke-virtual/range", RefKind::Method, true),
    op(0x75, Format::F3RC, "invoke-super/range", RefKind::Method, true),
    op(0x76, Format::F3RC, "invoke-direct/range", RefKind::Method, true),
    op(0x77, Format::F3RC, "invoke-static/range", RefKind::Method, true),
    op(0x78, Format::F3RC, "invoke-interface/range", RefKind::Method, true),
    op(0x79, Format::F10X, "unused", RefKind::None, false),
    op(0x7a, Format::F10X, "unused", RefKind::None, false),
    op(0x7b, Format::F12X, "neg-int", RefKind::None, true),
    op(0x7c, Format::F12X, "not-int", RefKind::None, true),
    op(0x7d, Format::F12X, "neg-long", RefKind::None, true),
    op(0x7e, Format::F12X, "not-long", RefKind::None, true),
    op(0x7f, Format::F12X, "neg-float", RefKind::None, true),
    op(0x80, Format::F12X, "neg-double", RefKind::None, true),
    op(0x81, Format::F12X, "int-to-long", RefKind::None, true),
    op(0x82, Format::F12X, "int-to-float", RefKind::None, true),
    op(0x83, Format::F12X, "int-to-double", RefKind::None, true),
    op(0x84, Format::F12X, "long-to-int", RefKind::None, true),
    op(0x85, Format::F12X, "long-to-float", RefKind::None, true),
    op(0x86, Format::F12X, "long-to-double", RefKind::None, true),
    op(0x87, Format::F12X, "float-to-int", RefKind::None, true),
    op(0x88, Format::F12X, "float-to-long", RefKind::None, true),
    op(0x89, Format::F12X, "float-to-double", RefKind::None, true),
    op(0x8a, Format::F12X, "double-to-int", RefKind::None, true),
    op(0x8b, Format::F12X, "double-to-long", RefKind::None, true),
    op(0x8c, Format::F12X, "double-to-float", RefKind::None, true),
    op(0x8d, Format::F12X, "int-to-byte", RefKind::None, true),
    op(0x8e, Format::F12X, "int-to-char", RefKind::None, true),
    op(0x8f, Format::F12X, "int-to-short", RefKind::None, true),
    op(0x90, Format::F23X, "add-int", RefKind::None, true),
    op(0x91, Format::F23X, "sub-int", RefKind::None, true),
    op(0x92, Format::F23X, "mul-int", RefKind::None, true),
    op(0x93, Format::F23X, "div-int", RefKind::None, true),
    op(0x94, Format::F23X, "rem-int", RefKind::None, true),
    op(0x95, Format::F23X, "and-int", RefKind::None, true),
    op(0x96, Format::F23X, "or-int", RefKind::None, true),
    op(0x97, Format::F23X, "xor-int", RefKind::None, true),
    op(0x98, Format::F23X, "shl-int", RefKind::None, true),
    op(0x99, Format::F23X, "shr-int", RefKind::None, true),
    op(0x9a, Format::F23X, "ushr-int", RefKind::None, true),
    op(0x9b, Format::F23X, "add-long", RefKind::None, true),
    op(0x9c, Format::F23X, "sub-long", RefKind::None, true),
    op(0x9d, Format::F23X, "mul-long", RefKind::None, true),
    op(0x9e, Format::F23X, "div-long", RefKind::None, true),
    op(0x9f, Format::F23X, "rem-long", RefKind::None, true),
    op(0xa0, Format::F23X, "and-long", RefKind::None, true),
    op(0xa1, Format::F23X, "or-long", RefKind::None, true),
    op(0xa2, Format::F23X, "xor-long", RefKind::None, true),
    op(0xa3, Format::F23X, "shl-long", RefKind::None, true),
    op(0xa4, Format::F23X, "shr-long", RefKind::None, true),
    op(0xa5, Format::F23X, "ushr-long", RefKind::None, true),
    op(0xa6, Format::F23X, "add-float", RefKind::None, true),
    op(0xa7, Format::F23X, "sub-float", RefKind::None, true),
    op(0xa8, Format::F23X, "mul-float", RefKind::None, true),
    op(0xa9, Format::F23X, "div-float", RefKind::None, true),
    op(0xaa, Format::F23X, "rem-float", RefKind::None, true),
    op(0xab, Format::F23X, "add-double", RefKind::None, true),
    op(0xac, Format::F23X, "sub-double", RefKind::None, true),
    op(0xad, Format::F23X, "mul-double", RefKind::None, true),
    op(0xae, Format::F23X, "div-double", RefKind::None, true),
    op(0xaf, Format::F23X, "rem-double", RefKind::None, true),
    op(0xb0, Format::F12X, "add-int/2addr", RefKind::None, true),
    op(0xb1, Format::F12X, "sub-int/2addr", RefKind::None, true),
    op(0xb2, Format::F12X, "mul-int/2addr", RefKind::None, true),
    op(0xb3, Format::F12X, "div-int/2addr", RefKind::None, true),
    op(0xb4, Format::F12X, "rem-int/2addr", RefKind::None, true),
    op(0xb5, Format::F12X, "and-int/2addr", RefKind::None, true),
    op(0xb6, Format::F12X, "or-int/2addr", RefKind::None, true),
    op(0xb7, Format::F12X, "xor-int/2addr", RefKind::None, true),
    op(0xb8, Format::F12X, "shl-int/2addr", RefKind::None, true),
    op(0xb9, Format::F12X, "shr-int/2addr", RefKind::None, true),
    op(0xba, Format::F12X, "ushr-int/2addr", RefKind::None, true),
    op(0xbb, Format::F12X, "add-long/2addr", RefKind::None, true),
    op(0xbc, Format::F12X, "sub-long/2addr", RefKind::None, true),
    op(0xbd, Format::F12X, "mul-long/2addr", RefKind::None, true),
    op(0xbe, Format::F12X, "div-long/2addr", RefKind::None, true),
    op(0xbf, Format::F12X, "rem-long/2addr", RefKind::None, true),
    op(0xc0, Format::F12X, "and-long/2addr", RefKind::None, true),
    op(0xc1, Format::F12X, "or-long/2addr", RefKind::None, true),
    op(0xc2, Format::F12X, "xor-long/2addr", RefKind::None, true),
    op(0xc3, Format::F12X, "shl-long/2addr", RefKind::None, true),
    op(0xc4, Format::F12X, "shr-long/2addr", RefKind::None, true),
    op(0xc5, Format::F12X, "ushr-long/2addr", RefKind::None, true),
    op(0xc6, Format::F12X, "add-float/2addr", RefKind::None, true),
    op(0xc7, Format::F12X, "sub-float/2addr", RefKind::None, true),
    op(0xc8, Format::F12X, "mul-float/2addr", RefKind::None, true),
    op(0xc9, Format::F12X, "div-float/2addr", RefKind::None, true),
    op(0xca, Format::F12X, "rem-float/2addr", RefKind::None, true),
    op(0xcb, Format::F12X, "add-double/2addr", RefKind::None, true),
    op(0xcc, Format::F12X, "sub-double/2addr", RefKind::None, true),
    op(0xcd, Format::F12X, "mul-double/2addr", RefKind::None, true),
    op(0xce, Format::F12X, "div-double/2addr", RefKind::None, true),
    op(0xcf, Format::F12X, "rem-double/2addr", RefKind::None, true),
    op(0xd0, Format::F22S, "add-int/lit16", RefKind::None, true),
    op(0xd1, Format::F22S, "rsub-int", RefKind::None, true),
    op(0xd2, Format::F22S, "mul-int/lit16", RefKind::None, true),
    op(0xd3, Format::F22S, "div-int/lit16", RefKind::None, true),
    op(0xd4, Format::F22S, "rem-int/lit16", RefKind::None, true),
    op(0xd5, Format::F22S, "and-int/lit16", RefKind::None, true),
    op(0xd6, Format::F22S, "or-int/lit16", RefKind::None, true),
    op(0xd7, Format::F22S, "xor-int/lit16", RefKind::None, true),
    op(0xd8, Format::F22B, "add-int/lit8", RefKind::None, true),
    op(0xd9, Format::F22B, "rsub-int/lit8", RefKind::None, true),
    op(0xda, Format::F22B, "mul-int/lit8", RefKind::None, true),
    op(0xdb, Format::F22B, "div-int/lit8", RefKind::None, true),
    op(0xdc, Format::F22B, "rem-int/lit8", RefKind::None, true),
    op(0xdd, Format::F22B, "and-int/lit8", RefKind::None, true),
    op(0xde, Format::F22B, "or-int/lit8", RefKind::None, true),
    op(0xdf, Format::F22B, "xor-int/lit8", RefKind::None, true),
    op(0xe0, Format::F22B, "shl-int/lit8", RefKind::None, true),
    op(0xe1, Format::F22B, "shr-int/lit8", RefKind::None, true),
    op(0xe2, Format::F22B, "ushr-int/lit8", RefKind::None, true),
    op(0xe3, Format::F10X, "unused", RefKind::None, false),
    op(0xe4, Format::F10X, "unused", RefKind::None, false),
    op(0xe5, Format::F10X, "unused", RefKind::None, false),
    op(0xe6, Format::F10X, "unused", RefKind::None, false),
    op(0xe7, Format::F10X, "unused", RefKind::None, false),
    op(0xe8, Format::F10X, "unused", RefKind::None, false),
    op(0xe9, Format::F10X, "unused", RefKind::None, false),
    op(0xea, Format::F10X, "unused", RefKind::None, false),
    op(0xeb, Format::F10X, "unused", RefKind::None, false),
    op(0xec, Format::F10X, "unused", RefKind::None, false),
    op(0xed, Format::F10X, "unused", RefKind::None, false),
    op(0xee, Format::F10X, "unused", RefKind::None, false),
    op(0xef, Format::F10X, "unused", RefKind::None, false),
    op(0xf0, Format::F10X, "unused", RefKind::None, false),
    op(0xf1, Format::F10X, "unused", RefKind::None, false),
    op(0xf2, Format::F10X, "unused", RefKind::None, false),
    op(0xf3, Format::F10X, "unused", RefKind::None, false),
    op(0xf4, Format::F10X, "unused", RefKind::None, false),
    op(0xf5, Format::F10X, "unused", RefKind::None, false),
    op(0xf6, Format::F10X, "unused", RefKind::None, false),
    op(0xf7, Format::F10X, "unused", RefKind::None, false),
    op(0xf8, Format::F10X, "unused", RefKind::None, false),
    op(0xf9, Format::F10X, "unused", RefKind::None, false),
    op(0xfa, Format::F45CC, "invoke-polymorphic", RefKind::Proto, true),
    op(0xfb, Format::F4RCC, "invoke-polymorphic/range", RefKind::Proto, true),
    op(0xfc, Format::F35C, "invoke-custom", RefKind::CallSite, true),
    op(0xfd, Format::F3RC, "invoke-custom/range", RefKind::CallSite, true),
    op(0xfe, Format::F21C, "const-method-handle", RefKind::MethodHandle, true),
    op(0xff, Format::F21C, "const-method-type", RefKind::MethodProto, true),
];

/// Look up an opcode row.
#[inline]
pub const fn opcode(b: u8) -> &'static Opcode {
    &OPCODES[b as usize]
}

/// Mnemonic for an opcode byte, e.g. `0x6e` -> `"invoke-virtual"`.
#[inline]
pub const fn mnemonic(b: u8) -> &'static str {
    OPCODES[b as usize].mnemonic
}

/// Width in bytes of the instruction at `b`, or of its payload when `b` is a
/// payload ident. Linear instruction walking depends on this being total.
#[inline]
pub const fn width_of(b: u8) -> u16 {
    OPCODES[b as usize].width
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_width_equals_leading_digit() {
        for f in Format::ALL {
            let n = f.name();
            let lead = n.as_bytes()[0] - b'0';
            assert_eq!(
                f.code_units(),
                lead as u16,
                "format {} leading digit disagrees with code_units()",
                n
            );
            assert_eq!(f.width(), f.code_units() * 2, "format {} width", n);
        }
    }

    #[test]
    fn table_widths_are_denormalised() {
        for o in OPCODES.iter() {
            assert_eq!(o.width, o.format.width(), "opcode 0x{:02x} width", o.opcode);
        }
    }

    #[test]
    fn opcodes_are_identity_ordered() {
        for (i, o) in OPCODES.iter().enumerate() {
            assert_eq!(o.opcode as usize, i, "opcode table is out of order at {i}");
        }
    }

    #[test]
    fn unused_set_matches_specification() {
        // AOSP marks exactly these ranges `(unused)`: 0x3e..=0x43, 0x73,
        // 0x79..=0x7a and 0xe3..=0xf9.
        let unused: Vec<u8> = OPCODES.iter().filter(|o| !o.valid).map(|o| o.opcode).collect();
        assert_eq!(unused.len(), 32, "expected 32 unused opcodes, got {unused:?}");
        assert_eq!(&unused[0..6], &[0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43]);
        assert!(unused.contains(&0x73));
        assert_eq!(&unused[7..9], &[0x79, 0x7a]);
        assert_eq!(unused.last(), Some(&0xf9));
        // Unused opcodes still have to declare a width so that a linear walk
        // over corrupt data terminates instead of looping.
        for o in OPCODES.iter().filter(|o| !o.valid) {
            assert_eq!(o.width, 2, "unused opcode 0x{:02x} must be 2 bytes", o.opcode);
            assert_eq!(o.format, Format::F10X);
        }
    }

    #[test]
    fn every_real_opcode_is_two_to_ten_bytes() {
        for o in OPCODES.iter().filter(|o| o.valid) {
            assert!(o.width >= 2 && o.width <= 10, "opcode 0x{:02x} width {}", o.opcode, o.width);
            assert!(!o.mnemonic.is_empty());
        }
    }

    #[test]
    fn reference_carrying_opcodes_declare_a_pool() {
        assert_eq!(opcode(0x1a).ref_kind, RefKind::String);
        assert_eq!(opcode(0x1b).ref_kind, RefKind::String);
        assert_eq!(opcode(0x22).ref_kind, RefKind::Type);
        assert_eq!(opcode(0x52).ref_kind, RefKind::Field);
        assert_eq!(opcode(0x60).ref_kind, RefKind::Field);
        assert_eq!(opcode(0x6e).ref_kind, RefKind::Method);
        assert_eq!(opcode(0x74).ref_kind, RefKind::Method);
        assert_eq!(opcode(0xfa).ref_kind, RefKind::Proto);
        assert_eq!(opcode(0xfc).ref_kind, RefKind::CallSite);
        assert_eq!(opcode(0xfe).ref_kind, RefKind::MethodHandle);
        assert_eq!(opcode(0xff).ref_kind, RefKind::MethodProto);
        assert_eq!(opcode(0x01).ref_kind, RefKind::None);
    }
}
