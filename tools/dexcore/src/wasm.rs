//! JSON shaping and the `wasm_bindgen` surface for the browser runtime.
//!
//! The shaping functions are public so that a native consumer gets byte-for-byte
//! the same JSON the browser does, and so that `cargo test` on the host covers
//! exactly the code that will run in the browser.
//!
//! Every export takes a `&[u8]` and returns a JSON string rather than a
//! `JsValue`, because every result is a tree. A JS caller does:
//!
//! ```js
//! import init, { parse_dex } from "./pkg/dexcore.js";
//! await init();
//! const summary = JSON.parse(parse_dex(dexBytes));
//! if (summary.error) { ... } else { ... }
//! ```
//!
//! # Errors
//!
//! Nothing here panics or throws. Every fallible path returns a JSON object with
//! an `error` field carrying a stable `kind` discriminant and a human-readable
//! `message`, so a hostile APK degrades to a value the caller can branch on. A
//! caller can therefore treat a `JsValue` return as always-parseable JSON.

use serde::Serialize;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// The pure logic — the JSON shaping, the summary, the class list, the method
// disassembly and the error envelope — is compiled for every target, so
// `cargo test` on the host exercises exactly the code the browser will run. Only
// the four thin `#[wasm_bindgen]` wrappers below are wasm-only.

/// What every export returns: either the payload, or a single `error` field.
///
/// Untagged, so a success is the payload itself and a failure is exactly
/// `{"error": {...}}`. A caller can therefore test `"error" in result` without
/// knowing the payload's shape.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Out<T> {
    Ok(T),
    Err { error: ErrorEnvelope },
}

/// The JSON shape of a failure.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    /// Stable, machine-readable discriminant, e.g. `truncated`.
    pub kind: &'static str,
    /// Human-readable detail.
    pub message: String,
    /// Byte offset or index the failure relates to, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

impl From<&crate::Error> for ErrorEnvelope {
    fn from(e: &crate::Error) -> ErrorEnvelope {
        use crate::Error::*;
        let offset = match e {
            IndexOutOfRange { index, .. } => Some(*index as u64),
            Truncated { need, .. } => Some(*need as u64),
            BadUleb128 { at } | BadMutf8 { at } => Some(*at as u64),
            BadMapEntry { off, .. } => Some(*off as u64),
            SectionOutOfRange { off, .. } => Some(*off as u64),
            BadInstruction { at, .. } => Some(*at as u64),
            BadAxmlString(i) => Some(*i as u64),
            _ => None,
        };
        ErrorEnvelope { kind: e.kind(), message: e.to_string(), offset }
    }
}

/// Serialise a result to a JSON string, never failing.
pub fn finish<T: Serialize>(r: Result<T, crate::Error>) -> String {
    let out = match r {
        Ok(v) => Out::Ok(v),
        Err(e) => Out::Err { error: ErrorEnvelope::from(&e) },
    };
    // A serialisation failure would itself be a bug, not bad input, so fall
    // back to a hand-built error object rather than panicking.
    serde_json::to_string(&out).unwrap_or_else(|e| {
        format!(
            "{{\"error\":{{\"kind\":\"serialize\",\"message\":\"{e}\"}}}}"
        )
    })
}

// ------------------------------------------------------------------ summary

/// Container-level facts about a `classes.dex`.
#[derive(Debug, Serialize)]
pub struct DexSummary {
    /// DEX version digits, e.g. `035`.
    pub version: String,
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: String,
    pub map_off: u32,
    pub data_off: u32,
    pub data_size: u32,
    pub string_count: u32,
    pub type_count: u32,
    pub proto_count: u32,
    pub field_count: u32,
    pub method_count: u32,
    pub class_count: u32,
    /// True when the Adler-32 and SHA-1 both match. False is not fatal for
    /// analysis — repackaging tools often rewrite APKs without recomputing — but
    /// it is worth reporting.
    pub integrity_ok: bool,
    /// Every `map_item`, with its type name, count and offset.
    pub map: Vec<MapEntry>,
    /// How many methods carry a `code_item`.
    pub method_count_with_code: u32,
}

/// One `map_list` row, with the type name resolved.
#[derive(Debug, Serialize)]
pub struct MapEntry {
    pub item_type: u16,
    /// e.g. `code_item`, or `unknown` for an unrecognised type.
    pub name: &'static str,
    pub size: u32,
    pub offset: u32,
}

/// One class, in the shape the UI wants.
#[derive(Debug, Serialize)]
pub struct ClassSummary {
    pub index: u32,
    pub descriptor: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
    pub access_flags: u32,
    pub source_file: String,
    /// Indices into the method pool, in the order `class_defs` stored them.
    pub direct_methods: Vec<u32>,
    pub virtual_methods: Vec<u32>,
    pub static_fields: Vec<u32>,
    pub instance_fields: Vec<u32>,
}

/// One decoded method body, for the disassembly view.
#[derive(Debug, Serialize)]
pub struct MethodSummary {
    pub class: String,
    pub name: String,
    pub signature: String,
    /// e.g. `Ljava/lang/String;.greet(Ljava/lang/String;)I`
    pub method_index: u32,
    pub access_flags: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub insns_size: u32,
    pub tries_size: u16,
    /// The instruction stream, already decoded.
    pub instructions: Vec<InstructionSummary>,
    /// Human-readable notes, e.g. an unresolvable pool index.
    pub warnings: Vec<String>,
}

/// One decoded instruction, flattened for the UI.
#[derive(Debug, Serialize)]
pub struct InstructionSummary {
    /// Offset within the code item, in bytes.
    pub byte_offset: u32,
    /// Offset within the code item, in code units.
    pub unit_offset: u32,
    /// Width in bytes.
    pub width: u16,
    /// The opcode byte, as hex without a prefix.
    pub opcode: String,
    /// The specification mnemonic, e.g. `invoke-virtual`.
    pub mnemonic: &'static str,
    /// One line of disassembly with every pool reference resolved.
    pub text: String,
    /// For a data payload, the decoded body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<PayloadSummary>,
}

/// A decoded data payload.
#[derive(Debug, Serialize)]
pub struct PayloadSummary {
    /// `packed-switch`, `sparse-switch` or `fill-array-data`.
    pub kind: &'static str,
    pub ident: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_key: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub keys: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub targets: Vec<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub element_width: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u32>,
    /// Raw payload bytes, hex-encoded, for `fill-array-data`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_hex: Option<String>,
}

// ------------------------------------------------------------------ exports

/// Parse a `classes.dex` and return a container summary as JSON.
///
/// # Errors
///
/// Returns `{"error": {"kind": ..., "message": ...}}` rather than throwing.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn parse_dex(bytes: &[u8]) -> JsValue {
    JsValue::from_str(&finish(summarise(bytes)))
}

pub fn summarise(bytes: &[u8]) -> Result<DexSummary, crate::Error> {
    let dex = crate::DexReader::open(bytes)?;
    let h = dex.header();
    let integrity_ok = dex.verify_integrity().is_ok();

    let mut map = Vec::new();
    for e in dex.map_list()? {
        map.push(MapEntry {
            item_type: e.item_type,
            name: crate::model::map_type::name(e.item_type),
            size: e.size,
            offset: e.offset,
        });
    }

    let mut with_code = 0u32;
    for ci in 0..dex.class_def_count() {
        if let Ok(Some(d)) = dex.class_def(ci).map(|c| c.class_data) {
            with_code += (d.direct_methods.iter().chain(d.virtual_methods.iter())
                .filter(|m| m.code_off != 0)
                .count()) as u32;
        }
    }

    Ok(DexSummary {
        version: String::from_utf8_lossy(&h.version).into_owned(),
        file_size: h.file_size,
        header_size: h.header_size,
        endian_tag: format!("0x{:08x}", h.endian_tag),
        map_off: h.map_off,
        data_off: h.data_off,
        data_size: h.data_size,
        string_count: dex.string_count(),
        type_count: dex.type_count(),
        proto_count: dex.proto_count(),
        field_count: dex.field_count(),
        method_count: dex.method_count(),
        class_count: dex.class_def_count(),
        integrity_ok,
        map,
        method_count_with_code: with_code,
    })
}

/// List every class in a `classes.dex`, with its members, as JSON.
///
/// # Errors
///
/// Returns `{"error": ...}` rather than throwing.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn list_classes(bytes: &[u8]) -> JsValue {
    JsValue::from_str(&finish(class_list(bytes)))
}

pub fn class_list(bytes: &[u8]) -> Result<Vec<ClassSummary>, crate::Error> {
    let dex = crate::DexReader::open(bytes)?;
    let mut out = Vec::new();
    for ci in 0..dex.class_def_count() {
        let c = dex.class_def(ci)?;
        let (sm, im, sf, inf) = match &c.class_data {
            Some(d) => (
                d.direct_methods.iter().map(|m| m.method_idx).collect(),
                d.virtual_methods.iter().map(|m| m.method_idx).collect(),
                d.static_fields.iter().map(|f| f.field_idx).collect(),
                d.instance_fields.iter().map(|f| f.field_idx).collect(),
            ),
            None => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        };
        out.push(ClassSummary {
            index: ci,
            descriptor: c.descriptor,
            superclass: c.superclass,
            interfaces: c.interfaces,
            access_flags: c.access_flags,
            source_file: c.source_file,
            direct_methods: sm,
            virtual_methods: im,
            static_fields: sf,
            instance_fields: inf,
        });
    }
    Ok(out)
}

/// Decode one method body, with every pool reference resolved, as JSON.
///
/// `class_idx` indexes `class_defs`; `method_idx` indexes that class's
/// *combined* direct-then-virtual method list, matching the order
/// [`list_classes`] reports. Use -1 to decode the first method that has code.
///
/// # Errors
///
/// Returns `{"error": ...}` rather than throwing. An index out of range is an
/// `index_out_of_range` error, not a panic.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn decode_method(bytes: &[u8], class_idx: u32, method_idx: i32) -> JsValue {
    JsValue::from_str(&finish(decode_one_method(bytes, class_idx, method_idx)))
}

pub fn decode_one_method(
    bytes: &[u8],
    class_idx: u32,
    method_idx: i32,
) -> Result<MethodSummary, crate::Error> {
    use crate::insn::Instruction as I;
    use crate::insn::Payload as P;

    let dex = crate::DexReader::open(bytes)?;
    if class_idx >= dex.class_def_count() {
        return Err(crate::Error::IndexOutOfRange {
            pool: "class_defs",
            index: class_idx,
            size: dex.class_def_count(),
        });
    }
    let class = dex.class_def(class_idx)?;
    let data = class
        .class_data
        .ok_or_else(|| crate::Error::MissingCode(class.descriptor.clone()))?;
    let mut all: Vec<&crate::model::EncodedMethod> = Vec::new();
    all.extend(data.direct_methods.iter());
    all.extend(data.virtual_methods.iter());

    let chosen: &crate::model::EncodedMethod = if method_idx < 0 {
        all.iter()
            .find(|m| m.code_off != 0)
            .copied()
            .ok_or_else(|| crate::Error::MissingCode(class.descriptor.clone()))?
    } else {
        *all.get(method_idx as usize).ok_or(crate::Error::IndexOutOfRange {
            pool: "class methods",
            index: method_idx as u32,
            size: all.len() as u32,
        })?
    };

    let m = dex.method_at(chosen.method_idx)?;
    let mut warnings = Vec::new();
    if chosen.code_off == 0 {
        warnings.push("no code_item: the method is abstract or native".to_string());
        let signature = m.signature();
        return Ok(MethodSummary {
            class: m.class,
            name: m.name,
            signature,
            method_index: chosen.method_idx,
            access_flags: chosen.access_flags,
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            insns_size: 0,
            tries_size: 0,
            instructions: Vec::new(),
            warnings,
        });
    }

    let code = dex.code_item(chosen.code_off)?;
    let raw = dex.code_units(chosen.code_off)?;
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let located = crate::decode_all(&units)?;

    let mut instructions = Vec::with_capacity(located.len());
    for l in &located {
        let (text, payload) = render(&dex, &l.instruction, &mut warnings)?;
        instructions.push(InstructionSummary {
            byte_offset: l.byte_offset,
            unit_offset: l.unit_offset,
            width: l.instruction.width(),
            opcode: match l.instruction.opcode() {
                Some(op) => format!("{op:02x}"),
                None => format!("{:04x}", match &l.instruction {
                    I::Payload(p) => match p {
                        P::PackedSwitch(s) => s.ident,
                        P::SparseSwitch(s) => s.ident,
                        P::FillArrayData(f) => f.ident,
                    },
                    _ => 0,
                }),
            },
            mnemonic: l.instruction.mnemonic(),
            text,
            payload,
        });
    }

    let signature = m.signature();
    Ok(MethodSummary {
        class: m.class,
        name: m.name,
        signature,
        method_index: chosen.method_idx,
        access_flags: chosen.access_flags,
        registers_size: code.registers_size,
        ins_size: code.ins_size,
        outs_size: code.outs_size,
        insns_size: code.insns_size,
        tries_size: code.tries_size,
        instructions,
        warnings,
    })
}

/// Render a register number, whatever width the format uses.
fn r<V: Into<u32>>(v: V) -> String {
    format!("v{}", v.into())
}

/// Render one instruction as a line of disassembly, resolving every reference.
fn render(
    dex: &crate::DexReader<'_>,
    insn: &crate::Instruction,
    warnings: &mut Vec<String>,
) -> Result<(String, Option<PayloadSummary>), crate::Error> {
    use crate::insn::Instruction as I;
    use crate::insn::Payload as P;

    fn s(dex: &crate::DexReader<'_>, i: u32, w: &mut Vec<String>) -> String {
        match dex.string(i) {
            Ok(x) => format!("{:?}", x.value),
            Err(_) => {
                w.push(format!("string index {i} is out of range"));
                format!("<string@{i}>")
            }
        }
    }
    fn t(dex: &crate::DexReader<'_>, i: u32, w: &mut Vec<String>) -> String {
        match dex.type_name(i) {
            Ok(x) => x,
            Err(_) => {
                w.push(format!("type index {i} is out of range"));
                format!("<type@{i}>")
            }
        }
    }
    fn f(dex: &crate::DexReader<'_>, i: u32, w: &mut Vec<String>) -> String {
        match dex.field_at(i) {
            Ok(x) => x.signature(),
            Err(_) => {
                w.push(format!("field index {i} is out of range"));
                format!("<field@{i}>")
            }
        }
    }
    fn mth(dex: &crate::DexReader<'_>, i: u32, w: &mut Vec<String>) -> String {
        match dex.method_at(i) {
            Ok(x) => x.signature(),
            Err(_) => {
                w.push(format!("method index {i} is out of range"));
                format!("<method@{i}>")
            }
        }
    }

    // Resolve a pool reference by the kind the opcode table declares for it.
    let refk = insn.entry().map(|e| e.ref_kind).unwrap_or(crate::opcodes::RefKind::None);
    let resolve = |dex: &crate::DexReader<'_>, i: u32, w: &mut Vec<String>| -> String {
        match refk {
            crate::opcodes::RefKind::String => s(dex, i, w),
            crate::opcodes::RefKind::Type => t(dex, i, w),
            crate::opcodes::RefKind::Field => f(dex, i, w),
            crate::opcodes::RefKind::Method => mth(dex, i, w),
            crate::opcodes::RefKind::MethodHandle
            | crate::opcodes::RefKind::MethodProto
            | crate::opcodes::RefKind::Proto
            | crate::opcodes::RefKind::CallSite
            | crate::opcodes::RefKind::None => {
                // The writer never emits these, and the reader does not model
                // their pools, so say so rather than printing a bare number.
                w.push(format!("{refk:?} reference {i} is not resolved: the pool is not modelled"));
                format!("<{refk:?}@{i}>")
            }
        }
    };

    let text = match insn {
        I::F10X { .. } => String::new(),
        I::F10T { offset, .. } => format!("{offset:+}"),
        I::F11N { a, literal, .. } => format!("{}, {}", r(*a), literal),
        I::F11X { a, .. } => r(*a),
        I::F12X { a, b, .. } => format!("{}, {}", r(*a), r(*b)),
        I::F20T { offset, .. } => format!("{offset:+}"),
        I::F20BC { a, index, .. } => format!("{}, <index {}>", r(*a), index),
        I::F21C { a, index, .. } => format!("{}, <{}>", r(*a), resolve(dex, *index as u32, warnings)),
        I::F21H { a, literal, .. } => format!("{}, {} << 16", r(*a), literal),
        I::F21S { a, literal, .. } => format!("{}, {}", r(*a), literal),
        I::F21T { a, offset, .. } => format!("{}, {offset:+}", r(*a)),
        I::F22B { a, b, literal, .. } => format!("{}, {}, {}", r(*a), r(*b), literal),
        I::F22X { a, b, .. } => format!("{}, {}", r(*a), r(*b)),
        I::F22C { a, b, index, .. } => format!("{}, {}, <{}>", r(*a), r(*b), resolve(dex, *index as u32, warnings)),
        I::F22S { a, b, literal, .. } => format!("{}, {}, {}", r(*a), r(*b), literal),
        I::F22T { a, b, offset, .. } => format!("{}, {}, {offset:+}", r(*a), r(*b)),
        I::F22CS { a, b, index, .. } => format!("{}, {}, <{}>", r(*a), r(*b), resolve(dex, *index as u32, warnings)),
        I::F23X { a, b, c, .. } => format!("{}, {}, {}", r(*a), r(*b), r(*c)),
        I::F30T { offset, .. } => format!("{offset:+}"),
        I::F31C { a, index, .. } => format!("{}, <{}>", r(*a), resolve(dex, *index, warnings)),
        I::F31I { a, literal, .. } => format!("{}, {}", r(*a), literal),
        I::F31T { a, offset, .. } => format!("{}, {offset:+}", r(*a)),
        I::F32X { a, b, .. } => format!("v{a}, v{b}"),
        I::F35C { index, .. } | I::F35MI { index, .. } => {
            let args: Vec<String> = insn.argument_registers().iter().map(|&x| r(x)).collect();
            format!("{{{}}}, <{}>", args.join(", "), resolve(dex, *index as u32, warnings))
        }
        I::F35MS { index, first_reg, reg_count, .. } => format!(
            "{{v{} .. v{}}}, <{}>",
            first_reg,
            *first_reg + reg_count.saturating_sub(1),
            resolve(dex, *index as u32, warnings)
        ),
        I::F3RC { index, first_reg, reg_count, .. }
        | I::F3RMI { index, first_reg, reg_count, .. }
        | I::F3RMS { index, first_reg, reg_count, .. } => format!(
            "{{v{} .. v{}}}, <{}>",
            first_reg,
            *first_reg + reg_count.saturating_sub(1),
            resolve(dex, *index as u32, warnings)
        ),
        I::F45CC { index, proto, .. } => {
            let args: Vec<String> = insn.argument_registers().iter().map(|&x| r(x)).collect();
            format!(
                "{{{}}}, <{}>, <proto {}>",
                args.join(", "),
                resolve(dex, *index as u32, warnings),
                proto
            )
        }
        I::F4RCC { index, first_reg, reg_count, proto, .. } => format!(
            "{{v{} .. v{}}}, <{}>, <proto {}>",
            first_reg,
            *first_reg + reg_count.saturating_sub(1),
            resolve(dex, *index as u32, warnings),
            proto
        ),
        I::F51L { a, literal, .. } => format!("{}, {}", r(*a), literal),
        I::F52C { a, b, index, .. } => format!("v{a}, v{b}, <{}>", resolve(dex, *index, warnings)),
        I::F5RC { index, first_reg, reg_count, .. } => format!(
            "{{v{first_reg} .. v{}}}, <{}>",
            first_reg + reg_count.saturating_sub(1),
            resolve(dex, *index, warnings)
        ),
        I::Unused { op } => {
            warnings.push(format!("opcode 0x{op:02x} is unused in the specification"));
            String::new()
        }
        I::Payload(_) => String::new(),
    };

    let payload = match insn {
        I::Payload(P::PackedSwitch(p)) => Some(PayloadSummary {
            kind: "packed-switch",
            ident: p.ident,
            first_key: Some(p.first_key),
            keys: Vec::new(),
            targets: p.targets.clone(),
            element_width: None,
            size: Some(p.targets.len() as u32),
            data_hex: None,
        }),
        I::Payload(P::SparseSwitch(p)) => Some(PayloadSummary {
            kind: "sparse-switch",
            ident: p.ident,
            first_key: None,
            keys: p.keys.clone(),
            targets: p.targets.clone(),
            element_width: None,
            size: Some(p.keys.len() as u32),
            data_hex: None,
        }),
        I::Payload(P::FillArrayData(p)) => Some(PayloadSummary {
            kind: "fill-array-data",
            ident: p.ident,
            first_key: None,
            keys: Vec::new(),
            targets: Vec::new(),
            element_width: Some(p.element_width),
            size: Some(p.size),
            data_hex: Some(p.data.iter().map(|b| format!("{b:02x}")).collect()),
        }),
        _ => None,
    };

    Ok((text, payload))
}

/// A parsed `AndroidManifest.xml`, as JSON.
///
/// # Errors
///
/// Returns `{"error": ...}` rather than throwing.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn parse_axml(bytes: &[u8]) -> JsValue {
    JsValue::from_str(&finish(parse_axml_inner(bytes)))
}

pub fn parse_axml_inner(bytes: &[u8]) -> Result<crate::axml::AxmlDocument, crate::Error> {
    crate::axml::parse(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_input_is_a_typed_json_error() {
        let out = summarise(&[]).unwrap_err();
        assert_eq!(out.kind(), "truncated");
        let json = finish::<DexSummary>(Err(out));
        assert!(json.starts_with("{\"error\":"), "must be nested under `error`: {json}");
        assert!(json.contains("\"kind\":\"truncated\""), "{json}");
    }

    #[test]
    fn bad_magic_reports_bad_magic() {
        let mut bytes = vec![0u8; 128];
        bytes[0..4].copy_from_slice(b"nope");
        let json = finish::<DexSummary>(summarise(&bytes));
        assert!(json.contains("\"kind\":\"bad_magic\""), "{json}");
    }

    #[test]
    fn a_real_fixture_produces_a_summary_with_resolved_fields() {
        let bytes = include_bytes!("../tests/fixtures/com.termux.boot_1000.dex");
        let s = summarise(bytes).expect("a real dex must summarise");
        assert_eq!(s.version, "035");
        assert_eq!(s.class_count, 6);
        assert!(s.integrity_ok, "the fixture's own checksum must verify");
        assert!(s.method_count_with_code > 0);
        assert!(!s.map.is_empty());
        assert_eq!(s.map[0].name, "header_item");
        assert_eq!(s.map[0].offset, 0);
    }

    #[test]
    fn a_real_manifest_parses_to_a_tree() {
        let bytes = include_bytes!("../tests/fixtures/com.termux.boot_1000.axml");
        let d = parse_axml_inner(bytes).expect("a real manifest must parse");
        assert_eq!(d.root.name, "manifest");
        assert_eq!(d.package_name().as_deref(), Some("com.termux.boot"));
        assert!(!d.find_all("application").is_empty());
    }

    #[test]
    fn every_method_in_a_fixture_decodes_or_reports_why_not() {
        let bytes = include_bytes!("../tests/fixtures/com.termux.boot_1000.dex");
        let classes = class_list(bytes).expect("class list");
        assert!(!classes.is_empty());
        let mut decoded = 0;
        for c in &classes {
            for idx in 0..(c.direct_methods.len() + c.virtual_methods.len()) {
                let m = decode_one_method(bytes, c.index, idx as i32).expect("must decode");
                assert!(!m.signature.is_empty());
                if !m.instructions.is_empty() {
                    decoded += 1;
                    assert!(m.warnings.is_empty(), "unexpected warnings: {:?}", m.warnings);
                }
            }
        }
        assert!(decoded > 5, "expected several methods with code, got {decoded}");
    }

    #[test]
    fn an_out_of_range_class_index_is_a_typed_error() {
        let bytes = include_bytes!("../tests/fixtures/com.termux.boot_1000.dex");
        let e = decode_one_method(bytes, 9999, 0).unwrap_err();
        assert_eq!(e.kind(), "index_out_of_range");
    }
}
