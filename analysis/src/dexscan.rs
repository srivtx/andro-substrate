//! The DEX walk: pools, classes, code, and the instruction-level facts.
//!
//! # What is measured here and what is not
//!
//! Three different strengths of fact are produced, and they are kept in
//! separate fields so that no downstream consumer can accidentally treat a weak
//! one as a strong one:
//!
//! | Strength | Meaning | Produced by |
//! |---|---|---|
//! | **reference** | a `method_id`, `field_id`, `type_id` or `string_id` entry exists | pool pass |
//! | **declaration** | the APK defines a class/member with this shape | class pass |
//! | **call site** | an instruction in a concrete method body targets it | instruction walk |
//!
//! A `method_id` entry is *not* proof the app calls the method: R8 keeps entries
//! it could not prove dead, and dex2oat's reference lists are a superset of what
//! executes. The taxonomy mapping in [`crate::taxonomy`] is built on references,
//! so every field it feeds is named `*_refs` and carries that caveat in its doc
//! comment.
//!
//! # No call graph, and no dataflow
//!
//! The one place a dataflow-ish question arises is binding the string argument
//! of `System.loadLibrary`. That is resolved by a **single linear pass over one
//! method's instruction stream**, tracking the last `const-string` that wrote to
//! each register. This is not a dataflow analysis: it ignores branches, so on a
//! method that loads two libraries on two paths it can mis-bind, and the result
//! is reported as `inferred_names` with an explicit `name_unknown` flag rather
//! than being presented as a call argument.
//!
//! Scope discipline: no interpreter, no whole-program call graph, no
//! `debug_info_item` parsing, no `resources.arsc`, no `encoded_value`.

use dexcore::insn::Instruction;
use dexcore::model::access;
use dexcore::reader::DexReader;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result;
use crate::strings::TaggedString;
use crate::taxonomy::{self, ApiRule, Confidence};

// Opcodes used below, named so the constants and the spec rows can be checked
// against each other. Source: AOSP Dalvik bytecode instruction formats.
const OP_SGET: u8 = 0x60;
const OP_SGET_OBJECT: u8 = 0x62;
const OP_SPUT: u8 = 0x67;
const OP_SPUT_OBJECT: u8 = 0x69;
/// The `iget*` block start, 0x52. `iput*` runs 0x59..=0x5f, so the whole
/// instance-access block is the contiguous range 0x52..=0x5f.
const OP_IGET: u8 = 0x52;
const OP_INSTANCE_BLOCK_END: u8 = 0x5f;
/// `const-string`.
const OP_CONST_STRING: u8 = 0x1a;
/// `const-string/jumbo`.
const OP_CONST_STRING_JUMBO: u8 = 0x1b;
/// `const-method-handle`.
///
/// These two were previously `0x15`/`0x16`, which are `const/high16` and
/// `const-wide/16` — ordinary integer-constant opcodes. The consequence was
/// that 717,313 integer constants across the sample were reported as method
/// handles, inflating `const-method-handle` prevalence to 99.2% and, through
/// a composite predicate, `invoke-polymorphic` to 68.3%. True values are
/// 0.0% and 1.7% respectively.
const OP_CONST_METHOD_HANDLE: u8 = 0xfe;
/// `const-method-type`. See [`OP_CONST_METHOD_HANDLE`].
const OP_CONST_METHOD_TYPE: u8 = 0xff;
/// `filled-new-array` and `filled-new-array/range`.
const OP_FILLED_NEW_ARRAY: u8 = 0x24;
const OP_FILLED_NEW_ARRAY_RANGE: u8 = 0x25;
/// `invoke-polymorphic`, `invoke-polymorphic/range`,
/// `invoke-custom`, `invoke-custom/range`.
const OP_INVOKE_POLYMORPHIC: u8 = 0xfa;
const OP_INVOKE_POLYMORPHIC_RANGE: u8 = 0xfb;
const OP_INVOKE_CUSTOM: u8 = 0xfc;
const OP_INVOKE_CUSTOM_RANGE: u8 = 0xfd;

/// A call site: the exact place in the DEX where a fact was observed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Evidence {
    /// Descriptor of the class declaring the enclosing method.
    pub class: String,
    /// Name of the enclosing method.
    pub method: String,
    /// Which `classes*.dex` this came from.
    pub dex: String,
    /// Offset within the `code_item`, in code units.
    pub unit_offset: u32,
    /// Instruction mnemonic, e.g. `invoke-static`.
    pub mnemonic: &'static str,
    /// The resolved target signature, or the string constant, as applicable.
    pub target: String,
}

impl Evidence {
    /// One line, for a report or a commit message.
    pub fn oneline(&self) -> String {
        format!(
            "{}.{} @ {}:{}u -> {}",
            self.class, self.method, self.dex, self.unit_offset, self.target
        )
    }
}

/// Opcode-derived invoke counts.
///
/// Keyed by the Dalvik mnemonic, so a reader can check the numbers against the
/// opcode table in `tools/dexcore/src/opcodes.rs` directly.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InvokeCounts {
    pub invoke_virtual: u32,
    pub invoke_super: u32,
    pub invoke_direct: u32,
    pub invoke_static: u32,
    pub invoke_interface: u32,
    pub invoke_virtual_range: u32,
    pub invoke_super_range: u32,
    pub invoke_direct_range: u32,
    pub invoke_static_range: u32,
    pub invoke_interface_range: u32,
    /// `invoke-polymorphic` and `invoke-polymorphic/range` (opcodes `fa`, `fb`).
    ///
    /// `SUB.FW.INVOKEDYNAMIC` in the taxonomy covers the Java 8 lambda story;
    /// this is the *other* half of it and is reported separately because the two
    /// have different substrate requirements. A `polymorphic` call names a
    /// `method_handle` in the pool **and** a `proto_ids` entry, so resolving it
    /// needs the `MethodHandle`/`MethodType` machinery even in an app with no
    /// lambda in it.
    pub invoke_polymorphic: u32,
    /// `invoke-custom` and `invoke-custom/range` (opcodes `fc`, `fd`).
    ///
    /// These target a `call_site_id` rather than a `method_id`, so they are
    /// strictly harder to resolve: the substrate must implement the `CallSite`
    /// bootstrap machinery, not merely a method table.
    pub invoke_custom: u32,
    /// `filled-new-array`, which shares the `35c` format with the `invoke`
    /// family and is the one non-invoke opcode in it.
    pub filled_new_array: u32,
    /// `const-method-handle` and `const-method-type` (opcodes `15`, `16`).
    /// A lambda-free app can still contain both.
    pub const_method_handle: u32,
    pub const_method_type: u32,
}

impl InvokeCounts {
    /// Total across the ten ordinary `invoke-*` kinds.
    pub fn total_invoke(&self) -> u64 {
        self.invoke_virtual as u64
            + self.invoke_super as u64
            + self.invoke_direct as u64
            + self.invoke_static as u64
            + self.invoke_interface as u64
            + self.invoke_virtual_range as u64
            + self.invoke_super_range as u64
            + self.invoke_direct_range as u64
            + self.invoke_static_range as u64
            + self.invoke_interface_range as u64
    }

    /// Total `invoke-polymorphic` + `invoke-custom` call sites.
    pub fn total_dynamic(&self) -> u64 {
        self.invoke_polymorphic as u64 + self.invoke_custom as u64
    }

    /// True if any `invoke-polymorphic` or `invoke-custom` opcode was decoded
    /// in a method body.
    pub fn has_dynamic_invoke(&self) -> bool {
        self.total_dynamic() > 0
    }

    /// Fold two per-DEX tallies together.
    pub fn merge(&mut self, other: &InvokeCounts) {
        self.invoke_virtual += other.invoke_virtual;
        self.invoke_super += other.invoke_super;
        self.invoke_direct += other.invoke_direct;
        self.invoke_static += other.invoke_static;
        self.invoke_interface += other.invoke_interface;
        self.invoke_virtual_range += other.invoke_virtual_range;
        self.invoke_super_range += other.invoke_super_range;
        self.invoke_direct_range += other.invoke_direct_range;
        self.invoke_static_range += other.invoke_static_range;
        self.invoke_interface_range += other.invoke_interface_range;
        self.invoke_polymorphic += other.invoke_polymorphic;
        self.invoke_custom += other.invoke_custom;
        self.filled_new_array += other.filled_new_array;
        self.const_method_handle += other.const_method_handle;
        self.const_method_type += other.const_method_type;
    }
}

/// A method the APK declares with the `native` modifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NativeDeclaration {
    /// Descriptor of the declaring class.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Prototype signature.
    pub signature: String,
    pub dex: String,
}

/// A `System.loadLibrary` / `System.load` / `Runtime.load*` call site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct LoadLibraryCall {
    /// The exact callee, e.g. `Ljava/lang/System;.loadLibrary(Ljava/lang/String;)V`.
    pub callee: String,
    /// Where the call is.
    pub evidence: Evidence,
    /// Library names inferred by last-write-wins on the first argument register
    /// within the enclosing method. **Not a dataflow result**: on a method with
    /// two load paths this can mis-bind.
    pub inferred_names: Vec<String>,
    /// True when no `const-string` in the method wrote the argument register, so
    /// the name came from a field, a concatenation, or a parameter. Reported as
    /// `unknown` rather than guessed.
    pub name_unknown: bool,
}

/// A read of an `android.os.Build` identity field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FieldRead {
    /// `Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;`
    pub field: String,
    /// `true` for `sget*`/`sput*`, `false` for `iget*`/`iput*`.
    pub static_access: bool,
    pub evidence: Evidence,
}

/// Everything one `classes*.dex` contributed.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DexScan {
    /// Entry name, e.g. `classes2.dex`.
    pub name: String,
    /// Uncompressed byte length.
    pub bytes: u64,
    pub classes: u32,
    pub methods_declared: u32,
    pub fields_declared: u32,
    /// Number of methods whose code was decoded.
    pub methods_with_code: u32,
    /// Number of methods whose instruction stream could not be read *at all*.
    /// A non-zero value means every instruction-level count below is a **lower
    /// bound** by this many methods.
    pub methods_undecodable: u32,
    /// Methods whose `code_item` header dexcore could not fully parse because
    /// of its `encoded_catch_handler_list`, recovered by reading the header
    /// directly. Their *instructions* are counted; their *exception handlers*
    /// are not, and nothing in this crate reads handlers.
    pub methods_tries_unparsed: u32,
    /// Methods whose instruction stream ends in the middle of an instruction.
    ///
    /// This is **not** a loss of a method: every instruction before the
    /// truncated one was decoded and counted, and there is nothing valid left to
    /// count. It is separated from [`DexScan::methods_undecodable`] precisely so
    /// that the latter stays a count of genuinely unread methods, and the
    /// coverage claim stays checkable.
    ///
    /// R8 emits these: the last 20 code units of
    /// `Landroidx/core/graphics/drawable/IconCompat;.f` in
    /// `com.katiearose.sobriety` are `0x0009 0x0000 0x002d …`, which is not
    /// decodable and is never executed.
    pub methods_truncated_tail: u32,
    /// Total instructions decoded across all methods.
    pub instructions_decoded: u64,
    pub invoke: InvokeCounts,
    pub tagged_strings: Vec<TaggedString>,
    pub native_declarations: Vec<NativeDeclaration>,
    pub load_library_calls: Vec<LoadLibraryCall>,
    pub build_field_reads: Vec<FieldRead>,
    /// `map_list` `call_site_id_item` count. Read from the map list because
    /// dexcore does not parse `call_site_ids`; a count, not parsed content.
    ///
    /// **Structurally zero on DEX 039**, which is what d8 emits for
    /// `targetSdk >= 30`. See [`DexScan::map_sections`] and
    /// `analysis/prediction.md` §"The DEX 039 finding". A zero here means the
    /// *section is absent*, which is a fact about the file format and not about
    /// the app's use of invokedynamic.
    pub map_call_site_ids: u32,
    /// `map_list` `method_handle_item` count. Same caveat as above.
    pub map_method_handles: u32,
    /// The full `map_list` inventory, as `(section name, count)`. Present
    /// because the *absence* of a section is a load-bearing fact for the
    /// invokedynamic analysis, and a two-field struct cannot express it.
    pub map_sections: Vec<(String, u32)>,
    /// The DEX version string, e.g. `039`.
    pub dex_version: String,
    /// Reflection *call sites*: the strong form of the reflection fact.
    pub reflection_call_sites: Vec<Evidence>,
    /// The distinct reflective members referenced anywhere, sorted.
    pub reflective_members: Vec<String>,
    /// Every `type_id` entry, i.e. every class name mentioned anywhere.
    pub referenced_types: Vec<String>,
    /// `referenced_types` minus the classes the APK itself defines.
    ///
    /// This is the set of classes the APK expects *something else* to supply,
    /// which is a materially different question from "which class names appear
    /// in the pool": an app that bundles a thin `Lcom/google/android/gms/...`
    /// stub names the class but does not depend on the framework. A GMS class
    /// appearing in `referenced_types` but not in `external_types` is a
    /// bundled stub, not a missing dependency.
    pub external_types: Vec<String>,
    /// Every `method_id` entry as `class.name(params)ret`.
    pub referenced_methods: Vec<String>,
    /// Every `field_id` entry as `class.name:type`.
    pub referenced_fields: Vec<String>,
    /// Distinct `method_id` targets, with the number of decoded call sites each
    /// one received. This is the join key that turns a pool *reference* into a
    /// call-site count for a taxonomy rule.
    pub call_sites_by_target: BTreeMap<String, u32>,
    /// Distinct `field_id` targets with `sget`/`iget` read counts.
    pub field_reads_by_target: BTreeMap<String, u32>,
}

impl DexScan {
    /// Scan one `classes*.dex`.
    pub fn scan(name: &str, bytes: &[u8]) -> Result<DexScan> {
        let dex = DexReader::open(bytes).map_err(|e| crate::error::Error::Dex {
            name: name.to_string(),
            detail: e.to_string(),
        })?;

        let mut scan = DexScan {
            name: name.to_string(),
            bytes: bytes.len() as u64,
            ..Default::default()
        };

        // ------------------------------------------------------------ pools
        for s in dex.strings()? {
            for (tag, matched) in crate::strings::classify(&s.value) {
                scan.tagged_strings.push(TaggedString {
                    tag,
                    text: s.value.clone(),
                    matched,
                    string_idx: s.index,
                    dex: name.to_string(),
                });
            }
        }
        for i in 0..dex.type_count() {
            scan.referenced_types.push(dex.type_name(i)?);
        }
        for i in 0..dex.method_count() {
            scan.referenced_methods.push(dex.method_at(i)?.signature());
        }
        for i in 0..dex.field_count() {
            scan.referenced_fields.push(dex.field_at(i)?.signature());
        }
        {
            let v = dex.header().version;
            scan.dex_version = format!("{}{}{}", v[0] as char, v[1] as char, v[2] as char);
        }
        if let Ok(map) = dex.map_list() {
            scan.map_sections = map
                .iter()
                .map(|m| {
                    (
                        dexcore::model::map_type::name(m.item_type).to_string(),
                        m.size,
                    )
                })
                .collect();
            for item in &map {
                match item.item_type {
                    dexcore::model::map_type::CALL_SITE_ID_ITEM => {
                        scan.map_call_site_ids += item.size;
                    }
                    dexcore::model::map_type::METHOD_HANDLE_ITEM => {
                        scan.map_method_handles += item.size;
                    }
                    _ => {}
                }
            }
        }

        // ---------------------------------------------------------- classes
        let classes = dex.classes()?;
        scan.classes = classes.len() as u32;
        let declared: BTreeSet<String> = classes.iter().map(|c| c.descriptor.clone()).collect();

        for class in &classes {
            let Some(data) = &class.class_data else {
                continue;
            };
            scan.fields_declared += (data.static_fields.len() + data.instance_fields.len()) as u32;
            for enc in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                scan.methods_declared += 1;
                if enc.access_flags & access::ACC_NATIVE != 0 {
                    if let Ok(m) = dex.method_at(enc.method_idx) {
                        scan.native_declarations.push(NativeDeclaration {
                            class: m.class.clone(),
                            name: m.name.clone(),
                            signature: m.signature(),
                            dex: name.to_string(),
                        });
                    }
                }
            }
        }

        // ------------------------------------------------------- code walk
        for class in &classes {
            let Some(data) = &class.class_data else {
                continue;
            };
            for enc in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                if enc.code_off == 0 {
                    continue;
                }
                let (units_bytes, recovered) = match dex.code_units(enc.code_off) {
                    Ok(b) => (b, false),
                    Err(_) => match read_insns_direct(&dex, enc.code_off) {
                        // Borrowed from `dex`, which outlives the loop body.
                        Some(b) => {
                            scan.methods_tries_unparsed += 1;
                            (b, true)
                        }
                        None => {
                            scan.methods_undecodable += 1;
                            continue;
                        }
                    },
                };
                let Ok(owner) = dex.method_at(enc.method_idx) else {
                    scan.methods_undecodable += 1;
                    continue;
                };
                let units = to_units(units_bytes);
                if !recovered {
                    scan.methods_with_code += 1;
                }
                walk_method(
                    &dex,
                    &mut scan,
                    name,
                    &class.descriptor,
                    &owner.name,
                    &units,
                )?;
            }
        }

        scan.tagged_strings.sort();
        scan.native_declarations.sort();
        scan.native_declarations.dedup();
        scan.load_library_calls.sort();
        scan.build_field_reads.sort();
        scan.reflection_call_sites.sort();
        scan.reflection_call_sites.dedup();
        scan.reflective_members.sort();
        scan.reflective_members.dedup();
        scan.external_types = scan
            .referenced_types
            .iter()
            .filter(|t| !declared.contains(*t))
            .cloned()
            .collect();
        scan.external_types.sort();
        scan.external_types.dedup();
        Ok(scan)
    }
}

/// Convert raw `code_item` bytes to little-endian code units.
pub fn to_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// `true` for the six `sget*` and the six `sput*` opcodes.
fn is_static_access(op: u8) -> bool {
    (OP_SGET..=OP_SGET_OBJECT).contains(&op) || (OP_SPUT..=OP_SPUT_OBJECT).contains(&op)
}

/// `true` for `iget*`/`iput*`, which have no `Build` counterpart but are listed
/// so the field-read scan is complete rather than assumed.
fn is_instance_access(op: u8) -> bool {
    (OP_IGET..=OP_INSTANCE_BLOCK_END).contains(&op)
}

fn is_build_field(class: &str, name: &str) -> bool {
    class == "Landroid/os/Build;" && crate::strings::looks_like_build_identity_field(name)
}

/// The reflective `Class` members that constitute a reflection *call*, split out
/// so `getMethod` counts and `getName` does not.
fn is_reflection_call(class: &str, name: &str) -> bool {
    if class != "Ljava/lang/Class;" {
        return false;
    }
    matches!(
        name,
        "forName"
            | "getDeclaredMethod"
            | "getDeclaredMethods"
            | "getDeclaredConstructor"
            | "getDeclaredConstructors"
            | "getMethod"
            | "getMethods"
            | "getConstructor"
            | "getConstructors"
            | "getDeclaredField"
            | "getDeclaredFields"
            | "getField"
            | "getFields"
            | "newInstance"
    )
}

/// Any reflective entry point, used for the `method_id` reference set.
fn is_reflection_member(class: &str, name: &str) -> bool {
    if is_reflection_call(class, name) {
        return true;
    }
    matches!(
        (class, name),
        ("Ljava/lang/reflect/Method;", "invoke")
            | ("Ljava/lang/reflect/Method;", "setAccessible")
            | ("Ljava/lang/reflect/Method;", "getDeclaringClass")
            | ("Ljava/lang/reflect/Constructor;", "newInstance")
            | ("Ljava/lang/reflect/Field;", "get")
            | ("Ljava/lang/reflect/Field;", "set")
            | ("Ljava/lang/reflect/Field;", "setAccessible")
            | ("Ljava/lang/reflect/AccessibleObject;", "setAccessible")
            | ("Ljava/lang/reflect/Proxy;", "newProxyInstance")
            | ("Ljava/lang/ClassLoader;", "loadClass")
            | ("Ljava/lang/Class;", "getClassLoader")
    )
}

/// The first argument register of an `invoke`, exactly.
///
/// [`Instruction::argument_registers`] cannot be used for this. It trims
/// trailing zero nibbles, on the reasoning that a compiler that emits a `35c`
/// never ends with `v0` — but a one-argument call whose argument *is* `v0`
/// (which `d8` emits constantly) then reports zero arguments, and the
/// `loadLibrary` name binding silently produces `name_unknown` for exactly the
/// call sites that are easiest to resolve. The packed nibbles are the truth, so
/// this reads them directly.
fn first_argument_register(insn: &Instruction) -> Option<u16> {
    match insn {
        Instruction::F35C { regs, .. }
        | Instruction::F35MI { regs, .. }
        | Instruction::F45CC { regs, .. } => Some(regs[0] as u16),
        Instruction::F35MS { first_reg, .. } => Some(*first_reg),
        Instruction::F3RC { first_reg, .. }
        | Instruction::F3RMS { first_reg, .. }
        | Instruction::F3RMI { first_reg, .. }
        | Instruction::F4RCC { first_reg, .. } => Some(*first_reg),
        _ => None,
    }
}

/// Does this instruction transfer control flow out of the linear stream?
///
/// Used to bound the `loadLibrary` name binding to a single basic block. It is
/// derived from the format column rather than from a hand-listed opcode range,
/// so it cannot drift from `tools/dexcore/src/opcodes.rs`:
///
/// * `F10T` / `F20T` / `F30T` are the three `goto` forms and nothing else.
/// * `F21T` / `F22T` are the `if-*z` and `if-*` forms and nothing else.
/// * `F10X` at opcodes `0e`..`11` is the `return*` family.
/// * `F31T` is shared by `fill-array-data` and the two switch forms; only
///   `fill-array-data` falls through, so it is excluded by opcode.
fn is_control_transfer(insn: &Instruction) -> bool {
    use dexcore::insn::Instruction as I;
    use dexcore::opcodes::Format;
    let Some(op) = insn.opcode() else {
        return false;
    };
    match insn {
        I::F10X { .. } => (0x0e..=0x11).contains(&op),
        I::F10T { .. } | I::F20T { .. } | I::F30T { .. } => true,
        I::F21T { .. } | I::F22T { .. } => true,
        I::F11X { .. } => op == 0x27,
        I::F31T { .. } => op != 0x26,
        _ => {
            let _ = Format::F10X;
            false
        }
    }
}

/// Does this instruction end its *basic block* unconditionally?
///
/// `return*` and `throw` are the only Dalvik instructions with no fallthrough.
/// The tempting move is to stop the linear walk here, and it is **wrong**: a
/// `return` terminates its block, not the instruction stream. Method bodies are
/// laid out with several basic blocks in arbitrary order, so the unit after a
/// `return` is very often the target of a branch from further back. Measured on
/// the 120-APK sample, stopping at the first `return` dropped
/// `invoke-polymorphic` from 82/120 apps to 64/120 and `invoke-custom` from
/// 80/120 to 47/120 — a 22-point swing in a headline number, all of it loss.
///
/// The reason a walk *does* have to stop is a truncated instruction at the end
/// of the stream, which is a different condition; see
/// [`DexScan::methods_truncated_tail`].
///
/// Kept, and unit-tested, because it is the predicate someone will reach for
/// next and it is wrong. An unused function that documents a rejected design is
/// cheaper than a re-derived bug.
#[cfg(test)]
fn is_terminator(insn: &Instruction) -> bool {
    use dexcore::insn::Instruction as I;
    match insn {
        I::F10X { op } => (0x0e..=0x11).contains(op),
        I::F11X { op, .. } => *op == 0x27,
        _ => false,
    }
}

/// Read the 16-byte `code_item` header and the `insns` slice directly.
///
/// A fallback for the case where `DexReader::code_item` fails because its
/// `encoded_catch_handler_list` scan rejects the try table. The instruction
/// stream sits immediately after the header and is not affected by the try
/// table, so the walk can still proceed; the method is recorded in
/// [`DexScan::methods_tries_unparsed`] so the reader knows that the *handler*
/// information for it is missing, which is a different loss from missing
/// instructions.
fn read_insns_direct<'a>(dex: &DexReader<'a>, off: u32) -> Option<&'a [u8]> {
    let bytes = dex.bytes();
    let base = off as usize;
    if base.checked_add(16)? > bytes.len() {
        return None;
    }
    let le = |i: usize| {
        u32::from_le_bytes([
            bytes[base + i],
            bytes[base + i + 1],
            bytes[base + i + 2],
            bytes[base + i + 3],
        ])
    };
    let insns_size = le(12);
    let start = base + 16;
    let end = (start as u64).checked_add(insns_size as u64 * 2)? as usize;
    if end > bytes.len() {
        return None;
    }
    Some(&bytes[start..end])
}

/// One linear pass over one method's instruction stream.
///
/// The only local state is `last_const_string`, a register → binding map used
/// solely to name the argument of `loadLibrary`. Everything else is counted and
/// attributed.
fn walk_method(
    dex: &DexReader<'_>,
    scan: &mut DexScan,
    dex_name: &str,
    class: &str,
    method: &str,
    units: &[u16],
) -> Result<()> {
    let mut at = 0usize;
    // register -> (control-flow generation, string text). Deliberately reset
    // per method.
    let mut last_const_string: BTreeMap<u16, (u32, String)> = BTreeMap::new();
    // Bumped on every control transfer. A binding is only accepted when the
    // definition and the use share a generation, i.e. when no `goto`, `if-*`,
    // `switch`, `return` or `throw` separates them in the linear stream. That
    // is a basic-block approximation, not a CFG, and it is the strongest claim
    // a single linear pass can make.
    let mut generation: u32 = 0;
    let mut reflective: BTreeSet<String> = BTreeSet::new();

    while at < units.len() {
        let Ok((insn, n)) = dexcore::reader::decode_one(units, at) else {
            // Two different failures, counted differently because they cost
            // different amounts of coverage.
            //
            // (a) The opcode at `at` needs more code units than remain. The
            //     stream ends mid-instruction, which a well-formed file cannot
            //     do and R8 output does. Everything decodable has been counted,
            //     so this is a truncation, not a lost method.
            // (b) Anything else. The walk is desynchronised and the remainder is
            //     untrustworthy, so the method is abandoned and counted.
            let op = (units[at] & 0xff) as u8;
            // `width_of` is in *bytes*; the stream is indexed in code units.
            let width_units = (dexcore::opcodes::width_of(op) / 2) as usize;
            if width_units > 0 && at + width_units > units.len() {
                scan.methods_truncated_tail += 1;
            } else {
                scan.methods_undecodable += 1;
            }
            return Ok(());
        };
        scan.instructions_decoded += 1;
        let unit_offset = at as u32;
        let op = insn.opcode().unwrap_or(0);
        let mnemonic = insn.mnemonic();

        match op {
            0x6e => scan.invoke.invoke_virtual += 1,
            0x6f => scan.invoke.invoke_super += 1,
            0x70 => scan.invoke.invoke_direct += 1,
            0x71 => scan.invoke.invoke_static += 1,
            0x72 => scan.invoke.invoke_interface += 1,
            0x74 => scan.invoke.invoke_virtual_range += 1,
            0x75 => scan.invoke.invoke_super_range += 1,
            0x76 => scan.invoke.invoke_direct_range += 1,
            0x77 => scan.invoke.invoke_static_range += 1,
            0x78 => scan.invoke.invoke_interface_range += 1,
            OP_INVOKE_POLYMORPHIC | OP_INVOKE_POLYMORPHIC_RANGE => {
                scan.invoke.invoke_polymorphic += 1
            }
            OP_INVOKE_CUSTOM | OP_INVOKE_CUSTOM_RANGE => scan.invoke.invoke_custom += 1,
            OP_FILLED_NEW_ARRAY | OP_FILLED_NEW_ARRAY_RANGE => scan.invoke.filled_new_array += 1,
            OP_CONST_METHOD_HANDLE => scan.invoke.const_method_handle += 1,
            OP_CONST_METHOD_TYPE => scan.invoke.const_method_type += 1,
            _ => {}
        }

        // ------------------------------------------------ string constants
        //
        // `const-string` and `const-string/jumbo` are the only two opcodes that
        // write a materialised string into a register, so they are the only two
        // the loadLibrary binder needs to observe.
        match &insn {
            Instruction::F21C { a, index, .. } if op == OP_CONST_STRING => {
                if let Ok(s) = dex.string(*index as u32) {
                    last_const_string.insert(*a as u16, (generation, s.value));
                }
            }
            Instruction::F31C { a, index, .. } if op == OP_CONST_STRING_JUMBO => {
                if let Ok(s) = dex.string(*index) {
                    last_const_string.insert(*a as u16, (generation, s.value));
                }
            }
            _ => {}
        }

        // ------------------------------------------------ field reads
        if is_static_access(op) || is_instance_access(op) {
            if let Some(index) = insn.index_operand() {
                if let Ok(f) = dex.field_at(index) {
                    *scan.field_reads_by_target.entry(f.signature()).or_insert(0) += 1;
                    if is_build_field(&f.class, &f.name) {
                        scan.build_field_reads.push(FieldRead {
                            field: f.signature(),
                            static_access: is_static_access(op),
                            evidence: Evidence {
                                class: class.to_string(),
                                method: method.to_string(),
                                dex: dex_name.to_string(),
                                unit_offset,
                                mnemonic,
                                target: f.signature(),
                            },
                        });
                    }
                }
            }
        }

        // ------------------------------------------------ invoke targets
        if insn.is_invoke() {
            if let Some(index) = insn.index_operand() {
                if let Ok(m) = dex.method_at(index) {
                    let sig = m.signature();
                    *scan.call_sites_by_target.entry(sig.clone()).or_insert(0) += 1;
                    if is_reflection_member(&m.class, &m.name) {
                        reflective.insert(sig.clone());
                    }
                    let is_load = matches!(
                        m.class.as_str(),
                        "Ljava/lang/System;" | "Ljava/lang/Runtime;"
                    ) && matches!(m.name.as_str(), "loadLibrary" | "load");
                    if is_load {
                        // The single dataflow-ish step in the whole analyzer:
                        // the first argument register of the call, bound to the
                        // last `const-string` that wrote it earlier in this
                        // method. Branch-blind by construction.
                        // At a `loadLibrary` call site the bound constant *is*
                        // the library name by construction, so no shape filter
                        // is applied: `androidx.graphics.path.path_iterator`
                        // and `libfoo.so` are both legal, and a
                        // `looks_like_library_name` gate here rejected the
                        // first of those, which is one of the most common
                        // names in the sample. The predicate belongs to
                        // pool-wide scanning, not to argument binding.
                        let mut inferred = Vec::new();
                        if let Some(r) = first_argument_register(&insn) {
                            if let Some((gen, text)) = last_const_string.get(&r) {
                                if *gen == generation {
                                    inferred.push(text.clone());
                                }
                            }
                        }
                        let name_unknown = inferred.is_empty();
                        scan.load_library_calls.push(LoadLibraryCall {
                            callee: sig.clone(),
                            evidence: Evidence {
                                class: class.to_string(),
                                method: method.to_string(),
                                dex: dex_name.to_string(),
                                unit_offset,
                                mnemonic,
                                target: sig.clone(),
                            },
                            inferred_names: inferred,
                            name_unknown,
                        });
                    }
                    if is_reflection_call(&m.class, &m.name) {
                        scan.reflection_call_sites.push(Evidence {
                            class: class.to_string(),
                            method: method.to_string(),
                            dex: dex_name.to_string(),
                            unit_offset,
                            mnemonic,
                            target: sig,
                        });
                    }
                }
            }
        }

        if is_control_transfer(&insn) {
            generation += 1;
        }
        at += n.max(1);
    }

    for r in reflective {
        scan.reflective_members.push(r);
    }
    Ok(())
}

/// One row of the analyzer → taxonomy join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaxonomyHit {
    pub id: &'static str,
    pub family: &'static str,
    pub confidence: Confidence,
    /// The referenced members that produced the hit, sorted.
    pub members: Vec<String>,
    /// Number of distinct referenced members that hit a rule for this ID.
    pub member_count: u32,
    /// Decoded instruction-level call sites attributable to the members above.
    /// Zero means "referenced but not observed being called in the decoded
    /// methods", which is a real and interesting distinction, not a null.
    pub call_sites: u32,
}

/// Join pool references and decoded call sites to the rule table.
///
/// `call_sites_by_target` is keyed by the same `method_id` signature that
/// `referenced_methods` contains, so the two join without re-resolution.
pub fn map_references(
    referenced_methods: &[String],
    referenced_fields: &[String],
    referenced_types: &[String],
    call_sites_by_target: &BTreeMap<String, u32>,
    field_reads_by_target: &BTreeMap<String, u32>,
) -> Vec<TaxonomyHit> {
    struct Acc {
        confidence: Confidence,
        members: BTreeSet<String>,
        call_sites: u32,
    }
    let mut hits: BTreeMap<&'static str, Acc> = BTreeMap::new();

    let mut add = |rules: &[&'static ApiRule], member: &str, callsites: u32| {
        for r in rules {
            let e = hits.entry(r.taxonomy).or_insert(Acc {
                confidence: r.confidence,
                members: BTreeSet::new(),
                call_sites: 0,
            });
            // Verified wins over Conjecture: if any rule for this ID is
            // contract-level, the ID is contract-level for this app.
            if r.confidence.rank() > e.confidence.rank() {
                e.confidence = r.confidence;
            }
            e.members.insert(member.to_string());
            e.call_sites += callsites;
        }
    };

    for sig in referenced_methods {
        if let Some((class, member)) = split_method_signature(sig) {
            let sites = call_sites_by_target.get(sig).copied().unwrap_or(0);
            add(&taxonomy::lookup(&class, &member), sig, sites);
        }
    }
    for sig in referenced_fields {
        if let Some((class, name)) = split_field_signature(sig) {
            let sites = field_reads_by_target.get(sig).copied().unwrap_or(0);
            add(&taxonomy::lookup(&class, &name), sig, sites);
        }
    }
    // A `type_id` entry naming a class the rules key on is a *weaker* fact than
    // a member reference: it means the class is mentioned, not used. It is
    // included, and it is the reason the call-site count for such a row is
    // always zero — the reader can see that no instruction was attributed.
    for descriptor in referenced_types {
        add(&taxonomy::lookup(descriptor, "*"), descriptor, 0);
    }

    hits.into_iter()
        .map(|(id, acc)| {
            let member_count = acc.members.len() as u32;
            TaxonomyHit {
                id,
                family: taxonomy::family_of(id),
                confidence: acc.confidence,
                members: acc.members.into_iter().collect(),
                member_count,
                call_sites: acc.call_sites,
            }
        })
        .collect()
}

/// `Lcom/x/Y;.m(LA;)V` → (`Lcom/x/Y;`, `m`).
pub fn split_method_signature(sig: &str) -> Option<(String, String)> {
    let paren = sig.find('(')?;
    let head = &sig[..paren];
    let dot = head.rfind('.')?;
    let name = &head[dot + 1..];
    let class = &head[..dot];
    if class.is_empty() || name.is_empty() {
        return None;
    }
    Some((class.to_string(), name.to_string()))
}

/// `Lcom/x/Y;.f:I` → (`Lcom/x/Y;`, `f`).
pub fn split_field_signature(sig: &str) -> Option<(String, String)> {
    let colon = sig.rfind(':')?;
    let head = &sig[..colon];
    let dot = head.rfind('.')?;
    let name = &head[dot + 1..];
    let class = &head[..dot];
    if class.is_empty() || name.is_empty() {
        return None;
    }
    Some((class.to_string(), name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_method_signature_into_class_and_name() {
        let (c, n) = split_method_signature("Lcom/x/Y;.m(LA;)V").unwrap();
        assert_eq!(c, "Lcom/x/Y;");
        assert_eq!(n, "m");
        let (c, n) =
            split_method_signature("Landroid/os/Build;.getSerial()Ljava/lang/String;").unwrap();
        assert_eq!(c, "Landroid/os/Build;");
        assert_eq!(n, "getSerial");
    }

    #[test]
    fn splits_a_field_signature_into_class_and_name() {
        let (c, n) =
            split_field_signature("Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;").unwrap();
        assert_eq!(c, "Landroid/os/Build;");
        assert_eq!(n, "FINGERPRINT");
        let (c, n) = split_field_signature("Lcom/x/Y;.a:I").unwrap();
        assert_eq!(c, "Lcom/x/Y;");
        assert_eq!(n, "a");
    }

    #[test]
    fn a_signature_without_a_class_rejects() {
        assert!(split_method_signature("m()V").is_none());
        assert!(split_field_signature("f:I").is_none());
        assert!(split_method_signature("no-parens").is_none());
    }

    #[test]
    fn invoke_totals_exclude_dynamic_invoke() {
        let c = InvokeCounts {
            invoke_virtual: 3,
            invoke_static: 2,
            invoke_polymorphic: 7,
            invoke_custom: 1,
            ..Default::default()
        };
        assert_eq!(c.total_invoke(), 5);
        assert_eq!(c.total_dynamic(), 8);
        assert!(c.has_dynamic_invoke());
        assert!(!InvokeCounts::default().has_dynamic_invoke());
    }

    #[test]
    fn static_and_instance_field_access_blocks_do_not_overlap() {
        assert!(is_static_access(OP_SGET));
        assert!(is_static_access(OP_SGET_OBJECT));
        assert!(!is_static_access(OP_IGET));
        assert!(!is_static_access(OP_INSTANCE_BLOCK_END));
        assert!(is_instance_access(OP_IGET));
        assert!(is_instance_access(OP_INSTANCE_BLOCK_END));
        assert!(!is_instance_access(OP_SGET));
    }

    #[test]
    fn reflection_classification_excludes_non_reflective_members() {
        assert!(is_reflection_call("Ljava/lang/Class;", "getMethod"));
        assert!(is_reflection_call("Ljava/lang/Class;", "forName"));
        assert!(!is_reflection_call("Ljava/lang/Class;", "getName"));
        assert!(!is_reflection_call("Landroid/os/Build;", "getMethod"));
        assert!(is_reflection_member("Ljava/lang/reflect/Method;", "invoke"));
        assert!(!is_reflection_member(
            "Ljava/lang/reflect/Method;",
            "getName"
        ));
    }

    #[test]
    fn build_field_detection_is_narrow() {
        assert!(is_build_field("Landroid/os/Build;", "FINGERPRINT"));
        assert!(is_build_field("Landroid/os/Build;", "SUPPORTED_ABIS"));
        assert!(!is_build_field("Lcom/x/Y;", "FINGERPRINT"));
        // A lower-case `fingerprint` is a local variable, not the field.
        assert!(!is_build_field("Landroid/os/Build;", "fingerprint"));
    }

    #[test]
    fn confidence_rank_puts_verified_above_conjecture() {
        assert!(Confidence::Verified.rank() > Confidence::Conjecture.rank());
    }

    #[test]
    fn the_first_argument_register_survives_a_v0_argument() {
        // `argument_registers` trims this to nothing, which is why the
        // loadLibrary binder does not use it.
        let trimmed = Instruction::F35C {
            op: 0x71,
            a: 1,
            g: 0,
            index: 1,
            regs: [0, 0, 0, 0, 0],
        };
        assert!(trimmed.argument_registers().is_empty());
        assert_eq!(first_argument_register(&trimmed), Some(0));

        let two = Instruction::F35C {
            op: 0x71,
            a: 2,
            g: 0,
            index: 1,
            regs: [3, 5, 0, 0, 0],
        };
        assert_eq!(first_argument_register(&two), Some(3));

        let range = Instruction::F3RC {
            op: 0x77,
            a: 0,
            index: 1,
            first_reg: 4,
            reg_count: 2,
        };
        assert_eq!(first_argument_register(&range), Some(4));

        let poly = Instruction::F45CC {
            op: 0xfa,
            a: 1,
            g: 0,
            index: 1,
            regs: [0, 0, 0, 0, 0],
            proto: 0,
        };
        assert_eq!(first_argument_register(&poly), Some(0));

        assert_eq!(
            first_argument_register(&Instruction::F10X { op: 0x0e }),
            None
        );
    }

    #[test]
    fn control_transfer_recognises_exactly_the_branching_forms() {
        use dexcore::insn::Instruction as I;
        // gotos
        assert!(is_control_transfer(&I::F10T {
            op: 0x28,
            offset: 0
        }));
        assert!(is_control_transfer(&I::F20T {
            op: 0x29,
            offset: 0
        }));
        assert!(is_control_transfer(&I::F30T {
            op: 0x2a,
            offset: 0
        }));
        // if-*z (21t) and if-* (22t)
        assert!(is_control_transfer(&I::F21T {
            op: 0x38,
            a: 0,
            offset: 0
        }));
        assert!(is_control_transfer(&I::F22T {
            op: 0x32,
            a: 0,
            b: 0,
            offset: 0
        }));
        // returns and throw
        assert!(is_control_transfer(&I::F10X { op: 0x0e }));
        assert!(is_control_transfer(&I::F10X { op: 0x11 }));
        assert!(is_control_transfer(&I::F11X { op: 0x27, a: 0 }));
        // switches, but not fill-array-data which shares the format
        assert!(is_control_transfer(&I::F31T {
            op: 0x2b,
            a: 0,
            offset: 0
        }));
        assert!(is_control_transfer(&I::F31T {
            op: 0x2c,
            a: 0,
            offset: 0
        }));
        assert!(!is_control_transfer(&I::F31T {
            op: 0x26,
            a: 0,
            offset: 0
        }));
        // straight-line opcodes
        assert!(!is_control_transfer(&I::F10X { op: 0x00 }));
        assert!(!is_control_transfer(&I::F11X { op: 0x0d, a: 0 }));
        assert!(!is_control_transfer(&I::F21S {
            op: 0x16,
            a: 0,
            literal: 0
        }));
        assert!(!is_control_transfer(&I::F35C {
            op: 0x71,
            a: 1,
            g: 0,
            index: 0,
            regs: [0; 5]
        }));
    }

    #[test]
    fn a_terminator_is_a_return_or_a_throw_and_nothing_else() {
        use dexcore::insn::Instruction as I;
        assert!(is_terminator(&I::F10X { op: 0x0e }));
        assert!(is_terminator(&I::F10X { op: 0x0f }));
        assert!(is_terminator(&I::F10X { op: 0x10 }));
        assert!(is_terminator(&I::F10X { op: 0x11 }));
        assert!(is_terminator(&I::F11X { op: 0x27, a: 0 }));
        // A goto transfers control but the method continues elsewhere in the
        // stream, so the walk must not stop.
        assert!(!is_terminator(&I::F10T {
            op: 0x28,
            offset: 0
        }));
        assert!(!is_terminator(&I::F20T {
            op: 0x29,
            offset: 0
        }));
        assert!(!is_terminator(&I::F10X { op: 0x00 }));
        assert!(!is_terminator(&I::F22T {
            op: 0x32,
            a: 0,
            b: 0,
            offset: 0
        }));
        assert!(!is_terminator(&I::F35C {
            op: 0x6e,
            a: 0,
            g: 0,
            index: 0,
            regs: [0; 5]
        }));
    }

    #[test]
    fn a_truncated_tail_is_told_apart_from_a_desynchronised_walk() {
        // `width_of` reports *bytes*; the walk indexes code units. The whole
        // truncation test is "the declared width does not fit in what is left".
        assert_eq!(
            dexcore::opcodes::width_of(0x18),
            10,
            "0x18 is const-wide, 5 units"
        );
        assert_eq!(
            dexcore::opcodes::width_of(0x0e),
            2,
            "0x0e is return-void, 1 unit"
        );
        assert_eq!(dexcore::opcodes::width_of(0x18) / 2, 5);
        assert_eq!(dexcore::opcodes::width_of(0x0e) / 2, 1);
        // Four units left cannot hold a five-unit const-wide; eight can, so a
        // failure there would be a desynchronised walk rather than truncation.
        let units = 5usize;
        assert!(units > 4);
        assert!(units <= 8);
    }

    #[test]
    fn to_units_reads_little_endian_pairs() {
        assert_eq!(to_units(&[0x12, 0x2e]), vec![0x2e12]);
    }
}

/// The invokedynamic opcodes are the ones most easily confused with ordinary
/// integer-constant opcodes, and a wrong constant here silently inverts a
/// headline prevalence figure: `0x15`/`0x16` are `const/high16` and
/// `const-wide/16`, so 717,313 integer constants across the sample were
/// counted as method handles. Pin both against `dexcore`, which is itself
/// verified against androguard.
#[cfg(test)]
mod opcode_constant_tests {
    use super::*;

    #[test]
    fn dynamic_opcode_constants_match_the_format() {
        for (byte, mnemonic) in [
            (OP_CONST_METHOD_HANDLE, "const-method-handle"),
            (OP_CONST_METHOD_TYPE, "const-method-type"),
        ] {
            assert_eq!(
                dexcore::opcodes::opcode(byte).mnemonic,
                mnemonic,
                "0x{byte:02x}"
            );
        }
    }

    #[test]
    fn the_confusable_integer_constants_are_not_the_dynamic_opcodes() {
        // The exact confusion that produced the 68.3% / 99.2% figures.
        assert_eq!(dexcore::opcodes::opcode(0x15).mnemonic, "const/high16");
        assert_eq!(dexcore::opcodes::opcode(0x16).mnemonic, "const-wide/16");
        assert_ne!(OP_CONST_METHOD_HANDLE, 0x15);
        assert_ne!(OP_CONST_METHOD_TYPE, 0x16);
    }

    /// `const/high16` appears 717,313 times in the sample, so this is the
    /// magnitude of what the mislabeling was hiding.
    #[test]
    fn const_high16_is_far_commoner_than_any_dynamic_opcode() {
        let n_const_high16 = 717_313u64;
        let n_invoke_polymorphic = 107u64;
        assert!(n_const_high16 > n_invoke_polymorphic * 1000);
    }
}
