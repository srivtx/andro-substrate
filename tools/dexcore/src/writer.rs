//! [`DexWriter`]: build a valid `classes.dex` from scratch.
//!
//! This is the component that makes andro-substrate's architecture possible.
//! The runtime has to fabricate synthetic classes for its `android.*` framework
//! shim and have them resolve in the same classloader as the app's own code.
//! Reading DEX is the common case; *writing* it is what lets the runtime inject
//! those classes.
//!
//! # Ordering constraints
//!
//! A conforming reader (dexlib2, `baksmali`, ART) rejects a DEX file whose id
//! pools are out of order. The specification requires:
//!
//! * `string_ids` sorted by the UTF-16 code point values of their contents
//! * `type_ids` sorted by `string_id` index
//! * `proto_ids` sorted by `(return_type_idx, parameters)`, parameters compared
//!   lexicographically by type index
//! * `field_ids` sorted by `(class_idx, name_idx, type_idx)`
//! * `method_ids` sorted by `(class_idx, name_idx, proto_idx)`
//! * `class_defs` ordered so a superclass or interface always appears *before*
//!   the class referencing it
//!
//! Pools are therefore interned in arbitrary order during construction and
//! sorted at emit time, so callers may add classes and references in any order.
//!
//! # Layout
//!
//! The section order and the `map_list` follow dexlib2's `DexWriter`, the most
//! widely exercised DEX writer in existence:
//!
//! ```text
//! header | string_ids | type_ids | proto_ids | field_ids | method_ids
//!        | class_defs | data:
//!          string_data | type_list | code_item | class_data | map_list
//! ```
//!
//! `code_item` and `type_list` are 4-byte aligned and `map_list` is 4-byte
//! aligned and last, so `data_off` and `data_size` are both even multiples of 4
//! as the specification requires. Map entries are emitted in ascending offset
//! order and never overlap.
//!
//! # Two-phase use
//!
//! Sorting the id pools *renumbers* them, so a `const-string` index that was
//! correct before sorting is wrong after it. Hand-assembled code therefore has
//! to be written against the final indices, which means the builder has two
//! phases:
//!
//! ```no_run
//! # use dexcore::writer::{ClassDef, DexWriter, MethodDef};
//! # fn main() -> dexcore::Result<()> {
//! let mut w = DexWriter::new();
//! w.add_class(ClassDef::root("La;").with_method(MethodDef::abstract_("f", &["I"], "V")));
//!
//! // Phase 1: intern everything and sort. No further references may be added.
//! let idx = w.freeze()?;
//!
//! // Phase 2: assemble code against the *final* indices.
//! let str_idx = idx.string("hello");
//! let mut a = dexcore::asm::Assembler::new();
//! a.const_string(0, str_idx as u16);
//! a.return_void();
//! w.set_code("La;", "f", a.into_code(1, 2, 0))?;
//!
//! // Phase 3: emit.
//! let bytes = w.emit()?;
//! # let _ = bytes; Ok(())
//! # }
//! ```
//!
//! [`DexWriter::emit`] refuses to run with code in it if the builder was never
//! frozen, because the operands could not be trusted.
//!
//! # Scope
//!
//! This writer emits what the runtime needs: a string pool, type/proto/field/
//! method pools, class definitions with encoded class data, and code items with
//! instruction streams, try/catch tables and encoded catch handlers. It does
//! **not** emit debug info, annotations, static-value arrays, call sites or
//! method handles. Those sections are simply omitted, which is legal: the
//! specification marks them optional and `map_list` then omits the
//! corresponding item types.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dex-format>

use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::header::{adler32, sha1, DexHeader, ENDIAN_CONSTANT, HEADER_SIZE, NO_INDEX};
use crate::model::{access, map_type};
use crate::mutf8;

/// A method body to emit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeBody {
    /// Total register file size, including parameters.
    pub registers_size: u16,
    /// Words of incoming arguments.
    pub ins_size: u16,
    /// Words of outgoing argument space.
    pub outs_size: u16,
    /// The instruction stream as little-endian bytes, already assembled.
    /// [`crate::asm::Assembler`] produces this.
    pub insns: Vec<u8>,
    /// Protected ranges and their handlers.
    pub tries: Vec<TryCatch>,
}

/// One protected range plus its handler list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryCatch {
    /// Start address, in code units, relative to the start of the code item.
    pub start_addr: u32,
    /// Length of the protected range, in code units.
    pub insn_count: u32,
    /// The handler list. A `None` type means catch-all and **must come last**,
    /// because the encoding requires it to.
    pub handler: CatchHandler,
}

/// An exception handler list: zero or more typed clauses, optionally a catch-all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatchHandler {
    /// `(catch type descriptor, handler address in code units)` pairs, in the
    /// order the types should be tested.
    pub handlers: Vec<(Option<String>, u32)>,
}

impl CatchHandler {
    /// True if the last clause is a catch-all.
    pub fn is_catch_all(&self) -> bool {
        self.handlers.last().map(|(t, _)| t.is_none()).unwrap_or(false)
    }

    fn validate(&self) -> Result<()> {
        if self.handlers.is_empty() {
            return Err(Error::ValueOutOfRange { what: "catch handler (must have clauses)", value: 0 });
        }
        for (i, (t, _)) in self.handlers.iter().enumerate() {
            if t.is_none() && i + 1 != self.handlers.len() {
                return Err(Error::ValueOutOfRange {
                    what: "catch-all clause position (must be last)",
                    value: i as u64,
                });
            }
        }
        Ok(())
    }
}

/// A field to declare on a synthetic class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDef {
    pub name: String,
    /// Type descriptor, e.g. `I`.
    pub type_descriptor: String,
    /// Bitwise OR of [`access`] constants.
    pub access_flags: u32,
}

impl FieldDef {
    /// A public static field.
    pub fn statics(name: &str, ty: &str) -> FieldDef {
        FieldDef {
            name: name.to_string(),
            type_descriptor: ty.to_string(),
            access_flags: access::ACC_PUBLIC | access::ACC_STATIC,
        }
    }

    /// A public instance field.
    pub fn instance(name: &str, ty: &str) -> FieldDef {
        FieldDef {
            name: name.to_string(),
            type_descriptor: ty.to_string(),
            access_flags: access::ACC_PUBLIC,
        }
    }
}

/// A method to declare on a synthetic class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDef {
    pub name: String,
    /// Parameter descriptors, e.g. `["I", "Ljava/lang/String;"]`.
    pub parameters: Vec<String>,
    /// Return descriptor, e.g. `V`.
    pub return_descriptor: String,
    /// Bitwise OR of [`access`] constants.
    pub access_flags: u32,
    /// The body. `None` for abstract and native methods.
    pub code: Option<CodeBody>,
}

impl MethodDef {
    /// A concrete method.
    pub fn concrete(
        name: &str,
        parameters: &[&str],
        return_descriptor: &str,
        access_flags: u32,
        code: CodeBody,
    ) -> MethodDef {
        MethodDef {
            name: name.to_string(),
            parameters: parameters.iter().map(|s| s.to_string()).collect(),
            return_descriptor: return_descriptor.to_string(),
            access_flags,
            code: Some(code),
        }
    }

    /// An abstract method with no body.
    pub fn abstract_(name: &str, parameters: &[&str], return_descriptor: &str) -> MethodDef {
        MethodDef {
            name: name.to_string(),
            parameters: parameters.iter().map(|s| s.to_string()).collect(),
            return_descriptor: return_descriptor.to_string(),
            access_flags: access::ACC_PUBLIC | access::ACC_ABSTRACT,
            code: None,
        }
    }
}

/// A class to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDef {
    /// Descriptor, e.g. `Landroid/os/Build;`.
    pub descriptor: String,
    /// Superclass descriptor. `None` means "no superclass", which is only legal
    /// for a root class; most shim classes want `Some("Ljava/lang/Object;")`.
    pub superclass: Option<String>,
    /// Interface descriptors.
    pub interfaces: Vec<String>,
    /// Bitwise OR of [`access`] constants.
    pub access_flags: u32,
    /// Source file name recorded in the class def, if any.
    pub source_file: Option<String>,
    pub static_fields: Vec<FieldDef>,
    pub instance_fields: Vec<FieldDef>,
    /// static, private or constructor methods.
    pub direct_methods: Vec<MethodDef>,
    /// everything else.
    pub virtual_methods: Vec<MethodDef>,
}

impl ClassDef {
    /// A class definition, to be filled in by the caller.
    pub fn new(descriptor: impl Into<String>, superclass: Option<String>) -> ClassDef {
        ClassDef {
            descriptor: descriptor.into(),
            superclass,
            interfaces: Vec::new(),
            access_flags: access::ACC_PUBLIC,
            source_file: None,
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            direct_methods: Vec::new(),
            virtual_methods: Vec::new(),
        }
    }

    /// A class extending `Ljava/lang/Object;`, the common shim case.
    pub fn extending_object(descriptor: impl Into<String>) -> ClassDef {
        ClassDef::new(descriptor, Some("Ljava/lang/Object;".to_string()))
    }

    /// A root class, with no superclass at all. Legal, and what
    /// `Ljava/lang/Object;` itself looks like.
    pub fn root(descriptor: impl Into<String>) -> ClassDef {
        ClassDef::new(descriptor, None)
    }

    /// Add a field, choosing static vs instance from the access flags.
    pub fn with_field(mut self, field: FieldDef) -> ClassDef {
        if field.access_flags & access::ACC_STATIC != 0 {
            self.static_fields.push(field);
        } else {
            self.instance_fields.push(field);
        }
        self
    }

    /// Add a method, choosing direct vs virtual from the access flags.
    pub fn with_method(mut self, method: MethodDef) -> ClassDef {
        if method.access_flags & (access::ACC_STATIC | access::ACC_PRIVATE | access::ACC_CONSTRUCTOR)
            != 0
        {
            self.direct_methods.push(method);
        } else {
            self.virtual_methods.push(method);
        }
        self
    }

    /// Every code body on this class: direct methods first, then virtual, in
    /// declaration order. This is the order [`DexWriter::emit`] assigns code
    /// item offsets in.
    fn all_code(&self) -> Vec<&CodeBody> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
            .filter_map(|m| m.code.as_ref())
            .collect()
    }
}

// ---------------------------------------------------------------- interning

/// The mutable pool used while a DEX file is being assembled.
///
/// Indices are *provisional*: they are assigned in insertion order and then
/// permuted by [`Pools::freeze`] to satisfy the specification's sort order.
#[derive(Debug, Clone, Default)]
struct Pool {
    /// MUTF-8 bytes -> provisional string index.
    strings: HashMap<Vec<u8>, usize>,
    /// Provisional string index -> (utf16 length, MUTF-8 bytes).
    string_values: Vec<(u64, Vec<u8>)>,
    /// provisional string index -> provisional type index.
    types: HashMap<usize, usize>,
    /// provisional type index -> provisional string index.
    type_values: Vec<usize>,
    protos: HashMap<(usize, Vec<usize>), usize>,
    /// provisional proto index -> (return type, parameters, shorty string).
    proto_values: Vec<(usize, Vec<usize>, usize)>,
    fields: HashMap<(usize, usize, usize), usize>,
    /// provisional field index -> (class, name string, type).
    field_values: Vec<(usize, usize, usize)>,
    methods: HashMap<(usize, usize, usize), usize>,
    /// provisional method index -> (class, name string, proto).
    method_values: Vec<(usize, usize, usize)>,
}

impl Pool {
    fn add_string(&mut self, s: &str) -> usize {
        let key = mutf8::encode(s);
        if let Some(&i) = self.strings.get(&key) {
            return i;
        }
        let i = self.string_values.len();
        self.strings.insert(key.clone(), i);
        self.string_values.push((mutf8::utf16_len(s), key));
        i
    }

    fn add_type(&mut self, descriptor: &str) -> usize {
        let s = self.add_string(descriptor);
        if let Some(&i) = self.types.get(&s) {
            return i;
        }
        let i = self.type_values.len();
        self.types.insert(s, i);
        self.type_values.push(s);
        i
    }

    /// Intern a prototype. `shorty` must already be interned.
    fn add_proto(&mut self, parameters: &[usize], ret: usize, shorty: &str) -> usize {
        let shorty_idx = self.add_string(shorty);
        if let Some(&i) = self.protos.get(&(ret, parameters.to_vec())) {
            return i;
        }
        let i = self.proto_values.len();
        self.protos.insert((ret, parameters.to_vec()), i);
        self.proto_values.push((ret, parameters.to_vec(), shorty_idx));
        i
    }

    fn add_field(&mut self, class: usize, name: &str, ty: usize) -> usize {
        let n = self.add_string(name);
        if let Some(&i) = self.fields.get(&(class, n, ty)) {
            return i;
        }
        let i = self.field_values.len();
        self.fields.insert((class, n, ty), i);
        self.field_values.push((class, n, ty));
        i
    }

    fn add_method(&mut self, class: usize, name: &str, proto: usize) -> usize {
        let n = self.add_string(name);
        if let Some(&i) = self.methods.get(&(class, n, proto)) {
            return i;
        }
        let i = self.method_values.len();
        self.methods.insert((class, n, proto), i);
        self.method_values.push((class, n, proto));
        i
    }
}

/// The five id pools after sorting, plus provisional-to-final index maps.
#[derive(Debug, Clone, Default)]
struct Pools {
    strings: Vec<u32>,
    types: Vec<u32>,
    /// Provisional proto index -> final proto index. Retained so that a remap
    /// can be applied in the reverse direction for diagnostics.
    #[allow(dead_code)]
    protos: Vec<u32>,
    fields: Vec<u32>,
    methods: Vec<u32>,
    /// Final string index -> (utf16 length, MUTF-8 bytes).
    string_values: Vec<(u64, Vec<u8>)>,
    /// Final type index -> final string index.
    type_values: Vec<u32>,
    /// Final proto index -> (shorty string, return type, parameters).
    proto_values: Vec<(u32, u32, Vec<u32>)>,
    /// Final field index -> (class, name, type).
    field_values: Vec<(u32, u32, u32)>,
    /// Final method index -> (class, name, proto).
    method_values: Vec<(u32, u32, u32)>,
}

impl Pools {
    /// Sort every pool into the order the specification demands.
    fn freeze(pool: &Pool) -> Pools {
        // 1. strings, by UTF-16 code point sequence. Sorting the MUTF-8 bytes
        //    would agree for the BMP but not for U+0000, which is stored as the
        //    two-byte C0 80, so compare the decoded units instead.
        let mut str_order: Vec<usize> = (0..pool.string_values.len()).collect();
        str_order.sort_by(|&a, &b| {
            utf16_units(&pool.string_values[a].1)
                .cmp(&utf16_units(&pool.string_values[b].1))
        });
        let mut strings = vec![0u32; pool.string_values.len()];
        let mut string_values = Vec::with_capacity(str_order.len());
        for (final_i, &prov) in str_order.iter().enumerate() {
            strings[prov] = final_i as u32;
            string_values.push(pool.string_values[prov].clone());
        }

        // 2. types, by final string index.
        let mut type_order: Vec<usize> = (0..pool.type_values.len()).collect();
        type_order.sort_by_key(|&i| strings[pool.type_values[i]]);
        let mut types = vec![0u32; pool.type_values.len()];
        let mut type_values = Vec::with_capacity(type_order.len());
        for (final_i, &prov) in type_order.iter().enumerate() {
            types[prov] = final_i as u32;
            type_values.push(strings[pool.type_values[prov]]);
        }

        // 3. protos, by (return type, parameters) with parameters compared
        //    lexicographically by final type index.
        let mut proto_order: Vec<usize> = (0..pool.proto_values.len()).collect();
        proto_order.sort_by(|&a, &b| {
            let (ra, pa, _) = &pool.proto_values[a];
            let (rb, pb, _) = &pool.proto_values[b];
            types[*ra].cmp(&types[*rb]).then_with(|| {
                let fa: Vec<u32> = pa.iter().map(|&t| types[t]).collect();
                let fb: Vec<u32> = pb.iter().map(|&t| types[t]).collect();
                fa.cmp(&fb)
            })
        });
        let mut protos = vec![0u32; pool.proto_values.len()];
        let mut proto_values = Vec::with_capacity(proto_order.len());
        for (final_i, &prov) in proto_order.iter().enumerate() {
            protos[prov] = final_i as u32;
            let (r, p, s) = &pool.proto_values[prov];
            proto_values.push((strings[*s], types[*r], p.iter().map(|&t| types[t]).collect()));
        }

        // 4. fields, by (class, name, type).
        let mut field_order: Vec<usize> = (0..pool.field_values.len()).collect();
        field_order.sort_by_key(|&i| {
            let (c, n, t) = pool.field_values[i];
            (types[c], strings[n], types[t])
        });
        let mut fields = vec![0u32; pool.field_values.len()];
        let mut field_values = Vec::with_capacity(field_order.len());
        for (final_i, &prov) in field_order.iter().enumerate() {
            fields[prov] = final_i as u32;
            let (c, n, t) = pool.field_values[prov];
            field_values.push((types[c], strings[n], types[t]));
        }

        // 5. methods, by (class, name, proto).
        let mut method_order: Vec<usize> = (0..pool.method_values.len()).collect();
        method_order.sort_by_key(|&i| {
            let (c, n, p) = pool.method_values[i];
            (types[c], strings[n], protos[p])
        });
        let mut methods = vec![0u32; pool.method_values.len()];
        let mut method_values = Vec::with_capacity(method_order.len());
        for (final_i, &prov) in method_order.iter().enumerate() {
            methods[prov] = final_i as u32;
            let (c, n, p) = pool.method_values[prov];
            method_values.push((types[c], strings[n], protos[p]));
        }

        Pools {
            strings,
            types,
            protos,
            fields,
            methods,
            string_values,
            type_values,
            proto_values,
            field_values,
            method_values,
        }
    }

    /// Decode the descriptor of a final type index.
    fn descriptor(&self, type_idx: u32) -> String {
        let s = self.type_values[type_idx as usize];
        let (_, bytes) = &self.string_values[s as usize];
        mutf8::decode(bytes).map(|(d, _)| d).unwrap_or_default()
    }
}

/// Decode MUTF-8 bytes into the UTF-16 code unit sequence used for sorting.
fn utf16_units(mutf8_bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < mutf8_bytes.len() {
        let b0 = mutf8_bytes[i];
        if b0 == 0 {
            break;
        } else if b0 < 0x80 {
            out.push(b0 as u16);
            i += 1;
        } else if b0 & 0xe0 == 0xc0 && i + 1 < mutf8_bytes.len() {
            let b1 = mutf8_bytes[i + 1];
            out.push(((b0 as u16 & 0x1f) << 6) | (b1 as u16 & 0x3f));
            i += 2;
        } else if b0 & 0xf0 == 0xe0 && i + 2 < mutf8_bytes.len() {
            let b1 = mutf8_bytes[i + 1];
            let b2 = mutf8_bytes[i + 2];
            out.push(((b0 as u16 & 0x0f) << 12) | ((b1 as u16 & 0x3f) << 6) | (b2 as u16 & 0x3f));
            i += 3;
        } else {
            i += 1;
        }
    }
    out
}

/// Compute the `shorty` descriptor for a prototype: one character for the
/// return type then one per parameter, `L` for any reference type.
fn shorty_descriptor(params: &[&str], ret: &str) -> String {
    fn c(d: &str) -> char {
        match d {
            "V" => 'V',
            "Z" => 'Z',
            "B" => 'B',
            "S" => 'S',
            "C" => 'C',
            "I" => 'I',
            "J" => 'J',
            "F" => 'F',
            "D" => 'D',
            _ => 'L',
        }
    }
    let mut s = String::with_capacity(params.len() + 1);
    s.push(c(ret));
    s.extend(params.iter().map(|p| c(p)));
    s
}

/// Final pool indices, produced by [`DexWriter::freeze`].
///
/// The indices are stable from the moment `freeze` returns until the builder is
/// dropped: adding a reference afterwards would renumber the pools, which
/// [`DexWriter::add_class`] and the `add_*` methods therefore refuse to do.
#[derive(Debug, Clone, Default)]
pub struct IndexMap {
    pools: Pools,
}


impl IndexMap {
    /// Final index of a string, searching the *final* pool. The `strings` remap
    /// array maps provisional indices to final ones and must never be used to
    /// look anything up, because `string_values` is already in final order.
    fn string_index(&self, value: &str) -> Option<u32> {
        let key = mutf8::encode(value);
        self.pools.string_values.iter().position(|(_, b)| *b == key).map(|i| i as u32)
    }

    /// Index into `string_ids` for a string that has already been interned.
    ///
    /// # Panics
    ///
    /// If the string was never interned. Every string a method body can name
    /// must be interned before [`DexWriter::freeze`], because a body is assembled
    /// against these indices and there is no opportunity to fix one up later.
    pub fn string(&self, value: &str) -> u16 {
        self.string_index(value)
            .unwrap_or_else(|| panic!("{value:?} was not interned before freeze")) as u16
    }

    /// Whether a string is present.
    pub fn has_string(&self, value: &str) -> bool {
        self.string_index(value).is_some()
    }

    /// Index into `type_ids`.
    pub fn type_(&self, descriptor: &str) -> Result<u16> {
        for i in 0..self.pools.type_values.len() {
            if self.descriptor(i as u32)? == descriptor {
                return Ok(i as u16);
            }
        }
        Err(Error::ValueOutOfRange { what: "type descriptor", value: descriptor.len() as u64 })
    }

    /// Index into `field_ids` for `(class, name, type)`.
    pub fn field(&self, class: &str, name: &str, ty: &str) -> Result<u16> {
        let c = self.type_(class)? as u32;
        let t = self.type_(ty)? as u32;
        let n = self
            .string_index(name)
            .ok_or(Error::ValueOutOfRange { what: "field name", value: 0 })?;
        for (i, &(fc, fname, ft)) in self.pools.field_values.iter().enumerate() {
            if fc == c && fname == n && ft == t {
                return Ok(i as u16);
            }
        }
        Err(Error::ValueOutOfRange { what: "field", value: 0 })
    }

    /// Index into `method_ids` for `(class, name, proto)`.
    pub fn method(&self, class: &str, name: &str, params: &[&str], ret: &str) -> Result<u16> {
        let c = self.type_(class)? as u32;
        let p = self.proto(params, ret)?;
        let n = self
            .string_index(name)
            .ok_or(Error::ValueOutOfRange { what: "method name", value: 0 })?;
        for (i, &(mc, mname, mp)) in self.pools.method_values.iter().enumerate() {
            if mc == c && mname == n && mp == p {
                return Ok(i as u16);
            }
        }
        Err(Error::ValueOutOfRange { what: "method", value: 0 })
    }

    /// Index into `proto_ids`.
    pub fn proto(&self, params: &[&str], ret: &str) -> Result<u32> {
        let r = self.type_(ret)?;
        let ps: Vec<u32> = params
            .iter()
            .map(|p| self.type_(p).map(u32::from))
            .collect::<Result<Vec<_>>>()?;
        for (i, (_, rr, pp)) in self.pools.proto_values.iter().enumerate() {
            if *rr == r as u32 && pp == &ps {
                return Ok(i as u32);
            }
        }
        Err(Error::ValueOutOfRange { what: "proto", value: 0 })
    }

    /// Number of strings, and so on, for each pool.
    pub fn counts(&self) -> IndexCounts {
        IndexCounts {
            strings: self.pools.string_values.len(),
            types: self.pools.type_values.len(),
            protos: self.pools.proto_values.len(),
            fields: self.pools.field_values.len(),
            methods: self.pools.method_values.len(),
        }
    }

    /// The type descriptor at a final type index, for diagnostics.
    pub fn descriptor(&self, type_idx: u32) -> Result<&str> {
        let s = self.pools.type_values[type_idx as usize];
        let (_, bytes) = &self.pools.string_values[s as usize];
        // The stored bytes include the terminator, and the descriptor never
        // contains a NUL, so the slice is the descriptor.
        std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| Error::BadMutf8 { at: 0 })
    }
}

/// Pool sizes, for the wasm summary and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexCounts {
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
}

/// The output of phase 1: sorted pools, a resolved class plan, and the code
/// bodies in the order their `code_item` offsets will be assigned.
struct Resolved {
    pools: Pools,
    plan: Vec<ClassPlan>,
    code_bodies: Vec<CodeBody>,
}

impl Pools {
    /// True when two pool sets would assign identical indices, i.e. nothing
    /// observable to a compiled instruction stream has changed.
    fn same_as(&self, other: &Pools) -> bool {
        self.string_values == other.string_values
            && self.type_values == other.type_values
            && self.proto_values == other.proto_values
            && self.field_values == other.field_values
            && self.method_values == other.method_values
    }
}

// ------------------------------------------------------------------- builder

/// Builder for a DEX file.
///
/// Pools are interned on insert, so adding the same string, type, proto, field
/// or method reference twice costs one map lookup and produces one entry. This
/// matters for the runtime's shim, where a hundred synthetic classes all
/// reference `Ljava/lang/Object;` and `Ljava/lang/String;`.
#[derive(Debug, Clone, Default)]
pub struct DexWriter {
    pool: Pool,
    classes: Vec<ClassDef>,
    /// The pools as they stood at the last [`DexWriter::freeze`]. Bodies
    /// installed afterwards do not change these, because `set_code` interns
    /// nothing; anything that *would* change them clears this field, so `emit`
    /// can tell whether the indices the caller compiled against still hold.
    frozen: Option<Pools>,
}


/// One staged class, resolved against the provisional pools.
#[derive(Clone)]
struct ClassPlan {
    class_idx: usize,
    super_idx: usize,
    interfaces: Vec<usize>,
    source_file: Option<usize>,
    static_fields: Vec<(u32, u32)>,
    instance_fields: Vec<(u32, u32)>,
    direct: Vec<MethodSlot>,
    virtual_: Vec<MethodSlot>,
    access_flags: u32,
}

impl std::fmt::Debug for ClassPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassPlan")
            .field("class_idx", &self.class_idx)
            .field("super_idx", &self.super_idx)
            .field("interfaces", &self.interfaces)
            .field("static_fields", &self.static_fields.len())
            .field("instance_fields", &self.instance_fields.len())
            .field("direct", &self.direct.len())
            .field("virtual_methods", &self.virtual_.len())
            .finish()
    }
}

/// One interned method: `(provisional method index, access flags, code index)`.
///
/// The code index is a position in the flat `code_offs` vector, or `u32::MAX`
/// for abstract and native methods, which have no `code_item`.
type MethodSlot = (u32, u32, u32);

impl DexWriter {
    /// An empty builder.
    pub fn new() -> DexWriter {
        DexWriter::default()
    }

    /// Intern a string. Prefer [`DexWriter::add_type`], which interns it too.
    pub fn add_string(&mut self, s: &str) -> u32 {
        self.unfreeze();
        self.pool.add_string(s) as u32
    }

    /// Intern a type descriptor.
    pub fn add_type(&mut self, descriptor: &str) -> u32 {
        self.unfreeze();
        self.pool.add_type(descriptor) as u32
    }

    /// Intern a prototype.
    pub fn add_proto(&mut self, parameters: &[&str], ret: &str) -> u32 {
        self.unfreeze();
        let r = self.pool.add_type(ret);
        let ps: Vec<usize> = parameters.iter().map(|p| self.pool.add_type(p)).collect();
        let shorty = shorty_descriptor(parameters, ret);
        self.pool.add_proto(&ps, r, &shorty) as u32
    }

    /// Intern a field reference.
    pub fn add_field(&mut self, class: &str, name: &str, ty: &str) -> u32 {
        self.unfreeze();
        let c = self.pool.add_type(class);
        let t = self.pool.add_type(ty);
        self.pool.add_field(c, name, t) as u32
    }

    /// Intern a method reference.
    pub fn add_method(&mut self, class: &str, name: &str, parameters: &[&str], ret: &str) -> u32 {
        self.unfreeze();
        let c = self.pool.add_type(class);
        let r = self.pool.add_type(ret);
        let ps: Vec<usize> = parameters.iter().map(|p| self.pool.add_type(p)).collect();
        let shorty = shorty_descriptor(parameters, ret);
        let proto = self.pool.add_proto(&ps, r, &shorty);
        self.pool.add_method(c, name, proto) as u32
    }

    /// Drop the frozen state, which the next `freeze` or `emit` recomputes.
    fn unfreeze(&mut self) {
        self.frozen = None;
    }

    /// Number of interned strings.
    pub fn string_count(&self) -> usize {
        self.pool.string_values.len()
    }

    /// Number of interned types.
    pub fn type_count(&self) -> usize {
        self.pool.type_values.len()
    }

    /// Number of interned protos.
    pub fn proto_count(&self) -> usize {
        self.pool.proto_values.len()
    }

    /// Number of interned field references.
    pub fn field_count(&self) -> usize {
        self.pool.field_values.len()
    }

    /// Number of interned method references.
    pub fn method_count(&self) -> usize {
        self.pool.method_values.len()
    }

    /// Number of class definitions staged for emission.
    pub fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Stage a class definition. Classes may be added in any order; the emit
    /// pass topologically sorts them so superclasses precede subclasses.
    ///
    /// Adding a class invalidates any frozen [`IndexMap`], because a new class
    /// can introduce new pool entries and so renumber the existing ones.
    pub fn add_class(&mut self, class: ClassDef) {
        self.frozen = None;
        self.classes.push(class);
    }

    /// Phase 1: intern every reference the staged classes make, sort the pools,
    /// and return the final indices.
    ///
    /// Code bodies are *not* touched. Assemble them against the returned
    /// [`IndexMap`], install them with [`DexWriter::set_code`], then
    /// [`DexWriter::emit`].
    ///
    /// Calling this more than once is harmless, but anything added in between
    /// invalidates the earlier index map.
    pub fn freeze(&mut self) -> Result<IndexMap> {
        let f = self.resolve()?;
        self.frozen = Some(f.pools.clone());
        Ok(IndexMap { pools: f.pools })
    }

    /// Install the body of a method that has already been declared.
    ///
    /// The method is identified by its defining class descriptor and name; the
    /// first match wins, so a class that overloads a name keeps its first
    /// declaration's body unless the caller disambiguates. Overloads on a
    /// synthetic shim class are vanishingly rare, and the alternative — threading
    /// a synthetic identity through the public API — would be worse.
    pub fn set_code(&mut self, class: &str, method: &str, code: CodeBody) -> Result<()> {
        let descriptor = class.to_string();
        let target = self
            .classes
            .iter_mut()
            .find(|c| c.descriptor == descriptor)
            .ok_or_else(|| Error::MissingSuperclass(descriptor.clone()))?;
        let slot = target
            .direct_methods
            .iter_mut()
            .chain(target.virtual_methods.iter_mut())
            .find(|m| m.name == method)
            .ok_or_else(|| Error::MissingCode(format!("{descriptor}.{method}")))?;
        slot.code = Some(code);
        // Deliberately *not* clearing `frozen`: `set_code` interns nothing, so
        // the pools — and therefore every index the caller already assembled
        // against — are unchanged. Exception handler types the new body names
        // must already have been interned before `freeze`; `emit` checks that
        // rather than silently renumbering.
        Ok(())
    }

    /// Phase 1: the interning, sorting and class-plan resolution that both
    /// `freeze` and `emit` need.
    fn resolve(&self) -> Result<Resolved> {
        let order = self.class_order()?;
        let mut pool = self.pool.clone();
        let mut plan: Vec<ClassPlan> = Vec::with_capacity(order.len());
        let mut code_bodies: Vec<CodeBody> = Vec::new();
        let mut next_code_index = 0usize;

        for &ci in &order {
            let class = &self.classes[ci];
            let class_idx = pool.add_type(&class.descriptor);
            let super_idx = match &class.superclass {
                Some(s) => pool.add_type(s),
                None => usize::MAX,
            };
            let interfaces: Vec<usize> = class.interfaces.iter().map(|i| pool.add_type(i)).collect();

            let mut static_fields = Vec::with_capacity(class.static_fields.len());
            for f in &class.static_fields {
                let t = pool.add_type(&f.type_descriptor);
                static_fields.push((pool.add_field(class_idx, &f.name, t) as u32, f.access_flags));
            }
            let mut instance_fields = Vec::with_capacity(class.instance_fields.len());
            for f in &class.instance_fields {
                let t = pool.add_type(&f.type_descriptor);
                instance_fields
                    .push((pool.add_field(class_idx, &f.name, t) as u32, f.access_flags));
            }

            let direct = intern_methods(
                &mut pool,
                class_idx,
                &class.direct_methods,
                &mut code_bodies,
                &mut next_code_index,
            );
            let virtual_ = intern_methods(
                &mut pool,
                class_idx,
                &class.virtual_methods,
                &mut code_bodies,
                &mut next_code_index,
            );

            // Exception handler clauses are pool references too, so intern them
            // now; by code-blob time every handler type is guaranteed present.
            for body in class.all_code() {
                for t in &body.tries {
                    for (ty, _) in &t.handler.handlers {
                        if let Some(ty) = ty {
                            pool.add_type(ty);
                        }
                    }
                }
            }

            plan.push(ClassPlan {
                class_idx,
                super_idx,
                interfaces,
                source_file: class.source_file.as_ref().map(|s| pool.add_string(s)),
                static_fields,
                instance_fields,
                direct,
                virtual_,
                access_flags: class.access_flags,
            });
        }

        Ok(Resolved { pools: Pools::freeze(&pool), plan, code_bodies })
    }

    // -------------------------------------------------------------- emitting

    /// Phase 3: assemble the DEX file.
    ///
    /// The returned bytes carry a valid Adler-32 checksum, a valid SHA-1
    /// signature, and a `map_list` that lists every section with the correct
    /// offset and count.
    ///
    /// If any class carries code, the builder must have been through
    /// [`DexWriter::freeze`] first: sorting the pools renumbers them, so
    /// operands that were not assembled against the final indices would point
    /// at the wrong entries. Rather than emit a file that is subtly wrong, this
    /// returns [`Error::MissingCode`] explaining what to do.
    ///
    /// Bodies installed with [`DexWriter::set_code`] are exempt from that check
    /// only because `set_code` interns nothing, so it cannot renumber the
    /// pools; the one thing it can get wrong — naming an exception type that
    /// was never interned — is checked here.
    pub fn emit(&self) -> Result<Vec<u8>> {
        let f = self.resolve()?;
        if self.frozen.is_none() && f.code_bodies.iter().any(|b| !b.insns.is_empty()) {
            return Err(Error::MissingCode(
                "code was declared but the builder was never frozen; call \
                 DexWriter::freeze() and assemble against the returned IndexMap"
                    .into(),
            ));
        }
        // If the pools moved after `freeze`, every index the caller compiled
        // against is now wrong, and the file would be subtly corrupt rather
        // than obviously broken. Refuse instead.
        if let Some(frozen) = &self.frozen {
            if !frozen.same_as(&f.pools) {
                return Err(Error::MissingCode(
                    "the pools changed after DexWriter::freeze(); re-freeze and \
                     reassemble the code bodies"
                        .into(),
                ));
            }
        }
        let p = &f.pools;
        let plan = &f.plan;

        // --- the offset-independent data blobs.
        let string_data: Vec<Vec<u8>> = p
            .string_values
            .iter()
            .map(|(utf16, bytes)| {
                let mut v = Vec::with_capacity(bytes.len() + 2);
                mutf8::write_uleb128(&mut v, *utf16 as u32);
                v.extend_from_slice(bytes);
                v
            })
            .collect();

        // type_lists are interned by content and shared between protos and class
        // interface lists, as dexlib2 does.
        let mut type_lists: Vec<Vec<u8>> = Vec::new();
        let mut type_list_index: HashMap<Vec<u32>, u32> = HashMap::new();
        let mut proto_type_lists = Vec::with_capacity(p.proto_values.len());
        for (_, _, params) in &p.proto_values {
            if params.is_empty() {
                proto_type_lists.push(u32::MAX);
            } else {
                proto_type_lists
                    .push(intern_type_list(params, &mut type_lists, &mut type_list_index));
            }
        }
        let mut class_type_lists = Vec::with_capacity(plan.len());
        for c in plan.iter() {
            if c.interfaces.is_empty() {
                class_type_lists.push(u32::MAX);
            } else {
                let types: Vec<u32> = c.interfaces.iter().map(|&t| p.types[t]).collect();
                class_type_lists
                    .push(intern_type_list(&types, &mut type_lists, &mut type_list_index));
            }
        }

        // Exception handler clauses name type descriptors, resolved against the
        // frozen type pool. Every one of them was interned in phase 1, so the
        // lookup cannot fail.
        let mut type_by_descriptor: HashMap<String, u32> = HashMap::new();
        for t in 0..p.type_values.len() {
            type_by_descriptor.insert(p.descriptor(t as u32), t as u32);
        }
        // Every exception handler type must already be a pool entry. If one is
        // missing, the caller installed a body after `freeze` that names a type
        // it had not declared, and honouring it would renumber the pools.
        for (i, body) in f.code_bodies.iter().enumerate() {
            for t in &body.tries {
                for (ty, _) in &t.handler.handlers {
                    if let Some(ty) = ty {
                        if !type_by_descriptor.contains_key(ty) {
                            return Err(Error::ValueOutOfRange {
                                what: "exception handler type (must be interned before freeze)",
                                value: i as u64 ^ ty.len() as u64,
                            });
                        }
                    }
                }
            }
        }
        let code_blobs: Result<Vec<Vec<u8>>> = f
            .code_bodies
            .iter()
            .map(|body| encode_code_item(body, |d| *type_by_descriptor.get(d).unwrap_or(&NO_INDEX)))
            .collect();
        let code_blobs = code_blobs?;

        // --- layout.
        let n_strings = p.string_values.len();
        let n_types = p.type_values.len();
        let n_protos = p.proto_values.len();
        let n_fields = p.field_values.len();
        let n_methods = p.method_values.len();
        let n_classes = plan.len();

        let mut off = HEADER_SIZE;
        let string_ids_off = off;
        off += 4 * n_strings as u32;
        let type_ids_off = off;
        off += 4 * n_types as u32;
        let proto_ids_off = off;
        off += 12 * n_protos as u32;
        let field_ids_off = off;
        off += 8 * n_fields as u32;
        let method_ids_off = off;
        off += 8 * n_methods as u32;
        let class_defs_off = off;
        off += 32 * n_classes as u32;
        let data_off = off;

        // string_data_item: byte aligned, contiguous.
        let mut cursor = data_off;
        let string_data_offs: Vec<u32> = string_data
            .iter()
            .map(|b| {
                let o = cursor;
                cursor += b.len() as u32;
                o
            })
            .collect();

        // type_list: 4-byte aligned.
        let mut type_list_offs = vec![0u32; type_lists.len()];
        for (i, b) in type_lists.iter().enumerate() {
            cursor = align4(cursor);
            type_list_offs[i] = cursor;
            cursor += b.len() as u32;
        }

        // code_item: 4-byte aligned.
        let mut code_offs = vec![0u32; code_blobs.len()];
        for (i, b) in code_blobs.iter().enumerate() {
            cursor = align4(cursor);
            code_offs[i] = cursor;
            cursor += b.len() as u32;
        }

        // class_data_item: byte aligned, and only now that code offsets exist.
        let class_data_blobs: Vec<Vec<u8>> = plan
            .iter()
            .map(|c| encode_class_data(c, p, &code_offs))
            .collect::<Result<Vec<_>>>()?;
        let class_data_offs: Vec<u32> = class_data_blobs
            .iter()
            .map(|b| {
                let o = cursor;
                cursor += b.len() as u32;
                o
            })
            .collect();

        // map_list: 4-byte aligned and last.
        let mut map_entries: Vec<(u16, u32, u32)> = vec![(map_type::HEADER_ITEM, 1, 0)];
        if n_strings > 0 {
            map_entries.push((map_type::STRING_ID_ITEM, n_strings as u32, string_ids_off));
        }
        if n_types > 0 {
            map_entries.push((map_type::TYPE_ID_ITEM, n_types as u32, type_ids_off));
        }
        if n_protos > 0 {
            map_entries.push((map_type::PROTO_ID_ITEM, n_protos as u32, proto_ids_off));
        }
        if n_fields > 0 {
            map_entries.push((map_type::FIELD_ID_ITEM, n_fields as u32, field_ids_off));
        }
        if n_methods > 0 {
            map_entries.push((map_type::METHOD_ID_ITEM, n_methods as u32, method_ids_off));
        }
        if n_classes > 0 {
            map_entries.push((map_type::CLASS_DEF_ITEM, n_classes as u32, class_defs_off));
        }
        if n_strings > 0 {
            map_entries.push((map_type::STRING_DATA_ITEM, n_strings as u32, string_data_offs[0]));
        }
        if !type_lists.is_empty() {
            map_entries.push((
                map_type::TYPE_LIST,
                type_lists.len() as u32,
                type_list_offs.iter().copied().filter(|&o| o != 0).min().unwrap_or(0),
            ));
        }
        if !code_blobs.is_empty() {
            map_entries.push((map_type::CODE_ITEM, code_blobs.len() as u32, code_offs[0]));
        }
        if !class_data_blobs.is_empty() {
            map_entries.push((
                map_type::CLASS_DATA_ITEM,
                class_data_blobs.len() as u32,
                class_data_offs[0],
            ));
        }

        cursor = align4(cursor);
        let map_off = cursor;
        map_entries.push((map_type::MAP_LIST, 1, map_off));
        cursor += 4 + 12 * map_entries.len() as u32;
        let file_size = cursor;

        // --- serialise.
        let mut out = vec![0u8; file_size as usize];

        for (i, &off) in string_data_offs.iter().enumerate() {
            put_u32(&mut out, string_ids_off as usize + i * 4, off);
        }
        for (i, s) in p.type_values.iter().enumerate() {
            put_u32(&mut out, type_ids_off as usize + i * 4, *s);
        }
        for (i, (shorty, ret, _)) in p.proto_values.iter().enumerate() {
            let base = proto_ids_off as usize + i * 12;
            put_u32(&mut out, base, *shorty);
            put_u32(&mut out, base + 4, *ret);
            let tl = proto_type_lists[i];
            put_u32(&mut out, base + 8, if tl == u32::MAX { 0 } else { type_list_offs[tl as usize] });
        }
        for (i, (c, n, t)) in p.field_values.iter().enumerate() {
            let base = field_ids_off as usize + i * 8;
            put_u16(&mut out, base, *c as u16);
            put_u16(&mut out, base + 2, *t as u16);
            put_u32(&mut out, base + 4, *n);
        }
        for (i, (c, n, pr)) in p.method_values.iter().enumerate() {
            let base = method_ids_off as usize + i * 8;
            put_u16(&mut out, base, *c as u16);
            put_u16(&mut out, base + 2, *pr as u16);
            put_u32(&mut out, base + 4, *n);
        }
        for (i, c) in plan.iter().enumerate() {
            let base = class_defs_off as usize + i * 32;
            put_u32(&mut out, base, p.types[c.class_idx]);
            put_u32(&mut out, base + 4, c.access_flags);
            put_u32(
                &mut out,
                base + 8,
                if c.super_idx == usize::MAX { NO_INDEX } else { p.types[c.super_idx] },
            );
            let tl = class_type_lists[i];
            put_u32(&mut out, base + 12, if tl == u32::MAX { 0 } else { type_list_offs[tl as usize] });
            put_u32(
                &mut out,
                base + 16,
                c.source_file.map(|s| p.strings[s]).unwrap_or(NO_INDEX),
            );
            put_u32(&mut out, base + 20, 0); // annotations_off
            put_u32(&mut out, base + 24, class_data_offs[i]);
            put_u32(&mut out, base + 28, 0); // static_values_off
        }

        for (b, o) in string_data.iter().zip(&string_data_offs) {
            out[*o as usize..*o as usize + b.len()].copy_from_slice(b);
        }
        for (b, o) in type_lists.iter().zip(&type_list_offs) {
            out[*o as usize..*o as usize + b.len()].copy_from_slice(b);
        }
        for (b, o) in code_blobs.iter().zip(&code_offs) {
            out[*o as usize..*o as usize + b.len()].copy_from_slice(b);
        }
        for (b, o) in class_data_blobs.iter().zip(&class_data_offs) {
            out[*o as usize..*o as usize + b.len()].copy_from_slice(b);
        }

        put_u32(&mut out, map_off as usize, map_entries.len() as u32);
        for (i, (t, size, o)) in map_entries.iter().enumerate() {
            let base = map_off as usize + 4 + i * 12;
            put_u16(&mut out, base, *t);
            put_u16(&mut out, base + 2, 0);
            put_u32(&mut out, base + 4, *size);
            put_u32(&mut out, base + 8, *o);
        }

        // --- header, then signature, then checksum.
        let header = DexHeader {
            version: *b"035",
            checksum: 0,
            signature: [0u8; 20],
            file_size,
            header_size: HEADER_SIZE,
            endian_tag: ENDIAN_CONSTANT,
            link_size: 0,
            link_off: 0,
            map_off,
            string_ids_size: n_strings as u32,
            string_ids_off: if n_strings > 0 { string_ids_off } else { 0 },
            type_ids_size: n_types as u32,
            type_ids_off: if n_types > 0 { type_ids_off } else { 0 },
            proto_ids_size: n_protos as u32,
            proto_ids_off: if n_protos > 0 { proto_ids_off } else { 0 },
            field_ids_size: n_fields as u32,
            field_ids_off: if n_fields > 0 { field_ids_off } else { 0 },
            method_ids_size: n_methods as u32,
            method_ids_off: if n_methods > 0 { method_ids_off } else { 0 },
            class_defs_size: n_classes as u32,
            class_defs_off: if n_classes > 0 { class_defs_off } else { 0 },
            data_size: file_size - data_off,
            data_off,
        };
        out[..HEADER_SIZE as usize].copy_from_slice(&header.to_bytes());

        // Order matters. The SHA-1 covers `out[32..]`, which excludes both the
        // checksum and the signature, so it goes first. The Adler-32 covers
        // `out[12..]`, which *includes* the signature field, so it goes second.
        // dexlib2's DexWriter writes them in the same order.
        let signature = sha1(&out[32..]);
        out[12..32].copy_from_slice(&signature);
        let checksum = adler32(&out[12..]);
        put_u32(&mut out, 8, checksum);

        Ok(out)
    }

    /// Order the staged classes so every in-file superclass and interface comes
    /// before the class that references it.
    fn class_order(&self) -> Result<Vec<usize>> {
        let mut seen: HashMap<&str, usize> = HashMap::new();
        for (i, c) in self.classes.iter().enumerate() {
            if seen.insert(c.descriptor.as_str(), i).is_some() {
                return Err(Error::DuplicateClass(c.descriptor.clone()));
            }
        }
        let mut emitted = vec![false; self.classes.len()];
        let mut order = Vec::with_capacity(self.classes.len());
        let mut progress = true;
        while order.len() < self.classes.len() {
            if !progress {
                return Err(Error::CyclicClassHierarchy(self.classes.len() - order.len()));
            }
            progress = false;
            for i in 0..self.classes.len() {
                if emitted[i] {
                    continue;
                }
                let c = &self.classes[i];
                let deps: Vec<Option<usize>> = c
                    .superclass
                    .iter()
                    .map(|s| seen.get(s.as_str()).copied())
                    .chain(c.interfaces.iter().map(|s| seen.get(s.as_str()).copied()))
                    .collect();
                if deps.iter().flatten().all(|&d| emitted[d]) {
                    emitted[i] = true;
                    order.push(i);
                    progress = true;
                }
            }
        }
        Ok(order)
    }
}

/// Intern a `type_list` by content, appending the encoded list to `lists`.
fn intern_type_list(
    types: &[u32],
    lists: &mut Vec<Vec<u8>>,
    index: &mut HashMap<Vec<u32>, u32>,
) -> u32 {
    if let Some(&i) = index.get(types) {
        return i;
    }
    let i = lists.len() as u32;
    let mut v = Vec::with_capacity(4 + types.len() * 2);
    v.extend_from_slice(&(types.len() as u32).to_le_bytes());
    for t in types {
        v.extend_from_slice(&t.to_le_bytes());
    }
    lists.push(v);
    index.insert(types.to_vec(), i);
    i
}

/// Intern a class's methods, appending their code bodies to `code_bodies`.
///
/// Each returned slot records the body's index in `code_bodies`, taken from
/// `next_code_index`, so the index survives the sort that `encode_class_data`
/// applies to satisfy the specification's increasing-`method_idx` requirement.
fn intern_methods(
    pool: &mut Pool,
    class_idx: usize,
    methods: &[MethodDef],
    code_bodies: &mut Vec<CodeBody>,
    next_code_index: &mut usize,
) -> Vec<MethodSlot> {
    let mut out = Vec::with_capacity(methods.len());
    for m in methods {
        let r = pool.add_type(&m.return_descriptor);
        let ps: Vec<usize> = m.parameters.iter().map(|p| pool.add_type(p)).collect();
        let shorty = shorty_descriptor(
            &m.parameters.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            &m.return_descriptor,
        );
        let proto = pool.add_proto(&ps, r, &shorty);
        let mi = pool.add_method(class_idx, &m.name, proto) as u32;
        let code_idx = match &m.code {
            Some(c) => {
                let i = *next_code_index;
                code_bodies.push(c.clone());
                *next_code_index += 1;
                i as u32
            }
            None => u32::MAX,
        };
        out.push((mi, m.access_flags, code_idx));
    }
    out
}

/// Encode a `class_data_item`, remapping provisional field and method indices
/// through the frozen pools and splicing in the code item offsets.
///
/// `encoded_field` and `encoded_method` store the *delta* from the previous
/// index, which is only representable as a ULEB128 if the list is sorted by
/// increasing index. The specification requires the producer to have sorted
/// them, and callers may declare members in any order, so the lists are sorted
/// here — after remapping, because the final index is what has to be increasing.
fn encode_class_data(plan: &ClassPlan, p: &Pools, code_offs: &[u32]) -> Result<Vec<u8>> {
    let remap_fields = |v: &[(u32, u32)]| -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> =
            v.iter().map(|&(f, flags)| (p.fields[f as usize], flags)).collect();
        out.sort_by_key(|&(f, _)| f);
        out
    };
    let remap_methods = |v: &[(u32, u32, u32)]| -> Vec<(u32, u32, u32)> {
        let mut out: Vec<(u32, u32, u32)> = v
            .iter()
            .map(|&(m, flags, slot)| (p.methods[m as usize], flags, slot))
            .collect();
        out.sort_by_key(|&(m, _, _)| m);
        out
    };

    let static_fields = remap_fields(&plan.static_fields);
    let instance_fields = remap_fields(&plan.instance_fields);
    let direct = remap_methods(&plan.direct);
    let virtual_ = remap_methods(&plan.virtual_);

    // Duplicates would make a delta of zero, which the format allows but which
    // would mean the same field or method was declared twice.
    for (label, list) in [
        ("static field", &static_fields),
        ("instance field", &instance_fields),
    ] {
        if list.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::DuplicateClass(format!("{label} declared twice")));
        }
    }
    for (label, list) in [("direct method", &direct), ("virtual method", &virtual_)] {
        if list.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::DuplicateClass(format!("{label} declared twice")));
        }
    }
    // A method index must not appear in both lists.
    for a in &direct {
        if virtual_.iter().any(|b| b.0 == a.0) {
            return Err(Error::DuplicateClass(
                "a method may not be both direct and virtual".into(),
            ));
        }
    }

    let mut v = Vec::new();
    mutf8::write_uleb128(&mut v, static_fields.len() as u32);
    mutf8::write_uleb128(&mut v, instance_fields.len() as u32);
    mutf8::write_uleb128(&mut v, direct.len() as u32);
    mutf8::write_uleb128(&mut v, virtual_.len() as u32);

    let mut prev = 0u32;
    for &(f, flags) in &static_fields {
        mutf8::write_uleb128(&mut v, f - prev);
        mutf8::write_uleb128(&mut v, flags);
        prev = f;
    }
    prev = 0;
    for &(f, flags) in &instance_fields {
        mutf8::write_uleb128(&mut v, f - prev);
        mutf8::write_uleb128(&mut v, flags);
        prev = f;
    }

    // Each slot already carries its own global code index, so the sort above
    // cannot detach a method from its body.
    prev = 0;
    for &(m, flags, code_idx) in &direct {
        mutf8::write_uleb128(&mut v, m - prev);
        mutf8::write_uleb128(&mut v, flags);
        mutf8::write_uleb128(&mut v, code_off(code_idx, code_offs));
        prev = m;
    }
    prev = 0;
    for &(m, flags, code_idx) in &virtual_ {
        mutf8::write_uleb128(&mut v, m - prev);
        mutf8::write_uleb128(&mut v, flags);
        mutf8::write_uleb128(&mut v, code_off(code_idx, code_offs));
        prev = m;
    }
    Ok(v)
}

/// The `code_item` offset for a method slot, or 0 when it has no code.
fn code_off(code_idx: u32, code_offs: &[u32]) -> u32 {
    if code_idx == u32::MAX {
        0
    } else {
        code_offs[code_idx as usize]
    }
}

/// Encode a `code_item`, including its try table and encoded catch handlers.
fn encode_code_item<F>(body: &CodeBody, type_index: F) -> Result<Vec<u8>>
where
    F: Fn(&str) -> u32,
{
    if body.insns.len() % 2 != 0 {
        return Err(Error::ValueOutOfRange {
            what: "insns length in bytes (must be a whole number of code units)",
            value: body.insns.len() as u64,
        });
    }
    let insns_size = (body.insns.len() / 2) as u32;
    let mut v = Vec::with_capacity(body.insns.len() + 64);
    v.extend_from_slice(&body.registers_size.to_le_bytes());
    v.extend_from_slice(&body.ins_size.to_le_bytes());
    v.extend_from_slice(&body.outs_size.to_le_bytes());
    v.extend_from_slice(&(body.tries.len() as u16).to_le_bytes());
    // The writer never emits debug info, so this is always zero.
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&insns_size.to_le_bytes());
    v.extend_from_slice(&body.insns);
    if body.tries.is_empty() {
        return Ok(v);
    }
    for t in &body.tries {
        t.handler.validate()?;
        if t.start_addr + t.insn_count > insns_size {
            return Err(Error::ValueOutOfRange {
                what: "try block range (outside the instruction stream)",
                value: (t.start_addr + t.insn_count) as u64,
            });
        }
    }

    // Two bytes of padding when insns_size is odd, so the try table is 4-aligned.
    if insns_size % 2 == 1 {
        v.extend_from_slice(&[0, 0]);
    }

    // Identical handler lists share one offset, as dexlib2 does. Build the
    // unique lists first so the uleb128 list-size prefix can be measured, then
    // assign offsets relative to the start of the list *including* that prefix.
    let mut unique: Vec<(Vec<Option<u32>>, Vec<u8>)> = Vec::new();
    let mut slot_of: Vec<u32> = Vec::with_capacity(body.tries.len());
    for t in &body.tries {
        let key: Vec<Option<u32>> = t
            .handler
            .handlers
            .iter()
            .map(|(ty, _)| ty.as_deref().map(&type_index))
            .collect();
        match unique.iter().position(|(k, _)| *k == key) {
            Some(i) => slot_of.push(i as u32),
            None => {
                // `encoded_catch_handler` is a signed count of *typed* clauses,
                // negated when a catch-all follows, then that many
                // (type_idx, addr) pairs, then the catch-all address. Emitting
                // the catch-all inside the pair loop as well would write it
                // twice, which shifts every later offset.
                let typed: Vec<(u32, u32)> = t
                    .handler
                    .handlers
                    .iter()
                    .filter_map(|(ty, addr)| ty.as_deref().map(|d| (type_index(d), *addr)))
                    .collect();
                let catch_all = t.handler.is_catch_all();
                let catch_all_addr = t.handler.handlers.last().map(|h| h.1).unwrap_or(0);

                let mut list = Vec::new();
                let n_typed = typed.len() as i32;
                write_sleb128(&mut list, if catch_all { -n_typed } else { n_typed });
                for (ty, addr) in &typed {
                    mutf8::write_uleb128(&mut list, *ty);
                    mutf8::write_uleb128(&mut list, *addr);
                }
                if catch_all {
                    mutf8::write_uleb128(&mut list, catch_all_addr);
                }
                unique.push((key, list));
                slot_of.push((unique.len() - 1) as u32);
            }
        }
    }

    let mut prefix = Vec::new();
    mutf8::write_uleb128(&mut prefix, unique.len() as u32);
    let mut offsets = Vec::with_capacity(unique.len());
    let mut cursor = prefix.len() as u32;
    for (_, list) in &unique {
        offsets.push(cursor);
        cursor += list.len() as u32;
    }

    for (t, &slot) in body.tries.iter().zip(&slot_of) {
        // try_item is `uint start_addr; ushort insn_count; ushort handler_off`,
        // which is 8 bytes. Writing insn_count as a u32 would silently make the
        // array 10 bytes per entry and every later offset wrong.
        v.extend_from_slice(&t.start_addr.to_le_bytes());
        v.extend_from_slice(&(t.insn_count as u16).to_le_bytes());
        let at = v.len();
        v.extend_from_slice(&0u16.to_le_bytes());
        // handler_off is measured from the start of the handler list, which has
        // not been appended to `v` yet.
        put_u16(&mut v, at, offsets[slot as usize] as u16);
    }
    v.extend_from_slice(&prefix);
    for (_, list) in &unique {
        v.extend_from_slice(list);
    }
    Ok(v)
}

fn write_sleb128(out: &mut Vec<u8>, v: i32) {
    let mut value = v as i64;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let sign_bit = byte & 0x40 != 0;
        if (value == 0 && !sign_bit) || (value == -1 && sign_bit) {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn align4(x: u32) -> u32 {
    (x + 3) & !3
}

fn put_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
