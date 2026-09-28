//! Shared scaffolding for the integration suites.
//!
//! Three things live here, because all three suites need all three:
//!
//! * [`Emit`] — a byte-level instruction emitter covering every Dalvik format the
//!   tests hand-assemble. `dexcore`'s own `Assembler` covers the formats a
//!   framework shim needs and deliberately not the whole set, and a coverage
//!   suite that could only reach through it would not be a coverage suite. The
//!   layouts here are the AOSP ones, and `decode_all` round-trips every byte
//!   this module produces in `emit_matches_the_decoder`.
//! * [`Case`] / [`run`] — declare a method, assemble its body against the frozen
//!   pool, emit the file, and run it in a *fresh* interpreter so that counters,
//!   heap and budget are per case.
//! * [`Recorder`] — a framework shim that logs everything and answers from a
//!   table, which is the shape another agent's `android.*` shim can grow into.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use dexcore::error::Result as DexResult;
use dexcore::model::access;
use dexcore::writer::{
    CatchHandler, ClassDef, CodeBody, DexWriter, FieldDef, IndexMap, MethodDef, TryCatch,
};
use dexcore::DexReader;

use dexinterp::host::{
    Call, CallSite, FieldAccess, Host, HostOutcome, HostValue, ResolvedCallSite, ThrowSpec,
};
use dexinterp::{Config, ExecError, Interpreter, Stats, Termination, Value};

// ============================================================== the emitter

/// A byte-level Dalvik instruction emitter.
///
/// Every method is named for its format identifier and takes the operands in the
/// order the specification lists them, so a test that reads `emit.22b(0xd8, 0, 1,
/// -1)` knows exactly what bytes it produced. `emit_matches_the_decoder` decodes
/// every byte this module can produce back through `dexcore`, so an encoding
/// mistake fails loudly here rather than as a mystery result later.
#[derive(Debug, Clone, Default)]
pub struct Emit {
    bytes: Vec<u8>,
}

impl Emit {
    /// An empty emitter.
    pub fn new() -> Emit {
        Emit { bytes: Vec::new() }
    }

    /// The bytes so far, for the decoder round-trip.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Code units emitted so far.
    pub fn units(&self) -> usize {
        self.bytes.len() / 2
    }

    /// The next code-unit offset, which branch offsets are relative to.
    pub fn here(&self) -> u32 {
        self.units() as u32
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// `10x` — `op`.
    pub fn nop(&mut self) -> &mut Self {
        self.u16(0x0000)
    }

    /// `11n` — `op A|B`, four-bit signed literal.
    pub fn const4(&mut self, a: u8, lit: i8) -> &mut Self {
        let b = ((lit as u16) & 0x000f) << 12;
        self.u16(0x0012 | ((a as u16 & 0x0f) << 8) | b)
    }

    /// `21s` — `op AA BBBB`, signed 16-bit literal.
    pub fn const16(&mut self, op: u8, a: u8, lit: i16) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(lit as u16)
    }

    /// `21h` — `op AA BBBB`, the literal is the high 16 bits.
    pub fn const_high16(&mut self, op: u8, a: u8, lit: i16) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(lit as u16)
    }

    /// `31i` — `op AA BBBBBBBB`.
    pub fn const32(&mut self, op: u8, a: u8, lit: i32) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u32(lit as u32)
    }

    /// `51l` — `op AA` + a 64-bit literal.
    pub fn const_wide(&mut self, op: u8, a: u8, lit: i64) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u64(lit as u64)
    }

    /// `12x` — `op B|A`, two four-bit registers.
    pub fn op12x(&mut self, op: u8, a: u8, b: u8) -> &mut Self {
        self.u16((op as u16) | (((a & 0x0f) as u16) << 8) | (((b & 0x0f) as u16) << 12))
    }

    /// `11x` — `op AA`.
    pub fn op11x(&mut self, op: u8, a: u8) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8))
    }

    /// `22x` — `op AA BBBB`.
    pub fn op22x(&mut self, op: u8, a: u8, b: u16) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(b)
    }

    /// `32x` — `AA|op BBBB`, the opcode in the *low* byte of the first unit.
    ///
    /// The AOSP format table writes the fields most-significant first, so `32x`
    /// reads `AA` in the high byte and `op` in the low one — the same order as
    /// every other format whose first byte is the opcode (`11x` is `op AA`,
    /// `22x` is `AA op` once read little-endian, `12x` is `B|A|op`). Putting the
    /// opcode in the high byte instead produces a method whose every instruction
    /// is the wrong one, and the first symptom is an out-of-range register
    /// number made out of the opcode byte.
    pub fn op32x(&mut self, op: u8, a: u16, b: u16) -> &mut Self {
        self.u16(((a & 0xff) << 8) | (op as u16));
        self.u16(b)
    }

    /// `22c` — `op B|A` then a 16-bit pool index.
    pub fn op22c(&mut self, op: u8, a: u8, b: u8, index: u16) -> &mut Self {
        self.u16((op as u16) | (((a & 0x0f) as u16) << 8) | (((b & 0x0f) as u16) << 12));
        self.u16(index)
    }

    /// `21c` — `op AA` then a 16-bit pool index.
    pub fn op21c(&mut self, op: u8, a: u8, index: u16) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(index)
    }

    /// `31c` — `op AA` then a 32-bit pool index.
    pub fn op31c(&mut self, op: u8, a: u8, index: u32) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u32(index)
    }

    /// `23x` — `op AA vBB, vCC`.
    pub fn op23x(&mut self, op: u8, a: u8, b: u8, c: u8) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(((c as u16) << 8) | (b as u16))
    }

    /// `22b` — `op AA vBB, #+CC`.
    pub fn op22b(&mut self, op: u8, a: u8, b: u8, lit: i8) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16((((lit as u16) & 0x00ff) << 8) | (b as u16))
    }

    /// `22s` — `op B|A` then a signed 16-bit literal.
    pub fn op22s(&mut self, op: u8, a: u8, b: u8, lit: i16) -> &mut Self {
        self.u16((op as u16) | (((a & 0x0f) as u16) << 8) | (((b & 0x0f) as u16) << 12));
        self.u16(lit as u16)
    }

    /// `22t` — `op B|A` then a branch offset.
    pub fn op22t(&mut self, op: u8, a: u8, b: u8, off: i16) -> &mut Self {
        self.u16((op as u16) | (((a & 0x0f) as u16) << 8) | (((b & 0x0f) as u16) << 12));
        self.u16(off as u16)
    }

    /// `21t` — `op AA` then a branch offset.
    pub fn op21t(&mut self, op: u8, a: u8, off: i16) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u16(off as u16)
    }

    /// `10t` — `op AA`, an 8-bit branch offset.
    pub fn op10t(&mut self, op: u8, off: i8) -> &mut Self {
        self.u16((op as u16) | (((off as u16) & 0x00ff) << 8))
    }

    /// `20t` — `op` then a 16-bit branch offset.
    pub fn op20t(&mut self, op: u8, off: i16) -> &mut Self {
        self.u16(op as u16);
        self.u16(off as u16)
    }

    /// `30t` — `op` then a 32-bit branch offset.
    pub fn op30t(&mut self, op: u8, off: i32) -> &mut Self {
        self.u16(op as u16);
        self.u32(off as u32)
    }

    /// `31t` — `op AA` then a 32-bit payload offset.
    pub fn op31t(&mut self, op: u8, a: u8, off: i32) -> &mut Self {
        self.u16((op as u16) | ((a as u16) << 8));
        self.u32(off as u32)
    }

    /// `35c` — `op A|G`, a method index, then `C|D|E|F`.
    ///
    /// `a` is the argument count, which is what d8 writes; `regs` holds the
    /// argument registers in order and the first four go into `C..F`, with a
    /// fifth in `G`.
    pub fn op35c(&mut self, op: u8, a: u8, index: u16, regs: &[u8]) -> &mut Self {
        let g = regs.get(4).copied().unwrap_or(0) as u16;
        let cdef = pack_nibbles(&regs[..regs.len().min(4)]);
        self.u16((op as u16) | (g << 8) | ((a as u16) << 12));
        self.u16(index);
        self.u16(cdef)
    }

    /// `35c` with the register list supplied already packed, for the case where
    /// the trailing `v0` must survive.
    pub fn op35c_raw(&mut self, op: u8, a: u8, index: u16, cdef: u16, g: u8) -> &mut Self {
        self.u16((op as u16) | ((g as u16) << 8) | ((a as u16) << 12));
        self.u16(index);
        self.u16(cdef)
    }

    /// `3rc` — `op AA`, a method index, then the first register of the range.
    pub fn op3rc(&mut self, op: u8, count: u8, index: u16, first: u16) -> &mut Self {
        self.u16((op as u16) | ((count as u16) << 8));
        self.u16(index);
        self.u16(first)
    }

    /// `45cc` — `35c` plus a trailing `proto_ids` index.
    pub fn op45cc(&mut self, op: u8, a: u8, index: u16, regs: &[u8], proto: u16) -> &mut Self {
        self.op35c(op, a, index, regs);
        self.u16(proto)
    }

    /// `4rcc` — `3rc` plus a trailing `proto_ids` index.
    pub fn op4rcc(&mut self, op: u8, count: u8, index: u16, first: u16, proto: u16) -> &mut Self {
        self.op3rc(op, count, index, first);
        self.u16(proto)
    }

    /// A `packed-switch-payload` (ident `0x0100`), padded to a whole code unit.
    pub fn packed_switch_payload(&mut self, first_key: i32, targets: &[i32]) -> &mut Self {
        self.u16(0x0100);
        self.u16(targets.len() as u16);
        self.u32(first_key as u32);
        for t in targets {
            self.u32(*t as u32);
        }
        self.pad()
    }

    /// A `sparse-switch-payload` (ident `0x0200`).
    pub fn sparse_switch_payload(&mut self, keys: &[i32], targets: &[i32]) -> &mut Self {
        self.u16(0x0200);
        self.u16(keys.len() as u16);
        for k in keys {
            self.u32(*k as u32);
        }
        for t in targets {
            self.u32(*t as u32);
        }
        self.pad()
    }

    /// A `fill-array-data-payload` (ident `0x0300`).
    pub fn fill_array_data_payload(&mut self, element_width: u16, data: &[u8]) -> &mut Self {
        self.u16(0x0300);
        self.u16(element_width);
        self.u32((data.len() / element_width as usize) as u32);
        self.bytes.extend_from_slice(data);
        self.pad()
    }

    /// Pad to the next code-unit boundary, which every payload requires.
    pub fn pad(&mut self) -> &mut Self {
        if self.bytes.len() % 2 == 1 {
            self.bytes.push(0);
        }
        self
    }

    /// The byte stream, padded.
    pub fn finish(&mut self) -> Vec<u8> {
        self.pad();
        self.bytes.clone()
    }

    /// A `code_item` body with the given register frame.
    pub fn code(mut self, registers: u16, ins: u16, outs: u16) -> CodeBody {
        CodeBody {
            registers_size: registers,
            ins_size: ins,
            outs_size: outs,
            insns: self.finish(),
            tries: Vec::new(),
        }
    }

    /// A `code_item` body with a try table.
    pub fn code_tries(
        mut self,
        registers: u16,
        ins: u16,
        outs: u16,
        tries: Vec<TryCatch>,
    ) -> CodeBody {
        CodeBody {
            registers_size: registers,
            ins_size: ins,
            outs_size: outs,
            insns: self.finish(),
            tries,
        }
    }

    /// Append an already-built emitter's bytes, so a test can compose helpers.
    pub fn push_body(&mut self, other: &Emit) -> &mut Self {
        self.bytes.extend_from_slice(&other.bytes);
        self
    }

    /// Overwrite a 32-bit little-endian field at a byte offset.
    ///
    /// A `31t` payload offset is only known once the payload has been placed,
    /// so it has to be back-patched; doing it by byte offset rather than by
    /// re-emitting keeps the instruction stream otherwise untouched.
    pub fn patch_i32(&mut self, byte_offset: usize, value: i32) {
        let at = byte_offset;
        if at + 4 <= self.bytes.len() {
            self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
}

fn pack_nibbles(regs: &[u8]) -> u16 {
    let mut v = 0u16;
    for (i, &r) in regs.iter().enumerate() {
        v |= ((r as u16) & 0x0f) << (i * 4);
    }
    v
}

/// A catch-all `TryCatch`.
pub fn catch_all(start: u32, count: u32, handler: u32) -> TryCatch {
    TryCatch {
        start_addr: start,
        insn_count: count,
        handler: CatchHandler {
            handlers: vec![(None, handler)],
        },
    }
}

/// A typed `TryCatch`, with an optional catch-all, which the encoding requires to
/// come last.
pub fn catches(
    start: u32,
    count: u32,
    clauses: &[(&str, u32)],
    catch_all: Option<u32>,
) -> TryCatch {
    let mut handlers: Vec<(Option<String>, u32)> = clauses
        .iter()
        .map(|(t, a)| (Some(t.to_string()), *a))
        .collect();
    if let Some(a) = catch_all {
        handlers.push((None, a));
    }
    TryCatch {
        start_addr: start,
        insn_count: count,
        handler: CatchHandler { handlers },
    }
}

// ========================================================== the dex builder

/// The class the synthetic methods live on.
pub const HOST: &str = "Lt;";

/// A subclass, for hierarchy and vtable tests.
pub const SUB: &str = "Lu;";

/// An interface, for `invoke-interface` tests.
pub const IFACE: &str = "Li;";

/// A method declaration, without its body.
#[derive(Clone, Debug)]
pub struct Declared {
    pub name: String,
    pub params: Vec<String>,
    pub ret: String,
    pub access_flags: u32,
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
}

impl Declared {
    /// The prototype descriptor, `(II)V`.
    pub fn signature(&self) -> String {
        format!("({}){}", self.params.join(""), self.ret)
    }
}

/// A synthetic DEX under construction.
pub struct Synthetic {
    writer: DexWriter,
    declared: Vec<Declared>,
    extra: Vec<ClassDef>,
    extra_instance_fields: Vec<FieldDef>,
}

impl Default for Synthetic {
    fn default() -> Synthetic {
        Synthetic::new()
    }
}

impl Synthetic {
    /// A synthetic dex whose host class `Lt;` extends `Ljava/lang/Object;`.
    pub fn new() -> Synthetic {
        let mut s = Synthetic {
            writer: DexWriter::new(),
            declared: Vec::new(),
            extra: Vec::new(),
            extra_instance_fields: Vec::new(),
        };
        s.declare("<init>", &[], "V", 1, 1);
        s
    }

    /// Declare an instance method.
    ///
    /// `ins_size` is *derived* from the prototype rather than passed in: the
    /// engine computes the argument window from it, and a hand-written value
    /// that disagrees with the prototype produces a window the callee cannot
    /// read. Deriving it here means a test cannot get that wrong by accident.
    pub fn declare(&mut self, name: &str, params: &[&str], ret: &str, registers: u16, outs: u16) {
        let ins = incoming_slots(params, false);
        self.writer.add_method(HOST, name, params, ret);
        self.declared.push(Declared {
            name: name.to_string(),
            params: params.iter().map(|p| p.to_string()).collect(),
            ret: ret.to_string(),
            access_flags: access::ACC_PUBLIC,
            registers,
            ins,
            outs,
        });
    }

    /// Declare a static method.
    pub fn declare_static(
        &mut self,
        name: &str,
        params: &[&str],
        ret: &str,
        registers: u16,
        outs: u16,
    ) {
        let ins = incoming_slots(params, true);
        self.writer.add_method(HOST, name, params, ret);
        self.declared.push(Declared {
            name: name.to_string(),
            params: params.iter().map(|p| p.to_string()).collect(),
            ret: ret.to_string(),
            access_flags: access::ACC_PUBLIC | access::ACC_STATIC,
            registers,
            ins,
            outs,
        });
    }

    /// The declaration for a name.
    pub fn get(&self, name: &str) -> Option<&Declared> {
        self.declared.iter().find(|d| d.name == name)
    }

    /// Add a class verbatim, with its own methods and bodies.
    pub fn class(&mut self, class: ClassDef) {
        self.extra.push(class);
    }

    /// Declare an extra instance field on the host class.
    ///
    /// Interning a field is not enough for the engine to store it: a field is
    /// only addressable if it appears in the class's `class_data_item`, because
    /// the instance layout is built from *that* list. A coverage suite therefore
    /// has to be able to declare fields rather than merely name them.
    pub fn field(&mut self, name: &str, ty: &str) {
        self.writer.add_field(HOST, name, ty);
        self.extra_instance_fields
            .push(FieldDef::instance(name, ty));
    }

    /// Borrow the writer, for interning references before the freeze.
    pub fn writer(&mut self) -> &mut DexWriter {
        &mut self.writer
    }

    fn host_class(&self) -> ClassDef {
        let mut c = ClassDef::extending_object(HOST)
            .with_field(FieldDef::statics("S", "I"))
            .with_field(FieldDef::statics("SD", "D"))
            .with_field(FieldDef::statics("SA", "Ljava/lang/String;"))
            .with_field(FieldDef::instance("i", "I"))
            .with_field(FieldDef::instance("j", "J"))
            .with_field(FieldDef::instance("d", "D"))
            .with_field(FieldDef::instance("f", "F"))
            .with_field(FieldDef::instance("b", "Z"))
            .with_field(FieldDef::instance("c", "C"))
            .with_field(FieldDef::instance("sh", "S"))
            .with_field(FieldDef::instance("by", "B"))
            .with_field(FieldDef::instance("o", "Ljava/lang/Object;"));
        for f in &self.extra_instance_fields {
            c = c.with_field(f.clone());
        }
        for d in &self.declared {
            let params: Vec<&str> = d.params.iter().map(|s| s.as_str()).collect();
            c = c.with_method(MethodDef {
                name: d.name.clone(),
                parameters: params.iter().map(|p| p.to_string()).collect(),
                return_descriptor: d.ret.clone(),
                access_flags: d.access_flags,
                // Filled in by `set_code` after the freeze.
                code: None,
            });
        }
        c
    }

    /// Freeze, let `assemble` produce every body against the final indices,
    /// install them, and emit.
    pub fn finish<F>(&mut self, assemble: F) -> DexResult<Vec<u8>>
    where
        F: FnOnce(&IndexMap) -> BTreeMap<String, CodeBody>,
    {
        let host = self.host_class();
        self.writer.add_class(host);
        for c in std::mem::take(&mut self.extra) {
            self.writer.add_class(c);
        }
        let idx = self.writer.freeze()?;
        let bodies = assemble(&idx);
        for (name, mut body) in bodies {
            // The *declaration* owns `ins_size`, because the engine derives the
            // argument window from it. A body that disagreed would make the
            // window unreadable, and a test that hand-wrote the value could get
            // that wrong without noticing.
            if let Some(d) = self.declared.iter().find(|d| d.name == name) {
                body.ins_size = d.ins;
                if body.registers_size < d.ins {
                    body.registers_size = d.ins;
                }
            }
            self.writer.set_code(HOST, &name, body)?;
        }
        let bytes = self.writer.emit()?;
        let repaired = repair_type_lists(bytes)
            .unwrap_or_else(|e| panic!("synthetic dex did not survive type_list repair: {e}"));
        Ok(repaired)
    }
}

// ======================================================== the writer repair

/// Re-encode every `type_list` in `bytes` with two-byte elements, in place.
///
/// # Why this exists
///
/// `dexcore::DexWriter` writes each `ushort` element of a `type_list` as **four**
/// bytes (`u32::to_le_bytes`) where the specification — and `dexcore`'s own
/// reader, and every real d8 output — use two:
///
/// ```text
/// type_list ::= size ubyte[4]          # 4 bytes
///               list ushort[size]      # 2 bytes each
/// ```
///
/// The consequence is silent and severe: every element *after the first* reads
/// back as type index 0. A two-parameter prototype written as `(II)I` comes out
/// of the file as `(IB)I` in these tests, purely because `"B"` happens to sort
/// first among the interned type descriptors. One-element lists are unaffected
/// (the low two bytes of a four-byte little-endian value are the value), which
/// is exactly why the bug survived `dexcore`'s own 138 tests: a round-trip test
/// that only ever uses zero- and one-parameter methods cannot see it.
///
/// The defect is in `dexcore`, which this crate must not modify, so the harness
/// repairs the bytes instead of working around them by avoiding multi-parameter
/// prototypes. Doing it in place is possible because the *slot* the writer
/// reserved is always large enough: it laid out `4 + 4*size` bytes where the
/// correct list needs `4 + 2*size`, so rewriting the first `2*size` bytes and
/// leaving the remainder as padding moves nothing. Every other offset in the
/// file — code items, class data, the `map_list` — stays valid.
///
/// `type_lists_written_by_dexcore_round_trip` is the self-check: it re-reads the
/// repaired file and asserts the prototypes match what the test asked for, so
/// the day `dexcore` is fixed this function's no-op case fails loudly rather
/// than the repair silently doing nothing.
fn repair_type_lists(mut bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let u32_at = |b: &[u8], at: usize| -> Result<u32, String> {
        let s = b
            .get(at..at + 4)
            .ok_or_else(|| format!("4-byte read at {at} is past the end"))?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    // Header field offsets, from the `header_item` layout. `magic` is
    // `ubyte[8]` and `signature` is `ubyte[20]`, which is what puts
    // `proto_ids_size` at 72 rather than at 56.
    const PROTO_IDS_SIZE: usize = 72;
    const PROTO_IDS_OFF: usize = 76;
    const CLASS_DEFS_SIZE: usize = 96;
    const CLASS_DEFS_OFF: usize = 100;

    let proto_size = u32_at(&bytes, PROTO_IDS_SIZE)? as usize;
    let proto_off = u32_at(&bytes, PROTO_IDS_OFF)? as usize;
    let class_size = u32_at(&bytes, CLASS_DEFS_SIZE)? as usize;
    let class_off = u32_at(&bytes, CLASS_DEFS_OFF)? as usize;

    // Every `type_list` the file references: a prototype's parameters and a
    // class's interfaces. They are interned by content, so the same offset can
    // appear many times; repairing it twice would be harmless but pointless.
    let mut offsets: Vec<u32> = Vec::new();
    for i in 0..proto_size {
        let base = proto_off + i * 12;
        let off = u32_at(&bytes, base + 8)?;
        if off != 0 {
            offsets.push(off);
        }
    }
    for i in 0..class_size {
        let base = class_off + i * 32;
        let off = u32_at(&bytes, base + 12)?;
        if off != 0 {
            offsets.push(off);
        }
    }
    offsets.sort_unstable();
    offsets.dedup();

    for &off in &offsets {
        let at = off as usize;
        let size = u32_at(&bytes, at)? as usize;
        if size < 2 {
            // Zero- and one-element lists already read correctly; a correct
            // writer's one-element list is also left untouched, so this is a
            // no-op once `dexcore` is fixed.
            continue;
        }
        // The writer reserved four bytes per element. Refuse rather than guess
        // if that much is not actually there.
        if at + 4 + size * 4 > bytes.len() {
            return Err(format!(
                "type_list at {at} declares {size} elements but the file is shorter"
            ));
        }
        for k in 0..size {
            let src = at + 4 + k * 4;
            let value = u16::from_le_bytes([bytes[src], bytes[src + 1]]);
            let dst = at + 4 + k * 2;
            bytes[dst] = value as u8;
            bytes[dst + 1] = (value >> 8) as u8;
        }
    }
    Ok(bytes)
}

/// Intern the references the host class and the standard target methods need.
///
/// Everything a body names must be in the pool before the freeze, because the
/// writer checks that rather than silently renumbering the indices a body was
/// assembled against.
pub fn intern_standard(s: &mut Synthetic) {
    let w = s.writer();
    for c in [
        "I",
        "J",
        "D",
        "F",
        "Z",
        "B",
        "C",
        "S",
        "V",
        "[I",
        "[J",
        "[D",
        "[F",
        "[B",
        "[C",
        "[S",
        "[Z",
        "[Ljava/lang/Object;",
        "[Ljava/lang/String;",
        "Ljava/lang/Object;",
        "Ljava/lang/String;",
        "Ljava/lang/Class;",
        "Ljava/lang/Throwable;",
        "Ljava/lang/Exception;",
        "Ljava/lang/RuntimeException;",
        "Ljava/lang/Error;",
        "Ljava/lang/NullPointerException;",
        "Ljava/lang/ArithmeticException;",
        "Ljava/lang/ArrayIndexOutOfBoundsException;",
        "Ljava/lang/ClassCastException;",
        "Ljava/lang/NegativeArraySizeException;",
        "Ljava/lang/ArrayStoreException;",
        "Ljava/lang/UnsupportedOperationException;",
        "Ljava/lang/IllegalStateException;",
        "Ljava/lang/IllegalArgumentException;",
        "Ljava/lang/NoSuchMethodError;",
        "Ljava/lang/NoSuchFieldError;",
        "Ljava/lang/AbstractMethodError;",
        "Ljava/lang/BootstrapMethodError;",
        "Ljava/lang/invoke/MethodHandle;",
        "Ljava/lang/reflect/MethodType;",
        SUB,
        IFACE,
    ] {
        w.add_type(c);
    }
    for f in [
        ("i", "I"),
        ("j", "J"),
        ("d", "D"),
        ("f", "F"),
        ("b", "Z"),
        ("c", "C"),
        ("sh", "S"),
        ("by", "B"),
        ("o", "Ljava/lang/Object;"),
        ("S", "I"),
        ("SD", "D"),
        ("SA", "Ljava/lang/String;"),
    ] {
        w.add_field(HOST, f.0, f.1);
    }
    w.add_method("Ljava/lang/Object;", "<init>", &[], "V");
    w.add_method("Ljava/lang/String;", "length", &[], "I");
    w.add_method(
        "Ljava/lang/String;",
        "replace",
        &["Ljava/lang/CharSequence;", "Ljava/lang/CharSequence;"],
        "Ljava/lang/String;",
    );
    w.add_method(
        "Ljava/lang/Throwable;",
        "<init>",
        &["Ljava/lang/String;"],
        "V",
    );
    w.add_method(
        "Ljava/lang/Exception;",
        "<init>",
        &["Ljava/lang/String;"],
        "V",
    );
    w.add_method("Ljava/lang/Error;", "<init>", &["Ljava/lang/String;"], "V");
    w.add_method("Ljava/lang/Object;", "hashCode", &[], "I");
    w.add_method(
        "Ljava/lang/invoke/MethodHandle;",
        "invoke",
        &["[Ljava/lang/Object;"],
        "Ljava/lang/Object;",
    );
    w.add_method(
        "Ljava/lang/invoke/MethodHandle;",
        "invokeExact",
        &["[Ljava/lang/Object;"],
        "Ljava/lang/Object;",
    );
    w.add_method(
        "Ljava/lang/invoke/MethodType;",
        "methodType",
        &["Ljava/lang/Class;", "[Ljava/lang/Class;"],
        "Ljava/lang/invoke/MethodType;",
    );
    // Interned so a test can build a `const-method-type` for it: a proto only
    // enters the pool through a method that uses it.
    w.add_method(HOST, "getStringFromInt", &["I"], "Ljava/lang/String;");
    w.add_method(HOST, "getInt", &[], "I");
    w.add_method(HOST, "getLong", &[], "J");
    w.add_method(HOST, "getFloat", &[], "F");
    w.add_method(HOST, "getDouble", &[], "D");
    w.add_method(HOST, "getObject", &[], "Ljava/lang/Object;");
    w.add_method(HOST, "getString", &[], "Ljava/lang/String;");
    w.add_method(HOST, "getClass", &[], "Ljava/lang/Class;");
    w.add_method(HOST, "getInt1", &[], "I");
    w.add_method(HOST, "getInt2", &[], "I");
    w.add_method(HOST, "getVoid", &[], "V");
    w.add_method(HOST, "sum", &["I", "I"], "I");
    w.add_method(HOST, "addLong", &["J", "J"], "J");
    w.add_method(HOST, "takesInt", &["I"], "V");
    w.add_method(HOST, "vMeth", &["I"], "I");
    w.add_method(HOST, "iMeth", &["I"], "I");
    w.add_method(HOST, "boom", &[], "V");
    w.add_method(HOST, "staticBoom", &[], "V");
    w.add_method(HOST, "recurses", &["I"], "I");
    w.add_method(HOST, "sync", &["Ljava/lang/Object;"], "V");
    w.add_method(HOST, "arrayLen", &["[I"], "I");
    w.add_method(HOST, "arrayWide", &["[J"], "J");
    w.add_method(HOST, "staticWide", &[], "J");
    w.add_method(HOST, "notThere", &["I"], "I");
    w.add_method(IFACE, "size", &[], "I");
    w.add_method(HOST, "notThere0", &[], "I");
    // The subclasses' constructors. A test that builds a `Lu;` and calls its
    // `vMeth` through a vtable has to name `Lu;.<init>` in the pool, and
    // `method_at` refuses an index that was never interned rather than inventing
    // one — which is the right behaviour for a test harness too, because a
    // silently wrong index would produce a wrong result rather than a failure.
    w.add_method(SUB, "<init>", &[], "V");
    w.add_method("Lj;", "<init>", &[], "V");
    // Long- and double-typed parameters, so a test can put a wide value in the
    // argument window without hand-counting slots.
    w.add_method(HOST, "takesLong", &["J"], "I");
    w.add_method(HOST, "takesDouble", &["D"], "I");
    w.add_method(HOST, "takesObject", &["Ljava/lang/Object;"], "I");
    for t in [
        "hello",
        "a",
        "b",
        "x",
        "",
        "from the shim",
        "hello ☃",
        "naïve",
        "from the callee",
    ] {
        w.add_string(t);
    }
    for t in ["[[I", "[[D", "[Z", "[C", "[S", "[B", "[F", "[[[I"] {
        w.add_type(t);
    }
    w.add_method(HOST, "five", &["IIIII"], "I");
    w.add_method(HOST, "usesThis", &["I"], "I");
}

/// The width of a call's argument window, in 32-bit words: one per parameter
/// plus the receiver, with a `long` or `double` counting as two.
pub fn incoming_slots(params: &[&str], is_static: bool) -> u16 {
    let words: usize = params
        .iter()
        .map(|p| match *p {
            "J" | "D" => 2,
            _ => 1,
        })
        .sum();
    (words + usize::from(!is_static)) as u16
}

/// Resolve a string index in a frozen pool.
pub fn string_at(idx: &IndexMap, s: &str) -> u16 {
    idx.string(s)
}

/// Resolve a type index in a frozen pool.
pub fn ty_at(idx: &IndexMap, d: &str) -> u16 {
    idx.type_(d)
        .expect("type must be interned before the freeze")
}

/// Resolve a field index in a frozen pool.
pub fn field_at(idx: &IndexMap, class: &str, name: &str, ty: &str) -> u16 {
    idx.field(class, name, ty)
        .expect("field must be interned before the freeze")
}

/// Resolve a method index in a frozen pool.
pub fn method_at(idx: &IndexMap, class: &str, name: &str, params: &[&str], ret: &str) -> u16 {
    idx.method(class, name, params, ret)
        .expect("method must be interned before the freeze")
}

/// Resolve a proto index in a frozen pool.
pub fn proto_at(idx: &IndexMap, params: &[&str], ret: &str) -> u32 {
    idx.proto(params, ret)
        .expect("proto must be interned before the freeze")
}

// ================================================================== the shim

/// A framework shim that records every call and answers from a table.
#[derive(Default)]
pub struct Recorder {
    log: RefCell<Vec<String>>,
    answers: RefCell<BTreeMap<String, HostValue>>,
    throws: RefCell<BTreeMap<String, (&'static str, Option<String>)>>,
    fields: RefCell<BTreeMap<String, HostValue>>,
    call_sites: RefCell<BTreeMap<String, ResolvedCallSite>>,
    known: RefCell<Vec<String>>,
}

impl Recorder {
    /// A recorder with no answers: every call is recorded and declined.
    pub fn new() -> Rc<Recorder> {
        Rc::new(Recorder::default())
    }

    /// Answer `class->name(sig)` with `v`.
    pub fn answer(&self, key: &str, v: HostValue) {
        self.answers.borrow_mut().insert(key.to_string(), v);
    }

    /// Make `class->name` raise `class` with `message`.
    pub fn throw(&self, key: &str, class: &'static str, message: &str) {
        self.throws
            .borrow_mut()
            .insert(key.to_string(), (class, Some(message.to_string())));
    }

    /// Answer a field read or write.
    pub fn field(&self, key: &str, v: HostValue) {
        self.fields.borrow_mut().insert(key.to_string(), v);
    }

    /// Resolve a call site whose bootstrap method is named `bootstrap`.
    pub fn resolve_call_site(&self, bootstrap: &str, r: ResolvedCallSite) {
        self.call_sites
            .borrow_mut()
            .insert(bootstrap.to_string(), r);
    }

    /// Claim a class exists.
    pub fn know(&self, class: &str) {
        self.known.borrow_mut().push(class.to_string());
    }

    /// What was asked, in order.
    pub fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    /// Forget the log, so a test can time two phases separately.
    pub fn clear_log(&self) {
        self.log.borrow_mut().clear();
    }
}

impl Recorder {
    /// The body of [`Host::invoke`], on `&self` so a shared `Recorder` can be
    /// forwarded to through an `Rc`.
    pub fn on_call(&self, call: &Call<'_>) -> HostOutcome {
        let key = format!("{}->{}{}", call.class, call.name, call.signature);
        self.log.borrow_mut().push(key.clone());
        if let Some((class, message)) = self.throws.borrow().get(&key) {
            return HostOutcome::Throw(ThrowSpec {
                class,
                message: message.clone(),
            });
        }
        match self.answers.borrow().get(&key) {
            Some(v) => HostOutcome::Value(v.clone()),
            None => HostOutcome::NotImplemented,
        }
    }

    /// The body of [`Host::get_field`], on `&self`.
    pub fn on_get_field(&self, field: &FieldAccess<'_>) -> HostOutcome {
        let key = format!("{}->{}:{}", field.class, field.name, field.ty);
        self.log.borrow_mut().push(key.clone());
        match self.fields.borrow().get(&key) {
            Some(v) => HostOutcome::Value(v.clone()),
            None => HostOutcome::NotImplemented,
        }
    }

    /// The body of [`Host::set_field`], on `&self`.
    pub fn on_set_field(&self, field: &FieldAccess<'_>, value: HostValue) -> HostOutcome {
        let key = format!("{}->{}:{}", field.class, field.name, field.ty);
        self.log.borrow_mut().push(key.clone());
        self.fields.borrow_mut().insert(key, value);
        HostOutcome::Value(HostValue::Null)
    }

    /// The body of [`Host::resolve_call_site`], on `&self`.
    pub fn on_call_site(&self, site: &CallSite<'_>) -> Option<ResolvedCallSite> {
        self.log.borrow_mut().push(format!(
            "call_site@{} bootstrap {}.{}{}",
            site.index, site.bootstrap_owner, site.bootstrap_name, site.bootstrap_signature
        ));
        self.call_sites.borrow().get(site.bootstrap_name).cloned()
    }

    /// The body of [`Host::class_known`], on `&self`.
    pub fn on_class_known(&self, descriptor: &str) -> bool {
        self.known.borrow().iter().any(|d| d == descriptor)
    }
}

impl Host for Recorder {
    fn invoke(&mut self, call: &Call<'_>) -> HostOutcome {
        self.on_call(call)
    }
    fn get_field(&mut self, field: &FieldAccess<'_>) -> HostOutcome {
        self.on_get_field(field)
    }
    fn set_field(&mut self, field: &FieldAccess<'_>, value: HostValue) -> HostOutcome {
        self.on_set_field(field, value)
    }
    fn resolve_call_site(&mut self, site: &CallSite<'_>) -> Option<ResolvedCallSite> {
        self.on_call_site(site)
    }
    fn class_known(&mut self, descriptor: &str) -> bool {
        self.on_class_known(descriptor)
    }
}

/// A newtype so an `Rc<Recorder>` can be moved into a `Box<dyn Host>` and still
/// be read by the test afterwards.
pub struct Shim(pub Rc<Recorder>);

impl Host for Shim {
    fn invoke(&mut self, call: &Call<'_>) -> HostOutcome {
        self.0.on_call(call)
    }
    fn get_field(&mut self, field: &FieldAccess<'_>) -> HostOutcome {
        self.0.on_get_field(field)
    }
    fn set_field(&mut self, field: &FieldAccess<'_>, value: HostValue) -> HostOutcome {
        self.0.on_set_field(field, value)
    }
    fn resolve_call_site(&mut self, site: &CallSite<'_>) -> Option<ResolvedCallSite> {
        self.0.on_call_site(site)
    }
    fn class_known(&mut self, descriptor: &str) -> bool {
        self.0.on_class_known(descriptor)
    }
}

/// Build an interpreter over `bytes`, with `host` installed when given.
pub fn vm(
    bytes: &[u8],
    config: Config,
    host: Option<Rc<Recorder>>,
) -> Result<Interpreter<'_>, ExecError> {
    let dex = DexReader::open(bytes).map_err(ExecError::from)?;
    let mut vm = dexinterp::new_interpreter(dex, config)?;
    if let Some(h) = host {
        vm.set_host(Box::new(Shim(h)));
    }
    Ok(vm)
}

// ================================================================ assertions

/// Call `name` on the host class, allocating a receiver first if the method is
/// an instance method.
///
/// This is what a runtime does before it calls `onCreate`, and putting it here
/// means the per-family tests are about opcodes rather than about remembering to
/// pass a `this`.
pub fn call0(vm: &mut Interpreter, name: &str, sig: &str) -> Result<Value, ExecError> {
    let is_static = vm
        .program()
        .by_descriptor
        .get(HOST)
        .and_then(|c| vm.program().find_method(*c, name, sig))
        .map(|d| d.is_static())
        .unwrap_or(true);
    if is_static {
        return vm.invoke_method(HOST, name, sig, &[]);
    }
    let receiver = vm.allocate(HOST)?;
    vm.invoke_method(HOST, name, sig, &[receiver])
}

/// Assert an error's discriminant, with the whole error in the message so a
/// mismatch says what actually happened.
#[track_caller]
pub fn assert_kind<T: std::fmt::Debug>(result: &Result<T, ExecError>, expected: &str) {
    match result {
        Ok(v) => panic!("expected {expected}, but the call returned {v:?}"),
        Err(e) => assert_eq!(e.kind(), expected, "got: {e}"),
    }
}

/// Assert the terminal condition rather than the discriminant, for the tests
/// whose point is that the conditions stay apart.
#[track_caller]
pub fn assert_termination<T: std::fmt::Debug>(
    result: &Result<T, ExecError>,
    expected: Termination,
) {
    match result {
        Ok(v) => panic!("expected {expected:?}, but the call returned {v:?}"),
        Err(e) => assert_eq!(e.termination(), expected, "got: {e}"),
    }
}

/// The class of an uncaught exception, or a failure message.
#[track_caller]
pub fn thrown_class<T: std::fmt::Debug>(result: &Result<T, ExecError>) -> String {
    match result {
        Err(ExecError::ExceptionRaised { class, .. }) => class.clone(),
        Ok(v) => panic!("expected an uncaught exception, got {v:?}"),
        Err(e) => panic!("expected an uncaught exception, got {e}"),
    }
}

/// The `Unsupported` discriminant of an error, or a failure message.
#[track_caller]
pub fn unsupported_kind<T: std::fmt::Debug>(result: &Result<T, ExecError>) -> String {
    match result {
        Err(ExecError::Unsupported { kind, detail, .. }) => {
            assert!(!detail.is_empty(), "an Unsupported must say why");
            kind.as_str().to_string()
        }
        Ok(v) => panic!("expected Unsupported, got {v:?}"),
        Err(e) => panic!("expected Unsupported, got {e}"),
    }
}

/// The `Malformed` discriminant of an error, or a failure message.
#[track_caller]
pub fn malformed_kind<T: std::fmt::Debug>(result: &Result<T, ExecError>) -> String {
    match result {
        Err(ExecError::Malformed { kind, detail, .. }) => {
            assert!(!detail.is_empty(), "a Malformed must say what was wrong");
            kind.as_str().to_string()
        }
        Ok(v) => panic!("expected Malformed, got {v:?}"),
        Err(e) => panic!("expected Malformed, got {e}"),
    }
}

/// `Stats` as a one-line summary, for failure messages.
pub fn summary(s: &Stats) -> String {
    format!(
        "{} instructions, {} allocations, {} bytes, {} shim calls, {} opcodes",
        s.instructions_executed,
        s.allocations,
        s.bytes_allocated,
        s.framework_calls,
        s.distinct_opcodes()
    )
}
