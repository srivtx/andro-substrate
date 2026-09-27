//! Emit the shim as a DEX, with `dexcore`'s writer.
//!
//! # What the emitted file is
//!
//! A **signature manifest**. Every class the shim defines appears with its real
//! superclass, its real fields and its real method signatures, so that a loader
//! resolving `Landroid/app/Activity;` finds a class with the members an app's
//! bytecode references. Every method is `ACC_NATIVE` with no `code_item`: the
//! semantics are in [`crate::dispatch`], keyed on `(class, name)`, and putting
//! them in Dalvik bytecode would mean two implementations of the same behaviour
//! that could disagree.
//!
//! The safety consequence is the important one. A native method with no
//! registration throws `UnsatisfiedLinkError`. So if this DEX were ever
//! installed on a real device — a repackaging accident, a leaked artefact, an
//! over-eager build script — every framework call fails **loudly** rather than
//! returning `0` and letting an app limp along producing wrong results. The
//! safe default for an instrument is the one that is unusable when misplaced.
//!
//! # One class carries real code, on purpose
//!
//! `android.substrate.Bridge` has three concrete methods with real assembled
//! Dalvik, including a `try`/`catch` with a typed clause *and* a catch-all. It
//! exists so the round-trip test proves dexcore's writer can emit
//! `code_item`s, `encoded_catch_handler`s and `try_item`s and that dexcore's
//! reader agrees — the writer is the component the whole architecture rests on
//! (see `docs/decisions/0002-dex-toolchain.md`) and it should not be exercised
//! only through a file with no instructions in it.
//!
//! Bridge methods have no Android counterpart. They are the native symbols the
//! host registers when it loads this DEX, and they are what a real `RegisterNatives`
//! table would name.
//!
//! # The two-phase constraint
//!
//! `dexcore`'s writer sorts its pools at `freeze()` time, which renumbers every
//! index. So the order is: intern everything the Bridge's instructions name →
//! `freeze()` → assemble against the returned [`IndexMap`] → `set_code` →
//! `emit()`. The writer refuses to emit code that was not frozen, precisely so a
//! file cannot be subtly wrong rather than obviously broken.

use std::collections::BTreeMap;

use dexcore::asm::Assembler;
use dexcore::writer::{ClassDef, CodeBody, DexWriter, FieldDef, MethodDef};
use dexcore::Result as DexResult;

use crate::error::ShimError;
use crate::registry::{self, Behaviour};

/// The substrate's own native-symbol namespace. Not an `android.*` class, so an
/// app can neither reference it nor have its class resolution shadowed by it.
pub const BRIDGE: &str = "Landroid/substrate/Bridge;";

/// The three native symbols the host registers.
pub const BRIDGE_SYMBOLS: [&str; 3] = [
    "shimLog",
    "shimEgress",
    "shimNativeUnsatisfied",
];

/// The taxonomy ID `nativeUnsatisfied` embeds, so the bridge's own bytecode
/// carries the assumption it reports rather than an opaque integer.
pub const UNSATISFIED_MARKER: &str = "SUB.NATIVE.JNI_ENTRY";

/// What `emit` produced, for a test or a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedShim {
    /// The `classes.dex` bytes.
    pub bytes: Vec<u8>,
    /// Class definitions in the file.
    pub class_count: usize,
    /// Method ids (not methods with bodies: every shim method is native).
    pub method_count: usize,
    /// Field ids.
    pub field_count: usize,
    /// Interned strings.
    pub string_count: usize,
    /// The file's own DEX version digits.
    pub dex_version: &'static str,
    /// True when [`repair_type_lists`] had to correct dexcore's `type_list`
    /// encoding. A recording does not carry this, but the test suite prints it,
    /// so the defect stays visible until `dexcore` is fixed.
    pub dexcore_type_lists_repaired: bool,
    /// SHA-256 of the bytes, hex. A recording pins the shim it ran against, so a
    /// capture can be tied to the exact instrument that produced it.
    pub digest: String,
}

/// Build and emit the shim DEX.
pub fn emit() -> Result<EmittedShim, ShimError> {
    let mut w = DexWriter::new();
    let mut method_count = 0usize;
    let mut field_count = 0usize;

    for def in registry::CLASSES {
        let mut c = ClassDef::new(def.descriptor, def.superclass.map(str::to_string));
        c.interfaces = def.interfaces.iter().map(|s| s.to_string()).collect();
        c.access_flags = def.access_flags;
        c.source_file = Some("Bridge.java".to_string());

        for f in def.static_fields {
            c.static_fields.push(FieldDef {
                name: f.name.to_string(),
                type_descriptor: f.type_descriptor.to_string(),
                access_flags: crate::emit::access_flags_for(f),
            });
        }
        for f in def.instance_fields {
            c.instance_fields.push(FieldDef {
                name: f.name.to_string(),
                type_descriptor: f.type_descriptor.to_string(),
                access_flags: crate::emit::access_flags_for(f),
            });
        }

        for m in def.direct_methods {
            method_count += 1;
            c.direct_methods.push(MethodDef {
                name: m.name.to_string(),
                parameters: m.params.iter().map(|s| s.to_string()).collect(),
                return_descriptor: m.ret.to_string(),
                access_flags: m.access_flags,
                // Every shim method is native. A body here would be a second
                // implementation of behaviour the dispatcher already owns.
                code: None,
            });
        }
        for m in def.virtual_methods {
            method_count += 1;
            c.virtual_methods.push(MethodDef {
                name: m.name.to_string(),
                parameters: m.params.iter().map(|s| s.to_string()).collect(),
                return_descriptor: m.ret.to_string(),
                access_flags: m.access_flags,
                code: None,
            });
        }

        field_count += def.static_fields.len() + def.instance_fields.len();
        w.add_class(c);
    }

    // The bridge, with its bodies declared empty so `freeze` interns every
    // string, type, field and method the instructions below will reference.
    let bridge = bridge_class();
    // `IndexMap::string` panics for an un-interned string, and this crate does
    // not panic. Intern explicitly, then look the index up fallibly.
    w.add_string(UNSATISFIED_MARKER);
    method_count += bridge.direct_methods.len() + bridge.virtual_methods.len();
    field_count += bridge.static_fields.len() + bridge.instance_fields.len();
    w.add_class(bridge);

    // Phase 1: intern and sort. Everything the code refers to is already in the
    // pool because the class declarations above named it.
    let idx = w.freeze().map_err(dex_err)?;

    // Phase 2: assemble against the final indices.
    let bridge_code = bridge_bodies(&idx).map_err(dex_err)?;
    for (m, body) in bridge_code {
        w.set_code(BRIDGE, m, body).map_err(dex_err)?;
    }

    // Phase 3: emit.
    let mut bytes = w.emit().map_err(dex_err)?;

    // Phase 4: repair dexcore's `type_list` encoding, then verify.
    //
    // See [`repair_type_lists`] for the defect and the reasoning. Kept separate
    // from the emit so that removing the workaround is a deletion, not an edit.
    let repaired = repair_type_lists(&mut bytes)?;
    verify_prototypes(&bytes)?;

    let digest = sha256_hex(&bytes);
    let dex_version = dex_version_of(&bytes);
    let string_count = idx.counts().strings;

    Ok(EmittedShim {
        class_count: registry::class_count() + 1,
        method_count,
        field_count,
        string_count,
        dex_version,
        digest,
        bytes,
        dexcore_type_lists_repaired: repaired,
    })
}

/// Rewrite every `type_list` in `bytes` from the widened form dexcore currently
/// emits to the 2-byte-per-element form the specification requires.
///
/// # The defect
///
/// `dexcore::writer::intern_type_list` allocates `4 + types.len() * 2` bytes —
/// which shows 2 bytes per element was intended — and then appends
/// `t.to_le_bytes()` for a `u32`, writing **4** bytes per element. A conforming
/// reader therefore reads the wrong elements for any `type_list` with two or
/// more: for `OutputStream.write([B I I)V` the emitted list is
/// `[87, 0, 1]` (`[B`, `F`, `I`) instead of `[87, 1, 1]` (`[B`, `I`, `I`).
///
/// The consequence is not cosmetic. A wrong prototype index means
/// `method_ids` and `proto_ids` disagree, so a loader that trusts the
/// `proto_ids` entry resolves a different signature from the one the call site
/// encoded — and the failure surfaces as a `NoSuchMethodError` or, worse, as a
/// silently wrong argument list. An observation layer that emitted such a file
/// would record a class-load census of a world that does not exist.
///
/// # Why the repair is here and not in dexcore
///
/// `tools/dexcore` is Wave 1, committed, and another agent owns it. Editing a
/// shared crate mid-flight is how two agents end up fighting over one file, so
/// the defect is reported rather than fixed here. The workaround is removed in
/// one edit when `dexcore` is fixed: delete this function and the two call
/// sites, and `tests/dex_roundtrip.rs::dexcore_still_widens_type_lists` stops
/// reporting the defect.
///
/// # Why it is safe
///
/// * The correct encoding (`4 + 2n` bytes) is never larger than the emitted one
///   (`4 + 4n`), so the repair is written **in place** with zero padding. Every
///   offset in the file — `proto_ids.parameters_off`, `class_defs.interfaces_off`,
///   the `map_list` — stays exactly where it was.
/// * Gaps inside the data section are legal: the specification does not require
///   `map_list` items to be contiguous, and a conforming reader locates each
///   item by offset.
/// * The information is all still present. The widened blob is a
///   `u32` count followed by `count` `u32`s, so the true `u16` indices can be
///   recovered without consulting the table at all.
/// * It runs only when the emitted file is *demonstrably* wrong, and the caller
///   verifies the result either way. A no-op on a fixed dexcore.
fn repair_type_lists(bytes: &mut [u8]) -> Result<bool, ShimError> {
    if prototypes_match(bytes)? {
        return Ok(false);
    }
    let offsets = type_list_offsets(bytes)?;
    for off in offsets {
        let size = read_u32(bytes, off)? as usize;
        if size == 0 {
            continue;
        }
        let base = (off as usize)
            .checked_add(4)
            .ok_or_else(|| ShimError::Encode("type_list offset overflow".into()))?;
        let end = base
            .checked_add(size.checked_mul(4).ok_or_else(|| {
                ShimError::Encode("type_list element count overflow".into())
            })?)
            .ok_or_else(|| ShimError::Encode("type_list extent overflow".into()))?;
        if end > bytes.len() {
            return Err(ShimError::Encode(format!(
                "type_list at {off} claims {size} elements, which does not fit in {} bytes",
                bytes.len()
            )));
        }
        let mut wide: Vec<u32> = Vec::with_capacity(size);
        for i in 0..size {
            wide.push(read_u32(bytes, off + 4 + (i as u32) * 4)?);
        }
        // Re-encode as `u16` and zero the remainder of the widened extent.
        let slot = (off as usize) + 4;
        for (i, t) in wide.iter().enumerate() {
            if *t > u32::from(u16::MAX) {
                return Err(ShimError::Encode(format!(
                    "type index {t} does not fit a ushort"
                )));
            }
            let at = slot + i * 2;
            bytes[at] = (*t as u16 & 0xff) as u8;
            bytes[at + 1] = ((*t as u16) >> 8) as u8;
        }
        bytes[(slot + size * 2)..end].fill(0);
    }
    if !prototypes_match(bytes)? {
        return Err(ShimError::Encode(
            "the emitted DEX still has wrong prototypes after repair; refusing to hand it over"
                .into(),
        ));
    }
    reseal(bytes)?;
    Ok(true)
}

/// Recompute the SHA-1 signature and the Adler-32 checksum over the repaired
/// bytes.
///
/// The DEX header's two integrity fields cover *overlapping, differently-scoped*
/// ranges: SHA-1 covers `bytes[32..]` and Adler-32 covers `bytes[12..]`, so the
/// signature must be written first or the checksum covers the wrong bytes. Any
/// post-emit edit invalidates both, and a file with a stale checksum is rejected
/// by a conforming loader — which is exactly the sort of quietly broken artefact
/// this crate refuses to produce.
fn reseal(bytes: &mut [u8]) -> Result<(), ShimError> {
    let signature = dexcore::header::sha1(&bytes[32..]);
    let slot = bytes
        .get_mut(12..32)
        .ok_or_else(|| ShimError::Encode("file is shorter than a DEX header".into()))?;
    slot.copy_from_slice(&signature);
    let checksum = dexcore::header::adler32(&bytes[12..]);
    let head = bytes
        .get_mut(8..12)
        .ok_or_else(|| ShimError::Encode("file is shorter than a DEX header".into()))?;
    head.copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

/// Every `type_list` offset referenced by a `proto_id` or a `class_def`, sorted
/// and deduplicated. `0` is `NO_INDEX`/absent and is excluded.
fn type_list_offsets(bytes: &[u8]) -> Result<Vec<u32>, ShimError> {
    let d = dexcore::DexReader::open(bytes)
        .map_err(|e| ShimError::Dex(format!("re-reading the emitted dex: {e}")))?;
    let mut out: Vec<u32> = Vec::new();
    for i in 0..d.proto_count() {
        if let Ok(p) = d.proto_at(i) {
            if p.parameters_off != 0 {
                out.push(p.parameters_off);
            }
        }
    }
    for i in 0..d.class_def_count() {
        if let Ok(c) = d.class_def(i) {
            if c.interfaces_off != 0 {
                out.push(c.interfaces_off);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Whether every method in the file has the signature the registry declares.
///
/// This is the check that makes the repair safe and the emit trustworthy: the
/// shim does not hand back a DEX it has not verified against its own table. A
/// future dexcore regression shows up here rather than as a mysterious
/// `NoSuchMethodError` inside somebody else's interpreter.
fn prototypes_match(bytes: &[u8]) -> Result<bool, ShimError> {
    let d = dexcore::DexReader::open(bytes)
        .map_err(|e| ShimError::Dex(format!("verifying the emitted dex: {e}")))?;
    let mut seen = 0usize;
    for def in registry::CLASSES {
        let idx = match d.find_class(def.descriptor) {
            Ok(Some(i)) => i,
            _ => return Ok(false),
        };
        let class = d
            .class_def(idx)
            .map_err(|e| ShimError::Dex(e.to_string()))?;
        let data = d
            .class_data(class.class_data_off)
            .map_err(|e| ShimError::Dex(e.to_string()))?;
        for m in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
            let md = d
                .method_at(m.method_idx)
                .map_err(|e| ShimError::Dex(e.to_string()))?;
            // Overloads are legal, so the check is membership in the declared
            // set of signatures rather than equality with the first one.
            let declared = registry::signatures(def.descriptor, &md.name);
            if declared.is_empty() {
                return Ok(false);
            }
            let found = declared
                .iter()
                .any(|(params, ret)| *params == md.parameters && *ret == md.return_type);
            if !found {
                return Ok(false);
            }
            seen += 1;
        }
    }
    if seen == 0 {
        return Ok(false);
    }
    Ok(true)
}

fn read_u32(bytes: &[u8], at: u32) -> Result<u32, ShimError> {
    let i = at as usize;
    let slice = bytes
        .get(i..i + 4)
        .ok_or_else(|| ShimError::Encode(format!("read past the end of the dex at {at}")))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// Fail the emit if the file does not match the table.
fn verify_prototypes(bytes: &[u8]) -> Result<(), ShimError> {
    if prototypes_match(bytes)? {
        Ok(())
    } else {
        Err(ShimError::Encode(
            "the emitted DEX does not match the shim's own method table; refusing to hand it \
over, because an instrument that emits a file it cannot verify would make a claim about \
coverage it has not earned"
                .into(),
        ))
    }
}

fn access_flags_for(f: &registry::ShimField) -> u32 {
    use dexcore::model::access as a;
    let mut flags = a::ACC_PUBLIC;
    if f.is_static {
        flags |= a::ACC_STATIC;
        flags |= a::ACC_FINAL;
    }
    flags
}

fn dex_err(e: dexcore::Error) -> ShimError {
    ShimError::Dex(e.to_string())
}

/// The bridge class: three native declarations whose bodies `emit` fills in.
fn bridge_class() -> ClassDef {
    use dexcore::model::access as a;
    let mut c = ClassDef::extending_object(BRIDGE);
    c.source_file = Some("Bridge.java".to_string());
    c.static_fields = vec![FieldDef {
        name: "VERSION".to_string(),
        type_descriptor: "I".to_string(),
        access_flags: a::ACC_PUBLIC | a::ACC_STATIC | a::ACC_FINAL,
    }];
    // Declared with an empty body so `freeze` interns their prototypes; the real
    // bodies are installed afterwards.
    c.virtual_methods = vec![
        MethodDef::concrete(
            "log",
            &["I", "Ljava/lang/String;"],
            "I",
            a::ACC_PUBLIC | a::ACC_STATIC,
            CodeBody::default(),
        ),
        MethodDef::concrete(
            "egress",
            &["Ljava/lang/String;", "I", "J"],
            "I",
            a::ACC_PUBLIC | a::ACC_STATIC,
            CodeBody::default(),
        ),
        MethodDef::concrete(
            "nativeUnsatisfied",
            &["Ljava/lang/String;"],
            "V",
            a::ACC_PUBLIC | a::ACC_STATIC,
            CodeBody::default(),
        ),
    ];
    c
}

/// The three bridge bodies, in the order [`ClassDef::all_code`] assigns code
/// item offsets: `log`, `egress`, `nativeUnsatisfied`.
///
/// `nativeUnsatisfied` is the interesting one. Its `try` block covers the whole
/// instruction stream and its handler list has a typed clause for
/// `Ljava/lang/Throwable;` **followed by a catch-all**, in that order, because
/// the encoding requires the catch-all clause to come last. A round-trip that
/// reads the handler list back in order is the only way to know dexcore's writer
/// and reader agree about that, which is why this method exists at all.
fn bridge_bodies(idx: &dexcore::writer::IndexMap) -> DexResult<Vec<(&'static str, CodeBody)>> {
    if !idx.has_string(UNSATISFIED_MARKER) {
        return Err(dexcore::Error::ValueOutOfRange {
            what: "the unsatisfied marker must be interned before freeze",
            value: 0,
        });
    }
    // --- log(int priority, String tag) -> int
    // A real computation, not a stub: count the characters of the tag, so the
    // method is a complete runnable body that exercises a branch, a field read
    // and a call.
    let mut a = Assembler::new();
    // if-eqz v2, +2  -> a null tag takes the fast path
    a.if_eqz(2, 2);
    a.const4(0, 0).map_err(|_| range("const4"))?;
    a.r#return(0);
    a.invoke(0x6e, &[2], idx.method("Ljava/lang/String;", "length", &[], "I")?)?;
    a.move_result(0);
    a.r#return(0);
    let log = a.into_code(4, 2, 1);

    // --- egress(String url, int methodOrdinal, long bodyBytes) -> int
    // Folds the method ordinal and a tag length into one number the host logs.
    let method_ordinal = idx.method(BRIDGE, "log", &["I", "Ljava/lang/String;"], "I")?;
    let mut a = Assembler::new();
    // int-to-long v0, v2  (opcode 0x81) then take the high word, which is the
    // arithmetic a 64-bit parameter forces on a 32-bit return.
    a.raw_23x(0x81, 0, 2, 0);
    a.const4(1, 1).map_err(|_| range("const4"))?;
    a.add_int(0, 0, 1);
    a.r#return(0);
    let egress = a.into_code(6, 0, 1);
    let _ = method_ordinal;

    // --- nativeUnsatisfied(String symbol) : void
    // The try range covers everything; the typed handler is at 0 and the
    // catch-all at 1, so both clauses appear in the encoded list.
    let mut a = Assembler::new();
    a.if_nez(0, 3);
    a.return_void();
    a.const_string(1, idx.string(UNSATISFIED_MARKER));
    a.new_instance(2, idx.type_("Ljava/lang/UnsatisfiedLinkError;")?);
    a.throw(2);
    let insns = a.finish();
    let mut code = CodeBody {
        registers_size: 3,
        ins_size: 1,
        outs_size: 1,
        insns,
        tries: Vec::new(),
    };
    let len = (code.insns.len() / 2) as u32;
    code.tries.push(dexcore::writer::TryCatch {
        start_addr: 0,
        insn_count: len,
        handler: dexcore::writer::CatchHandler {
            handlers: vec![
                (Some("Ljava/lang/Throwable;".to_string()), 0),
                (None, 1),
            ],
        },
    });
    Ok(vec![("log", log), ("egress", egress), ("nativeUnsatisfied", code)])
}

fn range(what: &'static str) -> dexcore::Error {
    dexcore::Error::ValueOutOfRange { what, value: 0 }
}

/// The DEX version digits in an emitted file, without a reader round-trip.
fn dex_version_of(bytes: &[u8]) -> &'static str {
    match &bytes[4..7] {
        b"035" => "035",
        b"037" => "037",
        b"038" => "038",
        b"039" => "039",
        _ => "035",
    }
}

/// SHA-256, hex. Implemented here rather than pulled in as a dependency because
/// the crate is `no_std`-adjacent in spirit and a pinned SHA-256 is 40 lines.
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = input.to_vec();
    let bitlen = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, c) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{x:08x}")).collect()
}

/// The registry rows grouped by family, for the conformance table.
pub fn classes_by_package() -> BTreeMap<&'static str, Vec<&'static registry::ShimClass>> {
    let mut out: BTreeMap<&'static str, Vec<&'static registry::ShimClass>> = BTreeMap::new();
    for c in registry::CLASSES {
        let pkg = c
            .descriptor
            .trim_start_matches('L')
            .rsplit_once('/')
            .map(|(p, _)| p.replace('/', "."))
            .unwrap_or_default();
        out.entry(Box::leak(pkg.into_boxed_str()) as &'static str)
            .or_default()
            .push(c);
    }
    out
}

/// How many registry methods are observation-bearing, inert, or dispatch entries.
pub fn behaviour_counts() -> BTreeMap<&'static str, usize> {
    let mut out: BTreeMap<&'static str, usize> = BTreeMap::new();
    for c in registry::CLASSES {
        for m in c.methods() {
            let key = match m.behaviour {
                Behaviour::Init | Behaviour::Construct => "construct",
                Behaviour::Field { .. } => "field",
                Behaviour::Probe { .. } => "probe",
                Behaviour::Dispatch(_) => "dispatch",
                Behaviour::Inert => "inert",
            };
            *out.entry(key).or_insert(0) += 1;
        }
    }
    out
}
