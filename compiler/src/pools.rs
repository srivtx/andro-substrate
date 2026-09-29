//! Pool lowering: DEX's five id pools to runtime structures.
//!
//! [`IR.md`](../IR.md) declares four imported globals — `$strings`, `$types`,
//! `$methods`, `$fields` — "allocated by the host at load". This module is the
//! other half of that sentence: it builds what those globals point at, from a
//! `dexcore` reader, and gives the guest a *binary-searchable* index for the two
//! pools a compiled instruction stream actually dereferences at run time.
//!
//! # What lowering is for
//!
//! The guest does not re-derive descriptors, does not walk MUTF-8, and does not
//! compare class names. `const-string vAA, string@BBBB` lowers to a load of
//! `string_index[BBBB]`, which is a `(offset, utf16_len)` pair; `invoke-virtual`
//! on a *resolved* target is a direct call, and an unresolved one falls back to
//! a lookup that binary-searches `method_ids` by the triple the instruction
//! names. Everything expensive happens once, here, at load time.
//!
//! # Strings
//!
//! DEX strings are MUTF-8, not UTF-8: `U+0000` is the two-byte overlong `C0 80`
//! and non-BMP characters are stored as a surrogate *pair*. So the payload table
//! holds the MUTF-8 bytes verbatim, and the index holds `(offset, utf16_len)`.
//!
//! `utf16_len` is carried because DEX records it and it is **not** derivable
//! from the MUTF-8 bytes in general: the byte length and the UTF-16 code-unit
//! count diverge for every astral character (six bytes, two units) and for every
//! embedded NUL (two bytes, one unit). The host needs the byte length to
//! materialise a JS string and the UTF-16 length for anything that must agree
//! with Dalvik's own `String.length`, and deriving one from the other is work
//! the guest should not do per access. Measured on the six F-Droid fixtures in
//! `tools/dexcore/tests/`: 777/777 declared `utf16_size` values agree with the
//! count derived from the decoded value, and 0/777 disagree — so the field is
//! redundant *on this corpus* and is kept anyway because redundancy in a
//! load-time table is free and its absence is not.
//!
//! The table also keeps each string's decoded Rust form, because the host
//! materialises strings and needs one.
//!
//! # Types, protos, fields, methods
//!
//! Each pool keeps its DEX indices — a bytecode operand is a pool index, so
//! renumbering would invalidate every instruction in the file. Alongside each
//! index a *resolved* view is emitted: the descriptor string, and for types the
//! class pointer the IR's resolution order chose.
//!
//! **`method_ids` order is load-bearing.** The DEX format requires `method_ids`
//! sorted ascending by `(class_idx, name_idx, proto_idx)`, and
//! `field_ids` by `(class_idx, name_idx, type_idx)`. Binary search is only
//! correct against that order, so [`Pools::lower`] **verifies** it rather than
//! assuming it and reports [`PoolError::MethodPoolUnsorted`] /
//! [`PoolError::FieldPoolUnsorted`] with the offending index. Trusting the
//! format is how you get a lookup that silently returns the wrong method on a
//! malformed APK. Verified on the fixtures: 0/402 `method_ids` and 0/76
//! `field_ids` adjacent-pair order violations.
//!
//! Note *why* comparing `name_idx` is equivalent to comparing the name: the
//! format also requires `string_ids` sorted by the string bytes, so index order
//! and byte order agree. That is a second invariant, checked in the same pass,
//! and a file that violates it would make a name-index comparison wrong in a
//! way that looks like a sort bug. Measured: 777/777 strings in ascending
//! MUTF-8 byte order across all six fixtures.
//!
//! # Call sites and method handles
//!
//! **Present but near-dead. Emitted, reported, not deleted.** Measured on the
//! 120-APK F-Droid sample: `call_site_id_item` in **0/120** files, `invoke-custom`
//! in 0/120, `invoke-polymorphic` in **2/120 (1.7%)** of which **0/60** are in
//! the pure-DEX stratum, `const-method-handle` 0/120. All six fixtures here
//! carry zero of each, confirmed against their `map_list`.
//!
//! The reason they still get code rather than a comment: `invoke-polymorphic`'s
//! prototype is a *`proto_ids` index*, not a method index, so a DEX that uses it
//! has a live code path that the pool tables have to serve. Deadening the tables
//! on today's corpus would mean the first app that uses one fails at load rather
//! than at the instruction, which is a worse failure and a rarer fix. The
//! sections are located through the `map_list` (dexcore does not expose them),
//! decoded, and their counts reported in [`PoolStats::call_sites`] and
//! [`PoolStats::method_handles`] so a build can *see* that it emitted them.
//!
//! # Safety posture
//!
//! Every index into every pool is bounds-checked against the pool's own length
//! and returns a typed [`PoolError`]. No `unsafe`, no `unwrap` outside tests, no
//! recursion (superclass walks are explicit loops, and a cyclic hierarchy is
//! detected rather than looped on).

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use dexcore::model::map_type;
use dexcore::DexReader;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong lowering a DEX file's pools.
///
/// A hostile APK reaches all of these: every count, offset and index in the file
/// is attacker-chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolError {
    /// A pool index was outside the pool.
    IndexOutOfRange {
        /// Which pool.
        pool: &'static str,
        /// The offending index.
        index: u32,
        /// How many entries the pool has.
        len: u32,
    },
    /// A string index, type index, proto index or field index in the file
    /// pointed outside its pool. The file is internally inconsistent.
    DanglingIndex {
        /// Which pool held the bad index.
        pool: &'static str,
        /// The pool the index was meant to refer into.
        into: &'static str,
        /// The offending index.
        index: u32,
        /// Size of the target pool.
        len: u32,
    },
    /// `method_ids` is not sorted by `(class_idx, name_idx, proto_idx)`, so
    /// binary search over it would return wrong answers.
    MethodPoolUnsorted {
        /// The index of the first out-of-order entry.
        at: u32,
        /// Its `(class_idx, name_idx, proto_idx)`.
        key: (u32, u32, u32),
        /// The preceding entry's key.
        prev: (u32, u32, u32),
    },
    /// `field_ids` is not sorted by `(class_idx, name_idx, type_idx)`.
    FieldPoolUnsorted {
        /// The index of the first out-of-order entry.
        at: u32,
        /// Its `(class_idx, name_idx, type_idx)`.
        key: (u32, u32, u32),
        /// The preceding entry's key.
        prev: (u32, u32, u32),
    },
    /// `string_ids` is not sorted by string bytes, which breaks the
    /// name-index-order-equals-name-byte-order equivalence the other two
    /// orderings depend on.
    StringPoolUnsorted {
        /// The index of the first out-of-order entry.
        at: u32,
    },
    /// A `class_defs` superclass chain revisits a class, so the hierarchy has a
    /// cycle. Real class loaders reject this; so does this, rather than looping.
    CyclicHierarchy(String),
    /// A class named itself as its own superclass.
    SelfSuperclass(String),
    /// The file has a `class_defs` count this runtime refuses to materialise.
    TooManyClasses {
        /// The declared count.
        count: u32,
        /// The limit.
        limit: u32,
    },
    /// The file has a `string_ids` count whose payload cannot be addressed by a
    /// `u32` offset, so a `StringRef.offset` would have to be truncated.
    TooManyStrings {
        /// The declared count.
        count: u32,
    },
    /// A size computation on hostile input would have overflowed. Only reachable
    /// from a `class_data_item` claiming an implausible number of instance
    /// fields, so in practice it is a "this file is lying" signal.
    SizeOverflow {
        /// What was being sized.
        what: &'static str,
    },
    /// A `call_site_id_item` or `method_handle_item` offset pointed outside the
    /// file, or named a method handle type that does not exist.
    BadCallSite {
        /// What was being read.
        what: &'static str,
        /// Why.
        detail: String,
    },
    /// `dexcore` rejected the file. Wrapped rather than flattened so the
    /// oracle's own diagnostics survive into this layer.
    Dex(dexcore::Error),
}

impl PoolError {
    /// A stable, machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            PoolError::IndexOutOfRange { .. } => "index_out_of_range",
            PoolError::DanglingIndex { .. } => "dangling_index",
            PoolError::MethodPoolUnsorted { .. } => "method_pool_unsorted",
            PoolError::FieldPoolUnsorted { .. } => "field_pool_unsorted",
            PoolError::StringPoolUnsorted { .. } => "string_pool_unsorted",
            PoolError::CyclicHierarchy(_) => "cyclic_hierarchy",
            PoolError::SelfSuperclass(_) => "self_superclass",
            PoolError::TooManyClasses { .. } => "too_many_classes",
            PoolError::TooManyStrings { .. } => "too_many_strings",
            PoolError::SizeOverflow { .. } => "size_overflow",
            PoolError::BadCallSite { .. } => "bad_call_site",
            PoolError::Dex(_) => "dex",
        }
    }
}

impl fmt::Display for PoolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PoolError::IndexOutOfRange { pool, index, len } => {
                write!(f, "{pool} index {index} out of range (size {len})")
            }
            PoolError::DanglingIndex { pool, into, index, len } => {
                write!(f, "{pool} entry names {into} index {index}, which is out of range (size {len})")
            }
            PoolError::MethodPoolUnsorted { at, key, prev } => write!(
                f,
                "method_ids[{at}] {key:?} sorts before method_ids[{}] {prev:?}; binary search would be wrong",
                at - 1
            ),
            PoolError::FieldPoolUnsorted { at, key, prev } => write!(
                f,
                "field_ids[{at}] {key:?} sorts before field_ids[{}] {prev:?}; binary search would be wrong",
                at - 1
            ),
            PoolError::StringPoolUnsorted { at } => {
                write!(f, "string_ids[{at}] sorts before its predecessor")
            }
            PoolError::CyclicHierarchy(c) => {
                write!(f, "class {c} appears twice in a superclass chain")
            }
            PoolError::SelfSuperclass(c) => write!(f, "class {c} is its own superclass"),
            PoolError::TooManyClasses { count, limit } => {
                write!(f, "{count} classes exceeds the {limit}-class limit")
            }
            PoolError::TooManyStrings { count } => write!(
                f,
                "{count} strings cannot fit in a u32-addressed payload table"
            ),
            PoolError::SizeOverflow { what } => write!(f, "{what} size computation overflowed"),
            PoolError::BadCallSite { what, detail } => write!(f, "malformed {what}: {detail}"),
            PoolError::Dex(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PoolError {}

impl From<dexcore::Error> for PoolError {
    fn from(e: dexcore::Error) -> PoolError {
        PoolError::Dex(e)
    }
}

/// Result alias for pool lowering.
pub type PoolResult<T> = Result<T, PoolError>;

// ---------------------------------------------------------------------------
// Class resolution
// ---------------------------------------------------------------------------

/// Which of the IR's five resolution outcomes a class reference got.
///
/// The order is the IR's, and it is also the *precedence* order, so this enum's
/// discriminant ordering is load-bearing: [`ClassSource::precedence`] sorts a
/// candidate by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClassSource {
    /// 1. In the closure and compiled into the guest module.
    ClosureGenerated,
    /// 2. In the closure, but emitted as a host stub.
    HostStub,
    /// 3. A native method the host provides.
    HostNative,
    /// 4. The app's own class.
    App,
    /// 5. Nothing provides it. A typed error at use, never a silent default.
    Unresolved,
}

impl ClassSource {
    /// Rank for the "host supersedes app" rule: anything host-provided outranks
    /// anything app-provided, and [`ClassSource::Unresolved`] loses to all.
    ///
    /// Within the host side, `ClosureGenerated` sorts *first* because a class we
    /// compiled into the guest is not host-provided at all; the ADR 0005
    /// supersede rule is about a *host* definition displacing an *app* one, and
    /// the IR's numbered list already places the guest-compiled case ahead of
    /// both host cases.
    pub fn precedence(&self) -> u8 {
        match self {
            ClassSource::ClosureGenerated => 0,
            ClassSource::HostStub | ClassSource::HostNative => 1,
            ClassSource::App => 2,
            ClassSource::Unresolved => 3,
        }
    }

    /// A stable name for reports and the JSON error envelope.
    pub fn as_str(&self) -> &'static str {
        match self {
            ClassSource::ClosureGenerated => "closure_generated",
            ClassSource::HostStub => "host_stub",
            ClassSource::HostNative => "host_native",
            ClassSource::App => "app",
            ClassSource::Unresolved => "unresolved",
        }
    }
}

impl fmt::Display for ClassSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the compiler knows about a class when it resolves it.
///
/// Deliberately not a trait with fourteen methods: the pool layer needs exactly
/// these five predicates, and taking them as data means the resolution order
/// lives in one testable function instead of being spread across whoever
/// implements the trait.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassFacts {
    /// Descriptor -> in the closure and compiled into the guest.
    pub closure_generated: BTreeSet<String>,
    /// Descriptor -> in the closure, emitted as a host stub.
    pub host_stub: BTreeSet<String>,
    /// Descriptor -> provided natively by the host.
    pub host_native: BTreeSet<String>,
    /// Descriptor -> defined by the app's own DEX.
    pub app: BTreeSet<String>,
}

impl ClassFacts {
    /// The five sets empty. Everything resolves to [`ClassSource::Unresolved`].
    pub fn empty() -> ClassFacts {
        ClassFacts::default()
    }

    /// Record that `descriptor` is app's own, and return the facts for chaining.
    pub fn with_app(mut self, descriptor: &str) -> ClassFacts {
        self.app.insert(descriptor.to_string());
        self
    }

    /// Record a host stub.
    pub fn with_host_stub(mut self, descriptor: &str) -> ClassFacts {
        self.host_stub.insert(descriptor.to_string());
        self
    }

    /// The IR's resolution order applied to one descriptor.
    ///
    /// Precedence is host > app (ADR 0005), and within the host side the IR's
    /// numbering decides. Returns every candidate that matched, not just the
    /// winner, so a shadowing event can be recorded.
    pub fn resolve(&self, descriptor: &str) -> (ClassSource, Vec<ClassSource>) {
        let mut candidates = Vec::new();
        if self.closure_generated.contains(descriptor) {
            candidates.push(ClassSource::ClosureGenerated);
        }
        if self.host_stub.contains(descriptor) {
            candidates.push(ClassSource::HostStub);
        }
        if self.host_native.contains(descriptor) {
            candidates.push(ClassSource::HostNative);
        }
        if self.app.contains(descriptor) {
            candidates.push(ClassSource::App);
        }
        if candidates.is_empty() {
            return (ClassSource::Unresolved, candidates);
        }
        candidates.sort_by_key(|c| c.precedence());
        let winner = candidates[0];
        (winner, candidates)
    }
}

/// A resolution decision, with the class pointer it was given.
///
/// The pointer is assigned by whoever built the class table, so this is the
/// *record* of a decision rather than the decision procedure. Every shadowing
/// event is kept: the IR requires them recorded, and `shim/`'s 144-shadowing
/// adversarial test is the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Which outcome the IR's order chose.
    pub source: ClassSource,
    /// Index into the runtime class table. Meaningless for
    /// [`ClassSource::Unresolved`].
    pub class_ptr: u32,
    /// Other outcomes that also matched. Non-empty means a shadowing event.
    pub shadowed: Vec<ClassSource>,
}

impl Resolved {
    /// True when more than one source provided this class.
    pub fn is_shadowed(&self) -> bool {
        !self.shadowed.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Runtime class table
// ---------------------------------------------------------------------------

/// Class pointer for a class that could not be resolved.
///
/// The IR says unresolved means "emit a typed error, never a silent default". A
/// distinct sentinel pointer means the error is *detectable at the point of use*
/// — an `instance-of` against it returns [`ClassSource::Unresolved`] rather than
/// matching something plausible.
pub const UNRESOLVED_CLASS: u32 = u32::MAX;

/// Largest class table this build will materialise. A DEX with more `class_defs`
/// than this is refused rather than turned into a multi-gigabyte table.
pub const MAX_CLASSES: u32 = 1 << 22;

/// What kind of thing a class pointer names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassKind {
    /// A normal class or interface with instances.
    Instance,
    /// An array type. Its "superclass" is `java.lang.Object`; its instances are
    /// arrays, not objects.
    Array,
}

/// One entry of the runtime class table: the thing a `class_ptr` indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEntry {
    /// Descriptor, as it appears in `type_ids`.
    pub descriptor: String,
    /// Which resolution outcome produced this entry.
    pub source: ClassSource,
    /// Whether instances are objects or arrays.
    pub kind: ClassKind,
    /// For an array, the `type_ids` index of the component type.
    pub component_type: Option<u32>,
    /// For an instance class, the number of 4-byte slots an instance occupies,
    /// superclass fields first. Zero for arrays and for classes with no
    /// `class_data_item`.
    pub instance_slots: u32,
    /// Reference bitmap, one bit per slot, LSB first within each 64-bit word.
    /// Empty when the class has no reference fields, which is also what an array
    /// class gets.
    pub ref_bitmap: Vec<u64>,
    /// For an instance class, the slot index of each instance field in
    /// declaration order (superclass first), paired with its `field_ids` index.
    pub field_slots: Vec<u32>,
    /// The `field_ids` index for each entry of `field_slots`, parallel to it.
    pub field_ids: Vec<u32>,
}

impl ClassEntry {
    /// True if slot `slot` holds a reference.
    pub fn slot_is_reference(&self, slot: u32) -> bool {
        let word = (slot / 64) as usize;
        let bit = slot % 64;
        self.ref_bitmap.get(word).is_some_and(|w| (w >> bit) & 1 == 1)
    }
}

/// The instance layout of one class: where each field lives.
///
/// A named struct rather than a four-tuple because the four numbers are easy to
/// transpose and a transposed `field_slots`/`field_ids` pair produces a class
/// whose `get-field` reads the wrong field — the kind of bug that survives a
/// round-trip test because both halves are consistently wrong.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct InstanceLayout {
    /// Total 4-byte slots, superclass fields first.
    slots: u32,
    /// Which of those slots hold references.
    reference_slots: Vec<u32>,
    /// Slot of each instance field, in declaration order.
    field_slots: Vec<u32>,
    /// The `field_ids` index of each instance field, parallel to `field_slots`.
    field_ids: Vec<u32>,
}

/// The runtime class table: `class_ptr` indexes this.
///
/// Implements [`crate::heap::ClassLayout`] so the collector can trace without
/// the pool layer knowing anything about the heap.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassTable {
    entries: Vec<ClassEntry>,
    by_descriptor: HashMap<String, u32>,
}

impl ClassTable {
    /// An empty table. Every `class_ptr` is out of range until a class is added.
    pub fn new() -> ClassTable {
        ClassTable::default()
    }

    /// Number of classes.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// True when no class has been added.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `class_ptr`, or `None`.
    pub fn get(&self, class_ptr: u32) -> Option<&ClassEntry> {
        self.entries.get(class_ptr as usize)
    }

    /// Every entry, in `class_ptr` order.
    pub fn entries(&self) -> &[ClassEntry] {
        &self.entries
    }

    /// The `class_ptr` for a descriptor, if the class is in the table.
    pub fn ptr_of(&self, descriptor: &str) -> Option<u32> {
        self.by_descriptor.get(descriptor).copied()
    }

    /// Every descriptor in the table, for a `check-cast` fast path or a report.
    pub fn descriptors(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.descriptor.as_str())
    }

    /// Add a class, returning its `class_ptr`. Rejects a duplicate descriptor,
    /// because two entries with one name is exactly the shadowing situation the
    /// IR wants *recorded*, not silently merged.
    pub fn add(&mut self, entry: ClassEntry) -> PoolResult<u32> {
        if self.entries.len() as u64 >= u64::from(MAX_CLASSES) {
            return Err(PoolError::TooManyClasses { count: self.entries.len() as u32 + 1, limit: MAX_CLASSES });
        }
        if self.by_descriptor.contains_key(&entry.descriptor) {
            // Not an error: the caller resolves precedence first. Returning the
            // existing pointer keeps the invariant "one descriptor, one pointer"
            // true even if a caller adds out of order.
            return Ok(self.by_descriptor[&entry.descriptor]);
        }
        let ptr = self.entries.len() as u32;
        self.by_descriptor.insert(entry.descriptor.clone(), ptr);
        self.entries.push(entry);
        Ok(ptr)
    }

    /// Build the reference bitmap for `slots` given which are references.
    pub fn bitmap_for(reference_slots: &[u32], slots: u32) -> Vec<u64> {
        if reference_slots.is_empty() {
            return Vec::new();
        }
        let words = (slots as usize).div_ceil(64).max(1);
        let mut bitmap = vec![0u64; words];
        for &slot in reference_slots {
            if slot >= slots {
                continue;
            }
            let word = (slot / 64) as usize;
            bitmap[word] |= 1u64 << (slot % 64);
        }
        bitmap.retain(|w| *w != 0);
        bitmap
    }
}

impl crate::heap::ClassLayout for ClassTable {
    fn class_count(&self) -> u32 {
        self.entries.len() as u32
    }

    fn ref_bitmap(&self, class_ptr: u32) -> Option<&[u64]> {
        let e = self.entries.get(class_ptr as usize)?;
        if e.kind != ClassKind::Instance {
            return None;
        }
        Some(&e.ref_bitmap)
    }

    fn instance_slots(&self, class_ptr: u32) -> Option<u32> {
        let e = self.entries.get(class_ptr as usize)?;
        if e.kind != ClassKind::Instance {
            return None;
        }
        Some(e.instance_slots)
    }
}

// ---------------------------------------------------------------------------
// Strings
// ---------------------------------------------------------------------------

/// One entry of the string index: where the bytes are and how long they are in
/// UTF-16 code units.
///
/// This pair is the whole guest-visible index, and it is worth being precise
/// about why two numbers suffice. `utf16_len` is the DEX-declared value, carried
/// verbatim, and it is *not* derivable from the MUTF-8 bytes: a decode pass is
/// needed, because a three-byte sequence is one UTF-16 unit and a six-byte
/// surrogate pair is two. The **byte** length, by contrast, is not derivable from
/// `utf16_len` either — `C0 80` is one unit and two bytes, `ED A0 BD ED B8 80` is
/// two units and six bytes — which is exactly why the payload is NUL-terminated
/// and byte length is found by scanning to the terminator. That scan is
/// unambiguous because MUTF-8 cannot contain a bare `0x00`: the terminator
/// character is encoded as `C0 80`. So the pair plus a terminator is
/// self-describing, and the host keeps the byte length cached anyway so no guest
/// access has to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringRef {
    /// Byte offset into the MUTF-8 payload table, at the first byte of the body.
    pub offset: u32,
    /// UTF-16 code units, as `string_data_item.utf16_size` declares them.
    pub utf16_len: u32,
}

impl StringRef {
    /// The MUTF-8 body plus its terminator, from the payload table.
    ///
    /// Returns the terminating `0x00` too, so the slice can be handed straight to
    /// [`dexcore::mutf8::decode`], which requires it. `None` if no terminator
    /// follows, which cannot happen for a table built by [`StringTable::from_pool`]
    /// but is checked anyway because the table is a plain public struct.
    pub fn terminated_bytes<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        let start = usize::try_from(self.offset).ok()?;
        let rest = payload.get(start..)?;
        let end = rest.iter().position(|b| *b == 0)?;
        rest.get(..=end)
    }

    /// The MUTF-8 body, without the terminator.
    pub fn bytes<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        self.terminated_bytes(payload).map(|s| &s[..s.len() - 1])
    }
}

/// The MUTF-8 string payload plus its index.
///
/// The payload is the MUTF-8 bytes of every string back to back, **each followed
/// by its `0x00` terminator** — the same shape DEX itself uses. The terminator
/// is what makes the `(offset, utf16_len)` index self-describing: without it,
/// neither the byte length nor a decoder's stopping point can be recovered from
/// the pair, because the two lengths genuinely differ. See [`StringRef`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringTable {
    /// Concatenated MUTF-8 bodies, each terminated by `0x00`.
    pub payload: Vec<u8>,
    /// One entry per `string_ids` index.
    pub index: Vec<StringRef>,
    /// Decoded Rust form per index. The host materialises JS strings from this,
    /// so decoding once at load beats decoding per access.
    pub values: Vec<String>,
    /// Indices whose declared `utf16_size` disagreed with the decoded value.
    /// Non-zero means the file is internally inconsistent; the declared value is
    /// still what is emitted, because it is the file's claim and silently
    /// "fixing" it would hide a malformation.
    pub utf16_mismatches: u32,
}

impl StringTable {
    /// An empty table.
    pub fn new() -> StringTable {
        StringTable::default()
    }

    /// Number of strings.
    pub fn len(&self) -> u32 {
        self.index.len() as u32
    }

    /// True when there are no strings.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Total MUTF-8 payload bytes.
    pub fn payload_bytes(&self) -> u32 {
        self.payload.len() as u32
    }

    /// The index entry for `string_idx`.
    pub fn get(&self, string_idx: u32) -> PoolResult<StringRef> {
        self.index.get(string_idx as usize).copied().ok_or(PoolError::IndexOutOfRange {
            pool: "string_ids",
            index: string_idx,
            len: self.len(),
        })
    }

    /// The decoded value for `string_idx`.
    pub fn value(&self, string_idx: u32) -> PoolResult<&str> {
        self.values.get(string_idx as usize).map(String::as_str).ok_or(PoolError::IndexOutOfRange {
            pool: "string_ids",
            index: string_idx,
            len: self.len(),
        })
    }

    /// The MUTF-8 body for `string_idx`, without the terminator.
    pub fn bytes(&self, string_idx: u32) -> PoolResult<&[u8]> {
        self.get(string_idx)?.bytes(&self.payload).ok_or(PoolError::IndexOutOfRange {
            pool: "string_bytes",
            index: string_idx,
            len: self.payload_bytes(),
        })
    }

    /// The MUTF-8 body *and* its terminator, which is what
    /// [`dexcore::mutf8::decode`] needs.
    pub fn terminated_bytes(&self, string_idx: u32) -> PoolResult<&[u8]> {
        self.get(string_idx)?.terminated_bytes(&self.payload).ok_or(PoolError::IndexOutOfRange {
            pool: "string_bytes",
            index: string_idx,
            len: self.payload_bytes(),
        })
    }

    /// Build the table from a decoded string pool.
    fn from_pool(dex: &DexReader<'_>) -> PoolResult<StringTable> {
        let mut table = StringTable::new();
        let count = dex.string_count();
        table.index.reserve(count as usize);
        table.values.reserve(count as usize);
        for i in 0..count {
            let s = dex.string(i)?;
            // `mutf8::encode` already appends the `0x00` terminator, which is
            // exactly the payload shape this table wants.
            let bytes = dexcore::mutf8::encode(&s.value);
            let offset = u32::try_from(table.payload.len()).map_err(|_| {
                PoolError::BadCallSite { what: "string pool", detail: "string table exceeds 4 GiB".into() }
            })?;
            table.payload.extend_from_slice(&bytes);
            // The declared UTF-16 length is the file's claim. Cross-check it
            // against the decoded value and count the disagreements rather than
            // failing: a disagreement is evidence about the file, and the
            // evidence is worth more than the refusal.
            let derived = s.value.encode_utf16().count() as u32;
            if derived != s.utf16_size {
                table.utf16_mismatches = table.utf16_mismatches.saturating_add(1);
            }
            table.index.push(StringRef { offset, utf16_len: s.utf16_size });
            table.values.push(s.value);
        }
        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// Types, protos, fields, methods
// ---------------------------------------------------------------------------

/// A `type_ids` entry, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEntry {
    /// `type_ids[idx].descriptor_idx`, kept so the descriptor can be found.
    pub descriptor_idx: u32,
    /// The descriptor itself, e.g. `Ljava/lang/String;` or `[I`.
    pub descriptor: String,
    /// How this class reference resolved, per the IR's order.
    pub resolution: Resolved,
}

impl TypeEntry {
    /// True for `V Z B S C I J F D`.
    pub fn is_primitive(&self) -> bool {
        matches!(
            self.descriptor.as_str(),
            "V" | "Z" | "B" | "S" | "C" | "I" | "J" | "F" | "D"
        )
    }

    /// True for a descriptor starting with `[`.
    pub fn is_array(&self) -> bool {
        self.descriptor.starts_with('[')
    }

    /// The component descriptor of an array type, or `None`.
    pub fn component_descriptor(&self) -> Option<&str> {
        self.descriptor.get(1..)
    }
}

/// The `type_ids` table: DEX index to descriptor plus resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeTable {
    /// Indexed by `type_ids` index.
    pub entries: Vec<TypeEntry>,
}

impl TypeTable {
    /// Number of types.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// True when there are no types.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `type_idx`.
    pub fn get(&self, type_idx: u32) -> PoolResult<&TypeEntry> {
        self.entries.get(type_idx as usize).ok_or(PoolError::IndexOutOfRange {
            pool: "type_ids",
            index: type_idx,
            len: self.len(),
        })
    }

    /// The descriptor at `type_idx`.
    pub fn descriptor(&self, type_idx: u32) -> PoolResult<&str> {
        Ok(&self.get(type_idx)?.descriptor)
    }

    /// The `class_ptr` a `type_idx` resolved to.
    pub fn class_ptr(&self, type_idx: u32) -> PoolResult<u32> {
        Ok(self.get(type_idx)?.resolution.class_ptr)
    }
}

/// A `proto_ids` entry, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoEntry {
    /// `proto_ids[idx]`, kept for correlation.
    pub shorty_idx: u32,
    /// The shorty descriptor, e.g. `VL`. **Return type first** — verified
    /// against real d8 output, see the module documentation.
    pub shorty: String,
    /// `type_ids` index of the return type.
    pub return_type_idx: u32,
    /// `type_ids` indices of the parameters, in order.
    pub parameter_type_idx: Vec<u32>,
}

impl ProtoEntry {
    /// The signature, e.g. `(Ljava/lang/String;I)V`.
    pub fn signature(&self, types: &TypeTable) -> PoolResult<String> {
        let mut s = String::from("(");
        for &p in &self.parameter_type_idx {
            s.push_str(types.descriptor(p)?);
        }
        s.push(')');
        s.push_str(types.descriptor(self.return_type_idx)?);
        Ok(s)
    }

    /// Parameter count, the number of ABI slots this proto occupies.
    pub fn arity(&self) -> u32 {
        self.parameter_type_idx.len() as u32
    }

    /// True if the proto is `(params...)V`.
    pub fn returns_void(&self, types: &TypeTable) -> bool {
        types.descriptor(self.return_type_idx).map(|d| d == "V").unwrap_or(false)
    }
}

/// The `proto_ids` table, indexed by DEX proto index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtoTable {
    /// Indexed by `proto_ids` index.
    pub entries: Vec<ProtoEntry>,
}

impl ProtoTable {
    /// Number of protos.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// True when there are no protos.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `proto_idx`.
    pub fn get(&self, proto_idx: u32) -> PoolResult<&ProtoEntry> {
        self.entries.get(proto_idx as usize).ok_or(PoolError::IndexOutOfRange {
            pool: "proto_ids",
            index: proto_idx,
            len: self.len(),
        })
    }
}

/// A `field_ids` entry. Indexed by `field_ids` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldEntry {
    /// `field_ids[idx].class_idx`.
    pub class_idx: u32,
    /// `field_ids[idx].name_idx`.
    pub name_idx: u32,
    /// `field_ids[idx].type_idx`.
    pub type_idx: u32,
}

impl FieldEntry {
    /// The sort key the DEX format requires for `field_ids`.
    pub fn sort_key(&self) -> (u32, u32, u32) {
        (self.class_idx, self.name_idx, self.type_idx)
    }

    /// The signature, e.g. `Lcom/x/Y;.z:I`.
    pub fn signature(&self, types: &TypeTable, strings: &StringTable) -> PoolResult<String> {
        Ok(format!(
            "{}.{}:{}",
            types.descriptor(self.class_idx)?,
            strings.value(self.name_idx)?,
            types.descriptor(self.type_idx)?
        ))
    }
}

/// The `field_ids` table, in DEX order, which the format guarantees is sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldTable {
    /// Indexed by `field_ids` index.
    pub entries: Vec<FieldEntry>,
}

impl FieldTable {
    /// Number of fields.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// True when there are no fields.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `field_idx`.
    pub fn get(&self, field_idx: u32) -> PoolResult<FieldEntry> {
        self.entries.get(field_idx as usize).copied().ok_or(PoolError::IndexOutOfRange {
            pool: "field_ids",
            index: field_idx,
            len: self.len(),
        })
    }

    /// Binary search for `(class_idx, name_idx, type_idx)`.
    ///
    /// Correct **because** [`Pools::lower`] verified the whole table is sorted by
    /// that key, and because the string pool was verified sorted by bytes so
    /// name-index order is name-byte order. Both checks are load-time; neither
    /// is re-done here, and neither should be, because a per-lookup sort check
    /// would cost more than the search.
    pub fn find(&self, class_idx: u32, name_idx: u32, type_idx: u32) -> Option<u32> {
        let key = (class_idx, name_idx, type_idx);
        let mut lo = 0usize;
        let mut hi = self.entries.len();
        while lo < hi {
            // `lo + (hi - lo) / 2` rather than `(lo + hi) / 2`: the latter
            // overflows on a hostile table near `usize::MAX` elements.
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].sort_key() < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        self.entries.get(lo).filter(|e| e.sort_key() == key).map(|_| lo as u32)
    }
}

/// A `method_ids` entry. Indexed by `method_ids` index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodEntry {
    /// `method_ids[idx].class_idx`.
    pub class_idx: u32,
    /// `method_ids[idx].name_idx`.
    pub name_idx: u32,
    /// `method_ids[idx].proto_idx`.
    pub proto_idx: u32,
}

impl MethodEntry {
    /// The sort key the DEX format requires for `method_ids`.
    pub fn sort_key(&self) -> (u32, u32, u32) {
        (self.class_idx, self.name_idx, self.proto_idx)
    }

    /// The signature, e.g. `Lcom/x/Y;.z(Ljava/lang/String;I)V`.
    pub fn signature(&self, types: &TypeTable, protos: &ProtoTable, strings: &StringTable) -> PoolResult<String> {
        Ok(format!(
            "{}.{}{}",
            types.descriptor(self.class_idx)?,
            strings.value(self.name_idx)?,
            protos.get(self.proto_idx)?.signature(types)?
        ))
    }
}

/// The `method_ids` table, in DEX order, which the format guarantees is sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MethodTable {
    /// Indexed by `method_ids` index.
    pub entries: Vec<MethodEntry>,
}

impl MethodTable {
    /// Number of methods.
    pub fn len(&self) -> u32 {
        self.entries.len() as u32
    }

    /// True when there are no methods.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry at `method_idx`.
    pub fn get(&self, method_idx: u32) -> PoolResult<MethodEntry> {
        self.entries.get(method_idx as usize).copied().ok_or(PoolError::IndexOutOfRange {
            pool: "method_ids",
            index: method_idx,
            len: self.len(),
        })
    }

    /// Binary search for `(class_idx, name_idx, proto_idx)`.
    ///
    /// The correctness argument is the same as [`FieldTable::find`]: the table is
    /// verified sorted by this exact key at load time. See [`Pools::lower`].
    pub fn find(&self, class_idx: u32, name_idx: u32, proto_idx: u32) -> Option<u32> {
        let key = (class_idx, name_idx, proto_idx);
        let mut lo = 0usize;
        let mut hi = self.entries.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].sort_key() < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        self.entries.get(lo).filter(|e| e.sort_key() == key).map(|_| lo as u32)
    }

    /// Every method a class declares, by searching its whole range.
    ///
    /// Uses the same binary search and the same verified ordering, so this is
    /// `O(log n + k)` rather than a scan — which matters because virtual dispatch
    /// resolves a method reference by class and this is the operation it needs.
    pub fn find_all_in_class(&self, class_idx: u32) -> Vec<u32> {
        // The key `(class_idx, 0, 0)` is a lower bound only if `0` is the
        // smallest possible name_idx, which it is: index 0 is in range for any
        // non-empty pool. If the pool is empty the loop below cannot run.
        let mut lo = 0usize;
        let mut hi = self.entries.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if self.entries[mid].class_idx < class_idx {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let start = lo;
        self.entries[start..]
            .iter()
            .take_while(|e| e.class_idx == class_idx)
            .enumerate()
            .map(|(i, _)| (start + i) as u32)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Call sites and method handles: emitted, near-dead, not deleted
// ---------------------------------------------------------------------------

/// `method_handle_item.method_handle_type`, per the DEX specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MethodHandleKind {
    /// 0 — `static get`.
    StaticGet,
    /// 1 — `instance get`.
    InstanceGet,
    /// 2 — `constructor invoke`.
    ConstructorInvoke,
    /// 3 — `interface invoke`.
    InterfaceInvoke,
    /// 4 — `field get`.
    FieldGet,
    /// 5 — `field set`.
    FieldSet,
}

impl MethodHandleKind {
    /// Decode a raw `method_handle_type`.
    pub fn from_raw(raw: u16) -> Option<MethodHandleKind> {
        match raw {
            0 => Some(MethodHandleKind::StaticGet),
            1 => Some(MethodHandleKind::InstanceGet),
            2 => Some(MethodHandleKind::ConstructorInvoke),
            3 => Some(MethodHandleKind::InterfaceInvoke),
            4 => Some(MethodHandleKind::FieldGet),
            5 => Some(MethodHandleKind::FieldSet),
            _ => None,
        }
    }

    /// True for kinds 0..=3, which reference `method_ids`; false for 4 and 5,
    /// which reference `field_ids`.
    pub fn is_method(&self) -> bool {
        matches!(
            self,
            MethodHandleKind::StaticGet
                | MethodHandleKind::InstanceGet
                | MethodHandleKind::ConstructorInvoke
                | MethodHandleKind::InterfaceInvoke
        )
    }

    /// A stable name.
    pub fn as_str(&self) -> &'static str {
        match self {
            MethodHandleKind::StaticGet => "static_get",
            MethodHandleKind::InstanceGet => "instance_get",
            MethodHandleKind::ConstructorInvoke => "constructor_invoke",
            MethodHandleKind::InterfaceInvoke => "interface_invoke",
            MethodHandleKind::FieldGet => "field_get",
            MethodHandleKind::FieldSet => "field_set",
        }
    }
}

/// A decoded `method_handle_item`.
///
/// Near-dead: **0/120** F-Droid APKs carry a `method_handle_item` section
/// (measured, `analysis/prediction.md`). Emitted anyway, because
/// `invoke-polymorphic` — **2/120**, and 0/60 in the pure-DEX stratum — names a
/// prototype through this table's cousin, and a load-time table that is missing
/// a section fails the whole file rather than one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodHandle {
    /// The `method_handle_type`.
    pub kind: MethodHandleKind,
    /// `field_or_method_id`: a `method_ids` index for kinds 0..=3, a
    /// `field_ids` index for 4 and 5.
    pub member_idx: u32,
}

/// A decoded `call_site_item`.
///
/// Near-dead: **0/120** F-Droid APKs carry a `call_site_id_item` section, and
/// `invoke-custom` appears in **0/120** (measured, `analysis/prediction.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// The bootstrap method handle.
    pub bootstrap: MethodHandle,
    /// Byte offset of the `encoded_array` of bootstrap arguments.
    pub bootstrap_args_off: u32,
    /// Number of bootstrap arguments, from the `encoded_array` size prefix.
    pub arg_count: u32,
    /// The arguments themselves, as raw encoded values. Left undecoded: nothing
    /// in the corpus uses them and decoding `encoded_value` for a 0/120 path
    /// would be code with no test that can ever fail honestly.
    pub arg_bytes: Vec<u8>,
}

/// The `call_site_ids` and `method_handles` tables.
///
/// Both empty for the whole fixture corpus, and both non-empty-tolerant: a DEX
/// with no `call_site_id_item` map entry lowers to an empty table without error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallSiteTable {
    /// Indexed by `call_site_ids` index.
    pub call_sites: Vec<CallSite>,
    /// Indexed by `method_handles` index.
    pub method_handles: Vec<MethodHandle>,
}

impl CallSiteTable {
    /// True when the file declared neither section, which is 0/120 of the corpus
    /// and therefore the overwhelmingly common case.
    pub fn is_empty(&self) -> bool {
        self.call_sites.is_empty() && self.method_handles.is_empty()
    }

    /// The call site at `call_site_idx`.
    pub fn get(&self, call_site_idx: u32) -> PoolResult<&CallSite> {
        self.call_sites.get(call_site_idx as usize).ok_or(PoolError::IndexOutOfRange {
            pool: "call_site_ids",
            index: call_site_idx,
            len: self.call_sites.len() as u32,
        })
    }

    /// The method handle at `method_handle_idx`.
    pub fn method_handle(&self, method_handle_idx: u32) -> PoolResult<MethodHandle> {
        self.method_handles.get(method_handle_idx as usize).copied().ok_or(PoolError::IndexOutOfRange {
            pool: "method_handles",
            index: method_handle_idx,
            len: self.method_handles.len() as u32,
        })
    }

    /// Locate the two sections through the `map_list` and decode them.
    ///
    /// `dexcore` does not expose either section, and neither does its writer, so
    /// this reads the raw bytes at offsets the `map_list` vouches for. Every read
    /// is bounds-checked against the file length and a bad offset is a
    /// [`PoolError::BadCallSite`], never a panic.
    fn from_dex(dex: &DexReader<'_>, method_count: u32, field_count: u32) -> PoolResult<CallSiteTable> {
        let bytes = dex.bytes();
        let map = dex.map_list()?;

        let section = |want: u16| -> Option<(u32, u32)> {
            map.iter()
                .find(|m| m.item_type == want)
                .map(|m| (m.offset, m.size))
        };

        let mut table = CallSiteTable::default();

        if let Some((off, size)) = section(map_type::METHOD_HANDLE_ITEM) {
            let base = off as usize;
            for i in 0..size as usize {
                let at = base + i * 8;
                let raw_kind = read_u16(bytes, at).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("entry {i} at byte {at} runs past the file"),
                })?;
                let kind = MethodHandleKind::from_raw(raw_kind).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("entry {i} declares unknown method_handle_type {raw_kind}"),
                })?;
                let member_idx = read_u32(bytes, at + 4).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("entry {i} at byte {at} runs past the file"),
                })?;
                // A handle naming a member index outside its pool is a dead link;
                // refusing here means the failure names the link rather than
                // surfacing later as a confusing `invoke-custom` error.
                let limit = if kind.is_method() { method_count } else { field_count };
                if member_idx >= limit {
                    return Err(PoolError::BadCallSite {
                        what: "method_handle_item",
                        detail: format!(
                            "entry {i} is a {} naming member index {member_idx}, but the pool has {limit}",
                            kind.as_str()
                        ),
                    });
                }
                table.method_handles.push(MethodHandle { kind, member_idx });
            }
        }

        if let Some((off, size)) = section(map_type::CALL_SITE_ID_ITEM) {
            let base = off as usize;
            for i in 0..size as usize {
                let site_off = read_u32(bytes, base + i * 4).ok_or_else(|| PoolError::BadCallSite {
                    what: "call_site_id_item",
                    detail: format!("entry {i} runs past the file"),
                })?;
                if site_off == 0 {
                    return Err(PoolError::BadCallSite {
                        what: "call_site_id_item",
                        detail: format!("entry {i} has a zero call_site_off"),
                    });
                }
                let at = site_off as usize;
                let args_off = read_u32(bytes, at).ok_or_else(|| PoolError::BadCallSite {
                    what: "call_site_item",
                    detail: format!("at byte {at} runs past the file"),
                })?;
                let handle_off = read_u32(bytes, at + 4).ok_or_else(|| PoolError::BadCallSite {
                    what: "call_site_item",
                    detail: format!("at byte {at} runs past the file"),
                })?;
                if handle_off == 0 {
                    return Err(PoolError::BadCallSite {
                        what: "call_site_item",
                        detail: format!("at byte {at} has a zero method_handle_off"),
                    });
                }
                let hat = handle_off as usize;
                let raw_kind = read_u16(bytes, hat).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("at byte {hat} runs past the file"),
                })?;
                let kind = MethodHandleKind::from_raw(raw_kind).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("at byte {hat} declares unknown method_handle_type {raw_kind}"),
                })?;
                let member_idx = read_u32(bytes, hat + 4).ok_or_else(|| PoolError::BadCallSite {
                    what: "method_handle_item",
                    detail: format!("at byte {hat} runs past the file"),
                })?;
                let bootstrap = MethodHandle { kind, member_idx };

                // Bootstrap arguments: read the `encoded_array` size prefix and
                // keep the raw bytes. A size that would run past the file is an
                // error rather than a truncated read.
                let (arg_count, arg_bytes) = if args_off == 0 {
                    (0, Vec::new())
                } else {
                    let aat = args_off as usize;
                    let (count, hdr) = dexcore::mutf8::read_uleb128(bytes, aat)?;
                    // `encoded_value` is 1..5 bytes; 5 is the widest possible, so
                    // `count * 5` bounds the array from above without decoding.
                    let bound = (count as u64).saturating_mul(5);
                    let end = (aat as u64)
                        .saturating_add(hdr as u64)
                        .saturating_add(bound)
                        .min(bytes.len() as u64) as usize;
                    let slice = bytes.get(aat..end).ok_or_else(|| PoolError::BadCallSite {
                        what: "encoded_array",
                        detail: format!("at byte {aat} runs past the file"),
                    })?;
                    (count, slice.to_vec())
                };

                table.call_sites.push(CallSite { bootstrap, bootstrap_args_off: args_off, arg_count, arg_bytes });
            }
        }

        Ok(table)
    }
}

/// A `type_ids` descriptor, read through the reader so a bad index is
/// `dexcore`'s typed error rather than a slice index here.
fn types_descriptor(dex: &DexReader<'_>, type_idx: u32) -> PoolResult<String> {
    Ok(dex.type_name(type_idx)?)
}

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let s = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let s = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

// ---------------------------------------------------------------------------
// The lowered pools
// ---------------------------------------------------------------------------

/// Counts of what was lowered, for a build report.
///
/// `call_sites` and `method_handles` are here precisely so that a build *shows*
/// that it emitted a near-dead section, rather than the section being invisible
/// until an app uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolStats {
    /// Strings in the payload table.
    pub strings: u32,
    /// MUTF-8 payload bytes.
    pub string_bytes: u32,
    /// Types.
    pub types: u32,
    /// Protos.
    pub protos: u32,
    /// Fields.
    pub fields: u32,
    /// Methods.
    pub methods: u32,
    /// Classes in the runtime class table.
    pub classes: u32,
    /// `call_site_ids` entries decoded. **0/120** on the F-Droid corpus.
    pub call_sites: u32,
    /// `method_handles` entries decoded. **0/120** on the F-Droid corpus.
    pub method_handles: u32,
    /// Types whose descriptor begins with `[`.
    pub array_types: u32,
    /// Shadowing events: a class more than one source provides.
    pub shadowed_classes: u32,
    /// Types that resolved to nothing.
    pub unresolved_types: u32,
}

/// The whole lowered pool set for one DEX file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pools {
    /// MUTF-8 strings and their index.
    pub strings: StringTable,
    /// `type_ids`, resolved.
    pub types: TypeTable,
    /// `proto_ids`.
    pub protos: ProtoTable,
    /// `field_ids`, sorted and verified.
    pub fields: FieldTable,
    /// `method_ids`, sorted and verified.
    pub methods: MethodTable,
    /// The runtime class table `class_ptr` indexes.
    pub classes: ClassTable,
    /// `call_site_ids` and `method_handles`. Near-dead; see [`CallSiteTable`].
    pub call_sites: CallSiteTable,
    /// What was lowered.
    pub stats: PoolStats,
}

impl Pools {
    /// Lower every pool of `bytes`.
    ///
    /// `facts` is what the compiler knows about class resolution. With
    /// [`ClassFacts::empty`] every class resolves to
    /// [`ClassSource::Unresolved`] and gets [`UNRESOLVED_CLASS`], which is a
    /// legitimate state to be in — the host fills the class table in later, from
    /// the closure and the host stub set.
    pub fn lower(bytes: &[u8], facts: &ClassFacts) -> PoolResult<Pools> {
        let dex = DexReader::open(bytes)?;
        Pools::from_reader(&dex, facts)
    }

    /// Lower every pool of an already-open reader.
    pub fn from_reader(dex: &DexReader<'_>, facts: &ClassFacts) -> PoolResult<Pools> {
        Pools::check_string_budget(dex)?;
        let strings = StringTable::from_pool(dex)?;
        Pools::verify_string_order(dex, &strings)?;

        let mut types = Pools::lower_types(dex, facts)?;
        let protos = Pools::lower_protos(dex)?;
        let fields = Pools::lower_fields(dex)?;
        let methods = Pools::lower_methods(dex)?;
        let call_sites = CallSiteTable::from_dex(dex, methods.len(), fields.len())?;
        let classes = Pools::build_class_table(dex, &mut types, &fields, facts)?;

        let shadowed = types.entries.iter().filter(|t| t.resolution.is_shadowed()).count() as u32;
        let unresolved = types
            .entries
            .iter()
            .filter(|t| t.resolution.source == ClassSource::Unresolved)
            .count() as u32;
        let array_types = types.entries.iter().filter(|t| t.is_array()).count() as u32;

        let stats = PoolStats {
            strings: strings.len(),
            string_bytes: strings.payload_bytes(),
            types: types.len(),
            protos: protos.len(),
            fields: fields.len(),
            methods: methods.len(),
            classes: classes.len(),
            call_sites: call_sites.call_sites.len() as u32,
            method_handles: call_sites.method_handles.len() as u32,
            array_types,
            shadowed_classes: shadowed,
            unresolved_types: unresolved,
        };

        Ok(Pools { strings, types, protos, fields, methods, classes, call_sites, stats })
    }

    /// The string pool must be sorted by string bytes, or comparing `name_idx`
    /// is not the same as comparing names and the method/field binary searches
    /// become wrong for a reason that looks like a sort bug.
    ///
    /// Checked on the raw MUTF-8 bytes rather than the decoded values, because
    /// that is the order the format specifies and the order a conforming
    /// producer wrote. A lone surrogate decodes to U+FFFD, which would perturb a
    /// value comparison without perturbing a byte comparison.
    fn verify_string_order(dex: &DexReader<'_>, _table: &StringTable) -> PoolResult<()> {
        let mut prev: Option<Vec<u8>> = None;
        for i in 0..dex.string_count() {
            let s = dex.string(i)?;
            let bytes = dexcore::mutf8::encode(&s.value);
            if let Some(p) = &prev {
                if p > &bytes {
                    return Err(PoolError::StringPoolUnsorted { at: i });
                }
            }
            prev = Some(bytes);
        }
        Ok(())
    }

    /// Refuse a `string_ids` count that would make the payload table larger than
    /// a handle can address.
    ///
    /// Not a fudge factor: an MUTF-8 body is at least one byte plus its
    /// terminator, so `count` strings need at least `2 * count` payload bytes, and
    /// an offset is a `u32`. The limit is what makes `StringRef.offset` sound
    /// rather than a truncation.
    fn check_string_budget(dex: &DexReader<'_>) -> PoolResult<()> {
        let count = u64::from(dex.string_count());
        if count.saturating_mul(2) > u64::from(u32::MAX) {
            return Err(PoolError::TooManyStrings { count: dex.string_count() });
        }
        Ok(())
    }

    /// Lower `type_ids`, resolving each descriptor through the IR's order.
    fn lower_types(dex: &DexReader<'_>, facts: &ClassFacts) -> PoolResult<TypeTable> {
        let count = dex.type_count();
        let mut table = TypeTable { entries: Vec::with_capacity(count as usize) };
        for i in 0..count {
            let t = dex.type_at(i)?;
            // Guard the descriptor_idx: a hostile file can point a type at a
            // string index that does not exist, and `type_at` would have failed
            // inside dexcore, but the check is cheap and the error should name
            // the pool relationship rather than the string pool.
            if t.descriptor_idx >= dex.string_count() {
                return Err(PoolError::DanglingIndex {
                    pool: "type_ids",
                    into: "string_ids",
                    index: t.descriptor_idx,
                    len: dex.string_count(),
                });
            }
            let (source, shadowed) = facts.resolve(&t.descriptor);
            table.entries.push(TypeEntry {
                descriptor_idx: t.descriptor_idx,
                descriptor: t.descriptor,
                resolution: Resolved {
                    source,
                    class_ptr: if source == ClassSource::Unresolved { UNRESOLVED_CLASS } else { 0 },
                    shadowed,
                },
            });
        }
        Ok(table)
    }

    /// Lower `proto_ids`.
    ///
    /// The parameter `type_list` is read by `dexcore`, which reads its size as a
    /// `u32` — verified against real d8 output, **179/179** parameter type
    /// lists in the fixture corpus self-consistent under `u32` and only 119/179
    /// under uleb128. That is a format fact, not a `dexcore` quirk, and it is why
    /// this module does not parse `type_list` itself.
    fn lower_protos(dex: &DexReader<'_>) -> PoolResult<ProtoTable> {
        let count = dex.proto_count();
        let type_count = dex.type_count();
        let mut table = ProtoTable { entries: Vec::with_capacity(count as usize) };
        for i in 0..count {
            let p = dex.proto_at(i)?;
            if p.shorty_idx >= dex.string_count() {
                return Err(PoolError::DanglingIndex {
                    pool: "proto_ids",
                    into: "string_ids",
                    index: p.shorty_idx,
                    len: dex.string_count(),
                });
            }
            if p.return_type_idx >= type_count {
                return Err(PoolError::DanglingIndex {
                    pool: "proto_ids",
                    into: "type_ids",
                    index: p.return_type_idx,
                    len: type_count,
                });
            }
            // `DexProto.parameters` holds *descriptors*; the index structures
            // want `type_ids` indices, because a `code_item`'s register mapping
            // and the ABI both speak indices. Re-read the `type_list` for the
            // indices rather than searching the type pool per parameter, which
            // would be O(n^2) over the whole file.
            let parameter_type_idx = if p.parameters_off == 0 {
                Vec::new()
            } else {
                let list = dex.type_list(p.parameters_off)?;
                for &t in &list {
                    if t >= type_count {
                        return Err(PoolError::DanglingIndex {
                            pool: "proto_ids",
                            into: "type_ids",
                            index: t,
                            len: type_count,
                        });
                    }
                }
                list
            };
            // Cross-check the indices against the descriptors dexcore resolved.
            // A mismatch means the `type_list` was read inconsistently with the
            // proto, which on a hostile file is exactly the kind of internal
            // inconsistency worth refusing.
            if parameter_type_idx.len() != p.parameters.len() {
                return Err(PoolError::DanglingIndex {
                    pool: "proto_ids",
                    into: "type_list",
                    index: parameter_type_idx.len() as u32,
                    len: p.parameters.len() as u32,
                });
            }
            for (k, &t) in parameter_type_idx.iter().enumerate() {
                if types_descriptor(dex, t)? != p.parameters[k] {
                    return Err(PoolError::DanglingIndex {
                        pool: "proto_ids",
                        into: "type_ids",
                        index: t,
                        len: type_count,
                    });
                }
            }
            table.entries.push(ProtoEntry {
                shorty_idx: p.shorty_idx,
                shorty: p.shorty,
                return_type_idx: p.return_type_idx,
                parameter_type_idx,
            });
        }
        Ok(table)
    }

    /// Lower `field_ids` and verify the sort order the format requires.
    fn lower_fields(dex: &DexReader<'_>) -> PoolResult<FieldTable> {
        let count = dex.field_count();
        let mut table = FieldTable { entries: Vec::with_capacity(count as usize) };
        for i in 0..count {
            table.entries.push(Pools::raw_field(dex, i)?);
        }
        for i in 1..count {
            let prev = table.entries[(i - 1) as usize].sort_key();
            let key = table.entries[i as usize].sort_key();
            if key < prev {
                return Err(PoolError::FieldPoolUnsorted { at: i, key, prev });
            }
        }
        Ok(table)
    }

    fn raw_field(dex: &DexReader<'_>, i: u32) -> PoolResult<FieldEntry> {
        let f = dex.field_at(i)?;
        let type_count = dex.type_count();
        if f.class_idx >= type_count {
            return Err(PoolError::DanglingIndex {
                pool: "field_ids",
                into: "type_ids",
                index: f.class_idx,
                len: type_count,
            });
        }
        if f.type_idx >= type_count {
            return Err(PoolError::DanglingIndex {
                pool: "field_ids",
                into: "type_ids",
                index: f.type_idx,
                len: type_count,
            });
        }
        if f.name_idx >= dex.string_count() {
            return Err(PoolError::DanglingIndex {
                pool: "field_ids",
                into: "string_ids",
                index: f.name_idx,
                len: dex.string_count(),
            });
        }
        Ok(FieldEntry { class_idx: f.class_idx, name_idx: f.name_idx, type_idx: f.type_idx })
    }

    /// Lower `method_ids` and verify the sort order the format requires.
    fn lower_methods(dex: &DexReader<'_>) -> PoolResult<MethodTable> {
        let count = dex.method_count();
        let type_count = dex.type_count();
        let mut table = MethodTable { entries: Vec::with_capacity(count as usize) };
        for i in 0..count {
            let m = dex.method_at(i)?;
            if m.class_idx >= type_count {
                return Err(PoolError::DanglingIndex {
                    pool: "method_ids",
                    into: "type_ids",
                    index: m.class_idx,
                    len: type_count,
                });
            }
            if m.proto_idx >= dex.proto_count() {
                return Err(PoolError::DanglingIndex {
                    pool: "method_ids",
                    into: "proto_ids",
                    index: m.proto_idx,
                    len: dex.proto_count(),
                });
            }
            if m.name_idx >= dex.string_count() {
                return Err(PoolError::DanglingIndex {
                    pool: "method_ids",
                    into: "string_ids",
                    index: m.name_idx,
                    len: dex.string_count(),
                });
            }
            table.entries.push(MethodEntry {
                class_idx: m.class_idx,
                name_idx: m.name_idx,
                proto_idx: m.proto_idx,
            });
        }
        for i in 1..count {
            let prev = table.entries[(i - 1) as usize].sort_key();
            let key = table.entries[i as usize].sort_key();
            if key < prev {
                return Err(PoolError::MethodPoolUnsorted { at: i, key, prev });
            }
        }
        Ok(table)
    }

    /// Build the runtime class table: instance layouts and reference bitmaps.
    ///
    /// This is the one part of pool lowering that walks a graph, so it is the
    /// one part that has to worry about cycles. The superclass walk is an
    /// explicit loop with a `visited` set; a cyclic hierarchy is a typed error
    /// rather than a hang.
    fn build_class_table(
        dex: &DexReader<'_>,
        types: &mut TypeTable,
        fields: &FieldTable,
        facts: &ClassFacts,
    ) -> PoolResult<ClassTable> {
        let mut table = ClassTable::new();
        let class_defs = dex.class_def_count();
        if class_defs > MAX_CLASSES {
            return Err(PoolError::TooManyClasses { count: class_defs, limit: MAX_CLASSES });
        }

        // Every class defined in this DEX is, by definition, `App`.
        let mut resolved: HashMap<u32, Resolved> = HashMap::new();
        for i in 0..types.len() {
            let descriptor = types.entries[i as usize].descriptor.clone();
            let (source, shadowed) = facts.resolve(&descriptor);
            resolved.insert(i, Resolved {
                source,
                class_ptr: if source == ClassSource::Unresolved { UNRESOLVED_CLASS } else { 0 },
                shadowed,
            });
        }

        // First pass: give every class a pointer, so a field type that names
        // another class can be resolved without a second walk.
        let mut class_of_def: Vec<u32> = Vec::with_capacity(class_defs as usize);
        for i in 0..class_defs {
            let raw = dex.class_def_raw(i)?;
            let class_idx = raw.0;
            let descriptor = types.descriptor(class_idx)?.to_string();
            let kind = if descriptor.starts_with('[') { ClassKind::Array } else { ClassKind::Instance };
            let component = if kind == ClassKind::Array {
                types.get(class_idx)?.component_descriptor().and_then(|c| {
                    types.entries.iter().position(|t| t.descriptor == c).map(|p| p as u32)
                })
            } else {
                None
            };
            let ptr = table.add(ClassEntry {
                descriptor,
                source: resolved.get(&class_idx).map(|r| r.source).unwrap_or(ClassSource::Unresolved),
                kind,
                component_type: component,
                instance_slots: 0,
                ref_bitmap: Vec::new(),
                field_slots: Vec::new(),
                field_ids: Vec::new(),
            })?;
            class_of_def.push(ptr);
        }

        // Second pass: instance layouts, superclass fields first.
        for i in 0..class_defs {
            let raw = dex.class_def_raw(i)?;
            if raw.3 != 0 {
                // interfaces_off is populated; interfaces contribute no instance
                // fields of their own, so nothing to do beyond the entry existing.
            }
            let ptr = class_of_def[i as usize];
            if table.get(ptr).is_some_and(|e| e.kind == ClassKind::Array) {
                continue;
            }
            let layout = Pools::instance_layout(dex, types, fields, raw.0, raw.2)?;
            let bitmap = ClassTable::bitmap_for(&layout.reference_slots, layout.slots);
            if let Some(entry) = table.entries.get_mut(ptr as usize) {
                entry.instance_slots = layout.slots;
                entry.ref_bitmap = bitmap;
                entry.field_slots = layout.field_slots;
                entry.field_ids = layout.field_ids;
            }
        }

        // Third pass: write the class pointers back into the type table.
        //
        // Only for types that actually resolved. A class can be in the table
        // (because this file has a `class_def_item` for it) and still be
        // `Unresolved` (because no source in `facts` claims it) — and then its
        // pointer must stay the sentinel, because the sentinel is what makes
        // "unresolved" *detectable* at the point of use rather than an
        // entry that happens to exist.
        for i in 0..types.len() {
            let descriptor = &types.entries[i as usize].descriptor;
            if let Some(r) = resolved.get_mut(&i) {
                if r.source == ClassSource::Unresolved {
                    r.class_ptr = UNRESOLVED_CLASS;
                    continue;
                }
                if let Some(ptr) = table.ptr_of(descriptor) {
                    r.class_ptr = ptr;
                }
            }
        }
        // Types with no `class_def_item` in this file are array types, primitives
        // and unresolved references. Arrays get a synthetic entry so that
        // `new-array` and `check-cast [I` have a `class_ptr`.
        for i in 0..types.len() {
            let entry = &types.entries[i as usize];
            if table.ptr_of(&entry.descriptor).is_some() {
                continue;
            }
            if !entry.is_array() {
                continue;
            }
            let component = entry
                .component_descriptor()
                .and_then(|c| types.entries.iter().position(|t| t.descriptor == c))
                .map(|p| p as u32);
            let ptr = table.add(ClassEntry {
                descriptor: entry.descriptor.clone(),
                source: resolved.get(&i).map(|r| r.source).unwrap_or(ClassSource::Unresolved),
                kind: ClassKind::Array,
                component_type: component,
                instance_slots: 0,
                ref_bitmap: Vec::new(),
                field_slots: Vec::new(),
                field_ids: Vec::new(),
            })?;
            if let Some(r) = resolved.get_mut(&i) {
                // Same rule as the pass above: an array class existing in the
                // table does not make the *reference* resolved.
                r.class_ptr = if r.source == ClassSource::Unresolved { UNRESOLVED_CLASS } else { ptr };
            }
        }
        // Finally, copy the resolved records into the type table.
        for i in 0..types.len() {
            if let Some(r) = resolved.get(&i) {
                types.entries[i as usize].resolution = r.clone();
            }
        }
        Ok(table)
    }

    /// Instance field layout for one class: superclass fields first, then this
    /// class's, each in `field_ids` order within the `class_data_item` list.
    ///
    /// A `long` or `double` takes two 4-byte slots, low half first, matching
    /// WebAssembly's in-memory `i64`/`f64`. That is the heap layout rule stated
    /// in [`crate::heap`] and it has to be decided here, because this is where
    /// the DEX field types are known.
    fn instance_layout(
        dex: &DexReader<'_>,
        types: &TypeTable,
        fields: &FieldTable,
        class_idx: u32,
        superclass_idx: u32,
    ) -> PoolResult<InstanceLayout> {
        let mut slots: u32 = 0;
        let mut refs: Vec<u32> = Vec::new();
        let mut field_slots: Vec<u32> = Vec::new();
        let mut field_id_list: Vec<u32> = Vec::new();
        let mut visited: BTreeSet<u32> = BTreeSet::new();

        // Walk superclass-first with an explicit stack. A cycle terminates on
        // `visited` and is reported rather than looped on.
        let mut chain: Vec<u32> = Vec::new();
        let mut cursor = if superclass_idx == dexcore::header::NO_INDEX { None } else { Some(superclass_idx) };
        while let Some(idx) = cursor {
            if idx == class_idx {
                return Err(PoolError::SelfSuperclass(types.descriptor(idx)?.to_string()));
            }
            if !visited.insert(idx) {
                return Err(PoolError::CyclicHierarchy(types.descriptor(idx)?.to_string()));
            }
            chain.push(idx);
            let next = match dex.find_class(types.descriptor(idx)?) {
                Ok(Some(def_idx)) => {
                    let raw = dex.class_def_raw(def_idx)?;
                    if raw.2 == dexcore::header::NO_INDEX {
                        None
                    } else {
                        Some(raw.2)
                    }
                }
                _ => None,
            };
            cursor = next;
        }
        // `chain` is superclass-last; walk it backwards so superclass fields come
        // first, matching dexinterp's layout so the two agree on field offsets.
        chain.reverse();
        chain.push(class_idx);

        for &idx in &chain {
            let def_idx = match dex.find_class(types.descriptor(idx)?) {
                Ok(Some(d)) => d,
                _ => continue,
            };
            let raw = dex.class_def_raw(def_idx)?;
            if raw.6 == 0 {
                continue;
            }
            let data = dex.class_data(raw.6)?;
            for f in &data.instance_fields {
                if f.field_idx >= fields.len() {
                    return Err(PoolError::DanglingIndex {
                        pool: "class_data_item",
                        into: "field_ids",
                        index: f.field_idx,
                        len: fields.len(),
                    });
                }
                let type_idx = fields.get(f.field_idx)?.type_idx;
                let descriptor = types.descriptor(type_idx)?;
                let width = crate::heap::field_slot_width(descriptor);
                field_slots.push(slots);
                field_id_list.push(f.field_idx);
                if width == 2 {
                    // A `long` occupies two slots and is never a reference.
                    slots = slots.checked_add(2).ok_or(PoolError::SizeOverflow {
                        what: "instance layout",
                    })?;
                } else {
                    if type_idx < types.len() && !types.entries[type_idx as usize].is_primitive() {
                        refs.push(slots);
                    }
                    slots = slots.checked_add(1).ok_or(PoolError::SizeOverflow {
                        what: "instance layout",
                    })?;
                }
            }
        }
        Ok(InstanceLayout { slots, reference_slots: refs, field_slots, field_ids: field_id_list })
    }

    /// Look a method up by class descriptor, name and parameter descriptors.
    ///
    /// The by-name path an `invoke-virtual` needs when the target was not
    /// resolved at link time. Interns the arguments into the file's own pools via
    /// the descriptor lists, then binary-searches. Returns `None` when the file
    /// has no such method, which is a normal answer (the method is in another
    /// DEX) and not an error.
    pub fn find_method(&self, class: &str, name: &str, params: &[&str], ret: &str) -> Option<u32> {
        let class_idx = self.type_index_of(class)?;
        let name_idx = self.string_index_of(name)?;
        let proto_idx = self.proto_index_of(params, ret)?;
        self.methods.find(class_idx, name_idx, proto_idx)
    }

    /// The `type_ids` index of a descriptor, if present.
    pub fn type_index_of(&self, descriptor: &str) -> Option<u32> {
        self.types.entries.iter().position(|t| t.descriptor == descriptor).map(|p| p as u32)
    }

    /// The `string_ids` index of a value, if present.
    pub fn string_index_of(&self, value: &str) -> Option<u32> {
        self.strings.values.iter().position(|v| v == value).map(|p| p as u32)
    }

    /// The `proto_ids` index of a signature, if present.
    pub fn proto_index_of(&self, params: &[&str], ret: &str) -> Option<u32> {
        let return_type_idx = self.type_index_of(ret)?;
        let mut parameter_type_idx = Vec::with_capacity(params.len());
        for p in params {
            parameter_type_idx.push(self.type_index_of(p)?);
        }
        self.protos
            .entries
            .iter()
            .position(|e| {
                e.return_type_idx == return_type_idx && e.parameter_type_idx == parameter_type_idx
            })
            .map(|p| p as u32)
    }

    /// Methods in one class, by descriptor.
    pub fn methods_of(&self, class: &str) -> Option<Vec<u32>> {
        let class_idx = self.type_index_of(class)?;
        Some(self.methods.find_all_in_class(class_idx))
    }

    /// Fields in one class, by descriptor.
    pub fn fields_of(&self, class: &str) -> Vec<u32> {
        let Some(class_idx) = self.type_index_of(class) else {
            return Vec::new();
        };
        self.fields
            .entries
            .iter()
            .enumerate()
            .filter(|(_, f)| f.class_idx == class_idx)
            .map(|(i, _)| i as u32)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::heap::ClassLayout;

    /// The six F-Droid extracts documented in `tools/dexcore/tests/FIXTURES.md`.
    const FIXTURES: &[(&str, &[u8])] = &[
        (
            "pro.rudloff.search_to_browser_2",
            include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex"),
        ),
        (
            "org.vi_server.red_screen_3",
            include_bytes!("../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex"),
        ),
        (
            "com.android.adbkeyboard_2",
            include_bytes!("../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex"),
        ),
        (
            "com.oF2pks.neolinker_7",
            include_bytes!("../../tools/dexcore/tests/fixtures/com.oF2pks.neolinker_7.dex"),
        ),
        (
            "com.termux.boot_1000",
            include_bytes!("../../tools/dexcore/tests/fixtures/com.termux.boot_1000.dex"),
        ),
        (
            "fr.smarquis.sleeptimer_16200",
            include_bytes!("../../tools/dexcore/tests/fixtures/fr.smarquis.sleeptimer_16200.dex"),
        ),
    ];

    fn fixture(name: &str) -> &'static [u8] {
        FIXTURES.iter().find(|(n, _)| *n == name).map(|(_, b)| *b).expect("named fixture")
    }

    /// Every fixture's classes, marked as the app's own.
    fn app_facts(bytes: &[u8]) -> ClassFacts {
        let dex = DexReader::open(bytes).unwrap();
        let mut facts = ClassFacts::empty();
        for c in dex.classes().unwrap() {
            facts.app.insert(c.descriptor);
        }
        facts
    }

    // ------------------------------------------------------------- strings

    #[test]
    fn string_table_round_trips_every_fixture_string() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let dex = DexReader::open(bytes).unwrap();
            assert_eq!(pools.strings.len(), dex.string_count(), "{name}");
            for i in 0..dex.string_count() {
                let src = dex.string(i).unwrap();
                assert_eq!(pools.strings.value(i).unwrap(), &src.value, "{name} string {i}");
                assert_eq!(pools.strings.get(i).unwrap().utf16_len, src.utf16_size, "{name} string {i}");
                // The payload slice must be exactly the MUTF-8 encoding, which
                // round-trips through dexcore's decoder.
                let (decoded, used) =
                    dexcore::mutf8::decode(pools.strings.terminated_bytes(i).unwrap()).unwrap();
                assert_eq!(decoded, src.value, "{name} string {i}");
                // The body is the slice minus the terminator, and the decoder
                // must consume exactly that much.
                assert_eq!(used, pools.strings.bytes(i).unwrap().len(), "{name} string {i}");
                assert_eq!(pools.strings.terminated_bytes(i).unwrap().last(), Some(&0u8));
            }
        }
    }

    #[test]
    fn declared_utf16_length_agrees_with_the_decoded_value_on_this_corpus() {
        // 777 strings across six fixtures. A disagreement would mean the file's
        // `utf16_size` and its body tell different stories, which is worth a
        // number rather than a comment.
        let mut total = 0u32;
        let mut mismatches = 0u32;
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            total = total.saturating_add(pools.strings.len());
            mismatches = mismatches.saturating_add(pools.strings.utf16_mismatches);
            let _ = name;
        }
        assert_eq!(total, 777, "fixture corpus size changed; re-measure");
        assert_eq!(mismatches, 0, "declared utf16_size disagreed with the body");
    }

    #[test]
    fn mutf8_payload_preserves_surrogate_pairs_and_embedded_nul() {
        // Written by hand as MUTF-8 so the table is fed the shapes that matter,
        // because the fixture corpus is entirely ASCII and cannot show this.
        let mut payload = Vec::new();
        // "a\0b": the embedded NUL is the overlong C0 80, and a *bare* 0x00
        // terminates. Four body bytes, three UTF-16 units.
        payload.extend_from_slice(&[b'a', 0xC0, 0x80, b'b', 0x00]);
        // U+1F600 as two three-byte surrogates, D83D DE00. Six body bytes, two
        // UTF-16 units, then a terminator.
        payload.extend_from_slice(&[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80, 0x00]);
        let table = StringTable {
            payload,
            index: vec![
                StringRef { offset: 0, utf16_len: 3 },
                StringRef { offset: 5, utf16_len: 2 },
            ],
            values: vec!["a\0b".to_string(), "\u{1f600}".to_string()],
            utf16_mismatches: 0,
        };
        // 4 bytes and 3 UTF-16 units: the length is not the byte length.
        assert_eq!(table.bytes(0).unwrap().len(), 4);
        assert_eq!(table.get(0).unwrap().utf16_len, 3);
        // 6 bytes and 2 UTF-16 units: a surrogate pair, not a 4-byte sequence.
        assert_eq!(table.bytes(1).unwrap().len(), 6);
        assert_eq!(table.get(1).unwrap().utf16_len, 2);
        assert!(!table.bytes(1).unwrap().contains(&0xF0), "no 4-byte MUTF-8 sequence");
        // The index alone is not enough to find the byte length: 3 and 2 units
        // describe 4 and 6 bytes. The terminator is what resolves it, and MUTF-8
        // cannot contain a bare zero, so the scan is unambiguous.
        assert!(table.bytes(0).unwrap().contains(&0xC0), "embedded NUL survives as C0 80");
        assert_eq!(table.terminated_bytes(0).unwrap().len(), 5);
        assert_eq!(table.terminated_bytes(1).unwrap().len(), 7);
        let (decoded, used) = dexcore::mutf8::decode(table.terminated_bytes(0).unwrap()).unwrap();
        assert_eq!(decoded, "a\0b");
        assert_eq!(used, 4);
        let (decoded, used) = dexcore::mutf8::decode(table.terminated_bytes(1).unwrap()).unwrap();
        assert_eq!(decoded, "\u{1f600}");
        assert_eq!(used, 6);
    }

    #[test]
    fn an_out_of_range_string_index_is_a_typed_error() {
        let pools = Pools::lower(fixture("pro.rudloff.search_to_browser_2"), &ClassFacts::empty()).unwrap();
        let n = pools.strings.len();
        for bad in [n, n + 1, u32::MAX] {
            assert_eq!(
                pools.strings.get(bad).unwrap_err().kind(),
                "index_out_of_range",
                "index {bad}"
            );
        }
    }

    // --------------------------------------------------------------- types

    #[test]
    fn types_lower_with_descriptors_and_indices_preserved() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let dex = DexReader::open(bytes).unwrap();
            assert_eq!(pools.types.len(), dex.type_count(), "{name}");
            for i in 0..dex.type_count() {
                let t = dex.type_at(i).unwrap();
                assert_eq!(pools.types.get(i).unwrap().descriptor, t.descriptor, "{name} type {i}");
                assert_eq!(pools.types.get(i).unwrap().descriptor_idx, t.descriptor_idx, "{name} type {i}");
            }
        }
    }

    #[test]
    fn with_no_facts_every_type_is_unresolved_with_a_sentinel_pointer() {
        let pools = Pools::lower(fixture("pro.rudloff.search_to_browser_2"), &ClassFacts::empty()).unwrap();
        for i in 0..pools.types.len() {
            let t = pools.types.get(i).unwrap();
            assert_eq!(t.resolution.source, ClassSource::Unresolved, "type {i}");
            assert_eq!(t.resolution.class_ptr, UNRESOLVED_CLASS, "type {i}");
        }
    }

    #[test]
    fn app_classes_resolve_to_app_and_get_a_real_class_pointer() {
        let bytes = fixture("fr.smarquis.sleeptimer_16200");
        let facts = app_facts(bytes);
        let pools = Pools::lower(bytes, &facts).unwrap();
        let mut checked = 0;
        for i in 0..pools.types.len() {
            let t = pools.types.get(i).unwrap();
            if facts.app.contains(&t.descriptor) {
                assert_eq!(t.resolution.source, ClassSource::App, "{}", t.descriptor);
                assert_ne!(t.resolution.class_ptr, UNRESOLVED_CLASS, "{}", t.descriptor);
                let entry = pools.classes.get(t.resolution.class_ptr).unwrap();
                assert_eq!(entry.descriptor, t.descriptor);
                assert_eq!(entry.source, ClassSource::App);
                checked += 1;
            }
        }
        assert!(checked > 0, "no class resolved to App");
    }

    // ------------------------------------------------- resolution precedence

    #[test]
    fn host_supersedes_app_and_the_shadowing_is_recorded() {
        // ADR 0005: a framework class the app also defines is the host's.
        let facts = ClassFacts::empty()
            .with_app("Lcom/x/Y;")
            .with_host_stub("Lcom/x/Y;");
        let (winner, all) = facts.resolve("Lcom/x/Y;");
        assert_eq!(winner, ClassSource::HostStub);
        assert_eq!(all, vec![ClassSource::HostStub, ClassSource::App]);
        let resolved = Resolved { source: winner, class_ptr: 3, shadowed: all[1..].to_vec() };
        assert!(resolved.is_shadowed());
    }

    #[test]
    fn a_class_in_the_closure_ranks_above_the_host_and_the_app() {
        // The IR numbers `closure-generated` first: a class compiled into the
        // guest is not host-provided, so the host-supersedes-app rule does not
        // apply to it.
        let mut facts = ClassFacts::empty().with_app("Lx;").with_host_stub("Lx;");
        facts.host_native.insert("Lx;".to_string());
        facts.closure_generated.insert("Lx;".to_string());
        let (winner, all) = facts.resolve("Lx;");
        assert_eq!(winner, ClassSource::ClosureGenerated);
        assert_eq!(all.len(), 4, "every source recorded: {all:?}");
    }

    #[test]
    fn host_native_outranks_host_stub_but_not_the_guest() {
        let mut facts = ClassFacts::empty().with_host_stub("Lx;");
        facts.host_native.insert("Lx;".to_string());
        assert_eq!(facts.resolve("Lx;").0, ClassSource::HostStub, "IR order within the host side");
        assert_eq!(ClassSource::HostNative.precedence(), ClassSource::HostStub.precedence());
    }

    #[test]
    fn a_name_no_source_provides_is_unresolved_with_no_candidates() {
        let facts = ClassFacts::empty();
        let (winner, all) = facts.resolve("Ldoes/not/Exist;");
        assert_eq!(winner, ClassSource::Unresolved);
        assert!(all.is_empty());
        let r = Resolved { source: winner, class_ptr: UNRESOLVED_CLASS, shadowed: all };
        assert!(!r.is_shadowed());
    }

    #[test]
    fn shadowed_class_count_is_reported_in_the_stats() {
        let bytes = fixture("pro.rudloff.search_to_browser_2");
        let mut facts = app_facts(bytes);
        // Mark one app class as also host-provided, which is the adversarial
        // shape: an app defining a framework class.
        let dex = DexReader::open(bytes).unwrap();
        let victim = dex.classes().unwrap()[0].descriptor.clone();
        facts.host_stub.insert(victim.clone());
        let pools = Pools::lower(bytes, &facts).unwrap();
        assert!(pools.stats.shadowed_classes >= 1, "expected a shadowing event for {victim}");
        let t = pools.types.get(pools.type_index_of(&victim).unwrap()).unwrap();
        assert!(t.resolution.is_shadowed());
        assert_eq!(t.resolution.source, ClassSource::HostStub);
    }

    // --------------------------------------------------------------- protos

    #[test]
    fn protos_lower_with_shorty_return_type_and_parameters() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let dex = DexReader::open(bytes).unwrap();
            assert_eq!(pools.protos.len(), dex.proto_count(), "{name}");
            for i in 0..dex.proto_count() {
                let p = dex.proto_at(i).unwrap();
                let e = pools.protos.get(i).unwrap();
                assert_eq!(e.shorty, p.shorty, "{name} proto {i}");
                assert_eq!(e.return_type_idx, p.return_type_idx, "{name} proto {i}");
                assert_eq!(e.arity() as usize, p.parameters.len(), "{name} proto {i}");
                assert_eq!(e.signature(&pools.types).unwrap(), p.signature(), "{name} proto {i}");
            }
        }
    }

    #[test]
    fn shorty_is_return_type_first_against_real_d8_output() {
        // The fact that makes this checkable: a shorty is return-first, so
        // `shorty[0]` is the return type's shorty code and `shorty[1..]` is the
        // parameters'. Under the parameters-first reading, every proto whose
        // return and first parameter differ would fail here.
        //
        // Measured on the six fixtures: 127 protos distinguish the two readings
        // and every one of them is return-first. 97 are ambiguous (return and
        // parameters spell the same) and 0 contradict it.
        let mut distinguishing = 0u32;
        let mut ambiguous = 0u32;
        let shorty_of = |d: &str| -> char {
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
        };
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            for i in 0..pools.protos.len() {
                let e = pools.protos.get(i).unwrap();
                let ret = shorty_of(pools.types.descriptor(e.return_type_idx).unwrap());
                let params: String = e
                    .parameter_type_idx
                    .iter()
                    .map(|&p| shorty_of(pools.types.descriptor(p).unwrap()))
                    .collect();
                let return_first: String =
                    std::iter::once(ret).chain(params.chars()).collect();
                let param_first: String =
                    params.chars().chain(std::iter::once(ret)).collect();
                assert_eq!(e.shorty, return_first, "{name} proto {i}: {e:?}");
                if param_first != return_first {
                    distinguishing = distinguishing.saturating_add(1);
                } else {
                    ambiguous = ambiguous.saturating_add(1);
                }
            }
        }
        assert_eq!(distinguishing, 127, "re-measure: the corpus changed");
        assert_eq!(ambiguous, 97, "re-measure: the corpus changed");
    }

    #[test]
    fn a_proto_with_a_type_list_round_trips_its_parameter_count() {
        // `type_list.size` is a u32, not a uleb128 — verified against real d8
        // output: 179/179 parameter type lists in this corpus are self-consistent
        // under u32 and only 119/179 under uleb128. The check here is the
        // observable consequence: a parameter list read as uleb128 would
        // mis-decode these, so the counts and signatures must all agree.
        let mut with_params = 0u32;
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let dex = DexReader::open(bytes).unwrap();
            for p in dex.protos().unwrap() {
                if p.parameters_off == 0 {
                    continue;
                }
                with_params = with_params.saturating_add(1);
                let e = pools.protos.get(p.index).unwrap();
                // The shorty's length is arity + 1, which only holds if the
                // parameter count came out right.
                assert_eq!(e.shorty.chars().count() as u32, e.arity() + 1, "{name} proto {}", p.index);
                // And the signature agrees with the descriptors dexcore resolved
                // from the same `type_list`, which is the cross-check that would
                // fail if the size prefix were read as a uleb128.
                assert_eq!(e.signature(&pools.types).unwrap(), p.signature(), "{name} proto {}", p.index);
                // Every parameter index is a real type index.
                for &t in &e.parameter_type_idx {
                    assert!(t < pools.types.len(), "{name} proto {}: {t}", p.index);
                }
            }
        }
        assert_eq!(with_params, 179, "re-measure: the corpus changed");
    }

    // --------------------------------------------------------------- fields

    #[test]
    fn field_pool_is_sorted_by_class_name_type_on_every_fixture() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            for i in 1..pools.fields.len() {
                let prev = pools.fields.entries[(i - 1) as usize].sort_key();
                let key = pools.fields.entries[i as usize].sort_key();
                assert!(prev <= key, "{name}: field_ids[{i}] {key:?} < [{i1}] {prev:?}", i1 = i - 1);
            }
        }
    }

    #[test]
    fn method_pool_is_sorted_by_class_name_proto_on_every_fixture() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            for i in 1..pools.methods.len() {
                let prev = pools.methods.entries[(i - 1) as usize].sort_key();
                let key = pools.methods.entries[i as usize].sort_key();
                assert!(prev <= key, "{name}: method_ids[{i}] {key:?} < {prev:?}");
            }
        }
    }

    #[test]
    fn string_pool_is_sorted_by_bytes_on_every_fixture() {
        // Lowering verifies this and returns `string_pool_unsorted` otherwise;
        // the test pins that it does not fire on real files.
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            assert!(!pools.strings.is_empty(), "{name}");
            let _ = name;
        }
    }

    #[test]
    fn field_binary_search_finds_every_entry_and_nothing_else() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let mut found = 0u32;
            for (i, e) in pools.fields.entries.iter().enumerate() {
                let got = pools.fields.find(e.class_idx, e.name_idx, e.type_idx);
                assert_eq!(got, Some(i as u32), "{name}: binary search missed field {i}");
                found += 1;
            }
            // A key one past the end of every existing name must miss.
            let last = pools.fields.entries.last().copied();
            if let Some(l) = last {
                let past = pools.fields.find(l.class_idx, l.name_idx + 1, l.type_idx);
                assert!(past.is_none(), "{name}: found a field that does not exist");
            }
            assert!(found > 0);
        }
    }

    #[test]
    fn method_binary_search_finds_every_entry_and_nothing_else() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            for (i, e) in pools.methods.entries.iter().enumerate() {
                assert_eq!(
                    pools.methods.find(e.class_idx, e.name_idx, e.proto_idx),
                    Some(i as u32),
                    "{name}: binary search missed method {i}"
                );
            }
            let last = pools.methods.entries.last().copied();
            if let Some(l) = last {
                assert!(pools.methods.find(l.class_idx, l.name_idx, l.proto_idx + 1).is_none(), "{name}");
                assert!(pools.methods.find(l.class_idx + 1, l.name_idx, l.proto_idx).is_none(), "{name}");
            }
        }
    }

    #[test]
    fn binary_search_agrees_with_a_linear_scan_on_every_fixture() {
        // The property that actually matters: for every (class, name) pair the
        // binary search and a brute-force scan return the same index. Run over
        // the whole corpus, not a sample.
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let mut checks = 0u32;
            for e in &pools.methods.entries {
                let linear = pools
                    .methods
                    .entries
                    .iter()
                    .position(|x| x.sort_key() == e.sort_key())
                    .map(|p| p as u32);
                assert_eq!(pools.methods.find(e.class_idx, e.name_idx, e.proto_idx), linear, "{name}");
                checks += 1;
            }
            for e in &pools.fields.entries {
                let linear = pools
                    .fields
                    .entries
                    .iter()
                    .position(|x| x.sort_key() == e.sort_key())
                    .map(|p| p as u32);
                assert_eq!(pools.fields.find(e.class_idx, e.name_idx, e.type_idx), linear, "{name}");
                checks += 1;
            }
            assert!(checks > 0, "{name}");
        }
    }

    #[test]
    fn find_all_in_class_returns_a_contiguous_sorted_range() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            for e in &pools.methods.entries {
                let all = pools.methods.find_all_in_class(e.class_idx);
                assert!(!all.is_empty(), "{name}");
                assert!(all.contains(&(pools.methods.entries.iter().position(|x| x.sort_key() == e.sort_key()).unwrap() as u32)));
                // Contiguous and ascending, because the class key is the major
                // component of the sort key.
                for w in all.windows(2) {
                    assert_eq!(w[1], w[0] + 1, "{name}: methods of a class are not contiguous");
                }
            }
        }
    }

    #[test]
    fn an_unsorted_method_pool_is_refused_rather_than_searched() {
        // Build the failure directly rather than forging a file: the check is
        // what matters, and its input is the table.
        let mut table = MethodTable::default();
        table.entries.push(MethodEntry { class_idx: 0, name_idx: 5, proto_idx: 0 });
        table.entries.push(MethodEntry { class_idx: 0, name_idx: 1, proto_idx: 0 });
        // The hazard, measured rather than asserted: a linear scan finds both
        // entries, the binary search finds one of them. That is the bug the
        // load-time order check exists to prevent — a `invoke-virtual` resolving
        // to "no such method" on a file that has it.
        let linear = |k: (u32, u32, u32)| table.entries.iter().position(|e| e.sort_key() == k).map(|p| p as u32);
        let mut disagreements = 0;
        for e in &table.entries {
            if table.find(e.class_idx, e.name_idx, e.proto_idx) != linear(e.sort_key()) {
                disagreements += 1;
            }
        }
        assert_eq!(disagreements, 2, "the search misses both present methods");
        assert_eq!(linear((0, 1, 0)), Some(1), "a linear scan finds it");
        assert_eq!(table.find(0, 1, 0), None, "the binary search does not");
        assert_eq!(linear((0, 5, 0)), Some(0), "a linear scan finds that one too");
        assert_eq!(table.find(0, 5, 0), None, "the binary search does not");
        // Which is why lowering checks first.
        let err = PoolError::MethodPoolUnsorted {
            at: 1,
            key: (0, 1, 0),
            prev: (0, 5, 0),
        };
        assert_eq!(err.kind(), "method_pool_unsorted");
        assert!(err.to_string().contains("binary search"));
    }

    #[test]
    fn an_unsorted_field_pool_is_refused_too() {
        let err = PoolError::FieldPoolUnsorted { at: 3, key: (0, 0, 0), prev: (0, 1, 0) };
        assert_eq!(err.kind(), "field_pool_unsorted");
        assert!(err.to_string().contains("field_ids"));
    }

    // -------------------------------------------------- signatures and lookup

    #[test]
    fn every_method_signature_matches_dexcore_on_every_fixture() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            let dex = DexReader::open(bytes).unwrap();
            for i in 0..pools.methods.len() {
                let mine = pools.methods.entries[i as usize]
                    .signature(&pools.types, &pools.protos, &pools.strings)
                    .unwrap();
                let theirs = dex.method_at(i).unwrap().signature();
                assert_eq!(mine, theirs, "{name}: method {i}");
            }
            for i in 0..pools.fields.len() {
                let mine = pools.fields.entries[i as usize]
                    .signature(&pools.types, &pools.strings)
                    .unwrap();
                let theirs = dex.field_at(i).unwrap().signature();
                assert_eq!(mine, theirs, "{name}: field {i}");
            }
        }
    }

    #[test]
    fn find_method_by_name_resolves_a_real_signature() {
        let bytes = fixture("fr.smarquis.sleeptimer_16200");
        let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
        let dex = DexReader::open(bytes).unwrap();
        // Pick any real method and look it up by its own signature.
        let target = dex.method_at(0).unwrap();
        let class = target.class.clone();
        let name = target.name.clone();
        let params: Vec<&str> = target.parameters.iter().map(String::as_str).collect();
        let ret = target.return_type.as_str();
        let idx = pools.find_method(&class, &name, &params, ret);
        assert_eq!(idx, Some(0), "should resolve to index 0");
        // A method that does not exist is None, not an error.
        assert_eq!(pools.find_method(&class, "noSuchMethod", &params, ret), None);
        assert_eq!(pools.find_method("Lno/Such/Class;", &name, &params, ret), None);
    }

    #[test]
    fn methods_of_and_fields_of_agree_with_the_raw_tables() {
        let bytes = fixture("com.termux.boot_1000");
        let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
        for (i, e) in pools.methods.entries.iter().enumerate() {
            let class = pools.types.descriptor(e.class_idx).unwrap().to_string();
            let all = pools.methods_of(&class).unwrap();
            assert!(all.contains(&(i as u32)));
            assert_eq!(all.len(), pools.methods_of(&class).unwrap().len());
        }
        for e in &pools.fields.entries {
            let class = pools.types.descriptor(e.class_idx).unwrap().to_string();
            let all = pools.fields_of(&class);
            assert!(!all.is_empty());
        }
    }

    // --------------------------------------------------------- class layout

    #[test]
    fn instance_layout_places_superclass_fields_first() {
        let bytes = fixture("com.oF2pks.neolinker_7");
        let pools = Pools::lower(bytes, &app_facts(bytes)).unwrap();
        for (i, e) in pools.types.entries.iter().enumerate() {
            let Some(ptr) = pools.classes.ptr_of(&e.descriptor) else { continue };
            let entry = pools.classes.get(ptr).unwrap();
            if entry.kind != ClassKind::Instance {
                continue;
            }
            // Field slots are strictly increasing and inside the object.
            for w in entry.field_slots.windows(2) {
                assert!(w[0] < w[1], "{}: field slots not ascending", e.descriptor);
            }
            if let Some(&max) = entry.field_slots.last() {
                assert!(max < entry.instance_slots.max(max), "{}: slot past the object", e.descriptor);
            }
            let _ = i;
        }
    }

    #[test]
    fn a_reference_bitmap_marks_exactly_the_reference_slots() {
        let bytes = fixture("fr.smarquis.sleeptimer_16200");
        let pools = Pools::lower(bytes, &app_facts(bytes)).unwrap();
        let mut checked = 0;
        for entry in pools.classes.entries() {
            if entry.kind != ClassKind::Instance {
                continue;
            }
            for slot in 0..entry.instance_slots {
                let is_ref = entry.slot_is_reference(slot);
                if is_ref {
                    // A reference slot must be backed by a field whose type is not
                    // a primitive descriptor.
                    assert!(entry.slot_is_reference(slot), "{} slot {slot}", entry.descriptor);
                }
            }
            checked += 1;
        }
        assert!(checked > 0, "no instance classes in the fixture");
    }

    #[test]
    fn array_types_get_a_class_entry_with_a_component() {
        let bytes = fixture("fr.smarquis.sleeptimer_16200");
        let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
        let mut arrays = 0;
        for i in 0..pools.types.len() {
            let t = pools.types.get(i).unwrap();
            if !t.is_array() {
                continue;
            }
            arrays += 1;
            let Some(ptr) = pools.classes.ptr_of(&t.descriptor) else { continue };
            let entry = pools.classes.get(ptr).unwrap();
            assert_eq!(entry.kind, ClassKind::Array);
            assert_eq!(entry.instance_slots, 0);
            if t.component_descriptor().is_some_and(|c| c != "V") {
                let comp = t.component_descriptor().unwrap();
                if let Some(ci) = pools.type_index_of(comp) {
                    assert_eq!(entry.component_type, Some(ci), "{}", t.descriptor);
                }
            }
        }
        assert!(arrays > 0, "fixture has no array types");
    }

    #[test]
    fn the_class_table_is_usable_as_a_heap_layout() {
        // The two halves have to fit together: the collector traces with the
        // class table, and an object allocated from it must be traceable.
        let bytes = fixture("com.termux.boot_1000");
        let pools = Pools::lower(bytes, &app_facts(bytes)).unwrap();
        assert!(pools.classes.class_count() > 0);
        for ptr in 0..pools.classes.class_count() {
            let Some(entry) = pools.classes.get(ptr) else { continue };
            if entry.kind != ClassKind::Instance {
                assert!(pools.classes.ref_bitmap(ptr).is_none(), "arrays have no instance layout");
                continue;
            }
            let slots = pools.classes.instance_slots(ptr).unwrap();
            assert_eq!(slots, entry.instance_slots, "{}: layout disagrees with the entry", entry.descriptor);
            for slot in 0..slots {
                assert_eq!(
                    pools.classes.ref_bitmap(ptr).is_some_and(|b| crate::heap::Heap::bit_is_set(b, slot)),
                    entry.slot_is_reference(slot),
                    "{}: slot {slot} disagrees",
                    entry.descriptor
                );
            }
        }
    }

    #[test]
    fn an_object_from_the_class_table_is_traceable_by_the_collector() {
        // End-to-end: build an object whose class pointer names a real class,
        // store a child handle in a reference slot, and confirm the collector
        // finds the child.
        let bytes = fixture("com.termux.boot_1000");
        let pools = Pools::lower(bytes, &app_facts(bytes)).unwrap();
        // Find a class with at least one reference slot.
        let Some(entry) = pools
            .classes
            .entries()
            .iter()
            .find(|e| e.kind == ClassKind::Instance && e.instance_slots > 0 && !e.field_slots.is_empty())
        else {
            return;
        };
        let ptr = pools.classes.ptr_of(&entry.descriptor).unwrap();
        let ref_slot = entry.field_slots[0];
        let mut heap = crate::heap::Heap::with_ceiling(1 << 20);
        heap.set_policy(crate::heap::CollectionPolicy::HostMarkSweep);
        let parent = heap.alloc_object(ptr, entry.instance_slots).unwrap();
        let child = heap.alloc_array(4, 1).unwrap();
        heap.store_field(parent, ref_slot, child).unwrap();
        let roots = crate::heap::RootSet::exact([parent]);
        let report = heap.collect(&roots, &pools.classes).unwrap();
        assert_eq!(heap.classify(child), Ok(crate::heap::HandleKind::Array), "child was not traced");
        assert_eq!(report.live, 2);
    }

    // ------------------------------------------------- call sites, near-dead

    #[test]
    fn no_fixture_carries_a_call_site_or_method_handle_section() {
        // Measured: 0/120 F-Droid APKs. The six fixtures agree.
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            assert_eq!(pools.stats.call_sites, 0, "{name} unexpectedly has call sites");
            assert_eq!(pools.stats.method_handles, 0, "{name} unexpectedly has method handles");
            assert!(pools.call_sites.is_empty(), "{name}");
            // And the stats report says so, so a build can see it.
            assert_eq!(pools.stats.call_sites, pools.call_sites.call_sites.len() as u32);
        }
    }

    #[test]
    fn a_call_site_index_out_of_range_is_a_typed_error() {
        let pools = Pools::lower(fixture("pro.rudloff.search_to_browser_2"), &ClassFacts::empty()).unwrap();
        assert_eq!(pools.call_sites.get(0).unwrap_err().kind(), "index_out_of_range");
        assert_eq!(pools.call_sites.method_handle(0).unwrap_err().kind(), "index_out_of_range");
    }

    #[test]
    fn method_handle_kinds_decode_and_classify_correctly() {
        for raw in 0u16..=5 {
            let k = MethodHandleKind::from_raw(raw).expect("0..=5 are all valid");
            assert!(k.is_method() == (raw <= 3), "kind {raw}");
            assert!(!k.as_str().is_empty());
        }
        for raw in [6u16, 7, 100, u16::MAX] {
            assert_eq!(MethodHandleKind::from_raw(raw), None, "raw {raw}");
        }
    }

    #[test]
    fn a_call_site_table_decodes_when_a_file_really_has_one() {
        // No fixture has one, so build the structures directly and prove the
        // shape is coherent. A path with no test that can fail is a path that
        // does not work; this is the minimum that keeps the near-dead code honest
        // about its own types.
        let table = CallSiteTable {
            call_sites: vec![CallSite {
                bootstrap: MethodHandle {
                    kind: MethodHandleKind::StaticGet,
                    member_idx: 0,
                },
                bootstrap_args_off: 0,
                arg_count: 0,
                arg_bytes: Vec::new(),
            }],
            method_handles: vec![MethodHandle {
                kind: MethodHandleKind::InterfaceInvoke,
                member_idx: 3,
            }],
        };
        assert!(!table.is_empty());
        assert_eq!(table.get(0).unwrap().bootstrap.member_idx, 0);
        assert_eq!(table.method_handle(0).unwrap().kind, MethodHandleKind::InterfaceInvoke);
        assert!(table.get(1).is_err());
    }

    // ----------------------------------------------------------- robustness

    #[test]
    fn garbage_input_is_a_typed_error_not_a_panic() {
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"not a dex file at all".to_vec(),
            vec![0u8; 4096],
            b"dex\n035\0".to_vec(),
        ];
        for bytes in cases {
            // Either it lowers or it is a typed error. A panic fails the test.
            match Pools::lower(&bytes, &ClassFacts::empty()) {
                Ok(_) => {}
                Err(e) => {
                    assert!(!e.kind().is_empty(), "every error has a kind");
                    assert!(!e.to_string().is_empty());
                }
            }
        }
    }

    #[test]
    fn a_truncated_dex_at_every_prefix_length_does_not_panic() {
        // Fuzz the container itself: every truncation of a real fixture, which
        // exercises every partial-read path in dexcore and in the call-site
        // reader.
        let full = fixture("pro.rudloff.search_to_browser_2");
        for len in 0..full.len() {
            let _ = Pools::lower(&full[..len], &ClassFacts::empty());
        }
        assert!(full.len() > 1000);
    }

    #[test]
    fn every_byte_flipped_in_the_first_two_kilobytes_does_not_panic() {
        // The header and the five id pools all live in the first ~2 KB, so this
        // walks every count, offset and index field a hostile file can corrupt.
        let full = fixture("org.vi_server.red_screen_3");
        let limit = full.len().min(2048);
        for i in 0..limit {
            for bit in [0x01u8, 0x02, 0x40, 0x80] {
                let mut m = full[..limit].to_vec();
                m[i] ^= bit;
                let _ = Pools::lower(&m, &ClassFacts::empty());
            }
        }
        // Also overwrite whole 4-byte windows with 0xFF, which is what a size or
        // offset field set to "huge" looks like.
        for i in (0..limit).step_by(4) {
            let mut m = full[..limit].to_vec();
            for b in i..(i + 4).min(limit) {
                m[b] = 0xFF;
            }
            let _ = Pools::lower(&m, &ClassFacts::empty());
        }
    }

    #[test]
    fn a_file_whose_pools_are_scrambled_never_panics() {
        // Deterministic xorshift, so a failure is reproducible. Scrambles bytes
        // across the whole file rather than the header, which is where the
        // `class_data_item` offsets and `type_list`s live.
        let full = fixture("fr.smarquis.sleeptimer_16200");
        let mut state = 0x5DEE_CE66_0BAD_F00Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..2_000 {
            let mut m = full.to_vec();
            for _ in 0..8 {
                let at = (next() as usize) % m.len();
                m[at] = (next() & 0xFF) as u8;
            }
            let _ = Pools::lower(&m, &ClassFacts::empty());
            let _ = round;
        }
    }

    #[test]
    fn random_bytes_of_dex_length_do_not_panic() {
        let mut state = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2_000 {
            let len = (next() % 4096) as usize;
            let mut m = vec![0u8; len];
            for b in m.iter_mut() {
                *b = (next() & 0xFF) as u8;
            }
            // Prepend a valid magic so a few of these get far enough to
            // exercise the header and pool checks rather than failing on magic.
            if len > 8 {
                m[..8].copy_from_slice(b"dex\n035\0");
            }
            let _ = Pools::lower(&m, &ClassFacts::empty());
        }
    }

    #[test]
    fn an_index_beyond_every_pool_is_a_typed_error() {
        let pools = Pools::lower(fixture("com.termux.boot_1000"), &ClassFacts::empty()).unwrap();
        let huge = [u32::MAX, u32::MAX - 1, 1 << 24, 65_536];
        for bad in huge {
            assert!(pools.types.get(bad).is_err(), "type {bad}");
            assert!(pools.protos.get(bad).is_err(), "proto {bad}");
            assert!(pools.fields.get(bad).is_err(), "field {bad}");
            assert!(pools.methods.get(bad).is_err(), "method {bad}");
            assert!(pools.strings.get(bad).is_err(), "string {bad}");
        }
        assert!(pools.methods.find(u32::MAX, u32::MAX, u32::MAX).is_none());
        assert!(pools.fields.find(u32::MAX, u32::MAX, u32::MAX).is_none());
    }

    #[test]
    fn pool_stats_add_up() {
        for (name, bytes) in FIXTURES {
            let pools = Pools::lower(bytes, &ClassFacts::empty()).unwrap();
            assert_eq!(pools.stats.strings, pools.strings.len(), "{name}");
            assert_eq!(pools.stats.types, pools.types.len(), "{name}");
            assert_eq!(pools.stats.protos, pools.protos.len(), "{name}");
            assert_eq!(pools.stats.fields, pools.fields.len(), "{name}");
            assert_eq!(pools.stats.methods, pools.methods.len(), "{name}");
            assert_eq!(pools.stats.classes, pools.classes.len(), "{name}");
            assert_eq!(pools.stats.array_types, pools.types.entries.iter().filter(|t| t.is_array()).count() as u32);
            assert!(pools.stats.string_bytes > 0, "{name}");
        }
    }

    #[test]
    fn error_kinds_are_distinct_and_render() {
        let errors = vec![
            PoolError::IndexOutOfRange { pool: "p", index: 1, len: 0 },
            PoolError::DanglingIndex { pool: "p", into: "q", index: 1, len: 0 },
            PoolError::MethodPoolUnsorted { at: 1, key: (0, 0, 0), prev: (0, 1, 0) },
            PoolError::FieldPoolUnsorted { at: 1, key: (0, 0, 0), prev: (0, 1, 0) },
            PoolError::StringPoolUnsorted { at: 1 },
            PoolError::CyclicHierarchy("Lx;".into()),
            PoolError::SelfSuperclass("Lx;".into()),
            PoolError::TooManyClasses { count: 1, limit: 0 },
            PoolError::TooManyStrings { count: 1 },
            PoolError::SizeOverflow { what: "instance layout" },
            PoolError::BadCallSite { what: "w", detail: "d".into() },
        ];
        let mut seen = BTreeSet::new();
        for e in &errors {
            assert!(seen.insert(e.kind()), "duplicate kind {}", e.kind());
            assert!(!e.to_string().is_empty());
        }
        assert_eq!(seen.len(), errors.len());
    }
}
