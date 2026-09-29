//! The guest heap: handles, allocation, and the collection strategy.
//!
//! This is the **host-side model** of the heap described in
//! [`IR.md`](../IR.md) § *Handle model*. The guest module will do the same
//! arithmetic inline in WebAssembly; keeping a Rust model of it means the bounds
//! checks, the layout rules and the collector can be *fuzzed* here rather than
//! reasoned about in generated code.
//!
//! # Layout
//!
//! Exactly the IR's, with two things it leaves open resolved and stated:
//!
//! ```text
//!   handle 0            null
//!   +8 (abs)   object   [class_ptr:u32][field_count:u32][slots...]   slots are 4 bytes
//!   +8 (abs)   array    [elem_width|u32 TAG][length:u32][elements...]
//! ```
//!
//! Two decisions the IR does not make, both load-bearing, both argued in the
//! report and restated at the code that depends on them:
//!
//! 1. **`field_count` counts 4-byte slots, not fields.** A `long` or `double`
//!    field occupies *two* consecutive slots, low half first, which is exactly
//!    how WebAssembly stores an `i64` in linear memory. The alternative —
//!    variable-width fields and a per-class layout table — was rejected because
//!    it makes the object header insufficient to compute the object's own size,
//!    so every bounds check would need a second load through a `class_ptr` the
//!    input file controls. The invariant that makes slotting safe is
//!    `class_ptr < 1 << 31`, checked when the class table is built.
//! 2. **Bit 31 of the first word is a kind tag**, so a handle is unambiguous
//!    about being an object or an array. The IR's two record shapes both start
//!    with a `u32` (`class_ptr` / `elem_width`) and nothing else distinguishes
//!    them. Two regions instead of a tag was the alternative; it wastes the
//!    whole gap between the object region and the array region, and the tag
//!    costs no information precisely because a class pointer can never need
//!    bit 31 (a `class_defs` count of 2^31 is not a file, it is a denial of
//!    service).
//!
//! # Allocation
//!
//! Bump allocation, 8-byte aligned, with `memory.grow` on demand in 64 KiB
//! pages. Allocation is bounded by a hard ceiling; exceeding it is
//! [`HeapError::OutOfMemory`], never a trap and never a panic.
//!
//! # Collection: **none by default**, host mark-sweep opt-in
//!
//! The recommendation is **do not collect**, with an opt-in host mark-sweep
//! available for embedders who can supply a sound root set. Reasoning, since it
//! is a decision and not a default:
//!
//! * **Reference counting is unsound for Java object graphs.** Java graphs are
//!   cyclic by construction — parent/child, listener lists, `Thread` holding its
//!   `Runnable` which holds the `Thread`. RC leaks every cycle, so it is not a
//!   bounded-memory strategy; it is a slow leak. The alternative failure —
//!   running a decrement on a use-after-free — is memory corruption, which is
//!   strictly worse than not collecting. RC is rejected.
//! * **A host mark-sweep is the only correct collector, and it is only correct
//!   given roots.** The host is the only party that can see handles the guest
//!   does not: handles parked in host tables, in a `HostImpl`'s captured state,
//!   in the root registry. But the guest's *own* live references live in
//!   WebAssembly locals and on the operand stack, which the host cannot read
//!   without a shadow stack that `codegen` has to maintain. Collect with an
//!   incomplete root set and a live object is freed; the guest keeps its handle;
//!   the next allocation reuses the bytes and the guest reads a *plausible
//!   wrong object*. That is silent data corruption, and it is worse than an
//!   out-of-memory abort because it does not announce itself.
//! * Therefore: default [`CollectionPolicy::None`], bump-only, ceiling-bounded,
//!   failing as a typed error that a runtime can turn into
//!   `java.lang.OutOfMemoryError` — which is exactly what ART does when a real
//!   app exhausts its heap. [`CollectionPolicy::HostMarkSweep`] exists, is
//!   tested, and is **never selected implicitly**: [`Heap::collect`] returns
//!   [`HeapError::CollectionDisabled`] unless the policy was set and an explicit
//!   [`RootSet`] was handed in.
//!
//! ## The failure mode, stated once more precisely
//!
//! With `None`: an app that allocates without bound — a `StringBuilder` in a
//! loop, an `ArrayList` that never stops growing — reaches the ceiling and is
//! aborted with a typed error. It does not corrupt anything and it does not
//! silently truncate. It is *observably different from ART*, which would have
//! collected and continued, and that divergence is a real cost of this choice
//! rather than a hypothetical.
//!
//! With `HostMarkSweep`: the failure is a stale handle, undetectable after the
//! freed block is reused. Two mitigations are implemented rather than promised.
//! [`Heap::quarantine_bytes`] delays reuse so that a stale handle is *detectable*
//! ([`HeapError::Freed`]) for a while, and [`RootSet::conservative`] lets an
//! embedder who maintains a shadow stack pass the scan ranges instead of an
//! exact list. Neither makes an incomplete root set safe; they make it
//! diagnosable. Only a sound root set does that.
//!
//! # Safety posture
//!
//! No `unsafe`, no panics, no `unwrap`, no recursion (the collector marks with an
//! explicit worklist and the fuzzer drives it with a deterministic PRNG). Every
//! arithmetic step that touches a size is `checked_*`, because the input file
//! controls every field offset and array length in it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Handle value reserved for `null`. Never returned by an allocation.
pub const NULL: u32 = 0;

/// First usable handle. Bytes `[0, 8)` are the null reservation; a handle is a
/// byte offset, so the first object is at byte 8.
pub const FIRST_HANDLE: u32 = 8;

/// Size of the linear-memory page that `memory.grow` operates in.
pub const PAGE_SIZE: usize = 64 * 1024;

/// Every allocation is a multiple of this. `long`/`double` fields are two
/// 4-byte slots, so natural 8-byte alignment avoids a split access on the
/// overwhelmingly common `J`/`D` field.
pub const ALIGN: usize = 8;

/// Bytes of header in front of an object's slots or an array's elements.
pub const HEADER_BYTES: u32 = 8;

/// Bit 31 of the first header word. Set for arrays, clear for objects.
pub const KIND_ARRAY: u32 = 0x8000_0000;

/// Largest value a `class_ptr` may take. Class pointers index a table built at
/// load time from `class_defs`, so exceeding this means the file is trying to
/// make us allocate an unbounded table rather than describing a class.
pub const MAX_CLASS_PTR: u32 = KIND_ARRAY;

/// Element widths an array may declare, in bytes. `byte[]`/`boolean[]` are 1,
/// `char[]`/`short[]` are 2, `int[]`/`float[]`/references are 4, `long[]`/
/// `double[]` are 8.
pub const VALID_ELEM_WIDTHS: [u32; 4] = [1, 2, 4, 8];

/// Slots per word in the reference bitmap.
const BITMAP_WORD_BITS: u32 = 64;

/// Largest block that goes on the reuse list. Anything bigger is quarantined
/// and then dropped; a multi-megabyte object is not worth the scan.
const MAX_REUSE_SIZE: u32 = 1 << 20;

/// Upper bound on the linear scan for a reusable block, so a pathological free
/// pattern cannot make allocation quadratic.
const MAX_REUSE_SCAN: usize = 64;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong touching the heap.
///
/// All of it is reachable from a hostile APK: an attacker controls every
/// `field_count`, every `elem_width`, every array `length` and every handle the
/// guest's own arithmetic produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeapError {
    /// A null handle was dereferenced. This is the guest's `NullPointerException`
    /// and the host must translate it, not swallow it.
    NullHandle,
    /// The handle is not an allocation start. Either it is below
    /// [`FIRST_HANDLE`], at or past the bump pointer, or it points into the
    /// middle of a live object.
    InvalidHandle {
        /// The offending handle.
        handle: u32,
    },
    /// The handle named a block that has been collected. Distinct from
    /// [`HeapError::InvalidHandle`] because it means the *collector* lost a
    /// reference, which is a different bug and a different fix.
    Freed {
        /// The stale handle.
        handle: u32,
    },
    /// An array operation was attempted on an object, or vice versa.
    WrongKind {
        /// The handle used.
        handle: u32,
        /// What the caller asked for.
        wanted: HandleKind,
        /// What the block actually is.
        found: HandleKind,
    },
    /// A field slot index past the end of the instance.
    FieldOutOfRange {
        /// The handle used.
        handle: u32,
        /// The requested slot.
        slot: u32,
        /// How many slots the instance has.
        slots: u32,
    },
    /// An array index past the end of the array.
    IndexOutOfRange {
        /// The handle used.
        handle: u32,
        /// The requested index.
        index: u32,
        /// The array's length.
        length: u32,
    },
    /// A byte range fell outside the block it was supposed to be in. This is the
    /// backstop behind every other bounds check; if it ever fires, one of them
    /// has a hole in it.
    OutOfBlock {
        /// The handle used.
        handle: u32,
        /// Byte offset within the block.
        rel: u32,
        /// Bytes wanted.
        len: u32,
        /// Bytes in the block.
        size: u32,
    },
    /// `elem_width` was not one of 1, 2, 4, 8.
    BadElementWidth {
        /// The handle used.
        handle: u32,
        /// The width the caller supplied.
        width: u32,
    },
    /// A size computation would have overflowed. Only reachable from lengths
    /// near `u32::MAX`; the error exists so the overflow is a diagnostic rather
    /// than a wrap.
    SizeOverflow {
        /// What was being sized.
        what: &'static str,
    },
    /// The heap ceiling would be exceeded.
    OutOfMemory {
        /// Bytes the allocation needed.
        requested: u64,
        /// Bytes the ceiling allows.
        ceiling: u64,
    },
    /// `collect` was called while the policy was [`CollectionPolicy::None`].
    ///
    /// [`CollectionPolicy::None`]: crate::heap::CollectionPolicy::None
    CollectionDisabled,
    /// A `class_ptr` outside the class table, or one with no reference bitmap.
    UnknownClass {
        /// The offending class pointer.
        class_ptr: u32,
    },
    /// A layout accessor was asked for an array class where it expected an
    /// object class, or the reverse.
    LayoutKindMismatch {
        /// The class pointer.
        class_ptr: u32,
    },
}

impl HeapError {
    /// A stable, machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            HeapError::NullHandle => "null_handle",
            HeapError::InvalidHandle { .. } => "invalid_handle",
            HeapError::Freed { .. } => "freed_handle",
            HeapError::WrongKind { .. } => "wrong_kind",
            HeapError::FieldOutOfRange { .. } => "field_out_of_range",
            HeapError::IndexOutOfRange { .. } => "index_out_of_range",
            HeapError::OutOfBlock { .. } => "out_of_block",
            HeapError::BadElementWidth { .. } => "bad_element_width",
            HeapError::SizeOverflow { .. } => "size_overflow",
            HeapError::OutOfMemory { .. } => "out_of_memory",
            HeapError::CollectionDisabled => "collection_disabled",
            HeapError::UnknownClass { .. } => "unknown_class",
            HeapError::LayoutKindMismatch { .. } => "layout_kind_mismatch",
        }
    }

    /// True for the errors that mean a *collector* lost a reference, as opposed
    /// to a caller passing something bad. Worth counting separately: it is the
    /// only one of these that indicates a bug in this crate's callers.
    pub fn is_use_after_free(&self) -> bool {
        matches!(self, HeapError::Freed { .. })
    }
}

impl fmt::Display for HeapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeapError::NullHandle => write!(f, "dereferenced the null handle"),
            HeapError::InvalidHandle { handle } => {
                write!(f, "handle {handle} is not an allocation start")
            }
            HeapError::Freed { handle } => {
                write!(f, "handle {handle} names a block that was collected")
            }
            HeapError::WrongKind { handle, wanted, found } => {
                write!(f, "handle {handle} is a {found}, not a {wanted}")
            }
            HeapError::FieldOutOfRange { handle, slot, slots } => write!(
                f,
                "handle {handle} has {slots} slot(s); slot {slot} is out of range"
            ),
            HeapError::IndexOutOfRange { handle, index, length } => {
                write!(f, "handle {handle} has length {length}; index {index} is out of range")
            }
            HeapError::OutOfBlock { handle, rel, len, size } => write!(
                f,
                "read of {len} byte(s) at +{rel} runs past the {size}-byte block at {handle}"
            ),
            HeapError::BadElementWidth { handle, width } => {
                write!(f, "handle {handle} declares element width {width}, which is not 1, 2, 4 or 8")
            }
            HeapError::SizeOverflow { what } => write!(f, "{what} size computation overflowed"),
            HeapError::OutOfMemory { requested, ceiling } => {
                write!(f, "allocation of {requested} byte(s) exceeds the {ceiling}-byte ceiling")
            }
            HeapError::CollectionDisabled => {
                write!(f, "collection is disabled; the policy is CollectionPolicy::None")
            }
            HeapError::UnknownClass { class_ptr } => {
                write!(f, "class_ptr {class_ptr} is outside the class table")
            }
            HeapError::LayoutKindMismatch { class_ptr } => {
                write!(f, "class_ptr {class_ptr} has the wrong class kind for this accessor")
            }
        }
    }
}

impl std::error::Error for HeapError {}

/// Result alias for heap operations.
pub type HeapResult<T> = Result<T, HeapError>;

/// How many 4-byte slots a DEX field of this descriptor occupies.
///
/// `J` and `D` take two, low half first, which is how WebAssembly stores an
/// `i64` or `f64` in linear memory. Everything else — including `Z`, `B`, `S`,
/// `C` and every reference — takes one, which is what the IR's calling
/// convention says for `Z B S C I`.
///
/// Lives here rather than in `pools` because it is the heap's layout rule; the
/// pool layer asks, rather than deciding.
pub fn field_slot_width(descriptor: &str) -> u32 {
    match descriptor {
        "J" | "D" => 2,
        // `V` has no storage; it can only be a return type, so an object slot
        // for it is already a malformation. One slot is the safe answer.
        "V" | "Z" | "B" | "S" | "C" | "I" | "F" => 1,
        // Every reference descriptor, array or not, is one slot.
        _ => 1,
    }
}

/// Which of the two record shapes a handle names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleKind {
    /// An instance: `[class_ptr][field_count][slots]`.
    Object,
    /// An array: `[elem_width|TAG][length][elements]`.
    Array,
}

impl fmt::Display for HandleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandleKind::Object => f.write_str("object"),
            HandleKind::Array => f.write_str("array"),
        }
    }
}

// ---------------------------------------------------------------------------
// Class layout
// ---------------------------------------------------------------------------

/// The per-class information the collector needs, supplied by the pool layer.
///
/// Declared here rather than in `pools` because the heap is the consumer and
/// this keeps `heap` testable against a stub. `pools::ClassTable` implements it.
pub trait ClassLayout {
    /// How many classes there are. A `class_ptr` must be below this.
    fn class_count(&self) -> u32;

    /// The reference bitmap for a class: one bit per 4-byte slot, LSB first
    /// within each 64-bit word. `None` for a `class_ptr` that is out of range or
    /// that names an array class, which the collector treats as untraceable.
    fn ref_bitmap(&self, class_ptr: u32) -> Option<&[u64]>;

    /// The number of 4-byte slots in an instance of this class. `None` for an
    /// array class or an unknown `class_ptr`.
    fn instance_slots(&self, class_ptr: u32) -> Option<u32>;
}

/// A layout that reports every class as having no reference fields.
///
/// Only correct for a program that provably allocates no cyclic or
/// cross-object references. It exists so the collector can be exercised without
/// a class table, and it is *not* the default anywhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoReferences;

impl ClassLayout for NoReferences {
    fn class_count(&self) -> u32 {
        0
    }
    fn ref_bitmap(&self, _class_ptr: u32) -> Option<&[u64]> {
        None
    }
    fn instance_slots(&self, _class_ptr: u32) -> Option<u32> {
        None
    }
}

// ---------------------------------------------------------------------------
// Extents
// ---------------------------------------------------------------------------

/// What the host knows about one block. The index is keyed by handle and is the
/// authority for the host; the guest recomputes sizes from headers with the same
/// formula, and a test asserts the two agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    /// A live instance.
    Object {
        /// Total bytes, already rounded up to [`ALIGN`].
        size: u32,
        /// 4-byte slots, from the header.
        slots: u32,
        /// Class pointer, from the header.
        class_ptr: u32,
    },
    /// A live array.
    Array {
        /// Total bytes, already rounded up to [`ALIGN`].
        size: u32,
        /// Bytes per element, from the header.
        elem_width: u32,
        /// Element count, from the header.
        length: u32,
    },
    /// A block that is free. May still be quarantined, in which case it is
    /// deliberately *not* handed out again yet.
    Free {
        /// Total bytes.
        size: u32,
        /// True while the block is being held back to keep stale handles
        /// detectable.
        quarantined: bool,
    },
}

// ---------------------------------------------------------------------------
// Roots
// ---------------------------------------------------------------------------

/// The set of handles a collection must treat as live.
///
/// There is no default and no "collect everything" path, on purpose. The guest's
/// own locals are not in here and the host cannot see them; see the module
/// documentation for why that makes an incomplete root set unsound rather than
/// merely wasteful.
#[derive(Debug, Clone, Default)]
pub struct RootSet {
    exact: BTreeSet<u32>,
    scan: Vec<(u32, u32)>,
}

impl RootSet {
    /// A root set built from an exact list of handles. The honest constructor:
    /// use it when the embedder really does know every live reference.
    pub fn exact<I: IntoIterator<Item = u32>>(handles: I) -> RootSet {
        RootSet { exact: handles.into_iter().collect(), scan: Vec::new() }
    }

    /// A root set that additionally treats every word-aligned `u32` in the given
    /// `(handle, byte_len)` ranges as a candidate root.
    ///
    /// This is the shadow-stack escape hatch: an embedder whose `codegen`
    /// maintains a spill area of live handles passes that area's extent here
    /// instead of enumerating handles. It is *conservative*, so it retains
    /// garbage — it cannot free a live object that the shadow stack mentions.
    pub fn conservative<H, R>(handles: H, ranges: R) -> RootSet
    where
        H: IntoIterator<Item = u32>,
        R: IntoIterator<Item = (u32, u32)>,
    {
        RootSet { exact: handles.into_iter().collect(), scan: ranges.into_iter().collect() }
    }

    /// Add one handle.
    pub fn insert(&mut self, handle: u32) {
        if handle != NULL {
            self.exact.insert(handle);
        }
    }

    /// Number of exactly-listed roots. Scanning ranges are not counted.
    pub fn len(&self) -> usize {
        self.exact.len()
    }

    /// True when no exact roots and no scan ranges were supplied. A collection
    /// with this root set is almost certainly wrong; the collector still runs,
    /// because refusing would hide the bug rather than report it.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.scan.is_empty()
    }

    fn roots(&self) -> impl Iterator<Item = u32> + '_ {
        self.exact.iter().copied()
    }

    fn scan_ranges(&self) -> &[(u32, u32)] {
        &self.scan
    }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// When the heap reclaims memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollectionPolicy {
    /// Bump-only. Allocation fails with [`HeapError::OutOfMemory`] at the
    /// ceiling. The default, and the recommendation — see the module
    /// documentation for the argument.
    #[default]
    None,
    /// Host-driven, non-moving mark-sweep. Requires an explicit [`RootSet`] on
    /// every call; never selected implicitly.
    HostMarkSweep,
}

impl CollectionPolicy {
    /// A stable name for reports and the JSON error envelope.
    pub fn as_str(&self) -> &'static str {
        match self {
            CollectionPolicy::None => "none",
            CollectionPolicy::HostMarkSweep => "host_mark_sweep",
        }
    }
}

/// What one collection did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GcReport {
    /// Blocks walked.
    pub scanned: u32,
    /// Blocks found reachable.
    pub live: u32,
    /// Blocks freed.
    pub freed: u32,
    /// Bytes freed.
    pub freed_bytes: u64,
    /// Bytes moved into the quarantine, where a stale handle is still
    /// [`HeapError::Freed`] rather than silently aliased.
    pub quarantined_bytes: u64,
    /// Blocks that were freed but are *not* yet reusable.
    pub quarantined_blocks: u32,
    /// Roots listed exactly, plus the number of scan ranges.
    pub roots: u32,
    /// Scan ranges supplied.
    pub scan_ranges: u32,
}

impl GcReport {
    /// True when the collection actually reclaimed something.
    pub fn freed_anything(&self) -> bool {
        self.freed > 0
    }
}

/// A snapshot of heap occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Bytes handed out, including headers and alignment padding.
    pub live_bytes: u64,
    /// Bytes the bump pointer has passed.
    pub bump_bytes: u64,
    /// Bytes currently backing the heap region, a multiple of [`PAGE_SIZE`].
    pub resident_bytes: u64,
    /// [`PAGE_SIZE`]-sized pages the guest module would have grown to.
    pub pages: u32,
    /// Live objects.
    pub objects: u32,
    /// Live arrays.
    pub arrays: u32,
    /// Free blocks, quarantined or not.
    pub free_blocks: u32,
    /// High-water mark of `live_bytes`.
    pub peak_bytes: u64,
}

// ---------------------------------------------------------------------------
// The heap
// ---------------------------------------------------------------------------

/// The guest heap.
///
/// `base` is the linear-memory address of handle 0. It is 0 in the IR's
/// reference layout; it is non-zero when the module's own data segment (the pool
/// images, which the IR places in imported globals) occupies the bottom of
/// linear memory. Handles are offsets from `base`, so `base` is a property of
/// where the heap is placed, not of the handle encoding.
#[derive(Debug)]
pub struct Heap {
    bytes: Vec<u8>,
    base: u32,
    next: u32,
    ceiling: u64,
    index: BTreeMap<u32, Extent>,
    reusable: Vec<u32>,
    quarantine: VecDeque<u32>,
    quarantine_budget: u64,
    policy: CollectionPolicy,
    live_bytes: u64,
    objects: u32,
    arrays: u32,
    peak_bytes: u64,
    collects: u64,
}

impl Default for Heap {
    fn default() -> Heap {
        Heap::new()
    }
}

impl Heap {
    /// A heap with the default ceiling of 64 MiB, handle 0 at address 0, and no
    /// collection.
    pub fn new() -> Heap {
        Heap::with_ceiling(64 * 1024 * 1024)
    }

    /// A heap with an explicit byte ceiling. `ceiling` counts from `base` and is
    /// clamped so that `base + ceiling` still fits a `u32` handle space.
    pub fn with_ceiling(ceiling: u64) -> Heap {
        let ceiling = ceiling.min(u32::MAX as u64);
        let bytes = vec![0u8; FIRST_HANDLE as usize];
        Heap {
            bytes,
            base: 0,
            next: FIRST_HANDLE,
            ceiling,
            index: BTreeMap::new(),
            reusable: Vec::new(),
            quarantine: VecDeque::new(),
            quarantine_budget: 0,
            policy: CollectionPolicy::None,
            live_bytes: 0,
            objects: 0,
            arrays: 0,
            peak_bytes: 0,
            collects: 0,
        }
    }

    /// Place the heap so that handle 0 lives at linear-memory address `base`.
    ///
    /// `base` must be a multiple of [`ALIGN`] and at least [`FIRST_HANDLE`].
    /// Returns the heap unchanged on a bad argument rather than panicking, since
    /// the value can come from a module layout this crate did not choose.
    pub fn at(mut self, base: u32) -> Heap {
        let ok = base as usize >= ALIGN
            && base as usize >= FIRST_HANDLE as usize
            // ALIGN is a power of two, so this is an alignment test and not a
            // division. Written as a mask rather than `is_multiple_of` because
            // the crate declares `rust-version = 1.75`.
            && base & (ALIGN as u32 - 1) == 0
            && u64::from(base) + self.ceiling <= u64::from(u32::MAX);
        if ok {
            // The region below `base` belongs to the module's data segment, not
            // to us, so the backing store is padded to keep `off` a plain index.
            self.bytes.resize(base as usize, 0);
            self.base = base;
        }
        self
    }

    /// Select the collection policy. Default is [`CollectionPolicy::None`].
    pub fn set_policy(&mut self, policy: CollectionPolicy) {
        self.policy = policy;
    }

    /// The current policy.
    pub fn policy(&self) -> CollectionPolicy {
        self.policy
    }

    /// How many freed blocks must be held back before they become reusable
    /// again. Zero, the default, means a freed handle is [`HeapError::Freed`]
    /// only until the next collection reuses its block; a nonzero value widens
    /// the window in which a stale handle is *detectable*. It costs memory.
    pub fn quarantine_bytes(&mut self, bytes: u64) {
        self.quarantine_budget = bytes;
        self.drain_quarantine();
    }

    /// The configured quarantine budget.
    pub fn quarantine_budget(&self) -> u64 {
        self.quarantine_budget
    }

    /// The byte offset of handle 0 within the guest's linear memory.
    pub fn base(&self) -> u32 {
        self.base
    }

    /// The bump pointer: the first handle not yet allocated.
    pub fn bump(&self) -> u32 {
        self.next
    }

    /// The byte ceiling.
    pub fn ceiling(&self) -> u64 {
        self.ceiling
    }

    /// Number of collections run.
    pub fn collections(&self) -> u64 {
        self.collects
    }

    /// The backing region, as the guest would see it after its last
    /// `memory.grow`. Empty below [`FIRST_HANDLE`] bytes are the null
    /// reservation and are always zero.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A snapshot of occupancy.
    pub fn stats(&self) -> Stats {
        let free_blocks = self
            .index
            .values()
            .filter(|e| matches!(e, Extent::Free { .. }))
            .count() as u32;
        Stats {
            live_bytes: self.live_bytes,
            bump_bytes: u64::from(self.next - FIRST_HANDLE),
            resident_bytes: self.bytes.len() as u64,
            pages: (self.bytes.len() / PAGE_SIZE) as u32,
            objects: self.objects,
            arrays: self.arrays,
            free_blocks,
            peak_bytes: self.peak_bytes,
        }
    }

    // ------------------------------------------------------------- allocation

    /// Largest slot count whose object still fits in a `u32` handle space.
    pub const MAX_SLOTS: u32 = (u32::MAX - HEADER_BYTES - (ALIGN as u32 - 1)) / 4;

    /// Bytes an object with `slots` 4-byte slots occupies, header and padding
    /// included.
    ///
    /// This is the formula the guest inlines, so it is total: the arithmetic is
    /// done in `u64` and saturates, meaning no `slots` value can overflow. The
    /// allocator still rejects `slots > MAX_SLOTS` with a typed error rather
    /// than handing back a saturated size, because a saturated size is a lie.
    pub const fn object_size(slots: u32) -> u32 {
        let raw = HEADER_BYTES as u64 + 4 * slots as u64;
        let aligned = (raw + ALIGN as u64 - 1) & !(ALIGN as u64 - 1);
        if aligned > u32::MAX as u64 {
            u32::MAX
        } else {
            aligned as u32
        }
    }

    /// Bytes an array of `length` elements of `elem_width` bytes occupies.
    /// Total for the same reason as [`Heap::object_size`].
    pub const fn array_size(length: u32, elem_width: u32) -> u32 {
        let raw = HEADER_BYTES as u64 + length as u64 * elem_width as u64;
        let aligned = (raw + ALIGN as u64 - 1) & !(ALIGN as u64 - 1);
        if aligned > u32::MAX as u64 {
            u32::MAX
        } else {
            aligned as u32
        }
    }

    /// True if `width` is an element width an array may declare.
    pub fn is_valid_elem_width(width: u32) -> bool {
        VALID_ELEM_WIDTHS.contains(&width)
    }

    /// Allocate an object with `slots` four-byte slots.
    ///
    /// `class_ptr` must be below [`MAX_CLASS_PTR`]; the tag bit is not available
    /// to a class pointer. The class table is not consulted — allocation must not
    /// depend on a layout the embedder might not have — so a `class_ptr` that no
    /// class table knows about is allocated happily and becomes
    /// [`HeapError::UnknownClass`] when something tries to *trace* it.
    pub fn alloc_object(&mut self, class_ptr: u32, slots: u32) -> HeapResult<u32> {
        if class_ptr >= MAX_CLASS_PTR {
            return Err(HeapError::UnknownClass { class_ptr });
        }
        if slots > Heap::MAX_SLOTS {
            return Err(HeapError::SizeOverflow { what: "object" });
        }
        let size = Heap::object_size(slots);
        let handle = self.reserve(size)?;
        let at = self.off(handle)?;
        self.put_u32(at, class_ptr)?;
        self.put_u32(at + 4, slots)?;
        self.zero_body(handle, size)?;
        self.index.insert(handle, Extent::Object { size, slots, class_ptr });
        self.objects = self.objects.saturating_add(1);
        self.live_bytes = self.live_bytes.saturating_add(u64::from(size));
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        Ok(handle)
    }

    /// Allocate an array of `length` elements of `elem_width` bytes.
    ///
    /// `elem_width` must be 1, 2, 4 or 8 and `length * elem_width` must not
    /// overflow. Both are attacker-controlled: a `new-array` whose type is a
    /// `long[]` and whose size register came from arithmetic can ask for
    /// `0xFFFFFFFF` longs.
    pub fn alloc_array(&mut self, elem_width: u32, length: u32) -> HeapResult<u32> {
        if !Heap::is_valid_elem_width(elem_width) {
            return Err(HeapError::BadElementWidth { handle: 0, width: elem_width });
        }
        if length > u32::MAX / elem_width {
            return Err(HeapError::SizeOverflow { what: "array" });
        }
        let size = Heap::array_size(length, elem_width);
        let handle = self.reserve(size)?;
        let at = self.off(handle)?;
        self.put_u32(at, elem_width | KIND_ARRAY)?;
        self.put_u32(at + 4, length)?;
        self.zero_body(handle, size)?;
        self.index.insert(handle, Extent::Array { size, elem_width, length });
        self.arrays = self.arrays.saturating_add(1);
        self.live_bytes = self.live_bytes.saturating_add(u64::from(size));
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        Ok(handle)
    }

    /// Zero the payload of a freshly-taken block. Every byte after the header,
    /// including alignment padding, so a read of an unwritten field is a defined
    /// zero rather than whatever the previous tenant left behind.
    fn zero_body(&mut self, handle: u32, size: u32) -> HeapResult<()> {
        let at = self.off(handle)?;
        let end = at + (size - HEADER_BYTES) as usize;
        match self.bytes.get_mut(at..end) {
            Some(body) => {
                body.fill(0);
                Ok(())
            }
            None => Err(HeapError::OutOfBlock { handle, rel: HEADER_BYTES, len: size, size }),
        }
    }

    /// Find `size` bytes, growing memory if the bump pointer cannot supply them.
    fn reserve(&mut self, size: u32) -> HeapResult<u32> {
        if let Some(handle) = self.take_reusable(size) {
            return Ok(handle);
        }
        let end = u64::from(self.next) + u64::from(size);
        if end > self.ceiling {
            return Err(HeapError::OutOfMemory { requested: end, ceiling: self.ceiling });
        }
        let end = end as u32;
        if end > self.next {
            self.grow_to(end)?;
            self.next = end;
        }
        Ok(self.next - size)
    }

    /// Reuse a freed block if one is big enough and not quarantined.
    fn take_reusable(&mut self, size: u32) -> Option<u32> {
        if size == 0 || size > MAX_REUSE_SIZE || self.reusable.is_empty() {
            return None;
        }
        let limit = self.reusable.len().min(MAX_REUSE_SCAN);
        let mut found: Option<usize> = None;
        for i in 0..limit {
            let &h = self.reusable.get(i)?;
            let Some(Extent::Free { size: free, quarantined }) = self.index.get(&h) else {
                return None;
            };
            if *quarantined {
                continue;
            }
            if *free >= size {
                found = Some(i);
                break;
            }
        }
        let i = found?;
        let handle = self.reusable[i];
        let Extent::Free { size: free, .. } = self.index.get(&handle).copied()? else {
            return None;
        };
        self.reusable.swap_remove(i);
        self.quarantine.retain(|&h| h != handle);
        if free > size {
            // Split: the tail becomes a fresh free block.
            let tail = handle + size;
            self.index.insert(tail, Extent::Free { size: free - size, quarantined: false });
            self.reusable.push(tail);
            self.index.insert(handle, Extent::Free { size, quarantined: false });
        }
        self.live_bytes = self.live_bytes.saturating_add(u64::from(size));
        self.peak_bytes = self.peak_bytes.max(self.live_bytes);
        Some(handle)
    }

    /// `memory.grow` in [`PAGE_SIZE`] units, up to the ceiling.
    ///
    /// `end` is a *handle*; the absolute address is `base + end`, and the
    /// ceiling is measured in handles from `base` so that a relocated heap has
    /// the same budget.
    fn grow_to(&mut self, end: u32) -> HeapResult<()> {
        let want = usize::try_from(self.base)
            .ok()
            .and_then(|b| b.checked_add(end as usize))
            .ok_or(HeapError::SizeOverflow { what: "memory" })?
            .next_multiple_of(PAGE_SIZE);
        if want as u64 > (self.base as u64).saturating_add(self.ceiling) {
            return Err(HeapError::OutOfMemory {
                requested: (want as u64).saturating_sub(self.base as u64),
                ceiling: self.ceiling,
            });
        }
        if want > self.bytes.len() {
            self.bytes.resize(want, 0);
        }
        Ok(())
    }

    // ------------------------------------------------------------ inspection

    /// What a handle names, or why it names nothing.
    pub fn classify(&self, handle: u32) -> HeapResult<HandleKind> {
        if handle == NULL {
            return Err(HeapError::NullHandle);
        }
        if handle < FIRST_HANDLE || handle >= self.next {
            return Err(HeapError::InvalidHandle { handle });
        }
        match self.index.get(&handle) {
            None => Err(HeapError::InvalidHandle { handle }),
            Some(Extent::Object { .. }) => Ok(HandleKind::Object),
            Some(Extent::Array { .. }) => Ok(HandleKind::Array),
            Some(Extent::Free { .. }) => Err(HeapError::Freed { handle }),
        }
    }

    /// Total bytes of the block at `handle`, header and padding included.
    pub fn block_size(&self, handle: u32) -> HeapResult<u32> {
        self.classify(handle)?;
        match self.index.get(&handle) {
            Some(Extent::Object { size, .. }) | Some(Extent::Array { size, .. }) => Ok(*size),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    /// The class pointer of an object.
    pub fn class_of(&self, handle: u32) -> HeapResult<u32> {
        self.expect_kind(handle, HandleKind::Object)?;
        match self.index.get(&handle) {
            Some(Extent::Object { class_ptr, .. }) => Ok(*class_ptr),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    /// The slot count of an object, from its header.
    pub fn slots_of(&self, handle: u32) -> HeapResult<u32> {
        self.expect_kind(handle, HandleKind::Object)?;
        match self.index.get(&handle) {
            Some(Extent::Object { slots, .. }) => Ok(*slots),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    /// The declared element width of an array.
    pub fn elem_width_of(&self, handle: u32) -> HeapResult<u32> {
        self.expect_kind(handle, HandleKind::Array)?;
        match self.index.get(&handle) {
            Some(Extent::Array { elem_width, .. }) => Ok(*elem_width),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    /// The declared element count of an array.
    pub fn array_len(&self, handle: u32) -> HeapResult<u32> {
        self.expect_kind(handle, HandleKind::Array)?;
        match self.index.get(&handle) {
            Some(Extent::Array { length, .. }) => Ok(*length),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    fn expect_kind(&self, handle: u32, wanted: HandleKind) -> HeapResult<()> {
        match self.classify(handle)? {
            found if found == wanted => Ok(()),
            found => Err(HeapError::WrongKind { handle, wanted, found }),
        }
    }

    // --------------------------------------------------------- field access

    /// Read the 4-byte slot `slot` of an object.
    pub fn load_field(&self, handle: u32, slot: u32) -> HeapResult<u32> {
        let slots = self.slots_of(handle)?;
        if slot >= slots {
            return Err(HeapError::FieldOutOfRange { handle, slot, slots });
        }
        let rel = HEADER_BYTES.checked_add(slot.checked_mul(4).ok_or(HeapError::SizeOverflow {
            what: "field offset",
        })?)
        .ok_or(HeapError::SizeOverflow { what: "field offset" })?;
        self.read_u32(handle, rel)
    }

    /// Write the 4-byte slot `slot` of an object.
    pub fn store_field(&mut self, handle: u32, slot: u32, value: u32) -> HeapResult<()> {
        let slots = self.slots_of(handle)?;
        if slot >= slots {
            return Err(HeapError::FieldOutOfRange { handle, slot, slots });
        }
        let rel = HEADER_BYTES.checked_add(slot.checked_mul(4).ok_or(HeapError::SizeOverflow {
            what: "field offset",
        })?)
        .ok_or(HeapError::SizeOverflow { what: "field offset" })?;
        self.write_le(handle, rel, 4, u64::from(value))
    }

    /// Read two consecutive slots as a little-endian 64-bit value: the low half
    /// of a `long`/`double` field is the lower slot.
    pub fn load_field_wide(&self, handle: u32, slot: u32) -> HeapResult<u64> {
        let slots = self.slots_of(handle)?;
        let need = slot.checked_add(1).ok_or(HeapError::SizeOverflow { what: "wide field" })?;
        if need >= slots {
            return Err(HeapError::FieldOutOfRange { handle, slot, slots });
        }
        let lo = self.load_field(handle, slot)?;
        let hi = self.load_field(handle, need)?;
        Ok(u64::from(lo) | (u64::from(hi) << 32))
    }

    /// Write two consecutive slots as a little-endian 64-bit value.
    pub fn store_field_wide(&mut self, handle: u32, slot: u32, value: u64) -> HeapResult<()> {
        let slots = self.slots_of(handle)?;
        let need = slot.checked_add(1).ok_or(HeapError::SizeOverflow { what: "wide field" })?;
        if need >= slots {
            return Err(HeapError::FieldOutOfRange { handle, slot, slots });
        }
        self.store_field(handle, slot, value as u32)?;
        self.store_field(handle, need, (value >> 32) as u32)
    }

    // --------------------------------------------------------- array access

    /// Read element `index` of an array as `width` bytes, zero-extended.
    ///
    /// `width` must equal the array's declared `elem_width`; reading a `long[]`
    /// as four bytes is a type error, not a truncation.
    pub fn array_read(&self, handle: u32, index: u32, width: u32) -> HeapResult<u64> {
        let (elem_width, length, size) = self.array_shape(handle)?;
        if width != elem_width {
            return Err(HeapError::BadElementWidth { handle, width });
        }
        if index >= length {
            return Err(HeapError::IndexOutOfRange { handle, index, length });
        }
        let rel = self.element_rel(handle, index, width, size)?;
        self.read_le(handle, rel, width)
    }

    /// Write element `index` of an array from the low `width` bytes of `value`.
    pub fn array_write(&mut self, handle: u32, index: u32, width: u32, value: u64) -> HeapResult<()> {
        let (elem_width, length, size) = self.array_shape(handle)?;
        if width != elem_width {
            return Err(HeapError::BadElementWidth { handle, width });
        }
        if index >= length {
            return Err(HeapError::IndexOutOfRange { handle, index, length });
        }
        let rel = self.element_rel(handle, index, width, size)?;
        self.write_le(handle, rel, width, value)
    }

    /// Read one element of an array of 4-byte elements as a handle or `i32`.
    pub fn array_ref(&self, handle: u32, index: u32) -> HeapResult<u32> {
        let v = self.array_read(handle, index, 4)?;
        Ok(v as u32)
    }

    /// Write one element of an array of 4-byte elements.
    pub fn set_array_ref(&mut self, handle: u32, index: u32, value: u32) -> HeapResult<()> {
        self.array_write(handle, index, 4, u64::from(value))
    }

    fn array_shape(&self, handle: u32) -> HeapResult<(u32, u32, u32)> {
        self.expect_kind(handle, HandleKind::Array)?;
        match self.index.get(&handle) {
            Some(Extent::Array { elem_width, length, size }) => Ok((*elem_width, *length, *size)),
            _ => Err(HeapError::InvalidHandle { handle }),
        }
    }

    fn element_rel(&self, handle: u32, index: u32, width: u32, size: u32) -> HeapResult<u32> {
        let byte = index.checked_mul(width).ok_or(HeapError::SizeOverflow { what: "array index" })?;
        let rel = HEADER_BYTES.checked_add(byte).ok_or(HeapError::SizeOverflow {
            what: "array index",
        })?;
        if rel.checked_add(width).map_or(true, |end| end > size) {
            return Err(HeapError::OutOfBlock { handle, rel, len: width, size });
        }
        Ok(rel)
    }

    // ------------------------------------------------------- raw byte access

    /// Address of `handle` within the guest's linear memory, and its index into
    /// [`Heap::bytes`].
    ///
    /// A handle is an offset *from* `base`, so the absolute address is
    /// `base + handle`. `base` is 0 in the IR's reference layout and non-zero
    /// when the module's data segment occupies the bottom of linear memory.
    fn off(&self, handle: u32) -> HeapResult<usize> {
        let abs = self.base.checked_add(handle).ok_or(HeapError::InvalidHandle { handle })?;
        let at = usize::try_from(abs).map_err(|_| HeapError::InvalidHandle { handle })?;
        if at > self.bytes.len() {
            return Err(HeapError::InvalidHandle { handle });
        }
        Ok(at)
    }

    /// Write a `u32` at a raw offset in the backing region. Only used for
    /// headers, which the allocator has just sized itself, so the only failure
    /// is a region that is shorter than the header it just promised.
    fn put_u32(&mut self, at: usize, value: u32) -> HeapResult<()> {
        for i in 0..4usize {
            match self.bytes.get_mut(at + i) {
                Some(slot) => *slot = (value >> (8 * i)) as u8,
                None => {
                    return Err(HeapError::OutOfBlock {
                        handle: 0,
                        rel: u32::try_from(at).unwrap_or(u32::MAX),
                        len: 4,
                        size: 0,
                    })
                }
            }
        }
        Ok(())
    }

    fn read_u32(&self, handle: u32, rel: u32) -> HeapResult<u32> {
        let v = self.read_le(handle, rel, 4)?;
        Ok(v as u32)
    }

    fn read_le(&self, handle: u32, rel: u32, len: u32) -> HeapResult<u64> {
        let size = self.block_size(handle)?;
        self.guard(handle, rel, len, size)?;
        let at = self.off(handle)? + rel as usize;
        let mut value: u64 = 0;
        for i in 0..len as usize {
            let byte = self
                .bytes
                .get(at + i)
                .ok_or(HeapError::OutOfBlock { handle, rel, len, size })?;
            value |= u64::from(*byte) << (8 * i);
        }
        Ok(value)
    }

    fn write_le(&mut self, handle: u32, rel: u32, len: u32, value: u64) -> HeapResult<()> {
        let size = self.block_size(handle)?;
        self.guard(handle, rel, len, size)?;
        let at = self.off(handle)? + rel as usize;
        for i in 0..len as usize {
            let byte = (value >> (8 * i)) as u8;
            match self.bytes.get_mut(at + i) {
                Some(slot) => *slot = byte,
                None => return Err(HeapError::OutOfBlock { handle, rel, len, size }),
            }
        }
        Ok(())
    }

    /// The backstop: refuse any read that leaves the block, whatever the
    /// higher-level check above believed.
    fn guard(&self, handle: u32, rel: u32, len: u32, size: u32) -> HeapResult<()> {
        if rel.checked_add(len).map_or(true, |end| end > size) {
            return Err(HeapError::OutOfBlock { handle, rel, len, size });
        }
        let _ = self.off(handle)?;
        Ok(())
    }

    // ------------------------------------------------------------ collection

    /// Run one mark-sweep collection.
    ///
    /// Returns [`HeapError::CollectionDisabled`] unless the policy is
    /// [`CollectionPolicy::HostMarkSweep`]: the guard against a collector
    /// running by accident against a root set nobody thought about.
    ///
    /// Non-moving by design. Moving would invalidate every handle the host
    /// holds, and the identity-preservation property is worth more than the
    /// compaction.
    pub fn collect(&mut self, roots: &RootSet, layout: &dyn ClassLayout) -> HeapResult<GcReport> {
        if self.policy != CollectionPolicy::HostMarkSweep {
            return Err(HeapError::CollectionDisabled);
        }
        self.collects = self.collects.saturating_add(1);

        let mut report = GcReport {
            roots: roots.len() as u32,
            scan_ranges: roots.scan_ranges().len() as u32,
            ..GcReport::default()
        };

        // Snapshot the live blocks. BTreeMap iteration is by handle, which is
        // allocation order, so the report is deterministic.
        let live: Vec<u32> = self
            .index
            .iter()
            .filter(|(_, e)| !matches!(e, Extent::Free { .. }))
            .map(|(h, _)| *h)
            .collect();
        report.scanned = live.len() as u32;
        if live.is_empty() {
            return Ok(report);
        }
        let live_set: BTreeSet<u32> = live.iter().copied().collect();

        // Mark. An explicit worklist, not recursion: a hostile object graph can
        // be a 200k-node linked list and the host stack is not ours to risk.
        let mut marked: BTreeSet<u32> = BTreeSet::new();
        let mut work: Vec<u32> = Vec::new();
        let mut push = |h: u32, work: &mut Vec<u32>, marked: &mut BTreeSet<u32>| {
            if h != NULL && live_set.contains(&h) && marked.insert(h) {
                work.push(h);
            }
        };
        for h in roots.roots() {
            push(h, &mut work, &mut marked);
        }
        for &(start, len) in roots.scan_ranges() {
            self.scan_conservative(start, len, &live_set, &mut work, &mut marked);
        }
        while let Some(handle) = work.pop() {
            self.trace(handle, layout, &mut push, &mut work, &mut marked)?;
        }
        report.live = marked.len() as u32;

        // Sweep.
        for handle in live {
            if marked.contains(&handle) {
                continue;
            }
            let (size, was_object, was_array) = match self.index.get(&handle) {
                Some(Extent::Object { size, .. }) => (*size, true, false),
                Some(Extent::Array { size, .. }) => (*size, false, true),
                _ => continue,
            };
            self.live_bytes = self.live_bytes.saturating_sub(u64::from(size));
            if was_object {
                self.objects = self.objects.saturating_sub(1);
            }
            if was_array {
                self.arrays = self.arrays.saturating_sub(1);
            }
            // Poison the header so a stale handle that happens to still be
            // readable does not look like a plausible object.
            let at = self.off(handle)?;
            self.put_u32(at, 0xDEAD_0BAD)?;
            self.put_u32(at + 4, 0)?;
            report.freed = report.freed.saturating_add(1);
            report.freed_bytes = report.freed_bytes.saturating_add(u64::from(size));
            self.quarantine.push_back(handle);
            self.index.insert(handle, Extent::Free { size, quarantined: true });
            report.quarantined_bytes = report.quarantined_bytes.saturating_add(u64::from(size));
            report.quarantined_blocks = report.quarantined_blocks.saturating_add(1);
        }
        if self.quarantine_budget == 0 {
            // No budget: everything freed this cycle is immediately reusable, and
            // `Freed` only survives until the next allocation lands on it.
            for &handle in &self.reusable {
                if let Some(Extent::Free { size, .. }) = self.index.get(&handle).copied() {
                    if size <= MAX_REUSE_SIZE {
                        self.index.insert(handle, Extent::Free { size, quarantined: false });
                    }
                }
            }
            self.drain_all_quarantine();
        } else {
            self.drain_quarantine();
        }
        Ok(report)
    }

    /// Treat every aligned `u32` in a scan range as a candidate root.
    ///
    /// A scan range is *raw linear memory*, not a heap block — a shadow stack is
    /// not itself a heap object — so this reads the backing store directly and
    /// does no handle validation on the range. A word that happens to look like
    /// a live handle is retained; that is the safe direction for a conservative
    /// scan, and the price is retaining some garbage.
    fn scan_conservative(
        &self,
        start: u32,
        len: u32,
        live: &BTreeSet<u32>,
        work: &mut Vec<u32>,
        marked: &mut BTreeSet<u32>,
    ) {
        let Some(from) = self.base.checked_add(start) else { return };
        let Some(from) = usize::try_from(from).ok() else { return };
        let Some(to) = usize::try_from(len).ok().and_then(|l| from.checked_add(l)) else { return };
        let end = to.min(self.bytes.len());
        let mut at = from;
        while at + 4 <= end {
            let word = &self.bytes[at..at + 4];
            let candidate = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            if candidate != NULL && live.contains(&candidate) && marked.insert(candidate) {
                work.push(candidate);
            }
            at += 4;
        }
    }

    /// Add every reference held by one block to the worklist.
    fn trace(
        &self,
        handle: u32,
        layout: &dyn ClassLayout,
        push: &mut impl FnMut(u32, &mut Vec<u32>, &mut BTreeSet<u32>),
        work: &mut Vec<u32>,
        marked: &mut BTreeSet<u32>,
    ) -> HeapResult<()> {
        match self.index.get(&handle).copied() {
            Some(Extent::Object { size, slots, class_ptr }) => {
                let Some(bitmap) = layout.ref_bitmap(class_ptr) else {
                    // Untraceable: an unknown class pointer, or a class with no
                    // bitmap. Retaining the block is the only safe answer; the
                    // alternative is freeing an object whose references we could
                    // not see.
                    let _ = size;
                    return Ok(());
                };
                for slot in 0..slots {
                    if !Heap::bit_is_set(bitmap, slot) {
                        continue;
                    }
                    let rel = HEADER_BYTES.saturating_add(slot.saturating_mul(4));
                    if rel.checked_add(4).map_or(true, |e| e > size) {
                        continue;
                    }
                    let child = self.read_le(handle, rel, 4)? as u32;
                    push(child, work, marked);
                }
                Ok(())
            }
            Some(Extent::Array { size, elem_width, length }) => {
                if elem_width != 4 {
                    // A primitive array holds no references. `width == 4` is
                    // ambiguous between `int[]` and a reference array, so this is
                    // conservative in the safe direction: it treats an `int[]`
                    // as possibly holding handles and retains more than it needs.
                    let _ = (size, length);
                    return Ok(());
                }
                for index in 0..length {
                    let Some(rel) = self.element_rel(handle, index, 4, size).ok() else {
                        break;
                    };
                    let child = self.read_le(handle, rel, 4)? as u32;
                    push(child, work, marked);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Test one bit of a class's reference bitmap.
    pub fn bit_is_set(bitmap: &[u64], slot: u32) -> bool {
        let word = (slot / BITMAP_WORD_BITS) as usize;
        let bit = slot % BITMAP_WORD_BITS;
        match bitmap.get(word) {
            Some(w) => (w >> bit) & 1 == 1,
            None => false,
        }
    }

    /// Release quarantined blocks until the budget is respected.
    fn drain_quarantine(&mut self) {
        if self.quarantine_budget == 0 {
            self.drain_all_quarantine();
            return;
        }
        let mut held: u64 = 0;
        for &h in &self.quarantine {
            if let Some(Extent::Free { size, .. }) = self.index.get(&h) {
                held = held.saturating_add(u64::from(*size));
            }
        }
        while held > self.quarantine_budget {
            let Some(handle) = self.quarantine.pop_front() else { break };
            if let Some(Extent::Free { size, quarantined }) = self.index.get(&handle).copied() {
                if quarantined {
                    self.index.insert(handle, Extent::Free { size, quarantined: false });
                }
                held = held.saturating_sub(u64::from(size));
                if size <= MAX_REUSE_SIZE && !self.reusable.contains(&handle) {
                    self.reusable.push(handle);
                }
            }
        }
    }

    fn drain_all_quarantine(&mut self) {
        for handle in self.quarantine.drain(..) {
            if let Some(Extent::Free { size, .. }) = self.index.get(&handle).copied() {
                self.index.insert(handle, Extent::Free { size, quarantined: false });
                if size <= MAX_REUSE_SIZE && !self.reusable.contains(&handle) {
                    self.reusable.push(handle);
                }
            }
        }
    }

    /// Free every block and return the bump pointer to [`FIRST_HANDLE`].
    ///
    /// Only sound when the embedder knows it holds no handles: there is no
    /// `RootSet` to check against, so the caller is asserting the whole heap is
    /// garbage. It exists for tearing a guest module down between runs, which is
    /// the one moment the answer is known.
    pub fn reset(&mut self) {
        self.bytes.clear();
        let fill = (self.base + FIRST_HANDLE) as usize;
        self.bytes.resize(fill, 0);
        self.next = FIRST_HANDLE;
        self.index.clear();
        self.reusable.clear();
        self.quarantine.clear();
        self.live_bytes = 0;
        self.objects = 0;
        self.arrays = 0;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A two-field class whose slots are `[ref, i32]` plus a `long` at slot 2.
    #[derive(Debug, Clone, Copy)]
    struct TwoFields;

    impl ClassLayout for TwoFields {
        fn class_count(&self) -> u32 {
            8
        }
        fn ref_bitmap(&self, class_ptr: u32) -> Option<&[u64]> {
            if class_ptr >= 8 {
                return None;
            }
            // slot 0 = ref, slot 1 = plain int, slot 2 = low half of a long.
            Some(&[0b0000_0001])
        }
        fn instance_slots(&self, class_ptr: u32) -> Option<u32> {
            if class_ptr >= 8 {
                None
            } else {
                Some(3)
            }
        }
    }

    fn heap() -> Heap {
        let mut h = Heap::with_ceiling(1 << 20);
        h.set_policy(CollectionPolicy::HostMarkSweep);
        h
    }

    // ------------------------------------------------------------ allocation

    #[test]
    fn first_allocation_is_handle_eight_and_null_is_reserved() {
        let mut h = Heap::new();
        assert_eq!(h.classify(NULL), Err(HeapError::NullHandle));
        let o = h.alloc_object(1, 2).unwrap();
        assert_eq!(o, FIRST_HANDLE);
        assert_eq!(h.classify(o), Ok(HandleKind::Object));
        assert_eq!(h.stats().live_bytes, u64::from(Heap::object_size(2)));
    }

    #[test]
    fn object_size_formula_matches_the_header() {
        // The guest recomputes sizes from headers; the host stores them. The two
        // must agree or a bounds check computed one way is wrong the other way.
        for slots in [0u32, 1, 2, 3, 7, 64, 1000] {
            let mut h = Heap::new();
            let o = h.alloc_object(3, slots).unwrap();
            assert_eq!(h.block_size(o).unwrap(), Heap::object_size(slots), "slots {slots}");
            assert_eq!(h.slots_of(o).unwrap(), slots);
        }
        for (len, width) in [(0u32, 1u32), (1, 4), (3, 2), (10, 8), (7, 1)] {
            let mut h = Heap::new();
            let a = h.alloc_array(width, len).unwrap();
            assert_eq!(h.block_size(a).unwrap(), Heap::array_size(len, width), "{len}x{width}");
        }
    }

    #[test]
    fn every_allocation_is_eight_byte_aligned() {
        let mut h = Heap::new();
        for width in [1u32, 2, 4, 8] {
            for count in 0..5u32 {
                let a = h.alloc_array(width, count).unwrap();
                assert_eq!(a as usize % ALIGN, 0, "array {count}x{width} at {a}");
                let o = h.alloc_object(1, count).unwrap();
                assert_eq!(o as usize % ALIGN, 0, "object {o}");
            }
        }
    }

    #[test]
    fn memory_grows_in_whole_pages_and_only_on_demand() {
        let mut h = Heap::with_ceiling(1 << 20);
        assert_eq!(h.stats().pages, 0, "nothing allocated, nothing grown");
        let size = Heap::object_size(0) as u64;
        assert_eq!(size, ALIGN as u64, "a slot-less object is header plus padding");
        h.alloc_object(1, 0).unwrap();
        assert_eq!(h.stats().pages, 1, "one small allocation still needs a page");

        // The bump pointer starts at FIRST_HANDLE, so `n` objects end at
        // `FIRST_HANDLE + n * size`. Fill to exactly one page, then step over.
        let fits = (PAGE_SIZE as u64 - FIRST_HANDLE as u64) / size;
        for _ in 1..fits {
            h.alloc_object(1, 0).unwrap();
        }
        assert_eq!(h.stats().pages, 1, "still exactly one page");
        assert!(h.bump() as u64 <= PAGE_SIZE as u64);
        h.alloc_object(1, 0).unwrap();
        assert_eq!(h.stats().pages, 2, "one more object forces memory.grow");
        assert_eq!(h.stats().resident_bytes % PAGE_SIZE as u64, 0);
    }

    #[test]
    fn ceiling_is_enforced_with_a_typed_error_not_a_panic() {
        let mut h = Heap::with_ceiling(4096);
        let mut err = None;
        for _ in 0..10_000 {
            match h.alloc_array(8, 1024) {
                Ok(_) => {}
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let err = err.expect("the ceiling must be hit");
        assert_eq!(err.kind(), "out_of_memory");
        assert!(h.stats().live_bytes <= h.ceiling());
    }

    #[test]
    fn class_pointer_cannot_use_the_kind_tag_bit() {
        let mut h = Heap::new();
        assert_eq!(h.alloc_object(KIND_ARRAY, 1).unwrap_err().kind(), "unknown_class");
        assert_eq!(h.alloc_object(u32::MAX, 1).unwrap_err().kind(), "unknown_class");
    }

    #[test]
    fn array_element_width_must_be_a_real_width() {
        let mut h = Heap::new();
        for width in [0u32, 3, 5, 6, 7, 9, 16, u32::MAX] {
            assert_eq!(h.alloc_array(width, 1).unwrap_err().kind(), "bad_element_width", "{width}");
        }
        for width in VALID_ELEM_WIDTHS {
            assert!(h.alloc_array(width, 1).is_ok(), "{width}");
        }
    }

    #[test]
    fn array_length_near_u32_max_is_an_error_not_a_wrap() {
        let mut h = Heap::new();
        let e = h.alloc_array(8, u32::MAX / 4 + 1).unwrap_err();
        assert_eq!(e.kind(), "size_overflow");
        // And the near-miss that does not overflow but cannot fit is OOM.
        let e = h.alloc_array(8, u32::MAX / 8).unwrap_err();
        assert!(matches!(e.kind(), "size_overflow" | "out_of_memory"), "{}", e.kind());
    }

    // ---------------------------------------------------------- field access

    #[test]
    fn fields_round_trip_including_wide_values() {
        let mut h = Heap::new();
        // slot 0 = ref, 1 = int, 2..3 = one long.
        let o = h.alloc_object(1, 4).unwrap();
        h.store_field(o, 0, 0xDEAD).unwrap();
        h.store_field(o, 1, 7).unwrap();
        h.store_field_wide(o, 2, 0x0123_4567_89AB_CDEF).unwrap();
        assert_eq!(h.load_field(o, 0).unwrap(), 0xDEAD);
        assert_eq!(h.load_field(o, 1).unwrap(), 7);
        assert_eq!(h.load_field_wide(o, 2).unwrap(), 0x0123_4567_89AB_CDEF);
        // The low half really is the low half: that is what makes a `long` at
        // slot 2 interchangeable with the two 4-byte loads codegen emits for a
        // split access.
        assert_eq!(h.load_field(o, 2).unwrap(), 0x89AB_CDEF);
        assert_eq!(h.load_field(o, 3).unwrap(), 0x0123_4567);
    }

    #[test]
    fn field_slot_past_the_end_is_a_typed_error() {
        let mut h = Heap::new();
        let o = h.alloc_object(1, 2).unwrap();
        for slot in [2u32, 3, 100, u32::MAX] {
            assert_eq!(
                h.load_field(o, slot).unwrap_err(),
                HeapError::FieldOutOfRange { handle: o, slot, slots: 2 },
                "slot {slot}"
            );
            assert_eq!(
                h.store_field(o, slot, 1).unwrap_err(),
                HeapError::FieldOutOfRange { handle: o, slot, slots: 2 }
            );
        }
    }

    #[test]
    fn a_wide_field_needs_both_of_its_slots() {
        let mut h = Heap::new();
        let o = h.alloc_object(1, 3).unwrap();
        // Slots 0 and 1 form a long; slots 2 and 3 do not both exist.
        assert!(h.load_field_wide(o, 0).is_ok());
        let e = h.load_field_wide(o, 2).unwrap_err();
        assert_eq!(e, HeapError::FieldOutOfRange { handle: o, slot: 2, slots: 3 });
        assert_eq!(h.load_field_wide(o, u32::MAX).unwrap_err().kind(), "size_overflow");
    }

    #[test]
    fn arrays_are_bounds_checked_on_both_width_and_index() {
        let mut h = Heap::new();
        let a = h.alloc_array(4, 3).unwrap();
        for i in 0..3 {
            h.array_write(a, i, 4, u64::from(0x100 + i)).unwrap();
        }
        assert_eq!(h.array_read(a, 0, 4).unwrap(), 0x100);
        assert_eq!(h.array_ref(a, 2).unwrap(), 0x102);
        assert_eq!(
            h.array_read(a, 3, 4).unwrap_err(),
            HeapError::IndexOutOfRange { handle: a, index: 3, length: 3 }
        );
        assert_eq!(
            h.array_read(a, 0, 8).unwrap_err(),
            HeapError::BadElementWidth { handle: a, width: 8 }
        );
        assert_eq!(h.array_read(a, u32::MAX, 4).unwrap_err().kind(), "index_out_of_range");
    }

    #[test]
    fn zero_length_arrays_reject_every_index() {
        let mut h = Heap::new();
        let a = h.alloc_array(8, 0).unwrap();
        assert_eq!(h.array_len(a).unwrap(), 0);
        assert_eq!(h.array_read(a, 0, 8).unwrap_err().kind(), "index_out_of_range");
        assert_eq!(h.array_write(a, 0, 8, 1).unwrap_err().kind(), "index_out_of_range");
    }

    #[test]
    fn object_and_array_operations_do_not_cross() {
        let mut h = Heap::new();
        let o = h.alloc_object(1, 1).unwrap();
        let a = h.alloc_array(4, 4).unwrap();
        assert_eq!(h.load_field(a, 0).unwrap_err().kind(), "wrong_kind");
        assert_eq!(h.array_len(o).unwrap_err().kind(), "wrong_kind");
        assert_eq!(h.class_of(a).unwrap_err().kind(), "wrong_kind");
        assert_eq!(h.elem_width_of(o).unwrap_err().kind(), "wrong_kind");
    }

    // ------------------------------------------------------------- fuzzing

    /// xorshift64, so a failure is reproducible from the printed seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 {
                0
            } else {
                self.next() % n
            }
        }
        fn u32(&mut self) -> u32 {
            self.next() as u32
        }
    }

    /// Every one of these returns either `Ok` or a typed error. The assertion
    /// that matters is that the test completes: a panic, an arithmetic overflow
    /// or an index-out-of-bounds would abort it.
    fn poke(h: &mut Heap, h0: u32, a: u32, b: u32, c: u32) {
        let _ = h.classify(h0);
        let _ = h.block_size(h0);
        let _ = h.class_of(h0);
        let _ = h.slots_of(h0);
        let _ = h.elem_width_of(h0);
        let _ = h.array_len(h0);
        let _ = h.load_field(h0, a);
        let _ = h.store_field(h0, a, b);
        let _ = h.load_field_wide(h0, a);
        let _ = h.store_field_wide(h0, a, u64::from(b) << 32 | u64::from(c));
        let _ = h.array_read(h0, a, b);
        let _ = h.array_write(h0, a, b, u64::from(c));
        let _ = h.array_ref(h0, a);
        let _ = h.set_array_ref(h0, a, b);
    }

    #[test]
    fn fuzz_adversarial_handles_slots_and_lengths_never_panic() {
        for seed in [0x1234_5678_9ABC_DEF0u64, 1, 0xFFFF_FFFF_FFFF_FFFF, 0xDEAD_BEEF] {
            let mut rng = Rng(seed);
            let mut h = Heap::with_ceiling(1 << 18);
            h.set_policy(CollectionPolicy::HostMarkSweep);
            let mut live: Vec<u32> = Vec::new();
            for step in 0..20_000u32 {
                // Bias towards real handles so the interesting paths get hit.
                let handle = if live.is_empty() || rng.below(3) == 0 {
                    match rng.u32() {
                        0 => NULL,
                        1 => 1,
                        2 => 7,
                        3 => u32::MAX,
                        4 => u32::MAX - 1,
                        n => n,
                    }
                } else {
                    let i = rng.below(live.len() as u64) as usize;
                    live[i]
                };
                let slot = match rng.below(4) {
                    0 => rng.u32(),
                    1 => u32::MAX,
                    2 => rng.below(8) as u32,
                    _ => 0,
                };
                let width = match rng.below(4) {
                    0 => rng.u32(),
                    1 => [0u32, 3, 5, 7][rng.below(4) as usize],
                    2 => VALID_ELEM_WIDTHS[rng.below(4) as usize],
                    _ => 4,
                };
                poke(&mut h, handle, slot, width, rng.u32());

                // Every so often, allocate something adversarial.
                if step % 37 == 0 {
                    let len = match rng.below(4) {
                        0 => rng.u32(),
                        1 => u32::MAX - rng.below(64) as u32,
                        2 => rng.below(8) as u32,
                        _ => rng.below(1024) as u32,
                    };
                    let w = [1u32, 2, 4, 8, 3, 0][rng.below(6) as usize];
                    if let Ok(n) = h.alloc_array(w, len) {
                        live.push(n);
                    }
                    if let Ok(n) = h.alloc_object(rng.below(4) as u32, len) {
                        live.push(n);
                    }
                }
                // And occasionally collect, so stale-handle paths are exercised.
                if step % 211 == 0 && !live.is_empty() {
                    let keep = &live[..live.len().min(4)];
                    let roots = RootSet::exact(keep.iter().copied());
                    let _ = h.collect(&roots, &TwoFields);
                }
            }
            if !live.is_empty() {
                let roots = RootSet::exact(live.iter().take(2).copied());
                let _ = h.collect(&roots, &TwoFields);
            }
        }
    }

    #[test]
    fn fuzz_hostile_type_lists_never_overflow_a_size() {
        // A `type_list`-driven `new-array` where the size register is arbitrary.
        // This is the shape of the real attack: the length is not in the file,
        // it is computed at run time.
        let mut rng = Rng(0xC0FF_EE00_1234_5678);
        let mut h = Heap::with_ceiling(1 << 20);
        for _ in 0..50_000 {
            let width = [1u32, 2, 4, 8][rng.below(4) as usize];
            // The first two are the exactly-divisible case and one past it,
            // computed without overflowing in the test itself.
            let len = match rng.below(5) {
                0 => rng.u32(),
                1 => rng.u32(),
                2 => u32::MAX / width,
                3 => u32::MAX / width + if width == 1 { 0 } else { 1 },
                _ => rng.below(4096) as u32,
            };
            match h.alloc_array(width, len) {
                Ok(handle) => {
                    assert_eq!(handle & (ALIGN as u32 - 1), 0);
                    // Reading the whole array must stay in bounds.
                    if len <= 1024 {
                        for i in 0..len {
                            let _ = h.array_read(handle, i, width);
                        }
                    }
                }
                Err(e) => {
                    let k = e.kind();
                    assert!(
                        k == "size_overflow" || k == "out_of_memory" || k == "bad_element_width",
                        "unexpected error kind {k}"
                    );
                }
            }
        }
        assert!(h.stats().live_bytes <= h.ceiling());
    }

    #[test]
    fn fuzz_interior_handles_are_rejected_not_resolved() {
        // A handle one byte into an object must not classify as anything.
        let mut h = Heap::new();
        let o = h.alloc_object(1, 4).unwrap();
        for delta in 1..8u32 {
            let inner = o + delta;
            let e = h.classify(inner).unwrap_err();
            assert!(matches!(e, HeapError::InvalidHandle { .. }), "delta {delta}: {e}");
        }
    }

    #[test]
    fn a_handle_past_the_bump_pointer_is_invalid() {
        let mut h = Heap::new();
        let o = h.alloc_object(1, 0).unwrap();
        let past = o + Heap::object_size(0);
        assert_eq!(h.classify(past).unwrap_err(), HeapError::InvalidHandle { handle: past });
        assert_eq!(h.classify(u32::MAX).unwrap_err(), HeapError::InvalidHandle { handle: u32::MAX });
    }

    // ------------------------------------------------------------ collection

    #[test]
    fn collection_is_refused_under_the_default_policy() {
        let mut h = Heap::new();
        assert_eq!(h.policy(), CollectionPolicy::None);
        let o = h.alloc_object(1, 1).unwrap();
        let roots = RootSet::exact([o]);
        assert_eq!(h.collect(&roots, &TwoFields).unwrap_err(), HeapError::CollectionDisabled);
        assert_eq!(h.policy().as_str(), "none");
    }

    #[test]
    fn a_collection_cycle_preserves_identity_for_held_handles() {
        let mut h = heap();
        // holder -> [target, target]  and an isolated cycle a <-> b.
        let holder = h.alloc_object(1, 2).unwrap();
        let target = h.alloc_object(1, 1).unwrap();
        h.store_field(target, 0, 12345).unwrap();
        h.store_field(holder, 0, target).unwrap();
        h.store_field(holder, 1, target).unwrap();
        let a = h.alloc_object(1, 1).unwrap();
        let b = h.alloc_object(1, 1).unwrap();
        h.store_field(a, 0, b).unwrap();
        h.store_field(b, 0, a).unwrap();
        // Pure garbage.
        for _ in 0..32 {
            let g = h.alloc_object(1, 2).unwrap();
            h.store_field(g, 0, 0xEEEE).unwrap();
        }
        let before = h.stats();
        assert_eq!(h.classify(holder), Ok(HandleKind::Object));

        let roots = RootSet::exact([holder]);
        let report = h.collect(&roots, &TwoFields).unwrap();
        assert!(report.freed_anything(), "garbage should have been reclaimed");
        assert_eq!(report.roots, 1);

        // Identity: the same handles, still readable, same values.
        assert_eq!(h.classify(holder), Ok(HandleKind::Object));
        assert_eq!(h.classify(target), Ok(HandleKind::Object));
        assert_eq!(h.load_field(target, 0).unwrap(), 12345);
        assert_eq!(h.load_field(holder, 0).unwrap(), target);
        assert_eq!(h.load_field(holder, 1).unwrap(), target);
        // The unreachable cycle went despite being cyclic: mark-sweep, not RC.
        assert!(h.classify(a).unwrap_err().is_use_after_free());
        assert!(h.classify(b).unwrap_err().is_use_after_free());
        assert!(h.stats().live_bytes < before.live_bytes);
        assert_eq!(report.freed, 34, "the 32 garbage objects plus the a<->b pair");
        assert_eq!(report.live, 2, "holder and target");
    }

    #[test]
    fn quarantine_makes_a_freed_handle_detectable() {
        let mut h = heap();
        h.quarantine_bytes(1 << 20);
        let keep = h.alloc_object(1, 1).unwrap();
        let drop_me = h.alloc_object(1, 1).unwrap();
        h.store_field(drop_me, 0, 99).unwrap();
        let report = h.collect(&RootSet::exact([keep]), &TwoFields).unwrap();
        assert_eq!(report.freed, 1);
        assert!(report.quarantined_blocks >= 1);
        let e = h.classify(drop_me).unwrap_err();
        assert!(e.is_use_after_free(), "expected a use-after-free, got {e}");
        assert_eq!(h.load_field(drop_me, 0).unwrap_err().kind(), "freed_handle");
    }

    #[test]
    fn a_conservative_root_scan_keeps_a_shadowed_object_alive() {
        // Models a codegen-maintained shadow stack: a region of linear memory
        // holding live handles. The object is only mentioned there.
        let mut h = heap();
        let obj = h.alloc_object(1, 1).unwrap();
        let stack = h.alloc_array(4, 8).unwrap();
        h.set_array_ref(stack, 0, obj).unwrap();
        // The shadow stack itself is a root, so the object survives transitively.
        let roots = RootSet::conservative([stack], [(stack, 32)]);
        let report = h.collect(&roots, &TwoFields).unwrap();
        assert_eq!(h.classify(obj), Ok(HandleKind::Object));
        assert_eq!(report.scan_ranges, 1);
    }

    #[test]
    fn an_untraceable_class_is_retained_not_freed() {
        // `TwoFields` has no bitmap for a `class_ptr` of 8 or above, so the
        // collector cannot see what such an object references. Freeing it would
        // be unsound, so it is kept even though nothing points at it. This is
        // the conservative direction, and it is the one that has to be chosen
        // when the class table is incomplete.
        let mut h = heap();
        let keep = h.alloc_object(1, 1).unwrap();
        let opaque = h.alloc_object(9, 1).unwrap();
        let dead = h.alloc_object(1, 1).unwrap();
        let report = h.collect(&RootSet::exact([keep, opaque]), &TwoFields).unwrap();
        assert_eq!(h.classify(opaque), Ok(HandleKind::Object), "untraceable must be kept");
        assert_eq!(h.classify(keep), Ok(HandleKind::Object));
        // `dead` is a known class with no references, so it does go.
        assert_eq!(report.freed, 1, "only the plain dead object");
        assert!(h.classify(dead).unwrap_err().is_use_after_free());
    }

    #[test]
    fn a_known_class_object_is_freed_only_when_unreachable() {
        let mut h = heap();
        let r = h.alloc_object(1, 0).unwrap();
        let d = h.alloc_object(1, 0).unwrap();
        let report = h.collect(&RootSet::exact([r]), &TwoFields).unwrap();
        assert_eq!(report.freed, 1);
        assert!(h.classify(d).unwrap_err().is_use_after_free());
    }

    #[test]
    fn deep_object_chains_do_not_overflow_the_host_stack() {
        // 20k linked nodes. A recursive tracer would blow up here.
        let mut h = heap();
        let head = h.alloc_object(1, 1).unwrap();
        let mut prev = head;
        for _ in 1..20_000u32 {
            let next = h.alloc_object(1, 1).unwrap();
            h.store_field(prev, 0, next).unwrap();
            prev = next;
        }
        h.store_field(prev, 0, 0xFFFF_FFFF).unwrap(); // not a handle
        let roots = RootSet::exact([head]);
        let report = h.collect(&roots, &TwoFields).unwrap();
        assert_eq!(report.live, 20_000);
        assert_eq!(h.classify(prev), Ok(HandleKind::Object));
    }

    #[test]
    fn a_freed_block_is_eventually_reused_and_then_stops_being_freed() {
        let mut h = heap();
        h.quarantine_bytes(0);
        let root = h.alloc_object(1, 1).unwrap();
        let victim = h.alloc_object(1, 4).unwrap();
        h.collect(&RootSet::exact([root]), &TwoFields).unwrap();
        // With no quarantine the block goes straight back on the reuse list.
        let again = h.alloc_object(1, 4).unwrap();
        assert_eq!(h.classify(again), Ok(HandleKind::Object));
        assert_eq!(again, victim, "the block should have been reused in place");
    }

    #[test]
    fn reset_returns_the_heap_to_its_initial_state() {
        let mut h = heap();
        let a = h.alloc_object(1, 4).unwrap();
        h.store_field(a, 0, 5).unwrap();
        h.reset();
        assert_eq!(h.bump(), FIRST_HANDLE);
        assert_eq!(h.stats().live_bytes, 0);
        assert_eq!(h.classify(a).unwrap_err().kind(), "invalid_handle");
        assert!(h.stats().free_blocks == 0);
    }

    // ------------------------------------------------------------- placement

    #[test]
    fn a_nonzero_base_shifts_every_address() {
        let mut h = Heap::new().at(4096);
        assert_eq!(h.base(), 4096);
        let o = h.alloc_object(1, 1).unwrap();
        assert_eq!(h.load_field(o, 0).unwrap(), 0);
        h.store_field(o, 0, 42).unwrap();
        assert_eq!(h.bytes()[4096 + 8 + 8], 42);
    }

    #[test]
    fn a_misaligned_base_is_ignored_rather_than_panicking() {
        let h = Heap::new().at(4097);
        assert_eq!(h.base(), 0);
        let h = Heap::new().at(4);
        assert_eq!(h.base(), 0);
    }

    #[test]
    fn reset_keeps_a_nonzero_base() {
        let mut h = Heap::new().at(1024);
        h.alloc_object(1, 1).unwrap();
        h.reset();
        assert_eq!(h.base(), 1024);
        assert_eq!(h.bump(), FIRST_HANDLE);
    }

    #[test]
    fn no_references_layout_is_honest_about_traceability() {
        let mut h = heap();
        let o = h.alloc_object(1, 1).unwrap();
        let roots = RootSet::exact([o]);
        h.collect(&roots, &NoReferences).unwrap();
        assert_eq!(h.classify(o), Ok(HandleKind::Object));
        assert_eq!(NoReferences.class_count(), 0);
    }

    #[test]
    fn error_kinds_are_distinct_and_stable() {
        let mut h = Heap::new();
        let o = h.alloc_object(1, 1).unwrap();
        let cases: Vec<HeapError> = vec![
            HeapError::NullHandle,
            HeapError::InvalidHandle { handle: 99 },
            HeapError::Freed { handle: 98 },
            HeapError::WrongKind { handle: 0, wanted: HandleKind::Object, found: HandleKind::Array },
            HeapError::FieldOutOfRange { handle: 0, slot: 0, slots: 0 },
            HeapError::IndexOutOfRange { handle: 0, index: 0, length: 0 },
            HeapError::OutOfBlock { handle: 0, rel: 0, len: 0, size: 0 },
            HeapError::BadElementWidth { handle: 0, width: 3 },
            HeapError::SizeOverflow { what: "array" },
            HeapError::OutOfMemory { requested: 0, ceiling: 0 },
            HeapError::CollectionDisabled,
            HeapError::UnknownClass { class_ptr: 0 },
            HeapError::LayoutKindMismatch { class_ptr: 0 },
        ];
        let mut seen = BTreeSet::new();
        for e in &cases {
            assert!(seen.insert(e.kind()), "duplicate kind {}", e.kind());
            // Display must not panic and must mention something.
            let s = e.to_string();
            assert!(!s.is_empty());
        }
        assert_eq!(seen.len(), cases.len());
        let _ = h.class_of(o).unwrap();
    }
}
