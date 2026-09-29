//! Ordered loading of N independent DEX containers.
//!
//! # What multidex actually is
//!
//! An APK with more than 65 536 methods ships `classes.dex`, `classes2.dex`,
//! …, `classesN.dex`. These are **not** segments of one file. Each is a
//! complete, self-contained DEX container with its own five id pools, its own
//! `header_item`, its own `map_list` and its own checksums. A `method_id`
//! index is an index into *that file's* `method_ids`, so:
//!
//! ```text
//! method_id[0] in classes.dex   == Landroid/app/ActionBar;.setDisplayHomeAsUpEnabled
//! method_id[0] in classes2.dex  == Lj$/util/Map$-CC;.$default$compute
//! ```
//!
//! (That pair is real, from the `sayura` fixture in `tests/fixtures/`, and
//! `tests/load_order.rs::pool_indices_are_per_file` asserts it.) Concatenating
//! the files, or carrying an index from one into the other, does not produce a
//! subtly wrong answer — it produces an answer about a *different method*.
//!
//! So this module does not merge. It **indexes**: it holds N readers and
//! resolves every reference against all of them, which is also what makes the
//! classloader-supersede boundary in `shim` work unchanged (see
//! [`crate::resolver`] and `tests/shim_supersede.rs`).
//!
//! # Load order is explicit, validated and recorded
//!
//! Three properties, each of which is a real behaviour an app can observe:
//!
//! 1. **Ordinal order, never lexicographic.** `classes10.dex` is load-order
//!    10 and loads *after* `classes2.dex`. Nine APKs in the F-Droid corpus
//!    store these entries in ZIP order (`classes.dex`, `classes10.dex`,
//!    `classes2.dex`, …), so a loader that trusted directory iteration would
//!    get those nine wrong. This is why [`parse_ordinal`] exists rather than
//!    `sort()` on the name.
//! 2. **First-wins on duplicates**, with a warning, never silent last-wins. See
//!    [`MultidexWarning::DuplicateClass`].
//! 3. **The order is recorded**, in [`LoadRecord`], because it is part of the
//!    contract and an analyst reading a recording has to be able to recover it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use dexcore::model::access;
use dexcore::reader::DexReader;
use serde::{Deserialize, Serialize};

use crate::multidex::error::{MultidexError, Result};

/// One file's position in load order: `0` is `classes.dex`.
///
/// This is a newtype rather than a bare `usize` because every error and every
/// warning in this module has to say *which file*, and a `usize` in a struct
/// field is exactly the thing a future refactor turns into a loop index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FileId(pub usize);

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// A `classes*.dex` entry offered to the loader: its name in the container and
/// its bytes.
#[derive(Debug, Clone)]
pub struct DexSource {
    /// The entry name, e.g. `classes2.dex`.
    pub name: String,
    /// The file's bytes.
    pub bytes: Arc<Vec<u8>>,
}

impl DexSource {
    /// A source from owned bytes.
    pub fn new(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> DexSource {
        DexSource {
            name: name.into(),
            bytes: Arc::new(bytes.into()),
        }
    }
}

/// The load-order ordinal of a `classes*.dex` entry name, or `None` if a
/// canonical Android loader would not load it.
///
/// `classes.dex` is ordinal 1 and `classes<N>.dex` is ordinal `N` for `N >= 2`.
/// The numeric parse is the point: `classes10.dex` is 10, and any
/// implementation that compares the *name* puts it second.
pub fn parse_ordinal(name: &str) -> Option<u32> {
    if name == "classes.dex" {
        return Some(1);
    }
    let rest = name.strip_prefix("classes")?.strip_suffix(".dex")?;
    // `classes.dex` is handled above; an empty suffix is not a valid number, and
    // a leading zero would make `classes03.dex` and `classes3.dex` collide on
    // an ordinal that Android itself treats as distinct names.
    if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if rest.len() > 1 && rest.starts_with('0') {
        return None;
    }
    rest.parse::<u32>().ok().filter(|n| *n >= 2)
}

/// A method's identity, independent of which file declared it.
///
/// `(class, name, parameter descriptors)` is the JVM/Dalvik method identity, so
/// it is the right key for a *cross-file* index: two files that both define
/// `Ljava/util/List;.size()I` agree about it even though their `method_id`
/// indices are unrelated. Return type is deliberately excluded — it is not part
/// of the identity, and Java overload resolution agrees.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MethodSig {
    /// Descriptor of the declaring class.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Parameter descriptors, in order.
    pub parameters: Vec<String>,
}

impl MethodSig {
    /// The identity form, e.g. `Lcom/x/Y;.z(Ljava/lang/String;I)`.
    ///
    /// No return type: it is not part of method identity, and printing one
    /// would suggest it is checked when it is not.
    pub fn signature(&self) -> String {
        self.to_string()
    }
}

impl std::fmt::Display for MethodSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}({})",
            self.class,
            self.name,
            self.parameters.join("")
        )
    }
}

/// A field's identity, independent of file: `(class, name, type)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FieldSig {
    pub class: String,
    pub name: String,
    pub type_descriptor: String,
}

impl std::fmt::Display for FieldSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}:{}", self.class, self.name, self.type_descriptor)
    }
}

/// One `class_def_item` that declares a descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassSite {
    /// The file this definition is in.
    pub file: FileId,
    /// The file's entry name.
    pub name: String,
    /// Index into that file's `class_defs`.
    pub class_def_idx: u32,
    /// `access_flags` as declared here.
    pub access_flags: u32,
    /// Superclass descriptor, empty for a root class.
    pub superclass: String,
    /// Declared interfaces.
    pub interfaces: Vec<String>,
    /// Whether this site carries a `class_data_item`.
    pub has_class_data: bool,
}

/// Where one method is defined: a `class_data_item` entry in a `class_def_item`
/// in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodDefSite {
    /// The file holding the defining `class_data_item`.
    pub file: FileId,
    /// The file's entry name.
    pub name: String,
    /// Index into that file's `class_defs`.
    pub class_def_idx: u32,
    /// The method's `method_id` index **in that file**.
    pub method_idx: u32,
    /// `access_flags` as declared here.
    pub access_flags: u32,
    /// Offset of the `code_item`, or 0 for abstract/native.
    pub code_off: u32,
}

impl MethodDefSite {
    /// Whether this site has a body at all.
    pub fn has_code(&self) -> bool {
        self.code_off != 0
    }

    /// Whether the declaration is abstract or native, i.e. bodyless by rule.
    pub fn is_declaration_only(&self) -> bool {
        self.access_flags & (access::ACC_ABSTRACT | access::ACC_NATIVE) != 0
    }
}

/// A class after merging every file that declared it.
#[derive(Debug, Clone, Serialize)]
pub struct MergedClass {
    /// Descriptor, e.g. `Lcom/x/Y;`.
    pub descriptor: String,
    /// The site that supplied the class-level header. Under first-wins this is
    /// the earliest file in load order, and it is recorded rather than inferred
    /// because a split class's superclass can disagree across files.
    pub primary: ClassSite,
    /// Every site that declared this descriptor, in load order.
    pub sites: Vec<ClassSite>,
    /// Methods, keyed by identity, with **every** defining site in load order.
    ///
    /// The value is a list rather than a single winner on purpose: whether one
    /// site wins or the method is [`Ambiguous`](crate::resolver::MethodResolution)
    /// is a policy decision that belongs to the resolver, and a loader that
    /// pre-resolved it would make that policy unobservable and untestable.
    pub methods: BTreeMap<MethodSig, Vec<MethodDefSite>>,
    /// Fields, keyed by identity, with every declaring site in load order.
    pub fields: BTreeMap<FieldSig, Vec<FieldDefSite>>,
    /// Per-site method sets, in load order.
    ///
    /// Kept separately from [`MergedClass::methods`] because the *relationship*
    /// between the sets is what distinguishes a split class from a duplicated
    /// one, and once they are merged into one union map that relationship is
    /// gone. Storing the union alone would make "split" and "duplicated" the
    /// same observation, which is precisely the distinction the resolver has to
    /// be able to make.
    pub site_method_sets: Vec<(FileId, BTreeSet<MethodSig>)>,
    /// Superclass descriptor, empty for a root class.
    pub superclass: String,
    /// Whether any site carries `static_values_item`.
    ///
    /// This is load-bearing and easy to lose. `static_values_item` holds every
    /// compile-time constant initialiser — a `static final int` or `static
    /// final String`. A loader that merged `class_data_item` but not
    /// `static_values_item` would read `0`/`null` for every such field and keep
    /// running, so the fact is surfaced in the merged view rather than left in
    /// a per-site detail nobody reads.
    pub has_static_values: bool,
}

/// One `encoded_field` declaring a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldDefSite {
    /// The file holding the defining `class_data_item`.
    pub file: FileId,
    /// Index into that file's `class_defs`.
    pub class_def_idx: u32,
    /// The field's `field_id` index **in that file**.
    pub field_idx: u32,
    /// `access_flags` as declared here.
    pub access_flags: u32,
}

/// One file, as loaded.
#[derive(Debug, Clone)]
pub struct LoadedFile {
    /// Position in load order.
    pub id: FileId,
    /// The load-order ordinal parsed from the name (1 == `classes.dex`).
    pub ordinal: u32,
    /// The entry name.
    pub name: String,
    /// The file's bytes.
    pub bytes: Arc<Vec<u8>>,
    /// Pool sizes, recorded because "how big is file 2's method pool" is the
    /// question every multidex bug reduces to.
    pub strings: u32,
    pub types: u32,
    pub protos: u32,
    pub fields: u32,
    pub methods: u32,
    pub class_defs: u32,
    /// The DEX header's own SHA-1 over the file, hex. Used as the file's
    /// content identity in the record; it is a hash the format already carries,
    /// so recording it costs no extra pass and no extra dependency.
    pub dex_sha1: String,
}

/// One entry in the recorded load order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadOrderEntry {
    /// Position in load order, from 0.
    pub file: FileId,
    /// The ordinal parsed from the name. This is the sort key, and it is
    /// recorded separately from `file` so a reader can see that ordinal 10
    /// really did load tenth.
    pub ordinal: u32,
    /// The entry name.
    pub name: String,
    /// File size in bytes.
    pub bytes: usize,
    /// `class_defs_size` in that file.
    pub class_defs: u32,
    /// `method_ids_size` in that file. Per-file: it is not the sum over the APK.
    pub method_ids: u32,
    /// The header SHA-1, hex.
    pub sha1: String,
}

/// Which part of a class header two files disagreed about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HeaderField {
    /// The superclass descriptor.
    Superclass,
    /// `access_flags`.
    AccessFlags,
    /// The declared interface list.
    Interfaces,
}

impl HeaderField {
    /// A stable tag for recordings and assertions.
    pub fn as_str(self) -> &'static str {
        match self {
            HeaderField::Superclass => "superclass",
            HeaderField::AccessFlags => "access_flags",
            HeaderField::Interfaces => "interfaces",
        }
    }
}

impl std::fmt::Display for HeaderField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Something the loader found that a reader of a recording needs to know about.
///
/// Each variant is a place where the naive answers — concatenate, last-wins,
/// trust the directory order — are wrong, and the fact is therefore surfaced
/// rather than resolved silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MultidexWarning {
    /// The same descriptor is declared in more than one file. Android's rule is
    /// first-wins with a warning; last-wins is a divergence an app can notice.
    DuplicateClass {
        /// The contended descriptor.
        descriptor: String,
        /// The site that won (earliest in load order).
        winner: FileId,
        /// The entry name of the winning file.
        winner_name: String,
        /// The sites that lost, in load order.
        losers: Vec<FileId>,
        /// The entry names of the losing files, parallel to `losers`.
        ///
        /// Carried because a recording reader has no way to map `#1` back to
        /// `classes2.dex` without re-deriving the load order, and a warning
        /// that cannot be acted on is a warning that gets ignored.
        loser_names: Vec<String>,
    },

    /// Two files declare the same class with **different class-level headers** —
    /// a different superclass, access flags or interface list.
    ///
    /// This is not cosmetic: the superclass determines which methods the class
    /// inherits, so a split class with two superclasses has no single correct
    /// answer. The loader keeps the first and records the disagreement.
    DivergentClassHeader {
        /// The descriptor.
        descriptor: String,
        /// The site whose header is in effect.
        primary: FileId,
        /// The site that disagreed.
        other: FileId,
        /// What disagreed: `superclass`, `access_flags` or `interfaces`.
        field: HeaderField,
        /// The primary's value, as a string.
        primary_value: String,
        /// The other site's value, as a string.
        other_value: String,
    },

    /// Two files define the same method signature. Whether this is harmless or
    /// [`Ambiguous`](crate::resolver::MethodResolution) depends on whether the
    /// definitions are equivalent, which the resolver decides; the loader only
    /// records that more than one site exists.
    DuplicateMethod {
        /// The method identity.
        signature: MethodSig,
        /// The earliest site.
        winner: FileId,
        /// Entry name of the winning file.
        winner_name: String,
        /// Later sites, in load order.
        others: Vec<FileId>,
        /// Entry names of the later files, parallel to `others`.
        other_names: Vec<String>,
    },

    /// A class's superclass is defined only in a **later** file.
    ///
    /// Within one DEX, `class_defs` must be ordered superclass-before-subclass.
    /// Across files that invariant cannot hold by construction, because the
    /// split is by method count, not by hierarchy. It is legal and common — the
    /// `sayura` fixture's `classes.dex` calls into `classes2.dex` — but it is
    /// the reason a loader cannot resolve lazily in one forward pass.
    SuperclassInLaterFile {
        /// The subclass.
        descriptor: String,
        /// The superclass.
        superclass: String,
        /// File holding the subclass.
        subclass_file: FileId,
        /// File holding the superclass.
        superclass_file: FileId,
    },

    /// A class's superclass is not defined in any loaded file. Expected for
    /// platform classes (`Ljava/lang/Object;`, framework types) and a genuine
    /// defect for anything else, so the descriptor is recorded either way.
    UnresolvedSuperclass {
        /// The subclass.
        descriptor: String,
        /// The missing superclass.
        superclass: String,
    },
}

impl MultidexWarning {
    /// A stable tag, for recordings and for assertions.
    pub fn kind(&self) -> &'static str {
        match self {
            MultidexWarning::DuplicateClass { .. } => "duplicate_class",
            MultidexWarning::DivergentClassHeader { .. } => "divergent_class_header",
            MultidexWarning::DuplicateMethod { .. } => "duplicate_method",
            MultidexWarning::SuperclassInLaterFile { .. } => "superclass_in_later_file",
            MultidexWarning::UnresolvedSuperclass { .. } => "unresolved_superclass",
        }
    }

    /// A one-line human-readable summary.
    pub fn summary(&self) -> String {
        match self {
            MultidexWarning::DuplicateClass {
                descriptor,
                winner_name,
                loser_names,
                ..
            } => {
                format!(
                    "{descriptor} also declared in {}; first-wins kept {winner_name}",
                    loser_names.join(", ")
                )
            }
            MultidexWarning::DivergentClassHeader {
                descriptor,
                field,
                primary,
                other,
                ..
            } => {
                format!("{descriptor} has a different {field} in {other} than in {primary}")
            }
            MultidexWarning::DuplicateMethod {
                signature,
                winner_name,
                other_names,
                ..
            } => {
                let others = if other_names.is_empty() {
                    "<unknown>".to_string()
                } else {
                    other_names.join(", ")
                };
                format!("{signature} also defined in {others}; first-wins kept {winner_name}")
            }
            MultidexWarning::SuperclassInLaterFile {
                descriptor,
                superclass,
                subclass_file,
                superclass_file,
            } => {
                format!("{descriptor} in {subclass_file} extends {superclass}, defined only later in {superclass_file}")
            }
            MultidexWarning::UnresolvedSuperclass {
                descriptor,
                superclass,
            } => {
                format!("{descriptor} extends {superclass}, which no loaded file defines")
            }
        }
    }

    /// The shim's diagnostic-pattern slot for this warning.
    ///
    /// Matches the shape of a `SIGNAL_PAT.*` token so the event lands in the
    /// same `probes` array as the shim's other structural observations.
    pub fn probe_pattern(&self) -> &'static str {
        match self {
            MultidexWarning::DuplicateClass { .. } => "MULTIDEX.DUPLICATE_CLASS",
            MultidexWarning::DivergentClassHeader { .. } => "MULTIDEX.DIVERGENT_CLASS_HEADER",
            MultidexWarning::DuplicateMethod { .. } => "MULTIDEX.DUPLICATE_METHOD",
            MultidexWarning::SuperclassInLaterFile { .. } => "MULTIDEX.SUPERCLASS_IN_LATER_FILE",
            MultidexWarning::UnresolvedSuperclass { .. } => "MULTIDEX.UNRESOLVED_SUPERCLASS",
        }
    }

    /// This warning as a shim `SubstrateEvent`, so the duplicate/supersede
    /// facts reach the recording rather than living only in a log.
    ///
    /// It goes into `Group::Probes` with `Source::ClassLoader` rather than
    /// `Group::Classes` on purpose. `shim::event::Detail::Classes` carries
    /// `{ descriptor, resolution, from_package }` and **no field for which of
    /// N files** answered — so emitting a duplicate as a `Classes` event would
    /// record "resolved to app_dex" and silently drop the load-order fact that
    /// is the entire observation. `Probes` has a free-form `detail` string,
    /// which preserves both file identities. Widening `Detail` to carry a
    /// per-file resolution is a change to `shim/`, which this component does not
    /// own; the lossy alternative was rejected instead, and the gap is
    /// recorded here rather than papered over.
    pub fn to_shim_event(&self, seq: u64, t_mono_ms: u64) -> shim::event::SubstrateEvent {
        shim::event::SubstrateEvent {
            seq,
            t_mono_ms,
            group: shim::event::Group::Probes,
            source: shim::event::Source::ClassLoader,
            // A structural fact the substrate observed directly, not something
            // inferred from a symptom.
            tier: shim::event::Tier::T0Direct,
            // A structural loader observation is not an assumption probe, so it
            // belongs to no assumption ID — the same reasoning the shim uses for
            // a class that resolved to itself.
            assumption: None,
            detail: shim::event::Detail::Probes {
                pattern: self.probe_pattern(),
                detail: self.summary(),
                axis: None,
            },
        }
    }
}

/// The recorded outcome of a load: the order, and everything noteworthy about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadRecord {
    /// The APK's package name, when the caller knows it. Carried so a recording
    /// can attribute a multidex finding to a package without a second lookup.
    pub package: Option<String>,
    /// Load order, ascending by ordinal.
    pub order: Vec<LoadOrderEntry>,
    /// Every warning, in the order it was found (file order, then class order,
    /// then within a class). Deterministic, so two runs of the same APK produce
    /// byte-identical records.
    pub warnings: Vec<MultidexWarning>,
}

impl LoadRecord {
    /// Warnings of one kind, for a test or an analyst filtering on one concern.
    pub fn warnings_of(&self, kind: &str) -> Vec<&MultidexWarning> {
        self.warnings.iter().filter(|w| w.kind() == kind).collect()
    }
}

/// The class space produced by a load: every class, merged across files.
#[derive(Debug, Clone, Default)]
pub struct ClassSpace {
    classes: BTreeMap<String, MergedClass>,
}

impl ClassSpace {
    /// Number of distinct descriptors.
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Whether the space is empty.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Every descriptor, sorted.
    pub fn descriptors(&self) -> impl Iterator<Item = &str> {
        self.classes.keys().map(String::as_str)
    }

    /// The merged class for a descriptor.
    pub fn get(&self, descriptor: &str) -> Option<&MergedClass> {
        self.classes.get(descriptor)
    }

    /// Whether a descriptor is defined anywhere.
    pub fn contains(&self, descriptor: &str) -> bool {
        self.classes.contains_key(descriptor)
    }
}

/// An ordered set of loaded DEX files and the class space they produce.
///
/// The loader holds bytes, not readers: `DexReader` borrows, and a struct that
/// owns its bytes *and* a reader over them would have to be self-referential.
/// Instead the load resolves everything it needs up front into owned,
/// file-independent keys ([`MethodSig`], [`FieldSig`], descriptors), and the
/// resolver re-opens a reader only for the rare operation that genuinely needs
/// raw bytes — a `code_item` read, and the code comparison that decides
/// ambiguity. `DexReader::open` validates the header and computes no checksum,
/// so that is cheap.
#[derive(Debug)]
pub struct MultidexLoader {
    package: Option<String>,
    files: Vec<LoadedFile>,
    space: ClassSpace,
    record: LoadRecord,
}

impl MultidexLoader {
    /// Load N DEX sources in ordinal order.
    ///
    /// Validation is strict and happens before anything is indexed: a
    /// non-canonical name, a missing `classes.dex`, a contested ordinal or a gap
    /// in the ordinals are all refusals. Each of them would otherwise change
    /// load order in a way that no recording could express, and the recording
    /// is the point of this component.
    pub fn load(sources: Vec<DexSource>) -> Result<MultidexLoader> {
        MultidexLoader::load_named(None, sources)
    }

    /// As [`MultidexLoader::load`], attributing the record to a package.
    pub fn load_named(package: Option<String>, sources: Vec<DexSource>) -> Result<MultidexLoader> {
        if sources.is_empty() {
            return Err(MultidexError::NoDexFiles);
        }

        // --- 1. Parse ordinals, reject anything a canonical loader skips. -----
        let mut by_ordinal: BTreeMap<u32, Vec<String>> = BTreeMap::new();
        for s in &sources {
            let ord = parse_ordinal(&s.name).ok_or_else(|| MultidexError::UnloadableName {
                name: s.name.clone(),
            })?;
            by_ordinal.entry(ord).or_default().push(s.name.clone());
        }
        for (ord, names) in &by_ordinal {
            if names.len() > 1 {
                return Err(MultidexError::DuplicateOrdinal {
                    ordinal: *ord,
                    names: {
                        let mut n = names.clone();
                        n.sort();
                        n
                    },
                });
            }
        }
        if !by_ordinal.contains_key(&1) {
            return Err(MultidexError::MissingPrimary {
                found: by_ordinal.values().flatten().cloned().collect(),
            });
        }
        // --- 2. The ordinals must be a gapless 1..=N. --------------------------
        let n = by_ordinal.len() as u32;
        let expected: Vec<u32> = (1..=n).collect();
        let present: Vec<u32> = by_ordinal.keys().copied().collect();
        if present != expected {
            let missing = (1..=n).find(|i| !by_ordinal.contains_key(i)).unwrap_or(0);
            return Err(MultidexError::NonContiguousLoad {
                missing,
                found: present,
            });
        }

        // --- 3. Order by ordinal, and only now open the files. ----------------
        // `BTreeMap` iteration is already ascending by ordinal, so the order is
        // established by the key type rather than by a separate sort that a
        // future edit could get wrong.
        let mut by_ordinal_ref: BTreeMap<u32, &DexSource> = BTreeMap::new();
        for src in &sources {
            if let Some(ord) = parse_ordinal(&src.name) {
                by_ordinal_ref.insert(ord, src);
            }
        }
        let ordered: Vec<(u32, &DexSource)> =
            by_ordinal_ref.iter().map(|(o, s)| (*o, *s)).collect();

        let mut files: Vec<LoadedFile> = Vec::with_capacity(ordered.len());
        let mut order: Vec<LoadOrderEntry> = Vec::with_capacity(ordered.len());
        for (id, (ordinal, src)) in ordered.into_iter().enumerate() {
            let id = FileId(id);
            let reader = DexReader::open(&src.bytes)
                .map_err(|source| MultidexError::from_dex(id, src.name.clone(), source))?;
            let h = reader.header();
            let sha1 = h
                .signature
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            order.push(LoadOrderEntry {
                file: id,
                ordinal,
                name: src.name.clone(),
                bytes: src.bytes.len(),
                class_defs: h.class_defs_size,
                method_ids: h.method_ids_size,
                sha1: sha1.clone(),
            });
            files.push(LoadedFile {
                id,
                ordinal,
                name: src.name.clone(),
                bytes: Arc::clone(&src.bytes),
                strings: h.string_ids_size,
                types: h.type_ids_size,
                protos: h.proto_ids_size,
                fields: h.field_ids_size,
                methods: h.method_ids_size,
                class_defs: h.class_defs_size,
                dex_sha1: sha1,
            });
        }

        let mut loader = MultidexLoader {
            package,
            files,
            space: ClassSpace::default(),
            record: LoadRecord {
                package: None,
                order,
                warnings: Vec::new(),
            },
        };
        loader.index()?;
        Ok(loader)
    }

    /// The package name, when the caller supplied one.
    pub fn package(&self) -> Option<&str> {
        self.package.as_deref()
    }

    /// The files, in load order.
    pub fn files(&self) -> &[LoadedFile] {
        &self.files
    }

    /// The number of loaded files.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// The recorded load.
    pub fn record(&self) -> &LoadRecord {
        &self.record
    }

    /// Every warning the load produced.
    pub fn warnings(&self) -> &[MultidexWarning] {
        &self.record.warnings
    }

    /// The merged class space.
    pub fn space(&self) -> &ClassSpace {
        &self.space
    }

    /// Every warning, as shim `SubstrateEvent`s, for the recording.
    ///
    /// `seq` is assigned contiguously from `first_seq` in warning order, which
    /// is deterministic for a given APK, so two runs produce identical event
    /// sequences. A recording can therefore be diffed across runs, which is
    /// the property the whole observation design turns on.
    pub fn warning_events(&self, first_seq: u64) -> Vec<shim::event::SubstrateEvent> {
        self.record
            .warnings
            .iter()
            .enumerate()
            .map(|(i, w)| w.to_shim_event(first_seq + i as u64, 0))
            .collect()
    }

    /// The class space flattened into the shim's `AppDex`.
    ///
    /// This is the hand-off point to the shim's classloader and it is
    /// deliberately thin: it flattens **descriptors only**, and it says nothing
    /// about which file each came from. That is correct, because
    /// `shim::classes::ClassLoader` makes a shim-versus-app decision and
    /// records it as `Resolution::ShimSupersedesApp`; adding a per-file notion
    /// here would either be dropped or would change the shim's decision, and
    /// the supersede rule from `docs/decisions/0005` §2 must not change.
    ///
    /// A descriptor that two files both declare appears **once**: the shim's
    /// loader takes a sorted, deduplicated list, and it would be meaningless to
    /// offer the same descriptor twice for a decision that is a boolean.
    ///
    /// # The package name should be supplied
    ///
    /// `shim::classes::AppDex::package` is a `String`, not an `Option`, so a
    /// loader built without one produces `package: ""` and the shim then
    /// records `from_package: Some("")` on every app-side resolution. An empty
    /// string there is worse than an absent one: a reader cannot tell "the
    /// package was not supplied" from "the package is the empty string", and
    /// the recording's job is to make that distinguishable. Build loaders that
    /// feed the shim with [`MultidexLoader::load_named`]. This is noted rather
    /// than papered over because the fix belongs in `shim/`, which this
    /// component does not own.
    pub fn shim_view(&self) -> shim::classes::AppDex {
        shim::classes::AppDex {
            package: self.package.clone().unwrap_or_default(),
            classes: self.space.descriptors().map(str::to_string).collect(),
        }
    }

    /// A reader over one file's bytes.
    ///
    /// Constructed on demand for the byte-level operations only; see the
    /// type-level note on [`MultidexLoader`].
    pub fn reader(&self, file: FileId) -> Result<DexReader<'_>> {
        let f = self.files.get(file.0).ok_or(MultidexError::NoDexFiles)?;
        DexReader::open(&f.bytes)
            .map_err(|source| MultidexError::from_dex(file, f.name.clone(), source))
    }

    /// One file's entry name.
    pub fn file_name(&self, file: FileId) -> Option<&str> {
        self.files.get(file.0).map(|f| f.name.as_str())
    }

    /// Look up a pool index **within one file**, reporting which file was
    /// out of range.
    ///
    /// This is the boundary check that makes per-file index spaces safe. A
    /// `method_id` that is valid in `classes.dex` and out of range in
    /// `classes2.dex` produces [`MultidexError::IndexOutOfRange`] naming
    /// `classes2.dex` and *its* pool size.
    pub fn check_index(
        &self,
        file: FileId,
        pool: &'static str,
        index: u32,
        size: u32,
    ) -> Result<()> {
        if index >= size {
            let name = self.file_name(file).unwrap_or("<unknown>").to_string();
            return Err(MultidexError::IndexOutOfRange {
                file,
                name,
                pool,
                index,
                size,
            });
        }
        Ok(())
    }

    /// Walk every class in every file, in load order, and build the merged space.
    fn index(&mut self) -> Result<()> {
        let mut space: BTreeMap<String, MergedClass> = BTreeMap::new();
        let mut warnings: Vec<MultidexWarning> = Vec::new();

        for file_index in 0..self.files.len() {
            let file = FileId(file_index);
            let reader = self.reader(file)?;
            let name = self.files[file_index].name.clone();

            for def_idx in 0..reader.class_def_count() {
                let class = reader
                    .class_def(def_idx)
                    .map_err(|source| MultidexError::from_dex(file, name.clone(), source))?;
                let site = ClassSite {
                    file,
                    name: name.clone(),
                    class_def_idx: def_idx,
                    access_flags: class.access_flags,
                    superclass: class.superclass.clone(),
                    interfaces: class.interfaces.clone(),
                    has_class_data: class.class_data.is_some(),
                };

                // Class-level header and method/field sites.
                let entry = space
                    .entry(class.descriptor.clone())
                    .or_insert_with(|| MergedClass {
                        descriptor: class.descriptor.clone(),
                        primary: site.clone(),
                        sites: Vec::new(),
                        methods: BTreeMap::new(),
                        fields: BTreeMap::new(),
                        site_method_sets: Vec::new(),
                        superclass: class.superclass.clone(),
                        has_static_values: class.static_values_off != 0,
                    });
                let is_first_site = entry.sites.is_empty();
                if !is_first_site {
                    // First-wins for the header, disagreement recorded.
                    if entry.superclass != class.superclass {
                        warnings.push(MultidexWarning::DivergentClassHeader {
                            descriptor: class.descriptor.clone(),
                            primary: entry.primary.file,
                            other: file,
                            field: HeaderField::Superclass,
                            primary_value: entry.superclass.clone(),
                            other_value: class.superclass.clone(),
                        });
                    }
                    if entry.primary.access_flags != class.access_flags {
                        warnings.push(MultidexWarning::DivergentClassHeader {
                            descriptor: class.descriptor.clone(),
                            primary: entry.primary.file,
                            other: file,
                            field: HeaderField::AccessFlags,
                            primary_value: format!("{:#x}", entry.primary.access_flags),
                            other_value: format!("{:#x}", class.access_flags),
                        });
                    }
                    if entry.primary.interfaces != class.interfaces {
                        warnings.push(MultidexWarning::DivergentClassHeader {
                            descriptor: class.descriptor.clone(),
                            primary: entry.primary.file,
                            other: file,
                            field: HeaderField::Interfaces,
                            primary_value: entry.primary.interfaces.join(","),
                            other_value: class.interfaces.join(","),
                        });
                    }
                    warnings.push(MultidexWarning::DuplicateClass {
                        descriptor: class.descriptor.clone(),
                        winner: entry.primary.file,
                        winner_name: entry.primary.name.clone(),
                        losers: Vec::new(),
                        loser_names: Vec::new(),
                    });
                }
                entry.has_static_values |= class.static_values_off != 0;
                entry.sites.push(site);

                // Methods and fields. Indices are resolved against *this*
                // file's pools, which is the entire point of the module.
                if let Some(data) = &class.class_data {
                    let mut here: BTreeSet<MethodSig> = BTreeSet::new();
                    for encoded in data
                        .direct_methods
                        .iter()
                        .chain(data.virtual_methods.iter())
                    {
                        let method_idx = encoded.method_idx;
                        // Bounds-check against this file's own method pool.
                        self.check_index(
                            file,
                            "method_ids",
                            method_idx,
                            self.files[file_index].methods,
                        )?;
                        let dm = reader.method_at(method_idx).map_err(|source| {
                            MultidexError::from_dex(file, name.clone(), source)
                        })?;
                        let sig = MethodSig {
                            class: class.descriptor.clone(),
                            name: dm.name.clone(),
                            parameters: dm.parameters.clone(),
                        };
                        here.insert(sig.clone());
                        let slot = entry.methods.entry(sig.clone()).or_default();
                        // Push the new site *before* deciding whether this is a
                        // duplicate: `others` has to mean "every site other than
                        // the winner", and computing it from the slot before the
                        // push yields the winner itself — a warning that reports
                        // a file as the *other* definer when the winner is in
                        // that very file.
                        slot.push(MethodDefSite {
                            file,
                            name: name.clone(),
                            class_def_idx: def_idx,
                            method_idx,
                            access_flags: encoded.access_flags,
                            code_off: encoded.code_off,
                        });
                        if slot.len() > 1 {
                            let others: Vec<FileId> = slot.iter().skip(1).map(|s| s.file).collect();
                            warnings.push(MultidexWarning::DuplicateMethod {
                                signature: sig,
                                winner: slot[0].file,
                                winner_name: slot[0].name.clone(),
                                others,
                                other_names: Vec::new(),
                            });
                        }
                    }
                    entry.site_method_sets.push((file, here));
                    for encoded in data.static_fields.iter().chain(data.instance_fields.iter()) {
                        let field_idx = encoded.field_idx;
                        self.check_index(
                            file,
                            "field_ids",
                            field_idx,
                            self.files[file_index].fields,
                        )?;
                        let df = reader.field_at(field_idx).map_err(|source| {
                            MultidexError::from_dex(file, name.clone(), source)
                        })?;
                        let sig = FieldSig {
                            class: class.descriptor.clone(),
                            name: df.name.clone(),
                            type_descriptor: df.type_descriptor.clone(),
                        };
                        entry.fields.entry(sig).or_default().push(FieldDefSite {
                            file,
                            class_def_idx: def_idx,
                            field_idx,
                            access_flags: encoded.access_flags,
                        });
                    }
                }
            }
        }

        // Backfill the losing file names on the duplicate warnings, now that
        // every file is known, so each warning names the files it is about.
        let by_id: BTreeMap<FileId, LoadedFile> =
            self.files.iter().map(|f| (f.id, f.clone())).collect();
        for w in warnings.iter_mut() {
            match w {
                MultidexWarning::DuplicateClass {
                    descriptor,
                    winner,
                    losers,
                    loser_names,
                    ..
                } => {
                    if let Some(m) = space.get(descriptor) {
                        *losers = m
                            .sites
                            .iter()
                            .map(|s| s.file)
                            .filter(|f| f != winner)
                            .collect();
                        *loser_names = m
                            .sites
                            .iter()
                            .filter(|s| s.file != *winner)
                            .map(|s| s.name.clone())
                            .collect();
                    }
                }
                MultidexWarning::DuplicateMethod {
                    others,
                    other_names,
                    ..
                } => {
                    *other_names = others
                        .iter()
                        .filter_map(|o| by_id.get(o))
                        .map(|f| f.name.clone())
                        .collect();
                }
                _ => {}
            }
        }

        // Cross-file hierarchy facts. These need the whole space, so they are a
        // second pass: a subclass in file 1 may have its superclass in file 2.
        for (descriptor, m) in &space {
            if m.superclass.is_empty() {
                continue;
            }
            match space.get(&m.superclass) {
                Some(sup) => {
                    if sup.primary.file > m.primary.file {
                        warnings.push(MultidexWarning::SuperclassInLaterFile {
                            descriptor: descriptor.clone(),
                            superclass: m.superclass.clone(),
                            subclass_file: m.primary.file,
                            superclass_file: sup.primary.file,
                        });
                    }
                }
                None => warnings.push(MultidexWarning::UnresolvedSuperclass {
                    descriptor: descriptor.clone(),
                    superclass: m.superclass.clone(),
                }),
            }
        }

        let pkg = self.package.clone();
        self.record.package = pkg;
        self.record.warnings = warnings;
        self.space = ClassSpace { classes: space };
        Ok(())
    }
}
