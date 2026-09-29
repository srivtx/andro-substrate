//! Cross-file class and method resolution.
//!
//! # The three rules, stated precisely
//!
//! These are the decisions a multidex loader has to make that a single-DEX
//! loader never has to, so they are stated as rules rather than left implicit in
//! the code.
//!
//! ## Rule 1 — split-class merging
//!
//! A descriptor may have a `class_def` in more than one file. The merged view
//! of class `C` is the **ordered union** of every site's `class_data_item`,
//! keyed by method/field identity ([`MethodSig`], [`FieldSig`]), in load order.
//!
//! - **Methods and fields merge; they do not shadow.** Every method of `C` is
//!   visible to the runtime, wherever it was declared, and the union is what
//!   makes a `MethodID` in one file and a `ClassDef` in another work.
//! - **Class-level metadata is first-wins.** Superclass, access flags and the
//!   interface list come from the earliest site in load order. Where a later
//!   site disagrees, the first-wins value is used *and*
//!   [`MultidexWarning::DivergentClassHeader`](crate::loader::MultidexWarning::DivergentClassHeader)
//!   is recorded — because a class with two superclasses has no single correct
//!   inheritance, and silently inheriting the first one would change which
//!   methods `C` resolves.
//! - **Method bodies are first-wins among equivalent definitions only.** When
//!   two files define the same method and the definitions are *not* equivalent,
//!   the loader does not pick: see Rule 2.
//!
//! ## Rule 2 — ambiguity is a first-class outcome
//!
//! Two definitions of the same [`MethodSig`] are **equivalent** when they agree
//! on the semantically observable parts of a declaration:
//!
//! - the presence of a `code_item` — a concrete body in one file and an
//!   abstract/native declaration in another is a real difference, because it
//!   changes whether the call executes app code or throws;
//! - `access_flags`, after masking `ACC_SYNTHETIC`, `ACC_BRIDGE` and
//!   `ACC_VARARGS`, which javac/d8 attach inconsistently between the split
//!   halves of a desugared method without changing what it does;
//! - the bytes of the `code_item`'s instruction stream, when both have one. Two
//!   files carrying byte-identical bodies for a method is duplication, not
//!   conflict, and treating it as conflict would make a loader refuse to run
//!   ordinary apps.
//!
//! Resolving a method therefore has **four** outcomes, and `Ambiguous` is one
//! of them rather than a silent pick:
//!
//! | outcome | meaning |
//! |---|---|
//! | [`Resolved`] | exactly one site, or several equivalent ones; the first is used |
//! | [`Ambiguous`] | two or more **inequivalent** definitions — the call site must be refused |
//! | [`NotFound`] | no loaded file defines it |
//!
//! `Ambiguous` carries every candidate site, so an analyst can see both
//! definitions rather than the fact of a conflict alone.
//!
//! ## Rule 3 — a call resolves where the method is *defined*
//!
//! Resolution is by identity, never by the file a reference was *read from*. A
//! `classes.dex` call site for `Lj$/util/Map$-CC;.$default$compute` resolves into
//! `classes2.dex`, which is where that method is actually defined — this is
//! ordinary, and the `sayura` fixture exercises it. Conversely, a
//! `method_id` index never crosses a file boundary: [`ScopedIndex`] exists so
//! that doing so is a typed [`IndexFromWrongFile`](crate::error::MultidexError::IndexFromWrongFile)
//! error rather than a wrong answer about a different method.
//!
//! # Relationship to the shim
//!
//! Nothing here decides whether a class comes from the framework shim or the
//! app. That is [`shim::classes::ClassLoader`]'s job, and the supersede rule
//! recorded in `docs/decisions/0005-shim-and-observation.md` is unchanged: the
//! shim wins over the app, always. This module answers the narrower question
//! *the shim delegates to it*: given an app's N files, which file defines this
//! descriptor or method, and do the files agree? See
//! `tests/shim_supersede.rs` for the proof that supersede still holds when the
//! app's colliding class lives in `classes2.dex` rather than `classes.dex`.

use dexcore::model::access;
use serde::{Deserialize, Serialize};

use crate::multidex::error::{MultidexError, Result};
use crate::multidex::loader::{
    ClassSite, FieldDefSite, FieldSig, FileId, MergedClass, MethodDefSite, MethodSig,
    MultidexLoader,
};

/// Access-flag bits that do not make two declarations of the same method
/// semantically different.
///
/// `ACC_SYNTHETIC` and `ACC_BRIDGE` are compiler bookkeeping that d8 attaches
/// inconsistently between the two halves of a desugared method; `ACC_VARARGS`
/// overlaps `ACC_TRANSIENT` in the flag word and is emitted per-declaration.
/// Masking them keeps a routine desugar from being reported as a conflict,
/// which is the failure mode that would make `Ambiguous` noise.
const EQUIVALENCE_MASK: u32 =
    !(access::ACC_SYNTHETIC | access::ACC_BRIDGE | access::ACC_VARARGS | access::ACC_TRANSIENT);

/// Why two definitions of the same method were judged different.
///
/// An enum rather than a free-form string so that a recording can be compared
/// across runs, and so the three cases are separately assertable. It is also
/// what makes the equivalence rule falsifiable: a test can demand that
/// `CodeBytes` is reported for two bodies that differ and *not* reported for
/// two that match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AmbiguityReason {
    /// One file has a `code_item` and the other does not. The most consequential
    /// case: the call site would either execute app code or throw.
    CodePresence,
    /// Access flags differ, after masking `ACC_SYNTHETIC`/`ACC_BRIDGE`/
    /// `ACC_VARARGS`/`ACC_TRANSIENT`.
    AccessFlags,
    /// Both have bodies and the instruction bytes differ.
    CodeBytes,
}

impl AmbiguityReason {
    /// A stable tag for recordings and assertions.
    pub fn as_str(self) -> &'static str {
        match self {
            AmbiguityReason::CodePresence => "code_presence",
            AmbiguityReason::AccessFlags => "access_flags",
            AmbiguityReason::CodeBytes => "code_bytes",
        }
    }
}

impl std::fmt::Display for AmbiguityReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A pool index together with the file it is valid in.
///
/// The point of the newtype: a bare `u32` pool index is meaningless without its
/// file, and in a multidex runtime a bare `u32` is a *bug waiting to happen*,
/// because it will silently resolve against the wrong pool. [`ScopedIndex::apply_to`]
/// refuses to cross files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScopedIndex {
    /// The file whose pool this index belongs to.
    pub file: FileId,
    /// Which pool: `method_ids`, `type_ids`, `field_ids`, `string_ids`, ...
    pub pool: &'static str,
    /// The index within that file.
    pub index: u32,
}

impl ScopedIndex {
    /// Mint an index belonging to `file`.
    pub fn new(file: FileId, pool: &'static str, index: u32) -> ScopedIndex {
        ScopedIndex { file, pool, index }
    }

    /// Use this index against `target`, refusing to cross a file boundary.
    ///
    /// Returns [`MultidexError::IndexFromWrongFile`] when `target` is not the
    /// minting file. The refusal is unconditional and not conditional on
    /// whether the index happens to be in range for `target`, because "in range"
    /// is exactly the coincidence that makes the bug silent.
    pub fn apply_to(&self, target: FileId) -> Result<ScopedIndex> {
        if self.file != target {
            return Err(MultidexError::IndexFromWrongFile {
                index_from: self.file,
                applied_to: target,
                pool: self.pool,
                index: self.index,
            });
        }
        Ok(*self)
    }
}

/// A class resolution: which file's definition is in effect, and whether any
/// other file disagreed about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassResolution {
    /// The descriptor.
    pub descriptor: String,
    /// The winning site: the first in load order.
    pub primary: ClassSite,
    /// Every site, in load order. More than one means the class is split or
    /// duplicated; the two are distinguished by whether the method sets are
    /// disjoint.
    pub sites: Vec<ClassSite>,
    /// Whether the class's methods are **split** across files, as opposed to
    /// merely duplicated.
    ///
    /// Split means at least one file contributes a method no other file
    /// defines. Duplicated means the files carry the same method set. The
    /// distinction matters: a split class is a legitimate build artefact to be
    /// merged, whereas a duplicated one is the conflict Android warns about.
    pub is_split: bool,
}

impl ClassResolution {
    /// Files that contributed at least one method, in load order.
    pub fn contributing_files(&self) -> Vec<FileId> {
        self.sites
            .iter()
            .filter(|s| s.has_class_data)
            .map(|s| s.file)
            .collect()
    }
}

/// How a method resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodResolution {
    /// Exactly one definition, or several that are equivalent. `site` is the
    /// first in load order; `equivalent` lists any other sites that agreed with
    /// it, so a duplicate that was *not* a conflict is still visible.
    Resolved {
        /// The method identity.
        signature: MethodSig,
        /// The definition in effect: the first in load order.
        site: MethodDefSite,
        /// Other sites defining the same signature with an equivalent
        /// definition. Empty in the ordinary single-site case.
        equivalent: Vec<MethodDefSite>,
    },
    /// Two or more files define this method **differently**. There is no
    /// correct answer, so the runtime must refuse the call site rather than
    /// pick one, and an analyst gets every candidate.
    Ambiguous {
        /// The method identity.
        signature: MethodSig,
        /// Every defining site, in load order. At least two.
        candidates: Vec<MethodDefSite>,
        /// The first reason two candidates were found to differ.
        reason: AmbiguityReason,
    },
    /// No loaded file defines the method. Distinct from `Ambiguous`: nothing
    /// claims it, rather than several things claiming it differently.
    NotFound {
        /// The method identity that was searched for.
        signature: MethodSig,
    },
}

impl MethodResolution {
    /// The winning site, if there is one. `None` for both `Ambiguous` and
    /// `NotFound`, which is the point: a caller that ignores the distinction
    /// gets no site rather than a wrong one.
    pub fn site(&self) -> Option<&MethodDefSite> {
        match self {
            MethodResolution::Resolved { site, .. } => Some(site),
            _ => None,
        }
    }

    /// Whether resolution succeeded.
    pub fn is_resolved(&self) -> bool {
        matches!(self, MethodResolution::Resolved { .. })
    }
}

/// How a field resolved. Mirrors [`MethodResolution`] but has no ambiguity
/// case, because a field has no body: two files declaring the same field with
/// different types would fail DEX validation, and identical declarations are
/// simply first-wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldResolution {
    /// The first declaration in load order.
    Resolved {
        /// The field identity.
        signature: FieldSig,
        /// The declaration in effect.
        site: FieldDefSite,
        /// Later sites that redeclared the same field.
        duplicates: Vec<FieldDefSite>,
    },
    /// No loaded file declares it.
    NotFound {
        /// The field identity that was searched for.
        signature: FieldSig,
    },
}

impl FieldResolution {
    /// The winning site, if there is one.
    pub fn site(&self) -> Option<&FieldDefSite> {
        match self {
            FieldResolution::Resolved { site, .. } => Some(site),
            FieldResolution::NotFound { .. } => None,
        }
    }
}

/// Whether a class's method declarations are **split** across files, as
/// opposed to merely duplicated or merely nested.
///
/// The predicate is set-theoretic and deliberately narrow: the class is split
/// when two sites carry *incomparable* method sets, i.e. there exist `f`, `g`
/// with `S(f) ⊄ S(g)` and `S(g) ⊄ S(f)`.
///
/// The two excluded cases matter, because calling them "split" would make the
/// flag useless:
///
/// - `S(f) == S(g)` is a **duplicate** — the ordinary multidex case the
///   first-wins rule and [`MultidexWarning::DuplicateClass`] already cover.
/// - `S(f) ⊂ S(g)` is a **redundant** site: `f` contributes nothing the other
///   does not, so the class is fully defined by one file and merging changes
///   nothing.
///
/// Only an incomparable pair means both files carry methods the other lacks,
/// which is the case where the merge is load-bearing.
///
/// A site with no `class_data_item` has the empty set, which is a subset of
/// every set and therefore never makes a class split — correctly, since a
/// marker interface in one file and its real declaration in another adds
/// nothing to merge.
fn is_split_class(merged: &MergedClass) -> bool {
    let sets: Vec<&std::collections::BTreeSet<MethodSig>> =
        merged.site_method_sets.iter().map(|(_, s)| s).collect();
    for (i, a) in sets.iter().enumerate() {
        for b in sets.iter().skip(i + 1) {
            let a_subset_b = a.is_subset(b);
            let b_subset_a = b.is_subset(a);
            if !a_subset_b && !b_subset_a {
                return true;
            }
        }
    }
    false
}

/// Cross-file resolution over a loaded set of files.
#[derive(Debug)]
pub struct Resolver<'a> {
    loader: &'a MultidexLoader,
}

impl<'a> Resolver<'a> {
    /// A resolver over a loaded set of files.
    pub fn new(loader: &'a MultidexLoader) -> Resolver<'a> {
        Resolver { loader }
    }

    /// The loader being resolved against.
    pub fn loader(&self) -> &'a MultidexLoader {
        self.loader
    }

    /// Resolve a class descriptor to the file that defines it.
    ///
    /// Returns `None` when no file defines it, which for a `Landroid/…` or
    /// `Ljava/…` descriptor is the normal case: the framework shim is what
    /// satisfies those, and this resolver deliberately does not know about it.
    pub fn resolve_class(&self, descriptor: &str) -> Option<ClassResolution> {
        let merged: &MergedClass = self.loader.space().get(descriptor)?;
        Some(ClassResolution {
            descriptor: merged.descriptor.clone(),
            primary: merged.primary.clone(),
            sites: merged.sites.clone(),
            is_split: is_split_class(merged),
        })
    }

    /// Whether a descriptor is defined in any loaded file.
    pub fn has_class(&self, descriptor: &str) -> bool {
        self.loader.space().contains(descriptor)
    }

    /// Every method of a class, in the merged view, sorted by identity.
    ///
    /// This is the class's full method set *as the runtime sees it*: the union
    /// across files, which is what a caller that walks `Foo`'s methods needs
    /// and what a per-file walk would get wrong.
    pub fn class_methods(&self, descriptor: &str) -> Vec<MethodSig> {
        self.loader
            .space()
            .get(descriptor)
            .map(|m| m.methods.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Resolve a method by identity, across all files.
    ///
    /// Applies [Rule 2](self): equivalent duplicates resolve to the first site,
    /// inequivalent ones are [`MethodResolution::Ambiguous`].
    pub fn resolve_method(
        &self,
        class: &str,
        name: &str,
        parameters: &[String],
    ) -> MethodResolution {
        let signature = MethodSig {
            class: class.to_string(),
            name: name.to_string(),
            parameters: parameters.to_vec(),
        };
        let Some(merged) = self.loader.space().get(class) else {
            return MethodResolution::NotFound { signature };
        };
        let Some(sites) = merged.methods.get(&signature) else {
            return MethodResolution::NotFound { signature };
        };

        if sites.len() == 1 {
            return MethodResolution::Resolved {
                signature,
                site: sites[0].clone(),
                equivalent: Vec::new(),
            };
        }

        // More than one site. Compare each against the first; the first
        // inequivalence decides the outcome and the reason.
        let first = &sites[0];
        for other in &sites[1..] {
            if let Some(reason) = self.differ(first, other) {
                return MethodResolution::Ambiguous {
                    signature,
                    candidates: sites.clone(),
                    reason,
                };
            }
        }
        MethodResolution::Resolved {
            signature,
            site: first.clone(),
            equivalent: sites[1..].to_vec(),
        }
    }

    /// Resolve a method by its [`MethodSig`].
    pub fn resolve_sig(&self, signature: &MethodSig) -> MethodResolution {
        self.resolve_method(&signature.class, &signature.name, &signature.parameters)
    }

    /// Resolve a field by identity, first-wins.
    pub fn resolve_field(&self, class: &str, name: &str, type_descriptor: &str) -> FieldResolution {
        let signature = FieldSig {
            class: class.to_string(),
            name: name.to_string(),
            type_descriptor: type_descriptor.to_string(),
        };
        let Some(merged) = self.loader.space().get(class) else {
            return FieldResolution::NotFound { signature };
        };
        match merged.fields.get(&signature) {
            Some(sites) if !sites.is_empty() => FieldResolution::Resolved {
                signature,
                site: sites[0].clone(),
                duplicates: sites[1..].to_vec(),
            },
            _ => FieldResolution::NotFound { signature },
        }
    }

    /// The `code_item` for a definition site, read on demand.
    ///
    /// This is the one operation that genuinely needs the raw bytes of a
    /// particular file, and it is the reason [`MethodResolution::Ambiguous`]
    /// can be a *precise* answer rather than "the flags differ, probably".
    /// Declared-only sites (abstract, native) have no `code_item` and yield
    /// `Ok(None)`.
    pub fn code(&self, site: &MethodDefSite) -> Result<Option<dexcore::CodeItem>> {
        if !site.has_code() {
            return Ok(None);
        }
        let reader = self.loader.reader(site.file)?;
        let item = reader
            .code_item(site.code_off)
            .map_err(|source| MultidexError::from_dex(site.file, site.name.clone(), source))?;
        Ok(Some(item))
    }

    /// Whether two definitions of the same method are semantically different,
    /// and if so, why. `None` means equivalent.
    ///
    /// This is Rule 2's predicate. It is a method rather than a free function
    /// because comparing code bytes needs the loader.
    fn differ(&self, a: &MethodDefSite, b: &MethodDefSite) -> Option<AmbiguityReason> {
        // 1. Body presence. Concrete vs declaration-only is observable: one
        //    executes app code, the other throws.
        if a.has_code() != b.has_code() {
            return Some(AmbiguityReason::CodePresence);
        }
        // 2. Access flags, modulo compiler bookkeeping.
        if a.access_flags & EQUIVALENCE_MASK != b.access_flags & EQUIVALENCE_MASK {
            return Some(AmbiguityReason::AccessFlags);
        }
        // 3. The instruction bytes. Two files with byte-identical bodies are
        //    duplication; different bodies are a real conflict.
        if a.has_code() && b.has_code() && self.code_bytes_differ(a, b) {
            return Some(AmbiguityReason::CodeBytes);
        }
        None
    }

    /// Compare two bodies' instruction streams.
    ///
    /// A read failure on either side is treated as "they differ", because the
    /// alternative — assuming two unreadable bodies agree — is precisely the
    /// silent wrong answer this module exists to avoid. The surfaces carrying
    /// this are on the recording path, so the caller can see it happened.
    fn code_bytes_differ(&self, a: &MethodDefSite, b: &MethodDefSite) -> bool {
        match (self.insns_of(a), self.insns_of(b)) {
            (Ok(x), Ok(y)) => x != y,
            _ => true,
        }
    }

    /// A site's instruction stream, read from *its own* file.
    fn insns_of(&self, site: &MethodDefSite) -> Result<Vec<u8>> {
        let reader = self.loader.reader(site.file)?;
        let units = reader
            .code_units(site.code_off)
            .map_err(|source| MultidexError::from_dex(site.file, site.name.clone(), source))?;
        Ok(units.to_vec())
    }
}
