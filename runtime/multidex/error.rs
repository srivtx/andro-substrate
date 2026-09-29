//! Typed errors.
//!
//! Every fallible entry point returns [`Result`]. Nothing in the load or
//! resolve path indexes a slice, a pool or a vector before a bounds check, so a
//! hostile or truncated APK degrades to one of these values rather than to a
//! panic. That is not a stylistic preference: this code runs against bytes an
//! attacker chose, and a panic in a browser substrate takes down the tab and
//! with it the recording that was in progress.
//!
//! Two things are specific to multidex and are worth naming here, because they
//! are failures that *cannot* happen when there is only one `classes.dex`:
//!
//! - [`MultidexError::IndexOutOfRange`] and [`MultidexError::IndexFromWrongFile`]
//!   both concern a pool index. In a single-DEX runtime an out-of-range
//!   `method_id` is simply a corrupt file. Here the same index may be perfectly
//!   valid *and meaningless*: `method_id[0]` in `classes.dex` and `method_id[0]`
//!   in `classes2.dex` are unrelated methods. The error therefore always names
//!   which file the index was applied to.
//! - [`MultidexError::NonContiguousLoad`] and friends are about the *set* of
//!   files, which is a shape a single-DEX runtime cannot express.

use std::fmt;

use crate::multidex::loader::FileId;

/// Result alias used throughout the module.
pub type Result<T> = std::result::Result<T, MultidexError>;

/// Everything that can go wrong while loading or resolving across N DEX files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultidexError {
    /// No DEX file was supplied at all. A runtime with nothing to load is a
    /// caller error, not a hostile input, but it is still a typed failure.
    NoDexFiles,

    /// An entry name that a canonical Android loader would not load, e.g.
    /// `foo.dex` or `Classes.dex`. The substrate only ever loads
    /// `classes.dex` and `classes<N>.dex`, so anything else is rejected rather
    /// than silently ignored: silently ignoring it would change load order in a
    /// way nothing records.
    UnloadableName {
        /// The entry name as it appeared in the container.
        name: String,
    },

    /// `classes.dex` is absent. Android always has one, and it is always
    /// load-order 0; an app without it is either not an APK or an adversarial
    /// one, and both are refusable.
    MissingPrimary {
        /// The names that *were* offered, sorted.
        found: Vec<String>,
    },

    /// Two entries claim the same load-order ordinal, e.g. both `classes3.dex`
    /// and `classes03.dex`. First-wins does not apply to file *names*: a
    /// duplicate ordinal is an ambiguous container, and picking one silently
    /// would decide load order by an accident of iteration.
    DuplicateOrdinal {
        /// The contested load-order ordinal (1 == `classes.dex`).
        ordinal: u32,
        /// Every name that claimed it, sorted.
        names: Vec<String>,
    },

    /// The ordinals are not the gapless run `1..=N`. A missing
    /// `classes2.dex` with `classes3.dex` present means the container is
    /// malformed, and loading `classes3.dex` anyway would invent an order the
    /// build never expressed.
    NonContiguousLoad {
        /// The first ordinal in the gap.
        missing: u32,
        /// The ordinals actually present, ascending.
        found: Vec<u32>,
    },

    /// `dexcore` rejected a file. The file identity is carried alongside so a
    /// message never says "bad magic" without saying *which* file.
    Dex {
        /// Which file in load order.
        file: FileId,
        /// The entry name.
        name: String,
        /// The underlying parse failure.
        source: dexcore::Error,
    },

    /// A pool index is outside the pool **of the file it was applied to**.
    ///
    /// The `size` in this error is that file's pool size, which is the whole
    /// point: the same index can be in range for one file and out of range for
    /// another, and a diagnostic that did not distinguish them would be
    /// actively misleading.
    IndexOutOfRange {
        /// The file the index was applied to.
        file: FileId,
        /// That file's entry name.
        name: String,
        /// Which pool: `method_ids`, `type_ids`, `string_ids`, ...
        pool: &'static str,
        /// The offending index.
        index: u32,
        /// That file's pool size.
        size: u32,
    },

    /// A [`ScopedIndex`](crate::resolver::ScopedIndex) was applied to a
    /// different file than the one it was minted from.
    ///
    /// This is the cross-file index leak the whole module exists to prevent: a
    /// `method_id` index is only meaningful inside the file that declared it,
    /// so carrying one across files is a bug with a *silent* failure mode
    /// unless it is made loud. It gets its own variant so that a test can
    /// assert the refusal rather than infer it from a wrong answer.
    IndexFromWrongFile {
        /// The file the index was minted from.
        index_from: FileId,
        /// The file it was applied to.
        applied_to: FileId,
        /// Which pool.
        pool: &'static str,
        /// The offending index.
        index: u32,
    },

    /// A structure ran past the end of one file's bytes. Kept distinct from
    /// [`MultidexError::Dex`] so a negative test can assert the error is about
    /// *this* file being short rather than about any file being malformed, and
    /// so a truncated `classes2.dex` is distinguishable from a corrupt one.
    TruncatedFile {
        /// Which file.
        file: FileId,
        /// That file's entry name.
        name: String,
        /// What was being read (`header`, `file`, `code`, ...).
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes the file actually has.
        have: usize,
    },
}

impl MultidexError {
    /// Attach a file identity to a `dexcore` failure, **promoting truncation to
    /// its own variant**.
    ///
    /// A short file is the one `dexcore` failure a multidex loader sees far
    /// more often than the rest — a partially-extracted `classes2.dex`, a
    /// range-limited download, a hostile file cut just past its header — and it
    /// is also the one an analyst most needs to tell apart from "this file is
    /// malformed in some other way". `dexcore` reports both as
    /// `Error::Truncated`, which is the right granularity for a single-DEX
    /// reader and too coarse here, so the promotion happens at this boundary
    /// where the file identity is known.
    pub(crate) fn from_dex(file: FileId, name: String, source: dexcore::Error) -> MultidexError {
        match source {
            dexcore::Error::Truncated { what, need, have } => MultidexError::TruncatedFile {
                file,
                name,
                what,
                need,
                have,
            },
            other => MultidexError::Dex {
                file,
                name,
                source: other,
            },
        }
    }

    /// A stable discriminant, for the wasm surface and for recording JSON.
    ///
    /// Stable means stable: these strings are written into recordings that are
    /// compared across runs, so they are part of the output format and are not
    /// renamed casually.
    pub fn kind(&self) -> &'static str {
        match self {
            MultidexError::NoDexFiles => "NoDexFiles",
            MultidexError::UnloadableName { .. } => "UnloadableName",
            MultidexError::MissingPrimary { .. } => "MissingPrimary",
            MultidexError::DuplicateOrdinal { .. } => "DuplicateOrdinal",
            MultidexError::NonContiguousLoad { .. } => "NonContiguousLoad",
            MultidexError::Dex { .. } => "Dex",
            MultidexError::IndexOutOfRange { .. } => "IndexOutOfRange",
            MultidexError::IndexFromWrongFile { .. } => "IndexFromWrongFile",
            MultidexError::TruncatedFile { .. } => "TruncatedFile",
        }
    }

    /// The file this error is about, when it is about one.
    pub fn file(&self) -> Option<FileId> {
        match self {
            MultidexError::Dex { file, .. }
            | MultidexError::IndexOutOfRange { file, .. }
            | MultidexError::TruncatedFile { file, .. } => Some(*file),
            MultidexError::IndexFromWrongFile { applied_to, .. } => Some(*applied_to),
            _ => None,
        }
    }
}

impl fmt::Display for MultidexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MultidexError::NoDexFiles => write!(f, "no DEX files supplied"),
            MultidexError::UnloadableName { name } => {
                write!(f, "{name:?} is not a loadable classes*.dex name")
            }
            MultidexError::MissingPrimary { found } => {
                write!(f, "classes.dex is missing; found {found:?}")
            }
            MultidexError::DuplicateOrdinal { ordinal, names } => write!(
                f,
                "load-order ordinal {ordinal} claimed by {names:?}; load order is ambiguous"
            ),
            MultidexError::NonContiguousLoad { missing, found } => write!(
                f,
                "load-order ordinal {missing} is missing; present ordinals are {found:?}"
            ),
            MultidexError::Dex { name, source, .. } => write!(f, "{name}: {source}"),
            MultidexError::IndexOutOfRange {
                name,
                pool,
                index,
                size,
                ..
            } => write!(
                f,
                "{name}: {pool}[{index}] is out of range; that file has {size} entries"
            ),
            MultidexError::IndexFromWrongFile {
                index_from,
                applied_to,
                pool,
                index,
            } => write!(
                f,
                "{pool}[{index}] was minted in file {index_from} and applied to file {applied_to}; \
                 pool indices are per-file"
            ),
            MultidexError::TruncatedFile {
                name, need, have, ..
            } => {
                write!(
                    f,
                    "{name}: truncated, needed {need} bytes but file has {have}"
                )
            }
        }
    }
}

impl std::error::Error for MultidexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MultidexError::Dex { source, .. } => Some(source),
            _ => None,
        }
    }
}
