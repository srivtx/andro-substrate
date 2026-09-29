//! # Multidex: ordered load of N DEX containers, and cross-file resolution
//!
//! ## The problem, stated without the euphemism
//!
//! A runtime that loads one `classes.dex` per run cannot run any app with more
//! than 65 536 methods. That is **31.13 % of the F-Droid corpus** — 1393 of
//! 4475 surveyed packages, from `corpus/survey.jsonl`, and the rate rises
//! steeply with `minSdk` (6.67 % below 21, 36.79 % at or above 21,
//! `r = 0.34`). So a corpus-level average understates how much this matters:
//! modern apps are overwhelmingly multidex. The component is load-bearing.
//!
//! And multidex is **not** concatenation. `classes.dex`, `classes2.dex`, … are
//! independent containers, each with its own five id pools, its own header and
//! its own checksums. Pool indices are per-file, so:
//!
//! ```text
//! method_id[0] in classes.dex   == Landroid/app/ActionBar;.setDisplayHomeAsUpEnabled
//! method_id[0] in classes2.dex  == Lj$/util/Map$-CC;.$default$compute
//! ```
//!
//! Merging the files is not an option anyway: `docs/decisions/0005` §2 already
//! establishes that a merge is a pool-renumbering operation dexcore's writer
//! cannot yet perform, and — separately — that *merging* is the wrong loader
//! boundary even for a tool that could do it. The design here is therefore
//! **index and resolve across N files**, which is also what keeps the shim's
//! supersede rule working untouched.
//!
//! ## What the legacy fallback cannot be used for
//!
//! `dalvik.system.DexClassLoader` handles all of this on a real device, by
//! handing the platform a dex jar and letting *it* own the index spaces. There
//! is no platform here: there is no VM, no `libart.so` and no
//! `DexClassLoader`. So the machinery that Android gets for free — per-file
//! pools, the 64 K method limit, first-wins duplicates — has to exist in this
//! crate, explicitly, and be recorded when it disagrees with the naive answer.
//!
//! ## Module map
//!
//! | module | role |
//! |---|---|
//! | [`error`] | `MultidexError`; every failure is typed, nothing panics |
//! | [`loader`] | ordinal load order, per-file index spaces, first-wins duplicates |
//! | [`resolver`] | cross-file class/method resolution, split-class merge, `Ambiguous` |
//!
//! ## The three rules
//!
//! Stated in full in [`resolver`]; in brief:
//!
//! 1. **Split-class merging.** A descriptor's `class_data` is the ordered union
//!    of every site's, keyed by method/field identity. Methods merge rather
//!    than shadow. Class-level metadata (superclass, flags, interfaces) is
//!    first-wins in load order, and a disagreement is recorded as
//!    [`MultidexWarning::DivergentClassHeader`] rather than resolved silently.
//! 2. **Ambiguity is a first-class outcome.** Two files defining the same
//!    method *differently* — different body presence, different observable
//!    access flags, or different instruction bytes — produce
//!    [`MethodResolution::Ambiguous`], carrying every candidate. Equivalent
//!    duplicates are not conflicts and resolve first-wins.
//! 3. **A call resolves where the method is defined.** Lookup is by identity,
//!    never by the file a reference was read from. A raw pool index may not
//!    cross files: [`ScopedIndex`] makes that a typed error rather than an
//!    answer about a different method.
//!
//! ## Safety posture
//!
//! [`loader::MultidexLoader::load`] opens every file with dexcore's
//! bounds-checked reader and then checks each `method_id`/`field_id` it walks
//! against **that file's** pool size, so a truncated or hostile file yields a
//! [`MultidexError`] naming the file. There are no `unwrap`s, no slicing
//! without a bounds check and no panicking paths in the load or resolve flow.
//!
//! ## Relationship to `shim`
//!
//! This module does not decide framework-versus-app. That boundary is
//! [`shim::classes::ClassLoader`]'s, and the supersede rule from
//! `docs/decisions/0005-shim-and-observation.md` is unchanged by anything here.
//! [`MultidexLoader::shim_view`] is the hand-off: it flattens the merged class
//! space into the `AppDex` the shim's loader already takes, and
//! `tests/shim_supersede.rs` proves the shim still wins when the colliding app
//! class lives in `classes2.dex` rather than `classes.dex`.

pub mod error;
pub mod loader;
pub mod resolver;

pub use error::{MultidexError, Result};
pub use loader::{
    parse_ordinal, ClassSite, ClassSpace, DexSource, FieldDefSite, FieldSig, FileId, HeaderField,
    LoadOrderEntry, LoadRecord, LoadedFile, MergedClass, MethodDefSite, MethodSig, MultidexLoader,
    MultidexWarning,
};
pub use resolver::{
    AmbiguityReason, ClassResolution, FieldResolution, MethodResolution, Resolver, ScopedIndex,
};
