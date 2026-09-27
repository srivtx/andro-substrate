//! # substrate-predictor
//!
//! A static, device-free predictor of whether an Android APK is executable in a
//! **non-Android substrate** — the browser-native sandbox andro-substrate is
//! building — and of *which* substrate assumptions it structurally requires.
//!
//! ## Why this exists
//!
//! `corpus/report.md` measured that 44.76% of the F-Droid corpus contains no
//! `lib/<abi>/*.so`, and it was careful to say that this is a *necessary* filter
//! and not a sufficient one. The gap between "no native code" and "will run" is
//! the project's actual subject matter, and it had no measurement. This crate
//! is that measurement, and it needs no device, no root grant and no running
//! emulator — only the APK.
//!
//! It also does something the corpus census deliberately did not: it reports
//! **which** `SUB.*` taxonomy IDs an app structurally requires, and marks every
//! mapping between a framework API and a taxonomy ID as either `VERIFIED` (the
//! API's documented contract *is* the assumption) or `CONJECTURE` (the linkage
//! assumes a usage pattern a reference alone does not establish).
//!
//! ## Module map
//!
//! | module | role |
//! |---|---|
//! | [`zip`] | central-directory reader; entry inventory and DEX extraction |
//! | [`strings`] | DEX string-constant classifiers, each individually tested |
//! | [`taxonomy`] | the framework-API → `SUB.*` rule table, with confidences |
//! | [`dexscan`] | pool, class and instruction walk; invoke kinds, native declarations, call sites |
//! | [`analysis`] | per-app aggregation into [`analysis::AppFacts`] |
//! | [`score`] | the documented rubric and the banded prediction |
//!
//! ## The two rules this crate is built around
//!
//! 1. **Static facts only, and `unknown` where a fact is not available.** No
//!    interpreter, no call graph, no `resources.arsc`, no `debug_info_item`, no
//!    `encoded_value`. Where a fact needs one of those, the field says so.
//! 2. **Never present a guess as an established fact.** Strength of evidence
//!    (reference / declaration / call site) and strength of taxonomy mapping
//!    (VERIFIED / CONJECTURE) are separate, separately serialised axes.
//!
//! ## Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes = std::fs::read("app.apk")?;
//! let (facts, prediction) = substrate_predictor::predict(bytes);
//! println!("{} {}", prediction.score_0_100, prediction.band);
//! for hit in &facts.taxonomy_hits {
//!     println!("{} {} {}", hit.id, hit.confidence.as_str(), hit.call_sites);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod analysis;
pub mod dexscan;
pub mod error;
pub mod score;
pub mod strings;
pub mod taxonomy;
pub mod zip;

pub use analysis::{analyze_apk, predict, AppFacts, TRUST_NOTE};
pub use dexscan::{
    DexScan, Evidence, InvokeCounts, LoadLibraryCall, NativeDeclaration, TaxonomyHit,
};
pub use error::{Error, Result};
pub use score::{Band, Component, Gate, GateHit, Prediction, RUBRIC};
pub use taxonomy::{Confidence, RULES};

/// The analyzer version, recorded in every output row so a measurement can be
/// tied to the code that produced it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The F-Droid index version this analysis was measured against, when the
/// caller supplies one. The census records `repo.version` for comparability;
/// a prediction without a repo version is not comparable to another.
pub const REQUIRED_CORPUS_VERSION: u32 = 30000;
