//! `substrate-harness` — run a real APK under the framework shim.
//!
//! This crate is the **recorder**, not the instrument. It is the only part of
//! andro-substrate that opens a file, and it opens exactly the one the
//! researcher named. The instrument itself, `shim`, has an empty `std::fs`
//! surface and its own source scan says so; this crate carries the same scan,
//! narrowed to the one read that is legitimate here
//! (`harness/tests/no_side_channels.rs`).
//!
//! # What it does
//!
//! 1. reads the APK: `AndroidManifest.xml` for the static facts, `classes.dex`
//!    for the bytecode;
//! 2. asks [`shim::realdex::run`] to execute the app's own lifecycle under a
//!    named substrate policy, with the shim's DEX layered in front of the app's
//!    class table (supersede, ADR 0005);
//! 3. emits a `ground-truth/1` document that `oracle/recorder/validate.mjs`
//!    accepts, plus a run report naming the rung reached, the framework surface
//!    the shim lacks, and the exact error the run stopped at.
//!
//! # What it deliberately does not do
//!
//! It does not make an app work. An app that needs `WifiManager` and finds no
//! shim method for it stops there, and the report says so with the missing
//! `Landroid/net/…;.method()V` named. That count is the point; see
//! `docs/decisions/0008-interpreter-shim-integration.md`.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]

pub mod apk;
pub mod policy_named;
pub mod report;
pub mod zip;

pub use apk::{open_apk, Apk, ApkError, ManifestFacts};
pub use policy_named::{parse_policy, PolicySpec};
pub use report::{render_report, RunSummary};
pub use zip::{Zip, ZipError};
