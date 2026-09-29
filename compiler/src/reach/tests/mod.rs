//! The reachability test suite.
//!
//! Six modules, chosen so each answers a different question and none of them
//! can be answered by a number alone:
//!
//! | module | question |
//! |---|---|
//! | [`virtual_dispatch`] | does a virtual call reach every implementor, and how do CHA and RTA differ? |
//! | [`hierarchy`] | do ancestors, overrides and bodyless methods each contribute their own edges? |
//! | [`reflection`] | is the reflective hole counted, named, and non-zero on real code? |
//! | [`entry_points`] | is the entry set the manifest and `IR.md` describe, and no larger? |
//! | [`validation`] | does the closure over-approximate a measured trace, and how does it differ? |
//! | [`robustness`] | does anything panic on truncated, corrupt or hostile input? |
//!
//! No test here asserts that the closure equals an empirical figure. That is
//! deliberate: tuning a static analysis until it reproduces a measurement is the
//! error `trace/FINDINGS.md` and `docs/analysis/0002-…` both exist to prevent.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

pub mod entry_points;
pub mod fixtures;
pub mod hierarchy;
pub mod reflection;
pub mod robustness;
pub mod validation;
pub mod virtual_dispatch;
