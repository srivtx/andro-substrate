//! Runtime substrate: the pieces that turn an APK's bytes into things a browser
//! can execute.
//!
//! This crate root is deliberately empty. Each subsystem lives in its own
//! top-level directory so that each agent owns exactly one directory (see
//! `compiler/IR.md`), and the `#[path]` attributes below are the only thing that
//! ties them together. An agent adding a subsystem adds one `#[path]` line here
//! and touches nothing else.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

#[path = "../resources/mod.rs"]
pub mod resources;

#[path = "../multidex/mod.rs"]
pub mod multidex;
