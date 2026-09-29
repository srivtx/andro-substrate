//! `resources.arsc`, `Res_value`, binary XML and the loader that ties them
//! together.
//!
//! An APK's resource story has four parts, one per module:
//!
//! - [`types`] — what a `Res_value` means once the type tag is read.
//! - [`arsc`] — the table: which resources exist, in which configurations.
//! - [`inflate`] — a compiled layout file, turned back into an element tree
//!   with every attribute reference already resolved.
//! - [`loader`] — the one entry point the rest of the runtime uses.
//!
//! Nothing in here panics on untrusted input. Every failure is a
//! [`ResourceError`], every walk over a possibly-cyclic structure has a depth
//! limit, and every `Vec` sized from a file-declared count is bounded against
//! the file first.

#![forbid(unsafe_code)]

pub mod arsc;
pub mod error;
pub mod inflate;
pub mod loader;
pub mod types;

#[cfg(test)]
mod testing;

pub use arsc::{
    Absence, LocaleData, MapEntry, MatchReport, Package, Payload, ResConfig, ResId, Resolved,
    ResourceTable, StringPool, TypeChunk, TypeSpec, ENTRY_FLAG_COMPLEX, ENTRY_FLAG_COMPACT,
    ENTRY_FLAG_PUBLIC, FLAG_OFFSET16, FLAG_SPARSE, NO_ENTRY, UTF8_FLAG,
};
pub use error::{ResourceError, Result, XmlError};
pub use inflate::{inflate, Attr, Element, InflateOptions, InflateReport, ResolvedAttr};
pub use loader::{AssetSource, MemorySource, ResourceLoader, ZipSource};
pub use types::{ColorFormat, Dimension, Fraction, Null, RawValue, Unit, Value};
