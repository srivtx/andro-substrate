//! Typed errors.
//!
//! Every fallible entry point returns [`Result`], and no error variant carries
//! an untyped panic. The predictor's input is an untrusted APK fetched from a
//! CDN, so a malformed archive must degrade to a typed error that the driver can
//! record as a row rather than a crash that loses the run.

use serde::Serialize;
use std::fmt;

/// A predictor error, with a stable `kind` discriminant for JSON reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The file is not a ZIP archive at all: no end-of-central-directory record.
    NotAZip,
    /// The central directory claims more bytes than the file has.
    Truncated {
        what: &'static str,
        need: u64,
        have: u64,
    },
    /// A ZIP feature this reader does not implement. Carries the method byte.
    UnsupportedCompression { name: String, method: u16 },
    /// Decompression failed or produced the wrong number of bytes.
    Inflate { name: String, detail: String },
    /// A `classes*.dex` entry did not parse as DEX.
    Dex { name: String, detail: String },
    /// A caller-supplied bound was exceeded, e.g. `--max-dex-bytes`.
    BudgetExceeded {
        what: &'static str,
        limit: u64,
        actual: u64,
    },
    /// Filesystem or serialisation failure. Kept as a string so `Error` stays
    /// `PartialEq` without pulling `std::io::Error` into the public type.
    Io(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotAZip => write!(f, "not a zip archive: no end-of-central-directory record"),
            Error::Truncated { what, need, have } => {
                write!(f, "truncated {what}: need {need} bytes, have {have}")
            }
            Error::UnsupportedCompression { name, method } => write!(
                f,
                "entry {name:?} uses compression method {method}, which this reader does not implement"
            ),
            Error::Inflate { name, detail } => write!(f, "inflate failed for {name:?}: {detail}"),
            Error::Dex { name, detail } => write!(f, "{name} did not parse as dex: {detail}"),
            Error::BudgetExceeded { what, limit, actual } => {
                write!(f, "budget exceeded for {what}: limit {limit}, actual {actual}")
            }
            Error::Io(detail) => write!(f, "io error: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<dexcore::Error> for Error {
    /// dexcore's errors are already typed with a `kind`; carry the message and
    /// the variant across rather than stringifying the whole type away, so a
    /// malformed DEX and a truncated one stay distinguishable downstream.
    fn from(e: dexcore::Error) -> Self {
        Error::Dex {
            name: "<dex>".to_string(),
            detail: e.to_string(),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// The JSON shape of an error, for the driver's per-app row.
#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    pub kind: &'static str,
    pub message: String,
}

impl Error {
    /// Stable `kind` string, used as the JSON discriminant and in tests.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::NotAZip => "not_a_zip",
            Error::Truncated { .. } => "truncated",
            Error::UnsupportedCompression { .. } => "unsupported_compression",
            Error::Inflate { .. } => "inflate",
            Error::Dex { .. } => "dex",
            Error::BudgetExceeded { .. } => "budget_exceeded",
            Error::Io(_) => "io",
        }
    }

    /// Render for a JSON row.
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            kind: self.kind(),
            message: self.to_string(),
        }
    }
}

impl serde::Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.envelope().serialize(s)
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;
