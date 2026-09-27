//! Errors. Every fallible shim operation returns one of these.
//!
//! # No panics
//!
//! The substrate executes untrusted APK bytecode, so every value that crosses
//! the boundary — a URL, a path, a header name, a class descriptor, a method
//! argument — is untrusted input. Nothing in this crate indexes a slice, unwraps
//! an `Option`, or asserts an arithmetic invariant on such a value; parsing is
//! total and returns an error instead. `tests/no_panic.rs` additionally scans
//! the crate for `unwrap`, `expect`, `panic!` and unchecked indexing outside
//! `#[cfg(test)]` code, so a future edit cannot quietly reintroduce one.

use std::fmt;

/// Anything that can go wrong in the shim, with a stable `kind` discriminant so
/// the JSON boundary never depends on a `Display` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimError {
    /// A method name that no registry entry claims.
    NoSuchMethod { class: String, method: String },
    /// A class descriptor outside the shim's namespace, offered for dispatch.
    NotAShimClass { descriptor: String },
    /// The class resolved to nothing: not in the shim, not in any app DEX.
    ClassNotFound { descriptor: String },
    /// A URL the redaction layer refused to parse into capture-safe parts.
    UnparseableUrl { reason: UrlProblem },
    /// A path outside the in-memory VFS that is not absolute or escapes the root.
    BadPath { path: String, reason: PathProblem },
    /// The VFS refused the operation.
    Vfs(VfsError),
    /// A bounded resource hit its ceiling. Always `Err`, never a panic.
    Exhausted { resource: &'static str, limit: usize },
    /// Networking was attempted. This is the *expected* outcome, not a bug.
    EgressDenied(EgressDenial),
    /// A `native` method with no implementation behind it.
    UnsatisfiedLink { symbol: String, library: Option<String> },
    /// dexcore rejected the request, or the writer produced something unreadable.
    Dex(String),
    /// Serialising an event or the recording failed.
    Encode(String),
}

impl ShimError {
    /// Stable machine-readable kind, for the JSON boundary and for tests.
    pub fn kind(&self) -> &'static str {
        match self {
            ShimError::NoSuchMethod { .. } => "NoSuchMethod",
            ShimError::NotAShimClass { .. } => "NotAShimClass",
            ShimError::ClassNotFound { .. } => "ClassNotFound",
            ShimError::UnparseableUrl { .. } => "UnparseableUrl",
            ShimError::BadPath { .. } => "BadPath",
            ShimError::Vfs(e) => e.kind(),
            ShimError::Exhausted { .. } => "ExhaustedResource",
            ShimError::EgressDenied(_) => "EgressDenied",
            ShimError::UnsatisfiedLink { .. } => "UnsatisfiedLinkError",
            ShimError::Dex(_) => "Dex",
            ShimError::Encode(_) => "Encode",
        }
    }
}

impl fmt::Display for ShimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShimError::NoSuchMethod { class, method } => {
                write!(f, "no shim method {class}.{method}")
            }
            ShimError::NotAShimClass { descriptor } => write!(f, "{descriptor} is not a shim class"),
            ShimError::ClassNotFound { descriptor } => write!(f, "cannot resolve {descriptor}"),
            ShimError::UnparseableUrl { reason } => write!(f, "unparseable URL: {reason}"),
            ShimError::BadPath { path, reason } => write!(f, "bad path {path:?}: {reason}"),
            ShimError::Vfs(e) => write!(f, "{e}"),
            ShimError::Exhausted { resource, limit } => {
                write!(f, "resource limit reached: {resource} > {limit}")
            }
            ShimError::EgressDenied(d) => write!(f, "{d}"),
            ShimError::UnsatisfiedLink { symbol, library } => match library {
                Some(l) => write!(f, "UnsatisfiedLinkError: {symbol} (library {l})"),
                None => write!(f, "UnsatisfiedLinkError: {symbol}"),
            },
            ShimError::Dex(m) => write!(f, "dex: {m}"),
            ShimError::Encode(m) => write!(f, "encode: {m}"),
        }
    }
}

impl std::error::Error for ShimError {}

impl From<VfsError> for ShimError {
    fn from(e: VfsError) -> ShimError {
        ShimError::Vfs(e)
    }
}

/// Why a URL could not be split into capture-safe parts.
///
/// Distinct from a *valid* URL with a query string: a query string is not an
/// error, it is silently stripped. These are the shapes that cannot yield a
/// scheme/host/path triple at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlProblem {
    Empty,
    TooLong,
    /// A control character or a raw space. NUL in particular would let an app
    /// forge a field boundary in any consumer that is not a strict JSON parser.
    IllegalByte,
    /// No `scheme:` prefix at all.
    NoScheme,
    /// The host is empty (e.g. `http:///path`).
    NoHost,
    /// `user:pass@host` present. The shim never wants credentials, and it will
    /// not even try to redact them out of a host field — it refuses the URL.
    UserInfo,
    /// A scheme outside the shim's recognised set.
    UnsupportedScheme,
    /// The port is not a decimal number in 1..=65535.
    BadPort,
}

impl fmt::Display for UrlProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UrlProblem::Empty => "empty",
            UrlProblem::TooLong => "longer than 4096 bytes",
            UrlProblem::IllegalByte => "contains a control character or space",
            UrlProblem::NoScheme => "no scheme",
            UrlProblem::NoHost => "no host",
            UrlProblem::UserInfo => "carries userinfo (credentials are never accepted)",
            UrlProblem::UnsupportedScheme => "unsupported scheme",
            UrlProblem::BadPort => "port is not 1..=65535",
        };
        f.write_str(s)
    }
}

/// Why a path was refused by the in-memory VFS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathProblem {
    /// Did not begin with `/`.
    NotAbsolute,
    /// Contained a NUL, a control character, or a lone surrogate escape.
    IllegalByte,
    /// Longer than [`crate::vfs::MAX_PATH_BYTES`].
    TooLong,
    /// More components than [`crate::vfs::MAX_DEPTH`].
    TooDeep,
    /// `..` escaped above the VFS root. Never resolved, never clamped.
    EscapesRoot,
}

impl fmt::Display for PathProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PathProblem::NotAbsolute => "not absolute",
            PathProblem::IllegalByte => "illegal byte",
            PathProblem::TooLong => "too long",
            PathProblem::TooDeep => "too deep",
            PathProblem::EscapesRoot => "escapes the VFS root",
        };
        f.write_str(s)
    }
}

/// A VFS operation that failed. Mirrors the oracle's `fs_access.result` enum
/// so a substrate access and a device access are directly comparable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    NoEntry,
    Denied,
    IsDirectory,
    NotDirectory,
    Exists,
    TooManyEntries,
    OutOfSpace,
    /// A path that is legal but the VFS refuses, e.g. `/dev/binder`.
    DeviceNotPresent,
}

impl VfsError {
    /// Stable machine-readable kind.
    pub fn kind(self) -> &'static str {
        match self {
            VfsError::NoEntry => "enoent",
            VfsError::Denied => "eacces",
            VfsError::IsDirectory => "eisdir",
            VfsError::NotDirectory => "enotdir",
            VfsError::Exists => "eexist",
            VfsError::TooManyEntries => "enospc",
            VfsError::OutOfSpace => "enospc",
            VfsError::DeviceNotPresent => "enoent",
        }
    }

    /// The oracle `fs_access.result` token for this outcome.
    pub fn oracle_result(self) -> &'static str {
        match self {
            VfsError::NoEntry | VfsError::DeviceNotPresent => "enoent",
            VfsError::Denied => "eacces",
            VfsError::IsDirectory => "eisdir",
            VfsError::NotDirectory => "enotdir",
            VfsError::Exists => "eexist",
            VfsError::TooManyEntries | VfsError::OutOfSpace => "enospc",
        }
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

/// The outcome of a network attempt. There is exactly one, and it is a failure:
/// the substrate has no egress and never will. The type exists so that this is
/// not a value the code can forget to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenial {
    /// The exception class the shim reports to the app, matching what a real
    /// unreachable network produces. `java.net.ConnectException`, because
    /// `SUB.NET.EGRESS`'s documented symptom is a silent spinner and a
    /// `ConnectException` is the honest closest analogue.
    pub exception_class: &'static str,
    /// The synthetic errno-shaped code.
    pub code: &'static str,
}

impl Default for EgressDenial {
    fn default() -> EgressDenial {
        EgressDenial {
            exception_class: "java.net.ConnectException",
            code: "ECONNREFUSED_SUBSTRATE_EGRESS_DENIED",
        }
    }
}

impl fmt::Display for EgressDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.exception_class, self.code)
    }
}
