//! Rooted path resolution: a `..` that escapes the root is an **error**, never
//! a clamp.
//!
//! # Why this file exists in a code generator
//!
//! A generated host answers `File`, `FileInputStream`, `SharedPreferences` and
//! `AssetManager` calls for an app whose paths it has never seen. It must
//! answer them *somewhere*, and the somewhere has to be bounded. The shim
//! already made this decision and documented the trap; it is repeated here
//! because a synthesiser makes the mistake *more* easily, not less:
//!
//! > silently clamping `/data/../../etc/passwd` to `/etc/passwd` makes the host
//! > lie
//!
//! Consider what clamping actually does to a recording. The app opens
//! `/data/data/eu.ln.gita/files/../../../../etc/hosts`. Under a clamp the host
//! reads a file it has — `/etc/hosts` — and records a *successful read of a
//! plausible path*. Under an error the host records a refused open and the
//! attempt is visible. The clamp is not merely less safe; it is the mechanism
//! by which a recording of an attack becomes a recording of a normal run.
//!
//! # The rule, stated once
//!
//! Resolution is lexical and happens **entirely inside** [`RootedPath::parse`].
//! There is no public constructor from a resolved string, no accessor that
//! returns a resolved path, and no `Default`. A [`RootedPath`] *is* its
//! resolution: the only way to obtain one is to parse an input, and parsing
//! either produces a path proven to be under the root or produces an error.
//!
//! Symlinks are a second reason this has to be lexical. The generated host has
//! no filesystem, so it cannot have a symlink, so a `..` can only ever be a
//! lexical `..` — which means lexical resolution is not an approximation here,
//! it is the complete semantics.

use core::fmt;

/// Longest path the resolver will look at. Matches the oracle's `android_path`
/// ceiling of 1024. Longer is refused, not truncated: a truncated path is a
/// *different* path, and answering a request for one as if it were the other is
/// the quiet wrongness the format forbids.
pub const MAX_PATH_BYTES: usize = 1024;

/// Longest single segment. The shim's resolver carries the same ceiling for
/// the same reason: a megabyte-long segment is not a path, it is an allocation
/// attack against the host.
pub const MAX_SEGMENT_BYTES: usize = 255;

/// Deepest path. Android's own `PATH_MAX` is 4096, but a generated host's
/// resident set is the browser tab's, so the ceiling is far tighter than the
/// platform's and a refusal is cheap and safe.
pub const MAX_DEPTH: usize = 64;

/// Why a path was refused. Every variant is a *refusal*, never a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathProblem {
    /// Empty input. An empty path addresses the root, which is a directory,
    /// and answering a request to open it with something is worse than saying
    /// no.
    Empty,
    /// A NUL or other control byte. Java strings can carry one; the shim's
    /// filesystem keys cannot, and truncating at the NUL would silently
    /// address a different path.
    IllegalByte,
    /// Longer than [`MAX_PATH_BYTES`], or a segment longer than
    /// [`MAX_SEGMENT_BYTES`].
    TooLong,
    /// More segments than [`MAX_DEPTH`].
    TooDeep,
    /// A relative path. The host has no working directory to resolve against,
    /// and inventing one would be a fabrication.
    NotAbsolute,
    /// `..` that would climb above the root.
    ///
    /// **This is the case the whole module is about.** It is an error and not
    /// a clamp, and `tests/path_traversal.rs` asserts it on
    /// `/data/../../etc/passwd` by name.
    EscapesRoot,
}

impl fmt::Display for PathProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PathProblem::Empty => "empty path",
            PathProblem::IllegalByte => "path carries a control byte",
            PathProblem::TooLong => "path exceeds the length ceiling",
            PathProblem::TooDeep => "path exceeds the depth ceiling",
            PathProblem::NotAbsolute => "path is not absolute",
            PathProblem::EscapesRoot => "path escapes the host root via `..`",
        };
        f.write_str(s)
    }
}

/// A path proven to resolve inside the host root.
///
/// There is deliberately no `pub fn new` taking a `&str`: every instance came
/// through [`RootedPath::parse`], which is the only place `..` is resolved and
/// the only place an escape can be caught. `#[non_exhaustive]` keeps a
/// future field from being added by construction rather than by a constructor
/// that skips validation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub struct RootedPath {
    /// The normalised absolute path, always starting with `/` and never
    /// containing `.`, `..`, an empty segment, or a trailing slash except for
    /// the root itself.
    normalised: String,
    /// Number of segments, so `/a/b/c` is distinguishable from `/a/bc` without
    /// walking the string.
    depth: usize,
}

impl RootedPath {
    /// The root itself, `/`. Always available, so an empty listing of an empty
    /// root is a representable answer rather than an error.
    pub fn root() -> RootedPath {
        RootedPath {
            normalised: "/".to_string(),
            depth: 0,
        }
    }

    /// Resolve an absolute path lexically, refusing anything that escapes.
    ///
    /// The resolution rules, in the order they are applied:
    ///
    /// 1. length ceilings, then a byte scan for NUL and C0 controls;
    /// 2. `..` resolved against a segment stack, so `/a/../b` is `/b`;
    /// 3. a pop past empty is [`PathProblem::EscapesRoot`], not a clamp and
    ///    not a saturating stay-at-root;
    /// 4. `.` and empty segments dropped, so `/a//b/` is `/a/b`.
    pub fn parse(input: &str) -> Result<RootedPath, PathProblem> {
        if input.is_empty() {
            return Err(PathProblem::Empty);
        }
        if input.len() > MAX_PATH_BYTES {
            return Err(PathProblem::TooLong);
        }
        if input.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
            return Err(PathProblem::IllegalByte);
        }
        if !input.starts_with('/') {
            return Err(PathProblem::NotAbsolute);
        }

        // A bounded stack of segment *lengths* plus offsets would be faster,
        // but the depth ceiling is 64 and the byte ceiling is 1024, so the
        // allocation is small and a `Vec<&str>` of borrows keeps the borrow
        // checker out of the question entirely.
        let mut segments: Vec<&str> = Vec::new();
        for seg in input.split('/') {
            if seg.is_empty() || seg == "." {
                continue;
            }
            if seg == ".." {
                if segments.pop().is_none() {
                    // The escape. Not clamped to "/etc/passwd" and not
                    // clamped to "/": refused, and the caller records that.
                    return Err(PathProblem::EscapesRoot);
                }
                continue;
            }
            if seg.len() > MAX_SEGMENT_BYTES {
                return Err(PathProblem::TooLong);
            }
            if segments.len() >= MAX_DEPTH {
                return Err(PathProblem::TooDeep);
            }
            segments.push(seg);
        }

        if segments.is_empty() {
            return Ok(RootedPath::root());
        }
        let mut normalised = String::with_capacity(input.len());
        for s in &segments {
            normalised.push('/');
            normalised.push_str(s);
        }
        Ok(RootedPath {
            normalised,
            depth: segments.len(),
        })
    }

    /// The normalised path.
    pub fn as_str(&self) -> &str {
        &self.normalised
    }

    /// Number of segments. The root is 0.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Whether this is the root.
    pub fn is_root(&self) -> bool {
        self.depth == 0
    }

    /// The final segment, if any. The root has none.
    pub fn file_name(&self) -> Option<&str> {
        if self.depth == 0 {
            None
        } else {
            self.normalised.rsplit('/').next()
        }
    }

    /// The parent directory, or `None` at the root.
    ///
    /// Clamped to the root on purpose, and this is the one place in the file a
    /// clamp is correct: the parent *of the root* is the root, because unlike
    /// a `..` in the input this is a statement about a path that is already
    /// proven to be inside the root. There is nothing to escape to.
    pub fn parent(&self) -> Option<RootedPath> {
        if self.depth == 0 {
            return None;
        }
        match self.normalised.rfind('/') {
            None | Some(0) => Some(RootedPath::root()),
            Some(i) => Some(RootedPath {
                normalised: self.normalised[..i].to_string(),
                depth: self.depth - 1,
            }),
        }
    }

    /// Resolve `input` as relative to `self`.
    ///
    /// The result is subject to exactly the same escape rule: `join` cannot
    /// produce a path outside the root, and an input that tries is refused
    /// rather than clamped. This is what makes `dir.join("../../etc")` an
    /// error instead of a hole.
    pub fn join(&self, input: &str) -> Result<RootedPath, PathProblem> {
        if input.is_empty() {
            return Ok(self.clone());
        }
        if input.len() > MAX_PATH_BYTES {
            return Err(PathProblem::TooLong);
        }
        if input.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
            return Err(PathProblem::IllegalByte);
        }
        if input.starts_with('/') {
            // An absolute input is resolved on its own merits, so
            // `/data` joined with `/../../etc` still escapes and is still
            // refused. Treating it as relative would be a second, subtler way
            // to lose the invariant.
            return RootedPath::parse(input);
        }
        let combined_len = self.normalised.len().saturating_add(input.len()).saturating_add(1);
        if combined_len > MAX_PATH_BYTES {
            return Err(PathProblem::TooLong);
        }
        RootedPath::parse(&format!("{}/{}", self.normalised, input))
    }

    /// Every prefix of this path, root first, including the path itself.
    ///
    /// What a directory listing is, and what `mkdirs` has to create. Derived by
    /// truncation rather than by joining, so it cannot disagree with
    /// [`RootedPath::as_str`].
    pub fn ancestors(&self) -> Vec<RootedPath> {
        let mut out = Vec::with_capacity(self.depth + 1);
        out.push(RootedPath::root());
        let mut acc = String::new();
        for seg in self.normalised.split('/').filter(|s| !s.is_empty()) {
            acc.push('/');
            acc.push_str(seg);
            out.push(RootedPath {
                normalised: acc.clone(),
                depth: out.len(),
            });
        }
        out
    }

    /// Whether `other` is this path or lies under it, on segment boundaries.
    ///
    /// Segment-aware on purpose: `/data/app` is not under `/data/a`. A
    /// `starts_with` on strings would say it is, and that is how a prefix
    /// check becomes a sandbox escape.
    pub fn contains(&self, other: &RootedPath) -> bool {
        if other.depth < self.depth {
            return false;
        }
        if self.depth == 0 {
            return true;
        }
        other.normalised.starts_with(&self.normalised)
            && other
                .normalised
                .as_bytes()
                .get(self.normalised.len())
                .is_none_or(|b| *b == b'/')
    }
}

impl fmt::Display for RootedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalised)
    }
}

impl AsRef<str> for RootedPath {
    fn as_ref(&self) -> &str {
        &self.normalised
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> String {
        RootedPath::parse(s).map(|x| x.to_string()).unwrap_or_else(|e| format!("ERR({e})"))
    }

    #[test]
    fn normalisation_is_lexical() {
        assert_eq!(p("/a/b/../c"), "/a/c");
        assert_eq!(p("/a/./b//c/"), "/a/b/c");
        assert_eq!(p("/"), "/");
        assert_eq!(p("/a/.."), "/");
        assert_eq!(p("/../"), "ERR(path escapes the host root via `..`)");
    }

    #[test]
    fn escaping_the_root_is_refused_not_clamped() {
        // The case the module is named for. `/etc/passwd` is what a clamp
        // would produce; the assertion is that it is not producible.
        assert_eq!(
            RootedPath::parse("/data/../../etc/passwd"),
            Err(PathProblem::EscapesRoot)
        );
        assert_eq!(
            RootedPath::parse("/../../../etc/shadow"),
            Err(PathProblem::EscapesRoot)
        );
        assert_eq!(RootedPath::parse("/.."), Err(PathProblem::EscapesRoot));
        assert_eq!(RootedPath::parse("/a/../.."), Err(PathProblem::EscapesRoot));
    }

    #[test]
    fn join_cannot_escape_either() {
        let dir = RootedPath::parse("/data/data/eu.ln.gita/files").unwrap_or(RootedPath::root());
        assert_eq!(dir.depth(), 4);
        // Climbing exactly to the root is legal: four `..` over a four-deep base
        // lands on `/`, which is inside the host root. This is not a clamp — the
        // resolver genuinely consumed four `..`.
        assert_eq!(
            dir.join("../../../../etc/passwd").map(|p| p.to_string()),
            Ok("/etc/passwd".to_string())
        );
        // One more `..` than the base is deep has nowhere to go, and is refused.
        // That is the case a clamp would answer with `/etc/passwd` again, having
        // silently pretended the extra `..` did not happen.
        assert_eq!(
            dir.join("../../../../../etc/passwd"),
            Err(PathProblem::EscapesRoot)
        );
        // An absolute input is judged on its own merits, not treated as relative.
        assert_eq!(
            dir.join("/data/../../etc"),
            Err(PathProblem::EscapesRoot)
        );
        assert_eq!(
            dir.join("notes.txt").map(|p| p.to_string()),
            Ok("/data/data/eu.ln.gita/files/notes.txt".to_string())
        );
    }

    #[test]
    fn contains_is_segment_aware() {
        let d = RootedPath::parse("/data/app").unwrap_or(RootedPath::root());
        let a = RootedPath::parse("/data/app/x").unwrap_or(RootedPath::root());
        let b = RootedPath::parse("/data/appendix").unwrap_or(RootedPath::root());
        assert!(d.contains(&a));
        assert!(!d.contains(&b), "a string prefix check would wrongly say true here");
        assert!(d.contains(&d));
        assert!(!a.contains(&d));
        assert!(RootedPath::root().contains(&b));
    }

    #[test]
    fn hostile_paths_are_refused_rather_than_panicking() {
        for bad in [
            "",
            "relative/path",
            ".",
            "..",
            "/a\0b",
            "/a\nb",
            &format!("/{}", "a".repeat(MAX_SEGMENT_BYTES + 1)),
            &format!("/{}", "a".repeat(MAX_PATH_BYTES + 1)),
            &format!("/{}", vec!["ab"; 100].join("/")),
        ] {
            assert!(RootedPath::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn depth_and_ancestors_agree_with_the_string() {
        let p = RootedPath::parse("/data/data/pkg/files/a.txt").unwrap_or(RootedPath::root());
        assert_eq!(p.depth(), 5);
        assert_eq!(p.file_name(), Some("a.txt"));
        let chain: Vec<String> = p.ancestors().iter().map(|x| x.to_string()).collect();
        assert_eq!(
            chain,
            vec!["/", "/data", "/data/data", "/data/data/pkg", "/data/data/pkg/files", "/data/data/pkg/files/a.txt"]
        );
        // Every ancestor really is a prefix of the whole, on a boundary.
        for a in p.ancestors() {
            assert!(a.contains(&p));
        }
        assert_eq!(RootedPath::root().parent(), None);
        assert_eq!(RootedPath::root().ancestors().len(), 1);
    }
}
