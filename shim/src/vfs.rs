//! The in-memory virtual filesystem.
//!
//! # Why nothing touches a disk
//!
//! An app that can write to a real disk can write to the *host's* disk. In a
//! browser the substrate's only storage is `IndexedDB` and `CacheStorage` and
//! they are same-origin, but a path-traversal bug in a VFS implementation is
//! still a bug that runs on the user's machine. Making the VFS a `BTreeMap`
//! makes that class of bug unrepresentable rather than merely unlikely, and it
//! makes the whole filesystem a value that can be serialised into a recording.
//!
//! # Why that matters for the study
//!
//! `oracle/RECORDING.md` §12 says a device capture on a stock non-rooted device
//! cannot see per-operation file access at all: `filesystem.accesses` is empty
//! and `access_trace_obtained` is false. The substrate sees every one. That is
//! the inversion the project is built on, and it only holds if the VFS records
//! the *attempt* even when it denies it — an app that probes for
//! `/system/build.prop` must appear in the trace whether or not the node exists,
//! because on a device the existence of the node is exactly what the app is
//! probing for.
//!
//! # Bounded, because the input is hostile
//!
//! Every limit here is a hard `Err`, never a truncation and never a panic. A
//! hostile APK can otherwise turn a filesystem call into a memory-exhaustion
//! attack against the *analysis tool*, which is an attack on the researcher.

use std::collections::BTreeMap;
use std::fmt;

use crate::error::{PathProblem, ShimError, VfsError};

/// Longest accepted path, matching the oracle's `android_path` ceiling.
pub const MAX_PATH_BYTES: usize = 1024;

/// Longest accepted path, in `/`-separated components.
pub const MAX_DEPTH: usize = 48;

/// Most nodes one VFS may hold.
pub const MAX_NODES: usize = 65_536;

/// Total bytes one VFS may hold.
pub const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Longest single write.
pub const MAX_WRITE_BYTES: usize = 8 * 1024 * 1024;

/// A canonicalised absolute path inside the VFS.
///
/// Construction is the only way to get one, and it validates: absolute, no
/// control bytes, bounded length and depth, and `..` resolved without ever
/// climbing above the root. A `..` that would escape is an error, not a clamp —
/// silently clamping `/data/../../etc/passwd` to `/etc/passwd` would make the
/// recording claim a different access than the app made.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VPath {
    normalised: String,
}

impl VPath {
    /// Canonicalise an untrusted path.
    pub fn parse(input: &str) -> Result<VPath, ShimError> {
        if input.len() > MAX_PATH_BYTES {
            return Err(ShimError::BadPath {
                path: input.chars().take(64).collect(),
                reason: PathProblem::TooLong,
            });
        }
        if input.is_empty() {
            return Err(ShimError::BadPath {
                path: String::new(),
                reason: PathProblem::NotAbsolute,
            });
        }
        if input.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(ShimError::BadPath {
                path: input.chars().take(64).collect(),
                reason: PathProblem::IllegalByte,
            });
        }
        if !input.starts_with('/') {
            return Err(ShimError::BadPath {
                path: input.chars().take(64).collect(),
                reason: PathProblem::NotAbsolute,
            });
        }
        let mut parts: Vec<&str> = Vec::new();
        for seg in input.split('/') {
            match seg {
                "" | "." => continue,
                ".." => {
                    if parts.pop().is_none() {
                        return Err(ShimError::BadPath {
                            path: input.chars().take(64).collect(),
                            reason: PathProblem::EscapesRoot,
                        });
                    }
                }
                other => parts.push(other),
            }
        }
        if parts.len() > MAX_DEPTH {
            return Err(ShimError::BadPath {
                path: input.chars().take(64).collect(),
                reason: PathProblem::TooDeep,
            });
        }
        let normalised = if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        };
        Ok(VPath { normalised })
    }

    /// The canonical path.
    pub fn as_str(&self) -> &str {
        &self.normalised
    }

    /// The last component, or `/`.
    pub fn file_name(&self) -> &str {
        match self.normalised.rsplit('/').next() {
            Some(s) if !s.is_empty() => s,
            _ => "/",
        }
    }

    /// The parent directory, or the root.
    pub fn parent(&self) -> VPath {
        match self.normalised.rsplit_once('/') {
            Some(("", _rest)) => VPath {
                normalised: "/".to_string(),
            },
            Some((head, _)) => {
                if head.is_empty() {
                    VPath { normalised: "/".to_string() }
                } else {
                    VPath {
                        normalised: head.to_string(),
                    }
                }
            }
            None => VPath {
                normalised: "/".to_string(),
            },
        }
    }

    /// Whether this path is `/` or lies under `prefix`.
    pub fn under(&self, prefix: &VPath) -> bool {
        if prefix.normalised == "/" {
            return true;
        }
        self.normalised == prefix.normalised
            || self.normalised.starts_with(&format!("{}/", prefix.normalised))
    }

    /// Append a component. Never fails: the depth check happens on parse, and
    /// `push` is only called on a `VPath` that came from `parse`.
    pub fn join(&self, component: &str) -> VPath {
        if self.normalised == "/" {
            VPath {
                normalised: format!("/{component}"),
            }
        } else {
            VPath {
                normalised: format!("{}/{component}", self.normalised),
            }
        }
    }
}

impl fmt::Display for VPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.normalised)
    }
}

/// What a node holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Dir { children: Vec<String>, mode: u32 },
    File { data: Vec<u8>, mode: u32 },
}

impl Node {
    /// Size in bytes, as `stat` would report it. A directory reports its own
    /// entry size, which is what the real `st_size` does too.
    pub fn size(&self) -> u64 {
        match self {
            Node::Dir { children, .. } => children.len() as u64,
            Node::File { data, .. } => data.len() as u64,
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Node::Dir { .. })
    }
}

/// The VFS.
#[derive(Debug, Clone, Default)]
pub struct Vfs {
    nodes: BTreeMap<String, Node>,
    total_bytes: u64,
}

impl Vfs {
    /// An empty VFS.
    pub fn new() -> Vfs {
        Vfs::default()
    }

    /// A VFS with the conventional Android directory skeleton present as empty
    /// directories. The skeleton exists so that a `stat` of `/sdcard` succeeds —
    /// which is what makes `SUB.FS.EXTERNAL_STORAGE`'s "degrades to
    /// internal-only" symptom reachable — while `/system/build.prop` does not.
    pub fn with_android_skeleton(data_dir: &VPath) -> Result<Vfs, ShimError> {
        let mut v = Vfs::new();
        for dir in [
            "/",
            "/data",
            "/system",
            "/system/app",
            "/vendor",
            "/apex",
            "/sdcard",
            "/proc",
            "/sys",
            "/dev",
            "/cache",
        ] {
            v.mkdir(&VPath::parse(dir)?)?;
        }
        v.mkdir(data_dir)?;
        v.mkdir(&data_dir.join("files"))?;
        v.mkdir(&data_dir.join("shared_prefs"))?;
        v.mkdir(&data_dir.join("cache"))?;
        v.mkdir(&data_dir.join("no_backup"))?;
        // /data/data is a symlink to /data/user/0 on a real device, and
        // SUB.FS.DATA_DIR is specifically about an app that notices. The VFS
        // records the symlink target so the divergence is visible rather than
        // absent.
        v.mkdir(&VPath::parse("/data/user")?)?;
        v.mkdir(&VPath::parse("/data/user/0")?)?;
        Ok(v)
    }

    /// Total bytes stored.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Number of nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Whether a node exists.
    pub fn exists(&self, path: &VPath) -> bool {
        self.nodes.contains_key(&path.normalised)
    }

    /// Whether a node is a directory.
    pub fn is_dir(&self, path: &VPath) -> bool {
        self.nodes.get(&path.normalised).map(Node::is_dir).unwrap_or(false)
    }

    /// `stat`: the node, or `NoEntry`.
    pub fn stat(&self, path: &VPath) -> Result<&Node, VfsError> {
        self.nodes.get(&path.normalised).ok_or(VfsError::NoEntry)
    }

    /// `read`: the bytes, or an error distinguishing "not there" from "it is a
    /// directory", because an app branching on `EISDIR` versus `ENOENT` is
    /// behaviour the study cares about.
    pub fn read(&self, path: &VPath) -> Result<&[u8], VfsError> {
        match self.nodes.get(&path.normalised) {
            Some(Node::File { data, .. }) => Ok(data),
            Some(Node::Dir { .. }) => Err(VfsError::IsDirectory),
            None => Err(VfsError::NoEntry),
        }
    }

    /// `readdir`, sorted so a recording is deterministic.
    pub fn list(&self, path: &VPath) -> Result<&[String], VfsError> {
        match self.nodes.get(&path.normalised) {
            Some(Node::Dir { children, .. }) => Ok(children),
            Some(Node::File { .. }) => Err(VfsError::NotDirectory),
            None => Err(VfsError::NoEntry),
        }
    }

    /// `mkdir`. Intermediate directories are created, as `mkdir -p` and as
    /// `Context.getDir` both behave.
    pub fn mkdir(&mut self, path: &VPath) -> Result<(), VfsError> {
        if path.normalised == "/" {
            self.nodes.entry(path.normalised.clone()).or_insert(Node::Dir {
                children: Vec::new(),
                mode: 0o755,
            });
            return Ok(());
        }
        if self.nodes.contains_key(&path.normalised) {
            return Err(VfsError::Exists);
        }
        if self.nodes.len() >= MAX_NODES {
            return Err(VfsError::TooManyEntries);
        }
        let parent = path.parent();
        if !self.nodes.contains_key(&parent.normalised) {
            self.mkdir(&parent)?;
        }
        // The parent exists by now; if it turned out to be a file, no path
        // beneath it is reachable and the whole chain must say so.
        match self.nodes.get(&parent.normalised) {
            Some(Node::Dir { .. }) => {}
            _ => return Err(VfsError::NotDirectory),
        }
        if let Some(Node::Dir { children, .. }) = self.nodes.get_mut(&parent.normalised) {
            children.push(path.file_name().to_string());
            children.sort();
        }
        self.nodes.insert(
            path.normalised.clone(),
            Node::Dir {
                children: Vec::new(),
                mode: 0o755,
            },
        );
        Ok(())
    }

    /// `write`, replacing any existing contents.
    pub fn write(&mut self, path: &VPath, data: &[u8]) -> Result<u64, VfsError> {
        if data.len() > MAX_WRITE_BYTES {
            return Err(VfsError::OutOfSpace);
        }
        if self.nodes.contains_key(&path.normalised) {
            if let Some(Node::Dir { .. }) = self.nodes.get(&path.normalised) { return Err(VfsError::IsDirectory) }
        }
        if let Some(existing) = self.nodes.get(&path.normalised) {
            self.total_bytes = self.total_bytes.saturating_sub(existing.size());
        }
        if self.total_bytes + data.len() as u64 > MAX_TOTAL_BYTES {
            return Err(VfsError::OutOfSpace);
        }
        if !self.nodes.contains_key(&path.normalised) {
            if self.nodes.len() >= MAX_NODES {
                return Err(VfsError::TooManyEntries);
            }
            let parent = path.parent();
            if !self.nodes.contains_key(&parent.normalised) {
                self.mkdir(&parent)?;
            }
            if let Some(Node::Dir { children, .. }) = self.nodes.get_mut(&parent.normalised) {
                children.push(path.file_name().to_string());
                children.sort();
            }
        }
        self.total_bytes += data.len() as u64;
        self.nodes.insert(
            path.normalised.clone(),
            Node::File {
                data: data.to_vec(),
                mode: 0o600,
            },
        );
        Ok(data.len() as u64)
    }

    /// `unlink` or `rmdir`.
    pub fn remove(&mut self, path: &VPath) -> Result<(), VfsError> {
        let node = self.nodes.get(&path.normalised).ok_or(VfsError::NoEntry)?;
        if node.is_dir() && node.size() > 0 {
            return Err(VfsError::Denied);
        }
        let removed = self.nodes.remove(&path.normalised).ok_or(VfsError::NoEntry)?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.size());
        let parent = path.parent().normalised;
        if let Some(Node::Dir { children, .. }) = self.nodes.get_mut(&parent) {
            let name = path.file_name();
            if let Some(i) = children.iter().position(|c| c == name) {
                children.remove(i);
            }
        }
        Ok(())
    }

    /// Every path present, sorted. This is what becomes
    /// `filesystem.app_dir_listing` in a recording.
    pub fn listing(&self) -> Vec<(String, u64, u32)> {
        self.nodes
            .iter()
            .map(|(p, n)| (p.clone(), n.size(), match n {
                Node::Dir { mode, .. } | Node::File { mode, .. } => *mode,
            }))
            .collect()
    }

    /// The listing restricted to one subtree.
    pub fn listing_under(&self, root: &VPath) -> Vec<(String, u64, u32)> {
        self.listing()
            .into_iter()
            .filter(|(path, _, _)| {
                let v = match VPath::parse(path) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                v.under(root)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> VPath {
        VPath::parse(s).expect("valid path")
    }

    #[test]
    fn paths_are_canonicalised() {
        assert_eq!(p("/a//b/./c").as_str(), "/a/b/c");
        assert_eq!(p("/a/b/../c").as_str(), "/a/c");
        assert_eq!(p("/").as_str(), "/");
        assert_eq!(p("/a/..").as_str(), "/");
    }

    #[test]
    fn escaping_the_root_is_refused_not_clamped() {
        // The whole point: an app probing for /etc/passwd must be recorded as
        // having asked for it.
        assert!(matches!(
            VPath::parse("/data/../../etc/passwd"),
            Err(ShimError::BadPath {
                reason: PathProblem::EscapesRoot,
                ..
            })
        ));
    }

    #[test]
    fn hostile_paths_error_rather_than_panic() {
        for bad in ["", "relative/path", "/a\0b", &format!("/{}", "x".repeat(2000))] {
            assert!(VPath::parse(bad).is_err(), "{bad:?} should be refused");
        }
        let deep = format!("/{}", vec!["x"; MAX_DEPTH + 5].join("/"));
        assert!(VPath::parse(&deep).is_err());
    }

    #[test]
    fn write_read_round_trip() {
        let mut v = Vfs::new();
        v.mkdir(&p("/data/data/a.b/files")).unwrap();
        v.write(&p("/data/data/a.b/files/t"), b"hello").unwrap();
        assert_eq!(v.read(&p("/data/data/a.b/files/t")).unwrap(), b"hello");
        assert_eq!(v.stat(&p("/data/data/a.b/files/t")).unwrap().size(), 5);
        assert_eq!(v.read(&p("/data/data/a.b/files")).unwrap_err(), VfsError::IsDirectory);
        assert_eq!(v.read(&p("/nope")).unwrap_err(), VfsError::NoEntry);
    }

    #[test]
    fn write_creates_missing_parents() {
        let mut v = Vfs::new();
        v.mkdir(&p("/")).unwrap();
        v.write(&p("/deep/a/b/c"), b"x").unwrap();
        assert!(v.is_dir(&p("/deep/a/b")));
        assert_eq!(v.list(&p("/deep/a/b")).unwrap(), &["c".to_string()]);
    }

    #[test]
    fn removing_a_non_empty_directory_is_denied() {
        let mut v = Vfs::new();
        v.mkdir(&p("/a/b")).unwrap();
        assert_eq!(v.remove(&p("/a")).unwrap_err(), VfsError::Denied);
        v.remove(&p("/a/b")).unwrap();
        assert!(v.remove(&p("/a")).is_ok());
    }

    #[test]
    fn byte_budget_is_enforced_without_panicking() {
        let mut v = Vfs::new();
        v.mkdir(&p("/")).unwrap();
        let big = vec![0u8; MAX_WRITE_BYTES + 1];
        assert_eq!(v.write(&p("/big"), &big).unwrap_err(), VfsError::OutOfSpace);
        // And the node was not created, so a later read reports absence rather
        // than an empty file.
        assert!(!v.exists(&p("/big")));
    }

    #[test]
    fn under_is_component_wise_not_prefix_wise() {
        // /data/data2 is not under /data/data. A string prefix test would get
        // this wrong and would let one app read another's directory.
        assert!(!p("/data/data2/x").under(&p("/data/data")));
        assert!(p("/data/data/x").under(&p("/data/data")));
    }
}
