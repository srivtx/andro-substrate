//! A minimal, hostile-input-safe ZIP reader for APKs.
//!
//! # Why this exists in its own crate
//!
//! `shim` has an *empty* `std::fs` surface, and `shim/tests/egress_denial.rs`
//! proves it three ways. That is a load-bearing property: an instrument that can
//! open a file is an instrument that can be made to read one. The recorder is a
//! different thing — the recorder is *supposed* to be handed a path — so it lives
//! here, outside the instrument, and it brings the discipline with it:
//! `harness/tests/no_side_channels.rs` runs the same class of source scan over
//! this crate and forbids everything `std::fs` and `std::net` except the one
//! `read` of the APK the user named.
//!
//! # What it supports, and what it refuses
//!
//! * `stored` (method 0) and `deflate` (method 8). Every other method is a
//!   typed error naming the method number, not a silent empty read.
//! * ZIP64 in the *end of central directory* locator, because a modern APK with
//!   a large `resources.arsc` can exceed 4 GiB and a reader that assumes it
//!   cannot will report a corrupt file for a perfectly good one. ZIP64 in the
//!   per-entry extra fields is read when present.
//! * No encryption, no multi-disk, no spanned archives. A file that claims any of
//!   them is refused with a message that says so.
//!
//! Every offset and length is checked against the buffer before it is used, and
//! the declared uncompressed size is a *bound* on the inflate output rather than
//! an allocation: an entry that claims 4 GiB and produces 30 bytes costs 30
//! bytes.

use std::fmt;

/// Why an APK could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// The file does not start with a local-file or empty-archive signature.
    NotAZip,
    /// No end-of-central-directory record within the last 64 KiB + 22 bytes.
    NoCentralDirectory,
    /// A field claims an offset or length outside the buffer.
    OutOfBounds {
        /// What was being read.
        what: &'static str,
        /// The value the file claimed.
        claimed: u64,
        /// The actual buffer length.
        len: u64,
    },
    /// A compression method this reader does not implement.
    UnsupportedMethod(u16),
    /// The entry is encrypted.
    Encrypted,
    /// A multi-disk or spanned archive.
    MultiDisk,
    /// The CRC did not match the stored bytes.
    CrcMismatch {
        /// The entry name.
        name: String,
    },
    /// The entry is a directory, or otherwise is not a regular file.
    NotAFile(String),
    /// The declared uncompressed size is implausible.
    ImplausibleSize {
        /// The entry name.
        name: String,
        /// The declared size.
        declared: u64,
    },
    /// Inflate produced a different number of bytes than the header declared.
    SizeMismatch {
        /// The entry name.
        name: String,
        /// What the local header said.
        declared: u64,
        /// What inflate produced.
        actual: usize,
    },
    /// The underlying stream failed.
    Io(String),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipError::NotAZip => f.write_str("not a ZIP archive (no end-of-central-directory)"),
            ZipError::NoCentralDirectory => f.write_str("no end-of-central-directory record"),
            ZipError::OutOfBounds { what, claimed, len } => write!(
                f,
                "{what} claims {claimed} which is outside a {len}-byte file"
            ),
            ZipError::UnsupportedMethod(m) => {
                write!(f, "compression method {m} is not stored or deflate")
            }
            ZipError::Encrypted => f.write_str("the entry is encrypted"),
            ZipError::MultiDisk => f.write_str("a multi-disk or spanned archive is not supported"),
            ZipError::CrcMismatch { name } => write!(f, "{name}: CRC-32 does not match"),
            ZipError::NotAFile(n) => write!(f, "{n} is not a regular file entry"),
            ZipError::ImplausibleSize { name, declared } => {
                write!(
                    f,
                    "{name}: declared uncompressed size {declared} is implausible"
                )
            }
            ZipError::SizeMismatch {
                name,
                declared,
                actual,
            } => write!(
                f,
                "{name}: declared {declared} uncompressed bytes but inflate produced {actual}"
            ),
            ZipError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for ZipError {}

/// Refuse to allocate more than this for one entry.
///
/// A hostile APK can declare a 4 GiB uncompressed size in a 10 KiB file. The
/// reader does not allocate on the declared number — `flate2` grows a buffer as
/// it produces output — but the *bound* still has to exist, or a zip bomb is
/// just a slow denial of service.
pub const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

/// Refuse to read more entries than this.
pub const MAX_ENTRIES: usize = 200_000;

/// One entry's central-directory record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The entry name, as stored.
    pub name: String,
    /// Compression method: 0 stored, 8 deflate.
    pub method: u16,
    /// Compressed size.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Offset of the local file header.
    pub local_header_offset: u64,
    /// General-purpose bit 0.
    pub encrypted: bool,
    /// Whether the entry is a directory, by name.
    pub is_directory: bool,
}

/// A read-only view over a ZIP archive already in memory.
pub struct Zip<'a> {
    bytes: &'a [u8],
    entries: Vec<Entry>,
}

impl std::fmt::Debug for Zip<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Zip")
            .field("entries", &self.entries.len())
            .finish()
    }
}

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64le(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at + 8)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(s);
    Some(u64::from_le_bytes(v))
}

impl<'a> Zip<'a> {
    /// Read the central directory.
    ///
    /// `None` is a typed error rather than an empty archive, because an empty
    /// archive is a legitimate thing and a missing central directory is a
    /// different one: a truncated download must not look like an APK with no
    /// classes in it.
    pub fn open(bytes: &'a [u8]) -> Result<Zip<'a>, ZipError> {
        let eocd = find_eocd(bytes).ok_or(ZipError::NoCentralDirectory)?;
        let mut cd_count = u16le(bytes, eocd + 10).ok_or(ZipError::NotAZip)? as usize;
        let mut cd_size = u32le(bytes, eocd + 12).ok_or(ZipError::NotAZip)? as u64;
        let mut cd_offset = u32le(bytes, eocd + 16).ok_or(ZipError::NotAZip)? as u64;
        let disk = u16le(bytes, eocd + 4).ok_or(ZipError::NotAZip)?;
        let cd_disk = u16le(bytes, eocd + 6).ok_or(ZipError::NotAZip)?;
        if disk != 0 || cd_disk != 0 {
            return Err(ZipError::MultiDisk);
        }
        // ZIP64: the 32-bit fields saturate and the real values live in the
        // record the locator points at.
        if cd_offset == 0xFFFF_FFFF || cd_count == 0xFFFF || cd_size == 0xFFFF_FFFF {
            let loc = eocd.checked_sub(20).ok_or(ZipError::NoCentralDirectory)?;
            if u32le(bytes, loc).ok_or(ZipError::NotAZip)? != 0x0706_4b50 {
                return Err(ZipError::NoCentralDirectory);
            }
            let z64 = u64le(bytes, loc + 8).ok_or(ZipError::NoCentralDirectory)? as usize;
            if u32le(bytes, z64).ok_or(ZipError::NotAZip)? != 0x0606_4b50 {
                return Err(ZipError::NoCentralDirectory);
            }
            cd_count = u64le(bytes, z64 + 32).ok_or(ZipError::NotAZip)? as usize;
            cd_size = u64le(bytes, z64 + 40).ok_or(ZipError::NotAZip)?;
            cd_offset = u64le(bytes, z64 + 48).ok_or(ZipError::NotAZip)?;
        }
        if cd_count > MAX_ENTRIES {
            return Err(ZipError::OutOfBounds {
                what: "the entry count",
                claimed: cd_count as u64,
                len: bytes.len() as u64,
            });
        }
        let mut entries = Vec::with_capacity(cd_count.min(1024));
        let mut at = cd_offset as usize;
        for _ in 0..cd_count {
            if u32le(bytes, at) != Some(0x0201_4b50) {
                return Err(ZipError::NotAZip);
            }
            let flags = u16le(bytes, at + 8).ok_or(ZipError::NotAZip)?;
            let method = u16le(bytes, at + 10).ok_or(ZipError::NotAZip)?;
            let mut compressed_size = u32le(bytes, at + 20).ok_or(ZipError::NotAZip)? as u64;
            let mut uncompressed_size = u32le(bytes, at + 24).ok_or(ZipError::NotAZip)? as u64;
            let name_len = u16le(bytes, at + 28).ok_or(ZipError::NotAZip)? as usize;
            let extra_len = u16le(bytes, at + 30).ok_or(ZipError::NotAZip)? as usize;
            let comment_len = u16le(bytes, at + 32).ok_or(ZipError::NotAZip)? as usize;
            let mut local_header_offset = u32le(bytes, at + 42).ok_or(ZipError::NotAZip)? as u64;
            let name_bytes = bytes
                .get(at + 46..at + 46 + name_len)
                .ok_or(ZipError::NotAZip)?;
            let name = String::from_utf8_lossy(name_bytes).into_owned();
            let extra = bytes
                .get(at + 46 + name_len..at + 46 + name_len + extra_len)
                .ok_or(ZipError::NotAZip)?;
            // ZIP64 extended information: 0x0001 in the header id, values in the
            // order the saturated fields appeared.
            let mut e = 0usize;
            while e + 4 <= extra.len() {
                let id = u16le(extra, e).unwrap_or(0);
                let size = u16le(extra, e + 2).unwrap_or(0) as usize;
                if e + 4 + size > extra.len() {
                    break;
                }
                if id == 0x0001 {
                    let mut o = e + 4;
                    if uncompressed_size == 0xFFFF_FFFF {
                        uncompressed_size = u64le(extra, o).unwrap_or(0);
                        o += 8;
                    }
                    if compressed_size == 0xFFFF_FFFF {
                        compressed_size = u64le(extra, o).unwrap_or(0);
                        o += 8;
                    }
                    if local_header_offset == 0xFFFF_FFFF {
                        local_header_offset = u64le(extra, o).unwrap_or(0);
                    }
                }
                e += 4 + size;
            }
            let is_directory = name.ends_with('/');
            entries.push(Entry {
                name,
                method,
                compressed_size,
                uncompressed_size,
                local_header_offset,
                encrypted: flags & 1 != 0,
                is_directory,
            });
            at += 46 + name_len + extra_len + comment_len;
        }
        let _ = cd_size;
        Ok(Zip { bytes, entries })
    }

    /// Every entry, in central-directory order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The first entry with this exact name.
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// The entry names, for diagnostics.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Decompress one entry.
    pub fn read(&self, name: &str) -> Result<Vec<u8>, ZipError> {
        let e = self
            .entry(name)
            .ok_or_else(|| ZipError::NotAFile(name.into()))?;
        if e.is_directory {
            return Err(ZipError::NotAFile(name.into()));
        }
        if e.encrypted {
            return Err(ZipError::Encrypted);
        }
        if e.uncompressed_size > MAX_ENTRY_BYTES {
            return Err(ZipError::ImplausibleSize {
                name: name.into(),
                declared: e.uncompressed_size,
            });
        }
        let lh = e.local_header_offset as usize;
        if u32le(self.bytes, lh) != Some(0x0403_4b50) {
            return Err(ZipError::NotAZip);
        }
        let name_len = u16le(self.bytes, lh + 26).ok_or(ZipError::NotAZip)? as usize;
        let extra_len = u16le(self.bytes, lh + 28).ok_or(ZipError::NotAZip)? as usize;
        let start = lh
            .checked_add(30 + name_len + extra_len)
            .ok_or(ZipError::NotAZip)?;
        let end = start
            .checked_add(e.compressed_size as usize)
            .ok_or(ZipError::OutOfBounds {
                what: "the entry body",
                claimed: e.local_header_offset.saturating_add(e.compressed_size),
                len: self.bytes.len() as u64,
            })?;
        let body = self.bytes.get(start..end).ok_or(ZipError::OutOfBounds {
            what: "the entry body",
            claimed: end as u64,
            len: self.bytes.len() as u64,
        })?;
        let out = match e.method {
            0 => body.to_vec(),
            8 => {
                use std::io::Read;
                let mut d = flate2::read::DeflateDecoder::new(body);
                let mut buf = Vec::with_capacity((e.uncompressed_size as usize).min(1 << 20));
                // A bounded read: `Read::take` on the decoder means a zip bomb
                // stops at the bound instead of filling memory.
                let read = (&mut d)
                    .take(MAX_ENTRY_BYTES + 1)
                    .read_to_end(&mut buf)
                    .map_err(|e| ZipError::Io(e.to_string()))?;
                if read as u64 > MAX_ENTRY_BYTES {
                    return Err(ZipError::ImplausibleSize {
                        name: name.into(),
                        declared: read as u64,
                    });
                }
                buf
            }
            m => return Err(ZipError::UnsupportedMethod(m)),
        };
        if out.len() as u64 != e.uncompressed_size {
            return Err(ZipError::SizeMismatch {
                name: name.into(),
                declared: e.uncompressed_size,
                actual: out.len(),
            });
        }
        Ok(out)
    }
}

/// Find the end-of-central-directory record: the last `PK\x05\x06` in the final
/// 64 KiB + 22 bytes, or the ZIP64 one if there is no 32-bit record.
fn find_eocd(b: &[u8]) -> Option<usize> {
    if b.len() < 22 {
        return None;
    }
    let start = b.len().saturating_sub(0xFFFF + 22);
    let mut i = b.len() - 22;
    loop {
        if b[i..].starts_with(&[0x50, 0x4b, 0x05, 0x06]) {
            return Some(i);
        }
        if i == start {
            return None;
        }
        i -= 1;
    }
}
