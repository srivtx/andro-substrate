//! Central-directory-only ZIP reader, enough to inventory an APK and to lift
//! `classes*.dex` and `AndroidManifest.xml` out of it.
//!
//! ## Why this exists rather than reusing `tools/corpus/zip-central-directory.mjs`
//!
//! Two reasons, both about scope discipline. The corpus tool is owned by
//! another agent's deliverable and this crate must not couple to it; and that
//! module deliberately never decompresses anything, because it was written to
//! classify APKs from HTTP range reads. The predictor needs the bytes of the DEX
//! files, so it needs a second reader.
//!
//! ## Deliberate omissions
//!
//! * No streaming, no `ZipFile` random access: an APK is read whole.
//! * Only `stored` (0) and `deflate` (8) are decompressed. Methods 1–7, 9–14, 93
//!   and 94 are rejected with [`Error::UnsupportedCompression`] rather than
//!   silently mis-read. A real APK uses deflate for everything but occasionally
//!   stores; if that assumption is ever violated the failure is typed, not
//!   wrong.
//! * No encryption, no multi-disk archives, no APK signing block parsing (the
//!   signing block sits between the last local header and the central directory
//!   and is located by the central directory, so it needs no separate handling).
//!
//! Layout offsets follow APPNOTE.TXT 4.3.16 (central directory header),
//! 4.3.16 (EOCD) and 4.5.3 (ZIP64).

use crate::error::{Error, Result};
use serde::Serialize;

const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_EOCD64_LOCATOR: u32 = 0x0706_4b50;

const EOCD_MIN_SIZE: usize = 22;
const CENTRAL_FIXED_SIZE: usize = 46;
const LOCAL_FIXED_SIZE: usize = 30;
const ZIP64_EXTRA_ID: u16 = 0x0001;
const MAX_COMMENT: u64 = 0xffff;
const UTF8_FLAG: u16 = 0x0800;

const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// One central directory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZipEntry {
    /// Path as stored, with `/` separators.
    pub name: String,
    /// Compression method: 0 = stored, 8 = deflate.
    pub method: u16,
    /// Compressed size from the header, or from the ZIP64 extra field.
    pub compressed_size: u64,
    /// Uncompressed size from the header, or from the ZIP64 extra field.
    pub uncompressed_size: u64,
    /// Offset of the local file header.
    pub local_header_offset: u64,
    /// General purpose bit 0.
    pub encrypted: bool,
    /// CRC-32 of the uncompressed data, as declared. Not verified unless the
    /// entry is actually extracted by [`Archive::read_entry`].
    pub crc32: u32,
}

impl ZipEntry {
    /// True for `lib/<abi>/<name>.so`.
    pub fn is_native_lib(&self) -> bool {
        self.name.starts_with("lib/")
            && self.name.ends_with(".so")
            && self.name.matches('/').count() == 2
    }

    /// The ABI directory name (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`, …)
    /// for a `lib/<abi>/*.so` entry, otherwise `None`.
    pub fn abi(&self) -> Option<&str> {
        if !self.is_native_lib() {
            return None;
        }
        let rest = &self.name["lib/".len()..];
        rest.split('/').next()
    }
}

/// A parsed ZIP archive: the entry table plus the original bytes.
#[derive(Debug, Clone)]
pub struct Archive {
    bytes: Vec<u8>,
    entries: Vec<ZipEntry>,
    /// True when the archive used ZIP64 structures.
    pub zip64: bool,
}

impl Archive {
    /// Parse the central directory out of a whole archive.
    pub fn open(bytes: Vec<u8>) -> Result<Archive> {
        let eocd = find_eocd(&bytes).ok_or(Error::NotAZip)?;

        let mut cd_count = u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]) as u64;
        let mut cd_size = u32::from_le_bytes([
            bytes[eocd + 12],
            bytes[eocd + 13],
            bytes[eocd + 14],
            bytes[eocd + 15],
        ]) as u64;
        let mut cd_off = u32::from_le_bytes([
            bytes[eocd + 16],
            bytes[eocd + 17],
            bytes[eocd + 18],
            bytes[eocd + 19],
        ]) as u64;

        let mut zip64 = false;
        // Any of the three ZIP64 sentinels means the ZIP64 record, if present,
        // is authoritative for all three values.
        if cd_count == 0xffff || cd_size == 0xffff_ffff || cd_off == 0xffff_ffff {
            if let Some((count, size, off)) = read_zip64_eocd(&bytes, eocd)? {
                cd_count = count;
                cd_size = size;
                cd_off = off;
                zip64 = true;
            }
        }

        let have = bytes.len() as u64;
        if cd_off + cd_size > have {
            return Err(Error::Truncated {
                what: "central directory",
                need: cd_off + cd_size,
                have,
            });
        }

        let mut entries = Vec::with_capacity(cd_count.min(1 << 20) as usize);
        let mut at = cd_off as usize;
        let end = (cd_off + cd_size) as usize;
        // A declared count is untrusted input: bound the walk by the byte range
        // and stop at the first non-signature, which is a corrupt-count defence
        // as well as a loop guarantee.
        while at + CENTRAL_FIXED_SIZE <= end && entries.len() as u64 <= cd_count {
            let sig = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            if sig != SIG_CENTRAL {
                break;
            }
            let flags = u16::from_le_bytes([bytes[at + 8], bytes[at + 9]]);
            let method = u16::from_le_bytes([bytes[at + 10], bytes[at + 11]]);
            let crc32 = u32::from_le_bytes([
                bytes[at + 16],
                bytes[at + 17],
                bytes[at + 18],
                bytes[at + 19],
            ]);
            let csize = u32::from_le_bytes([
                bytes[at + 20],
                bytes[at + 21],
                bytes[at + 22],
                bytes[at + 23],
            ]) as u64;
            let usize_ = u32::from_le_bytes([
                bytes[at + 24],
                bytes[at + 25],
                bytes[at + 26],
                bytes[at + 27],
            ]) as u64;
            let name_len = u16::from_le_bytes([bytes[at + 28], bytes[at + 29]]) as usize;
            let extra_len = u16::from_le_bytes([bytes[at + 30], bytes[at + 31]]) as usize;
            let comment_len = u16::from_le_bytes([bytes[at + 32], bytes[at + 33]]) as usize;
            let lho = u32::from_le_bytes([
                bytes[at + 42],
                bytes[at + 43],
                bytes[at + 44],
                bytes[at + 45],
            ]) as u64;

            let name_start = at + CENTRAL_FIXED_SIZE;
            let name_end = name_start + name_len;
            let extra_end = name_end + extra_len;
            if extra_end + comment_len > end || extra_end > bytes.len() {
                return Err(Error::Truncated {
                    what: "central directory entry",
                    need: extra_end as u64 + comment_len as u64,
                    have,
                });
            }
            let name = decode_name(&bytes[name_start..name_end], flags);

            let (csize, usize_, lho) =
                apply_zip64_extra(&bytes[name_end..extra_end], csize, usize_, lho)?;

            entries.push(ZipEntry {
                name,
                method,
                compressed_size: csize,
                uncompressed_size: usize_,
                local_header_offset: lho,
                encrypted: flags & 1 != 0,
                crc32,
            });
            at = extra_end + comment_len;
        }

        Ok(Archive {
            bytes,
            entries,
            zip64,
        })
    }

    /// Every entry, in central directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Number of entries actually parsed, which may be fewer than declared.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Look one entry up by exact name.
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// All entries whose name satisfies `pred`.
    pub fn filter<F: Fn(&str) -> bool>(&self, pred: F) -> impl Iterator<Item = &ZipEntry> {
        self.entries.iter().filter(move |e| pred(&e.name))
    }

    /// Extract one entry's uncompressed bytes.
    ///
    /// Only `stored` and `deflate` are supported; anything else is a typed
    /// error, because silently returning wrong bytes here would corrupt every
    /// downstream statistic without any visible symptom.
    pub fn read_entry(&self, entry: &ZipEntry) -> Result<Vec<u8>> {
        self.read_entry_prefix(entry, u64::MAX)
    }

    /// Extract at most `want` bytes of one entry's uncompressed data.
    ///
    /// Used for content sniffing, where the whole payload is not needed and
    /// decompressing a 40 MB asset to look at its first four bytes would be
    /// absurd. The deflate stream is not fully consumed when the prefix is
    /// short, which is exactly the point: the reader is dropped and the
    /// remainder is never produced.
    pub fn read_entry_prefix(&self, entry: &ZipEntry, want: u64) -> Result<Vec<u8>> {
        if entry.encrypted {
            return Err(Error::UnsupportedCompression {
                name: entry.name.clone(),
                method: 0xffff,
            });
        }
        let lho = entry.local_header_offset as usize;
        if lho + LOCAL_FIXED_SIZE > self.bytes.len() {
            return Err(Error::Truncated {
                what: "local file header",
                need: lho as u64 + LOCAL_FIXED_SIZE as u64,
                have: self.bytes.len() as u64,
            });
        }
        let sig = u32::from_le_bytes([
            self.bytes[lho],
            self.bytes[lho + 1],
            self.bytes[lho + 2],
            self.bytes[lho + 3],
        ]);
        if sig != SIG_LOCAL {
            return Err(Error::Truncated {
                what: "local file header signature",
                need: sig as u64,
                have: SIG_LOCAL as u64,
            });
        }
        let name_len = u16::from_le_bytes([self.bytes[lho + 26], self.bytes[lho + 27]]) as usize;
        let extra_len = u16::from_le_bytes([self.bytes[lho + 28], self.bytes[lho + 29]]) as usize;
        let data_off = lho + LOCAL_FIXED_SIZE + name_len + extra_len;
        let csize = entry.compressed_size as usize;
        let data_end = data_off.checked_add(csize).ok_or(Error::Truncated {
            what: "entry data",
            need: u64::MAX,
            have: self.bytes.len() as u64,
        })?;
        if data_end > self.bytes.len() {
            return Err(Error::Truncated {
                what: "entry data",
                need: data_end as u64,
                have: self.bytes.len() as u64,
            });
        }
        let raw = &self.bytes[data_off..data_end];

        match entry.method {
            METHOD_STORED => Ok(raw.iter().copied().take(want as usize).collect()),
            METHOD_DEFLATE => {
                use flate2::read::DeflateDecoder;
                let mut out = Vec::new();
                let want = if want == u64::MAX {
                    entry.uncompressed_size
                } else {
                    want
                };
                out.reserve((want.min(1 << 20)) as usize);
                let mut dec = DeflateDecoder::new(raw);
                let mut buf = [0u8; 4096];
                loop {
                    if out.len() as u64 >= want {
                        break;
                    }
                    let cap = ((want - out.len() as u64).min(buf.len() as u64)) as usize;
                    match std::io::Read::read(&mut dec, &mut buf[..cap]) {
                        Ok(0) => break,
                        Ok(n) => out.extend_from_slice(&buf[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(e) => {
                            return Err(Error::Inflate {
                                name: entry.name.clone(),
                                detail: e.to_string(),
                            })
                        }
                    }
                }
                if want == entry.uncompressed_size
                    && entry.uncompressed_size != 0
                    && out.len() as u64 != entry.uncompressed_size
                {
                    return Err(Error::Inflate {
                        name: entry.name.clone(),
                        detail: format!(
                            "expected {} bytes, produced {}",
                            entry.uncompressed_size,
                            out.len()
                        ),
                    });
                }
                Ok(out)
            }
            method => Err(Error::UnsupportedCompression {
                name: entry.name.clone(),
                method,
            }),
        }
    }
}

/// Locate the end-of-central-directory record by scanning backwards.
fn find_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < EOCD_MIN_SIZE {
        return None;
    }
    let lowest = bytes
        .len()
        .saturating_sub(EOCD_MIN_SIZE + MAX_COMMENT as usize);
    // Scan from the end backwards: the record is the last thing in the file.
    let mut i = bytes.len() - EOCD_MIN_SIZE;
    loop {
        if u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) == SIG_EOCD {
            let comment_len = u16::from_le_bytes([bytes[i + 20], bytes[i + 21]]) as usize;
            if i + EOCD_MIN_SIZE + comment_len == bytes.len() {
                return Some(i);
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
        if (i as u64) < lowest as u64 {
            return None;
        }
    }
}

/// Read the ZIP64 EOCD record via its locator, which sits immediately before the
/// classic EOCD.
fn read_zip64_eocd(bytes: &[u8], eocd: usize) -> Result<Option<(u64, u64, u64)>> {
    if eocd < 20 {
        return Ok(None);
    }
    let loc = eocd - 20;
    let sig = u32::from_le_bytes([bytes[loc], bytes[loc + 1], bytes[loc + 2], bytes[loc + 3]]);
    if sig != SIG_EOCD64_LOCATOR {
        return Ok(None);
    }
    let off = u64::from_le_bytes([
        bytes[loc + 8],
        bytes[loc + 9],
        bytes[loc + 10],
        bytes[loc + 11],
        bytes[loc + 12],
        bytes[loc + 13],
        bytes[loc + 14],
        bytes[loc + 15],
    ]) as usize;
    if off + 56 > bytes.len() {
        return Ok(None);
    }
    let sig64 = u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ]) as u32;
    if sig64 != SIG_EOCD64 {
        return Ok(None);
    }
    let rd = |k: usize| -> u64 {
        u64::from_le_bytes([
            bytes[off + k],
            bytes[off + k + 1],
            bytes[off + k + 2],
            bytes[off + k + 3],
            bytes[off + k + 4],
            bytes[off + k + 5],
            bytes[off + k + 6],
            bytes[off + k + 7],
        ])
    };
    Ok(Some((rd(32), rd(40), rd(48))))
}

/// Resolve the 0xffffffff sentinels through the ZIP64 extended information
/// extra field, which is a sequence of (id, size, payload) records in the order
/// the sentinels appear in the fixed record.
fn apply_zip64_extra(extra: &[u8], csize: u64, usize_: u64, lho: u64) -> Result<(u64, u64, u64)> {
    let mut csize = csize;
    let mut usize_ = usize_;
    let mut lho = lho;
    let mut at = 0usize;
    while at + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[at], extra[at + 1]]);
        let size = u16::from_le_bytes([extra[at + 2], extra[at + 3]]) as usize;
        let body_start = at + 4;
        if body_start + size > extra.len() {
            break;
        }
        if id == ZIP64_EXTRA_ID {
            let body = &extra[body_start..body_start + size];
            let mut k = 0usize;
            if usize_ == 0xffff_ffff {
                if k + 8 > body.len() {
                    return Err(Error::Truncated {
                        what: "zip64 extra",
                        need: k as u64 + 8,
                        have: body.len() as u64,
                    });
                }
                usize_ = be_u64(body, k);
                k += 8;
            }
            if csize == 0xffff_ffff {
                if k + 8 > body.len() {
                    return Err(Error::Truncated {
                        what: "zip64 extra",
                        need: k as u64 + 8,
                        have: body.len() as u64,
                    });
                }
                csize = be_u64(body, k);
                k += 8;
            }
            if lho == 0xffff_ffff {
                if k + 8 > body.len() {
                    return Err(Error::Truncated {
                        what: "zip64 extra",
                        need: k as u64 + 8,
                        have: body.len() as u64,
                    });
                }
                lho = be_u64(body, k);
            }
        }
        at = body_start + size;
    }
    Ok((csize, usize_, lho))
}

fn be_u64(b: &[u8], at: usize) -> u64 {
    u64::from_be_bytes([
        b[at],
        b[at + 1],
        b[at + 2],
        b[at + 3],
        b[at + 4],
        b[at + 5],
        b[at + 6],
        b[at + 7],
    ])
}

fn decode_name(bytes: &[u8], flags: u16) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if flags & UTF8_FLAG != 0 || bytes.iter().all(|&b| b < 0x80) {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // CP437 fallback. Only reachable for a legacy non-UTF8 archive, which a
    // modern APK is not, so the mapping is approximated rather than complete.
    bytes.iter().map(|&b| b as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal stored-only archive with two entries, built by hand.
    fn build_stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data) in entries {
            let lho = out.len() as u32;
            out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
            out.extend_from_slice(&10u16.to_le_bytes()); // version needed
            out.extend_from_slice(&0u16.to_le_bytes()); // flags
            out.extend_from_slice(&METHOD_STORED.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // time
            out.extend_from_slice(&0u16.to_le_bytes()); // date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc (unchecked here)
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);

            central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&10u16.to_le_bytes()); // version needed
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&METHOD_STORED.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes());
            central.extend_from_slice(&0u32.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&0u16.to_le_bytes()); // extra
            central.extend_from_slice(&0u16.to_le_bytes()); // comment
            central.extend_from_slice(&0u16.to_le_bytes()); // disk
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&lho.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        out.extend_from_slice(&central);
        let cd_size = central.len() as u32;
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_stored_entries_and_central_directory() {
        let bytes = build_stored(&[
            ("classes.dex", b"dex\n035\0"),
            ("AndroidManifest.xml", b"axml"),
        ]);
        let a = Archive::open(bytes).unwrap();
        assert_eq!(a.entry_count(), 2);
        assert!(!a.zip64);
        assert!(a.find("classes.dex").is_some());
        assert_eq!(
            a.read_entry(a.find("classes.dex").unwrap()).unwrap(),
            b"dex\n035\0"
        );
    }

    #[test]
    fn classifies_native_lib_entries_by_abi() {
        let bytes = build_stored(&[
            ("lib/arm64-v8a/libfoo.so", b"x"),
            ("lib/armeabi-v7a/libfoo.so", b"x"),
            ("res/5x.so", b"x"),
            ("assets/bin/busybox", b"x"),
        ]);
        let a = Archive::open(bytes).unwrap();
        let abis: Vec<&str> = a.entries().iter().filter_map(|e| e.abi()).collect();
        assert_eq!(abis, vec!["arm64-v8a", "armeabi-v7a"]);
        assert!(!a.find("res/5x.so").unwrap().is_native_lib());
    }

    #[test]
    fn rejects_a_file_that_is_not_a_zip() {
        assert_eq!(
            Archive::open(b"not a zip at all".to_vec()).unwrap_err(),
            Error::NotAZip
        );
    }

    #[test]
    fn rejects_an_entry_with_an_unimplemented_compression_method() {
        let mut bytes = build_stored(&[("classes.dex", b"zzz")]);
        // Flip the compression method in both the local header and the
        // central directory record so the record is the one that is read.
        let lho = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        bytes[lho + 8..lho + 10].copy_from_slice(&9u16.to_le_bytes());
        let cd_off = {
            let eocd = find_eocd(&bytes).unwrap();
            u32::from_le_bytes([
                bytes[eocd + 16],
                bytes[eocd + 17],
                bytes[eocd + 18],
                bytes[eocd + 19],
            ]) as usize
        };
        bytes[cd_off + 10..cd_off + 12].copy_from_slice(&9u16.to_le_bytes());
        let a = Archive::open(bytes).unwrap();
        let err = a.read_entry(a.find("classes.dex").unwrap()).unwrap_err();
        assert_eq!(err.kind(), "unsupported_compression");
    }

    #[test]
    fn a_central_directory_claiming_more_bytes_than_exist_is_a_typed_error() {
        let mut bytes = build_stored(&[("classes.dex", b"dex")]);
        let eocd = find_eocd(&bytes).unwrap();
        let huge = (bytes.len() as u32) + 4096;
        bytes[eocd + 12..eocd + 16].copy_from_slice(&huge.to_le_bytes());
        let err = Archive::open(bytes).unwrap_err();
        assert_eq!(err.kind(), "truncated");
    }

    #[test]
    fn a_file_shorter_than_the_eocd_record_is_not_a_zip() {
        assert_eq!(Archive::open(vec![0u8; 8]).unwrap_err(), Error::NotAZip);
    }

    #[test]
    fn walks_a_real_deflate_entry() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let payload = b"a repeated payload a repeated payload a repeated payload";
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let deflated = enc.finish().unwrap();

        let mut bytes = Vec::new();
        let lho = 0u32;
        bytes.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&METHOD_DEFLATE.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let name = b"classes.dex";
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(&deflated);

        let mut central = Vec::new();
        central.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&METHOD_DEFLATE.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(deflated.len() as u32).to_le_bytes());
        central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&lho.to_le_bytes());
        central.extend_from_slice(name);

        let cd_off = bytes.len() as u32;
        bytes.extend_from_slice(&central);
        let cd_size = central.len() as u32;
        bytes.extend_from_slice(&SIG_EOCD.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&cd_size.to_le_bytes());
        bytes.extend_from_slice(&cd_off.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());

        let a = Archive::open(bytes).unwrap();
        assert_eq!(
            a.read_entry(a.find("classes.dex").unwrap()).unwrap(),
            payload
        );
    }
}
