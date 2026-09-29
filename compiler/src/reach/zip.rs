//! A minimal, dependency-free ZIP reader with a DEFLATE decoder.
//!
//! # Why this exists
//!
//! `compiler/Cargo.toml` declares no runtime dependencies, deliberately: `abi`
//! and `marshal` are the layer everything else lowers *through*, and a
//! dependency there would couple the whole compiler to it. Reachability, by
//! contrast, has to open an APK, and an APK is a ZIP. Rather than add
//! `zip`/`flate2` to a crate another agent owns the dependency posture of, the
//! ~350 lines that a ZIP central-directory walk and an INFLATE decoder actually
//! need live here, inside the one directory this module owns.
//!
//! # Scope
//!
//! Exactly what an APK needs, and no more:
//!
//! * stored (method 0) and deflated (method 8) entries;
//! * the end-of-central-directory record, located by scanning backwards;
//! * Zip64 end-of-central-directory **is** parsed, but a Zip64 archive is
//!   rejected rather than supported, because no APK is 4 GiB and silently
//!   mis-reading one would be worse than refusing it.
//!
//! Everything is bounds-checked and returns [`ZipError`]. There is no `unsafe`
//! and no `unwrap`. A hostile APK gets a typed error, never a panic.

use std::fmt;

/// Anything that can go wrong opening or inflating an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipError {
    /// The file is shorter than the smallest structure a ZIP can contain.
    TooShort,
    /// No end-of-central-directory signature was found in the trailing 64 KiB.
    NoEndOfCentralDirectory,
    /// The end-of-central-directory record was found but its fields are
    /// inconsistent with the file length.
    BadEndOfCentralDirectory(&'static str),
    /// A Zip64 end-of-central-directory locator was present.
    Zip64Unsupported,
    /// A central-directory entry had an unparseable header.
    BadCentralDirectory(&'static str),
    /// An entry used a compression method this reader does not implement.
    UnsupportedMethod(u16),
    /// A local file header did not agree with the central directory.
    BadLocalHeader(&'static str),
    /// The compressed stream ended before the decoder was done.
    TruncatedStream,
    /// The compressed stream contains bytes that are not valid DEFLATE.
    CorruptStream(&'static str),
    /// The entry's uncompressed size did not match what the decoder produced.
    SizeMismatch { declared: u64, produced: usize },
    /// A name or comment was not valid UTF-8.
    NonUtf8Name,
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipError::TooShort => write!(f, "zip: file is too short to contain a zip"),
            ZipError::NoEndOfCentralDirectory => {
                write!(
                    f,
                    "zip: no end-of-central-directory record in the last 64 KiB"
                )
            }
            ZipError::BadEndOfCentralDirectory(w) => {
                write!(f, "zip: bad end-of-central-directory record: {w}")
            }
            ZipError::Zip64Unsupported => write!(f, "zip: zip64 archives are not supported"),
            ZipError::BadCentralDirectory(w) => write!(f, "zip: bad central directory: {w}"),
            ZipError::UnsupportedMethod(m) => {
                write!(f, "zip: compression method {m} is not supported")
            }
            ZipError::BadLocalHeader(w) => write!(f, "zip: bad local file header: {w}"),
            ZipError::TruncatedStream => write!(f, "zip: compressed stream ended early"),
            ZipError::CorruptStream(w) => write!(f, "zip: corrupt deflate stream: {w}"),
            ZipError::SizeMismatch { declared, produced } => {
                write!(
                    f,
                    "zip: entry declares {declared} bytes, decoder produced {produced}"
                )
            }
            ZipError::NonUtf8Name => write!(f, "zip: entry name is not valid UTF-8"),
        }
    }
}

impl std::error::Error for ZipError {}

/// `EOCD` signature, `PK\x05\x06`.
const SIG_EOCD: u32 = 0x0605_4b50;
/// Zip64 end-of-central-directory locator, `PK\x06\x07`.
const SIG_EOCD64_LOCATOR: u32 = 0x0706_4b50;
/// Central-directory file header, `PK\x01\x02`.
const SIG_CENTRAL: u32 = 0x0201_4b50;
/// Local file header, `PK\x03\x04`.
const SIG_LOCAL: u32 = 0x0403_4b50;

fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

/// One entry, as described by the central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZipEntry {
    /// Full path inside the archive, `/`-separated.
    pub name: String,
    /// Compression method: 0 stored, 8 deflated.
    pub method: u16,
    /// Uncompressed size as declared by the central directory.
    pub size: u64,
    /// Compressed size as declared by the central directory.
    pub compressed_size: u64,
    /// Offset of the local file header.
    pub local_header_offset: u64,
}

impl ZipEntry {
    /// True for names that address a directory rather than a file.
    pub fn is_dir(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// A parsed central directory.
#[derive(Debug, Clone, Default)]
pub struct ZipArchive {
    entries: Vec<ZipEntry>,
    cd_offset: usize,
}

impl ZipArchive {
    /// Read the central directory of an archive held in memory.
    ///
    /// This does not decompress anything; it is the cheap half, and it is what
    /// the reachability driver calls first so it can decide which members it
    /// wants before paying for inflate.
    pub fn open(bytes: &[u8]) -> Result<ZipArchive, ZipError> {
        if bytes.len() < 22 {
            return Err(ZipError::TooShort);
        }
        // The EOCD is at the end, but a comment of up to 64 KiB may follow it.
        let tail_start = bytes.len().saturating_sub(22 + 0xffff);
        let mut eocd = None;
        let mut i = bytes.len() - 22;
        loop {
            if u32le(bytes, i) == Some(SIG_EOCD) {
                eocd = Some(i);
                break;
            }
            if i == tail_start {
                break;
            }
            i -= 1;
        }
        let eocd = eocd.ok_or(ZipError::NoEndOfCentralDirectory)?;

        if let Some(loc) = eocd.checked_sub(20).and_then(|p| u32le(bytes, p)) {
            if loc == SIG_EOCD64_LOCATOR {
                return Err(ZipError::Zip64Unsupported);
            }
        }

        let count = u16le(bytes, eocd + 10).ok_or(ZipError::TooShort)? as usize;
        let cd_size = u32le(bytes, eocd + 12).ok_or(ZipError::TooShort)? as usize;
        let cd_offset = u32le(bytes, eocd + 16).ok_or(ZipError::TooShort)? as usize;

        if count == 0xffff || cd_size == 0xffff_ffff || cd_offset == 0xffff_ffff {
            return Err(ZipError::Zip64Unsupported);
        }
        let cd_end = cd_offset.checked_add(cd_size).ok_or(ZipError::TooShort)?;
        if cd_end > bytes.len() {
            return Err(ZipError::BadEndOfCentralDirectory(
                "central directory past end of file",
            ));
        }

        let mut entries = Vec::with_capacity(count);
        let mut p = cd_offset;
        for _ in 0..count {
            if u32le(bytes, p) != Some(SIG_CENTRAL) {
                return Err(ZipError::BadCentralDirectory("bad signature"));
            }
            let flags = u16le(bytes, p + 8).ok_or(ZipError::TooShort)?;
            let method = u16le(bytes, p + 10).ok_or(ZipError::TooShort)?;
            let csize = u32le(bytes, p + 20).ok_or(ZipError::TooShort)? as u64;
            let usize_ = u32le(bytes, p + 24).ok_or(ZipError::TooShort)? as u64;
            let name_len = u16le(bytes, p + 28).ok_or(ZipError::TooShort)? as usize;
            let extra_len = u16le(bytes, p + 30).ok_or(ZipError::TooShort)? as usize;
            let comment_len = u16le(bytes, p + 32).ok_or(ZipError::TooShort)? as usize;
            let lho = u32le(bytes, p + 42).ok_or(ZipError::TooShort)? as u64;

            // Bit 11 is the UTF-8 name flag. APK entries that carry non-ASCII
            // names set it; ones that do not are almost always ASCII anyway, so
            // lossy decoding is the safe reading for the rest.
            let name_bytes = bytes
                .get(p + 46..p + 46 + name_len)
                .ok_or(ZipError::BadCentralDirectory("name past end of file"))?;
            let name = if flags & 0x800 != 0 {
                std::str::from_utf8(name_bytes)
                    .map_err(|_| ZipError::NonUtf8Name)?
                    .to_string()
            } else {
                name_bytes.iter().map(|&b| b as char).collect()
            };

            if !matches!(method, 0 | 8) {
                return Err(ZipError::UnsupportedMethod(method));
            }

            entries.push(ZipEntry {
                name,
                method,
                size: usize_,
                compressed_size: csize,
                local_header_offset: lho,
            });
            p += 46 + name_len + extra_len + comment_len;
            if p > cd_end {
                return Err(ZipError::BadCentralDirectory(
                    "entry overruns the directory",
                ));
            }
        }
        Ok(ZipArchive { entries, cd_offset })
    }

    /// Every entry, in central-directory order.
    pub fn entries(&self) -> &[ZipEntry] {
        &self.entries
    }

    /// Look an entry up by exact name.
    pub fn find(&self, name: &str) -> Option<&ZipEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Offset of the central directory, carried so a caller can record where
    /// the archive's own index lives without a second parse.
    pub fn central_directory_offset(&self) -> usize {
        self.cd_offset
    }

    /// Decompress one entry.
    pub fn read(&self, bytes: &[u8], entry: &ZipEntry) -> Result<Vec<u8>, ZipError> {
        let lh = usize::try_from(entry.local_header_offset).map_err(|_| ZipError::TooShort)?;
        if u32le(bytes, lh) != Some(SIG_LOCAL) {
            return Err(ZipError::BadLocalHeader("bad signature"));
        }
        let name_len = u16le(bytes, lh + 26).ok_or(ZipError::TooShort)? as usize;
        let extra_len = u16le(bytes, lh + 28).ok_or(ZipError::TooShort)? as usize;
        let start = lh
            .checked_add(30)
            .and_then(|p| p.checked_add(name_len))
            .and_then(|p| p.checked_add(extra_len))
            .ok_or(ZipError::TooShort)?;
        let end = start
            .checked_add(usize::try_from(entry.compressed_size).map_err(|_| ZipError::TooShort)?)
            .ok_or(ZipError::TooShort)?;
        let data = bytes.get(start..end).ok_or(ZipError::TruncatedStream)?;

        let out = match entry.method {
            0 => data.to_vec(),
            8 => inflate(data, entry.size)?,
            m => return Err(ZipError::UnsupportedMethod(m)),
        };
        if out.len() as u64 != entry.size {
            return Err(ZipError::SizeMismatch {
                declared: entry.size,
                produced: out.len(),
            });
        }
        Ok(out)
    }
}

/// A LSB-first bit reader over a DEFLATE payload.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u64,
    cnt: u32,
}

impl<'a> Bits<'a> {
    fn new(data: &'a [u8]) -> Self {
        Bits {
            data,
            pos: 0,
            buf: 0,
            cnt: 0,
        }
    }

    /// Pull `n` (0..=16) bits, least significant first.
    fn take(&mut self, n: u32) -> Result<u32, ZipError> {
        while self.cnt < n {
            let byte = *self.data.get(self.pos).ok_or(ZipError::TruncatedStream)?;
            self.pos += 1;
            self.buf |= u64::from(byte) << self.cnt;
            self.cnt += 8;
        }
        let v = (self.buf & ((1u64 << n) - 1)) as u32;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    /// Drop `n` bits without interpreting them.
    fn drop(&mut self, n: u32) -> Result<(), ZipError> {
        if self.cnt >= n {
            self.buf >>= n;
            self.cnt -= n;
            return Ok(());
        }
        let whole = (n - self.cnt) as usize;
        self.pos = self
            .pos
            .checked_add(whole)
            .ok_or(ZipError::TruncatedStream)?;
        if self.pos > self.data.len() {
            return Err(ZipError::TruncatedStream);
        }
        self.cnt = 0;
        self.buf = 0;
        Ok(())
    }
}

/// A canonical Huffman decoding table, in the `puff` layout.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Huffman, ZipError> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l as usize >= 16 {
                return Err(ZipError::CorruptStream("code length above 15"));
            }
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut offs = [0usize; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + usize::from(counts[i]);
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                let slot = &mut offs[l as usize];
                let idx = *slot;
                symbols[idx] = sym as u16;
                *slot += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Result<u16, ZipError> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16usize {
            code |= bits.take(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - first < count {
                let at = (index + (code - first)) as usize;
                return self
                    .symbols
                    .get(at)
                    .copied()
                    .ok_or(ZipError::CorruptStream("symbol out of range"));
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(ZipError::CorruptStream("no huffman code matched"))
    }
}

/// Decode a raw DEFLATE stream (RFC 1951).
pub fn inflate(data: &[u8], expected: u64) -> Result<Vec<u8>, ZipError> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 22) as usize);
    let mut bits = Bits::new(data);

    loop {
        let last = bits.take(1)?;
        let kind = bits.take(2)?;
        match kind {
            0 => {
                bits.drop(bits.cnt % 8)?;
                let len = bits.take(16)? as usize;
                let nlen = bits.take(16)? as usize;
                if len != (!nlen & 0xffff) {
                    return Err(ZipError::CorruptStream("stored block length check failed"));
                }
                for _ in 0..len {
                    out.push(bits.take(8)? as u8);
                }
            }
            1 => {
                let mut lit = [0u8; 288];
                for (i, slot) in lit.iter_mut().enumerate() {
                    *slot = match i {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    };
                }
                let lit = Huffman::from_lengths(&lit)?;
                let dist = Huffman::from_lengths(&[5u8; 30])?;
                inflate_block(&mut bits, &lit, &dist, &mut out)?;
            }
            2 => {
                let hlit = bits.take(5)? as usize + 257;
                let hdist = bits.take(5)? as usize + 1;
                let hclen = bits.take(4)? as usize + 4;
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl = [0u8; 19];
                for &o in ORDER.iter().take(hclen) {
                    cl[o] = bits.take(3)? as u8;
                }
                let clh = Huffman::from_lengths(&cl)?;
                let mut lengths = vec![0u8; hlit + hdist];
                let mut i = 0;
                while i < lengths.len() {
                    let sym = clh.decode(&mut bits)?;
                    match sym {
                        0..=15 => {
                            lengths[i] = sym as u8;
                            i += 1;
                        }
                        16 => {
                            if i == 0 {
                                return Err(ZipError::CorruptStream(
                                    "repeat with no previous length",
                                ));
                            }
                            let prev = lengths[i - 1];
                            let n = 3 + bits.take(2)? as usize;
                            for _ in 0..n {
                                if i >= lengths.len() {
                                    return Err(ZipError::CorruptStream(
                                        "code length repeat overruns",
                                    ));
                                }
                                lengths[i] = prev;
                                i += 1;
                            }
                        }
                        17 => {
                            let n = 3 + bits.take(3)? as usize;
                            i = (i + n).min(lengths.len());
                        }
                        18 => {
                            let n = 11 + bits.take(7)? as usize;
                            i = (i + n).min(lengths.len());
                        }
                        _ => return Err(ZipError::CorruptStream("bad code-length symbol")),
                    }
                }
                let lit = Huffman::from_lengths(&lengths[..hlit])?;
                let dist = Huffman::from_lengths(&lengths[hlit..])?;
                inflate_block(&mut bits, &lit, &dist, &mut out)?;
            }
            _ => return Err(ZipError::CorruptStream("reserved block type")),
        }
        if last == 1 {
            break;
        }
    }
    Ok(out)
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn inflate_block(
    bits: &mut Bits<'_>,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
) -> Result<(), ZipError> {
    loop {
        let sym = lit.decode(bits)?;
        match sym {
            0..=255 => out.push(sym as u8),
            256 => return Ok(()),
            257..=285 => {
                let i = sym as usize - 257;
                let len = LEN_BASE[i] as usize + bits.take(LEN_EXTRA[i] as u32)? as usize;
                let dsym = dist.decode(bits)? as usize;
                if dsym >= 30 {
                    return Err(ZipError::CorruptStream("distance symbol 30/31"));
                }
                let d = DIST_BASE[dsym] as usize + bits.take(DIST_EXTRA[dsym] as u32)? as usize;
                if d == 0 || d > out.len() {
                    return Err(ZipError::CorruptStream("distance past start of output"));
                }
                let start = out.len() - d;
                for k in 0..len {
                    let b = out[start + k];
                    out.push(b);
                }
            }
            _ => return Err(ZipError::CorruptStream("bad literal/length symbol")),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    /// A stored-only archive with one member, built by hand so the test does
    /// not depend on the writer under test.
    fn stored_archive(name: &str, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let crc = 0u32; // not validated by this reader
                        // local header
        out.extend_from_slice(&SIG_LOCAL.to_le_bytes());
        out.extend_from_slice(&10u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(body);
        let cd_offset = out.len();
        out.extend_from_slice(&SIG_CENTRAL.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&10u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let cd_size = out.len() - cd_offset;
        out.extend_from_slice(&SIG_EOCD.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(cd_size as u32).to_le_bytes());
        out.extend_from_slice(&(cd_offset as u32).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn reads_a_stored_member() {
        let bytes = stored_archive("classes.dex", b"dex\n035\0hello");
        let ar = ZipArchive::open(&bytes).expect("open");
        assert_eq!(ar.entries().len(), 1);
        let e = ar.find("classes.dex").expect("entry");
        assert_eq!(ar.central_directory_offset(), 30 + "classes.dex".len() + 13);
        assert_eq!(ar.read(&bytes, e).expect("read"), b"dex\n035\0hello");
    }

    #[test]
    fn rejects_a_non_zip() {
        let err = ZipArchive::open(b"not a zip at all, really not").expect_err("should fail");
        assert!(matches!(
            err,
            ZipError::NoEndOfCentralDirectory | ZipError::TooShort
        ));
    }

    #[test]
    fn short_file_is_an_error_not_a_panic() {
        assert!(matches!(
            ZipArchive::open(b"PK").expect_err("short"),
            ZipError::TooShort
        ));
        assert!(matches!(
            ZipArchive::open(&[]).expect_err("empty"),
            ZipError::TooShort
        ));
    }

    #[test]
    fn inflates_a_fixed_huffman_stream() {
        // Produced by a standard deflater (raw, level 9) for "aaaaaaaaaa": a
        // fixed-Huffman block whose literals repeat into a back-reference.
        // Checked against zlib rather than written by hand, because a
        // hand-written DEFLATE vector that this reader also mis-decodes would
        // agree with itself and prove nothing.
        let comp = [75u8, 76, 132, 1, 0];
        let out = inflate(&comp, 10).expect("inflate");
        assert_eq!(out, b"aaaaaaaaaa");
    }

    #[test]
    fn truncating_a_stream_is_an_error() {
        assert!(matches!(
            inflate(&[0x4b], 10),
            Err(ZipError::TruncatedStream)
        ));
    }
}
