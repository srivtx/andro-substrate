//! DEX container header: parsing, serialisation and integrity primitives.
//!
//! The header is a fixed 0x70-byte little-endian structure. Everything after
//! `map_off` is a (size, offset) pair pointing into the file; the writer in
//! [`crate::writer`] is responsible for keeping those consistent.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dex-format>

use crate::error::{Error, Result};
use serde::Serialize;

/// Size of the v040-and-earlier `header_item`, in bytes.
pub const HEADER_SIZE: u32 = 0x70;

/// Size of the v041 `header_item` (container form), in bytes.
pub const HEADER_SIZE_V41: u32 = 0x78;

/// Little-endian marker stored in `endian_tag`.
pub const ENDIAN_CONSTANT: u32 = 0x1234_5678;

/// Byte-swapped marker; seeing this means the producer wrote big-endian.
pub const REVERSE_ENDIAN_CONSTANT: u32 = 0x7856_3412;

/// First bytes of every DEX file: `dex\n` followed by a three-digit version.
pub const MAGIC_PREFIX: &[u8; 4] = b"dex\n";

/// `NO_INDEX`, the sentinel for "this index is absent".
pub const NO_INDEX: u32 = 0xffff_ffff;

/// A parsed `header_item`.
///
/// Field names mirror the specification. `data_off`/`data_size` are only
/// meaningful for version 40 and earlier; version 41 replaces them with
/// `header_offset`/`container_size`, which are exposed as the same pair because
/// the layout is observationally identical for a single-container file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DexHeader {
    /// The three ASCII version digits, e.g. `b"035"`.
    pub version: [u8; 3],
    /// Adler-32 over `bytes[12..]`. Zero means "not computed".
    pub checksum: u32,
    /// SHA-1 over `bytes[32..]`. Zero means "not computed".
    pub signature: [u8; 20],
    /// Total file size in bytes.
    pub file_size: u32,
    /// Always `0x70` (v40 and earlier) or `0x78` (v41).
    pub header_size: u32,
    /// Always [`ENDIAN_CONSTANT`] for a file we can read.
    pub endian_tag: u32,
    /// Link section; always 0/0 in a standalone APK.
    pub link_size: u32,
    pub link_off: u32,
    /// Offset of the `map_list`, never zero.
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

impl DexHeader {
    /// Parse the header from the start of a DEX file.
    ///
    /// Validates the magic, `header_size` and `endian_tag` but deliberately
    /// does *not* validate the checksum or signature; see
    /// [`DexHeader::verify_integrity`]. Use [`DexHeader::parse_checked`] to get
    /// both behaviours in one call.
    pub fn parse(bytes: &[u8]) -> Result<DexHeader> {
        if bytes.len() < HEADER_SIZE as usize {
            return Err(Error::Truncated {
                what: "header",
                need: HEADER_SIZE as usize,
                have: bytes.len(),
            });
        }
        if &bytes[0..4] != MAGIC_PREFIX {
            return Err(Error::BadMagic { found: bytes[0..4].to_vec() });
        }
        let version = [bytes[4], bytes[5], bytes[6]];
        if bytes[7] != 0 {
            return Err(Error::BadMagic { found: bytes[0..8].to_vec() });
        }
        let header_size = read_u32(bytes, 36);
        if header_size != HEADER_SIZE && header_size != HEADER_SIZE_V41 {
            return Err(Error::BadHeaderSize(header_size));
        }
        let endian_tag = read_u32(bytes, 40);
        if endian_tag != ENDIAN_CONSTANT {
            return Err(Error::BadEndianTag(endian_tag));
        }
        let checksum = read_u32(bytes, 8);
        let mut signature = [0u8; 20];
        signature.copy_from_slice(&bytes[12..32]);

        let h = DexHeader {
            version,
            checksum,
            signature,
            file_size: read_u32(bytes, 32),
            header_size,
            endian_tag,
            link_size: read_u32(bytes, 44),
            link_off: read_u32(bytes, 48),
            map_off: read_u32(bytes, 52),
            string_ids_size: read_u32(bytes, 56),
            string_ids_off: read_u32(bytes, 60),
            type_ids_size: read_u32(bytes, 64),
            type_ids_off: read_u32(bytes, 68),
            proto_ids_size: read_u32(bytes, 72),
            proto_ids_off: read_u32(bytes, 76),
            field_ids_size: read_u32(bytes, 80),
            field_ids_off: read_u32(bytes, 84),
            method_ids_size: read_u32(bytes, 88),
            method_ids_off: read_u32(bytes, 92),
            class_defs_size: read_u32(bytes, 96),
            class_defs_off: read_u32(bytes, 100),
            data_size: read_u32(bytes, 104),
            data_off: read_u32(bytes, 108),
        };

        // Every section must lie inside the declared file. A file that lies
        // about its own length is malformed, and this is the cheapest place to
        // notice.
        if (h.file_size as usize) > bytes.len() {
            return Err(Error::Truncated { what: "file", need: h.file_size as usize, have: bytes.len() });
        }
        for (name, size, off, elem) in [
            ("string_ids", h.string_ids_size, h.string_ids_off, 4u32),
            ("type_ids", h.type_ids_size, h.type_ids_off, 4),
            ("proto_ids", h.proto_ids_size, h.proto_ids_off, 12),
            ("field_ids", h.field_ids_size, h.field_ids_off, 8),
            ("method_ids", h.method_ids_size, h.method_ids_off, 8),
            ("class_defs", h.class_defs_size, h.class_defs_off, 32),
        ] {
            h.check_section(name, size, off, elem)?;
        }
        h.check_section("map_list", 1, h.map_off, 4)?;
        h.check_section("data", 1, h.data_off, 0)?;
        Ok(h)
    }

    /// Parse and additionally require that the Adler-32 checksum and SHA-1
    /// signature both match the file contents.
    pub fn parse_checked(bytes: &[u8]) -> Result<DexHeader> {
        let h = DexHeader::parse(bytes)?;
        h.verify_integrity(bytes)?;
        Ok(h)
    }

    /// Check that `size` elements of `elem_size` bytes at `off` fit in the file.
    fn check_section(
        &self,
        name: &'static str,
        size: u32,
        off: u32,
        elem_size: u32,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        if off == 0 {
            return Err(Error::MissingSection(name));
        }
        let span = (size as u64) * (elem_size as u64);
        let end = (off as u64) + span;
        let file_end = if self.file_size == 0 { u64::MAX } else { self.file_size as u64 };
        if end > file_end {
            return Err(Error::SectionOutOfRange {
                name: name.to_string(),
                off,
                size,
                need: end,
                have: self.file_size as u64,
            });
        }
        Ok(())
    }

    /// True when the file declares a v041-or-later container header.
    pub fn is_container(&self) -> bool {
        self.header_size == HEADER_SIZE_V41
    }

    /// Recompute the Adler-32 checksum and SHA-1 signature from `bytes` and
    /// store them into `self`.
    pub fn recompute_integrity(&mut self, bytes: &mut [u8]) {
        // Order matters: the SHA-1 covers `bytes[32..]`, which excludes both
        // fields, so it can be computed first; the Adler-32 covers
        // `bytes[12..]`, which *includes* the signature, so it must come second.
        let sig = sha1(&bytes[32..]);
        bytes[12..32].copy_from_slice(&sig);
        let cs = adler32(&bytes[12..]);
        bytes[8..12].copy_from_slice(&cs.to_le_bytes());
        self.signature = sig;
        self.checksum = cs;
    }

    /// Verify that the header's own `checksum` and `signature` fields match the
    /// rest of the file.
    ///
    /// A failure here is not necessarily fatal for static analysis — a lot of
    /// repackaging tooling rewrites APKs without recomputing — so this is
    /// deliberately a separate call from [`DexHeader::parse`].
    pub fn verify_integrity(&self, bytes: &[u8]) -> Result<()> {
        if self.checksum != adler32(&bytes[12..]) {
            return Err(Error::ChecksumMismatch {
                declared: self.checksum,
                computed: adler32(&bytes[12..]),
            });
        }
        let sig = sha1(&bytes[32..]);
        if self.signature != sig {
            return Err(Error::SignatureMismatch {
                declared: hex16(&self.signature),
                computed: hex16(&sig),
            });
        }
        Ok(())
    }

    /// Serialise the header into a 0x70-byte little-endian buffer, padding with
    /// zeros if the source header was a 0x78-byte container header.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE as usize] {
        let mut b = [0u8; HEADER_SIZE as usize];
        b[0..4].copy_from_slice(MAGIC_PREFIX);
        b[4..7].copy_from_slice(&self.version);
        b[7] = 0;
        b[8..12].copy_from_slice(&self.checksum.to_le_bytes());
        b[12..32].copy_from_slice(&self.signature);
        let mut put = |off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        put(32, self.file_size);
        put(36, if self.header_size == 0 { HEADER_SIZE } else { self.header_size });
        put(40, self.endian_tag);
        put(44, self.link_size);
        put(48, self.link_off);
        put(52, self.map_off);
        put(56, self.string_ids_size);
        put(60, self.string_ids_off);
        put(64, self.type_ids_size);
        put(68, self.type_ids_off);
        put(72, self.proto_ids_size);
        put(76, self.proto_ids_off);
        put(80, self.field_ids_size);
        put(84, self.field_ids_off);
        put(88, self.method_ids_size);
        put(92, self.method_ids_off);
        put(96, self.class_defs_size);
        put(100, self.class_defs_off);
        put(104, self.data_size);
        put(108, self.data_off);
        b
    }
}

fn hex16(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[inline]
fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Adler-32 as specified by RFC 1950.
///
/// The DEX checksum is computed over every byte of the file after the
/// `checksum` field itself, i.e. `bytes[12..]`.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    // 5552 is the largest run that cannot overflow the u32 accumulators.
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// SHA-1 as specified by FIPS 180-4, implemented directly so that the crate
/// carries no crypto dependency into the WASM bundle.
///
/// The DEX signature is computed over every byte of the file after the
/// `signature` field, i.e. `bytes[32..]`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for block in padded.chunks_exact(64) {
        for (i, word) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_rfc1950_vectors() {
        assert_eq!(adler32(b""), 0x0000_0001);
        assert_eq!(adler32(b"a"), 0x0062_0062);
        assert_eq!(adler32(b"abc"), 0x024d_0127);
        assert_eq!(adler32(b"message digest"), 0x2975_0586);
        assert_eq!(adler32(b"abcdefghijklmnopqrstuvwxyz"), 0x9086_0b20);
        // Exercises the 5552-byte chunking path many times over.
        let long = vec![b'x'; 100_000];
        assert_eq!(adler32(&long), adler32_ref(&long));
    }

    /// Straightforward reference implementation used to check the chunked one.
    fn adler32_ref(data: &[u8]) -> u32 {
        let mut a: u64 = 1;
        let mut b: u64 = 0;
        for &byte in data {
            a = (a + byte as u64) % 65521;
            b = (b + a) % 65521;
        }
        ((b << 16) | a) as u32
    }

    #[test]
    fn sha1_matches_fips_vectors() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // One million 'a' — the classic FIPS vector, and a length that forces
        // several padding lengths to be exercised.
        assert_eq!(
            hex(&sha1(&vec![b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
    }

    #[test]
    fn parse_rejects_short_input() {
        let e = DexHeader::parse(&[0u8; 10]).unwrap_err();
        assert!(matches!(e, Error::Truncated { what: "header", .. }), "got {e:?}");
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut b = valid_minimal_header();
        b[0] = b'X';
        assert!(matches!(DexHeader::parse(&b), Err(Error::BadMagic { .. })));
    }

    #[test]
    fn parse_rejects_wrong_header_size_and_endian_tag() {
        let mut b = valid_minimal_header();
        b[36..40].copy_from_slice(&0x60u32.to_le_bytes());
        assert!(matches!(DexHeader::parse(&b), Err(Error::BadHeaderSize(0x60))));

        let mut b = valid_minimal_header();
        b[40..44].copy_from_slice(&REVERSE_ENDIAN_CONSTANT.to_le_bytes());
        assert!(matches!(DexHeader::parse(&b), Err(Error::BadEndianTag(_))));
    }

    /// A structurally valid, completely empty DEX file (just header + map_list).
    fn valid_minimal_header() -> [u8; 128] {
        let mut b = [0u8; 128];
        b[0..4].copy_from_slice(b"dex\n");
        b[4..8].copy_from_slice(b"035\0");
        b[32..36].copy_from_slice(&128u32.to_le_bytes()); // file_size
        b[36..40].copy_from_slice(&HEADER_SIZE.to_le_bytes());
        b[40..44].copy_from_slice(&ENDIAN_CONSTANT.to_le_bytes());
        b[52..56].copy_from_slice(&120u32.to_le_bytes()); // map_off
        b[56..60].copy_from_slice(&2u32.to_le_bytes()); // string_ids_size
        b[60..64].copy_from_slice(&112u32.to_le_bytes()); // string_ids_off
        b[104..108].copy_from_slice(&8u32.to_le_bytes()); // data_size
        b[108..112].copy_from_slice(&120u32.to_le_bytes()); // data_off
        b
    }

    #[test]
    fn parse_accepts_empty_dex() {
        let b = valid_minimal_header();
        let h = DexHeader::parse(&b).unwrap();
        assert_eq!(h.version, *b"035");
        assert_eq!(h.header_size, 0x70);
        assert_eq!(h.endian_tag, ENDIAN_CONSTANT);
        assert_eq!(h.string_ids_size, 2);
        assert_eq!(h.map_off, 120);
        assert_eq!(h.file_size, 128);
        assert_eq!(h.data_size, 8);
    }

    #[test]
    fn parse_detects_section_past_eof() {
        let mut b = valid_minimal_header();
        b[56..60].copy_from_slice(&1000u32.to_le_bytes()); // absurd string count
        let e = DexHeader::parse(&b).unwrap_err();
        assert!(
            matches!(e, Error::SectionOutOfRange { ref name, .. } if name == "string_ids"),
            "got {e:?}"
        );
    }

    #[test]
    fn parse_detects_file_shorter_than_declared() {
        let mut b = valid_minimal_header();
        b[32..36].copy_from_slice(&99999u32.to_le_bytes());
        assert!(matches!(DexHeader::parse(&b), Err(Error::Truncated { what: "file", .. })));
    }

    #[test]
    fn header_round_trips_through_bytes() {
        let mut b = valid_minimal_header().to_vec();
        let mut h = DexHeader::parse(&b).unwrap();
        h.recompute_integrity(&mut b);
        let h2 = DexHeader::parse(&b).unwrap();
        assert_eq!(h2.to_bytes(), b[..HEADER_SIZE as usize]);
        h2.verify_integrity(&b).unwrap();
    }

    #[test]
    fn integrity_mismatch_is_reported() {
        let mut b = valid_minimal_header().to_vec();
        let mut h = DexHeader::parse(&b).unwrap();
        h.recompute_integrity(&mut b);
        b[70] ^= 0xff; // flip a byte in the data section
        assert!(matches!(h.verify_integrity(&b), Err(Error::ChecksumMismatch { .. })));
    }
}
