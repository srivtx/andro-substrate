//! MUTF-8 (Modified UTF-8) codec and ULEB128 primitives.
//!
//! DEX string data is *not* standard UTF-8. It is MUTF-8, which differs in
//! three ways that matter in practice:
//!
//! 1. `U+0000` is encoded as the two-byte overlong sequence `C0 80` rather
//!    than a bare `0x00`, because `0x00` is the string terminator.
//! 2. Characters outside the BMP are stored as a *pair* of three-byte
//!    surrogate encodings, not as a single four-byte sequence.
//! 3. The `utf16_size` prefix counts UTF-16 code units, which is not the same
//!    as the number of bytes or the number of Unicode scalar values.
//!
//! Consequently `String::from_utf8` must never be applied to a DEX string pool.
//! [`decode`] returns a Rust `String` built from UTF-16 code units, which
//! reassembles surrogate pairs correctly, and lossy-encodes an unpaired
//! surrogate as U+FFFD so that a corrupt string can never panic.

use crate::error::{Error, Result};

/// Decode a NUL-terminated MUTF-8 sequence into a Rust `String`.
///
/// Returns the decoded string and the number of bytes consumed, *not*
/// including the terminating `0x00`.
///
/// Unpaired surrogates become U+FFFD. The function cannot fail on overlong
/// forms: any byte sequence that decodes to something in the surrogate range
/// is preserved as a replacement character rather than rejected, because the
/// specification explicitly permits lone surrogates in `string_data_item` and
/// says it is up to higher layers to reject them.
pub fn decode(bytes: &[u8]) -> Result<(String, usize)> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 == 0 {
            return Ok((String::from_utf16_lossy(&units), i));
        }
        if b0 < 0x80 {
            units.push(b0 as u16);
            i += 1;
        } else if b0 & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                return Err(Error::BadMutf8 { at: i });
            }
            let b1 = bytes[i + 1];
            if b0 == 0xc0 && b1 == 0x80 {
                // C0 80: the sanctioned overlong NUL.
                units.push(0);
            } else if (0xc2..=0xdf).contains(&b0) && b1 & 0xc0 == 0x80 {
                // Two-byte sequence covering U+0080..U+07FF. C0 and C1 would be
                // overlong forms of ASCII, which a conforming encoder never
                // emits, so they are rejected here.
                units.push(((b0 as u16 & 0x1f) << 6) | (b1 as u16 & 0x3f));
            } else {
                return Err(Error::BadMutf8 { at: i });
            }
            i += 2;
        } else if b0 & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                return Err(Error::BadMutf8 { at: i });
            }
            let b1 = bytes[i + 1];
            let b2 = bytes[i + 2];
            if b0 & 0x0f == 0x00 && b1 & 0x20 == 0x00 {
                // Overlong three-byte form of an ASCII character: reject it,
                // it cannot arise from a conforming encoder.
                return Err(Error::BadMutf8 { at: i });
            }
            if b1 & 0xc0 != 0x80 || b2 & 0xc0 != 0x80 {
                return Err(Error::BadMutf8 { at: i });
            }
            // Surrogates (U+D800..U+DFFF) are pushed as-is; from_utf16_lossy
            // turns unpaired ones into U+FFFD and pairs them correctly.
            units.push(
                ((b0 as u16 & 0x0f) << 12) | ((b1 as u16 & 0x3f) << 6) | (b2 as u16 & 0x3f),
            );
            i += 3;
        } else {
            // 4-byte sequences are *not* legal MUTF-8; non-BMP characters are
            // stored as surrogate pairs.
            return Err(Error::BadMutf8 { at: i });
        }
    }
    // Ran off the end without seeing the terminator.
    Err(Error::BadMutf8 { at: bytes.len() })
}

/// Encode a Rust `String` into NUL-terminated MUTF-8 bytes.
///
/// `String` is already valid Unicode, so astral characters are emitted as
/// surrogate pairs and `U+0000` as `C0 80`.
pub fn encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() + 1);
    for unit in s.encode_utf16() {
        push_unit(&mut out, unit);
    }
    out.push(0);
    out
}

/// Number of UTF-16 code units in `s`, which is what `utf16_size` records.
pub fn utf16_len(s: &str) -> u64 {
    s.encode_utf16().count() as u64
}

fn push_unit(out: &mut Vec<u8>, unit: u16) {
    match unit {
        // U+0000 is the string terminator, so MUTF-8 spells it as the two-byte
        // overlong sequence C0 80 rather than a bare zero byte.
        0x0000 => out.extend_from_slice(&[0xc0, 0x80]),
        0x0001..=0x007f => out.push(unit as u8),
        0x0080..=0x07ff => {
            out.push(0xc0 | (unit >> 6) as u8);
            out.push(0x80 | (unit & 0x3f) as u8);
        }
        _ => {
            out.push(0xe0 | (unit >> 12) as u8);
            out.push(0x80 | ((unit >> 6) & 0x3f) as u8);
            out.push(0x80 | (unit & 0x3f) as u8);
        }
    }
}

/// Read a ULEB128 value, returning the value and the number of bytes consumed.
///
/// Rejects values wider than 32 bits and values that run off the end of the
/// buffer; both are reachable from hostile input.
pub fn read_uleb128(bytes: &[u8], at: usize) -> Result<(u32, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let byte = *bytes.get(i).ok_or(Error::BadUleb128 { at })?;
        i += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(Error::BadUleb128 { at });
        }
    }
    if result > u32::MAX as u64 {
        return Err(Error::BadUleb128 { at });
    }
    Ok((result as u32, i - at))
}

/// Read a SLEB128 value, returning the value and the number of bytes consumed.
pub fn read_sleb128(bytes: &[u8], at: usize) -> Result<(i32, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let byte = *bytes.get(i).ok_or(Error::BadUleb128 { at })?;
        i += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1i64 << shift;
            }
            break;
        }
        if shift >= 35 {
            return Err(Error::BadUleb128 { at });
        }
    }
    Ok((result as i32, i - at))
}

/// Append `v` to `out` as ULEB128.
pub fn write_uleb128(out: &mut Vec<u8>, mut v: u32) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trips() {
        let s = "Lcom/example/Foo;";
        let bytes = encode(s);
        assert_eq!(*bytes.last().unwrap(), 0);
        let (out, used) = decode(&bytes).unwrap();
        assert_eq!(out, s);
        assert_eq!(used, bytes.len() - 1);
    }

    #[test]
    fn nul_is_encoded_as_c0_80() {
        let bytes = encode("a\0b");
        assert_eq!(bytes, vec![b'a', 0xc0, 0x80, b'b', 0x00]);
        let (s, _) = decode(&bytes).unwrap();
        assert_eq!(s, "a\0b");
    }

    #[test]
    fn two_byte_form_round_trips() {
        let s = "caf\u{e9}\u{7ff}";
        let (out, _) = decode(&encode(s)).unwrap();
        assert_eq!(out, s);
    }

    #[test]
    fn astral_is_stored_as_a_surrogate_pair() {
        let s = "\u{1f600}"; // U+1F600 GRINNING FACE
        let bytes = encode(s);
        // Three bytes per surrogate, two surrogates: no 4-byte sequence.
        assert_eq!(bytes.len(), 3 + 3 + 1);
        assert_eq!(bytes[0] & 0xf0, 0xe0, "first surrogate lead byte");
        assert_eq!(bytes[3] & 0xf0, 0xe0, "second surrogate lead byte");
        let (out, _) = decode(&bytes).unwrap();
        assert_eq!(out, s);
        assert_eq!(utf16_len(s), 2);
    }

    #[test]
    fn unpaired_surrogate_becomes_replacement_not_panic() {
        // ED A0 80 is U+D800 in isolation, which the spec permits.
        let bytes = [0xed, 0xa0, 0x80, 0x00];
        let (s, _) = decode(&bytes).unwrap();
        assert_eq!(s, "\u{fffd}");
    }

    #[test]
    fn four_byte_sequence_is_rejected() {
        // U+1F600 encoded as ordinary UTF-8. Legal UTF-8, illegal MUTF-8.
        let bytes = [0xf0, 0x9f, 0x98, 0x80, 0x00];
        assert!(matches!(decode(&bytes), Err(Error::BadMutf8 { at: 0 })));
    }

    #[test]
    fn overlong_ascii_is_rejected() {
        let bytes = [0xe0, 0x81, 0x81, 0x00]; // 3-byte overlong 'A'
        assert!(matches!(decode(&bytes), Err(Error::BadMutf8 { at: 0 })));
    }

    #[test]
    fn missing_terminator_is_an_error() {
        assert!(matches!(decode(b"abc"), Err(Error::BadMutf8 { .. })));
        assert!(matches!(decode(&[0xe0, 0x80]), Err(Error::BadMutf8 { .. })));
    }

    #[test]
    fn uleb128_round_trips() {
        for v in [0u32, 1, 0x7f, 0x80, 0x3fff, 0x4000, 0xffff_ffff] {
            let mut b = Vec::new();
            write_uleb128(&mut b, v);
            assert_eq!(read_uleb128(&b, 0).unwrap(), (v, b.len()), "value {v}");
        }
    }

    #[test]
    fn uleb128_known_encodings() {
        let mut zero = Vec::new();
        write_uleb128(&mut zero, 0);
        assert_eq!(zero, vec![0x00]);
        let mut b = Vec::new();
        write_uleb128(&mut b, 0x80);
        assert_eq!(b, vec![0x80, 0x01]);
    }

    #[test]
    fn uleb128_rejects_runaway_and_truncation() {
        assert!(matches!(read_uleb128(&[0x80; 8], 0), Err(Error::BadUleb128 { .. })));
        assert!(matches!(read_uleb128(&[0x80], 0), Err(Error::BadUleb128 { .. })));
        assert!(matches!(read_uleb128(&[], 0), Err(Error::BadUleb128 { .. })));
    }

    #[test]
    fn sleb128_sign_extends() {
        assert_eq!(read_sleb128(&[0x00], 0).unwrap(), (0, 1));
        assert_eq!(read_sleb128(&[0x7f], 0).unwrap(), (-1, 1));
        assert_eq!(read_sleb128(&[0x40], 0).unwrap(), (-64, 1));
        assert_eq!(read_sleb128(&[0xff, 0x7f], 0).unwrap(), (-1, 2));
        assert_eq!(read_sleb128(&[0x80, 0x7f], 0).unwrap(), (-128, 2));
    }
}
