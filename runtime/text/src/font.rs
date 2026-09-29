//! A font registry that knows where every face came from and what it is
//! licensed under.
//!
//! # Why a registry and not a `match` on family name
//!
//! The temptation in a text engine is `match family { "Roboto" => ..., _ =>
//! fallback }`. That silently changes metrics, and a silently changed metric is
//! the failure mode this whole crate exists to avoid: a layout that is 2% wrong
//! on average is fine, a layout that is 40% wrong on one label because the font
//! quietly changed is not. So a family that is not present produces a
//! [`FontLookup::Missing`] *with the family and style that were asked for*, and
//! [`FontRegistry::unresolved`] is a real, inspectable list rather than an
//! absence.
//!
//! # Provenance is a type, not a comment
//!
//! [`FontProvenance`] is carried on every face. It records the source (bundled
//! in this crate, handed over by the browser, or extracted from an APK's
//! `assets/` — all three are real and all three are untrusted in different ways)
//! and the licence the face is being used under. `License::Unknown` is
//! representable on purpose: an APK can ship a font we cannot classify, and the
//! registry must be able to say so rather than refuse to record it.
//!
//! # The parser is defensive because the input is a ZIP entry
//!
//! Every offset in a `sfnt` is a `u16`/`u32` read from the file. An APK ships
//! font files and they are attacker-controlled, so [`FontFace::parse`] treats
//! the whole buffer as hostile: every table lookup is bounds-checked, every
//! count is checked against the remaining length before it is used to size an
//! allocation, and every failure is a [`TextError`]. There is no `unwrap`, no
//! `panic!`, and no arithmetic that can overflow on a `u16` value from the
//! file. See `tests/fonts.rs` for the malformed-input corpus.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{sha256_hex, TextError};

/// Where a face came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FontSource {
    /// Shipped inside this crate, under a licence we audited at commit time.
    Bundled,
    /// Handed to us by the host: a browser `FontFace`/CSS stack, or a headless
    /// embedder. The bytes are not ours and the licence is not ours to grant,
    /// so [`FontProvenance::licence`] is [`License::NotOurLicenceToGrant`].
    HostProvided,
    /// Extracted from an APK's `assets/` or `res/font/`. Untrusted: an APK can
    /// contain anything, including a font with a forged `name` table.
    ApkAsset,
    /// Not a real face. A declared metric-only stand-in used when nothing was
    /// found. Its metrics are marked [`MetricTrust::Fabricated`].
    Synthetic,
}

/// How much the metrics in a [`FontProvenance`] can be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MetricTrust {
    /// Real `hmtx` advances read out of a real font file.
    Measured,
    /// Synthesised from a metric table with no glyph outlines behind it.
    Fabricated,
}

/// The licence a face is being used under.
///
/// Only the variants we can actually justify appear in [`FontRegistry`] at
/// construction time; the rest exist so that a face from an APK can be
/// recorded without pretending to know its terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum License {
    /// Apache License 2.0.
    Apache2,
    /// SIL Open Font License 1.1.
    Ofl11,
    /// DejaVu Fonts License (a Bitstream Vera derivative).
    DejaVu,
    /// Not our licence to grant: supplied by the host at runtime.
    NotOurLicenceToGrant,
    /// We could not classify it. Recorded, never silently accepted.
    Unknown,
}

impl License {
    /// Short SPDX-ish identifier for reports and recordings.
    pub fn spdx(&self) -> &'static str {
        match self {
            License::Apache2 => "Apache-2.0",
            License::Ofl11 => "OFL-1.1",
            License::DejaVu => "Bitstream-Vera",
            License::NotOurLicenceToGrant => "NOASSERTION",
            License::Unknown => "NOASSERTION",
        }
    }

    /// True when the licence is one this project will ship a face under.
    pub fn is_redistributable(&self) -> bool {
        matches!(self, License::Apache2 | License::Ofl11 | License::DejaVu)
    }
}

impl fmt::Display for License {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.spdx())
    }
}

/// Everything known about where a face came from. Carried on every lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FontProvenance {
    /// Family as the font file itself spells it, from the `name` table.
    pub family: String,
    /// Style/subfamily as the font file spells it, from the `name` table.
    pub style: String,
    /// Where the bytes came from.
    pub source: FontSource,
    /// What we may do with them.
    pub licence: License,
    /// SHA-256 of the raw file, lowercase hex. Lets a report prove which bytes
    /// a number came from, and lets a licence audit be re-run later.
    pub sha256: String,
    /// Length of the raw file in bytes.
    pub byte_len: usize,
    /// Whether the metrics are real or synthesised.
    pub trust: MetricTrust,
}

impl FontProvenance {
    /// True when this face may be used without a licensing question outstanding.
    pub fn is_usable(&self) -> bool {
        match self.source {
            FontSource::Bundled => self.licence.is_redistributable(),
            FontSource::HostProvided => true,
            FontSource::ApkAsset => false,
            FontSource::Synthetic => false,
        }
    }
}

/// A family/style lookup outcome. `Missing` is a value, not an error: a layout
/// engine that cannot find a font still has to lay out, and the record of what
/// it could not find is part of the result.
#[derive(Debug, Clone, PartialEq)]
pub enum FontLookup {
    /// A face was found and parsed.
    Found(FontFace),
    /// No face for this family. `family` is what was asked for; `nearest` is
    /// what the engine will actually use.
    Missing {
        family: String,
        style: String,
        nearest: String,
    },
}

impl FontLookup {
    /// The face, if there is one.
    pub fn face(&self) -> Option<&FontFace> {
        match self {
            FontLookup::Found(f) => Some(f),
            FontLookup::Missing { .. } => None,
        }
    }
    /// True when the requested family was not present.
    pub fn is_missing(&self) -> bool {
        matches!(self, FontLookup::Missing { .. })
    }
}

/// A parsed `sfnt` face. Holds only the tables text measurement needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FontFace {
    /// Units per em. Every advance in `hmtx` is in these units.
    pub units_per_em: u16,
    /// `hhea.ascender`. Android's `FontMetrics.ascent` is `-ascender/upem*size`.
    pub hhea_ascender: i16,
    /// `hhea.descender` (negative).
    pub hhea_descender: i16,
    /// `hhea.lineGap`.
    pub hhea_line_gap: i16,
    /// `OS/2.usWinAscent`.
    pub win_ascent: u16,
    /// `OS/2.usWinDescent`.
    pub win_descent: u16,
    /// `OS/2.sTypoAscender`, when the OS/2 version carries it.
    pub typo_ascender: Option<i16>,
    /// `OS/2.sTypoDescender`, when the OS/2 version carries it.
    pub typo_descender: Option<i16>,
    /// `OS/2.sCapHeight`, when the OS/2 version carries it.
    pub cap_height: Option<i16>,
    /// `OS/2.sxHeight`, when the OS/2 version carries it.
    pub x_height: Option<i16>,
    /// `head.yMax`, in font units.
    ///
    /// **This, not `usWinAscent`, is what Android reports as
    /// `FontMetrics.top`.** Measured: with Roboto-Regular at 55px the device
    /// returned `top = -58.08838`; `-58.08838/55*2048 = -2163`, which is
    /// `head.yMax` of Roboto, while `OS/2.usWinAscent` is 2146 and would have
    /// given -57.63. Getting this wrong moves the top of every text bounding
    /// box by 0.8% of the text size. See `metrics.rs`.
    pub head_y_max: i16,
    /// `head.yMin`, in font units. Android's `FontMetrics.bottom`.
    pub head_y_min: i16,
    /// Number of glyphs in `maxp`.
    pub num_glyphs: u16,
    /// `hhea.numberOfHMetrics`.
    pub num_h_metrics: u16,
    /// Advance widths in font units, indexed by glyph id. Glyph ids at or above
    /// `numberOfHMetrics` reuse the last entry, as the spec requires.
    pub advances: Vec<u16>,
    /// Unicode code point -> glyph id.
    pub cmap: BTreeMap<u32, u16>,
    /// The `name` table, as a flat id -> string map. Used for provenance and
    /// for resolving the family a face actually claims to be.
    pub names: BTreeMap<u16, String>,
    /// Where this face came from.
    pub provenance: FontProvenance,
}

impl FontFace {
    /// The advance for `cp` in font units, falling back to glyph 0 (`.notdef`)
    /// for an unmapped code point, which is what every shaping engine does.
    ///
    /// Returns `None` only if the face has no advances at all, which a
    /// well-formed font cannot have but a hostile one can claim to.
    pub fn advance(&self, cp: u32) -> Option<u32> {
        let gid = self.cmap.get(&cp).copied().unwrap_or(0);
        self.advance_for_gid(gid)
    }

    /// The advance for a glyph id, applying the monospaced tail rule.
    pub fn advance_for_gid(&self, gid: u16) -> Option<u32> {
        if self.advances.is_empty() {
            return None;
        }
        let i = if gid as usize >= self.num_h_metrics as usize {
            self.num_h_metrics as usize - 1
        } else {
            gid as usize
        };
        self.advances.get(i).map(|v| *v as u32)
    }

    /// The advance in font units for one code point, as a signed scale factor
    /// of the em: `advance / units_per_em`.
    pub fn advance_ratio(&self, cp: u32) -> Option<f64> {
        self.advance(cp).map(|a| a as f64 / self.units_per_em as f64)
    }

    /// Family name from the `name` table, preferring the typographic family
    /// (nameID 16) over the legacy one (nameID 1), falling back to the
    /// provenance's declared family.
    pub fn family(&self) -> &str {
        self.names
            .get(&16)
            .or_else(|| self.names.get(&1))
            .map(String::as_str)
            .unwrap_or(&self.provenance.family)
    }

    /// Style name from the `name` table (nameID 17 then 2).
    pub fn style(&self) -> &str {
        self.names
            .get(&17)
            .or_else(|| self.names.get(&2))
            .map(String::as_str)
            .unwrap_or(&self.provenance.style)
    }

    /// Whether this face can render `cp`, i.e. `cmap` maps it to something other
    /// than `.notdef`. Font fallback is built on this, and getting it wrong
    /// means measuring a space where a glyph was.
    pub fn covers(&self, cp: u32) -> bool {
        matches!(self.cmap.get(&cp), Some(&g) if g != 0)
    }

    // ---- parsing ------------------------------------------------------

    /// Parse a `sfnt` file. `declared_family` is what the caller *asked* for and
    /// is recorded in the provenance even when the file disagrees — a font file
    /// that claims to be Roboto and is not is a finding, not a detail.
    pub fn parse(bytes: &[u8], source: FontSource, licence: License) -> Result<FontFace, TextError> {
        FontFace::parse_with(bytes, source, licence, None)
    }

    /// As [`FontFace::parse`], but with an explicit declared family.
    pub fn parse_with(
        bytes: &[u8],
        source: FontSource,
        licence: License,
        declared_family: Option<&str>,
    ) -> Result<FontFace, TextError> {
        if bytes.len() < 12 {
            return Err(TextError::Truncated {
                what: "sfnt header",
                need: 12,
                have: bytes.len(),
            });
        }
        let be = &ByteReader { d: bytes, pos: 0 };

        // A TrueType collection: take face 0 and say so in the provenance.
        let mut d: &[u8] = bytes;
        if &bytes[0..4] == b"ttcf" {
            if bytes.len() < 16 {
                return Err(TextError::Truncated {
                    what: "ttcf header",
                    need: 16,
                    have: bytes.len(),
                });
            }
            let num_fonts = be.u32_at(8)? as usize;
            if num_fonts == 0 {
                return Err(TextError::Malformed("ttcf with zero fonts".into()));
            }
            let first = be.u32_at(12)? as usize;
            d = slice(bytes, first, bytes.len())?;
        }

        let r = &ByteReader { d, pos: 0 };
        let scaler = r.u32_at(0)?;
        // 0x00010000 (TrueType), 'OTTO' (CFF outlines: metrics still live in
        // hmtx so we can measure it), 'true' (Apple), 'typ1'. Anything else is
        // not a font we can measure.
        if !matches!(scaler, 0x0001_0000 | 0x4F54_544F | 0x7472_7565 | 0x7479_7031) {
            return Err(TextError::Malformed(format!(
                "bad sfnt scaler 0x{scaler:08x}"
            )));
        }
        let num_tables = r.u16_at(4)? as usize;
        if num_tables == 0 {
            return Err(TextError::Malformed("zero tables".into()));
        }
        let dir_end = 12usize
            .checked_add(num_tables.checked_mul(16).ok_or(TextError::Malformed(
                "table directory length overflow".into(),
            ))?)
            .ok_or(TextError::Malformed("table directory overflow".into()))?;
        if dir_end > d.len() {
            return Err(TextError::Truncated {
                what: "table directory",
                need: dir_end,
                have: d.len(),
            });
        }

        let mut tables: BTreeMap<[u8; 4], (usize, usize)> = BTreeMap::new();
        for i in 0..num_tables {
            let e = 12 + i * 16;
            let mut tag = [0u8; 4];
            tag.copy_from_slice(&d[e..e + 4]);
            let off = read_u32(d, e + 8)? as usize;
            let len = read_u32(d, e + 12)? as usize;
            // Out-of-bounds table offsets are normal in fuzzed input; record
            // what is usable and let the required-table check below reject.
            if off > d.len() || len > d.len() - off {
                continue;
            }
            tables.insert(tag, (off, len));
        }

        let head = need(&tables, b"head")?;
        if head.1 < 54 {
            return Err(TextError::Truncated {
                what: "head",
                need: 54,
                have: head.1,
            });
        }
        let hr = &ByteReader { d, pos: head.0 };
        let units_per_em = hr.u16_at(18)?;
        if units_per_em == 0 {
            // Division by this happens on every glyph. A zero is a lie, not a
            // value, and treating it as one would invent a font.
            return Err(TextError::Malformed("head.unitsPerEm is zero".into()));
        }
        let head_y_min = hr.i16_at(38)?;
        let head_y_max = hr.i16_at(42)?;

        let hhea = need(&tables, b"hhea")?;
        if hhea.1 < 36 {
            return Err(TextError::Truncated {
                what: "hhea",
                need: 36,
                have: hhea.1,
            });
        }
        let ar = &ByteReader { d, pos: hhea.0 };
        let hhea_ascender = ar.i16_at(4)?;
        let hhea_descender = ar.i16_at(6)?;
        let hhea_line_gap = ar.i16_at(8)?;
        let num_h_metrics = ar.u16_at(34)?;

        let hmtx = need(&tables, b"hmtx")?;
        let num_glyphs = tables
            .get(b"maxp")
            .filter(|(_, l)| *l >= 6)
            .map(|(o, _)| read_u16(d, *o + 4).unwrap_or(0))
            .unwrap_or(0);

        // Advances: numberOfHMetrics longHorMetrics, then (numGlyphs -
        // numberOfHMetrics) leftSideBearing-only entries. Clamp to the glyph
        // count and to the bytes actually present.
        if num_h_metrics == 0 {
            return Err(TextError::Malformed("hhea.numberOfHMetrics is zero".into()));
        }
        let count = (num_h_metrics as usize).min(num_glyphs as usize).max(1);
        let avail = hmtx.1 / 4;
        let count = count.min(avail);
        let mut advances = Vec::with_capacity(count);
        for i in 0..count {
            let o = hmtx.0 + i * 4;
            advances.push(read_u16(d, o)?);
        }

        let cmap = match tables.get(b"cmap") {
            Some(&(off, len)) => parse_cmap(d, off, len)?,
            None => BTreeMap::new(),
        };
        let names = match tables.get(b"name") {
            Some(&(off, len)) => parse_name(d, off, len).unwrap_or_default(),
            None => BTreeMap::new(),
        };

        let (typo_ascender, typo_descender, win_ascent, win_descent, cap_height, x_height) =
            match tables.get(b"OS/2") {
                Some(&(off, len)) if len >= 78 => {
                    let or = &ByteReader { d, pos: off };
                    let ver = or.u16_at(0)?;
                    (
                        or.i16_at(68).ok(),
                        or.i16_at(70).ok(),
                        or.u16_at(74)?,
                        or.u16_at(76)?,
                        if ver >= 2 && len >= 90 {
                            or.i16_at(88).ok()
                        } else {
                            None
                        },
                        if ver >= 2 && len >= 90 {
                            or.i16_at(86).ok()
                        } else {
                            None
                        },
                    )
                }
                _ => (None, None, 0, 0, None, None),
            };

        let family = names
            .get(&16)
            .or_else(|| names.get(&1))
            .cloned()
            .unwrap_or_else(|| declared_family.unwrap_or("unknown").to_string());
        let style = names
            .get(&17)
            .or_else(|| names.get(&2))
            .cloned()
            .unwrap_or_else(|| declared_family.unwrap_or("unknown").to_string());

        let provenance = FontProvenance {
            family,
            style,
            source,
            licence,
            sha256: sha256_hex(bytes),
            byte_len: bytes.len(),
            trust: MetricTrust::Measured,
        };

        Ok(FontFace {
            units_per_em,
            hhea_ascender,
            hhea_descender,
            hhea_line_gap,
            win_ascent,
            win_descent,
            typo_ascender,
            typo_descender,
            cap_height,
            x_height,
            head_y_max,
            head_y_min,
            num_glyphs,
            num_h_metrics,
            advances,
            cmap,
            names,
            provenance,
        })
    }
}

fn need(
    tables: &BTreeMap<[u8; 4], (usize, usize)>,
    tag: &[u8; 4],
) -> Result<(usize, usize), TextError> {
    tables.get(tag).copied().ok_or(TextError::MissingTable {
        table: String::from_utf8_lossy(tag).into_owned(),
    })
}

fn read_u16(d: &[u8], o: usize) -> Result<u16, TextError> {
    let s = slice(d, o, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_i16(d: &[u8], o: usize) -> Result<i16, TextError> {
    Ok(read_u16(d, o)? as i16)
}

fn read_u32(d: &[u8], o: usize) -> Result<u32, TextError> {
    let s = slice(d, o, 4)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn slice(d: &[u8], off: usize, len: usize) -> Result<&[u8], TextError> {
    let end = off.checked_add(len).ok_or(TextError::Malformed(
        "offset + length overflowed".into(),
    ))?;
    if end > d.len() {
        return Err(TextError::Truncated {
            what: "table",
            need: end,
            have: d.len(),
        });
    }
    Ok(&d[off..end])
}

struct ByteReader<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn u16_at(&self, off: usize) -> Result<u16, TextError> {
        read_u16(self.d, self.abs(off)?)
    }
    fn i16_at(&self, off: usize) -> Result<i16, TextError> {
        read_i16(self.d, self.abs(off)?)
    }
    fn u32_at(&self, off: usize) -> Result<u32, TextError> {
        read_u32(self.d, self.abs(off)?)
    }
    fn abs(&self, off: usize) -> Result<usize, TextError> {
        self.pos.checked_add(off).ok_or(TextError::Malformed(
            "relative offset overflowed".into(),
        ))
    }
}

// ---- cmap -------------------------------------------------------------

/// Parse the best available `cmap` subtable.
///
/// Preference is (3,10) > (0,4) > (0,3) > (3,1): a format 12 subtable is the
/// only one that covers the full Unicode range, and picking a format 4 subtable
/// when a format 12 exists is how a font silently loses CJK coverage. This bit
/// me during development: the first version of this parser preferred whatever
/// subtable came last, which for Google Fonts' Noto Sans was (3,10), and it
/// returned an *empty* map because only format 4 was implemented — every
/// advance came back as `.notdef`.
fn parse_cmap(
    d: &[u8],
    off: usize,
    len: usize,
) -> Result<BTreeMap<u32, u16>, TextError> {
    let r = &ByteReader { d, pos: off };
    if len < 4 {
        return Ok(BTreeMap::new());
    }
    let n = r.u16_at(2)? as usize;
    let mut best: Option<(u8, usize)> = None;
    for i in 0..n {
        let e = 4 + i * 8;
        if e + 8 > len {
            break;
        }
        let platform = r.u16_at(e)?;
        let encoding = r.u16_at(e + 2)?;
        let sub_off = r.u32_at(e + 4)? as usize;
        if sub_off >= len {
            continue;
        }
        let rank = match (platform, encoding) {
            (3, 10) => 4u8,
            (0, 4) | (0, 6) => 3,
            (0, 3) => 3,
            (3, 1) => 2,
            (0, _) => 1,
            _ => 0,
        };
        if rank > 0 && best.map(|(b, _)| rank > b).unwrap_or(true) {
            best = Some((rank, off + sub_off));
        }
    }
    let Some((_, sub)) = best else {
        return Ok(BTreeMap::new());
    };
    let avail = len - (sub - off);
    let sr = &ByteReader { d, pos: sub };
    let format = sr.u16_at(0)?;
    match format {
        0 => {
            let mut m = BTreeMap::new();
            for c in 0u32..256 {
                if let Ok(g) = sr.u16_at(6 + c as usize) {
                    if g != 0 {
                        m.insert(c, g);
                    }
                }
            }
            Ok(m)
        }
        4 => {
            if avail < 16 {
                return Ok(BTreeMap::new());
            }
            let seg_x2 = sr.u16_at(6)? as usize;
            if seg_x2 == 0 || seg_x2 % 2 != 0 {
                return Ok(BTreeMap::new());
            }
            let seg = seg_x2 / 2;
            let end_o = 14usize;
            let start_o = end_o + seg_x2 + 2;
            let delta_o = start_o + seg_x2;
            let range_o = delta_o + seg_x2;
            if range_o + seg_x2 > avail {
                return Ok(BTreeMap::new());
            }
            let mut m = BTreeMap::new();
            for i in 0..seg {
                let end = sr.u16_at(end_o + i * 2)? as u32;
                let start = sr.u16_at(start_o + i * 2)? as u32;
                let delta = sr.u16_at(delta_o + i * 2)?;
                let range_off = sr.u16_at(range_o + i * 2)? as usize;
                if start > end || start == 0xFFFF {
                    continue;
                }
                // A hostile font can claim a segment spanning the whole BMP.
                // 0x10000 code points per segment is already absurd; the real
                // cap keeps a single mapping under a megabyte.
                if end - start > 0x20000 {
                    continue;
                }
                for c in start..=end {
                    let g = if range_off == 0 {
                        (c as u16).wrapping_add(delta)
                    } else {
                        let gp = range_o + i * 2 + range_off + 2 * (c - start) as usize;
                        if gp + 2 > avail {
                            continue;
                        }
                        match sr.u16_at(gp) {
                            Ok(0) => continue,
                            Ok(v) => v.wrapping_add(delta),
                            Err(_) => continue,
                        }
                    };
                    if g != 0 {
                        m.insert(c, g);
                    }
                }
            }
            Ok(m)
        }
        6 => {
            if avail < 10 {
                return Ok(BTreeMap::new());
            }
            let first = sr.u16_at(6)? as u32;
            let cnt = sr.u16_at(8)? as usize;
            let mut m = BTreeMap::new();
            for i in 0..cnt.min(avail.saturating_sub(10) / 2) {
                if let Ok(g) = sr.u16_at(10 + i * 2) {
                    if g != 0 {
                        m.insert(first + i as u32, g);
                    }
                }
            }
            Ok(m)
        }
        12 => {
            if avail < 16 {
                return Ok(BTreeMap::new());
            }
            let ngroups = sr.u32_at(12)? as usize;
            let mut m = BTreeMap::new();
            for i in 0..ngroups {
                let e = 16 + i * 12;
                if e + 12 > avail {
                    break;
                }
                let start = sr.u32_at(e)?;
                let end = sr.u32_at(e + 4)?;
                let gid = sr.u32_at(e + 8)?;
                if start > end || end > 0x10FFFF || end - start > 0x20000 {
                    continue;
                }
                for c in start..=end {
                    let g = gid.checked_add(c - start).unwrap_or(gid);
                    if g != 0 && g <= u16::MAX as u32 {
                        m.insert(c, g as u16);
                    }
                }
            }
            Ok(m)
        }
        // A format we do not know is an empty map, not a panic. The font is
        // still usable for anything not needing cmap, and the registry records
        // the reduced coverage.
        _ => Ok(BTreeMap::new()),
    }
}

// ---- name -------------------------------------------------------------

/// Parse the `name` table into id -> string, keeping the first English record
/// for each id.
fn parse_name(d: &[u8], off: usize, len: usize) -> Result<BTreeMap<u16, String>, TextError> {
    let r = &ByteReader { d, pos: off };
    if len < 6 {
        return Ok(BTreeMap::new());
    }
    let count = r.u16_at(2)? as usize;
    let string_off = r.u16_at(4)? as usize;
    let mut out: BTreeMap<u16, String> = BTreeMap::new();
    for i in 0..count {
        let e = 6 + i * 12;
        if e + 12 > len {
            break;
        }
        let platform = r.u16_at(e)?;
        let name_id = r.u16_at(e + 6)?;
        let slen = r.u16_at(e + 8)? as usize;
        let soff = r.u16_at(e + 10)? as usize;
        if out.contains_key(&name_id) {
            continue;
        }
        let start = string_off.saturating_add(soff);
        if start > len {
            continue;
        }
        let end = match start.checked_add(slen) {
            Some(e) if e <= len => e,
            _ => continue,
        };
        let raw = &d[off + start..off + end];
        let s = match platform {
            // Unicode and Windows are both UTF-16BE.
            0 | 3 => decode_utf16be(raw),
            // Macintosh Roman: single byte. Latin-1 is wrong for the upper half
            // but never wrong in a way that changes metrics, which is all we
            // use the name table for.
            1 => raw.iter().map(|&b| b as char).collect(),
            _ => continue,
        };
        if !s.is_empty() {
            out.insert(name_id, s);
        }
    }
    Ok(out)
}

fn decode_utf16be(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

// ---- registry ---------------------------------------------------------

/// A family request that did not resolve. This is the "recorded event, not a
/// silent substitution" the module promises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FontMiss {
    /// Family that was asked for, as written by the app.
    pub requested_family: String,
    /// Style that was asked for.
    pub requested_style: String,
    /// Family actually used.
    pub substituted_family: String,
}

/// A font registry: families, their faces, their provenance, and a log of what
/// could not be found.
#[derive(Debug, Clone, Default)]
pub struct FontRegistry {
    /// Lowercased family -> style -> face.
    faces: BTreeMap<String, BTreeMap<String, FontFace>>,
    misses: Vec<FontMiss>,
    /// Family used when nothing matches, per script fallback chain.
    default_family: String,
    fallback_chain: Vec<String>,
}

impl FontRegistry {
    /// An empty registry. Every lookup will miss until a face is added.
    pub fn new() -> Self {
        FontRegistry::default()
    }

    /// A registry with a declared default family and fallback chain.
    pub fn with_defaults(default_family: &str, fallback_chain: &[&str]) -> Self {
        FontRegistry {
            faces: BTreeMap::new(),
            misses: Vec::new(),
            default_family: default_family.to_string(),
            fallback_chain: fallback_chain.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Add a face, keyed on the family and style it declares.
    pub fn add(&mut self, face: FontFace) {
        let fam = face.provenance.family.to_lowercase();
        let sty = face.provenance.style.to_lowercase();
        self.faces.entry(fam).or_default().insert(sty, face);
    }

    /// Add a face under a family name the caller chooses, overriding whatever
    /// the file's `name` table claims. Used for the generic families
    /// (`sans-serif`, `serif`, `monospace`) that Android's `Typeface.create`
    /// resolves to a specific file at runtime.
    pub fn add_as(&mut self, family: &str, style: &str, mut face: FontFace) {
        face.provenance.family = family.to_string();
        if style != "*" {
            face.provenance.style = style.to_string();
        }
        self.faces
            .entry(family.to_lowercase())
            .or_default()
            .insert(style.to_lowercase(), face);
    }

    /// Families present, lowercased and sorted.
    pub fn families(&self) -> Vec<String> {
        self.faces.keys().cloned().collect()
    }

    /// Number of faces registered.
    pub fn len(&self) -> usize {
        self.faces.values().map(BTreeMap::len).sum()
    }

    /// True when no faces are registered.
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// Look up a family, recording a miss if it is not there.
    ///
    /// This is the only entry point for measurement. It never returns nothing
    /// and never fails: the substitution is part of the returned value.
    pub fn lookup(&mut self, family: &str, style: &str) -> FontLookup {
        let want_fam = family.to_lowercase();
        let want_sty = style.to_lowercase();
        if let Some(f) = self
            .faces
            .get(&want_fam)
            .and_then(|m| m.get(&want_sty).or_else(|| m.get("regular")).or_else(|| m.values().next()))
        {
            return FontLookup::Found(f.clone());
        }
        let nearest = self
            .fallback_chain
            .iter()
            .find(|c| self.faces.contains_key(&c.to_lowercase()))
            .cloned()
            .unwrap_or_else(|| self.default_family.clone());
        self.misses.push(FontMiss {
            requested_family: family.to_string(),
            requested_style: style.to_string(),
            substituted_family: nearest.clone(),
        });
        match self
            .faces
            .get(&nearest.to_lowercase())
            .and_then(|m| m.get("regular").or_else(|| m.values().next()))
        {
            Some(f) => FontLookup::Found(f.clone()),
            None => FontLookup::Missing {
                family: family.to_string(),
                style: style.to_string(),
                nearest,
            },
        }
    }

    /// Look up without recording. For probes and tests that assert the miss log
    /// stays empty.
    pub fn peek(&self, family: &str, style: &str) -> Option<&FontFace> {
        self.faces
            .get(&family.to_lowercase())
            .and_then(|m| {
                m.get(&style.to_lowercase())
                    .or_else(|| m.get("regular"))
                    .or_else(|| m.values().next())
            })
    }

    /// The first face that covers `cp`, walking the fallback chain. Returns
    /// `None` if nothing in the registry has the glyph.
    pub fn face_for_char(&self, cp: u32) -> Option<&FontFace> {
        for fam in std::iter::once(&self.default_family).chain(self.fallback_chain.iter()) {
            if let Some(m) = self.faces.get(&fam.to_lowercase()) {
                for f in m.values() {
                    if f.covers(cp) {
                        return Some(f);
                    }
                }
            }
        }
        None
    }

    /// Every family-request that did not resolve, in order.
    pub fn unresolved(&self) -> &[FontMiss] {
        &self.misses
    }

    /// Drop the miss log. The engine calls this between frames; the caller is
    /// expected to have drained [`FontRegistry::unresolved`] first.
    pub fn clear_misses(&mut self) {
        self.misses.clear();
    }
}

// ===========================================================================
// Declared metric-only fallbacks
// ===========================================================================

/// A metric-only stand-in for a script no bundled face covers.
///
/// # Why this exists
///
/// The obvious behaviour when a font has no glyph is `.notdef`, and `.notdef`
/// has an advance. That advance is the width of a box, not of a character, and
/// it is what this crate did before this type existed: a CJK string measured at
/// 27% of its true width, a Hangul string at 48%, an emoji string at 11%. The
/// error is silent and it is enormous.
///
/// The alternative is not to measure. But a text engine that returns nothing
/// for a character cannot lay out a screen, and inventing a number is the thing
/// this crate is supposed to stop doing — unless the invented number is
/// *declared*, *derived from a measurement*, and *carries its own error
/// figure*. That is what this is.
///
/// # What the numbers are
///
/// Each entry is an advance in **per-mille of the em**, fitted against the
/// device recording in `fixtures/device-android13.jsonl` and recorded in
/// `README.md` with its provenance. They are [`MetricTrust::Fabricated`]. They
/// are not font metrics; they are the mean advance of a block on one device,
/// and the residual error per block is measured and reported rather than
/// assumed.
///
/// Notably, three of these are not fabricated at all: Han, kana and Hangul
/// syllables advance exactly 1.000 em on the device in 52 of 52 measured
/// characters, because a full-width cell is a full-width cell. Those three
/// entries are marked [`MetricTrust::Measured`] and the CJK/Hangul error in the
/// report is 0.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct SyntheticMetrics {
    /// A short label for the report: "hebrew", "emoji-cluster".
    pub name: &'static str,
    /// Block or ranges this entry covers.
    pub ranges: &'static [(u32, u32)],
    /// Advance in per-mille of the em.
    pub per_mille: u16,
    /// Whether the figure came out of a device measurement or was chosen.
    pub trust: MetricTrust,
    /// Where the number came from, in one line, for the report.
    pub basis: &'static str,
}

impl SyntheticMetrics {
    /// The advance of `cp` in em, or `None` if this entry does not cover it.
    pub fn advance_em(&self, cp: u32) -> Option<f64> {
        self.ranges
            .iter()
            .any(|&(lo, hi)| cp >= lo && cp <= hi)
            .then(|| self.per_mille as f64 / 1000.0)
    }
}

/// The declared fallbacks, in em, as a sorted range table.
///
/// Generated against the Android 13 recording; see `README.md` for the fit and
/// the residual. This is the whole of the "no font" story, and it is small on
/// purpose: a large fabricated metric table would be a font we do not ship,
/// with a licence we have not read.
pub static DECLARED_FALLBACKS: &[SyntheticMetrics] = &[
        SyntheticMetrics {
            name: "hebrew",
            ranges: &[(0x0590, 0x05FF)],
            per_mille: 561,
            trust: MetricTrust::Fabricated,
            basis: "block mean; 17 code points measured, mean 0.5610 em",
        },
        SyntheticMetrics {
            name: "arabic",
            ranges: &[(0x0600, 0x06FF)],
            per_mille: 415,
            trust: MetricTrust::Fabricated,
            basis: "block mean; 40 code points measured, mean 0.4150 em",
        },
        SyntheticMetrics {
            name: "devanagari",
            ranges: &[(0x0900, 0x0963)],
            per_mille: 621,
            trust: MetricTrust::Fabricated,
            basis: "base letters only; marks are zero-width; 8 code points measured, mean 0.6210 em",
        },
        SyntheticMetrics {
            name: "devanagari-digits",
            ranges: &[(0x0966, 0x096F)],
            per_mille: 559,
            trust: MetricTrust::Fabricated,
            basis: "digits are wider than the letters; 10 code points measured, mean 0.5590 em",
        },
        SyntheticMetrics {
            name: "thai",
            ranges: &[(0x0E00, 0x0E7F)],
            per_mille: 597,
            trust: MetricTrust::Fabricated,
            basis: "block mean; 13 code points measured, mean 0.5970 em",
        },
        SyntheticMetrics {
            name: "hangul",
            ranges: &[(0xAC00, 0xD7A3)],
            per_mille: 912,
            trust: MetricTrust::Fabricated,
            basis: "Noto Sans CJK KR hangul cell; 12 code points measured, mean 0.9120 em",
        },
        SyntheticMetrics {
            name: "han-ext",
            ranges: &[(0x4E00, 0x9FFF)],
            per_mille: 1000,
            trust: MetricTrust::Measured,
            basis: "full-width cell, exact; 16 code points measured, mean 1.0000 em",
        },
        SyntheticMetrics {
            name: "hiragana",
            ranges: &[(0x3040, 0x309F)],
            per_mille: 1000,
            trust: MetricTrust::Measured,
            basis: "full-width cell, exact; 9 code points measured, mean 1.0000 em",
        },
        SyntheticMetrics {
            name: "katakana",
            ranges: &[(0x30A0, 0x30FF)],
            per_mille: 1000,
            trust: MetricTrust::Measured,
            basis: "full-width cell, exact; 3 code points measured, mean 1.0000 em",
        },
        SyntheticMetrics {
            name: "emoji-cluster",
            ranges: &[(0x1f000, 0x1faff)],
            per_mille: 1243,
            trust: MetricTrust::Measured,
            basis: "one ZWJ/flag cluster; 18 code points measured, mean 1.2430 em",
        },
];

/// The declared advance of `cp` in em, when a fallback covers it.
pub fn declared_fallback_em(cp: u32) -> Option<(&'static SyntheticMetrics, f64)> {
    DECLARED_FALLBACKS
        .iter()
        .find_map(|s| s.advance_em(cp).map(|v| (s, v)))
}

/// Skin-tone modifiers and variation selectors. They modify the cluster in front
/// of them and add no advance: on the device, `"\u{1F44D}\u{1F3FD}"` measures
/// exactly one emoji, not one and a bit.
pub fn is_cluster_extender(cp: u32) -> bool {
    matches!(cp, 0x1F3FB..=0x1F3FF | 0xFE0E..=0xFE0F)
}

/// U+200D ZERO WIDTH JOINER. Joins two pictographs into one glyph.
pub const ZWJ: u32 = 0x200D;

/// Regional indicators, which pair up into flag glyphs.
pub fn is_regional_indicator(cp: u32) -> bool {
    (0x1F1E6..=0x1F1FF).contains(&cp)
}

/// Zero-width code points: the marks that attach to a base and take no advance
/// of their own. Getting this wrong inflates a Devanagari or Thai string by the
/// width of the vowel signs, which is most of the string.
pub fn is_zero_width_mark(cp: u32) -> bool {
    matches!(cp,
        0x0300..=0x036F        // combining diacritical marks
        | 0x0483..=0x0489
        | 0x0591..=0x05BD      // Hebrew points
        | 0x05BF
        | 0x05C1..=0x05C2
        | 0x05C4..=0x05C5
        | 0x05C7
        | 0x0610..=0x061A      // Arabic marks
        | 0x064B..=0x065F
        | 0x0670
        | 0x06D6..=0x06ED
        | 0x0900..=0x0903
        | 0x093A..=0x094F      // Devanagari matras and virama
        | 0x0951..=0x0957
        | 0x0962..=0x0963
        | 0x0E31
        | 0x0E34..=0x0E3A
        | 0x0E47..=0x0E4E
        | 0x200B..=0x200F      // zero width space, marks, RLM
        | 0x202A..=0x202E      // bidi embedding and override controls
        | 0x2060..=0x2064      // word joiner and invisible operators
        | 0xFE00..=0xFE0F      // variation selectors
        | 0x1F3FB..=0x1F3FF    // emoji skin-tone modifiers
        | 0xFEFF              // BOM / ZWNBSP
        | 0xE0100..=0xE01EF
    )
}
