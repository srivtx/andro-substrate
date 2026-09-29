//! The measurement seam. Everything the rest of the runtime needs to know about
//! the size of a piece of text goes through this file.
//!
//! # The published API
//!
//! [`measure`] returns a [`TextMetrics`]. That struct is the contract with
//! `runtime/graphics/` (B3) and it is deliberately boring: named fields, plain
//! `f32`/`i32`, no handles, no lifetimes, no fallible getters. A drawing path
//! that has to handle a `Result` to find out how tall a label is will end up
//! inventing a number, and an invented number is how a 40x error gets in.
//!
//! The fields, and what each one is *for*:
//!
//! | field | meaning | Android counterpart |
//! |---|---|---|
//! | `width` | advance width of one line, whole pixels | `Paint.measureText` |
//! | `ascent`, `descent` | signed, baseline-relative, px | `FontMetrics.ascent/descent` |
//! | `top`, `bottom` | signed, baseline-relative, px | `FontMetrics.top/bottom` |
//! | `line_height` | `ascent - descent + leading` | what `StaticLayout` uses for a line |
//! | `leading` | px | `FontMetrics.leading` |
//! | `min_ink`, `max_ink` | ink bounds, px | no `Paint` equivalent; ours only |
//!
//! # The rounding model, and why it is per-glyph
//!
//! Android's `Paint` has `subpixelText`, and the default is **off**. With
//! subpixel positioning off, each glyph's advance is rounded to a whole pixel
//! *before* it is summed. That is a different number from rounding the sum, and
//! it is worth a whole pixel of drift per string.
//!
//! Measured on the Android 13 emulator, Roboto-Regular at 55px,
//! `"Hello, world"`: the device returns `285.0`. Summing unrounded advances
//! gives `284.63`; rounding the total gives `285.0`; rounding each glyph gives
//! `285.0` and matches the per-glyph `getTextWidths` output exactly. The two
//! models agree here, so this is not yet a discriminating measurement —
//! `metrics.rs` reports the match rate of each model across the whole corpus
//! and says which ones survive. The default is per-glyph because that is what
//! the framework does; the harness is what tells us whether we got it right.
//!
//! # What is *not* modelled
//!
//! No `GPOS` kerning, no `GSUB` shaping — no ligatures, no contextual forms, no
//! cursive attachment. Android shapes with HarfBuzz and this does not. For
//! Latin that costs almost nothing; for Arabic, Devanagari and Thai it costs a
//! great deal, and `metrics.rs` measures exactly how much and reports it per
//! script rather than averaging it away. See README, "What we get wrong".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::font::{FontFace, FontRegistry};
use crate::TextError;

// ===========================================================================
// Bidi character classes and the generated table
// ===========================================================================

/// UAX#9 `Bidi_Class`. Table generated from Unicode 15.1.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum BidiClass {
    L,
    R,
    AL,
    EN,
    ES,
    ET,
    AN,
    CS,
    NSM,
    BN,
    B,
    S,
    WS,
    ON,
    LRE,
    LRO,
    RLE,
    RLO,
    PDF,
    LRI,
    RLI,
    FSI,
    PDI,
}

use BidiClass as B;

include!("bidi_table.rs");
include!("bidi_brackets.rs");

/// The `Bidi_Class` of a code point. Binary search over 1349 generated ranges.
pub fn bidi_class(cp: u32) -> BidiClass {
    let mut lo = 0usize;
    let mut hi = BIDI_RANGES.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let (s, e, c) = BIDI_RANGES[mid];
        if cp < s {
            hi = mid;
        } else if cp > e {
            lo = mid + 1;
        } else {
            return c;
        }
    }
    // Unreachable for any u32: the table's last range ends at 0x10FFFF and
    // anything above it is out of Unicode by definition.
    B::L
}

// ===========================================================================
// Style and metrics
// ===========================================================================

/// How glyph advances are quantised. Mirrors `Paint`'s subpixel/hinting knobs,
/// which are observable: an app can set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rounding {
    /// `subpixelText = false`, the framework default. Each glyph's advance is
    /// rounded to a whole pixel, then summed. The result is an integer.
    PerGlyphWholePixel,
    /// `subpixelText = true`. Advances stay fractional.
    Subpixel,
    /// The sum is rounded once at the end.
    WholePixelTotal,
}

/// Horizontal direction of a paragraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParagraphDirection {
    /// `Paint.measureText`'s `FIRST_STRONG_LTR` heuristic: an all-neutral
    /// string is left-to-right.
    FirstStrongLtr,
    /// `FIRST_STRONG_RTL`: an all-neutral string is right-to-left.
    FirstStrongRtl,
    /// Forced LTR, whatever the content says.
    Ltr,
    /// Forced RTL.
    Rtl,
}

/// Everything that affects a measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextStyle {
    /// Text size in **pixels**, as `Paint.setTextSize` takes it. The caller has
    /// already multiplied sp by density and `fontScale`; doing it here would
    /// mean guessing a density, and a wrong density is a wrong layout.
    pub text_size_px: f32,
    /// Family as the app asked for it. Looked up in the registry; a miss is
    /// recorded, never silently papered over.
    pub family: String,
    /// Style: `"regular"`, `"bold"`, `"italic"`, or anything the registry keyed.
    pub style: String,
    /// Extra advance per character, as a fraction of the em. `Paint
    /// .setLetterSpacing` takes em; we keep em so the value survives a
    /// textSize change the way the framework's does.
    pub letter_spacing_em: f32,
    /// Horizontal scale. `Paint.setTextScaleX`.
    pub text_scale_x: f32,
    /// Advance quantisation.
    pub rounding: Rounding,
    /// Paragraph direction.
    pub direction: ParagraphDirection,
    /// Locale tag, recorded for provenance. It does not change our numbers —
    /// this engine has one metric model — but a layout that is font-fallback
    /// sensitive needs to know the locale was fixed, and a report needs to say
    /// the measurement was locale-independent.
    pub locale: String,
}

impl Default for TextStyle {
    fn default() -> Self {
        TextStyle {
            text_size_px: 14.0,
            family: "sans-serif".to_string(),
            style: "regular".to_string(),
            letter_spacing_em: 0.0,
            text_scale_x: 1.0,
            rounding: Rounding::PerGlyphWholePixel,
            direction: ParagraphDirection::FirstStrongLtr,
            locale: "en-US".to_string(),
        }
    }
}

impl TextStyle {
    /// Android's `sp(14) -> px` at 1x, which is a useful neutral for tests.
    pub fn px(size: f32) -> Self {
        TextStyle {
            text_size_px: size,
            ..TextStyle::default()
        }
    }

    fn validate(&self) -> Result<(), TextError> {
        if !(self.text_size_px.is_finite() && self.text_size_px > 0.0) {
            return Err(TextError::InvalidStyle(format!(
                "text_size_px must be finite and > 0, got {}",
                self.text_size_px
            )));
        }
        if !self.text_scale_x.is_finite() {
            return Err(TextError::InvalidStyle("text_scale_x must be finite".into()));
        }
        if !self.letter_spacing_em.is_finite() {
            return Err(TextError::InvalidStyle(
                "letter_spacing_em must be finite".into(),
            ));
        }
        Ok(())
    }
}

/// The size of a piece of text. This is the type B3 consumes.
///
/// Every field is a plain number. There is no `Result` in the constructor
/// path a drawing pass takes; [`TextMetrics::safe`] exists only for the case
/// where a caller genuinely has no font at all and has to draw something.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TextMetrics {
    /// Advance width of the measured text, in pixels. Already multiplied by
    /// [`TextStyle::text_scale_x`] and including letter spacing.
    pub width: f32,
    /// Distance from the baseline up to the top of the line box, positive.
    pub ascent: f32,
    /// Distance from the baseline down to the bottom of the line box,
    /// positive. Android's `FontMetrics.descent` is *negative*; this is
    /// positive because every subtraction downstream would otherwise be an
    /// addition, and a sign flip that a drawing path gets wrong is invisible
    /// until the glyphs are upside down.
    pub descent: f32,
    /// Distance from the baseline up to the top of the font's ink bounds.
    pub top: f32,
    /// Distance from the baseline down to the bottom of the font's ink bounds.
    pub bottom: f32,
    /// Extra leading, `hhea.lineGap` scaled. Roboto has 0.
    pub leading: f32,
    /// `ascent + descent + leading`. What a `StaticLayout` line occupies.
    pub line_height: f32,
    /// Top of the inked area for this particular string, or `ascent` when the
    /// string is empty. Ours only: Android exposes no equivalent without
    /// rasterising, so do not treat it as a device-matched quantity.
    pub min_ink: f32,
    /// Bottom of the inked area for this particular string, or `descent` when
    /// the string is empty.
    pub max_ink: f32,
    /// Cap height for the face, or `ascent` when the face does not declare
    /// one. Some Android layouts baseline-align icons to cap height.
    pub cap_height: f32,
}

impl TextMetrics {
    /// Metrics for an empty string with no font: zero width, zero vertical.
    ///
    /// Named `safe` because it is the one place this crate fabricates numbers,
    /// and it is named so a reader has to go looking.
    pub fn safe() -> TextMetrics {
        TextMetrics {
            width: 0.0,
            ascent: 0.0,
            descent: 0.0,
            top: 0.0,
            bottom: 0.0,
            leading: 0.0,
            line_height: 0.0,
            min_ink: 0.0,
            max_ink: 0.0,
            cap_height: 0.0,
        }
    }

    /// Font-level metrics, independent of the string. Every `measure` call
    /// returns these unchanged, which is true of `Paint` too.
    pub fn vertical(font: &FontFace, size_px: f32) -> TextMetrics {
        let upem = font.units_per_em as f64;
        let k = size_px as f64 / upem;
        let ascent = -(font.hhea_ascender as f64 * k) as f32;
        let descent = -(font.hhea_descender as f64 * k) as f32;
        let top = -(font.head_y_max as f64 * k) as f32;
        let bottom = -(font.head_y_min as f64 * k) as f32;
        let leading = (font.hhea_line_gap as f64 * k) as f32;
        let cap = font
            .cap_height
            .map(|c| -(c as f64 * k) as f32)
            .unwrap_or(ascent);
        TextMetrics {
            width: 0.0,
            ascent,
            descent,
            top,
            bottom,
            leading,
            line_height: ascent + descent + leading,
            min_ink: ascent,
            max_ink: descent,
            cap_height: cap,
        }
    }
}

// ===========================================================================
// The measurement entry points
// ===========================================================================

/// Measure a single line of text.
///
/// This is `Paint.measureText` plus `Paint.getFontMetrics`, and it is the
/// function the rest of the runtime should call. It takes a resolved face
/// rather than a registry so that the registry's miss log is written in one
/// place, [`Shaper::measure`], and not scattered through the call stack.
pub fn measure(text: &str, style: &TextStyle, font: &FontFace) -> Result<TextMetrics, TextError> {
    style.validate()?;
    let mut m = TextMetrics::vertical(font, style.text_size_px);
    m.width = advance_of(text, style, font);
    m.min_ink = m.ascent;
    m.max_ink = m.descent;
    Ok(m)
}

/// Measure, and report how much of the result rests on a real glyph.
///
/// A caller that is about to lay out a screen should be able to ask "was any of
/// this invented" without re-walking the string. This is that question, answered
/// in the same pass as the measurement so the two can never disagree.
pub fn measure_with_coverage(
    text: &str,
    style: &TextStyle,
    font: &FontFace,
) -> Result<(TextMetrics, Coverage), TextError> {
    style.validate()?;
    let mut m = TextMetrics::vertical(font, style.text_size_px);
    let mut total = 0.0f32;
    let mut raw = 0.0f32;
    let mut cov = Coverage::default();
    for u in units(text) {
        if u.continuation {
            cov.continuations += 1;
            continue;
        }
        let (em, src) = advance_em(font, u.leader);
        let a = (em * style.text_size_px
            + style.letter_spacing_em * style.text_size_px)
            * style.text_scale_x;
        cov.record(src, u.leader);
        raw += a;
        total += quantise(a, style.rounding);
    }
    m.width = match style.rounding {
        Rounding::WholePixelTotal => raw.round(),
        _ => total,
    };
    m.min_ink = m.ascent;
    m.max_ink = m.descent;
    Ok((m, cov))
}

/// How much of a measurement came from real glyphs. Every field is a character
/// count, so they sum to the string's character count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub real_glyphs: usize,
    pub zero_width_marks: usize,
    pub declared_fallbacks: usize,
    pub uncovered: usize,
    /// Code points folded into the previous cluster: skin tones, joiner
    /// sequences, the second half of a flag.
    pub continuations: usize,
}

impl Coverage {
    fn record(&mut self, src: AdvanceSource, ch: char) {
        match src {
            AdvanceSource::RealGlyph => self.real_glyphs += 1,
            AdvanceSource::ZeroWidthMark => self.zero_width_marks += 1,
            AdvanceSource::DeclaredFallback => self.declared_fallbacks += 1,
            AdvanceSource::Uncovered => self.uncovered += 1,
        }
        let _ = ch;
    }
    /// Characters not measured from a real glyph outline.
    pub fn approximate(&self) -> usize {
        self.declared_fallbacks + self.uncovered
    }
    /// Characters no metric at all could be found for.
    pub fn is_complete(&self) -> bool {
        self.uncovered == 0
    }
}

/// One contiguous stretch of text with one direction, in logical order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Run {
    /// Byte range into the source string.
    pub start: usize,
    /// Byte range into the source string.
    pub end: usize,
    /// Resolved embedding level from the bidi algorithm. Even = LTR, odd = RTL.
    pub level: u8,
    /// Script-ish grouping key: characters sharing a level and a fallback face
    /// are measured together, because a fallback change is a metrics change.
    pub face: String,
    /// True when the run must be drawn right-to-left.
    pub rtl: bool,
    /// Width of the run's text in pixels.
    pub width: f32,
}

/// A resolved visual ordering: runs in visual (left-to-right on screen) order,
/// each pointing back at its logical byte range.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisualOrder {
    /// Paragraph embedding level: 0 = LTR, 1 = RTL.
    pub paragraph_level: u8,
    /// Run indices into the logical run list, in the order they appear left to
    /// right on screen.
    pub order: Vec<usize>,
}

impl VisualOrder {
    /// True when the paragraph is laid out right-to-left.
    pub fn is_rtl(&self) -> bool {
        self.paragraph_level % 2 == 1
    }
}

/// Measure text and resolve it into runs with a visual order.
///
/// `measure_runs` is not a convenience wrapper around `measure`: bidi
/// reordering does not change the *total* advance of a line, but it changes
/// which face measures which characters, and it changes the order a drawing
/// pass has to emit glyphs in. Getting it wrong silently reverses Arabic and
/// Hebrew UI, which is why the ordering is returned as data and not implied by
/// the caller.
pub fn measure_runs(
    text: &str,
    style: &TextStyle,
    registry: &FontRegistry,
) -> Result<(TextMetrics, Vec<Run>, VisualOrder), TextError> {
    style.validate()?;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    if chars.is_empty() {
        return Ok((TextMetrics::safe(), Vec::new(), VisualOrder {
            paragraph_level: 0,
            order: Vec::new(),
        }));
    }

    let paragraph_level = paragraph_level(&chars, style.direction);
    let resolution = resolve(&chars, paragraph_level);
    let order = resolution.order(&chars);
    let _ = &resolution.removed;

    // Group the *visual* sequence into runs. Measuring per run is what lets a
    // fallback face contribute different metrics to different parts of a line,
    // which is what Android does and what makes a mixed-script line add up.
    let mut runs: Vec<Run> = Vec::new();
    for &idx in &order {
        let (off, ch) = chars[idx];
        let level = resolution.levels[idx];
        let face = registry.face_for_char(ch as u32);
        let face_key = face
            .map(|f| f.provenance.family.clone())
            .unwrap_or_else(|| "\u{0}none".to_string());
        let same = matches!(
            runs.last(),
            Some(r) if r.level == level && r.face == face_key && r.end == off
        );
        match (same, face) {
            (true, Some(f)) => {
                let r = runs.last_mut().expect("checked above");
                r.width += glyph_advance(style, f, ch);
                r.end = off + ch.len_utf8();
            }
            (true, None) => {
                let r = runs.last_mut().expect("checked above");
                r.end = off + ch.len_utf8();
            }
            _ => {
                let width = face.map(|f| glyph_advance(style, f, ch)).unwrap_or(0.0);
                runs.push(Run {
                    start: off,
                    end: off + ch.len_utf8(),
                    level,
                    face: face_key,
                    rtl: level % 2 == 1,
                    width,
                });
            }
        }
    }

    let total: f32 = runs.iter().map(|r| r.width).sum();
    let base = registry
        .peek(&style.family, &style.style)
        .or_else(|| registry.face_for_char(' ' as u32));
    let mut m = base
        .map(|f| TextMetrics::vertical(f, style.text_size_px))
        .unwrap_or_else(TextMetrics::safe);
    m.width = total;
    Ok((
        m,
        runs,
        VisualOrder {
            paragraph_level,
            order,
        },
    ))
}

/// Measure and record any family miss, resolving the face through the
/// registry. This is the entry point a runtime should use; [`measure`] is the
/// one underneath it.
pub fn measure_with_registry(
    text: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
) -> Result<TextMetrics, TextError> {
    style.validate()?;
    match registry.lookup(&style.family, &style.style) {
        crate::font::FontLookup::Found(f) => measure(text, style, &f),
        crate::font::FontLookup::Missing {
            family,
            style: sty,
            nearest,
        } => Err(TextError::NoFontAvailable {
            family: format!("{family}/{sty} (would have substituted {nearest})"),
        }),
    }
}

/// One glyph's advance under a style, in em, before the style's scaling.
///
/// Three cases, in the order they are tried:
///
/// 1. The face has the character: its real `hmtx` advance.
/// 2. The character is a zero-width mark: `0.0`. A combining mark has no
///    advance of its own, and giving it one inflates a Devanagari string by
///    most of its width.
/// 3. A declared synthetic fallback covers it: the block mean from
///    [`crate::font::DECLARED_FALLBACKS`], which is a *fabricated* figure and is
///    reported as one.
/// 4. Nothing covers it: `0.0`, and the character is counted in
///    [`FontFace::advance`]'s miss accounting so a caller can see it.
///
/// Case 4 used to be case 3's job, and it was wrong by a factor of four on
/// CJK. `.notdef` has an advance; it is the width of a missing-glyph box, and
/// using it is how a CJK string ends up measured at 27% of its real width.
pub fn advance_em(font: &FontFace, ch: char) -> (f32, AdvanceSource) {
    let cp = ch as u32;
    if font.covers(cp) {
        if let Some(a) = font.advance(cp) {
            return (
                a as f32 / font.units_per_em as f32,
                AdvanceSource::RealGlyph,
            );
        }
    }
    if crate::font::is_zero_width_mark(cp) {
        return (0.0, AdvanceSource::ZeroWidthMark);
    }
    if let Some((_, em)) = crate::font::declared_fallback_em(cp) {
        return (em as f32, AdvanceSource::DeclaredFallback);
    }
    (0.0, AdvanceSource::Uncovered)
}

/// Where a character's advance came from. Carried so a report can say how much
/// of a line was measured and how much was guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvanceSource {
    /// A real glyph in a real font file.
    RealGlyph,
    /// A combining mark, measured as zero because that is what it is.
    ZeroWidthMark,
    /// A declared block mean. Fabricated, with a measured residual.
    DeclaredFallback,
    /// Nothing covered it. The advance is 0 and this is a finding.
    Uncovered,
}

impl AdvanceSource {
    /// True when the number is not a real glyph's advance.
    pub fn is_approximate(&self) -> bool {
        !matches!(self, AdvanceSource::RealGlyph)
    }
}

/// One glyph's advance under a style: em * size, plus letter spacing, times
/// the horizontal scale.
pub fn glyph_advance(style: &TextStyle, font: &FontFace, ch: char) -> f32 {
    let (em, _) = advance_em(font, ch);
    let raw = em * style.text_size_px;
    let with_spacing = raw + style.letter_spacing_em * style.text_size_px;
    with_spacing * style.text_scale_x
}

/// Sum of per-glyph advances, quantised per the style's rounding model.
fn advance_of(text: &str, style: &TextStyle, font: &FontFace) -> f32 {
    let mut total = 0.0f32;
    let mut raw = 0.0f32;
    for u in units(text) {
        if u.continuation {
            continue;
        }
        let (em, _) = advance_em(font, u.leader);
        let a = (em * style.text_size_px + style.letter_spacing_em * style.text_size_px)
            * style.text_scale_x;
        raw += a;
        total += quantise(a, style.rounding);
    }
    match style.rounding {
        Rounding::WholePixelTotal => raw.round(),
        _ => total,
    }
}

/// One advance-bearing piece of text: a grapheme cluster, for the small subset
/// of shaping this engine implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unit {
    /// Byte range of the whole cluster.
    pub start: usize,
    pub end: usize,
    /// The code point that carries the advance.
    pub leader: char,
    /// True when this code point is a continuation of the previous unit and
    /// contributes no advance of its own. A flag's second regional indicator,
    /// a skin-tone modifier, anything after a ZWJ.
    pub continuation: bool,
}

/// Split a string into advance-bearing units.
///
/// This is not a grapheme clusteriser. It implements the three joins that
/// change a *width* and skips the rest, because the rest do not:
///
/// * emoji ZWJ sequences — `"\u{1F468}\u{ZWJ}\u{1F469}"` is one glyph with
///   one advance, not three glyphs. Measured on the device: 1.243 em for the
///   whole family sequence.
/// * skin-tone modifiers and variation selectors — zero advance.
/// * regional indicator pairs — two code points, one flag glyph.
///
/// A full grapheme clusteriser is the right answer for *rendering*, where a
/// misplaced join is visible. For measurement a cluster is only interesting if
/// it changes the total, and these are the three that do.
pub fn units(text: &str) -> Vec<Unit> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out: Vec<Unit> = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let (start, leader) = chars[i];
        let mut end = start + leader.len_utf8();
        let mut j = i + 1;
        // Absorb extenders.
        while j < chars.len() {
            let c = chars[j].1;
            if crate::font::is_cluster_extender(c as u32) {
                end = chars[j].0 + c.len_utf8();
                j += 1;
                continue;
            }
            if c as u32 == crate::font::ZWJ {
                // A joiner glues the *next* pictograph into this cluster.
                let mut k = j + 1;
                if k < chars.len() {
                    let nc = chars[k].1;
                    if crate::font::is_cluster_extender(nc as u32) {
                        k += 1;
                    }
                    if k < chars.len() {
                        let nc = chars[k].1;
                        end = chars[k].0 + nc.len_utf8();
                        j = k + 1;
                        while j < chars.len()
                            && crate::font::is_cluster_extender(chars[j].1 as u32)
                        {
                            end = chars[j].0 + chars[j].1.len_utf8();
                            j += 1;
                        }
                        continue;
                    }
                }
            }
            break;
        }
        out.push(Unit {
            start,
            end,
            leader,
            continuation: false,
        });
        i = j.max(i + 1);
    }

    // Regional indicator pairs: a flag glyph is two code points carrying one
    // advance. Measured on the device, `"\u{1F1EC}\u{1F1E7}"` (the GB flag) is
    // 1.243 em, not 2.486, and a run of three is a flag plus a lone indicator.
    let mut prev_was_ri = false;
    for u in out.iter_mut() {
        if crate::font::is_regional_indicator(u.leader as u32) && prev_was_ri {
            u.continuation = true;
            prev_was_ri = false;
        } else {
            prev_was_ri = crate::font::is_regional_indicator(u.leader as u32);
        }
    }
    out
}

fn quantise(a: f32, r: Rounding) -> f32 {
    match r {
        Rounding::PerGlyphWholePixel => a.round(),
        Rounding::Subpixel | Rounding::WholePixelTotal => a,
    }
}

// ===========================================================================
// Bidi
// ===========================================================================
//
// A UAX#9 implementation: X1-X8 (explicit levels and overrides, including
// isolates), X9 (remove the explicit formatting characters), X10 (isolating
// run sequences), W1-W7 (weak), N0 (bracket pairs, BD16), N1-N2 (neutrals),
// I1-I2 (implicit), L1 (reset at line ends) and L2 (reorder).
//
// Why the full algorithm and not a "first strong character decides" heuristic:
// the heuristic gets plain Arabic and plain Hebrew right and everything else
// wrong, and the something-else is exactly the case that appears in a real app
// — an English label with a bracketed Arabic product name, a phone number
// inside RTL text, a price with a currency symbol. A wrong guess there reverses
// a word, which is the single most visible text bug there is.
//
// Conformance is measured, not asserted: `tests/bidi.rs` runs the Unicode
// `BidiTest.txt` (15.1.0) and reports the pass count with its denominator in
// the test name and in `README.md`.

/// An embedding level. Even is LTR, odd is RTL.
pub type BidiLevel = u8;

const MAX_DEPTH: usize = 125;

#[derive(Debug, Clone, Copy)]
struct Entry {
    level: BidiLevel,
    override_: Option<BidiClass>,
    isolate: bool,
}

/// P2/P3: the level of the first strong character, or the direction the caller
/// asked for if there is none. Public because a caller choosing a paragraph
/// alignment needs the same answer the engine will use.
pub fn paragraph_level_for(chars: &[(usize, char)], dir: ParagraphDirection) -> BidiLevel {
    paragraph_level(chars, dir)
}

fn paragraph_level(chars: &[(usize, char)], dir: ParagraphDirection) -> BidiLevel {
    match dir {
        ParagraphDirection::Ltr => return 0,
        ParagraphDirection::Rtl => return 1,
        ParagraphDirection::FirstStrongLtr | ParagraphDirection::FirstStrongRtl => {}
    }
    for (_, ch) in chars {
        match bidi_class(*ch as u32) {
            B::L => return 0,
            B::R | B::AL => return 1,
            _ => {}
        }
    }
    if dir == ParagraphDirection::FirstStrongRtl {
        1
    } else {
        0
    }
}

/// The result of running UAX#9 over one paragraph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BidiResolution {
    /// Embedding level per character. For a removed character this is the
    /// enclosing level, which is what X1-X8 assigned before X9 took it out.
    pub levels: Vec<BidiLevel>,
    /// Which characters X9 removed: the explicit formatting codes and `BN`.
    /// The UBA assigns them no level, and a drawing pass must not draw them.
    pub removed: Vec<bool>,
    /// The paragraph level P2/P3 chose.
    pub paragraph_level: BidiLevel,
}

impl BidiResolution {
    /// The visual order: logical character indices, left to right on screen.
    /// Characters X9 removed are not in it; a drawing pass has nothing to draw
    /// for them and a hit-test loop would be off by however many there are.
    pub fn order(&self, _chars: &[(usize, char)]) -> Vec<usize> {
        reorder(&self.levels, &self.removed, self.paragraph_level)
    }
}

/// Resolve every character's embedding level for a paragraph.
///
/// Public because the drawing path needs levels without needing widths, and
/// because `tests/bidi.rs` needs to test the algorithm without a font.
pub fn resolve_bidi(chars: &[(usize, char)], paragraph_level: BidiLevel) -> Vec<BidiLevel> {
    resolve(chars, paragraph_level).levels
}

/// As [`resolve_bidi`], keeping the X9 removal flags.
pub fn resolve(
    chars: &[(usize, char)],
    paragraph_level: BidiLevel,
) -> BidiResolution {
    let n = chars.len();
    let original: Vec<BidiClass> = chars.iter().map(|(_, c)| bidi_class(*c as u32)).collect();
    let mut types = original.clone();
    let mut levels = vec![paragraph_level; n];

    // ---- X1-X8: explicit embeddings, overrides and isolates ----
    //
    // One pass over the paragraph, recording three things per character: the
    // embedding level it sits at (X1-X8), whether it is removed for the rest
    // of the algorithm (X9), and the directional override in force at that
    // point (X6). An earlier version of this file walked the status stack
    // twice, once for levels and once for overrides; the two copies of a
    // state machine that has to agree character for character is exactly the
    // kind of thing that is right in testing and wrong in an app, so it is one
    // walk now.
    let mut stack: Vec<Entry> = vec![Entry {
        level: paragraph_level,
        override_: None,
        isolate: false,
    }];
    let mut overflow_isolate = 0usize;
    let mut overflow_embedding = 0usize;
    let mut valid_isolate = 0usize;
    let mut removed = vec![false; n];
    let mut override_in_force: Vec<Option<BidiClass>> = vec![None; n];

    for i in 0..n {
        let t = original[i];
        let top_level = stack.last().map(|e| e.level).unwrap_or(paragraph_level);
        let rtl = match t {
            B::RLE | B::RLO | B::RLI => true,
            B::LRE | B::LRO | B::LRI => false,
            B::FSI => matches!(fsi_direction(&original, i), B::R | B::AL),
            _ => false,
        };
        let new_level = if rtl {
            next_odd(top_level)
        } else {
            next_even(top_level)
        };
        let pushable = new_level <= MAX_DEPTH as BidiLevel
            && overflow_isolate == 0
            && overflow_embedding == 0;

        match t {
            B::RLE | B::LRE | B::RLO | B::LRO => {
                removed[i] = true;
                levels[i] = top_level;
                if pushable {
                    stack.push(Entry {
                        level: new_level,
                        override_: match t {
                            B::RLO => Some(B::R),
                            B::LRO => Some(B::L),
                            _ => None,
                        },
                        isolate: false,
                    });
                } else if overflow_isolate == 0 {
                    overflow_embedding += 1;
                }
            }
            B::RLI | B::LRI | B::FSI => {
                // X5c: an FSI takes its direction from the first strong
                // character inside its scope.
                if t == B::FSI {
                    types[i] = if rtl { B::RLI } else { B::LRI };
                }
                levels[i] = top_level;
                if pushable {
                    valid_isolate += 1;
                    stack.push(Entry {
                        level: new_level,
                        override_: None,
                        isolate: true,
                    });
                } else {
                    overflow_isolate += 1;
                }
            }
            B::PDI => {
                if overflow_isolate > 0 {
                    overflow_isolate -= 1;
                } else if valid_isolate > 0 {
                    overflow_embedding = 0;
                    while stack.len() > 1 && !stack.last().map(|e| e.isolate).unwrap_or(false) {
                        stack.pop();
                    }
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    valid_isolate -= 1;
                }
                levels[i] = stack.last().map(|e| e.level).unwrap_or(paragraph_level);
            }
            B::PDF => {
                removed[i] = true;
                levels[i] = top_level;
                if overflow_isolate == 0 {
                    if overflow_embedding > 0 {
                        overflow_embedding -= 1;
                    } else if stack.len() > 1 && !stack.last().map(|e| e.isolate).unwrap_or(false) {
                        stack.pop();
                    }
                }
            }
            B::B => {
                // X8: a paragraph separator resets the status stack.
                stack.truncate(1);
                overflow_isolate = 0;
                overflow_embedding = 0;
                valid_isolate = 0;
                levels[i] = paragraph_level;
            }
            B::BN => {
                removed[i] = true;
                levels[i] = top_level;
            }
            _ => {
                levels[i] = top_level;
            }
        }
        override_in_force[i] = stack.last().and_then(|e| e.override_);
    }

    // X6: apply the directional override in force at each surviving character.
    for i in 0..n {
        if let Some(o) = override_in_force[i] {
            if !removed[i] {
                types[i] = o;
            }
        }
    }

    // ---- X10: isolating run sequences ----
    let sequences = isolating_run_sequences(&types, &levels, &removed, paragraph_level);

    for seq in sequences {
        let sos = sos_of(&types, &seq, &levels, paragraph_level);
        resolve_weak(&mut types, &seq, sos);
        resolve_neutral(chars, &mut types, &seq, &levels, paragraph_level);
        resolve_implicit(&types, &seq, &mut levels);
    }

    // ---- L1: reset to the paragraph level at the end of the line ----
    //
    // L1 keys off the *original* types: after W and N have run, a space has
    // been rewritten to L or R, and using that here would reset nothing.
    reset_line_levels(&original, &removed, &mut levels, paragraph_level);

    BidiResolution {
        levels,
        removed,
        paragraph_level,
    }
}

fn next_odd(level: BidiLevel) -> BidiLevel {
    (level + 1) | 1
}

fn next_even(level: BidiLevel) -> BidiLevel {
    (level + 2) & !1
}

/// X5c: the direction an FSI takes from the first strong character between it
/// and its matching PDI.
fn fsi_direction(types: &[BidiClass], start: usize) -> BidiClass {
    let mut depth = 0usize;
    for t in types.iter().skip(start + 1) {
        match t {
            B::L => return B::L,
            B::R | B::AL => return B::R,
            B::RLI | B::LRI | B::FSI => depth += 1,
            B::PDI => {
                if depth == 0 {
                    // End of the scope with nothing strong in it. The scope
                    // inherits the paragraph direction; that is the same
                    // answer the reference implementation gives.
                    return B::L;
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    B::L
}


/// BD9: match every isolate initiator with its PDI, and every PDI with its
/// initiator. Index positions, `None` for "no match".
fn matching_pairs(types: &[BidiClass], removed: &[bool]) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
    let n = types.len();
    let mut initiator_to_pdi = vec![None; n];
    let mut pdi_to_initiator = vec![None; n];
    let mut stack: Vec<usize> = Vec::new();
    for i in 0..n {
        if removed[i] {
            continue;
        }
        match types[i] {
            B::RLI | B::LRI | B::FSI => stack.push(i),
            B::PDI => {
                if let Some(o) = stack.pop() {
                    initiator_to_pdi[o] = Some(i);
                    pdi_to_initiator[i] = Some(o);
                }
            }
            _ => {}
        }
    }
    (initiator_to_pdi, pdi_to_initiator)
}

/// X10: build the isolating run sequences. Each is a vector of indices, in
/// logical order, that resolve independently of every other sequence.
fn isolating_run_sequences(
    types: &[BidiClass],
    levels: &[BidiLevel],
    removed: &[bool],
    paragraph_level: BidiLevel,
) -> Vec<Vec<usize>> {
    let n = types.len();
    let (init_to_pdi, pdi_to_init) = matching_pairs(types, removed);

    // Level runs, ignoring removed characters.
    let mut level_runs: Vec<Vec<usize>> = Vec::new();
    let mut cur: Vec<usize> = Vec::new();
    let mut cur_level: Option<BidiLevel> = None;
    for i in 0..n {
        if removed[i] {
            continue;
        }
        if cur_level != Some(levels[i]) {
            if !cur.is_empty() {
                level_runs.push(std::mem::take(&mut cur));
            }
            cur_level = Some(levels[i]);
        }
        cur.push(i);
    }
    if !cur.is_empty() {
        level_runs.push(cur);
    }

    let mut used = vec![false; n];
    let mut sequences = Vec::new();
    for run in &level_runs {
        if used[run[0]] {
            continue;
        }
        let mut seq: Vec<usize> = Vec::new();
        let mut cursor = Some(run.clone());
        while let Some(r) = cursor {
            for &i in &r {
                if !used[i] {
                    used[i] = true;
                    seq.push(i);
                }
            }
            let last = *r.last().expect("level run is never empty");
            // The sequence ends if the run's last character is an isolate
            // initiator with no matching PDI, or a PDI with no matching
            // initiator within the sequence.
            let is_initiator = matches!(types[last], B::RLI | B::LRI | B::FSI);
            if is_initiator {
                match init_to_pdi[last] {
                    Some(p) if !used[p] => {
                        // Continue with the level run that starts at the PDI.
                        let p_level = levels[p];
                        let mut next: Vec<usize> = Vec::new();
                        let mut started = false;
                        let mut j = p;
                        while j < n {
                            if !removed[j] && levels[j] == p_level {
                                started = true;
                                next.push(j);
                            } else if started {
                                break;
                            }
                            j += 1;
                        }
                        cursor = if next.is_empty() { None } else { Some(next) };
                    }
                    _ => cursor = None,
                }
            } else if types[last] == B::PDI {
                match pdi_to_init[last] {
                    Some(o) if seq.contains(&o) => {
                        // The initiator is in this sequence, so the sequence
                        // ends here.
                        cursor = None;
                    }
                    Some(o) if !used[o] => {
                        let o_level = levels[o];
                        let mut next: Vec<usize> = Vec::new();
                        let mut started = false;
                        let mut j = o;
                        while j < n {
                            if !removed[j] && levels[j] == o_level {
                                started = true;
                                next.push(j);
                            } else if started {
                                break;
                            }
                            j += 1;
                        }
                        cursor = if next.is_empty() { None } else { Some(next) };
                    }
                    _ => cursor = None,
                }
            } else {
                cursor = None;
            }
        }
        let _ = paragraph_level;
        if !seq.is_empty() {
            sequences.push(seq);
        }
    }
    sequences
}

/// The start-of-sequence type for a run: its level's direction, unless the
/// sequence is preceded in the paragraph by a character that survives into it,
/// in which case that character's *original* type is the sos (UAX#9 X10).
fn sos_of(
    types: &[BidiClass],
    seq: &[usize],
    levels: &[BidiLevel],
    paragraph_level: BidiLevel,
) -> BidiClass {
    let Some(&first) = seq.first() else {
        return if paragraph_level % 2 == 0 { B::L } else { B::R };
    };
    if first == 0 {
        return if paragraph_level % 2 == 0 { B::L } else { B::R };
    }
    let seq_level = levels[first];
    // Walk back to the start of the level run that contains `first`.
    let mut j = first;
    while j > 0 && levels[j - 1] == seq_level {
        j -= 1;
    }
    if j == 0 {
        if paragraph_level % 2 == 0 {
            B::L
        } else {
            B::R
        }
    } else {
        types[j - 1]
    }
}

/// W1-W7 on one isolating run sequence, in place.
fn resolve_weak(types: &mut [BidiClass], seq: &[usize], sos: BidiClass) {
    // W1: NSM takes the type of the previous character.
    let mut prev = sos;
    for &i in seq {
        if types[i] == B::NSM {
            types[i] = prev;
        }
        // Isolates are treated as ON for W rules.
        prev = match types[i] {
            B::RLI | B::LRI | B::FSI | B::PDI => B::ON,
            t => t,
        };
    }
    // W2: EN becomes AN when the last strong type is AL.
    let mut last_strong = sos;
    for &i in seq {
        match types[i] {
            B::L | B::R | B::AL => last_strong = types[i],
            _ => {}
        }
        if types[i] == B::EN && last_strong == B::AL {
            types[i] = B::AN;
        }
    }
    // W3: AL becomes R.
    for &i in seq {
        if types[i] == B::AL {
            types[i] = B::R;
        }
    }
    // W4: a single ES between two ENs, or a single CS between two numbers of
    // the same type, becomes that type.
    let n = seq.len();
    for k in 0..n {
        let i = seq[k];
        if types[i] != B::ES && types[i] != B::CS {
            continue;
        }
        let before = if k == 0 { sos } else { types[seq[k - 1]] };
        let after = if k + 1 == n { sos } else { types[seq[k + 1]] };
        if before == B::EN && after == B::EN {
            types[i] = B::EN;
        } else if types[i] == B::CS && before == B::AN && after == B::AN {
            types[i] = B::AN;
        }
    }
    // W5: a sequence of ETs adjacent to an EN becomes EN.
    let mut k = 0;
    while k < n {
        if types[seq[k]] == B::ET {
            let start = k;
            while k < n && types[seq[k]] == B::ET {
                k += 1;
            }
            let before = if start == 0 { sos } else { types[seq[start - 1]] };
            let after = if k == n { sos } else { types[seq[k]] };
            if before == B::EN || after == B::EN {
                for j in start..k {
                    types[seq[j]] = B::EN;
                }
            }
        } else {
            k += 1;
        }
    }
    // W6: remaining separators and terminators become ON.
    for &i in seq {
        if matches!(types[i], B::ET | B::ES | B::CS) {
            types[i] = B::ON;
        }
    }
    // W7: EN becomes L when the last strong type is L.
    let mut last_strong = sos;
    for &i in seq {
        match types[i] {
            B::L | B::R => last_strong = types[i],
            _ => {}
        }
        if types[i] == B::EN && last_strong == B::L {
            types[i] = B::L;
        }
    }
}

/// N0-N2 on one isolating run sequence.
fn resolve_neutral(
    chars: &[(usize, char)],
    types: &mut [BidiClass],
    seq: &[usize],
    levels: &[BidiLevel],
    paragraph_level: BidiLevel,
) {
    let n = seq.len();
    if n == 0 {
        return;
    }
    let e = levels[seq[0]] % 2 == 0;
    let sos: BidiClass = if e { B::L } else { B::R };
    let dir = if e { B::L } else { B::R };
    let other = if e { B::R } else { B::L };
    let embedding = if e { B::L } else { B::R };

    // N0: bracket pairs. BD16 finds pairs inside the sequence; a pair with an
    // enclosed strong type matching the embedding direction is set to that
    // direction, otherwise the whole pair becomes the embedding direction.
    if e {
        let pairs = bracket_pairs(chars, seq, types);
        for (open, close) in pairs {
            let mut found_e = false;
            let mut found_o = false;
            for k in open + 1..close {
                match types[seq[k]] {
                    B::EN | B::AN | B::R => found_e = true,
                    B::L => found_o = true,
                    _ => {}
                }
                if found_e && found_o {
                    break;
                }
            }
            let set = if found_e {
                B::R
            } else if found_o {
                B::L
            } else {
                dir
            };
            types[seq[open]] = set;
            types[seq[close]] = set;
            // Anything still neutral or isolate between the brackets follows
            // BD16's "strong type" step.
            for k in open + 1..close {
                if matches!(types[seq[k]], B::ON | B::RLI | B::LRI | B::FSI | B::PDI) {
                    types[seq[k]] = set;
                }
            }
        }
    }

    // N1/N2: neutrals take the surrounding direction when it agrees, else the
    // embedding direction.
    let is_neutral = |t: BidiClass| {
        matches!(
            t,
            B::B | B::S | B::WS | B::ON | B::RLI | B::LRI | B::FSI | B::PDI
        )
    };
    let strong_of = |t: BidiClass| -> BidiClass {
        match t {
            B::EN | B::AN | B::R => B::R,
            B::L => B::L,
            _ => sos,
        }
    };
    let mut k = 0;
    while k < n {
        if !is_neutral(types[seq[k]]) {
            k += 1;
            continue;
        }
        let start = k;
        while k < n && is_neutral(types[seq[k]]) {
            k += 1;
        }
        let before = if start == 0 { sos } else { strong_of(types[seq[start - 1]]) };
        let after = if k == n { sos } else { strong_of(types[seq[k]]) };
        let set = if before == after { before } else { embedding };
        let _ = other;
        for j in start..k {
            types[seq[j]] = set;
        }
    }
    let _ = paragraph_level;
}

/// BD16 for a single isolating run sequence, in sequence-local indices.
///
/// The stack holds open brackets. 63 is the Unicode limit and past it a
/// character is "not a bracket any more", so a hostile input cannot make this
/// grow without bound. A strong type (L, R, EN, AN), an isolate, or a segment
/// terminator clears the stack, which is what stops a bracket pair being
/// matched across a word boundary.
fn bracket_pairs(
    chars: &[(usize, char)],
    seq: &[usize],
    types: &[BidiClass],
) -> Vec<(usize, usize)> {
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (k, &i) in seq.iter().enumerate() {
        let cp = canonical_bracket(chars[i].1 as u32);
        if let Some(partner) = closing_of(cp) {
            let mut found = None;
            for &(pos, open_cp) in stack.iter().rev() {
                if open_cp == partner {
                    found = Some(pos);
                    break;
                }
            }
            match found {
                Some(pos) => {
                    out.push((pos, k));
                    stack.retain(|&(p, _)| p < pos);
                }
                // An unmatched closing bracket clears the stack entirely.
                None => stack.clear(),
            }
        } else if is_opening_bracket(cp) {
            if stack.len() < 63 {
                stack.push((k, cp));
            }
        } else if matches!(
            types[i],
            B::L | B::R | B::EN | B::AN | B::RLI | B::LRI | B::FSI | B::PDI | B::B | B::S
        ) {
            // A strong type, an isolate, or a segment terminator closes any
            // bracket still open.
            stack.clear();
        }
        // Whitespace and neutrals leave the stack alone: a bracket pair is
        // allowed to contain them.
    }
    out
}

/// U+2329 and U+232A share a canonical decomposition and are treated as one
/// bracket pair (BD16).
fn canonical_bracket(cp: u32) -> u32 {
    if cp == 0x232A {
        return 0x2329;
    }
    for &(alias, canon) in BRACKET_CANON {
        if alias == cp {
            return canon;
        }
    }
    cp
}

/// If `cp` is a closing bracket, the code point of the bracket it pairs with.
fn closing_of(cp: u32) -> Option<u32> {
    for &(open, close) in BRACKET_PAIRS {
        if close == cp {
            return Some(canonical_bracket(open));
        }
    }
    None
}

fn is_opening_bracket(cp: u32) -> bool {
    BRACKET_PAIRS
        .iter()
        .any(|&(open, _)| canonical_bracket(open) == cp)
}

/// I1-I2: implicit levels from the resolved types.
fn resolve_implicit(types: &[BidiClass], seq: &[usize], levels: &mut [BidiLevel]) {
    #[allow(clippy::needless_range_loop)]
    for &i in seq {
        let level = levels[i];
        if level % 2 == 0 {
            match types[i] {
                B::R => levels[i] = level + 1,
                B::AN | B::EN => levels[i] = level + 2,
                _ => {}
            }
        } else if matches!(types[i], B::L | B::AN | B::EN) {
            levels[i] = level + 1;
        }
    }
}

/// L1: on each line, reset the embedding level of segment separators,
/// paragraph separators and any sequence of whitespace or isolate formatting
/// characters that precedes them or is at the end of the line.
fn reset_line_levels(
    original: &[BidiClass],
    removed: &[bool],
    levels: &mut [BidiLevel],
    paragraph_level: BidiLevel,
) {
    // L1 is defined over the line *after* X9 has removed the formatting
    // characters, and it matters. `"LRE WS RLE"` looks like a space in the
    // middle of an explicit embedding, but once the LRE and RLE are gone the
    // space is the last thing on the line, so L1 resets it to the paragraph
    // level. Walking the unfiltered sequence instead — which is what this did
    // first — leaves it at the embedding level and the Unicode test data
    // disagrees on 3% of its cases for exactly this reason.
    let live: Vec<usize> = (0..original.len()).filter(|i| !removed[*i]).collect();
    let mut trailing = true;
    for k in (0..live.len()).rev() {
        let i = live[k];
        match original[i] {
            B::B | B::S => {
                levels[i] = paragraph_level;
                trailing = true;
            }
            B::WS | B::RLI | B::LRI | B::FSI | B::PDI if trailing => {
                levels[i] = paragraph_level;
            }
            _ => trailing = false,
        }
    }
}

/// L2: from the highest level down to the lowest odd level, reverse any
/// contiguous sequence of characters at or above that level.
///
/// Returns the visual order: indices into the logical character vector, in
/// left-to-right screen order.
fn reorder(
    levels: &[BidiLevel],
    removed: &[bool],
    paragraph_level: BidiLevel,
) -> Vec<usize> {
    let mut order: Vec<usize> = (0..levels.len()).filter(|i| !removed[*i]).collect();
    let n = order.len();
    if n == 0 {
        return order;
    }
    let highest = levels.iter().copied().max().unwrap_or(paragraph_level);
    let lowest_odd = levels
        .iter()
        .copied()
        .filter(|l| l % 2 == 1)
        .min()
        .unwrap_or(highest + 1);
    let mut level = highest;
    while level >= lowest_odd && level > 0 {
        let mut i = 0;
        while i < n {
            if levels[order[i]] >= level {
                let start = i;
                while i < n && levels[order[i]] >= level {
                    i += 1;
                }
                order[start..i].reverse();
            } else {
                i += 1;
            }
        }
        if level == 0 {
            break;
        }
        level -= 1;
    }
    order
}

/// A per-script label for a string, used to group the calibration report.
///
/// This is a coarse grouping for reporting, not a script engine: it answers
/// "which rows of the error table is this string in", and the strings in the
/// corpus are curated per script, so the grouping can be as simple as "is the
/// first strong character RTL".
pub fn script_hint(text: &str) -> &'static str {
    for ch in text.chars() {
        match bidi_class(ch as u32) {
            B::R | B::AL => return "rtl",
            B::L => return "ltr",
            _ => {}
        }
    }
    "neutral"
}

/// Group a corpus by script for the error report. Returns a map from script to
/// the number of rows.
pub fn script_histogram(rows: &[&str]) -> BTreeMap<&'static str, usize> {
    let mut m: BTreeMap<&'static str, usize> = BTreeMap::new();
    for r in rows {
        *m.entry(script_hint(r)).or_insert(0) += 1;
    }
    m
}
