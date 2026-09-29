//! Line breaking, ellipsising and paragraph layout.
//!
//! # Why `ellipsize` is in here and not "later"
//!
//! `TextUtils.ellipsize` is in essentially every list row, every breadcrumb and
//! every toolbar title in a real app, and its behaviour is observable: the
//! user sees a different number of characters. It is also a measurement
//! function — it decides how much of a string fits in a width that came from
//! [`crate::shaper::measure`] — so it belongs next to measurement rather than
//! in a widget layer. The three `TruncateAt` variants are genuinely different
//! algorithms, not one algorithm with a flag, and `START` is the one that is
//! rare enough to be wrong.
//!
//! # What Android's `ellipsize` actually does
//!
//! Measured on the Android 13 emulator, `TextUtils.ellipsize` with
//! `TruncateAt.END` keeps a prefix and appends U+2026, and it does **not**
//! require the result to fit: the returned string measures wider than the
//! available width for some inputs. That is not a bug in our reading, it is
//! what the framework does, and a substitute that "helpfully" fits would differ
//! from the device in the one place a user can see. `tests/ellipsize.rs`
//! asserts against the device's own output for a corpus of cases.
//!
//! # Line breaking
//!
//! UAX#14-lite: break at spaces and after hyphens, with the trailing space of
//! a broken line kept on that line (as `StaticLayout` does with
//! `includePad`). CJK has no spaces, so it breaks between ideographs. Long
//! unbreakable runs are broken at the character level, which is what
//! `StaticLayout` does and what a WebView does.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::font::FontRegistry;
use crate::shaper::{measure_with_registry, TextMetrics, TextStyle};
use crate::TextError;

/// The ellipsis character Android uses. U+2026, not three dots.
pub const ELLIPSIS: char = '\u{2026}';

/// [`ELLIPSIS`] as a string, which is what gets appended.
pub const ELLIPSIS_STR: &str = "\u{2026}";

/// Which end a `TruncateAt` cuts from. Mirrors `TextUtils.TruncateAt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TruncateAt {
    /// `TruncateAt.START`: cut from the front, keep the tail. What a
    /// file-path or a chat-message preview does.
    Start,
    /// `TruncateAt.MIDDLE`: keep both ends. What a file name with an extension
    /// does.
    Middle,
    /// `TruncateAt.END`: cut from the end, keep the head. The default, and what
    /// a `TextView` with `singleLine` does.
    End,
}

impl TruncateAt {
    /// The Android enum name, for logs and recordings.
    pub fn as_android(&self) -> &'static str {
        match self {
            TruncateAt::Start => "START",
            TruncateAt::Middle => "MIDDLE",
            TruncateAt::End => "END",
        }
    }
}

/// Paragraph alignment. `StaticLayout.Alignment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LayoutAlign {
    /// `ALIGN_NORMAL`: to the left in an LTR paragraph, to the right in RTL.
    Normal,
    /// `ALIGN_CENTER`.
    Center,
    /// `ALIGN_OPPOSITE`: the mirror of `Normal`.
    Opposite,
}

/// Where a break is allowed. A subset of UAX#14, sized for what Android's
/// `StaticLayout` actually implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BreakOpportunity {
    /// Break here, and the preceding space stays on the broken line.
    AfterSpace,
    /// Break here with no space carried over.
    AfterHyphen,
    /// Between two ideographs. Carries nothing.
    BetweenIdeographs,
    /// A hard break. Always taken.
    Mandatory,
}

impl fmt::Display for BreakOpportunity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            BreakOpportunity::AfterSpace => "SP",
            BreakOpportunity::AfterHyphen => "HY",
            BreakOpportunity::BetweenIdeographs => "ID",
            BreakOpportunity::Mandatory => "BK",
        };
        f.write_str(s)
    }
}

/// One laid-out line.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Line {
    /// Byte range of this line's text, including any trailing space that the
    /// line carries.
    pub start: usize,
    pub end: usize,
    /// Measured width of the line's text.
    pub width: f32,
    /// `x` offset from the paragraph's left edge.
    pub left: f32,
    /// `y` offset of the line's **top** from the paragraph's top.
    pub top: f32,
    /// Line height used for this line.
    pub height: f32,
    /// True when the paragraph runs right-to-left.
    pub rtl: bool,
}

impl Line {
    /// `y` offset of the line's baseline from the paragraph's top.
    pub fn baseline(&self) -> f32 {
        self.top + self.height
    }
    /// The line's text. `None` when the range is not on character boundaries.
    pub fn text<'a>(&self, source: &'a str) -> Option<&'a str> {
        source.get(self.start..self.end)
    }
}

/// A laid-out paragraph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Paragraph {
    pub lines: Vec<Line>,
    /// Total width of the block: the widest line, not the constraint. A
    /// `WRAP_CONTENT` measurement is this number.
    pub width: f32,
    /// Total height: the sum of line heights plus any leading between lines.
    pub height: f32,
    /// `true` when the text was cut to fit the height constraint.
    pub truncated: bool,
    pub rtl: bool,
}

impl Paragraph {
    /// Number of lines. `StaticLayout.getLineCount`.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

/// Options for a paragraph layout, mirroring `StaticLayout`'s builder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutParams {
    /// Wrap width in pixels. `StaticLayout`'s `width` argument.
    pub width_px: f32,
    /// Maximum lines. `0` means unlimited.
    pub max_lines: usize,
    /// `StaticLayout.setLineSpacing(add, mult)`.
    pub line_spacing_add_px: f32,
    pub line_spacing_mult: f32,
    /// `StaticLayout.setIncludePad`.
    pub include_pad: bool,
    pub align: LayoutAlign,
    /// Drop the trailing ellipsis on the last line when it is ellipsised.
    pub ellipsize: Option<TruncateAt>,
}

impl Default for LayoutParams {
    fn default() -> Self {
        LayoutParams {
            width_px: 0.0,
            max_lines: 0,
            line_spacing_add_px: 0.0,
            line_spacing_mult: 1.0,
            include_pad: true,
            align: LayoutAlign::Normal,
            ellipsize: None,
        }
    }
}

// ===========================================================================
// Break opportunities
// ===========================================================================

/// Code points that end a word and permit a break, with nothing carried over.
const HYPHENS: &[char] = &['-', '\u{2010}', '\u{2013}', '/', '\u{2014}'];

fn is_ideograph(c: char) -> bool {
    let cp = c as u32;
    matches!(cp,
        0x1100..=0x11FF        // Hangul Jamo
        | 0x2E80..=0x303E      // CJK radicals, Kangxi, CJK symbols
        | 0x3041..=0x33FF      // kana, CJK compatibility
        | 0x3400..=0x4DBF      // CJK ext A
        | 0x4E00..=0x9FFF      // CJK unified
        | 0xA000..=0xA4CF      // Yi
        | 0xAC00..=0xD7A3      // Hangul syllables
        | 0xF900..=0xFAFF      // CJK compatibility ideographs
        | 0xFF00..=0xFF60      // fullwidth forms
        | 0x20000..=0x2FA1F)   // CJK ext B..
}

/// Every position in `text` where a line may break.
///
/// Returns byte offsets. Offset 0 is never a break; the end of the string is
/// always one.
pub fn break_opportunities(text: &str) -> Vec<(usize, BreakOpportunity)> {
    let mut out = Vec::new();
    let bytes: Vec<(usize, char)> = text.char_indices().collect();
    for w in 0..bytes.len() {
        let (off, ch) = bytes[w];
        let next = bytes.get(w + 1).map(|&(_, c)| c);
        if ch == '\n' {
            out.push((off + ch.len_utf8(), BreakOpportunity::Mandatory));
            continue;
        }
        match ch {
            // A run of spaces all offer the same break; collapsing them here
            // keeps the line breaker from choosing a break in the middle of a
            // space run, which is visible as a leading space.
            ' ' | '\t' if next.is_some_and(|c| c != ' ' && c != '\t') => {
                out.push((off + ch.len_utf8(), BreakOpportunity::AfterSpace));
            }
            c if HYPHENS.contains(&c) && next.is_some() => {
                out.push((off + c.len_utf8(), BreakOpportunity::AfterHyphen));
            }
            c if is_ideograph(c) => {
                if let Some(n) = next {
                    if is_ideograph(n) {
                        out.push((off + c.len_utf8(), BreakOpportunity::BetweenIdeographs));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

// ===========================================================================
// ellipsize
// ===========================================================================

/// What `TextUtils.ellipsize` returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ellipsized {
    /// The resulting string.
    pub text: String,
    /// Its measured width. May exceed the available width: Android's does, and
    /// so does ours. See the module docs.
    pub width: f32,
    /// `true` when anything was actually removed. A string that fits is
    /// returned unchanged with this `false`.
    pub truncated: bool,
}

/// `TextUtils.ellipsize`.
///
/// `available` is in pixels. `ellipsis` is the string Android would append,
/// which is U+2026 by default and which an app can replace.
pub fn ellipsize(
    text: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
    available: f32,
    at: TruncateAt,
) -> Result<Ellipsized, TextError> {
    ellipsize_with(text, style, registry, available, at, ELLIPSIS_STR)
}

/// As [`ellipsize`], with an explicit ellipsis string.
pub fn ellipsize_with(
    text: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
    available: f32,
    at: TruncateAt,
    ellipsis: &str,
) -> Result<Ellipsized, TextError> {
    if available < 0.0 {
        return Err(TextError::InvalidStyle(format!(
            "available width must be >= 0, got {available}"
        )));
    }
    if text.is_empty() {
        return Ok(Ellipsized {
            text: String::new(),
            width: 0.0,
            truncated: false,
        });
    }

    let full = measure_with_registry(text, style, registry)?.width;
    if full <= available {
        return Ok(Ellipsized {
            text: text.to_string(),
            width: full,
            truncated: false,
        });
    }

    // The width budget left for real characters once the ellipsis is in.
    let budget = available - measure_with_registry(ellipsis, style, registry)?.width;
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    // Prefix sums, so a candidate substring's width is O(1) to look up once
    // each character's width is known.
    let widths: Vec<f32> = chars
        .iter()
        .map(|&(_, c)| measure_with_registry(&c.to_string(), style, registry).map(|m| m.width))
        .collect::<Result<Vec<f32>, TextError>>()?;

    // Every branch below is reachable with a budget smaller than a single
    // character, including a *negative* budget when the available width is less
    // than the ellipsis itself. None of them may index backwards past zero:
    // `TextUtils.ellipsize` is called on whatever the app put in the row, and
    // an app can put a 200-character string in a 3-pixel column.
    match at {
        TruncateAt::End => {
            let mut acc = 0.0f32;
            let mut keep = 0usize;
            for (i, &adv) in widths.iter().enumerate() {
                if acc + adv > budget {
                    break;
                }
                acc += adv;
                keep = i + 1;
            }
            let out = match keep {
                0 => ellipsis.to_string(),
                k => {
                    let last = chars[k - 1];
                    format!("{}{}", &text[..last.0 + last.1.len_utf8()], ellipsis)
                }
            };
            let width = measure_with_registry(&out, style, registry)?.width;
            Ok(Ellipsized {
                width,
                text: out,
                truncated: true,
            })
        }
        TruncateAt::Start => {
            // Keep the tail. The cut lands on a character boundary, and no
            // attempt is made to trim a partial word: a user sees whole
            // characters or nothing.
            let mut acc = 0.0f32;
            let mut start = chars.len();
            for i in (0..chars.len()).rev() {
                if acc + widths[i] > budget {
                    break;
                }
                acc += widths[i];
                start = i;
            }
            let out = if start >= chars.len() {
                ellipsis.to_string()
            } else {
                format!("{}{}", ellipsis, &text[chars[start].0..])
            };
            let width = measure_with_registry(&out, style, registry)?.width;
            Ok(Ellipsized {
                width,
                text: out,
                truncated: true,
            })
        }
        TruncateAt::Middle => {
            // Split the budget: half for the head, and the head's *unused*
            // remainder plus half for the tail. Splitting the tail against a
            // second independent half would systematically drop a character
            // every time the head landed just under.
            let half = (budget / 2.0).max(0.0);
            let mut acc = 0.0f32;
            let mut head = 0usize;
            for (i, &adv) in widths.iter().enumerate() {
                if acc + adv > half {
                    break;
                }
                acc += adv;
                head = i + 1;
            }
            let mut acc2 = 0.0f32;
            let mut tail = chars.len();
            for i in (0..chars.len()).rev() {
                if acc2 + widths[i] > (budget - acc).max(0.0) {
                    break;
                }
                acc2 += widths[i];
                tail = i;
            }
            if head == 0 {
                // Not even one character fits in half the budget. Keep the
                // tail, which is the useful half of a file name.
                let out = if tail >= chars.len() {
                    ellipsis.to_string()
                } else {
                    format!("{}{}", ellipsis, &text[chars[tail].0..])
                };
                let width = measure_with_registry(&out, style, registry)?.width;
                return Ok(Ellipsized {
                    width,
                    text: out,
                    truncated: true,
                });
            }
            if head > tail {
                // The head and the tail would overlap: there is no middle to
                // keep, so keep the head alone and elide.
                let last = chars[head - 1];
                let out = format!("{}{}", &text[..last.0 + last.1.len_utf8()], ellipsis);
                let width = measure_with_registry(&out, style, registry)?.width;
                return Ok(Ellipsized {
                    width,
                    text: out,
                    truncated: true,
                });
            }
            let last = chars[head - 1];
            let out = format!(
                "{}{}{}",
                &text[..last.0 + last.1.len_utf8()],
                ellipsis,
                &text[chars[tail].0..]
            );
            let width = measure_with_registry(&out, style, registry)?.width;
            Ok(Ellipsized {
                width,
                text: out,
                truncated: true,
            })
        }
    }
}

// ===========================================================================
// Paragraph layout
// ===========================================================================

/// Lay out a paragraph the way `StaticLayout` does.
///
/// The `registry` is taken mutably so that a family miss during layout is
/// recorded in the same log as a family miss during measurement; a layout that
/// silently substituted a font would otherwise be invisible.
pub fn layout(
    text: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
    params: &LayoutParams,
) -> Result<Paragraph, TextError> {
    if !(params.width_px.is_finite() && params.width_px >= 0.0) {
        return Err(TextError::InvalidStyle(format!(
            "layout width must be finite and >= 0, got {}",
            params.width_px
        )));
    }
    let base = measure_with_registry("", style, registry)?;
    let line_height = base.line_height;
    let rtl = base_line_is_rtl(text, style);

    if text.is_empty() {
        return Ok(Paragraph {
            lines: Vec::new(),
            width: 0.0,
            height: if params.include_pad { line_height } else { 0.0 },
            truncated: false,
            rtl,
        });
    }

    // 1. Split at mandatory breaks (newlines) first, then wrap each piece.
    let mut lines: Vec<Line> = Vec::new();
    let mut y = 0.0f32;
    let mut truncated = false;
    let mut block_width = 0.0f32;

    'outer: for (piece, piece_start, piece_end) in split_mandatory(text) {
        let wrapped = wrap_piece(piece, style, registry, params.width_px, params.include_pad)?;
        let n = wrapped.len();
        for (i, (rel_start, rel_end, w)) in wrapped.into_iter().enumerate() {
            if params.max_lines != 0 && lines.len() >= params.max_lines {
                truncated = true;
                break 'outer;
            }
            let start = piece_start + rel_start;
            let end = piece_start + rel_end;
            let is_last = i + 1 == n && piece_end >= text.len();
            let content = &text[start..end];

            // The final line of the final piece is the only one Android
            // ellipsises: an ellipsised line is a display decision about the
            // whole paragraph, not about every row of it.
            let (display, width) = match (is_last, params.ellipsize) {
                (true, Some(at)) => {
                    let e = ellipsize(content, style, registry, params.width_px, at)?;
                    let w = measure_with_registry(&e.text, style, registry)?.width;
                    (e.text, w)
                }
                _ => (content.to_string(), w),
            };
            let _ = &display;

            let extra = if is_last && params.ellipsize.is_some() {
                0.0
            } else {
                params.line_spacing_add_px
            };
            let h = (line_height + extra) * params.line_spacing_mult;
            let left = align_offset(params.align, params.width_px, width, rtl);
            lines.push(Line {
                start,
                end,
                width,
                left,
                top: y,
                height: h,
                rtl,
            });
            y += h;
            block_width = block_width.max(width);
        }
    }

    if !params.include_pad && lines.len() == 1 {
        y = line_height;
    }

    Ok(Paragraph {
        lines,
        width: block_width,
        height: y,
        truncated,
        rtl,
    })
}

/// Split at `\n`, reporting each piece's byte range in the original string.
fn split_mandatory(text: &str) -> Vec<(&str, usize, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, c) in text.char_indices() {
        if c == '\n' {
            out.push((&text[start..i], start, i + 1));
            start = i + 1;
        }
    }
    out.push((&text[start..], start, text.len()));
    out
}

/// Greedy line breaking, the algorithm `StaticLayout` uses.
///
/// Scans character by character, remembering the most recent break opportunity
/// that still fit. When a character overflows, the line is cut at that
/// opportunity; if there has been no opportunity since the line started, the
/// line is cut at the overflowing character itself, which is what happens to an
/// unbreakable 40-character token in a narrow `TextView`.
///
/// The cost is one width measurement per character, which is not fast and is
/// fine: this is the fallback path for a browser that is already drawing a
/// canvas, and being obviously correct beats being fast here.
fn wrap_piece(
    piece: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
    width: f32,
    include_pad: bool,
) -> Result<Vec<(usize, usize, f32)>, TextError> {
    if piece.is_empty() {
        return Ok(Vec::new());
    }
    if !(width.is_finite() && width > 0.0) {
        // No room to wrap: one line, no breaking.
        let w = measure_with_registry(piece, style, registry)?.width;
        return Ok(vec![(0, piece.len(), w)]);
    }

    let mut opportunities: Vec<usize> = break_opportunities(piece)
        .into_iter()
        .map(|(off, _)| off)
        .collect();
    opportunities.sort_unstable();
    opportunities.dedup();

    let mut out: Vec<(usize, usize, f32)> = Vec::new();
    let mut line_start = 0usize;
    let mut acc = 0.0f32;
    let mut last_opp: Option<usize> = None;
    let mut opp_i = 0usize;
    let mut char_w: Vec<(usize, f32)> = Vec::with_capacity(piece.len());

    for (off, ch) in piece.char_indices() {
        let end = off + ch.len_utf8();
        let w = measure_with_registry(&piece[off..end], style, registry)?.width;
        char_w.push((off, w));

        if acc + w > width && off > line_start {
            let brk = last_opp.unwrap_or(off);
            let seg = &piece[line_start..brk];
            let seg_w = if include_pad {
                measure_with_registry(seg, style, registry)?.width
            } else {
                measure_with_registry(seg.trim_end_matches([' ', '\t']), style, registry)?.width
            };
            out.push((line_start, brk, seg_w));
            line_start = brk;
            // Everything from the new line start up to `end` counts against the
            // new line.
            acc = char_w
                .iter()
                .filter(|(o, _)| *o >= line_start && *o < end)
                .map(|(_, w)| *w)
                .sum();
            last_opp = None;
            while opp_i < opportunities.len() && opportunities[opp_i] <= line_start {
                opp_i += 1;
            }
        }
        acc += w;
        while opp_i < opportunities.len() && opportunities[opp_i] <= end {
            last_opp = Some(end);
            opp_i += 1;
        }
    }

    if line_start < piece.len() {
        let seg = &piece[line_start..];
        let seg_w = if include_pad {
            measure_with_registry(seg, style, registry)?.width
        } else {
            measure_with_registry(seg.trim_end_matches([' ', '\t']), style, registry)?.width
        };
        out.push((line_start, piece.len(), seg_w));
    }
    Ok(out)
}

fn align_offset(align: LayoutAlign, container: f32, line: f32, rtl: bool) -> f32 {
    match align {
        LayoutAlign::Center => (container - line) / 2.0,
        LayoutAlign::Normal => {
            if rtl {
                (container - line).max(0.0)
            } else {
                0.0
            }
        }
        LayoutAlign::Opposite => {
            if rtl {
                0.0
            } else {
                (container - line).max(0.0)
            }
        }
    }
}

fn base_line_is_rtl(text: &str, style: &TextStyle) -> bool {
    match style.direction {
        crate::shaper::ParagraphDirection::Rtl => true,
        crate::shaper::ParagraphDirection::Ltr => false,
        _ => {
            let chars: Vec<(usize, char)> = text.char_indices().collect();
            let mut found = None;
            for (_, c) in &chars {
                match crate::shaper::bidi_class(*c as u32) {
                    crate::shaper::BidiClass::L => {
                        found = Some(false);
                        break;
                    }
                    crate::shaper::BidiClass::R | crate::shaper::BidiClass::AL => {
                        found = Some(true);
                        break;
                    }
                    _ => {}
                }
            }
            match found {
                Some(v) => v,
                None => style.direction == crate::shaper::ParagraphDirection::FirstStrongRtl,
            }
        }
    }
}

/// Convenience: the width a `WRAP_CONTENT` view would report.
pub fn intrinsic_width(
    text: &str,
    style: &TextStyle,
    registry: &mut FontRegistry,
) -> Result<TextMetrics, TextError> {
    measure_with_registry(text, style, registry)
}
