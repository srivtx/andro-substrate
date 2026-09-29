//! Calibration: the error of this crate's measurements against a real device.
//!
//! # Why this file exists
//!
//! Everything else in this crate is a claim. This file is the check.
//!
//! A text engine is trivially self-consistent: if you sum the advances in
//! `hmtx` twice you get the same answer twice, and a test that compares the
//! engine against itself passes forever and says nothing about whether a `TextView`
//! on a phone is the right width. This project has already shipped two headline
//! numbers that were wrong by 40x and 20x, both for exactly that reason. So
//! this module holds the one number that matters: the distribution of the
//! difference between what this crate computes and what `android.graphics.Paint`
//! computes on a physical Android device, for the same text at the same size.
//!
//! # Method
//!
//! 1. [`corpus`] generates a fixed, deterministic list of measurement cases.
//!    It is a pure function of the crate version — no randomness, no clock.
//! 2. The same list is serialised to JSONL and pushed to an Android device by
//!    `runtime/text/tools/run_calibration.sh`, which builds a tiny APK, runs it
//!    and pulls the device's answers back into `fixtures/`.
//! 3. [`compare`] replays those device answers through this crate and reports
//!    the error.
//!
//! Step 2 is a measurement; step 3 is arithmetic on a recorded measurement. The
//! numbers in [`Report`] are therefore **measured** (they come off a device) and
//! the pass/fail thresholds in the tests are **derived** from them. Anything
//! labelled `conjecture` in this file is a guess and is not used in a test.
//!
//! # Reproducing
//!
//! ```text
//! cd runtime/text
//! SUBSTRATE_TEXT_CALIBRATE=1 tools/run_calibration.sh
//! ```
//!
//! Without the environment variable the test compares against the committed
//! `fixtures/device-android13.jsonl` and needs no device. That is deliberate:
//! a calibration figure that can only be regenerated on the machine that made
//! it is not a calibration figure, it is an anecdote.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::font::{FontRegistry, FontSource, License};
use crate::shaper::{measure, ParagraphDirection, Rounding, TextMetrics, TextStyle};

// ===========================================================================
// The corpus
// ===========================================================================

/// One measurement request. Serialised to the device unchanged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasureCase {
    pub id: u32,
    /// Script label, used to group the error report. Not a claim about the
    /// script of the string; a label the corpus author assigned.
    pub script: String,
    pub text: String,
    pub size_px: f32,
    pub typeface: String,
    pub bold: bool,
    pub letter_spacing_px: f32,
    pub text_scale_x: f32,
}

impl MeasureCase {
    /// The `TextStyle` this case asks for.
    pub fn style(&self) -> TextStyle {
        TextStyle {
            text_size_px: self.size_px,
            family: self.typeface.clone(),
            style: if self.bold { "bold".into() } else { "regular".into() },
            letter_spacing_em: if self.size_px > 0.0 {
                self.letter_spacing_px / self.size_px
            } else {
                0.0
            },
            text_scale_x: self.text_scale_x,
            rounding: Rounding::PerGlyphWholePixel,
            direction: ParagraphDirection::FirstStrongLtr,
            locale: "en-US".to_string(),
        }
    }
}

/// One `TextUtils.ellipsize` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EllipsizeCase {
    pub id: u32,
    pub script: String,
    pub text: String,
    pub size_px: f32,
    pub typeface: String,
    pub bold: bool,
    pub avail_px: f32,
    /// `START`, `MIDDLE` or `END`.
    pub where_: String,
}

/// One `StaticLayout` request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutCase {
    pub id: u32,
    pub script: String,
    pub text: String,
    pub size_px: f32,
    pub typeface: String,
    pub bold: bool,
    pub width_px: i32,
}

/// A calibration case of any kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Case {
    #[serde(rename = "measure")]
    Measure(MeasureCase),
    #[serde(rename = "ellipsize")]
    Ellipsize(EllipsizeCase),
    #[serde(rename = "layout")]
    Layout(LayoutCase),
}

impl Case {
    pub fn id(&self) -> u32 {
        match self {
            Case::Measure(c) => c.id,
            Case::Ellipsize(c) => c.id,
            Case::Layout(c) => c.id,
        }
    }
    pub fn script(&self) -> &str {
        match self {
            Case::Measure(c) => &c.script,
            Case::Ellipsize(c) => &c.script,
            Case::Layout(c) => &c.script,
        }
    }
}

/// The texts the corpus measures, grouped by script.
///
/// Deliberately not random and deliberately not generated from a seed: a
/// calibration corpus that changes when someone changes a PRNG is a corpus
/// whose error figures are not comparable between runs.
pub const CORPUS: &[(&str, &str)] = &[
    // ---- Latin ----
    ("latin", "Hello, world"),
    ("latin", "The quick brown fox jumps over the lazy dog"),
    ("latin", "Settings"),
    ("latin", "Wi-Fi"),
    ("latin", "  leading and trailing  "),
    ("latin", "IIII llll 0000 .... ---- ==== ++++"),
    ("latin", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
    ("latin", "abcdefghijklmnopqrstuvwxyz"),
    ("latin", "0123456789"),
    ("latin", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
    ("latin", "Monday 3rd February 2026, 14:35"),
    ("latin", "A"),
    ("latin", " "),
    ("latin", ""),
    ("latin", "jjjjjjjjjjjjjjjjjjjj"),
    ("latin", "WWWWWWWWWWWWWWWWWWWW"),
    ("latin", "MMMMMMMMMMMMMMMMMMMM"),
    ("latin", "iiiiiiiiiiiiiiiiiiii"),
    // ---- Latin with diacritics ----
    ("latin_ext", "Größe übersicht ÄÖÜ ß"),
    ("latin_ext", "Àéîõü çñ"),
    ("latin_ext", "Zażółć gęślą jaźń"),
    // ---- Greek ----
    ("greek", "Γειά σου Κόσμε"),
    ("greek", "αβγδεζηθικλμνξοπρστυφχψω"),
    ("greek", "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ"),
    // ---- Cyrillic ----
    ("cyrillic", "Привет мир"),
    ("cyrillic", "Съешь же ещё этих мягких французских булок"),
    ("cyrillic", "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"),
    ("cyrillic", "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"),
    // ---- Arabic ----
    ("arabic", "مرحبا بالعالم"),
    ("arabic", "اللغة العربية"),
    ("arabic", "هذا اختبار"),
    ("arabic", "أهلاً وسهلاً"),
    ("arabic", "محمد رسول الله"),
    // ---- Hebrew ----
    ("hebrew", "שלום עולם"),
    ("hebrew", "בדיקה עברית"),
    ("hebrew", "שלום"),
    // ---- Devanagari ----
    ("devanagari", "नमस्ते दुनिया"),
    ("devanagari", "हिन्दी"),
    ("devanagari", "क्षत्रिय"),
    // ---- Thai ----
    ("thai", "สวัสดีชาวโลก"),
    ("thai", "ภาษาไทย"),
    // ---- CJK ----
    ("cjk", "你好世界"),
    ("cjk", "中文字符测试"),
    ("cjk", "東京都渋谷区"),
    ("kana", "ひらがなカタカナ"),
    ("kana", "こんにちは世界"),
    ("hangul", "안녕하세요 세계"),
    ("hangul", "한국어 테스트"),
    // ---- Digits ----
    ("digits", "0123456789"),
    ("digits_arabic", "٠١٢٣٤٥٦٧٨٩"),
    ("digits_arabic", "۰۱۲۳۴۵۶۷۸۹"),
    ("digits_devanagari", "०१२३४५६७८९"),
    // ---- Emoji ----
    ("emoji", "😀😃😄😁"),
    ("emoji", "👍🏽 👩‍👩‍👧‍👦"),
    ("emoji", "🇬🇧🇺🇸"),
    // ---- Mixed and bidi ----
    ("mixed", "Total: 123 items"),
    ("mixed", "user@example.com"),
    ("mixed", "https://example.com/path?q=1"),
    ("mixed", "50% off — $12.99"),
    ("mixed", "מספר 123 עברי"),
    ("mixed", "رقم 123 عربي"),
    ("mixed", "العدد 5 apples"),
    ("mixed", "(מספר) 123"),
    ("mixed", "Total: ١٢٣ items"),
    ("mixed", "abc אבג abc"),
    ("mixed", "مرحبا world"),
    ("mixed", "‏RTL mark then text"),
    ("mixed", "price: $1,234.56 (approx.)"),
    ("mixed", "2026-02-14T14:35:00Z"),
    // ---- Pathological ----
    ("edge", "\u{200b}zero width space\u{200b}"),
    ("edge", "\u{feff}bom\u{feff}"),
    ("edge", "\u{0301}combining acute"),
    ("edge", "e\u{0301}"),
    ("edge", "\u{0640}arabic tatweel"),
    ("edge", "👨\u{200d}👩\u{200d}👧\u{200d}👦"),
    ("edge", "a\u{00ad}b"),
    ("edge", "very long unbroken tokenwithoutanyspaces at all here"),
    ("edge", "tab\there"),
    ("edge", "newline\nhere"),
    ("edge", "trailing space "),
    ("edge", "  "),
];

/// The text sizes the corpus measures at, in pixels.
pub const SIZES: &[f32] = &[8.0, 11.0, 14.0, 16.0, 20.0, 24.0, 34.0];

/// Typefaces the corpus sweeps. Android's `Typeface.create` resolves each to a
/// real file; `default` is the platform font.
pub const TYPEFACES: &[&str] = &["default", "sans-serif", "serif", "monospace"];

/// The full calibration corpus, deterministically generated.
///
/// Three sweeps, because they answer different questions:
///
/// * `SIZES x CORPUS` at the default typeface — the width error, per script,
///   at the sizes a real app uses.
/// * `TYPEFACES` at 16px over a Latin and a CJK sample — the typeface-sweep
///   error, which is dominated by the vertical metrics and is where a font
///   substitution shows up most.
/// * letter spacing and horizontal scale at 16px — whether the model of those
///   two knobs is right at all.
pub fn corpus() -> Vec<Case> {
    let mut out = Vec::new();
    let mut id = 1u32;

    for (script, text) in CORPUS {
        for size in SIZES {
            out.push(Case::Measure(MeasureCase {
                id,
                script: (*script).to_string(),
                text: (*text).to_string(),
                size_px: *size,
                typeface: "default".to_string(),
                bold: false,
                letter_spacing_px: 0.0,
                text_scale_x: 1.0,
            }));
            id += 1;
        }
    }

    for tf in TYPEFACES {
        for (script, text) in [
            ("latin", "The quick brown fox jumps over the lazy dog"),
            ("latin", "Settings"),
            ("greek", "Γειά σου Κόσμε"),
            ("cyrillic", "Привет мир"),
            ("arabic", "مرحبا بالعالم"),
            ("cjk", "中文字符测试"),
            ("kana", "こんにちは世界"),
            ("hangul", "안녕하세요 세계"),
            ("mixed", "Total: 123 items"),
        ] {
            for bold in [false, true] {
                out.push(Case::Measure(MeasureCase {
                    id,
                    script: script.to_string(),
                    text: text.to_string(),
                    size_px: 16.0,
                    typeface: (*tf).to_string(),
                    bold,
                    letter_spacing_px: 0.0,
                    text_scale_x: 1.0,
                }));
                id += 1;
            }
        }
    }

    for ls in [0.0f32, 0.02, 0.05, 0.1] {
        for (script, text) in [
            ("latin", "Letter spacing"),
            ("latin", "The quick brown fox"),
            ("arabic", "مرحبا بالعالم"),
            ("mixed", "Total: 123 items"),
        ] {
            out.push(Case::Measure(MeasureCase {
                id,
                script: script.to_string(),
                text: text.to_string(),
                size_px: 16.0,
                typeface: "default".to_string(),
                bold: false,
                letter_spacing_px: ls,
                text_scale_x: 1.0,
            }));
            id += 1;
        }
    }

    for sx in [0.5f32, 0.75, 1.25, 1.5] {
        for (script, text) in [("latin", "Scaled text"), ("arabic", "نص مقيس")] {
            out.push(Case::Measure(MeasureCase {
                id,
                script: script.to_string(),
                text: text.to_string(),
                size_px: 16.0,
                typeface: "default".to_string(),
                bold: false,
                letter_spacing_px: 0.0,
                text_scale_x: sx,
            }));
            id += 1;
        }
    }

    // ---- ellipsize ----
    let ell_texts = [
        ("latin", "The quick brown fox jumps over the lazy dog"),
        ("latin", "Settings"),
        ("latin", "abcdefghijklmnopqrstuvwxyz0123456789"),
        ("arabic", "مرحبا بالعالم هذا اختبار طويل"),
        ("hebrew", "בדיקה עברית ארוכה מאוד"),
        ("cjk", "中文字符测试字符串很长"),
        ("mixed", "Total: 1,234 items in your cart"),
        ("edge", "short"),
    ];
    for (script, text) in ell_texts {
        for avail in [40.0f32, 80.0, 120.0, 200.0, 320.0, 480.0] {
            for where_ in ["END", "START", "MIDDLE"] {
                out.push(Case::Ellipsize(EllipsizeCase {
                    id,
                    script: script.to_string(),
                    text: text.to_string(),
                    size_px: 16.0,
                    typeface: "default".to_string(),
                    bold: false,
                    avail_px: avail,
                    where_: where_.to_string(),
                }));
                id += 1;
            }
        }
    }

    // ---- StaticLayout ----
    let lay_texts = [
        ("latin", "The quick brown fox jumps over the lazy dog and keeps going"),
        ("latin", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod"),
        ("arabic", "مرحبا بالعالم هذا نص طويل نسبيا يحتوي على كلمات كثيرة"),
        ("cjk", "中文字符测试字符串很长用来测试换行行为"),
        ("edge", "very long unbroken tokenwithoutanyspaces at all here"),
    ];
    for (script, text) in lay_texts {
        for width in [80, 160, 320, 640] {
            out.push(Case::Layout(LayoutCase {
                id,
                script: script.to_string(),
                text: text.to_string(),
                size_px: 16.0,
                typeface: "default".to_string(),
                bold: false,
                width_px: width,
            }));
            id += 1;
        }
    }

    out
}

/// The corpus as JSONL, exactly as it is pushed to the device.
pub fn corpus_jsonl() -> String {
    let mut s = String::new();
    for c in corpus() {
        s.push_str(&serde_json::to_string(&c).expect("Case is always serialisable"));
        s.push('\n');
    }
    s
}

// ===========================================================================
// The device's answers
// ===========================================================================

/// A `Paint.measureText` + `Paint.getFontMetrics` answer from a real device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceMeasure {
    pub id: u32,
    pub kind: String,
    /// `Paint.measureText`, in px.
    pub width: f32,
    /// `Paint.getTextWidths`, per character, in px.
    pub widths: Vec<f32>,
    /// `FontMetrics.ascent`, negative.
    pub ascent: f32,
    /// `FontMetrics.descent`, positive.
    pub descent: f32,
    /// `FontMetrics.top`, negative.
    pub top: f32,
    /// `FontMetrics.bottom`, positive.
    pub bottom: f32,
    pub leading: f32,
    pub ascent_int: i32,
    pub descent_int: i32,
    pub top_int: i32,
    pub bottom_int: i32,
    pub char_sum: f32,
    pub measure_minus_charsum: f32,
}

/// A `TextUtils.ellipsize` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceEllipsize {
    pub id: u32,
    pub kind: String,
    pub result: String,
    pub result_width: f32,
}

/// A `StaticLayout` answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceLayout {
    pub id: u32,
    pub kind: String,
    pub lines: usize,
    pub height: i32,
    pub line_count_minus: Vec<f32>,
}

/// The header line: what device, what density, what locale. This is what makes
/// a recorded measurement a measurement rather than a number.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceHeader {
    pub record: String,
    pub sdk: i32,
    pub release: String,
    pub fingerprint: String,
    pub model: String,
    pub density: f32,
    pub density_dpi: i32,
    pub locale: String,
    pub font_scale: f32,
}

/// One line of a device recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeviceRow {
    Header(DeviceHeader),
    Measure(DeviceMeasure),
    Ellipsize(DeviceEllipsize),
    Layout(DeviceLayout),
    /// The app caught a throwable. Treated as a hard error by [`parse_device`],
    /// because a partial recording is not a measurement.
    Fatal { fatal: String },
}

/// A whole device recording.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecording {
    pub header: DeviceHeader,
    pub measures: BTreeMap<u32, DeviceMeasure>,
    pub ellipsizes: BTreeMap<u32, DeviceEllipsize>,
    pub layouts: BTreeMap<u32, DeviceLayout>,
}

/// Parse a device JSONL recording. A `fatal` row is an error: a harness that
/// recorded half a corpus and reported a mean over it would be exactly the
/// failure this project is trying to avoid.
pub fn parse_device(jsonl: &str) -> Result<DeviceRecording, String> {
    let mut header = None;
    let mut measures = BTreeMap::new();
    let mut ellipsizes = BTreeMap::new();
    let mut layouts = BTreeMap::new();
    for (n, line) in jsonl.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("line {}: not JSON: {e}", n + 1))?;
        if let Some(f) = v.get("fatal").and_then(|x| x.as_str()) {
            return Err(format!("line {}: device harness threw: {f}", n + 1));
        }
        let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("");
        if v.get("record").is_some() {
            header = Some(
                serde_json::from_value(v).map_err(|e| format!("line {}: header: {e}", n + 1))?,
            );
            continue;
        }
        match kind {
            "measure" => {
                let m: DeviceMeasure = serde_json::from_value(v)
                    .map_err(|e| format!("line {}: measure: {e}", n + 1))?;
                measures.insert(m.id, m);
            }
            "ellipsize" => {
                let m: DeviceEllipsize = serde_json::from_value(v)
                    .map_err(|e| format!("line {}: ellipsize: {e}", n + 1))?;
                ellipsizes.insert(m.id, m);
            }
            "layout" => {
                let m: DeviceLayout = serde_json::from_value(v)
                    .map_err(|e| format!("line {}: layout: {e}", n + 1))?;
                layouts.insert(m.id, m);
            }
            other => return Err(format!("line {}: unknown kind '{other}'", n + 1)),
        }
    }
    let header = header.ok_or_else(|| "no device header in recording".to_string())?;
    Ok(DeviceRecording {
        header,
        measures,
        ellipsizes,
        layouts,
    })
}

// ===========================================================================
// The error report
// ===========================================================================

/// How a figure was obtained. Every number in a report carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Provenance {
    /// Read off a real device.
    Measured,
    /// Arithmetic on measured values.
    Derived,
    /// A guess. Not used in any assertion.
    Conjecture,
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Provenance::Measured => "measured",
            Provenance::Derived => "derived",
            Provenance::Conjecture => "conjecture",
        })
    }
}

/// The distribution of one class of error.
///
/// Denominators are always carried. A mean without `n` is a decoration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorStats {
    /// How many comparisons went into these figures.
    pub n: usize,
    /// Comparisons where ours was exactly equal to the device's.
    pub exact: usize,
    /// Mean absolute error, px.
    pub mean_abs: f64,
    /// Median absolute error, px.
    pub median_abs: f64,
    /// 95th percentile absolute error, px.
    pub p95_abs: f64,
    /// Largest absolute error, px, and which case it was.
    pub worst_abs: f64,
    pub worst_abs_case: String,
    /// Mean relative error, as a fraction. Only over cases where the device
    /// width was at least `REL_FLOOR` px, because a relative error against a
    /// 1px width is noise.
    pub mean_rel: f64,
    /// Median relative error, as a fraction.
    pub median_rel: f64,
    /// Largest relative error, as a fraction, and which case it was.
    pub worst_rel: f64,
    pub worst_rel_case: String,
    /// Signed mean error, px. A large negative bias means we systematically
    /// under-measure, which is the dangerous direction: it makes text overflow
    /// its box rather than leave a gap.
    pub signed_mean: f64,
}

/// A relative error is only reported when the device width is at least this.
/// Below it, a 1px difference is a large percentage of nothing.
pub const REL_FLOOR: f32 = 8.0;

impl ErrorStats {
    /// Build the distribution from `(label, ours, theirs)` triples.
    pub fn from_rows(rows: &[(String, f64, f64)]) -> ErrorStats {
        let n = rows.len();
        if n == 0 {
            return ErrorStats {
                n: 0,
                exact: 0,
                mean_abs: 0.0,
                median_abs: 0.0,
                p95_abs: 0.0,
                worst_abs: 0.0,
                worst_abs_case: String::new(),
                mean_rel: 0.0,
                median_rel: 0.0,
                worst_rel: 0.0,
                worst_rel_case: String::new(),
                signed_mean: 0.0,
            };
        }
        let mut abs: Vec<(f64, &str)> = Vec::with_capacity(n);
        let mut signed_sum = 0.0f64;
        let mut exact = 0usize;
        for (label, ours, theirs) in rows {
            let d = ours - theirs;
            signed_sum += d;
            if d == 0.0 {
                exact += 1;
            }
            abs.push((d.abs(), label.as_str()));
        }
        let total_abs: f64 = abs.iter().map(|(a, _)| a).sum();
        let mut sorted: Vec<f64> = abs.iter().map(|(a, _)| *a).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_abs = quantile(&sorted, 0.5);
        let p95_abs = quantile(&sorted, 0.95);
        let worst = abs
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .copied()
            .unwrap_or((0.0, ""));

        let mut rel: Vec<(f64, &str)> = Vec::new();
        for (label, ours, theirs) in rows {
            if theirs.abs() >= REL_FLOOR as f64 {
                rel.push((((ours - theirs) / theirs).abs(), label.as_str()));
            }
        }
        let mut rel_sorted: Vec<f64> = rel.iter().map(|(r, _)| *r).collect();
        rel_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mean_rel = if rel.is_empty() {
            0.0
        } else {
            rel.iter().map(|(r, _)| r).sum::<f64>() / rel.len() as f64
        };
        let worst_rel = rel
            .iter()
            .max_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
            .copied()
            .unwrap_or((0.0, ""));

        ErrorStats {
            n,
            exact,
            mean_abs: total_abs / n as f64,
            median_abs,
            p95_abs,
            worst_abs: worst.0,
            worst_abs_case: worst.1.to_string(),
            mean_rel,
            median_rel: quantile(&rel_sorted, 0.5),
            worst_rel: worst_rel.0,
            worst_rel_case: worst_rel.1.to_string(),
            signed_mean: signed_sum / n as f64,
        }
    }
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let pos = q * (sorted.len() - 1) as f64;
    let lo = pos.floor() as usize;
    let hi = pos.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo as f64)
    }
}

/// Which rounding model to use for a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Model {
    /// Sum of per-glyph rounded advances. `Paint.subpixelText = false`.
    PerGlyph,
    /// Sum of fractional advances, rounded once.
    WholeTotal,
    /// Sum of fractional advances, unrounded.
    Subpixel,
}

impl Model {
    pub fn name(&self) -> &'static str {
        match self {
            Model::PerGlyph => "per-glyph whole pixel",
            Model::WholeTotal => "whole-pixel total",
            Model::Subpixel => "subpixel",
        }
    }
}

/// The whole calibration report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// What device produced the reference numbers.
    pub header: DeviceHeader,
    /// Corpus size.
    pub cases: usize,
    /// Comparisons actually made for the chosen model. Less than `cases` when
    /// the device recording is missing rows, and that gap is reported.
    pub compared: usize,
    /// Cases the device never answered, by id. A non-empty list means the
    /// device threw partway and every figure below is over a subset.
    pub missing: Vec<u32>,
    /// Width error, per script, for the platform typeface at normal weight.
    /// This is the headline table: it is the one where our face and the
    /// device's face are trying to be the same font.
    pub width_by_script: BTreeMap<String, ErrorStats>,
    /// Width error over the cases that turn a `Paint` knob
    /// (`letterSpacing`, `textScaleX`) rather than change the font.
    pub width_by_knob: BTreeMap<String, ErrorStats>,
    /// Width error, per typeface, for the chosen model.
    pub width_by_typeface: BTreeMap<String, ErrorStats>,
    /// Width error over everything, for each of the three rounding models. This
    /// is how the model choice itself is justified rather than asserted.
    pub width_by_model: BTreeMap<String, ErrorStats>,
    /// Font vertical metric error: ascent, descent, top, bottom, line height.
    pub vertical: BTreeMap<String, ErrorStats>,
    /// Ellipsise agreement: exact string match count out of compared.
    pub ellipsize: EllipsizeStats,
    /// Line count agreement for `StaticLayout`.
    pub layout: LayoutStats,
}

/// Ellipsise conformance against the device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EllipsizeStats {
    pub n: usize,
    /// Cases where our output string is byte-identical to the device's.
    pub exact: usize,
    /// Cases where the difference is a single trailing/leading character.
    pub off_by_one: usize,
    pub by_where: BTreeMap<String, (usize, usize)>,
}

/// `StaticLayout` line-count conformance against the device.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayoutStats {
    pub n: usize,
    /// Cases where our line count equals the device's.
    pub exact: usize,
    /// Total absolute difference in line counts, summed.
    pub total_line_delta: i64,
    /// Largest single line-count difference.
    pub worst: i64,
    pub worst_case: String,
}

// ===========================================================================
// Running the comparison
// ===========================================================================

/// The fonts the calibration uses.
///
/// `face` is the bundled open font: the one the shipped headless backend
/// measures with. `device_face` is the platform font, used only to separate
/// "the engine's arithmetic is wrong" from "the substitute font is not
/// Roboto"; it is never bundled, only read at calibration time from a device.
pub fn calibration_registry(face: &crate::font::FontFace) -> FontRegistry {
    let mut r = FontRegistry::with_defaults("sans-serif", &["sans-serif", "serif", "monospace"]);
    r.add_as("default", "regular", face.clone());
    r.add_as("sans-serif", "regular", face.clone());
    r.add_as("serif", "regular", face.clone());
    r.add_as("monospace", "regular", face.clone());
    r
}

/// A registry with the bundled regular and bold faces, which is what the crate
/// ships.
pub fn shipped_registry(regular: &crate::font::FontFace, bold: &crate::font::FontFace) -> FontRegistry {
    let mut r = FontRegistry::with_defaults("sans-serif", &["sans-serif", "serif", "monospace"]);
    r.add_as("sans-serif", "regular", regular.clone());
    r.add_as("sans-serif", "bold", bold.clone());
    r.add_as("default", "regular", regular.clone());
    r
}

/// Parse a bundled font, recording the licence it is bundled under.
pub fn parse_bundled(bytes: &[u8], licence: License) -> Result<crate::font::FontFace, crate::TextError> {
    crate::font::FontFace::parse_with(bytes, FontSource::Bundled, licence, Some("sans-serif"))
}

/// Replay a device recording through this crate and produce the report.
pub fn compare(
    cases: &[Case],
    device: &DeviceRecording,
    face: &crate::font::FontFace,
    model: Model,
) -> Report {
    let registry = calibration_registry(face);

    let mut width_by_script: BTreeMap<String, Vec<(String, f64, f64)>> = BTreeMap::new();
    let mut width_by_knob: BTreeMap<String, Vec<(String, f64, f64)>> = BTreeMap::new();
    let mut width_by_typeface: BTreeMap<String, Vec<(String, f64, f64)>> = BTreeMap::new();
    let mut width_by_model: BTreeMap<String, Vec<(String, f64, f64)>> = BTreeMap::new();
    let mut vertical: BTreeMap<String, Vec<(String, f64, f64)>> = BTreeMap::new();
    let mut missing = Vec::new();
    let mut compared = 0usize;

    for case in cases {
        let Case::Measure(c) = case else { continue };
        let Some(d) = device.measures.get(&c.id) else {
            missing.push(c.id);
            continue;
        };
        compared += 1;
        let label = format!("{}|{}|{}", c.script, c.size_px, c.text);

        let mut style = c.style();
        style.rounding = Rounding::PerGlyphWholePixel;

        let ours = match face_measure(&registry, c, &style, model) {
            Ok(m) => m,
            Err(_) => {
                missing.push(c.id);
                continue;
            }
        };

        // Three sweeps, three tables. Mixing them is how a per-script table
        // ends up quoting a monospace measurement under "latin" and looking
        // like a font-substitution problem when it is a sweep artifact.
        let is_sweep = c.typeface != "default" || c.bold;
        let is_knob = c.letter_spacing_px != 0.0 || c.text_scale_x != 1.0;
        if is_knob {
            width_by_knob
                .entry(c.script.clone())
                .or_default()
                .push((label.clone(), ours.width as f64, d.width as f64));
        } else if is_sweep {
            width_by_typeface
                .entry(format!("{}{}", c.typeface, if c.bold { "/bold" } else { "" }))
                .or_default()
                .push((label.clone(), ours.width as f64, d.width as f64));
        } else {
            width_by_script
                .entry(c.script.clone())
                .or_default()
                .push((label.clone(), ours.width as f64, d.width as f64));
        }
        for m in [Model::PerGlyph, Model::WholeTotal, Model::Subpixel] {
            if let Ok(mm) = face_measure(&registry, c, &style, m) {
                width_by_model
                    .entry(m.name().to_string())
                    .or_default()
                    .push((label.clone(), mm.width as f64, d.width as f64));
            }
        }

        for (name, a, b) in [
            ("ascent", ours.ascent, d.ascent),
            ("descent", ours.descent, d.descent),
            ("top", ours.top, d.top),
            ("bottom", ours.bottom, d.bottom),
            ("line_height", ours.line_height, d.ascent - d.descent + d.leading),
        ] {
            vertical
                .entry(name.to_string())
                .or_default()
                .push((label.clone(), a as f64, b as f64));
        }
    }

    // ---- ellipsize ----
    let mut ell = EllipsizeStats {
        n: 0,
        exact: 0,
        off_by_one: 0,
        by_where: BTreeMap::new(),
    };
    let mut reg = registry.clone();
    for case in cases {
        let Case::Ellipsize(c) = case else { continue };
        let Some(d) = device.ellipsizes.get(&c.id) else {
            continue;
        };
        ell.n += 1;
        let style = c.style_for_ellipsize();
        let at = match c.where_.as_str() {
            "START" => crate::layout::TruncateAt::Start,
            "MIDDLE" => crate::layout::TruncateAt::Middle,
            _ => crate::layout::TruncateAt::End,
        };
        let ours = crate::layout::ellipsize(&c.text, &style, &mut reg, c.avail_px, at);
        let entry = ell.by_where.entry(c.where_.clone()).or_insert((0, 0));
        entry.0 += 1;
        match &ours {
            Ok(e) if e.text == d.result => {
                ell.exact += 1;
                entry.1 += 1;
            }
            Ok(e) if char_distance(&e.text, &d.result) == 1 => ell.off_by_one += 1,
            _ => {}
        }
    }

    // ---- StaticLayout ----
    let mut lay = LayoutStats {
        n: 0,
        exact: 0,
        total_line_delta: 0,
        worst: 0,
        worst_case: String::new(),
    };
    let mut reg2 = registry.clone();
    for case in cases {
        let Case::Layout(c) = case else { continue };
        let Some(d) = device.layouts.get(&c.id) else { continue };
        lay.n += 1;
        let style = c.style_for_layout();
        let params = crate::layout::LayoutParams {
            width_px: c.width_px as f32,
            include_pad: true,
            ..Default::default()
        };
        let ours = crate::layout::layout(&c.text, &style, &mut reg2, &params);
        if let Ok(p) = ours {
            let delta = p.line_count() as i64 - d.lines as i64;
            if delta == 0 {
                lay.exact += 1;
            }
            lay.total_line_delta += delta.abs();
            if delta.abs() >= lay.worst.abs() {
                lay.worst = delta;
                lay.worst_case = format!("{}|{}px|{}", c.script, c.width_px, c.text);
            }
        }
    }

    let stat = |m: BTreeMap<String, Vec<(String, f64, f64)>>| -> BTreeMap<String, ErrorStats> {
        m.into_iter()
            .map(|(k, v)| (k, ErrorStats::from_rows(&v)))
            .collect()
    };

    Report {
        header: device.header.clone(),
        cases: cases.len(),
        compared,
        missing,
        width_by_script: stat(width_by_script),
        width_by_knob: stat(width_by_knob),
        width_by_typeface: stat(width_by_typeface),
        width_by_model: stat(width_by_model),
        vertical: stat(vertical),
        ellipsize: ell,
        layout: lay,
    }
}

fn face_measure(
    registry: &FontRegistry,
    c: &MeasureCase,
    style: &TextStyle,
    model: Model,
) -> Result<TextMetrics, crate::TextError> {
    let f = registry
        .peek(&c.typeface, if c.bold { "bold" } else { "regular" })
        .ok_or_else(|| crate::TextError::NoFontAvailable {
            family: c.typeface.clone(),
        })?;
    let mut s = style.clone();
    s.rounding = match model {
        Model::PerGlyph => Rounding::PerGlyphWholePixel,
        Model::WholeTotal => Rounding::WholePixelTotal,
        Model::Subpixel => Rounding::Subpixel,
    };
    // A case that asks for a typeface we did not bundle is measured with the
    // bundled face anyway. That is the whole point: the report is about the
    // engine plus its bundled font, and a miss is recorded in
    // `FontRegistry::unresolved` rather than quietly changing the row.
    measure(&c.text, &s, f)
}

/// Characters one string has that the other does not, by a simple LCS-free
/// count: enough to tell "dropped the last character" from "reordered the
/// string".
fn char_distance(a: &str, b: &str) -> usize {
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let (long, short) = if av.len() > bv.len() {
        (&av, &bv)
    } else {
        (&bv, &av)
    };
    let extra = long.len() - short.len();
    // Does the shorter string appear as a prefix of the longer, ignoring the
    // ellipsis? If so the difference is exactly the trailing ellipsis.
    let stripped: String = a.chars().filter(|c| *c != '\u{2026}').collect();
    let stripped_b: String = b.chars().filter(|c| *c != '\u{2026}').collect();
    if stripped == stripped_b {
        return extra;
    }
    av.len().abs_diff(bv.len()) + 1
}

impl EllipsizeCase {
    fn style_for_ellipsize(&self) -> TextStyle {
        TextStyle {
            text_size_px: self.size_px,
            family: self.typeface.clone(),
            style: if self.bold { "bold".into() } else { "regular".into() },
            ..TextStyle::default()
        }
    }
}

impl LayoutCase {
    fn style_for_layout(&self) -> TextStyle {
        TextStyle {
            text_size_px: self.size_px,
            family: self.typeface.clone(),
            style: if self.bold { "bold".into() } else { "regular".into() },
            ..TextStyle::default()
        }
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "device: {}  API {}  density {} ({}dpi)  locale {}",
            self.header.model,
            self.header.sdk,
            self.header.density,
            self.header.density_dpi,
            self.header.locale
        )?;
        writeln!(
            f,
            "cases: {} corpus, {} compared, {} missing",
            self.cases, self.compared, self.missing.len()
        )?;
        if !self.missing.is_empty() {
            writeln!(f, "  MISSING ids: {:?}", &self.missing[..self.missing.len().min(20)])?;
        }
        writeln!(f, "\nwidth error by rounding model (abs px):")?;
        for (k, v) in &self.width_by_model {
            writeln!(
                f,
                "  {k:24} n={:5} mean={:7.3} median={:7.3} p95={:7.3} worst={:8.3} exact={}/{}",
                v.n, v.mean_abs, v.median_abs, v.p95_abs, v.worst_abs, v.exact, v.n
            )?;
        }
        writeln!(f, "\nwidth error by script (abs px / rel):")?;
        for (k, v) in &self.width_by_script {
            writeln!(
                f,
                "  {k:18} n={:5} mean={:7.3} median={:7.3} p95={:7.3} worst={:8.3} ({:6.2}%) meanrel={:6.2}% worstrel={:7.2}%",
                v.n, v.mean_abs, v.median_abs, v.p95_abs, v.worst_abs, v.worst_rel * 100.0,
                v.mean_rel * 100.0, v.worst_rel * 100.0
            )?;
            if v.worst_abs > 0.0 {
                writeln!(f, "      worst case: {}", v.worst_abs_case)?;
            }
        }
        writeln!(f, "\nwidth error, letterSpacing / textScaleX sweep (abs px):")?;
        for (k, v) in &self.width_by_knob {
            writeln!(
                f,
                "  {k:18} n={:5} mean={:7.3} worst={:8.3} worstrel={:7.2}%",
                v.n, v.mean_abs, v.worst_abs, v.worst_rel * 100.0
            )?;
        }
        writeln!(f, "\nwidth error by typeface (abs px):")?;
        for (k, v) in &self.width_by_typeface {
            writeln!(
                f,
                "  {k:20} n={:5} mean={:7.3} worst={:8.3} worstrel={:7.2}%",
                v.n, v.mean_abs, v.worst_abs, v.worst_rel * 100.0
            )?;
        }
        writeln!(f, "\nvertical metric error (abs px):")?;
        for (k, v) in &self.vertical {
            writeln!(
                f,
                "  {k:12} n={:5} mean={:7.4} median={:7.4} worst={:8.4} exact={}/{}",
                v.n, v.mean_abs, v.median_abs, v.worst_abs, v.exact, v.n
            )?;
        }
        writeln!(
            f,
            "\nellipsize: {}/{} exact string, {} off by one char, by variant: {:?}",
            self.ellipsize.exact, self.ellipsize.n, self.ellipsize.off_by_one, self.ellipsize.by_where
        )?;
        writeln!(
            f,
            "layout:   {}/{} exact line count, total |delta| {}, worst {} ({})",
            self.layout.exact,
            self.layout.n,
            self.layout.total_line_delta,
            self.layout.worst,
            self.layout.worst_case
        )?;
        Ok(())
    }
}
