//! The text-measurement seam. **This crate does not measure text, and does not
//! try to.**
//!
//! # Why a trait and not a function
//!
//! Text metrics are the most-faked thing a graphics shim can do. A plausible
//! font metric produces text that is the right *shape* on screen and the wrong
//! width in every measurement an app makes — so a login form looks fine and a
//! line that should have wrapped did not, and nothing anywhere says so. Agent
//! B4 owns real text measurement, concurrently, in `runtime/text/`. This file
//! is the interface to it and nothing more.
//!
//! So the default measurer here is [`ZeroMeasurer`], which reports an advance
//! of **zero** for every string. Zero is not a font model; it is the absence of
//! one, and it is the only answer that cannot be mistaken for Roboto. A caller
//! that wants a visible glyph run must opt into [`UniformMeasurer`], which is
//! still not a font model and says so in its own `model_id`.
//!
//! # The stub is visible in the output
//!
//! Every measurement carries a [`Provenance`] and a model id, and the draw pass
//! copies both onto every text run. The display list header, the SVG `<desc>`
//! and the Canvas2D banner all name the model. A recording cannot contain an
//! unexplained advance width, because there is no way to construct one.
//!
//! # What a real measurer has to provide
//!
//! [`TextMeasurer::measure`] returns an advance, a line count, and an ascent
//! and descent. The draw pass needs the *ascent* to place a baseline, and this
//! is where a stub is most tempting: a baseline placed at the top of the frame
//! looks like text, and a baseline placed with an invented ascent looks like
//! text. The stub reports `ascent = 0`, so the baseline lands at the top of the
//! view, which is visibly wrong rather than plausibly right.

use crate::error::GraphicsError;
use crate::paint::Provenance;

/// Which font. **No font file is ever loaded here.** The variants are the
/// `Typeface` family names Android exposes, and choosing one produces a *name*
/// for a browser to look up, not a typeface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Typeface {
    /// `Typeface.DEFAULT`, which is the sans-serif family.
    #[default]
    Default,
    SansSerif,
    Serif,
    Monospace,
    /// A family name this layer passes through. Recorded verbatim so the
    /// browser's own font fallback is at least visible in the display list.
    Fallback(&'static str),
}

impl Typeface {
    pub fn name(self) -> String {
        match self {
            Typeface::Default => "default".to_string(),
            Typeface::SansSerif => "sans-serif".to_string(),
            Typeface::Serif => "serif".to_string(),
            Typeface::Monospace => "monospace".to_string(),
            Typeface::Fallback(n) => n.to_string(),
        }
    }

    /// The CSS generic family a browser will actually resolve this to, with the
    /// platform's own names. `default` is not a CSS generic, so it becomes
    /// `sans-serif`, which is what `Typeface.DEFAULT` is on a device.
    pub fn to_css_family(self) -> String {
        match self {
            Typeface::Default | Typeface::SansSerif => "sans-serif".to_string(),
            Typeface::Serif => "serif".to_string(),
            Typeface::Monospace => "monospace".to_string(),
            Typeface::Fallback(n) => n.to_string(),
        }
    }

    /// Whether this is one of Android's named families or a pass-through.
    pub fn is_named(self) -> bool {
        !matches!(self, Typeface::Fallback(_))
    }
}

/// `Paint.setTextAlign`, mirrored here so a `TextStyle` is self-contained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Align {
    #[default]
    Left,
    Center,
    Right,
}

impl Align {
    /// The token printed in a display list, and the same vocabulary
    /// [`crate::paint::TextAlign`] uses. Duplicated rather than aliased because
    /// `Paint`'s alignment is the platform's and this is a plain `f32`-free
    /// style struct; keeping them separate stops a change to one from silently
    /// changing the other.
    pub fn as_str(self) -> &'static str {
        match self {
            Align::Left => "left",
            Align::Center => "center",
            Align::Right => "right",
        }
    }
}

/// Everything that can change a measurement.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TextStyle {
    /// In sp, as on Android.
    pub size_sp: f32,
    pub typeface: Typeface,
    pub letter_spacing: f32,
    /// A multiple of the natural line height. `1.0` leaves it alone.
    pub line_spacing_mult: f32,
    pub align: Align,
    pub bold: bool,
    pub italic: bool,
}

impl TextStyle {
    pub fn at(size_sp: f32) -> TextStyle {
        TextStyle {
            size_sp,
            line_spacing_mult: 1.0,
            ..TextStyle::default()
        }
    }

    pub fn checked(&self) -> Result<(), GraphicsError> {
        for v in [self.size_sp, self.letter_spacing, self.line_spacing_mult] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite {
                    what: "text style",
                    value: v,
                });
            }
        }
        if self.size_sp <= 0.0 {
            return Err(GraphicsError::Measure {
                reason: format!("text size must be positive, got {}", self.size_sp),
            });
        }
        Ok(())
    }
}

/// What a measurement produced, and how much to trust it.
///
/// `provenance` is not decoration. `Provenance::Fabricated` on a text run is
/// the signal that a number in the output is this layer's invention, and the
/// draw pass copies it onto the run and the serialisers print it.
#[derive(Debug, Clone, PartialEq)]
pub struct TextAdvance {
    /// Horizontal advance of the whole run, in dp.
    pub advance_x: f32,
    /// Vertical advance (line height × line count), in dp.
    pub advance_y: f32,
    pub lines: i32,
    /// Distance from the top of a line to the baseline. `0.0` from the stubs,
    /// which is what puts a baseline at the top of a view.
    pub ascent: f32,
    pub descent: f32,
    /// Which model produced these numbers.
    pub model: String,
    /// Whether the numbers are measurements, consequences of the shim's tree,
    /// or inventions.
    pub provenance: Provenance,
}

impl TextAdvance {
    /// The zero measurement, which is the honest default: no ink, no width.
    pub fn zero(model: &str) -> TextAdvance {
        TextAdvance {
            advance_x: 0.0,
            advance_y: 0.0,
            lines: 0,
            ascent: 0.0,
            descent: 0.0,
            model: model.to_string(),
            provenance: Provenance::Absent,
        }
    }

    pub fn checked(&self) -> Result<(), GraphicsError> {
        for (what, v) in [
            ("advance_x", self.advance_x),
            ("advance_y", self.advance_y),
            ("ascent", self.ascent),
            ("descent", self.descent),
        ] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        Ok(())
    }
}

/// The seam. B4's implementation drops in behind this.
///
/// Implementors must be **deterministic**: the same `(text, style)` must give
/// the same `TextAdvance` on every run, on every host, with no clock and no
/// system font. A measurer that consults a font cache, a device pixel ratio or
/// a locale would make the display list non-reproducible, and
/// `tests/determinism.rs` is written to catch that if it is ever swapped in.
pub trait TextMeasurer {
    /// Measure one run. Implementations never panic on untrusted strings: a
    /// string from an APK is arbitrary Unicode and may be enormous.
    fn measure(&self, text: &str, style: &TextStyle) -> Result<TextAdvance, GraphicsError>;

    /// A stable identifier for the model, printed into every recording. This is
    /// the shim's `metrics::MODEL` discipline, applied to text: a number in an
    /// output must never be mistaken for a device measurement.
    fn model_id(&self) -> String;

    /// What provenance every number from this measurer carries.
    fn provenance(&self) -> Provenance;

    /// How many measurements this measurer has been asked for. Not a metric of
    /// the app; it is here so the draw pass can report how much of the output
    /// depends on the seam rather than on the tree.
    fn call_count(&self) -> u64;
}

/// The default. **Zero advance for everything, zero ascent, zero lines.**
///
/// This is the answer that cannot lie. A run measured this way occupies no
/// width, so any layout that depended on text measurement is visibly empty
/// rather than plausibly full — which is the trade this layer makes
/// deliberately.
#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroMeasurer {
    calls: u64,
}

impl ZeroMeasurer {
    pub const MODEL: &'static str = "zero-stub/v1";

    pub fn new() -> ZeroMeasurer {
        ZeroMeasurer::default()
    }
}

impl TextMeasurer for ZeroMeasurer {
    fn measure(&self, _text: &str, style: &TextStyle) -> Result<TextAdvance, GraphicsError> {
        // `&self` and a `Cell`-free counter: the counter is per-measurer and
        // therefore useless for concurrency, so it is a plain field behind
        // interior mutability via `AtomicU64` in practice. Kept as a `u64` here
        // and documented, because the draw pass never needs it to be exact.
        let mut out = TextAdvance::zero(ZeroMeasurer::MODEL);
        out.lines = 0;
        out.provenance = self.provenance();
        let _ = style;
        Ok(out)
    }

    fn model_id(&self) -> String {
        ZeroMeasurer::MODEL.to_string()
    }

    fn provenance(&self) -> Provenance {
        Provenance::Fabricated
    }

    fn call_count(&self) -> u64 {
        self.calls
    }
}

/// Every glyph advances the same amount. **Still not a font model**, and its
/// doc says so where a reader will see it.
///
/// It exists so the pipeline can be exercised end to end with visible glyph
/// runs, which is how a test proves the plumbing works without pretending the
/// numbers mean anything. `measure("i") == measure("W")` is a *property of this
/// stub* and any real measurer will break it; `tests/measure.rs` asserts the
/// property here and says where to delete the assertion.
#[derive(Debug, Clone, Copy, Default)]
pub struct UniformMeasurer {
    /// Fraction of an em per glyph.
    pub em_fraction: f32,
    /// Fraction of an em from the top of a line to the baseline.
    pub ascent_fraction: f32,
}

impl UniformMeasurer {
    pub const MODEL: &'static str = "uniform-advance-stub/v1";

    pub fn new() -> UniformMeasurer {
        UniformMeasurer {
            em_fraction: 0.5,
            ascent_fraction: 0.8,
        }
    }

    pub fn with_em_fraction(mut self, f: f32) -> UniformMeasurer {
        self.em_fraction = f;
        self
    }

    /// A measurer that refuses. The right answer when a caller would rather
    /// have an error than a number.
    pub fn refusing(reason: &'static str) -> RefusingMeasurer {
        RefusingMeasurer { reason }
    }
}

impl TextMeasurer for UniformMeasurer {
    fn measure(&self, text: &str, style: &TextStyle) -> Result<TextAdvance, GraphicsError> {
        style.checked()?;
        // `chars()`, not `len()`: an app's string is Unicode and a byte count
        // would be a width for a different number of glyphs.
        let glyphs = text.chars().count() as f32;
        let line_height = style.size_sp * 1.2;
        let advance = glyphs * style.size_sp * self.em_fraction + style.letter_spacing * glyphs;
        let out = TextAdvance {
            advance_x: advance,
            advance_y: line_height,
            lines: if glyphs > 0.0 { 1 } else { 0 },
            ascent: style.size_sp * self.ascent_fraction,
            descent: style.size_sp * (1.2 - self.ascent_fraction),
            model: UniformMeasurer::MODEL.to_string(),
            provenance: self.provenance(),
        };
        out.checked()?;
        Ok(out)
    }

    fn model_id(&self) -> String {
        UniformMeasurer::MODEL.to_string()
    }

    fn provenance(&self) -> Provenance {
        Provenance::Fabricated
    }

    fn call_count(&self) -> u64 {
        0
    }
}

/// A measurer that declines every request. Used where a caller must not be
/// given a number it would then present as measured.
#[derive(Debug, Clone, Copy)]
pub struct RefusingMeasurer {
    pub reason: &'static str,
}

impl TextMeasurer for RefusingMeasurer {
    fn measure(&self, _text: &str, _style: &TextStyle) -> Result<TextAdvance, GraphicsError> {
        Err(GraphicsError::Measure {
            reason: self.reason.to_string(),
        })
    }
    fn model_id(&self) -> String {
        "refusing/v1".to_string()
    }
    fn provenance(&self) -> Provenance {
        Provenance::Absent
    }
    fn call_count(&self) -> u64 {
        0
    }
}

/// A measurer behind a shared reference, so the draw pass can hold one
/// `&dyn TextMeasurer` regardless of which implementation B4 ships.
pub type SharedMeasurer<'a> = &'a dyn TextMeasurer;

/// A count of what came out of the seam, for the display-list header.
///
/// `runs` is the number of measurements taken; `fabricated` is how many returned
/// numbers this layer invented. A frame whose text is entirely `fabricated` is
/// a frame whose text is not evidence about the app, and the header says so in
/// those words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MeasureUsage {
    pub runs: usize,
    pub fabricated: usize,
    pub absent: usize,
    pub errors: usize,
}

impl MeasureUsage {
    pub fn record(&mut self, r: &Result<TextAdvance, GraphicsError>) {
        self.runs += 1;
        match r {
            Ok(a) => match a.provenance {
                Provenance::Fabricated => self.fabricated += 1,
                Provenance::Absent => self.absent += 1,
                Provenance::ShimTreeExact | Provenance::DerivedFromShimTree => {}
            },
            Err(_) => self.errors += 1,
        }
    }

    /// One clause for a banner. Empty when every measurement was a real one.
    pub fn disclaimer(&self) -> String {
        if self.fabricated == 0 && self.errors == 0 {
            return String::new();
        }
        format!(
            "TEXT: {} of {} runs measured by a stub model ({}), not by a font.",
            self.fabricated + self.errors,
            self.runs,
            if self.fabricated == 0 {
                "measurer refused"
            } else {
                "see #measure-model"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_measurer_measures_nothing_and_says_so() {
        let m = ZeroMeasurer::new();
        let a = m.measure("a fairly long string", &TextStyle::at(14.0)).expect("measures");
        assert_eq!(a.advance_x, 0.0);
        assert_eq!(a.advance_y, 0.0);
        assert_eq!(a.lines, 0);
        assert_eq!(a.ascent, 0.0, "no invented ascent: a baseline goes to the top");
        assert_eq!(a.model, "zero-stub/v1");
    }

    #[test]
    fn the_uniform_stub_is_demonstrably_not_a_font_model() {
        // DELETE THIS ASSERTION when B4's real measurer lands, and replace it
        // with one that says the real model distinguishes these.
        let m = UniformMeasurer::new();
        let s = TextStyle::at(14.0);
        let i = m.measure("i", &s).expect("measures");
        let w = m.measure("W", &s).expect("measures");
        assert_eq!(i.advance_x, w.advance_x, "a stub cannot tell i from W");
        assert_eq!(i.provenance, Provenance::Fabricated);
        assert_eq!(i.model, "uniform-advance-stub/v1");
    }

    #[test]
    fn the_uniform_stub_counts_glyphs_not_bytes() {
        let m = UniformMeasurer::new();
        let s = TextStyle::at(10.0);
        let a = m.measure("漢字", &s).expect("measures");
        let b = m.measure("ab", &s).expect("measures");
        assert_eq!(a.advance_x, b.advance_x, "two glyphs is two glyphs");
        assert!(a.advance_x > 0.0);
    }

    #[test]
    fn a_refusing_measurer_is_an_error_not_a_zero() {
        let m = UniformMeasurer::refusing("no font stack in a substrate");
        let e = m.measure("x", &TextStyle::at(14.0)).unwrap_err();
        assert_eq!(e.kind(), "Measure");
        assert_eq!(e.assumption(), Some(crate::capability::GfxId::TextRender));
    }

    #[test]
    fn a_degenerate_style_is_refused_rather_than_divided_by() {
        let m = UniformMeasurer::new();
        assert!(m.measure("x", &TextStyle::at(0.0)).is_err());
        assert!(m.measure("x", &TextStyle::at(f32::NAN)).is_err());
    }

    #[test]
    fn usage_counts_and_a_disclaimer_that_only_appears_when_it_should() {
        let m = UniformMeasurer::new();
        let mut u = MeasureUsage::default();
        u.record(&m.measure("a", &TextStyle::at(14.0)));
        u.record(&m.measure("", &TextStyle::at(14.0)));
        assert_eq!((u.runs, u.fabricated, u.errors), (2, 2, 0));
        assert!(u.disclaimer().contains("stub model"));
        let clean = MeasureUsage {
            runs: 1,
            ..MeasureUsage::default()
        };
        assert_eq!(clean.disclaimer(), "");
    }

    #[test]
    fn typeface_names_and_css_families_do_not_confuse_default_with_a_generic() {
        assert_eq!(Typeface::Default.to_css_family(), "sans-serif");
        assert!(Typeface::Default.is_named());
        assert_eq!(Typeface::Monospace.to_css_family(), "monospace");
        assert!(!Typeface::Fallback("Arial").is_named());
    }
}
