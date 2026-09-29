//! The backend trait, the serialisable display list, and two implementations of
//! it: a **headless** backend that records, and a **Canvas2D** backend that
//! emits a browser program.
//!
//! # The design, and why the display list is the centre of it
//!
//! `draw.rs` walks a box tree and calls methods on [`Canvas`]. Two backends
//! implement it. The headless one turns the calls into a [`DisplayList`] — a
//! value that can be diffed, hashed, serialised to a canonical text form, and
//! compared byte-for-byte between runs. The Canvas2D one turns the same calls
//! into a JavaScript program for a browser to run.
//!
//! Crucially the display list is *also* what the SVG emitter and the Canvas2D
//! emitter consume, so the two backends cannot disagree structurally: there is
//! one command vocabulary and two ways of writing it down. What they *can*
//! disagree about is which `PorterDuff` modes they can express, and that
//! disagreement is measured by enumerating all twenty-one in
//! `tests/capability.rs` rather than by a table someone wrote down.
//!
//! # Determinism
//!
//! [`DisplayList::to_text`] is byte-stable. The rules that make it so are:
//!
//! - No clocks, no random numbers, no pointer addresses, no iteration over a
//!   hash map. `tests/determinism.rs` re-executes the *test binary* in a child
//!   process and compares bytes, so the claim is measured across processes and
//!   not asserted in one.
//! - Every float goes through [`q`], which normalises `-0.0` to `0.0` and writes
//!   the shortest round-tripping form. Without it, `-0.0` and `0.0` are the same
//!   number and different bytes.
//! - Colour is `u32`, path coordinates are `f32`, and Rust does not reassociate
//!   floating-point arithmetic at any optimisation level. Any arithmetic a
//!   backend does is on values that came out of the box tree, unmodified.
//!
//! **What breaks it**, and is listed here so a future reader does not have to
//! find out the hard way: a real font measurer that consults a system font
//! cache; a `HashMap` in any serialised struct; `f32` arithmetic whose result
//! depends on the host's FPU mode; and anything that adds a timestamp, which
//! would make a golden test fail for a reason that has nothing to do with the
//! geometry.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::capability::{
    Audit, CapabilityReport, Claim, Emission, GfxId, Limitation, Origin, Probe, ProbeAnswer, Support,
    Verdict,
};
use crate::error::{BackendKind, GraphicsError};
use crate::measure::{TextAdvance, TextMeasurer, TextStyle};
use crate::paint::{
    Color, ColorFilter, Paint, Path, PorterDuffMode, Provenance, RectF,
};

/// Canonical float formatting.
///
/// Rust's `{:?}` for `f32` is the shortest representation that round-trips, which
/// is exactly what a byte-stable serialiser wants. Two things are normalised
/// first: `-0.0`, which is numerically `0.0` but not the same bytes and which
/// would otherwise make a diff depend on a sign a nobody set; and the
/// non-finite values, which no coordinate may be but which a caller can
/// arithmetic its way into.
pub fn q(v: f32) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    if v == f32::INFINITY {
        return "inf".to_string();
    }
    if v == f32::NEG_INFINITY {
        return "-inf".to_string();
    }
    if v == 0.0 {
        // Catches -0.0 as well as 0.0, and prints one byte for both.
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1.0e15 {
        // `{:?}` would print `1.0` where an integer coordinate is meant, and
        // `256.0` for a bitmask. Integral values print as integers so a display
        // list reads as the numbers a device would print, and so the same number
        // has exactly one spelling in every backend.
        return format!("{}", v as i64);
    }
    format!("{v:?}")
}

/// Quantise a dp value to 1/64 so a reported area is stable and readable.
///
/// Areas are a `f64` sum over many `f32` products; printing the raw `f64` gives
/// 17 significant digits of noise. 1/64 dp² is finer than any box edge the
/// shim's integer layout can produce, so quantising loses nothing real.
pub fn q_area(v: f64) -> String {
    if !v.is_finite() {
        return "nan".to_string();
    }
    let scaled = v * 64.0;
    if scaled.abs() < 9.0e15 {
        let r = (scaled as i64) as f64 / 64.0;
        if r == 0.0 {
            return "0".to_string();
        }
        return format!("{r}");
    }
    format!("{v}")
}

/// One text run, positioned. A positioned value rather than a `String` plus a
/// `Paint`, because the position *is* a finding: it is where a baseline landed
/// given an ascent this layer may have invented.
#[derive(Debug, Clone, PartialEq)]
pub struct TextRun {
    /// The view id this run belongs to, so a reader can tie a run to a box.
    pub id: String,
    pub text: String,
    /// Left edge, or the anchor, according to `style.align`.
    pub x: f32,
    /// Baseline, in the run's own coordinate space.
    pub baseline: f32,
    pub style: TextStyle,
    /// The measurement that positioned it, model id and provenance included.
    pub advance: TextAdvance,
}

impl TextRun {
    pub fn checked(&self) -> Result<(), GraphicsError> {
        for (what, v) in [("text x", self.x), ("text baseline", self.baseline)] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        self.style.checked()?;
        self.advance.checked()
    }
}

/// A bitmap handed to this layer, already decoded by whoever owns decoding.
///
/// `pixels` is `None` when the image was never decoded, which is the *only*
/// state this layer can reach on its own: there is no decoder here. When it is
/// `Some`, the bytes are `4 * width * height` RGBA8, and the SVG backend
/// **will not encode them** — there is no PNG encoder in this crate, and adding
/// one would mean this layer had produced pixels, which it has not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageBitmap {
    pub width: u32,
    pub height: u32,
    pub pixels: Option<Vec<u8>>,
}

impl ImageBitmap {
    /// A placeholder with no pixels: a real intrinsic size and nothing else.
    pub fn empty(width: u32, height: u32) -> ImageBitmap {
        ImageBitmap {
            width,
            height,
            pixels: None,
        }
    }

    pub fn checked(&self, id: &str) -> Result<(), GraphicsError> {
        if self.width == 0 || self.height == 0 {
            return Err(GraphicsError::BadBitmap {
                id: id.to_string(),
                width: self.width,
                height: self.height,
                bytes: self.pixels.as_ref().map_or(0, Vec::len),
            });
        }
        if let Some(px) = &self.pixels {
            let want = (self.width as usize)
                .saturating_mul(self.height as usize)
                .saturating_mul(4);
            if px.len() != want {
                return Err(GraphicsError::BadBitmap {
                    id: id.to_string(),
                    width: self.width,
                    height: self.height,
                    bytes: px.len(),
                });
            }
        }
        Ok(())
    }

    pub fn is_decoded(&self) -> bool {
        self.pixels.is_some()
    }
}

/// A placed image, as a draw call.
#[derive(Debug, Clone, PartialEq)]
pub struct ImageDraw {
    pub id: String,
    pub bitmap: ImageBitmap,
    /// Source rect in bitmap pixels, or `None` for the whole bitmap.
    pub src: Option<RectF>,
    /// Destination in the canvas's space.
    pub dst: RectF,
}

impl ImageDraw {
    pub fn checked(&self) -> Result<(), GraphicsError> {
        self.bitmap.checked(&self.id)?;
        RectF::checked(&self.dst)
    }
}

// ---------------------------------------------------------------------------
// Annotations: the visible meta-layer

/// `View.VISIBLE` and the other two, as the annotation records them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ViewState {
    #[default]
    Visible,
    Invisible,
    Gone,
}

impl ViewState {
    pub fn as_str(self) -> &'static str {
        match self {
            ViewState::Visible => "visible",
            ViewState::Invisible => "invisible",
            ViewState::Gone => "gone",
        }
    }
}

/// A non-ink step: something the reconstruction says *about itself*.
///
/// The separation is the point. Ink is a claim about what the screen would
/// hold; an annotation is a claim about the shim's box tree. Keeping them in
/// different variants means a count of fabricated ink can be taken without also
/// counting the reconstruction's own labels, and `tests/draw.rs` asserts that
/// the default pipeline has **zero** fabricated ink while producing plenty of
/// annotations.
#[derive(Debug, Clone, PartialEq)]
pub enum Annotation {
    /// An area the app's own drawing would have covered, for which there is no
    /// ink. The reason is a constant, so a reader cannot be told a story about
    /// it.
    UnknownInk {
        rect: RectF,
        reason: &'static str,
    },
    /// The boundary of a view, as the shim's tree has it. Drawn so boxes are
    /// countable by eye; **not** a claim that the app drew a border there.
    BoxOutline {
        id: String,
        rect: RectF,
        state: ViewState,
        kind: &'static str,
    },
    /// A `TextView`-shaped node whose characters the box tree withheld.
    TextWithheld {
        id: String,
        rect: RectF,
        chars: usize,
        /// Character-class counts, sorted by key because the shim hands them
        /// over in a `BTreeMap` and the sort is what makes this stable if that
        /// ever changes.
        classes: Vec<(String, usize)>,
        /// `email`, `phone`, `numeric`, joined with `+`, or `plain`.
        shape: String,
    },
    /// An `ImageView`-shaped node with no decoded bitmap.
    ImageAbsent {
        id: String,
        rect: RectF,
        reason: &'static str,
    },
    /// A decoded bitmap this layer cannot serialise. Distinct from
    /// `ImageAbsent`: the pixels *exist* upstream and this layer drops them,
    /// which is a different failure and a more interesting one.
    ImageNotEmbedded {
        id: String,
        rect: RectF,
        width: u32,
        height: u32,
    },
    /// A capability gap, recorded inline so a reader of the middle of a display
    /// list sees it rather than only the header.
    CapabilityNote {
        id: GfxId,
        text: String,
    },
    /// A free-form note.
    Note { text: String },
}

// ---------------------------------------------------------------------------
// Commands and steps

#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    Save,
    Restore,
    Translate {
        dx: f32,
        dy: f32,
    },
    Scale {
        sx: f32,
        sy: f32,
    },
    /// A clip. `effective` is the intersection of this rect with the clip
    /// already in force, computed at record time so a reader of the list can
    /// see what the consumer will actually use instead of having to replay the
    /// stack.
    ClipRect {
        rect: RectF,
        effective: RectF,
        antialias: bool,
    },
    ClipPath {
        path: Path,
        antialias: bool,
    },
    DrawColor {
        color: Color,
        mode: PorterDuffMode,
    },
    DrawRect {
        rect: RectF,
        paint: Box<Paint>,
    },
    DrawPath {
        path: Path,
        paint: Box<Paint>,
    },
    DrawTextRun {
        run: Box<TextRun>,
        paint: Box<Paint>,
    },
    DrawImage {
        img: Box<ImageDraw>,
        paint: Box<Paint>,
    },
    Annotate(Annotation),
}

impl Command {
    /// The operation name, which is also the first token of a display-list
    /// line.
    pub fn name(&self) -> &'static str {
        match self {
            Command::Save => "push",
            Command::Restore => "pop",
            Command::Translate { .. } => "translate",
            Command::Scale { .. } => "scale",
            Command::ClipRect { .. } => "clip-rect",
            Command::ClipPath { .. } => "clip-path",
            Command::DrawColor { .. } => "draw-color",
            Command::DrawRect { .. } => "draw-rect",
            Command::DrawPath { .. } => "draw-path",
            Command::DrawTextRun { .. } => "draw-text",
            Command::DrawImage { .. } => "draw-image",
            Command::Annotate(_) => "annotate",
        }
    }

    /// Does this command put ink on the surface?
    ///
    /// `false` for the transform and clip stack as well as for annotations: a
    /// `save` and a `clip-rect` change what later commands *may* affect, they do
    /// not themselves affect anything. Getting this wrong would let a frame with
    /// no drawing at all report ink coverage, which is the number this crate
    /// publishes.
    pub fn is_ink(&self) -> bool {
        !matches!(
            self,
            Command::Annotate(_)
                | Command::Save
                | Command::Restore
                | Command::Translate { .. }
                | Command::Scale { .. }
                | Command::ClipRect { .. }
                | Command::ClipPath { .. }
        )
    }
}

/// One command with its warranty attached.
///
/// A `Step` cannot be built without a `Provenance`, which is what makes "every
/// emitted value is labelled" a property of the type rather than a convention.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub provenance: Provenance,
    pub command: Command,
}

impl Step {
    /// Build a step with the provenance the command implies.
    pub fn new(command: Command) -> Step {
        let provenance = match &command {
            // The clip and transform stack is this layer's mechanism, driven by
            // the tree but not itself part of the tree.
            Command::Save
            | Command::Restore
            | Command::Translate { .. }
            | Command::Scale { .. }
            | Command::ClipRect { .. }
            | Command::ClipPath { .. } => Provenance::DerivedFromShimTree,
            _ => Provenance::Absent,
        };
        Step {
            provenance,
            command,
        }
    }

    /// Build a step with an explicit provenance, for the draw pass, which knows
    /// better than the default.
    pub fn with_provenance(provenance: Provenance, command: Command) -> Step {
        Step {
            provenance,
            command,
        }
    }
}

// ---------------------------------------------------------------------------
// The Canvas trait

/// What a backend must be able to do. The minimum a 2D `Canvas` can do, with
/// Android's method names where Android has one.
///
/// Every method returns `Result` because every method can fail: a coordinate
/// can be non-finite, a capability can be absent, a step budget can be spent.
/// There is no `unwrap` on this trait and no method that panics.
pub trait Canvas {
    /// Which surface this is. A recording has to name it, because "this is not
    /// supported" means something different for each.
    fn kind(&self) -> BackendKind;

    /// `Canvas.getClipBounds`.
    fn current_clip(&self) -> RectF;

    fn begin_frame(&mut self, viewport: RectF, density: f32) -> Result<(), GraphicsError>;

    fn save(&mut self) -> Result<(), GraphicsError>;
    fn restore(&mut self) -> Result<(), GraphicsError>;
    fn translate(&mut self, dx: f32, dy: f32) -> Result<(), GraphicsError>;
    fn scale(&mut self, sx: f32, sy: f32) -> Result<(), GraphicsError>;
    fn clip_rect(&mut self, r: RectF, antialias: bool) -> Result<(), GraphicsError>;
    fn clip_path(&mut self, p: &Path, antialias: bool) -> Result<(), GraphicsError>;

    /// `Canvas.drawColor`.
    fn draw_color(&mut self, c: Color, mode: PorterDuffMode) -> Result<(), GraphicsError>;
    /// `Canvas.drawRect`.
    fn draw_rect(&mut self, r: RectF, p: &Paint) -> Result<(), GraphicsError>;
    /// `Canvas.drawPath`.
    fn draw_path(&mut self, path: &Path, p: &Paint) -> Result<(), GraphicsError>;
    /// `Canvas.drawText`.
    fn draw_text_run(&mut self, run: &TextRun, p: &Paint) -> Result<(), GraphicsError>;
    /// `Canvas.drawBitmap`.
    fn draw_image(&mut self, img: &ImageDraw, p: &Paint) -> Result<(), GraphicsError>;
    /// A non-ink statement about the reconstruction.
    ///
    /// The caller supplies the [`Provenance`], because only the caller knows
    /// where the annotation's *values* came from. A `BoxOutline`'s rectangle is
    /// the shim's frame copied verbatim; an `UnknownInk`'s rectangle is this
    /// layer's statement that there is nothing there. Both are annotations and
    /// both are honest, and collapsing them onto one tag would lose the
    /// distinction the whole crate turns on.
    fn annotate(&mut self, a: Annotation, p: Provenance) -> Result<(), GraphicsError>;

    /// Answer a substrate-capability question. The default is `Absent` for
    /// everything except text measurement, which the default measurer can
    /// partially answer; a backend that overrides it is making a claim the
    /// report will audit.
    fn probe(&self, probe: &Probe) -> ProbeAnswer;
}

// ---------------------------------------------------------------------------
// Claims: what a backend says about itself before it is checked

/// The headless backend's claims. Ten absences and one substitution.
///
/// Every one of these is a *claim*, checked against a live probe by
/// [`CapabilityReport::audit`]. The reasons are phrased for a banner: they say
/// what is missing, not merely that something is.
pub fn headless_claims() -> Vec<Claim> {
    vec![
        Claim {
            id: GfxId::EglContext,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no GPU context: this layer emits a text serialisation, not a drawing",
        },
        Claim {
            id: GfxId::GlesVersion,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no GLES to ask; reporting a version would fabricate a capability probe",
        },
        Claim {
            id: GfxId::Vulkan,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no Vulkan instance; WebGPU is not an equivalent and is not claimed as one",
        },
        Claim {
            id: GfxId::Extensions,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no extension string: an empty one is read as \"nothing supported\" and a wrong one is a lie",
        },
        Claim {
            id: GfxId::RendererString,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no GPU string emitted; the host's would be a fingerprinting side channel and not the device's anyway",
        },
        Claim {
            id: GfxId::Surface,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no Surface/BufferQueue; bitmaps reach here undecoded, and this layer cannot encode them either",
        },
        Claim {
            id: GfxId::HwComposition,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no compositor: writing a display list is not presenting a frame",
        },
        Claim {
            id: GfxId::FrameBudget,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no vsync and no deadline; 16.7 ms would be a fabricated number, so none is reported",
        },
        Claim {
            id: GfxId::ScreenOn,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no PowerManager: a tab has no screen to be on or off",
        },
        Claim {
            id: GfxId::CameraPipe,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "no camera HAL and no camera2 pipeline",
        },
        Claim {
            id: GfxId::TextRender,
            verdict: Verdict::Substituted,
            emission: Emission::Substituted,
            origin: Origin::Fabricated,
            note: "runs can be emitted, but no font is loaded: advances and baselines are this layer's",
        },
    ]
}

// ---------------------------------------------------------------------------
// Display list

/// The viewport a display list was recorded against.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Viewport {
    /// In dp. The shim lays out in dp and this layer does not rescale the
    /// geometry, so the numbers here are the shim's numbers.
    pub width_dp: f32,
    pub height_dp: f32,
    /// dp to device pixels. `1.0` for the shim's own coordinate space, which is
    /// what `DisplayMetrics.density == 1.0` means. Recorded because a display
    /// list at density 2 is not the same artefact as one at density 1, and
    /// conflating them would make two captures non-comparable.
    pub density: f32,
}

impl Viewport {
    pub fn px_width(&self) -> f32 {
        self.width_dp * self.density
    }
    pub fn px_height(&self) -> f32 {
        self.height_dp * self.density
    }
    pub fn rect(&self) -> RectF {
        RectF::new(0.0, 0.0, self.width_dp, self.height_dp)
    }
    pub fn checked(&self) -> Result<(), GraphicsError> {
        if self.width_dp < 0.0 || self.height_dp < 0.0 || self.density <= 0.0 {
            return Err(GraphicsError::BadViewport {
                width: self.width_dp,
                height: self.height_dp,
                density: self.density,
            });
        }
        if !self.px_width().is_finite() || !self.px_height().is_finite() {
            return Err(GraphicsError::BadViewport {
                width: self.width_dp,
                height: self.height_dp,
                density: self.density,
            });
        }
        Ok(())
    }
}

/// Counts the header reports, all of them derivable from the steps and all of
/// them recomputed by the tests from the serialised bytes rather than trusted.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct ListCounts {
    pub steps: usize,
    pub by_provenance: [usize; 4],
    pub ink_steps: usize,
    pub ink_fabricated: usize,
    pub annotations: usize,
    pub text_runs: usize,
    pub text_withheld: usize,
    pub withheld_chars: usize,
    pub images_drawn: usize,
    pub images_absent: usize,
    pub clip_regions: usize,
    /// dp² of area the shim's boxes cover, counting overlaps as the shim's own
    /// `leaf_area` does. Copied from the tree by `draw.rs`.
    pub leaf_area_dp2: u64,
    /// dp² of area with no ink, over **leaf** boxes only, so it is
    /// commensurable with `leaf_area_dp2`. The shim's own `leaf_area` sums
    /// leaves, and a coverage fraction whose two sides measure different things
    /// is arithmetic rather than observation.
    pub unknown_ink_dp2: f64,
}

impl ListCounts {
    /// The fraction of leaf area with no ink, in `0.0..=1.0`. `1.0` is the
    /// default pipeline, and that is the number worth publishing.
    pub fn ink_coverage(&self) -> f64 {
        let total = self.leaf_area_dp2 as f64;
        if total <= 0.0 {
            return 0.0;
        }
        let unknown = self.unknown_ink_dp2.max(0.0);
        (1.0 - unknown / total).clamp(0.0, 1.0)
    }
}

/// The serialisable record of one pass.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayList {
    pub viewport: Viewport,
    /// The measure model's id, copied so a reader never has to guess which
    /// seam produced the advances.
    pub measure_model: String,
    /// What characters reached the draw pass. `withheld` is the default and is
    /// the common case, because the shim's `TextPolicy::ShapeOnly` never puts a
    /// character in a tree.
    pub text_policy: &'static str,
    pub capability: CapabilityReport,
    pub counts: ListCounts,
    /// The sentence a reader could be shown instead of the image.
    pub banner: String,
    pub steps: Vec<Step>,
}

impl DisplayList {
    /// Canonical, byte-stable text form.
    ///
    /// This is the artefact `tests/golden.rs` compares. Line order is step
    /// order, the header is a fixed set of keys in a fixed order, and every
    /// value is formatted by [`q`] or by an integer.
    pub fn to_text(&self) -> String {
        let mut s = String::with_capacity(1024 + self.steps.len() * 64);
        s.push_str("!display-list/1\n");
        let _ = writeln!(s, "#generator=runtime::graphics");
        let _ = writeln!(s, "#provenance=RECONSTRUCTION-OF-SHIM-BOX-TREE");
        let _ = writeln!(s, "#this-is=NOT-ANDROID");
        let _ = writeln!(s, "#app-draw-code-executed=false");
        let _ = writeln!(s, "#banner={}", self.banner);
        let _ = writeln!(
            s,
            "#geometry-origin=shim::layout::BoxNode (exact relative to the shim, not to a device)"
        );
        let _ = writeln!(s, "#measure-model={}", self.measure_model);
        let _ = writeln!(s, "#text-policy={}", self.text_policy);
        let _ = writeln!(
            s,
            "#viewport-dp={}x{}",
            q(self.viewport.width_dp),
            q(self.viewport.height_dp)
        );
        let _ = writeln!(s, "#density={}", q(self.viewport.density));
        let c = &self.counts;
        let _ = writeln!(s, "#steps={}", c.steps);
        let _ = writeln!(
            s,
            "#prov shim-exact={} derived={} fabricated={} absent={}",
            c.by_provenance[0], c.by_provenance[1], c.by_provenance[2], c.by_provenance[3]
        );
        let _ = writeln!(s, "#ink-steps={}", c.ink_steps);
        let _ = writeln!(s, "#ink-fabricated={}", c.ink_fabricated);
        let _ = writeln!(s, "#annotations={}", c.annotations);
        let _ = writeln!(s, "#text-runs={}", c.text_runs);
        let _ = writeln!(s, "#text-withheld={}", c.text_withheld);
        let _ = writeln!(s, "#withheld-chars={}", c.withheld_chars);
        let _ = writeln!(s, "#images-drawn={}", c.images_drawn);
        let _ = writeln!(s, "#images-absent={}", c.images_absent);
        let _ = writeln!(s, "#clip-regions={}", c.clip_regions);
        let _ = writeln!(s, "#leaf-area-dp2={}", c.leaf_area_dp2);
        let _ = writeln!(s, "#unknown-ink-dp2={}", q_area(c.unknown_ink_dp2));
        let _ = writeln!(s, "#ink-coverage={:.4}", c.ink_coverage());
        let _ = writeln!(
            s,
            "#gfx-ids-total={}",
            GfxId::ALL.len()
        );
        let _ = writeln!(s, "#gfx-reproduced={}", self.capability.reproduced());
        let _ = writeln!(
            s,
            "#gfx-observed-satisfied={}",
            self.capability.observed_satisfied()
        );
        let _ = writeln!(
            s,
            "#report-audit-mismatches={}",
            self.capability.audit.mismatches.len()
        );
        let _ = writeln!(s, "!capability backend={}", self.capability.backend);
        s.push_str(&self.capability.to_text());
        s.push_str("!end-capability\n");
        let _ = writeln!(
            s,
            "!frame dp={}x{} density={}",
            q(self.viewport.width_dp),
            q(self.viewport.height_dp),
            q(self.viewport.density)
        );
        for (i, st) in self.steps.iter().enumerate() {
            let _ = writeln!(s, "  {i} {} {}", st.command.name(), step_body(st));
        }
        s.push_str("!end-frame\n");
        s
    }

    /// A short, quotable summary. Used by the tests and by anything that wants
    /// the story without the bytes.
    pub fn summary(&self) -> String {
        format!(
            "{} steps ({} ink, {} of them fabricated), {} withheld text runs covering \
             {:.1}% of the leaf area, {} reproduced of {} SUB.GFX assumptions",
            self.counts.steps,
            self.counts.ink_steps,
            self.counts.ink_fabricated,
            self.counts.text_withheld,
            (1.0 - self.counts.ink_coverage()) * 100.0,
            self.capability.reproduced(),
            GfxId::ALL.len()
        )
    }

    /// The audit, recomputed against a live backend. A caller that has the
    /// backend can re-verify the report the list carries; a caller that has
    /// only the list can see the mismatch count in the header and nothing else,
    /// which is the intended asymmetry.
    pub fn audit_against(&self, probe: impl Fn(&Probe) -> ProbeAnswer) -> Audit {
        CapabilityReport::audit(
            self.capability.backend,
            &headless_claims(),
            self.capability.limitations.clone(),
            probe,
        )
        .audit
    }
}

/// The body of a display-list line, without the operation name and without the
/// leading indent. Public so `tests/golden.rs` can re-derive counts from the
/// text without reimplementing the formatter.
pub fn step_body(step: &Step) -> String {
    let mut s = String::new();
    match &step.command {
        Command::Save | Command::Restore => {}
        Command::Translate { dx, dy } => {
            let _ = write!(s, "dx={} dy={}", q(*dx), q(*dy));
        }
        Command::Scale { sx, sy } => {
            let _ = write!(s, "sx={} sy={}", q(*sx), q(*sy));
        }
        Command::ClipRect {
            rect,
            effective,
            antialias,
        } => {
            let _ = write!(
                s,
                "rect={} effective={} aa={}",
                rect,
                effective,
                if *antialias { 1 } else { 0 }
            );
        }
        Command::ClipPath { path, antialias } => {
            let _ = write!(s, "ops={} aa={}", path.len(), if *antialias { 1 } else { 0 });
        }
        Command::DrawColor { color, mode } => {
            let _ = write!(s, "color={} mode={}", color, mode);
        }
        Command::DrawRect { rect, paint } => {
            let _ = write!(s, "rect={} paint={}", rect, paint_token(paint));
        }
        Command::DrawPath { path, paint } => {
            let _ = write!(s, "ops={} paint={}", path.len(), paint_token(paint));
        }
        Command::DrawTextRun { run, paint } => {
            let _ = write!(
                s,
                "id={} x={} baseline={} advance={} lines={} ascent={} model={} mprov={} \
                 size_sp={} family={} align={} chars={} digest={} paint={}",
                escape_token(&run.id),
                q(run.x),
                q(run.baseline),
                q(run.advance.advance_x),
                run.advance.lines,
                q(run.advance.ascent),
                quote(&run.advance.model),
                run.advance.provenance,
                q(run.style.size_sp),
                escape_token(&run.style.typeface.to_css_family()),
                run.style.align.as_str(),
                run.text.chars().count(),
                digest(&run.text),
                paint_token(paint)
            );
        }
        Command::DrawImage { img, paint } => {
            let _ = write!(
                s,
                "id={} src={} dst={} decoded={} bitmap={}x{} paint={}",
                escape_token(&img.id),
                img.src.map_or_else(|| "-".to_string(), |r| r.to_string()),
                img.dst,
                u8::from(img.bitmap.is_decoded()),
                img.bitmap.width,
                img.bitmap.height,
                paint_token(paint)
            );
        }
        Command::Annotate(a) => {
            let _ = write!(s, "{}", annotation_token(a));
        }
    }
    let _ = write!(s, " prov={}", step.provenance);
    s
}

/// A paint, in one line. A shader's stops are included: a gradient's stops are
/// values, and a display list that omitted them would not be diffable.
pub fn paint_token(p: &Paint) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "style={} color={} aa={} sw={} cap={} join={} miter={} shader={} xfer={} cf={} \
         tsize={} tfamily={} talign={} spacing={} bold={}",
        p.style.as_str(),
        p.color,
        u8::from(p.anti_alias),
        q(p.stroke_width),
        p.stroke_cap.as_str(),
        p.stroke_join.as_str(),
        q(p.stroke_miter),
        shader_token(p.shader.as_ref()),
        p.effective_xfermode(),
        p.color_filter.kind(),
        q(p.text_size),
        escape_token(&p.typeface.to_css_family()),
        p.text_align.as_str(),
        q(p.letter_spacing),
        u8::from(p.fake_bold_text)
    );
    s
}

fn shader_token(s: Option<&ShaderRef>) -> String {
    match s {
        None => "none".to_string(),
        Some(sh) => match sh {
            crate::paint::Shader::Solid(c) => format!("solid({c})"),
            crate::paint::Shader::Linear {
                x0, y0, x1, y1, tile, ..
            } => format!(
                "linear({},{}->{},{} tile={})",
                q(*x0),
                q(*y0),
                q(*x1),
                q(*y1),
                tile.as_str()
            ),
            crate::paint::Shader::Radial {
                cx, cy, radius, fx, fy, tile, ..
            } => format!(
                "radial(c={},{} r={} focus={},{} tile={})",
                q(*cx),
                q(*cy),
                q(*radius),
                q(*fx),
                q(*fy),
                tile.as_str()
            ),
        },
    }
}

/// An alias so the signature above reads well.
type ShaderRef = crate::paint::Shader;

fn annotation_token(a: &Annotation) -> String {
    let mut s = String::new();
    match a {
        Annotation::UnknownInk { rect, reason } => {
            let _ = write!(s, "unknown-ink rect={} reason={}", rect, quote(reason));
        }
        Annotation::BoxOutline { id, rect, state, kind } => {
            let _ = write!(
                s,
                "box-outline id={} rect={} state={} kind={}",
                escape_token(id),
                rect,
                state.as_str(),
                kind
            );
        }
        Annotation::TextWithheld {
            id,
            rect,
            chars,
            classes,
            shape,
        } => {
            let cls: Vec<String> = classes
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            let _ = write!(
                s,
                "text-withheld id={} rect={} chars={} classes={} shape={}",
                escape_token(id),
                rect,
                chars,
                if cls.is_empty() {
                    "-".to_string()
                } else {
                    cls.join(",")
                },
                shape
            );
        }
        Annotation::ImageAbsent { id, rect, reason } => {
            let _ = write!(
                s,
                "image-absent id={} rect={} reason={}",
                escape_token(id),
                rect,
                quote(reason)
            );
        }
        Annotation::ImageNotEmbedded {
            id,
            rect,
            width,
            height,
        } => {
            let _ = write!(
                s,
                "image-not-embedded id={} rect={} bitmap={}x{}",
                escape_token(id),
                rect,
                width,
                height
            );
        }
        Annotation::CapabilityNote { id, text } => {
            let _ = write!(s, "capability id={} text={}", id.assumption(), quote(text));
        }
        Annotation::Note { text } => {
            let _ = write!(s, "note text={}", quote(text));
        }
    }
    s
}

/// A short, deterministic digest of a string, for a display list that must
/// identify text without holding it.
///
/// **The characters are not in the list.** A recording is a file that gets
/// attached to a study, and a login field's contents have no business being in
/// one; the shim's `TextPolicy` exists for the same reason. But a list that
/// cannot say *which* string it laid out cannot be diffed either, and
/// `TextPolicy::Include` means the caller deliberately decided this input was
/// synthetic.
///
/// So: a 64-bit FNV-1a over the UTF-8, printed as sixteen hex digits. It is not
/// a security hash and is not one — it identifies a string for a diff, and a
/// reader who wants the characters has the tree they passed in. Two strings with
/// the same digest but different content would compare equal, which is the
/// documented limit and the reason the caller is told this is a digest and not
/// an identity.
pub fn digest(s: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Quote a free-text field so it can contain spaces and still be one field.
///
/// The split from [`escape_token`] is deliberate. An **identifier** — a view id,
/// a model id — is arbitrary Unicode from an APK, is used unquoted, and so has
/// every space replaced. A **human-readable clause** — an annotation's reason, a
/// capability's note — is a `&'static str` this crate wrote, is meant to be read
/// by a person reading the artefact, and is quoted instead. Escaping the spaces
/// out of a sentence turns the golden files into noise for no safety gain, and a
/// golden file nobody can read is a golden file nobody will notice has changed.
///
/// A quote, a backslash, a newline or a control character is still escaped, so
/// the output stays line-oriented and attribute-safe.
pub fn quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\x{:02x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Make an untrusted string safe as one whitespace-delimited token.
///
/// A view id or a reason string comes from an APK. A space would break the
/// line format; a newline would break the file. Both are escaped, so the format
/// stays line-oriented and token-oriented for arbitrary Unicode.
pub fn escape_token(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            // A space becomes U+0001, which cannot occur in a view id a human
            // would write and cannot occur in a line-oriented format at all. The
            // mapping is documented on the function.
            ' ' => out.push('\u{1}'),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Headless backend

/// The recording backend. Turns calls into a [`DisplayList`] and rasterises
/// nothing.
///
/// The name is the honest one: it is not a renderer, it is a recorder. Its
/// capability report is the one that matters, because the display list is what
/// ends up in a recording.
pub struct HeadlessCanvas {
    steps: Vec<Step>,
    clip_stack: Vec<RectF>,
    viewport: Viewport,
    density: f32,
    step_limit: usize,
    measure: Option<TextAdvance>,
    steps_over_limit: bool,
    // Limits carried in from `draw.rs` so the header can report them.
    leaf_area_dp2: u64,
    text_policy: &'static str,
}

impl std::fmt::Debug for HeadlessCanvas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeadlessCanvas")
            .field("steps", &self.steps.len())
            .field("viewport", &self.viewport)
            .field("clip_depth", &self.clip_stack.len())
            .finish()
    }
}

impl HeadlessCanvas {
    pub fn new() -> HeadlessCanvas {
        HeadlessCanvas {
            steps: Vec::new(),
            clip_stack: vec![RectF::new(0.0, 0.0, 0.0, 0.0)],
            viewport: Viewport {
                width_dp: 0.0,
                height_dp: 0.0,
                density: 1.0,
            },
            density: 1.0,
            step_limit: 1_000_000,
            measure: None,
            steps_over_limit: false,
            leaf_area_dp2: 0,
            text_policy: "withheld",
        }
    }

    /// A pathological tree must not allocate without limit. The default is a
    /// million steps, which is far above any real screen.
    pub fn set_step_limit(&mut self, limit: usize) {
        self.step_limit = limit;
    }

    /// Set the measurement whose model id and provenance go in the header.
    pub fn set_measure(&mut self, m: Option<&TextAdvance>) {
        self.measure = m.cloned();
    }

    /// The shim's `leaf_area` is an `i64`; [`crate::draw::draw_tree`] saturates
    /// it at zero before it gets here, so this layer never has to.
    pub fn set_leaf_area(&mut self, dp2: u64) {
        self.leaf_area_dp2 = dp2;
    }

    pub fn set_text_policy(&mut self, p: &'static str) {
        self.text_policy = p;
    }

    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    fn push(&mut self, s: Step) -> Result<(), GraphicsError> {
        if self.steps.len() >= self.step_limit {
            self.steps_over_limit = true;
            return Err(GraphicsError::TooManySteps {
                steps: self.steps.len() + 1,
                limit: self.step_limit,
            });
        }
        self.steps.push(s);
        Ok(())
    }

    /// Recompute every count from the steps. Called by [`Self::finish`], and
    /// recomputed independently in the tests from the serialised bytes.
    pub fn counts(&self) -> ListCounts {
        let mut c = ListCounts {
            leaf_area_dp2: self.leaf_area_dp2,
            ..ListCounts::default()
        };
        let mut unknown = 0.0f64;
        for st in &self.steps {
            c.steps += 1;
            let pi = match st.provenance {
                Provenance::ShimTreeExact => 0,
                Provenance::DerivedFromShimTree => 1,
                Provenance::Fabricated => 2,
                Provenance::Absent => 3,
            };
            c.by_provenance[pi] += 1;
            if st.command.is_ink() {
                c.ink_steps += 1;
                if st.provenance == Provenance::Fabricated {
                    c.ink_fabricated += 1;
                }
            } else if matches!(st.command, Command::Annotate(_)) {
                // The transform and clip stack is neither ink nor an annotation;
                // counting it as an annotation would make the annotation count a
                // statement about the reconstruction when it is a statement about
                // the walk.
                c.annotations += 1;
            }
            match &st.command {
                Command::ClipRect { .. } | Command::ClipPath { .. } => c.clip_regions += 1,
                Command::DrawTextRun { .. } => c.text_runs += 1,
                Command::DrawImage { .. } => c.images_drawn += 1,
                Command::Annotate(Annotation::TextWithheld { chars, .. }) => {
                    c.text_withheld += 1;
                    c.withheld_chars = c.withheld_chars.saturating_add(*chars);
                }
                Command::Annotate(Annotation::ImageAbsent { .. }) => c.images_absent += 1,
                Command::Annotate(Annotation::UnknownInk { rect, .. }) => {
                    unknown += rect.area();
                }
                _ => {}
            }
        }
        c.unknown_ink_dp2 = unknown;
        c
    }

    /// The text model id for the header.
    pub fn measure_model(&self) -> String {
        self.measure
            .as_ref()
            .map(|a| a.model.clone())
            .unwrap_or_else(|| "none".to_string())
    }

    /// Seal the list, with the report audited against this backend's own live
    /// probes. The audit happens *here*, so a list that ships with a wrong claim
    /// ships with the disagreement written into its header.
    pub fn finish(self, banner_extra: &str) -> DisplayList {
        let report = CapabilityReport::audit(
            BackendKind::Headless,
            &headless_claims(),
            headless_limitations(),
            |p| self.probe(p),
        );
        let counts = self.counts();
        let banner = report.banner(&join_banner(banner_extra, &counts, &self));
        DisplayList {
            viewport: self.viewport,
            measure_model: self.measure_model(),
            text_policy: self.text_policy,
            capability: report,
            counts,
            banner,
            steps: self.steps,
        }
    }
}

fn join_banner(extra: &str, counts: &ListCounts, c: &HeadlessCanvas) -> String {
    let mut parts: Vec<String> = Vec::new();
    if !extra.is_empty() {
        parts.push(extra.to_string());
    }
    parts.push(format!(
        "no ink for {:.1}% of the shim's leaf area",
        (1.0 - counts.ink_coverage()) * 100.0
    ));
    if counts.ink_fabricated > 0 {
        parts.push(format!(
            "{} ink step(s) fabricated by this layer",
            counts.ink_fabricated
        ));
    }
    if counts.text_withheld > 0 {
        parts.push(format!(
            "{} text run(s) withheld by the shim's TextPolicy",
            counts.text_withheld
        ));
    }
    if let Some(m) = &c.measure {
        if m.provenance == Provenance::Fabricated {
            parts.push(format!("text measured by {}", m.model));
        }
    }
    parts.join("; ")
}

impl Default for HeadlessCanvas {
    fn default() -> Self {
        HeadlessCanvas::new()
    }
}

impl Canvas for HeadlessCanvas {
    fn kind(&self) -> BackendKind {
        BackendKind::Headless
    }

    fn current_clip(&self) -> RectF {
        self.clip_stack.last().copied().unwrap_or_default()
    }

    fn begin_frame(&mut self, viewport: RectF, density: f32) -> Result<(), GraphicsError> {
        RectF::checked(&viewport)?;
        if density <= 0.0 || !density.is_finite() {
            return Err(GraphicsError::BadViewport {
                width: viewport.width(),
                height: viewport.height(),
                density,
            });
        }
        self.viewport = Viewport {
            width_dp: viewport.width(),
            height_dp: viewport.height(),
            density,
        };
        self.density = density;
        self.clip_stack = vec![viewport];
        Ok(())
    }

    fn save(&mut self) -> Result<(), GraphicsError> {
        self.push(Step::new(Command::Save))
    }

    fn restore(&mut self) -> Result<(), GraphicsError> {
        if self.clip_stack.len() > 1 {
            self.clip_stack.pop();
        }
        self.push(Step::new(Command::Restore))
    }

    fn translate(&mut self, dx: f32, dy: f32) -> Result<(), GraphicsError> {
        for (what, v) in [("dx", dx), ("dy", dy)] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        self.push(Step::new(Command::Translate { dx, dy }))
    }

    fn scale(&mut self, sx: f32, sy: f32) -> Result<(), GraphicsError> {
        for (what, v) in [("sx", sx), ("sy", sy)] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        self.push(Step::new(Command::Scale { sx, sy }))
    }

    fn clip_rect(&mut self, r: RectF, antialias: bool) -> Result<(), GraphicsError> {
        RectF::checked(&r)?;
        let effective = self.current_clip().intersect(&r);
        self.clip_stack.push(effective);
        self.push(Step::new(Command::ClipRect {
            rect: r,
            effective,
            antialias,
        }))
    }

    fn clip_path(&mut self, p: &Path, antialias: bool) -> Result<(), GraphicsError> {
        p.checked()?;
        // A path clip's extent is its control-point bounds, intersected with
        // what is already in force. A conservative bound is what Skia reports
        // too; the difference is invisible in a display list and honest here.
        let effective = self.current_clip().intersect(&p.bounds());
        self.clip_stack.push(effective);
        self.push(Step::new(Command::ClipPath {
            path: p.clone(),
            antialias,
        }))
    }

    fn draw_color(&mut self, c: Color, mode: PorterDuffMode) -> Result<(), GraphicsError> {
        self.push(Step::with_provenance(
            Provenance::Fabricated,
            Command::DrawColor { color: c, mode },
        ))
    }

    fn draw_rect(&mut self, r: RectF, p: &Paint) -> Result<(), GraphicsError> {
        RectF::checked(&r)?;
        p.checked()?;
        if !self.intersects_clip(&r) {
            return Ok(());
        }
        self.push(Step::with_provenance(
            Provenance::Fabricated,
            Command::DrawRect {
                rect: r,
                paint: Box::new(p.clone()),
            },
        ))
    }

    fn draw_path(&mut self, path: &Path, p: &Paint) -> Result<(), GraphicsError> {
        path.checked()?;
        p.checked()?;
        if !self.intersects_clip(&path.bounds()) {
            return Ok(());
        }
        self.push(Step::with_provenance(
            Provenance::Fabricated,
            Command::DrawPath {
                path: path.clone(),
                paint: Box::new(p.clone()),
            },
        ))
    }

    fn draw_text_run(&mut self, run: &TextRun, p: &Paint) -> Result<(), GraphicsError> {
        run.checked()?;
        p.checked()?;
        // A run measured by the zero measurer occupies no width, so its box is
        // empty and the run is dropped. That is not an optimisation: it is the
        // same statement the measurement made, applied consistently.
        let w = run.advance.advance_x;
        let h = run.advance.advance_y;
        let box_ = RectF::new(run.x, run.baseline - run.advance.ascent, run.x + w, run.baseline + h);
        if !self.intersects_clip(&box_) {
            return Ok(());
        }
        self.push(Step::with_provenance(
            run.advance.provenance,
            Command::DrawTextRun {
                run: Box::new(run.clone()),
                paint: Box::new(p.clone()),
            },
        ))
    }

    fn draw_image(&mut self, img: &ImageDraw, p: &Paint) -> Result<(), GraphicsError> {
        img.checked()?;
        p.checked()?;
        if !self.intersects_clip(&img.dst) {
            return Ok(());
        }
        self.push(Step::with_provenance(
            Provenance::Fabricated,
            Command::DrawImage {
                img: Box::new(img.clone()),
                paint: Box::new(p.clone()),
            },
        ))
    }

    fn annotate(&mut self, a: Annotation, p: Provenance) -> Result<(), GraphicsError> {
        self.push(Step::with_provenance(p, Command::Annotate(a)))
    }

    fn probe(&self, probe: &Probe) -> ProbeAnswer {
        probe_answer(probe)
    }
}

impl HeadlessCanvas {
    fn intersects_clip(&self, r: &RectF) -> bool {
        // Strict overlap. A zero-area rectangle does not overlap anything, which
        // is what makes a zero-advance text run vanish and is also the platform's
        // behaviour for a zero-sized draw.
        r.intersects(&self.current_clip())
    }
}

/// The honest answer to every probe this layer can be asked, from any backend
/// built on it.
///
/// Ten absences and one substitution, and the substitution's value is a real
/// number so a reader can check it against their own. The number comes from
/// whatever measurer is in use; with the default that is zero.
pub fn probe_answer(probe: &Probe) -> ProbeAnswer {
    match probe {
        Probe::ContextCreation => ProbeAnswer::Absent {
            reason: "no GPU context is created by a serialising backend",
        },
        Probe::GlesVersion => ProbeAnswer::Absent {
            reason: "there is no GLES implementation to report a version from",
        },
        Probe::VulkanVersion => ProbeAnswer::Absent {
            reason: "there is no Vulkan implementation to report a version from",
        },
        Probe::GlExtensions => ProbeAnswer::Absent {
            reason: "no extension string exists; an empty one is indistinguishable from none",
        },
        Probe::GlRenderer => ProbeAnswer::Absent {
            reason: "no GPU string is emitted; the host's is not the device's and is a side channel",
        },
        Probe::Surface => ProbeAnswer::Absent {
            reason: "no Surface, SurfaceTexture or BufferQueue exists here",
        },
        Probe::HardwareCompositor => ProbeAnswer::Absent {
            reason: "there is no compositor: writing a list is not presenting a frame",
        },
        Probe::FrameBudget => ProbeAnswer::Absent {
            reason: "no vsync and no deadline, so no budget can be reported without inventing one",
        },
        Probe::ScreenOn => ProbeAnswer::Absent {
            reason: "a browser tab has no screen state to report",
        },
        Probe::CameraPipeline => ProbeAnswer::Absent {
            reason: "there is no camera HAL and no camera2 pipeline",
        },
        Probe::TextAdvance { sample, size_sp } => {
            // A number, and its model, so the claim is checkable.
            let style = crate::measure::TextStyle::at(*size_sp);
            let m = crate::measure::UniformMeasurer::new();
            match m.measure(sample, &style) {
                Ok(a) => ProbeAnswer::Substituted {
                    emission: Emission::Substituted,
                    origin: Origin::Fabricated,
                    value: format!("advance={} for {sample:?} at {size_sp}sp", q(a.advance_x)),
                    reason: "measured by a stub advance model, not by a loaded font",
                },
                Err(e) => ProbeAnswer::Absent {
                    reason: "the measurement seam refused",
                }
                .with_error(&e),
            }
        }
    }
}

/// Small helper so the `Err` arm of the probe can carry the error without a
/// second field on `ProbeAnswer::Absent`, whose shape is a clause and a string.
trait WithError {
    fn with_error(self, e: &GraphicsError) -> Self;
}

impl WithError for ProbeAnswer {
    fn with_error(self, e: &GraphicsError) -> Self {
        match self {
            ProbeAnswer::Absent { reason } => {
                // `reason` is a `&'static str`, so the error cannot be inlined.
                // The refusal clause stays static and the error is recorded in
                // the value slot by widening to `Substituted` only if it is
                // genuinely informative; a refusal is not a substitution, so the
                // static clause is kept and the error is dropped with a note.
                debug_assert!(!e.kind().is_empty());
                ProbeAnswer::Absent { reason }
            }
            other => other,
        }
    }
}

/// The headless backend's per-feature table.
pub fn headless_limitations() -> Vec<Limitation> {
    let mut v = vec![
        Limitation {
            feature: "rasterisation",
            instance: "",
            support: Support::Absent,
            note: "a display list is emitted; no pixel is computed, so 'absent' means the backend draws nothing",
        },
        Limitation {
            feature: "porter-duff-mode",
            instance: "all",
            support: Support::Recorded,
            note: "all 21 modes are recorded verbatim; recording is not compositing",
        },
        Limitation {
            feature: "color-filter",
            instance: "PorterDuffColorFilter",
            support: Support::Recorded,
            note: "recorded, not applied",
        },
        Limitation {
            feature: "shader",
            instance: "solid/linear/radial",
            support: Support::Recorded,
            note: "recorded with stops, not evaluated",
        },
        Limitation {
            feature: "shader",
            instance: "BitmapShader",
            support: Support::Absent,
            note: "no codec in this layer; a grey stand-in would be a plausible fabrication",
        },
        Limitation {
            feature: "color-filter",
            instance: "ColorMatrixColorFilter",
            support: Support::Absent,
            note: "a truncated 4x5 matrix produces confidently wrong colours",
        },
        Limitation {
            feature: "text",
            instance: "font metrics",
            support: Support::Absent,
            note: "no font is loaded; the default measurer reports a zero advance rather than a guess",
        },
        Limitation {
            feature: "antialiasing",
            instance: "edges and glyphs",
            support: Support::Absent,
            note: "no rasteriser, so the flag is recorded and its effect is neither reproduced nor claimed",
        },
    ];
    for m in PorterDuffMode::ALL {
        v.push(Limitation {
            feature: "porter-duff-mode",
            instance: m.as_str(),
            support: Support::Recorded,
            note: "recorded verbatim",
        });
    }
    v
}

// ---------------------------------------------------------------------------
// Canvas2D backend: per-mode expressibility, measured by enumeration

/// What a browser's `globalCompositeOperation` can do with a `PorterDuff.Mode`.
///
/// **This is the one place the two backends' capabilities are actually
/// different, so it is the one place the numbers are worth reading.**
///
/// - The twelve classic Porter-Duff operators map one-to-one onto Compositing 1
///   operators of the same name, which is the mapping the HTML specification
///   gives explicitly. `DST` has no operator — there is no way to ask a canvas
///   for "just the old content".
/// - `ADD` maps to `lighter`, which is Porter-Duff `ADD` with the sum clamped
///   per channel. Skia's `ADD` also clamps. Same name, same rule.
/// - The six separable blend modes map to Compositing operators of the same
///   name, but the two specifications disagree about the alpha handling:
///   Compositing blends premultiplied channels, and Skia's `SkBlendMode` for the
///   same name blends *unpremultiplied* colour and combines alpha separately.
///   They agree on opaque input and diverge on translucent input. So they are
///   `Substituted`, never `Exact`, and the note says why.
pub fn canvas2d_mode(mode: PorterDuffMode) -> Option<(&'static str, Support)> {
    use PorterDuffMode as M;
    Some(match mode {
        M::Clear => ("copy", Support::Exact),
        // `SRC` is not a blend-mode question at all: Compositing 1 has no
        // operator that keeps only the source, so the nearest one is
        // `source-over`, which is a *different operator*. The ink survives that
        // the app never asked to erase. Handled separately in `apply_xfermode`
        // so the comment says so.
        M::Src => ("source-over", Support::Substituted),
        M::Dst => return None,
        M::SrcOver => ("source-over", Support::Exact),
        M::DstOver => ("destination-over", Support::Exact),
        M::SrcIn => ("source-in", Support::Exact),
        M::DstIn => ("destination-in", Support::Exact),
        M::SrcOut => ("source-out", Support::Exact),
        M::DstOut => ("destination-out", Support::Exact),
        M::SrcAtop => ("source-atop", Support::Exact),
        M::DstAtop => ("destination-atop", Support::Exact),
        M::Xor => ("xor", Support::Exact),
        M::Add => ("lighter", Support::Exact),
        M::Multiply => ("multiply", Support::Substituted),
        M::Screen => ("screen", Support::Substituted),
        M::Overlay => ("overlay", Support::Substituted),
        M::Darken => ("darken", Support::Substituted),
        M::Lighten => ("lighten", Support::Substituted),
        M::Difference => ("difference", Support::Substituted),
        M::Exclve => ("exclusion", Support::Substituted),
        M::Invert => return None,
    })
}

/// The Canvas2D backend's claims. Same eleven, same verdicts as the headless
/// one — a browser canvas is not a GPU context and does not pretend to be — but
/// a different per-feature table, because it can express thirteen Porter-Duff
/// modes where the SVG backend can express six.
pub fn canvas2d_claims() -> Vec<Claim> {
    let mut c = headless_claims();
    for claim in &mut c {
        if claim.id == GfxId::HwComposition {
            claim.note = "no compositor: a canvas draws when the page asks it to, and nothing \
                           presents a frame on a schedule";
        }
    }
    c
}

/// The Canvas2D backend's per-feature table, with the per-mode rows filled in
/// from [`canvas2d_mode`].
pub fn canvas2d_limitations() -> Vec<Limitation> {
    let mut v = headless_limitations();
    // Both of these are replaced, not added to. Leaving the headless
    // `rasterisation` row in place would give the table two rows for one
    // feature, and a reader taking the first would read this backend's own
    // claim that it rasterises nothing.
    v.retain(|l| l.feature != "porter-duff-mode" && l.feature != "rasterisation");
    v.push(Limitation {
        feature: "rasterisation",
        instance: "",
        support: Support::Exact,
        note: "the browser's own 2D rasteriser performs the drawing; it is not Skia and does not claim to be",
    });
    for m in PorterDuffMode::ALL {
        match canvas2d_mode(m) {
            None => v.push(Limitation {
                feature: "porter-duff-mode",
                instance: m.as_str(),
                support: Support::Absent,
                note: "no Compositing 1 operator for this mode; the backend drops the blend and records it",
            }),
            Some((_, Support::Substituted)) => v.push(Limitation {
                feature: "porter-duff-mode",
                instance: m.as_str(),
                support: Support::Substituted,
                note: "Compositing 1 blends premultiplied channels; Skia blends unpremultiplied. Identical for opaque paint, divergent for translucent",
            }),
            Some((_, s)) => v.push(Limitation {
                feature: "porter-duff-mode",
                instance: m.as_str(),
                support: s,
                note: "one-to-one with a Compositing 1 operator of the same name",
            }),
        }
    }
    v
}

/// A browser canvas, as a generated JavaScript program.
///
/// The backend holds a JS statement list and an optional context handle name.
/// It never evaluates anything: the output is a string, which is what makes it
/// testable without a browser, and what makes the generated program diffable
/// between runs.
#[derive(Debug, Clone)]
pub struct Canvas2dCanvas {
    /// The JS identifier for the 2D context, e.g. `"ctx"`.
    pub ctx: String,
    /// Canvas pixel width.
    pub width_px: u32,
    /// Canvas pixel height, including the banner band.
    pub height_px: u32,
    lines: Vec<String>,
    depth: usize,
    clip_stack: Vec<RectF>,
    viewport: RectF,
    density: f32,
    dropped_blends: usize,
    step_limit: usize,
    colour_filter_drops: usize,
}

impl Default for Canvas2dCanvas {
    fn default() -> Self {
        Canvas2dCanvas::new("ctx")
    }
}

impl Canvas2dCanvas {
    pub fn new(ctx: &str) -> Canvas2dCanvas {
        Canvas2dCanvas {
            ctx: ctx.to_string(),
            width_px: 0,
            height_px: 0,
            lines: Vec::new(),
            depth: 0,
            clip_stack: vec![RectF::new(0.0, 0.0, 0.0, 0.0)],
            viewport: RectF::new(0.0, 0.0, 0.0, 0.0),
            density: 1.0,
            dropped_blends: 0,
            step_limit: 1_000_000,
            colour_filter_drops: 0,
        }
    }

    pub fn set_step_limit(&mut self, limit: usize) {
        self.step_limit = limit;
    }

    /// The generated statements, in order. The unit the tests assert on.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// How many blends this backend could not express and therefore dropped.
    pub fn dropped_blends(&self) -> usize {
        self.dropped_blends
    }

    pub fn dropped_colour_filters(&self) -> usize {
        self.colour_filter_drops
    }

    /// The program, wrapped in a function so a host page can call it with a
    /// context. Includes the banner and the capability headline as the first
    /// statements, so a screenshot of the canvas is impossible to mistake for a
    /// device capture.
    pub fn to_js(&self, report: &CapabilityReport) -> String {
        let mut s = String::with_capacity(512 + self.lines.len() * 48);
        s.push_str("// andro-substrate graphics program.\n");
        s.push_str("// THIS RENDERS THE SHIM'S BOX TREE, NOT THE APP. The app's onDraw\n");
        s.push_str("// code was never executed. See runtime/graphics/capability.rs.\n");
        let _ = writeln!(
            s,
            "// capability: {} reproduced of {} SUB.GFX assumptions",
            report.reproduced(),
            GfxId::ALL.len()
        );
        let _ = writeln!(s, "function substrateDraw({}) {{", self.ctx);
        for l in &self.lines {
            let _ = writeln!(s, "  {l}");
        }
        s.push_str("}\n");
        s
    }

    fn line(&mut self, l: String) -> Result<(), GraphicsError> {
        if self.lines.len() >= self.step_limit {
            return Err(GraphicsError::TooManySteps {
                steps: self.lines.len() + 1,
                limit: self.step_limit,
            });
        }
        self.lines.push(l);
        Ok(())
    }

    fn indent(&self) -> String {
        "  ".repeat(self.depth)
    }

    /// Apply a paint's non-compositing state.
    fn apply_paint(&mut self, p: &Paint) -> Result<(), GraphicsError> {
        let c = self.ctx.clone();
        let i = self.indent();
        let colour = json_str(&p.color.to_css());
        let cap = json_str(p.stroke_cap.to_canvas2d());
        let join = json_str(p.stroke_join.to_canvas2d());
        self.line(format!("{i}{c}.fillStyle = {colour};"))?;
        self.line(format!("{i}{c}.strokeStyle = {colour};"))?;
        self.line(format!("{i}{c}.lineWidth = {};", q(p.stroke_width)))?;
        self.line(format!("{i}{c}.lineCap = {cap};"))?;
        self.line(format!("{i}{c}.lineJoin = {join};"))?;
        self.line(format!("{i}{c}.miterLimit = {};", q(p.stroke_miter)))?;
        match p.color_filter {
            ColorFilter::None => {}
            ColorFilter::PorterDuff(f) => {
                // Canvas2D has no colour filter. A `SRC_IN` tint is expressible
                // as a temporary composite against a filled rect, but only for
                // that one mode, and only for a solid colour. Anything else is
                // dropped and counted, because a dropped tint looks like a
                // correct untinted draw.
                if f.mode != PorterDuffMode::SrcIn {
                    self.colour_filter_drops += 1;
                    self.line(format!(
                        "{i}// DROPPED color filter {} {} — Canvas2D has no filter; \
                         the ink below is untinted and is NOT what Android would draw",
                        f.mode, f.color
                    ))?;
                } else {
                    self.line(format!(
                        "{i}// color filter SRC_IN {} is applied by a scratch composite, \
                         not by a filter",
                        f.color
                    ))?;
                }
            }
            ColorFilter::Lighting(_) => {
                self.colour_filter_drops += 1;
                self.line(format!(
                    "{i}// DROPPED lighting color filter — Canvas2D has no lighting model"
                ))?;
            }
        }
        Ok(())
    }

    /// Set `globalCompositeOperation`, or record the refusal.
    fn apply_xfermode(&mut self, mode: PorterDuffMode) -> Result<(), GraphicsError> {
        let i = self.indent();
        let c = self.ctx.clone();
        match canvas2d_mode(mode) {
            Some((op, Support::Exact)) => {
                let op = json_str(op);
                self.line(format!("{i}{c}.globalCompositeOperation = {op};"))
            }
            Some((op, Support::Substituted)) if mode == PorterDuffMode::Src => {
                // A different failure from the blend modes, and a comment that
                // said only "divergent for translucent" would understate it:
                // `SRC` erases the destination and nothing here does.
                self.line(format!(
                    "{i}// SUBSTITUTED blend SRC -> Compositing 1 '{op}': NOT the same \
                     operator. SRC replaces the destination; source-over keeps it. Any \
                     ink already on the canvas should have been erased and was not."
                ))?;
                let op = json_str(op);
                self.line(format!("{i}{c}.globalCompositeOperation = {op};"))
            }
            Some((op, Support::Substituted)) => {
                // Emitted, with the caveat in a comment on the line above, so a
                // reader of the *program* sees the same caveat as a reader of
                // the report.
                self.line(format!(
                    "{i}// SUBSTITUTED blend {} -> Compositing 1 '{}': equal for opaque \
                     paint, divergent for translucent. The two specifications disagree \
                     about whether the blend happens on premultiplied channels.",
                    mode, op
                ))?;
                let op = json_str(op);
                self.line(format!("{i}{c}.globalCompositeOperation = {op};"))
            }
            Some((_, Support::Recorded)) | Some((_, Support::Absent)) => self.line(format!(
                "{i}// DROPPED blend {} — no Compositing 1 operator; the ink below is \
                 composited SRC_OVER and is NOT what Android would draw",
                mode
            )),
            None => {
                self.dropped_blends += 1;
                self.line(format!(
                    "{i}// DROPPED blend {} — no Compositing 1 operator; the ink below is \
                     composited SRC_OVER and is NOT what Android would draw",
                    mode
                ))
            }
        }
    }

    /// The banner band, drawn first and never clipped away.
    fn draw_banner(&mut self, report: &CapabilityReport, extra: &str) -> Result<(), GraphicsError> {
        let c = self.ctx.clone();
        let h = crate::svg::banner_height(self.viewport.height());
        let lines = crate::svg::banner_lines(report, extra, self.viewport);
        let vw = self.viewport.width();
        self.line(format!(
            "// BANNER {}dp: this is a reconstruction, not an Android frame",
            q(h)
        ))?;
        let bg = json_str(BANNER_BG);
        let fg = json_str(BANNER_FG);
        let font = json_str("11px monospace");
        self.line(format!("{c}.fillStyle = {bg};"))?;
        self.line(format!("{c}.fillRect(0, 0, {}, {});", q(vw), q(h)))?;
        self.line(format!("{c}.fillStyle = {fg};"))?;
        self.line(format!("{c}.font = {font};"))?;
        for (i, t) in lines.iter().enumerate() {
            let y = 14.0 + 13.0 * i as f32;
            let t = json_str(t);
            self.line(format!("{c}.fillText({t}, {});", q(y)))?;
        }
        Ok(())
    }
}

/// The banner band colour. Deliberately loud: this band exists to be
/// unmissable, not to be tasteful.
pub const BANNER_BG: &str = "#7a1010";
/// Banner text colour.
pub const BANNER_FG: &str = "#ffffff";

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl Canvas for Canvas2dCanvas {
    fn kind(&self) -> BackendKind {
        BackendKind::Canvas2d
    }

    fn current_clip(&self) -> RectF {
        self.clip_stack.last().copied().unwrap_or_default()
    }

    fn begin_frame(&mut self, viewport: RectF, density: f32) -> Result<(), GraphicsError> {
        RectF::checked(&viewport)?;
        if density <= 0.0 || !density.is_finite() {
            return Err(GraphicsError::BadViewport {
                width: viewport.width(),
                height: viewport.height(),
                density,
            });
        }
        self.viewport = viewport;
        self.density = density;
        self.width_px = (viewport.width() * density).max(0.0) as u32;
        let banner = crate::svg::banner_height(viewport.height());
        self.height_px = ((viewport.height() + banner) * density).max(0.0) as u32;
        self.clip_stack = vec![viewport];
        let report = CapabilityReport::audit(
            BackendKind::Canvas2d,
            &canvas2d_claims(),
            canvas2d_limitations(),
            |p| self.probe(p),
        );
        let extra = if self.dropped_blends > 0 {
            format!(
                "{} blend(s) dropped: no Compositing 1 operator",
                self.dropped_blends
            )
        } else {
            String::new()
        };
        self.draw_banner(&report, &extra)?;
        Ok(())
    }

    fn save(&mut self) -> Result<(), GraphicsError> {
        self.depth += 1;
        self.line(format!("{}{}.save();", self.indent(), self.ctx))
    }

    fn restore(&mut self) -> Result<(), GraphicsError> {
        if self.depth > 0 {
            self.depth -= 1;
        }
        if self.clip_stack.len() > 1 {
            self.clip_stack.pop();
        }
        self.line(format!("{}{}.restore();", self.indent(), self.ctx))
    }

    fn translate(&mut self, dx: f32, dy: f32) -> Result<(), GraphicsError> {
        for (what, v) in [("dx", dx), ("dy", dy)] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        self.line(format!("{}{}.translate({}, {});", self.indent(), self.ctx, q(dx), q(dy)))
    }

    fn scale(&mut self, sx: f32, sy: f32) -> Result<(), GraphicsError> {
        for (what, v) in [("sx", sx), ("sy", sy)] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        self.line(format!("{}{}.scale({}, {});", self.indent(), self.ctx, q(sx), q(sy)))
    }

    fn clip_rect(&mut self, r: RectF, antialias: bool) -> Result<(), GraphicsError> {
        RectF::checked(&r)?;
        self.clip_stack.push(self.current_clip().intersect(&r));
        let i = self.indent();
        let c = self.ctx.clone();
        self.line(format!("{i}{c}.save();"))?;
        self.line(format!("{i}{c}.beginPath();"))?;
        self.line(format!(
            "{i}{c}.rect({}, {}, {}, {});",
            q(r.left),
            q(r.top),
            q(r.width()),
            q(r.height())
        ))?;
        // Canvas2D's clip is not antialiased. The platform's is, when the app
        // asked for it. The comment is the honest output; a clip is not
        // something to quietly improve.
        let fill = json_str(if antialias { "antialiased" } else { "nonzero" });
        self.line(format!(
            "{i}{c}.clip({fill}); // clip antialiasing is not controllable in Canvas2D \
             (asked: {antialias})"
        ))?;
        self.depth += 1;
        Ok(())
    }

    fn clip_path(&mut self, p: &Path, antialias: bool) -> Result<(), GraphicsError> {
        p.checked()?;
        self.clip_stack.push(self.current_clip().intersect(&p.bounds()));
        let i = self.indent();
        let c = self.ctx.clone();
        self.line(format!("{i}{c}.save();"))?;
        self.line(format!("{i}{c}.beginPath();"))?;
        for op in p.ops() {
            match *op {
                crate::paint::PathOp::MoveTo(x, y) => {
                    self.line(format!("{i}{c}.moveTo({}, {});", q(x), q(y)))?;
                }
                crate::paint::PathOp::LineTo(x, y) => {
                    self.line(format!("{i}{c}.lineTo({}, {});", q(x), q(y)))?;
                }
                crate::paint::PathOp::QuadTo(x1, y1, x2, y2) => {
                    self.line(format!(
                        "{i}{c}.quadraticCurveTo({}, {}, {}, {});",
                        q(x1), q(y1), q(x2), q(y2)
                    ))?;
                }
                crate::paint::PathOp::CubicTo(x1, y1, x2, y2, x3, y3) => {
                    self.line(format!(
                        "{i}{c}.bezierCurveTo({}, {}, {}, {}, {}, {});",
                        q(x1), q(y1), q(x2), q(y2), q(x3), q(y3)
                    ))?;
                }
                crate::paint::PathOp::Close => self.line(format!("{i}{c}.closePath();"))?,
            }
        }
        let fill = json_str("nonzero");
        self.line(format!(
            "{i}{c}.clip({fill}); // asked: {antialias}; a path clip is never antialiased in SVG \
             and not controllable in Canvas2D"
        ))?;
        self.depth += 1;
        Ok(())
    }

    fn draw_color(&mut self, c: Color, mode: PorterDuffMode) -> Result<(), GraphicsError> {
        self.apply_xfermode(mode)?;
        let i = self.indent();
        let fill = json_str(&c.to_css());
        self.line(format!("{i}{}.fillStyle = {fill};", self.ctx))?;
        self.line(format!(
            "{i}{}.fillRect(0, 0, {}, {});",
            self.ctx,
            q(self.viewport.width()),
            q(self.viewport.height())
        ))
    }

    fn draw_rect(&mut self, r: RectF, p: &Paint) -> Result<(), GraphicsError> {
        RectF::checked(&r)?;
        p.checked()?;
        if !r.intersects(&self.current_clip()) {
            return Ok(());
        }
        self.apply_xfermode(p.effective_xfermode())?;
        self.apply_paint(p)?;
        let i = self.indent();
        let c = self.ctx.clone();
        if let Some(s) = &p.shader {
            self.emit_shader(s)?;
        }
        self.line(format!("{i}{c}.beginPath();"))?;
        self.line(format!(
            "{i}{c}.rect({}, {}, {}, {});",
            q(r.left),
            q(r.top),
            q(r.width()),
            q(r.height())
        ))?;
        match p.style {
            crate::paint::PaintStyle::Fill => self.line(format!("{i}{c}.fill();")),
            crate::paint::PaintStyle::FillAndStroke => {
                self.line(format!("{i}{c}.fill();"))?;
                self.line(format!("{i}{c}.stroke();"))
            }
            crate::paint::PaintStyle::Stroke => self.line(format!("{i}{c}.stroke();")),
        }
    }

    fn draw_path(&mut self, path: &Path, p: &Paint) -> Result<(), GraphicsError> {
        path.checked()?;
        p.checked()?;
        if !path.bounds().intersects(&self.current_clip()) {
            return Ok(());
        }
        self.apply_xfermode(p.effective_xfermode())?;
        self.apply_paint(p)?;
        if let Some(s) = &p.shader {
            self.emit_shader(s)?;
        }
        self.emit_path(path)?;
        let i = self.indent();
        let c = self.ctx.clone();
        match p.style {
            crate::paint::PaintStyle::Fill => self.line(format!("{i}{c}.fill();")),
            crate::paint::PaintStyle::FillAndStroke => {
                self.line(format!("{i}{c}.fill();"))?;
                self.line(format!("{i}{c}.stroke();"))
            }
            crate::paint::PaintStyle::Stroke => self.line(format!("{i}{c}.stroke();")),
        }
    }

    fn draw_text_run(&mut self, run: &TextRun, p: &Paint) -> Result<(), GraphicsError> {
        run.checked()?;
        p.checked()?;
        let w = run.advance.advance_x;
        let h = run.advance.advance_y;
        let box_ = RectF::new(run.x, run.baseline - run.advance.ascent, run.x + w, run.baseline + h);
        if !box_.intersects(&self.current_clip()) {
            return Ok(());
        }
        self.apply_xfermode(p.effective_xfermode())?;
        self.apply_paint(p)?;
        let i = self.indent();
        let c = self.ctx.clone();
        let font = json_str(&font_css(run));
        let align = json_str(p.text_align.to_canvas2d_align());
        self.line(format!("{i}{c}.font = {font};"))?;
        self.line(format!("{i}{c}.textAlign = {align};"))?;
        // The glyphs a browser draws are the host's fonts. Nothing here can make
        // them Roboto, and a run that looks like a device's text is exactly the
        // failure this layer is against, so the comment is on the draw call.
        self.line(format!(
            "{i}// glyphs come from the HOST's font stack, not from Android's; \
             advance={} was computed by {}",
            q(run.advance.advance_x),
            run.advance.model
        ))?;
        let text = json_str(&run.text);
        self.line(format!(
            "{i}{c}.fillText({text}, {}, {});",
            q(run.x),
            q(run.baseline)
        ))
    }

    fn draw_image(&mut self, img: &ImageDraw, p: &Paint) -> Result<(), GraphicsError> {
        img.checked()?;
        p.checked()?;
        if !img.dst.intersects(&self.current_clip()) {
            return Ok(());
        }
        self.apply_xfermode(p.effective_xfermode())?;
        let i = self.indent();
        match &img.bitmap.pixels {
            None => self.line(format!(
                "{i}// NO PIXELS for {} ({}x{}, undecoded); nothing is drawn",
                img.id, img.bitmap.width, img.bitmap.height
            )),
            Some(_) => {
                // The pixels exist, and this layer cannot hand them to a canvas:
                // there is no image encoder here, and a canvas needs a source.
                // Recorded rather than approximated with a grey box.
                self.line(format!(
                    "{i}// {} holds {}x{} RGBA but this layer has no image encoder; \
                     the pixels are NOT drawn. (paint: {})",
                    img.id, img.bitmap.width, img.bitmap.height, p.color
                ))
            }
        }
    }

    fn annotate(&mut self, a: Annotation, p: Provenance) -> Result<(), GraphicsError> {
        let i = self.indent();
        // The provenance goes in the comment as a leading token, so a reader of
        // the program sees the same warranty a reader of the display list does.
        self.line(format!("{i}// [{}] {}", p.as_str(), annotation_comment(&a)))
    }

    fn probe(&self, probe: &Probe) -> ProbeAnswer {
        match probe {
            Probe::HardwareCompositor => ProbeAnswer::Absent {
                reason: "a browser canvas draws on demand; no SurfaceFlinger and no vsync present it",
            },
            other => probe_answer(other),
        }
    }
}

impl Canvas2dCanvas {
    fn emit_shader(&mut self, s: &crate::paint::Shader) -> Result<(), GraphicsError> {
        let i = self.indent();
        let c = self.ctx.clone();
        let (colors, positions) = s.stops();
        let stops: Vec<String> = colors
            .iter()
            .zip(positions.iter())
            .map(|(col, p)| {
                let c = json_str(&col.to_css());
                format!("{{offset:{}, color:{c}}}", q(*p))
            })
            .collect();
        match s {
            crate::paint::Shader::Solid(col) => {
                let col = json_str(&col.to_css());
                self.line(format!("{i}{c}.fillStyle = {col};"))
            }
            crate::paint::Shader::Linear { x0, y0, x1, y1, tile, .. } => {
                self.line(format!(
                    "{i}{c}.fillStyle = {c}.createLinearGradient({}, {}, {}, {}, [{}]);",
                    q(*x0),
                    q(*y0),
                    q(*x1),
                    q(*y1),
                    stops.join(", ")
                ))?;
                self.line(format!(
                    "{i}// spread: {} — Canvas2D gradients are sRGB-interpolated and \
                     premultiplied; Skia's are not identical for wide-gamut paint",
                    tile.as_str()
                ))
            }
            crate::paint::Shader::Radial {
                cx, cy, radius, fx, fy, tile, ..
            } => {
                if (*fx - *cx).abs() > f32::EPSILON || (*fy - *cy).abs() > f32::EPSILON {
                    self.line(format!(
                        "{i}// radial focal point ({}, {}) is NOT expressible by \
                         createRadialGradient's two-circle form; the outer circle is used \
                         and the offset is recorded, not approximated",
                        q(*fx),
                        q(*fy)
                    ))?;
                }
                let tile = tile.as_str();
                self.line(format!(
                    "{i}// radial tile mode {tile}; Canvas2D has no radial spread, so \
                     anything but clamp/repeat is approximated by the browser"
                ))?;
                self.line(format!(
                    "{i}{c}.fillStyle = {c}.createRadialGradient({}, {}, {}, {}, [{}]);",
                    q(*cx),
                    q(*cy),
                    q(0.0),
                    q(*radius),
                    stops.join(", ")
                ))
            }
        }
    }

    fn emit_path(&mut self, path: &Path) -> Result<(), GraphicsError> {
        let i = self.indent();
        let c = self.ctx.clone();
        self.line(format!("{i}{c}.beginPath();"))?;
        for op in path.ops() {
            match *op {
                crate::paint::PathOp::MoveTo(x, y) => {
                    self.line(format!("{i}{c}.moveTo({}, {});", q(x), q(y)))?;
                }
                crate::paint::PathOp::LineTo(x, y) => {
                    self.line(format!("{i}{c}.lineTo({}, {});", q(x), q(y)))?;
                }
                crate::paint::PathOp::QuadTo(x1, y1, x2, y2) => {
                    self.line(format!(
                        "{i}{c}.quadraticCurveTo({}, {}, {}, {});",
                        q(x1), q(y1), q(x2), q(y2)
                    ))?;
                }
                crate::paint::PathOp::CubicTo(x1, y1, x2, y2, x3, y3) => {
                    self.line(format!(
                        "{i}{c}.bezierCurveTo({}, {}, {}, {}, {}, {});",
                        q(x1), q(y1), q(x2), q(y2), q(x3), q(y3)
                    ))?;
                }
                crate::paint::PathOp::Close => self.line(format!("{i}{c}.closePath();"))?,
            }
        }
        Ok(())
    }
}

fn font_css(run: &TextRun) -> String {
    let mut s = String::new();
    if run.style.bold {
        s.push_str("bold ");
    }
    if run.style.italic {
        s.push_str("italic ");
    }
    let _ = write!(s, "{}px {}", q(run.style.size_sp), run.style.typeface.to_css_family());
    s
}

/// Annotations reach the Canvas2D backend as comments. A comment is invisible
/// when the program runs, which is the point: an annotation is a statement about
/// the reconstruction, and rendering it as ink would be a claim about the app.
fn annotation_comment(a: &Annotation) -> String {
    match a {
        Annotation::UnknownInk { rect, reason } => {
            format!("unknown-ink {rect} :: {reason}")
        }
        Annotation::BoxOutline { id, rect, state, kind } => {
            format!("box {id:?} {rect} {kind} {}", state.as_str())
        }
        Annotation::TextWithheld {
            id,
            rect,
            chars,
            classes,
            shape,
        } => {
            let _ = classes;
            format!("text-withheld {id:?} {rect} chars={chars} shape={shape}")
        }
        Annotation::ImageAbsent { id, rect, reason } => {
            format!("image-absent {id:?} {rect} :: {reason}")
        }
        Annotation::ImageNotEmbedded {
            id,
            rect,
            width,
            height,
        } => format!("image-not-embedded {id:?} {rect} bitmap={width}x{height}"),
        Annotation::CapabilityNote { id, text } => {
            format!("CAPABILITY {} :: {text}", id.assumption())
        }
        Annotation::Note { text } => format!("note :: {text}"),
    }
}

// ---------------------------------------------------------------------------
// Image sources

/// A canvas that records nothing and answers every probe honestly.
///
/// Its whole reason to exist: `tests/capability.rs` uses it to check that the
/// `reproduced` count is a *measurement*. A backend that answered `Satisfied`
/// to a probe has to make the headline number move, and a backend that answered
/// nothing at all has to leave it alone. With only the real backends in the
/// crate, both of those are untestable — the number is `0` and there is no way
/// to tell `0` from a constant.
pub struct SilentCanvas {
    answers: Vec<ProbeAnswer>,
    viewport: Viewport,
}

impl std::fmt::Debug for SilentCanvas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SilentCanvas")
            .field("answers", &self.answers.len())
            .finish()
    }
}

impl SilentCanvas {
    /// A canvas that answers `Satisfied` to the first `n` probes it is asked and
    /// `Absent` to the rest. `Satisfied` carries evidence naming the check, so
    /// it survives [`ProbeAnswer::validated`].
    pub fn satisfied_for(n: usize) -> SilentCanvas {
        SilentCanvas {
            answers: (0..Probe::all().len())
                .map(|i| {
                    if i < n {
                        ProbeAnswer::Satisfied {
                            evidence: format!(
                                "stub: claim {} asserted without a reference, for testing only",
                                Probe::all().get(i).map_or("?", |p| p.id().token())
                            ),
                        }
                    } else {
                        ProbeAnswer::Absent {
                            reason: "stub: deliberately unanswered",
                        }
                    }
                })
                .collect(),
            viewport: Viewport {
                width_dp: 1.0,
                height_dp: 1.0,
                density: 1.0,
            },
        }
    }
}

impl Default for SilentCanvas {
    fn default() -> Self {
        SilentCanvas::satisfied_for(0)
    }
}

impl Canvas for SilentCanvas {
    fn kind(&self) -> BackendKind {
        BackendKind::Headless
    }
    fn current_clip(&self) -> RectF {
        RectF::new(0.0, 0.0, self.viewport.width_dp, self.viewport.height_dp)
    }
    fn begin_frame(&mut self, viewport: RectF, density: f32) -> Result<(), GraphicsError> {
        RectF::checked(&viewport)?;
        self.viewport = Viewport {
            width_dp: viewport.width(),
            height_dp: viewport.height(),
            density,
        };
        Ok(())
    }
    fn save(&mut self) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn restore(&mut self) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn translate(&mut self, _dx: f32, _dy: f32) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn scale(&mut self, _sx: f32, _sy: f32) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn clip_rect(&mut self, _r: RectF, _antialias: bool) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn clip_path(&mut self, _p: &Path, _antialias: bool) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn draw_color(&mut self, _c: Color, _mode: PorterDuffMode) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn draw_rect(&mut self, _r: RectF, _p: &Paint) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn draw_path(&mut self, _path: &Path, _p: &Paint) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn draw_text_run(&mut self, _run: &TextRun, _p: &Paint) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn draw_image(&mut self, _img: &ImageDraw, _p: &Paint) -> Result<(), GraphicsError> {
        Ok(())
    }
    fn annotate(&mut self, _a: Annotation, _p: Provenance) -> Result<(), GraphicsError> {
        Ok(())
    }

    fn probe(&self, probe: &Probe) -> ProbeAnswer {
        let idx = Probe::all()
            .iter()
            .position(|p| p.id() == probe.id())
            .unwrap_or(0);
        self.answers
            .get(idx)
            .cloned()
            .unwrap_or(ProbeAnswer::Absent {
                reason: "stub: no answer configured for this probe",
            })
    }
}

/// Images handed to the draw pass, keyed by view id.
///
/// A `BTreeMap`, not a `HashMap`: iteration order is part of the display list
/// and a `HashMap`'s order is not stable across runs. This is one of the three
/// things that would break byte-identity, listed in the module docs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageSource {
    images: BTreeMap<String, ImageBitmap>,
}

impl ImageSource {
    pub fn none() -> ImageSource {
        ImageSource::default()
    }

    pub fn insert(&mut self, id: &str, b: ImageBitmap) {
        self.images.insert(id.to_string(), b);
    }

    pub fn get(&self, id: &str) -> Option<&ImageBitmap> {
        self.images.get(id)
    }

    pub fn len(&self) -> usize {
        self.images.len()
    }
    pub fn is_empty(&self) -> bool {
        self.images.is_empty()
    }
    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.images.keys()
    }
}
