//! The paint vocabulary: the subset of `android.graphics` that real UI uses.
//!
//! # Scope, and the reason for the gaps
//!
//! `Color`, `RectF`, `Path`, `Shader`, `PorterDuff.Mode`, `XFERMODE`,
//! `ColorFilter` and `Paint` are here, with the platform's real names and the
//! platform's real constants. What is *not* here is at least as important:
//!
//! - **`BitmapShader`** is absent. Shading from a decoded bitmap needs a codec,
//!   and this layer has none. `Shader::of_kind` returns a typed error rather
//!   than a 1×1 stand-in, because a tiled grey texture is a plausible-looking
//!   fabrication and a plausible-looking fabrication is the failure this whole
//!   layer is built against.
//! - **`ColorMatrixColorFilter`** is absent. It is a 20-float matrix; a
//!   truncated one produces confidently wrong colours.
//! - **`ComposeShader`**, `RuntimeShader` (AGSL), `PathEffect`, and
//!   `setShadowLayer` are absent for the same reason: each is a large surface
//!   whose partial implementation is indistinguishable from a bug.
//!
//! Each of those absences is a `Support::Absent` row in the capability report,
//! not a silent hole.
//!
//! # Floating point
//!
//! `RectF` and `Path` are `f32`, as on Android. Every serialiser in this crate
//! goes through [`crate::canvas::q`] so that `-0.0` cannot become `-0` in one
//! backend's output and `0` in another's, and so that a value round-trips
//! through the text form byte for byte.

use std::fmt;

use crate::error::GraphicsError;

// ---------------------------------------------------------------------------
// Provenance

/// Where a value in the output came from. **Every step of the display list
/// carries one, and the serialisers print it**, so no number in a recording can
/// be read without its warranty.
///
/// This is the mechanism behind the project's hardest-won lesson, from its own
/// shim author: *"a shim returning plausible values produces recordings that
/// read like measurements of the app and are partly measurements of me… This
/// gets worse the more plausible the shim is."* The four arms are ordered from
/// "true of the shim's model" to "there is nothing", and nothing in between
/// gets to be silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// Copied without alteration from the shim's `BoxNode`. Exact *relative to
    /// the shim's layout model*. The shim's own header is explicit that its
    /// numbers are not a device's, and neither is anything carrying this tag.
    ShimTreeExact,
    /// A consequence of the shim's tree, true of the shim's model by
    /// definition: a clip rectangle implied by a parent frame, an outline drawn
    /// because there is a box.
    DerivedFromShimTree,
    /// Invented by this layer. A device would have produced something else.
    Fabricated,
    /// There is no value, and that is the finding.
    Absent,
}

impl Provenance {
    pub const ALL: [Provenance; 4] = [
        Provenance::ShimTreeExact,
        Provenance::DerivedFromShimTree,
        Provenance::Fabricated,
        Provenance::Absent,
    ];

    /// The token printed in the display list, chosen so it cannot be skimmed
    /// past: `fabricated` is a word, not a colour code.
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::ShimTreeExact => "shim-exact",
            Provenance::DerivedFromShimTree => "derived",
            Provenance::Fabricated => "fabricated",
            Provenance::Absent => "absent",
        }
    }

    /// The plain-English reading, for a banner or a report row.
    pub fn explain(self) -> &'static str {
        match self {
            Provenance::ShimTreeExact => {
                "exactly the shim's layout value; not a device measurement"
            }
            Provenance::DerivedFromShimTree => {
                "a consequence of the shim's layout, not of the app's drawing"
            }
            Provenance::Fabricated => "invented here; a device would differ",
            Provenance::Absent => "nothing emitted, deliberately",
        }
    }

    /// Does this step put ink on the surface?
    ///
    /// The distinction the anti-plausibility test turns on: an annotation is
    /// *about* the reconstruction and does not claim to be the app's output, so
    /// a frame with a hundred annotations and zero fabricated ink has honestly
    /// drawn nothing.
    pub fn is_ink(self) -> bool {
        matches!(
            self,
            Provenance::ShimTreeExact
                | Provenance::DerivedFromShimTree
                | Provenance::Fabricated
        )
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Color

/// `android.graphics.Color`: a non-premultiplied ARGB `u32`.
///
/// Non-premultiplied, because that is what `Color.argb()` returns and what
/// `Paint.setColor` takes. Premultiplication happens at composite time and is
/// never baked in here; a `Color` that had been through premultiply and back
/// would have lost the alpha of every fully transparent colour, which is the
/// classic "why is my shadow the wrong colour" bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Color(pub u32);

impl Color {
    pub const TRANSPARENT: Color = Color(0x0000_0000);
    pub const BLACK: Color = Color(0xFF00_0000);
    pub const WHITE: Color = Color(0xFFFF_FFFF);
    pub const GRAY: Color = Color(0xFF80_8080);

    pub fn argb(&self) -> u32 {
        self.0
    }
    pub fn alpha(&self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
    pub fn red(&self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    pub fn green(&self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    pub fn blue(&self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    /// `Color.argb(a, r, g, b)`, truncating each channel to a byte exactly as
    /// the platform's `& 0xFF` does. A caller passing 300 gets 44, which is
    /// what Android does, and quietly clamping instead would be a divergence.
    pub fn argb_of(a: i32, r: i32, g: i32, b: i32) -> Color {
        Color(
            (((a as u32) & 0xFF) << 24)
                | (((r as u32) & 0xFF) << 16)
                | (((g as u32) & 0xFF) << 8)
                | ((b as u32) & 0xFF),
        )
    }

    pub fn is_opaque(&self) -> bool {
        self.alpha() == 0xFF
    }
    pub fn is_transparent(&self) -> bool {
        self.alpha() == 0
    }

    /// CSS `rgba(r,g,b,a)`. This is what SVG and Canvas2D both want, and it is
    /// *non-premultiplied*, which both of them accept: SVG's `fill` and
    /// `fill-opacity` are separate, and Canvas2D's `rgba()` is specified
    /// non-premultiplied.
    pub fn to_css(&self) -> String {
        // The alpha goes through `q`, so `0x00` is `0` and `0xFF` is `1` — one
        // byte each, deterministically, and never `0.0`/`1.0` spelled two ways
        // in two different backends' output.
        format!(
            "rgba({},{},{},{})",
            self.red(),
            self.green(),
            self.blue(),
            crate::canvas::q(f32::from(self.alpha()) / 255.0)
        )
    }

    /// `#rrggbb`, for the cases where a serialiser wants a hex. Alpha is dropped
    /// and the caller is expected to have set an opacity attribute; the
    /// serialisers that do this say so in the attribute they emit.
    pub fn to_hex6(&self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.red(), self.green(), self.blue())
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08x}", self.0)
    }
}

// ---------------------------------------------------------------------------
// RectF

/// `android.graphics.RectF`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct RectF {
    pub left: f32,
    pub top: f32,
    pub right: f32,
    pub bottom: f32,
}

impl RectF {
    pub fn new(left: f32, top: f32, right: f32, bottom: f32) -> RectF {
        RectF {
            left,
            top,
            right,
            bottom,
        }
    }

    /// From the shim's integer `Rect`, in dp.
    pub fn from_dp(left: i32, top: i32, right: i32, bottom: i32) -> RectF {
        RectF::new(left as f32, top as f32, right as f32, bottom as f32)
    }

    /// Reject a rectangle a serialiser could not honestly write. `NaN` in an SVG
    /// attribute is not a number; it is a parse error in somebody else's reader.
    pub fn checked(r: &RectF) -> Result<(), GraphicsError> {
        for (what, v) in [
            ("left", r.left),
            ("top", r.top),
            ("right", r.right),
            ("bottom", r.bottom),
        ] {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what, value: v });
            }
        }
        Ok(())
    }

    /// The platform's `RectF.width()`: subtraction, *not* a clamp. Android
    /// returns a negative width for an inverted rect and relies on the caller;
    /// clamping here would make an inverted rect silently empty and hide the
    /// inversion, which is a layout bug worth seeing.
    pub fn width(&self) -> f32 {
        self.right - self.left
    }
    pub fn height(&self) -> f32 {
        self.bottom - self.top
    }
    pub fn is_empty(&self) -> bool {
        self.width() <= 0.0 || self.height() <= 0.0
    }
    pub fn area(&self) -> f64 {
        if self.is_empty() {
            0.0
        } else {
            f64::from(self.width()) * f64::from(self.height())
        }
    }

    /// Non-negative extent, for places that need a length and cannot have a
    /// negative one.
    pub fn width_nonneg(&self) -> f32 {
        self.width().max(0.0)
    }
    pub fn height_nonneg(&self) -> f32 {
        self.height().max(0.0)
    }

    pub fn center_x(&self) -> f32 {
        (self.left + self.right) / 2.0
    }
    pub fn center_y(&self) -> f32 {
        (self.top + self.bottom) / 2.0
    }

    pub fn offset(&self, dx: f32, dy: f32) -> RectF {
        RectF::new(self.left + dx, self.top + dy, self.right + dx, self.bottom + dy)
    }

    pub fn inset(&self, d: f32) -> RectF {
        RectF::new(self.left + d, self.top + d, self.right - d, self.bottom - d)
    }

    pub fn contains_rect(&self, other: &RectF) -> bool {
        other.left >= self.left
            && other.right <= self.right
            && other.top >= self.top
            && other.bottom <= self.bottom
    }

    pub fn intersects(&self, other: &RectF) -> bool {
        self.left < other.right && other.left < self.right && self.top < other.bottom && other.top < self.bottom
    }

    /// `RectF.intersect`: the overlap, or the empty rect at `left/top`.
    pub fn intersect(&self, other: &RectF) -> RectF {
        if !self.intersects(other) {
            return RectF::new(self.left, self.top, self.left, self.top);
        }
        RectF::new(
            self.left.max(other.left),
            self.top.max(other.top),
            self.right.min(other.right),
            self.bottom.min(other.bottom),
        )
    }

    /// The smallest rectangle containing both. The empty rect is the identity,
    /// exactly as `RectF.union` treats it.
    pub fn union(&self, other: &RectF) -> RectF {
        if self.is_empty() {
            return *other;
        }
        if other.is_empty() {
            return *self;
        }
        RectF::new(
            self.left.min(other.left),
            self.top.min(other.top),
            self.right.max(other.right),
            self.bottom.max(other.bottom),
        )
    }
}

impl fmt::Display for RectF {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{},{} {}x{}]",
            crate::canvas::q(self.left),
            crate::canvas::q(self.top),
            crate::canvas::q(self.width_nonneg()),
            crate::canvas::q(self.height_nonneg())
        )
    }
}

// ---------------------------------------------------------------------------
// Path

/// One verb of a `Path`. Android's `Path` is a union of verbs; this is the same
/// thing, flattened.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PathOp {
    MoveTo(f32, f32),
    LineTo(f32, f32),
    QuadTo(f32, f32, f32, f32),
    CubicTo(f32, f32, f32, f32, f32, f32),
    Close,
}

impl PathOp {
    pub fn name(&self) -> &'static str {
        match self {
            PathOp::MoveTo(..) => "M",
            PathOp::LineTo(..) => "L",
            PathOp::QuadTo(..) => "Q",
            PathOp::CubicTo(..) => "C",
            PathOp::Close => "Z",
        }
    }
}

/// `android.graphics.Path`, as a verb list.
///
/// Not a `PathEffect` pipeline and not a fill-type-aware path: those are absent
/// deliberately, see the module docs.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Path {
    ops: Vec<PathOp>,
}

impl Path {
    pub fn new() -> Path {
        Path { ops: Vec::new() }
    }
    pub fn ops(&self) -> &[PathOp] {
        &self.ops
    }
    pub fn len(&self) -> usize {
        self.ops.len()
    }
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn move_to(&mut self, x: f32, y: f32) -> &mut Self {
        self.ops.push(PathOp::MoveTo(x, y));
        self
    }
    pub fn line_to(&mut self, x: f32, y: f32) -> &mut Self {
        self.ops.push(PathOp::LineTo(x, y));
        self
    }
    pub fn quad_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32) -> &mut Self {
        self.ops.push(PathOp::QuadTo(x1, y1, x2, y2));
        self
    }
    pub fn cubic_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x3: f32, y3: f32) -> &mut Self {
        self.ops.push(PathOp::CubicTo(x1, y1, x2, y2, x3, y3));
        self
    }
    pub fn close(&mut self) -> &mut Self {
        self.ops.push(PathOp::Close);
        self
    }

    /// `Path.addRect`, counterclockwise, with the start point at the top-left —
    /// Android's convention, so a rect path and a `drawRect` of the same rect
    /// produce the same winding and therefore the same fill.
    pub fn add_rect(&mut self, r: &RectF) -> &mut Self {
        self.move_to(r.left, r.top)
            .line_to(r.left, r.bottom)
            .line_to(r.right, r.bottom)
            .line_to(r.right, r.top)
            .close()
    }

    /// `Path.addRoundRect`, as four corner arcs. `rx`/`ry` are clamped to half
    /// the extent exactly as the platform clamps them, because a corner radius
    /// larger than the box is a clamp on device too.
    pub fn add_round_rect(&mut self, r: &RectF, rx: f32, ry: f32) -> &mut Self {
        let rx = rx.max(0.0).min(r.width_nonneg() / 2.0);
        let ry = ry.max(0.0).min(r.height_nonneg() / 2.0);
        const K: f32 = 0.552_284_8; // the standard circle-to-cubic constant
        let (ox, oy) = (rx * K, ry * K);
        let (l, t, rt, b) = (r.left, r.top, r.right, r.bottom);
        self.move_to(l + rx, t)
            .line_to(rt - rx, t)
            .cubic_to(rt - rx + ox, t, rt, t + ry - oy, rt, t + ry)
            .line_to(rt, b - ry)
            .cubic_to(rt, b - ry + oy, rt - rx + ox, b, rt - rx, b)
            .line_to(l + rx, b)
            .cubic_to(l + rx - ox, b, l, b - ry + oy, l, b - ry)
            .line_to(l, t + ry)
            .cubic_to(l, t + ry - oy, l + rx - ox, t, l + rx, t)
            .close()
    }

    /// `Path.addOval`, as the four-segment cubic approximation Skia uses for
    /// non-uniform axes (the same kappa, applied per axis).
    pub fn add_oval(&mut self, r: &RectF) -> &mut Self {
        const K: f32 = 0.552_284_8;
        let cx = r.center_x();
        let cy = r.center_y();
        let rx = r.width() / 2.0;
        let ry = r.height() / 2.0;
        let (ox, oy) = (rx * K, ry * K);
        self.move_to(cx - rx, cy)
            .cubic_to(cx - rx, cy - oy, cx - ox, cy - ry, cx, cy - ry)
            .cubic_to(cx + ox, cy - ry, cx + rx, cy - oy, cx + rx, cy)
            .cubic_to(cx + rx, cy + oy, cx + ox, cy + ry, cx, cy + ry)
            .cubic_to(cx - ox, cy + ry, cx - rx, cy + oy, cx - rx, cy)
            .close()
    }

    /// `Path.addCircle`, as an oval plus a `moveTo` at the centre.
    ///
    /// The trailing `moveTo` is what `Path.addCircle` actually appends: it
    /// makes the subpath explicit for the fill rule and costs one verb.
    pub fn add_circle(&mut self, cx: f32, cy: f32, r: f32) -> &mut Self {
        let r = r.max(0.0);
        self.add_oval(&RectF::new(cx - r, cy - r, cx + r, cy + r));
        self.move_to(cx, cy)
    }

    /// Control-point bounds. A conservative bound, which is what Skia returns
    /// and what a caller must treat.
    pub fn bounds(&self) -> RectF {
        let (mut l, mut t, mut rr, mut b) = (f32::INFINITY, f32::INFINITY, f32::NEG_INFINITY, f32::NEG_INFINITY);
        let mut bump = |x: f32, y: f32| {
            l = l.min(x);
            t = t.min(y);
            rr = rr.max(x);
            b = b.max(y);
        };
        for op in &self.ops {
            match *op {
                PathOp::MoveTo(x, y) | PathOp::LineTo(x, y) => bump(x, y),
                PathOp::QuadTo(x1, y1, x2, y2) => {
                    bump(x1, y1);
                    bump(x2, y2);
                }
                PathOp::CubicTo(x1, y1, x2, y2, x3, y3) => {
                    bump(x1, y1);
                    bump(x2, y2);
                    bump(x3, y3);
                }
                PathOp::Close => {}
            }
        }
        if !l.is_finite() {
            return RectF::new(0.0, 0.0, 0.0, 0.0);
        }
        RectF::new(l, t, rr, b)
    }

    /// Reject a path a serialiser could not honestly write.
    pub fn checked(&self) -> Result<(), GraphicsError> {
        for op in &self.ops {
            let coords: &[f32] = match *op {
                PathOp::MoveTo(x, y) | PathOp::LineTo(x, y) => &[x, y],
                PathOp::QuadTo(a, b, c, d) => &[a, b, c, d],
                PathOp::CubicTo(a, b, c, d, e, f) => &[a, b, c, d, e, f],
                PathOp::Close => &[],
            };
            for v in coords {
                if !v.is_finite() {
                    return Err(GraphicsError::NonFinite {
                        what: "path coordinate",
                        value: *v,
                    });
                }
            }
        }
        Ok(())
    }

    /// SVG `d` attribute. Present for both SVG and the Canvas2D emitter, and
    /// the *only* place a path becomes a string, so the two backends cannot
    /// disagree about a path's spelling.
    pub fn to_svg_d(&self) -> String {
        let mut s = String::new();
        for op in &self.ops {
            s.push(' ');
            s.push_str(op.name());
            match *op {
                PathOp::MoveTo(x, y) | PathOp::LineTo(x, y) => {
                    s.push(' ');
                    s.push_str(&crate::canvas::q(x));
                    s.push(' ');
                    s.push_str(&crate::canvas::q(y));
                }
                PathOp::QuadTo(x1, y1, x2, y2) => {
                    s.push(' ');
                    for v in [x1, y1, x2, y2] {
                        s.push_str(&crate::canvas::q(v));
                        s.push(' ');
                    }
                }
                PathOp::CubicTo(x1, y1, x2, y2, x3, y3) => {
                    s.push(' ');
                    for v in [x1, y1, x2, y2, x3, y3] {
                        s.push_str(&crate::canvas::q(v));
                        s.push(' ');
                    }
                }
                PathOp::Close => {}
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Shader

/// `android.graphics.Shader.TileMode`. `Disabled` is the platform's
/// `DISABLE_TILE_MODE`, the value a shader takes when tiling is switched off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TileMode {
    Clamp,
    #[default]
    Repeat,
    Mirror,
    Disabled,
}

impl TileMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TileMode::Clamp => "clamp",
            TileMode::Repeat => "repeat",
            TileMode::Mirror => "mirror",
            TileMode::Disabled => "disabled",
        }
    }
    /// The SVG `spreadMethod` this maps to. `Mirror` and `Repeat` both become
    /// `repeat`; the difference is invisible at the tile boundary and SVG 1.1
    /// has no mirror. Recorded, not hidden.
    pub fn to_svg_spread(self) -> Option<&'static str> {
        match self {
            TileMode::Repeat | TileMode::Mirror => Some("repeat"),
            TileMode::Clamp => Some("pad"),
            TileMode::Disabled => None,
        }
    }
    /// The Canvas2D `CanvasPattern` repetition string.
    pub fn to_canvas2d_repeat(self) -> Option<&'static str> {
        match self {
            TileMode::Repeat | TileMode::Mirror => Some("repeat"),
            TileMode::Clamp => Some("clamp"),
            TileMode::Disabled => None,
        }
    }
}

/// The shaders real UI uses: a solid, a linear gradient, a radial gradient.
///
/// `BitmapShader` is deliberately absent — see the module docs. Requesting one
/// through [`Shader::bitmap_unsupported`] is how a caller discovers that.
#[derive(Debug, Clone, PartialEq)]
pub enum Shader {
    /// A solid colour. Android spells this as `Paint.setColor` with a null
    /// shader rather than as a shader at all; it is here so a backend has one
    /// place to answer "what is the fill", and the serialisers print it as
    /// `shader=solid(0x...)` so it is not mistaken for a gradient.
    Solid(Color),
    Linear {
        x0: f32,
        y0: f32,
        x1: f32,
        y1: f32,
        colors: Vec<Color>,
        /// Stops in `0.0..=1.0`, parallel to `colors`. Empty means evenly
        /// spaced, which is also what Android's two-argument constructor does.
        positions: Vec<f32>,
        tile: TileMode,
    },
    Radial {
        cx: f32,
        cy: f32,
        radius: f32,
        /// Focal point. Android defaults it to the centre; a `SweepGradient` is
        /// not modelled and would be a different type here.
        fx: f32,
        fy: f32,
        colors: Vec<Color>,
        positions: Vec<f32>,
        tile: TileMode,
    },
}

impl Default for Shader {
    fn default() -> Shader {
        // Hand-written rather than `#[default]` on a data-carrying variant:
        // "the default shader is a fully transparent solid" is a claim about
        // this layer's behaviour, and a derived impl would not have said it.
        Shader::Solid(Color::TRANSPARENT)
    }
}

impl Shader {
    /// What kind of shader this is, for the capability report and the
    /// `shader=` token in the display list.
    pub fn kind(&self) -> &'static str {
        match self {
            Shader::Solid(_) => "solid",
            Shader::Linear { .. } => "linear",
            Shader::Radial { .. } => "radial",
        }
    }

    /// The error a `BitmapShader` request produces. A named function so the
    /// absence is a *reachable* thing with a message, not a hole in a match.
    pub fn bitmap_unsupported() -> GraphicsError {
        GraphicsError::UnsupportedShader {
            which: "BitmapShader",
            backend: crate::error::BackendKind::Headless,
        }
    }

    /// Validate the invariants a serialiser depends on.
    pub fn checked(&self) -> Result<(), GraphicsError> {
        let check_list = |name: &'static str, v: &[f32]| -> Result<(), GraphicsError> {
            for x in v {
                if !x.is_finite() {
                    return Err(GraphicsError::NonFinite { what: name, value: *x });
                }
            }
            Ok(())
        };
        let check_colors = |cs: &[Color]| -> Result<(), GraphicsError> {
            if cs.is_empty() {
                return Err(GraphicsError::Encode {
                    what: "shader",
                    reason: "a gradient needs at least two colours".to_string(),
                });
            }
            Ok(())
        };
        match self {
            Shader::Solid(_) => Ok(()),
            Shader::Linear {
                x0,
                y0,
                x1,
                y1,
                colors,
                positions,
                ..
            } => {
                check_list("linear gradient x0", &[*x0])?;
                check_list("linear gradient y0", &[*y0])?;
                check_list("linear gradient x1", &[*x1])?;
                check_list("linear gradient y1", &[*y1])?;
                check_colors(colors)?;
                check_list("gradient position", positions)
            }
            Shader::Radial {
                cx,
                cy,
                radius,
                colors,
                positions,
                ..
            } => {
                check_list("radial centre", &[*cx, *cy, *radius])?;
                check_colors(colors)?;
                check_list("gradient position", positions)
            }
        }
    }

    /// The `colors` and `positions` a serialiser needs, with evenly spaced
    /// stops materialised when the shader was built without them.
    pub fn stops(&self) -> (Vec<Color>, Vec<f32>) {
        match self {
            Shader::Solid(c) => (vec![*c], vec![0.0]),
            Shader::Linear {
                colors, positions, ..
            }
            | Shader::Radial {
                colors, positions, ..
            } => {
                let n = colors.len();
                if !positions.is_empty() {
                    return (colors.clone(), positions.clone());
                }
                if n <= 1 {
                    return (colors.clone(), vec![0.0; n]);
                }
                let last = (n - 1) as f32;
                (
                    colors.clone(),
                    (0..n).map(|i| i as f32 / last).collect(),
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PorterDuff

/// `android.graphics.PorterDuff.Mode`, all twenty-one, with the platform's own
/// names.
///
/// The classic twelve are *compositing operators* and are reproduced exactly by
/// a backend that has the matching primitive. The other nine are the separable
/// blend modes, and the word "exactly" is doing real work there: Skia's
/// `PorterDuff.Mode.MULTIPLY` and the Compositing spec's `multiply` agree for
/// opaque colours and **differ for translucent ones**, because the two
/// specifications disagree about whether the blend happens on premultiplied or
/// straight alpha. Every backend in this crate records those six-plus as
/// `Support::Substituted` rather than `Support::Exact`, and the reason is in
/// [`crate::canvas`] next to the mapping it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PorterDuffMode {
    Clear,
    Src,
    Dst,
    /// The mode a `Paint` with no `XFERMODE` set composites with, and so the
    /// `Default`. Named here so the derive and [`Paint::effective_xfermode`]
    /// cannot drift apart.
    #[default]
    SrcOver,
    DstOver,
    SrcIn,
    DstIn,
    SrcOut,
    DstOut,
    SrcAtop,
    DstAtop,
    Xor,
    Add,
    Multiply,
    Screen,
    Overlay,
    Darken,
    Lighten,
    Difference,
    Exclve,
    Invert,
}

/// `PorterDuffXfermode` is spelled `EXCLVE` on the platform because `EXCLUDE`
/// was a Java keyword. Reproducing the spelling matters: a study that greps
/// decompiled code for mode names has to find the same tokens Android has.
pub const PORTER_DUFF_MODE_COUNT: usize = 21;

impl PorterDuffMode {
    pub const ALL: [PorterDuffMode; PORTER_DUFF_MODE_COUNT] = [
        PorterDuffMode::Clear,
        PorterDuffMode::Src,
        PorterDuffMode::Dst,
        PorterDuffMode::SrcOver,
        PorterDuffMode::DstOver,
        PorterDuffMode::SrcIn,
        PorterDuffMode::DstIn,
        PorterDuffMode::SrcOut,
        PorterDuffMode::DstOut,
        PorterDuffMode::SrcAtop,
        PorterDuffMode::DstAtop,
        PorterDuffMode::Xor,
        PorterDuffMode::Add,
        PorterDuffMode::Multiply,
        PorterDuffMode::Screen,
        PorterDuffMode::Overlay,
        PorterDuffMode::Darken,
        PorterDuffMode::Lighten,
        PorterDuffMode::Difference,
        PorterDuffMode::Exclve,
        PorterDuffMode::Invert,
    ];

    /// The platform's constant name, e.g. `"SRC_IN"`, `"EXCLVE"`.
    pub fn as_str(self) -> &'static str {
        match self {
            PorterDuffMode::Clear => "CLEAR",
            PorterDuffMode::Src => "SRC",
            PorterDuffMode::Dst => "DST",
            PorterDuffMode::SrcOver => "SRC_OVER",
            PorterDuffMode::DstOver => "DST_OVER",
            PorterDuffMode::SrcIn => "SRC_IN",
            PorterDuffMode::DstIn => "DST_IN",
            PorterDuffMode::SrcOut => "SRC_OUT",
            PorterDuffMode::DstOut => "DST_OUT",
            PorterDuffMode::SrcAtop => "SRC_ATOP",
            PorterDuffMode::DstAtop => "DST_ATOP",
            PorterDuffMode::Xor => "XOR",
            PorterDuffMode::Add => "ADD",
            PorterDuffMode::Multiply => "MULTIPLY",
            PorterDuffMode::Screen => "SCREEN",
            PorterDuffMode::Overlay => "OVERLAY",
            PorterDuffMode::Darken => "DARKEN",
            PorterDuffMode::Lighten => "LIGHTEN",
            PorterDuffMode::Difference => "DIFFERENCE",
            PorterDuffMode::Exclve => "EXCLVE",
            PorterDuffMode::Invert => "INVERT",
        }
    }

    /// The first twelve are the original Porter-Duff operators; the rest are
    /// separable blend modes added later. Used to decide what a backend can
    /// claim `Exact` for.
    pub fn is_porter_duff_classic(self) -> bool {
        matches!(
            self,
            PorterDuffMode::Clear
                | PorterDuffMode::Src
                | PorterDuffMode::Dst
                | PorterDuffMode::SrcOver
                | PorterDuffMode::DstOver
                | PorterDuffMode::SrcIn
                | PorterDuffMode::DstIn
                | PorterDuffMode::SrcOut
                | PorterDuffMode::DstOut
                | PorterDuffMode::SrcAtop
                | PorterDuffMode::DstAtop
                | PorterDuffMode::Xor
        )
    }

    pub fn parse(s: &str) -> Option<PorterDuffMode> {
        PorterDuffMode::ALL.into_iter().find(|m| m.as_str() == s)
    }
}

impl fmt::Display for PorterDuffMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ColorFilter

/// `PorterDuffColorFilter(color, mode)`: take the source's alpha and give it a
/// flat colour, composited with `mode`.
///
/// The canonical use is `SRC_IN` — a solid colour masked by an existing alpha
/// channel — which is how `BitmapDrawable` tinting works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PorterDuffColorFilter {
    pub color: Color,
    pub mode: PorterDuffMode,
}

/// `LightingColorFilter`, the platform's 4×4 matrix in its compact form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LightingColorFilter {
    pub ambient_color: u32,
    pub diffuse_color: u32,
    pub specular_color: u32,
    pub alpha: u32,
}

/// `android.graphics.ColorFilter`, the subset modelled here.
///
/// `ColorMatrixColorFilter` is **absent** on purpose — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorFilter {
    #[default]
    None,
    PorterDuff(PorterDuffColorFilter),
    Lighting(LightingColorFilter),
}

impl ColorFilter {
    pub fn kind(&self) -> &'static str {
        match self {
            ColorFilter::None => "none",
            ColorFilter::PorterDuff(_) => "porter-duff",
            ColorFilter::Lighting(_) => "lighting",
        }
    }

    /// The error a `ColorMatrixColorFilter` request produces.
    pub fn color_matrix_unsupported(backend: crate::error::BackendKind) -> GraphicsError {
        GraphicsError::UnsupportedColorFilter {
            which: "ColorMatrixColorFilter",
            backend,
        }
    }
}

// ---------------------------------------------------------------------------
// Paint

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PaintStyle {
    #[default]
    Fill,
    FillAndStroke,
    Stroke,
}

impl PaintStyle {
    pub fn as_str(self) -> &'static str {
        match self {
            PaintStyle::Fill => "fill",
            PaintStyle::FillAndStroke => "fill-and-stroke",
            PaintStyle::Stroke => "stroke",
        }
    }
    /// The SVG `paint-order`, which is the only way SVG expresses a fill *and*
    /// a stroke on one shape. SVG has no `STROKE` or `FILL` style: it always
    /// has both, and `paint-order` decides which is on top. So a `Fill` paint
    /// with a stroke colour set renders stroked in SVG and not at all in
    /// Canvas2D — a real divergence, recorded in the display list as
    /// `style=fill` plus `stroke=none` so a reader can see the ink was not
    /// meant.
    pub fn to_svg_paint_order(self) -> &'static str {
        match self {
            PaintStyle::Fill => "fill",
            PaintStyle::FillAndStroke => "fill stroke",
            PaintStyle::Stroke => "stroke",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrokeCap {
    #[default]
    Butt,
    Round,
    Square,
}

impl StrokeCap {
    pub fn as_str(self) -> &'static str {
        match self {
            StrokeCap::Butt => "butt",
            StrokeCap::Round => "round",
            StrokeCap::Square => "square",
        }
    }
    pub fn to_canvas2d(self) -> &'static str {
        match self {
            StrokeCap::Butt => "butt",
            StrokeCap::Round => "round",
            StrokeCap::Square => "square",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrokeJoin {
    #[default]
    Miter,
    Round,
    Bevel,
}

impl StrokeJoin {
    pub fn as_str(self) -> &'static str {
        match self {
            StrokeJoin::Miter => "miter",
            StrokeJoin::Round => "round",
            StrokeJoin::Bevel => "bevel",
        }
    }
    pub fn to_canvas2d(self) -> &'static str {
        match self {
            StrokeJoin::Miter => "miter",
            StrokeJoin::Round => "round",
            StrokeJoin::Bevel => "bevel",
        }
    }
}

/// `android.graphics.Paint`, partial, and serialisable.
///
/// Defaults mirror the platform's: black, `Fill`, anti-alias **off**. An
/// app that never calls `setAntiAlias` gets aliased text on a device and will
/// get aliased text here, which is the right answer for a different reason —
/// the browser's rasteriser is not Skia's — and both facts are in the display
/// list's `antialias` field rather than in a README.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Paint {
    pub style: PaintStyle,
    pub stroke_width: f32,
    pub stroke_cap: StrokeCap,
    pub stroke_join: StrokeJoin,
    pub stroke_miter: f32,
    /// Skia's default miter limit. Below 4 a miter is bevelled, which is a
    /// visible difference on a sharp corner, so the value is recorded.
    pub anti_alias: bool,
    pub color: Color,
    pub shader: Option<Shader>,
    pub xfermode: Option<Xfermode>,
    pub color_filter: ColorFilter,
    /// In sp, as on Android. Converted to dp by the density the caller supplies;
    /// the conversion happens once, here, and is visible in the display list.
    pub text_size: f32,
    pub text_align: TextAlign,
    pub typeface: crate::measure::Typeface,
    pub letter_spacing: f32,
    pub fake_bold_text: bool,
}

impl Paint {
    /// `Paint::default()` on Android: black, fill, no anti-alias.
    pub fn new() -> Paint {
        Paint {
            style: PaintStyle::Fill,
            stroke_width: 0.0,
            stroke_cap: StrokeCap::Butt,
            stroke_join: StrokeJoin::Miter,
            stroke_miter: 4.0,
            anti_alias: false,
            color: Color::BLACK,
            shader: None,
            xfermode: None,
            color_filter: ColorFilter::None,
            text_size: 14.0,
            text_align: TextAlign::Left,
            typeface: crate::measure::Typeface::Default,
            letter_spacing: 0.0,
            fake_bold_text: false,
        }
    }

    pub fn fill(mut self, c: Color) -> Paint {
        self.color = c;
        self.style = PaintStyle::Fill;
        self
    }
    pub fn stroke(mut self, c: Color, w: f32) -> Paint {
        self.color = c;
        self.style = PaintStyle::Stroke;
        self.stroke_width = w;
        self
    }
    pub fn with_shader(mut self, s: Shader) -> Paint {
        self.shader = Some(s);
        self
    }
    pub fn with_xfermode(mut self, m: PorterDuffMode) -> Paint {
        self.xfermode = Some(Xfermode::new(m));
        self
    }
    pub fn with_color_filter(mut self, f: ColorFilter) -> Paint {
        self.color_filter = f;
        self
    }
    pub fn text(mut self, size: f32, t: crate::measure::Typeface) -> Paint {
        self.text_size = size;
        self.typeface = t;
        self
    }

    /// The composite mode actually in force. A null `XFERMODE` means
    /// `SRC_OVER`, which is what the platform does; printing `xfer=none` for an
    /// unset xfermode would hide the one mode every paint actually uses.
    pub fn effective_xfermode(&self) -> PorterDuffMode {
        self.xfermode
            .map(|x| x.mode)
            .unwrap_or(PorterDuffMode::SrcOver)
    }

    /// Every float in the paint, for the finiteness check.
    pub fn floats(&self) -> [f32; 6] {
        [
            self.stroke_width,
            self.stroke_miter,
            self.text_size,
            self.letter_spacing,
            match self.typeface {
                crate::measure::Typeface::Fallback(_) => 1.0,
                _ => 0.0,
            },
            0.0,
        ]
    }

    pub fn checked(&self) -> Result<(), GraphicsError> {
        for v in self.floats() {
            if !v.is_finite() {
                return Err(GraphicsError::NonFinite { what: "paint", value: v });
            }
        }
        if let Some(s) = &self.shader {
            s.checked()?;
        }
        Ok(())
    }
}

/// `android.graphics.XFERMODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Xfermode {
    pub mode: PorterDuffMode,
}

impl Xfermode {
    pub fn new(mode: PorterDuffMode) -> Xfermode {
        Xfermode { mode }
    }
    pub fn as_str(&self) -> &'static str {
        self.mode.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextAlign {
    #[default]
    Left,
    Center,
    Right,
}

impl TextAlign {
    pub fn as_str(self) -> &'static str {
        match self {
            TextAlign::Left => "left",
            TextAlign::Center => "center",
            TextAlign::Right => "right",
        }
    }
    /// SVG's `text-anchor`.
    pub fn to_svg_anchor(self) -> &'static str {
        match self {
            TextAlign::Left => "start",
            TextAlign::Center => "middle",
            TextAlign::Right => "end",
        }
    }
    /// Canvas2D's `textAlign`.
    pub fn to_canvas2d_align(self) -> &'static str {
        match self {
            TextAlign::Left => "left",
            TextAlign::Center => "center",
            TextAlign::Right => "right",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_is_ordered_from_most_to_least_defensible() {
        // The order is a claim about defensibility, and the
        // `Fabricated`-ink test in tests/draw.rs depends on it.
        assert!(Provenance::ShimTreeExact < Provenance::DerivedFromShimTree);
        assert!(Provenance::DerivedFromShimTree < Provenance::Fabricated);
        assert!(Provenance::Fabricated < Provenance::Absent);
        for p in Provenance::ALL {
            assert!(!p.explain().is_empty());
        }
        assert!(!Provenance::Absent.is_ink());
        assert!(Provenance::Fabricated.is_ink());
    }

    #[test]
    fn color_channels_are_the_platforms_bit_layout() {
        let c = Color::argb_of(0x80, 0x11, 0x22, 0x33);
        assert_eq!(c.argb(), 0x8011_2233);
        assert_eq!((c.alpha(), c.red(), c.green(), c.blue()), (0x80, 0x11, 0x22, 0x33));
        // Android masks with &0xFF rather than saturating; so do we.
        assert_eq!(Color::argb_of(300, 0, 0, 0).alpha(), 44);
        assert_eq!(Color::TRANSPARENT.to_css(), "rgba(0,0,0,0)");
        assert_eq!(Color::WHITE.to_css(), "rgba(255,255,255,1)");
    }

    #[test]
    fn rectf_keeps_androids_signed_width() {
        let inverted = RectF::new(10.0, 0.0, 0.0, 5.0);
        assert_eq!(inverted.width(), -10.0, "RectF.width() does not clamp");
        assert!(inverted.is_empty());
        assert_eq!(inverted.area(), 0.0);
        assert_eq!(inverted.width_nonneg(), 0.0);
    }

    #[test]
    fn rectf_intersect_and_union_match_the_platform_edge_cases() {
        let a = RectF::new(0.0, 0.0, 10.0, 10.0);
        let b = RectF::new(20.0, 20.0, 30.0, 30.0);
        assert!(!a.intersects(&b));
        let i = a.intersect(&b);
        assert!(i.is_empty() && i.left == 0.0 && i.top == 0.0);
        // The empty rect is the identity for union, as on the platform.
        let e = RectF::new(3.0, 4.0, 3.0, 4.0);
        assert_eq!(e.union(&a), a);
        assert_eq!(a.union(&e), a);
        assert_eq!(a.union(&b), RectF::new(0.0, 0.0, 30.0, 30.0));
    }

    #[test]
    fn a_rect_path_winds_counterclockwise_from_the_top_left() {
        let mut p = Path::new();
        p.add_rect(&RectF::new(0.0, 0.0, 10.0, 10.0));
        assert_eq!(p.ops()[0], PathOp::MoveTo(0.0, 0.0));
        assert_eq!(*p.ops().last().unwrap_or(&PathOp::Close), PathOp::Close);
        // Going down the left edge first is counterclockwise in a y-down space.
        assert_eq!(p.ops()[1], PathOp::LineTo(0.0, 10.0));
        assert_eq!(p.bounds(), RectF::new(0.0, 0.0, 10.0, 10.0));
    }

    #[test]
    fn round_rect_clamps_its_radius_like_the_platform_does() {
        let mut p = Path::new();
        p.add_round_rect(&RectF::new(0.0, 0.0, 10.0, 10.0), 999.0, 999.0);
        let b = p.bounds();
        assert!(b.width() <= 10.001 && b.height() <= 10.001, "{b:?}");
        assert!(b.width() >= 9.0, "a clamped radius still reaches the edges: {b:?}");
    }

    #[test]
    fn a_gradient_without_stops_materialises_evenly_spaced_ones() {
        let s = Shader::Linear {
            x0: 0.0,
            y0: 0.0,
            x1: 0.0,
            y1: 1.0,
            colors: vec![Color::BLACK, Color::WHITE, Color::GRAY],
            positions: Vec::new(),
            tile: TileMode::Clamp,
        };
        let (_, p) = s.stops();
        assert_eq!(p, vec![0.0, 0.5, 1.0]);
        // Explicit stops are respected verbatim. Rebuilt by hand rather than
        // with `..s`, because a struct-update on an enum variant is not a thing
        // and writing it out keeps the two cases adjacent and comparable.
        let s2 = Shader::Linear {
            x0: 0.0,
            y0: 0.0,
            x1: 0.0,
            y1: 1.0,
            colors: vec![Color::BLACK, Color::WHITE],
            positions: vec![0.1, 0.9],
            tile: TileMode::Clamp,
        };
        let (_, p2) = s2.stops();
        assert_eq!(p2, vec![0.1, 0.9]);
    }

    #[test]
    fn a_gradient_with_no_colours_is_an_error_not_an_empty_swatch() {
        let s = Shader::Linear {
            x0: 0.0,
            y0: 0.0,
            x1: 0.0,
            y1: 1.0,
            colors: Vec::new(),
            positions: Vec::new(),
            tile: TileMode::Repeat,
        };
        assert!(s.checked().is_err());
    }

    #[test]
    fn there_are_twenty_one_porter_duff_modes_and_they_round_trip() {
        assert_eq!(PorterDuffMode::ALL.len(), 21);
        for m in PorterDuffMode::ALL {
            assert_eq!(PorterDuffMode::parse(m.as_str()), Some(m));
        }
        // The platform's spelling, including the keyword workaround.
        assert_eq!(PorterDuffMode::Exclve.as_str(), "EXCLVE");
        assert_eq!(PorterDuffMode::SrcIn.as_str(), "SRC_IN");
        assert_eq!(PorterDuffMode::parse("EXCLUDE"), None);
        assert_eq!(
            PorterDuffMode::ALL
                .iter()
                .filter(|m| m.is_porter_duff_classic())
                .count(),
            12
        );
    }

    #[test]
    fn an_unset_xfermode_is_src_over_and_says_so() {
        let p = Paint::new();
        assert_eq!(p.effective_xfermode(), PorterDuffMode::SrcOver);
        assert!(p.xfermode.is_none());
        assert_eq!(
            p.with_xfermode(PorterDuffMode::SrcIn).effective_xfermode(),
            PorterDuffMode::SrcIn
        );
    }

    #[test]
    fn absent_paint_features_are_reachable_errors_not_silent_defaults() {
        assert!(matches!(
            Shader::bitmap_unsupported(),
            GraphicsError::UnsupportedShader { which: "BitmapShader", .. }
        ));
        assert!(matches!(
            ColorFilter::color_matrix_unsupported(crate::error::BackendKind::Svg),
            GraphicsError::UnsupportedColorFilter {
                which: "ColorMatrixColorFilter",
                ..
            }
        ));
    }

    #[test]
    fn non_finite_paint_and_path_values_are_refused() {
        let p = Paint::new().text(f32::NAN, crate::measure::Typeface::Default);
        assert!(p.checked().is_err());
        let mut path = Path::new();
        path.line_to(f32::INFINITY, 0.0);
        assert!(path.checked().is_err());
    }
}
