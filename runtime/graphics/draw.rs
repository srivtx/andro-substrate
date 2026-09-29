//! Mapping the shim's box tree to draw commands.
//!
//! # The single most important sentence in this file
//!
//! **The app's `onDraw` was never executed.** The shim's `BoxNode` is the
//! output of a measure/layout/draw cycle in which `draw` produces *geometry* and
//! sets `painted: false` on every node. There is no background colour in a
//! `BoxNode`, no border, no drawable, no text layout. So this pass cannot
//! reproduce any ink, and it does not: with the default [`DrawConfig`] the
//! answer is **zero fabricated ink commands** and a tree of annotations saying
//! where the ink is missing.
//!
//! A `Theme` exists, and using it is legitimate, but every fill it produces is
//! tagged `Provenance::Fabricated` and the header counts them. The test
//! `default_pipeline_fabricates_no_ink` asserts the count is zero, and that is
//! the assertion that stops this file from drifting into building something that
//! looks like Android.
//!
//! # Text, specifically
//!
//! The shim's `TextPolicy::ShapeOnly` records a string's *length*, its
//! character-class histogram and three shape guesses, and never a character. So
//! the tree does not contain the text, and a rendering of that tree cannot
//! contain the text either. Rather than draw the shape's character count, this
//! pass emits a `TextWithheld` annotation: a hatched band, with the length and
//! the class histogram, saying that glyphs would be here and are not.
//!
//! When the caller captured with `TextPolicy::Include`, the tree *does* carry
//! the characters, and [`TextSource::from_tree`] picks them up. The text is then
//! measured by the seam in `measure.rs` — by default the *zero* measurer, so
//! the run has no width and is dropped, which is the same statement the
//! measurement made. The pipeline for characters-present and run-visible is
//! `tests/draw.rs` with a non-default measurer, and the advances in it are
//! labelled `fabricated` there too.
//!
//! # Clipping
//!
//! A `ViewGroup` clips its children by default (`clipChildren == true`). This
//! pass emits a `ClipRect` per container for exactly that reason, and records
//! the *effective* clip — the intersection with what is already in force — so a
//! reader does not have to replay the stack. Note that with the shim's layout
//! the children are inside their parent, so most of those clips remove nothing;
//! a test constructs a `FrameLayout` child larger than its parent to show the
//! clip is real rather than decorative.
//!
//! Note also what a clip is *not*: the headless backend records clips and does
//! not apply them, because it rasterises nothing. "Commands removed by
//! clipping" is therefore not a number this layer can report, and
//! [`DrawReport`] does not pretend otherwise.

use std::collections::BTreeMap;

use shim::layout::{BoxNode, NodeKind, TextPolicy, Visibility};

use crate::canvas::{
    Annotation, Canvas, DisplayList, HeadlessCanvas, ImageDraw, ImageSource,
    TextRun, ViewState, Viewport,
};
use crate::error::GraphicsError;
use crate::measure::{MeasureUsage, TextMeasurer};
use crate::paint::{Color, Paint, PaintStyle, Provenance, RectF, Shader};

/// The reason string carried by every `UnknownInk` annotation.
///
/// One constant, so a reader cannot be told a different story per box, and so a
/// test can assert the string.
pub const NO_APP_PAINT: &str =
    "the shim's BoxNode carries geometry only; the app's onDraw never ran here";
/// The reason string for an absent image.
pub const NO_BITMAP: &str = "no decoded bitmap was supplied; this layer has no codec";
/// The reason string for a decoded bitmap the serialiser cannot embed.
pub const NO_IMAGE_ENCODER: &str =
    "this layer has no image encoder, so decoded pixels are recorded and not drawn";

/// Where the characters of a text view come from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TextSource {
    /// The box tree withheld every character. The default, and the only honest
    /// choice when the capture used `TextPolicy::Omit` or `ShapeOnly`.
    #[default]
    Withheld,
    /// Characters, keyed by view id.
    Supplied(BTreeMap<String, String>),
}

impl TextSource {
    /// Collect the characters from a tree, if the tree has any.
    ///
    /// Returns `Withheld` unless *every* text-bearing node carries its
    /// characters. A partial source is a bug, not a partial rendering: mixing
    /// real strings with placeholders inside one frame is how a reader ends up
    /// believing a mixture.
    pub fn from_tree(tree: &BoxNode) -> TextSource {
        let mut map = BTreeMap::new();
        collect_text(tree, &mut map);
        if map.is_empty() {
            TextSource::Withheld
        } else {
            TextSource::Supplied(map)
        }
    }

    pub fn get(&self, id: &str) -> Option<&str> {
        match self {
            TextSource::Withheld => None,
            TextSource::Supplied(m) => m.get(id).map(String::as_str),
        }
    }

    pub fn policy_label(&self) -> &'static str {
        match self {
            TextSource::Withheld => "withheld",
            TextSource::Supplied(_) => "included",
        }
    }

    pub fn len(&self) -> usize {
        match self {
            TextSource::Withheld => 0,
            TextSource::Supplied(m) => m.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn collect_text(node: &BoxNode, out: &mut BTreeMap<String, String>) -> bool {
    let mut complete = true;
    if let Some(shape) = &node.text {
        match &shape.text {
            Some(t) => {
                out.insert(node.id.clone(), t.clone());
            }
            None => complete = false,
        }
    }
    for c in &node.children {
        if !collect_text(c, out) {
            complete = false;
        }
    }
    complete
}

/// A set of placeholder fills, one per view kind.
///
/// **Every fill here is a fabrication.** The shim's tree has no paint, so
/// there is no way to know what colour a `Button` was; a theme is a guess with
/// a shape, and it is tagged `Fabricated` on every command it produces so the
/// guess cannot be quoted as a measurement. [`Theme::none`] — the default — draws
/// nothing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    /// No fills. The default, and the only option that fabricates no ink.
    #[default]
    None,
    /// Flat placeholders, chosen to be obviously not a device's palette.
    Placeholder,
}

impl Theme {
    /// The fill for a node, or `None` for "there is no ink and there never was".
    pub fn fill_for(&self, kind: NodeKind) -> Option<Color> {
        match self {
            Theme::None => None,
            Theme::Placeholder => Some(match kind {
                NodeKind::Button => Color::argb_of(255, 200, 200, 200),
                NodeKind::EditText => Color::argb_of(255, 245, 245, 245),
                NodeKind::ImageView => Color::argb_of(255, 220, 230, 245),
                NodeKind::TextView => Color::argb_of(0, 0, 0, 0),
                _ => Color::argb_of(0, 0, 0, 0),
            }),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Theme::None => "none",
            Theme::Placeholder => "placeholder",
        }
    }
}

/// How to run a pass. Every bound has a default, and every default is the
/// conservative one.
#[derive(Debug, Clone, PartialEq)]
pub struct DrawConfig {
    pub viewport: Viewport,
    pub theme: Theme,
    pub text: TextSource,
    pub images: ImageSource,
    /// Fill for text ink. `None` means the default, black.
    pub text_color: Option<Color>,
    /// A gradient for text ink. If set, it is a fabrication of the same order as
    /// a themed fill and is tagged as one.
    pub text_shader: Option<Shader>,
    /// Draw the box outlines, the unknown-ink hatch and the withheld-text bands.
    /// These are annotations, not ink, and turning them off produces an *empty*
    /// display list, which is itself the most honest output of all.
    pub annotate: bool,
    /// Cap on the drawing recursion.
    pub max_depth: usize,
    /// Cap on the display list length.
    pub max_steps: usize,
}

impl Default for DrawConfig {
    fn default() -> DrawConfig {
        DrawConfig {
            viewport: Viewport {
                width_dp: 0.0,
                height_dp: 0.0,
                density: 1.0,
            },
            theme: Theme::None,
            text: TextSource::Withheld,
            images: ImageSource::none(),
            text_color: None,
            text_shader: None,
            annotate: true,
            max_depth: 1024,
            max_steps: 1_000_000,
        }
    }
}

impl DrawConfig {
    pub fn with_viewport(width_dp: f32, height_dp: f32, density: f32) -> DrawConfig {
        DrawConfig {
            viewport: Viewport {
                width_dp,
                height_dp,
                density,
            },
            ..DrawConfig::default()
        }
    }
}

/// What one pass observed. Every field is derivable from the display list, and
/// `tests/draw.rs` re-derives them from the serialised bytes rather than
/// trusting them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DrawReport {
    pub nodes_visited: usize,
    pub nodes_visible: usize,
    pub nodes_invisible: usize,
    /// Nodes with a `TextShape`, whether or not the characters survived.
    pub text_nodes: usize,
    pub text_with_characters: usize,
    /// `data-`sizes: total characters that reached the draw pass.
    pub characters: usize,
    /// Characters the shim's `TextPolicy` withheld.
    pub characters_withheld: usize,
    pub image_nodes: usize,
    pub images_with_bitmaps: usize,
    /// Areas with no ink, in dp². The headline: how much of the screen this
    /// layer could not speak for.
    pub unknown_ink_dp2: f64,
    /// The shim's own `leaf_area`, copied so the coverage fraction has a
    /// denominator that is not this layer's invention.
    pub leaf_area_dp2: u64,
    pub usage: MeasureUsage,
    pub theme: &'static str,
    pub text_policy: &'static str,
}

impl DrawReport {
    /// The fraction of the shim's leaf area this layer put ink in. `0.0` under
    /// the default config, and that is the number worth publishing.
    pub fn ink_coverage(&self) -> f64 {
        let total = self.leaf_area_dp2 as f64;
        if total <= 0.0 {
            return 0.0;
        }
        (1.0 - (self.unknown_ink_dp2.max(0.0) / total)).clamp(0.0, 1.0)
    }
}

/// Walk a box tree onto a canvas.
///
/// The recursion is bounded by `config.max_depth`; an app can nest views as
/// deeply as it likes and this function must not be the thing that overflows the
/// stack. `BoxNode` is built by the shim, which has its own recursion, so this
/// is a second, independent bound and not a redundant one.
pub fn draw_tree(
    tree: &BoxNode,
    config: &DrawConfig,
    measurer: &dyn TextMeasurer,
    canvas: &mut HeadlessCanvas,
) -> Result<DrawReport, GraphicsError> {
    config.viewport.checked()?;
    canvas.set_step_limit(config.max_steps);
    // `leaf_area` is the shim's own figure, `i64` and possibly negative on a
    // degenerate tree. Saturating at zero keeps the coverage denominator
    // non-negative without inventing a number.
    let leaf_area = tree.leaf_area().max(0) as u64;
    canvas.set_step_limit(config.max_steps);
    canvas.set_leaf_area(leaf_area);
    canvas.set_text_policy(config.text.policy_label());
    canvas.begin_frame(config.viewport.rect(), config.viewport.density)?;

    let mut report = DrawReport {
        leaf_area_dp2: leaf_area,
        theme: config.theme.label(),
        text_policy: config.text.policy_label(),
        ..DrawReport::default()
    };
    let mut unknown = 0.0f64;

    canvas.save()?;
    draw_node(
        tree,
        RectF::new(0.0, 0.0, 0.0, 0.0),
        0,
        config,
        measurer,
        canvas,
        &mut report,
        &mut unknown,
    )?;
    canvas.restore()?;

    report.unknown_ink_dp2 = unknown;
    // Cross-check the two ways of counting: the report and the canvas both
    // accumulate, and a disagreement is a bug in one of them. Surfaced rather
    // than silently reconciled.
    let counts = canvas.counts();
    if counts.unknown_ink_dp2 != unknown {
        // A floating-point sum in a different order is the only legitimate
        // source of a small difference; anything larger is a real divergence.
        let d = (counts.unknown_ink_dp2 - unknown).abs();
        if d > 0.5 {
            return Err(GraphicsError::Encode {
                what: "draw report",
                reason: format!("unknown-ink area disagrees by {d} dp^2"),
            });
        }
    }
    Ok(report)
}

/// One node, recursively. `pub(crate)` because [`crate::testutil`] drives the
/// same walk into the Canvas2D backend: the two backends must be exercised by
/// the *same* traversal, or a difference between their outputs could be a
/// difference in their walk rather than in their expressiveness.
#[allow(clippy::too_many_arguments)]
pub(crate) fn draw_node(
    node: &BoxNode,
    parent_origin: RectF,
    depth: usize,
    config: &DrawConfig,
    measurer: &dyn TextMeasurer,
    canvas: &mut dyn Canvas,
    report: &mut DrawReport,
    unknown: &mut f64,
) -> Result<(), GraphicsError> {
    if depth > config.max_depth {
        return Err(GraphicsError::TreeTooDeep {
            depth,
            limit: config.max_depth,
        });
    }
    report.nodes_visited += 1;

    // The shim drops GONE children from the tree, so this is defensive. A GONE
    // node that reaches here is still recorded, because a node that vanished
    // silently is exactly the kind of thing a study should see.
    if node.visibility == Visibility::Gone {
        report.nodes_invisible += 1;
        if config.annotate {
            canvas.annotate(
                Annotation::BoxOutline {
                    id: node.id.clone(),
                    rect: RectF::from_dp(
                        node.frame.left,
                        node.frame.top,
                        node.frame.right,
                        node.frame.bottom,
                    ),
                    state: ViewState::Gone,
                    kind: node.kind.as_str(),
                },
                // The rectangle is the shim's frame, unaltered. The *statement*
                // that the node is gone is this layer's; the frame is not.
                Provenance::ShimTreeExact,
            )?;
        }
        return Ok(());
    }

    // INVISIBLE occupies space and draws nothing — not its own onDraw, and not
    // its children's dispatchDraw. The outline says so, because a hole where a
    // view is reserved is a fact a reader needs.
    if node.visibility == Visibility::Invisible {
        report.nodes_invisible += 1;
        canvas.save()?;
        canvas.translate(node.frame.left as f32, node.frame.top as f32)?;
        if config.annotate {
            canvas.annotate(
                Annotation::BoxOutline {
                    id: node.id.clone(),
                    rect: RectF::new(0.0, 0.0, node.frame.width() as f32, node.frame.height() as f32),
                    state: ViewState::Invisible,
                    kind: node.kind.as_str(),
                },
                Provenance::ShimTreeExact,
            )?;
            canvas.annotate(
                Annotation::UnknownInk {
                    rect: RectF::new(0.0, 0.0, node.frame.width() as f32, node.frame.height() as f32),
                    reason: "view is INVISIBLE: it reserves space and paints nothing, on device too",
                },
                // There is no ink here, and that is the finding. Not a
                // fabricated value and not a tree value: an absence, labelled as
                // one.
                Provenance::Absent,
            )?;
            *unknown += node.frame.width() as f64 * node.frame.height() as f64;
        }
        canvas.restore()?;
        return Ok(());
    }

    report.nodes_visible += 1;
    let local = RectF::new(0.0, 0.0, node.frame.width() as f32, node.frame.height() as f32);

    canvas.save()?;
    canvas.translate(node.frame.left as f32, node.frame.top as f32)?;

    // A container clips its children, as `ViewGroup` does by default. Emitted
    // before anything inside, and the effective clip is recorded.
    let is_container = !node.children.is_empty();
    if is_container {
        canvas.clip_rect(local, false)?;
    }

    // --- ink ---------------------------------------------------------------
    match config.theme.fill_for(node.kind) {
        Some(c) => {
            // Fabricated: a `BoxNode` has no paint. The tag is on the step.
            let mut paint = Paint::new();
            paint.color = c;
            paint.style = PaintStyle::Fill;
            paint.anti_alias = true;
            if node.kind == NodeKind::Button || node.kind == NodeKind::EditText {
                // A themed button gets a hairline so the boxes are countable.
                // Still fabricated, still tagged: it is an annotation drawn as
                // ink, and the report says the theme was on.
                paint.style = PaintStyle::FillAndStroke;
                paint.stroke_width = 1.0;
            }
            canvas.draw_rect(local, &paint)?;
        }
        None => {
            // Only *leaves* contribute. The shim's `leaf_area` sums leaf boxes,
            // so a coverage figure that also counted parents would divide a
            // numerator by a denominator measuring different things, and the
            // "100% of the leaf area has no ink" claim would be arithmetic
            // rather than observation. A parent's area is its children's area.
            if config.annotate && !local.is_empty() && node.children.is_empty() {
                canvas.annotate(
                    Annotation::UnknownInk {
                        rect: local,
                        reason: NO_APP_PAINT,
                    },
                    Provenance::Absent,
                )?;
                *unknown += local.area();
            }
        }
    }

    // --- outline -----------------------------------------------------------
    if config.annotate {
        canvas.annotate(
            Annotation::BoxOutline {
                id: node.id.clone(),
                rect: local,
                state: ViewState::Visible,
                kind: node.kind.as_str(),
            },
            // The rectangle is the shim's frame. The fact that we draw an
            // outline at all is this layer's choice, and the header says the
            // outlines are not app ink — but the *number* is the shim's.
            Provenance::ShimTreeExact,
        )?;
    }

    // --- text --------------------------------------------------------------
    if let Some(shape) = &node.text {
        report.text_nodes += 1;
        match config.text.get(&node.id) {
            Some(s) => {
                report.text_with_characters += 1;
                report.characters += s.chars().count();
                let style = crate::measure::TextStyle {
                    size_sp: node_measured_text_size(&node.measured_width, &node.measured_height),
                    ..crate::measure::TextStyle::at(crate::measure::TextStyle::at(1.0).size_sp)
                };
                let m = measurer.measure(s, &style);
                report.usage.record(&m);
                match m {
                    Ok(adv) => {
                        // The baseline is `top + ascent`. With the default
                        // measurer the ascent is 0, so the baseline lands at the
                        // top of the view: visibly wrong rather than plausibly
                        // right. The x offset is the platform's own padding
                        // convention, which the shim's box tree does not carry
                        // per-node, so the shim's documented `PADDING` is used
                        // and named.
                        let run = TextRun {
                            id: node.id.clone(),
                            text: s.to_string(),
                            x: shim_padding(),
                            baseline: adv.ascent,
                            style,
                            advance: adv,
                        };
                        let mut paint = Paint::new();
                        paint.style = PaintStyle::Fill;
                        paint.anti_alias = true;
                        if let Some(c) = config.text_color {
                            paint.color = c;
                        }
                        if let Some(sh) = &config.text_shader {
                            paint.shader = Some(sh.clone());
                        }
                        canvas.draw_text_run(&run, &paint)?;
                    }
                    Err(_) => {
                        // The measurer refused. A refusal is a finding, not a
                        // failure of the pass: record it and move on, so one
                        // unmappable string does not cost the whole frame — and,
                        // crucially, so one refusal does not cost the *children*,
                        // which is why this is a branch and not an early return.
                        if config.annotate {
                            canvas.annotate(
                                Annotation::TextWithheld {
                                    id: node.id.clone(),
                                    rect: local,
                                    chars: s.chars().count(),
                                    classes: Vec::new(),
                                    shape: shape_label(shape),
                                },
                                Provenance::ShimTreeExact,
                            )?;
                        }
                    }
                }
            }
            None => {
                report.characters_withheld += shape.chars;
                let classes: Vec<(String, usize)> = shape
                    .classes
                    .iter()
                    .map(|(k, v)| (k.clone(), *v))
                    .collect();
                if config.annotate {
                    canvas.annotate(
                        Annotation::TextWithheld {
                            id: node.id.clone(),
                            rect: local,
                            // The shim recorded the length and the histogram.
                            // Both are its numbers, so both carry its provenance
                            // — the one place where the tree's own arithmetic
                            // reaches an annotation unaltered.
                            chars: shape.chars,
                            classes,
                            shape: shape_label(shape),
                        },
                        Provenance::ShimTreeExact,
                    )?;
                }
            }
        }
    }

    // --- image -------------------------------------------------------------
    if node.kind == NodeKind::ImageView || node.kind == NodeKind::Drawable {
        report.image_nodes += 1;
        match config.images.get(&node.id) {
            Some(bmp) => {
                report.images_with_bitmaps += 1;
                let img = ImageDraw {
                    id: node.id.clone(),
                    bitmap: bmp.clone(),
                    src: None,
                    dst: local,
                };
                let mut paint = Paint::new();
                paint.anti_alias = true;
                canvas.draw_image(&img, &paint)?;
                if bmp.is_decoded() {
                    // The pixels exist and are still not drawn. A distinct
                    // annotation, because "we have the bitmap and dropped it"
                    // and "we never had the bitmap" are different failures.
                    canvas.annotate(
                        Annotation::ImageNotEmbedded {
                            id: node.id.clone(),
                            rect: local,
                            width: bmp.width,
                            height: bmp.height,
                        },
                        Provenance::Absent,
                    )?;
                }
            }
            None if config.annotate => {
                canvas.annotate(
                    Annotation::ImageAbsent {
                        id: node.id.clone(),
                        rect: local,
                        reason: NO_BITMAP,
                    },
                    Provenance::Absent,
                )?;
            }
            None => {}
        }
    }

    // --- children ----------------------------------------------------------
    let child_origin = parent_origin.offset(node.frame.left as f32, node.frame.top as f32);
    for child in &node.children {
        draw_node(
            child,
            child_origin,
            depth + 1,
            config,
            measurer,
            canvas,
            report,
            unknown,
        )?;
    }

    canvas.restore()?;
    Ok(())
}

/// The shim's documented default padding, used as the text inset.
///
/// The box tree does not carry per-node padding, and inventing a per-kind inset
/// table would be a second fabrication on top of the missing glyphs. The shim's
/// own `metrics::PADDING` is a real number from a real model, so it is used and
/// named here.
fn shim_padding() -> f32 {
    shim::layout::metrics::PADDING as f32
}

/// A text size for the measurement. Derived from the node's own measured box,
/// so it is a function of the tree rather than a constant.
fn node_measured_text_size(width: &str, height: &str) -> f32 {
    // The shim records the *spec* strings, not numbers, so the only honest
    // source of a size is the frame the node was given. A leaf whose height is
    // known gives a line height; the shim's own model says a line is 16 dp with
    // 4 dp of padding top and bottom, so the text size is what is left.
    match (width.parse::<f32>(), height.parse::<f32>()) {
        (Ok(_), Ok(h)) if h > 2.0 * shim_padding() => {
            (h - 2.0 * shim_padding()).clamp(1.0, 4096.0)
        }
        _ => 14.0,
    }
}

/// The shape label for a withheld text node: which of the three guesses fired.
pub fn shape_label(shape: &shim::layout::TextShape) -> String {
    let mut v: Vec<&str> = Vec::new();
    if shape.looks_like_email {
        v.push("email");
    }
    if shape.looks_like_phone {
        v.push("phone");
    }
    if shape.looks_numeric {
        v.push("numeric");
    }
    if v.is_empty() {
        "plain".to_string()
    } else {
        v.join("+")
    }
}

/// Convenience: the whole pipeline, head to head, with the default
/// configuration. What a caller reaches for.
pub fn render(
    tree: &BoxNode,
    config: &DrawConfig,
    measurer: &dyn TextMeasurer,
) -> Result<(DisplayList, DrawReport), GraphicsError> {
    let mut canvas = HeadlessCanvas::new();
    let report = draw_tree(tree, config, measurer, &mut canvas)?;
    // The first measurement's model id goes in the header, so the reader knows
    // which seam produced the advances without a second call.
    let model = if report.usage.runs > 0 {
        measurer.model_id()
    } else {
        format!("{} (unused)", measurer.model_id())
    };
    let extra = report.usage.disclaimer();
    let list = canvas.finish(&extra);
    let mut list = list;
    list.measure_model = model;
    Ok((list, report))
}

/// A login-form-shaped tree, for the tests and for anyone who wants to see what
/// the default pipeline produces without wiring a tree together.
///
/// Built through the shim's own `View` API so the geometry is the shim's, not
/// this layer's. `TextPolicy::ShapeOnly` is used, which is why the rendering has
/// no text in it.
pub fn demo_tree(viewport_w: i32, viewport_h: i32) -> BoxNode {
    use shim::layout::{Dimension, Orientation, Size, View};
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut title = View::text("title", "TextView", NodeKind::TextView, "Sign in");
    title.layout_params.width = Dimension::MatchParent;
    root.add(title);
    let mut field = View::text(
        "email",
        "EditText",
        NodeKind::EditText,
        "person@example.invalid",
    );
    field.layout_params.width = Dimension::MatchParent;
    root.add(field);
    let mut button = View::text("go", "Button", NodeKind::Button, "Continue");
    button.layout_params.width = Dimension::Exact(120);
    root.add(button);
    root.run(
        Size {
            width: viewport_w,
            height: viewport_h,
        },
        TextPolicy::ShapeOnly,
    )
}

/// Build a tree that carries its characters, for the text-present path.
pub fn demo_tree_with_text(viewport_w: i32, viewport_h: i32) -> BoxNode {
    use shim::layout::{Dimension, Orientation, Size, View};
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut title = View::text("title", "TextView", NodeKind::TextView, "Sign in");
    title.layout_params.width = Dimension::MatchParent;
    root.add(title);
    let mut field = View::text(
        "email",
        "EditText",
        NodeKind::EditText,
        "person@example.invalid",
    );
    field.layout_params.width = Dimension::MatchParent;
    root.add(field);
    let mut button = View::text("go", "Button", NodeKind::Button, "Continue");
    button.layout_params.width = Dimension::Exact(120);
    root.add(button);
    root.run(
        Size {
            width: viewport_w,
            height: viewport_h,
        },
        TextPolicy::Include,
    )
}
