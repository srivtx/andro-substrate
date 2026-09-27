//! A real measure/layout/draw cycle producing a serialisable box tree.
//!
//! # Why a box tree and not a rendered frame
//!
//! The study needs to know *what the app asked the screen to be*, not what a
//! particular rasteriser produced from it. A pixel buffer would be lossy
//! (two different layouts can produce identical pixels at a given scale) and it
//! would be untestable: "does this PNG look right" is not an assertion. A box
//! tree is exact, cheap, diffable between a substrate run and a device run, and
//! assertable property by property. So the draw pass emits geometry, not
//! colour, and this file says so in its own output: every node carries
//! `painted: false` and there is no rasteriser anywhere in the crate.
//!
//! That also means `SUB.GFX.*` findings from this layer are *geometry* findings
//! only. Nothing here can detect a wrong-pixel bug, a shader failure or a
//! surface-format problem, and `shim/CONFORMANCE.md` says so.
//!
//! # Text measurement without a font
//!
//! Text is where a layout engine is most likely to fudge. This one does not
//! fudge: it uses a fixed, documented advance table (see [`metrics`]) keyed on
//! character class, so `measure` is a real function of the string and the same
//! string always measures the same. That makes measurement *deterministic and
//! testable*, which is what a comparison against a device needs. It is not
//! *accurate*: the numbers will not match a phone's Roboto, and the discrepancy
//! is exactly `SUB.GFX.TEXT_RENDER`. The class exposes
//! [`metrics::MODEL`] so a recording can state which model produced a tree.
//!
//! # Text is not recorded, only its shape
//!
//! An `EditText` holds whatever the user typed. Serialising it into a recording
//! would put a password into a JSON file, so [`TextPolicy`] defaults to
//! [`TextPolicy::ShapeOnly`]: the tree records the string's length, whether it
//! looks like an email, a phone number or a number, and its character classes —
//! never a character. `Include` exists for a study that has already decided its
//! inputs are synthetic, and the recording says which policy was used.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};


/// The font model. Documented, fixed, and named in the output.
pub mod metrics {
    /// Which model produced a measurement. Recorded so a number in a box tree is
    /// never mistaken for a device measurement.
    pub const MODEL: &str = "shim-advance-table/v1";

    /// Default line height in dp.
    pub const LINE_HEIGHT: i32 = 16;
    /// Default text size in dp.
    pub const TEXT_SIZE: i32 = 14;
    /// Horizontal padding in dp.
    pub const PADDING: i32 = 4;
    /// Extra horizontal inset a `Button` adds around its text.
    pub const BUTTON_INSET: i32 = 16;
    /// Extra vertical inset a `Button` adds.
    pub const BUTTON_INSET_V: i32 = 8;
    /// Height of a single-line `EditText` frame.
    pub const EDIT_TEXT_HEIGHT: i32 = 24;
    /// Default intrinsic size of a drawable-backed `ImageView`.
    pub const IMAGE_SIZE: i32 = 48;

    /// Advance width, in eighths of an em, for one character class.
    ///
    /// `wide` covers CJK and fullwidth forms, which on a real device are about
    /// twice the advance of a Latin letter; getting that wrong is a
    /// layout-visible difference, so the model has the class rather than one
    /// average.
    fn advance_eighths(c: char) -> u32 {
        let cp = c as u32;
        let wide = matches!(cp,
            0x1100..=0x115F      // Hangul Jamo
            | 0x2E80..=0xA4CF    // CJK radicals .. Yi
            | 0xAC00..=0xD7A3    // Hangul syllables
            | 0xF900..=0xFAFF    // CJK compatibility ideographs
            | 0xFF00..=0xFF60    // fullwidth forms
            | 0xFFE0..=0xFFE6);
        if wide {
            return 16;
        }
        match c {
            'i' | 'l' | 'j' | 'I' | '|' | '.' | ',' | ':' | ';' | '\'' | '!' => 4,
            'f' | 't' | 'r' | '(' | ')' | '[' | ']' | '/' | ' ' => 6,
            'm' | 'w' | 'M' | 'W' | '@' | '%' => 14,
            c if c.is_ascii_uppercase() => 12,
            c if c.is_ascii_digit() => 10,
            c if c.is_ascii_lowercase() => 10,
            _ => 10,
        }
    }

    /// The width of a single line of text, in dp, for a given text size.
    pub fn text_width(text: &str, size: i32) -> i32 {
        let eighths: u32 = text.chars().map(advance_eighths).sum();
        // Round up, because a text layout never truncates by rounding down and
        // then reporting a negative overflow.
        ((eighths * size as u32) as u64).div_ceil(8) as i32
    }

    /// The number of lines `text` needs at `width` dp. Wraps on spaces, like
    /// `StaticLayout` does for a body of text.
    pub fn line_count(text: &str, size: i32, width: i32) -> i32 {
        if text.is_empty() || width <= 0 {
            return if text.is_empty() { 0 } else { 1 };
        }
        let mut lines = 1;
        let mut cur = 0i32;
        for word in text.split(' ') {
            let w = text_width(word, size);
            if cur == 0 {
                cur = w;
            } else if cur + 4 + w <= width {
                cur += 4 + w;
            } else {
                lines += 1;
                cur = w;
            }
        }
        lines
    }

    /// The height of `text` at `width` dp.
    pub fn text_height(text: &str, size: i32, width: i32) -> i32 {
        line_count(text, size, width) * LINE_HEIGHT
    }
}

/// A rectangle, in dp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl Rect {
    pub fn width(&self) -> i32 {
        self.right.saturating_sub(self.left).max(0)
    }
    pub fn height(&self) -> i32 {
        self.bottom.saturating_sub(self.top).max(0)
    }
    pub fn is_empty(&self) -> bool {
        self.width() == 0 || self.height() == 0
    }
}

/// A size, in dp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Size {
    pub width: i32,
    pub height: i32,
}

/// How a child is sized by its parent. The subset of
/// `android.view.ViewGroup.LayoutParams` that a static box tree can honour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Dimension {
    /// Exactly this many dp.
    Exact(i32),
    /// Whatever the child measures to.
    WrapContent,
    /// Whatever the parent offers.
    MatchParent,
}

impl Dimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Dimension::Exact(_) => "exact",
            Dimension::WrapContent => "wrap_content",
            Dimension::MatchParent => "match_parent",
        }
    }
}

/// `ViewGroup.LayoutParams`, partial.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct LayoutParams {
    pub width: Dimension,
    pub height: Dimension,
    /// LinearLayout weight. `1.0` is the whole of the leftover space.
    pub weight: f32,
    pub margin_left: i32,
    pub margin_top: i32,
    pub margin_right: i32,
    pub margin_bottom: i32,
    /// `android.view.Gravity`, as a bitmask, using the **real** platform
    /// constants: `LEFT = 0x03`, `RIGHT = 0x05`, `TOP = 0x30`, `BOTTOM = 0x50`,
    /// `CENTER_HORIZONTAL = 0x01`, `CENTER_VERTICAL = 0x10`.
    ///
    /// The real values, not convenient ones. A shim that invented its own bitmask
    /// would mis-place every gravity an app sets, and a wrong layout that looks
    /// plausible is a worse failure than a layout that is obviously absent.
    pub gravity: i32,
}

impl Default for LayoutParams {
    fn default() -> LayoutParams {
        LayoutParams {
            width: Dimension::WrapContent,
            height: Dimension::WrapContent,
            weight: 0.0,
            margin_left: 0,
            margin_top: 0,
            margin_right: 0,
            margin_bottom: 0,
            gravity: 0x33, // TOP | LEFT, the platform's own values
        }
    }
}

impl LayoutParams {
    fn horizontal_margin(&self) -> i32 {
        self.margin_left.saturating_add(self.margin_right)
    }
    fn vertical_margin(&self) -> i32 {
        self.margin_top.saturating_add(self.margin_bottom)
    }
}

/// `View.VISIBLE` and the one other value that changes a box tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Visible,
    Invisible,
    Gone,
}

/// What a node is, for the box tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    View,
    ViewGroup,
    TextView,
    Button,
    EditText,
    ImageView,
    LinearLayout,
    FrameLayout,
    Drawable,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeKind::View => "view",
            NodeKind::ViewGroup => "viewgroup",
            NodeKind::TextView => "textview",
            NodeKind::Button => "button",
            NodeKind::EditText => "edittext",
            NodeKind::ImageView => "imageview",
            NodeKind::LinearLayout => "linearlayout",
            NodeKind::FrameLayout => "framelayout",
            NodeKind::Drawable => "drawable",
        }
    }
}

/// How much of a string reaches the box tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextPolicy {
    /// No characters, ever.
    Omit,
    /// Length, character-class histogram, and three shape guesses.
    ShapeOnly,
    /// The characters. Only for captures whose inputs are known-synthetic.
    Include,
}

impl TextPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            TextPolicy::Omit => "omit",
            TextPolicy::ShapeOnly => "shape-only",
            TextPolicy::Include => "include",
        }
    }
}

/// What a box tree says about a string without containing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextShape {
    /// Number of Unicode scalar values.
    pub chars: usize,
    /// Counts by class: `letter`, `digit`, `space`, `punct`, `other`.
    pub classes: BTreeMap<String, usize>,
    /// `@`-present and a dot after it.
    pub looks_like_email: bool,
    /// Nine or more digits, optionally with `+`, `-`, spaces and brackets.
    pub looks_like_phone: bool,
    /// Parses as a signed decimal integer.
    pub looks_numeric: bool,
    /// The characters, only under [`TextPolicy::Include`].
    pub text: Option<String>,
}

impl TextShape {
    /// Derive a shape from a string. The only place a string is read, and the
    /// only place the result can lose it.
    pub fn of(text: &str, policy: TextPolicy) -> TextShape {
        let mut classes: BTreeMap<String, usize> = BTreeMap::new();
        let mut digits = 0usize;
        let mut phoneish = 0usize;
        for c in text.chars() {
            let key = if c.is_alphabetic() {
                "letter"
            } else if c.is_ascii_digit() {
                digits += 1;
                "digit"
            } else if c.is_whitespace() {
                "space"
            } else if c.is_ascii_punctuation() {
                phoneish += 1;
                "punct"
            } else {
                "other"
            };
            *classes.entry(key.to_string()).or_insert(0) += 1;
        }
        let body: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        let phone_digits = body.chars().filter(|c| c.is_ascii_digit()).count();
        TextShape {
            chars: text.chars().count(),
            classes,
            looks_like_email: body.contains('@')
                && body
                    .split_once('@')
                    .map(|(a, b)| !a.is_empty() && b.contains('.') && !b.starts_with('.'))
                    .unwrap_or(false),
            looks_like_phone: phone_digits >= 9 && phoneish > 0,
            looks_numeric: !text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '-' || c == '+' || c == '.')
                && digits > 0,
            text: match policy {
                TextPolicy::Omit => None,
                TextPolicy::ShapeOnly => None,
                TextPolicy::Include => Some(text.to_string()),
            },
        }
    }
}

/// One node of a drawn box tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxNode {
    /// The app-supplied view id, or a synthesised `path`-derived one.
    pub id: String,
    pub class: String,
    pub kind: NodeKind,
    pub frame: Rect,
    /// `MeasureSpec` resolution of the width and height, as strings, so a reader
    /// can tell `Exact(0)` from `WrapContent` resolving to 0.
    pub measured_width: String,
    pub measured_height: String,
    pub visibility: Visibility,
    /// The text shape. `None` for a view with no text.
    pub text: Option<TextShape>,
    /// `false`, always. This layer produces geometry and no raster output, and
    /// the field is present so that no reader has to infer it.
    pub painted: bool,
    pub children: Vec<BoxNode>,
}

impl BoxNode {
    /// Total nodes in this subtree, including itself.
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(BoxNode::count).sum::<usize>()
    }

    /// Total area of the subtree, in dp², counting only leaves. Overlapping
    /// boxes are counted twice, which is the point: a `FrameLayout` that stacks
    /// two children is *using* the area twice and a study should see it.
    pub fn leaf_area(&self) -> i64 {
        if self.children.is_empty() {
            (self.frame.width() as i64) * (self.frame.height() as i64)
        } else {
            self.children.iter().map(BoxNode::leaf_area).sum()
        }
    }

    /// A flat `id -> frame` list, for a diff between two runs.
    pub fn flatten(&self) -> Vec<(String, Rect)> {
        let mut out = vec![(self.id.clone(), self.frame)];
        for c in &self.children {
            out.extend(c.flatten());
        }
        out
    }
}

/// `LinearLayout` orientation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Orientation {
    Vertical,
    Horizontal,
}

/// A `View` in the shim's view tree.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    pub id: String,
    pub class: String,
    pub kind: NodeKind,
    pub visibility: Visibility,
    pub layout_params: LayoutParams,
    pub padding: i32,
    /// The string a `TextView`/`Button`/`EditText` holds. Held in memory because
    /// the app put it there, and *not* copied into a box tree unless the
    /// recording's `TextPolicy` says so.
    pub text: String,
    /// Intrinsic size for a drawable-backed view.
    pub intrinsic: Option<Size>,
    pub measured: Size,
    pub frame: Rect,
    /// Children, empty for a leaf.
    pub children: Vec<View>,
    pub orientation: Orientation,
}

impl View {
    /// A leaf view.
    pub fn leaf(id: &str, class: &str, kind: NodeKind) -> View {
        View {
            id: id.to_string(),
            class: class.to_string(),
            kind,
            visibility: Visibility::Visible,
            layout_params: LayoutParams::default(),
            padding: metrics::PADDING,
            text: String::new(),
            intrinsic: None,
            measured: Size::default(),
            frame: Rect::default(),
            children: Vec::new(),
            orientation: Orientation::Vertical,
        }
    }

    /// A view with a text body.
    pub fn text(id: &str, class: &str, kind: NodeKind, text: &str) -> View {
        let mut v = View::leaf(id, class, kind);
        v.text = text.to_string();
        v
    }

    /// A container.
    pub fn group(id: &str, class: &str, kind: NodeKind, orientation: Orientation) -> View {
        let mut v = View::leaf(id, class, kind);
        v.orientation = orientation;
        v
    }

    /// Add a child and return the child, for chaining.
    pub fn add(&mut self, child: View) -> &mut View {
        self.children.push(child);
        self
    }

    /// The node's own preferred size, ignoring the parent's offer. This is the
    /// `onMeasure` intrinsic size.
    pub fn intrinsic_size(&self) -> Size {
        match self.kind {
            NodeKind::TextView => Size {
                width: metrics::text_width(&self.text, metrics::TEXT_SIZE) + 2 * self.padding,
                height: metrics::LINE_HEIGHT + 2 * self.padding,
            },
            NodeKind::Button => Size {
                width: metrics::text_width(&self.text, metrics::TEXT_SIZE)
                    + 2 * self.padding
                    + metrics::BUTTON_INSET,
                height: metrics::LINE_HEIGHT + 2 * self.padding + metrics::BUTTON_INSET_V,
            },
            NodeKind::EditText => Size {
                // An EditText is scrollable and does not grow with its content,
                // which is the detail that makes an overflowing login form
                // behave the way it does.
                width: 120 + 2 * self.padding,
                height: metrics::EDIT_TEXT_HEIGHT + 2 * self.padding,
            },
            NodeKind::ImageView => self.intrinsic.unwrap_or(Size {
                width: metrics::IMAGE_SIZE,
                height: metrics::IMAGE_SIZE,
            }),
            NodeKind::Drawable => self.intrinsic.unwrap_or(Size { width: 0, height: 0 }),
            _ => Size::default(),
        }
    }

    /// `measure`: resolve this subtree's size given the offered space, exactly
    /// as `View.onMeasure` would with a matching `MeasureSpec`.
    pub fn measure(&mut self, offered: Size) -> Size {
        let available_w = offered.width.max(0);
        let available_h = offered.height.max(0);
        let lm = self.layout_params;
        let horizontal_margin = lm.horizontal_margin();
        let vertical_margin = lm.vertical_margin();
        let intrinsic = self.intrinsic_size();
        let kind = self.kind;
        let is_container = matches!(
            kind,
            NodeKind::ViewGroup | NodeKind::LinearLayout | NodeKind::FrameLayout
        );

        if !is_container {
            let m = match lm.width {
                Dimension::Exact(w) => w.saturating_sub(horizontal_margin).max(0),
                Dimension::MatchParent => available_w.saturating_sub(horizontal_margin).max(0),
                Dimension::WrapContent => match kind {
                    NodeKind::TextView | NodeKind::Button => metrics::text_width(
                        &self.text,
                        metrics::TEXT_SIZE,
                    )
                    .saturating_add(2 * self.padding + horizontal_margin)
                    .max(intrinsic.width),
                    _ => intrinsic.width,
                },
            };
            let h = match lm.height {
                Dimension::Exact(h) => h.saturating_sub(vertical_margin).max(0),
                Dimension::MatchParent => available_h.saturating_sub(vertical_margin).max(0),
                Dimension::WrapContent => match kind {
                    NodeKind::TextView | NodeKind::Button => metrics::text_height(
                        &self.text,
                        metrics::TEXT_SIZE,
                        m.saturating_sub(2 * self.padding).max(1),
                    )
                    .saturating_add(2 * self.padding + vertical_margin),
                    _ => intrinsic.height,
                },
            };
            self.measured = Size { width: m, height: h };
            return self.measured;
        }

        // --- container: measure every child first.
        let pad_x = 2 * self.padding + horizontal_margin;
        let pad_y = 2 * self.padding + vertical_margin;
        let child_params: Vec<LayoutParams> =
            self.children.iter().map(|c| c.layout_params).collect();
        let mut child_sizes: Vec<Size> = Vec::with_capacity(self.children.len());
        for (i, c) in self.children.iter_mut().enumerate() {
            let child_offered = if kind == NodeKind::LinearLayout && self.orientation == Orientation::Horizontal
            {
                // A horizontal LinearLayout hands each child what is left, so a
                // child's own measurement is not independent of its position.
                let used: i32 = child_sizes
                    .iter()
                    .zip(&child_params)
                    .map(|(s, p)| s.width + p.horizontal_margin())
                    .sum::<i32>()
                    + child_params
                        .get(i)
                        .map(|p| p.margin_left)
                        .unwrap_or(0);
                Size {
                    width: (available_w - used).max(0),
                    height: available_h,
                }
            } else {
                Size {
                    width: available_w,
                    height: available_h,
                }
            };
            child_sizes.push(c.measure(child_offered));
        }

        let params = child_params;
        let has_weight = params.iter().any(|p| p.weight > 0.0);

        // The padding is part of the container's size on both axes. Omitting it
        // is the classic wrap-content bug: the children are then laid out
        // *outside* the frame the parent reserved for them, and every
        // children-inside-parent assertion downstream fails for a reason that
        // looks like a rounding error and is not.
        let (mut m, mut h) = match (kind, self.orientation) {
            (NodeKind::LinearLayout, Orientation::Horizontal) => {
                let main = if has_weight {
                    // Real LinearLayout: with a weighted child the main axis
                    // takes the whole offer, because the weight is about
                    // dividing a known space, not about a wrap-content guess.
                    available_w.saturating_sub(pad_x)
                } else {
                    child_sizes
                        .iter()
                        .zip(&params)
                        .map(|(s, p)| s.width + p.horizontal_margin())
                        .sum::<i32>()
                        .saturating_add(pad_x)
                };
                let cross = child_sizes
                    .iter()
                    .map(|s| s.height)
                    .max()
                    .unwrap_or(0)
                    .max(intrinsic.height)
                    .saturating_add(pad_y);
                (main, cross)
            }
            (NodeKind::LinearLayout, Orientation::Vertical) => {
                let cross = child_sizes
                    .iter()
                    .map(|s| s.width)
                    .max()
                    .unwrap_or(0)
                    .max(intrinsic.width)
                    .saturating_add(pad_x);
                let main = if has_weight {
                    available_h.saturating_sub(pad_y)
                } else {
                    child_sizes
                        .iter()
                        .zip(&params)
                        .map(|(s, p)| s.height + p.vertical_margin())
                        .sum::<i32>()
                        .saturating_add(pad_y)
                };
                (cross, main)
            }
            // FrameLayout: wrap-content is the largest child on each axis, plus
            // the container's own padding.
            _ => (
                child_sizes
                    .iter()
                    .map(|s| s.width)
                    .max()
                    .unwrap_or(0)
                    .max(intrinsic.width)
                    .saturating_add(pad_x),
                child_sizes
                    .iter()
                    .map(|s| s.height)
                    .max()
                    .unwrap_or(0)
                    .max(intrinsic.height)
                    .saturating_add(pad_y),
            ),
        };

        m = match lm.width {
            Dimension::Exact(w) => w.saturating_sub(horizontal_margin).max(0),
            Dimension::MatchParent => available_w.saturating_sub(horizontal_margin).max(0),
            Dimension::WrapContent => m.max(0),
        };
        h = match lm.height {
            Dimension::Exact(v) => v.saturating_sub(vertical_margin).max(0),
            Dimension::MatchParent => available_h.saturating_sub(vertical_margin).max(0),
            Dimension::WrapContent => h.max(0),
        };

        self.measured = Size { width: m, height: h };
        self.measured
    }

    /// `layout`: place this subtree inside `frame`, honouring the parent's
    /// orientation, weights and gravity.
    pub fn layout(&mut self, frame: Rect) {
        self.frame = frame;
        if self.children.is_empty() {
            return;
        }
        let lm = self.layout_params;
        let inner = Rect {
            left: frame.left + self.padding + lm.margin_left,
            top: frame.top + self.padding + lm.margin_top,
            right: frame.right - self.padding - lm.margin_right,
            bottom: frame.bottom - self.padding - lm.margin_bottom,
        };
        let inner_w = inner.width();
        let inner_h = inner.height();

        let child_params: Vec<LayoutParams> =
            self.children.iter().map(|c| c.layout_params).collect();
        let kind = self.kind;
        let orientation = self.orientation;
        let total_weight: f32 = child_params.iter().map(|p| p.weight).sum();
        let total_margin_main: i32 = match orientation {
            Orientation::Vertical => child_params.iter().map(|p| p.vertical_margin()).sum(),
            Orientation::Horizontal => child_params.iter().map(|p| p.horizontal_margin()).sum(),
        };
        let main_extent = match orientation {
            Orientation::Vertical => inner_h,
            Orientation::Horizontal => inner_w,
        };
        // Space left after every unweighted child's margin.
        let used_by_unweighted: i32 = child_params
            .iter()
            .zip(&self.children)
            .filter(|(p, _)| p.weight <= 0.0)
            .map(|(p, c)| match orientation {
                Orientation::Vertical => c.measured.height + p.vertical_margin(),
                Orientation::Horizontal => c.measured.width + p.horizontal_margin(),
            })
            .sum();
        let leftover = (main_extent - total_margin_main - used_by_unweighted).max(0);

        let mut cursor = match orientation {
            Orientation::Vertical => inner.top,
            Orientation::Horizontal => inner.left,
        };

        for (i, child) in self.children.iter_mut().enumerate() {
            let p = child_params.get(i).copied().unwrap_or_default();
            let extra = if p.weight > 0.0 && total_weight > 0.0 {
                ((leftover as f32) * (p.weight / total_weight)).round() as i32
            } else {
                0
            };
            let child_frame = match kind {
                NodeKind::LinearLayout => {
                    let (w, h) = match orientation {
                        Orientation::Vertical => (
                            match p.width {
                                Dimension::Exact(w) => w,
                                Dimension::MatchParent => inner_w,
                                Dimension::WrapContent => child.measured.width,
                            }
                            .max(0),
                            child.measured.height + extra,
                        ),
                        Orientation::Horizontal => (
                            child.measured.width + extra,
                            match p.height {
                                Dimension::Exact(h) => h,
                                Dimension::MatchParent => inner_h,
                                Dimension::WrapContent => child.measured.height,
                            }
                            .max(0),
                        ),
                    };
                    let (l, t) = match orientation {
                        Orientation::Vertical => (inner.left + p.margin_left, cursor + p.margin_top),
                        Orientation::Horizontal => (cursor + p.margin_left, inner.top + p.margin_top),
                    };
                    Rect {
                        left: l,
                        top: t,
                        right: l.saturating_add(w),
                        bottom: t.saturating_add(h),
                    }
                }
                _ => {
                    // FrameLayout: gravity decides, and every child is offered
                    // the full frame so `match_parent` behaves.
                    let w = match p.width {
                        Dimension::MatchParent => inner_w,
                        Dimension::Exact(w) => w,
                        Dimension::WrapContent => child.measured.width,
                    };
                    let h = match p.height {
                        Dimension::MatchParent => inner_h,
                        Dimension::Exact(h) => h,
                        Dimension::WrapContent => child.measured.height,
                    };
                    let l = inner.left
                        + p.margin_left
                        + gravity_offset(p.gravity & 0x07, inner_w - w);
                    let t =
                        inner.top + p.margin_top + gravity_offset(p.gravity & 0x70, inner_h - h);
                    Rect {
                        left: l,
                        top: t,
                        right: l.saturating_add(w),
                        bottom: t.saturating_add(h),
                    }
                }
            };
            child.layout(child_frame);
            cursor = match orientation {
                Orientation::Vertical => {
                    child_frame.bottom + child_params.get(i).map(|p| p.margin_bottom).unwrap_or(0)
                }
                Orientation::Horizontal => {
                    child_frame.right + child_params.get(i).map(|p| p.margin_right).unwrap_or(0)
                }
            };
        }
    }

    /// `draw`: produce the serialisable box tree. No rasterisation happens and
    /// none is possible; see the module docs.
    pub fn draw(&self, policy: TextPolicy) -> BoxNode {
        let has_text = matches!(
            self.kind,
            NodeKind::TextView | NodeKind::Button | NodeKind::EditText
        );
        BoxNode {
            id: self.id.clone(),
            class: self.class.clone(),
            kind: self.kind,
            frame: self.frame,
            measured_width: self.layout_params.width.as_str().to_string(),
            measured_height: self.layout_params.height.as_str().to_string(),
            visibility: self.visibility,
            text: if has_text {
                Some(TextShape::of(&self.text, policy))
            } else {
                None
            },
            painted: false,
            children: self
                .children
                .iter()
                .filter(|c| c.visibility != Visibility::Gone)
                .map(|c| c.draw(policy))
                .collect(),
        }
    }

    /// The full cycle: measure, layout, draw.
    pub fn run(&mut self, viewport: Size, policy: TextPolicy) -> BoxNode {
        let m = self.measure(viewport);
        self.layout(Rect {
            left: 0,
            top: 0,
            right: m.width,
            bottom: m.height,
        });
        self.draw(policy)
    }
}

/// The `Gravity` constants the shim honours, with the platform's own values.
pub mod gravity {
    pub const CENTER_HORIZONTAL: i32 = 0x01;
    pub const LEFT: i32 = 0x03;
    pub const RIGHT: i32 = 0x05;
    pub const CENTER_VERTICAL: i32 = 0x10;
    pub const TOP: i32 = 0x30;
    pub const BOTTOM: i32 = 0x50;
    pub const CENTER: i32 = CENTER_HORIZONTAL | CENTER_VERTICAL;
    pub const TOP_LEFT: i32 = TOP | LEFT;
}

/// The `Gravity` offset for one axis.
///
/// `axis` is the *already masked* value: `gravity & 0x07` for the horizontal
/// axis and `gravity & 0x70` for the vertical. That matters, because the
/// platform's constants overlap: `LEFT` is `0x03`, so a test for "the right bit
/// is set" is true of `LEFT` as well as `RIGHT` and would pin every left-gravity
/// child to the right edge. The masked values are disjoint, so they are matched
/// exactly.
fn gravity_offset(axis: i32, space: i32) -> i32 {
    let space = space.max(0);
    match axis {
        gravity::RIGHT | gravity::BOTTOM => space,
        gravity::CENTER_HORIZONTAL | gravity::CENTER_VERTICAL => space / 2,
        // `LEFT`, `TOP`, and an axis with no gravity at all.
        _ => 0,
    }
}

/// The result of a layout pass, plus the observation it produced.
#[derive(Debug, Clone, PartialEq)]
pub struct LayoutPass {
    /// The tree the app asked for.
    pub tree: BoxNode,
    /// The viewport it was laid out in.
    pub viewport: Size,
    /// `SIGNAL_PAT.LAYOUT_PASS`. The oracle's `diagnostic` family enum has no
    /// entry for layout, so this is recorded in `probes` with a null family and
    /// the `SUB.GFX.TEXT_RENDER` ID carries the meaning.
    pub pattern: &'static str,
}

impl fmt::Display for LayoutPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} nodes in {}x{} dp ({} dp^2 of leaf area), model {}",
            self.tree.count(),
            self.viewport.width,
            self.viewport.height,
            self.tree.leaf_area(),
            metrics::MODEL
        )
    }
}

/// Serialise a box tree to JSON.
pub fn tree_to_json(tree: &BoxNode) -> Result<String, crate::error::ShimError> {
    serde_json::to_string(tree)
        .map_err(|e| crate::error::ShimError::Encode(format!("box tree: {e}")))
}

/// Serialise a box tree for the `probes[].output` field, truncating to the
/// oracle's 8000-byte ceiling and reporting whether it did.
pub fn tree_for_probe(tree: &BoxNode, max_bytes: usize) -> (String, bool) {
    /// Appended when the tree did not fit. Its own length is reserved, because a
    /// marker that pushes the output *over* the ceiling is a marker the reader
    /// will never see: the field would fail its `maxLength` and the whole
    /// recording would be rejected.
    const MARKER: &str = ",\"truncated\":true}";
    match tree_to_json(tree) {
        Ok(s) if s.len() <= max_bytes => (s, false),
        Ok(s) => {
            let budget = max_bytes.saturating_sub(MARKER.len());
            let mut cut = budget.min(s.len());
            while cut > 0 && !s.is_char_boundary(cut) {
                cut -= 1;
            }
            let head = &s[..cut];
            // Close on a whole node boundary where one exists, so the output is
            // still valid JSON and a reader can tell it is incomplete.
            let close = head.rfind("]}").map(|i| &head[..i]).unwrap_or(head);
            let out = format!("{close}{MARKER}");
            (out[..max_bytes.min(out.len())].to_string(), true)
        }
        Err(e) => (format!("{{\"error\":\"{e}\"}}"), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vertical() -> View {
        let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
        root.layout_params.width = Dimension::MatchParent;
        root.add(View::text("title", "TextView", NodeKind::TextView, "Sign in"));
        let mut field = View::text("email", "EditText", NodeKind::EditText, "someone@example.invalid");
        field.layout_params.width = Dimension::MatchParent;
        root.add(field);
        let mut b = View::text("go", "Button", NodeKind::Button, "Continue");
        b.layout_params.width = Dimension::Exact(120);
        root.add(b);
        root
    }

    #[test]
    fn a_vertical_linear_layout_stacks_and_grows() {
        let mut v = vertical();
        let t = v.run(Size { width: 360, height: 640 }, TextPolicy::ShapeOnly);
        let flat = t.flatten();
        let by_id = |id: &str| flat.iter().find(|(k, _)| k == id).map(|(_, r)| *r).unwrap();
        let title = by_id("title");
        let email = by_id("email");
        let go = by_id("go");
        assert!(title.bottom <= email.top, "title must sit above the field");
        assert!(email.bottom <= go.top, "field must sit above the button");
        assert_eq!(go.width(), 120);
        assert_eq!(email.width(), 360 - 2 * metrics::PADDING);
    }

    #[test]
    fn weights_distribute_the_leftover_space() {
        let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Horizontal);
        root.layout_params.width = Dimension::MatchParent;
        let mut a = View::leaf("a", "View", NodeKind::View);
        a.layout_params.weight = 1.0;
        let mut b = View::leaf("b", "View", NodeKind::View);
        b.layout_params.weight = 1.0;
        root.add(a);
        root.add(b);
        let t = root.run(Size { width: 100, height: 10 }, TextPolicy::Omit);
        let flat = t.flatten();
        let a = flat.iter().find(|(k, _)| k == "a").unwrap().1;
        let b = flat.iter().find(|(k, _)| k == "b").unwrap().1;
        // 100 dp offered, 4 dp padding each side, so 92 to divide: 46 each.
        assert_eq!(a.width(), 46);
        assert_eq!(b.width(), 46);
        assert_eq!(b.left, a.right);
    }

    #[test]
    fn gone_children_are_dropped_and_invisible_ones_kept() {
        let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
        root.add(View::leaf("keep", "View", NodeKind::View));
        let mut gone = View::leaf("gone", "View", NodeKind::View);
        gone.visibility = Visibility::Gone;
        root.add(gone);
        let mut invisible = View::leaf("inv", "View", NodeKind::View);
        invisible.visibility = Visibility::Invisible;
        root.add(invisible);
        let t = root.run(Size { width: 100, height: 100 }, TextPolicy::Omit);
        let flat = t.flatten();
        let ids: Vec<&str> = flat.iter().map(|(k, _)| k.as_str()).collect();
        assert!(ids.contains(&"inv"));
        assert!(!ids.contains(&"gone"));
    }

    #[test]
    fn text_never_appears_in_the_default_policy() {
        let mut v = vertical();
        let t = v.run(Size { width: 360, height: 640 }, TextPolicy::ShapeOnly);
        let json = tree_to_json(&t).unwrap();
        assert!(!json.contains("someone@example.invalid"), "text leaked: {json}");
        assert!(!json.contains("Sign in"));
        // But the shape is there, and it is enough to say "this field holds an
        // email address" without holding the address.
        t
            .flatten()
            .into_iter()
            .find(|(k, _)| k == "email")
            .map(|_| ())
            .unwrap();
        assert_eq!((), ());
        let node = find(&t, "email");
        let shape = node.text.as_ref().expect("a text shape");
        assert_eq!(shape.chars, "someone@example.invalid".chars().count());
        assert!(shape.looks_like_email);
        assert!(shape.text.is_none());
    }

    #[test]
    fn the_include_policy_is_opt_in() {
        let mut v = vertical();
        let t = v.run(Size { width: 360, height: 640 }, TextPolicy::Include);
        let json = tree_to_json(&t).unwrap();
        assert!(json.contains("Sign in"));
    }

    #[test]
    fn frame_layout_honours_gravity() {
        let mut root = View::group("root", "FrameLayout", NodeKind::FrameLayout, Orientation::Vertical);
        root.layout_params.width = Dimension::MatchParent;
        let mut c = View::leaf("c", "View", NodeKind::View);
        c.layout_params.width = Dimension::Exact(10);
        c.layout_params.height = Dimension::Exact(10);
        c.layout_params.gravity = 0x11 | 0x01; // TOP|LEFT|CENTER_HORIZONTAL
        root.add(c);
        let t = root.run(Size { width: 100, height: 100 }, TextPolicy::Omit);
        let rect = t.flatten().into_iter().find(|(k, _)| k == "c").unwrap().1;
        // 100 dp wide, 4 dp padding each side, a 10 dp child, centred: the 82 dp
        // of slack splits evenly, so the child starts at 4 + 41.
        assert_eq!(rect.left, metrics::PADDING + 41);
        assert_eq!(rect.width(), 10);
    }

    #[test]
    fn zero_sized_viewport_does_not_panic() {
        let mut v = vertical();
        let t = v.run(Size { width: 0, height: 0 }, TextPolicy::Omit);
        assert_eq!(t.frame.width(), 0);
    }

    #[test]
    fn leaf_area_counts_overlap_twice() {
        let mut root = View::group("root", "FrameLayout", NodeKind::FrameLayout, Orientation::Vertical);
        root.layout_params.width = Dimension::MatchParent;
        for id in ["a", "b"] {
            let mut v = View::leaf(id, "View", NodeKind::View);
            v.layout_params.width = Dimension::Exact(10);
            v.layout_params.height = Dimension::Exact(10);
            root.add(v);
        }
        let t = root.run(Size { width: 50, height: 50 }, TextPolicy::Omit);
        assert_eq!(t.leaf_area(), 200);
    }

    fn find<'a>(n: &'a BoxNode, id: &str) -> &'a BoxNode {
        if n.id == id {
            return n;
        }
        for c in &n.children {
            if let Some(f) = find_opt(c, id) {
                return f;
            }
        }
        panic!("no node {id}");
    }

    fn find_opt<'a>(n: &'a BoxNode, id: &str) -> Option<&'a BoxNode> {
        if n.id == id {
            return Some(n);
        }
        for c in &n.children {
            if let Some(f) = find_opt(c, id) {
                return Some(f);
            }
        }
        None
    }
}
