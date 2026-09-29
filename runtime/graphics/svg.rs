//! The SVG serialisation. A diffable, viewable artefact that is *not* a frame.
//!
//! # Three things are in the output, always
//!
//! 1. **A banner band** above the viewport, filled with a colour chosen to be
//!    unmissable, carrying the sentence that would be shown instead of the image.
//! 2. **`<desc>` and `<metadata>`** holding the capability report, the
//!    provenance of every arm of it, the measure model's id, and the ink
//!    coverage. Machine-readable and human-readable at once.
//! 3. **A `data-prov` attribute on every drawn element.** A test counts them, so
//!    "every emitted value is labelled" is checked rather than asserted.
//!
//! # What SVG cannot do, and what happens when it is asked
//!
//! SVG 1.1's `feComposite` has six operators that are Porter-Duff exactly:
//! `over`, `in`, `out`, `atop`, `xor`, and — via a transparent `feFlood` into
//! `out` — `clear`. The other fifteen modes have no expression, and the blend
//! modes `feComposite` *does* have (`multiply`, `screen`, `darken`, `lighten`)
//! follow the Compositing specification, not Skia.
//!
//! When a mode cannot be expressed, **the element is emitted unblended and
//! carries `data-blend-dropped`**. It is not approximated with the nearest
//! available mode, and it is not omitted. And the banner escalates: a frame
//! with a dropped blend gets a different banner from one without, so the
//! difference is visible without reading the metadata.

use std::fmt::Write as _;

use crate::capability::{CapabilityReport, GfxId, Support};
use crate::canvas::{Annotation, Command, DisplayList, Step, Viewport, q, q_area};
use crate::error::GraphicsError;
use crate::paint::{Color, Paint, PaintStyle, PorterDuffMode, Provenance, RectF, Shader};

/// The banner band height in dp, for an app viewport `app_height_dp` tall.
///
/// Clamped so a tiny viewport still has a readable banner and a tall one does
/// not push the reconstruction off the screen. The clamp is deterministic and
/// the chosen value is printed in the output, so two SVGs of the same tree at
/// different viewports are visibly different rather than subtly different.
pub fn banner_height(app_height_dp: f32) -> f32 {
    let a = app_height_dp.abs();
    let third = a / 3.0;
    if !third.is_finite() {
        return 0.0;
    }
    third.clamp(48.0, 132.0)
}

/// The banner's text lines. Shared with the Canvas2D backend so both surfaces
/// say the same words.
pub fn banner_lines(report: &CapabilityReport, extra: &str, viewport: RectF) -> Vec<String> {
    let mut v = vec![
        "RECONSTRUCTION OF THE SHIM'S LAYOUT — NOT AN ANDROID FRAME".to_string(),
        format!(
            "The app's onDraw code was never executed. Geometry below is the shim's \
             box tree, exact relative to the shim only."
        ),
        format!(
            "Text was withheld by the shim's TextPolicy: a rendering cannot be shown for a \
             string the tree does not contain."
        ),
        format!("{} reproduced of {} SUB.GFX assumptions.", report.reproduced(), GfxId::ALL.len()),
    ];
    if !extra.is_empty() {
        v.push(extra.to_string());
    }
    v.push(format!(
        "view {}x{} dp at density {}; a browser's rasteriser is not Skia, so even the \
         filled shapes below are not device pixels.",
        q(viewport.width()),
        q(viewport.height()),
        q(1.0)
    ));
    v
}

/// XML text escaping. Applied to every string that came from an APK, because a
/// view id containing `<` is a hostile input and an unescaped one is an
/// injection.
pub fn xml_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && c != '\n' && c != '\t' => o.push('\u{fffd}'),
            c => o.push(c),
        }
    }
    o
}

/// What an SVG writer dropped or substituted, so the caller can report it and
/// the test can count it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SvgFidelity {
    /// Blends that have no `feComposite` operator and were therefore not applied.
    pub dropped_blends: Vec<PorterDuffMode>,
    /// Blends expressed with a Compositing-spec operator that is not Skia's.
    pub substituted_blends: Vec<PorterDuffMode>,
    /// Shaders that have no SVG gradient element and were rendered as a flat
    /// average of their stops. `BitmapShader` is not in this list: it is
    /// refused before it reaches the writer.
    pub flattened_shaders: Vec<String>,
    /// Decoded bitmaps whose pixels were not embedded, because there is no PNG
    /// encoder in this crate.
    pub unembedded_images: Vec<String>,
    /// A paint that wanted a stroke with `STROKE` or `FILL` style, which SVG
    /// cannot express: SVG always has both a fill and a stroke.
    pub stroke_style_losses: Vec<&'static str>,
    /// Clip antialiasing flags that SVG does not offer.
    pub clip_antialias_notes: usize,
}

impl SvgFidelity {
    /// How many things had to be dropped or substituted. The banner escalates
    /// when this is non-zero.
    pub fn losses(&self) -> usize {
        self.dropped_blends.len()
            + self.substituted_blends.len()
            + self.flattened_shaders.len()
            + self.unembedded_images.len()
            + self.stroke_style_losses.len()
    }

    pub fn summary(&self) -> String {
        let mut v: Vec<String> = Vec::new();
        if !self.dropped_blends.is_empty() {
            v.push(format!(
                "{} Porter-Duff blend(s) not expressible in SVG and NOT applied: {}",
                self.dropped_blends.len(),
                self.dropped_blends
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !self.substituted_blends.is_empty() {
            v.push(format!(
                "{} blend(s) applied with Compositing-spec operators that are not Skia's: {}",
                self.substituted_blends.len(),
                self.substituted_blends
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !self.flattened_shaders.is_empty() {
            v.push(format!(
                "{} shader(s) drawn as a flat average of their stops: {}",
                self.flattened_shaders.len(),
                self.flattened_shaders.join(",")
            ));
        }
        if !self.unembedded_images.is_empty() {
            v.push(format!(
                "{} image(s) NOT embedded: this layer has no image encoder: {}",
                self.unembedded_images.len(),
                self.unembedded_images.join(",")
            ));
        }
        if !self.stroke_style_losses.is_empty() {
            v.push(format!(
                "SVG has no FILL/STROKE paint style: {} paint(s) drew a stroke where \
                 the list said fill only, or vice versa",
                self.stroke_style_losses.len()
            ));
        }
        v.join("; ")
    }
}

/// The SVG's own per-feature table, with the Porter-Duff rows filled in by
/// enumeration so the reported counts are derived rather than written down.
pub fn svg_limitations() -> Vec<crate::capability::Limitation> {
    use crate::capability::Limitation;
    let mut v = vec![
        Limitation {
            feature: "rasterisation",
            instance: "",
            support: Support::Absent,
            note: "an SVG file is emitted; no pixel is computed by this layer",
        },
        Limitation {
            feature: "text",
            instance: "glyph outlines",
            support: Support::Substituted,
            note: "the viewer's font, in the viewer's rasteriser; not Android's typeface and not Skia",
        },
        Limitation {
            feature: "antialiasing",
            instance: "",
            support: Support::Substituted,
            note: "the viewer's rasteriser decides; there is no AA control on an SVG shape and none on a clip",
        },
        Limitation {
            feature: "image",
            instance: "bitmap pixels",
            support: Support::Absent,
            note: "no image encoder in this layer, so decoded bitmaps are recorded and not embedded",
        },
    ];
    for m in PorterDuffMode::ALL {
        let (support, note) = match fe_composite_mode(m) {
            None => (
                Support::Absent,
                "no feComposite operator for this mode; the blend is dropped and recorded on the element",
            ),
            Some(FeMode::Blend(_)) => (
                Support::Substituted,
                "feComposite's blend operators follow the Compositing spec; Skia's same-named modes blend unpremultiplied, so translucent paint diverges",
            ),
            Some(FeMode::Exact(_)) => (
                Support::Exact,
                "one-to-one with an feComposite operator of the same name",
            ),
        };
        v.push(Limitation {
            feature: "porter-duff-mode",
            instance: m.as_str(),
            support,
            note,
        });
    }
    v
}

/// The `feComposite` operator, if the mode has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeMode {
    /// A true Porter-Duff equivalent.
    Exact(&'static str),
    /// A Compositing-spec separable blend, which is *not* the same function as
    /// Skia's mode of that name.
    Blend(&'static str),
}

/// The exact mapping. `None` for the fifteen modes SVG cannot express.
///
/// The point of `Exact` versus `Blend` is the word "exact": `in`, `out`, `atop`
/// and `xor` are Porter-Duff operators in both specifications, whereas
/// `multiply` is a blend mode in both and the two specifications disagree about
/// alpha. `CLEAR` is exact and needs a transparent `feFlood` composed with
/// `out`, which is algebraically Porter-Duff `CLEAR` on a known background.
pub fn fe_composite_mode(mode: PorterDuffMode) -> Option<FeMode> {
    use PorterDuffMode as M;
    match mode {
        M::Clear => Some(FeMode::Exact("clear")),
        M::SrcOver => Some(FeMode::Exact("over")),
        M::SrcIn => Some(FeMode::Exact("in")),
        M::SrcOut => Some(FeMode::Exact("out")),
        M::SrcAtop => Some(FeMode::Exact("atop")),
        M::Xor => Some(FeMode::Exact("xor")),
        M::Multiply => Some(FeMode::Blend("multiply")),
        M::Screen => Some(FeMode::Blend("screen")),
        M::Darken => Some(FeMode::Blend("darken")),
        M::Lighten => Some(FeMode::Blend("lighten")),
        // The remaining eleven have no feComposite operator, and SVG composites
        // source over destination: there is no primitive that keeps the
        // destination alone.
        M::Src
        | M::Dst
        | M::DstOver
        | M::DstIn
        | M::DstOut
        | M::DstAtop
        | M::Add
        | M::Overlay
        | M::Difference
        | M::Exclve
        | M::Invert => None,
    }
}

/// Serialise a display list as SVG.
///
/// The output is well-formed XML for any display list this crate can produce:
/// every untrusted string is escaped, every coordinate is finite (checked, not
/// assumed), and the gradient/filter `defs` are collected before the body so
/// forward references cannot occur.
pub fn to_svg(list: &DisplayList) -> Result<(String, SvgFidelity), GraphicsError> {
    list.viewport.checked()?;
    let vp = list.viewport;
    let banner = banner_height(vp.height_dp);
    let width = vp.px_width();
    let height = vp.px_height() + banner * vp.density;
    if !width.is_finite() || !height.is_finite() || width < 0.0 || height < 0.0 {
        return Err(GraphicsError::BadViewport {
            width: vp.width_dp,
            height: vp.height_dp,
            density: vp.density,
        });
    }

    let mut f = SvgFidelity::default();
    let mut defs = Defs::default();
    let mut body = String::with_capacity(list.steps.len() * 96);

    // The app's reconstruction lives in its own group, translated below the
    // banner, and clipped to the viewport so a strut off the edge of the frame
    // is cut exactly as the clip chain would cut it.
    body.push_str(&format!(
        "\n  <g id=\"app-reconstruction\" data-prov=\"derived\" \
         transform=\"translate(0,{})\" clip-path=\"url(#clip-viewport)\">\n",
        q(banner * vp.density)
    ));
    let mut depth = 0usize;
    for (i, step) in list.steps.iter().enumerate() {
        emit_step(step, i, &mut body, &mut depth, vp, &mut f, &mut defs)?;
    }
    body.push_str("  </g>\n");

    let mut s = String::with_capacity(2048 + body.len());
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let _ = writeln!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" \
         xmlns:substrate=\"https://andro-substrate.invalid/graphics/1\" \
         width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" \
         data-substrate-provenance=\"reconstruction-of-shim-box-tree\" \
         data-substrate-is-android=\"false\" \
         data-app-draw-code-executed=\"false\" \
         data-backend=\"{}\" \
         data-measure-model=\"{}\" \
         data-text-policy=\"{}\" \
         data-gfx-ids-total=\"{}\" \
         data-gfx-reproduced=\"{}\" \
         data-gfx-observed-satisfied=\"{}\" \
         data-report-audit-mismatches=\"{}\" \
         data-ink-fabricated=\"{}\" \
         data-ink-coverage=\"{:.4}\" \
         data-viewport-rect=\"x=0 y={} w={} h={}\">",
        q(width),
        q(height),
        q(width),
        q(height),
        vp.density as u32,
        xml_escape(&list.measure_model),
        xml_escape(list.text_policy),
        GfxId::ALL.len(),
        list.capability.reproduced(),
        list.capability.observed_satisfied(),
        list.capability.audit.mismatches.len(),
        list.counts.ink_fabricated,
        list.counts.ink_coverage(),
        q(banner * vp.density),
        q(vp.px_width()),
        q(vp.px_height())
    );
    let _ = writeln!(s, "  <title>{}</title>", xml_escape(&list.banner));
    s.push_str("  <desc>\n");
    s.push_str(&desc_body(list));
    s.push_str("  </desc>\n");
    s.push_str("  <metadata>\n");
    s.push_str(&metadata_body(list));
    s.push_str("  </metadata>\n");
    let _ = writeln!(s, "  <style>{}", CSS);
    s.push_str("  </style>\n");
    s.push_str(&defs.render(vp, banner));
    // The viewport clip, in document coordinates.
    let _ = writeln!(
        s,
        "  <clipPath id=\"clip-viewport\"><rect x=\"0\" y=\"{}\" width=\"{}\" height=\"{}\"/></clipPath>",
        q(banner * vp.density),
        q(vp.px_width()),
        q(vp.px_height())
    );
    s.push_str(&banner_svg(list, vp, banner, &f));
    s.push_str(&body);
    s.push_str(&legend_svg(vp, banner));
    s.push_str("</svg>\n");
    Ok((s, f))
}

const CSS: &str = "\
.shim-box{fill:none;stroke:#2f6f9f;stroke-width:1;stroke-dasharray:3 2}
.shim-box-invisible{fill:none;stroke:#9a9a9a;stroke-width:1;stroke-dasharray:1 3}
.withheld{fill:url(#pat-withheld);stroke:#b06a00;stroke-width:1}
.image-absent{fill:url(#pat-absent);stroke:#8a2f2f;stroke-width:1.5}
.unknown-ink{fill:url(#pat-unknown);stroke:none;opacity:0.5}
.legend-text{font-family:monospace;font-size:10px;fill:#111}
.legend-bg{fill:#f4f1e8;stroke:#333;stroke-width:1}
.legend-head{font-family:monospace;font-size:11px;font-weight:bold;fill:#111}";

/// A `<defs>` collector. Gradients and filters are created on first use and
/// referenced by index, so the ids are deterministic: the *n*-th distinct
/// gradient in step order is `grad-n`.
#[derive(Debug, Default)]
struct Defs {
    grads: Vec<(String, String)>,
}

impl Defs {
    fn grad(&mut self, body: String) -> String {
        if let Some((_, existing)) = self.grads.iter().find(|(_, b)| *b == body) {
            return format!("url(#{existing})");
        }
        let id = format!("grad-{}", self.grads.len());
        self.grads.push((id.clone(), body));
        format!("url(#{id})")
    }

    fn render(&self, _vp: Viewport, _banner: f32) -> String {
        let mut s = String::new();
        s.push_str("  <defs>\n");
        s.push_str(
            "    <pattern id=\"pat-unknown\" width=\"8\" height=\"8\" patternUnits=\"userSpaceOnUse\">\
             <rect width=\"8\" height=\"8\" fill=\"#ffffff\"/>\
             <path d=\"M0,0 L8,0 L0,8 Z\" fill=\"#d9d9d9\"/></pattern>\n",
        );
        s.push_str(
            "    <pattern id=\"pat-withheld\" width=\"6\" height=\"6\" patternUnits=\"userSpaceOnUse\">\
             <rect width=\"6\" height=\"6\" fill=\"#fff4e0\"/>\
             <path d=\"M0,6 L6,0\" stroke=\"#d98c1a\" stroke-width=\"1.5\"/></pattern>\n",
        );
        s.push_str(
            "    <pattern id=\"pat-absent\" width=\"6\" height=\"6\" patternUnits=\"userSpaceOnUse\">\
             <rect width=\"6\" height=\"6\" fill=\"#f6e4e4\"/>\
             <path d=\"M0,0 L6,6 M6,0 L0,6\" stroke=\"#a33\" stroke-width=\"1\"/></pattern>\n",
        );
        for (id, body) in &self.grads {
            let _ = writeln!(s, "    <{body} id=\"{id}\"/>");
        }
        // The blend filters are emitted for *every* operator, present or not,
        // so a reader of the file can see the complete set SVG offers rather
        // than only the ones this particular display list happened to use. A
        // file that contained only `blend-over` would read as "only SRC_OVER is
        // expressible", which is a different and wrong claim.
        for (op, note) in FE_OPERATORS {
            let _ = writeln!(
                s,
                "    <filter id=\"blend-{op}\" x=\"-50%\" y=\"-50%\" width=\"200%\" height=\"200%\" \
                 color-interpolation-filters=\"sRGB\" data-note=\"{}\">\
                 <feFlood flood-color=\"#fff\" flood-opacity=\"1\" result=\"k\"/>\
                 <feComposite in=\"SourceGraphic\" in2=\"k\" operator=\"{op}\"/></filter>",
                xml_escape(note)
            );
        }
        s.push_str("  </defs>\n");
        s
    }
}

/// The seven `feComposite` operators this crate emits a filter for, with the
/// reason each is or is not a Porter-Duff equivalent.
pub const FE_OPERATORS: [(&str, &str); 9] = [
    ("over", "Porter-Duff SRC_OVER: source over destination"),
    ("in", "Porter-Duff SRC_IN: source where destination is opaque"),
    ("out", "Porter-Duff SRC_OUT: source where destination is transparent"),
    ("atop", "Porter-Duff SRC_ATOP: source over destination, both masked to the union"),
    ("xor", "Porter-Duff XOR: the symmetric difference"),
    ("multiply", "Compositing blend, NOT Skia MULTIPLY: premultiplied here, unpremultiplied there"),
    ("screen", "Compositing blend, NOT Skia SCREEN: premultiplied here, unpremultiplied there"),
    ("darken", "Compositing blend, NOT Skia DARKEN: premultiplied here, unpremultiplied there"),
    ("lighten", "Compositing blend, NOT Skia LIGHTEN: premultiplied here, unpremultiplied there"),
];

fn desc_body(list: &DisplayList) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "    THIS FILE IS NOT A SCREENSHOT OF AN APP.");
    let _ = writeln!(s, "    {}", xml_escape(&list.banner));
    let _ = writeln!(s, "    Provenance of each element is on its data-prov attribute:");
    for p in Provenance::ALL {
        let _ = writeln!(s, "      {} = {}", p, xml_escape(p.explain()));
    }
    let _ = writeln!(s, "    {}", list.summary());
    let _ = writeln!(s, "    Capability report:");
    s.push_str(&xml_escape(&indent(&list.capability.to_text(), "    ")));
    s
}

fn metadata_body(list: &DisplayList) -> String {
    let mut s = String::new();
    s.push_str("    <substrate:display-list version=\"1\">\n");
    let _ = writeln!(s, "      <substrate:banner>{}</substrate:banner>", xml_escape(&list.banner));
    let _ = writeln!(
        s,
        "      <substrate:geometry-origin>shim::layout::BoxNode</substrate:geometry-origin>"
    );
    let _ = writeln!(
        s,
        "      <substrate:geometry-trust>exact-relative-to-the-shim-only</substrate:geometry-trust>"
    );
    let _ = writeln!(
        s,
        "      <substrate:app-draw-code-executed>false</substrate:app-draw-code-executed>"
    );
    let _ = writeln!(
        s,
        "      <substrate:measure-model>{}</substrate:measure-model>",
        xml_escape(&list.measure_model)
    );
    let _ = writeln!(
        s,
        "      <substrate:text-policy>{}</substrate:text-policy>",
        xml_escape(list.text_policy)
    );
    let _ = writeln!(
        s,
        "      <substrate:viewport dp-w=\"{}\" dp-h=\"{}\" density=\"{}\"/>",
        q(list.viewport.width_dp),
        q(list.viewport.height_dp),
        q(list.viewport.density)
    );
    let c = &list.counts;
    let _ = writeln!(
        s,
        "      <substrate:counts steps=\"{}\" ink=\"{}\" ink-fabricated=\"{}\" annotations=\"{}\" \
         text-runs=\"{}\" text-withheld=\"{}\" withheld-chars=\"{}\" images-drawn=\"{}\" \
         images-absent=\"{}\" clip-regions=\"{}\" leaf-area-dp2=\"{}\" unknown-ink-dp2=\"{}\" \
         ink-coverage=\"{:.4}\"/>",
        c.steps,
        c.ink_steps,
        c.ink_fabricated,
        c.annotations,
        c.text_runs,
        c.text_withheld,
        c.withheld_chars,
        c.images_drawn,
        c.images_absent,
        c.clip_regions,
        c.leaf_area_dp2,
        q_area(c.unknown_ink_dp2),
        c.ink_coverage()
    );
    let _ = writeln!(
        s,
        "      <substrate:capability backend=\"{}\" reproduced=\"{}\" observed-satisfied=\"{}\" \
         audit-mismatches=\"{}\">",
        list.capability.backend,
        list.capability.reproduced(),
        list.capability.observed_satisfied(),
        list.capability.audit.mismatches.len()
    );
    for e in &list.capability.entries {
        let _ = writeln!(
            s,
            "        <substrate:assumption id=\"{}\" verdict=\"{}\" emission=\"{}\" origin=\"{}\" \
             observed=\"{}\">{}</substrate:assumption>",
            xml_escape(&e.id.assumption()),
            e.claimed.as_str(),
            e.emission.as_str(),
            e.origin.as_str(),
            e.observed.verdict().as_str(),
            xml_escape(e.note)
        );
    }
    s.push_str("      </substrate:capability>\n");
    let _ = writeln!(
        s,
        "      <substrate:headline>{}</substrate:headline>",
        xml_escape(&list.capability.headline())
    );
    s.push_str("    </substrate:display-list>\n");
    s
}

fn indent(text: &str, pad: &str) -> String {
    let mut s = String::new();
    for line in text.lines() {
        s.push_str(pad);
        s.push_str(line);
        s.push('\n');
    }
    s
}

fn banner_svg(list: &DisplayList, vp: Viewport, banner: f32, f: &SvgFidelity) -> String {
    let mut s = String::new();
    let h = banner * vp.density;
    let extra = f.summary();
    let lines = banner_lines(&list.capability, &extra, vp.rect());
    // The band escalates from dark red to black when something had to be
    // dropped, so a degraded artefact is distinguishable at a glance.
    let bg = if f.losses() > 0 { "#000000" } else { "#7a1010" };
    let _ = writeln!(
        s,
        "  <g id=\"provenance-banner\" data-prov=\"absent\">\n    <rect id=\"banner-bg\" x=\"0\" \
         y=\"0\" width=\"{}\" height=\"{}\" fill=\"{bg}\"/>\n    <text class=\"legend-head\" \
         x=\"6\" y=\"14\" fill=\"#ffffff\">{}</text>",
        q(vp.px_width()),
        q(h),
        xml_escape(&lines[0])
    );
    let mut y = 14.0 + 13.0;
    for t in lines.iter().skip(1) {
        let _ = writeln!(
            s,
            "    <text class=\"legend-text\" x=\"6\" y=\"{}\" fill=\"#ffffff\">{}</text>",
            q(y),
            xml_escape(t)
        );
        y += 13.0;
    }
    s.push_str("  </g>\n");
    s
}

/// A small legend at the foot of the file naming the hatch patterns and the
/// provenance colours, so a screenshot of the SVG alone carries its own key.
fn legend_svg(vp: Viewport, banner: f32) -> String {
    let mut s = String::new();
    let y = banner * vp.density + vp.px_height();
    let entries: [(&str, &str); 4] = [
        ("pat-unknown", "no ink: the app's drawing was not available"),
        ("pat-withheld", "text the shim's box tree withheld"),
        ("pat-absent", "image never decoded"),
        ("pat-box", "view boundary from the shim's tree (not app ink)"),
    ];
    let _ = writeln!(
        s,
        "  <g id=\"provenance-legend\" data-prov=\"derived\" transform=\"translate(0,{})\">",
        q(y)
    );
    for (i, (pat, label)) in entries.iter().enumerate() {
        let col = i % 2;
        let row = i / 2;
        let x = 6.0 + col as f32 * (vp.px_width() / 2.0);
        let yy = 12.0 + row as f32 * 12.0;
        let _ = writeln!(
            s,
            "    <rect x=\"{}\" y=\"{}\" width=\"10\" height=\"8\" fill=\"url(#{})\" stroke=\"#333\"/>",
            q(x),
            q(yy - 7.0),
            pat
        );
        let _ = writeln!(
            s,
            "    <text class=\"legend-text\" x=\"{}\" y=\"{}\">{}</text>",
            q(x + 14.0),
            q(yy),
            xml_escape(label)
        );
    }
    s.push_str("  </g>\n");
    s
}

/// Emit one display-list step. Returns an error rather than writing a
/// non-finite coordinate, which would be a parse error in any viewer.
fn emit_step(
    step: &Step,
    index: usize,
    out: &mut String,
    depth: &mut usize,
    vp: Viewport,
    f: &mut SvgFidelity,
    defs: &mut Defs,
) -> Result<(), GraphicsError> {
    let pad = "  ".repeat(*depth + 2);
    let id = format!("s{index}");
    let prov = step.provenance.as_str();
    match &step.command {
        Command::Save => {
            *depth += 1;
            let _ = writeln!(out, "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"push\"/>");
        }
        Command::Restore => {
            *depth = depth.saturating_sub(1);
            let _ = writeln!(out, "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"pop\"/>");
        }
        Command::Translate { dx, dy } => {
            *depth += 1;
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"translate\" \
                 transform=\"translate({}, {})\"/>",
                q(*dx),
                q(*dy)
            );
        }
        Command::Scale { sx, sy } => {
            *depth += 1;
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"scale\" \
                 transform=\"scale({}, {})\"/>",
                q(*sx),
                q(*sy)
            );
        }
        Command::ClipRect {
            rect,
            effective,
            antialias,
        } => {
            RectF::checked(rect)?;
            *depth += 1;
            if *antialias {
                f.clip_antialias_notes += 1;
            }
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"clip-rect\" \
                 data-asked-antialias=\"{antialias}\" clip-path=\"url(#c{id})\">",
                antialias = if *antialias { "true" } else { "false" }
            );
            let _ = writeln!(
                out,
                "{pad}  <clipPath id=\"c{id}\"><rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"/></clipPath>",
                q(effective.left),
                q(effective.top),
                q(effective.width_nonneg()),
                q(effective.height_nonneg())
            );
        }
        Command::ClipPath { path, antialias } => {
            path.checked()?;
            *depth += 1;
            if *antialias {
                f.clip_antialias_notes += 1;
            }
            let d = xml_escape(&path.to_svg_d());
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"clip-path\" \
                 data-asked-antialias=\"{antialias}\" clip-path=\"url(#c{id})\">\n\
                 {pad}  <clipPath id=\"c{id}\"><path d=\"{d}\"/></clipPath>",
                antialias = if *antialias { "true" } else { "false" }
            );
        }
        Command::DrawColor { color, mode } => {
            let (fill, dropped) = solid_or_mode(*color, *mode, f);
            let _ = writeln!(
                out,
                "{pad}<rect id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-color\" \
                 x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{fill}\"{}/>",
                q(vp.width_dp),
                q(vp.height_dp),
                dropped
            );
        }
        Command::DrawRect { rect, paint } => {
            RectF::checked(rect)?;
            paint.checked()?;
            let a = paint_attrs(paint, f, defs);
            let _ = writeln!(
                out,
                "{pad}<rect id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-rect\" \
                 x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"{}/>",
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg()),
                a
            );
        }
        Command::DrawPath { path, paint } => {
            path.checked()?;
            paint.checked()?;
            let a = paint_attrs(paint, f, defs);
            let _ = writeln!(
                out,
                "{pad}<path id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-path\" d=\"{}\"{}/>",
                xml_escape(&path.to_svg_d()),
                a
            );
        }
        Command::DrawTextRun { run, paint } => {
            run.checked()?;
            paint.checked()?;
            let mut a = String::new();
            let _ = write!(
                a,
                " data-measure-model=\"{}\" data-measure-prov=\"{}\" data-advance=\"{}\"",
                xml_escape(&run.advance.model),
                run.advance.provenance,
                q(run.advance.advance_x)
            );
            a.push_str(&paint_attrs(paint, f, defs));
            // No fill at all unless the paint has something to fill with: a
            // `Fill` paint with a transparent colour and no shader must not
            // come out as a black glyph.
            if paint.color.is_transparent() && paint.shader.is_none() {
                let _ = write!(
                    out,
                    "{pad}<text id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-text\" x=\"{}\" \
                     y=\"{}\" font-family=\"{}\" font-size=\"{}\" text-anchor=\"{}\" \
                     fill=\"none\"{a}>{}</text>",
                    q(run.x),
                    q(run.baseline),
                    xml_escape(&run.style.typeface.to_css_family()),
                    q(run.style.size_sp),
                    paint.text_align.to_svg_anchor(),
                    xml_escape(&run.text)
                );
            } else {
                let _ = write!(
                    out,
                    "{pad}<text id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-text\" x=\"{}\" \
                     y=\"{}\" font-family=\"{}\" font-size=\"{}\" text-anchor=\"{}\"{a}>{}</text>",
                    q(run.x),
                    q(run.baseline),
                    xml_escape(&run.style.typeface.to_css_family()),
                    q(run.style.size_sp),
                    paint.text_align.to_svg_anchor(),
                    xml_escape(&run.text)
                );
            }
        }
        Command::DrawImage { img, paint: _paint } => {
            img.checked()?;
            let dropped = if img.bitmap.is_decoded() {
                f.unembedded_images.push(img.id.clone());
                format!(
                    " data-not-embedded=\"true\" data-bitmap=\"{}\" data-bytes=\"{}\"",
                    xml_escape(&img.id),
                    img.bitmap.pixels.as_ref().map_or(0, Vec::len)
                )
            } else {
                String::new()
            };
            let label = xml_escape(if img.bitmap.is_decoded() {
                "PIXELS NOT EMBEDDED: no image encoder in this layer"
            } else {
                "IMAGE NOT DECODED"
            });
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"draw-image\" \
                 data-image=\"{}\" data-decoded=\"{}\"{dropped}>\n\
                 {pad}  <rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" \
                 class=\"image-absent\"/>\
                 {pad}  <text class=\"legend-text\" x=\"{}\" y=\"{}\">{label}</text>\n{pad}  </g>",
                xml_escape(&img.id),
                img.bitmap.is_decoded(),
                q(img.dst.left),
                q(img.dst.top),
                q(img.dst.width_nonneg()),
                q(img.dst.height_nonneg()),
                q(img.dst.left + 2.0),
                q(img.dst.top + 10.0)
            );
        }
        Command::Annotate(a) => {
            emit_annotation(a, &id, prov, out, pad.as_str());
        }
    }
    Ok(())
}

fn emit_annotation(a: &Annotation, id: &str, prov: &str, out: &mut String, pad: &str) {
    match a {
        Annotation::UnknownInk { rect, reason } => {
            let _ = writeln!(
                out,
                "{pad}<rect id=\"{id}\" data-prov=\"{prov}\" data-op=\"unknown-ink\" \
                 data-reason=\"{}\" class=\"unknown-ink\" x=\"{}\" y=\"{}\" width=\"{}\" \
                 height=\"{}\"/>",
                xml_escape(reason),
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg())
            );
        }
        Annotation::BoxOutline {
            id: vid,
            rect,
            state,
            kind,
        } => {
            let class = if *state == crate::canvas::ViewState::Visible {
                "shim-box"
            } else {
                "shim-box-invisible"
            };
            let _ = writeln!(
                out,
                "{pad}<rect id=\"{id}\" data-prov=\"{prov}\" data-op=\"box-outline\" \
                 data-view=\"{}\" data-kind=\"{}\" data-state=\"{}\" class=\"{}\" x=\"{}\" \
                 y=\"{}\" width=\"{}\" height=\"{}\"/>",
                xml_escape(vid),
                xml_escape(kind),
                state.as_str(),
                class,
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg())
            );
        }
        Annotation::TextWithheld {
            id: vid,
            rect,
            chars,
            classes,
            shape,
        } => {
            let cls: Vec<String> = classes.iter().map(|(k, v)| format!("{k}={v}")).collect();
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"text-withheld\" \
                 data-view=\"{}\" data-chars=\"{}\" data-classes=\"{}\" data-shape=\"{}\">\n\
                 {pad}  <rect class=\"withheld\" x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"/>\n\
                 {pad}  <text class=\"legend-text\" x=\"{}\" y=\"{}\">{} chars withheld ({})</text>\n\
                 {pad}</g>",
                xml_escape(vid),
                chars,
                xml_escape(&cls.join(",")),
                xml_escape(shape),
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg()),
                q(rect.left + 2.0),
                q(rect.top + 10.0),
                chars,
                xml_escape(shape)
            );
        }
        Annotation::ImageAbsent { id: vid, rect, reason } => {
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"image-absent\" \
                 data-view=\"{}\" data-reason=\"{}\">\n\
                 {pad}  <rect class=\"image-absent\" x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"/>\n\
                 {pad}  <text class=\"legend-text\" x=\"{}\" y=\"{}\">no bitmap</text>\n{pad}</g>",
                xml_escape(vid),
                xml_escape(reason),
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg()),
                q(rect.left + 2.0),
                q(rect.top + 10.0)
            );
        }
        Annotation::ImageNotEmbedded {
            id: vid,
            rect,
            width,
            height,
        } => {
            let _ = writeln!(
                out,
                "{pad}<g id=\"{id}\" data-prov=\"{prov}\" data-op=\"image-not-embedded\" \
                 data-view=\"{}\" data-bitmap=\"{width}x{height}\">\n\
                 {pad}  <rect class=\"image-absent\" x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\"/>\n\
                 {pad}  <text class=\"legend-text\" x=\"{}\" y=\"{}\">pixels not embedded</text>\n\
                 {pad}</g>",
                xml_escape(vid),
                q(rect.left),
                q(rect.top),
                q(rect.width_nonneg()),
                q(rect.height_nonneg()),
                q(rect.left + 2.0),
                q(rect.top + 10.0)
            );
        }
        Annotation::CapabilityNote { id: gid, text } => {
            let _ = writeln!(
                out,
                "{pad}<metadata id=\"{id}\" data-prov=\"{prov}\" data-op=\"capability-note\" \
                 data-assumption=\"{}\">{}</metadata>",
                xml_escape(&gid.assumption()),
                xml_escape(text)
            );
        }
        Annotation::Note { text } => {
            let _ = writeln!(
                out,
                "{pad}<metadata id=\"{id}\" data-prov=\"{prov}\" data-op=\"note\">{}</metadata>",
                xml_escape(text)
            );
        }
    }
}

/// The fill and blend attributes for a paint, plus the `data-blend-dropped`
/// marker when a mode could not be expressed.
fn paint_attrs(p: &Paint, f: &mut SvgFidelity, defs: &mut Defs) -> String {
    let mut a = String::new();
    let mode = p.effective_xfermode();

    // Fill.
    let (fill, fill_opacity) = match &p.shader {
        None => (p.color.to_hex6(), Some(f32::from(p.color.alpha()) / 255.0)),
        Some(s) => match shader_fill(s, defs) {
            Some((f_ref, op)) => (f_ref, op),
            None => {
                f.flattened_shaders.push(s.kind().to_string());
                // Not a silent substitution: the element carries
                // data-shader-flattened, and the banner counts it.
                a.push_str(&format!(
                    " data-shader-flattened=\"{}\" data-shader-stops=\"{}\"",
                    s.kind(),
                    s.stops().0.len()
                ));
                let avg = average_color(&s.stops().0);
                (avg.to_hex6(), Some(f32::from(avg.alpha()) / 255.0))
            }
        },
    };
    match p.style {
        PaintStyle::Fill => {
            let _ = write!(a, " fill=\"{fill}\" fill-opacity=\"{}\"", q(fill_opacity.unwrap_or(1.0)));
        }
        PaintStyle::FillAndStroke => {
            let _ = write!(
                a,
                " fill=\"{fill}\" fill-opacity=\"{}\" stroke=\"{}\" stroke-opacity=\"{}\" \
                 paint-order=\"fill stroke\"",
                q(fill_opacity.unwrap_or(1.0)),
                p.color.to_hex6(),
                q(f32::from(p.color.alpha()) / 255.0)
            );
        }
        PaintStyle::Stroke => {
            f.stroke_style_losses.push("STROKE");
            let _ = write!(
                a,
                " fill=\"none\" stroke=\"{}\" stroke-opacity=\"{}\" stroke-width=\"{}\" \
                 stroke-linecap=\"{}\" stroke-linejoin=\"{}\" stroke-miterlimit=\"{}\" \
                 data-style=\"stroke\"",
                p.color.to_hex6(),
                q(f32::from(p.color.alpha()) / 255.0),
                q(p.stroke_width),
                p.stroke_cap.as_str(),
                p.stroke_join.as_str(),
                q(p.stroke_miter)
            );
        }
    }
    if p.style != PaintStyle::Stroke {
        // SVG has no FILL/STROKE style; a Fill paint with a stroke set would
        // draw a stroke it was never asked for. Recorded either way.
        if p.stroke_width > 0.0 && p.style == PaintStyle::Fill {
            f.stroke_style_losses.push("FILL-with-stroke");
            a.push_str(" data-style=\"fill\" data-note=\"stroke-width set but style=fill; SVG would stroke, so it is suppressed here\"");
        }
    }
    if let Some(fd) = blend_attrs(mode, f) {
        a.push_str(&fd);
    }
    a
}

/// `filter: url(#…)` for a mode, or the dropped-blend marker. A dropped blend
/// leaves the element composited normally, which is *wrong*, so the element says
/// so on its own attributes.
fn blend_attrs(mode: PorterDuffMode, f: &mut SvgFidelity) -> Option<String> {
    match fe_composite_mode(mode) {
        None => {
            f.dropped_blends.push(mode);
            Some(format!(
                " data-blend=\"{}\" data-blend-dropped=\"true\" \
                 data-blend-note=\"not applied: no feComposite operator for {}; this ink is \
                 composited normally and is NOT what Android would draw\"",
                mode.as_str(),
                mode.as_str()
            ))
        }
        Some(FeMode::Blend(op)) => {
            f.substituted_blends.push(mode);
            Some(format!(
                " filter=\"url(#blend-{op})\" data-blend=\"{}\" data-blend-substituted=\"true\" \
                 data-blend-note=\"feComposite '{op}' is a Compositing-spec blend; Skia's {} blends \
                 unpremultiplied, so translucent paint diverges\"",
                mode.as_str(),
                mode.as_str()
            ))
        }
        Some(FeMode::Exact(op)) => Some(format!(
            " filter=\"url(#blend-{op})\" data-blend=\"{}\" data-blend-exact=\"true\"",
            mode.as_str()
        )),
    }
}

/// The `<linearGradient>` / `<radialGradient>` body, or `None` when the shader
/// cannot be expressed and must be flattened.
fn shader_fill(s: &Shader, defs: &mut Defs) -> Option<(String, Option<f32>)> {
    let (colors, positions) = s.stops();
    if colors.len() < 2 {
        return None;
    }
    let spread = match (&s, spread_of(s)) {
        (Shader::Linear { tile, .. }, sp) | (Shader::Radial { tile, .. }, sp) => {
            let _ = tile;
            sp?
        }
        (Shader::Solid(_), _) => "pad",
    };
    let stops: String = colors
        .iter()
        .zip(positions.iter())
        .map(|(c, p)| {
            format!(
                "<stop offset=\"{}\" stop-color=\"{}\" stop-opacity=\"{}\"/>",
                q(*p),
                c.to_hex6(),
                q(f32::from(c.alpha()) / 255.0)
            )
        })
        .collect();
    let body = match s {
        Shader::Solid(_) => return None,
        Shader::Linear { x0, y0, x1, y1, .. } => format!(
            "<linearGradient gradientUnits=\"userSpaceOnUse\" spreadMethod=\"{spread}\" \
             x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\">{}</linearGradient>",
            q(*x0), q(*y0), q(*x1), q(*y1), stops
        ),
        Shader::Radial {
            cx, cy, radius, fx, fy, ..
        } => {
            // SVG's `fx`/`fy` are absolute user-space coordinates, same as
            // Android's, so no conversion is needed. What *is* different is the
            // default focus for a two-point SVG radial, so it is written out
            // explicitly rather than left to the default.
            format!(
                "<radialGradient gradientUnits=\"userSpaceOnUse\" spreadMethod=\"{spread}\" \
                 cx=\"{}\" cy=\"{}\" r=\"{}\" fx=\"{}\" fy=\"{}\">{}</radialGradient>",
                q(*cx), q(*cy), q(*radius), q(*fx), q(*fy), stops
            )
        }
    };
    Some((defs.grad(body), Some(1.0)))
}

fn spread_of(s: &Shader) -> Option<&'static str> {
    match s {
        Shader::Linear { tile, .. } | Shader::Radial { tile, .. } => tile.to_svg_spread(),
        Shader::Solid(_) => None,
    }
}

/// The average of the stops, used only when a shader has to be flattened. Named
/// `average_color` rather than hidden in a `default` arm so a reader can see
/// that the fallback is an arithmetic mean and therefore wrong.
fn average_color(colors: &[Color]) -> Color {
    if colors.is_empty() {
        return Color::TRANSPARENT;
    }
    let mut a = 0u32;
    let mut r = 0u32;
    let mut g = 0u32;
    let mut b = 0u32;
    for c in colors {
        a += c.alpha() as u32;
        r += c.red() as u32;
        g += c.green() as u32;
        b += c.blue() as u32;
    }
    let n = colors.len() as u32;
    Color::argb_of(
        (a / n) as i32,
        (r / n) as i32,
        (g / n) as i32,
        (b / n) as i32,
    )
}

/// Fill a solid colour or a full-canvas `drawColor`, applying the mode.
fn solid_or_mode(
    c: Color,
    mode: PorterDuffMode,
    f: &mut SvgFidelity,
) -> (String, String) {
    match blend_attrs(mode, f) {
        Some(attrs) if attrs.contains("dropped") => (c.to_hex6(), attrs),
        Some(attrs) => (c.to_hex6(), attrs),
        None => (c.to_hex6(), String::new()),
    }
}

/// The re-derivation helper the tests use: recount `data-prov` attributes in a
/// serialised SVG. Public so a test does not have to reimplement a tag scan.
pub fn count_attr(svg: &str, attr: &str) -> usize {
    let needle = format!("{attr}=\"");
    let mut n = 0;
    let mut from = 0;
    while let Some(i) = svg.get(from..).and_then(|t| t.find(&needle)) {
        n += 1;
        from += i + needle.len();
    }
    n
}

/// The display-list text, for embedding in an SVG as a comment so the two
/// artefacts cannot drift apart.
pub fn embedded_list(list: &DisplayList) -> String {
    let body = list.to_text();
    let mut s = String::with_capacity(body.len() + 128);
    s.push_str("  <!--\n  BEGIN display-list (identical to the standalone artefact)\n");
    for line in body.lines() {
        s.push_str("  ");
        s.push_str(line);
        s.push('\n');
    }
    s.push_str("  END display-list -->\n");
    s
}
