//! The SVG serialisation: well-formed, escaped, and honest about what it drops.
//!
//! # The checks that matter here
//!
//! A display list that is honest can still be serialised into a file that lies —
//! by dropping a blend without saying so, by letting an untrusted view id break
//! the XML, or by omitting the banner. So the tests check the *file*, not the
//! struct.

use shim::layout::{Dimension, NodeKind, Orientation, View};
use substrate_runtime::canvas::{Canvas as _, Command, DisplayList, HeadlessCanvas};
use substrate_runtime::draw::{self, DrawConfig, TextSource, Theme};
use substrate_runtime::measure::{UniformMeasurer, ZeroMeasurer};
use substrate_runtime::paint::{
    Color, Paint, PaintStyle, PorterDuffColorFilter, PorterDuffMode, RectF, Shader, TileMode,
};
use substrate_runtime::svg::{self, SvgFidelity};

const W: i32 = 360;
const H: i32 = 640;

fn default_cfg() -> DrawConfig {
    DrawConfig::with_viewport(W as f32, H as f32, 1.0)
}

fn default_svg() -> (String, SvgFidelity, DisplayList) {
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let (s, f) = svg::to_svg(&list).expect("svg");
    (s, f, list)
}

/// A minimal well-formedness checker: tags balance, attributes are quoted,
/// nothing is left open. Not a full XML parser — a parser would be a dependency
/// and a parser would also be *too lenient* about the things most likely to be
/// wrong here.
fn assert_well_formed(doc: &str) {
    let mut stack: Vec<String> = Vec::new();
    let bytes: Vec<char> = doc.chars().collect();
    let mut i = 0;
    let mut tags = 0usize;
    while i < bytes.len() {
        if bytes[i] != '<' {
            i += 1;
            continue;
        }
        // A comment or a declaration.
        if doc[i..].starts_with("<!--") {
            let end = doc[i..].find("-->").map(|p| i + p + 3);
            assert!(end.is_some(), "an unterminated comment");
            i = end.unwrap_or(bytes.len());
            continue;
        }
        if doc[i..].starts_with("<?") {
            let end = doc[i..].find("?>").map(|p| i + p + 2);
            assert!(end.is_some(), "an unterminated XML declaration");
            i = end.unwrap_or(bytes.len());
            continue;
        }
        let close = doc[i..].find('>').map(|p| i + p);
        let close = close.unwrap_or_else(|| panic!("a '<' with no '>' at offset {i}"));
        let inner: String = doc[i + 1..close].to_string();
        i = close + 1;
        tags += 1;
        if let Some(name) = inner.strip_prefix('/') {
            let got = stack.pop();
            assert_eq!(
                got.as_deref(),
                Some(name.trim()),
                "closing tag </{name}> does not match the open element"
            );
        } else {
            let self_closing = inner.trim_end().ends_with('/');
            // An attribute value must be quoted if there is one.
            let name_end = inner
                .find(|c: char| c.is_whitespace())
                .unwrap_or(inner.len());
            let name = inner[..name_end].to_string();
            assert!(!name.is_empty(), "an empty tag name");
            let rest = &inner[name_end..];
            if let Some(eq) = rest.find('=') {
                let after = rest[eq + 1..].trim_start();
                assert!(
                    after.starts_with('"'),
                    "attribute of <{name}> is not double-quoted: {rest}"
                );
            }
            if !self_closing {
                stack.push(name);
            }
        }
    }
    assert!(stack.is_empty(), "unclosed elements: {stack:?}");
    assert!(tags > 10, "only {tags} tags: the checker is not seeing the document");
}

#[test]
fn the_default_svg_is_well_formed() {
    let (s, _f, _l) = default_svg();
    assert_well_formed(&s);
}

#[test]
fn the_svg_says_what_it_is_in_three_places() {
    // The banner (visual), the `<desc>` (for a screen reader and for grep), and
    // the attributes (for a program). One is not enough: an SVG pasted into a
    // document loses its filename but not its attributes.
    let (s, _f, _l) = default_svg();
    assert!(s.contains("data-substrate-is-android=\"false\""));
    assert!(s.contains("data-substrate-provenance=\"reconstruction-of-shim-box-tree\""));
    assert!(s.contains("data-app-draw-code-executed=\"false\""));
    assert!(s.contains("<desc>"));
    assert!(s.contains("THIS FILE IS NOT A SCREENSHOT OF AN APP."));
    assert!(s.contains("id=\"provenance-banner\""));
    assert!(s.contains("id=\"provenance-legend\""));
    assert!(s.contains("RECONSTRUCTION"));
}

#[test]
fn every_drawn_element_carries_a_provenance() {
    // Checked by counting, not by reading: if a serialiser path forgot the
    // attribute, the count would drop and this fails.
    let (s, _f, list) = default_svg();
    let tagged = svg::count_attr(&s, "data-prov");
    // Every step becomes at least one element, plus the two group wrappers and
    // the banner and legend groups.
    assert!(
        tagged >= list.steps.len(),
        "{tagged} elements are tagged for {} steps",
        list.steps.len()
    );
    // And every provenance value in the output is one this crate defines.
    for p in substrate_runtime::paint::Provenance::ALL {
        let pat = format!("data-prov=\"{}\"", p.as_str());
        let _ = s.contains(&pat);
    }
    let mut i = 0;
    let mut found: Vec<String> = Vec::new();
    while let Some(at) = s[i..].find("data-prov=\"") {
        let start = i + at + "data-prov=\"".len();
        let rest = &s[start..];
        let end = rest.find('"').unwrap_or(0);
        found.push(rest[..end].to_string());
        i = start + end;
    }
    assert!(!found.is_empty());
    for f in &found {
        assert!(
            substrate_runtime::paint::Provenance::ALL
                .iter()
                .any(|p| p.as_str() == f),
            "unknown provenance token {f:?} in the output"
        );
    }
}

#[test]
fn the_capability_report_is_in_the_metadata_and_complete() {
    let (s, _f, _l) = default_svg();
    assert!(s.contains("<substrate:capability"));
    for g in substrate_runtime::GfxId::ALL {
        assert!(
            s.contains(&format!("id=\"{}\"", g.assumption())),
            "no assumption row for {}",
            g.assumption()
        );
    }
    assert!(s.contains("data-gfx-ids-total=\"11\""));
    assert!(s.contains("data-gfx-reproduced=\"0\""));
    assert!(s.contains("data-report-audit-mismatches=\"0\""));
    assert!(s.contains("<substrate:measure-model>"));
    assert!(s.contains("<substrate:headline>"));
}

#[test]
fn the_counts_in_the_metadata_agree_with_the_display_list() {
    let (s, _f, list) = default_svg();
    let c = &list.counts;
    for (key, want) in [
        ("steps", c.steps as u64),
        ("ink", c.ink_steps as u64),
        ("ink-fabricated", c.ink_fabricated as u64),
        ("annotations", c.annotations as u64),
        ("text-runs", c.text_runs as u64),
        ("text-withheld", c.text_withheld as u64),
        ("images-drawn", c.images_drawn as u64),
        ("images-absent", c.images_absent as u64),
        ("clip-regions", c.clip_regions as u64),
        ("leaf-area-dp2", c.leaf_area_dp2),
    ] {
        let pat = format!("{key}=\"{want}\"");
        assert!(s.contains(&pat), "the metadata does not say {pat}");
    }
}

#[test]
fn the_banner_sits_above_the_viewport_and_does_not_scale_it() {
    // The reconstruction is not scaled to make room for the banner; the banner
    // is added above it. So the app's own rectangle has exactly the viewport's
    // device-pixel size, and a reader can measure it.
    let (s, _f, list) = default_svg();
    let banner = svg::banner_height(list.viewport.height_dp);
    assert!(banner > 0.0);
    let vp_w = list.viewport.px_width();
    let vp_h = list.viewport.px_height();
    let want = format!("data-viewport-rect=\"x=0 y={} w={} h={}\"", substrate_runtime::canvas::q(banner), substrate_runtime::canvas::q(vp_w), substrate_runtime::canvas::q(vp_h));
    assert!(s.contains(&want), "the viewport rect is not where it should be");
    // The document is taller than the app by exactly the banner.
    let h_attr = extract_attr(&s, "height").unwrap_or_default();
    assert!(
        h_attr.contains(&substrate_runtime::canvas::q(vp_h + banner)),
        "document height {h_attr} is not the viewport plus the banner"
    );
}

fn extract_attr(doc: &str, name: &str) -> Option<String> {
    let at = doc.find(&format!(" {name}=\""))?;
    let start = at + name.len() + 3;
    let rest = &doc[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[test]
fn a_dropped_blend_is_annotated_on_the_element_and_escalates_the_banner() {
    // The failure this whole crate is built against: emitting a shape that
    // looks like the app's, having silently not applied the blend. So: the
    // element says so, and the banner changes colour.
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("a", "View", NodeKind::View));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let cfg = DrawConfig {
        theme: Theme::Placeholder,
        ..default_cfg()
    };
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    // Inject a mode SVG cannot express. The list is a value, so this is a
    // legitimate construction rather than a hack on the serialiser.
    let mut list = list;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            **paint = paint.clone().with_xfermode(PorterDuffMode::DstAtop);
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert_eq!(f.dropped_blends, vec![PorterDuffMode::DstAtop], "{f:?}");
    assert!(s.contains("data-blend-dropped=\"true\""), "{s}");
    assert!(
        s.contains("NOT what Android would draw"),
        "the element does not say the ink is wrong"
    );
    // The banner escalated from dark red to black.
    assert!(s.contains("fill=\"#000000\""), "the banner did not escalate");
    assert!(f.summary().contains("DST_ATOP"), "{}", f.summary());
    assert_well_formed(&s);
}

#[test]
fn an_expressible_blend_is_annotated_as_exact_and_not_as_dropped() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("a", "View", NodeKind::View));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let (list, _r) = draw::render(
        &tree,
        &DrawConfig {
            theme: Theme::Placeholder,
            ..default_cfg()
        },
        &ZeroMeasurer::new(),
    )
    .expect("render");
    let mut list = list;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            **paint = paint.clone().with_xfermode(PorterDuffMode::SrcIn);
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert!(f.dropped_blends.is_empty(), "{f:?}");
    assert!(s.contains("data-blend-exact=\"true\""), "SRC_IN should be exact in SVG");
    assert!(!s.contains("data-blend-dropped"), "{s}");
    // The filter it references is actually defined.
    assert!(s.contains("<filter id=\"blend-in\""), "the filter is missing");
    assert!(s.contains("operator=\"in\""), "{s}");
    assert_well_formed(&s);
}

#[test]
fn a_substituted_blend_says_both_specs_disagree() {
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            **paint = paint.clone().with_xfermode(PorterDuffMode::Multiply);
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert_eq!(f.substituted_blends, vec![PorterDuffMode::Multiply]);
    assert!(s.contains("data-blend-substituted=\"true\""), "{s}");
    assert!(s.contains("unpremultiplied"), "the reason is not on the element");
    assert!(!s.contains("data-blend-exact"), "MULTIPLY must not be called exact");
}

#[test]
fn a_gradient_becomes_a_real_gradient_element_not_an_average() {
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { rect, paint } = &mut s.command {
            let p = Paint::new().with_shader(Shader::Linear {
                x0: rect.left,
                y0: rect.top,
                x1: rect.right,
                y1: rect.bottom,
                colors: vec![Color::BLACK, Color::WHITE],
                positions: Vec::new(),
                tile: TileMode::Clamp,
            });
            **paint = p;
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert!(f.flattened_shaders.is_empty(), "a linear gradient is expressible: {f:?}");
    assert!(s.contains("<linearGradient"), "{s}");
    assert!(s.contains("spreadMethod=\"pad\""), "the tile mode is not recorded");
    assert!(s.contains("stop-color=\"#000000\""));
    assert!(s.contains("stop-color=\"#ffffff\""));
    assert!(s.contains("gradientUnits=\"userSpaceOnUse\""), "the gradient must be in the node's space");
    assert_well_formed(&s);
}

#[test]
fn a_radial_gradient_writes_its_focus_out_rather_than_leaving_it_to_the_default() {
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { rect, paint } = &mut s.command {
            let p = Paint::new().with_shader(Shader::Radial {
                cx: rect.center_x(),
                cy: rect.center_y(),
                radius: 40.0,
                fx: rect.left + 5.0,
                fy: rect.top + 5.0,
                colors: vec![Color::WHITE, Color::BLACK],
                positions: vec![0.0, 1.0],
                tile: TileMode::Repeat,
            });
            **paint = p;
        }
    }
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.contains("<radialGradient"), "{s}");
    assert!(s.contains("fx="), "the focal point is not written: {s}");
    assert!(s.contains("spreadMethod=\"repeat\""), "mirror must map to repeat and say so");
}

#[test]
fn a_stroke_only_paint_is_recorded_as_a_svg_limitation() {
    // SVG has no FILL/STROKE style: it always has both, and `paint-order`
    // decides which is on top. A `STROKE` paint therefore draws a fill SVG
    // would draw and Canvas2D would not.
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            let p = Paint::new().stroke(Color::BLACK, 2.0);
            let p = Paint { style: PaintStyle::Stroke, ..p };
            **paint = p;
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert!(!f.stroke_style_losses.is_empty(), "{f:?}");
    assert!(s.contains("fill=\"none\""), "a stroke paint must not fill in SVG");
    assert!(s.contains("data-style=\"stroke\""), "{s}");
    assert!(f.summary().contains("FILL/STROKE"), "{}", f.summary());
}

#[test]
fn a_fill_paint_with_a_stroke_width_does_not_silently_gain_a_stroke() {
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            let p = Paint::new().fill(Color::BLACK);
            let p = Paint { stroke_width: 4.0, ..p };
            **paint = p;
        }
    }
    let (s, f) = svg::to_svg(&list).expect("svg");
    assert!(
        f.stroke_style_losses.contains(&"FILL-with-stroke"),
        "{f:?}"
    );
    assert!(s.contains("data-note=\"stroke-width set but style=fill"));
    assert!(!s.contains("stroke=\"#"), "a fill paint gained a stroke: {s}");
}

#[test]
fn a_colour_filter_is_a_note_and_not_a_filter() {
    // SVG has no colour filter. The only Porter-Duff mode a flood-and-composite
    // can express is SRC_IN, and this layer does not even do that, so every
    // filter is recorded as a note.
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            **paint = paint.clone().with_color_filter(substrate_runtime::paint::ColorFilter::PorterDuff(
                PorterDuffColorFilter {
                    color: Color::WHITE,
                    mode: PorterDuffMode::SrcIn,
                },
            ));
        }
    }
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.contains("cf=porter-duff"), "{s}");
    // And the shape is not tinted, which is the honest outcome, with the caveat
    // in the summary rather than a false claim of a tint.
    assert!(!s.contains("<feFlood flood-color=\"#ffffff\" result=\"tint"));
    let _ = RectF::new(0.0, 0.0, 1.0, 1.0);
}

#[test]
fn an_untrusted_view_id_cannot_inject_xml() {
    // The vector is hostile: quotes, angle brackets, an ampersand, a newline.
    let nasty = "a\"b<c>d&e'f\ng\"";
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf(nasty, "View", NodeKind::View));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.contains("&quot;") || s.contains("&amp;") || s.contains("&lt;"), "{s}");
    assert!(!s.contains(&format!("id=\"{nasty}\"")), "the id was not escaped");
    // No attribute was closed early.
    assert!(!s.contains("data-view=\"a\"b"), "an injection landed: {s}");
    assert_well_formed(&s);
}

#[test]
fn a_wildcard_path_does_not_break_the_d_attribute() {
    let mut p = substrate_runtime::paint::Path::new();
    p.move_to(0.0, 0.0)
        .quad_to(1.0, 2.0, 3.0, 4.0)
        .cubic_to(1.0, 1.0, 2.0, 2.0, 3.0, 3.0)
        .close();
    let d = p.to_svg_d();
    assert!(d.contains("Q "), "{d}");
    assert!(d.contains("C "), "{d}");
    assert!(d.ends_with('Z'), "{d}");
    // No exponent notation, which some viewers' path parsers reject.
    assert!(!d.contains('e') && !d.contains('E'), "{d}");
}

#[test]
fn a_non_finite_coordinate_is_refused_rather_than_written_as_nan() {
    // `NaN` in an SVG attribute is not a number; it is a parse error in
    // somebody else's reader.
    let mut c = HeadlessCanvas::new();
    let cfg = default_cfg();
    c.begin_frame(cfg.viewport.rect(), 1.0).expect("frame");
    let e = c
        .draw_rect(
            RectF::new(f32::NAN, 0.0, 1.0, 1.0),
            &Paint::new().fill(Color::BLACK),
        )
        .unwrap_err();
    assert_eq!(e.kind(), "NonFinite", "{e}");
    let e2 = c
        .translate(f32::INFINITY, 0.0)
        .unwrap_err();
    assert_eq!(e2.kind(), "NonFinite", "{e2}");
    // And a path.
    let mut p = substrate_runtime::paint::Path::new();
    p.line_to(f32::NAN, 0.0);
    let e3 = c.clip_path(&p, false).unwrap_err();
    assert_eq!(e3.kind(), "NonFinite", "{e3}");
}

#[test]
fn the_legend_explains_every_pattern_the_output_uses() {
    let (s, _f, _l) = default_svg();
    for (pat, _) in [
        ("pat-unknown", ""),
        ("pat-withheld", ""),
        ("pat-absent", ""),
    ] {
        assert!(s.contains(&format!("<pattern id=\"{pat}\"")), "{pat} is not defined");
        assert!(s.contains(&format!("url(#{pat})")), "{pat} is not used or not keyed");
    }
    assert!(s.contains("not app ink"), "the legend does not disclaim the outlines");
}

#[test]
fn an_empty_tree_still_produces_a_valid_svg_with_the_banner() {
    // The most important degenerate case: nothing to draw. The output must still
    // be a valid, labelled file, not a broken one and not a fake frame.
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert_well_formed(&s);
    assert!(s.contains("RECONSTRUCTION"));
    assert!(s.contains("data-ink-fabricated=\"0\""));
}

#[test]
fn a_zero_viewport_produces_a_tiny_but_valid_svg() {
    for (w, h) in [(0.0, 0.0), (1.0, 1.0)] {
        let tree = draw::demo_tree(W, H);
        let (list, _r) = draw::render(
            &tree,
            &DrawConfig::with_viewport(w, h, 1.0),
            &ZeroMeasurer::new(),
        )
        .expect("render");
        let (s, _f) = svg::to_svg(&list).expect("svg");
        assert_well_formed(&s);
        assert!(!s.contains("nan"), "a NaN reached a {w}x{h} svg");
    }
}

#[test]
fn a_text_run_in_svg_carries_its_measure_model_and_a_transparent_paint_is_not_black() {
    let tree = draw::demo_tree_with_text(W, H);
    let (list, _r) = draw::render(
        &tree,
        &DrawConfig {
            text: TextSource::from_tree(&tree),
            ..default_cfg()
        },
        &UniformMeasurer::new(),
    )
    .expect("render");
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.contains("<text "), "no text element: {s}");
    assert!(s.contains("data-measure-model=\"uniform-advance-stub/v1\""), "{s}");
    assert!(s.contains("data-measure-prov=\"fabricated\""), "{s}");
    assert!(s.contains("data-advance=\""), "{s}");
    // The default paint is black, so the glyphs are black; the point is that the
    // advance is labelled, not that the colour is interesting.
    assert!(s.contains("fill=\"#000000\""), "{s}");
    assert_well_formed(&s);
}

#[test]
fn a_transparent_paint_does_not_come_out_as_black_glyphs() {
    // A `Fill` paint with a transparent colour and no shader must render as
    // nothing, not as a default fill.
    let mut list = default_svg().2;
    for s in &mut list.steps {
        if let Command::DrawRect { paint, .. } = &mut s.command {
            let p = Paint::new();
            let p = Paint { color: Color::TRANSPARENT, ..p };
            **paint = p;
        }
    }
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.contains("fill-opacity=\"0\""), "{s}");
    assert!(s.contains("fill=\"#000000\""));
    // The colour is the transparent black, so the hex is black and the opacity
    // carries the transparency. That is correct and it is why the attribute is
    // there.
    assert!(!s.contains("fill-opacity=\"1\" fill=\"#000000\""), "{s}");
}

#[test]
fn the_svg_is_byte_identical_for_the_same_list() {
    let list = default_svg().2;
    let a = svg::to_svg(&list).expect("1").0;
    let b = svg::to_svg(&list).expect("2").0;
    assert_eq!(a, b);
    let (_t, _f, other) = default_svg();
    assert_eq!(svg::to_svg(&other).expect("3").0, a, "a rebuild differed");
}

#[test]
fn a_walk_of_the_svg_sees_the_same_operations_as_the_display_list() {
    // Cross-check: the number of draw operations in the file matches the
    // display list's, so nothing was dropped in serialisation.
    let (s, _f, list) = default_svg();
    let ops = svg::count_attr(&s, "data-op=");
    let expected = list
        .steps
        .iter()
        .filter(|st| !matches!(st.command, Command::ClipRect { .. } | Command::ClipPath { .. }))
        .count();
    // Clips emit an element *and* a clipPath, and Save/Restore emit a group, so
    // the count is at least the number of non-clip steps.
    assert!(
        ops >= expected,
        "{ops} data-op attributes for {expected} non-clip steps"
    );
    for st in &list.steps {
        if matches!(st.command, Command::Annotate(substrate_runtime::canvas::Annotation::TextWithheld { .. }))
        {
            assert!(s.contains("data-op=\"text-withheld\""), "{s}");
        }
    }
}

#[test]
fn a_display_list_built_by_hand_serialises_as_well_as_a_drawn_one() {
    // The serialiser is a property of the list, not of how the list was made.
    let mut c = HeadlessCanvas::new();
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_rect(RectF::new(1.0, 2.0, 3.0, 4.0), &Paint::new().fill(Color::argb_of(255, 200, 30, 30)))
        .expect("rect");
    let list: DisplayList = c.finish("");
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert_well_formed(&s);
    assert!(s.contains("data-prov=\"fabricated\""), "a hand-built rect is still fabricated ink");
}
