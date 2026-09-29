//! The Canvas2D backend: the generated program must be a faithful record of
//! what this layer can and cannot express in a browser.
//!
//! # The specific trap
//!
//! Canvas2D has a `globalCompositeOperation` that covers most of Android's
//! `PorterDuff.Mode` list, and *not* covering all of it. A backend that mapped
//! the missing ones to the nearest available operator would produce a frame
//! that looks right and is wrong for exactly the cases that are hard to spot —
//! a tint that did not apply, an `ATOP` that became an `OVER`. So the two modes
//! with no operator are **dropped and recorded as a comment in the program**, and
//! the tests count them.
//!
//! The other trap is the reverse: the six separable blend modes *are*
//! expressible, and mapping them to their namesakes looks right. They are
//! emitted with a comment saying the two specifications disagree, because
//! Compositing blends premultiplied channels and Skia does not.

use shim::layout::{Dimension, NodeKind, Orientation, View};
use substrate_runtime::canvas::{
    canvas2d_limitations, canvas2d_mode, Canvas, Canvas2dCanvas, BANNER_BG,
};
use substrate_runtime::draw::{self, DrawConfig, TextSource, Theme};
use substrate_runtime::measure::{UniformMeasurer, ZeroMeasurer};
use substrate_runtime::paint::{Color, Paint, RectF, Shader, TileMode};
use substrate_runtime::testutil::canvas2d_program;
use substrate_runtime::CapabilityReport;

const W: i32 = 360;
const H: i32 = 640;

fn default_cfg() -> DrawConfig {
    DrawConfig::with_viewport(W as f32, H as f32, 1.0)
}

fn simple_tree() -> shim::layout::BoxNode {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut v = View::leaf("a", "View", NodeKind::View);
    v.layout_params.width = Dimension::Exact(10);
    v.layout_params.height = Dimension::Exact(10);
    root.add(v);
    root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    )
}

fn themed_tree() -> shim::layout::BoxNode {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("a", "View", NodeKind::View));
    root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    )
}

#[test]
fn the_program_is_a_function_and_starts_with_the_warning() {
    let js = canvas2d_program(&simple_tree(), &default_cfg(), &ZeroMeasurer::new());
    assert!(js.contains("function substrateDraw(ctx) {"), "{js}");
    assert!(js.contains("THIS RENDERS THE SHIM'S BOX TREE, NOT THE APP"), "{js}");
    assert!(js.contains("onDraw"), "{js}");
    assert!(js.contains("0 reproduced of 11"), "{js}");
    // The banner is drawn, in the loud colour, before anything else.
    let fill_at = js.find("fillStyle").unwrap_or(0);
    let save_at = js.find("ctx.save()").unwrap_or(usize::MAX);
    assert!(fill_at < save_at, "the banner is not first:\n{js}");
    assert!(js.contains(&format!("\"{BANNER_BG}\"")), "{js}");
    assert!(js.contains("RECONSTRUCTION OF THE SHIM'S LAYOUT"), "{js}");
}

#[test]
fn the_program_is_byte_identical_for_the_same_tree() {
    let t = simple_tree();
    let a = canvas2d_program(&t, &default_cfg(), &ZeroMeasurer::new());
    for i in 0..16 {
        assert_eq!(a, canvas2d_program(&t, &default_cfg(), &ZeroMeasurer::new()), "run {i}");
    }
}

#[test]
fn the_bracket_count_balances() {
    // A generated program with an unbalanced brace fails at *runtime* in a
    // browser, which no unit test here would catch. Cheap to check and it is the
    // difference between a program and a string.
    for (name, js) in [
        ("simple", canvas2d_program(&simple_tree(), &default_cfg(), &ZeroMeasurer::new())),
        (
            "themed",
            canvas2d_program(
                &themed_tree(),
                &DrawConfig {
                    theme: Theme::Placeholder,
                    ..default_cfg()
                },
                &ZeroMeasurer::new(),
            ),
        ),
    ] {
        let mut depth = 0i32;
        let mut in_str = false;
        let mut prev = '\0';
        for c in js.chars() {
            if in_str {
                if c == '"' && prev != '\\' {
                    in_str = false;
                }
            } else {
                match c {
                    '"' => in_str = true,
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            assert!(depth >= 0, "{name}: a closing brace with nothing open:\n{js}");
            prev = c;
        }
        assert_eq!(depth, 0, "{name}: {depth} unclosed braces");
        assert!(!in_str, "{name}: an unterminated string:\n{js}");
    }
}

#[test]
fn every_emitted_statement_ends_in_a_semicolon_or_is_a_comment() {
    // A missing semicolon is a syntax error, and a statement without one would
    // swallow the next.
    for (name, js) in [
        ("simple", canvas2d_program(&simple_tree(), &default_cfg(), &ZeroMeasurer::new())),
        (
            "themed",
            canvas2d_program(
                &themed_tree(),
                &DrawConfig {
                    theme: Theme::Placeholder,
                    ..default_cfg()
                },
                &ZeroMeasurer::new(),
            ),
        ),
    ] {
        for line in js.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with("//") || t.starts_with("function") || t == "}" {
                continue;
            }
            assert!(
                t.ends_with(';'),
                "{name}: a statement with no semicolon: {t:?}\n{js}"
            );
        }
    }
}

#[test]
fn a_blend_with_no_compositing_operator_is_dropped_and_counted_not_substituted() {
    // The whole point. `DST` and `INVERT` have no `globalCompositeOperation`.
    // Mapping either to a neighbour would be a silently wrong frame.
    assert_eq!(canvas2d_mode(substrate_runtime::PorterDuffMode::Dst), None);
    assert_eq!(canvas2d_mode(substrate_runtime::PorterDuffMode::Invert), None);
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_rect(
        RectF::new(0.0, 0.0, 10.0, 10.0),
        &Paint::new().with_xfermode(substrate_runtime::PorterDuffMode::Dst),
    )
    .expect("draw");
    assert_eq!(c.dropped_blends(), 1, "the drop was not counted");
    let js = c.lines().join("\n");
    assert!(js.contains("DROPPED blend DST"), "{js}");
    assert!(js.contains("NOT what Android would draw"), "{js}");
    // And the shape is still drawn, composited SRC_OVER, which is the honest
    // outcome: the ink appears and is wrong, and says so.
    assert!(js.contains("ctx.fill()"), "{js}");
}

#[test]
fn every_one_of_the_twenty_one_modes_is_exercised_end_to_end() {
    // Not a table check. Each mode is driven through the real backend and the
    // program is inspected, so a mode that is *declared* one way and *emitted*
    // another fails here.
    for m in substrate_runtime::PorterDuffMode::ALL {
        let mut c = Canvas2dCanvas::new("ctx");
        c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
        c.draw_rect(
            RectF::new(0.0, 0.0, 10.0, 10.0),
            &Paint::new().with_xfermode(m),
        )
        .expect("draw");
        let js = c.lines().join("\n");
        match canvas2d_mode(m) {
            None => {
                assert!(js.contains("DROPPED blend"), "{m} should be dropped:\n{js}");
                assert_eq!(c.dropped_blends(), 1, "{m}");
                assert!(
                    !js.contains("globalCompositeOperation = \"copy\""),
                    "{m}: a dropped blend still set an operator"
                );
            }
            Some((op, substrate_runtime::capability::Support::Exact)) => {
                assert!(
                    js.contains(&format!("globalCompositeOperation = \"{op}\"")),
                    "{m} should set {op}:\n{js}"
                );
                assert!(!js.contains("DROPPED blend"), "{m} was dropped unexpectedly");
                assert!(!js.contains("SUBSTITUTED blend"), "{m} was called substituted");
                assert_eq!(c.dropped_blends(), 0, "{m}");
            }
            Some((op, substrate_runtime::capability::Support::Substituted)) => {
                assert!(
                    js.contains(&format!("globalCompositeOperation = \"{op}\"")),
                    "{m} should set {op}"
                );
                assert!(
                    js.contains("SUBSTITUTED blend"),
                    "{m} must be flagged as substituted:\n{js}"
                );
                assert!(js.contains("premultiplied"), "{m}: the reason is not on the line");
                assert_eq!(c.dropped_blends(), 0, "{m}");
            }
            Some((_, s)) => panic!("{m} mapped to an unexpected support {s:?}"),
        }
    }
}

#[test]
fn src_in_is_exact_in_canvas2d_and_named_correctly() {
    // The brief names SRC_IN, and the mapping is the one people get wrong:
    // Canvas2D's `source-in` is Porter-Duff `SRC_IN`, not `DST_IN`. The
    // direction of the name is literal.
    assert_eq!(
        canvas2d_mode(substrate_runtime::PorterDuffMode::SrcIn),
        Some(("source-in", substrate_runtime::capability::Support::Exact))
    );
    assert_eq!(
        canvas2d_mode(substrate_runtime::PorterDuffMode::DstIn),
        Some(("destination-in", substrate_runtime::capability::Support::Exact))
    );
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 10.0, 10.0), 1.0).expect("frame");
    c.draw_rect(
        RectF::new(0.0, 0.0, 5.0, 5.0),
        &Paint::new().with_xfermode(substrate_runtime::PorterDuffMode::SrcIn),
    )
    .expect("draw");
    assert!(c.lines().join("\n").contains("\"source-in\""));
}

#[test]
fn a_colour_filter_is_dropped_with_a_reason_rather_than_ignored() {
    // Canvas2D has no colour filter. A tint that silently did not apply looks
    // exactly like a correct untinted draw.
    for (cf, want) in [
        (
            substrate_runtime::paint::ColorFilter::PorterDuff(
                substrate_runtime::paint::PorterDuffColorFilter {
                    color: Color::WHITE,
                    mode: substrate_runtime::PorterDuffMode::Multiply,
                },
            ),
            "DROPPED color filter MULTIPLY",
        ),
        (
            substrate_runtime::paint::ColorFilter::Lighting(substrate_runtime::paint::LightingColorFilter {
                ambient_color: 0xFF00_0000,
                diffuse_color: 0xFF00_0000,
                specular_color: 0,
                alpha: 0,
            }),
            "DROPPED lighting color filter",
        ),
    ] {
        let mut c = Canvas2dCanvas::new("ctx");
        c.begin_frame(RectF::new(0.0, 0.0, 10.0, 10.0), 1.0).expect("frame");
        c.draw_rect(
            RectF::new(0.0, 0.0, 5.0, 5.0),
            &Paint::new().fill(Color::BLACK).with_color_filter(cf),
        )
        .expect("draw");
        let js = c.lines().join("\n");
        assert!(js.contains(want), "expected {want:?} in:\n{js}");
        assert_eq!(c.dropped_colour_filters(), 1);
    }
    // SRC_IN is the one mode a scratch composite could do, and the backend says
    // so rather than pretending it applied a filter.
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 10.0, 10.0), 1.0).expect("frame");
    c.draw_rect(
        RectF::new(0.0, 0.0, 5.0, 5.0),
        &Paint::new().fill(Color::BLACK).with_color_filter(
            substrate_runtime::paint::ColorFilter::PorterDuff(
                substrate_runtime::paint::PorterDuffColorFilter {
                    color: Color::WHITE,
                    mode: substrate_runtime::PorterDuffMode::SrcIn,
                },
            ),
        ),
    )
    .expect("draw");
    let js = c.lines().join("\n");
    assert!(js.contains("scratch composite"), "{js}");
    assert_eq!(c.dropped_colour_filters(), 0, "SRC_IN is not dropped");
}

#[test]
fn a_gradient_becomes_a_create_gradient_call_with_its_stops() {
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_rect(
        RectF::new(0.0, 0.0, 50.0, 50.0),
        &Paint::new().with_shader(Shader::Linear {
            x0: 0.0,
            y0: 0.0,
            x1: 50.0,
            y1: 0.0,
            colors: vec![Color::BLACK, Color::WHITE],
            positions: vec![0.0, 1.0],
            tile: TileMode::Clamp,
        }),
    )
    .expect("draw");
    let js = c.lines().join("\n");
    assert!(js.contains("ctx.createLinearGradient(0, 0, 50, 0"), "{js}");
    assert!(js.contains("offset:0"), "{js}");
    assert!(js.contains("offset:1"), "{js}");
    // The interpolation-space divergence is recorded on the line.
    assert!(js.contains("sRGB-interpolated"), "{js}");
}

#[test]
fn a_radial_gradient_with_an_offset_focus_records_what_it_cannot_do() {
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_rect(
        RectF::new(0.0, 0.0, 50.0, 50.0),
        &Paint::new().with_shader(Shader::Radial {
            cx: 25.0,
            cy: 25.0,
            radius: 20.0,
            fx: 10.0,
            fy: 10.0,
            colors: vec![Color::BLACK, Color::WHITE],
            positions: Vec::new(),
            tile: TileMode::Repeat,
        }),
    )
    .expect("draw");
    let js = c.lines().join("\n");
    assert!(js.contains("ctx.createRadialGradient(25, 25, 0, 20"), "{js}");
    assert!(js.contains("NOT expressible"), "the focal offset was silently dropped: {js}");
}

#[test]
fn a_clip_records_that_canvas2d_cannot_antialias_one() {
    // The app asked for an antialiased clip. Canvas2D has no control over it. The
    // comment says the flag was asked for and cannot be honoured.
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.clip_rect(RectF::new(0.0, 0.0, 50.0, 50.0), true).expect("clip");
    let js = c.lines().join("\n");
    assert!(js.contains("ctx.clip(\"antialiased\")"), "{js}");
    assert!(
        js.contains("not controllable in Canvas2D"),
        "the antialias divergence is not recorded: {js}"
    );
    // And an unaliased clip is passed through with the same note.
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.clip_rect(RectF::new(0.0, 0.0, 50.0, 50.0), false).expect("clip");
    let js = c.lines().join("\n");
    assert!(js.contains("asked: false"), "{js}");
}

#[test]
fn a_text_run_says_the_glyphs_come_from_the_host_and_names_the_measuring_model() {
    // The failure a screenshot invites: a browser's font rendering a string and
    // looking like a device. The comment on the draw call says otherwise.
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let js = canvas2d_program(&tree, &cfg, &UniformMeasurer::new());
    assert!(js.contains("ctx.fillText("), "{js}");
    assert!(
        js.contains("glyphs come from the HOST's font stack"),
        "the glyph provenance is not on the draw call:\n{js}"
    );
    assert!(js.contains("uniform-advance-stub/v1"), "the model is not named: {js}");
    assert!(js.contains("14px sans-serif"), "{js}");
}

#[test]
fn an_undecoded_image_draws_nothing_and_says_so() {
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_image(
        &substrate_runtime::canvas::ImageDraw {
            id: "pic".to_string(),
            bitmap: substrate_runtime::canvas::ImageBitmap::empty(10, 10),
            src: None,
            dst: RectF::new(0.0, 0.0, 10.0, 10.0),
        },
        &Paint::new(),
    )
    .expect("draw");
    let js = c.lines().join("\n");
    assert!(js.contains("NO PIXELS for pic"), "{js}");
    assert!(!js.contains("ctx.drawImage"), "an image was drawn from nothing");
}

#[test]
fn a_decoded_image_is_not_drawn_either_because_there_is_no_encoder() {
    let mut c = Canvas2dCanvas::new("ctx");
    c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
    c.draw_image(
        &substrate_runtime::canvas::ImageDraw {
            id: "pic".to_string(),
            bitmap: substrate_runtime::canvas::ImageBitmap {
                width: 2,
                height: 2,
                pixels: Some(vec![0; 16]),
            },
            src: None,
            dst: RectF::new(0.0, 0.0, 10.0, 10.0),
        },
        &Paint::new(),
    )
    .expect("draw");
    let js = c.lines().join("\n");
    assert!(js.contains("no image encoder"), "{js}");
    assert!(js.contains("NOT drawn"), "{js}");
    assert!(!js.contains("ctx.drawImage"));
}

#[test]
fn annotations_reach_the_program_as_comments_not_as_ink() {
    // An annotation is a statement about the reconstruction. Rendering it would
    // be a claim about the app.
    let js = canvas2d_program(&draw::demo_tree(W, H), &default_cfg(), &ZeroMeasurer::new());
    assert!(js.contains("// box "), "{js}");
    assert!(js.contains("// unknown-ink"), "{js}");
    assert!(js.contains("// text-withheld"), "{js}");
    assert!(
        !js.contains("ctx.fillText(\"chars withheld"),
        "an annotation was rendered as text: {js}"
    );
}

#[test]
fn the_two_backends_walk_the_tree_identically() {
    // Same tree, same config, two backends. The *sequence of operations* must
    // match; only the encoding differs. If it did not, a difference in the
    // outputs could be a difference in the walks.
    let tree = draw::demo_tree(W, H);
    let cfg = default_cfg();
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("display list");
    let js = canvas2d_program(&tree, &cfg, &ZeroMeasurer::new());
    for (op, js_call) in [
        ("translate", "ctx.translate("),
        ("clip-rect", "ctx.clip("),
    ] {
        let from_list = list
            .steps
            .iter()
            .filter(|s| s.command.name() == op)
            .count();
        let from_js = js.matches(js_call).count();
        assert_eq!(from_list, from_js, "{op}: list {from_list} vs js {from_js}");
    }
    let saves_list = list.steps.iter().filter(|s| s.command.name() == "push").count();
    let saves_js = js.matches("ctx.save()").count();
    // The Canvas2D clip path also saves, so the JS count is at least the list's.
    assert!(saves_js >= saves_list, "list {saves_list} vs js {saves_js}");
    let restores_list = list
        .steps
        .iter()
        .filter(|s| s.command.name() == "pop")
        .count();
    let restores_js = js.matches("ctx.restore()").count();
    assert!(restores_js >= restores_list, "list {restores_list} vs js {restores_js}");
}

#[test]
fn the_canvas2d_report_says_the_same_eleven_verdicts_and_no_more() {
    let r = CapabilityReport::audit(
        substrate_runtime::BackendKind::Canvas2d,
        &substrate_runtime::canvas::canvas2d_claims(),
        canvas2d_limitations(),
        substrate_runtime::canvas::probe_answer,
    );
    assert_eq!(r.entries.len(), 11);
    assert_eq!(r.reproduced(), 0);
    assert!(r.clean(), "{:?}", r.audit.mismatches);
    // The rasterisation row is the one that *improves* over the headless backend,
    // and it improves in a specific way: the browser really does draw.
    let raster = canvas2d_limitations()
        .into_iter()
        .find(|l| l.feature == "rasterisation")
        .expect("a rasterisation row");
    assert_eq!(raster.support, substrate_runtime::capability::Support::Exact);
    assert!(raster.note.contains("not Skia"), "{}", raster.note);
}

#[test]
fn a_step_limit_turns_a_runaway_program_into_a_typed_error() {
    let mut c = Canvas2dCanvas::new("ctx");
    c.set_step_limit(3);
    c.begin_frame(RectF::new(0.0, 0.0, 10.0, 10.0), 1.0).expect("frame");
    let mut err = None;
    for _ in 0..10 {
        if let Err(e) = c.draw_rect(
            RectF::new(0.0, 0.0, 1.0, 1.0),
            &Paint::new().fill(Color::BLACK),
        ) {
            err = Some(e);
            break;
        }
    }
    let e = err.expect("the limit was never hit");
    assert_eq!(e.kind(), "TooManySteps", "{e}");
}

#[test]
fn a_bad_viewport_is_refused_by_both_backends() {
    for (w, h, d) in [(0.0, 0.0, 0.0), (1.0, 1.0, -1.0), (f32::NAN, 1.0, 1.0)] {
        let r = RectF::new(0.0, 0.0, w, h);
        let mut c = Canvas2dCanvas::new("ctx");
        let e = c.begin_frame(r, d).unwrap_err();
        assert!(
            matches!(e.kind(), "BadViewport" | "NonFinite"),
            "{w}x{h} at {d} gave {e}"
        );
    }
}
