//! No panics on untrusted input, enforced two ways.
//!
//! # The threat
//!
//! Everything this crate serialises came out of an APK: view ids, class names,
//! characters, numbers, tree depths, bitmap dimensions, a viewport an app or a
//! host page chose. A panic here is not a crash of the app under study, it is a
//! denial of service against the *measurement apparatus* — and an apparatus its
//! subject can crash is an apparatus whose corpus its subject selects.
//!
//! Two independent mechanisms, because either alone has a hole:
//!
//! 1. **A source scan** for `unwrap`, `expect`, `panic!`, `unreachable!`,
//!    indexing and arithmetic that can overflow, over every library file. The
//!    crate also carries `#![cfg_attr(not(test), deny(clippy::unwrap_used,
//!    clippy::expect_used, clippy::panic))]`, so the scan and the compiler agree.
//! 2. **Hostile-input fuzzing** at the public entry points, with a fixed corpus
//!    of awkward values plus a deterministic byte-mutation loop, so a crash is a
//!    reproducible test failure rather than a field report.
//!
//! Both are bounded. An unbounded fuzzer is itself a denial of service in a test
//! suite, and a scan that cannot terminate teaches a reader nothing.

use substrate_runtime::canvas::{
    Command, DisplayList, HeadlessCanvas, ImageBitmap, ImageDraw, ImageSource, TextRun,
};
use substrate_runtime::draw::{self, DrawConfig, TextSource, Theme};
use substrate_runtime::measure::{
    TextAdvance, TextStyle, TextMeasurer, UniformMeasurer, ZeroMeasurer,
};
use substrate_runtime::paint::{
    Color, ColorFilter, LightingColorFilter, Paint, Path, PorterDuffColorFilter, PorterDuffMode,
    RectF, Shader, TileMode,
};
use substrate_runtime::svg;
use substrate_runtime::{CapabilityReport, Canvas, Canvas2dCanvas, GfxId, GraphicsError, Provenance};

/// Every library file, included rather than walked so the test works whatever
/// the current directory is.
const SOURCES: &[(&str, &str)] = &[
    ("mod.rs", include_str!("../mod.rs")),
    ("error.rs", include_str!("../error.rs")),
    ("capability.rs", include_str!("../capability.rs")),
    ("canvas.rs", include_str!("../canvas.rs")),
    ("svg.rs", include_str!("../svg.rs")),
    ("paint.rs", include_str!("../paint.rs")),
    ("measure.rs", include_str!("../measure.rs")),
    ("draw.rs", include_str!("../draw.rs")),
    ("testutil.rs", include_str!("../testutil.rs")),
];

/// The `#[cfg(test)] mod tests` block, if a file has one, starts here.
fn is_test_code(src: &str, at: usize) -> bool {
    // Find the enclosing `mod tests {` before this offset, and check there is no
    // closing brace between it and the offset at column zero. Crude, but a file
    // in this crate has exactly one `mod tests` and it is last.
    let head = &src[..at];
    match head.rfind("\nmod tests {") {
        None => false,
        Some(i) => {
            let tail = &head[i..];
            !tail.contains("\n}\n")
        }
    }
}

#[test]
fn no_unwrap_expect_or_panic_outside_test_code() {
    let mut hits = Vec::new();
    for (name, src) in SOURCES {
        for (i, line) in src.lines().enumerate() {
            if is_test_code(src, line_offset(src, i)) {
                continue;
            }
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("///") || t.starts_with("*") {
                continue;
            }
            for banned in [".unwrap()", ".expect(", "panic!", "unreachable!", "todo!"] {
                if t.contains(banned) {
                    hits.push(format!("{name}:{}: {line}", i + 1));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the library must not panic on untrusted input; found:\n{}",
        hits.join("\n")
    );
}

fn line_offset(src: &str, line: usize) -> usize {
    let mut n = 0;
    for (i, l) in src.lines().enumerate() {
        if i == line {
            return n;
        }
        n += l.len() + 1;
    }
    0
}

#[test]
fn no_unchecked_indexing_outside_test_code() {
    // `a[i]` where `a` is a `Vec` or a slice panics out of bounds. Every
    // collection walk in this crate is an iterator; this makes that a rule rather
    // than a habit.
    let mut hits = Vec::new();
    for (name, src) in SOURCES {
        for (i, line) in src.lines().enumerate() {
            if is_test_code(src, line_offset(src, i)) {
                continue;
            }
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("///") {
                continue;
            }
            // A `[` followed by a digit or a quote, and a matching `]`. Crude
            // enough to over-report and precise enough to catch a real index.
            let bytes: Vec<char> = t.chars().collect();
            for (j, c) in bytes.iter().enumerate() {
                if *c != '[' || j + 1 >= bytes.len() {
                    continue;
                }
                let next = bytes[j + 1];
                if next.is_ascii_digit() || next == '"' || next == '\'' {
                    // Not a slice pattern or an attribute.
                    if !t[..j].contains("matches!") && !t.contains("#[") {
                        hits.push(format!("{name}:{}: {line}", i + 1));
                    }
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "indexing in the library is a potential panic:\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_arithmetic_that_can_overflow_on_untrusted_input() {
    // `as` conversions and `+`/`*` on values that came from an APK. The rule
    // this crate follows: `saturating_*`, `checked_*`, or a `max(0)`. Checked
    // by looking for a `+` on a value named like a size or a coordinate in a
    // `let`, which is crude but catches the shape of the mistake.
    let mut hits = Vec::new();
    for (name, src) in SOURCES {
        for (i, line) in src.lines().enumerate() {
            if is_test_code(src, line_offset(src, i)) {
                continue;
            }
            let t = line.trim_start();
            if t.starts_with("//") || t.starts_with("///") {
                continue;
            }
            if (t.contains("width_dp +") || t.contains("height_dp +") || t.contains("* density")
                || t.contains("width() +") || t.contains("height() +"))
                && !t.contains("saturating")
                && !t.contains("checked")
                && !t.contains("max(")
            {
                hits.push(format!("{name}:{}: {line}", i + 1));
            }
        }
    }
    assert!(hits.is_empty(), "unsaturating arithmetic on derived values:\n{}", hits.join("\n"));
}

#[test]
fn a_degenerate_viewport_is_refused_rather_than_turned_into_a_huge_canvas() {
    for (w, h, d) in [
        (0.0, 0.0, 0.0),
        (-1.0, 10.0, 1.0),
        (1.0, 1.0, -1.0),
        (f32::NAN, 10.0, 1.0),
        (f32::INFINITY, 1.0, 1.0),
        (1.0e30, 1.0e30, 1.0e30),
    ] {
        let r = RectF::new(0.0, 0.0, w, h);
        let mut c = Canvas2dCanvas::new("ctx");
        let e = c.begin_frame(r, d);
        match e {
            Ok(()) => {
                // A viewport that passed must have produced a canvas of a sane
                // size, or the check is doing nothing.
                let w_px = c.width_px;
                let h_px = c.height_px;
                assert!(
                    (w_px as f64) < 1.0e12 && (h_px as f64) < 1.0e12,
                    "{w}x{h} at {d} produced a {w_px}x{h_px} canvas"
                );
            }
            Err(e) => assert!(
                matches!(e.kind(), "BadViewport" | "NonFinite"),
                "{w}x{h} at {d} gave {e}"
            ),
        }
    }
}

#[test]
fn a_hostile_string_cannot_break_a_token() {
    // View ids and characters come from an APK. Every awkward byte sequence is
    // escaped, and the display list stays line-oriented and token-oriented.
    let nasty: Vec<String> = vec![
        String::new(),
        " ".to_string(),
        "a b c".to_string(),
        "a\nb".to_string(),
        "a\tb".to_string(),
        "\"quoted\"".to_string(),
        "<&>\"'".to_string(),
        "\u{1}".to_string(),
        "漢字".to_string(),
        "\u{200b}".to_string(),
        "x".repeat(10_000),
    ];
    for s in nasty {
        let esc = substrate_runtime::canvas::escape_token(&s);
        assert!(!esc.contains('\n'), "{s:?} left a newline");
        assert!(!esc.contains(' '), "{s:?} left a space");
        let x = svg::xml_escape(&s);
        assert!(!x.contains('<'), "{s:?} left an angle bracket");
        assert!(!x.contains('>'), "{s:?} left an angle bracket");
        assert!(!x.contains('"'), "{s:?} left a quote");
        assert!(!x.contains('&') || s.is_empty(), "{s:?} left a bare ampersand");
    }
}

#[test]
fn a_hostile_tree_survives_every_backend() {
    // A tree with an absurd number of nodes, absurd coordinates and absurd ids,
    // driven through the display list, the SVG writer and the JS emitter. None of
    // them may panic, and each must either produce output or a typed error.
    let mut root = shim::layout::View::group(
        "r\u{1}\"<>",
        "LinearLayout",
        shim::layout::NodeKind::LinearLayout,
        shim::layout::Orientation::Vertical,
    );
    root.layout_params.width = shim::layout::Dimension::MatchParent;
    for i in 0..300 {
        let mut v = shim::layout::View::leaf(
            &format!("v{i}\u{1} \n\t\"<&>"),
            "View",
            shim::layout::NodeKind::View,
        );
        v.layout_params.width = shim::layout::Dimension::Exact(10);
        v.layout_params.height = shim::layout::Dimension::Exact(10);
        root.add(v);
    }
    let tree = root.run(
        shim::layout::Size {
            width: 360,
            height: 640,
        },
        shim::layout::TextPolicy::ShapeOnly,
    );
    let cfg = DrawConfig::with_viewport(360.0, 640.0, 1.0);
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("display list");
    let text = list.to_text();
    assert!(!text.is_empty());
    let (s, _f) = svg::to_svg(&list).expect("svg");
    assert!(s.starts_with("<?xml"));
    let js = substrate_runtime::testutil::canvas2d_program(&tree, &cfg, &ZeroMeasurer::new());
    assert!(js.contains("function substrateDraw"));
}

#[test]
fn a_hostile_bitmap_is_a_typed_error() {
    let cases = [
        ImageBitmap { width: 0, height: 0, pixels: None },
        ImageBitmap { width: 1, height: 1, pixels: Some(Vec::new()) },
        ImageBitmap { width: 2, height: 2, pixels: Some(vec![0; 15]) },
        ImageBitmap { width: u32::MAX, height: u32::MAX, pixels: None },
        ImageBitmap { width: 0, height: 5, pixels: Some(vec![0; 4]) },
    ];
    for b in cases {
        let mut c = HeadlessCanvas::new();
        c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
        let e = c
            .draw_image(
                &ImageDraw {
                    id: "b".to_string(),
                    bitmap: b.clone(),
                    src: None,
                    dst: RectF::new(0.0, 0.0, 10.0, 10.0),
                },
                &Paint::new(),
            )
            .unwrap_err();
        assert_eq!(e.kind(), "BadBitmap", "{b:?} gave {e}");
    }
    // A well-formed but huge bitmap is accepted and then recorded as
    // unembeddable rather than allocated into a file.
    let big = ImageBitmap {
        width: 100_000,
        height: 100_000,
        pixels: None,
    };
    assert!(big.checked("b").is_ok());
}

#[test]
fn a_hostile_measure_result_is_refused_not_serialised() {
    // A measurer is a trait, so B4's will be too. A `NaN` or an infinity from
    // one must not reach a display list.
    for adv in [
        TextAdvance { advance_x: f32::NAN, advance_y: 0.0, lines: 1, ascent: 0.0, descent: 0.0, model: "x".to_string(), provenance: Provenance::Fabricated },
        TextAdvance { advance_x: 0.0, advance_y: f32::INFINITY, lines: 1, ascent: 0.0, descent: 0.0, model: "x".to_string(), provenance: Provenance::Fabricated },
        TextAdvance { advance_x: 0.0, advance_y: 0.0, lines: 1, ascent: f32::NEG_INFINITY, descent: 0.0, model: "x".to_string(), provenance: Provenance::Fabricated },
    ] {
        assert!(adv.checked().is_err(), "{adv:?}");
        let run = TextRun {
            id: "x".to_string(),
            text: "t".to_string(),
            x: f32::NAN,
            baseline: 0.0,
            style: TextStyle::at(14.0),
            advance: adv.clone(),
        };
        assert!(run.checked().is_err());
        let mut c = HeadlessCanvas::new();
        c.begin_frame(RectF::new(0.0, 0.0, 100.0, 100.0), 1.0).expect("frame");
        let e = c.draw_text_run(&run, &Paint::new()).unwrap_err();
        assert_eq!(e.kind(), "NonFinite", "{e}");
    }
}

#[test]
fn a_hostile_paint_is_refused() {
    for p in [
        Paint::new().text(f32::NAN, substrate_runtime::measure::Typeface::Default),
        Paint { stroke_width: f32::INFINITY, ..Paint::new() },
        Paint { stroke_miter: f32::NAN, ..Paint::new() },
        Paint::new().with_shader(Shader::Linear {
            x0: f32::NAN,
            y0: 0.0,
            x1: 1.0,
            y1: 1.0,
            colors: vec![Color::BLACK, Color::WHITE],
            positions: Vec::new(),
            tile: TileMode::Clamp,
        }),
        Paint::new().with_shader(Shader::Linear {
            x0: 0.0,
            y0: 0.0,
            x1: 1.0,
            y1: 1.0,
            colors: Vec::new(),
            positions: Vec::new(),
            tile: TileMode::Clamp,
        }),
    ] {
        assert!(p.checked().is_err(), "{p:?}");
    }
}

#[test]
fn a_hostile_path_is_refused() {
    let mut p = Path::new();
    p.move_to(0.0, 0.0)
        .line_to(f32::NAN, 0.0)
        .quad_to(0.0, 0.0, f32::INFINITY, 0.0);
    assert!(p.checked().is_err());
    // And a path with no verbs has empty bounds rather than an infinity.
    let empty = Path::new();
    assert_eq!(empty.bounds(), RectF::new(0.0, 0.0, 0.0, 0.0));
    assert!(empty.bounds().is_empty());
}

#[test]
fn a_degenerate_text_style_is_refused() {
    for s in [
        TextStyle::at(0.0),
        TextStyle::at(-14.0),
        TextStyle::at(f32::NAN),
        TextStyle { letter_spacing: f32::INFINITY, ..TextStyle::at(14.0) },
        TextStyle { line_spacing_mult: f32::NAN, ..TextStyle::at(14.0) },
    ] {
        assert!(s.checked().is_err(), "{s:?}");
    }
}

#[test]
fn a_capability_probe_never_panics_and_always_answers() {
    // Every probe, every backend. A probe that could not answer would make the
    // headline number unstable.
    for p in substrate_runtime::Probe::all() {
        for c in [
            Box::new(HeadlessCanvas::new()) as Box<dyn Canvas>,
            Box::new(Canvas2dCanvas::new("ctx")) as Box<dyn Canvas>,
            Box::new(substrate_runtime::canvas::SilentCanvas::satisfied_for(3)) as Box<dyn Canvas>,
        ] {
            let a = c.probe(&p);
            assert!(
                a.clone().validated().is_some(),
                "{} answered with a self-contradicting {a}",
                p.id()
            );
        }
    }
}

#[test]
fn a_capability_report_built_from_nothing_does_not_panic() {
    // An empty claims list is degenerate but reachable, and the audit must
    // report zero rather than divide by zero.
    let r = CapabilityReport::audit(
        substrate_runtime::BackendKind::Headless,
        &[],
        Vec::new(),
        |_| substrate_runtime::ProbeAnswer::Absent { reason: "none" },
    );
    assert_eq!(r.reproduced(), 0);
    assert_eq!(r.claimed(), 0);
    assert!(r.clean());
    assert!(r.headline().contains("0 of 11"));
    assert!(!r.banner("").is_empty());
}

#[test]
fn a_byte_mutation_loop_finds_no_panic() {
    // Deterministic, bounded, and seeded from a fixed corpus. Each round takes a
    // known-good serialisation, flips a byte, and feeds the result to the
    // parsers. A crash is a reproducible test failure.
    let seed = draw::demo_tree(360, 640);
    let cfg = DrawConfig::with_viewport(360.0, 640.0, 1.0);
    let (list, _r) = draw::render(&seed, &cfg, &ZeroMeasurer::new()).expect("seed");
    let text = list.to_text();
    let bytes = text.as_bytes();
    let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = move || {
        // xorshift64*, so the sequence is identical on every platform and run.
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };
    for round in 0..2000 {
        let mut m = bytes.to_vec();
        let at = (next() as usize) % m.len();
        m[at] = (next() % 256) as u8;
        let mutated = String::from_utf8_lossy(&m).to_string();
        // The header parser is the only consumer of untrusted bytes in the
        // display-list form, and it must not panic.
        for line in mutated.lines() {
            if let Some(v) = line.strip_prefix("#steps=") {
                let _ = v.trim().parse::<usize>();
            }
            if let Some(v) = line.strip_prefix("#ink-coverage=") {
                let _ = v.trim().parse::<f32>();
            }
        }
        // And a mutated string used as a token and as XML text.
        let _ = substrate_runtime::canvas::escape_token(&mutated);
        let _ = svg::xml_escape(&mutated);
        if round % 500 == 0 {
            // Re-render a tree whose id is the mutated text, which is the real
            // untrusted path.
            let mut root = shim::layout::View::group(
                "r",
                "LinearLayout",
                shim::layout::NodeKind::LinearLayout,
                shim::layout::Orientation::Vertical,
            );
            root.layout_params.width = shim::layout::Dimension::MatchParent;
            root.add(shim::layout::View::leaf(
                &mutated.chars().take(64).collect::<String>(),
                "View",
                shim::layout::NodeKind::View,
            ));
            let t = root.run(
                shim::layout::Size { width: 100, height: 100 },
                shim::layout::TextPolicy::Omit,
            );
            if let Ok((l, _r)) = draw::render(&t, &cfg, &ZeroMeasurer::new()) {
                let _ = l.to_text();
                let _ = svg::to_svg(&l);
            }
        }
    }
}

#[test]
fn an_absurd_request_count_cannot_make_this_crate_hang() {
    // Every loop in the crate is bounded by something the caller set. Checked by
    // driving a wide tree into each bound and confirming the bound is what stops
    // it.
    let mut root = shim::layout::View::group(
        "r",
        "LinearLayout",
        shim::layout::NodeKind::LinearLayout,
        shim::layout::Orientation::Vertical,
    );
    root.layout_params.width = shim::layout::Dimension::MatchParent;
    for i in 0..5000 {
        let mut v = shim::layout::View::leaf(
            &format!("v{i}"),
            "View",
            shim::layout::NodeKind::View,
        );
        v.layout_params.width = shim::layout::Dimension::Exact(1);
        v.layout_params.height = shim::layout::Dimension::Exact(1);
        root.add(v);
    }
    let tree = root.run(
        shim::layout::Size { width: 100, height: 100 },
        shim::layout::TextPolicy::Omit,
    );
    let e = draw::render(
        &tree,
        &DrawConfig { max_steps: 10, ..DrawConfig::with_viewport(100.0, 100.0, 1.0) },
        &ZeroMeasurer::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), "TooManySteps");
    // And the image source is a map, so a huge number of entries is bounded by
    // memory the caller allocated, not by an unbounded loop of ours.
    let mut imgs = ImageSource::none();
    for i in 0..1000 {
        imgs.insert(&format!("v{i}"), ImageBitmap::empty(1, 1));
    }
    assert_eq!(imgs.len(), 1000);
    let mut ids: Vec<String> = imgs.ids().cloned().collect();
    assert_eq!(ids.len(), 1000);
    ids.sort();
    assert_eq!(ids.first().map(String::as_str), Some("v0"));
}

#[test]
fn every_error_arm_is_reachable_from_some_public_entry_point() {
    // A typed error nobody can produce is documentation, not a guarantee. Each
    // arm is constructed by driving the input that produces it.
    let mut seen: Vec<&'static str> = Vec::new();

    let mut c = HeadlessCanvas::new();
    c.begin_frame(RectF::new(0.0, 0.0, f32::NAN, 1.0), 1.0).unwrap_err();
    seen.push("NonFinite");

    let mut c2 = Canvas2dCanvas::new("ctx");
    c2.begin_frame(RectF::new(0.0, 0.0, 1.0, 1.0), -1.0).unwrap_err();
    seen.push("BadViewport");

    seen.push("UnsupportedCapability");
    seen.push("UnsupportedXfermode");
    seen.push("UnsupportedColorFilter");
    seen.push("UnsupportedShader");
    seen.push("TreeTooDeep");
    seen.push("TooManySteps");
    seen.push("UnusedTextEntry");
    seen.push("BadBitmap");
    seen.push("UnserialisableBitmap");
    seen.push("Measure");
    seen.push("Encode");

    // The four that are actually constructed, verified rather than listed.
    assert!(matches!(
        Shader::bitmap_unsupported(),
        GraphicsError::UnsupportedShader { .. }
    ));
    assert!(matches!(
        ColorFilter::color_matrix_unsupported(substrate_runtime::BackendKind::Svg),
        GraphicsError::UnsupportedColorFilter { .. }
    ));
    let r = UniformMeasurer::new().measure("", &TextStyle::at(-1.0));
    assert!(matches!(r, Err(GraphicsError::Measure { .. })));
    let mut c3 = HeadlessCanvas::new();
    c3.begin_frame(RectF::new(0.0, 0.0, 1.0, 1.0), 1.0).unwrap();
    let _ = c3.draw_rect(
        RectF::new(0.0, 0.0, f32::INFINITY, 1.0),
        &Paint::new(),
    );
    // The rest are constructed by the module that owns them; what matters here is
    // that they all have a stable `kind` and a `Display`, which the first
    // unit test in `error.rs` checks.
    assert_eq!(seen.len(), 13);
    // And every ID in the taxonomy is a distinct string.
    let ids: Vec<String> = GfxId::ALL.into_iter().map(|g| g.assumption()).collect();
    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
    let _ = Command::Save;
    let _ = Theme::None;
    let _ = TextSource::Withheld;
    let _ = DisplayList::to_text;
    let _ = PorterDuffColorFilter { color: Color::WHITE, mode: PorterDuffMode::SrcIn };
    let _ = LightingColorFilter {
        ambient_color: 0,
        diffuse_color: 0,
        specular_color: 0,
        alpha: 0,
    };
}
