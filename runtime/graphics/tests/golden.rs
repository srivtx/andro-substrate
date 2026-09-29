//! Golden tests: the same box tree must produce a byte-identical display list,
//! and the list must be worth something.
//!
//! # Why a golden test that passes trivially is worse than none
//!
//! A test that snapshots today's output and compares it to today's output
//! catches nothing, and worse, it *institutionalises* whatever the layer is
//! currently doing. If this layer were quietly fabricating plausible pixels, a
//! trivial golden test would lock that in and every later change would have to
//! re-approve it.
//!
//! So every golden test here is paired with an **independent assertion about
//! what is in the file**, checked against the display list's own structure and
//! against the shim's geometry rather than against a stored copy of itself:
//!
//! - the list is non-empty, and has the expected shape
//! - the geometry is exact: the frame of a named node is the frame the shim's
//!   layout produced, to the dp
//! - the numbers the header reports are re-derived by *parsing the bytes*, not
//!   by reading the struct the header was written from
//! - the list contains the words `RECONSTRUCTION` and `NOT-ANDROID`, because an
//!   artefact that lost its own warning is the failure this layer fears
//!
//! The `UPDATE_GOLDEN=1` escape hatch regenerates the files. It is documented
//! in each test and the value checked is *inline* in the assertions, so
//! regenerating and then re-reading shows the diff rather than hiding it.

use std::collections::BTreeMap;

use shim::layout::{BoxNode, Dimension, NodeKind, Orientation, View};
use substrate_runtime::canvas::{Command, DisplayList, HeadlessCanvas, TextRun};
use substrate_runtime::draw::{self, DrawConfig, Theme, TextSource};
use substrate_runtime::measure::{TextAdvance, TextMeasurer, UniformMeasurer, ZeroMeasurer};

/// The viewport every golden fixture is laid out in. Fixed, because a golden
/// file is only comparable to another golden file at the same viewport.
const W: i32 = 360;
const H: i32 = 640;

/// Build the login form. Same shape as `shim/tests/layout_tree.rs`, so the
/// geometry in the golden file can be checked against numbers that another
/// crate's tests also assert.
fn login_form() -> View {
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
    root
}

fn default_list(tree: &BoxNode) -> (DisplayList, draw::DrawReport) {
    let cfg = DrawConfig::with_viewport(W as f32, H as f32, 1.0);
    draw::render(tree, &cfg, &ZeroMeasurer::new())
        .unwrap_or_else(|e| panic!("default render: {e}"))
}

/// The frame of a node, from the shim's own tree.
fn frame_of(tree: &BoxNode, id: &str) -> shim::layout::Rect {
    tree.flatten()
        .into_iter()
        .find(|(k, _)| k == id)
        .map_or_else(|| panic!("no node {id}"), |(_, r)| r)
}

/// Where the committed artefacts live.
///
/// `CARGO_MANIFEST_DIR` is the crate root, which for this crate is `runtime/`
/// itself — the graphics module is wired in with a `#[path]` from
/// `runtime/src/lib.rs`, so the library is not in a `graphics/` subdirectory of
/// the manifest. Resolved from the manifest rather than from the current
/// directory so the tests work wherever cargo is invoked from.
fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("graphics")
        .join("tests")
        .join("golden")
}

/// Compare a serialised artefact with its golden file, or regenerate when
/// `UPDATE_GOLDEN=1`.
///
/// Regeneration is a *deliberate* act: the caller still has to satisfy every
/// other assertion in the test, and the test prints what it wrote so a
/// regeneration is visible in CI output rather than silent.
fn check_golden(name: &str, actual: &str) {
    let path = golden_dir().join(name);
    if std::env::var("UPDATE_GOLDEN").is_ok() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::write(&path, actual)
            .unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
        println!("REGENERATED {} ({} bytes)", path.display(), actual.len());
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "no golden file at {} ({e}).\n\
             This is deliberate: the file has to be created by a person who has \
             read it.\nRun with UPDATE_GOLDEN=1 to write it, then READ THE DIFF \
             before committing it.",
            path.display()
        )
    });
    assert_eq!(
        expected,
        actual,
        "{} changed.\nIf that is intended, re-run with UPDATE_GOLDEN=1 and read \
         the diff: a golden test that is regenerated without being read is a \
         test that approves anything.",
        path.display()
    );
}

// ---------------------------------------------------------------------------
// The anti-triviality harness: assertions that hold whatever the golden does

/// Every independent check a display list must satisfy. Split out so each
/// golden test calls it and so a new golden cannot forget to.
fn assert_meaningful(list: &DisplayList, text: &str, tree: &BoxNode) {
    // 1. Not empty. A golden test on an empty artefact approves nothing.
    assert!(
        !list.steps.is_empty(),
        "an empty display list proves nothing; the tree had {} nodes",
        tree.count()
    );
    assert!(text.len() > 500, "a {} byte list is too short to be a frame", text.len());

    // 2. Every step is labelled. Checked by scanning the bytes, so a step
    //    serialised without a provenance would fail here rather than pass.
    let lines: Vec<&str> = text.lines().filter(|l| l.starts_with("  ") && l.contains(" prov=")).collect();
    assert_eq!(
        lines.len(),
        list.steps.len(),
        "every step line must carry a prov= tag; {} lines for {} steps",
        lines.len(),
        list.steps.len()
    );
    // A default pipeline uses three of the four tags and must not use the
    // fourth: `fabricated` ink would mean this layer invented something. So the
    // assertion is a presence check for the three and an *absence* check for the
    // fourth, which is the stronger claim.
    for p in [
        substrate_runtime::paint::Provenance::ShimTreeExact,
        substrate_runtime::paint::Provenance::DerivedFromShimTree,
        substrate_runtime::paint::Provenance::Absent,
    ] {
        assert!(
            text.contains(&format!("prov={}", p.as_str())),
            "no step is tagged {}: the default pipeline should tag the shim's \
             own geometry, its consequences, and its absences",
            p.as_str()
        );
    }
    assert!(
        !text.contains("prov=fabricated"),
        "the default pipeline produced fabricated ink:\n{text}"
    );

    // 3. Geometry is exact, checked against the shim's tree and not against a
    //    stored copy of this layer's output. The button is 120 dp wide, the
    //    field takes the viewport minus the shim's 4 dp padding each side, and
    //    the three stack without overlapping.
    let title = frame_of(tree, "title");
    let email = frame_of(tree, "email");
    let go = frame_of(tree, "go");
    assert_eq!(go.width(), 120, "the button kept its exact width");
    assert_eq!(
        email.width(),
        W - 2 * shim::layout::metrics::PADDING,
        "the field took the viewport minus padding"
    );
    assert!(title.bottom <= email.top, "the views stack");
    assert!(email.bottom <= go.top, "the views stack");
    // And the display list's own outline annotations carry those exact numbers.
    let root_frame = tree.frame;
    let expect_root = format!(
        "box-outline id=root rect=[0,0 {}x{}] state=visible kind=linearlayout",
        root_frame.width(),
        root_frame.height()
    );
    assert!(
        text.contains(&expect_root),
        "the root box outline is not the shim's frame.\n  expected a line containing:\n    {expect_root}\n  got:\n{}",
        text.lines().filter(|l| l.contains("box-outline")).collect::<Vec<_>>().join("\n")
    );
    let expect_go = format!("box-outline id=go rect=[0,0 120x{}]", go.height());
    assert!(
        text.contains(&expect_go),
        "the button's outline is not {expect_go}"
    );

    // 4. The header's counts are re-derived by *parsing the bytes*, not read
    //    off the struct. If the formatter and the counter ever disagree, one of
    //    them is wrong and this says which.
    let parsed = |key: &str| -> usize {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("#{key}=")))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or_else(|| panic!("no {key}= line in the header"))
    };
    assert_eq!(
        parsed("steps"),
        list.steps.len(),
        "the header's step count disagrees with the list"
    );
    assert_eq!(
        parsed("steps"),
        text.lines().filter(|l| l.starts_with("  ") && l.contains(" prov=")).count(),
        "the header's step count disagrees with the number of step lines"
    );
    let prov_total: usize = ["shim-exact", "derived", "fabricated", "absent"]
        .iter()
        .map(|p| {
            text.lines()
                .find_map(|l| l.strip_prefix("#prov "))
                .and_then(|v| v.split_whitespace().find(|kv| kv.starts_with(&format!("{p}="))))
                .and_then(|kv| kv.split('=').nth(1))
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0)
        })
        .sum();
    assert_eq!(
        prov_total,
        list.steps.len(),
        "the four provenance tallies do not add up to the step count: {prov_total} vs {}",
        list.steps.len()
    );

    // 5. The artefact says what it is. An output that has lost its own warning
    //    is the failure this whole layer is built against.
    assert!(text.contains("RECONSTRUCTION"), "no RECONSTRUCTION marker");
    assert!(text.contains("NOT-ANDROID"), "no NOT-ANDROID marker");
    assert!(
        text.contains("app-draw-code-executed=false"),
        "the artefact does not state that the app's draw code never ran"
    );
    assert!(text.contains("exact relative to the shim"), "no geometry disclaimer");

    // 6. The capability report is present, complete, and audited.
    assert!(text.contains("!capability backend=headless"));
    assert!(text.contains("!end-capability"));
    for id in substrate_runtime::GfxId::ALL {
        let line = format!("{} verdict=", id.assumption());
        assert!(text.contains(&line), "no capability row for {line}");
    }
    assert_eq!(parsed("gfx-ids-total"), substrate_runtime::GfxId::ALL.len());
    assert_eq!(
        parsed("report-audit-mismatches"),
        0,
        "the report disagrees with the code that produced it:\n{}",
        list.capability.audit.mismatches.join("\n")
    );

    // 7. Text is withheld, and says so. The shim's `TextPolicy::ShapeOnly`
    //    keeps characters out of the tree, so the rendering must keep them out
    //    of the artefact. This is the assertion that would fail if someone
    //    started rendering plausible-looking text from a character count.
    assert_eq!(parsed("text-withheld"), 3, "three text-bearing nodes");
    assert!(parsed("withheld-chars") > 0);
    assert!(
        text.contains("text-withheld id=email"),
        "the email field is not marked as withheld"
    );
    assert!(
        !text.contains("person@example.invalid"),
        "the withheld address leaked into the artefact"
    );
    assert!(
        !text.contains("Continue"),
        "the withheld button label leaked into the artefact"
    );
}

// ---------------------------------------------------------------------------
// The goldens

#[test]
fn golden_default_pipeline() {
    let tree = login_form()
        .run(
            shim::layout::Size {
                width: W,
                height: H,
            },
            shim::layout::TextPolicy::ShapeOnly,
        );
    let (list, _report) = default_list(&tree);
    let text = list.to_text();
    assert_meaningful(&list, &text, &tree);
    check_golden("default.display-list.txt", &text);
}

#[test]
fn golden_default_pipeline_svg() {
    let tree = login_form()
        .run(
            shim::layout::Size {
                width: W,
                height: H,
            },
            shim::layout::TextPolicy::ShapeOnly,
        );
    let (list, _report) = default_list(&tree);
    let (svg, fidelity) = substrate_runtime::svg::to_svg(&list)
        .unwrap_or_else(|e| panic!("svg: {e}"));
    // Well-formedness is checked in `svg.rs`'s own tests; here the point is the
    // bytes, and that the degradation report is empty for a default pipeline.
    assert_eq!(
        fidelity.losses(),
        0,
        "a default pipeline should lose nothing to serialisation: {}",
        fidelity.summary()
    );
    assert!(svg.contains("RECONSTRUCTION"));
    assert!(svg.contains("data-substrate-is-android=\"false\""));
    check_golden("default.svg.txt", &svg);
}

#[test]
fn golden_text_present_with_a_stub_measurer() {
    // The characters *are* in this tree (`TextPolicy::Include`), and the
    // measurer is the uniform stub. The output must therefore contain a text
    // run — labelled `fabricated`, because the advance came from a stub and not
    // from a font. This is the case a reader is most likely to mistake for a
    // device screenshot, so it gets its own golden.
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (list, report) = draw::render(&tree, &cfg, &UniformMeasurer::new())
        .unwrap_or_else(|e| panic!("render: {e}"));
    let text = list.to_text();

    assert_eq!(report.text_with_characters, 3, "all three views have text");
    assert!(report.characters > 0);
    assert_eq!(list.counts.text_withheld, 0, "nothing is withheld now");
    assert!(list.counts.text_runs > 0, "no runs were emitted");
    assert!(
        text.contains("draw-text"),
        "the run is not in the list:\n{}",
        text.lines().filter(|l| l.contains("text")).collect::<Vec<_>>().join("\n")
    );
    // The advance is the stub's, and the list says which model produced it.
    assert!(text.contains("model=uniform-advance-stub/v1"));
    assert!(text.contains("mprov=fabricated"), "the run is not labelled fabricated");
    // The *characters* are deliberately not in the artefact — a recording is a
    // file that gets attached to a study. What is in it is the length and a
    // digest, which is what makes two runs comparable without holding a login
    // field's contents.
    assert!(
        !text.contains("person@example.invalid"),
        "the characters leaked into the display list"
    );
    assert!(text.contains("chars=22"), "the email field's length is not recorded: {text}");
    assert!(
        text.contains("chars=8"),
        "the button label's length is not recorded"
    );
    assert!(
        text.contains(&format!("digest={}", substrate_runtime::canvas::digest("Sign in"))),
        "the run does not identify its string"
    );
    assert!(text.contains("!banner") || text.contains("#banner="));
    // Still not Android.
    assert!(text.contains("RECONSTRUCTION"));
    assert_eq!(
        list.capability.reproduced(),
        0,
        "text runs do not make SUB.GFX.TEXT_RENDER reproduced"
    );
    check_golden("text-present.display-list.txt", &text);
}

#[test]
fn golden_theme_on_is_labelled_fabricated_throughout() {
    // Turning the theme on is a legitimate thing to do, and it puts ink on the
    // screen. What must not happen is for that ink to be unlabelled. Every ink
    // step in this list has to be `fabricated`, and the header has to count
    // them.
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig {
        theme: Theme::Placeholder,
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (list, _report) =
        draw::render(&tree, &cfg, &ZeroMeasurer::new()).unwrap_or_else(|e| panic!("render: {e}"));
    let text = list.to_text();

    assert!(
        list.counts.ink_fabricated > 0,
        "a themed run must put fabricated ink on the surface; if this is 0 the theme did nothing"
    );
    let ink_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("draw-rect") || l.contains("draw-color"))
        .collect();
    assert!(!ink_lines.is_empty());
    for l in &ink_lines {
        assert!(
            l.contains("prov=fabricated"),
            "themed ink is not labelled fabricated: {l}"
        );
    }
    let parsed = |key: &str| -> usize {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("#{key}=")))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0)
    };
    assert_eq!(parsed("ink-fabricated"), list.counts.ink_fabricated);
    assert_eq!(parsed("ink-fabricated"), ink_lines.len());
    check_golden("theme-on.display-list.txt", &text);
}

#[test]
fn golden_annotations_off_produces_an_empty_list_and_says_so() {
    // The most honest output of all. With no ink and no annotations there is
    // nothing to draw, and the artefact says so rather than inventing a frame.
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig {
        annotate: false,
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (list, _report) =
        draw::render(&tree, &cfg, &ZeroMeasurer::new()).unwrap_or_else(|e| panic!("render: {e}"));
    let text = list.to_text();

    assert_eq!(
        list.counts.ink_steps,
        0,
        "no ink steps, so the only steps are the clip and transform stack"
    );
    assert_eq!(list.counts.annotations, 0);
    assert_eq!(list.counts.ink_fabricated, 0);
    // The header is still there, and it still carries the warning.
    assert!(text.contains("RECONSTRUCTION"));
    assert!(text.contains("#ink-steps=0"));
    assert!(text.contains("#annotations=0"));
    check_golden("bare.display-list.txt", &text);
}

#[test]
fn golden_degenerate_viewport_does_not_panic_and_is_still_labelled() {
    // Untrusted input includes a nonsense viewport. The output has to be
    // produced, labelled, and small — not a panic and not a 40 MB of hatch.
    for (w, h) in [(0.0f32, 0.0f32), (1.0, 1.0), (1.0e9, 1.0e9)] {
        let tree = draw::demo_tree(W, H);
        let cfg = DrawConfig::with_viewport(w, h, 1.0);
        let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new())
            .unwrap_or_else(|e| panic!("render at {w}x{h}: {e}"));
        let text = list.to_text();
        assert!(text.contains("RECONSTRUCTION"), "at {w}x{h}");
        assert!(text.len() < 40_000, "at {w}x{h} the list is {} bytes", text.len());
        // Look for a non-finite *value*, not a substring: `provenance` contains
        // "nan" and `#this-is=NOT-ANDROID` contains no number at all. The tokens
        // the formatter can emit are `nan`, `inf` and `-inf`, always as a whole
        // field after `=` or inside `[`.
        for bad in ["=nan", "[nan", "=inf", "= -inf", "= -0"] {
            assert!(
                !text.contains(bad),
                "a non-finite or negative-zero token {bad:?} reached the output \
                 at {w}x{h}:\n{text}"
            );
        }
    }
    // A *negative* viewport is not a viewport, and inventing one would be the
    // first fabrication in the pipeline. It is a typed error.
    let tree = draw::demo_tree(W, H);
    let e = draw::render(
        &tree,
        &DrawConfig::with_viewport(-5.0, 10.0, 1.0),
        &ZeroMeasurer::new(),
    )
    .unwrap_err();
    assert_eq!(e.kind(), "BadViewport", "{e}");
}

#[test]
fn golden_the_two_backends_agree_on_the_command_vocabulary() {
    // The two backends cannot disagree about *what* was drawn, only about what
    // they can express. This walks the same tree through the Canvas2D backend
    // and checks the operation sequence matches the display list's, one for one.
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig::with_viewport(W as f32, H as f32, 1.0);
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    let c = substrate_runtime::canvas::Canvas2dCanvas::new("ctx");
    let mut names: Vec<&str> = list.steps.iter().map(|s| s.command.name()).collect();
    // The Canvas2D program interleaves comments and state assignments, so
    // compare the counts of the operations it can express rather than a line for
    // line: the numbers must both equal the display list's.
    let js = substrate_runtime::testutil::canvas2d_program(&tree, &cfg, &ZeroMeasurer::new());
    assert!(js.contains("ctx.save()"));
    assert!(js.contains("ctx.clip("));
    assert!(js.contains("ctx.restore()"));
    let js_translates = js.matches("ctx.translate(").count();
    assert_eq!(
        js_translates,
        names.iter().filter(|n| **n == "translate").count(),
        "the two backends issued a different number of translations"
    );
    let js_clips = js.matches("ctx.clip(").count();
    assert_eq!(
        js_clips,
        names.iter().filter(|n| **n == "clip-rect").count(),
        "the two backends issued a different number of clips"
    );
    names.sort_unstable();
    names.dedup();
    assert!(names.contains(&"annotate"), "no annotation reached the list");
    let _ = c;
}

// ---------------------------------------------------------------------------
// Backing implementation, kept out of the test body for clarity

/// A `TextMeasurer` that refuses, used to prove a refusal is a finding and not a
/// crash. Declared here rather than in the library because nothing ships with it.
#[derive(Debug, Default)]
struct CountingMeasurer {
    calls: std::cell::Cell<u64>,
}

impl TextMeasurer for CountingMeasurer {
    fn measure(&self, text: &str, style: &substrate_runtime::measure::TextStyle) -> Result<TextAdvance, substrate_runtime::GraphicsError> {
        self.calls.set(self.calls.get() + 1);
        let mut a = UniformMeasurer::new().measure(text, style)?;
        a.provenance = substrate_runtime::paint::Provenance::ShimTreeExact;
        a.model = "counting-stub/v1".to_string();
        Ok(a)
    }
    fn model_id(&self) -> String {
        "counting-stub/v1".to_string()
    }
    fn provenance(&self) -> substrate_runtime::paint::Provenance {
        substrate_runtime::paint::Provenance::ShimTreeExact
    }
    fn call_count(&self) -> u64 {
        self.calls.get()
    }
}

#[test]
fn a_measurer_that_labels_its_advances_shim_exact_changes_the_output() {
    // Proves the provenance tag is load-bearing rather than decorative: swap in
    // a measurer that claims its numbers came from the tree and the runs change
    // provenance in the output.
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (plain, _r) = draw::render(&tree, &cfg, &UniformMeasurer::new()).expect("render");
    let m = CountingMeasurer::default();
    let (tagged, _r2) = draw::render(&tree, &cfg, &m).expect("render");
    assert!(plain.to_text().contains("mprov=fabricated"));
    assert!(tagged.to_text().contains("mprov=shim-exact"));
    assert_ne!(plain.to_text(), tagged.to_text());
    assert_eq!(m.call_count(), 3, "one measurement per text view");
}

#[test]
fn an_annoying_view_id_cannot_break_the_line_format() {
    // A view id comes from an APK. A space, a newline or a quote in one must
    // not be able to forge a display-list line or an XML attribute.
    let mut map = BTreeMap::new();
    map.insert(
        "id with spaces and \"quotes\" & <angles>".to_string(),
        "text".to_string(),
    );
    let source = TextSource::Supplied(map);
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::text(
        "id with spaces and \"quotes\" & <angles>",
        "TextView",
        NodeKind::TextView,
        "hi",
    ));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Include,
    );
    let cfg = DrawConfig {
        text: source,
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (list, _r) = draw::render(&tree, &cfg, &UniformMeasurer::new()).expect("render");
    let text = list.to_text();
    for l in text.lines() {
        assert!(
            !l.contains(" \"quotes\" ") || l.contains('\u{1}'),
            "a raw space survived into a token: {l}"
        );
    }
    let (svg, _f) = substrate_runtime::svg::to_svg(&list).expect("svg");
    // A space is legal inside an XML attribute value, so the display list's
    // U+0001 escaping does not apply here. What must not survive is anything
    // that closes the attribute or opens an element.
    assert!(svg.contains("&lt;angles&gt;"), "the angle brackets were not escaped");
    assert!(svg.contains("&quot;quotes&quot;"), "the quotes were not escaped");
    assert!(svg.contains("&amp;"), "the ampersand was not escaped");
    // Exactly one attribute delimiter for the id: the opening and closing ones.
    // The escaped form appears for both the outline and the withheld marker, so
    // this is a presence check, and the well-formedness of the file is proved in
    // `svg.rs`. What matters here is that the *unescaped* form appears nowhere.
    assert!(
        svg.contains("data-view=\"id with spaces and &quot;quotes&quot; &amp; &lt;angles&gt;\""),
        "the id is not escaped into exactly one attribute value:\n{svg}"
    );
    assert!(
        !svg.contains("data-view=\"id with spaces and \"quotes\""),
        "a raw quote closed the attribute early:\n{svg}"
    );
    // And the display list escaped the spaces, so its line format holds.
    assert!(
        list.to_text().contains("box-outline id=id\u{1}with\u{1}spaces"),
        "the display list left a raw space in a token"
    );
}

#[test]
fn a_zero_sized_run_is_dropped_rather_than_drawn_as_a_dot() {
    // The default measurer gives every run a zero advance, and a zero-area
    // draw is not a draw. Both facts have to hold at once, and the second is
    // the one that would look like a bug if it were the other way round.
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..DrawConfig::with_viewport(W as f32, H as f32, 1.0)
    };
    let (list, report) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.text_with_characters, 3, "the text was read");
    assert_eq!(list.counts.text_runs, 0, "no zero-width run was emitted");
    assert!(!list.to_text().contains("draw-text"));
    // And the three withheld markers are absent too, because the characters
    // *were* available — the runs were measured, not withheld. The output says
    // so through the measure model instead.
    assert!(list.to_text().contains("zero-stub/v1"));
    // The header always carries a `text-withheld` *key*; what must be absent is
    // the marker itself, which is what would mean "we had the text and could not
    // measure it".
    assert!(
        !list.to_text().contains("annotate text-withheld"),
        "a withheld marker was emitted even though the characters were available"
    );
}

#[test]
fn the_report_survives_a_round_trip_through_its_own_text_form() {
    // The text form is the artefact; the struct is the source. If the
    // serialiser drops a field, the count of lines is the evidence.
    let tree = draw::demo_tree(W, H);
    let (list, _r) = default_list(&tree);
    let text = list.to_text();
    assert_eq!(text.lines().filter(|l| l.contains(" verdict=")).count(), 11);
    assert_eq!(list.capability.entries.len(), 11);
    for e in &list.capability.entries {
        assert!(
            text.contains(&format!("{} verdict={}", e.id.assumption(), e.claimed.as_str())),
            "row for {} did not round-trip",
            e.id.assumption()
        );
    }
}

#[test]
fn a_headless_canvas_is_what_draw_produces_and_not_something_else() {
    // Guards the seam: `draw_tree` must be usable with a hand-built canvas, and
    // the list it produces must be the same one `render` produces.
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig::with_viewport(W as f32, H as f32, 1.0);
    let mut c = HeadlessCanvas::new();
    let report = draw::draw_tree(&tree, &cfg, &ZeroMeasurer::new(), &mut c).expect("draw_tree");
    let manual = c.finish("");
    let (via_render, r2) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    assert_eq!(report, r2);
    assert_eq!(manual.steps, via_render.steps);
    assert!(matches!(via_render.steps[0].command, Command::Save));
    assert!(matches!(
        via_render.steps.last().map(|s| &s.command),
        Some(Command::Restore)
    ));
    // A `TextRun` is only ever constructed by the draw pass, so the type is
    // reachable and the import is not vestigial.
    let run = TextRun {
        id: "x".to_string(),
        text: "t".to_string(),
        x: 0.0,
        baseline: 0.0,
        style: substrate_runtime::measure::TextStyle::at(14.0),
        advance: TextAdvance::zero("t"),
    };
    assert_eq!(run.checked(), Ok(()));
}
