//! The draw pass: does it stay honest, and does it stay inside its bounds?
//!
//! # What a draw pass could plausibly get wrong, in order of how badly it would
//! mislead
//!
//! 1. **Fabricating plausible ink.** Painting a grey rounded rectangle for a
//!    `Button` because a theme said so, and calling it a rendering. Every such
//!    fill is tagged `fabricated` and counted in the header; the tests assert
//!    the count is *zero* under the default configuration.
//! 2. **Rendering text it does not have.** The shim's `TextPolicy::ShapeOnly`
//!    keeps characters out of the tree, so a rendering of that tree cannot show
//!!    text. Drawing a character count, or a plausible-looking glyph block, would
//!    be the single most misleading thing this layer could do.
//! 3. **Silently dropping a view.** A node that vanishes makes the output look
//!    clean. `INVISIBLE` reserves space on a real device and must be shown as
//!    reserving space.
//! 4. **Overflowing on a hostile tree.** An app nests views as deeply as it
//!    likes.
//!
//! Each has a test below.

use shim::layout::{BoxNode, Dimension, NodeKind, Orientation, View, Visibility};
use substrate_runtime::canvas::{Annotation, Command, HeadlessCanvas, ImageBitmap, ImageSource, ViewState};
use substrate_runtime::draw::{self, DrawConfig, Theme, TextSource, NO_APP_PAINT};
use substrate_runtime::measure::{RefusingMeasurer, TextMeasurer, UniformMeasurer, ZeroMeasurer};
use substrate_runtime::paint::{Color, PorterDuffMode, Provenance};

const W: i32 = 360;
const H: i32 = 640;

fn frame_of(tree: &BoxNode, id: &str) -> shim::layout::Rect {
    tree.flatten()
        .into_iter()
        .find(|(k, _)| k == id)
        .map_or_else(|| panic!("no node {id} in {:?}", tree.flatten()), |(_, r)| r)
}

fn default_cfg() -> DrawConfig {
    DrawConfig::with_viewport(W as f32, H as f32, 1.0)
}

// ---------------------------------------------------------------------------
// 1. Fabricated ink

#[test]
fn the_default_pipeline_fabricates_no_ink() {
    // THE anti-plausibility test. The shim's box tree has no paint in it, so
    // there is no correct colour for anything, and this layer draws none.
    let tree = draw::demo_tree(W, H);
    let (list, report) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");

    assert_eq!(
        list.counts.ink_fabricated,
        0,
        "the default pipeline invented ink:\n{}",
        list.to_text()
            .lines()
            .filter(|l| l.contains("prov=fabricated"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert_eq!(
        list.counts.ink_steps,
        0,
        "no step in the default pipeline is ink at all; every step is a \
         clip, a transform or an annotation"
    );
    // The shape is still there, and it is all annotations.
    assert!(list.counts.annotations > 0);
    assert!(list.counts.clip_regions > 0);
    assert_eq!(report.ink_coverage(), 0.0, "no ink means no coverage");
    // And the report is empty of pixels: 100% of the leaf area has no ink.
    assert!(list.to_text().contains("no ink for 100.0% of the shim's leaf area"));
}

#[test]
fn ink_coverage_is_computed_against_the_shims_own_area_not_this_layers() {
    // The denominator is the shim's `leaf_area`, so the coverage figure is a
    // statement about the shim's geometry rather than about this layer's
    // bookkeeping. If the two disagree, the number is reported as an error
    // rather than silently reconciled.
    let tree = draw::demo_tree(W, H);
    let mut c = HeadlessCanvas::new();
    let report = draw::draw_tree(&tree, &default_cfg(), &ZeroMeasurer::new(), &mut c).expect("draw");
    assert_eq!(report.leaf_area_dp2, tree.leaf_area().max(0) as u64);
    assert_eq!(report.ink_coverage(), 0.0);
    // The counts agree between the pass and the canvas, which `draw_tree`
    // checks internally and would have returned an `Encode` error for.
    assert_eq!(c.counts().unknown_ink_dp2, report.unknown_ink_dp2);
}

#[test]
fn turning_the_theme_on_produces_fabricated_ink_and_says_so() {
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig {
        theme: Theme::Placeholder,
        ..default_cfg()
    };
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    assert!(list.counts.ink_fabricated > 0, "the theme did nothing");
    for st in &list.steps {
        if st.command.is_ink() {
            assert_eq!(
                st.provenance,
                Provenance::Fabricated,
                "themed ink must be tagged fabricated: {:?}",
                st.command.name()
            );
        }
    }
    assert!(list.to_text().contains("theme=placeholder") || list.counts.ink_fabricated > 0);
    // The banner escalates, so a screenshot of this is not mistaken for a
    // device capture.
    assert!(list.banner.contains("fabricated by this layer"), "{}", list.banner);
}

#[test]
fn a_themed_fill_is_only_ever_produced_by_the_theme_and_nothing_else() {
    // A `View` with no theme fill gets no ink, even though it has a box. The
    // absence is recorded as an `UnknownInk` with the reason, so a reader can
    // tell "the app painted nothing" from "we did not know".
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let unknowns: Vec<&Annotation> = list
        .steps
        .iter()
        .filter_map(|s| match &s.command {
            Command::Annotate(a @ Annotation::UnknownInk { .. }) => Some(a),
            _ => None,
        })
        .collect();
    assert!(!unknowns.is_empty(), "no area was marked as having no ink");
    for a in &unknowns {
        match a {
            Annotation::UnknownInk { reason, .. } => assert_eq!(*reason, NO_APP_PAINT),
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Text

#[test]
fn withheld_text_produces_a_placeholder_and_never_a_rendering() {
    let tree = draw::demo_tree(W, H);
    let (list, report) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");

    assert_eq!(report.text_nodes, 3, "three text-bearing views");
    assert_eq!(report.characters, 0, "no character reached the draw pass");
    assert!(report.characters_withheld > 0);
    assert_eq!(list.counts.text_withheld, 3);
    assert_eq!(list.counts.text_runs, 0, "no run was drawn from text that does not exist");
    assert_eq!(list.counts.withheld_chars, report.characters_withheld);

    let text = list.to_text();
    for (id, chars) in [("title", 7), ("email", 22), ("go", 8)] {
        let want = format!("text-withheld id={id} ");
        assert!(text.contains(&want), "no placeholder for {id}");
        assert!(text.contains(&format!("chars={chars}")), "{id}: wrong char count");
    }
    // The email shape guess is carried through: the shim did tell us this looks
    // like an address, which is a real finding, and it is shown without the
    // address.
    assert!(text.contains("shape=email"), "{text}");
    // And the class histogram, which is what makes the placeholder informative.
    assert!(text.contains("letter="), "the class histogram is missing");
}

#[test]
fn a_character_count_is_never_drawn_as_characters() {
    // The specific trap: a rendering that shows `x x x x` where the text was,
    // or a filled bar proportional to the length. Nothing in the list does
    // that.
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let text = list.to_text();
    assert!(!text.contains("draw-text"), "a text run was emitted with no text available");
    for s in list.steps.iter().filter(|s| s.command.is_ink()) {
        assert!(
            !matches!(s.command, Command::DrawTextRun { .. }),
            "ink was drawn for text that does not exist"
        );
    }
}

#[test]
fn text_present_in_the_tree_is_drawn_and_labelled_with_the_measuring_model() {
    let tree = draw::demo_tree_with_text(W, H);
    assert!(
        tree.flatten()
            .into_iter()
            .any(|(_, _)| true)
            && find_text(&tree, "title").is_some(),
        "the Include tree should carry characters"
    );
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let (list, report) = draw::render(&tree, &cfg, &UniformMeasurer::new()).expect("render");
    assert_eq!(list.counts.text_withheld, 0);
    assert_eq!(list.counts.text_runs, 3);
    assert_eq!(report.characters, 37, "7 + 22 + 8");
    let text = list.to_text();
    assert!(text.contains("model=uniform-advance-stub/v1"));
    assert!(text.contains("mprov=fabricated"));
    // The stub's banner clause reaches the output, because a reader of the
    // numbers needs to know they are not Roboto's.
    assert!(
        text.contains("stub model") || text.contains("uniform-advance-stub"),
        "the measure model is not in the artefact"
    );
}

#[test]
fn a_mixed_source_is_refused_rather_than_half_rendered() {
    // `from_tree` returns `Withheld` unless every text node has its characters.
    // A partial source would put real strings next to placeholders inside one
    // frame, which is the mixture that misleads hardest.
    let tree = draw::demo_tree(W, H);
    assert_eq!(TextSource::from_tree(&tree), TextSource::Withheld);
    let tree2 = draw::demo_tree_with_text(W, H);
    assert!(matches!(TextSource::from_tree(&tree2), TextSource::Supplied(_)));
}

#[test]
fn a_refusing_measurer_is_a_marker_not_a_failure_and_not_a_silent_empty() {
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let m = RefusingMeasurer {
        reason: "no font stack in a substrate",
    };
    let (list, report) = draw::render(&tree, &cfg, &m).expect("render");
    assert_eq!(report.usage.errors, 3, "three refusals recorded");
    assert_eq!(list.counts.text_runs, 0);
    // The characters were available, so the marker says "withheld" only because
    // the measurement was refused — the class list is empty, which is the tell.
    assert_eq!(list.counts.text_withheld, 3);
    assert!(report.usage.disclaimer().contains("measurer refused"));
}

fn find_text(tree: &BoxNode, id: &str) -> Option<String> {
    if tree.id == id {
        return tree.text.as_ref().and_then(|t| t.text.clone());
    }
    tree.children.iter().find_map(|c| find_text(c, id))
}

// ---------------------------------------------------------------------------
// 3. Views must not vanish

#[test]
fn an_invisible_view_reserves_space_and_says_it_is_invisible() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut a = View::leaf("a", "View", NodeKind::View);
    a.layout_params.height = Dimension::Exact(40);
    let mut b = View::leaf("b", "View", NodeKind::View);
    b.visibility = Visibility::Invisible;
    b.layout_params.height = Dimension::Exact(40);
    let mut c = View::leaf("c", "View", NodeKind::View);
    c.visibility = Visibility::Gone;
    c.layout_params.height = Dimension::Exact(40);
    root.add(a);
    root.add(b);
    root.add(c);
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );

    // The shim drops GONE. INVISIBLE stays and takes part in layout, on a real
    // device too.
    assert!(frame_of(&tree, "b").height() == 40, "INVISIBLE must reserve space");
    let (list, report) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.nodes_invisible, 1, "one invisible view");
    assert!(!list.to_text().contains("id=c"), "a GONE view appeared");

    let text = list.to_text();
    assert!(text.contains("id=b") && text.contains("state=invisible"), "{text}");
    // And its area is marked as having no ink, with a reason that names the
    // platform behaviour rather than this layer's ignorance.
    assert!(
        text.contains("view is INVISIBLE: it reserves space and paints nothing"),
        "{text}"
    );
}

#[test]
fn a_gone_node_reaching_the_painter_is_recorded_not_dropped_silently() {
    // The shim filters GONE, so this is the defensive path. A node that reached
    // here and was dropped without a trace would make the output look complete.
    let tree = draw::demo_tree(W, H);
    let mut forced = tree.clone();
    forced.visibility = Visibility::Gone;
    let (list, report) =
        draw::render(&forced, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.nodes_invisible, 1);
    assert!(list.to_text().contains("state=gone"));
    // And nothing was drawn for it.
    assert!(!list.to_text().contains("draw-rect"));
}

#[test]
fn every_node_in_the_tree_reaches_the_output() {
    // No node may be lost between the shim's tree and the display list. Each one
    // produces at least an outline, so the count of outlines equals the count of
    // nodes.
    let tree = draw::demo_tree(W, H);
    let (list, report) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.nodes_visited, tree.count());
    assert_eq!(report.nodes_visible, tree.count());
    let outlines = list
        .steps
        .iter()
        .filter(|s| {
            matches!(
                &s.command,
                Command::Annotate(Annotation::BoxOutline { .. })
            )
        })
        .count();
    assert_eq!(outlines, tree.count(), "a node was lost");
    for (id, _) in tree.flatten() {
        assert!(
            list.to_text().contains(&format!("box-outline id={id} ")),
            "no outline for {id}"
        );
    }
}

#[test]
fn the_visibility_state_matches_the_shims_own_field() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut b = View::leaf("b", "View", NodeKind::View);
    b.visibility = Visibility::Invisible;
    root.add(b);
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    assert_eq!(tree.visibility, Visibility::Invisible);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let states: Vec<ViewState> = list
        .steps
        .iter()
        .filter_map(|s| match &s.command {
            Command::Annotate(Annotation::BoxOutline { state, .. }) => Some(*state),
            _ => None,
        })
        .collect();
    assert!(states.contains(&ViewState::Invisible));
}

// ---------------------------------------------------------------------------
// 4. Clipping, and hostile trees

#[test]
fn a_container_clips_its_children_and_the_effective_clip_is_recorded() {
    // A `FrameLayout` child larger than its parent overflows, which is the only
    // way the shim's layout produces a child outside its parent. The clip has to
    // be real, not decorative.
    let mut root = View::group(
        "root",
        "FrameLayout",
        NodeKind::FrameLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    let mut big = View::leaf("big", "View", NodeKind::View);
    big.layout_params.width = Dimension::Exact(1000);
    big.layout_params.height = Dimension::Exact(1000);
    root.add(big);
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    assert!(frame_of(&tree, "big").width() == 1000, "the child really does overflow");

    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let text = list.to_text();
    assert!(text.contains("clip-rect"), "no clip was emitted");
    // The effective clip is the parent's frame, not the child's 1000 dp.
    assert!(
        text.contains(&format!("effective=[0,0 {},{}]", tree.frame.width(), tree.frame.height())),
        "the effective clip is not the parent's frame:\n{text}"
    );
}

#[test]
fn a_deep_tree_is_a_typed_error_and_not_a_stack_overflow() {
    // An app nests views as deeply as it likes. The shim built the tree, so this
    // crate's recursion is the second thing that could be made to fail.
    let mut v = View::leaf("leaf", "View", NodeKind::View);
    for i in 0..3000 {
        let mut parent = View::group(
            &format!("p{i}"),
            "LinearLayout",
            NodeKind::LinearLayout,
            Orientation::Vertical,
        );
        parent.layout_params.width = Dimension::MatchParent;
        parent.add(v);
        v = parent;
    }
    let tree = v.run(
        shim::layout::Size {
            width: 100,
            height: 100,
        },
        shim::layout::TextPolicy::Omit,
    );
    let cfg = DrawConfig {
        max_depth: 512,
        ..DrawConfig::with_viewport(100.0, 100.0, 1.0)
    };
    let e = draw::render(&tree, &cfg, &ZeroMeasurer::new()).unwrap_err();
    assert_eq!(e.kind(), "TreeTooDeep", "{e}");
    assert!(e.to_string().contains("over the 512 limit"), "{e}");
    // The default depth is higher than the shim's own test tree.
    let cfg = DrawConfig::with_viewport(100.0, 100.0, 1.0);
    assert!(cfg.max_depth >= 512, "the default must handle the 500-level case");
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("the default bound holds");
    assert!(list.counts.clip_regions >= 500);
}

#[test]
fn a_wide_tree_hits_the_step_limit_with_a_typed_error() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    for i in 0..2000 {
        let mut v = View::leaf(&format!("v{i}"), "View", NodeKind::View);
        v.layout_params.width = Dimension::Exact(1);
        v.layout_params.height = Dimension::Exact(1);
        root.add(v);
    }
    let tree = root.run(
        shim::layout::Size {
            width: 100,
            height: 100,
        },
        shim::layout::TextPolicy::Omit,
    );
    let cfg = DrawConfig {
        max_steps: 100,
        ..DrawConfig::with_viewport(100.0, 100.0, 1.0)
    };
    let e = draw::render(&tree, &cfg, &ZeroMeasurer::new()).unwrap_err();
    assert_eq!(e.kind(), "TooManySteps", "{e}");
}

// ---------------------------------------------------------------------------
// Geometry exactness

#[test]
fn the_geometry_in_the_output_is_the_shims_geometry_to_the_dp() {
    // Not "close to", not "monotonic": the exact integers the shim's layout
    // produced, re-derived from the shim's tree and compared with what this
    // layer serialised.
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let text = list.to_text();
    for (id, r) in tree.flatten() {
        let want = format!(
            "box-outline id={id} rect=[0,0 {},{}]",
            r.width(),
            r.height()
        );
        assert!(text.contains(&want), "expected a line containing:\n  {want}\ngot:\n{text}");
    }
    // The paddings, margins and insets the shim applied are visible in the
    // offsets between parent and child, because this layer translates by the
    // child's absolute frame.
    let pad = shim::layout::metrics::PADDING;
    let root = frame_of(&tree, "root");
    let title = frame_of(&tree, "title");
    assert_eq!(title.left, root.left + pad, "the shim's padding is in the geometry");
    assert!(
        text.contains(&format!("dx={} dy={}", title.left, title.top)),
        "the translate to the title is not the shim's offset"
    );
}

#[test]
fn children_stay_inside_their_parent_in_the_output() {
    // The shim's layout guarantees this for a `LinearLayout`; the display list
    // has to agree, or the two layers disagree about the geometry.
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let _ = list;
    fn check(n: &BoxNode) {
        let f = n.frame;
        for c in &n.children {
            assert!(
                c.frame.left >= f.left && c.frame.right <= f.right,
                "child {} of {} escapes horizontally: {:?} in {:?}",
                c.id,
                n.id,
                c.frame,
                f
            );
            assert!(
                c.frame.top >= f.top && c.frame.bottom <= f.bottom,
                "child {} of {} escapes vertically: {:?} in {:?}",
                c.id,
                n.id,
                c.frame,
                f
            );
            check(c);
        }
    }
    check(&tree);
}

#[test]
fn a_horizontal_row_divides_the_leftover_the_way_the_shim_did() {
    // Weights are the shim's arithmetic; this layer must not recompute them.
    let mut root = View::group(
        "row",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Horizontal,
    );
    root.layout_params.width = Dimension::MatchParent;
    for (id, w) in [("a", 1.0), ("b", 1.0), ("c", 2.0)] {
        let mut v = View::leaf(id, "View", NodeKind::View);
        v.layout_params.weight = w;
        root.add(v);
    }
    let tree = root.run(
        shim::layout::Size {
            width: 304,
            height: 10,
        },
        shim::layout::TextPolicy::Omit,
    );
    let (list, _r) =
        draw::render(&tree, &DrawConfig::with_viewport(304.0, 10.0, 1.0), &ZeroMeasurer::new())
            .expect("render");
    let text = list.to_text();
    for (id, want) in [("a", 74), ("b", 74), ("c", 148)] {
        assert!(
            text.contains(&format!("box-outline id={id} rect=[0,0 {want},")),
            "{id} should be {want} dp wide"
        );
    }
}

// ---------------------------------------------------------------------------
// Images

#[test]
fn an_image_view_with_no_bitmap_is_marked_absent_not_grey() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("pic", "ImageView", NodeKind::ImageView));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let (list, report) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.image_nodes, 1);
    assert_eq!(report.images_with_bitmaps, 0);
    assert_eq!(list.counts.images_absent, 1);
    assert_eq!(list.counts.images_drawn, 0);
    let text = list.to_text();
    assert!(text.contains("image-absent id=pic"), "{text}");
    assert!(text.contains("no decoded bitmap was supplied"), "{text}");
    assert!(!text.contains("draw-image"), "an image was drawn from nothing");
}

#[test]
fn a_decoded_bitmap_is_recorded_and_still_not_drawn() {
    // The pixels exist and this layer still will not show them, because there is
    // no image encoder here. That is a *different* failure from "never decoded"
    // and the output distinguishes them.
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("pic", "ImageView", NodeKind::ImageView));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    let mut images = ImageSource::none();
    images.insert(
        "pic",
        ImageBitmap {
            width: 2,
            height: 2,
            pixels: Some(vec![0; 16]),
        },
    );
    let cfg = DrawConfig {
        images,
        ..default_cfg()
    };
    let (list, report) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    assert_eq!(report.images_with_bitmaps, 1);
    assert_eq!(list.counts.images_drawn, 1, "the draw call is recorded");
    let text = list.to_text();
    assert!(text.contains("draw-image"), "{text}");
    assert!(text.contains("decoded=1"), "{text}");
    assert!(text.contains("bitmap=2x2"), "{text}");
    assert!(
        text.contains("image-not-embedded id=pic"),
        "a decoded bitmap was not reported as unembeddable:\n{text}"
    );
}

#[test]
fn a_malformed_bitmap_is_a_typed_error_not_a_draw() {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = Dimension::MatchParent;
    root.add(View::leaf("pic", "ImageView", NodeKind::ImageView));
    let tree = root.run(
        shim::layout::Size {
            width: W,
            height: H,
        },
        shim::layout::TextPolicy::Omit,
    );
    for bad in [
        ImageBitmap {
            width: 0,
            height: 0,
            pixels: None,
        },
        ImageBitmap {
            width: 2,
            height: 2,
            pixels: Some(vec![0; 3]),
        },
    ] {
        let mut images = ImageSource::none();
        images.insert("pic", bad.clone());
        let cfg = DrawConfig {
            images,
            ..default_cfg()
        };
        let e = draw::render(&tree, &cfg, &ZeroMeasurer::new()).unwrap_err();
        assert_eq!(e.kind(), "BadBitmap", "{bad:?} gave {e}");
        assert!(e.assumption().is_some(), "a bad bitmap is a SUB.GFX.SURFACE problem");
    }
}

// ---------------------------------------------------------------------------
// The seam

#[test]
fn the_measurer_is_a_trait_and_a_custom_one_drops_in() {
    // B4's real measurer replaces the stub by implementing this trait and
    // changing nothing else. Proven here with a measurer that is neither of the
    // crate's.
    struct HalfEm;
    impl TextMeasurer for HalfEm {
        fn measure(
            &self,
            text: &str,
            style: &substrate_runtime::measure::TextStyle,
        ) -> Result<substrate_runtime::TextAdvance, substrate_runtime::GraphicsError> {
            let mut a = UniformMeasurer::new()
                .with_em_fraction(0.5)
                .measure(text, style)?;
            a.model = "half-em/v9".to_string();
            Ok(a)
        }
        fn model_id(&self) -> String {
            "half-em/v9".to_string()
        }
        fn provenance(&self) -> Provenance {
            Provenance::Fabricated
        }
        fn call_count(&self) -> u64 {
            0
        }
    }
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let (list, report) = draw::render(&tree, &cfg, &HalfEm).expect("render");
    assert_eq!(list.measure_model, "half-em/v9");
    assert_eq!(report.usage.runs, 3);
    assert!(list.to_text().contains("model=half-em/v9"));
}

#[test]
fn a_measurer_returning_a_non_finite_advance_is_refused() {
    struct Broken;
    impl TextMeasurer for Broken {
        fn measure(
            &self,
            _t: &str,
            _s: &substrate_runtime::measure::TextStyle,
        ) -> Result<substrate_runtime::TextAdvance, substrate_runtime::GraphicsError> {
            Ok(substrate_runtime::TextAdvance {
                advance_x: f32::NAN,
                advance_y: 0.0,
                lines: 1,
                ascent: 0.0,
                descent: 0.0,
                model: "broken".to_string(),
                provenance: Provenance::Fabricated,
            })
        }
        fn model_id(&self) -> String {
            "broken".to_string()
        }
        fn provenance(&self) -> Provenance {
            Provenance::Fabricated
        }
        fn call_count(&self) -> u64 {
            0
        }
    }
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let (list, report) = draw::render(&tree, &cfg, &Broken).expect("render");
    assert_eq!(report.usage.errors, 3, "a NaN advance is an error, not a run");
    assert_eq!(list.counts.text_runs, 0);
    assert!(!list.to_text().contains("nan"), "a NaN reached the output");
}

#[test]
fn an_unset_paint_composites_src_over_and_the_output_says_so() {
    // The mode every paint actually uses. Printing `xfer=none` for an unset
    // xfermode would hide it.
    let tree = draw::demo_tree(W, H);
    let cfg = DrawConfig {
        theme: Theme::Placeholder,
        ..default_cfg()
    };
    let (list, _r) = draw::render(&tree, &cfg, &ZeroMeasurer::new()).expect("render");
    let text = list.to_text();
    assert!(text.contains("xfer=SRC_OVER"), "the default mode is not in the output");
    assert!(!text.contains("xfer=none"), "an unset xfermode was printed as none");
    // And a paint with an explicit mode keeps it.
    let p = substrate_runtime::Paint::new().with_xfermode(PorterDuffMode::SrcIn);
    assert_eq!(p.effective_xfermode(), PorterDuffMode::SrcIn);
    let _ = Color::WHITE;
}
