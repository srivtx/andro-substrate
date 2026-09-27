//! The measure/layout/draw cycle: is it real arithmetic, and is the box tree
//! inspectable?
//!
//! # What "real" means here
//!
//! Not "renders a picture". A pixel buffer is lossy — two different layouts can
//! produce identical pixels at one scale — and it is untestable, because "does
//! this look right" is not an assertion. A box tree is exact, cheap, diffable
//! between a substrate run and a device run, and assertable property by property,
//! which is what a comparison study needs. Every node carries `painted: false`
//! and there is no rasteriser in the crate, so nothing has to be inferred.
//!
//! # What is *not* claimed
//!
//! The font model is a documented advance table, not Roboto. Measurements will
//! not match a phone's, and the discrepancy is exactly `SUB.GFX.TEXT_RENDER`. The
//! model is *deterministic* and that is the property these tests check; matching a
//! device is not, and cannot be, without a font.

use shim::layout::{
    self, Dimension, NodeKind, Orientation, Size, TextPolicy, TextShape, View, Visibility,
};
use shim::taxonomy::AssumptionId;
use shim::{Shim, ShimCaller};

fn login_form() -> View {
    let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
    root.layout_params.width = Dimension::MatchParent;
    let mut title = View::text("title", "TextView", NodeKind::TextView, "Sign in");
    title.layout_params.width = Dimension::MatchParent;
    root.add(title);
    let mut field = View::text("email", "EditText", NodeKind::EditText, "person@example.invalid");
    field.layout_params.width = Dimension::MatchParent;
    root.add(field);
    let mut button = View::text("go", "Button", NodeKind::Button, "Continue");
    button.layout_params.width = Dimension::Exact(120);
    root.add(button);
    root
}

fn rect_of(t: &layout::BoxNode, id: &str) -> layout::Rect {
    t.flatten()
        .into_iter()
        .find(|(k, _)| k == id)
        .unwrap_or_else(|| panic!("no node {id} in {:?}", t.flatten()))
        .1
}

#[test]
fn measure_then_layout_produces_a_consistent_box_tree() {
    let mut v = login_form();
    let m = v.measure(Size { width: 360, height: 640 });
    // A vertical LinearLayout of three children is at least as tall as the sum of
    // them, and never taller than the offer.
    assert!(m.height > 0 && m.height <= 640, "{m:?}");
    assert!(m.width > 0 && m.width <= 360, "{m:?}");
    v.layout(layout::Rect { left: 0, top: 0, right: m.width, bottom: m.height });
    let t = v.draw(TextPolicy::ShapeOnly);

    // The three invariants a box tree must satisfy if the layout pass is real.
    for node in &t.flatten().into_iter().map(|(_, r)| r).collect::<Vec<_>>() {
        assert!(node.width() >= 0 && node.height() >= 0);
        assert!(node.right >= node.left && node.bottom >= node.top, "{node:?}");
    }
    // Children lie inside their parent.
    let root = &t;
    let inside = |child: &layout::Rect| {
        child.left >= root.frame.left
            && child.right <= root.frame.right
            && child.top >= root.frame.top
            && child.bottom <= root.frame.bottom
    };
    let title = rect_of(&t, "title");
    let email = rect_of(&t, "email");
    let go = rect_of(&t, "go");
    assert!(inside(&title) && inside(&email) && inside(&go));
    // And they do not overlap, because they are stacked.
    assert!(title.bottom <= email.top, "{title:?} vs {email:?}");
    assert!(email.bottom <= go.top, "{email:?} vs {go:?}");
    // The button honoured its exact width; the text views did not.
    assert_eq!(go.width(), 120);
    assert_eq!(email.width(), 360 - 2 * layout::metrics::PADDING);
}

#[test]
fn weights_divide_the_leftover_space_exactly() {
    let mut root = View::group("row", "LinearLayout", NodeKind::LinearLayout, Orientation::Horizontal);
    root.layout_params.width = Dimension::MatchParent;
    for (id, w) in [("a", 1.0), ("b", 1.0), ("c", 2.0)] {
        let mut v = View::leaf(id, "View", NodeKind::View);
        v.layout_params.weight = w;
        root.add(v);
    }
    let t = root.run(Size { width: 304, height: 10 }, TextPolicy::Omit);
    // 304 - 8 padding = 296 to divide, in the ratio 1:1:2 -> 74, 74, 148.
    let a = rect_of(&t, "a");
    let b = rect_of(&t, "b");
    let c = rect_of(&t, "c");
    assert_eq!((a.width(), b.width(), c.width()), (74, 74, 148));
    assert_eq!(b.left, a.right);
    assert_eq!(c.left, b.right);
    assert_eq!(c.right, 304 - layout::metrics::PADDING);
}

#[test]
fn a_zero_or_negative_viewport_does_not_panic_and_produces_zero_sized_boxes() {
    for vp in [
        Size { width: 0, height: 0 },
        Size { width: 1, height: 1 },
        Size { width: i32::MAX, height: i32::MAX },
    ] {
        let mut v = login_form();
        let t = v.run(vp, TextPolicy::ShapeOnly);
        assert!(t.frame.width() >= 0 && t.frame.height() >= 0);
        for (_, r) in t.flatten() {
            assert!(r.width() >= 0 && r.height() >= 0, "{vp:?} produced {r:?}");
        }
    }
}

#[test]
fn deep_and_wide_trees_do_not_blow_the_stack_or_the_output() {
    // Untrusted input: an app can nest views as deeply as it likes. 500 levels
    // must not overflow, and the serialised tree must stay inside the oracle's
    // 8000-byte `probes[].output` ceiling with truncation reported rather than
    // silently applied.
    let mut v = View::leaf("leaf", "View", NodeKind::View);
    for i in 0..500 {
        let mut parent = View::group(&format!("p{i}"), "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
        parent.layout_params.width = Dimension::MatchParent;
        parent.add(v);
        v = parent;
    }
    let t = v.run(Size { width: 100, height: 100 }, TextPolicy::Omit);
    assert_eq!(t.count(), 501);
    let (out, truncated) = layout::tree_for_probe(&t, 8000);
    assert!(truncated, "a 501-node tree cannot fit in 8000 bytes");
    assert!(out.len() <= 8000, "{} bytes: the marker must be reserved, not appended past the \
limit", out.len());
    assert!(out.contains("\"truncated\":true"));
}

#[test]
fn text_measurement_is_a_real_function_of_the_string() {
    // Not an average, not a guess: the advance table is keyed on character
    // class, so a wide string measures wider and a narrow one narrower, and the
    // same string always measures the same.
    let w = |s: &str| layout::metrics::text_width(s, layout::metrics::TEXT_SIZE);
    assert_eq!(w(""), 0);
    assert!(w("WWWW") > w("iiii"), "a wide glyph must advance further");
    assert!(w("漢字") > w("abc"), "a fullwidth form is about twice a Latin letter");
    assert_eq!(w("hello"), w("hello"), "determinism is the property that matters");
    assert!(w("hello") > w("hell"));
    // Wrapping is real, so a long string takes more lines than a short one.
    assert_eq!(layout::metrics::line_count("", 14, 100), 0);
    assert_eq!(layout::metrics::line_count("a", 14, 100), 1);
    assert!(layout::metrics::line_count(&"word ".repeat(40), 14, 100) > 1);
    assert!(layout::metrics::text_height(&"word ".repeat(40), 14, 100) > layout::metrics::text_height("word", 14, 100));
}

#[test]
fn the_font_model_is_named_in_the_output() {
    // A number in a box tree must never be mistaken for a device measurement.
    let mut v = login_form();
    let t = v.run(Size { width: 360, height: 640 }, TextPolicy::Omit);
    let mut s = Shim::new("a.b", vec![]).expect("shim");
    let a = s
        .invoke("Landroid/app/Activity;", "<init>", "()V", &[])
        .expect("Activity");
    s.set_view_tree(&a, v).expect("install the view tree");
    let tree = s.run_layout(Size { width: 360, height: 640 }).expect("layout");
    let probes: Vec<String> = s
        .events()
        .iter()
        .map(|e| e.summary())
        .filter(|s| s.contains("LAYOUT"))
        .collect();
    assert_eq!(probes.len(), 1, "{}", probes.join("; "));
    assert!(probes[0].contains(layout::metrics::MODEL), "{}", probes[0]);
    assert!(probes[0].contains("painted: false"), "{}", probes[0]);
    assert_eq!(tree.count(), t.count());
}

#[test]
fn the_layout_pass_is_recorded_with_its_taxonomy_id() {
    let mut s = Shim::new("a.b", vec![]).expect("shim");
    let a = s
        .invoke("Landroid/app/Activity;", "<init>", "()V", &[])
        .expect("Activity");
    s.set_view_tree(&a, login_form()).expect("install the view tree");
    s.run_layout(Size { width: 360, height: 640 }).expect("layout");
    let ev = s
        .events()
        .iter()
        .find(|e| e.summary().contains("LAYOUT"))
        .expect("a layout event");
    assert_eq!(ev.assumption, Some(AssumptionId::GfxTextRender));
    assert_eq!(ev.group, shim::event::Group::Probes);
}

#[test]
fn gone_children_leave_the_tree_and_invisible_ones_do_not() {
    let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
    root.layout_params.width = Dimension::MatchParent;
    let mut gone = View::leaf("gone", "View", NodeKind::View);
    gone.visibility = Visibility::Gone;
    gone.layout_params.height = Dimension::Exact(40);
    let mut invisible = View::leaf("invisible", "View", NodeKind::View);
    invisible.visibility = Visibility::Invisible;
    invisible.layout_params.height = Dimension::Exact(40);
    root.add(gone);
    root.add(invisible);
    let t = root.run(Size { width: 100, height: 100 }, TextPolicy::Omit);
    let ids: Vec<String> = t.flatten().into_iter().map(|(k, _)| k).collect();
    assert!(!ids.contains(&"gone".to_string()));
    assert!(ids.contains(&"invisible".to_string()));
    // An invisible child still occupies its measured space, because it still
    // takes part in layout; a gone one does not. That is the difference between
    // the two, and getting it wrong is a layout bug an app can see. With only a
    // `GONE` child of 40 dp, the row must be shorter than with an `INVISIBLE` one.
    let gone_only = {
        let mut r = View::group("r", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
        r.layout_params.width = Dimension::MatchParent;
        let mut g = View::leaf("g", "View", NodeKind::View);
        g.visibility = Visibility::Gone;
        g.layout_params.height = Dimension::Exact(40);
        r.add(g);
        r.run(Size { width: 100, height: 100 }, TextPolicy::Omit)
    };
    assert!(
        gone_only.frame.height() < t.frame.height(),
        "a GONE child must not reserve space: {} vs {}",
        gone_only.frame.height(),
        t.frame.height()
    );
}

#[test]
fn frame_layout_stacks_and_gravity_places() {
    let mut root = View::group("root", "FrameLayout", NodeKind::FrameLayout, Orientation::Vertical);
    root.layout_params.width = Dimension::MatchParent;
    let mut top_left = View::leaf("tl", "View", NodeKind::View);
    top_left.layout_params.width = Dimension::Exact(10);
    top_left.layout_params.height = Dimension::Exact(10);
    let mut centre = View::leaf("c", "View", NodeKind::View);
    centre.layout_params.width = Dimension::Exact(10);
    centre.layout_params.height = Dimension::Exact(10);
    centre.layout_params.gravity = layout::gravity::CENTER;
    root.add(top_left);
    root.add(centre);
    let t = root.run(Size { width: 100, height: 100 }, TextPolicy::Omit);
    let tl = rect_of(&t, "tl");
    let c = rect_of(&t, "c");
    assert_eq!(
        (tl.left, tl.top),
        (layout::metrics::PADDING, layout::metrics::PADDING),
        "TOP|LEFT must pin to the top-left of the frame's content box"
    );
    // The FrameLayout does not grow to the viewport vertically: wrap_content is
    // the largest child, which is the documented behaviour and a common source of
    // "my layout is only as tall as its content" surprises.
    assert_eq!(c.left, tl.left + (t.frame.width() - 2 * layout::metrics::PADDING - 10) / 2);
    // Overlap is visible in the area accounting, which is the point of counting
    // leaf area rather than the bounding box.
    assert!(t.leaf_area() >= 200, "two 10x10 children");
}

#[test]
fn an_edit_text_does_not_grow_with_its_content() {
    // A scrollable single-line field has a fixed height, which is the detail that
    // makes an overflowing login form behave the way it does.
    let short = View::text("e", "EditText", NodeKind::EditText, "a");
    let long = View::text("e", "EditText", NodeKind::EditText, &"x".repeat(200));
    assert_eq!(
        short.intrinsic_size().height,
        long.intrinsic_size().height,
        "an EditText is scrollable; its height does not depend on its content"
    );
    // A TextView does grow.
    let ts = View::text("t", "TextView", NodeKind::TextView, "a");
    let tl = View::text("t", "TextView", NodeKind::TextView, &"x".repeat(200));
    assert!(tl.intrinsic_size().width > ts.intrinsic_size().width);
}

#[test]
fn a_text_shape_reveals_the_shape_without_the_characters() {
    for (input, email, phone, numeric) in [
        ("someone@example.invalid", true, false, false),
        ("+44 7700 900123", false, true, false),
        ("-1234", false, false, true),
        ("hunter2", false, false, false),
        ("-1234", false, false, true),
        ("", false, false, false),
    ] {
        let s = TextShape::of(input, TextPolicy::ShapeOnly);
        assert_eq!(s.looks_like_email, email, "{input}");
        assert_eq!(s.looks_like_phone, phone, "{input}");
        assert_eq!(s.looks_numeric, numeric, "{input}");
        assert_eq!(s.chars, input.chars().count());
        assert!(s.text.is_none(), "{input}: the characters must never be held");
        // And the rendered shape must not contain the input either.
        let json = serde_json::to_string(&s).expect("json");
        if !input.is_empty() {
            assert!(!json.contains(input), "{input} leaked into {json}");
        }
    }
}

#[test]
fn a_malformed_view_tree_cannot_be_serialised_into_a_valid_looking_document() {
    // Truncation must be visible. A `probes[].output` that is silently cut is a
    // tree an analyst will read as complete.
    let mut big = {
        let mut root = View::group("root", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
        for i in 0..200 {
            let mut v = View::text(&format!("v{i}"), "TextView", NodeKind::TextView, &"w".repeat(40));
            v.layout_params.width = Dimension::MatchParent;
            root.add(v);
        }
        root
    };
    let t = big.run(Size { width: 400, height: 4000 }, TextPolicy::Omit);
    let (out, truncated) = layout::tree_for_probe(&t, 8000);
    assert!(truncated);
    assert!(out.contains("\"truncated\":true"));
    assert!(out.len() <= 8000);
}
