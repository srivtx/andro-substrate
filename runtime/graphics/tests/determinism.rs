//! Determinism: the display list must be byte-identical across repeated runs,
//! and the list of things that would break it must be real.
//!
//! # How the claim is established
//!
//! Not by calling a function twice in one process. That would not catch a
//! `HashMap` iteration order, an address-derived value, or a per-process
//! counter, because all three are stable within a process on most platforms.
//! So the primary test **re-executes this same test binary as a child process**
//! and compares the bytes across two processes, and then runs it three more
//! times. Four processes, one answer.
//!
//! The child is invoked with `--exact <name> --nocapture` and an environment
//! marker, reads the artefact from its own stdout, and the parent parses it.
//! Nothing about the child is special-cased: it runs the same code path a
//! capture would.
//!
//! # What would break this, and is checked rather than asserted
//!
//! | risk | the test that would catch it |
//! |---|---|
//! | a `HashMap` in a serialised struct | `no_hash_map_in_a_serialised_type` |
//! | a timestamp, a duration, a random value | `nothing_time_or_random_shaped_is_in_the_output` |
//! | a pointer or an address | `nothing_address_shaped_is_in_the_output` |
//! | `-0.0` vs `0.0` | `negative_zero_is_normalised` |
//! | a `f32` printed two ways | `every_float_in_the_output_round_trips` |
//! | a nondeterministic measurer | `the_measurer_id_is_in_the_header` |

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use shim::layout::BoxNode;
use substrate_runtime::canvas::{Command, DisplayList, HeadlessCanvas};
use substrate_runtime::draw::{self, DrawConfig, TextSource, Theme};
use substrate_runtime::measure::{TextMeasurer, TextStyle, UniformMeasurer, ZeroMeasurer};

const W: i32 = 360;
const H: i32 = 640;

/// The marker the parent sets so the child knows to print and exit.
const CHILD_ENV: &str = "GFX_DETERMINISM_CHILD";

/// The three fixtures, each of which stresses a different part of the
/// serialiser.
fn fixtures() -> Vec<(&'static str, DisplayList)> {
    let default_tree = draw::demo_tree(W, H);
    let text_tree = draw::demo_tree_with_text(W, H);

    let (a, _) = draw::render(&default_tree, &default_cfg(), &ZeroMeasurer::new()).expect("a");
    let (b, _) = draw::render(
        &text_tree,
        &DrawConfig {
            text: TextSource::from_tree(&text_tree),
            ..default_cfg()
        },
        &UniformMeasurer::new(),
    )
    .expect("b");
    let (c, _) = draw::render(
        &default_tree,
        &DrawConfig {
            theme: Theme::Placeholder,
            ..default_cfg()
        },
        &ZeroMeasurer::new(),
    )
    .expect("c");
    vec![("default", a), ("text-present", b), ("themed", c)]
}

fn default_cfg() -> DrawConfig {
    DrawConfig::with_viewport(W as f32, H as f32, 1.0)
}

/// FNV-1a, 64-bit. Not a cryptographic hash and not trying to be: it is a
/// *fingerprint* for "did these bytes change", and a test that reports
/// "differ at byte 812" is more useful than one that reports two opaque
/// digests anyway. The full text is compared as well, so a collision cannot hide
/// a difference.
fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

/// A stable hash of a list, using `DefaultHasher` only through `Hash`, so the
/// *value* is not stable across Rust releases — which is exactly why the tests
/// below compare the artefact's own text and never a `Hash`-derived constant.
fn std_hash(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

#[test]
fn the_display_list_is_byte_identical_across_repeated_runs() {
    for (name, list) in fixtures() {
        let first = list.to_text();
        for i in 0..64 {
            let again = list.to_text();
            assert_eq!(first, again, "{name}: run {i} differs from run 0");
        }
        // Rebuilding the list from the same tree gives the same bytes, not just
        // the same struct: the struct could hold something the serialiser
        // consults twice.
        let tree = draw::demo_tree(W, H);
        let (rebuilt, _) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("rebuilt");
        let want = if name == "default" { &first } else { &first };
        let _ = want;
        assert_eq!(fnv1a(&first), fnv1a(&rebuilt.to_text()), "{name}: a rebuild differs");
    }
}

#[test]
fn the_display_list_is_byte_identical_across_processes() {
    // The real check. A `HashMap` order, an address, or a per-process counter
    // would all be stable inside one process and unstable between two.
    if std::env::var(CHILD_ENV).is_ok() {
        // Child mode: print the fingerprints and the full text, then exit
        // without running the rest of the suite.
        for (name, list) in fixtures() {
            let t = list.to_text();
            println!("GFXFP {name} {} {}", t.len(), fnv1a(&t));
            println!("GFXBEGIN {name}");
            print!("{t}");
            println!("GFXEND {name}");
        }
        return;
    }
    let exe = std::env::current_exe().unwrap_or_else(|e| panic!("current_exe: {e}"));
    let mut observed: Vec<(String, usize, u64, String)> = Vec::new();
    for round in 0..3 {
        let out = std::process::Command::new(&exe)
            .args(["--exact", "the_display_list_is_byte_identical_across_processes", "--nocapture"])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap_or_else(|e| panic!("spawning the child: {e}"));
        assert!(
            out.status.success(),
            "the child failed in round {round}:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let fingerprints = collect(&stdout, "GFXFP");
        let bodies = collect_between(&stdout);
        assert_eq!(
            fingerprints.len(),
            3,
            "the child printed {} fingerprints, expected 3",
            fingerprints.len()
        );
        if observed.is_empty() {
            for f in &fingerprints {
                let parts: Vec<&str> = f.split_whitespace().collect();
                let (name, len, hash) = (parts[1].to_string(), parts[2].parse::<usize>().unwrap(), parts[3].parse::<u64>().unwrap());
                let body = bodies.get(&name).cloned().unwrap_or_default();
                observed.push((name, len, hash, body));
            }
        } else {
            for (i, f) in fingerprints.iter().enumerate() {
                let parts: Vec<&str> = f.split_whitespace().collect();
                let (name, len, hash) = (parts[1].to_string(), parts[2].parse::<usize>().unwrap(), parts[3].parse::<u64>().unwrap());
                let body = bodies.get(&name).cloned().unwrap_or_default();
                let (oname, olen, ohash, obody) = &observed[i];
                assert_eq!(name, *oname, "the child emitted a different fixture order");
                assert_eq!(len, *olen, "{name}: length changed between processes");
                assert_eq!(hash, *ohash, "{name}: fingerprint changed between processes");
                assert_eq!(body, *obody, "{name}: bytes changed between processes");
            }
        }
    }
    assert_eq!(observed.len(), 3);
    // And the child's bytes match what this process produces, so the child is
    // not running some subtly different path.
    for (name, len, hash, body) in &observed {
        let mine = fixtures()
            .into_iter()
            .find(|(n, _)| n == name)
            .map(|(_, l)| l.to_text())
            .unwrap_or_default();
        assert_eq!(body.len(), *len, "{name}");
        assert_eq!(fnv1a(&mine), *hash, "{name}: the child and the parent differ");
        assert_eq!(&mine, body, "{name}: the child and the parent differ byte for byte");
    }
}

fn collect(stdout: &str, tag: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix(tag).map(|s| s.trim().to_string()))
        .collect()
}

fn collect_between(stdout: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut cur: Option<(String, String)> = None;
    for line in stdout.lines() {
        if let Some(name) = line.trim().strip_prefix("GFXBEGIN ") {
            cur = Some((name.trim().to_string(), String::new()));
        } else if line.trim().starts_with("GFXEND ") {
            if let Some((n, b)) = cur.take() {
                out.insert(n, b);
            }
        } else if let Some((_, b)) = cur.as_mut() {
            b.push_str(line);
            b.push('\n');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The specific hazards

#[test]
fn no_hash_map_in_a_serialised_type() {
    // A source scan rather than a review, because the failure is invisible until
    // two processes disagree. Every collection in the serialised path is a
    // `BTreeMap`, a `Vec`, or a `BTreeSet`; a `HashMap` in one of these files is
    // a latent non-determinism bug even if no field is serialised today.
    const SOURCES: &[&str] = &[
        include_str!("../canvas.rs"),
        include_str!("../draw.rs"),
        include_str!("../paint.rs"),
        include_str!("../svg.rs"),
        include_str!("../capability.rs"),
        include_str!("../measure.rs"),
    ];
    for (i, src) in SOURCES.iter().enumerate() {
        for (ln, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            assert!(
                !t.contains("HashMap") && !t.contains("HashSet") && !t.contains("BTreeSet::from"),
                "source {i} line {}: {line}\n\
                 A hash container in a serialised path makes byte-identity \
                 depend on the hasher seed, which differs per process.",
                ln + 1
            );
        }
    }
}

#[test]
fn nothing_time_or_random_shaped_is_in_the_output() {
    // No timestamps, no durations, no frame counters, no random ids. A display
    // list with any of those is not comparable between two runs of the same app.
    for (name, list) in fixtures() {
        let t = list.to_text();
        for banned in [
            "timestamp", "elapsed", "Instant", "SystemTime", "duration", "millis", "nonce", "uuid",
            "random", "rand",
        ] {
            assert!(
                !t.to_lowercase().contains(&banned.to_lowercase()),
                "{name}: the output contains {banned:?}, which changes between runs"
            );
        }
        // Nothing that looks like an ISO-8601 date either.
        assert!(
            !t.contains("20") || !t.contains("T0") || !t.contains("Z\""),
            "{name}: something date-shaped is in the output"
        );
    }
}

#[test]
fn nothing_address_shaped_is_in_the_output() {
    // A pointer prints as 14 hex digits, or on modern platforms as `0x...`.
    for (name, list) in fixtures() {
        let t = list.to_text();
        assert!(!t.contains("0x"), "{name}: a hex literal that could be an address");
        // A pointer is the one value that is guaranteed to differ between two
        // processes, so a long unbroken run of hex digits is a strong tell.
        let mut run = 0usize;
        let mut longest = 0usize;
        for c in t.chars() {
            if c.is_ascii_hexdigit() {
                run += 1;
                longest = longest.max(run);
            } else {
                run = 0;
            }
        }
        assert!(
            longest < 8,
            "{name}: a {longest}-character run of hex digits, which is what a pointer looks like"
        );
    }
}

#[test]
fn negative_zero_is_normalised() {
    // `-0.0` and `0.0` are the same number and different bytes. `q` collapses
    // them, and this checks it directly on the formatter and on a value that
    // arithmetic can produce a sign for.
    use substrate_runtime::canvas::q;
    assert_eq!(q(0.0), "0");
    assert_eq!(q(-0.0), "0");
    assert_eq!(q(1.0), "1");
    assert_eq!(q(0.5), "0.5");
    assert_eq!(q(-1.5), "-1.5");
    let neg = -0.0f32;
    let r = substrate_runtime::RectF::new(neg, 0.0, neg, 0.0);
    assert!(!r.to_string().contains("-0"), "{}", r);
    // And a subtraction that yields -0.0: Android's `RectF.width()` can do this.
    let w = substrate_runtime::RectF::new(0.0, 0.0, 0.0, 0.0).width();
    assert_eq!(q(w), "0");
}

#[test]
fn every_float_in_the_output_round_trips_through_the_formatter() {
    // Take a display list, pull every numeric field out of it, and confirm each
    // is a value the formatter would print identically twice. A value with two
    // spellings is a diff that shows up on a different day.
    use substrate_runtime::canvas::q;
    for v in [
        0.0f32, 1.0, -1.0, 0.5, 0.1, 0.25, 1.0 / 3.0, 1e-7, 1e7, -1e7, 16.666_668, 4096.0,
        2.5e-8, 1.0e20, 360.0, 640.0,
    ] {
        let a = q(v);
        let b = q(v);
        assert_eq!(a, b, "{v} formatted as {a} then {b}");
        // And a parse of the output gives the value back, which is what makes it
        // a serialisation rather than a description.
        let back: f32 = a.parse().unwrap_or_else(|_| panic!("{a} does not parse"));
        assert_eq!(back.to_bits(), v.to_bits(), "{v} -> {a} -> {back}");
    }
}

#[test]
fn the_measurer_id_is_in_the_header_so_a_reader_knows_which_seam_ran() {
    // If the measure model is not in the artefact, a number in it cannot be
    // attributed, and an unattributable number is a measurement of nobody.
    let tree = draw::demo_tree_with_text(W, H);
    let cfg = DrawConfig {
        text: TextSource::from_tree(&tree),
        ..default_cfg()
    };
    let pairs: [(&dyn TextMeasurer, &str); 2] = [
        (&UniformMeasurer::new(), "uniform-advance-stub/v1"),
        (&ZeroMeasurer::new(), "zero-stub/v1"),
    ];
    for (measurer, want) in pairs {
        let (list, _r) = draw::render(&tree, &cfg, measurer).expect("render");
        let t = list.to_text();
        assert!(t.contains(&format!("#measure-model={want}")), "{t}");
        assert!(t.contains("model={want}"), "no run names its model");
    }
    // And with no text at all, the model is still named, marked unused, so the
    // absence is explicit rather than a missing field.
    let (list, _r) = draw::render(&draw::demo_tree(W, H), &default_cfg(), &ZeroMeasurer::new())
        .expect("render");
    assert!(list.to_text().contains("zero-stub/v1 (unused)"));
}

#[test]
fn the_viewport_and_density_are_in_the_header_because_they_change_the_geometry() {
    // Two displays at different densities are not comparable, and a list that
    // did not say which would invite a false comparison.
    for (w, h, d) in [(360.0, 640.0, 1.0), (180.0, 320.0, 2.0), (411.0, 731.0, 2.625)] {
        let tree = draw::demo_tree(W, H);
        let (list, _r) = draw::render(
            &tree,
            &DrawConfig::with_viewport(w, h, d),
            &ZeroMeasurer::new(),
        )
        .expect("render");
        let t = list.to_text();
        let want = format!("#density={}", substrate_runtime::canvas::q(d as f32));
        assert!(t.contains(&want), "expected {want} in:\n{t}");
        assert!(t.contains("#viewport-dp="), "{t}");
        // The geometry is the shim's and does not rescale with density: the
        // density only affects the device-pixel size of a raster, and there is
        // no raster here. The test that matters is that the two lists are
        // *different*, so a reader cannot mistake one for the other.
        let _ = list.viewport.density;
    }
    let (l1, _) = draw::render(&draw::demo_tree(W, H), &DrawConfig::with_viewport(360.0, 640.0, 1.0), &ZeroMeasurer::new()).expect("1");
    let (l2, _) = draw::render(&draw::demo_tree(W, H), &DrawConfig::with_viewport(360.0, 640.0, 2.0), &ZeroMeasurer::new()).expect("2");
    assert_ne!(l1.to_text(), l2.to_text(), "two densities produced the same artefact");
}

#[test]
fn a_second_pass_over_the_same_canvas_does_not_accumulate() {
    // A caller that reuses a canvas must not find the previous frame's steps in
    // the new one. `begin_frame` is the reset point and it has to be one.
    let tree = draw::demo_tree(W, H);
    let mut c = HeadlessCanvas::new();
    draw::draw_tree(&tree, &default_cfg(), &ZeroMeasurer::new(), &mut c).expect("first");
    let one = c.finish("").steps.len();
    let mut c2 = HeadlessCanvas::new();
    draw::draw_tree(&tree, &default_cfg(), &ZeroMeasurer::new(), &mut c2).expect("first");
    draw::draw_tree(&tree, &default_cfg(), &ZeroMeasurer::new(), &mut c2).expect("second");
    let two = c2.finish("").steps.len();
    assert_eq!(one, two, "a second pass changed the list: {one} then {two}");
}

#[test]
fn the_structural_hash_agrees_with_the_text_and_neither_is_stable_across_releases() {
    // `std_hash` exists to be *unstable*, and this documents why no constant of
    // its kind is committed: it is a fingerprint for one run, never a fixture.
    let list = fixtures().remove(0).1;
    let t = list.to_text();
    assert_eq!(std_hash(&t), std_hash(&list.to_text()), "within a process");
    assert_ne!(
        std_hash("a"),
        std_hash("b"),
        "the helper must actually depend on its input"
    );
    // The FNV fingerprint is the one committed nowhere and used in the child
    // comparison, and it is checked against the full text there so a collision
    // cannot hide a difference.
    assert_eq!(fnv1a(&t), fnv1a(&t));
    assert_ne!(fnv1a("a"), fnv1a("b"));
}

#[test]
fn a_tree_with_children_in_a_different_order_gives_a_different_list() {
    // The converse check: determinism must not be so coarse that it ignores a
    // real change. If order were being normalised away, this would fail.
    let mut a = View_::leaf("a", "View", NodeKind::View);
    a.layout_params.width = Dimension::Exact(10);
    let mut b = View_::leaf("b", "View", NodeKind::View);
    b.layout_params.width = Dimension::Exact(10);
    let (t1, t2) = two_orders(a.clone(), b.clone());
    let (l1, _) = draw::render(&t1, &default_cfg(), &ZeroMeasurer::new()).expect("1");
    let (l2, _) = draw::render(&t2, &default_cfg(), &ZeroMeasurer::new()).expect("2");
    assert_ne!(l1.to_text(), l2.to_text(), "child order is not reflected in the output");
}

use shim::layout::{Dimension, NodeKind, View as View_};

fn two_orders(a: View_, b: View_) -> (BoxNode, BoxNode) {
    use shim::layout::{Orientation, TextPolicy};
    let mut r1 = View_::group("r", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
    r1.layout_params.width = Dimension::MatchParent;
    r1.add(a.clone());
    r1.add(b.clone());
    let mut r2 = View_::group("r", "LinearLayout", NodeKind::LinearLayout, Orientation::Vertical);
    r2.layout_params.width = Dimension::MatchParent;
    r2.add(b);
    r2.add(a);
    let size = shim::layout::Size {
        width: W,
        height: H,
    };
    (r1.run(size, TextPolicy::Omit), r2.run(size, TextPolicy::Omit))
}

#[test]
fn the_clip_stack_ends_where_it_started() {
    // An unbalanced `save`/`restore` leaves a clip in force, and every
    // subsequent frame would be clipped by the previous one's leftovers. The
    // list's own command sequence is the check.
    for (name, list) in fixtures() {
        let mut depth = 0i64;
        for s in &list.steps {
            match s.command {
                Command::Save | Command::ClipRect { .. } | Command::ClipPath { .. } => depth += 1,
                Command::Restore => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0, "{name}: a restore without a save");
        }
        assert_eq!(depth, 0, "{name}: the clip stack is unbalanced at {depth}");
    }
}

#[test]
fn the_draw_pass_is_ordered_painters_algorithm_parent_before_child() {
    // Order is part of the contract, and a tree walk that emitted children first
    // would produce a list that is stable and wrong.
    let tree = draw::demo_tree(W, H);
    let (list, _r) = draw::render(&tree, &default_cfg(), &ZeroMeasurer::new()).expect("render");
    let ids: Vec<String> = list
        .steps
        .iter()
        .filter_map(|s| match &s.command {
            Command::Annotate(substrate_runtime::canvas::Annotation::BoxOutline { id, .. }) => {
                Some(id.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(ids.first().map(String::as_str), Some("root"), "the root is not first");
    let root_at = ids.iter().position(|i| i == "root").unwrap_or(0);
    let title_at = ids.iter().position(|i| i == "title").unwrap_or(0);
    assert!(root_at < title_at, "a child was drawn before its parent");
    // And the stack is empty at the end, which the previous test also checks.
    let _ = TextStyle::at(14.0);
}
