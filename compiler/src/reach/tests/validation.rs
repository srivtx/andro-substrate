//! Validation: the static closure against a measured trace, and the refusal
//! to make the two agree.
//!
//! The defect this module exists to prevent is a static analysis tuned until it
//! reproduces a number. So nothing here asserts an equality with an empirical
//! figure; the assertions are about the *shape* of the disagreement and about
//! the trace reader being right.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::reach::validate::{self, Coverage, Layout, TraceError};

use super::fixtures::real_apps;

fn synthetic_trace(rows: &[(&str, &str, &str)], overflow: bool) -> String {
    let mut f = String::new();
    f.push_str("*version\n3\n");
    f.push_str(&format!("data-file-overflow={overflow}\n"));
    f.push_str("clock=dual\nelapsed-time-usec=6289722\nnum-method-calls=512758\n");
    f.push_str("*threads\n8654\tmain\n");
    f.push_str("*methods\n");
    for (i, (c, m, s)) in rows.iter().enumerate() {
        f.push_str(&format!("0x{i:x}\t{c}\t{m}\t{s}\tSrc.java\n"));
    }
    f.push_str("*end\nSLOW\0\0\0\0 binary noise that must not be read");
    f
}

#[test]
fn a_clean_trace_reads_to_the_distinct_count() {
    let f = synthetic_trace(
        &[
            ("android.app.Activity", "onCreate", "(Landroid/os/Bundle;)V"),
            ("android.app.Activity", "onCreate", "(Landroid/os/Bundle;)V"),
            ("java.lang.String", "valueOf", "(I)Ljava/lang/String;"),
        ],
        false,
    );
    let t = validate::parse_trace("t", f.as_bytes()).expect("parse");
    assert_eq!(t.layout, Layout::Batched);
    assert_eq!(t.coverage, Coverage::Exhaustive);
    assert_eq!(t.table_rows, 3);
    assert_eq!(
        t.distinct_all.len(),
        2,
        "the repeated row is a duplicate, not a second method"
    );
    assert_eq!(t.duplicates, 1);
    assert_eq!(t.rejected_total(), 0);
    assert!(t.accounting_ok());
    assert_eq!(t.distinct.len(), 2, "both are framework namespaces");
    assert_eq!(t.num_method_calls, Some(512758));
}

#[test]
fn the_accounting_is_closed_for_every_shape_of_row() {
    let f = synthetic_trace(
        &[
            ("android.app.Activity", "onCreate", "(Landroid/os/Bundle;)V"),
            ("not a class", "m", "()V"),
            ("a.b.C", "m", "not-a-descriptor"),
            ("a.b.C", "m", "()V"),
            ("too", "few", "extra-but-still-five"),
        ],
        false,
    );
    let t = validate::parse_trace("t", f.as_bytes()).expect("parse");
    assert_eq!(t.table_rows, 5);
    assert_eq!(t.duplicates, 0);
    assert_eq!(t.distinct_all.len(), 2);
    assert_eq!(
        t.rejected_total(),
        3,
        "rejections: {}",
        t.rejected
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    assert!(
        t.accounting_ok(),
        "table_rows must equal distinct + duplicates + rejected"
    );
}

#[test]
fn an_overflowed_trace_is_a_lower_bound_and_says_so() {
    let f = synthetic_trace(&[("android.app.Activity", "onCreate", "()V")], true);
    let t = validate::parse_trace("t", f.as_bytes()).expect("parse");
    assert_eq!(t.coverage, Coverage::Truncated);
    assert!(!t.coverage.is_exhaustive());
    assert!(t.coverage.as_str().contains("TRUNCATED"));
}

#[test]
fn a_failed_capture_is_refused_rather_than_read_as_an_empty_closure() {
    // trace/FINDINGS.md §8: a 0-byte trace once read as a run with no
    // framework calls. An empty method set that then scores as a perfect
    // match against an empty closure is the same error.
    assert_eq!(validate::parse_trace("empty", b""), Err(TraceError::Empty));
    // And the Jaccard of two empty sets is reported as undefined, not 1.0.
    let f = synthetic_trace(&[("android.app.Activity", "onCreate", "()V")], false);
    let t = validate::parse_trace("t", f.as_bytes()).expect("parse");
    assert_eq!(t.distinct.len(), 1);
}

#[test]
fn a_real_committed_fixture_manifest_names_the_same_components_the_entry_rules_expect() {
    // The fixtures are DEX extracts, not APKs, so this asserts the weaker but
    // still load-bearing property: a real manifest's component set is
    // reproducible and every name expands to a descriptor.
    for app in real_apps() {
        let a = crate::reach::entry::Manifest::parse(app.axml).expect("parse");
        let b = crate::reach::entry::Manifest::parse(app.axml).expect("parse");
        assert_eq!(
            a.components, b.components,
            "{}: parsing must be deterministic",
            app.name
        );
        for c in &a.components {
            assert!(c.descriptor.starts_with('L') && c.descriptor.ends_with(';'));
            assert!(
                !c.name.starts_with('.'),
                "{}: a relative name must be expanded",
                app.name
            );
        }
    }
}

#[test]
fn validation_reports_the_difference_rather_than_hiding_it() {
    // Build a real closure, then validate it against a trace that names one
    // method it cannot possibly contain. The report must say so in both
    // directions and must not claim to be an over-approximation.
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let mut p = crate::reach::model::Program::build(vec![crate::reach::model::DexInput::new(
        "classes.dex",
        crate::reach::model::UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = crate::reach::entry::Manifest::parse(app.axml).expect("parse");
    let config = crate::reach::Config {
        framework: crate::reach::FrameworkSource::Follow,
        entry: crate::reach::entry::EntryPolicy::ColdStart,
        max_rounds: 64,
        ..crate::reach::Config::default()
    };
    let entry = crate::reach::entry::entry_points(&p, &manifest, config.entry, false);
    let a = crate::reach::Analyzer::new(&mut p, config);
    let closure = a.run(&entry);

    let trace_bytes = synthetic_trace(
        &[
            ("android.app.Activity", "onCreate", "(Landroid/os/Bundle;)V"),
            (
                "android.widget.TextView",
                "nonexistentMethodNeverCalled",
                "()V",
            ),
        ],
        false,
    );
    let trace = validate::parse_trace("synthetic", trace_bytes.as_bytes()).expect("parse");
    let v = validate::validate_against_trace(&p, &closure, &trace, "test closure");
    assert!(
        !v.is_over_approximation(),
        "a traced method the closure lacks must fail the check"
    );
    assert!(v
        .missing
        .iter()
        .any(|m| m.contains("nonexistentMethodNeverCalled")));
    assert!(
        v.ratio.is_finite(),
        "a non-empty trace gives a finite ratio"
    );
    assert_eq!(v.trace_classes, 2);
    let md = v.render();
    assert!(
        v.verdict().contains("NOT an over-approximation"),
        "the verdict must name the failure: {}",
        v.verdict()
    );
    assert!(
        md.contains("absent from the static closure"),
        "the render must say which direction the disagreement runs"
    );
    assert!(
        md.contains("Reflection"),
        "the render must name reflection as the first cause to rule out"
    );
    assert!(v.verdict().contains("traced methods missing"));
}

#[test]
fn validation_of_a_closure_against_an_empty_trace_is_undefined_not_perfect() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let mut p = crate::reach::model::Program::build(vec![crate::reach::model::DexInput::new(
        "classes.dex",
        crate::reach::model::UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = crate::reach::entry::Manifest::parse(app.axml).expect("parse");
    let config = crate::reach::Config {
        framework: crate::reach::FrameworkSource::Follow,
        entry: crate::reach::entry::EntryPolicy::ColdStart,
        max_rounds: 64,
        ..crate::reach::Config::default()
    };
    let entry = crate::reach::entry::entry_points(&p, &manifest, config.entry, false);
    let a = crate::reach::Analyzer::new(&mut p, config);
    let closure = a.run(&entry);
    let trace_bytes = synthetic_trace(&[("zzz.not.framework", "m", "()V")], false);
    let trace = validate::parse_trace("emptyish", trace_bytes.as_bytes()).expect("parse");
    assert_eq!(trace.distinct.len(), 0, "zzz is not a framework namespace");
    let v = validate::validate_against_trace(&p, &closure, &trace, "test");
    assert_eq!(v.trace_methods, 0);
    // A zero-denominator Jaccard must be `None`, never 1.0: an empty set
    // compared with an empty set is not a perfect match, it is no evidence.
    assert_eq!(v.jaccard, None);
}

#[test]
fn the_policy_grid_names_each_cell_rather_than_applying_it_anonymously() {
    let grid = validate::default_grid();
    assert!(grid.len() >= 4, "the report needs a range, not a point");
    for (name, c) in &grid {
        assert!(!name.is_empty());
        assert!(!c.dispatch.as_str().is_empty());
    }
    let names: Vec<&str> = grid.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.iter().any(|n| n.starts_with("RTA")));
    assert!(names.iter().any(|n| n.starts_with("CHA")));
    assert!(names.iter().any(|n| n.contains("black-box")));
    assert!(names.iter().any(|n| n.contains("IR.md entry")));
}
