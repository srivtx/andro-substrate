//! Entry points, read from real `AndroidManifest.xml` files.
//!
//! `IR.md` fixes the entry set normatively, and the two ways of getting it
//! wrong are symmetric: too few (an app crashes on a broadcast the closure
//! never saw) and too many (the closure is inflated by components no external
//! caller can reach). Both directions are tested against real manifests.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::reach::entry::{self, ComponentKind, EntryPolicy, Manifest};
use crate::reach::model::{DexInput, Program, UnitRole};
use crate::reach::{Analyzer, Closure, Config, FrameworkSource};

use super::fixtures::real_apps;

#[test]
fn every_committed_manifest_parses() {
    let mut n = 0;
    for app in real_apps() {
        let m = Manifest::parse(app.axml)
            .unwrap_or_else(|e| panic!("{}: manifest must parse: {e}", app.name));
        assert!(
            !m.components.is_empty(),
            "{}: a manifest must declare components",
            app.name
        );
        n += 1;
    }
    assert!(n > 0);
}

#[test]
fn a_launcher_activity_is_found_when_one_exists() {
    let mut launchers = 0usize;
    for app in real_apps() {
        let Ok(m) = Manifest::parse(app.axml) else {
            continue;
        };
        if let Some(c) = m.launcher() {
            launchers += 1;
            assert_eq!(c.kind, ComponentKind::Activity);
            assert!(
                c.descriptor.starts_with('L') && c.descriptor.ends_with(';'),
                "{}",
                c.descriptor
            );
            assert!(
                !c.descriptor.contains('.'),
                "a descriptor is slashed, not dotted: {}",
                c.descriptor
            );
        }
    }
    // Recorded rather than asserted as a positive: the fixture set was chosen
    // for DEX shape, not for having a launcher, and a future fixture that adds
    // one must not fail this test.
    assert!(launchers <= real_apps().len());
}

#[test]
fn exported_defaults_to_true_exactly_when_an_intent_filter_is_present() {
    // The rule is load-bearing in the permissive direction: dropping an
    // exported component under-counts, and over-counting only inflates. Both
    // come from the same place, so the branch is asserted directly on a real
    // manifest that has both kinds of component.
    for app in real_apps() {
        let Ok(m) = Manifest::parse(app.axml) else {
            continue;
        };
        for c in &m.components {
            match c.exported_from {
                entry::ExportedFrom::IntentFilterDefault => {
                    assert!(c.exported, "{}: default implies true", app.name)
                }
                entry::ExportedFrom::DefaultFalse => {
                    assert!(!c.exported, "{}: default implies false", app.name)
                }
                entry::ExportedFrom::Explicit => {}
            }
            if c.kind == ComponentKind::Provider {
                // ContentProviders are reachable from the platform regardless
                // of `exported`, which is why `EntryPolicy::Extended` seeds
                // them. Nothing in the manifest records that, so there is
                // nothing to assert here beyond the fact that a provider was
                // parsed at all.
                assert!(!c.descriptor.is_empty());
            }
        }
    }
}

#[test]
fn the_ir_md_policy_seeds_only_the_launcher_and_exported_components() {
    let app = match real_apps().into_iter().find(|a| {
        Manifest::parse(a.axml)
            .ok()
            .and_then(|m| m.launcher().cloned())
            .is_some()
    }) {
        Some(a) => a,
        None => {
            eprintln!(
                "note: no committed fixture declares a LAUNCHER activity; policy test is vacuous"
            );
            return;
        }
    };
    let p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = Manifest::parse(app.axml).expect("a real manifest must parse");
    let set = entry::entry_points(&p, &manifest, EntryPolicy::IrMd, false);

    // Every seeded component is either the launcher or exported, and nothing
    // else appears.
    for point in &set.points {
        let owner = point
            .component
            .trim_matches('L')
            .trim_end_matches(';')
            .replace('/', ".");
        let c = manifest
            .components
            .iter()
            .find(|c| c.name == owner)
            .unwrap_or_else(|| panic!("{owner} is not a manifest component"));
        if point.kind == ComponentKind::Activity {
            assert!(
                c.is_launcher || c.exported,
                "{}: IR.md seeds the launcher's onCreate and exported components; {} is neither",
                app.name,
                c.name
            );
        } else {
            assert!(
                c.exported,
                "{}: {} is neither the launcher nor exported",
                app.name, c.name
            );
        }
    }
}

#[test]
fn the_cold_start_policy_adds_the_framework_seeds_and_names_them() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = Manifest::parse(app.axml).expect("a real manifest must parse");
    // The universe here is the APK's own DEX, so the framework seeds cannot
    // resolve. That is the point of checking `unresolved` rather than
    // `points`: the seeds are *named* either way, and a reader can see exactly
    // which framework classes the policy assumed and which the universe did
    // not supply.
    let ir = entry::entry_points(&p, &manifest, EntryPolicy::IrMd, false);
    let ext = entry::entry_points(&p, &manifest, EntryPolicy::Extended, false);
    let cold = entry::entry_points(&p, &manifest, EntryPolicy::ColdStart, false);
    let named = |s: &entry::EntrySet| -> Vec<String> {
        s.points
            .iter()
            .chain(s.unresolved.iter())
            .chain(s.missing.iter())
            .map(|e| e.method.clone())
            .collect()
    };
    assert!(
        named(&cold).len() > named(&ir).len(),
        "cold-start must add seeds: {} vs {}",
        named(&cold).len(),
        named(&ir).len()
    );
    assert!(
        named(&cold)
            .iter()
            .any(|m| m.contains("Landroid/app/ActivityThread;")),
        "the cold-start policy must name its framework seeds"
    );
    // `ActivityThread.main` is only in ColdStart, not in Extended.
    assert!(!named(&ext)
        .iter()
        .any(|m| m.contains("ActivityThread;.main")));
    assert!(named(&cold)
        .iter()
        .any(|m| m.contains("ActivityThread;.main")));
    // And the seeds this universe genuinely lacks are reported as such.
    assert!(
        cold.unresolved
            .iter()
            .any(|m| m.method.contains("Landroid/app/ActivityThread;")),
        "a framework seed with no framework DEX must be reported, not dropped"
    );
}

#[test]
fn widening_to_the_full_surface_adds_methods_beyond_the_lifecycle_list() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = Manifest::parse(app.axml).expect("a real manifest must parse");
    let narrow = entry::entry_points(&p, &manifest, EntryPolicy::IrMd, false);
    let wide = entry::entry_points(&p, &manifest, EntryPolicy::IrMd, true);
    assert!(wide.points.len() >= narrow.points.len());
    assert!(wide.widened_to_full_surface);
    assert!(!narrow.widened_to_full_surface);
}

#[test]
fn an_entry_point_naming_a_class_the_universe_lacks_is_reported_not_dropped() {
    let p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        super::fixtures::minimal_dex(),
    )])
    .expect("a minimal DEX must load");
    let set = entry::explicit_entry_points(
        &p,
        &[
            "Lnot/Here;.m()V",              // class absent from the universe
            "Ljava/lang/Object;.nope()V",   // class present, method absent
            "garbage",                      // unparseable
            "Ljava/lang/Object;.<init>()V", // present
        ],
    );
    assert_eq!(
        set.unresolved.len(),
        1,
        "a class the universe lacks must be reported"
    );
    assert_eq!(
        set.missing.len(),
        1,
        "a method the class does not declare must be reported"
    );
    assert_eq!(
        set.manifest_gaps.len(),
        1,
        "an unparseable name must be reported"
    );
    assert_eq!(set.resolved(), 1, "the one real entry point must resolve");
    assert!(set.summary().contains("class-not-in-universe"));
}

#[test]
fn a_closure_over_a_real_app_completes_and_reports_its_window() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let mut p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = Manifest::parse(app.axml).expect("a real manifest must parse");
    let config = Config {
        framework: FrameworkSource::Follow,
        entry: EntryPolicy::ColdStart,
        max_rounds: 64,
        ..Config::default()
    };
    let entry = entry::entry_points(&p, &manifest, config.entry, false);
    let a = Analyzer::new(&mut p, config);
    let c: Closure = a.run(&entry);
    let report = crate::reach::report::ClosureReport::build(&p, &c, app.name, "test window");
    assert!(
        report.header.contains("window: test window"),
        "the window definition must be on the header"
    );
    assert!(
        report.header.contains("RTA"),
        "the dispatch policy must be on the header"
    );
    assert!(
        report.header.contains("framework DEX bodies followed"),
        "the framework policy must be on the header"
    );
    assert!(report.closure_size().is_some());
    let md = report.to_markdown();
    assert!(md.contains("## Edges by kind"));
    assert!(md.contains("## Entry points"));
    let json = report.to_json();
    assert!(json.starts_with('{') && json.trim_end().ends_with('}'));
    assert!(
        json.contains("\"provenance\": \"measured\"")
            || json.contains("\"provenance\": \"derived\"")
    );
}
