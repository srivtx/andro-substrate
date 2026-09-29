//! The supersede rule, proven unchanged under multidex.
//!
//! `docs/decisions/0005-shim-and-observation.md` §2 fixes the classloader
//! boundary: **supersede, not merge**. The shim's classes resolve ahead of the
//! app's, so a hostile APK that declares its own `Landroid/app/Activity;` gets
//! it shadowed and the observation layer keeps working. That is a security
//! property, and it is not this component's to change.
//!
//! What this component adds is the question the shim *delegates*: given an app's
//! N files, which of them defines what. The risk this suite guards is that
//! adding per-file resolution quietly changes the shim-versus-app decision —
//! for instance by making "the app defines it, in `classes2.dex`" look
//! different from "the app defines it, in `classes.dex`". It must not, because
//! a shim that lost to an app class in a later file would be a regression in
//! the one property ADR 0005 calls a security boundary.

mod common;

use common::{sayura_sources, secondary, Body, Klass, Meth};
use shim::classes::{AppDex, ClassLoader};
use shim::event::Resolution;
use substrate_runtime::multidex::{FileId, MultidexLoader, MultidexWarning};

/// The baseline: a single-DEX app that declares a framework class is shadowed.
#[test]
fn a_single_dex_app_is_shadowed_by_the_shim() {
    let app = Klass::new("Landroid/app/Activity;").with(Meth::concrete(
        "onCreate",
        "V",
        Body::ReturnVoid,
    ));
    let loader =
        MultidexLoader::load_named(Some("com.example.app".into()), vec![common::primary1(&app)])
            .unwrap();

    let cl = ClassLoader::new(
        vec!["Landroid/app/Activity;".to_string()],
        loader.shim_view(),
    );
    assert_eq!(
        cl.resolve("Landroid/app/Activity;"),
        (
            Resolution::ShimSupersedesApp,
            Some("com.example.app".to_string())
        ),
        "the collision is attributed to the app package, not to a file"
    );
    assert_eq!(cl.collisions(), vec!["Landroid/app/Activity;".to_string()]);
}

/// The multidex version of the same property, and the case that could plausibly
/// have broken it: the colliding app class lives in `classes2.dex`, not
/// `classes.dex`. A loader that consulted only the primary file would not see
/// the collision at all and would report a plain `ShimDex`; one that let a later
/// file's presence change the precedence would report something else. The shim
/// must win either way, and the collision must still be visible.
#[test]
fn an_app_class_in_a_secondary_file_is_still_shadowed() {
    // classes.dex: a harmless app class. classes2.dex: the collision.
    let primary_klass = Klass::new("La/App;").with(Meth::concrete("run", "V", Body::ReturnVoid));
    let hostile =
        Klass::new("Landroid/app/Activity;").with(Meth::concrete("pwn", "V", Body::ReturnVoid));
    let loader = MultidexLoader::load_named(
        Some("com.example.hostile".into()),
        vec![
            common::primary1(&primary_klass),
            common::secondary1(2, &hostile),
        ],
    )
    .unwrap();

    // The multidex layer does find the hostile class, in file 2.
    let r = substrate_runtime::multidex::Resolver::new(&loader);
    let res = r
        .resolve_class("Landroid/app/Activity;")
        .expect("the app does define it");
    assert_eq!(res.primary.file, FileId(1));
    assert_eq!(res.primary.name, "classes2.dex");

    // The hand-off to the shim flattens across all files, so the shim's loader
    // sees the collision and still wins.
    let view = loader.shim_view();
    assert!(
        view.classes.contains(&"Landroid/app/Activity;".to_string()),
        "the shim must be told about the collision in classes2.dex"
    );
    assert!(view.classes.contains(&"La/App;".to_string()));

    let cl = ClassLoader::new(vec!["Landroid/app/Activity;".to_string()], view);
    assert_eq!(
        cl.resolve("Landroid/app/Activity;"),
        (
            Resolution::ShimSupersedesApp,
            Some("com.example.hostile".to_string())
        ),
        "the shim must win regardless of which app file declared the class"
    );
    assert_eq!(cl.collisions(), vec!["Landroid/app/Activity;".to_string()]);
}

/// Precedence is identical whichever file the class came from: the decision is
/// made on the shim-versus-app axis, not on a per-file axis.
#[test]
fn precedence_does_not_depend_on_which_file_declared_the_class() {
    let hostile =
        || Klass::new("Landroid/app/Activity;").with(Meth::concrete("pwn", "V", Body::ReturnVoid));
    let benign = || Klass::new("La/Benign;");

    // Collision in classes.dex.
    let in_first = MultidexLoader::load_named(
        Some("com.example.p".into()),
        vec![common::primary(&[hostile()]), secondary(2, &[benign()])],
    )
    .unwrap();
    // Collision in classes.dex of a three-file APK.
    let in_first_of_three = MultidexLoader::load_named(
        Some("com.example.p".into()),
        vec![
            common::primary(&[hostile()]),
            secondary(2, &[benign()]),
            secondary(3, &[Klass::new("La/Third;")]),
        ],
    )
    .unwrap();
    // Collision in classes2.dex.
    let in_second = MultidexLoader::load_named(
        Some("com.example.p".into()),
        vec![common::primary(&[benign()]), secondary(2, &[hostile()])],
    )
    .unwrap();
    // Collision in classes3.dex of three.
    let in_third = MultidexLoader::load_named(
        Some("com.example.p".into()),
        vec![
            common::primary(&[benign()]),
            secondary(2, &[Klass::new("La/Second;")]),
            secondary(3, &[hostile()]),
        ],
    )
    .unwrap();

    for (label, loader) in [
        ("classes.dex of 2", in_first),
        ("classes.dex of 3", in_first_of_three),
        ("classes2.dex of 2", in_second),
        ("classes3.dex of 3", in_third),
    ] {
        let cl = ClassLoader::new(
            vec!["Landroid/app/Activity;".to_string()],
            loader.shim_view(),
        );
        assert_eq!(
            cl.resolve("Landroid/app/Activity;"),
            (
                Resolution::ShimSupersedesApp,
                Some("com.example.p".to_string())
            ),
            "collision in {label} must still be shadowed"
        );
        assert_eq!(
            cl.collisions(),
            vec!["Landroid/app/Activity;"],
            "collision in {label}"
        );
    }
}

/// A class the shim does *not* provide still resolves to the app's, whichever
/// file holds it. Supersede is about precedence, not about the shim claiming
/// everything.
#[test]
fn an_app_only_class_resolves_to_the_app_from_either_file() {
    let loader = MultidexLoader::load_named(
        Some("com.example.app".into()),
        vec![
            common::primary(&[Klass::new("La/FromOne;").with(Meth::concrete(
                "m",
                "V",
                Body::ReturnVoid,
            ))]),
            secondary(
                2,
                &[Klass::new("La/FromTwo;").with(Meth::concrete("n", "V", Body::ReturnVoid))],
            ),
        ],
    )
    .unwrap();

    let view = loader.shim_view();
    let cl = ClassLoader::new(vec!["Landroid/app/Activity;".to_string()], view);
    for c in ["La/FromOne;", "La/FromTwo;"] {
        assert_eq!(
            cl.resolve(c),
            (Resolution::AppDex, Some("com.example.app".to_string())),
            "{c} must resolve to the app, attributed to the package"
        );
    }
}

/// A framework class the app never declares is `Unresolvable` through the shim,
/// even though the multidex layer has an opinion about it: neither layer may
/// invent an answer for a class neither has.
#[test]
fn a_class_neither_layer_defines_stays_unresolvable() {
    let loader = MultidexLoader::load(vec![common::primary(&[Klass::new("La/Only;")])]).unwrap();
    assert!(!loader
        .shim_view()
        .classes
        .contains(&"Landroid/widget/Button;".to_string()));
    let cl = ClassLoader::new(
        vec!["Landroid/app/Activity;".to_string()],
        loader.shim_view(),
    );
    assert_eq!(
        cl.resolve("Landroid/widget/Button;").0,
        Resolution::Unresolvable
    );
}

/// The real multidex fixture hands off cleanly: all 106 class descriptors across
/// both files reach the shim, deduplicated, and the shim resolves against them.
#[test]
fn the_real_fixture_hands_off_every_class_to_the_shim() {
    let loader = MultidexLoader::load_named(
        Some("org.fcitx.fcitx5.android.plugin.sayura".into()),
        sayura_sources(),
    )
    .unwrap();
    let view: AppDex = loader.shim_view();
    assert_eq!(
        view.classes.len(),
        106,
        "101 in classes.dex plus 5 in classes2.dex"
    );
    // Sorted and deduplicated, which is what `ClassLoader` requires of an
    // `AppDex` and what makes a duplicate declaration invisible to it.
    let mut sorted = view.classes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted, view.classes,
        "the hand-off must be sorted and deduplicated"
    );

    assert_eq!(view.package, "org.fcitx.fcitx5.android.plugin.sayura");
    let cl = ClassLoader::new(vec!["Ljava/lang/String;".to_string()], view);
    // The shim provides String, so it wins; nothing in this fixture collides.
    assert_eq!(cl.resolve("Ljava/lang/String;").0, Resolution::ShimDex);
    assert!(
        cl.collisions().is_empty(),
        "a well-formed APK declares no framework classes"
    );
}

/// Duplicate-class warnings reach the shim's event stream, so the
/// first-wins decision is in the recording rather than only in a log.
#[test]
fn duplicate_warnings_reach_the_recording_as_events() {
    let dup = Klass::new("La/Dup;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let hostile = Klass::new("Landroid/app/Activity;");
    let loader = MultidexLoader::load(vec![
        common::primary(&[dup.clone(), hostile.clone()]),
        secondary(2, &[dup, hostile]),
    ])
    .unwrap();

    let events = loader.warning_events(0);
    assert!(!events.is_empty());

    let dupes: Vec<_> = events
        .iter()
        .filter(|e| e.summary().contains("MULTIDEX.DUPLICATE_CLASS"))
        .collect();
    // Both `La/Dup;` and `Landroid/app/Activity;` are declared twice, so each
    // gets a `DUPLICATE_CLASS` event. Two more events are expected and are not
    // errors: the synthetic builder emits `Ljava/lang/Object;` into both files,
    // and `La/Dup;.m` is also a `DUPLICATE_METHOD`. Filtering by pattern *and*
    // descriptor keeps this assertion about the two it names.
    let named: Vec<String> = events
        .iter()
        .map(|e| e.summary())
        .filter(|s| {
            s.contains("MULTIDEX.DUPLICATE_CLASS")
                && (s.contains("La/Dup;") || s.contains("Landroid/app/Activity;"))
        })
        .collect();
    assert_eq!(
        named.len(),
        2,
        "one DUPLICATE_CLASS event per duplicated descriptor"
    );
    for e in &dupes {
        assert_eq!(e.group, shim::event::Group::Probes);
        assert_eq!(e.source, shim::event::Source::ClassLoader);
        assert_eq!(e.tier, shim::event::Tier::T0Direct);
        assert!(
            e.assumption.is_none(),
            "a structural fact is not an assumption probe"
        );
    }

    // The event text names both files, which `Detail::Classes` could not carry.
    let activity_event = dupes
        .iter()
        .find(|e| e.summary().contains("Landroid/app/Activity;"))
        .expect("the framework collision must be recorded");
    assert!(activity_event.summary().contains("classes.dex"));
    assert!(activity_event.summary().contains("classes2.dex"));
}

/// `seq` is contiguous and deterministic, so two runs of one APK produce
/// identical event sequences and a recording can be diffed.
#[test]
fn warning_event_sequences_are_deterministic() {
    let dup = Klass::new("La/Dup;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let sources = || vec![common::primary1(&dup), common::secondary1(2, &dup)];
    let a = MultidexLoader::load(sources()).unwrap();
    let b = MultidexLoader::load(sources()).unwrap();

    let ea = a.warning_events(0);
    let eb = b.warning_events(0);
    assert_eq!(ea.len(), eb.len());
    for (i, (x, y)) in ea.iter().zip(eb.iter()).enumerate() {
        assert_eq!(x.seq, i as u64);
        assert_eq!(x.seq, y.seq);
        assert_eq!(x.summary(), y.summary());
    }
    // A non-zero start offset is honoured, so this composes with other event
    // producers on the same sequence line.
    assert_eq!(a.warning_events(100)[0].seq, 100);
}

/// Every warning kind maps to a distinct diagnostic pattern, so a recording can
/// be filtered by concern.
#[test]
fn every_warning_kind_has_a_distinct_probe_pattern() {
    let dup = Klass::new("La/Dup;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let divergent =
        Klass::new("La/D;")
            .extending("La/B1;")
            .with(Meth::concrete("m", "V", Body::ReturnVoid));
    let divergent2 =
        Klass::new("La/D;")
            .extending("La/B2;")
            .with(Meth::concrete("n", "V", Body::ReturnVoid));
    let loader = MultidexLoader::load(vec![
        common::primary(&[dup.clone(), divergent]),
        secondary(2, &[dup, divergent2]),
    ])
    .unwrap();
    // The mapping from warning *kind* to pattern must be injective, so a
    // recording can be filtered by concern. Repeats are expected and fine: one
    // event is emitted per occurrence, not per kind.
    let mut by_kind: Vec<(&str, &str)> = loader
        .warnings()
        .iter()
        .map(|w| (w.kind(), w.probe_pattern()))
        .collect();
    by_kind.sort_unstable();
    by_kind.dedup();
    let kinds: std::collections::BTreeSet<&str> = by_kind.iter().map(|(k, _)| *k).collect();
    let patterns: std::collections::BTreeSet<&str> = by_kind.iter().map(|(_, p)| *p).collect();
    assert_eq!(
        kinds.len(),
        patterns.len(),
        "two kinds must not share a pattern: {by_kind:?}"
    );
    assert!(patterns.iter().any(|p| p.contains("DUPLICATE_CLASS")));
    assert!(patterns
        .iter()
        .any(|p| p.contains("DIVERGENT_CLASS_HEADER")));
    assert!(patterns.iter().any(|p| p.contains("UNRESOLVED_SUPERCLASS")));
    // Superclass facts are warnings too, so they appear in the record.
    assert!(loader
        .warnings()
        .iter()
        .any(|w| matches!(w, MultidexWarning::UnresolvedSuperclass { .. })));
}
