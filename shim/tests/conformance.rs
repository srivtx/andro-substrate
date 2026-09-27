//! Conformance: how much of the real `android.*` surface does the shim cover,
//! and does `CONFORMANCE.md` still say so?
//!
//! # The measurement
//!
//! Coverage is measured against the set of `android.*` and `java.*` types the
//! **real** DEX fixtures in `tools/dexcore/tests/fixtures/` actually reference.
//! Not against `android.jar` (a number nobody could act on) and not against a
//! hand-written wish list. A real, tiny, F-Droid-published corpus is the right
//! denominator for "will this shim run anything", and it is already committed, so
//! no APK is downloaded.
//!
//! This test also emits the numbers, so a reader who wants to recompute them does
//! not have to take `CONFORMANCE.md`'s word for anything.

use std::collections::BTreeSet;

use shim::registry::{self, Behaviour};

/// A real fixture, embedded from `tools/dexcore/tests/fixtures/`.
const DEXES: &[(&str, &[u8])] = &[
    (
        "pro.rudloff.search_to_browser_2",
        include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex"),
    ),
    (
        "org.vi_server.red_screen_3",
        include_bytes!("../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex"),
    ),
    (
        "com.android.adbkeyboard_2",
        include_bytes!("../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex"),
    ),
    (
        "com.oF2pks.neolinker_7",
        include_bytes!("../../tools/dexcore/tests/fixtures/com.oF2pks.neolinker_7.dex"),
    ),
    (
        "com.termux.boot_1000",
        include_bytes!("../../tools/dexcore/tests/fixtures/com.termux.boot_1000.dex"),
    ),
    (
        "fr.smarquis.sleeptimer_16200",
        include_bytes!("../../tools/dexcore/tests/fixtures/fr.smarquis.sleeptimer_16200.dex"),
    ),
];

/// The `android.*` and `java.*` types the corpus references, and how many
/// fixtures reference each.
fn reference_set() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, bytes) in DEXES {
        let d = dexcore::DexReader::open(bytes).expect("fixture parses");
        for i in 0..d.type_count() {
            if let Ok(t) = d.type_at(i) {
                if shim::classes::is_framework_namespace(&t.descriptor) {
                    out.insert(t.descriptor);
                }
            }
        }
    }
    out
}

#[test]
fn report_the_measured_coverage() {
    let all = reference_set();
    let covered: BTreeSet<&String> = all.iter().filter(|c| registry::find(c).is_some()).collect();
    let android_total = all.iter().filter(|c| c.starts_with("Landroid/")).count();
    let android_covered = covered.iter().filter(|c| c.starts_with("Landroid/")).count();
    let java_total = all.len() - android_total;
    let java_covered = covered.len() - android_covered;

    println!("CORPORA: {} DEX fixtures, all from F-Droid", DEXES.len());
    println!(
        "TYPES:   android.* referenced {} / covered {} ({:.1}%)",
        android_total,
        android_covered,
        pct(android_covered, android_total)
    );
    println!(
        "         java.*    referenced {} / covered {} ({:.1}%)",
        java_total,
        java_covered,
        pct(java_covered, java_total)
    );
    println!(
        "TOTAL:   referenced {} / covered {} ({:.1}%)",
        all.len(),
        covered.len(),
        pct(covered.len(), all.len())
    );
    println!("SHIM:    {} classes, {} methods, {} fields", registry::class_count(), registry::method_count(), registry::field_count());
    for (k, v) in shim::emit::behaviour_counts() {
        println!("         {k}: {v}");
    }
    println!("MISSING (referenced by the corpus, absent from the shim):");
    for c in all.iter().filter(|c| registry::find(c).is_none()) {
        println!("         {c}");
    }

    // Floor, so a coverage regression is a test failure and not a paragraph in a
    // document that nobody re-reads. The measured value is far above it.
    assert!(covered.len() * 2 >= all.len(), "coverage has fallen below half");
}

fn pct(a: usize, b: usize) -> f64 {
    if b == 0 {
        0.0
    } else {
        100.0 * a as f64 / b as f64
    }
}

/// The method references the corpus makes, and how many the shim implements.
fn method_coverage() -> (usize, usize) {
    let mut all: BTreeSet<(String, String, String, String)> = BTreeSet::new();
    for (_, bytes) in DEXES {
        let d = dexcore::DexReader::open(bytes).expect("fixture parses");
        for i in 0..d.method_count() {
            if let Ok(m) = d.method_at(i) {
                if shim::classes::is_framework_namespace(&m.class) {
                    all.insert((m.class.clone(), m.name.clone(), m.parameters.join(""), m.return_type.clone()));
                }
            }
        }
    }
    let covered = all
        .iter()
        .filter(|(c, n, p, r)| {
            registry::signatures(c, n)
                .iter()
                .any(|(dp, dr)| dp.join("") == *p && *dr == *r)
        })
        .count();
    (all.len(), covered)
}

#[test]
fn method_coverage_is_measured_and_floored() {
    let (referenced, covered) = method_coverage();
    println!(
        "METHODS referenced {referenced} covered {covered} ({:.1}%)",
        100.0 * covered as f64 / referenced as f64
    );
    assert!(referenced > 150, "the corpus should reference a real number of methods");
    // The floor is a fifth, well below the measured value, and exists so a
    // coverage *regression* is a test failure rather than a paragraph nobody
    // re-reads.
    assert!(
        covered * 5 >= referenced,
        "method coverage has fallen below a fifth: {covered}/{referenced}"
    );
}

#[test]
fn conformance_md_agrees_with_the_table() {
    // `CONFORMANCE.md` is a claim about the code. This makes it a claim the code
    // checks: every descriptor and every method in the registry must appear in the
    // document, and the headline numbers must match what the corpus measurement
    // above produces.
    let doc = include_str!("../CONFORMANCE.md");
    let mut missing: Vec<String> = Vec::new();
    for c in registry::CLASSES {
        if !doc.contains(c.descriptor) {
            missing.push(c.descriptor.to_string());
        }
        for m in c.methods() {
            if !doc.contains(m.name) {
                missing.push(format!("{}.{}", c.descriptor, m.name));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "CONFORMANCE.md does not mention: {missing:?}. The document is the project's public \
claim about coverage, so it must be regenerated whenever the table changes."
    );

    // And the headline numbers.
    let all = reference_set();
    let covered = all.iter().filter(|c| registry::find(c).is_some()).count();
    let (m_ref, m_cov) = method_coverage();
    for (label, value) in [
        ("registry classes", registry::class_count()),
        ("registry methods", registry::method_count()),
        ("registry fields", registry::field_count()),
        ("referenced types", all.len()),
        ("covered types", covered),
        ("referenced methods", m_ref),
        ("covered methods", m_cov),
    ] {
        let needle = format!("{label} | {value}");
        assert!(
            doc.contains(&needle),
            "CONFORMANCE.md's `{label}` row does not read `{needle}`; regenerate the table"
        );
    }
}

#[test]
fn every_declared_static_method_is_really_static() {
    // Getting `static` wrong is not cosmetic: the dispatcher strips `args[0]` as
    // `this` for an instance method, so a static method marked as an instance one
    // silently loses its first argument. An app calling
    // `System.loadLibrary("foo")` would get "parameter 0 was not a string".
    //
    // The list below is transcribed from the Android API, not from the registry,
    // so it is an independent check rather than a restatement.
    const REAL_STATICS: &[(&str, &str)] = &[
        ("Ljava/lang/System;", "loadLibrary"),
        ("Ljava/lang/System;", "load"),
        ("Ljava/lang/System;", "currentTimeMillis"),
        ("Ljava/lang/System;", "getProperty"),
        ("Ljava/lang/Class;", "forName"),
        ("Ljava/lang/Thread;", "sleep"),
        ("Ljava/lang/Thread;", "currentThread"),
        ("Ljava/util/regex/Pattern;", "compile"),
        ("Landroid/util/Log;", "v"),
        ("Landroid/util/Log;", "d"),
        ("Landroid/util/Log;", "i"),
        ("Landroid/util/Log;", "w"),
        ("Landroid/util/Log;", "e"),
        ("Landroid/util/Log;", "println"),
        ("Landroid/util/Base64;", "encodeToString"),
        ("Landroid/os/Looper;", "getMainLooper"),
        ("Landroid/os/Looper;", "prepare"),
        ("Landroid/os/Looper;", "loop"),
        ("Landroid/os/Looper;", "quit"),
        ("Landroid/os/Parcel;", "obtain"),
        ("Landroid/os/SystemClock;", "uptimeMillis"),
        ("Landroid/os/SystemClock;", "elapsedRealtime"),
        ("Landroid/os/SystemClock;", "currentThreadTimeMillis"),
        ("Landroid/os/Environment;", "getExternalStorageDirectory"),
        ("Landroid/os/Environment;", "getExternalStorageState"),
        ("Landroid/view/LayoutInflater;", "from"),
        ("Landroid/widget/Toast;", "makeText"),
        ("Landroid/net/Uri;", "parse"),
        ("Landroid/text/TextUtils;", "isEmpty"),
    ];
    for (class, name) in REAL_STATICS {
        let m = registry::signatures(class, name);
        assert!(!m.is_empty(), "{class}.{name} is not in the shim");
        let c = registry::find(class).expect("class");
        let decl = c
            .methods()
            .find(|x| x.name == *name)
            .unwrap_or_else(|| panic!("{class}.{name}"));
        assert_eq!(
            decl.access_flags & dexcore::model::access::ACC_STATIC,
            dexcore::model::access::ACC_STATIC,
            "{class}.{name} must be ACC_STATIC"
        );
    }
}

#[test]
fn nothing_the_table_marks_observation_bearing_is_inert() {
    // A method the table calls a `Probe` or a `Dispatch` must be one the
    // dispatcher can actually reach. `tests/dex_roundtrip.rs` checks that
    // directly; this checks the *proportion*, because a table that is 90% `Inert`
    // would pass that test and be a worse instrument.
    let counts = shim::emit::behaviour_counts();
    let total: usize = counts.values().sum();
    let inert = counts.get("inert").copied().unwrap_or(0);
    let observation = counts.get("probe").copied().unwrap_or(0) + counts.get("dispatch").copied().unwrap_or(0);
    println!("behaviour counts: {counts:?}");
    assert!(total > 200, "the table should be substantial");
    assert!(
        observation * 2 > inert,
        "more than half the surface is Inert ({inert} of {total}); an instrument that answers \
without observing is a compatibility layer"
    );
}

#[test]
fn every_class_in_the_table_is_in_the_namespaces_it_claims() {
    // The supersede decision is decidable only because the boundary is
    // `Landroid/` + `Ljava/`. A class outside those namespaces would be resolved
    // by ordinary delegation, and a framework class inside them would shadow the
    // app's own — so both are worth asserting.
    for c in registry::CLASSES {
        let framework = shim::classes::is_framework_namespace(c.descriptor);
        assert!(
            framework,
            "{} is not in the framework namespace, so the supersede decision does not apply to \
it; either move it or document the exception",
            c.descriptor
        );
        // And a framework class the shim declares may not also be a `java.*`
        // class pretending to be `android.*`, or vice versa.
        if c.descriptor.starts_with("Landroid/") {
            assert!(
                c.superclass.map(shim::classes::is_framework_namespace).unwrap_or(true)
                    || s_is_java_lang_object(c.superclass),
                "{} has a superclass outside the framework namespace",
                c.descriptor
            );
        }
    }
}

fn s_is_java_lang_object(s: Option<&str>) -> bool {
    matches!(s, Some("Ljava/lang/Object;"))
}

#[test]
fn every_behaviour_variant_is_reachable_from_the_table() {
    // If a `Behaviour` variant is never used, the dispatcher arm for it is dead
    // code and this crate is carrying a branch it does not need.
    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for c in registry::CLASSES {
        for m in c.methods() {
            seen.insert(match m.behaviour {
                Behaviour::Init | Behaviour::Construct => "construct",
                Behaviour::Field { .. } => "field",
                Behaviour::Probe { .. } => "probe",
                Behaviour::Dispatch(_) => "dispatch",
                Behaviour::Inert => "inert",
            });
        }
    }
    assert_eq!(seen.len(), 5, "all five behaviours are used: {seen:?}");
}

#[test]
fn the_supersede_boundary_is_where_the_decision_says_it_is() {
    // The ADR claims supersede; this checks the code does what the ADR says.
    let mut app = vec![
        "Landroid/app/Activity;".to_string(),
        "Landroid/os/Build;".to_string(),
        "La/b/Main;".to_string(),
    ];
    app.sort();
    let l = shim::classes::ClassLoader::new(registry::descriptors(), shim::classes::AppDex {
        package: "a.b".to_string(),
        classes: app,
    });
    // The shim wins, every time.
    for c in ["Landroid/app/Activity;", "Landroid/os/Build;"] {
        assert_eq!(
            l.resolve(c).0,
            shim::event::Resolution::ShimSupersedesApp,
            "{c}"
        );
    }
    // A class only the app has is unaffected: supersede applies to the framework
    // namespaces, and an app's own `a.b.Main` is the app's.
    assert_eq!(
        l.resolve("La/b/Main;").0,
        shim::event::Resolution::AppDex
    );
    // A class nobody has is unresolvable, which is SUB.FW.CLASS_LOADER.
    assert_eq!(
        l.resolve("Lcom/google/gson/Gson;").0,
        shim::event::Resolution::Unresolvable
    );
    // And the collision set is exactly the framework classes the app shadowed.
    assert_eq!(
        l.collisions(),
        vec![
            "Landroid/app/Activity;".to_string(),
            "Landroid/os/Build;".to_string()
        ]
    );
}
