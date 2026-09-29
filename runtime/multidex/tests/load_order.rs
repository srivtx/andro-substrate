//! Load order, per-file index spaces, and the recorded load.
//!
//! The property under test throughout is the one the brief calls out: load
//! order is part of the contract, so it must be *explicit and recorded* rather
//! than implied by whatever order a directory or a hash map happened to yield.

mod common;

use std::path::PathBuf;

use common::{sayura_sources, secondary, Body, Klass, Meth};
use substrate_runtime::multidex::{
    parse_ordinal, DexSource, FileId, MultidexLoader, MultidexWarning,
};

/// `classes.dex` is ordinal 1 and `classes<N>.dex` is ordinal `N`.
#[test]
fn ordinals_parse_numerically_not_lexicographically() {
    assert_eq!(parse_ordinal("classes.dex"), Some(1));
    assert_eq!(parse_ordinal("classes2.dex"), Some(2));
    assert_eq!(parse_ordinal("classes10.dex"), Some(10));
    assert_eq!(parse_ordinal("classes13.dex"), Some(13));
}

/// Names a canonical Android loader would not load are rejected, not ignored.
#[test]
fn non_canonical_names_are_refused() {
    for name in [
        "Classes.dex",
        "classes1.dex",
        "classes0.dex",
        "classes03.dex",
        "classes.dex.bak",
        "dex/classes.dex",
        "foo.dex",
        "classes.dex2",
        "classes-.dex",
    ] {
        assert_eq!(parse_ordinal(name), None, "{name} must not be loadable");
    }
}

/// The trap the brief names: `classes10.dex` sorts *second* by name and *tenth*
/// by ordinal. Nine APKs in the F-Droid corpus store their entries in that
/// order, so a loader that sorted names would get those nine wrong.
///
/// Ten files are used because that is the smallest count where the trap bites:
/// with nine or fewer, no name contains a digit that sorts before `classes2`.
#[test]
fn ordinal_order_beats_lexicographic_order() {
    // Build 1..=10, then offer them in a deliberately hostile order.
    let mut sources: Vec<DexSource> = (2..=10)
        .rev()
        .map(|n| secondary(n, &[Klass::new(&format!("Lt/F{n};"))]))
        .collect();
    sources.push(DexSource::new(
        "classes.dex",
        common::build_dex(&[Klass::new("Lt/F1;")]),
    ));

    // Confirm the trap is real for this set: a name sort puts classes10 second.
    let mut by_name: Vec<String> = sources.iter().map(|s| s.name.clone()).collect();
    by_name.sort();
    assert_eq!(
        by_name[0..3],
        ["classes.dex", "classes10.dex", "classes2.dex"],
        "the lexicographic order really is wrong; otherwise this test proves nothing"
    );

    let loader = MultidexLoader::load(sources).expect("load must succeed");
    let names: Vec<&str> = loader.files().iter().map(|f| f.name.as_str()).collect();
    let expected: Vec<String> = std::iter::once("classes.dex".to_string())
        .chain((2..=10).map(|n| format!("classes{n}.dex")))
        .collect();
    assert_eq!(
        names,
        expected.iter().map(String::as_str).collect::<Vec<_>>()
    );

    // And the recorded order agrees, with the ordinal carried separately so a
    // reader can see that ordinal 10 really did load tenth.
    let ords: Vec<u32> = loader.record().order.iter().map(|e| e.ordinal).collect();
    assert_eq!(ords, (1..=10).collect::<Vec<u32>>());
    let ids: Vec<usize> = loader.record().order.iter().map(|e| e.file.0).collect();
    assert_eq!(ids, (0..10).collect::<Vec<usize>>());
}

/// The ordinals must be the gapless run `1..=N`, because a gap means the
/// container is malformed and loading past it would invent an order the build
/// never expressed. Android's own loader stops at the first gap.
#[test]
fn a_gap_in_the_ordinals_is_refused() {
    let sources = vec![
        DexSource::new("classes.dex", common::build_dex(&[Klass::new("Lt/One;")])),
        secondary(2, &[Klass::new("Lt/Two;")]),
        secondary(10, &[Klass::new("Lt/Ten;")]),
    ];
    let err = MultidexLoader::load(sources).expect_err("a gap must be refused");
    assert_eq!(err.kind(), "NonContiguousLoad");
    assert_eq!(
        err.to_string(),
        "load-order ordinal 3 is missing; present ordinals are [1, 2, 10]"
    );
}

/// The central fact of the whole component, asserted against real bytes.
#[test]
fn pool_indices_are_per_file() {
    let loader = MultidexLoader::load(sayura_sources()).expect("fixtures must load");
    assert_eq!(loader.file_count(), 2);

    let [f0, f1] = [FileId(0), FileId(1)];
    let r0 = loader.reader(f0).unwrap();
    let r1 = loader.reader(f1).unwrap();

    // The two files' pools are genuinely different sizes...
    assert_eq!(loader.files()[0].strings, 725);
    assert_eq!(loader.files()[1].strings, 89);
    assert_eq!(loader.files()[0].methods, 498);
    assert_eq!(loader.files()[1].methods, 38);

    // ...and method_id[0] names two completely unrelated methods. This is the
    // concrete reason indices cannot cross files, taken from a real APK.
    let m0 = r0.method_at(0).unwrap();
    let m1 = r1.method_at(0).unwrap();
    assert_eq!(
        (m0.class.as_str(), m0.name.as_str()),
        ("Landroid/app/ActionBar;", "setDisplayHomeAsUpEnabled")
    );
    assert_eq!(
        (m1.class.as_str(), m1.name.as_str()),
        ("Lj$/util/Map$-CC;", "$default$compute")
    );
    assert_ne!(m0.signature(), m1.signature());
}

/// Method pool sizes are recorded per file, never summed, because a summed
/// number is the thing that makes a remapping layer look necessary.
#[test]
fn recorded_order_carries_per_file_pool_sizes() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let rec = loader.record();
    assert_eq!(rec.order.len(), 2);

    let first = &rec.order[0];
    assert_eq!(first.name, "classes.dex");
    assert_eq!(first.ordinal, 1);
    assert_eq!(first.method_ids, 498);
    assert_eq!(first.class_defs, 101);
    assert_eq!(first.bytes, 56_024);
    // The DEX header's own SHA-1, hex: content identity for free, since the
    // format already carries the hash.
    assert_eq!(first.sha1.len(), 40);
    assert!(first.sha1.chars().all(|c| c.is_ascii_hexdigit()));

    let second = &rec.order[1];
    assert_eq!(second.name, "classes2.dex");
    assert_eq!(second.ordinal, 2);
    assert_eq!(second.method_ids, 38);
    assert_eq!(second.class_defs, 5);
    assert_eq!(second.bytes, 4_748);
    assert_ne!(first.sha1, second.sha1);
}

/// The record is serialisable and round-trips, because it is meant to travel
/// inside a recording rather than live only in a log.
#[test]
fn load_record_serialises() {
    let loader = MultidexLoader::load_named(
        Some("org.fcitx.fcitx5.android.plugin.sayura".to_string()),
        sayura_sources(),
    )
    .unwrap();
    let json = serde_json::to_string(loader.record()).expect("record must serialise");
    let back: substrate_runtime::multidex::LoadRecord =
        serde_json::from_str(&json).expect("must round-trip");
    assert_eq!(&back, loader.record());
    assert_eq!(
        back.package.as_deref(),
        Some("org.fcitx.fcitx5.android.plugin.sayura")
    );
    assert_eq!(back.order[0].name, "classes.dex");
}

/// A real multidex APK's primary file and secondary file define disjoint class
/// sets, so the merged space is a union with no duplicates.
#[test]
fn a_real_multidex_pair_has_no_duplicate_classes() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let dupes = loader.record().warnings_of("duplicate_class");
    assert!(
        dupes.is_empty(),
        "a well-formed dx build must not duplicate a class_def, got {:?}",
        dupes.iter().map(|w| w.summary()).collect::<Vec<_>>()
    );
    // 101 + 5 disjoint class_defs.
    assert_eq!(loader.space().len(), 106);
}

/// Warnings are deterministic: the same bytes must produce a byte-identical
/// record, because a recording that reorders between runs cannot be diffed.
#[test]
fn warnings_are_deterministic_across_runs() {
    let dup = Klass::new("La/Dup;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let sources = vec![common::primary1(&dup), common::secondary1(2, &dup)];
    let a = MultidexLoader::load(sources.clone()).unwrap();
    let b = MultidexLoader::load(sources).unwrap();
    assert_eq!(a.record(), b.record());
    let ja = serde_json::to_string(a.record()).unwrap();
    let jb = serde_json::to_string(b.record()).unwrap();
    assert_eq!(ja, jb);
}

/// First-wins, with a warning naming every file — the rule Android states, and
/// the one silent last-wins would break.
#[test]
fn duplicate_class_is_first_wins_with_a_warning() {
    let dup = Klass::new("La/Dup;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&dup), common::secondary1(2, &dup)]).unwrap();

    let dupes: Vec<&MultidexWarning> = loader
        .record()
        .warnings_of("duplicate_class")
        .into_iter()
        .filter(|w| matches!(w, MultidexWarning::DuplicateClass { descriptor, .. } if descriptor == "La/Dup;"))
        .collect();
    assert_eq!(dupes.len(), 1, "exactly one duplicate warning for La/Dup;");
    match dupes[0] {
        MultidexWarning::DuplicateClass {
            descriptor,
            winner,
            losers,
            ..
        } => {
            assert_eq!(descriptor, "La/Dup;");
            assert_eq!(*winner, FileId(0), "the earlier file must win");
            assert_eq!(*losers, vec![FileId(1)]);
        }
        other => panic!("unexpected warning {other:?}"),
    }
}

/// Two files may legitimately contribute different methods to one class. That
/// is the split-class case, and the merged space is the union.
#[test]
fn split_class_merges_both_method_sets() {
    let a = Klass::new("La/Split;").with(Meth::concrete("onlyInFile1", "V", Body::ReturnVoid));
    let b = Klass::new("La/Split;").with(Meth::concrete("onlyInFile2", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();

    assert_eq!(loader.space().len(), 2, "La/Split; plus Ljava/lang/Object;");
    let r = substrate_runtime::multidex::Resolver::new(&loader);
    let methods = r.class_methods("La/Split;");
    assert_eq!(methods.len(), 2, "both files' methods must be visible");
    assert!(methods.iter().any(|m| m.name == "onlyInFile1"));
    assert!(methods.iter().any(|m| m.name == "onlyInFile2"));
}

/// A class that appears in two files with the *same* method set is duplicated,
/// not split. The resolver distinguishes the two, and the distinction is
/// observable rather than a comment.
#[test]
fn duplicated_class_is_not_reported_as_split() {
    let same = Klass::new("La/Same;")
        .with(Meth::concrete("a", "V", Body::ReturnVoid))
        .with(Meth::concrete("b", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&same), common::secondary1(2, &same)]).unwrap();
    let r = substrate_runtime::multidex::Resolver::new(&loader);
    let res = r.resolve_class("La/Same;").expect("class resolves");
    assert!(
        !res.is_split,
        "identical method sets are duplication, not a split"
    );
    assert_eq!(res.sites.len(), 2);
}

#[test]
fn split_class_is_reported_as_split() {
    let a = Klass::new("La/Split;").with(Meth::concrete("onlyIn1", "V", Body::ReturnVoid));
    let b = Klass::new("La/Split;").with(Meth::concrete("onlyIn2", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = substrate_runtime::multidex::Resolver::new(&loader);
    let res = r.resolve_class("La/Split;").expect("class resolves");
    assert!(res.is_split);
    assert_eq!(res.contributing_files(), vec![FileId(0), FileId(1)]);
}

/// A subclass in file 1 whose superclass is only in file 2 is legal, and is
/// exactly why a loader cannot resolve in one forward pass.
#[test]
fn superclass_in_a_later_file_is_recorded() {
    let base = Klass::new("La/Base;");
    let derived = Klass::new("La/Derived;").extending("La/Base;");
    let loader = MultidexLoader::load(vec![
        common::primary1(&derived),
        common::secondary1(2, &base),
    ])
    .unwrap();

    let w = loader.record().warnings_of("superclass_in_later_file");
    assert_eq!(w.len(), 1);
    assert_eq!(
        w[0].summary(),
        "La/Derived; in #0 extends La/Base;, defined only later in #1"
    );
    // It is a warning, not an error: the hierarchy resolves fine.
    let r = substrate_runtime::multidex::Resolver::new(&loader);
    assert!(r.resolve_class("La/Base;").is_some());
}

/// A superclass in no file at all is also recorded, because "the class is
/// missing" and "the superclass is a platform class" are different facts.
#[test]
fn unresolved_superclass_is_recorded() {
    let orphan = Klass::new("La/Orphan;").extending("La/Absent;");
    let loader = MultidexLoader::load(vec![common::primary1(&orphan)]).unwrap();
    let w = loader.record().warnings_of("unresolved_superclass");
    assert_eq!(w.len(), 1);
    assert_eq!(
        w[0].summary(),
        "La/Orphan; extends La/Absent;, which no loaded file defines"
    );
}

/// A method declared in two files is recorded even when the two declarations
/// turn out to be equivalent — the loader records that more than one site
/// exists and leaves the equivalence judgement to the resolver.
#[test]
fn a_duplicate_method_is_recorded_and_names_its_files() {
    let dup = Klass::new("La/DupM;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&dup), common::secondary1(2, &dup)]).unwrap();

    let w = loader.record().warnings_of("duplicate_method");
    assert_eq!(w.len(), 1, "one duplicate method");
    // The summary must name the files, because a recording reader cannot map a
    // bare `#1` back to `classes2.dex` without re-deriving the load order.
    assert_eq!(
        w[0].summary(),
        "La/DupM;.m() also defined in classes2.dex; first-wins kept classes.dex"
    );
}

// ---------------------------------------------------------------------------
// The corpus measurement this component exists for.
// ---------------------------------------------------------------------------

/// The multidex rate in `corpus/survey.jsonl`, recomputed here so the figure
/// quoted in `FIXTURES.md` and in the module docs is auditable rather than
/// asserted.
///
/// The numbers in the docs are the point of the exercise — "31.13 % of the
/// corpus is multidex" is a load-bearing claim — so a test that recomputes them
/// from the survey is worth more than a comment repeating them. If the corpus is
/// regenerated and the rate moves, this fails and the docs must move with it.
///
/// The corpus is outside this crate and is owned elsewhere, so the test **skips
/// rather than fails** when the file is absent: a missing corpus is not a
/// multidex bug, and a test that cannot run in a given checkout should say so
/// loudly rather than fail opaquely.
#[test]
fn the_corpus_multidex_rate_is_what_the_docs_claim() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("corpus")
        .join("survey.jsonl");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not present; the corpus multidex rate cannot be recomputed here",
            path.display()
        );
        return;
    };

    let mut total = 0usize;
    let mut multidex = 0usize;
    let mut lo_total = 0usize;
    let mut lo_multi = 0usize;
    let mut hi_total = 0usize;
    let mut hi_multi = 0usize;
    let mut max_dex = 0u32;

    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let row: serde_json::Value = serde_json::from_str(line).expect("survey row must be JSON");
        if !row["ok"].as_bool().unwrap_or(false) {
            continue;
        }
        let count = match row["dexCount"].as_u64() {
            Some(c) => c,
            None => continue,
        };
        total += 1;
        max_dex = max_dex.max(count as u32);
        if count > 1 {
            multidex += 1;
        }
        match row["minSdk"].as_u64() {
            Some(sdk) if sdk < 21 => {
                lo_total += 1;
                lo_multi += usize::from(count > 1);
            }
            Some(_) => {
                hi_total += 1;
                hi_multi += usize::from(count > 1);
            }
            None => {}
        }
    }

    assert_eq!(
        total, 4475,
        "the corpus size changed; the docs need updating"
    );
    assert_eq!(
        multidex, 1393,
        "the multidex count changed; the docs need updating"
    );
    // 1393/4475 = 31.128...
    assert!(
        (multidex as f64 / total as f64 - 0.3113).abs() < 0.0001,
        "rate is {:.4}, docs say 0.3113",
        multidex as f64 / total as f64
    );
    // The minSdk trend: the corpus average hides it.
    assert_eq!((lo_multi, lo_total), (56, 840));
    assert_eq!((hi_multi, hi_total), (1337, 3634));
    assert_eq!(
        max_dex, 13,
        "the largest dexCount changed; the docs need updating"
    );

    let lo = lo_multi as f64 / lo_total as f64;
    let hi = hi_multi as f64 / hi_total as f64;
    assert!(
        hi > lo * 4.0,
        "minSdk>=21 rate {hi:.4} should dwarf minSdk<21 rate {lo:.4}"
    );
}
