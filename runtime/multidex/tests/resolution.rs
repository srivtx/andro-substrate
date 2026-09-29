//! Cross-file resolution: the split-class merge, the `Ambiguous` outcome, and
//! per-file `invoke` correctness.
//!
//! The three rules being tested are stated in full in the module docs of
//! `resolver.rs`. These tests are the falsifiable form of those statements: each
//! one names the rule it pins down and would fail if the rule changed.

mod common;

use common::{sayura_sources, secondary, Body, Klass, Meth};
use dexcore::model::access;
use substrate_runtime::multidex::{
    AmbiguityReason, FieldResolution, FileId, MethodResolution, MultidexLoader, Resolver,
    ScopedIndex,
};

// ---------------------------------------------------------------------------
// Rule 3: a call resolves where the method is *defined*.
// ---------------------------------------------------------------------------

/// The real case, from real bytes. `classes.dex` calls
/// `Lj$/util/Map$-CC;.$default$compute`, which is defined only in
/// `classes2.dex`. A loader that resolved "in the file the reference came from"
/// would report this method as missing, and a loader that merged the method
/// pools without renumbering would call the wrong method entirely.
#[test]
fn a_call_from_file_1_resolves_into_file_2() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let r = Resolver::new(&loader);

    // The class is defined only in classes2.dex.
    let class = r
        .resolve_class("Lj$/util/Map$-CC;")
        .expect("class must resolve");
    assert_eq!(
        class.primary.file,
        FileId(1),
        "Map$-CC lives in classes2.dex"
    );
    assert_eq!(class.primary.name, "classes2.dex");

    // ...and the method resolves, to a site in file 2. Its identity includes
    // its parameters, so the call has to name them: method identity is
    // `(class, name, parameter descriptors)`, not a bare name.
    let params: Vec<String> = [
        "Ljava/util/Map;",
        "Ljava/lang/Object;",
        "Ljava/util/function/BiFunction;",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let res = r.resolve_method("Lj$/util/Map$-CC;", "$default$compute", &params);
    let site = res.site().expect("must resolve");
    assert_eq!(site.file, FileId(1));
    assert_eq!(site.name, "classes2.dex");
    assert!(site.has_code());

    // The wrong parameter list is a *different* method, and does not resolve —
    // which is the behaviour that makes overloading work across files at all.
    assert!(matches!(
        r.resolve_method("Lj$/util/Map$-CC;", "$default$compute", &[]),
        MethodResolution::NotFound { .. }
    ));
}

/// The class's full method set is the union over files, which is what a caller
/// walking `Map$-CC`'s methods needs.
#[test]
fn a_classes_method_set_is_the_union_across_files() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let r = Resolver::new(&loader);
    let methods = r.class_methods("Lj$/util/Map$-CC;");
    assert!(
        methods.len() >= 5,
        "Map$-CC has many $default$ bridges, got {}",
        methods.len()
    );
    assert!(methods.iter().all(|m| m.class == "Lj$/util/Map$-CC;"));
}

/// Nine methods in the fixture are defined only in `classes2.dex` yet
/// referenced from `classes.dex`'s method pool. The count is asserted so that
/// if a fixture is swapped, the test fails rather than silently testing less.
#[test]
fn the_fixture_really_has_cross_file_invoke_targets() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let r = Resolver::new(&loader);

    let in_file2_only: Vec<String> = ["Lj$/util/Map$-CC;", "Lj$/util/Map;"]
        .iter()
        .flat_map(|c| r.class_methods(c))
        .map(|m| m.name)
        .collect();
    assert!(
        in_file2_only.iter().any(|n| n.starts_with("$default$")),
        "expected $default$ bridges defined in classes2.dex, got {in_file2_only:?}"
    );

    // And none of them are defined in file 1.
    for c in ["Lj$/util/Map$-CC;", "Lj$/util/Map;"] {
        for m in r.class_methods(c) {
            let res = r.resolve_sig(&m);
            assert_eq!(
                res.site().unwrap().file,
                FileId(1),
                "{m} must come from classes2.dex"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Rule 1: split-class merging.
// ---------------------------------------------------------------------------

/// A class whose methods are split across files resolves all of them.
#[test]
fn a_split_class_resolves_every_method() {
    let a = Klass::new("La/Split;")
        .with(Meth::concrete("alpha", "V", Body::ReturnVoid))
        .with(Meth::concrete_p("beta", &["I"], "V", Body::ReturnV0));
    let b = Klass::new("La/Split;").with(Meth::concrete("gamma", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = Resolver::new(&loader);

    let alpha = r.resolve_method("La/Split;", "alpha", &[]);
    assert_eq!(alpha.site().unwrap().file, FileId(0));
    let beta = r.resolve_method("La/Split;", "beta", &["I".to_string()]);
    assert_eq!(beta.site().unwrap().file, FileId(0));
    let gamma = r.resolve_method("La/Split;", "gamma", &[]);
    assert_eq!(gamma.site().unwrap().file, FileId(1));
}

/// Overload identity includes parameter types, so a split class that splits an
/// overload pair across files still resolves both distinctly.
#[test]
fn overloads_split_across_files_stay_distinct() {
    let a = Klass::new("La/Ov;").with(Meth::concrete_p("f", &["I"], "V", Body::ReturnVoid));
    let b = Klass::new("La/Ov;").with(Meth::concrete_p(
        "f",
        &["Ljava/lang/String;"],
        "V",
        Body::ReturnVoid,
    ));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = Resolver::new(&loader);

    let int_overload = r.resolve_method("La/Ov;", "f", &["I".to_string()]);
    let str_overload = r.resolve_method("La/Ov;", "f", &["Ljava/lang/String;".to_string()]);
    assert_eq!(int_overload.site().unwrap().file, FileId(0));
    assert_eq!(str_overload.site().unwrap().file, FileId(1));
    assert_eq!(r.class_methods("La/Ov;").len(), 2);
}

/// Fields merge across a split class the same way methods do, and a field
/// declared in only one file is still visible.
#[test]
fn fields_merge_across_files() {
    let in1 = Klass::new("La/F;")
        .with_static_field("a", "I")
        .with(Meth::concrete("m", "V", Body::ReturnVoid));
    let in2 = Klass::new("La/F;")
        .with_static_field("b", "Ljava/lang/String;")
        .with(Meth::concrete("n", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&in1), common::secondary1(2, &in2)]).unwrap();
    let r = Resolver::new(&loader);

    let a = r.resolve_field("La/F;", "a", "I");
    assert_eq!(a.site().unwrap().file, FileId(0));
    let b = r.resolve_field("La/F;", "b", "Ljava/lang/String;");
    assert_eq!(
        b.site().unwrap().file,
        FileId(1),
        "a field from file 2 is visible"
    );
    // A field nobody declares is NotFound, not an error.
    assert!(matches!(
        r.resolve_field("La/F;", "c", "I"),
        FieldResolution::NotFound { .. }
    ));
    // ...and the type descriptor is part of field identity.
    assert!(matches!(
        r.resolve_field("La/F;", "a", "J"),
        FieldResolution::NotFound { .. }
    ));
}

/// A field redeclared identically in both files resolves first-wins with the
/// duplicate still visible, mirroring the method rule.
#[test]
fn a_duplicated_field_is_first_wins() {
    let dup = Klass::new("La/F2;").with_static_field("x", "I");
    let loader =
        MultidexLoader::load(vec![common::primary1(&dup), common::secondary1(2, &dup)]).unwrap();
    let r = Resolver::new(&loader);
    match r.resolve_field("La/F2;", "x", "I") {
        FieldResolution::Resolved {
            site, duplicates, ..
        } => {
            assert_eq!(site.file, FileId(0));
            assert_eq!(duplicates.len(), 1);
            assert_eq!(duplicates[0].file, FileId(1));
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

/// Class-level metadata is first-wins, and a disagreement is recorded rather
/// than resolved silently. This is the half of Rule 1 that is *not* a merge.
#[test]
fn divergent_superclass_is_first_wins_and_recorded() {
    let in1 = Klass::new("La/D;")
        .extending("La/Base1;")
        .with(Meth::concrete("m", "V", Body::ReturnVoid));
    let in2 = Klass::new("La/D;")
        .extending("La/Base2;")
        .with(Meth::concrete("n", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&in1), common::secondary1(2, &in2)]).unwrap();

    let div = loader.record().warnings_of("divergent_class_header");
    assert_eq!(div.len(), 1, "one disagreement about the superclass");
    assert!(div[0].summary().contains("different superclass"));
    assert!(div[0].summary().contains("#1"), "names the dissenting file");

    // The first file's superclass is the one in effect.
    let r = Resolver::new(&loader);
    let res = r.resolve_class("La/D;").unwrap();
    assert_eq!(res.primary.file, FileId(0));
    assert_eq!(res.primary.superclass, "La/Base1;");
    // And both method sets merged.
    assert_eq!(r.class_methods("La/D;").len(), 2);
}

/// Divergent access flags are also first-wins, and recorded.
#[test]
fn divergent_access_flags_are_first_wins_and_recorded() {
    let pubc = Klass::new("La/A;")
        .with_flags(access::ACC_PUBLIC)
        .with(Meth::concrete("m", "V", Body::ReturnVoid));
    let finalc = Klass::new("La/A;")
        .with_flags(access::ACC_PUBLIC | access::ACC_FINAL)
        .with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader = MultidexLoader::load(vec![
        common::primary1(&pubc),
        common::secondary1(2, &finalc),
    ])
    .unwrap();
    let div = loader.record().warnings_of("divergent_class_header");
    assert!(div
        .iter()
        .any(|w| w.summary().contains("different access_flags")));
    let r = Resolver::new(&loader);
    assert_eq!(
        r.resolve_class("La/A;").unwrap().primary.access_flags,
        access::ACC_PUBLIC
    );
}

// ---------------------------------------------------------------------------
// Rule 2: Ambiguous is a first-class outcome.
// ---------------------------------------------------------------------------

/// Two files, same method, **different bodies**: `Ambiguous`, never a silent
/// pick. This is the headline case the brief asks for.
#[test]
fn a_method_defined_differently_in_two_files_is_ambiguous() {
    let a = Klass::new("La/C;").with(Meth::concrete("pick", "V", Body::ReturnVoid));
    let b = Klass::new("La/C;").with(Meth::concrete("pick", "V", Body::ReturnV0));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = Resolver::new(&loader);

    let res = r.resolve_method("La/C;", "pick", &[]);
    match &res {
        MethodResolution::Ambiguous {
            signature,
            candidates,
            reason,
        } => {
            assert_eq!(signature.name, "pick");
            assert_eq!(candidates.len(), 2, "every candidate is surfaced");
            assert_eq!(candidates[0].file, FileId(0));
            assert_eq!(candidates[1].file, FileId(1));
            assert_eq!(*reason, AmbiguityReason::CodeBytes);
        }
        other => panic!("must be Ambiguous, got {other:?}"),
    }
    // And no site is offered to a caller that ignores the distinction.
    assert!(
        res.site().is_none(),
        "an Ambiguous result must not hand back a site"
    );
    assert!(!res.is_resolved());
}

/// Concrete in one file, abstract in the other: the *most* consequential
/// conflict, because the call site either executes app code or throws.
#[test]
fn concrete_versus_abstract_is_ambiguous_on_code_presence() {
    let concrete = Klass::new("La/P;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let abstract_ = Klass::new("La/P;").with(Meth::abstract_("m", &[], "V"));
    let loader = MultidexLoader::load(vec![
        common::primary1(&concrete),
        common::secondary1(2, &abstract_),
    ])
    .unwrap();
    let r = Resolver::new(&loader);

    let res = r.resolve_method("La/P;", "m", &[]);
    match &res {
        MethodResolution::Ambiguous {
            reason, candidates, ..
        } => {
            assert_eq!(*reason, AmbiguityReason::CodePresence);
            assert!(candidates[0].has_code());
            assert!(!candidates[1].has_code());
        }
        other => panic!("must be Ambiguous, got {other:?}"),
    }
}

/// Differing access flags are a conflict too.
#[test]
fn differing_access_flags_are_ambiguous() {
    let pub_m = Klass::new("La/Fl;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let static_m = Klass::new("La/Fl;").with(
        Meth::concrete("m", "V", Body::ReturnVoid)
            .with_flags(access::ACC_PUBLIC | access::ACC_STATIC),
    );
    let loader = MultidexLoader::load(vec![
        common::primary1(&pub_m),
        common::secondary1(2, &static_m),
    ])
    .unwrap();
    let r = Resolver::new(&loader);

    match r.resolve_method("La/Fl;", "m", &[]) {
        MethodResolution::Ambiguous { reason, .. } => {
            assert_eq!(reason, AmbiguityReason::AccessFlags)
        }
        other => panic!("must be Ambiguous, got {other:?}"),
    }
}

/// Two files carrying **byte-identical** bodies is duplication, not conflict.
/// Treating it as a conflict would make `Ambiguous` noise and would refuse to
/// run ordinary apps, so the equivalence rule has to be tested as carefully as
/// the conflict rule.
#[test]
fn identical_definitions_in_two_files_are_not_ambiguous() {
    let dup = Klass::new("La/Same;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&dup), common::secondary1(2, &dup)]).unwrap();
    let r = Resolver::new(&loader);

    match r.resolve_method("La/Same;", "m", &[]) {
        MethodResolution::Resolved {
            site, equivalent, ..
        } => {
            assert_eq!(site.file, FileId(0), "first-wins");
            assert_eq!(equivalent.len(), 1, "the duplicate is still visible");
            assert_eq!(equivalent[0].file, FileId(1));
        }
        other => panic!("must be Resolved, got {other:?}"),
    }
}

/// The equivalence mask: `ACC_SYNTHETIC`/`ACC_BRIDGE`/`ACC_VARARGS` differ
/// between the two halves of a desugared method routinely, and flagging those
/// would swamp the signal.
#[test]
fn compiler_bookkeeping_flags_alone_are_not_ambiguity() {
    let plain = Klass::new("La/Syn;").with(Meth::concrete("lambda$0", "V", Body::ReturnVoid));
    let synthetic = Klass::new("La/Syn;").with(
        Meth::concrete("lambda$0", "V", Body::ReturnVoid)
            .with_flags(access::ACC_PUBLIC | access::ACC_SYNTHETIC),
    );
    let bridge = Klass::new("La/Syn;").with(
        Meth::concrete("lambda$0", "V", Body::ReturnVoid)
            .with_flags(access::ACC_PUBLIC | access::ACC_BRIDGE),
    );
    let loader = MultidexLoader::load(vec![
        common::primary1(&plain),
        common::secondary1(2, &synthetic),
        common::secondary1(3, &bridge),
    ])
    .unwrap();
    let r = Resolver::new(&loader);

    match r.resolve_method("La/Syn;", "lambda$0", &[]) {
        MethodResolution::Resolved { equivalent, .. } => assert_eq!(equivalent.len(), 2),
        other => panic!("SYNTHETIC/BRIDGE must not be a conflict, got {other:?}"),
    }
}

/// A method nothing defines is `NotFound`, which is a different answer from
/// `Ambiguous`: nothing claims it, rather than several things claiming it
/// differently.
#[test]
fn an_absent_method_is_not_found_not_ambiguous() {
    let a = Klass::new("La/N;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader = MultidexLoader::load(vec![common::primary1(&a), secondary(2, &[])]).unwrap();
    let r = Resolver::new(&loader);

    match r.resolve_method("La/N;", "absent", &[]) {
        MethodResolution::NotFound { signature } => assert_eq!(signature.name, "absent"),
        other => panic!("must be NotFound, got {other:?}"),
    }
    // A class that does not exist at all is NotFound too, not an error.
    match r.resolve_method("La/NoSuchClass;", "m", &[]) {
        MethodResolution::NotFound { .. } => {}
        other => panic!("must be NotFound, got {other:?}"),
    }
}

/// The `code_item` of a resolved site is readable, which is what makes the
/// ambiguity decision checkable rather than a claim about flags.
#[test]
fn a_resolved_site_yields_its_code_item() {
    let a = Klass::new("La/Cd;").with(Meth::concrete("m", "V", Body::ReturnV1));
    let b = Klass::new("La/Cd;");
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = Resolver::new(&loader);

    let site = r.resolve_method("La/Cd;", "m", &[]).site().unwrap().clone();
    let code = r
        .code(&site)
        .unwrap()
        .expect("a concrete method has a code_item");
    assert_eq!(code.insns_size, 1);
    // The body really is the `return v1` we built, read back from file 0.
    let units = loader
        .reader(FileId(0))
        .unwrap()
        .code_units(site.code_off)
        .unwrap();
    assert_eq!(units, &[0x0f, 0x01]);
}

/// A method's site records whether it has a body and whether it is a
/// declaration only, which is the pair the equivalence rule is built on.
#[test]
fn a_site_reports_body_presence_and_declaration_only() {
    let a = Klass::new("La/Site;")
        .with(Meth::concrete("m", "V", Body::ReturnVoid))
        .with(Meth::abstract_("n", &[], "V"));
    let loader = MultidexLoader::load(vec![common::primary1(&a)]).unwrap();
    let r = Resolver::new(&loader);

    let m = r
        .resolve_method("La/Site;", "m", &[])
        .site()
        .unwrap()
        .clone();
    assert!(m.has_code());
    assert!(!m.is_declaration_only());

    let n = r
        .resolve_method("La/Site;", "n", &[])
        .site()
        .unwrap()
        .clone();
    assert!(!n.has_code());
    assert!(n.is_declaration_only());

    // ...and a declaration-only site yields no code item, rather than an error
    // or a zero-length one.
    assert!(r.code(&n).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Rule 3 (negative side): a pool index may not cross a file.
// ---------------------------------------------------------------------------

/// A `method_id` index minted in one file and applied to another is a typed
/// error, not a lookup against the wrong pool.
#[test]
fn a_pool_index_cannot_cross_a_file_boundary() {
    let idx = ScopedIndex::new(FileId(0), "method_ids", 17);
    assert_eq!(idx.apply_to(FileId(0)).unwrap(), idx, "same file is fine");
    let err = idx
        .apply_to(FileId(1))
        .expect_err("crossing files must be refused");
    assert_eq!(err.kind(), "IndexFromWrongFile");
    assert_eq!(
        err.to_string(),
        "method_ids[17] was minted in file #0 and applied to file #1; pool indices are per-file"
    );
}

/// The refusal is unconditional even when the index happens to be in range for
/// the target file — which is the coincidence that makes the bug silent.
#[test]
fn crossing_is_refused_even_when_the_index_is_in_range() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    // method_id 0 is valid in *both* files and means different things.
    let idx = ScopedIndex::new(FileId(0), "method_ids", 0);
    let err = idx
        .apply_to(FileId(1))
        .expect_err("in-range does not make it valid");
    assert_eq!(err.kind(), "IndexFromWrongFile");
    // ...and the two lookups really are different methods.
    let a = loader.reader(FileId(0)).unwrap().method_at(0).unwrap();
    let b = loader.reader(FileId(1)).unwrap().method_at(0).unwrap();
    assert_ne!(a.signature(), b.signature());
    assert!(loader
        .check_index(FileId(1), "method_ids", 0, loader.files()[1].methods)
        .is_ok());
}
