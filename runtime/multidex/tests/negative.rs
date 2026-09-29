//! Negative suite: hostile and malformed input, typed errors, no panics.
//!
//! Every case here is something an attacker chose or a build tool got wrong.
//! The requirement is that each one produces a typed [`MultidexError`] and
//! never a panic, because a panic in a browser substrate kills the tab and
//! with it the recording that was in progress.
//!
//! The four the brief names explicitly:
//!
//! 1. a truncated file 2 of N — [`truncated_secondary_file_is_a_typed_error`]
//! 2. a class defined in both files — [`a_class_defined_in_both_files_is_first_wins`]
//! 3. a method split across files — [`a_method_split_across_files_merges`]
//! 4. a `method_id` valid in one file and out of range in another —
//!    [`an_index_valid_in_one_file_and_out_of_range_in_another`]

mod common;

use common::{sayura_sources, secondary, Body, Klass, Meth};
use substrate_runtime::multidex::{
    DexSource, FileId, MethodResolution, MultidexError, MultidexLoader, Resolver,
};

/// Every variant of the error type has a stable `kind`, so a recording written
/// by one build is comparable with a recording written by another.
#[test]
fn every_error_kind_is_distinct() {
    let kinds = [
        MultidexError::NoDexFiles.kind(),
        MultidexError::UnloadableName { name: "x".into() }.kind(),
        MultidexError::MissingPrimary { found: vec![] }.kind(),
        MultidexError::DuplicateOrdinal {
            ordinal: 1,
            names: vec![],
        }
        .kind(),
        MultidexError::NonContiguousLoad {
            missing: 1,
            found: vec![],
        }
        .kind(),
        MultidexError::IndexOutOfRange {
            file: FileId(0),
            name: "classes.dex".into(),
            pool: "method_ids",
            index: 0,
            size: 0,
        }
        .kind(),
        MultidexError::IndexFromWrongFile {
            index_from: FileId(0),
            applied_to: FileId(1),
            pool: "method_ids",
            index: 0,
        }
        .kind(),
        MultidexError::TruncatedFile {
            file: FileId(0),
            name: "classes.dex".into(),
            what: "header",
            need: 100,
            have: 10,
        }
        .kind(),
    ];
    let mut sorted = kinds.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        kinds.len(),
        "error kinds must be distinct: {kinds:?}"
    );
}

// ---------------------------------------------------------------------------
// (1) Truncation.
// ---------------------------------------------------------------------------

/// Truncating file 2 of N must fail with a typed error naming file 2, not a
/// panic and not a silent partial load.
#[test]
fn truncated_secondary_file_is_a_typed_error() {
    let good = common::build_dex(&[Klass::new("Lt/One;").with(Meth::concrete(
        "m",
        "V",
        Body::ReturnVoid,
    ))]);
    let second = common::build_dex(&[Klass::new("Lt/Two;").with(Meth::concrete(
        "n",
        "V",
        Body::ReturnVoid,
    ))]);
    assert!(
        second.len() > 200,
        "fixture must be long enough to truncate meaningfully"
    );

    // Cut file 2 in half: a valid header, a body that runs off the end.
    let cut = &second[..second.len() / 2];
    let err = MultidexLoader::load(vec![
        DexSource::new("classes.dex", good),
        DexSource::new("classes2.dex", cut.to_vec()),
    ])
    .expect_err("a truncated file must be refused");

    // A short file is promoted out of the generic `Dex` variant, so an analyst
    // can tell "truncated" from "malformed" without parsing a message string.
    assert_eq!(err.kind(), "TruncatedFile", "got {err}");
    assert_eq!(
        err.file(),
        Some(FileId(1)),
        "the error must name file 2, got {err}"
    );
    match &err {
        MultidexError::TruncatedFile {
            file,
            name,
            need,
            have,
            what,
        } => {
            assert_eq!(*file, FileId(1));
            assert_eq!(name, "classes2.dex");
            assert!(*have < *need, "have {have} must be below need {need}");
            assert!(!what.is_empty());
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(
        err.to_string().contains("classes2.dex"),
        "the message must name the file: {err}"
    );
}

/// File 1 truncated instead of file 2, so the attribution is shown to be
/// computed from the bytes rather than assumed to be "the second file".
#[test]
fn truncation_attributes_to_whichever_file_is_short() {
    let second = common::build_dex(&[Klass::new("Lt/Two;").with(Meth::concrete(
        "n",
        "V",
        Body::ReturnVoid,
    ))]);
    let first = common::build_dex(&[Klass::new("Lt/One;").with(Meth::concrete(
        "m",
        "V",
        Body::ReturnVoid,
    ))]);

    let err = MultidexLoader::load(vec![
        DexSource::new("classes.dex", first[..first.len() / 3].to_vec()),
        DexSource::new("classes2.dex", second),
    ])
    .expect_err("must refuse");
    assert_eq!(err.file(), Some(FileId(0)), "file 1 is the short one here");
    assert!(err.to_string().contains("classes.dex"));
}

/// A file too short even to hold a header is a typed error, not an index panic.
#[test]
fn a_file_shorter_than_its_header_is_a_typed_error() {
    for len in [0usize, 1, 4, 8, 0x3f, 0x70] {
        let err = MultidexLoader::load(vec![DexSource::new("classes.dex", vec![0u8; len])])
            .expect_err("a short file must be refused");
        assert_eq!(err.file(), Some(FileId(0)), "len {len} must name file 0");
    }
}

/// Truncation at several depths, because a cut file can fail anywhere and every
/// one of those places has to be a typed error rather than a panic.
#[test]
fn truncation_at_many_offsets_never_panics() {
    let second = common::build_dex(&[Klass::new("Lt/Two;").with(Meth::concrete(
        "n",
        "V",
        Body::ReturnVoid,
    ))]);
    let primary = common::build_dex(&[Klass::new("Lt/One;")]);
    let step = (second.len() / 40).max(1);
    for cut in (0..second.len()).step_by(step) {
        // The point is that this returns rather than unwinding.
        let _ = MultidexLoader::load(vec![
            DexSource::new("classes.dex", primary.clone()),
            DexSource::new("classes2.dex", second[..cut].to_vec()),
        ]);
    }
}

/// Corrupting bytes in a valid-length file must also stay typed.
#[test]
fn corrupted_bytes_never_panic() {
    let mut bytes =
        common::build_dex(&[Klass::new("Lt/C;").with(Meth::concrete("m", "V", Body::ReturnVoid))]);
    // Flip bytes across the whole file, including the header and the checksum.
    for i in (0..bytes.len()).step_by(7) {
        bytes[i] ^= 0xff;
    }
    // No panic, whatever the outcome.
    let _ = MultidexLoader::load(vec![DexSource::new("classes.dex", bytes)]);
}

// ---------------------------------------------------------------------------
// (2) A class defined in both files.
// ---------------------------------------------------------------------------

/// The brief's second case. Android's rule is first-wins with a warning;
/// last-wins is a divergence an app can notice, so the winner is asserted.
#[test]
fn a_class_defined_in_both_files_is_first_wins() {
    let dup = Klass::new("La/Both;").with(Meth::concrete("m", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&dup), common::secondary1(2, &dup)]).unwrap();
    let r = Resolver::new(&loader);

    let res = r.resolve_class("La/Both;").expect("resolves");
    assert_eq!(res.primary.file, FileId(0), "first file wins");
    assert_eq!(res.sites.len(), 2, "both definitions are recorded");

    // The method is present in both files with identical bodies, so it is a
    // duplicate rather than a conflict — and the duplicate is still visible.
    match r.resolve_method("La/Both;", "m", &[]) {
        MethodResolution::Resolved {
            site, equivalent, ..
        } => {
            assert_eq!(site.file, FileId(0));
            assert_eq!(equivalent.len(), 1);
        }
        other => panic!("expected Resolved, got {other:?}"),
    }

    // A warning was surfaced into the record.
    assert!(!loader.record().warnings_of("duplicate_class").is_empty());
}

// ---------------------------------------------------------------------------
// (3) A method split across files.
// ---------------------------------------------------------------------------

/// The brief's third case: one class, methods in two files, merged rather than
/// shadowed.
#[test]
fn a_method_split_across_files_merges() {
    let a = Klass::new("La/S;")
        .with(Meth::concrete("inFile1", "V", Body::ReturnVoid))
        .with(Meth::concrete_p("alsoIn1", &["I"], "I", Body::ReturnV0));
    let b = Klass::new("La/S;")
        .with(Meth::concrete("inFile2", "V", Body::ReturnVoid))
        .with(Meth::concrete_p("alsoIn2", &["J"], "I", Body::ReturnV0));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();
    let r = Resolver::new(&loader);

    let res = r.resolve_class("La/S;").expect("resolves");
    assert!(res.is_split, "incomparable per-site method sets is a split");

    // All four methods are reachable, each attributed to the file that has it.
    let expected: [(&str, Vec<String>, FileId); 4] = [
        ("inFile1", vec![], FileId(0)),
        ("alsoIn1", vec!["I".to_string()], FileId(0)),
        ("inFile2", vec![], FileId(1)),
        ("alsoIn2", vec!["J".to_string()], FileId(1)),
    ];
    for (name, params, file) in expected {
        let res = r.resolve_method("La/S;", name, &params);
        assert_eq!(
            res.site().unwrap().file,
            file,
            "{name} must come from file {file:?}"
        );
    }
    assert_eq!(r.class_methods("La/S;").len(), 4);
}

// ---------------------------------------------------------------------------
// (4) An index valid in one file and out of range in another.
// ---------------------------------------------------------------------------

/// The brief's fourth case. File 1 has 3+ methods and file 2 has fewer, so an
/// index that is valid for one is out of range for the other. The error must
/// name the *target* file and *its* pool size, because that is the only pair
/// of facts that makes the failure diagnosable.
#[test]
fn an_index_valid_in_one_file_and_out_of_range_in_another() {
    let a = Klass::new("Lt/A;")
        .with(Meth::concrete("a1", "V", Body::ReturnVoid))
        .with(Meth::concrete("a2", "V", Body::ReturnVoid))
        .with(Meth::concrete("a3", "V", Body::ReturnVoid));
    let b = Klass::new("Lt/B;").with(Meth::concrete("b1", "V", Body::ReturnVoid));
    let loader =
        MultidexLoader::load(vec![common::primary1(&a), common::secondary1(2, &b)]).unwrap();

    let big = loader.files()[0].methods;
    let small = loader.files()[1].methods;
    assert!(big > small, "file 1 must have the larger method pool");

    // An index in range for file 1...
    let in_range = big - 1;
    assert!(loader
        .check_index(FileId(0), "method_ids", in_range, big)
        .is_ok());
    // ...and the same index against file 2's pool, where it is out of range.
    let err = loader
        .check_index(FileId(1), "method_ids", in_range, small)
        .expect_err("the index must be out of range for file 2");
    assert_eq!(err.kind(), "IndexOutOfRange");
    match &err {
        MultidexError::IndexOutOfRange {
            file,
            name,
            pool,
            index,
            size,
        } => {
            assert_eq!(
                *file,
                FileId(1),
                "the error names the file it was applied to"
            );
            assert_eq!(name, "classes2.dex");
            assert_eq!(*pool, "method_ids");
            assert_eq!(*index, in_range);
            assert_eq!(*size, small, "the reported size is *file 2's* pool size");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        err.to_string(),
        format!(
            "classes2.dex: method_ids[{in_range}] is out of range; that file has {small} entries"
        )
    );
}

/// A `ScopedIndex` refuses to cross files even when the index would be in range
/// for the target — the coincidence that makes a cross-file index bug silent.
#[test]
fn a_scoped_index_from_the_wrong_file_is_refused() {
    let loader = MultidexLoader::load(sayura_sources()).unwrap();
    let idx = substrate_runtime::multidex::ScopedIndex::new(FileId(0), "method_ids", 0);
    // Valid in both files, meaning different things in each.
    assert!(loader
        .check_index(FileId(0), "method_ids", 0, loader.files()[0].methods)
        .is_ok());
    assert!(loader
        .check_index(FileId(1), "method_ids", 0, loader.files()[1].methods)
        .is_ok());
    // ...and still refused, because the index does not *belong* to file 1.
    let err = idx.apply_to(FileId(1)).expect_err("must refuse");
    assert_eq!(err.kind(), "IndexFromWrongFile");
}

// ---------------------------------------------------------------------------
// Structural refusals.
// ---------------------------------------------------------------------------

/// No files at all.
#[test]
fn no_files_is_a_typed_error() {
    let err = MultidexLoader::load(vec![]).expect_err("must refuse");
    assert_eq!(err.kind(), "NoDexFiles");
    assert_eq!(err.to_string(), "no DEX files supplied");
}

/// A name a canonical loader would not load is refused rather than skipped,
/// because silently skipping would change load order invisibly.
#[test]
fn a_non_canonical_name_is_refused() {
    for name in [
        "foo.dex",
        "Classes.dex",
        "classes1.dex",
        "classes0.dex",
        "classes03.dex",
    ] {
        let sources = vec![
            DexSource::new("classes.dex", common::build_dex(&[Klass::new("Lt/A;")])),
            DexSource::new(name, common::build_dex(&[Klass::new("Lt/B;")])),
        ];
        let err = MultidexLoader::load(sources).expect_err("{name} must be refused");
        assert_eq!(err.kind(), "UnloadableName", "{name}");
        assert!(err.to_string().contains(name));
    }
}

/// `classes.dex` missing: without it there is no load-order 0.
#[test]
fn a_missing_primary_is_refused() {
    let sources = vec![secondary(2, &[Klass::new("Lt/B;")])];
    let err = MultidexLoader::load(sources).expect_err("must refuse");
    assert_eq!(err.kind(), "MissingPrimary");
    assert!(err.to_string().contains("classes2.dex"));
}

/// Two names claiming one ordinal: load order would otherwise be decided by
/// which one iteration happened to see first.
#[test]
fn a_contested_ordinal_is_refused() {
    // `classes03.dex` is not a canonical name, so it is refused on that ground
    // first; the contested-ordinal path needs two *parseable* names, which only
    // happens if the same entry appears twice. Building it directly proves the
    // check exists rather than leaving it unreachable.
    let bytes = common::build_dex(&[Klass::new("Lt/A;")]);
    let sources = vec![
        DexSource::new("classes.dex", bytes.clone()),
        DexSource::new("classes2.dex", bytes.clone()),
        DexSource::new("classes2.dex", bytes),
    ];
    let err = MultidexLoader::load(sources).expect_err("a repeated entry must be refused");
    assert_eq!(err.kind(), "DuplicateOrdinal");
    match err {
        MultidexError::DuplicateOrdinal { ordinal, names } => {
            assert_eq!(ordinal, 2);
            assert_eq!(names, vec!["classes2.dex", "classes2.dex"]);
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// A container that is not a DEX at all.
#[test]
fn a_non_dex_container_is_refused() {
    let junk = vec![0x41u8; 4096];
    let err =
        MultidexLoader::load(vec![DexSource::new("classes.dex", junk)]).expect_err("must refuse");
    assert_eq!(err.kind(), "Dex");
    assert_eq!(err.file(), Some(FileId(0)));
}

/// A fuzz-style sweep: random mutations of a real two-file corpus, asserting
/// only that nothing panics. This is the broad no-panic guarantee; the specific
/// cases above pin the specific errors.
#[test]
fn mutation_sweep_never_panics() {
    // A small deterministic PRNG, so a failure is reproducible from the seed.
    let mut state: u64 = 0x5eed_1234_9abc_def0;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let f1 = common::fixture_bytes("sayura_classes.dex");
    let f2 = common::fixture_bytes("sayura_classes2.dex");

    for round in 0..300 {
        let mut a = f1.clone();
        let mut b = f2.clone();
        for _ in 0..(1 + round % 8) {
            let idx = (next() as usize) % a.len();
            a[idx] = (next() & 0xff) as u8;
        }
        for _ in 0..(1 + round % 5) {
            let idx = (next() as usize) % b.len();
            b[idx] = (next() & 0xff) as u8;
        }
        // Truncate one of them half the time, which is the more interesting
        // shape: a header that still parses over a body that does not.
        if round % 2 == 0 {
            b.truncate(b.len() / 2);
        }
        match MultidexLoader::load(vec![
            DexSource::new("classes.dex", a),
            DexSource::new("classes2.dex", b),
        ]) {
            Ok(loader) => {
                // If it loaded, resolving against it must also be panic-free.
                let r = Resolver::new(&loader);
                for c in loader.space().descriptors().take(50) {
                    for m in r.class_methods(c) {
                        let _ = r.resolve_sig(&m);
                    }
                }
            }
            Err(e) => {
                assert!(!e.kind().is_empty());
            }
        }
    }
}
