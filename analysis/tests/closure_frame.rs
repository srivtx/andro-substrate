//! Pins the figures quoted in `docs/analysis/0001-why-the-ranking-inverts.md`.
//!
//! The document's own pinning test is `docs/analysis/closure-frame/test-figures.py`,
//! which re-derives ~970 figures from `docs/analysis/measurement.json` and
//! refuses any number in the prose it cannot account for. This test is the
//! `cargo test` entry point to it, and additionally re-asserts the static half
//! of the document straight from `analysis/candidates/measured.jsonl`, so the
//! document's static table cannot drift from the file it claims to quote.
//!
//! Why the rubric matters here: `analysis/candidates.md` ranks candidates by
//! smallest referenced `android.*` surface. A 24-app cold-start measurement
//! contradicts that basis (Pearson r = +0.152, p = 0.483, n = 24 — the sign is
//! positive, not negative). `analysis/candidates.md` is deliberately NOT
//! modified by that finding; this test records the contradiction so it cannot
//! be quietly forgotten.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <repo>/analysis
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("analysis/ has a parent")
        .to_path_buf()
}

/// Minimal reader for the one-field-per-line `stats.py` output.
fn stats_figures() -> BTreeMap<String, String> {
    let script = repo_root().join("docs/analysis/closure-frame/stats.py");
    let out = Command::new("python3")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
    assert!(
        out.status.success(),
        "{} failed: {}",
        script.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("stats.py emits utf-8")
        .lines()
        .filter_map(|l| l.split_once(" = "))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[test]
fn the_document_pinning_test_passes() {
    let script = repo_root().join("docs/analysis/closure-frame/test-figures.py");
    let out = Command::new("python3")
        .arg(&script)
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "docs/analysis/closure-frame/test-figures.py failed — the document and the \
         measurement have drifted.\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("PASS"),
        "pinning test did not report PASS:\n{stdout}\n{stderr}"
    );
}

/// The four published candidates: the static numbers the document's §1.1 table
/// quotes, asserted against the committed measurement file.
#[test]
fn the_documents_static_table_matches_measured_jsonl() {
    let path = repo_root().join("analysis/candidates/measured.jsonl");
    let text = std::fs::read_to_string(&path).expect("measured.jsonl is committed");

    // (package, apkBytes, dexBytes, ownMethods, androidTypes, androidMethods)
    let expect: &[(&str, u64, u64, u64, usize, usize)] = &[
        ("eu.quelltext.gita", 895_225, 24_897, 43, 15, 17),
        ("com.jeffliu.balancetheball", 42_170, 4_671, 30, 17, 27),
        ("org.debian.eugen.headingcalculator", 84_382, 7_761, 54, 16, 33),
        ("tk.al54.dev.badpixels", 13_949, 3_681, 22, 15, 17),
    ];

    for (pkg, apk, dex, methods, types, ameth) in expect {
        let line = text
            .lines()
            .find(|l| l.contains(&format!("\"packageName\":\"{pkg}\"")))
            .unwrap_or_else(|| panic!("{pkg} not in measured.jsonl"));
        // The file is one JSON object per line; assert on the exact fragments the
        // document's table depends on rather than pulling in a JSON dependency.
        for frag in [
            format!("\"apkBytes\":{apk}"),
            format!("\"dexBytes\":{dex}"),
            format!("\"methods\":{methods}"),
            format!("\"distinctAndroidTypes\":{types}"),
        ] {
            assert!(
                line.contains(&frag),
                "{pkg}: expected `{frag}` in its measured.jsonl row; the document's \
                 §1.1 table would be wrong"
            );
        }
        let ameths = line
            .split("\"androidMethods\":[")
            .nth(1)
            .and_then(|s| s.split(']').next())
            .map(|s| s.split(',').filter(|x| !x.trim().is_empty()).count())
            .unwrap_or(0);
        assert_eq!(
            ameths, *ameth,
            "{pkg}: document claims {ameth} distinct android.* methods, file has {ameths}"
        );
    }
}

/// The load-bearing dynamic figures, so a corrupted or regenerated
/// `measurement.json` fails here rather than silently changing the argument.
#[test]
fn the_measured_closure_figures_are_what_the_document_claims() {
    let f = stats_figures();

    let expect: &[(&str, &str)] = &[
        // cohort
        ("n_apps", "24"),
        ("n_apps_untruncated", "16"),
        ("n_apps_truncated", "8"),
        ("closure_min", "3731"),
        ("closure_max", "7374"),
        ("closure_median", "6070.5"),
        ("closure_min_clean", "4588"),
        ("closure_median_clean", "5995.0"),
        // the four published candidates
        ("fw_med[eu_quelltext_gita]", "5722"),
        ("fw_med[tk_al54_dev_badpixels]", "4588"),
        ("fw_med[com_jeffliu_balancetheball]", "5132"),
        ("fw_med[org_debian_eugen_headingcalculator]", "4941"),
        // the rubric's two heaviest features are the 2nd and 9th weakest of 11
        ("r_pearson[distinctAndroidMethods]", "0.152"),
        ("p_pearson[distinctAndroidMethods]", "0.483"),
        ("ci95_lo[distinctAndroidMethods]", "-0.268"),
        ("ci95_hi[distinctAndroidMethods]", "0.523"),
        ("r_pearson[distinctAndroidTypes]", "0.294"),
        // ...and the only feature whose CI excludes zero
        ("r_pearson[referencesAdapterType]", "0.491"),
        ("p_pearson[referencesAdapterType]", "0.014"),
        ("r_clean[referencesAdapterType]", "0.511"),
        ("p_clean[referencesAdapterType]", "0.042"),
        // the mechanism
        ("mechanism[adapter][eu_quelltext_gita]", "132"),
        ("mechanism[adapter][com_jeffliu_balancetheball]", "0"),
        ("mechanism[adapter][org_debian_eugen_headingcalculator]", "0"),
        ("mechanism[adapter][tk_al54_dev_badpixels]", "0"),
        ("mechanism[text][com_jeffliu_balancetheball]", "218"),
        ("mechanism[text][eu_quelltext_gita]", "116"),
        // the floor
        ("core_all24", "2350"),
        ("union_all24", "12880"),
        ("gita_specific_vs_other23", "37"),
        ("gita_minus_badpixels", "1331"),
        ("gita_minus_badpixels_shared_with_population", "1294"),
        // the gap
        ("static_recall_pct[eu_quelltext_gita]", "100.0"),
        ("static_recall_gita_pct", "0.3"),
        ("shim_coverage_vs_gita_pct", "3.8"),
        // the brief's four numbers, audited
        ("legacy_reported_counts_reproduced", "1"),
        ("legacy_captures_with_gita_class", "9"),
        ("legacy_t_trace_framework", "213"),
        ("legacy_sparse_gita_distinct", "206,323,325,395,331,333"),
    ];

    for (k, v) in expect {
        let got = f
            .get(*k)
            .unwrap_or_else(|| panic!("stats.py no longer emits `{k}`"));
        assert_eq!(got, v, "`{k}`: document pins {v}, measurement says {got}");
    }
}

/// `candidates.md` still ranks on smallest `android.*` surface, and the
/// measurement says that basis does not predict dynamic demand. If someone
/// later reorders the shortlist on measured grounds, this test should be the
/// first thing deleted — it exists so the contradiction stays visible.
#[test]
fn the_rubric_contradiction_is_still_recorded() {
    let doc = std::fs::read_to_string(
        repo_root().join("docs/analysis/0001-why-the-ranking-inverts.md"),
    )
    .expect("the document is committed");
    for needle in [
        "candidates.md",
        "contradicted",
        "retire the surface-size score",
        "referencesAdapterType == false",
        "What would falsify this",
        "Does not survive",
        "Survives:",
    ] {
        assert!(
            doc.contains(needle),
            "0001 no longer contains `{needle}` — the rubric contradiction has been \
             edited out of the record"
        );
    }
}
