//! Figure pins for candidate selection.
//!
//! **Why a Rust test for a Node script's output.** `candidates.md` and
//! `candidate-selection.md` quote numbers, and prose drifts from measurement for
//! exactly the reason this project keeps hitting: nobody re-runs the thing.
//! `analysis/tests/selection.test.mjs` is the primary guard — it can call the
//! ranking function directly. This file is the second guard, for the one
//! artefact a Rust test *can* check: that
//! `analysis/candidates/measured.jsonl` still says what the prose says. It runs
//! in `cargo test` alongside the predictor's own suite, so a stale
//! `measured.jsonl` is caught by the command a reader is most likely to run.
//!
//! It reads two files and asserts nothing else:
//!
//! * `../candidates/measured.jsonl` — 200 measured pool rows
//! * `../candidates/negatives.jsonl` — 4 measured known-bad rows
//!
//! If either is missing the test **fails** rather than skipping. A skipped
//! figure guard is worse than none, because it reads like a pass.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Minimal JSON value reader. `serde_json` is already a dependency; this only
/// exists so the test can read the JSONL without pulling the predictor's own
/// types in and coupling the two.
use serde_json::Value;

fn repo_relative(rel: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR is `<repo>/analysis`.
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn read_jsonl(rel: &str) -> Vec<Value> {
    let path = repo_relative(rel);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "cannot read {rel} ({}): {e}\n\
             Run: (cd analysis && node select-candidates.mjs measure)",
            path.display()
        )
    });
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{rel}: bad JSON line: {e}")))
        .collect()
}

fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            panic!(
                "row for {} has no string {key}",
                v.get("packageName").and_then(Value::as_str).unwrap_or("?")
            )
        })
        .to_string()
}

fn n(v: &Value, path: &[&str]) -> i64 {
    let mut cur = v;
    for (i, k) in path.iter().enumerate() {
        cur = cur.get(*k).unwrap_or_else(|| {
            panic!(
                "no {} at {} in {}",
                k,
                path[..=i].join("."),
                s(v, "packageName")
            )
        });
    }
    cur.as_i64()
        .unwrap_or_else(|| panic!("{} is not an integer", path.join(".")))
}

/// Length of the array at `path`. Used where a "count" in the JSON is really an
/// array, because an empty array has to be distinguishable from a missing field.
fn arr_len(v: &Value, path: &[&str]) -> usize {
    let mut cur = v;
    for (i, k) in path.iter().enumerate() {
        cur = cur.get(*k).unwrap_or_else(|| {
            panic!(
                "no {} at {} in {}",
                k,
                path[..=i].join("."),
                s(v, "packageName")
            )
        });
    }
    cur.as_array()
        .unwrap_or_else(|| panic!("{} is not an array", path.join(".")))
        .len()
}

fn bool(v: &Value, path: &[&str]) -> bool {
    let mut cur = v;
    for (i, k) in path.iter().enumerate() {
        cur = cur.get(*k).unwrap_or_else(|| {
            panic!(
                "no {} at {} in {}",
                k,
                path[..=i].join("."),
                s(v, "packageName")
            )
        });
    }
    cur.as_bool()
        .unwrap_or_else(|| panic!("{} is not a boolean", path.join(".")))
}

fn find<'a>(rows: &'a [Value], package: &str) -> &'a Value {
    rows.iter()
        .find(|r| r.get("packageName").and_then(Value::as_str) == Some(package))
        .unwrap_or_else(|| panic!("{package} is not in the measured rows"))
}

/// The shortlist, as pinned in `analysis/candidates.md`.
///
/// `(package, versionCode, score, distinctAndroidTypes, distinctAndroidMethods,
///   shimMethodsCovered, censusDexBytes, dexMethods, clickCallSites,
///   reflectionCallSites, taxonomyIdCount, sha256)`
type Pinned = (
    &'static str,
    i64,
    f64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
    &'static str,
);

const TOP_10: &[Pinned] = &[
    (
        "eu.quelltext.gita",
        6,
        0.5130,
        15,
        17,
        7,
        24897,
        43,
        2,
        0,
        3,
        "1dc68f1ff0bff92408dc8b472c2afafec2f45cabb269a0a10cb4222d34b8d8cb",
    ),
    (
        "tk.al54.dev.badpixels",
        4,
        0.5409,
        15,
        17,
        3,
        3681,
        22,
        2,
        0,
        3,
        "43842c079c9f8cde375dc4a25ad62f7cd39237b4dcbf5ddbbb45738a620dd82f",
    ),
    (
        "com.jeffliu.balancetheball",
        4,
        0.5521,
        17,
        27,
        8,
        4671,
        30,
        0,
        0,
        6,
        "6180534b151e4d50365b21483f3719e32f207a42675dee20227de449c875c1e2",
    ),
    (
        "org.debian.eugen.headingcalculator",
        4,
        0.5610,
        16,
        33,
        14,
        7761,
        54,
        1,
        2,
        4,
        "dbcfc1903051b66e7f6d3bd65a49d79527d2c143dfd870e9384bb2c9c1b8b383",
    ),
    (
        "S.N.A.K.E",
        1000001,
        0.5735,
        14,
        40,
        6,
        3025,
        9,
        0,
        0,
        5,
        "d8b3db6f912c67bec1ae9dec5b1b4ffd9958004bd7c5efec88cec48c23bfca86",
    ),
    (
        "us.spotco.extirpater",
        35,
        0.6197,
        19,
        38,
        10,
        8268,
        51,
        1,
        0,
        4,
        "ba8dcd0566affda61b7ad94cb7f1f2b1c0cbff2cb78bd2fd042b6a0e3858406e",
    ),
    (
        "ru.henridellal.fsassist",
        5,
        0.7679,
        30,
        37,
        11,
        16248,
        132,
        3,
        0,
        5,
        "e5525642c146806c3251e268d8f120759585a620f353a4680a791f551b32b823",
    ),
    (
        "com.github.rsteube.t4",
        4,
        0.7769,
        25,
        41,
        15,
        14737,
        195,
        2,
        2,
        5,
        "f76b18eeef2df33ac77709a1410c9eda68c162954563895325793d42cf83a1e7",
    ),
    (
        "anupam.acrylic",
        19,
        0.8140,
        132,
        210,
        37,
        24041,
        198,
        0,
        0,
        8,
        "df01309e3641fac77cd9bd356558e122e31f1317f988dfb4144ebad949e0ac84",
    ),
    (
        "io.github.ebraminio.bouncy",
        1,
        0.8145,
        32,
        66,
        11,
        7882,
        48,
        1,
        0,
        7,
        "a509db2afda544f6da9620eb473319b0a034c6ffc8b6536e2a8a7bcc0f407f54",
    ),
];

#[test]
fn the_measured_pool_is_the_size_the_documents_quote() {
    let rows = read_jsonl("candidates/measured.jsonl");
    assert_eq!(rows.len(), 200, "the pool is 200 measured APKs");
    let negatives = read_jsonl("candidates/negatives.jsonl");
    assert_eq!(negatives.len(), 4, "the known-bad set is 4 measured APKs");
}

#[test]
fn the_top_ten_figures_are_still_the_ones_candidates_md_quotes() {
    let rows = read_jsonl("candidates/measured.jsonl");
    for (i, (pkg, vc, _score, a_types, a_meth, shim_m, dex_b, meths, click, refl, tax, sha)) in
        TOP_10.iter().enumerate()
    {
        let r = find(&rows, pkg);
        let label = format!("#{} {pkg}", i + 1);
        assert_eq!(n(r, &["versionCode"]), *vc, "{label} versionCode");
        assert_eq!(
            n(r, &["dex", "distinctAndroidTypes"]),
            *a_types,
            "{label} distinctAndroidTypes"
        );
        assert_eq!(
            n(r, &["dex", "distinctAndroidMethods"]),
            *a_meth,
            "{label} distinctAndroidMethods"
        );
        assert_eq!(
            n(r, &["dex", "shimMethodsCovered"]),
            *shim_m,
            "{label} shimMethodsCovered"
        );
        assert_eq!(
            n(r, &["census", "dexBytes"]),
            *dex_b,
            "{label} census dexBytes"
        );
        assert_eq!(n(r, &["dex", "methods"]), *meths, "{label} dex methods");
        assert_eq!(
            n(r, &["dex", "clickCallSites"]),
            *click,
            "{label} clickCallSites"
        );
        assert_eq!(
            n(r, &["dex", "reflectionCallSites"]),
            *refl,
            "{label} reflectionCallSites"
        );
        assert_eq!(s(r, "sha256"), *sha, "{label} sha256");
        let ids = r["taxonomy"]["ids"]
            .as_array()
            .expect("taxonomy.ids is an array");
        assert_eq!(ids.len() as i64, *tax, "{label} taxonomy id count");
    }
}

#[test]
fn the_gate_histogram_is_still_the_one_the_documents_quote() {
    // The histogram is recomputed from `measured.jsonl` by re-running the gates
    // in Rust, so this is an independent implementation of the rule rather than
    // a restatement of a stored number. If the two disagree, one of them is
    // wrong and that is the finding.
    let rows = read_jsonl("candidates/measured.jsonl");
    let mut h: BTreeMap<&str, i64> = BTreeMap::new();
    for r in &rows {
        let mut why: Vec<&str> = Vec::new();
        if n(r, &["archive", "soAnywhere"]) > 0 {
            why.push("so_entry_anywhere");
        }
        if n(r, &["archive", "elfPayloads"]) > 0 {
            why.push("elf_payload_anywhere");
        }
        if n(r, &["archive", "libEntries"]) > 0 {
            why.push("lib_entry");
        }
        if n(r, &["dex", "nativeMethods"]) > 0 {
            why.push("native_method_declared");
        }
        if n(r, &["dex", "loadLibraryCallSites"]) > 0 {
            why.push("load_library_call_site");
        }
        if n(r, &["manifest", "counts", "service"]) > 0 {
            why.push("declares_service");
        }
        if n(r, &["manifest", "counts", "receiver"]) > 0 {
            why.push("declares_receiver");
        }
        if n(r, &["manifest", "counts", "provider"]) > 0 {
            why.push("declares_provider");
        }
        if n(r, &["manifest", "launcherCount"]) < 1 {
            why.push("no_launcher_activity");
        }
        if n(r, &["dex", "renderCallSites"]) < 1 {
            why.push("no_render_call_site");
        }
        if arr_len(r, &["archive", "layoutOnclickBindings"]) > 0 {
            why.push("layout_onclick_reflective_dispatch");
        }
        let ids: Vec<String> = r["taxonomy"]["ids"]
            .as_array()
            .expect("taxonomy.ids is an array")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        if ids.iter().any(|i| i == "SUB.FW.WEBVIEW") {
            why.push("webview_content_dependency");
        }
        // There is deliberately no separate `soft_keyboard_on_launch_path`
        // gate. It existed briefly and was folded into
        // `text_field_on_launch_path`, because keying on the taxonomy *ID* needs
        // the app to reference `InputMethodManager`, and an app whose only text
        // field is an `EditText` with `requestFocus` never does. The eight pool
        // apps that do reference the IME are counted once, under the broader
        // name.
        let perms: Vec<String> = r["manifest"]["permissions"]
            .as_array()
            .expect("permissions is an array")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        if perms.iter().any(|p| p == "android.permission.WAKE_LOCK") {
            why.push("special_permission:android.permission.WAKE_LOCK");
        }
        if perms
            .iter()
            .any(|p| p == "android.permission.SYSTEM_ALERT_WINDOW")
        {
            why.push("special_permission:android.permission.SYSTEM_ALERT_WINDOW");
        }
        let types: Vec<String> = r["dex"]["androidTypes"]
            .as_array()
            .expect("androidTypes is an array")
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_string())
            .collect();
        // The full TEXT_FIELD_TYPES list, plus the taxonomy ID. Checking only
        // EditText here gave 70 where the script gives 73, which is why this
        // gate is re-implemented rather than read from a stored number: a
        // partial list is a wrong number, and it is wrong silently.
        const TEXT_FIELD_TYPES: &[&str] = &[
            "Landroid/widget/EditText;",
            "Landroid/widget/AutoCompleteTextView;",
            "Landroid/widget/MultiAutoCompleteTextView;",
            "Landroid/view/inputmethod/InputMethodManager;",
            "Landroid/view/inputmethod/InputMethod;",
        ];
        if types.iter().any(|t| TEXT_FIELD_TYPES.contains(&t.as_str()))
            || ids.iter().any(|i| i == "SUB.INPUT.IME")
        {
            why.push("text_field_on_launch_path");
        }
        for w in why {
            *h.entry(w).or_default() += 1;
        }
    }
    // Only the gates that can fire inside this pool are pinned; the rest are
    // asserted to be zero, which is itself a result worth keeping.
    let pinned: &[(&str, i64)] = &[
        ("declares_service", 87),
        ("declares_receiver", 79),
        ("text_field_on_launch_path", 73),
        ("no_launcher_activity", 46),
        ("layout_onclick_reflective_dispatch", 45),
        ("webview_content_dependency", 34),
        ("no_render_call_site", 29),
        ("declares_provider", 26),
        ("special_permission:android.permission.WAKE_LOCK", 13),
        (
            "special_permission:android.permission.SYSTEM_ALERT_WINDOW",
            7,
        ),
        // Zero inside the DEX-only pool. These are the numbers the brief's hard
        // filters 2, 3 and 4 exist to establish, so they are pinned as zeros
        // rather than left unasserted.
        ("so_entry_anywhere", 0),
        ("elf_payload_anywhere", 0),
        ("lib_entry", 0),
        ("native_method_declared", 0),
        ("load_library_call_site", 0),
    ];
    for (k, v) in pinned {
        assert_eq!(h.get(k).copied().unwrap_or(0), *v, "gate {k}");
    }
    // The total is a checksum on the individual pins: a gate added to the list
    // without its count being updated fails here even if every per-gate
    // assertion still passes. 439 was measured after the IME gate was folded
    // into `text_field_on_launch_path`; the JS and this re-implementation now
    // agree on it.
    assert_eq!(
        h.values().sum::<i64>(),
        439,
        "total gate hits; a row may trip several"
    );
}

#[test]
fn every_pool_row_is_pure_dex_by_measurement_not_by_the_census() {
    // The headline the pool was built for. It is re-derived here from the
    // archive facts rather than read from the census, because the census's
    // `hasNativeCode` is a `lib/<abi>/` test and is not sufficient.
    let rows = read_jsonl("candidates/measured.jsonl");
    for r in &rows {
        let pkg = s(r, "packageName");
        for path in [
            vec!["archive", "soAnywhere"],
            vec!["archive", "elfPayloads"],
            vec!["archive", "libEntries"],
            vec!["dex", "nativeMethods"],
            vec!["dex", "nativeMethodsUnimplemented"],
            vec!["dex", "loadLibraryCallSites"],
            vec!["dex", "playServicesClasses"],
            vec!["dex", "playIntegrityApiClasses"],
            vec!["dex", "licensingClasses"],
            vec!["dex", "invokePolymorphic"],
            vec!["dex", "invokeCustom"],
        ] {
            assert_eq!(n(r, &path), 0, "{pkg} {}", path.join("."));
        }
        assert!(
            !bool(r, &["archive", "elfSniffBudgetExhausted"]),
            "{pkg} ELF sniff budget exhausted"
        );
        assert!(bool(r, &["dex", "analysable"]), "{pkg} not analysable");
        assert_eq!(
            n(r, &["dex", "methodsUndecodable"]),
            0,
            "{pkg} undecodable methods"
        );
    }
}

#[test]
fn the_known_bad_combapp_is_rejected_for_what_the_census_misses() {
    let neg = read_jsonl("candidates/negatives.jsonl");
    let m = find(&neg, "org.bitbucket.watashi564.combapp");
    // The census says this app has no native code, because its criterion is
    // `lib/<abi>/`. It ships two real ELF binaries at `res/5x.so` and
    // `res/yG.so`, 7.3 MB and 17.8 MB decompressed.
    assert!(
        !bool(m, &["census", "hasNativeCode"]),
        "the census calls it clean"
    );
    assert_eq!(
        n(m, &["archive", "libEntries"]),
        0,
        "and it has no lib/ entry either"
    );
    assert_eq!(n(m, &["archive", "elfPayloads"]), 2, "but two ELF payloads");
    let names: Vec<String> = m["archive"]["elfPayloadNames"]
        .as_array()
        .expect("elfPayloadNames is an array")
        .iter()
        .map(|v| v.as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names, vec!["res/5x.so", "res/yG.so"]);
    assert_eq!(
        arr_len(m, &["census", "straySharedObjects"]),
        2,
        "the census does list them, in its own field"
    );
}

#[test]
fn the_top_candidate_needs_the_listview_adapter_family_and_nothing_else() {
    let rows = read_jsonl("candidates/measured.jsonl");
    let g = find(&rows, "eu.quelltext.gita");
    assert_eq!(n(g, &["dex", "distinctAndroidTypes"]), 15);
    assert_eq!(n(g, &["dex", "shimTypesCovered"]), 9);
    assert_eq!(n(g, &["dex", "distinctAndroidMethods"]), 17);
    assert_eq!(n(g, &["dex", "shimMethodsCovered"]), 7);
    assert_eq!(n(g, &["dex", "shimMethodNamesCovered"]), 10);
    assert_eq!(arr_len(g, &["manifest", "permissions"]), 0);
    assert_eq!(n(g, &["dex", "renderCallSites"]), 4);
    assert_eq!(n(g, &["dex", "clickCallSites"]), 2);
    assert_eq!(arr_len(g, &["taxonomy", "byClass", "REFUSE"]), 0);
}

#[test]
fn the_pool_still_contains_no_wildcard_placeholder() {
    // Every measured row must carry a real 64-hex digest and a byte size that
    // matches the index, so the shortlist is bound to bytes rather than to a
    // filename.
    let rows = read_jsonl("candidates/measured.jsonl");
    for r in &rows {
        let pkg = s(r, "packageName");
        let sha = s(r, "sha256");
        assert_eq!(sha.len(), 64, "{pkg} sha256 length");
        assert!(
            sha.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{pkg} sha256 is not lowercase hex"
        );
        assert_eq!(
            n(r, &["apkBytes"]),
            n(r, &["census", "apkBytesIndex"]),
            "{pkg} size vs the F-Droid index"
        );
    }
}
