//! End-to-end tests over **real** DEX files.
//!
//! These are the six `classes*.dex` fixtures already in
//! `tools/dexcore/tests/fixtures/`, lifted from live F-Droid APKs by Agent 1.
//! They are used here rather than synthetic DEX so that the analyzer is tested
//! against the bytes a real d8/R8 pipeline emits, including the `invoke-custom`
//! and `invoke-polymorphic` shapes a hand-assembled fixture would not contain.
//!
//! Each fixture is wrapped in a stored-only ZIP so the whole pipeline —
//! central directory, entry extraction, DEX parse, instruction walk, taxonomy
//! join, rubric — is exercised end to end.

use std::collections::BTreeMap;

use substrate_predictor::analysis::{analyze_apk, AppFacts};
use substrate_predictor::score::{Band, Prediction};
use substrate_predictor::{Confidence, Gate};

/// The fixtures under test, named so a failure says which app broke.
///
/// The DEX bytes are borrowed from `tools/dexcore/tests/fixtures/`, which Agent 1
/// extracted from live F-Droid APKs; provenance and SHA-256s are recorded in
/// that crate's `tests/FIXTURES.md`. They are `include_bytes!`d rather than read
/// at run time so the test binary is self-contained and a path change cannot
/// silently turn the suite green by skipping it.
///
/// They are the same small DEX files, so they exercise the *shapes* — DEX 035
/// and 038, `invoke-custom`, `native` declarations, real `Build` reads — and
/// not the *distribution*. The distribution comes from the 50-APK run in
/// `analysis/prediction.md`.
const FIXTURES: &[(&str, &[u8])] = &[
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
    (
        "org.vi_server.red_screen_3",
        include_bytes!("../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex"),
    ),
    (
        "pro.rudloff.search_to_browser_2",
        include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex"),
    ),
];

fn dex_of(name: &str) -> &'static [u8] {
    FIXTURES
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("unknown fixture {name}"))
        .1
}

/// The names alone, for the loops that only need an identifier.
fn fixture_names() -> Vec<&'static str> {
    FIXTURES.iter().map(|(n, _)| *n).collect()
}

/// Wrap `payload` in a minimal stored-only ZIP under `entry_name`, plus an
/// optional second entry. A real APK's central directory is ZIP64-annotated and
/// deflate-compressed; the reader exercises both in its own unit tests, and
/// what matters here is that the pipeline sees the DEX bytes unchanged.
fn make_apk(entry_name: &str, payload: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut entries: Vec<(&str, &[u8])> = vec![(entry_name, payload)];
    for (n, d) in extra {
        entries.push((n, d));
    }

    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in &entries {
        let lho = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // crc unchecked
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&lho.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn analyze_fixture(name: &str) -> AppFacts {
    let dex = FIXTURES
        .iter()
        .find(|(n, _)| *n == name)
        .unwrap_or_else(|| panic!("unknown fixture {name}"))
        .1;
    analyze_apk(make_apk("classes.dex", dex, &[]))
}

#[test]
fn every_fixture_parses_and_scores() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        assert!(
            facts.analysable,
            "{name} was not analysable: {:?}",
            facts.error
        );
        assert_eq!(facts.dex_files, vec!["classes.dex".to_string()], "{name}");
        assert!(facts.classes > 0, "{name} reported zero classes");
        assert!(
            facts.code.instructions_decoded > 0,
            "{name} decoded no instructions"
        );
        assert_eq!(
            facts.code.methods_undecodable, 0,
            "{name} has undecodable code items; every count is a lower bound"
        );
        let p = Prediction::compute(&facts);
        assert_ne!(p.band, Band::Unknown, "{name}");
        assert_eq!(
            p.components.len(),
            substrate_predictor::RUBRIC.len(),
            "{name}"
        );
    }
}

#[test]
fn invoke_counts_are_internally_consistent() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        let i = &facts.code.invoke;
        // The five ordinary kinds plus their range forms must add up to
        // something no larger than the total instructions decoded.
        assert!(
            i.total_invoke() + i.total_dynamic() + i.filled_new_array as u64
                <= facts.code.instructions_decoded,
            "{name}: invoke counts exceed the instruction count"
        );
        // And at least one invoke must exist in a non-trivial app.
        assert!(i.total_invoke() > 0, "{name}: no invoke decoded at all");
    }
}

#[test]
fn every_reported_build_field_read_has_a_method_id_behind_it() {
    // The `Build` reads are claimed at call-site strength, so each one must
    // appear in the pool's `field_ids` too. If this fails, the instruction walk
    // is inventing reads.
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        let field_read_counts: BTreeMap<String, u32> = facts
            .dex_scans
            .iter()
            .flat_map(|s| s.field_reads_by_target.iter())
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        for r in &facts.build.evidence {
            assert!(
                field_read_counts.contains_key(&r.target),
                "{name}: {}",
                r.oneline()
            );
        }
        assert!(
            facts.build.total_reads as usize >= facts.build.evidence.len(),
            "{name}"
        );
    }
}

#[test]
fn load_library_call_sites_name_a_real_method_id() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        for c in &facts.native.load_library_calls {
            assert!(
                c.callee.starts_with("Ljava/lang/System;")
                    || c.callee.starts_with("Ljava/lang/Runtime;"),
                "{name}: unexpected loader {}",
                c.callee
            );
            // A call site must have an enclosing method with a descriptor.
            assert!(
                c.evidence.class.starts_with('L'),
                "{name}: {}",
                c.evidence.oneline()
            );
            // Either a name was bound or the unknown flag is set. Never neither.
            assert_eq!(
                c.name_unknown,
                c.inferred_names.is_empty(),
                "{name}: {}",
                c.evidence.oneline()
            );
        }
    }
}

#[test]
fn taxonomy_hits_only_carry_ids_from_the_frozen_registry() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        for h in &facts.taxonomy_hits {
            assert!(h.id.starts_with("SUB."), "{name}: {}", h.id);
            assert_eq!(h.id.split('.').count(), 3, "{name}: {}", h.id);
            assert_eq!(
                h.family,
                substrate_predictor::taxonomy::family_of(h.id),
                "{name}"
            );
            assert!(h.member_count > 0, "{name}: {} with no members", h.id);
            assert_eq!(
                h.member_count as usize,
                h.members.len(),
                "{name}: member_count disagrees with members"
            );
        }
        // Family rollup must be a partition of the hits, so the member totals
        // have to add back up.
        let sum: u32 = facts.family_rollup.iter().map(|(_, m, _)| *m).sum();
        let expect: u32 = facts.taxonomy_hits.iter().map(|h| h.member_count).sum();
        assert_eq!(
            sum, expect,
            "{name}: family rollup does not partition the hits"
        );
    }
}

#[test]
fn a_native_lib_entry_gates_the_prediction() {
    let facts = analyze_apk(make_apk(
        "classes.dex",
        dex_of("fr.smarquis.sleeptimer_16200"),
        &[
            ("lib/arm64-v8a/libsleeptimer.so", b"\x7fELF\x02\x01\x01\x00"),
            (
                "lib/armeabi-v7a/libsleeptimer.so",
                b"\x7fELF\x02\x01\x01\x00",
            ),
        ],
    ));
    assert!(facts.analysable);
    assert_eq!(facts.native.lib_entries.len(), 2);
    assert_eq!(facts.native.abis, vec!["arm64-v8a", "armeabi-v7a"]);
    let p = Prediction::compute(&facts);
    assert_eq!(p.band, Band::Refuse);
    assert!(p.gates.iter().any(|g| g.gate == Gate::NativePayload));
    // The gate list names the entries, so the verdict is auditable.
    let g = p
        .gates
        .iter()
        .find(|g| g.gate == Gate::NativePayload)
        .unwrap();
    assert!(g
        .evidence
        .iter()
        .any(|e| e.contains("lib/arm64-v8a/libsleeptimer.so")));
}

#[test]
fn an_elf_payload_under_assets_is_found_by_sniffing_not_by_extension() {
    let facts = analyze_apk(make_apk(
        "classes.dex",
        dex_of("pro.rudloff.search_to_browser_2"),
        &[
            // A busybox-style payload with no `.so` extension: the shape the
            // corpus census said a `lib/`-only check misses by construction.
            (
                "assets/rootfs/bin/busybox",
                b"\x7fELF\x02\x01\x01\x00padding",
            ),
            ("assets/chaquopy/app.imy", b"not an elf file at all"),
        ],
    ));
    assert!(facts.analysable);
    assert_eq!(facts.native.assets_total, 2);
    assert_eq!(facts.native.assets_sniffed, 2);
    assert!(!facts.native.assets_sniff_budget_exhausted);
    assert_eq!(
        facts.native.asset_native_payloads,
        vec!["assets/rootfs/bin/busybox".to_string()]
    );
    let p = Prediction::compute(&facts);
    assert!(p.gates.iter().any(|g| g.gate == Gate::NativePayload));
}

#[test]
fn an_unanalysable_apk_never_produces_a_confident_number() {
    let facts = analyze_apk(b"PK-not-really".to_vec());
    assert!(!facts.analysable);
    let p = Prediction::compute(&facts);
    assert_eq!(p.band, Band::Unknown);
    assert_eq!(p.score_0_100, 0.0);
    assert!(p.components.is_empty());
}

#[test]
fn a_multi_dex_apk_sums_its_counts() {
    let a = dex_of("fr.smarquis.sleeptimer_16200");
    let b = dex_of("com.termux.boot_1000");
    let facts = analyze_apk(make_apk("classes.dex", a, &[("classes2.dex", b)]));
    assert!(facts.analysable);
    assert_eq!(facts.dex_files, vec!["classes.dex", "classes2.dex"]);

    let single_a = analyze_fixture("fr.smarquis.sleeptimer_16200");
    let single_b = analyze_fixture("com.termux.boot_1000");
    assert_eq!(facts.classes, single_a.classes + single_b.classes);
    assert_eq!(facts.code.instructions_decoded, {
        single_a.code.instructions_decoded + single_b.code.instructions_decoded
    });
    assert_eq!(facts.code.invoke.invoke_static, {
        single_a.code.invoke.invoke_static + single_b.code.invoke.invoke_static
    });
}

#[test]
fn the_reflection_report_separates_call_sites_from_string_constants() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        // A `Class.forName` *call site* is a claim about an instruction; a
        // class-shaped string is a claim about a constant. Both can be zero,
        // neither may be invented, and the two counters are distinct fields.
        assert!(
            facts.code.reflection_call_site_total as usize
                >= facts.code.reflection_call_sites.len(),
            "{name}"
        );
        for e in &facts.code.reflection_call_sites {
            assert!(
                e.target.starts_with("Ljava/lang/Class;")
                    || e.target.starts_with("Ljava/lang/reflect/"),
                "{name}: {} is not a reflective target",
                e.oneline()
            );
        }
        for s in &facts.code.reflective_string_constants {
            assert!(s.len() > 1, "{name}: empty reflective string constant");
        }
    }
}

#[test]
fn trust_reports_never_claim_a_server_side_verdict_is_observable() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        assert!(!facts.trust.server_side_verdict_observable, "{name}");
        assert!(!facts.trust.server_side_note.is_empty(), "{name}");
    }
}

#[test]
fn path_literals_quote_the_constant_that_produced_them() {
    for name in fixture_names() {
        let facts = analyze_fixture(name);
        for c in &facts.paths.constants {
            assert!(!c.text.is_empty(), "{name}");
            assert!(c.dex.ends_with(".dex"), "{name}: {}", c.text);
            if let Some(m) = &c.matched {
                assert!(
                    c.text.contains(m.trim_start_matches("contains:")),
                    "{name}: {} does not contain its own match {m}",
                    c.text
                );
            }
        }
    }
}

#[test]
fn the_rubric_is_fully_populated_for_a_real_app() {
    // Every rubric row must be present with a re-derivable subscore, so a
    // reader can recompute the total by hand from the JSON.
    let facts = analyze_fixture("com.oF2pks.neolinker_7");
    let p = Prediction::compute(&facts);
    let mut by_id: BTreeMap<&str, &substrate_predictor::score::Component> = BTreeMap::new();
    for c in &p.components {
        by_id.insert(c.id, c);
        let expect = (c.evidence_count as f64 / c.saturation as f64).min(1.0);
        assert!(
            (c.subscore - expect).abs() < 1e-12,
            "{}: subscore not re-derivable",
            c.id
        );
        assert!(
            (c.contribution - c.weight * c.subscore).abs() < 1e-12,
            "{}",
            c.id
        );
    }
    assert_eq!(by_id.len(), substrate_predictor::RUBRIC.len());
    let weight_sum: f64 = p.components.iter().map(|c| c.weight).sum();
    assert!((weight_sum - 1.0).abs() < 1e-12);
}

#[test]
fn a_verified_hit_outranks_a_conjecture_hit_for_the_same_id() {
    // `Landroid/os/Build;.FINGERPRINT` is Verified and the `Build` catch-all is
    // Conjecture; an app touching both must report FINGERPRINT as VERIFIED.
    let facts = analyze_fixture("fr.smarquis.sleeptimer_16200");
    for h in &facts.taxonomy_hits {
        let rows: Vec<&substrate_predictor::taxonomy::ApiRule> = substrate_predictor::RULES
            .iter()
            .filter(|r| r.taxonomy == h.id)
            .collect();
        let best = rows.iter().map(|r| r.confidence.rank()).max().unwrap_or(0);
        assert_eq!(
            h.confidence.rank(),
            best,
            "{}: reported {} but the table's best is {:?}",
            h.id,
            h.confidence.as_str(),
            best
        );
    }
    let _ = Confidence::Verified;
}
