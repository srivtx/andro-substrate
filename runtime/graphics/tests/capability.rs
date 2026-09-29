//! The capability report, checked against the code rather than against itself.
//!
//! # The failure this file exists to prevent
//!
//! The previous generation of this project shipped two headline numbers that
//! were wrong by 40× and 20×, and both times because a self-consistent
//! artefact was never checked against reality. A report that only records what
//! the code believes about itself is exactly such an artefact.
//!
//! So the checks here run in four directions, none of which is "the report
//! agrees with the report":
//!
//! 1. **The registry against the document.** The eleven IDs are read out of
//!    `docs/divergence-taxonomy.md` and compared with [`GfxId::ALL`]. If the
//!    taxonomy grows, this fails; if the registry drifts from it, this fails.
//! 2. **The claim against a live probe.** [`CapabilityReport::audit`] runs the
//!    probes and compares. A backend that lies is caught.
//! 3. **The number against a counterfactual.** A stub backend that answers
//!    `Satisfied` has to move `reproduced()`. If it does not, the number is a
//!    constant and the headline is worthless.
//! 4. **The per-feature table against enumeration.** All twenty-one
//!    `PorterDuff` modes are counted against what the emitters actually do, so
//!    adding a mode without updating a table fails here.

use std::collections::BTreeSet;

use substrate_runtime::capability::{
    CapabilityReport, Claim, Emission, GfxId, Limitation, Origin, Probe, ProbeAnswer, Support,
    Verdict,
};
use substrate_runtime::canvas::{
    canvas2d_claims, canvas2d_limitations, canvas2d_mode, headless_claims, headless_limitations,
    probe_answer, Canvas as _, SilentCanvas,
};
use substrate_runtime::error::BackendKind;
use substrate_runtime::paint::{PorterDuffMode, PORTER_DUFF_MODE_COUNT};
use substrate_runtime::svg::{fe_composite_mode, svg_limitations, FeMode, FE_OPERATORS};

const TAXONOMY: &str = include_str!("../../../docs/divergence-taxonomy.md");

/// The `SUB.GFX` IDs the taxonomy document actually contains, in §12.
fn ids_in_the_document() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in TAXONOMY.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("| `SUB.GFX.") {
            if let Some((token, _)) = rest.split_once('`') {
                out.insert(format!("SUB.GFX.{token}"));
            }
        }
    }
    out
}

#[test]
fn the_registry_is_exactly_the_taxonomys_gfx_family() {
    let doc = ids_in_the_document();
    let mine: BTreeSet<String> = GfxId::ALL.into_iter().map(|g| g.assumption()).collect();
    assert_eq!(
        doc.len(),
        11,
        "the taxonomy's SUB.GFX family should have 11 members; found {doc:?}"
    );
    let missing: Vec<&String> = doc.difference(&mine).collect();
    let extra: Vec<&String> = mine.difference(&doc).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the registry and docs/divergence-taxonomy.md have drifted.\n  \
         in the document, not in GfxId::ALL: {missing:?}\n  \
         in GfxId::ALL, not in the document: {extra:?}"
    );
}

#[test]
fn the_document_also_states_the_family_size_this_code_assumes() {
    // §12's heading is "SUB.GFX — graphics, display, and composition (11)". If
    // the count in the document ever changes, the heading changes with it, and
    // the hard-coded 11 in the report stops being a measurement.
    assert!(
        TAXONOMY.contains("`SUB.GFX` — graphics, display, and composition (11)"),
        "the taxonomy's stated SUB.GFX size is no longer 11; update GfxId::ALL, \
         Probe::all, and every count derived from them"
    );
}

#[test]
fn a_claim_of_satisfied_with_no_evidence_cannot_enter_a_report() {
    // The shape check. `Satisfied` with a blank evidence string is a claim
    // nobody checked, and it is rejected before it can be counted.
    let bad = ProbeAnswer::Satisfied {
        evidence: "   ".to_string(),
    };
    assert!(bad.clone().validated().is_none());
    assert!(bad.verdict() == Verdict::Satisfied, "the verdict is still satisfied...");
    // ...which is why the audit, not the verdict, is the thing that must reject
    // it. Checked here so the two halves cannot be mistaken for each other.
    let report = CapabilityReport::audit(
        BackendKind::Headless,
        &[Claim {
            id: GfxId::Vulkan,
            verdict: Verdict::Satisfied,
            emission: Emission::AndroidSemantics,
            origin: Origin::DeviceMeasured,
            note: "n",
        }],
        Vec::new(),
        |_| ProbeAnswer::Satisfied {
            evidence: String::new(),
        },
    );
    assert!(
        !report.audit.malformed.is_empty(),
        "a blank-evidence Satisfied must be recorded as malformed"
    );
}

#[test]
fn a_backend_that_lies_is_caught_by_its_own_probe() {
    // Claims `Satisfied`, answers `Absent`. The audit must record the
    // disagreement rather than letting the claim through.
    let report = CapabilityReport::audit(
        BackendKind::Headless,
        &[Claim {
            id: GfxId::TextRender,
            verdict: Verdict::Satisfied,
            emission: Emission::AndroidSemantics,
            origin: Origin::DeviceMeasured,
            note: "an implausible claim",
        }],
        Vec::new(),
        |_| ProbeAnswer::Absent {
            reason: "no font is loaded",
        },
    );
    assert_eq!(report.observed_satisfied(), 0);
    assert_eq!(report.reproduced(), 0);
    assert_eq!(report.audit.mismatches.len(), 1, "{:?}", report.audit.mismatches);
    assert!(!report.clean());
}

#[test]
fn the_headline_number_is_a_measurement_and_not_a_constant() {
    // THE test. The real backends all report `0` reproduced, so on its own that
    // number could be a hard-coded zero. A stub that answers `Satisfied` to
    // every probe must make it eleven — and if it does not, the number is not
    // derived from the audit at all and the whole report is decorative.
    let claims = headless_claims();
    let real = CapabilityReport::audit(
        BackendKind::Headless,
        &claims,
        headless_limitations(),
        probe_answer,
    );
    assert_eq!(real.reproduced(), 0, "no real backend has a device reference");
    assert_eq!(real.observed_satisfied(), 0);
    assert!(real.clean(), "the real report must be self-consistent");

    // Now the counterfactual: the same claims, but a backend that says it can
    // do everything.
    let stub = SilentCanvas::satisfied_for(usize::MAX);
    let loud = CapabilityReport::audit(
        BackendKind::Headless,
        &claims,
        headless_limitations(),
        |p| stub.probe(p),
    );
    assert_eq!(loud.observed_satisfied(), 11, "the stub answered every probe");
    assert_eq!(
        loud.reproduced(),
        11,
        "if a backend satisfies every probe and claims every mode, `reproduced` \
         must be 11 — otherwise the number does not come from the audit"
    );
    // And the intermediate case: satisfying some but not all.
    let half = SilentCanvas::satisfied_for(5);
    let mid = CapabilityReport::audit(
        BackendKind::Headless,
        &claims,
        headless_limitations(),
        |p| half.probe(p),
    );
    assert_eq!(mid.observed_satisfied(), 5);
    assert_eq!(mid.reproduced(), 5);
    assert_eq!(mid.audit.mismatches.len(), 6, "six claims contradicted");
}

#[test]
fn reproduced_requires_a_device_reference_not_just_a_satisfied_probe() {
    // `observed_satisfied` counts probes; `reproduced` additionally requires the
    // claim to be AndroidSemantics and the origin to be DeviceMeasured. The two
    // numbers are different and the gap between them is the honest part.
    let stub = SilentCanvas::satisfied_for(usize::MAX);
    let loud = CapabilityReport::audit(
        BackendKind::Headless,
        &headless_claims(),
        headless_limitations(),
        |p| stub.probe(p),
    );
    assert_eq!(loud.observed_satisfied(), 11);
    // The claims are all Absent/Substituted with Fabricated or Absent origins, so
    // satisfying the probe does not promote any of them.
    assert_eq!(
        loud.reproduced(),
        0,
        "a satisfied probe alone must not reproduce anything; the claim and the \
         origin are also required"
    );
}

#[test]
fn every_real_backend_reports_the_same_verdicts_for_the_same_ids() {
    // The two backends differ in what they can *express* and must not differ in
    // what the substrate *has*. A Canvas2D canvas and an SVG file are both
    // missing the GPU.
    let h = CapabilityReport::audit(
        BackendKind::Headless,
        &headless_claims(),
        headless_limitations(),
        probe_answer,
    );
    let c = CapabilityReport::audit(
        BackendKind::Canvas2d,
        &canvas2d_claims(),
        canvas2d_limitations(),
        probe_answer,
    );
    assert_eq!(h.entries.len(), 11);
    assert_eq!(c.entries.len(), 11);
    for (a, b) in h.entries.iter().zip(&c.entries) {
        assert_eq!(a.id, b.id);
        assert_eq!(a.claimed, b.claimed, "{} differs between backends", a.id);
    }
    // And the counts a reader would quote.
    assert_eq!(h.reproduced(), 0);
    assert_eq!(c.reproduced(), 0);
    assert!(h.headline().contains("0 of 11"));
    assert!(c.headline().contains("0 of 11"));
}

#[test]
fn the_banner_says_the_two_things_that_matter() {
    let r = CapabilityReport::audit(
        BackendKind::Headless,
        &headless_claims(),
        headless_limitations(),
        probe_answer,
    );
    let b = r.banner("no ink for 100% of the leaf area");
    assert!(b.contains("RECONSTRUCTION"), "{b}");
    assert!(b.contains("NOT an Android frame"), "{b}");
    assert!(b.contains("onDraw code was never executed"), "{b}");
    assert!(b.contains("0 reproduced of 11"), "{b}");
    assert!(b.contains("100% of the leaf area"), "{b}");
}

#[test]
fn the_absence_rows_are_reachable_and_their_reasons_are_readable() {
    // A report of ten `Absent`s is only useful if `Absent` is a reachable state
    // and the reasons say something. Checked by driving the probes directly.
    let mut absent = 0;
    let mut substituted = 0;
    for p in Probe::all() {
        let a = probe_answer(&p);
        match a {
            ProbeAnswer::Absent { reason } => {
                absent += 1;
                assert!(reason.len() > 20, "a bare reason: {reason:?}");
                assert!(
                    !reason.to_lowercase().contains("todo"),
                    "a placeholder reason reached a report: {reason:?}"
                );
            }
            ProbeAnswer::Substituted { value, reason, .. } => {
                substituted += 1;
                assert!(!value.is_empty(), "a substitution with no value");
                assert!(reason.len() > 20);
            }
            ProbeAnswer::Satisfied { .. } => {
                panic!("{} claims Satisfied with no device behind it", p.id())
            }
        }
    }
    assert_eq!(absent, 10, "ten of the eleven assumptions are simply absent");
    assert_eq!(substituted, 1, "and one is partially answered: text metrics");
}

#[test]
fn the_text_probe_returns_a_number_a_reader_can_check() {
    let a = probe_answer(&Probe::TextAdvance {
        sample: "Mg",
        size_sp: 14.0,
    });
    match a {
        ProbeAnswer::Substituted { value, origin, .. } => {
            assert!(value.contains("advance="), "{value}");
            assert!(value.contains("Mg"), "the sample must be in the record: {value}");
            assert_eq!(origin, Origin::Fabricated);
        }
        other => panic!("expected a substitution, got {other}"),
    }
}

#[test]
fn a_missing_probe_for_an_id_is_reported_not_skipped() {
    // If an ID is added to the registry without a probe, the audit says so
    // rather than leaving the gap invisible.
    let report = CapabilityReport::audit(
        BackendKind::Headless,
        &[Claim {
            // A GfxId the probe table has no entry for is not constructible
            // today, so this checks the other half: a claims list longer than
            // the probe table.
            id: GfxId::ScreenOn,
            verdict: Verdict::Absent,
            emission: Emission::NotEmitted,
            origin: Origin::Absent,
            note: "n",
        }],
        Vec::new(),
        probe_answer,
    );
    assert_eq!(report.audit.checked, 1);
    assert!(report.audit.malformed.is_empty());
    assert_eq!(Probe::all().len(), GfxId::ALL.len());
}

// ---------------------------------------------------------------------------
// The per-feature tables, checked by enumeration

#[test]
fn canvas2d_expresses_thirteen_of_twenty_one_modes_exactly() {
    // Enumerated, not copied from a table: every mode is asked what the backend
    // would do, and the counts come from the answers.
    let mut exact = 0;
    let mut substituted = 0;
    let mut absent = Vec::new();
    for m in PorterDuffMode::ALL {
        match canvas2d_mode(m) {
            None => absent.push(m),
            Some((_, Support::Exact)) => exact += 1,
            Some((_, Support::Substituted)) => substituted += 1,
            Some((_, s)) => panic!("{m} mapped to an unexpected support {s:?}"),
        }
    }
    assert_eq!(PorterDuffMode::ALL.len(), PORTER_DUFF_MODE_COUNT);
    assert_eq!(exact, 13, "SRC_IN among them, which the brief calls out");
    assert_eq!(substituted, 6, "the separable blend modes, all premultiplied-mismatched");
    assert_eq!(
        absent,
        vec![PorterDuffMode::Dst, PorterDuffMode::Invert],
        "only DST and INVERT have no Compositing 1 operator"
    );
    // The declared table must agree with the function, row for row.
    let table = canvas2d_limitations();
    for m in PorterDuffMode::ALL {
        let row = table
            .iter()
            .find(|l| l.feature == "porter-duff-mode" && l.instance == m.as_str())
            .unwrap_or_else(|| panic!("no declared row for {m}"));
        let expected = match canvas2d_mode(m) {
            None => Support::Absent,
            Some((_, s)) => s,
        };
        assert_eq!(row.support, expected, "declared support for {m} is stale");
        assert!(row.note.len() > 20, "{m}: a note with no content");
    }
    assert_eq!(
        table.iter().filter(|l| l.feature == "porter-duff-mode").count(),
        21,
        "one row per mode, and no more"
    );
}

#[test]
fn svg_expresses_six_of_twenty_one_modes_exactly() {
    let mut exact = 0;
    let mut blend = 0;
    let mut absent = Vec::new();
    for m in PorterDuffMode::ALL {
        match fe_composite_mode(m) {
            None => absent.push(m),
            Some(FeMode::Exact(_)) => exact += 1,
            Some(FeMode::Blend(_)) => blend += 1,
        }
    }
    assert_eq!(exact, 6, "over, in, out, atop, xor, clear");
    assert_eq!(blend, 4, "multiply, screen, darken, lighten — blends, not Porter-Duff");
    assert_eq!(absent.len(), 11);
    // SRC_IN, the mode the brief names, is one of the six.
    assert!(matches!(fe_composite_mode(PorterDuffMode::SrcIn), Some(FeMode::Exact("in"))));
    // And the emitted filter ids all exist in the declared operator table, so a
    // filter reference can never dangle.
    for m in PorterDuffMode::ALL {
        if let Some(op) = fe_composite_mode(m) {
            let name = match op {
                FeMode::Exact(o) | FeMode::Blend(o) => o,
            };
            assert!(
                FE_OPERATORS.iter().any(|(n, _)| *n == name),
                "{m} maps to feComposite operator {name:?}, which has no filter defined"
            );
        }
    }
}

#[test]
fn the_headless_backend_records_every_mode_and_claims_no_rasteriser() {
    let table = headless_limitations();
    for m in PorterDuffMode::ALL {
        let row = table
            .iter()
            .find(|l| l.feature == "porter-duff-mode" && l.instance == m.as_str())
            .unwrap_or_else(|| panic!("no row for {m}"));
        assert_eq!(row.support, Support::Recorded, "{m}");
    }
    let raster = table
        .iter()
        .find(|l| l.feature == "rasterisation")
        .expect("a rasterisation row");
    assert_eq!(
        raster.support,
        Support::Absent,
        "the recording backend must never claim it rasterises"
    );
    // The features that are genuinely missing, listed so a reader does not have
    // to infer them from a hole in a match arm.
    for want in ["BitmapShader", "ColorMatrixColorFilter", "font metrics"] {
        let row = table
            .iter()
            .find(|l| l.instance == want)
            .unwrap_or_else(|| panic!("no row for {want}"));
        assert_eq!(row.support, Support::Absent, "{want}");
    }
}

#[test]
fn the_svg_table_agrees_with_the_svg_map_and_with_the_operator_list() {
    let table = svg_limitations();
    let exact_rows = table
        .iter()
        .filter(|l| l.feature == "porter-duff-mode" && l.support == Support::Exact)
        .count();
    assert_eq!(exact_rows, 6);
    for m in PorterDuffMode::ALL {
        let row = table
            .iter()
            .find(|l| l.feature == "porter-duff-mode" && l.instance == m.as_str())
            .unwrap_or_else(|| panic!("no declared row for {m}"));
        let expected = match fe_composite_mode(m) {
            None => Support::Absent,
            Some(FeMode::Exact(_)) => Support::Exact,
            Some(FeMode::Blend(_)) => Support::Substituted,
        };
        assert_eq!(row.support, expected, "declared support for {m} is stale");
    }
    // No bitmap embedding, and the note says why.
    let img = table.iter().find(|l| l.feature == "image").expect("an image row");
    assert_eq!(img.support, Support::Absent);
    assert!(img.note.contains("encoder"), "{}", img.note);
}

#[test]
fn the_report_text_lists_all_eleven_with_their_reasons() {
    let r = CapabilityReport::audit(
        BackendKind::Headless,
        &headless_claims(),
        headless_limitations(),
        probe_answer,
    );
    let t = r.to_text();
    for g in GfxId::ALL {
        assert!(t.contains(&g.assumption()), "no row for {}", g.assumption());
        assert!(!g.assumption_text().is_empty(), "the taxonomy text for {} is empty", g.token());
    }
    assert_eq!(t.lines().filter(|l| l.contains(" verdict=")).count(), 11);
    // Every row carries an observed verdict, so a reader can see the claim and
    // the observation side by side.
    for l in t.lines().filter(|l| l.contains(" verdict=")) {
        assert!(l.contains(" observed="), "row has no observation: {l}");
        assert!(l.contains(" :: "), "row has no reason: {l}");
    }
}

#[test]
fn limitations_are_a_public_type_so_a_caller_can_print_them() {
    // The tables are `Vec<Limitation>` rather than opaque strings, so a
    // recording can serialise them. Checked structurally here.
    let l: Limitation = Limitation {
        feature: "f",
        instance: "i",
        support: Support::Substituted,
        note: "n",
    };
    assert_eq!(l.support.as_str(), "substituted");
}
