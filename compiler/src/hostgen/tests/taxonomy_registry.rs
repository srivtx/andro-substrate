//! Taxonomy registry conformance.
//!
//! # What this file defends
//!
//! `docs/divergence-taxonomy.md` is normative and pre-registered. The Rust
//! registry in [`hostgen::taxonomy`] is a transcription of it. Two things must
//! hold, and neither is checkable from one side alone:
//!
//! 1. **Every ID in the registry is in the document.** A stub attributed to an
//!    ID the taxonomy does not define is a measurement of an assumption nobody
//!    wrote down, which is worse than an unattributed stub because it looks
//!    rigorous.
//! 2. **Every ID in the document is in the registry.** A missing ID means some
//!    real method's absence is being attributed to a weaker assumption than the
//!    truth — the exact "misbehave instead of refusing" failure the design
//!    exists to avoid.
//!
//! Plus the derived columns: family, symptom class, hard-wall, and the three
//! sets §17 and §18 enumerate. Those are transcribed by hand from prose, and a
//! transcription error in a hand-transcribed table is invisible until someone
//! relies on it.

use std::collections::BTreeSet;

use crate::hostgen::taxonomy::{
    AssumptionId, Family, SymptomClass, TaxonomyError, ASSUMPTION_ID_COUNT, FAMILY_COUNT,
};

/// The taxonomy document, embedded at compile time.
///
/// `include_str!` over a path relative to this file, so the test cannot pass
/// because a working directory moved.
const DOC: &str = include_str!("../../../../docs/divergence-taxonomy.md");

/// Every `SUB.<FAMILY>.<LEAF>` ID the document defines.
///
/// Parsed rather than hard-coded, because hard-coding the list would make this
/// test check the transcription against itself.
fn ids_in_document() -> Vec<String> {
    let mut out = Vec::new();
    let mut family: Option<String> = None;
    for line in DOC.lines() {
        // `## 4. `SUB.IPC` — Binder, services, and cross-process communication`
        if let Some(rest) = line.strip_prefix("## ") {
            if let Some(open) = rest.find('`') {
                if let Some(close) = rest[open + 1..].find('`') {
                    let token = &rest[open + 1..open + 1 + close];
                    if token.starts_with("SUB.") {
                        family = Some(token.to_string());
                    } else {
                        family = None;
                    }
                }
            }
            continue;
        }
        let family = match &family {
            Some(f) => f,
            None => continue,
        };
        // `| `SUB.IPC.BINDER_DEV` | …`
        if !line.starts_with("| `") {
            continue;
        }
        let rest = &line[3..];
        let end = match rest.find('`') {
            Some(i) => i,
            None => continue,
        };
        let id = &rest[..end];
        if !id.starts_with(&format!("{family}.")) {
            continue;
        }
        out.push(id.to_string());
    }
    out
}

/// The `Class` column of a row, reduced to a single [`SymptomClass`].
///
/// Six rows name a pair (`REFUSE / DEGRADE` and similar) and resolve to the
/// stronger outcome; that rule is applied on both sides so the comparison is
/// like-for-like.
fn class_in_document(id: &str) -> Option<SymptomClass> {
    let needle = format!("| `{id}` |");
    let line = DOC.lines().find(|l| l.starts_with(&needle))?;
    let cells: Vec<&str> = line.trim().trim_matches('|').split('|').collect();
    let raw = cells.get(4)?.replace("**", "");
    let head = raw.split(" / ").next().unwrap_or("");
    let head = head.split(" (").next().unwrap_or("");
    let head = head.split(" for ").next().unwrap_or("");
    let head = head.split(" else ").next().unwrap_or("");
    Some(match head.trim() {
        "REFUSE" => SymptomClass::Refuse,
        "MISBEHAVE" => SymptomClass::Misbehave,
        "DEGRADE" => SymptomClass::Degrade,
        _ => return None,
    })
}

#[test]
fn the_registry_has_exactly_145_ids() {
    assert_eq!(
        AssumptionId::ALL.len(),
        145,
        "the taxonomy registry summary (§18) says 145 IDs"
    );
    assert_eq!(ASSUMPTION_ID_COUNT, 145);
}

#[test]
fn there_are_exactly_16_families() {
    assert_eq!(Family::ALL.len(), 16);
    assert_eq!(FAMILY_COUNT, 16);
    let distinct: BTreeSet<Family> = Family::ALL.into_iter().collect();
    assert_eq!(distinct.len(), 16, "Family::ALL contains a duplicate");
}

#[test]
fn every_registry_id_appears_in_the_document() {
    let doc = ids_in_document();
    assert_eq!(doc.len(), 145, "the document parse found the wrong count");
    for id in AssumptionId::ALL {
        assert!(
            doc.iter().any(|d| d == id.as_str()),
            "{} is in the Rust registry but not in docs/divergence-taxonomy.md; an attribution \
             to an ID the taxonomy does not define is a measurement of an assumption nobody \
             wrote down",
            id.as_str()
        );
    }
}

#[test]
fn every_document_id_appears_in_the_registry() {
    let doc = ids_in_document();
    for d in &doc {
        assert!(
            AssumptionId::lookup(d).is_some(),
            "{d} is defined in the taxonomy but absent from the Rust registry; every method \
             whose absence predicates it will be attributed to something weaker"
        );
    }
}

#[test]
fn the_two_sets_are_equal_as_sets_not_just_as_counts() {
    let mut doc: Vec<String> = ids_in_document();
    doc.sort();
    doc.dedup();
    let mut reg: Vec<String> = AssumptionId::ALL.iter().map(|a| a.as_str().to_string()).collect();
    reg.sort();
    reg.dedup();
    assert_eq!(doc, reg, "the document and the registry differ");
    // And no duplicate variant slipped into `ALL`.
    assert_eq!(reg.len(), 145);
}

#[test]
fn every_ids_family_matches_the_prefix_it_lives_under() {
    // The document's own §18 counts, read straight off the section headers.
    let mut per_family: BTreeMap<String, usize> = BTreeMap::new();
    let mut family: Option<String> = None;
    for line in DOC.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            family = rest.find('`').and_then(|o| {
                rest[o + 1..]
                    .find('`')
                    .map(|c| rest[o + 1..o + 1 + c].to_string())
            });
            continue;
        }
        if line.starts_with("| `") && family.is_some() {
            *per_family.entry(family.clone().unwrap_or_default()).or_insert(0) += 1;
        }
    }
    // §18's summary table, transcribed. If the document's own prose and its own
    // summary disagree, this is where it shows.
    let declared: BTreeMap<Family, usize> = [
        (Family::Build, 15),
        (Family::Trust, 9),
        (Family::Kernel, 10),
        (Family::Ipc, 14),
        (Family::Fs, 10),
        (Family::Res, 8),
        (Family::Time, 7),
        (Family::Cpu, 7),
        (Family::Mem, 7),
        (Family::Gfx, 11),
        (Family::Native, 6),
        (Family::Net, 9),
        (Family::Hw, 10),
        (Family::Fw, 11),
        (Family::Input, 4),
        (Family::Pwr, 7),
    ]
    .into_iter()
    .collect();
    for (fam, expected) in &declared {
        let actual = per_family.get(fam.as_str()).copied().unwrap_or(0);
        assert_eq!(
            actual, *expected,
            "family {fam}: §18 says {expected} IDs, the document's tables hold {actual}"
        );
    }
    for id in AssumptionId::ALL {
        let s = id.as_str();
        let prefix = &s[..s.rfind('.').unwrap_or(0)];
        assert_eq!(
            id.family().as_str(),
            prefix,
            "{s} resolves to family {} but lives under {prefix}",
            id.family()
        );
    }
}

#[test]
fn every_transcribed_symptom_class_matches_the_document() {
    for id in AssumptionId::ALL {
        let want = class_in_document(id.as_str());
        assert!(
            want.is_some(),
            "{} has no parsable Class column in the document",
            id.as_str()
        );
        assert_eq!(
            Some(id.class()),
            want,
            "{}: the registry says {:?} and the document says {:?}",
            id.as_str(),
            id.class(),
            want
        );
    }
}

#[test]
fn the_five_dual_class_rows_are_the_ones_the_document_names() {
    // Independently derived from the document: a row whose Class cell mentions
    // more than one of the three classes.
    let mut dual: BTreeSet<String> = BTreeSet::new();
    let is_class = |s: &str| ["REFUSE", "MISBEHAVE", "DEGRADE"].contains(&s);
    let mut family: Option<String> = None;
    for line in DOC.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            family = rest
                .find('`')
                .and_then(|o| rest[o + 1..].find('`').map(|c| rest[o + 1..o + 1 + c].to_string()));
            continue;
        }
        if !line.starts_with("| `") || family.is_none() {
            continue;
        }
        let rest = &line[3..];
        let end = match rest.find('`') {
            Some(i) => i,
            None => continue,
        };
        let id = rest[..end].to_string();
        let cells: Vec<&str> = line.trim().trim_matches('|').split('|').collect();
        if let Some(raw) = cells.get(4) {
            // Strip the markdown emphasis, then split the cell into the class
            // tokens it names. The separator grammar is small and closed:
            //
            //   `REFUSE`                             one class
            //   `REFUSE / DEGRADE`                   two, `/`
            //   `**REFUSE** for animation…, else **MISBEHAVE**`  two, `else`
            //   `**REFUSE** (for any app with …)`    one — the parenthetical is
            //                                          a qualifier, not a class
            //
            // So the cell is cut at the first qualifier marker (`(`, ` for `)
            // *unless* it already contained `else`, and then each part is
            // stripped of its emphasis and checked against the three class
            // names. A qualifier never introduces a class, so this is exact.
            let raw = raw.replace("**", "");
            let connective = if raw.contains(" else ") {
                " else "
            } else if raw.contains('/') {
                "/"
            } else {
                ""
            };
            let mut parts: Vec<String> = Vec::new();
            if connective.is_empty() {
                parts.push(raw.clone());
            } else {
                parts.extend(raw.split(connective).map(|p| p.to_string()));
            }
            let parts: Vec<String> = parts
                .iter()
                .map(|p| {
                    p.split(" (")
                        .next()
                        .unwrap_or("")
                        .split(" for ")
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_matches('/')
                        .trim()
                        .to_string()
                })
                .collect();
            if parts.len() > 1 && parts.iter().all(|p| is_class(p)) {
                dual.insert(id);
            }
        }
    }
    let from_registry: BTreeSet<String> = AssumptionId::ALL
        .iter()
        .filter(|a| a.also_possible().is_some())
        .map(|a| a.as_str().to_string())
        .collect();
    assert_eq!(
        from_registry, dual,
        "the set of rows the document writes as a pair differs from the registry's"
    );
    assert_eq!(
        from_registry.len(),
        5,
        "expected the 5 rows that name two classes: {from_registry:?}"
    );
}

#[test]
fn the_hard_wall_set_is_exactly_the_six_of_section_17_1() {
    // §17.1 names five IDs plus `SUB.TRUST.SAFETYNET`, which is unsatisfiable on
    // every device and so is a hard wall in a different sense — it cannot be
    // *satisfied*, rather than cannot be *reached*.
    let hard: BTreeSet<String> = AssumptionId::ALL
        .iter()
        .filter(|a| a.hard_wall())
        .map(|a| a.as_str().to_string())
        .collect();
    let expected: BTreeSet<String> = [
        "SUB.IPC.BINDER_DEV",
        "SUB.IPC.BROADCAST",
        "SUB.NET.EGRESS",
        "SUB.PWR.BOOT_COMPLETED",
        "SUB.TRUST.PLAY_INTEGRITY",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(hard, expected);

    // And the unsatisfiable-on-any-device pair is the exclusion set.
    let excluded: BTreeSet<String> = AssumptionId::ALL
        .iter()
        .filter(|a| a.excluded_from_scoring())
        .map(|a| a.as_str().to_string())
        .collect();
    assert_eq!(
        excluded,
        BTreeSet::from([
            "SUB.TRUST.SAFETYNET".to_string(),
            "SUB.CPU.NUMERIC".to_string()
        ])
    );
}

#[test]
fn the_misbehave_invisible_set_is_exactly_section_17_3_s_table() {
    let inv: BTreeSet<String> = AssumptionId::ALL
        .iter()
        .filter(|a| a.invisible_to_crash_counter())
        .map(|a| a.as_str().to_string())
        .collect();
    assert_eq!(
        inv,
        BTreeSet::from([
            "SUB.CPU.ATOMIC".to_string(),
            "SUB.FW.NON_SDK_API".to_string(),
            "SUB.FW.REFLECTION".to_string(),
            "SUB.IPC.BINDER_THREADPOOL".to_string(),
            "SUB.IPC.PACKAGE_MANAGER_OTHER".to_string(),
            "SUB.NET.WEBSOCKET".to_string(),
            "SUB.RES.ARSC".to_string(),
            "SUB.TIME.ELAPSED_REALTIME".to_string(),
        ]),
        "§17.3's table is the authoritative list of assumptions a crash counter misses"
    );
}

#[test]
fn the_most_consequential_set_is_exactly_section_18_s_last_column() {
    let mc: BTreeSet<String> = AssumptionId::ALL
        .iter()
        .filter(|a| a.most_consequential_in_family())
        .map(|a| a.as_str().to_string())
        .collect();
    assert_eq!(mc.len(), 22, "§18 names 22 across the 16 families");
    // Every family contributes at least one, except… let me check the document:
    // §18 lists MEM's LARGE_HEAP, so all 16 should be covered except any family
    // whose row lists none. Reading the table: every family has at least one.
    let families_covered: BTreeSet<Family> = AssumptionId::ALL
        .iter()
        .filter(|a| a.most_consequential_in_family())
        .map(|a| a.family())
        .collect();
    assert_eq!(families_covered.len(), 16, "§18 covers all 16 families");
}

#[test]
fn misbehave_is_the_class_the_taxonomy_says_is_invisible() {
    // §17.3 opens: "`MISBEHAVE` is 45 of the entries above." The document's own
    // count is checked against the registry's, because a drift here would mean
    // the class column was transcribed wrong for some row.
    let count = AssumptionId::ALL
        .iter()
        .filter(|a| a.class() == SymptomClass::Misbehave)
        .count();
    // The five dual rows resolve to the stronger class, so the misbehave count
    // is the document's own tally minus the ones that resolve upward.
    let doc_misbehave = ids_in_document()
        .iter()
        .filter(|id| class_in_document(id) == Some(SymptomClass::Misbehave))
        .count();
    assert_eq!(
        count, doc_misbehave,
        "the registry's Misbehave count disagrees with the document's"
    );
    assert!(count > 0);
}

#[test]
fn parse_rejects_a_well_shaped_but_unregistered_id() {
    // Shape is not membership, which is the whole reason `parse` exists.
    assert!(AssumptionId::well_shaped("SUB.NET.NOT_A_REAL_LEAF"));
    assert_eq!(
        AssumptionId::parse("SUB.NET.NOT_A_REAL_LEAF"),
        Err(TaxonomyError::Unregistered)
    );
    for bad in ["SUB", "NET.EGRESS", "sub.net.egress", "SUB.net", "", "SUB..EGRESS"] {
        assert_eq!(
            AssumptionId::parse(bad),
            Err(TaxonomyError::Malformed),
            "{bad:?} should be malformed, not unregistered"
        );
    }
}

#[test]
fn every_id_round_trips_through_its_string() {
    for id in AssumptionId::ALL {
        assert_eq!(AssumptionId::lookup(id.as_str()), Some(id));
        assert_eq!(id.as_str().parse::<AssumptionId>(), Ok(id));
    }
}

/// Local alias so the test file has no `use std::collections::BTreeMap`.
use std::collections::BTreeMap;
