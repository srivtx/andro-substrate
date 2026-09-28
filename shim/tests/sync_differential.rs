//! The sync differential: the control that turns a demonstration into a claim
//! it is entitled to — and, on this workload, into a demonstration that it is
//! not entitled to a measurement at all.
//!
//! # What is being tested
//!
//! | claim | tests |
//! |---|---|
//! | a deterministic workload reports **zero** variance, and that is reported as zero rather than dressed up | [`a_deterministic_workload_reports_zero_variance`] |
//! | the control **detects** variability when there is variability, using the one policy value the shim itself declares non-reproducible | [`a_non_reproducible_substrate_is_detected_as_varying`], [`variability_introduced_into_the_documents_is_detected`] |
//! | the four-way classification is **exhaustive and disjoint** over the leaf set | [`the_four_way_classification_is_exhaustive_over_the_leaf_set`], [`each_class_is_reachable_and_disjoint`] |
//! | a leaf that varies under sync is **never** called substrate-determined | [`a_leaf_that_varies_under_sync_is_never_substrate_determined`] |
//! | the sync arm is the *same runs* as the committed policy differential, not a parallel invention | [`the_sync_arm_reproduces_the_committed_recordings_byte_for_byte`] |
//! | the correction to the earlier result is computed, not asserted | [`the_unmoved_count_is_recomputed_and_agrees_with_the_differential`] |
//! | the new code path is inside the egress and redaction invariants | [`the_sync_path_cannot_reach_a_socket_on_any_reproducible_axis_combination`], [`no_sync_arm_can_capture_a_body_a_header_or_a_query_value`] |

use shim::differential;
use shim::policy::{Axis, FactClass, SubstratePolicy, TimeMode};
use shim::syncdiff::{self, Arm, Attribution, Workload, COMMITTED_RUNS, MIN_RUNS};

/// The two policies the committed policy differential uses.
fn committed() -> (SubstratePolicy, SubstratePolicy) {
    differential::committed_policies()
}

/// The full experiment over the committed pair. Sixteen scenario runs, about two
/// seconds; the tests below that need it share one via `OnceLock` so the suite
/// does not pay for it repeatedly.
fn committed_experiment() -> &'static syncdiff::SyncDifferential {
    use std::sync::OnceLock;
    static D: OnceLock<syncdiff::SyncDifferential> = OnceLock::new();
    D.get_or_init(|| {
        let (l, r) = committed();
        syncdiff::run(l, r, COMMITTED_RUNS).expect("sync differential")
    })
}

/// The positive control, shared: sixteen more scenario runs, and four tests want
/// them.
fn non_reproducible_experiment() -> &'static syncdiff::SyncDifferential {
    use std::sync::OnceLock;
    static D: OnceLock<syncdiff::SyncDifferential> = OnceLock::new();
    D.get_or_init(|| {
        let hr = SubstratePolicy::default()
            .with(Axis::Time, "host_real")
            .expect("host_real is a declared value");
        syncdiff::run(hr, hr, COMMITTED_RUNS).expect("control")
    })
}

// =========================================================== 1. the zero result

#[test]
fn a_deterministic_workload_reports_zero_variance() {
    let d = committed_experiment();
    assert_eq!(
        d.runs, COMMITTED_RUNS,
        "a control below {} is not a measurement; the committed arm must use at least that many",
        MIN_RUNS
    );
    assert!(
        d.runs >= MIN_RUNS,
        "COMMITTED_RUNS is below the floor the module declares"
    );
    // The headline of this file, and it is a zero.
    assert_eq!(
        d.left_sync_varying(),
        0,
        "the scenario is a fixed call sequence with a virtual clock; it must be byte-identical"
    );
    assert_eq!(d.right_sync_varying(), 0);
    assert!(d.false_negatives.is_empty());
    assert!(
        d.report().contains("0 MOVE BETWEEN IDENTICAL RUNS"),
        "the report must state the zero in the correction section, not bury it"
    );
    // And the zero must be reported AS a zero, with its licence attached, because
    // a control that returns zero on a deterministic input is the single easiest
    // result in the project to over-claim. Matched on fragments that do not cross
    // a line break, since the report is hard-wrapped.
    let r = d.report();
    for fragment in [
        "A zero noise floor here is a fact about a fixed call sequence",
        "It does NOT convert the earlier",
        "number into a measurement",
        "degenerate with respect to the",
    ] {
        assert!(r.contains(fragment), "missing {fragment:?} from the report");
    }
}

#[test]
fn the_report_never_presents_the_earlier_number_as_a_measurement() {
    let d = committed_experiment();
    let r = d.report();
    assert!(r.contains("demonstration"), "{r}");
    // And the differential's own report, which is the document the 1432 came
    // from, has to carry the correction too.
    let d2 = differential::run(committed().0, committed().1).expect("differential");
    let rep = d2.report();
    for fragment in [
        "demonstration that the",
        "attribution MECHANISM works",
        "It is",
        "not a measurement of any app",
        "0007-sync-differential",
    ] {
        assert!(
            rep.contains(fragment),
            "differential.report.txt is missing {fragment:?}"
        );
    }
    // And the corrected arithmetic is what the committed report now says.
    assert!(
        rep.contains("1486 of 1617 compared leaves are byte-identical"),
        "the corrected unmoved count is not in the report"
    );
    assert!(
        !rep.contains("1432 of 1617"),
        "the undercount is still in the committed report"
    );
}

// ====================================================== 2. the control has power

#[test]
fn a_non_reproducible_substrate_is_detected_as_varying() {
    // The positive control, and it is not manufactured: `time: host_real` is an
    // axis value the shim already had, already declared `reproducible: false`,
    // and it reads the host's wall clock. If the control cannot see this, the
    // zero in the previous test means nothing.
    let d = non_reproducible_experiment();
    assert!(
        !d.left.policy.reproducible(),
        "the positive control must be a substrate the shim itself declares non-reproducible"
    );
    let moving = d.left_sync_varying();
    assert!(
        moving > 0,
        "eight runs of a substrate that reads the host clock produced {} identical documents; the \
         control is not seeing the only nondeterminism this crate has",
        d.runs
    );
    // And the leaves it found are clock observations, which is the check that
    // the control found *this* variance and not some other one. The count is a
    // lower bound rather than a fixed number: two runs whose host-clock read
    // lands in the same millisecond are byte-identical, so it moves with the
    // machine. Which is exactly why the artefact does not commit it.
    //
    // The set is also not fixed — `Thread.sleep` reports the elapsed time the
    // axis presented, so `SIGNAL_PAT.SLEEP` moves too when the host clock has
    // advanced a millisecond between two reads. So the assertion is on the
    // *taxonomy token*, not on a hand-listed set of patterns: every moving leaf
    // must be a pattern the `time` axis governs.
    for v in d.verdicts.iter().filter(|v| v.sync_varies()) {
        assert_eq!(
            v.class,
            FactClass::Time,
            "{} moved but is not a clock fact; the control is picking up something it should not",
            v.pointer
        );
        let token = v
            .pointer
            .split("SIGNAL_PAT.")
            .nth(1)
            .and_then(|rest| rest.split([']', ' ']).next())
            .unwrap_or("");
        assert_eq!(
            differential::pattern_class(&format!("SIGNAL_PAT.{token}")),
            FactClass::Time,
            "{} moved but the pattern it carries is not one the time axis governs",
            v.pointer
        );
    }
    // Under the strict value-set rule these cannot be called substrate-determined:
    // both arms read the clock, so both value sets differ and no policy changed.
    for v in d.verdicts.iter().filter(|v| v.sync_varies()) {
        assert!(
            !v.is_substrate_determined(),
            "{} wanders and was called substrate-determined",
            v.pointer
        );
    }
}

/// Build N documents from a template, each carrying a policy declaration.
///
/// The control's arithmetic is a pure function of documents, so a test can hand
/// it documents with a known perturbation and check the four-way table directly —
/// which is the only way to reach the `both` and `sync_varies` buckets on a
/// workload that has no nondeterminism of its own.
///
/// `mutate` receives the run index and the document. A key it never sets is
/// present in every run with its template value, and a key it *removes* is the
/// absence-is-a-value case.
fn documents(
    policy: &SubstratePolicy,
    n: usize,
    mutate: &dyn Fn(usize, &mut serde_json::Value),
) -> Vec<serde_json::Value> {
    (0..n)
        .map(|i| {
            let mut v = serde_json::json!({
                "steady": "same",
                "policy_moved": "template",
                "sync_only": "template",
                "both_arms": "template",
                "capture": { "nested": "same" },
            });
            mutate(i, &mut v);
            if let Some(o) = v.as_object_mut() {
                o.insert("substrate_policy".into(), policy.to_json());
            }
            v
        })
        .collect()
}

fn arm(policy: SubstratePolicy, docs: Vec<serde_json::Value>) -> Arm {
    Arm {
        policy,
        documents: docs,
    }
}

#[test]
fn variability_introduced_into_the_documents_is_detected() {
    let p = SubstratePolicy::default();
    let q = p.with(Axis::Network, "synthetic_loopback").expect("q");

    // `sync_only` takes a different value on every run, and the SAME value in the
    // same run of the other arm. That is the shape of a `HashMap` iteration
    // order, or a frame that landed differently: a leaf that moves with no
    // policy change, and whose two value sets are equal.
    let left = arm(
        p,
        documents(&p, 5, &|i, v| {
            v["sync_only"] = serde_json::json!(i);
            v["policy_moved"] = serde_json::json!("left");
        }),
    );
    let right = arm(
        q,
        documents(&q, 5, &|i, v| {
            v["sync_only"] = serde_json::json!(i);
            v["policy_moved"] = serde_json::json!("right");
        }),
    );
    let d = syncdiff::decompose(left, right, Workload::Script).expect("decompose");
    let by = |p: &str| {
        d.verdicts
            .iter()
            .find(|v| v.pointer == p)
            .unwrap_or_else(|| {
                panic!(
                    "no leaf at {p}; the universe is {:?}",
                    d.verdicts
                        .iter()
                        .map(|v| v.pointer.clone())
                        .collect::<Vec<_>>()
                )
            })
    };

    let w = by("/sync_only");
    assert!(
        w.sync_varies(),
        "a leaf that took 5 values over 5 runs did not vary"
    );
    assert_eq!(w.left_values.len(), 5);
    assert!(!w.policy_varies(), "both arms hold the same set of values");
    assert_eq!(w.verdict, Attribution::SyncVaries);

    let pm = by("/policy_moved");
    assert!(pm.policy_varies());
    assert!(!pm.sync_varies());
    assert_eq!(pm.verdict, Attribution::PolicyVaries);
    assert!(pm.is_substrate_determined());

    let s = by("/steady");
    assert_eq!(s.verdict, Attribution::Stable);
    assert_eq!(by("/capture/nested").verdict, Attribution::Stable);

    // And this is the correction, computed rather than asserted: the
    // two-document differential called `sync_only` unmoved, because run 0 of each
    // arm happened to agree, and the control says otherwise.
    assert!(
        d.policy_diff
            .moved
            .iter()
            .all(|m| m.difference.pointer != "/sync_only"),
        "the single-run diff should not have seen it"
    );
    assert!(
        d.false_negatives.contains(&"/sync_only".to_string()),
        "the wandering leaf is exactly the false negative the control exists to find; got {:?}",
        d.false_negatives
    );
    assert!(
        !d.false_positives.contains(&"/sync_only".to_string()),
        "and it was not a false positive, because the single-run diff got it wrong in the other \
         direction"
    );
}

#[test]
fn an_absence_is_a_value_and_varies_like_one() {
    // A leaf present on some runs and not others is the nondeterminism an
    // inserted diagnostic or an early-returning branch produces, and it is
    // invisible to a diff that only compares leaves present on both sides.
    let p = SubstratePolicy::default();
    let q = p;
    let left = arm(
        p,
        documents(&p, 4, &|i, v| {
            if i % 2 == 0 {
                v["sync_only"] = serde_json::json!("present");
            } else if let Some(o) = v.as_object_mut() {
                o.remove("sync_only");
            }
        }),
    );
    let right = arm(
        q,
        documents(&q, 4, &|i, v| {
            if i % 2 == 0 {
                v["sync_only"] = serde_json::json!("present");
            } else if let Some(o) = v.as_object_mut() {
                o.remove("sync_only");
            }
        }),
    );
    let d = syncdiff::decompose(left, right, Workload::Script).expect("decompose");
    let w = d
        .verdicts
        .iter()
        .find(|v| v.pointer == "/sync_only")
        .expect("the leaf is in the universe");
    assert!(w.sync_varies());
    assert_eq!(w.left_values.len(), 2, "one value plus one absence");
    assert!(w.left_values.iter().any(Option::is_none));
    assert!(!w.is_substrate_determined());
}

#[test]
fn a_wandering_leaf_under_one_policy_and_a_stable_one_under_the_other_is_both() {
    // The coincidence bucket. Both arms run `host_real`, so both wander; the
    // value sets differ, so a set comparison calls the leaf policy-varying, and
    // the repetition says it is not stable. `Both` is the only honest verdict.
    let d = non_reproducible_experiment();
    let both = d.in_class(Attribution::Both);
    assert!(
        !both.is_empty(),
        "the non-reproducible substrate produced no `both` leaves; the coincidence bucket is \
         unreachable and therefore untested"
    );
    for v in &both {
        assert!(v.sync_varies(), "{} is `both` but stable", v.pointer);
        assert!(
            v.policy_varies(),
            "{} is `both` but policy-invariant",
            v.pointer
        );
    }
    // Same policy on both sides, so `PolicyVaries` can only be reached by a
    // wandering leaf that the strict rule happens to let through. It must not be.
    assert_eq!(
        d.count(Attribution::PolicyVaries),
        0,
        "no policy changed between the arms, so nothing is substrate-determined"
    );
}

// ================================================== 3. the table is a partition

#[test]
fn the_four_way_classification_is_exhaustive_over_the_leaf_set() {
    for d in [
        committed_experiment(),
        &syncdiff::run(
            SubstratePolicy::default()
                .with(Axis::Time, "host_real")
                .expect("hr"),
            SubstratePolicy::default()
                .with(Axis::Time, "host_real")
                .expect("hr"),
            COMMITTED_RUNS,
        )
        .expect("control"),
    ] {
        let total: usize = d.counts().iter().map(|(_, n)| n).sum();
        assert_eq!(
            total,
            d.verdicts.len(),
            "the four classes must partition the leaf set; the counts sum to {total} over {} leaves",
            d.verdicts.len()
        );
        // Disjoint as well as exhaustive, which the sum alone does not prove.
        for a in Attribution::all() {
            for b in Attribution::all() {
                if a == b {
                    continue;
                }
                assert!(
                    d.in_class(a)
                        .iter()
                        .all(|v| d.in_class(b).iter().all(|w| w.pointer != v.pointer)),
                    "{a:?} and {b:?} overlap"
                );
            }
        }
        // And the pointers are unique, so a leaf cannot be counted twice.
        let mut seen = std::collections::BTreeSet::new();
        for v in &d.verdicts {
            assert!(
                seen.insert(v.pointer.clone()),
                "{} counted twice",
                v.pointer
            );
        }
    }
}

#[test]
fn each_class_is_reachable_and_disjoint() {
    // A hand-built table exercising all four, so the partition is not only
    // arithmetically true but visibly correct.
    let p = SubstratePolicy::default();
    let q = p;
    let left = arm(
        p,
        documents(&p, 4, &|i, v| {
            v["sync_only"] = serde_json::json!(i);
            v["both_arms"] = serde_json::json!(i);
            v["policy_moved"] = serde_json::json!("L");
            v["steady"] = serde_json::json!("S");
        }),
    );
    let right = arm(
        q,
        documents(&q, 4, &|i, v| {
            v["sync_only"] = serde_json::json!(i);
            v["both_arms"] = serde_json::json!(i + 100);
            v["policy_moved"] = serde_json::json!("R");
            v["steady"] = serde_json::json!("S");
        }),
    );
    let d = syncdiff::decompose(left, right, Workload::Script).expect("decompose");
    let want = [
        ("/both_arms", Attribution::Both),
        ("/policy_moved", Attribution::PolicyVaries),
        ("/steady", Attribution::Stable),
        ("/sync_only", Attribution::SyncVaries),
    ];
    for (p, want) in want {
        let v = d
            .verdicts
            .iter()
            .find(|v| v.pointer == p)
            .unwrap_or_else(|| panic!("{p} missing"));
        assert_eq!(v.verdict, want, "{p}");
    }
    for (a, n) in d.counts() {
        assert!(
            n >= 1,
            "{a:?} is unreachable in a table that should reach all four"
        );
    }
}

#[test]
fn a_leaf_that_varies_under_sync_is_never_substrate_determined() {
    // The invariant the whole module exists to protect, asserted as a sweep over
    // every leaf of every experiment in this file rather than as one example.
    let p = SubstratePolicy::default();
    let experiments = [
        committed_experiment(),
        non_reproducible_experiment(),
        &syncdiff::run(p, p, COMMITTED_RUNS).expect("same policy"),
    ];
    let mut checked = 0usize;
    for d in &experiments {
        for v in &d.verdicts {
            if v.sync_varies() {
                assert!(
                    !v.is_substrate_determined(),
                    "{} varies under repetition and was called substrate-determined",
                    v.pointer
                );
                assert_ne!(v.verdict, Attribution::PolicyVaries, "{}", v.pointer);
            }
            // The converse also has to hold for the count to mean anything.
            if v.verdict == Attribution::PolicyVaries {
                assert!(v.policy_varies(), "{} varies across policies", v.pointer);
                assert!(!v.sync_varies(), "{} is stable under repetition", v.pointer);
            }
            checked += 1;
        }
    }
    assert!(
        checked > 3000,
        "only {checked} leaves swept; the sweep is not running"
    );
}

// ============================================== 4. it is the same experiment

#[test]
fn the_sync_arm_reproduces_the_committed_recordings_byte_for_byte() {
    // Not a parallel invention: the sync arm runs `scenario::run_with`, so its
    // run 0 must be the very file the policy differential was computed from.
    // If this fails, the two results are about different programs and the
    // intersection between them means nothing.
    let d = committed_experiment();
    let left = d.left.rendered()[0].trim_end().to_string();
    let right = d.right.rendered()[0].trim_end().to_string();
    assert_eq!(
        left,
        include_str!("../recordings/differential-left.fabricated.recording.json").trim_end(),
        "the sync arm's left run 0 is not the committed left recording"
    );
    assert_eq!(
        right,
        include_str!("../recordings/differential-right.loud.recording.json").trim_end(),
        "the sync arm's right run 0 is not the committed right recording"
    );
    // And all N runs of a reproducible arm really are the same bytes.
    let lr = d.left.rendered();
    assert!(
        lr.windows(2).all(|w| w[0] == w[1]),
        "a reproducible policy produced two different documents"
    );
}

#[test]
fn the_unmoved_count_is_recomputed_and_agrees_with_the_differential() {
    // Two independent derivations of the same number: the walk counts it as it
    // goes, the sync arm recomputes it from leaf addresses. If they ever differ,
    // the intersection in the report is arithmetic on unrelated numbers.
    let d = committed_experiment();
    assert_eq!(
        d.previously_unmoved, d.policy_diff.identical_leaves,
        "the sync arm and the differential disagree about how many leaves did not move"
    );
    assert_eq!(
        d.previously_unmoved + (d.policy_diff.compared_leaves - d.previously_unmoved),
        d.policy_diff.compared_leaves
    );
    // And the corrected figure, which supersedes the committed 1432.
    assert_eq!(
        d.policy_diff.identical_leaves, 1486,
        "the unmoved count changed; the committed report's 1432 came from subtracting \
         one-sided differences from the compared count and was an undercount"
    );
    assert_eq!(d.previously_moved + d.previously_unmoved, d.verdicts.len());
}

#[test]
fn the_policy_effect_is_stable_across_every_pairing() {
    let d = committed_experiment();
    let pairs = (d.runs * d.runs) as i128;
    for v in d.verdicts.iter().filter(|v| v.policy_varies()) {
        assert_eq!(
            v.cross_pairs_disagreeing as i128, pairs,
            "{} disagreed in only {} of {pairs} pairings: on a deterministic input every pairing \
             must agree, and a leaf that does not is either a cancellation bug or real variance",
            v.pointer, v.cross_pairs_disagreeing
        );
    }
    // Every leaf that is stable under repetition and identical across policies
    // agrees in every pairing too, which is the rest of the partition.
    for v in d.verdicts.iter().filter(|v| !v.policy_varies()) {
        assert_eq!(v.cross_pairs_disagreeing, 0, "{}", v.pointer);
    }
}

// ==================================================== 5. it refuses bad input

#[test]
fn a_single_run_is_refused_because_it_is_the_thing_this_replaces() {
    let e = syncdiff::repeat(SubstratePolicy::default(), 1).expect_err("n=1 must be refused");
    assert!(e.to_string().contains("single run"), "{e}");
}

// The floors are compile-time facts about the crate, so they are asserted where
// they are declared rather than at run time: an `assert!` over two constants is
// either always true or already a compile error, and a comment goes stale where
// a check does not.
const _: () = {
    assert!(
        MIN_RUNS >= 5,
        "the declared floor must be at least five runs"
    );
    assert!(
        COMMITTED_RUNS >= MIN_RUNS,
        "the committed arm is below the floor"
    );
    assert!(
        MIN_RUNS < COMMITTED_RUNS,
        "the committed arm should exceed the floor"
    );
};

#[test]
fn arms_of_unequal_length_are_refused() {
    let p = SubstratePolicy::default();
    let l = syncdiff::repeat(p, 2).expect("left");
    let r = syncdiff::repeat(p, 3).expect("right");
    let e = syncdiff::decompose(l, r, Workload::Script).expect_err("unequal N must be refused");
    assert!(e.to_string().contains("unequal N"), "{e}");
}

// ============================================== 6. the invariants still hold

#[test]
fn the_sync_path_cannot_reach_a_socket_on_any_reproducible_axis_combination() {
    // The 162-combination egress sweep, extended to the new code path. The sync
    // arm's only new capability is running the whole scenario repeatedly and
    // then reasoning about the resulting documents, so the egress question is
    // whether any document the new path produces says a byte left. N = 2 and not
    // MIN_RUNS because the egress property is per-event and does not depend on
    // N; N bounds the *measurement* claim, not the structural invariant, and this
    // test is about the structural invariant. `decompose` is exercised separately
    // over the committed pair, where it is the analysis and not a network
    // surface.
    for policy in reproducible_policies() {
        let arm = syncdiff::repeat(policy, 2).expect("repeat");
        assert_every_attempt_blocked(&arm.documents[0]);
        assert_every_attempt_blocked(&arm.documents[1]);
    }
}

/// Assert that nothing in a document says a byte left the substrate.
fn assert_every_attempt_blocked(doc: &serde_json::Value) {
    use serde_json::Value as J;
    let net = doc.get("network").expect("a document has a network block");
    let attempts = net.get("attempts").and_then(J::as_array).expect("attempts");
    assert!(
        !attempts.is_empty(),
        "a run that made no attempt proved nothing"
    );
    let axis = doc
        .get("substrate_policy")
        .and_then(|p| p.get("network"))
        .and_then(J::as_str)
        .unwrap_or("?");
    for a in attempts {
        assert_eq!(
            a.get("result").and_then(J::as_str),
            Some("blocked_by_policy"),
            "an attempt resolved under network = {axis}"
        );
    }
    assert_eq!(
        doc.get("environment")
            .and_then(|e| e.get("network"))
            .and_then(|n| n.get("egress_available"))
            .and_then(J::as_bool),
        Some(false),
        "egress_available moved under network = {axis}"
    );
    if let Some(t) = net.get("byte_totals_observed") {
        for side in ["tx_bytes", "rx_bytes"] {
            if let Some(v) = t.get(side) {
                assert_eq!(v.as_u64(), Some(0), "{side} moved under {axis}");
            }
        }
    }
}

#[test]
fn no_sync_arm_can_capture_a_body_a_header_or_a_query_value() {
    // The redaction invariant, extended to the new code path. The sync arm runs
    // the scenario, and the scenario is the script that builds a signed URL, sets
    // an `Authorization` header and writes a 512-byte body; if a repeated or
    // decomposed run could surface any of it, the invariant would be broken by
    // repetition rather than by a single run.
    const BODY: &str = "sync-canary-body-7d1e-do-not-record";
    const HEADER: &str = "Bearer sync-canary-3a9f-do-not-record";
    const QUERY: &str = "sync-canary-sig-2b4c-do-not-record";

    let d = syncdiff::run(
        SubstratePolicy::default(),
        SubstratePolicy::default()
            .with(Axis::Network, "synthetic_loopback")
            .expect("loopback"),
        COMMITTED_RUNS,
    )
    .expect("sync differential");
    for doc in d.left.documents.iter().chain(&d.right.documents) {
        let text = serde_json::to_string(doc).expect("serialise");
        for c in [BODY, HEADER, QUERY] {
            assert!(
                !text.contains(c),
                "a canary survived into a sync-arm document"
            );
        }
        // The scenario's own canaries, which are in the committed recording's
        // fixture: a repeated run must not start recording them either.
        for c in [
            shim::scenario::CANARY_QUERY_VALUE,
            shim::scenario::CANARY_HEADER_VALUE,
        ] {
            assert!(
                !text.contains(c),
                "a scenario canary survived into a sync-arm document"
            );
        }
    }
    // And the same gate the binaries apply, over the whole report.
    let report = format!("{}{}", d.left.rendered()[0], d.report());
    assert!(shim::redact::scrub(&report, &[]).is_ok());
    let _ = HEADER;
    let _ = BODY;
    let _ = QUERY;
}

/// Every reproducible policy: the same 162 combinations `tests/policy.rs` sweeps
/// for egress, enumerated as a flat list so this sweep covers each exactly once.
fn reproducible_policies() -> Vec<SubstratePolicy> {
    use shim::policy::{IdentityMode, NetworkMode, PackageMode, SystemFsMode};
    let mut out = Vec::with_capacity(162);
    for identity in [
        IdentityMode::Fabricated,
        IdentityMode::Withheld,
        IdentityMode::Refusing,
    ] {
        for system_fs in [
            SystemFsMode::Fabricated,
            SystemFsMode::Empty,
            SystemFsMode::Absent,
        ] {
            for packages in [
                PackageMode::SubjectOnly,
                PackageMode::AllPresent,
                PackageMode::Error,
            ] {
                for network in [NetworkMode::RecordAndDeny, NetworkMode::SyntheticLoopback] {
                    for time in [
                        TimeMode::Virtual,
                        TimeMode::Scaled {
                            numerator: 2,
                            denominator: 1,
                        },
                        TimeMode::Frozen,
                    ] {
                        out.push(SubstratePolicy {
                            identity,
                            system_fs,
                            cross_app_packages: packages,
                            network,
                            time,
                        });
                    }
                }
            }
        }
    }
    assert_eq!(out.len(), 162, "the axis vocabulary changed");
    out
}

// ================================================= 7. the committed artefact

#[test]
fn the_committed_sync_report_is_current() {
    // Regeneration is checked, not asserted: change a handler and this fails,
    // which is the correct outcome for an artefact an analyst will cite.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_shim-sync-differential"))
        .output()
        .expect("run shim-sync-differential");
    assert!(out.status.success(), "shim-sync-differential failed");
    let text = String::from_utf8(out.stdout).expect("utf-8");

    let mut sections: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.starts_with("==== ") && line.ends_with(" ====") {
            sections.push((line.to_string(), String::new()));
            continue;
        }
        if let Some(last) = sections.last_mut() {
            last.1.push_str(line);
            last.1.push('\n');
        }
    }
    let headers: Vec<&String> = sections.iter().map(|(h, _)| h).collect();
    assert_eq!(
        headers.len(),
        4,
        "two arms, one control, one report: {headers:?}"
    );
    let report = sections.last().expect("the report section").1.trim_end();
    assert_eq!(
        text.trim_end(),
        include_str!("../recordings/sync-differential.report.txt").trim_end(),
        "shim/recordings/sync-differential.report.txt is stale; regenerate with the command in \
         shim/recordings/README.md"
    );
    assert!(headers[0].contains(&differential::arm_label(&committed().0)));
    assert!(headers[1].contains(&differential::arm_label(&committed().1)));
    assert!(headers[2].contains("host_real"), "{headers:?}");
    // The numbers a reader will quote, asserted so a report that says something
    // else cannot be committed by accident.
    assert!(
        report.contains("OF ITS 1486 UNMOVED LEAVES, 0 MOVE BETWEEN IDENTICAL RUNS"),
        "{report}"
    );
    assert!(report.contains("SUBSTRATE-DETERMINED: 345"), "{report}");
    assert!(report.contains("policy_varies 345"), "{report}");
    assert!(report.contains("sync_varies   0"), "{report}");
    assert!(report.contains("both          0"), "{report}");
    assert!(report.contains("stable        1486"), "{report}");
}

#[test]
fn the_control_section_reports_the_nondeterminism_it_found() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_shim-sync-differential"))
        .output()
        .expect("run shim-sync-differential");
    let text = String::from_utf8(out.stdout).expect("utf-8");
    // The stable claims, which is all the artefact is allowed to make about an
    // arm whose values depend on the host clock.
    assert!(text.contains("reproducible: false"));
    assert!(
        text.contains("ITS COUNTS ARE DELIBERATELY NOT COMMITTED"),
        "the artefact must not commit a number that changes with machine load"
    );
    // And the control really does find variance, asserted as a bound rather than
    // as a committed integer: two runs whose host-clock read lands in the same
    // millisecond are identical, so the count is a lower bound and moves with
    // the machine.
    let d = non_reproducible_experiment();
    assert!(
        d.left_sync_varying() > 0,
        "the control found no varying leaf, so nothing here demonstrates the control has power"
    );
    for v in d.verdicts.iter().filter(|v| v.sync_varies()) {
        assert_eq!(
            v.class,
            FactClass::Time,
            "{} moved under a host-clock arm and is not classified as a clock fact",
            v.pointer
        );
    }
}
