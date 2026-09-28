//! The **sync differential**: the control the policy differential was missing.
//!
//! # The gap this closes
//!
//! [`crate::differential`] runs one script under two policies and attributes
//! every moved fact. Its own module docs, and ADR 0006, name the flaw it cannot
//! see:
//!
//! > It cannot separate the substrate from the app's own nondeterminism, and
//! > every conclusion from the committed differential rests on the script being
//! > deterministic.
//!
//! The fix is a second axis of repetition. Run the **same** workload N times
//! under the **same** policy and diff those N documents against each other.
//! Whatever moves between them moved without any substrate decision changing, so
//! it is app + interpreter, not substrate. Only then does "moved across
//! policies" mean anything.
//!
//! # The decomposition, and why the categories are not collapsed
//!
//! For one leaf, over N runs of the left policy and N of the right:
//!
//! | class | moves under repetition | moves across policies | what may be claimed |
//! |---|---|---|---|
//! | [`Attribution::PolicyVaries`] | no | yes | **substrate-determined** — the only bucket that licenses the claim |
//! | [`Attribution::SyncVaries`] | yes | no | app + interpreter. The policy differential called this leaf unmoved; that is a **false negative** |
//! | [`Attribution::Both`] | yes | yes | substrate and program both acted. Unattributable |
//! | [`Attribution::Stable`] | no | no | nothing, in either direction |
//!
//! The asymmetry is the point. A leaf in `SyncVaries` is the correction the
//! earlier result owes: it was reported as not moving, and it does. A leaf in
//! `Both` is a *worse* problem than either half — the substrate changed it and
//! the program wanders across it, so not even the size of the effect is
//! measurable from N runs. Neither bucket is folded into the other, and
//! `stable` is never reported as a positive result.
//!
//! # Definitions, stated so they can be argued with
//!
//! * **`sync_varies`** — the leaf's observed value is not constant across the N
//!   runs of one arm, or not constant across the N of the other. Absence counts
//!   as a value, so an array element emitted on some runs and not others varies.
//! * **`policy_varies`** — the *set* of values observed under the left policy is
//!   not the set observed under the right. Deliberately the strict comparison:
//!   two policies that both wander produce unequal value sets even where the
//!   substrate had nothing to do with it, and `Both` is the correct verdict for
//!   that. The cost is stated in the report; the benefit is that
//!   `PolicyVaries` can never be reached by a wandering leaf.
//! * **`unmoved_by_policy_diff`** — the value at run 0 of each arm is equal and
//!   the pointer is present in both. That is exactly what the two-document
//!   differential decided, at exactly its granularity, so the intersection below
//!   is against the earlier verdict and not against a re-derivation of it.
//! * **`substrate_determined`** is `PolicyVaries` and nothing else. It is a
//!   predicate on one bucket, not a fifth bucket, so the four counts always sum
//!   to the leaf set.
//!
//! # What this cannot do, and will not pretend to
//!
//! The control measures the noise floor **of the workload it is given**. This
//! crate's workload is a fixed, branch-free call sequence with a virtual clock
//! advanced by literals, so it is deterministic; the measured floor is zero, and
//! a zero floor licenses exactly one thing, which is that *this input* has no
//! nondeterminism for a substrate effect to hide in. It says nothing about an
//! APK, because there is no APK here for the nondeterminism to come from. The
//! shim declares one axis value
//! ([`TimeMode::HostReal`](crate::policy::TimeMode::HostReal)) to be
//! `reproducible: false`; running the sync arm under it is how the control is
//! shown to have power without inventing any.
//!
//! What survives even a perfectly working control: a nondeterministic leaf and a
//! substrate effect can coincide, and a per-run nondeterminism of probability `p`
//! slips past an N-run arm with probability `(1-p)^(N-1)`. The report prints that
//! at three representative `p` rather than leaving the reader to assume it is
//! zero.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value as J;

use crate::differential::{self, leaves, Differential, Leaf};
use crate::policy::{FactClass, SubstratePolicy};

/// The number of runs the committed sync arm uses.
///
/// N ≥ 5 is a floor and not a preference: ADR 0006's own second objection is
/// that "one diff cannot distinguish a small substrate effect from a large app
/// effect that happened to cancel", and a control with two runs has exactly that
/// problem. Eight is the smallest round number comfortably above the floor, and
/// the report states the escape probability it buys rather than claiming the
/// floor is the floor.
pub const COMMITTED_RUNS: usize = 8;

/// The smallest N at which a control may be described as a measurement.
///
/// Below this, a zero result is too weak to say anything: a two-run "control" is
/// the same single diff ADR 0006 says is not a measurement.
pub const MIN_RUNS: usize = 5;

/// What kind of evidence there is, and what it licenses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Workload {
    /// The synthetic script: a fixed, branch-free call sequence with a virtual
    /// clock. Deterministic by construction, so a zero noise floor is a fact
    /// about the *input* and not about any app.
    Script,
}

impl Workload {
    /// The label that goes in the report, so an artefact says what it measured.
    pub fn as_str(self) -> &'static str {
        match self {
            Workload::Script => {
                "shim::scenario::run_with (one function, no per-policy branch, virtual clock \
                 advanced by literals)"
            }
        }
    }

    /// What a result under this workload does and does not license. Written out
    /// in full because the licence is the deliverable, not the count.
    pub fn license(self) -> &'static str {
        match self {
            Workload::Script => {
                "A zero noise floor here is a fact about a fixed call sequence, not about any app. \
                 It shows the control is wired up and that this input is deterministic. It cannot \
                 detect app nondeterminism, because there is no app in the input: no HashMap to \
                 reorder, no retry, no locale, no frame callback. The earlier 1432-of-1617 figure \
                 therefore remains a demonstration of the attribution mechanism, and the existence \
                 of this control does not upgrade it to a measurement."
            }
        }
    }
}

/// The four-way classification of one leaf.
///
/// Named after the question each answers, and deliberately not named after the
/// conclusion, so that reading a bucket's name never pre-supplies its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attribution {
    /// Moved across policies, did not move across repetitions. The **only**
    /// bucket in which the substrate-determined claim is licensed.
    PolicyVaries,
    /// Moved across repetitions, did not move across policies. App plus
    /// interpreter; a false negative in any differential that called it unmoved.
    SyncVaries,
    /// Moved in both. The substrate decided something and the program wanders
    /// across it; unattributable at any sample size.
    Both,
    /// Moved in neither. Says nothing, in either direction.
    Stable,
}

impl Attribution {
    /// Every class, in report order.
    pub fn all() -> [Attribution; 4] {
        [
            Attribution::PolicyVaries,
            Attribution::SyncVaries,
            Attribution::Both,
            Attribution::Stable,
        ]
    }

    /// The token used in the report and in the committed artefact.
    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::PolicyVaries => "policy_varies",
            Attribution::SyncVaries => "sync_varies",
            Attribution::Both => "both",
            Attribution::Stable => "stable",
        }
    }

    /// What may be said about a leaf in this bucket. Written out for each one,
    /// because the temptation to read `both` as "some of it is the substrate" is
    /// exactly the collapse this module exists to prevent.
    pub fn license(self) -> &'static str {
        match self {
            Attribution::PolicyVaries => {
                "SUBSTRATE-DETERMINED. Stable under repetition and changed across policies: the \
                 substrate decided this leaf. This is the strongest claim the harness supports."
            }
            Attribution::SyncVaries => {
                "APP + INTERPRETER. Moved without any policy changing, so any policy-to-policy \
                 diff that called this leaf unmoved got it wrong."
            }
            Attribution::Both => {
                "UNATTRIBUTABLE. The substrate changed this leaf AND the program wanders across \
                 it. Neither the fact of the change nor its size can be attributed from these \
                 runs; no N separates a substrate effect from an app effect acting on the same \
                 leaf."
            }
            Attribution::Stable => {
                "NOTHING CLAIMED. It did not move under repetition and did not move across \
                 policies. That is equally consistent with 'determined by the app' and with 'not \
                 exercised here'."
            }
        }
    }

    /// Whether the substrate-determined claim is licensed for this bucket.
    pub fn is_substrate_determined(self) -> bool {
        matches!(self, Attribution::PolicyVaries)
    }
}

/// One leaf, pooled over every run in the experiment.
#[derive(Debug, Clone)]
pub struct LeafVerdict {
    /// The unique pointer, as [`differential::leaves`] addresses it.
    pub pointer: String,
    /// The pointer the two-document differential would have used, which is the
    /// same pointer for every sibling sharing a repeated array identity.
    pub base: String,
    /// The class the classifier assigns.
    pub class: FactClass,
    /// The bucket.
    pub verdict: Attribution,
    /// The distinct values seen under the left policy, in first-seen order.
    pub left_values: Vec<Option<J>>,
    /// The distinct values seen under the right policy.
    pub right_values: Vec<Option<J>>,
    /// The value each arm presented at run 0, i.e. the two documents the
    /// two-document differential actually compared.
    pub left_first: Option<J>,
    /// The value the right arm presented at run 0.
    pub right_first: Option<J>,
    /// How many of the N×N left/right pairings disagreed on this leaf. The direct
    /// answer to "how much of the policy effect is stable across repetitions":
    /// `runs²` means every pairing disagreed, `1` means exactly one did.
    pub cross_pairs_disagreeing: usize,
}

impl LeafVerdict {
    /// Whether the leaf moved under repetition of either arm.
    pub fn sync_varies(&self) -> bool {
        self.left_values.len() > 1 || self.right_values.len() > 1
    }

    /// Whether the leaf moved under repetition of the left arm alone.
    pub fn left_sync_varies(&self) -> bool {
        self.left_values.len() > 1
    }

    /// Whether the leaf moved under repetition of the right arm alone.
    pub fn right_sync_varies(&self) -> bool {
        self.right_values.len() > 1
    }

    /// Whether the leaf's value set differs between the two policies.
    pub fn policy_varies(&self) -> bool {
        self.left_values != self.right_values
    }

    /// Whether the earlier two-document differential reported this leaf as
    /// unmoved: present at run 0 in both arms, same value.
    ///
    /// The "present in both" half is load-bearing. The differential compared
    /// only pointers present on both sides; a pointer present on one side only
    /// was reported as a difference, so counting it as unmoved would invent
    /// leaves the earlier result never looked at.
    pub fn unmoved_by_policy_diff(&self) -> bool {
        self.left_first.is_some() && self.left_first == self.right_first
    }

    /// The substrate-determined predicate. Read off the bucket rather than
    /// recomputed, so a bucket can never disagree with its own claim.
    pub fn is_substrate_determined(&self) -> bool {
        self.verdict.is_substrate_determined()
    }

    /// A one-line rendering, with the values **counted** and never printed.
    ///
    /// Withheld deliberately: under a non-reproducible policy the values contain
    /// the host's wall clock, and a committed artefact carrying it would import
    /// this host's clock skew into the repository. That the leaves move at all
    /// is the finding; the timestamps are not.
    pub fn render(&self) -> String {
        format!(
            "  {:<9} {:<20} left_distinct={} right_distinct={} cross_disagree={}  {}",
            self.verdict.as_str(),
            self.class.as_str(),
            self.left_values.len(),
            self.right_values.len(),
            self.cross_pairs_disagreeing,
            self.pointer
        )
    }
}

/// One arm of the sync differential: a policy, and the N documents it produced.
#[derive(Debug, Clone)]
pub struct Arm {
    /// The declared policy, identical across all N runs by construction.
    pub policy: SubstratePolicy,
    /// The N recordings.
    pub documents: Vec<J>,
}

impl Arm {
    /// The N documents rendered, for byte-identity against a committed file.
    pub fn rendered(&self) -> Vec<String> {
        self.documents
            .iter()
            .map(|d| serde_json::to_string_pretty(d).unwrap_or_default())
            .collect()
    }
}

/// The whole experiment: N runs of each of two policies, decomposed.
#[derive(Debug, Clone)]
pub struct SyncDifferential {
    /// N: the number of times each policy ran the workload.
    pub runs: usize,
    /// The left arm.
    pub left: Arm,
    /// The right arm.
    pub right: Arm,
    /// What kind of workload this is, for the licence paragraph.
    pub workload: Workload,
    /// Every leaf, sorted by pointer. The universe the four counts partition.
    pub verdicts: Vec<LeafVerdict>,
    /// The policy-to-policy differential, recomputed from run 0 of each arm
    /// rather than trusted, so the intersection below cannot be against a stale
    /// number.
    pub policy_diff: Differential,
    /// Leaves the policy differential reported as **not** moved that nevertheless
    /// moved between identical runs. Each one is a false negative in the earlier
    /// result, and the size of this set is the headline.
    pub false_negatives: Vec<String>,
    /// Leaves the policy differential reported as **moved** that no substrate
    /// decision can account for, because they move under repetition. The mirror
    /// correction: a single-run differential inflates its own attribution, and on
    /// a non-reproducible policy the inflation is not small.
    pub false_positives: Vec<String>,
    /// How many leaves the policy differential reported as not moved, recomputed
    /// here. Cross-checked against `policy_diff.identical_leaves` in the tests.
    pub previously_unmoved: usize,
    /// How many leaf addresses the policy differential had to report as moved.
    /// Larger than the number of *pointers* it reported, because a repeated
    /// array identity is one pointer and several leaves.
    pub previously_moved: usize,
    /// How many distinct pointers the policy differential's own difference lists
    /// name, and how many entries those lists hold. The two differ because one
    /// pointer can carry several differences.
    pub earlier_list_pointers: usize,
    /// The number of entries across the policy differential's four difference
    /// lists: moved, derived, declared, unattributed.
    pub earlier_list_entries: usize,
}

impl SyncDifferential {
    /// How many leaves are in a class.
    pub fn count(&self, a: Attribution) -> usize {
        self.verdicts.iter().filter(|v| v.verdict == a).count()
    }

    /// The four counts, in report order.
    pub fn counts(&self) -> [(Attribution, usize); 4] {
        Attribution::all().map(|a| (a, self.count(a)))
    }

    /// The leaves in a class.
    pub fn in_class(&self, a: Attribution) -> Vec<&LeafVerdict> {
        self.verdicts.iter().filter(|v| v.verdict == a).collect()
    }

    /// Leaves that move under repetition of one arm alone.
    pub fn left_sync_varying(&self) -> usize {
        self.verdicts
            .iter()
            .filter(|v| v.left_sync_varies())
            .count()
    }

    /// Leaves that move under repetition of the other arm alone.
    pub fn right_sync_varying(&self) -> usize {
        self.verdicts
            .iter()
            .filter(|v| v.right_sync_varies())
            .count()
    }

    /// The escape probability of a per-run nondeterminism of probability `p`
    /// from an N-run arm: `(1-p)^(N-1)`.
    ///
    /// The hole that survives the control. A zero measured floor is a statement
    /// about these N runs; a rare nondeterminism passes straight through, and the
    /// size of the hole depends on N rather than on the code.
    pub fn escape_probability(&self, p: f64) -> f64 {
        (1.0 - p).powi(self.runs as i32 - 1)
    }

    /// The report: the committed artefact, deliberately plain.
    pub fn report(&self) -> String {
        let mut o = String::new();
        o.push_str("SYNC DIFFERENTIAL: THE NOISE FLOOR UNDER THE POLICY DIFFERENTIAL\n");
        o.push_str("===========================================================\n\n");
        o.push_str(&format!(
            "runs   : {} per arm (a control below {} is not a measurement)\n\
             workload: {}\n\
             left   : {}\n\
                      {}\n\
             right  : {}\n\
                      {}\n\n",
            self.runs,
            MIN_RUNS,
            self.workload.as_str(),
            self.left.policy.digest(),
            differential::arm_label(&self.left.policy),
            self.right.policy.digest(),
            differential::arm_label(&self.right.policy),
        ));
        o.push_str(&format!(
            "leaf universe: {} distinct addresses, over {} left documents and {} right \
             documents.\n  A pointer that appears on some runs and not others is one leaf that \
             varies; absence is a value.\n\n",
            self.verdicts.len(),
            self.left.documents.len(),
            self.right.documents.len(),
        ));

        o.push_str("1. WHAT REPETITION ALONE MOVED  (app + interpreter)\n");
        o.push_str("-----------------------------------------------\n");
        o.push_str(&format!(
            "  left arm  : {} of {} leaves move across {} identical runs\n  right arm : {} of {} \
             leaves move across {} identical runs\n  either arm: {} of {} leaves move under \
             repetition\n\n",
            self.left_sync_varying(),
            self.verdicts.len(),
            self.runs,
            self.right_sync_varying(),
            self.verdicts.len(),
            self.runs,
            self.count(Attribution::SyncVaries) + self.count(Attribution::Both),
            self.verdicts.len(),
        ));
        let movers: Vec<&LeafVerdict> = self.verdicts.iter().filter(|v| v.sync_varies()).collect();
        if movers.is_empty() {
            o.push_str(&format!(
                "  Both arms are byte-identical across all {} runs. That is a real result, and what\n  \
                 it licenses is exactly this:\n\n    {}\n\n",
                self.runs,
                self.workload.license()
            ));
        } else {
            for v in &movers {
                o.push_str(&format!("{}\n", v.render()));
            }
            o.push('\n');
        }

        o.push_str("2. THE FOUR-WAY DECOMPOSITION\n");
        o.push_str("---------------------------\n");
        for (a, n) in self.counts() {
            o.push_str(&format!("  {:<13} {}\n", a.as_str(), n));
        }
        o.push_str(&format!(
            "  {:<13} {}    (the four sum to the leaf universe, and the tests assert it)\n\n",
            "TOTAL",
            self.verdicts.len()
        ));
        for a in Attribution::all() {
            o.push_str(&format!("  {}\n", a.license()));
        }
        o.push_str(&format!(
            "\n  SUBSTRATE-DETERMINED: {}. That count is the only thing in this report that may be \
             cited as\n  a substrate effect, and it is the count that a study would report.\n\n",
            self.count(Attribution::PolicyVaries)
        ));

        o.push_str("3. THE CORRECTION TO THE EARLIER RESULT\n");
        o.push_str("------------------------------------\n");
        o.push_str(&format!(
            "  FALSE NEGATIVES — leaves the earlier diff called unmoved that move anyway.\n  \
             OF ITS {} UNMOVED LEAVES, {} MOVE BETWEEN IDENTICAL RUNS.\n",
            self.previously_unmoved,
            self.false_negatives.len()
        ));
        if self.false_negatives.is_empty() {
            o.push_str("  Zero. Every leaf the earlier differential called unmoved did not move under\n  \
                 repetition either. Read that for exactly what it is. It confirms that the fixed\n  \
                 script is deterministic, which is the assumption the earlier result rested on and\n  \
                 which no artefact before this one could check. It does NOT convert the earlier\n  \
                 number into a measurement, because a control that measures the noise floor of a\n  \
                 deterministic program cannot see the noise a real app would have introduced.\n  \
                 The correction owed is zero because the workload is degenerate with respect to the\n  \
                 confound, not because the confound is absent from the method.\n\n");
        } else {
            for p in &self.false_negatives {
                o.push_str(&format!("  {p}\n"));
            }
            o.push('\n');
        }
        o.push_str(&format!(
            "  FALSE POSITIVES — leaves the earlier diff called moved that no policy can own.\n  \
             OF ITS {} MOVED LEAVES, {} ARE NOT SUBSTRATE-DETERMINED.\n",
            self.previously_moved,
            self.false_positives.len()
        ));
        if self.false_positives.is_empty() {
            o.push_str(
                "  Zero, and for a reason worth naming: both arms of the committed pair declare\n  \
                 themselves reproducible, so there is no wandering for a single-run diff to\n  \
                 misread. The number is a property of those two policies, not of the method.\n\n",
            );
        } else {
            for p in &self.false_positives {
                o.push_str(&format!("  {p}\n"));
            }
            o.push('\n');
        }
        o.push_str("  RECONCILING THE TWO LEAF SPACES, because the numbers do not tie by eye.\n");
        o.push_str(&format!(
            "    leaves compared at run 0 (present in both arms)        {}\n    \
             of those, identical                                 {}\n    \
             of those, differing                                  {}\n    \
             leaves present on one side only (addresses)          {}\n    \
             SUBSTRATE-DETERMINED, total                          {}\n    \
             entries in the earlier report's difference lists     {}\n    \
             distinct pointers in those lists                     {}\n\n",
            self.policy_diff.compared_leaves,
            self.previously_unmoved,
            self.policy_diff.compared_leaves - self.previously_unmoved,
            self.previously_moved - (self.policy_diff.compared_leaves - self.previously_unmoved),
            self.count(Attribution::PolicyVaries),
            self.earlier_list_entries,
            self.earlier_list_pointers,
        ));
        o.push_str(&format!(
            "  Two arithmetic corrections, both of which change a published number, and one\n  \
             granularity difference that does not:\n    \
             (a) CORRECTION. The committed differential.report.txt printed\n        \
             \"1432 of 1617 compared leaves are byte-identical\". That was wrong: it computed\n    \
             \x20   `identical = compared - every difference`, and a one-sided pointer — a leaf in \
             one\n        document and absent from the other — is a difference that was never a\n    \
             \x20   compared leaf. The true figure was {} all along. The error was an undercount,\n    \
             \x20   which is the direction that makes an unmoved set look smaller than it is.\n    \
             (b) GRANULARITY, not an error. The earlier report lists differences by *pointer*;\n    \
             \x20   an N-way comparison has to address the same leaf in N documents, so it counts\n    \
             \x20   addresses. Six `SIGNAL_PAT.BUILD_FIELD` diagnostics that exist only in the right\n    \
             \x20   arm are one line of that list and six leaf addresses. Where a whole array\n    \
             \x20   element is absent, the walk records the difference at the *element* pointer\n    \
             \x20   rather than at the leaves beneath it, which is a third granularity and the\n    \
             \x20   reason the two pointer counts differ from each other too.\n\n",
            self.previously_unmoved,
        ));

        o.push_str("4. HOW MUCH OF THE POLICY EFFECT SURVIVES REPETITION\n");
        o.push_str("-----------------------------------------------\n");
        let pairs = self.runs * self.runs;
        let policy_moved: Vec<&LeafVerdict> =
            self.verdicts.iter().filter(|v| v.policy_varies()).collect();
        let always = policy_moved
            .iter()
            .filter(|v| v.cross_pairs_disagreeing == pairs)
            .count();
        let sometimes = policy_moved
            .iter()
            .filter(|v| v.cross_pairs_disagreeing > 0 && v.cross_pairs_disagreeing < pairs)
            .count();
        let never = policy_moved
            .iter()
            .filter(|v| v.cross_pairs_disagreeing == 0)
            .count();
        o.push_str(&format!(
            "  {} left/right pairings per leaf. Of the {} leaves whose value set differs between\n  \
             the two policies:\n    disagreed in all {pairs} pairings        : {always}\n    \
             disagreed in some pairings     : {sometimes}\n    disagreed in none — cancellation : \
             {never}\n\n",
            pairs,
            policy_moved.len(),
        ));
        o.push_str(&format!(
            "  This is ADR 0006's second objection, answered for this workload: a small substrate\n  \
             effect cannot hide behind a large app effect, because a hiding place would have to\n  \
             disagree in only some pairings and there are {pairs} of them per leaf. Zero in the\n  \
             `some` line is a statement about this deterministic input, not a general guarantee.\n\n"
        ));

        o.push_str("5. WHAT REMAINS UNATTRIBUTABLE EVEN WITH THIS CONTROL\n");
        o.push_str("----------------------------------------------\n");
        o.push_str(&format!(
            "  1. Coincidence. A leaf that is nondeterministic and substrate-sensitive at the same\n  \
             time is unattributable at any N, and lands in `both` when the sample catches it.\n  \
             Here `both` is {}. There is no test in this crate that can force it to be zero, and\n  \
             adding one would be manufacturing a result.\n",
            self.count(Attribution::Both)
        ));
        o.push_str(&format!(
            "  2. The sampling hole. A per-run nondeterminism of probability p slips past an {}-run\n  \
             arm with probability (1-p)^(N-1):\n",
            self.runs
        ));
        for p in [0.01f64, 0.1, 0.5] {
            o.push_str(&format!(
                "       p = {p:.2}  -> {:.3}\n",
                self.escape_probability(p)
            ));
        }
        o.push_str(
            "     A measured zero is a statement about these runs and not a proof of determinism,\n     \
             and no amount of repetition inside this harness becomes one.\n",
        );
        o.push_str(&format!(
            "  3. The missing subject. {}\n",
            self.workload.license()
        ));
        o.push_str(
            "  4. Model versus reality. Nothing here is a statement about a device. A fact that did\n  \
             not move under a different substrate is a fact about this program under two\n  \
             substrates; what the program does on hardware is outside both files, and no number\n  \
             in this report is evidence about it.\n",
        );
        o
    }
}

/// Run the identical workload N times under one policy.
///
/// The N runs differ in nothing the caller controls: same function, same policy
/// value, same input. Whatever the resulting documents disagree about is the
/// noise floor of that workload, and it is the number every later claim about a
/// policy-to-policy difference has to be read against.
pub fn repeat(policy: SubstratePolicy, n: usize) -> Result<Arm, crate::error::ShimError> {
    if n < 2 {
        return Err(crate::error::ShimError::Encode(format!(
            "a sync arm with n={n} is a single run, which is the thing this module exists to \
                 replace; n >= 2 is the hard minimum and n >= {MIN_RUNS} is the minimum for a \
                 claim"
        )));
    }
    let mut documents = Vec::with_capacity(n);
    for _ in 0..n {
        documents.push(crate::scenario::run_with(policy)?.document);
    }
    Ok(Arm { policy, documents })
}

/// The whole experiment: repeat both policies N times and decompose the leaves.
pub fn run(
    left: SubstratePolicy,
    right: SubstratePolicy,
    n: usize,
) -> Result<SyncDifferential, crate::error::ShimError> {
    let la = repeat(left, n)?;
    let ra = repeat(right, n)?;
    decompose(la, ra, Workload::Script)
}

/// Decompose two already-produced arms.
///
/// Split out from [`run`] so the same arithmetic can be pointed at documents a
/// test assembled itself. That is how "variability is detected when introduced"
/// is checked without putting a source of nondeterminism into the library.
pub fn decompose(
    left: Arm,
    right: Arm,
    workload: Workload,
) -> Result<SyncDifferential, crate::error::ShimError> {
    if left.documents.is_empty() || right.documents.is_empty() {
        return Err(crate::error::ShimError::Encode(
            "a sync arm with no documents has no leaves; every arm needs at least one run".into(),
        ));
    }
    if left.documents.len() != right.documents.len() {
        return Err(crate::error::ShimError::Encode(format!(
            "the two arms ran {} and {} times; a policy-to-policy comparison at unequal N \
                 measures a difference in repetition count as well as a difference in substrate",
            left.documents.len(),
            right.documents.len()
        )));
    }
    // The earlier result, recomputed rather than read from a committed file, so
    // the intersection below cannot be against a stale number.
    let policy_diff = differential::diff(&left.documents[0], &right.documents[0])?;
    let left_tables: Vec<BTreeMap<String, Leaf>> = left.documents.iter().map(leaves).collect();
    let right_tables: Vec<BTreeMap<String, Leaf>> = right.documents.iter().map(leaves).collect();

    // The universe is the union over every run of every arm, so a pointer that
    // appears on some runs and not others is one leaf that varies rather than a
    // leaf that comes and goes.
    let mut universe: BTreeSet<String> = BTreeSet::new();
    for t in left_tables.iter().chain(&right_tables) {
        for k in t.keys() {
            universe.insert(k.clone());
        }
    }

    let mut verdicts = Vec::with_capacity(universe.len());
    for pointer in universe {
        let sample = |tables: &[BTreeMap<String, Leaf>]| -> Vec<Option<J>> {
            let mut seen: Vec<Option<J>> = Vec::new();
            for t in tables {
                let v = t.get(&pointer).and_then(|l| l.value.clone());
                if !seen.contains(&v) {
                    seen.push(v);
                }
            }
            seen
        };
        let left_values = sample(&left_tables);
        let right_values = sample(&right_tables);
        let left_first = left_tables[0].get(&pointer).and_then(|l| l.value.clone());
        let right_first = right_tables[0].get(&pointer).and_then(|l| l.value.clone());
        let sync_varies = left_values.len() > 1 || right_values.len() > 1;
        let policy_varies = left_values != right_values;
        let verdict = match (sync_varies, policy_varies) {
            (false, true) => Attribution::PolicyVaries,
            (true, false) => Attribution::SyncVaries,
            (true, true) => Attribution::Both,
            (false, false) => Attribution::Stable,
        };
        // Classified from a run that actually had the leaf; a pointer absent
        // everywhere falls back to classifying from the pointer alone rather than
        // from a value it does not have.
        let class = left_tables
            .iter()
            .chain(&right_tables)
            .find_map(|t| t.get(&pointer).map(|l| l.class))
            .unwrap_or_else(|| differential::classify(&pointer, None, None));
        let mut cross_pairs_disagreeing = 0usize;
        for lt in &left_tables {
            for rt in &right_tables {
                let l = lt.get(&pointer).and_then(|x| x.value.clone());
                let r = rt.get(&pointer).and_then(|x| x.value.clone());
                if l != r {
                    cross_pairs_disagreeing += 1;
                }
            }
        }
        verdicts.push(LeafVerdict {
            base: differential::base_pointer(&pointer),
            pointer,
            class,
            verdict,
            left_values,
            right_values,
            left_first,
            right_first,
            cross_pairs_disagreeing,
        });
    }

    let previously_unmoved = verdicts
        .iter()
        .filter(|v| v.unmoved_by_policy_diff())
        .count();
    let previously_moved = verdicts
        .iter()
        .filter(|v| !v.unmoved_by_policy_diff())
        .count();
    // The differential's own lists, at its own granularity. A one-sided array
    // element is recorded at the *element* pointer rather than at the leaf
    // pointers underneath it, so this number is not the number of distinct base
    // pointers among the moved addresses either, and conflating the two would be
    // the third way of making these counts fail to tie.
    let mut earlier: BTreeSet<String> = BTreeSet::new();
    let mut earlier_entries = 0usize;
    for m in &policy_diff.moved {
        earlier.insert(m.difference.pointer.clone());
        earlier_entries += 1;
    }
    for d in policy_diff
        .derived
        .iter()
        .chain(&policy_diff.declared)
        .chain(&policy_diff.unattributed)
    {
        earlier.insert(d.pointer.clone());
        earlier_entries += 1;
    }
    let false_negatives: Vec<String> = verdicts
        .iter()
        .filter(|v| v.unmoved_by_policy_diff() && v.sync_varies())
        .map(|v| v.pointer.clone())
        .collect();
    let false_positives: Vec<String> = verdicts
        .iter()
        .filter(|v| !v.unmoved_by_policy_diff() && !v.is_substrate_determined())
        .map(|v| v.pointer.clone())
        .collect();

    Ok(SyncDifferential {
        runs: left.documents.len(),
        left,
        right,
        workload,
        verdicts,
        policy_diff,
        false_negatives,
        false_positives,
        previously_unmoved,
        previously_moved,
        earlier_list_pointers: earlier.len(),
        earlier_list_entries: earlier_entries,
    })
}
