//! The **differential**: the analysis affordance that makes the confound
//! measurable.
//!
//! # What is being solved
//!
//! The shim terminates every side effect, so an app's control flow after a
//! denied sink is determined by the shim. Every fact downstream — an exception, a
//! lifecycle terminal, a `MISBEHAVE` outcome — is therefore a **joint** property
//! of app and substrate, and a recording of one substrate does not separate them.
//! An analyst reading `exceptions[3]` sees "the app threw" when the correct
//! reading is "the app reached a place the shim lacks, and then did whatever it
//! does there".
//!
//! One recording cannot fix that. **Two can.** Run the *same* program under two
//! substrates and diff: whatever moved was decided by the substrate, and whatever
//! did not move was not. That is the deliverable, and the reason the substrate's
//! behaviour had to become a parameter first.
//!
//! # The three claims this module has to earn
//!
//! 1. **Attribution from the recordings alone.** Not from the shim's internals.
//!    Both documents carry a `substrate_policy` block, and every axis in it
//!    declares the [`FactClass`]es it governs. The diff reads the *left*
//!    document's declaration, reads the *right* document's declaration, finds the
//!    axes whose value differs, and blames a moved fact on whichever of them
//!    governs the moved fact's class. An analyst with the two JSON files and no
//!    access to this crate gets the same answer.
//! 2. **No unmoved fact is being called a substrate fact.** The report counts
//!    what did not move, because the unmoved set is the positive result: it is
//!    the app's observable behaviour, and the whole point is that it survives a
//!    change of substrate.
//! 3. **No moved fact escapes attribution.** A difference in
//!    [`FactClass::App`] between two runs of the *same script* is impossible if
//!    the shim is doing what it says, so the report checks for it and treats one
//!    as a bug. That is the check that makes claims 1 and 2 worth anything: a
//!    harness that reported unattributed differences without flagging them would
//!    be decoration.
//!
//! # What it does not do
//!
//! It cannot separate the substrate from **the app's own nondeterminism**,
//! because it runs a script rather than an APK and the script is deterministic by
//! construction. On a real run the same diff would be confounded by the app.
//!
//! That limit is not a note any more; it has a control. [`crate::syncdiff`] runs
//! the same script N times under *one* policy, diffs those runs against each
//! other, and subtracts what moved there from what moved across policies. A leaf
//! may be called substrate-determined only if it does **not** move under
//! repetition. See `docs/decisions/0006-substrate-policy.md` for the diagnosis,
//! `docs/divergence/0007-sync-differential.md` for the control and its answer on
//! this workload (a measured noise floor of exactly zero, which licenses nothing
//! about any app), and `shim/recordings/sync-differential.report.txt` for the
//! artefact.
//!
//! The arithmetic in this module was also wrong in a way the control forced into
//! the open: `identical_leaves` was `compared_leaves - differences.len()`, and a
//! one-sided pointer is a difference that was never a compared leaf, so the
//! unmoved count was an undercount. The walk counts identical leaves as it goes
//! now, and the corrected figure is in the committed report.

use std::collections::BTreeMap;

use serde_json::Value as J;

use crate::policy::{Axis, FactClass, SubstratePolicy};
use crate::scenario::ScenarioOutput;

/// How many entries each report section lists before it summarises the rest.
///
/// The report is a committed artefact, and a report nobody reads is a report
/// nobody maintains. Every *attributed* move is always listed in full — that is
/// the deliverable — while the declaration and the roll-up listings, which are
/// bookkeeping, are capped.
const CAP: usize = 25;

/// One observable fact that differs between two recordings.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// The JSON pointer into the document.
    pub pointer: String,
    /// What class of fact this is.
    pub class: FactClass,
    /// The value in the left document, or `None` if the fact is absent there.
    pub left: Option<J>,
    /// The value in the right document, or `None` if absent there.
    pub right: Option<J>,
}

impl Difference {
    /// A short rendering for a report or a test failure.
    pub fn render(&self) -> String {
        let l = self
            .left
            .as_ref()
            .map(abbrev)
            .unwrap_or_else(|| "<absent>".to_string());
        let r = self
            .right
            .as_ref()
            .map(abbrev)
            .unwrap_or_else(|| "<absent>".to_string());
        format!("{} [{}] {} -> {}", self.pointer, self.class.as_str(), l, r)
    }
}

fn abbrev(v: &J) -> String {
    let s = v.to_string();
    if s.len() <= 90 {
        s
    } else {
        format!(
            "{}…",
            &s[..s.char_indices().nth(88).map_or(s.len(), |(i, _)| i)]
        )
    }
}

/// A difference plus the axis that explains it.
#[derive(Debug, Clone, PartialEq)]
pub struct Attributed {
    /// The difference.
    pub difference: Difference,
    /// The axis whose declared value differs between the two policies and which
    /// governs this fact's class. `None` only for [`FactClass::PolicyDeclaration`]
    /// and [`FactClass::DerivedRollUp`], which are explained by themselves.
    pub axis: Option<Axis>,
    /// That axis's value in the left document, as the document states it.
    pub left_value: Option<String>,
    /// That axis's value in the right document, as the document states it.
    pub right_value: Option<String>,
}

/// The result of diffing two recordings of the same program.
#[derive(Debug, Clone, PartialEq)]
pub struct Differential {
    /// The left policy, as the left recording declares it.
    pub left: SubstratePolicy,
    /// The right policy, as the right recording declares it.
    pub right: SubstratePolicy,
    /// Every moved fact, with its attribution.
    pub moved: Vec<Attributed>,
    /// How many leaves were compared. The denominator for `unmoved`, so the
    /// report can say "412 of 430 facts did not move" instead of leaving the
    /// reader to guess the size of the space.
    pub compared_leaves: usize,
    /// How many leaves were identical.
    pub identical_leaves: usize,
    /// Points in the two documents that differ and are in neither a governed
    /// class nor a derived roll-up. Must be empty: see the module docs.
    pub unattributed: Vec<Difference>,
    /// Moved facts that are recorder-derived roll-ups, kept out of the verdict.
    pub derived: Vec<Difference>,
    /// Moved facts that *are* the declaration: the policy block, the options
    /// that copy it, the observer effects generated from it, the gap list it
    /// generates, and the generated `limits` sentences. Expected to differ
    /// whenever the policies differ, and attributable to "the policy" rather
    /// than to any one axis.
    pub declared: Vec<Difference>,
}

impl Differential {
    /// The axes whose value differs between the two declared policies.
    pub fn moved_axes(&self) -> Vec<(Axis, &'static str, &'static str)> {
        Axis::all()
            .into_iter()
            .filter(|a| self.left.axis(*a) != self.right.axis(*a))
            .map(|a| (a, self.left.axis(a), self.right.axis(a)))
            .collect()
    }

    /// The moved facts in one class, in document order.
    pub fn moved_in(&self, class: FactClass) -> Vec<&Attributed> {
        self.moved
            .iter()
            .filter(|m| m.difference.class == class)
            .collect()
    }

    /// A human-readable report. The artefact the deliverable is read from, and
    /// deliberately plain: no colour, no alignment tricks, one fact per line.
    pub fn report(&self) -> String {
        let mut o = String::new();
        o.push_str("SUBSTRATE POLICY DIFFERENTIAL\n");
        o.push_str("===========================\n\n");
        o.push_str(&format!(
            "left  : {}\nright : {}\nscript: identical (shim::scenario::run_with, one function, no per-policy branch)\n\n",
            self.left.digest(),
            self.right.digest()
        ));
        o.push_str("AXES THAT DIFFER\n----------------\n");
        let axes = self.moved_axes();
        if axes.is_empty() {
            o.push_str("  (none: the two policies are the same policy)\n");
        }
        for (a, l, r) in &axes {
            o.push_str(&format!("  {a}: {l} -> {r}\n"));
            for c in a.governs() {
                o.push_str(&format!("      governs {}\n", c.as_str()));
            }
        }
        o.push_str("\nFACTS THAT MOVED, AND WHY\n--------------------------\n");
        if self.moved.is_empty() {
            o.push_str("  (none)\n");
        }
        for m in &self.moved {
            match m.axis {
                Some(a) => o.push_str(&format!(
                    "  [{:<9}] {}\n              axis {} : {} -> {}\n              {}\n",
                    a.as_str(),
                    m.difference.pointer,
                    a.as_str(),
                    m.left_value.as_deref().unwrap_or("?"),
                    m.right_value.as_deref().unwrap_or("?"),
                    m.difference.render()
                )),
                None => o.push_str(&format!(
                    "  [{:<9}] {}\n              {}\n",
                    m.difference.class.as_str(),
                    m.difference.pointer,
                    m.difference.render()
                )),
            }
        }
        o.push_str("\nFACTS THAT DID NOT MOVE\n----------------------\n");
        o.push_str(&format!(
            "  {} of {} compared leaves are byte-identical. Read that as what it is: a \
             demonstration that the\n  attribution MECHANISM works, on a fixed branch-free script, under two substrates. It \
             is\n  not a measurement of any app. A leaf that did not move between these two \
             documents is a leaf\n  that did not move on THIS run; whether it would have moved on a run with a \
             `HashMap` iteration\n  order, a retry, a timestamp or an animation frame is a question this input \
             cannot even pose.\n  The control that poses it is the sync arm: the same workload repeated under the SAME \
             policy,\n  differenced against itself. See docs/divergence/0007-sync-differential.md for \
             that arm and for\n  the four-way decomposition it enables. The number above is a property of a \
             deterministic program.\n",
            self.identical_leaves, self.compared_leaves
        ));
        for class in [
            FactClass::App,
            FactClass::EnvironmentIdentity,
            FactClass::IdentityProbe,
            FactClass::SystemFs,
            FactClass::CrossAppPackages,
            FactClass::Network,
            FactClass::Time,
        ] {
            o.push_str(&format!(
                "  {:<24} moved {}\n",
                class.as_str(),
                self.moved_in(class).len()
            ));
        }
        o.push_str("\nUNATTRIBUTED DIFFERENCES\n-----------------------\n");
        if self.unattributed.is_empty() {
            o.push_str("  (none) Every difference is explained by the policy declarations in the two documents,\n  which is the result the design was built to produce.\n");
        } else {
            o.push_str("  These differ and no axis declares responsibility for them. With one script and two\n  policies that should be impossible; treat it as a bug in the declaration, not as a result.\n");
            for d in &self.unattributed {
                o.push_str(&format!("  {}\n", d.render()));
            }
        }
        o.push_str("\nTHE DECLARATION ITSELF, WHICH MOVED\n---------------------------------\n");
        o.push_str(&format!(
            "  {} fields. These are the policy block, the recorder options that copy it, the\n  observer effects generated from it, the gap list it generates and the `limits`\n  sentences it generates. They are expected to differ and are attributable to\n  \"the policy\", not to any one axis. The first {CAP} are listed; the rest are of\n  the same kinds.\n",
            self.declared.len(),
            CAP = CAP
        ));
        for d in self.declared.iter().take(CAP) {
            o.push_str(&format!("  {}\n", d.render()));
        }
        if self.declared.len() > CAP {
            o.push_str(&format!("  ... and {} more\n", self.declared.len() - CAP));
        }
        o.push_str("\nDERIVED ROLL-UPS THAT MOVED\n---------------------------\n");
        if self.derived.is_empty() {
            o.push_str("  (none)\n");
        } else {
            o.push_str(&format!(
                "  {} of them. Recorder-assigned ordinals, index-based evidence pointers, and\n  sums over facts of mixed composition. None is attributable to an axis: they are made of\n  the facts above, and the facts above are what to read. The first {CAP} are listed.\n",
                self.derived.len(),
                CAP = CAP
            ));
            for d in self.derived.iter().take(CAP) {
                o.push_str(&format!("  {}\n", d.render()));
            }
            if self.derived.len() > CAP {
                o.push_str(&format!("  ... and {} more\n", self.derived.len() - CAP));
            }
        }
        o.push_str(
            "\nWHAT THIS DOES NOT SHOW\n---------------------\nThe input was a fixed script, not an APK. The script is \
             deterministic, so nothing here separates\nthe substrate from the app's own nondeterminism; on a real \
             run the same diff would be\nconfounded by it. That control now exists and is \
             committed: docs/divergence/0007-sync-differential.md\nis the ADR, and \
             shim/recordings/sync-differential.report.txt is its output. Read this\nreport as the \
             mechanism demonstration it is. And a fact that did not move is not\nthereby a fact \
             about a real device: it is a fact about this program under two\nsubstrates, and the \
             third thing a study needs — what the program does on hardware — is\noutside anything \
             in these two files. See docs/decisions/0006-substrate-policy.md.\n",
        );
        o
    }
}

// ------------------------------------------------------------------- the diff

/// Diff two recordings and attribute every difference, from the documents alone.
///
/// `left` and `right` are the serialised documents. Nothing about the shim's
/// internals is consulted: the axis values come from each document's
/// `substrate_policy` block, and the `governs` lists come from the same blocks.
pub fn diff(left: &J, right: &J) -> Result<Differential, crate::error::ShimError> {
    let lp = declared_policy(left)?;
    let rp = declared_policy(right)?;
    let mut raw: Vec<Difference> = Vec::new();
    let mut leaves = 0usize;
    let mut identical = 0usize;
    walk("", left, right, None, &mut raw, &mut leaves, &mut identical);

    let mut moved = Vec::new();
    let mut derived = Vec::new();
    let mut declared = Vec::new();
    let mut unattributed = Vec::new();
    for d in raw {
        match d.class {
            FactClass::PolicyDeclaration => declared.push(d),
            FactClass::DerivedRollUp => derived.push(d),
            _ => {
                // Which axes govern this class, and which of those differ?
                let governing: Vec<Axis> = Axis::all()
                    .into_iter()
                    .filter(|a| a.governs().contains(&d.class))
                    .collect();
                let culprit = governing
                    .iter()
                    .copied()
                    .find(|a| lp.axis(*a) != rp.axis(*a));
                match culprit {
                    Some(a) => moved.push(Attributed {
                        left_value: Some(lp.axis(a).to_string()),
                        right_value: Some(rp.axis(a).to_string()),
                        difference: d,
                        axis: Some(a),
                    }),
                    None => {
                        if d.class == FactClass::App {
                            unattributed.push(d);
                        } else {
                            // A governed class whose axis did not move: the
                            // declaration is incomplete, and saying so is more
                            // useful than filing it as a result.
                            unattributed.push(d);
                        }
                    }
                }
            }
        }
    }
    Ok(Differential {
        left: lp,
        right: rp,
        moved,
        compared_leaves: leaves,
        identical_leaves: identical,
        unattributed,
        derived,
        declared,
    })
}

/// Read a recording's own declared policy, with the digest verified.
fn declared_policy(doc: &J) -> Result<SubstratePolicy, crate::error::ShimError> {
    let block = doc.get("substrate_policy").ok_or_else(|| {
        crate::error::ShimError::Encode(
            "the document carries no substrate_policy block, so nothing in it can be attributed \
             to a substrate decision"
                .into(),
        )
    })?;
    SubstratePolicy::from_json(block)
}

/// Walk two JSON documents in parallel, collecting every leaf that differs and
/// counting the leaves that did not.
///
/// `element` is the nearest enclosing array element, because a diagnostic's
/// `pattern` and a filesystem access's `path` are what classify it and neither
/// is visible from a leaf. Carrying the element down the recursion is why the
/// classifier is a pure function of the document rather than a lookup table the
/// walker has to special-case at every array.
///
/// `identical` is counted **in the walk** rather than derived afterwards as
/// `leaves - differences`. The subtraction is wrong, and was: a pointer present
/// on one side only is a difference but was never a compared leaf, so subtracting
/// every difference from the compared count double-counted the absences. The
/// committed report said "1432 of 1617 compared leaves are byte-identical" when
/// the true figure was 1486 — the number was an undercount of the unmoved set by
/// exactly the number of one-sided differences. An undercount is the dangerous
/// direction: it makes the unmoved set look smaller than it is, and the unmoved
/// set is the positive result. See `docs/divergence/0007-sync-differential.md`.
#[allow(clippy::too_many_arguments)]
fn walk(
    pointer: &str,
    a: &J,
    b: &J,
    element: Option<&J>,
    out: &mut Vec<Difference>,
    leaves: &mut usize,
    identical: &mut usize,
) {
    match (a, b) {
        (J::Object(x), J::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let p = if pointer.is_empty() {
                    format!("/{k}")
                } else {
                    format!("{pointer}/{k}")
                };
                match (x.get(k), y.get(k)) {
                    (Some(va), Some(vb)) => walk(&p, va, vb, element, out, leaves, identical),
                    (va, vb) => {
                        let class = classify(&p, va.or(vb), element);
                        out.push(Difference {
                            pointer: p,
                            class,
                            left: va.cloned(),
                            right: vb.cloned(),
                        });
                    }
                }
            }
        }
        (J::Array(x), J::Array(y)) => {
            walk_array(pointer, x, y, out, leaves, identical);
        }
        _ => {
            *leaves += 1;
            if a != b {
                out.push(Difference {
                    pointer: pointer.to_string(),
                    class: classify(pointer, Some(a), element),
                    left: Some(a.clone()),
                    right: Some(b.clone()),
                });
            } else {
                *identical += 1;
            }
        }
    }
}

/// Compare two arrays by **element identity**, not by index.
///
/// This is not a refinement; it is the difference between a working harness and
/// a broken one. A policy that inserts one extra diagnostic shifts every
/// subsequent index, and an index-based diff then reports the *same* WebView-load
/// observation as "at 38 the pattern is WEBVIEW_LOAD, at 38 the pattern is
/// LOOPBACK_RESPONSE" — a difference that is an artefact of the comparison and
/// not a fact about either document. The first version of this module had
/// exactly that bug and the `unattributed` check caught it, which is the check
/// earning its keep.
///
/// Identity is `array_identity`, and elements are paired within an identity in
/// order, so an element that appears only on one side is reported as an addition
/// and never silently displaces its neighbour.
fn walk_array(
    pointer: &str,
    x: &[J],
    y: &[J],
    out: &mut Vec<Difference>,
    leaves: &mut usize,
    identical: &mut usize,
) {
    let keys_x: Vec<Option<String>> = x.iter().map(|e| array_identity(pointer, e)).collect();
    let keys_y: Vec<Option<String>> = y.iter().map(|e| array_identity(pointer, e)).collect();
    if keys_x.iter().any(Option::is_none) || keys_y.iter().any(Option::is_none) {
        // No identity function for this array: fall back to index, and say so in
        // the pointer so nobody mistakes an index diff for an identity diff.
        let n = x.len().max(y.len());
        for i in 0..n {
            let p = format!("{pointer}/#{i}");
            match (x.get(i), y.get(i)) {
                (Some(va), Some(vb)) => walk(&p, va, vb, Some(va), out, leaves, identical),
                (va, vb) => {
                    let class = classify(&p, va.or(vb), None);
                    out.push(Difference {
                        pointer: p,
                        class,
                        left: va.cloned(),
                        right: vb.cloned(),
                    });
                }
            }
        }
        return;
    }
    let mut used_x = vec![false; x.len()];
    let mut used_y = vec![false; y.len()];
    let mut order: Vec<&String> = keys_x.iter().chain(keys_y.iter()).flatten().collect();
    order.sort();
    order.dedup();
    for k in order {
        let idx_x: Vec<usize> = (0..x.len())
            .filter(|i| keys_x[*i].as_deref() == Some(k))
            .collect();
        let idx_y: Vec<usize> = (0..y.len())
            .filter(|i| keys_y[*i].as_deref() == Some(k))
            .collect();
        let n = idx_x.len().max(idx_y.len());
        for j in 0..n {
            let a = idx_x.get(j).map(|i| &x[*i]);
            let b = idx_y.get(j).map(|i| &y[*i]);
            let p = format!("{pointer}[{k}]");
            match (a, b) {
                (Some(va), Some(vb)) => {
                    if let Some(i) = idx_x.get(j) {
                        used_x[*i] = true;
                    }
                    if let Some(i) = idx_y.get(j) {
                        used_y[*i] = true;
                    }
                    walk(&p, va, vb, Some(va), out, leaves, identical);
                }
                (va, vb) => {
                    let class = classify(&p, va.or(vb), None);
                    out.push(Difference {
                        pointer: p,
                        class,
                        left: va.cloned(),
                        right: vb.cloned(),
                    });
                }
            }
        }
    }
}

/// A stable identity for one array element, or `None` if this array has no
/// identity function.
///
/// The identity fields are the ones that say *what was observed*, never the ones
/// that say *when* or *in what order* — an index-derived `seq` shifts the moment
/// an element is inserted, which is exactly the failure this exists to prevent.
pub fn array_identity(pointer: &str, elem: &J) -> Option<String> {
    // A scalar array's element *is* its identity.
    if let Some(s) = elem.as_str() {
        return Some(truncate_key(s));
    }
    if elem.is_number() || elem.is_boolean() || elem.is_null() {
        return Some(elem.to_string());
    }
    let fields: &[&str] = match pointer {
        "/diagnostics" => &["pattern"],
        // The class *and* the top frame: `NoClassDefFoundError` alone does not
        // say which class was missing, and the identity axis's refusal and an
        // app's own failed `forName` are the same class name.
        "/exceptions" => &["class", "stack_frames"],
        "/filesystem/accesses" => &["op", "path"],
        "/filesystem/app_dir_listing" => &["path"],
        "/network/attempts" => &["method", "host", "path"],
        "/jni/calls" => &["symbol", "declaring_class"],
        "/native/dlopen_failures" => &["library"],
        "/lifecycle/events" => &["type", "component"],
        "/capture/observer_effects" => &["kind", "applied"],
        "/substrate_probe_hits" => &["assumption_id"],
        "/substrate_policy/axis_declarations" => &["axis"],
        "/capture_quality/unobserved" => &["signal", "reason_code"],
        "/probes" => &["command"],
        _ => return None,
    };
    let mut key = String::new();
    for f in fields {
        let v = elem.get(*f).unwrap_or(&J::Null);
        key.push_str(f);
        key.push('=');
        match v {
            J::String(s) => key.push_str(&truncate_key(s)),
            J::Array(items) => {
                // Only the first element identifies the entry; a second one of the
                // same kind is the same entry, and the in-order pairing handles it.
                if let Some(first) = items.first() {
                    key.push_str(&truncate_key(first.as_str().unwrap_or_default()));
                }
            }
            other => key.push_str(&truncate_key(&other.to_string())),
        }
        key.push_str(KEY_SEP);
    }
    Some(key.trim_end_matches(KEY_SEP).to_string())
}

/// The separator between identity fields inside an array key.
///
/// `::` rather than a space, because two of the fields are free text that
/// contains spaces — `probes[].command` is a whole sentence — and a space would
/// make the key unparseable. Chosen because no recording value contains it.
const KEY_SEP: &str = "::";

/// One scalar leaf of a recording, as [`leaves`] sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Leaf {
    /// The JSON pointer, with an occurrence index when the enclosing array has
    /// more than one element sharing an identity.
    pub pointer: String,
    /// The value at that pointer. `None` means the pointer is **absent** from the
    /// document, which is a different observation from a JSON `null` and is
    /// tracked separately because "the array element was not emitted this time"
    /// is exactly the kind of fact a repeated-run comparison has to notice.
    pub value: Option<J>,
    /// The class the classifier assigns, from the pointer, the value and the
    /// enclosing array element.
    pub class: FactClass,
}

/// Every scalar leaf of one recording, keyed by a pointer that is **unique**
/// within the document.
///
/// The leaf *space* here is the same one [`diff`] walks: same
/// [`array_identity`] rules, same [`classify`], same `KEY_SEP`. The one
/// difference is that an array element which repeats an identity already taken
/// by a sibling gets a `~{occurrence}` suffix, so six `SIGNAL_PAT.BUILD_FIELD`
/// diagnostics are six addressable leaves rather than one key written six times.
/// The differential does not need the suffix because it pairs positionally
/// within an identity; an N-way comparison does, because it has to address the
/// same leaf in N documents at once.
///
/// The count is the check on the claim: `leaves(doc).len() == diff(doc, doc)
/// .compared_leaves`, asserted in this module's tests. If the two ever disagree
/// the sync arm and the policy differential are talking about different leaf
/// spaces and the intersection between them is meaningless.
pub fn leaves(doc: &J) -> BTreeMap<String, Leaf> {
    let mut out = BTreeMap::new();
    collect_leaves("", None, doc, &mut out);
    out
}

fn collect_leaves(pointer: &str, element: Option<&J>, v: &J, out: &mut BTreeMap<String, Leaf>) {
    match v {
        J::Object(m) => {
            for (k, val) in m {
                let p = if pointer.is_empty() {
                    format!("/{k}")
                } else {
                    format!("{pointer}/{k}")
                };
                collect_leaves(&p, element, val, out);
            }
        }
        J::Array(a) => {
            // Same rule as `walk_array`: one element without an identity makes
            // the whole array index-addressed, and mixing the two schemes inside
            // one array would double-count the elements before the unidentifiable
            // one.
            if a.iter().any(|e| array_identity(pointer, e).is_none()) {
                for (i, e) in a.iter().enumerate() {
                    collect_leaves(&format!("{pointer}/#{i}"), Some(e), e, out);
                }
                return;
            }
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            for e in a {
                let base = format!(
                    "{pointer}[{}]",
                    array_identity(pointer, e).unwrap_or_default()
                );
                let n = seen.entry(base.clone()).or_insert(0);
                let key = if *n == 0 {
                    base.clone()
                } else {
                    format!("{base}~{n}")
                };
                *n += 1;
                collect_leaves(&key, Some(e), e, out);
            }
        }
        _ => {
            out.insert(
                pointer.to_string(),
                Leaf {
                    pointer: pointer.to_string(),
                    value: Some(v.clone()),
                    class: classify(pointer, Some(v), element),
                },
            );
        }
    }
}

/// Delete the `~{occurrence}` suffix [`leaves`] adds to a repeated array
/// identity, yielding the pointer [`diff`] would have used for the same leaf.
///
/// Needed to join the two leaf spaces: the sync arm addresses a leaf uniquely,
/// the differential addresses it by identity, and a leaf whose sibling moved
/// shares the differential's pointer with that sibling.
///
/// The suffix is *removed*, not truncated, because it sits between the array's
/// closing bracket and whatever fields follow inside the element:
/// `/diagnostics[pattern=P]~1/detail` folds onto `/diagnostics[pattern=P]/detail`
/// and not onto `/diagnostics[pattern=P]`. It is recognised only as `]~digits`
/// followed by `/` or the end of the pointer, so a `~` inside an identity is
/// left alone. Returns a `String` because removing a span from the middle of a
/// pointer cannot borrow.
pub fn base_pointer(pointer: &str) -> String {
    let mut from = 0usize;
    while let Some(rel) = pointer[from..].find('~') {
        let i = from + rel;
        let rest = &pointer[i + 1..];
        let digits = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        if i > 0
            && pointer.as_bytes()[i - 1] == b']'
            && digits > 0
            && matches!(rest.as_bytes().get(digits), None | Some(b'/'))
        {
            let mut s = String::with_capacity(pointer.len() - 1 - digits);
            s.push_str(&pointer[..i]);
            s.push_str(&rest[digits..]);
            return s;
        }
        from = i + 1;
        if from >= pointer.len() {
            break;
        }
    }
    pointer.to_string()
}

/// One field of an array key, by name.
fn key_field<'a>(key: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}=");
    let mut rest = key;
    loop {
        if let Some(after) = rest.strip_prefix(&prefix) {
            return after.split(KEY_SEP).next().unwrap_or_default();
        }
        match rest.split_once(KEY_SEP) {
            Some((_, tail)) => rest = tail,
            None => return "",
        }
    }
}

fn truncate_key(s: &str) -> String {
    if s.chars().count() <= 60 {
        s.to_string()
    } else {
        s.chars().take(60).collect()
    }
}

/// The bracketed identity of the array element a pointer addresses, if any.
///
/// `/exceptions[class=java.lang.NoClassDefFoundError Landroid/os/Build;.FINGERPRINT]/message`
/// yields the key, which is how a leaf three levels below an array member can
/// still be classified by what its element *is*.
fn bracket_key(pointer: &str) -> Option<&str> {
    // The FIRST `[` and the LAST `]`, not the last of each: an identity may
    // itself contain brackets — a generated `limits` sentence begins with
    // "[substrate_policy] " — and taking the last bracket on each side silently
    // truncated the key to "substrate_policy" and lost the marker. A JSON pointer
    // has no bracket of its own, so the first `[` is always the array marker.
    let open = pointer.find('[')?;
    let close = pointer.rfind(']')?;
    if close <= open {
        return None;
    }
    Some(&pointer[open + 1..close])
}

/// Classify one JSON pointer into a [`FactClass`].
///
/// **A function of the pointer and the value, and of nothing else.** No shim
/// state, no thread-local, no knowledge of which run produced either document.
/// That is what makes the attribution reproducible by a third party, and it is
/// why the rules below are a table of prefixes and patterns rather than a set of
/// calls into the crate.
///
/// `value` is the value at that pointer, or for a *missing* pointer the value
/// from whichever document has it. `element` is the nearest enclosing array
/// member, which is where a `pattern`, a `path` or a `class` lives; where it is
/// available it wins, because a diagnostic is identified by its pattern and not
/// by the text of its detail.
pub fn classify(pointer: &str, value: Option<&J>, element: Option<&J>) -> FactClass {
    let src = element.or(value);
    let s = || {
        element
            .or(value)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
    };
    let field = |k: &str| -> String { src.map(|v| path_field(v, k)).unwrap_or_default() };
    // What the enclosing array element *is*, when this pointer is inside one.
    let key = bracket_key(pointer).unwrap_or_default().to_string();

    // 1. The declaration, and the recording's copy of it.
    if pointer == "/substrate_policy" || pointer.starts_with("/substrate_policy/") {
        return FactClass::PolicyDeclaration;
    }
    if pointer.starts_with("/recorder/options/substrate_policy") {
        return FactClass::PolicyDeclaration;
    }
    // The document's own closing statement carries the policy digest, so it
    // differs whenever the policy does.
    if pointer == "/notes" {
        return FactClass::PolicyDeclaration;
    }
    // The gap list is generated from the declaration, so it is a restatement of
    // it rather than an observation.
    if pointer.starts_with("/capture_quality/unobserved") {
        return FactClass::PolicyDeclaration;
    }
    if pointer.starts_with("/capture/observer_effects") {
        return FactClass::PolicyDeclaration;
    }

    // 2. Explicit `t_mono_ms` is the recorder's own timeline, and the `time`
    //    axis deliberately does not touch it. This rule comes before the array
    //    rules so that a `t_mono_ms` inside a diagnostics entry is not misfiled
    //    as an identity or network fact.
    if pointer.ends_with("/t_mono_ms") || pointer == "/t_mono_ms" {
        return FactClass::App;
    }

    // 3. The `limits` entries a policy *generates*. They are restatements of the
    //    declaration rather than observations, and every generated one carries
    //    this marker — which is what lets the classifier tell a generated entry
    //    from an unconditional one without a list of them, and keeps working when
    //    a sentence is split to fit the schema's length cap.
    if pointer.starts_with("/network/limits") || pointer.starts_with("/filesystem/limits") {
        let text = if key.is_empty() {
            value
                .map(|v| v.as_str().unwrap_or_default())
                .unwrap_or_default()
                .to_string()
        } else {
            key
        };
        return if text.starts_with(crate::recording::GENERATED_LIMIT) {
            FactClass::PolicyDeclaration
        } else {
            FactClass::App
        };
    }

    // 4. Roll-ups.
    if pointer.starts_with("/summary") || pointer.starts_with("/capture_quality/signals_obtained") {
        return FactClass::DerivedRollUp;
    }
    if pointer == "/classes/total_loaded_count" {
        return FactClass::DerivedRollUp;
    }
    // `probes[].id` and `substrate_probe_hits[].evidence` are recorder-assigned
    // ordinals and index-based pointers. Both shift the moment a policy inserts
    // one observation, which is an artefact of the bookkeeping rather than a
    // change in what was observed — so they are roll-ups, not facts.
    if pointer.starts_with("/probes[") && pointer.ends_with("]/id") {
        return FactClass::DerivedRollUp;
    }
    // A probe hit's counts, timestamps and index-based evidence pointers are sums
    // over the facts above them, not facts of their own. So is the whole entry
    // for an assumption no axis governs — see the note on
    // `Axis::governs_assumption` for the shim reusing one ID across two axes.
    if pointer.starts_with("/substrate_probe_hits[") {
        let leaf = pointer.rsplit('/').next().unwrap_or_default();
        if matches!(
            leaf,
            "hit_count" | "first_t_mono_ms" | "last_t_mono_ms" | "evidence"
        ) || pointer.contains("]/evidence")
        {
            return FactClass::DerivedRollUp;
        }
    }

    // 5. The environment block, field by field. This list is the identity axis's
    //    declared footprint and it is deliberately explicit: `egress_available`
    //    and `is_emulator` sit in the same object and belong to no axis, which is
    //    exactly the sort of thing a prefix rule would get wrong.
    if let Some(rest) = pointer.strip_prefix("/environment") {
        let rest = rest.split('[').next().unwrap_or(rest);
        return if is_identity_environment_field(rest) {
            FactClass::EnvironmentIdentity
        } else {
            FactClass::App
        };
    }

    // 6. The clock.
    if pointer.starts_with("/clock") {
        return FactClass::Time;
    }

    // 7. The network block, in full. `capture_method` and
    //    `byte_totals_observed` do not move under any axis value, so a prefix
    //    rule is safe here and a field list would be a maintenance hazard.
    if pointer.starts_with("/network") {
        return FactClass::Network;
    }

    // 8. Filesystem accesses, by path.
    if pointer.starts_with("/filesystem/accesses") {
        let p = field("path");
        return if is_system_path(&p) {
            FactClass::SystemFs
        } else {
            FactClass::App
        };
    }

    // 9. Diagnostics, by recognition pattern.
    if pointer.starts_with("/diagnostics") {
        let c = pattern_class(&field("pattern"));
        if c != FactClass::App {
            return c;
        }
        // An unrecognised pattern, so fall back to the text before giving up.
        // Conservative: a pattern nobody classified lands in `App` and, if it
        // moves, shows up unattributed rather than being confidently mislabelled.
        let text = format!("{}{}", field("pattern"), field("detail"));
        return pattern_from_text(&text).unwrap_or(FactClass::App);
    }

    // 10. Probes, by command and then by output.
    if pointer.starts_with("/probes") {
        if let Some(c) = pattern_from_command(&field("command")) {
            return c;
        }
        if let Some(c) = pattern_from_text(&field("output")) {
            return c;
        }
        return FactClass::App;
    }

    // 11. Exceptions, by class. A substrate-chosen exception is a policy fact
    //     and the class is the only place the choice is written down.
    if pointer.starts_with("/exceptions") {
        // A leaf under an exception is classified by the exception itself, via
        // the key the walk gave the element. That is what keeps
        // `stack_frames[0]` — which has no `class` field of its own — in the
        // right bucket.
        let class = if key.is_empty() {
            field("class")
        } else {
            key_field(&key, "class").to_string()
        };
        let subject = if key.is_empty() {
            field("message")
        } else {
            key.clone()
        };
        return match class.as_str() {
            "java.net.ConnectException" | "java.net.SocketException" | "java.io.IOException" => {
                FactClass::Network
            }
            "android.content.pm.NameNotFoundException" => FactClass::CrossAppPackages,
            "java.lang.NoClassDefFoundError" | "java.lang.ClassNotFoundException" => {
                let msg = if key.is_empty() {
                    field("message")
                } else {
                    subject
                };
                if msg.contains("Build") {
                    FactClass::IdentityProbe
                } else {
                    FactClass::App
                }
            }
            _ => FactClass::App,
        };
    }

    // 12. Class lists. The identity axis removes `android.os.Build*` from the
    //     shim's own table, so a `classes.loaded` entry naming it is a
    //     substrate decision even though `classes.loaded` reads like the app's
    //     own census.
    if pointer.starts_with("/classes/loaded")
        || pointer.starts_with("/classes/framework_classes_touched")
        || pointer.starts_with("/classes/third_party_package_prefixes")
    {
        let name = if key.is_empty() { s().to_string() } else { key };
        return if name.starts_with("android.os.Build") {
            FactClass::EnvironmentIdentity
        } else {
            FactClass::App
        };
    }

    // 13. Probe hits, by taxonomy ID — the one place where a stable join key
    //     beats a pointer, because the schema may move the array later.
    if pointer.starts_with("/substrate_probe_hits") {
        let raw = if key.is_empty() {
            field("assumption_id")
        } else {
            key_field(&key, "assumption_id").to_string()
        };
        let id = crate::taxonomy::AssumptionId::parse(&raw).ok();
        return match id.and_then(|i| {
            Axis::all()
                .into_iter()
                .find_map(|a| a.governs_assumption(i))
        }) {
            Some(c) => c,
            // Ungoverned: a roll-up over facts of mixed composition. Filing it
            // as `App` would raise a false alarm the moment a policy changed any
            // one of its constituents; filing it as an axis's class would invent an
            // owner. DerivedRollUp is the only honest third option, and the
            // report sends the reader to the constituents.
            None => FactClass::DerivedRollUp,
        };
    }

    FactClass::App
}

/// Read a string field out of an object, tolerating a non-object (a bare leaf).
fn path_field(v: &J, key: &str) -> String {
    v.get(key)
        .and_then(J::as_str)
        .unwrap_or_default()
        .to_string()
}

/// The `environment` fields the identity axis is responsible for.
fn is_identity_environment_field(rest: &str) -> bool {
    const IDENTITY: &[&str] = &[
        "/android_release",
        "/sdk_int",
        "/build_fingerprint",
        "/build_tags",
        "/model",
        "/manufacturer",
        "/brand",
        "/product",
        "/device",
        "/hardware",
        "/board",
        "/abis",
        "/serial",
        "/bootloader",
    ];
    // Prefix, not equality: `abis` is an array and its members are identity too.
    if IDENTITY
        .iter()
        .any(|f| rest == *f || rest.starts_with(&format!("{f}/")))
    {
        return true;
    }
    // `properties_observed` is a flattened getprop dump: identity, whole.
    rest.starts_with("/properties_observed")
}

/// A `/proc`, `/sys` or `/dev` path — the `system_fs` axis's footprint.
fn is_system_path(p: &str) -> bool {
    p.starts_with("/proc/") || p.starts_with("/sys/") || p.starts_with("/dev/")
}

/// The fact class a `SIGNAL_PAT.*` token belongs to.
///
/// Split out and named because it is the mapping an analyst needs in order to
/// read the report without the crate: it is a table from the taxonomy's own
/// pattern names to the axis that answers them.
pub fn pattern_class(pattern: &str) -> FactClass {
    match pattern {
        "SIGNAL_PAT.BUILD_FIELD"
        | "SIGNAL_PAT.BUILD_TAGS"
        | "SIGNAL_PAT.SDK_INT"
        | "SIGNAL_PAT.EMULATOR_PROBE" => FactClass::IdentityProbe,
        "SIGNAL_PAT.PROC_STATUS"
        | "SIGNAL_PAT.PROC_MAPS"
        | "SIGNAL_PAT.PROC_UPTIME"
        | "SIGNAL_PAT.PROC_CPUINFO"
        | "SIGNAL_PAT.PROC_MEMINFO"
        | "SIGNAL_PAT.PROC_OTHER"
        | "SIGNAL_PAT.BATTERY"
        | "SIGNAL_PAT.CPU_ONLINE"
        | "SIGNAL_PAT.SYS_BLOCK"
        | "SIGNAL_PAT.SYS_OTHER"
        | "SIGNAL_PAT.ENTROPY" => FactClass::SystemFs,
        "SIGNAL_PAT.PM_QUERY" | "SIGNAL_PAT.PM_SELF" | "SIGNAL_PAT.SYSTEM_FEATURE" => {
            FactClass::CrossAppPackages
        }
        "SIGNAL_PAT.LOOPBACK_RESPONSE"
        | "SIGNAL_PAT.HEADER_NAME"
        | "SIGNAL_PAT.EGRESS"
        | "SIGNAL_PAT.WEBVIEW_LOAD"
        | "SIGNAL_PAT.JAVASCRIPT_INTERFACE" => FactClass::Network,
        "SIGNAL_PAT.CLOCK_WALL"
        | "SIGNAL_PAT.CLOCK_MONOTONIC"
        | "SIGNAL_PAT.CLOCK_UPTIME"
        | "SIGNAL_PAT.CLOCK_ELAPSED"
        | "SIGNAL_PAT.SLEEP"
        | "SIGNAL_PAT.MESSAGE_QUEUE"
        | "SIGNAL_PAT.VSYNC"
        | "SIGNAL_PAT.FRAME_CALLBACK"
        | "SIGNAL_PAT.ANIMATION" => FactClass::Time,
        _ => FactClass::App,
    }
}

/// The class implied by a probe's `command` string, for commands that name a
/// pattern directly (`substrate.probe SIGNAL_PAT.BUILD_FIELD`).
fn pattern_from_command(cmd: &str) -> Option<FactClass> {
    let p = cmd.strip_prefix("substrate.probe ")?;
    Some(pattern_class(p.trim()))
}

/// The class implied by free text, as a last resort inside a probe's `output`.
///
/// Conservative on purpose: this only fires on the axis labels the shim itself
/// writes, so an unrecognised output falls through to
/// [`FactClass::App`] and, if it moves, shows up as unattributed. Better a
/// false alarm than a confident wrong answer.
fn pattern_from_text(text: &str) -> Option<FactClass> {
    for a in Axis::all() {
        let marker = format!("substrate_policy axis {}", a.as_str());
        if text.contains(&marker) {
            return Some(match a {
                Axis::Identity => FactClass::IdentityProbe,
                Axis::SystemFs => FactClass::SystemFs,
                Axis::CrossAppPackages => FactClass::CrossAppPackages,
                Axis::Network => FactClass::Network,
                Axis::Time => FactClass::Time,
            });
        }
    }
    if text.contains("SIGNAL_PAT.BUILD_FIELD") {
        return Some(FactClass::IdentityProbe);
    }
    if text.contains("SIGNAL_PAT.CLASS_RESOLVE") && text.contains("android.os.Build") {
        return Some(FactClass::EnvironmentIdentity);
    }
    None
}

// ------------------------------------------------------------------ the runs

/// One arm of the differential: a policy, and the document it produced.
#[derive(Debug, Clone, PartialEq)]
pub struct Arm {
    /// The declared policy.
    pub policy: SubstratePolicy,
    /// The recording, ready to serialise.
    pub document: J,
}

/// Run the identical script under two policies and diff the results.
pub fn run(
    left: SubstratePolicy,
    right: SubstratePolicy,
) -> Result<Differential, crate::error::ShimError> {
    let (l, r) = two_arms(left, right)?;
    diff(&l.document, &r.document)
}

/// Run the identical script under two policies and keep both documents.
pub fn two_arms(
    left: SubstratePolicy,
    right: SubstratePolicy,
) -> Result<(Arm, Arm), crate::error::ShimError> {
    let a = crate::scenario::run_with(left)?;
    let b = crate::scenario::run_with(right)?;
    Ok((
        Arm {
            policy: a.substrate_policy,
            document: a.document,
        },
        Arm {
            policy: b.substrate_policy,
            document: b.document,
        },
    ))
}

/// The two arms the committed differential uses.
///
/// `fabricated` against `withheld`, and *every* axis flipped at once.
///
/// Why all five: the point of the committed artefact is not to demonstrate one
/// axis in isolation but to show that a *maximally different* substrate still
/// leaves the app's own observable behaviour intact and moves only what the
/// declaration says it should. An all-defaults-versus-one-axis differential
/// would be easier to read and would prove less, because it would leave the
/// reader free to assume the other four axes are inert.
pub fn committed_policies() -> (SubstratePolicy, SubstratePolicy) {
    use crate::policy::{IdentityMode, NetworkMode, PackageMode, SystemFsMode, TimeMode};
    let loud = SubstratePolicy {
        identity: IdentityMode::Withheld,
        system_fs: SystemFsMode::Absent,
        cross_app_packages: PackageMode::Error,
        network: NetworkMode::SyntheticLoopback,
        time: TimeMode::Frozen,
    };
    (SubstratePolicy::default(), loud)
}

/// The label each committed arm carries, for filenames and prose.
pub fn committed_labels() -> (&'static str, &'static str) {
    ("fabricated", "withheld-absent-error-loopback-frozen")
}

/// A short human label for a policy, derived from its axis values.
///
/// Derived rather than stored so it cannot drift from the policy it names, and
/// filesystem-safe so it can be used in a recording's filename.
pub fn arm_label(p: &SubstratePolicy) -> String {
    Axis::all()
        .into_iter()
        .map(|a| format!("{}-{}", a.as_str(), p.axis(a)))
        .collect::<Vec<_>>()
        .join("_")
}

/// Convenience for tests and the binary: a [`ScenarioOutput`] as an [`Arm`].
impl From<ScenarioOutput> for Arm {
    fn from(o: ScenarioOutput) -> Arm {
        Arm {
            policy: o.substrate_policy,
            document: o.document,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IdentityMode, NetworkMode, PackageMode, SystemFsMode, TimeMode};

    #[test]
    fn the_classifier_never_calls_an_app_fact_a_substrate_fact() {
        // The load-bearing negative cases, one per rule that could get it wrong.
        assert_eq!(
            classify("/environment/is_emulator", None, None),
            FactClass::App
        );
        assert_eq!(
            classify("/environment/graphics/gl_renderer", None, None),
            FactClass::App
        );
        assert_eq!(
            classify("/environment/network/egress_available", None, None),
            FactClass::App,
            "egress_available belongs to no axis and must not be draggable by one"
        );
        assert_eq!(classify("/lifecycle/terminal", None, None), FactClass::App);
        assert_eq!(
            classify(
                "/classes/loaded/0",
                Some(&J::String("a.b.Main".into())),
                None
            ),
            FactClass::App
        );
        assert_eq!(
            classify(
                "/exceptions/0",
                Some(&json_obj(&[("class", "java.lang.UnsatisfiedLinkError")])),
                None
            ),
            FactClass::App
        );
        assert_eq!(
            classify("/diagnostics/0/t_mono_ms", Some(&J::from(12)), None),
            FactClass::App
        );
    }

    #[test]
    fn the_classifier_does_call_a_substrate_fact_a_substrate_fact() {
        assert_eq!(
            classify("/environment/build_fingerprint", None, None),
            FactClass::EnvironmentIdentity
        );
        assert_eq!(
            classify(
                "/classes/loaded/3",
                Some(&J::String("android.os.Build".into())),
                None
            ),
            FactClass::EnvironmentIdentity
        );
        assert_eq!(
            classify(
                "/diagnostics/2",
                Some(&json_obj(&[("pattern", "SIGNAL_PAT.PROC_STATUS")])),
                None
            ),
            FactClass::SystemFs
        );
        assert_eq!(
            classify(
                "/filesystem/accesses/3",
                Some(&json_obj(&[("path", "/proc/self/status")])),
                None
            ),
            FactClass::SystemFs
        );
        assert_eq!(
            classify(
                "/exceptions/1",
                Some(&json_obj(&[(
                    "class",
                    "android.content.pm.NameNotFoundException"
                )])),
                None
            ),
            FactClass::CrossAppPackages
        );
        assert_eq!(
            classify("/network/attempts/0/result", None, None),
            FactClass::Network
        );
        assert_eq!(
            classify("/clock/monotonic_resolution_ms", None, None),
            FactClass::Time
        );
        assert_eq!(
            classify("/substrate_policy/identity", None, None),
            FactClass::PolicyDeclaration
        );
        assert_eq!(
            classify("/summary/exception_count", None, None),
            FactClass::DerivedRollUp
        );
    }

    #[test]
    fn an_identity_that_contains_brackets_still_yields_its_whole_key() {
        // Regression test: `limits` entries generated from the policy start with
        // "[substrate_policy] ", and the classifier's `THIS RUN`-style marker test
        // was silently reading "substrate_policy" instead.
        let p = "/network/limits[[substrate_policy] NO BYTES MOVED. The egress sink refused…]";
        assert_eq!(
            bracket_key(p),
            Some("[substrate_policy] NO BYTES MOVED. The egress sink refused…")
        );
        assert!(classify(p, Some(&J::String("x".into())), None) == FactClass::PolicyDeclaration);
        // And an index-keyed fallback pointer has no key at all.
        assert_eq!(bracket_key("/diagnostics/#4"), None);
        assert_eq!(bracket_key("/diagnostics"), None);
    }

    #[test]
    fn the_enclosing_array_element_outranks_the_leaf() {
        // A diagnostic is identified by its `pattern`, not by the text of its
        // `detail`; getting this wrong is how a `Build.FINGERPRINT` read would
        // end up filed as an app fact.
        let element = json_obj(&[("pattern", "SIGNAL_PAT.BUILD_FIELD")]);
        assert_eq!(
            classify(
                "/diagnostics/4/detail",
                Some(&J::String("Build.FINGERPRINT = whatever".into())),
                Some(&element)
            ),
            FactClass::IdentityProbe
        );
        // And with no element, the same leaf falls through — which is the safe
        // default, because an unattributed difference is a false alarm and a
        // wrong class is a lie.
        assert_eq!(
            classify(
                "/diagnostics/4/detail",
                Some(&J::String("Build.FINGERPRINT = whatever".into())),
                None
            ),
            FactClass::App
        );
    }

    fn json_obj(pairs: &[(&str, &str)]) -> J {
        let mut m = serde_json::Map::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), J::String((*v).to_string()));
        }
        J::Object(m)
    }

    #[test]
    fn every_pattern_the_shim_emits_classifies_to_something_named() {
        // A pattern with no arm falls through to App, which is the safe default,
        // but the taxonomy's identity/net/fs patterns must all be *deliberate*.
        for p in [
            "SIGNAL_PAT.BUILD_FIELD",
            "SIGNAL_PAT.BUILD_TAGS",
            "SIGNAL_PAT.SDK_INT",
            "SIGNAL_PAT.EMULATOR_PROBE",
            "SIGNAL_PAT.PROC_STATUS",
            "SIGNAL_PAT.PROC_MAPS",
            "SIGNAL_PAT.PROC_OTHER",
            "SIGNAL_PAT.PROC_UPTIME",
            "SIGNAL_PAT.PROC_CPUINFO",
            "SIGNAL_PAT.PROC_MEMINFO",
            "SIGNAL_PAT.BATTERY",
            "SIGNAL_PAT.CPU_ONLINE",
            "SIGNAL_PAT.SYS_BLOCK",
            "SIGNAL_PAT.SYS_OTHER",
            "SIGNAL_PAT.ENTROPY",
            "SIGNAL_PAT.PM_QUERY",
            "SIGNAL_PAT.PM_SELF",
            "SIGNAL_PAT.SYSTEM_FEATURE",
            "SIGNAL_PAT.LOOPBACK_RESPONSE",
            "SIGNAL_PAT.HEADER_NAME",
            "SIGNAL_PAT.CLOCK_WALL",
            "SIGNAL_PAT.CLOCK_MONOTONIC",
            "SIGNAL_PAT.CLOCK_UPTIME",
            "SIGNAL_PAT.CLOCK_ELAPSED",
            "SIGNAL_PAT.SLEEP",
            "SIGNAL_PAT.MESSAGE_QUEUE",
        ] {
            let c = pattern_class(p);
            assert_ne!(
                c,
                FactClass::App,
                "{p} falls through to App, so it is undeclared"
            );
        }
    }

    #[test]
    fn a_policy_that_did_not_move_cannot_explain_anything() {
        let doc = crate::scenario::run_with(SubstratePolicy::default())
            .expect("run")
            .document;
        let d = diff(&doc, &doc).expect("diff");
        assert!(d.moved.is_empty());
        assert!(d.unattributed.is_empty());
        assert!(d.derived.is_empty());
        assert!(d.declared.is_empty());
        assert_eq!(d.identical_leaves, d.compared_leaves);
        assert!(d.compared_leaves > 400, "only {} leaves", d.compared_leaves);
    }

    #[test]
    fn an_array_element_is_identified_not_indexed() {
        // The regression test for the index-shift bug, written as the smallest
        // case that reproduces it.
        let a = serde_json::json!({
            "diagnostics": [
                {"pattern": "SIGNAL_PAT.WEBVIEW_LOAD", "detail": "one"},
                {"pattern": "SIGNAL_PAT.CLOCK_WALL", "detail": "two"}
            ]
        });
        let b = serde_json::json!({
            "diagnostics": [
                {"pattern": "SIGNAL_PAT.LOOPBACK_RESPONSE", "detail": "new"},
                {"pattern": "SIGNAL_PAT.WEBVIEW_LOAD", "detail": "one"},
                {"pattern": "SIGNAL_PAT.CLOCK_WALL", "detail": "two"}
            ]
        });
        let d = diff_aid(&a, &b);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(
            d[0].pointer,
            "/diagnostics[pattern=SIGNAL_PAT.LOOPBACK_RESPONSE]"
        );
        assert_eq!(d[0].left, None);
        assert!(
            matches!(&d[0].right, Some(J::Object(o)) if o.get("detail") == Some(&J::from("new")))
        );
    }

    /// `diff` over two bare fragments, by wrapping them so each carries a
    /// declaration. Used to test the walk without paying for two full runs.
    fn diff_aid(a: &J, b: &J) -> Vec<Difference> {
        let p = SubstratePolicy::default();
        let mut x = serde_json::Map::new();
        for (k, v) in a.as_object().expect("object") {
            x.insert(k.clone(), v.clone());
        }
        x.insert("substrate_policy".into(), p.to_json());
        let mut y = serde_json::Map::new();
        for (k, v) in b.as_object().expect("object") {
            y.insert(k.clone(), v.clone());
        }
        y.insert("substrate_policy".into(), p.to_json());
        let dx = diff(&J::Object(x), &J::Object(y)).expect("diff");
        dx.moved
            .into_iter()
            .map(|m| m.difference)
            .chain(dx.unattributed)
            .chain(dx.derived)
            .filter(|d| !d.pointer.starts_with("/substrate_policy"))
            .collect()
    }

    #[test]
    fn the_leaf_table_and_the_walk_count_the_same_leaf_space() {
        // The load-bearing cross-check for the sync arm. `leaves` and `walk` are
        // two views of one notion of a leaf; if their cardinalities ever diverge
        // the four-way classification and the earlier differential are counting
        // different things, and the intersection between them is arithmetic on
        // unrelated numbers.
        for (l, r) in [
            (SubstratePolicy::default(), SubstratePolicy::default()),
            committed_policies(),
        ] {
            let (a, b) = two_arms(l, r).expect("arms");
            let self_diff = diff(&a.document, &a.document).expect("diff");
            assert_eq!(
                leaves(&a.document).len(),
                self_diff.compared_leaves,
                "left arm"
            );
            assert_eq!(
                leaves(&a.document).len(),
                self_diff.identical_leaves,
                "a self-diff has no differences, so compared and identical coincide"
            );
            let both = diff(&a.document, &b.document).expect("diff");
            let one_sided = |ds: &[Difference]| {
                ds.iter()
                    .filter(|d| d.left.is_none() || d.right.is_none())
                    .count()
            };
            let moved: Vec<Difference> = both.moved.iter().map(|m| m.difference.clone()).collect();
            let two_sided = (both.moved.len() - one_sided(&moved)) + both.derived.len()
                - one_sided(&both.derived)
                + both.declared.len()
                - one_sided(&both.declared)
                + both.unattributed.len()
                - one_sided(&both.unattributed);
            assert_eq!(
                both.compared_leaves,
                both.identical_leaves + two_sided,
                "compared leaves split into identical and two-sided differences, and a one-sided \
                 difference is a pointer that was never a compared leaf at all"
            );
        }
    }

    #[test]
    fn a_repeated_array_identity_stays_addressable() {
        // Three `BUILD_FIELD` diagnostics share one identity, so `walk` writes the
        // same pointer three times and `leaves` has to disambiguate them or the
        // sync arm would silently compare one of them to itself N times.
        let doc = serde_json::json!({
            "diagnostics": [
                {"pattern": "SIGNAL_PAT.BUILD_FIELD", "detail": "a"},
                {"pattern": "SIGNAL_PAT.BUILD_FIELD", "detail": "b"},
                {"pattern": "SIGNAL_PAT.BUILD_FIELD", "detail": "c"}
            ]
        });
        let t = leaves(&doc);
        assert_eq!(t.len(), 6, "`pattern` and `detail` per element");
        let mut details: Vec<(String, &str)> = t
            .iter()
            .filter(|(k, _)| k.ends_with("/detail"))
            .map(|(k, l)| {
                (
                    k.clone(),
                    l.value.as_ref().and_then(|v| v.as_str()).unwrap_or(""),
                )
            })
            .collect();
        details.sort();
        assert_eq!(
            details.iter().map(|(_, d)| *d).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        for (k, _) in &details {
            assert_eq!(
                base_pointer(k),
                details[0].0,
                "every sibling must fold back onto the first occurrence's pointer, which is the \
                 one the differential writes"
            );
        }
        assert_ne!(details[0].0, details[1].0, "each element needs its own key");
    }

    #[test]
    fn the_loud_arm_moves_only_governed_facts() {
        let loud = SubstratePolicy {
            identity: IdentityMode::Withheld,
            system_fs: SystemFsMode::Absent,
            cross_app_packages: PackageMode::Error,
            network: NetworkMode::SyntheticLoopback,
            time: TimeMode::Frozen,
        };
        let d = run(SubstratePolicy::default(), loud).expect("differential");
        assert!(
            d.unattributed.is_empty(),
            "an app-class fact moved under two policies:\n{}",
            d.unattributed
                .iter()
                .map(|x| x.render())
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(!d.moved.is_empty());
        // And the app's own observable behaviour is intact.
        assert!(
            d.identical_leaves > 300,
            "only {} of {} leaves survived the substrate change",
            d.identical_leaves,
            d.compared_leaves
        );
    }
}
