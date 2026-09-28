# 0007 — A policy-to-policy diff is a mechanism demonstration, not a measurement

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: that the substrate differential requires a **sync arm** — the same
  workload repeated N times under *one* policy — before any difference it reports
  may be called a substrate effect; what the four-way decomposition is; and what
  remains unattributable even with the control in place.
- **Scope**: `shim/`, plus corrections to the places where a committed document
  presented the earlier number as a measurement. Does not touch `corpus/`,
  `analysis/`, `tools/`, `oracle/`, `docs/research-protocol.md` or
  `docs/divergence-taxonomy.md`.
- **Amends**: [ADR 0006](decisions/0006-substrate-policy.md). 0006 is right and
  remains accepted; it named the missing arm and said that without it the first
  number is not a measurement. This ADR builds that arm, and then answers the
  question 0006 could not: **what does the arm's answer do to the number?**
- **Supersedes nothing.**

## Context

[ADR 0006](decisions/0006-substrate-policy.md) built the substrate policy family
and the differential over it, and then recorded, in the same document, why the
result it had just committed was weaker than it looked:

> **The most important thing: it cannot separate the substrate from the app's own
> nondeterminism, and every conclusion drawn from the committed differential rests
> on the script being deterministic.**
>
> The differential's input is `shim::scenario::run_with` — a fixed sequence of
> calls, deliberately branch-free, with the virtual clock advanced by literals. That
> is what makes "the same script" true, and it is also exactly what the harness
> cannot check. […] Every leaf that "did not move" would be a leaf that happened
> not to move. **The report's headline number — 1432 of 1617 leaves identical — is
> therefore evidence about a deterministic program under two substrates, and about
> nothing else.**
>
> What would fix it, and does not exist yet:
>
> 1. **Run the same APK twice under the same policy** and diff. Whatever moves
>    between those two runs is the app plus the interpreter. Subtract it from the
>    policy-to-policy diff and what is left is the substrate. **Without that arm the
>    first number is not a measurement.**
> 2. **N runs, not two.** A single policy-to-policy diff cannot distinguish a small
>    substrate effect from a large app effect that happened to cancel.

That is the state of the art: a correct diagnosis, an unimplemented remedy, and a
committed number in the repository that a reader will quote as a measurement
because nothing in its neighbourhood says otherwise.

The gap is not a missing feature. It is that a *measurement* is a claim about a
population of runs, and the harness has been making population claims from single
runs. Two documents cannot support a statement about variance. Neither can
sixteen, but sixteen can at least say whether the variance is zero, and sixteen
runs per arm also remove the cancellation objection that a single pairing cannot
address.

## Decision

### 1. The sync arm, and the decomposition it enables

`shim::syncdiff` runs the **same** `scenario::run_with` **N** times under the
**same** `SubstratePolicy` and diffs those N documents against each other. It
reuses the existing harness rather than forking it: the leaf space, the array
identity function and the fact classifier are `differential::leaves`,
`differential::array_identity` and `differential::classify`, and
`differential::tests::the_leaf_table_and_the_walk_count_the_same_leaf_space`
asserts that the two views agree on the cardinality of the leaf space, so the
four-way counts and the earlier differential's counts are about the same things.

Each leaf lands in exactly one of four buckets.

| bucket | moves under repetition | moves across policies | what may be said |
|---|---|---|---|
| `policy_varies` | no | yes | **substrate-determined.** The only bucket that licenses the claim. |
| `sync_varies` | yes | no | app + interpreter. Any diff that called this leaf unmoved got it wrong. |
| `both` | yes | yes | substrate and program both acted. Unattributable. |
| `stable` | no | no | nothing, in either direction. |

The four partition the leaf set — asserted, not asserted-to — and
`substrate_determined` is a predicate on `policy_varies`, not a fifth bucket, so
the counts always sum to the universe. The asymmetry is the whole point: a leaf
in `sync_varies` is a false negative owed to the earlier result, and a leaf in
`both` is a *worse* problem than either half, because not even the size of the
effect is measurable from N runs. Neither is folded into the other, and `stable`
is never reported as a positive result.

**Definitions, because they are arguable.** *Absence is a value*: a pointer
present on some runs and not others is one leaf that varies, which is the shape an
early-returning branch or an inserted diagnostic takes. *`policy_varies` is set
inequality*, not run-0 inequality: two policies that both wander produce unequal
value sets even where the substrate had nothing to do with it. That is
conservative — it pushes such leaves into `both` rather than into
`policy_varies` — and the cost is stated in the report. *The earlier result's
unmoved set is matched on the base pointer*, because a repeated array identity is
one pointer to the two-document differential and several leaves to an N-way
comparison, and pretending otherwise would understate the correction.

**N.** `MIN_RUNS = 5` is the floor below which a zero is too weak to mean
anything, and `COMMITTED_RUNS = 8` is what the committed artefact uses. A
two-run control is the single diff 0006 says is not a measurement, so
`syncdiff::repeat` refuses `n < 2` and the report prints the escape probability
rather than assuming the bound is zero.

### 2. Two arithmetic corrections the control forced into the open

Writing the control down required saying precisely how many leaves did not move,
and the number the committed report printed was wrong.

**The unmoved count was an undercount.** `differential::diff` computed
`identical = compared_leaves - differences.len()`. A pointer present in one
document and absent in the other is a difference, but it was never a *compared*
leaf — the walk only counts leaves it reached on both sides. Subtracting it
understated the unmoved set by exactly the number of one-sided differences.
**The committed "1432 of 1617" was 1486 all along.** The error ran in the
direction that makes an unmoved set look *smaller* than it is, which is the
direction that reads as caution and is in fact a wrong number. The walk now counts
identical leaves as it goes, and `shim/tests/sync_differential.rs`
(`the_unmoved_count_is_recomputed_and_agrees_with_the_differential`) asserts that
two independent derivations — the walk and the leaf table — produce the same
figure.

**The two leaf spaces do not tie by eye, and that is not an error.** The
reconciliation is printed in the artefact:

```
leaves compared at run 0 (present in both arms)            1617
of those, identical                                        1486
of those, differing                                         131
leaves present on one side only (leaf addresses)            214
substrate-determined, total                                 345
entries in the earlier report's difference lists            185
distinct pointers in those lists                            154
```

131 + 214 = 345. The 185 entries collapse to 154 pointers because one pointer can
carry several differences, and six `SIGNAL_PAT.BUILD_FIELD` diagnostics that exist
only in the right arm are one line of the earlier list and six leaf addresses. An
N-way comparison has to address the same leaf in N documents at once, so it counts
addresses. Where a whole array element is absent the walk records the difference
at the *element* pointer rather than at the leaves beneath it, which is a third
granularity and the reason the two pointer counts differ from each other too. All
three numbers are printed so a reader who adds them up differently is not left
wondering whether one of them is wrong.

### 3. The result, and the correction it owes

Committed artefact: `shim/recordings/sync-differential.report.txt`, regenerated by
`shim-sync-differential` and checked byte-for-byte by
`shim/tests/sync_differential.rs::the_committed_sync_report_is_current`. **N = 8
per arm. Workload: `shim::scenario::run_with`. Left policy `default()`
(`identity-fabricated_system_fs-fabricated_cross_app_packages-subject_only_network-record_and_deny_time-virtual`,
digest `fnv1a64:3831a4e300ed0c91`); right policy the ADR 0006 loud arm
(`identity-withheld_system_fs-absent_cross_app_packages-error_network-synthetic_loopback_time-frozen`,
digest `fnv1a64:b71360edcacb3d39`).**

| | count |
|---|---|
| leaf universe (addresses, over 16 documents) | 1831 |
| `policy_varies` — **substrate-determined** | **345** |
| `sync_varies` — app + interpreter | 0 |
| `both` — unattributable | 0 |
| `stable` | 1486 |
| leaves the earlier diff called unmoved | 1486 |
| **of those, leaves that move between identical runs** | **0** |
| leaves the earlier diff called moved that no policy owns | 0 of 345 |
| of 64 left/right pairings per leaf, policy-varying leaves disagreeing in *some* | 0 |

**The headline number is zero, and that is the result.** Of the 1486 leaves the
earlier differential reported as not moving, **zero** move between identical runs.
Every false negative the previous result owed is paid: there are none.

And the correct reading of that zero is the uncomfortable one. The correction is
zero because the workload is **degenerate with respect to the confound**, not
because the confound is absent from the method. The input is a fixed call
sequence: there is no `HashMap` to reorder, no retry, no locale, no frame
callback, no interpreter. A control that measures the noise floor of a
deterministic program cannot see the noise a real app would have introduced, and
so its zero **does not upgrade the earlier number to a measurement**. The
strongest claim the harness can now support about the committed pair is narrower
than the one the reader was about to make, and the whole point of building the
control was to find that out rather than to have it discovered later.

**The control has power, and this is shown without manufacturing anything.** The
shim already had an axis value that declares itself non-reproducible:
`TimeMode::HostReal`, which reads the host's wall clock and is the leak ADR 0006
put in the family on purpose. Eight runs of the scenario under that policy produce
documents that differ, the control finds the leaves that differ, every one of them
is a clock fact, and **none of them is ever filed as substrate-determined**. A
control that reported zero everywhere would have demonstrated nothing; this one
demonstrates detection on the only nondeterminism this crate has.

That control's *counts* are deliberately not committed. How many leaves move
depends on how long each run took on the machine that produced the file: two runs
whose `SystemClock.elapsedRealtime` read lands in the same millisecond are
byte-identical, and a loaded machine moves that boundary. Committing them would be
committing noise and calling it a result. The artefact therefore states the arm,
its N and its `reproducible: false` declaration, and the three stable claims live
in the test suite as assertions of `> 0`.

**The second objection, answered for this workload.** ADR 0006 warned that one
diff cannot distinguish a small substrate effect from a large app effect that
happened to cancel. With 8 runs per arm there are 64 left/right pairings per leaf.
Of the 345 substrate-determined leaves, **345 disagree in all 64 pairings and 0
disagree in only some**, so nothing on this input is a cancellation. That is a
statement about a deterministic input, and the report says so rather than
generalising it.

## Consequences

### The positive consequence

- **The unmoved count is now a correct number.** 1486, not 1432, and computed two
  ways that are asserted to agree.
- **There is a control, it runs, and its result is committed.** A study can now
  point the same arithmetic at a real APK, and the report it produces will say
  what the noise floor is rather than assuming there is none.
- **A difference may be called a substrate effect only with the sync arm behind
  it.** `policy_varies` is the sole license, and it is defined negatively first:
  a leaf that varies under repetition is never substrate-determined. That is
  asserted as a sweep over every leaf of every experiment in the suite
  (`a_leaf_that_varies_under_sync_is_never_substrate_determined`), not as one
  example.
- **The mechanism is unchanged and still sound.** `run_with` is one function, both
  arms declare their policy, the classifier is still a pure function of pointer
  and value, and the committed pair is byte-identical to what the sync arm's run 0
  produces (`the_sync_arm_reproduces_the_committed_recordings_byte_for_byte`). The
  control was added to the *argument*, not to the recording format: no new field,
  no new schema, no second document type.

### The negative consequences, stated plainly

- **The unmoved set is still not a measurement of anything.** It is a fact about
  this program under two substrates, measured on a workload that has no
  nondeterminism to confound it. The `stable` bucket is explicitly reported as
  licensing nothing, because "did not move here" and "not exercised here" are the
  same observation from inside the harness.
- **The harness is still not pointed at an APK.** The missing arm 0006 asked for
  is built; the missing *subject* is not. Until the input is bytecode the control
  is measuring the shim's own determinism, which is worth knowing and is not the
  question the project exists to answer.
- **The leaf space grew a second granularity.** `differential::leaves` addresses a
  repeated array identity with a `~{occurrence}` suffix so an N-way comparison can
  name one leaf in N documents. The two-document walk keeps its pointer-only
  naming, because it pairs positionally. Both are correct; they are not
  interchangeable, and the report prints all three granularities so the arithmetic
  is checkable. A future schema change that adds a new array of objects without an
  identity function will silently move every member to index addressing in both
  views — which is a loss of precision, not a change of result, and the
  `unattributed` check still catches the failures that matter.
- **The `both` bucket cannot be driven to zero and must not be asserted to be
  zero.** It is where coincidence lands, coincidence is not a bug to be fixed, and
  a test that forced it to zero would be manufacturing a result. On the committed
  pair it is empty; that is a fact about that pair.
- **A control that returns zero invites over-claiming more than one that returns
  a number.** The report therefore prints the licence paragraph *inside* the
  zero branch, the differential's own report carries the same correction, and two
  tests assert the wording is still there. The failure mode being defended against
  is a future reader, not a future run.

### Rejected alternatives

- **Report only the count of moving leaves and not the four-way table.** Rejected:
  it hides the `both` bucket, and `both` is where an honest harness says *I cannot
  tell*. A decomposition that only ever has two answers is the same error as the
  single diff, one level up.
- **Make the workload nondeterministic on purpose** — a per-run counter, an
  iteration over a `HashMap`, a `host_real` arm in the *committed pair* — to
  produce a non-zero noise floor and make the control look useful. Rejected: the
  number would then be a property of the knob, and the committed pair's headline
  would move with machine timing, which is the failure mode the whole module is
  built to detect. The control is demonstrated on the one nondeterminism the
  substrate already had and already declared.
- **Commit the host-clock leaf list with the values redacted to counts.**
  Rejected: even the *list* is timing-dependent, because whether a
  `CLOCK_ELAPSED` read moves depends on where the millisecond boundary falls
  between two runs. Asserting `> 0` in a test is the stable form of the same
  claim.
- **Fold `sync_varies` and `both` into a single "not attributable" bucket.**
  Rejected: they are different failures with different remedies. `sync_varies` is
  the earlier result's false negative and is subtracted. `both` is not
  recoverable by more runs and must stay visible.
- **Compare run *i* of the left arm with run *i* of the right arm and call that
  "the policy diff at N".** Rejected: index-matching is arbitrary, and with a
  wandering leaf it manufactures a difference between two runs of the same policy.
  The set comparison is the conservative form; the per-leaf pairing count is
  reported alongside it so the reader can see the policy effect's stability
  directly.

## What remains unattributable even with this control

1. **Coincidence.** A leaf that is nondeterministic *and* substrate-sensitive at
   the same time is unattributable at any N. It lands in `both` when the sample
   catches it and in `policy_varies` when the sample misses it, and the second
   case is indistinguishable from a genuine substrate effect. No repetition inside
   this harness removes the possibility; only a workload whose nondeterminism is
   independent of the substrate would, and nothing can establish that from the
   inside.
2. **The sampling hole.** A per-run nondeterminism of probability `p` slips past
   an N-run arm with probability `(1-p)^(N-1)`. At N = 8 that is 0.932 for
   `p = 0.01`, 0.478 for `p = 0.10` and 0.008 for `p = 0.50`. A measured zero is a
   statement about these eight runs, not a proof of determinism, and the report
   prints those three numbers precisely so the residual cannot be read as zero.
3. **The missing subject.** The input is a script, not an APK. The
   nondeterminism an interpreter contributes is not in the input, so the control
   has nothing to measure it from. This is the same gap ADR 0006 described; the
   difference is that it is now *measured* rather than *assumed*, and the
   measurement is the reason to keep describing the earlier number as a
   demonstration.
4. **Model versus reality.** Nothing here is a statement about a device. The
   third thing a study needs — what the program does on hardware — is outside
   every file in this repository, and no number in the sync report is evidence
   about it.

## References

- `shim/src/syncdiff.rs` — the four buckets, the runner, the report.
- `shim/src/differential.rs` — `leaves`, `base_pointer`, and the walk that now
  counts identical leaves as it goes.
- `shim/tests/sync_differential.rs` — every claim above, including the
  162-combination egress sweep extended to the new path.
- `shim/recordings/sync-differential.report.txt` — the committed artefact.
- `shim/recordings/differential.report.txt` — the corrected unmoved count.
- `docs/decisions/0006-substrate-policy.md` — the diagnosis this ADR implements.
