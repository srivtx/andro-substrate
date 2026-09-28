# 0006 — The substrate is a declared parameter, not a given

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: that the shim's own behaviour becomes an explicit, serialised,
  versioned policy; what the axes are; what the policy provably cannot do; and
  what the policy family still cannot separate from the app.
- **Scope**: `shim/`, plus one optional top-level object in
  `oracle/schema/ground-truth.schema.json` and a section in
  `oracle/RECORDING.md`. Does not touch `corpus/`, `analysis/`, `tools/`,
  `docs/research-protocol.md` or `docs/divergence-taxonomy.md`.
- **Supersedes nothing.** [ADR 0005](0005-shim-and-observation.md) decided what
  the shim is *for*. It also recorded, in its "honest limits", the flaw this ADR
  exists to answer.

## Context

ADR 0005 built the shim as an observation layer and said, in the right spirit,
that the shim's answers are the researcher's choices and are recorded as choices.
It did not follow that sentence to its conclusion. The shim's author did:

> The layer observes a *different program*, and the difference is invisible in
> the output. The shim terminates every side effect. Once it has, the app's
> control flow is determined by the researcher's choice, not by the app. So every
> downstream fact — an exception, a lifecycle terminal, a `MISBEHAVE` outcome —
> is a *joint* property of app and shim, and the recording does not separate
> them. An analyst reading `exceptions[3]` will see 'the app threw' when the
> correct reading is 'the app reached a place the shim lacks, and then did
> whatever it does there'. This gets **worse the more plausible the shim is**: a
> shim returning obvious nulls fails loudly and is easy to discount; mine returns
> plausible `Build.*` and `/proc` values on purpose, so it produces recordings
> that read like measurements of the app and are partly measurements of me.

And on why the obvious fix was rejected:

> Separating 'the app does X' from 'the app, when X is denied, does Y' needs a
> substrate *parameter*, and this crate has none by design: the redaction rule
> forbids the first kind of knob and the egress rule forbids the second.

Both diagnoses are accepted in full, and the second one is the interesting part.
The objection is a real constraint, not a superstition — and it turns out to be a
constraint on the *kinds* of knob, not on knobs. A parameter over **what the shim
returns** is not a parameter over **what the shim may do**, and the whole design
below turns on keeping those two apart in the type system rather than in a review
comment.

## Decision

### 1. `shim::policy::SubstratePolicy` — five orthogonal axes

| axis | values | governs |
|---|---|---|
| `identity` | `fabricated` · `withheld` · `refusing` | `environment_identity`, `identity_probe` |
| `system_fs` | `fabricated` · `empty` · `absent` | `system_fs` |
| `cross_app_packages` | `subject_only` · `all_present` · `error` | `cross_app_packages` |
| `network` | `record_and_deny` · `synthetic_loopback` | `network` |
| `time` | `virtual` · `scaled{n,d}` · `frozen` · `host_real` | `time` |

Three values per axis are not decoration. Two of the load-bearing distinctions are
*third* answers that a two-valued design would collapse:

- `system_fs: empty` — the path **exists** and reads as zero bytes. That is
  neither plausible content (the old default) nor `ENOENT` (`absent`), and an app
  that calls `exists()` before `read()` takes a different branch under each. The
  first version of this ADR's own test suite caught that `absent` and `empty`
  were *identical to the app* because `read_path` returned `Ok([])` for a
  missing `/proc` entry. That was a pre-existing bug: the shim recorded `ENOENT`
  correctly and then told the app the file was empty. Fixed, and it is the
  clearest argument in the codebase for the axis having three values.
- `cross_app_packages: error` — a `NameNotFoundException` is observably
  different from "not installed, no error". An app with a `try`/`catch` behaves
  differently from one that silently finds nothing, and the *difference* is the
  measurement.
- `identity: refusing` — removing `android.os.Build` from the shim's own class
  table, so the failure is an ordinary `NoClassDefFoundError` from the ordinary
  classloader. Distinct from `withheld` because withholding hands the app a
  *value* to branch on while refusing removes the *question's subject*.

`time: host_real` is deliberately non-reproducible and says so
(`reproducible: false`). It exists so a study can *show* what a substrate that
leaks the host clock does, rather than argue about it.

### 2. The default is the confound

`SubstratePolicy::default()` is the pre-existing behaviour on every axis,
unchanged, so every pre-existing test keeps its meaning and the committed
recording is the same capture with a declaration attached.

A family whose default is the obviously-null substrate would make the *interesting*
value look like a curiosity and every comparison would be against a baseline no
real study would use. The plausible fabricator is the confound, so it is the
baseline and the others are counterfactuals.

### 3. The policy is applied at emission, and says which axis answered

`Detail::Probes` gained a typed `axis: Option<Axis>`. Every fabricated value in
the crate is produced through a path that sets it, and the rendered detail ends
with a fixed, greppable label:

```
probes SIGNAL_PAT.BUILD_FIELD: Build.FINGERPRINT = andro-substrate/shim/0.1.0:… [answered by substrate_policy axis identity]
```

`filesystem.accesses[].notes` carries the same sentence for `/proc`, `/sys` and
`/dev`, because that object has no other field free to say it.

`axis: None` is the common case and is not an oversight: a class resolution, a
`Bundle` write and a layout pass are the *app's* behaviour and belong to no axis.
The set of `None`s is the set of things the substrate did not decide.

### 4. The recording carries the whole declaration, and the schema holds it to it

`ground-truth/1` gains one **optional, substrate-only** top-level object,
`substrate_policy`, and nothing required became optional or weaker. It is absent
from a device capture because a device is not a substrate; absence means "no
substrate was involved", never "the default".

Three version numbers, because a recording has to be interpretable years later by
someone who has never read this file:

- `policy_format` (`"andro-substrate.substrate-policy/1"`) — the *shape*. A
  reader that does not recognise it must refuse rather than guess.
- `policy_version` (`u16`) — the *meaning* of the vocabulary. Bumped when a value
  is added, removed, or **redefined**, even if the shape is unchanged. Two
  documents with different `policy_version`s may use the same token for
  different things.
- `shim_version` — what a value *returns* is a property of the code, not only of
  the vocabulary.

Plus `policy_digest`: an FNV-1a 64 checksum over the canonical declaration, for
joining two recordings to "the same policy" without diffing prose. Explicitly not
a security property; chosen because it is eight lines and adds no dependency to a
crate whose dependency list is itself an invariant.

`substrate_policy.invariants` is a `const`-pinned block, and an axis's `governs`
list may not name `app`, `derived_roll_up` or `policy_declaration`.
`oracle/recorder/negative-tests.sh` has one negative case per constraint plus a
positive control.

### 5. The differential is the deliverable

`shim::differential` runs **one** script — `scenario::run_with`, a single
function with no per-policy branch — under two policies and diffs the two
documents. Three claims it has to earn, and all three are tested:

1. **Attribution from the recordings alone.** The classifier
   (`differential::classify`) is a pure function of a JSON pointer, its value and
   its enclosing array element. The axis values come out of each document's
   `substrate_policy` block, and the `governs` lists come out of the same blocks.
   An analyst with the two JSON files and no access to this crate gets the same
   answer.
2. **What did not move is the app.** The report counts it, because the unmoved
   set is the positive result.
3. **Nothing escapes attribution.** A difference in the `app` class between two
   runs of the same script is impossible if the shim does what it says, so the
   harness reports it as a bug rather than as a finding. This check earned its
   keep immediately: it caught that the first version compared array elements by
   *index*, so one policy inserting a single diagnostic made every later
   `probes[].id` and `substrate_probe_hits[].evidence` pointer appear to move.
   Elements are now compared by identity (`op`+`path`, `class`+top frame,
   `pattern`, `command`, `assumption_id`, …).

The committed pair is `shim/recordings/differential-{left.fabricated,right.loud}.recording.json`
with `differential.report.txt`. Both arms are validated by the oracle validator and
their `unattributed` list is empty.

### 6. What the policy provably cannot do, and how that is proved

**Egress.** `EgressSink` holds no policy field at all, so no policy value is even
in reach of it, and `EgressSink::request` returns `Result<Never, EgressDenial>` on
every path. The `network` axis's only power is *post-refusal presentation*:
`Detail::Net` gained a `presentation: NetPresentation` field, and
`NetPresentation::Loopback(r)` is layered on top of an `outcome` that is `Err`.
The recording's `network.attempts[].result` is `blocked_by_policy` under **both**
network values, `byte_totals_observed` is zero under both, and
`environment.network.egress_available` is `false` under both. The loopback arm
that does *not* move those three is the evidence.
`tests/policy.rs::no_policy_value_can_reach_a_real_socket` drives all 162
reproducible axis combinations through every network surface against a live
`TcpListener`, and asserts the sink refused on every net event of every run.

**Redaction.** The policy type is five enums. `SubstratePolicy` has five fields
and `LoopbackResponse` has three (`status`, `declared_body_bytes`,
`content_type`); a test asserts both field lists by name, so adding a `String`
either is the deliberate act of weakening the invariant or fails the build. Every
`set(axis, value)` takes a `&str` matched against a closed list, so there is no
path by which an app-supplied string becomes a policy value.
`tests/policy.rs::no_policy_value_can_capture_a_body_a_header_or_a_query_value`
runs 108 axis combinations with three canaries in the body, a header value and a
query value, and requires them absent from the events, the state and the
serialised document.

**Reproduction.** No environment variable, no feature flag, no file. The only way
to run a non-default substrate is `Shim::with_policy(..)`, so "which substrate
produced this" is a value in a struct rather than ambient configuration — and
`tests/egress_denial.rs`'s source scan, which forbids `std::env` outright, now
covers `src/policy.rs` and `src/differential.rs`.

## Consequences

### The positive consequence

The questions an app asked are now not measurements of the substrate. In the
committed differential, **1486 of 1617 compared leaves are byte-identical** across
two maximally different substrates, and the class-by-class tally of moved facts
lands entirely in the five governed classes.

> **Both numbers in that paragraph were wrong when this ADR was first accepted, and
> both are corrected here by [ADR 0007](../divergence/0007-sync-differential.md).**
>
> * **1486, not 1432.** The unmoved count was computed as
>   `compared_leaves - differences.len()`, and a pointer present in one document
>   and absent in the other is a difference that was never a *compared* leaf.
>   Subtracting it understated the unmoved set by exactly the number of one-sided
>   differences. The error ran in the direction that makes an unmoved set look
>   smaller than it is.
> * **A demonstration, not a measurement.** "The questions an app asked are now
>   not measurements of the substrate" is the correct *direction* and it was
>   stated about leaves that had not been shown to be app-determined. The sync arm
>   in ADR 0007 measured this workload's noise floor at **exactly zero** across
>   eight runs per arm, which confirms the script is deterministic and licenses
>   **nothing further**: a control that measures the noise floor of a
>   deterministic program cannot see the noise a real app would have introduced.
>   The 1486 remain a demonstration that the attribution mechanism works. Read
>   "not a measurement" as "not a measurement of the substrate" *and not a
>   measurement of the app either*.

Three results in that diff are worth reading closely, because they are the
confound in its pure form:

1. **The app's own exceptions are untouched; the substrate's are not.** Both arms
   contain `java.lang.ClassNotFoundException` (from the script's `Class.forName`)
   and two `java.lang.UnsatisfiedLinkError`s (from `loadLibrary`/`load`). The left
   arm *additionally* contains `java.net.ConnectException` ×2 and
   `java.io.IOException` ×2. The right arm instead contains
   `android.content.pm.NameNotFoundException` ×2 — and **no network exceptions at
   all**, because `synthetic_loopback` made `connect()` succeed. An app whose
   `catch (IOException)` block ran twice in one arm and never in the other has a
   behavioural difference, and nothing in either document says which app that is.
2. **The taxonomy's own attribution moved.** `SUB.TRUST.DEBUG_DETECT` is a probe
   hit in the left arm and absent in the right: `/proc/self/status` resolves under
   `system_fs: fabricated` and is `ENOENT` under `absent`, and the shim labels a
   *successful* read of that path `TrustDebugDetect` and a failed one
   `KernelProcSelf`. So the **divergence ID the shim assigns to a probe depends on
   whether the probe succeeded** — which means the ID is partly a statement about
   the substrate, not only about the app, and `substrate_probe_hits` cannot be
   read as a pure census of app assumptions. This is a pre-existing property of
   `read_system_tree`'s fallback and it was invisible until two policies existed.
3. **The refusals that did not move are the strongest evidence.** Across both
   arms: `environment.network.egress_available` is `false`,
   `byte_totals_observed.tx_bytes` is `0`, and every
   `network.attempts[].result` is `blocked_by_policy` — including in the arm that
   showed the app a 200. `classes.loaded` (7), `jni.calls` (2),
   `lifecycle.terminal` (`L2_FIRST_FRAME_DRAWN`) and the number of network
   attempts (3) are all identical. The part of the recording that did not change
   when the parameter changed is not a measurement of the substrate.

### The negative consequences, stated plainly

- **216 substrates exist** and a recording can be read by someone who assumes the
  default. Every axis that differs from the default gets its own
  `capture.observer_effects` entry, generated from the declaration rather than
  written by hand, but a reader who ignores that block is still reading a
  document about a substrate they may not have chosen.
- **The format forces a minimum identity claim.** `environment.sdk_int` has
  `minimum: 1`, so a policy that withholds identity entirely must still report
  SDK 1 and release `"1"`. The recording names the floor; the residual is real.
- **`/dev` routing changed.** `dispatch::is_system_path` now includes `/dev`,
  because the fabricated tree models `/dev/urandom` and the classifier, the axis
  statements and the `limits` prose all counted it. A model that lists a path the
  router never reaches is a model that cannot be claimed for.
- **A `/proc` read of an unmodelled path now returns `ENOENT` to the app**, not an
  empty byte string. This is a behaviour change to the pre-existing shim, and it
  is a bug fix: the shim was recording the refusal and then contradicting it.
- **The shim reuses one taxonomy ID across two axes.** `SUB.NATIVE.LOAD_LIBRARY`
  is attached both to the JNI machinery and to the `/proc/self/maps` system-tree
  entry, so its roll-up over a changed `system_fs` axis is a sum of mixed
  composition. The classifier files such roll-ups as `derived_roll_up` and says so
  rather than inventing an owner.

## What the policy family still cannot separate from the app

**The most important thing: it cannot separate the substrate from the app's own
nondeterminism, and every conclusion drawn from the committed differential rests on
the script being deterministic.**

The differential's input is `shim::scenario::run_with` — a fixed sequence of
calls, deliberately branch-free, with the virtual clock advanced by literals. That
is what makes "the same script" true, and it is also exactly what the harness
cannot check. On a real run the same diff would be confounded by everything the
interpreter does that is not the policy: the app's own scheduling, a `HashMap`
iteration order, a retry, a timestamp, a locale, an animated layout that lands on
a different frame. Every leaf that "did not move" would be a leaf that happened not
to move. **The report's headline number — 1432 of 1617 leaves identical — is
therefore evidence about a deterministic program under two substrates, and about
nothing else.** It is a demonstration that the *mechanism* works, not a measurement
of any app. Anyone who reads it otherwise has reintroduced exactly the error the
ADR exists to name, one level up.

> **Status: the arm exists.** [ADR 0007](../divergence/0007-sync-differential.md)
> implements it. Two things to carry forward from this section, both settled:
>
> * The number was **1486**, not 1432. The unmoved count was an undercount; see
>   the correction in Consequences above.
> * **Of the 1486 leaves reported as unmoved, 0 move between identical runs** at
>   N = 8 per arm. That is a real result and it is the *uncomfortable* one: the
>   correction is zero because the workload is degenerate with respect to the
>   confound, not because the confound is gone. The 1486 are a demonstration. The
>   control exists now, and it has been measured; what it measured was the shim's
>   own determinism, because that is all the input contains.
>
> The two items below are therefore no longer "what would fix it" but "what is
> still missing": the *subject* is still a script and not an APK.

This is not fixable inside the differential, because it is a property of the
absence of an interpreter. What would fix it, and does not exist yet:

1. **Run the same APK twice under the same policy** and diff. Whatever moves
   between those two runs is the app plus the interpreter. Subtract it from the
   policy-to-policy diff and what is left is the substrate. Without this arm the
   first number is not a measurement. — *The arm exists
   (`shim::syncdiff`, ADR 0007). What does not exist is an APK to point it at.*
2. **N runs, not two.** A single policy-to-policy diff cannot distinguish a small
   substrate effect from a large app effect that happened to cancel. — *Done: the
   committed arm is N = 8 per arm, giving 64 left/right pairings per leaf, and 0
   of the 345 substrate-determined leaves disagree in only some of them.*

Until arm 1 exists, the honest summary is: *the shim's dependence on its own
behaviour is now declared, labelled per-observation, and demonstrably the sole
cause of every difference the harness can see — and the harness cannot yet see
whether the app also had a say in those differences.* — *Superseded by ADR 0007,
which measures that floor at zero for this workload and therefore cannot show the
app had no say either.*

### And four smaller things, in descending order of how much they should worry you

- **The axes are a partition the shim's author chose.** A behaviour that is a
  joint property but is *filed* under a class no axis governs is reported as
  unattributed, which is a false alarm; a behaviour filed under a class an axis
  governs when it is not is a false all-clear. The classifier is a hand-written
  table of prefixes and patterns, and its coverage is asserted only against
  *today's* document. A schema change that moved a field under a different prefix
  would change attribution silently. The `unattributed` check catches the first
  failure mode and cannot see the second.
- **`all_present` is a deception knob, and that is now fine.** It reports packages
  installed that are not, and the list-valued queries return a non-empty list
  whose contents are *not materialised* because the shim knows nothing about the
  other apps. That is a genuinely new third outcome — "told yes, given nothing
  usable" — and no real device produces it. It is declared, which is the point, but
  a study that runs the `all_present` arm is measuring a substrate nobody ships.
- **A policy can only vary what the shim has a value for.** Every axis answers
  questions the shim models. `SUB.RES.ARSC`, `invokedynamic`, Binder, input
  delivery and the vsync loop are not axes and cannot become axes, because there
  is no *value* to vary — only a missing mechanism. The confound is measurable
  exactly where the shim has something to say, and the parts of the surface with
  nothing to say are as unmodelled as they were. The differential makes the
  modelled part look better than it is, because a part with no axis is a part with
  no evidence in the report.
- **The `app` class is a claim about the shim's completeness, not a proof.** "This
  fact was not decided by the substrate" is only as good as the classifier, and
  the classifier is a table someone wrote. Every addition to the recording format
  is a chance to mis-file a fact, and a mis-filing in the `app` direction is the
  one the harness is built to catch and cannot catch — there is nothing to catch it
  against.

### Rejected alternatives

- **A `--allow-egress` flag, or an `IdentityMode::Real`.** Rejected: the objection
  in the Context section is correct about this. A knob over *permissions* is a
  different and much worse design, and the type system now makes it impossible to
  write by accident.
- **Making the default the obvious null-substrate.** Rejected: it would make every
  comparison in the study a comparison against a baseline nobody would use, and it
  would have hidden the fact that plausibility is the confound.
- **Recording both answers in one document** — run the script twice inside the
  recorder and emit a document with two `environment` blocks. Rejected: the format
  is a *recording*, and two recordings merged into one is two recordings that
  cannot be validated, diffed or cited separately. The oracle format's whole value
  is that one document is one run.
- **A `substrate_effects` field on every observation** (a list of axes that *could*
  have mattered, per fact, rather than the one that did). Rejected: it is
  unauditable — nothing would ever populate the "could have" part, and an
  unauditable field in an evidence format is worse than no field.

## References

- `shim/src/policy.rs` — the type, the axes, the versioning, the serialisation.
- `shim/src/differential.rs` — the classifier, the walk, the report.
- `shim/tests/policy.rs` — the evidence for every claim above.
- `shim/recordings/differential.report.txt` — the worked differential.
- `shim/recordings/sync-differential.report.txt` and
  `docs/divergence/0007-sync-differential.md` — the control this ADR asked for,
  and the correction to this ADR's own numbers.
- `oracle/RECORDING.md` §3.1 — the format-level statement.
