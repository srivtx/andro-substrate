# 0008 — The interpreter runs real APKs, and the shim's compatibility surface is the measurement

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: how `tools/dexinterp` and `shim` are joined; that the boundary is
  a **layered class table**, not a DEX merge; what the framework layer is allowed
  to be; where the disk boundary moved and why; and — the load-bearing part —
  that **no shim class or method was added to produce any result in this ADR**.
- **Scope**: `tools/dexinterp/`, `shim/`, a new `harness/` crate, and
  `docs/decisions/0008-*` plus `harness/FINDINGS.md`. Does not touch `tools/dexcore/`,
  `analysis/`, `corpus/`, `oracle/`, `docs/research-protocol.md` or
  `docs/divergence-taxonomy.md`.
- **Supersedes nothing.** ADR 0005 chose supersede as a *decision*; this ADR
  implements it and measures what it costs. ADR 0006 and ADR 0007 left the sync
  control without a subject; this ADR supplies one.

## Context

[ADR 0003](0003-execution-engine.md) specified an interpreter with a `Host`
boundary. [ADR 0005](0005-shim-and-observation.md) built the other side and
chose a **supersede** classloader. Between them sat 153 interpreter tests, 201
shim tests and **no connection at all**. Nothing had ever executed a real APK.
`shim::scenario` drove the shim with a hand-written, branch-free call sequence,
which its own author flagged as degenerate: no `HashMap`, no retry, no locale, no
frame callback, so the sync control had no noise to measure.

The task was to close that gap, and the instruction that governs everything below
is that **growing the shim until an app appears to work is a measurement, not a
fix**. So this ADR records what the gap looks like when nothing is grown.

## Decision

### 1. The boundary is a layered class table, and it is not a merge

`dexinterp::Program::build_layered(&app_dex, &host_classes)` builds one class
table from two inputs:

* every `class_def_item` of the app's `classes.dex` whose descriptor the shim
  does **not** also declare, as [`ClassSource::Dex`];
* every class the shim's own DEX declares, as [`ClassSource::Host`], with
  `code_off` forced to `0` for every method **unconditionally**;
* the builtin framework table, only for descriptors neither input declared.

App classes the shim also declares are **dropped** and named in
`Program::shadowed` and `Stats::shadowed_classes`.

This is not a container operation and it never becomes one, because **no index
from the second file is ever mixed into the first file's operand space**. The
app's `method_ids` indices are untouched. A framework method the app's
instructions reference is *already* in the app's own pool as a bodiless entry —
the app cannot call a method whose id is not in its pool — and attaching a
declaration to that entry is exactly what turns `invoke-super` into a host call.
Framework methods the app never references are interned at fresh pool indices the
app's bytecode cannot name, which is correct: nothing needs them.

DEX merging remains unbuilt and is still a `dexcore` writer feature. ADR 0005's
six-item list stands unchanged; this ADR adds a fifth consequence, in §7.

### 2. The host is asked about the class that *declares* the method, and an `Abstract` slot is not "no such method"

**Both of these were bugs, found only by running a real app, and between them they
were the largest thing standing between an app and the shim.**

The engine resolved `MainActivity.getIntent()` — found nothing the app declared —
and handed the host `(MainActivity, getIntent, …)`. The shim's `lookup` walks the
registry's superclass chain, and `MainActivity` is not in the registry, so it found
nothing there either. Every *inherited* framework method on *every* app class was
reported as missing. The engine now passes the resolved declaring class, which is
what a classloader does: it resolves, and then it asks about what it resolved to.

The second is subtler and mattered more. `Program::vtable_lookup` returns an
`Abstract` entry for a slot the receiver's class inherits but does not implement —
**the commonest shape a framework call has** — and `vtable_target` was collapsing
that to `None`, which the dispatch loop then reported as
`NoSuchMethodError` *before the host was ever consulted*. So
`Activity.setContentView(int)`, which the shim implements, was recorded as
missing for a real app.

The fix is one line of intent: **a vtable slot resolves to a declaration, and a
bodiless declaration is routed to the host.** The measured effect is in
`tools/dexinterp/README.md`'s correction note: `fr.smarquis.sleeptimer_16200`'s
method census went from 28 returned / 57 raised to **40 / 45**, with
`NoSuchMethodError` falling from 16 to 4, and `eu.quelltext.gita`'s executed
instruction count went from 5 to **20**.

Both were *measurement* errors — they made the shim look smaller than it is. That
is the argument for the discipline below in one line: **growing the shim before
these were fixed would have added a dozen classes to compensate for an engine that
was mis-routing calls**, and the result would have been a number about nothing.

### 3. The two value conventions disagree, and the disagreement is resolved in one place

The engine's `Call.args` has `args[0] == this` for the instance forms. The shim's
`ShimCaller::invoke` takes *only* declared parameters for a `<init>`, because the
object it is constructing **is** the receiver. Both conventions are documented and
both are right.

Passing the receiver through made `java.net.URL.<init>(String)` parse the
receiver, and a later `connect()` then reported *"a connection with no URL"* —
**a plausible wrong answer produced by an instrument**, which is the single worst
failure mode this project has. The adapter now drops the receiver for `<init>`,
with the reasoning in `shim/src/interp.rs::args_to_shim`.

Two more translation rules, both in the same function:

* **Engine heap index ⇄ shim object id** is mediated by a high bit
  (`ENGINE_ID_BIT`) so the two id spaces cannot alias. Without it a shim-allocated
  object whose id equalled an engine heap index would share one `ObjState` — a
  *wrong* observation, not a missing one.
* **An argument the shim has no representation for is a refusal, not a `null`.**
  `HostOutcome::NotImplemented` plus a counter. A fabricated `null` would enter
  the recording indistinguishable from a real one, and the study would read it as
  a fact about the app.

### 4. A string's characters cross the boundary, and only because the engine was asked to

A `Value::Ref` is a heap index the host cannot resolve — the engine is mid-dispatch
and cannot be re-entered. `Host::wants_rendered_args()` (default `false`) is how
a host says "render every argument as a `HostValue` in parallel", which is the
only way `Intent.getAction`, `Bundle.getString` and `Uri.getQuery` can work at all.
The default preserves the existing cost, and the existing 153 tests are unchanged
because the mock hosts decline.

### 5. The disk boundary moved one crate outward, and the scan moved with it

`shim` has an **empty `std::fs` surface**, and `shim/tests/egress_denial.rs` proves
it three ways. A recorder that reads an APK cannot live there. So it lives in a
new crate, `harness/`, which is *not* part of the shim's source scan.

Leaving a new crate out of a source scan is how a scan gets defeated without
anyone noticing, so the scan **moved with it**: `harness/tests/no_side_channels.rs`
runs the same class of check over a fixed list of every file in the new crate,
forbids every networking and subprocess and syscall and thread symbol, and — as a
positive control, because a scan that cannot fail proves nothing — asserts that
the *only* filesystem calls in the whole crate are the recorder's three: read the
APK, write the recording, write the report.

`harness` declares exactly one non-project dependency, `flate2`, for inflate.
`harness/tests/no_side_channels.rs` says so in a test so that removing it looks
like a decision rather than like drift.

### 6. The recording for an executed run is a **patch** over the synthetic one, and the patch is enumerated

`shim::realrec::build_real` calls the existing `recording::build` and then replaces
`realrec::PATCHED_FIELDS` — 40 JSON pointers, listed in the source and asserted by
a test. A second, parallel builder would be two places to satisfy the schema's
cross-field invariants, and a differential comparing a document from each would be
comparing two shapes. The committed synthetic recording is byte-identical to what
it produced before this ADR, which is checked.

Three fields deserve their reasoning written down, because each is a place where
the schema's vocabulary has no substrate token and a wrong answer would be a lie:

| field | value | why |
|---|---|---|
| `synthetic` | `false` | the flag means "no app bytecode was run". That is false. `provenance.execution_performed: true` and `capture_quality.completeness: "partial"` are forced by the schema's own `allOf`. |
| `environment.kind` | `"synthetic"` | **unchanged.** The enum has no substrate value and inventing one is not this project's call. A substrate is not a device, so the only non-device token is correct, and a reader who wants substrate captures filters on `synthetic == false` and gets them. |
| `capture.root_shell` | `true` | unchanged, and this is the one field the module leans on without its name describing what it holds. Validator check S5 rejects a `T0_DIRECT` claim on a non-synthetic capture unless the recorder had a root shell or the app was debuggable. A substrate has neither and needs neither: it *is* the process. The field is the schema's only proxy for in-process observation authority, and `provenance.notes` says so in words rather than leaving a reader to reconcile a `root_shell` against a browser. |

`recorder.implementation` stays `"synthetic"` for the same vocabulary reason, with
the reason in `provenance.notes`. `provenance.capture_script_sha256` carries the
SHA-256 of the shim DEX the framework layer was built from — which *is* the code
that decided every answer the app received — and the note says it is not literally
the harness binary's digest, because a field that claims a provenance it does not
have is worse than an absent field.

### 7. What the merge path still needs, given this one exists

ADR 0005's six items stand. This ADR adds two observations that only became
visible once a real APK was being run:

* **A two-DEX `Program` is now demonstrably *sufficient* for an interpreter**, so
  the missing feature in `dexcore` is not "read two files" — it is only the
  operand rewriting. That narrows item 2 of ADR 0005's list from "pool import plus
  rewriting" to "rewriting alone", because the class table is the part that turned
  out to be easy and the operand renumbering is the part that has not been started.
* **Multi-dex is now a measurable number** rather than a caveat:
  `capture_quality.unobserved` carries an entry per skipped `classesN.dex` and
  `notes.substrate` carries the count. Zero for these 14 candidates; non-zero for
  any app above ~64 K methods, which is most contemporary ones.

### 8. Nothing was added to the shim, and that is the result

**0 shim classes and 0 shim methods were added for any of the 14 candidates.** The
full per-candidate table, the exact terminal errors, and the three framework
methods plus two declaration defects that stand between these apps and their next
instruction are in [`harness/FINDINGS.md`](../../harness/FINDINGS.md).

The headline: **highest `lifecycle.terminal` reached by any of 14 real APKs is
`L0_PROCESS_STARTED`; 0 reached `L1_ACTIVITY_RESUMED`.** The furthest candidate
(`eu.quelltext.gita_6`, the app `analysis/candidates.md` recommends) executed
**20 instructions** of its own bytecode and produced the sweep's most interesting
observations — `SIGNAL_PAT.SET_CONTENT_VIEW` and `SIGNAL_PAT.FIND_VIEW_BY_ID`,
fired because the app called them, not because a script called them. It then
stopped on the largest single blocker in the sweep, below.

Five stops are not gaps but **defects in the shim's own declarations** — classes
the shim declares with a method marked `ACC_ABSTRACT` that is concrete on every
device — and they are recorded rather than fixed, because fixing them mid-sweep
would have changed the table under the other rows:

* **`Ljava/lang/Object;.<init>()V` is `ACC_ABSTRACT`.** It is concrete
  everywhere, and **two** of fourteen apps died in a `super()` call — including
  the furthest candidate. This is the largest single blocker measured here and it
  is a one-line registry fix that was deliberately left unapplied.
* **`Landroid/content/BroadcastReceiver;.<init>()V` is `ACC_ABSTRACT`.** An inner
  `BroadcastReceiver` — half of Android's shape — cannot be constructed.

The three genuine *gaps* are `Activity.getIntent()` (2 apps),
`Activity.requestWindowFeature(int)` (2 apps) and the whole class
`java.util.Timer` (1 app). All three are **inherited members of a class the app
subclasses**, which is the pattern that matters: see `FINDINGS.md` §7 for why that
makes growing the shim a quarter of work rather than a week.

`L2_FIRST_FRAME_DRAWN` is **structurally unreachable**: there is no display, no
vsync and no rasteriser, so `first_frame_drawn` is never emitted. It is named in
`capture_quality.unobserved` on every recording rather than left to be inferred
from an absent event.

### 9. Supersede was never shadowed in practice, and that is a finding

**0 shadowing events across 14 real APKs.** Adversarial coverage is a test
instead: `shim/tests/interp_boundary.rs` feeds the shim's *own emitted DEX* in as a
hostile APK — a legal file declaring all 144 framework classes, one with a real
`code_item` — and asserts **144 shadowed classes**, **1 framework body refused**,
and that the shim's registry still answers. So the security property has a test
rather than an argument, and the honest reading is that supersede is unexercised
by honest APKs and load-bearing only against hostile ones.

## Consequences

### The positive consequence

The observation layer now records things **as consequences of execution**. A
shim that has not been called records zero events, which is a test, so a non-empty
array in a recording is a fact about the app. `search_to_browser`'s recording
contains `Landroid/app/Application;.onCreate() called, in the documented order`
because the driver called an *inherited* framework method on an app class that does
not override it — an observation the synthetic scenario had to write down by hand
and that here nobody wrote down.

The differential's subject is now a real program. `shim::syncdiff::repeat_real`
and `run_real` take a closure that runs the real DEX; ADR 0007's control has an
APK to point at.

### The negative consequences, stated plainly

- **The class-load census is structurally reduced under supersede.** Because the
  framework layer is known in advance, the engine rarely has to ask, so
  `classes.loaded` holds 0–1 entries per run where a device capture would hold
  hundreds. ADR 0005 lists "a shadowed app class is a silent disappearance" as a
  blind spot; this is a second, larger one — **the framework side of the census
  is a model, not a measurement**, and a recording that lists 144 framework
  classes as "loaded" would be a lie about what was observed.
- **`Graph`-free, `invokedynamic`-free.** Zero call sites were reached by these 13
  apps, so ADR 0005's `SUB.FW.INVOKEDYNAMIC` claim is **untested by this sweep,
  not refuted**. They are old and small. The host records a refusal with the
  bootstrap owner named, so a wider sweep produces a count.
- **The real-DEX sync arm is honest and currently weak.** It runs and it reports
  zero varying leaves, and that is because 0–20 instructions is not enough program
  for nondeterminism to express itself in. `Workload::RealDex`'s licence text says
  so in the report itself.
- **Single-DEX only.** Multi-dex is a count, not a capability.

## Alternatives rejected

| alternative | why not |
|---|---|
| **Grow the shim until apps run, then report the rungs** | The task's explicit prohibition, and on this evidence a quarter of work for a number that measures the author rather than the substrate. The compatibility cost is the transitive closure of `Activity`'s and `Context`'s public API, not a method count. |
| **Merge the two DEX files** | ADR 0005 §2's six items, none started. The layered class table gets an interpreter the *same* facts with none of them. |
| **A second recording builder for real runs** | Two places to satisfy the schema's cross-field invariants, and a differential comparing one of each compares shapes. `PATCHED_FIELDS` keeps the shape single-sourced and the patch enumerable. |
| **Put the APK reader in the shim** | It would break the empty-`std::fs` surface that `tests/egress_denial.rs` proves three ways, and the surface is load-bearing: an instrument that can open a file is an instrument that can be made to read one. |
| **Leave the new crate out of the source scan** | That is how a scan gets defeated without anybody noticing. The scan moved with the code and gained a positive control. |
| **Fabricate `null` for an argument the shim cannot represent** | A `null` in a recording is indistinguishable from an app's real `null`. The refusal is counted in `framework_calls_unimplemented` and in `SubstrateHost::unrepresentable_calls` instead. |
| **Emit `first_frame_drawn` when a layout pass runs** | It would be a fabrication: a `BoxNode` carries `painted: false` and there is no compositor. `L2` is reported as unreachable rather than claimed. |
| **Fix the two `ACC_ABSTRACT` constructors before reporting** | It would have changed the registry under the other twelve rows. They are reported as defects, with the fix named and unapplied — and one of them is the single largest blocker in the sweep, which is exactly why it is reported rather than quietly fixed. |

## References

- `shim/src/interp.rs` — `SubstrateHost`, the `dexinterp::Host` implementation.
- `shim/src/realdex.rs` — the lifecycle driver, the rung ladder, the missing surface.
- `shim/src/realrec.rs` — `PATCHED_FIELDS` and the recording patch.
- `shim/tests/interp_boundary.rs` — the seven boundary claims, on real DEX.
- `harness/` — the recorder: ZIP reader, manifest reader, the `apk-run` CLI, the
  inherited source scan, and `FINDINGS.md`.
- `tools/dexinterp/src/program.rs` — `HostClass`, `build_layered`,
  `host_classes_from_dex`, `Program::prototypes`, `method_code_offset`.
- `docs/decisions/0005-shim-and-observation.md` — supersede, and why merge is a
  writer feature.
- `docs/divergence/0007-sync-differential.md` — the control this supplies a
  subject for.
