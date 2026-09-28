# Recordings

## The five files here

| file | what it is |
|---|---|
| `synthetic.recording.json` | the shim under the **default** substrate policy. The regression fixture for the observation layer. |
| `differential-left.fabricated.recording.json` | the **left arm**: the same script under the default policy. |
| `differential-right.loud.recording.json` | the **right arm**: the same script under the loudest substrate in the family. |
| `differential.report.txt` | the attribution table, computed **from the two JSON files alone**. |
| `sync-differential.report.txt` | the **control**: the same workload run 8× per arm under one policy, and the four-way decomposition. |

**All five are synthetic fixtures, not evidence.** See the note below; it applies
to every file in this directory.

## The differential, and why it is committed

The shim terminates every side effect, so an app's control flow after a refusal is
determined by the shim. Every fact downstream of that — an exception, a lifecycle
terminal, a `MISBEHAVE` outcome — is a **joint** property of app and substrate, and
one recording cannot separate them. The fix is not a better annotation; it is a
second run.

Both arms execute **the same function**, `shim::scenario::run_with`, with no
per-policy branch anywhere in the script. The only thing that differs is the
`SubstratePolicy` value, and each arm's recording carries that value in its
top-level `substrate_policy` block. All five axes differ:

| axis | left | right |
|---|---|---|
| `identity` | `fabricated` | `withheld` |
| `system_fs` | `fabricated` | `absent` |
| `cross_app_packages` | `subject_only` | `error` |
| `network` | `record_and_deny` | `synthetic_loopback` |
| `time` | `virtual` | `frozen` |

The result, in the report's own words: **1486 of 1617 compared leaves are
byte-identical**, every moved fact is attributed to an axis that actually changed,
and the `app` class — the things the substrate did not decide — moved zero.

### Read this before you cite the number

**It is a demonstration of a mechanism, not a measurement of anything.** 1486 of
1617 is evidence about a **deterministic script** under two substrates. It
demonstrates that the attribution mechanism works. It is **not** a measurement of
any app, and it cannot be: the input is a fixed call sequence, so it contains no
app nondeterminism for the harness to mistake for a substrate effect. A fact that
did not move is a fact about *this program* under two substrates — it is not
evidence that the app decides it, either.

The number was **1432** when the first version of this README was written. That was
an arithmetic error: the unmoved count was `compared − every difference`, and a
pointer present in one document and absent in the other is a difference that was
never a compared leaf. 1486 is the corrected figure and
`docs/divergence/0007-sync-differential.md` explains it.

### The control exists, and its answer is zero

`shim-sync-differential` runs the same workload **8 times per arm under one
policy** and diffs those runs against each other: whatever moves there moved with
no substrate decision changing, so it is app + interpreter. That is the arm
ADR 0006 said was missing, and without it the number above is not a measurement.

It is built, and it is committed as `sync-differential.report.txt`. Its answer for
this workload:

| | count |
|---|---|
| of the 1486 leaves reported as unmoved, leaves that move between identical runs | **0** |
| `policy_varies` — substrate-determined | 345 |
| `sync_varies` — app + interpreter | 0 |
| `both` — unattributable | 0 |
| `stable` — nothing claimed | 1486 |

**Zero is the real result, and it does not upgrade the number above.** It confirms
the script is deterministic — the assumption the earlier result rested on and
which nothing before this could check. It cannot show an app had no say, because
there is no app in the input for one to have. The correction owed is zero because
the workload is degenerate with respect to the confound, not because the confound
is gone.

The control is shown to have power on `time: host_real`, the one axis value whose
own declaration says `reproducible: false` and which reads the host's wall clock:
eight runs of that policy produce documents that differ, and every leaf that
differs is a clock fact. Its *counts* are deliberately not committed, because
whether a host-clock read lands in the same millisecond on two runs depends on how
loaded the machine is.

`docs/divergence/0007-sync-differential.md` is the ADR. It also states what remains
unattributable even with the control in place — coincidence, the `(1-p)^(N-1)`
sampling hole, the missing subject, and the gap between a model and a device.

### Regenerating

```sh
cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-record \
    > shim/recordings/synthetic.recording.json

cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-differential \
    > /tmp/differential.txt

cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-sync-differential \
    > shim/recordings/sync-differential.report.txt
```

`shim-differential` prints both arms and the report to **stdout**, separated by
`==== … ====` marker lines, because this crate's `std::fs` surface is empty and
that is one of the two halves of the invariant `tests/egress_denial.rs` checks. To
split it into the three committed files:

```sh
awk '/^==== left arm/  {f="recordings/differential-left.fabricated.recording.json"; next}
     /^==== right arm/ {f="recordings/differential-right.loud.recording.json"; next}
     /^==== report/     {f="recordings/differential.report.txt"; next}
     /^==== /           {next}
                       {print > f}' /tmp/differential.txt
```

`shim-sync-differential` prints the whole artefact in one piece, so it is
redirected rather than split. Its output is byte-stable across runs: the
non-reproducible control's numbers are withheld precisely so that they cannot
drift with machine load.

`tests/policy.rs` asserts the three `shim-differential` artefacts are
byte-identical to what the binary prints today, and
`tests/sync_differential.rs` asserts the same for the sync report, so regeneration
is **checked**, not asserted.

## `synthetic.recording.json`

**This is a synthetic fixture, not evidence.** It is labelled
`"synthetic": true` at the top level, carries a `provenance.synthetic_reason`, an
`app.is_synthetic: true` flag, a `capture_quality.warnings` entry that says so in
its first sentence, and a `notes` field that says so again. Analysis pipelines
should filter on `synthetic == false` before using any recording; the oracle
validator prints `[SYNTHETIC FIXTURE - not evidence]` on this one for the same
reason.

## What it is

The output of `shim::scenario::run()`: a scripted sequence of real calls into the
shim's observation layer, rendered as an `andro-substrate.ground-truth/1` document.

It is **not** a capture. No APK was installed, no bytecode was executed, and no
Android device or container was involved. Every dynamic field describes the
shim's own behaviour under a fixed script, not any app's behaviour. The *static*
`app` block — package, `apk_sha256`, version — is true of the fixture APK
`pro.rudloff.search_to_browser_2`, catalogued in
[`tools/dexcore/tests/FIXTURES.md`](../../tools/dexcore/tests/FIXTURES.md); that
does not make the rest of the document a statement about that app.

## Why it exists at all

Two reasons, and the second is the important one.

1. It pins the format. It exercises `net`, `fs`, `classes`, `jni`, `exceptions`
   and `probes`, twenty-two distinct `substrate_probe_hits` across eleven
   divergence families, a layout pass and a twelve-entry
   `capture_quality.unobserved` list. A schema example cannot do that: the format
   is only useful if a *real* observation layer can fill it, and this is the proof
   that it can.

2. It is the regression test for the observation layer. `tests/redaction.rs`
   asserts that the committed file is byte-identical to what the recorder produces
   today. Regeneration is therefore **checked**, not asserted: change a handler and
   this file goes stale and the suite fails, which is the correct outcome — a
   recording that silently diverges from the instrument that produced it is worse
   than no recording.

## Regenerating

```sh
cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-record \
    > shim/recordings/synthetic.recording.json
```

The binary writes to **stdout**, not to a file. That is deliberate: it means this
crate's `std::fs` surface is empty, which is one of the two halves of the
egress/fs invariant `tests/egress_denial.rs` checks by scanning the source. There
is no code path in the library or the binary that can open a file.

The binary exits:

| code | meaning |
|---|---|
| 0 | the document was produced and passed the shim's own privacy scrub |
| 1 | the shim could not produce a document |
| 2 | the document failed the privacy scrub — a redaction regression, and the file is **not** written |

## Validating

```sh
node oracle/recorder/validate.mjs shim/recordings/synthetic.recording.json
```

Expected:

```
OK   shim/recordings/synthetic.recording.json  [SYNTHETIC FIXTURE - not evidence]
       reason: Produced by shim::scenario::run() driving the shim directly. ...

1 file(s) valid.
```

The validator is `oracle/recorder/validate.mjs` and the schema is
`oracle/schema/ground-truth.schema.json`. Neither was modified: this document
conforms to the format as it stands, including the cross-field invariants the
validator enforces and which a substrate capture would otherwise trip — a
`T0_DIRECT` claim with no authority, a recorded access with `obtained: false`, a
summary that disagrees with the arrays it summarises, an event outside the
declared observation window.

## What the shim recorded, and where it went

The substrate has capabilities a device arm cannot have, and this document is
where that shows:

| the recording says | on a stock device |
|---|---|
| `filesystem.access_trace_obtained: true`, with 8 per-operation accesses | `false`, with an empty array |
| `jni.obtained: true`, with 2 `java_to_native` calls, both `UNSATISFIED` | `false`; JNI transitions are unobtainable without in-process instrumentation |
| `classes.loaded_obtained: true`, with 7 classes and a per-class resolution source | `false`; a class-load census needs root |
| `network.attempts` with method, host, path, header names and body length | a MITM proxy, and only if the operator accepts the observer effect |
| `build_field_reads`: 4 `Build.*` fields read, by name, with values | nothing; a field read leaves no trace |
| `proc_sys_reads`: 5 `/proc` and `/sys` paths read, with a taxonomy ID each | nothing |

That is the inversion the project is built on, and `oracle/RECORDING.md` §12 says
plainly that a stock non-rooted device cannot produce any of it.
