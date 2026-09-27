# Recordings

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
