# 0005 — The framework shim is an observation layer, not a compatibility layer

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: what the `android.*` shim is for; the classloader boundary; where
  redaction happens; what backs the filesystem; and what this shim cannot yet do.
- **Scope**: `shim/`. Does not touch `oracle/`, `corpus/`, `analysis/` or
  `docs/research-protocol.md`.

## Context

`tools/dexcore` can already *write* DEX. That is not a curiosity: ADR
[0002](0002-dex-toolchain.md) committed to it on the grounds that the runtime must
fabricate synthetic `android.content.Intent`-style classes that resolve in the
same classloader as untrusted app code. This ADR decides how.

Two things are true at once, and the tension between them is the whole design
problem.

**On a real device, an app's behaviour is nearly unobservable.** `oracle/RECORDING.md`
§12 says a stock non-rooted capture cannot see per-operation file access,
per-class loading, JNI transitions or network exchanges. The mandatory
`capture_quality.unobserved` field exists precisely so that a reader confronts
those gaps instead of reading an empty array as an absence of behaviour. Learning
what an app does requires root or Frida: fragile, detectable by the app, and
legally fraught.

**In a browser substrate, the substrate *is* the process.** There is no kernel to
hide behind, no `/proc` to lie in, no native code to hide behind. Every byte the
app produces passes through code this project wrote. That is not an advantage to
be engineered in later — it is a consequence of the architecture, and it is
strictly better than the device arm at the thing the project is measuring.

The temptation, given a shim that can observe everything, is to make it also
*work*: implement the framework properly, keep the app happy, and measure whatever
survives. That temptation is the mistake this ADR refuses, for a reason that is
about research validity rather than engineering taste.

## Decision

### 1. Observation is the primary goal; compatibility is instrumental

**The shim exists to make every substrate interaction visible, structured, and
directly comparable to a device capture in the format
`oracle/schema/ground-truth.schema.json` defines.** Where visibility and
compatibility conflict, visibility wins, and the conflict is written down in
`shim/CONFORMANCE.md` rather than quietly resolved.

Concretely, three places where a compatibility-first shim would have done
something else:

- **`Uri.getQuery()` returns an empty string.** The shim parses the query into
  *parameter names* and discards the values, so there is no value to hand back. A
  compatibility shim would return the query. The cost is real — an app that
  round-trips a signed URL through the shim gets a different string, which is a
  `SUB.FW.SERIALIZATION` finding — and it is recorded, not hidden.
- **`Thread.sleep` advances a virtual clock and returns.** A compatibility shim
  blocks. A substrate that really slept would be *the source* of the timing the
  study is trying to measure.
- **`Handler.post` enqueues and nothing drains it.** A compatibility shim would
  need a display to run the frame loop. There is no display, so a frame-driven app
  stalls — and `queue.size()` is the measurement of `SUB.TIME.VSYNC`.

The general form of the rule: **the shim's answers are the researcher's choices,
so they are recorded as choices.** Every `probes` entry says what was returned
*and* that it was synthesised, and every `limits` array says what the mechanism
structurally cannot see.

The counter-argument, stated fairly: a shim that never lets an app proceed
produces a corpus of failures, and a corpus of failures measures the shim. That is
true, and it is why `lifecycle.terminal` is never claimed as
`L3_STEADY_STATE` — the oracle's own text calls that rung the weakest-evidenced
one, asserting a *usable* app, and a shim that has never run a real activity has
no business claiming it.

### 2. The classloader boundary is **supersede**, not merge

Two ways to make the shim's classes resolve alongside the app's:

1. **Merge** — rewrite the app's DEX so it contains the shim's classes too,
   producing one `classes.dex`.
2. **Supersede** — keep two DEX files and give the shim's precedence: a
   `Landroid/…` or `Ljava/…` reference resolves in the shim DEX *even when the
   app's own DEX also defines it*.

**Decision: supersede.** The loader is `shim/src/classes.rs`; the shadowing is
recorded as `Resolution::ShimSupersedesApp`, and the collision set is exposed so an
analyst can see which framework classes an app tried to define.

Supersede is right for two reasons, and the second is the important one.

First, merge is not a container operation. It is a **pool-renumbering**
operation, because inserting the shim's strings, types, protos, fields and
methods changes every index, and every index appears as an operand in the app's
`insns`. dexcore's writer has no path from `DexReader` to `DexWriter`'s pools at
all.

Second, merge is the *wrong shape of boundary*. Under merge, a hostile APK can
define its own `Landroid/app/Activity;` and the shim's implementation of
`startActivity` is simply gone — or the merge tool picks a winner and the choice
becomes an attack surface. Under supersede the shim always wins, so an app that
declares its own framework class gets it shadowed and the observation layer keeps
working. That is a security property, not a compromise.

It is not free, and the cost is a blind spot worth naming: **the app's own class
disappears silently.** It is recorded rather than hidden, but a recording that
says "resolved to the shim" and a recording that says "the app's class was
shadowed and never ran" differ only in a field name. A future study should treat
`shim_supersedes_app` as a signal that the app is doing something deliberate.

#### What the merge path would need, precisely

`dexcore`'s writer is missing six things, and the sixth is the one that decides
whether the work is a week or a quarter.

1. **Pool import.** A `DexWriter::import(&DexReader)` that copies the five id
   pools with a provisional→final remap and re-sorts the merged pools. The writer
   currently interns only what the caller declares.
2. **Operand rewriting.** A pass over every imported `code_item` that rewrites
   `type_id`, `field_id`, `method_id` and `string_id` operands across the
   instruction formats that carry them (`21c`, `22c`, `35c`, `3rc`, `21t`, `21s`,
   `21h`, `22s`, `31i`, `31t`, `45cc`, `4rcc`), plus `fill-array-data-payload`
   index arrays, `class_data_item` delta bases, `encoded_catch_handler` type
   indices, and `annotations_directory`/`static_values`. `asm.rs` *encodes*
   instructions; there is no decoder→re-encoder path.
3. **Sections the writer omits but a merge must preserve.** `static_values_item`
   is not optional in practice: every `static final int`/`String` initialiser in
   the app lives there, so a merged file without it silently reads `0`/`null` for
   every compile-time constant the app has. `debug_info_item` matters too, since
   real stack traces are what `exceptions[].stack_frames` is made of.
4. **`method_handle_item` and `call_site_item`.** Without them a merged DEX
   containing any `invokedynamic` cannot load on a real loader at all, and modern
   DEX is saturated with `invokedynamic` — `SUB.FW.INVOKEDYNAMIC` is marked COMMON
   in the taxonomy for exactly this reason.
5. **Multi-dex.** A real APK has `classes.dex` … `classesN.dex`. The writer emits
   one `class_defs` block. A merge must also satisfy the "superclass precedes
   subclass" rule *across* both inputs and detect descriptor collisions.
6. **A two-pass size-and-offset solver, because rewriting changes instruction
   widths.** This is the one that decides the schedule. A `35c` invoke that must
   become `invoke/range`, a `21h` that must become `21t`, a `const-method-handle`
   that must become `invoke-polymorphic` — each changes the instruction's code-unit
   count, which moves every subsequent branch target and every `try_item` start
   address. You cannot patch offsets after the fact; the layout has to be solved
   with the rewritten widths known, which means the rewrite has to be complete
   before emission starts, which means the writer needs a two-phase mode it does
   not have.

**If merge is ever wanted, do it in dexcore, not here.** It is a writer feature.

### 3. Redaction happens at the point of capture

**Decision:** there is no field anywhere in this crate that can hold a request
body, a header value, or a query-string value, and the parser that would have to
hold them drops them on the floor. `RequestMeta::parse` destructures a URL and
discards userinfo, query values and the fragment; `HeaderNames::record` takes a
name and rejects anything containing `:`, so an app cannot smuggle
`Authorization: Bearer …` in as a single "name".

The rejected alternative is redact-on-serialisation. A downstream redactor is one
refactor, one debug `println!`, one `--capture-raw` flag or one
`serde(skip_serializing)` mistake away from writing a live credential to disk, and
nothing in the type system objects. Redaction at capture is a property of the
types; redaction downstream is a promise.

Three consequences that are *not* costs but design:

- **Bodies are not digested.** The oracle format permits `body_sha256`; the shim
  sets it to `null`. A digest over a low-entropy body — a four-digit PIN field, an
  `"ok"` acknowledgement — is reversible by brute force in under a second, so
  "we hashed it" would be a false assurance. Length only, and the reason travels
  with the recording in `privacy.notes`.
- **A path is a policy, not a constant.** A REST design puts identifiers in path
  segments, so `PathPolicy` is a parameter and the choice is recorded in
  `privacy.notes` alongside the residual risk — which is what `RECORDING.md` §5
  asks a recorder to do.
- **Text is a shape, not a string.** A box tree records a text view's character
  count, class histogram and whether it looks like an email, never a character.
  `TextPolicy::Include` exists for captures whose inputs are known-synthetic.

Enforced by `tests/redaction.rs` with canary strings, by a structural check on
`RequestMeta`'s field list, and by `redact::scrub` over the serialised document.

### 4. The filesystem is an in-memory `BTreeMap`

**Decision:** `shim/src/vfs.rs`. Nothing touches a disk.

An app that can write to a real disk writes to the *researcher's* disk. In a
browser the substrate's only storage is same-origin `IndexedDB`, but a
path-traversal bug in a VFS is still a bug that runs on someone's machine. A
`BTreeMap` makes that class unrepresentable rather than unlikely, and makes the
whole filesystem a value that can be serialised into a recording.

The observability consequence is the real reason. A device arm's
`filesystem.accesses` is empty and `access_trace_obtained` is `false`. The
substrate's is not — and crucially it records the **attempt**, including the
denial, because on a device the existence of `/system/build.prop` is exactly what
the app is probing for.

`/proc` and `/sys` are a **separate mechanism** from the VFS, on purpose. They are
kernel interfaces, not files, so the shim fabricates the specific reads an app's
anti-tamper, watchdog and capability code actually makes and records each as a
`probes` event tagged with the taxonomy ID it feeds. The contents are fabrications
and the recording says so on every one.

### 5. Networking has exactly one door, and it is a wall

**Decision:** `shim/src/net.rs`. `EgressSink::request` is the only function in the
crate that produces a network outcome, and it always produces a failure. There is
no other door: no trait an interpreter could implement to reach a socket, no
feature flag, no environment variable, no CLI switch.

The failure is a *value*, not an abort, because `SUB.NET.EGRESS`'s documented
symptom is a spinner that never stops, and that is precisely because the
platform's failure is invisible to the app. The sink returns a
`java.net.ConnectException`-shaped failure and lets the app's own handling run, so
an app that retries is visible as repeated denied attempts and an app that gives
up cleanly is equally visible. Neither is the substrate deciding for it.

Proven three independent ways in `tests/egress_denial.rs`: a live `TcpListener`
that nothing ever connects to; a classified source scan for networking and disk
symbols across every file in the crate; and a check that the emitted DEX names no
transport class.

### 6. Layout produces geometry, and says so

**Decision:** `shim/src/layout.rs` runs a real `measure` → `layout` → `draw` cycle
and emits a serialisable box tree. No rasteriser exists, and every `BoxNode`
carries `painted: false`.

A pixel buffer would be lossy — two different layouts can produce identical pixels
at one scale — and untestable, because "does this look right" is not an assertion.
A box tree is exact, diffable between a substrate run and a device run, and
assertable property by property, which is what a two-arm comparison needs.

The consequence is stated rather than buried: `SUB.GFX.*` findings from this layer
are *geometry* findings only. A wrong-pixel bug, a shader failure or a
surface-format problem is structurally invisible to it. Text measurement uses a
documented, deterministic advance table, so it is reproducible and it is **not**
Roboto — the discrepancy is exactly `SUB.GFX.TEXT_RENDER`, and
`layout::metrics::MODEL` travels in the output so no reader mistakes one for the
other.

### 7. The emitted DEX is a signature manifest, and every method is `ACC_NATIVE`

**Decision:** `shim/src/emit.rs` emits the shim through `dexcore`'s writer with
every method `ACC_NATIVE` and no `code_item`. Semantics live in the dispatcher,
keyed on `(class, name)`, and there is only one implementation of them.

The safety consequence is the point. A native method with no registration throws
`UnsatisfiedLinkError`. So if this DEX were ever installed on a real device — a
repackaging accident, a leaked artefact, an over-eager build script — every
framework call fails **loudly** rather than returning `0` and letting an app limp
along producing wrong results. The safe default for an instrument is the one that
is unusable when misplaced.

One class, `android.substrate.Bridge`, carries real assembled Dalvik including a
`try` block with a typed clause *and* a catch-all, so the round-trip test proves
dexcore's `code_item` and `encoded_catch_handler` paths rather than exercising a
file with no instructions in it.

## A defect found in `dexcore`, reported rather than fixed

`dexcore::writer::intern_type_list` allocates `4 + 2n` bytes — which shows 2 bytes
per element was intended — and then appends `t.to_le_bytes()` for a `u32`,
writing **4** bytes per element. Every `type_list` with two or more elements is
mis-encoded: `OutputStream.write([B I I)V` is emitted as `([B F I)`, and a
conforming loader resolves a signature the call site never encoded.

`tools/dexcore` is Wave 1 and owned by another agent, so this ADR **reports** the
defect rather than editing a shared crate mid-flight. `shim::emit::repair_type_lists`
corrects the emitted bytes **in place** — the correct encoding is never larger than
the emitted one, so no offset moves and a gap inside the data section is legal —
then reseals the SHA-1 and Adler-32, and `verify_prototypes` re-reads the file and
refuses to hand it over unless every method matches the registry.
`tests/dex_roundtrip.rs::dexcore_still_widens_type_lists` prints a note on every
run while the workaround is live. Removing it is a deletion plus two lines once
`dexcore` is fixed.

## The honest state: this shim will not run real apps

Stated first because everything else is read against it.

`shim/CONFORMANCE.md` measures coverage against the six committed F-Droid DEX
fixtures: **90 of 90 referenced framework types** and **59 of 215 referenced
methods (27.4 %)**. Against the platform — on the order of 30 000 classes and
600 000 methods — the shim is well under half a percent. An app will stop at the
first framework call it makes that is not in the table.

`corpus/report.md` reports 44.76 % of F-Droid apps with no native code, and
`docs/divergence-taxonomy.md` §0.1 says the correct reading is *"a necessary
filter, not a sufficient one"*. The conformance table is the concrete version of
that: **this shim is a measurement instrument with a small compatibility surface,
and it does not yet run apps.**

Three things are missing at a level no amount of shim work would fix, and they are
in `capture_quality.unobserved` of every recording:

- **No `invokedynamic`.** Modern DEX is saturated with it, so a large fraction of
  contemporary app behaviour never reaches a shim method at all.
- **No `resources.arsc`.** Every `getString`, `getIdentifier` and
  `setContentView(int)` is null or 0.
- **No display, no vsync, no Binder, no input, no boot.** Structurally
  unsatisfiable, and each one listed with the family it kills.

## The single most important limitation

**The layer observes a *different program*, and the difference is invisible in the
output.**

The shim terminates every side effect. Egress is denied, the filesystem is a map,
`Thread.sleep` does not block, the message queue never drains, and
`PackageManager` answers "not installed" for every package but the subject. Each of
those is a *researcher's choice about what the app's execution means*, and once it
is made, the app's control flow after that point is determined by the choice rather
than by the app.

So every downstream fact in a recording — an exception, a lifecycle terminal, a
`MISBEHAVE`-class outcome, a divergence count — is a joint property of the app and
of the shim, and the recording does not separate them. An analyst reading
`exceptions[3]` will see "the app threw" when the correct reading is "the app
reached a place the shim does not have, and then did whatever it does there".

This is a *measurement-validity* hazard, not a missing feature, and it gets worse
the more plausible the shim is. A shim that returned `null` everywhere would fail
loudly and be easy to discount. A shim that returns plausible values — which this
one does, deliberately, for `Build.*` and `/proc` — produces recordings that read
like measurements of the app and are partly measurements of the shim.

The one mitigation in place is that every fabricated answer is labelled as
fabricated at the point it is emitted, `privacy.notes` and every `limits` array
say what the mechanism cannot see, and `symptom_class` on a substrate recording is
the shim's own answer rather than a prediction. The mitigation is necessary and it
is not sufficient. A two-arm study that wants to separate "the app does X" from
"the app, when X is denied, does Y" needs a substrate *parameter* — a shim that can
be told to allow a thing and a different recording for the same app — and this
crate has no such parameter, by design: §3 forbids the first kind of knob and §5
forbids the second.

Two further blind spots, stated more briefly because they are narrower:

- **A shadowed app class is a silent disappearance.** Recorded as
  `shim_supersedes_app`, but the recording cannot show what the app's own class
  would have done.
- **Reflection is indistinguishable from a direct call.** A reflective call and a
  direct one go through the same table, which is good for coverage and fatal for
  attribution: a recording cannot tell you which of a class's call sites were
  reached reflectively.

## Alternatives rejected

| alternative | why not |
|---|---|
| **Compat-first**: implement the framework properly, measure what survives | The project's output would be "apps that happened to run", which `RECORDING.md` §1 explicitly says is the thing this exists to replace with a measurement. |
| **Merge into the app's DEX** | Not a container operation; needs operand rewriting across every instruction format, plus `static_values`, `debug_info`, `method_handle` and `call_site` sections dexcore does not emit. And it turns the shim's own boundary into an attack surface. |
| **Redact on serialisation** | One refactor away from writing a live credential to a recording. |
| **A real VFS with a temp directory** | An app's file bug becomes a bug on the researcher's disk. |
| **Return plausible values silently** | Fabrications that do not announce themselves turn a substrate capture into an apparent measurement of the app. Every one is labelled. |
| **An interpreter in this crate** | Owned elsewhere. The boundary is `dispatch::ShimCaller`, four methods, and `dispatch::testing::MockCaller` so the interpreter half can be built against a mock in parallel. |
