# The ground-truth recording format

**Version:** `andro-substrate.ground-truth/1`
**Normative schema:** [`schema/ground-truth.schema.json`](schema/ground-truth.schema.json) (JSON Schema draft 2020-12)
**Validator:** [`recorder/validate.mjs`](recorder/validate.mjs) — dependency-free, subset implementation, fails loudly on unimplemented keywords
**Reference implementation:** [`recorder/adb-recorder.sh`](recorder/adb-recorder.sh)

> **STATUS: NOTHING HAS BEEN CAPTURED.** Both example recordings under
> `schema/examples/` are **synthetic fixtures**, hand-authored to pin down the
> format. No APK has been installed on any device by this tooling, no logcat has
> been read, and no reference environment has been started. The recorder script
> has been syntax-checked (`sh -n`) and its output contract is exercised by the
> negative test suite, but it has **never been executed against a device**. The
> first real run should be treated as a debug session, not as data collection.

---

## 1. Why a ground truth exists at all

A browser-native substrate with no Linux kernel, no Binder, no `/proc`, no
`/sys`, no ELF loading and no `/system` is **provably not Android**. Every claim
of the form "app X does not work in the substrate" is therefore a *comparative*
claim, and a comparison needs two sides. The right-hand side is this format.

Without it, the only available output of the project is a demo — a list of apps
that happened to run. With it, the output is a measurement: for each app, a
recorded account of what it does on real Android, and a set of specific,
falsifiable points at which the substrate differs.

The recording is the *reference arm* of a two-arm design. It is deliberately
uninteresting on its own: what matters is the join key between a recording and
a substrate run, which is the `substrate_probe_hits` array (§7).

---

## 2. What a recording is

A recording is an **evidence document**, not a log dump and not a summary. The
distinction is load-bearing and drives almost every design decision below.

Three properties follow from it:

1. **Every observation declares how it was obtained.** `source` says which
   mechanism; `tier` says how much to trust it. A signal seen in logcat and a
   signal read from `/proc/<pid>/maps` are not the same kind of claim and are
   not permitted to look the same.

2. **Every gap is enumerated.** `capture_quality.unobserved` is **mandatory**.
   A recorder that reports no gaps on a stock non-rooted device is lying,
   because a stock non-rooted device cannot deliver a class-load census, a
   per-operation file-access trace, JNI transitions, or a network exchange.
   Recording *why* each is missing is what stops downstream analysis from
   reading absence of evidence as evidence of absence.

3. **Absence is never encoded as a negative.** Where the recorder could not
   look, the array is empty **and** a `limits` string or an `unobserved` entry
   says so. `"the app made no network requests"` and `"no network requests were
   observable"` are different claims and must not share a representation.

### Observation tiers

| Tier | Meaning | Requires | Typical contents |
|---|---|---|---|
| `T0_DIRECT` | Read directly from a live source with authority | root shell, or a debuggable build (`run-as`), or in-process instrumentation | `/proc/<pid>/maps`, `/proc/<pid>/fd`, `/proc/uptime`, thread counts, app data dir listing with SELinux labels |
| `T1_LOGCAT` | The platform chose to log it | nothing beyond `adb` | lifecycle transitions, `Displayed … +Nms`, crashes with stack traces, slow-operation warnings, `UnsatisfiedLinkError`, cleartext rejections |
| `T2_SNAPSHOT` | A point-in-time state dump | nothing beyond `adb` | `dumpsys package/window/netstats/connectivity/battery/power`, `pm path`, package lists |
| `T3_INFERRED` | Derived by an analyst or a post-processor | judgement, recorded as such | `substrate_probe_hits`, reconstructed class lists, inferred verdicts |
| `T4_UNOBSERVED` | Explicitly not looked for | n/a | placeholders, disabled probes |

The single most important field in the format is `tier`, because it is what
separates *"we looked and saw nothing"* from *"we could not look"*.

### The validator enforces the honest combinations

`validate.mjs` implements cross-field invariants beyond JSON Schema, including:

- `classes.loaded` non-empty while `classes.loaded_obtained == false` → reject.
- `jni.obtained == false` with recorded `jni.calls` → reject.
- A `T0_DIRECT` claim with `capture.root_shell == false` **and**
  `app.debuggable == false` → reject. You cannot have direct evidence from a
  process you have no authority over.
- `environment.attestation.observed_verdict` of `MEETS_DEVICE_INTEGRITY` or
  `MEETS_STRONG_INTEGRITY` on a `redroid`/`emulator_avd` environment → reject.
  A container has no hardware-backed proof of a certified manufacturer image and
  cannot produce either verdict. This holds regardless of the `synthetic` flag.
- `privacy.bodies_captured == true` anywhere → reject.
- A `path` containing `?` → reject (§5).
- `substrate_probe_hits[].evidence[]` pointers that do not resolve in their own
  document → reject.
- `summary` counts that disagree with the arrays they summarise → reject.
- Lifecycle events that decrease in `t_mono_ms` → reject.
- `completeness == "complete"` while a signal is `not_implemented` → reject.
- `lifecycle.terminal == "LF_UNRESOLVED"` on a complete capture that obtained
  lifecycle logcat → reject. Unresolved is an outcome to be earned, not a
  default.

---

## 3. Top-level structure

| Key | Purpose |
|---|---|
| `record_format` | Format discriminator, `"andro-substrate.ground-truth/1"`. |
| `synthetic` | **Mandatory** boolean. `true` ⇒ the document describes a hypothetical execution and is not evidence. |
| `capture_id` | `<package>__<apk_sha256[:16]>__<environment_kind>__<run>`. |
| `provenance` | Did an execution actually happen, on what recorder source, on what host. |
| `recorder` | Name, version, implementation, effective non-secret options. |
| `capture` | Timing, install, launch, device serial, clock, **observer effects**, interventions. |
| `substrate_policy` | **Optional, substrate-only.** What the observation layer returned when the app asked it something, and what it was permitted to do. Absent from a device capture: a device is not a substrate. §3.1. |
| `app` | Package, versionCode, **APK SHA-256**, min/target SDK, permissions, split APKs, declared native libs, data dir. |
| `environment` | Android version, API level, ABI, build fingerprint, SELinux, Play Services, image digest, **attestation ceiling**. |
| `clock` | Which clock the relative timeline came from, and at what resolution. |
| `privacy` | Redaction policy actually applied. |
| `lifecycle` | Ordered events + the **derived terminal state** (the primary dependent variable, §8). |
| `network` | Capture method, attempts, byte totals, and what the method cannot see. |
| `filesystem` | Access trace flag, app data dir listing, open fds, limits. |
| `classes` | Loaded-class set or census, dex files, limits. |
| `native` | Mapped `.so` files, dlopen failures, thread count, limits. |
| `jni` | Java↔native transitions, or an explicit statement that they are unobservable. |
| `exceptions` | Java exceptions and native crashes with stack frames. |
| `diagnostics` | Non-lifecycle signals: jank, GC pauses, slow ops, cleartext rejections, TLS failures, Play Services errors, JIT activity. |
| `probes` | Every adb command run, with status and truncated output. |
| `substrate_probe_hits` | **The join key** (§7). |
| `capture_quality` | Completeness, signals expected vs obtained, unobserved gaps, warnings, `empty_failure`. |
| `summary` | Optional convenience roll-up. The analysis script recomputes rather than trusting it, and the validator checks it. |

---

## 3.1 `substrate_policy` — the substrate arm's own behaviour, declared

**This section is about a problem the format did not originally have, and the
field is a partial answer to it.**

### The problem

A shim that terminates every side effect observes a *different program*. Once the
substrate has refused a request, the app's control flow is determined by the
substrate, not by the app. So every downstream fact — an exception, a lifecycle
terminal, a `MISBEHAVE` outcome — is a **joint** property of app and substrate, and
a recording of one substrate does not separate them. An analyst reading
`exceptions[3]` sees "the app threw" when the correct reading is "the app reached
a place the shim lacks, and then did whatever it does there".

This gets *worse* the more plausible the shim is. A shim returning obvious nulls
fails loudly and is easy to discount; a shim returning plausible `Build.*` and
`/proc` values produces recordings that read like measurements of the app and are
partly measurements of the shim. Plausibility is what makes the confound
invisible, so plausibility has to become a variable rather than a virtue.

### The field

`substrate_policy` is optional and substrate-only. When present it names five
orthogonal axes, the value each took, the classes of recorded fact each governs,
and a prose statement of what that value does:

| axis | values |
|---|---|
| `identity` | `fabricated` · `withheld` · `refusing` |
| `system_fs` | `fabricated` · `empty` · `absent` |
| `cross_app_packages` | `subject_only` · `all_present` · `error` |
| `network` | `record_and_deny` · `synthetic_loopback` |
| `time` | `virtual` · `scaled` · `frozen` · `host_real` |

Three version numbers, because three different questions are being asked of a
declaration read years later:

- **`policy_format`** — the shape of the object. A reader that does not recognise
  it must refuse to interpret the axis values rather than guess.
- **`policy_version`** — the *meaning* of the vocabulary. Bumped when a value is
  added, removed or **redefined**, even if the shape is unchanged. Two documents
  with different `policy_version`s may use the same token for different things.
- **`shim_version`** — what a value *returns* is a property of the code, not only
  of the vocabulary.

Plus `policy_digest`, a content checksum for joining two recordings to "the same
policy" without diffing prose. It is not a security property.

### What it does and does not buy

It **does** make attribution machine-readable. `axis_declarations[].governs` says
which classes of fact each axis decides, so two recordings of the same program
under two policies can be diffed and every moved fact blamed on the axis that
moved — from the two JSON files alone, with no access to the tool that wrote them.
A fact in the `app` class was not decided by the substrate.

It **does not** separate the two inside a single document. No `ground-truth/1`
document can, and a field that claimed otherwise would be the same conflation with
a new vocabulary. The separation is a measurement *across two runs*, and the
schema's job is to make both runs legible enough to do it.

### The constraints are not advisory

```json
"invariants": {
  "egress": "structurally_impossible",
  "bodies_captured": false,
  "header_values_captured": false,
  "query_values_captured": false
}
```

Each is a `const` in the schema, and an axis's `governs` list may not name `app`,
`derived_roll_up` or `policy_declaration` — no axis may claim responsibility for a
fact that was not the substrate's doing, for a recorder's own roll-up, or for the
declaration itself. `oracle/recorder/negative-tests.sh` has a case per constraint,
plus a positive control, so relaxing any of them fails `make test`.

### One place the format constrains the measurement

`environment.android_release` has `minLength: 1` and `environment.sdk_int` has
`minimum: 1`. A substrate that withholds identity entirely still has to record
*something*, and the format's answer is the floor: release `"1"`, SDK 1. That is a
claim the policy did not make, and the recording says so in `notes`. A format that
cannot express "unknown" makes the recorder lie by omission; a format that *can*
still constrains a recorder that wants to say "unknown". Recording the floor
explicitly is the minimum, and the residual is stated here rather than discovered.

`docs/decisions/0006-substrate-policy.md` is the design record, including what the
policy family still cannot separate from the app.

---

## 4. Timing, and why it is awkward

### The `t=0` anchor

`t=0` is **not** the instant `am start` returned. It is the timestamp of the
first logcat line mentioning the package in the drained buffer, falling back to
the first line in the buffer. The recorder states which anchor it used in
`clock.monotonic_epoch_ref` and `clock.t_zero_definition`.

The offset between the launch intent and the anchor is **not observable**, so:

- **Relative intervals** between events share a clock and are usable.
- **Absolute latencies** from the launch intent carry an unquantified error.

This is stated rather than papered over. Any analysis that reports
"time-to-first-frame from launch" must carry the anchor caveat with it.

### Clock sources

| `clock.monotonic_source` | Resolution | Limitation |
|---|---|---|
| `logcat_wall` | 1 ms | **No year.** Wall clock, not monotonic; an NTP step mid-capture can reorder events. This is what a stock device gives you. |
| `proc_uptime` | ~10 ms | Monotonic, no year, coarse. Requires root or a debuggable build. |
| `host_monotonic` | 1 ms | The *host* clock, not the device's. Wrong device if the two disagree. |
| `substrate_instrumentation` | varies | Only available in a substrate run, never in a reference capture. |
| `synthetic_fixture` | 1 ms | Invented. |

`clock.monotonic_resolution_ms` reports what was actually obtained. The
recorder never claims 1 ms when the host clock only offers seconds.

Midnight rollover is handled by adding 24 h to any timestamp appearing to precede
`t0` by more than 12 h.

### Pattern confidence

`lifecycle_event.matched_pattern` names the pattern that fired, and the pattern
identifiers are version-sensitive. Their confidence, stated honestly:

| Pattern ID | Matches | Confidence |
|---|---|---|
| `LIFECYCLE_PAT.START_PROC` | `Start proc <pid>:<pkg>/…` | **STABLE** across many versions; the separator has changed between releases |
| `LIFECYCLE_PAT.DISPLAYED` | `Displayed <component>: +<N>ms` | **STABLE** — the platform's own first-draw timestamp, the single most valuable signal in the format |
| `LIFECYCLE_PAT.PROCESS_DIED` | `Process <pkg> (pid N) has died` | **STABLE**, wording varies |
| `LIFECYCLE_PAT.PROCESS_KILLED` | `Killing N:<pkg>/…` | **STABLE** |
| `EXC_PAT.FATAL` | `FATAL EXCEPTION: <thread>` | **STABLE** |
| `EXC_PAT.FATAL_SIGNAL` | `Fatal signal N` / `signal N (SIG…)` | **STABLE** |
| `EXC_PAT.ANR` | `ANR in <pkg>` / `ANR: Reason:` | **STABLE** |
| `LIFECYCLE_PAT.ON_CREATE` … `ON_DESTROY` | `am_on_*_called` | **VERSION-SENSITIVE** — these platform lifecycle traces do not exist on every release. When absent, the resume transition is simply *invisible* at T1, and the recorder must say so rather than score it as a missing event |
| `LIFECYCLE_PAT.INPUT_DELIVERED` | `Delivering touch to window` | **STABLE but out of protocol** — the automated harness synthesises no input, so it will not normally appear |
| `LIFECYCLE_PAT.T0_ANCHOR` | (synthetic) | the anchor itself |
| `SIGNAL_PAT.*` | jank / GC / slow-op / TLS / cleartext / load-fail / Play Services / Binder / JIT / low-memory | **VERSION-SENSITIVE** individually; the set is a superset, so absence of a match is weak evidence |
| window focus | *(no pattern)* | **UNOBSERVED BY DESIGN.** There is no reliable stock log line for focus change. `lifecycle.window_focused` is therefore normally `null`, and the recorder does not fabricate it. |

When a pattern is expected but does not match, the recorder writes a
`pattern_not_matched` entry to `capture_quality.unobserved`. That distinction —
**"no match" is not "did not happen"** — is preserved end to end.

---

## 5. Privacy: what is deliberately NOT captured

`privacy.policy` is `andro-substrate/oracle-privacy/1`. The rules are
unconditional, applied by the recorder rather than by an analyst afterwards, and
the validator rejects a recording that violates them.

### Never captured, at any tier

- **Request and response bodies**, in whole or in part. `privacy.bodies_captured`
  is `const: false` in the schema and `network_attempt.body_captured` is
  `const: false`. Bodies carry credentials, personal data and sometimes
  plaintext secrets. Only two derived facts are kept:
  - `body_bytes` — the length. A zero-length body and an unknown body are
    different facts and are not collapsed into one.
  - `body_sha256` — a digest, which lets an analyst detect that two requests
    carried identical payloads without either payload being recoverable.
- **Header values** for anything not on a small low-sensitivity allowlist. The
  schema sets `network_attempt.headers` to `additionalProperties: false` with an
  explicit set (`accept`, `accept-encoding`, `accept-language`, `cache-control`,
  `content-type`, `content-length`, `transfer-encoding`, `user-agent`,
  `connection`, `range`, `if-none-match`, `if-modified-since`, `upgrade`,
  `sec-fetch-*`). An unapproved header **cannot** be recorded even by accident.
- **Sensitive header values.** `auth_header_names` records the *names* of
  present `Authorization`, `Cookie`, `X-Api-Key`-style headers and never their
  values. The presence of an `Authorization` header is itself a finding; its
  contents are not needed to make it.
- **Query strings.** `path` is path-only. `query_param_names` keeps parameter
  names, never values — signed URLs and OAuth callbacks routinely carry live
  credentials in the query. The validator rejects any `path` containing `?`.
- **File contents.** `filesystem.app_dir_listing` records paths, sizes, modes,
  owners and SELinux labels. Not one byte of file data.
- **Stack-frame arguments.** Exception messages are truncated at 2000 characters
  and are the one place where user data can leak through an app's own
  formatting; the recorder's redaction decision and any residual risk belong in
  `privacy.notes`.
- **User identifiers.** No account, no Android ID, no advertising ID.
- **`ANDROID_SERIAL`** is recorded in `environment.serial` because the reference
  environment's identity is part of the experimental condition — but see
  `privacy.notes`, and prefer `null` for a shared or cloud device.
- **The APK itself.** Only the digest. `apk_digest_on_device` exists so a
  recording can prove the analysed artifact is the installed one.

### Hostnames

Three modes, because attribution and confidentiality genuinely conflict:

- `hmac` (**default**) — each hostname becomes `HMAC-SHA256(key, hostname)`,
  rendered as `hmac:<16 hex>`. Hosts can be grouped and counted across a corpus
  without being disclosed. **The key is held out of band and is never stored in
  the recording**, so a recording is useless for reversing the token.
- `plain` — verbatim hostnames. Highest research value, highest
  re-identification risk: pre-signed URLs routinely embed identity in the
  hostname. The validator emits a review warning on any non-synthetic recording
  using this mode.
- `none` — no hostnames at all.

### Observer effects must be enumerated

`capture.observer_effects` records every deliberate or incidental perturbation,
each with `expected_to_change_behaviour`. The two that matter most:

- **`mitm_proxy_installed`** — off by default. Trusting a user CA changes
  behaviour for exactly the cert-pinning and `usesCleartextTraffic` apps this
  project most needs to observe. The default protocol declines to pay that
  price, and `network.limits` says what is consequently invisible.
- **`root_shell_used`** — recorded, flagged as not expected to change behaviour,
  but honest to enumerate.

`capture.interventions_during_run` records anything the harness did *after*
`t=0`. Any entry with `expected_to_change_behaviour: true` invalidates an
`L3_STEADY_STATE` claim, and the validator rejects it.

---

## 6. The two example recordings

Both are **synthetic fixtures**. Both validate. Neither is evidence.

| File | Exercises |
|---|---|
| `schema/examples/minimal.recording.json` | The provable lower bound. Every required key present; every observation array empty; every `*_obtained` flag `false`; `lifecycle.events` a single synthetic anchor; terminal `L0_PROCESS_STARTED`. The point of this file is that its empty arrays are *labelled* as unobserved, so it is a worked example of "absence of evidence ≠ evidence of absence". |
| `schema/examples/full.recording.json` | The maximum surface: 12 lifecycle events, terminal `LF_CRASHED` after a first frame, a `dlopen` failure, a TLS pinning rejection, a Play Integrity refusal, 4 network attempts, 6 fs accesses, 10 classes, 6 native libraries, 5 JNI calls, 2 exceptions (1 fatal), 3 diagnostics, 10 probes, 6 `substrate_probe_hits`, and 4 declared capture gaps. It is a *specification of an interesting capture*, not a capture. |

The package name and version in the `full` fixture are those of a real F-Droid
app, used only so the fixture exercises realistic string shapes. **No behaviour
attributed to that app there was ever observed.** Every number in it was chosen
to satisfy the schema's cross-field invariants.

Both carry `"synthetic": true` at top level, a `provenance.synthetic_reason`, a
`capture_quality.warnings` entry saying so, and a `notes` field saying so.
Analysis pipelines should filter on `synthetic == false`; the validator prints
`[SYNTHETIC FIXTURE - not evidence]` on any fixture it passes.

---

## 7. The join key: `substrate_probe_hits`

This is the reason the format exists.

A ground-truth recording answers: **which substrate assumptions does this app
demonstrably exercise?** A substrate run answers: **which assumptions did the
substrate violate?** Both answers are expressed as the same array of

```
{ assumption_id, family, symptom_class, first_t_mono_ms, last_t_mono_ms,
  hit_count, evidence: [JSON Pointer], source, tier, confidence, notes }
```

so the two are directly diffable. Concretely: `evidence` gives JSON Pointers
into the recording, so a claim can always be checked against the data it rests
on. `symptom_class` on a **ground-truth** recording is a *forward prediction* —
what this app is expected to do if the assumption is violated — and must not be
read as a measurement. `confidence` is `certain`, `likely` or `speculative`.

`assumption_id` is validated for **shape** (`SUB.<FAMILY>[.<LEAF>…]`) rather
than for registry membership, so the taxonomy in
[`../docs/divergence-taxonomy.md`](../docs/divergence-taxonomy.md) can grow
without invalidating old recordings. **Analysis must cross-check membership
against that document**; the schema deliberately does not do it, because a
schema change should never be required to record a new hypothesis.

---

## 8. The primary dependent variable

The terminal state is a **ladder**, derived mechanically from `lifecycle.events`
by `deriveTerminal()` in `validate.mjs`. The schema permits the recorder to
declare it; the validator recomputes it and rejects a mismatch. It is never
graded by hand.

| Terminal | Condition |
|---|---|
| `LF_UNRESOLVED` | No evidence either way. Only permitted when the capture is degraded or lifecycle logcat was not obtained. |
| `LF_FAILED_BEFORE_L0` | Positive failure evidence (install failed, launch refused, fatal signal) with no process ever starting. |
| `LF_NEVER_RESUMED` | Process started, then died, crashed, or ANR'd before any `activity_resume`. |
| `L0_PROCESS_STARTED` | Process started, never resumed, no failure. |
| `LF_CRASHED` | Resumed, then a fatal exception or native crash. |
| `LF_ANR` | Resumed, then an ANR. |
| `L1_ACTIVITY_RESUMED` | Resumed, never drew a frame, no failure. |
| `L2_FIRST_FRAME_DRAWN` | Drew a frame, did not settle. |
| `L3_STEADY_STATE` | Drew a frame and settled: no fatal, no death, no ANR afterwards. |

`L3_STEADY_STATE` is the only rung that asserts a *usable* app, and it is the
weakest-evidenced one, because "no crash logged" is not "works". The
schema therefore carries two additional anti-false-positive fields:

- `quiet_window_ms` — the length of the final contiguous interval with no
  app-attributable log output. This is the anti-retry-loop signal.
- `sustained_log_spam` — true on repetitive output, the classic signature of a
  silent retry loop. A non-empty `exceptions` array does **not** imply this is
  false.

**Stated imprecision:** a death after resume but before first frame is graded
`L1_ACTIVITY_RESUMED`, because no rung distinguishes that case. This is a
limitation of the ladder, not an oversight.

---

## 9. Reference environments

| Kind | Requirements | Contamination |
|---|---|---|
| `redroid` | Linux; `binderfs`, `ashmem`/`memfd`, IPv6, ION/DMA-BUF heaps, 4 KB pages; `--privileged`; SELinux typically permissive. adb on 5555. **[V8][V9]** | No sensors, no camera, no hardware attestation, no Play Services on a plain image. `is_emulator` is set `false` because redroid is not an emulator in the `ro.kernel.qemu` sense, but it is **not a phone** and must never be treated as one. |
| `emulator_avd` | Linux only, KVM, nested virtualisation (AWS bare metal / KVM-capable instances, Azure Dv3/Ev3, GCE nested virt). Google's published images. **[V10][V11]** | Detectable as an emulator (`ro.kernel.qemu`, `ro.hardware`, generic fingerprint). Cannot produce `MEETS_DEVICE_INTEGRITY` or `MEETS_STRONG_INTEGRITY`. |
| `emulator_avd_playstore_image` | As above, with a Play Store system image | Play Store present, Play Services present. Better for `SUB.TRUST.PLAY_SERVICES`, still not attestable. |
| `physical_device` | A real handset | The only environment where a hardware-backed verdict is *possible*. |
| `cloud_device_farm` | Farm-provided | Shared; serial is not a useful identifier. |

**The recorder's classification is deliberately conservative.** An unrecognised
device defaults to `emulator_avd` and is treated as a *contaminated* oracle,
never as a real phone. Misclassifying a container as "real" would let it serve
as an integrity oracle and quietly poison the study. Override only with
`ANDRO_ENV_KIND=physical_device`, and mean it.

### The attestation ceiling

`environment.attestation` separates:

- `max_expected_verdict` — the **ceiling implied by the environment class**.
  `NONE` for any container or emulator. Derived from the documented requirement
  that `MEETS_DEVICE_INTEGRITY` demands "a genuine and certified Android
  device" and, on Android 13+, hardware-backed proof of a locked bootloader on a
  certified manufacturer image **[V1]**, and `MEETS_STRONG_INTEGRITY` demands
  hardware-backed security signals plus a recent security patch **[V1][V3]**.
- `observed_verdict` — normally **`null`, always, from a recorder.** Verdicts are
  computed server-side by Google Play and returned to the app's **backend**
  **[V2]**. They are not locally observable. Filling this field requires an
  operator reading it from the Play Store UI by hand **[V20]**, and `basis` must
  then be `operator_assertion`.
- `safetynet_available` — **`false` for every capture taken after 2025-01-31.**
  SafetyNet Attestation was fully turned down on that date; every call now
  invokes the failure listener with `ApiException` status `7`
  (`NETWORK_ERROR`), on every device **[V4][V5]**. This is a genuine and
  under-appreciated fact for this project: **SafetyNet can no longer discriminate
  a real phone from a substrate at all**, so any app whose only integrity gate is
  SafetyNet fails identically on both sides and yields no divergence signal.

### Choosing a reference environment per app

The environment is part of the experimental condition, not a nuisance. An app
that requires Play Services cannot be meaningfully grounded on a plain redroid
image, because the oracle then lacks the very thing being measured. The
protocol requires an app whose `SUB.TRUST.*` assumptions matter to be grounded
on an environment that **has** Play Services, and this is recorded as a
threat-to-validity item rather than papered over.

---

## 10. Operating the recorder

```sh
# one APK
sh oracle/recorder/adb-recorder.sh --apk app.apk --out out.json --duration 90

# a corpus directory (basename is the package hint)
make -C oracle capture APKDIR=../corpus/apks/org.fdroid.fdroid DURATION=90

# with network exchange, accepting the observer effect
sh oracle/recorder/adb-recorder.sh --apk app.apk --out out.json --mitm

# validate anything
node oracle/recorder/validate.mjs out.json
node oracle/recorder/validate.mjs --supported     # the implemented keyword subset
```

### Timing semantics

| Phase | Bound | Meaning |
|---|---|---|
| Boot wait | `BOOT_TIMEOUT` (300 s) | Waits for `sys.boot_completed=1` **and** a responsive package manager. *Not* part of the observation window. Exceeding it is a hard failure. |
| Settle | `SETTLE_SECONDS` (3 s) | Between wake and launch. |
| **Observation window** | `DURATION` (90 s) | From the launch intent to the logcat drain. **All lifecycle claims are made inside this window.** Below 5 s the recorder refuses to run: a cold start cannot reach first draw, and a short window would silently manufacture `LF_*` failures. |
| Snapshot | `SNAPSHOT_AT` (8 s) | Live `/proc` read, **while the process is still alive**. Only a live snapshot can see fds, threads and maps; a post-mortem read of `/proc` is impossible. `0` disables. |
| Collection | `SNAPSHOT_TIMEOUT` (30 s) per probe | After the window. |

If the process is already gone at the snapshot time, that is a `soft_fail` with
an explicit note that fd and thread evidence is **unrecoverable for this run** —
not silently retried.

### Failure behaviour

- A step that **could not do what it claims** writes a `reason_code` into
  `capture_quality.unobserved`. Reason codes: `not_implemented`,
  `insufficient_permission`, `requires_root`, `requires_debuggable_build`,
  `requires_in_process_instrumentation`, `requires_observer_effect`,
  `signal_absent_in_platform_version`, `pattern_not_matched`, `timeout`,
  `tool_missing`, `scope_out_of_protocol`.
- A step that was **required and produced nothing** sets
  `capture_quality.empty_failure` and exits **3**.
- The recorder **self-validates** its own output with `validate.mjs` before
  exiting, and exits **4** on failure. Emitting a non-conforming recording is a
  recorder bug, not a data point.
- A failed run's recording is **kept**, with the failure recorded inside it. A
  vanished run is a lost datum; a recorded failure is a data point.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Recording written and valid |
| 2 | Usage error, or the environment is unusable (no device, no `adb`, no SHA-256 tool) |
| 3 | A required step produced nothing (`capture_quality.empty_failure` is `true`) |
| 4 | The recording failed self-validation |

### Dependencies

`/bin/sh`, `adb`, `awk`, `sed`, `cut`, `sort`, `tr`, `wc`, and one of
`sha256sum` / `shasum` / `openssl` for digests. `unzip` or `jar` is used
opportunistically to list declared native libraries; without it, that signal is
recorded as `tool_missing`. `node` is used only for optional self-validation.
**No `jq`, no `python`.** JSON is emitted with an `awk`-based escaper, in which
escape order is load-bearing: control characters → space, then backslash, then
double quote.

---

## 11. Testing

```sh
make -C oracle schema-check   # both fixtures validate
make -C oracle test           # 23 negative cases
make -C oracle lint-shell     # sh -n
```

`make test` runs [`recorder/negative-tests.sh`](recorder/negative-tests.sh), which
breaks exactly one thing in a known-good fixture and asserts the validator
**rejects** it — 21 rejection cases plus 2 acceptance cases that guard against
over-rejection. A validator that cannot fail is worse than none, and a
`schema-check` that only ever sees good input proves nothing.

The suite found four real defects during development, all of which are fixed:

1. The `assumption_id` pattern did not permit underscores, so it would have
   rejected every real ID (`SUB.TRUST.PLAY_INTEGRITY`).
2. `verified_boot_hash` was capped at 40 characters, below the 64 of a SHA-256.
3. `probes[].t_mono_ms` could not be negative, although environment probes
   legitimately run *before* `t=0`.
4. A `redroid` environment could claim `MEETS_STRONG_INTEGRITY` because the
   check was gated behind `synthetic == false`.

---

## 12. What this format does not do

Stated plainly, because a format that oversells itself is worse than none.

- **It does not observe the app.** It observes what the platform chooses to log
  plus what a privileged snapshot can read. On a stock non-rooted device that
  excludes per-operation file access, class loading, JNI transitions and network
  exchanges entirely.
- **It cannot attribute a behaviour to a cause.** A `T1` exception tells you the
  app threw; it does not tell you which substrate assumption caused it. The
  causal step is the *comparison* against a substrate run, and that comparison is
  an interpretation, not a measurement.
- **It does not record bodies**, so it cannot support any claim about what an app
  *sent*. Only that it tried to connect, and how much data moved.
- **It does not observe input, taps, or user intent.** The automated protocol
  synthesises no input at all, so `first_input_delivered` is normally `null`.
  Nothing here supports a claim about interactivity.
- **It is not a substitute for running the app on a real phone.** A container
  oracle is a contaminated oracle; see
  [`../docs/research-protocol.md`](../docs/research-protocol.md) §7 threat T-04.
- **A substrate recording does not separate the substrate from the app.** §3.1
  makes the substrate's behaviour a declared parameter, which makes the
  dependency *measurable*; it does not make it disappear. A fact in a
  policy-governed class is a joint property, and no single document can say which
  half is the app's. The separation is a diff against a second run, and a study
  that reports a single substrate run as a measurement of the app has made the
  error this field exists to make visible.

---

## 13. References

Verified by direct retrieval on 2026-09-28. Anything not listed here is marked
`UNVERIFIED` or `CONJECTURE` wherever it is used.

- **[V1]** Google, *Returned integrity verdict format* (Play Integrity).
  <https://developer.android.com/google/play/integrity/verdicts> —
  `MEETS_DEVICE_INTEGRITY` requires "a genuine and certified Android device";
  on Android 13+ it carries "hardware-backed proof that the device bootloader is
  locked and the loaded Android OS is a certified device manufacturer image".
  `MEETS_BASIC_INTEGRITY` "may not be certified". `MEETS_STRONG_INTEGRITY`
  (Android 13+) "requires hardware-backed security signals and a recent security
  patch".
- **[V2]** Google, *Make a standard API request* (Play Integrity).
  <https://developer.android.com/google/play/integrity/standard> — the token is
  "signed and encrypted" and the verdict is "decrypted and verified" by a Google
  Play server and returned to **the app's backend server**. Establishes that
  verdicts are not locally observable. `requestHash` max 500 characters.
- **[V3]** Google, *Overview of the Play Integrity API*.
  <https://developer.android.com/google/play/integrity/overview> — standard vs
  classic requests; minimum API 23; warm-up required for standard requests.
- **[V4]** SafetyNet Attestation API client announcement, *"SafetyNet Attestation
  API support ending"*.
  <https://groups.google.com/g/safetynet-api-clients/c/qcMXTCpHReg> — "fully
  turning down … starting January 31, 2025"; the task "will always invoke the on
  failure listener with an `ApiException`. The value of the status code will be 7
  (NETWORK_ERROR)". No extensions.
- **[V5]** Google, *SafetyNet Attestation API*.
  <https://developer.android.com/privacy-and-security/safetynet> — deprecated,
  replaced by the Play Integrity API.
- **[V6]** Google, *Restrictions on non-SDK interfaces*.
  <https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces>
  — blocklist, `max-target-x`, and `unsupported` lists; `NoSuchFieldError` /
  `NoSuchMethodError` on access to a blocked member; `hidden_api_policy` values
  0/1/2.
- **[V7]** Google, *Updates to non-SDK interface restrictions in Android 10*.
  <https://developer.android.com/about/versions/10/non-sdk-q> — list renaming to
  `max-target-x`; `@UnsupportedAppUsage(maxTargetSdk = …)`.
- **[V8]** `remote-android/redroid-doc`.
  <https://github.com/remote-android/redroid-doc> — mandatory kernel features
  `binderfs`, `ashmem`/`memfd`, `IPv6`, `ION`/`DMA-BUF Heaps`, 4 KB page size;
  `docker run -itd --rm --privileged -p 5555:5555 redroid/redroid:12.0.0_64only-latest`;
  `setenforce 0`.
- **[V9]** `remote-android/redroid-modules`.
  <https://github.com/remote-android/redroid-modules> —
  `modprobe binder_linux devices="binder,hwbinder,vndbinder"`;
  `modprobe ashmem_linux`; DKMS or in-tree modules on kernel ≥ 5.0.
- **[V10]** `google/android-emulator-container-scripts`.
  <https://github.com/google/android-emulator-container-scripts> — "Linux
  only"; KVM required; nested virtualisation guidance for AWS, Azure and GCE;
  pre-built images in `us-docker.pkg.dev/android-emulator-268719/images/`.
  Docker Desktop on macOS/Windows is explicitly not supported for KVM.
- **[V11]** Android Studio Blog, *Continuous Testing with Android Emulator
  Containers*, 2020-08-03.
  <https://androidstudio.googleblog.com/2020/08/continuous-testing-with-android.html>
- **[V12]** AOSP, `core/java/android/os/SystemClock.java`.
  <https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/os/SystemClock.java>
  — `uptimeMillis`/`uptimeNanos` exclude deep sleep; `elapsedRealtime`/
  `elapsedRealtimeNanos` include it; both "guaranteed to be monotonic". The file
  also carries `@RavenwoodReplace` annotations and synthetic `$ravenwood`
  implementations (e.g. `elapsedRealtimeNanos()` expressed as
  `uptimeNanos() + HOUR_IN_MILLIS`). **Observation only**: that AOSP now models
  some of these clocks with replaceable native implementations. *Any claim about
  what "Ravenwood" is or is intended for is this document's conjecture and is not
  supported by the retrieved text.*
- **[V13]** Google, *SystemClock* API reference.
  <https://developer.android.com/reference/android/os/SystemClock> — same clock
  semantics.
- **[V14]** F-Droid, *"F-Droid in 2025 — Strengthening Our Foundations in a
  Changing Mobile Landscape"*, 2026-01-23.
  <https://f-droid.org/2026/01/23/fdroid-in-2025-strengthening-our-foundations-in-a-changing-mobile-landscape.html>
  — "4,061 apps on the main repo", ~21% reproducibly built. Used for the
  sampling frame in the research protocol.
- **[V15]** F-Droid, *All our APIs*.
  <https://f-droid.org/docs/All_our_APIs/> — `https://f-droid.org/repo/index-v2.json`
  is the signed index; per-app build metadata is YAML in the `fdroiddata`
  repository.
- **[V16]** AWAKE wiki, *App Virtualization Attacks*.
  <https://awakewiki.org/attacks/app-virtualization/> — VirtualApp, DroidPlugin
  and VirtualXposed run unmodified APKs inside an unmodified host, intercepting
  input and network traffic without repackaging, which defeats repackaging
  detection. **Secondary source; figures quoted there (a Promon study of 113
  banking apps, and an "Anti-Plugin" talk reporting 64,058 samples) are
  `UNVERIFIED` at their primary sources and are not relied upon here.**
- **[V17]** `asLody/VirtualApp` README.
  <https://github.com/asLody/VirtualApp> — a framework-level proxy plus native
  "IO redirection"; explicitly documents the need to make the system believe the
  guest app is installed, and notes a 64-bit host requirement to reach Google Play.
- **[V18]** `didi/VirtualAPK`.
  <https://github.com/didi/virtualapk> — plugin framework that loads an APK's
  Activity, Service, Receiver and Provider without manifest registration.
- **[V19]** Google Play Console Help, *Use the Play Integrity API to detect risky
  interactions and fight abuse*.
  <https://support.google.com/googleplay/android-developer/answer/11395166> —
  `deviceIntegrity` covers "a genuine certified Android device";
  "untrustworthy devices and other untrustworthy environments".
- **[V20]** Google, *Additional tools and support* (Play Integrity).
  <https://developer.android.com/google/play/integrity/additional-tools> — a
  verdict can be generated on-device from the Play Store's own developer
  options, and Play Protect certification is surfaced in Play Store → About.
  The only documented route by which an operator can read a verdict locally.

**Not verified.** <https://source.android.com/docs/core/runtime/dex-format> was
attempted and the fetch timed out; it is not cited in support of any claim here.
Community-forum claims about emulator behaviour under `MEETS_STRONG_INTEGRITY`
are treated as `UNVERIFIED` and are not relied upon; the documentary basis used
instead is [V1].
