# Research protocol (PRE-REGISTRATION)

**Status:** pre-registration. Written **before** any measurement. No results
exist. Nothing in this document has been observed.

**Companion documents**
- [`divergence-taxonomy.md`](divergence-taxonomy.md) — the hypothesis space
  (145 assumption IDs across 16 families).
- [`../oracle/RECORDING.md`](../oracle/RECORDING.md) — the ground-truth
  recording format the reference arm produces.

**Anti-reverse-engineering commitment.** This document and the taxonomy it
references are hashed at the bottom of §10. Any analysis that reports a result
must cite that hash. If the protocol changes after data collection begins, the
change must be recorded as a dated amendment with a reason, and results
collected under the earlier hash must be reported separately. The intent is
that the reader can always tell which promises were made first.

---

## 1. Research questions

**RQ1 — Compatibility.** For a DEX-only sample of real Android apps, what
fraction reaches each rung of the lifecycle ladder (§4) in a browser-native
substrate with no Linux kernel, no Binder, no `/proc`, no `/sys`, no ELF loading,
no `/system`, and no network egress?

**RQ2 — Attribution.** Which substrate assumptions account for the observed
failures, and what is the *class* of each (degrade / refuse / misbehave)?

**RQ3 — Ordering.** Which assumptions are the binding constraints — i.e. if a
substrate solved assumption X, how many currently-failing apps would move up a
rung? This is the question that turns a compatibility number into a roadmap.

**RQ4 — Silent failure.** What fraction of apps reach a *usable-looking* state
that is nonetheless wrong — the `MISBEHAVE` class — and can any of it be detected
without a human looking at the screen?

**RQ5 — Oracle sensitivity.** How much does the answer change when the ground
truth changes? Specifically, how many conclusions are artefacts of the reference
environment rather than properties of Android?

**RQ6 — The native-code filter.** Does excluding apps with native code change
the *distribution* of the remaining failures, or only its denominator? (The
prediction is only the denominator. See §8.3.)

**Deliberately not asked.** "What is the maximum achievable compatibility?"
That is an unbounded engineering question, not a research question, and
answering it would require a substrate that does not exist.

---

## 2. What this study is *not*

- It is **not** a claim that "no native code ⇒ will run". That is false, and §8.3
  of the taxonomy explains why.
- It is **not** a claim that a browser substrate is safer or better than
  Android. The honest framing is in taxonomy §0.2: the substrate has a strictly
  smaller attack surface *and* a strictly smaller capability surface. Which
  matters depends on the app.
- It is **not** a novelty claim about running APKs outside Android. Prior art
  already does that (VirtualApp, DroidPlugin, VirtualXposed, VirtualAPK —
  [V16][V17][V18]). The novelty, if any, is the *quantified, oracle-backed*
  account of where it fails.
- It is **not** a measurement of Play Store apps, because of RQ5/T-02 below.

---

## 3. Sampling plan

**3.1 Reuse the corpus; do not build a second one.** The sampling frame is
whatever the corpus tooling (`corpus/`, owned by another agent) materialises.
This document specifies the *fields this study requires* and nothing about their
format or location, so that the two efforts do not collide or duplicate.

**3.2 Required fields per sampled app** (a request on the corpus, not a
specification of its output):

| Field | Used for |
|---|---|
| `package` | capture identity, PackageManager joins |
| `apk_sha256` | dedup, and binding an analysis to an artifact |
| `apk_path` | what the recorder installs |
| `apk_size_bytes` | size stratum |
| `min_sdk`, `target_sdk` | SDK stratum; `target_sdk` also drives non-SDK enforcement [V6][V7] |
| `has_native_libs` | the primary stratum (§3.4) |
| `declared_permissions` | prior on `SUB.TRUST`, `SUB.HW`, `SUB.IPC` exposure |
| `uses_webview` | prior on `SUB.FW.WEBVIEW` |
| `manifest_declares_boot_receiver` | prior on `SUB.PWR.BOOT_COMPLETED` |
| `dex_method_count`, `uses_invokedynamic` | prior on `SUB.FW.INVOKEDYNAMIC` |
| `declared_components` | prior on `SUB.IPC.PACKAGE_MANAGER_OTHER` |

**3.3 Frame.** The F-Droid main repository is the frame because it is a
**signed, versioned, machine-readable index** that can be sampled
reproducibly: `index-v2.json` plus per-app YAML build metadata [V15]. It held
**4,061 apps** on the main repository as of the 2026-01-23 annual report, ~21%
reproducibly built [V14]. Reproducibility matters more than representativeness
here — see T-02 for why representativeness is not achievable.

**3.4 Strata.** Two-axis stratified sample, seed fixed at `20260928`:

- **Axis A — native code**: `has_native_libs ∈ {false, true}`.
- **Axis B — `min_sdk`**: `{≤ 21, 22–28, ≥ 29}` (pre-ART, ART-with-hidden-API-era,
  post-hidden-API-enforcement). [V6][V7]

Sample **N = 200** apps by proportional allocation, minimum 20 per non-empty
stratum. Rationale for 200: with a simple proportion, N = 200 gives a 95%
interval half-width of about ±3.5 points at p = 0.5 and ±3.0 points at p = 0.05.
That is enough to distinguish "5%" from "11%" and **not** enough to distinguish
"5%" from "6%". Stated up front so nobody later reads a 2-point difference as a
finding.

**3.5 Exclusions, declared in advance.** An app is excluded, with the reason
recorded, if: no launchable activity; `min_sdk` above the reference image's API
level; the APK exceeds a size that makes installation exceed the boot-timeout;
the app is a launcher/keyboard (requires a role we do not grant); the package
appears in more than one F-Droid repo; the APK digest is already sampled.

**3.6 Reference environment pairing.** The reference environment is **not** an
arbitrary implementation detail. It is a factor:

| Level | Environment | Purpose |
|---|---|---|
| E1 | redroid, AOSP image, no GMS | Primary arm. Reproducible, scriptable, root available. |
| E2 | redroid or AVD, **`google_apis_playstore` image** | For any app whose ground truth shows `SUB.TRUST.PLAY_SERVICES` exposure. Measuring a GMS-dependent app on a GMS-less oracle produces a *wrong* ground truth (T-01). |
| E3 | Physical device or cloud device farm, 2+ handsets | **Sub-sample of 30 apps**, for sensitivity analysis (RQ5). Not the main arm, because of cost. |

**3.7 Repeats.** Each sampled app is captured **3 times** per environment.
Mandatory, not optional: `SUB.CPU.TIERING` and `SUB.TIME.VSYNC` (§8.2 of the
taxonomy) predict *intermittent* failure, and a single run would systematically
over-report compatibility. Per-run outcomes are retained; the unit of analysis is
the **app**, with runs nested.

**3.8 Budget.** ~600 captures × ~110 s ≈ **18.5 device-hours** for the main arm
plus ~3.5 h for the sensitivity sub-sample. If the device budget is smaller, the
pre-registered fallback is: **reduce N to 100 and keep repeats = 3** (dropping
repeats to hit N is forbidden — repeats protect against the dominant bias).

---

## 4. The primary dependent variable

This is the measurement. It is defined operationally, implemented in
`oracle/recorder/validate.mjs` as `deriveTerminal()`, and **recomputed by the
validator on every recording**, so it cannot be graded by hand or adjusted
post hoc.

### 4.1 The ladder

Given one recording of one cold launch of one app, with `t = 0` at the launch
intent:

| Rung | Label | Condition (evaluated in this order) |
|---|---|---|
| — | `LF_UNRESOLVED` | No evidence either way. **Only permitted** when the capture is degraded or lifecycle logcat was not obtained; the validator rejects it otherwise. |
| — | `LF_FAILED_BEFORE_L0` | Install failed, or the launch intent was refused, or a fatal signal occurred, and no process ever started. |
| 0 | `LF_NEVER_RESUMED` | A `process_start` was observed, then a `process_died` / `fatal_exception` / `native_crash` / `anr` **before** any `activity_resume`. |
| 0 | `L0_PROCESS_STARTED` | `process_start` observed, no `activity_resume`, no failure. |
| 1 | `LF_CRASHED` | `activity_resume` observed, then a fatal exception or native crash at t ≥ resume. |
| 1 | `LF_ANR` | `activity_resume` observed, then an `anr` at t ≥ resume. |
| 1 | `L1_ACTIVITY_RESUMED` | `activity_resume` observed, no `first_frame_drawn`, no failure. |
| 2 | `LF_CRASHED` / `LF_ANR` | As above but at t ≥ `first_frame_drawn`. |
| 2 | `L2_FIRST_FRAME_DRAWN` | `first_frame_drawn` observed, and no fatal/death/ANR afterwards. |
| 3 | `L3_STEADY_STATE` | `L2` **and** `reached_steady_state`: no fatal, no death, no ANR afterwards, **and** no behaviour-changing intervention during the window. |

`activity_resume` is signalled by `am_on_resume_called`; `first_frame_drawn` by
the platform's own `Displayed <activity>: +Nms` line. Both are version-sensitive
patterns; when a pattern is expected and does not match, the recorder writes
`pattern_not_matched` into `capture_quality.unobserved` and the run is **not**
scored as a missing event.

**Known imprecision, stated rather than hidden:** a death after resume but before
first frame is graded `L1_ACTIVITY_RESUMED`, because no rung distinguishes that
case. Stated here so that it cannot be discovered later and presented as a
discovery.

### 4.2 Two guards against a false "success"

`L3_STEADY_STATE` is the only rung asserting a *usable* app, and "no crash
logged" is not "works". Two mandatory companion fields:

- **`quiet_window_ms`** — the final contiguous interval with no
  app-attributable log output. Zero means the app was still talking; the
  anti-retry-loop signal.
- **`sustained_log_spam`** — true on repetitive output. A non-empty `exceptions`
  array does **not** imply this is false.

**A run reaching `L2` or `L3` with `quiet_window_ms == 0` and
`sustained_log_spam == true` is classified `L2_NOISY`, not `L3_STEADY_STATE`.**

### 4.3 The secondary variable: usefulness

`L3_STEADY_STATE` measures "did not die", not "works". A login wall, an error
page, and a working app are all `L3`. To bound this, a **manual
usefulness screen** is applied to the 30-app E3 sub-sample by two independent
raters, recording: does the first screen show the app's own content, or an
error/login/empty state? Inter-rater agreement is reported (Cohen's κ) as a
measurement in its own right (T-10). No automated proxy is used; any proxy would
be a guess dressed as a measure.

### 4.4 What the DV deliberately does not capture

- **Interactivity.** The automated protocol synthesises no input, so
  `first_input_delivered` is normally `null` and no rung asserts "the user can
  press a button and something happens". `SUB.INPUT.*` is therefore
  **NOT MEASURED** by the automated arm, and must be reported as such.
- **Sustained behaviour.** A 90-second window cannot speak to battery drain,
  thermal behaviour, or multi-hour stability.
- **Correctness of computation.** Nothing in this design can tell whether a
  displayed number is *right*. RQ4 is therefore answered only where a
  deterministic signal exists (a logged error, a missing expected resource), and
  otherwise RQ4 is reported as **not answerable with this instrument** — which is
  itself the honest finding.

---

## 5. Measurement procedure

Per (app, environment, run):

1. Wait for boot; confirm `sys.boot_completed=1` **and** a responsive PM.
2. Record the environment. **Classify conservatively** — an unrecognised device
   is treated as a contaminated oracle, never as a real phone.
3. Install the APK (`adb install -r -t`). Record the install result verbatim.
4. Read the package identity from the *installed* package, never from the
   filename. Resolve the launch activity on-device.
5. Snapshot pre-launch state: `dumpsys window`, `dumpsys netstats`, `dumpsys
   connectivity`, app data dir listing.
6. `logcat -c`, then wake, settle 3 s, dispatch the launch intent. **t = 0.**
7. At t = 8 s, take a **live** `/proc/<pid>/{maps,fd,status,mountinfo}`
   snapshot. A post-mortem `/proc` read is impossible, so this is the only
   chance; if the process is already gone, that is recorded as an unrecoverable
   gap for this run.
8. Run to t = 90 s. No input, no interaction, no `am` commands, no `pm grant`.
9. Drain logcat; collect post-run dumpsys; parse lifecycle, diagnostics,
   exceptions; assemble the recording; **self-validate**; exit non-zero on
   failure.
10. Do not uninstall. The installed state is the substrate arm's starting point.

For the **substrate arm**, the runtime fills the same recording shape, with
`environment.kind` set to a substrate value and `substrate_probe_hits`
populated from its own instrumentation. The two arms are then joined on
`apk_sha256` and compared on the ladder and on `substrate_probe_hits`.

**Differences the arms must not paper over:** the substrate has no network and
the reference does, so *any* `SUB.NET` divergence is confounded with the egress
policy rather than with the substrate. This is stated per-result, not globally.

---

## 6. Analysis plan

Fixed in advance. Deviations require a dated amendment.

**6.1 Estimand.** For each rung `r ∈ {0,1,2,3}` and each assumption family `F`,
the proportion of apps (unit = app) whose best-of-3 outcome is ≥ `r`, with a
cluster bootstrap (resampling apps, not runs) 95% interval.

**6.2 Best-of-3 vs all-of-3.** Both are reported. Best-of-3 is the compatibility
claim; all-of-3 is the reliability claim. Reporting only best-of-3 is
prohibited — that is exactly the "run it once, get a pass, ship the claim" failure
mode.

**6.3 Attribution.** For each app failing at rung < 3, each candidate assumption
is scored: `certain` (a diagnostic signal in the recording names it),
`likely` (a static prior from §3.2 plus a compatible symptom), `speculative`.
Only `certain` hits are counted in headline numbers. The denominator of "which
assumptions does this app exercise" is the ground truth's
`substrate_probe_hits`, and where that is empty, the app contributes to
**UNKNOWN**, not to "no assumptions".

**6.4 Ordering (RQ3).** A leave-one-out ablation over families: for family `F`,
report the number of apps that would move up a rung if `F` were satisfied. This
is computed from the *observed* hit set and is an **upper bound** on the benefit,
because satisfying one assumption may expose a previously masked later failure.
Stated as an upper bound in the output, not just in a footnote.

**6.5 Multiplicity.** 145 assumption IDs × 6 rungs is ~870 comparisons. All
p-values are reported as **descriptive only**, with Benjamini–Hochberg adjusted
q-values and an explicit statement that the study is not powered for per-ID
inference. The primary claims are the rung proportions and the family-level
ordering, which are far fewer comparisons.

**6.6 Reporting rules.**

- Every table cell carries an **n** and an interval. No bare percentages.
- Every absence claim carries the observation tier that supports it. "Not
  observed" and "not present" are different cells.
- The synthetic fixtures in `oracle/schema/examples/` are **never** included in
  any denominator. Analysis filters `synthetic == false`.
- No result is reported without its `apk_sha256` list, so every number is
  re-derivable.

**6.7 What will be reported even if it is embarrassing.** A null result — e.g.
"the DEX-only filter changes nothing" — is a publishable outcome and will be
reported as such. So will "the instrument cannot see 60% of the taxonomy, so the
attribution table is mostly `UNKNOWN`".

---

## 7. Threats to validity

Ordered roughly by how much they can damage the result. Each names what it would
take to fix it, so a reader can see which are fatal and which are merely
limiting.

### T-01 — **The oracle is not Android. This is the dominant threat.**

redroid is a privileged Linux container and an AVD is an emulator. Both fail a
substantial subset of *the same assumptions the study is measuring*:
`SUB.BUILD.EMULATOR` (generic fingerprints, no sensors), `SUB.TRUST.PLAY_SERVICES`
(absent on plain images), `SUB.TRUST.ATTESTATION_KEY`,
`SUB.KERNEL.SYS_THERMAL`, `SUB.HW.*` broadly. The E3 physical-device arm exists
only to *quantify* this, on 30 apps.

The consequence is an **attribution error, not just noise**. If Play Integrity
returns `NONE` on both redroid and the substrate, the correct finding is *"a
privileged Linux container cannot produce a hardware-backed attestation"*, not
*"a browser substrate cannot"*. Those are different claims with different fixes,
and only the first is true.

**Pre-registered mitigation:** report the estimand as *divergence from the
reference environment*, always with `environment.kind` attached to the number;
report the E3 sensitivity sub-sample separately; never write "Android" where the
data says "redroid". **Residual risk: HIGH and not eliminated.** A 30-app
physical-device arm cannot validate a 200-app container-based one.

### T-02 — F-Droid is not the app population, and the bias runs in a known direction.

F-Droid is FOSS, sideloaded, and by policy avoids proprietary components. It
therefore systematically **excludes** the apps most likely to fail hard —
banking, DRM, Play-billing games, Play-Integrity-gated enterprise apps — and
systematically **includes** apps with fewer proprietary dependencies.

**Direction of bias: compatibility is OVERSTATED.** A compatibility figure
derived from F-Droid is an estimate about FOSS sideloaded apps, and it will be
optimistic for the Play Store population by an unknown and probably large
margin. Quantifying that margin requires a second corpus, which is out of scope;
it is a **stated limitation, not a solved problem**.

**Mitigation:** the estimand is stated as a property of the F-Droid frame, in
every table. **Residual risk: HIGH, and directional — the worst combination,
because it will not show up as noise.**

### T-03 — Play Integrity censors the measurement, and the corpus may dodge it.

The pre-registered expectation is that for Play-distributed commercial apps, the
integrity gate is **upstream of everything else**: the app is refused at first
launch, never reaches `SUB.RES`, `SUB.GFX`, `SUB.FW`, or `SUB.INPUT`, and the
study learns the refusal and nothing else. The measurement is **right-censored**:
the interesting capability surface is unobserved precisely because the app stops.

The mirror-image problem is that the F-Droid frame has **no Play Integrity**, so
the study may dodge the very thing it most needs to characterise, and may report
a compatibility number that says nothing about commercial apps.

**Mitigation:** the Play-Integrity-dominated scenario is reported as a first-class
result (§8.1), not as a footnote. Any app whose ground truth shows an integrity
call is **excluded from the capability-surface denominator** and reported
separately, because its later rungs are structurally unmeasured. **Residual
risk: HIGH.** This threat cannot be designed away; it can only be reported.

### T-04 — The instrument is blind to much of the taxonomy.

At tiers T1/T2 a stock non-rooted device yields no per-operation file-access
trace, no class-load census, no JNI transitions, and no network exchange. The
recorder states this in `capture_quality.unobserved` and in every `limits` array,
but the consequence stands: **for a large fraction of (app, assumption) cells
there is no instrument at all.** The `MISBEHAVE` class — silent wrongness — is
almost entirely in the blind spot by construction, because a silent failure
produces no log line to detect.

**Mitigation:** assumption-level hit rates are reported **only** for assumptions
with a specified T1/T2 detection signal; the rest are reported as `NOT MEASURED`,
never as zero. **Residual risk: HIGH and structural.** The study can measure
*refusals* far better than *silent misbehaviour*, which biases the reported class
distribution toward REFUSE.

### T-05 — Observer effects are large and mostly unavoidable.

Root shell, `logcat` draining, install-by-adb, no prior app state, no Google
account, no interactively granted runtime permissions, no user input, no
first-run onboarding. Any app needing a permission grant, a login, or an
onboarding step fails **in the harness**, and scoring that as a substrate
divergence is wrong.

**Mitigation:** every perturbation is enumerated in `capture.observer_effects`;
apps whose ground truth requires a grant or a login are tagged and reported as a
separate stratum. **Residual risk: MODERATE** — controllable but not removable.

### T-06 — `L2`/`L3` conflate "works" with "did not die".

A login wall, a network error page, and a working app are the same rung. §4.3
bounds this with a 30-app manual screen, which is far too small a sample to
correct the headline number.

**Mitigation:** headline claims are stated as *"reached first frame without
fatal error"*, never as *"works"*. **Residual risk: HIGH for any user-facing
claim, MODERATE for the DV as defined.** The DV is deliberately a weak variable;
it is a weak variable *on purpose*, and the report must not quietly upgrade it.

### T-07 — The substrate is a moving target and the study will drift.

The runtime is under active development. A result is only meaningful against a
pinned revision, and re-running with an unchanged hypothesis after a fix is
exactly how a favourable number gets manufactured.

**Mitigation:** every result carries the substrate revision. The protocol hash
(§10) is fixed before collection. Post-hoc re-runs are reported as a
time series, never as a single final number. **Residual risk: MODERATE** —
manageable by discipline.

### T-08 — Oracle/substrate asymmetry is a confound on *every* comparison.

A divergence in `Build.MODEL` may be "the app needed a real model string" or
"we chose a bad string". These are not distinguishable without a control.

**Mitigation:** a **synthetic-identity baseline** is pre-registered — the
substrate is run with a *self-consistent, obviously synthetic* identity and with
a *plausible retail* identity, and the difference in rung outcomes is reported
as the *fabrication-attributable* portion. **Residual risk: MODERATE.** This is
the only mitigation for T-08 and it is worth the extra runs.

### T-09 — Reverse-engineering the result.

**Mitigation:** protocol hash; amendments dated and reasoned; §6.6's rule that
null and embarrassing results are reported. **Residual risk: LOW**, contingent on
the hash being recorded in the first commit rather than retrofitted.

### T-10 — Classifier reliability on symptom triage.

§6.3's `certain`/`likely`/`speculative` scoring involves judgement, whether by a
human or a model. Unreliable triage would inflate `certain` counts.

**Mitigation:** a 50-recording double-scored subset; Cohen's κ reported as a
result. **Residual risk: LOW-MODERATE** and measurable.

### T-11 — Statistical power and multiplicity.

N = 200 with 6 rungs and 145 assumptions. Per-ID rates near 1% have intervals
spanning most of [0, 5]%. A family-level finding with 20 members is far better
determined than any member.

**Mitigation:** §6.5. **Residual risk: MODERATE**, and it is a limit on *which*
claims are available, not on their honesty.

### T-12 — Recording fidelity: a pattern that stops matching looks like behaviour that stopped.

The logcat patterns are version-sensitive. If `am_on_resume_called` is absent on
a newer image, every app grades `L0_PROCESS_STARTED` — a fabricated collapse.

**Mitigation:** `pattern_not_matched` warnings; the validator's
`LF_UNRESOLVED` guard; and a **pattern-coverage report per environment** that is
published alongside the results, so a pattern regression is visible as a pattern
regression. **Residual risk: MODERATE** and entirely mitigable with the coverage
report.

### T-13 — The corpus filter defines the headline number.

"N% of apps are DEX-only" is a property of the filter, and reporting it as
compatibility is circular.

**Mitigation:** §2 and taxonomy §0.1 forbid the conflation in writing. **Residual
risk: LOW** — it is a reporting-discipline risk.

### T-14 — Single-host measurement for all timing results.

Timing, thermal, and Doze results come from one machine at one ambient
temperature. `SUB.CPU.TIERING` and `SUB.TIME.VSYNC` are host-dependent, and a
fast host flatters the substrate.

**Mitigation:** record host specification; report timing results as ratios to
the same app on the reference device, never as absolutes; do not report a
cross-host timing comparison as a general claim. **Residual risk: MODERATE.**

### T-15 — The evaluator is not a neutral instrument; it is a design choice.

Every substrate decision — `getSystemService` returning `null` versus throwing,
whether to fabricate an integrity verdict, what to report for `/proc/uptime` — is
a free variable that changes the result. A study that does not enumerate its
choices cannot be reproduced, and a study whose choices were tuned produces a
number about the tuner.

**Mitigation:** taxonomy §4's `SUB.IPC.SYSTEM_SERVICE` entry pre-registers the
`null`-not-throw choice and the ethics of fabricating an integrity verdict (§8.1).
**Residual risk: HIGH, and structural to the whole genre.** This is the threat
that this project is best placed to address, because naming a free variable is
what a taxonomy is for.

---

## 8. Pre-registered expected result range

Written before measuring, including the outcomes that would be embarrassing.
These are predictions, not findings.

### 8.1 The dominant scenario: the integrity wall

**Expected, and stated up front as a real possibility: for Play-distributed
commercial apps, a large majority fail at `L0`/`LF_FAILED_BEFORE_L0` on the
integrity gate, and the study learns almost nothing about the rest of the
taxonomy.**

Supporting mechanism, verified: a Play Integrity verdict is computed
**server-side by Google Play** from hardware-backed signals and returned to the
app's **own backend** [V2]; `MEETS_DEVICE_INTEGRITY` requires a genuine
certified device and, on Android 13+, hardware-backed proof of a locked
bootloader on a certified manufacturer image [V1]; `MEETS_STRONG_INTEGRITY`
additionally requires hardware-backed signals and a recent security patch
[V1][V3]. A browser substrate has none of these and cannot acquire them.

**Predicted shape of this scenario:**

- On the F-Droid frame: **largely absent**, because F-Droid apps do not call
  Play Integrity. So this corpus may report a *high* compatibility number that
  says nothing about the commercial population. **This is the single most
  likely way the study produces a misleading result.**
- On any Play-distributed sample: `MEETS_STRONG_INTEGRITY` and
  `MEETS_DEVICE_INTEGRITY` → `NONE`; the client's *backend* rejects; the client
  surfaces a generic error. The failure is **REFUSE**, and its *cause* is
  server-side and unobservable from either arm.

**A note on SafetyNet, because it changes what is measurable.** SafetyNet
Attestation stopped working for every app on **2025-01-31**; every call now
invokes the failure listener with `ApiException` status 7 `NETWORK_ERROR`
[V4][V5]. So any app whose only integrity gate is SafetyNet **fails identically
on a real phone and on the substrate** and carries **zero** discriminating
signal. Such apps must be excluded from divergence scoring, not counted as
compatibility failures.

### 8.2 The second scenario: the timing wall

**Expected: a substantial minority of apps that pass the integrity gate still
fail or hang in the substrate, for reasons that are *speed*, not correctness.**

`SUB.CPU.TIERING` (no AOT, possibly no JIT) and `SUB.TIME.VSYNC` (no display) both
predict failure that is **intermittent** and looks like flakiness. This is why
§3.7 mandates three repeats, and why best-of-3 alone is prohibited.

### 8.3 The DEX-only filter

**Expected: excluding apps with native code changes the denominator
dramatically and the numerator barely at all.** Reasoning: native code is a
sufficient reason to reject an app, but the other ~140 assumptions are live
regardless, and several of them (`SUB.TRUST.PLAY_INTEGRITY`,
`SUB.IPC.BROADCAST`, `SUB.FW.INVOKEDYNAMIC`) refuse apps on their own.

**This is the prediction most likely to be wrong in an interesting way.** If
the DEX-only filter turns out to be highly predictive, that would mean most apps
fail *only* because of native code, which would be a genuinely surprising and
reportable result. Pre-registered either way (RQ6).

### 8.4 The overall range

For the **F-Droid frame** on the reference arm, and stated as a range I would
consider unsurprising:

| Rung | Expected share of apps | Confidence in this range |
|---|---|---|
| Reaches `L1` or better | **50–85%** | Moderate |
| Reaches `L2` or better (first frame drawn) | **40–80%** | Low-moderate |
| Reaches `L3_STEADY_STATE` | **30–70%** | **Low** |
| `L3` **and** passes the manual usefulness screen | **15–50%** | **Very low** |

For a **Play-distributed** population, all four figures are expected to be
**dramatically lower**, dominated by §8.1.

**Stated as the honest summary: the most likely single finding of this project is
not a compatibility percentage. It is a characterisation of the *shape* of the
failure space — that a small number of assumptions are binding constraints for
most apps, that the binding constraint differs by app population, and that the
`MISBEHAVE` class is the one the instrument is worst at detecting.** If the
compatibility numbers come out high, the interpretation that most deserves
suspicion is the one where the F-Droid frame happened to dodge the integrity
wall.

### 8.5 Results that would falsify this protocol

- Compatibility so high that the integrity wall does not appear even on a
  Play-distributed sample → the `SUB.TRUST` priors are wrong and the wall is
  defeatable.
- `L3_STEADY_STATE` strongly correlated with a single assumption across the
  whole corpus → the ordering analysis (RQ3) collapses to a single number and
  the taxonomy was over-specified.
- The E3 physical-device arm shows the *same* rung distribution as redroid →
  T-01 is much less serious than pre-registered, and the study can be read as
  being about Android rather than about a container. This is the outcome that
  would most improve the study's standing, and it is entirely possible.

---

## 9. Reproducibility requirements

- Every capture records `capture_script_sha256`, `apk_sha256`, the reference
  `image_digest`, and the substrate revision. A result that cannot name all four
  is not reproducible and will not be reported.
- Recording format version is `andro-substrate.ground-truth/1`. A format change
  invalidates comparability and requires re-baselining.
- The synthetic fixtures are labelled as such at every level
  (`synthetic: true`, `provenance.synthetic_reason`, a `warnings` entry, and
  `notes`) and are filtered out of all analysis.
- No recording is fabricated. There is no code path in `adb-recorder.sh` that
  emits a recording describing an execution that did not happen, and the recorder
  exits non-zero when a required step produces nothing.

---

## 10. Pre-registration hash

Computed over the two documents this protocol depends on. To be recorded in the
first commit that contains them, so that any later change is visible as a change.

```
sha256( docs/research-protocol.md || docs/divergence-taxonomy.md )
```

The value is printed by:

```sh
cat docs/research-protocol.md docs/divergence-taxonomy.md | shasum -a 256
```

**Note on self-reference.** The digest covers `research-protocol.md`, so it
**cannot be written into that file** — doing so would change the digest. It
belongs in the first commit that contains these two files, as the commit subject
or as a recorded value elsewhere. The working-tree digest at authoring time is
reported in the agent handover notes for this milestone; if the committed blobs
hash differently, **the committed value governs** and any results quoting the
working-tree value must say so.

Any result must cite it. If the protocol or taxonomy is edited after data
collection starts, the pre-edit hash must appear in the results table as well.

---

## 11. References

The verification key is the one in
[`../oracle/RECORDING.md`](../oracle/RECORDING.md) §13. All of the following
were retrieved and checked on **2026-09-28**; the substantive claim each one
supports is marked in the text above.

- **[V1]** <https://developer.android.com/google/play/integrity/verdicts> —
  integrity verdict requirements.
- **[V2]** <https://developer.android.com/google/play/integrity/standard> —
  verdicts are server-side; the token goes to the app's backend.
- **[V3]** <https://developer.android.com/google/play/integrity/overview> —
  `MEETS_STRONG_INTEGRITY`; standard vs classic requests.
- **[V4]** <https://groups.google.com/g/safetynet-api-clients/c/qcMXTCpHReg> —
  SafetyNet turndown, 2025-01-31, `ApiException` status 7.
- **[V5]** <https://developer.android.com/privacy-and-security/safetynet> —
  SafetyNet deprecated.
- **[V6]** <https://developer.android.com/guide/app-compatibility/restrictions-non-sdk-interfaces>
  — non-SDK enforcement from API 28; the `max-target-x` mechanism behind
  `SDK_INT` strata and `SUB.FW.NON_SDK_API`.
- **[V7]** <https://developer.android.com/about/versions/10/non-sdk-q> — list
  renaming, `@UnsupportedAppUsage(maxTargetSdk=…)`.
- **[V12][V13]** AOSP `SystemClock.java` and the `SystemClock` reference —
  `uptimeMillis` excludes deep sleep, `elapsedRealtime` includes it, both
  monotonic.
- **[V14]** <https://f-droid.org/2026/01/23/fdroid-in-2025-strengthening-our-foundations-in-a-changing-mobile-landscape.html>
  — 4,061 apps on the main repo; ~21% reproducibly built.
- **[V15]** <https://f-droid.org/docs/All_our_APIs/> — the signed
  `index-v2.json` and per-app YAML metadata behind the sampling frame.
- **[V16][V17][V18]** AWAKE *App Virtualization Attacks*;
  `asLody/VirtualApp`; `didi/VirtualAPK` — prior art for running unmodified
  APKs outside their installed context. **[V16] is a secondary source; its
  quantitative claims are UNVERIFIED at primary and are not relied upon.**

**Marked UNVERIFIED and not relied upon:** community-forum claims about emulator
behaviour under `MEETS_STRONG_INTEGRITY`; the quantitative figures quoted in
[V16]. **Conjecture:** every prior in the taxonomy that is not tagged `[Vn]`,
including the expected result ranges in §8.
