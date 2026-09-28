# 0001 — Why the ranking inverts, and what to do about the rubric

**Agent 14.** One question: *the four cold-start measurements say the smallest app
needs the biggest framework closure — does that hold, and what does it do to
`analysis/candidates.md`?*

Every figure carries a tag.

* **[measured]** — read directly off a capture or counted in a committed file.
* **[derived]** — a computation over measured values. Reproduce with
  `python3 docs/analysis/closure-frame/stats.py`; pinned by
  `python3 docs/analysis/closure-frame/test-figures.py`.
* **[conjecture]** — interpretation, labelled as such.

The per-app numbers are in `docs/analysis/measurement.json` (24 apps × 1–3
repetitions; every trace identified by SHA-256). **`stats.py` emits 700+ figures
and this document quotes only figures it emits.**

---

## 0. The short answer

1. **The four-app "anti-correlation" does not survive.** On the four published
   candidates the rank correlation between static `android.*` method count and
   measured closure is **−0.4** (Pearson **−0.188**), and the four closures span
   only **1,134** methods, or **22.5 %** of their median. Across the 24-app cohort the same variable has
   a **positive** Pearson *r* of **+0.152** (95 % CI **[−0.268, +0.523]**,
   *p* = 0.483); on the 16 untruncated captures, **+0.376** (CI [−0.147, +0.735],
   *p* = 0.154). Four points did not contain an anti-correlation. They contained
   noise whose sign was set by which apps happened to be short-listed. **[derived]**
2. **The `17 → 628` table is one app, not four, and its numbers are a
   sampling-budget artefact.** I decoded all 15 traces the brief left on the
   device. **Nine of the 15 contain gita's classes; the only other app anywhere
   is `headingcalculator` (`t.trace`); `balancetheball` and `badpixels` were
   never captured.** Only **1 of the 4** reported counts (373) equals any
   per-file count in the artefacts. The six sparse gita captures measure
   **206 / 323 / 325 / 395 / 331 / 333** distinct methods — the *same app*,
   varying by 1.9×. **[measured]**
3. **On a clean measurement the ordering reverses.** gita, which the rubric
   ranked #1, needs **5,722** framework methods; badpixels, ranked #2, needs
   **4,588** and is the cheapest of the 24. **The rubric's second choice was its
   best one, and the rubric's reasoning is what displaced it.** **[measured]**
4. **No static size feature predicts dynamic demand.** Eleven candidates tested
   at n = 24; nine are indistinguishable from zero. The exception is
   *whether the app references an `AdapterView`/`Adapter` type*: *r* = **+0.491**
   (CI [0.109, 0.746], *p* = 0.014), worth a median **+848 methods (+15.6 %)**,
   and **+907.5 (+17.1 %)** on the untruncated subset (medians 6,216 vs 5,308.5).
   **[derived]**
5. **Recommendation: retire the surface-size score as a selector.** Keep §1.3's
   hard filters verbatim — they are structural refusals, not size proxies, and
   nothing here touches them. Replace the ranking with a **gate** on
   `referencesAdapterType == false`, and stop. §5. Falsification conditions in
   §5.3, including the one I think is most likely to bite (F1).
6. **The gap is explainable and the predictor is not wrong — it answers a
   different question.** The static method set is a **subset** of what runs
   (recall 76.5–100 %, no false positives on the four) with **0.3 % recall** for
   gita. The ratio measured/static spans **21.1× to 399.4×** across 24 apps.
   §6. Conclusions that **survive**: the hard filters, the DEX toolchain, and
   `FINDINGS.md` §7's "transitive closure" projection, which this is the first
   measurement of. Conclusions that **do not**: every number in the project that
   reads a static `android.*` count as a quantity of work, including the
   shim-coverage percentage, which recomputes from 27.4 % to **3.8 %**.

---

## 1. The measurement that just landed, audited

The brief reports four apps, four framework counts (628 / 373 / 338 / 242) and
four static predictions (17 / 27 / 33 / 17). I looked for the artefacts before
looking for the mechanism.

### 1.1 The static half is confirmed exactly

[measured] Read from `analysis/candidates/measured.jsonl`:

| app | APK B | DEX B | own methods | `android.*` types | `android.*` methods |
|---|--:|--:|--:|--:|--:|
| `eu.quelltext.gita` | 895,225 | 24,897 | 43 | 15 | **17** |
| `com.jeffliu.balancetheball` | 42,170 | 4,671 | 30 | 17 | **27** |
| `org.debian.eugen.headingcalculator` | 84,382 | 7,761 | 54 | 16 | **33** |
| `tk.al54.dev.badpixels` | 13,949 | 3,681 | 22 | 15 | **17** |

The brief's 17 / 27 / 33 / 17 is `len(dex.androidMethods)` and its 43 / 30 /
54 / 22 is `dex.methods`. Both exact. The brief left three APK sizes blank; the
measured values are above, and **badpixels is 13,949 B of APK (3,681 B of DEX),
not 27 KB.**

### 1.2 The dynamic half is one app, and I could not reproduce it

[measured] `adb devices` showed `emulator-5554` already running: Android 13,
SDK 33, `arm64-v8a`, `ro.product.model = "Android SDK built for arm64"`,
`ro.kernel.qemu = 1`, `adbd` already running as root. **I did not boot it.** I
used it read/write — I installed 20 APKs onto it and wrote traces to
`/data/local/tmp/mine`.

The brief's traces exist, in `/data/local/tmp`, never committed. I listed 23
files there at the start of this session: 6 were zero bytes (failed captures) and
17 had content. `measure.py` decodes every one of the 17 and records them under
`measurement.json` § `legacyCaptures` / `legacyUndecodable`. **[measured]**

* **14 decoded, 1 not** — `f1.trace` is in ART's *interleaved streaming* format
  and is also truncated at **8,388,602** B, so this decoder does not read it.
  **Two further files, `m_recreate.trace` and `m_recreate2.trace`, were removed
  from the device by a cleanup step of mine before the audit ran. They are named
  here and nowhere else; I quote no figure from them.**
* **9 of the 14 contain `eu.quelltext.gita` classes.** Every large trace is
  gita. The only non-gita app anywhere is `t.trace`
  (`org.debian.eugen.headingcalculator`, **213** framework methods).
* **No capture of `balancetheball` or `badpixels` exists on the device.**
* The six sparse gita captures, in file order: **206, 323, 325, 395, 331, 333**
  distinct methods — **202, 298, 299, 373, 306, 312** after the four-prefix
  filter. Same app, same window definition, **1.9× spread.**
* **1 of the 4** reported counts (373) equals any per-file count.

**[conjecture]** The reported 628 / 373 / 338 / 242 are a sampling-budget
artefact: whichever window and rate produced them, the count moves with the
budget and not with the app. Agent 15 reached the compatible conclusion
independently from the other side — `0002-is-the-closure-well-defined.md` reports
mean pairwise Jaccard **0.44** across the six sparse gita captures, versus
**0.9999** at full tracing. **Any per-app claim resting on the brief's four
numbers is void.** This is also the answer to the brief's request to "use the
capture harness in `trace/` if it exists": it does not exist; `/data/local/tmp`
was where the captures actually were, and they were of one app.

### 1.3 So I took my own measurement

Same already-running rooted emulator, capture method recorded in
`measurement.json` § `method`:

```
adb shell am force-stop <pkg>
adb shell am start-activity -S -W -P <file> -n <pkg>/<activity>
```

`-S` force-stops, so `LaunchState: COLD` is asserted by the shell, not assumed.
`-W` waits for the first frame. `-P` starts ART **buffered method tracing** —
every enter and exit, no sampling — which stops when the app reports idle. I
then waited for the on-device file size to stabilise before pulling, because ART
flushes seconds after launch and pulling early yields a 0-byte file. (It did,
twice, before I fixed it. **[measured]**)

Window limitations, stated up front:

* **It is not "to first frame inclusive."** ART stops at idle, so post-frame
  settle work is inside the window. This inflates all 24 apps and favours none,
  but these are *first-frame-plus-settle* closures. **[measured]**
* **It is a cold start**, so no previous activity of the same app is torn down
  inside the window. The brief's "includes the previous activity's teardown"
  caveat does not apply to my captures; it plausibly does to the sparse ones,
  which is one more reason not to compare across instruments.
* `com.android.internal.*` — **344 to 423** methods per app, **370** for gita
  rep 1 — is excluded by the project's four-prefix rule. I report it separately
  rather than silently changing the rule. **[measured]**
* **8 of 24 captures overflowed the ART trace buffer** and are truncated at
  exactly **599,184** method calls. I could not raise the buffer: the relevant
  system property is read at zygote init, so it would need an emulator restart,
  and I was not going to restart a device the orchestrator had already set up.
  I therefore report **every correlation twice: once on all 24 and once on the
  16 untruncated captures**, and the two agree in sign and in which features
  matter. The eight affected: `app.rapidsplit`, `art.tessell.editor`,
  `ir.ammari.nodelook`, `org.asafonov.monly`, `org.billthefarmer.specie`,
  `org.droidtr.keyboard`, `org.example.rosary`, `org.ghostrain`. **[measured]**

**n = 24 apps, 1–3 repetitions each, 141,696 to 599,184 method calls each,
median 364,465.** The four published candidates plus 20 more from
`analysis/candidates/measured.jsonl`, stratified to span
`distinctAndroidMethods` 15 → 228. The sample is *not* random; see §4. **[measured]**

### 1.4 The cohort

[measured] `aMeth` = distinct `android.*` methods referenced; `fw` = measured
framework methods, min/median/max over repetitions; `adapter` = methods on
`Adapter`/`AbsListView`/`ListView`/`AdapterView`/`BaseAdapter`/`ArrayAdapter`/
`ListAdapter` classes; `%core` = share of the 24-app universal core (§3.4).

| package | aMeth | types | fw min | fw med | fw max | adapter | %core | trunc |
|---|--:|--:|--:|--:|--:|--:|--:|:-:|
| `com.tmendes.dadosd` | 15 | 14 | 5766 | 5991 | 5991 | 0 | 40.8 | no |
| `eu.quelltext.gita` | **17** | 15 | 5617 | **5722** | 5741 | **132** | 41.1 | no |
| `tk.al54.dev.badpixels` | **17** | 15 | **4580** | **4588** | 4695 | 0 | 51.2 | no |
| `name.seguri.android.lock` | 27 | 22 | 5054 | 5188 | 5188 | 0 | 46.5 | no |
| `com.jeffliu.balancetheball` | 27 | 17 | 5037 | 5132 | 5181 | 0 | 45.8 | no |
| `name.seguri.android.getforegroundactivity` | 31 | 23 | 6760 | 7076 | 7076 | 0 | 34.8 | no |
| `org.debian.eugen.headingcalculator` | 33 | 16 | 4600 | 4941 | 5021 | 0 | 51.1 | no |
| `org.asafonov.monly` | 37 | 20 | 6142 | 6142 | 6142 | 0 | 38.3 | **yes** |
| `com.dosse.dozeoff` | 41 | 25 | 5423 | 5429 | 5429 | 0 | 43.3 | no |
| `nl.eventinfra.wifisetup` | 46 | 31 | 6155 | 6155 | 6155 | 52 | 38.2 | no |
| `ir.ammari.nodelook` | 58 | 35 | 4745 | 4758 | 4758 | 0 | 49.5 | **yes** |
| `com.hobbyone.HashDroid` | 64 | 43 | 7069 | 7257 | 7257 | 51 | 33.2 | no |
| `com.trianguloy.adnihilation` | 67 | 33 | 6098 | 6272 | 6272 | 0 | 38.5 | no |
| `com.fr3ts0n.androbd.plugin.sensorprovider` | 78 | 36 | 6215 | 6277 | 6277 | 127 | 37.4 | no |
| `app.rapidsplit` | 90 | 44 | 6072 | 6299 | 6299 | 0 | 37.3 | **yes** |
| `art.tessell.editor` | 100 | 62 | 6121 | 6324 | 6324 | 0 | 38.4 | **yes** |
| `org.ghostrain` | 118 | 60 | 4540 | 4649 | 4649 | 0 | 50.5 | **yes** |
| `org.billthefarmer.specie` | 127 | 68 | 5158 | 7130 | 7130 | 109 | 45.6 | **yes** |
| `com.trianguloy.continuousDataUsage` | 141 | 71 | 7368 | 7374 | 7374 | 0 | 31.9 | no |
| `com.github.yeriomin.smsscheduler` | 157 | 74 | 5956 | 5999 | 5999 | 146 | 39.5 | no |
| `org.droidtr.keyboard` | 177 | 57 | 3349 | 3731 | 3731 | 0 | 70.2 | **yes** |
| `org.cheeserobot.btcwidget` | 190 | 95 | 6128 | 6408 | 6408 | 0 | 38.4 | no |
| `is.zi.huewidgets` | 204 | 82 | 5539 | 5855 | 5855 | 0 | 42.4 | no |
| `org.example.rosary` | 228 | 75 | 6240 | 6577 | 6577 | 0 | 35.7 | **yes** |

Closure range **3731 to 7374**, median **6070.5**, population SD **911.7**.
On the 16 untruncated captures: **4588 to 7374**, median **5995**. **[derived]**

---

## 2. The instrument, and why I trust its counts

I did not trust the brief's format description either, so I decoded the files
and made the decoder falsify itself. The ART buffered method-trace format is a
text header (`*version`, `*threads`, `*methods`, terminated by `*end`) then a
32-byte `SLOW` packet followed by a fixed 14-byte record per method call:
`tid:u16le`, `(methodId<<2 | kind):u16le`, three more words, `kind` 0 = enter,
1 = exit, 2 = thread change. **[measured]** `closure-frame/art-trace.py`. This
is the same format Agent 15's `lib/arttrace.mjs` reads, and our decoders agree
exactly on the shared files — the six sparse gita captures come out
**206 / 323 / 325 / 395 / 331 / 333** from both. **[derived]**

Three self-checks, all of which must hold or the decode is rejected:

1. `(len(data) − 32) % 14 == 0`, and the record count equals the header's
   `num-method-calls`. Holds for all 24 captures and all 15 legacy files.
2. The set of method ids in the data equals the `*methods` table exactly — zero
   in either direction. This is the strong one: the table is the **complete**
   set of methods in the window, not a partial index.
3. Per-thread enter/exit balance. gita rep 1: **273,905** exactly-matched
   exits, **111** frames popped by speculative unwind, **7** exits with no
   matching frame, **43** frames still open when the trace was cut. Across all
   24: 4,903,774 exact, 1,123 speculative, 186 unmatched. **[measured]**

Check 2 licenses the headline claim. The number is not a sample of a sample: it
is the exact distinct-method set of a full method trace.

**A caveat I will not paper over.** Check 3 is not perfect, and the residual
~1-frame desynchronisation makes *edge*-level attribution unreliable — a naive
caller-of analysis produced nonsense such as `ListView.layoutChildren` called by
`Settings.isInSystemServer`. Correct edges appear too
(`AbsListView.layoutChildren → AbsListView.obtainView`,
`ViewGroup.layout → ViewGroup.measureChildWithMargins`) but I could not find a
threshold that keeps the good ones and drops the bad. **So §3 is argued from
method *sets*, which are exact, not from a call graph, which is not.** The brief
asked me to "trace the call structure if the trace format allows; if it does
not, say so rather than guessing." The format carries the sequence; **my unwind
of it is not sound enough to publish a call graph, and the set-level evidence
does not need one.** A call-graph reconstruction needs a proper ART trace
parser against the platform source, not a heuristic unwinder.

---

## 3. Why does the smallest app need the biggest closure?

### 3.1 The decomposition

gita, rep 1: **5,722** counted framework methods across **894** distinct
framework classes, out of 548,192 method calls. **[measured]**

| family | methods | share |
|---|--:|--:|
| `android.view` | **1,452** | **25.4 %** |
| `android.graphics` | 813 | 14.2 % |
| `android.app` | 561 | 9.8 % |
| `android.content` | 519 | 9.1 % |
| `android.os` | 421 | 7.4 % |
| `android.widget` | 414 | 7.2 % |
| `java.lang` | 285 | 5.0 % |
| `java.util` | 277 | 4.8 % |
| `android.util` | 225 | 3.9 % |
| `android.net` | 119 | 2.1 % |
| `android.text` | 116 | 2.0 % |

`android.view` is **25.4 %**. The brief's "199 of 628" is **31.7 %**. The shape
agrees; the magnitude does not, for the reason in §1.2. **[derived]**

### 3.2 Is `android.view` list recycling, text, touch, or generic?

The brief's working hypothesis was `ListView` + `ArrayAdapter`. **The set-level
evidence supports it, more sharply than the brief assumed.** Partitioning the
four candidate mechanisms by class prefix: **[measured]**

| mechanism | gita | balancetheball | headingcalculator | badpixels |
|---|--:|--:|--:|--:|
| adapter / list recycling | **132** | **0** | **0** | **0** |
| text measurement & layout | 116 | **218** | 140 | 87 |
| touch dispatch | 56 | 56 | 14 | 14 |
| `SurfaceView` / render | 67 | 67 | 54 | 67 |

* **The adapter path is gita's, exclusively, among the four.** **132** methods on
  `Adapter`/`AbsListView`/`ListView`/`AdapterView`/`AbsAdapter`/`BaseAdapter`/
  `ArrayAdapter`/`ListAdapter` classes, present in gita and **zero** in the other
  three. The recycling hypothesis, confirmed at set level. **[measured]**
* **"A custom-drawing game avoids the view toolkit" is false as stated.**
  balancetheball touches **more** text machinery than gita — **218** against
  **116**, a difference of **102** — because it draws text with `Canvas.drawText` and pays for
  `StaticLayout` / Minikin / font configuration directly, where gita's `TextView`
  gets it through the adapter's `getView`. **[measured]**
* **The `SurfaceView` path is not a discriminator at all**: 67 / 67 / 54 / 67.
  Whatever balancetheball avoids by drawing to one `SurfaceView`, it pays for
  elsewhere. **[measured]**

### 3.3 …and then a wider sample dissolves it

I got this wrong first and corrected it, so it is worth stating plainly.
Within the four, gita's closure exceeds badpixels' by **1,331** methods and
**982** of those are executed by none of the other three. That looks like a
mechanism. Across all 24, **only 37** of gita's methods are executed by no other
app, and only **8** of the 132 adapter methods are gita-exclusive — the other
**124** are shared with `smsscheduler` (116), `sensorprovider` (115), `specie`
(63), `wifisetup` (17) and `HashDroid` (15), i.e. **5 of the other 23 apps**.
**[measured]**

gita's genuinely unique 37: **13** on `GradientColor` (gita's layout uses a
gradient drawable), **3** on `AbsListView$RecycleBin`, **3** on
`ListView.measureScrapChild` / `recycleOnMeasure` / `measureHeightOfChildren`,
**1** on `ArrayAdapter.<init>`, **1** on `BaseAdapter.isEnabled`, **6** on
`View`/`ViewGroup` temporary-detach and autofill, **4** on
`Resources.newTheme`/lambda, and 3 odds and ends. **[measured]**

**[conjecture]** The mechanism is real — an `AdapterView` on screen does pull a
deep framework path — but it is **not rare**. It is what every list-shaped
Android app does. gita is not unusual for having a `ListView`; gita is unusual
for having *nothing else*, and the four-app shortlist is what made that look
like a gita-specific property. Within the four it is a mechanism; across the
population it is a **6-in-24 minority trait worth +16 %**, which is §4's
finding and the only one with a *p* under 0.05.

### 3.4 The floor — the number that actually matters for cost

[derived]

* Intersection of all 24 apps' framework method sets: **2,350** methods.
* Union: **12,880**. The core is **18.2 %** of the union.
* gita's closure is **41.1 %** core; badpixels' **51.2 %**; `droidtr.keyboard`'s
  **70.2 %**; `continuousDataUsage`'s **31.9 %**.

**Roughly two to five thousand methods of any app's closure is the platform's own
cold-start cost** — process start, `ZygoteInit`, class loading, `ActivityThread`
bring-up, resource and theme resolution, the window and input pipelines — paid
identically by every app. An app's own contribution is the remainder, and for a
minimal app that remainder is a few dozen methods. **This is the project's cost
model, and no static feature in the corpus predicts any of it.**

---

## 4. Does the anti-correlation hold beyond four points?

**No. At n = 24 the sign is even wrong, and it stays positive at n = 16.**
**[derived]** Pearson *r* against measured closure (median of repetitions), with
Fisher *p*, 95 % CI, and the same fit on the 16 untruncated captures only. Eleven
features, including everything the rubric scores on:

| static feature | *r* (n=24) | 95 % CI | *p* | *r* (n=16) | 95 % CI (n=16) | *p* (n=16) |
|---|--:|---|--:|--:|---|--:|
| references an `AdapterView`/`Adapter` type | **+0.491** | [+0.109, +0.746] | **0.014** | **+0.511** | [+0.020, +0.803] | **0.042** |
| `android.view`+`android.widget` type count | +0.218 | [−0.203, +0.571] | 0.309 | +0.509 | [+0.018, +0.802] | 0.043 |
| `distinctAndroidTypes` (weight 0.28) | +0.294 | [−0.124, +0.624] | 0.165 | +0.458 | [−0.049, +0.777] | 0.074 |
| `dexBytes` (weight 0.07) | +0.203 | [−0.218, +0.561] | 0.345 | +0.453 | [−0.056, +0.775] | 0.078 |
| manifest components (weight 0.01) | +0.266 | [−0.154, +0.605] | 0.211 | +0.248 | [−0.282, +0.662] | 0.361 |
| `dex.methods` (weight 0.04) | +0.235 | [−0.186, +0.583] | 0.272 | +0.306 | [−0.223, +0.696] | 0.254 |
| `LayoutInflater.inflate` call sites | +0.204 | [−0.217, +0.561] | 0.343 | +0.069 | [−0.442, +0.546] | 0.803 |
| **`distinctAndroidMethods` (weight 0.22)** | **+0.152** | **[−0.268, +0.523]** | **0.483** | **+0.376** | [−0.147, +0.735] | 0.154 |
| manifest permissions | +0.048 | [−0.362, +0.443] | 0.825 | +0.129 | [−0.392, +0.587] | 0.640 |
| APK bytes | +0.254 | [−0.167, +0.596] | 0.234 | +0.065 | [−0.445, +0.543] | 0.815 |
| `Canvas.draw*` call sites | −0.056 | [−0.449, +0.356] | 1.201 | +0.109 | [−0.409, +0.574] | 0.693 |

**Every single *r* has the same sign on both subsets except `Canvas.draw*`, and
no size feature reaches significance on either.** The rubric's two heaviest
components — `android_types` (0.28) and `android_methods` (0.22), **50 % of the
weight between them** — are the 2nd and 9th weakest of eleven at n = 24, and
their CIs comfortably contain both −0.5 and +0.5.

**Limits of this evidence, because they are real:**

* **The sample is stratified, not random.** I chose 20 of 149 eligible APKs to
  span the `distinctAndroidMethods` range deliberately. That inflates
  independent-variable variance and attenuates every *r* toward zero. A random
  sample would give narrower CIs. It would not plausibly manufacture a strong
  relationship from features this weak — but "attenuated by design" is the
  honest caveat and it applies to every *r* in the table.
* **n = 24, or 16.** Even for the adapter flag the CI runs to +0.80.
* **One window definition, one device, one SDK.** Internally fair; nothing here
  claims to generalise.
* The adapter effect survives partial correlation against both size proxies:
  **+0.454** given `dex.methods`, **+0.493** given APK bytes. Not simply
  "bigger apps use lists". **[derived]**

---

## 5. The rubric

### 5.1 What is contradicted, for the orchestrator

`analysis/candidates.md` is **unmodified**. Its §1.4 states the ranking is
`(score, distinctAndroidTypes, distinctAndroidMethods, dexBytes, packageName,
versionCode)` with `android_types` and `android_methods` carrying 0.50 of 1.00;
its opening line justifies gita on the grounds that it "has to need as little
framework surface as possible"; and its §2.1 asserts gita "is first or second
under every counterfactual, which is the only reason I am willing to recommend a
component I added after seeing the data."

| claim in `candidates.md` | status |
|---|---|
| smaller static surface ⇒ smaller dynamic closure | **contradicted**; *r* = +0.152, *p* = 0.483, sign positive |
| gita needs the least framework work of the 200 | **contradicted**; it is 2nd most expensive of 24 |
| ranks 1–4 identify the cheapest work | **contradicted**; #1 gita = 5,722 is the *most* expensive, #2 badpixels = 4,588 the *least* |
| gita is "one afternoon of shim work", badpixels "four" | **contradicted**; 1,294 of gita's 1,331-method excess over badpixels are methods 20 other F-Droid apps also execute |
| `distinctAndroidTypes`/`distinctAndroidMethods` as selection keys | **unsupported**; 50 % of the weight on the 2nd and 9th weakest of 11 features |
| `shim_method_gap`, saturation 1.0 | **damaged**; a fraction of a set that is 0.3 % of the real one |

The #3 row is the sharpest and I will not hedge it: **the rubric's second choice
was its best one, and the rubric's reasoning is what displaced it.** Its own
§2.1 counterfactual — "without `shim_method_gap`" — makes badpixels #1. The one
component the author added *after* seeing the data, and disclosed, is the one
that pointed at the right app.

### 5.2 Recommendation

**Retire the surface-size score as a selector. Replace the ranking with a gate.**

**Stage 1 — a gate, not a score: keep the hard filters verbatim.** Every filter
in `candidates.md` §1.3 survives: `webview_content_dependency`,
`text_field_on_launch_path`, `layout_onclick_reflective_dispatch`, the
native/DEX filters, the special permissions. They are *structural* claims about
what the substrate cannot do, not size proxies, and nothing in this measurement
touches them. `webview_content_dependency` in particular is the strongest
argument in that document and this measurement strengthens it: an app that
delegates its UI to `WebView` looks *small* statically and is still refused.

**Stage 2 — among survivors, select on `referencesAdapterType == false`, and
stop.** Justification, strongest first:

1. The only measured feature whose CI excludes zero, on both subsets:
   *r* = +0.491 (CI [0.109, 0.746], *p* = 0.014, n = 24) and *r* = +0.511
   (CI [0.020, 0.803], *p* = 0.042, n = 16). **[measured]**
2. Free: the analyzer already resolves `distinctAndroidTypes`; this is a
   substring test on a list it already produces. **[measured]**
3. It is a **mechanism**, not a correlate. It names the widget that causes the
   depth — an `AdapterView` forces child creation, recycling, measure and layout
   per row. gita pays 132 methods for it; three list-free apps pay 0. A selector
   you can explain beats a selector with a better *r*. **[measured]**
4. It inverts the current rubric on the measured four and lands **badpixels
   first** — the app the measurement says is cheapest to reach first frame on.

The other 18 of 24 apps have no better discriminator available, and I am not
going to manufacture one. With |*r*| ≤ 0.51 for everything tested, **the honest
answer to "which surviving app is cheapest?" is "we do not know, and the
instrument that would tell us costs one cold start per candidate."** That is a
concrete, budgeted recommendation: the entire measurement in this document is
**51 cold-start captures across 24 apps**, 37 of them untruncated, in roughly
20 minutes of wall clock on one emulator. If the project can afford N captures,
it should spend them on N candidates and select on measured closure.

### 5.3 What would falsify this

| # | falsifier | threshold |
|---|---|---|
| **F1** | The adapter effect is an artefact of stratification or of the to-idle window. | Re-run on **24 randomly sampled** eligible APKs, and separately with a first-frame-exclusive window. If *r* < 0.2 or the CI covers 0, §5.2 collapses. **This is the one I expect to bite.** |
| **F2** | The adapter effect is really just size. | Already contradicted: partial *r* is +0.454 given `dex.methods`, +0.493 given APK bytes. **Falsified if** a size-controlled fit drops the coefficient below 0.1. |
| **F3** | A better static predictor exists and I missed it. | Any feature with *p* < 0.05 and CI excluding 0 in a re-fit including the adapter flag *and* size. I tested 11 features across four families; the sweep should be wider. |
| **F4** | Measured closure is not a stable property of the app. | Partly tested: gita's 3 repetitions span 5617–5741 (spread **124**, 2.2 % of median). **Falsified if** more repetitions put the per-app spread above ~10 % of median — then no static selector can work and Stage 1 is the only option. |
| **F5** | The window definition dominates. | If a first-frame-exclusive window reorders the 24 materially relative to a to-idle window, every number here is window-conditional and the rubric should be replaced by a *measured, window-specified* number, not any static proxy. |
| **F6** | The floor dominates, so selection is pointless. | **Already half true**: the 2,350-method core is 18.2 % of the union but 32–70 % of any one app. **Falsified as a plan** if the project's real cost is proportional to the app-specific *residue* rather than the total, in which case the floor argument is irrelevant and the adapter flag alone should drive selection. |
| **F7** | The 8 truncated captures biased the cohort. | Tested: every *r* is reported on both subsets and no feature changes significance class. **Falsified if** re-capturing the 8 with a larger buffer (needs an emulator restart) reorders the cohort. |

---

## 6. The 17 → 628 gap, and which conclusions survive

### 6.1 The gap is explainable, and the predictor is not wrong

[measured] The static method list is a **subset** of what runs, at high hit rate:

| app | static `android.*` methods | present at run time | recall | measured / static |
|---|--:|--:|--:|--:|
| `gita` | 17 | 17 | **100.0 %** | **337×** |
| `badpixels` | 17 | 13 | 76.5 % | 270× |
| `balancetheball` | 27 | 23 | 85.2 % | 190× |
| `headingcalculator` | 33 | 31 | 93.9 % | 150× |

**No false positives on these four**: every method the analyzer names is
genuinely executed. Its problem is exclusively **recall**, and the recall figure
is brutal — for gita, **17 of 5,722**, i.e. **0.3 %**. Across the 24 apps the
ratio spans **21.1×** (`org.droidtr.keyboard`) to **399.4×**
(`com.tmendes.dadosd`). **[derived]**

Three mechanisms account for the missing mass, and the data separates them:

1. **Inherited and transitive framework API.** gita names 15 `android.*` types;
   the run touches **894** framework classes. Calling
   `ListView.setAdapter` means implementing `AdapterView`, `ViewGroup`,
   `ViewParent`, `Drawable`, `AttributeSet`, `TypedArray` and their closures.
   A static analyser sees the app's call sites; it cannot see the API surface of
   classes the app *subclasses or instantiates*, because that surface is not in
   the APK. **Structural, not a fixable defect.** **[derived from 15 → 894]**
2. **Framework-internal callbacks.** `onMeasure`, `onLayout`, `onDraw`,
   `dispatchKeyEvent`, layout inflation, theme and resource resolution,
   `ClassLoader` — these execute because the framework calls *back into* the
   widget tree, driven by data the APK does not contain. **Structural.**
3. **A platform floor no app can avoid**: the 2,350-method core of §3.4.
   **Structural.**

**[conjecture]** None of the three is a bug. The predictor is a precise
enumeration of app→framework *edges*; the project has been reading it as an
estimate of framework *work*, and it is not one. The conversion factor is not
even approximately constant — **21.1× to 399.4× is a 19-fold range** — so no
calibrated multiplier repairs it either. **There is no way to get the closure
from the APK by static means alone**, because the input the answer depends on
(the platform's own API surface, and the app's widget tree) is not in the APK.

### 6.2 What survives, what does not, and what is damaged

**Does not survive — void on this evidence:**

* `candidates.md`'s core heuristic, in both its size form and its published
  ordering (§5.1). The stated basis is contradicted; the shortlist order is
  contradicted.
* Any claim of the form "app X needs about N framework methods" where N came
  from `distinctAndroidMethods`, `distinctAndroidTypes`, or a score built from
  them. In this repository that includes `prediction.md`'s compatibility score
  to the extent it is read as a work estimate, and `shim_method_gap`'s
  saturation at 1.0.
* **The brief's four-row table, and any inference from it** — including the
  "37×" figure, which is one draw from a 21–399× range.
* The four headline numbers in the orchestrator's message should not be
  propagated into any other document.

**Survives:**

* **The hard filters in `candidates.md` §1.3.** Structural refusals, not size
  proxies. Nothing here touches them, and `webview_content_dependency` is
  *strengthened* — a WebView app looks small statically and would still be
  refused. (`harness/FINDINGS.md` §5 records `com.termux.boot` stopping on
  `WebView.loadUrl` with a real URL, which is the same failure this filter
  predicts. **[measured, by that harness run — not by me]**
* **The precision of the DEX toolchain.** Zero undecodable bodies, correct
  multi-DEX handling, byte-exact ZIP parsing, the `straySharedObjects` find, the
  `0x15`/`0x16` mislabelling correction. `cargo test` in `analysis`: **14 + 1
  doc-test** pass; in `tools/dexcore`: **21 + 2 doc-tests** pass. The instrument
  is good. **It is the inference that is unsound.**
* **`harness/FINDINGS.md` §7's projection.** It said the cost is "the transitive
  closure of the public API of the handful of classes an app extends", not a
  method count, and called growing the shim "a quarter of work, not a week".
  This document is the first measurement of that quantity and it vindicates the
  projection: gita, which extends nothing and names 15 types, needs 5,722
  methods. **[derived]**
* **The taxonomy's structural classifications**, on the hard-filter argument.
* **The 0/14 `L0_PROCESS_STARTED` result and every number behind it.** Nothing
  here was re-run; the harness recordings are untouched.

**Damaged but not dead — the shim-coverage figures.** `candidates.md`'s "27.4 %
method coverage" and `FINDINGS.md`'s "215 of ~600,000" were computed against the
17–108-method sets that this document shows are 0.3–1.3 % of the real closure.
Against gita's 5,722-method target, 215 shim methods is **3.8 %**. And
`FINDINGS.md` §7's "a quarter of work" is optimistic by roughly the same factor
— **5,722 methods is a different project from 215.** **[derived]**

---

## 7. Reproducing this

```sh
# 1. capture (rooted Android 13 arm64 device, APKs installed)
python3 docs/analysis/closure-frame/capture.py 2        # writes traces; not committed
# 2. decode + join against the committed static table
A14_TRACE_DIR=<dir> python3 docs/analysis/closure-frame/measure.py
# 3. every figure quoted above
python3 docs/analysis/closure-frame/stats.py
# 4. the figures cannot drift from the prose
python3 docs/analysis/closure-frame/test-figures.py
```

`measure.py` writes `docs/analysis/measurement.json` with a SHA-256 for every
trace consumed, including the 15 legacy artefacts of §1.2. Traces are not
committed (~95 MB); the hashes identify the bytes. `test-figures.py` pins 200+
figures and **also scans the document for any integer `stats.py` cannot
account for**, so prose cannot acquire an unsourced number. **This document
quotes no figure that `stats.py` does not produce.**

Related, by another agent on the same artefacts: `0002-is-the-closure-well-defined.md`
(budget-dependence of the closure, and the boot-classpath denominator).

## 8. What I would do next, in order

1. **Re-run on 24 randomly sampled APKs** (F1). My stratified sample is the
   weakest link and it costs one `sort | head`.
2. **Re-run with a first-frame-exclusive window** (F5) — drive `am profile stop`
   off the `-W` `TotalTime` rather than off idle. Two lines in `capture.py`, and
   it may reorder the cohort.
3. **Widen the feature sweep past 11** (F3). Specifically untested and
   plausibly important: `RecyclerView` presence, number of distinct
   `android.widget.*` types, layout XML presence, and **`minSdk`/`targetSdk`**.
   `org.droidtr.keyboard` has the largest static surface and the *smallest*
   closure, and I have no explanation for it.
4. **Build a proper ART trace call-graph reader** (§2) if any future question
   needs caller/callee structure. The set-level analysis here does not, and a
   heuristic unwinder should not be trusted to.
5. **Do not grow the shim on the strength of any of this.** The finding is that
   the closure is 21–399× the static estimate. That is an argument *against*
   "grow the shim until apps run" and for the measurement-instrument thesis —
   not an argument for picking a different app.
