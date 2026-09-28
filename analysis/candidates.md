# Candidate selection: the first APK andro-substrate will execute

**Status:** a decision, with the measurement behind it. No APK has been run.

Nothing in this repository has ever executed a real Android APK. The shim
covers 144 framework classes and 334 methods; measured against the six F-Droid
fixtures in `shim/CONFORMANCE.md` that is **100% type coverage and 27.4% method
coverage** of what real apps call, and well under 0.5% of the declared platform.
The first subject therefore has to need as little framework surface as
possible — and it has to *draw something*, because the pre-registered dependent
variable is `L2_FIRST_FRAME_DRAWN` (`docs/research-protocol.md` §4.1) and an app
with no UI cannot produce an L2 observation at all.

**Recommendation: [`eu.quelltext.gita`](https://f-droid.org/packages/eu.quelltext.gita/) 6.**

| | |
|---|---|
| APK | `eu.quelltext.gita_6.apk`, 895,225 bytes |
| SHA-256 | `1dc68f1ff0bff92408dc8b472c2afafec2f45cabb269a0a10cb4222d34b8d8cb` |
| DEX | 1 file, 24,897 compressed bytes, 43 methods, 19 classes |
| Manifest | 1 launcher `Activity`, 2 `Activity`, 0 `Service`/`Receiver`/`Provider`, **0 permissions** |
| Framework surface | 15 `android.*` types, 17 `android.*` methods; shim has 9 / 7 |
| Renders via | `setContentView(I)` ×2, `LayoutInflater.inflate` ×2 |
| Clickable via | `ListView.setOnItemClickListener` ×2 |
| Taxonomy | 3 IDs, **0 REFUSE-class** |
| Score | 0.5130 (penalty, lower is better) |

The single strongest reason to choose it over the runner-up
([`tk.al54.dev.badpixels`](https://f-droid.org/packages/tk.al54.dev.badpixels/),
0.5409): **the shim already implements 7 of its 17 framework methods against 3
of badpixels' 17, and all 10 of gita's missing methods are ordinary
view-toolkit members — nine of them are the one `ListView`/`Adapter` family the
shim lacks wholesale.** badpixels' 14 missing methods are scattered across
`GestureDetector`, `MotionEvent`, `Menu`/`MenuInflater`/`MenuItem` and the
`OnClick`/`OnTouch` listener interfaces, so its gap is four unrelated families
rather than one. gita is one afternoon of shim work; badpixels is four.

---

## 1. The ranking rule, so someone else can re-derive it

Three stages. Only the middle one touches the network.

| stage | input | output | pure? |
|---|---|---|---|
| 1 `pool` | `corpus/survey.jsonl` | the rows passing the census-derivable filters | yes |
| 2 `measure` | the pool | `candidates/measured.jsonl` — one row per downloaded APK | no |
| 3 `rank` | survey + `measured.jsonl` | the ranked shortlist | yes |

Stage 2 is separate because it is the only stage that needs the network and the
only one whose output is an artefact rather than a decision. Its output is
committed, like `analysis/sample/rows.jsonl` is, so **stage 3 re-runs offline**,
and every number below is re-derivable from two committed files plus one
script. Stage 3 **refuses to run** if a pool row has no measured row
(`refusing to rank`, exit 3) rather than quietly ranking on less evidence.

```sh
node analysis/select-candidates.mjs pool       # stage 1, offline
node analysis/select-candidates.mjs measure    # stage 2, downloads 200 APKs
node analysis/select-candidates.mjs rank --top 12 --explain
node analysis/select-candidates.mjs rank --without shim_method_gap   # counterfactual
node analysis/select-candidates.mjs verify /tmp/…/eu.quelltext.gita_6.apk
```

**No seed, because nothing is random.** The pool is a total order on
`(dexBytes, packageName, versionCode)`; the shortlist is a total order on
`(score, distinctAndroidTypes, distinctAndroidMethods, dexBytes, packageName,
versionCode)`. `packageName` is last precisely so the sort can never tie. Every
component is `min(1, count / saturation)` and every weight is printed by
`--explain` and pinned by `analysis/tests/`.

### 1.1 Stage 1 — the pool: 4,475 rows in, 213 out

Filters, all on `survey.jsonl`'s own fields. Reasons are counted separately
because a row can trip several.

| rejection reason | rows |
|---|---:|
| `dex_over_cap` (> 128 KiB compressed DEX) | 4,167 |
| `has_native_lib` | 2,472 |
| `native_library_count` | 2,472 |
| `apk_over_cap` (> 8 MiB) | 1,955 |
| `stray_shared_object` | 6 |
| `no_dex` | 2 |
| `manifest_unparsed` | 1 |
| `no_min_sdk` | 1 |
| `no_resources_arsc` | 1 |
| **pass** | **213** |

The 200 measured are the 213 sorted by `(dexBytes, packageName, versionCode)` and
cut at 200, so `LUBITS.poolSize`. Total fetch: 74,734,923 bytes, largest DEX in
the set 94,613 bytes.

Two size caps are **stated, not measured**, and they come from
`docs/research-protocol.md` §3.5 ("the APK exceeds a size that makes installation
exceed the boot-timeout"). They are caps a reader can disagree with; nothing
downstream depends on the exact values.

### 1.2 Stage 1 → 2 boundary: the census's `hasNativeCode` is not sufficient

`hasNativeCode` is the census's `lib/<abi>/` test. It is a *necessary* filter and
not a sufficient one, which `corpus/report.md` already says; here it is a
specific, findable failure.

Six corpus rows ship a `.so` outside `lib/`. Five are already excluded by
`hasNativeCode` (Chaquopy runtimes, bundled `llama.cpp`). **One is not:**

```
org.bitbucket.watashi564.combapp
  survey.jsonl:  hasNativeCode = false,  nativeLibraryCount = 0     <- "no native code"
  real bytes:    res/5x.so   7,321,429 B decompressed, ELF
                 res/yG.so  17,821,874 B decompressed, ELF
```

A reader who took `hasNativeCode` at its word would ship this app. The fix is
one field: `straySharedObjects`, which the census already populates. The
`analysis/tests/figures.rs` test re-asserts exactly this, and the
`combapp` APK is downloaded, measured and kept in
`candidates/negatives.jsonl` so the case is a measurement rather than an assertion.

### 1.3 Stage 2 — the archive-level hard filters

All of these need the bytes, so they cannot live in stage 1.

| gate | fires on | pool rows rejected |
|---|---|---:|
| `declares_service` | any `<service>` | 87 |
| `declares_receiver` | any `<receiver>` | 79 |
| `text_field_on_launch_path` | references an `EditText`/IME type, or hits `SUB.INPUT.IME` | 73 |
| `no_launcher_activity` | no `MAIN`+`LAUNCHER` filter | 46 |
| `layout_onclick_reflective_dispatch` | any `android:onClick` in any layout | 45 |
| `webview_content_dependency` | taxonomy hit `SUB.FW.WEBVIEW` | 34 |
| `no_render_call_site` | no `setContentView`/`inflate`/`Canvas.draw*` call site | 29 |
| `declares_provider` | any `<provider>` | 26 |
| `special_permission:…WAKE_LOCK` | declares `android.permission.WAKE_LOCK` | 13 |
| `special_permission:…SYSTEM_ALERT_WINDOW` | declares `SYSTEM_ALERT_WINDOW` | 7 |
| `so_entry_anywhere` | a `*.so` entry at any path | 0 |
| `elf_payload_anywhere` | an entry beginning `\x7fELF` at any path | 0 |
| `lib_entry` | a `lib/<abi>/` entry | 0 |
| `native_method_declared` | a method with the `native` modifier | 0 |
| `native_method_unimplemented` | `native` with no `lib/` sibling and no bound `loadLibrary` | 0 |
| `load_library_call_site` | a `System.loadLibrary`/`load` call site | 0 |
| `play_services` | an external `com.google.android.gms.*` class | 0 |
| `play_integrity_api`, `licensing`, `integrity_literal`, `drm_literal` | as named | 0 |
| `invoke_polymorphic`, `invoke_custom`, `const_method_handle` | a decoded call site | 0 |
| `dynamic_code_loader` | an external `DexClassLoader`-family class | 0 |
| `unanalysable_dex` | the APK or a DEX did not parse | 0 |

**200 measured, 181 rejected, 19 eligible.** Total gate hits 439; a row trips
several. The ten zeros are the brief's hard filters 2, 3 and 4, established by
measurement rather than assumed, and `analysis/tests/figures.rs` pins each of
them to zero.

Three of those zeros are worth pausing on:

* **`invoke-polymorphic` / `invoke-custom`: 0/200.** This is the corrected
  figure. `analysis/prediction.md` §4.1 still reports 68.3% / 67.5%, which is
  **stale** — `analysis/src/dexscan.rs` documents the mislabelling that produced
  it (`0x15`/`0x16` are `const/high16`/`const-wide/16`, not
  `const-method-handle`/`const-method-type`) and gives the true values as 0.0%
  and **1.7%**, with 0/60 in the DEX-only stratum. The code is fixed; the
  document was not updated. Had this selection trusted §4.1, hard filter 4
  would have rejected 199 of the 200 and left nothing to choose.
* **Play Services / Integrity / licensing: 0/200**, as `prediction.md` §4.1
  already reports for its own sample. F-Droid's build recipes remove GMS
  dependencies, so the gate the pre-registration expects to dominate has never
  fired. Per the protocol these are *excluded from scoring* rather than counted
  as failures, which is why they are gates and not components.
* **No undecodable method bodies in 200/200 single-or-multi-DEX APKs**, and every
  APK's byte size matches the F-Droid index. The analyzer's 99.866% instruction
  coverage claim holds on a different 200.

### 1.4 The ranking rubric

`score = Σ weight · min(1, count / saturation)`, a **penalty**: lower is better.
The sign is the opposite of `prediction.md`'s compatibility score on purpose —
that rubric predicts *incompatibility*, this one picks a *subject*.

| id | weight | saturation | count |
|---|---:|---:|---|
| `android_types` | 0.28 | 24 | distinct `android.*` types referenced |
| `android_methods` | 0.22 | 60 | distinct `android.*` methods referenced |
| `taxonomy` | 0.14 | 3 | Σ class-weight over distinct taxonomy IDs hit |
| `shim_method_gap` | 0.15 | 1 | fraction of framework methods with no same-named shim method |
| `dex_bytes` | 0.07 | 65,536 | compressed DEX bytes |
| `dex_methods` | 0.04 | 400 | methods declared in the DEX |
| `clickable_view` | 0.07 | 2 | decoded click-handler call sites |
| `reflection` | 0.02 | 8 | decoded reflective call sites |
| `components` | 0.01 | 8 | manifest components declared |

Weights sum to 1.000000. Taxonomy class weights: `REFUSE` 1.0,
`MISBEHAVE` 0.6, `DEGRADE` 0.3, and a multi-class cell scores as its worst
class.

**Two components are mine, not the brief's, and both are disclosed:**

* `shim_method_gap`. The number of framework methods an app touches and the
  number of those the shim implements are different questions, and only the
  second one predicts how much work the first run costs. It is load-bearing:
  `S.N.A.K.E` has the *fewest* distinct `android.*` types of any candidate
  (14) and ranks **5th**, because 34 of its 40 framework methods have no
  same-named shim method.
* `clickable_view`. Added **after** the first run, which is exactly the post-hoc
  adjustment T-09 warns about. It is included because the brief asks for "an app
  with a layout and a clickable view", and it *does* change the answer, so the
  ranking without it is published in §3.

### 1.5 Launch-path gates, and why each exists

Four gates exist because a candidate put something between `onCreate` and the
first frame that the substrate either cannot do or does silently — and in every
case the obvious DEX signals said the app was clean. Each is hand-verified
against the real bytes; each is a consequence of the frozen taxonomy, not a
preference.

1. **`webview_content_dependency`** — `SUB.FW.WEBVIEW` is `REFUSE`: "hybrid
   apps lose their entire UI". `org.asafonov.blockbuster` ranked **2nd** before
   this gate existed, with only 6 distinct `android.*` types, because it
   outsources its entire UI to
   `WebView.loadUrl("file:///android_asset/index.html")` and touches almost no
   framework itself. That is the failure mode of any surface-size metric: an app
   that delegates its work to a component the substrate lacks looks *small*.
   Deliberately **not** a general "no REFUSE-class hit" gate: 63 of the then-75
   eligible apps tripped at least one, most often `SUB.INPUT.INPUT_EVENT` — which
   is `REFUSE` for pointer input, but the protocol's automated cold launch sends
   none (§4.4, `lifecycle.first_input_delivered`, "normally unobserved").
   Gating on it would exclude a third of the pool for a risk that cannot occur.
2. **`text_field_on_launch_path`** — keyed on the *observable* (a referenced
   `EditText`/IME type), not on the taxonomy ID. The taxonomy ties the refusal to
   *having* a text field, not to calling `InputMethodManager`: `SUB.INPUT.IME` is
   "every app with a text field is unusable" and `SUB.IPC.WINDOW_MANAGER` is
   "REFUSE (for any app with a text field)" — "usually the first visible break".
   Keying on the ID was tried first and is **wrong**: `dudeofx.eval`, whose
   layout is `LinearLayout > ListView + LinearLayout > EditText[requestFocus]`,
   has no `SUB.INPUT.IME` hit and sailed through.
3. **`layout_onclick_reflective_dispatch`** — `android:onClick` is resolved by
   the *framework*: `LayoutInflater` wraps the view in a `DeclaredOnClickListener`
   that calls `getMethod(name)` on the context's class at dispatch time. So an
   app that binds its buttons that way has **zero** reflective call sites in its
   own DEX and still needs a reflective member lookup implemented. This gate is
   why layouts are parsed, which is otherwise the one thing the predictor
   explicitly does not do. `com.tmendes.dadosd` reports
   `reflection_call_sites = 0` and binds three of them.
4. **`special_permission:…`** — `docs/research-protocol.md` §3.5 already excludes
   "a launcher/keyboard (requires a role we do not grant)"; an app needing a
   user-granted overlay or wake-lock permission is the same category.
   `org.vi_server.red_screen` declares `SYSTEM_ALERT_WINDOW` and spends its whole
   `onCreate` on `WindowManager$LayoutParams` (forced `screenBrightness`,
   `type = 2010` = `TYPE_SYSTEM_ERROR`) plus a `PowerManager` wake lock.

---

## 2. The shortlist

`aTypes`/`aMeth` are distinct `android.*` types/methods referenced. `shimM` is
how many of those methods the shim implements. Full SHA-256s are in
`analysis/tests/selection.test.mjs`.

| # | package | ver | SHA-256 (16) | DEX B | meths | aTypes | aMeth | shimM | click | refl | cmp | tax | score |
|--:|---|--:|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| 1 | `eu.quelltext.gita` | 6 | `1dc68f1ff0bff924` | 24,897 | 43 | 15 | 17 | 7 | 2 | 0 | 2 | 3 | **0.5130** |
| 2 | `tk.al54.dev.badpixels` | 4 | `43842c079c9f8cde` | 3,681 | 22 | 15 | 17 | 3 | 2 | 0 | 1 | 3 | 0.5409 |
| 3 | `com.jeffliu.balancetheball` | 4 | `6180534b151e4d50` | 4,671 | 30 | 17 | 27 | 8 | 0 | 0 | 1 | 6 | 0.5521 |
| 4 | `org.debian.eugen.headingcalculator` | 4 | `dbcfc1903051b66e` | 7,761 | 54 | 16 | 33 | 14 | 1 | 2 | 1 | 4 | 0.5610 |
| 5 | `S.N.A.K.E` | 1000001 | `d8b3db6f912c67be` | 3,025 | **9** | **14** | 40 | 6 | 0 | 0 | 1 | 5 | 0.5735 |
| 6 | `us.spotco.extirpater` | 35 | `ba8dcd0566affda6` | 8,268 | 51 | 19 | 38 | 10 | 1 | 0 | 1 | 4 | 0.6197 |
| 7 | `ru.henridellal.fsassist` | 5 | `e5525642c146806c` | 16,248 | 132 | 30 | 37 | 11 | 3 | 0 | 5 | 5 | 0.7679 |
| 8 | `com.github.rsteube.t4` | 4 | `f76b18eeef2df33a` | 14,737 | 195 | 25 | 41 | 15 | 2 | 2 | 1 | 5 | 0.7769 |
| 9 | `anupam.acrylic` | 19 | `df01309e3641fac7` | 24,041 | 198 | 132 | 210 | 37 | 0 | 0 | 4 | 8 | 0.8140 |
| 10 | `io.github.ebraminio.bouncy` | 1 | `a509db2afda544f6` | 7,882 | 48 | 32 | 66 | 11 | 1 | 0 | 1 | 7 | 0.8145 |
| 11 | `com.biotstoiq.hayago` | 21 | `c7f8e8b03ff8f99e` | 13,948 | 128 | 28 | 60 | 11 | 16 | 0 | 2 | 4 | 0.8534 |
| 12 | `com.dozingcatsoftware.dodge` | 10 | `a5687d1bad7b2927` | 23,411 | 224 | 49 | 95 | 23 | 7 | 1 | 3 | 12 | 0.8773 |

Ranks 13–19: `com.quaap.dodatheexploda` 0.8827,
`cz.jirkovsky.lukas.chmupocasi` 0.8853, `de.tcrass.minos` 0.8874,
`com.quaap.fishberserker` 0.8914, `org.billthefarmer.scope` 0.8923,
`com.smorgasbork.hotdeath` 0.9069, `org.billthefarmer.tuner` 0.9139.

### 2.1 Counterfactuals — what each of my components is worth

| ranking | #1 | #2 | #3 |
|---|---|---|---|
| as published | `eu.quelltext.gita` | `tk.al54.dev.badpixels` | `com.jeffliu.balancetheball` |
| without `shim_method_gap` | `tk.al54.dev.badpixels` | `eu.quelltext.gita` | `S.N.A.K.E` |
| without `clickable_view` | `eu.quelltext.gita` | `tk.al54.dev.badpixels` | `org.debian.eugen.headingcalculator` |
| without `taxonomy` | `com.jeffliu.balancetheball` | `eu.quelltext.gita` | `tk.al54.dev.badpixels` |

`eu.quelltext.gita` is first or second under every counterfactual, which is the
only reason I am willing to recommend a component I added after seeing the data.
Reproduce any cell with `rank --without <id>`.

---

## 3. Hand-verification

Every hard filter in §1.3 was checked against the real bytes, not against the
census. Three independent tools were used so no single parser is load-bearing:
this repository's `zip.rs`/`axml.mjs`, the Rust predictor
(`analysis/target/release/predict`), and `androguard` 4.1.4.

### 3.1 What the predictor's filters missed

| candidate | passed | actually | root cause |
|---|---|---|---|
| `org.bitbucket.watashi564.combapp` | `hasNativeCode == false` | 2 real ELF binaries at `res/5x.so`, `res/yG.so` | the census's `hasNativeCode` is a `lib/<abi>/` test; a payload at any other path is invisible to it |
| `org.asafonov.blockbuster` | 6 `android.*` types, 2nd by score | whole UI is `WebView`; `SUB.FW.WEBVIEW` = `REFUSE` | a surface-size metric rewards an app for outsourcing its work to a component the substrate lacks |
| `com.tmendes.dadosd` | `reflection_call_sites = 0` | 3 `android:onClick` bindings, i.e. framework-side reflection | the app's DEX cannot see reflection the *framework* performs on its behalf |
| `dudeofx.eval` | no `SUB.INPUT.IME` hit | `EditText[requestFocus]` — the first thing it does is summon a keyboard | the taxonomy ties the refusal to *having* a text field; the rule table only maps `InputMethodManager` |
| `org.vi_server.red_screen` | 9 types, 13 methods, **1st by score** | `TYPE_SYSTEM_ERROR` window, forced brightness, wake lock, `SYSTEM_ALERT_WINDOW` | small surface because it delegates the window to the system; the score cannot see that |

The first is a census false negative. The other four are false negatives of the
*predictor's* signals, and each is now a gate. **A false negative in the
predictor is a finding, and all five are written down here rather than
absorbed into the rule silently.**

### 3.2 Candidates that failed the archive-level check despite passing the census filter

**None of the 200.** Every pool APK measured clean on `.so` anywhere, ELF
anywhere, `lib/<abi>/`, `native` declarations, `loadLibrary` call sites, GMS,
Play Integrity, licensing/DRM, `invoke-polymorphic`/`invoke-custom`, dynamic
class loaders, and DEX analysability. That is a real result about this stratum,
and it is *not* a result about the corpus: the census's own 2,003 DEX-only apps
include `combapp`.

The 181 rejections are all manifest, launch-path, or renderability failures. By
far the biggest are background lifecycle: 87 declare a `Service`, 79 a
`receiver`, 26 a `provider`. Hard filter 7's premise — "background lifecycle is a
large surface cost for no benefit here" — is the single most productive
criterion in the whole exercise: 87 of 181 rejections, 48% of them, for free.

### 3.3 Independent cross-check of the manifest parser

`analysis/lib/axml.mjs` is a hand-written AXML reader, so it was checked against
`androguard` — a different implementation — over **200 APKs × 9 manifest fields
= 1,800 comparisons: 0 disagreements.** Fields: `activity`, `service`,
`receiver`, `provider`, `minSdk`, `targetSdk`, `package`, `permissions`,
`launchers`.

The shim surface parse (`analysis/lib/shim-surface.mjs`) reads
`shim/src/registry.rs` as text rather than linking the shim, and is pinned to the
144 / 334 / 55 that `shim/CONFORMANCE.md` publishes. It was additionally diffed
against a Rust dump of `registry::CLASSES` built from the real table: **144/144
classes, 0 method-set disagreements, 0 field-set disagreements.**

---

## 4. The framework surface the top 3 will need

The shim declares 144 classes and 334 methods. Per candidate:

### 4.1 `eu.quelltext.gita` — 15 types, 17 methods, 7 covered

Six classes are missing from the shim, and five of them are one family:

```
Landroid/widget/ListView;                  Landroid/widget/ArrayAdapter;
Landroid/widget/AdapterView;               Landroid/widget/ListAdapter;
Landroid/widget/AdapterView$OnItemClickListener;   Landroid/annotation/SuppressLint;
```

Ten methods are missing, all `android.widget`/`android.view`/`android.content`:

```
View;.findViewById              ListView;.setAdapter        ListView;.getItemAtPosition
LayoutInflater;.inflate         ListView;.setOnItemClickListener
ArrayAdapter;.<init>           Context;.getResources       Context;.startActivity
Intent;.getIntExtra             Intent;.putExtra
```

**Estimate: ~5 classes, ~10 methods, all in the ordinary view toolkit.** No
hardware, no sensors, no media, no window management, no network, no permissions.
Five of the ten are already implemented on a *different* class — the shim has
`Activity.findViewById`, `Activity.getWindow`, `LayoutInflater` — and the
name-level coverage reading is 10/17 rather than 7/17, so the conservative
figure understates what exists. `SuppressLint` is an annotation, i.e. zero
runtime surface.

### 4.2 `tk.al54.dev.badpixels` — 15 types, 17 methods, 3 covered

Nine classes missing, in **four** unrelated families: `GestureDetector`,
`GestureDetector$OnGestureListener`, `GestureDetector$SimpleOnGestureListener`,
`MotionEvent`, `Menu`, `MenuInflater`, `MenuItem`, `View$OnClickListener`,
`View$OnTouchListener`. Fourteen methods missing, of which the first-frame path
is `FrameLayout.setBackgroundColor` and `FrameLayout.setOnClickListener`.

**Estimate: ~9 classes, ~14 methods, across gesture, motion, menu and listener
families.** Trips `SUB.INPUT.INPUT_EVENT` (`REFUSE`) — harmless for a no-input
launch, but the app's *content* is a colour that changes on a fling, so a
first-frame capture shows a colour and nothing else.

### 4.3 `com.jeffliu.balancetheball` — 17 types, 27 methods, 8 covered

Twelve classes missing including the entire drawing stack
(`Canvas`, `Paint`, `Paint$Style`), the sensor stack (`SensorManager`, `Sensor`,
`SensorEvent`, `SensorEventListener`), and `MediaPlayer`. Nineteen methods
missing. Trips **three** `REFUSE`-class IDs: `SUB.GFX.SURFACE`, `SUB.HW.SENSORS`,
`SUB.INPUT.INPUT_EVENT`.

**Estimate: ~12 classes, ~19 methods, including two hardware families the
substrate has no answer for.** It is the only top-3 candidate whose value
depends on a sensor.

---

## 5. Threats to this selection

1. **Ranking is an opinion with a number attached.** The weights sum to 1 and
   are printed, and §2.1 publishes the counterfactuals, but nothing validates
   them. They encode "small framework surface first", which is defensible and
   unmeasured.
2. **Two components were added after seeing the data.** Disclosed in §1.4 and
   §2.1. `clickable_view` moves #1↔#2; `shim_method_gap` moves #1↔#2 and lifts
   `S.N.A.K.E` into #3.
3. **`android.* method references` is a reference-level signal, not call sites.**
   R8 keeps entries it cannot prove dead. `S.N.A.K.E` declares 9 methods and
   references 40 framework methods; the excess is overrides and dead entries.
4. **`distinctAndroidMethods` understates the surface, systematically.** It
   counts only `Landroid/`-owned references, so an inherited framework method
   called through an app's own subclass is invisible. gita calls **six**
   inherited framework members that way (`setContentView`, `findViewById`,
   `getIntent`, `getSystemService`, `getStringResourceByName`, `getTitle`); five
   are shim-implemented. `dex.appOwnedCallSiteMembers` records the full list and
   is pinned by a test, but separating framework members from the app's own
   needs the DEX class hierarchy, which nothing here reads. For gita this makes
   the reported surface *smaller* than the truth by 6 methods.
5. **The shim-coverage figure is a lower bound by name.** A shim method with the
   right name and wrong parameters counts as coverage here.
   `shim/tests/conformance.rs` is the authority on signatures.
6. **`res/layout/` cannot be used to decide "has a layout".** Resource-name
   obfuscation relocates layouts: `org.vi_server.red_screen`'s only layout is
   `res/01.xml`, and `headingcalculator`'s are `res/Oh.xml`, `res/Qc.xml` and
   `res/gm.xml`. Every render signal here is a call site instead.
7. **The pool is the 200 smallest of 213, not a sample of F-Droid.** 13 apps
   were not measured. `LIMITS.poolSize` is a stated choice, and a small one
   biases hard: the top candidate has the **largest** DEX of the top 12, so a
   tighter cut would have excluded the recommendation.
8. **A candidate that is merely *survivable* is not a candidate that will
   succeed.** 19 of 200 apps clear the gates; the shortlist says which are
   cheapest, not which will reach L2. `S.N.A.K.E` is 5th partly because 34 of its
   40 framework methods are unimplemented, which is a prediction about effort,
   not about outcome.

---

## 6. Reproducing this

```sh
cd analysis
cargo build --release
node select-candidates.mjs pool
node select-candidates.mjs measure \
  --extra org.bitbucket.watashi564.combapp,se.leap.riseupvpn,sh.haven.app,com.econverter.app
node select-candidates.mjs rank --top 12 --explain
node --test 'tests/*.test.mjs'      # 58 tests
cargo test                          # 55 unit + 14 pipeline + 7 figures + 1 doc
```

No APK is committed. The cache is `/tmp/andro-substrate-candidates`, outside the
repository; `corpus/apks/` is gitignored and unused here. `measured.jsonl`
(4.5 MB) and `negatives.jsonl` (800 KB) are derived rows, each carrying the
SHA-256 of the APK it came from, and each APK's byte size is checked against the
F-Droid index before it is trusted.

The per-reference lists inside a row are capped at 1,024 entries, which is above
the pool's maximum (586 framework methods, `cn.rbc.termuc`) and below all four
negatives (2,821–6,906). The **counts** are always exact; a test asserts that no
pool row is truncated, so no figure in this document rests on a shortened list.
Stored lists are in code-unit order, not `localeCompare` order, so the committed
file's bytes do not depend on the machine that produced it — `amirz.dngprocessor`
is what caught that.

**Every figure in this document is pinned.** `analysis/tests/figures.rs` re-derives
the gate histogram in Rust — an independent implementation of the same rules,
which is how a 70-vs-73 discrepancy in the `text_field_on_launch_path` list was
caught — and asserts the ten zero rows, the pool size, the top-10 table, and every
SHA-256. `analysis/tests/selection.test.mjs` asserts determinism (including
order-independence under four shuffles), the top-10 table, the known-good
candidate, five known-bad candidates, and every number quoted here. Prose that
drifts from the measurement is a failing test.
