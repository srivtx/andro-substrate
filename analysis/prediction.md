# The static substrate-dependency predictor: rubric, measurement, and what it cannot know

**Status:** a measurement, and a *hypothesis* about prediction. The signal
counts below are results. The rubric weights are an opinion. Nothing here has
been validated against observed behaviour, because there is nothing yet to
validate against, and §7 says exactly what that costs.

Companion files:

| file | what it is |
|---|---|
| `analysis/src/` | the analyzer (`substrate-predictor`) |
| `analysis/run-sample.mjs` | the deterministic sample driver that produced every number here |
| `analysis/sample/rows.jsonl` | one row per analysed APK, with the evidence behind every count |
| `analysis/sample/summary.json` | the aggregates, machine-readable |
| `analysis/validation-set/labels.json` | 20 hand labels, six features, SHA-256s |
| `analysis/validate-prediction.mjs` | the correlation harness, in its honest not-validatable state |
| `docs/divergence/0004-static-predictor.md` | the ADR tying these outputs to taxonomy IDs |

---

## 1. What is being predicted, precisely

The prediction is **not** "will this app run". It is:

> **Does the APK structurally require a capability that a browser-native
> substrate with no Android underneath does not have?**

That is a strictly weaker and strictly more measurable claim, and the difference
matters: an app can be structurally dependent on something it only touches on a
code path this analysis cannot see, and an app can be structurally dependent on
nothing and still fail because its server rejects its request. The taxonomy's
§17.3 table of MISBEHAVE entries exists precisely because "the app starts" and
"the app worked" are different claims.

Everything the analyzer emits is a **static fact about the APK**, at one of three
strengths, kept in separate fields so they cannot be confused:

| strength | meaning | where |
|---|---|---|
| **reference** | a `method_id` / `field_id` / `type_id` / `string_id` entry exists | `dexscan's` pool pass |
| **declaration** | the APK defines a class or member with this shape | class pass |
| **call site** | an instruction in a concrete method body targets it | instruction walk |

A `method_id` entry is *not* proof of a call. R8 keeps entries it could not
prove dead. Every count derived from a reference is named `*_refs` and says so.

---

## 2. The sample

Selection is a **stride over the corpus**, stratified, not random and not chosen
by looking at the analyzer's output:

```
population:  corpus/survey.jsonl, the 4,475 rows with ok === true
order:       ascending (packageName, versionCode)
eligibility: indexSize <= 125,829,120 bytes  (120 MiB)
strata:      corpus hasNativeCode === true  -> 60
             corpus hasNativeCode === false -> 60
selection:   take every k-th row of each stratum, k = |stratum| / 60
```

The stratification is not cosmetic. F-Droid is ~55% native by the corpus's own
census, so a uniform sample would be dominated by apps already disqualified by
`corpus/report.md`; the project's actual question is about the DEX-only subset.
Both strata are reported separately, with their own denominators, everywhere.

**`corpus/survey.jsonl` and `tools/corpus/` were read and not modified.** The 120
APKs were fetched from `https://f-droid.org/repo/` and are not committed.

Denominators, stated once and used everywhere:

```
chosen                    120
analysable                120     (0 unanalysable, 0 fetch failures)
DEX-only stratum           60
native stratum             60
```

Instruction coverage over the whole sample:

```
methods with a code_item read   4,196,811
fully decoded                   4,191,199   (99.866%)
undecodable (whole method lost)         0   (0.000%)
truncated tail (no loss)        5,612       (0.134%)
try table unparsed              10,206      (0.243%)
apps with any undecodable method  0 / 120
```

`methods_undecodable = 0` is a result, and it took work to get. Two real causes
were found and handled, both documented at the code:

* **R8 unreachable filler.** `Landroidx/core/graphics/drawable/IconCompat;.f` in
  `com.katiearose.sobriety` ends with 20 code units of `0x0009 0x0000 0x002d …`
  after its `return-void`, which is not a decodable instruction stream and is
  never executed. Walking into it produced a spurious "opcode 0x09 needs 3 code
  units, only 2 remain" and lost the method. Detected by comparing the opcode's
  declared width against the units that remain, and counted separately as
  `methods_truncated_tail` so the "lost" count stays meaningful.
* **Unparseable try tables.** `DexReader::code_item` fails for 10,206 methods
  because its `encoded_catch_handler_list` scan rejects the handler list. The
  instruction stream is at a fixed offset after the 16-byte header and is
  unaffected, so it is read directly. Those methods' *handlers* are not read;
  nothing in this analyzer reads handlers.

The tempting wrong fix, recorded because it was tried and measured: stopping the
linear walk at the first `return*`. A `return` terminates its **basic block**,
not the instruction stream — method bodies are laid out with several blocks in
arbitrary order. Stopping there dropped `invoke-polymorphic` from 82/120 apps to
64/120 and `invoke-custom` from 81/120 to 47/120. A 22-point swing in a headline
number, all of it loss. The walk runs the whole stream.

---

## 3. The rubric, every weight

Ten components. The weights sum to exactly 1.000 (asserted in `src/score.rs`
and re-asserted in `tests/pipeline.rs`). Each is a saturating count,
`subscore = min(1, evidence_count / saturation)`, and the total is
`Σ weight · subscore` over the components that did not gate.

| id | weight | saturation | what it measures | evidence accessor |
|---|---:|---:|---|---|
| `native_payload` | 0.22 | 1 | `lib/<abi>/*.so` entry, ELF under `assets/`, or a `loadLibrary`/`load` call site | `native.lib_entries + asset_native_payloads + load_library_calls` |
| `dynamic_invoke` | 0.18 | 1 | `invoke-polymorphic`, `invoke-custom` or `const-method-handle` decoded in a method body | `invoke.invoke_polymorphic + invoke.invoke_custom` |
| `play_services` | 0.15 | 1 | an external `com.google.android.gms.*` class | `trust.play_services_classes` |
| `native_methods` | 0.12 | 4 | a method declared `native` | `native.native_declarations` |
| `integrity_attestation` | 0.10 | 1 | Play Integrity / SafetyNet / licensing / DRM classes or constants | `trust.play_integrity_api_classes + integrity_literals + drm_literals + licensing_classes` |
| `build_identity` | 0.09 | 4 | instruction-level reads of `android.os.Build` identity fields | `build.total_reads` |
| `reflection_surface` | 0.06 | 8 | decoded reflective call sites | `code.reflection_call_site_total` |
| `dynamic_code` | 0.05 | 1 | external `DexClassLoader`-family classes | `code.dynamic_code_classes` |
| `kernel_fs_literals` | 0.02 | 8 | string constants naming `/proc`, `/sys`, `/dev` nodes, `/system` partitions, `/data/data`, SELinux contexts | `paths.tag_counts` (path tags only) |
| `hardware_surface` | 0.01 | 4 | referenced members in taxonomy family `SUB.HW`, plus `SUB.GFX.CAMERA_PIPE` | `taxonomy_hits` filtered by family |

### 3.1 Hard walls are gates, not weights

Four components additionally fire a **gate**, which sets the band to `REFUSE`
regardless of the score:

| gate | fires on | taxonomy IDs |
|---|---|---|
| `NATIVE_PAYLOAD` | any `lib/<abi>/*.so`, any ELF under `assets/`, or any `loadLibrary` call site | `SUB.NATIVE.LOAD_LIBRARY`, `SUB.FS.LIB_PATH`, `SUB.NATIVE.JNI_ENTRY` |
| `DYNAMIC_INVOKE` | any decoded `invoke-polymorphic`, `invoke-custom` or `const-method-handle` | `SUB.FW.INVOKEDYNAMIC` |
| `PLAY_SERVICES` | any external `com.google.android.gms.*` class | `SUB.TRUST.PLAY_SERVICES` |
| `NATIVE_METHOD_UNIMPLEMENTED` | a `native` declaration with no `lib/` sibling and no matching `loadLibrary` argument | `SUB.NATIVE.JNI_ENTRY` |

An app shipping a `.so` is not "mostly incompatible"; it is out of scope for a
bytecode-only substrate, which is the argument `corpus/report.md` already makes
and which a weighted average would obscure. So a gated app's score is reported
*beside* the prediction, as a description of how much else is also unmet, not as
the prediction. Two totals are emitted for exactly this reason:
`score_0_100` (over ungated weight) and `score_rescaled_0_100` (gated weight
redistributed).

`NATIVE_METHOD_UNIMPLEMENTED` is a name-based heuristic and is a **lower
bound**: a real JNI implementation lives inside a `.so` under an unpredictable
name, so an app with no `lib/` entry and no matching `loadLibrary` argument
*may* still resolve — from a library another DEX file loads, or from a payload
the analyzer did not sniff. The field is a list of suspects, not a verdict.

### 3.2 Bands

| band | condition | meaning |
|---|---|---|
| `REFUSE` | any gate fired | prediction: the app will not run |
| `DEGRADE` | no gate, `score_0_100` in [40, 70) | prediction: the app starts and something is missing |
| `LIKELY_RUNS` | no gate, score in [20, 40) | prediction: the app runs with no specific capability loss |
| `MINIMAL` | no gate, score < 20 | the app uses very little the substrate must fake |
| `UNKNOWN` | the APK or a DEX did not parse | never a score, never `MINIMAL` |

### 3.3 What is deliberately *not* in the score

* **`resources.arsc`.** Not parsed (out of scope, and dexcore does not).
  `SUB.RES.ARSC` is neither scored nor claimed, and it is arguably the single
  largest unmeasured source of divergence. A substrate that fabricates resources
  by ID alone produces silent wrong-resource bugs, which the taxonomy lists as
  MISBEHAVE and which no static score can see.
* **`targetSdk`.** It correlates strongly with modern bytecode in this corpus,
  but correlating is not measuring, and the manifest is not read.
* **Obfuscation.** See T-VAL-3 — the bias is directional and it *lowers* the
  score for the same behaviour.
* **Server-side gating.** Play Integrity verdicts, account state and licence
  checks terminate on a server. Not observable, not modelled. See §5.

---

## 4. The measurements

Denominator: **120 analysable APKs**, of which **60 are DEX-only** by the corpus's
own central-directory criterion. Exact numerators, no rounding.

### 4.1 Headline

| signal | all 120 | DEX-only 60 | native 60 |
|---|---:|---:|---:|
| `invoke-polymorphic` present | **82/120 = 68.3%** | 27/60 = 45.0% | 55/60 = 91.7% |
| `invoke-custom` present | **81/120 = 67.5%** | 30/60 = 50.0% | 51/60 = 85.0% |
| either of the two (union) | 90/120 = 75.0% | 33/60 = 55.0% | 57/60 = 95.0% |
| `const-method-handle` present | **119/120 = 99.2%** | 59/60 = 98.3% | 60/60 = 100% |
| `const-method-type` present | 118/120 = 98.3% | 58/60 = 96.7% | 60/60 = 100% |
| declares a `native` method | **64/120 = 53.3%** | 4/60 = 6.7% | 60/60 = 100% |
| `loadLibrary`/`load` call site | **63/120 = 52.5%** | 3/60 = 5.0% | 60/60 = 100% |
| …with the library name bound | 56/120 = 46.7% | 3/60 = 5.0% | 53/60 = 88.3% |
| `lib/<abi>/*.so` entry | **60/120 = 50.0%** | 0/60 = 0.0% | 60/60 = 100% |
| native payload outside `lib/` | **1/120 = 0.8%** | 0/60 = 0.0% | 1/60 = 1.7% |
| reads a `Build` identity field | **99/120 = 82.5%** | 41/60 = 68.3% | 58/60 = 96.7% |
| references Play Services | **0/120 = 0.0%** | 0/60 = 0.0% | 0/60 = 0.0% |
| references Play Integrity | **0/120 = 0.0%** | 0/60 = 0.0% | 0/60 = 0.0% |
| references licensing/DRM | 39/120 = 32.5% | 4/60 = 6.7% | 35/60 = 58.3% |
| reflective call site | **115/120 = 95.8%** | 55/60 = 91.7% | 60/60 = 100% |
| external dex class loader | 10/120 = 8.3% | 4/60 = 6.7% | 6/60 = 10.0% |

(The union row is `90/120`, not the sum of the two rows above it: an app with
both opcodes is one app. Its per-stratum split, 33 + 57, does sum to 90.)

The `declaredNativeMethods`, `loadLibraryCallSites` and `libEntries` figures for
the native stratum are `60/60` by construction, because that stratum was defined
by the corpus's own `lib/<abi>/*.so` criterion. They are reported to confirm the
analyzer independently reproduces the census, **not** as independent evidence.
`payload outside lib/` at 1/60 in the native stratum is the one non-tautological
row there: `se.leap.riseupvpn` ships OpenVPN binaries under `assets/` that a
`lib/`-only check cannot see.

**Play Services and Play Integrity are 0/120.** This is a real and important
result with a specific cause: F-Droid apps are built without GMS dependencies
because F-Droid's build recipes remove them. The taxonomy's §17.1 hard-wall set
includes `SUB.TRUST.PLAY_INTEGRITY` as the "most likely dominant finding", and
**F-Droid dodges it entirely** — which `research-protocol.md` T-03 anticipated.
The honest conclusion is that this corpus cannot speak to the single family the
pre-registration expects to dominate, and the number must not be read as "apps
do not use Play Integrity".

### 4.2 Bands and gates

```
REFUSE     119/120 = 99.2%
DEGRADE      0/120
LIKELY_RUNS  0/120
MINIMAL      1/120 =  0.8%
UNKNOWN      0/120

NATIVE_PAYLOAD             60/120 = 50.0%
DYNAMIC_INVOKE            119/120 = 99.2%
PLAY_SERVICES               0/120 =  0.0%
NATIVE_METHOD_UNIMPLEMENTED  4/120 =  3.3%
```

A `REFUSE` rate of 99.2% is not a compatibility result. It is the statement that
`DYNAMIC_INVOKE` fires on 119/120 apps, which is a statement about the **d8
toolchain**, not about 119 individual apps. §4.4 explains why, and §7 explains
why that makes the band almost uninformative even though the underlying counts
are not.

### 4.3 The DEX 039 finding

This is the most consequential structural observation in the whole analysis, and
it is a property of the format rather than of the apps.

```
DEX version of the first classes.dex, over the 120 sampled APKs:
  035   56 apps
  037   30 apps
  038   19 apps
  039   15 apps

map_list contains call_site_id_item      0/120
map_list contains method_handle_item     0/120
```

Zero of 120 files have either section, *including* files with 13,951
`const-method-handle` instructions and 14 `invoke-custom` sites. And the
`method@` operand of `invoke-polymorphic` is written as the `NO_INDEX` sentinel:

```
$ cargo run --release --example dex-sections -- <apk>
# and, byte level, com.co3 classes.dex:
== Lek2; .run code_item@3537020 units[464..474]
 0003 0000 000d 0000 fffa ffff 0003 0000
target: invoke-polymorphic fmt=Some("F45CC") index_operand=Some(65535)
  as method_id : None
  as string_id : None
  as field_id  : None
  as type_id   : None
  method_count=32605
```

`0xffff` is `NO_INDEX`. There is no pool to resolve it against, because the pool
it would refer to is not in the file.

Three consequences, and they matter for what a substrate must build:

1. **The dependency is real and near-universal.** 99.2% of apps contain at least
   one dynamic-invoke opcode. `SUB.FW.INVOKEDYNAMIC` is not a niche 2017-era
   problem; it is the default output of `d8`.
2. **The dependency is not enumerable from the DEX.** Because there is no
   `call_site_ids` section, the *set* of bootstrap methods an app needs cannot be
   read off the pool. The only statically available signal is a **count of
   opcodes**. A substrate has to implement `MethodHandle`, `MethodType`,
   `CallSite` and the `LambdaMetafactory` / `InnerClassLambdaMetafactory`
   bootstrappers for all of them; there is no subset it can pick.
3. **The taxonomy rule table under-reports it by 6×.** `SUB.FW.INVOKEDYNAMIC`
   from the rule table (which keys on `java.lang.invoke.*` *classes*) fires on
   **12/120** apps, because in DEX 039 nothing references those classes by name.
   The opcode count says 119/120. The rule table is not wrong; it is answering a
   different, weaker question, and the gap between 12 and 119 is the honest
   measure of what name-based analysis loses.

An unexplained regularity, recorded rather than glossed: `minSdk` does **not**
predict the opcodes. `invoke-custom` appears in 29/34 apps with `minSdk >= 26`
and 51/86 with `minSdk < 26`. Whatever the mechanism, the usual "d8 desugars
below 26" story does not explain this sample, and the mechanism was not
investigated further.

### 4.4 Three real examples per top signal, with the DEX evidence

`predict <apk>` prints the full document; each line below is copied from
`sample/rows.jsonl`.

#### Signal A — dynamic invoke (`const-method-handle` 119/120)

**`com.katiearose.sobriety` v22**, DEX 035, 23,821 methods with code,
`invoke-polymorphic` and `invoke-custom` present, 0 methods undecodable. Library
target `Lek2;.run`, `code_item@3537020`, unit 468:

```
fffa ffff 0003 0000     invoke-polymorphic {v0,v3}, method@NO_INDEX, proto@0000
```

**`com.co3` v214**, DEX 037, 119,909 methods with code, `invoke_custom` = 14,
`invoke_polymorphic` = 9, `const_method_handle` = 3,159, and
`map_call_site_ids` = 0. Library target `Lch;.b`, `code_item@1347940`, unit 550:

```
0159 0000 00fc 0000 00ce    invoke-custom {v0, v0, vc, ve}, call_site@0000
```

Both files: `map_list` has no `call_site_id_item` and no `method_handle_item`.

#### Signal B — reflection call sites (115/120)

**`app.halma` v15**, `Landroidx/core/app/ActivityRecreator;`:

```
.getActivityThreadClass  @ classes.dex:2u   invoke-static  -> Ljava/lang/Class;.forName(Ljava/lang/String;)Ljava/lang/Class;
.getMainThreadField      @ classes.dex:4u   invoke-virtual -> Ljava/lang/Class;.getDeclaredField(Ljava/lang/String;)Ljava/lang/Field;
.getPerformStopActivity2Params @ classes.dex:19u invoke-virtual -> Ljava/lang/Class;.getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
```

This is `SUB.FW.REFLECTION` and `SUB.FW.NON_SDK_API` in one method: AndroidX is
reflecting into `android.app.ActivityThread`, which is exactly the family the
taxonomy rates COMMON. 209 reflective call sites in this app.

**`app.traced_it` v16**, obfuscated synthetic class `La80;`, static initialiser:

```
.<clinit> @ classes.dex:6u   invoke-virtual -> Ljava/lang/Class;.getDeclaredField(Ljava/lang/String;)Ljava/lang/Field;
.<clinit> @ classes.dex:18u  invoke-virtual -> Ljava/lang/Class;.getDeclaredField(Ljava/lang/String;)Ljava/lang/Field;
.<clinit> @ classes.dex:30u  invoke-virtual -> Ljava/lang/Class;.getDeclaredField(Ljava/lang/String;)Ljava/lang/Field;
```

161 reflective call sites. The class name is `a8`, the method is `<clinit>`, and
the *only* thing that makes this countable is the `method_id` entry for
`Class.getDeclaredField` — which is the concrete form of T-VAL-3. Reflection over
obfuscated code is countable; reflection over *the string argument* is not.

#### Signal C — `Build` identity reads (99/120)

**`com.bodycheck` v2`: 267 reads across 8 distinct fields** — `BRAND`, `DEVICE`,
`FINGERPRINT`, `HARDWARE`, `ID`, `MANUFACTURER`, `MODEL`, `PRODUCT`. The next
densest app in the sample has 77. This is the anti-tamper signature the taxonomy
predicts for `SUB.BUILD.FINGERPRINT` (prior: "OCCASIONAL — CONJECTURE; high for
finance/DRM apps"), and it is the clearest example in the sample of a
field-read *count* carrying information that a boolean does not.

**`com.aw.huda` v513`: 25 reads across 19 distinct fields** — including
`BOOTLOADER`, `TAGS` and all three `SUPPORTED_*_ABIS` variants. `BOOTLOADER` and
`TAGS` together are the `SUB.BUILD.BOOTLOADER` / `SUB.BUILD.TAGS` pair, which the
taxonomy calls a hard gate for anti-tamper: 6/120 and 9/120 apps respectively.

Most-read fields over the 120 apps:

```
FINGERPRINT  83   MANUFACTURER  76   MODEL  76   BRAND  42   DEVICE  37
PRODUCT      24   SUPPORTED_ABIS 21  ID     21   TYPE   15   HARDWARE 13
CPU_ABI      13   BOARD        12   DISPLAY 12  CPU_ABI2 11  TAGS   9
```

#### Signal D — native payload: the `lib/`-only check is not enough

**`se.leap.riseupvpn` v186000** ships 22 `lib/` entries **and** four ELF
payloads under `assets/` with **no `.so` extension**:

```
assets/pie_openvpn.arm64-v8a
assets/pie_openvpn.armeabi-v7a
assets/pie_openvpn.x86
assets/pie_openvpn.x86_64
```

Found by content sniffing (first four bytes `\x7fELF`), not by name — 12 asset
entries, all 12 sniffed, sniff budget not exhausted. This is the mechanism
`corpus/report.md` named when it said a `lib/`-only check "misses by
construction".

The sniff is bounded and its coverage is reported per app
(`assets_total` / `assets_sniffed` / `assets_sniff_budget_exhausted`), because
an unbounded sniff of a 40 MB asset is not an analysis budget. One app in the
sample hit the cap: `com.aw.huda` has 59 asset entries, 58 were sniffed, and
`assets_sniff_budget_exhausted` is `true` — so for that app the "no native
payload outside `lib/`" claim is a statement about 58 of 59 entries, not all
59.

**Four DEX-only apps declare `native` methods with nothing in the APK to
implement them**, which is the specific failure mode the brief asked for:

| app | native declarations | `lib/` entries | `loadLibrary` sites | name bound |
|---|---:|---:|---:|---|
| `com.katiearose.sobriety` v22 | 90 | 0 | 0 | — |
| `com.vermont.possin` v9 | 237 | 0 | 4 | `secp256k1` |
| `com.rosan.dhizuku` v17 | 8 | 0 | 1 | `androidx.graphics.path` |
| `info.schnatterer.nusic` v24 | 15 | 0 | 1 | `discid-java` |

`com.katiearose.sobriety` is the clearest: **90 `native` declarations, no `.so`
anywhere in the archive, and not one `loadLibrary` call site in the decoded
bytecode.** Whatever implements those 90 methods is not in the APK. The other
three at least name a candidate, and the names are telling: `secp256k1` and
`discid-java` are native libraries that must come from *somewhere* — a payload
the analyzer did not sniff, another APK, or a system image.

Whether an implementation arrives some other way is **not statically
determinable**, which is why the field is called
`native_declarations_unimplemented` and not `will_throw`. T-VAL-4 gives the
concrete case where a `native` declaration is never reached at all.

#### Signal E — `loadLibrary` name binding, and a known defect

56/63 `loadLibrary` call sites had their library name bound. Two examples:

```
Landroidx/graphics/path/PathIteratorPreApi34Impl;.<clinit> @ classes.dex:2u
    invoke-static -> Ljava/lang/System;.loadLibrary(Ljava/lang/String;)V   name = "androidx.graphics.path"
Lio/flutter/embedding/engine/FlutterJNI;.loadLibrary @ classes.dex:13u
    invoke-static -> Ljava/lang/System;.loadLibrary(Ljava/lang/String;)V   name = "flutter"
```

Binding is a single linear pass with two bounds, and both were needed:

* **The first argument register is read from the packed nibbles**, not from
  `Instruction::argument_registers`, which trims trailing zero nibbles and so
  reports *zero* arguments for the very common case of a one-argument call whose
  argument is `v0`. Fixing this moved bound names from 5/60 to 14/60 in the
  first 60-app run.
* **The shape filter was removed from the call site.** `looks_like_library_name`
  rejects dots, and `androidx.graphics.path` — one of the most common library
  names in the sample — contains three. The filter belongs to pool-wide scanning,
  not to argument binding, where the string *is* the name by construction. This
  moved it from 14/60 to 30/60.
* **The binding is same-basic-block.** A control-transfer generation counter is
  bumped on `goto*`, `if-*`, `switch`, `return*` and `throw`, and a binding is
  accepted only if the definition and the use share a generation. This is a
  basic-block approximation, not a CFG.

**Known defect, on the record:** `com.co3` has an inferred library name of the
bare string `"lib"`, which is a mis-binding — the argument register was reused
on another path. Last-write-wins-within-a-block does not eliminate register
reuse. The prediction does not depend on it (`NATIVE_PAYLOAD` fires on the 21
`lib/` entries), and `validation-set/labels.json` records it as a defect rather
than hiding it.

---

## 5. Trust and integrity: what is and is not claimed

`AppFacts::trust` carries six fields and one constant, `TRUST_NOTE`, which is
serialised into every row so the caveat travels with the data:

> A Play Integrity reference is a *client-side API call*: the app obtains a
> token and sends it to its own backend. Whether that backend accepts the request
> is not observable statically, is not a substrate failure, and is not modelled
> here. What the analyzer reports is only that the client-side path is present.

Concretely, the analyzer emits:

* `trust.play_integrity_api_classes` — external `com.google.android.play.core.*`
* `trust.integrity_literals` — string constants naming a Play Integrity or
  SafetyNet symbol
* `trust.drm_literals`, `trust.licensing_classes` — licensing/DRM
* `trust.firebase_classes` — Firebase, reported **separately** because Firebase
  has non-GMS backends and is a weaker signal
* `trust.server_side_verdict_observable` — **always `false`**, and present
  precisely so it cannot be confused with the fields above

`SUB.NET.BACKEND_VERDICT` is the taxonomy ID where a Play Integrity refusal
actually terminates. It is not scored, not gated, and cannot be, from an APK.

Two classifier defects were found by running this over real data and are fixed,
with regression tests:

* A bare `"integritytoken"` substring matched
  `access$parseSabrIntegrityTokenData` — a YouTube/SABR internal — producing a
  false Play Integrity positive on `NewPipeEnhanced`. The literal list now
  contains only specific symbols and package names.
* A bare `"drm"` substring produced **258 false positives in a single app**.
  Removed. Every DRM literal is now at least six characters and names a type or
  package.

`SUB.TRUST.SAFETYNET` carries no weight, per the taxonomy's own §2 note that it
has been unsatisfiable for every app since 2025-01-31 and therefore has zero
discriminating power. Including it would be adding a constant to an average.

---

## 6. The taxonomy join

The rule table (`src/taxonomy.rs`, 145 rules) maps
`(class descriptor, member name)` to a `SUB.*` ID with a confidence tag
(116 `VERIFIED`, 29 `CONJECTURE`, 76 distinct IDs across 15 of the 16 families):

* **VERIFIED** — the API's documented contract *is* the assumption.
  `System.loadLibrary` is documented to load a native shared library, so a
  `method_id` entry for it is a verified reference to
  `SUB.NATIVE.LOAD_LIBRARY`.
* **CONJECTURE** — the linkage assumes a usage pattern a reference alone does not
  establish. `Class.forName` is verified to be reflection, but "this app reflects
  over framework internals" depends on the string argument, which is reported
  separately.

A unit test parses `docs/divergence-taxonomy.md` and asserts that **no rule
invokes an ID outside it**, so the frozen pre-registration cannot drift out from
under the rule table. 76 of the 145 IDs are reachable; the missing 69 are the
ones this pass cannot see at all — manifest declarations, `resources.arsc`,
runtime-only behaviour, and properties of the runtime rather than the bytes —
and §7 enumerates them one at a time.

Top of the distribution (apps out of 120, all VERIFIED unless noted):

| ID | apps | members | call sites | conf |
|---|---:|---:|---:|---|
| `SUB.FW.ACTIVITY_LIFECYCLE` | 120 | 677 | 1,023 | VERIFIED |
| `SUB.FW.SERIALIZATION` | 120 | 17,244 | 139,978 | VERIFIED |
| `SUB.BUILD.SDK_INT` | 116 | 150 | 59,748 | VERIFIED |
| `SUB.TIME.WALL_CLOCK` | 116 | 116 | 3,934 | VERIFIED |
| `SUB.FW.REFLECTION` | 115 | 1,071 | 35,251 | VERIFIED |
| `SUB.INPUT.INPUT_EVENT` | 115 | 5,844 | 42,781 | CONJECTURE |
| `SUB.IPC.SYSTEM_SERVICE` | 115 | 224 | 6,722 | VERIFIED |
| `SUB.GFX.TEXT_RENDER` | 113 | 6,596 | 28,333 | CONJECTURE |
| `SUB.IPC.PACKAGE_MANAGER_OTHER` | 113 | 558 | 1,571 | VERIFIED |
| `SUB.RES.DISPLAY_METRICS` | 113 | 676 | 4,653 | CONJECTURE |
| `SUB.BUILD.FINGERPRINT` | 83 | 83 | 190 | VERIFIED |
| `SUB.CPU.CORE_COUNT` | 91 | 91 | 264 | VERIFIED |
| `SUB.FW.INVOKEDYNAMIC` | **12** | 82 | 333 | VERIFIED |

Two rows in that table are worth a reader's attention, because both are
*technically* correct and both are nearly useless:

* `SUB.INPUT.INPUT_EVENT` at 115/120 comes from a rule on
  `MotionEvent`/`KeyEvent` with member `*`. An app that only *dispatches* a
  synthetic key event is not receiving input, which is the actual assumption. The
  row is `CONJECTURE` for exactly this reason and the 42,781 call sites are
  overwhelmingly `MotionEvent.obtain`.
* `SUB.FW.INVOKEDYNAMIC` at 12/120 against an opcode count of 119/120 — §4.3.

---

## 7. Threats to validity

Ordered by how much they should change a reader's confidence.

### T-VAL-1 — Static analysis cannot see runtime-only behaviour, and the gap is not symmetric

The three things static analysis structurally cannot observe:

1. **Runtime-only reflection.** `Class.forName(s)` where `s` is decoded at run
   time is not a string constant in the DEX. Measured: `app.traced_it` has 886
   reflective-looking string constants and 161 reflective call sites; the
   *binding* between them is never available statically.
2. **String decoding.** Obfuscators split a class name across a `char[]`,
   XOR it, or build it from a `StringBuilder`. The `reflection surface` signal
   degrades to zero for such an app, and the score degrades with it.
3. **Server-side gating.** Play Integrity verdicts, subscription state, account
   validity, feature-flag cohorts, A/B assignment, rate limits, and geo-blocking
   are all decided by a server the analyzer never contacts. `SUB.NET.BACKEND_VERDICT`
   and `SUB.TRUST.PLAY_INTEGRITY` both terminate there.

The asymmetry is the problem. Signals 1 and 2 make the analyzer **miss**
dependencies, which biases the score *downward* — toward optimism. Signal 3
creates dependencies the analyzer cannot see at all, and it fails *closed*, which
no amount of static work can detect. The direction of the error is therefore
known and unfavourable, and it is not correctable within this method.

### T-VAL-2 — Twenty hand labels cannot validate a scorer

`validation-set/labels.json` has 20 apps × 6 features = 120 cells.
`validate-prediction.mjs` reports 20/20 agreement on every feature, and that
number is worth **nothing** as evidence about the predictor, for three reasons
that the script prints before anyone can quote it:

* The labels were produced by the analyzer's author, from the same static
  artefacts the analyzer reads. This is a test of whether the implementation
  matches its intent. Perfect agreement is the *expected* result of writing both
  sides of the comparison.
* Three of the six features are ≥91% or ≤9% positive in the set. A feature that
  is almost always true cannot discriminate, so agreement on it is close to
  meaningless. Only `F1` (native payload, 10/20) and `F6` (dex class loader,
  4/20) have any spread, and both agree 20/20.
* n = 20 supports no significance test. One app flipping moves any rate by 5
  percentage points. Cohen's κ is reported but is degenerate on the
  single-class columns and is printed as `n/a` rather than as 0 or 1.

What the validation set *is* good for: catching implementation regressions, and
pinning the selection rule and the SHA-256s so a future run compares the same
bytes. All 20 fetched digests match the SHA-256 F-Droid publishes in its index
for the same package and versionCode, which closes the gap
`corpus/report.md` names — "SHA-256 values come from the F-Droid index and were
not checked against the served bytes".

### T-VAL-3 — Obfuscation defeats name-based analysis, directionally

R8 renames `com.example.Foo` to `a.b.c`. A `looks_like_qualified_class_name`
predicate that requires a known root package finds nothing in an obfuscated app.
The rule table keys on class descriptors and member names, so **every** taxonomy
hit from an obfuscated app is under-counted. The bias is therefore *downward*:
an obfuscated app scores lower for the same behaviour. The only name-independent
signals in the whole analyzer are the ten invoke opcodes, `ACC_NATIVE`, the
central-directory inventory, and the `/proc`, `/sys`, `/dev` string literals.
Nothing in the sample suggests F-Droid apps are systematically obfuscated —
`NewPipeEnhanced` retains `Landroidx/graphics/path/PathIteratorPreApi34Impl;`
— but the bias is real and unquantified, and this corpus cannot bound it.

### T-VAL-4 — A perfect static predictor is impossible in principle

Not "hard", not "we did not try". **Impossible.** The strongest single reason:

> **An app's dependence on a substrate capability is a property of the paths it
> takes, and the set of paths is a property of its inputs, its server, its clock
> and its user — none of which is in the APK.**

So for any static predicate `P(APK)` and any app `A`, there is a reachable
execution of `A` on which `P(A)` is wrong. The cleanest instance, and it is not a
contrived one: an app that ships a `.so` and calls `loadLibrary` in a static
initialiser, wrapped in `if (Build.SUPPORTED_ABIS.contains("arm64"))`. On the
arm64 device it needs the library; in a substrate whose `SUPPORTED_ABIS` is
`[]` it never reaches the call. The static fact "this APK has a native payload"
is a fact about a path the substrate may never take. The analyzer's gate
therefore encodes a *worst case over paths*, and the worst case is the right
default for a feasibility argument and the wrong default for a compatibility
claim. Those are different uses and the number should not be quoted for both.

Two narrower versions of the same problem, each with a real instance in the
sample:

* **Conditional native loading.** The four DEX-only apps with unimplemented
  `native` declarations (§4.4) may never call them. `com.katiearose.sobriety`
  declares 90 and calls 0 in the decoded bytecode — the declarations could be
  reached only from a code path behind a runtime check.
* **Test hooks and debug paths.** A `native` declaration used only by an
  `androidTest` source set does not ship. A `loadLibrary` guarded by
  `BuildConfig.DEBUG` never fires in a release build. Nothing in the DEX records
  which build variant it came from.

The mitigation is not better static analysis; it is that the *substrate* must be
built to answer these at run time, and the predictor's job reduces to
shortlisting which apps are worth attempting.

### T-VAL-5 — The rubric's weights are an opinion, and 99.2% REFUSE makes the band nearly vacuous

The weights in §3 sum to 1.000 and are internally consistent. They are also
**unvalidated**, and the ordering — native code and invokedynamic worse than Play
Services, worse than build identity, worse than reflection, worse than the
kernel literals — is an argument, not a measurement. Nobody has shown that
`dynamic_invoke` at 0.18 deserves more than `reflection_surface` at 0.06.

Worse, the band is degenerate in this corpus. With `DYNAMIC_INVOKE` at 119/120
and `NATIVE_PAYLOAD` at exactly the 60 native apps, the bands are
`REFUSE 119, MINIMAL 1`. A five-level scale with four levels empty and one
holding 99% of the sample carries no information. The band exists for the corpus
the predictor will eventually be applied to — Google Play apps, older and
larger `call_site_ids` files, apps built with hand-written assembly — and on this
corpus it should be read as "the gate set is too coarse for F-Droid", not as a
compatibility measurement.

### T-VAL-6 — The string-constant evidence is one step removed from behaviour

A `/proc/self/status` in the string pool proves the constant is in the APK, not
that the app reads it. A dead branch, a help screen, a log message, or a
diagnostics dump produces the same constant. The analyzer reports constants and
call sites as separate fields and never multiplies them together; the
`kernel_fs_literals` component is weighted 0.02 for this reason, which is close
to zero and is honest about the evidence.

Two precision defects were found by running on real data and are fixed with
regression tests: a bare `"integritytoken"` and a bare `"drm"` (§5). Both were
false-positive generators producing 258 and 1 spurious positives respectively on
a single app. A reader should assume more of these exist in the classifiers that
the 120-app sample happened not to exercise.

### T-VAL-7 — F-Droid is not the app population, and this sample dodges the expected dominant finding

Already stated in `corpus/report.md` and restated because it bites here:
Play Services and Play Integrity are **0/120**. The pre-registration expects
`SUB.TRUST.PLAY_INTEGRITY` to dominate (`research-protocol.md` §8.1). This
corpus cannot test that hypothesis at all, and the analyzer's `PLAY_SERVICES`
gate has **never fired on any app in the sample**. A gate that has never fired
is untested code, and the honest thing is to say so rather than to present the
0/120 as a finding about the ecosystem.

### T-VAL-8 — `resources.arsc` is unparsed, and it is probably the biggest miss

Stated in §3.3 and repeated because it is the most consequential scope decision
in the whole deliverable. `SUB.RES.ARSC` is COMMON in the taxonomy and its
documented failure mode is "IDs resolve to the **wrong resource** with no
error" — a MISBEHAVE, invisible to a crash counter, and completely invisible
here. The predictor therefore assigns *no* score to what may be the largest single
divergence family, and a low score must not be read as "this app is easy".

### T-VAL-9 — Instruction counts are over-approximations, and one linear pass is not a call graph

The walk is linear over each method's whole instruction stream, so it counts
instructions in unreachable blocks and in both arms of every branch. The
`loadLibrary` name binding is bounded to a single basic block by a
control-transfer generation counter, which is an approximation of a CFG and
still mis-binds under register reuse (the `com.co3` `"lib"` case). No call graph
is built, so no cross-procedural fact is available at all — including whether a
`native` method is ever called, which is the single most valuable missing
analysis for the `NATIVE_METHOD_UNIMPLEMENTED` gate. This is a scope decision,
not an oversight: an interprocedural analysis is a different project.

### T-VAL-10 — One sample, one moment, and the corpus is a snapshot

`repo.version` is 30000. F-Droid's index changes daily; a re-measurement must
re-record it, and a number without one is not comparable to this one. 120 of
4,475 packages is 2.7%, and the stride is over *package* names, so any
systematic correlation between a package's name and its technology is inherited
into the sample. `n = 120` gives a 95% CI of roughly ±8 percentage points on a
50% rate, and the whole rubric lives inside that band.

---

## 8. Verdict on the rubric

**The weights are not yet defensible as weights.** They are defensible as
*ranking*: the ordering is a reasonable argument, the ten components are the
right ten, the accessors are individually checkable, and the hard-wall gates are
the right gates. What is missing is any evidence that 0.22 and 0.02 are the right
numbers rather than 0.20 and 0.00, and no amount of static analysis can supply
it — only correlation with observed behaviour can, which does not exist yet.

Two things would change the verdict, in order of value:

1. **A verified-running set of 20+ apps with oracle recordings.** Enough to fit
   the weights. Below about 40 correlated apps, any weight vector fits and the
   fit is not distinguishable from the prior.
2. **Re-weighting by the taxonomy's own `Class` column.** `REFUSE` should
   dominate `DEGRADE`, which should dominate `MISBEHAVE`, because the outcome
   distribution depends on the class and not on how often the assumption is
   made. The current weights ignore the column entirely. This is cheap, needs no
   runtime, and is a strictly better prior than what is there.

Until then the components should be read individually and the total treated as a
summary of an argument, not as a measurement.
