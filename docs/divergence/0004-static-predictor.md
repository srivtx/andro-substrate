# 0004 — The static substrate-dependency predictor: analyzer outputs bound to taxonomy IDs

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: which of the 145 `SUB.*` IDs a static analyzer can establish, on
  what evidence, and with what confidence; which it cannot establish at all; and
  what the resulting score is allowed to claim.

## Context

`corpus/report.md` measured that 44.76% of the F-Droid corpus contains no
`lib/<abi>/*.so` and was explicit that this is a **necessary** filter and not a
sufficient one. The gap between "no native code" and "will run" is the project's
actual subject matter, and it had no measurement. `research-protocol.md` §8
pre-registers an expected result range; §7 T-01 names "the oracle is not
Android" as the dominant threat to the whole study.

Two things make a static predictor worth building rather than a heuristic:

1. **It is the only measurement available before the runtime exists.** A runtime
   that runs 8% of apps is a demo. A defensible static predictor is a result,
   because it is a claim about all 4,475 apps that needs no device, no root
   grant and no emulator.
2. **It is the only way to see the apps the runtime will not reach.** A
   measurement taken only on apps that ran is a measurement of the apps that were
   easy.

`tools/dexcore` parses `class_data_item` and `code_item` including try tables,
does not parse `debug_info_item` or `encoded_value`, and does not parse
`resources.arsc`. That is the floor this decision is built on.

## Decision

Ship `analysis/` (crate `substrate-predictor`) as a **static fact extractor with a
documented, component-wise rubric**, and bind its outputs to taxonomy IDs under
two rules.

### Rule 1 — Evidence strength is a first-class, serialised axis

Three strengths, in separate fields, never combined:

| strength | established by | what it does *not* establish |
|---|---|---|
| **reference** | a `method_id` / `field_id` / `type_id` / `string_id` entry | that the member is ever called — R8 keeps entries it could not prove dead |
| **declaration** | the APK defines the class or member | that anything reaches it |
| **call site** | an instruction in a decoded method body targets it | that the method containing it is reachable — the walk is a linear superset |

Everything derived from a reference is named `*_refs` or `*_referenced` and says
so in its doc comment. `Predict` and `AppFacts` never multiply a reference count
by a call-site count.

### Rule 2 — Mapping confidence is a first-class, serialised axis

Every rule in `analysis/src/taxonomy.rs` carries `VERIFIED` or `CONJECTURE`:

* **VERIFIED** — the API's documented contract *is* the assumption.
  `System.loadLibrary` is documented to load a native shared library, so a
  `method_id` entry for it is a verified reference to
  `SUB.NATIVE.LOAD_LIBRARY`. No behavioural inference is needed.
* **CONJECTURE** — the linkage assumes a usage pattern a reference alone does not
  establish. `Class.forName` is verified to be reflection
  (`SUB.FW.REFLECTION` names `Class.forName` in its own text), but "this app
  reflects over *framework internals*" depends on the string argument, which is
  a separate, separately-reported signal.

Presenting the second kind as the first would let a reader believe the predictor
measures `SUB.FW.REFLECTION` when it measures the much weaker "this APK contains
a reference to `Class.forName`". The tag makes the difference visible in the
output instead of in a footnote. A unit test parses
`docs/divergence-taxonomy.md` and asserts that **no rule invents an ID**, so the
frozen pre-registration cannot drift out from under the table.

## The mapping table

145 rules cover 76 of the 145 IDs, across 15 of the 16 families: 116
rules are `VERIFIED` and 29 are `CONJECTURE`. Grouped by family, with the
evidence strength each one rests on.

| family | IDs mapped | evidence | what the analyzer establishes |
|---|---|---|---|
| `SUB.BUILD` | FINGERPRINT, MODEL, MANUFACTURER, BRAND, PRODUCT, DEVICE, HARDWARE, BOARD, BOOTLOADER, SERIAL, TAGS, RADIO, SDK_INT, ABILITIES | `field_id` + **instruction-level `sget`** for the field rows; `method_id` for `getRadioVersion`; `hasSystemFeature` for ABILITIES | A counted read of each named field, with the enclosing method and code offset. 99/120 apps read at least one; 83 read `FINGERPRINT`. This is the strongest and cheapest family in the taxonomy and the analyzer measures it at call-site strength. |
| `SUB.TRUST` | PLAY_SERVICES, KEYSTORE_ANDROIDKEYSTORE, ATTESTATION_KEY, ROOT_DETECT, DEBUG_DETECT, GMS_ACCOUNT | `method_id` / `type_id` reference | Only that a **client-side API** is referenced. `PLAY_INTEGRITY` and `SAFETYNET` are deliberately **not** scored or gated. |
| `SUB.KERNEL` | CPU.CORE_COUNT only (`Runtime.availableProcessors`) | `method_id` | One member; the rest of the family is reached through string literals instead. |
| `SUB.IPC` | SYSTEM_SERVICE, SERVICE_MANAGER, ACTIVITY_MANAGER, PACKAGE_MANAGER_OTHER, ABILITIES, ALARM_MANAGER, JOB_SCHEDULER, CONNECTIVITY_MANAGER, CONTENT_PROVIDER, NOTIFICATION | `method_id` reference | That the API is referenced. `PACKAGE_MANAGER_OTHER` is marked VERIFIED for `queryIntentActivities`/`getInstallerPackageName` and **CONJECTURE** for `getPackageInfo`/`getApplicationInfo`, because those are equally used for self-queries. `BROADCAST` maps from `BroadcastReceiver.onReceive` and is CONJECTURE: a receiver being *defined* does not say which broadcast it waits for. |
| `SUB.FS` | SYSTEM_LAYOUT, EXTERNAL_STORAGE, LIB_PATH, ASHMEM, PACKAGE_PATH, PERM_MODEL, DATA_DIR, OBB, MOUNT_NS, SELINUX_CONTEXT | entry names + string constants | Path-shaped constants per tag, plus the `.so` inventory. String constants are **not** scored above 0.02 (§3.3 of `prediction.md`). |
| `SUB.RES` | ARSC **absent**, QUALIFIER absent, LOCALE, TIMEZONE, FONT_SCALE absent, DISPLAY_METRICS, PACKAGE_RESOLVER, SYSTEM_FONTS absent | `method_id` | `ARSC` is out of scope and is the largest unmeasured risk (T-VAL-8). |
| `SUB.TIME` | MONOTONIC, ELAPSED_REALTIME, WALL_CLOCK, SLEEP, VSYNC, SLOW_OPERATION absent, ANR_BUDGET absent | `method_id` | Clean mapping: each is a named method whose contract is the assumption. `VSYNC` also from `Choreographer` and, CONJECTURE, `ValueAnimator`. |
| `SUB.CPU` | CORE_COUNT, ARCH, TIERING absent, GC absent, ATOMIC absent, THREAD_AFFINITY absent, NUMERIC absent | `field_id` for ABI lists | `TIERING` cannot be observed in an APK at all; it is a property of the runtime, not of the bytes. |
| `SUB.MEM` | DIRECT_BYTEBUFFER, MMAP, LARGE_HEAP absent, HW_CAPS, LMK absent, NATIVE_HEAP absent, ENTROPY absent | `method_id` + `/dev/urandom` constants | `ENTROPY` is a string-constant signal only. |
| `SUB.NATIVE` | LOAD_LIBRARY, JNI_ENTRY, EXEC_SEGMENTS absent, LINKER_NS absent, ISA absent, SIGNAL_CRASH absent | entry names + `ACC_NATIVE` + call sites | The one family the analyzer measures at full strength: a `.so` entry, a `native` declaration, and a `loadLibrary` call site are each unambiguous. |
| `SUB.NET` | EGRESS, DNS absent, TLS_TRUST absent, CLEARTEXT_POLICY absent, PROXY, NATIVE_HTTP, WEBSOCKET absent, QUIC absent, **BACKEND_VERDICT absent** | `method_id` | `EGRESS` is split: `URL.openConnection` is VERIFIED (documented to open a connection), `Socket`/`HttpURLConnection` references are CONJECTURE. |
| `SUB.GFX` | EGL_CONTEXT, GLES_VERSION absent, VULKAN, EXTENSIONS absent, RENDERER_STRING absent, SURFACE, HW_COMPOSITION absent, FRAME_BUDGET absent, SCREEN_ON, CAMERA_PIPE, TEXT_RENDER | `method_id` / `type_id` | `TEXT_RENDER` from `Canvas` is CONJECTURE: a canvas is also used for non-text drawing. |
| `SUB.HW` | SENSORS, CAMERA (→ GFX.CAMERA_PIPE), LOCATION, BLUETOOTH, NFC, VIBRATE, TELEPHONY, BIOMETRIC, CONTACTS_SMS absent, PRINTER_SCANNER absent | `type_id` / `method_id` | The only rule keyed on a *type* is `SUB.FW.INVOKEDYNAMIC`; the rest key on members. `SUB.HW` is the most reliably mapped family, at type-reference strength. |
| `SUB.FW` | CLASS_LOADER, REFLECTION, **INVOKEDYNAMIC**, NON_SDK_API, SERIALIZATION, DYNAMIC_CODE, ACTIVITY_LIFECYCLE, CONTENT_PROVIDER_INIT, CRYPTO_PROVIDER, WEBVIEW, PROCESS_ISOLATION absent | `method_id` / `type_id` / opcodes | `INVOKEDYNAMIC` is the one case where the **opcode count is the load-bearing signal and the rule table is not** — see the DEX 039 finding below. |
| `SUB.INPUT` | INPUT_EVENT, IME, WINDOW_FOCUS absent, HAPTIC absent | `method_id` | `INPUT_EVENT` is CONJECTURE: an app may only *dispatch* synthetic events, not receive them. 115/120 apps hit it, 42,781 of the call sites are `MotionEvent.obtain`, and the taxonomy's own `Class` for it is REFUSE — which is exactly why the tag matters. |
| `SUB.PWR` | WAKE_LOCK, BATTERY, DOZE, APP_STANDBY absent, BOOT_COMPLETED absent, PROCESS_REAPER absent, UPTIME_POLICY absent | `method_id` / `type_id` | `BOOT_COMPLETED` is in the taxonomy's hard-wall set and is **not** statically detectable: it is a manifest declaration, and the manifest is not parsed. |

### The four gates, and what each is worth

| gate | taxonomy | status in the 120-APK sample |
|---|---|---|
| `NATIVE_PAYLOAD` | `SUB.NATIVE.LOAD_LIBRARY`, `SUB.FS.LIB_PATH`, `SUB.NATIVE.JNI_ENTRY` | 60/120, and exactly the 60 apps the corpus census independently flagged |
| `DYNAMIC_INVOKE` | `SUB.FW.INVOKEDYNAMIC` | 119/120 |
| `PLAY_SERVICES` | `SUB.TRUST.PLAY_SERVICES` | **0/120 — never fired, therefore untested** |
| `NATIVE_METHOD_UNIMPLEMENTED` | `SUB.NATIVE.JNI_ENTRY` | 4/120, all DEX-only |

## The DEX 039 finding, and why it changes the design

Measured, not assumed:

```
map_list contains call_site_id_item    0/120 sampled APKs
map_list contains method_handle_item   0/120
```

including files with 13,951 `const-method-handle` instructions. And the
`method@` operand of `invoke-polymorphic` is written as `NO_INDEX` (`0xffff`) —
verified at byte level in `com.co3`:

```
== Lek2; .run code_item@3537020 units[464..474]
 0003 0000 000d 0000 fffa ffff 0003 0000
target: invoke-polymorphic fmt=Some("F45CC") index_operand=Some(65535)
  as method_id : None      (method_count=32605)
```

Three decisions follow, and they are the reason this ADR exists:

1. **`SUB.FW.INVOKEDYNAMIC` is measured from the opcode, not from the pool.**
   The rule table keys on `java.lang.invoke.*` *classes* and therefore reports
   **12/120**. The opcode count reports **119/120**. The table is not wrong; it
   answers a weaker question, and the 12-vs-119 gap is the honest measure of
   what name-based analysis loses. Both numbers are published, side by side,
   because quoting either alone is misleading.
2. **The dependency is unenumerable, not merely unenumerated.** With no
   `call_site_ids` section there is no set of bootstrap methods to read off the
   file, so a substrate cannot implement "just the bootstrappers these apps
   need". It must implement the machinery. This upgrades the item from
   *occasional* to *structural* relative to the taxonomy's prior, which is a
   legitimate amendment to a prior and not to a definition: the ID keeps its
   meaning.
3. **`DYNAMIC_INVOKE` gates on the weakest of its three sub-signals.**
   `invoke-polymorphic` (82/120) and `invoke-custom` (81/120) must be resolved
   at execution and are unambiguous. `const-method-handle` alone (119/120) only
   requires the constant pool to resolve an `ldc`. All three counts are
   published separately so a reader can re-derive the gate with a stricter rule.

An unexplained regularity, recorded rather than resolved: `minSdk` does not
predict the opcodes. `invoke-custom` appears in 29/34 apps with `minSdk >= 26`
and 51/86 with `minSdk < 26`. The usual "d8 desugars below 26" account does not
fit this sample and the mechanism was not investigated.

## What the score is, and what it is not

Ten components, weights summing to 1.000, each a saturating count with a
documented saturation point, plus four gates that set the band to `REFUSE`
outright. The full rubric is `analysis/prediction.md` §3.

Two rejections, both of which would have been easier to ship:

* **A flat weighted average over everything.** Rejected because it makes the
  prediction discontinuous at the native-code boundary, which is the one
  boundary `corpus/report.md` already argued for. Gated components report their
  weight and contribution, and the total is reported over ungated weight, with a
  second rescaled total for comparison.
* **Scoring `resources.arsc`, `targetSdk` or obfuscation resistance.** Rejected:
  the first is not parsed, the second is not read, and the third is a bias to be
  documented rather than a feature to be modelled. `targetSdk` in particular
  correlates strongly with modern bytecode in this corpus, and correlating is
  not measuring.

## Consequences

* The analyzer ships with `prediction.md` carrying a ten-item threats-to-validity
  section, and the score's weights are labelled an unvalidated opinion. A
  reader who disagrees with `0.22` can re-weight one row without discarding the
  other nine, because the components are serialised separately.
* `analysis/validate-prediction.mjs` exits non-zero and says "NOT VALIDATABLE
  YET" until a ground-truth recording or an `observed.json` exists. It filters
  `oracle/schema/examples/` on `synthetic === true` and
  `provenance.execution_performed === false`, so the two committed fixtures can
  never be mistaken for evidence.
* The 20-app hand-labelled set is committed with digests but no APKs. All 20
  fetched SHA-256s match the index. `prediction.md` T-VAL-2 states, in the file
  itself, that 20 labels are far too few to validate a scorer and that the 20/20
  agreement reported by the validator measures implementation correctness only.
* **The band is degenerate on F-Droid** (`REFUSE 119, MINIMAL 1`). That is a
  property of the corpus and of a gate set tuned for a broader population, and
  it is reported as such rather than smoothed.
* **`SUB.TRUST.PLAY_INTEGRITY` is untestable on this corpus.** F-Droid build
  recipes remove GMS dependencies, so `PLAY_SERVICES` fires 0/120 and
  `PLAY_INTEGRITY` fires 0/120. The pre-registration expects this family to
  dominate; this corpus cannot test that. Recorded as T-VAL-7 so a later reader
  does not read 0/120 as a finding about the ecosystem.

## Alternatives rejected

**Report only the corpus-structural facts, no score.** Cheaper and harder to
misread. Rejected because the brief's question — *which* apps are worth
attempting — needs an ordering, and because the components are reported
separately anyway, so a reader who wants no score can ignore the total and lose
nothing.

**Score everything as a single number with no components.** Rejected outright: it
makes it impossible to disagree with one weight, and it hides the fact that four
of the ten components are `CONJECTURE`-adjacent in places.

**Build a call graph and use reachability to decide whether a `native` method
matters.** This would materially improve `NATIVE_METHOD_UNIMPLEMENTED`, which is
currently a name-based lower bound. Rejected as out of scope: it is a different
project, and the brief forbids whole-program call-graph analysis.

**Wait for the runtime and measure the predictor against it.** Rejected as a
sequencing error, not as a bad idea. The static measurement is the one that
covers the apps the runtime will never reach, so doing it first is what makes
the runtime's sample non-cherry-picked.

## References

* `analysis/prediction.md` — rubric, all weights, the 120-APK measurement,
  ten threats to validity
* `analysis/sample/summary.json` — every aggregate, machine-readable
* `analysis/sample/rows.jsonl` — per-app rows with the evidence behind each count
* `analysis/validation-set/labels.json` — 20 apps, 6 features, SHA-256s
* `corpus/report.md` — the 44.76% figure and the "necessary, not sufficient" argument
* `docs/research-protocol.md` — pre-registration; unmodified
* `docs/divergence-taxonomy.md` — the 145 IDs; unmodified, and read by a test
