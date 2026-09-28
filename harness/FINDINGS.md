# How far a real APK gets, and what it needed to get there

**This is a finding, not a changelog.** Every number in it comes from a run whose
artefacts are committed next to it: `harness/recordings/<apk>.recording.json` is
the `ground-truth/1` document the run produced, and `harness/reports/<apk>.report.txt`
is the harness's own account of the same run. All fourteen recordings are accepted
by `oracle/recorder/validate.mjs`.

Reproduce any row with:

```sh
cargo run --quiet --manifest-path harness/Cargo.toml --bin apk-run -- \
    <apk> --policy default --quiet \
    --out harness/recordings/<apk>.recording.json \
    --report harness/reports/<apk>.report.txt
```

APKs: `https://f-droid.org/repo/<package>_<versionCode>.apk`, all pure-DEX and
single-`classes.dex` (selected from `corpus/survey.jsonl`, plus
`eu.quelltext.gita_6` from `analysis/candidates.md`).

---

## 1. The headline

| | |
|---|---|
| candidates run | **14** (13 F-Droid pure-DEX single-dex + `eu.quelltext.gita_6`) |
| highest `lifecycle.terminal` reached by any candidate | **`L0_PROCESS_STARTED`** |
| candidates that reached `L1_ACTIVITY_RESUMED` | **0** |
| candidates that reached `L2_FIRST_FRAME_DRAWN` | **0** |
| **shim classes added to reach any of the above** | **0** |
| **shim methods added to reach any of the above** | **0** |
| furthest candidate, by instructions of app bytecode executed | **`eu.quelltext.gita` 6 — 20** |
| framework methods the shim lacks that these apps need | **3 distinct** |
| shim *declaration* defects that block two more | **2** |
| `invokedynamic` call sites encountered | **0** |
| app classes shadowed by the shim in these runs | **0** |
| network attempts any app reached | **0** |

**Nothing was added to the shim.** The 14 runs were done against the 144-class,
215-method registry that ADR 0005 shipped, and every one of them stopped there
and named the surface it stopped on. That is the measurement; a table of
`L1_ACTIVITY_RESUMED` bought by growing the registry until the apps survived would
be a measurement of how many methods one author was willing to write.

## 2. `L2_FIRST_FRAME_DRAWN` is not "hard", it is structurally unreachable

There is no display, no vsync and no rasteriser, so `first_frame_drawn` is never
emitted and `L2` cannot be claimed. `L3_STEADY_STATE` is worse: it asserts a
*usable* app, and a substrate that has never resumed an activity has no business
claiming it. So the ceiling for this architecture is `L1_ACTIVITY_RESUMED`, and
the honest reading of §1 is "0 of 14 got within one method of it".

## 3. Per candidate

`ins` is real instructions of the app's own bytecode dispatched by the engine.
`stages ok/total` is how far the lifecycle driver got.

| candidate | terminal | stages | ins | stopped on | exact terminal error |
|---|---|---|---|---|---|
| **`eu.quelltext.gita` 6** | `L0_PROCESS_STARTED` | **1/2** | **20** | `Object.<init>()V` **abstract in the shim** | `AbstractMethodError: Ljava/lang/Object;.<init>()V is abstract in the framework shim` |
| `pro.rudloff.search_to_browser` 2 | `L0_PROCESS_STARTED` | **3/4** | 6 | `Activity.getIntent()` | `NoSuchMethodError: Lpro/rudloff/search_to_browser/MainActivity;.getIntent()Landroid/content/Intent; is not implemented by Lpro/rudloff/search_to_browser/MainActivity; (…onCreate(Landroid/os/Bundle;)V at unit 3, opcode 0x6e)` |
| `tk.al54.dev.badpixels` 4 | `L0_PROCESS_STARTED` | 1/2 | 9 | `Activity.requestWindowFeature(int)` | `NoSuchMethodError: Ltk/al54/dev/badpixels/MainActivity;.requestWindowFeature(I)Z is not implemented by Ltk/al54/dev/badpixels/MainActivity; (…onCreate(Landroid/os/Bundle;)V at unit 4, opcode 0x6e)` |
| `org.vi_server.red_screen` 3 | `L0_PROCESS_STARTED` | 1/2 | 5 | `Activity.requestWindowFeature(int)` | `NoSuchMethodError: Lorg/vi_server/red_screen/RedScreenActivity;.requestWindowFeature(I)Z is not implemented by …RedScreenActivity; (…onCreate(Landroid/os/Bundle;)V at unit 4, opcode 0x6e)` |
| `com.oF2pks.neolinker` 7 | `L0_PROCESS_STARTED` | 1/2 | 9 | `Activity.getIntent()` | `NoSuchMethodError: Lcom/oF2pks/neolinker/MainActivity;.getIntent()Landroid/content/Intent; is not implemented by …MainActivity; (…onCreate(Landroid/os/Bundle;)V at unit 12, opcode 0x6e)` |
| `com.termux.boot` 1000 | `L0_PROCESS_STARTED` | 1/2 | 7 | a URL the redaction layer refuses | `MalformedURLException: the WebView was given a URL the substrate cannot parse (…BootActivity;.onCreate(Landroid/os/Bundle;)V at unit 10, opcode 0x6e)` |
| `com.github.mrrar.gps_locker` 11 | `L0_PROCESS_STARTED` | 0/1 | 7 | `Object.<init>()V` **abstract in the shim** | `AbstractMethodError: Ljava/lang/Object;.<init>()V is abstract in the framework shim (La/k;.<init>(Lcom/github/mrrar/gps_locker/MainActivity;)V at unit 0, opcode 0x70)` |
| `de.cweiske.headphoneindicator` 3 | `L0_PROCESS_STARTED` | 0/1 | 5 | `BroadcastReceiver.<init>()V` **abstract in the shim** | `AbstractMethodError: Landroid/content/BroadcastReceiver;.<init>()V is abstract in the framework shim (…MainActivity$1;.<init>(…MainActivity;)V at unit 2, opcode 0x70)` |
| `com.page.bizzle` 2 | `L0_PROCESS_STARTED` | 0/1 | 3 | `java.util.Timer` absent | `NoSuchMethodError: the framework shim has no Ljava/util/Timer;.<init>()V (Lcom/page/bizzle/MainActivity;.<init>()V at unit 5, opcode 0x70)` |
| `com.android.adbkeyboard` 2 | `L0_PROCESS_STARTED` | 0/0 | 0 | no `<activity>` in the manifest | — (the driver had nothing to launch) |
| `com.zinaro.cachecleanerwidget` 1 | `L0_PROCESS_STARTED` | 0/0 | 0 | no `<activity>` in the manifest | — |
| `com.martinmimigames.tinymusicplayer` 4 | `L0_PROCESS_STARTED` | 0/0 | 0 | no `<activity>` in the manifest | — |
| `com.martinmimigames.littlemusicplayer` 15 | `L0_PROCESS_STARTED` | 0/0 | 0 | no `<activity>` in the manifest | — |
| `io.github.colemakmods.mod_dh` 3 | `L0_PROCESS_STARTED` | 0/0 | 0 | no `<activity>` in the manifest | — |

## 4. The framework surface these 14 apps need, as a set

**Three** distinct framework methods stand between these apps and their next
instruction, and **none of them was added**:

| framework method | apps | what adding it would mean |
|---|---|---|
| `Landroid/app/Activity;.getIntent()Landroid/content/Intent;` | 2 | 1 registry entry; returns the shim's own `Intent`, which already exists |
| `Landroid/app/Activity;.requestWindowFeature(I)Z` | 2 | 1 registry entry that must return `0`, which is **a fabrication** — "the feature was honoured and nothing happened". It is listed rather than added for exactly that reason |
| `Ljava/util/Timer;` (whole class) | 1 | a class plus `schedule`/`cancel`; a real timer needs a real thread, which this substrate does not have |

And **two** more stops are not gaps but **defects in the shim's own declarations**,
where a class the shim declares is marked `ACC_ABSTRACT` for a method that is
concrete on every device:

| shim declaration | apps that died on it | what it should be |
|---|---|---|
| `Ljava/lang/Object;.<init>()V` | **2** (incl. the furthest candidate) | concrete no-op |
| `Landroid/content/BroadcastReceiver;.<init>()V` | 1 | concrete no-op |

Both are one-line registry fixes and **neither is applied**, because applying them
mid-sweep would have changed the table under the other twelve rows. `Object`'s
constructor being abstract is the single largest blocker in this sweep: it stops
the *best* candidate in the set.

## 5. Observations that fired as a consequence of execution

These are in the recordings' `diagnostics` and `probes`, and they are the point of
the integration — nothing calls a shim method unless bytecode did:

| observation | app | fired because |
|---|---|---|
| `SIGNAL_PAT.SET_CONTENT_VIEW` | **`eu.quelltext.gita`** | the app's `onCreate` called `setContentView(I)` on itself; the shim served it |
| `SIGNAL_PAT.FIND_VIEW_BY_ID` | **`eu.quelltext.gita`** | and then asked for a view by id |
| `SIGNAL_PAT.LIFECYCLE` ×2 | `search_to_browser` | the app declares no `Application.onCreate` and no `Activity.onCreate`, so the driver called the **inherited framework** ones |
| `SIGNAL_PAT.LIFECYCLE` | `neolinker`, `termux.boot`, `red_screen`, `badpixels` | same, for the activity |
| `SIGNAL_PAT.FW_CLASS_LOADER` | `neolinker`, `red_screen`, `badpixels`, `search_to_browser` | the engine reached a method nothing declares |
| `classloader.resolve` | `gps_locker`, `headphoneindicator`, `bizzle`, `gita` | a class the shim does not have |
| `java.net.MalformedURLException` | `termux.boot` | the app passed a real URL to `WebView.loadUrl` |

A control asserts the converse: a shim that has not been called records **zero**
events, so a non-empty array in a recording is a fact about the app, not about the
scenario. `gita`'s two view-toolkit observations are the strongest single piece of
evidence here: they are the project's core claim — a browser substrate sees
*more* of what an app did than a device can — demonstrated on an app that nobody
scripted.

## 6. Four defects the integration found, in order of how much they mattered

1. **The engine asked the host about the wrong class.** A call whose only
   declaration was an inherited framework method was handed to the host keyed on
   the *subclass* (`MainActivity.getIntent`), which a shim whose superclass walk
   starts at a class it does not define can never satisfy. Fixed: the host is now
   asked about the class that *declares* the method, which is what a classloader
   resolves.
2. **An `Abstract` vtable slot was reported as "no such method".** The commonest
   shape a framework call has — an app inherits a method it does not implement —
   was being answered with `NoSuchMethodError` *before the host was consulted*.
   `Activity.setContentView(int)`, which the shim implements, was reported as
   missing for a real app. Fixed: a vtable slot resolves to a *declaration*,
   concrete or not, and a bodiless one is routed to the host. This moved
   `eu.quelltext.gita` from **5 instructions to 20**, and moved
   `fr.smarquis.sleeptimer_16200`'s method census from 28 returned to **40**
   (`NoSuchMethodError` 16 → 4) — see the correction note in `tools/dexinterp/README.md`.
3. **The constructor receiver was being passed twice.** The engine's convention is
   `args[0] == this`; the shim's is that a `<init>` receives only its declared
   parameters. Both are right. The symptom was `java.net.URL.<init>(String)`
   parsing the *receiver*, and a later `connect()` reporting "a connection with no
   URL" — **a plausible wrong answer from an instrument**, the worst failure mode
   in this project. Fixed in the adapter.
4. **`to_host_value` rendered an object's key with `Display`.** `Ref` displays as
   `@12`, so every shim-allocated object silently failed to translate and every
   framework call was declined as "unrepresentable". The counter caught it.

Defects 1, 2 and 4 were all *measurement* errors — they made the shim look
smaller than it is, or made it look like it had answered something it had not.
They are the reason the discipline in ADR 0005's "record the conflicts" exists,
and the reason the shim was not grown: growing it before these were fixed would
have added a dozen classes to compensate for an engine that was mis-routing calls.

## 7. What this implies, stated as a projection and labelled as one

The shim covers **215 methods** (ADR 0005's own number) of a platform with roughly
600 000. These 14 apps, at 0–20 instructions of app bytecode each, need **3 more
framework methods** and **2 one-line declaration fixes**. Extrapolating linearly
from that ratio is meaningless, and the interesting fact is *why*: all three are
**inherited methods on a class the app subclasses**, and the two declaration
defects are constructors of `Object` and `BroadcastReceiver`.

The compatibility cost of a framework shim is not a method count; it is the
**transitive closure of the public API of the handful of classes an app extends**.
Reaching `L1_ACTIVITY_RESUMED` means implementing that closure for `Activity` and
`Context` — several hundred methods, most returning objects the shim would then
also have to model, and `Context` alone reaches `ContentResolver`,
`PackageManager`, `getSystemService`, `getResources` and the whole preference and
file-access surface. **On this evidence, "grow the shim until apps run" is a
quarter of work, not a week, and it is the wrong project.** The measurement
instrument is the deliverable; this run is the first evidence that the instrument
measures something.

## 8. The three limits that are *not* shim-work

Structural, and unchanged by any registry growth:

* **`classes*.dex` beyond the first.** 0 for all 14 candidates, so the count is 0
  everywhere — but the interpreter takes one file and the harness reports the
  rest. Merging is a `dexcore` writer feature (ADR 0005 §2, items 1–6) and does
  not exist.
* **`invokedynamic`.** 0 call sites were reached, so ADR 0005's
  `SUB.FW.INVOKEDYNAMIC` — the taxonomy's COMMON-in-modern-apps claim — is
  **untested by this sweep, not refuted**. These 14 apps are small and old. The
  host records a refusal with the bootstrap owner named, so a wider sweep produces
  a count.
* **`resources.arsc`.** Not parsed. `setContentView(int)` is served (that is how
  `gita` got its two view observations) but the *layout id* is meaningless, so
  nothing inflates and no box tree is ever built. That is the structural reason
  `L2` is doubly unreachable.

## 9. Was supersede ever actually shadowed in practice?

**No. 0 shadowing events in 14 real APKs.** Adversarial coverage is a test
instead: `shim/tests/interp_boundary.rs::a_hostile_app_cannot_override_a_shim_method`
feeds the shim's *own emitted DEX* in as a hostile APK — a legal file that declares
all 144 framework classes and carries one class with a real `code_item` — and
asserts **144 shadowed classes**, **1 framework body refused**, and that the shim's
registry still answers.

That is the finding. Supersede is unexercised by honest APKs and is load-bearing
only against hostile ones, which is what ADR 0005 argued for it. It now has a test
rather than an argument, and the number it is tested at is 144.

## 10. The consequence for ADR 0006 and ADR 0007

ADR 0006's open item was *"run the same APK twice under the same policy and
diff"*; ADR 0007 said the arm did not exist because there was no APK to point it
at. There is now:

```rust
shim::syncdiff::repeat_real(policy, n, |p| { /* one real run -> one document */ })
shim::syncdiff::run_real(left, right, n, run)
```

`shim/tests/interp_boundary.rs::the_same_dex_and_policy_produce_the_same_recording`
runs the real-DEX arm at N = 3 and asserts the documents are **byte-identical** and
that the terminal is `L0_PROCESS_STARTED`. So the noise floor of a real APK under
one substrate is measured at **zero leaves varying, on this workload**.

Read that carefully, because it is a comfortable result and a weak one. It is zero
because these apps execute 0–20 instructions before they stop, which is not enough
program for nondeterminism to express itself in. The control has power —
`Workload::RealDex`'s licence text says so in the report itself — but it has not
been pointed at anything with a `HashMap` in it. **The control exists and is
honest; the workload is still too short to mean much.**
