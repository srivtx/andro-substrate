# Shim conformance

**What this file is.** The shim's coverage, measured rather than asserted. Every
number below is produced by `tests/conformance.rs`, which reads the **real** DEX
fixtures committed under `tools/dexcore/tests/fixtures/` and compares what they
reference against what `shim/src/registry.rs` declares. No APK is downloaded, and
`android.jar` is not used as a denominator — a number nobody could act on is not a
measurement.

**Regenerate these numbers:**

```sh
cargo test --manifest-path shim/Cargo.toml --test conformance -- --nocapture
```

If this file and that test ever disagree, the test is right: it reads the code.

---

## 1. Headline numbers

| metric | value |
|---|---|
| registry classes | 144 |
| registry methods | 334 |
| registry fields | 55 |
| referenced types | 90 |
| covered types | 90 |
| referenced methods | 215 |
| covered methods | 59 |
| shim DEX bytes | see `recorder.options.shim_dex_sha256` in a recording |

Method-level coverage of what the corpus actually calls: **59 / 215 = 27.4 %**.
Type-level coverage of what the corpus names: **90 / 90 = 100 %**.

### Read those two numbers together, and read this next

Type coverage is 100 % and it means almost nothing on its own. It says the shim
declares a class for every framework type these six apps mention, so an app fails
at the *next* level — a `NoSuchMethodError` on a specific call — rather than at
the class level. That is worth something: a class-level failure is invisible to a
study that only reports which apps launch, and a method-level failure is
attributable. But 27.4 % of methods means **roughly seven in eight framework
calls in these apps are not implemented at all.**

Against the whole platform, 144 classes and 334 methods is a rounding error.
`android.jar` is on the order of 30 000 classes and 600 000 methods; the shim
covers well under half a percent of the declared surface. `corpus/report.md`
reports 44.76 % of F-Droid apps have no native code, and
`docs/divergence-taxonomy.md` §0.1 says the correct reading of that is *"a
necessary filter, not a sufficient one"*. This file is the concrete version of
that: **this shim will not run a real app end to end, and the number above is
why.**

## 2. What the numbers are measured against

Six F-Droid `classes.dex` extracts, committed in
`tools/dexcore/tests/fixtures/` and catalogued in
[`tools/dexcore/tests/FIXTURES.md`](../tools/dexcore/tests/FIXTURES.md):

| fixture | why it is in the set |
|---|---|
| `pro.rudloff.search_to_browser_2` | smallest (1.9 KB); a plain activity; `MainActivity extends Landroid/app/Activity;` exercises the loader boundary |
| `org.vi_server.red_screen_3` | a `try`/`catch` structure |
| `com.android.adbkeyboard_2` | an **input-method service**, not an activity |
| `com.oF2pks.neolinker_7` | deep `intent-filter` trees; `Build$VERSION` |
| `com.termux.boot_1000` | `JobScheduler`, `WebView`, `Log`, `File`, `BroadcastReceiver` |
| `fr.smarquis.sleeptimer_16200` | the largest (18 KB); notifications, services, alarm, tiles |

This is a deliberately tiny and non-random corpus. It is a **lower bound on
difficulty**, not a sample: these are small, plain, dependency-light apps. A
corpus of commercial apps would be far worse, and `docs/divergence-taxonomy.md`
predicts exactly which families would bite first.

## 3. Per-class method coverage

`covered / referenced` for each framework class the corpus calls. Sorted by how
much of the class is missing, because that is the column that predicts whether an
app gets anywhere.

| class | covered/referenced | note |
|---|---|---|
| `Landroid/app/Activity;` | 3/4 | the one class the corpus is most confident about |
| `Landroid/content/Uri;` `Landroid/net/Uri;` | 2/2 | full |
| `Landroid/webkit/WebView;` | 2/2 | full; `loadUrl` is routed to the egress sink |
| `Ljava/lang/System;` | 1/1 | full; `loadLibrary`/`load` are `UNSATISFIED` |
| `Landroid/app/Application;` | 1/1 | full |
| `Landroid/app/job/JobScheduler;` | 1/1 | declared; the job never runs |
| `Landroid/os/PowerManager;` | 1/1 | a wake lock that changes nothing |
| `Landroid/graphics/drawable/Icon;` | 1/1 | full |
| `Landroid/content/Intent;` | 4/22 | the single worst-covered class the corpus uses heavily |
| `Landroid/app/Notification$Builder;` | 1/19 | second worst; a fluent builder with ~40 setters |
| `Ljava/lang/String;` | 5/13 | `String` alone is 13 referenced methods |
| `Ljava/io/File;` | 2/9 | all of the VFS path goes through it |
| `Landroid/content/Context;` | 3/9 | the most-called class in any Android app |
| `Ljava/lang/StringBuilder;` | 4/8 | |
| `Landroid/view/inputmethod/InputConnection;` | 1/7 | the IME surface; `SUB.INPUT.IME` |
| `Ljava/lang/Object;` | 2/5 | |
| `Landroid/service/quicksettings/TileService;` | 0/5 | declared, none implemented |
| `Landroid/app/PendingIntent;` | 0/5 | declared, none implemented |
| `Landroid/app/AlarmManager;` | 0/3 | declared; alarms enqueued and never fired |
| `Ljava/util/List;` | 1/4 | |
| `Landroid/service/quicksettings/Tile;` | 0/3 | |
| `Landroid/app/NotificationChannel;` | 0/3 | |
| `Ljava/util/ListIterator;` | 0/3 | |
| `Ljava/lang/Enum;` | 1/3 | |
| `Ljava/util/Collection;` | 1/3 | |
| `Landroid/os/Bundle;` | 0/3 | **declared, none implemented** — see §4 |
| `Landroid/app/JobInfo$Builder;` | 1/4 | |
| `Landroid/widget/Toast;` | 2/4 | |
| `Landroid/media/AudioManager;` | 2/4 | |
| `Landroid/view/Window;` | 1/4 | |
| `Landroid/net/Uri$Builder;` | 3/4 | |
| `Landroid/app/NotificationManager;` | 1/5 | |
| `Ljava/util/Arrays;` | 0/2 | |
| `Landroid/os/BaseBundle;` | 0/2 | |
| `Landroid/content/IntentFilter;` | 1/2 | |
| `Landroid/inputmethodservice/InputMethodService;` | 0/2 | the whole IME app class |
| `Landroid/app/IntentService;` | 0/2 | |
| `Ljava/text/DateFormat;` | 1/2 | recorded: locale and timezone are `SUB.RES.LOCALE`/`TIMEZONE` |
| `Landroid/service/notification/StatusBarNotification;` | 0/2 | |
| `Landroid/view/KeyEvent;` | 0/2 | |
| `Landroid/content/Context;` see also `getSystemService(Class)` | 0/1 | the `Class` overload is absent |
| `Landroid/util/Log;` | 0/1 | one overload, `Log.w(String, Throwable)` |
| `Landroid/util/Base64;` | 0/1 | the `int flags` overload |
| `Landroid/view/View;` | 0/2 | `setAlpha`, `setEnabled` |
| `Landroid/view/LayoutInflater;` | 0/1 | `inflate(int, ViewGroup)` |
| `Landroid/content/res/Resources;` | 0/1 | `getString(int, Object[])` |
| `Landroid/content/ComponentName;` | 0/1 | the `(Context, Class)` constructor |
| `Landroid/content/BroadcastReceiver;` | 0/1 | the no-arg constructor |
| `Landroid/app/Service;` | 0/1 | `stopForeground(int)` |
| `Landroid/app/job/JobService;` | 0/1 | the no-arg constructor |
| `Landroid/app/Notification$Action$Builder;` | 0/2 | |
| `Landroid/app/job/JobParameters;` | 0/2 | |
| `Ljava/lang/Boolean;` `Ljava/lang/Date;` `Ljava/lang/OutOfMemoryError;` `Ljava/lang/RuntimeException;` `Ljava/lang/reflect/Array;` `Ljava/util/NoSuchElementException;` `Landroid/graphics/Color;` `Landroid/view/inputmethod/ExtractedTextRequest;` | 0/1 each | declared so the type resolves |

### `Landroid/os/Bundle;` at 0/3 is the most misleading line in this table

The shim *does* implement `putString`, `getString`, `putInt`, `getInt`,
`putBoolean`, `getBoolean`, `containsKey`, `keySet`, `isEmpty` and `size` — and
the fixtures reference three *other* `Bundle` methods that are not implemented. A
reader who saw "0/3" and stopped would conclude the wrong thing. It is listed here
because the point of the table is to be the number a reader has to trust, not the
number that flatters.

## 4. Behaviour mix

| behaviour | methods | what it means |
|---|---|---|
| `dispatch` | 141 | a named observation and a recorded event |
| `inert` | 78 | declared so a type resolves; returns a value of the right shape, records nothing |
| `construct` | 69 | `<init>`; records nothing on its own |
| `field` | 28 | a field accessor; the field *name* is recorded, the value is not |
| `probe` | 18 | a read of a system fact; the value and the taxonomy ID are recorded |

141 + 18 = **159 observation-bearing methods against 78 inert ones.** A shim with
the ratio the other way round would be a compatibility layer, and
`tests/conformance.rs` fails if it ever does.

`Inert` is not a euphemism for "works". `java.lang.String.substring` is declared
and `Inert`, so a string method returns a correctly-typed value and the
*interpreter* — which does not exist yet — is expected to supply the real
behaviour. The registry is a signature manifest; the semantics live in
`src/behaviour.rs`. Any `Inert` method an app depends on for a *side effect* is a
divergence the study will not see, and that is stated rather than hidden.

## 5. What a "conformant" app cannot rely on

A conformant app, in this project's sense, is one whose behaviour under the shim
can be *measured*. Everything below is a case where it cannot be, and each entry
is a place a recording will be silent in a way that is not obvious from the
recording.

| it cannot rely on | what happens | taxonomy |
|---|---|---|
| **the shim implementing its framework method** | 156 of 215 referenced methods do not exist. An app hits `NoSuchMethodError`, which is recorded — but the *class* resolved, so a study that only counts "classes touched" sees a false positive. | `SUB.FW.CLASS_LOADER` |
| **`invokedynamic`** | The shim has no `method_handle_item` or `call_site_item`, and `dexcore`'s writer emits neither. Modern DEX is saturated with `invokedynamic`, so a large fraction of contemporary app behaviour **never reaches a shim method at all** and is structurally invisible to this layer. | `SUB.FW.INVOKEDYNAMIC` |
| **any resource** | No `resources.arsc` is parsed, no name→id map exists, and the app's own layout XML is never inflated. Every `getString`, `getIdentifier` and `setContentView(int)` returns null or 0. | `SUB.RES.ARSC` |
| **pixels** | Layout produces geometry, not pixels. `BoxNode.painted` is always `false` and there is no rasteriser. A wrong-pixel bug is invisible; so is `SUB.GFX.EXTENSIONS`, `SUB.GFX.VULKAN`, `SUB.GFX.EGL_CONTEXT`. | `SUB.GFX.TEXT_RENDER` only |
| **a font** | The advance table is documented and deterministic, not Roboto. Measurements will not match a phone's. | `SUB.GFX.TEXT_RENDER` |
| **any network** | Every request is recorded and refused, on every policy value, at the sink. No response, status, redirect or TLS session is observable, ever. The `network` axis can change what the app is *shown* (`synthetic_loopback` returns a declared 200) and cannot change what the sink *permits*. | `SUB.NET.EGRESS` |
| **any native code** | No ELF loader. Every `native` method and every `loadLibrary` is `UNSATISFIED`. | `SUB.NATIVE.*` |
| **real `/proc`, `/sys`** | Both are fabricated, and *which* fabrication is a declared parameter (`substrate_policy.system_fs`): plausible content, an empty-but-existing file, or `ENOENT`. Under the default `/proc/self/maps` is empty, `/proc/uptime` is 0, and `TracerPid` is 0 — a *lie*, and a recorded one. | `SUB.KERNEL.*` |
| **another app existing** | The substrate holds exactly one app, so every cross-app `PackageManager` query answers "not installed", with no exception. The other two values of the axis report every package installed (with a list whose contents are *not* materialised) or throw `NameNotFoundException`. | `SUB.IPC.PACKAGE_MANAGER_OTHER` |
| **Binder, services, alarms, jobs** | Declared, recorded, and never delivered. An app that defers work to an `AlarmManager` or a `JobScheduler` produces no symptom at all. | `SUB.IPC.*` |
| **a boot** | No `BOOT_COMPLETED`, no system broadcast, ever. | `SUB.IPC.BROADCAST` |
| **input** | No `MotionEvent`, no `KeyEvent`, no soft keyboard, no click ever delivered. An app that gates its login on a tap produces nothing and reports nothing. | `SUB.INPUT.*` |
| **vsync** | No display, so `Choreographer` never posts. The `Handler`/`MessageQueue` are recorded and never drained; `queue.size()` is the measurement. | `SUB.TIME.VSYNC` |
| **wall-clock time** | `System.currentTimeMillis()` returns 0, not the host's clock, so a recording is reproducible. The `time` axis can scale, freeze or replace it, and a `host_real` recording is declared `reproducible: false`. | `SUB.TIME.WALL_CLOCK` |
| **its own behaviour not being decided by the shim** | A shim that terminates every side effect observes a *different program*, so every fact downstream of a refusal is a **joint** property of app and shim. `docs/decisions/0006-substrate-policy.md` makes the substrate a declared parameter so the dependency is measurable, and it does not claim to remove it. A single substrate run is not a measurement of the app. | all of them |
| **its own class, if it defines a framework one** | A hostile APK's `Landroid/app/Activity;` is shadowed by the shim's. The shim wins by construction, and the collision is recorded as `shim_supersedes_app` — because the alternative would make the shim's own boundary an attack surface. | `SUB.FW.CLASS_LOADER` |
| **reflection over an incomplete surface** | `Class.forName` and `Method.invoke` are dispatched through the *same* table as a direct call, so a reflective call and a direct one are indistinguishable. Good for coverage, fatal for attribution. | `SUB.FW.REFLECTION` |
| **ART's execution tier** | There is no AOT `odex` and no JIT warm-up. A slow app in a substrate is the interpreter's cost, and a recording cannot separate the two. | `SUB.CPU.TIERING` |

## 5a. The substrate is a parameter, and the recording says which way it was set

`SubstratePolicy` is the shim's own behaviour as a declared value. Every value the
shim fabricates is produced by one of its five axes, and every fabricated
observation carries the axis that produced it, so a `Build.FINGERPRINT` read can
say *which* substrate answered it rather than leaving a reader to infer it from
the shape of the value.

| axis | values | the default is |
|---|---|---|
| `identity` | `fabricated` · `withheld` · `refusing` | `fabricated` |
| `system_fs` | `fabricated` · `empty` · `absent` | `fabricated` |
| `cross_app_packages` | `subject_only` · `all_present` · `error` | `subject_only` |
| `network` | `record_and_deny` · `synthetic_loopback` | `record_and_deny` |
| `time` | `virtual` · `scaled{n,d}` · `frozen` · `host_real` | `virtual` |

**The default is the pre-existing behaviour on every axis**, so the numbers above
and the rest of this document describe the same shim as before, and the committed
`recordings/synthetic.recording.json` is the same capture with a declaration
attached. A family whose default were the obvious null-substrate would make the
plausible one look like a curiosity — and the plausible one is the confound.

Three things the axes provably cannot do, with the test for each:

- **No value can enable egress.** `EgressSink` holds no policy field, its
  `request` returns `Result<Never, EgressDenial>`, and
  `network.attempts[].result` is `blocked_by_policy` under *both* network values.
  `tests/policy.rs` drives all 162 reproducible combinations against a live
  `TcpListener`.
- **No value can capture a body, a header value or a query value.** The policy type
  is five enums and a synthesised response is a status, a length and a content
  type. `tests/policy.rs` runs 108 combinations with three canaries and requires
  them absent from the events, the state and the serialised document.
- **No value can be set from the environment.** The only way to run a non-default
  substrate is `Shim::with_policy(..)`, so "which substrate produced this" is a
  value in a struct. `tests/egress_denial.rs` forbids `std::env` outright and its
  source scan now covers `src/policy.rs` and `src/differential.rs`.

`docs/decisions/0006-substrate-policy.md` has the full decision, the worked
differential, and — the part that matters most — what the family still cannot
separate from the app.

## 6. The classloader boundary

The shim resolves in the same classloader as app code via
[supersede](../docs/decisions/0005-shim-and-observation.md): a `Landroid/…` or
`Ljava/…` reference resolves in the shim DEX **even when the app's own DEX also
defines it**, and the shadowing is recorded as `Resolution::ShimSupersedesApp`.

The DEX this shim emits is a **signature manifest**, not a program. Every method
is `ACC_NATIVE` with no `code_item`, so a misplaced DEX throws
`UnsatisfiedLinkError` rather than silently returning `0` — the safe default for
an instrument is the one that is unusable when misplaced. The semantics live in
`src/dispatch.rs` and `src/behaviour.rs`, keyed on `(class, name)`.

`tests/dex_roundtrip.rs` checks all of that against the emitted bytes.

## 7. The `dexcore` defect this shim works around

`dexcore::writer::intern_type_list` allocates `4 + 2n` bytes per `type_list` and
then appends `u32::to_le_bytes()` for each index, writing **4** bytes per element
instead of 2. Every `type_list` with two or more elements is therefore
mis-encoded: `OutputStream.write([B I I)V` is emitted as `([B F I)`, and a loader
that trusts the `proto_ids` entry resolves a signature the call site never
encoded.

`tools/dexcore` is Wave 1 and owned elsewhere, so the defect is **reported, not
fixed here**. `shim::emit::repair_type_lists` corrects the emitted bytes in place,
reserves nothing, moves no offset, and reseals the SHA-1 and Adler-32; then
`verify_prototypes` re-reads the file and refuses to hand it over unless every
method matches the registry. `tests/dex_roundtrip.rs::dexcore_still_widens_type_lists`
prints a note on every run while the workaround is still needed. Removing it is a
deletion plus a two-line change once `dexcore` is fixed.

## 8. Adding to the shim

Add a row to `shim/src/registry.rs` and nothing else. The table drives the emitted
DEX, the dispatcher's handler selection, the conformance table and the
`CONFORMANCE.md` drift test. A `Behaviour::Dispatch` key with no handler is a
hard error at run time and a test failure, so a method cannot be added that
silently does nothing.

---

## 9. Appendix: the complete table

Every class in `shim/src/registry.rs` and every method on it, with the
`Behaviour` that decides what the method does when the dispatcher runs it:

- `ctor` — a constructor. Records nothing on its own.
- `dispatch` — a named observation and a recorded event. See
  `src/behaviour.rs`.
- `probe` — a read of a system fact; the value and its taxonomy ID are recorded.
- `get` / `set` — a field accessor. The field *name* is recorded; the value is not.
- `inert` — declared so a type resolves, and it returns a value of the right
  shape. The semantics are the interpreter's, and that is stated in §4.

Generated by the same registry the DEX is emitted from, so the table cannot
describe a class the file does not contain.

| class | extends | implements | fields | methods |
|---|---|---|---|---|
| `Landroid/app/Activity;` | `Landroid/content/ContextWrapper;` | — | 1 | `<init>`·ctor, `onCreate`·dispatch, `onStart`·dispatch, `onResume`·dispatch, `onPause`·dispatch, `onStop`·dispatch, `onDestroy`·dispatch, `setContentView`·dispatch, `findViewById`·dispatch, `finish`·dispatch, `getWindow`·dispatch |
| `Landroid/app/ActivityContext;` | `Landroid/content/Context;` | — | 0 | `<init>`·ctor, `startActivity`·dispatch, `startService`·dispatch |
| `Landroid/app/Application;` | `Landroid/content/ContextWrapper;` | — | 0 | `<init>`·ctor, `onCreate`·dispatch |
| `Landroid/content/Context;` | `Ljava/lang/Object;` | — | 0 | `getPackageName`·dispatch, `getPackageManager`·dispatch, `getApplicationInfo`·dispatch, `getSystemService`·dispatch, `getFilesDir`·dispatch, `getCacheDir`·dispatch, `getDataDir`·dispatch, `getExternalFilesDir`·dispatch, `openFileInput`·dispatch, `openFileOutput`·dispatch, `getString`·dispatch, `getAssets`·dispatch, `sendBroadcast`·dispatch, `registerReceiver`·dispatch |
| `Landroid/content/ContextWrapper;` | `Landroid/content/Context;` | — | 0 | `<init>`·ctor |
| `Landroid/content/Intent;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 6 | `<init>`·ctor, `<init>`·ctor, `getAction`·get, `setAction`·set, `getData`·get, `setData`·set, `getPackageName`·get, `addFlags`·set |
| `Landroid/content/ComponentName;` | `Landroid/os/Parcelable;` | — | 0 | `<init>`·ctor, `getPackageName`·get, `getClassName`·get |
| `Landroid/content/BroadcastReceiver;` | `Ljava/lang/Object;` | — | 0 | `onReceive`·dispatch |
| `Landroid/content/pm/PackageManager;` | `Ljava/lang/Object;` | — | 0 | `getPackageInfo`·dispatch, `getApplicationInfo`·dispatch, `getInstalledPackages`·dispatch, `queryIntentActivities`·dispatch, `hasSystemFeature`·dispatch, `getInstallerPackageName`·dispatch |
| `Landroid/content/pm/PackageInfo;` | `Ljava/lang/Object;` | — | 3 | `<init>`·ctor |
| `Landroid/content/pm/ApplicationInfo;` | `Ljava/lang/Object;` | — | 6 | `<init>`·ctor, `isDebuggable`·dispatch |
| `Landroid/os/Bundle;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `<init>`·ctor, `<init>`·ctor, `putString`·dispatch, `getString`·dispatch, `putInt`·dispatch, `getInt`·dispatch, `putBoolean`·dispatch, `getBoolean`·dispatch, `containsKey`·dispatch, `keySet`·dispatch, `isEmpty`·dispatch, `size`·dispatch |
| `Landroid/os/BaseBundle;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `containsKey`·dispatch |
| `Landroid/os/PersistableBundle;` | `Landroid/os/BaseBundle;` | — | 0 | `<init>`·ctor |
| `Landroid/os/Parcelable;` | `Ljava/lang/Object;` | — | 0 | `describeContents`·inert |
| `Landroid/os/Parcel;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `writeString`·dispatch, `readString`·dispatch, `obtain`·dispatch, `recycle`·dispatch |
| `Landroid/os/Handler;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `post`·dispatch, `postDelayed`·dispatch, `removeCallbacks`·dispatch, `getLooper`·dispatch |
| `Landroid/os/Looper;` | `Ljava/lang/Object;` | — | 0 | `getMainLooper`·dispatch, `prepare`·dispatch, `loop`·dispatch, `quit`·dispatch |
| `Landroid/os/MessageQueue;` | `Ljava/lang/Object;` | — | 0 | `size`·dispatch |
| `Landroid/os/SystemClock;` | `Ljava/lang/Object;` | — | 0 | `uptimeMillis`·probe, `elapsedRealtime`·probe, `currentThreadTimeMillis`·probe |
| `Landroid/os/Build;` | `Ljava/lang/Object;` | — | 13 | `<init>`·ctor, `getRadioVersion`·probe |
| `Landroid/os/Build$VERSION;` | `Ljava/lang/Object;` | — | 3 | — |
| `Landroid/os/Environment;` | `Ljava/lang/Object;` | — | 0 | `getExternalStorageDirectory`·dispatch, `getExternalStorageState`·dispatch |
| `Landroid/util/Log;` | `Ljava/lang/Object;` | — | 0 | `v`·probe, `d`·probe, `i`·probe, `w`·probe, `e`·probe, `println`·probe |
| `Landroid/util/Base64;` | `Ljava/lang/Object;` | — | 0 | `encodeToString`·probe |
| `Landroid/view/View;` | `Ljava/lang/Object;` | — | 3 | `<init>`·ctor, `measure`·dispatch, `layout`·dispatch, `getWidth`·get, `getHeight`·get, `setVisibility`·set, `getVisibility`·get, `setOnClickListener`·dispatch |
| `Landroid/view/ViewGroup;` | `Landroid/view/View;` | — | 0 | `addView`·dispatch, `removeView`·dispatch, `getChildCount`·dispatch, `getChildAt`·dispatch |
| `Landroid/view/ViewGroup$LayoutParams;` | `Ljava/lang/Object;` | — | 5 | `<init>`·ctor |
| `Landroid/view/LayoutInflater;` | `Ljava/lang/Object;` | — | 0 | `from`·dispatch |
| `Landroid/view/Window;` | `Ljava/lang/Object;` | — | 0 | `setContentView`·dispatch, `addFlags`·dispatch |
| `Landroid/webkit/WebView;` | `Landroid/view/View;` | — | 0 | `<init>`·ctor, `loadUrl`·probe, `addJavascriptInterface`·probe |
| `Landroid/widget/TextView;` | `Landroid/view/View;` | — | 0 | `<init>`·ctor, `setText`·dispatch, `getText`·get |
| `Landroid/widget/Button;` | `Landroid/widget/TextView;` | — | 0 | `<init>`·ctor |
| `Landroid/widget/EditText;` | `Landroid/widget/TextView;` | — | 0 | `<init>`·ctor, `getText`·get |
| `Landroid/widget/ImageView;` | `Landroid/view/View;` | — | 0 | `<init>`·ctor, `setImageResource`·dispatch |
| `Landroid/widget/LinearLayout;` | `Landroid/view/ViewGroup;` | — | 2 | `<init>`·ctor, `setOrientation`·dispatch |
| `Landroid/widget/FrameLayout;` | `Landroid/view/ViewGroup;` | — | 0 | `<init>`·ctor |
| `Landroid/widget/Toast;` | `Ljava/lang/Object;` | — | 0 | `makeText`·probe, `show`·probe |
| `Landroid/graphics/drawable/Drawable;` | `Ljava/lang/Object;` | — | 0 | `getIntrinsicWidth`·get, `getIntrinsicHeight`·get |
| `Landroid/net/Uri;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `<init>`·ctor, `parse`·dispatch, `toString`·get, `getScheme`·get, `getHost`·get, `getPath`·get, `getQuery`·get |
| `Landroid/text/TextUtils;` | `Ljava/lang/Object;` | — | 0 | `isEmpty`·get |
| `Landroid/app/NotificationManager;` | `Ljava/lang/Object;` | — | 0 | `notify`·dispatch, `areNotificationsEnabled`·dispatch |
| `Landroid/app/Notification;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `<init>`·ctor, `setContentTitle`·inert, `setSmallIcon`·dispatch |
| `Landroid/app/Notification$Builder;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `setContentTitle`·inert, `build`·inert |
| `Landroid/app/Notification$Action;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | — |
| `Landroid/app/Notification$Action$Builder;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor |
| `Landroid/app/NotificationChannel;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor |
| `Landroid/service/notification/StatusBarNotification;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | — |
| `Landroid/service/quicksettings/Tile;` | `Ljava/lang/Object;` | — | 0 | `updateTile`·dispatch |
| `Landroid/service/quicksettings/TileService;` | `Landroid/app/Service;` | — | 0 | `onStartListening`·dispatch, `onClick`·dispatch |
| `Landroid/graphics/Color;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 3 | `alpha`·inert, `red`·inert, `rgb`·inert |
| `Landroid/graphics/drawable/Icon;` | `Ljava/lang/Object;` | — | 0 | `createWithResource`·dispatch |
| `Landroid/inputmethodservice/InputMethodService;` | `Landroid/app/Service;` | — | 0 | `onCreateInputView`·dispatch, `onEvaluateFullscreenMode`·dispatch |
| `Landroid/view/inputmethod/InputConnection;` | `Ljava/lang/Object;` | — | 0 | `commitText`·dispatch, `deleteSurroundingText`·dispatch |
| `Landroid/view/inputmethod/ExtractedText;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `<init>`·ctor, `text`·inert |
| `Landroid/view/inputmethod/ExtractedTextRequest;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `getToken`·inert |
| `Ljava/lang/Throwable;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `<init>`·ctor, `getMessage`·inert, `getStackTrace`·probe |
| `Ljava/lang/Exception;` | `Ljava/lang/Throwable;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/RuntimeException;` | `Ljava/lang/Exception;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/Error;` | `Ljava/lang/Throwable;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/UnsatisfiedLinkError;` | `Ljava/lang/Error;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/ClassNotFoundException;` | `Ljava/lang/ReflectiveOperationException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/ReflectiveOperationException;` | `Ljava/lang/Exception;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/IllegalArgumentException;` | `Ljava/lang/RuntimeException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/NullPointerException;` | `Ljava/lang/RuntimeException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/Object;` | `— (root)` | — | 0 | `toString`·inert, `equals`·inert, `hashCode`·inert |
| `Ljava/lang/String;` | `Ljava/lang/Object;` | Landroid/os/Parcelable;, Ljava/lang/CharSequence;, Ljava/lang/Comparable; | 0 | `length`·inert, `isEmpty`·inert, `concat`·inert, `substring`·inert, `startsWith`·inert, `contains`·inert, `trim`·inert, `toLowerCase`·inert, `toUpperCase`·inert |
| `Ljava/lang/CharSequence;` | `Ljava/lang/Object;` | — | 0 | `toString`·inert, `length`·inert |
| `Ljava/lang/Comparable;` | `Ljava/lang/Object;` | — | 0 | `compareTo`·inert |
| `Ljava/lang/System;` | `Ljava/lang/Object;` | — | 0 | `loadLibrary`·dispatch, `load`·dispatch, `currentTimeMillis`·probe, `getProperty`·dispatch |
| `Ljava/lang/Class;` | `Ljava/lang/Object;` | — | 0 | `forName`·dispatch, `getName`·inert, `getMethod`·dispatch |
| `Ljava/lang/reflect/Method;` | `Ljava/lang/Object;` | — | 0 | `invoke`·dispatch, `getName`·inert |
| `Ljava/lang/Thread;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `sleep`·dispatch, `currentThread`·dispatch, `getName`·inert |
| `Ljava/lang/StringBuilder;` | `Ljava/lang/Object;` | Ljava/lang/CharSequence;, Ljava/lang/Appendable; | 0 | `<init>`·ctor, `append`·inert, `toString`·inert, `length`·inert |
| `Ljava/lang/Appendable;` | `Ljava/lang/Object;` | — | 0 | `append`·inert |
| `Ljava/lang/Iterable;` | `Ljava/lang/Object;` | — | 0 | `iterator`·inert |
| `Ljava/lang/Enum;` | `Ljava/lang/Object;` | Ljava/lang/Comparable;, Landroid/os/Parcelable; | 0 | `name`·inert, `ordinal`·inert |
| `Ljava/lang/Boolean;` | `Ljava/lang/Object;` | Ljava/lang/Comparable; | 0 | `booleanValue`·inert, `parseBoolean`·inert |
| `Ljava/lang/Long;` | `Ljava/lang/Number;` | Ljava/lang/Comparable; | 0 | `longValue`·inert, `parseLong`·inert |
| `Ljava/lang/Integer;` | `Ljava/lang/Number;` | Ljava/lang/Comparable; | 2 | `intValue`·inert, `parseInt`·inert, `toString`·inert |
| `Ljava/lang/Number;` | `Ljava/lang/Object;` | — | 0 | `intValue`·inert, `longValue`·inert, `doubleValue`·inert |
| `Ljava/lang/IndexOutOfBoundsException;` | `Ljava/lang/RuntimeException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/NumberFormatException;` | `Ljava/lang/IllegalArgumentException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/UnsupportedOperationException;` | `Ljava/lang/RuntimeException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/StackOverflowError;` | `Ljava/lang/Error;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/OutOfMemoryError;` | `Ljava/lang/Error;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/NoSuchMethodError;` | `Ljava/lang/Error;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/NoSuchFieldError;` | `Ljava/lang/Error;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/NoSuchMethodException;` | `Ljava/lang/ReflectiveOperationException;` | — | 0 | `<init>`·ctor |
| `Ljava/lang/StackTraceElement;` | `Ljava/lang/Object;` | — | 0 | `getClassName`·inert, `getMethodName`·inert, `getLineNumber`·inert |
| `Ljava/lang/annotation/Annotation;` | `Ljava/lang/Object;` | — | 0 | `annotationType`·inert |
| `Ljava/lang/annotation/ElementType;` | `Ljava/lang/Enum;` | — | 2 | — |
| `Ljava/lang/annotation/RetentionPolicy;` | `Ljava/lang/Enum;` | — | 1 | — |
| `Ljava/lang/annotation/Retention;` | `Ljava/lang/Object;` | Ljava/lang/annotation/Annotation; | 0 | — |
| `Ljava/lang/annotation/Target;` | `Ljava/lang/Object;` | Ljava/lang/annotation/Annotation; | 0 | — |
| `Ljava/lang/reflect/Array;` | `Ljava/lang/Object;` | — | 0 | `getLength`·inert |
| `Ljava/io/Serializable;` | `Ljava/lang/Object;` | — | 0 | — |
| `Ljava/util/Iterator;` | `Ljava/lang/Object;` | — | 0 | `hasNext`·inert, `next`·inert |
| `Ljava/util/ListIterator;` | `Ljava/util/Iterator;` | — | 0 | — |
| `Ljava/util/Comparator;` | `Ljava/lang/Object;` | — | 0 | `compare`·inert |
| `Ljava/util/RandomAccess;` | `Ljava/lang/Object;` | — | 0 | — |
| `Ljava/util/NoSuchElementException;` | `Ljava/lang/RuntimeException;` | — | 0 | `<init>`·ctor |
| `Ljava/util/HashMap;` | `Ljava/lang/Object;` | Ljava/util/Map; | 0 | `<init>`·ctor, `put`·inert, `get`·inert, `size`·inert |
| `Ljava/util/Map;` | `Ljava/lang/Object;` | — | 0 | `size`·inert, `get`·inert |
| `Ljava/util/Date;` | `Ljava/lang/Object;` | Ljava/lang/Comparable;, Ljava/io/Serializable; | 0 | `<init>`·ctor, `getTime`·inert, `toString`·inert |
| `Ljava/text/DateFormat;` | `Ljava/lang/Object;` | — | 0 | `getDateTimeInstance`·probe, `format`·inert |
| `Landroid/content/IntentFilter;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `addAction`·inert, `addCategory`·inert |
| `Landroid/content/res/Resources;` | `Ljava/lang/Object;` | — | 0 | `getString`·dispatch, `getIdentifier`·dispatch, `getDisplayMetrics`·dispatch |
| `Landroid/content/res/AssetManager;` | `Ljava/lang/Object;` | — | 0 | `open`·dispatch, `list`·dispatch |
| `Landroid/util/DisplayMetrics;` | `Ljava/lang/Object;` | — | 2 | `<init>`·ctor |
| `Landroid/net/Uri$Builder;` | `Ljava/lang/Object;` | — | 0 | `scheme`·inert, `authority`·inert, `path`·inert, `build`·inert |
| `Landroid/app/Service;` | `Landroid/content/ContextWrapper;` | — | 0 | `onBind`·dispatch, `onStartCommand`·dispatch, `stopSelf`·dispatch |
| `Landroid/app/IntentService;` | `Landroid/app/Service;` | — | 0 | `onHandleIntent`·dispatch |
| `Landroid/app/AlarmManager;` | `Ljava/lang/Object;` | — | 0 | `set`·dispatch, `setExact`·dispatch, `cancel`·dispatch |
| `Landroid/app/PendingIntent;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | `getBroadcast`·inert |
| `Landroid/app/job/JobScheduler;` | `Ljava/lang/Object;` | — | 0 | `schedule`·dispatch |
| `Landroid/app/job/JobService;` | `Landroid/app/Service;` | — | 0 | `onStartJob`·dispatch |
| `Landroid/app/job/JobInfo;` | `Ljava/lang/Object;` | Landroid/os/Parcelable; | 0 | — |
| `Landroid/app/job/JobInfo$Builder;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `setPeriodic`·inert, `build`·inert |
| `Landroid/app/job/JobParameters;` | `Ljava/lang/Object;` | — | 0 | — |
| `Landroid/media/AudioManager;` | `Ljava/lang/Object;` | — | 0 | `getStreamVolume`·dispatch, `setStreamVolume`·dispatch |
| `Landroid/os/PowerManager;` | `Ljava/lang/Object;` | — | 0 | `newWakeLock`·dispatch, `isScreenOn`·dispatch, `isIgnoringBatteryOptimizations`·dispatch |
| `Landroid/os/PowerManager$WakeLock;` | `Ljava/lang/Object;` | — | 0 | `acquire`·dispatch, `release`·dispatch, `isHeld`·dispatch |
| `Landroid/view/KeyEvent;` | `Ljava/lang/Object;` | — | 1 | — |
| `Landroid/view/WindowManager$LayoutParams;` | `Ljava/lang/Object;` | — | 2 | `<init>`·ctor |
| `Ljava/io/IOException;` | `Ljava/lang/Throwable;` | — | 0 | `<init>`·ctor, `<init>`·ctor |
| `Ljava/io/InputStream;` | `Ljava/lang/Object;` | — | 0 | `read`·dispatch, `close`·dispatch |
| `Ljava/io/OutputStream;` | `Ljava/lang/Object;` | — | 0 | `write`·dispatch, `close`·dispatch |
| `Ljava/io/FileInputStream;` | `Ljava/io/InputStream;` | — | 0 | `<init>`·ctor |
| `Ljava/io/FileOutputStream;` | `Ljava/io/OutputStream;` | — | 0 | `<init>`·ctor |
| `Ljava/io/ByteArrayOutputStream;` | `Ljava/io/OutputStream;` | — | 0 | `<init>`·ctor |
| `Ljava/io/File;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `getAbsolutePath`·dispatch, `exists`·dispatch, `length`·dispatch, `isDirectory`·dispatch, `list`·dispatch, `delete`·dispatch |
| `Ljava/net/MalformedURLException;` | `Ljava/io/IOException;` | — | 0 | `<init>`·ctor |
| `Ljava/net/URL;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `openConnection`·dispatch, `toString`·get, `getProtocol`·get, `getHost`·get, `getPort`·get, `getPath`·get, `getQuery`·get |
| `Ljava/net/URLConnection;` | `Ljava/lang/Object;` | — | 0 | `connect`·dispatch, `setRequestProperty`·dispatch, `setConnectTimeout`·dispatch, `setReadTimeout`·dispatch |
| `Ljava/net/HttpURLConnection;` | `Ljava/net/URLConnection;` | — | 0 | `setRequestMethod`·dispatch, `getResponseCode`·dispatch, `getInputStream`·dispatch, `setDoOutput`·dispatch, `getOutputStream`·dispatch |
| `Ljava/net/ConnectException;` | `Ljava/io/IOException;` | — | 0 | `<init>`·ctor |
| `Ljava/net/Socket;` | `Ljava/lang/Object;` | — | 0 | `<init>`·ctor, `<init>`·ctor, `connect`·dispatch, `getInputStream`·dispatch, `getOutputStream`·dispatch |
| `Ljava/util/ArrayList;` | `Ljava/lang/Object;` | Ljava/util/List;, Ljava/util/Collection;, Ljava/lang/Iterable; | 0 | `<init>`·ctor, `add`·inert, `size`·inert, `isEmpty`·inert, `get`·inert |
| `Ljava/util/List;` | `Ljava/lang/Object;` | Ljava/util/Collection; | 0 | `size`·inert, `isEmpty`·inert |
| `Ljava/util/Collection;` | `Ljava/lang/Object;` | Ljava/lang/Iterable; | 0 | `size`·inert |
| `Ljava/util/Set;` | `Ljava/lang/Object;` | Ljava/util/Collection; | 0 | `size`·inert |
| `Ljava/util/Arrays;` | `Ljava/lang/Object;` | — | 0 | — |
| `Ljava/util/regex/Pattern;` | `Ljava/lang/Object;` | — | 0 | `compile`·dispatch, `matcher`·dispatch |
