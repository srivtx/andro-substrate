# Divergence taxonomy: substrate assumptions an Android app can make

**Status:** hypothesis space, pre-registered. **No results.** Nothing in this
document is a finding. Every entry is a falsifiable claim about what *might*
happen, written down *before* measuring, so that the measurement cannot be
reverse-engineered to look good.

**Registry:** 16 families, each with a stable ID namespace. IDs are permanent.
Adding entries is fine; changing an existing ID's meaning is not.

**Normative reading.** For each assumption:

- **Assumption** — stated so that it can be *refuted* by an observation.
- **Symptom** — what the app does when the assumption is violated.
- **Detection** — the signal in the ground-truth recording that establishes the
  assumption is load-bearing for *this* app (`oracle/RECORDING.md` §7).
- **Class** — the trichotomy. This is the most consequential column.
  - **DEGRADE** — the app runs, a capability is reduced, usually visibly.
  - **REFUSE** — the app will not start, or blocks a specific flow, usually
    visibly, usually with a message.
  - **MISBEHAVE** — the app appears to run and produces *silently wrong* results.
    No error, no log, no user-visible symptom. **This is the class that matters
    most**, because it is the only one an evaluation that reports crash counts
    will miss entirely.
- **Prior** — COMMON / OCCASIONAL / RARE, plus provenance:
  - `[Vn]` = traced to a verified source listed in §6.
  - **CONJECTURE** = this document's own prior, no external support. Most entries.
  - **UNVERIFIED** = a claim with a source that could not be checked.

---

## 0. Framing, stated before the taxonomy so it cannot be smuggled in later

### 0.1 "No native code" does not imply "will run"

This is the single most likely misreading of the project and it is false.

A DEX-only corpus is a **necessary filter**, not a sufficient one. It eliminates
the `SUB.NATIVE.*` family and nothing else. Every other family in this document
— roughly 140 further assumptions — remains live, and several of them
(`SUB.TRUST.PLAY_INTEGRITY`, `SUB.IPC.BROADCAST`, `SUB.CPU.TIERING`) refuse apps
outright with no native code anywhere in sight.

The honest statement of the native-code contribution is: *"native code is a
sufficient reason to reject an app for a browser-native substrate, and is not
necessary."* Any result that reports "X% of apps are DEX-only" must not be
reported as "X% of apps will run".

### 0.2 The substrate is stronger in some respects, and weaker in others

Stated symmetrically, because a one-sided framing is a rhetorical device, not a
finding.

**Stronger than a real Android device:**

| Property | Why it is stronger |
|---|---|
| No syscall surface | There is no kernel attack surface to reach. An app cannot `ptrace`, `mount`, `ioctl` or `mknod`, because none of those exist. Android apps that reach for `/proc/<pid>/mem` or `ptrace` have no target at all. |
| No filesystem | Nothing to traverse, poison, or race. Path-traversal and symlink attacks have no surface. |
| Hard egress denial | Egress is denied *by construction* rather than by firewall rules, and cannot be reconfigured by the app. Strictly stronger than Android, where a compromised app can find a path around most in-process network restrictions. |
| No kernel, no firmware, no vendor drivers | No kernel CVEs, no boot chain, no TrustZone to attack. |
| Determinism | A single-threaded, single-process, single-tenant runtime is far easier to reason about than a preemptively scheduled 8-core system. |

**Weaker than a real Android device:**

| Property | Why it is weaker |
|---|---|
| No hardware attestation | No TEE, no hardware-backed KeyStore, no `MEETS_DEVICE_INTEGRITY`. Not implementable in software, at any effort. |
| No sensors, camera, microphone, telephony | Hardware that does not exist cannot be emulated convincingly. |
| No Play Services | The largest single source of app-level assumptions on Android. |
| No display, no vsync, no compositor | `Choreographer`, `SurfaceFlinger`, and the entire animation contract are absent. |
| No Binder | The IPC substrate that the framework itself is built on. |
| No wall clock authority | Apps may check time plausibility; a browser tab's clock is the host's, not a device's. |
| No `/system` | `resources.arsc`, the framework, and system fonts are not a filesystem you can open. |

The honest summary: **the substrate has a strictly smaller attack surface and a
strictly smaller capability surface.** Whether that is "safer" or "more useful"
depends entirely on the app, and this project measures which, per app, rather
than asserting either.

### 0.3 A refusal is a result

An app that cleanly refuses to run in the substrate is a *measured* outcome with
a *located* cause. An app that appears to run and silently computes the wrong
answer is a worse outcome for the user and a much more interesting one for this
project. The taxonomy is built to distinguish them, and the analysis plan
forbids reporting a single "runs / does not run" figure.

---

## 1. `SUB.BUILD` — `android.os.Build` identity (15)

| ID | Assumption (falsifiable) | Symptom when violated | Detection signal | Class | Prior |
|---|---|---|---|---|---|
| `SUB.BUILD.FINGERPRINT` | `Build.FINGERPRINT` matches a plausible retail device string | Apps compare it against known-bad values; a non-retail string is refused | `probes[env.getprop]`, `environment.build_fingerprint`, `diagnostics[NET/…]` | REFUSE | OCCASIONAL — **CONJECTURE**; high for finance/DRM apps |
| `SUB.BUILD.MODEL` | `Build.MODEL` names a real handset | Feature gates keyed on model (e.g. "is this a Samsung") take the wrong branch | `probes[env.getprop]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.BUILD.MANUFACTURER` | `Build.MANUFACTURER` set and consistent with `BRAND` | Vendor-specific workarounds misfire | `probes[env.getprop]` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.BUILD.BRAND` | `Build.BRAND` consistent with manufacturer | Same as above | `probes[env.getprop]` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.BUILD.PRODUCT` | `Build.PRODUCT` consistent with the rest of the identity | Consistency checks in anti-tamper code fail | `probes[env.getprop]` | REFUSE | RARE — **CONJECTURE** |
| `SUB.BUILD.DEVICE` | `Build.DEVICE` consistent with `PRODUCT` | Same as above | `probes[env.getprop]` | REFUSE | RARE — **CONJECTURE** |
| `SUB.BUILD.HARDWARE` | `Build.HARDWARE` matches the SoC family | Apps select CPU-specific code paths; wrong path is often slower or wrong | `probes[env.getprop]` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.BUILD.BOARD` | `Build.BOARD` names a real board | Rarely read directly; usually only inside anti-tamper cross-checks | `probes[env.getprop]` | REFUSE | RARE — **CONJECTURE** |
| `SUB.BUILD.TAGS` | `Build.TAGS` indicates a signed release build | `test-keys`/`debug` tags are treated as a compromise signal | `probes[env.getprop]` | REFUSE | RARE — **CONJECTURE** |
| `SUB.BUILD.SERIAL` | `Build.SERIAL` / `ANDROID_SERIAL` is a stable per-device identifier | Per-device licensing and activation fail; often a hard stop at first run | `environment.serial` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.BUILD.BOOTLOADER` | `Build.BOOTLOADER` / `ro.boot.verifiedbootstate` reads `locked`/`green` | Anti-tamper and integrity checks fail closed | `environment.verified_boot_state` | REFUSE | OCCASIONAL — **CONJECTURE**; every container fails this |
| `SUB.BUILD.RADIO` | `Build.getRadioVersion()` non-empty | Telephony-dependent features disabled; some apps disable themselves | `probes[env.getprop]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.BUILD.SDK_INT` | `Build.VERSION.SDK_INT` equals the real API level, and `RELEASE` matches | **Every version-gated code path is exercised differently.** The substrate must pick one API level and the app will run a branch it was never tested on | `environment.sdk_int`, `app.target_sdk` | MISBEHAVE | COMMON — **CONJECTURE**; the mechanism is documented in [V6][V7] for non-SDK lists |
| `SUB.BUILD.EMULATOR` | Device is not an emulator/container: `ro.kernel.qemu`, `ro.hardware`, generic fingerprint, absence of sensors, timing profiles | Explicit refusal or feature stripping in security-sensitive and DRM apps | `environment.is_emulator`, `environment.sensors_absent` | REFUSE | COMMON for DRM/banking — **UNVERIFIED** at any primary source; treated as a well-known community observation, and it is the reason threat T-04 exists |
| `SUB.BUILD.ABILITIES` | `PackageManager.hasSystemFeature(...)` reports the device's real capabilities | Apps conclude hardware is absent and disable themselves or misconfigure | `environment.sensors_present`/`_absent`, `probes[env.sensors]` | DEGRADE | COMMON — **CONJECTURE** |

---

## 2. `SUB.TRUST` — attestation and privileged services (9)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.TRUST.PLAY_INTEGRITY` | The Play Integrity API yields a usable verdict, ultimately `MEETS_DEVICE_INTEGRITY` | The app obtains a token, sends it to **its own backend**, and the **backend** rejects the request. The client sees a non-200 with an opaque body | `network.attempts[result=http_error, path contains decodeIntegrityToken]`, `exceptions[ApiException]` | **REFUSE** | COMMON in shipping commercial apps — **CONJECTURE**, mechanism [V2][V3] |
| `SUB.TRUST.SAFETYNET` | SafetyNet Attestation returns a verdict | **Nothing.** The API stopped working for every app on 2025-01-31 and now always fails with `ApiException` status 7 `NETWORK_ERROR` [V4][V5] | `diagnostics[SIGNAL_PAT.PLAY_SERVICES]`, `exceptions[ApiException]` | MISBEHAVE | **This assumption is unsatisfiable on *any* device, real or synthetic.** It therefore has **zero** discriminating power and must be excluded from divergence scoring |
| `SUB.TRUST.PLAY_SERVICES` | `com.google.android.gms.*` classes exist and resolve | `NoClassDefFoundError` at first use; or silent `Task` failure; or the app's whole login stack is dead | `classes.third_party_package_prefixes`, `environment.google_play_services.present` | **REFUSE** | COMMON — **CONJECTURE**; [V16][V17][V18] show these frameworks cannot proxy GMS out of existence |
| `SUB.TRUST.KEYSTORE_ANDROIDKEYSTORE` | `AndroidKeyStore` provider exists and stores keys | `KeyStore.getInstance("AndroidKeyStore")` throws; every key operation fails | `exceptions[KeyStoreException]`, `diagnostics[NET/…]` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.TRUST.ATTESTATION_KEY` | Keys can be hardware-attested: the attestation chain terminates in a Google or OEM root of trust | `KeyGenParameterSpec` attestation requests produce no chain; server-side policy rejects | `exceptions`, `network` (the app's attestation upload) | REFUSE | OCCASIONAL — **CONJECTURE**; the requirement is documented in [V1] |
| `SUB.TRUST.ROOT_DETECT` | The device is not rooted / not hooked | Root and hooking detection is a hard gate in security-sensitive apps | `diagnostics[PLAY_SERVICES]`, `exceptions`, `network` to a risk-scoring endpoint | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.TRUST.DEBUG_DETECT` | `Debug.isDebuggerConnected()` is false, `ApplicationInfo.FLAG_DEBUGGABLE` unset, `/proc/self/status` `TracerPid == 0` | App exits or blanks its UI when a debugger is attached | `probes[proc.status]` (`TracerPid`) | REFUSE | RARE — **CONJECTURE**; does not affect an automated run unless the substrate is instrumented |
| `SUB.TRUST.GMS_ACCOUNT` | A `GoogleAccount` exists, obtainable via `AccountManager` | Account-dependent flows (backup, sync, sign-in) are unavailable | `exceptions[SecurityException]`, `network` absence | DEGRADE | COMMON — **CONJECTURE** |
| `SUB.TRUST.CERT_TRUST` | The app's signing certificate is in the platform trust store, or pinned | Server-side or local cert validation fails | `diagnostics[TLS_FAILURE]`, `exceptions[SSLHandshakeException]` | DEGRADE | COMMON — **CONJECTURE** |

> **The `SUB.TRUST` family is the most likely place for this project to produce a
> single dominant finding, and the honest pre-registered expectation is that it
> dominates everything else.** See `research-protocol.md` §4.

---

## 3. `SUB.KERNEL` — `/proc`, `/sys`, and kernel interfaces (10)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.KERNEL.PROC_SELF` | `/proc/self/` exists and is readable | `FileNotFoundException` or `IOException`; fallback path taken | `filesystem.accesses`, `diagnostics` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.KERNEL.PROC_STAT` | `/proc/<pid>/stat` or `/proc/self/status` is readable, giving thread count and state | The exact input to a watchdog that decides whether to kill "a stuck" process | `native.thread_count_at_snapshot`, `probes[proc.status]` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.KERNEL.PROC_UPTIME` | `/proc/uptime` gives seconds since boot | Up-time gates ("too old, re-bootstrap") never trip, or trip constantly | `probes[env.uptime]`, `clock.monotonic_epoch_ref` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.KERNEL.PROC_CPUINFO` | `/proc/cpuinfo` lists real CPU features | ISA-feature detection takes the wrong branch; may select an unavailable path | `probes[env.getprop]` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.KERNEL.PROC_MEMINFO` | `/proc/meminfo` and `/sys/fs/cgroup` reflect real memory limits | Memory-based feature gating (cache size, concurrency) is miscalibrated | `environment.total_ram_bytes`, `probes[env.getprop]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.KERNEL.SYS_POWER` | `/sys/class/power_supply/*` reports battery level and charging state | Battery-aware features (low-power mode, charge-only scheduling) are wrong | `probes[env.battery]`, `environment` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.KERNEL.SYS_THERMAL` | `/sys/class/thermal/*` reports temperatures | Thermal throttling logic never engages | `probes[env.battery]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.KERNEL.SYS_BLOCK` | `/sys/block/*` storage geometry is real | Storage-space checks and cache eviction heuristics are miscalibrated | `probes[env.getprop]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.KERNEL.SYS_CLASS_NET` | `/sys/class/net/*` describes real interfaces | Network-interface enumeration returns nothing; per-interface accounting breaks | `probes[env.connectivity]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.KERNEL.SIGNAL_MODEL` | POSIX signal delivery, `sigaltstack`, and `SIGQUIT`-style thread dumps behave as on ART | The runtime's own crash reporting misbehaves; ANR dumps unavailable | `exceptions[kind=abort]`, `diagnostics[ANR]` | MISBEHAVE | RARE — **CONJECTURE**; mostly a *substrate implementer's* problem, not an app's assumption |

---

## 4. `SUB.IPC` — Binder, services, and cross-process communication (14)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.IPC.BINDER_DEV` | `/dev/binder` (or `/dev/binderfs`) exists and can be opened | `IOException`/`FileNotFoundException` at Binder init. **There is no browser analogue at all**, and no amount of framework shimming changes that | `filesystem.accesses[path=/dev/binder]`, `filesystem.open_fds_at_snapshot[kind=binder]` | **REFUSE** | COMMON for any app that touches the framework deeply — **CONJECTURE** |
| `SUB.IPC.SERVICE_MANAGER` | `ServiceManager.getService("…")` returns a live `IBinder` | `ServiceNotFoundException`, or a `DeadObjectException` on first `transact` | `diagnostics[SIGNAL_PAT.BINDER]`, `exceptions` | **REFUSE** | COMMON — **CONJECTURE** |
| `SUB.IPC.SYSTEM_SERVICE` | `Context.getSystemService(X)` returns a working implementation for ~90 service constants | Depends on the constant. Some null-check (DEGRADE), some do not (REFUSE) | `diagnostics[BINDER]`, `exceptions` | REFUSE / DEGRADE | COMMON — **CONJECTURE** |
| `SUB.IPC.ACTIVITY_MANAGER` | Activity launches, task affinity, and `startActivityForResult` work | Result never delivered; `onActivityResult` never fires. Often a **silent** no-op if the app does not check the result code | `lifecycle.events` (no second activity), `probes[win.windows]` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.IPC.WINDOW_MANAGER` | Window tokens, focus, and `InputMethodManager` work | Soft keyboard never appears; text input is impossible. Usually the first visible break | `lifecycle.window_focused` (normally unobserved), `diagnostics` | **REFUSE** (for any app with a text field) | COMMON — **CONJECTURE** |
| `SUB.IPC.PACKAGE_MANAGER_SELF` | `getPackageName()`, `getPackageInfo(getPackageName())` return a coherent `ApplicationInfo` | Version/`versionCode` self-checks fail; update prompts loop | `app.*` fields | MISBEHAVE | COMMON — **CONJECTURE** |
| `SUB.IPC.PACKAGE_MANAGER_OTHER` | `getPackageInfo("com.whatsapp")`, `queryIntentActivities`, `getInstallerPackageName` answer truthfully about **other** apps | The substrate has exactly one app, so **every query about another app returns "not installed"**. Inter-app features (share targets, "is X installed", deep-link handoff) fail **silently** | `network.attempts` (the lookup becomes an HTTP probe instead), `diagnostics` | **MISBEHAVE** | COMMON — **CONJECTURE**. A prime example of the class an evaluation misses |
| `SUB.IPC.BROADCAST` | System broadcasts arrive: `BOOT_COMPLETED`, `CONNECTIVITY_CHANGE`, `BATTERY_CHANGED`, `USER_PRESENT`, `TIMEZONE_CHANGED`, `PACKAGE_REPLACED` | **A browser tab has no boot. `BOOT_COMPLETED` never fires.** Apps that defer initialisation to that receiver never initialise — a silent, permanent hang with no exception | `lifecycle.events` (no `process_start` or an immediate resume with no work), `exceptions` empty | **MISBEHAVE** (looks like a hang, not a crash) | COMMON — **CONJECTURE**. Structurally guaranteed to fail |
| `SUB.IPC.ALARM_MANAGER` | `AlarmManager` `setExact`/`setAlarmClock` fire, including in Doze | Alarms never fire; deferred work never runs | `probes`, `lifecycle` (no follow-on activity) | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.IPC.JOB_SCHEDULER` | `JobScheduler` and `WorkManager` enqueue and run jobs | Background sync never happens; no visible symptom at all | `probes[power]`, `lifecycle` | MISBEHAVE | COMMON — **CONJECTURE** |
| `SUB.IPC.CONNECTIVITY_MANAGER` | `getActiveNetworkInfo()` is non-null and `isConnected()` is true | App treats itself as offline and shows a cached/empty state | `environment.network`, `diagnostics[NET_FAILURE]` | DEGRADE | COMMON — **CONJECTURE** |
| `SUB.IPC.CONTENT_PROVIDER` | Cross-process `content://` resolution against system providers (contacts, media, downloads) works | Contacts/media pickers return empty; **usually presented as "no items", not an error** | `diagnostics`, `exceptions[SecurityException]` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.IPC.NOTIFICATION` | `NotificationManager` posts notifications that the user sees | `POST_NOTIFICATIONS` permission flow, channels, and the shade do not exist | `exceptions[SecurityException]`, `lifecycle` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.IPC.BINDER_THREADPOOL` | The framework's Binder thread pool has a specific depth (default 16) | An app that transacts from a saturated pool **deadlocks**, because its own reply is queued behind itself. This is the archetypal MISBEHAVE | `diagnostics[BINDER]`, `native.thread_count_at_snapshot` | **MISBEHAVE** | RARE — **CONJECTURE**, but high-impact |

> **A design fork the project must decide explicitly and record:** when the
> substrate cannot provide a system service, does `getSystemService()` return
> `null` or throw? Apps differ. `null` produces DEGRADE for null-checking apps
> and an NPE (REFUSE) for the rest; throwing produces REFUSE uniformly. This is
> a **free variable in the experiment**, and choosing it silently would make the
> result unfalsifiable. Pre-registration: return `null`, count both outcomes.

---

## 5. `SUB.FS` — filesystem layout and permissions (10)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.FS.SYSTEM_LAYOUT` | `/system`, `/vendor`, `/product`, `/apex` exist with a known layout | Framework-jar and resource lookups by path fail | `filesystem.accesses[path=/system/...]` | REFUSE | RARE for app code, COMMON for frameworks that scan paths — **CONJECTURE** |
| `SUB.FS.DATA_DIR` | App data lives at `/data/data/<pkg>`, and `/data/data` is equivalent to `/data/user/0` | `/data/data` is a **symlink** on modern Android. An app that stats or string-compares the path can disagree with `Context.getFilesDir()` | `app.data_dir`, `filesystem.app_dir_listing` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.FS.EXTERNAL_STORAGE` | `Environment.getExternalStorageDirectory()` returns a writable shared volume, subject to scoped storage | No shared volume; `MediaStore` unusable. Apps commonly degrade to internal-only | `filesystem.accesses`, `exceptions[FileNotFoundException]` | DEGRADE | COMMON — **CONJECTURE** |
| `SUB.FS.SELINUX_CONTEXT` | Files carry SELinux labels such as `u:r:app_data_file:s0:c123,c256`, readable via the hidden `android.os.SELinux` | Label queries return null; **anti-tamper and crash-SDK code paths take a fallback silently** | `filesystem.app_dir_listing[selinux_context]` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.FS.LIB_PATH` | `System.loadLibrary` searches a known `lib/` path, and the dynamic linker resolves dependencies | `UnsatisfiedLinkError` | `diagnostics[SIGNAL_PAT.LOAD_FAIL]`, `exceptions[UnsatisfiedLinkError]` | REFUSE | COMMON for any app with JNI — **CONJECTURE** |
| `SUB.FS.ASHMEM` | `/dev/ashmem` or `memfd_create` provides shared anonymous memory | `FileNotFoundException`; zero-copy and shared-buffer paths fail | `filesystem.accesses`, `diagnostics` | DEGRADE | OCCASIONAL — **CONJECTURE**; `memfd` is the modern path and the substrate can in principle offer it |
| `SUB.FS.PERM_MODEL` | POSIX modes: `0700` on the data dir, `0771` on shared prefs, app uid ownership | Mode/ownership checks fail; apps that gate on `canRead()` misbehave | `filesystem.app_dir_listing[mode, owner_uid]` | MISBEHAVE | RARE — **CONJECTURE** |
| `SUB.FS.PACKAGE_PATH` | `ApplicationInfo.sourceDir` points at a real APK containing `resources.arsc` and `classes*.dex` | Direct APK reads (a legitimate technique) fail | `app.code_path`, `classes.dex_files` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.FS.OBB` | Optional expansion files in `/sdcard/Android/obb/` are readable | Large-asset games cannot start | `filesystem.accesses` | REFUSE | RARE in F-Droid, COMMON in Play-distributed games — **CONJECTURE** |
| `SUB.FS.MOUNT_NS` | `/proc/<pid>/mountinfo` and `/proc/self/mounts` describe a real mount namespace | Namespace-parsing code fails | `probes[proc.mountinfo]` | DEGRADE | RARE — **CONJECTURE** |

---

## 6. `SUB.RES` — resources and configuration (8)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.RES.ARSC` | `resources.arsc` is parsed into a real `ResourceTable` with valid resource IDs | `Resources$NotFoundException`; or, worse, IDs resolve to the **wrong resource** with no error | `classes.dex_files`, `exceptions[Resources$NotFoundException]` | REFUSE / **MISBEHAVE** | COMMON — **CONJECTURE**. A substrate that fakes resources by ID alone produces silent wrong-resource bugs |
| `SUB.RES.QUALIFIER` | Resource qualifier selection works: density, locale, orientation, night mode, `uiMode`, screen size | Wrong-variant assets; UI rendered at the wrong scale or in the wrong language | `environment.density_dpi`, `environment.locale` | MISBEHAVE | COMMON — **CONJECTURE** |
| `SUB.RES.LOCALE` | `Locale.getDefault()` and per-app locales resolve | Content in the wrong language; date/number formatting wrong | `environment.locale` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.RES.TIMEZONE` | `TimeZone.getDefault()` is a real IANA zone | Date rendering and scheduled logic off; **often by hours** | `environment.timezone` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.RES.FONT_SCALE` | `Configuration.fontScale` reflects user accessibility settings | Layout breaks, or text is drawn at a size the layout was not designed for | `environment.font_scale` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.RES.DISPLAY_METRICS` | `DisplayMetrics` (density, `xdpi`/`ydpi`, smallest width) are real | Layout decisions from `smallestScreenWidthDp` buckets are wrong | `environment.screen` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.RES.PACKAGE_RESOLVER` | `Resources.getIdentifier(name, type, pkg)` maps names to IDs, and `getResourceName` inverts it | `0` returned, or the wrong ID for a name | `diagnostics` | MISBEHAVE | OCCASIONAL — **CONJECTURE**; the substrate must expose the *name→ID* mapping, not just the ID space |
| `SUB.RES.SYSTEM_FONTS` | System fonts (`sans-serif`, `serif`, `monospace`, emoji) are available to the text stack | Text renders with fallbacks or fails | `probes[env.getprop]` | DEGRADE | COMMON — **CONJECTURE** |

---

## 7. `SUB.TIME` — clocks, and the one that surprises people (7)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.TIME.MONOTONIC` | `SystemClock.uptimeMillis()` is monotonic ms since boot | Backoff, timeouts, and debounce logic compute wrong intervals | `clock.monotonic_resolution_ms`, `probes[env.uptime]` | DEGRADE | COMMON — **CONJECTURE** |
| `SUB.TIME.ELAPSED_REALTIME` | `SystemClock.elapsedRealtime()` includes deep sleep [V13] | See the note below — this fails in the **opposite** direction from intuition | `probes[env.uptime]` | **MISBEHAVE** | OCCASIONAL — **CONJECTURE**, mechanism [V13] |
| `SUB.TIME.WALL_CLOCK` | `System.currentTimeMillis()` is the device's authoritative time | Clock-skew detection ("is the time plausible?") fails; token expiry computed wrongly | `capture.started_utc`, `clock.wall_clock_source` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.TIME.VSYNC` | `Choreographer` posts frame callbacks on a real display's vsync, and `ValueAnimator` is frame-driven | **Animations never advance**, or spin at CPU speed. Frame-driven state machines (including game loops) stall or busy-loop | `diagnostics[SIGNAL_PAT.JANK]`, `lifecycle` | **REFUSE** for animation-dependent apps, else **MISBEHAVE** | COMMON — **CONJECTURE**; a substrate with no display has no vsync to post on |
| `SUB.TIME.SLEEP` | `Thread.sleep` and `Object.wait` honour the requested duration and are not starved | Timeouts fire spuriously; retry loops exhaust their budget | `diagnostics[SIGNAL_PAT.SLOW_OPERATION]`, `diagnostics[ANR]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.TIME.SLOW_OPERATION` | Platform slow-operation thresholds (`Slow operation`, `Slow dispatch`, `Slow delivery`) are not tripped | A latency-sensitive app believes it is fast when the host is not | `diagnostics[SIGNAL_PAT.SLOW_OPERATION]` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.TIME.ANR_BUDGET` | The ~5 s input-dispatch ANR budget is met | ANR on a host that is merely slow, or a timeout where the app self-reports failure | `lifecycle.events[type=anr]`, `diagnostics[ANR]` | REFUSE | OCCASIONAL — **CONJECTURE** |

> **The counter-intuitive one, stated because it is easy to get backwards.**
> On a real Android device `elapsedRealtime() − uptimeMillis()` equals accumulated
> **deep-sleep (suspend) time**; `uptimeMillis` explicitly excludes deep sleep and
> `elapsedRealtime` explicitly includes it, and both are guaranteed monotonic
> **[V12][V13]**. A browser host is a mains-powered desktop that essentially
> never suspends, so in the substrate the two clocks are **indistinguishable and
> their difference is always ≈ 0**. Any app that infers "how long was the user
> away" from that difference — session timeouts, "screensaver" heuristics,
> resume-from-background decisions, cached-data-age checks — will compute
> **zero** on the substrate where it computes hours on a phone. The failure is
> silent, and it is in the *opposite* direction from the intuition that a
> substrate has "no clock".

---

## 8. `SUB.CPU` — processors, memory model, and ART tiering (7)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.CPU.CORE_COUNT` | `Runtime.availableProcessors()` reflects real cores | Thread-pool sizing is wrong. Usually harmless; occasionally a watchdog or a spin-wait barrier misbehaves | `native.thread_count_at_snapshot`, `probes[env.abilist]` | DEGRADE | COMMON to *read*, RARE to *fail on* — **CONJECTURE** |
| `SUB.CPU.ARCH` | The executing ISA matches the app's `SUPPORTED_ABIS` and any `Build.SUPPORTED_32_BIT_ABIS` fallback | Wrong instruction path; on the web, WASM has no equivalent to `armeabi-v7a` NEON | `environment.abis`, `app.native_libs_declared` | REFUSE | COMMON for JNI apps — **CONJECTURE** |
| `SUB.CPU.TIERING` | **ART execution tiers**: AOT-compiled dex (`base.apk` + `.odex`/`.vdex`) or JIT-warmed methods execute at near-native speed | **This is the most under-appreciated item in the whole taxonomy.** Cold first launch runs *interpreted*. Code that is a few hundred milliseconds warm on a phone can be **100–1000× slower interpreted**, so apps hit their own internal timeouts, ANRs, and network timeouts. The app is not broken; it is *too slow*, and it fails in ways that look like flakiness | `lifecycle.time_to_first_frame_ms` vs ground truth, `diagnostics[SIGNAL_PAT.GC]`, `diagnostics[SLOW_OPERATION]`, `lifecycle.terminal` | **MISBEHAVE** | COMMON — **CONJECTURE**. A JS/WASM interpreter with no tiering and no JIT will hit this for any computationally non-trivial app |
| `SUB.CPU.GC` | ART's generational GC cadence and heap-growth policy apply | Allocation-heavy loops thrash; GC pauses where the phone had none | `diagnostics[SIGNAL_PAT.GC]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.CPU.ATOMIC` | `compareAndSet`, `VarHandle`, and memory barriers behave as the JMM specifies | Racy code that is "usually fine" becomes genuinely wrong, non-deterministically | not directly observable | **MISBEHAVE** | RARE — **CONJECTURE**. The one class that can produce *irreproducible* results |
| `SUB.CPU.THREAD_AFFINITY` | Thread priorities, affinity, and the scheduler's real-time guarantees | Timing-sensitive loops jitter; `Thread.setPriority` is advisory | `native.thread_count_at_snapshot` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.CPU.NUMERIC` | `StrictMath` and floating point behave with the precision the platform guarantees | Historically a Dalvik-on-x86 x87 issue. **On ARM64 this is a non-issue**, and the platform moved | not directly observable | MISBEHAVE | **RARE, and deliberately listed to be excluded.** Recorded so that a future analyst does not "rediscover" it on a platform it no longer applies to |

---

## 9. `SUB.MEM` — memory model and hardware capability (7)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.MEM.DIRECT_BYTEBUFFER` | `allocateDirect`, `FileChannel.map`, and `sun.misc.Unsafe` off-heap access work | Zero-copy and image-processing paths fall back to heap copies, or fail | `exceptions[UnsupportedOperationException]`, `diagnostics` | DEGRADE | OCCASIONAL — **CONJECTURE**; WebAssembly memory and SABs are in-principle analogues, so this is *partly* satisfiable |
| `SUB.MEM.MMAP` | `mmap` of files and of anonymous memory | Same as above | `filesystem.accesses[op=mmap]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.MEM.LARGE_HEAP` | `android:largeHeap` and `dalvik.vm.heapsize` grant a larger heap | `OutOfMemoryError` on workloads a phone handles | `exceptions[OutOfMemoryError]` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.MEM.HW_CAPS` | `ActivityManager.MemoryInfo`, `isLowRamDevice()`, `MemoryClass` reflect the device | Cache and concurrency budgets miscalibrated; app either thrashes or under-uses | `environment.low_ram_device`, `environment.total_ram_bytes` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.MEM.LMK` | The lowmemorykiller and cached-process reclamation behave as expected | Background processes vanish at different times; state restoration paths taken | `lifecycle.events[type=recycled_to_cached, process_killed]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.MEM.NATIVE_HEAP` | `Debug.getNativeHeapAllocatedSize()` returns meaningful numbers | Leak heuristics misfire | `probes[proc.status]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.MEM.ENTROPY` | `/dev/urandom` and `getrandom(2)` provide a CSPRNG | See §10 | `filesystem.accesses[path=/dev/urandom]` | MISBEHAVE | RARE — **CONJECTURE** |

---

## 10. `SUB.NATIVE` — native code and JNI (6)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.NATIVE.LOAD_LIBRARY` | `System.loadLibrary("foo")` succeeds | `UnsatisfiedLinkError: dlopen failed` | `diagnostics[SIGNAL_PAT.LOAD_FAIL]`, `exceptions[UnsatisfiedLinkError]`, `app.native_libs_declared` | **REFUSE** | COMMON in the general Play population; **OCCASIONAL in a DEX-only corpus, and structurally ZERO if the corpus is filtered to DEX-only** — **CONJECTURE** |
| `SUB.NATIVE.JNI_ENTRY` | JNI methods are implemented and callable | `UnsatisfiedLinkError`, or `NoSuchMethodError` on a native-backed method | `exceptions`, `jni.calls` | REFUSE | COMMON for JNI apps — **CONJECTURE** |
| `SUB.NATIVE.EXEC_SEGMENTS` | Mapped `.so` files are executable | `dlopen` succeeds but `mprotect`/execute fails | `native.exec_segments_observed` | REFUSE | COMMON for JNI apps — **CONJECTURE** |
| `SUB.NATIVE.LINKER_NS` | The linker namespace isolates app libraries from system libraries | Wrong symbol resolution; version-mismatched `libc` semantics | `native.libraries_loaded`, `native.system_libraries_mapped` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.NATIVE.ISA` | CPU ISA extensions the native code requires are present | `SIGILL` | `exceptions[kind=sigsegv/abort]`, `environment.abis` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.NATIVE.SIGNAL_CRASH` | Native crashes produce a tombstone and a readable stack | The app's own crash reporter gets nothing; a native crash becomes an unexplained process death | `exceptions[kind=abort, sigsegv]`, `exceptions[].crash_log_ref` | **MISBEHAVE** | OCCASIONAL — **CONJECTURE** |

> **The honest statement of this family.** In a DEX-only corpus every ID here is
> structurally zero, and that is a *property of the corpus*, not a measurement of
> the apps. Report it as a corpus statistic, never as a compatibility result.

---

## 11. `SUB.NET` — network and transport (9)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.NET.EGRESS` | Outbound sockets work at all | **Nothing happens.** No DNS, no connect, no error at the socket layer. Apps surface this as an empty screen or a spinner that never stops | `network.attempts[]` empty **plus** `network.capture_method` / `network.limits` establishing the observation was possible | **REFUSE** (for network-dependent apps) | COMMON — **CONJECTURE**. This is the family's defining member: the substrate's *strongest* security property is also its most common hard failure |
| `SUB.NET.DNS` | DNS resolution returns real addresses | `UnknownHostException` | `diagnostics[SIGNAL_PAT.NET_FAILURE]` | REFUSE | COMMON — **CONJECTURE** |
| `SUB.NET.TLS_TRUST` | The platform trust store, CT enforcement, and the app's pinning all validate | `SSLHandshakeException`, `Trust anchor for certification path not found` | `diagnostics[SIGNAL_PAT.TLS_FAILURE]` | REFUSE | COMMON — **CONJECTURE** |
| `SUB.NET.CLEARTEXT_POLICY` | `usesCleartextTraffic` / `NetworkSecurityConfig` permits the app's HTTP traffic | `Cleartext traffic to <host> not permitted` | `diagnostics[SIGNAL_PAT.CLEARTEXT_BLOCKED]` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.NET.PROXY` | `ProxySelector.getDefault()` and `VpnService` see the real network configuration | Proxy-discovered endpoints and captive-portal logic break | `environment.network.system_proxy` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.NET.NATIVE_HTTP` | Cronet / OkHttp native stack / Conscrypt `SSLSocket` implementations are available | `NoClassDefFoundError` on a Conscrypt or Cronet class | `classes.third_party_package_prefixes`, `exceptions` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.NET.WEBSOCKET` | WebSocket upgrades work, including `wss` and permessage-deflate | Long-lived channels never establish; **the app usually shows a live UI that is silently stale** | `diagnostics[NET_FAILURE]`, `network.attempts` | **MISBEHAVE** | OCCASIONAL — **CONJECTURE** |
| `SUB.NET.QUIC` | HTTP/3 over QUIC is available or its absence is handled | Long stalls then HTTP/3-specific failures | `network.attempts[transport=quic]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.NET.BACKEND_VERDICT` | The app's **own server** accepts the request and returns a usable response | The failure is **not in the app** and **not on the device**; it is a 4xx from a server the substrate cannot influence. This is where `SUB.TRUST.PLAY_INTEGRITY` actually terminates | `network.attempts[status_code 4xx, result=http_error]` | **REFUSE** | COMMON — **CONJECTURE**, mechanism [V2] |

> **Note the observer-effect asymmetry.** "No connection at all" and "handshake
> rejected" are different symptoms of the same unmet assumption, and they must not
> be merged. Hard egress denial produces the *first*; a network that is reachable
> but not trusted produces the *second*.

---

## 12. `SUB.GFX` — graphics, display, and composition (11)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.GFX.EGL_CONTEXT` | `EGL14`/`GLES20` contexts can be created and made current | Rendering throws; often only on the path that actually draws | `exceptions[EGL_BAD_*]`, `environment.graphics` | REFUSE | COMMON for game/engine apps — **CONJECTURE** |
| `SUB.GFX.GLES_VERSION` | `GLES20.glGetString(GL_VERSION)` reports ≥ 3.0 | Feature detection takes a lower path; shaders fail to compile | `environment.graphics.gles_version` | DEGRADE / REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.GFX.VULKAN` | `VK_KHR_*` and a real Vulkan instance exist | Vulkan render path fails | `environment.graphics.vulkan_version` | REFUSE | OCCASIONAL — **CONJECTURE**; WebGPU is a partial but *not equivalent* analogue |
| `SUB.GFX.EXTENSIONS` | The extension string lists what the app needs | Feature path missing; often a silent quality downgrade | `environment.graphics.extensions_known` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.GFX.RENDERER_STRING` | `GL_RENDERER` names a device GPU | Anti-fraud GPU-fingerprint checks see a browser string | `environment.graphics.gl_renderer` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.GFX.SURFACE` | `Surface`, `SurfaceView`, `SurfaceTexture`, and the BufferQueue exist | Video and camera preview have no surface at all | `exceptions`, `lifecycle` | REFUSE | COMMON for media apps — **CONJECTURE** |
| `SUB.GFX.HW_COMPOSITION` | Hardware composition and `SurfaceFlinger` behave as assumed | Frame pacing differs; video playback jitters | `diagnostics[SIGNAL_PAT.JANK]`, `lifecycle.jank_events` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.GFX.FRAME_BUDGET` | A frame lands within ~16.7 ms at 60 Hz | `Choreographer` deadlines missed; jank | `diagnostics[JANK]`, `lifecycle.jank_events` | DEGRADE | COMMON — **CONJECTURE** |
| `SUB.GFX.SCREEN_ON` | `PowerManager.isScreenOn()`, and the app can keep the screen awake | Wake-lock and keep-screen-on are no-ops | `probes[power]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.GFX.CAMERA_PIPE` | The camera HAL and the camera2 pipeline exist | Camera features absent | `environment.sensors_absent`, `SUB.BUILD.ABILITIES` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.GFX.TEXT_RENDER` | `Canvas`, `Paint`, `Typeface`, and `Bitmap` behave as on device | Text layout differs; `StaticLayout` measurements wrong | `probes[env.getprop]` | DEGRADE | OCCASIONAL — **CONJECTURE** |

---

## 13. `SUB.HW` — sensors and physical hardware (10)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.HW.SENSORS` | `SensorManager` reports accelerometer, gyroscope, magnetometer | Step counters, rotation, and tilt features are dead | `probes[env.sensors]`, `environment.sensors_absent` | DEGRADE / REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.HW.CAMERA` | A camera exists | Camera features absent | `SUB.BUILD.ABILITIES` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.HW.LOCATION` | `FusedLocationProvider` yields fixes | Maps, geofencing, and location-dependent UI are dead | `diagnostics`, `exceptions[SecurityException]` | REFUSE | COMMON — **CONJECTURE** |
| `SUB.HW.BLUETOOTH` | A Bluetooth adapter and bonded devices exist | BLE and companion-device features dead | `probes[env.getprop]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.HW.NFC` | An NFC controller exists | Tap-to-pay and tag reading dead | `SUB.BUILD.ABILITIES` | REFUSE | RARE — **CONJECTURE** |
| `SUB.HW.VIBRATE` | `Vibrator` produces haptic feedback | Silent UI; not a functional failure | `probes[env.getprop]` | DEGRADE | COMMON to *call*, RARE to *fail on* — **CONJECTURE** |
| `SUB.HW.TELEPHONY` | Telephony, SIM, and carrier APIs exist | Telecom-specific features dead | `environment.sensors_absent`, `SUB.BUILD.ABILITIES` | DEGRADE | RARE in F-Droid — **CONJECTURE** |
| `SUB.HW.BIOMETRIC` | `BiometricPrompt` and `FingerprintManager` can authenticate | Login flow cannot complete | `exceptions` | **REFUSE** (blocks login) | OCCASIONAL — **CONJECTURE** |
| `SUB.HW.CONTACTS_SMS` | Contacts and SMS providers are populated | Import/backup dead; usually an empty picker, not an error | `SUB.IPC.CONTENT_PROVIDER` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.HW.PRINTER_SCANNER` | USB/print/scanner peripherals exist | Peripheral flows dead | `SUB.BUILD.ABILITIES` | DEGRADE | RARE in F-Droid — **CONJECTURE** |

---

## 14. `SUB.FW` — framework, class loading, and app model (11)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.FW.CLASS_LOADER` | The full `java.*`, `javax.*`, `org.w3c.dom.*`, `org.xml.*`, `org.json.*`, `org.apache.http.*` surface exists, and the class loader resolves it | `NoClassDefFoundError` on a class that was never in the APK. The substrate must **synthesise the JDK surface**, not just run dex | `exceptions[NoClassDefFoundError]`, `classes.framework_classes_touched` | **REFUSE** | COMMON — **CONJECTURE**. Structurally guaranteed to fail for any app using a class the substrate has not implemented |
| `SUB.FW.REFLECTION` | `Class.forName`, `getDeclaredMethod`, `Method.invoke`, and `Proxy` work for framework types | Reflection-based feature detection silently returns null | `exceptions[ReflectiveOperationException]`, `diagnostics` | **MISBEHAVE** | COMMON — **CONJECTURE**. Very high risk in a substrate: reflection over an *incomplete* surface fails **quietly** |
| `SUB.FW.INVOKEDYNAMIC` | `INVOKE-DYNAMIC`, `LambdaMetafactory`, and method handles work | Any Java 8+ lambda or method reference throws `BootstrapMethodError` | `exceptions[BootstrapMethodError]` | **REFUSE** | **COMMON in modern apps** — **CONJECTURE**. Modern DEX is saturated with `invokedynamic`; a substrate that does not implement the bootstrap machinery will fail most contemporary bytecode |
| `SUB.FW.NON_SDK_API` | Non-SDK framework interfaces are reachable, or the platform's enforcement applies as it does on device | On a real device, blocked members throw `NoSuchFieldError`/`NoSuchMethodError`; a substrate with **no** enforcement silently returns a value the app then misuses **[V6][V7]** | `exceptions[NoSuch*Error]`, `app.uses_non_sdk_api` | **MISBEHAVE** | OCCASIONAL — **CONJECTURE**, mechanism [V6][V7]. Subtle: the substrate must *reproduce the blocklist* or it will differ from the reference in the opposite direction |
| `SUB.FW.SERIALIZATION` | `Parcel`, `Bundle`, `IBinder` marshalling, and `Serializable` round-trip identically | Intents lose data; state restoration is subtly wrong | `exceptions`, `lifecycle` | **MISBEHAVE** | OCCASIONAL — **CONJECTURE** |
| `SUB.FW.DYNAMIC_CODE` | `DexClassLoader`, `InMemoryDexClassLoader`, and `PathClassLoader` load new dex | Hot-patching, plug-in, and AOT-download flows dead | `exceptions[ClassNotFoundException]`, `classes.dynamic_dex_loaded` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.FW.ACTIVITY_LIFECYCLE` | `onCreate`/`onStart`/`onResume`/`onPause`/`onStop`/`onDestroy` fire in the documented order, including for configuration changes and process death | Lifecycle-dependent initialisation runs in the wrong order; state loss on rotation | `lifecycle.events` | **MISBEHAVE** | COMMON — **CONJECTURE** |
| `SUB.FW.CONTENT_PROVIDER_INIT` | `ContentProvider.onCreate()` runs before `Application.onCreate()` | Initialisation order is wrong; the classic Android launch-order bug class | `lifecycle.events` | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.FW.CRYPTO_PROVIDER` | The JCA provider list contains `AndroidKeyStore` and Conscrypt | Cipher and signature operations fail | `exceptions[NoSuchProviderException]` | REFUSE | OCCASIONAL — **CONJECTURE** |
| `SUB.FW.WEBVIEW` | `android.webkit.WebView` with the Java↔JS bridge (`addJavascriptInterface`, `WebViewClient`) is available | Hybrid apps lose their entire UI | `exceptions[ClassNotFoundException]` | REFUSE | COMMON — **CONJECTURE** |
| `SUB.FW.PROCESS_ISOLATION` | A separate process per `android:process`, and per-process lifecycles | Cross-process IPC in the app's own design fails | `probes[proc.maps]`, `diagnostics[BINDER]` | DEGRADE | RARE — **CONJECTURE** |

> **The one place the substrate is structurally *better*.** `SUB.FW.WEBVIEW` is
> the family where a browser substrate has an advantage no Android device
> offers: it is *already* a Chromium. A WebView-backed hybrid app could
> plausibly get a more faithful WebView in the substrate than on a six-year-old
> phone with an un-updated System WebView. This is a **hypothesis**, not a
> result, and it is listed precisely so that a study which only looks for
> failures will not miss it.

---

## 15. `SUB.INPUT` — input and windowing (4)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.INPUT.INPUT_EVENT` | `MotionEvent`/`KeyEvent` arrive with real pointer and multi-touch semantics | No text entry, no gestures, no scrolling. **The first thing a human notices** | `lifecycle.first_input_delivered` (normally unobserved — the automated protocol sends no input) | **REFUSE** | COMMON — **CONJECTURE** |
| `SUB.INPUT.IME` | `InputMethodManager` produces a soft keyboard | No keyboard; **every app with a text field is unusable** | `SUB.IPC.WINDOW_MANAGER` | **REFUSE** | COMMON — **CONJECTURE** |
| `SUB.INPUT.WINDOW_FOCUS` | `onWindowFocusChanged` fires correctly, and focus order is sane | Focus-dependent UI (search fields, dialogs, accessibility) misbehaves silently | `lifecycle.window_focused` (normally unobserved) | MISBEHAVE | OCCASIONAL — **CONJECTURE** |
| `SUB.INPUT.HAPTIC` | Haptic feedback fires | Silent UI | `SUB.HW.VIBRATE` | DEGRADE | RARE — **CONJECTURE** |

---

## 16. `SUB.PWR` — power, scheduling, and process lifetime (7)

| ID | Assumption | Symptom | Detection | Class | Prior |
|---|---|---|---|---|---|
| `SUB.PWR.WAKE_LOCK` | `PowerManager.WakeLock` is held across a background operation | Background work is not kept alive; but in a substrate nothing is ever killed, so the *opposite* of the expected failure | `probes[power]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.PWR.DOZE` | `DeviceIdleStateListener`, `setAndAllowWhileIdle`, and job deferral behave as documented | Background sync runs far more often than on a real phone. A **performance** divergence, not a correctness one | `probes[power]`, `lifecycle` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.PWR.APP_STANDBY` | App-standby buckets restrict background work | No restriction exists; see `SUB.PWR.DOZE` | `probes[power]` | DEGRADE | RARE — **CONJECTURE** |
| `SUB.PWR.BOOT_COMPLETED` | `BOOT_COMPLETED` is delivered after install/upgrade | **No boot exists.** The receiver never fires and deferred initialisation never happens | `SUB.IPC.BROADCAST` | **MISBEHAVE** | COMMON — **CONJECTURE**. Structurally guaranteed to fail |
| `SUB.PWR.PROCESS_REAPER` | Cached processes are reclaimed under memory pressure | Nothing is ever reclaimed; a different set of lifetime bugs than a real device | `lifecycle.events[process_killed]` absent | DEGRADE | RARE — **CONJECTURE** |
| `SUB.PWR.BATTERY` | Battery level, charging state, and `BatteryManager` are real | Battery-aware behaviour is wrong; also a **tempting side channel for fingerprinting**, which is a reason the substrate should *lie consistently* rather than expose the host's battery | `probes[env.battery]` | DEGRADE | OCCASIONAL — **CONJECTURE** |
| `SUB.PWR.UPTIME_POLICY` | Process priority and cgroup placement follow Android's oom-adj scheme | Memory and scheduling behaviour differs from the reference | `probes[proc.status]` | DEGRADE | RARE — **CONJECTURE** |

---

## 17. Cross-cutting observations

**17.1 The families that are structurally guaranteed to fail.** Independent of
implementation quality, effort, or corpus:

- `SUB.IPC.BINDER_DEV` — no `/dev/binder`, ever.
- `SUB.TRUST.PLAY_INTEGRITY` (`MEETS_DEVICE_INTEGRITY`/`MEETS_STRONG_INTEGRITY`)
  — no hardware-backed attestation, ever. These require hardware-backed proof of
  a locked bootloader on a certified manufacturer image **[V1][V3]**.
- `SUB.IPC.BROADCAST` (`BOOT_COMPLETED`) and `SUB.PWR.BOOT_COMPLETED` — no boot.
- `SUB.NET.EGRESS` — under a no-egress policy.
- `SUB.TRUST.SAFETYNET` — unsatisfiable on **every** device since 2025-01-31
  **[V4][V5]**, and therefore carries no signal.

These are the honest "hard wall" set. Any study that reports a percentage
without separating them is reporting an average of a constant and a measurement.

**17.2 The failure that looks like flakiness.** `SUB.CPU.TIERING` and
`SUB.TIME.VSYNC` produce apps that *sometimes* work. They are the main reason a
naive evaluation would over-report compatibility: run it once, get a pass, ship
the claim. The protocol therefore mandates repeated runs (§5 of
`research-protocol.md`).

**17.3 The class that a crash-count evaluation cannot see.** `MISBEHAVE` is 45
of the entries above. Of those, the ones that matter most are:

| ID | Why it is invisible to a crash counter |
|---|---|
| `SUB.IPC.PACKAGE_MANAGER_OTHER` | Query returns "not installed"; the feature is just gone |
| `SUB.RES.ARSC` | Wrong resource, no exception |
| `SUB.TIME.ELAPSED_REALTIME` | Suspend time reads as 0; session logic silently wrong |
| `SUB.FW.REFLECTION` | `getDeclaredMethod` returns null; fallback path taken |
| `SUB.FW.NON_SDK_API` | Substrate returns a value a real device would have thrown on |
| `SUB.NET.WEBSOCKET` | Live-looking UI, silently stale data |
| `SUB.CPU.ATOMIC` | Non-deterministic, and rare |
| `SUB.IPC.BINDER_THREADPOOL` | Deadlock; often looks like "slow" |

**17.4 Where the substrate wins.** Stated in §0.2 and repeated here so it is not
lost: no syscall surface, no filesystem, hard egress denial, no firmware, and —
per `SUB.FW.WEBVIEW` — a *native* Chromium where Android has a WebView
applet. A study that reports only incompatibility counts is a study that has
stopped measuring early.

**17.5 Prior-art calibration.** App-level virtualisation frameworks —
VirtualApp, DroidPlugin, VirtualXposed, VirtualAPK **[V16][V17][V18]** — already
run **unmodified** APKs inside an unmodified host by proxying the framework
layer and redirecting I/O. They hit exactly these walls, and the same walls
appear in the security literature as the reason those frameworks are abused: the
APK is unmodified so repackaging detection does not fire **[V16]**. Two
consequences for this project:

1. **Calibration.** Independent prior art converging on the same failure set is
   the strongest external support available for the priors above. It is also
   the strongest warning: if in-app virtualisation cannot solve this, a
   browser-native substrate with *no Android at all underneath* will not either.
2. **Novelty.** This project is not novel in "run unmodified APKs somewhere
   else". What would be novel is a **quantified, oracle-backed** account of
   *where* it fails — which is precisely what `oracle/` and this document exist
   to provide. That is the claim to make, and it is a narrower claim than
   "nobody has done this".

---

## 18. Registry summary

| Family | IDs | Hard-wall members | Most consequential |
|---|---|---|---|
| `SUB.BUILD` | 15 | — | `EMULATOR`, `SDK_INT` |
| `SUB.TRUST` | 9 | `PLAY_INTEGRITY`, `SAFETYNET` | `PLAY_INTEGRITY` |
| `SUB.KERNEL` | 10 | — | `PROC_STAT` |
| `SUB.IPC` | 14 | `BINDER_DEV`, `BROADCAST` | `SERVICE_MANAGER` |
| `SUB.FS` | 10 | — | `DATA_DIR`, `LIB_PATH` |
| `SUB.RES` | 8 | — | `ARSC` |
| `SUB.TIME` | 7 | — | `VSYNC`, `ELAPSED_REALTIME` |
| `SUB.CPU` | 7 | — | **`TIERING`** |
| `SUB.MEM` | 7 | — | `LARGE_HEAP` |
| `SUB.GFX` | 11 | — | `EGL_CONTEXT`, `SURFACE` |
| `SUB.NATIVE` | 6 | all, in a DEX-only corpus | `LOAD_LIBRARY` |
| `SUB.NET` | 9 | `EGRESS` | `BACKEND_VERDICT` |
| `SUB.HW` | 10 | — | `LOCATION`, `BIOMETRIC` |
| `SUB.FW` | 11 | — | `CLASS_LOADER`, `INVOKEDYNAMIC` |
| `SUB.INPUT` | 4 | `INPUT_EVENT`, `IME` | `IME` |
| `SUB.PWR` | 7 | `BOOT_COMPLETED` | `BOOT_COMPLETED` |

Counts are of IDs defined in this document, computed by
`grep -o 'SUB\.[A-Z_]*\(\.[A-Z_]*\)*' docs/divergence-taxonomy.md | sort -u`.

**No results are reported here.** See `research-protocol.md` for what will be
measured, how, and what would falsify it.
