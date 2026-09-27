# What fraction of Android apps contain no native code?

**Answer: 44.76% (2,003 / 4,475) of the F-Droid corpus.**

> **Read the limitations before quoting this.** This is a **census of F-Droid**, not
> a sample of the Android ecosystem, and "contains no native code" is a statement
> about ZIP entry names — not about whether the app would actually run. A number
> below is not a licence to claim the runtime works; it is the ceiling on who
> could even be a candidate. See [Limitations](#limitations), which is not
> boilerplate.

- **Numerator / denominator:** 2,003 / 4,475
- **95% Wilson interval:** 43.31% – 46.22% (wide enough that you should quote a
  range, not a point estimate)
- **Complement:** 2,472 / 4,475 = 55.24% **do** ship native code
- **Method:** HTTP range reads of the ZIP central directory only. No APK was
  downloaded whole. 0.820% of the bytes.

## Reproduce

```bash
node tools/corpus/survey.mjs --n 5000 --seed 20260928 --concurrency 8
```

`--n 5000` exceeds the 4,475-package population, so this runs a **census**, not
a sample: there is no sampling error. The seed is still recorded, and the seeded
n=3,000 subsample is reported alongside so the sampling path is exercised and
reproducible.

Unit tests (Node 20+; no dependencies, nothing to install):

```bash
node --test
```

> Note: `node --test tests/` — the form with an explicit directory — **fails on
> Node v22.21.0** with `Error: Cannot find module '.../tests'`. A directory
> positional argument is treated as a module entry point rather than a directory
> to scan. This is a Node CLI behaviour, not a repository defect; it reproduces
> in a bare scratch directory. `node --test` (auto-discovery) and
> `node --test tests/*.test.mjs` both work. Use one of those.

Outputs: `corpus/survey.jsonl` (one row per app) and `corpus/summary.json`
(aggregate). The index is cached under `node_modules/.cache/fdroid/`, which the
existing `.gitignore` already excludes.

## Provenance

| | |
|---|---|
| Corpus | F-Droid, latest version of every package |
| Index | `https://f-droid.org/repo/index-v1.json` |
| **Index version** | **30000** |
| Index `repo.timestamp` | 1790497006850 = 2026-09-27T08:16:46.850Z |
| Index SHA-256 | `1f4bd109de2f5c1e5a13d8282d5a0b1411f170aee0b2426080e708803d6fb562` |
| Index size | 63,129,759 bytes |
| Index retrieved | 2026-09-27T19:53:44.243Z |
| Packages in index | 4,475 |
| **Seed** | **20260928** (mulberry32, 32-bit integer ops) |
| Sampled | 4,475 (census) |
| Classified OK | 4,475 (0 failures) |
| Wall clock | 1,459.4 s at concurrency 8 |
| Node | v22.21.0 |

**Why index-v1 and not the newer index-v2.** v2 is 2.5% smaller but publishes
**no `repo.version` identifier** — only a timestamp. v1 publishes
`repo.version = 30000` and `repo.maxage = 14`. Both serialisations carry an
identical `repo.timestamp` and an identical package count (4,475), so they
describe the same repository state and choosing v1 costs no coverage. v1 also
publishes per version the `apkName`, the APK `size`, the sha256 `hash`,
`minSdkVersion`, `targetSdkVersion` and a `nativecode` array, which makes URL
construction and provenance authoritative rather than reconstructed. Licence
data, which v1 dropped, is recoverable by optional join against v2
(`ANDRO_WITH_LICENSES=1`) and is not used in the headline.

**Determinism.** The app list is sorted by `packageName` with a code-unit
comparison (never `localeCompare`, which is locale-dependent), then shuffled
with a seeded `mulberry32` and Fisher–Yates. Verified: same seed → identical
order; different seed → different order; sorted input confirmed. Rows are
written in sample order, not completion order, so concurrency does not affect
the output file.

## Method

A ZIP's central directory lives at the end of the file. For each APK:

1. `HEAD` for the total size (0 body bytes).
2. `Range: bytes=-131072` for the End Of Central Directory record.
3. If the directory is not already inside that tail, a second exact range for
   it. Needed for 252 of 4,475 apps.
4. One small range for `AndroidManifest.xml` to read `minSdkVersion` from the
   APK's own bytes via a from-scratch binary-AXML reader.

Native code is defined as **an entry matching `lib/<abi>/<file>.so`**. No entry
payload is ever decompressed except the manifest.

### Validation

- **Cross-check against the F-Droid index's own `nativecode` declaration:**
  index says native 2,473; we measured native 2,472; we found native where the
  index declared none: **0**.
- The single disagreement is `com.tht.k3pler`, whose declared `nativecode` is
  `amd64-Linux-gpp/jni`, `amd64-Windows-gpp/jni`, `i386-MacOSX-gpp/jni` and
  friends — **desktop** JNI platform tags from a Kotlin Multiplatform build, not
  Android ABIs. Its APK genuinely has no `lib/<android-abi>/` entry. Here the
  measurement is more precise than the index, and the app is correctly counted
  in the numerator.
- **`minSdkVersion` parsed from 4,474 / 4,475 manifests, disagreeing with the
  F-Droid index value in 0 cases.** The one unparsed APK,
  `org.fdroid.fdroid.privileged.ota`, has no `AndroidManifest.xml` entry at all
  (it is a resource-only OTA package).
- The AXML reader had three separate bugs during development (a UTF-16
  double-byte-swap, a u32-vs-u16 offset-array confusion, and using the ZIP
  general-purpose UTF-8 flag `0x0800` instead of the `ResStringPool` flag
  `0x0100`). All three are covered by regression tests in both string-pool
  encodings; each was confirmed to fail the test suite when reverted.

## Byte cost

| | |
|---|---|
| **Fetched by the range approach** | **669,714,734 B (638.69 MiB)** |
| **What a full download would have cost** | **81,700,227,935 B (76.089 GiB)** |
| Fraction of a full download | **0.820%** |
| Mean per app | 149,657 B (vs a mean APK of 18,257,034 B) |
| HTTP requests | 13,677 (1 retry, 0 redirects) |
| Retries | 1 transient `fetch failed`, recovered |

The 128 KiB tail dominates the cost: 4,475 × 131,072 ≈ 587 MB of the 670 MB
total. Everything else — directories and manifests — is ~83 MB.

Per-row `bytesFetched` sums exactly to the reported total (669,714,734) and
per-row `requests` sums exactly to 13,677. This is checked on every run and
printed in the report. It is worth stating explicitly because an earlier
version measured per-row cost as a delta of a *shared* global counter, which
under concurrency over-counted by exactly the worker count; the fix charges each
network call to its own call site, and a test asserts the sum reconciles.

## Breakdown

### By `minSdkVersion` (read from each APK's own `AndroidManifest.xml`)

| `minSdkVersion` | no native code | total | % |
|---|---:|---:|---:|
| < 16 (pre-Jelly Bean) | 294 | 339 | **86.73%** |
| 16–20 (JB – JB MR1) | 338 | 501 | **67.47%** |
| 21–23 (L – M) | 733 | 1,374 | **53.35%** |
| 24–25 (N – N MR1) | 256 | 975 | **26.26%** |
| 26–28 (O – P) | 266 | 904 | **29.42%** |
| 29–32 (Q – T) | 101 | 330 | **30.61%** |
| 33+ (recent) | 14 | 51 | **27.45%** |
| unknown (no manifest entry) | 1 | 1 | 100.00% |

**The single most actionable finding in this report is the trend, not the
headline.** The pure-DEX share collapses from 86.7% below API 16 to roughly
27–30% for anything targeting API 24 or later. Bytecode-only execution is
plausible for a large majority of *old* F-Droid apps and for a *minority* of
current ones. The capability is real but it is a legacy channel, and a runtime
built for it is betting on the long tail, not on the ecosystem.

### Most common native ABIs

| ABI | libraries shipped | apps shipping |
|---|---:|---:|
| `x86_64` | 16,332 | 2,065 |
| `arm64-v8a` | 9,348 | 2,207 |
| `armeabi-v7a` | 6,555 | 1,912 |
| `x86` | 4,769 | 1,566 |
| `armeabi` | 84 | 60 |
| `mips` | 45 | 36 |
| `mips64` | 34 | 28 |
| `riscv64` | 2 | 1 |

`arm64-v8a` is the most widely *shipped* ABI by app count while `x86_64` has the
most *libraries* — desktop-class tooling ships large x86_64 payload sets
(android-emulator targets, gRPC, Rust NDK builds). `mips`/`mips64`/`riscv64`
are effectively dead ABI directories that a handful of legacy projects never
cleaned up; their presence should not be read as real hardware support.

### Other measurements

- Mean `classes*.dex` count: 1.532. 3,080 apps have exactly one DEX; 1,393 have
  more than one; **2 have none** (`org.fdroid.fdroid.privileged.ota`, a
  resource-only package, and `org.rayg.streaktracker`).
- Mean DEX payload: 3,546,121 B compressed / 8,075,211 B uncompressed.
- Mean ZIP entry count: 847.4 (max 32,290). 0 ZIP64 archives.
- `resources.arsc` present in 4,474 of 4,475.
- **Mean APK size: 5.4 MiB for pure-DEX apps vs 27.1 MiB for apps with native
  code.** The pure-DEX set is 10.63 GiB in total. The absence of native code is
  strongly correlated with the absence of a large SDK, which is the mechanism
  behind the `minSdk` trend above, and it also means the *interesting* runtime
  target set is the small, simple, self-contained apps.

## Sensitivity to the definition

| Definition | Result |
|---|---|
| **A.** No `lib/<abi>/*.so` entry (the literal definition) | **2,003 / 4,475 = 44.76%** |
| B. A: and no `.so` anywhere in the archive | 2,002 / 4,475 = 44.74% |
| C. B: and at least one `classes*.dex` present | 2,001 / 4,475 = 44.72% |

The result is robust to tightening the definition: the whole plausible range is
**44.72% – 44.76%**, a spread of 0.04 percentage points. Only 6 apps carry
`.so` files outside `lib/`, and 5 of those (Chaquopy, a USB bridge, a bundled
Linux userland) also have ordinary `lib/` entries, so they were already
counted correctly. The lone exception, `org.bitbucket.watashi564.combapp`, has
obfuscated `res/5x.so` and `res/yG.so` files that are not ABI-shaped and are
most likely resources with a misleading extension.

Earlier runs of this survey classified 4,474/4,475, each time losing a different
app to a transient connection reset. Bounding those runs gives 44.76%–44.78%,
which brackets the final figure; the final run's retry-on-connection-error
handling classified 4,475/4,475 with 0 failures.

## Limitations

### The one that matters most

**This measurement establishes that a pure-DEX APK contains no native code. It
does not establish that such an APK would run — and the gap between those two
statements is where this project actually lives.**

Absence of `lib/**.so` is *necessary* for bytecode-only execution, not
*sufficient*. A pure-DEX APK may still:

- call native code **transitively**, through a library that loads it at runtime
  (the survey found 5 apps shipping real `.so` payloads under `assets/`, e.g.
  Chaquopy's Python runtime and a bundled `llama.cpp`/busybox userland, which
  `lib/`-only detection misses by construction);
- depend on Android framework services that exist only on a device
  (`ActivityManager`, `PackageManager`, `WindowManager`, `NotificationManager`, …);
- depend on `content://` provider IPC with other installed apps;
- use reflection into platform internals, or `DexClassLoader` to fetch more code;
- require a real `libart.so`/ART runtime for anything subtle in the class
  loader, verifier or JIT.

The real number of apps a bytecode-only runtime could **actually execute** is
some number ≤ 44.76% of this corpus, and this survey provides no way to
estimate how much smaller. If the project needs a feasibility argument, that
argument is the next measurement, and it is a much harder one.

### The rest

- **F-Droid is not the Android app population.** It over-represents small,
  independent, often single-developer projects and under-represents commercial
  apps, games, and apps depending on large proprietary SDKs — precisely the
  segment most likely to ship native code. This number should be read as a
  **lower bound** on the ecosystem's pure-DEX share, not an estimate of it. The
  `minSdk` trend shows the mechanism directly: the measurement is strongly
  confounded with app age and project size.
- **Latest version per package only.** 13,689 versions exist across 4,475
  packages. Older versions are more likely to be pure-DEX, so this biases
  *against* the numerator. A version-level census would raise the number.
- **Entry names, not file contents.** A `.so` is identified by path, never by
  inspecting the ELF header, so a native library stored under a non-`.so` name
  in `lib/<abi>/` is missed. Non-standard ABI directory names are possible.
- **F-Droid index version 30000 only.** The number is valid for that index
  state. F-Droid's index changes daily; a re-measurement must re-record
  `repo.version`, and a number without one is not comparable to this one.
- **No signature verification.** SHA-256 values come from the F-Droid index and
  were not checked against the served bytes; a compromised CDN could in
  principle serve different content. The SHA-256 of the central directory bytes
  actually parsed is recorded per row so any future re-measurement can detect a
  difference.
- **No execution, no behaviour.** Nothing here measures whether the runtime can
  observe network or file side effects, nor whether the resulting sandbox is
  sound. A smaller reachable population makes the sandbox cheaper to build; it
  says nothing about whether it works.

## What this licenses the project to claim

Exactly one claim:

> 2,003 of 4,475 APKs in the F-Droid index at version 30000 contain no
> `lib/<abi>/*.so` entries, and are therefore not **structurally** disqualified
> from execution by a bytecode-only runtime.

And the honest framing of the project it implies: **bytecode-only execution is a
real but minority and ageing channel — about 45% of this corpus, concentrated
in pre-API-24 apps — and the remaining ~55% is out of scope by construction
rather than by choice.**

Not: that those apps run; that this says anything about Google Play; that
behavioural observation is feasible; that any of this makes the sandbox safe.
