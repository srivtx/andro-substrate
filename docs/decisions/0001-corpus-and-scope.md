# 1. Corpus and scope for the native-code measurement

- Status: accepted
- Date: 2026-09-28
- Deciders: andro-substrate
- Relates to: `tools/corpus/*`, `corpus/report.md`

## Context

andro-substrate proposes a browser-native runtime that executes untrusted
Android APK bytecode (Dalvik/DEX) with no Linux kernel, no native code and no
network egress, so that an app's code-level side effects can be observed
without the APK leaving the machine.

The honest scope of that proposal depends on one measurement that nobody has
published: **what fraction of real-world Android apps contain no native code**
(equivalently: no `lib/<abi>/*.so` entries in the APK ZIP), and therefore
could in principle be executed by a bytecode-only runtime.

Without that number the project is either a research artefact with no
reachable users, or a general-purpose Android runtime, which is a different and
much larger project. The number has to come first.

## Decision

### Corpus: F-Droid, and only F-Droid

The corpus is the F-Droid repository, latest version of every package, as
published by `index-v1.json` at index version 30000.

Alternatives considered and rejected:

- **Google Play.** Rejected on legal grounds. Google Play's Terms of Service
  prohibit scraping, and building a research corpus on a ToS-prohibited source
  would make the result unpublishable. This is not a judgement about
  technical feasibility.
- **APKPure, APKMirror and similar mirrors.** Rejected. Their licensing and
  terms are undocumented with respect to automated corpus research, they
  repackage upstream binaries, and their index format is not a documented
  public contract. Reproducibility would rest on an unpublished scraper.
- **A hand-curated set of "simple" apps.** Rejected as self-defeating: any
  curation that improves the number is exactly the bias the measurement exists
  to eliminate.

F-Droid is free/libre software, publishes a documented repository index as a
machine-readable contract, keeps historical versions addressable by a stable
URL pattern, and states plainly that it aims to host "only software libre de
bonne foi". The licence of the corpus' *contents* is therefore not a research
blocker in the way a commercial app store's would be.

The cost of this choice is stated plainly: **F-Droid is not a random sample of
the Android app population.** It over-represents small, independent, often
single-developer projects, and under-represents commercial apps, games and
apps depending on large SDKs — precisely the segment most likely to ship
native code. A number derived here is a lower bound on how much of the
ecosystem a bytecode-only runtime can address, not an estimate of it. This is
recorded as a first-class limitation, not a footnote.

### Index serialisation: index-v1.json, not index-v2.json

F-Droid serves both `index-v1.json` (63,129,759 bytes) and `index-v2.json`
(61,580,220 bytes). The newer v2 was evaluated first and rejected for a
specific reason: **v2 does not publish a repository version identifier.** It
carries `repo.timestamp` but no `repo.version`, so results keyed to v2 could
only be pinned to a timestamp. v1 publishes `repo.version = 30000` together
with `repo.maxage`, which is the explicit named index state this measurement
needs in order to be checkable later.

Both serialisations carry an identical `repo.timestamp`
(`1790497006850`, 2026-09-27T08:16:46.850Z) and an identical package count
(4,475), so they describe the same repository state and choosing v1 costs no
coverage. v1 additionally publishes, per version, the `apkName`, the APK
`size`, the `hash` (sha256), `minSdkVersion`, `targetSdkVersion` and a
`nativecode` array. The `apkName` and `hash` fields make URL construction and
provenance authoritative rather than reconstructed from a URL pattern.

Licence information, dropped by the v1 serialisation, is recovered by optional
join against v2 `metadata` (`ANDRO_WITH_LICENSES=1`). It is not used in the
headline measurement.

Note for future readers: at index version 30000 the v1 layout is
`packages[<packageName>][<ordinal>] = <version record>`, not the older
`packages[<packageName>].packages[]` array. Code written against the older
layout will silently find zero versions.

### Sampling method

The survey classifies **every** package in the index (N = 4,475), not a
sample. A census removes sampling error entirely, which is strictly better
than a sample of the same size, and the range-request method makes it cheap
enough to be practical.

The sampler is still implemented, seeded and exercised, because the brief
requires a reproducible sampling path and because the seeded subsample is
quoted alongside the census:

- app list sorted by `packageName` with a code-unit comparison, so ordering
  never depends on host locale;
- `mulberry32` PRNG seeded with the fixed constant **20260928**, all 32-bit
  integer arithmetic, identical on every platform;
- Fisher–Yates shuffle of the sorted list, then take the first n.

When n ≥ population the census is returned unshuffled and the seed has no
effect on the result; the seed is still recorded. The seeded n = 3,000
subsample is computed from the census rows with the same routine and reported
in `corpus/summary.json` under `seededSubsample`, with a Wilson 95%
interval.

### What is measured

"Contains no native code" is defined operationally as: **the APK's ZIP central
directory contains no entry whose path matches `lib/<abi>/<file>.so`.**

Entry names are read from the central directory, which is fetched with HTTP
range requests: a suffix range for the End Of Central Directory record, then a
second range for the central directory itself when it is not already inside
the first. No APK is downloaded whole. The whole-file SHA-256 comes from the
F-Droid index; the SHA-256 of the central directory bytes actually parsed is
recorded per row in `corpus/survey.jsonl` so a later reader can prove they
inspected the same directory.

`minSdkVersion` is parsed from the APK's own binary `AndroidManifest.xml`,
using one extra small range request and a from-scratch AXML reader, and is
cross-checked against the index value. This cross-check is the validation
mechanism for the whole pipeline.

A `.so` entry outside `lib/` is counted separately as `straySharedObjects` and
does **not** by itself mark an APK as having native code, because such an entry
is not loadable by the Android native linker and so does not imply a
requirement for a native runtime. Those apps are still reported.

## What the number licenses us to claim

The measurement supports exactly one claim:

> **X out of Y APKs in the F-Droid index at version 30000 contain no
> `lib/<abi>/*.so` entries, and are therefore not *structurally* disqualified
> from execution by a bytecode-only runtime.**

It does **not** support any of the following, and no such claim may be made
downstream:

- that such an APK **would run**. A pure-DEX APK may still call into native
  code transitively, use JNI declared in the manifest, depend on Android
  framework services that only exist on a device, depend on
  `content://`/provider IPC, or use reflection into platform internals. Absence
  of native code is *necessary* for feasibility, not *sufficient*.
- anything about **Google Play** or the commercial app population. The corpus
  is F-Droid and the sample is not random with respect to the ecosystem.
- anything about **behavioural observability**. Whether the runtime can
  actually observe the app's network and file side effects is a separate
  engineering question with its own success rate, and no number in
  `corpus/report.md` speaks to it.
- anything about **safety**. A lower share of reachable apps makes the sandbox
  cheaper to build; it says nothing about whether the sandbox is sound.

The permitted framing for the project as a whole is: *bytecode-only execution
is a real but minority channel, covering roughly the fraction reported, and
the remainder of the app population is out of scope by construction rather than
by choice.*

## Consequences

- Every figure in `corpus/report.md` must remain recomputable from
  `corpus/survey.jsonl` and `corpus/summary.json`, and tied to a named index
  version and a recorded seed. The raw index JSON is cached under
  `node_modules/.cache/fdroid/` so the existing `.gitignore` already excludes
  it and no ignore rule needed editing.
- Any future re-measurement must re-record `repo.version`; a number without
  one is not comparable to this one.
- If the headline fraction is low, that is a publishable finding about the
  feasibility of bytecode-only Android execution, and it should be reported as
  such rather than softened by narrowing the corpus.
