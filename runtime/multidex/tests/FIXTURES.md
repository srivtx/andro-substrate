# Fixtures

Extracted `.dex` files from genuine multidex F-Droid APKs. **No APK is
committed** — only the individual `classes*.dex` entries that were extracted
from them, because an APK carries native libraries, resources and assets that
this component never reads, and a 45 MB artefact in a source tree is a cost
nobody gets value from.

Every fixture below has a SHA-256 in this file and a test that loads it, so a
fixture cannot drift without a test failing.

## Provenance

Both fixtures come from one APK:

| | |
|---|---|
| package | `org.fcitx.fcitx5.android.plugin.sayura` |
| version | 114 |
| source | `https://f-droid.org/repo/org.fcitx.fcitx5.android.plugin.sayura_114.apk` |
| extracted | `classes.dex`, `classes2.dex` |

It was chosen for being genuinely multidex *and* small (60 772 bytes of DEX
total, from a 107 938-byte APK). Among the multidex entries in
`corpus/survey.jsonl` it is the smallest by total uncompressed DEX size that is
not a near-empty plugin stub, so it is the cheapest fixture that still carries
real application code.

## The fixtures

| file | bytes | SHA-256 |
|---|---:|---|
| `sayura_classes.dex` | 56 024 | `7542b0716ddf7c9b00a1113525a06e77e65ffaf8713ab863b0e7a60967c363cd` |
| `sayura_classes2.dex` | 4 748 | `fa75ae061b2a3c7e107c8ced65bb2b4f1823075a2a5a1ca1834b1f47e24193ef` |

Reproduce with:

```sh
curl -sSfLO https://f-droid.org/repo/org.fcitx.fcitx5.android.plugin.sayura_114.apk
unzip -o org.fcitx.fcitx5.android.plugin.sayura_114.apk 'classes*.dex' -d out
shasum -a 256 out/classes.dex out/classes2.dex
```

## What this pair exercises, and what it does not

This is a real `dx` build, so it covers the *ordinary* multidex shape:

- **Independent index spaces.** 725 strings / 498 methods in `classes.dex`
  against 89 strings / 38 methods in `classes2.dex`. `method_id[0]` is
  `Landroid/app/ActionBar;.setDisplayHomeAsUpEnabled` in one file and
  `Lj$/util/Map$-CC;.$default$compute` in the other — unrelated methods at the
  same index. Asserted in `load_order.rs::pool_indices_are_per_file`.
- **Cross-file `invoke`.** Nine methods defined only in `classes2.dex` are
  referenced from `classes.dex`'s method pool, so a loader that resolved within
  the referencing file would report them missing. Asserted in
  `resolution.rs::a_call_from_file_1_resolves_into_file_2`.
- **A superclass in a later file.** Legal, and the reason resolution cannot be
  a single forward pass.
- **A well-formed duplicate-free build.** 101 + 5 disjoint class definitions.

**It does not contain** a duplicated class, a split `class_def`, or two files
defining the same method. `dx` never splits a `class_def_item` across files, and
a genuine duplicate class is a build bug. Those shapes are therefore built
synthetically with `dexcore`'s writer in `tests/common/mod.rs`, and tested in
`resolution.rs` and `negative.rs`.

That split is deliberate. Pretending a real APK exercises the merge and
ambiguity rules would leave those rules untested, because no well-formed APK
reaches them — and a rule that is only ever exercised by the code that
implements it is a rule nothing has checked.

## Corpus context

From `corpus/survey.jsonl`, all 4475 rows with `ok: true`:

| `dexCount` | packages |
|---:|---:|
| 0 | 2 |
| 1 | 3080 |
| 2 | 855 |
| 3 | 323 |
| 4 | 108 |
| 5 | 56 |
| 6 | 23 |
| 7 | 11 |
| 8 | 3 |
| 9 | 5 |
| 10 | 4 |
| 11 | 3 |
| 13 | 2 |

**1393 / 4475 = 31.13 %** of the corpus is multidex. Two entries have no DEX at
all and are excluded from neither figure — they are counted in the denominator,
so the rate is very slightly pessimistic.

The rate rises with `minSdk`: **6.67 %** below 21 (56/840) against **36.79 %**
at or above 21 (1337/3634), `r = 0.34` between `minSdk` and multidex. A
corpus-wide average therefore understates the problem for any modern app.

### On the local candidate cache

`/tmp/andro-substrate-candidates/` holds 204 APKs of which only **3** are
multidex (1.47 %), which contradicts the 31.13 % above and is worth explaining
rather than leaving as an apparent contradiction:

- All 204 agree with the survey's `dexCount` exactly, so the survey is not wrong
  and neither is the cache.
- The cache is size-biased toward tiny APKs: median 0.10 MB against the
  corpus median of 6.63 MB, a factor of 66.
- Multidex correlates with size (Pearson `r = 0.157` on APK bytes; median 4.42 MB
  for single-dex against 13.80 MB for multidex), so a tiny-APK sample will
  under-represent it.

**Any measurement of multidex prevalence must use the corpus, not this cache.**
