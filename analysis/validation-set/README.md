# The validation set: 20 hand labels

**Read `../prediction.md` §7 T-VAL-2 before using anything in this directory.**
20 apps cannot validate a scorer, and the validator that reads these labels
reports 20/20 agreement on every feature — which is worth nothing as evidence,
because the labels were written by the analyzer's author, from the same static
artefacts the analyzer reads. Perfect agreement is the *expected* result of
writing both sides of a comparison.

## What is here

| file | contents |
|---|---|
| `labels.json` | 20 apps × 6 features, with SHA-256s, per-app notes, and the selection rule |
| (no APKs) | never committed. `corpus/apks/` and the download cache are gitignored; only digests and derived rows are |

## The selection rule

```
population:  analysis/sample/rows.jsonl  (the 120-APK deterministic sample)
order:       ascending by packageName, ties broken by versionCode
take:        the first 20
```

Deterministic, re-derivable from a committed file with no extra tooling, and
independent of every signal the analyzer reports — it cannot be contaminated by
picking apps that look good or bad. The 20 span both strata: 10 DEX-only, 10
native.

## The six features

| id | feature |
|---|---|
| `F1` | `native_payload` — ships a native payload (`lib/<abi>/*.so`, or an ELF under `assets/`), or calls `System`/`Runtime` `loadLibrary`/`load`, or declares a `native` method nothing in the APK implements |
| `F2` | `dynamic_invoke` — decoded bytecode contains `invoke-polymorphic`, `invoke-custom` or `const-method-handle` |
| `F3` | `trust_client_api` — references a Play Integrity, SafetyNet, Play Services, licensing or DRM client API (`MediaDrm` and `com.widevine` included) |
| `F4` | `build_identity` — an instruction reads an `android.os.Build` identity field |
| `F5` | `reflection` — a decoded call site targets `Class.forName` / `getMethod(s)` / `getDeclaredMethod(s)` / `Field.setAccessible` / `Method.invoke` / `Proxy.newProxyInstance` / `ClassLoader.loadClass` |
| `F6` | `dynamic_code` — an external `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader` / `BaseDexClassLoader` class is referenced |

Label values are `yes`, `no`, `unknown`. All 120 cells are `yes` or `no`; no
feature needed `unknown` on this population, and that is itself a finding worth
naming — it means none of the six features is ambiguous *on these 20 apps*, which
is a much weaker claim than "none is ambiguous".

## Distribution, and the point of it

| feature | yes | no | positive rate |
|---|---:|---:|---:|
| `F1` native_payload | 10 | 10 | 50% |
| `F2` dynamic_invoke | 20 | 0 | 100% |
| `F3` trust_client_api | 7 | 13 | 35% |
| `F4` build_identity | 19 | 1 | 95% |
| `F5` reflection | 19 | 1 | 95% |
| `F6` dynamic_code | 4 | 16 | 20% |

Three of the six features are ≥95% or ≤20% positive. A feature that is almost
always true cannot discriminate between apps, so agreement on `F2` is
arithmetically forced rather than informative. Only `F1` and `F3` have spread,
and only `F1` has enough of it to be worth a 20-app test at all.

`F2` at 100% is the sharpest illustration: **a feature that is always true
carries zero information and would score a perfect kappa against any labels
whatsoever.** It is in the set because it is the most important feature in the
rubric, not because 20 labels can test it.

## Digests, and why they are here

`labels.json` records two SHA-256s per app:

* `sha256` — of the bytes actually fetched from `https://f-droid.org/repo/` and
  analysed.
* `corpusIndexSha256` — the digest F-Droid publishes in its index for the same
  package and versionCode.

`labels.json.selection.sha256Verification` records that **20 of 20 match**. That
closes a specific gap named in `corpus/report.md`: "SHA-256 values come from the
F-Droid index and were not checked against the served bytes; a compromised CDN
could in principle serve different content." For these 20 apps it is now checked.

## Known defects recorded in the labels

* **`com.co3` has an inferred library name of the bare string `"lib"`**, a
  mis-binding: the argument register was reused on another path. The `F1` label
  does not depend on it — the gate fires on 21 `lib/` entries — and the defect is
  recorded in the app's `note` rather than hidden.
* **`app.traced_it`'s `F3` is one string constant** (`Landroid/media/MediaDrm;`).
  Thin evidence, and a stricter labelling rule would have called it `unknown`.
  Recorded as `yes` with the caveat inline.
* **`com.anysoftkeyboard.*`'s `F6` is the weakest positive in the set** — a
  keyboard language pack referencing `BaseDexClassLoader` through the
  AnySoftKeyboard API. Flagged as such in the app's `note`.
* **`com.anysoftkeyboard.languagepack.slovene` and `...esperanto` contain
  identical DEX** apart from dictionary data. Their identical labels are correct
  and their agreement tests nothing, so together they cost one useful
  observation. Noted rather than swapped out, because changing the selection rule
  after seeing the results would be exactly the reverse-engineering
  `research-protocol.md` T-09 prohibits.

## Running the comparison

```sh
node analysis/validate-prediction.mjs
```

Exits 3 with an explicit "NOT VALIDATABLE YET" until either
`analysis/validation-set/observed.json` exists or a non-synthetic recording
appears in `oracle/schema/examples/`. It filters the two committed fixtures on
`synthetic === true` and `provenance.execution_performed === false` so they can
never be mistaken for evidence.
