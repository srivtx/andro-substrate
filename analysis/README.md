# `analysis/` — the static substrate-dependency predictor

Consumes [`tools/dexcore`](../tools/dexcore) and answers, from an APK alone and
with no device:

> Does this app structurally require a capability a browser-native substrate
> does not have, and which `SUB.*` IDs in the frozen divergence taxonomy does it
> require?

The gap it fills is stated in [`corpus/report.md`](../corpus/report.md): 44.76%
of the corpus has no `lib/<abi>/*.so`, and that is a **necessary** filter, not a
sufficient one. The difference between "no native code" and "will run" is the
project's actual subject matter and it had no measurement.

**Read [`prediction.md`](prediction.md) for the rubric, the 120-APK
measurement, and the threats to validity.** Read
[`../docs/divergence/0004-static-predictor.md`](../docs/divergence/0004-static-predictor.md)
for the decision record and the full ID mapping table.

## Two rules this crate is built around

1. **Static facts only, and `unknown` where a fact is not available.** No
   interpreter, no call graph, no `resources.arsc`, no `debug_info_item`, no
   `encoded_value`. Where a signal needs one of those, the field says so and the
   limitation is named.
2. **Never present a guess as an established fact.** Two independent axes of
   evidence strength are serialised, never combined:

   * *evidence* — `reference` (a pool entry) / `declaration` / `call site`
   * *taxonomy mapping* — `VERIFIED` (the API's contract **is** the assumption) /
     `CONJECTURE` (the linkage assumes a usage pattern)

## Layout

| path | what it is |
|---|---|
| `src/zip.rs` | central-directory reader; `stored` + `deflate` only, everything else a typed error |
| `src/strings.rs` | DEX string-constant classifiers, each individually tested with its failure mode |
| `src/taxonomy.rs` | 145 rules mapping framework APIs to 76 taxonomy IDs, each with a confidence (116 VERIFIED / 29 CONJECTURE) |
| `src/dexscan.rs` | pool, class and instruction walk: invoke kinds, `native` declarations, call sites |
| `src/analysis.rs` | per-app aggregation into `AppFacts`; every selection rule is in a doc comment |
| `src/score.rs` | the ten-component rubric, four gates, five bands |
| `src/bin/predict.rs` | per-APK JSON driver |
| `tests/pipeline.rs` | 14 end-to-end tests over the six real DEX fixtures from `tools/dexcore` |
| `examples/dex-sections.rs` | prints the `map_list` inventory — the one command that checks the DEX 039 finding |
| `examples/why-undecodable.rs` | shows why a `code_item` fails to decode, and which failures cost coverage |
| `examples/streambytes.rs` | dumps raw code units for one method, for byte-level inspection |
| `run-sample.mjs` | the deterministic 120-APK sample driver |
| `sample/rows.jsonl`, `sample/summary.json` | derived rows and aggregates (committed) |
| `validation-set/` | 20 hand labels, six features, SHA-256s, and why 20 is too few |
| `validate-prediction.mjs` | correlation harness; exits 3 with "NOT VALIDATABLE YET" |

## Use

```sh
cd analysis
cargo build --release

# one APK, full document (includes every pool entry — tens of MB on a big app)
./target/release/predict app.apk

# one APK, signal blocks only
./target/release/predict --summary app.apk

# many, one compact row each
./target/release/predict --jsonl --out rows.jsonl a.apk b.apk c.apk

# the 120-APK sample that produced every number in prediction.md
node run-sample.mjs --n 120 --strata 60:60

# the static half of the correlation, and the honest refusal of the other half
node validate-prediction.mjs
```

No APK is ever committed. The download cache defaults to `/tmp`, and
`corpus/apks/` is gitignored.

## The three findings worth knowing before reading the code

* **`SUB.FW.INVOKEDYNAMIC` fires on 119/120 sampled apps** — `const-method-handle`
  is in 119/120, `invoke-custom` in 81/120, `invoke-polymorphic` in 82/120. This
  is a property of the `d8` toolchain, not of 119 individual apps.
* **No sampled DEX has a `call_site_id_item` or `method_handle_item` section**
  (0/120, including DEX 039 files with 13,951 `const-method-handle`
  instructions), and the `method@` operand of `invoke-polymorphic` is the
  `NO_INDEX` sentinel `0xffff`. The invokedynamic dependency is therefore
  **unenumerable**: a substrate cannot implement "just the bootstrappers these
  apps need", only the machinery. The rule table reports 12/120 for the same
  family, because it keys on class names; both numbers are published.
* **Play Services and Play Integrity are 0/120.** F-Droid build recipes remove
  GMS dependencies, so the gate that the pre-registration expects to dominate has
  never fired. It is untested code, and the 0/120 is a fact about F-Droid, not
  about the ecosystem.

## Tests

```sh
cargo test        # 52 unit + 14 integration + 1 doc = 67
cargo clippy --all-targets   # clean, zero warnings
cargo fmt --check            # clean
```
