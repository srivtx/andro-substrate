# substrate-harness — run a real APK under the framework shim

The recorder. It is the only crate in andro-substrate that opens a file, and it
opens exactly the one the researcher named. The instrument (`shim`) has an empty
`std::fs` surface and its own source scan says so; this crate carries the same
scan, narrowed to the one read that is legitimate here
(`tests/no_side_channels.rs`, with a positive control so a green result means
something).

## Usage

```sh
# the lifecycle of the launcher activity, under a named substrate policy
cargo run --quiet --bin apk-run -- ~/apks/search_to_browser_2.apk --policy default

# one named method, to prove class resolution without a lifecycle
cargo run --quiet --bin apk-run -- ~/apks/search_to_browser_2.apk \
    --method 'Lpro/rudloff/search_to_browser/MainActivity;.<init>()V'

# a specific axis, and both artefacts to files
cargo run --quiet --bin apk-run -- ~/apks/termux_1000.apk \
    --policy 'identity=refusing;system_fs=absent' \
    --out out.recording.json --report out.report.txt
```

| flag | meaning |
|---|---|
| `--policy NAME` | `default`, `loud`, `refusing`, `loopback`, or `axis=value;…` over `identity`, `system_fs`, `cross_app_packages`, `network`, `time`. Default `default`. |
| `--method SIG` | run one method instead of the lifecycle, e.g. `Lcom/example/Foo;.compute()I` |
| `--static` | the `--method` target is `static` (no receiver) |
| `--budget N` | instruction budget per stage; `0` = unbounded. Default 25 000 000 |
| `--out FILE` | write the recording here instead of stdout |
| `--report FILE` | write the run report here instead of stderr |
| `--quiet` | do not print the run report |

Named policies are the two arms the committed differential already uses, so a
`--policy` value means the same thing here as in
`shim/recordings/differential.report.txt`. There is no flag that can open a
socket; `tests/real_apk_run.rs` asserts the axis vocabulary is exactly five.

## Exit codes

| code | meaning |
|---|---|
| 0 | a recording was produced and passed the shim's privacy scrub |
| 1 | the APK could not be read, or the run could not be started |
| 2 | the recording failed the privacy scrub — a redaction regression |
| 3 | the recording was produced but the app did not complete any stage |

`3` is not a tool failure. It is how the tool says the run produced a valid,
honest document about an app that stopped, so a corpus script can keep going
without parsing the report.

## The recording

`--out` writes a `ground-truth/1` document that `oracle/recorder/validate.mjs`
accepts. It is produced by `shim::realrec::build_real`, which patches the 40
fields enumerated in `PATCHED_FIELDS` and nothing else — the document shape is
single-sourced with the synthetic capture so a differential can compare them.

```sh
node oracle/recorder/validate.mjs harness/recordings/*.recording.json
```

## The report

`--report` writes a plain-text table: the `lifecycle.terminal` the run reached,
the stage it stopped at with the exact engine message, the framework surface that
app needed and the shim did not have, and the engine's counters. It is not a
`ground-truth/1` document and does not pretend to be — the format is a schema for
a capture, and "how much framework surface did this app need before it stopped" has
nowhere in it that would not either overstate the number or bury it.

## Reading the results

**[`FINDINGS.md`](FINDINGS.md) is the deliverable**: the per-candidate rung table,
the framework surface, the shadowing count, and the three defects the integration
found. `recordings/` and `reports/` are the artefacts every number in it comes
from.

## What it will not do

It does not make an app work. An app that needs a framework method the shim does
not have stops there and the report says so with the method named. That count is
the project's first real measurement of the shim's compatibility surface, and it
is a finding rather than a defect — see `FINDINGS.md` §7 for why growing the
registry until apps run is the wrong project.

Structurally absent regardless of the registry: no display (so `L2_FIRST_FRAME_DRAWN`
is unreachable), no `resources.arsc`, no Binder, no `invokedynamic`, no native
code, one `classes.dex` per run. Each is named in
`capture_quality.unobserved` on every recording.

## Layout

| file | role |
|---|---|
| `src/zip.rs` | a minimal, hostile-input-safe ZIP reader: stored + deflate, ZIP64, every field bounds-checked, every entry size-bounded |
| `src/apk.rs` | the APK's static facts: manifest via `dexcore::axml`, dex files, native libraries, assets, SHA-256 |
| `src/policy_named.rs` | `--policy` resolution, over the shim's own closed axis vocabulary |
| `src/report.rs` | the run report |
| `src/bin/apk-run.rs` | the CLI |
| `examples/insn-dump.rs` | a debugging aid: the decoded instruction stream of one method |
| `tests/no_side_channels.rs` | the inherited source scan, plus its positive control |
| `tests/zip_apk.rs` | hostile containers, and SHA-256 against the published vectors |
| `tests/real_apk_run.rs` | a real DEX runs and produces a valid recording |
