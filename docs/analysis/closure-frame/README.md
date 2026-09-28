# closure-frame — the measurement behind 0001

`docs/analysis/0001-why-the-ranking-inverts.md` claims that the static
`android.*` surface an APK references does not predict the framework closure it
actually needs at run time, and that the ranking in `analysis/candidates.md` is
contradicted by that. These are the scripts that produced the numbers, in the
order they run.

| file | role |
|---|---|
| `art-trace.py` | decoder for ART's buffered method-trace format (14-byte records). Self-checking; see its docstring. |
| `capture.py` | cold-start capture: `am start-activity -S -W -P`, then wait for the on-device file to stop growing. |
| `sample20.json`, `apps20.list` | the 20 extra APKs, drawn from `analysis/candidates/measured.jsonl` to span `distinctAndroidMethods` 15–228. |
| `measure.py` | decode every trace, join against the committed static table, write `../measurement.json`. |
| `stats.py` | every derived figure. Prints `key = value`; `--json` for machines. |
| `test-figures.py` | pins the document. Fails on any figure that disagrees **or** on any integer in the prose `stats.py` cannot account for. |
| `fwsets.json` | each app's exact framework method set (rep 1), for the core/intersection work. |

```sh
# capture (rooted Android 13 arm64 device, APK installed)
python3 capture.py 2
# decode + join
A14_TRACE_DIR=<dir holding the traces> python3 measure.py
# figures
python3 stats.py
# the document cannot drift from the data
python3 test-figures.py
```

`analysis/tests/closure_frame.rs` is the `cargo test` entry point: it runs
`test-figures.py`, re-asserts the document's static table straight from
`analysis/candidates/measured.jsonl`, and records the fact that
`analysis/candidates.md` still ranks on a basis this measurement contradicts.

## Traces are not committed

They total roughly 95 MB. `measurement.json` carries a SHA-256 for every trace
consumed — the 51 cold-start captures of §1.3 and the 15 legacy artefacts of
§1.2 — so the bytes are identifiable even though they are not in the tree.
Eight of the 51 hit the ART trace buffer and are truncated at 599,184 method
calls; every figure in the document is reported on both the full cohort and the
16 untruncated apps.
