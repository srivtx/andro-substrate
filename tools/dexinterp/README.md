# dexinterp

A **Dalvik interpreter**. [`dexcore`](../dexcore) reads, decodes and writes DEX;
this crate **executes** it — decoded bytecode runs to completion against a typed
register file, a real heap, virtual dispatch, a real exception hierarchy, and a
boundary at which everything the engine does *not* implement is handed to a
framework shim and recorded.

## Why this exists

andro-substrate runs untrusted Android APK bytecode in a browser with no kernel,
no native code and no network egress, and its job is to run an app's
`Application` + `Activity` lifecycle and record every side effect.
44.76% of the F-Droid corpus in [`corpus/report.md`](../../corpus/report.md)
contains no native code; that is the ceiling on the project's reach, and it says
nothing about whether the remaining bytecode runs. This crate is the instrument
that turns "it did not work" into a located cause.

## The one thing to know: four outcomes, never one

The pre-registered protocol forbids a single "runs / does not run" number, and
the temptation to produce one anyway is what makes such a number worthless. So
every run ends in exactly one of four conditions, each with a stable name:

| Outcome | `kind()` | What it means | Whose finding it is |
| --- | --- | --- | --- |
| `Termination::ExceptionRaised` | `exception_raised` | The app threw and nothing caught it | The app |
| `Termination::BudgetExhausted` | `budget_exhausted`, `stack_overflow` | The app was still working when a limit fired | Ours — a `tier` result |
| `Termination::Unsupported` | `unsupported` + 8 named causes | The app reached bytecode we do not implement | Ours — a `gap` result |
| `Termination::EngineFault` | `malformed`, `out_of_memory` | The file breaks a rule the verifier would have caught | The file — a `divergence` result |

A run that hit the instruction budget was an app **still making progress**.
Recording that as a crash would report `SUB.CPU.TIERING` as `SUB.FW.CLASS_LOADER`,
which is the specific miscount the taxonomy exists to prevent.

```rust
match vm.invoke_method(class, "onCreate", "(Landroid/os/Bundle;)V", &[bundle]) {
    Ok(v) => println!("returned {v:?}"),
    Err(e) => println!("{} [{}]", e, e.termination().as_str()),
}
```

`Unsupported` and `Malformed` each carry their own enum of named discriminants
(8 and 11), so results are counted over named causes rather than over error
strings.

## What it does

- **All 224 specification-defined opcodes dispatched**, 219 executed to return
  and 5 refused by name with the reason and the cost of adding each
  (`tests/coverage.rs::EXCLUSIONS`). The evidence is the engine's own
  `Stats::opcode_counts`, not what a test believed it exercised — and an opcode
  the dispatch forgets is a test failure, not a silence.
- **Typed values, no verifier.** `Value` is a 9-variant enum, so a `long`/`double`
  high word (`Value::WidePad`) is representable and reading it is a type error.
  A `TypeMismatch` names the unit and opcode, because there is no install-time
  check to have caught it earlier.
- **Real control flow**: virtual/interface/super dispatch, all three goto
  widths, packed and sparse switches, try/catch/finally with inline unwinding,
  and `fill-array-data` payloads whose widths are recomputed from their own
  contents.
- **Real exceptions**: the `Throwable` hierarchy, catch matching by class,
  `finally` always running, and an uncaught throw ending the run as
  `ExceptionRaised` rather than as a fault.
- **A framework boundary that keeps going.** A missing class, an `abstract`
  method, or a `native` method goes to the `Host` trait. The default `Host`
  returns the declared type's zero value and records the substitution, so a
  census reaches the next statement instead of stopping at the first
  `android.*` call. `Stats::framework_calls_unimplemented` records the count,
  because "reached `onCreate`" means nothing without it.
- **Named refusals for `invoke-custom`.** The whole resolution chain is walked —
  call site, method handle, bootstrap method, its defining class, whether that
  class is in the file — and the missing link is reported, because
  `SUB.FW.INVOKEDYNAMIC` is a pre-registered hypothesis and this is what tests it.

## What it does *not* do

Stated plainly, because each of these is a limit on what a result from this
crate can claim.

- **No verifier.** See ADR [0003](docs/decisions/0003-execution-engine.md) §2.
  Every `Malformed` is a finding about a *file*, not about app behaviour.
- **No garbage collector.** Memory grows to the end of the run or to a limit.
  That is what makes `Stats::bytes_allocated` comparable between runs, and it is
  also why a long-running app needs `max_bytes`.
- **No threads.** `monitor-enter` is a per-object reentrant hold count, so mutual
  exclusion is trivially satisfied and happens-before is *nothing*. A
  `synchronized` method is not made atomic by taking a monitor. See
  `heap::Monitor`.
- **No `MethodHandle` runtime and no lambda desugaring at run time.**
  `invoke-polymorphic{,/range}` and `const-method-handle` are refused by name.
- **No `invoke-custom` execution.** The chain is decoded and the missing link
  reported; there is no `LambdaMetafactory`.
- **No CompactDex and no v41 container**, as in ADR
  [0002](../../docs/decisions/0002-dex-toolchain.md).
- **No framework.** `android.*` and `java.*` behaviour is the `Host` trait's job.
  This crate declares the class *hierarchy* it needs for control flow and nothing
  else. See ADR
  [0005](../../docs/decisions/0005-shim-and-observation.md) for what the shim is
  for.
- **No debug info, no profiling hooks, no JNI.**

## Measured against real APKs

`tests/real_dex.rs` runs every method of two real APKs in the corpus and
reports which returned, which raised, and which faulted.

**`fr.smarquis.sleeptimer_16200`** — 85 methods with code: **28 returned**, 57
raised, **zero `EngineFault`**. Every one of the 57 is a statement about the
shim's surface, not about the decoder: 25 `NullPointerException`, 16
`NoSuchMethodError`, 13 `UnsupportedOperationException`, 2
`IndexOutOfBoundsException`, 1 `NoSuchElementException`. The full census
dispatches 45 distinct opcodes over 446 instructions and 193 allocations.

**`com.termux.boot_1000`** — 14 methods with code: **5 returned**, 9 raised
(8 `NullPointerException`, 1 `NoSuchMethodError`), **zero `EngineFault`**. Its
constructors and `<clinit>` run, and `onCreate` runs real bytecode until it
stops at `Landroid/app/Activity;.setContentView(Landroid/view/View;)V` (opcode
`0x6e`), which needs a real framework.

**So the single most likely reason a modern F-Droid APK still fails is the shim,
not this engine.** That is measured, not assumed: the failures above are missing
`android.*`/`java.*` methods at real `invoke-*` instructions, not decode errors.

Every number in this section is asserted in `tests/real_dex.rs`, so the prose
cannot drift from the measurement. Two of them are pinned *exactly* — the census
totals and the opcode count — because a change to either means the engine
reaches a different amount of a real APK, which is the quantity the study
depends on and precisely the kind of quiet regression nothing else here would
notice.

## Resource limits

Untrusted input drives every count in a DEX header, so no declared count is
trusted as an allocation size.

| Limit | Default | Behaviour when reached |
| --- | --- | --- |
| `instruction_budget` | `DEFAULT_INSTRUCTION_BUDGET` (25,000,000) | `budget_exhausted` |
| `max_call_depth` | `DEFAULT_MAX_CALL_DEPTH` (512) | `stack_overflow` |
| `max_objects` | unlimited | `budget_exhausted` |
| `max_bytes` | unlimited | `budget_exhausted` |

The frame stack is a `Vec` and unwinding is a `pop` loop: there is no host stack
to overflow, so a runaway recursion is a typed error at a chosen depth rather
than a `SIGSEGV` in a browser tab. Budget exhaustion is a recorded outcome, not
a crash.

## Two `dexcore` defects this crate compensates for

Recorded rather than hidden; both are calls for `tools/dexcore` to fix at source,
and `dexcore` is out of scope here.

1. **`DexWriter::intern_type_list` writes each `ushort` element as 4 bytes**, so
   a multi-parameter prototype does not survive a write/read round trip. The test
   harness repairs multi-element lists in place after `emit`. `real_dex.rs` is
   unaffected — it only reads.
2. **A `32x` instruction is 2 code units, and a payload's width follows from its
   contents** (`4 + 2*targets`, `2 + 4*keys`), but the decoder reports 3 for the
   former and undercounts the latter by half. `Program::decode_code` corrects
   both and records the result in `Insn::units`, so the walk that builds the
   instruction list and the run loop that consumes it cannot disagree. The
   `F32X` defect is visible as every branch target after a `move/16` being wrong;
   the payload defect is invisible to a linear walk and was found in a real
   eight-target packed-switch payload.

## Tests

```
cargo test        # 153 tests
cargo clippy --all-targets
cargo fmt --check
```

| Suite | Count | What it holds the engine to |
| --- | --- | --- |
| unit tests | 55 | per-module units |
| `tests/semantics.rs` | 44 | opcode-by-opcode semantics, end to end |
| `tests/coverage.rs` | 8 | all 224 opcodes dispatched; each refusal named |
| `tests/negative.rs` | 32 | malformed input, budgets, and no panics |
| `tests/real_dex.rs` | 13 | two real APKs, censused and asserted |

Two of these are worth calling out:

- **`negative.rs` fuzzes deterministically.** It mutates a valid file 2,000
  times from a fixed seed and asserts that no mutation panics, that distinct
  malformed inputs produce *distinct* error kinds rather than one catch-all, and
  that every mutation ends in one of the four conditions. A random seed would be
  easier to write and worthless to re-run.
- **`coverage.rs` fails on an untested opcode.** Removing one case from the
  corpus fails with
  `1 of the 224 defined opcodes were never dispatched: ["if-lez"]`, which is
  checked, not assumed.

## Reading the code

| File | What is in it |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | crate overview, the three design properties, and an example |
| [`src/exec.rs`](src/exec.rs) | the run loop, dispatch, calls, exceptions, monitors |
| [`src/program.rs`](src/program.rs) | class layout, method/vtable resolution, `code_item` decoding |
| [`src/value.rs`](src/value.rs) | the `Value` enum, the JVM type model, MUTF-8-adjacent parsing |
| [`src/heap.rs`](src/heap.rs) | objects, arrays, strings, classes, monitors |
| [`src/ops.rs`](src/ops.rs) | the arithmetic, and the conversions that follow the Java rules |
| [`src/error.rs`](src/error.rs) | the four terminal conditions and the named discriminants |
| [`src/host.rs`](src/host.rs) | the `Host` trait and the recording default |
| [`src/classes.rs`](src/classes.rs) | the builtin `java.*` hierarchy needed for control flow |
| [`src/config.rs`](src/config.rs) | limits, `Stats`, and what a run reports |
| [`docs/decisions/0003-execution-engine.md`](docs/decisions/0003-execution-engine.md) | why the engine is shaped this way |

## Safety properties

- `#![forbid(unsafe_code)]`.
- No panicking path is reachable from file contents: every register, array index
  and pool index is bounds-checked, every `Result` from `dexcore` is mapped to a
  named `ExecError`, and a declared length is never used directly as an
  allocation size.
- `clippy::unwrap_used` and `clippy::expect_used` are warned crate-wide, and
  `cargo clippy --all-targets` is clean. The only `unwrap`s left in the crate
  are in the `#[cfg(test)]` modules, where every value unwrapped was built by the
  test itself and the module carries an `allow` saying exactly that.
- `tests/negative.rs` asserts the no-panic property over 2,000 mutations rather
  than leaving it to inspection.

## Reference

<https://source.android.com/docs/core/runtime/dalvik-bytecode>
