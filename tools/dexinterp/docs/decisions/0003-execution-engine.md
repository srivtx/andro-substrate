# 0003 — The execution engine: four outcomes, no host stack, and where a
# refusal stops

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: what `tools/dexinterp` is responsible for; the four terminal
  conditions and why they are not merged; the register and value model; the
  resource limits; what happens at a `Host` boundary; and the `dexcore` decoder
  defects this engine compensates for.
- **Scope**: `tools/dexinterp/`. Does not touch `tools/dexcore/`, `shim/`,
  `corpus/`, `oracle/`, `analysis/`, or `docs/research-protocol.md`.

## Context

ADR [0002](../../../../docs/decisions/0002-dex-toolchain.md) settled that the DEX toolchain is Rust
compiled to WASM, and that it has to *write* DEX as well as read it. That
settled the file layer. It did not settle the layer above it: given a valid,
decodable `classes.dex`, what does and does not execute?

The project's pre-registered protocol forbids a single "runs / does not run"
verdict. 44.76% of the F-Droid corpus in
[`corpus/report.md`](../../../../corpus/report.md) contains no native code, and
that figure says nothing about whether the remaining bytecode runs, or where it
stops. Every claim this project makes downstream — `SUB.FW.INVOKEDYNAMIC`,
`SUB.FW.CLASS_LOADER`, `SUB.CPU.TIERING`, `SUB.NATIVE.JNI_ENTRY` — needs an
instrument that distinguishes *the app failed* from *we stopped watching*.

That distinction is the whole design problem, and it is easy to get wrong in the
direction that flatters the substrate. An interpreter that reports every stall as
a crash makes the browser arm look universal; one that reports every stall as
"unsupported" makes it look empty. Both are wrong, and both are the same error:
collapsing distinct claims into one bucket.

## Decision

### 1. Four terminal conditions, each with a stable name

Every run ends in exactly one of four conditions, carried by
`Termination` and given a stable string by `ExecError::kind()`:

| `Termination` | `kind()` | What it claims | Who is at fault |
| --- | --- | --- | --- |
| `ExceptionRaised` | `exception_raised` | The app threw, and nothing caught it | The app |
| `BudgetExhausted` | `budget_exhausted`, `stack_overflow` | The app was still making progress when a limit fired | Us, and it is a `tier` finding |
| `Unsupported` | `unsupported` (+ a named discriminant) | The app reached bytecode we deliberately do not implement | Us, and it is a `gap` finding |
| `EngineFault` | `malformed`, `out_of_memory` | The file violates a rule the verifier would have caught | The file, so a `divergence` finding |

The two inside `EngineFault` and `BudgetExhausted` are separate `kind()` strings
precisely so that "we ran out of object slots" and "this bytecode is not valid
Dalvik" cannot be counted as one bucket either.

`Unsupported` and `Malformed` each carry their own `Copy` enum of
discriminants — eight and eleven respectively — so the count is over named causes,
not over an error string. `Unsupported::BootstrapMethodMissing` and
`Unsupported::CallSiteUnresolved` in particular are the *same* taxonomy entry
(`SUB.FW.INVOKEDYNAMIC`) but distinct discriminants, because "this file declares
no `call_site_ids` at all" and "the file has them and the substrate cannot run
the lambda" are different results that imply different fixes.

`tests/negative.rs` asserts that the four conditions stay apart, that every
discriminant is distinct, and that no code path in the crate can reach a fifth
outcome.

### 2. No verifier; typing at the point of use

**The engine does not verify.** ART refuses to install a DEX that fails
verification, so on a real device a type error is not an outcome the app can
reach. Which means every `Malformed` variant is a finding about *a file*, not
about an app's behaviour, and a `Malformed` in a census over the corpus is
evidence about the corpus rather than about the substrate.

That is a deliberate boundary. A verifier is a whole-program analysis whose
answer is a property of the file; this crate's job is to run decoded bytecode,
and the two have different failure semantics. The cost is that a `TypeMismatch`
can be raised *late* — at the instruction that reads the bad register, not at
install time — so `Malformed` must report the offending unit and opcode, and
`ExecError`'s `Display` does.

The register file is a `Vec<Value>` sized by the method's `registers_size`.
`Value` is a 9-variant enum, not a tagged union of raw words, so that the
`long`/`double` high word (`Value::WidePad`) is representable: reading it is a
type error, and writing it is a bug the engine reports rather than something it
silently accepts.

### 3. Arity counts values, widths count words — and the distinction is not academic

`MethodDecl` exposes two different counts, and conflating them makes an ordinary
method unreachable:

- `incoming_slots()` — register words, so it decides where each argument lands
  in the callee's window. A `long` counts two.
- `incoming_values()` — `Value`s the caller must supply. A `long` counts one.

`fr.smarquis.sleeptimer_16200` has a real
`(LContext;J LNotification;)V` method whose three-argument call the engine
rejected as "4 argument words" until the two were separated. The arity check
uses `incoming_values()`; the window layout uses `incoming_slots()`.

The same shape of bug bit three times in a row, which is why each is called out
where it is fixed: return types are checked against `Frame.return_type` rather
than against the width of the instruction that returns (`return` is 32 bits and
`return-wide` is 48, and both can carry a `long`); wide values are normalised on
the way out of a frame so that a `double`'s bit pattern cannot survive as a
`Long`; and `as_double` reinterprets `Long` *bits* rather than converting them
numerically, which is what `const-wide` + `return` + `double-to-long` in real
bytecode actually means.

### 4. Instruction widths are computed once, in one place, and stored

`Insn` carries a `units: u16` field alongside the decoded instruction, and the run
loop advances the program counter by that field rather than by re-deriving a
width. The reason is that two widths cannot be taken on trust:

- A `32x` instruction (`move/16`, `move-wide/16`, `move-object/16`) is encoded in
  **two** code units as `AA|op BBBB`, while `dexcore`'s `Format::F32X::width()`
  reports three — the format identifier begins with a `3` that is not its width.
- A data payload's width follows from its own decoded contents: the
  specification's layouts give `4 + 2*targets` for a packed-switch payload and
  `2 + 4*keys` for a sparse one, where each 32-bit field is two code units.

Both are corrected in `Program::decode_code`, and both are bugs in `dexcore`'s
decoder rather than in the engine. Recording the width on the `Insn` means the
linear walk that builds the list and the run loop that consumes it cannot
disagree, and it puts the compensation in one auditable place instead of two
call sites that each have to remember.

### 5. No host stack: frames are a `Vec`, unwinding is a `pop` loop

**Recursion is bounded by a typed error, not by the host's stack.** A call pushes
a `Frame` onto a `Vec`; exception unwinding pops frames in a loop and runs each
handler inline; there is no Rust recursion anywhere on the execute path. The
default `max_call_depth` is 512, and exceeding it is
`ExecError::StackOverflow` — a `BudgetExhausted` outcome, not a `SIGSEGV` in a
browser tab.

The same argument drives the two allocation limits. A `new-array` whose
`registers_size` says four million elements, or a `fill-array-data` payload whose
declared size is the rest of the file, are both attacker-chosen counts. They are
bounded by bytes that remain (`max_bytes`) and objects that remain
(`max_objects`), not by the count in the file.

There is no garbage collector. Memory grows to the end of the run or to a limit,
which is what makes `Stats::bytes_allocated` independent of when a collection
would have happened and therefore comparable between two runs. The cost is
stated plainly in the README rather than papered over.

### 6. `monitor-enter` is a reentrant per-object lock, and nothing more

`monitor-enter`/`monitor-exit` maintain a real per-object reentrant hold count, so
mutual exclusion is trivially satisfied and `SUB.CPU.ATOMIC`'s "did it take the
lock" question gets a real answer.

Happens-before gets nothing. There are no threads, so a monitor cannot order
anything, and a method that is `synchronized` is not made atomic by taking one.
`heap::Monitor` says so in its own documentation, because the tempting reading —
"we implemented monitors, so `SUB.CPU.ATOMIC` is covered" — is wrong in the way
that matters.

A frame that returns while still holding a monitor is
`Malformed::UnbalancedMonitor`, which is its own discriminant rather than a
`TypeMismatch` because it is the one `Malformed` that is not about types at all:
it is monitor state, which the verifier does track, so a file reaching it is a
file ART would have rejected.

### 7. The `Host` boundary substitutes a declared zero and records the miss

A method with no `code_item` — `abstract` or `native` — and a class not in the
file are both handed to the `Host` trait. The default `Host` does not implement
them.

**The default returns the declared type's zero value and records the
substitution.** This is the decision the whole study rests on: a missing
`android.content.Context` method returns `null` and the run *continues*, so the
census reaches the next statement instead of stopping at the first framework
call. The cost is that a run which would have crashed on a real device can get
further here, so `Stats::framework_calls_unimplemented` is recorded per run and
`real_dex.rs` asserts on it, because an app that reached `onCreate` and reported
success is a claim that means nothing without the count of things that were
faked on the way.

The exception is a *missing class* when phantom classes are disabled, which is
`Unsupported::ClassNotFound` — `SUB.FW.CLASS_LOADER`, and a real finding rather
than a substitution.

### 8. `invoke-custom` decodes the whole resolution chain before refusing

`invoke-custom` is the pre-registered `SUB.FW.INVOKEDYNAMIC` hypothesis, so the
engine walks the entire chain — call site, method handle, bootstrap method, the
class that defines it, whether that class is in the file — and reports which link
is missing. Five opcodes are refused this way and named in
`tests/coverage.rs::EXCLUSIONS` with the reason and the cost of adding each.

The exclusions exist because they have to exist, not because they are
convenient: `dexcore`'s `DexWriter` emits no `call_site_ids` and no
`method_handles` section, so no synthetic file can contain `invoke-custom` or
`const-method-handle` at all. `real_dex.rs` covers the same chain against a file
that has both sections.

## Consequences

**The corpus can be censused, and the census is honest about its own blind
spots.** `real_dex.rs` runs every method of two real APKs and reports which
returned, which raised, and which faulted. On
`fr.smarquis.sleeptimer_16200` that is 85 methods: 28 returned, and the remaining
57 are all *app* exceptions — 25 `NullPointerException`, 16 `NoSuchMethodError`,
13 `UnsupportedOperationException`, 2 `IndexOutOfBoundsException`, 1
`NoSuchElementException` — with zero `EngineFault`. Every one of those 57 is a
statement about the shim's surface, not about the decoder, and the suite asserts
that distinction rather than reporting a single pass rate. `com.termux.boot_1000`
is 14 methods, 5 returned, 9 thrown, zero faults. All of these figures are
pinned in `tests/real_dex.rs` so that neither this ADR nor the crate README can
quote a number the suite no longer produces.

**The single most likely reason a modern F-Droid APK still fails is the shim,
not this engine.** `com.termux.boot_1000`'s `onCreate` decodes and runs, and
stops at `Landroid/app/Activity;.setContentView(Landroid/view/View;)V` — opcode
`0x6e`, a real invoke that needs a real framework. Measured, not assumed.

**Two `dexcore` defects are compensated for here rather than fixed at source,
because `dexcore` is out of scope for this ADR.** A call for each is in
`tools/dexcore`'s own follow-ups; until then:

- `DexWriter::intern_type_list` writes each `ushort` element of a `type_list` as
  four bytes, so a multi-parameter prototype does not survive a write/read round
  trip. The test harness repairs multi-element lists in place after `emit`.
  `real_dex.rs` is unaffected — it only reads.
- The `F32X` width and payload-width defects described in §4.

Both are recorded in `Insn::units`'s documentation and in `decode_code` rather
than as a silent shim, so that a reader who finds them in a debugger can tell
they are known.

**A panic in this crate is a bug in this crate.** The harness enforces it
structurally: `negative.rs` mutates a valid file 2,000 times deterministically
and asserts that no mutation panics, that distinct malformed inputs produce
*distinct* error kinds rather than one catch-all, and that a byte flip can only
ever end in one of the four conditions. A fuzzer with a random seed would be
easier to write and worthless to re-run; the mutation is derived from a fixed
seed so a failure reproduces.

**The uncovered case is a test failure, not a silence.** `coverage.rs` asserts
that all 224 specification-defined opcodes are dispatched by the engine, from
`Stats::opcode_counts` — the engine's own record — rather than from what a test
believed it exercised. 219 execute to return and 5 are refused by name. Verified
by mutation: removing one case fails with
`1 of the 224 defined opcodes were never dispatched: ["if-lez"]`.

## Follow-ups

- A verifier would move every `Malformed` from run time to load time. It is a
  separate analysis with separate failure semantics and is not an extension of
  this engine.
- `CompactDex` and the v41 container format are out of scope, as in
  [0002](../../../../docs/decisions/0002-dex-toolchain.md).
- The `type_list` writer defect in `dexcore` should be fixed at source; the
  in-place repair in the test harness is a workaround with a known failure mode
  (a prototype with more elements than the harness recognises) and should not
  outlive it.
- `Unsupported::ClassNotFound` currently fires only when phantom classes are
  disabled. The default is to accept an undeclared class and record it, which is
  the right default for a census and the wrong one for a conformance claim; the
  distinction is in `Config` and should stay in both.
