# 0002 — The DEX toolchain: Rust → WASM, written from scratch

- **Status**: accepted
- **Date**: 2026-09-28
- **Decides**: the implementation language for reading and writing DEX, whether
  to vendor an existing disassembler, and how to handle MUTF-8.

## Context

andro-substrate executes untrusted Android APK bytecode in a browser, with no
Linux kernel, no native code and no network egress, so that an app's code-level
side effects can be observed without the APK leaving the machine.

Three properties are non-negotiable, and together they determine almost
everything else:

1. **The APK never leaves the machine.** Analysis happens client-side, so the
   whole toolchain has to run in a browser.
2. **The runtime must *write* DEX, not just read it.** To intercept
   `android.content.Intent` calls, the runtime has to fabricate a
   `Landroid/content/Intent;` class that resolves in the same classloader as the
   untrusted app's own code. A reader cannot do that; an assembler can. Most
   projects stop at reading, which is precisely the gap that makes this one hard.
3. **The whole runtime is untrusted input's execution target.** A DEX reader is
   the first thing a hostile APK touches, so it must be total: no panics, no
   unbounded allocation driven by a declared count, no hangs.

## The language: Rust compiled to WASM, not TypeScript

**Decision: Rust, compiled to `wasm32-unknown-unknown`, with `wasm-bindgen` for
the JS boundary.**

The alternative was TypeScript running in a Web Worker. It was rejected on four
grounds, in descending order of importance.

**Bit-exact format work needs a language where that is the default.** DEX
strings are MUTF-8, where `U+0000` is `C0 80` and astral characters are stored
as surrogate *pairs*; `insns` are little-endian `u16` arrays whose *byte* layout
is the format (`const/4 vA, #+B` is `B|A|op` in nibbles, so byte 1 is
`(B << 4) | A`); `fill-array-data-payload` bodies are a whole number of code
units long with a variable element width. Every one of those is a place where
JavaScript's number model and string model make a mistake *silently*. JavaScript
has no `u16`; `u32 & 0xffff` and `>>> 16` are idioms you have to remember, and
the SHA-1 and Adler-32 implementations want `u32` wrapping arithmetic that
`Number` does not provide. In Rust these are the types; the bugs that do get
written are the interesting ones, and the compiler finds the rest.

**The writer has to be right about unsigned arithmetic.** The DEX header's
Adler-32 and SHA-1 cover *overlapping, differently-scoped* ranges: Adler-32
covers `bytes[12..]` and therefore includes the signature, while SHA-1 covers
`bytes[32..]` and includes neither. The signature must be computed first. In
JavaScript this is doable but it is a place where a signed `>>> 0` slip produces
a file that only your own code can read. In Rust, `wrapping_add` on `u32` makes
it routine.

**WASM is smaller and faster than JS for this shape of work.** A 104 KB
optimised `.wasm` against a JS bundle plus a hand-written SHA-1 is not a
tiebreaker, but it is not nothing either — the `.wasm` was 104 KB *with*
`wasm-opt` applied, before any attempt to shrink it.

**Zero-cost FFI on the other side.** The runtime agent is writing a Dalvik
interpreter. Compiling it to the same `wasm32-unknown-unknown` target means the
DEX reader, the writer and the interpreter are one Rust crate graph with no
serialisation boundary between them — no JSON, no `Float64Array`, no copying a
`Uint8Array` across a module boundary on the hot path. With TypeScript, the same
boundary would sit between the reader and the interpreter, which is the single
worst place to put one.

The cost is real and worth naming: the build needs a Rust toolchain and
`wasm-pack`, where a TS toolchain would need nothing beyond `npm`. The
mitigations are that both are ordinary CI dependencies, and that
`crate-type = ["cdylib", "rlib"]` means the same crate also builds natively,
which is what makes the fixture-based test suite possible at all — the tests run
on the host in milliseconds, with no headless browser.

**Rejected: a Rust→WASM runtime plus a JS DEX library.** Two implementations of
one format, disagreeing at the boundary, is strictly worse than either alone.

## Vendored or written: written, and the licence is the reason

**Decision: write it. Vendor nothing.**

The obvious thing to do was start from
[androguard/dex-bytecode](https://github.com/androguard/dex-bytecode) (Apache-2.0),
which is a disassembler *and* an assembler and covers the payload
pseudo-instructions. It is genuinely good prior art, and it was read closely —
the whole opcode table was extracted, compared entry by entry against the AOSP
Dalvik bytecode specification, and the two were found to agree on all 224
defined opcodes and on the exact set of 32 unused ones. That comparison is
recorded in `tools/dexcore/src/opcodes.rs` and asserted independently in
`tools/dexcore/tests/opcode_table.rs`.

It was not vendored, for three reasons.

**The thing that matters most is the part that does not exist.** The project's
hard requirement is *writing* DEX that a real Android tool accepts. The
differences between "produces a file" and "produces a file dexlib2, `baksmali`
and ART all accept" are where the actual risk lives: the six pool sort orders,
the `map_list` contents, the two integrity fields and their order of computation,
4-byte alignment of `code_item` and `map_list`, the 2-byte padding before a try
table when `insns_size` is odd, the catch-all clause having to come last in an
`encoded_catch_handler`, and `handler_off` being measured from the start of the
handler list *including* its `uleb128` size prefix. Adopting a reader would have
meant inheriting none of that knowledge. The writer had to be written from the
specification, and the spec is a better teacher than an existing codebase,
because it is unambiguous where the codebases are merely consistent.

**The licence question resolves cleanly anyway.** Apache-2.0 would have been
fine with attribution. But the most defensible position is that the opcode table
is not really licensable expression: it is a transcription of a specification
table that AOSP publishes under Apache-2.0, and *any* correct implementation
must contain exactly those 224 rows, in that order, with those mnemonics. Two
independent transcriptions agreeing is evidence of correctness, not of copying.
Stating that plainly — and pointing at the cross-check — is more honest than
copying a file and adding a header, which would invite the question "did you
take the rest?"

**Ownership of the failure modes.** A parser that has only ever seen its own
output is not tested. Writing this meant the test suite could be aimed at
*specific* classes of bug, and it was: the fixture suite walks every instruction
of every method in six real APK-derived DEX files and asserts the decoded stream
tiles each `code_item` exactly. That single test found four real bugs that unit
tests had missed — a `try_item` read as three 32-bit fields instead of
`{u32, u16, u16}`, the `23x` operand lanes swapped, the try table aligned by
rounding *down* instead of up, and `B` and `C` read from the wrong half of the
second code unit in `22b` and `23x`. None of those would have been caught by a
vendored reader either, but they would have been caught *somewhere other than
here*, which is worse.

**Where prior art was used, it was used as a test oracle, not as source.** The
four disputed operand layouts (`35c` nibble order, `3rc` register count, `22b`
and `23x` byte lanes) were settled by installing
[androguard](https://github.com/androguard/androguard) and comparing its raw
output against mine on real bytes. The results are now in comments at the
relevant tests, and `tests/writer.rs` runs androguard against `DexWriter`'s
*output* on every test run, so the writer is checked by something that is not
this crate. See `tools/dexcore/tests/FIXTURES.md`.

**Reference material consulted, none of it copied:** the AOSP
[DEX format](https://source.android.com/docs/core/runtime/dex-format) and
[Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode)
documents; dexlib2's `DexWriter.java` (BSD-3-Clause) for the writer's section
order, `handler_off` semantics and the signature-then-checksum order;
androguard's `Instruction*.py` classes (Apache-2.0) for the operand lane
layouts; and
[apkman](https://github.com/jiusanzhou/apkman) (MIT) for the shape a
browser-side Rust→WASM Android tool takes.

## MUTF-8: a first-class module, not a helper

**Decision: a dedicated `mutf8` module with a lossy-but-total decoder, and no
`String::from_utf8` anywhere near a string pool.**

The details that matter, all of which are easy to get wrong:

- `U+0000` is `C0 80`, not `0x00`. A bare zero terminates the string, so an
  encoder that emits it truncates.
- Non-BMP characters are stored as two three-byte surrogate encodings. A four-byte
  sequence is *legal UTF-8 and illegal MUTF-8*, so `String::from_utf8` on a DEX
  string pool is not merely unidiomatic, it is wrong on real input.
- `C0` and `C1` leads are overlong forms of ASCII and are rejected; `C0 80` is
  the one sanctioned exception.
- `utf16_size` counts UTF-16 code units, which is neither the byte length nor the
  character count. An astral character is 6 bytes and 2 units.
- The specification explicitly permits *lone* surrogates in a string pool, and
  says it is up to higher layers to reject them. A decoder that errors on them
  would fail on real APKs; one that panics on them would be a crash bug in a
  browser tab. The decoder therefore reassembles pairs and maps unpaired
  surrogates to U+FFFD, so it is total by construction.

This is one of the two places where "no panics on malformed input" is not
achievable with plain `from_utf8`, which is why it gets its own module and its
own tests rather than a comment.

The writer's `IndexMap` sorts strings by their **decoded UTF-16 code unit
sequence** rather than by their MUTF-8 bytes. For the entire BMP those two
orders coincide, but not for `U+0000`, whose two-byte overlong encoding sorts
*after* every single-byte character while its code unit sorts *before* all of
them. A pool containing a NUL would fail dexlib2's ordering check.

## Consequences

**The two-phase writer API exists because sorting renumbers.** The id pools must
be sorted, so a `const-string` index assembled before sorting is wrong after it.
Rather than paper over that with a fixup pass, `DexWriter` is explicitly
`freeze` → assemble → `set_code` → `emit`, and `emit` *refuses* to produce a file
whose bodies were assembled against unsorted indices. A tool that silently emits
a plausible-but-wrong DEX is worse than one that stops.

**`Instruction` is an enum over formats, not over mnemonics, and carries `op`.**
A 256-variant enum keyed on mnemonics carries no information, because a single
format such as `12x` backs thirty-odd operations. But the format alone does not
identify the operation either: `35c` covers `invoke-virtual` through
`invoke-interface` *and* `filled-new-array`, and a runtime that cannot tell those
apart is useless. So each variant stores the opcode alongside its operands, and
`Instruction::mnemonic()` consults the table.

**A parser for a format designed for mutually-distrusting parties is not a
security boundary.** The reader is bounds-checked and tested not to panic, but
it allocates proportionally to declared pool sizes and is not hardened against
timing. The runtime's threat model should not read "`dexcore` returned a
`Result`" as "this APK was safe". That belongs in
[0001 — the sandbox boundary](#), and it is recorded in the crate README so it
cannot be missed by someone who only reads the code.

## Follow-ups

- A real Android toolchain in CI (`d8` plus `dexdump`) would be a stronger
  writer oracle than androguard, and is worth adding if a suitable image is
  available.
- CompactDex and the v41 container format are out of scope now. If the runtime
  ever needs to meet a `cdex`-using app, that is a new ADR rather than an
  extension of this one.
