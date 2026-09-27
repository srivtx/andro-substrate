# dexcore

DEX container reader, Dalvik bytecode decoder, **DEX writer/assembler**, and
Android binary XML parser, compiled to `wasm32-unknown-unknown` so it can run in
a browser with no server.

## Why the writer is the point

Most DEX tooling stops at reading. andro-substrate cannot. The runtime has to
fabricate synthetic classes for its `android.*` framework shim and have them
resolve in the same classloader as the untrusted app's own code — which means
emitting a `classes.dex` that dexlib2, `baksmali` and ART will all accept. The
writer in [`src/writer.rs`](src/writer.rs) is the component that makes the
architecture possible, and it is the part of this crate that took the most care.

## The DEX format, in brief

A `classes.dex` is a fixed 0x70-byte `header_item` followed by a series of index
sections and one data section.

```text
offset 0x00  header_item          magic, checksum, signature, and (size, offset)
                                 pairs for every section
              string_ids          u32 -> string_data_item
              type_ids            u32 -> a string
              proto_ids           shorty, return type, parameter type_list
              field_ids           class, type, name
              method_ids          class, proto, name
              class_defs          8 u32s: class, flags, superclass, interfaces,
                                 source file, annotations, class_data,
                                 static values
data_off    data                 string_data, type_list, code_item,
                                 class_data, map_list
```

Three things in that layout are easy to get wrong and are pinned by tests here:

**Strings are MUTF-8, not UTF-8.** `U+0000` is stored as the two-byte overlong
sequence `C0 80` rather than a bare `0x00`, because a bare zero terminates the
string. Characters outside the BMP are stored as a *pair* of three-byte surrogate
encodings, not as one four-byte sequence. `utf16_size` counts UTF-16 code units,
which is neither the byte length nor the character count. Applying
`String::from_utf8` to a DEX string pool is a bug; [`src/mutf8.rs`](src/mutf8.rs)
exists so that nobody has to.

**The pools must be sorted, or a real tool rejects the file.** `string_ids` by
UTF-16 code point, `type_ids` by string index, `proto_ids` by
`(return_type, parameters)`, `field_ids` and `method_ids` by
`(class, name, type-or-proto)`, and `class_defs` so that a superclass or
interface always precedes the class referencing it. The writer sorts at emit
time, so callers may add things in any order.

**The header's two integrity fields cover different ranges, in a specific
order.** Adler-32 covers everything after the `checksum` field — so it includes
the signature. SHA-1 covers everything after the `signature` field — so it
includes neither. The signature must therefore be computed *first*. Getting the
order wrong produces a file that this crate reads happily and every other tool
rejects, so `header.rs` and `writer.rs` both do it in the same sequence and both
are tested against RFC 1950 and FIPS 180-4 vectors.

`map_list` lists every item type with its offset and count, ordered by ascending
offset and never overlapping, and `map_list` itself is always last. The
`TYPE_*` constants and their item sizes are in
[`src/model.rs`](src/model.rs).

Reference: <https://source.android.com/docs/core/runtime/dex-format> and
<https://source.android.com/docs/core/runtime/dalvik-bytecode>.

## What it does

| module | role |
|---|---|
| `header` | `header_item` parse/serialise, Adler-32, SHA-1 |
| `opcodes` | the 256-entry Dalvik opcode table, formats and widths |
| `mutf8` | MUTF-8 codec, ULEB128/SLEB128 |
| `model` | resolved pool and class structures |
| `insn` | the decoded `Instruction` enum |
| `reader` | bounds-checked reader over a `classes.dex` |
| `asm` | instruction encoder, producing `code_item` byte streams |
| `writer` | DEX builder: pools, class defs, `map_list` |
| `axml` | Android binary XML, for reading `AndroidManifest.xml` |
| `wasm` | JSON shaping and the `#[wasm_bindgen]` surface |

### Reading

```rust
let dex = dexcore::DexReader::open(&bytes)?;
for class in dex.classes()? {
    println!("{} extends {}", class.descriptor, class.superclass);
    if let Some(data) = &class.class_data {
        for m in data.virtual_methods.iter().chain(&data.direct_methods) {
            let info = dex.method_at(m.method_idx)?;
            if m.code_off == 0 { continue }
            let code = dex.code_item(m.code_off)?;
            let insns = dex.decode_all(m.code_off)?;
            // ... symbolic execution or disassembly
        }
    }
}
```

`decode_all` walks an instruction stream linearly and returns `Located` values
with byte and unit offsets. Every step consumes at least one code unit, so a
stream of `(unused)` opcodes terminates rather than spinning.

### Writing

Sorting the id pools *renumbers* them, so a `const-string` index that was right
before sorting is wrong after it. The writer is therefore two-phase, and refuses
to emit a file that was assembled the wrong way round:

```rust
let mut w = DexWriter::new();

// Phase 1: declare the classes, and intern every reference the bodies will use.
w.add_string("hello from the shim");
w.add_method("Ljava/lang/Object;", "valueOf", &["Ljava/lang/Object;"], "Ljava/lang/String;");
w.add_class(
    ClassDef::extending_object("Landroid/substrate/Shim;")
        .with_field(FieldDef::statics("COUNT", "I"))
        .with_method(MethodDef::abstract_("greet", &["Ljava/lang/String;"], "I")),
);

// Phase 2: sort the pools and take the final indices.
let idx = w.freeze()?;
let hello = idx.string("hello from the shim");
let value_of = idx.method("Ljava/lang/Object;", "valueOf", &["Ljava/lang/Object;"], "Ljava/lang/String;")?;

// Phase 3: assemble against those indices, install the body, then emit.
let mut a = Assembler::new();
a.const_string(0, hello);
a.invoke(0x71, &[0], value_of)?;
a.move_result_object(0);
a.return_object(0);
w.set_code("Landroid/substrate/Shim;", "greet", a.into_code(1, 2, 1))?;
let bytes = w.emit()?;
```

`emit` returns a typed error rather than a subtly wrong file if a body was
assembled against unsorted indices, if a body names an exception type that was
never interned, or if a try range runs past the end of its instruction stream.

### In the browser

```sh
wasm-pack build --target web
```

produces a ~100 KB `.wasm` with four exports. Each takes a `&[u8]` and returns
JSON, because every result is a tree:

```js
import init, { parse_dex, list_classes, decode_method, parse_axml } from "./pkg/dexcore.js";
await init();

const summary = JSON.parse(parse_dex(dexBytes));
if (summary.error) { console.warn(summary.error.kind, summary.error.message); }
else { console.log(summary.class_count, "classes", summary.integrity_ok); }

const method = JSON.parse(decode_method(dexBytes, 0, 3));
for (const i of method.instructions) {
  console.log(i.byte_offset, i.mnemonic, i.text);
}
```

`decode_method`'s `method_idx` indexes the class's direct-then-virtual method
list, matching the order `list_classes` reports; `-1` means "the first method
that has code". Every export returns `{"error": {"kind", "message", "offset"}}`
rather than throwing, so a hostile APK degrades to a value the caller can branch
on. `kind` is a stable discriminant — `truncated`, `bad_magic`,
`index_out_of_range`, `checksum_mismatch` and so on.

## Building and testing

```sh
cd tools/dexcore

cargo test                                  # unit + integration + fixture tests
cargo build --target wasm32-unknown-unknown # the browser target
wasm-pack build --target web                # the publishable package
```

`cargo test` runs five suites:

| suite | what it covers |
|---|---|
| unit tests (`src/**`) | MUTF-8 round trips, ULEB128 bounds, Adler-32 and SHA-1 against RFC/FIPS vectors, header validation, instruction decoding, the assembler, AXML chunk walking, the wasm JSON shaping |
| `tests/opcode_table.rs` | all 256 opcodes against an independent transcription of the specification table; every width derived from the format identifier's leading digit |
| `tests/fixtures.rs` | real DEX and AXML: header invariants, pool sort order, map ordering, exact-tiling disassembly of every method in every fixture, operand frame checks, and a battery of negative tests |
| `tests/writer.rs` | writer round trips: header and integrity, `map_list` completeness, pool sort order, try/catch and payload round trips, and an independent parse by androguard |
| doctests | the two examples in this file and in `src/lib.rs` |

The fixture-based suites are not optional extras. Several of the bugs this crate
had during development — a `try_item` read as three 32-bit fields, `23x` operand
lanes swapped, a try table aligned by rounding *down* — were invisible to unit
tests and caught immediately by walking real files.

### The optional androguard cross-check

`tests/writer.rs` shells out to
[androguard](https://github.com/androguard/androguard) to confirm that a
completely independent DEX implementation parses what `DexWriter` produces, and
agrees on every instruction count. It skips itself if androguard is absent, so
it never blocks a build:

```sh
python3 -m pip install --user androguard
```

The opcode table was also cross-checked opcode-by-opcode against
[androguard/dex-bytecode](https://github.com/androguard/dex-bytecode)
(Apache-2.0) during development; the two agree on all 224 defined opcodes and on
the exact set of 32 unused ones. See
[`docs/decisions/0002-dex-toolchain.md`](../../docs/decisions/0002-dex-toolchain.md).

## What it does **not** do

Being specific about this, because the gaps matter more than the features.

**Container formats.** Only `dex` versions 035 through 040 are read and written —
no CompactDex (`cdex`), no v41+ container headers (the header fields are
modelled, but nothing reads a multi-dex container), and no
`dex\n041`-and-later file is emitted. A multidex APK is the *caller's* problem:
`DexReader` handles one `classes.dex` at a time, and the runtime has to
concatenate `classes.dex`, `classes2.dex`, ... itself.

**Sections not implemented.**

- *Writer*: no debug info, no annotations, no `encoded_array` (so no static field
  initialisers — `static_values_off` is always 0), no `annotations_directory`,
  no call sites, no method handles. The writer therefore cannot emit
  `invoke-custom`, `invoke-polymorphic` or `const-method-*` calls usefully, even
  though the reader decodes them.
- *Reader*: the pools above are read structurally where trivial (`map_list`,
  `try_item`, `code_item`, `class_data_item`, `string_data_item`, `type_list`)
  but their *contents* are not modelled: `debug_info_item` is skipped entirely
  (no local variable names, no line numbers), `annotation_item` and
  `encoded_value` are skipped, and `call_site_item` and `method_handle_item` are
  not exposed. The `wasm` layer says `<MethodHandle@N>` rather than guessing.

**Semantics.** This is a *format* library. It decodes and assembles bytecode; it
does not interpret it. There is no verifier — Dalvik register typing, type
assignment and the `move-result` conventions are not checked — and no
interpreter. Branch offsets are returned raw and relative; resolving them needs a
code-item base address that the caller has.

**Two known format ambiguities**, documented at their definitions:

- For `35c`, d8 writes the *argument count* in the `A` nibble and delivers the
  result to a following `move-result`, rather than writing a destination
  register as the specification describes. `Instruction::argument_count_hint`
  reports `A`; use it as a hint, not as ground truth.
- The `35c` argument nibbles do not encode a count, so a trailing `v0` argument
  is indistinguishable from padding.
  `Instruction::argument_registers` trims trailing zeros and is therefore wrong
  for that one case; `Instruction::packed_registers` plus the target method's
  prototype arity is exact.

**Unusual DEX variants.** The `Format` enum includes `22cs`, `35ms`, `35mi`,
`3rms`, `3rmi`, `40sc`, `41c`, `52c` and `5rc`, which no Dalvik opcode uses. They
are decoded so a foreign file degrades into something readable rather than a hard
failure, but they are not part of Dalvik and are not tested against a real
producer.

**Android binary XML.** The string pool, resource map, namespace declarations and
start/end elements are parsed, with typed values decoded for strings, integers,
booleans, floats, colours and references. Chunks of unknown type are skipped, as
aapt2 expects. `cdata` nodes are ignored, `android:...` attributes on a
`<manifest>` are not interpreted semantically (a version *code* is a number, not
a comparable version), and `resources.arsc` is **not** parsed — resolving
`@7f030000` to a string needs the resource table, which is a separate format
this crate does not touch.

**Not a security boundary.** The reader is bounds-checked and will not panic on
malformed input — that is tested — but it is a parser for a format designed for
mutually-distrusting parties to read each other's files. It is not hardened
against an adversary who can observe timing, and it allocates proportionally to
declared pool sizes. The runtime's threat model should not treat
"dexcore returned a `Result`" as "this APK was safe".
