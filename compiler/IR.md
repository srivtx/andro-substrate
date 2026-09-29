# andro-substrate compiler IR — the contract every compiler agent codes against

Status: **normative**. If an agent needs this to change, it files a comment in
its own report rather than editing this file. The orchestrator arbitrates.

## What the compiler is

`dexcore` parses and writes DEX. `dexinterp` interprets DEX. Neither compiles
anything to WebAssembly. This component adds:

    (app DEX + framework DEX) --reach--> closure --synth--> host
              |                                  |
              +--------> AOT translate ----------+----> WASM module + host stubs

Two outputs, two consumers:

- **Guest module** — the app's own DEX compiled to WASM, so the browser's JIT
  runs it natively instead of us interpreting it. This is the performance answer.
- **Host module** — *generated*, not hand-written. For a class or method in the
  closure that we choose not to compile (because it is small, or framework
  plumbing, or better expressed in JS), emit a host stub. This is what replaces
  the 334 hand-written shim classes and the ~370,000 lines they imply.

## Target

- `wasm32-unknown-unknown`, no WASI, no host imports except a declared set.
- Consumers: browsers (primary) and Node (tests).
- No `memory64`, no SIMD requirement in v1, no threads in v1.

## Module shape

A compiled unit is one WASM module per input DEX file, plus one host module.

```wat
(module
  ;; ---- imports: the ONLY things a guest may call out ----
  (import "env.log"        (func (param i32 i32)))          ;; msg ptr, len
  (import "env.throw"      (func (param i32 i32) (result i32)))
  (import "env.hostcall"   (func (param i32 i32 i32) (result i32)))  ;; idx, args, ret
  (import "env.now"        (func (result i64)))
  (import "env.alloc"      (func (param i32) (result i32)))
  (import "env.gc"         (func))

  ;; ---- DEX pools, one per class_def, allocated by the host at load ----
  (global $strings (import "env.strings") i32)
  (global $types   (import "env.types")   i32)
  (global $methods (import "env.methods") i32)
  (global $fields  (import "env.fields")  i32)

  ;; ---- one exported function per compiled DEX method ----
  (func (export "m_1234") (param ...) (result ...) ...)
)
```

## Calling convention (normative)

Registers are WASM locals. `v0..vN` map to WASM params/locals **in order**.

| DEX type | WASM type |
|---|---|
| `Z B S C I` | `i32` (32-bit; `Z` is `0`/`1`, not bool) |
| `J` | `i64` |
| `F` | `f32` |
| `D` | `f64` |
| object, array, `null` | `i32` handle into the guest heap |
| `void` | no result |

**Widening is explicit.** A DEX method declaring `(II)I` takes two `i32` and
returns one. There is no hidden boxing. Any agent adding a boxing helper is
solving the wrong problem.

**Null** is handle `0`. A guest heap starts with `0` reserved as `null`.

## Handle model

Guest heap is a bump-allocated region inside the module's linear memory.
`i32` handles are byte offsets. The host never dereferences them.

```
  +0      null
  +8..    objects   : [class_ptr:u32][field_count:u32][fields...]
  +..     arrays    : [elem_width:u32][length:u32][elements...]
```

Class pointers are indices into a runtime class table, resolved from the DEX
`type_ids` at load time. **Not** compile-time addresses — a class may be
supplied by the host module, in which case the pointer refers into a host
table.

## Class resolution order (normative)

At link time, for every class reference, resolve in this order and record the
decision:

1. **closure-generated** — we compiled it; it is in the guest module
2. **host-stub** — it is in the closure but we chose a host implementation
3. **host-native** — a native method the host provides
4. **app** — the app's own class
5. **unresolved** — emit a typed error, never a silent default

Precedence when a name exists in more than one: **host > app**. This is the
supersede rule from ADR 0005, unchanged. Record every shadowing event; the
adversarial test in `shim/` (`144 shadowed classes`) is the model.

## Reachability (the closure)

Entry points: the launch activity's `onCreate`, plus anything the manifest
marks `exported=true`.

A method is in the closure if it is:
- reachable in the call graph from an entry point, **including virtual dispatch
  on all implementors in the loaded DEX**, or
- reached by a `hostcall` whose class is in the closure (transitively), or
- referenced as a superclass of a class in the closure, transitively, or
- an override of a method in the closure

**Reflection is a hole and must be reported, not assumed.** A `const-string`
naming a class is a *candidate* edge. Agents implementing reachability must
emit an explicit `reflective_edge` record and surface it in the report. A
closure is only sound if the report says how many unresolved reflective edges
there were. Silence is a failure.

## Host stub ABI

A host stub is emitted as a JS/TS function plus an entry in a host table:

```ts
export type HostEntry =
  | { kind: "class"; name: string }
  | { kind: "method"; cls: string; name: string; sig: string; impl: HostImpl }
  | { kind: "native"; cls: string; name: string; sig: string; state: "satisfied"|"unsatisfied" };

export type HostImpl = (recv: Handle, args: Handle[]) => Handle | number | bigint;
```

Every stub records, at emit time, which taxonomy ID its absence would
predicate. See `docs/divergence-taxonomy.md` (145 IDs). A stub generated
without a taxonomy attribution is a defect.

## Verification (normative for every agent)

A compiled method is **correct** if, for the fixtures in
`tools/dexcore/tests/FIXTURES.md`, executing it through `dexinterp` and through
the compiled WASM produce **identical** results and identical exception kinds.
`dexinterp` is the oracle. Divergence is a bug in the compiler, never in the
oracle.

Any agent producing code must show that equality on the methods it compiles.
"Looks right" is not verification.

## Non-negotiables, inherited from the rest of the project

- **No panics** on untrusted input, at any layer.
- **Every fabricated value is labelled** as fabricated, at emission.
- **Egress stays structurally impossible** — no compiler output may enable real
  network I/O.
- **Redaction stays in the types** — no emitted field can hold a request body,
  a header value, or a query-string value.
- Every figure is labelled **measured**, **derived**, or **conjecture**.

## Ownership

Each agent owns exactly one directory. Nothing outside it.

| dir | owner |
|---|---|
| `compiler/src/ir.rs`, `compiler/src/lower/` | A1 |
| `compiler/src/codegen/` | A2 |
| `compiler/src/pools.rs`, `compiler/src/heap.rs` | A3 |
| `compiler/src/reach/` | A4 |
| `compiler/src/hostgen/` | A5 |
| `compiler/src/abi.rs`, `compiler/src/marshal.rs` | A6 |
| `runtime/resources/` | B1 |
| `runtime/multidex/` | B2 |
| `runtime/graphics/` | B3 |
| `runtime/text/` | B4 |
| `runtime/natives/` | B5 |
| `runtime/ipc/` | B6 |
| `runtime/storage/` | B7 |
| `measure/closure-overlap/` | C1 |
| `measure/shim-gap/` | C2 |
| `measure/determinism/` | C3 |
| `measure/native-reach/` | C4 |
| `web/` | D1 (shell, owns all of `web/`) |
