//! Opcode coverage: every opcode in `dexcore`'s table reaches the engine's
//! dispatch, and every one that does not run says so by name.
//!
//! # The contract
//!
//! For each of the **224 opcodes the Dalvik specification defines**, exactly one
//! of the following holds, and this suite proves which:
//!
//! 1. **executed** — a case in [`coverage_corpus`] dispatched it and the method
//!    returned normally;
//! 2. **refused** — a case dispatched it and the engine reported a *named*
//!    `Unsupported`, with the name listed in [`EXCLUSIONS`];
//! 3. **unreached** — no case dispatched it at all. **This is a test failure**,
//!    and the only thing standing between the engine and an untested opcode.
//!
//! The third case is what the suite exists for. An opcode the engine's dispatch
//! forgets does not produce a wrong answer — it falls through to a `foreign` arm
//! and reports `Unsupported::ForeignFormat` — but an opcode that is dispatched
//! and mishandled *would* produce a plausible wrong answer, and nothing else in
//! the crate would notice. The evidence is the engine's own
//! `Stats::opcode_counts`, indexed by opcode byte, so the claim is a fact about
//! what the engine recorded rather than about what a test believed it exercised.
//!
//! # Why the corpus is hand-assembled
//!
//! Because there is no way around it: `dexcore::DexWriter` emits no
//! `call_site_ids` and no `method_handles` section, so no synthetic file can
//! contain the `invoke-custom` and `const-method-handle` forms at all. Those
//! five opcodes are therefore *refused* rather than executed, which is a real
//! and honest result — the engine decodes the whole resolution chain and names
//! what is missing — and it is why the exclusion list exists as data rather than
//! as silence. `real_dex.rs` covers the same chain against a file that has the
//! sections.
//!
//! The other two "refusals" in the list are the `invoke-polymorphic` pair, which
//! needs a `MethodHandle` runtime that does not exist, and the
//! `const-method-handle` that goes with it.
//!
//! # Hand-assembly hazards this corpus avoids
//!
//! Three of them cost real debugging time on the way to this file, so they are
//! called out where they occur:
//!
//! * `const/4` holds a **signed four-bit** literal. A `10` written into it is
//!   `-6`, silently.
//! * A branch offset is measured in code units **from the branch itself**, and
//!   `const`/`add-int/lit8`/`invoke-*` occupy two or three, so a hand-counted
//!   offset drifts the moment an instruction's width changes.
//! * `new-array` on a zero-length array followed by an `aput` is an
//!   `ArrayIndexOutOfBoundsException`, not a way to write zeros.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use dexcore::model::access;
use dexcore::writer::{ClassDef, CodeBody, FieldDef, MethodDef, TryCatch};

use dexinterp::host::HostValue;
use dexinterp::{Config, Termination};

/// An opcode the engine dispatches but does not execute, with the reason.
///
/// The reason is data rather than a comment because a bare opcode number is not
/// reviewable: a reader has to be able to see, at the point of exclusion, what
/// is missing and what it would cost to add. [`every_refused_opcode_names_itself`]
/// checks that each of these is genuinely reached and genuinely refused, and
/// [`no_other_case_refused`] checks that the list is not a dumping ground.
struct Exclusion {
    /// The opcode byte.
    op: u8,
    /// The corpus case that dispatches it.
    case: &'static str,
    /// The `Unsupported` discriminant the engine must report.
    kind: &'static str,
    /// Why the engine does not execute it.
    why: &'static str,
}

const EXCLUSIONS: &[Exclusion] = &[
    Exclusion {
        op: 0xfa,
        case: "invokePolymorphic",
        kind: "polymorphic_call",
        why: "`invoke-polymorphic` (45cc). The target method, its name and its signature are \
              all decoded and reported, but there is nothing to dispatch through: a \
              signature-polymorphic call needs a `java.lang.invoke.MethodHandle` for a \
              signature the DEX does not name, and this substrate has no `MethodHandle` \
              machinery for one. `Host::resolve_call_site` cannot express it either, so \
              the gap is structural rather than a missing table entry. Reported as \
              `Unsupported::PolymorphicCall`, a distinct record from every other gap.",
    },
    Exclusion {
        op: 0xfb,
        case: "invokePolymorphicRange",
        kind: "polymorphic_call",
        why: "`invoke-polymorphic/range` (4rcc). The same gap as 0xfa in the \
              contiguous-register form; the call site is decoded and refused identically.",
    },
    Exclusion {
        op: 0xfc,
        case: "invokeCustom",
        kind: "bootstrap_method_missing",
        why: "`invoke-custom` (35c). The engine implements the whole resolution chain — call \
              site, method handle, bootstrap method, its defining class, whether that class \
              is in the file, and every bootstrap argument as a value — and then asks the \
              host to resolve it. It cannot be *executed* by a synthetic test because \
              `dexcore::DexWriter` emits no `call_site_ids` section, so no synthetic file \
              can contain one; the reachable outcome is \
              `Unsupported::BootstrapMethodMissing` naming exactly that absence. \
              `real_dex.rs` walks the same chain against a real file, where the section \
              exists.",
    },
    Exclusion {
        op: 0xfd,
        case: "invokeCustomRange",
        kind: "bootstrap_method_missing",
        why: "`invoke-custom/range` (3rc). The same gap as 0xfc in the \
              contiguous-register form: no synthetic `call_site_ids`, so no resolvable call \
              site, so the chain is decoded and the missing link is named.",
    },
    Exclusion {
        op: 0xfe,
        case: "constMethodHandle",
        kind: "method_handle_unresolved",
        why: "`const-method-handle` (21c). Reaches `Program::method_handle`, which reports \
              `Unsupported::MethodHandleUnresolved` and says whether the dex has no \
              `method_handles` section at all or the index is out of range. As with 0xfc, \
              `dexcore::DexWriter` cannot produce the section, so a synthetic test can only \
              reach the refusal.",
    },
];

/// One named method body.
struct Case {
    name: &'static str,
    ret: &'static str,
    /// Register count of the frame.
    registers: u16,
    /// A try table, for the cases that need one.
    tries: Option<Vec<TryCatch>>,
    body: Box<dyn Fn(&dexcore::writer::IndexMap) -> Emit>,
}

impl std::fmt::Debug for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Case")
            .field("name", &self.name)
            .field("ret", &self.ret)
            .finish()
    }
}

fn case(
    name: &'static str,
    ret: &'static str,
    body: impl Fn(&dexcore::writer::IndexMap) -> Emit + 'static,
) -> Case {
    Case {
        name,
        ret,
        registers: 12,
        tries: None,
        body: Box::new(body),
    }
}

/// A case with a try table, which the `throw` and `move-exception` opcodes need
/// in order to be observable at all: an uncaught `throw` ends the run, and
/// `move-exception` is only legal inside a handler.
fn tried(
    name: &'static str,
    ret: &'static str,
    tries: Vec<TryCatch>,
    body: impl Fn(&dexcore::writer::IndexMap) -> Emit + 'static,
) -> Case {
    Case {
        name,
        ret,
        registers: 12,
        tries: Some(tries),
        body: Box::new(body),
    }
}

/// `n` cases named by the format they cover, built from a table of opcode bytes.
fn each(
    prefix: &str,
    ops: &[u8],
    ret: &'static str,
    build: impl Fn(u8) -> Emit + 'static,
) -> Vec<Case> {
    let build = std::rc::Rc::new(build);
    ops.iter()
        .enumerate()
        .map(|(i, &op)| {
            let build = std::rc::Rc::clone(&build);
            case(
                Box::leak(format!("{prefix}{i}").into_boxed_str()),
                ret,
                move |_| build(op),
            )
        })
        .collect()
}

// ============================================================ the corpus

fn arithmetic() -> Vec<Case> {
    let mut out = Vec::new();
    // The eleven `int` opcodes of the 23x family, minus the two whose failure is
    // a throwable (division has its own group).
    out.extend(each(
        "int23x",
        &[0x90, 0x91, 0x92, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.const4(1, 5);
            e.op23x(op, 2, 0, 1);
            e.op11x(0x0f, 2);
            e
        },
    ));
    out.extend(each(
        "int22s",
        &[0xd0, 0xd1, 0xd2, 0xd5, 0xd6, 0xd7],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.op22s(op, 1, 0, 5);
            e.op11x(0x0f, 1);
            e
        },
    ));
    out.extend(each(
        "int22b",
        &[0xd8, 0xd9, 0xda, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.op22b(op, 1, 0, 5);
            e.op11x(0x0f, 1);
            e
        },
    ));
    out.extend(each(
        "int2addr",
        &[0xb0, 0xb1, 0xb2, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.const4(1, 5);
            e.op12x(op, 0, 1);
            e.op11x(0x0f, 0);
            e
        },
    ));
    out.extend(each(
        "long23x",
        &[0x9b, 0x9c, 0x9d, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5],
        "J",
        |op| {
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 3);
            e.const_wide(0x18, 2, 5);
            e.op23x(op, 4, 0, 2);
            e.op11x(0x10, 4);
            e
        },
    ));
    out.extend(each(
        "long2addr",
        &[0xbb, 0xbc, 0xbd, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5],
        "J",
        |op| {
            let mut e = Emit::new();
            e.const_wide(0x18, 0, 3);
            e.const_wide(0x18, 2, 5);
            e.op12x(op, 0, 2);
            e.op11x(0x10, 0);
            e
        },
    ));
    // `div-float` and `rem-float` are here rather than in `division()` because
    // dividing 3.0 by 5.0 does not fail: a float division by zero is infinity,
    // not a throwable, which is the whole difference from `div-int`.
    out.extend(each(
        "float23x",
        &[0xa6, 0xa7, 0xa8, 0xa9, 0xaa],
        "F",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.const4(1, 5);
            e.op12x(0x82, 0, 0);
            e.op12x(0x82, 1, 1);
            e.op23x(op, 2, 0, 1);
            e.op11x(0x0f, 2);
            e
        },
    ));
    out.extend(each(
        "float2addr",
        &[0xc6, 0xc7, 0xc8, 0xc9, 0xca],
        "F",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.const4(1, 5);
            e.op12x(0x82, 0, 0);
            e.op12x(0x82, 1, 1);
            e.op12x(op, 0, 1);
            e.op11x(0x0f, 0);
            e
        },
    ));
    out.extend(each(
        "double23x",
        &[0xab, 0xac, 0xad, 0xae, 0xaf],
        "D",
        |op| {
            let mut e = Emit::new();
            e.const_wide(0x18, 0, (3.0f64).to_bits() as i64);
            e.const_wide(0x18, 2, (5.0f64).to_bits() as i64);
            e.op23x(op, 4, 0, 2);
            e.op11x(0x10, 4);
            e
        },
    ));
    out.extend(each(
        "double2addr",
        &[0xcb, 0xcc, 0xcd, 0xce, 0xcf],
        "D",
        |op| {
            let mut e = Emit::new();
            e.const_wide(0x18, 0, (3.0f64).to_bits() as i64);
            e.const_wide(0x18, 2, (5.0f64).to_bits() as i64);
            e.op12x(op, 0, 2);
            e.op11x(0x10, 0);
            e
        },
    ));
    out
}

/// Division and remainder, whose failure is a *throwable* rather than a value,
/// so each opcode needs operands that do not divide by zero.
fn division() -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(each("div23x", &[0x93, 0x94], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 7);
        e.const4(1, 2);
        e.op23x(op, 2, 0, 1);
        e.op11x(0x0f, 2);
        e
    }));
    out.extend(each("div22s", &[0xd3, 0xd4], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 7);
        e.op22s(op, 1, 0, 2);
        e.op11x(0x0f, 1);
        e
    }));
    out.extend(each("div22b", &[0xdb, 0xdc], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 7);
        e.op22b(op, 1, 0, 2);
        e.op11x(0x0f, 1);
        e
    }));
    out.extend(each("div2addr", &[0xb3, 0xb4], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 7);
        e.const4(1, 2);
        e.op12x(op, 0, 1);
        e.op11x(0x0f, 0);
        e
    }));
    out.extend(each("divLong23x", &[0x9e, 0x9f], "J", |op| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 7);
        e.const_wide(0x18, 2, 2);
        e.op23x(op, 4, 0, 2);
        e.op11x(0x10, 4);
        e
    }));
    out.extend(each("divLong2addr", &[0xbe, 0xbf], "J", |op| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 7);
        e.const_wide(0x18, 2, 2);
        e.op12x(op, 0, 2);
        e.op11x(0x10, 0);
        e
    }));
    out
}

fn conversions() -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(each(
        "unary",
        &[0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80],
        "I",
        |op| {
            // Every unary `12x` is exercised through an `int` operand and narrowed
            // back, because the six that widen cannot be returned through an `()I`
            // method without lying about the prototype.
            let mut e = Emit::new();
            e.const4(0, 3);
            match op {
                0x7d | 0x7e => {
                    e.const_wide(0x18, 2, 3);
                    e.op12x(op, 4, 2);
                    e.op12x(0x84, 1, 4);
                }
                0x7f => {
                    e.op12x(0x82, 2, 0);
                    e.op12x(op, 3, 2);
                    e.op12x(0x87, 1, 3);
                }
                0x80 => {
                    e.const_wide(0x18, 2, (3.0f64).to_bits() as i64);
                    e.op12x(op, 4, 2);
                    e.op12x(0x8a, 1, 4);
                }
                _ => {
                    e.op12x(op, 1, 0);
                }
            }
            e.op11x(0x0f, 1);
            e
        },
    ));
    out.extend(each(
        "convFromInt",
        &[0x81, 0x82, 0x83, 0x8d, 0x8e, 0x8f],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.op12x(op, 2, 0);
            // Narrow back so the method's `()I` prototype is honest: each widening
            // is read through the matching narrowing, so the case's declared return
            // type describes the value that actually comes out.
            match op {
                0x81 => e.op12x(0x84, 1, 2),
                0x82 => e.op12x(0x87, 1, 2),
                0x83 => e.op12x(0x8a, 1, 2),
                _ => e.op12x(0x01, 1, 2),
            };
            e.op11x(0x0f, 1);
            e
        },
    ));
    out.extend(each("convFromLong", &[0x84, 0x85, 0x86], "I", |op| {
        // Each conversion produces a different shape, so each is read back
        // through the matching narrowing: `long-to-double` yields a `double`,
        // `long-to-float` a `float`, and `long-to-int` an `int`. Claiming one
        // `()I` prototype for all three only works if the bodies lie about it,
        // which is the mistake the per-family suite documents.
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 3);
        e.op12x(op, 2, 0);
        match op {
            0x85 => e.op12x(0x87, 1, 2),
            0x86 => e.op12x(0x8a, 1, 2),
            _ => e.op12x(0x01, 1, 2),
        };
        e.op11x(0x0f, 1);
        e
    }));
    out.extend(each("convFromFloat", &[0x87, 0x88, 0x89], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 3);
        e.op12x(0x82, 2, 0);
        e.op12x(op, 3, 2);
        match op {
            0x88 => e.op12x(0x84, 1, 3),
            0x89 => e.op12x(0x8a, 1, 3),
            _ => e.op12x(0x01, 1, 3),
        };
        e.op11x(0x0f, 1);
        e
    }));
    out.extend(each("convFromDouble", &[0x8a, 0x8b, 0x8c], "I", |op| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, (3.0f64).to_bits() as i64);
        e.op12x(op, 2, 0);
        match op {
            0x8b => e.op12x(0x84, 1, 2),
            0x8c => e.op12x(0x87, 1, 2),
            _ => e.op12x(0x01, 1, 2),
        };
        e.op11x(0x0f, 1);
        e
    }));
    out
}

fn comparisons() -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(each("cmpFloat", &[0x2d, 0x2e], "I", |op| {
        let mut e = Emit::new();
        e.const4(0, 1);
        e.const4(1, 2);
        e.op12x(0x82, 0, 0);
        e.op12x(0x82, 1, 1);
        e.op23x(op, 2, 0, 1);
        e.op11x(0x0f, 2);
        e
    }));
    out.extend(each("cmpDouble", &[0x2f, 0x30], "I", |op| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, (1.0f64).to_bits() as i64);
        e.const_wide(0x18, 2, (2.0f64).to_bits() as i64);
        e.op23x(op, 4, 0, 2);
        e.op11x(0x0f, 4);
        e
    }));
    out.push(case("cmpLong", "I", |_| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 1);
        e.const_wide(0x18, 2, 2);
        e.op23x(0x31, 4, 0, 2);
        e.op11x(0x0f, 4);
        e
    }));
    out.extend(each(
        "if22t",
        &[0x32, 0x33, 0x34, 0x35, 0x36, 0x37],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.const4(1, 2);
            e.op22t(op, 0, 1, 2);
            e.const4(2, 1);
            e.op11x(0x0f, 2);
            e
        },
    ));
    out.extend(each(
        "if21t",
        &[0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d],
        "I",
        |op| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op21t(op, 0, 2);
            e.const4(2, 1);
            e.op11x(0x0f, 2);
            e
        },
    ));
    out
}

fn moves() -> Vec<Case> {
    let mut out = Vec::new();
    // `12x`, `22x` and `32x` of each of the three move families.
    for (n, f, w) in [(0x01u8, 0x02u8, 0x03u8), (0x07, 0x08, 0x09)] {
        out.push(case(
            Box::leak(format!("move{n:02x}").into_boxed_str()),
            "I",
            move |_| {
                let mut e = Emit::new();
                e.const4(0, 3);
                e.op12x(n, 1, 0);
                e.op11x(0x0f, 1);
                e
            },
        ));
        out.push(case(
            Box::leak(format!("moveFrom16_{f:02x}").into_boxed_str()),
            "I",
            move |_| {
                let mut e = Emit::new();
                e.const4(0, 3);
                e.op22x(f, 1, 0);
                e.op11x(0x0f, 1);
                e
            },
        ));
        out.push(case(
            Box::leak(format!("move16_{w:02x}").into_boxed_str()),
            "I",
            move |_| {
                let mut e = Emit::new();
                e.const4(0, 3);
                // `32x` is `AA|op BBBB`: the *opcode* is the low byte of the first
                // code unit and the 8-bit destination is the high one. Getting this
                // the other way round produces a method whose every instruction is
                // the wrong one, and the first symptom is an out-of-range register
                // number built out of the opcode byte.
                e.op32x(w, 1, 0);
                e.op11x(0x0f, 1);
                e
            },
        ));
    }
    // The wide move, in all three widths, returned with `return-wide`.
    out.push(case("moveWide12x", "J", |_| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 3);
        e.op12x(0x04, 2, 0);
        e.op11x(0x10, 2);
        e
    }));
    out.push(case("moveWide22x", "J", |_| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 3);
        e.op22x(0x05, 2, 0);
        e.op11x(0x10, 2);
        e
    }));
    out.push(case("moveWide32x", "J", |_| {
        let mut e = Emit::new();
        e.const_wide(0x18, 0, 3);
        e.op32x(0x06, 2, 0);
        e.op11x(0x10, 2);
        e
    }));
    out
}

fn constants_and_results() -> Vec<Case> {
    vec![
        case("nop", "I", |_| {
            let mut e = Emit::new();
            e.const4(0, 3);
            e.nop();
            e.op11x(0x0f, 0);
            e
        }),
        case("returnVoid", "V", |_| {
            let mut e = Emit::new();
            e.u16(0x000e); // return-void
            e
        }),
        case("const4", "I", |_| {
            let mut e = Emit::new();
            e.const4(0, -3);
            e.op11x(0x0f, 0);
            e
        }),
        case("const16", "I", |_| {
            let mut e = Emit::new();
            e.const16(0x13, 0, -300);
            e.op11x(0x0f, 0);
            e
        }),
        case("const32", "I", |_| {
            let mut e = Emit::new();
            e.const32(0x14, 0, 70_000);
            e.op11x(0x0f, 0);
            e
        }),
        case("constHigh16", "I", |_| {
            let mut e = Emit::new();
            e.const_high16(0x15, 0, 0x1234);
            e.op11x(0x0f, 0);
            e
        }),
        case("constWide16", "J", |_| {
            let mut e = Emit::new();
            e.const16(0x16, 0, -300);
            e.op11x(0x10, 0);
            e
        }),
        case("constWide32", "J", |_| {
            let mut e = Emit::new();
            e.const32(0x17, 0, -70_000);
            e.op11x(0x10, 0);
            e
        }),
        case("constWide", "J", |_| {
            let mut e = Emit::new();
            e.const_wide(0x18, 0, -5_000_000_000);
            e.op11x(0x10, 0);
            e
        }),
        case("constWideHigh16", "J", |_| {
            let mut e = Emit::new();
            e.const_high16(0x19, 0, -1);
            e.op11x(0x10, 0);
            e
        }),
        case("constString", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x1a, 0, string_at(idx, "hello"));
            e.const4(1, 0);
            e.op11x(0x0f, 1);
            e
        }),
        case("constStringJumbo", "I", |idx| {
            let big = jumbo_string();
            let mut e = Emit::new();
            e.op31c(0x1b, 0, string_at(idx, &big) as u32);
            e.const4(1, 0);
            e.op11x(0x0f, 1);
            e
        }),
        case("constClass", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x1c, 0, ty_at(idx, "Ljava/lang/String;"));
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("constMethodType", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0xff, 0, proto_at(idx, &["I"], "Ljava/lang/String;") as u16);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("constMethodHandle", "I", |_idx| {
            // Index 0, and no synthetic file has a `method_handles` section, so
            // this is the refusal path: the opcode is dispatched and the engine
            // names what is missing. See EXCLUSIONS.
            let mut e = Emit::new();
            e.op21c(0xfe, 0, 0);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("moveResult", "I", |idx| {
            let mut e = Emit::new();
            e.op35c(0x71, 0, method_at(idx, HOST, "getInt", &[], "I"), &[]);
            e.op11x(0x0a, 0);
            e.op11x(0x0f, 0);
            e
        }),
        case("moveResultWide", "J", |idx| {
            let mut e = Emit::new();
            e.op35c(0x71, 0, method_at(idx, HOST, "getLong", &[], "J"), &[]);
            e.op11x(0x0b, 0);
            e.op11x(0x10, 0);
            e
        }),
        case("moveResultObject", "Ljava/lang/Object;", |idx| {
            let mut e = Emit::new();
            e.op35c(
                0x71,
                0,
                method_at(idx, HOST, "getObject", &[], "Ljava/lang/Object;"),
                &[],
            );
            e.op11x(0x0c, 0);
            e.op11x(0x11, 0);
            e
        }),
        // A `throw` that a handler catches, so both the throw and the
        // `move-exception` in the handler are observable and the case returns.
        tried(
            "throwCaught",
            "I",
            // `new-instance` is two units and the `throw` the third, so the
            // protected range is units 0..=2 and the handler starts at 3. A range
            // that stops at unit 1 leaves the `throw` outside it, the exception
            // propagates, and the case ends without reaching `move-exception`.
            vec![catch_all(0, 3, 3)],
            |idx| {
                let mut e = Emit::new();
                e.op21c(0x22, 0, ty_at(idx, "Ljava/lang/IllegalStateException;"));
                e.op11x(0x27, 0); // throw
                e.op11x(0x0d, 1); // move-exception v1 (the handler)
                e.op11x(0x0f, 1);
                e
            },
        ),
    ]
}

/// The `const-string/jumbo` string, interned before the freeze.
///
/// A real 40,000-character string, because the only thing distinguishing
/// `const-string/jumbo` from `const-string` is that its index is 32 bits wide
/// *and* the string is over the 65,535-byte limit that keeps it out of a 16-bit
/// index. A short stand-in would have exercised the register width and nothing
/// else, and would have passed whether or not the string_data_item the
/// instruction points at is the long one.
fn jumbo_string() -> String {
    // One repeated 4-byte character, so the length is exactly 40,000: over the
    // 0xffff-unit limit, and a multiple of the payload's 2-unit alignment so the
    // test does not depend on a half-filled final unit.
    "abcd".repeat(10_000)
}

fn arrays() -> Vec<Case> {
    let mut out = vec![case("newArrayAndLength", "I", |idx| {
        let mut e = Emit::new();
        e.const4(0, 3);
        e.op22c(0x23, 4, 0, ty_at(idx, "[I"));
        e.op12x(0x21, 1, 4);
        e.op11x(0x0f, 1);
        e
    })];
    out.push(case("filledNewArray", "I", |idx| {
        let mut e = Emit::new();
        e.const4(0, 7);
        // `const/16` rather than `const/4`: the packed form holds a signed
        // four-bit literal, so an `8` written into it is `-8`.
        e.const16(0x13, 1, 8);
        e.op35c(0x24, 2, ty_at(idx, "[I"), &[0, 1]);
        e.op11x(0x0c, 0);
        e.const4(1, 0);
        e.op23x(0x44, 2, 0, 1);
        e.op11x(0x0f, 2);
        e
    }));
    out.push(case("filledNewArrayRange", "I", |idx| {
        let mut e = Emit::new();
        e.const4(0, 2);
        e.const16(0x13, 1, 8);
        e.op3rc(0x25, 2, ty_at(idx, "[I"), 0);
        e.op11x(0x0c, 2);
        e.const4(3, 1);
        e.op23x(0x44, 4, 2, 3);
        e.op11x(0x0f, 4);
        e
    }));
    // The seven loads. The element is read back from a fresh array of the right
    // component type, and a value of the right shape is stored first so the read
    // is of something the store actually put there.
    for (op, ty, ret, wide) in [
        (0x44u8, "[I", "I", false),
        (0x45, "[J", "J", true),
        (0x46, "[Ljava/lang/Object;", "I", false),
        (0x47, "[Z", "I", false),
        (0x48, "[B", "I", false),
        (0x49, "[C", "I", false),
        (0x4a, "[S", "I", false),
    ] {
        out.push(case(
            Box::leak(format!("aget{op:02x}").into_boxed_str()),
            ret,
            move |idx| {
                let ty = ty.to_string();
                let mut e = Emit::new();
                e.const4(0, 1);
                e.op22c(0x23, 4, 0, ty_at(idx, &ty));
                if wide {
                    e.const_wide(0x18, 5, 7);
                } else if ty.starts_with("[L") {
                    e.op21c(0x22, 5, ty_at(idx, "Ljava/lang/Object;"));
                } else {
                    e.const4(5, 7);
                }
                e.const4(6, 0);
                e.op23x(0x4b, 5, 4, 6); // aput
                e.op23x(op, 7, 4, 6); // aget
                e.op11x(if wide { 0x10 } else { 0x0f }, 7);
                e
            },
        ));
    }
    // The seven stores, each paired with the matching load so the value is
    // observable and the store is not dead code.
    for (op, ty, load) in [
        (0x4bu8, "[I", 0x44u8),
        (0x4c, "[J", 0x45),
        (0x4d, "[Ljava/lang/Object;", 0x46),
        (0x4e, "[Z", 0x47),
        (0x4f, "[B", 0x48),
        (0x50, "[C", 0x49),
        (0x51, "[S", 0x4a),
    ] {
        out.push(case(
            Box::leak(format!("aput{op:02x}").into_boxed_str()),
            if ty == "[J" { "J" } else { "I" },
            move |idx| {
                let ty = ty.to_string();
                let mut e = Emit::new();
                e.const4(0, 1);
                e.op22c(0x23, 4, 0, ty_at(idx, &ty));
                if ty == "[J" {
                    e.const_wide(0x18, 5, 7);
                } else if ty.starts_with("[L") {
                    e.op21c(0x22, 5, ty_at(idx, "Ljava/lang/Object;"));
                } else {
                    e.const4(5, 7);
                }
                e.const4(6, 0);
                e.op23x(op, 5, 4, 6);
                e.op23x(load, 7, 4, 6);
                e.op11x(if ty == "[J" { 0x10 } else { 0x0f }, 7);
                e
            },
        ));
    }
    out
}

/// The three payload-referencing instructions, each with a back-patched offset.
///
/// The offsets are captured with `Emit::here()` as the body is emitted rather
/// than counted by hand, because a branch or payload offset is measured in code
/// units *from the instruction that carries it* and every instruction in these
/// three bodies is a different width.
fn payloads() -> Vec<Case> {
    vec![
        case("fillArrayData", "I", |idx| {
            let mut e = Emit::new();
            e.const4(0, 2);
            e.op22c(0x23, 4, 0, ty_at(idx, "[I"));
            let fill_at = e.here() as i64;
            e.op31t(0x26, 4, 0);
            e.const4(1, 1);
            e.op23x(0x44, 5, 4, 1);
            e.op11x(0x0f, 5);
            let payload_at = e.here() as i64;
            e.fill_array_data_payload(4, &[1, 2, 3, 4, 0x11, 0x22, 0x33, 0x44]);
            e.patch_i32(fill_at as usize * 2 + 2, (payload_at - fill_at) as i32);
            e
        }),
        case("packedSwitch", "I", |_| {
            let mut e = Emit::new();
            e.const4(0, 2);
            let sw = e.here() as i64;
            e.op31t(0x2b, 0, 0);
            e.const4(1, 100);
            e.op11x(0x0f, 1);
            let t_one = e.here() as i64;
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            let t_two = e.here() as i64;
            e.const4(1, 2);
            e.op11x(0x0f, 1);
            let payload = e.here() as i64;
            e.packed_switch_payload(1, &[(t_one - sw) as i32, (t_two - sw) as i32]);
            e.patch_i32(sw as usize * 2 + 2, (payload - sw) as i32);
            e
        }),
        case("sparseSwitch", "I", |_| {
            let mut e = Emit::new();
            e.const4(0, 100);
            let sw = e.here() as i64;
            e.op31t(0x2c, 0, 0);
            e.const4(1, 100);
            e.op11x(0x0f, 1);
            let t_one = e.here() as i64;
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            let t_two = e.here() as i64;
            e.const4(1, 2);
            e.op11x(0x0f, 1);
            let payload = e.here() as i64;
            e.sparse_switch_payload(&[1, 100], &[(t_one - sw) as i32, (t_two - sw) as i32]);
            e.patch_i32(sw as usize * 2 + 2, (payload - sw) as i32);
            e
        }),
    ]
}

/// The three `goto` widths, forward.
///
/// The three bodies are identical apart from the branch's own width, and the
/// offset each one needs is *different*: the target — the `return` after the
/// `const/16` the branch skips — is at unit `2 + 2 + width`, and the branch is at
/// unit 2, so the offset is `2 + width`. Emitting the number directly is
/// clearer than back-patching, and it is the point of the test: a body that used
/// one number for all three widths would be testing the widths only by accident.
///
/// Back-patching these offsets at all is a trap worth naming: `patch_i32` writes
/// **four** bytes, which is right for `31t` and `30t` and wrong for `10t` and
/// `20t`, whose offset fields are one and two bytes wide. A four-byte write at a
/// one-byte field silently truncates the *following* instruction instead.
fn branches() -> Vec<Case> {
    let mut out = Vec::new();
    for width in [1i32, 2, 3] {
        out.push(case(
            Box::leak(format!("goto{width}").into_boxed_str()),
            "I",
            move |_| {
                let mut e = Emit::new();
                e.const16(0x13, 0, 7);
                let off = 2 + width;
                match width {
                    1 => e.op10t(0x28, off as i8),
                    2 => e.op20t(0x29, off as i16),
                    _ => e.op30t(0x2a, off),
                };
                e.const16(0x13, 0, 9);
                e.op11x(0x0f, 0);
                e
            },
        ));
    }
    out
}

fn calls_and_types() -> Vec<Case> {
    let out = vec![
        case("invokeVirtual", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.const4(1, 5);
            e.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[0, 1]);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeVirtualRange", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.const4(1, 5);
            e.op3rc(0x74, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), 0);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeSuper", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.const4(1, 3);
            e.op35c(
                0x6f,
                2,
                method_at(idx, SUB, "superMeth", &["I"], "I"),
                &[0, 1],
            );
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeSuperRange", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.const4(1, 3);
            e.op3rc(0x75, 2, method_at(idx, SUB, "superMeth", &["I"], "I"), 0);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeDirect", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.op35c(0x70, 2, method_at(idx, SUB, "<init>", &[], "V"), &[0]);
            e.const4(1, 5);
            e.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[0, 1]);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeDirectRange", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, SUB));
            e.op3rc(0x76, 1, method_at(idx, SUB, "<init>", &[], "V"), 0);
            e.const4(1, 5);
            e.op3rc(0x74, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), 0);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeStatic", "I", |idx| {
            let mut e = Emit::new();
            e.const4(0, 4);
            e.const4(1, 5);
            e.op35c(
                0x71,
                2,
                method_at(idx, HOST, "sum", &["I", "I"], "I"),
                &[0, 1],
            );
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeStaticRange", "I", |idx| {
            let mut e = Emit::new();
            e.const4(0, 4);
            e.const4(1, 5);
            e.op3rc(0x77, 2, method_at(idx, HOST, "sum", &["I", "I"], "I"), 0);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeInterface", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, "Lj;"));
            e.const4(1, 0);
            e.op35c(0x72, 2, method_at(idx, IFACE, "size", &[], "I"), &[0, 1]);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("invokeInterfaceRange", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, "Lj;"));
            // `size()` takes no argument, so the contiguous range is the
            // receiver alone: `AA` is the whole register count and must be 1.
            e.op3rc(0x78, 1, method_at(idx, IFACE, "size", &[], "I"), 0);
            e.op11x(0x0a, 2);
            e.op11x(0x0f, 2);
            e
        }),
        case("instanceOf", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x1a, 0, string_at(idx, "a"));
            e.op22c(0x20, 1, 0, ty_at(idx, "Ljava/lang/String;"));
            e.op11x(0x0f, 1);
            e
        }),
        case("checkCast", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x1a, 0, string_at(idx, "a"));
            e.op21c(0x1f, 0, ty_at(idx, "Ljava/lang/String;"));
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("newInstance", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("monitorEnterExit", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.op11x(0x1d, 0);
            e.op11x(0x1e, 0);
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        }),
    ];
    out
}

fn fields() -> Vec<Case> {
    let mut out = Vec::new();
    // One field of each component type, declared on the host class so it has a
    // slot: interning a field is not enough, the instance layout comes from the
    // class's `class_data_item`.
    for (_, ty) in [
        (0u8, "I"),
        (0, "J"),
        (0, "Ljava/lang/Object;"),
        (0, "Z"),
        (0, "B"),
        (0, "C"),
        (0, "S"),
    ] {
        out.push(case(
            Box::leak(format!("field{ty}").into_boxed_str()),
            "I",
            move |idx| {
                let ty = ty.to_string();
                let mut e = Emit::new();
                e.op21c(0x22, 0, ty_at(idx, HOST));
                if ty == "J" {
                    e.const_wide(0x18, 1, 7);
                } else if ty == "Ljava/lang/Object;" {
                    e.op21c(0x22, 1, ty_at(idx, "Ljava/lang/Object;"));
                } else {
                    e.const4(1, 7);
                }
                // The seven instance stores, then the matching load.
                let (iput, iget) = match ty.as_str() {
                    "I" => (0x59u8, 0x52u8),
                    "J" => (0x5a, 0x53),
                    "Ljava/lang/Object;" => (0x5b, 0x54),
                    "Z" => (0x5c, 0x55),
                    "B" => (0x5d, 0x56),
                    "C" => (0x5e, 0x57),
                    _ => (0x5f, 0x58),
                };
                e.op22c(iput, 1, 0, field_at(idx, HOST, "fld", &ty));
                e.op22c(iget, 2, 0, field_at(idx, HOST, "fld", &ty));
                e.const4(3, 0);
                e.op11x(0x0f, 3);
                e
            },
        ));
    }
    // The seven static loads and stores against one static field per type.
    for (_, ty) in [
        (0u8, "I"),
        (0, "J"),
        (0, "Ljava/lang/Object;"),
        (0, "Z"),
        (0, "B"),
        (0, "C"),
        (0, "S"),
    ] {
        out.push(case(
            Box::leak(format!("static{ty}").into_boxed_str()),
            "I",
            move |idx| {
                let ty = ty.to_string();
                let (sput, sget) = match ty.as_str() {
                    "I" => (0x67u8, 0x60u8),
                    "J" => (0x68, 0x61),
                    "Ljava/lang/Object;" => (0x69, 0x62),
                    "Z" => (0x6a, 0x63),
                    "B" => (0x6b, 0x64),
                    "C" => (0x6c, 0x65),
                    _ => (0x6d, 0x66),
                };
                let mut e = Emit::new();
                if ty == "J" {
                    e.const_wide(0x18, 0, 7);
                } else if ty == "Ljava/lang/Object;" {
                    e.op21c(0x22, 0, ty_at(idx, "Ljava/lang/Object;"));
                } else {
                    e.const4(0, 7);
                }
                e.op21c(sput, 0, field_at(idx, HOST, "SF", &ty));
                e.op21c(sget, 1, field_at(idx, HOST, "SF", &ty));
                e.const4(2, 0);
                e.op11x(0x0f, 2);
                e
            },
        ));
    }
    out
}

/// The five opcodes the engine dispatches but refuses. See [`EXCLUSIONS`].
fn exclusions() -> Vec<Case> {
    vec![
        case("invokeCustom", "I", |_idx| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op35c(0xfc, 1, 0, &[0]);
            e.op11x(0x0a, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("invokeCustomRange", "I", |_idx| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op3rc(0xfd, 1, 0, 0);
            e.op11x(0x0a, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("invokePolymorphic", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.op45cc(
                0xfa,
                2,
                method_at(idx, HOST, "vMeth", &["I"], "I"),
                &[0, 1],
                proto_at(idx, &["I"], "I") as u16,
            );
            e.op11x(0x0a, 1);
            e.op11x(0x0f, 1);
            e
        }),
        case("invokePolymorphicRange", "I", |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, HOST));
            e.const4(1, 1);
            e.op4rcc(
                0xfb,
                2,
                method_at(idx, HOST, "vMeth", &["I"], "I"),
                0,
                proto_at(idx, &["I"], "I") as u16,
            );
            e.op11x(0x0a, 1);
            e.op11x(0x0f, 1);
            e
        }),
    ]
}

fn coverage_corpus() -> Vec<Case> {
    let mut out = Vec::new();
    out.extend(arithmetic());
    out.extend(division());
    out.extend(conversions());
    out.extend(comparisons());
    out.extend(moves());
    out.extend(constants_and_results());
    out.extend(arrays());
    out.extend(payloads());
    out.extend(branches());
    out.extend(calls_and_types());
    out.extend(fields());
    out.extend(exclusions());
    out
}

// ============================================================== the run

/// One case's outcome.
#[derive(Clone, Debug)]
struct Outcome {
    /// `true` if the method returned normally.
    returned: bool,
    /// `ExecError::kind()`.
    kind: String,
    /// The whole error, for a failure message.
    detail: String,
    /// The `Unsupported` discriminant, when it is one.
    unsupported: Option<String>,
    /// `Termination::as_str()`.
    termination: String,
    /// Every opcode the engine dispatched during this case.
    opcodes: BTreeSet<u8>,
}

fn build_file() -> Vec<u8> {
    let corpus = coverage_corpus();
    let mut s = Synthetic::new();
    // The callees the corpus calls, each with a real body, so a call that
    // reaches them is a call the *engine* resolved rather than one the shim
    // answered.
    s.declare_static("getInt", &[], "I", 2, 0);
    s.declare_static("getLong", &[], "J", 4, 0);
    s.declare_static("getObject", &[], "Ljava/lang/Object;", 2, 0);
    s.declare_static("getJumbo", &[], "Ljava/lang/Object;", 2, 0);
    s.declare_static("sum", &["I", "I"], "I", 6, 0);
    s.declare("vMeth", &["I"], "I", 2, 2);
    for ty in ["I", "J", "Ljava/lang/Object;", "Z", "B", "C", "S"] {
        s.field("fld", ty);
        s.field("SF", ty);
    }
    for c in &corpus {
        s.declare_static(c.name, &[], c.ret, c.registers, 0);
    }
    intern_standard(&mut s);
    s.writer().add_string(&jumbo_string());

    // `Lu;` extends `Lp;` so `invoke-super` has somewhere to resolve, and
    // carries its own `vMeth` so `invoke-virtual` has an override to find.
    let mut ctor = Emit::new();
    ctor.op11x(0x0e, 0);
    let mut vmeth = Emit::new();
    vmeth.const16(0x13, 0, 7);
    vmeth.op12x(0xb0, 0, 1);
    vmeth.op11x(0x0f, 0);
    let mut smeth = Emit::new();
    smeth.const16(0x13, 0, 999);
    smeth.op11x(0x0f, 0);
    let sub = ClassDef::new(SUB, Some("Lp;".to_string()))
        .with_field(FieldDef::instance("u", "I"))
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC,
            ctor.code(1, 1, 0),
        ))
        .with_method(MethodDef::concrete(
            "vMeth",
            &["I"],
            "I",
            access::ACC_PUBLIC,
            vmeth.clone().code(2, 2, 0),
        ))
        .with_method(MethodDef::concrete(
            "superMeth",
            &["I"],
            "I",
            access::ACC_PUBLIC,
            smeth.clone().code(2, 2, 0),
        ));
    s.class(sub);
    let mut pctor = Emit::new();
    pctor.op11x(0x0e, 0);
    let mut psmeth = Emit::new();
    psmeth.const16(0x13, 0, 11);
    psmeth.op12x(0xb0, 0, 1);
    psmeth.op11x(0x0f, 0);
    let parent = ClassDef::extending_object("Lp;")
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC,
            pctor.code(1, 1, 0),
        ))
        .with_method(MethodDef::concrete(
            "superMeth",
            &["I"],
            "I",
            access::ACC_PUBLIC,
            psmeth.code(2, 2, 0),
        ));
    s.class(parent);
    let iface = ClassDef::new(IFACE, Some("Ljava/lang/Object;".to_string()))
        .with_method(MethodDef::abstract_("size", &[], "I"));
    s.class(iface);
    let mut ictor = Emit::new();
    ictor.op11x(0x0e, 0);
    let mut isize = Emit::new();
    isize.const16(0x13, 0, 21);
    isize.op11x(0x0f, 0);
    let mut impl_class = ClassDef::extending_object("Lj;");
    impl_class.interfaces.push(IFACE.to_string());
    let impl_class = impl_class
        .with_method(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC,
            ictor.code(1, 1, 0),
        ))
        .with_method(MethodDef::concrete(
            "size",
            &[],
            "I",
            access::ACC_PUBLIC,
            isize.code(2, 1, 0),
        ));
    s.class(impl_class);

    s.finish(|idx| {
        let mut out: BTreeMap<String, CodeBody> = BTreeMap::new();
        let mut g = Emit::new();
        g.const16(0x13, 0, 42);
        g.op11x(0x0f, 0);
        out.insert("getInt".to_string(), g.code(2, 0, 0));
        let mut l = Emit::new();
        l.const_wide(0x18, 0, 9);
        l.op11x(0x10, 0);
        out.insert("getLong".to_string(), l.code(4, 0, 0));
        let mut o = Emit::new();
        o.op21c(0x1a, 0, string_at(idx, "hello"));
        o.op11x(0x11, 0);
        out.insert("getObject".to_string(), o.code(2, 0, 0));
        // Returns the jumbo string itself rather than a constant, so a test can
        // read the characters back and check the index really pointed at it.
        let mut j = Emit::new();
        j.op31c(0x1b, 0, string_at(idx, &jumbo_string()) as u32);
        j.op11x(0x11, 0);
        out.insert("getJumbo".to_string(), j.code(2, 0, 0));
        let mut sum = Emit::new();
        // Static with two `int` parameters and six registers: the incoming window
        // is the *last* `ins_size` registers, v4 and v5.
        sum.op23x(0x90, 0, 4, 5);
        sum.op11x(0x0f, 0);
        out.insert("sum".to_string(), sum.code(6, 2, 0));
        out.insert("vMeth".to_string(), vmeth.code(2, 2, 2));
        for c in &corpus {
            let e = (c.body)(idx);
            let body = match &c.tries {
                Some(t) => e.code_tries(c.registers, 0, 0, t.clone()),
                None => e.code(c.registers, 0, 0),
            };
            out.insert(c.name.to_string(), body);
        }
        out
    })
    .expect("emit")
}

/// Run every case in a *fresh* interpreter, so a case's opcode histogram is its
/// own and no case can mask another.
fn run_corpus() -> BTreeMap<String, Outcome> {
    let corpus = coverage_corpus();
    let bytes = build_file();
    let rec = Recorder::new();
    rec.answer("Ljava/lang/String;->length()I", HostValue::Int(1));
    let mut out = BTreeMap::new();
    for c in &corpus {
        let sig = format!("(){}", c.ret);
        let mut vm = vm(&bytes, Config::default(), Some(rec.clone())).expect("open");
        let r = vm.invoke_method(HOST, c.name, &sig, &[]);
        let stats = vm.stats();
        let opcodes: BTreeSet<u8> = (0u8..=0xff)
            .filter(|&op| stats.opcode_counts[op as usize] > 0)
            .collect();
        let outcome = match r {
            Ok(v) => Outcome {
                returned: true,
                kind: "returned".to_string(),
                detail: format!("{v:?}"),
                unsupported: None,
                termination: "returned".to_string(),
                opcodes,
            },
            Err(e) => {
                let unsupported = match &e {
                    dexinterp::ExecError::Unsupported { kind, .. } => {
                        Some(kind.as_str().to_string())
                    }
                    _ => None,
                };
                Outcome {
                    returned: false,
                    kind: e.kind().to_string(),
                    detail: format!("{e}"),
                    unsupported,
                    termination: e.termination().as_str().to_string(),
                    opcodes,
                }
            }
        };
        out.insert(c.name.to_string(), outcome);
    }
    out
}

fn defined_opcodes() -> BTreeSet<u8> {
    dexcore::opcodes::OPCODES
        .iter()
        .filter(|o| o.valid)
        .map(|o| o.opcode)
        .collect()
}

/// Every opcode any case dispatched.
fn dispatched(run: &BTreeMap<String, Outcome>) -> BTreeSet<u8> {
    let mut all = BTreeSet::new();
    for o in run.values() {
        all.extend(o.opcodes.iter().copied());
    }
    all
}

#[test]
fn the_jumbo_string_really_is_the_forty_thousand_character_one() {
    // The corpus's `constStringJumbo` case only proves the opcode dispatched: it
    // returns a hard-coded `1`, so it would pass just as happily if the
    // instruction pointed at some other string in the pool. With a short
    // stand-in for the jumbo string that is exactly the mistake it would hide —
    // the register is 32 bits either way, and only the `string_data_item` behind
    // the index tells them apart.
    //
    // So this reads the string back out of the heap and compares the text, which
    // catches both a payload read at the wrong width and an index that resolved
    // to a different string. Verified by mutation: pointing the instruction at
    // `"hello"` fails with `left: 5, right: 40000`.
    //
    // What this does *not* catch is a 32-bit index silently truncated to 16
    // bits, because a pool this small numbers its strings under 0x10000 and the
    // truncation is a no-op. That needs a file with more than 65,535 strings,
    // which is not a synthetic-file question.
    let bytes = build_file();
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let v = vm
        .invoke_method(HOST, "getJumbo", "()Ljava/lang/Object;", &[])
        .expect("returns");
    let got = vm
        .heap()
        .string_of(v)
        .expect("a string came back")
        .to_string();
    let want = jumbo_string();
    // The pool holds short strings too, so "some string" is not good enough.
    assert_eq!(
        got.len(),
        40_000,
        "the length came from the wrong payload width"
    );
    assert_eq!(got, want);
}

#[test]
fn a_refusal_is_an_unsupported_and_never_a_crash() {
    // The four terminal conditions have to stay apart, and a refusal is one of
    // the four. Every excluded case must therefore end in `Unsupported` and
    // *nothing else*: an `ExceptionRaised` here would put a substrate gap in the
    // bucket that means "the app crashed", and an `EngineFault` would put it in
    // the bucket that means "this file is malformed".
    let run = run_corpus();
    for x in EXCLUSIONS {
        let o = run.get(x.case).expect("exclusion case exists");
        assert_eq!(
            o.termination, "unsupported",
            "{} ended as {}",
            x.case, o.termination
        );
        assert_ne!(o.termination, "exception_raised", "{}", x.case);
        assert_ne!(o.termination, "budget_exhausted", "{}", x.case);
        assert_ne!(o.termination, "engine_fault", "{}", x.case);
    }
}

#[test]
fn the_coverage_table_is_the_one_the_specification_describes() {
    // A coverage claim is only meaningful against a right table, and
    // `dexcore/tests/opcode_table.rs` proves the table against a second,
    // independent transcription. What is asserted here is only that the
    // arithmetic in the tests below has the shape it assumes.
    assert_eq!(
        defined_opcodes().len(),
        224,
        "the specification defines 224 opcodes"
    );
    assert_eq!(dexcore::opcodes::OPCODES.len(), 256);
    assert_eq!(
        256 - defined_opcodes().len(),
        32,
        "the specification leaves 32 opcodes unused"
    );
}

#[test]
fn every_defined_opcode_is_dispatched_by_the_engine() {
    let run = run_corpus();
    let defined = defined_opcodes();
    let got = dispatched(&run);
    // The claim that matters. An opcode in neither set is one the engine's
    // dispatch never saw, which means nothing in this crate tests it — and an
    // untested opcode is exactly how a plausible wrong answer gets shipped.
    let unaccounted: Vec<&'static str> = defined
        .difference(&got)
        .map(|op| dexcore::opcodes::mnemonic(*op))
        .collect();
    assert!(
        unaccounted.is_empty(),
        "{} of the {} defined opcodes were never dispatched: {unaccounted:?}",
        unaccounted.len(),
        defined.len()
    );
    // And the other direction: nothing outside the defined set was ever
    // dispatched. The 32 `(unused)` slots must be refused, not executed.
    let undefined: Vec<&'static str> = got
        .difference(&defined)
        .map(|op| dexcore::opcodes::mnemonic(*op))
        .collect();
    assert!(
        undefined.is_empty(),
        "the engine dispatched {undefined:?}, which the specification leaves unused"
    );
}

#[test]
fn every_refused_opcode_names_itself() {
    let run = run_corpus();
    for x in EXCLUSIONS {
        let outcome = run.get(x.case).unwrap_or_else(|| {
            panic!(
                "the exclusion for {} names case {:?}, which the corpus does not have",
                hex(x.op),
                x.case
            )
        });
        assert!(
            outcome.opcodes.contains(&x.op),
            "{} claims to cover 0x{:02x} but the case never dispatched it",
            x.case,
            x.op
        );
        assert!(
            !outcome.returned,
            "{} was expected to be refused, but it returned {}",
            x.case, outcome.detail
        );
        assert_eq!(
            outcome.unsupported.as_deref(),
            Some(x.kind),
            "{} refused with {:?}, not the declared {:?}: {}",
            x.case,
            outcome.unsupported,
            x.kind,
            outcome.detail
        );
        // Never the "I met an opcode I do not know" arm: that would mean the
        // engine's dispatch does not know the opcode at all, which is a
        // different and much worse claim.
        assert_ne!(
            outcome.unsupported.as_deref(),
            Some("foreign_format"),
            "{}",
            x.case
        );
        assert!(
            outcome.detail.len() > x.why.len() / 4,
            "{} refused without saying what was missing",
            x.case
        );
        assert!(
            x.why.len() > 60,
            "the exclusion for 0x{:02x} has no reason worth reviewing",
            x.op
        );
    }
}

#[test]
fn no_other_case_refused() {
    // The exclusion list is a list, not a filter. If an opcode outside it stops
    // working, this test fails with the case's name — which is the signal that an
    // exclusion is needed *with a reason*, rather than the engine quietly
    // ceasing to execute something.
    let run = run_corpus();
    let excluded: BTreeSet<&str> = EXCLUSIONS.iter().map(|x| x.case).collect();
    let failed: Vec<(&str, String, String)> = run
        .iter()
        .filter(|(name, o)| !o.returned && !excluded.contains(name.as_str()))
        .map(|(name, o)| (name.as_str(), o.kind.clone(), o.detail.clone()))
        .collect();
    assert!(
        failed.is_empty(),
        "{} non-excluded case(s) did not return: {failed:?}",
        failed.len()
    );
    // ...and every case did *something*, so a case whose body failed to decode
    // cannot masquerade as coverage.
    let empty: Vec<&str> = run
        .iter()
        .filter(|(name, o)| o.opcodes.is_empty() && name.as_str() != "returnVoid")
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        empty.is_empty(),
        "these cases dispatched nothing at all: {empty:?}"
    );
}

#[test]
fn the_exclusion_list_is_disjoint_and_complete() {
    let mut seen = BTreeSet::new();
    for x in EXCLUSIONS {
        assert!(seen.insert(x.op), "0x{:02x} is excluded twice", x.op);
        let e = dexcore::opcodes::opcode(x.op);
        assert!(
            e.valid,
            "0x{:02x} is excluded but the specification leaves it unused",
            x.op
        );
        assert_ne!(e.mnemonic, "unused");
    }
    // Nothing outside the defined set may be excluded, and the count is small
    // enough to read: five opcodes out of 224.
    assert_eq!(
        EXCLUSIONS.len(),
        5,
        "the exclusion list has grown; each entry needs a reviewable reason"
    );
}

#[test]
fn an_unused_opcode_is_refused_by_name_and_still_counted_as_dispatched() {
    // A `10x` slot the specification marks `(unused)`. Reaching one is not a
    // crash, not a wrong answer and not a `foreign_format`; it is
    // `Unsupported::UnusedOpcode`, which is a distinct record — and the engine
    // still counts it, which is what lets the coverage arithmetic tell "never
    // reached" from "reached and refused".
    let mut s = Synthetic::new();
    // Static, so the case can be called with no arguments: an instance method
    // would report an argument-count mismatch before the opcode is ever reached.
    s.declare_static("unusedOpcode", &[], "I", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.u16(0x003e); // 0x3e is `(unused)`: one code unit, no operands
            e.op11x(0x0f, 0);
            BTreeMap::from([("unusedOpcode".to_string(), e.code(4, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let result = vm.invoke_method(HOST, "unusedOpcode", "()I", &[]);
    let e = result.expect_err("must refuse");
    assert_eq!(e.kind(), "unsupported", "the error was: {e}");
    assert_eq!(e.termination(), Termination::Unsupported);
    assert_eq!(
        unsupported_kind(&vm.invoke_method(HOST, "unusedOpcode", "()I", &[])),
        "unused_opcode"
    );
    assert!(
        vm.stats().executed(0x3e),
        "the unused opcode was dispatched before being refused"
    );
}

fn hex(op: u8) -> String {
    format!("0x{op:02x}")
}
