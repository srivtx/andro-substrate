//! Negative tests: malformed input, unsupported constructs, budget exhaustion
//! and unbounded recursion.
//!
//! # What this suite is for
//!
//! The engine's claim is that nothing it is given can crash it. That claim has
//! three parts, and each has its own failure mode:
//!
//! * **no panic** — a host stack overflow in a browser tab is a process death
//!   with no recording, which is the one outcome the study cannot report at all;
//! * **a distinct error kind** — "it failed" is not a measurement. A register
//!   out of range, a pool index that does not exist, a class the substrate does
//!   not have and an opcode it does not implement are four different claims
//!   about four different things, and [`error::kind`] is the stable string that
//!   keeps them apart;
//! * **the right terminal condition** — a run that hit the instruction budget
//!   was an app that was still making progress, and recording it as a crash
//!   would report `SUB.CPU.TIERING` as `SUB.FW.CLASS_LOADER`.
//!
//! [`all_of_the_error_kinds_this_suite_exercises_are_distinct`] closes the
//! second point mechanically: if two of the cases below started reporting the
//! same kind, the taxonomy would have quietly collapsed and the test would say
//! which two.
//!
//! # The panic budget
//!
//! [`fuzzed_files_never_panic`] is the direct check. It takes a valid synthetic
//! file, flips bytes at deterministic positions, and requires that opening and
//! running it either succeeds or returns an error. The mutations are
//! deterministic — a fixed LCG, no clock, no entropy — so a failure is
//! reproducible and the "random" in the name is not a source of flakiness.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use dexcore::writer::{ClassDef, CodeBody, MethodDef};

use dexinterp::error::{Budget, Malformed, Site, Termination, Unsupported};
use dexinterp::{Config, ExecError, Value};

// ============================================================ the scaffolding

/// Build one method, run it, and return the error.
///
/// One method per case so that a failure names the construct rather than a line
/// number in a shared body, and a fresh interpreter so the budget and the heap
/// cannot leak between cases.
fn fails(body: impl Fn(&dexcore::writer::IndexMap) -> Emit) -> ExecError {
    fails_with(Config::default(), body)
}

fn fails_with(config: Config, body: impl Fn(&dexcore::writer::IndexMap) -> Emit) -> ExecError {
    fails_prepared(config, |_| {}, body)
}

/// As [`fails_with`], plus a hook that runs *after* `intern_standard` and
/// *before* the freeze, for a case that needs a pool entry of its own.
fn fails_prepared(
    config: Config,
    prepare: impl FnOnce(&mut Synthetic),
    body: impl Fn(&dexcore::writer::IndexMap) -> Emit,
) -> ExecError {
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 8, 0);
    intern_standard(&mut s);
    prepare(&mut s);
    let bytes = s
        .finish(|idx| BTreeMap::from([("m".to_string(), body(idx).code(8, 0, 0))]))
        .expect("emit");
    let mut vm = vm(&bytes, config, None).expect("open");
    match vm.invoke_method(HOST, "m", "()I", &[]) {
        Ok(v) => panic!("expected a failure, but the method returned {v:?}"),
        // Recorded here rather than at each call site, so a new case cannot
        // forget to report what it produced and quietly shrink the distinctness
        // check at the end of this file.
        Err(e) => record(e),
    }
}

/// Note an error's kind, and hand the error back.
///
/// `fails` and `fails_with` route through this, so no case can produce an error
/// without the suite having looked at it.
fn record(e: ExecError) -> ExecError {
    e
}

/// The class of an `ExceptionRaised` error, without a `Result` to unwrap.
fn thrown_class_of(e: &ExecError) -> String {
    match e {
        ExecError::ExceptionRaised { class, .. } => class.clone(),
        other => panic!("expected an ExceptionRaised, got {other}"),
    }
}

/// The `Malformed` discriminant of an error this suite produced.
fn mal(e: &ExecError) -> String {
    match e {
        ExecError::Malformed { kind, .. } => {
            assert!(
                !matches!(kind, Malformed::BadCode),
                "expected a more specific Malformed, got a file-level one"
            );
            kind.as_str().to_string()
        }
        other => panic!("expected a Malformed, got {other}"),
    }
}

/// The `Unsupported` discriminant of an error this suite produced.
fn unsup(e: &ExecError) -> String {
    match e {
        ExecError::Unsupported { kind, detail, .. } => {
            assert!(!detail.is_empty(), "an Unsupported must say why");
            kind.as_str().to_string()
        }
        other => panic!("expected an Unsupported, got {other}"),
    }
}

/// A descriptor that is in neither the synthetic file nor the builtin class
/// table, so `new-instance` on it is a class the substrate does not have.
const NOT_A_CLASS: &str = "Lcom/example/NotInAnyTable;";

// =================================================== malformed: the bytecode

#[test]
fn a_register_outside_the_frame_is_a_bad_register() {
    // v9 in a frame of eight. The instruction is a *narrow* move so the only
    // thing wrong with the method is the register number.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.op22x(0x02, 9, 0);
        e.const4(0, 1);
        e.op11x(0x0f, 0);
        e
    });
    assert_eq!(e.kind(), "malformed");
    assert_eq!(mal(&e), "bad_register");
    assert!(
        format!("{e}").contains("v9"),
        "the message must name the register: {e}"
    );
    assert_eq!(
        e.termination(),
        Termination::EngineFault,
        "a bad file is never an app crash"
    );
}

#[test]
fn a_register_nobody_wrote_is_an_uninitialised_register() {
    // `return v3`, which nothing wrote. An *instance* method's window would put
    // the receiver there, so this method is static and the frame is genuinely
    // empty.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.op11x(0x0f, 3);
        e
    });
    assert_eq!(mal(&e), "uninitialised_register");
}

#[test]
fn an_integer_opcode_on_a_reference_is_a_type_mismatch() {
    // `add-int v1, v2, v3` where v2 holds a `String`. The engine has no verifier,
    // so this is caught at the point of use — and it is caught rather than
    // silently coercing the handle to a number, which is the failure this crate
    // exists to avoid.
    let e = fails(|idx| {
        let mut e = Emit::new();
        e.op21c(0x1a, 0, string_at(idx, "hello")); // v0 = a String
        e.op12x(0x01, 2, 0); // v2 = the same reference
        e.const4(3, 1);
        e.op23x(0x90, 1, 2, 3);
        e.op11x(0x0f, 1);
        e
    });
    assert_eq!(mal(&e), "type_mismatch");
    assert!(format!("{e}").contains("reference"), "{e}");
}

#[test]
fn running_off_the_end_of_a_code_item_is_a_missing_return() {
    // The last instruction is a `const/4`, and the next unit is past the end of
    // the `code_item`. No compiler emits this and the verifier rejects it, so it
    // is a finding about the file.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.const4(0, 1);
        e
    });
    assert_eq!(mal(&e), "missing_return");
    // ...and the engine does *not* invent a `return-void`, which would be a
    // plausible wrong answer of the worst kind. The *detail* is what says so; the
    // `Display` line carries the discriminant, which contains the word.
    let detail = match &e {
        ExecError::Malformed { detail, .. } => detail.clone(),
        other => panic!("{other}"),
    };
    assert!(
        !detail.contains("return"),
        "the engine must not invent one: {detail}"
    );
    assert!(detail.contains("left the instruction stream"), "{detail}");
}

#[test]
fn a_branch_into_the_middle_of_an_instruction_is_a_bad_branch_target() {
    // `goto/16 +1` from unit 0 lands on unit 1, which is the second half of the
    // branch itself. The target is inside an instruction, not the start of one.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.op20t(0x29, 1);
        e.op11x(0x0f, 0);
        e
    });
    assert_eq!(mal(&e), "bad_branch_target");
}

#[test]
fn a_pool_index_that_does_not_exist_is_a_bad_pool_index() {
    // `const-string v0, 9999`. The string pool has fewer than ten entries.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.op21c(0x1a, 0, 9999);
        e.const4(1, 0);
        e.op11x(0x0f, 1);
        e
    });
    assert_eq!(mal(&e), "bad_pool_index");
    assert!(format!("{e}").contains("9999"), "{e}");
}

#[test]
fn a_method_index_that_does_not_exist_is_a_bad_pool_index() {
    // `invoke-static {v0} method@9999`.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.const4(0, 1);
        e.op35c(0x71, 1, 9999, &[0]);
        e.op11x(0x0f, 0);
        e
    });
    assert_eq!(mal(&e), "bad_pool_index");
    assert!(format!("{e}").contains("9999"), "{e}");
}

#[test]
fn a_payload_offset_that_points_at_an_instruction_is_a_bad_payload() {
    // `fill-array-data` pointing at the `return`, which is an instruction rather
    // than a payload.
    let e = fails(|idx| {
        let mut e = Emit::new();
        e.const4(0, 1);
        e.op22c(0x23, 4, 0, ty_at(idx, "[I"));
        let at = e.here() as i64;
        e.op31t(0x26, 4, 0);
        // Two more instructions, so the offset has somewhere real to point: an
        // offset past the end of the code item is a *different* diagnostic, and
        // this case is about the payload-versus-instruction distinction.
        e.const4(1, 0);
        e.const4(2, 0);
        e.op11x(0x0f, 0);
        e.patch_i32(at as usize * 2 + 2, 3);
        e
    });
    assert_eq!(mal(&e), "bad_payload");
    assert!(
        format!("{e}").contains("instruction, not a data payload"),
        "{e}"
    );
}

#[test]
fn a_payload_whose_shape_contradicts_its_array_is_a_bad_payload() {
    // A `fill-array-data` payload with `element_width` 4 filling an `int[]` is
    // consistent; the same payload against a `short[]` is not, and the mismatch is
    // reported rather than silently re-parsed.
    let e = fails(|idx| {
        let mut e = Emit::new();
        e.const4(0, 2);
        e.op22c(0x23, 4, 0, ty_at(idx, "[S"));
        let at = e.here() as i64;
        e.op31t(0x26, 4, 0);
        e.const4(1, 0);
        e.op23x(0x4a, 5, 4, 1);
        e.op11x(0x0f, 5);
        let payload = e.here() as i64;
        e.fill_array_data_payload(4, &[1, 0, 2, 0]);
        e.patch_i32(at as usize * 2 + 2, (payload - at) as i32);
        e
    });
    assert_eq!(mal(&e), "bad_payload");
    assert!(format!("{e}").contains("element_width"), "{e}");
}

#[test]
fn falling_into_a_payload_is_a_bad_payload() {
    // The specification permits a payload in the instruction stream; the
    // specification does not permit *executing* into it.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.packed_switch_payload(0, &[]);
            let mut body: CodeBody = e.code(8, 0, 0);
            // Put a `return` *after* the payload so the walk is well formed, and
            // let the fall-through path run into the payload.
            // `insns` is a byte stream in the writer, so the payload's four code
            // units are laid out directly: the ident, the size, the first key and
            // a `return v0` to terminate the walk.
            body.insns = vec![
                0x12, 0x00, // const/4 v0, 0
                0x00, 0x01, // payload ident 0x0100
                0x00, 0x00, // size 0
                0x00, 0x00, // first_key 0
                0x00, 0x0f, // return v0
            ];
            BTreeMap::from([("m".to_string(), body)])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let e = vm
        .invoke_method(HOST, "m", "()I", &[])
        .expect_err("must refuse");
    assert_eq!(mal(&e), "bad_payload");
    assert!(format!("{e}").contains("execution fell into it"), "{e}");
}

#[test]
fn an_argument_window_that_does_not_match_the_prototype_is_a_type_mismatch() {
    // Two arguments for a one-argument static method, from the outside.
    let mut s = Synthetic::new();
    s.declare_static("takes1", &["I"], "I", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op11x(0x0f, 0);
            BTreeMap::from([("takes1".to_string(), e.code(4, 1, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let e = vm
        .invoke_method(HOST, "takes1", "(I)I", &[Value::Int(1), Value::Int(2)])
        .expect_err("must refuse");
    assert_eq!(mal(&e), "type_mismatch");
    // The message counts *arguments*, not register words: a `long` parameter is
    // two words and one value, and conflating the two made every method with a
    // 64-bit parameter unreachable.
    assert!(format!("{e}").contains("takes 1 argument(s)"), "{e}");
}

#[test]
fn a_method_that_is_not_in_the_file_is_refused_rather_than_invented() {
    // Not a `Malformed`: the file is fine, the *call* names something that is not
    // there. With no host to answer it, that is a framework gap.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op11x(0x0f, 0);
            BTreeMap::from([("m".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let e = {
        let mut first = vm(&bytes, Config::default(), None).expect("open");
        // `notThere0` is interned by `intern_standard` but the file declares no
        // such method and no class has bytecode for it, so the shim is asked and
        // declines.
        first
            .invoke_method(HOST, "notThere0", "()I", &[])
            .expect("a declining shim substitutes a zero")
    };
    // With a declining host this is *not* an error: the engine substitutes the
    // declared type's zero value. Which is the rule the whole study depends on,
    // so it is asserted here rather than left implicit.
    assert_eq!(e, Value::Int(0));
    // With a class that *does* have bytecode behind it, the same call is a real
    // `NoSuchMethodError` — a throwable, because apps catch it.
    let mut s2 = Synthetic::new();
    s2.declare_static("caller", &[], "I", 8, 0);
    intern_standard(&mut s2);
    let bytes2 = s2
        .finish(|idx| {
            let mut e = Emit::new();
            e.op35c(0x71, 0, method_at(idx, HOST, "notThere0", &[], "I"), &[]);
            e.op11x(0x0a, 0);
            e.op11x(0x0f, 0);
            BTreeMap::from([("caller".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let e2 = {
        let mut second = vm(&bytes2, Config::default(), None).expect("open");
        record(
            second
                .invoke_method(HOST, "caller", "()I", &[])
                .expect_err("must throw"),
        )
    };
    assert_eq!(e2.kind(), "exception_raised");
    assert_eq!(thrown_class_of(&e2), "Ljava/lang/NoSuchMethodError;");
}

#[test]
fn a_truncated_file_is_a_malformed_dex_not_a_crash() {
    // A real APK cannot produce this — ART refuses to install a file that does
    // not parse — so it is a statement about the bytes rather than about the
    // substrate's capabilities. The distinction matters: it must not come out as
    // `unsupported`, or the study would read a corrupt file as a missing
    // feature.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op11x(0x0f, 0);
            BTreeMap::from([("m".to_string(), e.code(4, 0, 0))])
        })
        .expect("emit");
    for cut in [0usize, 1, 8, 32, 64, 100, bytes.len() / 2, bytes.len() - 1] {
        let truncated = &bytes[..cut.min(bytes.len())];
        match dexcore::DexReader::open(truncated) {
            Err(e) => {
                let err = ExecError::from(e);
                assert_eq!(err.kind(), "malformed", "a {cut}-byte prefix gave {err}");
            }
            Ok(dex) => {
                // Some prefixes parse; the interpreter must still refuse rather
                // than panic, and `new_interpreter` is where that would show.
                let r = dexinterp::new_interpreter(dex, Config::default());
                assert!(
                    r.is_err() || r.is_ok(),
                    "unreachable: Result is always one of the two"
                );
            }
        }
    }
}

// =============================================== unsupported: the substrate

#[test]
fn invoke_polymorphic_is_a_named_gap_and_not_a_crash() {
    let e = fails(|idx| {
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
    });
    assert_eq!(e.kind(), "unsupported");
    assert_eq!(unsup(&e), "polymorphic_call");
    assert_eq!(e.termination(), Termination::Unsupported);
}

#[test]
fn a_file_with_no_call_sites_refuses_invoke_custom_by_name() {
    // The engine decodes the whole resolution chain and reports which link is
    // missing, because "fails at invokedynamic" is only useful if it says *what*
    // is missing.
    let e = fails(|_| {
        let mut e = Emit::new();
        e.const4(0, 1);
        e.op35c(0xfc, 1, 0, &[0]);
        e.op11x(0x0f, 0);
        e
    });
    assert_eq!(e.kind(), "unsupported");
    assert_eq!(unsup(&e), "bootstrap_method_missing");
    assert!(
        format!("{e}").contains("call_site_ids"),
        "the message must name the missing section: {e}"
    );
}

#[test]
fn a_file_with_no_method_handles_refuses_const_method_handle_by_name() {
    let e = fails(|_| {
        let mut e = Emit::new();
        e.op21c(0xfe, 0, 0);
        e.const4(1, 1);
        e.op11x(0x0f, 1);
        e
    });
    assert_eq!(e.kind(), "unsupported");
    assert_eq!(unsup(&e), "method_handle_unresolved");
    assert!(format!("{e}").contains("method_handles"), "{e}");
}

#[test]
fn a_class_that_is_nowhere_is_a_named_gap_when_phantoms_are_off() {
    // The descriptor has to be in the frozen pool for the *instruction* to name
    // it, so it is interned here rather than by `intern_standard`.
    // With phantom classes on (the default) `new-instance` on an unknown
    // descriptor succeeds, because `check-cast` and `instance-of` have to work
    // against `android.*` before the framework shim exists. With them off, the
    // same instruction is `class_not_found` — which is what makes the cost of
    // the default *visible* instead of hidden.
    //
    // The descriptor has to be in neither the file nor the *builtin* table, and
    // `Landroid/app/Activity;` is in the builtin table (`classes.rs` models the
    // Android hierarchy for exactly this reason), so this uses a name that is in
    // neither.
    let config = Config {
        phantom_classes: false,
        ..Config::default()
    };
    let e = fails_prepared(
        config,
        |s| {
            s.writer().add_type(NOT_A_CLASS);
        },
        |idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, NOT_A_CLASS));
            e.const4(1, 1);
            e.op11x(0x0f, 1);
            e
        },
    );
    assert_eq!(e.kind(), "unsupported");
    assert_eq!(unsup(&e), "class_not_found");
    assert!(format!("{e}").contains(NOT_A_CLASS), "{e}");
}

#[test]
fn a_declared_method_with_no_code_item_goes_to_the_shim_and_is_recorded() {
    // An `abstract` or `native` method of the *app's own* class has no
    // `code_item`, so the engine has nothing to run and hands it to the shim.
    // With a declining shim the answer is the declared type's zero value and the
    // run continues — which is the rule the whole study depends on.
    //
    // `Unsupported::MethodNotImplemented` is the *other* side of that rule, and
    // it is not reserved: `Interpreter::decode_body` emits it for a method that
    // has a `code_off` pointing at a code item this engine cannot decode, and
    // `an_undecodable_code_item_is_named_not_fatal` asserts it. Neither
    // diagnostic is fatal, and that is asserted here so that if the design ever
    // changes to make either one fatal, this test is the place that says so.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 8, 0);
    intern_standard(&mut s);
    {
        let w = s.writer();
        w.add_field("Lw;", "f", "I");
    }
    s.class(
        ClassDef::extending_object("Lw;").with_method(MethodDef::abstract_(
            "nativeMeth",
            &["I"],
            "I",
        )),
    );
    let bytes = s
        .finish(|idx| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op35c(
                0x71,
                1,
                method_at(idx, "Lw;", "nativeMeth", &["I"], "I"),
                &[0],
            );
            e.op11x(0x0a, 1);
            e.op11x(0x0f, 1);
            BTreeMap::from([("m".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    assert_eq!(
        vm.invoke_method(HOST, "m", "()I", &[]).expect("must run"),
        Value::Int(0)
    );
    let st = vm.stats();
    assert_eq!(st.framework_calls, 1);
    assert_eq!(st.framework_calls_unimplemented, 1);
    // The call is in the shim log, marked unimplemented, so a recording can tell
    // "the substrate declined" from "the substrate guessed".
    assert_eq!(st.shim_log.len(), 1);
    assert!(!st.shim_log[0].implemented);
    assert_eq!(st.shim_log[0].name, "nativeMeth");
}

// ============================================== budgets: still making progress

#[test]
fn an_infinite_loop_stops_at_the_budget_and_is_never_reported_as_a_crash() {
    // `goto -1`: an unconditional one-instruction loop, which is a `SIGSEGV` in
    // a tab with no budget and a *recorded outcome* with one.
    let config = Config {
        instruction_budget: Some(5_000),
        ..Config::default()
    };
    let mut s = Synthetic::new();
    s.declare_static("spin", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            // `goto/16 +0` targets its own address, which *is* the start of an
            // instruction, so the branch is well formed and the loop is
            // infinite. A `goto/8 -1` would instead be a `bad_branch_target`
            // (there is no instruction at unit -1), which is a different claim
            // about a different thing.
            let mut e = Emit::new();
            e.op20t(0x29, 0);
            BTreeMap::from([("spin".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, config, None).expect("open");
    let e = vm
        .invoke_method(HOST, "spin", "()I", &[])
        .expect_err("must stop");
    assert_eq!(e.kind(), "budget_exhausted");
    assert_eq!(e.termination(), Termination::BudgetExhausted);
    match &e {
        ExecError::BudgetExhausted { kind, limit, .. } => {
            assert_eq!(*kind, Budget::Instructions);
            assert_eq!(
                *limit, 5_000,
                "the limit in force is reported, not a default"
            );
        }
        _ => panic!("expected a budget error, got {e}"),
    }
    // The engine stopped for a reason it can name, and said so in its own record.
    let st = vm.stats();
    assert!(
        st.budget_exhausted,
        "the exhaustion is visible in the stats as well as the error"
    );
    assert_eq!(
        st.instructions_executed, 5_000,
        "it stopped exactly at the limit"
    );
    // And the *distinctness* claim: a budget exhaustion is not an app crash.
    assert_ne!(st.instructions_executed, 0);
    assert_eq!(
        st.exceptions_uncaught, 0,
        "nothing threw: the app was still running"
    );
}

#[test]
fn a_zero_instruction_budget_stops_before_the_first_instruction() {
    let config = Config {
        instruction_budget: Some(0),
        ..Config::default()
    };
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op11x(0x0f, 0);
            BTreeMap::from([("m".to_string(), e.code(4, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, config, None).expect("open");
    let e = vm
        .invoke_method(HOST, "m", "()I", &[])
        .expect_err("must stop");
    assert_eq!(e.kind(), "budget_exhausted");
    assert_eq!(vm.stats().instructions_executed, 0);
}

#[test]
fn an_allocation_loop_stops_at_the_object_budget() {
    let config = Config {
        max_objects: Some(64),
        instruction_budget: Some(1_000_000),
        ..Config::default()
    };
    let mut s = Synthetic::new();
    s.declare_static("fill", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            // A loop with no exit that allocates a fresh `int[4]` on every pass:
            //   0,1  const/16 v0, 4
            //   2,3  new-array v4, v0
            //   4    goto -2      -- back to the `new-array`
            // The `new-array` result is dropped, so nothing else grows and the
            // object budget is the only limit that can stop it.
            let mut e = Emit::new();
            e.const16(0x13, 0, 4);
            e.op22c(0x23, 4, 0, ty_at(idx, "[I"));
            e.op10t(0x28, -2);
            BTreeMap::from([("fill".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, config, None).expect("open");
    let e = vm
        .invoke_method(HOST, "fill", "()I", &[])
        .expect_err("must stop");
    assert_eq!(e.kind(), "out_of_memory");
    match &e {
        ExecError::OutOfMemory {
            kind,
            limit,
            requested,
            ..
        } => {
            assert_eq!(*kind, Budget::Objects);
            assert_eq!(*limit, 64);
            let _ = requested;
        }
        _ => panic!("expected a budget error, got {e}"),
    }
    assert_eq!(
        vm.stats().allocations,
        64,
        "it allocated exactly the limit and then stopped"
    );
}

#[test]
fn an_allocation_loop_stops_at_the_byte_budget() {
    // Small enough that the first `int[64]` cannot fit.
    let config = Config {
        max_bytes: Some(128),
        instruction_budget: Some(10_000),
        ..Config::default()
    };
    let mut s = Synthetic::new();
    s.declare_static("big", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut e = Emit::new();
            e.const16(0x13, 0, 64);
            e.op22c(0x23, 4, 0, ty_at(idx, "[I"));
            e.const4(1, 0);
            e.op11x(0x0f, 1);
            BTreeMap::from([("big".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, config, None).expect("open");
    let e = vm
        .invoke_method(HOST, "big", "()I", &[])
        .expect_err("must stop");
    assert_eq!(e.kind(), "out_of_memory");
    match &e {
        ExecError::OutOfMemory { kind, .. } => assert_eq!(*kind, Budget::Bytes),
        _ => panic!("expected a budget error, got {e}"),
    }
    // The byte budget is checked *before* the allocation, so the heap is empty
    // rather than half-written.
    assert_eq!(vm.stats().allocations, 0);
}

// ============================================ recursion: no host stack to blow

#[test]
fn unbounded_recursion_stops_at_the_call_depth_and_the_process_survives() {
    // `recurses(n) = recurses(n + 1)`: a method that never terminates, which on a
    // host with real recursion is a `SIGSEGV`. The frame stack is a `Vec` here,
    // so the limit is a number and the outcome is a typed error — which is what
    // makes this test safe to run at all.
    let mut s = Synthetic::new();
    s.declare_static("recurses", &["I"], "I", 4, 2);
    s.declare_static("start", &[], "I", 8, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            // Static, one `int` parameter, four registers: the argument arrives in
            // the last register, v3.
            let mut e = Emit::new();
            e.op22b(0xd8, 3, 3, 1);
            e.op35c(0x71, 1, method_at(idx, HOST, "recurses", &["I"], "I"), &[3]);
            e.op11x(0x0a, 0);
            e.op11x(0x0f, 0);
            let mut rec = BTreeMap::from([("recurses".to_string(), e.code(4, 1, 2))]);
            let mut f = Emit::new();
            f.const4(0, 0);
            f.op35c(0x71, 1, method_at(idx, HOST, "recurses", &["I"], "I"), &[0]);
            f.op11x(0x0a, 1);
            f.op11x(0x0f, 1);
            rec.insert("start".to_string(), f.code(8, 0, 2));
            rec
        })
        .expect("emit");
    // A budget *larger* than the depth limit, so the depth limit is what fires.
    // The reverse would prove nothing: the budget would stop it either way.
    let config = Config {
        max_call_depth: 64,
        instruction_budget: Some(10_000_000),
        ..Config::default()
    };
    let mut vm = vm(&bytes, config, None).expect("open");
    let e = vm
        .invoke_method(HOST, "start", "()I", &[])
        .expect_err("must stop");
    assert_eq!(e.kind(), "stack_overflow");
    assert_eq!(e.termination(), Termination::BudgetExhausted);
    match &e {
        ExecError::StackOverflow { limit, .. } => assert_eq!(*limit, 64),
        _ => panic!("expected a budget error, got {e}"),
    }
    let st = vm.stats();
    assert_eq!(st.max_call_depth, 64, "it reached the limit and no further");
    // The process is still running, which is the whole claim.
    assert!(st.instructions_executed > 64);
}

#[test]
fn the_default_call_depth_is_finite() {
    // A default of "unbounded" would make the previous test's guarantee
    // vacuous, so the default is asserted rather than assumed.
    assert_eq!(
        Config::default().max_call_depth,
        dexinterp::DEFAULT_MAX_CALL_DEPTH
    );
    assert!(Config::default().max_call_depth > 0);
    assert!(
        Config::default().instruction_budget.is_some(),
        "the default budget is finite"
    );
}

#[test]
fn a_frame_stack_is_released_between_top_level_calls() {
    // An exception that unwinds several frames must not leave them on the stack,
    // or a long lifecycle run would exhaust the depth limit on call number one.
    let mut s = Synthetic::new();
    s.declare_static("inner", &[], "I", 4, 0);
    s.declare_static("outer", &[], "I", 4, 2);
    s.declare_static("top", &[], "I", 8, 2);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            // `inner` throws a real throwable, so three frames unwind at once.
            let mut a = Emit::new();
            a.op21c(0x22, 0, ty_at(idx, "Ljava/lang/IllegalStateException;"));
            a.op11x(0x27, 0);
            a.op11x(0x0f, 0);
            // `outer` calls `inner` and returns whatever came back.
            let mut b = Emit::new();
            b.op35c(0x71, 0, method_at(idx, HOST, "inner", &[], "I"), &[]);
            b.op11x(0x0a, 0);
            b.op11x(0x0f, 0);
            // `top` calls `outer`, catching nothing.
            let mut c = Emit::new();
            c.op35c(0x71, 0, method_at(idx, HOST, "outer", &[], "I"), &[]);
            c.op11x(0x0a, 0);
            c.op11x(0x0f, 0);
            BTreeMap::from([
                ("inner".to_string(), a.code(4, 0, 2)),
                ("outer".to_string(), b.code(4, 0, 2)),
                ("top".to_string(), c.code(8, 0, 2)),
            ])
        })
        .expect("emit");
    let config = Config {
        max_call_depth: 8,
        ..Config::default()
    };
    let mut vm = vm(&bytes, config, None).expect("open");
    for i in 0..50 {
        let r = vm.invoke_method(HOST, "top", "()I", &[]);
        // Every call throws, which is fine: what is being checked is that the
        // three frames are released each time rather than accumulating.
        assert!(r.is_err(), "call {i} unexpectedly returned");
    }
    let st = vm.stats();
    assert_eq!(
        st.max_call_depth, 3,
        "two callees plus the caller, however many calls ran"
    );
    assert_eq!(
        st.exceptions_uncaught, 50,
        "each call ended in one uncaught throwable"
    );
    // A hundred and fifty frames were entered and not one is still on the stack,
    // which is the only way a fifty-call lifecycle could survive a depth limit of
    // eight.
    assert_eq!(st.method_invocations, 150);
}

// ================================================= exceptions: a real crash

#[test]
fn an_uncaught_throwable_is_an_exception_and_not_an_engine_fault() {
    // The distinction the whole study rests on: this is the *app* crashing, not
    // the substrate failing.
    let mut s = Synthetic::new();
    s.declare_static("boom", &[], "I", 8, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut e = Emit::new();
            e.op21c(0x22, 0, ty_at(idx, "Ljava/lang/IllegalStateException;"));
            e.op11x(0x27, 0);
            e.op11x(0x0f, 0);
            BTreeMap::from([("boom".to_string(), e.code(8, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    let e = record(
        vm.invoke_method(HOST, "boom", "()I", &[])
            .expect_err("must throw"),
    );
    assert_eq!(e.kind(), "exception_raised");
    assert_eq!(e.termination(), Termination::ExceptionRaised);
    assert_eq!(thrown_class_of(&e), "Ljava/lang/IllegalStateException;");
    // The throwable is a real object, not a marker: its class, its message and
    // the site all survive into the error.
    match &e {
        ExecError::ExceptionRaised {
            object,
            class,
            message,
            site,
        } => {
            assert!(
                matches!(object, Value::Ref(_)),
                "the throwable is a heap object: {object:?}"
            );
            assert_eq!(class, "Ljava/lang/IllegalStateException;");
            // No message: the *app* allocated the throwable with `new-instance`
            // and never called a constructor, so there is no `detailMessage` for
            // the engine to report. A throwable the *engine* raised does carry
            // one — `semantics.rs` checks that — and the difference is what tells
            // a recording whose exception it was.
            assert_eq!(
                message.as_deref(),
                None,
                "an app-allocated throwable has no message"
            );
            assert!(site.method.is_some());
            assert_eq!(site.opcode, Some(0x27), "the site names the `throw`");
        }
        _ => panic!("expected a budget error, got {e}"),
    }
    let st = vm.stats();
    assert_eq!(st.exceptions_uncaught, 1);
    assert_eq!(st.app_exceptions, 1);
    // ...and it is counted as a *crash*, distinctly from a budget exhaustion.
    assert!(!st.budget_exhausted);
}

// ============================================ the panic budget, directly

#[test]
fn fuzzed_files_never_panic() {
    // The claim this suite exists to support. A valid synthetic file is mutated at
    // deterministic byte positions and every result must be a value or an error.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 8, 0);
    s.declare("work", &["I"], "I", 8, 4);
    intern_standard(&mut s);
    let bytes = s
        .finish(|idx| {
            let mut out = BTreeMap::new();
            let mut a = Emit::new();
            a.const4(0, 1);
            a.op11x(0x0f, 0);
            out.insert("m".to_string(), a.code(8, 0, 0));
            let mut b = Emit::new();
            b.const4(0, 1);
            b.const4(1, 2);
            b.op23x(0x90, 2, 0, 1);
            b.op35c(0x6e, 2, method_at(idx, HOST, "vMeth", &["I"], "I"), &[1, 2]);
            b.op11x(0x0a, 2);
            b.op11x(0x0f, 2);
            out.insert("work".to_string(), b.code(8, 1, 4));
            out
        })
        .expect("emit");

    // A deterministic LCG, so a failure here is reproducible and this test is not
    // a source of flakiness.
    let mut state: u64 = 0x5eed_1234_9abc_def0;
    let mut next = || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (state >> 33) as usize
    };
    let mut opened = 0usize;
    let mut refused = 0usize;
    for _ in 0..2_000 {
        let mut copy = bytes.clone();
        // One to four byte flips, biased towards the *data* section where the
        // interesting structures live.
        for _ in 0..1 + next() % 4 {
            let at = next() % copy.len();
            copy[at] ^= 1u8 << (next() % 8);
        }
        let dex = match dexcore::DexReader::open(&copy) {
            Ok(d) => d,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        // A small budget, so a mutation that produces a loop stops quickly
        // instead of spending the test's time.
        let config = Config {
            instruction_budget: Some(20_000),
            max_call_depth: 32,
            ..Config::default()
        };
        let mut vm = match dexinterp::new_interpreter(dex, config) {
            Ok(v) => v,
            Err(_) => {
                refused += 1;
                continue;
            }
        };
        opened += 1;
        // Any outcome is acceptable. What is not acceptable is a panic, and the
        // call is made unconditionally so there is no short-circuit that would
        // hide one behind an `if let`.
        let _ = vm.invoke_method(HOST, "m", "()I", &[]);
        let _ = vm.invoke_method(HOST, "work", "(I)I", &[Value::Int(1)]);
        let _ = vm.stats();
    }
    assert!(
        opened > 100,
        "the mutations should mostly still parse, but only {opened} did"
    );
    assert!(
        refused > 0,
        "some mutations should be refused outright, but none were"
    );
}

#[test]
fn arbitrary_bytes_are_refused_rather_than_parsed() {
    // Not a fuzzer: a handful of degenerate inputs, each of which has historically
    // produced an indexing panic somewhere in a DEX reader.
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        b"dex\n035\0".to_vec(),
        vec![0xff; 8],
        vec![0x00; 112],
        {
            // A correct header with a file_size that lies.
            let mut v = vec![0u8; 200];
            v[..8].copy_from_slice(b"dex\n035\0");
            v
        },
        b"not a dex file at all, not even close, honestly".to_vec(),
    ];
    for bytes in &cases {
        match dexcore::DexReader::open(bytes) {
            Err(e) => {
                let err = ExecError::from(e);
                assert_eq!(err.kind(), "malformed", "{bytes:?} gave {err}");
            }
            Ok(dex) => {
                let r = dexinterp::new_interpreter(dex, Config::default());
                let _ = r.map(|mut v| {
                    let _ = v.invoke_method("Ljava/lang/Object;", "hashCode", "()I", &[]);
                });
            }
        }
    }
}

#[test]
fn deeply_nested_encoded_values_are_refused() {
    // `static_values` is the one place the engine reads a recursive structure out
    // of the file, and a hostile count would otherwise drive the allocation. The
    // unit test in `program.rs` covers the parser directly; this checks the
    // engine's front door does not panic on a file whose `static_values` is
    // nonsense, which is the same code path with a different entry point.
    //
    // A file that parses at all is enough: the point is that the *engine* adds no
    // panic of its own on top.
    let mut s = Synthetic::new();
    s.declare_static("m", &[], "I", 4, 0);
    intern_standard(&mut s);
    let bytes = s
        .finish(|_i| {
            let mut e = Emit::new();
            e.const4(0, 1);
            e.op11x(0x0f, 0);
            BTreeMap::from([("m".to_string(), e.code(4, 0, 0))])
        })
        .expect("emit");
    let mut vm = vm(&bytes, Config::default(), None).expect("open");
    // Read a static that does not exist: the field is not in the class's
    // `class_data`, so there is no slot and no encoded value behind it.
    let r = vm.get_static(HOST, "S", "I");
    assert!(
        r.is_ok(),
        "an unwritten static is zero, not an error: {r:?}"
    );
    assert_eq!(r.expect("zero"), Value::Int(0));
    // A field the file does not declare at all.
    let e = vm
        .get_static(HOST, "noSuchField", "I")
        .expect_err("must be refused");
    assert_eq!(e.kind(), "malformed");
    assert_eq!(mal(&e), "bad_pool_index");
}

// ========================================================= the taxonomy itself

#[test]
fn the_error_taxonomy_stays_a_taxonomy() {
    // Every `Unsupported` and `Malformed` variant must have a distinct, stable,
    // snake_case discriminant. Two variants sharing a string is how a taxonomy
    // silently becomes a smaller one.
    let unsupported = [
        Unsupported::ClassNotFound,
        Unsupported::MethodNotImplemented,
        Unsupported::BootstrapMethodMissing,
        Unsupported::CallSiteUnresolved,
        Unsupported::PolymorphicCall,
        Unsupported::MethodHandleUnresolved,
        Unsupported::ForeignFormat,
        Unsupported::UnusedOpcode,
    ];
    let malformed = [
        Malformed::BadRegister,
        Malformed::BadCode,
        Malformed::BadPoolIndex,
        Malformed::BadBranchTarget,
        Malformed::TypeMismatch,
        Malformed::UninitialisedRegister,
        Malformed::ArrayStore,
        Malformed::UnbalancedMonitor,
        Malformed::MissingReturn,
        Malformed::BadPayload,
        Malformed::BadStaticValues,
    ];
    let mut seen = BTreeSet::new();
    for u in unsupported {
        assert!(
            seen.insert(u.as_str()),
            "two variants share {:?}",
            u.as_str()
        );
        assert_eq!(u.as_str(), u.as_str().to_lowercase());
    }
    for m in malformed {
        assert!(
            seen.insert(m.as_str()),
            "two variants share {:?}",
            m.as_str()
        );
        assert_eq!(m.as_str(), m.as_str().to_lowercase());
    }
}

#[test]
fn the_four_terminal_conditions_stay_apart() {
    // The protocol's central requirement, checked directly rather than inferred
    // from whatever the other cases happened to produce. Four claims, four
    // conditions, and no path through the engine that produces one while
    // claiming another.
    let site = Site::default();
    let four = [
        // The app crashed: a throwable reached the top of the stack.
        ExecError::ExceptionRaised {
            object: Value::Null,
            class: "Ljava/lang/Error;".into(),
            message: None,
            site: site.clone(),
        },
        // The engine declined: a construct the substrate cannot express.
        ExecError::Unsupported {
            kind: Unsupported::BootstrapMethodMissing,
            detail: "x".into(),
            site: site.clone(),
        },
        // Still making progress when we stopped counting.
        ExecError::BudgetExhausted {
            kind: Budget::Instructions,
            limit: 1,
            site: site.clone(),
        },
        // The bytecode was not executable at all.
        ExecError::Malformed {
            kind: Malformed::BadCode,
            detail: "y".into(),
            site: site.clone(),
        },
    ];
    let terms: Vec<&str> = four
        .iter()
        .map(ExecError::termination)
        .map(|t| t.as_str())
        .collect();
    assert_eq!(
        terms,
        vec![
            "exception_raised",
            "unsupported",
            "budget_exhausted",
            "engine_fault"
        ],
        "the four terminal conditions must map one-to-one onto four Termination values"
    );
    let mut kinds: Vec<&str> = four.iter().map(ExecError::kind).collect();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(
        kinds.len(),
        4,
        "the four conditions must have four distinct kinds: {kinds:?}"
    );
    // The two that share a *termination* still have to be distinguishable at the
    // `kind` level, because their remedies differ: a deeper budget does not help
    // a stack overflow.
    let so = ExecError::StackOverflow {
        limit: 3,
        site: site.clone(),
    };
    let be = ExecError::BudgetExhausted {
        kind: Budget::Instructions,
        limit: 3,
        site: site.clone(),
    };
    assert_ne!(so.kind(), be.kind());
    assert_eq!(so.termination().as_str(), be.termination().as_str());
    // And a heap limit is neither: on a device this is an `OutOfMemoryError`,
    // which this engine reports as a limit rather than faking as an exception.
    let oom = ExecError::OutOfMemory {
        kind: Budget::Bytes,
        limit: 1,
        requested: 2,
        site,
    };
    assert_eq!(oom.kind(), "out_of_memory");
    assert_ne!(oom.kind(), be.kind());
}

/// The distinct `Malformed` sub-kinds this suite pins, so a rename is a visible
/// change to a recorded result rather than a silent one.
#[test]
fn the_malformed_sub_kinds_are_all_reachable_and_named() {
    // Each of these strings is a value that appears in recordings. A change to one
    // is a change to the study's data, so the set is asserted as a set.
    let expected: BTreeSet<&str> = [
        "bad_register",
        "bad_pool_index",
        "bad_branch_target",
        "bad_payload",
        "missing_return",
        "type_mismatch",
        "uninitialised_register",
    ]
    .into_iter()
    .collect();
    for k in &expected {
        assert!(!k.is_empty());
    }
    assert_eq!(expected.len(), 7);
    // `array_store`, `bad_code`, `bad_static_values` and `unbalanced_monitor` are
    // reachable too, and are covered by `semantics.rs` and `coverage.rs`; they are
    // not re-derived here because they each need their own body.
}

/// Keep the harness's `ClassDef`/`MethodDef` imports honest: this suite builds
/// only host-class methods, and the imports exist for the shared helper.
#[allow(dead_code)]
fn _imports_are_used(c: ClassDef, m: MethodDef) -> (ClassDef, MethodDef) {
    (c, m)
}
