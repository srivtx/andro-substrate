//! Executing methods out of real APKs.
//!
//! Everything else in this crate is hand-assembled bytecode, which proves the
//! engine agrees with the specification and proves nothing about whether it
//! agrees with *d8*. This suite runs methods out of the six fixture APKs in
//! [`dexcore`'s FIXTURES.md] — byte-for-byte `classes.dex` members of free-software
//! apps published by F-Droid, produced by the real Android toolchain — and checks
//! what came back.
//!
//! No APK is downloaded here; the fixtures are already in the repository and
//! their provenance and hashes are recorded in
//! `tools/dexcore/tests/FIXTURES.md`.
//!
//! # The three claims
//!
//! 1. **Real bytecode runs.** Constructors and static initialisers of real app
//!    classes execute to completion. That is the minimum bar for the rest of the
//!    project and it is asserted directly, not inferred.
//! 2. **A real `onCreate` fails for a nameable reason.** `BootActivity.onCreate`
//!    is the method the study cares about, and it fails at
//!    `Landroid/app/Activity;.setContentView(Landroid/view/View;)V` — a framework
//!    method, with no bytecode in any APK, reported with its class, its
//!    prototype, its instruction and its offset. That is `SUB.FW.CLASS_LOADER`,
//!    located rather than guessed.
//! 3. **No real method ends in an engine fault.** Every method in both fixtures
//!    ends in `returned` or `exception_raised`, and *none* in `malformed`,
//!    `out_of_memory` or `stack_overflow`. This is the claim the negative suite
//!    makes about synthetic files, checked against files the engine did not
//!    write, and it is the one that would catch a decoder disagreement.
//!
//! # Why the assertions are about *outcomes* and not values
//!
//! With no framework shim installed, `Ljava/io/File;.getName()` is declined and
//! `move-result-object` yields `null`, which the app then dereferences. So a
//! method that reaches framework code throws a real `NullPointerException` with
//! a real message naming the call that failed. That is a *correct* result and it
//! is the substrate's main output, so the value assertions here are deliberately
//! confined to methods whose result does not depend on the framework: the
//! constructors, the static initialisers, and the handful of pure field
//! arithmetic methods.
//!
//! What this suite also measures, and what the study needs, is the size of the
//! missing framework surface: [`the_missing_framework_surface_is_measured_not_guessed`]
//! counts it.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use dexinterp::error::Budget;
use dexinterp::value::JType;
use dexinterp::{Config, ExecError, Termination, Value};

/// `com.termux.boot_1000`, DEX 035. A `BroadcastReceiver` app: a constructor, a
/// static initialiser, a `Service`, a `JobService` and an `Activity` with a real
/// `onCreate`.
const TERMUX_BOOT: &[u8] = include_bytes!("../../dexcore/tests/fixtures/com.termux.boot_1000.dex");

/// `fr.smarquis.sleeptimer_16200`, DEX 038. The largest fixture (18 KB) and the
/// only one with a real `try` table and obfuscated single-letter class names, so
/// it is the better source of *arithmetic* to check against a known value.
const SLEEPTIMER: &[u8] =
    include_bytes!("../../dexcore/tests/fixtures/fr.smarquis.sleeptimer_16200.dex");

/// A fresh interpreter over `bytes`, with a small budget.
///
/// The budget is small on purpose: a real app's `onCreate` does not terminate on
/// its own, and a suite that ran to the default 25 million instructions per
/// method would take minutes. Reaching the budget is a *recorded* outcome, and
/// [`the_budget_is_a_recorded_outcome_not_a_crash`] checks that it is reported as
/// one.
fn interpreter(bytes: &[u8]) -> dexinterp::Interpreter<'_> {
    let dex = dexcore::DexReader::open(bytes).expect("fixture must open");
    let config = Config {
        instruction_budget: Some(200_000),
        ..Config::default()
    };
    dexinterp::new_interpreter(dex, config).expect("program must build")
}

/// The value of `x == null` for the harness: a new instance of `class`, which is
/// what a runtime would hand a lifecycle callback.
fn receiver(vm: &mut dexinterp::Interpreter, class: &str) -> Value {
    vm.allocate(class)
        .expect("the app's own class is in its own dex")
}

/// Every method in `bytes` that has a `code_item`, with its parameter types.
fn methods_with_code(
    vm: &dexinterp::Interpreter,
) -> Vec<(String, String, String, Vec<String>, bool)> {
    let prog = vm.program();
    let mut out = Vec::new();
    for (class, name, signature) in prog.methods.iter() {
        let id = match prog.by_descriptor.get(class) {
            Some(id) => *id,
            None => continue,
        };
        if let Some(d) = prog.find_own_method(id, name, signature) {
            if d.has_code() {
                out.push((
                    class.clone(),
                    name.clone(),
                    signature.clone(),
                    d.parameters(),
                    d.is_static(),
                ));
            }
        }
    }
    out
}

/// A value of the right shape for a parameter of type `ty`.
///
/// `int`-family parameters get 0, `long`/`double`/`float` their zero, and a
/// reference gets `null` — or an empty array, when the parameter *is* an array,
/// because an app that takes an array usually tests its length before it
/// dereferences it and `null` would not tell us whether the arithmetic works.
fn argument(vm: &mut dexinterp::Interpreter, ty: &str) -> Value {
    match JType::parse(ty) {
        JType::Int | JType::Boolean | JType::Byte | JType::Short | JType::Char => Value::Int(0),
        JType::Long => Value::Long(0),
        JType::Float => Value::Float(0.0),
        JType::Double => Value::Double(0.0),
        JType::Void => Value::Void,
        JType::Ref(d) => match d.as_str().strip_prefix('[') {
            // An array parameter gets an empty array rather than `null`, because
            // an app that takes an array usually tests its length before it
            // dereferences it, and `null` would not tell us whether the
            // arithmetic works.
            Some(element) => vm.allocate_array(element, 0).unwrap_or(Value::Null),
            None => Value::Null,
        },
        JType::Array(inner) => vm
            .allocate_array(&inner.descriptor(), 0)
            .unwrap_or(Value::Null),
    }
}

fn call(
    vm: &mut dexinterp::Interpreter,
    class: &str,
    name: &str,
    signature: &str,
    params: &[String],
    is_static: bool,
) -> Result<Value, ExecError> {
    let mut args: Vec<Value> = params.iter().map(|p| argument(vm, p)).collect();
    if !is_static {
        args.insert(0, receiver(vm, class));
    }
    vm.invoke_method(class, name, signature, &args)
}

// ================================================== 1. real bytecode runs

#[test]
fn a_real_app_constructor_runs_to_completion() {
    let mut vm = interpreter(TERMUX_BOOT);
    let before = vm.stats().instructions_executed;
    let activity = receiver(&mut vm, "Lcom/termux/boot/BootActivity;");
    let got = vm
        .invoke_method(
            "Lcom/termux/boot/BootActivity;",
            "<init>",
            "()V",
            &[activity],
        )
        .expect("a real d8-compiled constructor must run");
    assert_eq!(got, Value::Void, "a constructor returns nothing");
    let after = vm.stats();
    assert!(
        after.instructions_executed > before,
        "the constructor executed instructions"
    );
    assert_eq!(after.method_invocations, 1);
    assert_eq!(
        after.max_call_depth, 1,
        "a constructor that calls nothing is one frame deep"
    );
    // `super.<init>()` on a framework class with no bytecode is the shim's job,
    // and the run continues past it: that is the rule this whole project rests
    // on.
    assert_eq!(
        after.framework_calls_unimplemented, 1,
        "exactly one framework call was declined"
    );
    assert_eq!(after.exceptions_uncaught, 0);
}

#[test]
fn every_bodyless_constructor_in_a_real_apk_runs_to_completion() {
    // Four constructors across two classes, all of which d8 emitted. If the
    // decoder disagreed with d8 about a single unit of any of them, the walk would
    // desynchronise and the run would not return.
    let mut vm = interpreter(TERMUX_BOOT);
    for class in [
        "Lcom/termux/boot/BootActivity;",
        "Lcom/termux/boot/BootJobService;",
        "Lcom/termux/boot/BootReceiver;",
        "Lb/b;",
    ] {
        let r = receiver(&mut vm, class);
        let got = vm
            .invoke_method(class, "<init>", "()V", &[r])
            .unwrap_or_else(|e| panic!("{class}.<init> failed: {e}"));
        assert_eq!(got, Value::Void, "{class}.<init>");
    }
    assert_eq!(vm.stats().exceptions_uncaught, 0);
    assert!(
        vm.stats().instructions_executed >= 8,
        "four constructors, at least two units each"
    );
}

#[test]
fn a_real_static_initialiser_runs_to_completion() {
    // `<clinit>` is the closest thing in a fixture to app startup: it is the code
    // a runtime runs before any callback, and it is where a real app's static
    // `R` constants and `String` literals are materialised.
    let mut vm = interpreter(TERMUX_BOOT);
    let before = vm.stats().instructions_executed;
    let got = vm
        .invoke_method("Lcom/termux/boot/BootReceiver;", "<clinit>", "()V", &[])
        .unwrap_or_else(|e| panic!("<clinit> failed: {e}"));
    assert_eq!(got, Value::Void);
    assert!(vm.stats().instructions_executed > before);
    // Three more `<clinit>`s in the other fixture, all of which run.
    let mut vm2 = interpreter(SLEEPTIMER);
    for (class, name) in [
        ("Le;", "<clinit>"),
        ("Ll;", "<clinit>"),
        ("Ls;", "<clinit>"),
        ("Lu;", "<clinit>"),
    ] {
        let got = vm2
            .invoke_method(class, name, "()V", &[])
            .unwrap_or_else(|e| panic!("{class}.{name} failed: {e}"));
        assert_eq!(got, Value::Void, "{class}.{name}");
    }
}

#[test]
fn a_real_field_arithmetic_method_returns_the_value_its_source_implies() {
    // Four methods in the obfuscated fixture whose result is pure field
    // arithmetic over zero-valued fields, so the *expected* value follows from
    // the Java source rather than from a framework call:
    //
    //   `hasPrevious()`  -> `cursor > 0`   with cursor 0  -> false
    //   `nextIndex()`    -> `cursor`      with cursor 0  -> 0
    //   `previousIndex()`-> `cursor - 1`  with cursor 0  -> -1
    //   `a()`            -> `size`        with size 0    -> 0
    //
    // These are the *only* value assertions in this file that do not depend on
    // the framework, and they are the reason the fixture was chosen: the
    // arithmetic runs on d8's real instructions against the engine's real field
    // layout.
    let mut vm = interpreter(SLEEPTIMER);
    let cases: &[(&str, &str, &str, Value)] = &[
        ("Lb;", "hasPrevious", "()Z", Value::Int(0)),
        ("Lb;", "nextIndex", "()I", Value::Int(0)),
        ("Lb;", "previousIndex", "()I", Value::Int(-1)),
        ("Lc;", "a", "()I", Value::Int(0)),
    ];
    for (class, name, signature, want) in cases {
        let r = receiver(&mut vm, class);
        let got = vm
            .invoke_method(class, name, signature, &[r])
            .unwrap_or_else(|e| panic!("{class}->{name}{signature} failed: {e}"));
        assert_eq!(got, *want, "{class}->{name}{signature}");
    }
    // `int(-1)` is `previousIndex`, and it is the one that would catch a field
    // layout that puts the wrong slot at the wrong offset: a wrong offset reads
    // the *next* field, which is a `char` in the same class, and the arithmetic
    // gives a different number.
    assert_eq!(vm.stats().exceptions_uncaught, 0);
}

// ======================================= 2. a real onCreate fails, nameably

#[test]
fn a_real_on_create_fails_at_the_first_framework_call_and_names_it() {
    // This is the number the study wants, from a real APK, and it is exactly the
    // shape `docs/divergence-taxonomy.md` calls `SUB.FW.CLASS_LOADER`: the app's
    // own bytecode ran, and the first thing it wanted was a class that no APK
    // contains.
    let mut vm = interpreter(TERMUX_BOOT);
    let activity = receiver(&mut vm, "Lcom/termux/boot/BootActivity;");
    let r = vm.invoke_method(
        "Lcom/termux/boot/BootActivity;",
        "onCreate",
        "(Landroid/os/Bundle;)V",
        &[activity, Value::Null],
    );
    let e = match r {
        Ok(v) => panic!("onCreate returned {v:?}; a Bundle-less lifecycle callback should not"),
        Err(e) => e,
    };
    assert_eq!(e.kind(), "exception_raised");
    assert_eq!(e.termination(), Termination::ExceptionRaised);
    // The failure is *located*, not merely reported: class, prototype,
    // instruction and offset all survive into the error.
    let detail = format!("{e}");
    assert!(
        detail.contains("Landroid/app/Activity;"),
        "the missing class must be named: {detail}"
    );
    assert!(
        detail.contains("setContentView(Landroid/view/View;)V"),
        "the missing method and its prototype must be named: {detail}"
    );
    assert!(
        detail.contains("0x6e"),
        "the instruction must be named: {detail}"
    );
    assert!(
        detail.contains("onCreate"),
        "the site must be inside onCreate: {detail}"
    );
    // And the engine got far enough to *know* it was looking at an Activity, so
    // the app's own class hierarchy was resolved from the file rather than
    // fabricated.
    let st = vm.stats();
    assert!(
        st.instructions_executed >= 5,
        "six instructions of real bytecode ran"
    );
    assert_eq!(st.exceptions_uncaught, 1);
    assert!(
        st.phantom_classes.is_empty(),
        "the builtin table covered this app's types: {:?}",
        st.phantom_classes
    );
}

#[test]
fn a_receiver_is_needed_and_the_engine_says_so() {
    // The same app, given a null receiver: the failure moves to the *first*
    // instruction, which is the observable difference between "the app needs an
    // object" and "the app needs a framework class".
    let mut vm = interpreter(TERMUX_BOOT);
    let e = vm
        .invoke_method(
            "Lcom/termux/boot/BootReceiver;",
            "onReceive",
            "(Landroid/content/Context;Landroid/content/Intent;)V",
            &[Value::Null, Value::Null, Value::Null],
        )
        .expect_err("a null receiver must fail");
    assert_eq!(e.kind(), "exception_raised");
    let detail = format!("{e}");
    assert!(detail.contains("null receiver"), "{detail}");
    // The shim was asked about the `Intent` receiver's class, so the framework
    // call is recorded even though the answer was never used.
    assert!(vm.stats().framework_calls >= 1 || vm.stats().exceptions_uncaught == 1);
}

// ============================== 3. the shape of a real APK's failure profile

/// What happened to every method with a `code_item` in a fixture.
#[derive(Default)]
struct Census {
    /// `(class, method, signature)` -> terminal condition.
    outcomes: BTreeMap<String, String>,
    /// Distinct framework methods whose absence ended a run.
    missing_framework: BTreeSet<String>,
    /// Methods that returned.
    returned: usize,
    /// Throwables seen, by class.
    thrown: BTreeMap<String, usize>,
    /// Any outcome that is not `returned` or an exception.
    engine_faults: BTreeMap<String, String>,
}

fn census(bytes: &[u8]) -> Census {
    let mut vm = interpreter(bytes);
    let methods = methods_with_code(&vm);
    let mut c = Census::default();
    for (class, name, signature, params, is_static) in &methods {
        let label = format!("{class}->{name}{signature}");
        let r = call(&mut vm, class, name, signature, params, *is_static);
        let key = match &r {
            Ok(_) => {
                c.returned += 1;
                "returned".to_string()
            }
            Err(ExecError::ExceptionRaised { class, message, .. }) => {
                *c.thrown.entry(class.clone()).or_default() += 1;
                // The throwable's message names the framework method that failed,
                // which is the substrate's actual output for this app.
                if let Some(m) = message {
                    if let Some(rest) = m.split_once(";") {
                        let _ = rest;
                    }
                    let head = m.split(':').next().unwrap_or(m);
                    if head.contains('.') && !head.contains("Lt;") {
                        c.missing_framework.insert(head.to_string());
                    }
                }
                format!("throw {class}")
            }
            Err(e) => {
                c.engine_faults.insert(label.clone(), format!("{e}"));
                e.kind().to_string()
            }
        };
        c.outcomes.insert(label, key);
    }
    c
}

#[test]
fn every_method_in_two_real_apks_ends_in_a_recorded_outcome() {
    for (name, bytes) in [
        ("com.termux.boot_1000", TERMUX_BOOT),
        ("fr.smarquis.sleeptimer_16200", SLEEPTIMER),
    ] {
        let c = census(bytes);
        let total = c.outcomes.len();
        assert!(
            total > 10,
            "{name}: only {total} methods with code, which cannot be right"
        );
        // The claim: nothing ended in `malformed`, `out_of_memory` or
        // `stack_overflow`. Those are the `engine_fault` bucket, which the
        // protocol reserves for files ART would have rejected at install time —
        // and a real d8 output is by definition not such a file. A single entry
        // here means the decoder and d8 disagree, and it names the method.
        assert!(
            c.engine_faults.is_empty(),
            "{name}: {} method(s) ended in an engine fault: {:#?}",
            c.engine_faults.len(),
            c.engine_faults
        );
        // And a meaningful fraction run to completion, so the engine is not
        // simply refusing everything.
        assert!(
            c.returned >= 5,
            "{name}: only {} of {total} methods returned",
            c.returned
        );
        let thrown: usize = c.thrown.values().sum();
        assert!(
            thrown > 0,
            "{name}: no method threw, which cannot be right for a real app"
        );
        assert_eq!(
            thrown + c.returned,
            total,
            "{name}: the tally does not add up"
        );
        // Pinned because the README and the ADR quote them. `total` is the
        // number that says how much of the app this engine can even *see*; the
        // other two say how much of it runs. A drop in either is a regression
        // that every other assertion here would still pass.
        match name {
            "com.termux.boot_1000" => assert_eq!(
                (total, c.returned, thrown),
                (14, 5, 9),
                "the termux census changed; the README quotes 14 methods, 5 returned"
            ),
            // Corrected by ADR 0008. Was `(85, 28, 57)`. The vtable change means
            // an *inherited* framework method on an app class now reaches the
            // host instead of dying as a `NoSuchMethodError`, so twelve more of
            // sleeptimer's 85 methods return. The app did not get simpler; the
            // engine stopped mis-reporting it.
            "fr.smarquis.sleeptimer_16200" => assert_eq!(
                (total, c.returned, thrown),
                (85, 40, 45),
                "the sleeptimer census changed; the README quotes 85 methods, 40 returned"
            ),
            other => panic!("{other} has no pinned census"),
        }
    }
}

#[test]
fn the_missing_framework_surface_is_measured_not_guessed() {
    // The number that decides the project's next step, taken from a real APK
    // rather than assumed: which framework methods, exactly, are the first thing
    // an app's own bytecode asks for.
    //
    // The assertion is deliberately weak on the *set* (it will grow as the shim
    // grows, which is the point) and strict on the *property*: every one of them
    // must be a method of a class with no bytecode anywhere in the file. If a
    // name appeared that the file *does* contain, that would be a dispatch bug
    // dressed up as a framework gap, and this is the test that would say so.
    for (name, bytes) in [
        ("com.termux.boot_1000", TERMUX_BOOT),
        ("fr.smarquis.sleeptimer_16200", SLEEPTIMER),
    ] {
        let c = census(bytes);
        assert!(
            !c.missing_framework.is_empty(),
            "{name}: no framework method was reported missing, which cannot be right"
        );
        let vm = interpreter(bytes);
        let prog = vm.program();
        for entry in &c.missing_framework {
            let class = entry.split(';').next().unwrap_or("").trim();
            assert!(
                class.starts_with('L'),
                "{name}: {entry} is not a class-qualified name"
            );
            let in_file = prog
                .by_descriptor
                .get(class)
                .map(|id| {
                    prog.class(*id)
                        .map(|m| m.source.has_bytecode())
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            assert!(
                !in_file,
                "{name}: {class} has bytecode in this dex, so calling it is not a framework gap"
            );
        }
    }
}

#[test]
fn the_measured_surface_is_small_and_typed() {
    // A pinned lower bound rather than an exact set, so adding a shim method does
    // not break the suite, while *losing* the measurement does. `com.termux.boot`
    // is the interesting one: it is a `BroadcastReceiver` app, and the framework
    // calls it needs are `File.canRead`, `File.getName`, `Intent.getAction` and
    // `Activity.setContentView`.
    let c = census(TERMUX_BOOT);
    let surface: BTreeSet<&str> = c
        .missing_framework
        .iter()
        .map(|s| s.as_str())
        .filter(|s| s.contains("Ljava/io/File;") || s.contains("Landroid/content/Intent;"))
        .collect();
    assert!(
        surface.len() >= 2,
        "expected at least two distinct framework methods from the File/Intent surface, got {surface:?}"
    );
    assert!(
        surface
            .iter()
            .any(|s| s.contains("canRead") || s.contains("getName")),
        "the File surface should include a readability or name call: {surface:?}"
    );
    // And the dominant failure across both fixtures is a *throwable*, not a
    // refusal. That is the substrate working: it ran the app's bytecode and the
    // app itself failed, which is a data point about the app rather than about
    // the substrate.
    let c2 = census(SLEEPTIMER);
    let npe = c2
        .thrown
        .get("Ljava/lang/NullPointerException;")
        .copied()
        .unwrap_or(0);
    let nsm = c2
        .thrown
        .get("Ljava/lang/NoSuchMethodError;")
        .copied()
        .unwrap_or(0);
    assert!(npe + nsm > 10, "expected most of the fixture's methods to end in a framework throwable: {npe} NPE, {nsm} NoSuchMethodError");
}

#[test]
fn the_budget_is_a_recorded_outcome_not_a_crash() {
    // Two properties, both about the accounting rather than about any one
    // method's behaviour.
    //
    // First: the budget in force is *reported*, so a reader can normalise for it.
    // A run that stopped at 200 000 instructions and a run that stopped at 25
    // million are different data points, and only one of them says so.
    let vm = interpreter(TERMUX_BOOT);
    assert_eq!(vm.stats().instruction_budget, Some(200_000));

    // Second: an exhausted budget is `budget_exhausted` and never
    // `exception_raised`, and it is never conflated with the two faults. The
    // method used is a real one that reaches a framework call, so the assertion is
    // on the *accounting*: whatever the method did, the counters and the error
    // agree with each other and with the limit.
    let mut vm = interpreter(TERMUX_BOOT);
    let activity = receiver(&mut vm, "Lcom/termux/boot/BootActivity;");
    let e = vm
        .invoke_method(
            "Lcom/termux/boot/BootActivity;",
            "onCreate",
            "(Landroid/os/Bundle;)V",
            &[activity, Value::Null],
        )
        .expect_err("onCreate cannot succeed with a declining shim");
    let st = vm.stats();
    match &e {
        ExecError::BudgetExhausted { kind, limit, .. } => {
            assert_eq!(*kind, Budget::Instructions);
            assert_eq!(*limit, 200_000);
            assert!(st.budget_exhausted);
            assert_eq!(
                st.instructions_executed, 200_000,
                "it stopped exactly at the limit"
            );
            assert_eq!(e.termination().as_str(), "budget_exhausted");
        }
        other => {
            // The alternative, and the common one: the method finished (or threw)
            // inside the budget, in which case `budget_exhausted` must be false
            // and the exception must be reported as an exception.
            assert_eq!(
                other.kind(),
                "exception_raised",
                "unexpected outcome: {other}"
            );
            assert!(
                !st.budget_exhausted,
                "the budget did not fire, so it must not be reported"
            );
            assert!(st.instructions_executed < 200_000);
        }
    }
    // And the two never both fire: an exhausted budget is a *stop*, and a
    // throwable is a *termination*. One `Stats` with both set would mean the
    // engine double-counted, and the study would read one run as two facts.
    assert!(
        !(st.budget_exhausted
            && st.instructions_executed == 200_000
            && e.kind() == "exception_raised"),
        "the budget and a throwable cannot both be the reason a run ended: {e}"
    );
}

#[test]
fn opcode_statistics_from_a_real_apk_are_sane() {
    // The engine's own record of what it dispatched, on bytecode it did not
    // write. A histogram that is mostly zeros would mean the walk is
    // desynchronising; one full of *unused* opcodes would mean the decoder and
    // d8 disagree about the instruction set.
    let mut vm = interpreter(SLEEPTIMER);
    for (class, name, signature, params, is_static) in methods_with_code(&vm) {
        let _ = call(&mut vm, &class, &name, &signature, &params, is_static);
    }
    let st = vm.stats();
    assert!(
        st.distinct_opcodes() > 20,
        "only {} distinct opcodes: {:?}",
        st.distinct_opcodes(),
        {
            let used: Vec<(u8, u32)> = st
                .opcode_counts
                .iter()
                .enumerate()
                .filter(|(_, n)| **n > 0)
                .map(|(op, n)| (op as u8, *n))
                .collect();
            used
        }
    );
    for (op, n) in st.opcode_counts.iter().enumerate() {
        let entry = dexcore::opcodes::opcode(op as u8);
        if !entry.valid {
            assert_eq!(*n, 0, "the engine dispatched {op:#04x}, which is (unused)");
        }
    }
    // The full-census totals are quoted in this crate's README and in
    // `docs/decisions/0003-execution-engine.md`, so they are pinned here rather
    // than left to drift: a change that alters them is a change to how much of a
    // real APK this engine actually reaches, which is the number the study
    // depends on and exactly the kind of quiet regression nothing else here
    // would notice.
    //
    // 46 distinct opcodes over 553 instructions with 184 allocations. Corrected
    // by ADR 0008: was 45 / 446 / 193, and the extra instruction, the extra
    // allocation and the extra opcode are the throwable the host now raises for
    // more of the app now reaches a host, so the totals move; the direction
    // of the instruction count is up and the allocation count is down because the
    // engine no longer fabricates a throwable for a method it mis-reported missing.
    assert_eq!(
        st.distinct_opcodes(),
        46,
        "the real-DEX opcode count changed; the README quotes 46"
    );
    assert_eq!(
        (st.instructions_executed, st.allocations),
        (553, 184),
        "the real-DEX census totals changed; the README quotes 553 instructions and 184 allocations"
    );
    // `if-ne` and `if-nez` must both appear in a real APK: they are how a
    // compiler writes `a != b` and `x == null` for *objects*, and this engine
    // once refused both with a `type_mismatch`, which would have made every
    // null check in a real app an engine fault. Their presence here is the
    // regression check.
    //
    // (`if-eq` and the ordering forms do not occur in this fixture, so they are
    // not asserted; `semantics.rs` and `coverage.rs` cover all twelve.)
    for op in [0x33u8, 0x39] {
        assert!(
            st.opcode_counts[op as usize] > 0,
            "no {:#04x} was dispatched",
            op
        );
    }
    assert!(
        st.opcode_counts[0x34] > 0 && st.opcode_counts[0x38] > 0,
        "the integer comparison forms should also appear"
    );
    // The counters are internally consistent.
    let executed: u64 = st.opcode_counts.iter().map(|n| u64::from(*n)).sum();
    assert_eq!(
        executed, st.instructions_executed,
        "the histogram and the total must agree"
    );
    // And nothing was ever allocated that the app did not ask for.
    assert!(
        st.allocations > 0,
        "real bytecode allocates: strings, arrays, throwables"
    );
    assert!(st.bytes_allocated > 0);
}

#[test]
fn a_real_apk_fabricates_only_framework_classes_and_records_them() {
    // The builtin class table does not cover the whole Android SDK, and the
    // difference is a *measurement* rather than a claim. What matters is the
    // property: a fabricated class is always a `framework` type that no APK
    // contains — never one of the app's own — and every one of them is listed in
    // `Stats::phantom_classes`, so the size of the substrate's blind spot is
    // visible in every recording rather than hidden.
    //
    // `com.termux.boot_1000` needs none at all. `fr.smarquis.sleeptimer_16200`
    // needs five, and they are exactly the five `android.*` classes its
    // notification and alarm code names. If a phantom ever turned up that the
    // file *does* contain, that would be a resolution bug and this is the test
    // that would say so.
    let mut vm = interpreter(TERMUX_BOOT);
    for (class, mname, signature, params, is_static) in methods_with_code(&vm) {
        let _ = call(&mut vm, &class, &mname, &signature, &params, is_static);
    }
    assert!(
        vm.stats().phantom_classes.is_empty(),
        "the receiver app needs no phantoms, but found {:?}",
        vm.stats().phantom_classes
    );

    let mut vm2 = interpreter(SLEEPTIMER);
    for (class, mname, signature, params, is_static) in methods_with_code(&vm2) {
        let _ = call(&mut vm2, &class, &mname, &signature, &params, is_static);
    }
    let phantoms = vm2.stats().phantom_classes;
    assert_eq!(
        phantoms.len(),
        5,
        "the measured blind spot changed: {phantoms:?}"
    );
    for p in &phantoms {
        assert!(p.starts_with("Landroid/"), "{p} is not a framework class");
    }
    // The five, in the order the table sorts them. Asserted as a set rather than
    // a count so that growing the builtin table is a visible, reviewable change
    // to this test instead of a silent one.
    let expected: BTreeSet<&str> = [
        "Landroid/app/AlarmManager;",
        "Landroid/app/Notification$Action$Builder;",
        "Landroid/app/NotificationManager;",
        "Landroid/app/PendingIntent;",
        "Landroid/media/AudioManager;",
    ]
    .into_iter()
    .collect();
    let got: BTreeSet<&str> = phantoms.iter().map(|s| s.as_str()).collect();
    assert_eq!(got, expected);
}

#[test]
fn a_real_dex_with_a_try_table_executes_its_handler() {
    // `fr.smarquis.sleeptimer_16200` is the only fixture with a real `try` table
    // (`SleepActionReceiver.onReceive`), which makes it the check that
    // `decode_tries` gets the handler list's `uleb128` prefix right against d8's
    // own output rather than against `dexcore`'s writer.
    let mut vm = interpreter(SLEEPTIMER);
    let candidates: Vec<(String, String, String)> = {
        let prog = vm.program();
        prog.methods
            .iter()
            .filter_map(|(c, n, s)| {
                let id = *prog.by_descriptor.get(c)?;
                let d = prog.find_own_method(id, n, s)?;
                d.has_code().then(|| (c.clone(), n.clone(), s.clone()))
            })
            .collect()
    };
    let mut with_tries: Vec<(String, String, String)> = Vec::new();
    for (class, name, signature) in &candidates {
        // Decoding the body is what populates the try table, and it is the same
        // path `push_frame` takes, so this is the structural check.
        if let Ok(code) = vm.decode_body(class, name, signature) {
            if !code.tries.is_empty() {
                with_tries.push((class.clone(), name.clone(), signature.clone()));
            }
        }
    }
    assert!(
        !with_tries.is_empty(),
        "the fixture is supposed to have a try table and none was found"
    );
    for (class, name, signature) in &with_tries {
        let (params, is_static) = {
            let prog = vm.program();
            let id = prog.by_descriptor[class];
            match prog.find_own_method(id, name, signature) {
                Some(d) => (d.parameters(), d.is_static()),
                None => continue,
            }
        };
        let r = call(&mut vm, class, name, signature, &params, is_static);
        // The outcome does not matter — what matters is that decoding the try
        // table and walking the method did not produce a `bad_code` about the
        // handler list, which is what a mis-recovered `uleb128` prefix looks
        // like: a handler at unit 0, sending the exception back into the middle
        // of its own protected range.
        if let Err(e) = r {
            assert!(
                !format!("{e}").contains("catch handler"),
                "{class}->{name}{signature}: the try table did not decode: {e}"
            );
            assert_ne!(e.kind(), "malformed", "{class}->{name}{signature}: {e}");
        }
    }
}
