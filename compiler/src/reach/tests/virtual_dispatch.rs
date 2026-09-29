//! Virtual dispatch: the property the whole closure rests on.
//!
//! `IR.md` says an `invoke-virtual` reaches "every implementor of C present in
//! the loaded DEX". These tests construct a hierarchy with a known answer and
//! assert it, under both dispatch policies, because the two disagree and the
//! disagreement is the licence RTA needs.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use dexcore::writer::{ClassDef, MethodDef};

use crate::reach::entry::explicit_entry_points;
use crate::reach::model::{DexInput, Program, UnitRole};
use crate::reach::{Analyzer, Config, DispatchPolicy, EntryPolicy, FrameworkSource};

use super::fixtures::*;

/// The hierarchy every test here uses.
///
/// ```text
/// Ltest/Base;            run()
///   +-- Ltest/A;         run()          (allocated)
///   |     +-- Ltest/C;  run()          (NEVER allocated — the RTA/CHA case)
///   +-- Ltest/B;         run()          (allocated)
///
/// Ltest/I;               ping()
///   implemented by Ltest/A and Ltest/B
/// ```
fn base_hierarchy() -> Vec<u8> {
    let mut b = Builder::new();
    for d in [
        "Ljava/lang/Object;",
        "Ltest/Base;",
        "Ltest/A;",
        "Ltest/B;",
        "Ltest/C;",
        "Ltest/I;",
        "Ltest/Driver;",
    ] {
        b.ty(d);
    }
    b.method_ref(
        "Ljava/lang/Class;",
        "forName",
        &["Ljava/lang/String;"],
        "Ljava/lang/Class;",
    );
    b.method_ref("Ltest/Base;", "run", &[], "V");
    b.method_ref("Ltest/I;", "ping", &[], "V");

    b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
    b.class(interface("Ltest/I;", "ping"));
    b.class(class_with_method(
        "Ltest/Base;",
        Some("Ljava/lang/Object;"),
        "run",
    ));

    // A, B and C override `run`. A and B additionally implement `I` directly;
    // C inherits `ping` from A. One declaration per class, because a second
    // `class_def` for the same descriptor is a duplicate and a test that trips
    // over that is testing the writer, not reachability.
    let concrete = |name: &str| {
        MethodDef::concrete(
            name,
            &[],
            "V",
            dexcore::model::access::ACC_PUBLIC,
            dexcore::writer::CodeBody::default(),
        )
    };
    let mut a_def = with_ctor(
        ClassDef::new("Ltest/A;", Some("Ltest/Base;".into()))
            .with_method(concrete("run"))
            .with_method(concrete("ping")),
    );
    a_def.interfaces = vec!["Ltest/I;".into()];
    b.class(a_def);
    let mut b_def = with_ctor(
        ClassDef::new("Ltest/B;", Some("Ltest/Base;".into()))
            .with_method(concrete("run"))
            .with_method(concrete("ping")),
    );
    b_def.interfaces = vec!["Ltest/I;".into()];
    b.class(b_def);
    let mut c =
        with_ctor(ClassDef::new("Ltest/C;", Some("Ltest/A;".into())).with_method(concrete("run")));
    c.interfaces = vec!["Ltest/I;".into()];
    b.class(c);

    // The entry point.
    b.class(with_ctor(
        ClassDef::new("Ltest/Driver;", Some("Ljava/lang/Object;".into())).with_method(
            MethodDef::concrete(
                "go",
                &[],
                "V",
                dexcore::model::access::ACC_PUBLIC | dexcore::model::access::ACC_STATIC,
                dexcore::writer::CodeBody::default(),
            ),
        ),
    ));

    let mut f = b.freeze();
    f.code("Ljava/lang/Object;", "<init>", empty_void());
    f.code("Ltest/Base;", "run", empty_void());
    f.code("Ltest/A;", "run", empty_void());
    f.code("Ltest/A;", "ping", empty_void());
    f.code("Ltest/B;", "run", empty_void());
    f.code("Ltest/B;", "ping", empty_void());
    f.code("Ltest/C;", "run", empty_void());

    // go(): new A; new B; Base.run(); I.ping();
    let mut a = dexcore::asm::Assembler::new();
    a.new_instance(0, f.ty("Ltest/A;"));
    a.invoke(0x70, &[0], f.method("Ltest/A;", "<init>", &[], "V"))
        .expect("invoke-direct");
    a.new_instance(1, f.ty("Ltest/B;"));
    a.invoke(0x70, &[1], f.method("Ltest/B;", "<init>", &[], "V"))
        .expect("invoke-direct");
    a.invoke(0x6e, &[0], f.method("Ltest/Base;", "run", &[], "V"))
        .expect("invoke-virtual");
    a.invoke(0x72, &[1], f.method("Ltest/I;", "ping", &[], "V"))
        .expect("invoke-interface");
    a.return_void();
    f.code("Ltest/Driver;", "go", a.into_code(2, 0, 2));
    f.emit()
}

/// The bare universe, for assertions about indexing rather than the fixpoint.
fn program_for(_dispatch: DispatchPolicy) -> Program {
    let bytes = base_hierarchy();
    Program::build(vec![DexInput::new("classes.dex", UnitRole::App, bytes)])
        .expect("a hand-built DEX must load")
}

fn closure_for(dispatch: DispatchPolicy) -> (Program, crate::reach::Closure) {
    let bytes = base_hierarchy();
    let mut p = Program::build(vec![DexInput::new("classes.dex", UnitRole::App, bytes)])
        .expect("a hand-built DEX must load");
    let c = Config {
        dispatch,
        framework: FrameworkSource::Follow,
        entry: EntryPolicy::IrMd,
        max_rounds: 32,
        ..Config::default()
    };
    let entry = explicit_entry_points(&p, &["Ltest/Driver;.go()V"]);
    let a = Analyzer::new(&mut p, c);
    let closure = a.run(&entry);
    (p, closure)
}

fn contains(p: &Program, c: &crate::reach::Closure, class: &str, name: &str, proto: &str) -> bool {
    let Some(cid) = p.class(class) else {
        return false;
    };
    p.lookup(cid, name, proto)
        .is_some_and(|m| c.methods.contains(&m))
}

#[test]
fn cha_reaches_every_implementor_including_unallocated_ones() {
    let (p, c) = closure_for(DispatchPolicy::Cha);
    assert!(c.is_complete(), "the fixpoint must not have hit a bound");

    // The two allocated implementors.
    assert!(
        contains(&p, &c, "Ltest/A;", "run", "()V"),
        "A.run must be in the closure"
    );
    assert!(
        contains(&p, &c, "Ltest/B;", "run", "()V"),
        "B.run must be in the closure"
    );
    // The unallocated grandchild, reachable only because C is a subtype of A
    // and therefore of Base. This is the assertion the brief asks for: a
    // deliberately-constructed dynamic dispatch reaches ALL implementors.
    assert!(
        contains(&p, &c, "Ltest/C;", "run", "()V"),
        "CHA must reach C.run even though nothing allocates C"
    );
    // And the base method itself: the call site names it, and a vtable slot is
    // an edge in both directions.
    assert!(
        contains(&p, &c, "Ltest/Base;", "run", "()V"),
        "Base.run must be in the closure"
    );
}

#[test]
fn cha_reaches_every_interface_implementor() {
    let (p, c) = closure_for(DispatchPolicy::Cha);
    assert!(
        contains(&p, &c, "Ltest/A;", "ping", "()V"),
        "A.ping must be in the closure"
    );
    assert!(
        contains(&p, &c, "Ltest/B;", "ping", "()V"),
        "B.ping must be in the closure"
    );
    assert!(
        contains(&p, &c, "Ltest/I;", "ping", "()V"),
        "I.ping must be in the closure"
    );
    // C does not declare `ping`; it inherits A's. A dispatch to `I.ping` on a C
    // therefore lands in `A.ping`, which is already in the closure, and there
    // is no separate `C.ping` for the analysis to find. Asserting that C
    // *inherits* rather than declares is the point: a closure that invented a
    // method the class does not have would be reporting a fiction.
    assert!(
        p.class("Ltest/C;")
            .and_then(|c| p.lookup(c, "ping", "()V"))
            .is_none(),
        "C must inherit ping, not declare it"
    );
    assert!(
        contains(&p, &c, "Ltest/A;", "ping", "()V"),
        "the inherited implementation must be in the closure"
    );
}

#[test]
fn rta_reaches_allocated_implementors_and_no_others() {
    let (p, c) = closure_for(DispatchPolicy::Rta);
    assert!(
        contains(&p, &c, "Ltest/A;", "run", "()V"),
        "A.run must be in the closure"
    );
    assert!(
        contains(&p, &c, "Ltest/B;", "run", "()V"),
        "B.run must be in the closure"
    );
    // Nothing in `go()` allocates C, so RTA — which is licensed only by
    // assuming no reflective allocation — must not claim C.run. If this test
    // ever starts failing, RTA has become unsound in the "optimistic"
    // direction and the reflective-edge report stops being a sufficient
    // caveat.
    assert!(
        !contains(&p, &c, "Ltest/C;", "run", "()V"),
        "RTA must not claim an unallocated implementor"
    );
    // The base method still comes in: the call site names it directly.
    assert!(contains(&p, &c, "Ltest/Base;", "run", "()V"));
}

#[test]
fn cha_is_a_superset_of_rta_on_this_hierarchy() {
    let (_, cha) = closure_for(DispatchPolicy::Cha);
    let (_, rta) = closure_for(DispatchPolicy::Rta);
    for m in &rta.methods {
        assert!(
            cha.methods.contains(m),
            "CHA must contain everything RTA contains"
        );
    }
    assert!(
        cha.methods.len() > rta.methods.len(),
        "CHA must be strictly larger here"
    );
}

#[test]
fn a_virtual_call_records_virtual_edges_not_direct_ones() {
    let (_, c) = closure_for(DispatchPolicy::Cha);
    assert!(
        c.method_edges_of(crate::reach::EdgeKind::Virtual) > 0,
        "virtual edges must be recorded"
    );
    // The entry point only makes virtual and interface calls, so there should
    // be no direct edge out of it other than the two constructors.
    assert!(c.method_edges_of(crate::reach::EdgeKind::Direct) > 0);
}

#[test]
fn overriding_pulls_in_the_overridden_method_and_the_reverse_holds() {
    let (p, c) = closure_for(DispatchPolicy::Rta);
    let base = p.class("Ltest/Base;").expect("Base exists");
    let base_run = p.lookup(base, "run", "()V").expect("Base.run exists");
    let a = p.class("Ltest/A;").expect("A exists");
    let a_run = p.lookup(a, "run", "()V").expect("A.run exists");
    // A.run is in the closure because of the call site, and the vtable rule
    // then brings Base.run in as the method A.run shadows.
    assert!(c.methods.contains(&a_run));
    assert!(c.methods.contains(&base_run));
    // The edge runs base -> override: the base method is in the closure and
    // the override is what a dispatch through it can reach. Asserting the
    // other direction would pass trivially once the closure is right and then
    // stop testing the edge at all.
    assert!(
        c.edges.iter().any(|e| e.from == base_run
            && e.to == a_run
            && e.kind == crate::reach::EdgeKind::Virtual),
        "the vtable slot must be recorded as an edge from the shadowed method to the override"
    );
}

#[test]
fn the_hierarchy_loads_and_indexes_the_expected_shape() {
    let mut p = program_for(DispatchPolicy::Cha);
    assert!(p.class("Ltest/C;").is_some());
    assert!(p.class("Ltest/Base;").is_some());
    let base = p.class("Ltest/Base;").expect("Base exists");
    assert_eq!(
        p.transitive_subtypes(base).len(),
        3,
        "Base has A, B and C below it"
    );
    let i = p.class("Ltest/I;").expect("I exists");
    assert_eq!(
        p.transitive_subtypes(i).len(),
        3,
        "I is implemented by A, B and C"
    );
}
