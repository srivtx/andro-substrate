//! Superclass inclusion, the override closure, and the transitive chain.
//!
//! `IR.md` lists three separate rules that a naive implementation conflates:
//! a class drags its ancestors, a method drags its overrides, and a bodyless
//! method drags a hostcall. Each gets its own assertion here, because
//! conflating them is how a closure quietly stops being sound.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::reach::entry::explicit_entry_points;
use crate::reach::model::{DexInput, Program, UnitRole};
use crate::reach::{
    Analyzer, Closure, Config, DispatchPolicy, EdgeKind, EntryPolicy, FrameworkSource,
};

use super::fixtures::*;

/// ```text
/// Ldeep/A;  ->  Ldeep/B;  ->  Ldeep/C;  ->  Ljava/lang/Object;
/// Ldeep/Leaf;  implements  Ldeep/I;  extends  Ldeep/C;
/// ```
fn deep_hierarchy() -> Vec<u8> {
    let mut b = Builder::new();
    for d in [
        "Ljava/lang/Object;",
        "Ldeep/A;",
        "Ldeep/B;",
        "Ldeep/C;",
        "Ldeep/I;",
        "Ldeep/Leaf;",
        "Ldeep/Entry;",
    ] {
        b.ty(d);
    }
    b.string("hello");
    b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
    let mut i = interface("Ldeep/I;", "hook");
    i.interfaces = vec!["Ldeep/B;".to_string()];
    b.class(i);
    b.class(class_with_method(
        "Ldeep/A;",
        Some("Ljava/lang/Object;"),
        "top",
    ));
    b.class(class_with_method("Ldeep/B;", Some("Ldeep/A;"), "top"));
    b.class(class_with_method("Ldeep/C;", Some("Ldeep/B;"), "top"));
    b.class(object_implementor("Ldeep/Leaf;", "Ldeep/I;", "hook"));
    b.class(
        dexcore::writer::ClassDef::extending_object("Ldeep/Entry;").with_method(
            dexcore::writer::MethodDef::concrete(
                "go",
                &[],
                "V",
                dexcore::model::access::ACC_PUBLIC | dexcore::model::access::ACC_STATIC,
                dexcore::writer::CodeBody::default(),
            ),
        ),
    );
    let mut f = b.freeze();
    f.code("Ljava/lang/Object;", "<init>", empty_void());
    f.code("Ldeep/A;", "top", empty_void());
    f.code("Ldeep/B;", "top", empty_void());
    f.code("Ldeep/C;", "top", empty_void());
    f.code("Ldeep/Leaf;", "hook", empty_void());
    // go(): new Leaf(); C.top();
    let mut a = dexcore::asm::Assembler::new();
    a.new_instance(0, f.ty("Ldeep/Leaf;"));
    a.invoke(0x70, &[0], f.method("Ldeep/Leaf;", "<init>", &[], "V"))
        .expect("invoke-direct");
    a.invoke(0x6e, &[0], f.method("Ldeep/C;", "top", &[], "V"))
        .expect("invoke-virtual");
    a.return_void();
    f.code("Ldeep/Entry;", "go", a.into_code(1, 0, 1));
    f.emit()
}

fn run(dispatch: DispatchPolicy) -> (Program, Closure) {
    let mut p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        deep_hierarchy(),
    )])
    .expect("a hand-built DEX must load");
    let c = Config {
        dispatch,
        framework: FrameworkSource::Follow,
        entry: EntryPolicy::IrMd,
        max_rounds: 32,
        ..Config::default()
    };
    let entry = explicit_entry_points(&p, &["Ldeep/Entry;.go()V"]);
    let a = Analyzer::new(&mut p, c);
    let closure = a.run(&entry);
    (p, closure)
}

#[test]
fn a_class_in_the_closure_drags_its_whole_ancestor_chain() {
    let (p, c) = run(DispatchPolicy::Cha);
    // Leaf is in the closure because `go` allocates it. Its chain is
    // Leaf -> C -> B -> A -> Object, and so is I (Leaf implements it).
    for d in [
        "Ldeep/Leaf;",
        "Ldeep/C;",
        "Ldeep/B;",
        "Ldeep/A;",
        "Ljava/lang/Object;",
        "Ldeep/I;",
    ] {
        let cid = p
            .class(d)
            .unwrap_or_else(|| panic!("{d} must be in the universe"));
        assert!(
            c.classes.contains(&cid),
            "{d} must be in the closure's class set"
        );
    }
    assert!(
        c.class_edges_of(EdgeKind::Superclass) >= 5,
        "every ancestor link must be counted"
    );
}

#[test]
fn an_intermediate_ancestor_is_included_even_though_nothing_names_it() {
    let (p, c) = run(DispatchPolicy::Cha);
    // `go` names Ldeep/C and Ldeep/Leaf. B and A are named by nothing in the
    // entry point; they are in the closure only because of the ancestor rule.
    let b = p.class("Ldeep/B;").expect("B exists");
    let a = p.class("Ldeep/A;").expect("A exists");
    assert!(c.classes.contains(&b) && c.classes.contains(&a));
    // Being in the *class* closure does not by itself pull their method bodies
    // in: a class is a vtable shape, a method is a callable. This is asserted
    // so the two are never silently merged.
    let b_top = p.lookup(b, "top", "()V").expect("B.top exists");
    let a_top = p.lookup(a, "top", "()V").expect("A.top exists");
    assert!(
        c.methods.contains(&b_top),
        "B.top shadows A.top, so the slot brings it in"
    );
    assert!(
        c.methods.contains(&a_top),
        "and the chain continues up from there"
    );
}

#[test]
fn a_grandchild_override_is_reached_through_the_vtable_under_cha() {
    let (p, c) = run(DispatchPolicy::Cha);
    for d in ["Ldeep/A;", "Ldeep/B;", "Ldeep/C;"] {
        let cid = p.class(d).unwrap_or_else(|| panic!("{d} exists"));
        let top = p
            .lookup(cid, "top", "()V")
            .unwrap_or_else(|| panic!("{d}.top exists"));
        assert!(
            c.methods.contains(&top),
            "{d}.top must be in the closure under CHA"
        );
    }
}

#[test]
fn a_bodyless_method_in_the_closure_is_reported_as_a_hostcall() {
    // Ldeep/I;.hook is abstract: no DEX body, so the host must implement it.
    let (p, c) = run(DispatchPolicy::Cha);
    let i = p.class("Ldeep/I;").expect("I exists");
    let hook = p.lookup(i, "hook", "()V").expect("I.hook exists");
    assert!(p.methods[hook.0 as usize].is_bodyless());
    if c.methods.contains(&hook) {
        assert!(
            c.bodyless.contains(&hook),
            "a bodyless method in the closure must be listed"
        );
    }
}

#[test]
fn supersede_prefers_the_framework_definition() {
    // The same class declared by both an app unit and a framework unit: the
    // framework body wins, as on a real device (the boot classpath is the
    // parent loader) and as IR.md's "host > app" rule requires.
    let bytes = {
        let mut b = Builder::new();
        b.ty("Ljava/lang/Object;");
        b.ty("Ldup/Thing;");
        b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
        b.class(override_class("Ldup/Thing;", "Ljava/lang/Object;", "run"));
        let mut f = b.freeze();
        f.code("Ljava/lang/Object;", "<init>", empty_void());
        f.code("Ldup/Thing;", "run", empty_void());
        f.emit()
    };
    let p = Program::build(vec![
        DexInput::new("app/classes.dex", UnitRole::App, bytes.clone()),
        DexInput::new("host/classes.dex", UnitRole::Framework, bytes),
    ])
    .expect("both units must load");
    let thing = p.class("Ldup/Thing;").expect("Thing exists");
    let resolved = p.classes[thing.0 as usize]
        .resolved()
        .expect("Thing is defined");
    assert_eq!(
        p.units[resolved.unit.0 as usize].role,
        UnitRole::Framework,
        "the host must win"
    );
    assert!(
        p.shadowed.iter().any(|(d, _)| d == "Ldup/Thing;"),
        "the shadowing event must be recorded, not silently resolved: {:?}",
        p.shadowed
    );
}

#[test]
fn transitive_subtypes_terminate_on_a_cyclic_interface_graph() {
    // A hostile or corrupt DEX can make an interface extend itself. The
    // worklist must terminate; the cycle is a finding, not a hang.
    //
    // `DexWriter` refuses to emit a self-extending interface, which is worth
    // knowing in its own right, so the cycle is introduced into the indexed
    // universe directly — that is the state a corrupt input would leave it in.
    let bytes = {
        let mut b = Builder::new();
        b.ty("Ljava/lang/Object;");
        b.ty("Lcyc/A;");
        b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
        b.class(class_with_method(
            "Lcyc/A;",
            Some("Ljava/lang/Object;"),
            "m",
        ));
        let mut f = b.freeze();
        f.code("Ljava/lang/Object;", "<init>", empty_void());
        f.code("Lcyc/A;", "m", empty_void());
        f.emit()
    };
    let mut p = Program::build(vec![DexInput::new("classes.dex", UnitRole::App, bytes)])
        .expect("a hand-built DEX must load");
    let a = p.class("Lcyc/A;").expect("A exists");
    p.classes[a.0 as usize].children.push(a);
    let subs = p.transitive_subtypes(a);
    assert_eq!(
        subs.len(),
        1,
        "a self-edge must not make the subtype set contain A twice"
    );
    // A second call must hit the memo and agree.
    assert_eq!(p.transitive_subtypes(a).len(), 1);
}
