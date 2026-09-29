//! Reflection: the hole, and the requirement that it is counted.
//!
//! `IR.md`: "A closure is only sound if the report says how many unresolved
//! reflective edges there were. Silence is a failure."
//!
//! So these tests assert three separate things, because they are three
//! separate claims and conflating them is how a hole gets reported as a
//! feature:
//!
//! 1. a class-shaped literal the universe does not contain is recorded as
//!    `Unresolved` — not dropped, not silently resolved;
//! 2. a literal handed to `Class.forName` at a syntactic site is recorded as
//!    `ForNameSite` and, under the expanding policy, drags the class's
//!    overridable surface into the closure;
//! 3. **on a real APK**, the unresolved count is non-zero. A synthetic fixture
//!    can only show the machinery works; only real code shows the hole is
//!    real.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::reach::entry::{explicit_entry_points, Manifest};
use crate::reach::model::{DexInput, Program, UnitRole};
use crate::reach::{
    Analyzer, Closure, Config, EntryPolicy, FrameworkSource, ReflectionPolicy, ReflectiveVerdict,
};

use super::fixtures::*;

/// A DEX with three kinds of string constant in one method.
fn reflective_app() -> Vec<u8> {
    let mut b = Builder::new();
    b.ty("Ljava/lang/Object;");
    b.ty("Ljava/lang/Class;");
    b.ty("Ltest/Target;");
    b.ty("Ltest/Entry;");
    b.method_ref(
        "Ljava/lang/Class;",
        "forName",
        &["Ljava/lang/String;"],
        "Ljava/lang/Class;",
    );
    b.string("Ltest/Target;");
    b.string("com.example.NotHere");
    b.string("a plain log message");
    b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
    let concrete = |n: &str| {
        dexcore::writer::MethodDef::concrete(
            n,
            &[],
            "V",
            dexcore::model::access::ACC_PUBLIC,
            dexcore::writer::CodeBody::default(),
        )
    };
    b.class(with_ctor(
        crate::reach::tests::fixtures::override_class(
            "Ltest/Target;",
            "Ljava/lang/Object;",
            "hello",
        )
        .with_method(concrete("greet"))
        .with_method(concrete("secret")),
    ));
    b.class(with_ctor(
        dexcore::writer::ClassDef::new("Ltest/Entry;", Some("Ljava/lang/Object;".into()))
            .with_method(dexcore::writer::MethodDef::concrete(
                "go",
                &[],
                "V",
                dexcore::model::access::ACC_PUBLIC | dexcore::model::access::ACC_STATIC,
                dexcore::writer::CodeBody::default(),
            )),
    ));
    let mut f = b.freeze();
    f.code("Ljava/lang/Object;", "<init>", empty_void());
    f.code("Ltest/Target;", "hello", empty_void());
    f.code("Ltest/Target;", "greet", empty_void());
    f.code("Ltest/Target;", "secret", empty_void());

    // Three literals in one body, in this order:
    //   const-string v0, "Ltest/Target;";  Class.forName(v0)   -> ForNameSite
    //   const-string v0, "com.example.NotHere;"                 -> Unresolved
    //   const-string v0, "a plain log message"                  -> NotAClass
    let target = f.string("Ltest/Target;");
    let missing = f.string("com.example.NotHere");
    let plain = f.string("a plain log message");
    let forname = f.method(
        "Ljava/lang/Class;",
        "forName",
        &["Ljava/lang/String;"],
        "Ljava/lang/Class;",
    );
    let mut a = dexcore::asm::Assembler::new();
    a.const_string(0, target);
    a.invoke(0x71, &[0], forname).expect("invoke-static");
    a.const_string(0, missing);
    a.const_string(0, plain);
    a.return_void();
    f.code("Ltest/Entry;", "go", a.into_code(1, 0, 1));
    f.emit()
}

fn run(bytes: Vec<u8>, reflection: ReflectionPolicy) -> (Program, Closure) {
    let mut p = Program::build(vec![DexInput::new("classes.dex", UnitRole::App, bytes)])
        .expect("a hand-built DEX must load");
    let c = Config {
        framework: FrameworkSource::Follow,
        entry: EntryPolicy::IrMd,
        reflection,
        max_rounds: 32,
        ..Config::default()
    };
    let entry = explicit_entry_points(&p, &["Ltest/Entry;.go()V"]);
    let a = Analyzer::new(&mut p, c);
    let closure = a.run(&entry);
    (p, closure)
}

fn has(p: &Program, c: &Closure, class: &str, name: &str) -> bool {
    p.class(class)
        .and_then(|cid| p.lookup(cid, name, "()V"))
        .is_some_and(|m| c.methods.contains(&m))
}

#[test]
fn every_const_string_is_counted_not_just_the_class_shaped_ones() {
    let (_, c) = run(reflective_app(), ReflectionPolicy::ForNameExpands);
    assert_eq!(
        c.const_string_instructions, 3,
        "every const-string must be counted as the denominator"
    );
    assert_eq!(c.reflective_edges.len(), 3);
    assert_eq!(
        c.nonclass_literals(),
        1,
        "a log message is not a class name"
    );
    assert_eq!(c.forname_reflective(), 1);
    assert_eq!(
        c.unresolved_reflective(),
        1,
        "the missing class must be recorded as unresolved"
    );
    assert_eq!(
        c.resolved_reflective(),
        0,
        "a forName site is its own verdict, not 'resolved'"
    );
}

#[test]
fn the_unresolved_literal_is_named_in_the_report_not_swallowed() {
    let (_, c) = run(reflective_app(), ReflectionPolicy::ForNameExpands);
    let names: Vec<&str> = c.distinct_unresolved_literals().into_iter().collect();
    assert_eq!(names, vec!["com.example.NotHere"]);
    // And it is reported as a class-shaped literal, so the count is a hole in
    // class resolution rather than a string that happened to look odd.
    let e = c
        .reflective_edges
        .iter()
        .find(|e| e.verdict == ReflectiveVerdict::Unresolved)
        .expect("an unresolved edge");
    assert_eq!(e.descriptor.as_deref(), Some("Lcom/example/NotHere;"));
    assert!(e.target.is_none(), "an unresolved edge has no target class");
}

#[test]
fn a_forname_site_expands_the_class_into_the_closure() {
    let (p, c) = run(reflective_app(), ReflectionPolicy::ForNameExpands);
    assert!(
        has(&p, &c, "Ltest/Target;", "hello"),
        "a forName site must pull the class's methods in"
    );
    assert!(has(&p, &c, "Ltest/Target;", "greet"));
    assert!(
        has(&p, &c, "Ltest/Target;", "secret"),
        "the whole overridable surface, not a guessed subset"
    );
}

#[test]
fn class_only_policy_does_not_expand() {
    let (p, c) = run(reflective_app(), ReflectionPolicy::ClassOnly);
    let target = p.class("Ltest/Target;").expect("Target exists");
    assert!(
        c.classes.contains(&target),
        "the class itself still enters the closure"
    );
    assert!(
        !has(&p, &c, "Ltest/Target;", "hello"),
        "class-only must not expand to the surface"
    );
    assert!(
        !has(&p, &c, "Ltest/Target;", "secret"),
        "class-only must not expand to the surface"
    );
    // The edge accounting is the same either way: the hole does not get smaller
    // because a policy was tightened. A tighter closure is a smaller claim
    // about the same ignorance, not less ignorance.
    assert_eq!(c.unresolved_reflective(), 1);
    assert_eq!(c.forname_reflective(), 1);
}

#[test]
fn the_reflective_class_enters_the_closure_and_drags_its_ancestors() {
    let (p, c) = run(reflective_app(), ReflectionPolicy::ClassOnly);
    let target = p.class("Ltest/Target;").expect("Target exists");
    assert!(
        c.classes.contains(&target),
        "a resolved reflective class must enter the closure"
    );
    let object = p.class("Ljava/lang/Object;").expect("Object exists");
    assert!(
        c.classes.contains(&object),
        "a class drags its transitive superclass chain"
    );
    assert!(c.class_edges_of(crate::reach::EdgeKind::Superclass) > 0);
    assert!(c.class_edges_of(crate::reach::EdgeKind::Reflective) > 0);
}

// ---------------------------------------------------------------------------
// The claim that matters: on real code the hole is non-zero.
// ---------------------------------------------------------------------------

#[test]
fn real_apps_have_a_non_zero_unresolved_reflective_edge_count() {
    // The committed fixtures are tiny DEX *extracts*, so their entry-point
    // closures are a handful of methods and cannot reach the string constants
    // that carry the reflective holes. The claim is therefore made against
    // the static surface — every method the DEX declares — which is the same
    // classifier over the same real files, and is also the quantity
    // `analysis/candidates.md` measures. The per-app table is printed because
    // a single aggregate assertion would hide that most of these apps have no
    // class-shaped literal at all, which is itself the finding.
    let mut rows: Vec<(String, u64, usize, usize)> = Vec::new();
    for app in real_apps() {
        let Ok(mut p) = Program::build(vec![DexInput::new(
            "classes.dex",
            UnitRole::App,
            app.dex.to_vec(),
        )]) else {
            continue;
        };
        let config = Config {
            framework: FrameworkSource::Follow,
            entry: EntryPolicy::IrMd,
            max_rounds: 64,
            ..Config::default()
        };
        let entry = crate::reach::entry::all_method_roots(&p);
        let a = Analyzer::new(&mut p, config);
        let c = a.run(&entry);
        rows.push((
            app.name.to_string(),
            c.const_string_instructions,
            c.reflective_edges
                .iter()
                .filter(|e| e.descriptor.is_some())
                .count(),
            c.unresolved_reflective(),
        ));
    }
    for (n, cs, shaped, unres) in &rows {
        eprintln!("{n}: const-strings={cs} class-shaped={shaped} unresolved={unres}");
    }
    assert!(
        !rows.is_empty(),
        "at least one real fixture must have loaded"
    );
    let total_unresolved: usize = rows.iter().map(|r| r.3).sum();
    assert!(
        total_unresolved > 0,
        "a real APK's DEX must contain at least one class-shaped string constant the universe \
         cannot resolve; zero would mean the classifier never sees one, not that apps are clean"
    );
    assert!(
        rows.iter().all(|r| r.1 >= r.2 as u64),
        "the class-shaped subset can never exceed every const-string decoded"
    );
}

#[test]
fn the_dominant_false_positive_class_is_measured_not_hidden() {
    // The classifier is liberal on purpose, and the cost of that is
    // measurable: most class-shaped literals in a real APK are intent action
    // and extra *names*, not class names. Pinned here so the report's
    // unresolved count is read with the right expectation attached.
    let app = real_apps()
        .into_iter()
        .find(|a| a.name == "com.termux.boot_1000")
        .expect("the termux fixture is committed");
    let mut p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let config = Config {
        framework: FrameworkSource::Follow,
        ..Config::default()
    };
    let entry = crate::reach::entry::all_method_roots(&p);
    let a = Analyzer::new(&mut p, config);
    let c = a.run(&entry);
    let literals = c.distinct_unresolved_literals();
    assert!(
        literals.contains("android.intent.action.BOOT_COMPLETED"),
        "expected the intent-action false positive to be present, got {literals:?}"
    );
    // And a genuine class name, which is the case the hole is really about.
    assert!(
        literals.contains("com.termux.app.TermuxService"),
        "expected a real class name among the class-shaped literals, got {literals:?}"
    );
}

#[test]
fn a_real_app_report_states_its_reflective_holes() {
    let Some(app) = launcher_app() else {
        // No fixture declares MAIN+LAUNCHER. The absence is itself recorded
        // rather than skipped silently: it is why this test can be vacuous.
        eprintln!("note: no committed fixture declares a LAUNCHER activity");
        return;
    };
    let mut p = Program::build(vec![DexInput::new(
        "classes.dex",
        UnitRole::App,
        app.dex.to_vec(),
    )])
    .expect("a real fixture must load");
    let manifest = Manifest::parse(app.axml).expect("a real manifest must parse");
    let config = Config {
        framework: FrameworkSource::Follow,
        entry: EntryPolicy::ColdStart,
        max_rounds: 64,
        ..Config::default()
    };
    let entry = crate::reach::entry::entry_points(&p, &manifest, config.entry, false);
    let a = Analyzer::new(&mut p, config);
    let c = a.run(&entry);
    let report = crate::reach::report::ClosureReport::build(
        &p,
        &c,
        app.name,
        "ColdStart / 6.2 s equivalent",
    );
    let md = report.to_markdown();
    assert!(
        md.contains("## Reflection"),
        "the report must have a reflection section"
    );
    assert!(
        md.contains("unresolved reflective edges existed")
            || md.contains("Unresolved reflective edges"),
        "the report must state the unresolved count in words, not only as a table row"
    );
    // Every figure in the report carries a provenance tag.
    for line in md.lines() {
        if line.starts_with("| ") && line.contains("[") && line.contains("] `") {
            assert!(
                line.contains("[measured]")
                    || line.contains("[derived]")
                    || line.contains("[conjecture]"),
                "an unlabelled figure reached the report: {line}"
            );
        }
    }
}
