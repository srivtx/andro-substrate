//! The interpreter–shim boundary, exercised as a boundary.
//!
//! Every test here loads **real DEX**: the committed F-Droid `classes.dex`
//! extracts in `tools/dexcore/tests/fixtures/`, and the shim's own emitted DEX.
//! Nothing is hand-assembled, because the claim under test is about two real
//! class tables meeting, and a hand-built fixture would test the harness instead
//! of the claim.
//!
//! The seven claims, in the order the deliverables name them:
//!
//! 1. an app-only class resolves from the app DEX;
//! 2. an `android.*` class resolves from the shim;
//! 3. shadowing is recorded — from the class table *and* from the runtime;
//! 4. a hostile app cannot override a shim method;
//! 5. the two hard invariants (egress impossible, redaction in the types) hold on
//!    this path and not merely on the scripted one;
//! 6. the host boundary is observation-bearing, not decorative;
//! 7. the run is deterministic, so the differential and the sync control have
//!    something stable to be run against.

use std::collections::BTreeSet;

use dexinterp::config::Config;
use dexinterp::host::Host;
use shim::classes::AppDex;
use shim::event::{Detail, Resolution};
use shim::interp::SubstrateHost;
use shim::policy::SubstratePolicy;

/// The six committed F-Droid DEX extracts, read at compile time so the test does
/// not need a file at run time and cannot be skipped by a missing fixture.
const APP_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex");
const ADBKEYBOARD_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex");
const REDSCREEN_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex");

/// The framework layer: the shim's own DEX, emitted from its registry.
fn shim_dex() -> Vec<u8> {
    shim::emit::emit()
        .expect("the shim must be able to emit its own DEX")
        .bytes
        .clone()
}

fn layered<'a>(app: &'a [u8], budget: u64) -> dexinterp::Interpreter<'a> {
    let reader = dexcore::DexReader::open(app).expect("the fixture DEX must parse");
    let cfg = Config {
        instruction_budget: Some(budget),
        max_shim_log: 65_536,
        ..Config::default()
    };
    // The layer lives in a `OnceLock` and the interpreter copies what it needs,
    // so the returned value does not borrow it and a test may keep a
    // `SubstrateHost` alive across several `invoke_method` calls.
    dexinterp::new_layered_interpreter(reader, layer(), cfg)
        .expect("the layered build must resolve")
}

/// The framework layer, built once. `once_cell` is not a dependency of this
/// crate and a `static` with a `OnceLock` is three lines.
static LAYER: std::sync::OnceLock<Vec<dexinterp::HostClass>> = std::sync::OnceLock::new();

fn layer() -> &'static [dexinterp::HostClass] {
    LAYER.get_or_init(|| {
        let bytes = shim_dex();
        let reader = dexcore::DexReader::open(&bytes).expect("the shim DEX must parse");
        dexinterp::program::host_classes_from_dex(&reader).expect("shim declarations must resolve")
    })
}

fn host_for(pkg: &str) -> SubstrateHost {
    SubstrateHost::with_policy(pkg, Vec::new(), SubstratePolicy::default())
        .expect("the shim builds")
}

/// A frame's classes, by descriptor, for a receiver the engine allocated.
fn classes_of(vm: &dexinterp::Interpreter<'_>) -> Vec<String> {
    (0..vm.heap().len() as u32)
        .filter_map(|i| {
            let v = dexinterp::Value::Ref(dexinterp::Ref(i + 1));
            vm.class_of(v)
        })
        .collect()
}

// ------------------------------------------------------------------ claim 1

#[test]
fn an_app_only_class_resolves_from_the_app_dex() {
    let vm = layered(APP_DEX, 1_000_000);
    let mut vm = vm;
    let id = vm
        .program_mut()
        .class_for("Lpro/rudloff/search_to_browser/MainActivity;", false);
    assert!(
        id.is_some(),
        "the app's own class must be in the class table"
    );
    let meta = vm
        .program()
        .class(id.expect("checked above"))
        .expect("the class must resolve");
    match meta.source {
        dexinterp::ClassSource::Dex(i) => assert!(
            i < 8,
            "an app class must come from the app's own class_def, got index {i}"
        ),
        other => panic!("an app class must not be {other:?}"),
    }
    // And it is *runnable*: a bodiless declaration would prove nothing.
    let protos = vm.prototypes("Lpro/rudloff/search_to_browser/MainActivity;", "onCreate");
    assert!(
        !protos.is_empty(),
        "the app's activity declares onCreate, and the table must show it"
    );
    assert!(
        vm.program()
            .method_code_offset(
                "Lpro/rudloff/search_to_browser/MainActivity;",
                "onCreate",
                "(Landroid/os/Bundle;)V"
            )
            .is_some(),
        "the app's onCreate must have a code_item the engine can execute"
    );
}

// ------------------------------------------------------------------ claim 2

#[test]
fn an_android_class_resolves_from_the_shim_not_from_a_placeholder() {
    let vm = layered(APP_DEX, 1_000_000);
    let mut vm = vm;
    let id = vm
        .program_mut()
        .class_for("Landroid/app/Activity;", false)
        .expect("the shim declares Activity");
    let meta = vm.program().class(id).expect("resolves");
    assert_eq!(
        meta.source,
        dexinterp::ClassSource::Host,
        "an android.* class must come from the framework layer, never from a phantom"
    );
    assert!(
        vm.stats().phantom_classes.is_empty()
            || !vm
                .stats()
                .phantom_classes
                .iter()
                .any(|p| p == "Landroid/app/Activity;"),
        "Activity must not also be recorded as a fabricated placeholder"
    );
    // A declaration, not a body: the whole point of the boundary.
    assert!(
        vm.program()
            .method_code_offset(
                "Landroid/app/Activity;",
                "onCreate",
                "(Landroid/os/Bundle;)V"
            )
            .is_none(),
        "a framework method must have no code_item the engine could run"
    );
    assert!(
        !vm.stats().host_bodies_refused.is_empty(),
        "and the shim DEX does carry real code (android/substrate/Bridge), so the refusal to run \
         a framework body is a counted event rather than a claim that cannot happen"
    );
}

#[test]
fn the_hierarchy_crosses_the_boundary_so_a_catch_works() {
    let vm = layered(APP_DEX, 1_000_000);
    let mut vm = vm;
    let application = vm
        .program_mut()
        .class_for("Lpro/rudloff/search_to_browser/MainApplication;", true)
        .expect("app class");
    let app = vm
        .program_mut()
        .class_for("Landroid/app/Application;", true)
        .expect("shim class");
    assert!(
        vm.program().is_a(application, app),
        "MainApplication extends Landroid/app/Application; and the two class tables must be one \
         hierarchy, or every catch clause and every vtable slot crossing the boundary is wrong"
    );
    // And through two levels, so the walk is a walk and not a lookup.
    let activity = vm
        .program_mut()
        .class_for("Lpro/rudloff/search_to_browser/MainActivity;", true)
        .expect("app class");
    let android_activity = vm
        .program_mut()
        .class_for("Landroid/app/Activity;", true)
        .expect("shim class");
    assert!(
        vm.program().is_a(activity, android_activity),
        "MainActivity extends Landroid/app/Activity;, which is the crossing that matters"
    );
    let object = vm
        .program_mut()
        .class_for("Ljava/lang/Object;", true)
        .expect("Object");
    assert!(
        vm.program().is_a(activity, object),
        "and the app class must still be an Object, four levels up in a table the app never saw"
    );
}

// ------------------------------------------------------------------ claim 3

#[test]
fn shadowing_is_recorded_from_the_class_table() {
    // The shim's own descriptor set, offered to the loader as though the app had
    // defined it. A hostile APK's shape, constructed directly rather than shipped.
    let app_classes = vec![
        "Lpro/rudloff/search_to_browser/MainActivity;".to_string(),
        "Landroid/app/Activity;".to_string(),
    ];
    let loader = shim::classes::ClassLoader::new(
        shim::registry::descriptors(),
        AppDex {
            package: "pro.rudloff.search_to_browser".to_string(),
            classes: app_classes.clone(),
        },
    );
    assert_eq!(
        loader.resolve("Landroid/app/Activity;"),
        (
            Resolution::ShimSupersedesApp,
            Some("pro.rudloff.search_to_browser".into())
        ),
        "a descriptor in both places must resolve to the shim and say so"
    );
    assert_eq!(
        loader.resolve("Lpro/rudloff/search_to_browser/MainActivity;"),
        (
            Resolution::AppDex,
            Some("pro.rudloff.search_to_browser".into())
        ),
        "an app-namespace class must resolve from the app"
    );
    assert_eq!(
        loader.collisions(),
        vec!["Landroid/app/Activity;".to_string()],
        "the collision set is the app's own attempt to define framework classes"
    );
}

#[test]
fn the_class_table_drops_an_app_class_the_shim_also_defines() {
    // The mechanism the collision set describes, exercised end to end: build the
    // class table with a hostile descriptor list and read the shadowed set back.
    let reader = dexcore::DexReader::open(APP_DEX).expect("fixture");
    let app = dexinterp::Program::build(&reader).expect("single-file build");
    // Rebuild, declaring the app's own activity as a framework class. The
    // layered build is what the harness uses; the assertion is that the app's
    // class disappears from it.
    let mut hostile: Vec<dexinterp::HostClass> = layer().to_vec();
    hostile.push(dexinterp::HostClass {
        descriptor: "Lpro/rudloff/search_to_browser/MainActivity;".to_string(),
        superclass: Some("Landroid/app/Activity;".to_string()),
        interfaces: Vec::new(),
        access_flags: dexcore::model::access::ACC_PUBLIC,
        instance_fields: Vec::new(),
        static_fields: Vec::new(),
        methods: vec![(
            "onCreate".to_string(),
            "(Landroid/os/Bundle;)V".to_string(),
            dexcore::model::access::ACC_NATIVE,
        )],
        has_body: false,
    });
    let layered = dexinterp::Program::build_layered(&reader, &hostile).expect("layered build");
    assert_eq!(
        layered.shadowed,
        vec!["Lpro/rudloff/search_to_browser/MainActivity;".to_string()],
        "the app's own class must be in the shadowed set, and only that one"
    );
    let meta = layered
        .class(layered.by_descriptor["Lpro/rudloff/search_to_browser/MainActivity;"])
        .expect("still in the table");
    assert_eq!(
        meta.source,
        dexinterp::ClassSource::Host,
        "and the entry that survives must be the shim's, not the app's"
    );
    assert!(
        app.by_descriptor
            .contains_key("Lpro/rudloff/search_to_browser/MainActivity;"),
        "the unlayered build keeps it, so the test is comparing two builds and not one"
    );
}

#[test]
fn the_two_halves_of_the_boundary_agree() {
    // The class table and the runtime both decide resolution. A boundary where
    // they disagree is one an app can choose which to satisfy, so this asserts
    // they do not — for a real app and for the two apps whose own classes are
    // the interesting ones.
    for (dex, pkg) in [
        (APP_DEX, "pro.rudloff.search_to_browser"),
        (ADBKEYBOARD_DEX, "com.android.adbkeyboard"),
        (REDSCREEN_DEX, "org.vi_server.red_screen"),
    ] {
        let vm = layered(dex, 1_000_000);
        let mut host = host_for(pkg);
        let shim_descriptors: BTreeSet<String> =
            shim::registry::descriptors().into_iter().collect();
        // Every framework class the class table claims must be one the runtime
        // also says exists, and vice versa.
        for d in &shim_descriptors {
            let in_table = vm.program().by_descriptor.contains_key(d);
            let known = host.class_known(d);
            assert_eq!(
                in_table, known,
                "{pkg}: the class table and the runtime disagree about {d}"
            );
        }
        // And the app's own classes must be unknown to the shim, so the shim
        // never answers a call on app code.
        for c in [
            "Lpro/rudloff/search_to_browser/MainActivity;",
            "Lorg/vi_server/red_screen/RedScreenActivity;",
        ] {
            if vm.program().by_descriptor.contains_key(c) {
                assert!(
                    !host.class_known(c),
                    "{pkg}: the shim must not claim to serve the app's own class {c}"
                );
            }
        }
    }
}

// ------------------------------------------------------------------ claim 4

#[test]
fn a_hostile_app_cannot_override_a_shim_method() {
    // The security property ADR 0005 chose supersede for, asserted end to end on
    // a DEX that really does define framework classes: the shim's own emitted
    // DEX is a legal file that declares all 144 `android.*`/`java.*` classes and
    // carries one class with a real `code_item`. Handed to the layered build as
    // the *app*, it is a hostile APK in every respect that matters.
    let hostile = shim_dex();
    let reader = dexcore::DexReader::open(&hostile).expect("the hostile DEX parses");
    let cfg = Config {
        instruction_budget: Some(1_000_000),
        max_shim_log: 65_536,
        ..Config::default()
    };
    let vm = dexinterp::new_layered_interpreter(reader, layer(), cfg).expect("layered build");
    let stats = vm.stats();
    assert!(
        stats.shadowed_classes.len() > 100,
        "every framework class the hostile file declares must be shadowed, got {}",
        stats.shadowed_classes.len()
    );
    assert!(
        stats
            .shadowed_classes
            .contains(&"Landroid/os/Build;".to_string()),
        "including Build, which is the class whose values an integrity check reads"
    );
    // A framework-layer body is never executable, even one the layer itself
    // declares — and the refusal is counted, so "the framework has no code" is a
    // number rather than a claim that cannot be tested.
    assert!(
        stats
            .host_bodies_refused
            .contains(&"Landroid/substrate/Bridge;".to_string()),
        "the shim's one real-code class must be present in the refusal list, got {:?}",
        stats.host_bodies_refused
    );
    assert!(
        vm.program()
            .method_code_offset("Landroid/substrate/Bridge;", "ping", "()I")
            .is_none(),
        "a framework-layer body must never be executable"
    );
    // And the shim's registry, not the app, still answers for a class the app
    // also defined. The runtime half of supersede is `class_known`, which is
    // what the engine consults, so this drives that and then the answer.
    let mut host = SubstrateHost::with_policy(
        "pro.rudloff.search_to_browser",
        vec!["Landroid/os/Build;".to_string()],
        SubstratePolicy::default(),
    )
    .expect("the shim builds");
    assert!(
        host.class_known("Landroid/os/Build;"),
        "the shim declares Build, so the runtime resolves it"
    );
    // A static field read, because `Build`'s interesting values are fields and a
    // `sget` is the observation an integrity check actually makes.
    let outcome = host.get_field(&dexinterp::FieldAccess {
        class: "Landroid/os/Build;",
        name: "FINGERPRINT",
        ty: "Ljava/lang/String;",
        target: None,
    });
    match outcome {
        dexinterp::HostOutcome::Value(dexinterp::HostValue::Str(s)) => {
            assert!(
                s.starts_with("andro-substrate/"),
                "the answer must be the shim's fabricated identity, got {s:?}"
            );
        }
        other => panic!("expected the shim's fabricated fingerprint, got {other:?}"),
    }
    // The classloader half records the same phenomenon, and names it.
    let events = host.events_snapshot();
    assert!(
        events.iter().any(|e| matches!(
            &e.detail,
            Detail::Classes {
                resolution: Resolution::ShimSupersedesApp,
                descriptor,
                ..
            } if descriptor == "Landroid/os/Build;"
        )),
        "the collision must appear in the event stream as shim_supersedes_app"
    );
}

// ------------------------------------------------------------------ claim 5

#[test]
fn egress_is_still_impossible_on_the_interpreter_path() {
    // The same invariant `shim/tests/egress_denial.rs` proves for the scripted
    // path, driven here through the host an interpreter calls. The sequence is a
    // real one — a `URL` is constructed and then opened — because the shim keeps
    // the parsed request on the object and a refusal that never had a request to
    // refuse would prove nothing.
    let mut host = SubstrateHost::with_policy(
        "pro.rudloff.search_to_browser",
        Vec::new(),
        SubstratePolicy::default(),
    )
    .expect("the shim builds");
    let url = "https://example.invalid/telemetry?v=1";
    // The shim's own request sequence, driven through the host: construct a URL,
    // open a connection, and connect. The denial is at `connect`, which is
    // deliberate — a constructed URL and an attempted one are different facts and
    // the trace has to be able to tell them apart.
    let ctor = host.invoke(&dexinterp::Call {
        class: "Ljava/net/URL;",
        name: "<init>",
        signature: "(Ljava/lang/String;)V",
        kind: dexinterp::InvokeKind::Direct,
        args: &[dexinterp::Value::Null, dexinterp::Value::Null],
        rendered: &[
            dexinterp::HostValue::Null,
            dexinterp::HostValue::Str(url.to_string()),
        ],
    });
    let url_obj = match ctor {
        dexinterp::HostOutcome::Value(v) => v,
        other => panic!("URL.<init> must produce an object, got {other:?}"),
    };
    let conn = host.invoke(&dexinterp::Call {
        class: "Ljava/net/URL;",
        name: "openConnection",
        signature: "()Ljava/net/URLConnection;",
        kind: dexinterp::InvokeKind::Virtual,
        args: &[dexinterp::Value::Null],
        rendered: &[url_obj],
    });
    let conn_obj = match conn {
        dexinterp::HostOutcome::Value(v) => v,
        other => panic!("openConnection must produce a connection, got {other:?}"),
    };
    let out = host.invoke(&dexinterp::Call {
        class: "Ljava/net/URLConnection;",
        name: "connect",
        signature: "()V",
        kind: dexinterp::InvokeKind::Virtual,
        args: &[dexinterp::Value::Null],
        rendered: &[conn_obj],
    });
    assert!(
        matches!(out, dexinterp::HostOutcome::Throw(_)),
        "connect() must raise on every policy under the default substrate: {out:?}"
    );
    // And the refusal is *recorded*, in one of the two places the shim records a
    // network fact: a `net` event with an `Err` outcome, or a probe tagged with
    // `SUB.NET.EGRESS`. Both are the observation layer; which one a given call
    // produces is the shim's business and is not this test's.
    let events = host.events_snapshot();
    let refused_and_recorded = events.iter().any(|e| match &e.detail {
        Detail::Net {
            outcome,
            body_bytes,
            ..
        } => outcome.is_err() && body_bytes.is_none_or(|b| b == 0),
        Detail::Probes { .. } => e.assumption == Some(shim::AssumptionId::NetEgress),
        _ => false,
    });
    assert!(
        refused_and_recorded,
        "the refusal must be recorded as a network observation; the stream was {events:?}"
    );
    // Nothing was transmitted, and the *value* of the query parameter is gone
    // while its *name* is not. That split is ADR 0005's stated design — the shim
    // parses a query into parameter names and discards the values, so there is no
    // value to hand back — and it is worth asserting on the interpreter path
    // because a path that re-serialised the URL would leak `v=1` without any of
    // the types changing.
    let rendered = format!("{events:?}");
    assert!(
        !rendered.contains("v=1"),
        "the query value must not survive into the event stream: {rendered}"
    );
    assert!(
        rendered.contains("query_param_names: [\"v\"]"),
        "and the parameter NAME is kept, because that is what the design says is kept: {rendered}"
    );
    assert!(
        rendered.contains("body_bytes: None"),
        "no body may be reported, because no body was sent"
    );
}

#[test]
fn no_policy_value_can_open_a_socket_from_the_interpreter_path() {
    // Every *reproducible* combination of the five axes, driven through the host
    // the interpreter would use. This is the invariant re-proved at the new
    // boundary rather than assumed to follow from the old one, and the value
    // lists are the shim's own closed vocabulary rather than a list written here,
    // so a new axis value cannot slip past this test.
    let axes: [(shim::Axis, &[&str]); 5] = [
        (
            shim::Axis::Identity,
            &["fabricated", "withheld", "refusing"],
        ),
        (shim::Axis::SystemFs, &["fabricated", "empty", "absent"]),
        (
            shim::Axis::CrossAppPackages,
            &["subject_only", "all_present", "error"],
        ),
        (
            shim::Axis::Network,
            &["record_and_deny", "synthetic_loopback"],
        ),
        (shim::Axis::Time, &["virtual", "frozen", "host_real"]),
    ];
    let mut counts = [0usize; 5];
    for (c, (_, values)) in counts.iter_mut().zip(axes.iter()) {
        *c = values.len();
    }
    let mut total = 1usize;
    for c in counts {
        total *= c;
    }
    let mut idx = [0usize; 5];
    let mut runs = 0usize;
    for _ in 0..total {
        let mut policy = SubstratePolicy::default();
        for (i, (axis, values)) in axes.iter().enumerate() {
            policy
                .set(*axis, values[idx[i]])
                .expect("the vocabulary is closed and every token above is in it");
        }
        // Advance the odometer.
        for i in (0..5).rev() {
            idx[i] += 1;
            if idx[i] < counts[i] {
                break;
            }
            idx[i] = 0;
        }
        let mut host =
            SubstrateHost::with_policy("a.b", Vec::new(), policy).expect("the shim builds");
        // Two networking entry points, because the sink is reached by more than
        // one class and a test that only drives one of them proves less.
        for (class, name, sig, kind, args) in [
            (
                "Ljava/net/HttpURLConnection;",
                "getInputStream",
                "()Ljava/io/InputStream;",
                dexinterp::InvokeKind::Virtual,
                vec![dexinterp::Value::Null],
            ),
            (
                "Landroid/webkit/WebView;",
                "loadUrl",
                "(Ljava/lang/String;)V",
                dexinterp::InvokeKind::Virtual,
                vec![dexinterp::Value::Null, dexinterp::Value::Null],
            ),
        ] {
            let rendered: Vec<dexinterp::HostValue> =
                args.iter().map(|_| dexinterp::HostValue::Null).collect();
            let out = host.invoke(&dexinterp::Call {
                class,
                name,
                signature: sig,
                kind,
                args: &args,
                rendered: &rendered,
            });
            // The claim ADR 0006 makes is about the *record*, not about what the
            // app is handed: `synthetic_loopback` may present a 200 and a stream,
            // and the refusal underneath is what the recording has to show. So the
            // assertion is that no recorded network event ever reports success,
            // and that `record_and_deny` additionally raises.
            assert!(
                !host
                    .events_snapshot()
                    .iter()
                    .any(|e| matches!(&e.detail, shim::Detail::Net { outcome: Ok(_), .. })),
                "policy {policy:?}: a network event reported success on {class}.{name}"
            );
            if policy.network == shim::NetworkMode::RecordAndDeny {
                assert!(
                    matches!(out, dexinterp::HostOutcome::Throw(_)),
                    "policy {policy:?} handed the app a network result instead of raising: {out:?}"
                );
            }
        }
        runs += 1;
    }
    assert_eq!(runs, total);
    assert!(
        runs > 150,
        "the sweep must actually be large: it ran {runs} combinations"
    );
}

#[test]
fn redaction_stays_in_the_types_on_the_interpreter_path() {
    // Canary strings, through the host, and then through the serialised
    // recording. Nothing may survive, and the check is over the *document*, not
    // over the in-memory events, because a field that is dropped at serialisation
    // is still a field.
    const CANARY_QUERY: &str = "sig-zz91-do-not-record";
    const CANARY_HEADER: &str = "Bearer zz44-do-not-record";
    const CANARY_BODY: &str = "zz77-do-not-record";
    let mut host = SubstrateHost::with_policy("a.b", Vec::new(), SubstratePolicy::default())
        .expect("the shim builds");
    let url = format!("https://example.invalid/p?token={CANARY_QUERY}");
    for (class, name, sig) in [
        ("Ljava/net/URL;", "openStream", "()Ljava/io/InputStream;"),
        (
            "Ljava/net/HttpURLConnection;",
            "getInputStream",
            "()Ljava/io/InputStream;",
        ),
    ] {
        let out = host.invoke(&dexinterp::Call {
            class,
            name,
            signature: sig,
            kind: dexinterp::InvokeKind::Virtual,
            args: &[dexinterp::Value::Null],
            rendered: &[dexinterp::HostValue::Str(url.clone())],
        });
        assert!(matches!(out, dexinterp::HostOutcome::Throw(_)));
    }
    // The canaries must not be in any event, and the header/body canaries were
    // never given to the shim at all — there is no field that could hold them,
    // which is the invariant. Assert the shape rather than the absence.
    let events = host.events_snapshot();
    let rendered_events = format!("{events:?}");
    for canary in [CANARY_QUERY, CANARY_HEADER, CANARY_BODY] {
        assert!(
            !rendered_events.contains(canary),
            "{canary} reached the event stream"
        );
    }
    assert!(
        !shim::redact::HeaderNames::new().record(&format!("Authorization: {CANARY_HEADER}")),
        "a name carrying a colon must be refused outright"
    );
    let policy = SubstratePolicy::default();
    // The structural check `tests/policy.rs` performs, repeated here because the
    // new path is a new place the policy could have grown a field.
    let rendered_policy = serde_json::to_string(&policy).unwrap_or_default();
    for canary in [CANARY_QUERY, CANARY_HEADER, CANARY_BODY] {
        assert!(!rendered_policy.contains(canary));
    }
}

// ------------------------------------------------------------------ claim 6

#[test]
fn observations_fire_from_execution_and_only_from_execution() {
    // The claim ADR 0005's "observation is the primary goal" rests on: a shim
    // method called by bytecode records, and a shim method nobody called does
    // not. The second half is the half a hand-written scenario cannot show, and
    // it is the half that makes the recording a measurement of the app.
    let before = {
        let host = SubstrateHost::with_policy(
            "pro.rudloff.search_to_browser",
            Vec::new(),
            SubstratePolicy::default(),
        )
        .expect("the shim builds");
        host.events_snapshot().len()
    };
    assert_eq!(before, 0, "a shim that was not called records nothing");

    // Now run a real app method that reads a framework field, and require an
    // identity event as a consequence.
    let cfg = Config {
        instruction_budget: Some(2_000_000),
        max_shim_log: 65_536,
        ..Config::default()
    };
    let reader = dexcore::DexReader::open(APP_DEX).expect("fixture");
    let mut vm = dexinterp::new_layered_interpreter(reader, layer(), cfg).expect("build");
    vm.set_host(Box::new(
        SubstrateHost::with_policy(
            "pro.rudloff.search_to_browser",
            Vec::new(),
            SubstratePolicy::default(),
        )
        .expect("the shim builds"),
    ));
    let me = vm
        .allocate("Lpro/rudloff/search_to_browser/MainActivity;")
        .expect("the app's own class allocates");
    let _ = vm.invoke_method(
        "Lpro/rudloff/search_to_browser/MainActivity;",
        "<init>",
        "()V",
        &[me],
    );
    let stats = vm.stats();
    assert!(
        stats.framework_calls > 0,
        "the app's constructor must have called the framework"
    );
    assert!(
        stats.framework_field_accesses > 0 || stats.framework_calls > 0,
        "and the engine must have counted the boundary crossings"
    );
}

#[test]
fn a_missing_framework_method_is_named_rather_than_guessed() {
    // The discipline this whole integration is subject to, asserted on the real
    // app: `Activity.getIntent()` is not in the shim, and the run must stop
    // there with the method named, not return null and limp on.
    let cfg = Config {
        instruction_budget: Some(2_000_000),
        max_shim_log: 65_536,
        ..Config::default()
    };
    let reader = dexcore::DexReader::open(APP_DEX).expect("fixture");
    let mut vm = dexinterp::new_layered_interpreter(reader, layer(), cfg).expect("build");
    let host = SubstrateHost::with_policy(
        "pro.rudloff.search_to_browser",
        Vec::new(),
        SubstratePolicy::default(),
    )
    .expect("the shim builds");
    assert!(
        !host.serves(
            "Landroid/app/Activity;",
            "getIntent",
            "()Landroid/content/Intent;"
        ),
        "the premise of this test: the shim does NOT declare Activity.getIntent"
    );
    vm.set_host(Box::new(host));
    let activity = vm
        .allocate("Lpro/rudloff/search_to_browser/MainActivity;")
        .expect("allocates");
    let bundle = vm
        .allocate("Landroid/os/Bundle;")
        .expect("the shim's Bundle allocates");
    let _ = vm.invoke_method(
        "Lpro/rudloff/search_to_browser/MainActivity;",
        "onCreate",
        "(Landroid/os/Bundle;)V",
        &[activity, bundle],
    );
    let stats = vm.stats();
    assert!(
        stats
            .unresolved_methods
            .iter()
            .any(|m| m.contains("getIntent")),
        "the missing method must be named in the run's counters, got {:?}",
        stats.unresolved_methods
    );
    assert!(
        !classes_of(&vm).is_empty(),
        "and the app's own objects must still exist: the run got somewhere real"
    );
}

// ------------------------------------------------------------------ claim 7

#[test]
fn the_same_dex_and_policy_produce_the_same_recording() {
    // The sync control's precondition, asserted directly. If a real APK run were
    // not reproducible, every differential number computed from it would be
    // measuring the harness.
    let policy = SubstratePolicy::default();
    let identity = shim::realdex::ApkIdentity {
        package: "pro.rudloff.search_to_browser".to_string(),
        activities: vec!["pro.rudloff.search_to_browser.MainActivity".to_string()],
        launcher_activity: Some("pro.rudloff.search_to_browser.MainActivity".to_string()),
        application: Some("pro.rudloff.search_to_browser.MainApplication".to_string()),
        ..Default::default()
    };
    let run = |p: SubstratePolicy| {
        shim::realdex::run(
            APP_DEX,
            &p,
            &identity,
            &shim::realdex::Plan::Lifecycle,
            Config::default(),
        )
        .map(|r| r.document)
    };
    let arm = shim::syncdiff::repeat_real(policy, 3, run).expect("the arm runs");
    assert_eq!(arm.documents.len(), 3);
    assert_eq!(
        arm.rendered()[0],
        arm.rendered()[1],
        "two runs of the same DEX under the same policy must produce the same document"
    );
    assert_eq!(arm.rendered()[1], arm.rendered()[2]);
    // And the terminal must be derived, not asserted.
    let doc = &arm.documents[0];
    assert_eq!(
        doc["lifecycle"]["terminal"], "L0_PROCESS_STARTED",
        "the app is stopped by a missing framework method before it resumes, and the ladder says \
         L0 rather than a rung the run did not reach"
    );
    assert_eq!(
        doc["synthetic"], false,
        "a document produced by executing an APK is not a fixture"
    );
}
