//! The observation layer: does a shim call actually produce a structured,
//! taxonomy-tagged event, and are the event's `source`/`tier` honest?
//!
//! Every group the oracle defines gets exercised here against a **real** APK
//! extract, not against a synthetic description of one. The fixtures are the
//! committed `classes.dex` members listed in
//! `tools/dexcore/tests/FIXTURES.md`; no APK is downloaded.

use shim::event::{Detail, Group, NativeOutcome, Resolution, SubstrateEvent, Tier};
use shim::registry;
use shim::taxonomy::AssumptionId;
use shim::{Shim, ShimCaller, Value};
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// The real fixture DEXes, embedded from `tools/dexcore/tests/fixtures/`.
///
/// `include_bytes!` with a path outside this crate's directory is allowed and is
/// the only way to use the existing fixtures without duplicating or re-downloading
/// them, which the task forbids.
pub mod fixtures {
    pub const SEARCH_TO_BROWSER: &[u8] =
        include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex");
    pub const SLEEP_TIMER: &[u8] =
        include_bytes!("../../tools/dexcore/tests/fixtures/fr.smarquis.sleeptimer_16200.dex");
    pub const ADBKEYBOARD: &[u8] =
        include_bytes!("../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex");
    pub const TERMUX_BOOT: &[u8] =
        include_bytes!("../../tools/dexcore/tests/fixtures/com.termux.boot_1000.dex");
}

/// The class descriptors a fixture defines, read with `dexcore`.
fn fixture_classes(dex: &'static [u8]) -> Vec<String> {
    let leaked: &'static [u8] = dex;
    let reader = dexcore::DexReader::open(leaked).expect("fixture dex must parse");
    let mut out: Vec<String> = Vec::new();
    for i in 0..reader.class_def_count() {
        if let Ok(c) = reader.class_def(i) {
            out.push(c.descriptor.clone());
        }
    }
    out.sort();
    out
}

/// The `android.*` and `java.*` types a fixture **references**.
///
/// Not the types it *defines*: a real APK's `classes.dex` never defines a
/// framework class, it only names them in its type pool, and those names are
/// exactly the set the shim has to satisfy. This is the reference set
/// `shim/CONFORMANCE.md` measures coverage against.
fn fixture_referenced_types(dex: &'static [u8]) -> Vec<String> {
    let reader = dexcore::DexReader::open(dex).expect("fixture dex must parse");
    let mut out: Vec<String> = Vec::new();
    for i in 0..reader.type_count() {
        if let Ok(t) = reader.type_at(i) {
            if shim::classes::is_framework_namespace(&t.descriptor) {
                out.push(t.descriptor);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn shim_for(dex: &'static [u8], package: &str) -> Shim {
    Shim::new(package, fixture_classes(dex)).expect("shim")
}

fn events_of(shim: &Shim, group: Group) -> Vec<SubstrateEvent> {
    shim.events().iter().filter(|e| e.group == group).cloned().collect()
}

fn summary(shim: &Shim) -> String {
    shim.events()
        .iter()
        .map(|e| format!("[{}] {}", e.group, e.summary()))
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------- class loads

#[test]
fn a_class_load_event_is_emitted_with_its_resolution_source() {
    // The fixture's `MainActivity extends Landroid/app/Activity;` and the fixture
    // does *not* define `Landroid/app/Activity;`. That single fact is the whole
    // reason the loader boundary exists, so it is the thing to check first.
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    assert!(
        !fixture_classes(fixtures::SEARCH_TO_BROWSER)
            .contains(&"Landroid/app/Activity;".to_string()),
        "the fixture must not define the framework class, or this test proves nothing"
    );

    let (res, _) = shim.note_class_resolution("Landroid/app/Activity;");
    assert_eq!(res, Resolution::ShimDex);
    let evs = events_of(&shim, Group::Classes);
    assert_eq!(evs.len(), 1);
    let e = &evs[0];
    assert_eq!(e.assumption, Some(AssumptionId::FwClassLoader));
    assert_eq!(e.tier, Tier::T0Direct, "the substrate is the process");
    assert!(e.summary().contains("shim_dex"), "{}", e.summary());
}

#[test]
fn the_three_resolution_sources_are_distinguishable() {
    let mut app: Vec<String> = fixture_classes(fixtures::SEARCH_TO_BROWSER);
    // A hostile APK defining its own `android.app.Activity`. Legal in a dex, and
    // under the supersede decision the shim wins — which must be *recorded*, not
    // silent, or an analyst would never know the app tried.
    app.push("Landroid/app/Activity;".to_string());
    let mut shim = Shim::new("pro.rudloff.search_to_browser", app).expect("shim");

    assert_eq!(
        shim.note_class_resolution("Landroid/app/Activity;").0,
        Resolution::ShimSupersedesApp
    );
    assert_eq!(
        shim.note_class_resolution("Lpro/rudloff/search_to_browser/MainActivity;").0,
        Resolution::AppDex
    );
    assert_eq!(
        shim.note_class_resolution("Lcom/google/android/gms/Foo;").0,
        Resolution::Unresolvable
    );
    shim.note_dynamic_class_loader("Lcom/example/plugin");
    assert_eq!(
        shim.note_class_resolution("Lcom/example/plugin/Thing;").0,
        Resolution::DynamicUnavailable
    );

    let joined = summary(&shim);
    for want in [
        "shim_supersedes_app",
        "app_dex",
        "unresolvable",
        "dynamic_unavailable",
    ] {
        assert!(joined.contains(want), "missing {want} in:\n{joined}");
    }
    assert_eq!(
        shim.loader().collisions(),
        vec!["Landroid/app/Activity;".to_string()],
        "the collision set is what an analyst needs for SUB.FW.CLASS_LOADER"
    );
}

#[test]
fn the_fixture_classes_are_what_the_scenario_assumes() {
    // The scenario hard-codes the class list so it needs no file at run time.
    // This test is what stops that hard-coding from going stale.
    let real: BTreeSet<String> = fixture_classes(fixtures::SEARCH_TO_BROWSER)
        .into_iter()
        .collect();
    let assumed: BTreeSet<String> = shim::scenario::FIXTURE_CLASSES
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        real, assumed,
        "shim::scenario::FIXTURE_CLASSES is stale; the scenario would claim class loads that \
the fixture does not contain"
    );
}

// ------------------------------------------------------------------- network

#[test]
fn a_network_call_is_recorded_redacted_and_denied() {
    let mut shim = shim_for(fixtures::SLEEP_TIMER, "fr.smarquis.sleeptimer");
    let url = "https://api.substrate.invalid/v1/sync?token=SECRET-TOKEN&sig=SECRET-SIG#frag";
    shim.invoke(
        "Ljava/net/URL;",
        "<init>",
        "(Ljava/lang/String;)V",
        &[Value::Str(url.into())],
    )
    .expect("a well-formed URL constructs");
    let conn = shim
        .invoke("Ljava/net/URL;", "openConnection", "()Ljava/net/URLConnection;", &[Value::Ref("Ljava/net/URL;".into(), 1)])
        .expect("openConnection");
    shim.invoke(
        "Ljava/net/HttpURLConnection;",
        "setRequestMethod",
        "(Ljava/lang/String;)V",
        &[conn.clone(), Value::Str("POST".into())],
    )
    .expect("setRequestMethod");
    shim.invoke(
        "Ljava/net/URLConnection;",
        "setRequestProperty",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            conn.clone(),
            Value::Str("Authorization".into()),
            Value::Str("Bearer SECRET-BEARER".into()),
        ],
    )
    .expect("setRequestProperty");

    let r = shim.invoke("Ljava/net/URLConnection;", "connect", "()V", &[conn]);
    assert!(r.is_err(), "connect must fail: the substrate has no network");

    let evs = events_of(&shim, Group::Net);
    assert_eq!(evs.len(), 1, "{}", summary(&shim));
    match &evs[0].detail {
        Detail::Net {
            meta,
            method,
            headers,
            body_bytes,
            outcome,
            recorded_path,
        } => {
            assert_eq!(method.as_str(), "POST");
            assert_eq!(meta.host, "api.substrate.invalid");
            assert_eq!(meta.port, 443);
            assert_eq!(recorded_path, "/v1/sync");
            assert!(!recorded_path.contains('?'), "the invariant under test");
            assert_eq!(
                meta.query_param_names,
                vec!["token".to_string(), "sig".to_string()],
                "names survive, values do not"
            );
            assert!(meta.query_present && meta.fragment_present);
            assert!(headers.has_sensitive(), "the header NAME is a finding");
            assert!(headers.redacted_count() > 0, "and its value was withheld");
            assert_eq!(*body_bytes, None, "no body was obtainable, which is not zero");
            assert!(outcome.is_err());
        }
        other => panic!("expected a net event, got {other:?}"),
    }
    assert_eq!(evs[0].assumption, Some(AssumptionId::NetEgress));

    let rendered = format!("{:?}", shim.events());
    for secret in ["SECRET-TOKEN", "SECRET-SIG", "SECRET-BEARER", "token="] {
        assert!(
            !rendered.contains(secret),
            "{secret:?} survived into the event stream:\n{rendered}"
        );
    }
}

#[test]
fn a_webview_load_reaches_the_same_sink() {
    // One mechanism, two surfaces. An app using a WebView must be as visible as
    // one using HttpURLConnection, or SUB.FW.WEBVIEW would be a blind spot
    // rather than a measured refusal.
    let mut shim = shim_for(fixtures::TERMUX_BOOT, "com.termux.boot");
    let wv = Value::Ref("Landroid/webkit/WebView;".into(), 1);
    shim.invoke(
        "Landroid/webkit/WebView;",
        "loadUrl",
        "(Ljava/lang/String;)V",
        &[wv, Value::Str("https://cdn.substrate.invalid/a.js?v=SECRET".into())],
    )
    .expect("loadUrl records and refuses");
    let evs = events_of(&shim, Group::Net);
    assert_eq!(evs.len(), 1, "{}", summary(&shim));
    assert!(!format!("{:?}", shim.events()).contains("SECRET"));
    let j = events_of(&shim, Group::Probes);
    assert!(
        j.iter().any(|e| e.summary().contains("SIGNAL_PAT.WEBVIEW_LOAD")),
        "a WebView load must be identifiable as one, and not just look like an \
HttpURLConnection request: SUB.FW.WEBVIEW is a whole family and a study that could not \
tell the two apart would be measuring a mixture. {}",
        summary(&shim)
    );
}

// ----------------------------------------------------------------------- fs

#[test]
fn a_proc_read_is_probed_and_tagged() {
    let mut shim = shim_for(fixtures::ADBKEYBOARD, "com.android.adbkeyboard");
    let bytes = shim
        .read_path_public("/proc/self/status")
        .expect("the system tree fabricates /proc/self/status");
    let text = String::from_utf8_lossy(&bytes).to_string();
    assert!(text.contains("TracerPid:\t0"), "{text}");

    // One call, two events: the `fs` access a device arm could record, and the
    // `probes` entry carrying the taxonomy ID and the fabricated value.
    let fs = events_of(&shim, Group::Fs);
    let probes = events_of(&shim, Group::Probes);
    assert_eq!(fs.len(), 1, "{}", summary(&shim));
    assert_eq!(fs[0].assumption, Some(AssumptionId::TrustDebugDetect));
    assert!(fs[0].summary().contains("/proc/self/status"));
    assert_eq!(probes.len(), 1, "{}", summary(&shim));
    assert_eq!(probes[0].seq, 1, "the pair must be contiguous");
    assert!(probes[0].summary().contains("SIGNAL_PAT.PROC_STATUS"));
    assert!(
        probes[0].summary().contains("there is no kernel"),
        "the recording must say the value is fabricated"
    );
}

#[test]
fn an_unmodelled_proc_path_is_recorded_as_a_refusal_not_silently_dropped() {
    let mut shim = shim_for(fixtures::ADBKEYBOARD, "com.android.adbkeyboard");
    let _ = shim.read_path_public("/proc/self/exe");
    let fs = events_of(&shim, Group::Fs);
    assert_eq!(fs.len(), 1, "the *attempt* is the measurement");
    assert!(fs[0].summary().contains("enoent"), "{}", fs[0].summary());
    assert_eq!(fs[0].assumption, Some(AssumptionId::KernelProcSelf));
}

#[test]
fn the_vfs_records_reads_writes_and_denials_on_an_in_memory_tree() {
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    let data_dir = shim.data_dir().as_str().to_string();
    let path = format!("{data_dir}/files/state.json");
    shim.write_path_public(&path, b"{\"n\":1}")
        .expect("a write into the app's data dir succeeds");
    let read_back = shim.read_path_public(&path).expect("and reads back");
    assert_eq!(read_back, b"{\"n\":1}");
    // And a path outside the data dir, which is SUB.FS.SYSTEM_LAYOUT.
    assert!(shim.read_path_public("/system/build.prop").is_err());
    // And an escaping path, which is refused rather than clamped.
    assert!(shim.read_path_public("/data/../../etc/passwd").is_err());

    let fs = events_of(&shim, Group::Fs);
    let joined: String = fs.iter().map(|e| e.summary()).collect();
    assert!(joined.contains("files/state.json"), "{joined}");
    assert!(joined.contains("/system/build.prop"), "{joined}");
    // Nothing reached a real disk: the shim has no `std::fs` surface at all, and
    // `tests/no_side_channels.rs` proves it by scanning the source.
    assert!(!shim.vfs().listing().is_empty());
    assert!(shim.vfs().node_count() < 65_536);
}

#[test]
fn a_file_outside_the_data_dir_is_tagged_system_layout() {
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    let _ = shim.read_path_public("/sdcard/foo");
    let fs = events_of(&shim, Group::Fs);
    assert!(fs.iter().any(|e| e.assumption == Some(AssumptionId::FsSystemLayout)));
}

// ----------------------------------------------------------------------- jni

#[test]
fn a_native_method_call_yields_unsatisfied() {
    let mut shim = shim_for(fixtures::SLEEP_TIMER, "fr.smarquis.sleeptimer");
    let r = shim.invoke(
        "Ljava/lang/System;",
        "loadLibrary",
        "(Ljava/lang/String;)V",
        &[Value::Str("nativecrypto".into())],
    );
    assert_eq!(r.unwrap_err().kind(), "UnsatisfiedLinkError");

    let jni = events_of(&shim, Group::Jni);
    assert_eq!(jni.len(), 1, "{}", summary(&shim));
    match &jni[0].detail {
        Detail::Jni { library, outcome, .. } => {
            assert_eq!(library.as_deref(), Some("nativecrypto"));
            assert_eq!(*outcome, NativeOutcome::Unsatisfied);
            // There is no success variant to reach, which is the point.
            assert!(matches!(outcome, NativeOutcome::Unsatisfied));
        }
        other => panic!("expected a jni event, got {other:?}"),
    }
    assert_eq!(jni[0].assumption, Some(AssumptionId::NativeLoadLibrary));

    // And the exception it throws is recorded, with a stack, and is catchable.
    let exc = events_of(&shim, Group::Exceptions);
    assert!(exc.iter().any(|e| e.summary().contains("UnsatisfiedLinkError")));
    assert!(shim.pending_exception().is_some());
    shim.catch_exception("java.lang.UnsatisfiedLinkError");
    assert!(
        events_of(&shim, Group::Exceptions)
            .iter()
            .any(|e| matches!(&e.detail, Detail::Exceptions { caught: Some(true), .. })),
        "{}",
        summary(&shim)
    );
}

// ------------------------------------------------------------------ exceptions

#[test]
fn a_thrown_exception_carries_a_stack_and_a_tier() {
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    let _ = shim.invoke(
        "Ljava/lang/Class;",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        &[Value::Str("org.json.JSONObject".into())],
    );
    let exc = events_of(&shim, Group::Exceptions);
    assert_eq!(exc.len(), 1, "{}", summary(&shim));
    match &exc[0].detail {
        Detail::Exceptions { class, stack, fatal, caught, .. } => {
            assert_eq!(class, "java.lang.ClassNotFoundException");
            assert!(!stack.is_empty(), "a stack is required by the schema");
            assert!(!fatal, "a missing class is not fatal to the run");
            assert_eq!(*caught, Some(false));
        }
        other => panic!("expected an exception, got {other:?}"),
    }
}

// --------------------------------------------------------------------- probes

#[test]
fn build_reads_are_probed_with_values_and_the_right_id() {
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    for field in ["FINGERPRINT", "MANUFACTURER"] {
        shim.read_static("Landroid/os/Build;", field)
            .unwrap_or_else(|e| panic!("Build.{field}: {e}"));
    }
    // A `static final int` constant, read the way an app reads it: an `sget`
    // that `d8` will usually have inlined away, so a device arm cannot see it.
    shim.read_static("Landroid/content/pm/ApplicationInfo;", "FLAG_DEBUGGABLE")
        .expect("a static final int resolves");
    let probes = events_of(&shim, Group::Probes);
    assert_eq!(probes.len(), 3, "{}", summary(&shim));
    for p in &probes[..2] {
        assert_eq!(p.assumption, Some(AssumptionId::BuildFingerprint));
        assert!(p.summary().contains("SIGNAL_PAT.BUILD_FIELD"));
        assert!(
            p.summary().contains("andro-substrate"),
            "the value must be reported, because an app branching on the model needs a \
value, not just a field name: {}",
            p.summary()
        );
    }
    assert!(probes[2].summary().contains("SIGNAL_PAT.STATIC_FIELD"));
    assert_eq!(
        shim.read_static("Landroid/content/pm/ApplicationInfo;", "FLAG_DEBUGGABLE")
            .unwrap(),
        Value::Int(0x0002),
        "a static final int must carry its real platform value, or a layout the app wrote \
with MATCH_PARENT would measure against a bogus constant"
    );
    // An absent property is observable as an *absence*, which is a different fact
    // from a value and is the whole point of `SUB.BUILD.EMULATOR`.
    shim.invoke(
        "Ljava/lang/System;",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[Value::Str("ro.kernel.qemu".into())],
    )
    .expect("getProperty");
}

#[test]
fn a_cross_app_package_query_is_recorded_as_silently_not_installed() {
    let mut shim = shim_for(fixtures::SLEEP_TIMER, "fr.smarquis.sleeptimer");
    let pm = Value::Ref("Landroid/content/pm/PackageManager;".into(), 1);
    let self_r = shim.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[pm.clone(), Value::Str("fr.smarquis.sleeptimer".into()), Value::Int(0)],
    );
    assert!(self_r.is_ok(), "a self-query answers");
    let other = shim.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[pm, Value::Str("com.whatsapp".into()), Value::Int(0)],
    );
    assert_eq!(other.unwrap(), Value::Null, "and every other package is null");

    let ids: Vec<AssumptionId> = events_of(&shim, Group::Probes)
        .iter()
        .filter_map(|e| e.assumption)
        .collect();
    assert!(ids.contains(&AssumptionId::IpcPackageManagerSelf));
    assert!(
        ids.contains(&AssumptionId::IpcPackageManagerOther),
        "the cross-app query is the case the taxonomy calls out"
    );
    assert!(summary(&shim).contains("not an error"), "{}", summary(&shim));
}

#[test]
fn a_system_service_other_than_the_package_manager_is_null_and_recorded() {
    let mut shim = shim_for(fixtures::ADBKEYBOARD, "com.android.adbkeyboard");
    for svc in ["connectivity", "window", "package"] {
        let v = shim
            .invoke(
                "Landroid/content/Context;",
                "getSystemService",
                "(Ljava/lang/String;)Ljava/lang/Object;",
                &[Value::Ref("Landroid/content/Context;".into(), 1), Value::Str(svc.into())],
            )
            .expect("getSystemService");
        if svc == "package" {
            assert!(matches!(v, Value::Ref(..)), "package returns a shim service");
        } else {
            assert_eq!(v, Value::Null);
        }
    }
    assert_eq!(
        events_of(&shim, Group::Probes)
            .iter()
            .filter(|e| e.assumption == Some(AssumptionId::IpcSystemService))
            .count(),
        3
    );
}

#[test]
fn the_message_queue_records_work_that_will_never_run() {
    let mut shim = shim_for(fixtures::ADBKEYBOARD, "com.android.adbkeyboard");
    for _ in 0..3 {
        shim.invoke(
            "Landroid/os/Handler;",
            "post",
            "(Ljava/lang/Object;)Z",
            &[Value::Ref("Landroid/os/Handler;".into(), 1), Value::Ref("Ljava/lang/Runnable;".into(), 1)],
        )
        .expect("post");
    }
    assert_eq!(shim.queue_depth(), 3);
    let depth = shim
        .invoke("Landroid/os/MessageQueue;", "size", "()I", &[Value::Ref("Landroid/os/MessageQueue;".into(), 1)])
        .expect("size");
    assert_eq!(depth, Value::Int(3));
    // The divergence is SUB.TIME.VSYNC: the queue never drains, because there is
    // no display and therefore no vsync.
    assert!(shim
        .events()
        .iter()
        .any(|e| e.assumption == Some(AssumptionId::TimeVsync)));
}

// --------------------------------------------------------------- the boundary

#[test]
fn the_trait_boundary_is_usable_by_an_interpreter_and_by_a_mock() {
    // The contract another agent codes against. A mock satisfies it without the
    // shim's state, so the interpreter half can be built and tested in parallel.
    let mut mock = shim::dispatch::testing::MockCaller::new();
    assert!(shim::ShimCaller::resolves(
        &mock,
        "Landroid/os/Bundle;",
        "putString",
        "(Ljava/lang/String;Ljava/lang/String;)V"
    ));
    let r = mock
        .invoke(
            "Landroid/os/Bundle;",
            "putString",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[Value::Null],
        )
        .expect("a mock returns a value");
    assert_eq!(r, Value::Null, "a void method returns Null");
    assert_eq!(mock.calls().len(), 1);
    assert_eq!(mock.calls()[0].name, "putString");

    // And the real shim satisfies the same trait, with the same resolution
    // answers, which is the property the interpreter depends on.
    let real: &mut dyn ShimCaller = &mut Shim::new("a.b", vec![]).expect("shim");
    assert!(real.resolves("Landroid/os/Bundle;", "putString", ""));
    assert!(!real.resolves("Landroid/os/Bundle;", "noSuchMethod", ""));
    // A fresh shim has observed nothing, and saying so is part of the contract:
    // an `events()` that started non-empty would mean something recorded an
    // observation nobody asked for.
    let before = real.events().len();
    assert_eq!(before, 0, "a fresh shim must have an empty event stream");
    let _ = real.invoke("Landroid/os/Bundle;", "isEmpty", "()Z", &[Value::Ref("Landroid/os/Bundle;".into(), 1)]);
    assert!(real.events().len() > before, "a call must be observable");
}

#[test]
fn a_method_on_a_superclass_resolves_against_a_subclass() {
    // A loader resolves a superclass method against a subclass call site. A shim
    // that only matched the exact class would report NoSuchMethod for
    // `activity.getSystemService`, which is a divergence in the *loader* and the
    // least useful kind there is.
    let mut shim = shim_for(fixtures::SEARCH_TO_BROWSER, "pro.rudloff.search_to_browser");
    let r = shim.invoke(
        "Landroid/app/Activity;",
        "getSystemService",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        &[Value::Ref("Landroid/app/Activity;".into(), 1), Value::Str("alarm".into())],
    );
    assert!(r.is_ok(), "Activity inherits Context.getSystemService");
    // And a Widget inherits TextView's method three levels up.
    let r = shim.invoke(
        "Landroid/widget/EditText;",
        "setText",
        "(Ljava/lang/CharSequence;)V",
        &[Value::Ref("Landroid/widget/EditText;".into(), 1), Value::Str("x".into())],
    );
    assert!(r.is_ok());
}

#[test]
fn a_method_the_shim_does_not_define_is_a_nosuchmethod_not_a_silent_zero() {
    let mut shim = shim_for(fixtures::SLEEP_TIMER, "fr.smarquis.sleeptimer");
    let r = shim.invoke("Landroid/view/View;", "noSuchMethod", "()V", &[]);
    assert_eq!(r.unwrap_err().kind(), "NoSuchMethod");
}

#[test]
fn every_event_sequence_is_gap_free_and_monotonic() {
    // The oracle validator rejects out-of-order lifecycle events, and a recording
    // is only joinable if `seq` is a dense index into the arrays it indexes.
    let mut shim = shim_for(fixtures::TERMUX_BOOT, "com.termux.boot");
    for step in 0..8u64 {
        shim.clock_mut().advance(step);
        let _ = shim.note_class_resolution("Landroid/os/Build;");
        let _ = shim.read_path_public("/proc/uptime");
        let _ = shim.invoke("Landroid/util/Log;", "d", "(ILjava/lang/String;Ljava/lang/String;)I",
            &[Value::Int(3), Value::Str("t".into()), Value::Str("m".into())]);
    }
    let evs = shim.events();
    for (i, e) in evs.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "sequence must be dense");
        if i > 0 {
            assert!(
                e.t_mono_ms >= evs[i - 1].t_mono_ms,
                "the virtual clock is monotonic by construction"
            );
        }
    }
}

#[test]
fn every_taxonomy_id_the_shim_emits_is_in_the_taxonomy_document() {
    // The oracle schema validates an `assumption_id`'s SHAPE, not its membership.
    // This crate does the membership check, and this test ties it to the
    // document so neither can drift into fiction.
    let doc = include_str!("../../docs/divergence-taxonomy.md");
    let mut shim = shim_for(fixtures::SLEEP_TIMER, "fr.smarquis.sleeptimer");
    // Provoke one of each kind so the sweep is not vacuous.
    let _ = shim.note_class_resolution("Landroid/app/Activity;");
    let _ = shim.read_path_public("/proc/self/status");
    let _ = shim.read_path_public("/sys/class/power_supply/battery/capacity");
    let _ = shim.read_static("Landroid/os/Build;", "FINGERPRINT");
    let _ = shim.invoke("Ljava/lang/System;", "loadLibrary", "(Ljava/lang/String;)V", &[Value::Str("x".into())]);
    let _ = shim.invoke("Landroid/content/pm/PackageManager;", "hasSystemFeature", "(Ljava/lang/String;)Z",
        &[Value::Ref("Landroid/content/pm/PackageManager;".into(), 1), Value::Str("android.hardware.camera".into())]);
    let _ = shim.invoke("Landroid/os/Handler;", "post", "(Ljava/lang/Object;)Z",
        &[Value::Ref("Landroid/os/Handler;".into(), 1), Value::Ref("Ljava/lang/Runnable;".into(), 1)]);
    // net, fs and the serialization surface, so the sweep touches every group.
    let _ = shim.invoke("Ljava/net/URL;", "<init>", "(Ljava/lang/String;)V",
        &[Value::Str("https://h.invalid/p?q=1".into())]);
    let _ = shim.invoke("Ljava/net/URL;", "openConnection", "()Ljava/net/URLConnection;",
        &[Value::Ref("Ljava/net/URL;".into(), 1)]);
    let _ = shim.invoke("Ljava/net/URLConnection;", "connect", "()V",
        &[Value::Ref("Ljava/net/HttpURLConnection;".into(), 1)]);
    let _ = shim.write_path_public("/data/data/fr.smarquis.sleeptimer/files/a", b"x");
    let _ = shim.invoke("Landroid/os/Bundle;", "putString", "(Ljava/lang/String;Ljava/lang/String;)V",
        &[Value::Ref("Landroid/os/Bundle;".into(), 1), Value::Str("k".into()), Value::Str("v".into())]);
    let _ = shim.invoke("Landroid/content/Context;", "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
        &[Value::Ref("Landroid/content/Context;".into(), 1), Value::Str("window".into())]);
    let _ = shim.invoke("Landroid/app/Activity;", "setContentView", "(I)V",
        &[Value::Ref("Landroid/app/Activity;".into(), 1), Value::Int(7)]);
    let _ = shim.invoke("Ljava/lang/Thread;", "sleep", "(J)V", &[Value::Long(5)]);

    let mut emitted: BTreeSet<AssumptionId> = BTreeSet::new();
    for e in shim.events() {
        if let Some(id) = e.assumption {
            emitted.insert(id);
        }
    }
    assert!(emitted.len() >= 8, "the sweep should reach several families: {emitted:?}");
    for id in emitted {
        assert!(
            doc.contains(id.as_str()),
            "{} is not in docs/divergence-taxonomy.md",
            id.as_str()
        );
        assert!(AssumptionId::lookup(id.as_str()).is_some());
    }
    // And the whole registered set, not just the exercised one, must be real.
    for id in AssumptionId::ALL {
        assert!(doc.contains(id.as_str()), "{} is unregistered in the taxonomy", id.as_str());
    }
}

#[test]
fn the_fixture_census_is_what_conformance_measures_against() {
    // Shared setup for `conformance.rs`, exposed here so the measurement in
    // CONFORMANCE.md can be recomputed by anyone.
    static SET: OnceLock<BTreeSet<String>> = OnceLock::new();
    let all = SET.get_or_init(|| {
        let mut out = BTreeSet::new();
        for dex in [
            fixtures::SEARCH_TO_BROWSER,
            fixtures::SLEEP_TIMER,
            fixtures::ADBKEYBOARD,
            fixtures::TERMUX_BOOT,
        ] {
            out.extend(fixture_referenced_types(dex));
        }
        out
    });
    assert!(all.len() > 60, "the reference set should be substantial: {}", all.len());
    let covered: usize = all
        .iter()
        .filter(|c| registry::find(c).is_some())
        .count();
    eprintln!(
        "android.*/java.* types referenced by 4 real DEX fixtures: {}, covered by the shim: \
{covered} ({:.1}%)",
        all.len(),
        100.0 * covered as f64 / all.len() as f64
    );
    assert!(covered > 20, "the shim should cover a real fraction, not a token amount");
}
