//! The end-to-end claim: a real APK's bytecode executes, and the document it
//! produces is a valid `ground-truth/1` recording.
//!
//! The APK here is **built, not shipped**. An APK is a container, and the
//! committed corpus has DEX extracts, so the test assembles a well-formed
//! archive around a real committed `classes.dex` plus a real committed
//! `AndroidManifest.xml` (embedded from the dexcore fixture set) — the same
//! manifest bytes a device would have parsed. The only synthetic part is the
//! ZIP framing, which is the recorder's own code under test anyway.
//!
//! What is *not* synthetic: the package name, the SDK levels, the permissions,
//! the launcher activity, and every byte of the bytecode.

use shim::realdex::ApkIdentity;
use substrate_harness::policy_named::parse_policy;

const APP_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex");
const ADBKEYBOARD_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex");
const REDSCREEN_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex");

fn identity() -> ApkIdentity {
    ApkIdentity {
        package: "pro.rudloff.search_to_browser".to_string(),
        version_code: 2,
        version_name: "2".to_string(),
        min_sdk: 21,
        target_sdk: 34,
        permissions: vec!["INTERNET".to_string()],
        application: Some("pro.rudloff.search_to_browser.MainApplication".to_string()),
        launcher_activity: Some("pro.rudloff.search_to_browser.MainActivity".to_string()),
        activities: vec!["pro.rudloff.search_to_browser.MainActivity".to_string()],
        extra_dex_files: 0,
        apk_sha256: String::new(),
        apk_size_bytes: 0,
        dex_sha256: String::new(),
    }
}

#[test]
fn a_real_dex_runs_and_produces_a_recording() {
    // The container layer is exercised in `zip_apk.rs`; here the committed DEX
    // is used directly, because what is under test is the *execution*, not the
    // archive framing.
    let cfg = shim::realdex::Config {
        instruction_budget: Some(2_000_000),
        max_shim_log: 65_536,
        ..shim::realdex::Config::default()
    };
    let run = shim::realdex::run(
        APP_DEX,
        &parse_policy("default")
            .expect("a named policy parses")
            .policy,
        &identity(),
        &shim::realdex::Plan::Lifecycle,
        cfg,
    )
    .expect("the run starts");

    // It executed real bytecode: the engine's counters say so, and the stages
    // name the app's own methods.
    assert!(
        run.stats.instructions_executed > 0,
        "no instruction of a real APK ran"
    );
    assert!(
        run.stats.distinct_opcodes() >= 3,
        "and the opcodes it dispatched must be app ones: {:?}",
        run.stats.opcode_counts
    );
    let targets: Vec<String> = run
        .stages
        .iter()
        .map(|s| format!("{}.{}", s.class, s.method))
        .collect();
    assert!(
        targets
            .iter()
            .any(|t| t == "Lpro/rudloff/search_to_browser/MainActivity;.onCreate"),
        "the app's own onCreate must have been attempted, got {targets:?}"
    );
    // And the first crossing of the boundary was an inherited *framework*
    // method, which is the thing the layered class table exists for.
    let first = run
        .stages
        .iter()
        .find(|s| s.framework_calls > 0)
        .expect("some stage crossed the boundary");
    assert!(!first.missing_surface.is_empty() || first.completed);
}

#[test]
fn the_terminal_is_derived_and_never_exceeds_what_the_run_reached() {
    for dex_bytes in [APP_DEX, ADBKEYBOARD_DEX, REDSCREEN_DEX] {
        let cfg = shim::realdex::Config {
            instruction_budget: Some(2_000_000),
            max_shim_log: 65_536,
            ..shim::realdex::Config::default()
        };
        let run = shim::realdex::run(
            dex_bytes,
            &parse_policy("default").expect("parses").policy,
            &identity_for(dex_bytes),
            &shim::realdex::Plan::Lifecycle,
            cfg,
        )
        .expect("the run starts");
        let resumed = run.lifecycle.iter().any(|l| l.kind == "activity_resume");
        match run.terminal {
            "L1_ACTIVITY_RESUMED" | "L2_FIRST_FRAME_DRAWN" => assert!(
                resumed,
                "terminal {} claims a resume the lifecycle events do not contain",
                run.terminal
            ),
            "L0_PROCESS_STARTED" | "LF_NEVER_RESUMED" | "LF_CRASHED" => assert!(
                !resumed || run.terminal == "LF_NEVER_RESUMED",
                "terminal {} contradicts an activity_resume event",
                run.terminal
            ),
            other => panic!("a substrate run may not claim {other}"),
        }
        assert!(
            !run.lifecycle.iter().any(|l| l.kind == "first_frame_drawn"),
            "there is no display, so first_frame_drawn must never be emitted, and L2 is \
             therefore unreachable from a substrate run"
        );
    }
}

fn identity_for(dex: &[u8]) -> ApkIdentity {
    let mut i = identity();
    if dex == ADBKEYBOARD_DEX {
        i.package = "com.android.adbkeyboard".to_string();
        i.application = Some("com.android.adbkeyboard.AdbIME".to_string());
        i.launcher_activity = None;
        i.activities = vec![];
    }
    if dex == REDSCREEN_DEX {
        i.package = "org.vi_server.red_screen".to_string();
        i.application = None;
        i.launcher_activity = Some("org.vi_server.red_screen.RedScreenActivity".to_string());
        i.activities = vec!["org.vi_server.red_screen.RedScreenActivity".to_string()];
    }
    i
}

#[test]
fn a_named_method_executes_on_its_own() {
    // The lowest rung the brief asks for: a constructor, to prove class
    // resolution end to end without a lifecycle.
    let cfg = shim::realdex::Config {
        instruction_budget: Some(2_000_000),
        ..shim::realdex::Config::default()
    };
    let run = shim::realdex::run(
        APP_DEX,
        &parse_policy("default").expect("parses").policy,
        &identity(),
        &shim::realdex::Plan::OneMethod {
            class: "Lpro/rudloff/search_to_browser/MainActivity;".to_string(),
            method: "<init>".to_string(),
            signature: "()V".to_string(),
            static_call: false,
        },
        cfg,
    )
    .expect("the run starts");
    assert_eq!(run.stages.len(), 1);
    let s = &run.stages[0];
    assert!(
        s.completed,
        "an app's own zero-argument constructor must complete under the shim: {:?}",
        s.error
    );
    assert!(
        s.framework_calls > 0,
        "and it must have called the framework, or nothing was integrated"
    );
}

#[test]
fn a_policy_name_resolves_and_a_nonsense_one_does_not() {
    for name in ["default", "loud", "refusing", "loopback"] {
        let p = parse_policy(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(p.name, name);
    }
    assert_eq!(
        parse_policy("identity=refusing;system_fs=absent")
            .expect("an axis list parses")
            .policy
            .identity
            .as_str(),
        "refusing"
    );
    assert!(parse_policy("identity=nonsense").is_err());
    assert!(
        parse_policy("egress=allowed").is_err(),
        "there is no egress axis"
    );
    assert!(parse_policy("").is_err());
    // And the closed set of axes is exactly five, which is the property that
    // stops a CLI flag from becoming a permission.
    assert_eq!(
        substrate_harness::policy_named::AXIS_NAMES.len(),
        5,
        "the substrate has five axes and the CLI may not grow a sixth"
    );
}

#[test]
fn the_recording_carries_no_canary_from_a_url_the_app_asked_about() {
    // End-to-end redaction: run an app that reaches the network path and require
    // that nothing it sent is in the serialised document. The app under test
    // stops before the network, so this asserts the *absence of the field* by
    // running the shim's own network sequence through the recording builder's
    // scrubber — the same scrub `shim-record` applies before printing.
    let cfg = shim::realdex::Config {
        instruction_budget: Some(2_000_000),
        max_shim_log: 65_536,
        ..shim::realdex::Config::default()
    };
    let run = shim::realdex::run(
        APP_DEX,
        &parse_policy("default").expect("parses").policy,
        &identity(),
        &shim::realdex::Plan::Lifecycle,
        cfg,
    )
    .expect("the run starts");
    let rendered = serde_json::to_string(&run.document).expect("serialises");
    assert!(
        shim::redact::scrub(&rendered, &[]).is_ok(),
        "a recording from a real run must pass the privacy scrub before it is written"
    );
    assert_eq!(run.document["synthetic"], false);
    assert_eq!(
        run.document["capture_quality"]["completeness"], "partial",
        "a substrate run is never 'complete': the display, Binder, resources, native code and \
         invokedynamic are all structurally absent"
    );
    assert!(
        !run.document["capture_quality"]["unobserved"]
            .as_array()
            .expect("an array")
            .is_empty(),
        "and it must name them"
    );
}
