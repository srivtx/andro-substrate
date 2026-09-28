//! The synthetic capture: a scripted sequence of real shim calls.
//!
//! # Why a scenario module rather than a hand-authored JSON file
//!
//! Because the point of the deliverable is that the recording is *produced by the
//! recorder*, not typed out. Every dynamic field in
//! `shim/recordings/synthetic.recording.json` comes from a
//! [`SubstrateEvent`](crate::event::SubstrateEvent) that the shim emitted in
//! response to a call made here, and `tests/recording.rs` asserts that the
//! committed file is byte-identical to what this module produces. A fixture that
//! was hand-written would prove nothing about the observation layer and would
//! drift silently the moment a handler changed.
//!
//! # The script
//!
//! It is deliberately shaped to touch every observation group and several
//! taxonomy families, in an order an actual app might:
//!
//! 1. resolve the app's own classes and the framework classes it extends
//! 2. `Application.onCreate`, then the activity lifecycle
//! 3. read the identity fields an integrity check reads
//! 4. read `/proc/self/status` and `/proc/cpuinfo` — the kernel probes
//! 5. ask the package manager about itself and about another app
//! 6. set the content view, run the layout pass
//! 7. post to the message queue and never drain it
//! 8. build a URL with a signed query string, set an `Authorization` header, and
//!    connect — the egress denial, with the redaction on show
//! 9. `System.loadLibrary` — the `UNSATISFIED` native attempt
//! 10. catch the two exceptions the shim threw
//!
//! Step 8 is the one to read closely: the URL carries a canary token in the
//! query and the header carries a canary value, and neither appears anywhere in
//! the recording. `tests/redaction.rs` checks exactly that with the same
//! canaries.

use serde_json::Value as J;

use crate::dispatch::{Shim, ShimCaller, Value};
use crate::event::SubstrateEvent;
use crate::layout::{NodeKind, Orientation, Size, TextPolicy, View};
use crate::policy::SubstratePolicy;
use crate::recording::{build, CaptureFacts, Extras};
use crate::registry;
use crate::vfs::VPath;

/// A canary the query string carries. It must not survive into the recording.
pub const CANARY_QUERY_VALUE: &str = "sig-9f3a1c7e-do-not-record";
/// A canary the `Authorization` header value carries.
pub const CANARY_HEADER_VALUE: &str = "Bearer canary-4b7e2a91-do-not-record";

/// The classes `pro.rudloff.search_to_browser_2` defines, read from the fixture.
///
/// Hard-coded rather than parsed at run time so the scenario has no dependency
/// on a file path, and cross-checked against the fixture by
/// `tests/observation.rs::the_fixture_classes_are_what_the_scenario_assumes`.
pub const FIXTURE_CLASSES: &[&str] = &[
    "Lpro/rudloff/search_to_browser/BuildConfig;",
    "Lpro/rudloff/search_to_browser/MainActivity;",
    "Lpro/rudloff/search_to_browser/MainApplication;",
    "Lpro/rudloff/search_to_browser/R;",
];

/// What the scenario produced.
#[derive(Debug, Clone, PartialEq)]
pub struct ScenarioOutput {
    /// Every event, in order.
    pub events: Vec<SubstrateEvent>,
    /// The serialised box tree, for `probes[]`.
    pub box_tree: Option<J>,
    /// The VFS listing at the end of the run.
    pub vfs_listing: Vec<(String, u64, u32)>,
    /// The substrate policy the run was under. Carried out so a caller cannot
    /// hold a document without knowing which substrate produced it — the whole
    /// point of the policy family is that the two travel together.
    pub substrate_policy: SubstratePolicy,
    /// The document, ready to serialise.
    pub document: J,
}

/// Run the scenario under the default substrate policy and build the document.
pub fn run() -> Result<ScenarioOutput, crate::error::ShimError> {
    run_with(SubstratePolicy::default())
}

/// Run the identical script under an explicit substrate policy.
///
/// **The script is byte-for-byte the same function.** That is the whole basis of
/// the differential: the only thing that differs between two runs is the
/// `SubstratePolicy` value, so every difference in the two recordings is
/// attributable to it. A differential that used a different script per policy
/// would prove nothing, and the refactor that introduced one would be invisible.
pub fn run_with(
    substrate_policy: SubstratePolicy,
) -> Result<ScenarioOutput, crate::error::ShimError> {
    let mut shim = Shim::with_policy(
        "pro.rudloff.search_to_browser",
        FIXTURE_CLASSES.iter().map(|s| s.to_string()).collect(),
        substrate_policy,
    )?;
    shim.set_path_policy(crate::redact::PathPolicy::Full);
    shim.set_text_policy(TextPolicy::ShapeOnly);

    step_1_class_resolution(&mut shim);
    step_2_lifecycle(&mut shim);
    step_3_identity(&mut shim);
    step_4_kernel_probes(&mut shim);
    step_5_package_manager(&mut shim);
    let box_tree = step_6_layout(&mut shim)?;
    step_7_message_queue(&mut shim);
    step_8_egress(&mut shim);
    step_9_native(&mut shim);
    step_10_catch(&mut shim);

    let events = shim.take_events();
    let vfs_listing = shim.vfs().listing();
    let extras = Extras {
        box_tree: Some(serde_json::to_value(&box_tree).unwrap_or(J::Null)),
        vfs_listing,
    };
    let mut facts = CaptureFacts::fixture_with(substrate_policy);
    facts.shim_dex_sha256 = crate::emit::emit().map(|e| e.digest).unwrap_or_default();
    let document = build(&facts, &events, &extras)?;

    Ok(ScenarioOutput {
        events,
        box_tree: extras.box_tree,
        vfs_listing: extras.vfs_listing,
        substrate_policy,
        document,
    })
}

/// 1. Resolve the app's own classes and the framework classes it extends.
fn step_1_class_resolution(shim: &mut Shim) {
    for d in FIXTURE_CLASSES {
        shim.note_class_resolution(d);
    }
    // The one the loader boundary exists for: the app's `MainActivity` extends a
    // framework class the app's own dex does not define.
    shim.note_class_resolution("Landroid/app/Activity;");
    shim.note_class_resolution("Landroid/os/Build$VERSION;");
    // And one that resolves to nothing, so the recording carries an unresolvable
    // observation as well as a successful one. Absence of an unresolvable entry
    // would be the suspicious thing.
    shim.note_class_resolution("Lcom/google/android/gms/auth/GoogleAuthUtil;");
    shim.note_dynamic_class_loader("Lcom/example/plugin");
    shim.note_class_resolution("Lcom/example/plugin/Thing;");
    // `Class.forName` is the same resolution through the reflection path, which
    // is how anti-tamper code actually asks.
    let _ = shim.invoke(
        "Ljava/lang/Class;",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        &[Value::Str("android.app.Activity".into())],
    );
    let _ = shim.invoke(
        "Ljava/lang/Class;",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        &[Value::Str("org.json.JSONObject".into())],
    );
}

/// 2. The application and activity lifecycle.
fn step_2_lifecycle(shim: &mut Shim) {
    for stage in [
        ("Landroid/app/Application;", "onCreate"),
        ("Landroid/app/Activity;", "onCreate"),
        ("Landroid/app/Activity;", "onStart"),
        ("Landroid/app/Activity;", "onResume"),
    ] {
        let (class, name) = stage;
        shim.clock_mut().advance(match name {
            "onCreate" => 4,
            "onStart" => 2,
            _ => 3,
        });
        let _ = shim.invoke(class, name, "()V", &[Value::Null]);
    }
}

/// 3. The identity reads an integrity check performs.
fn step_3_identity(shim: &mut Shim) {
    // A `Build.*` read is an `sget`, not a call, so it goes through the trait's
    // `read_static` rather than through a shim method Android does not have.
    for field in ["FINGERPRINT", "MANUFACTURER", "MODEL", "BRAND"] {
        let _ = shim.read_static("Landroid/os/Build;", field);
    }
    for field in ["SDK_INT", "RELEASE"] {
        let _ = shim.read_static("Landroid/os/Build$VERSION;", field);
    }
    // The two that must come back absent. A shim that answered them would be
    // pretending to be a device, and an app that checks would then take a branch
    // the substrate cannot actually support.
    let _ = shim.invoke(
        "Ljava/lang/System;",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[Value::Str("ro.kernel.qemu".into())],
    );
    let info = shim
        .invoke("Landroid/content/pm/ApplicationInfo;", "<init>", "()V", &[])
        .expect("ApplicationInfo");
    let _ = shim.invoke(
        "Landroid/content/pm/ApplicationInfo;",
        "isDebuggable",
        "()Z",
        &[info],
    );
    // A `static final int` constant, read the way an app reads it.
    let _ = shim.read_static("Landroid/content/pm/ApplicationInfo;", "FLAG_DEBUGGABLE");
}

/// 4. The kernel probes.
///
/// Each call produces an `fs` event *and* a `probes` event, which is how a
/// substrate access lines up with a device one.
fn step_4_kernel_probes(shim: &mut Shim) {
    for path in [
        "/proc/self/status",
        "/proc/self/maps",
        "/proc/cpuinfo",
        "/proc/uptime",
        "/sys/class/power_supply/battery/capacity",
    ] {
        shim.clock_mut().advance(1);
        let _ = shim.read_path_public(path);
    }
    // An unmodelled path, so the recording shows a refusal as well as a
    // fabricated answer. An app reading /proc/self/exe on a device gets a real
    // path; here it gets ENOENT, and that difference is a finding.
    shim.clock_mut().advance(1);
    let _ = shim.read_path_public("/proc/self/exe");
}

/// 5. PackageManager, about itself and about another app.
fn step_5_package_manager(shim: &mut Shim) {
    shim.clock_mut().advance(1);
    let ctx = shim
        .invoke("Landroid/content/pm/PackageManager;", "<init>", "()V", &[])
        .unwrap_or_else(|_| shim.ref_for("Landroid/content/pm/PackageManager;"));
    let _ = shim.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[
            ctx.clone(),
            Value::Str("pro.rudloff.search_to_browser".into()),
            Value::Int(0),
        ],
    );
    // The cross-app query. Null, no exception, and the app's inter-app feature
    // quietly gone. This is the case the taxonomy calls "a prime example of the
    // class an evaluation misses".
    let _ = shim.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[
            Value::Ref("Landroid/content/pm/PackageManager;".into(), 1),
            Value::Str("com.whatsapp".into()),
            Value::Int(0),
        ],
    );
    let _ = shim.invoke(
        "Landroid/content/pm/PackageManager;",
        "queryIntentActivities",
        "(Landroid/content/Intent;I)Ljava/util/List;",
        &[
            ctx.clone(),
            Value::Ref("Landroid/content/Intent;".into(), 1),
            Value::Int(0),
        ],
    );
    for feature in [
        "android.hardware.camera",
        "android.hardware.sensor.accelerometer",
        "android.hardware.touchscreen",
    ] {
        let _ = shim.invoke(
            "Landroid/content/pm/PackageManager;",
            "hasSystemFeature",
            "(Ljava/lang/String;)Z",
            &[ctx.clone(), Value::Str(feature.into())],
        );
    }
    let _ = shim.invoke(
        "Landroid/content/Context;",
        "getSystemService",
        "(Ljava/lang/String;)Ljava/lang/Object;",
        &[ctx, Value::Str("connectivity".into())],
    );
}

/// 6. The layout pass: a real measure/layout/draw cycle over a real view tree.
fn step_6_layout(shim: &mut Shim) -> Result<crate::layout::BoxNode, crate::error::ShimError> {
    shim.clock_mut().advance(2);
    let activity = shim
        .invoke("Landroid/app/Activity;", "<init>", "()V", &[])
        .expect("Activity");
    let _ = shim.invoke(
        "Landroid/app/Activity;",
        "setContentView",
        "(I)V",
        &[activity.clone(), Value::Int(0x7f040001)],
    );
    shim.clock_mut().advance(28);

    // Install a view tree, because the app's own layout XML is not parsed
    // (SUB.RES.ARSC) and a layout pass with an empty tree would prove nothing.
    shim.set_view_tree(&activity, build_login_tree())
        .expect("install the view tree");
    shim.run_layout(Size {
        width: 1080 / 3,
        height: 2340 / 3,
    })
}

/// A sign-in form, the most common view tree in the F-Droid corpus.
fn build_login_tree() -> View {
    let mut root = View::group(
        "root",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Vertical,
    );
    root.layout_params.width = crate::layout::Dimension::MatchParent;

    let mut title = View::text(
        "title",
        "TextView",
        NodeKind::TextView,
        "Sign in to continue",
    );
    title.layout_params.width = crate::layout::Dimension::MatchParent;
    root.add(title);

    let mut email = View::text(
        "email",
        "EditText",
        NodeKind::EditText,
        "person@example.invalid",
    );
    email.layout_params.width = crate::layout::Dimension::MatchParent;
    root.add(email);

    let mut password = View::text("password", "EditText", NodeKind::EditText, "hunter2");
    password.layout_params.width = crate::layout::Dimension::MatchParent;
    root.add(password);

    let mut row = View::group(
        "row",
        "LinearLayout",
        NodeKind::LinearLayout,
        Orientation::Horizontal,
    );
    let mut ok = View::text("ok", "Button", NodeKind::Button, "Continue");
    ok.layout_params.weight = 1.0;
    row.add(ok);
    let mut cancel = View::text("cancel", "Button", NodeKind::Button, "Cancel");
    cancel.layout_params.weight = 1.0;
    row.add(cancel);
    root.add(row);

    root
}

/// 7. Post work to the queue and never drain it.
fn step_7_message_queue(shim: &mut Shim) {
    shim.clock_mut().advance(1);
    let looper = shim
        .invoke(
            "Landroid/os/Looper;",
            "getMainLooper",
            "()Landroid/os/Looper;",
            &[],
        )
        .expect("getMainLooper");
    let handler = shim
        .invoke(
            "Landroid/os/Handler;",
            "<init>",
            "(Landroid/os/Looper;)V",
            &[looper],
        )
        .expect("Handler");
    for _ in 0..3 {
        let _ = shim.invoke(
            "Landroid/os/Handler;",
            "post",
            "(Ljava/lang/Object;)Z",
            &[
                handler.clone(),
                Value::Ref("Ljava/lang/Runnable;".into(), 1),
            ],
        );
    }
    let queue = shim.ref_for("Landroid/os/MessageQueue;");
    let _ = shim.invoke("Landroid/os/MessageQueue;", "size", "()I", &[queue]);
    // Two reads of the substrate's clock, and one sleep, so the `time` axis has
    // something to transform. Under `frozen` both reads answer 0 and the sleep
    // advances nothing the app can see; under `scaled` they are multiplied.
    for name in ["uptimeMillis", "elapsedRealtime"] {
        let _ = shim.invoke("Landroid/os/SystemClock;", name, "()J", &[]);
    }
    let _ = shim.invoke("Ljava/lang/System;", "currentTimeMillis", "()J", &[]);
    shim.clock_mut().advance(5);
    let _ = shim.invoke("Ljava/lang/Thread;", "sleep", "(J)V", &[Value::Long(50)]);
    let _ = shim.invoke("Landroid/os/SystemClock;", "elapsedRealtime", "()J", &[]);
    let _ = shim.invoke("Landroid/os/Looper;", "loop", "()V", &[]);
}

/// 8. The egress denial, with the redaction on show.
///
/// Handles come from the calls that allocate them, never from a literal. An
/// earlier version of this script hard-coded `Ref(…, 1)` and silently produced a
/// recording with no network attempt in it, because by this point the shim's id
/// counter was well past 1. A synthetic fixture that quietly omits its central
/// observation is worse than no fixture, so the handles are threaded properly.
fn step_8_egress(shim: &mut Shim) {
    shim.clock_mut().advance(3);
    let url = "https://api.substrate.invalid/v1/sync?token=CANARY&sig=CANARY#anchor";
    let url = url.replace("CANARY", CANARY_QUERY_VALUE);
    let u = shim
        .invoke(
            "Ljava/net/URL;",
            "<init>",
            "(Ljava/lang/String;)V",
            &[Value::Str(url.clone())],
        )
        .expect("URL");
    let conn = shim
        .invoke(
            "Ljava/net/URL;",
            "openConnection",
            "()Ljava/net/URLConnection;",
            &[u],
        )
        .expect("openConnection");
    let _ = shim.invoke(
        "Ljava/net/HttpURLConnection;",
        "setRequestMethod",
        "(Ljava/lang/String;)V",
        std::slice::from_ref(&conn),
    );
    let _ = shim.invoke(
        "Ljava/net/URLConnection;",
        "setConnectTimeout",
        "(I)V",
        &[conn.clone(), Value::Int(15_000)],
    );
    // The header value carries a canary. It is read by nobody.
    let _ = shim.invoke(
        "Ljava/net/URLConnection;",
        "setRequestProperty",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            conn.clone(),
            Value::Str("Authorization".into()),
            Value::Str(CANARY_HEADER_VALUE.into()),
        ],
    );
    let _ = shim.invoke(
        "Ljava/net/URLConnection;",
        "setRequestProperty",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            conn.clone(),
            Value::Str("Content-Type".into()),
            Value::Str("application/json".into()),
        ],
    );
    let _ = shim.invoke(
        "Ljava/net/URLConnection;",
        "setRequestProperty",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            conn.clone(),
            Value::Str("X-Api-Key".into()),
            Value::Str(format!("key-{CANARY_HEADER_VALUE}")),
        ],
    );
    let out = shim.invoke(
        "Ljava/net/HttpURLConnection;",
        "getOutputStream",
        "()Ljava/io/OutputStream;",
        std::slice::from_ref(&conn),
    );
    if let Ok(sink) = out {
        // The body is counted, never read.
        let _ = shim.invoke(
            "Ljava/io/OutputStream;",
            "write",
            "([BII)V",
            &[
                sink,
                Value::Bytes(vec![0u8; 512]),
                Value::Int(0),
                Value::Int(512),
            ],
        );
    }
    shim.clock_mut().advance(2);
    // The terminal. Throws under the default network axis; returns normally
    // under `synthetic_loopback`. The script does not branch on either.
    let _ = shim.invoke(
        "Ljava/net/URLConnection;",
        "connect",
        "()V",
        std::slice::from_ref(&conn),
    );
    // The two reads a denied substrate refuses and a loopback substrate answers.
    // Under the default both throw `IOException`; under loopback one returns 200
    // and the other returns a handle onto a zero-length declared buffer. This is
    // the sharpest single contrast in the differential: an app that treats 200
    // as success never enters its failure path, and no policy in this crate can
    // make that the app's own doing.
    let _ = shim.invoke(
        "Ljava/net/HttpURLConnection;",
        "getResponseCode",
        "()I",
        std::slice::from_ref(&conn),
    );
    let _ = shim.invoke(
        "Ljava/net/HttpURLConnection;",
        "getInputStream",
        "()Ljava/io/InputStream;",
        std::slice::from_ref(&conn),
    );
    // A second attempt, because an app that retries is a finding and one that
    // does not is a different finding.
    shim.clock_mut().advance(1);
    let _ = shim.invoke("Ljava/net/URLConnection;", "connect", "()V", &[conn]);

    // A WebView load, routed to the same sink: one mechanism, two surfaces.
    shim.clock_mut().advance(1);
    let wv = shim
        .invoke(
            "Landroid/webkit/WebView;",
            "<init>",
            "(Landroid/content/Context;)V",
            &[Value::Str(String::new())],
        )
        .expect("WebView");
    let _ = shim.invoke(
        "Landroid/webkit/WebView;",
        "loadUrl",
        "(Ljava/lang/String;)V",
        &[
            wv,
            Value::Str(format!(
                "https://cdn.substrate.invalid/app.js?v={CANARY_QUERY_VALUE}"
            )),
        ],
    );
}

/// 9. The native attempt.
fn step_9_native(shim: &mut Shim) {
    shim.clock_mut().advance(1);
    let _ = shim.invoke(
        "Ljava/lang/System;",
        "loadLibrary",
        "(Ljava/lang/String;)V",
        &[Value::Str("nativecrypto".into())],
    );
    shim.clock_mut().advance(1);
    // An absolute path, which is the variant that reaches the linker directly.
    let _ = shim.invoke(
        "Ljava/lang/System;",
        "load",
        "(Ljava/lang/String;)V",
        &[Value::Str("/system/lib/libnativecrypto.so".into())],
    );
}

/// 10. Catch the two exceptions the shim threw.
fn step_10_catch(shim: &mut Shim) {
    shim.catch_exception("java.net.ConnectException");
    shim.clock_mut().advance(1);
    shim.catch_exception("java.lang.UnsatisfiedLinkError");
    shim.clock_mut().advance(1);
    // And a file access, so the VFS is not empty in the recording.
    if let Ok(p) = VPath::parse("/data/data/pro.rudloff.search_to_browser/files/state.json") {
        let _ = shim.write_path_public(p.as_str(), b"{\"count\":3}");
    }
    if let Ok(p) = VPath::parse("/system/build.prop") {
        let _ = shim.read_path_public(p.as_str());
    }
}

/// A descriptor of every class the shim defines, for a quick sanity check that
/// the emitted DEX and the table agree.
pub fn shim_descriptors() -> Vec<String> {
    registry::descriptors()
}
