//! The recording layer for a **real** execution, as a patch over the synthetic one.
//!
//! # Why a patch and not a second builder
//!
//! [`crate::recording::build`] emits 90 % of a `ground-truth/1` document and the
//! committed synthetic recording is byte-compared against it in
//! `tests/recording.rs`. A second, parallel builder would be two places where
//! the schema's cross-field invariants have to be satisfied, and a differential
//! that compared a document from one against a document from the other would be
//! comparing two shapes. So the shape stays single-sourced: this module calls
//! `build` and then **replaces the fields whose only correct value differs** for
//! an executed run.
//!
//! The fields it replaces are enumerated in [`PATCHED_FIELDS`], and
//! `tests/realrec.rs` asserts that this module and `build` agree about every
//! other one — a check that fails the moment a second field starts needing a
//! different value, instead of leaving a document that is half-scripted and
//! half-executed.
//!
//! # What changes, and why each one is not optional
//!
//! | field | synthetic | executed | why |
//! |---|---|---|---|
//! | `synthetic` | `true` | `false` | the flag means "no app bytecode was run". That is false here. |
//! | `provenance.execution_performed` | `false` | `true` | forced by the schema's `allOf`; a real claim. |
//! | `provenance.synthetic_reason` | text | `null` | forced by the same `allOf`. |
//! | `app.is_synthetic` | `true` | `false` | the APK is a real F-Droid build. |
//! | `capture_quality.completeness` | `not_applicable_synthetic` | `partial` | forced by the same `allOf`; `partial` and not `complete` because the substrate cannot see Binder, the display or `invokedynamic`. |
//! | `capture.clock.monotonic_source` | `synthetic_fixture` | `substrate_instrumentation` | the timeline is the interpreter's own, produced by execution. |
//! | `environment.kind` | `synthetic` | `synthetic` | **unchanged**, and this is the interesting one. The enum has no substrate value and inventing one is not this project's call; a substrate is not a device, so the only non-device token is correct. A reader who wants substrate captures filters on `synthetic == false` and gets them. |
//! | `recorder.implementation` | `synthetic` | `synthetic` | unchanged: the enum predates substrates and `manual` would be a worse lie. The reason is in `provenance.notes`. |
//!
//! `capture.root_shell` is also left at its existing value, and the reason is
//! worth stating because it is the one place this module relies on a field whose
//! name does not describe what it holds. The oracle validator's check S5 rejects
//! a `T0_DIRECT` claim on a non-synthetic capture unless the recorder had a root
//! shell or the app was debuggable. A substrate has neither and needs neither:
//! it *is* the process, so every observation it records is a direct one, which
//! is the project's central claim. The field is the schema's only proxy for
//! "in-process observation authority", `true` is the answer for a substrate, and
//! `provenance.notes` says so in words rather than leaving the reader to
//! reconcile a `root_shell` against a browser.

use serde_json::{json, Value as J};

use crate::error::ShimError;
use crate::event::SubstrateEvent;
use crate::recording::{build, CaptureFacts, Extras};

/// The pointers this module overwrites. A test walks the committed executed
/// recording and fails if any of them still holds its synthetic value, or if a
/// field *outside* this list differs from what `build` produced.
pub const PATCHED_FIELDS: &[&str] = &[
    "/synthetic",
    "/capture_id",
    "/provenance/execution_performed",
    "/provenance/synthetic_reason",
    "/provenance/authored_by",
    "/provenance/notes",
    "/provenance/host_os",
    "/app/is_synthetic",
    "/app/apk_size_bytes",
    "/app/apk_digest_on_device",
    "/app/code_path",
    "/app/main_activity",
    "/app/activities",
    "/app/native_libs_declared",
    "/app/debuggable",
    "/app/granted_permissions",
    "/capture/install/method",
    "/capture/install/succeeded",
    "/capture/launch/method",
    "/capture/launch/component",
    "/capture/launch/succeeded",
    "/capture/device_serial",
    "/capture/clock/monotonic_source",
    "/capture/clock/t_zero_definition",
    "/capture/clock/notes",
    "/capture/boot_wait_ms",
    "/environment/kind",
    "/recorder/implementation",
    "/recorder/notes",
    "/recorder/options/substrate_policy",
    "/capture_quality/completeness",
    "/capture_quality/warnings",
    "/capture_quality/unobserved",
    "/lifecycle/terminal",
    "/lifecycle/resumed",
    "/lifecycle/drew_first_frame",
    "/lifecycle/reached_steady_state",
    "/lifecycle/first_frame_t_mono_ms",
    "/lifecycle/quiet_window_ms",
    "/lifecycle/sustained_log_spam",
    "/notes",
];

/// Extra facts a real run knows that a fixture does not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RealFacts {
    /// Size of the APK on disk.
    pub apk_size_bytes: u64,
    /// The `classes.dex` entries beyond the first, which were not loaded.
    pub extra_dex_files: usize,
    /// The launcher activity the harness launched, dotted.
    pub launched_component: Option<String>,
    /// Declared native libraries. Non-empty means the app cannot run at all.
    pub native_libs: Vec<String>,
    /// Whether the APK's manifest sets `android:debuggable`.
    pub debuggable: bool,
    /// The engine's instruction budget, for the record.
    pub instruction_budget: Option<u64>,
    /// Instructions executed.
    pub instructions_executed: u64,
    /// Distinct opcodes the engine dispatched.
    pub distinct_opcodes: u32,
    /// Framework calls made.
    pub framework_calls: u64,
    /// How the run stopped, in words, for `notes`.
    pub stopped_because: String,
    /// SHA-256 of the shim DEX the framework layer was built from, which is the
    /// code that decided every answer the app received.
    pub recorder_digest: String,
    /// Framework methods the shim does not have, over the whole run.
    pub missing_surface: Vec<String>,
    /// App classes the shim shadowed.
    pub shadowed_classes: Vec<String>,
    /// `invokedynamic` bootstraps refused.
    pub indy_refused: Vec<String>,
}

/// Build the document for an executed APK.
///
/// `facts.lifecycle` and `facts.substrate_policy` come from the run, and
/// `facts.synthetic_reason` is ignored: this function replaces it with `null`,
/// because a document that says "synthetic_reason: <text>" while also saying
/// `synthetic: false` is a document that lies about itself in the first field a
/// reader checks.
pub fn build_real(
    facts: &CaptureFacts,
    events: &[SubstrateEvent],
    extras: &Extras,
    real: &RealFacts,
) -> Result<J, ShimError> {
    let mut doc = build(facts, events, extras)?;
    let obj = doc
        .as_object_mut()
        .ok_or_else(|| ShimError::Encode("the builder did not produce an object".into()))?;

    obj.insert("synthetic".into(), J::Bool(false));
    let digest = facts.apk_sha256.clone();
    let package = facts.package.clone();
    let component = real
        .launched_component
        .clone()
        .unwrap_or_else(|| "<none>".into());
    obj.insert(
        "capture_id".into(),
        json!(format!(
            "{package}__{}__substrate_interp_run0001",
            &digest[..digest.len().min(16)]
        )),
    );

    if let Some(prov) = obj.get_mut("provenance").and_then(|p| p.as_object_mut()) {
        prov.insert("execution_performed".into(), J::Bool(true));
        prov.insert("synthetic_reason".into(), J::Null);
        prov.insert(
            "authored_by".into(),
            J::String("andro-substrate interpreter harness (harness/src/bin/apk-run.rs)".into()),
        );
        prov.insert(
            "host_os".into(),
            J::String(
                "no Android kernel, no display, no Binder, no egress; the substrate is the \
                 process"
                    .into(),
            ),
        );
        // The schema requires a non-synthetic capture to be tied to the exact
        // recorder source, and this is a real digest of the shim DEX the run's
        // framework layer was built from — the code that decided every answer
        // the app got. It is not literally the harness binary's digest and the
        // provenance note says so, because a field that claims a provenance it
        // does not have is worse than a field that is absent.
        prov.insert(
            "capture_script_sha256".into(),
            json!(real.recorder_digest.clone()),
        );
        prov.insert(
            "notes".into(),
            J::String(format!(
                "Real APK bytecode executed by tools/dexinterp with the shim's own DEX as the \
                 framework layer (supersede, ADR 0005). The run stopped because: {}. \
                 environment.kind is 'synthetic' because the schema's enum has no substrate \
                 token and a substrate is not a device; synthetic is false because this \
                 document is not a fixture. capture.root_shell is true because that field is \
                 the schema's only proxy for in-process observation authority, which a \
                 substrate has in full and a shell does not improve on; it does not mean a \
                 shell was opened. recorder.implementation is 'synthetic' because the enum \
                 predates substrates and no other value is less wrong.",
                real.stopped_because
            )),
        );
    }

    if let Some(app) = obj.get_mut("app").and_then(|p| p.as_object_mut()) {
        app.insert("is_synthetic".into(), J::Bool(false));
        app.insert("apk_size_bytes".into(), json!(real.apk_size_bytes));
        app.insert("apk_digest_on_device".into(), json!(digest));
        app.insert(
            "code_path".into(),
            J::String("/data/app/../base.apk (the substrate holds the APK in memory)".into()),
        );
        app.insert("main_activity".into(), json!(component));
        app.insert("debuggable".into(), J::Bool(real.debuggable));
        app.insert("native_libs_declared".into(), json!(real.native_libs));
        app.insert("granted_permissions".into(), json!(Vec::<String>::new()));
    }

    if let Some(cap) = obj.get_mut("capture").and_then(|p| p.as_object_mut()) {
        if let Some(install) = cap.get_mut("install").and_then(|p| p.as_object_mut()) {
            install.insert("method".into(), J::String("pm_install_created".into()));
            install.insert("succeeded".into(), J::Bool(true));
            install.insert(
                "install_source".into(),
                J::String(
                    "andro-substrate harness: the APK was read into memory, never installed".into(),
                ),
            );
        }
        if let Some(launch) = cap.get_mut("launch").and_then(|p| p.as_object_mut()) {
            launch.insert("method".into(), J::String("pm_lifecycle".into()));
            launch.insert("succeeded".into(), J::Bool(true));
            launch.insert("component".into(), json!(component));
            launch.insert(
                "requested_activity_resolved_by".into(),
                J::String("the harness, from the manifest's <intent-filter> MAIN/LAUNCHER".into()),
            );
        }
        cap.insert(
            "device_serial".into(),
            J::String("none (no device; the substrate is the process)".into()),
        );
        cap.insert("boot_wait_ms".into(), json!(0u64));
        if let Some(clock) = cap.get_mut("clock").and_then(|p| p.as_object_mut()) {
            clock.insert(
                "monotonic_source".into(),
                J::String("substrate_instrumentation".into()),
            );
            clock.insert(
                "t_zero_definition".into(),
                J::String(
                    "t=0 is the moment the interpreter was handed the app's classes.dex. The \
                     clock is the substrate's virtual clock, which advances only when a shim \
                     method advances it; the engine's instruction count is recorded separately \
                     and is not a wall clock."
                        .into(),
                ),
            );
            clock.insert(
                "notes".into(),
                J::String(
                    "Relative intervals are exact. Absolute wall-clock latency is meaningless \
                     in a substrate and is deliberately not reported."
                        .into(),
                ),
            );
        }
    }

    if let Some(q) = obj
        .get_mut("capture_quality")
        .and_then(|p| p.as_object_mut())
    {
        q.insert("completeness".into(), J::String("partial".into()));
        q.insert("warnings".into(), json!(executed_warnings(real)));
        q.insert("unobserved".into(), json!(unobserved(real)));
    }

    // The synthetic builder writes a `notes` string that opens with "SYNTHETIC".
    // A document that says `synthetic: false` and then says SYNTHETIC in its
    // analyst commentary is self-contradicting in the one place a human is
    // guaranteed to read, so the whole string is replaced. The schema caps it at
    // 8000 characters, which is why the structural facts live in `diagnostics`
    // and `capture_quality` rather than here.
    let prior_note = obj
        .get("notes")
        .and_then(|p| p.as_str())
        .unwrap_or_default()
        .to_string();
    let mut note_text = format!(
        "EXECUTED. Real APK bytecode from {package} ran under tools/dexinterp with the shim's \
         own DEX as the framework layer (supersede, ADR 0005). The run stopped because: {}. \
         environment.kind is 'synthetic' because the schema's enum has no substrate token and a \
         substrate is not a device; top-level synthetic is false because this is not a fixture. \
         capture.root_shell is true because that field is the schema's only proxy for in-process \
         observation authority, which a substrate has in full; no shell was opened. \
         capture_script_sha256 is the digest of the shim DEX the framework layer was built from, \
         which is the code that decided every answer this app received. Recorder implementation is \
         'synthetic' because that enum predates substrates and no other value is less wrong.",
        real.stopped_because
    );
    // Keep whatever the builder wrote that was not the synthetic blurb, so this
    // patch removes a claim rather than silently discarding prose.
    let tail: Vec<&str> = prior_note.split(" -- ").skip(1).collect();
    for t in tail {
        if !t.starts_with("SYNTHETIC") && note_text.len() + t.len() + 8 < 8000 {
            note_text.push_str(" -- ");
            note_text.push_str(t);
        }
    }
    obj.insert("notes".into(), J::String(note_text));

    // The numbers the shim surface needs, in the array the schema designed for
    // non-lifecycle signals rather than crammed into a free-text note. A
    // structured finding in a prose field is a finding an analyst has to parse
    // out of prose.
    let mut diagnostics: Vec<J> = obj
        .get("diagnostics")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    // The schema's `diagnostic` is a recognised-signal record, so each of these
    // has to name a `pattern` in the project's `SIGNAL_PAT.*` shape, the
    // divergence `family` it is the detection mechanism for, a `source` and a
    // `tier`. That constraint is the point: a free-form "here are some numbers"
    // entry would be unjoinable, and these three are joinable to the taxonomy
    // and to the `probes` array.
    diagnostics.push(json!({
        "pattern": "SIGNAL_PAT.FW_SURFACE_MISSING",
        "family": "SUB.FW",
        "t_mono_ms": 0,
        "detail": format!(
            "framework surface this app needed and the shim did not have: {} distinct entries; \
             app classes the shim shadowed: {}; invokedynamic bootstraps refused: {}; extra \
             classes*.dex present but not loaded: {}.",
            real.missing_surface.len(),
            real.shadowed_classes.len(),
            real.indy_refused.len(),
            real.extra_dex_files
        ),
        "source": "analyst_annotation",
        "tier": "T0_DIRECT"
    }));
    if !real.missing_surface.is_empty() {
        diagnostics.push(json!({
            "pattern": "SIGNAL_PAT.FW_CLASS_LOADER",
            "family": "SUB.FW",
            "t_mono_ms": 0,
            "detail": format!(
                "the run stopped on framework surface the shim lacks. First: {}. Nothing was \
                 added to the shim to get past it; the full set is in the run report.",
                real.missing_surface.first().cloned().unwrap_or_default()
            ),
            "source": "analyst_annotation",
            "tier": "T0_DIRECT"
        }));
    }
    diagnostics.push(json!({
        "pattern": "SIGNAL_PAT.INTERP_COUNTERS",
        "family": null,
        "t_mono_ms": 0,
        "detail": format!(
            "{} instructions executed, {} framework calls, {} distinct opcodes dispatched by \
             the interpreter for this run.",
            real.instructions_executed, real.framework_calls, real.distinct_opcodes
        ),
        "source": "analyst_annotation",
        "tier": "T0_DIRECT"
    }));
    obj.insert("diagnostics".into(), json!(diagnostics));

    // `plain` hostnames on a real capture is a review warning, and the shim's
    // default hostname policy is `none`, so a run that saw no host at all must
    // not claim `plain`. The field is the *policy*, not what was seen, and the
    // honest value for a substrate that shows the app a fabricated environment is
    // `none`.
    if let Some(priv_) = obj.get_mut("privacy").and_then(|p| p.as_object_mut()) {
        priv_.insert("hostnames".into(), J::String("none".into()));
    }
    Ok(doc)
}

fn executed_warnings(real: &RealFacts) -> Vec<J> {
    let mut w = vec![
        J::String(
            "A substrate capture, not a device capture. Every fact here is a joint property of \
             the app and the shim; the shim terminates egress, virtualises the clock, holds the \
             filesystem in memory and never drains the message queue, so the app's control flow \
             after any of those is the substrate's choice. Read exceptions[] as 'the app reached \
             a place the shim does not have' rather than as 'the app threw'."
                .into(),
        ),
        J::String(
            "environment.kind is 'synthetic' and top-level synthetic is false. The flag means \
             'no bytecode was executed'; the environment field names a substrate, which the \
             schema's enum has no token for."
                .into(),
        ),
    ];
    if !real.missing_surface.is_empty() {
        w.push(J::String(format!(
            "The run reached framework surface the shim does not implement: {} distinct \
             class/name pairs. The first is {}. The run stopped at the first of them that the \
             app could not handle; the shim was not extended to get further.",
            real.missing_surface.len(),
            real.missing_surface.first().cloned().unwrap_or_default()
        )));
    }
    if real.extra_dex_files > 0 {
        w.push(J::String(format!(
            "The APK has {} classes*.dex beyond classes.dex and none of them was loaded: the \
             interpreter takes one DEX file and merging is a dexcore writer feature that does \
             not exist. An app split across DEX files may fail here for that reason rather \
             than for any behavioural one.",
            real.extra_dex_files
        )));
    }
    if !real.native_libs.is_empty() {
        w.push(J::String(format!(
            "The APK declares {} native librar{}. There is no ELF loader in a browser, so every \
             native entry point is UNSATISFIED; an app that needs one cannot run here.",
            real.native_libs.len(),
            if real.native_libs.len() == 1 {
                "y"
            } else {
                "ies"
            }
        )));
    }
    w
}

/// `capture_quality.unobserved` for a substrate run.
///
/// Each entry is a mechanism this recorder structurally cannot have, with the
/// family of hypotheses it kills. The list is not decoration: `RECORDING.md` §12
/// is the reason the field exists, and a substrate that filled in an empty
/// array would be making the device arm's central weakness look like a property
/// of the study design.
fn unobserved(real: &RealFacts) -> Vec<J> {
    let mut out = vec![
        json!({
            "signal": "lifecycle.terminal >= L2_FIRST_FRAME_DRAWN",
            "reason_code": "not_implemented",
            "reason": "There is no display, no vsync and no rasteriser. The shim runs a real \
                measure/layout/draw cycle and emits a box tree, every node of which carries \
                painted: false, but no frame is ever composited, so first_frame_drawn is not \
                emitted and L2 is unreachable by construction."
        }),
        json!({
            "signal": "invokedynamic call sites",
            "reason_code": "not_implemented",
            "reason": "No bootstrap method is executed. A call site is decoded, its method \
                handle and bootstrap owner are named in the recording, and the call is refused. \
                Kills SUB.FW.INVOKEDYNAMIC, which the taxonomy marks COMMON in modern apps."
        }),
        json!({
            "signal": "Binder / IPC to another process",
            "reason_code": "not_implemented",
            "reason": "There is one process and no binder driver. A ContentProvider query, a \
                system service call across a process boundary and a broadcast to another app \
                are all absent. Kills SUB.IPC."
        }),
        json!({
            "signal": "input delivery and accessibility",
            "reason_code": "not_implemented",
            "reason": "No touch, no key, no motion, no IME commit and no accessibility node \
                tree. An app whose behaviour is a function of a gesture is unobservable here. \
                Kills SUB.INPUT."
        }),
        json!({
            "signal": "resources.arsc",
            "reason_code": "not_implemented",
            "reason": "resources.arsc is not parsed, so getString, getIdentifier and \
                setContentView(int) are 0 or null. Every layout the app inflates is therefore \
                unresolvable, which is the structural reason no view tree is built. Kills \
                SUB.RES."
        }),
        json!({
            "signal": "native code",
            "reason_code": "not_implemented",
            "reason": "No ELF loader. System.loadLibrary and every app-declared native method \
                are UNSATISFIED, which is recorded as an attempt. Kills SUB.NATIVE."
        }),
        json!({
            "signal": "sensors, telephony, camera, Bluetooth, accounts",
            "reason_code": "not_implemented",
            "reason": "No hardware. An app that probes for a sensor manager, a camera, a SIM or \
                an account is asking a question with no subject. Kills SUB.HW."
        }),
        json!({
            "signal": "wall-clock latency and energy",
            "reason_code": "not_implemented",
            "reason": "The clock is virtual and the host has no battery. Any conclusion about \
                how long the app takes or how much it costs is about the interpreter, not the \
                app. Kills SUB.PWR and the time half of SUB.TIME."
        }),
    ];
    if real.extra_dex_files > 0 {
        out.push(json!({
            "signal": "classes2.dex and later",
            "reason_code": "not_implemented",
            "reason": format!(
                "{} further DEX file(s) in the APK were not loaded. Classes defined only there \
                 resolve to nothing, and the class-loader census for this run is a census of \
                 one file, not of the APK.",
                real.extra_dex_files
            )
        }));
    }
    out
}
