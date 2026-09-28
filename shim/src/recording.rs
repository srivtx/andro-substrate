//! Turn a shim event stream into a `ground-truth/1` document.
//!
//! # The one constraint that shapes everything here
//!
//! `oracle/` is not this agent's to change. The output must validate against
//! `oracle/schema/ground-truth.schema.json` as it stands, including the
//! cross-field invariants in `oracle/recorder/validate.mjs`. That rules out the
//! convenient options: no substrate-only top-level field, no substrate-only
//! group, no invented `signal_source` value, no way to add a view tree to the
//! schema.
//!
//! The consequence is that the substrate's extra facts go where the schema
//! already has a place for them, and the mapping is worth stating once:
//!
//! | substrate fact | goes into |
//! |---|---|
//! | a denied request | `network.attempts[]` with `result: blocked_by_policy` |
//! | a VFS operation | `filesystem.accesses[]` with `access_trace_obtained: true` |
//! | a class resolution | `classes.loaded[]` plus a `classes`-group `probes` entry |
//! | a `native` attempt | `jni.calls[]` with `jni.obtained: true` |
//! | a thrown exception | `exceptions[]` |
//! | a `Build.*` / `/proc` read | `diagnostics[]` with a `SIGNAL_PAT.*` pattern and a family |
//! | the box tree | `probes[]` output, with `output_truncated` set when it does not fit |
//! | an assumption the app exercises | `substrate_probe_hits[]` with evidence pointers |
//! | what the substrate cannot see | `capture_quality.unobserved[]` |
//!
//! # Two places the substrate arm is *stronger* than the device arm
//!
//! `filesystem.access_trace_obtained` and `jni.obtained` are `false` in
//! essentially every real device capture, and `true` here. The validator's
//! invariant that forbids recorded accesses with `obtained: false` is on the
//! substrate's side trivially satisfied — and the direction matters: a device
//! arm that recorded accesses would be rejected, so the substrate arm is the one
//! that can carry the richer document.
//!
//! # The synthetic case is the only one this builder emits
//!
//! A `Shim` alone has not executed an APK: the interpreter does that, and it does
//! not exist yet. So the builder produces a document that is *labelled*
//! `synthetic: true` with a `synthetic_reason` and a warning, exactly as
//! `oracle/RECORDING.md` §6 requires, and the fact that it is a fixture is
//! repeated in three more places an analyst could look. It is never possible for
//! this output to be mistaken for evidence.

use serde_json::{json, Map, Value as J};

use crate::error::ShimError;
use crate::event::{
    axis_suffix, Detail, FsOp, Group, NetPresentation, Resolution, SubstrateEvent, Tier,
};
use crate::policy::{Axis, NetworkMode, SubstratePolicy, POLICY_FORMAT, POLICY_VERSION};
use crate::redact::PathPolicy;
use crate::taxonomy::AssumptionId;

/// The oracle's format discriminator.
pub const RECORD_FORMAT: &str = "andro-substrate.ground-truth/1";

/// The privacy policy the oracle fixes.
pub const PRIVACY_POLICY: &str = "andro-substrate/oracle-privacy/1";

/// Longest exception message, matching the oracle's `maxLength`.
const MAX_MESSAGE: usize = 2000;

/// Longest probe output, matching the oracle's `maxLength`.
const MAX_PROBE_OUTPUT: usize = 8000;

/// Longest probe command string.
const MAX_PROBE_COMMAND: usize = 600;

/// Static facts about the capture that the event stream does not carry.
///
/// All of it is either a real fact read from a fixture or an explicitly
/// synthetic placeholder, and `synthetic_notes` says which.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureFacts {
    /// The subject package.
    pub package: String,
    /// SHA-256 of the APK. For a fixture this is the *real* digest of the
    /// fixture APK recorded in `tools/dexcore/tests/FIXTURES.md`, so the static
    /// half of the document is a true statement about a real file and only the
    /// dynamic half is invented.
    pub apk_sha256: String,
    pub apk_size_bytes: u64,
    pub version_code: u32,
    pub version_name: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub declared_permissions: Vec<String>,
    /// SHA-256 of the shim DEX the events came from, so a capture is tied to the
    /// exact instrument that produced it.
    pub shim_dex_sha256: String,
    /// SHA-256 of this crate at the recording's revision, if known.
    pub toolchain_revision: String,
    /// The viewport the layout pass ran in.
    pub viewport: (i32, i32),
    /// Why this document is a fixture. At least 16 characters, as the schema
    /// requires, and required to be specific: a generic reason is how a fixture
    /// ends up looking like evidence.
    pub synthetic_reason: String,
    /// The lifecycle timestamps the shim observed, in order.
    pub lifecycle: Vec<LifecyclePoint>,
    /// The path policy actually applied, for `privacy.notes`.
    pub path_policy: PathPolicy,
    /// The text policy actually applied, for `privacy.notes`.
    pub text_policy: crate::layout::TextPolicy,
    /// The substrate policy the shim answered under.
    ///
    /// A field of the facts rather than a builder argument because it is *the*
    /// declaration: the document's `environment` block, its
    /// `substrate_policy` block and its `observer_effects` all have to agree, and
    /// three arguments that can disagree is three arguments that will.
    pub substrate_policy: SubstratePolicy,
}

/// One observed lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecyclePoint {
    /// The oracle `lifecycle_event.type` token.
    pub kind: &'static str,
    pub t_mono_ms: u64,
    /// The class the transition happened in.
    pub component: String,
    /// The `matched_pattern` identifier.
    pub pattern: &'static str,
}

impl CaptureFacts {
    /// Facts for a fixture built from a real F-Droid DEX extract.
    ///
    /// `pro.rudloff.search_to_browser_2` is used because it is the smallest
    /// fixture and because its `MainActivity extends Landroid/app/Activity;`
    /// exercises the loader boundary directly.
    pub fn fixture() -> CaptureFacts {
        CaptureFacts {
            package: "pro.rudloff.search_to_browser".to_string(),
            apk_sha256: "8dcc801faed47a1d8043083117a09eeee972e0d1affabcacb88eee286e4df0a5"
                .to_string(),
            apk_size_bytes: 0,
            version_code: 2,
            version_name: "2".to_string(),
            min_sdk: 21,
            target_sdk: 34,
            declared_permissions: vec![
                "android.permission.INTERNET".to_string(),
                "android.permission.QUERY_ALL_PACKAGES".to_string(),
            ],
            shim_dex_sha256: String::new(),
            toolchain_revision: "n/a (synthetic fixture; no execution performed)".to_string(),
            viewport: (1080, 2340),
            synthetic_reason:
                "Produced by shim::scenario::run() driving the shim directly. No APK \
was installed, no interpreter executed any bytecode, and no Android device or \
container was involved. The static fields are true of the fixture APK named in \
shim/CONFORMANCE.md; every dynamic field is invented by the scenario script and \
describes no real execution."
                    .to_string(),
            lifecycle: vec![
                LifecyclePoint {
                    kind: "process_start",
                    t_mono_ms: 0,
                    component: "pro.rudloff.search_to_browser".into(),
                    pattern: "LIFECYCLE_PAT.SUBSTRATE_T0",
                },
                LifecyclePoint {
                    kind: "activity_create",
                    t_mono_ms: 4,
                    component: "pro.rudloff.search_to_browser.MainActivity".into(),
                    pattern: "LIFECYCLE_PAT.AM_ON_CREATE",
                },
                LifecyclePoint {
                    kind: "activity_start",
                    t_mono_ms: 6,
                    component: "pro.rudloff.search_to_browser.MainActivity".into(),
                    pattern: "LIFECYCLE_PAT.AM_ON_START",
                },
                LifecyclePoint {
                    kind: "activity_resume",
                    t_mono_ms: 9,
                    component: "pro.rudloff.search_to_browser.MainActivity".into(),
                    pattern: "LIFECYCLE_PAT.AM_ON_RESUME",
                },
                LifecyclePoint {
                    kind: "first_frame_drawn",
                    t_mono_ms: 41,
                    component: "pro.rudloff.search_to_browser.MainActivity".into(),
                    pattern: "LIFECYCLE_PAT.SUBSTRATE_LAYOUT",
                },
                LifecyclePoint {
                    kind: "capture_boundary",
                    t_mono_ms: 4000,
                    component: "shim".into(),
                    pattern: "LIFECYCLE_PAT.T0_ANCHOR",
                },
            ],
            path_policy: PathPolicy::Full,
            text_policy: crate::layout::TextPolicy::ShapeOnly,
            substrate_policy: SubstratePolicy::default(),
        }
    }

    /// The same fixture facts under an explicit substrate policy.
    ///
    /// The `environment` block is derived from the policy rather than asserted,
    /// so a recording's environment and its `substrate_policy` block cannot
    /// disagree about what the substrate claimed to be.
    pub fn fixture_with(substrate_policy: SubstratePolicy) -> CaptureFacts {
        let mut f = CaptureFacts::fixture();
        f.substrate_policy = substrate_policy;
        f
    }

    /// The identity the policy declares, with the recording format's floors
    /// applied where the schema forbids a null.
    ///
    /// `environment.android_release` has `minLength: 1` and
    /// `environment.sdk_int` has `minimum: 1`, so a policy that withholds
    /// identity still has to record *something*. The floor is reported and named
    /// in `notes`, because a reader who saw `"1"` in a withheld substrate's
    /// environment and did not know about the floor would read it as a claim.
    pub fn declared_identity(&self) -> crate::system::BuildInfo {
        let mut b = self.substrate_policy.identity.environment_identity();
        if b.is_empty() {
            b.release = "1".to_string();
            b.sdk_int = 1;
        }
        b
    }
}

/// The oracle's lifecycle terminal ladder, recomputed here so the builder never
/// guesses and never disagrees with `validate.mjs`.
///
/// The logic is a transcription of `deriveTerminal` in the validator, minus the
/// `LF_UNRESOLVED` escape hatch, which a synthetic fixture may not use: the
/// validator rejects `LF_UNRESOLVED` only when `completeness == "complete"`, but
/// `deriveTerminal` short-circuits on it, so using it would hide the derivation
/// entirely. A fixture derives its terminal from its events like any other
/// document.
pub fn derive_terminal(events: &[LifecyclePoint], fatal_after_resume: bool) -> &'static str {
    let first = |k: &str| events.iter().find(|e| e.kind == k).map(|e| e.t_mono_ms);
    let start = first("process_start");
    let resume = first("activity_resume");
    let frame = first("first_frame_drawn");
    let died = first("process_died");
    let anr = first("anr");
    if start.is_none() {
        return "LF_FAILED_BEFORE_L0";
    }
    let before = |t: Option<u64>, r: Option<u64>| t.is_some() && (r.is_none() || t < r);
    if before(died, resume) || before(anr, resume) {
        return "LF_NEVER_RESUMED";
    }
    if resume.is_none() {
        return "L0_PROCESS_STARTED";
    }
    if fatal_after_resume {
        return "LF_CRASHED";
    }
    if frame.is_none() {
        return "L1_ACTIVITY_RESUMED";
    }
    // A substrate capture never claims steady state: `L3_STEADY_STATE` asserts a
    // *usable* app and the oracle's own text says that is the weakest-evidenced
    // rung. A shim that has never run a real activity has no business claiming
    // it.
    "L2_FIRST_FRAME_DRAWN"
}

/// Facts the event stream does not carry but the schema has no place for.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extras {
    /// The serialised box tree from the layout pass, for `probes[].output`.
    pub box_tree: Option<J>,
    /// The VFS listing: `(path, size, mode)`.
    pub vfs_listing: Vec<(String, u64, u32)>,
}

/// Build the document.
pub fn build(
    facts: &CaptureFacts,
    events: &[SubstrateEvent],
    extras: &Extras,
) -> Result<J, ShimError> {
    let mut net_attempts: Vec<J> = Vec::new();
    let mut fs_accesses: Vec<J> = Vec::new();
    let mut classes_loaded: Vec<String> = Vec::new();
    let mut framework_classes: Vec<String> = Vec::new();
    let mut jni_calls: Vec<J> = Vec::new();
    let mut exceptions: Vec<J> = Vec::new();
    let mut diagnostics: Vec<J> = Vec::new();
    let mut probes: Vec<J> = Vec::new();
    let mut app_listing: Vec<J> = Vec::new();
    let mut dlopen_failures: Vec<J> = Vec::new();
    let mut probe_hit_index: Vec<(AssumptionId, Vec<String>)> = Vec::new();
    // Structurally zero: every attempt is refused before a socket exists, so
    // there is nothing to total. `net_seen` only exists to keep the compiler
    // honest about `net_attempts` being used in more than one place.
    let mut net_seen = false;

    for ev in events {
        match &ev.detail {
            Detail::Net {
                meta,
                method,
                headers,
                body_bytes,
                outcome,
                presentation,
                recorded_path,
            } => {
                net_seen = true;
                let mut a = Map::new();
                a.insert("seq".into(), json!(net_attempts.len()));
                a.insert("t_mono_ms".into(), json!(ev.t_mono_ms));
                a.insert("direction".into(), json!("outbound_request"));
                a.insert("scheme".into(), json!(meta.scheme.as_str()));
                a.insert(
                    "host".into(),
                    if meta.host.ends_with(".invalid") {
                        J::String(meta.host.clone())
                    } else {
                        J::Null
                    },
                );
                a.insert("port".into(), json!(meta.port));
                a.insert("path".into(), json!(recorded_path));
                a.insert("query_param_names".into(), json!(meta.query_param_names));
                a.insert("method".into(), json!(method.as_str()));
                a.insert("auth_header_names".into(), json!(headers.sensitive_names()));
                a.insert(
                    "redacted_header_count".into(),
                    json!(headers.redacted_count()),
                );
                a.insert(
                    "body_bytes".into(),
                    match body_bytes {
                        Some(n) => json!(n),
                        None => J::Null,
                    },
                );
                // No digest, on purpose: see the module docs of `crate::redact`.
                a.insert("body_sha256".into(), J::Null);
                a.insert("body_captured".into(), json!(false));
                a.insert("transport".into(), json!("tcp"));
                // The sink's outcome and the app's presentation are two
                // different facts and this is where they come apart. `result` is
                // `blocked_by_policy` under EVERY network axis value, because the
                // sink refused under every one of them. What the policy may add
                // is a `status_code` the app was shown, plus a `notes` sentence
                // saying it was shown rather than received.
                a.insert(
                    "result".into(),
                    json!(match outcome {
                        Ok(()) => "ok",
                        Err(_) => "blocked_by_policy",
                    }),
                );
                a.insert(
                    "status_code".into(),
                    match presentation.response() {
                        Some(r) => json!(r.status),
                        None => J::Null,
                    },
                );
                a.insert(
                    "error_class".into(),
                    match (outcome, presentation) {
                        (_, NetPresentation::Loopback(_)) => J::Null,
                        (Ok(()), _) => J::Null,
                        (Err(d), _) => json!(d.exception_class),
                    },
                );
                a.insert("source".into(), json!(ev.source.oracle_token()));
                a.insert("tier".into(), json!(ev.tier.as_str()));
                a.insert(
                    "notes".into(),
                    json!(format!(
                        "denied at the substrate's egress sink; no socket, no DNS query, no packet. \
                         Hostname policy: plain, and the host is an RFC 2606 reserved name because \
                         there is no real network to attribute. The query string was dropped in the \
                         URL parser; only parameter names survive.{}",
                        match presentation {
                            NetPresentation::Denied => String::new(),
                            NetPresentation::Loopback(r) => format!(
                                " PRESENTATION: the app was shown a synthesised {} response ({}, {} \
                                 declared body bytes) because the substrate_policy network axis is \
                                 '{}'. The request was still refused at the sink and the denial is \
                                 the value of `result` above; the status is a value this policy \
                                 declared, not one that was received.",
                                r.status,
                                r.content_type,
                                r.declared_body_bytes,
                                NetworkMode::SyntheticLoopback.as_str()
                            ),
                        }
                    )),
                );
                let idx = net_attempts.len();
                net_attempts.push(J::Object(a));
                if let Some(id) = ev.assumption {
                    push_hit(&mut probe_hit_index, id, format!("/network/attempts/{idx}"));
                }
            }
            Detail::Fs {
                op,
                path,
                bytes,
                result,
            } => {
                let mut a = fs_json(fs_accesses.len(), ev, *op, path, *bytes, *result);
                // A `/proc`, `/sys` or `/dev` access is decided by the
                // `system_fs` axis, and `fs_access.notes` is the only field on
                // this object that can say so — a device arm would leave it null
                // and a substrate arm must not.
                if is_system_path(path) {
                    a["notes"] = json!(format!(
                        "a fabricated filesystem read: the answer came from the substrate's \
                         system_fs axis, not from a kernel{}",
                        axis_suffix(Some(Axis::SystemFs))
                    ));
                }
                fs_accesses.push(a);
                let idx = fs_accesses.len() - 1;
                if let Some(id) = ev.assumption {
                    push_hit(
                        &mut probe_hit_index,
                        id,
                        format!("/filesystem/accesses/{idx}"),
                    );
                }
            }
            Detail::Classes {
                descriptor,
                resolution,
                from_package,
            } => {
                let name = descriptor_to_java(descriptor);
                if *resolution != Resolution::Unresolvable && !classes_loaded.contains(&name) {
                    classes_loaded.push(name.clone());
                }
                if is_framework(descriptor) {
                    framework_classes.push(name);
                }
                probes.push(probe_json(
                    probes.len(),
                    ev,
                    "classloader.resolve",
                    &format!(
                        "{} -> {}",
                        descriptor,
                        match (resolution, from_package) {
                            (Resolution::ShimDex, _) => "the shim DEX".to_string(),
                            (Resolution::AppDex, Some(p)) => p.to_string(),
                            (Resolution::AppDex, None) => "an app DEX".to_string(),
                            (Resolution::ShimSupersedesApp, Some(p)) => {
                                format!("the shim DEX, superseding {p}'s own definition")
                            }
                            (Resolution::ShimSupersedesApp, None) => {
                                "the shim DEX, superseding the app's own definition".to_string()
                            }
                            (Resolution::Unresolvable, _) => "nothing: unresolvable".to_string(),
                            (Resolution::DynamicUnavailable, _) => {
                                "nothing: the substrate has no DexClassLoader".to_string()
                            }
                        }
                    ),
                ));
                let idx = probes.len() - 1;
                if let Some(id) = ev.assumption {
                    push_hit(&mut probe_hit_index, id, format!("/probes/{idx}"));
                }
            }
            Detail::Jni {
                symbol,
                declaring_class,
                library,
                outcome,
            } => {
                jni_calls.push(json!({
                    "seq": jni_calls.len(),
                    "t_mono_ms": ev.t_mono_ms,
                    "direction": "java_to_native",
                    "symbol": truncate(symbol, 300),
                    "declaring_class": declaring_class.as_ref().map(|s| truncate(s, 300)),
                    "source": ev.source.oracle_token(),
                    "tier": ev.tier.as_str(),
                }));
                if let Some(l) = library {
                    dlopen_failures.push(json!({
                        "t_mono_ms": ev.t_mono_ms,
                        "library": truncate(l, 300),
                        "error_class": "java.lang.UnsatisfiedLinkError",
                    }));
                }
                let idx = jni_calls.len() - 1;
                if let Some(id) = ev.assumption {
                    push_hit(&mut probe_hit_index, id, format!("/jni/calls/{idx}"));
                }
                let _ = outcome;
            }
            Detail::Exceptions {
                class,
                message,
                stack,
                fatal,
                caught,
            } => {
                if *fatal {
                    exceptions.push(json!({
                        "t_mono_ms": ev.t_mono_ms,
                        "fatal": true,
                        "kind": "java_exception",
                        "thread": "main",
                        "class": truncate(class, 400),
                        "message": truncate(message, MAX_MESSAGE),
                        "stack_frames": stack.iter().take(128).map(|s| truncate(s, 400)).collect::<Vec<_>>(),
                        "source": ev.source.oracle_token(),
                        "tier": ev.tier.as_str(),
                    }));
                } else if *caught == Some(false) {
                    exceptions.push(json!({
                        "t_mono_ms": ev.t_mono_ms,
                        "fatal": false,
                        "kind": "java_exception",
                        "thread": "main",
                        "class": truncate(class, 400),
                        "message": truncate(message, MAX_MESSAGE),
                        "stack_frames": stack.iter().take(128).map(|s| truncate(s, 400)).collect::<Vec<_>>(),
                        "source": ev.source.oracle_token(),
                        "tier": ev.tier.as_str(),
                    }));
                }
                let idx = exceptions.len().saturating_sub(1);
                if *caught == Some(false) {
                    if let Some(id) = ev.assumption {
                        push_hit(&mut probe_hit_index, id, format!("/exceptions/{idx}"));
                    }
                }
            }
            Detail::Probes {
                pattern,
                detail,
                axis,
            } => {
                let family = ev.assumption.map(|a| a.family().as_str().to_string());
                // The axis label is appended to the detail rather than held in a
                // field of its own: `diagnostic` is a closed object with
                // `additionalProperties: false`, and the *pattern* plus the
                // policy's `governs` list is what a machine reads. The label is
                // the last thing in the sentence so the value being labelled
                // reads first.
                let detail = if axis.is_some() {
                    format!("{}{}", detail, axis_suffix(*axis))
                } else {
                    detail.clone()
                };
                let detail = detail.as_str();
                if let Some(id) = ev.assumption {
                    let diag_idx = diagnostics.len();
                    diagnostics.push(json!({
                        "pattern": pattern,
                        "family": family.clone(),
                        "t_mono_ms": ev.t_mono_ms,
                        "detail": truncate(detail, 400),
                        "source": ev.source.oracle_token(),
                        "tier": ev.tier.as_str(),
                    }));
                    let ev_ptr = format!("/diagnostics/{diag_idx}");
                    push_hit(&mut probe_hit_index, id, ev_ptr);
                    // A probe whose detail is long — a build field value, a
                    // system-tree read — also goes into `probes`, which is the
                    // oracle's home for "verbatim (or truncated) output".
                    if detail.len() > 120 {
                        probes.push(probe_json(
                            probes.len(),
                            ev,
                            &format!("substrate.probe {pattern}"),
                            detail,
                        ));
                    }
                } else {
                    // No assumption: still a probe, still visible, never a
                    // diagnostic, because a diagnostic without a family cannot
                    // be joined to the taxonomy.
                    if *pattern == "SIGNAL_PAT.LAYOUT_PASS" {
                        continue;
                    }
                    probes.push(probe_json(
                        probes.len(),
                        ev,
                        &format!("substrate.probe {pattern}"),
                        detail,
                    ));
                }
                if *pattern == "SIGNAL_PAT.MESSAGE_QUEUE" {
                    // The queue depth is the SUB.TIME.VSYNC measurement and it is
                    // an integer, so it also belongs in app_dir_listing-style
                    // structured form; the oracle has nowhere else for it, so the
                    // probe output is the record.
                }
            }
        }
    }

    // A layout pass produces the box tree. The oracle has no field for it, so it
    // goes into `probes[]` as an output, which is exactly what that field is
    // for, and the events keep the arithmetic.
    for ev in events {
        if let Detail::Probes {
            pattern, detail, ..
        } = &ev.detail
        {
            if *pattern == "SIGNAL_PAT.LAYOUT_PASS" {
                let rendered = extras
                    .box_tree
                    .as_ref()
                    .and_then(|t| serde_json::to_string(t).ok())
                    .unwrap_or_default();
                let (output, truncated) = if rendered.len() <= MAX_PROBE_OUTPUT {
                    (rendered, false)
                } else {
                    (truncate(&rendered, MAX_PROBE_OUTPUT), true)
                };
                probes.push(json!({
                    "id": format!("layout.{}", probes.len()),
                    "t_mono_ms": ev.t_mono_ms,
                    "command": "shim.layout.dump root",
                    "status": "ok",
                    "source": ev.source.oracle_token(),
                    "tier": ev.tier.as_str(),
                    "output": output,
                    "output_truncated": truncated,
                    "error": J::Null,
                }));
                let idx = probes.len() - 1;
                if let Some(id) = ev.assumption {
                    push_hit(&mut probe_hit_index, id, format!("/probes/{idx}"));
                }
                let _ = detail;
            }
        }
    }

    // `filesystem.app_dir_listing` is what a device arm can produce with `ls`.
    // The substrate can enumerate its whole VFS, so it fills that field with
    // every node the app's data directory subtree contains, which is the honest
    // shape for the same information.
    for (path, size, mode) in &extras.vfs_listing {
        app_listing.push(json!({
            "path": path,
            "entry_type": if path.ends_with('/') { "dir" } else { "file" },
            "size_bytes": size,
            "mode": Some(format!("{mode:o}")),
            "owner_uid": J::Null,
            "selinux_context": J::Null,
        }));
    }

    let _ = net_seen;
    let net_bytes_tx: u64 = 0;
    let net_bytes_rx: u64 = 0;

    let fatal_count = exceptions
        .iter()
        .filter(|e| e.get("fatal").and_then(J::as_bool) == Some(true))
        .count();
    let terminal = derive_terminal(&facts.lifecycle, false);
    let first_frame = facts
        .lifecycle
        .iter()
        .find(|e| e.kind == "first_frame_drawn")
        .map(|e| e.t_mono_ms);

    let mut families: Vec<String> = probe_hit_index
        .iter()
        .map(|(id, _)| id.family().as_str().to_string())
        .collect();
    families.sort();
    families.dedup();

    let hits: Vec<J> = probe_hit_index
        .iter()
        .map(|(id, evidence)| {
            json!({
                "assumption_id": id.as_str(),
                "family": id.family().as_str(),
                // On a SUBSTRATE recording `symptom_class` is a measurement, not a
                // forward prediction: this is the divergence the shim itself
                // produced. The schema's description says so for the ground-truth
                // case; the shape is identical, which is the point.
                "symptom_class": id.class().as_str(),
                "first_t_mono_ms": first_t_for(events, *id),
                "last_t_mono_ms": last_t_for(events, *id),
                "hit_count": count_for(events, *id),
                "evidence": evidence,
                "source": "synthetic_fixture",
                "tier": "T0_DIRECT",
                "confidence": "certain",
                "notes": format!(
                    "observed by the substrate's own instrumentation, not inferred. A device arm \
                     can only establish the environment half of this ID; the substrate establishes \
                     the app half."
                ),
            })
        })
        .collect();

    let lifecycle_events: Vec<J> = facts
        .lifecycle
        .iter()
        .map(|p| {
            json!({
                "type": p.kind,
                "t_mono_ms": p.t_mono_ms,
                "t_wall_utc": J::Null,
                "component": p.component,
                "pid": 1,
                "source": "synthetic_fixture",
                "tier": "T0_DIRECT",
                "log_tag": J::Null,
                "log_priority": J::Null,
                "matched_pattern": p.pattern,
                "detail": format!("{} at t={} ms", p.kind, p.t_mono_ms),
            })
        })
        .collect();

    // The window must contain every lifecycle event too, not just the last
    // observation: the validator checks the max over `lifecycle.events`, and a
    // boundary marker is a real event with a real time.
    let last_event_ms = events
        .iter()
        .map(|e| e.t_mono_ms)
        .chain(facts.lifecycle.iter().map(|p| p.t_mono_ms))
        .max()
        .unwrap_or(0);
    let window_ms = (last_event_ms + 1).max(1);
    let max_tier = max_tier(events);
    // The identity the policy declares, once, so the environment block and the
    // `substrate_policy` block cannot disagree.
    let declared = facts.declared_identity();
    let observer_effects = observer_effects_for(facts.substrate_policy);
    let policy = facts.substrate_policy;
    let net_limits = with_extra_limits(
        [
            "The substrate has no network. There is no capture method to choose: attempts are \
recorded at the sink and refused, so a substrate capture can never show a response, a status \
code, a TLS session or a redirect.",
            "SUB.NET.EGRESS is therefore structurally unsatisfiable here, and every network-dependent \
app is expected to fail identically in every substrate run. That is a property of the \
architecture, not a finding about any app.",
            "No DNS query is ever issued, so a request to a host that does not resolve and a \
request to a host that does are indistinguishable in this document.",
            "Byte totals are zero by construction, so a recording cannot distinguish an app that \
sends nothing from an app that sends and is refused before transmission.",
        ],
        network_limits(policy),
    );
    let fs_limits = with_extra_limits(
        [
            "There is no real disk. The VFS is an in-memory map, so a file an app would have \
persisted across a process death is lost at the end of the run and any state-restoration path \
takes its fallback branch.",
            "The /proc and /sys trees are FABRICATED. Which fabrication is decided by the \
substrate_policy system_fs axis: 'fabricated' is synthetic but plausible content, 'empty' is a \
path that exists and reads as zero bytes, 'absent' is ENOENT.",
            "No SELinux labels, no uid/gid ownership and no POSIX modes beyond a single synthetic \
mode per node, so SUB.FS.PERM_MODEL and SUB.FS.SELINUX_CONTEXT cannot be assessed from this \
document at all.",
            "Path contents are never recorded. Only paths, operations and byte counts, so a \
recording supports no claim about what an app stored.",
        ],
        filesystem_limits(policy),
    );

    let doc = json!({
        "record_format": RECORD_FORMAT,
        "synthetic": true,
        "capture_id": format!(
            "{}__{}__{}__run0001",
            facts.package,
            &facts.apk_sha256[..16],
            "synthetic_substrate"
        ),
        // The declaration, before anything else a reader would look at. Placed
        // here so that a reader who opens the document and reads the first page
        // meets the substrate's own behaviour before meeting the app's.
        "substrate_policy": facts.substrate_policy.to_json(),
        "provenance": {
            "execution_performed": false,
            "synthetic_reason": facts.synthetic_reason,
            "toolchain_revision": facts.toolchain_revision,
            "capture_script_sha256": J::Null,
            "authored_by": "andro-substrate shim recorder (shim/src/bin/shim-record.rs)",
            "host_os": "any; the shim performs no host I/O",
            "notes": "No APK was installed and no bytecode was executed. The 'execution' was a \
                      scripted sequence of calls into the shim's observation layer, which is why \
                      every dynamic field here describes the shim's behaviour rather than an app's."
        },
        "recorder": {
            "name": "shim-recorder",
            "version": crate::VERSION,
            "implementation": "synthetic",
            "options": {
                "path_policy": facts.path_policy.as_str(),
                "text_policy": facts.text_policy.as_str(),
                "egress": "denied",
                "vfs": "in-memory",
                "shim_dex_sha256": facts.shim_dex_sha256,
                "toolchain": crate::TOOL_NAME,
                // The policy, again, in the one place a recorder's *options* are
                // supposed to live. Redundant with the top-level block on
                // purpose: the top-level block is the declaration and this is the
                // pointer, and a reader who reads only `recorder.options` should
                // still learn which substrate produced the document.
                "substrate_policy": facts.substrate_policy.digest(),
                "substrate_policy_format": POLICY_FORMAT,
                "substrate_policy_version": u64::from(POLICY_VERSION),
                "substrate_policy_identity": facts.substrate_policy.identity.as_str(),
                "substrate_policy_system_fs": facts.substrate_policy.system_fs.as_str(),
                "substrate_policy_cross_app_packages": facts
                    .substrate_policy
                    .cross_app_packages
                    .as_str(),
                "substrate_policy_network": facts.substrate_policy.network.as_str(),
                "substrate_policy_time": facts.substrate_policy.time.as_str(),
            },
            "adb_version": J::Null,
            "notes": "Emits a ground-truth/1 document so a substrate capture and a device capture are \
                      the same shape and can be diffed directly. The substrate's own behaviour is \
                      declared in the top-level `substrate_policy` object, which is optional in the \
                      schema and absent from a device capture: a device has no substrate policy \
                      because a device is not one."
        },
        "capture": {
            "started_utc": "2026-09-28T00:00:00.000Z",
            "ended_utc": "2026-09-28T00:00:04.000Z",
            "duration_ms": window_ms.max(4001),
            "observation_window_ms": window_ms,
            "boot_wait_ms": 0,
            "install": {
                "method": "not_applicable_synthetic",
                "succeeded": true,
                "flags": [],
                "apks_replaced_existing": J::Null,
                "install_source": J::Null,
                "error": J::Null
            },
            "launch": {
                "method": "not_applicable_synthetic",
                "component": J::Null,
                "requested_activity_resolved_by": J::Null,
                "succeeded": true,
                "error": J::Null
            },
            "device_serial": "none",
            "shell_uid": J::Null,
            "root_shell": true,
            "snapshot_at_ms": J::Null,
            "clock": {
                "monotonic_source": "synthetic_fixture",
                "monotonic_resolution_ms": 1,
                "wall_clock_source": "none",
                "monotonic_epoch_ref": J::Null,
                "t_zero_definition": "t=0 is the substrate's virtual clock origin, set at Shim::new. \
    The clock is virtual and advances only when the scenario advances it or a shim method advances it, \
    so the timeline is exactly reproducible. It is NOT substrate_instrumentation: a real run would use \
    that, and claiming it here would overstate what a fixture knows.",
                "notes": "Relative intervals are exact; absolute wall-clock latency is meaningless \
    in a fixture and is deliberately not reported."
            },
            "observer_effects": observer_effects,
            "interventions_during_run": []
        },
        "app": {
            "package": facts.package,
            "apk_sha256": facts.apk_sha256,
            "apk_size_bytes": facts.apk_size_bytes,
            "apk_paths": [],
            "apk_digest_on_device": J::Null,
            "version_code": facts.version_code,
            "version_name": facts.version_name,
            "min_sdk": facts.min_sdk,
            "target_sdk": facts.target_sdk,
            "shared_user_id": J::Null,
            "user_id": 10123,
            "install_flags": [],
            "private_flags": [],
            "debuggable": false,
            "declared_permissions": facts.declared_permissions,
            "granted_permissions": Vec::<String>::new(),
            "requested_features": [],
            "split_apks": [],
            "main_activity": "pro.rudloff.search_to_browser.MainActivity",
            "activities": ["pro.rudloff.search_to_browser.MainActivity"],
            "services": [],
            "receivers": [],
            "providers": [],
            "native_libs_declared": [],
            "uses_non_sdk_api": J::Null,
            "signature_sha256": [],
            "data_dir": format!("/data/data/{}", facts.package),
            "code_path": J::Null,
            "device_protected_data_dir": J::Null,
            "is_synthetic": true
        },
        "environment": {
            "kind": "synthetic",
            // Every identity field below is derived from the `identity` axis, not
            // asserted by the builder. That is the whole point: an environment
            // block that is a hard-coded constant while a `substrate_policy` block
            // next to it says `withheld` is a document that lies to a reader who
            // diffs the two, and the schema has no way to catch that.
            "android_release": declared.release,
            "security_patch": J::Null,
            "sdk_int": declared.sdk_int,
            "build_fingerprint": declared.fingerprint,
            "build_id": J::Null,
            "build_type": J::Null,
            "build_tags": declared.tags,
            "model": declared.model,
            "manufacturer": declared.manufacturer,
            "brand": declared.brand,
            "product": declared.product,
            "device": declared.device,
            "hardware": declared.hardware,
            "board": declared.board,
            "serial": J::Null,
            "bootloader": J::Null,
            "abis": declared.abis,
            "cpu_count": 4,
            "total_ram_bytes": 1073741824u64,
            "low_ram_device": true,
            "is_emulator": false,
            "is_physical_device": false,
            "bootloader_unlocked": J::Null,
            "ro_secure": J::Null,
            "verified_boot_state": J::Null,
            "selinux": J::Null,
            "selinux_enforcing": J::Null,
            "verified_boot_hash": J::Null,
            "image_digest": J::Null,
            "image_fingerprint": J::Null,
            "google_play_services": {
                "present": false,
                "version_name": J::Null,
                "version_code": J::Null,
                "enabled": false,
                "detected_by": "unknown"
            },
            "play_store_present": false,
            "attestation": {
                "play_integrity_supported": false,
                "safetynet_available": false,
                "max_expected_verdict": "NONE",
                "observed_verdict": J::Null,
                "basis": "documented_requirement",
                "notes": "NONE is a ceiling, not an observation. No hardware attestation exists in a \
    browser and none can be faked convincingly; the shim does not try, because a shim that could pass \
    MEETS_DEVICE_INTEGRITY would not be a shim. safetynet_available is false because SafetyNet was \
    turned down for every app on 2025-01-31 and now always fails, on any device."
            },
            "locale": J::Null,
            "timezone": J::Null,
            "font_scale": J::Null,
            "density_dpi": 420,
            "screen": {
                "width_px": facts.viewport.0,
                "height_px": facts.viewport.1,
                "density_dpi": 420,
                "refresh_rate_hz": J::Null,
                "supported_refresh_rates_hz": []
            },
            "graphics": {
                "gles_version": J::Null,
                "vulkan_version": J::Null,
                "egl_vendor": J::Null,
                "gl_renderer": J::Null,
                "extensions_known": false,
                "hardware_accelerated_default": false
            },
            "network": {
                // `false` on EVERY network axis value, including
                // `synthetic_loopback`. A substrate that showed the app a 200
                // did not gain egress, and a recording that reported
                // `egress_available: true` here would be claiming the one
                // capability the project is built on not having. This field not
                // moving under the loopback policy is the load-bearing evidence.
                "egress_available": false,
                "default_network_type": J::Null,
                "validated": false
            },
            "sensors_present": crate::system::Capabilities::default().present().to_vec(),
            "sensors_absent": crate::system::Capabilities::default().absent().to_vec(),
            "properties_observed": {
                "ro.build.fingerprint": declared.fingerprint,
                // Absent on every identity axis value, and NOT because an axis
                // says so: the substrate simply does not model the property. A
                // reader must be able to tell "no axis governs this" from "an
                // axis decided this", so it is said rather than shown as an
                // empty value. See docs/decisions/0006 for why this is a known
                // limit of the family rather than a missing value.
                "ro.kernel.qemu": "<absent: not modelled by any policy axis>",
                "ro.debuggable": "0",
                "ro.build.version.sdk": declared.sdk_int.to_string()
            }
        },
        "clock": {
            "monotonic_source": "synthetic_fixture",
            "monotonic_resolution_ms": 1,
            "wall_clock_source": "none",
            "monotonic_epoch_ref": J::Null,
            "t_zero_definition": "t=0 is the substrate's virtual clock origin.",
            "notes": "Virtual and exactly reproducible. Deliberately NOT \
    substrate_instrumentation: a fixture cannot claim a real substrate clock."
        },
        "privacy": {
            "policy": PRIVACY_POLICY,
            "bodies_captured": false,
            "hostnames": "plain",
            "secrets_redacted": true,
            "user_ca_trusted": false,
            "notes": format!(
                "Policy applied at the point of capture, not downstream: the shim's URL parser drops \
    the query string's values and the fragment before any struct can hold them, and its header type \
    has no parameter that would accept a value. Path policy: {}. Text policy for view trees: {}. \
    BODIES ARE NOT DIGESTED, unlike the oracle format which permits body_sha256: a digest over a \
    low-entropy body is reversible by brute force, so only the length is kept and body_sha256 is null. \
    RESIDUAL RISK: a request path is recorded verbatim under path=full, and REST designs do put \
    identifiers in path segments; switch to path=shape-only or path=opaque to remove that. Exception \
    messages are truncated at 2000 characters, which is the one place an app's own formatting can leak \
    user data into a message; the shim's own messages contain no app data, and a message thrown by the \
    INTERPRETER is out of this crate's control. Hostnames are recorded plainly because every host in \
    this document is an RFC 2606 reserved name ending in .invalid, so there is nothing to re-identify.",
                facts.path_policy.as_str(),
                facts.text_policy.as_str()
            )
        },
        "lifecycle": {
            "events": lifecycle_events,
            "terminal": terminal,
            "activity_started": facts.lifecycle.iter().find(|e| e.kind == "activity_start").map(|e| e.t_mono_ms),
            "activity_resumed": facts.lifecycle.iter().find(|e| e.kind == "activity_resume").map(|e| e.t_mono_ms),
            "first_frame_drawn": first_frame,
            "window_focused": J::Null,
            "first_input_delivered": J::Null,
            "reached_steady_state": false,
            "quiet_window_ms": 0,
            "sustained_log_spam": J::Null,
            "jank_events": 0
        },
        "network": {
            "capture_method": "none",
            "hostname_resolution": "plain",
            "attempts": net_attempts,
            "byte_totals_observed": {
                "source": "synthetic_fixture",
                "tx_bytes": net_bytes_tx,
                "rx_bytes": net_bytes_rx,
                "connection_count": net_attempts.len(),
                "destination_resolvable": true,
                "uid": 10123,
                "note": "Zero bytes moved. Every attempt terminated at the substrate's egress sink \
    before any socket was created, so the counters are structurally zero rather than \
    unmeasured. The destination is resolvable because the shim parsed the hostname; it was never \
    looked up."
            },
            "limits": net_limits
        },
        "filesystem": {
            "accesses": fs_accesses,
            "access_trace_obtained": true,
            "app_dir_listing": app_listing,
            "open_fds_at_snapshot": [],
            "limits": fs_limits
        },
        "classes": {
            "loaded": classes_loaded,
            "loaded_obtained": true,
            "total_loaded_count": classes_loaded.len(),
            "framework_classes_touched": framework_classes,
            "third_party_package_prefixes": ["pro.rudloff.search_to_browser".to_string()],
            "dex_files": ["<app classes.dex, parsed by dexcore>".to_string()],
            "dynamic_dex_loaded": [],
            "limits": [
                "SUB.FW.CLASS_LOADER: the shim defines a small fraction of the java.* surface. A \
    class the shim does not define resolves to nothing and is recorded as unresolvable, which on a \
    device would have been a NoClassDefFoundError from the app's own dex.",
                "A class the APP defines that the shim also defines is shadowed. The shim's \
    definition wins, so the app's own class disappears silently; the resolution is recorded as \
    shim_supersedes_app precisely so that this is visible.",
                "No invokedynamic, no method handles, no call sites. Modern dex is saturated with \
    invokedynamic, so a large fraction of contemporary app behaviour never reaches a shim method at \
    all and is therefore structurally unobservable by this layer.",
                "Reflection is dispatched through the same table as a direct call, so a reflective \
    call and a direct one are indistinguishable in this document. That is a feature for coverage and a \
    blind spot for attribution.",
                "The loaded list is what the shim's loader saw, which is not the same as what ART \
    would have loaded: there is no verification, no resolution of a method reference to a class that \
    was never initialised, and no separate compilation."
            ]
        },
        "native": {
            "libraries_loaded": [],
            "obtained": true,
            "mapping_obtained": true,
            "exec_segments_observed": false,
            "dlopen_failures": dlopen_failures,
            "system_libraries_mapped": [],
            "jit_or_aot_activity_observed": false,
            "thread_count_at_snapshot": 1,
            "limits": [
                "The substrate has no ELF loader, no .so and no /system/lib, so \
    SUB.NATIVE.LOAD_LIBRARY and SUB.NATIVE.JNI_ENTRY are structurally unsatisfiable and every native \
    attempt is UNSATISFIED.",
                "mapping_obtained is true because the shim knows its own (empty) mapping set \
    exhaustively. A device arm can only read /proc/<pid>/maps, and only with root or a debuggable \
    build.",
                "No JIT and no AOT: the substrate's execution model is whatever the interpreter is, \
    so SUB.CPU.TIERING cannot be measured here at all. A slow app in a substrate is the interpreter's \
    cost, not ART's, and this document cannot separate the two."
            ]
        },
        "jni": {
            "calls": jni_calls,
            "obtained": true,
            "limits": [
                "Every call is java_to_native and every outcome is UNSATISFIED. The substrate \
    implements no native code, so there is no native_to_java direction to record.",
                "obtained is true because the shim is the process and sees every call site the \
    interpreter routes through it. A device arm can only claim this with in-process instrumentation, \
    which the oracle protocol explicitly declines to use."
            ]
        },
        "exceptions": exceptions,
        "probes": probes,
        "diagnostics": diagnostics,
        "substrate_probe_hits": hits,
        "capture_quality": {
            "completeness": "not_applicable_synthetic",
            "max_tier_reached": max_tier,
            "signals_expected": [
                "class_load_census",
                "file_access_trace",
                "jni_transitions",
                "network_attempts",
                "build_field_reads",
                "proc_sys_reads",
                "package_manager_queries",
                "layout_pass",
                "message_queue_depth"
            ],
            "signals_obtained": signals_obtained(events),
            "unobserved": unobserved(policy),
            "warnings": vec![
                "SYNTHETIC FIXTURE - NOT EVIDENCE. No APK was installed, no bytecode was executed, \
    and no Android device or container was involved. Every dynamic field describes the shim's own \
    behaviour under a scripted sequence of calls, not any app's behaviour. Analysis pipelines must \
    filter on synthetic == false before using this document; the oracle validator prints \
    [SYNTHETIC FIXTURE - not evidence] on it for the same reason.",
                "The static app block (package, apk_sha256, version) is true of the fixture APK \
    pro.rudloff.search_to_browser_2 recorded in tools/dexcore/tests/FIXTURES.md. That does not make \
    the rest of the document a statement about that app.",
                "is_emulator is false and the attestation ceiling is NONE. The substrate is not \
    attempting to pass emulator detection, because a substrate that could pass it would not be a \
    substrate. An app that checks will check and will fail, and this document will say so.",
                "THE SUBSTRATE IS A DECLARED PARAMETER, NOT A GIVEN. The top-level substrate_policy \
    object records every choice this instrument made about its own behaviour, and every value it \
    fabricated is labelled at emission with the axis that produced it. Facts in a policy-governed \
    class are a JOINT property of the app and that declaration, and this document alone cannot \
    separate them: the way to separate them is to run the same program under a second policy and \
    diff, which is what shim/recordings/differential-*.recording.json are. A fact in no governed class \
    was not decided by the substrate."
            ],
            "empty_failure": false,
            "exit_code": 0
        },
        "summary": {
            "lifecycle_terminal": terminal,
            "time_to_first_frame_ms": first_frame,
            "event_count": facts.lifecycle.len(),
            "network_attempt_count": net_attempts_len(&net_attempts),
            "network_destinations": net_attempts_len(&net_attempts),
            "exception_count": exceptions.len(),
            "fatal_count": fatal_count,
            "class_count": classes_loaded.len(),
            "native_library_count": 0,
            "distinct_families_touched": families.len(),
            "families_touched": families.clone()
        },
        "notes": format!(
            "SYNTHETIC. Produced by shim::scenario::run() and emitted by \
    shim/src/bin/shim-record.rs. Conforms to oracle/schema/ground-truth.schema.json so that a substrate \
    capture and a device capture are the same document shape and directly diffable. Regenerate with: \
    cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-record > \
    shim/recordings/synthetic.recording.json -- SUBSTRATE POLICY: {digest}. Every fabricated value in \
    this document was produced by one of the five axes declared in the top-level substrate_policy \
    object, and none of those axes can widen a capability or a capture surface. The two-arm worked \
    differential is in shim/recordings/differential-*.recording.json; read their substrate_policy \
    blocks before diffing anything else.",
            digest = policy.digest()
        )
    });

    // Belt and braces: refuse to hand out a document that would fail the
    // structural privacy rules.
    let rendered =
        serde_json::to_string(&doc).map_err(|e| ShimError::Encode(format!("recording: {e}")))?;
    crate::redact::scrub(&rendered, &[]).map_err(|v| {
        ShimError::Encode(format!(
            "the recording would violate the privacy policy: {:?}",
            v.first()
        ))
    })?;

    Ok(doc)
}

// -------------------------------------------------------------------- helpers

/// One `capture.observer_effects` entry per axis that is not at its default,
/// after two entries that are always there.
///
/// The oracle requires every observer effect to be enumerated because an unlisted
/// one invalidates the capture. Before the policy family there was exactly one
/// substrate to describe, and one paragraph did it. Now there are 3·3·3·2·4 = 216
/// substrates, and a paragraph cannot enumerate them — so the enumeration is
/// generated from the declaration, one entry per axis that actually differs from
/// the default, and each entry names the axis and its value.
///
/// An axis left at its default gets no entry, and that is not an omission: the
/// default's effect is the `debug_attach` entry, which is always present.
fn observer_effects_for(policy: SubstratePolicy) -> Vec<J> {
    let mut effects = vec![
        json!({
            "kind": "debug_attach",
            "applied": true,
            "detail": "The substrate is the process. It denies egress, substitutes a \
        synthetic device identity, has no /proc or /sys, has no display, and answers every PackageManager \
        query about another app with 'not installed'. Each of these is an observer effect in the oracle's \
        sense and each plausibly changes app behaviour, so all are declared here rather than discovered \
        by an analyst.",
            "expected_to_change_behaviour": true
        }),
        json!({
            "kind": "none",
            "applied": false,
            "detail": "No MITM proxy and no user CA: the substrate has no network to \
        intercept, which is strictly stronger than proxying and needs no trust-store change.",
            "expected_to_change_behaviour": false
        }),
    ];
    let default = SubstratePolicy::default();
    for a in Axis::all() {
        if policy.axis(a) == default.axis(a) {
            continue;
        }
        effects.push(json!({
            // `none` is the only token in the oracle's enum that means
            // "something the recorder chose", and the substrate's policy axes
            // are exactly that. `debug_attach` is taken by the substrate being
            // the process, which is a different claim.
            "kind": "none",
            "applied": true,
            "detail": truncate(
                &format!(
                    "substrate_policy axis {} = {} (the recorder's default is {}). {}",
                    a.as_str(),
                    policy.axis(a),
                    default.axis(a),
                    a.statement(policy.axis(a))
                ),
                1000
            ),
            "expected_to_change_behaviour": true
        }));
    }
    effects
}

/// A `limits` array: the unconditional entries, then whatever the declared policy
/// adds. Kept as a helper because `json!` will not evaluate `a + b` inside an
/// array literal, and because the unconditional half has to be a single literal
/// for the compiler to check it against the schema's 400-character cap.
fn with_extra_limits(base: [&str; 4], extra: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = base.iter().map(|s| (*s).to_string()).collect();
    out.extend(extra);
    out
}

/// Extra `network.limits` entries when the network axis is not the default.
///
/// The default's limits are already unconditional, because the default is a hard
/// denial and a hard denial has one limit. The loopback arm needs its own,
/// because it is the only value under which a `status_code` in this document is
/// not null, and an unlabelled status code in a substrate recording is exactly
/// the kind of thing a reader mistakes for evidence.
fn network_limits(policy: SubstratePolicy) -> Vec<String> {
    if policy.network == NetworkMode::RecordAndDeny {
        return Vec::new();
    }
    [
        "THIS RUN PRESENTED SYNTHESISED RESPONSES. The substrate_policy network axis is \
'synthetic_loopback': connect() returned normally and getResponseCode() returned 200.",
        "NO BYTES MOVED. The egress sink refused every attempt exactly as it does under the \
default policy, which is why every attempts[].result is still blocked_by_policy and \
byte_totals_observed is still zero. Only the presentation changed.",
        "Consequence: any app behaviour that depends on a response existing — a success branch, a \
parse of a body, the absence of a retry — is a property of this policy, not of the app and not \
of any device.",
        "THIS RUN ALSO PUTS A STATUS CODE IN THE DOCUMENT. It is a value the policy declared, \
never one that was received. Diff two substrate recordings' substrate_policy blocks before \
diffing their attempts, or the difference will read as a difference in the app.",
    ]
    .into_iter()
    .map(|s| format!("{GENERATED_LIMIT} {s}"))
    .collect()
}

/// The prefix on every `limits` sentence this crate generates from the declared
/// policy, as opposed to the unconditional ones it always emits.
///
/// The differential classifies a `limits` entry by this prefix, which is how it
/// tells a restatement of the declaration from an observation. It is a marker
/// rather than an index because the generated entries are appended and can be
/// more than one sentence; a `limits` array that started at a fixed offset would
/// break the moment a sentence was split to fit the schema's 400-character cap.
pub const GENERATED_LIMIT: &str = "[substrate_policy]";

/// Extra `filesystem.limits` entries when the system filesystem axis is not the
/// default.
fn filesystem_limits(policy: SubstratePolicy) -> Vec<String> {
    let sentences: Vec<&str> = match policy.system_fs {
        crate::policy::SystemFsMode::Fabricated => Vec::new(),
        crate::policy::SystemFsMode::Empty => vec![
            "THIS RUN SERVED EMPTY SYSTEM FILES. The substrate_policy system_fs axis is 'empty': \
every modelled /proc, /sys and /dev path exists and reads as zero bytes.",
            "An app that stats before it reads gets existence; an app that parses gets nothing. \
The pair (exists, empty) is neither a plausible kernel nor a missing file, and no real Android \
device produces it.",
        ],
        crate::policy::SystemFsMode::Absent => vec![
            "THIS RUN HAD NO SYSTEM FILESYSTEM. The substrate_policy system_fs axis is 'absent': \
every /proc, /sys and /dev read returned ENOENT, and every attempt was recorded.",
            "An app that treats ENOENT as 'not an emulator' takes a different branch from one \
that parses /proc/self/status, and both are substrate artefacts.",
        ],
    };
    sentences
        .into_iter()
        .map(|s| format!("{GENERATED_LIMIT} {s}"))
        .collect()
}

/// Whether a path is one the `system_fs` axis is responsible for.
fn is_system_path(path: &str) -> bool {
    path.starts_with("/proc/") || path.starts_with("/sys/") || path.starts_with("/dev/")
}

fn net_attempts_len(v: &[J]) -> usize {
    v.len()
}

fn is_framework(descriptor: &str) -> bool {
    descriptor.starts_with("Landroid/") || descriptor.starts_with("Ljava/")
}

/// `Landroid/app/Activity;` → `android.app.Activity`. The oracle's `java_fqcn`
/// pattern rejects a trailing `;`, so the conversion is mandatory, not cosmetic.
fn descriptor_to_java(descriptor: &str) -> String {
    descriptor
        .trim_start_matches('L')
        .trim_end_matches(';')
        .replace('/', ".")
}

fn push_hit(hits: &mut Vec<(AssumptionId, Vec<String>)>, id: AssumptionId, pointer: String) {
    match hits.iter_mut().find(|(h, _)| *h == id) {
        Some((_, ev)) => {
            if !ev.contains(&pointer) {
                ev.push(pointer);
            }
        }
        None => hits.push((id, vec![pointer])),
    }
}

fn count_for(events: &[SubstrateEvent], id: AssumptionId) -> u64 {
    events.iter().filter(|e| e.assumption == Some(id)).count() as u64
}

fn first_t_for(events: &[SubstrateEvent], id: AssumptionId) -> u64 {
    events
        .iter()
        .find(|e| e.assumption == Some(id))
        .map(|e| e.t_mono_ms)
        .unwrap_or(0)
}

fn last_t_for(events: &[SubstrateEvent], id: AssumptionId) -> u64 {
    events
        .iter()
        .rev()
        .find(|e| e.assumption == Some(id))
        .map(|e| e.t_mono_ms)
        .unwrap_or(0)
}

fn fs_json(
    seq: usize,
    ev: &SubstrateEvent,
    op: FsOp,
    path: &str,
    bytes: u64,
    result: Result<u64, crate::error::VfsError>,
) -> J {
    json!({
        "seq": seq,
        "t_mono_ms": ev.t_mono_ms,
        "op": op.as_str(),
        "path": path,
        "size_bytes": bytes,
        "result": match result {
            Ok(_) => "ok",
            Err(e) => e.oracle_result(),
        },
        "errno": match result {
            Ok(_) => J::Null,
            Err(e) => json!(e.kind()),
        },
        "source": ev.source.oracle_token(),
        "tier": ev.tier.as_str(),
        "notes": J::Null
    })
}

fn probe_json(seq: usize, ev: &SubstrateEvent, command: &str, output: &str) -> J {
    let (out, truncated) = if output.len() <= MAX_PROBE_OUTPUT {
        (output.to_string(), false)
    } else {
        (truncate(output, MAX_PROBE_OUTPUT), true)
    };
    json!({
        "id": format!("p{seq:03}"),
        "t_mono_ms": ev.t_mono_ms,
        "command": truncate(command, MAX_PROBE_COMMAND),
        "status": "ok",
        "source": ev.source.oracle_token(),
        "tier": ev.tier.as_str(),
        "output": out,
        "output_truncated": truncated,
        "error": J::Null
    })
}

fn max_tier(events: &[SubstrateEvent]) -> &'static str {
    let best = events
        .iter()
        .map(|e| e.tier)
        .max()
        .unwrap_or(Tier::T4Unobserved);
    best.as_str()
}

fn signals_obtained(events: &[SubstrateEvent]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let has = |g: Group| events.iter().any(|e| e.group == g);
    if has(Group::Classes) {
        out.push("class_load_census".to_string());
    }
    if has(Group::Fs) {
        out.push("file_access_trace".to_string());
    }
    if has(Group::Jni) {
        out.push("jni_transitions".to_string());
    }
    if has(Group::Net) {
        out.push("network_attempts".to_string());
    }
    if events
        .iter()
        .any(|e| matches!(&e.detail, Detail::Probes { pattern, .. } if *pattern == "SIGNAL_PAT.BUILD_FIELD" || *pattern == "SIGNAL_PAT.SDK_INT"))
    {
        out.push("build_field_reads".to_string());
    }
    if events.iter().any(|e| matches!(&e.detail, Detail::Probes { pattern, .. } if pattern.starts_with("SIGNAL_PAT.PROC") || pattern.starts_with("SIGNAL_PAT.BATTERY") || pattern.starts_with("SIGNAL_PAT.SYS")))
    {
        out.push("proc_sys_reads".to_string());
    }
    if events
        .iter()
        .any(|e| matches!(&e.detail, Detail::Probes { pattern, .. } if *pattern == "SIGNAL_PAT.PM_QUERY" || *pattern == "SIGNAL_PAT.PM_SELF"))
    {
        out.push("package_manager_queries".to_string());
    }
    if events
        .iter()
        .any(|e| matches!(&e.detail, Detail::Probes { pattern, .. } if *pattern == "SIGNAL_PAT.LAYOUT_PASS"))
    {
        out.push("layout_pass".to_string());
    }
    if events
        .iter()
        .any(|e| matches!(&e.detail, Detail::Probes { pattern, .. } if *pattern == "SIGNAL_PAT.MESSAGE_QUEUE"))
    {
        out.push("message_queue_depth".to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// What the substrate structurally cannot observe, enumerated.
///
/// The oracle makes this field mandatory and says a recorder that reports no
/// gaps is lying. The substrate's gap list is *shorter* than a device's — it sees
/// more, not less — and the entries here are the things a browser cannot have at
/// all, which is the whole shape of the divergence.
///
/// **A `limits` array that a policy could shrink would be a lie.** So the last
/// entry is about the *declared* substrate rather than about the code: what a
/// given policy value takes away is listed there, per value, so the gap list
/// grows with the policy and never with the app.
fn unobserved(policy: SubstratePolicy) -> Vec<J> {
    let u = |signal: &str, code: &str, reason: &str| {
        json!({
            "signal": signal,
            "reason_code": code,
            "reason": reason
        })
    };
    let mut v = vec![
        u(
            "display_and_compositor",
            "not_implemented",
            "There is no display, no SurfaceFlinger and no vsync. Choreographer never posts a frame \
callback, so animation never advances and the layout pass produces geometry only. SUB.TIME.VSYNC \
is structurally unsatisfiable.",
        ),
        u(
            "binder_ipc",
            "not_implemented",
            "There is no /dev/binder, no ServiceManager and no IBinder. Every system service except \
the package manager is null, which is SUB.IPC.SYSTEM_SERVICE and SUB.IPC.BINDER_DEV.",
        ),
        u(
            "input_delivery",
            "not_implemented",
            "The substrate synthesises no input and delivers no MotionEvent or KeyEvent, so \
lifecycle.first_input_delivered is null and no app flow that waits for a tap can be observed \
past that point.",
        ),
        u(
            "process_reclamation",
            "not_implemented",
            "Nothing is ever reaped: no lowmemorykiller, no oom_adj, no cached-process states. \
lifecycle.events contains no process_killed, and the lifetime bugs a device shows will not \
appear.",
        ),
        u(
            "art_execution_tier",
            "not_implemented",
            "There is no AOT-compiled odex and no JIT warm-up. Execution cost belongs entirely to \
the interpreter, so SUB.CPU.TIERING cannot be measured and a slow app here is not evidence of \
anything about ART.",
        ),
        u(
            "resources_arsc",
            "not_implemented",
            "The APK is not a filesystem and resources.arsc is not parsed. Every getIdentifier, \
getString and setContentView(resource) returns null, so SUB.RES.ARSC is unsatisfiable and the \
name-to-id mapping that RES.PACKAGE_RESOLVER needs does not exist.",
        ),
        u(
            "boot_and_system_broadcasts",
            "not_implemented",
            "A browser tab has no boot. BOOT_COMPLETED and every other system broadcast is never \
delivered, so an app that defers initialisation to a receiver never initialises and never \
reports that it did not.",
        ),
        u(
            "hardware_attestation",
            "requires_in_process_instrumentation",
            "No TEE, no hardware-backed KeyStore, no MEETS_DEVICE_INTEGRITY and no \
MEETS_STRONG_INTEGRITY. Not implementable in software at any effort, so the shim does not try.",
        ),
        u(
            "selinux_labels_and_ownership",
            "not_implemented",
            "No SELinux, no uid/gid ownership and no POSIX modes beyond one synthetic mode per VFS \
node, so SUB.FS.SELINUX_CONTEXT and SUB.FS.PERM_MODEL cannot be assessed.",
        ),
        u(
            "invokedynamic_and_method_handles",
            "not_implemented",
            "The shim has no method-handle or call-site machinery, and the writer emits no \
method_handle_item or call_site_item. Modern dex is saturated with invokedynamic, so a large \
fraction of contemporary app behaviour never reaches a shim method and is therefore structurally \
invisible to this layer. This is the layer's most serious blind spot.",
        ),
        u(
            "network_responses",
            "scope_out_of_protocol",
            "Egress is denied by construction, so no response, status code, TLS session or \
redirect is ever observable. Every attempt is recorded and refused; that is a stronger property \
than a proxy but it is a strictly smaller set of observations.",
        ),
        u(
            "real_wall_clock",
            "not_implemented",
            "System.currentTimeMillis() returns the substrate's own epoch rather than a wall \
clock, so a recording is reproducible and does not import the host's skew. The divergence from \
a device is real and is recorded as SUB.TIME.WALL_CLOCK.",
        ),
        u(
            "which_facts_are_the_substrates",
            "not_implemented",
            "NOTHING HERE CAN BE OBSERVED, AND THIS IS THE MOST IMPORTANT ENTRY IN THE LIST. A \
substrate that terminates every side effect cannot tell an analyst, from one recording, which \
facts are the app's and which are its own; every fact in a policy-governed class is a joint \
property. The policy family makes the dependency measurable rather than separating it in one run: \
the substrate's behaviour is a declared parameter, every fabricated value is labelled with the \
axis that produced it, and the separation is obtained by running the same program under two \
policies and diffing. That is a measurement across runs, not an observation within one, and no \
single ground-truth/1 document can substitute for it.",
        ),
    ];
    // And now the per-value gaps: what THIS declared substrate gives up relative
    // to the default. Growing with the policy, never with the app.
    if policy.time.reproducible() {
        v.push(u(
            "host_wall_clock",
            "scope_out_of_protocol",
            &format!(
                "This run used the substrate's own time axis ({}), so the host's clock was not \
exposed. That is a choice, not an absence: the substrate_policy declaration is where a reader \
finds it, and docs/decisions/0006-substrate-policy.md is why the choice is a parameter.",
                policy.time.as_str()
            ),
        ));
    }
    for a in [
        Axis::Identity,
        Axis::SystemFs,
        Axis::CrossAppPackages,
        Axis::Network,
        Axis::Time,
    ] {
        let d = SubstratePolicy::default();
        if policy.axis(a) == d.axis(a) {
            continue;
        }
        v.push(u(
            &format!("substrate_policy_axis_{}", a.as_str()),
            "scope_out_of_protocol",
            &format!(
                "This run declared substrate_policy axis {} = {} rather than the recorder default \
{}. The axis governs {} in this document, and every value it produced is labelled at emission. \
Facts in those classes are joint properties of the app and this declaration; the two-arm \
differential in shim/recordings/ is how they are separated.",
                a.as_str(),
                policy.axis(a),
                d.axis(a),
                a.governs()
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    v
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}
