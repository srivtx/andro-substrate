//! The real workload: an APK's own bytecode, run under a substrate policy.
//!
//! # Why this module exists
//!
//! `shim::scenario` drives the shim with a hand-written, branch-free call
//! sequence. That is a fine way to prove the observation layer *works* and a
//! poor way to measure anything, for the reason its own author wrote down: a
//! script with no `HashMap`, no retry, no locale and no frame callback is
//! degenerate with respect to exactly the confound the differential is about.
//!
//! Here the calls come from bytecode. Nothing invokes
//! [`Shim::invoke`](crate::dispatch::Shim) unless an `invoke-*` instruction in
//! the APK's own `classes.dex` did, so:
//!
//! * an app that never touches the network produces **no** network attempt;
//! * an app that calls `Build.FINGERPRINT` twice produces two field reads and
//!   the second one is visible as a second one;
//! * an app that fails on a missing framework method fails *there*, and the
//!   missing method is named in the recording.
//!
//! The last one is the measurement this project most needs, and the reason
//! nothing here fabricates a framework class to make an app survive. See
//! [`DexRun::missing_surface`], which is a *count of what the shim does not
//! have*, not a to-do list.
//!
//! # What it does not do, and will not
//!
//! * **No DEX merging.** The app's file and the shim's file stay two files, and
//!   the shim's class declarations are layered in front of the app's class
//!   *table* (ADR 0005). A `classes2.dex` is counted and named as a limit, not
//!   loaded.
//! * **No first frame.** There is no display, so a frame is never drawn and
//!   `first_frame_drawn` is never emitted. `L2_FIRST_FRAME_DRAWN` is therefore
//!   structurally unreachable from here, and saying so is more useful than
//!   emitting the event to look complete.
//! * **No `invokedynamic`.** [`SubstrateHost::resolve_call_site`] records the
//!   refusal and names the bootstrap; the run stops at the first one, which is
//!   the `SUB.FW.INVOKEDYNAMIC` claim, measured rather than asserted.
//!
//! # The rung ladder
//!
//! [`DexRun::terminal`] is derived from the lifecycle points actually observed,
//! by the *same* function the synthetic capture uses
//! ([`crate::recording::derive_terminal`]), so the two cannot disagree and the
//! validator's own `deriveTerminal` is the third opinion on the same events.

use std::collections::BTreeSet;

pub use dexinterp::config::Config;
use dexinterp::config::Stats;
use dexinterp::error::ExecError;
use dexinterp::value::Value as EngineValue;
use dexinterp::Interpreter;
use serde_json::Value as J;

use crate::dispatch::Shim;
use crate::event::{Detail, Group, Source, SubstrateEvent, Tier};
use crate::interp::SubstrateHost;
use crate::layout::Size;
use crate::policy::SubstratePolicy;
use crate::recording::{derive_terminal, CaptureFacts, Extras, LifecyclePoint};

/// Static facts about the subject, read by the harness from the APK.
///
/// Carried in rather than parsed here because this crate has no `std::fs` and no
/// ZIP reader by design (`tests/egress_denial.rs` asserts the surface is empty);
/// the manifest is the harness's job and this module is the consumer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApkIdentity {
    /// `package` from the manifest.
    pub package: String,
    /// `android:versionCode`.
    pub version_code: u32,
    /// `android:versionName`.
    pub version_name: String,
    /// `uses-sdk` / `minSdkVersion`.
    pub min_sdk: u32,
    /// `targetSdkVersion`.
    pub target_sdk: u32,
    /// Every `uses-permission` name.
    pub permissions: Vec<String>,
    /// The `application` class, dotted, or `None`.
    pub application: Option<String>,
    /// The launcher activity, dotted, or `None`.
    pub launcher_activity: Option<String>,
    /// Every declared `activity`, dotted, in manifest order.
    pub activities: Vec<String>,
    /// `classes2.dex` … `classesN.dex`: present in the APK, not loaded.
    pub extra_dex_files: usize,
    /// SHA-256 of the APK.
    pub apk_sha256: String,
    /// Size of the APK in bytes.
    pub apk_size_bytes: u64,
    /// SHA-256 of the `classes.dex` that *was* loaded.
    pub dex_sha256: String,
}

/// What kind of entry point a stage ran, for the results table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageKind {
    /// A `static` method with a body, called with no arguments.
    StaticMethod,
    /// `new-instance` plus `invoke-direct <init>`.
    Constructor,
    /// An instance method with a body, on an instance the driver allocated.
    InstanceMethod,
    /// `Application.onCreate()`.
    ApplicationOnCreate,
    /// `Activity.onCreate(Bundle)`.
    ActivityOnCreate,
    /// `Activity.onStart()`.
    ActivityOnStart,
    /// `Activity.onResume()`.
    ActivityOnResume,
}

impl StageKind {
    /// A stable token for a report.
    pub fn as_str(self) -> &'static str {
        match self {
            StageKind::StaticMethod => "static_method",
            StageKind::Constructor => "constructor",
            StageKind::InstanceMethod => "instance_method",
            StageKind::ApplicationOnCreate => "application_onCreate",
            StageKind::ActivityOnCreate => "activity_onCreate",
            StageKind::ActivityOnStart => "activity_onStart",
            StageKind::ActivityOnResume => "activity_onResume",
        }
    }
}

/// What one stage did.
#[derive(Debug, Clone, PartialEq)]
pub struct StageOutcome {
    /// Which kind of entry point this was.
    pub kind: StageKind,
    /// The class, as a type descriptor.
    pub class: String,
    /// The method name.
    pub method: String,
    /// The prototype descriptor.
    pub signature: String,
    /// Whether the method returned normally.
    pub completed: bool,
    /// The engine's terminal condition when it did not, as a stable `kind()`.
    pub error_kind: Option<String>,
    /// The full message, for the results file.
    pub error: Option<String>,
    /// Instructions executed during this stage.
    pub instructions: u64,
    /// Framework calls made during this stage.
    pub framework_calls: u64,
    /// Of those, the ones the shim did not implement.
    pub unimplemented: u64,
    /// Framework methods the shim does not have, first seen in this stage.
    ///
    /// **The headline number.** A stage's failure here names the exact
    /// `Landroid/…;.m()V` the app needed and the shim lacks, which is the
    /// project's first real measurement of the shim's compatibility surface.
    pub missing_surface: Vec<String>,
}

/// A completed run.
#[derive(Debug)]
pub struct DexRun {
    /// The document, in `ground-truth/1` shape.
    pub document: J,
    /// Every stage, in order, including the one that failed.
    pub stages: Vec<StageOutcome>,
    /// The lifecycle points actually observed.
    pub lifecycle: Vec<LifecyclePoint>,
    /// The derived terminal, from [`derive_terminal`].
    pub terminal: &'static str,
    /// The shim's events.
    pub events: Vec<SubstrateEvent>,
    /// The engine's counters.
    pub stats: Stats,
    /// Framework methods the shim does not have, over the whole run, sorted.
    pub missing_surface: Vec<String>,
    /// Every `(class, name, signature)` nothing could answer, engine-wide.
    ///
    /// The compatibility surface as a set rather than as a sequence of calls,
    /// and distinct from `missing_surface`: a method the shim was *asked* for
    /// and declined, versus one nothing declares.
    pub unresolved: Vec<String>,
    /// App classes the shim shadowed, from the class table.
    pub shadowed: Vec<String>,
    /// `invokedynamic` bootstrap owners the substrate refused, sorted.
    pub indy_refused: Vec<String>,
    /// Calls declined because an argument had no shim-side representation.
    pub unrepresentable: u64,
    /// The first stage that did not complete.
    pub stopped_at: Option<usize>,
}

/// How to drive a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// One named method, to prove that a specific thing executes.
    ///
    /// `signature` is the prototype descriptor and `static_call` says whether the
    /// first argument is absent. This is the lowest rung that still proves class
    /// resolution end to end.
    OneMethod {
        /// Type descriptor of the declaring class.
        class: String,
        /// Method name.
        method: String,
        /// Prototype descriptor.
        signature: String,
        /// Whether it is a `static` method.
        static_call: bool,
    },
    /// The `Application` then `Activity` lifecycle, in the order Android runs it.
    Lifecycle,
}

/// Every class descriptor the app's own DEX defines.
///
/// Read with `dexcore` rather than from the engine's `Program` so that the shim's
/// `ClassLoader` and the interpreter's class table are built from the *same*
/// answer and cannot disagree about which classes the app has.
fn app_descriptors(dex_bytes: &[u8]) -> Vec<String> {
    let reader = match dexcore::DexReader::open(dex_bytes) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for i in 0..reader.class_def_count() {
        if let Ok(d) = reader.class_def(i) {
            out.push(d.descriptor);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Run `app_dex` under `policy`.
///
/// The shim's DEX is emitted from this crate's own registry, so the framework
/// layer a run sees is exactly the one `shim::emit::verify_prototypes` checks.
pub fn run(
    app_dex: &[u8],
    policy: &SubstratePolicy,
    identity: &ApkIdentity,
    plan: &Plan,
    config: Config,
) -> Result<DexRun, crate::error::ShimError> {
    let shim_dex = crate::emit::emit().map_err(|e| crate::error::ShimError::Dex(e.to_string()))?;
    let shim_bytes = shim_dex.bytes.clone();
    let shim_digest = shim_dex.digest.clone();
    // Kept for `provenance.capture_script_sha256`: the schema wants a real
    // capture tied to the exact code that produced it, and for a substrate run
    // that code is the DEX the framework layer was built from.
    let shim_digest_for_recorder = shim_digest.clone();
    let shim_reader = dexcore::DexReader::open(&shim_bytes)
        .map_err(|e| crate::error::ShimError::Dex(e.to_string()))?;
    let host_classes = dexinterp::program::host_classes_from_dex(&shim_reader)
        .map_err(|e| crate::error::ShimError::Dex(e.to_string()))?;
    let app_reader = dexcore::DexReader::open(app_dex)
        .map_err(|e| crate::error::ShimError::Dex(e.to_string()))?;
    let config_budget = config.instruction_budget;
    let mut vm = dexinterp::new_layered_interpreter(app_reader, &host_classes, config)
        .map_err(|e| crate::error::ShimError::Dex(e.to_string()))?;
    let shim = Shim::with_policy(&identity.package, app_descriptors(app_dex), *policy)?;
    let host = SubstrateHost::new(shim);
    vm.set_host(Box::new(host));

    let mut stages: Vec<StageOutcome> = Vec::new();
    let mut lifecycle: Vec<LifecyclePoint> = Vec::new();
    let mut missing: BTreeSet<String> = BTreeSet::new();
    let mut stopped_at: Option<usize> = None;
    let mut fatal_after_resume = false;

    // `process_start` is a substrate decision, not a measurement: the recorder
    // started. It is emitted first so every later point has a window, and it is
    // the only point the driver invents — the rest are recorded when a lifecycle
    // method *returns*.
    lifecycle.push(LifecyclePoint {
        kind: "process_start",
        t_mono_ms: 0,
        component: identity.package.clone(),
        pattern: "LIFECYCLE_PAT.SUBSTRATE_T0",
    });

    match plan {
        Plan::OneMethod {
            class,
            method,
            signature,
            static_call,
        } => {
            let kind = if *static_call {
                StageKind::StaticMethod
            } else {
                StageKind::InstanceMethod
            };
            let args: Vec<EngineValue> = if *static_call {
                Vec::new()
            } else {
                match vm.allocate(class) {
                    Ok(v) => vec![v],
                    Err(e) => {
                        stages.push(StageOutcome {
                            kind,
                            class: class.clone(),
                            method: method.clone(),
                            signature: signature.clone(),
                            completed: false,
                            error_kind: Some(e.termination().as_str().to_string()),
                            error: Some(format!("the object could not be allocated: {e}")),
                            instructions: 0,
                            framework_calls: 0,
                            unimplemented: 0,
                            missing_surface: Vec::new(),
                        });
                        stopped_at = Some(0);
                        Vec::new()
                    }
                }
            };
            if *static_call || !args.is_empty() {
                let before_ins = vm.stats().instructions_executed;
                let before_fw = vm.stats().framework_calls;
                let mark = mark(&vm);
                let outcome = vm.invoke_method(class, method, signature, &args);
                let out = stage_outcome(
                    kind,
                    class,
                    method,
                    signature,
                    &vm,
                    before_ins,
                    before_fw,
                    mark.log,
                    mark.unresolved,
                    outcome,
                );
                if !out.completed {
                    stopped_at = Some(stages.len());
                }
                push_stage(&mut stages, &mut missing, out);
            }
        }
        Plan::Lifecycle => {
            let app_class = identity
                .application
                .as_ref()
                .map(|d| format!("L{};", d.replace('.', "/")))
                .unwrap_or_default();
            let activity_class = identity
                .launcher_activity
                .as_ref()
                .or_else(|| identity.activities.first())
                .map(|d| format!("L{};", d.replace('.', "/")))
                .unwrap_or_default();

            let dotted = |desc: &str| -> String {
                desc.trim_start_matches('L')
                    .trim_end_matches(';')
                    .replace('/', ".")
            };

            // ---- the Application, if the manifest names one
            let mut app_obj: Option<EngineValue> = None;
            if !app_class.is_empty() {
                let ctor = pick_ctor(&vm, &app_class);
                match ctor {
                    None => {
                        stages.push(StageOutcome {
                            kind: StageKind::Constructor,
                            class: app_class.clone(),
                            method: "<init>".into(),
                            signature: "()V".into(),
                            completed: false,
                            error_kind: Some("MethodNotFound".into()),
                            error: Some(format!(
                                "{app_class} declares no constructor at all, so the substrate                                  cannot build one. The manifest names it as the <application>                                  class, which is a claim the APK makes and the DEX does not back."
                            )),
                            instructions: 0,
                            framework_calls: 0,
                            unimplemented: 0,
                            missing_surface: Vec::new(),
                        });
                        stopped_at = Some(stages.len().saturating_sub(1));
                    }
                    Some(sig) => {
                        match drive_ctor(&mut vm, &app_class, &sig, &mut stages, &mut missing) {
                            Ok(v) => app_obj = Some(v),
                            Err(()) => stopped_at = Some(stages.len().saturating_sub(1)),
                        }
                    }
                }
                if stopped_at.is_none() {
                    if let Some(v) = app_obj {
                        // `Application.onCreate()` is `()V` and nothing else, so a
                        // hard-coded signature would be right by accident. The
                        // lookup below means the stage is the app's own override
                        // when it has one and the shim's when it does not.
                        let sig = vm
                            .prototypes(&app_class, "onCreate")
                            .into_iter()
                            .find(|p| p == "()V")
                            .unwrap_or_else(|| "()V".into());
                        match drive_noargs(
                            &mut vm,
                            &app_class,
                            v,
                            "onCreate",
                            &sig,
                            StageKind::ApplicationOnCreate,
                            &mut stages,
                            &mut missing,
                        ) {
                            Ok(()) => {}
                            Err(()) => stopped_at = Some(stages.len().saturating_sub(1)),
                        }
                    }
                }
            }

            // ---- the Activity
            let mut activity_obj: Option<EngineValue> = None;
            if stopped_at.is_none() && !activity_class.is_empty() {
                let ctor = pick_ctor(&vm, &activity_class);
                match ctor {
                    None => {
                        stages.push(StageOutcome {
                            kind: StageKind::Constructor,
                            class: activity_class.clone(),
                            method: "<init>".into(),
                            signature: "()V".into(),
                            completed: false,
                            error_kind: Some("MethodNotFound".into()),
                            error: Some(format!("{activity_class} declares no constructor at all")),
                            instructions: 0,
                            framework_calls: 0,
                            unimplemented: 0,
                            missing_surface: Vec::new(),
                        });
                        stopped_at = Some(stages.len().saturating_sub(1));
                    }
                    Some(sig) => {
                        match drive_ctor(&mut vm, &activity_class, &sig, &mut stages, &mut missing)
                        {
                            Ok(v) => activity_obj = Some(v),
                            Err(()) => stopped_at = Some(stages.len().saturating_sub(1)),
                        }
                    }
                }
            }
            // `onCreate(Bundle)`. The `Bundle` is allocated by the driver, which
            // is a substrate decision and is declared as one: a real launch hands
            // the activity an empty bundle, and the substrate's `Bundle` is the
            // substrate's, not the app's.
            if stopped_at.is_none() && activity_obj.is_some() {
                let obj = activity_obj.unwrap_or(EngineValue::Null);
                let bundle = vm
                    .allocate("Landroid/os/Bundle;")
                    .unwrap_or(EngineValue::Null);
                let before_ins = vm.stats().instructions_executed;
                let before_fw = vm.stats().framework_calls;
                let mark = mark(&vm);
                let sig = pick_bundle_ctor(&vm, &activity_class, "onCreate");
                let outcome = vm.invoke_method(&activity_class, "onCreate", &sig, &[obj, bundle]);
                let out = stage_outcome(
                    StageKind::ActivityOnCreate,
                    &activity_class,
                    "onCreate",
                    &sig,
                    &vm,
                    before_ins,
                    before_fw,
                    mark.log,
                    mark.unresolved,
                    outcome,
                );
                if !out.completed {
                    stopped_at = Some(stages.len());
                } else {
                    lifecycle.push(LifecyclePoint {
                        kind: "activity_create",
                        t_mono_ms: vm.stats().instructions_executed,
                        component: dotted(&activity_class),
                        pattern: "LIFECYCLE_PAT.AM_ON_CREATE",
                    });
                }
                push_stage(&mut stages, &mut missing, out);
            }
            for (name, kind, event_kind) in [
                ("onStart", StageKind::ActivityOnStart, "activity_start"),
                ("onResume", StageKind::ActivityOnResume, "activity_resume"),
            ] {
                #[allow(clippy::needless_range_loop)]
                if stopped_at.is_some() {
                    break;
                }
                let obj = match activity_obj {
                    Some(v) => v,
                    None => break,
                };
                let before_ins = vm.stats().instructions_executed;
                let before_fw = vm.stats().framework_calls;
                let mark = mark(&vm);
                let sig = pick_noargs(&vm, &activity_class, name);
                let outcome = vm.invoke_method(&activity_class, name, &sig, &[obj]);
                let out = stage_outcome(
                    kind,
                    &activity_class,
                    name,
                    &sig,
                    &vm,
                    before_ins,
                    before_fw,
                    mark.log,
                    mark.unresolved,
                    outcome,
                );
                let completed = out.completed;
                push_stage(&mut stages, &mut missing, out);
                if completed {
                    lifecycle.push(LifecyclePoint {
                        kind: event_kind,
                        t_mono_ms: vm.stats().instructions_executed,
                        component: dotted(&activity_class),
                        pattern: if name == "onStart" {
                            "LIFECYCLE_PAT.AM_ON_START"
                        } else {
                            "LIFECYCLE_PAT.AM_ON_RESUME"
                        },
                    });
                } else {
                    fatal_after_resume = lifecycle.iter().any(|l| l.kind == "activity_resume");
                    stopped_at = Some(stages.len().saturating_sub(1));
                }
            }
        }
    }

    // Recover the shim.
    let boxed: Box<dyn std::any::Any> = vm.take_host();
    let host = match boxed.downcast::<SubstrateHost>() {
        Ok(h) => *h,
        Err(_) => {
            return Err(crate::error::ShimError::Encode(
                "the host that ran was not the one this driver installed".into(),
            ))
        }
    };
    let unrepresentable = host.unrepresentable_calls();
    let mut indy: Vec<String> = host.indy_refused().to_vec();
    indy.sort();
    indy.dedup();
    let mut shim = host.into_shim();
    let events = shim.take_events();
    let vfs_listing = shim.vfs().listing();
    let stats = vm.stats();

    // No frame. There is no display, so `first_frame_drawn` is never emitted and
    // the terminal cannot exceed `L1_ACTIVITY_RESUMED`. Said here rather than
    // left to a reader to infer from an absent event.
    let terminal = derive_terminal(&lifecycle, fatal_after_resume);

    let box_tree = shim
        .run_layout(Size {
            width: 1080,
            height: 2340,
        })
        .ok()
        .and_then(|b| serde_json::to_value(&b).ok());

    let mut facts = CaptureFacts::fixture_with(*policy);
    facts.package = identity.package.clone();
    facts.version_code = identity.version_code;
    facts.version_name = identity.version_name.clone();
    facts.min_sdk = identity.min_sdk;
    facts.target_sdk = identity.target_sdk;
    facts.declared_permissions = identity.permissions.clone();
    facts.shim_dex_sha256 = shim_digest;
    facts.toolchain_revision = format!(
        "andro-substrate harness; shim {}; interpreter {}; dexinterp+shim+dexcore built from \
         this working tree",
        crate::VERSION,
        env!("CARGO_PKG_VERSION")
    );
    facts.lifecycle = lifecycle.clone();
    let extras = Extras {
        box_tree: box_tree.clone(),
        vfs_listing,
    };
    let missing_surface: Vec<String> = missing.iter().cloned().collect();
    let real = crate::realrec::RealFacts {
        apk_size_bytes: identity.apk_size_bytes,
        extra_dex_files: identity.extra_dex_files,
        launched_component: identity.launcher_activity.clone(),
        native_libs: Vec::new(),
        debuggable: false,
        instruction_budget: config_budget,
        instructions_executed: stats.instructions_executed,
        distinct_opcodes: stats.distinct_opcodes(),
        framework_calls: stats.framework_calls,
        recorder_digest: shim_digest_for_recorder.clone(),
        stopped_because: describe_stop(&stages, stopped_at),
        missing_surface: missing_surface.clone(),
        shadowed_classes: stats.shadowed_classes.clone(),
        indy_refused: indy.clone(),
    };
    let document = crate::realrec::build_real(&facts, &events, &extras, &real)?;

    Ok(DexRun {
        document,
        stages,
        lifecycle,
        terminal,
        events,
        missing_surface,
        unresolved: stats.unresolved_methods.clone(),
        shadowed: stats.shadowed_classes.clone(),
        indy_refused: indy,
        unrepresentable,
        stats,
        stopped_at,
    })
}

/// One sentence naming the stage the run stopped at, for `provenance.notes`.
///
/// Written here rather than in the caller because "where did it stop and what was
/// missing there" is the single most quoted sentence in the results file, and a
/// results file that quotes it should not be quoting a `format!` in a test.
pub fn describe_stop(stages: &[StageOutcome], stopped_at: Option<usize>) -> String {
    match stopped_at.and_then(|i| stages.get(i)) {
        Some(s) => {
            let missing = s
                .missing_surface
                .first()
                .cloned()
                .unwrap_or_else(|| "no framework method was missing at this stage".into());
            format!(
                "it stopped in {}.{}() [{}] with {}. The engine reported: {}",
                s.class,
                s.method,
                s.signature,
                missing,
                s.error.as_deref().unwrap_or("(none)")
            )
        }
        None => "every stage the driver attempted completed".to_string(),
    }
}

/// Choose a constructor prototype, preferring the no-argument one.
///
/// An `Activity`'s real constructors are `()`, `(Context)`, `(Context,AttributeSet)`
/// and `(int,Context,AttributeSet)`, and which of them the DEX declares is the
/// app's business. `()` is tried first because it is the one that needs no
/// framework object the driver would have to invent; `Object.<init>()` is
/// always inherited, so the search finds something for every class, and the
/// search order is the *substrate's* choice, which is why the chosen signature
/// is written into the stage line rather than assumed.
fn pick_ctor(vm: &Interpreter<'_>, class: &str) -> Option<String> {
    let protos = vm.prototypes(class, "<init>");
    for want in ["()V", "(Landroid/content/Context;)V"] {
        if protos.iter().any(|p| p == want) {
            return Some(want.to_string());
        }
    }
    protos.into_iter().next()
}

/// Choose the `onCreate` prototype that takes a `Bundle` and nothing else.
fn pick_bundle_ctor(vm: &Interpreter<'_>, class: &str, name: &str) -> String {
    let protos = vm.prototypes(class, name);
    for want in ["(Landroid/os/Bundle;)V"] {
        if protos.iter().any(|p| p == want) {
            return want.to_string();
        }
    }
    protos
        .into_iter()
        .find(|p| p.starts_with("(Landroid/os/Bundle;"))
        .unwrap_or_else(|| "(Landroid/os/Bundle;)V".to_string())
}

/// Choose a zero-parameter prototype, falling back to whatever exists.
fn pick_noargs(vm: &Interpreter<'_>, class: &str, name: &str) -> String {
    let protos = vm.prototypes(class, name);
    if protos.iter().any(|p| p == "()V") {
        return "()V".to_string();
    }
    protos
        .into_iter()
        .next()
        .unwrap_or_else(|| "()V".to_string())
}

/// A marker in the engine's cumulative logs, so a stage can be told what *it*
/// added rather than what the run has seen so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogMark {
    /// How many `ShimRecord`s existed before the stage.
    log: usize,
    /// How many distinct unresolvable methods existed before the stage.
    unresolved: usize,
}

fn mark(vm: &Interpreter<'_>) -> LogMark {
    let s = vm.stats();
    LogMark {
        log: s.shim_log.len(),
        unresolved: s.unresolved_methods.len(),
    }
}

/// Add a stage and fold its missing surface into the run-wide set.
fn push_stage(stages: &mut Vec<StageOutcome>, missing: &mut BTreeSet<String>, out: StageOutcome) {
    for m in &out.missing_surface {
        missing.insert(m.clone());
    }
    stages.push(out);
}

/// `new-instance` + `invoke-direct <init>`.
fn drive_ctor(
    vm: &mut Interpreter<'_>,
    class: &str,
    signature: &str,
    stages: &mut Vec<StageOutcome>,
    missing: &mut BTreeSet<String>,
) -> Result<EngineValue, ()> {
    let obj = match vm.allocate(class) {
        Ok(v) => v,
        Err(e) => {
            stages.push(StageOutcome {
                kind: StageKind::Constructor,
                class: class.to_string(),
                method: "<init>".to_string(),
                signature: signature.to_string(),
                completed: false,
                error_kind: Some(e.termination().as_str().to_string()),
                error: Some(e.to_string()),
                instructions: 0,
                framework_calls: 0,
                unimplemented: 0,
                missing_surface: Vec::new(),
            });
            return Err(());
        }
    };
    let before_ins = vm.stats().instructions_executed;
    let before_fw = vm.stats().framework_calls;
    let mark = mark(vm);
    let outcome = vm.invoke_method(class, "<init>", signature, &[obj]);
    let out = stage_outcome(
        StageKind::Constructor,
        class,
        "<init>",
        signature,
        vm,
        before_ins,
        before_fw,
        mark.log,
        mark.unresolved,
        outcome,
    );
    let ok = out.completed;
    for m in &out.missing_surface {
        missing.insert(m.clone());
    }
    stages.push(out);
    if ok {
        Ok(obj)
    } else {
        Err(())
    }
}

/// An instance method with no parameters, on an object the driver already has.
#[allow(clippy::too_many_arguments)]
fn drive_noargs(
    vm: &mut Interpreter<'_>,
    class: &str,
    obj: EngineValue,
    method: &str,
    signature: &str,
    kind: StageKind,
    stages: &mut Vec<StageOutcome>,
    missing: &mut BTreeSet<String>,
) -> Result<(), ()> {
    let before_ins = vm.stats().instructions_executed;
    let before_fw = vm.stats().framework_calls;
    let mark = mark(vm);
    let outcome = vm.invoke_method(class, method, signature, &[obj]);
    let out = stage_outcome(
        kind,
        class,
        method,
        signature,
        vm,
        before_ins,
        before_fw,
        mark.log,
        mark.unresolved,
        outcome,
    );
    let ok = out.completed;
    for m in &out.missing_surface {
        missing.insert(m.clone());
    }
    stages.push(out);
    if ok {
        Ok(())
    } else {
        Err(())
    }
}

/// Build one stage's outcome from an `invoke_method` result.
///
/// The `missing_surface` list is taken from the engine's own bounded
/// [`ShimRecord`](dexinterp::config::ShimRecord) log, filtered to entries added
/// during this stage. That log is the engine's, not the shim's, and it is
/// bounded by `Config::max_shim_log`, so a stage that made a million framework
/// calls reports the first 4096 and the caller can see the truncation through
/// `Stats::shim_log_truncated`.
#[allow(clippy::too_many_arguments)]
fn stage_outcome(
    kind: StageKind,
    class: &str,
    method: &str,
    signature: &str,
    vm: &Interpreter<'_>,
    before_ins: u64,
    before_fw: u64,
    before_log: usize,
    before_unresolved: usize,
    outcome: Result<EngineValue, ExecError>,
) -> StageOutcome {
    let stats = vm.stats();
    let mut missing_surface: Vec<String> = Vec::new();
    // Only the entries this stage appended. The log is cumulative and the study
    // question is "what did it need to get *here*", so a stage that inherits its
    // predecessor's wish list reports the run's total four times and answers
    // nothing.
    for rec in stats.shim_log.iter().skip(before_log) {
        if rec.implemented {
            continue;
        }
        if !rec.class.starts_with("Landroid/") && !rec.class.starts_with("Ljava/") {
            continue;
        }
        missing_surface.push(format!("{}.{}{}", rec.class, rec.name, rec.signature));
    }
    // And the methods nothing at all could answer, which never reach the shim
    // because the engine raises the `NoSuchMethodError` itself. Prefixed, because
    // "the shim was asked and declined" and "nothing declares this" are different
    // facts about the same missing surface.
    for m in stats.unresolved_methods.iter().skip(before_unresolved) {
        missing_surface.push(format!("undeclared: {m}"));
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    missing_surface.retain(|m| seen.insert(m.clone()));
    match outcome {
        Ok(_) => StageOutcome {
            kind,
            class: class.to_string(),
            method: method.to_string(),
            signature: signature.to_string(),
            completed: true,
            error_kind: None,
            error: None,
            instructions: stats.instructions_executed.saturating_sub(before_ins),
            framework_calls: stats.framework_calls.saturating_sub(before_fw),
            unimplemented: stats
                .framework_calls_unimplemented
                .saturating_sub(0)
                .min(stats.framework_calls.saturating_sub(before_fw)),
            missing_surface,
        },
        Err(e) => StageOutcome {
            kind,
            class: class.to_string(),
            method: method.to_string(),
            signature: signature.to_string(),
            completed: false,
            error_kind: Some(e.termination().as_str().to_string()),
            error: Some(e.to_string()),
            instructions: stats.instructions_executed.saturating_sub(before_ins),
            framework_calls: stats.framework_calls.saturating_sub(before_fw),
            unimplemented: stats.framework_calls.saturating_sub(before_fw),
            missing_surface,
        },
    }
}

/// A synthetic note the driver can attach to its recording.
pub fn note_unobserved(
    group: Group,
    source: Source,
    tier: Tier,
    pattern: &'static str,
    detail: String,
) -> SubstrateEvent {
    SubstrateEvent {
        seq: 0,
        t_mono_ms: 0,
        group,
        source,
        tier,
        assumption: None,
        detail: Detail::Probes {
            pattern,
            detail,
            axis: None,
        },
    }
}
