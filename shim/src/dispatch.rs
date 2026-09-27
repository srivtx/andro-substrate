//! The boundary between the shim and an interpreter, and the shim's side of it.
//!
//! # What this crate deliberately does not have
//!
//! No interpreter, no bytecode evaluator, no frame stack, no object heap for
//! app values. Another agent owns that. What this crate owns is the thing an
//! interpreter needs in order to *route* a call into the shim instead of into a
//! missing class, and the guarantee that routing is where all observation
//! happens.
//!
//! # The trait
//!
//! [`ShimCaller`] is the whole contract, and it is four methods wide on purpose.
//! An interpreter that has resolved `(class, name, descriptor)` to a shim method
//! calls [`ShimCaller::invoke`] and gets a [`Value`] back. It does not need to
//! know anything about the VFS, the egress sink, the redaction policy or the
//! recorder, and it cannot reach any of them: they are all private fields of
//! [`Shim`].
//!
//! That is the design goal. The observation layer is the *only* path from an app
//! to a side effect, which is what makes "the shim observes every interaction"
//! a structural property rather than a claim. There is no second door for an
//! interpreter to find later, and no environment variable that opens one.
//!
//! # The argument convention
//!
//! `args[0]` is `this` for an instance method and is absent for a static one.
//! That matches what an interpreter already has in hand — `this` is the object
//! in the invoke's first register — so the contract costs the interpreter
//! nothing and costs the shim a single well-documented rule. `Behaviour::Field`
//! accessors, `Bundle` mutation and `File` path reads all need the receiver, and
//! the alternative (a separate "current receiver" field the host has to set) is
//! the kind of ambient state that eventually gets out of step.
//!
//! # The mock
//!
//! [`testing::MockCaller`] implements the same trait and records what it was
//! asked for. Every test of the *interpreter's* side of the contract uses it, so
//! the two halves can be developed in parallel and neither has to wait for the
//! other to exist.

use std::collections::BTreeMap;

use crate::classes::{AppDex, ClassLoader};
use crate::error::{EgressDenial, ShimError, VfsError};
use crate::event::{
    CapturePolicy, Detail, FsOp, Group, NativeOutcome, Resolution, Source, SubstrateEvent, Tier,
};
use crate::layout::{self, BoxNode, Size, TextPolicy, View};
use crate::net::{EgressRequest, EgressSink};
use crate::redact::{HeaderNames, HttpMethod, RequestMeta};
use crate::registry::{self, Behaviour};
use crate::system::{self, BuildInfo, Capabilities, Clock, SystemTree};
use crate::taxonomy::AssumptionId;
use crate::vfs::{VPath, Vfs};

/// A value crossing the shim boundary.
///
/// Deliberately small and deliberately *not* a JVM value. The interpreter owns
/// representation; the shim only needs enough to make a decision, and a richer
/// type here would be a place for the two to disagree about what a reference is.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A Dalvik `null`.
    Null,
    /// A 32-bit integer. Also carries `boolean` and `char`.
    Int(i32),
    /// A 64-bit integer.
    Long(i64),
    /// A float.
    Float(f32),
    /// A string, borrowed by value. Strings are the one thing the shim really
    /// does hold: paths, actions, tags, URLs. Each is used to make a decision
    /// and is then dropped or reduced, never stored in an event.
    Str(String),
    /// An opaque handle. The shim does not dereference it; the interpreter does.
    /// It is a `(class, id)` pair so the shim can associate state with an
    /// object without owning it.
    Ref(String, u32),
    /// Bytes, for a body being written to a sink. The shim counts them and
    /// discards them; there is nowhere for them to be stored.
    Bytes(Vec<u8>),
}

impl Value {
    /// The string, if it is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The int, if it is one. `true` counts as 1, as Dalvik does.
    pub fn as_int(&self) -> Option<i32> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// The handle, if there is one.
    pub fn as_ref_id(&self) -> Option<u32> {
        match self {
            Value::Ref(_, id) => Some(*id),
            _ => None,
        }
    }

    /// The byte length of a `Bytes`, or of a `Str`'s UTF-8 encoding. `None` for
    /// anything else, so a caller cannot accidentally report a body length for a
    /// value that has none.
    pub fn byte_len(&self) -> Option<u64> {
        match self {
            Value::Bytes(b) => Some(b.len() as u64),
            Value::Str(s) => Some(s.len() as u64),
            _ => None,
        }
    }
}

/// The one trait an interpreter implements against.
///
/// Object-safe on purpose: an interpreter is a bytecode evaluator and will hold
/// this inside a `Box<dyn ShimCaller>`.
///
/// # The argument convention
///
/// `args[0]` is `this` for an instance method and is absent for a static one.
/// That matches what an interpreter already has in hand — `this` is the object
/// in the invoke's first register — so the contract costs the interpreter
/// nothing and costs the shim a single well-documented rule. `Behaviour::Field`
/// accessors, `Bundle` mutation and `File` path reads all need the receiver, and
/// the alternative (a separate "current receiver" field the host has to set) is
/// the kind of ambient state that eventually gets out of step.
pub trait ShimCaller {
    /// Resolve and invoke a shim method.
    ///
    /// `class` is a type descriptor, `name` a method name, `descriptor` a
    /// parameter-descriptor string, and `args` the already-evaluated arguments
    /// with the receiver first. Returning `Err` means the app sees an exception;
    /// the shim has recorded the attempt either way.
    fn invoke(
        &mut self,
        class: &str,
        name: &str,
        descriptor: &str,
        args: &[Value],
    ) -> Result<Value, ShimError>;

    /// Whether the shim defines a method. An interpreter calls this *before*
    /// `invoke` to decide whether a call site is a shim call, a missing class
    /// (`SUB.FW.CLASS_LOADER`) or its own code. Answering it separately keeps
    /// the "no shim class" path off the error path, which matters: a
    /// `NoClassDefFoundError` and a `NoSuchMethodError` are different
    /// divergences and must not be collapsed.
    fn resolves(&self, class: &str, name: &str, descriptor: &str) -> bool;

    /// Every descriptor the shim defines. A loader calls this once to build its
    /// delegate table, rather than probing per call site.
    fn shim_classes(&self) -> Vec<String>;

    /// Read a **static field**, which is how an app reads `Build.FINGERPRINT`,
    /// `Build$VERSION.SDK_INT` and the `LayoutParams` constants.
    ///
    /// A separate method rather than a shim method because a Dalvik `sget` has no
    /// method to route through: the field *is* the interface, and pretending
    /// otherwise would invent a method Android does not have. It is still
    /// observation-bearing, which is why it lives on the same trait — an
    /// `sget` on a shim class is exactly the observation the project needs and
    /// exactly what a device arm cannot see.
    fn read_static(&mut self, class: &str, name: &str) -> Result<Value, ShimError>;

    /// A snapshot of what has been observed so far. `&self`, so a recording can
    /// be taken mid-run without disturbing it.
    fn events(&self) -> &[SubstrateEvent];
}

/// A zero of the right shape. `null` for a reference, 0 for a number, `false`
/// for a boolean.
pub fn default_for(ret: &str) -> Value {
    match ret {
        "V" => Value::Null,
        "Z" => Value::Int(0),
        "I" | "S" | "B" | "C" => Value::Int(0),
        "J" => Value::Long(0),
        "F" | "D" => Value::Float(0.0),
        _ => Value::Null,
    }
}

/// In-memory shim state, keyed by object handle.
///
/// Public so a host can install a view tree through
/// [`Shim::objects_mut_public`]; every field stays crate-private, so a host can
/// set a view and nothing else.
#[derive(Debug, Default)]
pub struct ObjState {
    /// `Bundle` contents. Values are held because the app must read them back;
    /// they are never written to a recording.
    pub(crate) bundle: BTreeMap<String, Value>,
    /// `Intent` fields.
    pub(crate) intent: BTreeMap<String, Value>,
    /// A `File`'s canonical path.
    pub(crate) path: Option<VPath>,
    /// A `java.net.URL`'s parsed request. Parsed, never stored as text: the raw
    /// URL may carry a query string and there is no field here that could hold
    /// one.
    pub(crate) url_meta: Option<RequestMeta>,
    /// A connection under construction, before it is denied.
    pub(crate) connection: Option<ConnectionState>,
    /// A view tree.
    pub(crate) view: Option<View>,
    /// A parcel's contents.
    pub(crate) parcel: Vec<Value>,
}

/// A connection under construction, before it is denied.
#[derive(Debug, Default)]
pub(crate) struct ConnectionState {
    pub(crate) meta: Option<RequestMeta>,
    pub(crate) method: HttpMethod,
    pub(crate) headers: HeaderNames,
    pub(crate) body_bytes: u64,
    pub(crate) timeout_ms: Option<u32>,
}

/// Most objects the shim will track at once. A hostile app can manufacture
/// handles, so the table is bounded and `Shim::object_mut` degrades rather than
/// growing without limit.
pub const MAX_OBJECTS: usize = 65_536;

/// An exception in flight.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingException {
    pub class: String,
    pub message: String,
    pub stack: Vec<String>,
    pub caught: Option<bool>,
}

/// The observation layer.
///
/// Holds every side-effect capability the substrate has. Everything else in the
/// crate is a helper for one of these fields, and nothing outside this struct
/// can reach the VFS or the sink.
#[derive(Debug)]
pub struct Shim {
    pub(crate) loader: ClassLoader,
    pub(crate) build: BuildInfo,
    pub(crate) capabilities: Capabilities,
    pub(crate) system: SystemTree,
    pub(crate) clock: Clock,
    pub(crate) vfs: Vfs,
    pub(crate) sink: EgressSink,
    pub(crate) policy: CapturePolicy,
    pub(crate) text_policy: TextPolicy,
    pub(crate) objects: BTreeMap<u32, ObjState>,
    pub(crate) next_id: u32,
    pub(crate) events: Vec<SubstrateEvent>,
    /// Everything posted to the message queue, with a due time. Nothing drains
    /// it: the substrate has no display and therefore no vsync, and an app that
    /// waits for a frame callback waits forever. Recording the queue depth is the
    /// measurement of `SUB.TIME.VSYNC`.
    pub(crate) queue: Vec<(u64, u64)>,
    pub(crate) pending_exception: Option<PendingException>,
    pub(crate) package: String,
    pub(crate) data_dir: VPath,
}

impl Shim {
    /// Build a shim over one app DEX.
    ///
    /// `app_classes` is the app's own descriptor list, which the loader needs so
    /// that a class resolution can say *where* a class came from — an answer a
    /// device arm cannot give at all.
    pub fn new(package: &str, app_classes: Vec<String>) -> Result<Shim, ShimError> {
        let data_dir = VPath::parse(&format!("/data/data/{package}"))?;
        let vfs = Vfs::with_android_skeleton(&data_dir)?;
        Ok(Shim {
            loader: ClassLoader::new(registry::descriptors(), AppDex {
                package: package.to_string(),
                classes: app_classes,
            }),
            build: BuildInfo::default(),
            capabilities: Capabilities::default(),
            system: SystemTree::default(),
            clock: Clock::new(),
            vfs,
            sink: EgressSink::new(crate::redact::PathPolicy::Full),
            policy: CapturePolicy::default(),
            text_policy: TextPolicy::ShapeOnly,
            objects: BTreeMap::new(),
            next_id: 1,
            events: Vec::new(),
            queue: Vec::new(),
            pending_exception: None,
            package: package.to_string(),
            data_dir,
        })
    }

    /// Replace the path policy. Events already recorded keep the path they were
    /// recorded with, because the event stores the rendered path rather than the
    /// raw one.
    pub fn set_path_policy(&mut self, policy: crate::redact::PathPolicy) {
        self.policy = CapturePolicy { path: policy };
        self.sink.path_policy = policy;
    }

    /// The text policy a layout pass will use.
    pub fn set_text_policy(&mut self, policy: TextPolicy) {
        self.text_policy = policy;
    }

    /// The virtual clock.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// The virtual clock, mutably, so a host can advance time.
    pub fn clock_mut(&mut self) -> &mut Clock {
        &mut self.clock
    }

    /// The subject's package name.
    pub fn package(&self) -> &str {
        &self.package
    }

    /// The VFS, read-only. A caller that could write to the VFS without going
    /// through [`ShimCaller::invoke`] would be a second, unobserved door, so the
    /// accessor hands out `&Vfs` and nothing else.
    pub fn vfs(&self) -> &Vfs {
        &self.vfs
    }

    /// The message-queue depth. `SUB.TIME.VSYNC`'s measurement.
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    /// The synthetic build identity.
    pub fn build(&self) -> &BuildInfo {
        &self.build
    }

    /// The class loader.
    pub fn loader(&self) -> &ClassLoader {
        &self.loader
    }

    /// The app's own data directory in the VFS.
    pub fn data_dir(&self) -> &VPath {
        &self.data_dir
    }

    /// The declared capture policy.
    pub fn policy(&self) -> CapturePolicy {
        self.policy
    }

    /// Take the events, leaving the shim ready for the next segment of a run.
    pub fn take_events(&mut self) -> Vec<SubstrateEvent> {
        std::mem::take(&mut self.events)
    }

    /// Allocate a handle for an object of `class`, with default state.
    pub fn ref_for(&mut self, class: &str) -> Value {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        self.objects.insert(id, ObjState::default());
        Value::Ref(class.to_string(), id)
    }

    /// Run a measure/layout/draw cycle on the shim's root view and record the
    /// pass.
    ///
    /// The tree comes back to the caller *and* goes into the event stream as a
    /// `probes` entry, because the oracle has no top-level field for a view tree
    /// and inventing one would break the comparability the format exists for.
    pub fn run_layout(&mut self, viewport: Size) -> Result<BoxNode, ShimError> {
        let id = self
            .objects
            .iter()
            .find(|(_, s)| s.view.is_some())
            .map(|(id, _)| *id)
            .ok_or_else(|| ShimError::Encode("no view tree installed".into()))?;
        let mut view = match self.objects.get_mut(&id).and_then(|s| s.view.take()) {
            Some(v) => v,
            None => return Err(ShimError::Encode("view tree disappeared".into())),
        };
        let measured = view.measure(viewport);
        view.layout(layout::Rect {
            left: 0,
            top: 0,
            right: measured.width,
            bottom: measured.height,
        });
        let tree = view.draw(self.text_policy);
        if let Some(s) = self.objects.get_mut(&id) {
            s.view = Some(view);
        }
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: self.clock.now_ms(),
            group: Group::Probes,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: Some(AssumptionId::GfxTextRender),
            detail: Detail::Probes {
                pattern: "SIGNAL_PAT.LAYOUT_PASS",
                detail: format!(
                    "{} nodes laid out in {}x{} dp; {} dp^2 of leaf area; font model {}; painted: false \
                     (this layer produces geometry, not pixels)",
                    tree.count(),
                    viewport.width,
                    viewport.height,
                    tree.leaf_area(),
                    layout::metrics::MODEL
                ),
            },
        });
        Ok(tree)
    }

    /// Read a path. Public because a host — or a scenario script — must be able
    /// to drive the VFS without going through a Dalvik method, and going through
    /// a Dalvik method would make the caller contrive a `File` for no reason. It
    /// records identically either way, so it is not a second observation path.
    pub fn read_path_public(&mut self, input: &str) -> Result<Vec<u8>, ShimError> {
        self.read_path(input)
    }

    /// Write a path. See [`Shim::read_path_public`].
    pub fn write_path_public(&mut self, input: &str, data: &[u8]) -> Result<u64, ShimError> {
        self.write_path(input, data)
    }

    /// Install a view tree on an object, for a host that has inflated a layout
    /// the app shipped.
    ///
    /// The one piece of object state a host may write, and the only reason
    /// `ObjState` is exposed at all. The APK's layout XML is not parsed —
    /// `SUB.RES.ARSC` is unsatisfiable without a `resources.arsc` — so the
    /// interpreter builds the tree itself and hands it over here. A layout pass
    /// with an empty tree would prove nothing, and an app that inflates nothing
    /// would look identical to an app whose layout the shim failed to build.
    pub fn set_view_tree(&mut self, handle: &Value, view: View) -> Result<(), ShimError> {
        let id = handle
            .as_ref_id()
            .ok_or_else(|| ShimError::Encode("set_view_tree needs an object handle".into()))?;
        self.object_mut(id).view = Some(view);
        Ok(())
    }

    /// The state of an object, creating it if the handle is new.
    ///
    /// Forgiving on purpose. An interpreter may hand over a handle the shim has
    /// never seen — a field of an app object the shim only partially models, for
    /// instance — and a `Bundle.putString` that silently lost its write would be
    /// an unobservable divergence, which is the one failure mode this crate exists
    /// to prevent. The map is bounded so a hostile app cannot grow it without
    /// limit.
    pub(crate) fn object_mut(&mut self, id: u32) -> &mut ObjState {
        if !self.objects.contains_key(&id) && self.objects.len() >= MAX_OBJECTS {
            // Saturated: hand back the root object's state rather than allocate.
            // The write is then lost, and `capture_quality` says the shim has a
            // bounded object table, so the loss is declared rather than silent.
            return self.objects.entry(0).or_default();
        }
        self.objects.entry(id).or_default()
    }

    /// The class loader, mutably, for a host registering a dynamic-code prefix.
    pub fn loader_mut(&mut self) -> &mut ClassLoader {
        &mut self.loader
    }

    /// The next event sequence number. Assigned at record time so the sequence is
    /// gap-free even when a `sysfs_events` pair is emitted, which reserves two.
    pub(crate) fn next_seq(&self) -> u64 {
        self.events.len() as u64
    }

    /// Record an event, stamping the sequence and the current virtual time.
    pub(crate) fn record(&mut self, mut ev: SubstrateEvent) {
        ev.seq = self.events.len() as u64;
        ev.t_mono_ms = self.clock.now_ms();
        self.events.push(ev);
    }

    /// Record an event with the caller's sequence and time. Only for the
    /// `sysfs_events` pair, which must be contiguous.
    fn record_raw(&mut self, ev: SubstrateEvent) {
        self.events.push(ev);
    }

    /// Read a system-tree path, recording both the `fs` and the `probes` event.
    fn read_system_tree(&mut self, input: &str, op: FsOp) -> Option<String> {
        let path = VPath::parse(input).ok()?;
        let base = self.next_seq();
        let t = self.clock.now_ms();
        match self.system.read(&path) {
            Some((contents, assumption)) => {
                let (fs_ev, probe_ev) =
                    system::sysfs_events(&path, Some(contents), assumption, base, t);
                self.record_raw(fs_ev);
                self.record_raw(probe_ev);
                Some(contents.to_string())
            }
            None => {
                let assumption = self
                    .classify_sysfs(input)
                    .unwrap_or(AssumptionId::FsSystemLayout);
                self.record_raw(SubstrateEvent {
                    seq: base,
                    t_mono_ms: t,
                    group: Group::Fs,
                    source: Source::SyntheticSysfs,
                    tier: Tier::T0Direct,
                    assumption: Some(assumption),
                    detail: Detail::Fs {
                        op,
                        path: path.as_str().to_string(),
                        bytes: 0,
                        result: Err(VfsError::NoEntry),
                    },
                });
                None
            }
        }
    }

    /// Which assumption an *unmodelled* system path feeds, by prefix.
    fn classify_sysfs(&self, path: &str) -> Option<AssumptionId> {
        if path.starts_with("/proc/") {
            Some(AssumptionId::KernelProcSelf)
        } else if path.starts_with("/sys/") {
            Some(AssumptionId::KernelSysClass)
        } else if path.starts_with("/dev/") {
            Some(AssumptionId::FsSystemLayout)
        } else {
            None
        }
    }

    /// A VFS file operation, recorded whatever the outcome. A denial is
    /// information: an app probing for `/system/build.prop` must appear in the
    /// trace whether or not the node exists.
    pub(crate) fn vfs_op(&mut self, op: FsOp, path: &VPath, bytes: u64, result: Result<u64, VfsError>) {
        let assumption = if path.under(&self.data_dir) {
            AssumptionId::FsDataDir
        } else {
            AssumptionId::FsSystemLayout
        };
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Fs,
            source: Source::Vfs,
            tier: Tier::T0Direct,
            assumption: Some(assumption),
            detail: Detail::Fs {
                op,
                path: path.as_str().to_string(),
                bytes,
                result,
            },
        });
    }

    /// Run a VFS closure, recording the operation and its outcome.
    fn with_vfs<T>(
        &mut self,
        op: FsOp,
        path: &VPath,
        f: impl FnOnce(&mut Vfs, &VPath) -> Result<T, VfsError>,
    ) -> Result<T, VfsError> {
        let r = f(&mut self.vfs, path);
        let result = match &r {
            Ok(_) => Ok(0),
            Err(e) => Err(*e),
        };
        self.vfs_op(op, path, 0, result);
        r
    }

    /// Read a path, routing `/proc` and `/sys` to the fabricated system tree.
    pub(crate) fn read_path(&mut self, input: &str) -> Result<Vec<u8>, ShimError> {
        let path = VPath::parse(input)?;
        if self.is_system_path(&path) {
            return Ok(self
                .read_system_tree(path.as_str(), FsOp::Read)
                .unwrap_or_default()
                .into_bytes());
        }
        self.with_vfs(FsOp::Read, &path, |vfs, p| {
            vfs.read(p).map(|b| b.to_vec())
        })
        .map_err(ShimError::Vfs)
    }

    /// Write a path. A write into `/proc` or `/sys` is refused, which is exactly
    /// what a kernel does, and is recorded.
    pub(crate) fn write_path(&mut self, input: &str, data: &[u8]) -> Result<u64, ShimError> {
        let path = VPath::parse(input)?;
        if self.is_system_path(&path) {
            self.vfs_op(FsOp::Write, &path, data.len() as u64, Err(VfsError::Denied));
            return Err(ShimError::Vfs(VfsError::Denied));
        }
        self.with_vfs(FsOp::Write, &path, |vfs, p| vfs.write(p, data))
            .map_err(ShimError::Vfs)
    }

    fn is_system_path(&self, path: &VPath) -> bool {
        path.as_str().starts_with("/proc/") || path.as_str().starts_with("/sys/")
    }

    /// Terminate a request at the sink, recording the redacted attempt.
    ///
    /// The one and only egress path. Every networking in the substrate — URL,
    /// HttpURLConnection, raw Socket, WebView.loadUrl — arrives here.
    pub(crate) fn egress(
        &mut self,
        meta: RequestMeta,
        method: HttpMethod,
        body: Option<u64>,
    ) -> Result<(), EgressDenial> {
        let recorded_path = meta.path_under(self.policy.path);
        let mut headers = HeaderNames::new();
        let timeout = self
            .objects
            .values()
            .find_map(|s| s.connection.as_ref().and_then(|c| c.timeout_ms));
        let req = EgressRequest {
            meta: &meta,
            method,
            headers: &headers,
            body_bytes: body,
            timeout_ms: timeout,
        };
        let outcome = self.sink.request(&req);
        // Fold in whatever header names the app set, if any. Only names.
        if let Some(st) = self.objects.values().find_map(|s| s.connection.as_ref()) {
            for n in st.headers.names() {
                headers.record(&n);
            }
        }
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Net,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: Some(AssumptionId::NetEgress),
            detail: Detail::Net {
                meta,
                method,
                headers,
                body_bytes: body,
                outcome: outcome.clone().map(|_| ()),
                recorded_path,
            },
        });
        outcome.map(|v| match v {})
    }

    /// Throw a shim-side exception, recording it.
    pub(crate) fn throw(
        &mut self,
        class: &str,
        message: &str,
        stack: Vec<String>,
        fatal: bool,
    ) -> ShimError {
        let stack = if stack.is_empty() {
            vec!["<shim>".to_string()]
        } else {
            stack
        };
        self.pending_exception = Some(PendingException {
            class: class.to_string(),
            message: message.to_string(),
            stack: stack.clone(),
            caught: Some(false),
        });
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Exceptions,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: None,
            detail: Detail::Exceptions {
                class: class.to_string(),
                message: truncate(message, 2000),
                stack,
                fatal,
                caught: Some(false),
            },
        });
        ShimError::Encode(format!("thrown {class}: {message}"))
    }

    /// Mark the in-flight exception as caught and record that.
    pub fn catch_exception(&mut self, class: &str) {
        if let Some(mut p) = self.pending_exception.take() {
            p.caught = Some(true);
            self.record(SubstrateEvent {
                seq: 0,
                t_mono_ms: 0,
                group: Group::Exceptions,
                source: Source::SubstrateInstrumentation,
                tier: Tier::T0Direct,
                assumption: None,
                detail: Detail::Exceptions {
                    class: p.class.clone(),
                    message: truncate(&p.message, 2000),
                    stack: p.stack.clone(),
                    fatal: false,
                    caught: Some(true),
                },
            });
            return;
        }
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Probes,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: None,
            detail: Detail::Probes {
                pattern: "SIGNAL_PAT.EXCEPTION_CAUGHT",
                detail: format!(
                    "catch({class}) with nothing in flight; the app caught an exception the shim did not throw"
                ),
            },
        });
    }

    /// The exception currently in flight, if any.
    pub fn pending_exception(&self) -> Option<&PendingException> {
        self.pending_exception.as_ref()
    }

    /// Record a class resolution, whether or not the shim served it.
    pub fn note_class_resolution(&mut self, descriptor: &str) -> (Resolution, Option<String>) {
        let (resolution, from) = self.loader.resolve(descriptor);
        let assumption = if resolution == Resolution::DynamicUnavailable {
            AssumptionId::FwDynamicCode
        } else {
            AssumptionId::FwClassLoader
        };
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Classes,
            source: Source::ClassLoader,
            tier: Tier::T0Direct,
            assumption: Some(assumption),
            detail: Detail::Classes {
                descriptor: descriptor.to_string(),
                resolution,
                from_package: from.clone(),
            },
        });
        (resolution, from)
    }

    /// Record a `native` call or a `loadLibrary`, always `UNSATISFIED`.
    pub fn note_native(
        &mut self,
        symbol: &str,
        declaring_class: Option<&str>,
        library: Option<&str>,
    ) -> ShimError {
        self.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Jni,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: Some(if library.is_some() {
                AssumptionId::NativeLoadLibrary
            } else {
                AssumptionId::NativeJniEntry
            }),
            detail: Detail::Jni {
                symbol: symbol.to_string(),
                declaring_class: declaring_class.map(str::to_string),
                library: library.map(str::to_string),
                // Two outcomes, neither of which is a success. There is no ELF
                // loader in a browser, so even a declaration the app made itself
                // cannot be satisfied.
                outcome: NativeOutcome::Unsatisfied,
            },
        });
        ShimError::UnsatisfiedLink {
            symbol: symbol.to_string(),
            library: library.map(str::to_string),
        }
    }

    /// Register a dex-class-loader prefix as unavailable.
    pub fn note_dynamic_class_loader(&mut self, prefix: &str) {
        self.loader.note_dynamic_prefix(prefix);
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n).collect::<String>() + "\u{2026}"
    }
}

// ----------------------------------------------------------------- dispatch

impl Shim {
    /// Find a method, walking the in-registry superclass chain.
    ///
    /// A real classloader resolves a method on a superclass against a subclass's
    /// call site, and a shim that only matched the exact class would report
    /// `NoSuchMethod` for `activity.getSystemService()` — a divergence in the
    /// *loader* rather than in the observation layer, and the least useful kind.
    /// A superclass outside the registry is not walked: there is nothing to walk
    /// to, and the app's own classes live in the interpreter.
    pub fn lookup(
        &self,
        class: &str,
        name: &str,
    ) -> Option<(&'static registry::ShimClass, &'static registry::ShimMethod)> {
        let mut cursor = class;
        // Bounded: a cycle in the table is a table bug, and this must not hang.
        for _ in 0..registry::CLASSES.len() + 1 {
            let c = registry::find(cursor)?;
            if let Some(m) = c.methods().find(|m| m.name == name) {
                return Some((c, m));
            }
            cursor = c.superclass?;
        }
        None
    }
}

impl ShimCaller for Shim {
    fn resolves(&self, class: &str, name: &str, descriptor: &str) -> bool {
        let _ = descriptor;
        match self.lookup(class, name) {
            Some((_, m)) => m.access_flags & dexcore::model::access::ACC_ABSTRACT == 0,
            None => false,
        }
    }

    fn shim_classes(&self) -> Vec<String> {
        registry::descriptors()
    }

    fn events(&self) -> &[SubstrateEvent] {
        &self.events
    }

    fn read_static(&mut self, class: &str, name: &str) -> Result<Value, ShimError> {
        // A static field read is observation-bearing on exactly the same path as
        // a `getX()`, so it reuses it. `Build.*` is the interesting case: the
        // value is returned *and* the field name is recorded with its taxonomy ID,
        // which is a measurement a device arm cannot make at all.
        self.field_access(class, name, true, &[], &[])
    }

    fn invoke(
        &mut self,
        class: &str,
        name: &str,
        descriptor: &str,
        args: &[Value],
    ) -> Result<Value, ShimError> {
        let (def, method) = self.lookup(class, name).ok_or_else(|| ShimError::NoSuchMethod {
            class: class.to_string(),
            method: name.to_string(),
        })?;
        if method.access_flags & dexcore::model::access::ACC_ABSTRACT != 0 {
            return Err(ShimError::NoSuchMethod {
                class: def.descriptor.to_string(),
                method: name.to_string(),
            });
        }
        let _ = descriptor;
        // `args[0]` is `this` for an instance method and absent for a static one,
        // so the declared parameters are `args[1..]` or `args` respectively. Every
        // handler then indexes parameters by their prototype position, which is
        // the only way a static and an instance handler can share code without an
        // off-by-one waiting to happen.
        // A constructor is an instance method, but `this` is what it is *creating*,
        // so the caller passes only the declared parameters. Special-casing it
        // here is better than a second convention an interpreter has to know.
        let is_static = method.access_flags & dexcore::model::access::ACC_STATIC != 0
            || method.access_flags & dexcore::model::access::ACC_CONSTRUCTOR != 0;
        let params: &[Value] = if is_static { args } else { args.get(1..).unwrap_or(&[]) };
        match method.behaviour {
            Behaviour::Init | Behaviour::Construct => {
                let v = self.ref_for(class);
                self.after_construct(class, &v, params);
                Ok(v)
            }
            Behaviour::Field { is_get } => self.field_access(class, name, is_get, args, params),
            Behaviour::Probe { pattern } => self.probe(class, name, pattern, args, params),
            Behaviour::Dispatch(key) => self.dispatch(class, name, key, args, params),
            Behaviour::Inert => {
                // An `Inert` method has a body, so return a value of the right
                // shape rather than a refusal: `length()` erroring would make an
                // app fail in a way a device would not. The registry's `Inert`
                // marker is the honest statement that the shim is not modelling
                // it, and `tests/conformance.rs` counts them.
                Ok(default_for(method.ret))
            }
        }
    }
}

/// Mocks and test doubles. Public so an integration test — and, once it exists,
/// the interpreter — can use them.
pub mod testing {
    use super::*;

    /// A [`ShimCaller`] that records calls and returns nothing meaningful.
    ///
    /// This is the whole of the interpreter-side contract, and it is small on
    /// purpose. An interpreter that can satisfy this trait can route every
    /// framework call into the observation layer; one that cannot cannot, and
    /// the difference is a compile error rather than a missed observation at run
    /// time.
    #[derive(Debug, Default)]
    pub struct MockCaller {
        calls: Vec<RecordedCall>,
        /// When set, `invoke` returns this instead of a computed value.
        canned: Option<Result<Value, ShimError>>,
    }

    /// One call the mock saw.
    #[derive(Debug, Clone, PartialEq)]
    pub struct RecordedCall {
        pub class: String,
        pub name: String,
        pub descriptor: String,
        pub args: Vec<Value>,
    }

    impl MockCaller {
        /// A mock that returns a zero of the right shape for every call.
        pub fn new() -> MockCaller {
            MockCaller::default()
        }

        /// A mock that always returns `canned`.
        pub fn returning(canned: Result<Value, ShimError>) -> MockCaller {
            MockCaller {
                calls: Vec::new(),
                canned: Some(canned),
            }
        }

        /// Every call, in order.
        pub fn calls(&self) -> &[RecordedCall] {
            &self.calls
        }

        /// Forget the calls, keeping the canned result.
        pub fn clear(&mut self) {
            self.calls.clear();
        }
    }

    impl ShimCaller for MockCaller {
        fn invoke(
            &mut self,
            class: &str,
            name: &str,
            descriptor: &str,
            args: &[Value],
        ) -> Result<Value, ShimError> {
            self.calls.push(RecordedCall {
                class: class.to_string(),
                name: name.to_string(),
                descriptor: descriptor.to_string(),
                args: args.to_vec(),
            });
            if let Some(canned) = &self.canned {
                return canned.clone();
            }
            let method = registry::find_method(class, name)
                .map(|(_, m)| m.ret)
                .ok_or_else(|| ShimError::NoSuchMethod {
                    class: class.to_string(),
                    method: name.to_string(),
                })?;
            Ok(default_for(method))
        }

        fn resolves(&self, class: &str, name: &str, descriptor: &str) -> bool {
            let _ = descriptor;
            registry::find_method(class, name).is_some()
        }

        fn shim_classes(&self) -> Vec<String> {
            registry::descriptors()
        }

        fn read_static(&mut self, class: &str, name: &str) -> Result<Value, ShimError> {
            let _ = name;
            registry::find(class)
                .map(|_| Value::Null)
                .ok_or(ShimError::NotAShimClass {
                    descriptor: class.to_string(),
                })
        }

        fn events(&self) -> &[SubstrateEvent] {
            &[]
        }
    }
}
