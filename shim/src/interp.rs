//! The interpreter's side of the boundary, and the only place the two halves meet.
//!
//! # What this module is
//!
//! [`SubstrateHost`] implements [`dexinterp::Host`] by forwarding to a
//! [`Shim`]. That is the whole integration: the interpreter resolves a call,
//! finds a class with no bytecode, and asks. The answer comes from the same
//! `dispatch::Behaviour` table a scripted capture uses, and the observation is
//! recorded by the same code that records it for the synthetic scenario.
//!
//! The point of that sentence is the one the project cares about. In
//! `shim::scenario` the shim's methods are called *by hand*, so every event in
//! the committed recording is a consequence of a decision somebody wrote down.
//! Here, nothing calls [`Shim::invoke`] unless bytecode did. An app that never
//! touches the network produces no network attempt, not a simulated one.
//!
//! # Value translation, and the one place it is lossy
//!
//! The two crates deliberately disagree about what a value is.
//! `dexinterp::Value` is a register word; `dispatch::Value` is a shim-side
//! handle. Bridging them needs three rules, and the third one is a refusal.
//!
//! * **Engine object → shim object.** `dexinterp` allocates the object on
//!   `new-instance`, and the shim has to hold state against it. The engine's
//!   heap index is used as the shim's object id, offset by
//!   [`ENGINE_ID_BIT`]. The bit matters: without it a shim-allocated object
//!   whose id happened to equal an engine heap index would alias, and the two
//!   objects would share one `ObjState` — a wrong observation rather than a
//!   missing one, which is the failure mode this project can least afford.
//! * **Shim object → engine object.** The shim's own counter cannot be reached
//!   by the adapter, so a shim-allocated id is turned into an
//!   `Opaque { key: "a<id>" }`. The engine's `(class, key)` bijection then makes
//!   it the *same* engine object every time, which is what makes
//!   `getSystemService()` then `getSystemService()` then `configure()` work.
//! * **A string.** The engine cannot be asked to read its own heap while it is
//!   mid-dispatch, so the adapter asks the engine to render the arguments up
//!   front ([`dexinterp::Host::wants_rendered_args`]). This is the only way a
//!   host ever learns what a `Ljava/lang/String;` says, and the shim needs it
//!   for `Intent.getAction`, `Bundle.getString`, `Uri.getQuery` and every other
//!   string-shaped observation the project exists to make.
//!
//! The lossy case is an argument the shim has no representation for — an
//! `Object[]`, say. It is **not** translated to `null` and it is **not** guessed:
//! the call is declined with
//! [`dexinterp::HostOutcome::NotImplemented`], which the engine counts in
//! `framework_calls_unimplemented` and which this module counts in
//! [`SubstrateHost::unrepresentable_calls`]. A fabricated `null` would be an
//! observation the recording could not distinguish from a real one, and the
//! study would read it as a fact about the app.
//!
//! # The two hard invariants are not reachable from here
//!
//! This module holds a `Shim` and nothing else. It cannot open a socket,
//! because `EgressSink` is a private field of `Shim` and its return type is
//! `Result<Never, EgressDenial>`. It cannot hold a request body, a header value
//! or a query value, because no type on this side of the call has a field that
//! could: `HostValue` and `dispatch::Value` are the only two value types here
//! and neither one is written to an event. A substrate *policy* reaches this
//! module only through the `Shim` it was built with, and the policy's fields are
//! five enums.
//!
//! # Supersede, and where the shadowing is counted
//!
//! Class resolution has two halves and they must agree or the boundary leaks.
//!
//! * The **class table** side is [`dexinterp::Program::build_layered`]: an app
//!   class whose descriptor the shim also defines is *dropped*, so the app's
//!   own `Landroid/app/Activity;` is not a runnable class. The dropped set is
//!   `dexinterp::Stats::shadowed_classes`.
//! * The **runtime** side is [`SubstrateHost::class_known`], which asks the same
//!   [`crate::classes::ClassLoader`] the recording uses, and records
//!   [`crate::event::Resolution::ShimSupersedesApp`] for a collision.
//!
//! Both count the same phenomenon from opposite ends, and
//! `tests/interp_boundary.rs` asserts they agree — because a boundary where the
//! two halves disagree is a boundary where an app can choose which one to
//! satisfy.

use std::collections::{BTreeSet, HashMap};

use dexinterp::host::{
    Call, CallSite, FieldAccess, Host, HostOutcome, HostValue, InvokeKind, ResolvedCallSite,
    ThrowSpec,
};
use dexinterp::Value as EngineValue;

use crate::dispatch::{Shim, ShimCaller, Value as ShimValue};
use crate::event::{Group, Resolution, Source, SubstrateEvent, Tier};
use crate::policy::SubstratePolicy;
use crate::taxonomy::AssumptionId;

/// Bit set on a shim object id to say "this object is the engine's, not mine".
///
/// `dexinterp`'s heap is bounded by `Config::max_objects`; the shim's table is
/// bounded by [`crate::dispatch::MAX_OBJECTS`]. Both are far below 2³¹, so the
/// top bit is free and the two id spaces cannot alias.
const ENGINE_ID_BIT: u32 = 0x8000_0000;

/// An object the adapter allocated a name for, and the name.
type OpaqueKeys = HashMap<u32, String>;

/// The framework shim, seen as an interpreter host.
///
/// Owns the [`Shim`] because the shim *is* the observation layer: taking it by
/// reference would mean the caller could reach its VFS and its sink directly,
/// and this module's entire claim is that it cannot.
#[derive(Debug)]
pub struct SubstrateHost {
    shim: Shim,
    /// Shim object id -> the `Opaque` key the engine knows it by.
    shim_objects: OpaqueKeys,
    /// Descriptors already recorded by `class_known`, so a class is *counted*
    /// once and *observed* once.
    ///
    /// Bounded by the number of distinct classes an APK mentions, which for a
    /// real APK is thousands, so a run cannot be made to allocate without limit
    /// by a program that mentions the same class in a loop.
    seen_classes: BTreeSet<String>,
    /// Calls declined because an argument had no shim-side representation.
    unrepresentable_calls: u64,
    /// `invokedynamic` call sites offered and refused, by bootstrap owner.
    indy_refused: Vec<String>,
    /// `invokedynamic` call sites resolved to the method handle they name.
    indy_resolved: u64,
}

impl SubstrateHost {
    /// Wrap a shim as an interpreter host.
    pub fn new(shim: Shim) -> SubstrateHost {
        SubstrateHost {
            shim,
            shim_objects: HashMap::new(),
            seen_classes: BTreeSet::new(),
            unrepresentable_calls: 0,
            indy_refused: Vec::new(),
            indy_resolved: 0,
        }
    }

    /// Build a shim for `package` under `policy` and wrap it.
    pub fn with_policy(
        package: &str,
        app_classes: Vec<String>,
        policy: SubstratePolicy,
    ) -> Result<SubstrateHost, crate::error::ShimError> {
        Ok(SubstrateHost::new(Shim::with_policy(
            package,
            app_classes,
            policy,
        )?))
    }

    /// The shim, once the run is over. Taking it back is how a caller reads the
    /// event stream: [`SubstrateHost`] holds it privately so that no code path
    /// during a run can reach a capability behind the host boundary.
    pub fn into_shim(self) -> Shim {
        self.shim
    }

    /// The shim, borrowed. Present for a caller that needs the class loader or
    /// the policy; [`SubstrateHost::into_shim`] is the only way to *take* the
    /// events, so nothing can drain the observation stream mid-run and then call
    /// what it drained a capture.
    pub fn shim(&self) -> &Shim {
        &self.shim
    }

    /// A copy of the shim's events so far.
    pub fn events_snapshot(&self) -> Vec<SubstrateEvent> {
        self.shim.events().to_vec()
    }

    /// Whether the shim's registry can serve this method, without dispatching it.
    ///
    /// For a driver deciding *in advance* whether a lifecycle stage is worth
    /// attempting. A check that dispatched would record the attempt, and a
    /// capability probe is not an observation.
    pub fn serves(&self, class: &str, name: &str, signature: &str) -> bool {
        self.shim.resolves(class, name, signature)
    }

    /// Calls declined because an argument had no shim-side representation.
    pub fn unrepresentable_calls(&self) -> u64 {
        self.unrepresentable_calls
    }

    /// `invokedynamic` call sites this host refused, with the bootstrap owner.
    pub fn indy_refused(&self) -> &[String] {
        &self.indy_refused
    }

    /// `invokedynamic` call sites resolved to the method handle they name.
    pub fn indy_resolved(&self) -> u64 {
        self.indy_resolved
    }

    /// A note, recorded in the shim's own event stream.
    ///
    /// The adapter has no observation group of its own — that would be a second
    /// place an app's behaviour could be recorded, which is the thing the
    /// shim's design exists to prevent — so every fact it learns about the
    /// *engine's* behaviour goes into the `classes` group under
    /// `SUB.FW.CLASS_LOADER`, or into the `probes` group as a named pattern.
    fn note(
        &mut self,
        group: Group,
        assumption: Option<AssumptionId>,
        pattern: &'static str,
        detail: String,
    ) {
        self.shim.record(SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group,
            source: Source::ClassLoader,
            tier: Tier::T0Direct,
            assumption,
            detail: crate::event::Detail::Probes {
                pattern,
                detail,
                axis: None,
            },
        });
    }

    /// Turn one rendered argument into a shim value.
    ///
    /// `None` means "no faithful translation", which is a refusal and not a
    /// default. See the module documentation for why it is not a `null`.
    fn to_shim(&self, hv: &HostValue) -> Option<ShimValue> {
        Some(match hv {
            HostValue::Null => ShimValue::Null,
            HostValue::Int(i) => ShimValue::Int(*i),
            HostValue::Long(l) => ShimValue::Long(*l),
            HostValue::Float(f) => ShimValue::Float(*f),
            HostValue::Double(d) => ShimValue::Float(*d as f32),
            HostValue::Str(s) => ShimValue::Str(s.clone()),
            HostValue::Class(c) => ShimValue::Str(c.clone()),
            HostValue::MethodType(p) => ShimValue::Str(p.clone()),
            HostValue::Ref(v) => return self.engine_ref_to_shim(*v),
            HostValue::Opaque { class, key } => {
                // `id:<n>` came from the engine's heap; `a<n>` is a name this
                // adapter invented for a shim-allocated object.
                if let Some(n) = key.strip_prefix("id:").and_then(|s| s.parse::<u32>().ok()) {
                    return Some(ShimValue::Ref(class.clone(), ENGINE_ID_BIT | n));
                }
                if let Some(n) = key.strip_prefix('a').and_then(|s| s.parse::<u32>().ok()) {
                    return Some(ShimValue::Ref(class.clone(), n));
                }
                // An unknown key shape. Refusing beats guessing an identity.
                return None;
            }
            // A primitive array is bytes as far as the shim is concerned, and
            // `dispatch::Value::Bytes` is explicitly a value the shim counts and
            // discards — which is the right treatment for a `char[]` from
            // `toCharArray` and for a `byte[]` from `getBytes`, since neither
            // can end up in an event.
            HostValue::Array { component, items } => {
                if !is_primitive_descriptor(component) {
                    return None;
                }
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    match it {
                        HostValue::Int(i) => out.extend_from_slice(&i.to_le_bytes()),
                        HostValue::Long(l) => out.extend_from_slice(&l.to_le_bytes()),
                        HostValue::Float(f) => out.extend_from_slice(&f.to_le_bytes()),
                        HostValue::Double(d) => out.extend_from_slice(&d.to_le_bytes()),
                        _ => return None,
                    }
                }
                ShimValue::Bytes(out)
            }
        })
    }

    /// The engine handed back a raw register value rather than a rendered one,
    /// which only happens if the host declined rendering.
    fn engine_ref_to_shim(&self, v: EngineValue) -> Option<ShimValue> {
        match v {
            EngineValue::Int(i) => Some(ShimValue::Int(i)),
            EngineValue::Long(l) => Some(ShimValue::Long(l)),
            EngineValue::Float(f) => Some(ShimValue::Float(f)),
            EngineValue::Double(d) => Some(ShimValue::Float(d as f32)),
            EngineValue::Null | EngineValue::Uninit | EngineValue::Void | EngineValue::WidePad => {
                Some(ShimValue::Null)
            }
            EngineValue::Ref(r) => Some(ShimValue::Ref(
                "Ljava/lang/Object;".to_string(),
                ENGINE_ID_BIT | r.id(),
            )),
        }
    }

    /// Translate a whole argument list.
    ///
    /// **Constructors drop the receiver.** The engine's convention is that
    /// `args[0]` is `this` for the instance forms, and the shim's convention is
    /// that a `<init>` receives only its declared parameters because the object it
    /// is being handed *is* the receiver. Both conventions are right and they
    /// disagree, so the disagreement is resolved here — once, in the only place
    /// the two worlds touch.
    ///
    /// It is not a cosmetic fix. `Ljava/net/URL;.<init>(String)` parses its
    /// argument into the object's state, and with the receiver left in place it
    /// parses the receiver, gets a null URL, and the later `connect()` reports
    /// "a connection with no URL" — a *plausible wrong answer* from an
    /// instrument, which is the worst failure mode in this project.
    fn args_to_shim(&mut self, call: &Call<'_>) -> Option<Vec<ShimValue>> {
        let is_ctor = call.name == "<init>";
        let drop_receiver =
            is_ctor && !matches!(call.kind, InvokeKind::Static) && !call.args.is_empty();
        let mut out = Vec::with_capacity(call.args.len());
        if call.rendered.is_empty() {
            for (i, a) in call.args.iter().enumerate() {
                if i == 0 && drop_receiver {
                    continue;
                }
                out.push(self.engine_ref_to_shim(*a)?);
            }
        } else {
            for (i, hv) in call.rendered.iter().enumerate() {
                if i == 0 && drop_receiver {
                    continue;
                }
                out.push(self.to_shim(hv)?);
            }
        }
        Some(out)
    }

    /// Turn a shim value into something the engine can materialise.
    fn shim_value_to_host(&mut self, v: ShimValue) -> HostValue {
        match v {
            ShimValue::Null => HostValue::Null,
            ShimValue::Int(i) => HostValue::Int(i),
            ShimValue::Long(l) => HostValue::Long(l),
            ShimValue::Float(f) => HostValue::Float(f),
            ShimValue::Str(s) => HostValue::Str(s),
            ShimValue::Bytes(_) => HostValue::Null,
            ShimValue::Ref(class, id) => {
                if id & ENGINE_ID_BIT != 0 {
                    // The engine already owns this one; hand back the exact key
                    // its renderer used so the `(class, key)` bijection resolves
                    // to the same object.
                    return HostValue::Opaque {
                        class,
                        key: format!("id:{}", id & !ENGINE_ID_BIT),
                    };
                }
                let key = self
                    .shim_objects
                    .entry(id)
                    .or_insert_with(|| format!("a{id}"))
                    .clone();
                HostValue::Opaque { class, key }
            }
        }
    }

    /// Map a shim error onto a real throwable.
    ///
    /// The mapping is one-to-one and every arm names the class a device would
    /// have raised, because the app's own `catch` clauses are the observable:
    /// an app that catches `IOException` and retries must be recorded as having
    /// retried, and one that catches nothing must be recorded as having thrown
    /// `ConnectException` rather than as "the shim said no".
    fn throwable(e: crate::error::ShimError) -> Option<(&'static str, String)> {
        use crate::error::ShimError as E;
        Some(match e {
            E::NoSuchMethod {
                ref class,
                ref method,
            } => (
                "Ljava/lang/NoSuchMethodError;",
                format!("{class}.{method} is not implemented by the framework shim"),
            ),
            E::NotAShimClass { ref descriptor } => (
                "Ljava/lang/ClassNotFoundException;",
                format!("{descriptor} is not a framework class"),
            ),
            E::ClassNotFound { ref descriptor } => (
                "Ljava/lang/ClassNotFoundException;",
                format!("{descriptor} could not be resolved by the classloader"),
            ),
            E::UnparseableUrl { .. } => (
                "Ljava/net/URISyntaxException;",
                "the URL is not one the redaction layer will accept".to_string(),
            ),
            E::BadPath { ref path, .. } => (
                "Ljava/lang/IllegalArgumentException;",
                format!("{path:?} is not a path this filesystem will accept"),
            ),
            E::Vfs(ref v) => {
                let class = match v {
                    crate::error::VfsError::NoEntry | crate::error::VfsError::DeviceNotPresent => {
                        "Ljava/io/FileNotFoundException;"
                    }
                    crate::error::VfsError::Denied => "Ljava/io/FileNotFoundException;",
                    _ => "Ljava/io/IOException;",
                };
                (class, v.to_string())
            }
            E::Exhausted { resource, limit } => (
                "Ljava/lang/IllegalStateException;",
                format!("substrate resource {resource} exhausted at {limit}"),
            ),
            E::EgressDenied(ref d) => return Some((d.exception_class, d.to_string())),
            E::UnsatisfiedLink { ref symbol, .. } => (
                "Ljava/lang/UnsatisfiedLinkError;",
                format!("{symbol} has no native implementation in this substrate"),
            ),
            E::Dex(ref m) | E::Encode(ref m) => {
                return Some(("Ljava/lang/InternalError;", m.clone()))
            }
        })
    }
}

/// Is this a component descriptor the shim can carry as bytes?
fn is_primitive_descriptor(d: &str) -> bool {
    matches!(d, "Z" | "B" | "S" | "C" | "I" | "J" | "F" | "D")
}

impl Host for SubstrateHost {
    fn wants_rendered_args(&self) -> bool {
        true
    }

    fn invoke(&mut self, call: &Call<'_>) -> HostOutcome {
        // Whether the shim can serve this at all is decided *before* the
        // arguments are translated, so that "the shim has no such method" and
        // "the shim could not accept what the app passed" stay two different
        // recorded facts.
        if !self.shim.resolves(call.class, call.name, call.signature) {
            self.shim.note_class_resolution(call.class);
            return match crate::registry::find(call.class) {
                Some(_) => HostOutcome::Throw(ThrowSpec::new(
                    "Ljava/lang/AbstractMethodError;",
                    format!(
                        "{}.{}{} is abstract in the framework shim; the substrate does not \
                         implement the framework, it observes it",
                        call.class, call.name, call.signature
                    ),
                )),
                None => HostOutcome::Throw(ThrowSpec::new(
                    "Ljava/lang/NoSuchMethodError;",
                    format!(
                        "the framework shim has no {}.{}{}",
                        call.class, call.name, call.signature
                    ),
                )),
            };
        }

        let args = match self.args_to_shim(call) {
            Some(a) => a,
            None => {
                self.unrepresentable_calls += 1;
                self.note(
                    Group::Probes,
                    None,
                    "SIGNAL_PAT.FW_ARG_UNREPRESENTABLE",
                    format!(
                        "{}.{}{} was not dispatched: an argument has no representation in the \
                         observation layer's value type. The call is declined rather than answered \
                         with a fabricated null, so it is counted as unimplemented by the engine \
                         and no observation claims the app made it.",
                        call.class, call.name, call.signature
                    ),
                );
                return HostOutcome::NotImplemented;
            }
        };

        match self
            .shim
            .invoke(call.class, call.name, call.signature, &args)
        {
            Ok(v) => HostOutcome::Value(self.shim_value_to_host(v)),
            Err(e) => {
                let pending = self.shim.pending_exception().cloned();
                // The shim has already recorded the exception it raised. If it
                // raised one, the engine must raise the *same* class, or the
                // app's `catch` clauses will disagree with the recording.
                if let Some(p) = pending {
                    let class = throwable_class(&p.class);
                    return HostOutcome::Throw(ThrowSpec {
                        class,
                        message: Some(p.message),
                    });
                }
                match SubstrateHost::throwable(e) {
                    Some((class, message)) => HostOutcome::Throw(ThrowSpec {
                        class,
                        message: Some(message),
                    }),
                    None => HostOutcome::NotImplemented,
                }
            }
        }
    }

    fn get_field(&mut self, field: &FieldAccess<'_>) -> HostOutcome {
        // A static read is `ShimCaller::read_static`, which is the same code path
        // as a getter and records the same way. An *instance* field on a
        // framework class is not something the shim stores — the engine owns the
        // instance — so declining is the honest answer and the engine counts it.
        if field.target.is_none() || matches!(field.target, Some(EngineValue::Null)) {
            return match self.shim.read_static(field.class, field.name) {
                Ok(v) => HostOutcome::Value(self.shim_value_to_host(v)),
                Err(e) => match SubstrateHost::throwable(e) {
                    Some((class, message)) => HostOutcome::Throw(ThrowSpec {
                        class,
                        message: Some(message),
                    }),
                    None => HostOutcome::NotImplemented,
                },
            };
        }
        HostOutcome::NotImplemented
    }

    fn set_field(&mut self, field: &FieldAccess<'_>, value: HostValue) -> HostOutcome {
        // There is no shim-side static store. A write to a framework static is
        // refused loudly rather than silently dropped, because an app that
        // writes `Build.FINGERPRINT` and then reads it back is an observation
        // this layer cannot make and must not fake.
        let _ = (field, value);
        self.note(
            Group::Probes,
            Some(AssumptionId::FwClassLoader),
            "SIGNAL_PAT.FW_STATIC_WRITE_REFUSED",
            format!(
                "a write to {}.{} was refused: the observation layer holds no writable static \
                 storage for the framework, so the value the app wrote does not exist and the \
                 app's next read of it will not return it",
                field.class, field.name
            ),
        );
        HostOutcome::NotImplemented
    }

    fn class_known(&mut self, descriptor: &str) -> bool {
        if self.seen_classes.contains(descriptor) {
            // Still answer, still do not re-record: a class asked about twice is
            // one class, and an event stream with a duplicate per lookup is a
            // stream about the lookup rather than about the app.
            return self.shim.loader().resolve(descriptor).0 != Resolution::Unresolvable;
        }
        self.seen_classes.insert(descriptor.to_string());
        let (resolution, from) = self.shim.note_class_resolution(descriptor);
        if resolution == Resolution::ShimSupersedesApp {
            self.note(
                Group::Classes,
                Some(AssumptionId::FwClassLoader),
                "SIGNAL_PAT.CLASS_LOADER.SHIM_SUPERSEDES_APP",
                format!(
                    "{descriptor} is defined by both the app{} and the framework shim. The shim's \
                     definition supersedes the app's, so the app's class body never runs. Recorded \
                     because a silent disappearance is a blind spot (ADR 0005).",
                    from.map(|p| format!(" ({p})")).unwrap_or_default()
                ),
            );
        }
        resolution != Resolution::Unresolvable
    }

    fn resolve_call_site(&mut self, site: &CallSite<'_>) -> Option<ResolvedCallSite> {
        // `LambdaMetafactory` is the one bootstrap a substrate can resolve
        // *faithfully*, because resolving it is not an invention: the call site
        // names a method handle, the handle names a method, and ART calls that
        // method. Every other bootstrap — a desugared `switch` on an enum, a
        // `ConstantBootstraps` string concat, a `StringConcatFactory` site — is
        // genuinely a piece of code the substrate does not have, and is refused
        // with its owner named.
        let owner = site.bootstrap_owner;
        if !matches!(
            owner,
            "Ljava/lang/invoke/LambdaMetafactory;" | "Ljava/lang/invoke/StringConcatFactory;"
        ) {
            self.indy_refused
                .push(format!("{owner}.{}", site.bootstrap_name));
            self.note(
                Group::Probes,
                Some(AssumptionId::FwInvokeDynamic),
                "SIGNAL_PAT.FW_INVOKEDYNAMIC_UNRESOLVED",
                format!(
                    "invoke-custom at call_site {} names bootstrap {owner}.{}{} (handle type {}). \
                     The substrate cannot run a bootstrap method it does not have, so the call site \
                     is refused rather than guessed at. This is the SUB.FW.INVOKEDYNAMIC claim, \
                     measured.",
                    site.index,
                    site.bootstrap_name,
                    site.bootstrap_signature,
                    site.method_handle_type
                ),
            );
            return None;
        }
        // A resolved call site still has to name a target, and the adapter has
        // no way to reach the engine's `method_handles` table from inside a
        // `Host` call. The engine offers the *arguments*; the handle's target is
        // not among them for a `REF_invokeStatic` whose implementation takes no
        // captures, and is not derivable for one that does. So this is recorded
        // as unresolved rather than resolved to the wrong method.
        self.indy_refused
            .push(format!("{owner}.{}", site.bootstrap_name));
        self.note(
            Group::Probes,
            Some(AssumptionId::FwInvokeDynamic),
            "SIGNAL_PAT.FW_INVOKEDYNAMIC_UNRESOLVED",
            format!(
                "invoke-custom at call_site {} names {owner}.{}{}, which is a bootstrap the \
                 substrate recognises but cannot execute: resolving it needs the call site's \
                 method handle, and the host boundary hands over the bootstrap's arguments rather \
                 than the handle. Refused, and counted.",
                site.index, site.bootstrap_name, site.bootstrap_signature
            ),
        );
        None
    }
}

/// Map a shim exception class name onto a class descriptor the engine can raise.
///
/// The shim names exceptions in the JNI form (`java.net.ConnectException`) and
/// the engine wants a type descriptor. A name that is already a descriptor
/// passes through; anything unrecognised becomes `RuntimeException` rather than
/// being invented into a class that does not exist.
fn throwable_class(name: &str) -> &'static str {
    if name.starts_with('L') && name.ends_with(';') {
        return match name {
            "Ljava/lang/NullPointerException;" => "Ljava/lang/NullPointerException;",
            "Ljava/io/IOException;" => "Ljava/io/IOException;",
            _ => "Ljava/lang/RuntimeException;",
        };
    }
    match name {
        "java.lang.NullPointerException" => "Ljava/lang/NullPointerException;",
        "java.lang.IllegalArgumentException" => "Ljava/lang/IllegalArgumentException;",
        "java.lang.IllegalStateException" => "Ljava/lang/IllegalStateException;",
        "java.lang.RuntimeException" => "Ljava/lang/RuntimeException;",
        "java.lang.UnsupportedOperationException" => "Ljava/lang/UnsupportedOperationException;",
        "java.lang.ClassNotFoundException" => "Ljava/lang/ClassNotFoundException;",
        "java.lang.NoSuchMethodException" => "Ljava/lang/NoSuchMethodException;",
        "java.lang.SecurityException" => "Ljava/lang/SecurityException;",
        "java.lang.OutOfMemoryError" => "Ljava/lang/OutOfMemoryError;",
        "java.lang.UnsatisfiedLinkError" => "Ljava/lang/UnsatisfiedLinkError;",
        "java.lang.Error" => "Ljava/lang/Error;",
        "java.io.IOException" => "Ljava/io/IOException;",
        "java.io.FileNotFoundException" => "Ljava/io/FileNotFoundException;",
        "java.io.UnsupportedEncodingException" => "Ljava/io/UnsupportedEncodingException;",
        "java.net.ConnectException" => "Ljava/net/ConnectException;",
        "java.net.MalformedURLException" => "Ljava/net/MalformedURLException;",
        "java.net.SocketException" => "Ljava/net/SocketException;",
        "java.net.UnknownHostException" => "Ljava/net/UnknownHostException;",
        "java.net.SocketTimeoutException" => "Ljava/net/SocketTimeoutException;",
        "java.security.SecureRandom" => "Ljava/security/SecureRandom;",
        "android.content.pm.NameNotFoundException" => "Landroid/content/pm/NameNotFoundException;",
        "android.util.Log" => "Landroid/util/Log;",
        "android.database.sqlite.SQLiteException" => "Landroid/database/sqlite/SQLiteException;",
        "java.lang.Throwable" => "Ljava/lang/Throwable;",
        "java.lang.Exception" => "Ljava/lang/Exception;",
        "java.lang.AssertionError" => "Ljava/lang/AssertionError;",
        "java.lang.ArrayIndexOutOfBoundsException" => "Ljava/lang/ArrayIndexOutOfBoundsException;",
        "java.lang.StringIndexOutOfBoundsException" => {
            "Ljava/lang/StringIndexOutOfBoundsException;"
        }
        "java.lang.NumberFormatException" => "Ljava/lang/NumberFormatException;",
        "java.lang.InterruptedException" => "Ljava/lang/InterruptedException;",
        "java.util.NoSuchElementException" => "Ljava/util/NoSuchElementException;",
        _ => "Ljava/lang/RuntimeException;",
    }
}
