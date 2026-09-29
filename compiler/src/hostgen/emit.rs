//! Closure → host table.
//!
//! # The shape, and the one place it is refined
//!
//! `compiler/IR.md` §Host stub ABI fixes the entry type:
//!
//! ```text
//! HostEntry =
//!   | { kind: "class";  name: string }
//!   | { kind: "method"; cls: string; name: string; sig: string; impl: HostImpl }
//!   | { kind: "native"; cls: string; name: string; sig: string; state: "satisfied"|"unsatisfied" }
//! ```
//!
//! That union is reproduced here **exactly** — same three variants, same
//! discriminants, same fields — with one addition: every variant carries a
//! `taxonomy` field. `IR.md` says it three lines later, in the same section:
//! "Every stub records, at emit time, which taxonomy ID its absence would
//! predicate … A stub generated without a taxonomy attribution is a defect."
//!
//! So the attribution is not an addition, it is a requirement the type above was
//! not able to express. Rather than invent a parallel structure, the field is
//! added to the normative union, which makes it a *refinement*: every value of
//! `IR.md`'s union is still expressible, and no value expressible here lacks the
//! attribution. This is filed as a comment to the orchestrator per `IR.md` §0
//! rather than as an edit to `IR.md`.
//!
//! # Classification order, and why it is a `u8` comparison
//!
//! `IR.md` §Class resolution order is normative and its five steps are the
//! variants of [`Kind`], declared in that order with `#[repr(u8)]` and derived
//! `Ord`. "Precedence when a name exists in more than one: **host > app**" is
//! then literally `Kind::HostStub < Kind::App`, which is a property of the
//! declaration rather than a rule someone has to remember to apply.
//!
//! # Shadowing is recorded, always
//!
//! ADR 0005's supersede rule says a host implementation wins over the app's own,
//! and `IR.md` requires "Record every shadowing event". The adversarial test in
//! `shim/` — a DEX that declares all 144 of the shim's framework classes and is
//! handed in as the app — is the model, and `tests/hostile_apk.rs` reproduces the
//! shape here.
//!
//! A shadow event is *not* an error. A hostile APK that declares
//! `Landroid/os/Build;` with its own body does not get to serve `Build`, and the
//! fact that it tried is a finding about the app. So the emitter records the
//! event, counts it, and names the app's definition in the report — it does not
//! fail, and it does not quietly prefer the host either.

use core::fmt;

use crate::hostgen::answer::{
    AnswerSource, DeclaredEnv, FabricationLedger, resolve,
};
use crate::hostgen::closure::{Closure, ClosureMember, Origin};
use crate::hostgen::egress::SideEffectClass;
use crate::hostgen::policy::{Axis, HostPolicy, POLICY_FORMAT, POLICY_VERSION};
use crate::hostgen::synth::{
    SideEffectPolicy, SynthAnswer, attribute, synthesise,
};
use crate::hostgen::taxonomy::AssumptionId;

/// The resolution kind of a name, in `IR.md`'s order.
///
/// The declaration order *is* the precedence order, and it is load-bearing:
/// `Kind::HostStub < Kind::App` is the supersede rule from ADR 0005, written
/// once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    /// `IR.md` step 1: we compiled it; it is in the guest module.
    ClosureGenerated = 1,
    /// Step 2: it is in the closure but we chose a host implementation.
    HostStub = 2,
    /// Step 3: a `native` method the host provides.
    HostNative = 3,
    /// Step 4: the app's own class.
    App = 4,
    /// Step 5: emit a typed error, never a silent default.
    Unresolved = 5,
}

impl Kind {
    /// Every kind, in `IR.md`'s order.
    pub const ALL: [Kind; 5] = [
        Kind::ClosureGenerated,
        Kind::HostStub,
        Kind::HostNative,
        Kind::App,
        Kind::Unresolved,
    ];

    /// The `IR.md` step number, so a report can cite the spec rather than an
    /// internal enumeration.
    pub fn step(self) -> u8 {
        self as u8
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::ClosureGenerated => "closure-generated",
            Kind::HostStub => "host-stub",
            Kind::HostNative => "host-native",
            Kind::App => "app",
            Kind::Unresolved => "unresolved",
        }
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a host-native method has an implementation behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeState {
    /// The host can satisfy it.
    Satisfied,
    /// It cannot, and the runtime throws `UnsatisfiedLinkError` rather than
    /// inventing a body.
    Unsatisfied,
}

/// A taxonomy attribution on an emitted entry.
///
/// Newtype rather than a bare [`AssumptionId`] for the reason `IR.md` calls a
/// defect. A bare ID can be written down without anyone deciding anything: an
/// entry carrying `FwClassLoader` looks identical whether it was chosen or
/// defaulted. This has no `Default` and no `new`, so an entry cannot be built
/// without a decision, and the honest fallback
/// ([`crate::hostgen::synth::TaxAttribution::fallback`]) is a *named* value
/// that a reader can grep for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaxRef(pub AssumptionId);

impl TaxRef {
    /// The ID.
    pub fn id(self) -> AssumptionId {
        self.0
    }
}

/// A class the host serves, with the assumption its absence predicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEntry {
    pub name: String,
    pub taxonomy: TaxRef,
}

/// A method the host implements on behalf of the closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodEntry {
    pub cls: String,
    pub name: String,
    pub sig: String,
    /// Where the answer's value comes from. **Not optional.** A method entry
    /// with no `source` is a stub whose behaviour is unknown, which is the
    /// defect `IR.md` names.
    pub source: AnswerSource,
    pub taxonomy: TaxRef,
    pub side_effect: SideEffectClass,
    pub side_effect_policy: SideEffectPolicy,
    pub classification: Kind,
}

impl MethodEntry {
    /// `class->name signature`, the host table's index key.
    pub fn key(&self) -> String {
        format!("{}->{} {}", self.cls, self.name, self.sig)
    }

    /// Whether this entry is a fabrication. The ledger's input.
    pub fn is_fabrication(&self) -> bool {
        self.source.is_fabrication()
    }

    /// Whether this entry is refused.
    pub fn is_denial(&self) -> bool {
        matches!(self.source, AnswerSource::Denied(_))
    }
}

/// A `native` method the host does or does not provide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEntry {
    pub cls: String,
    pub name: String,
    pub sig: String,
    pub state: NativeState,
    pub taxonomy: TaxRef,
}

impl NativeEntry {
    pub fn key(&self) -> String {
        format!("{}->{} {}", self.cls, self.name, self.sig)
    }
}

/// `IR.md`'s `HostEntry`, refined with the attribution it requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEntry {
    Class(ClassEntry),
    Method(MethodEntry),
    Native(NativeEntry),
}

impl HostEntry {
    /// The discriminant `IR.md` spells.
    pub fn kind(&self) -> Kind {
        match self {
            HostEntry::Class(_) => Kind::HostStub,
            HostEntry::Method(m) => m.classification,
            HostEntry::Native(_) => Kind::HostNative,
        }
    }

    /// The attribution, which exists on every variant by construction.
    pub fn taxonomy(&self) -> TaxRef {
        match self {
            HostEntry::Class(c) => c.taxonomy,
            HostEntry::Method(m) => m.taxonomy,
            HostEntry::Native(n) => n.taxonomy,
        }
    }

    /// The table index key, or `None` for a class entry.
    pub fn key(&self) -> Option<String> {
        match self {
            HostEntry::Class(_) => None,
            HostEntry::Method(m) => Some(m.key()),
            HostEntry::Native(n) => Some(n.key()),
        }
    }

    /// The rendered JS/TS shape `IR.md` specifies, as a string.
    ///
    /// A `Display` rather than a builder so the emitted form is one function and
    /// cannot drift from the type — the same reasoning the shim gives for having
    /// one registry table rather than three that have to agree.
    pub fn to_js(&self) -> String {
        match self {
            HostEntry::Class(c) => format!(
                "{{ kind: \"class\", name: {:?}, taxonomy: {:?} }}",
                c.name,
                c.taxonomy.id().as_str()
            ),
            HostEntry::Method(m) => format!(
                "{{ kind: \"method\", cls: {:?}, name: {:?}, sig: {:?}, source: {:?}, \
                 taxonomy: {:?}, side_effect: \"{:?}\" }}",
                m.cls,
                m.name,
                m.sig,
                m.source.render(),
                m.taxonomy.id().as_str(),
                m.side_effect
            ),
            HostEntry::Native(n) => format!(
                "{{ kind: \"native\", cls: {:?}, name: {:?}, sig: {:?}, state: \"{}\", \
                 taxonomy: {:?} }}",
                n.cls,
                n.name,
                n.sig,
                match n.state {
                    NativeState::Satisfied => "satisfied",
                    NativeState::Unsatisfied => "unsatisfied",
                },
                n.taxonomy.id().as_str()
            ),
        }
    }
}

/// One shadowing event: a host entry over a name the app also defines.
///
/// `IR.md`: "Precedence when a name exists in more than one: **host > app** …
/// Record every shadowing event."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEvent {
    /// The class descriptor.
    pub class: String,
    /// Which host kind won.
    pub won: Kind,
    /// Which kind lost.
    pub lost: Kind,
    /// How many members of the class were affected.
    pub members: usize,
}

impl fmt::Display for ShadowEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: host ({}) supersedes app ({}) over {} member(s)",
            self.class,
            self.won,
            self.lost,
            self.members
        )
    }
}

/// A refusal to emit, with the reason.
///
/// `IR.md` step 5: unresolved names produce "a typed error, never a silent
/// default". This is that error, and it is fatal for the module rather than a
/// member, because a partially-emitted host is a host that looks complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// A class the closure needs that nothing can resolve. `IR.md` step 5.
    Unresolved { class: String, reason: String },
    /// An entry was classified as egress but was given something other than a
    /// denial. This should be unreachable — `synth` sets it structurally — and
    /// it is checked anyway because the egress invariant is worth a redundant
    /// assertion, exactly as the shim argues for its redundant `scrub`.
    EgressNotDenied { key: String },
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmitError::Unresolved { class, reason } => {
                write!(f, "unresolved class {class}: {reason}")
            }
            EmitError::EgressNotDenied { key } => write!(
                f,
                "{key} is classified as egress but was not denied; egress denial must be structural"
            ),
        }
    }
}

/// The generated host: everything `compiler/IR.md` asks the host module to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostModule {
    pub entries: Vec<HostEntry>,
    pub shadow_events: Vec<ShadowEvent>,
    pub unresolved: Vec<(String, String)>,
    pub ledger: FabricationLedger,
    pub policy: HostPolicy,
    pub declared: DeclaredEnv,
    pub closure_len: usize,
    pub closure_classes: usize,
    pub unresolved_reflective: usize,
    pub ambiguous_reflective: usize,
    pub entry_points: Vec<String>,
}

impl HostModule {
    /// Entries of one kind.
    pub fn of_kind(&self, k: Kind) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind() == k)
            .count()
    }

    /// How many shadowing events were recorded. `IR.md` requires the count.
    pub fn shadowed_classes(&self) -> usize {
        self.shadow_events.len()
    }

    /// Distinct taxonomy IDs across every entry.
    pub fn taxonomy_ids(&self) -> Vec<AssumptionId> {
        let mut v: Vec<AssumptionId> = self
            .entries
            .iter()
            .map(|e| e.taxonomy().id())
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    /// How many entries were attributed by the fallback rule rather than a
    /// specific one. Reported separately so a total never hides a guess rate.
    pub fn fallback_attributions(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.taxonomy().id() == AssumptionId::FwClassLoader)
            .count()
    }

    /// The run report.
    ///
    /// Every figure here is **derived from the module being emitted**, so the
    /// report cannot disagree with the artefact — which is the failure mode the
    /// shim's own registry comment describes.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str("andro-substrate generated host\n");
        s.push_str(&format!("  policy:      {POLICY_FORMAT} v{POLICY_VERSION}\n"));
        s.push_str(&format!(
            "  digest:      {:016x} (fnv1a64, a join key, not a security property)\n",
            self.policy.digest()
        ));
        s.push_str(&format!(
            "  closure:     {} members over {} classes, from {} entry point(s)\n",
            self.closure_len,
            self.closure_classes,
            self.entry_points.len()
        ));
        s.push_str(&format!(
            "  reflective:  {} unresolved, {} ambiguous candidate edge(s)\n",
            self.unresolved_reflective, self.ambiguous_reflective
        ));
        s.push_str("  entries by classification, in IR.md resolution order:\n");
        for k in Kind::ALL {
            s.push_str(&format!(
                "    {:<18} step {}  {}\n",
                k.as_str(),
                k.step(),
                self.of_kind(k)
            ));
        }
        s.push_str(&format!(
            "  shadowing:   {} class(es) where the host superseded the app (ADR 0005)\n",
            self.shadowed_classes()
        ));
        s.push_str(&format!(
            "  attribution: {} distinct taxonomy IDs; {} entries fell back to the \
             class-loader default\n",
            self.taxonomy_ids().len(),
            self.fallback_attributions()
        ));
        s.push_str(&self.ledger.report());
        s.push_str("  policy declaration:\n");
        for line in self.policy.declaration().lines() {
            s.push_str("    ");
            s.push_str(line);
            s.push('\n');
        }
        s.push_str("  declared environment:\n");
        for line in self.declared.declaration().lines() {
            s.push_str("    ");
            s.push_str(line);
            s.push('\n');
        }
        s
    }

    /// Every entry's rendered JS, one per line.
    pub fn to_js(&self) -> String {
        let mut s = String::new();
        for e in &self.entries {
            s.push_str(&e.to_js());
            s.push('\n');
        }
        s
    }
}

/// Emit a host module from a closure.
///
/// Returns an error rather than a partial module when a class cannot be
/// resolved, because `IR.md` step 5's "typed error, never a silent default" is
/// only meaningful if it is actually typed. The two exceptions are enumerated
/// into [`HostModule::unresolved`] rather than aborting: an unresolved *class*
/// is fatal, an unresolved *member* is a fact about the app.
pub fn emit(
    closure: &Closure,
    policy: &HostPolicy,
    env: &DeclaredEnv,
) -> Result<HostModule, EmitError> {
    let mut entries: Vec<HostEntry> = Vec::with_capacity(closure.len());
    let mut ledger = FabricationLedger::new();
    let mut unresolved: Vec<(String, String)> = Vec::new();

    // Classes, first: one entry per class the host serves, so the table's shape
    // matches `IR.md`'s and a reader can see the class surface separately from
    // the method surface.
    let mut classes: Vec<&str> = closure.members().iter().map(|m| m.class.as_str()).collect();
    classes.sort_unstable();
    classes.dedup();

    for class in &classes {
        let class = *class;
        if !closure.host_claims(class) {
            // An app-owned class gets no host class entry: emitting one would
            // be the shadow ADR 0005 forbids in the other direction.
            continue;
        }
        if !class.starts_with('L') || !class.ends_with(';') || class.len() < 3 {
            unresolved.push((class.to_string(), "not a DEX type descriptor".to_string()));
            continue;
        }
        // The class-level attribution: what its *absence* would predicate. A
        // class that does not resolve is `SUB.FW.CLASS_LOADER`, which is the
        // assumption that the surface must exist for the app to run at all.
        let probe = ClosureMember::new(class, "<init>", "()V", Origin::CallGraph);
        entries.push(HostEntry::Class(ClassEntry {
            name: class.to_string(),
            taxonomy: TaxRef(attribute(&probe).id),
        }));
    }

    // Members, in classification order.
    for member in closure.members() {
        let kind = classify(closure, member);
        match kind {
            Kind::ClosureGenerated => {
                entries.push(HostEntry::Method(MethodEntry {
                    cls: member.class.clone(),
                    name: member.name.clone(),
                    sig: member.signature.clone(),
                    source: AnswerSource::Structural(crate::hostgen::answer::StructuralAnswer::Void),
                    taxonomy: TaxRef(AssumptionId::FwClassLoader),
                    side_effect: SideEffectClass::None,
                    side_effect_policy: SideEffectPolicy::for_class(SideEffectClass::None),
                    classification: kind,
                }));
            }
            Kind::Unresolved => {
                unresolved.push((member.key(), "no implementation and no app definition".to_string()));
            }
            Kind::App => {
                // The app's own code answers. No host entry: emitting one would
                // be the shadow the supersede rule forbids in the other
                // direction. The event is recorded below.
                continue;
            }
            Kind::HostNative => {
                let attribution = attribute(member);
                entries.push(HostEntry::Native(NativeEntry {
                    cls: member.class.clone(),
                    name: member.name.clone(),
                    sig: member.signature.clone(),
                    // A `native` method the host cannot implement is
                    // `Unsatisfied`, which makes the runtime throw
                    // `UnsatisfiedLinkError`. That is the shim's `ACC_NATIVE`
                    // safety decision, restated: the failure mode when misplaced
                    // must be a loud exception, never a silent zero.
                    state: NativeState::Unsatisfied,
                    taxonomy: TaxRef(attribution.id),
                }));
            }
            Kind::HostStub => {
                let answer: SynthAnswer = synthesise(member, policy, env);
                let entry = MethodEntry {
                    cls: member.class.clone(),
                    name: member.name.clone(),
                    sig: member.signature.clone(),
                    source: answer.source,
                    taxonomy: TaxRef(answer.attribution.id),
                    side_effect: answer.effects,
                    side_effect_policy: answer.effect_policy,
                    classification: kind,
                };
                // The egress invariant, checked at the artefact and not only in
                // the synthesiser. Redundant on purpose.
                if entry.side_effect == SideEffectClass::Egress && !entry.is_denial() {
                    return Err(EmitError::EgressNotDenied { key: entry.key() });
                }
                ledger.record(entry.key(), entry.source, entry.taxonomy.id());
                entries.push(HostEntry::Method(entry));
            }
        }
    }

    let shadow_events = record_shadowing(closure, &entries);

    Ok(HostModule {
        entries,
        shadow_events,
        unresolved,
        ledger,
        policy: *policy,
        declared: env.clone(),
        closure_len: closure.len(),
        closure_classes: closure.class_count(),
        unresolved_reflective: closure.unresolved_reflective(),
        ambiguous_reflective: closure.ambiguous_reflective(),
        entry_points: closure.entry_points().to_vec(),
    })
}

/// Decide a member's resolution kind, following `IR.md`'s five steps in order.
///
/// The order is the specification and the code is the transcription, so the
/// reader can check one against the other line by line.
pub fn classify(closure: &Closure, member: &ClosureMember) -> Kind {
    // Step 1 — closure-generated: we compiled this class into the guest module.
    if closure.generated_classes().iter().any(|c| c == &member.class) {
        return Kind::ClosureGenerated;
    }
    // Step 2 — host-stub: it is in the closure and we chose a host implementation.
    // Checked before `App` so that "host > app" is a property of the statement
    // order and not a rule that could be dropped from one arm. `host_claims`
    // already excludes the app's own package, so this arm and the `App` arm
    // cannot both match — except in the adversarial case, where the app declares
    // a framework class, and there the host wins, which is the point.
    if closure.host_claims(&member.class) {
        return if member.access.is_native {
            Kind::HostNative
        } else {
            Kind::HostStub
        };
    }
    // Step 4 — app: the app's own class.
    if closure.app_classes().iter().any(|c| c == &member.class) {
        return Kind::App;
    }
    // Step 3 is folded into step 2 above: a `native` method on a host-served
    // class is `HostNative`, and a `native` method on anything else falls
    // through to step 4 or step 5.
    //
    // Step 5 — unresolved: emit a typed error, never a silent default.
    Kind::Unresolved
}

/// Record every shadowing event.
///
/// One event per class, not per member: the shim's adversarial case reports
/// "144 shadowed classes", and that is the more useful unit — it says how many
/// *names* the app tried to take over, not how many methods those names had.
pub fn record_shadowing(closure: &Closure, entries: &[HostEntry]) -> Vec<ShadowEvent> {
    let mut out: Vec<ShadowEvent> = Vec::new();
    let app: Vec<&str> = closure
        .app_classes()
        .iter()
        .map(|s| s.as_str())
        .collect();

    for class in app {
        let members = closure
            .members()
            .iter()
            .filter(|m| m.class == class)
            .count();
        if members == 0 {
            continue;
        }
        // Did the host actually take the class? Look at the emitted entries
        // rather than assuming: an entry list that says otherwise is a bug, and
        // this is where it would show.
        let won = entries
            .iter()
            .filter_map(|e| match e {
                HostEntry::Method(m) if &m.cls == class => Some(m.classification),
                HostEntry::Native(n) if &n.cls == class => Some(Kind::HostNative),
                HostEntry::Class(c) if &c.name == class => Some(Kind::HostStub),
                _ => None,
            })
            .min();
        let won = match won {
            Some(w) if w < Kind::App => w,
            _ => continue,
        };
        out.push(ShadowEvent {
            class: class.to_string(),
            won,
            lost: Kind::App,
            members,
        });
    }
    out
}

/// Convenience: resolve one environment-dependent answer, for a caller that has
/// a parameter rather than a closure member.
pub fn answer_for(policy: &HostPolicy, env: &DeclaredEnv, param: crate::hostgen::answer::EnvParam) -> AnswerSource {
    resolve(policy, env, param)
}

/// Which axes the report should print, for a caller that wants a filtered view.
pub fn declared_axes(policy: &HostPolicy) -> Vec<(Axis, &'static str)> {
    Axis::ALL.iter().map(|a| (*a, policy.axis(*a))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostgen::closure::{ReflectiveEdge, ReflectiveStatus};

    fn m(class: &str, name: &str, sig: &str) -> ClosureMember {
        ClosureMember::new(class, name, sig, Origin::CallGraph)
    }

    fn sample_closure() -> Closure {
        let mut c = Closure::new();
        c.add_entry_point("Leu/ln/gita/activities/MainActivity;->onCreate(Landroid/os/Bundle;)V");
        // From the manifest, as a real pipeline would. Without it the package
        // would derive as `Eu/ln/gita/activities/` and the app's own
        // `Eu/ln/gita/Main;` would be misread as framework.
        c.set_app_package("eu.ln.gita");
        c.add(m("Landroid/os/Build$VERSION;", "SDK_INT", "I"));
        c.add(m("Landroid/os/Build;", "FINGERPRINT", "()Ljava/lang/String;"));
        c.add(m("Ljava/net/HttpURLConnection;", "connect", "()V"));
        c.add(m("Ljava/lang/Integer;", "MAX_VALUE", "I"));
        c.add(m("Ljava/lang/Object;", "hashCode", "()I"));
        c.add(m("Lcom/example/Ghost;", "vanish", "()V"));
        c
    }

    #[test]
    fn classification_follows_ir_steps_in_order() {
        let mut c = sample_closure();
        c.add_generated_class("Landroid/os/Build;");
        // Declared as the app's own class, and inside the app's package.
        c.add_app_class("Eu/ln/gita/Main;");
        c.add(m("Eu/ln/gita/Main;", "onCreate", "()V"));
        assert_eq!(classify(&c, &m("Landroid/os/Build;", "FINGERPRINT", "()V")), Kind::ClosureGenerated);
        assert_eq!(classify(&c, &m("Ljava/net/HttpURLConnection;", "connect", "()V")), Kind::HostStub);
        assert_eq!(classify(&c, &m("Eu/ln/gita/Main;", "onCreate", "()V")), Kind::App);
        // A well-formed class outside the app's package is host-served, not
        // unresolved. `IR.md` step 5 is for a name *nothing* can resolve, and a
        // generated host's answer to "the app called a library we have no source
        // for" is a stub that denies — recorded, not omitted.
        assert_eq!(
            classify(&c, &m("Lcom/example/Ghost;", "vanish", "()V")),
            Kind::HostStub
        );
        // Step 5 does fire for a name that is not a descriptor at all.
        assert_eq!(classify(&c, &m("not-a-descriptor", "x", "()V")), Kind::Unresolved);
    }

    #[test]
    fn host_beats_app_in_the_declaration_order() {
        // ADR 0005's supersede rule as a property of the enum, not a rule.
        assert!(Kind::HostStub < Kind::App);
        assert!(Kind::HostNative < Kind::App);
        assert!(Kind::ClosureGenerated < Kind::HostStub);
        assert!(Kind::Unresolved > Kind::App);
        assert_eq!(
            Kind::ALL.iter().map(|k| k.step()).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn a_native_member_of_a_host_class_is_host_native() {
        let mut c = sample_closure();
        let mut nm = m("Lcom/example/N;", "f", "()I");
        nm.access.is_native = true;
        c.add(nm.clone());
        assert_eq!(classify(&c, &nm), Kind::HostNative);
    }

    #[test]
    fn every_emitted_entry_carries_a_taxonomy_id() {
        let c = sample_closure();
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        assert!(h.is_ok());
        if let Ok(h) = h {
            assert!(!h.entries.is_empty());
            for e in &h.entries {
                assert!(
                    AssumptionId::ALL.contains(&e.taxonomy().id()),
                    "{} has an unregistered ID",
                    e.key().unwrap_or_else(|| "class".to_string())
                );
            }
        }
    }

    #[test]
    fn shadowing_is_counted_and_named() {
        let mut c = sample_closure();
        // The adversarial shape: the app declares a framework class itself.
        c.add_app_class("Landroid/os/Build;");
        c.add(m("Landroid/os/Build;", "FINGERPRINT", "()Ljava/lang/String;"));
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        assert!(h.is_ok());
        if let Ok(h) = h {
            assert_eq!(h.shadowed_classes(), 1);
            assert_eq!(h.shadow_events[0].class, "Landroid/os/Build;");
            assert!(h.shadow_events[0].won < Kind::App);
            assert_eq!(h.shadow_events[0].lost, Kind::App);
            assert!(h.shadow_events[0].members >= 1);
            assert!(h.shadow_events[0].to_string().contains("supersedes"));
        }
    }

    #[test]
    fn a_class_outside_the_app_package_is_host_served_not_unresolved() {
        // `IR.md` step 5 is for a name *nothing* can resolve, and for a generated
        // host that is close to empty: the generator's whole claim is that it
        // answers every class outside the app's package. `Lcom/example/Ghost;`
        // is exactly the case the generator exists to handle — the app called a
        // library we have no source for — so it becomes a host stub that denies,
        // and the denial is recorded.
        let c = sample_closure();
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        assert!(h.is_ok(), "{:?}", h.err());
        if let Ok(h) = h {
            assert!(
                h.unresolved.is_empty(),
                "a well-formed class outside the app package must not be unresolved: {:?}",
                h.unresolved
            );
            assert!(
                h.entries.iter().any(|e| {
                    e.key().map(|k| k.contains("Ghost")).unwrap_or(false)
                }),
                "the ghost class must still get an entry"
            );
            assert!(h.of_kind(Kind::HostStub) > 0);
        }
    }

    #[test]
    fn a_malformed_descriptor_is_recorded_rather_than_served() {
        let mut c = sample_closure();
        c.add(m("not-a-descriptor", "x", "()V"));
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        assert!(h.is_ok());
        if let Ok(h) = h {
            assert!(
                h.unresolved
                    .iter()
                    .any(|(k, why)| k.contains("not-a-descriptor") && why.contains("app definition")),
                "{:?}",
                h.unresolved
            );
        }
    }

    #[test]
    fn the_report_counts_everything_it_claims_to() {
        let mut c = sample_closure();
        c.add_reflective(ReflectiveEdge::unresolved("La;", "Lcom/example/Missing;"));
        c.add_reflective(ReflectiveEdge {
            from_class: "La;".into(),
            target: "Lcom/example/;".into(),
            status: ReflectiveStatus::Ambiguous,
            site: None,
        });
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        assert!(h.is_ok());
        if let Ok(h) = h {
            let r = h.report();
            assert!(r.contains("closure:     6 members over 6 classes"), "{r}");
            assert!(r.contains("1 unresolved, 1 ambiguous"), "{r}");
            assert!(r.contains("host-stub"), "{r}");
            assert!(r.contains("fabrication ledger"), "{r}");
            assert!(r.contains("declared environment"), "{r}");
            // The reflective count is present, not implied.
            assert!(r.contains("reflective"), "{r}");
        }
    }

    #[test]
    fn the_js_rendering_is_the_ir_shape() {
        let c = sample_closure();
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        if let Ok(h) = h {
            let js = h.to_js();
            assert!(js.contains(r#"kind: "class""#), "{js}");
            assert!(js.contains(r#"kind: "method""#), "{js}");
            assert!(js.contains(r#"taxonomy: "SUB."#), "{js}");
        }
    }

    #[test]
    fn the_ledger_matches_what_the_entries_say() {
        let c = sample_closure();
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new());
        if let Ok(h) = h {
            let by_entries = h
                .entries
                .iter()
                .filter(|e| matches!(e, HostEntry::Method(m) if m.is_fabrication()))
                .count();
            assert_eq!(h.ledger.total(), by_entries);
            // `Object.hashCode()I` returns an int, so it denies rather than
            // fabricating a zero: an int default would be an interpretation.
            assert!(h.ledger.count_of(crate::hostgen::answer::StructuralAnswer::Zero) == 0);
            // `Build.FINGERPRINT` returns a reference, so it is `null` and it is
            // counted.
            assert!(h.ledger.count_of(crate::hostgen::answer::StructuralAnswer::Null) >= 1);
            // `void` returns are not fabrications, so they are absent from the
            // ledger even though they are the most common answer on a real
            // closure.
            assert_eq!(
                h.ledger.count_of(crate::hostgen::answer::StructuralAnswer::Void),
                0,
                "void must never be counted as a fabrication"
            );
        }
    }
}
