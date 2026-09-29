//! Where an answer comes from — the design problem this crate exists to solve.
//!
//! # The critique, and the answer to it
//!
//! The shim's author left this, and it is the sharpest thing anyone has said
//! about this project:
//!
//! > *A policy can only vary what the shim has a value for. … there is no value
//! > to vary, only a missing mechanism.*
////!
//! Read precisely: a hand-written shim invents an answer per method, one at a
//! time, and a policy axis can then vary it. For 4,649 methods nobody invents
//! 4,649 answers, so a policy over 4,649 methods mostly varies *nothing* — and
//! the members that do have answers are the 334 the shim author happened to
//! think about.
//!
//! A synthesiser has something the hand-writer did not. It can emit an
//! **explicit parameterised answer**: a value that comes from a parameter the
//! operator sets, or from a platform constant, and that is *named in the
//! recording*. That is not a fabrication with a nicer name. A fabrication is a
//! value nobody chose; a declared value is one somebody chose, can repeat, and
//! can counterfactualise by changing a single declaration.
//!
//! So there are exactly four places an answer can come from, and three of them
//! are not inventions:
//!
//! | source | who chose the value | recorded as | honest? |
//! |---|---|---|---|
//! | [`AnswerSource::Constant`] | nobody — it is true on every device | `fabricated: false`, source `platform-constant` | yes |
//! | [`AnswerSource::Declared`] | the operator, at load time | `fabricated: false`, source `declared:<param>` | yes |
//! | [`AnswerSource::Structural`] | nobody — it is the type's canonical absence | `fabricated: true`, source `structural:<kind>` | **yes, if labelled** |
//! | [`AnswerSource::Denied`] | nobody — there is no answer | `fabricated: false`, source `denied:<kind>` | yes |
//!
//! The one row that is "yes, if labelled" is the whole reason this module
//! exists. A structural answer — `null`, `0`, `false`, an empty array — is not
//! *chosen*, but it is also not a *guess*: it is the type's own statement that
//! there is nothing there. The danger is not the value; it is that a value with
//! no provenance attached reads in a recording exactly like a real one. So every
//! structural answer is enumerated in [`FabricationLedger`], and the run's
//! report states the count.
//!
//! # Why `Denied` is a first-class answer and not a fallback
//!
//! `IR.md` §Class resolution order step 5 says unresolved means "emit a typed
//! error, **never a silent default**". A denial is that typed error, and it is
//! the honest response to the overwhelming majority of a real closure: there is
//! no correct value for `android.opengl.GLES20.glReadPixels`'s third argument in
//! a substrate with no GPU, and the only two alternatives are a plausible lie
//! and a crash. For `MISBEHAVE`-class assumptions, the crash is the better of
//! those, because the lie is invisible.
//!
//! # The ledger is not optional
//!
//! [`FabricationLedger`] exists so a reader of a recording can answer "which of
//! these answers were invented?" without asking the generator. It is a
//! required output of [`crate::hostgen::emit::HostModule`] and its `total` is in
//! the run report.

use core::fmt;

use crate::hostgen::path::PathProblem;
use crate::hostgen::policy::{ClockMode, HostPolicy, IdentityMode, UndeclaredMode};
use crate::hostgen::taxonomy::AssumptionId;

/// An environment parameter a host answer can be read from.
///
/// The point of this enum is that it is **closed and named**. "Read the value
/// from the environment" is what makes a shim a liar; "read it from
/// `EnvParam::BuildSdkInt`, which the operator set or did not set" is a
/// mechanism, and when it is unset the answer is a [`DenialKind::Undeclared`]
/// rather than a guess.
///
/// Each variant is one axis of `IR.md`'s "correct answer depends on the
/// environment", and each names the `SUB.*` ID it feeds so the linkage is
/// explicit rather than implied by the parameter's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EnvParam {
    /// `Build.VERSION.SDK_INT`. `SUB.BUILD.SDK_INT`.
    BuildSdkInt,
    /// `Build.MODEL` / `MANUFACTURER` / `BRAND` / `DEVICE`. `SUB.BUILD.MODEL`.
    BuildModel,
    /// `Build.FINGERPRINT`. `SUB.BUILD.FINGERPRINT`.
    BuildFingerprint,
    /// `PackageManager.hasSystemFeature` / `Build.ABILITIES`. `SUB.BUILD.ABILITIES`.
    HasSystemFeature,
    /// `DisplayMetrics.densityDpi`. `SUB.RES.QUALIFIER`.
    DensityDpi,
    /// `Resources.getIdentifier` name→ID resolution. `SUB.RES.PACKAGE_RESOLVER`.
    ResourceId,
    /// `getSystemService(name)`. `SUB.IPC.SYSTEM_SERVICE`.
    SystemService,
    /// `PackageManager` answer for the subject package.
    /// `SUB.IPC.PACKAGE_MANAGER_SELF`.
    SelfPackage,
    /// `Locale.getDefault`. `SUB.RES.LOCALE`.
    Locale,
    /// `TimeZone.getDefault`. `SUB.RES.TIMEZONE`.
    TimeZone,
    /// `Configuration.fontScale`. `SUB.RES.FONT_SCALE`.
    FontScale,
    /// The wall clock, in milliseconds. `SUB.TIME.WALL_CLOCK`.
    WallClockMillis,
    /// `SystemClock.uptimeMillis`. `SUB.TIME.MONOTONIC`.
    UptimeMillis,
    /// `SystemClock.elapsedRealtime`. `SUB.TIME.ELAPSED_REALTIME`.
    ElapsedRealtimeMillis,
}

impl EnvParam {
    /// Every parameter, in declaration order.
    pub const ALL: [EnvParam; 14] = [
        EnvParam::BuildSdkInt,
        EnvParam::BuildModel,
        EnvParam::BuildFingerprint,
        EnvParam::HasSystemFeature,
        EnvParam::DensityDpi,
        EnvParam::ResourceId,
        EnvParam::SystemService,
        EnvParam::SelfPackage,
        EnvParam::Locale,
        EnvParam::TimeZone,
        EnvParam::FontScale,
        EnvParam::WallClockMillis,
        EnvParam::UptimeMillis,
        EnvParam::ElapsedRealtimeMillis,
    ];

    /// The name the operator sets, and the token the declaration records.
    pub fn as_str(self) -> &'static str {
        match self {
            EnvParam::BuildSdkInt => "build.sdk_int",
            EnvParam::BuildModel => "build.model",
            EnvParam::BuildFingerprint => "build.fingerprint",
            EnvParam::HasSystemFeature => "build.has_system_feature",
            EnvParam::DensityDpi => "res.density_dpi",
            EnvParam::ResourceId => "res.resource_id",
            EnvParam::SystemService => "ipc.system_service",
            EnvParam::SelfPackage => "ipc.self_package",
            EnvParam::Locale => "res.locale",
            EnvParam::TimeZone => "res.timezone",
            EnvParam::FontScale => "res.font_scale",
            EnvParam::WallClockMillis => "time.wall_clock_millis",
            EnvParam::UptimeMillis => "time.uptime_millis",
            EnvParam::ElapsedRealtimeMillis => "time.elapsed_realtime_millis",
        }
    }

    /// The assumption an answer read from this parameter feeds.
    ///
    /// Declared alongside the parameter rather than looked up from it, so the
    /// link between "which knob the operator turns" and "which assumption this
    /// predicates" is a single `match` that cannot drift: adding a parameter
    /// without an ID does not compile.
    pub fn taxonomy(self) -> AssumptionId {
        match self {
            EnvParam::BuildSdkInt => AssumptionId::BuildSdkInt,
            EnvParam::BuildModel => AssumptionId::BuildModel,
            EnvParam::BuildFingerprint => AssumptionId::BuildFingerprint,
            EnvParam::HasSystemFeature => AssumptionId::BuildAbilities,
            EnvParam::DensityDpi => AssumptionId::ResQualifier,
            EnvParam::ResourceId => AssumptionId::ResPackageResolver,
            EnvParam::SystemService => AssumptionId::IpcSystemService,
            EnvParam::SelfPackage => AssumptionId::IpcPackageManagerSelf,
            EnvParam::Locale => AssumptionId::ResLocale,
            EnvParam::TimeZone => AssumptionId::ResTimezone,
            EnvParam::FontScale => AssumptionId::ResFontScale,
            EnvParam::WallClockMillis => AssumptionId::TimeWallClock,
            EnvParam::UptimeMillis => AssumptionId::TimeMonotonic,
            EnvParam::ElapsedRealtimeMillis => AssumptionId::TimeElapsedRealtime,
        }
    }
}

impl fmt::Display for EnvParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A value that is true on every Android device and so needs no operator.
///
/// The table is deliberately tiny. Every entry has to survive one question —
/// *would this be wrong on any real device?* — and `Math.PI` survives it while
/// "a typical pixel density" does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlatformConstant {
    /// `Integer.MAX_VALUE`, and every `2^31-1`-shaped accessor.
    IntMaxValue,
    /// `Integer.MIN_VALUE`.
    IntMinValue,
    /// `Long.MAX_VALUE`.
    LongMaxValue,
    /// `Long.MIN_VALUE`.
    LongMinValue,
    /// `Float.POSITIVE_INFINITY`.
    FloatPositiveInfinity,
    /// `Float.NaN`.
    FloatNan,
    /// `Double.POSITIVE_INFINITY`.
    DoublePositiveInfinity,
    /// `Double.NaN`.
    DoubleNan,
    /// The empty string. True everywhere, on every device, forever.
    EmptyString,
}

impl PlatformConstant {
    pub fn as_str(self) -> &'static str {
        match self {
            PlatformConstant::IntMaxValue => "Integer.MAX_VALUE",
            PlatformConstant::IntMinValue => "Integer.MIN_VALUE",
            PlatformConstant::LongMaxValue => "Long.MAX_VALUE",
            PlatformConstant::LongMinValue => "Long.MIN_VALUE",
            PlatformConstant::FloatPositiveInfinity => "Float.POSITIVE_INFINITY",
            PlatformConstant::FloatNan => "Float.NaN",
            PlatformConstant::DoublePositiveInfinity => "Double.POSITIVE_INFINITY",
            PlatformConstant::DoubleNan => "Double.NaN",
            PlatformConstant::EmptyString => "\"\"",
        }
    }
}

/// The type's own statement that there is nothing there.
///
/// Every one of these is a fabricated value and every one is enumerated in
/// [`FabricationLedger`], **except [`StructuralAnswer::Void`]** — a `void`
/// method returns no value, so there is nothing for the app to consume and
/// nothing to have fabricated. Counting it would inflate the ledger with a
/// fabrication that cannot have happened, which is the failure mode of every
/// honesty mechanism: a number that can be inflated is a number nobody trusts.
///
/// They are here because refusing all of the others makes the host refuse a
/// large fraction of a real closure, and because the honest version of
/// "fabricate" is "fabricate and say so" — not "refuse", which is a different
/// decision with a different cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StructuralAnswer {
    /// Nothing is returned. **Not a fabrication** — see the type's docs.
    Void,
    /// `null`. The canonical absent reference.
    Null,
    /// `0`. The canonical absent number.
    Zero,
    /// `false`. The canonical absent boolean — the most dangerous of the three,
    /// because a boolean is a branch predicate.
    False,
    /// An empty array.
    EmptyArray,
    /// An empty string. Distinct from `null`, and the recording keeps them
    /// distinct because they are different facts.
    EmptyString,
}

impl StructuralAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            StructuralAnswer::Void => "void",
            StructuralAnswer::Null => "null",
            StructuralAnswer::Zero => "0",
            StructuralAnswer::False => "false",
            StructuralAnswer::EmptyArray => "[]",
            StructuralAnswer::EmptyString => "\"\"",
        }
    }

    /// Whether this structural answer is a **fabrication**: a value the app will
    /// consume as if it were real, and which nobody chose.
    ///
    /// `Void` is excluded because it produces no value at all. This is the only
    /// place a structural answer is exempt, and the exemption is load-bearing:
    /// on a real closure most methods are `void`, so counting them would put a
    /// number in the report that is mostly an artefact of counting nothing.
    pub fn is_fabrication(self) -> bool {
        !matches!(self, StructuralAnswer::Void)
    }
}

/// Why an answer was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenialKind {
    /// The environment parameter this answer needed was not declared.
    Undeclared(EnvParam),
    /// No platform constant covers this and the return type carries no safe
    /// structural absence — a boolean, most often.
    NoSafeValue,
    /// The capability does not exist and the app is told so.
    Absent,
    /// Would have required egress.
    Egress,
    /// Would have required native code or a raw device.
    Privileged,
    /// The path escaped the host root.
    Path(PathProblem),
    /// A `native` method the host does not implement.
    UnsatisfiedLink,
}

impl fmt::Display for DenialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenialKind::Undeclared(p) => write!(f, "no declared value for {}", p.as_str()),
            DenialKind::NoSafeValue => {
                f.write_str("no platform constant and no safe structural absence for this type")
            }
            DenialKind::Absent => f.write_str("capability absent in the substrate"),
            DenialKind::Egress => f.write_str("egress denied"),
            DenialKind::Privileged => f.write_str("native or raw-device access denied"),
            DenialKind::Path(p) => write!(f, "path refused: {p}"),
            DenialKind::UnsatisfiedLink => f.write_str("no native implementation"),
        }
    }
}

/// Where an emitted host answer's value comes from.
///
/// Exhaustive and closed. A synthesiser has exactly these five options and no
/// others, which is what makes "was anything invented?" answerable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerSource {
    /// True on every device. Nobody chose it; nobody had to.
    Constant(PlatformConstant),
    /// Chosen by the operator and named in the declaration.
    Declared(EnvParam),
    /// The type's own absence. **Fabricated, and always labelled.**
    Structural(StructuralAnswer),
    /// Refused.
    Denied(DenialKind),
}

impl AnswerSource {
    /// The token the recording carries for this source.
    pub fn as_str(self) -> &'static str {
        match self {
            AnswerSource::Constant(_) => "platform-constant",
            AnswerSource::Declared(_) => "declared",
            AnswerSource::Structural(_) => "structural",
            AnswerSource::Denied(_) => "denied",
        }
    }

    /// Whether this source is a **fabrication**: a value nobody chose that the
    /// app will nonetheless consume as if it were real.
    ///
    /// Only [`AnswerSource::Structural`] is. `Constant` is true on every device,
    /// `Declared` was chosen, and `Denied` produced no value at all.
    pub fn is_fabrication(self) -> bool {
        match self {
            AnswerSource::Structural(s) => s.is_fabrication(),
            _ => false,
        }
    }

    /// The rendered source for a recording: `declared:<param>`,
    /// `structural:null`, `denied:undeclared`, and so on.
    pub fn render(self) -> String {
        match self {
            AnswerSource::Constant(c) => format!("platform-constant:{}", c.as_str()),
            AnswerSource::Declared(p) => format!("declared:{}", p.as_str()),
            AnswerSource::Structural(s) => format!("structural:{}", s.as_str()),
            AnswerSource::Denied(DenialKind::Undeclared(p)) => {
                format!("denied:undeclared:{}", p.as_str())
            }
            AnswerSource::Denied(k) => format!("denied:{k}"),
        }
    }
}

/// The environment the host answers against: the set of parameters the operator
/// actually declared.
///
/// A newtype over a sorted list rather than a map because there are at most 14
/// parameters, a lookup is linear, and a `HashMap` here would mean a host
/// whose behaviour depends on hash iteration order — which is exactly the class
/// of nondeterminism this project is trying to eliminate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeclaredEnv {
    params: Vec<EnvParam>,
    clock: Option<i64>,
}

impl DeclaredEnv {
    /// An environment with nothing declared, which is the default and the state
    /// most real closures run in.
    pub fn new() -> DeclaredEnv {
        DeclaredEnv::default()
    }

    /// Declare a parameter. Declaring the same one twice is idempotent.
    pub fn declare(&mut self, p: EnvParam) -> &mut DeclaredEnv {
        if !self.params.contains(&p) {
            self.params.push(p);
            self.params.sort_unstable();
        }
        self
    }

    /// Declare a frozen wall-clock instant, for [`crate::hostgen::policy::ClockMode::Frozen`].
    pub fn declare_clock(&mut self, millis: i64) -> &mut DeclaredEnv {
        self.clock = Some(millis);
        self
    }

    /// Whether the operator declared this parameter.
    pub fn has(&self, p: EnvParam) -> bool {
        self.params.contains(&p)
    }

    /// The declared clock instant, if any.
    pub fn clock_millis(&self) -> Option<i64> {
        self.clock
    }

    /// Every declared parameter, sorted.
    pub fn params(&self) -> &[EnvParam] {
        &self.params
    }

    /// A declaration string for the recording: which parameters existed, and
    /// explicitly that an absent one was absent.
    pub fn declaration(&self) -> String {
        let mut s = format!(
            "declared environment parameters ({} of {}):",
            self.params.len(),
            EnvParam::ALL.len()
        );
        for p in EnvParam::ALL {
            if self.has(p) {
                s.push_str("\n  + ");
            } else {
                s.push_str("\n  - ");
            }
            s.push_str(p.as_str());
        }
        match self.clock_millis() {
            Some(ms) => s.push_str(&format!("\n  frozen clock: {ms} ms")),
            None => s.push_str("\n  frozen clock: not declared"),
        }
        s
    }
}

/// One entry in the fabrication ledger.
///
/// Keyed by the host table entry so a reader can go from "something was
/// invented" to "here it is" in one step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricationRecord {
    /// `class->name signature`, the host table's index key.
    pub entry_key: String,
    pub source: AnswerSource,
    pub taxonomy: AssumptionId,
}

/// Every answer in a host module whose value nobody chose.
///
/// This is the module's answer to the predecessor's critique, stated as an
/// artefact rather than as a promise: `ledger.total()` is a number in the run
/// report, so "how much of this run was invented?" is a measurement rather than
/// something a reader has to infer from the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FabricationLedger {
    records: Vec<FabricationRecord>,
    /// Denials kept alongside, so a reader sees not only what was invented but
    /// what was refused. The two together are the whole honesty surface; one
    /// without the other is the shim's original sin in a new outfit.
    denials: Vec<FabricationRecord>,
}

impl FabricationLedger {
    pub fn new() -> FabricationLedger {
        FabricationLedger::default()
    }

    /// Record an answer. Structurals go in the fabrication list and denials in
    /// the denial list; the other two sources are not recorded here because
    /// they are not fabrications and not refusals.
    pub fn record(&mut self, entry_key: impl Into<String>, source: AnswerSource, taxonomy: AssumptionId) {
        let r = FabricationRecord {
            entry_key: entry_key.into(),
            source,
            taxonomy,
        };
        match source {
            AnswerSource::Structural(s) if s.is_fabrication() => self.records.push(r),
            AnswerSource::Denied(_) => self.denials.push(r),
            // A `void` structural answer, and the two chosen sources, are none
            // of this ledger's business: there is nothing to disclose.
            AnswerSource::Structural(_) | AnswerSource::Constant(_) | AnswerSource::Declared(_) => {}
        }
    }

    /// How many answers were fabricated.
    pub fn total(&self) -> usize {
        self.records.len()
    }

    /// How many answers were refused.
    pub fn denials(&self) -> usize {
        self.denials.len()
    }

    /// The fabricated answers.
    pub fn fabrications(&self) -> &[FabricationRecord] {
        &self.records
    }

    /// The refused answers.
    pub fn denial_records(&self) -> &[FabricationRecord] {
        &self.denials
    }

    /// How many fabrications there are of one source kind.
    pub fn count_of(&self, s: StructuralAnswer) -> usize {
        self.records
            .iter()
            .filter(|r| r.source == AnswerSource::Structural(s))
            .count()
    }

    /// Distinct taxonomy IDs among the fabrications.
    ///
    /// The number that matters for the report: if a fabrication predicates
    /// `SUB.IPC.PACKAGE_MANAGER_OTHER`, a crash-counting evaluation will not see
    /// the run go wrong.
    pub fn misbehave_fabrications(&self) -> usize {
        self.records
            .iter()
            .filter(|r| r.taxonomy.class() == crate::hostgen::taxonomy::SymptomClass::Misbehave)
            .count()
    }

    /// A report block. States the counts and does not editorialise.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "fabrication ledger: {} fabricated answers, {} refused answers, {} of the \
             fabricated ones predicate a MISBEHAVE assumption\n",
            self.total(),
            self.denials(),
            self.misbehave_fabrications()
        ));
        for s2 in [
            StructuralAnswer::Void,
            StructuralAnswer::Null,
            StructuralAnswer::Zero,
            StructuralAnswer::False,
            StructuralAnswer::EmptyArray,
            StructuralAnswer::EmptyString,
        ] {
            s.push_str(&format!(
                "  fabricated {} × {}: {}\n",
                self.count_of(s2),
                s2.as_str(),
                s2.token()
            ));
        }
        s
    }
}

impl StructuralAnswer {
    /// A one-line justification, carried into the report so the reason a value
    /// was chosen travels with the count.
    pub fn token(self) -> &'static str {
        match self {
            StructuralAnswer::Null => "the canonical absent reference; the app has an ordinary null check",
            StructuralAnswer::Zero => "the canonical absent number; feeds arithmetic and comparisons",
            StructuralAnswer::False => "the canonical absent boolean; a branch predicate, and the most dangerous of these",
            StructuralAnswer::EmptyArray => "an empty sequence; length 0, which the app can and does check",
            StructuralAnswer::EmptyString => "the empty string; distinct from null and kept distinct",
            StructuralAnswer::Void => {
                "nothing is returned, so there is no value to fabricate; not counted as a fabrication"
            }
        }
    }
}

/// Apply the policy to a parameter that has no declared value.
///
/// This is the function that decides the default behaviour of an
/// environment-dependent answer, and it is one function so that the decision is
/// in one place and a test can enumerate it over the whole policy space.
pub fn undeclared_answer(policy: &HostPolicy, param: EnvParam) -> AnswerSource {
    // The clock is its own axis, so it consults `clock` rather than `undeclared`.
    if matches!(
        param,
        EnvParam::WallClockMillis | EnvParam::UptimeMillis | EnvParam::ElapsedRealtimeMillis
    ) {
        return match policy.clock {
            ClockMode::Deny => AnswerSource::Denied(DenialKind::Undeclared(param)),
            ClockMode::HostReal | ClockMode::Frozen => AnswerSource::Declared(param),
        };
    }
    // Identity has its own axis.
    if matches!(
        param,
        EnvParam::BuildSdkInt
            | EnvParam::BuildModel
            | EnvParam::BuildFingerprint
            | EnvParam::HasSystemFeature
    ) {
        return match policy.identity {
            IdentityMode::Withheld => AnswerSource::Structural(StructuralAnswer::Zero),
            IdentityMode::Declared => AnswerSource::Denied(DenialKind::Undeclared(param)),
        };
    }
    match policy.undeclared {
        UndeclaredMode::Deny | UndeclaredMode::RefuseClass => {
            AnswerSource::Denied(DenialKind::Undeclared(param))
        }
        UndeclaredMode::Null => AnswerSource::Structural(StructuralAnswer::Null),
    }
}

/// Resolve a parameter to its answer source, consulting the declared environment
/// first.
///
/// The shape of every environment-dependent answer in the host, in one function.
pub fn resolve(
    policy: &HostPolicy,
    env: &DeclaredEnv,
    param: EnvParam,
) -> AnswerSource {
    let clock_ok = match policy.clock {
        ClockMode::Deny => env.has(param),
        ClockMode::HostReal | ClockMode::Frozen => true,
    };
    if env.has(param) && clock_ok {
        AnswerSource::Declared(param)
    } else {
        undeclared_answer(policy, param)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_structural_answers_are_fabrications() {
        assert!(AnswerSource::Structural(StructuralAnswer::Null).is_fabrication());
        assert!(
            !AnswerSource::Structural(StructuralAnswer::Void).is_fabrication(),
            "a void method returns no value; counting it would inflate the ledger"
        );
        assert!(!AnswerSource::Constant(PlatformConstant::IntMaxValue).is_fabrication());
        assert!(!AnswerSource::Declared(EnvParam::BuildSdkInt).is_fabrication());
        assert!(!AnswerSource::Denied(DenialKind::Absent).is_fabrication());
    }

    #[test]
    fn every_declared_source_renders_with_its_parameter() {
        for p in EnvParam::ALL {
            assert_eq!(
                AnswerSource::Declared(p).render(),
                format!("declared:{}", p.as_str())
            );
            assert!(AssumptionId::ALL.contains(&p.taxonomy()), "{p} has no taxonomy ID");
        }
    }

    #[test]
    fn the_default_policy_denies_every_undeclared_parameter() {
        let policy = HostPolicy::default();
        let env = DeclaredEnv::new();
        for p in EnvParam::ALL {
            match resolve(&policy, &env, p) {
                AnswerSource::Denied(DenialKind::Undeclared(_)) => {}
                other => panic!("{p} should deny under the default policy, got {}", other.render()),
            }
        }
    }

    #[test]
    fn a_declared_parameter_removes_the_denial_and_the_fabrication() {
        let policy = HostPolicy::default();
        let mut env = DeclaredEnv::new();
        assert!(matches!(
            resolve(&policy, &env, EnvParam::BuildSdkInt),
            AnswerSource::Denied(_)
        ));
        env.declare(EnvParam::BuildSdkInt);
        assert_eq!(
            resolve(&policy, &env, EnvParam::BuildSdkInt),
            AnswerSource::Declared(EnvParam::BuildSdkInt)
        );
    }

    #[test]
    fn the_clock_axis_is_independent_of_the_undeclared_axis() {
        let mut env = DeclaredEnv::new();
        env.declare(EnvParam::UptimeMillis);
        for (clock, want_denied) in [
            (ClockMode::Deny, false),
            (ClockMode::HostReal, false),
            (ClockMode::Frozen, false),
        ] {
            let mut p = HostPolicy::default();
            p.clock = clock;
            // With the parameter declared, all three clock values answer from
            // the declaration — which is the point: `HostReal` and `Frozen`
            // differ in *what the operator set*, not in whether the answer
            // exists.
            assert!(matches!(
                resolve(&p, &env, EnvParam::UptimeMillis),
                AnswerSource::Declared(_)
            ));
            assert!(!want_denied);
        }
        // And with the parameter absent, only `Deny` refuses.
        let empty = DeclaredEnv::new();
        let mut deny = HostPolicy::default();
        deny.clock = ClockMode::Deny;
        assert!(matches!(
            resolve(&deny, &empty, EnvParam::WallClockMillis),
            AnswerSource::Denied(_)
        ));
        let mut frozen = HostPolicy::default();
        frozen.clock = ClockMode::Frozen;
        assert_eq!(
            resolve(&frozen, &empty, EnvParam::WallClockMillis),
            AnswerSource::Declared(EnvParam::WallClockMillis)
        );
    }

    #[test]
    fn the_identity_axis_can_fabricate_a_zero_on_purpose() {
        let mut p = HostPolicy::default();
        p.identity = IdentityMode::Withheld;
        let env = DeclaredEnv::new();
        assert_eq!(
            resolve(&p, &env, EnvParam::BuildSdkInt),
            AnswerSource::Structural(StructuralAnswer::Zero)
        );
    }

    #[test]
    fn the_ledger_separates_fabrications_from_denials() {
        let mut l = FabricationLedger::new();
        l.record("La;->a()V", AnswerSource::Structural(StructuralAnswer::Null), AssumptionId::IpcPackageManagerOther);
        l.record("La;->b()V", AnswerSource::Structural(StructuralAnswer::Null), AssumptionId::IpcPackageManagerSelf);
        l.record("La;->c()V", AnswerSource::Structural(StructuralAnswer::Zero), AssumptionId::BuildSdkInt);
        l.record("La;->d()I", AnswerSource::Denied(DenialKind::Absent), AssumptionId::GfxEglContext);
        l.record("La;->e()I", AnswerSource::Declared(EnvParam::BuildSdkInt), AssumptionId::BuildSdkInt);
        l.record("La;->f()I", AnswerSource::Constant(PlatformConstant::IntMaxValue), AssumptionId::CpuNumeric);
        assert_eq!(l.total(), 3);
        assert_eq!(l.denials(), 1);
        assert_eq!(l.count_of(StructuralAnswer::Null), 2);
        assert_eq!(l.count_of(StructuralAnswer::Zero), 1);
        // PACKAGE_MANAGER_OTHER and SDK_INT are both Misbehave.
        assert_eq!(l.misbehave_fabrications(), 3);
        let r = l.report();
        assert!(r.contains("3 fabricated answers"), "{r}");
        assert!(r.contains("1 refused answers"), "{r}");
    }

    #[test]
    fn the_env_declaration_names_what_is_absent() {
        let mut env = DeclaredEnv::new();
        env.declare(EnvParam::BuildSdkInt);
        let d = env.declaration();
        assert!(d.contains("+ build.sdk_int"));
        assert!(d.contains("- build.fingerprint"));
        assert!(d.contains("frozen clock: not declared"));
        env.declare_clock(1_700_000_000_000);
        assert!(env.declaration().contains("frozen clock: 1700000000000 ms"));
        assert_eq!(env.clock_millis(), Some(1_700_000_000_000));
    }

    #[test]
    fn declaring_twice_is_idempotent_and_order_is_deterministic() {
        let mut a = DeclaredEnv::new();
        a.declare(EnvParam::Locale);
        a.declare(EnvParam::BuildSdkInt);
        a.declare(EnvParam::Locale);
        let mut b = DeclaredEnv::new();
        b.declare(EnvParam::BuildSdkInt);
        b.declare(EnvParam::Locale);
        assert_eq!(a.params(), b.params());
        assert_eq!(a.params(), &[EnvParam::BuildSdkInt, EnvParam::Locale]);
    }
}
