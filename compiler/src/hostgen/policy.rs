//! The substrate policy: what a *declared* answer is, and what an undeclared one
//! becomes.
//!
//! # The critique this module answers
//!
//! The shim's own author wrote this, and it stands:
//!
//! > *A policy can only vary what the shim has a value for. … there is no value
//! > to vary, only a missing mechanism.*
//!
//! That is exactly right about a *hand-written* shim, whose answers were invented
//! one at a time by a person who had to decide what `Build.MODEL` should be.
//! Five axes over 334 such answers is a lot of leverage. The same five axes over
//! 4,649 answers, most of which nobody ever thought about, is a policy that
//! mostly varies a default nobody chose.
//!
//! So these axes do not vary answers. They vary **provenance**: how much the
//! substrate is willing to assert on the app's behalf, and what it does when it
//! cannot.
//!
//! # The axes
//!
//! Six orthogonal axes, each a closed set of named values:
//!
//! | axis | values | what it actually governs |
//! |---|---|---|
//! | [`Axis::Undeclared`] | [`UndeclaredMode::Deny`] · [`Null`] · [`RefuseClass`] | what an answer with no declared value becomes |
//! | [`Axis::Identity`] | [`IdentityMode::Declared`] · [`Withheld`] | whether `Build.*` / `getprop` answer at all |
//! | [`Axis::Network`] | [`NetworkMode::Deny`] · [`LoopbackSynthetic`] | **nothing** — both deny, which is the point |
//! | [`Axis::Path`] | [`PathPolicy::Full`] · [`ShapeOnly`] · [`Opaque`] | how much of a request path is recorded |
//! | [`Axis::Clock`] | [`ClockMode::Deny`] · [`HostReal`] · [`Frozen`] | the wall clock, an explicit declared value |
//! | [`Axis::SideEffect`] | [`SideEffectMode::Record`] · [`Deny`] | in-substrate state mutation |
//!
//! **3 × 2 × 2 × 3 × 3 × 2 = 216 combinations.** The shim sweeps 162. The extra
//! 54 come from having two axes it does not (undeclared-answer handling and
//! side-effect scope), which is the honest consequence of generating rather than
//! writing: a generator has more decisions to expose than a hand-writer had
//! choices to make.
//!
//! # Orthogonality, in the strong sense
//!
//! No value of one axis changes the meaning of another. [`Axis::governs`] names
//! what each axis moves, so a differential run can attribute a moved fact to the
//! axis that moved it rather than to "the policy", which is not an attribution.
//!
//! # The two properties no axis can violate
//!
//! 1. **No axis can widen a capability.** Every value of [`Axis::Network`] denies
//!    egress; [`Axis::Undeclared::Deny`] is the default so that widening takes a
//!    source edit rather than a configuration. `tests/egress_denial.rs` sweeps
//!    all 216 against a live `TcpListener`.
//! 2. **No axis can widen what is captured.** Redaction is structural — see
//!    [`crate::hostgen::redact`] — and [`Axis::Path`] varies only *how much of a
//!    path* is kept, never whether a query value exists. There is no field for
//!    one to be put in.
//!
//! # Versioning, three numbers
//!
//! A recording has to be interpretable years later by someone who has never read
//! this file, so "what did `undeclared: null` mean?" must be answerable from the
//! document itself.
//!
//! * [`POLICY_FORMAT`] — the *shape* of the serialised declaration. Bumped only
//!   on an incompatible JSON change.
//! * [`POLICY_VERSION`] — the *meaning* of the axis vocabulary. Bumped when a
//!   value is added, removed, or redefined. A shape-compatible redefinition still
//!   bumps it.
//! * [`HostPolicy::digest`] — an FNV-1a 64 over the canonical declaration, so two
//!   recordings can be joined to "the same policy" without string-diffing prose.
//!   A checksum for joining, explicitly **not** a security property.

use core::fmt;

use crate::hostgen::redact::PathPolicy;

/// The serialised shape of a policy declaration.
pub const POLICY_FORMAT: &str = "andro-substrate.host-policy/1";

/// The meaning of the axis vocabulary.
pub const POLICY_VERSION: u16 = 1;

// ======================================================================== axes

/// What an answer becomes when the environment parameter it needs was not
/// declared by whoever is running the substrate.
///
/// This is the axis the shim could not have, and it is the most consequential
/// one here, because for most of a 4,649-method closure the parameter will not
/// be declared — there is no parameter for `TextUtils.getEllipsisString`'s
/// thirteenth argument, and pretending otherwise is how a plausible
/// fabrication happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UndeclaredMode {
    /// Throw. The stub denies and the recording says so.
    ///
    /// **The default**, and the reason it is the default is a research-validity
    /// argument rather than an engineering one: a withheld substrate fails
    /// loudly and is easy to discount, so the facts it produces are about the
    /// app. A plausible one is the confound, and a confound has to be
    /// *available* for the other values to be read as counterfactuals — but it
    /// does not have to be the default, and here the burden of proof runs the
    /// other way, because a generated host has no plausible answer to fall back
    /// on and would have to invent one.
    Deny,
    /// Return the canonical "absent" value for the type: `null` for a
    /// reference, `0` for a number, `false` for a boolean.
    ///
    /// Available, and a legitimate counterfactual. It is not the default because
    /// `0` and `false` are exactly the values an app silently computes with, and
    /// the resulting `MISBEHAVE` is invisible to a crash counter.
    Null,
    /// Throw the exception the *real* device would throw for this API, so the
    /// app's own failure handling runs.
    ///
    /// Distinct from [`UndeclaredMode::Deny`] in the way that matters for
    /// [`crate::hostgen::synth`]: a `ClassNotFoundException` lets the app take
    /// its fallback branch and keeps running, whereas a generic denial may
    /// unwind a frame the app did not expect to unwind.
    RefuseClass,
}

impl UndeclaredMode {
    pub fn as_str(self) -> &'static str {
        match self {
            UndeclaredMode::Deny => "deny",
            UndeclaredMode::Null => "null",
            UndeclaredMode::RefuseClass => "refuse-class",
        }
    }

    pub fn parse(s: &str) -> Option<UndeclaredMode> {
        Some(match s {
            "deny" => UndeclaredMode::Deny,
            "null" => UndeclaredMode::Null,
            "refuse-class" => UndeclaredMode::RefuseClass,
            _ => return None,
        })
    }
}

/// Whether an identity field (`Build.*`, `getprop`, `SystemProperties`)
/// answers at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdentityMode {
    /// Answer from a **declared** environment parameter, or deny if it is not
    /// declared. The default.
    ///
    /// Note what this is not: it is not "answer with a plausible device". A
    /// declared identity is one the operator chose and can name in the
    /// recording; a plausible one is one this crate invented, which is the
    /// confound the shim's author identified and the reason `RefuseClass` and
    /// `Null` below exist as honest alternatives.
    Declared,
    /// `Build` still resolves so the app's control flow is not interrupted, but
    /// every field answers the canonical absent value.
    ///
    /// The "fails loudly but keeps running" arm, and it is genuinely useful
    /// precisely because it is easy to discount: an app that gets `null` from
    /// `Build.MODEL` takes an obviously-abnormal branch, so the difference
    /// between that branch and the declared one is a measurement of *the
    /// substrate's plausibility*.
    Withheld,
}

impl IdentityMode {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityMode::Declared => "declared",
            IdentityMode::Withheld => "withheld",
        }
    }

    pub fn parse(s: &str) -> Option<IdentityMode> {
        Some(match s {
            "declared" => IdentityMode::Declared,
            "withheld" => IdentityMode::Withheld,
            _ => return None,
        })
    }
}

/// How outbound network is handled.
///
/// **Both values deny.** That is the entire design of this axis, and it is why
/// it exists: the shim's `NetworkMode` had a `SyntheticLoopback` value, and the
/// honest test of whether an axis can widen a capability is whether *every*
/// value of it refuses to. `tests/egress_denial.rs` drives both against a live
/// `TcpListener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkMode {
    /// Record the attempt and throw the Java-shaped failure.
    Deny,
    /// Record the attempt, and *additionally* record that the app expected a
    /// loopback peer, so an analyst can see which apps were written against a
    /// local server. Still throws; still opens nothing.
    LoopbackSynthetic,
}

impl NetworkMode {
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::Deny => "deny",
            NetworkMode::LoopbackSynthetic => "loopback-synthetic",
        }
    }

    pub fn parse(s: &str) -> Option<NetworkMode> {
        Some(match s {
            "deny" => NetworkMode::Deny,
            "loopback-synthetic" => NetworkMode::LoopbackSynthetic,
            _ => return None,
        })
    }
}

/// The wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClockMode {
    /// `System.currentTimeMillis` and friends deny unless the operator declared
    /// a clock. The default.
    ///
    /// `SUB.TIME.WALL_CLOCK` is `DEGRADE`: a plausible clock is off by the
    /// browser's idea of the user's timezone and by nothing else, and a
    /// token-expiry check that passes on the substrate is a `MISBEHAVE` the app
    /// never sees.
    Deny,
    /// Answer from the host's clock, and **record that fact in the declaration**
    /// so a reading knows the clock was the browser's and not the device's.
    HostReal,
    /// A frozen declared instant, for making timeouts deterministic.
    Frozen,
}

impl ClockMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ClockMode::Deny => "deny",
            ClockMode::HostReal => "host-real",
            ClockMode::Frozen => "frozen",
        }
    }

    pub fn parse(s: &str) -> Option<ClockMode> {
        Some(match s {
            "deny" => ClockMode::Deny,
            "host-real" => ClockMode::HostReal,
            "frozen" => ClockMode::Frozen,
            _ => return None,
        })
    }
}

/// Mutation of state the substrate owns — the app's own data directory, its
/// `SharedPreferences`, its in-memory SQLite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SideEffectMode {
    /// Perform the mutation inside the substrate's own in-memory state and
    /// record it. The default, and safe: the state is the app's own and there is
    /// nothing outside the sandbox for it to reach.
    Record,
    /// Refuse every mutation. For the differential arm where mutation itself is
    /// the variable — how many bugs are "the app wrote something and read it
    /// back differently".
    Deny,
}

impl SideEffectMode {
    pub fn as_str(self) -> &'static str {
        match self {
            SideEffectMode::Record => "record",
            SideEffectMode::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<SideEffectMode> {
        Some(match s {
            "record" => SideEffectMode::Record,
            "deny" => SideEffectMode::Deny,
            _ => return None,
        })
    }
}

/// A policy axis. The discriminant set is closed and the enumeration is the
/// public one, so a new axis is a compile error in every `match` that has to be
/// updated rather than a silent omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Axis {
    Undeclared,
    Identity,
    Network,
    Path,
    Clock,
    SideEffect,
}

impl Axis {
    /// Every axis, in declaration order.
    pub const ALL: [Axis; 6] = [
        Axis::Undeclared,
        Axis::Identity,
        Axis::Network,
        Axis::Path,
        Axis::Clock,
        Axis::SideEffect,
    ];

    /// The token a declaration uses for this axis.
    pub fn as_str(self) -> &'static str {
        match self {
            Axis::Undeclared => "undeclared",
            Axis::Identity => "identity",
            Axis::Network => "network",
            Axis::Path => "path",
            Axis::Clock => "clock",
            Axis::SideEffect => "side_effect",
        }
    }

    /// What this axis moves. Used to attribute a changed fact to a changed axis.
    pub fn governs(self) -> &'static str {
        match self {
            Axis::Undeclared => "answers whose declared parameter is absent",
            Axis::Identity => "Build.* fields, getprop, SystemProperties",
            Axis::Network => "nothing: every value denies egress",
            Axis::Path => "the rendering of a recorded request path",
            Axis::Clock => "System.currentTimeMillis, uptimeMillis, elapsedRealtime",
            Axis::SideEffect => "in-substrate state mutation",
        }
    }

    /// The human-readable statement recorded alongside each value, so an
    /// analyst never has to read this file to know what a declaration meant.
    pub fn statement(self, value: &str) -> &'static str {
        match (self, value) {
            (Axis::Undeclared, "deny") => {
                "an answer whose declared parameter is absent throws; nothing is guessed"
            }
            (Axis::Undeclared, "null") => {
                "an answer whose declared parameter is absent returns the type's canonical \
                 absent value; the recording marks every such answer as fabricated"
            }
            (Axis::Undeclared, "refuse-class") => {
                "an answer whose declared parameter is absent throws the exception a real \
                 device would throw for that API"
            }
            (Axis::Identity, "declared") => {
                "Build.* and getprop answer from a declared environment parameter, or deny \
                 if that parameter is not declared"
            }
            (Axis::Identity, "withheld") => {
                "Build.* resolves so control flow continues, and every field answers the \
                 canonical absent value"
            }
            (Axis::Network, "deny") => "every outbound attempt is recorded and refused",
            (Axis::Network, "loopback-synthetic") => {
                "every outbound attempt is recorded and refused, and the recording also notes \
                 that the app expected a loopback peer; nothing is opened under either value"
            }
            (Axis::Path, _) => {
                "the recorded path rendering only; no query value exists to be revealed at \
                 any setting of this axis"
            }
            (Axis::Clock, "deny") => "clock reads deny unless the operator declared a clock",
            (Axis::Clock, "host-real") => {
                "clock reads answer from the host clock, and the declaration says so"
            }
            (Axis::Clock, "frozen") => "clock reads answer with a declared frozen instant",
            (Axis::SideEffect, "record") => {
                "mutations are performed inside the substrate's own state and recorded"
            }
            (Axis::SideEffect, "deny") => "mutations are refused and recorded as refusals",
            _ => "axis value not in the registry",
        }
    }
}

impl fmt::Display for Axis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ====================================================================== policy

/// A complete, closed policy declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostPolicy {
    pub undeclared: UndeclaredMode,
    pub identity: IdentityMode,
    pub network: NetworkMode,
    pub path: PathPolicy,
    pub clock: ClockMode,
    pub side_effect: SideEffectMode,
}

impl Default for HostPolicy {
    /// Every axis at the value that fabricates nothing. The shim's default was
    /// the plausible fabricator, for the reason given in its own module docs;
    /// here the reason is different and worth stating, because it is the one
    /// place this crate deliberately differs from its predecessor rather than
    /// porting it.
    ///
    /// A generated host is not asked "what does `Build.MODEL` say". It is asked
    /// 4,649 times "what does *this* method say", and for most of them there is
    /// no plausible answer to give. The only two options are a declared
    /// parameter or a refusal, and a policy whose default is a refusal cannot
    /// accidentally emit a fabricated value. The other two values of
    /// [`Axis::Undeclared`] exist so a *fabricating* substrate is a
    /// configuration away and can therefore be measured as a counterfactual
    /// rather than as an accident.
    fn default() -> HostPolicy {
        HostPolicy {
            undeclared: UndeclaredMode::Deny,
            identity: IdentityMode::Declared,
            network: NetworkMode::Deny,
            path: PathPolicy::Full,
            clock: ClockMode::Deny,
            side_effect: SideEffectMode::Record,
        }
    }
}

impl HostPolicy {
    /// The value of one axis, as its token.
    pub fn axis(&self, axis: Axis) -> &'static str {
        match axis {
            Axis::Undeclared => self.undeclared.as_str(),
            Axis::Identity => self.identity.as_str(),
            Axis::Network => self.network.as_str(),
            Axis::Path => match self.path {
                PathPolicy::Full => "full",
                PathPolicy::ShapeOnly => "shape-only",
                PathPolicy::Opaque => "opaque",
            },
            Axis::Clock => self.clock.as_str(),
            Axis::SideEffect => self.side_effect.as_str(),
        }
    }

    /// A copy with one axis replaced. The only way to change an axis, so "which
    /// axis is this run using" is always a one-line diff.
    pub fn with(mut self, axis: Axis, value: &str) -> Result<HostPolicy, PolicyError> {
        self.set(axis, value)?;
        Ok(self)
    }

    /// Set one axis from its token. An unknown token is an error, never a
    /// silent fall-through to a default — a policy that silently accepts a typo
    /// is a policy whose declaration does not describe its behaviour.
    pub fn set(&mut self, axis: Axis, value: &str) -> Result<(), PolicyError> {
        let bad = || PolicyError::UnknownValue {
            axis: axis.as_str(),
            value: value.to_string(),
        };
        match axis {
            Axis::Undeclared => self.undeclared = UndeclaredMode::parse(value).ok_or_else(bad)?,
            Axis::Identity => self.identity = IdentityMode::parse(value).ok_or_else(bad)?,
            Axis::Network => self.network = NetworkMode::parse(value).ok_or_else(bad)?,
            Axis::Path => {
                self.path = match value {
                    "full" => PathPolicy::Full,
                    "shape-only" => PathPolicy::ShapeOnly,
                    "opaque" => PathPolicy::Opaque,
                    _ => return Err(bad()),
                }
            }
            Axis::Clock => self.clock = ClockMode::parse(value).ok_or_else(bad)?,
            Axis::SideEffect => self.side_effect = SideEffectMode::parse(value).ok_or_else(bad)?,
        }
        Ok(())
    }

    /// The path policy this declaration carries, for [`crate::hostgen::redact`]
    /// and [`crate::hostgen::egress`] to use.
    pub fn path_policy(&self) -> PathPolicy {
        self.path
    }

    /// Every axis, with its value and the statement that value carries.
    pub fn axis_declarations(&self) -> Vec<(Axis, &'static str, &'static str)> {
        Axis::ALL
            .iter()
            .map(|a| (*a, self.axis(*a), a.statement(self.axis(*a))))
            .collect()
    }

    /// The canonical declaration, as one line: `format=… version=… a=v a=v …`.
    pub fn canonical(&self) -> String {
        let mut s = format!("{POLICY_FORMAT} v{POLICY_VERSION}");
        for a in Axis::ALL {
            s.push(' ');
            s.push_str(a.as_str());
            s.push('=');
            s.push_str(self.axis(a));
        }
        s
    }

    /// An FNV-1a 64 digest over [`Self::canonical`], so two runs can be joined
    /// to "the same policy" without string-diffing prose.
    ///
    /// A checksum for joining. **Explicitly not a security property**, and the
    /// collision behaviour is stated rather than assumed: FNV-1a is not
    /// collision-resistant, and this is used to detect "these two runs used
    /// different axes", never to prove anything to an adversary.
    pub fn digest(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in self.canonical().as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        h
    }

    /// The declaration body a recording carries, including the guarantees that
    /// no axis value can violate.
    pub fn declaration(&self) -> String {
        let mut s = String::new();
        s.push_str("Substrate policy, declared by the host generator.\n");
        s.push_str(&format!("  format:  {POLICY_FORMAT}\n"));
        s.push_str(&format!("  version: {POLICY_VERSION}\n"));
        for (a, v, statement) in self.axis_declarations() {
            s.push_str(&format!(
                "  {a} = {v}\n      governs: {}\n      means: {statement}\n",
                a.governs()
            ));
        }
        s.push_str(
            "  Guarantees, declared by the type and not by this document:\n    \
             - every value of every axis refuses to permit egress\n    \
             - no axis value can create a field that could hold a body, a header value or a \
             query value, because none exists\n    \
             - every fabricated answer is labelled at emission and listed in the run's \
             fabrication ledger\n",
        );
        s
    }

    /// Every reproducible combination, as a flat list.
    ///
    /// 216 values: 3 undeclared × 2 identity × 2 network × 3 path × 3 clock ×
    /// 2 side-effect. A flat list rather than nested loops at the call site,
    /// because a sweep that enumerates its own space cannot silently skip a
    /// combination when an axis gains a value — `tests/egress_denial.rs` asserts
    /// the length, which is what catches that.
    pub fn all_combinations() -> Vec<HostPolicy> {
        let mut out = Vec::with_capacity(216);
        for undeclared in [
            UndeclaredMode::Deny,
            UndeclaredMode::Null,
            UndeclaredMode::RefuseClass,
        ] {
            for identity in [IdentityMode::Declared, IdentityMode::Withheld] {
                for network in [NetworkMode::Deny, NetworkMode::LoopbackSynthetic] {
                    for path in [PathPolicy::Full, PathPolicy::ShapeOnly, PathPolicy::Opaque] {
                        for clock in [ClockMode::Deny, ClockMode::HostReal, ClockMode::Frozen] {
                            for side_effect in [SideEffectMode::Record, SideEffectMode::Deny] {
                                out.push(HostPolicy {
                                    undeclared,
                                    identity,
                                    network,
                                    path,
                                    clock,
                                    side_effect,
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }
}

/// Why a policy declaration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnknownValue { axis: &'static str, value: String },
    /// A token that is not an axis at all.
    UnknownAxis { token: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::UnknownValue { axis, value } => {
                write!(f, "{value:?} is not a value of axis {axis}")
            }
            PolicyError::UnknownAxis { token } => write!(f, "{token:?} is not an axis"),
        }
    }
}

/// Assert the combination count at compile time.
///
/// 216, against the shim's 162. If an axis gains or loses a value this stops
/// compiling, which is the point: the sweep count is a claim about the space,
/// and a claim that drifts silently is worse than one that fails.
const _: () = assert!(AXIS_COMBINATIONS == 216);

/// 3 × 2 × 2 × 3 × 3 × 2.
pub const AXIS_COMBINATIONS: usize = 3 * 2 * 2 * 3 * 3 * 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_combination_count_is_the_claim() {
        assert_eq!(HostPolicy::all_combinations().len(), 216);
        assert_eq!(AXIS_COMBINATIONS, 216);
    }

    #[test]
    fn every_combination_has_a_distinct_canonical_form() {
        // A duplicate canonical form would mean two of the "216" are the same
        // policy counted twice, and the sweep would be quietly smaller.
        let all = HostPolicy::all_combinations();
        let mut seen: Vec<String> = Vec::with_capacity(all.len());
        for p in &all {
            let c = p.canonical();
            assert!(!seen.contains(&c), "duplicate policy declaration: {c}");
            seen.push(c);
        }
    }

    #[test]
    fn an_unknown_axis_value_is_an_error_not_a_default() {
        let mut p = HostPolicy::default();
        assert!(p.set(Axis::Undeclared, "nonsense").is_err());
        // And the failed set left nothing behind.
        assert_eq!(p.undeclared, UndeclaredMode::Deny);
        assert!(p.set(Axis::Path, "shape_only").is_err());
        assert_eq!(p.path, PathPolicy::Full);
    }

    #[test]
    fn every_axis_token_round_trips() {
        let base = HostPolicy::default();
        for a in Axis::ALL {
            let v = base.axis(a);
            let mut p = base;
            assert!(p.set(a, v).is_ok(), "axis {a} token {v:?}");
            assert_eq!(p.axis(a), v);
            assert_ne!(a.statement(v), "axis value not in the registry");
        }
        // An axis that does not exist is reported, not silently ignored.
        assert_eq!(
            Axis::Undeclared.statement("definitely-not-a-value"),
            "axis value not in the registry"
        );
    }

    #[test]
    fn the_default_policy_fabricates_nothing() {
        let d = HostPolicy::default();
        assert_eq!(d.undeclared, UndeclaredMode::Deny);
        assert_eq!(d.identity, IdentityMode::Declared);
        assert_eq!(d.clock, ClockMode::Deny);
        assert_eq!(d.network, NetworkMode::Deny);
    }

    #[test]
    fn the_declaration_names_the_guarantees_it_cannot_violate() {
        let text = HostPolicy::default().declaration();
        assert!(text.contains("every value of every axis refuses to permit egress"));
        assert!(text.contains("fabrication ledger"));
        assert!(text.contains(POLICY_FORMAT));
        for a in Axis::ALL {
            assert!(text.contains(a.as_str()), "{a} missing from the declaration");
        }
    }

    #[test]
    fn the_digest_joins_runs_and_changes_with_an_axis() {
        let a = HostPolicy::default();
        let b = a.with(Axis::Clock, "frozen").unwrap_or(a);
        assert_eq!(a.digest(), a.digest());
        assert_ne!(a.digest(), b.digest());
        assert_ne!(a.digest(), 0);
    }
}
