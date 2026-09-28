//! The **substrate policy**: the shim's own behaviour, as a declared parameter.
//!
//! # The problem this module exists to solve
//!
//! A shim terminates every side effect. Once it has, the app's control flow is
//! determined by the *shim*, not by the app. So every fact downstream — an
//! exception, a lifecycle terminal, a `MISBEHAVE` outcome — is a **joint**
//! property of app and substrate, and a recording of one shim with one fixed
//! behaviour does not separate the two. An analyst reading `exceptions[3]` will
//! see "the app threw" when the correct reading is "the app reached a place the
//! shim lacks, and then did whatever it does there".
//!
//! And it gets *worse* the more plausible the shim is. A shim returning obvious
//! nulls fails loudly and is easy to discount. A shim returning plausible
//! `Build.*` and `/proc` values produces recordings that read like measurements
//! of the app and are partly measurements of the shim. Plausibility is what
//! makes the confound invisible, so plausibility is what has to become a
//! variable.
//!
//! Separating "the app does X" from "the app, when X is denied, does Y" needs a
//! substrate *parameter*. The obvious objection is that this crate has no
//! parameters by design: the redaction rule forbids the first kind of knob and
//! the egress rule forbids the second. That objection is correct about *those*
//! two kinds of knob, and this module is careful to contain neither:
//!
//! * **No policy axis can widen a capability.** An axis decides what the shim
//!   *returns*, never what the browser is *permitted to do*. There is no axis
//!   value that opens a socket, a file or a header value, and
//!   `tests/egress_denial.rs` proves the negative two ways — a live
//!   `TcpListener` that no policy value can connect to, and a source scan that
//!   now covers this file.
//! * **No policy axis can widen what is captured.** The redaction invariant is
//!   structural: there is no field in this crate that can hold a body, a header
//!   value or a query-string value. A policy is a set of enums; none of them has
//!   a field that could carry one.
//!
//! What is left — and it turns out to be enough — is a knob over **what the
//! fabricated answer is**, which is precisely the part that was doing the
//! confounding.
//!
//! # The axes
//!
//! Five orthogonal axes, each with a closed set of named values:
//!
//! | axis | values |
//! |---|---|
//! | [`Axis::Identity`] | [`IdentityMode::Fabricated`] · [`IdentityMode::Withheld`] · [`IdentityMode::Refusing`] |
//! | [`Axis::SystemFs`] | [`SystemFsMode::Fabricated`] · [`SystemFsMode::Empty`] · [`SystemFsMode::Absent`] |
//! | [`Axis::CrossAppPackages`] | [`PackageMode::SubjectOnly`] · [`PackageMode::AllPresent`] · [`PackageMode::Error`] |
//! | [`Axis::Network`] | [`NetworkMode::RecordAndDeny`] · [`NetworkMode::SyntheticLoopback`] |
//! | [`Axis::Time`] | [`TimeMode::Virtual`] · [`TimeMode::Scaled`] · [`TimeMode::Frozen`] · [`TimeMode::HostReal`] |
//!
//! Orthogonal in the strong sense: no value of one axis changes any other, and
//! the recording declares each axis's [`governs`](Axis::governs) set so the
//! diff machinery can attribute a moved fact to the axis that moved.
//!
//! # Why the default is the plausible fabricator
//!
//! [`SubstratePolicy::default`] is the pre-existing behaviour, unchanged in every
//! respect, so every existing test keeps its meaning and the committed recording
//! is the same capture with a declaration attached. A *withheld* substrate fails
//! loudly and is easy to discount; a plausible one is the confound, and the
//! confound has to be the default for the other values to be read as
//! counterfactuals rather than as the interesting case.
//!
//! # Versioning, and why there are three numbers
//!
//! A recording has to be interpretable years later by someone who has never read
//! this file, so "what did `identity: fabricated` mean?" must be answerable from
//! the document. Three numbers, each answering a different question:
//!
//! * [`POLICY_FORMAT`] — `"andro-substrate.substrate-policy/1"`. The *shape* of
//!   the serialised declaration. Bumped only when the JSON shape changes
//!   incompatibly. Monotone, never reused.
//! * [`POLICY_VERSION`] — `u16`. The *meaning* of the axis vocabulary: bumped
//!   when a value is added to an axis, removed from one, or redefined. This is
//!   the number that says whether `identity: "fabricated"` carried the semantics
//!   the reader assumes. A shape-compatible redefinition of a value still bumps
//!   it. Monotone, never reused.
//! * `shim_version` — the crate version, because *what a value returns* is a
//!   property of the code, not only of the vocabulary. A recording that says
//!   `identity: "fabricated", shim_version: "0.1.0"` names the exact instrument.
//!
//! Plus [`SubstratePolicy::digest`], a content checksum over the canonical
//! declaration, so two recordings can be joined to "the same policy" without
//! string-diffing prose. It is FNV-1a 64: a checksum for joining, explicitly
//! **not** a security property.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value as J};

use crate::error::ShimError;
use crate::system::{BuildInfo, PropValue};

/// The serialised shape of a policy declaration.
pub const POLICY_FORMAT: &str = "andro-substrate.substrate-policy/1";

/// The *meaning* of the axis vocabulary. See the module docs for what bumps it.
pub const POLICY_VERSION: u16 = 1;

/// How an identity field (`Build.*`, `getprop`, `SystemProperties`) answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMode {
    /// A plausible, self-consistent synthetic device. The default, and the
    /// confound this module exists to make visible.
    ///
    /// The values are fabricated *on purpose*: a substrate reporting obviously
    /// fake values would be trivially detected, every integrity check would
    /// refuse, and the study would measure the refusal instead of the app.
    Fabricated,
    /// No identity is stated. Every field answers `null`, and the `Build` class
    /// still resolves so the app's control flow is not interrupted.
    ///
    /// This is the "fails loudly" arm, and it is useful precisely because it is
    /// easy to discount: an app that gets `null` from `Build.MODEL` takes an
    /// obviously-abnormal branch, and the difference between that branch and the
    /// plausible one is a measurement of *the substrate's plausibility*, not of
    /// the app.
    Withheld,
    /// The identity subsystem is **not provided at all**. `Landroid/os/Build;`
    /// and `Landroid/os/Build$VERSION;` are removed from the shim's class table,
    /// so a field access fails with `NoClassDefFoundError` through the ordinary
    /// classloader path.
    ///
    /// Distinct from [`IdentityMode::Withheld`] in a way that matters: withholding
    /// hands the app a *value* (`null`) to branch on, while refusing removes the
    /// *question's subject*. An app that branches on `Build.SDK_INT` and an app
    /// that crashes before the branch are different behaviours, and only one of
    /// them is a property of the app.
    Refusing,
}

impl IdentityMode {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityMode::Fabricated => "fabricated",
            IdentityMode::Withheld => "withheld",
            IdentityMode::Refusing => "refusing",
        }
    }

    /// Parse the oracle token. `None` for an unknown one, so an unreadable
    /// declaration is an error rather than a silently-defaulted reading.
    pub fn parse(s: &str) -> Option<IdentityMode> {
        Some(match s {
            "fabricated" => IdentityMode::Fabricated,
            "withheld" => IdentityMode::Withheld,
            "refusing" => IdentityMode::Refusing,
            _ => return None,
        })
    }

    /// Whether the shim's class table serves `android.os.Build` at all.
    pub fn serves_build_class(self) -> bool {
        !matches!(self, IdentityMode::Refusing)
    }

    /// The `BuildInfo` the recording's `environment` block reports.
    ///
    /// Note what `Withheld` *cannot* do: `environment.android_release` has
    /// `minLength: 1` and `environment.sdk_int` has `minimum: 1`, so the schema
    /// forces a floor. The withheld arm therefore reports the schema floor
    /// (`"1"` / `1`) and the recording says so in `notes`. **The format makes a
    /// minimum identity claim even when the policy withholds identity** — a
    /// real, if small, instance of the format constraining the measurement, and
    /// the reason the floor is stated rather than left to be discovered.
    pub fn environment_identity(self) -> BuildInfo {
        match self {
            IdentityMode::Fabricated => BuildInfo::default(),
            IdentityMode::Withheld | IdentityMode::Refusing => BuildInfo::withheld(),
        }
    }

    /// The value a read of `prop` returns to the app, given the fabricated
    /// device. The policy is applied *here*, at emission, so no fabricated value
    /// can reach the app without passing through the axis that produced it.
    pub fn read(self, prop: crate::system::Prop, build: &BuildInfo) -> PropValue {
        match self {
            IdentityMode::Fabricated => prop.value(build),
            IdentityMode::Withheld | IdentityMode::Refusing => PropValue::Absent,
        }
    }
}

/// How the fabricated `/proc` and `/sys` trees answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemFsMode {
    /// A plausible, self-consistent synthetic tree. `TracerPid` is 0 and
    /// `/proc/self/maps` is empty: a lie, and a recorded one.
    Fabricated,
    /// Every path the substrate models **exists** and reads as zero bytes. A
    /// distinct third answer, and the reason this axis has three values: "the
    /// file is there and is empty" and "the file is not there" are different
    /// facts, and an app that checks `exists()` before reading gets a different
    /// answer under each.
    Empty,
    /// No path exists. Every read is `ENOENT`, and the attempt is recorded.
    Absent,
}

impl SystemFsMode {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            SystemFsMode::Fabricated => "fabricated",
            SystemFsMode::Empty => "empty",
            SystemFsMode::Absent => "absent",
        }
    }

    /// Parse the oracle token.
    pub fn parse(s: &str) -> Option<SystemFsMode> {
        Some(match s {
            "fabricated" => SystemFsMode::Fabricated,
            "empty" => SystemFsMode::Empty,
            "absent" => SystemFsMode::Absent,
            _ => return None,
        })
    }

    /// Whether a modelled path exists at all.
    pub fn path_exists(self) -> bool {
        !matches!(self, SystemFsMode::Absent)
    }

    /// The contents a modelled path returns. `None` means the read is `ENOENT`.
    pub fn contents(self, modelled: &'static str) -> Option<&'static str> {
        match self {
            SystemFsMode::Fabricated => Some(modelled),
            SystemFsMode::Empty => Some(""),
            SystemFsMode::Absent => None,
        }
    }
}

/// How a `PackageManager` query about **another** app answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageMode {
    /// The substrate holds exactly one app, so every cross-app query answers
    /// "not installed" with no error. The pre-existing behaviour.
    SubjectOnly,
    /// Every package is reported installed.
    ///
    /// The list-valued queries return a non-empty list whose **contents are not
    /// materialised**, because the substrate holds one app and knows nothing
    /// about the others. That is not a shortcut; it is the honest shape of the
    /// answer, and it is declared per-probe. An app that iterates a share-target
    /// list gets an object it cannot meaningfully inspect, which is a *third*
    /// outcome distinct from both empty and error.
    AllPresent,
    /// Every cross-app query throws `NameNotFoundException`.
    ///
    /// The loud arm. An app that handles the exception behaves observably
    /// differently from one that silently finds nothing, and the difference is
    /// the measurement.
    Error,
}

impl PackageMode {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            PackageMode::SubjectOnly => "subject_only",
            PackageMode::AllPresent => "all_present",
            PackageMode::Error => "error",
        }
    }

    /// Parse the oracle token.
    pub fn parse(s: &str) -> Option<PackageMode> {
        Some(match s {
            "subject_only" => PackageMode::SubjectOnly,
            "all_present" => PackageMode::AllPresent,
            "error" => PackageMode::Error,
            _ => return None,
        })
    }

    /// Whether a cross-app `getPackageInfo` returns a `PackageInfo`.
    pub fn cross_app_installed(self) -> bool {
        matches!(self, PackageMode::AllPresent)
    }

    /// Whether a cross-app `getPackageInfo` throws instead of answering.
    pub fn cross_app_throws(self) -> bool {
        matches!(self, PackageMode::Error)
    }
}

/// What the substrate presents to the app when a request reaches the sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Record the attempt, refuse it, and show the app the sink's
    /// `ConnectException`. The pre-existing behaviour, and the only one a
    /// substrate with no network can honestly do.
    RecordAndDeny,
    /// Record the attempt, refuse it — identically, at the same sink, with the
    /// same `denials` tally — and *present* a response the policy declares.
    ///
    /// The refusal is not weakened. `EgressSink::request` still returns
    /// `Err(EgressDenial)` on this path, and the recording's `network` block
    /// still says `egress_available: false` with `tx_bytes`/`rx_bytes` of zero.
    /// What the policy changes is the *presentation*: `getResponseCode()` returns
    /// a declared status instead of throwing, and `getInputStream()` returns a
    /// handle onto a declared-length zero-filled buffer.
    ///
    /// This is the arm that exposes the central confound most sharply. An app
    /// that gets a 200 takes a success branch, and the exception, the retry
    /// loop or the offline banner that a denied substrate would have produced
    /// never happens. Those are *joint* facts, and under this policy the shim
    /// can show exactly how much of the app's behaviour was its own.
    SyntheticLoopback,
}

impl NetworkMode {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkMode::RecordAndDeny => "record_and_deny",
            NetworkMode::SyntheticLoopback => "synthetic_loopback",
        }
    }

    /// Parse the oracle token.
    pub fn parse(s: &str) -> Option<NetworkMode> {
        Some(match s {
            "record_and_deny" => NetworkMode::RecordAndDeny,
            "synthetic_loopback" => NetworkMode::SyntheticLoopback,
            _ => return None,
        })
    }

    /// The response the loopback arm declares. No status, no body, no header
    /// value can vary: everything is a constant of the policy, which is what
    /// makes the resulting recording interpretable and the diff attributable.
    pub fn loopback_response(self) -> Option<LoopbackResponse> {
        match self {
            NetworkMode::RecordAndDeny => None,
            NetworkMode::SyntheticLoopback => Some(LoopbackResponse::default()),
        }
    }
}

/// The response the loopback arm shows the app.
///
/// A status, a declared length and a content type. **No bytes.** There is no
/// field here an interpreter could fill with a body, which is the same
/// structural argument the redaction layer makes, applied to the fabrication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoopbackResponse {
    /// The HTTP status the app sees from `getResponseCode()`.
    pub status: u16,
    /// The length the response declares, and the length of the zero-filled
    /// buffer `getInputStream()` hands over. Declared, never stored.
    pub declared_body_bytes: u64,
    /// The content type handed back, for an app that branches on it.
    pub content_type: &'static str,
}

impl Default for LoopbackResponse {
    /// A 200 with an empty body.
    ///
    /// 200 and not 204, and not a body: an app that *succeeds* is the case worth
    /// measuring, and a body the app can parse is a second fabrication whose
    /// contents the shim would have to invent. An empty 200 is the smallest
    /// presentation that changes the app's control flow.
    fn default() -> LoopbackResponse {
        LoopbackResponse {
            status: 200,
            declared_body_bytes: 0,
            content_type: "application/octet-stream",
        }
    }
}

/// How the substrate's clock answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode", content = "args")]
pub enum TimeMode {
    /// The virtual clock, driven by the recorded schedule and advanced only by
    /// the interpreter. The pre-existing behaviour, and the only one that makes
    /// a recording exactly reproducible.
    Virtual,
    /// The virtual clock multiplied by a declared rational. Deterministic and
    /// reproducible, and it changes what an app's *derived* timings look like:
    /// a retry backoff, a `Thread.sleep` and a deadline all scale.
    Scaled {
        /// Numerator.
        numerator: u64,
        /// Denominator. Never zero; a zero denominator is refused at
        /// construction rather than silently treated as 1.
        denominator: u64,
    },
    /// The clock does not advance as far as the app is concerned. `elapsedRealtime`
    /// and `currentTimeMillis` are both 0 forever.
    ///
    /// The pathological arm, and it is worth having: a frozen clock makes every
    /// timeout-based branch take the "no time has passed" path, which is a
    /// behaviour no real app can exhibit and therefore one whose appearance in a
    /// recording is diagnostic of the substrate.
    Frozen,
    /// The host's real wall clock and the host's real elapsed time.
    ///
    /// **Not reproducible**, and the declaration says so
    /// ([`TimeMode::reproducible`] is `false`). Present because a substrate that
    /// leaks the host clock is a real and easy mistake, and a study should be
    /// able to *show* what it does rather than argue about it.
    HostReal,
}

impl TimeMode {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            TimeMode::Virtual => "virtual",
            TimeMode::Scaled { .. } => "scaled",
            TimeMode::Frozen => "frozen",
            TimeMode::HostReal => "host_real",
        }
    }

    /// Parse the oracle token, and the scale if there is one. `None` for an
    /// unknown token, and `None` for `scaled` without a usable rational.
    pub fn parse(s: &str, scale: Option<(u64, u64)>) -> Option<TimeMode> {
        Some(match s {
            "virtual" => TimeMode::Virtual,
            "frozen" => TimeMode::Frozen,
            "host_real" => TimeMode::HostReal,
            "scaled" => {
                let (numerator, denominator) = scale?;
                if denominator == 0 {
                    return None;
                }
                TimeMode::Scaled {
                    numerator,
                    denominator,
                }
            }
            _ => return None,
        })
    }

    /// Whether a recording under this value is byte-reproducible.
    pub fn reproducible(self) -> bool {
        !matches!(self, TimeMode::HostReal)
    }

    /// The value `elapsedRealtime` / `uptimeMillis` / `currentThreadTimeMillis`
    /// returns for a virtual time of `virtual_ms`.
    pub fn elapsed(self, virtual_ms: u64, host: HostClock) -> u64 {
        match self {
            TimeMode::Virtual => virtual_ms,
            TimeMode::Scaled {
                numerator,
                denominator,
            } => virtual_ms.saturating_mul(numerator) / denominator.max(1),
            TimeMode::Frozen => 0,
            TimeMode::HostReal => host.elapsed_ms(),
        }
    }

    /// The value `currentTimeMillis` returns.
    ///
    /// The wall clock is a different question from the elapsed clock, so it is a
    /// different function with no scale parameter: scaling a wall clock is
    /// meaningless, and a substrate that leaked the host's wall clock would make
    /// a recording unreproducible *and* import the host's skew into the app. The
    /// substrate's own epoch is therefore 0, and the only value that ever moves
    /// it is [`TimeMode::HostReal`].
    pub fn wall(self, host: HostClock) -> u64 {
        match self {
            TimeMode::HostReal => host.wall_ms(),
            TimeMode::Virtual | TimeMode::Scaled { .. } | TimeMode::Frozen => 0,
        }
    }
}

/// The host clock, sampled once at [`crate::dispatch::Shim`] construction.
///
/// Only [`TimeMode::HostReal`] reads it, and the only cost when no policy uses
/// that value is one `Instant` and one `SystemTime` per `Shim`. There is no
/// `std::fs`, `std::net` or `std::env` here, so the egress and side-channel
/// invariants are unaffected.
#[derive(Debug, Clone, Copy)]
pub struct HostClock {
    /// Monotonic anchor.
    start: Instant,
    /// Wall-clock anchor, in milliseconds since the Unix epoch.
    wall_start_ms: u64,
}

impl HostClock {
    /// Sample the host clock.
    pub fn sample() -> HostClock {
        HostClock {
            start: Instant::now(),
            wall_start_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        }
    }

    /// Milliseconds since this `HostClock` was sampled.
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// The host's wall clock in milliseconds since the Unix epoch.
    pub fn wall_ms(&self) -> u64 {
        self.wall_start_ms.saturating_add(self.elapsed_ms())
    }
}

/// A class of observable fact in a recording.
///
/// The unit of *attribution*: an axis declares which classes it governs, and
/// [`crate::differential`] classifies every JSON pointer that differs between
/// two recordings, so a moved fact is blamed on the axis that moved rather than
/// on the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactClass {
    /// The declaration itself. Expected to differ whenever the policy differs,
    /// and attributable to "the policy", not to any one axis.
    PolicyDeclaration,
    /// `environment.*` identity fields and `environment.properties_observed.*`.
    EnvironmentIdentity,
    /// Diagnostics and probes carrying a `Build.*` / `getprop` / `ro.*` pattern.
    IdentityProbe,
    /// Filesystem accesses under `/proc`, `/sys` or `/dev`, and their probes.
    SystemFs,
    /// Package-manager probes, and the exceptions a package query threw.
    CrossAppPackages,
    /// `network.*`, and the exceptions the network arm produced.
    Network,
    /// The clock, and every `t_mono_ms` the time axis moved.
    Time,
    /// A roll-up the *recorder* derived: `summary.*`,
    /// `capture_quality.signals_obtained`, `classes.total_loaded_count`. A
    /// derived fact is not attributable to an axis, and pretending otherwise
    /// would either raise a false alarm when it moves for a reason its
    /// constituents already explain, or hide a real confound. It is reported in
    /// its own bucket with a pointer to the facts it is made of.
    DerivedRollUp,
    /// Everything else: the app's own behaviour under a fixed script.
    ///
    /// The class that carries the result. If a fact in this class moves between
    /// two recordings of the *same* script under two policies, the harness has
    /// found a confound the policy does not account for, and says so.
    App,
}

impl std::fmt::Display for FactClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FactClass {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            FactClass::PolicyDeclaration => "policy_declaration",
            FactClass::EnvironmentIdentity => "environment_identity",
            FactClass::IdentityProbe => "identity_probe",
            FactClass::SystemFs => "system_fs",
            FactClass::CrossAppPackages => "cross_app_packages",
            FactClass::Network => "network",
            FactClass::Time => "time",
            FactClass::DerivedRollUp => "derived_roll_up",
            FactClass::App => "app",
        }
    }

    /// Parse the oracle token.
    pub fn parse(s: &str) -> Option<FactClass> {
        Some(match s {
            "policy_declaration" => FactClass::PolicyDeclaration,
            "environment_identity" => FactClass::EnvironmentIdentity,
            "identity_probe" => FactClass::IdentityProbe,
            "system_fs" => FactClass::SystemFs,
            "cross_app_packages" => FactClass::CrossAppPackages,
            "network" => FactClass::Network,
            "time" => FactClass::Time,
            "derived_roll_up" => FactClass::DerivedRollUp,
            "app" => FactClass::App,
            _ => return None,
        })
    }

    /// Every class, in declaration order. The axis-declaration list and the
    /// diff report both enumerate over this, so a new class cannot be added
    /// without every consumer seeing it.
    pub fn all() -> [FactClass; 9] {
        [
            FactClass::PolicyDeclaration,
            FactClass::EnvironmentIdentity,
            FactClass::IdentityProbe,
            FactClass::SystemFs,
            FactClass::CrossAppPackages,
            FactClass::Network,
            FactClass::Time,
            FactClass::DerivedRollUp,
            FactClass::App,
        ]
    }
}

/// One of the five orthogonal axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Axis {
    /// Identity and attestation values.
    Identity,
    /// Fabricated filesystem reads under `/proc`, `/sys` and `/dev`.
    SystemFs,
    /// Cross-app `PackageManager` queries.
    CrossAppPackages,
    /// Network.
    Network,
    /// Timing.
    Time,
}

impl std::fmt::Display for Axis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Axis {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            Axis::Identity => "identity",
            Axis::SystemFs => "system_fs",
            Axis::CrossAppPackages => "cross_app_packages",
            Axis::Network => "network",
            Axis::Time => "time",
        }
    }

    /// Parse the oracle token.
    pub fn parse(s: &str) -> Option<Axis> {
        Some(match s {
            "identity" => Axis::Identity,
            "system_fs" => Axis::SystemFs,
            "cross_app_packages" => Axis::CrossAppPackages,
            "network" => Axis::Network,
            "time" => Axis::Time,
            _ => return None,
        })
    }

    /// Every axis, in declaration order.
    pub fn all() -> [Axis; 5] {
        [
            Axis::Identity,
            Axis::SystemFs,
            Axis::CrossAppPackages,
            Axis::Network,
            Axis::Time,
        ]
    }

    /// The fact classes this axis governs.
    ///
    /// This is the whole attribution mechanism, and it is a *declaration*, not a
    /// runtime lookup: the diff reads it out of each recording, so a fact can be
    /// blamed on an axis without the analyst consulting the shim's source. An
    /// axis that moved but whose governed classes did not is a policy with no
    /// observable effect on that run, and the diff report says so — which is
    /// itself a result worth having.
    pub fn governs(self) -> &'static [FactClass] {
        match self {
            Axis::Identity => &[FactClass::EnvironmentIdentity, FactClass::IdentityProbe],
            Axis::SystemFs => &[FactClass::SystemFs],
            Axis::CrossAppPackages => &[FactClass::CrossAppPackages],
            Axis::Network => &[FactClass::Network],
            Axis::Time => &[FactClass::Time],
        }
    }

    /// The fact class a taxonomy assumption's facts belong to, if any.
    ///
    /// The second half of the attribution mechanism, and the reason the diff
    /// survives a schema change: `substrate_probe_hits[].assumption_id` is a
    /// stable taxonomy token, so a roll-up keyed on it can be attributed without
    /// the classifier knowing anything about where it sits in the document.
    pub fn governs_assumption(self, id: crate::taxonomy::AssumptionId) -> Option<FactClass> {
        use crate::taxonomy::{AssumptionId as A, Family as F};
        let cls = match id.family() {
            // `SUB.BUILD.*` is the identity axis, and so is `SUB.TRUST.DEBUG_DETECT`:
            // reading `/proc/self/status` for a `TracerPid` is an identity claim in
            // everything but name, and the taxonomy's own families are a partition
            // of the *platform*, not of the substrate's knobs.
            F::Build => FactClass::IdentityProbe,
            F::Trust | F::Kernel => FactClass::SystemFs,
            F::Net => FactClass::Network,
            F::Time => FactClass::Time,
            F::Ipc => {
                return if matches!(id, A::IpcPackageManagerSelf) {
                    // A self-query is not a cross-app query; the axis is not
                    // allowed to reach it and the classifier must not let it.
                    None
                } else {
                    Some(FactClass::CrossAppPackages)
                };
            }
            _ => return None,
        };
        Some(cls)
    }

    /// The human-readable statement of what this axis's value does, recorded
    /// beside the value so a reader does not have to know the crate.
    pub fn statement(self, value: &str) -> String {
        match (self, value) {
            (Axis::Identity, "fabricated") => format!(
                "Build.* and getprop answer a plausible, self-consistent synthetic device \
                 (fingerprint '{f}', model '{m}', SDK {sdk}). ro.kernel.qemu is ABSENT and \
                 ro.debuggable is 0, both fixed by this value and by no other axis.",
                f = BuildInfo::default().fingerprint,
                m = BuildInfo::default().model,
                sdk = BuildInfo::default().sdk_int,
            ),
            (Axis::Identity, "withheld") => {
                "Build.* and getprop answer null/absent. android.os.Build still resolves, so the \
                 app's control flow is not interrupted; it is handed a value to branch on. The \
                 recording's environment block is forced by the schema to a floor of release \"1\" \
                 and SDK 1, which is a claim the policy did not make."
                    .to_string()
            }
            (Axis::Identity, "refusing") => {
                "android.os.Build and android.os.Build$VERSION are absent from the shim's class \
                 table, so a field access fails with NoClassDefFoundError through the ordinary \
                 classloader path. No value is handed to the app at all."
                    .to_string()
            }
            (Axis::SystemFs, "fabricated") => format!(
                "The fabricated tree holds {} paths with plausible contents. TracerPid is 0 and \
                 /proc/self/maps is empty, which is a recorded lie.",
                crate::system::SystemTree::default().paths().len()
            ),
            (Axis::SystemFs, "empty") => format!(
                "The same {} paths exist and every one reads as zero bytes. exists() is true and \
                 the content is empty: a third answer, distinct from both plausible content and \
                 ENOENT.",
                crate::system::SystemTree::default().paths().len()
            ),
            (Axis::SystemFs, "absent") => {
                "No path exists. Every /proc, /sys and /dev read is ENOENT and every attempt is \
                 recorded. An app that stats before it reads gets a different answer from one \
                 that does not."
                    .to_string()
            }
            (Axis::CrossAppPackages, "subject_only") => {
                "The substrate holds exactly one app, so every cross-app query answers 'not \
                 installed' with no exception and an app's inter-app feature is silently gone."
                    .to_string()
            }
            (Axis::CrossAppPackages, "all_present") => {
                "Every package is reported installed. getPackageInfo returns a PackageInfo; \
                 getInstalledPackages and queryIntentActivities return a non-empty list whose \
                 contents are NOT materialised, because the substrate knows nothing about the \
                 other apps. A non-empty list the app cannot inspect is a third outcome, not a \
                 success."
                    .to_string()
            }
            (Axis::CrossAppPackages, "error") => {
                "Every cross-app query throws NameNotFoundException. The loud arm: an app that \
                 handles the exception is observably different from one that silently finds \
                 nothing, and the difference is the measurement."
                    .to_string()
            }
            (Axis::Network, "record_and_deny") => {
                "Every attempt is recorded at the egress sink and refused with ConnectException. \
                 No socket, no DNS, no packet; structurally, for every policy."
                    .to_string()
            }
            (Axis::Network, "synthetic_loopback") => {
                "Every attempt is recorded at the egress sink and refused exactly as under \
                 record_and_deny, with the same denial tally; what changes is the PRESENTATION. \
                 getResponseCode() returns 200 and getInputStream() returns a handle onto a \
                 zero-length declared buffer. egress_available stays false and tx_bytes and \
                 rx_bytes stay 0, because no packet exists."
                    .to_string()
            }
            (Axis::Time, "virtual") => {
                "The virtual clock: elapsedRealtime is the recorded schedule's time and \
                 currentTimeMillis is 0. Exactly reproducible."
                    .to_string()
            }
            (Axis::Time, "scaled") => {
                "The virtual clock multiplied by a declared rational. Deterministic and \
                 reproducible; a retry backoff, a Thread.sleep and a deadline all scale with it."
                    .to_string()
            }
            (Axis::Time, "frozen") => {
                "The clock never advances as far as the app is concerned: elapsedRealtime and \
                 currentTimeMillis are 0 forever, so every timeout-based branch takes the 'no \
                 time has passed' path. A behaviour no real app can exhibit, which is what makes \
                 it diagnostic of the substrate."
                    .to_string()
            }
            (Axis::Time, "host_real") => {
                "The host's real wall clock and real elapsed time. NOT REPRODUCIBLE, and the \
                 declaration says so. Present so that a study can show what a substrate leaking \
                 the host clock does rather than argue about it."
                    .to_string()
            }
            (a, v) => format!("axis {} = {} (no statement recorded)", a.as_str(), v),
        }
    }
}

/// The whole substrate's declared behaviour.
///
/// Every value the shim fabricates is produced by this type, and every recording
/// that a shim produced carries a serialisation of it. That is the whole
/// design: the confound becomes a measured variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstratePolicy {
    /// How identity and attestation values answer.
    pub identity: IdentityMode,
    /// How the fabricated filesystem answers.
    pub system_fs: SystemFsMode,
    /// How cross-app `PackageManager` queries answer.
    pub cross_app_packages: PackageMode,
    /// What the substrate presents at the egress sink.
    pub network: NetworkMode,
    /// How the clock answers.
    pub time: TimeMode,
}

impl Default for SubstratePolicy {
    /// The pre-existing behaviour, in every respect, on every axis.
    ///
    /// Chosen because it is the *confound*. A family whose default is the
    /// obvious null-returning substrate would make the interesting value look
    /// like a curiosity, and every comparison would be against a baseline no
    /// real study would use.
    fn default() -> SubstratePolicy {
        SubstratePolicy {
            identity: IdentityMode::Fabricated,
            system_fs: SystemFsMode::Fabricated,
            cross_app_packages: PackageMode::SubjectOnly,
            network: NetworkMode::RecordAndDeny,
            time: TimeMode::Virtual,
        }
    }
}

impl SubstratePolicy {
    /// The value of one axis.
    pub fn axis(&self, axis: Axis) -> &'static str {
        match axis {
            Axis::Identity => self.identity.as_str(),
            Axis::SystemFs => self.system_fs.as_str(),
            Axis::CrossAppPackages => self.cross_app_packages.as_str(),
            Axis::Network => self.network.as_str(),
            Axis::Time => self.time.as_str(),
        }
    }

    /// The host clock this policy reads under [`TimeMode::HostReal`].
    pub fn host_clock(&self) -> Option<HostClock> {
        match self.time {
            TimeMode::HostReal => Some(HostClock::sample()),
            _ => None,
        }
    }

    /// Whether a recording under this policy is byte-reproducible.
    pub fn reproducible(&self) -> bool {
        self.time.reproducible()
    }

    /// A copy with one axis replaced. The only way to change an axis, so that
    /// "which axis is this run using" is always a one-line diff.
    pub fn with(mut self, axis: Axis, value: &str) -> Result<SubstratePolicy, ShimError> {
        self.set(axis, value)?;
        Ok(self)
    }

    /// Set one axis from its oracle token. An unknown token is an error, never a
    /// silent no-op: a policy that could not be read must not be run.
    pub fn set(&mut self, axis: Axis, value: &str) -> Result<(), ShimError> {
        match axis {
            Axis::Identity => {
                self.identity = IdentityMode::parse(value).ok_or_else(|| bad(axis, value))?
            }
            Axis::SystemFs => {
                self.system_fs = SystemFsMode::parse(value).ok_or_else(|| bad(axis, value))?
            }
            Axis::CrossAppPackages => {
                self.cross_app_packages =
                    PackageMode::parse(value).ok_or_else(|| bad(axis, value))?
            }
            Axis::Network => {
                self.network = NetworkMode::parse(value).ok_or_else(|| bad(axis, value))?
            }
            Axis::Time => {
                // A scale may accompany the token; absent means 1:1, which is
                // `Virtual`'s behaviour, so `scaled` without a scale is an error
                // rather than a silent `Virtual`.
                let scale = if value == "scaled" {
                    Some((1, 1))
                } else {
                    None
                };
                self.time = TimeMode::parse(value, scale).ok_or_else(|| bad(axis, value))?;
            }
        }
        Ok(())
    }

    /// The declaration body: every axis, its value, the classes it governs, and
    /// a statement of what the value does. This is what a recording embeds, and
    /// it is deliberately self-describing — a reader with the document and no
    /// access to this crate can still say what the substrate did.
    pub fn axis_declarations(&self) -> Vec<J> {
        Axis::all()
            .into_iter()
            .map(|a| {
                json!({
                    "axis": a.as_str(),
                    "value": self.axis(a),
                    "governs": a.governs().iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    "statement": a.statement(self.axis(a)),
                })
            })
            .collect()
    }

    /// The canonical declaration, without the digest. Stable field order, so
    /// the digest is a function of the *content* and not of a serialiser's mood.
    pub fn canonical(&self) -> J {
        json!({
            "policy_format": POLICY_FORMAT,
            "policy_version": POLICY_VERSION,
            "shim_version": crate::VERSION,
            "reproducible": self.reproducible(),
            "identity": self.identity.as_str(),
            "system_fs": self.system_fs.as_str(),
            "cross_app_packages": self.cross_app_packages.as_str(),
            "network": self.network.as_str(),
            "time": self.time,
            "axis_declarations": self.axis_declarations(),
            "invariants": {
                "egress": "structurally_impossible",
                "bodies_captured": false,
                "header_values_captured": false,
                "query_values_captured": false,
                "note": "Declared by the policy type, not by this document: no axis value can \
                         widen a capability or a capture surface. EgressSink::request returns \
                         Err on every axis, there is no std::fs or std::net surface in the crate, \
                         and no field in it can hold a body, a header value or a query value."
            },
            "notes": format!(
                "Every value the shim fabricated during this run was produced by one of the five \
                 axes declared above, and every such value is labelled at emission with the axis \
                 that produced it. A fact in this document that is NOT in a governed class was \
                 not decided by the substrate. A fact that IS in a governed class is a joint \
                 property of the app and this declaration, and the two arms of the differential \
                 in shim/recordings/ are what separate them. policy_version is {} and the axis \
                 vocabulary is defined in docs/decisions/0006-substrate-policy.md.",
                POLICY_VERSION
            )
        })
    }

    /// A content checksum over the canonical declaration, for joining two
    /// recordings to "the same policy" without string-diffing prose.
    ///
    /// FNV-1a 64. **Not** a security property and not a digest in the crypto
    /// sense; it is a join key. Its virtue is that it is eight lines long and
    /// adds no dependency to a crate whose dependency list is itself an
    /// invariant.
    pub fn digest(&self) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let body = self.canonical().to_string();
        for b in body.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("fnv1a64:{h:016x}")
    }

    /// The full serialised declaration, digest included.
    pub fn to_json(&self) -> J {
        let mut v = self.canonical();
        if let J::Object(o) = &mut v {
            // Right after `shim_version`, so a human reading the raw JSON sees
            // the three version numbers together.
            let mut out = serde_json::Map::new();
            for (k, val) in o.iter() {
                out.insert(k.clone(), val.clone());
                if k == "shim_version" {
                    out.insert("policy_digest".to_string(), J::String(self.digest()));
                }
            }
            *o = out;
        }
        v
    }

    /// Read a declaration back. Round-tripping is a tested property, because a
    /// policy that cannot be re-read is not a machine-readable declaration.
    pub fn from_json(v: &J) -> Result<SubstratePolicy, ShimError> {
        let format = v
            .get("policy_format")
            .and_then(J::as_str)
            .ok_or_else(|| ShimError::Encode("policy: no policy_format".into()))?;
        if format != POLICY_FORMAT {
            return Err(ShimError::Encode(format!(
                "policy: this build reads {format} and the document says {POLICY_FORMAT}"
            )));
        }
        let version = v
            .get("policy_version")
            .and_then(J::as_u64)
            .ok_or_else(|| ShimError::Encode("policy: no policy_version".into()))?;
        if version != u64::from(POLICY_VERSION) {
            return Err(ShimError::Encode(format!(
                "policy: the document declares axis vocabulary version {version}; this build \
                 understands {POLICY_VERSION}. The values may not mean the same thing."
            )));
        }
        let field = |k: &str| -> Result<&str, ShimError> {
            v.get(k)
                .and_then(J::as_str)
                .ok_or_else(|| ShimError::Encode(format!("policy: no `{k}`")))
        };
        let mut p = SubstratePolicy::default();
        p.set(Axis::Identity, field("identity")?)?;
        p.set(Axis::SystemFs, field("system_fs")?)?;
        p.set(Axis::CrossAppPackages, field("cross_app_packages")?)?;
        p.set(Axis::Network, field("network")?)?;
        let time = v
            .get("time")
            .ok_or_else(|| ShimError::Encode("policy: no `time`".into()))?;
        let scale = time.get("args").and_then(|a| {
            Some((
                a.get("numerator")?.as_u64()?,
                a.get("denominator")?.as_u64()?,
            ))
        });
        p.set(
            Axis::Time,
            time.get("mode")
                .and_then(J::as_str)
                .ok_or_else(|| ShimError::Encode("policy: no `time.mode`".into()))?,
        )?;
        p.time = TimeMode::parse(
            time.get("mode").and_then(J::as_str).unwrap_or(""),
            if scale.is_some() { scale } else { None },
        )
        .ok_or_else(|| ShimError::Encode(format!("policy: unreadable time value {time}")))?;
        // The digest is recomputed rather than trusted: a declaration whose
        // digest does not match its content is a corrupted document and must not
        // be run.
        if let Some(d) = v.get("policy_digest").and_then(J::as_str) {
            if d != p.digest() {
                return Err(ShimError::Encode(format!(
                    "policy: digest {d} does not match the declaration's content ({})",
                    p.digest()
                )));
            }
        }
        Ok(p)
    }
}

fn bad(axis: Axis, value: &str) -> ShimError {
    let known: Vec<&str> = match axis {
        Axis::Identity => vec!["fabricated", "withheld", "refusing"],
        Axis::SystemFs => vec!["fabricated", "empty", "absent"],
        Axis::CrossAppPackages => vec!["subject_only", "all_present", "error"],
        Axis::Network => vec!["record_and_deny", "synthetic_loopback"],
        Axis::Time => vec!["virtual", "scaled", "frozen", "host_real"],
    };
    ShimError::Encode(format!(
        "policy: {value:?} is not a value of axis {}; known values are {known:?}",
        axis.as_str()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_pre_existing_behaviour_on_every_axis() {
        let d = SubstratePolicy::default();
        assert_eq!(d.identity, IdentityMode::Fabricated);
        assert_eq!(d.system_fs, SystemFsMode::Fabricated);
        assert_eq!(d.cross_app_packages, PackageMode::SubjectOnly);
        assert_eq!(d.network, NetworkMode::RecordAndDeny);
        assert_eq!(d.time, TimeMode::Virtual);
        assert!(d.reproducible());
    }

    #[test]
    fn the_serialised_form_round_trips() {
        for identity in [
            IdentityMode::Fabricated,
            IdentityMode::Withheld,
            IdentityMode::Refusing,
        ] {
            for system_fs in [
                SystemFsMode::Fabricated,
                SystemFsMode::Empty,
                SystemFsMode::Absent,
            ] {
                for network in [NetworkMode::RecordAndDeny, NetworkMode::SyntheticLoopback] {
                    for time in [
                        TimeMode::Virtual,
                        TimeMode::Scaled {
                            numerator: 7,
                            denominator: 3,
                        },
                        TimeMode::Frozen,
                    ] {
                        let p = SubstratePolicy {
                            identity,
                            system_fs,
                            cross_app_packages: PackageMode::AllPresent,
                            network,
                            time,
                        };
                        let j = p.to_json();
                        let back = SubstratePolicy::from_json(&j).expect("round trip");
                        assert_eq!(back, p);
                        assert_eq!(back.digest(), p.digest());
                    }
                }
            }
        }
    }

    #[test]
    fn a_tampered_declaration_is_refused() {
        let mut j = SubstratePolicy::default().to_json();
        j["identity"] = J::String("withheld".into());
        // The digest no longer describes the content.
        assert!(SubstratePolicy::from_json(&j).is_err());
    }

    #[test]
    fn a_future_axis_version_is_refused_rather_than_guessed_at() {
        let mut j = SubstratePolicy::default().to_json();
        j["policy_version"] = json!(POLICY_VERSION + 1);
        let e = SubstratePolicy::from_json(&j).expect_err("must refuse");
        assert!(format!("{e}").contains("vocabulary version"));
    }

    #[test]
    fn an_unknown_value_is_an_error_and_never_a_silent_default() {
        let mut p = SubstratePolicy::default();
        let e = p.set(Axis::Network, "allow").expect_err("must refuse");
        assert!(format!("{e}").contains("not a value of axis network"));
        assert_eq!(p.network, NetworkMode::RecordAndDeny, "and changes nothing");
    }

    #[test]
    fn every_axis_declares_the_classes_it_governs_and_nothing_overlaps() {
        let mut seen: Vec<FactClass> = Vec::new();
        for a in Axis::all() {
            for c in a.governs() {
                assert!(
                    !seen.contains(c),
                    "{} is governed by two axes, so attribution would be ambiguous",
                    c.as_str()
                );
                seen.push(*c);
            }
        }
        assert!(
            !seen.contains(&FactClass::App),
            "the app class is governed by no axis"
        );
        assert!(!seen.contains(&FactClass::PolicyDeclaration));
        // Every governed class must be attributable to something.
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn every_axis_and_value_pair_has_a_statement() {
        // Only the *legal* combinations, and the point of the test is the
        // fallthrough: `Axis::statement` has a `_` arm for an impossible pairing,
        // and this is what notices when a new value is added without one.
        let legal: [(Axis, &[&str]); 5] = [
            (Axis::Identity, &["fabricated", "withheld", "refusing"]),
            (Axis::SystemFs, &["fabricated", "empty", "absent"]),
            (
                Axis::CrossAppPackages,
                &["subject_only", "all_present", "error"],
            ),
            (Axis::Network, &["record_and_deny", "synthetic_loopback"]),
            (Axis::Time, &["virtual", "scaled", "frozen", "host_real"]),
        ];
        let mut n = 0;
        for (a, values) in legal {
            for v in values {
                n += 1;
                let s = a.statement(v);
                assert!(
                    !s.contains("no statement recorded"),
                    "axis {} value {v} has no statement",
                    a.as_str()
                );
                assert!(!s.is_empty());
            }
        }
        assert_eq!(
            n,
            3 + 3 + 3 + 2 + 4,
            "the axis vocabulary changed; re-check this test"
        );
    }

    #[test]
    fn a_zero_scale_denominator_is_refused() {
        assert!(TimeMode::parse("scaled", Some((1, 0))).is_none());
        assert!(TimeMode::parse("scaled", None).is_none());
        assert_eq!(
            TimeMode::parse("scaled", Some((3, 1))),
            Some(TimeMode::Scaled {
                numerator: 3,
                denominator: 1
            })
        );
    }

    #[test]
    fn the_time_axis_scales_and_freezes_the_clock() {
        let h = HostClock::sample();
        assert_eq!(TimeMode::Virtual.elapsed(500, h), 500);
        assert_eq!(
            TimeMode::Scaled {
                numerator: 3,
                denominator: 2
            }
            .elapsed(500, h),
            750
        );
        assert_eq!(TimeMode::Frozen.elapsed(500, h), 0);
        // The wall clock is a different question and stays pinned except under
        // the host axis.
        assert_eq!(TimeMode::Frozen.wall(h), 0);
        assert!(TimeMode::HostReal.wall(h) > 1_600_000_000_000);
        assert!(!TimeMode::HostReal.reproducible());
    }

    #[test]
    fn the_declared_invariants_contradict_nothing_the_schema_can_see() {
        let j = SubstratePolicy::default().to_json();
        let inv = &j["invariants"];
        assert_eq!(inv["egress"], J::String("structurally_impossible".into()));
        assert_eq!(inv["bodies_captured"], J::Bool(false));
        assert_eq!(inv["header_values_captured"], J::Bool(false));
        assert_eq!(inv["query_values_captured"], J::Bool(false));
        // And the three version numbers are all present and distinct in kind.
        assert_eq!(j["policy_format"], J::String(POLICY_FORMAT.into()));
        assert_eq!(j["policy_version"], json!(POLICY_VERSION));
        assert_eq!(j["shim_version"], J::String(crate::VERSION.into()));
        assert!(j["policy_digest"]
            .as_str()
            .unwrap_or_default()
            .starts_with("fnv1a64:"));
    }

    #[test]
    fn two_policies_that_differ_have_different_digests() {
        let a = SubstratePolicy::default();
        let b = a.with(Axis::Identity, "withheld").expect("valid value");
        assert_ne!(a.digest(), b.digest());
        // And one that does not differ has the same digest, so the join key is
        // not noise.
        assert_eq!(
            a.digest(),
            a.with(Axis::Identity, "fabricated").unwrap().digest()
        );
    }
}
