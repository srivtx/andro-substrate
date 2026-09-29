//! Egress denial, ported from `shim/src/net.rs` and made *tighter*, because the
//! generated host has more doors than the hand-written one did.
//!
//! # There is exactly one network capability and it is a wall
//!
//! `SUB.NET.EGRESS` is the taxonomy's defining `REFUSE` and also the substrate's
//! strongest security property. Recording it faithfully is more useful than any
//! amount of compatibility work, so the design is a single terminal every path
//! must pass through.
//!
//! [`EgressSink::request`] is the only function in `hostgen` that produces a
//! network outcome, and it always produces a failure. There is no other door: no
//! trait an interpreter could implement to reach a socket, no feature flag, no
//! environment variable, no policy value that permits traffic. `tests/
//! egress_denial.rs` proves this three ways — a source scan of the whole module
//! for networking symbols, a live test that opens a real `TcpListener` and shows
//! no combination of policy values connects to it, and a check that no emitted
//! host entry names a transport class.
//!
//! # Why `Never` and not `Result<(), E>`
//!
//! `EgressSink::request` returns `Result<Never, EgressDenial>`.
//!
//! `Never` is uninhabited, so there is no success value an `unwrap` could
//! produce, no branch that could treat a completed request as reachable, and no
//! `Default`, `new`, or `from` to build one. The strongest statement the type
//! system can make about a capability that does not exist. The shim already
//! worked this out; it is ported rather than reinvented.
//!
//! # Why the generated host needs *more* care than the shim
//!
//! The shim declares four networking classes and the app reaches the sink
//! through them, so a chokepoint at those four is sufficient — and even then
//! `Socket` has to be present, or `HttpURLConnection` is evadable.
//!
//! A generated host is different: it emits an entry for **every networking method
//! in the closure**, which for a real app is tens of distinct entry points
//! across `java.net`, `javax.net.ssl`, `android.net`, `org.apache.http`,
//! `okhttp3`, `java.rmi`, `javax.naming` and whatever else the app pulled in. Each
//! of those entries is a route to the same sink, and the failure mode of
//! getting one wrong is not a compile error — it is an entry with no sink
//! behind it, which at runtime is a silent no-op, which is precisely the
//! [`SUB.NET.EGRESS`] symptom ("an empty screen or a spinner that never stops").
//!
//! So [`SideEffectClass::Egress`] is a *classification on the emitted entry*, and
//! [`crate::hostgen::synth`] makes it structural: an entry classified as egress
//! is required to be denied, and [`crate::hostgen::emit`] refuses to emit a host
//! module in which an egress-classified entry is anything other than a denial.
//! `tests/egress_denial.rs` checks that over a real closure.
//!
//! # The error is a value, not an abort
//!
//! `SUB.NET.EGRESS`'s documented symptom is a spinner that never stops, and
//! that is *because* the platform's failure is invisible to the app. So the sink
//! returns a `java.net`-shaped failure, records the attempt, and lets the app's
//! own error handling run. An app that retries in a loop is then visible as
//! repeated denied attempts, which is a finding. An app that gives up cleanly is
//! equally visible. Neither is the substrate deciding for it.

use core::fmt;

use crate::hostgen::policy::HostPolicy;
use crate::hostgen::redact::{HeaderNames, HttpMethod, PathPolicy, RequestMeta, Scheme};

/// The uninhabited success type.
///
/// [`EgressSink::request`] returns `Result<Never, EgressDenial>`, so there is no
/// value an `unwrap` could produce and no way for a caller to treat a successful
/// network operation as reachable. `Never` is uninhabited *by construction*,
/// which is a stronger statement than a flag that happens to be set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Never {}

/// Why a request was denied. Always present; never absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDenial {
    /// The endpoint, under the sink's own path policy. Never carries a query.
    pub endpoint: String,
    pub method: HttpMethod,
    pub scheme: Scheme,
    /// Header *names* only, per [`HeaderNames`]. No values.
    pub header_names: Vec<String>,
    pub sensitive_headers_present: bool,
    /// Length of the body the app was about to send, if it had one. `None`
    /// means "no body was obtainable", which a zero-length body is not.
    pub body_bytes: Option<u64>,
    /// How long the app was willing to wait. Recorded because "the app set a
    /// 30 s timeout" is part of the observation, and a synthetic failure that
    /// ignored it would misdescribe the app.
    pub timeout_ms: Option<u32>,
    /// How many times this sink has denied, including this one.
    pub attempt_ordinal: u64,
}

impl fmt::Display for EgressDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} denied (attempt #{}): {}",
            self.method.as_str(),
            self.attempt_ordinal,
            self.endpoint
        )
    }
}

/// What a caller hands the sink.
///
/// Deliberately cannot express a body: only a *length*, because the caller has
/// the bytes and deliberately does not pass them on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressRequest<'a> {
    pub meta: &'a RequestMeta,
    pub method: HttpMethod,
    pub headers: &'a HeaderNames,
    pub body_bytes: Option<u64>,
    pub timeout_ms: Option<u32>,
}

/// How a host method is classified for side effects.
///
/// The point of the classification is that it is attached to the **emitted
/// entry**, so the deny decision is made once at emission and cannot be
/// forgotten at runtime. See [`SideEffectClass::Egress`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideEffectClass {
    /// No observable effect: pure arithmetic, formatting, accessors.
    None,
    /// Reads or writes state the host owns, inside the app's own data scope.
    LocalState,
    /// Touches something that does not exist in the substrate: `/proc`, `/sys`,
    /// sensors, the display, a Binder service.
    Absent,
    /// Would open a socket. Always denied; see the module docs.
    Egress,
    /// Would execute native code, spawn a process, or open a raw device.
    Privileged,
}

/// The result of driving a side-effecting host entry.
///
/// `Permitted` carries no payload, which is deliberate: an allowed side effect
/// is either in-memory or absent, so there is nothing to hand back, and a
/// payload here would be an invitation to put one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SideEffectOutcome {
    /// The effect was performed inside the substrate's own state.
    Permitted,
    /// The effect was refused. Carries the reason, never the argument values.
    Denied(DenialReason),
}

/// Why a side effect was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialReason {
    Egress(EgressDenial),
    /// The capability does not exist in the substrate, and the app is told so.
    Absent {
        /// The `SUB.*` ID this denial predicates, so the refusal is itself a
        /// measurement rather than a shrug.
        taxonomy: crate::hostgen::taxonomy::AssumptionId,
    },
    /// The environment parameter this answer needed was not declared.
    Undeclared,
    /// A path escaped the host root.
    Path(crate::hostgen::path::PathProblem),
    /// The method is `native` and the host has no implementation for it.
    UnsatisfiedLink,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenialReason::Egress(d) => write!(f, "egress denied: {d}"),
            DenialReason::Absent { taxonomy } => {
                write!(f, "capability absent ({taxonomy})")
            }
            DenialReason::Undeclared => {
                f.write_str("no declared value for this environment-dependent answer")
            }
            DenialReason::Path(p) => write!(f, "path refused: {p}"),
            DenialReason::UnsatisfiedLink => f.write_str("no native implementation"),
        }
    }
}

/// The only network capability in the substrate.
///
/// It holds nothing but its policy, because it must not be possible to
/// configure it into permitting traffic. Note what is *absent*: there is no
/// `allow`, no `enabled` flag, no endpoint override, no "deny list" that a
/// default value could accidentally omit an entry from. There is one function
/// and it fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressSink {
    /// The path policy applied when producing the endpoint string. Immutable
    /// after construction, because a mutable redaction policy is a redaction
    /// policy that can be switched off.
    path_policy: PathPolicy,
    /// Every denial this sink has produced, so a recorder bug cannot erase the
    /// evidence that a request happened.
    denials: Vec<EgressDenial>,
}

impl EgressSink {
    /// A sink under a host policy.
    ///
    /// The policy is accepted and its `NetworkMode` recorded, but it cannot
    /// change the outcome. Both values of the axis deny; that is the property
    /// `tests/egress_denial.rs` sweeps over all 216 combinations.
    pub fn new(policy: &HostPolicy) -> EgressSink {
        EgressSink {
            path_policy: policy.path_policy(),
            denials: Vec::new(),
        }
    }

    /// A sink with an explicit path policy.
    pub fn with_path_policy(path_policy: PathPolicy) -> EgressSink {
        EgressSink {
            path_policy,
            denials: Vec::new(),
        }
    }

    /// The path policy in force.
    pub fn path_policy(&self) -> PathPolicy {
        self.path_policy
    }

    /// How many attempts this sink has refused.
    pub fn denials(&self) -> usize {
        self.denials.len()
    }

    /// Every denial, in order.
    pub fn denial_log(&self) -> &[EgressDenial] {
        &self.denials
    }

    /// The endpoint string this sink reports for a request, under its policy.
    pub fn endpoint_for(&self, meta: &RequestMeta) -> String {
        meta.endpoint(self.path_policy)
    }

    /// **The only function in `hostgen` that can be reached by an
    /// `HttpURLConnection`, a `HttpsURLConnection`, a `Socket`, a
    /// `DatagramSocket`, a `WebView.loadUrl`, or a third-party HTTP library. It
    /// always fails, and its success type is uninhabited.**
    pub fn request(&mut self, req: &EgressRequest<'_>) -> Result<Never, EgressDenial> {
        let denial = EgressDenial {
            endpoint: req.meta.endpoint(self.path_policy),
            method: req.method,
            scheme: req.meta.scheme,
            header_names: req.headers.names(),
            sensitive_headers_present: req.headers.has_sensitive(),
            body_bytes: req.body_bytes,
            timeout_ms: req.timeout_ms,
            attempt_ordinal: self.denials.len() as u64 + 1,
        };
        self.denials.push(denial.clone());
        // Constructed rather than returned from a branch, so there is no `Ok`
        // to delete and no way to reach this function's success type.
        Err(denial)
    }

    /// The shim-level refusal, wrapped so a caller need not import two types.
    pub fn refuse(&mut self, req: &EgressRequest<'_>) -> EgressDenial {
        match self.request(req) {
            // `Never` has no values, so this arm is unreachable *by
            // construction* rather than by assertion. If a future edit ever
            // gave `request` a success path, this stops compiling.
            Ok(v) => match v {},
            Err(d) => d,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> RequestMeta {
        match RequestMeta::parse("https://api.example.invalid/v1/sync?k=v#f") {
            Ok(m) => m,
            Err(_) => RequestMeta::parse("https://api.example.invalid/").unwrap_or_else(|_| {
                // Unreachable for a literal that parsed above; kept total so
                // this helper cannot panic on hostile input in a future edit.
                RequestMeta {
                    scheme: Scheme::Https,
                    host: "api.example.invalid".to_string(),
                    port: 443,
                    path: "/".to_string(),
                    query_param_names: Vec::new(),
                    query_present: false,
                    fragment_present: false,
                }
            }),
        }
    }

    #[test]
    fn every_request_is_denied_and_counted() {
        let m = meta();
        let mut headers = HeaderNames::new();
        headers.record("Authorization");
        headers.record("Content-Type");
        let mut sink = EgressSink::with_path_policy(PathPolicy::Full);
        for _ in 0..5 {
            let req = EgressRequest {
                meta: &m,
                method: HttpMethod::Post,
                headers: &headers,
                body_bytes: Some(1024),
                timeout_ms: Some(30_000),
            };
            assert!(sink.request(&req).is_err());
        }
        assert_eq!(sink.denials(), 5);
        // Ordinals are monotone and 1-based, so a recording can be read in order.
        let ordinals: Vec<u64> = sink.denial_log().iter().map(|d| d.attempt_ordinal).collect();
        assert_eq!(ordinals, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn the_denial_carries_names_but_never_values() {
        let m = meta();
        let mut headers = HeaderNames::new();
        headers.record("Authorization");
        headers.record("X-Api-Key");
        let mut sink = EgressSink::with_path_policy(PathPolicy::Full);
        let req = EgressRequest {
            meta: &m,
            method: HttpMethod::Get,
            headers: &headers,
            body_bytes: Some(64),
            timeout_ms: None,
        };
        let d = sink.refuse(&req);
        assert_eq!(d.header_names, vec!["authorization", "x-api-key"]);
        assert!(d.sensitive_headers_present);
        assert_eq!(d.body_bytes, Some(64));
        assert_eq!(d.timeout_ms, None);
        let blob = format!("{d:?}");
        assert!(!blob.contains('?'), "the endpoint carried a query: {blob}");
        assert!(!blob.contains("#f"));
    }

    #[test]
    fn path_policy_only_changes_the_endpoint_rendering() {
        let m = meta();
        for (policy, want) in [
            (PathPolicy::Full, "https://api.example.invalid:443/v1/sync"),
            (PathPolicy::ShapeOnly, "https://api.example.invalid:443/:2/:4"),
            (PathPolicy::Opaque, "https://api.example.invalid:443/2-segments"),
        ] {
            let sink = EgressSink::with_path_policy(policy);
            assert_eq!(sink.endpoint_for(&m), want, "policy {policy:?}");
        }
    }

    #[test]
    fn the_side_effect_classes_are_distinct() {
        // A trivially checkable guard against two arms collapsing into one.
        let all = [
            SideEffectClass::None,
            SideEffectClass::LocalState,
            SideEffectClass::Absent,
            SideEffectClass::Egress,
            SideEffectClass::Privileged,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }
}
