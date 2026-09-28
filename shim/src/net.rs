//! Egress denial.
//!
//! # There is exactly one network capability and it is a wall
//!
//! The substrate's headline security property — no syscall surface, so no
//! `socket`, no `connect`, no DNS — is also its most common hard failure:
//! `SUB.NET.EGRESS` is the taxonomy's defining REFUSE, and the substrate's
//! "strictly smaller attack surface" is the very thing that makes
//! network-dependent apps unrunnable. Recording that faithfully is more useful
//! than any amount of compatibility work, so the design here is a single
//! terminal that every path must pass through.
//!
//! [`EgressSink::request`] is the only function in the crate that produces a
//! network outcome, and it always produces a failure. There is no other door:
//! no trait an interpreter could implement to reach a socket, no feature flag,
//! no environment variable, no `--allow-egress`. `tests/egress_denial.rs` proves
//! this three ways — a source scan of the whole crate for networking symbols, a
//! live test that opens a real `TcpListener` and shows the shim never connects
//! to it, and a check that the emitted DEX names no transport class.
//!
//! # The error is a value, not an abort
//!
//! `SUB.NET.EGRESS`'s documented symptom is a spinner that never stops, and
//! that is *because* the platform's failure is invisible to the app. So the
//! sink returns a `java.net.ConnectException`-shaped failure, records the
//! attempt, and lets the app's own error handling run. An app that retries in a
//! loop is then visible in the trace as repeated denied attempts, which is a
//! finding; an app that gives up cleanly is equally visible. Neither is the
//! substrate deciding for it.

use crate::error::{EgressDenial, ShimError};
use crate::redact::{HeaderNames, HttpMethod, PathPolicy, RequestMeta};

/// What a caller hands the sink. Deliberately cannot express a body: only a
/// length, because the sink's caller has the bytes and deliberately does not
/// pass them on.
#[derive(Debug, Clone, PartialEq)]
pub struct EgressRequest<'a> {
    pub meta: &'a RequestMeta,
    pub method: HttpMethod,
    pub headers: &'a HeaderNames,
    /// Length of the body the app is about to send, if it has one. `None` means
    /// "no body was obtainable", which the schema keeps distinct from zero.
    pub body_bytes: Option<u64>,
    /// How long the app is willing to wait, in milliseconds. Recorded, because
    /// "the app set a 30 s timeout" is part of the observation and a
    /// synthetic failure that ignored it would misdescribe the app.
    pub timeout_ms: Option<u32>,
}

/// The only network capability in the substrate.
///
/// It holds nothing but its policy, because it must not be possible to
/// configure it into permitting traffic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressSink {
    /// The path policy applied to `RequestMeta::path` when producing the
    /// endpoint string. Set at construction and immutable thereafter.
    pub path_policy: PathPolicy,
    /// Every denial this sink has produced, for the recorder to fold in and for
    /// a test to assert on. The sink keeps its own tally rather than trusting
    /// the recorder, so a recorder bug cannot erase the evidence that a request
    /// happened.
    denials: u64,
}

impl EgressSink {
    /// A sink with the given path policy.
    pub fn new(path_policy: PathPolicy) -> EgressSink {
        EgressSink {
            path_policy,
            denials: 0,
        }
    }

    /// How many attempts this sink has refused.
    pub fn denials(&self) -> u64 {
        self.denials
    }

    /// The only function in the substrate that can be reached by an
    /// `HttpURLConnection`, an `HttpsURLConnection`, a `Socket`, a `DatagramSocket`
    /// or a third-party HTTP library. It always fails.
    pub fn request(&mut self, req: &EgressRequest<'_>) -> Result<Never, EgressDenial> {
        let _ = (
            req.meta,
            req.method,
            req.headers,
            req.body_bytes,
            req.timeout_ms,
        );
        self.denials = self.denials.saturating_add(1);
        Err(EgressDenial::default())
    }

    /// The endpoint string this sink would have reported, under its own policy.
    /// Exposed so a caller can log an attempt without constructing a request.
    pub fn endpoint_for(&self, meta: &RequestMeta) -> String {
        meta.endpoint(self.path_policy)
    }
}

/// The uninhabited success type. `EgressSink::request` returns
/// `Result<Never, EgressDenial>`, so there is no value an unwrap could produce
/// and no way for a caller to treat a successful network operation as
/// reachable. `Never` is uninhabited by construction, which is the strongest
/// statement the type system can make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Never {}

impl EgressSink {
    /// The shim-level error a denied request surfaces as, for the dispatcher's
    /// convenience. Equivalent to `Err(EgressDenial)` wrapped in the crate's
    /// error enum, provided so callers do not have to import two types.
    pub fn refuse(&mut self, req: &EgressRequest<'_>) -> ShimError {
        match self.request(req) {
            Ok(v) => match v {},
            Err(d) => ShimError::EgressDenied(d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_is_denied() {
        let meta = RequestMeta::parse("https://api.example.invalid/v1/sync?k=v").unwrap();
        let headers = HeaderNames::new();
        let mut sink = EgressSink::new(PathPolicy::Full);
        for _ in 0..5 {
            let req = EgressRequest {
                meta: &meta,
                method: HttpMethod::Post,
                headers: &headers,
                body_bytes: Some(1024),
                timeout_ms: Some(30_000),
            };
            assert!(sink.request(&req).is_err());
        }
        assert_eq!(sink.denials(), 5);
    }

    #[test]
    fn the_endpoint_string_has_no_query() {
        let meta = RequestMeta::parse("https://api.example.invalid/v1/sync?k=v#f").unwrap();
        let sink = EgressSink::new(PathPolicy::Full);
        assert_eq!(
            sink.endpoint_for(&meta),
            "https://api.example.invalid:443/v1/sync"
        );
    }
}
