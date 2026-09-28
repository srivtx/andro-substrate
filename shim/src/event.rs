//! The event model. One struct, six groups, one taxonomy ID per event.
//!
//! # Shape
//!
//! Every observation the shim makes is a [`SubstrateEvent`]. The groups are the
//! oracle's observation groups — `net`, `fs`, `classes`, `jni`, `exceptions`,
//! `probes` — because the whole point of the format is that a substrate capture
//! and a device capture are the same document shape and can be diffed. Adding a
//! substrate-only group would have been easier and would have cost the project
//! its central claim, so the six groups are fixed and the substrate-specific
//! facts go in `notes` and in `assumption`.
//!
//! # `tier`, and why the shim can claim T0 where a phone cannot
//!
//! The oracle defines `T0_DIRECT` as "read directly from a live source with
//! authority — root shell, a debuggable build, or in-process instrumentation".
//! A stock device cannot get there; the substrate's entire reason for existing
//! is that it *is* the process. So the shim records `T0_DIRECT` for everything
//! it observes in its own address space, and the validator's check that a
//! `T0_DIRECT` claim requires `root_shell` or `debuggable` is gated on
//! `synthetic == false` and does not fire. That is not a loophole being
//! exploited: the substrate really does have direct authority, and the honest
//! place to say so is the tier field, not a caveat in a doc comment.
//!
//! What the shim deliberately does *not* claim: it never claims to have observed
//! anything it inferred. Layout arithmetic, for instance, is `T0_DIRECT` for the
//! boxes it computed, because it computed them; the *reasoning* about what a
//! frame budget means is `T3_INFERRED` and lives in `notes`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{EgressDenial, VfsError};
use crate::policy::{Axis, LoopbackResponse};
use crate::redact::{HeaderNames, HttpMethod, PathPolicy, RequestMeta};
use crate::taxonomy::AssumptionId;

/// Oracle `observation_tier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    T0Direct,
    T1Logcat,
    T2Snapshot,
    T3Inferred,
    T4Unobserved,
}

impl Tier {
    /// The oracle token.
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::T0Direct => "T0_DIRECT",
            Tier::T1Logcat => "T1_LOGCAT",
            Tier::T2Snapshot => "T2_SNAPSHOT",
            Tier::T3Inferred => "T3_INFERRED",
            Tier::T4Unobserved => "T4_UNOBSERVED",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Oracle `signal_source`. Only the values a substrate can honestly produce are
/// representable: there is no `logcat` to read and no `adb` to run, and offering
/// them would let a recording lie about its own provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Source {
    /// The substrate's own instrumentation of the process it owns. In the
    /// oracle enum this is `substrate_instrumentation`'s sibling; the schema has
    /// no such token, so a substrate capture uses `synthetic_fixture` when the
    /// document is a fixture and `analyst_annotation` is never appropriate
    /// either. The mapping lives in `crate::recording`.
    SubstrateInstrumentation,
    /// The in-memory VFS.
    Vfs,
    /// A class-resolution decision made by the shim's loader.
    ClassLoader,
    /// The substrate's fabricated system tree (`/proc`, `/sys`).
    SyntheticSysfs,
}

impl Source {
    /// The oracle `signal_source` token.
    ///
    /// `substrate_instrumentation` is not in the schema's `signal_source` enum,
    /// which is a real gap: the oracle was written for a device arm and has no
    /// vocabulary for the substrate arm it is meant to be compared with. The
    /// closest truthful token is `synthetic_fixture` for a fixture and
    /// `unknown` for a live substrate capture, with `clock.monotonic_source =
    /// substrate_instrumentation` and `probes[]` carrying the provenance. This
    /// is reported in the final report as a schema gap rather than fixed by
    /// editing `oracle/`, which is not this agent's to change.
    pub fn oracle_token(self) -> &'static str {
        match self {
            Source::SubstrateInstrumentation
            | Source::Vfs
            | Source::ClassLoader
            | Source::SyntheticSysfs => "synthetic_fixture",
        }
    }
}

/// The six observation groups. These are the oracle's, unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Group {
    Net,
    Fs,
    Classes,
    Jni,
    Exceptions,
    Probes,
}

impl Group {
    pub fn as_str(self) -> &'static str {
        match self {
            Group::Net => "net",
            Group::Fs => "fs",
            Group::Classes => "classes",
            Group::Jni => "jni",
            Group::Exceptions => "exceptions",
            Group::Probes => "probes",
        }
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A file operation, matching the oracle's `fs_access.op` enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOp {
    Open,
    Read,
    Write,
    Stat,
    List,
    Unlink,
    Rename,
    Mkdir,
    Chmod,
    Chown,
    Mmap,
    Truncate,
    Symlink,
    Fsync,
    Access,
}

impl FsOp {
    pub fn as_str(self) -> &'static str {
        match self {
            FsOp::Open => "open",
            FsOp::Read => "read",
            FsOp::Write => "write",
            FsOp::Stat => "stat",
            FsOp::List => "list",
            FsOp::Unlink => "unlink",
            FsOp::Rename => "rename",
            FsOp::Mkdir => "mkdir",
            FsOp::Chmod => "chmod",
            FsOp::Chown => "chown",
            FsOp::Mmap => "mmap",
            FsOp::Truncate => "truncate",
            FsOp::Symlink => "symlink",
            FsOp::Fsync => "fsync",
            FsOp::Access => "access",
        }
    }
}

/// How a class reference resolved. This is the substrate's one unambiguous
/// advantage over a device capture, where the class list is unobtainable
/// without root: the loader knows exactly which dex each class came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution {
    /// Found in the shim's own DEX.
    ShimDex,
    /// Found in one of the app's DEX files.
    AppDex,
    /// Found in both, and the shim won. Recorded separately from `ShimDex`
    /// because "the app defines its own android.app.Activity" is an
    /// anti-tamper signal in its own right and must not be invisible.
    ShimSupersedesApp,
    /// Found nowhere.
    Unresolvable,
    /// A dex file added at runtime, which the shim does not provide.
    DynamicUnavailable,
}

impl Resolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Resolution::ShimDex => "shim_dex",
            Resolution::AppDex => "app_dex",
            Resolution::ShimSupersedesApp => "shim_supersedes_app",
            Resolution::Unresolvable => "unresolvable",
            Resolution::DynamicUnavailable => "dynamic_unavailable",
        }
    }

    /// Whether the shim's own table satisfied the reference.
    pub fn is_served_by_shim(self) -> bool {
        matches!(self, Resolution::ShimDex | Resolution::ShimSupersedesApp)
    }
}

/// What a `native` method attempt resolved to. There is no success case, and
/// the enum has no variant for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NativeOutcome {
    /// No implementation behind the declaration.
    Unsatisfied,
    /// The library was requested but the loader has no ELF at all.
    NoElfLoader,
}

impl NativeOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            NativeOutcome::Unsatisfied => "UNSATISFIED",
            NativeOutcome::NoElfLoader => "UNSATISFIED_NO_ELF_LOADER",
        }
    }
}

/// What the substrate *presented* to the app when a request reached the sink.
///
/// The distinction this type exists for: `Detail::Net::outcome` records what the
/// **sink** did, and it is `Err` on every policy value without exception. This
/// records what the **app** was shown, and a policy may choose to show it a
/// response. Keeping them in two fields is what makes the claim "no policy
/// enables egress" a property of the type rather than of a code review: the
/// loopback arm cannot set `outcome` to `Ok`, because
/// `EgressSink::request` returns `Result<Never, EgressDenial>` and there is no
/// `Never` value to put in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetPresentation {
    /// The app is shown the sink's `ConnectException`. The substrate's default,
    /// and the absence of a fabrication rather than a fabrication of one.
    Denied,
    /// The app is shown a response the `network` policy axis declared. Nothing
    /// was transmitted: see the type's own documentation.
    Loopback(LoopbackResponse),
}

impl NetPresentation {
    /// Whether the app was shown a synthesised response.
    pub fn is_loopback(self) -> bool {
        matches!(self, NetPresentation::Loopback(_))
    }

    /// The declared response, if any.
    pub fn response(self) -> Option<LoopbackResponse> {
        match self {
            NetPresentation::Denied => None,
            NetPresentation::Loopback(r) => Some(r),
        }
    }
}

/// The payload. One variant per group, so a `match` is exhaustive and a new
/// group cannot be added without every consumer handling it.
#[derive(Debug, Clone, PartialEq)]
pub enum Detail {
    /// An outbound request that the egress sink terminated.
    Net {
        meta: RequestMeta,
        method: HttpMethod,
        headers: HeaderNames,
        /// Length only. Never a byte, never a digest: see [`crate::redact`].
        body_bytes: Option<u64>,
        /// What the **sink** did. `Err` for every policy value, always.
        outcome: Result<(), EgressDenial>,
        /// What the **app** was shown. A policy may add a presentation on top of
        /// the refusal; it can never replace it.
        presentation: NetPresentation,
        /// The path as it was recorded, after the policy was applied. Stored so
        /// the event is self-contained and the recording cannot re-apply a
        /// different policy to it later.
        recorded_path: String,
    },
    /// A VFS operation, or a read of the fabricated system tree.
    Fs {
        op: FsOp,
        path: String,
        bytes: u64,
        result: Result<u64, VfsError>,
    },
    /// A class resolution.
    Classes {
        descriptor: String,
        resolution: Resolution,
        /// The app package whose DEX satisfied the reference, when one did.
        from_package: Option<String>,
    },
    /// A `native` call or a `loadLibrary`.
    Jni {
        symbol: String,
        declaring_class: Option<String>,
        library: Option<String>,
        outcome: NativeOutcome,
    },
    /// A throw or a catch.
    Exceptions {
        class: String,
        message: String,
        stack: Vec<String>,
        fatal: bool,
        /// Whether the app caught it.
        caught: Option<bool>,
    },
    /// A read of `Build.*`, `/proc`, `/sys`, or a PackageManager query.
    Probes {
        /// A `SIGNAL_PAT.*` identifier, matching the oracle's diagnostic
        /// pattern shape so the two are diffable.
        pattern: &'static str,
        detail: String,
        /// The substrate-policy axis whose value produced the answer in
        /// `detail`, or `None` when this observation is not a fabricated answer
        /// at all.
        ///
        /// This is the *emission-time label* the whole policy family rests on: a
        /// `Build.FINGERPRINT` read can say which axis answered it, so a reader
        /// never has to infer it from the shape of the value. `None` is the
        /// interesting case rather than an oversight — a class resolution or a
        /// bundle write is the *app's* behaviour and belongs to no axis.
        axis: Option<Axis>,
    },
}

impl Detail {
    /// Which group this payload belongs to.
    pub fn group(&self) -> Group {
        match self {
            Detail::Net { .. } => Group::Net,
            Detail::Fs { .. } => Group::Fs,
            Detail::Classes { .. } => Group::Classes,
            Detail::Jni { .. } => Group::Jni,
            Detail::Exceptions { .. } => Group::Exceptions,
            Detail::Probes { .. } => Group::Probes,
        }
    }
}

/// One observation.
#[derive(Debug, Clone, PartialEq)]
pub struct SubstrateEvent {
    /// Monotonic, gap-free, starting at 0. The join key for every pointer into
    /// a substrate recording.
    pub seq: u64,
    /// Milliseconds since the substrate's virtual `t=0`.
    pub t_mono_ms: u64,
    pub group: Group,
    pub source: Source,
    pub tier: Tier,
    /// The taxonomy ID this observation exercises. `None` only where the
    /// observation is not an assumption probe at all — a class that resolved to
    /// the shim, say, which is the mechanism rather than the assumption.
    pub assumption: Option<AssumptionId>,
    pub detail: Detail,
}

impl SubstrateEvent {
    /// A short human-readable line, for `notes` fields and for test failures.
    pub fn summary(&self) -> String {
        self.detail.summary()
    }
}

impl Detail {
    /// A short human-readable line.
    pub fn summary(&self) -> String {
        match self {
            Detail::Net {
                meta,
                method,
                recorded_path,
                body_bytes,
                outcome,
                presentation,
                ..
            } => {
                let verdict = match outcome {
                    Ok(()) => "ok",
                    Err(d) => d.code,
                };
                format!(
                    "net {} {}://{}:{}{} body={} -> {verdict}{}",
                    method.as_str(),
                    meta.scheme.as_str(),
                    meta.host,
                    meta.port,
                    recorded_path,
                    body_bytes
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "?".into()),
                    match presentation {
                        NetPresentation::Denied => String::new(),
                        NetPresentation::Loopback(r) => format!(
                            "; presented a synthesised {} response ({}) by substrate_policy \
                             axis network, with nothing transmitted",
                            r.status, r.content_type
                        ),
                    }
                )
            }
            Detail::Fs {
                op,
                path,
                bytes,
                result,
            } => format!(
                "fs {} {path} bytes={bytes} -> {}",
                op.as_str(),
                match result {
                    Ok(_) => "ok",
                    Err(e) => e.oracle_result(),
                }
            ),
            Detail::Classes {
                descriptor,
                resolution,
                from_package,
            } => format!(
                "classes {descriptor} -> {}{}",
                resolution.as_str(),
                match from_package {
                    Some(p) => format!(" ({p})"),
                    None => String::new(),
                }
            ),
            Detail::Jni {
                symbol,
                library,
                outcome,
                ..
            } => format!(
                "jni {symbol}{} -> {}",
                match library {
                    Some(l) => format!(" [{l}]"),
                    None => String::new(),
                },
                outcome.as_str()
            ),
            Detail::Exceptions {
                class,
                message,
                fatal,
                caught,
                ..
            } => format!(
                "exceptions {class}: {message} fatal={fatal} caught={}",
                match caught {
                    Some(c) => c.to_string(),
                    None => "?".into(),
                }
            ),
            Detail::Probes {
                pattern,
                detail,
                axis,
                ..
            } => format!("probes {pattern}: {detail}{}", axis_suffix(*axis)),
        }
    }
}

/// The emission-time axis label, appended to a probe's rendered detail.
///
/// A fixed, greppable shape, because a label an analyst has to parse is a label
/// nobody will use: `[answered by substrate_policy axis system_fs = empty]`. The
/// recording's `substrate_policy.axis_declarations` says what that value *does*,
/// so the label here and the declaration there are enough to read any fabricated
/// value years later without the crate.
pub fn axis_suffix(axis: Option<Axis>) -> String {
    match axis {
        None => String::new(),
        Some(a) => format!(" [answered by substrate_policy axis {}]", a.as_str()),
    }
}

/// The same label with the axis's *value* spelled out, for the two places where
/// the value itself is the finding: a read that returned nothing, and an
/// exception the substrate chose to throw.
pub fn axis_value_suffix(axis: Axis, value: &str) -> String {
    format!(" [substrate_policy axis {} = {value}]", axis.as_str())
}

/// The rendering policy applied when a network event was created. Kept on the
/// recorder rather than on the event so that an event's own record is final and
/// cannot be re-interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturePolicy {
    pub path: PathPolicy,
}

impl Default for CapturePolicy {
    fn default() -> CapturePolicy {
        CapturePolicy {
            path: PathPolicy::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Scheme;

    #[test]
    fn every_detail_variant_names_its_group() {
        let net = Detail::Net {
            meta: RequestMeta::parse("https://a.invalid/x").unwrap(),
            method: HttpMethod::Get,
            headers: HeaderNames::new(),
            body_bytes: Some(0),
            outcome: Err(EgressDenial::default()),
            presentation: NetPresentation::Denied,
            recorded_path: "/x".to_string(),
        };
        assert_eq!(net.group(), Group::Net);
        assert_eq!(
            Detail::Fs {
                op: FsOp::Open,
                path: "/x".into(),
                bytes: 0,
                result: Ok(0)
            }
            .group(),
            Group::Fs
        );
        assert_eq!(
            Detail::Jni {
                symbol: "s".into(),
                declaring_class: None,
                library: None,
                outcome: NativeOutcome::Unsatisfied
            }
            .group(),
            Group::Jni
        );
    }

    #[test]
    fn a_zero_length_body_is_distinct_from_an_unknown_one() {
        // The oracle makes this distinction load-bearing; make sure the summary
        // rendering keeps it.
        let mut ev = SubstrateEvent {
            seq: 0,
            t_mono_ms: 0,
            group: Group::Net,
            source: Source::SubstrateInstrumentation,
            tier: Tier::T0Direct,
            assumption: Some(AssumptionId::NetEgress),
            detail: Detail::Probes {
                pattern: "SIGNAL_PAT.X",
                detail: String::new(),
                axis: None,
            },
        };
        ev.detail = Detail::Net {
            meta: RequestMeta::parse("https://a.invalid/x").unwrap(),
            method: HttpMethod::Post,
            headers: HeaderNames::new(),
            body_bytes: Some(0),
            outcome: Err(EgressDenial::default()),
            presentation: NetPresentation::Denied,
            recorded_path: "/x".into(),
        };
        assert!(ev.summary().contains("body=0"));
        ev.detail = match ev.detail {
            Detail::Net {
                meta,
                method,
                headers,
                outcome,
                presentation,
                recorded_path,
                ..
            } => Detail::Net {
                meta,
                method,
                headers,
                body_bytes: None,
                outcome,
                presentation,
                recorded_path,
            },
            _ => unreachable!(),
        };
        assert!(ev.summary().contains("body=?"));
    }

    #[test]
    fn scheme_tokens_match_the_oracle_enum() {
        for s in [
            Scheme::Http,
            Scheme::Https,
            Scheme::Ws,
            Scheme::Wss,
            Scheme::Other,
        ] {
            assert!(matches!(
                s.as_str(),
                "http" | "https" | "ws" | "wss" | "other"
            ));
        }
    }

    #[test]
    fn a_denied_request_and_a_loopback_one_are_both_denials() {
        // The security property, asserted at the layer the policy can reach. A
        // presentation may be added on top of a refusal; it can never replace it.
        let meta = RequestMeta::parse("https://a.invalid/x").unwrap();
        let denied = Detail::Net {
            meta: meta.clone(),
            method: HttpMethod::Get,
            headers: HeaderNames::new(),
            body_bytes: None,
            outcome: Err(EgressDenial::default()),
            presentation: NetPresentation::Denied,
            recorded_path: "/x".into(),
        };
        let Detail::Net {
            meta,
            method,
            headers,
            body_bytes,
            outcome,
            recorded_path,
            ..
        } = denied.clone()
        else {
            unreachable!()
        };
        let looped = Detail::Net {
            meta,
            method,
            headers,
            body_bytes,
            outcome,
            presentation: NetPresentation::Loopback(LoopbackResponse::default()),
            recorded_path,
        };
        for d in [&denied, &looped] {
            let Detail::Net { outcome, .. } = d else {
                panic!()
            };
            assert!(outcome.is_err(), "the sink refuses on every policy value");
        }
        let s = looped.summary();
        // The refusal is the verdict, under the loopback policy exactly as under
        // the default; the presentation is a clause after it, never a replacement.
        assert!(s.contains(EgressDenial::default().code), "{s}");
        assert!(!s.contains("-> ok"), "{s}");
        assert!(denied.summary().contains(EgressDenial::default().code));
        assert!(!denied.summary().contains("presented a synthesised"));
        assert!(s.contains("presented a synthesised 200 response"), "{s}");
        assert!(s.contains("with nothing transmitted"), "{s}");
    }

    #[test]
    fn a_probe_says_which_axis_answered_it_and_an_app_fact_says_none() {
        let p = Detail::Probes {
            pattern: "SIGNAL_PAT.BUILD_FIELD",
            detail: "Build.FINGERPRINT = andro-substrate/shim".into(),
            axis: Some(Axis::Identity),
        };
        assert!(p
            .summary()
            .contains("[answered by substrate_policy axis identity]"));
        let app_fact = Detail::Probes {
            pattern: "SIGNAL_PAT.CLASS_RESOLVE",
            detail: "La/b/Main; -> app_dex".into(),
            axis: None,
        };
        assert_eq!(
            app_fact.summary(),
            "probes SIGNAL_PAT.CLASS_RESOLVE: La/b/Main; -> app_dex"
        );
    }
}
