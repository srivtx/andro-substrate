//! Naming a substrate policy on a command line.
//!
//! # Two forms, and why both
//!
//! A **named** policy (`--policy loud`, `--policy default`) is what a study
//! quotes, because a name is stable across code changes and appears in a
//! results table as one cell. An **axis** specification
//! (`--policy 'identity=refusing;system_fs=absent'`) is what a study uses to
//! point the differential at one axis at a time, and it is the same closed
//! vocabulary the shim's own `SubstratePolicy::set` matches against.
//!
//! Nothing here can invent a value. Every token is checked by
//! [`shim::SubstratePolicy::set`], which matches a closed list and returns an
//! error for anything else; this module only decides *which* axis a token is for
//! and refuses a token that claims an axis the substrate does not have. That
//! direction matters: a policy is a parameter over what the shim *returns*, and
//! the CLI must not become a parameter over what it may *do*. There is no flag
//! here that can open a socket, and a test asserts the list of accepted axis
//! names is exactly the five in `shim::policy::Axis`.
//!
//! The named policies are the two arms the committed differential already uses,
//! so a `--policy` value means the same thing here as it does in
//! `shim/recordings/differential.report.txt`.

use shim::error::ShimError;
use shim::policy::{Axis, SubstratePolicy};

/// A parsed `--policy` argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySpec {
    /// The name as written, for the report and the `capture_id`.
    pub name: String,
    /// The policy value it resolved to.
    pub policy: SubstratePolicy,
}

/// Why a `--policy` argument was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The name is not one of the named policies and is not an `axis=value` list.
    UnknownName(String),
    /// An assignment with no `=`, or an empty axis.
    Malformed(String),
    /// The substrate has no such axis. The five are the whole set.
    UnknownAxis(String),
    /// The axis exists and the token is not one of its values.
    BadValue {
        /// The axis token.
        axis: String,
        /// The value that was refused.
        value: String,
    },
    /// Nothing was given at all.
    Empty,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::UnknownName(n) => write!(
                f,
                "unknown policy {n:?}; use one of: default, loud, or axis=value pairs separated \
                 by ';' (identity, system_fs, cross_app_packages, network, time)"
            ),
            PolicyError::Malformed(s) => {
                write!(f, "malformed policy assignment {s:?}; expected axis=value")
            }
            PolicyError::UnknownAxis(a) => write!(
                f,
                "{a:?} is not a substrate axis; the five are identity, system_fs, \
                 cross_app_packages, network, time"
            ),
            PolicyError::BadValue { axis, value } => {
                write!(f, "{value:?} is not a value of the {axis} axis")
            }
            PolicyError::Empty => f.write_str("no policy was named"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The axis tokens the CLI accepts, and nothing else.
pub const AXIS_NAMES: &[&str] = &[
    "identity",
    "system_fs",
    "cross_app_packages",
    "network",
    "time",
];

/// The named policies, and what each one is.
///
/// `loud` is the substrate the committed right-hand arm uses: identity withheld,
/// `/proc` and `/sys` absent, cross-app queries an error. It exists so a study
/// has a second arm that is *maximally different* from the default, which ADR
/// 0006 argues is the confound and therefore the baseline.
pub const NAMED: &[(&str, &str)] = &[
    (
        "default",
        "identity=fabricated, system_fs=fabricated, cross_app_packages=subject_only, \
         network=record_and_deny, time=virtual",
    ),
    (
        "loud",
        "identity=withheld, system_fs=absent, cross_app_packages=error, \
         network=record_and_deny, time=virtual",
    ),
    (
        "refusing",
        "identity=refusing, system_fs=absent, cross_app_packages=error, \
         network=record_and_deny, time=frozen",
    ),
    (
        "loopback",
        "identity=fabricated, system_fs=fabricated, cross_app_packages=all_present, \
         network=synthetic_loopback, time=virtual",
    ),
];

/// The axis a CLI token names, or an error naming the five.
pub fn axis_of(token: &str) -> Result<Axis, PolicyError> {
    match token {
        "identity" => Ok(Axis::Identity),
        "system_fs" => Ok(Axis::SystemFs),
        "cross_app_packages" => Ok(Axis::CrossAppPackages),
        "network" => Ok(Axis::Network),
        "time" => Ok(Axis::Time),
        other => Err(PolicyError::UnknownAxis(other.to_string())),
    }
}

/// Resolve a `--policy` argument.
pub fn parse_policy(spec: &str) -> Result<PolicySpec, PolicyError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err(PolicyError::Empty);
    }
    if let Some((_, blurb)) = NAMED.iter().find(|(n, _)| *n == spec) {
        let mut p = SubstratePolicy::default();
        for pair in blurb.split(',') {
            let (a, v) = pair
                .split_once('=')
                .ok_or_else(|| PolicyError::Malformed(pair.into()))?;
            let axis = axis_of(a.trim())?;
            p.set(axis, v.trim()).map_err(|_| PolicyError::BadValue {
                axis: a.trim().to_string(),
                value: v.trim().to_string(),
            })?;
        }
        return Ok(PolicySpec {
            name: spec.to_string(),
            policy: p,
        });
    }
    if !spec.contains('=') {
        return Err(PolicyError::UnknownName(spec.to_string()));
    }
    let mut p = SubstratePolicy::default();
    for pair in spec.split(';') {
        let (a, v) = pair
            .split_once('=')
            .ok_or_else(|| PolicyError::Malformed(pair.into()))?;
        let axis = axis_of(a.trim())?;
        p.set(axis, v.trim()).map_err(|_| PolicyError::BadValue {
            axis: a.trim().to_string(),
            value: v.trim().to_string(),
        })?;
    }
    Ok(PolicySpec {
        name: spec.to_string(),
        policy: p,
    })
}

/// The `ShimError` a `set` produced, for a caller that prefers the shim's own
/// type. Kept so a future caller does not reach into `shim::error` for a
/// conversion this crate has no business making.
pub fn as_shim_error(e: &PolicyError) -> Option<ShimError> {
    match e {
        PolicyError::BadValue { axis, value } => Some(ShimError::Encode(format!(
            "{axis}={value} is not a substrate policy value"
        ))),
        _ => None,
    }
}
