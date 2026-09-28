//! # shim — the `android.*` framework shim as an **observation layer**
//!
//! andro-substrate runs untrusted APK bytecode in a browser. This crate is the
//! part that makes that *measurable* rather than merely possible.
//!
//! ## The inversion this crate is built on
//!
//! On a real Android device, learning what an app does — which files it opens,
//! what it sends, which classes it loads, which `Build.*` fields it reads —
//! requires root or Frida: fragile, detectable by the app, and legally fraught.
//! `oracle/RECORDING.md` §12 says it plainly: on a stock non-rooted device the
//! per-operation file access, class-load census, JNI transitions and network
//! exchanges are **not observable at all**, and a recorder that reports no gaps
//! is lying.
//!
//! In a browser substrate there is no hiding place. The substrate *is* the
//! process, so every byte the app produces passes through code this project
//! wrote. Observability is not a feature to be added; it is a consequence of the
//! architecture.
//!
//! So the shim's primary design goal is **not** compatibility. It is to make
//! every interaction visible, structured, and directly comparable to a device
//! capture in the format `oracle/schema/ground-truth.schema.json` defines. Where
//! the two goals conflict, visibility wins, and the conflict is written down in
//! [`CONFORMANCE.md`](https://github.com/srivtx/andro-substrate/blob/main/shim/CONFORMANCE.md)
//! rather than quietly resolved.
//!
//! ## What is in here
//!
//! | module | role |
//! |---|---|
//! | [`registry`] | **the** class and method table. One table; four consumers. |
//! | [`dispatch`] | the [`dispatch::ShimCaller`] trait an interpreter plugs into, and the observation-backed implementation. |
//! | [`behaviour`] | what each method *does* and *records*. Never only one. |
//! | [`event`] | [`event::SubstrateEvent`], in the oracle's six observation groups. |
//! | [`redact`] | the redaction invariant. Redaction happens in the parser, so there is no field to forget to scrub. |
//! | [`net`] | the egress sink. The only network capability, and it is a wall. |
//! | [`vfs`] | an in-memory virtual filesystem. Nothing touches a disk. |
//! | [`classes`] | the classloader and the supersede decision. |
//! | [`policy`] | **the substrate policy**: the shim's own behaviour, as a declared parameter. |
//! | [`differential`] | run one program under two substrates and attribute every moved fact. |
//! | [`system`] | the fabricated device identity, and the probes that read it. |
//! | [`layout`] | a real measure/layout/draw cycle producing a serialisable box tree. |
//! | [`emit`] | emit the shim as a DEX with `dexcore`'s writer. |
//! | [`recording`] | turn an event stream into a `ground-truth/1` document. |
//! | [`scenario`] | the synthetic capture, driven by real shim calls. |
//!
//! ## The redaction invariant, in one sentence
//!
//! There is no field anywhere in this crate that can hold a request body, a
//! header value, or a query-string value, and the parser that would have to
//! hold them drops them on the floor. Redaction at capture, not downstream,
//! because a downstream redactor is one refactor away from writing a real
//! credential to disk. `tests/redaction.rs` proves it with canary strings that
//! must not survive serialisation.
//!
//! ## The honest limits
//!
//! * **This shim will not run real apps yet.** It covers a small fraction of
//!   `android.jar` and it is missing `invokedynamic`, Binder, `WebView`'s real
//!   engine, resources, sensors and Play Services entirely.
//!   `shim/CONFORMANCE.md` states the measured fraction rather than an
//!   impression of it.
//! * **The layer observes a different program.** The shim terminates every side
//!   effect, so an app's control flow after a denied sink is determined by the
//!   shim rather than by the app. That is a measurement-validity hazard and it
//!   is stated in `docs/decisions/0005-shim-and-observation.md` rather than
//!   buried.
//! * **Layout is geometry, not pixels.** No rasteriser exists. A pixel-level
//!   divergence would be structurally invisible to this layer.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::all)]
// The recording builder is one large `json!` literal; the default 128 frames is
// not enough to expand it and splitting the document would not help.
#![recursion_limit = "512"]

pub mod behaviour;
pub mod classes;
pub mod differential;
pub mod dispatch;
pub mod emit;
pub mod error;
pub mod event;
pub mod layout;
pub mod net;
pub mod policy;
pub mod recording;
pub mod redact;
pub mod registry;
pub mod scenario;
pub mod system;
pub mod taxonomy;
pub mod vfs;

pub use dispatch::{Shim, ShimCaller, Value};
pub use error::{EgressDenial, ShimError, VfsError};
pub use event::{Detail, Group, NetPresentation, Resolution, SubstrateEvent, Tier};
pub use layout::{BoxNode, NodeKind, Orientation, Size, TextPolicy, View};
pub use net::{EgressRequest, EgressSink};
pub use policy::{
    Axis, FactClass, IdentityMode, LoopbackResponse, NetworkMode, PackageMode, SubstratePolicy,
    SystemFsMode, TimeMode, POLICY_FORMAT, POLICY_VERSION,
};
pub use redact::{HeaderNames, HttpMethod, PathPolicy, RequestMeta, Scheme};
pub use taxonomy::{AssumptionId, Family, SymptomClass};

/// The crate's own version, for a recording's `recorder.version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The shim DEX's schema name. Used in `probes[].command` so a reader knows
/// which instrument produced a box tree.
pub const TOOL_NAME: &str = "andro-substrate-shim";
