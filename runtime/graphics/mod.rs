//! `runtime/graphics` — the shim's layout, turned into pixels-shaped data.
//!
//! # What this crate is
//!
//! The substrate has no display, so no app can reach `L2_FIRST_FRAME_DRAWN`, and
//! that rung is the study's primary dependent variable. This crate is the
//! missing layer between the shim's real measure/layout box tree
//! (`shim/src/layout.rs`) and something a person can look at: it maps the box
//! tree to draw commands and writes them down as a canonical display list, an
//! SVG, or a browser Canvas2D program.
//!
//! # What this crate is not
//!
//! **It is not a rendering of the app.** The app's `onDraw` was never executed.
//! The shim's `BoxNode` is geometry and nothing else — every node carries
//! `painted: false` and there is no rasteriser anywhere in that crate. So a
//! frame produced here is a rendering of *the shim's view of the layout*, which
//! is a partial reconstruction covering a small fraction of what even the
//! simplest candidate app needs.
//!
//! The project's own shim author wrote down why that distinction has to be
//! enforced in the output rather than in a README:
//!
//! > a shim returning plausible values produces recordings that read like
//! > measurements of the app and are partly measurements of me… This gets worse
//! > the more plausible the shim is.
//!
//! So every value in every artefact this crate emits carries a
//! [`Provenance`](paint::Provenance) tag, the capability report is *in* the
//! output, and a banner says so in words at the top of anything rendered. **An
//! empty box is honest; a plausible-but-wrong box is not.**
//!
//! # The modules
//!
//! | module | what it is |
//! |---|---|
//! | [`paint`] | `Color`, `RectF`, `Path`, `Shader`, `PorterDuff.Mode`, `XFERMODE`, `ColorFilter`, `Paint` — the platform's names, and its gaps |
//! | [`measure`] | the text-measurement seam. A trait, and a stub that measures nothing |
//! | [`capability`] | the `SUB.GFX.*` report, its probes, and the audit that checks the report against the code |
//! | [`canvas`] | the backend trait, the display list, the headless backend, and the Canvas2D backend |
//! | [`svg`] | the SVG serialisation, its banner, and its own table of what SVG cannot express |
//! | [`draw`] | the box tree to draw commands mapping |
//! | [`error`] | `GraphicsError`. There are no panics on untrusted input |
//!
//! # The three numbers worth publishing
//!
//! 1. **`0` of `11` `SUB.GFX` assumptions reproduced.** Measured by running
//!    eleven probes, not asserted. See [`capability`].
//! 2. **`0` fabricated ink commands** under the default configuration. See
//!    [`draw`].
//! 3. **The Porter-Duff split**, which is the one place the two backends
//!    genuinely differ: `21` modes recorded, `13` expressible in Canvas2D,
//!    `6` in SVG. Enumerated, so a new mode cannot be added without a test
//!    noticing.
//!
//! # Determinism
//!
//! The display-list text form is byte-stable across runs and across processes.
//! `tests/determinism.rs` re-executes the test binary as a child process and
//! compares bytes, so the claim is measured rather than asserted. What would
//! break it is listed in [`canvas`] next to the rules that keep it.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
// No `unwrap`, `expect` or `panic!` in shipped code. `cfg_attr(not(test), ...)`
// rather than a flat `deny` so the unit tests below may assert on an `Err`
// without tripping a lint that exists to protect the library, exactly as
// `shim/tests/no_panic.rs` scans only non-test source.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// Under `cfg(test)` the rule is off rather than downgraded: a test asserting on
// the happy path legitimately unwraps, and a warning on every such line would
// train a reader to ignore the lint that matters. The `shim` crate enforces the
// same rule the same way — by scanning non-test source.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod capability;
pub mod canvas;
pub mod draw;
pub mod error;
pub mod measure;
pub mod paint;
pub mod svg;
pub mod testutil;

pub use capability::{CapabilityReport, GfxId, Probe, ProbeAnswer, Verdict};
pub use canvas::{Canvas, DisplayList, HeadlessCanvas, Canvas2dCanvas, Viewport};
pub use draw::{draw_tree, render, DrawConfig, DrawReport, TextSource, Theme};
pub use error::{BackendKind, GraphicsError};
pub use measure::{TextAdvance, TextMeasurer, TextStyle, UniformMeasurer, ZeroMeasurer};
pub use paint::{
    Color, ColorFilter, Path, Paint, PorterDuffMode, Provenance, RectF, Shader, Xfermode,
};

/// The crate version, in a constant, for a header that wants it. Not a
/// `CARGO_PKG_VERSION` read: a recording should name the *output format*, and
/// the format version is [`FORMAT_VERSION`].
pub const OUTPUT_FORMAT: &str = "display-list/1";

/// The display-list format version. Bumped only on a change that makes two
/// artefacts non-comparable, which is the point of having one.
pub const FORMAT_VERSION: &str = OUTPUT_FORMAT;
