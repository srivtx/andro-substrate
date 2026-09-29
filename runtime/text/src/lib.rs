//! Text measurement, shaping and line layout for andro-substrate.
//!
//! # What this is
//!
//! A real Android layout is sized by measured text. `TextView` wraps at a
//! width computed from `Paint.measureText`, `TextUtils.ellipsize` decides what a
//! list row shows, and `StaticLayout` decides how tall a paragraph is. Without
//! those numbers nothing lays out, and a drawing path that receives invented
//! numbers produces a picture rather than a layout.
//!
//! So this crate has to produce *widths*. It cannot produce Android's exact
//! widths, because Android's widths come out of Roboto, Roboto is not
//! redistributable here, and a browser's `measureText` is a different shaper
//! (HarfBuzz) with different metrics and different fallback. That is stated up
//! front because the alternative — a text module that quietly looks plausible —
//! is the failure mode this crate is built to avoid.
//!
//! # The contract
//!
//! 1. **Deterministic.** Same input, same numbers, always, on every backend.
//!    No wall clock, no hash-map iteration order, no locale ambient state, no
//!    floating-point that depends on target features. Asserted in
//!    `tests/determinism.rs`.
//! 2. **No panics.** An APK ships both the text and, via `assets/fonts/`, the
//!    font files. Every failure path is a [`TextError`].
//! 3. **Declared, not assumed.** Every measurement records which font, which
//!    rounding model, and — for the derived vertical metrics — which font table
//!    field it came from, so a number in a box tree can be traced.
//! 4. **Calibrated.** [`metrics`] measures this crate's error against a real
//!    Android 13 device and reports the distribution, not a mean.
//!
//! # The number that matters
//!
//! See [`metrics`] and `README.md` for the measured error against the emulator.
//! Short version: the horizontal model reproduces the device exactly for the
//! bundled font's advance widths, and the residual error is the difference
//! between the bundled font and Roboto, which is a *font* problem and is
//! reported as such rather than hidden in a fudge factor.
//!
//! # Integration
//!
//! `runtime/Cargo.toml` and `runtime/src/lib.rs` belong to B1. To wire this in,
//! B1 adds one line to their crate root:
//!
//! ```ignore
//! #[path = "../text/mod.rs"]
//! pub mod text;
//! ```
//!
//! until then this is a standalone crate (`cargo test` in this directory).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod font;
pub mod layout;
pub mod metrics;
pub mod shaper;

use std::fmt;

pub use font::{FontFace, FontLookup, FontProvenance, FontRegistry, License, MetricTrust};
pub use layout::{Ellipsized, LayoutAlign, LayoutParams, Line, Paragraph, TruncateAt};
pub use shaper::{
    BidiClass, BidiLevel, Run, TextMetrics, TextStyle, VisualOrder, measure, measure_runs, resolve_bidi,
};

/// Every way text handling can fail. There is no panic path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TextError {
    /// A font file ended before a structure it declared.
    Truncated {
        what: &'static str,
        need: usize,
        have: usize,
    },
    /// A table a measurement needs is absent.
    MissingTable { table: String },
    /// A structure parsed but is internally impossible.
    Malformed(String),
    /// A style that cannot exist (negative text size, zero-em letter spacing).
    InvalidStyle(String),
    /// No font could be found for a request and no fallback existed either.
    NoFontAvailable { family: String },
    /// Byte offsets in a shape string that are not on a character boundary.
    NotCharBoundary { offset: usize },
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TextError::Truncated { what, need, have } => {
                write!(f, "truncated {what}: need {need} bytes, have {have}")
            }
            TextError::MissingTable { table } => write!(f, "font has no '{table}' table"),
            TextError::Malformed(m) => write!(f, "malformed font: {m}"),
            TextError::InvalidStyle(m) => write!(f, "invalid text style: {m}"),
            TextError::NoFontAvailable { family } => {
                write!(f, "no font available for family '{family}'")
            }
            TextError::NotCharBoundary { offset } => {
                write!(f, "offset {offset} is not a character boundary")
            }
        }
    }
}

impl std::error::Error for TextError {}

/// SHA-256, used only to pin the exact bytes a measurement came from.
///
/// This is a provenance fingerprint, not a security primitive: it answers "are
/// these the same bytes as last month's report", not "is this file safe". The
/// file is untrusted and is treated as untrusted by the parser; hashing it
/// first would be a false sense of safety. Implemented here rather than pulled
/// in as a dependency because a font registry is not a place to want a supply
/// chain, and the crate is 60 lines. Verified against the FIPS 180-4 vectors in
/// `tests/fonts.rs`.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut dd, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = dd.wrapping_add(t1);
            dd = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for v in h {
        out.push_str(&format!("{v:08x}"));
    }
    out
}
