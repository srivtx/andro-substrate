//! Typed failures. Every fallible operation in this crate returns one of these
//! and none of them panics.
//!
//! # Why this file exists at all
//!
//! The substrate renders *untrusted* input: a box tree built from an APK's own
//! view hierarchy, whose geometry the app chose and whose text may be an
//! attacker-supplied string that ends up inside an SVG attribute. A panic here
//! is not a crash of the app under study, it is a denial of service against the
//! measurement apparatus, and an apparatus that its subject can crash selects
//! its own corpus. So parsing is total, arithmetic saturates, and every
//! "should not happen" is an `Err` with a name.
//!
//! The `kind()` discriminant is stable and machine-readable for the same reason
//! the shim has one: a recording's JSON must not depend on a `Display` string
//! that someone might reword.

use std::fmt;

use crate::capability::GfxId;
use crate::paint::PorterDuffMode;

/// Which surface produced a value. Errors and capability reports both name it,
/// because "this is not supported" means something different for a browser
/// Canvas2D context than for an SVG file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackendKind {
    /// The recording backend: a serialisable display list, no rasterisation.
    Headless,
    /// SVG. A vector serialisation, diffable, viewable, not a frame.
    Svg,
    /// A browser `CanvasRenderingContext2D`, emitted as a JS program.
    Canvas2d,
}

impl BackendKind {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendKind::Headless => "headless",
            BackendKind::Svg => "svg",
            BackendKind::Canvas2d => "canvas2d",
        }
    }
}

impl fmt::Display for BackendKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything that can go wrong while turning a box tree into pixels-shaped
/// data.
#[derive(Debug, Clone, PartialEq)]
pub enum GraphicsError {
    /// A coordinate reached a backend as `NaN` or an infinity. No serialiser
    /// may emit it: `NaN` in an SVG attribute is not a number, it is a parse
    /// error in somebody else's reader.
    NonFinite {
        what: &'static str,
        value: f32,
    },
    /// The viewport is negative, non-finite, or so large that `dp * density`
    /// would overflow.
    BadViewport {
        width: f32,
        height: f32,
        density: f32,
    },
    /// A capability probe came back `Absent` and the caller demanded the
    /// capability anyway. This is the *expected* path for a substrate
    /// assumption the runtime cannot satisfy; it is an error because silently
    /// substituting something is the failure mode this layer exists to prevent.
    Unsupported {
        id: GfxId,
        what: &'static str,
        reason: &'static str,
    },
    /// A backend cannot express this compositing mode and declined rather than
    /// approximate it.
    UnsupportedXfermode {
        mode: PorterDuffMode,
        backend: BackendKind,
    },
    /// A backend cannot express this `ColorFilter` and declined.
    UnsupportedColorFilter {
        which: &'static str,
        backend: BackendKind,
    },
    /// A backend cannot express this shader and declined.
    UnsupportedShader {
        which: &'static str,
        backend: BackendKind,
    },
    /// The tree is deeper than the configured bound. The shim's own recursion
    /// produced a value, but *this* crate's recursion must not be the thing that
    /// overflows the stack.
    TreeTooDeep {
        depth: usize,
        limit: usize,
    },
    /// The display list is longer than the configured bound. A pathological
    /// tree of one-node children would otherwise allocate without limit.
    TooManySteps {
        steps: usize,
        limit: usize,
    },
    /// A view id in a text source that is not in the tree. Reported rather than
    /// ignored: a text source that does not match the tree is a wiring bug, and
    /// a wrong string on screen is worse than a missing one.
    UnusedTextEntry {
        id: String,
    },
    /// A supplied bitmap is internally inconsistent: a length that is not
    /// `4 * w * h`, or zero dimensions.
    BadBitmap {
        id: String,
        width: u32,
        height: u32,
        bytes: usize,
    },
    /// A supplied bitmap is well-formed but this layer cannot serialise its
    /// pixels (there is no PNG encoder here and encoding one would be a claim
    /// this layer has not earned).
    UnserialisableBitmap {
        id: String,
    },
    /// Text measurement failed, or the measurer refused.
    Measure {
        reason: String,
    },
    /// Serialisation failed. On a `String` this should be unreachable; the arm
    /// exists so a future non-`String` writer cannot be added without a
    /// decision about what it does on failure.
    Encode {
        what: &'static str,
        reason: String,
    },
}

impl GraphicsError {
    /// Stable machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            GraphicsError::NonFinite { .. } => "NonFinite",
            GraphicsError::BadViewport { .. } => "BadViewport",
            GraphicsError::Unsupported { .. } => "UnsupportedCapability",
            GraphicsError::UnsupportedXfermode { .. } => "UnsupportedXfermode",
            GraphicsError::UnsupportedColorFilter { .. } => "UnsupportedColorFilter",
            GraphicsError::UnsupportedShader { .. } => "UnsupportedShader",
            GraphicsError::TreeTooDeep { .. } => "TreeTooDeep",
            GraphicsError::TooManySteps { .. } => "TooManySteps",
            GraphicsError::UnusedTextEntry { .. } => "UnusedTextEntry",
            GraphicsError::BadBitmap { .. } => "BadBitmap",
            GraphicsError::UnserialisableBitmap { .. } => "UnserialisableBitmap",
            GraphicsError::Measure { .. } => "Measure",
            GraphicsError::Encode { .. } => "Encode",
        }
    }

    /// The `SUB.GFX` ID this failure is an instance of, when it is one. Used to
    /// attribute a gap to the taxonomy rather than to a stack trace.
    pub fn assumption(&self) -> Option<GfxId> {
        match self {
            GraphicsError::Unsupported { id, .. } => Some(*id),
            GraphicsError::UnsupportedXfermode { .. } => Some(GfxId::TextRender),
            GraphicsError::UnsupportedColorFilter { .. } => Some(GfxId::TextRender),
            GraphicsError::UnsupportedShader { .. } => Some(GfxId::TextRender),
            GraphicsError::BadBitmap { .. } | GraphicsError::UnserialisableBitmap { .. } => {
                Some(GfxId::Surface)
            }
            GraphicsError::Measure { .. } => Some(GfxId::TextRender),
            _ => None,
        }
    }
}

impl fmt::Display for GraphicsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphicsError::NonFinite { what, value } => {
                write!(f, "{what} is not finite: {value}")
            }
            GraphicsError::BadViewport {
                width,
                height,
                density,
            } => write!(f, "viewport {width}x{height} at density {density} is unusable"),
            GraphicsError::Unsupported {
                id,
                what,
                reason,
            } => write!(f, "{}: {what} is absent — {reason}", id.assumption()),
            GraphicsError::UnsupportedXfermode { mode, backend } => write!(
                f,
                "backend {backend} cannot express {} and declined to approximate it",
                mode.as_str()
            ),
            GraphicsError::UnsupportedColorFilter { which, backend } => {
                write!(f, "backend {backend} cannot express a {which} color filter")
            }
            GraphicsError::UnsupportedShader { which, backend } => {
                write!(f, "backend {backend} cannot express a {which} shader")
            }
            GraphicsError::TreeTooDeep { depth, limit } => {
                write!(f, "tree is {depth} deep, over the {limit} limit")
            }
            GraphicsError::TooManySteps { steps, limit } => {
                write!(f, "display list reached {steps} steps, over the {limit} limit")
            }
            GraphicsError::UnusedTextEntry { id } => {
                write!(f, "text source has {id:?}, which is not in the tree")
            }
            GraphicsError::BadBitmap {
                id,
                width,
                height,
                bytes,
            } => write!(
                f,
                "bitmap {id:?} is {width}x{height} with {bytes} bytes of pixels"
            ),
            GraphicsError::UnserialisableBitmap { id } => write!(
                f,
                "bitmap {id:?} holds real pixels, which this layer cannot encode"
            ),
            GraphicsError::Measure { reason } => write!(f, "text measurement failed: {reason}"),
            GraphicsError::Encode { what, reason } => write!(f, "serialising {what}: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_arm_has_a_stable_kind_and_no_arm_collides() {
        let all = [
            GraphicsError::NonFinite {
                what: "x",
                value: f32::NAN,
            },
            GraphicsError::BadViewport {
                width: -1.0,
                height: 0.0,
                density: 1.0,
            },
            GraphicsError::Unsupported {
                id: GfxId::Vulkan,
                what: "w",
                reason: "r",
            },
            GraphicsError::UnsupportedXfermode {
                mode: PorterDuffMode::SrcAtop,
                backend: BackendKind::Svg,
            },
            GraphicsError::UnsupportedColorFilter {
                which: "w",
                backend: BackendKind::Svg,
            },
            GraphicsError::UnsupportedShader {
                which: "w",
                backend: BackendKind::Canvas2d,
            },
            GraphicsError::TreeTooDeep { depth: 1, limit: 0 },
            GraphicsError::TooManySteps { steps: 1, limit: 0 },
            GraphicsError::UnusedTextEntry { id: String::new() },
            GraphicsError::BadBitmap {
                id: String::new(),
                width: 0,
                height: 0,
                bytes: 0,
            },
            GraphicsError::UnserialisableBitmap { id: String::new() },
            GraphicsError::Measure { reason: String::new() },
            GraphicsError::Encode {
                what: "w",
                reason: String::new(),
            },
        ];
        let mut kinds: Vec<&str> = all.iter().map(GraphicsError::kind).collect();
        let n = kinds.len();
        kinds.sort_unstable();
        kinds.dedup();
        assert_eq!(kinds.len(), n, "two error arms share a kind: {kinds:?}");
        // And every arm renders, so a recording never carries an empty message.
        for e in &all {
            assert!(!format!("{e}").is_empty());
        }
    }

    #[test]
    fn untrusted_coordinates_are_refused_rather_than_serialised_as_nan() {
        for v in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let r = crate::paint::RectF::new(0.0, 0.0, v, 10.0);
            let err = crate::paint::RectF::checked(&r).err();
            assert!(matches!(err, Some(GraphicsError::NonFinite { .. })), "{v}");
        }
    }
}
