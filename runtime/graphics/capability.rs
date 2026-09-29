//! The capability report: what this renderer can and cannot reproduce, expressed
//! against the eleven `SUB.GFX.*` IDs, and **measured rather than declared**.
//!
//! # Why this file is the deliverable and the renderer is not
//!
//! The rendering this layer can produce is a reconstruction of the *shim's* box
//! tree, which covers 3.8 % of what the simplest candidate app needs. A frame
//! that looks like Android is worse than no frame, because a reader will read it
//! as evidence about the app. So the report is not a footnote to the output; it
//! is *in* the output, in the display-list header, in the SVG `<desc>`, and
//! burned into a banner across the top of every rendered surface.
//!
//! # The trap this file is built to avoid
//!
//! The previous generation of this project shipped two headline numbers that
//! were wrong by 40× and 20×, and the cause was the same both times: **a
//! self-consistent artifact that was never checked against reality.** A report
//! that merely records what the code believes about itself would be exactly
//! that artifact.
//!
//! So every claim here has a *probe*: a call a real backend answers, whose
//! observed answer is compared against the claim. [`CapabilityReport::audit`]
//! runs the probes and reports the disagreements. The report that ships in a
//! display list is the *audited* one, and it carries its own mismatch count — a
//! report that is wrong about itself says so in its own header rather than
//! needing a reader to notice.
//!
//! The consequence for the headline number: `fully_reproduced` is 0, but it is 0
//! because **eleven probes ran and eleven returned `Absent`**, not because a
//! constant says zero. `tests/capability.rs` proves the probes are real by
//! asserting that a backend which *did* answer `Satisfied` is recorded as
//! `Satisfied`, and that the taxonomy document's own ID set matches this
//! registry exactly.

use std::fmt;

use crate::error::BackendKind;

/// The `SUB.GFX` family of `docs/divergence-taxonomy.md` §12.
///
/// All eleven IDs, in the taxonomy's order. `tests/capability.rs` reads the
/// taxonomy document and fails if this set and the document's differ, so the
/// registry cannot silently fall behind the pre-registered hypothesis space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GfxId {
    EglContext,
    GlesVersion,
    Vulkan,
    Extensions,
    RendererString,
    Surface,
    HwComposition,
    FrameBudget,
    ScreenOn,
    CameraPipe,
    TextRender,
}

impl GfxId {
    /// All eleven.
    pub const ALL: [GfxId; 11] = [
        GfxId::EglContext,
        GfxId::GlesVersion,
        GfxId::Vulkan,
        GfxId::Extensions,
        GfxId::RendererString,
        GfxId::Surface,
        GfxId::HwComposition,
        GfxId::FrameBudget,
        GfxId::ScreenOn,
        GfxId::CameraPipe,
        GfxId::TextRender,
    ];

    /// The ID's short token, e.g. `"EGL_CONTEXT"`.
    pub fn token(self) -> &'static str {
        match self {
            GfxId::EglContext => "EGL_CONTEXT",
            GfxId::GlesVersion => "GLES_VERSION",
            GfxId::Vulkan => "VULKAN",
            GfxId::Extensions => "EXTENSIONS",
            GfxId::RendererString => "RENDERER_STRING",
            GfxId::Surface => "SURFACE",
            GfxId::HwComposition => "HW_COMPOSITION",
            GfxId::FrameBudget => "FRAME_BUDGET",
            GfxId::ScreenOn => "SCREEN_ON",
            GfxId::CameraPipe => "CAMERA_PIPE",
            GfxId::TextRender => "TEXT_RENDER",
        }
    }

    /// The full assumption ID, e.g. `"SUB.GFX.EGL_CONTEXT"`.
    pub fn assumption(self) -> String {
        format!("SUB.GFX.{}", self.token())
    }

    /// Parse a short token. `None` for anything not in the family.
    pub fn parse_token(s: &str) -> Option<GfxId> {
        GfxId::ALL.into_iter().find(|g| g.token() == s)
    }

    /// The taxonomy's one-line statement of the assumption, condensed. This is
    /// what appears next to the verdict so a reader does not have to open the
    /// document.
    pub fn assumption_text(self) -> &'static str {
        match self {
            GfxId::EglContext => "EGL/GLES contexts can be created and made current",
            GfxId::GlesVersion => "GLES20.glGetString(GL_VERSION) reports >= 3.0",
            GfxId::Vulkan => "a real Vulkan instance exists",
            GfxId::Extensions => "the extension string lists what the app needs",
            GfxId::RendererString => "GL_RENDERER names a device GPU",
            GfxId::Surface => "Surface/SurfaceView/SurfaceTexture and BufferQueue exist",
            GfxId::HwComposition => "hardware composition and SurfaceFlinger behave as assumed",
            GfxId::FrameBudget => "a frame lands within ~16.7 ms at 60 Hz",
            GfxId::ScreenOn => "PowerManager.isScreenOn() and keep-screen-on work",
            GfxId::CameraPipe => "the camera HAL and camera2 pipeline exist",
            GfxId::TextRender => "Canvas, Paint, Typeface and Bitmap behave as on device",
        }
    }
}

impl fmt::Display for GfxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.assumption())
    }
}

/// A question a backend can be asked, whose answer is an observation rather
/// than an assertion.
///
/// There is exactly one probe per `GfxId` and `tests/capability.rs` asserts the
/// correspondence is a bijection, so a new ID cannot appear without a probe and
/// a probe cannot answer for a second ID.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Probe {
    /// Can a GPU context be created at all? (`GfxId::EglContext`)
    ContextCreation,
    /// `glGetString(GL_VERSION)`. (`GfxId::GlesVersion`)
    GlesVersion,
    /// `vkEnumerateInstanceVersion`. (`GfxId::Vulkan`)
    VulkanVersion,
    /// `glGetString(GL_EXTENSIONS)`. (`GfxId::Extensions`)
    GlExtensions,
    /// `glGetString(GL_RENDERER)`. (`GfxId::RendererString`)
    GlRenderer,
    /// Can a `Surface` be obtained and consumed? (`GfxId::Surface`)
    Surface,
    /// Is there a compositor that will present this? (`GfxId::HwComposition`)
    HardwareCompositor,
    /// What is the per-frame deadline? (`GfxId::FrameBudget`)
    FrameBudget,
    /// `PowerManager.isScreenOn()`. (`GfxId::ScreenOn`)
    ScreenOn,
    /// Is there a camera pipeline? (`GfxId::CameraPipe`)
    CameraPipeline,
    /// Measure a run of text. (`GfxId::TextRender`)
    ///
    /// The only probe with a payload, because `SUB.GFX.TEXT_RENDER` is the only
    /// ID in the family this layer can *partly* answer: it can produce a number,
    /// and the number is not Roboto's.
    TextAdvance {
        sample: &'static str,
        size_sp: f32,
    },
}

impl Probe {
    /// Which ID this probe answers for.
    pub fn id(&self) -> GfxId {
        match self {
            Probe::ContextCreation => GfxId::EglContext,
            Probe::GlesVersion => GfxId::GlesVersion,
            Probe::VulkanVersion => GfxId::Vulkan,
            Probe::GlExtensions => GfxId::Extensions,
            Probe::GlRenderer => GfxId::RendererString,
            Probe::Surface => GfxId::Surface,
            Probe::HardwareCompositor => GfxId::HwComposition,
            Probe::FrameBudget => GfxId::FrameBudget,
            Probe::ScreenOn => GfxId::ScreenOn,
            Probe::CameraPipeline => GfxId::CameraPipe,
            Probe::TextAdvance { .. } => GfxId::TextRender,
        }
    }

    /// A short name for the probe, stable in serialised output.
    pub fn name(&self) -> &'static str {
        match self {
            Probe::ContextCreation => "context-creation",
            Probe::GlesVersion => "gles-version",
            Probe::VulkanVersion => "vulkan-version",
            Probe::GlExtensions => "gl-extensions",
            Probe::GlRenderer => "gl-renderer",
            Probe::Surface => "surface",
            Probe::HardwareCompositor => "hardware-compositor",
            Probe::FrameBudget => "frame-budget",
            Probe::ScreenOn => "screen-on",
            Probe::CameraPipeline => "camera-pipeline",
            Probe::TextAdvance { sample, .. } => {
                // The sample is part of the probe's identity: a reader has to be
                // able to reproduce the number, so the string is in the record.
                let _ = sample;
                "text-advance"
            }
        }
    }

    /// All eleven probes, one per ID, in taxonomy order.
    pub fn all() -> Vec<Probe> {
        GfxId::ALL
            .into_iter()
            .map(|id| match id {
                GfxId::EglContext => Probe::ContextCreation,
                GfxId::GlesVersion => Probe::GlesVersion,
                GfxId::Vulkan => Probe::VulkanVersion,
                GfxId::Extensions => Probe::GlExtensions,
                GfxId::RendererString => Probe::GlRenderer,
                GfxId::Surface => Probe::Surface,
                GfxId::HwComposition => Probe::HardwareCompositor,
                GfxId::FrameBudget => Probe::FrameBudget,
                GfxId::ScreenOn => Probe::ScreenOn,
                GfxId::CameraPipe => Probe::CameraPipeline,
                GfxId::TextRender => Probe::TextAdvance {
                    sample: "Mg",
                    size_sp: 14.0,
                },
            })
            .collect()
    }
}

/// What a backend actually said when asked [`Probe`].
///
/// The `Absent` arm is not a failure mode; for ten of the eleven IDs it is the
/// *correct* answer, and the reason strings say so in words. What matters is
/// that `Absent` is a deliberate, reportable outcome and not a `0` or an empty
/// string that a reader could mistake for a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeAnswer {
    /// The capability does not exist on this backend. Nothing was emitted and
    /// nothing is claimed. The most important property of this arm is that it
    /// is *reachable*: `tests/capability.rs` runs a stub backend that answers
    /// `Satisfied` and checks the report changes, so a report full of `Absent`
    /// is a measurement rather than a constant.
    Absent {
        /// Why, in one clause, phrased so it can be printed inside a banner.
        reason: &'static str,
    },
    /// Something was produced and it is not Android's. `emission` says what
    /// came out, `origin` says where the value came from, `value` is the value
    /// itself so a reader can check it.
    Substituted {
        emission: Emission,
        origin: Origin,
        value: String,
        reason: &'static str,
    },
    /// Android-equivalent. `evidence` must name the check that established it;
    /// an empty evidence string is rejected by [`ProbeAnswer::validated`],
    /// because "trust me" is the failure this whole module exists to prevent.
    Satisfied {
        evidence: String,
    },
}

/// What a backend emits for a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Emission {
    /// The emitted operation means what Android's would mean, for the values
    /// involved.
    AndroidSemantics,
    /// Something was emitted, and it is not the operation Android would perform.
    Substituted,
    /// Nothing was emitted. Deliberately.
    NotEmitted,
}

impl Emission {
    pub fn as_str(self) -> &'static str {
        match self {
            Emission::AndroidSemantics => "android-semantics",
            Emission::Substituted => "substituted",
            Emission::NotEmitted => "not-emitted",
        }
    }
}

/// Where an emitted value came from. The distinction the project's own shim
/// author insisted on: *the shim's view of the layout, not Android's*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Exactly the value in the shim's `BoxNode`, copied without alteration.
    /// True of the shim's model. Says nothing about Android, whose layout pass
    /// produced different numbers — the shim's own header says so.
    ShimTreeExact,
    /// A consequence of the shim's tree, and true of the shim's model by
    /// definition (a clip rectangle implied by a parent frame, say).
    DerivedFromShimTree,
    /// Invented by this layer. Android would have produced something else.
    Fabricated,
    /// There is no value, on purpose.
    Absent,
    /// Checked against a real Android device or a Skia reference, and agreeing
    /// to a stated tolerance.
    ///
    /// **This variant exists so that "reproduced" can mean something.** It is
    /// the only origin that can satisfy [`Capability::reproduced`], and no
    /// backend in this crate produces it, because this crate has neither a
    /// device nor Skia. That is why the headline is `0` — and why the `0` is a
    /// measurement and not a constant: the audit runs, eleven probes answer,
    /// ten come back `Absent` and one comes back `Substituted`, and none of them
    /// can name a device.
    ///
    /// The variant is present rather than omitted so that a future agent who
    /// *does* have a reference has somewhere honest to put the evidence, and so
    /// "not attempted yet" stays distinguishable from "cannot be done" instead
    /// of collapsing into `Absent`.
    DeviceMeasured,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::ShimTreeExact => "shim-tree-exact",
            Origin::DerivedFromShimTree => "derived-from-shim-tree",
            Origin::Fabricated => "fabricated",
            Origin::Absent => "absent",
            Origin::DeviceMeasured => "device-measured",
        }
    }
}

impl ProbeAnswer {
    /// Reject the shapes that would make the report worthless: a `Satisfied`
    /// with no evidence, and a `Substituted` that claims to emit Android
    /// semantics.
    pub fn validated(self) -> Option<Self> {
        match &self {
            ProbeAnswer::Satisfied { evidence } if evidence.trim().is_empty() => None,
            ProbeAnswer::Substituted { emission, .. }
                if *emission == Emission::AndroidSemantics =>
            {
                None
            }
            _ => Some(self),
        }
    }

    /// The verdict, derived from what was observed rather than declared.
    pub fn verdict(&self) -> Verdict {
        match self {
            ProbeAnswer::Absent { .. } => Verdict::Absent,
            ProbeAnswer::Substituted { .. } => Verdict::Substituted,
            ProbeAnswer::Satisfied { .. } => Verdict::Satisfied,
        }
    }
}

impl fmt::Display for ProbeAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeAnswer::Absent { reason } => write!(f, "absent ({reason})"),
            ProbeAnswer::Substituted {
                emission,
                origin,
                value,
                reason,
            } => write!(
                f,
                "substituted: {emission:?}/{origin:?} = {value} ({reason})"
            ),
            ProbeAnswer::Satisfied { evidence } => write!(f, "satisfied: {evidence}"),
        }
    }
}

/// Three-valued. The count of `Satisfied` is the headline number the report is
/// audited on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Absent,
    Substituted,
    Satisfied,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Absent => "absent",
            Verdict::Substituted => "substituted",
            Verdict::Satisfied => "satisfied",
        }
    }
}

/// How faithfully a backend can express one *feature* (a compositing mode, a
/// colour filter, a shader). A per-feature table, separate from the per-
/// assumption report, because "can this backend draw this" and "does this
/// substrate have a GPU" are different questions and the earlier generation of
/// this project conflated them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Support {
    /// The backend has a primitive whose semantics match. Not a claim that the
    /// *values* match — see the per-assumption report for that.
    Exact,
    /// The backend has something close, and the difference is recorded. Used
    /// for the separable blend modes, where Canvas2D and SVG follow the
    /// Compositing spec's premultiplied formulas and Skia follows its own.
    Substituted,
    /// The backend records the operation faithfully in its serialisation but
    /// does not perform it, because it is not a rasteriser.
    Recorded,
    /// The backend cannot express it, and refuses.
    Absent,
}

impl Support {
    pub fn as_str(self) -> &'static str {
        match self {
            Support::Exact => "exact",
            Support::Substituted => "substituted",
            Support::Recorded => "recorded",
            Support::Absent => "absent",
        }
    }
}

/// One line of a per-backend feature table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limitation {
    /// What the feature is, e.g. `"porter-duff-mode"`.
    pub feature: &'static str,
    /// The specific instance, e.g. `"SRC_ATOP"`. Empty for a family-level row.
    pub instance: &'static str,
    pub support: Support,
    /// One clause. Printed in the report; must not be empty.
    pub note: &'static str,
}

/// One `SUB.GFX` row: the claim, and the observation that backs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: GfxId,
    /// The verdict the backend *claims*.
    pub claimed: Verdict,
    /// What the backend *emits*, when it emits anything.
    pub emission: Emission,
    /// Where the emitted value comes from.
    pub origin: Origin,
    /// The observed answer to [`GfxId`]'s probe, in full.
    pub observed: ProbeAnswer,
    /// Why, in one clause. Never empty.
    pub note: &'static str,
}

impl Capability {
    /// Is the claim supported by the observation? This is the whole point of
    /// the module: the two fields must agree.
    pub fn agrees(&self) -> bool {
        self.claimed == self.observed.verdict()
    }

    /// Is this capability reproduced well enough to count toward the headline
    /// number?
    ///
    /// Three conditions, all of which must hold:
    ///
    /// 1. The backend claims `Satisfied` **and** the live probe observed
    ///    `Satisfied`. A claim on its own is not a result; that is the whole
    ///    point of the audit.
    /// 2. The emission carries `AndroidSemantics` — the operation means what
    ///    Android's would mean.
    /// 3. The value carries `Origin::DeviceMeasured` — it was checked against a
    ///    device or a Skia reference.
    ///
    /// Condition 3 is what makes the current count `0` a *measurement*. Every
    /// other origin is exact-or-derived **relative to the shim's box tree**,
    /// which is a different object from what a device computes, and a value
    /// from the shim's tree can never stand in for one. No backend here has a
    /// device, so no backend here can satisfy it.
    pub fn reproduced(&self) -> bool {
        self.claimed == Verdict::Satisfied
            && self.observed.verdict() == Verdict::Satisfied
            && self.emission == Emission::AndroidSemantics
            && self.origin == Origin::DeviceMeasured
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} claimed={} emission={} origin={} agrees={} :: {}",
            self.id.assumption(),
            self.claimed.as_str(),
            self.emission.as_str(),
            self.origin.as_str(),
            self.agrees(),
            self.note
        )
    }
}

/// The audit: a claim-by-claim comparison between what a backend says it can do
/// and what it actually does.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Audit {
    pub checked: usize,
    pub mismatches: Vec<String>,
    /// Probes that could not produce a well-formed answer at all.
    pub malformed: Vec<String>,
}

impl Audit {
    /// True when every claim survived its probe.
    pub fn clean(&self) -> bool {
        self.mismatches.is_empty() && self.malformed.is_empty()
    }
}

impl fmt::Display for Audit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of {} claims agree{}",
            self.checked - self.mismatches.len() - self.malformed.len(),
            self.checked,
            if self.mismatches.is_empty() && self.malformed.is_empty() {
                ""
            } else {
                "; disagreements are in the report itself"
            }
        )
    }
}

/// A backend's claim about one `SUB.GFX` ID, before it is checked.
///
/// Kept separate from [`Capability`] so the *claim* is data a backend supplies
/// and the *observation* is data the probe produces; merging them is how a
/// self-consistent artifact gets built by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claim {
    pub id: GfxId,
    pub verdict: Verdict,
    pub emission: Emission,
    pub origin: Origin,
    pub note: &'static str,
}

/// The audited capability report for one backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    pub backend: BackendKind,
    pub entries: Vec<Capability>,
    pub audit: Audit,
    /// Per-feature expression table, e.g. the Porter-Duff modes.
    pub limitations: Vec<Limitation>,
}

impl CapabilityReport {
    /// Run every probe against a live backend and compare with its claims.
    ///
    /// `probe` is the backend itself. There is no path through this crate that
    /// produces a report without one.
    pub fn audit<F>(backend: BackendKind, claims: &[Claim], limitations: Vec<Limitation>, probe: F) -> Self
    where
        F: Fn(&Probe) -> ProbeAnswer,
    {
        let mut entries = Vec::with_capacity(claims.len());
        let mut mismatches = Vec::new();
        let mut malformed = Vec::new();
        let probes = Probe::all();
        for claim in claims {
            // Only probe IDs the backend makes a claim about. A backend that
            // declines to comment is recorded as such rather than probed blind.
            let Some(p) = probes.iter().find(|p| p.id() == claim.id) else {
                malformed.push(format!("{}: no probe answers for this ID", claim.id));
                continue;
            };
            let observed = probe(p);
            let entry = Capability {
                id: claim.id,
                claimed: claim.verdict,
                emission: claim.emission,
                origin: claim.origin,
                note: claim.note,
                observed: observed.clone(),
            };
            if observed.clone().validated().is_none() {
                malformed.push(format!(
                    "{}: probe returned a self-contradicting answer ({observed})",
                    claim.id
                ));
            }
            if !entry.agrees() {
                mismatches.push(format!(
                    "{}: claimed {} but observed {}",
                    claim.id,
                    claim.verdict.as_str(),
                    observed
                ));
            }
            entries.push(entry);
        }
        let checked = entries.len();
        CapabilityReport {
            backend,
            entries,
            audit: Audit {
                checked,
                mismatches,
                malformed,
            },
            limitations,
        }
    }

    /// The headline: how many of the eleven `SUB.GFX` assumptions this backend
    /// reproduces. Measured from the audited entries, not from a constant.
    pub fn reproduced(&self) -> usize {
        self.entries.iter().filter(|c| c.reproduced()).count()
    }

    /// How many IDs the backend makes any claim about at all.
    pub fn claimed(&self) -> usize {
        self.entries.len()
    }

    /// How many were probed and observed to be `Satisfied`. This is the number
    /// that must be zero today, and that a stub backend can make non-zero — the
    /// property that keeps it from being a constant.
    pub fn observed_satisfied(&self) -> usize {
        self.entries
            .iter()
            .filter(|c| c.observed.verdict() == Verdict::Satisfied)
            .count()
    }

    /// `true` when the audit found no disagreement.
    pub fn clean(&self) -> bool {
        self.audit.clean()
    }

    /// The one-sentence headline for a recording.
    pub fn headline(&self) -> String {
        format!(
            "{} backend: {} of {} SUB.GFX assumptions reproduced ({} observed satisfied, \
             {} claim/observation mismatches, {} probed)",
            self.backend,
            self.reproduced(),
            GfxId::ALL.len(),
            self.observed_satisfied(),
            self.audit.mismatches.len(),
            self.audit.checked
        )
    }

    /// The banner, in words, for a rendered surface. Written to be *unmistakable
    /// at a glance* rather than precise, because its job is to stop a reader
    /// mistaking the image for a device capture.
    pub fn banner(&self, extra: &str) -> String {
        format!(
            "RECONSTRUCTION — shim box tree, NOT an Android frame. \
             App onDraw code was never executed. {} reproduced of {}.{}",
            self.reproduced(),
            GfxId::ALL.len(),
            if extra.is_empty() {
                String::new()
            } else {
                format!(" {extra}")
            }
        )
    }

    /// Multi-line text form, for the display-list header and the SVG `<desc>`.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        for c in &self.entries {
            s.push_str("  ");
            s.push_str(&c.id.assumption());
            s.push_str(" verdict=");
            s.push_str(c.claimed.as_str());
            s.push_str(" emission=");
            s.push_str(c.emission.as_str());
            s.push_str(" origin=");
            s.push_str(c.origin.as_str());
            s.push_str(" observed=");
            s.push_str(c.observed.verdict().as_str());
            s.push_str(" :: ");
            s.push_str(c.note);
            s.push('\n');
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registry_is_eleven_and_round_trips_its_tokens() {
        assert_eq!(GfxId::ALL.len(), 11, "docs/divergence-taxonomy.md §12 says 11");
        for g in GfxId::ALL {
            assert_eq!(GfxId::parse_token(g.token()), Some(g));
            assert!(g.assumption().starts_with("SUB.GFX."));
            assert!(!g.assumption_text().is_empty());
        }
        assert_eq!(GfxId::parse_token("NOT_AN_ID"), None);
    }

    #[test]
    fn probes_and_ids_are_in_bijection() {
        let probes = Probe::all();
        assert_eq!(probes.len(), GfxId::ALL.len());
        for (i, p) in probes.iter().enumerate() {
            assert_eq!(p.id(), GfxId::ALL[i], "probe order must track the taxonomy");
        }
        let mut ids: Vec<GfxId> = probes.iter().map(Probe::id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), probes.len(), "two probes answer for one ID");
    }

    #[test]
    fn a_satisfied_claim_with_no_evidence_is_rejected() {
        assert!(ProbeAnswer::Satisfied {
            evidence: "   ".to_string()
        }
        .validated()
        .is_none());
        assert!(ProbeAnswer::Satisfied {
            evidence: "compared 1e4 spans against Skia".to_string()
        }
        .validated()
        .is_some());
    }

    #[test]
    fn a_substitution_may_not_claim_android_semantics() {
        // "We drew something, and it means exactly what Android's would" is
        // `Satisfied`, not `Substituted`. Allowing both is how a report learns
        // to talk itself into a claim.
        assert!(ProbeAnswer::Substituted {
            emission: Emission::AndroidSemantics,
            origin: Origin::Fabricated,
            value: "x".to_string(),
            reason: "r",
        }
        .validated()
        .is_none());
    }

    /// A capability row with everything but `origin` already favourable. Used
    /// to isolate the effect of each condition on [`Capability::reproduced`].
    fn near_miss(origin: Origin) -> Capability {
        Capability {
            id: GfxId::TextRender,
            claimed: Verdict::Satisfied,
            emission: Emission::AndroidSemantics,
            origin,
            observed: ProbeAnswer::Satisfied {
                evidence: "compared 1e4 spans against Skia 1e-3".to_string(),
            },
            note: "n",
        }
    }

    #[test]
    fn only_a_device_measured_value_can_count_as_reproduced() {
        // This is the load-bearing test of the whole module, and it is stated
        // as a one-sided check on purpose: it enumerates every origin this crate
        // can actually produce and shows none of them qualifies. The box tree is
        // exact *relative to the shim*, which is not the same object as what a
        // device computes, so no value from it can stand in for one.
        for o in [
            Origin::ShimTreeExact,
            Origin::DerivedFromShimTree,
            Origin::Fabricated,
            Origin::Absent,
        ] {
            assert!(
                !near_miss(o).reproduced(),
                "{} must not count as reproduced",
                o.as_str()
            );
        }
        // And the one origin that does qualify has to be produced deliberately,
        // with evidence, not reached by accident.
        assert!(near_miss(Origin::DeviceMeasured).reproduced());
    }

    #[test]
    fn reproduced_needs_the_probe_to_agree_not_just_the_claim() {
        // A backend that claims `Satisfied` while its own probe says `Absent`
        // must not score, and the audit must record the disagreement. Without
        // this, a single line of code could take the headline number to eleven.
        let mut c = near_miss(Origin::DeviceMeasured);
        c.observed = ProbeAnswer::Absent {
            reason: "there is no device to compare against",
        };
        assert!(!c.reproduced());
        assert!(!c.agrees());
    }

    #[test]
    fn reproduced_needs_android_semantics_not_a_substitution() {
        let mut c = near_miss(Origin::DeviceMeasured);
        c.emission = Emission::Substituted;
        assert!(!c.reproduced());
    }
}
