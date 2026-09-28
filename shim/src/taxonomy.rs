//! The join to [`docs/divergence-taxonomy.md`](../../docs/divergence-taxonomy.md).
//!
//! Every observation the shim records is worth nothing to the study until it
//! carries the ID of the substrate assumption it exercises. An event that says
//! "read `/proc/self/status`" is a log line; an event that says "read
//! `/proc/self/status` → `SUB.TRUST.DEBUG_DETECT`" is a measurement, because the
//! same ID appears in `substrate_probe_hits[]` on a device capture and the two
//! become diffable.
//!
//! # Why the IDs are checked here at all
//!
//! The oracle schema deliberately validates the *shape* of an `assumption_id`
//! and not its membership, so that the taxonomy can grow without invalidating
//! old recordings. That is the right call for a long-lived evidence format and
//! the wrong call for a compile-time constant, so this module does the
//! membership check instead: [`AssumptionId::parse`] rejects an ID that is
//! well-shaped but not in the registry, and `tests/conformance.rs` fails if an
//! ID in the taxonomy document is missing from [`ALL`]. Neither side can drift
//! without a test noticing.
//!
//! # Severity, and the honest reading of it
//!
//! [`AssumptionId::class`] is the trichotomy from the taxonomy. It is *not* a
//! prediction of what an app does — it is what the taxonomy says happens when
//! the assumption is violated, recorded at capture time so an analyst joining
//! the two arms does not have to look it up and cannot get it wrong.

use std::fmt;
use std::str::FromStr;

use crate::error::ShimError;

/// The coarse family, matching the two-level prefix of every ID in the taxonomy.
/// The oracle schema has the identical enum under `divergence_family`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    Build,
    Trust,
    Kernel,
    Ipc,
    Fs,
    Res,
    Time,
    Cpu,
    Mem,
    Gfx,
    Native,
    Net,
    Hw,
    Fw,
    Input,
    Pwr,
}

impl Family {
    /// All sixteen, in the taxonomy's own order.
    pub const ALL: [Family; 16] = [
        Family::Build,
        Family::Trust,
        Family::Kernel,
        Family::Ipc,
        Family::Fs,
        Family::Res,
        Family::Time,
        Family::Cpu,
        Family::Mem,
        Family::Gfx,
        Family::Native,
        Family::Net,
        Family::Hw,
        Family::Fw,
        Family::Input,
        Family::Pwr,
    ];

    /// The `SUB.<FAMILY>` token, e.g. `"SUB.NET"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Build => "SUB.BUILD",
            Family::Trust => "SUB.TRUST",
            Family::Kernel => "SUB.KERNEL",
            Family::Ipc => "SUB.IPC",
            Family::Fs => "SUB.FS",
            Family::Res => "SUB.RES",
            Family::Time => "SUB.TIME",
            Family::Cpu => "SUB.CPU",
            Family::Mem => "SUB.MEM",
            Family::Gfx => "SUB.GFX",
            Family::Native => "SUB.NATIVE",
            Family::Net => "SUB.NET",
            Family::Hw => "SUB.HW",
            Family::Fw => "SUB.FW",
            Family::Input => "SUB.INPUT",
            Family::Pwr => "SUB.PWR",
        }
    }

    /// Parse a family token. `None` for anything not in the registry.
    pub fn parse(s: &str) -> Option<Family> {
        Family::ALL.into_iter().find(|f| f.as_str() == s)
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The trichotomy: what an app does when the assumption is violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymptomClass {
    Degrade,
    Refuse,
    Misbehave,
    Unknown,
}

impl SymptomClass {
    /// The oracle `symptom_class` token.
    pub fn as_str(self) -> &'static str {
        match self {
            SymptomClass::Degrade => "degrade",
            SymptomClass::Refuse => "refuse",
            SymptomClass::Misbehave => "misbehave",
            SymptomClass::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SymptomClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A registered substrate assumption.
///
/// Only the IDs the shim actually produces are enumerated. That is a
/// deliberate subset of the taxonomy's 145: the shim is an observation layer,
/// so it emits an ID when it *observed something*, not when a class merely
/// exists. `tests/conformance.rs` asserts the reverse direction — that every ID
/// in this module also appears in the taxonomy document — so the subset cannot
/// drift into fiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssumptionId {
    // --- SUB.BUILD
    /// `Build.FINGERPRINT` and friends. A field read.
    BuildFingerprint,
    /// `Build.VERSION.SDK_INT` / `RELEASE`. A field read.
    BuildSdkInt,
    /// Emulator/container detection inputs.
    BuildEmulator,
    /// `PackageManager.hasSystemFeature`.
    BuildAbilities,
    /// `Build.TAGS` / `Build.SERIAL`.
    BuildTags,
    // --- SUB.TRUST
    /// `/proc/self/status` `TracerPid`, `Debug.isDebuggerConnected()`.
    TrustDebugDetect,
    /// `Signature` / `GET_SIGNATURES`, and the platform trust store.
    TrustCertTrust,
    // --- SUB.KERNEL
    /// Any `/proc/**` read.
    KernelProcSelf,
    /// Any `/sys/**` read.
    KernelSysClass,
    // --- SUB.IPC
    /// `PackageManager` query about an app other than the subject.
    IpcPackageManagerOther,
    /// `PackageManager` self-query.
    IpcPackageManagerSelf,
    /// `Context.getSystemService`.
    IpcSystemService,
    // --- SUB.FS
    /// App-private data directory.
    FsDataDir,
    /// Any absolute path that is not under the data dir: `/system`, `/sdcard`, …
    FsSystemLayout,
    /// `System.loadLibrary` / `System.load`.
    FsLibPath,
    // --- SUB.RES
    /// `Resources` / `getIdentifier`.
    ResArsc,
    // --- SUB.FW
    /// A class that resolved to the shim.
    FwClassLoader,
    /// A class that resolved to nothing.
    FwDynamicCode,
    /// `Parcelable` / `Bundle` marshalling.
    FwSerialization,
    /// `android.webkit.WebView` touched.
    FwWebview,
    /// An `invokedynamic` call site the substrate could not resolve.
    ///
    /// Added with the interpreter integration, because until something executed
    /// `INVOKE-DYNAMIC` the shim had no occasion to *observe* one: a class merely
    /// existing is not an observation, and the enum is a subset chosen for what
    /// was observed. Now that bytecode runs, the refusal is observed on every
    /// Java 8+ lambda and method reference, and `SUB.FW.INVOKEDYNAMIC` — marked
    /// COMMON in the taxonomy — has a count behind it.
    FwInvokeDynamic,
    // --- SUB.NET
    /// Any outbound request.
    NetEgress,
    /// DNS-shaped work inside a request.
    NetDns,
    // --- SUB.NATIVE
    /// `System.loadLibrary` / an app-declared `native` method.
    NativeLoadLibrary,
    /// A `native` method invoked with no implementation behind it.
    NativeJniEntry,
    // --- SUB.TIME
    /// `SystemClock` reads.
    TimeMonotonic,
    /// Frame / vsync scheduling.
    TimeVsync,
    // --- SUB.GFX
    /// Canvas/text measurement and the draw pass.
    GfxTextRender,
}

impl AssumptionId {
    /// Every ID the shim can emit.
    pub const ALL: [AssumptionId; 28] = [
        AssumptionId::BuildFingerprint,
        AssumptionId::BuildSdkInt,
        AssumptionId::BuildEmulator,
        AssumptionId::BuildAbilities,
        AssumptionId::BuildTags,
        AssumptionId::TrustDebugDetect,
        AssumptionId::TrustCertTrust,
        AssumptionId::KernelProcSelf,
        AssumptionId::KernelSysClass,
        AssumptionId::IpcPackageManagerOther,
        AssumptionId::IpcPackageManagerSelf,
        AssumptionId::IpcSystemService,
        AssumptionId::FsDataDir,
        AssumptionId::FsSystemLayout,
        AssumptionId::FsLibPath,
        AssumptionId::ResArsc,
        AssumptionId::FwClassLoader,
        AssumptionId::FwDynamicCode,
        AssumptionId::FwSerialization,
        AssumptionId::FwWebview,
        AssumptionId::FwInvokeDynamic,
        AssumptionId::NetEgress,
        AssumptionId::NetDns,
        AssumptionId::NativeLoadLibrary,
        AssumptionId::NativeJniEntry,
        AssumptionId::TimeMonotonic,
        AssumptionId::TimeVsync,
        AssumptionId::GfxTextRender,
    ];

    /// The full taxonomy ID, e.g. `"SUB.NET.EGRESS"`.
    pub fn as_str(self) -> &'static str {
        match self {
            AssumptionId::BuildFingerprint => "SUB.BUILD.FINGERPRINT",
            AssumptionId::BuildSdkInt => "SUB.BUILD.SDK_INT",
            AssumptionId::BuildEmulator => "SUB.BUILD.EMULATOR",
            AssumptionId::BuildAbilities => "SUB.BUILD.ABILITIES",
            AssumptionId::BuildTags => "SUB.BUILD.TAGS",
            AssumptionId::TrustDebugDetect => "SUB.TRUST.DEBUG_DETECT",
            AssumptionId::TrustCertTrust => "SUB.TRUST.CERT_TRUST",
            AssumptionId::KernelProcSelf => "SUB.KERNEL.PROC_SELF",
            AssumptionId::KernelSysClass => "SUB.KERNEL.SYS_BLOCK",
            AssumptionId::IpcPackageManagerOther => "SUB.IPC.PACKAGE_MANAGER_OTHER",
            AssumptionId::IpcPackageManagerSelf => "SUB.IPC.PACKAGE_MANAGER_SELF",
            AssumptionId::IpcSystemService => "SUB.IPC.SYSTEM_SERVICE",
            AssumptionId::FsDataDir => "SUB.FS.DATA_DIR",
            AssumptionId::FsSystemLayout => "SUB.FS.SYSTEM_LAYOUT",
            AssumptionId::FsLibPath => "SUB.FS.LIB_PATH",
            AssumptionId::ResArsc => "SUB.RES.ARSC",
            AssumptionId::FwClassLoader => "SUB.FW.CLASS_LOADER",
            AssumptionId::FwDynamicCode => "SUB.FW.DYNAMIC_CODE",
            AssumptionId::FwSerialization => "SUB.FW.SERIALIZATION",
            AssumptionId::FwWebview => "SUB.FW.WEBVIEW",
            AssumptionId::FwInvokeDynamic => "SUB.FW.INVOKEDYNAMIC",
            AssumptionId::NetEgress => "SUB.NET.EGRESS",
            AssumptionId::NetDns => "SUB.NET.DNS",
            AssumptionId::NativeLoadLibrary => "SUB.NATIVE.LOAD_LIBRARY",
            AssumptionId::NativeJniEntry => "SUB.NATIVE.JNI_ENTRY",
            AssumptionId::TimeMonotonic => "SUB.TIME.MONOTONIC",
            AssumptionId::TimeVsync => "SUB.TIME.VSYNC",
            AssumptionId::GfxTextRender => "SUB.GFX.TEXT_RENDER",
        }
    }

    /// The family this ID belongs to.
    pub fn family(self) -> Family {
        let s = self.as_str();
        Family::parse(&s[..s.rfind('.').unwrap_or(s.len())]).unwrap_or(Family::Fw)
    }

    /// The class from the taxonomy's trichotomy, copied from that document's own
    /// `Class` column rather than re-derived. Recording it at capture time means
    /// an analyst joining the two arms never has to look it up and cannot get it
    /// wrong; `tests/conformance.rs` re-checks every value against the markdown
    /// so the two cannot drift.
    ///
    /// Two rows in the taxonomy carry two classes (`SUB.IPC.SYSTEM_SERVICE` and
    /// `SUB.RES.ARSC`, both `REFUSE / DEGRADE`). The shim records the stronger
    /// one, `Refuse`, because that is the outcome the observation layer is in a
    /// position to see: a null service or a zero resource id is a degradation
    /// the app may absorb silently, whereas a class that is not there at all is
    /// a refusal.
    pub fn class(self) -> SymptomClass {
        match self {
            AssumptionId::BuildFingerprint
            | AssumptionId::BuildEmulator
            | AssumptionId::BuildTags
            | AssumptionId::TrustDebugDetect
            | AssumptionId::IpcSystemService
            | AssumptionId::FsSystemLayout
            | AssumptionId::FsLibPath
            | AssumptionId::ResArsc
            | AssumptionId::FwClassLoader
            | AssumptionId::FwDynamicCode
            | AssumptionId::FwWebview
            | AssumptionId::FwInvokeDynamic
            | AssumptionId::NetEgress
            | AssumptionId::NetDns
            | AssumptionId::NativeLoadLibrary
            | AssumptionId::NativeJniEntry
            | AssumptionId::TimeVsync => SymptomClass::Refuse,
            AssumptionId::BuildAbilities
            | AssumptionId::TrustCertTrust
            | AssumptionId::KernelProcSelf
            | AssumptionId::KernelSysClass
            | AssumptionId::TimeMonotonic
            | AssumptionId::GfxTextRender => SymptomClass::Degrade,
            AssumptionId::BuildSdkInt
            | AssumptionId::IpcPackageManagerOther
            | AssumptionId::IpcPackageManagerSelf
            | AssumptionId::FsDataDir
            | AssumptionId::FwSerialization => SymptomClass::Misbehave,
        }
    }

    /// Look an ID up by its full string. Well-shaped but unregistered IDs fail,
    /// which is the membership check the oracle schema deliberately omits.
    pub fn lookup(s: &str) -> Option<AssumptionId> {
        AssumptionId::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// Parse a full ID, or explain why it is not in the registry.
    pub fn parse(s: &str) -> Result<AssumptionId, ShimError> {
        if !Self::well_shaped(s) {
            return Err(ShimError::Encode(format!(
                "{s:?} is not a SUB.<FAMILY>[.<LEAF>] id"
            )));
        }
        AssumptionId::lookup(s).ok_or_else(|| {
            ShimError::Encode(format!(
                "{s:?} is well shaped but not in the shim's registry"
            ))
        })
    }

    /// The shape rule the oracle schema enforces, duplicated so the shim can
    /// reject a malformed ID without pulling in the schema.
    fn well_shaped(s: &str) -> bool {
        let mut parts = s.split('.');
        if parts.next() != Some("SUB") {
            return false;
        }
        let mut n = 0;
        for p in parts {
            n += 1;
            if p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return false;
            }
        }
        n >= 2
    }
}

impl fmt::Display for AssumptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AssumptionId {
    type Err = ShimError;

    fn from_str(s: &str) -> Result<AssumptionId, ShimError> {
        AssumptionId::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_round_trips_through_its_string() {
        for id in AssumptionId::ALL {
            assert_eq!(AssumptionId::lookup(id.as_str()), Some(id));
        }
    }

    #[test]
    fn every_id_belongs_to_a_real_family() {
        for id in AssumptionId::ALL {
            let s = id.as_str();
            let prefix = &s[..s.rfind('.').unwrap_or(0)];
            assert!(
                Family::parse(prefix).is_some(),
                "{id} has no registered family {prefix}"
            );
        }
    }

    #[test]
    fn unregistered_but_well_shaped_ids_are_rejected() {
        // The whole point of `lookup`: shape is not membership.
        assert!(AssumptionId::well_shaped("SUB.NET.NOT_A_REAL_LEAF"));
        assert!(AssumptionId::parse("SUB.NET.NOT_A_REAL_LEAF").is_err());
    }

    #[test]
    fn malformed_ids_are_rejected() {
        for bad in [
            "SUB",
            "NET.EGRESS",
            "sub.net.egress",
            "SUB.net",
            "",
            "SUB..EGRESS",
        ] {
            assert!(
                AssumptionId::parse(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
