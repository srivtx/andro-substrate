//! The complete divergence taxonomy, as a compile-time registry.
//!
//! # Why this file exists at all, when `docs/divergence-taxonomy.md` already
//! //! exists
//!!
//! The taxonomy document is a *hypothesis space*, pre-registered, and it is
//! normative for the study. But `compiler/IR.md` requires that every emitted
//! host stub "records, at emit time, which taxonomy ID its absence would
//! predicate", and requires that a stub generated without such an attribution
//! is a defect. An attribution therefore has to exist as a *value* at emission
//! time, in Rust, where a typo is a compile error and a missing case is a
//! non-exhaustive match. Prose cannot enforce that. This file does.
//!
//! # It is the full 145, not a subset
//!
//! The hand-written shim enumerates 28 of the 145 ([`shim/src/taxonomy.rs`]),
//! and says why: it is an *observation* layer, so it emits an ID when it
//! observed something, and a class merely existing is not an observation. That
//! is the right rule for a shim and the wrong rule for a synthesiser.
//!
//! A synthesiser emits a stub for a method that was *never called and may never
//! be called*. "Not observed" is precisely the situation in which the
//! attribution is still needed, because the attribution is not about what
//! happened — it is about what the app would have assumed if the stub were
//! absent. Restricting the registry to 28 would make the majority of a
//! generated host unattributable, and an unattributable stub is a defect.
//!
//! # Membership is checked, in both directions
//!
//! `tests/taxonomy_registry.rs` asserts that these 145 are exactly the IDs in
//! the document, in the same order. Neither side can drift without a test
//! failing, which is the same defence [`AssumptionId::parse`] gives the shim
//! and the reason it exists there too.
//!
//! # The `Class` column is copied, not re-derived
//!
//! [`SymptomClass`] is the taxonomy's own trichotomy, transcribed from the
//! document. Six rows carry two classes (e.g. `SUB.IPC.SYSTEM_SERVICE` is
//! `REFUSE / DEGRADE`). Those resolve to the **stronger** outcome, `Refuse`,
//! for the reason the shim gives: a degradation the app may absorb silently is
//! a different — and less interesting — observation than a refusal, and an
//! instrument must not record the milder outcome for the harsher one. The
//! second class is retained in [`SymptomClass::also_possible`] so the
//! information is recorded rather than discarded.
//!
//! # Hard walls are a property of the ID, not of a run
//!
//! [`AssumptionId::hard_wall`] marks §17.1's set: assumptions that fail
//! *independently of implementation quality*. A synthesiser that returns a
//! plausible value for `SUB.NET.EGRESS` has not made the app work; it has
//! made the app wait forever for something that can never arrive, which is a
//! worse measurement because it looks like the app's problem.

use core::fmt;
use core::str::FromStr;

/// The coarse family: the two-level prefix of every ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// `SUB.BUILD`
    Build,
    /// `SUB.TRUST`
    Trust,
    /// `SUB.KERNEL`
    Kernel,
    /// `SUB.IPC`
    Ipc,
    /// `SUB.FS`
    Fs,
    /// `SUB.RES`
    Res,
    /// `SUB.TIME`
    Time,
    /// `SUB.CPU`
    Cpu,
    /// `SUB.MEM`
    Mem,
    /// `SUB.GFX`
    Gfx,
    /// `SUB.NATIVE`
    Native,
    /// `SUB.NET`
    Net,
    /// `SUB.HW`
    Hw,
    /// `SUB.FW`
    Fw,
    /// `SUB.INPUT`
    Input,
    /// `SUB.PWR`
    Pwr,
}

impl Family {
    /// Every family, in the taxonomy document's own order. The count is 16.
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

    /// The `SUB.<FAMILY>` token.
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

    /// Look a family up by token. `None` for anything unregistered.
    pub fn parse(s: &str) -> Option<Family> {
        Family::ALL.into_iter().find(|f| f.as_str() == s)
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// The trichotomy: what an app does when the assumption is violated.
///
/// This is *not* a prediction about any particular app. It is what the
/// taxonomy says happens when the assumption is violated, transcribed so that
/// an analyst joining the substrate arm to a device capture never has to look
/// it up and cannot get it wrong.
///
/// [`SymptomClass::Misbehave`] is the class the whole design of this module
/// serves: it is the only class an evaluation that reports crash counts will
/// miss, and it is the class a *fabricated* answer silently promotes itself
/// into. Returning a plausible `Build.FINGERPRINT` does not make an app work;
/// it converts a loud `REFUSE` into a silent `MISBEHAVE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SymptomClass {
    /// The app runs; a capability is reduced, usually visibly.
    Degrade,
    /// The app will not start, or blocks a flow, usually visibly.
    Refuse,
    /// The app appears to run and produces silently wrong results.
    Misbehave,
}

impl SymptomClass {
    /// All three, strongest first. [`SymptomClass::Refuse`] sorts first because
    /// six taxonomy rows carry two classes and resolve to the stronger one.
    pub const ALL: [SymptomClass; 3] = [SymptomClass::Refuse, SymptomClass::Misbehave, SymptomClass::Degrade];

    /// The oracle `symptom_class` token.
    pub fn as_str(self) -> &'static str {
        match self {
            SymptomClass::Degrade => "degrade",
            SymptomClass::Refuse => "refuse",
            SymptomClass::Misbehave => "misbehave",
        }
    }
}

impl fmt::Display for SymptomClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

/// A registered substrate assumption.
///
/// All 145, exhaustively, in the taxonomy document's own order. The order is not
/// cosmetic: `ALL` is what a conformance test walks to prove this registry and
/// `docs/divergence-taxonomy.md` have not drifted apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AssumptionId {
    /// `SUB.BUILD.FINGERPRINT`
    BuildFingerprint,
    /// `SUB.BUILD.MODEL`
    BuildModel,
    /// `SUB.BUILD.MANUFACTURER`
    BuildManufacturer,
    /// `SUB.BUILD.BRAND`
    BuildBrand,
    /// `SUB.BUILD.PRODUCT`
    BuildProduct,
    /// `SUB.BUILD.DEVICE`
    BuildDevice,
    /// `SUB.BUILD.HARDWARE`
    BuildHardware,
    /// `SUB.BUILD.BOARD`
    BuildBoard,
    /// `SUB.BUILD.TAGS`
    BuildTags,
    /// `SUB.BUILD.SERIAL`
    BuildSerial,
    /// `SUB.BUILD.BOOTLOADER`
    BuildBootloader,
    /// `SUB.BUILD.RADIO`
    BuildRadio,
    /// `SUB.BUILD.SDK_INT`
    BuildSdkInt,
    /// `SUB.BUILD.EMULATOR`
    BuildEmulator,
    /// `SUB.BUILD.ABILITIES`
    BuildAbilities,
    /// `SUB.TRUST.PLAY_INTEGRITY`
    TrustPlayIntegrity,
    /// `SUB.TRUST.SAFETYNET`
    TrustSafetynet,
    /// `SUB.TRUST.PLAY_SERVICES`
    TrustPlayServices,
    /// `SUB.TRUST.KEYSTORE_ANDROIDKEYSTORE`
    TrustKeystoreAndroidkeystore,
    /// `SUB.TRUST.ATTESTATION_KEY`
    TrustAttestationKey,
    /// `SUB.TRUST.ROOT_DETECT`
    TrustRootDetect,
    /// `SUB.TRUST.DEBUG_DETECT`
    TrustDebugDetect,
    /// `SUB.TRUST.GMS_ACCOUNT`
    TrustGmsAccount,
    /// `SUB.TRUST.CERT_TRUST`
    TrustCertTrust,
    /// `SUB.KERNEL.PROC_SELF`
    KernelProcSelf,
    /// `SUB.KERNEL.PROC_STAT`
    KernelProcStat,
    /// `SUB.KERNEL.PROC_UPTIME`
    KernelProcUptime,
    /// `SUB.KERNEL.PROC_CPUINFO`
    KernelProcCpuinfo,
    /// `SUB.KERNEL.PROC_MEMINFO`
    KernelProcMeminfo,
    /// `SUB.KERNEL.SYS_POWER`
    KernelSysPower,
    /// `SUB.KERNEL.SYS_THERMAL`
    KernelSysThermal,
    /// `SUB.KERNEL.SYS_BLOCK`
    KernelSysBlock,
    /// `SUB.KERNEL.SYS_CLASS_NET`
    KernelSysClassNet,
    /// `SUB.KERNEL.SIGNAL_MODEL`
    KernelSignalModel,
    /// `SUB.IPC.BINDER_DEV`
    IpcBinderDev,
    /// `SUB.IPC.SERVICE_MANAGER`
    IpcServiceManager,
    /// `SUB.IPC.SYSTEM_SERVICE`
    IpcSystemService,
    /// `SUB.IPC.ACTIVITY_MANAGER`
    IpcActivityManager,
    /// `SUB.IPC.WINDOW_MANAGER`
    IpcWindowManager,
    /// `SUB.IPC.PACKAGE_MANAGER_SELF`
    IpcPackageManagerSelf,
    /// `SUB.IPC.PACKAGE_MANAGER_OTHER`
    IpcPackageManagerOther,
    /// `SUB.IPC.BROADCAST`
    IpcBroadcast,
    /// `SUB.IPC.ALARM_MANAGER`
    IpcAlarmManager,
    /// `SUB.IPC.JOB_SCHEDULER`
    IpcJobScheduler,
    /// `SUB.IPC.CONNECTIVITY_MANAGER`
    IpcConnectivityManager,
    /// `SUB.IPC.CONTENT_PROVIDER`
    IpcContentProvider,
    /// `SUB.IPC.NOTIFICATION`
    IpcNotification,
    /// `SUB.IPC.BINDER_THREADPOOL`
    IpcBinderThreadpool,
    /// `SUB.FS.SYSTEM_LAYOUT`
    FsSystemLayout,
    /// `SUB.FS.DATA_DIR`
    FsDataDir,
    /// `SUB.FS.EXTERNAL_STORAGE`
    FsExternalStorage,
    /// `SUB.FS.SELINUX_CONTEXT`
    FsSelinuxContext,
    /// `SUB.FS.LIB_PATH`
    FsLibPath,
    /// `SUB.FS.ASHMEM`
    FsAshmem,
    /// `SUB.FS.PERM_MODEL`
    FsPermModel,
    /// `SUB.FS.PACKAGE_PATH`
    FsPackagePath,
    /// `SUB.FS.OBB`
    FsObb,
    /// `SUB.FS.MOUNT_NS`
    FsMountNs,
    /// `SUB.RES.ARSC`
    ResArsc,
    /// `SUB.RES.QUALIFIER`
    ResQualifier,
    /// `SUB.RES.LOCALE`
    ResLocale,
    /// `SUB.RES.TIMEZONE`
    ResTimezone,
    /// `SUB.RES.FONT_SCALE`
    ResFontScale,
    /// `SUB.RES.DISPLAY_METRICS`
    ResDisplayMetrics,
    /// `SUB.RES.PACKAGE_RESOLVER`
    ResPackageResolver,
    /// `SUB.RES.SYSTEM_FONTS`
    ResSystemFonts,
    /// `SUB.TIME.MONOTONIC`
    TimeMonotonic,
    /// `SUB.TIME.ELAPSED_REALTIME`
    TimeElapsedRealtime,
    /// `SUB.TIME.WALL_CLOCK`
    TimeWallClock,
    /// `SUB.TIME.VSYNC`
    TimeVsync,
    /// `SUB.TIME.SLEEP`
    TimeSleep,
    /// `SUB.TIME.SLOW_OPERATION`
    TimeSlowOperation,
    /// `SUB.TIME.ANR_BUDGET`
    TimeAnrBudget,
    /// `SUB.CPU.CORE_COUNT`
    CpuCoreCount,
    /// `SUB.CPU.ARCH`
    CpuArch,
    /// `SUB.CPU.TIERING`
    CpuTiering,
    /// `SUB.CPU.GC`
    CpuGc,
    /// `SUB.CPU.ATOMIC`
    CpuAtomic,
    /// `SUB.CPU.THREAD_AFFINITY`
    CpuThreadAffinity,
    /// `SUB.CPU.NUMERIC`
    CpuNumeric,
    /// `SUB.MEM.DIRECT_BYTEBUFFER`
    MemDirectBytebuffer,
    /// `SUB.MEM.MMAP`
    MemMmap,
    /// `SUB.MEM.LARGE_HEAP`
    MemLargeHeap,
    /// `SUB.MEM.HW_CAPS`
    MemHwCaps,
    /// `SUB.MEM.LMK`
    MemLmk,
    /// `SUB.MEM.NATIVE_HEAP`
    MemNativeHeap,
    /// `SUB.MEM.ENTROPY`
    MemEntropy,
    /// `SUB.NATIVE.LOAD_LIBRARY`
    NativeLoadLibrary,
    /// `SUB.NATIVE.JNI_ENTRY`
    NativeJniEntry,
    /// `SUB.NATIVE.EXEC_SEGMENTS`
    NativeExecSegments,
    /// `SUB.NATIVE.LINKER_NS`
    NativeLinkerNs,
    /// `SUB.NATIVE.ISA`
    NativeIsa,
    /// `SUB.NATIVE.SIGNAL_CRASH`
    NativeSignalCrash,
    /// `SUB.NET.EGRESS`
    NetEgress,
    /// `SUB.NET.DNS`
    NetDns,
    /// `SUB.NET.TLS_TRUST`
    NetTlsTrust,
    /// `SUB.NET.CLEARTEXT_POLICY`
    NetCleartextPolicy,
    /// `SUB.NET.PROXY`
    NetProxy,
    /// `SUB.NET.NATIVE_HTTP`
    NetNativeHttp,
    /// `SUB.NET.WEBSOCKET`
    NetWebsocket,
    /// `SUB.NET.QUIC`
    NetQuic,
    /// `SUB.NET.BACKEND_VERDICT`
    NetBackendVerdict,
    /// `SUB.GFX.EGL_CONTEXT`
    GfxEglContext,
    /// `SUB.GFX.GLES_VERSION`
    GfxGlesVersion,
    /// `SUB.GFX.VULKAN`
    GfxVulkan,
    /// `SUB.GFX.EXTENSIONS`
    GfxExtensions,
    /// `SUB.GFX.RENDERER_STRING`
    GfxRendererString,
    /// `SUB.GFX.SURFACE`
    GfxSurface,
    /// `SUB.GFX.HW_COMPOSITION`
    GfxHwComposition,
    /// `SUB.GFX.FRAME_BUDGET`
    GfxFrameBudget,
    /// `SUB.GFX.SCREEN_ON`
    GfxScreenOn,
    /// `SUB.GFX.CAMERA_PIPE`
    GfxCameraPipe,
    /// `SUB.GFX.TEXT_RENDER`
    GfxTextRender,
    /// `SUB.HW.SENSORS`
    HwSensors,
    /// `SUB.HW.CAMERA`
    HwCamera,
    /// `SUB.HW.LOCATION`
    HwLocation,
    /// `SUB.HW.BLUETOOTH`
    HwBluetooth,
    /// `SUB.HW.NFC`
    HwNfc,
    /// `SUB.HW.VIBRATE`
    HwVibrate,
    /// `SUB.HW.TELEPHONY`
    HwTelephony,
    /// `SUB.HW.BIOMETRIC`
    HwBiometric,
    /// `SUB.HW.CONTACTS_SMS`
    HwContactsSms,
    /// `SUB.HW.PRINTER_SCANNER`
    HwPrinterScanner,
    /// `SUB.FW.CLASS_LOADER`
    FwClassLoader,
    /// `SUB.FW.REFLECTION`
    FwReflection,
    /// `SUB.FW.INVOKEDYNAMIC`
    FwInvokedynamic,
    /// `SUB.FW.NON_SDK_API`
    FwNonSdkApi,
    /// `SUB.FW.SERIALIZATION`
    FwSerialization,
    /// `SUB.FW.DYNAMIC_CODE`
    FwDynamicCode,
    /// `SUB.FW.ACTIVITY_LIFECYCLE`
    FwActivityLifecycle,
    /// `SUB.FW.CONTENT_PROVIDER_INIT`
    FwContentProviderInit,
    /// `SUB.FW.CRYPTO_PROVIDER`
    FwCryptoProvider,
    /// `SUB.FW.WEBVIEW`
    FwWebview,
    /// `SUB.FW.PROCESS_ISOLATION`
    FwProcessIsolation,
    /// `SUB.INPUT.INPUT_EVENT`
    InputInputEvent,
    /// `SUB.INPUT.IME`
    InputIme,
    /// `SUB.INPUT.WINDOW_FOCUS`
    InputWindowFocus,
    /// `SUB.INPUT.HAPTIC`
    InputHaptic,
    /// `SUB.PWR.WAKE_LOCK`
    PwrWakeLock,
    /// `SUB.PWR.DOZE`
    PwrDoze,
    /// `SUB.PWR.APP_STANDBY`
    PwrAppStandby,
    /// `SUB.PWR.BOOT_COMPLETED`
    PwrBootCompleted,
    /// `SUB.PWR.PROCESS_REAPER`
    PwrProcessReaper,
    /// `SUB.PWR.BATTERY`
    PwrBattery,
    /// `SUB.PWR.UPTIME_POLICY`
    PwrUptimePolicy,
}

impl AssumptionId {
    /// Every ID, in taxonomy order. The count is 145;
    /// `tests/taxonomy_registry.rs` asserts it, because a silently shortened list is
    /// an unattributable stub waiting to happen.
    pub const ALL: [AssumptionId; 145] = [
        AssumptionId::BuildFingerprint,
        AssumptionId::BuildModel,
        AssumptionId::BuildManufacturer,
        AssumptionId::BuildBrand,
        AssumptionId::BuildProduct,
        AssumptionId::BuildDevice,
        AssumptionId::BuildHardware,
        AssumptionId::BuildBoard,
        AssumptionId::BuildTags,
        AssumptionId::BuildSerial,
        AssumptionId::BuildBootloader,
        AssumptionId::BuildRadio,
        AssumptionId::BuildSdkInt,
        AssumptionId::BuildEmulator,
        AssumptionId::BuildAbilities,
        AssumptionId::TrustPlayIntegrity,
        AssumptionId::TrustSafetynet,
        AssumptionId::TrustPlayServices,
        AssumptionId::TrustKeystoreAndroidkeystore,
        AssumptionId::TrustAttestationKey,
        AssumptionId::TrustRootDetect,
        AssumptionId::TrustDebugDetect,
        AssumptionId::TrustGmsAccount,
        AssumptionId::TrustCertTrust,
        AssumptionId::KernelProcSelf,
        AssumptionId::KernelProcStat,
        AssumptionId::KernelProcUptime,
        AssumptionId::KernelProcCpuinfo,
        AssumptionId::KernelProcMeminfo,
        AssumptionId::KernelSysPower,
        AssumptionId::KernelSysThermal,
        AssumptionId::KernelSysBlock,
        AssumptionId::KernelSysClassNet,
        AssumptionId::KernelSignalModel,
        AssumptionId::IpcBinderDev,
        AssumptionId::IpcServiceManager,
        AssumptionId::IpcSystemService,
        AssumptionId::IpcActivityManager,
        AssumptionId::IpcWindowManager,
        AssumptionId::IpcPackageManagerSelf,
        AssumptionId::IpcPackageManagerOther,
        AssumptionId::IpcBroadcast,
        AssumptionId::IpcAlarmManager,
        AssumptionId::IpcJobScheduler,
        AssumptionId::IpcConnectivityManager,
        AssumptionId::IpcContentProvider,
        AssumptionId::IpcNotification,
        AssumptionId::IpcBinderThreadpool,
        AssumptionId::FsSystemLayout,
        AssumptionId::FsDataDir,
        AssumptionId::FsExternalStorage,
        AssumptionId::FsSelinuxContext,
        AssumptionId::FsLibPath,
        AssumptionId::FsAshmem,
        AssumptionId::FsPermModel,
        AssumptionId::FsPackagePath,
        AssumptionId::FsObb,
        AssumptionId::FsMountNs,
        AssumptionId::ResArsc,
        AssumptionId::ResQualifier,
        AssumptionId::ResLocale,
        AssumptionId::ResTimezone,
        AssumptionId::ResFontScale,
        AssumptionId::ResDisplayMetrics,
        AssumptionId::ResPackageResolver,
        AssumptionId::ResSystemFonts,
        AssumptionId::TimeMonotonic,
        AssumptionId::TimeElapsedRealtime,
        AssumptionId::TimeWallClock,
        AssumptionId::TimeVsync,
        AssumptionId::TimeSleep,
        AssumptionId::TimeSlowOperation,
        AssumptionId::TimeAnrBudget,
        AssumptionId::CpuCoreCount,
        AssumptionId::CpuArch,
        AssumptionId::CpuTiering,
        AssumptionId::CpuGc,
        AssumptionId::CpuAtomic,
        AssumptionId::CpuThreadAffinity,
        AssumptionId::CpuNumeric,
        AssumptionId::MemDirectBytebuffer,
        AssumptionId::MemMmap,
        AssumptionId::MemLargeHeap,
        AssumptionId::MemHwCaps,
        AssumptionId::MemLmk,
        AssumptionId::MemNativeHeap,
        AssumptionId::MemEntropy,
        AssumptionId::NativeLoadLibrary,
        AssumptionId::NativeJniEntry,
        AssumptionId::NativeExecSegments,
        AssumptionId::NativeLinkerNs,
        AssumptionId::NativeIsa,
        AssumptionId::NativeSignalCrash,
        AssumptionId::NetEgress,
        AssumptionId::NetDns,
        AssumptionId::NetTlsTrust,
        AssumptionId::NetCleartextPolicy,
        AssumptionId::NetProxy,
        AssumptionId::NetNativeHttp,
        AssumptionId::NetWebsocket,
        AssumptionId::NetQuic,
        AssumptionId::NetBackendVerdict,
        AssumptionId::GfxEglContext,
        AssumptionId::GfxGlesVersion,
        AssumptionId::GfxVulkan,
        AssumptionId::GfxExtensions,
        AssumptionId::GfxRendererString,
        AssumptionId::GfxSurface,
        AssumptionId::GfxHwComposition,
        AssumptionId::GfxFrameBudget,
        AssumptionId::GfxScreenOn,
        AssumptionId::GfxCameraPipe,
        AssumptionId::GfxTextRender,
        AssumptionId::HwSensors,
        AssumptionId::HwCamera,
        AssumptionId::HwLocation,
        AssumptionId::HwBluetooth,
        AssumptionId::HwNfc,
        AssumptionId::HwVibrate,
        AssumptionId::HwTelephony,
        AssumptionId::HwBiometric,
        AssumptionId::HwContactsSms,
        AssumptionId::HwPrinterScanner,
        AssumptionId::FwClassLoader,
        AssumptionId::FwReflection,
        AssumptionId::FwInvokedynamic,
        AssumptionId::FwNonSdkApi,
        AssumptionId::FwSerialization,
        AssumptionId::FwDynamicCode,
        AssumptionId::FwActivityLifecycle,
        AssumptionId::FwContentProviderInit,
        AssumptionId::FwCryptoProvider,
        AssumptionId::FwWebview,
        AssumptionId::FwProcessIsolation,
        AssumptionId::InputInputEvent,
        AssumptionId::InputIme,
        AssumptionId::InputWindowFocus,
        AssumptionId::InputHaptic,
        AssumptionId::PwrWakeLock,
        AssumptionId::PwrDoze,
        AssumptionId::PwrAppStandby,
        AssumptionId::PwrBootCompleted,
        AssumptionId::PwrProcessReaper,
        AssumptionId::PwrBattery,
        AssumptionId::PwrUptimePolicy,
    ];

    /// The full taxonomy ID, e.g. `"SUB.NET.EGRESS"`.
    pub fn as_str(self) -> &'static str {
        match self {
            AssumptionId::BuildFingerprint => "SUB.BUILD.FINGERPRINT",
            AssumptionId::BuildModel => "SUB.BUILD.MODEL",
            AssumptionId::BuildManufacturer => "SUB.BUILD.MANUFACTURER",
            AssumptionId::BuildBrand => "SUB.BUILD.BRAND",
            AssumptionId::BuildProduct => "SUB.BUILD.PRODUCT",
            AssumptionId::BuildDevice => "SUB.BUILD.DEVICE",
            AssumptionId::BuildHardware => "SUB.BUILD.HARDWARE",
            AssumptionId::BuildBoard => "SUB.BUILD.BOARD",
            AssumptionId::BuildTags => "SUB.BUILD.TAGS",
            AssumptionId::BuildSerial => "SUB.BUILD.SERIAL",
            AssumptionId::BuildBootloader => "SUB.BUILD.BOOTLOADER",
            AssumptionId::BuildRadio => "SUB.BUILD.RADIO",
            AssumptionId::BuildSdkInt => "SUB.BUILD.SDK_INT",
            AssumptionId::BuildEmulator => "SUB.BUILD.EMULATOR",
            AssumptionId::BuildAbilities => "SUB.BUILD.ABILITIES",
            AssumptionId::TrustPlayIntegrity => "SUB.TRUST.PLAY_INTEGRITY",
            AssumptionId::TrustSafetynet => "SUB.TRUST.SAFETYNET",
            AssumptionId::TrustPlayServices => "SUB.TRUST.PLAY_SERVICES",
            AssumptionId::TrustKeystoreAndroidkeystore => "SUB.TRUST.KEYSTORE_ANDROIDKEYSTORE",
            AssumptionId::TrustAttestationKey => "SUB.TRUST.ATTESTATION_KEY",
            AssumptionId::TrustRootDetect => "SUB.TRUST.ROOT_DETECT",
            AssumptionId::TrustDebugDetect => "SUB.TRUST.DEBUG_DETECT",
            AssumptionId::TrustGmsAccount => "SUB.TRUST.GMS_ACCOUNT",
            AssumptionId::TrustCertTrust => "SUB.TRUST.CERT_TRUST",
            AssumptionId::KernelProcSelf => "SUB.KERNEL.PROC_SELF",
            AssumptionId::KernelProcStat => "SUB.KERNEL.PROC_STAT",
            AssumptionId::KernelProcUptime => "SUB.KERNEL.PROC_UPTIME",
            AssumptionId::KernelProcCpuinfo => "SUB.KERNEL.PROC_CPUINFO",
            AssumptionId::KernelProcMeminfo => "SUB.KERNEL.PROC_MEMINFO",
            AssumptionId::KernelSysPower => "SUB.KERNEL.SYS_POWER",
            AssumptionId::KernelSysThermal => "SUB.KERNEL.SYS_THERMAL",
            AssumptionId::KernelSysBlock => "SUB.KERNEL.SYS_BLOCK",
            AssumptionId::KernelSysClassNet => "SUB.KERNEL.SYS_CLASS_NET",
            AssumptionId::KernelSignalModel => "SUB.KERNEL.SIGNAL_MODEL",
            AssumptionId::IpcBinderDev => "SUB.IPC.BINDER_DEV",
            AssumptionId::IpcServiceManager => "SUB.IPC.SERVICE_MANAGER",
            AssumptionId::IpcSystemService => "SUB.IPC.SYSTEM_SERVICE",
            AssumptionId::IpcActivityManager => "SUB.IPC.ACTIVITY_MANAGER",
            AssumptionId::IpcWindowManager => "SUB.IPC.WINDOW_MANAGER",
            AssumptionId::IpcPackageManagerSelf => "SUB.IPC.PACKAGE_MANAGER_SELF",
            AssumptionId::IpcPackageManagerOther => "SUB.IPC.PACKAGE_MANAGER_OTHER",
            AssumptionId::IpcBroadcast => "SUB.IPC.BROADCAST",
            AssumptionId::IpcAlarmManager => "SUB.IPC.ALARM_MANAGER",
            AssumptionId::IpcJobScheduler => "SUB.IPC.JOB_SCHEDULER",
            AssumptionId::IpcConnectivityManager => "SUB.IPC.CONNECTIVITY_MANAGER",
            AssumptionId::IpcContentProvider => "SUB.IPC.CONTENT_PROVIDER",
            AssumptionId::IpcNotification => "SUB.IPC.NOTIFICATION",
            AssumptionId::IpcBinderThreadpool => "SUB.IPC.BINDER_THREADPOOL",
            AssumptionId::FsSystemLayout => "SUB.FS.SYSTEM_LAYOUT",
            AssumptionId::FsDataDir => "SUB.FS.DATA_DIR",
            AssumptionId::FsExternalStorage => "SUB.FS.EXTERNAL_STORAGE",
            AssumptionId::FsSelinuxContext => "SUB.FS.SELINUX_CONTEXT",
            AssumptionId::FsLibPath => "SUB.FS.LIB_PATH",
            AssumptionId::FsAshmem => "SUB.FS.ASHMEM",
            AssumptionId::FsPermModel => "SUB.FS.PERM_MODEL",
            AssumptionId::FsPackagePath => "SUB.FS.PACKAGE_PATH",
            AssumptionId::FsObb => "SUB.FS.OBB",
            AssumptionId::FsMountNs => "SUB.FS.MOUNT_NS",
            AssumptionId::ResArsc => "SUB.RES.ARSC",
            AssumptionId::ResQualifier => "SUB.RES.QUALIFIER",
            AssumptionId::ResLocale => "SUB.RES.LOCALE",
            AssumptionId::ResTimezone => "SUB.RES.TIMEZONE",
            AssumptionId::ResFontScale => "SUB.RES.FONT_SCALE",
            AssumptionId::ResDisplayMetrics => "SUB.RES.DISPLAY_METRICS",
            AssumptionId::ResPackageResolver => "SUB.RES.PACKAGE_RESOLVER",
            AssumptionId::ResSystemFonts => "SUB.RES.SYSTEM_FONTS",
            AssumptionId::TimeMonotonic => "SUB.TIME.MONOTONIC",
            AssumptionId::TimeElapsedRealtime => "SUB.TIME.ELAPSED_REALTIME",
            AssumptionId::TimeWallClock => "SUB.TIME.WALL_CLOCK",
            AssumptionId::TimeVsync => "SUB.TIME.VSYNC",
            AssumptionId::TimeSleep => "SUB.TIME.SLEEP",
            AssumptionId::TimeSlowOperation => "SUB.TIME.SLOW_OPERATION",
            AssumptionId::TimeAnrBudget => "SUB.TIME.ANR_BUDGET",
            AssumptionId::CpuCoreCount => "SUB.CPU.CORE_COUNT",
            AssumptionId::CpuArch => "SUB.CPU.ARCH",
            AssumptionId::CpuTiering => "SUB.CPU.TIERING",
            AssumptionId::CpuGc => "SUB.CPU.GC",
            AssumptionId::CpuAtomic => "SUB.CPU.ATOMIC",
            AssumptionId::CpuThreadAffinity => "SUB.CPU.THREAD_AFFINITY",
            AssumptionId::CpuNumeric => "SUB.CPU.NUMERIC",
            AssumptionId::MemDirectBytebuffer => "SUB.MEM.DIRECT_BYTEBUFFER",
            AssumptionId::MemMmap => "SUB.MEM.MMAP",
            AssumptionId::MemLargeHeap => "SUB.MEM.LARGE_HEAP",
            AssumptionId::MemHwCaps => "SUB.MEM.HW_CAPS",
            AssumptionId::MemLmk => "SUB.MEM.LMK",
            AssumptionId::MemNativeHeap => "SUB.MEM.NATIVE_HEAP",
            AssumptionId::MemEntropy => "SUB.MEM.ENTROPY",
            AssumptionId::NativeLoadLibrary => "SUB.NATIVE.LOAD_LIBRARY",
            AssumptionId::NativeJniEntry => "SUB.NATIVE.JNI_ENTRY",
            AssumptionId::NativeExecSegments => "SUB.NATIVE.EXEC_SEGMENTS",
            AssumptionId::NativeLinkerNs => "SUB.NATIVE.LINKER_NS",
            AssumptionId::NativeIsa => "SUB.NATIVE.ISA",
            AssumptionId::NativeSignalCrash => "SUB.NATIVE.SIGNAL_CRASH",
            AssumptionId::NetEgress => "SUB.NET.EGRESS",
            AssumptionId::NetDns => "SUB.NET.DNS",
            AssumptionId::NetTlsTrust => "SUB.NET.TLS_TRUST",
            AssumptionId::NetCleartextPolicy => "SUB.NET.CLEARTEXT_POLICY",
            AssumptionId::NetProxy => "SUB.NET.PROXY",
            AssumptionId::NetNativeHttp => "SUB.NET.NATIVE_HTTP",
            AssumptionId::NetWebsocket => "SUB.NET.WEBSOCKET",
            AssumptionId::NetQuic => "SUB.NET.QUIC",
            AssumptionId::NetBackendVerdict => "SUB.NET.BACKEND_VERDICT",
            AssumptionId::GfxEglContext => "SUB.GFX.EGL_CONTEXT",
            AssumptionId::GfxGlesVersion => "SUB.GFX.GLES_VERSION",
            AssumptionId::GfxVulkan => "SUB.GFX.VULKAN",
            AssumptionId::GfxExtensions => "SUB.GFX.EXTENSIONS",
            AssumptionId::GfxRendererString => "SUB.GFX.RENDERER_STRING",
            AssumptionId::GfxSurface => "SUB.GFX.SURFACE",
            AssumptionId::GfxHwComposition => "SUB.GFX.HW_COMPOSITION",
            AssumptionId::GfxFrameBudget => "SUB.GFX.FRAME_BUDGET",
            AssumptionId::GfxScreenOn => "SUB.GFX.SCREEN_ON",
            AssumptionId::GfxCameraPipe => "SUB.GFX.CAMERA_PIPE",
            AssumptionId::GfxTextRender => "SUB.GFX.TEXT_RENDER",
            AssumptionId::HwSensors => "SUB.HW.SENSORS",
            AssumptionId::HwCamera => "SUB.HW.CAMERA",
            AssumptionId::HwLocation => "SUB.HW.LOCATION",
            AssumptionId::HwBluetooth => "SUB.HW.BLUETOOTH",
            AssumptionId::HwNfc => "SUB.HW.NFC",
            AssumptionId::HwVibrate => "SUB.HW.VIBRATE",
            AssumptionId::HwTelephony => "SUB.HW.TELEPHONY",
            AssumptionId::HwBiometric => "SUB.HW.BIOMETRIC",
            AssumptionId::HwContactsSms => "SUB.HW.CONTACTS_SMS",
            AssumptionId::HwPrinterScanner => "SUB.HW.PRINTER_SCANNER",
            AssumptionId::FwClassLoader => "SUB.FW.CLASS_LOADER",
            AssumptionId::FwReflection => "SUB.FW.REFLECTION",
            AssumptionId::FwInvokedynamic => "SUB.FW.INVOKEDYNAMIC",
            AssumptionId::FwNonSdkApi => "SUB.FW.NON_SDK_API",
            AssumptionId::FwSerialization => "SUB.FW.SERIALIZATION",
            AssumptionId::FwDynamicCode => "SUB.FW.DYNAMIC_CODE",
            AssumptionId::FwActivityLifecycle => "SUB.FW.ACTIVITY_LIFECYCLE",
            AssumptionId::FwContentProviderInit => "SUB.FW.CONTENT_PROVIDER_INIT",
            AssumptionId::FwCryptoProvider => "SUB.FW.CRYPTO_PROVIDER",
            AssumptionId::FwWebview => "SUB.FW.WEBVIEW",
            AssumptionId::FwProcessIsolation => "SUB.FW.PROCESS_ISOLATION",
            AssumptionId::InputInputEvent => "SUB.INPUT.INPUT_EVENT",
            AssumptionId::InputIme => "SUB.INPUT.IME",
            AssumptionId::InputWindowFocus => "SUB.INPUT.WINDOW_FOCUS",
            AssumptionId::InputHaptic => "SUB.INPUT.HAPTIC",
            AssumptionId::PwrWakeLock => "SUB.PWR.WAKE_LOCK",
            AssumptionId::PwrDoze => "SUB.PWR.DOZE",
            AssumptionId::PwrAppStandby => "SUB.PWR.APP_STANDBY",
            AssumptionId::PwrBootCompleted => "SUB.PWR.BOOT_COMPLETED",
            AssumptionId::PwrProcessReaper => "SUB.PWR.PROCESS_REAPER",
            AssumptionId::PwrBattery => "SUB.PWR.BATTERY",
            AssumptionId::PwrUptimePolicy => "SUB.PWR.UPTIME_POLICY",
        }
    }

    /// The family this ID belongs to.
    pub fn family(self) -> Family {
        match self {
            AssumptionId::BuildFingerprint => Family::Build,
            AssumptionId::BuildModel => Family::Build,
            AssumptionId::BuildManufacturer => Family::Build,
            AssumptionId::BuildBrand => Family::Build,
            AssumptionId::BuildProduct => Family::Build,
            AssumptionId::BuildDevice => Family::Build,
            AssumptionId::BuildHardware => Family::Build,
            AssumptionId::BuildBoard => Family::Build,
            AssumptionId::BuildTags => Family::Build,
            AssumptionId::BuildSerial => Family::Build,
            AssumptionId::BuildBootloader => Family::Build,
            AssumptionId::BuildRadio => Family::Build,
            AssumptionId::BuildSdkInt => Family::Build,
            AssumptionId::BuildEmulator => Family::Build,
            AssumptionId::BuildAbilities => Family::Build,
            AssumptionId::TrustPlayIntegrity => Family::Trust,
            AssumptionId::TrustSafetynet => Family::Trust,
            AssumptionId::TrustPlayServices => Family::Trust,
            AssumptionId::TrustKeystoreAndroidkeystore => Family::Trust,
            AssumptionId::TrustAttestationKey => Family::Trust,
            AssumptionId::TrustRootDetect => Family::Trust,
            AssumptionId::TrustDebugDetect => Family::Trust,
            AssumptionId::TrustGmsAccount => Family::Trust,
            AssumptionId::TrustCertTrust => Family::Trust,
            AssumptionId::KernelProcSelf => Family::Kernel,
            AssumptionId::KernelProcStat => Family::Kernel,
            AssumptionId::KernelProcUptime => Family::Kernel,
            AssumptionId::KernelProcCpuinfo => Family::Kernel,
            AssumptionId::KernelProcMeminfo => Family::Kernel,
            AssumptionId::KernelSysPower => Family::Kernel,
            AssumptionId::KernelSysThermal => Family::Kernel,
            AssumptionId::KernelSysBlock => Family::Kernel,
            AssumptionId::KernelSysClassNet => Family::Kernel,
            AssumptionId::KernelSignalModel => Family::Kernel,
            AssumptionId::IpcBinderDev => Family::Ipc,
            AssumptionId::IpcServiceManager => Family::Ipc,
            AssumptionId::IpcSystemService => Family::Ipc,
            AssumptionId::IpcActivityManager => Family::Ipc,
            AssumptionId::IpcWindowManager => Family::Ipc,
            AssumptionId::IpcPackageManagerSelf => Family::Ipc,
            AssumptionId::IpcPackageManagerOther => Family::Ipc,
            AssumptionId::IpcBroadcast => Family::Ipc,
            AssumptionId::IpcAlarmManager => Family::Ipc,
            AssumptionId::IpcJobScheduler => Family::Ipc,
            AssumptionId::IpcConnectivityManager => Family::Ipc,
            AssumptionId::IpcContentProvider => Family::Ipc,
            AssumptionId::IpcNotification => Family::Ipc,
            AssumptionId::IpcBinderThreadpool => Family::Ipc,
            AssumptionId::FsSystemLayout => Family::Fs,
            AssumptionId::FsDataDir => Family::Fs,
            AssumptionId::FsExternalStorage => Family::Fs,
            AssumptionId::FsSelinuxContext => Family::Fs,
            AssumptionId::FsLibPath => Family::Fs,
            AssumptionId::FsAshmem => Family::Fs,
            AssumptionId::FsPermModel => Family::Fs,
            AssumptionId::FsPackagePath => Family::Fs,
            AssumptionId::FsObb => Family::Fs,
            AssumptionId::FsMountNs => Family::Fs,
            AssumptionId::ResArsc => Family::Res,
            AssumptionId::ResQualifier => Family::Res,
            AssumptionId::ResLocale => Family::Res,
            AssumptionId::ResTimezone => Family::Res,
            AssumptionId::ResFontScale => Family::Res,
            AssumptionId::ResDisplayMetrics => Family::Res,
            AssumptionId::ResPackageResolver => Family::Res,
            AssumptionId::ResSystemFonts => Family::Res,
            AssumptionId::TimeMonotonic => Family::Time,
            AssumptionId::TimeElapsedRealtime => Family::Time,
            AssumptionId::TimeWallClock => Family::Time,
            AssumptionId::TimeVsync => Family::Time,
            AssumptionId::TimeSleep => Family::Time,
            AssumptionId::TimeSlowOperation => Family::Time,
            AssumptionId::TimeAnrBudget => Family::Time,
            AssumptionId::CpuCoreCount => Family::Cpu,
            AssumptionId::CpuArch => Family::Cpu,
            AssumptionId::CpuTiering => Family::Cpu,
            AssumptionId::CpuGc => Family::Cpu,
            AssumptionId::CpuAtomic => Family::Cpu,
            AssumptionId::CpuThreadAffinity => Family::Cpu,
            AssumptionId::CpuNumeric => Family::Cpu,
            AssumptionId::MemDirectBytebuffer => Family::Mem,
            AssumptionId::MemMmap => Family::Mem,
            AssumptionId::MemLargeHeap => Family::Mem,
            AssumptionId::MemHwCaps => Family::Mem,
            AssumptionId::MemLmk => Family::Mem,
            AssumptionId::MemNativeHeap => Family::Mem,
            AssumptionId::MemEntropy => Family::Mem,
            AssumptionId::NativeLoadLibrary => Family::Native,
            AssumptionId::NativeJniEntry => Family::Native,
            AssumptionId::NativeExecSegments => Family::Native,
            AssumptionId::NativeLinkerNs => Family::Native,
            AssumptionId::NativeIsa => Family::Native,
            AssumptionId::NativeSignalCrash => Family::Native,
            AssumptionId::NetEgress => Family::Net,
            AssumptionId::NetDns => Family::Net,
            AssumptionId::NetTlsTrust => Family::Net,
            AssumptionId::NetCleartextPolicy => Family::Net,
            AssumptionId::NetProxy => Family::Net,
            AssumptionId::NetNativeHttp => Family::Net,
            AssumptionId::NetWebsocket => Family::Net,
            AssumptionId::NetQuic => Family::Net,
            AssumptionId::NetBackendVerdict => Family::Net,
            AssumptionId::GfxEglContext => Family::Gfx,
            AssumptionId::GfxGlesVersion => Family::Gfx,
            AssumptionId::GfxVulkan => Family::Gfx,
            AssumptionId::GfxExtensions => Family::Gfx,
            AssumptionId::GfxRendererString => Family::Gfx,
            AssumptionId::GfxSurface => Family::Gfx,
            AssumptionId::GfxHwComposition => Family::Gfx,
            AssumptionId::GfxFrameBudget => Family::Gfx,
            AssumptionId::GfxScreenOn => Family::Gfx,
            AssumptionId::GfxCameraPipe => Family::Gfx,
            AssumptionId::GfxTextRender => Family::Gfx,
            AssumptionId::HwSensors => Family::Hw,
            AssumptionId::HwCamera => Family::Hw,
            AssumptionId::HwLocation => Family::Hw,
            AssumptionId::HwBluetooth => Family::Hw,
            AssumptionId::HwNfc => Family::Hw,
            AssumptionId::HwVibrate => Family::Hw,
            AssumptionId::HwTelephony => Family::Hw,
            AssumptionId::HwBiometric => Family::Hw,
            AssumptionId::HwContactsSms => Family::Hw,
            AssumptionId::HwPrinterScanner => Family::Hw,
            AssumptionId::FwClassLoader => Family::Fw,
            AssumptionId::FwReflection => Family::Fw,
            AssumptionId::FwInvokedynamic => Family::Fw,
            AssumptionId::FwNonSdkApi => Family::Fw,
            AssumptionId::FwSerialization => Family::Fw,
            AssumptionId::FwDynamicCode => Family::Fw,
            AssumptionId::FwActivityLifecycle => Family::Fw,
            AssumptionId::FwContentProviderInit => Family::Fw,
            AssumptionId::FwCryptoProvider => Family::Fw,
            AssumptionId::FwWebview => Family::Fw,
            AssumptionId::FwProcessIsolation => Family::Fw,
            AssumptionId::InputInputEvent => Family::Input,
            AssumptionId::InputIme => Family::Input,
            AssumptionId::InputWindowFocus => Family::Input,
            AssumptionId::InputHaptic => Family::Input,
            AssumptionId::PwrWakeLock => Family::Pwr,
            AssumptionId::PwrDoze => Family::Pwr,
            AssumptionId::PwrAppStandby => Family::Pwr,
            AssumptionId::PwrBootCompleted => Family::Pwr,
            AssumptionId::PwrProcessReaper => Family::Pwr,
            AssumptionId::PwrBattery => Family::Pwr,
            AssumptionId::PwrUptimePolicy => Family::Pwr,
        }
    }

    /// The taxonomy's `Class` column, transcribed.
    ///
    /// This is *not* a prediction about any app. It is what the taxonomy says
    /// happens when the assumption is violated, recorded at emission so an analyst
    /// joining the substrate arm to a device capture never has to look it up.
    ///
    /// `Misbehave` is the class this whole crate is organised around: it is the
    /// only class a crash-counting evaluation misses, and it is the class a
    /// *fabricated* answer silently promotes itself into.
    pub fn class(self) -> SymptomClass {
        match self {
            AssumptionId::BuildFingerprint => SymptomClass::Refuse,
            AssumptionId::BuildModel => SymptomClass::Degrade,
            AssumptionId::BuildManufacturer => SymptomClass::Misbehave,
            AssumptionId::BuildBrand => SymptomClass::Misbehave,
            AssumptionId::BuildProduct => SymptomClass::Refuse,
            AssumptionId::BuildDevice => SymptomClass::Refuse,
            AssumptionId::BuildHardware => SymptomClass::Misbehave,
            AssumptionId::BuildBoard => SymptomClass::Refuse,
            AssumptionId::BuildTags => SymptomClass::Refuse,
            AssumptionId::BuildSerial => SymptomClass::Refuse,
            AssumptionId::BuildBootloader => SymptomClass::Refuse,
            AssumptionId::BuildRadio => SymptomClass::Degrade,
            AssumptionId::BuildSdkInt => SymptomClass::Misbehave,
            AssumptionId::BuildEmulator => SymptomClass::Refuse,
            AssumptionId::BuildAbilities => SymptomClass::Degrade,
            AssumptionId::TrustPlayIntegrity => SymptomClass::Refuse,
            AssumptionId::TrustSafetynet => SymptomClass::Misbehave,
            AssumptionId::TrustPlayServices => SymptomClass::Refuse,
            AssumptionId::TrustKeystoreAndroidkeystore => SymptomClass::Refuse,
            AssumptionId::TrustAttestationKey => SymptomClass::Refuse,
            AssumptionId::TrustRootDetect => SymptomClass::Refuse,
            AssumptionId::TrustDebugDetect => SymptomClass::Refuse,
            AssumptionId::TrustGmsAccount => SymptomClass::Degrade,
            AssumptionId::TrustCertTrust => SymptomClass::Degrade,
            AssumptionId::KernelProcSelf => SymptomClass::Degrade,
            AssumptionId::KernelProcStat => SymptomClass::Misbehave,
            AssumptionId::KernelProcUptime => SymptomClass::Misbehave,
            AssumptionId::KernelProcCpuinfo => SymptomClass::Misbehave,
            AssumptionId::KernelProcMeminfo => SymptomClass::Degrade,
            AssumptionId::KernelSysPower => SymptomClass::Degrade,
            AssumptionId::KernelSysThermal => SymptomClass::Degrade,
            AssumptionId::KernelSysBlock => SymptomClass::Degrade,
            AssumptionId::KernelSysClassNet => SymptomClass::Degrade,
            AssumptionId::KernelSignalModel => SymptomClass::Misbehave,
            AssumptionId::IpcBinderDev => SymptomClass::Refuse,
            AssumptionId::IpcServiceManager => SymptomClass::Refuse,
            AssumptionId::IpcSystemService => SymptomClass::Refuse,
            AssumptionId::IpcActivityManager => SymptomClass::Misbehave,
            AssumptionId::IpcWindowManager => SymptomClass::Refuse,
            AssumptionId::IpcPackageManagerSelf => SymptomClass::Misbehave,
            AssumptionId::IpcPackageManagerOther => SymptomClass::Misbehave,
            AssumptionId::IpcBroadcast => SymptomClass::Misbehave,
            AssumptionId::IpcAlarmManager => SymptomClass::Misbehave,
            AssumptionId::IpcJobScheduler => SymptomClass::Misbehave,
            AssumptionId::IpcConnectivityManager => SymptomClass::Degrade,
            AssumptionId::IpcContentProvider => SymptomClass::Misbehave,
            AssumptionId::IpcNotification => SymptomClass::Degrade,
            AssumptionId::IpcBinderThreadpool => SymptomClass::Misbehave,
            AssumptionId::FsSystemLayout => SymptomClass::Refuse,
            AssumptionId::FsDataDir => SymptomClass::Misbehave,
            AssumptionId::FsExternalStorage => SymptomClass::Degrade,
            AssumptionId::FsSelinuxContext => SymptomClass::Misbehave,
            AssumptionId::FsLibPath => SymptomClass::Refuse,
            AssumptionId::FsAshmem => SymptomClass::Degrade,
            AssumptionId::FsPermModel => SymptomClass::Misbehave,
            AssumptionId::FsPackagePath => SymptomClass::Refuse,
            AssumptionId::FsObb => SymptomClass::Refuse,
            AssumptionId::FsMountNs => SymptomClass::Degrade,
            AssumptionId::ResArsc => SymptomClass::Refuse,
            AssumptionId::ResQualifier => SymptomClass::Misbehave,
            AssumptionId::ResLocale => SymptomClass::Degrade,
            AssumptionId::ResTimezone => SymptomClass::Misbehave,
            AssumptionId::ResFontScale => SymptomClass::Degrade,
            AssumptionId::ResDisplayMetrics => SymptomClass::Degrade,
            AssumptionId::ResPackageResolver => SymptomClass::Misbehave,
            AssumptionId::ResSystemFonts => SymptomClass::Degrade,
            AssumptionId::TimeMonotonic => SymptomClass::Degrade,
            AssumptionId::TimeElapsedRealtime => SymptomClass::Misbehave,
            AssumptionId::TimeWallClock => SymptomClass::Degrade,
            AssumptionId::TimeVsync => SymptomClass::Refuse,
            AssumptionId::TimeSleep => SymptomClass::Degrade,
            AssumptionId::TimeSlowOperation => SymptomClass::Misbehave,
            AssumptionId::TimeAnrBudget => SymptomClass::Refuse,
            AssumptionId::CpuCoreCount => SymptomClass::Degrade,
            AssumptionId::CpuArch => SymptomClass::Refuse,
            AssumptionId::CpuTiering => SymptomClass::Misbehave,
            AssumptionId::CpuGc => SymptomClass::Degrade,
            AssumptionId::CpuAtomic => SymptomClass::Misbehave,
            AssumptionId::CpuThreadAffinity => SymptomClass::Degrade,
            AssumptionId::CpuNumeric => SymptomClass::Misbehave,
            AssumptionId::MemDirectBytebuffer => SymptomClass::Degrade,
            AssumptionId::MemMmap => SymptomClass::Degrade,
            AssumptionId::MemLargeHeap => SymptomClass::Refuse,
            AssumptionId::MemHwCaps => SymptomClass::Degrade,
            AssumptionId::MemLmk => SymptomClass::Degrade,
            AssumptionId::MemNativeHeap => SymptomClass::Degrade,
            AssumptionId::MemEntropy => SymptomClass::Misbehave,
            AssumptionId::NativeLoadLibrary => SymptomClass::Refuse,
            AssumptionId::NativeJniEntry => SymptomClass::Refuse,
            AssumptionId::NativeExecSegments => SymptomClass::Refuse,
            AssumptionId::NativeLinkerNs => SymptomClass::Refuse,
            AssumptionId::NativeIsa => SymptomClass::Refuse,
            AssumptionId::NativeSignalCrash => SymptomClass::Misbehave,
            AssumptionId::NetEgress => SymptomClass::Refuse,
            AssumptionId::NetDns => SymptomClass::Refuse,
            AssumptionId::NetTlsTrust => SymptomClass::Refuse,
            AssumptionId::NetCleartextPolicy => SymptomClass::Refuse,
            AssumptionId::NetProxy => SymptomClass::Degrade,
            AssumptionId::NetNativeHttp => SymptomClass::Refuse,
            AssumptionId::NetWebsocket => SymptomClass::Misbehave,
            AssumptionId::NetQuic => SymptomClass::Degrade,
            AssumptionId::NetBackendVerdict => SymptomClass::Refuse,
            AssumptionId::GfxEglContext => SymptomClass::Refuse,
            AssumptionId::GfxGlesVersion => SymptomClass::Degrade,
            AssumptionId::GfxVulkan => SymptomClass::Refuse,
            AssumptionId::GfxExtensions => SymptomClass::Degrade,
            AssumptionId::GfxRendererString => SymptomClass::Refuse,
            AssumptionId::GfxSurface => SymptomClass::Refuse,
            AssumptionId::GfxHwComposition => SymptomClass::Degrade,
            AssumptionId::GfxFrameBudget => SymptomClass::Degrade,
            AssumptionId::GfxScreenOn => SymptomClass::Degrade,
            AssumptionId::GfxCameraPipe => SymptomClass::Refuse,
            AssumptionId::GfxTextRender => SymptomClass::Degrade,
            AssumptionId::HwSensors => SymptomClass::Degrade,
            AssumptionId::HwCamera => SymptomClass::Refuse,
            AssumptionId::HwLocation => SymptomClass::Refuse,
            AssumptionId::HwBluetooth => SymptomClass::Degrade,
            AssumptionId::HwNfc => SymptomClass::Refuse,
            AssumptionId::HwVibrate => SymptomClass::Degrade,
            AssumptionId::HwTelephony => SymptomClass::Degrade,
            AssumptionId::HwBiometric => SymptomClass::Refuse,
            AssumptionId::HwContactsSms => SymptomClass::Misbehave,
            AssumptionId::HwPrinterScanner => SymptomClass::Degrade,
            AssumptionId::FwClassLoader => SymptomClass::Refuse,
            AssumptionId::FwReflection => SymptomClass::Misbehave,
            AssumptionId::FwInvokedynamic => SymptomClass::Refuse,
            AssumptionId::FwNonSdkApi => SymptomClass::Misbehave,
            AssumptionId::FwSerialization => SymptomClass::Misbehave,
            AssumptionId::FwDynamicCode => SymptomClass::Refuse,
            AssumptionId::FwActivityLifecycle => SymptomClass::Misbehave,
            AssumptionId::FwContentProviderInit => SymptomClass::Misbehave,
            AssumptionId::FwCryptoProvider => SymptomClass::Refuse,
            AssumptionId::FwWebview => SymptomClass::Refuse,
            AssumptionId::FwProcessIsolation => SymptomClass::Degrade,
            AssumptionId::InputInputEvent => SymptomClass::Refuse,
            AssumptionId::InputIme => SymptomClass::Refuse,
            AssumptionId::InputWindowFocus => SymptomClass::Misbehave,
            AssumptionId::InputHaptic => SymptomClass::Degrade,
            AssumptionId::PwrWakeLock => SymptomClass::Degrade,
            AssumptionId::PwrDoze => SymptomClass::Degrade,
            AssumptionId::PwrAppStandby => SymptomClass::Degrade,
            AssumptionId::PwrBootCompleted => SymptomClass::Misbehave,
            AssumptionId::PwrProcessReaper => SymptomClass::Degrade,
            AssumptionId::PwrBattery => SymptomClass::Degrade,
            AssumptionId::PwrUptimePolicy => SymptomClass::Degrade,
        }
    }

    /// The weaker outcome for the rows the document writes as a pair.
    ///
    /// Five rows name two classes (`SUB.IPC.SYSTEM_SERVICE` and `SUB.RES.ARSC`
    /// are `REFUSE / …`; `SUB.TIME.VSYNC` is `REFUSE` for animation-dependent
    /// apps and `MISBEHAVE` otherwise). Those resolve to the stronger outcome in
    /// [`Self::class`], because a degradation the app may absorb silently is a
    /// different and less interesting observation than a refusal, and an instrument
    /// must not record the milder outcome for the harsher one. The second class is
    /// kept here so the information is recorded rather than discarded.
    ///
    /// `None` for the 140 rows that name exactly one class.
    pub fn also_possible(self) -> Option<SymptomClass> {
        match self {
            AssumptionId::IpcSystemService => Some(SymptomClass::Degrade),
            AssumptionId::ResArsc => Some(SymptomClass::Misbehave),
            AssumptionId::TimeVsync => Some(SymptomClass::Misbehave),
            AssumptionId::GfxGlesVersion => Some(SymptomClass::Refuse),
            AssumptionId::HwSensors => Some(SymptomClass::Refuse),
            // the remaining 140 rows name a single class
            _ => None,
        }
    }

    /// §17.1 hard wall: fails *independently of implementation quality*.
    ///
    /// A synthesiser cannot make these true. It can choose to fail loudly — which
    /// is a measurement — or return a plausible value and let the app wait forever
    /// for something that cannot arrive, which is worse because the recording then
    /// reads as a property of the app.
    pub fn hard_wall(self) -> bool {
        match self {
            AssumptionId::TrustPlayIntegrity => true,
            AssumptionId::IpcBinderDev => true,
            AssumptionId::IpcBroadcast => true,
            AssumptionId::NetEgress => true,
            AssumptionId::PwrBootCompleted => true,
            // §17.1 lists exactly the members above
            _ => false,
        }
    }

    /// Carries no signal and is excluded from any divergence score.
    ///
    /// `SUB.TRUST.SAFETYNET` has been unsatisfiable on every device since
    /// 2025-01-31, so it discriminates nothing; `SUB.CPU.NUMERIC` is a
    /// Dalvik-on-x87 issue ARM64 moved past. Both are kept so a future analyst does
    /// not "rediscover" them, and both are excluded because scoring a constant is
    /// averaging it into a measurement.
    pub fn excluded_from_scoring(self) -> bool {
        match self {
            AssumptionId::TrustSafetynet => true,
            AssumptionId::CpuNumeric => true,
            // §2 and §8 respectively
            _ => false,
        }
    }

    /// §17.3: assumptions whose failure is invisible to a crash counter.
    ///
    /// These get the most scrutiny in [`crate::synth`], because they are the ones
    /// a fabricated answer converts into silent wrongness instead of a visible
    /// failure.
    pub fn invisible_to_crash_counter(self) -> bool {
        match self {
            AssumptionId::IpcPackageManagerOther => true,
            AssumptionId::IpcBinderThreadpool => true,
            AssumptionId::ResArsc => true,
            AssumptionId::TimeElapsedRealtime => true,
            AssumptionId::CpuAtomic => true,
            AssumptionId::NetWebsocket => true,
            AssumptionId::FwReflection => true,
            AssumptionId::FwNonSdkApi => true,
            // §17.3's table lists exactly the members above
            _ => false,
        }
    }

    /// §18's "most consequential" member of its family.
    pub fn most_consequential_in_family(self) -> bool {
        match self {
            AssumptionId::BuildSdkInt => true,
            AssumptionId::BuildEmulator => true,
            AssumptionId::TrustPlayIntegrity => true,
            AssumptionId::KernelProcStat => true,
            AssumptionId::IpcServiceManager => true,
            AssumptionId::FsDataDir => true,
            AssumptionId::FsLibPath => true,
            AssumptionId::ResArsc => true,
            AssumptionId::TimeElapsedRealtime => true,
            AssumptionId::TimeVsync => true,
            AssumptionId::CpuTiering => true,
            AssumptionId::MemLargeHeap => true,
            AssumptionId::NativeLoadLibrary => true,
            AssumptionId::NetBackendVerdict => true,
            AssumptionId::GfxEglContext => true,
            AssumptionId::GfxSurface => true,
            AssumptionId::HwLocation => true,
            AssumptionId::HwBiometric => true,
            AssumptionId::FwClassLoader => true,
            AssumptionId::FwInvokedynamic => true,
            AssumptionId::InputIme => true,
            AssumptionId::PwrBootCompleted => true,
            // §18's registry summary lists exactly the members above
            _ => false,
        }
    }

    /// Look an ID up by its full token. `None` for a well-shaped but
    /// unregistered ID: shape is not membership.
    pub fn lookup(s: &str) -> Option<AssumptionId> {
        AssumptionId::ALL.into_iter().find(|a| a.as_str() == s)
    }

    /// The shape rule the oracle schema enforces, duplicated so an ID can be
    /// rejected here without pulling in the schema.
    pub fn well_shaped(s: &str) -> bool {
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

    /// Parse a full ID, or explain why it is not in the registry.
    ///
    /// The error is `&'static str`-shaped rather than a crate error enum because
    /// this module deliberately depends on nothing else in hostgen: a taxonomy
    /// mistake should surface at emission, not through three layers of wrapping.
    pub fn parse(s: &str) -> Result<AssumptionId, TaxonomyError> {
        if !Self::well_shaped(s) {
            return Err(TaxonomyError::Malformed);
        }
        Self::lookup(s).ok_or(TaxonomyError::Unregistered)
    }
}

impl fmt::Display for AssumptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.as_str()) }
}

impl FromStr for AssumptionId {
    type Err = TaxonomyError;

    fn from_str(s: &str) -> Result<AssumptionId, TaxonomyError> {
        AssumptionId::parse(s)
    }
}

/// Why an ID was rejected. The two cases are kept apart because they mean
/// different things to whoever has to fix them: a malformed ID is a typo, an
/// unregistered one means the taxonomy grew and this crate did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaxonomyError {
    /// Not shaped like `SUB.<FAMILY>.<LEAF>` at all.
    Malformed,
    /// Correctly shaped, absent from the 145-ID registry.
    Unregistered,
}

impl fmt::Display for TaxonomyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TaxonomyError::Malformed => f.write_str("not a SUB.<FAMILY>.<LEAF> identifier"),
            TaxonomyError::Unregistered => {
                f.write_str("well shaped but absent from the 145-ID registry")
            }
        }
    }
}

/// How many IDs the registry holds. Asserted against
/// `docs/divergence-taxonomy.md` §18 by `tests/taxonomy_registry.rs`.
pub const ASSUMPTION_ID_COUNT: usize = 145;

/// How many families.
pub const FAMILY_COUNT: usize = 16;

// ---- transcribed from docs/divergence-taxonomy.md.
// tests/taxonomy_registry.rs asserts these counts in both directions.
const _TAXONOMY_COUNTS: () = assert!(ASSUMPTION_ID_COUNT == 145 && FAMILY_COUNT == 16);
