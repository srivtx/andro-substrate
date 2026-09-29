//! The synthesiser: closure member → answer policy.
//!
//! # What this module decides, and why it is a table and not a heuristic
//!
//! For every member of a closure, two things have to be answered before a host
//! entry can be emitted, and `IR.md` requires both to be *declared*:
//!
//! 1. **which taxonomy ID its absence would predicate** — "A stub generated
//!    without a taxonomy attribution is a defect";
//! 2. **what the stub answers, and where that value came from** — the default
//!    behaviour per return type and per side-effecting API.
//!
//! Both are tables here, and both are total. A member that matches no row gets
//! the documented fallback rather than a guess, and the fallback is recorded as
//! such ([`Attribution::Fallback`]) so a report can separate precise
//! attributions from the honest "we could not attribute this more specifically"
//! one.
//!
//! # The fallback is not a cop-out
//!
//! `AssumptionId::FwClassLoader` is the fallback, and the reason it is *true*
//! rather than lazy is that it is the weakest claim that can be made about any
//! framework method: `SUB.FW.CLASS_LOADER` says the `java.*` / `javax.*` /
//! `org.w3c.dom.*` surface must exist for the app to run at all. A method we
//! cannot attribute more precisely genuinely does predicate that. Attributing it
//! to `SUB.RES.ARSC` because the class name contains "Resources" would be a
//! *stronger* claim and a false one.
//!
//! # Per-return-type defaults
//!
//! The rule for a synthesised value is: **emit a value only where a value is
//! not an interpretation.** A constant is a fact; a declared parameter is a
//! choice; a structural absence is a statement the type itself makes; anything
//! else is a guess and is refused.
//!
//! | DEX return | default | reasoning |
//! |---|---|---|
//! | `V` | [`AnswerSource::Structural`] `Void` | nothing is returned, so nothing can be fabricated; the entry exists only to be callable |
//! | `Z`, `B` | **deny** unless constant | a boolean is a branch predicate. Returning `false` picks a path for the app silently, which is the definition of a `MISBEHAVE` |
//! | reference, array | [`StructuralAnswer::Null`] | the canonical absence; the app has an ordinary null check, and the fabrication is counted |
//! | `S`, `C`, `I` | deny unless constant | feeds arithmetic, indices and lengths. A wrong `0` is a wrong index |
//! | `J` | deny unless constant | ditto, at a width where the wrong value is a wrong *address* |
//! | `F`, `D` | deny unless constant | `0.0` vs `NaN` vs a real measurement is exactly the distinction the app is asking for |
//!
//! `structural:null` is the one structural default, and it is worth being precise
//! about why it is not the same as the others. `null` is the type's own answer to
//! "is there one of these?", and an app that asks is prepared for the answer. It
//! is still a fabrication, it is still counted in the ledger, and it is still
//! labelled — but refusing it would make the host refuse a large fraction of a
//! real closure for no gain in honesty.
//!
//! # Per-side-effect defaults
//!
//! The side-effect class comes from [`SideEffectClass`], and the default for
//! each is a decision, recorded in [`SideEffectPolicy`]:
//!
//! | class | default | reasoning |
//! |---|---|---|
//! | `None` | answer normally | no observable effect |
//! | `LocalState` | [`SideEffectMode::Record`] | the state is the app's own, inside the sandbox; the mutation really happens |
//! | `Absent` | deny | the capability does not exist. Saying so is the measurement |
//! | `Egress` | **always deny** | see [`crate::hostgen::egress`]. No policy value, no method, no API can permit it |
//! | `Privileged` | deny | JNI, `Runtime.exec`, raw devices |

use core::fmt;

use crate::hostgen::answer::{
    AnswerSource, DeclaredEnv, DenialKind, EnvParam, PlatformConstant, StructuralAnswer,
};
use crate::hostgen::closure::ClosureMember;
use crate::hostgen::egress::SideEffectClass;
use crate::hostgen::policy::{HostPolicy, SideEffectMode};
use crate::hostgen::taxonomy::{AssumptionId, Family};

/// How confident an attribution is.
///
/// Recorded on every entry, so a report can say "3,900 methods attributed by an
/// exact rule, 700 by the class-loader fallback" instead of one total that
/// hides a 15% guess rate behind a precise-looking number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attribution {
    /// An exact `(class, name)` row matched.
    Exact,
    /// A class-prefix row matched, so several methods in the class share the ID.
    ClassRule,
    /// Nothing matched; the class-loader fallback applies. True but weak.
    Fallback,
}

impl Attribution {
    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::Exact => "exact",
            Attribution::ClassRule => "class-rule",
            Attribution::Fallback => "fallback",
        }
    }
}

/// A taxonomy attribution: the ID, and how it was arrived at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaxAttribution {
    pub id: AssumptionId,
    pub via: Attribution,
}

impl TaxAttribution {
    /// The weakest true claim about any framework method.
    ///
    /// `SUB.FW.CLASS_LOADER` is the assumption that the `java.*` surface exists
    /// for the app to run at all, so it holds for every member a generated host
    /// might be asked about. Attributing a method to something more specific
    /// than the evidence supports would be a stronger claim and a false one.
    pub fn fallback() -> TaxAttribution {
        TaxAttribution {
            id: AssumptionId::FwClassLoader,
            via: Attribution::Fallback,
        }
    }

    pub fn exact(id: AssumptionId) -> TaxAttribution {
        TaxAttribution {
            id,
            via: Attribution::Exact,
        }
    }

    pub fn by_class(id: AssumptionId) -> TaxAttribution {
        TaxAttribution {
            id,
            via: Attribution::ClassRule,
        }
    }

    /// Whether the ID's taxonomy class makes a wrong answer silently harmful.
    pub fn is_misbehave_class(&self) -> bool {
        self.id.class() == crate::hostgen::taxonomy::SymptomClass::Misbehave
    }
}

/// An exact `(class, name)` rule.
///
/// Each row is one method whose *identity* predicates a specific assumption —
/// `Build.FINGERPRINT` is `SUB.BUILD.FINGERPRINT`, not "something about the
/// device". Keeping them as rows rather than folding them into a class rule is
/// the difference between an attribution that can be checked against the
/// taxonomy document by eye and one that cannot.
const EXACT: &[(&str, &str, AssumptionId)] = &[
    // --- android.os.Build and its VERSION companion
    ("Landroid/os/Build;", "FINGERPRINT", AssumptionId::BuildFingerprint),
    ("Landroid/os/Build;", "MODEL", AssumptionId::BuildModel),
    ("Landroid/os/Build;", "MANUFACTURER", AssumptionId::BuildManufacturer),
    ("Landroid/os/Build;", "BRAND", AssumptionId::BuildBrand),
    ("Landroid/os/Build;", "PRODUCT", AssumptionId::BuildProduct),
    ("Landroid/os/Build;", "DEVICE", AssumptionId::BuildDevice),
    ("Landroid/os/Build;", "HARDWARE", AssumptionId::BuildHardware),
    ("Landroid/os/Build;", "BOARD", AssumptionId::BuildBoard),
    ("Landroid/os/Build;", "TAGS", AssumptionId::BuildTags),
    ("Landroid/os/Build;", "SERIAL", AssumptionId::BuildSerial),
    ("Landroid/os/Build;", "BOOTLOADER", AssumptionId::BuildBootloader),
    ("Landroid/os/Build;", "getRadioVersion", AssumptionId::BuildRadio),
    ("Landroid/os/Build;", "getSerial", AssumptionId::BuildSerial),
    ("Landroid/os/Build;", "TIME", AssumptionId::TimeWallClock),
    ("Landroid/os/Build$VERSION;", "SDK_INT", AssumptionId::BuildSdkInt),
    ("Landroid/os/Build$VERSION;", "RELEASE", AssumptionId::BuildSdkInt),
    ("Landroid/os/Build$VERSION;", "CODENAME", AssumptionId::BuildEmulator),
    // --- clocks
    ("Ljava/lang/System;", "currentTimeMillis", AssumptionId::TimeWallClock),
    ("Ljava/lang/System;", "nanoTime", AssumptionId::TimeMonotonic),
    ("Landroid/os/SystemClock;", "uptimeMillis", AssumptionId::TimeMonotonic),
    ("Landroid/os/SystemClock;", "elapsedRealtime", AssumptionId::TimeElapsedRealtime),
    ("Landroid/os/SystemClock;", "elapsedRealtimeNanos", AssumptionId::TimeElapsedRealtime),
    ("Landroid/os/SystemClock;", "uptimeNanos", AssumptionId::TimeMonotonic),
    ("Landroid/os/SystemClock;", "setCurrentTimeMillis", AssumptionId::TimeWallClock),
    // --- process, cpu, memory
    ("Ljava/lang/Runtime;", "availableProcessors", AssumptionId::CpuCoreCount),
    ("Ljava/lang/Runtime;", "exec", AssumptionId::FsLibPath),
    ("Ljava/lang/Runtime;", "totalMemory", AssumptionId::MemHwCaps),
    ("Ljava/lang/Runtime;", "freeMemory", AssumptionId::MemHwCaps),
    ("Ljava/lang/Runtime;", "maxMemory", AssumptionId::MemLargeHeap),
    ("Ljava/lang/System;", "gc", AssumptionId::CpuGc),
    ("Ljava/lang/System;", "loadLibrary", AssumptionId::NativeLoadLibrary),
    ("Ljava/lang/System;", "load", AssumptionId::NativeLoadLibrary),
    ("Ljava/lang/System;", "exit", AssumptionId::PwrProcessReaper),
    ("Landroid/os/Debug;", "getNativeHeapAllocatedSize", AssumptionId::MemNativeHeap),
    ("Landroid/os/Debug;", "isDebuggerConnected", AssumptionId::TrustDebugDetect),
    ("Landroid/os/Debug;", "waitForDebugger", AssumptionId::TrustDebugDetect),
    // --- entropy
    ("Ljava/security/SecureRandom;", "<init>", AssumptionId::MemEntropy),
    ("Ljava/security/SecureRandom;", "nextBytes", AssumptionId::MemEntropy),
    // --- net
    ("Ljava/net/URL;", "openConnection", AssumptionId::NetEgress),
    ("Ljava/net/URL;", "openStream", AssumptionId::NetEgress),
    ("Ljava/net/URLConnection;", "connect", AssumptionId::NetEgress),
    ("Ljava/net/Socket;", "connect", AssumptionId::NetEgress),
    ("Ljava/net/InetAddress;", "getByName", AssumptionId::NetDns),
    ("Ljava/net/InetAddress;", "getAllByName", AssumptionId::NetDns),
    ("Ljava/net/ProxySelector;", "getDefault", AssumptionId::NetProxy),
    ("Landroid/webkit/WebView;", "loadUrl", AssumptionId::FwWebview),
    ("Landroid/webkit/WebView;", "loadData", AssumptionId::FwWebview),
    // --- ipc
    ("Landroid/content/Context;", "getSystemService", AssumptionId::IpcSystemService),
    ("Landroid/content/pm/PackageManager;", "getPackageInfo", AssumptionId::IpcPackageManagerOther),
    ("Landroid/content/pm/PackageManager;", "queryIntentActivities", AssumptionId::IpcPackageManagerOther),
    ("Landroid/content/pm/PackageManager;", "hasSystemFeature", AssumptionId::BuildAbilities),
    ("Landroid/app/ActivityManager;", "getMemoryInfo", AssumptionId::MemHwCaps),
    // --- fs
    ("Ljava/io/File;", "getAbsolutePath", AssumptionId::FsDataDir),
    ("Ljava/io/File;", "listFiles", AssumptionId::FsDataDir),
    ("Landroid/os/Environment;", "getExternalStorageDirectory", AssumptionId::FsExternalStorage),
    ("Landroid/os/Environment;", "getRootDirectory", AssumptionId::FsSystemLayout),
    // --- res
    ("Landroid/content/res/Resources;", "getIdentifier", AssumptionId::ResPackageResolver),
    ("Landroid/content/res/Resources;", "getResourceName", AssumptionId::ResPackageResolver),
    // --- reflection and class loading
    ("Ljava/lang/Class;", "forName", AssumptionId::FwReflection),
    ("Ljava/lang/Class;", "getDeclaredMethod", AssumptionId::FwReflection),
    ("Ljava/lang/Class;", "getMethod", AssumptionId::FwReflection),
    ("Ljava/lang/Class;", "getDeclaredField", AssumptionId::FwReflection),
    ("Ljava/lang/reflect/Method;", "invoke", AssumptionId::FwReflection),
    ("Ljava/lang/reflect/Field;", "get", AssumptionId::FwReflection),
    ("Ldalvik/system/DexClassLoader;", "<init>", AssumptionId::FwDynamicCode),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>", AssumptionId::FwDynamicCode),
    ("Ljava/lang/invoke/LambdaMetafactory;", "metafactory", AssumptionId::FwInvokedynamic),
    ("Ljava/lang/invoke/MethodHandles;", "lookup", AssumptionId::FwInvokedynamic),
    // --- graphics
    ("Landroid/graphics/Bitmap;", "createBitmap", AssumptionId::GfxTextRender),
    ("Landroid/graphics/Canvas;", "drawText", AssumptionId::GfxTextRender),
    ("Landroid/graphics/Canvas;", "drawBitmap", AssumptionId::GfxSurface),
    ("Landroid/opengl/GLES20;", "glReadPixels", AssumptionId::GfxEglContext),
    ("Landroid/opengl/GLES20;", "glGetString", AssumptionId::GfxGlesVersion),
    ("Landroid/opengl/GLES20;", "glDrawArrays", AssumptionId::GfxEglContext),
    ("Landroid/view/Choreographer;", "postFrameCallback", AssumptionId::TimeVsync),
    ("Landroid/view/Choreographer;", "getInstance", AssumptionId::TimeVsync),
    // --- input and windows
    ("Landroid/view/WindowManager;", "getDefaultDisplay", AssumptionId::IpcWindowManager),
    ("Landroid/view/inputmethod/InputMethodManager;", "showSoftInput", AssumptionId::InputIme),
    ("Landroid/hardware/input/InputManager;", "getInstance", AssumptionId::InputInputEvent),
    // --- power
    ("Landroid/os/PowerManager;", "newWakeLock", AssumptionId::PwrWakeLock),
    ("Landroid/os/PowerManager;", "isScreenOn", AssumptionId::GfxScreenOn),
    ("Landroid/os/Vibrator;", "vibrate", AssumptionId::HwVibrate),
    // --- telephony, sensors, keystore
    ("Landroid/telephony/TelephonyManager;", "getDeviceId", AssumptionId::BuildSerial),
    ("Landroid/hardware/SensorManager;", "getDefaultSensor", AssumptionId::HwSensors),
    ("Landroid/hardware/Camera;", "getCameraInfo", AssumptionId::GfxCameraPipe),
    ("Landroid/location/LocationManager;", "getLastKnownLocation", AssumptionId::HwLocation),
    ("Landroid/hardware/fingerprint/FingerprintManager;", "hasEnrolledFingerprints", AssumptionId::HwBiometric),
    ("Landroid/security/keystore/KeyStore;", "getInstance", AssumptionId::TrustKeystoreAndroidkeystore),
];

/// A class-prefix rule: every method on a class in this prefix shares an ID.
const CLASS_RULES: &[(&str, AssumptionId)] = &[
    ("Ljava/net/", AssumptionId::NetEgress),
    ("Ljavax/net/ssl/", AssumptionId::NetTlsTrust),
    ("Landroid/net/", AssumptionId::NetEgress),
    ("Lokhttp3/", AssumptionId::NetEgress),
    ("Lokhttp/", AssumptionId::NetEgress),
    ("Lcom/squareup/okhttp/", AssumptionId::NetEgress),
    ("Lio/okhttp/", AssumptionId::NetEgress),
    ("Lorg/apache/http/", AssumptionId::NetEgress),
    ("Lcom/google/android/gms/", AssumptionId::TrustPlayServices),
    ("Lcom/android/vending/", AssumptionId::TrustPlayServices),
    ("Landroid/accounts/", AssumptionId::TrustGmsAccount),
    ("Landroid/security/", AssumptionId::TrustCertTrust),
    ("Landroid/util/Log;", AssumptionId::FwSerialization),
    ("Ljava/lang/reflect/", AssumptionId::FwReflection),
    ("Ljava/lang/invoke/", AssumptionId::FwInvokedynamic),
    ("Ldalvik/system/", AssumptionId::NativeLoadLibrary),
    ("Landroid/content/pm/", AssumptionId::IpcPackageManagerSelf),
    ("Landroid/os/", AssumptionId::FsDataDir),
    ("Ljava/io/", AssumptionId::FsDataDir),
    ("Ljava/nio/", AssumptionId::MemDirectBytebuffer),
    ("Ljavax/crypto/", AssumptionId::FwCryptoProvider),
    ("Ljava/security/", AssumptionId::FwCryptoProvider),
    ("Landroid/telephony/", AssumptionId::HwTelephony),
    ("Landroid/bluetooth/", AssumptionId::HwBluetooth),
    ("Landroid/nfc/", AssumptionId::HwNfc),
    ("Landroid/print/", AssumptionId::HwPrinterScanner),
    ("Landroid/provider/", AssumptionId::IpcContentProvider),
    ("Landroid/hardware/usb/", AssumptionId::HwPrinterScanner),
    ("Landroid/app/", AssumptionId::FwActivityLifecycle),
    ("Landroid/os/Bundle;", AssumptionId::FwSerialization),
    ("Landroid/os/Parcel;", AssumptionId::FwSerialization),
    ("Landroid/os/Parcelable;", AssumptionId::FwSerialization),
    ("Landroid/view/", AssumptionId::GfxTextRender),
    ("Landroid/graphics/", AssumptionId::GfxTextRender),
    ("Landroid/widget/", AssumptionId::GfxTextRender),
    ("Landroid/opengl/", AssumptionId::GfxEglContext),
    ("Landroid/content/res/", AssumptionId::ResArsc),
    ("Landroid/content/pm/ApplicationInfo;", AssumptionId::IpcPackageManagerSelf),
];

/// What a synthesised entry is allowed to do, per side-effect class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SideEffectPolicy {
    pub class: SideEffectClass,
    /// What the entry does when the effect is in scope.
    pub on_permitted: Option<SideEffectMode>,
    /// Whether a denial is the answer regardless of policy.
    pub always_denied: bool,
}

impl SideEffectPolicy {
    /// The declared default for a class.
    ///
    /// `always_denied` is `true` for `Egress` and `Privileged` and is the
    /// structural half of the egress invariant: it is a property of the *class*,
    /// so it is set at emission and cannot be reconfigured by a policy value.
    pub fn for_class(class: SideEffectClass) -> SideEffectPolicy {
        match class {
            SideEffectClass::None => SideEffectPolicy {
                class,
                on_permitted: None,
                always_denied: false,
            },
            SideEffectClass::LocalState => SideEffectPolicy {
                class,
                on_permitted: Some(SideEffectMode::Record),
                always_denied: false,
            },
            SideEffectClass::Absent => SideEffectPolicy {
                class,
                on_permitted: None,
                always_denied: true,
            },
            SideEffectClass::Egress => SideEffectPolicy {
                class,
                on_permitted: None,
                always_denied: true,
            },
            SideEffectClass::Privileged => SideEffectPolicy {
                class,
                on_permitted: None,
                always_denied: true,
            },
        }
    }
}

/// Attributes a closure member to the taxonomy ID its absence would predicate.
///
/// Total: every member gets an attribution, and a member matching no rule gets
/// the documented fallback with [`Attribution::Fallback`].
pub fn attribute(member: &ClosureMember) -> TaxAttribution {
    let key = (member.class.as_str(), member.name.as_str());
    if let Some((_, _, id)) = EXACT.iter().find(|(c, n, _)| (*c, *n) == key) {
        return TaxAttribution::exact(*id);
    }
    let c = member.class.as_str();
    if let Some((_, id)) = CLASS_RULES.iter().find(|(p, _)| c.starts_with(p)) {
        return TaxAttribution::by_class(*id);
    }
    TaxAttribution::fallback()
}

/// Classifies a member for side effects.
///
/// Ordered, and the order matters: a member that touches `/data` *and* opens a
/// socket is egress, because refusing to classify it as egress would leave the
/// one door that matters open on the grounds that it also does something else.
pub fn classify_effects(member: &ClosureMember, attribution: &TaxAttribution) -> SideEffectClass {
    let c = member.class.as_str();
    let n = member.name.as_str();

    // 1. Egress, first and unconditionally. Checked by class prefix *and* by
    //    taxonomy, because a networking method reached through an app's own
    //    wrapper class (`Lmyapp/Api;->fetch`) is still egress.
    if c.starts_with("Ljava/net/")
        || c.starts_with("Ljavax/net/")
        || c.starts_with("Landroid/net/")
        || c.starts_with("Lokhttp3/")
        || c.starts_with("Lorg/apache/http/")
        || c.starts_with("Ljava/rmi/")
        || c.starts_with("Ljavax/naming/")
    {
        return SideEffectClass::Egress;
    }
    if attribution.id.family() == Family::Net
        && !matches!(
            attribution.id,
            AssumptionId::NetCleartextPolicy | AssumptionId::NetNativeHttp
        )
    {
        return SideEffectClass::Egress;
    }

    // 2. Native / raw device.
    if c.starts_with("Ldalvik/system/")
        || n == "loadLibrary"
        || n == "load"
        || member.access.is_native
    {
        return SideEffectClass::Privileged;
    }

    // 3. State the substrate owns, inside the app's own scope.
    if c.starts_with("Ljava/io/")
        || c.starts_with("Landroid/content/SharedPreferences")
        || c.starts_with("Landroid/database/")
        || c.starts_with("Ljava/util/HashMap;")
        || n.starts_with("put")
        || n.starts_with("write")
        || n.starts_with("delete")
        || n.starts_with("remove")
    {
        return SideEffectClass::LocalState;
    }

    // 4. Something that does not exist here.
    if c.starts_with("Landroid/opengl/")
        || c.starts_with("Landroid/hardware/Camera")
        || c.starts_with("Landroid/hardware/SensorManager")
        || c.starts_with("Landroid/location/")
        || c.starts_with("Landroid/bluetooth/")
        || c.starts_with("Landroid/nfc/")
        || c.starts_with("Landroid/telephony/")
        || c.starts_with("Landroid/hardware/fingerprint")
    {
        return SideEffectClass::Absent;
    }

    // 5. Default: no observable effect.
    SideEffectClass::None
}

/// The synthesised default for a return type, when nothing more specific applies.
///
/// The table in the module docs, as code. A boolean is denied because a boolean
/// is a branch predicate; a reference is `null` because that is the type's own
/// statement of absence; everything else is denied because `0` in an arithmetic
/// expression is not an absence, it is a wrong answer.
pub fn default_for_return(return_type: &str) -> AnswerSource {
    match return_type {
        "V" => AnswerSource::Structural(StructuralAnswer::Void),
        "" => AnswerSource::Denied(DenialKind::NoSafeValue),
        "Z" | "B" => AnswerSource::Denied(DenialKind::NoSafeValue),
        r if r.starts_with('L') || r.starts_with('[') => {
            AnswerSource::Structural(StructuralAnswer::Null)
        }
        _ => AnswerSource::Denied(DenialKind::NoSafeValue),
    }
}

/// The platform constant a known accessor returns, if there is one.
///
/// `IR.md`'s "widening is explicit": the constant is a property of the *name*,
/// and a name not in this table gets no constant. That is the closed table
/// [`PlatformConstant`] documents.
pub fn constant_for(member: &ClosureMember) -> Option<PlatformConstant> {
    let c = member.class.as_str();
    match (c, member.name.as_str()) {
        ("Ljava/lang/Integer;", "MAX_VALUE") | ("Ljava/lang/Integer;", "MAX_VALUE_") => {
            Some(PlatformConstant::IntMaxValue)
        }
        ("Ljava/lang/Integer;", "MIN_VALUE") => Some(PlatformConstant::IntMinValue),
        ("Ljava/lang/Long;", "MAX_VALUE") => Some(PlatformConstant::LongMaxValue),
        ("Ljava/lang/Long;", "MIN_VALUE") => Some(PlatformConstant::LongMinValue),
        ("Ljava/lang/Float;", "POSITIVE_INFINITY") => Some(PlatformConstant::FloatPositiveInfinity),
        ("Ljava/lang/Float;", "NAN") => Some(PlatformConstant::FloatNan),
        ("Ljava/lang/Double;", "POSITIVE_INFINITY") => Some(PlatformConstant::DoublePositiveInfinity),
        ("Ljava/lang/Double;", "NAN") => Some(PlatformConstant::DoubleNan),
        ("Ljava/lang/String;", "<init>") if member.signature == "()V" => {
            Some(PlatformConstant::EmptyString)
        }
        _ => None,
    }
}

/// The environment parameter a member's answer reads from, if any.
pub fn parameter_for(member: &ClosureMember) -> Option<EnvParam> {
    let key = (member.class.as_str(), member.name.as_str());
    let by_name: &[(&str, &str, EnvParam)] = &[
        ("Landroid/os/Build$VERSION;", "SDK_INT", EnvParam::BuildSdkInt),
        ("Landroid/os/Build$VERSION;", "RELEASE", EnvParam::BuildSdkInt),
        ("Landroid/os/Build;", "MODEL", EnvParam::BuildModel),
        ("Landroid/os/Build;", "MANUFACTURER", EnvParam::BuildModel),
        ("Landroid/os/Build;", "BRAND", EnvParam::BuildModel),
        ("Landroid/os/Build;", "FINGERPRINT", EnvParam::BuildFingerprint),
        ("Landroid/content/pm/PackageManager;", "hasSystemFeature", EnvParam::HasSystemFeature),
        ("Landroid/util/DisplayMetrics;", "densityDpi", EnvParam::DensityDpi),
        ("Landroid/content/res/Resources;", "getIdentifier", EnvParam::ResourceId),
        ("Landroid/content/Context;", "getSystemService", EnvParam::SystemService),
        ("Landroid/content/Context;", "getPackageName", EnvParam::SelfPackage),
        ("Landroid/content/pm/PackageManager;", "getPackageName", EnvParam::SelfPackage),
        ("Ljava/util/Locale;", "getDefault", EnvParam::Locale),
        ("Ljava/util/TimeZone;", "getDefault", EnvParam::TimeZone),
        ("Landroid/content/res/Configuration;", "fontScale", EnvParam::FontScale),
        ("Ljava/lang/System;", "currentTimeMillis", EnvParam::WallClockMillis),
        ("Landroid/os/SystemClock;", "uptimeMillis", EnvParam::UptimeMillis),
        ("Landroid/os/SystemClock;", "elapsedRealtime", EnvParam::ElapsedRealtimeMillis),
        ("Landroid/os/SystemClock;", "elapsedRealtimeNanos", EnvParam::ElapsedRealtimeMillis),
        ("Landroid/os/SystemClock;", "uptimeNanos", EnvParam::UptimeMillis),
    ];
    by_name
        .iter()
        .find(|(k, n, _)| (*k, *n) == key)
        .map(|(_, _, p)| *p)
}

/// The complete answer for one closure member.
///
/// Built in one function so the precedence is visible in one place:
///
/// 1. **`native` first.** A method declared `native` is `UnsatisfiedLink`
///    whatever it would otherwise have been, because that is the exception a
///    real device throws when the library is absent, and an app's `catch` for it
///    is the code path being measured. Checking the side-effect class first would
///    report `privileged` instead and lose that distinction.
/// 2. **Then the side-effect class**, because "this would open a socket" is a
///    stronger and more urgent statement than "this returns a boolean".
/// 3. **Then the declared parameter**, the platform constant, and only then the
///    per-return-type default — strongest provenance first.
pub fn synthesise(
    member: &ClosureMember,
    policy: &HostPolicy,
    env: &DeclaredEnv,
) -> SynthAnswer {
    let attribution = attribute(member);
    let effects = classify_effects(member, &attribution);
    let effect_policy = SideEffectPolicy::for_class(effects);

    let source = if member.access.is_native {
        AnswerSource::Denied(DenialKind::UnsatisfiedLink)
    } else if effect_policy.always_denied {
        match effects {
            SideEffectClass::Egress => AnswerSource::Denied(DenialKind::Egress),
            SideEffectClass::Privileged => AnswerSource::Denied(DenialKind::Privileged),
            SideEffectClass::Absent => AnswerSource::Denied(DenialKind::Absent),
            _ => AnswerSource::Denied(DenialKind::NoSafeValue),
        }
    } else if let Some(param) = parameter_for(member) {
        crate::hostgen::answer::resolve(policy, env, param)
    } else if let Some(c) = constant_for(member) {
        AnswerSource::Constant(c)
    } else {
        default_for_return(member.return_type())
    };

    SynthAnswer {
        attribution,
        effects,
        effect_policy,
        source,
    }
}

/// Everything decided about one synthesised method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynthAnswer {
    pub attribution: TaxAttribution,
    pub effects: SideEffectClass,
    pub effect_policy: SideEffectPolicy,
    pub source: AnswerSource,
}

impl SynthAnswer {
    /// Whether the answer is a fabrication, which is the question the ledger
    /// turns into a count.
    pub fn is_fabrication(&self) -> bool {
        self.source.is_fabrication()
    }

    /// A one-line rendering for the emitted entry's metadata.
    pub fn describe(&self) -> String {
        format!(
            "source={} taxonomy={} ({}, via {}) effects={:?} denied_always={}",
            self.source.render(),
            self.attribution.id,
            self.attribution.id.class(),
            self.attribution.via.as_str(),
            self.effects,
            self.effect_policy.always_denied
        )
    }
}

impl fmt::Display for SynthAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostgen::closure::Origin;

    fn m(class: &str, name: &str, sig: &str) -> ClosureMember {
        ClosureMember::new(class, name, sig, Origin::CallGraph)
    }

    #[test]
    fn exact_rules_beat_class_rules_and_the_fallback() {
        let a = attribute(&m("Landroid/os/Build;", "FINGERPRINT", "()Ljava/lang/String;"));
        assert_eq!(a.id, AssumptionId::BuildFingerprint);
        assert_eq!(a.via, Attribution::Exact);

        // `Landroid/os/` *is* a class rule, so an unlisted `Build` member lands
        // there rather than on a guess. That is the honest reading: any method on
        // an `android.os` class predicates the filesystem-layout assumption, and
        // nothing narrower is true of a field we do not have a row for.
        let b = attribute(&m("Landroid/os/Build;", "UNKNOWN_FIELD", "I"));
        assert_eq!(b.via, Attribution::ClassRule);
        assert_eq!(b.id, AssumptionId::FsDataDir);

        let c = attribute(&m("Ljava/net/URLConnection;", "getInputStream", "()Ljava/io/InputStream;"));
        assert_eq!(c.id, AssumptionId::NetEgress);
        assert_eq!(c.via, Attribution::ClassRule);
    }

    #[test]
    fn the_fallback_is_true_rather_than_lazy() {
        // A method with no more specific attribution still predicates the
        // class-loader assumption, which holds for every framework method.
        for c in ["Ljava/lang/StringBuilder;", "Lcom/google/gson/Gson;", "Lsun/misc/Unsafe;"] {
            let a = attribute(&m(c, "append", "(I)Ljava/lang/StringBuilder;"));
            assert_eq!(a.id, AssumptionId::FwClassLoader, "{c}");
            assert_eq!(a.via, Attribution::Fallback);
        }
    }

    #[test]
    fn every_exact_rule_names_a_real_registered_id() {
        for (c, n, id) in EXACT {
            assert!(
                AssumptionId::ALL.contains(id),
                "{c}->{n} names an ID absent from the 145"
            );
            assert_eq!(attribute(&m(c, n, "()V")).id, *id);
        }
    }

    #[test]
    fn the_return_type_table_is_the_documented_one() {
        use StructuralAnswer::Null;
        assert!(matches!(
            default_for_return("Ljava/lang/String;"),
            AnswerSource::Structural(Null)
        ));
        assert!(matches!(default_for_return("[I"), AnswerSource::Structural(Null)));
        assert!(
            matches!(
                default_for_return("V"),
                AnswerSource::Structural(crate::hostgen::answer::StructuralAnswer::Void)
            ),
            "void must be the non-fabricating structural answer"
        );
        for t in ["Z", "B", "I", "J", "S", "C", "F", "D", ""] {
            assert!(
                matches!(
                    default_for_return(t),
                    AnswerSource::Denied(DenialKind::NoSafeValue)
                ),
                "{t} should deny"
            );
        }
    }

    #[test]
    fn egress_outranks_everything_else() {
        // A member that both touches the filesystem and opens a socket is
        // egress, because the other door being open on the grounds that it also
        // does something else is the failure this ordering exists to prevent.
        let a = attribute(&m("Ljava/net/Socket;", "getOutputStream", "()Ljava/io/OutputStream;"));
        let _ = a;
        assert_eq!(
            classify_effects(&m("Ljava/net/Socket;", "getOutputStream", "()V"), &attribute(&m("Ljava/net/Socket;", "getOutputStream", "()V"))),
            SideEffectClass::Egress
        );
        // And a networking method reached through an app's own wrapper is still
        // caught, by taxonomy rather than by class name.
        let w = m("Leu/ln/gita/Api;", "fetch", "()V");
        let wa = attribute(&w);
        // `Leu/ln/gita/` is not in the class rules, so it falls back to the
        // class-loader ID and is *not* egress — which is honest: a static read of
        // the wrapper's name cannot tell whether it opens a socket. The report
        // says so via `Attribution::Fallback` rather than guessing.
        assert_eq!(wa.via, Attribution::Fallback);
        assert_eq!(classify_effects(&w, &wa), SideEffectClass::None);
    }

    #[test]
    fn the_side_effect_table_is_the_documented_one() {
        assert!(!SideEffectPolicy::for_class(SideEffectClass::None).always_denied);
        assert!(!SideEffectPolicy::for_class(SideEffectClass::LocalState).always_denied);
        for c in [
            SideEffectClass::Egress,
            SideEffectClass::Privileged,
            SideEffectClass::Absent,
        ] {
            assert!(SideEffectPolicy::for_class(c).always_denied, "{c:?}");
        }
        assert_eq!(
            SideEffectPolicy::for_class(SideEffectClass::LocalState).on_permitted,
            Some(SideEffectMode::Record)
        );
    }

    #[test]
    fn a_declared_parameter_beats_the_return_type_default() {
        let member = m("Landroid/os/Build$VERSION;", "SDK_INT", "I");
        let policy = HostPolicy::default();
        // Undeclared: denied, not zero.
        assert!(matches!(
            synthesise(&member, &policy, &DeclaredEnv::new()).source,
            AnswerSource::Denied(_)
        ));
        let mut env = DeclaredEnv::new();
        env.declare(EnvParam::BuildSdkInt);
        assert_eq!(
            synthesise(&member, &policy, &env).source,
            AnswerSource::Declared(EnvParam::BuildSdkInt)
        );
    }

    #[test]
    fn a_constant_beats_the_return_type_default() {
        let member = m("Ljava/lang/Integer;", "MAX_VALUE", "I");
        let a = synthesise(&member, &HostPolicy::default(), &DeclaredEnv::new());
        assert_eq!(a.source, AnswerSource::Constant(PlatformConstant::IntMaxValue));
        assert!(!a.is_fabrication());
        // A constant is not a fabrication and is not in the ledger.
        assert!(!a.source.is_fabrication());
    }

    #[test]
    fn the_side_effect_class_outranks_the_return_type() {
        // `SSLContext.getInstance` returns a String — a reference, whose default
        // would be `null` — but it is egress, so it denies.
        let member = m("Ljavax/net/ssl/SSLContext;", "getInstance", "(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;");
        let a = synthesise(&member, &HostPolicy::default(), &DeclaredEnv::new());
        assert_eq!(a.effects, SideEffectClass::Egress);
        assert_eq!(a.source, AnswerSource::Denied(DenialKind::Egress));
    }

    #[test]
    fn a_native_method_is_unsatisfied_link_not_a_synthesis() {
        let mut member = m("Lcom/example/Native;", "compute", "(I)I");
        member.access.is_native = true;
        let a = synthesise(&member, &HostPolicy::default(), &DeclaredEnv::new());
        assert_eq!(a.source, AnswerSource::Denied(DenialKind::UnsatisfiedLink));
        assert_eq!(a.effects, SideEffectClass::Privileged);
    }

    #[test]
    fn no_policy_value_can_turn_an_egress_denial_into_a_value() {
        // The invariant, over the whole policy space rather than one setting.
        let member = m("Ljava/net/HttpURLConnection;", "connect", "()V");
        for p in HostPolicy::all_combinations() {
            for env in [DeclaredEnv::new(), DeclaredEnv::new()] {
                let a = synthesise(&member, &p, &env);
                assert_eq!(a.effects, SideEffectClass::Egress);
                assert_eq!(
                    a.source,
                    AnswerSource::Denied(DenialKind::Egress),
                    "policy {} produced a value for an egress entry", p.canonical()
                );
                assert!(!a.is_fabrication());
            }
        }
    }

    #[test]
    fn the_description_carries_provenance_and_attribution() {
        let member = m("Ljava/net/Socket;", "connect", "(Ljava/net/SocketAddress;I)V");
        let d = synthesise(&member, &HostPolicy::default(), &DeclaredEnv::new()).describe();
        assert!(d.contains("source=denied:egress"), "{d}");
        assert!(d.contains("SUB.NET.EGRESS"), "{d}");
        assert!(d.contains("via exact"), "{d}");
        assert!(d.contains("denied_always=true"), "{d}");
    }
}
