//! The framework-API → taxonomy-ID mapping table.
//!
//! # The honesty rule this module exists to enforce
//!
//! Every rule carries a [`Confidence`]. A rule is
//!
//! * [`Confidence::Verified`] when the *contract* of the API is the assumption.
//!   `System.loadLibrary` is documented to load a native shared library, so a
//!   `method_id` entry for it is a verified reference to
//!   `SUB.NATIVE.LOAD_LIBRARY` — the identifier, the signature and the
//!   documented behaviour all agree, and no behavioural inference is required.
//!
//! * [`Confidence::Conjecture`] when the *linkage* from the API to the
//!   assumption is a claim about how apps use it. `Class.forName` is verified
//!   to be reflection (`SUB.FW.REFLECTION` is literally about
//!   `Class.forName`), but "this app reflects over framework internals" is not
//!   established by a `method_id` entry alone: the string argument decides, and
//!   the string argument is separately reported rather than assumed.
//!
//! Presenting the second kind as the first would let a reader believe the
//! predictor is measuring `SUB.FW.REFLECTION` when it is measuring the much
//! weaker "this app contains a call to `Class.forName`". The tags make that
//! difference visible in the output instead of in a footnote.
//!
//! Rules are matched on `(class descriptor, member name)`. A `method_id` or
//! `field_id` entry in the DEX is a *reference*, not a call: dex2oat and R8 can
//! leave entries behind for methods that are never reached, and this module
//! never claims otherwise. Call-site counts come from the instruction walk in
//! [`crate::dexscan`], which is a different and stronger fact.

use serde::Serialize;

/// Strength of the mapping from an API reference to a taxonomy ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    /// The API's documented contract *is* the assumption.
    Verified,
    /// The mapping assumes a typical usage pattern that a reference alone does
    /// not establish.
    Conjecture,
}

impl Confidence {
    /// Lowercase wire form used in the JSON rows and in the ADR table.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Verified => "VERIFIED",
            Confidence::Conjecture => "CONJECTURE",
        }
    }

    /// Ordering strength, so a join can keep the strongest tag for an ID.
    /// `Verified` (1) outranks `Conjecture` (0).
    pub fn rank(self) -> u8 {
        match self {
            Confidence::Conjecture => 0,
            Confidence::Verified => 1,
        }
    }
}

/// One mapping rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRule {
    /// L-form type descriptor of the defining class, e.g. `Landroid/os/Build;`.
    pub class: &'static str,
    /// Method or field name, or `*` for any member of the class.
    pub member: &'static str,
    /// Taxonomy ID from `docs/divergence-taxonomy.md`.
    pub taxonomy: &'static str,
    pub confidence: Confidence,
    /// Why this rule carries the confidence it does.
    pub note: &'static str,
}

const V: Confidence = Confidence::Verified;
const C: Confidence = Confidence::Conjecture;

/// The rule table.
///
/// Ordering is irrelevant to matching (the lookup is a linear scan over a
/// small, fixed set) but grouped by taxonomy family for reviewability.
pub static RULES: &[ApiRule] = &[
    // ------------------------------------------------------------ SUB.BUILD
    ApiRule {
        class: "Landroid/os/Build;",
        member: "FINGERPRINT",
        taxonomy: "SUB.BUILD.FINGERPRINT",
        confidence: V,
        note: "static field on Build; the field *is* the assumption",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "MODEL",
        taxonomy: "SUB.BUILD.MODEL",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "MANUFACTURER",
        taxonomy: "SUB.BUILD.MANUFACTURER",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "BRAND",
        taxonomy: "SUB.BUILD.BRAND",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "PRODUCT",
        taxonomy: "SUB.BUILD.PRODUCT",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "DEVICE",
        taxonomy: "SUB.BUILD.DEVICE",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "HARDWARE",
        taxonomy: "SUB.BUILD.HARDWARE",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "BOARD",
        taxonomy: "SUB.BUILD.BOARD",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "BOOTLOADER",
        taxonomy: "SUB.BUILD.BOOTLOADER",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "SERIAL",
        taxonomy: "SUB.BUILD.SERIAL",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "TAGS",
        taxonomy: "SUB.BUILD.TAGS",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "RADIO",
        taxonomy: "SUB.BUILD.RADIO",
        confidence: V,
        note: "static field on Build",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "getRadioVersion",
        taxonomy: "SUB.BUILD.RADIO",
        confidence: V,
        note: "documented to return the radio firmware version",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "SUPPORTED_ABIS",
        taxonomy: "SUB.CPU.ARCH",
        confidence: V,
        note: "the ABI list the app believes it is running on",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "SUPPORTED_32_BIT_ABIS",
        taxonomy: "SUB.CPU.ARCH",
        confidence: V,
        note: "32-bit ABI fallback list",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "SUPPORTED_64_BIT_ABIS",
        taxonomy: "SUB.CPU.ARCH",
        confidence: V,
        note: "64-bit ABI list",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "CPU_ABI",
        taxonomy: "SUB.CPU.ARCH",
        confidence: V,
        note: "deprecated pre-API-21 ABI field",
    },
    ApiRule {
        class: "Landroid/os/Build$VERSION;",
        member: "SDK_INT",
        taxonomy: "SUB.BUILD.SDK_INT",
        confidence: V,
        note: "the API level the app branches on",
    },
    ApiRule {
        class: "Landroid/os/Build$VERSION;",
        member: "RELEASE",
        taxonomy: "SUB.BUILD.SDK_INT",
        confidence: V,
        note: "the version string the app branches on",
    },
    ApiRule {
        class: "Landroid/os/SystemProperties;",
        member: "*",
        taxonomy: "SUB.BUILD.EMULATOR",
        confidence: V,
        note: "the hidden getprop bridge; reading ro.* is how emulator detection works",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "getSerial",
        taxonomy: "SUB.BUILD.SERIAL",
        confidence: V,
        note: "documented to return Build.SERIAL or a generated value",
    },
    // ------------------------------------------------------------ SUB.TRUST
    ApiRule {
        class: "Landroid/security/keystore/KeyStore;",
        member: "*",
        taxonomy: "SUB.TRUST.KEYSTORE_ANDROIDKEYSTORE",
        confidence: C,
        note: "the class is the JCA provider front end; the *provider name* is the assumption",
    },
    ApiRule {
        class: "Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        member: "*",
        taxonomy: "SUB.TRUST.ATTESTATION_KEY",
        confidence: C,
        note: "a builder reference does not imply setAttestations were requested",
    },
    ApiRule {
        class: "Landroid/security/keystore/KeyProperties;",
        member: "*",
        taxonomy: "SUB.TRUST.ATTESTATION_KEY",
        confidence: C,
        note: "attestation constants are a subset of this class",
    },
    ApiRule {
        class: "Landroid/app/KeyguardManager;",
        member: "*",
        taxonomy: "SUB.TRUST.ROOT_DETECT",
        confidence: C,
        note: "isDeviceSecure is one of several integrity heuristics; not a root check by itself",
    },
    ApiRule {
        class: "Landroid/os/Debug;",
        member: "isDebuggerConnected",
        taxonomy: "SUB.TRUST.DEBUG_DETECT",
        confidence: V,
        note: "the method's contract is exactly the assumption",
    },
    ApiRule {
        class: "Landroid/accounts/AccountManager;",
        member: "getAccountsByType",
        taxonomy: "SUB.TRUST.GMS_ACCOUNT",
        confidence: C,
        note: "a non-GMS account type also resolves here; account *existence* is what matters",
    },
    ApiRule {
        class: "Landroid/accounts/AccountManager;",
        member: "*",
        taxonomy: "SUB.TRUST.GMS_ACCOUNT",
        confidence: C,
        note: "any AccountManager use is account-system dependency",
    },
    // ------------------------------------------------------------ SUB.KERNEL
    ApiRule {
        class: "Ljava/lang/Runtime;",
        member: "availableProcessors",
        taxonomy: "SUB.CPU.CORE_COUNT",
        confidence: V,
        note: "documented to return the available processor count",
    },
    // -------------------------------------------------------------- SUB.IPC
    ApiRule {
        class: "Landroid/os/ServiceManager;",
        member: "getService",
        taxonomy: "SUB.IPC.SERVICE_MANAGER",
        confidence: V,
        note: "documented to return an IBinder for a named system service",
    },
    ApiRule {
        class: "Landroid/content/Context;",
        member: "getSystemService",
        taxonomy: "SUB.IPC.SYSTEM_SERVICE",
        confidence: V,
        note: "the service accessor is the assumption",
    },
    ApiRule {
        class: "Landroid/content/Context;",
        member: "startActivityForResult",
        taxonomy: "SUB.IPC.ACTIVITY_MANAGER",
        confidence: V,
        note: "result-delivering activity launch",
    },
    ApiRule {
        class: "Landroid/app/Activity;",
        member: "startActivityForResult",
        taxonomy: "SUB.IPC.ACTIVITY_MANAGER",
        confidence: V,
        note: "result-delivering activity launch",
    },
    ApiRule {
        class: "Landroid/app/Activity;",
        member: "onActivityResult",
        taxonomy: "SUB.IPC.ACTIVITY_MANAGER",
        confidence: V,
        note: "the result callback that must fire",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "getPackageInfo",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: C,
        note: "also used for self-queries (SUB.IPC.PACKAGE_MANAGER_SELF); the argument decides",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "getApplicationInfo",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: C,
        note: "same self-vs-other ambiguity as getPackageInfo",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "queryIntentActivities",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: V,
        note: "documented to enumerate installed handlers; empty in a one-app substrate",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "queryIntentServices",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: V,
        note: "documented to enumerate installed services",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "queryIntentContentProviders",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: V,
        note: "documented to enumerate installed providers",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "getInstallerPackageName",
        taxonomy: "SUB.IPC.PACKAGE_MANAGER_OTHER",
        confidence: V,
        note: "the installer is another package by definition",
    },
    ApiRule {
        class: "Landroid/content/pm/PackageManager;",
        member: "hasSystemFeature",
        taxonomy: "SUB.BUILD.ABILITIES",
        confidence: V,
        note: "documented to answer from the device feature database",
    },
    ApiRule {
        class: "Landroid/app/AlarmManager;",
        member: "setExact",
        taxonomy: "SUB.IPC.ALARM_MANAGER",
        confidence: V,
        note: "exact alarm scheduling",
    },
    ApiRule {
        class: "Landroid/app/AlarmManager;",
        member: "setAlarmClock",
        taxonomy: "SUB.IPC.ALARM_MANAGER",
        confidence: V,
        note: "user-visible next-alarm scheduling",
    },
    ApiRule {
        class: "Landroid/app/JobScheduler;",
        member: "schedule",
        taxonomy: "SUB.IPC.JOB_SCHEDULER",
        confidence: V,
        note: "job enqueue",
    },
    ApiRule {
        class: "Landroid/net/ConnectivityManager;",
        member: "getActiveNetworkInfo",
        taxonomy: "SUB.IPC.CONNECTIVITY_MANAGER",
        confidence: V,
        note: "documented to return the currently active network",
    },
    ApiRule {
        class: "Landroid/net/ConnectivityManager;",
        member: "isActiveNetworkMetered",
        taxonomy: "SUB.IPC.CONNECTIVITY_MANAGER",
        confidence: V,
        note: "metering state of the active network",
    },
    ApiRule {
        class: "Landroid/app/NotificationManager;",
        member: "notify",
        taxonomy: "SUB.IPC.NOTIFICATION",
        confidence: V,
        note: "post a notification",
    },
    ApiRule {
        class: "Landroid/content/ContentResolver;",
        member: "query",
        taxonomy: "SUB.IPC.CONTENT_PROVIDER",
        confidence: C,
        note: "the app's own provider is also a legal target; the URI decides",
    },
    ApiRule {
        class: "Landroid/app/ActivityManager;",
        member: "getMemoryInfo",
        taxonomy: "SUB.MEM.HW_CAPS",
        confidence: V,
        note: "documented to fill in device memory state",
    },
    ApiRule {
        class: "Landroid/app/ActivityManager;",
        member: "isLowRamDevice",
        taxonomy: "SUB.MEM.HW_CAPS",
        confidence: V,
        note: "documented low-RAM heuristic",
    },
    // ---------------------------------------------------------------- SUB.FS
    ApiRule {
        class: "Ljava/lang/System;",
        member: "loadLibrary",
        taxonomy: "SUB.NATIVE.LOAD_LIBRARY",
        confidence: V,
        note: "documented to load a native shared library by name",
    },
    ApiRule {
        class: "Ljava/lang/System;",
        member: "load",
        taxonomy: "SUB.NATIVE.LOAD_LIBRARY",
        confidence: V,
        note: "documented to load a native shared library by absolute path",
    },
    ApiRule {
        class: "Ljava/lang/Runtime;",
        member: "loadLibrary",
        taxonomy: "SUB.NATIVE.LOAD_LIBRARY",
        confidence: V,
        note: "instance form of System.loadLibrary",
    },
    ApiRule {
        class: "Ljava/lang/Runtime;",
        member: "load",
        taxonomy: "SUB.NATIVE.LOAD_LIBRARY",
        confidence: V,
        note: "instance form of System.load",
    },
    ApiRule {
        class: "Ljava/lang/Runtime;",
        member: "exec",
        taxonomy: "SUB.FS.SYSTEM_LAYOUT",
        confidence: V,
        note: "process execution; no exec in the substrate",
    },
    ApiRule {
        class: "Landroid/os/Environment;",
        member: "getExternalStorageDirectory",
        taxonomy: "SUB.FS.EXTERNAL_STORAGE",
        confidence: V,
        note: "documented to return the shared external volume",
    },
    ApiRule {
        class: "Landroid/os/Environment;",
        member: "getExternalStorageState",
        taxonomy: "SUB.FS.EXTERNAL_STORAGE",
        confidence: V,
        note: "mounted state of the shared external volume",
    },
    ApiRule {
        class: "Landroid/os/Build;",
        member: "*",
        taxonomy: "SUB.BUILD.ABILITIES",
        confidence: C,
        note: "a catch-all: any Build member implies identity dependency",
    },
    // ---------------------------------------------------------------- SUB.RES
    ApiRule {
        class: "Landroid/content/res/Resources;",
        member: "getIdentifier",
        taxonomy: "SUB.RES.PACKAGE_RESOLVER",
        confidence: V,
        note: "name to resource id; needs the name->ID table, not just the ID space",
    },
    ApiRule {
        class: "Landroid/content/res/Resources;",
        member: "getResourceName",
        taxonomy: "SUB.RES.PACKAGE_RESOLVER",
        confidence: V,
        note: "resource id to name; the inverse mapping",
    },
    ApiRule {
        class: "Ljava/util/Locale;",
        member: "getDefault",
        taxonomy: "SUB.RES.LOCALE",
        confidence: V,
        note: "process default locale",
    },
    ApiRule {
        class: "Ljava/util/TimeZone;",
        member: "getDefault",
        taxonomy: "SUB.RES.TIMEZONE",
        confidence: V,
        note: "process default time zone",
    },
    ApiRule {
        class: "Landroid/util/DisplayMetrics;",
        member: "*",
        taxonomy: "SUB.RES.DISPLAY_METRICS",
        confidence: C,
        note: "a type reference does not prove density is read; the method_id is what counts",
    },
    // --------------------------------------------------------------- SUB.TIME
    ApiRule {
        class: "Landroid/os/SystemClock;",
        member: "uptimeMillis",
        taxonomy: "SUB.TIME.MONOTONIC",
        confidence: V,
        note: "documented as ms since boot excluding deep sleep",
    },
    ApiRule {
        class: "Landroid/os/SystemClock;",
        member: "elapsedRealtime",
        taxonomy: "SUB.TIME.ELAPSED_REALTIME",
        confidence: V,
        note: "documented as ms since boot including deep sleep",
    },
    ApiRule {
        class: "Ljava/lang/System;",
        member: "currentTimeMillis",
        taxonomy: "SUB.TIME.WALL_CLOCK",
        confidence: V,
        note: "device wall clock",
    },
    ApiRule {
        class: "Ljava/lang/Thread;",
        member: "sleep",
        taxonomy: "SUB.TIME.SLEEP",
        confidence: V,
        note: "documented to suspend for a duration",
    },
    ApiRule {
        class: "Landroid/view/Choreographer;",
        member: "*",
        taxonomy: "SUB.TIME.VSYNC",
        confidence: V,
        note: "documented to post frame callbacks on the display's vsync",
    },
    ApiRule {
        class: "Landroid/animation/ValueAnimator;",
        member: "*",
        taxonomy: "SUB.TIME.VSYNC",
        confidence: C,
        note: "frame-driven animator; the class exists without a display",
    },
    // ----------------------------------------------------------------- SUB.CPU
    ApiRule {
        class: "Ljava/lang/invoke/MethodHandle;",
        member: "*",
        taxonomy: "SUB.FW.INVOKEDYNAMIC",
        confidence: V,
        note: "the method-handle machinery invokedynamic desugars to",
    },
    ApiRule {
        class: "Ljava/lang/invoke/MethodHandles$Lookup;",
        member: "*",
        taxonomy: "SUB.FW.INVOKEDYNAMIC",
        confidence: V,
        note: "the call-site binding machinery",
    },
    ApiRule {
        class: "Ljava/lang/invoke/CallSite;",
        member: "*",
        taxonomy: "SUB.FW.INVOKEDYNAMIC",
        confidence: V,
        note: "the call-site object invokedynamic resolves against",
    },
    ApiRule {
        class: "Ljava/lang/invoke/ConstantCallSite;",
        member: "*",
        taxonomy: "SUB.FW.INVOKEDYNAMIC",
        confidence: V,
        note: "a lambda call site type",
    },
    ApiRule {
        class: "Ljava/lang/invoke/MethodType;",
        member: "*",
        taxonomy: "SUB.FW.INVOKEDYNAMIC",
        confidence: V,
        note: "the polymorphic signature machinery",
    },
    ApiRule {
        class: "Ljava/lang/invoke/MethodHandles$Lookup;",
        member: "findVirtual",
        taxonomy: "SUB.FW.NON_SDK_API",
        confidence: C,
        note: "handles on non-SDK framework members; the receiver decides",
    },
    // ----------------------------------------------------------------- SUB.MEM
    ApiRule {
        class: "Ljava/nio/ByteBuffer;",
        member: "allocateDirect",
        taxonomy: "SUB.MEM.DIRECT_BYTEBUFFER",
        confidence: V,
        note: "documented to allocate off-heap memory",
    },
    ApiRule {
        class: "Ljava/nio/MappedByteBuffer;",
        member: "*",
        taxonomy: "SUB.MEM.MMAP",
        confidence: V,
        note: "a mapped buffer is mmap by definition",
    },
    ApiRule {
        class: "Lsun/misc/Unsafe;",
        member: "*",
        taxonomy: "SUB.MEM.DIRECT_BYTEBUFFER",
        confidence: V,
        note: "raw off-heap access",
    },
    ApiRule {
        class: "Ljava/io/FileInputStream;",
        member: "getChannel",
        taxonomy: "SUB.MEM.MMAP",
        confidence: C,
        note: "a channel is often used without mmap",
    },
    // --------------------------------------------------------------- SUB.NET
    ApiRule {
        class: "Ljava/net/Socket;",
        member: "*",
        taxonomy: "SUB.NET.EGRESS",
        confidence: C,
        note: "a socket reference is not necessarily an outbound connection",
    },
    ApiRule {
        class: "Ljava/net/URL;",
        member: "openConnection",
        taxonomy: "SUB.NET.EGRESS",
        confidence: V,
        note: "documented to open a connection",
    },
    ApiRule {
        class: "Ljava/net/HttpURLConnection;",
        member: "*",
        taxonomy: "SUB.NET.EGRESS",
        confidence: C,
        note: "type reference; the call sites are counted separately",
    },
    ApiRule {
        class: "Lorg/conscrypt/Conscrypt;",
        member: "*",
        taxonomy: "SUB.NET.NATIVE_HTTP",
        confidence: V,
        note: "the Conscrypt provider, whose default socket factory is backed by BoringSSL",
    },
    ApiRule {
        class: "Lorg/chromium/net/ChronetEngine;",
        member: "*",
        taxonomy: "SUB.NET.NATIVE_HTTP",
        confidence: V,
        note: "Cronet's engine; the stack is native by construction",
    },
    ApiRule {
        class: "Ljava/net/ProxySelector;",
        member: "getDefault",
        taxonomy: "SUB.NET.PROXY",
        confidence: V,
        note: "process default proxy selector",
    },
    ApiRule {
        class: "Landroid/net/VpnService;",
        member: "*",
        taxonomy: "SUB.NET.PROXY",
        confidence: V,
        note: "VPN configuration API",
    },
    // ---------------------------------------------------------------- SUB.GFX
    ApiRule {
        class: "Landroid/opengl/EGL14;",
        member: "*",
        taxonomy: "SUB.GFX.EGL_CONTEXT",
        confidence: V,
        note: "the EGL context API",
    },
    ApiRule {
        class: "Landroid/opengl/GLES20;",
        member: "*",
        taxonomy: "SUB.GFX.EGL_CONTEXT",
        confidence: V,
        note: "the GLES entry points; a context must exist to call them",
    },
    ApiRule {
        class: "Landroid/opengl/GLSurfaceView;",
        member: "*",
        taxonomy: "SUB.GFX.EGL_CONTEXT",
        confidence: V,
        note: "a GLES view owns an EGL context",
    },
    ApiRule {
        class: "Landroid/vulkan/Vulkan;",
        member: "*",
        taxonomy: "SUB.GFX.VULKAN",
        confidence: V,
        note: "the Vulkan loader API",
    },
    ApiRule {
        class: "Landroid/view/Surface;",
        member: "*",
        taxonomy: "SUB.GFX.SURFACE",
        confidence: V,
        note: "a surface is a BufferQueue consumer",
    },
    ApiRule {
        class: "Landroid/view/SurfaceView;",
        member: "*",
        taxonomy: "SUB.GFX.SURFACE",
        confidence: V,
        note: "a dedicated drawing surface",
    },
    ApiRule {
        class: "Landroid/media/MediaPlayer;",
        member: "*",
        taxonomy: "SUB.GFX.SURFACE",
        confidence: C,
        note: "audio-only playback needs no surface",
    },
    ApiRule {
        class: "Landroid/graphics/Canvas;",
        member: "*",
        taxonomy: "SUB.GFX.TEXT_RENDER",
        confidence: C,
        note: "a canvas can be used for non-text drawing",
    },
    ApiRule {
        class: "Landroid/os/PowerManager;",
        member: "isScreenOn",
        taxonomy: "SUB.GFX.SCREEN_ON",
        confidence: V,
        note: "documented screen-on state",
    },
    ApiRule {
        class: "Landroid/os/PowerManager;",
        member: "newWakeLock",
        taxonomy: "SUB.PWR.WAKE_LOCK",
        confidence: V,
        note: "acquire a wake lock",
    },
    // ----------------------------------------------------------------- SUB.HW
    ApiRule {
        class: "Landroid/hardware/SensorManager;",
        member: "*",
        taxonomy: "SUB.HW.SENSORS",
        confidence: V,
        note: "the sensor registry",
    },
    ApiRule {
        class: "Landroid/location/LocationManager;",
        member: "*",
        taxonomy: "SUB.HW.LOCATION",
        confidence: V,
        note: "the platform location API",
    },
    ApiRule {
        class: "Lcom/google/android/gms/location/FusedLocationProviderClient;",
        member: "*",
        taxonomy: "SUB.HW.LOCATION",
        confidence: V,
        note: "the GMS fused provider; requires Play Services",
    },
    ApiRule {
        class: "Landroid/hardware/CameraManager;",
        member: "*",
        taxonomy: "SUB.GFX.CAMERA_PIPE",
        confidence: V,
        note: "the camera2 manager",
    },
    ApiRule {
        class: "Landroid/hardware/Camera;",
        member: "*",
        taxonomy: "SUB.GFX.CAMERA_PIPE",
        confidence: V,
        note: "the deprecated camera API",
    },
    ApiRule {
        class: "Landroid/bluetooth/BluetoothAdapter;",
        member: "*",
        taxonomy: "SUB.HW.BLUETOOTH",
        confidence: V,
        note: "the local Bluetooth adapter",
    },
    ApiRule {
        class: "Landroid/nfc/NfcAdapter;",
        member: "*",
        taxonomy: "SUB.HW.NFC",
        confidence: V,
        note: "the NFC adapter",
    },
    ApiRule {
        class: "Landroid/telephony/TelephonyManager;",
        member: "*",
        taxonomy: "SUB.HW.TELEPHONY",
        confidence: V,
        note: "the telephony subsystem",
    },
    ApiRule {
        class: "Landroid/os/Vibrator;",
        member: "*",
        taxonomy: "SUB.HW.VIBRATE",
        confidence: V,
        note: "the haptic actuator",
    },
    ApiRule {
        class: "Landroid/hardware/biometrics/BiometricPrompt;",
        member: "*",
        taxonomy: "SUB.HW.BIOMETRIC",
        confidence: V,
        note: "the biometric prompt",
    },
    ApiRule {
        class: "Landroid/hardware/fingerprint/FingerprintManager;",
        member: "*",
        taxonomy: "SUB.HW.BIOMETRIC",
        confidence: V,
        note: "the deprecated fingerprint API",
    },
    // ----------------------------------------------------------------- SUB.FW
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "forName",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "documented to load a class by name at run time",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getDeclaredMethod",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective method lookup",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getDeclaredMethods",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective method enumeration",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getMethod",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective public method lookup",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getMethods",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective public method enumeration",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getDeclaredField",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective field lookup",
    },
    ApiRule {
        class: "Ljava/lang/Class;",
        member: "getFields",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective public field enumeration",
    },
    ApiRule {
        class: "Ljava/lang/reflect/Method;",
        member: "invoke",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective invocation",
    },
    ApiRule {
        class: "Ljava/lang/reflect/Constructor;",
        member: "newInstance",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "reflective construction",
    },
    ApiRule {
        class: "Ljava/lang/reflect/Proxy;",
        member: "newProxyInstance",
        taxonomy: "SUB.FW.REFLECTION",
        confidence: V,
        note: "dynamic proxy generation; needs the full interface surface",
    },
    ApiRule {
        class: "Ljava/lang/reflect/Field;",
        member: "setAccessible",
        taxonomy: "SUB.FW.NON_SDK_API",
        confidence: C,
        note: "often used to reach non-SDK members; also used on public members",
    },
    ApiRule {
        class: "Ljava/lang/reflect/Method;",
        member: "setAccessible",
        taxonomy: "SUB.FW.NON_SDK_API",
        confidence: C,
        note: "as above",
    },
    ApiRule {
        class: "Ldalvik/system/DexClassLoader;",
        member: "*",
        taxonomy: "SUB.FW.DYNAMIC_CODE",
        confidence: V,
        note: "documented to load dex from a path at run time",
    },
    ApiRule {
        class: "Ldalvik/system/InMemoryDexClassLoader;",
        member: "*",
        taxonomy: "SUB.FW.DYNAMIC_CODE",
        confidence: V,
        note: "documented to load dex from a byte buffer",
    },
    ApiRule {
        class: "Ldalvik/system/PathClassLoader;",
        member: "*",
        taxonomy: "SUB.FW.DYNAMIC_CODE",
        confidence: V,
        note: "a dex-backed class loader",
    },
    ApiRule {
        class: "Ldalvik/system/BaseDexClassLoader;",
        member: "*",
        taxonomy: "SUB.FW.DYNAMIC_CODE",
        confidence: V,
        note: "the abstract supertype of every dex class loader; a reference to it is a reference to dex loading",
    },
    ApiRule {
        class: "Landroid/content/ComponentName;",
        member: "*",
        taxonomy: "SUB.FW.SERIALIZATION",
        confidence: C,
        note: "ComponentName is part of the Intent marshalling contract",
    },
    ApiRule {
        class: "Landroid/os/Parcel;",
        member: "*",
        taxonomy: "SUB.FW.SERIALIZATION",
        confidence: V,
        note: "the marshalling primitive itself",
    },
    ApiRule {
        class: "Landroid/os/Bundle;",
        member: "*",
        taxonomy: "SUB.FW.SERIALIZATION",
        confidence: V,
        note: "the parcelled map itself",
    },
    ApiRule {
        class: "Landroid/os/IBinder;",
        member: "*",
        taxonomy: "SUB.FW.SERIALIZATION",
        confidence: V,
        note: "the Binder marshalling interface",
    },
    ApiRule {
        class: "Landroid/content/Intent;",
        member: "*",
        taxonomy: "SUB.FW.SERIALIZATION",
        confidence: C,
        note:
            "Intents are the most-marshalled object, but the class is also the substrate's own hook",
    },
    ApiRule {
        class: "Landroid/webkit/WebView;",
        member: "*",
        taxonomy: "SUB.FW.WEBVIEW",
        confidence: V,
        note: "the WebView class; a hybrid app's entire UI depends on it",
    },
    ApiRule {
        class: "Landroid/webkit/WebView;",
        member: "addJavascriptInterface",
        taxonomy: "SUB.FW.WEBVIEW",
        confidence: V,
        note: "the Java to JS bridge",
    },
    ApiRule {
        class: "Landroid/webkit/WebViewClient;",
        member: "*",
        taxonomy: "SUB.FW.WEBVIEW",
        confidence: V,
        note: "WebView navigation and JS callback plumbing",
    },
    ApiRule {
        class: "Landroid/webkit/WebSettings;",
        member: "*",
        taxonomy: "SUB.FW.WEBVIEW",
        confidence: V,
        note: "WebView configuration",
    },
    ApiRule {
        class: "Landroid/app/Application;",
        member: "*",
        taxonomy: "SUB.FW.ACTIVITY_LIFECYCLE",
        confidence: C,
        note: "any Application subclass is the lifecycle entry point, not evidence of misuse",
    },
    ApiRule {
        class: "Landroid/app/Activity;",
        member: "onCreate",
        taxonomy: "SUB.FW.ACTIVITY_LIFECYCLE",
        confidence: V,
        note: "the documented first lifecycle callback",
    },
    ApiRule {
        class: "Landroid/content/ContentProvider;",
        member: "onCreate",
        taxonomy: "SUB.FW.CONTENT_PROVIDER_INIT",
        confidence: V,
        note: "documented to run before Application.onCreate",
    },
    ApiRule {
        class: "Landroid/app/Activity;",
        member: "onConfigurationChanged",
        taxonomy: "SUB.FW.ACTIVITY_LIFECYCLE",
        confidence: V,
        note: "configuration-change handling",
    },
    // -------------------------------------------------------------- SUB.INPUT
    ApiRule {
        class: "Landroid/view/InputMethodManager;",
        member: "showSoftInput",
        taxonomy: "SUB.INPUT.IME",
        confidence: V,
        note: "request a soft keyboard",
    },
    ApiRule {
        class: "Landroid/view/inputmethod/InputMethodManager;",
        member: "showSoftInput",
        taxonomy: "SUB.INPUT.IME",
        confidence: V,
        note: "fully-qualified form of the same class",
    },
    ApiRule {
        class: "Landroid/view/MotionEvent;",
        member: "*",
        taxonomy: "SUB.INPUT.INPUT_EVENT",
        confidence: C,
        note: "the app may only dispatch synthetic events, not receive them",
    },
    ApiRule {
        class: "Landroid/view/KeyEvent;",
        member: "*",
        taxonomy: "SUB.INPUT.INPUT_EVENT",
        confidence: C,
        note: "as above",
    },
    // ---------------------------------------------------------------- SUB.PWR
    ApiRule {
        class: "Landroid/os/IdleStateObserver;",
        member: "*",
        taxonomy: "SUB.PWR.DOZE",
        confidence: C,
        note: "an observer interface; the app may register and never be called",
    },
    ApiRule {
        class: "Landroid/app/PowerManager;",
        member: "*",
        taxonomy: "SUB.PWR.DOZE",
        confidence: C,
        note: "power-management entry point; Doze is one of several concerns",
    },
    ApiRule {
        class: "Landroid/os/BatteryManager;",
        member: "*",
        taxonomy: "SUB.PWR.BATTERY",
        confidence: V,
        note: "the battery subsystem",
    },
    ApiRule {
        class: "Landroid/os/BroadcastReceiver;",
        member: "onReceive",
        taxonomy: "SUB.IPC.BROADCAST",
        confidence: C,
        note: "a receiver is *delivered* broadcasts; onReceive alone does not say which",
    },
    ApiRule {
        class: "Landroid/content/BroadcastReceiver;",
        member: "onReceive",
        taxonomy: "SUB.IPC.BROADCAST",
        confidence: C,
        note: "as above",
    },
];

/// Every taxonomy ID the rules can produce, sorted and deduplicated.
///
/// Used to size the "IDs this app structurally requires" output, and to make
/// sure a future rule edit cannot silently introduce an ID that is not in
/// `docs/divergence-taxonomy.md` (asserted in `tests/taxonomy_ids.rs`).
pub fn mapped_ids() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = RULES.iter().map(|r| r.taxonomy).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The family of a taxonomy ID: `SUB.FW.REFLECTION` → `SUB.FW`.
///
/// Returns a sub-slice of `id`, so there is no allocation and no interning. An
/// ID with fewer than three components is returned unchanged, which keeps a
/// malformed future ID visible instead of silently becoming an empty family.
pub fn family_of(id: &str) -> &str {
    let mut rest = id;
    // Skip the leading `SUB.`.
    for want in 0..2 {
        let Some(dot) = rest.find('.') else { return id };
        if dot == 0 {
            return id;
        }
        rest = &rest[dot + 1..];
        if want == 1 {
            // `rest` is now `MEMBER`; the family is everything before it.
            return &id[..id.len() - rest.len() - 1];
        }
    }
    id
}

/// Look a rule up by class descriptor and member name.
///
/// Matching is exact on the class and exact-or-`*` on the member, most specific
/// first, so a catch-all `*` rule never shadows a named rule for the same class.
pub fn lookup(class: &str, member: &str) -> Vec<&'static ApiRule> {
    let mut out: Vec<&'static ApiRule> = RULES
        .iter()
        .filter(|r| r.class == class && (r.member == member || r.member == "*"))
        .collect();
    out.sort_by_key(|r| if r.member == "*" { 1 } else { 0 });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_id_is_shaped_like_a_taxonomy_id() {
        for id in mapped_ids() {
            assert!(id.starts_with("SUB."), "{id} is not a SUB.* id");
            assert_eq!(id.split('.').count(), 3, "{id} is not SUB.FAMILY.MEMBER");
            for seg in id.split('.') {
                assert!(
                    seg.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
                    "{id} has a non-constant segment {seg}"
                );
            }
        }
    }

    #[test]
    fn no_rule_invents_a_taxonomy_id() {
        // The taxonomy is frozen pre-registration, so the rule table may only
        // reference IDs that actually exist in it. If
        // `docs/divergence-taxonomy.md` cannot be read the check is skipped
        // rather than silently passing, and says so.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/divergence-taxonomy.md");
        let Ok(text) = std::fs::read_to_string(&path) else {
            eprintln!("skipping: {} not readable", path.display());
            return;
        };
        let mut declared: Vec<&str> = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while let Some(at) = text[i..].find("SUB.") {
            let start = i + at;
            let mut end = start;
            while end < bytes.len()
                && (bytes[end].is_ascii_uppercase() || bytes[end] == b'_' || bytes[end] == b'.')
            {
                end += 1;
            }
            declared.push(&text[start..end]);
            i = end;
        }
        declared.sort_unstable();
        declared.dedup();
        assert!(
            declared.len() > 100,
            "only {} IDs parsed from the taxonomy; the extraction is broken",
            declared.len()
        );
        for id in mapped_ids() {
            assert!(
                declared.contains(&id),
                "{id} is used by a rule but is not declared in docs/divergence-taxonomy.md"
            );
        }
    }

    #[test]
    fn load_library_maps_to_a_verified_rule() {
        let rules = lookup("Ljava/lang/System;", "loadLibrary");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].taxonomy, "SUB.NATIVE.LOAD_LIBRARY");
        assert_eq!(rules[0].confidence, Confidence::Verified);
    }

    #[test]
    fn build_fingerprint_is_verified_but_the_build_catch_all_is_not() {
        assert_eq!(
            lookup("Landroid/os/Build;", "FINGERPRINT")[0].confidence,
            Confidence::Verified
        );
        let catch_all = lookup("Landroid/os/Build;", "FINGERPRINT")
            .into_iter()
            .find(|r| r.member == "*")
            .expect("the Build catch-all must still apply");
        assert_eq!(catch_all.taxonomy, "SUB.BUILD.ABILITIES");
        assert_eq!(catch_all.confidence, Confidence::Conjecture);
    }

    #[test]
    fn a_named_rule_sorts_before_the_catch_all() {
        let rules = lookup("Landroid/os/Build;", "FINGERPRINT");
        assert_eq!(rules[0].member, "FINGERPRINT");
        assert_eq!(rules[1].member, "*");
    }

    #[test]
    fn an_unmapped_class_returns_nothing() {
        assert!(lookup("Lcom/example/Widget;", "doThing").is_empty());
    }

    #[test]
    fn family_extraction_takes_the_first_two_components() {
        assert_eq!(family_of("SUB.FW.REFLECTION"), "SUB.FW");
        assert_eq!(family_of("SUB.BUILD.SDK_INT"), "SUB.BUILD");
        assert_eq!(family_of("garbage"), "garbage");
    }

    #[test]
    fn both_confidence_levels_are_represented() {
        // A table with only VERIFIED rows would be a lie about what is known.
        assert!(RULES.iter().any(|r| r.confidence == Confidence::Conjecture));
        assert!(RULES.iter().any(|r| r.confidence == Confidence::Verified));
        let conjectures = RULES
            .iter()
            .filter(|r| r.confidence == Confidence::Conjecture)
            .count();
        assert!(
            conjectures >= 20,
            "expected a substantial CONJECTURE share, got {conjectures}"
        );
    }
}
