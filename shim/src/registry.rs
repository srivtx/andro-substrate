//! The shim's class and method table.
//!
//! # One table, four consumers
//!
//! This module is the single source of truth for the shim's surface, and it is
//! consumed by four things that must never disagree:
//!
//! | consumer | what it needs the table for |
//! |---|---|
//! | [`crate::emit`] | the DEX: class defs, method ids, access flags |
//! | [`crate::dispatch`] | which methods have behaviour and what it does |
//! | [`shim/CONFORMANCE.md`](../../CONFORMANCE.md) | the coverage table |
//! | [`crate::classes`] | which descriptors resolve in the shim |
//!
//! A shim whose documentation, emitted bytecode and dispatch table disagree is
//! worse than no shim: the recording would claim coverage it does not have, and
//! the whole project is a claim about coverage. So there is one table and
//! `tests/conformance.rs` checks the other three against it.
//!
//! # Methods are `ACC_NATIVE`, and that is a safety decision
//!
//! Every shim method is emitted with `ACC_NATIVE` and no `code_item`. Two
//! consequences, both deliberate:
//!
//! * The DEX is a **signature manifest**, not a program. The semantics live in
//!   the dispatcher, keyed on `(class, method, descriptor)`, which is where the
//!   observation happens. There is no way for the two to disagree because there
//!   is only one of them.
//! * A method with `ACC_NATIVE` and no registration **throws
//!   `UnsatisfiedLinkError`**. If this DEX were ever installed on a real device
//!   — a mistake, a repackaging, a leaked artefact — the failure mode is a loud
//!   exception, not a method that silently returns `0` and lets an app limp
//!   along producing wrong results. The safe default for an instrument is the
//!   one that is unusable when misplaced.
//!
//! # The table is deliberately incomplete
//!
//! `corpus/report.md` says 44.76% of F-Droid apps have no native code, and
//! `docs/divergence-taxonomy.md` §0.1 says that does not imply they will run.
//! This table is the concrete demonstration: it covers the classes the six
//! committed DEX fixtures actually reference, plus the networking, JNI and
//! serialisation surfaces the observation layer exists to see, and it is still
//! nowhere near the ~30 000 classes in `android.jar`. `CONFORMANCE.md` says
//! exactly what fraction, measured against those fixtures rather than asserted.

use crate::event::FsOp;

/// A field on a shim class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimField {
    pub name: &'static str,
    pub type_descriptor: &'static str,
    pub is_static: bool,
    /// The taxonomy ID a read of this field feeds, where that is meaningful.
    /// `None` for bookkeeping fields with no assumption behind them.
    pub assumption: Option<&'static str>,
}

/// What a method does when the dispatcher runs it.
///
/// This is the observation contract. It is deliberately coarse: it names *what
/// is observed*, not *how the app's value is computed*, because the second is
/// the interpreter's business and duplicating it here would create two
/// implementations of the same semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    /// Constructor / class initialiser. Records nothing on its own.
    Init,
    /// An observation-bearing call. The `pattern` becomes a `SIGNAL_PAT.*`.
    Probe { pattern: &'static str },
    /// A field accessor. `is_get` distinguishes `getX` from `setX`.
    Field { is_get: bool },
    /// A constructor for a container type; records nothing.
    Construct,
    /// A member of the observation surface with a *specific* dispatcher entry
    /// point, named so a missing implementation is a compile error rather than
    /// a silent fallthrough.
    Dispatch(&'static str),
    /// A method with no behaviour. Present so the type resolves; calling it is
    /// a recorder bug, and the dispatcher says so rather than guessing.
    Inert,
}

/// A method on a shim class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimMethod {
    pub name: &'static str,
    /// Parameter type descriptors, e.g. `&["I", "Ljava/lang/String;"]`.
    pub params: &'static [&'static str],
    /// Return descriptor.
    pub ret: &'static str,
    /// Bitwise OR of `ACC_*` constants from `dexcore::model::access`.
    pub access_flags: u32,
    pub behaviour: Behaviour,
    /// One line of prose, quoted into `CONFORMANCE.md`.
    pub doc: &'static str,
}

/// A class in the shim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimClass {
    pub descriptor: &'static str,
    /// `None` only for `Ljava/lang/Object;`, which is the root.
    pub superclass: Option<&'static str>,
    pub interfaces: &'static [&'static str],
    pub access_flags: u32,
    pub static_fields: &'static [ShimField],
    pub instance_fields: &'static [ShimField],
    pub direct_methods: &'static [ShimMethod],
    pub virtual_methods: &'static [ShimMethod],
}

impl ShimClass {
    /// Every method on the class, direct then virtual.
    pub fn methods(&self) -> impl Iterator<Item = &'static ShimMethod> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
    }
}

// Access-flag shorthands, matching `dexcore::model::access` so the emit path
// needs no arithmetic.
const PUBLIC: u32 = dexcore::model::access::ACC_PUBLIC;
const STATIC: u32 = dexcore::model::access::ACC_STATIC;
const FINAL: u32 = dexcore::model::access::ACC_FINAL;
const NATIVE: u32 = dexcore::model::access::ACC_NATIVE;
const ABSTRACT: u32 = dexcore::model::access::ACC_ABSTRACT;
const CTOR: u32 = dexcore::model::access::ACC_CONSTRUCTOR;

/// `Ljava/lang/String;`, the most-referenced type in every fixture.
const STRING: &str = "Ljava/lang/String;";
const OBJECT: &str = "Ljava/lang/Object;";
const BUNDLE: &str = "Landroid/os/Bundle;";
const CONTEXT: &str = "Landroid/content/Context;";
const CONTEXT_WRAPPER: &str = "Landroid/content/ContextWrapper;";
const VIEW: &str = "Landroid/view/View;";
const VIEWGROUP: &str = "Landroid/view/ViewGroup;";
const URL: &str = "Ljava/net/URL;";
const URLCONN: &str = "Ljava/net/URLConnection;";
const PACKAGE_INFO: &str = "Landroid/content/pm/PackageInfo;";
const APP_INFO: &str = "Landroid/content/pm/ApplicationInfo;";
const PARCELABLE: &str = "Landroid/os/Parcelable;";
const THROWABLE: &str = "Ljava/lang/Throwable;";

macro_rules! ctor {
    ($($ignored:expr),*) => {
        ShimMethod {
            name: "<init>",
            params: &[],
            ret: "V",
            // Native like every other shim method: a `new` in a misplaced DEX
            // must throw, not silently produce an uninitialised object.
            access_flags: PUBLIC | CTOR | NATIVE,
            behaviour: Behaviour::Construct,
            doc: "Constructor. Records nothing on its own.",
        }
    };
}

macro_rules! ctor_with {
    ($($name:expr),*) => {
        ShimMethod {
            name: "<init>",
            params: &[$($name),*],
            ret: "V",
            // Native like every other shim method: a `new` in a misplaced DEX
            // must throw, not silently produce an uninitialised object.
            access_flags: PUBLIC | CTOR | NATIVE,
            behaviour: Behaviour::Construct,
            doc: "Constructor. Records nothing on its own.",
        }
    };
}

/// A **static** Android method. Getting this wrong is not a cosmetic bug: the
/// dispatcher strips `args[0]` as `this` for an instance method, so a static
/// method wrongly marked as an instance one silently loses its first argument.
/// `tests/conformance.rs` checks the set below against a list of real Android
/// signatures, so an app that calls `System.loadLibrary("foo")` and gets
/// `parameter 0 was not a string` cannot happen silently.
macro_rules! nats {
    ($name:literal, [$($p:expr),*], $r:expr, $b:expr, $doc:literal) => {
        ShimMethod {
            name: $name,
            params: &[$($p),*],
            ret: $r,
            access_flags: PUBLIC | NATIVE | STATIC,
            behaviour: $b,
            doc: $doc,
        }
    };
}

macro_rules! nat {
    ($name:literal, [$($p:expr),*], $r:expr, $b:expr, $doc:literal) => {
        ShimMethod {
            name: $name,
            params: &[$($p),*],
            ret: $r,
            access_flags: PUBLIC | NATIVE,
            behaviour: $b,
            doc: $doc,
        }
    };
}

/// The whole table. Ordered by package, then by class, then by member, so the
/// emitted DEX, the conformance table and a diff all read the same way.
pub static CLASSES: &[ShimClass] = &[
    // ================================================== android.app
    ShimClass {
        descriptor: "Landroid/app/Activity;",
        superclass: Some(CONTEXT_WRAPPER),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[
            ShimField {
                name: "shimView",
                type_descriptor: VIEW,
                is_static: false,
                assumption: Some("SUB.GFX.TEXT_RENDER"),
            },
        ],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("onCreate", [BUNDLE], "V", Behaviour::Dispatch("activity.onCreate"),
                 "onCreate(Bundle). Records the lifecycle transition; SUB.FW.ACTIVITY_LIFECYCLE is the assumption the *ordering* feeds."),
            nat!("onStart", [], "V", Behaviour::Dispatch("activity.onStart"),
                 "onStart(). Lifecycle transition only."),
            nat!("onResume", [], "V", Behaviour::Dispatch("activity.onResume"),
                 "onResume(). Lifecycle transition only."),
            nat!("onPause", [], "V", Behaviour::Dispatch("activity.onPause"),
                 "onPause(). Lifecycle transition only."),
            nat!("onStop", [], "V", Behaviour::Dispatch("activity.onStop"),
                 "onStop(). Lifecycle transition only."),
            nat!("onDestroy", [], "V", Behaviour::Dispatch("activity.onDestroy"),
                 "onDestroy(). Lifecycle transition only."),
            nat!("setContentView", ["I"], "V", Behaviour::Dispatch("activity.setContentView"),
                 "setContentView(int). Resolves a layout id; with no resources.arsc this is SUB.RES.ARSC."),
            nat!("findViewById", ["I"], VIEW, Behaviour::Dispatch("activity.findViewById"),
                 "findViewById(int). Returns the shim's view if the id is one it knows, else null."),
            nat!("finish", [], "V", Behaviour::Dispatch("activity.finish"),
                 "finish(). Records the request; no second activity is ever launched (SUB.IPC.ACTIVITY_MANAGER)."),
            nat!("getWindow", [], "Landroid/view/Window;", Behaviour::Dispatch("activity.getWindow"),
                 "getWindow(). A Window shim exists so SUB.IPC.WINDOW_MANAGER is a *refusal* the app can catch, not a NoClassDefFoundError."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/ActivityContext;",
        superclass: Some(CONTEXT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("startActivity", [OBJECT], "V", Behaviour::Dispatch("context.startActivity"),
                 "startActivity(Intent). Records the intent's action and component only, then a SUB.IPC.ACTIVITY_MANAGER refusal."),
            nat!("startService", [OBJECT], "V", Behaviour::Dispatch("context.startService"),
                 "startService(Intent). Refused: there is no service manager."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/Application;",
        superclass: Some(CONTEXT_WRAPPER),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("onCreate", [], "V", Behaviour::Dispatch("application.onCreate"),
                 "onCreate(). Recorded so the launch-order assumption SUB.FW.CONTENT_PROVIDER_INIT is checkable."),
        ],
    },
    // ================================================== android.content
    ShimClass {
        descriptor: "Landroid/content/Context;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getPackageName", [], STRING, Behaviour::Dispatch("context.getPackageName"),
                 "getPackageName(). The subject's own package; SUB.IPC.PACKAGE_MANAGER_SELF."),
            nat!("getPackageManager", [], "Landroid/content/pm/PackageManager;", Behaviour::Dispatch("context.getPackageManager"),
                 "getPackageManager(). Returns the shim's PackageManager."),
            nat!("getApplicationInfo", [], APP_INFO, Behaviour::Dispatch("context.getApplicationInfo"),
                 "getApplicationInfo(). Synthesised; the real APK is not mounted anywhere."),
            nat!("getSystemService", [STRING], OBJECT, Behaviour::Dispatch("context.getSystemService"),
                 "getSystemService(String). Every service except PACKAGE_SERVICE is null: SUB.IPC.SYSTEM_SERVICE."),
            nat!("getFilesDir", [], STRING, Behaviour::Dispatch("context.getFilesDir"),
                 "getFilesDir(). A VFS path under /data/data/<pkg>; SUB.FS.DATA_DIR."),
            nat!("getCacheDir", [], STRING, Behaviour::Dispatch("context.getCacheDir"),
                 "getCacheDir(). A VFS path."),
            nat!("getDataDir", [], STRING, Behaviour::Dispatch("context.getDataDir"),
                 "getDataDir(). /data/data/<pkg> — the legacy symlink path, deliberately distinct from getFilesDir()."),
            nat!("getExternalFilesDir", [STRING], STRING, Behaviour::Dispatch("context.getExternalFilesDir"),
                 "getExternalFilesDir(String). A VFS path under /sdcard; there is no shared volume (SUB.FS.EXTERNAL_STORAGE)."),
            nat!("openFileInput", [STRING, "I"], "Ljava/io/FileInputStream;", Behaviour::Dispatch("fs.openFileInput"),
                 "openFileInput(String, int). A VFS read."),
            nat!("openFileOutput", [STRING, "I"], "Ljava/io/FileOutputStream;", Behaviour::Dispatch("fs.openFileOutput"),
                 "openFileOutput(String, int). A VFS write."),
            nat!("getString", ["I"], STRING, Behaviour::Dispatch("res.getString"),
                 "getString(int). Returns the shim's own string for a known id, else null: SUB.RES.ARSC."),
            nat!("getAssets", [], "Landroid/content/res/AssetManager;", Behaviour::Dispatch("res.getAssets"),
                 "getAssets(). Empty: the APK is not a filesystem."),
            nat!("sendBroadcast", [OBJECT], "V", Behaviour::Dispatch("context.sendBroadcast"),
                 "sendBroadcast(Intent). Records the intent; delivers nothing (SUB.IPC.BROADCAST)."),
            nat!("registerReceiver", [OBJECT, "Landroid/content/BroadcastReceiver;", "I"], OBJECT,
                 Behaviour::Dispatch("context.registerReceiver"),
                 "registerReceiver(...). Registers; BOOT_COMPLETED never arrives because there is no boot (SUB.PWR.BOOT_COMPLETED)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/ContextWrapper;",
        superclass: Some(CONTEXT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!("Landroid/content/Context;")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/content/Intent;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "ACTION_MAIN", type_descriptor: STRING, is_static: true, assumption: None },
            ShimField { name: "ACTION_VIEW", type_descriptor: STRING, is_static: true, assumption: None },
        ],
        instance_fields: &[
            ShimField { name: "action", type_descriptor: STRING, is_static: false, assumption: None },
            ShimField { name: "data", type_descriptor: "Landroid/net/Uri;", is_static: false, assumption: Some("SUB.NET.EGRESS") },
            ShimField { name: "packageName", type_descriptor: STRING, is_static: false, assumption: None },
            ShimField { name: "flags", type_descriptor: "I", is_static: false, assumption: None },
        ],
        direct_methods: &[
            ctor!(),
            ctor_with!(STRING),
        ],
        virtual_methods: &[
            nat!("getAction", [], STRING, Behaviour::Field { is_get: true }, "getAction(). Field read."),
            nat!("setAction", [STRING], OBJECT, Behaviour::Field { is_get: false }, "setAction(String). Field write."),
            nat!("getData", [], "Landroid/net/Uri;", Behaviour::Field { is_get: true },
                 "getData(). The URI is a *string* the app supplied; the dispatcher routes it to the egress sink, so an ACTION_VIEW intent carrying a URL becomes a denied request."),
            nat!("setData", ["Landroid/net/Uri;"], OBJECT, Behaviour::Field { is_get: false },
                 "setData(Uri). Field write; does not itself contact anything."),
            nat!("getPackageName", [], STRING, Behaviour::Field { is_get: true }, "getPackageName(). Field read."),
            nat!("addFlags", ["I"], OBJECT, Behaviour::Field { is_get: false }, "addFlags(int). Field write."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/ComponentName;",
        superclass: Some(PARCELABLE),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING, STRING)],
        virtual_methods: &[
            nat!("getPackageName", [], STRING, Behaviour::Field { is_get: true }, "getPackageName(). Field read."),
            nat!("getClassName", [], STRING, Behaviour::Field { is_get: true }, "getClassName(). Field read."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/BroadcastReceiver;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onReceive", [CONTEXT, OBJECT], "V", Behaviour::Dispatch("receiver.onReceive"),
                 "onReceive(Context, Intent). Never invoked by the shim; declared so SUB.PWR.BOOT_COMPLETED is a silent no-op rather than a NoClassDefFoundError."),
        ],
    },
    // ================================================== android.content.pm
    ShimClass {
        descriptor: "Landroid/content/pm/PackageManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getPackageInfo", [STRING, "I"], PACKAGE_INFO, Behaviour::Dispatch("pm.getPackageInfo"),
                 "getPackageInfo(String, int). Self-query answers; every other package answers null. This is SUB.IPC.PACKAGE_MANAGER_OTHER and it is silent."),
            nat!("getApplicationInfo", [STRING, "I", "I"], APP_INFO, Behaviour::Dispatch("pm.getApplicationInfo"),
                 "getApplicationInfo(String, int, int). Same rule."),
            nat!("getInstalledPackages", ["I"], "Ljava/util/List;", Behaviour::Dispatch("pm.getInstalledPackages"),
                 "getInstalledPackages(int). A list of exactly one. An app enumerating for a share target sees an empty answer, not an error."),
            nat!("queryIntentActivities", [OBJECT, "I"], "Ljava/util/List;", Behaviour::Dispatch("pm.queryIntentActivities"),
                 "queryIntentActivities(Intent, int). Always an empty list: there is one app and it is the caller."),
            nat!("hasSystemFeature", [STRING], "Z", Behaviour::Dispatch("pm.hasSystemFeature"),
                 "hasSystemFeature(String). Answers from the fabricated capability set: SUB.BUILD.ABILITIES."),
            nat!("getInstallerPackageName", [STRING], STRING, Behaviour::Dispatch("pm.getInstallerPackageName"),
                 "getInstallerPackageName(String). Always null: an APK dropped into a browser was never installed."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/pm/PackageInfo;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[
            ShimField { name: "packageName", type_descriptor: STRING, is_static: false, assumption: None },
            ShimField { name: "versionCode", type_descriptor: "I", is_static: false, assumption: None },
            ShimField { name: "versionName", type_descriptor: STRING, is_static: false, assumption: None },
        ],
        direct_methods: &[ctor!()],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/content/pm/ApplicationInfo;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[
            ShimField { name: "FLAG_DEBUGGABLE", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[
            ShimField { name: "packageName", type_descriptor: STRING, is_static: false, assumption: None },
            ShimField { name: "sourceDir", type_descriptor: STRING, is_static: false, assumption: Some("SUB.FS.PACKAGE_PATH") },
            ShimField { name: "dataDir", type_descriptor: STRING, is_static: false, assumption: Some("SUB.FS.DATA_DIR") },
            ShimField { name: "flags", type_descriptor: "I", is_static: false, assumption: None },
            ShimField { name: "nativeLibraryDir", type_descriptor: STRING, is_static: false, assumption: Some("SUB.FS.LIB_PATH") },
        ],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("isDebuggable", [], "Z", Behaviour::Dispatch("pm.isDebuggable"),
                 "ApplicationInfo.isDebuggable(). Always false, because the substrate is not a debuggable build and reporting true would manufacture a refusal."),
        ],
    },
    // ================================================== android.os
    ShimClass {
        descriptor: "Landroid/os/Bundle;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[
            ctor!(),
            ctor_with!(PARCELABLE),
        ],
        virtual_methods: &[
            nat!("putString", [STRING, STRING], "V", Behaviour::Dispatch("bundle.putString"),
                 "putString(String, String). Held in memory. Values are NOT recorded: a Bundle carries intents' extras and those carry identifiers."),
            nat!("getString", [STRING], STRING, Behaviour::Dispatch("bundle.getString"),
                 "getString(String). A read, returning the value the app put there."),
            nat!("putInt", [STRING, "I"], "V", Behaviour::Dispatch("bundle.putInt"), "putInt(String, int)."),
            nat!("getInt", [STRING], "I", Behaviour::Dispatch("bundle.getInt"), "getInt(String)."),
            nat!("putBoolean", [STRING, "Z"], "V", Behaviour::Dispatch("bundle.putBoolean"), "putBoolean(String, boolean)."),
            nat!("getBoolean", [STRING], "Z", Behaviour::Dispatch("bundle.getBoolean"), "getBoolean(String)."),
            nat!("containsKey", [STRING], "Z", Behaviour::Dispatch("bundle.containsKey"), "containsKey(String)."),
            nat!("keySet", [], "Ljava/util/Set;", Behaviour::Dispatch("bundle.keySet"), "keySet(). Keys only, never values."),
            nat!("isEmpty", [], "Z", Behaviour::Dispatch("bundle.isEmpty"), "isEmpty()."),
            nat!("size", [], "I", Behaviour::Dispatch("bundle.size"), "size()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/BaseBundle;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("containsKey", [STRING], "Z", Behaviour::Dispatch("bundle.containsKey"), "containsKey(String). Declared on BaseBundle as well so a cast to it resolves."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/PersistableBundle;",
        superclass: Some("Landroid/os/BaseBundle;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/os/Parcelable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("describeContents", [], "I", Behaviour::Inert, "describeContents(). Inert; the shim does not marshal to a byte buffer."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/Parcel;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("writeString", [STRING], "V", Behaviour::Dispatch("parcel.writeString"),
                 "writeString(String). Counts a byte length and a length prefix; records neither, because the payload is app data."),
            nat!("readString", [], STRING, Behaviour::Dispatch("parcel.readString"),
                 "readString(). Returns the value the app wrote. Round-trips within a run; does not survive a process death, which is SUB.FW.SERIALIZATION."),
            nats!("obtain", [], "Landroid/os/Parcel;", Behaviour::Dispatch("parcel.obtain"), "obtain(). A fresh in-memory parcel."),
            nat!("recycle", [], "V", Behaviour::Dispatch("parcel.recycle"), "recycle(). A no-op; there is no native buffer."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/Handler;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!("Landroid/os/Looper;")],
        virtual_methods: &[
            nat!("post", [OBJECT], "Z", Behaviour::Dispatch("handler.post"),
                 "post(Runnable). Enqueues into the virtual MessageQueue. Nothing drains it unless the host chooses to, and the substrate has no display, so a frame-driven state machine stalls (SUB.TIME.VSYNC)."),
            nat!("postDelayed", [OBJECT, "J"], "Z", Behaviour::Dispatch("handler.postDelayed"),
                 "postDelayed(Runnable, long). Enqueued with a due time."),
            nat!("removeCallbacks", [OBJECT], "V", Behaviour::Dispatch("handler.removeCallbacks"), "removeCallbacks(Runnable)."),
            nat!("getLooper", [], "Landroid/os/Looper;", Behaviour::Dispatch("handler.getLooper"), "getLooper(). The substrate's one looper."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/Looper;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("getMainLooper", [], "Landroid/os/Looper;", Behaviour::Dispatch("looper.getMainLooper"), "getMainLooper(). One looper, always the same."),
            nats!("prepare", [], "V", Behaviour::Dispatch("looper.prepare"), "prepare(). A no-op; the looper already exists."),
            nats!("loop", [], "V", Behaviour::Dispatch("looper.loop"), "loop(). Returns immediately. A real looper blocks forever; one that never blocks is the shape of the SUB.TIME.VSYNC divergence."),
            nats!("quit", [], "V", Behaviour::Dispatch("looper.quit"), "quit(). A no-op."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/MessageQueue;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("size", [], "I", Behaviour::Dispatch("queue.size"), "size(). How much work the app has queued and is waiting on. The clearest single measurement of SUB.TIME.VSYNC."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/SystemClock;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("uptimeMillis", [], "J", Behaviour::Probe { pattern: "SIGNAL_PAT.CLOCK_UPTIME" },
                 "uptimeMillis(). The substrate's virtual clock. Monotonic by construction, which is what SUB.TIME.MONOTONIC asks for and the study must not mistake for compliance."),
            nats!("elapsedRealtime", [], "J", Behaviour::Probe { pattern: "SIGNAL_PAT.CLOCK_ELAPSED" },
                 "elapsedRealtime(). The same virtual clock; the deep-sleep distinction does not exist here."),
            nats!("currentThreadTimeMillis", [], "J", Behaviour::Probe { pattern: "SIGNAL_PAT.CLOCK_THREAD" },
                 "currentThreadTimeMillis(). Virtual CPU time."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/Build;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "FINGERPRINT", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "MODEL", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "MANUFACTURER", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "BRAND", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "DEVICE", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "PRODUCT", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "HARDWARE", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "BOARD", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.FINGERPRINT") },
            ShimField { name: "TAGS", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.TAGS") },
            ShimField { name: "SERIAL", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.TAGS") },
            ShimField { name: "BOOTLOADER", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.TAGS") },
            ShimField { name: "VERSION", type_descriptor: "Landroid/os/Build$VERSION;", is_static: true, assumption: None },
            ShimField { name: "SUPPORTED_ABIS", type_descriptor: "[Ljava/lang/String;", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("getRadioVersion", [], STRING, Behaviour::Probe { pattern: "SIGNAL_PAT.BUILD_RADIO" },
                 "getRadioVersion(). Empty: there is no telephony."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/Build$VERSION;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | STATIC | FINAL,
        static_fields: &[
            ShimField { name: "SDK_INT", type_descriptor: "I", is_static: true, assumption: Some("SUB.BUILD.SDK_INT") },
            ShimField { name: "RELEASE", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.SDK_INT") },
            ShimField { name: "CODENAME", type_descriptor: STRING, is_static: true, assumption: Some("SUB.BUILD.SDK_INT") },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/os/Environment;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("getExternalStorageDirectory", [], "Ljava/io/File;", Behaviour::Dispatch("fs.externalStorage"),
                 "getExternalStorageDirectory(). A VFS directory that exists and is empty: SUB.FS.EXTERNAL_STORAGE degrades rather than fails."),
            nats!("getExternalStorageState", [], STRING, Behaviour::Dispatch("fs.externalStorageState"),
                 "getExternalStorageState(). \"mounted\". Lying about this is the point: the app must not discover the substrate by a null it would expect to be null on a phone."),
        ],
    },
    // ================================================== android.util
    ShimClass {
        descriptor: "Landroid/util/Log;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("v", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" },
                 "Log.v. The tag is recorded; the message is not. An app's log line routinely contains a URL, a user id and a stack fragment."),
            nats!("d", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" }, "Log.d. Tag only."),
            nats!("i", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" }, "Log.i. Tag only."),
            nats!("w", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" }, "Log.w. Tag only."),
            nats!("e", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" }, "Log.e. Tag only."),
            nats!("println", ["I", STRING, STRING], "I", Behaviour::Probe { pattern: "SIGNAL_PAT.LOG" }, "println. Tag only."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/util/Base64;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("encodeToString", ["[B", "I"], STRING, Behaviour::Probe { pattern: "SIGNAL_PAT.BASE64" },
                 "encodeToString(byte[], int). Implemented, so a token-holding app does not crash before the point where it would have sent one. The bytes are not recorded."),
        ],
    },
    // ================================================== android.view
    ShimClass {
        descriptor: "Landroid/view/View;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[
            ShimField { name: "VISIBLE", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "INVISIBLE", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "GONE", type_descriptor: "I", is_static: true, assumption: None },
        ],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("measure", ["I", "I"], "V", Behaviour::Dispatch("view.measure"),
                 "measure(int, int). Runs the real measure pass."),
            nat!("layout", ["I", "I", "I", "I"], "V", Behaviour::Dispatch("view.layout"),
                 "layout(int, int, int, int). Runs the real layout pass."),
            nat!("getWidth", [], "I", Behaviour::Field { is_get: true }, "getWidth(). The laid-out width, not the requested one."),
            nat!("getHeight", [], "I", Behaviour::Field { is_get: true }, "getHeight(). The laid-out height."),
            nat!("setVisibility", ["I"], "V", Behaviour::Field { is_get: false }, "setVisibility(int). Changes whether the node appears in the box tree."),
            nat!("getVisibility", [], "I", Behaviour::Field { is_get: true }, "getVisibility()."),
            nat!("setOnClickListener", ["Ljava/lang/Object;"], "V", Behaviour::Dispatch("view.setOnClickListener"),
                 "setOnClickListener(View.OnClickListener). Held. No input is ever delivered (SUB.INPUT.INPUT_EVENT), so the listener is dead code and the app waits forever."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/ViewGroup;",
        superclass: Some(VIEW),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("addView", [VIEW, "I"], "V", Behaviour::Dispatch("viewgroup.addView"),
                 "addView(View, int). Index -1 appends, as on a device."),
            nat!("removeView", [VIEW], "V", Behaviour::Dispatch("viewgroup.removeView"), "removeView(View)."),
            nat!("getChildCount", [], "I", Behaviour::Dispatch("viewgroup.getChildCount"), "getChildCount()."),
            nat!("getChildAt", ["I"], VIEW, Behaviour::Dispatch("viewgroup.getChildAt"), "getChildAt(int)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/ViewGroup$LayoutParams;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[
            ShimField { name: "MATCH_PARENT", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "WRAP_CONTENT", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[
            ShimField { name: "width", type_descriptor: "I", is_static: false, assumption: None },
            ShimField { name: "height", type_descriptor: "I", is_static: false, assumption: None },
            ShimField { name: "weight", type_descriptor: "F", is_static: false, assumption: None },
        ],
        direct_methods: &[ctor_with!("II")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/view/LayoutInflater;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("from", [CONTEXT], "Landroid/view/LayoutInflater;", Behaviour::Dispatch("inflater.from"),
                 "from(Context). Returns the shim's inflater, which builds a fixed view tree. The layout XML the app shipped is not parsed, which is SUB.RES.ARSC in its purest form."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/Window;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("setContentView", ["Landroid/view/View;"], "V", Behaviour::Dispatch("window.setContentView"),
                 "Window.setContentView(View)."),
            nat!("addFlags", ["I"], "V", Behaviour::Dispatch("window.addFlags"), "addFlags(int)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/webkit/WebView;",
        superclass: Some(VIEW),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("loadUrl", [STRING], "V", Behaviour::Probe { pattern: "SIGNAL_PAT.WEBVIEW_LOAD" },
                 "loadUrl(String). The URL is routed to the egress sink like any other request: it is *recorded* and *denied*. SUB.FW.WEBVIEW is the one family where a substrate could be better than a phone, so its failures must be visible, not hidden behind a NoClassDefFoundError."),
            nat!("addJavascriptInterface", [OBJECT, STRING], "V", Behaviour::Probe { pattern: "SIGNAL_PAT.WEBVIEW_BRIDGE" },
                 "addJavascriptInterface(Object, String). Records the *names* the app exposed to JavaScript, never the methods."),
        ],
    },
    // ================================================== android.widget
    ShimClass {
        descriptor: "Landroid/widget/TextView;",
        superclass: Some(VIEW),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("setText", ["Ljava/lang/CharSequence;"], "V", Behaviour::Dispatch("textview.setText"),
                 "setText(CharSequence). Measured with the documented advance table; the characters are not recorded unless the capture policy says so."),
            nat!("getText", [], "Ljava/lang/CharSequence;", Behaviour::Field { is_get: true }, "getText()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/widget/Button;",
        superclass: Some("Landroid/widget/TextView;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/widget/EditText;",
        superclass: Some("Landroid/widget/TextView;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("getText", [], "Ljava/lang/CharSequence;", Behaviour::Field { is_get: true }, "getText(). The string a user typed. Never serialised into a box tree by default."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/widget/ImageView;",
        superclass: Some(VIEW),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("setImageResource", ["I"], "V", Behaviour::Dispatch("imageview.setImageResource"),
                 "setImageResource(int). Sets a synthetic intrinsic size; there is no drawable to decode (SUB.GFX.TEXT_RENDER adjacent)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/widget/LinearLayout;",
        superclass: Some(VIEWGROUP),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[
            ShimField { name: "HORIZONTAL", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "VERTICAL", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[
            nat!("setOrientation", ["I"], "V", Behaviour::Dispatch("linearlayout.setOrientation"), "setOrientation(int)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/widget/FrameLayout;",
        superclass: Some(VIEWGROUP),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/widget/Toast;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("makeText", [CONTEXT, "Ljava/lang/CharSequence;", "I"], "Landroid/widget/Toast;", Behaviour::Probe { pattern: "SIGNAL_PAT.TOAST" },
                 "makeText(...). Records the message's *shape* and length, not the message. A toast is a UI affordance the substrate has no display for."),
            nat!("show", [], "V", Behaviour::Probe { pattern: "SIGNAL_PAT.TOAST" }, "show(). A no-op with no display."),
        ],
    },
    // ================================================== android.graphics
    ShimClass {
        descriptor: "Landroid/graphics/drawable/Drawable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getIntrinsicWidth", [], "I", Behaviour::Field { is_get: true }, "getIntrinsicWidth(). From the shim's synthetic size table."),
            nat!("getIntrinsicHeight", [], "I", Behaviour::Field { is_get: true }, "getIntrinsicHeight()."),
        ],
    },
    // ================================================== android.net
    ShimClass {
        descriptor: "Landroid/net/Uri;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nats!("parse", [STRING], "Landroid/net/Uri;", Behaviour::Dispatch("uri.parse"),
                 "Uri.parse(String). Parses; a malformed URI is null, as on a device. A well-formed one is a value, and nothing contacts it until it is opened."),
            nat!("toString", [], STRING, Behaviour::Field { is_get: true }, "toString(). The URI text, which is a URL and therefore may carry a query string: never recorded verbatim."),
            nat!("getScheme", [], STRING, Behaviour::Field { is_get: true }, "getScheme()."),
            nat!("getHost", [], STRING, Behaviour::Field { is_get: true }, "getHost()."),
            nat!("getPath", [], STRING, Behaviour::Field { is_get: true }, "getPath()."),
            nat!("getQuery", [], STRING, Behaviour::Field { is_get: true }, "getQuery(). The raw query string. Never recorded — it is the field the redaction exists for."),
        ],
    },
    // ================================================== android.text
    ShimClass {
        descriptor: "Landroid/text/TextUtils;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("isEmpty", ["Ljava/lang/CharSequence;"], "Z", Behaviour::Field { is_get: true }, "isEmpty(CharSequence)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/NotificationManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("notify", [STRING, OBJECT], "V", Behaviour::Dispatch("notification.notify"),
                 "notify(String, Notification). Recorded and dropped: there is no shade, no channel registry and no POST_NOTIFICATIONS runtime permission, so SUB.IPC.NOTIFICATION is unsatisfiable."),
            nat!("areNotificationsEnabled", [], "Z", Behaviour::Dispatch("notification.areNotificationsEnabled"),
                 "areNotificationsEnabled(). True, because reporting false would manufacture a refusal that has nothing to do with the app."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/Notification;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT, "I", "I")],
        virtual_methods: &[
            nat!("setContentTitle", [STRING], "Landroid/app/Notification;", Behaviour::Inert, "setContentTitle(CharSequence). The title is app content and is not recorded."),
            nat!("setSmallIcon", ["I"], "Landroid/app/Notification;", Behaviour::Dispatch("res.getString"),
                 "setSmallIcon(int). A resource id with no resources.arsc behind it: SUB.RES.ARSC."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/Notification$Builder;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(CONTEXT, "Landroid/content/ComponentName;")],
        virtual_methods: &[
            nat!("setContentTitle", [STRING], "Landroid/app/Notification$Builder;", Behaviour::Inert, "setContentTitle(CharSequence)."),
            nat!("build", [], "Landroid/app/Notification;", Behaviour::Inert, "build()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/Notification$Action;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/app/Notification$Action$Builder;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(OBJECT, "I", "I")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/app/NotificationChannel;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING, STRING, "I")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/service/notification/StatusBarNotification;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/service/quicksettings/Tile;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("updateTile", ["Landroid/service/quicksettings/Tile;"], "V", Behaviour::Dispatch("tile.updateTile"),
                 "updateTile(Tile). There is no quick-settings panel, so this never renders."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/service/quicksettings/TileService;",
        superclass: Some("Landroid/app/Service;"),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onStartListening", [], "V", Behaviour::Dispatch("service.onStartCommand"), "onStartListening(). Never called."),
            nat!("onClick", [], "V", Behaviour::Dispatch("service.onStartCommand"), "onClick(). Never called."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/graphics/Color;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "BLACK", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "WHITE", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "TRANSPARENT", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("alpha", ["I"], "I", Behaviour::Inert, "alpha(int)."),
            nat!("red", ["I"], "I", Behaviour::Inert, "red(int)."),
            nat!("rgb", ["III"], "I", Behaviour::Inert, "rgb(int, int, int)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/graphics/drawable/Icon;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("createWithResource", [CONTEXT, "I"], "Landroid/graphics/drawable/Icon;", Behaviour::Dispatch("res.getString"),
                 "createWithResource(Context, int). A synthetic intrinsic size; there is no drawable to decode."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/inputmethodservice/InputMethodService;",
        superclass: Some("Landroid/app/Service;"),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onCreateInputView", [], VIEW, Behaviour::Dispatch("ime.onCreateInputView"),
                 "onCreateInputView(). Never called: there is no window manager, so no keyboard is ever shown, which is SUB.INPUT.IME and the first thing a human notices."),
            nat!("onEvaluateFullscreenMode", [], "V", Behaviour::Dispatch("ime.onEvaluateFullscreenMode"),
                 "onEvaluateFullscreenMode(). Never called."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/inputmethod/InputConnection;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("commitText", [STRING, "I"], "Z", Behaviour::Dispatch("ime.commitText"),
                 "commitText(CharSequence, int). Never called: the substrate delivers no input at \
all, so no field can ever receive text (SUB.INPUT.INPUT_EVENT)."),
            nat!("deleteSurroundingText", ["II"], "Z", Behaviour::Dispatch("ime.commitText"), "deleteSurroundingText(int, int). Never called."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/inputmethod/ExtractedText;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("text", [], STRING, Behaviour::Inert, "text(). The selected text, which is user content and is never recorded."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/inputmethod/ExtractedTextRequest;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getToken", ["I", "I", "II", "I"], "Landroid/os/IBinder;", Behaviour::Inert, "getToken(...)."),
        ],
    },
    // ================================================== java.lang
    ShimClass {
        descriptor: THROWABLE,
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!("Ljava/lang/Throwable;"), ctor_with!(STRING)],
        virtual_methods: &[
            nat!("getMessage", [], STRING, Behaviour::Inert, "getMessage()."),
            nat!("getStackTrace", [], "[Ljava/lang/StackTraceElement;", Behaviour::Probe { pattern: "SIGNAL_PAT.STACK" },
                 "getStackTrace(). Recorded as frame descriptors. The oracle allows frame strings but no arguments, and this shim has no argument capture at all."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Exception;",
        superclass: Some(THROWABLE),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/RuntimeException;",
        superclass: Some("Ljava/lang/Exception;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/Error;",
        superclass: Some(THROWABLE),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/UnsatisfiedLinkError;",
        superclass: Some("Ljava/lang/Error;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/ClassNotFoundException;",
        superclass: Some("Ljava/lang/ReflectiveOperationException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/ReflectiveOperationException;",
        superclass: Some("Ljava/lang/Exception;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/IllegalArgumentException;",
        superclass: Some("Ljava/lang/RuntimeException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/NullPointerException;",
        superclass: Some("Ljava/lang/RuntimeException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/Object;",
        superclass: None,
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("toString", [], STRING, Behaviour::Inert, "toString(). Inert; the dispatcher owns object identity and formatting."),
            nat!("equals", [OBJECT], "Z", Behaviour::Inert, "equals(Object). Reference identity, as on a device without a shim override."),
            nat!("hashCode", [], "I", Behaviour::Inert, "hashCode()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/String;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE, "Ljava/lang/CharSequence;", "Ljava/lang/Comparable;"],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("length", [], "I", Behaviour::Inert, "length()."),
            nat!("isEmpty", [], "Z", Behaviour::Inert, "isEmpty()."),
            nat!("concat", [STRING], STRING, Behaviour::Inert, "concat(String)."),
            nat!("substring", ["I"], STRING, Behaviour::Inert, "substring(int)."),
            nat!("startsWith", [STRING], "Z", Behaviour::Inert, "startsWith(String)."),
            nat!("contains", ["Ljava/lang/CharSequence;"], "Z", Behaviour::Inert, "contains(CharSequence)."),
            nat!("trim", [], STRING, Behaviour::Inert, "trim()."),
            nat!("toLowerCase", [], STRING, Behaviour::Inert, "toLowerCase()."),
            nat!("toUpperCase", [], STRING, Behaviour::Inert, "toUpperCase()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/CharSequence;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("toString", [], STRING, Behaviour::Inert, "toString()."),
            nat!("length", [], "I", Behaviour::Inert, "length()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Comparable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("compareTo", [OBJECT], "I", Behaviour::Inert, "compareTo(Object)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/System;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("loadLibrary", [STRING], "V", Behaviour::Dispatch("jni.loadLibrary"),
                 "loadLibrary(String). Recorded and UNSATISFIED. The substrate has no ELF loader and no /system/lib, so this is the single most consequential refusal in the whole shim."),
            nats!("load", [STRING], "V", Behaviour::Dispatch("jni.load"),
                 "load(String). As loadLibrary, for an absolute path."),
            nats!("currentTimeMillis", [], "J", Behaviour::Probe { pattern: "SIGNAL_PAT.CLOCK_WALL" },
                 "currentTimeMillis(). The *host's* wall clock, which is the substrate's own honest divergence (SUB.TIME.WALL_CLOCK) and is recorded as such rather than hidden."),
            nats!("getProperty", [STRING], STRING, Behaviour::Dispatch("system.getProperty"),
                 "getProperty(String). A substrate property, e.g. \"substrate.runtime\"."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Class;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("forName", [STRING], "Ljava/lang/Class;", Behaviour::Dispatch("class.forName"),
                 "Class.forName(String). A *real* class-resolution event, with the source. This is the hook anti-tamper code uses most, and it is SUB.FW.REFLECTION as much as SUB.FW.CLASS_LOADER."),
            nat!("getName", [], STRING, Behaviour::Inert, "getName()."),
            nat!("getMethod", [STRING, "[Ljava/lang/Class;"], "Ljava/lang/reflect/Method;", Behaviour::Dispatch("class.getMethod"),
                 "getMethod(String, Class...). Records the method name; returns a shim Method whose invoke is dispatched."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/reflect/Method;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("invoke", ["Ljava/lang/Object;", "[Ljava/lang/Object;"], OBJECT, Behaviour::Dispatch("method.invoke"),
                 "invoke(Object, Object[]). Dispatched through the same table as a direct call, so a reflective call and a direct one produce identical observations. An observation layer that only saw direct calls would miss every obfuscated app."),
            nat!("getName", [], STRING, Behaviour::Inert, "getName()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Thread;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!()],
        virtual_methods: &[
            nats!("sleep", ["J"], "V", Behaviour::Dispatch("thread.sleep"),
                 "Thread.sleep(long). Advances the virtual clock and returns; it does not block, because blocking would make the substrate itself the source of the timing the study is measuring."),
            nats!("currentThread", [], "Ljava/lang/Thread;", Behaviour::Dispatch("thread.currentThread"), "currentThread()."),
            nat!("getName", [], STRING, Behaviour::Inert, "getName()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/StringBuilder;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/CharSequence;", "Ljava/lang/Appendable;"],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("append", ["Ljava/lang/String;"], "Ljava/lang/StringBuilder;", Behaviour::Inert,
                 "append(String). Inert, but a *very* widely used class: declaring it means a failure elsewhere is a failure of the app's logic and not a NoClassDefFoundError."),
            nat!("toString", [], STRING, Behaviour::Inert, "toString()."),
            nat!("length", [], "I", Behaviour::Inert, "length()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Appendable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[nat!("append", ["Ljava/lang/CharSequence;"], "Ljava/lang/Appendable;", Behaviour::Inert, "append(CharSequence).")],
    },
    ShimClass {
        descriptor: "Ljava/lang/Iterable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[nat!("iterator", [], "Ljava/util/Iterator;", Behaviour::Inert, "iterator().")],
    },
    ShimClass {
        descriptor: "Ljava/lang/Enum;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/Comparable;", PARCELABLE],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("name", [], STRING, Behaviour::Inert, "name()."),
            nat!("ordinal", [], "I", Behaviour::Inert, "ordinal()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Boolean;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/Comparable;"],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("booleanValue", [], "Z", Behaviour::Inert, "booleanValue()."),
            nat!("parseBoolean", [STRING], "Z", Behaviour::Inert, "parseBoolean(String)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Long;",
        superclass: Some("Ljava/lang/Number;"),
        interfaces: &["Ljava/lang/Comparable;"],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("longValue", [], "J", Behaviour::Inert, "longValue()."),
            nat!("parseLong", [STRING], "J", Behaviour::Inert, "parseLong(String)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Integer;",
        superclass: Some("Ljava/lang/Number;"),
        interfaces: &["Ljava/lang/Comparable;"],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "MAX_VALUE", type_descriptor: "I", is_static: true, assumption: None },
            ShimField { name: "MIN_VALUE", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("intValue", [], "I", Behaviour::Inert, "intValue()."),
            nat!("parseInt", [STRING], "I", Behaviour::Inert, "parseInt(String)."),
            nat!("toString", [], STRING, Behaviour::Inert, "toString()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/Number;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("intValue", [], "I", Behaviour::Inert, "intValue()."),
            nat!("longValue", [], "J", Behaviour::Inert, "longValue()."),
            nat!("doubleValue", [], "D", Behaviour::Inert, "doubleValue()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/IndexOutOfBoundsException;",
        superclass: Some("Ljava/lang/RuntimeException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/NumberFormatException;",
        superclass: Some("Ljava/lang/IllegalArgumentException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/UnsupportedOperationException;",
        superclass: Some("Ljava/lang/RuntimeException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/StackOverflowError;",
        superclass: Some("Ljava/lang/Error;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/OutOfMemoryError;",
        superclass: Some("Ljava/lang/Error;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/NoSuchMethodError;",
        superclass: Some("Ljava/lang/Error;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/NoSuchFieldError;",
        superclass: Some("Ljava/lang/Error;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/NoSuchMethodException;",
        superclass: Some("Ljava/lang/ReflectiveOperationException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/StackTraceElement;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getClassName", [], STRING, Behaviour::Inert, "getClassName()."),
            nat!("getMethodName", [], STRING, Behaviour::Inert, "getMethodName()."),
            nat!("getLineNumber", [], "I", Behaviour::Inert, "getLineNumber()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/annotation/Annotation;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("annotationType", [], "Ljava/lang/Class;", Behaviour::Inert, "annotationType()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/lang/annotation/ElementType;",
        superclass: Some("Ljava/lang/Enum;"),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "METHOD", type_descriptor: "Ljava/lang/annotation/ElementType;", is_static: true, assumption: None },
            ShimField { name: "TYPE", type_descriptor: "Ljava/lang/annotation/ElementType;", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/annotation/RetentionPolicy;",
        superclass: Some("Ljava/lang/Enum;"),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "RUNTIME", type_descriptor: "Ljava/lang/annotation/RetentionPolicy;", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/annotation/Retention;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/annotation/Annotation;"],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/annotation/Target;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/annotation/Annotation;"],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/lang/reflect/Array;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("getLength", ["Ljava/lang/Object;"], "I", Behaviour::Inert, "getLength(Object)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/io/Serializable;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/util/Iterator;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("hasNext", [], "Z", Behaviour::Inert, "hasNext()."),
            nat!("next", [], OBJECT, Behaviour::Inert, "next()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/ListIterator;",
        superclass: Some("Ljava/util/Iterator;"),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/util/Comparator;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("compare", [OBJECT, OBJECT], "I", Behaviour::Inert, "compare(Object, Object)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/RandomAccess;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/util/NoSuchElementException;",
        superclass: Some("Ljava/lang/RuntimeException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/util/HashMap;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/util/Map;"],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("put", [OBJECT, OBJECT], OBJECT, Behaviour::Inert, "put(Object, Object)."),
            nat!("get", [OBJECT], OBJECT, Behaviour::Inert, "get(Object)."),
            nat!("size", [], "I", Behaviour::Inert, "size()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/Map;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("size", [], "I", Behaviour::Inert, "size()."),
            nat!("get", [OBJECT], OBJECT, Behaviour::Inert, "get(Object)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/Date;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/Comparable;", "Ljava/io/Serializable;"],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("getTime", [], "J", Behaviour::Inert, "getTime()."),
            nat!("toString", [], STRING, Behaviour::Inert, "toString()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/text/DateFormat;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("getDateTimeInstance", ["I", "I"], "Ljava/text/DateFormat;", Behaviour::Probe { pattern: "SIGNAL_PAT.LOCALE" },
                 "getDateTimeInstance(int, int). Recorded: which locale and which date style an \
app formats with is SUB.RES.LOCALE and SUB.RES.TIMEZONE, and it is invisible on a device."),
            nat!("format", ["Ljava/util/Date;"], STRING, Behaviour::Inert, "format(Date)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/IntentFilter;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!()],
        virtual_methods: &[
            nat!("addAction", [STRING], "V", Behaviour::Inert, "addAction(String)."),
            nat!("addCategory", [STRING], "V", Behaviour::Inert, "addCategory(String)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/res/Resources;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getString", ["I"], STRING, Behaviour::Dispatch("res.getString"), "getString(int). Null: no resources.arsc."),
            nat!("getIdentifier", [STRING, STRING, STRING], "I", Behaviour::Dispatch("res.getIdentifier"), "getIdentifier(...). 0: no name-to-id map, which is SUB.RES.PACKAGE_RESOLVER."),
            nat!("getDisplayMetrics", [], "Landroid/util/DisplayMetrics;", Behaviour::Dispatch("res.getDisplayMetrics"), "getDisplayMetrics()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/content/res/AssetManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("open", [STRING], "Ljava/io/InputStream;", Behaviour::Dispatch("res.assetsOpen"), "open(String). The APK is not a filesystem."),
            nat!("list", [STRING], "[Ljava/lang/String;", Behaviour::Dispatch("res.assetsOpen"), "list(String). Empty."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/util/DisplayMetrics;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[
            ShimField { name: "densityDpi", type_descriptor: "I", is_static: false, assumption: Some("SUB.RES.DISPLAY_METRICS") },
            ShimField { name: "widthPixels", type_descriptor: "I", is_static: false, assumption: Some("SUB.RES.DISPLAY_METRICS") },
        ],
        direct_methods: &[ctor!()],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/net/Uri$Builder;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("scheme", [STRING], "Landroid/net/Uri$Builder;", Behaviour::Inert, "scheme(String)."),
            nat!("authority", [STRING], "Landroid/net/Uri$Builder;", Behaviour::Inert, "authority(String)."),
            nat!("path", [STRING], "Landroid/net/Uri$Builder;", Behaviour::Inert, "path(String)."),
            nat!("build", [], "Landroid/net/Uri;", Behaviour::Inert, "build()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/Service;",
        superclass: Some(CONTEXT_WRAPPER),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onBind", [OBJECT], OBJECT, Behaviour::Dispatch("service.onBind"), "onBind(Intent). Never called: there is no service manager."),
            nat!("onStartCommand", [OBJECT, "I", "I"], "I", Behaviour::Dispatch("service.onStartCommand"), "onStartCommand(...). Never called."),
            nat!("stopSelf", [], "V", Behaviour::Dispatch("service.stopSelf"), "stopSelf(). A no-op; nothing is ever stopped because nothing is ever started."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/IntentService;",
        superclass: Some("Landroid/app/Service;"),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onHandleIntent", [OBJECT], "V", Behaviour::Dispatch("service.onHandleIntent"), "onHandleIntent(Intent). Never called."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/AlarmManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("set", ["I", "J", OBJECT], "V", Behaviour::Dispatch("alarm.set"), "set(int, long, PendingIntent). Enqueued and never fired: a substrate has no alarm daemon and no Doze, which is SUB.IPC.ALARM_MANAGER."),
            nat!("setExact", ["I", "J", OBJECT], "V", Behaviour::Dispatch("alarm.set"), "setExact(...). Same."),
            nat!("cancel", [OBJECT], "V", Behaviour::Dispatch("alarm.cancel"), "cancel(PendingIntent)."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/PendingIntent;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("getBroadcast", [CONTEXT, "I", OBJECT, "I", "I"], "Landroid/app/PendingIntent;", Behaviour::Inert, "getBroadcast(...). A token, never a scheduled event."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/job/JobScheduler;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("schedule", ["Landroid/app/job/JobInfo;"], "I", Behaviour::Dispatch("job.schedule"), "schedule(JobInfo). Accepted and never run: there is no job daemon, which is SUB.IPC.JOB_SCHEDULER and the app gets no symptom at all."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/job/JobService;",
        superclass: Some("Landroid/app/Service;"),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("onStartJob", ["Landroid/app/job/JobParameters;"], "Z", Behaviour::Dispatch("job.onStartJob"), "onStartJob(...). Never called."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/job/JobInfo;",
        superclass: Some(OBJECT),
        interfaces: &[PARCELABLE],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/app/job/JobInfo$Builder;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!("J", "Landroid/content/ComponentName;")],
        virtual_methods: &[
            nat!("setPeriodic", ["J", "J"], "Landroid/app/job/JobInfo$Builder;", Behaviour::Inert, "setPeriodic(long, long)."),
            nat!("build", [], "Landroid/app/job/JobInfo;", Behaviour::Inert, "build()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/app/job/JobParameters;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/media/AudioManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("getStreamVolume", ["I"], "I", Behaviour::Dispatch("audio.getStreamVolume"), "getStreamVolume(int). A synthetic level: there is no audio hardware, so every volume-dependent behaviour is unfounded."),
            nat!("setStreamVolume", ["III"], "V", Behaviour::Dispatch("audio.setStreamVolume"), "setStreamVolume(int, int, int). A no-op."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/PowerManager;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("newWakeLock", ["I", STRING], "Landroid/os/PowerManager$WakeLock;", Behaviour::Dispatch("power.newWakeLock"), "newWakeLock(int, String). A lock that is granted and never matters: nothing is ever reaped here, which is the *opposite* of the expected failure (SUB.PWR.WAKE_LOCK)."),
            nat!("isScreenOn", [], "Z", Behaviour::Dispatch("power.isScreenOn"), "isScreenOn(). False: there is no display, which is SUB.GFX.SCREEN_ON."),
            nat!("isIgnoringBatteryOptimizations", [STRING], "Z", Behaviour::Dispatch("power.isIgnoringBatteryOptimizations"), "isIgnoringBatteryOptimizations(...). True, because nothing is ever optimised away."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/os/PowerManager$WakeLock;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("acquire", ["J"], "V", Behaviour::Dispatch("power.acquire"), "acquire(long). Granted and irrelevant: no process is ever reaped in a substrate."),
            nat!("release", [], "V", Behaviour::Dispatch("power.acquire"), "release()."),
            nat!("isHeld", [], "Z", Behaviour::Dispatch("power.acquire"), "isHeld()."),
        ],
    },
    ShimClass {
        descriptor: "Landroid/view/KeyEvent;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[
            ShimField { name: "KEYCODE_ENTER", type_descriptor: "I", is_static: true, assumption: None },
        ],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Landroid/view/WindowManager$LayoutParams;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[
            ShimField { name: "width", type_descriptor: "I", is_static: false, assumption: None },
            ShimField { name: "height", type_descriptor: "I", is_static: false, assumption: None },
        ],
        direct_methods: &[ctor_with!(CONTEXT)],
        virtual_methods: &[],
    },
    // ================================================== java.io
    ShimClass {
        descriptor: "Ljava/io/IOException;",
        superclass: Some(THROWABLE),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor!(), ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/io/InputStream;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("read", ["[B"], "I", Behaviour::Dispatch("io.read"),
                 "read(byte[]). A VFS read; the bytes stay in the VFS and are never recorded."),
            nat!("close", [], "V", Behaviour::Dispatch("io.close"), "close(). A no-op; there is no file descriptor."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/io/OutputStream;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("write", ["[B", "I", "I"], "V", Behaviour::Dispatch("io.write"),
                 "write(byte[], int, int). A VFS write; the bytes are stored in memory and never recorded."),
            nat!("close", [], "V", Behaviour::Dispatch("io.close"), "close()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/io/FileInputStream;",
        superclass: Some("Ljava/io/InputStream;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!("Ljava/io/File;")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/io/FileOutputStream;",
        superclass: Some("Ljava/io/OutputStream;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!("Ljava/io/File;")],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/io/ByteArrayOutputStream;",
        superclass: Some("Ljava/io/OutputStream;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!()],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/io/File;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[
            nat!("getAbsolutePath", [], STRING, Behaviour::Dispatch("fs.getAbsolutePath"),
                 "getAbsolutePath(). The canonicalised VFS path."),
            nat!("exists", [], "Z", Behaviour::Dispatch("fs.exists"), "exists(). A VFS stat."),
            nat!("length", [], "J", Behaviour::Dispatch("fs.length"), "length(). A VFS stat."),
            nat!("isDirectory", [], "Z", Behaviour::Dispatch("fs.isDirectory"), "isDirectory(). A VFS stat."),
            nat!("list", [], "[Ljava/lang/String;", Behaviour::Dispatch("fs.list"), "list(). A VFS readdir, sorted."),
            nat!("delete", [], "Z", Behaviour::Dispatch("fs.delete"), "delete(). A VFS unlink."),
        ],
    },
    // ================================================== java.net
    ShimClass {
        descriptor: "Ljava/net/MalformedURLException;",
        superclass: Some("Ljava/io/IOException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: URL,
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[
            nat!("openConnection", [], URLCONN, Behaviour::Dispatch("net.openConnection"),
                 "openConnection(). Returns a shim connection. Nothing is opened, here or later: the denial happens at connect time so that a *constructed* URL and an *attempted* one are distinguishable in the trace."),
            nat!("toString", [], STRING, Behaviour::Field { is_get: true }, "toString(). Redacted by construction; the shim holds the parsed parts, not the text."),
            nat!("getProtocol", [], STRING, Behaviour::Field { is_get: true }, "getProtocol()."),
            nat!("getHost", [], STRING, Behaviour::Field { is_get: true }, "getHost()."),
            nat!("getPort", [], "I", Behaviour::Field { is_get: true }, "getPort()."),
            nat!("getPath", [], STRING, Behaviour::Field { is_get: true }, "getPath()."),
            nat!("getQuery", [], STRING, Behaviour::Field { is_get: true }, "getQuery(). Never recorded."),
        ],
    },
    ShimClass {
        descriptor: URLCONN,
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("connect", [], "V", Behaviour::Dispatch("net.connect"),
                 "connect(). The terminal. Records the redacted request and throws: SUB.NET.EGRESS."),
            nat!("setRequestProperty", [STRING, STRING], "V", Behaviour::Dispatch("net.setRequestProperty"),
                 "setRequestProperty(String, String). Records the NAME. The value is dropped inside the call and has no path to the recorder, because HeaderNames has no parameter that would accept one."),
            nat!("setConnectTimeout", ["I"], "V", Behaviour::Dispatch("net.setConnectTimeout"), "setConnectTimeout(int)."),
            nat!("setReadTimeout", ["I"], "V", Behaviour::Dispatch("net.setReadTimeout"), "setReadTimeout(int)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/net/HttpURLConnection;",
        superclass: Some(URLCONN),
        interfaces: &[],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("setRequestMethod", [STRING], "V", Behaviour::Dispatch("net.setRequestMethod"), "setRequestMethod(String)."),
            nat!("getResponseCode", [], "I", Behaviour::Dispatch("net.getResponseCode"), "getResponseCode(). Always throws: no response exists."),
            nat!("getInputStream", [], "Ljava/io/InputStream;", Behaviour::Dispatch("net.getInputStream"), "getInputStream(). Always throws."),
            nat!("setDoOutput", ["Z"], "V", Behaviour::Dispatch("net.setDoOutput"), "setDoOutput(boolean)."),
            nat!("getOutputStream", [], "Ljava/io/OutputStream;", Behaviour::Dispatch("net.getOutputStream"), "getOutputStream(). Returns a sink that accepts bytes, counts them, and discards them, so a POST reaches the recorded body length."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/net/ConnectException;",
        superclass: Some("Ljava/io/IOException;"),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(STRING)],
        virtual_methods: &[],
    },
    ShimClass {
        descriptor: "Ljava/net/Socket;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!(), ctor_with!(STRING, "I")],
        virtual_methods: &[
            nat!("connect", ["Ljava/net/SocketAddress;", "I"], "V", Behaviour::Dispatch("net.socketConnect"),
                 "Socket.connect(...). The other way in, and it terminates at the same sink. An app using raw sockets rather than HttpURLConnection produces the same observation, which is the point of having one sink."),
            nat!("getInputStream", [], "Ljava/io/InputStream;", Behaviour::Dispatch("net.getInputStream"), "getInputStream(). Throws."),
            nat!("getOutputStream", [], "Ljava/io/OutputStream;", Behaviour::Dispatch("net.getOutputStream"), "getOutputStream()."),
        ],
    },
    // ================================================== java.util
    ShimClass {
        descriptor: "Ljava/util/ArrayList;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/util/List;", "Ljava/util/Collection;", "Ljava/lang/Iterable;"],
        access_flags: PUBLIC,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[ctor_with!()],
        virtual_methods: &[
            nat!("add", [OBJECT], "Z", Behaviour::Inert, "add(Object)."),
            nat!("size", [], "I", Behaviour::Inert, "size()."),
            nat!("isEmpty", [], "Z", Behaviour::Inert, "isEmpty()."),
            nat!("get", ["I"], OBJECT, Behaviour::Inert, "get(int)."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/List;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/util/Collection;"],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("size", [], "I", Behaviour::Inert, "size()."),
            nat!("isEmpty", [], "Z", Behaviour::Inert, "isEmpty()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/Collection;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/lang/Iterable;"],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("size", [], "I", Behaviour::Inert, "size()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/Set;",
        superclass: Some(OBJECT),
        interfaces: &["Ljava/util/Collection;"],
        access_flags: PUBLIC | ABSTRACT,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nat!("size", [], "I", Behaviour::Inert, "size()."),
        ],
    },
    ShimClass {
        descriptor: "Ljava/util/Arrays;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[],
    },
    // ================================================== java.util.regex
    ShimClass {
        descriptor: "Ljava/util/regex/Pattern;",
        superclass: Some(OBJECT),
        interfaces: &[],
        access_flags: PUBLIC | FINAL,
        static_fields: &[],
        instance_fields: &[],
        direct_methods: &[],
        virtual_methods: &[
            nats!("compile", [STRING], "Ljava/util/regex/Pattern;", Behaviour::Dispatch("pattern.compile"),
                 "Pattern.compile(String). A real pattern is kept and reported; the substrate does not evaluate it, so a match() call is a refusal rather than a wrong answer."),
            nat!("matcher", [STRING], "Ljava/lang/Object;", Behaviour::Dispatch("pattern.matcher"),
                 "matcher(CharSequence). Reports the pattern and the input's shape; does not evaluate."),
        ],
    },
];

/// Every class descriptor the shim defines, sorted.
pub fn descriptors() -> Vec<String> {
    let mut v: Vec<String> = CLASSES.iter().map(|c| c.descriptor.to_string()).collect();
    v.sort();
    v
}

/// Total classes in the table.
pub fn class_count() -> usize {
    CLASSES.len()
}

/// Total methods in the table.
pub fn method_count() -> usize {
    CLASSES.iter().map(|c| c.methods().count()).sum()
}

/// Total fields in the table.
pub fn field_count() -> usize {
    CLASSES
        .iter()
        .map(|c| c.static_fields.len() + c.instance_fields.len())
        .sum()
}

/// Look a class up by descriptor.
pub fn find(descriptor: &str) -> Option<&'static ShimClass> {
    CLASSES.iter().find(|c| c.descriptor == descriptor)
}

/// Look a method up by descriptor and name.
///
/// Signature is deliberately not part of the key, because the emitted DEX
/// cannot express two methods of the same name and arity with different
/// signatures on one class without a rewrite pass, and the shim's table has no
/// such pair. `tests/conformance.rs` asserts that, so a future edit adding an
/// overload fails loudly instead of producing a DEX that lies.
pub fn find_method(class: &str, name: &str) -> Option<(&'static ShimClass, &'static ShimMethod)> {
    let c = find(class)?;
    c.methods().find(|m| m.name == name).map(|m| (c, m))
}

/// Every declared signature of `(class, name)`, walking the superclass chain.
///
/// Overloads are real in this table — `Intent` has a no-arg and a
/// `String`-argument constructor, as on a device — so a caller that needs to
/// match a *signature* rather than a name must handle more than one.
pub fn signatures(class: &str, name: &str) -> Vec<(Vec<String>, String)> {
    let mut cursor = class;
    let mut out = Vec::new();
    for _ in 0..CLASSES.len() + 1 {
        let c = match find(cursor) {
            Some(c) => c,
            None => break,
        };
        for m in c.methods() {
            if m.name == name {
                out.push((
                    m.params.iter().map(|p| p.to_string()).collect(),
                    m.ret.to_string(),
                ));
            }
        }
        if !out.is_empty() {
            break;
        }
        cursor = match c.superclass {
            Some(s) => s,
            None => break,
        };
    }
    out
}

/// The filesystem operation a method implies, where that is the interesting
/// fact about it. Used by the conformance table and by `tests/observation.rs`.
pub fn fs_op_of(behaviour: Behaviour) -> Option<FsOp> {
    match behaviour {
        Behaviour::Dispatch(d) => match d {
            "fs.openFileInput" | "fs.openFileOutput" | "io.read" => Some(FsOp::Read),
            "fs.exists" | "fs.length" | "fs.isDirectory" => Some(FsOp::Stat),
            "fs.list" => Some(FsOp::List),
            "fs.delete" => Some(FsOp::Unlink),
            "io.write" => Some(FsOp::Write),
            _ => None,
        },
        _ => None,
    }
}
