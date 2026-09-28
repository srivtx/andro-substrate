//! The fabricated device identity, and the probes that read it.
//!
//! # The most valuable thing the substrate observes
//!
//! `SUB.BUILD.*` is one of the largest families in the taxonomy, and on a stock
//! non-rooted device it is **completely unobservable**: an app's reads of
//! `Build.FINGERPRINT` leave no trace in logcat, no entry in `dumpsys`, nothing
//! in `/proc`. The oracle records the values as *environment* facts and can only
//! infer that the app cared. The substrate sees every single read, with the field
//! name, and can say which fields an app depends on.
//!
//! That is a strictly better measurement than a device arm can make, and it is
//! the clearest instance of the project's inversion.
//!
//! # The values are fabrications, and the recording says so
//!
//! The shim reports a *self-consistent* synthetic device. That is a deliberate
//! choice over two worse ones. A substrate that reported the host's real values
//! would be non-reproducible and would leak the host's identity into the
//! recording. A substrate that reported obviously-fake values (`FINGERPRINT =
//! "fake"`) would be trivially detected, and every app with an integrity check
//! would refuse — which would make the study measure the refusal rather than the
//! app. So the identity is plausible, fixed, and *stated*: every probe event
//! carries the value it returned, and the recording's `environment` block
//! describes a substrate rather than a device.
//!
//! # The values are fabrications *of a policy value*, not of this file
//!
//! Everything in this module that invents a value — the [`BuildInfo`], the
//! [`SystemTree`], the [`Clock`], the [`PackageQuery`] answer — is a function
//! of one field of [`crate::policy::SubstratePolicy`]. The plausibility above is
//! the *default* of the `identity` and `system_fs` axes, not a property of the
//! code, which is the difference between a confound and a measured variable. Each
//! fabricated value carries the axis that produced it at emission
//! ([`crate::event::axis_suffix`]), so a `Build.FINGERPRINT` read says which
//! axis answered it without the reader having to guess.

use serde::{Deserialize, Serialize};

use crate::error::ShimError;
use crate::event::{axis_suffix, Detail, FsOp, Source, SubstrateEvent, Tier};
use crate::policy::{Axis, IdentityMode, PackageMode, SubstratePolicy, SystemFsMode};
use crate::taxonomy::AssumptionId;
use crate::vfs::VPath;

/// The synthetic device identity the shim reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildInfo {
    /// `android.os.Build.FINGERPRINT`.
    pub fingerprint: String,
    pub brand: String,
    pub device: String,
    pub manufacturer: String,
    pub model: String,
    pub product: String,
    pub hardware: String,
    pub board: String,
    /// `Build.TAGS`. A release build, because `test-keys` is itself a
    /// compromise signal and reporting it would manufacture a refusal that the
    /// study would then misattribute.
    pub tags: String,
    pub serial: String,
    pub bootloader: String,
    pub radio: String,
    /// `Build.VERSION.SDK_INT`.
    pub sdk_int: i32,
    /// `Build.VERSION.RELEASE`.
    pub release: String,
    pub abis: Vec<String>,
    pub supported_32_bit_abis: Vec<String>,
}

impl BuildInfo {
    /// The device no axis asserts: every string empty, no ABI, SDK 0.
    ///
    /// What the `identity` axis's [`IdentityMode::Withheld`] and
    /// [`IdentityMode::Refusing`] values report. Note that `sdk_int: 0` is
    /// *not* a legal value anywhere in the recording format, which is why the
    /// recording's `environment` block substitutes the schema floor and says so;
    /// the type and the format disagree, and the format wins because the
    /// recording has to validate.
    pub fn withheld() -> BuildInfo {
        BuildInfo {
            fingerprint: String::new(),
            brand: String::new(),
            device: String::new(),
            manufacturer: String::new(),
            model: String::new(),
            product: String::new(),
            hardware: String::new(),
            board: String::new(),
            tags: String::new(),
            serial: String::new(),
            bootloader: String::new(),
            radio: String::new(),
            sdk_int: 0,
            release: String::new(),
            abis: Vec::new(),
            supported_32_bit_abis: Vec::new(),
        }
    }

    /// Whether any field states anything.
    pub fn is_empty(&self) -> bool {
        self.fingerprint.is_empty() && self.model.is_empty() && self.sdk_int == 0
    }
}

impl Default for BuildInfo {
    /// A plausible, fixed, obviously-synthetic-on-inspection device.
    ///
    /// `ro.kernel.qemu`, the generic `ro.hardware` and the missing sensor set
    /// are all deliberately left *out*, and that is the honest choice for a
    /// study of `SUB.BUILD.EMULATOR`: the substrate is not pretending to pass
    /// emulator detection, because a substrate that could pass it would not be a
    /// substrate. An app that checks will check and will fail, and the study
    /// will see exactly that.
    fn default() -> BuildInfo {
        BuildInfo {
            fingerprint: "andro-substrate/shim/0.1.0:substrate/0.1.0:user/release-keys".to_string(),
            brand: "substrate".to_string(),
            device: "substrate".to_string(),
            manufacturer: "andro-substrate".to_string(),
            model: "Substrate".to_string(),
            product: "substrate".to_string(),
            hardware: "substrate".to_string(),
            board: "substrate".to_string(),
            tags: "release-keys".to_string(),
            serial: "substrate-no-serial".to_string(),
            bootloader: "substrate-unknown".to_string(),
            radio: String::new(),
            sdk_int: 34,
            release: "14".to_string(),
            abis: vec!["wasm32".to_string()],
            supported_32_bit_abis: vec!["arm64-v8a".to_string()],
        }
    }
}

/// A `getprop` read. The result is always one of these two shapes, so a reader
/// can tell "the app read a property the substrate does not model" from "the
/// property is absent", which on a device are very different things.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropValue {
    Text(String),
    Absent,
}

/// The fabricated `/proc` and `/sys` tree.
///
/// This is a *separate mechanism* from [`crate::vfs`] on purpose. The VFS is
/// where app data lives and where writes are observed. `/proc` and `/sys` are
/// kernel interfaces, not files: a browser has no kernel, so the shim
/// fabricates exactly the reads that an app's anti-tamper, watchdog and
/// capability code actually makes, and records each one as a `probes` event
/// tagged with the taxonomy ID it feeds. Reading `/proc/self/status` and getting
/// a `TracerPid` of 0 is not "compatibility"; it is *observation of a lie*, and
/// the recording has to make that legible.
#[derive(Debug, Clone)]
pub struct SystemTree {
    entries: Vec<(&'static str, &'static str, AssumptionId)>,
}

impl Default for SystemTree {
    fn default() -> SystemTree {
        SystemTree {
            entries: vec![
                (
                    "/proc/self/status",
                    "Name:\tsubstrate\nUmask:\t0077\nState:\tR (running)\nTgid:\t1\nPid:\t1\nTracerPid:\t0\nThreads:\t1\n",
                    AssumptionId::TrustDebugDetect,
                ),
                (
                    "/proc/self/maps",
                    "",
                    AssumptionId::NativeLoadLibrary,
                ),
                (
                    "/proc/self/stat",
                    "1 (substrate) R 1 1 0 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0",
                    AssumptionId::KernelProcSelf,
                ),
                (
                    "/proc/uptime",
                    "0.00 0.00\n",
                    AssumptionId::TimeMonotonic,
                ),
                (
                    "/proc/cpuinfo",
                    "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\nprocessor\t: 3\n\nfeatures\t: substrate-no-isa\n",
                    AssumptionId::KernelProcSelf,
                ),
                (
                    "/proc/meminfo",
                    "MemTotal:\t        1048576 kB\nMemFree:\t         524288 kB\n",
                    AssumptionId::KernelProcSelf,
                ),
                (
                    "/proc/self/mountinfo",
                    "1 0 0:1 / / rw,relatime - substrate\n",
                    AssumptionId::FsSystemLayout,
                ),
                (
                    "/sys/class/power_supply/battery/capacity",
                    "100\n",
                    AssumptionId::KernelSysClass,
                ),
                (
                    "/sys/class/power_supply/battery/status",
                    "Discharging\n",
                    AssumptionId::KernelSysClass,
                ),
                (
                    "/sys/devices/system/cpu/online",
                    "0-3\n",
                    AssumptionId::KernelSysClass,
                ),
                (
                    "/sys/block/sda/size",
                    "0\n",
                    AssumptionId::KernelSysClass,
                ),
                (
                    "/dev/urandom",
                    "",
                    AssumptionId::KernelProcSelf,
                ),
            ],
        }
    }
}

impl SystemTree {
    /// Every path the tree fabricates, sorted.
    pub fn paths(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.entries.iter().map(|(p, _, _)| *p).collect();
        v.sort();
        v
    }

    /// The fabricated contents of a path, plus the ID its read feeds, **under
    /// the default `system_fs` axis**. See [`SystemTree::read_with`] for the
    /// policy-driven form; this one exists so the tree stays inspectable on its
    /// own, in tests and in the axis statements.
    pub fn read(&self, path: &VPath) -> Option<(&'static str, AssumptionId)> {
        self.read_with(path, SystemFsMode::Fabricated)
    }

    /// The contents of a path under a `system_fs` axis value, plus the ID its
    /// read feeds.
    ///
    /// `None` means the read is `ENOENT`, and that is the load-bearing case: an
    /// app reading `/proc/self/exe` on a device gets a real path and in a
    /// substrate gets nothing, and the divergence is `SUB.IPC.BINDER_DEV`
    /// shaped. The caller records the failure; it must not invent content.
    ///
    /// Note that [`SystemFsMode::Empty`] returns `Some("")` rather than `None`:
    /// the path *exists*. An app that calls `exists()` before `read()` gets
    /// `true` here and `false` under `absent`, which is a different control-flow
    /// decision and therefore a different measurement.
    pub fn read_with(
        &self,
        path: &VPath,
        mode: SystemFsMode,
    ) -> Option<(&'static str, AssumptionId)> {
        let p = path.as_str();
        self.entries
            .iter()
            .find(|(e, _, _)| *e == p)
            .and_then(|(_, c, a)| mode.contents(c).map(|m| (m, *a)))
    }

    /// Whether a path is one the tree fabricates, without reading it. This is a
    /// property of the *table*, not of the axis: under `absent` the modelled
    /// paths still exist as entries, they simply do not resolve.
    pub fn has(&self, path: &VPath) -> bool {
        self.entries.iter().any(|(e, _, _)| *e == path.as_str())
    }
}

/// A `getprop` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prop {
    /// `ro.build.fingerprint`
    Fingerprint,
    /// `ro.product.model`
    Model,
    /// `ro.product.manufacturer`
    Manufacturer,
    /// `ro.product.brand`
    Brand,
    /// `ro.product.device`
    Device,
    /// `ro.product.name`
    Product,
    /// `ro.hardware`
    Hardware,
    /// `ro.board.platform`
    Board,
    /// `ro.build.tags`
    Tags,
    /// `ro.serialno`
    Serial,
    /// `ro.bootloader`
    Bootloader,
    /// `ro.build.version.sdk`
    SdkInt,
    /// `ro.build.version.release`
    Release,
    /// `ro.build.version.security_patch`
    SecurityPatch,
    /// `ro.kernel.qemu`. Always absent, and always probed: the *absence* is
    /// the finding, so it must be observable that the app asked.
    KernelQemu,
    /// `ro.debuggable`. Always `0`, because reporting `1` would manufacture an
    /// integrity failure that has nothing to do with the app.
    Debuggable,
}

impl Prop {
    /// Parse a `SystemProperties`-style key. `None` for anything unmodelled, so
    /// an unmodelled key is an observable `Absent` rather than silence.
    pub fn parse(key: &str) -> Option<Prop> {
        Some(match key {
            "ro.build.fingerprint" => Prop::Fingerprint,
            "ro.product.model" => Prop::Model,
            "ro.product.manufacturer" => Prop::Manufacturer,
            "ro.product.brand" => Prop::Brand,
            "ro.product.device" => Prop::Device,
            "ro.product.name" => Prop::Product,
            "ro.hardware" => Prop::Hardware,
            "ro.board.platform" => Prop::Board,
            "ro.build.tags" => Prop::Tags,
            "ro.serialno" => Prop::Serial,
            "ro.bootloader" => Prop::Bootloader,
            "ro.build.version.sdk" => Prop::SdkInt,
            "ro.build.version.release" => Prop::Release,
            "ro.build.version.security_patch" => Prop::SecurityPatch,
            "ro.kernel.qemu" => Prop::KernelQemu,
            "ro.debuggable" => Prop::Debuggable,
            _ => return None,
        })
    }

    /// The value, from the synthetic `BuildInfo`.
    pub fn value(self, b: &BuildInfo) -> PropValue {
        match self {
            Prop::Fingerprint => PropValue::Text(b.fingerprint.clone()),
            Prop::Model => PropValue::Text(b.model.clone()),
            Prop::Manufacturer => PropValue::Text(b.manufacturer.clone()),
            Prop::Brand => PropValue::Text(b.brand.clone()),
            Prop::Device => PropValue::Text(b.device.clone()),
            Prop::Product => PropValue::Text(b.product.clone()),
            Prop::Hardware => PropValue::Text(b.hardware.clone()),
            Prop::Board => PropValue::Text(b.board.clone()),
            Prop::Tags => PropValue::Text(b.tags.clone()),
            Prop::Serial => PropValue::Text(b.serial.clone()),
            Prop::Bootloader => PropValue::Text(b.bootloader.clone()),
            Prop::SdkInt => PropValue::Text(b.sdk_int.to_string()),
            Prop::Release => PropValue::Text(b.release.clone()),
            Prop::SecurityPatch => PropValue::Absent,
            Prop::KernelQemu => PropValue::Absent,
            Prop::Debuggable => PropValue::Text("0".to_string()),
        }
    }

    /// The taxonomy ID a read of this property feeds.
    pub fn assumption(self) -> AssumptionId {
        match self {
            Prop::Fingerprint | Prop::Hardware | Prop::Board => AssumptionId::BuildFingerprint,
            Prop::Model | Prop::Manufacturer | Prop::Brand | Prop::Device | Prop::Product => {
                AssumptionId::BuildFingerprint
            }
            Prop::Tags | Prop::Serial | Prop::Bootloader => AssumptionId::BuildTags,
            Prop::SdkInt | Prop::Release | Prop::SecurityPatch => AssumptionId::BuildSdkInt,
            Prop::KernelQemu | Prop::Debuggable => AssumptionId::BuildEmulator,
        }
    }

    /// The `SIGNAL_PAT.*` identifier for the probe.
    pub fn pattern(self) -> &'static str {
        match self {
            Prop::Fingerprint
            | Prop::Model
            | Prop::Manufacturer
            | Prop::Brand
            | Prop::Device
            | Prop::Product
            | Prop::Hardware
            | Prop::Board => "SIGNAL_PAT.BUILD_FIELD",
            Prop::Tags | Prop::Serial | Prop::Bootloader => "SIGNAL_PAT.BUILD_TAGS",
            Prop::SdkInt | Prop::Release | Prop::SecurityPatch => "SIGNAL_PAT.SDK_INT",
            Prop::KernelQemu | Prop::Debuggable => "SIGNAL_PAT.EMULATOR_PROBE",
        }
    }
}

/// The substrate's clock.
///
/// A virtual clock, not a wall clock, and that is the point: a substrate run has
/// to be replayable, and an app's timing behaviour is what `SUB.TIME.*` is about,
/// so the clock is driven by the recorded schedule rather than by the host. It
/// never advances on its own; the interpreter advances it.
#[derive(Debug, Clone, Default)]
pub struct Clock {
    now_ms: u64,
}

impl Clock {
    /// A clock at `t=0`.
    pub fn new() -> Clock {
        Clock { now_ms: 0 }
    }

    /// The current virtual time.
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    /// Advance by a delta, saturating. Monotonicity is an invariant, not a
    /// hope: a recording with events out of order is rejected by the oracle
    /// validator, and a clock that could go backwards would make that a
    /// property of the shim rather than of the app.
    pub fn advance(&mut self, delta_ms: u64) -> u64 {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
        self.now_ms
    }

    /// Jump to an absolute time, never backwards.
    pub fn advance_to(&mut self, t_ms: u64) -> u64 {
        if t_ms > self.now_ms {
            self.now_ms = t_ms;
        }
        self.now_ms
    }
}

/// The devices the substrate has no hardware for. `hasSystemFeature` answers
/// from this set, and the *absent* entries are what make
/// `SUB.BUILD.ABILITIES` observable.
#[derive(Debug, Clone)]
pub struct Capabilities {
    present: Vec<String>,
    absent: Vec<String>,
}

impl Default for Capabilities {
    fn default() -> Capabilities {
        let present = vec![
            "android.hardware.touchscreen".to_string(),
            "android.hardware.faketouch".to_string(),
            "android.software.leanback".to_string(),
        ];
        let absent = vec![
            "android.hardware.camera".to_string(),
            "android.hardware.camera.any".to_string(),
            "android.hardware.location".to_string(),
            "android.hardware.location.gps".to_string(),
            "android.hardware.sensor.accelerometer".to_string(),
            "android.hardware.sensor.gyroscope".to_string(),
            "android.hardware.sensor.compass".to_string(),
            "android.hardware.nfc".to_string(),
            "android.hardware.bluetooth".to_string(),
            "android.hardware.telephony".to_string(),
            "android.hardware.telephony.gsm".to_string(),
            "android.hardware.fingerprint".to_string(),
            "android.hardware.usb.host".to_string(),
            "android.software.leanback".to_string(),
            "android.hardware.vulkan.level".to_string(),
        ];
        Capabilities { present, absent }
    }
}

impl Capabilities {
    /// `PackageManager.hasSystemFeature`. Records the probe either way: the
    /// question an app asked is the measurement, not the answer.
    pub fn has_system_feature(&self, feature: &str) -> bool {
        self.present.iter().any(|f| f == feature)
    }

    /// The features the substrate claims.
    pub fn present(&self) -> &[String] {
        &self.present
    }

    /// The features the substrate admits it lacks. The `present` list contains a
    /// duplicate of one `absent` entry on purpose: an inconsistency between the
    /// two answers is exactly the kind of thing an anti-tamper check looks for,
    /// and hiding it would make the substrate *more* deceptive than a device.
    pub fn absent(&self) -> &[String] {
        &self.absent
    }
}

/// A read of a `Build.*` field, and the value the shim returned — under an
/// explicit `identity` axis value.
///
/// The policy is applied *here*, at emission, so there is no path by which a
/// fabricated identity value reaches an app without the axis that produced it
/// being recorded alongside it.
pub fn read_build_field(
    field: &str,
    build: &BuildInfo,
    identity: IdentityMode,
) -> (PropValue, AssumptionId) {
    // `SystemProperties`-style keys and bare `Build.*` field names resolve to the
    // same properties, so a read of either is recorded identically. That matters:
    // an app reading `Build.FINGERPRINT` and an app reading
    // `SystemProperties.get("ro.build.fingerprint")` make the same assumption,
    // and the taxonomy has one ID for it.
    let prop = Prop::parse(field).or(match field {
        "FINGERPRINT" => Some(Prop::Fingerprint),
        "MODEL" => Some(Prop::Model),
        "MANUFACTURER" => Some(Prop::Manufacturer),
        "BRAND" => Some(Prop::Brand),
        "DEVICE" => Some(Prop::Device),
        "PRODUCT" => Some(Prop::Product),
        "HARDWARE" => Some(Prop::Hardware),
        "BOARD" => Some(Prop::Board),
        "TAGS" => Some(Prop::Tags),
        "SERIAL" => Some(Prop::Serial),
        "BOOTLOADER" => Some(Prop::Bootloader),
        "SDK_INT" => Some(Prop::SdkInt),
        "RELEASE" => Some(Prop::Release),
        _ => None,
    });
    match prop {
        Some(p) => (identity.read(p, build), p.assumption()),
        None => (PropValue::Absent, AssumptionId::BuildFingerprint),
    }
}

/// A `probes` event for a `Build.*` read, labelled with the axis that answered.
pub fn build_field_event(
    field: &str,
    value: &PropValue,
    identity: IdentityMode,
    seq: u64,
    t_mono_ms: u64,
) -> SubstrateEvent {
    let (prop, assumption) = match Prop::parse(field) {
        Some(p) => (Some(p), p.assumption()),
        None => (
            None,
            match field {
                "FINGERPRINT" => AssumptionId::BuildFingerprint,
                "TAGS" | "SERIAL" | "BOOTLOADER" => AssumptionId::BuildTags,
                "SDK_INT" | "RELEASE" => AssumptionId::BuildSdkInt,
                _ => AssumptionId::BuildFingerprint,
            },
        ),
    };
    let pattern = prop
        .map(|p| p.pattern())
        .unwrap_or("SIGNAL_PAT.BUILD_FIELD");
    let rendered = match value {
        PropValue::Text(t) => t.clone(),
        PropValue::Absent => match identity {
            // The two absences are different facts and the recording must not
            // flatten them: "the substrate models this and answers null" is not
            // "the substrate does not model this".
            IdentityMode::Fabricated => "<absent: substrate does not model this>".to_string(),
            IdentityMode::Withheld | IdentityMode::Refusing => {
                "<withheld: substrate states no identity>".to_string()
            }
        },
    };
    SubstrateEvent {
        seq,
        t_mono_ms,
        group: crate::event::Group::Probes,
        source: Source::SubstrateInstrumentation,
        tier: Tier::T0Direct,
        assumption: Some(assumption),
        detail: Detail::Probes {
            pattern,
            detail: format!("Build.{field} = {rendered}"),
            axis: Some(Axis::Identity),
        },
    }
}

/// A `probes` event for a `getprop`-style `System.getProperty` read, labelled
/// with the axis that answered.
///
/// A separate function from [`build_field_event`] because the assumption is the
/// same and the *question* is different: `Build.FINGERPRINT` and
/// `SystemProperties.get("ro.build.fingerprint")` are one assumption, and
/// `ro.kernel.qemu` is another.
pub fn property_event(
    key: &str,
    value: &PropValue,
    identity: IdentityMode,
    seq: u64,
    t_mono_ms: u64,
) -> SubstrateEvent {
    let assumption = Prop::parse(key).map(|p| p.assumption());
    let pattern = Prop::parse(key)
        .map(|p| p.pattern())
        .unwrap_or("SIGNAL_PAT.BUILD_FIELD");
    let rendered = match value {
        PropValue::Text(t) => t.clone(),
        PropValue::Absent => match identity {
            IdentityMode::Fabricated => "<absent: substrate does not model this>".to_string(),
            IdentityMode::Withheld | IdentityMode::Refusing => {
                "<withheld: substrate states no identity>".to_string()
            }
        },
    };
    SubstrateEvent {
        seq,
        t_mono_ms,
        group: crate::event::Group::Probes,
        source: Source::SubstrateInstrumentation,
        tier: Tier::T0Direct,
        assumption,
        detail: Detail::Probes {
            pattern,
            detail: format!("System.getProperty(\"{key}\") = {rendered}"),
            axis: Some(Axis::Identity),
        },
    }
}

/// A `probes` event for a `/proc` or `/sys` read, plus the matching `fs` event.
///
/// Two events from one call, deliberately. The `fs` event is what a device
/// capture's `filesystem.accesses` would hold, so the two arms line up. The
/// `probes` event carries the taxonomy ID and the fabricated value, which is
/// the part a device arm structurally cannot produce.
pub fn sysfs_events(
    path: &VPath,
    contents: Option<&str>,
    assumption: AssumptionId,
    mode: SystemFsMode,
    seq: u64,
    t_mono_ms: u64,
) -> (SubstrateEvent, SubstrateEvent) {
    let op = if contents.is_some() {
        FsOp::Read
    } else {
        FsOp::Open
    };
    let len = contents.map(|c| c.len() as u64);
    let fs_event = SubstrateEvent {
        seq,
        t_mono_ms,
        group: crate::event::Group::Fs,
        source: Source::SyntheticSysfs,
        tier: Tier::T0Direct,
        assumption: Some(assumption),
        detail: Detail::Fs {
            op,
            path: path.as_str().to_string(),
            bytes: len.unwrap_or(0),
            result: Ok(len.unwrap_or(0)),
        },
    };
    // The prose names the axis value, because "0 bytes" and "ENOENT" and "a
    // hundred plausible bytes" are three different substrates and the sentence
    // has to say which one produced this one.
    let what = match mode {
        SystemFsMode::Fabricated => format!(
            "{} -> {} bytes, fabricated by the substrate; there is no kernel",
            path,
            match len {
                Some(n) => format!("{n}"),
                None => "<absent>".to_string(),
            }
        ),
        SystemFsMode::Empty => format!(
            "{path} -> 0 bytes: the path exists in the substrate's model and is empty, which is \
             not the same answer as ENOENT"
        ),
        SystemFsMode::Absent => format!(
            "{path} -> ENOENT: the substrate models no /proc or /sys at all under this axis, so \
             the read failed. The attempt is recorded; the answer was never invented."
        ),
    };
    let probe_event = SubstrateEvent {
        seq: seq.saturating_add(1),
        t_mono_ms,
        group: crate::event::Group::Probes,
        source: Source::SyntheticSysfs,
        tier: Tier::T0Direct,
        assumption: Some(assumption),
        detail: Detail::Probes {
            pattern: pattern_for_sysfs(path.as_str()),
            // No axis suffix here: `Detail::summary` and the recording builder
            // both append it from the typed `axis` field, and writing it into the
            // string as well would put it in the document twice.
            detail: what,
            axis: Some(Axis::SystemFs),
        },
    };
    (fs_event, probe_event)
}

/// The `SIGNAL_PAT.*` identifier for a system-tree read.
pub fn pattern_for_sysfs(path: &str) -> &'static str {
    if path.contains("/proc/self/status") {
        "SIGNAL_PAT.PROC_STATUS"
    } else if path.contains("/proc/self/maps") || path.contains("/proc/self/stat") {
        "SIGNAL_PAT.PROC_MAPS"
    } else if path.contains("/proc/uptime") {
        "SIGNAL_PAT.PROC_UPTIME"
    } else if path.contains("/proc/cpuinfo") {
        "SIGNAL_PAT.PROC_CPUINFO"
    } else if path.contains("/proc/meminfo") {
        "SIGNAL_PAT.PROC_MEMINFO"
    } else if path.contains("/proc") {
        "SIGNAL_PAT.PROC_OTHER"
    } else if path.contains("/sys/class/power_supply") {
        "SIGNAL_PAT.BATTERY"
    } else if path.contains("/sys/devices/system/cpu") {
        "SIGNAL_PAT.CPU_ONLINE"
    } else if path.contains("/sys/block") {
        "SIGNAL_PAT.SYS_BLOCK"
    } else if path.contains("/sys") {
        "SIGNAL_PAT.SYS_OTHER"
    } else if path.contains("/dev/urandom") {
        "SIGNAL_PAT.ENTROPY"
    } else {
        "SIGNAL_PAT.SYS_OTHER"
    }
}

/// A PackageManager cross-app query, evaluated under an explicit axis value.
///
/// Under the substrate's default the substrate holds exactly one app, so
/// **every** query about another app answers "not installed". That is not a
/// limitation to be papered over; it is `SUB.IPC.PACKAGE_MANAGER_OTHER`'s whole
/// point, and the taxonomy calls it "a prime example of the class an evaluation
/// misses" — the app gets no error, an empty list, and silently loses an
/// inter-app feature. Recording the query and the empty answer together is what
/// makes it visible, and the `cross_app_packages` axis is what makes the
/// *emptiness* a declared choice rather than an accident of the implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageQuery {
    /// The package asked about.
    pub package: String,
    /// The subject APK's own package.
    pub subject: String,
    /// Whether the answer is "installed".
    pub installed: bool,
    /// Whether the query is about another app rather than the subject.
    pub cross_app: bool,
    /// The axis value that decided the answer.
    pub mode: PackageMode,
}

impl PackageQuery {
    /// Evaluate a query under an axis value.
    pub fn ask(package: &str, subject: &str, mode: PackageMode) -> PackageQuery {
        let cross_app = package != subject;
        // A self-query is not a cross-app query, so no axis value may turn it
        // into one: the `versionCode` self-check is a different assumption and
        // the taxonomy has a separate ID for it. A hostile app naming the
        // subject package is the only `true` the default can produce.
        let installed = if cross_app {
            mode.cross_app_installed()
        } else {
            true
        };
        PackageQuery {
            package: package.to_string(),
            subject: subject.to_string(),
            installed,
            cross_app,
            mode,
        }
    }

    /// Whether the query should throw rather than answer.
    pub fn throws(&self) -> bool {
        self.cross_app && self.mode.cross_app_throws()
    }

    /// The assumption a query feeds: a self-query is a different assumption from
    /// a cross-app one, and conflating them would lose the `versionCode`
    /// self-check finding.
    pub fn assumption(&self) -> AssumptionId {
        if self.cross_app {
            AssumptionId::IpcPackageManagerOther
        } else {
            AssumptionId::IpcPackageManagerSelf
        }
    }

    /// The `probes` event, labelled with the axis that answered.
    pub fn event(&self, seq: u64, t_mono_ms: u64) -> SubstrateEvent {
        let outcome =
            if self.cross_app {
                match self.mode {
                PackageMode::SubjectOnly =>
                    "not installed; the app sees an empty list, not an error".to_string(),
                PackageMode::AllPresent =>
                    "installed, per policy; the substrate holds one app and knows nothing about \
                     the others, so this answer is asserted rather than known"
                        .to_string(),
                PackageMode::Error =>
                    "NameNotFoundException; the substrate refuses the query rather than answering \
                     it, which is a different control-flow outcome from an empty answer"
                        .to_string(),
            }
            } else {
                "self".to_string()
            };
        SubstrateEvent {
            seq,
            t_mono_ms,
            group: crate::event::Group::Probes,
            source: Source::ClassLoader,
            tier: Tier::T0Direct,
            assumption: Some(self.assumption()),
            detail: Detail::Probes {
                pattern: "SIGNAL_PAT.PM_QUERY",
                detail: format!(
                    "PackageManager query for {} -> {outcome}{}",
                    self.package,
                    if self.cross_app {
                        axis_suffix(Some(Axis::CrossAppPackages))
                    } else {
                        String::new()
                    }
                ),
                axis: if self.cross_app {
                    Some(Axis::CrossAppPackages)
                } else {
                    None
                },
            },
        }
    }
}

/// The answer a list-valued package query gives, described. The list's
/// *contents* are not materialised under any axis value, because the substrate
/// holds exactly one app and knows nothing about the others: a list the app
/// cannot meaningfully inspect is a third outcome, and declaring it is more
/// honest than fabricating entries.
pub fn installed_list_probe(class: &str, name: &str, mode: PackageMode) -> String {
    match mode {
        PackageMode::SubjectOnly => format!(
            "{class}.{name}() -> a list of exactly one entry (the subject itself). An app looking \
             for a share target, a handler or a peer finds nothing, and finds nothing *without an \
             error*.{}",
            axis_suffix(Some(Axis::CrossAppPackages))
        ),
        PackageMode::AllPresent => format!(
            "{class}.{name}() -> a list reported NON-EMPTY for every query, with its contents NOT \
             materialised: the substrate holds one app and cannot describe the other apps it \
             claims are installed. An app that iterates this list gets entries it cannot \
             inspect, which is not the same outcome as a populated list on a device.{}",
            axis_suffix(Some(Axis::CrossAppPackages))
        ),
        PackageMode::Error => format!(
            "{class}.{name}() -> NameNotFoundException. The query is refused, so an app with a \
             try/catch behaves differently from one that silently found nothing.{}",
            axis_suffix(Some(Axis::CrossAppPackages))
        ),
    }
}

/// The clock read a `time` axis value produced, as a `probes` detail. Split out
/// so the recorded sentence and the recorded value come from one place and
/// cannot disagree.
pub fn clock_detail(method: &str, virtual_ms: u64, presented_ms: u64) -> String {
    if virtual_ms == presented_ms {
        format!(
            "{method}() -> {presented_ms}: the substrate's virtual clock, advanced only by the \
             recorded schedule.{}",
            axis_suffix(Some(Axis::Time))
        )
    } else {
        format!(
            "{method}() -> {presented_ms} for a virtual time of {virtual_ms} ms: the substrate's \
             time axis transformed the answer, and the untransformed value is stated so the \
             transformation is checkable.{}",
            axis_suffix(Some(Axis::Time))
        )
    }
}

/// The wall-clock read a `time` axis value produced.
pub fn wall_clock_detail(virtual_ms: u64, presented_ms: u64) -> String {
    let why = if presented_ms == 0 {
        "Zero, not the host's wall clock. A substrate that returned the host's time would make a \
         recording unreproducible and would import the host's skew into the app. This diverges \
         from a device and the divergence is recorded."
    } else {
        "The HOST's wall clock. This value is not reproducible, leaks the host's clock skew into \
         the app, and is recorded here so the effect is visible rather than inferred."
    };
    format!(
        "System.currentTimeMillis() -> {presented_ms} (virtual {virtual_ms} ms). {why}{}",
        axis_suffix(Some(Axis::Time))
    )
}

/// The identity `BuildInfo` a whole policy declares, for the recording's
/// `environment` block.
pub fn declared_identity(policy: &SubstratePolicy) -> BuildInfo {
    policy.identity.environment_identity()
}

/// Canonicalise an untrusted path for a system-tree read.
pub fn sysfs_path(input: &str) -> Result<VPath, ShimError> {
    VPath::parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fabricated() -> SubstratePolicy {
        SubstratePolicy::default()
    }

    #[test]
    fn a_proc_read_yields_both_an_fs_and_a_probe_event() {
        let p = sysfs_path("/proc/self/status").unwrap();
        let tree = SystemTree::default();
        let (content, assumption) = tree.read(&p).expect("modelled");
        assert_eq!(assumption, AssumptionId::TrustDebugDetect);
        assert!(content.contains("TracerPid:\t0"));
        let (fs, probe) = sysfs_events(
            &p,
            Some(content),
            assumption,
            SystemFsMode::Fabricated,
            7,
            100,
        );
        assert_eq!(fs.group, crate::event::Group::Fs);
        assert_eq!(probe.group, crate::event::Group::Probes);
        assert_eq!(probe.seq, 8);
        assert_eq!(
            probe.summary(),
            format!(
                "probes SIGNAL_PAT.PROC_STATUS: /proc/self/status -> {} bytes, fabricated by the \
substrate; there is no kernel [answered by substrate_policy axis system_fs]",
                content.len()
            )
        );
    }

    #[test]
    fn an_unmodelled_proc_path_is_absent_not_empty() {
        let p = sysfs_path("/proc/self/exe").unwrap();
        assert!(SystemTree::default().read(&p).is_none());
    }

    #[test]
    fn the_three_system_fs_values_are_three_distinct_answers() {
        let p = sysfs_path("/proc/self/status").unwrap();
        let tree = SystemTree::default();
        let fabricated = tree
            .read_with(&p, SystemFsMode::Fabricated)
            .expect("modelled");
        let empty = tree
            .read_with(&p, SystemFsMode::Empty)
            .expect("modelled, but empty");
        let absent = tree.read_with(&p, SystemFsMode::Absent);
        assert!(fabricated.0.contains("TracerPid"));
        assert_eq!(empty.0, "", "the path exists and is empty: a third answer");
        assert_eq!(absent, None, "and the loud arm is ENOENT");
        // All three name the same taxonomy ID, so they are comparable.
        assert_eq!(fabricated.1, empty.1);
        // And every one of them is labelled with the axis.
        for m in [
            SystemFsMode::Fabricated,
            SystemFsMode::Empty,
            SystemFsMode::Absent,
        ] {
            let (_, probe) = sysfs_events(&p, None, fabricated.1, m, 0, 0);
            let Detail::Probes { axis, .. } = &probe.detail else {
                panic!()
            };
            assert_eq!(*axis, Some(Axis::SystemFs));
        }
    }

    #[test]
    fn kernel_qemu_is_absent_and_that_is_observable() {
        let p = fabricated();
        let (v, a) = read_build_field("ro.kernel.qemu", &BuildInfo::default(), p.identity);
        assert_eq!(v, PropValue::Absent);
        assert_eq!(a, AssumptionId::BuildEmulator);
        let ev = build_field_event("ro.kernel.qemu", &v, p.identity, 0, 0);
        assert!(ev.summary().contains("substrate does not model this"));
        assert!(ev
            .summary()
            .contains("answered by substrate_policy axis identity"));
    }

    #[test]
    fn the_withheld_identity_says_withheld_and_not_unmodelled() {
        // The two absences are different facts. Flattening them would let a
        // withheld substrate's nulls be read as an emulator-detection finding.
        let withheld = IdentityMode::Withheld;
        let (v, _) = read_build_field("FINGERPRINT", &BuildInfo::withheld(), withheld);
        assert_eq!(v, PropValue::Absent);
        let ev = build_field_event("FINGERPRINT", &v, withheld, 0, 0);
        assert!(
            ev.summary().contains("substrate states no identity"),
            "{}",
            ev.summary()
        );
    }

    #[test]
    fn a_cross_app_package_query_records_the_empty_answer() {
        let q = PackageQuery::ask(
            "com.whatsapp",
            "pro.rudloff.search_to_browser",
            PackageMode::SubjectOnly,
        );
        assert!(!q.installed);
        assert!(!q.throws());
        assert_eq!(q.assumption(), AssumptionId::IpcPackageManagerOther);
        let s = q.event(0, 0).summary();
        assert!(s.contains("not installed"), "{s}");
        assert!(
            s.contains("answered by substrate_policy axis cross_app_packages"),
            "{s}"
        );
    }

    #[test]
    fn no_axis_value_can_turn_a_self_query_into_a_cross_app_one() {
        for m in [
            PackageMode::SubjectOnly,
            PackageMode::AllPresent,
            PackageMode::Error,
        ] {
            let q = PackageQuery::ask("a.b", "a.b", m);
            assert!(q.installed, "{m:?} made a self-query fail");
            assert!(!q.throws(), "{m:?} made a self-query throw");
            assert_eq!(q.assumption(), AssumptionId::IpcPackageManagerSelf);
        }
    }

    #[test]
    fn the_package_axis_answers_all_three_ways() {
        let subject = "a.b";
        let only = PackageQuery::ask("c.d", subject, PackageMode::SubjectOnly);
        assert!(!only.installed && !only.throws());
        let all = PackageQuery::ask("c.d", subject, PackageMode::AllPresent);
        assert!(all.installed && !all.throws());
        let err = PackageQuery::ask("c.d", subject, PackageMode::Error);
        assert!(!err.installed && err.throws());
        // And the list-valued query says so too, without inventing entries.
        assert!(
            installed_list_probe("LPM;", "getInstalledPackages", PackageMode::AllPresent)
                .contains("NOT materialised")
        );
    }

    #[test]
    fn the_clock_read_states_the_transformation_it_applied() {
        let plain = clock_detail("SystemClock.elapsedRealtime", 500, 500);
        assert!(plain.contains("-> 500"));
        assert!(plain.contains("axis time"));
        let scaled = clock_detail("SystemClock.elapsedRealtime", 500, 1500);
        assert!(
            scaled.contains("-> 1500 for a virtual time of 500 ms"),
            "{scaled}"
        );
        let wall = wall_clock_detail(500, 0);
        assert!(wall.contains("not the host's wall clock"), "{wall}");
    }

    #[test]
    fn the_clock_never_goes_backwards() {
        let mut c = Clock::new();
        assert_eq!(c.now_ms(), 0);
        c.advance(10);
        assert_eq!(c.advance_to(5), 10);
        c.advance(u64::MAX);
        assert_eq!(c.now_ms(), u64::MAX);
    }
}
