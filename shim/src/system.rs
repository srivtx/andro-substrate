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
//: "fake"`) would be trivially detected, and every app with an integrity check
//! would refuse — which would make the study measure the refusal rather than the
//! app. So the identity is plausible, fixed, and *stated*: every probe event
//! carries the value it returned, and the recording's `environment` block
//! describes a substrate rather than a device.

use serde::{Deserialize, Serialize};

use crate::error::ShimError;
use crate::event::{Detail, FsOp, Source, SubstrateEvent, Tier};
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

    /// The fabricated contents of a path, plus the ID its read feeds.
    ///
    /// `None` for a path the substrate does not model, which is the important
    /// case: an app reading `/proc/self/exe` on a device gets a real path and in
    /// a substrate gets `ENOENT`, and the divergence is `SUB.IPC.BINDER_DEV`
    /// shaped. The caller records the failure; it must not invent content.
    pub fn read(&self, path: &VPath) -> Option<(&'static str, AssumptionId)> {
        let p = path.as_str();
        self.entries
            .iter()
            .find(|(e, _, _)| *e == p)
            .map(|(_, c, a)| (*c, *a))
    }

    /// Whether a path is one the tree fabricates, without reading it.
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
            Prop::Fingerprint | Prop::Model | Prop::Manufacturer | Prop::Brand | Prop::Device
            | Prop::Product | Prop::Hardware | Prop::Board => "SIGNAL_PAT.BUILD_FIELD",
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

/// A read of a `Build.*` field, and the value the shim returned.
pub fn read_build_field(field: &str, build: &BuildInfo) -> (PropValue, AssumptionId) {
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
        Some(p) => (p.value(build), p.assumption()),
        None => (PropValue::Absent, AssumptionId::BuildFingerprint),
    }
}

/// A `probes` event for a `Build.*` read.
pub fn build_field_event(field: &str, value: &PropValue, seq: u64, t_mono_ms: u64) -> SubstrateEvent {
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
    let pattern = prop.map(|p| p.pattern()).unwrap_or("SIGNAL_PAT.BUILD_FIELD");
    SubstrateEvent {
        seq,
        t_mono_ms,
        group: crate::event::Group::Probes,
        source: Source::SubstrateInstrumentation,
        tier: Tier::T0Direct,
        assumption: Some(assumption),
        detail: Detail::Probes {
            pattern,
            detail: format!(
                "Build.{} = {}",
                field,
                match value {
                    PropValue::Text(t) => t.clone(),
                    PropValue::Absent => "<absent: substrate does not model this>".to_string(),
                }
            ),
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
    seq: u64,
    t_mono_ms: u64,
) -> (SubstrateEvent, SubstrateEvent) {
    let op = if contents.is_some() { FsOp::Read } else { FsOp::Open };
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
    let probe_event = SubstrateEvent {
        seq: seq.saturating_add(1),
        t_mono_ms,
        group: crate::event::Group::Probes,
        source: Source::SyntheticSysfs,
        tier: Tier::T0Direct,
        assumption: Some(assumption),
        detail: Detail::Probes {
            pattern: pattern_for_sysfs(path.as_str()),
            detail: format!(
                "{} -> {} bytes, fabricated by the substrate; there is no kernel",
                path,
                match len {
                    Some(n) => format!("{n}"),
                    None => "<absent>".to_string(),
                }
            ),
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

/// A PackageManager cross-app query.
///
/// The substrate holds exactly one app, so **every** query about another app
/// answers "not installed". That is not a limitation to be papered over; it is
/// `SUB.IPC.PACKAGE_MANAGER_OTHER`'s whole point, and the taxonomy calls it "a
/// prime example of the class an evaluation misses" — the app gets no error, an
/// empty list, and silently loses an inter-app feature. Recording the query and
/// the empty answer together is what makes it visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageQuery {
    /// The package asked about.
    pub package: String,
    /// The subject APK's own package.
    pub subject: String,
    /// Whether the answer is "installed".
    pub installed: bool,
}

impl PackageQuery {
    /// Evaluate a query.
    pub fn ask(package: &str, subject: &str) -> PackageQuery {
        PackageQuery {
            package: package.to_string(),
            subject: subject.to_string(),
            // A hostile app could name the subject package and get a hit; that
            // is the only `true` this function can produce.
            installed: package == subject,
        }
    }

    /// The assumption a query feeds: a self-query is a different assumption from
    /// a cross-app one, and conflating them would lose the `versionCode`
    /// self-check finding.
    pub fn assumption(&self) -> AssumptionId {
        if self.package == self.subject {
            AssumptionId::IpcPackageManagerSelf
        } else {
            AssumptionId::IpcPackageManagerOther
        }
    }

    /// The `probes` event.
    pub fn event(&self, seq: u64, t_mono_ms: u64) -> SubstrateEvent {
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
                    "PackageManager query for {} -> {} (substrate holds exactly one app; every \
                     other answer is 'not installed' and the app sees an empty list, not an error)",
                    self.package,
                    if self.installed { "self" } else { "not installed" }
                ),
            },
        }
    }
}

/// Canonicalise an untrusted path for a system-tree read.
pub fn sysfs_path(input: &str) -> Result<VPath, ShimError> {
    VPath::parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proc_read_yields_both_an_fs_and_a_probe_event() {
        let p = sysfs_path("/proc/self/status").unwrap();
        let tree = SystemTree::default();
        let (content, assumption) = tree.read(&p).expect("modelled");
        assert_eq!(assumption, AssumptionId::TrustDebugDetect);
        assert!(content.contains("TracerPid:\t0"));
        let (fs, probe) = sysfs_events(&p, Some(content), assumption, 7, 100);
        assert_eq!(fs.group, crate::event::Group::Fs);
        assert_eq!(probe.group, crate::event::Group::Probes);
        assert_eq!(probe.seq, 8);
        assert_eq!(
            probe.summary(),
            format!(
                "probes SIGNAL_PAT.PROC_STATUS: /proc/self/status -> {} bytes, fabricated by the \
substrate; there is no kernel",
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
    fn kernel_qemu_is_absent_and_that_is_observable() {
        let (v, a) = read_build_field("ro.kernel.qemu", &BuildInfo::default());
        assert_eq!(v, PropValue::Absent);
        assert_eq!(a, AssumptionId::BuildEmulator);
    }

    #[test]
    fn a_cross_app_package_query_records_the_empty_answer() {
        let q = PackageQuery::ask("com.whatsapp", "pro.rudloff.search_to_browser");
        assert!(!q.installed);
        assert_eq!(q.assumption(), AssumptionId::IpcPackageManagerOther);
        assert!(q.event(0, 0).summary().contains("not installed"));
    }

    #[test]
    fn a_self_package_query_is_a_different_assumption() {
        let q = PackageQuery::ask("a.b", "a.b");
        assert_eq!(q.assumption(), AssumptionId::IpcPackageManagerSelf);
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
