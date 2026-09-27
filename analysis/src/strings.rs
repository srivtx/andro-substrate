//! Classification of DEX string constants.
//!
//! This is where most of the predictor's *evidence* comes from and also where
//! most of its false positives live, so every classifier here is a named,
//! documented, individually testable predicate with a stated failure mode.
//! Nothing in this module guesses: a pattern either matches or it does not, and
//! a match carries the matched text as evidence.
//!
//! The three judgements this module encodes, stated up front because they are the
//! ones a reader will want to argue with:
//!
//! 1. **A string constant is not a call site.** Finding the literal
//!    `"/proc/self/status"` in the string pool proves the constant is *in the
//!    APK*, and a DEX assembler that had dead-code-eliminated an unreachable
//!    branch is the only thing that would have dropped it. It does **not** prove
//!    the app reads that path. The predictor reports constants and call sites
//!    as separate facts and never multiplies them together.
//! 2. **Dotted-name detection is defeated by obfuscation.** R8 renames
//!    `com.example.Foo` to `a.b.c`, so an obfuscated app's reflection targets
//!    are invisible. See `prediction.md` T-VAL-3.
//! 3. **A path-shaped string is not a filesystem assumption.** An app may ship
//!    `/sdcard/foo` as documentation, or a constant that only ever reaches a
//!    help screen. Again: reported, not scored as certainty.

use serde::Serialize;

/// How a string constant was classified, and what it is evidence of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StringTag {
    /// Looks like an absolute path, with the prefix identified.
    FilesystemPath,
    /// A Linux `proc` path, the family `SUB.KERNEL` is built on.
    ProcPath,
    /// A `sysfs` path.
    SysPath,
    /// A device node: `/dev/binder`, `/dev/urandom`, `/dev/ashmem`, …
    DevNode,
    /// An Android system partition path: `/system`, `/vendor`, `/apex`, …
    SystemPartition,
    /// An app-private data path.
    AppDataPath,
    /// A SELinux label or context string such as `u:r:app_data_file:s0`.
    SelinuxContext,
    /// An external-storage path.
    ExternalStorage,
    /// Looks like a fully-qualified Java class name.
    QualifiedClassName,
    /// Looks like a `package.Class#method` or `package.Class.method` reference.
    QualifiedMemberName,
    /// A *named reference* to an `android.os.Build` identity field, spelled as a
    /// descriptor, a dotted name or a `Build.FIELD` shorthand.
    ///
    /// This is deliberately **not** "the constant is a bare `FINGERPRINT`": a
    /// bare upper-snake constant is far more often a Java type descriptor letter
    /// (`"TYPE"`, `"ID"`, `"HOST"`), a resource name, or an enum constant, and
    /// tagging those would make the signal worthless. The `Build` field fact is
    /// established at the `field_id` and instruction level, where the full
    /// descriptor is available; this tag is only for the named-reference shape a
    /// reflective app would build.
    BuildIdentityLiteral,
    /// A probable native library name passed to `System.loadLibrary`.
    LibraryName,
    /// A Play Integrity / Play Services / SafetyNet related literal.
    IntegrityLiteral,
    /// A licensing or DRM library name.
    DrmLiteral,
    /// A JNI-ish name, typically `Java_com_example_Native_thing`.
    JniSymbolName,
}

/// One classified string constant.
///
/// `text` is the constant verbatim and is the evidence: a reader should be able
/// to grep the DEX for it and find it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TaggedString {
    pub tag: StringTag,
    /// The constant as stored in the DEX.
    pub text: String,
    /// The prefix or substring that triggered the tag, for `path_prefix` tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
    /// Pool index, so the constant can be located in the file.
    pub string_idx: u32,
    /// Which `classes*.dex` the constant came from.
    pub dex: String,
}

/// Does `needle` occur in `hay` at a position that could plausibly begin a path?
///
/// True when the match is at the start of the string, or when the preceding
/// character is a delimiter rather than part of an identifier or a longer path.
/// `https://example.com/proc/` fails: the preceding character is `m`. So does
/// `libfoo.so/proc/x`. `"see /proc/cpuinfo"` passes: the preceding character is
/// a space.
fn at_token_boundary(hay: &str, needle: &str) -> bool {
    let Some(at) = hay.find(needle) else {
        return false;
    };
    if at == 0 {
        return true;
    }
    let prev = hay.as_bytes()[at - 1];
    !(prev.is_ascii_alphanumeric() || prev == b'.' || prev == b'/' || prev == b'-' || prev == b'_')
}

/// Prefix table for path-shaped constants, longest-match first.
///
/// Each entry pairs a filesystem prefix with the taxonomy-relevant meaning of
/// having that literal in the APK. `id` is the taxonomy family it feeds, not a
/// claim that the app *uses* it.
const PATH_PREFIXES: &[(&str, StringTag)] = &[
    // procfs
    ("/proc/self/status", StringTag::ProcPath),
    ("/proc/self/maps", StringTag::ProcPath),
    ("/proc/self/mounts", StringTag::ProcPath),
    ("/proc/self/mountinfo", StringTag::ProcPath),
    ("/proc/self/cmdline", StringTag::ProcPath),
    ("/proc/self/exe", StringTag::ProcPath),
    ("/proc/self/oom_score", StringTag::ProcPath),
    ("/proc/self/task", StringTag::ProcPath),
    ("/proc/self/attr", StringTag::ProcPath),
    ("/proc/cpuinfo", StringTag::ProcPath),
    ("/proc/meminfo", StringTag::ProcPath),
    ("/proc/uptime", StringTag::ProcPath),
    ("/proc/stat", StringTag::ProcPath),
    ("/proc/version", StringTag::ProcPath),
    ("/proc/", StringTag::ProcPath),
    // sysfs
    ("/sys/class/thermal", StringTag::SysPath),
    ("/sys/class/power_supply", StringTag::SysPath),
    ("/sys/class/net", StringTag::SysPath),
    ("/sys/class/block", StringTag::SysPath),
    ("/sys/devices/", StringTag::SysPath),
    ("/sys/fs/cgroup", StringTag::SysPath),
    ("/sys/fs/selinux", StringTag::SelinuxContext),
    ("/sys/", StringTag::SysPath),
    // device nodes
    ("/dev/binder", StringTag::DevNode),
    ("/dev/binderfs", StringTag::DevNode),
    ("/dev/urandom", StringTag::DevNode),
    ("/dev/random", StringTag::DevNode),
    ("/dev/ashmem", StringTag::DevNode),
    ("/dev/socket", StringTag::DevNode),
    ("/dev/mem", StringTag::DevNode),
    ("/dev/graphics", StringTag::DevNode),
    ("/dev/bus", StringTag::DevNode),
    ("/dev/", StringTag::DevNode),
    // system partitions
    ("/system/bin", StringTag::SystemPartition),
    ("/system/lib", StringTag::SystemPartition),
    ("/system/framework", StringTag::SystemPartition),
    ("/system/fonts", StringTag::SystemPartition),
    ("/system/", StringTag::SystemPartition),
    ("/vendor/", StringTag::SystemPartition),
    ("/product/", StringTag::SystemPartition),
    ("/odm/", StringTag::SystemPartition),
    ("/apex/", StringTag::SystemPartition),
    // app data and external storage
    ("/data/data/", StringTag::AppDataPath),
    ("/data/user/", StringTag::AppDataPath),
    ("/data/local/tmp", StringTag::AppDataPath),
    ("/sdcard/", StringTag::ExternalStorage),
    ("/storage/emulated", StringTag::ExternalStorage),
    ("/storage/self/primary", StringTag::ExternalStorage),
    ("/mnt/sdcard", StringTag::ExternalStorage),
    ("/Android/obb/", StringTag::ExternalStorage),
];

/// Package and class-name prefixes that make a dotted string worth treating as a
/// class reference rather than a domain, a version, a file name or prose.
///
/// Deliberately conservative: a bare `com.google.android.gms` prefix is included
/// because GMS is a first-class taxonomy target, but the generic set is limited
/// to well-known root packages so that `example.text.here` does not inflate the
/// reflection surface.
const CLASS_ROOTS: &[&str] = &[
    "android.",
    "androidx.",
    "com.android.",
    "com.google.android.",
    "dalvik.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "kotlin.Metadata",
    "org.w3c.",
    "org.xml.",
    "org.json.",
    "org.xmlpull.",
    "org.apache.",
    "org.ietf.",
    "org.kxml.",
    "sun.",
    "jdk.",
    "com.google.gson.",
    "com.google.protobuf.",
    "com.google.firebase.",
    "okhttp3.",
    "retrofit2.",
    "okio.",
    "org.apache.http.",
    "org.bouncycastle.",
    "org.conscrypt.",
];

/// Method or field name fragments whose presence next to a `Class` receiver is
/// evidence of reflective feature detection.
const REFLECTIVE_NAMES: &[&str] = &[
    "getDeclaredMethod",
    "getDeclaredMethods",
    "getDeclaredField",
    "getDeclaredFields",
    "getMethod",
    "getMethods",
    "getField",
    "getFields",
    "getConstructor",
    "getConstructors",
    "forName",
    "newInstance",
    "setAccessible",
    "getDeclaredConstructor",
];

/// Substrings that identify a Play Integrity, Play Services or SafetyNet
/// reference in a string constant.
const INTEGRITY_LITERALS: &[&str] = &[
    "playintegrity",
    "play-integrity",
    "standardIntegrityToken",
    "MEETS_DEVICE_INTEGRITY",
    "MEETS_BASIC_INTEGRITY",
    "MEETS_STRONG_INTEGRITY",
    "decodeIntegrityToken",
    // A bare "integritytoken" was in the first version of this list and was
    // removed after it matched `access$parseSabrIntegrityTokenData` in
    // NewPipeEnhanced — an internal YouTube/SABR method name, not a Play
    // Integrity reference. Every entry is now a specific symbol or a package
    // name, never a plausible substring.
    "safetynet",
    "SafetyNetApi",
    "attestation.response",
    "com.google.android.gms.safetynet",
    "com.google.android.play.core.integrity",
];

/// Substrings that identify a licensing, activation or DRM library reference.
///
/// A bare `"drm"` was in the first version of this list and was removed after it
/// produced 258 false positives in a single app (`NewPipeEnhanced`), because any
/// three-letter substring matches inside unrelated constants. Every entry here
/// is at least six characters and names a specific type, package or service.
const DRM_LITERALS: &[&str] = &[
    "com.google.android.vending.licensing",
    "ILicensingService",
    "LicenseChecker",
    "com.google.android.vending",
    "widevine",
    "com.widevine",
    "MediaDrm",
    "android.media.MediaDrm",
    "play_licensing",
    "com.android.billingclient",
    "billingclient",
    "DRMConfig",
    "licensechecker",
];

/// A class/method name is a plausible identifier if it is non-empty and every
/// character is a letter, digit, `_` or `$`. This is the check that separates
/// `com.example.Foo` from `https://example.com/`.
fn is_java_identifier_segment(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
}

/// A bare identifier such as `libfoo` or `foo`, with no path separator, dot, or
/// extension. This is the shape `System.loadLibrary` takes.
pub fn looks_like_library_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 96 {
        return false;
    }
    if s.contains('/') || s.contains('\\') || s.contains('.') || s.contains(':') {
        return false;
    }
    // `+` is here because the NDK really does ship `libc++_shared.so`, and
    // `System.loadLibrary("c++_shared")` is a real call site in the wild.
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '+')
}

/// Does `s` look like a fully-qualified class name?
///
/// Requires a known root package, at least one dot, at least one interior dot
/// beyond the root, and all-identifier segments. `Landroid/os/Build;`-style
/// descriptors are handled by the caller, which sees the real class names.
pub fn looks_like_qualified_class_name(s: &str) -> bool {
    if s.len() > 512 || s.contains('/') || s.contains(' ') {
        return false;
    }
    if !CLASS_ROOTS.iter().any(|r| s.starts_with(r)) {
        return false;
    }
    let segs: Vec<&str> = s.split('.').collect();
    if segs.len() < 3 {
        return false;
    }
    segs.iter().all(|seg| is_java_identifier_segment(seg))
}

/// Does `s` look like `pkg.Class#method`, `pkg.Class.method` or `pkg/Class`?
///
/// The slash form is what a descriptor string constant spells (`java/lang/Class`),
/// and it is common in apps that build names by concatenation.
pub fn looks_like_qualified_member_name(s: &str) -> bool {
    if s.len() > 512 || s.contains(' ') {
        return false;
    }
    if let Some((head, _)) = s.split_once('#') {
        return head.contains('.') && head.split('.').count() >= 2;
    }
    if s.contains('/') {
        // `java/lang/Class` or `java/lang/Class;getMethod`
        let body = s.trim_start_matches('L').trim_end_matches(';');
        let segs: Vec<&str> = body.split('/').collect();
        return segs.len() >= 3 && segs.iter().all(|seg| is_java_identifier_segment(seg));
    }
    let segs: Vec<&str> = s.split('.').collect();
    segs.len() >= 3
        && segs[..segs.len() - 1]
            .iter()
            .all(|seg| is_java_identifier_segment(seg))
        && is_java_identifier_segment(segs[segs.len() - 1])
}

/// Does `s` look like an `android.os.Build` identity field name?
///
/// An upper-snake identifier, and nothing else: a lower-case `fingerprint` is a
/// local variable, and `TAGS_LIKE_THING` is somebody's constant. This is the
/// predicate used against `field_id` entries, where the defining class is known,
/// so the ambiguity of a bare name does not arise.
pub fn looks_like_build_identity_field(s: &str) -> bool {
    BUILD_IDENTITY_FIELDS.contains(&s)
}

/// If `s` names an `android.os.Build` identity field, return the field name.
///
/// Three accepted spellings, and nothing else:
///
/// * descriptor — `Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;`
/// * dotted — `android.os.Build.FINGERPRINT` or `Build.FINGERPRINT`
/// * descriptor, class only — `Landroid/os/Build;`
pub fn build_identity_reference(s: &str) -> Option<&'static str> {
    let tail = s
        .strip_prefix("Landroid/os/Build;")
        .or_else(|| s.strip_prefix("android.os.Build."))
        .or_else(|| s.strip_prefix("Build."))?;
    // Descriptor form: strip the field name off the front of `.F:N;`-shaped text.
    let tail = tail.strip_prefix('.').unwrap_or(tail);
    let field = tail.split([':', ';']).next().unwrap_or(tail);
    if looks_like_build_identity_field(field) {
        BUILD_IDENTITY_FIELDS.iter().find(|f| **f == field).copied()
    } else {
        None
    }
}

/// The `Build` fields the predicate accepts, in the order the predicate tests
/// them. Kept as data so `build_identity_reference` can hand back a `&'static
/// str` rather than borrowing from the input.
const BUILD_IDENTITY_FIELDS: &[&str] = &[
    "FINGERPRINT",
    "MODEL",
    "MANUFACTURER",
    "BRAND",
    "PRODUCT",
    "DEVICE",
    "HARDWARE",
    "BOARD",
    "BOOTLOADER",
    "SERIAL",
    "TAGS",
    "TYPE",
    "USER",
    "HOST",
    "ID",
    "DISPLAY",
    "RADIO",
    "TIME",
    "SUPPORTED_ABIS",
    "SUPPORTED_32_BIT_ABIS",
    "SUPPORTED_64_BIT_ABIS",
    "CPU_ABI",
    "CPU_ABI2",
];

/// Does `s` look like a JNI-exported symbol name?
pub fn looks_like_jni_symbol(s: &str) -> bool {
    s.starts_with("Java_")
        && s.len() > 5
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Classify one string constant, returning every tag it matches.
///
/// Multi-tagging is intentional and honest: a constant can be both a path and
/// a `proc` path, and collapsing that to one tag would lose the distinction the
/// taxonomy cares about.
pub fn classify(s: &str) -> Vec<(StringTag, Option<String>)> {
    let mut out: Vec<(StringTag, Option<String>)> = Vec::new();

    for (prefix, tag) in PATH_PREFIXES {
        if s.starts_with(prefix) {
            out.push((*tag, Some((*prefix).to_string())));
            break;
        }
    }
    // A path appearing *inside* a longer string still counts, but only when it
    // starts at a token boundary. Without that test `https://example.com/proc/`
    // and `a/b/proc/c` both tag as `PROC_PATH`, and the tag stops meaning
    // anything. The boundary rule is: the character before the match must not be
    // something that makes the match part of a longer word or a longer path.
    if out.is_empty() {
        for (prefix, tag) in PATH_PREFIXES {
            if prefix.len() > 3 && at_token_boundary(s, prefix) {
                out.push((*tag, Some(format!("contains:{prefix}"))));
                break;
            }
        }
    }

    if s.contains("u:r:") || s.contains(":s0:") || s.contains("selinux") {
        out.push((StringTag::SelinuxContext, None));
    }

    if looks_like_qualified_class_name(s) {
        out.push((StringTag::QualifiedClassName, None));
    } else if looks_like_qualified_member_name(s) {
        out.push((StringTag::QualifiedMemberName, None));
    }

    if let Some(field) = build_identity_reference(s) {
        out.push((StringTag::BuildIdentityLiteral, Some(field.to_string())));
    }

    let lower = s.to_ascii_lowercase();
    if INTEGRITY_LITERALS
        .iter()
        .any(|lit| lower.contains(&lit.to_ascii_lowercase()))
    {
        out.push((StringTag::IntegrityLiteral, None));
    }
    if DRM_LITERALS
        .iter()
        .any(|lit| lower.contains(&lit.to_ascii_lowercase()))
    {
        out.push((StringTag::DrmLiteral, None));
    }

    if looks_like_jni_symbol(s) {
        out.push((StringTag::JniSymbolName, None));
    }

    out
}

/// The reflective method names in [`REFLECTIVE_NAMES`], exported so the call
/// matcher and this module cannot drift apart.
pub fn reflective_names() -> &'static [&'static str] {
    REFLECTIVE_NAMES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(s: &str) -> Vec<StringTag> {
        classify(s).into_iter().map(|(t, _)| t).collect()
    }

    #[test]
    fn finds_proc_and_sys_paths_with_the_prefix_as_evidence() {
        let got = classify("/proc/self/status");
        assert_eq!(got[0].0, StringTag::ProcPath);
        assert_eq!(got[0].1.as_deref(), Some("/proc/self/status"));

        assert!(tags("/proc/cpuinfo").contains(&StringTag::ProcPath));
        assert!(tags("/sys/class/power_supply/battery/capacity").contains(&StringTag::SysPath));
        assert!(tags("/sys/fs/cgroup/memory/memory.limit_in_bytes").contains(&StringTag::SysPath));
    }

    #[test]
    fn finds_device_nodes_and_partitions() {
        assert!(tags("/dev/binder").contains(&StringTag::DevNode));
        assert!(tags("/dev/urandom").contains(&StringTag::DevNode));
        assert!(tags("/dev/ashmem").contains(&StringTag::DevNode));
        assert!(tags("/dev/socket/logdw").contains(&StringTag::DevNode));
        assert!(tags("/system/framework/framework.jar").contains(&StringTag::SystemPartition));
        assert!(tags("/data/data/com.example/files").contains(&StringTag::AppDataPath));
        assert!(tags("/sdcard/DCIM").contains(&StringTag::ExternalStorage));
    }

    #[test]
    fn does_not_tag_ordinary_prose_or_urls_as_paths() {
        for s in [
            "Hello, world",
            "https://example.com/proc/",
            "the /proc filesystem is not supported",
            "",
            "/",
        ] {
            assert!(
                !tags(s).contains(&StringTag::ProcPath),
                "{s:?} should not be a proc path"
            );
        }
    }

    #[test]
    fn recognises_class_names_only_under_known_roots() {
        assert!(looks_like_qualified_class_name("android.os.Build"));
        assert!(looks_like_qualified_class_name("java.lang.reflect.Method"));
        assert!(looks_like_qualified_class_name(
            "com.google.android.gms.safetynet.SafetyNetApi"
        ));
        assert!(!looks_like_qualified_class_name("com.example"));
        assert!(!looks_like_qualified_class_name("example.text.here"));
        assert!(!looks_like_qualified_class_name("3.14.159"));
        assert!(!looks_like_qualified_class_name("android.os"));
    }

    #[test]
    fn recognises_member_names_in_all_three_spellings() {
        assert!(looks_like_qualified_member_name(
            "java.lang.Class#getMethod"
        ));
        assert!(looks_like_qualified_member_name(
            "android.os.Build.FINGERPRINT"
        ));
        assert!(looks_like_qualified_member_name("java/lang/Class"));
        assert!(!looks_like_qualified_member_name("getMethod"));
        assert!(!looks_like_qualified_member_name("a.b"));
    }

    #[test]
    fn build_identity_field_names_are_upper_snake_and_nothing_else() {
        assert!(looks_like_build_identity_field("FINGERPRINT"));
        assert!(looks_like_build_identity_field("SUPPORTED_ABIS"));
        // Lowercase is a local variable or a resource name, not `Build`.
        assert!(!looks_like_build_identity_field("fingerprint"));
        assert!(!looks_like_build_identity_field("model"));
        assert!(!looks_like_build_identity_field("FINGERPRINT_LIKE"));
    }

    #[test]
    fn a_bare_upper_snake_constant_is_not_a_build_field_reference() {
        // "TYPE" is a Java type descriptor letter and "ID" is a type letter.
        // Tagging either as a Build identity field would be a false positive
        // with no evidence behind it.
        for s in ["TYPE", "ID", "HOST", "FINGERPRINT"] {
            assert!(!tags(s).contains(&StringTag::BuildIdentityLiteral), "{s}");
        }
    }

    #[test]
    fn a_named_build_reference_is_tagged_with_its_field() {
        assert_eq!(
            build_identity_reference("Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;"),
            Some("FINGERPRINT")
        );
        assert_eq!(
            build_identity_reference("android.os.Build.MODEL"),
            Some("MODEL")
        );
        assert_eq!(build_identity_reference("Build.SERIAL"), Some("SERIAL"));
        assert_eq!(build_identity_reference("Landroid/os/Build;"), None);
        assert_eq!(build_identity_reference("android.os.Build.NOPE"), None);
        let got = classify("Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;");
        assert!(got
            .iter()
            .any(|(t, _)| *t == StringTag::BuildIdentityLiteral));
        // The evidence must be a substring of the constant, so a reader can
        // check it by eye.
        let (_, m) = got
            .iter()
            .find(|(t, _)| *t == StringTag::BuildIdentityLiteral)
            .unwrap();
        assert!("Landroid/os/Build;.FINGERPRINT:Ljava/lang/String;".contains(m.as_ref().unwrap()));
    }

    #[test]
    fn a_path_inside_a_longer_word_is_not_a_path() {
        assert!(!tags("https://example.com/proc/self/status").contains(&StringTag::ProcPath));
        assert!(!tags("libfoo.so/proc/cpuinfo").contains(&StringTag::ProcPath));
        // A quoted or space-separated literal inside a message is a genuine hit.
        assert!(tags("cannot read /proc/cpuinfo").contains(&StringTag::ProcPath));
    }

    #[test]
    fn library_names_exclude_paths_and_dotted_names() {
        assert!(looks_like_library_name("sqlite3"));
        assert!(looks_like_library_name("choral_android"));
        assert!(looks_like_library_name("c++_shared"));
        assert!(!looks_like_library_name("lib/arm64-v8a/libfoo.so"));
        assert!(!looks_like_library_name("libfoo.so"));
        assert!(!looks_like_library_name(""));
    }

    #[test]
    fn a_three_letter_substring_is_not_a_drm_signal() {
        // "drm" was a false-positive machine: it matched 258 constants in
        // NewPipeEnhanced. Only specific type names count now.
        assert!(!tags("0.##x").contains(&StringTag::DrmLiteral));
        assert!(!tags("android.app.admin.DEVICE_ADMIN").contains(&StringTag::DrmLiteral));
        assert!(!tags("com.example.drmtool").contains(&StringTag::DrmLiteral));
        assert!(tags("android.media.MediaDrm").contains(&StringTag::DrmLiteral));
        assert!(tags("com.widevine").contains(&StringTag::DrmLiteral));
    }

    #[test]
    fn an_internal_method_name_is_not_a_play_integrity_reference() {
        // The regression this list actually needed: a bare "integritytoken"
        // substring matched a YouTube/SABR internal and produced a false
        // positive in the first run over the 120-APK sample.
        assert!(!tags("access$parseSabrIntegrityTokenData").contains(&StringTag::IntegrityLiteral));
        assert!(!tags("IntegrityTokenData").contains(&StringTag::IntegrityLiteral));
        assert!(tags("decodeIntegrityToken").contains(&StringTag::IntegrityLiteral));
        assert!(
            tags("com.google.android.play.core.integrity.IntegrityManager")
                .contains(&StringTag::IntegrityLiteral)
        );
    }

    #[test]
    fn integrity_and_drm_literals_are_found_case_insensitively() {
        assert!(
            tags("com.google.android.play.core.integrity.IntegrityManager")
                .contains(&StringTag::IntegrityLiteral)
        );
        assert!(tags("MEETS_DEVICE_INTEGRITY").contains(&StringTag::IntegrityLiteral));
        assert!(tags("decodeIntegrityToken").contains(&StringTag::IntegrityLiteral));
        assert!(tags("com.google.android.gms.safetynet.SafetyNetApi")
            .contains(&StringTag::IntegrityLiteral));
        assert!(
            tags("com.google.android.vending.licensing.ILicensingService")
                .contains(&StringTag::DrmLiteral)
        );
        assert!(tags("widevine").contains(&StringTag::DrmLiteral));
    }

    #[test]
    fn jni_exports_are_recognised() {
        assert!(tags("Java_com_example_Native_doThing").contains(&StringTag::JniSymbolName));
        assert!(!tags("Java_").contains(&StringTag::JniSymbolName));
    }

    #[test]
    fn a_manifest_style_package_name_is_not_mistaken_for_a_class() {
        // `com.example.app` has two dots and three segments but an unknown root.
        assert!(!tags("com.example.app").contains(&StringTag::QualifiedClassName));
    }
}
