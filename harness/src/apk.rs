//! Reading an APK into the facts a run needs.
//!
//! Everything here is a *static* fact read out of the file: the package name,
//! the SDK levels, the permissions, which class is the launcher, and which
//! `classes*.dex` exist. Nothing here decides anything the app will observe, and
//! nothing here is allowed to be a value the recording cannot show — every field
//! either comes from the APK or is reported as absent.

use std::fmt;

use dexcore::axml::{self, AttributeValue};

use crate::zip::{Zip, ZipError};

/// Why an APK could not be turned into a run.
#[derive(Debug)]
pub enum ApkError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The container is not a readable ZIP.
    Zip(ZipError),
    /// `AndroidManifest.xml` is missing or not binary XML.
    NoManifest(String),
    /// `classes.dex` is missing.
    NoDex,
    /// The APK has no `classes*.dex` at all.
    NoClasses,
}

impl fmt::Display for ApkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApkError::Io(e) => write!(f, "cannot read the APK: {e}"),
            ApkError::Zip(e) => write!(f, "cannot read the APK container: {e}"),
            ApkError::NoManifest(why) => {
                write!(f, "AndroidManifest.xml is unusable: {why}")
            }
            ApkError::NoDex => f.write_str("the APK has no classes.dex"),
            ApkError::NoClasses => f.write_str("the APK has no classes*.dex at all"),
        }
    }
}

impl std::error::Error for ApkError {}

impl From<ZipError> for ApkError {
    fn from(e: ZipError) -> ApkError {
        ApkError::Zip(e)
    }
}

impl From<std::io::Error> for ApkError {
    fn from(e: std::io::Error) -> ApkError {
        ApkError::Io(e)
    }
}

/// An APK, opened.
#[derive(Debug)]
pub struct Apk {
    /// The raw file. Kept because every other field is derived from it and a
    /// caller may want the digest.
    bytes: Vec<u8>,
    /// The container.
    zip: Zip<'static>,
    /// The manifest's static facts.
    pub manifest: ManifestFacts,
    /// `classes.dex` … `classesN.dex`, in archive order.
    pub dex_names: Vec<String>,
}

/// What the manifest says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManifestFacts {
    /// `package`.
    pub package: String,
    /// `android:versionCode`, or 0.
    pub version_code: u32,
    /// `android:versionName`, or `""`.
    pub version_name: String,
    /// `minSdkVersion`, or 0.
    pub min_sdk: u32,
    /// `targetSdkVersion`, or 0.
    pub target_sdk: u32,
    /// Every `uses-permission`, without the `android.permission.` prefix.
    pub permissions: Vec<String>,
    /// The `application` class, dotted, or `None`.
    pub application: Option<String>,
    /// The launcher activity, dotted, or `None`.
    pub launcher_activity: Option<String>,
    /// Every `activity`, dotted, in manifest order.
    pub activities: Vec<String>,
    /// Whether `android:debuggable` is set.
    pub debuggable: bool,
    /// `uses-feature`/`uses-library` names, which correlate with hardware the
    /// substrate has none of.
    pub features: Vec<String>,
    /// The error string, if the manifest would not parse.
    pub error: Option<String>,
}

/// Read an APK from a path.
///
/// The one place in the project that opens a file by name, and it opens exactly
/// the file the researcher named. `harness/tests/no_side_channels.rs` scans this
/// crate's source to keep it that way.
pub fn open_apk(path: &std::path::Path) -> Result<Apk, ApkError> {
    let bytes = std::fs::read(path)?;
    open_apk_bytes(bytes)
}

/// Read an APK already in memory. The path-taking wrapper exists only so the
/// tests can drive the same code a CLI does.
pub fn open_apk_bytes(bytes: Vec<u8>) -> Result<Apk, ApkError> {
    // The `Zip` borrows its buffer, so the archive is opened over a leaked
    // `Box` that the `Apk` owns for its whole life. A self-referential struct
    // is not expressible without unsafe, and `unsafe` is forbidden in this
    // project; the leak is bounded by one buffer per `Apk`, which is one per run.
    let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
    let zip = Zip::open(leaked)?;
    let manifest = match zip.read("AndroidManifest.xml") {
        Ok(m) => match axml::parse(&m) {
            Ok(doc) => read_manifest(&doc),
            Err(e) => ManifestFacts {
                error: Some(e.to_string()),
                ..Default::default()
            },
        },
        Err(ZipError::NotAFile(_)) => {
            return Err(ApkError::NoManifest("not present in the archive".into()))
        }
        Err(e) => return Err(ApkError::NoManifest(e.to_string())),
    };
    let mut dex_names: Vec<String> = zip
        .names()
        .iter()
        .filter(|n| {
            let rest = &n[n.len().saturating_sub(4)..];
            rest.eq_ignore_ascii_case(".dex") && n.starts_with("classes")
        })
        .map(|s| (*s).to_string())
        .collect();
    dex_names.sort();
    dex_names.dedup();
    if dex_names.is_empty() {
        return Err(ApkError::NoClasses);
    }
    if !dex_names.iter().any(|n| n == "classes.dex") {
        return Err(ApkError::NoDex);
    }
    Ok(Apk {
        bytes,
        zip,
        manifest,
        dex_names,
    })
}

impl Apk {
    /// The file's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A lower-case hex SHA-256.
    ///
    /// Written out rather than pulled in as a dependency: SHA-256 is thirty lines
    /// of table and the shim's whole dependency list is an invariant its tests
    /// assert. A wrong implementation here would be caught by `tests/apk.rs`,
    /// which checks the two published digests of the F-Droid fixtures.
    pub fn sha256(&self) -> String {
        sha256_hex(&self.bytes)
    }

    /// The primary `classes.dex`.
    pub fn classes_dex(&self) -> Result<Vec<u8>, ApkError> {
        Ok(self.zip.read("classes.dex")?)
    }

    /// `classes2.dex` and later, in order.
    pub fn extra_dex(&self) -> Result<Vec<(String, Vec<u8>)>, ApkError> {
        let mut out = Vec::new();
        for n in &self.dex_names {
            if n == "classes.dex" {
                continue;
            }
            out.push((n.clone(), self.zip.read(n)?));
        }
        Ok(out)
    }

    /// `lib/**.so` entry names, i.e. the native libraries the APK ships.
    pub fn native_libs(&self) -> Vec<String> {
        self.zip
            .names()
            .iter()
            .filter(|n| n.starts_with("lib/") && n.ends_with(".so"))
            .map(|s| (*s).to_string())
            .collect()
    }

    /// `assets/**` entry names, which is where a lot of an app's behaviour lives
    /// and which this harness reports so a reader knows it was not loaded.
    pub fn assets(&self) -> Vec<String> {
        self.zip
            .names()
            .iter()
            .filter(|n| n.starts_with("assets/"))
            .map(|s| (*s).to_string())
            .collect()
    }
}

/// Pull the static facts out of a parsed manifest.
fn read_manifest(doc: &axml::AxmlDocument) -> ManifestFacts {
    let mut f = ManifestFacts {
        package: doc.package_name().unwrap_or_default(),
        ..Default::default()
    };
    for e in doc.find_all("uses-permission") {
        if let Some(n) = e.attribute_value("android:name") {
            f.permissions.push(
                n.strip_prefix("android.permission.")
                    .unwrap_or(&n)
                    .to_string(),
            );
        }
    }
    f.permissions.sort();
    f.permissions.dedup();
    for e in doc.find_all("uses-feature") {
        if let Some(n) = e.attribute_value("android:name") {
            f.features.push(n);
        }
    }
    for e in doc.find_all("uses-library") {
        if let Some(n) = e.attribute_value("android:name") {
            f.features.push(n);
        }
    }
    // `find_all` returns a `Vec`, so this is "the first one" written as a loop
    // that breaks: an `application` element is unique in a well-formed manifest
    // and a second one means the file is odd, in which case the first is as
    // good a choice as any and the anomaly shows up as a wrong `application`.
    if let Some(e) = doc.find_all("application").into_iter().next() {
        f.version_code = int_of(e, "android:versionCode").unwrap_or(f.version_code);
        f.version_name = e
            .attribute_value("android:versionName")
            .unwrap_or(f.version_name);
        f.debuggable = matches!(
            e.attribute("android:debuggable").map(|a| &a.value),
            Some(AttributeValue::Int(1))
        );
        f.min_sdk = int_of(e, "android:minSdkVersion").unwrap_or(f.min_sdk);
        f.target_sdk = int_of(e, "android:targetSdkVersion").unwrap_or(f.target_sdk);
        f.application = e.attribute_value("android:name");
    }
    // `minSdkVersion` can also be a `<uses-sdk>` sibling of `<application>`.
    if f.min_sdk == 0 || f.target_sdk == 0 {
        for e in doc.find_all("uses-sdk") {
            if let Some(v) = int_of(e, "android:minSdkVersion") {
                f.min_sdk = v;
            }
            if let Some(v) = int_of(e, "android:targetSdkVersion") {
                f.target_sdk = v;
            }
        }
    }
    for e in doc.find_all("activity") {
        let name = match e.attribute_value("android:name") {
            Some(n) => n,
            None => continue,
        };
        // An inner class is written `.MainActivity`; the leading dot means the
        // package, and anything else without a dot is already fully qualified.
        let dotted = if let Some(rest) = name.strip_prefix('.') {
            format!("{}{}", f.package, rest)
        } else if name.contains('.') {
            name.clone()
        } else {
            format!("{}.{}", f.package, name)
        };
        let is_launcher = e.find_all("intent-filter").into_iter().any(|filter| {
            filter.find_all("action").into_iter().any(|a| {
                a.attribute_value("android:name").as_deref() == Some("android.intent.action.MAIN")
            }) && filter.find_all("category").into_iter().any(|c| {
                c.attribute_value("android:name").as_deref()
                    == Some("android.intent.category.LAUNCHER")
            })
        });
        f.activities.push(dotted.clone());
        if is_launcher && f.launcher_activity.is_none() {
            f.launcher_activity = Some(dotted);
        }
    }
    f
}

fn int_of(e: &axml::Element, name: &str) -> Option<u32> {
    match e.attribute(name).map(|a| &a.value) {
        Some(AttributeValue::Int(i)) => Some(*i as u32),
        // A resource reference in `minSdkVersion` is a real thing in a
        // `values/` resource, and a harness that guessed would be guessing.
        _ => None,
    }
}

/// SHA-256, in hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let d = sha256(data);
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// The FIPS 180-4 SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, b) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
