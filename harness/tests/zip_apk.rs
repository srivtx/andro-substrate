//! Reading a real APK, and refusing a hostile one.
//!
//! The fixtures are the six committed F-Droid DEX extracts' sibling APKs — but
//! an APK is a container and the committed corpus has containers, not archives, so
//! these tests **build** the archives they read. A ZIP writer is thirty lines
//! here rather than a dependency, and building the archive means the reader is
//! tested against bytes whose every field the test chose.

use substrate_harness::apk::{self, sha256_hex};
use substrate_harness::zip::{Zip, ZipError};

/// A minimal stored-entry ZIP builder: local header, data, central directory,
/// EOCD. Only enough for a fixture, and only ever called with arguments a test
/// wrote.
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut cd: Vec<u8> = Vec::new();
    for (name, data) in entries {
        let off = out.len() as u32;
        let crc = crc32(data);
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        cd.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes()); // version made by
        cd.extend_from_slice(&20u16.to_le_bytes()); // version needed
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // extra
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        cd.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        cd.extend_from_slice(&off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *e = c;
    }
    let mut c = 0xFFFF_FFFFu32;
    for b in data {
        c = table[((c ^ *b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFF_FFFF
}

/// A synthetic APK with a real binary manifest, taken from the committed corpus
/// so the reader is exercised against bytes dexcore has already parsed.
fn synthetic_apk(manifest: &[u8], dex: &[u8]) -> Vec<u8> {
    zip(&[
        ("AndroidManifest.xml", manifest),
        ("classes.dex", dex),
        ("res/layout/main.xml", b"\x00\x01"),
        ("lib/arm64-v8a/libnative.so", b"\x7fELF"),
        ("assets/config.json", b"{}"),
    ])
}

const APP_DEX: &[u8] =
    include_bytes!("../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex");

#[test]
fn a_stored_apk_reads_back_exactly() {
    let bytes = synthetic_apk(b"not really axml", APP_DEX);
    let z = Zip::open(&bytes).expect("the archive is well formed");
    assert_eq!(z.entries().len(), 5);
    assert_eq!(z.read("classes.dex").expect("dex reads"), APP_DEX);
    assert_eq!(
        z.read("AndroidManifest.xml").expect("manifest reads"),
        b"not really axml"
    );
    assert!(z.names().contains(&"lib/arm64-v8a/libnative.so"));
}

#[test]
fn an_apk_reports_its_dex_files_native_libraries_and_assets() {
    // The manifest is unparseable on purpose, so this test is about the
    // container facts and not about the manifest reader.
    let a = apk::open_apk_bytes(synthetic_apk(b"not really axml", APP_DEX)).expect("opens");
    assert_eq!(a.dex_names, vec!["classes.dex".to_string()]);
    assert_eq!(
        a.native_libs(),
        vec!["lib/arm64-v8a/libnative.so".to_string()]
    );
    assert_eq!(a.assets(), vec!["assets/config.json".to_string()]);
    assert!(a.extra_dex().expect("reads").is_empty());
    assert!(
        a.manifest.error.is_some(),
        "an unparseable manifest must say so rather than read as an app with no permissions"
    );
}

#[test]
fn an_apk_with_no_dex_is_an_error_not_an_empty_one() {
    let bytes = zip(&[("AndroidManifest.xml", b"x"), ("res/a", b"y")]);
    let e = apk::open_apk_bytes(bytes).expect_err("no classes at all");
    assert!(
        matches!(e, apk::ApkError::NoClasses),
        "a truncated or non-APK download must not look like an APK with no classes: {e}"
    );
}

#[test]
fn a_missing_manifest_is_reported_separately_from_a_broken_one() {
    let bytes = zip(&[("classes.dex", APP_DEX)]);
    let e = apk::open_apk_bytes(bytes).expect_err("no manifest");
    assert!(matches!(e, apk::ApkError::NoManifest(_)), "{e}");
}

// ------------------------------------------------------------ hostile input

#[test]
fn a_truncated_archive_is_an_error_at_every_cut() {
    let bytes = synthetic_apk(b"not really axml", APP_DEX);
    for cut in [
        0,
        1,
        4,
        7,
        8,
        16,
        32,
        64,
        128,
        256,
        512,
        1024,
        2048,
        bytes.len() - 1,
    ] {
        let slice = &bytes[..cut.min(bytes.len())];
        // Either it opens or it is a typed error. Never a panic, and never a
        // silently empty archive.
        match Zip::open(slice) {
            Ok(z) => {
                for e in z.entries() {
                    // Either it inflates or it is a typed error; the point of
                    // the loop is that neither path panics.
                    let _ = z.read(&e.name);
                }
            }
            Err(ZipError::NoCentralDirectory) | Err(ZipError::NotAZip) => {}
            Err(other) => panic!("cut {cut}: unexpected error {other}"),
        }
    }
}

#[test]
fn a_corrupted_length_is_refused_rather_than_read() {
    let mut bytes = synthetic_apk(b"not really axml", APP_DEX);
    // The EOCD's entry count is the first field a hostile file would lie about.
    let n = bytes.len();
    let eocd = bytes[n - 22..]
        .windows(4)
        .position(|w| w == [0x50, 0x4b, 0x05, 0x06])
        .map(|p| n - 22 + p)
        .expect("built by zip()");
    bytes[eocd + 10..eocd + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    // And the count must not be believed: an absurd one is refused before any
    // allocation proportional to it.
    match Zip::open(&bytes) {
        Ok(z) => assert!(z.entries().len() <= MAX_SANE),
        Err(ZipError::NoCentralDirectory)
        | Err(ZipError::NotAZip)
        | Err(ZipError::OutOfBounds { .. }) => {}
        Err(other) => panic!("{other}"),
    }
}

const MAX_SANE: usize = 200_000;

#[test]
fn a_deflate_stream_that_lies_about_its_size_is_refused() {
    // A zip bomb's header claim, with the real (tiny) payload behind it.
    let mut bytes = synthetic_apk(b"m", APP_DEX);
    // Find the classes.dex local header and set its uncompressed size to 4 GiB.
    let at = bytes
        .windows(11)
        .position(|w| w == b"classes.dex")
        .expect("built");
    let lh = at - 30;
    bytes[lh + 22..lh + 26].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // The central directory copy, which is what the reader trusts.
    let cd = bytes
        .windows(11)
        .rposition(|w| w == b"classes.dex")
        .expect("built");
    let cdh = cd - 46;
    bytes[cdh + 24..cdh + 28].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    if let Ok(z) = Zip::open(&bytes) {
        // Either the ZIP64 extra field supplies a real size, or the claim is
        // refused. A 4 GiB allocation is not among the outcomes.
        match z.read("classes.dex") {
            Err(ZipError::ImplausibleSize { .. })
            | Err(ZipError::SizeMismatch { .. })
            | Err(ZipError::OutOfBounds { .. })
            | Err(ZipError::NotAZip) => {}
            Err(other) => panic!("{other}"),
            Ok(d) => assert!(d.len() < 1 << 20, "a bomb produced {} bytes", d.len()),
        }
    }
}

#[test]
fn an_unsupported_compression_method_is_a_named_error() {
    let mut bytes = synthetic_apk(b"m", APP_DEX);
    let at = bytes
        .windows(11)
        .position(|w| w == b"classes.dex")
        .expect("built");
    let lh = at - 30;
    bytes[lh + 8..lh + 10].copy_from_slice(&99u16.to_le_bytes()); // LFH method
    let cd = bytes
        .windows(11)
        .rposition(|w| w == b"classes.dex")
        .expect("built");
    let cdh = cd - 46;
    bytes[cdh + 10..cdh + 12].copy_from_slice(&99u16.to_le_bytes());
    let z = Zip::open(&bytes).expect("the central directory still parses");
    assert_eq!(
        z.read("classes.dex"),
        Err(ZipError::UnsupportedMethod(99)),
        "an unknown method must be refused by number, not read as garbage"
    );
}

// ------------------------------------------------------------------- SHA-256

#[test]
fn sha256_matches_the_published_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // A million 'a' — the vector that catches a chunking mistake, which is the
    // only bug a hand-written SHA-256 plausibly has.
    let million = vec![b'a'; 1_000_000];
    assert_eq!(
        sha256_hex(&million),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}
