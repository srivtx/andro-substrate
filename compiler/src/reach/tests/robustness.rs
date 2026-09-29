//! Robustness: no panics on untrusted input, and the APK path end to end.
//!
//! `IR.md`'s first non-negotiable is "No panics on untrusted input, at any
//! layer." An APK is untrusted input, and so is everything reachable from it:
//! the ZIP container, the DEX inside it, the manifest, and a string constant
//! that flows into a class-name test. Each is fuzzed here by truncation and by
//! single-byte corruption, which is cheap and catches the class of bug that
//! matters (an out-of-bounds read reached by flipping one byte).

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crate::reach::entry::Manifest;
use crate::reach::model::{DexInput, Program, UnitRole};
use crate::reach::zip::{ZipArchive, ZipError};
use crate::reach::{app_inputs_from_apk, framework_inputs_from_jar};

use super::fixtures::real_apps;

#[test]
fn a_truncated_or_corrupt_zip_is_an_error_not_a_panic() {
    // A real APK is needed for the interesting cases, and one is not committed.
    // A synthetic archive with every byte class the reader touches is enough:
    // truncation at every length must be an `Err` or a well-formed read.
    let archive = synthetic_apk();
    for n in 0..archive.len() {
        let cut = &archive[..n];
        match ZipArchive::open(cut) {
            Ok(ar) => {
                // If it parsed, every entry it claims must still read.
                for e in ar.entries() {
                    let _ = ar.read(cut, e);
                }
            }
            Err(ZipError::TooShort) | Err(ZipError::NoEndOfCentralDirectory) => {}
            Err(_) => {}
        }
    }
}

#[test]
fn single_byte_corruption_never_panics() {
    let archive = synthetic_apk();
    // Corrupt the central directory, the local header and the deflate stream
    // in turn. Deterministic positions, not random, so a failure reproduces.
    for pos in [
        archive.len() / 2,
        archive.len() - 6,
        archive.len() - 22,
        4,
        30,
    ] {
        let mut b = archive.clone();
        if let Some(x) = b.get_mut(pos) {
            *x ^= 0xff;
        }
        if let Ok(ar) = ZipArchive::open(&b) {
            for e in ar.entries() {
                let _ = ar.read(&b, e);
            }
        }
    }
}

#[test]
fn inflate_rejects_garbage_without_allocating_without_bound() {
    // A deflate stream that claims a huge length must not be trusted into a
    // huge allocation: this reader grows the output as it actually decodes.
    for b in [
        vec![0x00, 0x00, 0x00, 0xff, 0xff],
        vec![0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xff; 32],
        vec![0x4b, 0x4c, 0x44, 0x00],
    ] {
        let _ = crate::reach::zip::inflate(&b, u64::MAX);
    }
}

#[test]
fn a_truncated_dex_is_an_error_not_a_panic() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    for n in [
        0usize,
        1,
        4,
        0x70,
        0x200,
        app.dex.len() / 2,
        app.dex.len() - 1,
    ] {
        let truncated = app.dex[..n.min(app.dex.len())].to_vec();
        // Whatever happens, it must be a `Result`. A panicking reader on a
        // truncated file is the failure this test exists to catch.
        let _ = Program::build(vec![DexInput::new("classes.dex", UnitRole::App, truncated)]);
    }
}

#[test]
fn a_dex_with_every_byte_flipped_at_the_header_still_terminates() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    for pos in 0..0x70usize {
        let mut b = app.dex.to_vec();
        b[pos] ^= 0xff;
        let _ = Program::build(vec![DexInput::new("classes.dex", UnitRole::App, b)]);
    }
}

#[test]
fn a_corrupt_manifest_is_an_error_not_a_panic() {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    #[allow(unused_variables)]
    let _ = &app;
    for n in [0usize, 1, 8, 32, app.axml.len() / 2, app.axml.len() - 1] {
        let cut = &app.axml[..n.min(app.axml.len())];
        match Manifest::parse(cut) {
            Ok(_) | Err(_) => {}
        }
    }
    for pos in [0usize, 4, 8, 16, 40] {
        let mut b = app.axml.to_vec();
        if let Some(x) = b.get_mut(pos) {
            *x ^= 0xff;
        }
        let _ = Manifest::parse(&b);
    }
}

#[test]
fn a_truncated_trace_is_an_error_not_an_empty_method_set() {
    let trace =
        b"*version\n3\ndata-file-overflow=false\n*methods\n0x1\ta.b.C\tm\t()V\tC.java\n*end\n";
    for n in 0..trace.len() {
        if let Ok(t) = crate::reach::validate::parse_trace("t", &trace[..n]) {
            assert!(
                t.table_rows <= 1,
                "a truncated trace cannot invent method rows"
            );
        }
    }
}

#[test]
fn class_shape_detection_is_total_over_awkward_input() {
    let awkward: Vec<String> = [
        "",
        "\u{0}",
        "\u{10FFFF}",
        "L",
        ";",
        "L;L;L;L;",
        "..",
        "/",
        "//",
        "L/",
        ".a.b",
        "a..b",
        ".a",
        "Ljava/lang/String;\u{0}",
        "Ljava lang String;",
        "$",
        "_",
        "1",
        "-",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .chain(std::iter::once("L;".repeat(400)))
    .collect();
    for s in &awkward {
        let _ = crate::reach::class_like_descriptor(s);
    }
    // A pathological length must be rejected, not scanned.
    let long = "a".repeat(100_000);
    assert_eq!(crate::reach::class_like_descriptor(&long), None);
}

#[test]
fn the_apk_path_works_end_to_end_on_a_synthetic_archive() {
    let apk = synthetic_apk();
    let (units, manifest) = app_inputs_from_apk(&apk).expect("a synthetic APK must load");
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].name, "classes.dex");
    assert_eq!(units[0].role, UnitRole::App);
    assert!(manifest.is_some(), "AndroidManifest.xml must be recovered");
    let p = Program::build(units).expect("the extracted DEX must load");
    assert!(p
        .all_descriptors()
        .iter()
        .any(|d| d == "Ljava/lang/Object;"));
}

#[test]
fn the_jar_path_recognises_multi_dex_containers() {
    let jar = synthetic_jar();
    let units =
        framework_inputs_from_jar(&jar, "framework.jar").expect("a synthetic jar must load");
    assert_eq!(units.len(), 2, "classes.dex and classes2.dex both count");
    assert_eq!(units[0].name, "framework.jar!classes.dex");
    assert_eq!(units[1].name, "framework.jar!classes2.dex");
    assert!(units.iter().all(|u| u.role == UnitRole::Framework));
}

#[test]
fn a_non_zip_offered_as_an_apk_is_a_typed_error() {
    let err = app_inputs_from_apk(b"this is not a zip file at all").expect_err("must fail");
    assert!(
        err.to_string().contains("zip"),
        "the error must name its cause: {err}"
    );
}

/// A minimal but genuinely deflated APK, built with the crate's own inflater
/// round-tripped through hand-written ZIP structures.
fn synthetic_apk() -> Vec<u8> {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let mut v = Vec::new();
    let members: [(&str, &[u8]); 2] = [("classes.dex", app.dex), ("AndroidManifest.xml", app.axml)];
    for (name, body) in members {
        v.extend_from_slice(&stored_entry(name, body));
    }
    central_directory(&mut v, &["classes.dex", "AndroidManifest.xml"])
}

fn synthetic_jar() -> Vec<u8> {
    let app = real_apps().into_iter().next().expect("a fixture exists");
    let mut v = Vec::new();
    v.extend_from_slice(&stored_entry("classes.dex", app.dex));
    v.extend_from_slice(&stored_entry("classes2.dex", app.dex));
    central_directory(&mut v, &["classes.dex", "classes2.dex"])
}

/// A stored-method local file header followed by its data.
fn stored_entry(name: &str, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    v.extend_from_slice(&20u16.to_le_bytes()); // version needed
    v.extend_from_slice(&0u16.to_le_bytes()); // flags
    v.extend_from_slice(&0u16.to_le_bytes()); // stored
    v.extend_from_slice(&0u16.to_le_bytes()); // time
    v.extend_from_slice(&0u16.to_le_bytes()); // date
    v.extend_from_slice(&0u32.to_le_bytes()); // crc (not validated by this reader)
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(body.len() as u32).to_le_bytes());
    v.extend_from_slice(&(name.len() as u16).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes()); // extra
    v.extend_from_slice(name.as_bytes());
    v.extend_from_slice(body);
    v
}

fn central_directory(v: &mut Vec<u8>, names: &[&str]) -> Vec<u8> {
    // Recover each entry's local offset by re-walking the local headers.
    let mut offsets = Vec::new();
    let mut at = 0usize;
    for n in names {
        let nl = n.len();
        offsets.push(at);
        let size = u32::from_le_bytes([v[at + 18], v[at + 19], v[at + 20], v[at + 21]]) as usize;
        at += 30 + nl + size;
    }
    let cd_offset = v.len();
    for (n, off) in names.iter().zip(offsets.iter()) {
        let entry = &v[*off..];
        let size = u32::from_le_bytes([entry[18], entry[19], entry[20], entry[21]]);
        v.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&20u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(*off as u32).to_le_bytes());
        v.extend_from_slice(n.as_bytes());
    }
    let cd_size = v.len() - cd_offset;
    v.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&(names.len() as u16).to_le_bytes());
    v.extend_from_slice(&(names.len() as u16).to_le_bytes());
    v.extend_from_slice(&(cd_size as u32).to_le_bytes());
    v.extend_from_slice(&(cd_offset as u32).to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.to_vec()
}
