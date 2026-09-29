//! Shared test fixtures and the tools the tests check themselves against.
//!
//! Every byte in `fixtures/` came out of a real APK built by the real Android
//! toolchain, or — in one documented case — a reframed real table. The SHA-256
//! of each is pinned in `FIXTURES.md` and re-checked here, so a fixture that is
//! silently edited fails the suite rather than quietly redefining what the
//! tests mean.

use std::path::{Path, PathBuf};

use crate::resources::arsc::{ResConfig, ResourceTable};
use crate::resources::loader::{MemorySource, ResourceLoader};

/// Where the fixtures live, relative to this file.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/fixtures")
}

/// Every id the clock31 table defines, for a fuzz sweep that has to resolve
/// something plausible rather than nothing.
pub fn clock_fixture_ids(table: &ResourceTable) -> Vec<u32> {
    table.all_ids()
}

/// Read a fixture by name.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = fixture_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read fixture {name}: {e}"))
}

/// The SHA-256 of each fixture, as pinned in `FIXTURES.md`.
///
/// If this is out of date with the files, `fixtures_match_their_recorded_hashes`
/// fails, which is the point: it means somebody changed a byte without saying
/// so, and every other test in this module is only meaningful relative to those
/// bytes.
pub const FIXTURE_SHA256: &[(&str, &str)] = &[
    ("clock31.arsc", "5e84881e6e45eb7fccc4cce579f6f400cbf375de72b71ea3803bbcb188dfcc20"),
    ("clock31.layout_c31_widget.axml", "f8f42b054ea679c769008f4bb89abc4870d912196bb9f4c9514f4e41d5557530"),
    ("clock31.layout_calendar_entry.axml", "7e77f52105bef15b58b61f24d39c66794482f8d6e32e816e41b45dd608263419"),
    ("clock31.manifest.axml", "3714a030e0964bb8977a0920ccb0e6c178867116a77979f3137af5eb2a2ecba8"),
    ("pixel10proxl.arsc", "5b8da83ef9085a549e2af07d1c2803efd4431a3e9601a4efb9593da5aeea9578"),
    ("t4.arsc", "3dd20c2a71b4b5e14805dc963dde761686fc05733ed3aab9a6885814fa5294fc"),
    ("t4.drawable_button.axml", "6e1c68eff668d9034813d61c4a0cd87e014bff2ed7b52981d3bb81e802b68710"),
    ("vanillaplug.arsc", "f343d3a820b5d85d08f2c466ad4cd03fd6321d5f07bf718b65eee636b94741e2"),
    ("weatherforecast.reframed.apk", "6fe6ae6ffe21b787f4a3fd75fc853d26b7b43810f232066232fb102e6ff83f6b"),
    ("weatherforecast.reframed.arsc", "135592e59ff3c02a96dc64a86ff4294e58bcb85e748ada5b655dbaecc39680d6"),
];

/// Whether `aapt2` can be found, so the differential tests can run.
pub fn aapt2() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let build_tools = Path::new(&home).join("Library/Android/sdk/build-tools");
    let mut best: Option<(u32, PathBuf)> = None;
    for entry in std::fs::read_dir(&build_tools).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let version: u32 = name.split('.').next()?.parse().ok()?;
        let path = entry.path().join("aapt2");
        if path.exists() && best.as_ref().is_none_or(|(v, _)| version > *v) {
            best = Some((version, path));
        }
    }
    best.map(|(_, p)| p)
}

/// Run `aapt2 dump resources` on an APK and return its stdout.
pub fn aapt2_dump_resources(apk: &Path) -> Option<String> {
    let out = std::process::Command::new(aapt2()?)
        .args(["dump", "resources"])
        .arg(apk)
        .output()
        .ok()?;
    String::from_utf8(out.stdout).ok()
}

/// Whether `apkanalyzer` can be found.
///
/// This is the *real* oracle for configuration selection: unlike `aapt2`, which
/// only dumps, `apkanalyzer` links `libandroidfw` and resolves a resource
/// against a device configuration, which is exactly the code path this module
/// reimplements.
pub fn apkanalyzer() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let p = Path::new(&home)
        .join("Library/Android/sdk/cmdline-tools/latest/bin/apkanalyzer");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

/// Ask the real `libandroidfw` what a resource resolves to for a configuration.
///
/// `config` is an `apkanalyzer` qualifier string such as `it`, `land-xhdpi-v22`
/// or `default`. Returns `None` when the tool is missing or reports an error,
/// which the caller must treat as "no opinion" rather than as "absent".
pub fn oracle_value(apk: &Path, type_name: &str, name: &str, config: &str) -> Option<String> {
    let tool = apkanalyzer()?;
    // apkanalyzer is a JVM tool and inherits a broken JAVA_HOME from Android
    // Studio installs often enough to be worth fixing up here.
    let java_home = std::env::var("JAVA_HOME").ok().filter(|p| Path::new(p).is_dir())
        .or_else(|| {
            let out = std::process::Command::new("/usr/libexec/java_home").arg("-v").arg("17").output().ok()?;
            let p = String::from_utf8(out.stdout).ok()?;
            let p = p.trim();
            if p.is_empty() { None } else { Some(p.to_string()) }
        });
    let mut cmd = std::process::Command::new(tool);
    if let Some(jh) = java_home {
        cmd.env("JAVA_HOME", jh);
    }
    let out = cmd
        .args(["resources", "value", "--config", config, "--name", name, "--type", type_name])
        .arg(apk)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim_end_matches('\n');
    if text.is_empty() { None } else { Some(text.to_string()) }
}

/// `clock31.arsc` with `style/Theme.Clock31.AppWidgetContainerParent`'s parent
/// rewritten to point back at `style/Theme.Clock31.AppWidgetContainer`.
///
/// The real chain is
///   `0x7f070001` → `0x7f070002` → `0x01030128` (a framework style),
/// so changing one four-byte field turns it into a cycle. The bytes are the
/// real file's; only that one pointer differs, which is what makes this a
/// negative fixture rather than a synthesised one.
pub fn clock31_with_style_cycle() -> Vec<u8> {
    let mut bytes = fixture("clock31.arsc");
    // `style` is type byte 7, and `style/Theme.Clock31.AppWidgetContainerParent`
    // is entry index 2 within it.
    let parent_at = find_style_parent_field(&bytes, 7, 2).expect("style entry 2 is present");
    bytes[parent_at..parent_at + 4].copy_from_slice(&0x7f07_0001u32.to_le_bytes());
    bytes
}

/// `clock31.arsc` with `string/app_widget_description`'s value replaced by a
/// self-reference, so following it can only ever cycle.
///
/// The original is a `TYPE_STRING`; the replacement is a `TYPE_REFERENCE`
/// pointing at the string's own id, which is the shape a hostile table would
/// use to make a caller spin.
pub fn clock31_with_self_referencing_string() -> Vec<u8> {
    let mut bytes = fixture("clock31.arsc");
    // `string` is type byte 6; `string/app_widget_description` is entry 1.
    let at = find_simple_value_field(&bytes, 6, 1).expect("string entry 1 is present");
    // Res_value: size=8, res0=0, dataType=0x01 (TYPE_REFERENCE), data=<itself>.
    bytes[at + 3] = 0x01;
    bytes[at + 4..at + 8].copy_from_slice(&0x7f06_0001u32.to_le_bytes());
    bytes
}

/// Byte offset, inside the whole file, of the `parent` word of one entry of a
/// `ResTable_type` with the given one-based type byte.
fn find_style_parent_field(bytes: &[u8], type_byte: u8, entry: usize) -> Option<usize> {
    let (chunk_at, header_size) = find_type_chunk(bytes, type_byte)?;
    let entries_start = rd32(bytes, chunk_at + 16) as usize;
    let offset = rd32(bytes, chunk_at + header_size + entry * 4) as usize;
    Some(chunk_at + entries_start + offset + 8)
}

/// Byte offset of the `Res_value` of a *simple* entry.
fn find_simple_value_field(bytes: &[u8], type_byte: u8, entry: usize) -> Option<usize> {
    let (chunk_at, header_size) = find_type_chunk(bytes, type_byte)?;
    let entries_start = rd32(bytes, chunk_at + 16) as usize;
    let offset = rd32(bytes, chunk_at + header_size + entry * 4) as usize;
    let entry_at = chunk_at + entries_start + offset;
    let size = u16::from_le_bytes([bytes[entry_at], bytes[entry_at + 1]]) as usize;
    Some(entry_at + size)
}

/// The absolute offset and header size of the first `ResTable_type` chunk with
/// the given one-based `ResTable_type.id`.
fn find_type_chunk(bytes: &[u8], type_byte: u8) -> Option<(usize, usize)> {
    let mut at = 12usize;
    while at + 8 <= bytes.len() {
        let (t, hs, size) = (rd16(bytes, at), rd16(bytes, at + 2), rd32(bytes, at + 4) as usize);
        if size < 8 {
            return None;
        }
        if t == 0x0200 {
            let mut sub = at + hs as usize;
            let end = at + size;
            while sub + 8 <= end {
                let st = rd16(bytes, sub);
                let shs = rd16(bytes, sub + 2) as usize;
                let ssz = rd32(bytes, sub + 4) as usize;
                if ssz < 8 {
                    return None;
                }
                if st == 0x0201 && bytes[sub + 8] == type_byte {
                    return Some((sub, shs));
                }
                sub += ssz;
            }
            return None;
        }
        at += size;
    }
    None
}

fn rd16(b: &[u8], o: usize) -> u16 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn rd32(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
