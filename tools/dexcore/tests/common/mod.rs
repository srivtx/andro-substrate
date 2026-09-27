//! Shared helpers for the fixture-based integration tests.
//!
//! Every DEX and AXML file under `tests/fixtures/` is a *tiny* extract taken
//! from a free-software APK published by F-Droid. Provenance — the source URL
//! and the SHA-256 of both the APK and the extracted member — is recorded in
//! `tests/FIXTURES.md` and in [`FIXTURES`].

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// One fixture: the extracted `classes.dex` and `AndroidManifest.xml`.
pub struct Fixture {
    /// Short name, e.g. `fr.smarquis.sleeptimer_16200`.
    pub name: &'static str,
    /// DEX version digits as they appear in the file, e.g. `038`.
    pub dex_version: &'static str,
    /// SHA-256 of the APK the fixtures were extracted from.
    pub apk_sha256: &'static str,
    /// The `classes.dex` bytes.
    pub dex: &'static [u8],
    /// The `AndroidManifest.xml` bytes, in Android binary XML form.
    pub axml: &'static [u8],
}

/// The fixture set, all sourced from F-Droid.
///
/// Deliberately small: the largest `classes.dex` here is 18 KB, so the whole
/// directory stays under 100 KB while still covering DEX versions 035 and 038,
/// single-package and multi-class layouts, interfaces, and constructors.
pub const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "pro.rudloff.search_to_browser_2",
        dex_version: "038",
        apk_sha256: "8dcc801faed47a1d8043083117a09eeee972e0d1affabcacb88eee286e4df0a5",
        dex: include_bytes!("../fixtures/pro.rudloff.search_to_browser_2.dex"),
        axml: include_bytes!("../fixtures/pro.rudloff.search_to_browser_2.axml"),
    },
    Fixture {
        name: "org.vi_server.red_screen_3",
        dex_version: "035",
        apk_sha256: "70e9b8490e5303210b93c7505e05f6b04724f20a426f5ac20c5d677b9147d085",
        dex: include_bytes!("../fixtures/org.vi_server.red_screen_3.dex"),
        axml: include_bytes!("../fixtures/org.vi_server.red_screen_3.axml"),
    },
    Fixture {
        name: "com.android.adbkeyboard_2",
        dex_version: "035",
        apk_sha256: "f9446fd3d7f775a764eb0df696b6819a7f3a4ea85bd17871855848ef72d6bb21",
        dex: include_bytes!("../fixtures/com.android.adbkeyboard_2.dex"),
        axml: include_bytes!("../fixtures/com.android.adbkeyboard_2.axml"),
    },
    Fixture {
        name: "com.oF2pks.neolinker_7",
        dex_version: "035",
        apk_sha256: "58a7d4b3e25af7c3091fbc2450227df2a3415423c4f176f25a96f7687a5acdcc",
        dex: include_bytes!("../fixtures/com.oF2pks.neolinker_7.dex"),
        axml: include_bytes!("../fixtures/com.oF2pks.neolinker_7.axml"),
    },
    Fixture {
        name: "com.termux.boot_1000",
        dex_version: "035",
        apk_sha256: "6f7cf9b94f539d3efd4af3544ff819947b49395275d8cfa7e5f80de14f3d9cf8",
        dex: include_bytes!("../fixtures/com.termux.boot_1000.dex"),
        axml: include_bytes!("../fixtures/com.termux.boot_1000.axml"),
    },
    Fixture {
        name: "fr.smarquis.sleeptimer_16200",
        dex_version: "038",
        apk_sha256: "4eacc3395dc5ca5381b6cf8628a197ce540f7e09d281254cd37601e93e1d5306",
        dex: include_bytes!("../fixtures/fr.smarquis.sleeptimer_16200.dex"),
        axml: include_bytes!("../fixtures/fr.smarquis.sleeptimer_16200.axml"),
    },
];

/// Directory holding the raw fixture files, for the provenance test.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}
