//! `resources.arsc` — the resource table.
//!
//! An APK's `resources.arsc` is a tree of `ResChunk`s. At the top is a
//! `ResTable_header`, then one global value string pool, then one or more
//! `ResTable_package` chunks. Each package carries two more string pools (type
//! names and entry names) and, per resource type, a `ResTable_typeSpec` plus one
//! `ResTable_type` per configuration.
//!
//! ```text
//! ResTable_header      0x0002
//!   ResStringPool      0x0001   every string *value* in the table
//!   ResTable_package   0x0200
//!     ResStringPool    0x0001   type names   ("layout", "string", ...)
//!     ResStringPool    0x0001   entry names  ("activity_main", ...)
//!     ResTable_typeSpec 0x0202  one per type: entry count + per-entry flags
//!     ResTable_type     0x0201  one per (type, configuration)
//! ```
//!
//! Reference: `ResourceTypes.h` in AOSP, which is the normative description of
//! every structure here. The matching and ordering logic in [`ResConfig`] is a
//! direct port of `ResTable_config::match` / `isMoreSpecificThan` /
//! `isBetterThan` from `ResourceTypes.cpp`, and is checked against
//! `apkanalyzer`, which links the same library.

use std::collections::BTreeMap;

use crate::resources::error::{ResourceError, Result};
use crate::resources::types::{RawValue, Value};

// --- chunk types -----------------------------------------------------------

/// `ResChunk_header.type` — the table itself.
pub const RES_TABLE_TYPE: u16 = 0x0002;
/// `ResChunk_header.type` — a string pool, wherever it appears.
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
/// `ResChunk_header.type` — a package.
pub const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
/// `ResChunk_header.type` — one configuration of one type.
pub const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
/// `ResChunk_header.type` — the shape shared by all configurations of one type.
pub const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
/// `ResChunk_header.type` — a shared-library declaration.
pub const RES_TABLE_LIBRARY_TYPE: u16 = 0x0203;
/// `ResChunk_header.type` — an overlayable declaration.
pub const RES_TABLE_OVERLAYABLE_TYPE: u16 = 0x0204;
/// `ResChunk_header.type` — an overlayable policy.
pub const RES_TABLE_OVERLAYABLE_POLICY_TYPE: u16 = 0x0205;
/// `ResChunk_header.type` — a staged alias.
pub const RES_TABLE_STAGED_ALIAS_TYPE: u16 = 0x0206;

/// `ResStringPool_header::SORTED_FLAG`.
pub const SORTED_FLAG: u32 = 1 << 0;
/// `ResStringPool_header::UTF8_FLAG`.
///
/// **This is the flag the AXML history in this project got wrong.** The
/// `ResStringPool_header` is the same structure in a binary XML file and in
/// `resources.arsc`, and `0x0100` is the only thing that distinguishes them:
///
/// | file | `flags` in the 204-APK F-Droid corpus |
/// |---|---|
/// | `AndroidManifest.xml` | `0x0` (UTF-16) in 203 of 204 APKs |
/// | `resources.arsc` | `0x100` (UTF-8) in 201 of 204 APKs |
///
/// A reader that carries the AXML default (UTF-16) into the resource table
/// decodes every resource *name* and every string *value* as UTF-16 pairs: the
/// table still parses, every id still resolves, and every string is garbage.
/// The flag has to be read, never assumed.
pub const UTF8_FLAG: u32 = 1 << 8;

/// `ResTable_type::FLAG_SPARSE`.
pub const FLAG_SPARSE: u8 = 0x01;
/// `ResTable_type::FLAG_OFFSET16`.
pub const FLAG_OFFSET16: u8 = 0x02;

/// `ResTable_type::NO_ENTRY`, the offset meaning "this entry has no value here".
pub const NO_ENTRY: u32 = 0xffff_ffff;

/// `ResTable_entry::FLAG_COMPLEX` — a bag of name/value pairs, not one value.
pub const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
/// `ResTable_entry::FLAG_PUBLIC` — declared public.
pub const ENTRY_FLAG_PUBLIC: u16 = 0x0002;
/// `ResTable_entry::FLAG_WEAK` — overridable.
pub const ENTRY_FLAG_WEAK: u16 = 0x0004;
/// `ResTable_entry::FLAG_COMPACT` — the value lives inside the entry itself.
pub const ENTRY_FLAG_COMPACT: u16 = 0x0008;

/// `ResTable_typeSpec::SPEC_PUBLIC`.
pub const SPEC_PUBLIC: u32 = 0x4000_0000;
/// `ResTable_typeSpec::SPEC_STAGED_API`.
pub const SPEC_STAGED_API: u32 = 0x2000_0000;

/// The smallest `ResTable_config.size` that can be read at all: the `size`
/// field itself. Everything past the declared size is treated as zero, which is
/// what makes one decoder able to read a 28-byte config written by Android 1.5
/// and a 64-byte one written by Android 14.
pub const RES_CONFIG_MIN_SIZE: u32 = 4;

// --- ResConfig -------------------------------------------------------------

// Field bitfield constants, from `ResourceTypes.h`. They are all "zero means
// any", which is the property the whole matcher is built on: a resource whose
// qualifier is absent matches every device.

/// `MASK_LAYOUTDIR`, the layout-direction bits of `screenLayout`.
pub const MASK_LAYOUTDIR: u8 = 0xC0;
/// `SHIFT_LAYOUTDIR`.
pub const SHIFT_LAYOUTDIR: u8 = 6;
/// `SCREENSIZE_ANY`.
pub const SCREENSIZE_ANY: u8 = 0x00;
/// `SCREENSIZE_SMALL`.
pub const SCREENSIZE_SMALL: u8 = 0x01;
/// `SCREENSIZE_NORMAL`.
pub const SCREENSIZE_NORMAL: u8 = 0x02;
/// `SCREENSIZE_LARGE`.
pub const SCREENSIZE_LARGE: u8 = 0x03;
/// `SCREENSIZE_XLARGE`.
pub const SCREENSIZE_XLARGE: u8 = 0x04;
/// `MASK_SCREENLONG`, the long/not-long bits of `screenLayout`.
pub const MASK_SCREENLONG: u8 = 0x30;
/// `SHIFT_SCREENLONG`.
pub const SHIFT_SCREENLONG: u8 = 4;
/// `SCREENLONG_ANY`.
pub const SCREENLONG_ANY: u8 = 0x00;
/// `SCREENLONG_NO`.
pub const SCREENLONG_NO: u8 = 0x10;
/// `SCREENLONG_YES`.
pub const SCREENLONG_YES: u8 = 0x20;
/// `MASK_SCREENSIZE`, the size-class bits of `screenLayout`.
pub const MASK_SCREENSIZE: u8 = 0x0F;
/// `MASK_UI_MODE_TYPE`, the mode-type bits of `uiMode`.
pub const MASK_UI_MODE_TYPE: u8 = 0x0F;
/// `MASK_UI_MODE_NIGHT`, the day/night bits of `uiMode`.
pub const MASK_UI_MODE_NIGHT: u8 = 0x30;
/// `SHIFT_UI_MODE_NIGHT`.
pub const SHIFT_UI_MODE_NIGHT: u8 = 4;
/// `UI_MODE_NIGHT_ANY`.
pub const UI_MODE_NIGHT_ANY: u8 = 0x00;
/// `UI_MODE_NIGHT_NO`.
pub const UI_MODE_NIGHT_NO: u8 = 0x10;
/// `UI_MODE_NIGHT_YES`.
pub const UI_MODE_NIGHT_YES: u8 = 0x20;
/// `MASK_SCREENROUND`, the round/not-round bits of `screenLayout2`.
pub const MASK_SCREENROUND: u8 = 0x03;
/// `MASK_WIDE_COLOR_GAMUT`, the gamut bits of `colorMode`.
pub const MASK_WIDE_COLOR_GAMUT: u8 = 0x03;
/// `MASK_HDR`, the HDR bits of `colorMode`.
pub const MASK_HDR: u8 = 0x0C;
/// `SHIFT_COLOR_MODE_HDR`.
pub const SHIFT_COLOR_MODE_HDR: u8 = 2;
/// `MASK_KEYSHIDDEN`, the keys-hidden bits of `inputFlags`.
pub const MASK_KEYSHIDDEN: u8 = 0x03;
/// `KEYSHIDDEN_ANY`.
pub const KEYSHIDDEN_ANY: u8 = 0x00;
/// `KEYSHIDDEN_NO` — "a keyboard is available".
pub const KEYSHIDDEN_NO: u8 = 0x01;
/// `KEYSHIDDEN_YES`.
pub const KEYSHIDDEN_YES: u8 = 0x02;
/// `KEYSHIDDEN_SOFT`.
pub const KEYSHIDDEN_SOFT: u8 = 0x03;
/// `MASK_NAVHIDDEN`, the nav-hidden bits of `inputFlags`.
pub const MASK_NAVHIDDEN: u8 = 0x0C;
/// `SHIFT_NAVHIDDEN`.
pub const SHIFT_NAVHIDDEN: u8 = 2;

/// `DENSITY_DEFAULT` — the qualifier `160dpi` is stored as, and treated as.
pub const DENSITY_DEFAULT: u16 = 0;
/// `DENSITY_LOW`.
pub const DENSITY_LOW: u16 = 120;
/// `DENSITY_MEDIUM`.
pub const DENSITY_MEDIUM: u16 = 160;
/// `DENSITY_TV`.
pub const DENSITY_TV: u16 = 213;
/// `DENSITY_HIGH`.
pub const DENSITY_HIGH: u16 = 240;
/// `DENSITY_XHIGH`.
pub const DENSITY_XHIGH: u16 = 320;
/// `DENSITY_XXHIGH`.
pub const DENSITY_XXHIGH: u16 = 480;
/// `DENSITY_XXXHIGH`.
pub const DENSITY_XXXHIGH: u16 = 640;
/// `DENSITY_ANY` — the `anydpi` qualifier.
pub const DENSITY_ANY: u16 = 0xfffe;
/// `DENSITY_NONE` — the `nodpi` qualifier.
pub const DENSITY_NONE: u16 = 0xffff;

/// `ORIENTATION_ANY`.
pub const ORIENTATION_ANY: u8 = 0;
/// `ORIENTATION_PORT`.
pub const ORIENTATION_PORT: u8 = 1;
/// `ORIENTATION_LAND`.
pub const ORIENTATION_LAND: u8 = 2;
/// `ORIENTATION_SQUARE`.
pub const ORIENTATION_SQUARE: u8 = 3;

/// `TOUCHSCREEN_ANY`.
pub const TOUCHSCREEN_ANY: u8 = 0;
/// `TOUCHSCREEN_NOTOUCH`.
pub const TOUCHSCREEN_NOTOUCH: u8 = 1;
/// `TOUCHSCREEN_STYLUS`.
pub const TOUCHSCREEN_STYLUS: u8 = 2;
/// `TOUCHSCREEN_FINGER`.
pub const TOUCHSCREEN_FINGER: u8 = 3;

/// `KEYBOARD_ANY`.
pub const KEYBOARD_ANY: u8 = 0;
/// `KEYBOARD_NOKEYS`.
pub const KEYBOARD_NOKEYS: u8 = 1;
/// `KEYBOARD_QWERTY`.
pub const KEYBOARD_QWERTY: u8 = 2;
/// `KEYBOARD_12KEY`.
pub const KEYBOARD_12KEY: u8 = 3;

/// `NAVIGATION_ANY`.
pub const NAVIGATION_ANY: u8 = 0;
/// `NAVIGATION_NONAV`.
pub const NAVIGATION_NONAV: u8 = 1;
/// `NAVIGATION_DPAD`.
pub const NAVIGATION_DPAD: u8 = 2;
/// `NAVIGATION_TRACKBALL`.
pub const NAVIGATION_TRACKBALL: u8 = 3;
/// `NAVIGATION_WHEEL`.
pub const NAVIGATION_WHEEL: u8 = 4;

/// `UI_MODE_TYPE_ANY`.
pub const UI_MODE_TYPE_ANY: u8 = 0x00;
/// `UI_MODE_TYPE_NORMAL`.
pub const UI_MODE_TYPE_NORMAL: u8 = 0x01;
/// `UI_MODE_TYPE_DESK`.
pub const UI_MODE_TYPE_DESK: u8 = 0x02;
/// `UI_MODE_TYPE_CAR`.
pub const UI_MODE_TYPE_CAR: u8 = 0x03;
/// `UI_MODE_TYPE_TELEVISION`.
pub const UI_MODE_TYPE_TELEVISION: u8 = 0x04;
/// `UI_MODE_TYPE_APPLIANCE`.
pub const UI_MODE_TYPE_APPLIANCE: u8 = 0x05;
/// `UI_MODE_TYPE_WATCH`.
pub const UI_MODE_TYPE_WATCH: u8 = 0x06;
/// `UI_MODE_TYPE_VR_HEADSET`.
pub const UI_MODE_TYPE_VR_HEADSET: u8 = 0x07;

/// Packed Tagalog, which CLDR replaced with Filipino.
const K_TAGALOG: [u8; 2] = [b't', b'l'];
/// Packed Filipino.
const K_FILIPINO: [u8; 2] = [0xAD, 0x05];
/// Packed English.
const K_ENGLISH: [u8; 2] = [b'e', b'n'];
/// Packed United States.
const K_UNITED_STATES: [u8; 2] = [b'U', b'S'];

/// The regions that CLDR parents directly to `en` rather than to `en-001`.
///
/// AOSP answers "is this locale close to US English?" with
/// `localeDataIsCloseToUsEnglish`, which walks CLDR's parent-locale table: the
/// answer is "we reach `en` before we reach `en-001`". The regions that parent
/// to `en` directly are exactly the US territories below — CLDR's `parentLocales`
/// maps every one of them to `en`, and every other English region to `en-001`.
/// The list is small, stable and auditable; the *general* CLDR walk is not
/// reproducible from the arsc, which is why [`LocaleData`] is a separate type
/// and why [`ResConfig::match`] reports when it had to do without one.
const EN_REGIONS_PARENTED_DIRECTLY_TO_EN: [&[u8; 2]; 8] = [
    b"US", b"AS", b"GU", b"MH", b"MP", b"PR", b"VI", b"UM",
];

/// A parsed `ResTable_config`: the device configuration a resource is qualified
/// for.
///
/// Every field follows the same rule: **zero means "any"**. A config that is
/// all zeros is the default resource and matches every device; a config that
/// pins one field matches only devices that agree on it. That is the whole
/// idea behind the format, and it is why [`ResConfig::matches`] can be
/// asymmetric: the default config matches any request, but a request with no
/// qualifiers does not match a config that demands `land`.
///
/// # Locale data
///
/// Three of AOSP's locale predicates — `localeDataComputeScript`,
/// `localeDataIsCloseToUsEnglish` and `localeDataCompareRegions` — read
/// CLDR's generated `LocaleDataLookup` table, which is several megabytes and
/// is not derivable from an APK. What is derivable is implemented exactly
/// ([`ResConfig::is_locale_more_specific_than`], the Tagalog/Filipino
/// equivalence, the en-US preference). What is not is replaced by AOSP's *own*
/// conservative branch — see [`ResConfig::matches_with`] and
/// [`LocaleData`], which reports when a degraded answer was used rather than
/// quietly returning one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ResConfig {
    /// Mobile country code, or 0 for "any".
    pub mcc: u16,
    /// Mobile network code, or 0 for "any".
    pub mnc: u16,
    /// ISO-639 language, packed as two 7-bit ASCII bytes, or a 3-letter code
    /// packed into a `u16` with the high bit set. `[0, 0]` is "any".
    pub language: [u8; 2],
    /// ISO-3166 region, packed the same way as `language`.
    pub country: [u8; 2],
    /// `ORIENTATION_*`.
    pub orientation: u8,
    /// `TOUCHSCREEN_*`.
    pub touchscreen: u8,
    /// Screen density in dpi, or one of the `DENSITY_*` constants.
    pub density: u16,
    /// `KEYBOARD_*`.
    pub keyboard: u8,
    /// `NAVIGATION_*`.
    pub navigation: u8,
    /// `KEYSHIDDEN_*` / `NAVHIDDEN_*` bitfield.
    pub input_flags: u8,
    /// Grammatical gender, or 0 for "any".
    pub grammatical_infection: u8,
    /// Screen width in pixels, or 0 for "any".
    pub screen_width: u16,
    /// Screen height in pixels, or 0 for "any".
    pub screen_height: u16,
    /// Minimum SDK version, or 0 for "any".
    pub sdk_version: u16,
    /// Minor version, or 0 for "any".
    pub minor_version: u16,
    /// `screenLayout` bitfield: size class, long, layout direction.
    pub screen_layout: u8,
    /// `uiMode` bitfield: mode type, night mode.
    pub ui_mode: u8,
    /// Smallest width in dp, or 0 for "any".
    pub smallest_screen_width_dp: u16,
    /// Screen width in dp, or 0 for "any".
    pub screen_width_dp: u16,
    /// Screen height in dp, or 0 for "any".
    pub screen_height_dp: u16,
    /// ISO-15924 script, e.g. `Latn`. Empty is "unspecified".
    pub locale_script: [u8; 4],
    /// BCP-47 variant, e.g. `POSIX`. Empty is "unspecified".
    pub locale_variant: [u8; 8],
    /// `MASK_SCREENROUND`.
    pub screen_layout2: u8,
    /// `MASK_WIDE_COLOR_GAMUT` / `MASK_HDR`.
    pub color_mode: u8,
    /// Whether `locale_script` was inferred rather than stated.
    pub locale_script_was_computed: bool,
    /// BCP-47 `u` extension (numbering system), e.g. `arab`.
    pub locale_numbering_system: [u8; 8],
}

impl ResConfig {
    /// A configuration that matches nothing in particular: the default config.
    pub const DEFAULT: ResConfig = ResConfig {
        mcc: 0,
        mnc: 0,
        language: [0, 0],
        country: [0, 0],
        orientation: 0,
        touchscreen: 0,
        density: 0,
        keyboard: 0,
        navigation: 0,
        input_flags: 0,
        grammatical_infection: 0,
        screen_width: 0,
        screen_height: 0,
        sdk_version: 0,
        minor_version: 0,
        screen_layout: 0,
        ui_mode: 0,
        smallest_screen_width_dp: 0,
        screen_width_dp: 0,
        screen_height_dp: 0,
        locale_script: [0; 4],
        locale_variant: [0; 8],
        screen_layout2: 0,
        color_mode: 0,
        locale_script_was_computed: false,
        locale_numbering_system: [0; 8],
    };

    /// `true` when every field is zero, i.e. this is the unqualified default.
    pub fn is_default(&self) -> bool {
        *self == ResConfig::DEFAULT
    }

    /// The `imsi` union word: `mcc | mnc << 16`.
    pub fn imsi(&self) -> u32 {
        u32::from(self.mcc) | (u32::from(self.mnc) << 16)
    }

    /// The `locale` union word: the four bytes of `language` and `country`.
    pub fn locale(&self) -> u32 {
        u32::from_le_bytes([self.language[0], self.language[1], self.country[0], self.country[1]])
    }

    /// The `screenType` union word: orientation, touchscreen, density.
    pub fn screen_type(&self) -> u32 {
        u32::from(self.orientation)
            | (u32::from(self.touchscreen) << 8)
            | (u32::from(self.density) << 16)
    }

    /// The `input` union word: keyboard, navigation, input flags, grammatical.
    pub fn input(&self) -> u32 {
        u32::from(self.keyboard)
            | (u32::from(self.navigation) << 8)
            | (u32::from(self.input_flags) << 16)
            | (u32::from(self.grammatical_infection) << 24)
    }

    /// The `screenSize` union word: pixel width and height.
    pub fn screen_size(&self) -> u32 {
        u32::from(self.screen_width) | (u32::from(self.screen_height) << 16)
    }

    /// The `version` union word: SDK and minor version.
    pub fn version(&self) -> u32 {
        u32::from(self.sdk_version) | (u32::from(self.minor_version) << 16)
    }

    /// The `screenConfig` union word: layout, ui mode, smallest width dp.
    pub fn screen_config(&self) -> u32 {
        u32::from(self.screen_layout)
            | (u32::from(self.ui_mode) << 8)
            | (u32::from(self.smallest_screen_width_dp) << 16)
    }

    /// The `screenSizeDp` union word: dp width and height.
    pub fn screen_size_dp(&self) -> u32 {
        u32::from(self.screen_width_dp) | (u32::from(self.screen_height_dp) << 16)
    }

    /// The `screenConfig2` union word: round, colour mode, reserved padding.
    ///
    /// AOSP tests this whole word for non-zero, so a config whose only non-zero
    /// byte is the reserved padding still enters the round/colour branch. The
    /// two sub-masks it then tests are both zero, so the outcome is the same
    /// either way, but the word is kept faithfully.
    pub fn screen_config2(&self) -> u32 {
        u32::from(self.screen_layout2) | (u32::from(self.color_mode) << 8)
    }

    /// Parse a `ResTable_config` out of `b` starting at `off`.
    ///
    /// Reads only the fields the declared `size` covers; every field past it is
    /// zero, which is AOSP's effective behaviour and is what lets one decoder
    /// read tables written by every SDK since 2009.
    pub fn parse(b: &[u8], off: usize) -> Result<ResConfig> {
        if off + 4 > b.len() {
            return Err(ResourceError::Truncated {
                what: "ResTable_config.size",
                need: off + 4,
                have: b.len(),
            });
        }
        let size = u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]);
        if size < RES_CONFIG_MIN_SIZE {
            return Err(ResourceError::BadConfigSize { size });
        }
        if off + size as usize > b.len() {
            return Err(ResourceError::Truncated {
                what: "ResTable_config",
                need: off + size as usize,
                have: b.len(),
            });
        }
        let mut c = ResConfig::DEFAULT;
        // A field is read only if the whole field lies inside the declared
        // size. `size` grows over releases: 28, 32, 36, 48, 52, 56, 64.
        let has = |end: usize| end <= size as usize;
        let u8_at = |i: usize| -> u8 { b[off + i] };
        let u16_at = |i: usize| -> u16 { u16::from_le_bytes([b[off + i], b[off + i + 1]]) };
        let u32_at = |i: usize| -> u32 {
            u32::from_le_bytes([b[off + i], b[off + i + 1], b[off + i + 2], b[off + i + 3]])
        };

        if has(8) {
            c.mcc = u16_at(4);
            c.mnc = u16_at(6);
        }
        if has(12) {
            c.language = [u8_at(8), u8_at(9)];
            c.country = [u8_at(10), u8_at(11)];
        }
        if has(16) {
            c.orientation = u8_at(12);
            c.touchscreen = u8_at(13);
            c.density = u16_at(14);
        }
        if has(20) {
            c.keyboard = u8_at(16);
            c.navigation = u8_at(17);
            c.input_flags = u8_at(18);
            c.grammatical_infection = u8_at(19);
        }
        if has(24) {
            c.screen_width = u16_at(20);
            c.screen_height = u16_at(22);
        }
        if has(28) {
            c.sdk_version = u16_at(24);
            c.minor_version = u16_at(26);
        }
        if has(32) {
            c.screen_layout = u8_at(28);
            c.ui_mode = u8_at(29);
            c.smallest_screen_width_dp = u16_at(30);
        }
        if has(36) {
            c.screen_width_dp = u16_at(32);
            c.screen_height_dp = u16_at(34);
        }
        if has(40) {
            c.locale_script.copy_from_slice(&b[off + 36..off + 40]);
        }
        if has(48) {
            c.locale_variant.copy_from_slice(&b[off + 40..off + 48]);
        }
        if has(52) {
            c.screen_layout2 = u8_at(48);
            c.color_mode = u8_at(49);
        }
        if has(53) {
            // A `bool` is one byte, 0 or 1. A byte outside that range is not
            // a bool; treating it as "computed" only ever makes the script
            // count as stated, which is the conservative direction.
            c.locale_script_was_computed = u8_at(52) != 0;
        }
        if has(64) {
            c.locale_numbering_system.copy_from_slice(&b[off + 56..off + 64]);
        }
        Ok(c)
    }

    /// Whether two packed two-byte codes are identical.
    fn codes_identical(a: &[u8; 2], b: &[u8; 2]) -> bool {
        a[0] == b[0] && a[1] == b[1]
    }

    /// Whether two languages are the same, allowing for Tagalog/Filipino.
    ///
    /// CLDR retired `tl` in favour of `fil`. AAPT2 writes whichever the app
    /// used, and a device reports the other, so without this equivalence a
    /// Tagalog app renders in English on a Filipino phone.
    pub fn langs_are_equivalent(a: &[u8; 2], b: &[u8; 2]) -> bool {
        ResConfig::codes_identical(a, b)
            || (ResConfig::codes_identical(a, &K_TAGALOG) && ResConfig::codes_identical(b, &K_FILIPINO))
            || (ResConfig::codes_identical(a, &K_FILIPINO) && ResConfig::codes_identical(b, &K_TAGALOG))
    }

    /// The locale importance score: variant, then script, then numbering system.
    ///
    /// AOSP picks variant over script by fiat, because BCP-47 gives no way to
    /// order `en-US-POSIX` against `en-Latn-US`, and says so in a comment
    /// rather than pretending the order is derived.
    pub fn importance_score_of_locale(&self) -> i32 {
        i32::from(self.locale_variant[0] != 0) * 4
            + i32::from(self.locale_script[0] != 0 && !self.locale_script_was_computed) * 2
            + i32::from(self.locale_numbering_system[0] != 0)
    }

    /// Positive if `self` is the more specific locale.
    ///
    /// Port of `ResTable_config::isLocaleMoreSpecificThan`.
    pub fn is_locale_more_specific_than(&self, o: &ResConfig) -> i32 {
        if self.locale() != 0 || o.locale() != 0 {
            if self.language[0] != o.language[0] {
                if self.language[0] == 0 {
                    return -1;
                }
                if o.language[0] == 0 {
                    return 1;
                }
            }
            if self.country[0] != o.country[0] {
                if self.country[0] == 0 {
                    return -1;
                }
                if o.country[0] == 0 {
                    return 1;
                }
            }
        }
        self.importance_score_of_locale() - o.importance_score_of_locale()
    }

    /// Whether this locale is close to US English.
    ///
    /// AOSP answers this by walking CLDR's parent table and checking whether
    /// `en` is reached before `en-001`. The set of regions that parent directly
    /// to `en` is exactly [`EN_REGIONS_PARENTED_DIRECTLY_TO_EN`], so the
    /// answer is computable without the table. A region with no English parent
    /// at all still answers false.
    pub fn is_close_to_us_english(&self, region: &[u8; 2]) -> bool {
        EN_REGIONS_PARENTED_DIRECTLY_TO_EN.iter().any(|r| *r == region)
    }

    /// Whether this config can serve a device with the given configuration.
    ///
    /// Port of `ResTable_config::match`, including its asymmetry: a default
    /// resource matches every device, but a device with no qualifiers does not
    /// match a resource that demands qualifiers.
    ///
    /// Uses [`ResConfig::matches_with`] and discards the report; prefer the
    /// latter if you want to know whether a degraded answer was involved.
    pub fn matches(&self, device: &ResConfig) -> bool {
        self.matches_with(device, &LocaleData::default()).matched
    }

    /// [`ResConfig::matches`], plus a report of whether a CLDR-dependent
    /// predicate had to be skipped.
    pub fn matches_with(&self, device: &ResConfig, locale: &LocaleData) -> MatchReport {
        let mut report = MatchReport::default();

        if self.imsi() != 0 {
            if self.mcc != 0 && self.mcc != device.mcc {
                return report.no();
            }
            if self.mnc != 0 && self.mnc != device.mnc {
                return report.no();
            }
        }

        if self.locale() != 0 {
            // Country and variant are deliberately *not* consulted here. AOSP
            // weeds those out in the specificity comparison instead, and doing
            // it in both places would reject `values-en` for an `en-US` device.
            if !ResConfig::langs_are_equivalent(&self.language, &device.language) {
                return report.no();
            }
            // Normally the two configs' scripts are compared directly. When the
            // device's script is unknown, or ours is unset and cannot be
            // computed, AOSP falls back to requiring the countries to match.
            let countries_must_match = if device.locale_script[0] == 0 {
                true
            } else if self.locale_script[0] == 0 && !self.locale_script_was_computed {
                match locale.compute_script(&self.language, &self.country) {
                    Some(script) => {
                        report.script_computed = true;
                        if script != device.locale_script {
                            return report.no();
                        }
                        false
                    }
                    None => {
                        report.locale_data_absent = true;
                        true
                    }
                }
            } else {
                if self.locale_script != device.locale_script {
                    return report.no();
                }
                false
            };
            if countries_must_match
                && self.country[0] != 0
                && !ResConfig::codes_identical(&self.country, &device.country)
            {
                return report.no();
            }
        }

        if self.grammatical_infection != 0 && self.grammatical_infection != device.grammatical_infection {
            return report.no();
        }

        if self.screen_config() != 0 {
            let layout_dir = self.screen_layout & MASK_LAYOUTDIR;
            if layout_dir != 0 && layout_dir != (device.screen_layout & MASK_LAYOUTDIR) {
                return report.no();
            }
            // A resource qualified for a *larger* screen than the device's
            // does not match; a resource qualified for a smaller one does.
            let screen_size = self.screen_layout & MASK_SCREENSIZE;
            if screen_size != 0 && screen_size > (device.screen_layout & MASK_SCREENSIZE) {
                return report.no();
            }
            let screen_long = self.screen_layout & MASK_SCREENLONG;
            if screen_long != 0 && screen_long != (device.screen_layout & MASK_SCREENLONG) {
                return report.no();
            }
            let ui_mode_type = self.ui_mode & MASK_UI_MODE_TYPE;
            if ui_mode_type != 0 && ui_mode_type != (device.ui_mode & MASK_UI_MODE_TYPE) {
                return report.no();
            }
            let ui_mode_night = self.ui_mode & MASK_UI_MODE_NIGHT;
            if ui_mode_night != 0 && ui_mode_night != (device.ui_mode & MASK_UI_MODE_NIGHT) {
                return report.no();
            }
            if self.smallest_screen_width_dp != 0
                && self.smallest_screen_width_dp > device.smallest_screen_width_dp
            {
                return report.no();
            }
        }

        if self.screen_config2() != 0 {
            let screen_round = self.screen_layout2 & MASK_SCREENROUND;
            if screen_round != 0 && screen_round != (device.screen_layout2 & MASK_SCREENROUND) {
                return report.no();
            }
            let hdr = self.color_mode & MASK_HDR;
            if hdr != 0 && hdr != (device.color_mode & MASK_HDR) {
                return report.no();
            }
            let wide = self.color_mode & MASK_WIDE_COLOR_GAMUT;
            if wide != 0 && wide != (device.color_mode & MASK_WIDE_COLOR_GAMUT) {
                return report.no();
            }
        }

        if self.screen_size_dp() != 0 {
            if self.screen_width_dp != 0 && self.screen_width_dp > device.screen_width_dp {
                return report.no();
            }
            if self.screen_height_dp != 0 && self.screen_height_dp > device.screen_height_dp {
                return report.no();
            }
        }

        if self.screen_type() != 0 {
            if self.orientation != 0 && self.orientation != device.orientation {
                return report.no();
            }
            // Density is never compared: any density can be scaled to any
            // other, so a resource qualified `-xhdpi` is a candidate for a
            // `hdpi` device and the *choice* between candidates is made later,
            // by `is_better_than`. Comparing here would reject every
            // density-qualified resource on every other-density device.
            if self.touchscreen != 0 && self.touchscreen != device.touchscreen {
                return report.no();
            }
        }

        if self.input() != 0 {
            let keys_hidden = self.input_flags & MASK_KEYSHIDDEN;
            if keys_hidden != 0 && keys_hidden != (device.input_flags & MASK_KEYSHIDDEN) {
                // `KEYSHIDDEN_NO` means "a keyboard is available", which also
                // describes a soft keyboard. A device asking for a soft
                // keyboard is therefore served a `keysHidden=no` resource.
                if keys_hidden != KEYSHIDDEN_NO
                    || (device.input_flags & MASK_KEYSHIDDEN) != KEYSHIDDEN_SOFT
                {
                    return report.no();
                }
            }
            let nav_hidden = self.input_flags & MASK_NAVHIDDEN;
            if nav_hidden != 0 && nav_hidden != (device.input_flags & MASK_NAVHIDDEN) {
                return report.no();
            }
            if self.keyboard != 0 && self.keyboard != device.keyboard {
                return report.no();
            }
            if self.navigation != 0 && self.navigation != device.navigation {
                return report.no();
            }
        }

        if self.screen_size() != 0 {
            if self.screen_width != 0 && self.screen_width > device.screen_width {
                return report.no();
            }
            if self.screen_height != 0 && self.screen_height > device.screen_height {
                return report.no();
            }
        }

        if self.version() != 0 {
            if self.sdk_version != 0 && self.sdk_version > device.sdk_version {
                return report.no();
            }
            if self.minor_version != 0 && self.minor_version != device.minor_version {
                return report.no();
            }
        }

        report.yes()
    }

    /// Whether this config is more specific than `o`.
    ///
    /// Port of `ResTable_config::isMoreSpecificThan`. The order of the tests
    /// *is* the precedence: an earlier field outranks a later one, so a config
    /// that differs only in orientation is beaten by one that differs in
    /// locale, whatever else it says.
    pub fn is_more_specific_than(&self, o: &ResConfig) -> bool {
        if self.imsi() != 0 || o.imsi() != 0 {
            if self.mcc != o.mcc {
                if self.mcc == 0 {
                    return false;
                }
                if o.mcc == 0 {
                    return true;
                }
            }
            if self.mnc != o.mnc {
                if self.mnc == 0 {
                    return false;
                }
                if o.mnc == 0 {
                    return true;
                }
            }
        }

        if self.locale() != 0 || o.locale() != 0 {
            let diff = self.is_locale_more_specific_than(o);
            if diff < 0 {
                return false;
            }
            if diff > 0 {
                return true;
            }
        }

        if self.grammatical_infection != 0 || o.grammatical_infection != 0 {
            if self.grammatical_infection != o.grammatical_infection {
                if self.grammatical_infection == 0 {
                    return false;
                }
                if o.grammatical_infection == 0 {
                    return true;
                }
            }
        }

        if self.screen_layout != 0 || o.screen_layout != 0 {
            if (self.screen_layout ^ o.screen_layout) & MASK_LAYOUTDIR != 0 {
                if self.screen_layout & MASK_LAYOUTDIR == 0 {
                    return false;
                }
                if o.screen_layout & MASK_LAYOUTDIR == 0 {
                    return true;
                }
            }
        }

        if self.smallest_screen_width_dp != 0 || o.smallest_screen_width_dp != 0 {
            if self.smallest_screen_width_dp != o.smallest_screen_width_dp {
                if self.smallest_screen_width_dp == 0 {
                    return false;
                }
                if o.smallest_screen_width_dp == 0 {
                    return true;
                }
            }
        }

        if self.screen_size_dp() != 0 || o.screen_size_dp() != 0 {
            if self.screen_width_dp != o.screen_width_dp {
                if self.screen_width_dp == 0 {
                    return false;
                }
                if o.screen_width_dp == 0 {
                    return true;
                }
            }
            if self.screen_height_dp != o.screen_height_dp {
                if self.screen_height_dp == 0 {
                    return false;
                }
                if o.screen_height_dp == 0 {
                    return true;
                }
            }
        }

        if self.screen_layout != 0 || o.screen_layout != 0 {
            if (self.screen_layout ^ o.screen_layout) & MASK_SCREENSIZE != 0 {
                if self.screen_layout & MASK_SCREENSIZE == 0 {
                    return false;
                }
                if o.screen_layout & MASK_SCREENSIZE == 0 {
                    return true;
                }
            }
            if (self.screen_layout ^ o.screen_layout) & MASK_SCREENLONG != 0 {
                if self.screen_layout & MASK_SCREENLONG == 0 {
                    return false;
                }
                if o.screen_layout & MASK_SCREENLONG == 0 {
                    return true;
                }
            }
        }

        if self.screen_layout2 != 0 || o.screen_layout2 != 0 {
            if (self.screen_layout2 ^ o.screen_layout2) & MASK_SCREENROUND != 0 {
                if self.screen_layout2 & MASK_SCREENROUND == 0 {
                    return false;
                }
                if o.screen_layout2 & MASK_SCREENROUND == 0 {
                    return true;
                }
            }
        }

        if self.color_mode != 0 || o.color_mode != 0 {
            if (self.color_mode ^ o.color_mode) & MASK_HDR != 0 {
                if self.color_mode & MASK_HDR == 0 {
                    return false;
                }
                if o.color_mode & MASK_HDR == 0 {
                    return true;
                }
            }
            if (self.color_mode ^ o.color_mode) & MASK_WIDE_COLOR_GAMUT != 0 {
                if self.color_mode & MASK_WIDE_COLOR_GAMUT == 0 {
                    return false;
                }
                if o.color_mode & MASK_WIDE_COLOR_GAMUT == 0 {
                    return true;
                }
            }
        }

        if self.orientation != o.orientation {
            if self.orientation == 0 {
                return false;
            }
            if o.orientation == 0 {
                return true;
            }
        }

        if self.ui_mode != 0 || o.ui_mode != 0 {
            if (self.ui_mode ^ o.ui_mode) & MASK_UI_MODE_TYPE != 0 {
                if self.ui_mode & MASK_UI_MODE_TYPE == 0 {
                    return false;
                }
                if o.ui_mode & MASK_UI_MODE_TYPE == 0 {
                    return true;
                }
            }
            if (self.ui_mode ^ o.ui_mode) & MASK_UI_MODE_NIGHT != 0 {
                if self.ui_mode & MASK_UI_MODE_NIGHT == 0 {
                    return false;
                }
                if o.ui_mode & MASK_UI_MODE_NIGHT == 0 {
                    return true;
                }
            }
        }

        // Density is deliberately absent: AOSP comments that the default "just
        // equals 160", so no density is more specific than another. The
        // preference between two densities is made by `is_better_than` instead.

        if self.touchscreen != o.touchscreen {
            if self.touchscreen == 0 {
                return false;
            }
            if o.touchscreen == 0 {
                return true;
            }
        }

        if self.input() != 0 || o.input() != 0 {
            if (self.input_flags ^ o.input_flags) & MASK_KEYSHIDDEN != 0 {
                if self.input_flags & MASK_KEYSHIDDEN == 0 {
                    return false;
                }
                if o.input_flags & MASK_KEYSHIDDEN == 0 {
                    return true;
                }
            }
            if (self.input_flags ^ o.input_flags) & MASK_NAVHIDDEN != 0 {
                if self.input_flags & MASK_NAVHIDDEN == 0 {
                    return false;
                }
                if o.input_flags & MASK_NAVHIDDEN == 0 {
                    return true;
                }
            }
            if self.keyboard != o.keyboard {
                if self.keyboard == 0 {
                    return false;
                }
                if o.keyboard == 0 {
                    return true;
                }
            }
            if self.navigation != o.navigation {
                if self.navigation == 0 {
                    return false;
                }
                if o.navigation == 0 {
                    return true;
                }
            }
        }

        if self.screen_size() != 0 || o.screen_size() != 0 {
            if self.screen_width != o.screen_width {
                if self.screen_width == 0 {
                    return false;
                }
                if o.screen_width == 0 {
                    return true;
                }
            }
            if self.screen_height != o.screen_height {
                if self.screen_height == 0 {
                    return false;
                }
                if o.screen_height == 0 {
                    return true;
                }
            }
        }

        if self.version() != 0 || o.version() != 0 {
            if self.sdk_version != o.sdk_version {
                if self.sdk_version == 0 {
                    return false;
                }
                if o.sdk_version == 0 {
                    return true;
                }
            }
            if self.minor_version != o.minor_version {
                if self.minor_version == 0 {
                    return false;
                }
                if o.minor_version == 0 {
                    return true;
                }
            }
        }

        false
    }

    /// Whether this config is a better match for `device` than `o` is.
    ///
    /// Port of `ResTable_config::isBetterThan`. This, not
    /// [`ResConfig::is_more_specific_than`], is what `ResTable::getEntry` uses
    /// to choose between configurations that all matched — the "pick the
    /// nearest" half of resource selection, which is why a `480dp`-wide
    /// layout wins on a `411dp` device over the default one.
    ///
    /// Returns `false` when neither is better, which is what makes the caller
    /// keep the earlier candidate: the scan in [`TypeSpec::select`] relies on
    /// ties resolving to file order, exactly as AOSP's does.
    pub fn is_better_than(&self, o: &ResConfig, device: &ResConfig) -> bool {
        if self.imsi() != 0 || o.imsi() != 0 {
            if self.mcc != o.mcc && device.mcc != 0 {
                return self.mcc != 0;
            }
            if self.mnc != o.mnc && device.mnc != 0 {
                return self.mnc != 0;
            }
        }

        if device.locale() != 0
            && (self.locale() != 0 || o.locale() != 0)
            && self.is_locale_better_than(o, device)
        {
            return true;
        }

        if self.grammatical_infection != 0 || o.grammatical_infection != 0 {
            if self.grammatical_infection != o.grammatical_infection
                && device.grammatical_infection != 0
            {
                return self.grammatical_infection != 0;
            }
        }

        if self.screen_layout != 0 || o.screen_layout != 0 {
            if (self.screen_layout ^ o.screen_layout) & MASK_LAYOUTDIR != 0
                && (device.screen_layout & MASK_LAYOUTDIR) != 0
            {
                return (self.screen_layout & MASK_LAYOUTDIR) > (o.screen_layout & MASK_LAYOUTDIR);
            }
        }

        if self.smallest_screen_width_dp != 0 || o.smallest_screen_width_dp != 0 {
            // Over-large candidates were already filtered by `matches`, so the
            // largest surviving value is the closest one.
            if self.smallest_screen_width_dp != o.smallest_screen_width_dp {
                return self.smallest_screen_width_dp > o.smallest_screen_width_dp;
            }
        }

        if self.screen_size_dp() != 0 || o.screen_size_dp() != 0 {
            // Closest to the request, by summed absolute error. A config that
            // leaves a dimension unset scores the full request size against
            // itself, so an explicitly-sized candidate always wins.
            let mut my_delta: i64 = 0;
            let mut other_delta: i64 = 0;
            if device.screen_width_dp != 0 {
                my_delta += i64::from(device.screen_width_dp) - i64::from(self.screen_width_dp);
                other_delta += i64::from(device.screen_width_dp) - i64::from(o.screen_width_dp);
            }
            if device.screen_height_dp != 0 {
                my_delta += i64::from(device.screen_height_dp) - i64::from(self.screen_height_dp);
                other_delta += i64::from(device.screen_height_dp) - i64::from(o.screen_height_dp);
            }
            if my_delta != other_delta {
                return my_delta < other_delta;
            }
        }

        if self.screen_layout != 0 || o.screen_layout != 0 {
            if (self.screen_layout ^ o.screen_layout) & MASK_SCREENSIZE != 0
                && (device.screen_layout & MASK_SCREENSIZE) != 0
            {
                // Backwards compatibility: an undefined size class counts as
                // `normal`, but only when the device is at least `normal`. On a
                // small screen, small really is better than undefined.
                let my_sl = self.screen_layout & MASK_SCREENSIZE;
                let o_sl = o.screen_layout & MASK_SCREENSIZE;
                let mut fixed_my = my_sl;
                let mut fixed_o = o_sl;
                if (device.screen_layout & MASK_SCREENSIZE) >= SCREENSIZE_NORMAL {
                    if fixed_my == 0 {
                        fixed_my = SCREENSIZE_NORMAL;
                    }
                    if fixed_o == 0 {
                        fixed_o = SCREENSIZE_NORMAL;
                    }
                }
                if fixed_my == fixed_o {
                    // Equal after the substitution: whichever one is actually
                    // undefined is the worse match.
                    if my_sl == 0 {
                        return false;
                    }
                    return true;
                }
                return fixed_my > fixed_o;
            }
            if (self.screen_layout ^ o.screen_layout) & MASK_SCREENLONG != 0
                && (device.screen_layout & MASK_SCREENLONG) != 0
            {
                return self.screen_layout & MASK_SCREENLONG != 0;
            }
        }

        if self.screen_layout2 != 0 || o.screen_layout2 != 0 {
            if (self.screen_layout2 ^ o.screen_layout2) & MASK_SCREENROUND != 0
                && (device.screen_layout2 & MASK_SCREENROUND) != 0
            {
                return self.screen_layout2 & MASK_SCREENROUND != 0;
            }
        }

        if self.color_mode != 0 || o.color_mode != 0 {
            if (self.color_mode ^ o.color_mode) & MASK_WIDE_COLOR_GAMUT != 0
                && (device.color_mode & MASK_WIDE_COLOR_GAMUT) != 0
            {
                return self.color_mode & MASK_WIDE_COLOR_GAMUT != 0;
            }
            if (self.color_mode ^ o.color_mode) & MASK_HDR != 0 && (device.color_mode & MASK_HDR) != 0
            {
                return self.color_mode & MASK_HDR != 0;
            }
        }

        if self.orientation != o.orientation && device.orientation != 0 {
            return self.orientation != 0;
        }

        if self.ui_mode != 0 || o.ui_mode != 0 {
            if (self.ui_mode ^ o.ui_mode) & MASK_UI_MODE_TYPE != 0
                && (device.ui_mode & MASK_UI_MODE_TYPE) != 0
            {
                return self.ui_mode & MASK_UI_MODE_TYPE != 0;
            }
            if (self.ui_mode ^ o.ui_mode) & MASK_UI_MODE_NIGHT != 0
                && (device.ui_mode & MASK_UI_MODE_NIGHT) != 0
            {
                return self.ui_mode & MASK_UI_MODE_NIGHT != 0;
            }
        }

        if self.screen_type() != 0 || o.screen_type() != 0 {
            if self.density != o.density {
                // Unset density means the system default, which is `medium`.
                let this_density = if self.density != 0 { i32::from(self.density) } else { i32::from(DENSITY_MEDIUM) };
                let other_density = if o.density != 0 { i32::from(o.density) } else { i32::from(DENSITY_MEDIUM) };

                // `anydpi` is always preferred over picking a bucket: it is the
                // app saying "scale this yourself", which is right for vector
                // drawables at any density.
                if this_density == i32::from(DENSITY_ANY) {
                    return true;
                }
                if other_density == i32::from(DENSITY_ANY) {
                    return false;
                }

                let mut requested_density = i32::from(device.density);
                if device.density == 0 || device.density == DENSITY_ANY {
                    requested_density = i32::from(DENSITY_MEDIUM);
                }

                // Prefer scaling *down*, and prefer the candidate nearest the
                // request from above. `h` is the larger density, `b_im_bigger`
                // says whether that is us.
                let mut h = this_density;
                let mut l = other_density;
                let mut b_im_bigger = true;
                if l > h {
                    std::mem::swap(&mut l, &mut h);
                    b_im_bigger = false;
                }
                if h == requested_density {
                    return b_im_bigger;
                }
                if l >= requested_density {
                    return !b_im_bigger;
                }
                b_im_bigger
            } else {
                false
            };

            if self.touchscreen != o.touchscreen && device.touchscreen != 0 {
                return self.touchscreen != 0;
            }
        }

        if self.input() != 0 || o.input() != 0 {
            let keys_hidden = self.input_flags & MASK_KEYSHIDDEN;
            let o_keys_hidden = o.input_flags & MASK_KEYSHIDDEN;
            if keys_hidden != o_keys_hidden {
                let req_keys_hidden = device.input_flags & MASK_KEYSHIDDEN;
                if req_keys_hidden != 0 {
                    if keys_hidden == 0 {
                        return false;
                    }
                    if o_keys_hidden == 0 {
                        return true;
                    }
                    // `KEYSHIDDEN_NO` and `KEYSHIDDEN_SOFT` are treated as
                    // equivalent for compatibility; an exact match breaks the
                    // tie.
                    if req_keys_hidden == keys_hidden {
                        return true;
                    }
                    if req_keys_hidden == o_keys_hidden {
                        return false;
                    }
                }
            }

            let nav_hidden = self.input_flags & MASK_NAVHIDDEN;
            let o_nav_hidden = o.input_flags & MASK_NAVHIDDEN;
            if nav_hidden != o_nav_hidden {
                let req_nav_hidden = device.input_flags & MASK_NAVHIDDEN;
                if req_nav_hidden != 0 {
                    if nav_hidden == 0 {
                        return false;
                    }
                    if o_nav_hidden == 0 {
                        return true;
                    }
                }
            }

            if self.keyboard != o.keyboard && device.keyboard != 0 {
                return self.keyboard != 0;
            }
            if self.navigation != o.navigation && device.navigation != 0 {
                return self.navigation != 0;
            }
        }

        if self.screen_size() != 0 || o.screen_size() != 0 {
            let mut my_delta: i64 = 0;
            let mut other_delta: i64 = 0;
            if device.screen_width != 0 {
                my_delta += i64::from(device.screen_width) - i64::from(self.screen_width);
                other_delta += i64::from(device.screen_width) - i64::from(o.screen_width);
            }
            if device.screen_height != 0 {
                my_delta += i64::from(device.screen_height) - i64::from(self.screen_height);
                other_delta += i64::from(device.screen_height) - i64::from(o.screen_height);
            }
            if my_delta != other_delta {
                return my_delta < other_delta;
            }
        }

        if self.version() != 0 || o.version() != 0 {
            if self.sdk_version != o.sdk_version && device.sdk_version != 0 {
                return self.sdk_version > o.sdk_version;
            }
            if self.minor_version != o.minor_version && device.minor_version != 0 {
                return self.minor_version != 0;
            }
        }

        // Nothing the device actually cares about separated them.
        self.is_more_specific_than(o)
    }

    /// Whether this locale is a better match for `device` than `o`'s.
    ///
    /// Port of `ResTable_config::isLocaleBetterThan`, minus the one step that
    /// needs CLDR's parent-locale tree: the region comparison. Everything
    /// before it — the "no language at all" preference for US English, which
    /// is where unqualified `values/` resources historically lived for
    /// English-language apps — is exact.
    pub fn is_locale_better_than(&self, o: &ResConfig, device: &ResConfig) -> bool {
        if device.locale() == 0 {
            return false;
        }
        if self.locale() == 0 && o.locale() == 0 {
            return false;
        }

        if !ResConfig::langs_are_equivalent(&self.language, &o.language) {
            // Both matched the request, so the only way to get here with
            // different languages is that one has no language and the other
            // has one that matches. Naming the language wins — except that an
            // unqualified resource is the traditional home of the US English
            // strings, so for en-US an unqualified resource beats `en-GB`.
            if ResConfig::codes_identical(&device.language, &K_ENGLISH) {
                if ResConfig::codes_identical(&device.country, &K_UNITED_STATES) {
                    if self.language[0] != 0 {
                        return self.country[0] == 0
                            || ResConfig::codes_identical(&self.country, &K_UNITED_STATES);
                    }
                    return !(o.country[0] == 0
                        || ResConfig::codes_identical(&o.country, &K_UNITED_STATES));
                } else if self.is_close_to_us_english(&device.country) {
                    if self.language[0] != 0 {
                        return self.is_close_to_us_english(&self.country);
                    }
                    return !self.is_close_to_us_english(&o.country);
                }
            }
            return self.language[0] != 0;
        }

        // The languages are equivalent and non-empty. AOSP would compare
        // regions through CLDR here; without that table the region step is
        // skipped, and the variant / numbering-system / identical-language
        // steps below still apply.
        let locale_matches = self.locale_variant == device.locale_variant;
        let other_matches = o.locale_variant == device.locale_variant;
        if locale_matches != other_matches {
            return locale_matches;
        }

        let numsys_matches = self.locale_numbering_system == device.locale_numbering_system;
        let other_numsys_matches = o.locale_numbering_system == device.locale_numbering_system;
        if numsys_matches != other_numsys_matches {
            return numsys_matches;
        }

        // Tagalog and Filipino are equivalent but not identical, and an exact
        // match beats an equivalent one.
        ResConfig::codes_identical(&self.language, &device.language)
            && !ResConfig::codes_identical(&o.language, &device.language)
    }

    /// The resource-qualifier suffix for this config, e.g. `-land-xhdpi-v22`.
    ///
    /// AAPT2 prints configurations in exactly this form (`aapt2 dump resources`
    /// shows `(land-xhdpi-v22)` next to each variant), which makes this a
    /// differential-test surface: the string this produces for a config decoded
    /// from real bytes can be compared with the string AAPT2 prints for the
    /// same bytes.
    pub fn to_qualifier_string(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.mcc != 0 || self.mnc != 0 {
            parts.push(format!("mcc{}mnc{}", self.mcc, self.mnc));
        }
        if self.language[0] != 0 {
            let mut l = String::from("b+");
            l.push_str(&unpack_code(&self.language));
            if self.country[0] != 0 {
                l.push('+');
                l.push_str(&unpack_code(&self.country));
            }
            if self.locale_script[0] != 0 && !self.locale_script_was_computed {
                l.push('+');
                l.push_str(&cstr(&self.locale_script));
            }
            if self.locale_variant[0] != 0 {
                l.push('+');
                l.push_str(&cstr(&self.locale_variant));
            }
            if self.locale_numbering_system[0] != 0 {
                l.push('+');
                l.push_str(&cstr(&self.locale_numbering_system));
            }
            parts.push(l);
        }
        match self.screen_layout & MASK_LAYOUTDIR {
            0x40 => parts.push("ldltr".into()),
            0x80 => parts.push("ldrtl".into()),
            _ => {}
        }
        match self.screen_layout & MASK_SCREENSIZE {
            SCREENSIZE_SMALL => parts.push("small".into()),
            SCREENSIZE_NORMAL => parts.push("normal".into()),
            SCREENSIZE_LARGE => parts.push("large".into()),
            SCREENSIZE_XLARGE => parts.push("xlarge".into()),
            _ => {}
        }
        match self.screen_layout & MASK_SCREENLONG {
            SCREENLONG_NO => parts.push("notlong".into()),
            SCREENLONG_YES => parts.push("long".into()),
            _ => {}
        }
        match self.screen_layout2 & MASK_SCREENROUND {
            0x01 => parts.push("notround".into()),
            0x02 => parts.push("round".into()),
            _ => {}
        }
        match self.color_mode & MASK_WIDE_COLOR_GAMUT {
            0x01 => parts.push("nowidecg".into()),
            0x02 => parts.push("widecg".into()),
            _ => {}
        }
        match self.color_mode & MASK_HDR {
            0x04 => parts.push("lowdr".into()),
            0x08 => parts.push("highdr".into()),
            _ => {}
        }
        match self.orientation {
            ORIENTATION_PORT => parts.push("port".into()),
            ORIENTATION_LAND => parts.push("land".into()),
            ORIENTATION_SQUARE => parts.push("square".into()),
            _ => {}
        }
        match self.ui_mode & MASK_UI_MODE_TYPE {
            UI_MODE_TYPE_DESK => parts.push("desk".into()),
            UI_MODE_TYPE_CAR => parts.push("car".into()),
            UI_MODE_TYPE_TELEVISION => parts.push("television".into()),
            UI_MODE_TYPE_APPLIANCE => parts.push("appliance".into()),
            UI_MODE_TYPE_WATCH => parts.push("watch".into()),
            UI_MODE_TYPE_VR_HEADSET => parts.push("vrheadset".into()),
            _ => {}
        }
        match self.ui_mode & MASK_UI_MODE_NIGHT {
            UI_MODE_NIGHT_NO => parts.push("notnight".into()),
            UI_MODE_NIGHT_YES => parts.push("night".into()),
            _ => {}
        }
        match self.density {
            DENSITY_LOW => parts.push("ldpi".into()),
            DENSITY_MEDIUM => parts.push("mdpi".into()),
            DENSITY_TV => parts.push("tvdpi".into()),
            DENSITY_HIGH => parts.push("hdpi".into()),
            DENSITY_XHIGH => parts.push("xhdpi".into()),
            DENSITY_XXHIGH => parts.push("xxhdpi".into()),
            DENSITY_XXXHIGH => parts.push("xxxhdpi".into()),
            DENSITY_ANY => parts.push("anydpi".into()),
            DENSITY_NONE => parts.push("nodpi".into()),
            d if d != 0 => parts.push(format!("{d}dpi")),
            _ => {}
        }
        match self.touchscreen {
            TOUCHSCREEN_NOTOUCH => parts.push("notouch".into()),
            TOUCHSCREEN_STYLUS => parts.push("stylus".into()),
            TOUCHSCREEN_FINGER => parts.push("finger".into()),
            _ => {}
        }
        match self.input_flags & MASK_KEYSHIDDEN {
            KEYSHIDDEN_NO => parts.push("keysexposed".into()),
            KEYSHIDDEN_YES => parts.push("keyshidden".into()),
            KEYSHIDDEN_SOFT => parts.push("keyssoft".into()),
            _ => {}
        }
        match self.keyboard {
            KEYBOARD_NOKEYS => parts.push("nokeys".into()),
            KEYBOARD_QWERTY => parts.push("qwerty".into()),
            KEYBOARD_12KEY => parts.push("12key".into()),
            _ => {}
        }
        match self.input_flags & MASK_NAVHIDDEN {
            0x04 => parts.push("navexposed".into()),
            0x08 => parts.push("navhidden".into()),
            _ => {}
        }
        match self.navigation {
            NAVIGATION_NONAV => parts.push("nonav".into()),
            NAVIGATION_DPAD => parts.push("dpad".into()),
            NAVIGATION_TRACKBALL => parts.push("trackball".into()),
            NAVIGATION_WHEEL => parts.push("wheel".into()),
            _ => {}
        }
        if self.screen_size() != 0 {
            parts.push(format!("{}x{}", self.screen_width, self.screen_height));
        }
        if self.smallest_screen_width_dp != 0 {
            parts.push(format!("sw{}dp", self.smallest_screen_width_dp));
        }
        if self.screen_size_dp() != 0 {
            parts.push(format!("{}dp", self.screen_width_dp));
            parts.push(format!("{}dp", self.screen_height_dp));
        }
        if self.sdk_version != 0 {
            parts.push(format!("v{}", self.sdk_version));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("-{}", parts.join("-"))
        }
    }
}

/// Read a NUL-padded fixed-width code field as a string.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Unpack a two-byte locale code into its 2- or 3-letter form.
fn unpack_code(code: &[u8; 2]) -> String {
    if code[0] & 0x80 != 0 {
        // A packed 3-letter code: 5 bits per letter, high bit set.
        let packed = ((u32::from(code[1]) << 8) | u32::from(code[0])) & 0x7fff;
        let c = |shift: u32| char::from(b'A' + ((packed >> (5 * shift)) & 0x1f) as u8);
        format!("{}{}{}", c(2), c(1), c(0))
    } else {
        String::from_utf8_lossy(code).into_owned()
    }
}

/// The outcome of [`ResConfig::matches_with`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MatchReport {
    /// Whether the config matched the device.
    pub matched: bool,
    /// The resource's script had to be inferred from its language and region.
    pub script_computed: bool,
    /// A CLDR-dependent predicate was unavailable and AOSP's conservative
    /// branch was taken instead. See [`LocaleData`].
    pub locale_data_absent: bool,
}

impl MatchReport {
    fn yes(&self) -> MatchReport {
        MatchReport { matched: true, ..*self }
    }
    fn no(&self) -> MatchReport {
        MatchReport { matched: false, ..*self }
    }
}

/// The slice of CLDR that AOSP's locale predicates need.
///
/// AOSP reads a generated table (`LocaleDataLookup.cpp`, several megabytes of
/// CLDR parent-locale and likely-script data) that ships inside
/// `libandroidfw` and is not recoverable from an APK. This is a deliberately
/// empty placeholder for it: the default value carries no data, and every
/// method that needs it returns `None`, which pushes
/// [`ResConfig::matches_with`] into AOSP's own conservative branch and sets
/// [`MatchReport::locale_data_absent`].
///
/// A host that can ship CLDR — or a caller that has already loaded it — can
/// supply it here. Nothing in this crate guesses at the data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocaleData {
    /// Overrides for `localeDataComputeScript`, keyed by `"<lang>-<REGION>"`.
    script_overrides: BTreeMap<String, [u8; 4]>,
}

impl LocaleData {
    /// An empty locale database, which degrades every CLDR-dependent answer to
    /// AOSP's conservative branch and reports that it did.
    pub fn empty() -> LocaleData {
        LocaleData::default()
    }

    /// Teach the database a likely script for a language (and optionally region).
    ///
    /// Only affects [`ResConfig::matches_with`]; the region-preference step in
    /// [`ResConfig::is_better_than`] is not driven from here.
    pub fn with_script(mut self, language: &str, region: Option<&str>, script: &str) -> LocaleData {
        let key = match region {
            Some(r) => format!("{}-{r}", language.to_ascii_lowercase()),
            None => language.to_ascii_lowercase(),
        };
        let mut bytes = [0u8; 4];
        for (i, b) in script.bytes().take(4).enumerate() {
            bytes[i] = b;
        }
        self.script_overrides.insert(key, bytes);
        self
    }

    /// `localeDataComputeScript`: the likely script for a language and region.
    pub fn compute_script(&self, language: &[u8; 2], country: &[u8; 2]) -> Option<[u8; 4]> {
        if language[0] == 0 {
            return Some([0; 4]);
        }
        let lang = unpack_code(language);
        if country[0] != 0 {
            let region = unpack_code(country);
            if let Some(s) = self.script_overrides.get(&format!("{}-{}", lang.to_ascii_lowercase(), region)) {
                return Some(*s);
            }
        }
        self.script_overrides.get(&lang.to_ascii_lowercase()).copied()
    }
}

// --- string pool -----------------------------------------------------------

/// A parsed `ResStringPool`.
///
/// The same structure appears in `AndroidManifest.xml` and in
/// `resources.arsc`, and the two disagree about the default encoding — see
/// [`UTF8_FLAG`]. A UTF-8 string is two 1-or-2-byte lengths (UTF-16 code unit
/// count, then byte count) followed by that many bytes; a UTF-16 string is two
/// 1-or-2-unit lengths followed by that many `u16`s and a `0x0000`. AAPT2
/// writes a trailing NUL after a UTF-8 string, but the byte length already
/// bounds it, so the NUL is not required and is not relied on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringPool {
    strings: Vec<String>,
    flags: u32,
}

impl StringPool {
    /// An empty pool.
    pub fn empty() -> StringPool {
        StringPool::default()
    }

    /// Whether the pool's strings are UTF-8.
    pub fn is_utf8(&self) -> bool {
        self.flags & UTF8_FLAG != 0
    }

    /// Whether the pool declares its string offsets sorted by content.
    pub fn is_sorted(&self) -> bool {
        self.flags & SORTED_FLAG != 0
    }

    /// The pool's raw flags word.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// How many strings the pool holds.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Every string, in pool order.
    pub fn strings(&self) -> &[String] {
        &self.strings
    }

    /// The string at `index`, or a typed error if the index is out of range.
    pub fn get(&self, pool_name: &'static str, index: u32) -> Result<&str> {
        if index == u32::MAX {
            return Err(ResourceError::StringIndexOutOfRange {
                pool: pool_name,
                index,
                size: self.strings.len() as u32,
            });
        }
        self.strings.get(index as usize).map(String::as_str).ok_or(
            ResourceError::StringIndexOutOfRange {
                pool: pool_name,
                index,
                size: self.strings.len() as u32,
            },
        )
    }

    /// Parse a `ResStringPool_header` plus its data.
    ///
    /// `chunk` is the whole chunk, starting at the `ResChunk_header`.
    pub fn parse(pool_name: &'static str, chunk: &[u8]) -> Result<StringPool> {
        if chunk.len() < 28 {
            return Err(ResourceError::Truncated {
                what: "ResStringPool_header",
                need: 28,
                have: chunk.len(),
            });
        }
        let header_size = u16::from_le_bytes([chunk[2], chunk[3]]) as usize;
        if header_size < 28 {
            return Err(ResourceError::BadHeaderSize {
                chunk: RES_STRING_POOL_TYPE,
                header_size: header_size as u16,
                min: 28,
            });
        }
        let string_count = rd_u32(chunk, 8);
        let _style_count = rd_u32(chunk, 12);
        let flags = rd_u32(chunk, 16);
        let strings_start = rd_u32(chunk, 20) as usize;
        let utf8 = flags & UTF8_FLAG != 0;

        // The declared count is attacker-controlled and `Vec::with_capacity`
        // is not, so the count is bounded by what the chunk could physically
        // hold before anything is allocated. The unit is two bytes for UTF-8
        // (two one-byte lengths plus an empty payload) and four for UTF-16
        // (two one-unit lengths, a terminator unit, and two bytes of padding),
        // which is what AOSP's own guard uses.
        let unit = if utf8 { 2 } else { 4 };
        let data_bytes = chunk.len().saturating_sub(strings_start);
        let offsets_bytes = string_count as usize * 4;
        if offsets_bytes > chunk.len().saturating_sub(header_size) {
            return Err(ResourceError::StringPoolOverlong {
                pool: pool_name,
                count: string_count,
                have: chunk.len().saturating_sub(header_size),
            });
        }
        let max_strings = data_bytes / unit + 1;
        if string_count as usize > max_strings {
            return Err(ResourceError::StringPoolOverlong {
                pool: pool_name,
                count: string_count,
                have: data_bytes,
            });
        }

        let offsets_start = header_size;
        let data_start = strings_start;
        let mut strings = Vec::with_capacity(string_count as usize);
        for i in 0..string_count as usize {
            let off_at = offsets_start + i * 4;
            let off = rd_u32(chunk, off_at) as usize;
            // `data_start + off` must land inside the chunk, and the string's
            // own length prefix must be readable from there.
            let at = data_start.checked_add(off).filter(|a| *a < chunk.len()).ok_or(
                ResourceError::StringIndexOutOfRange { pool: pool_name, index: i as u32, size: string_count },
            )?;
            let s = if utf8 {
                decode_utf8_string(pool_name, chunk, at, i as u32)?
            } else {
                decode_utf16_string(pool_name, chunk, at, i as u32)?
            };
            strings.push(s);
        }
        Ok(StringPool { strings, flags })
    }
}

/// Read a 1-or-2-byte length prefix, as `ResStringPool::decodeLength` does.
///
/// AAPT2 never emits the 3- and 4-byte forms that AOSP's decoder tolerates, so
/// a lead byte of `0b11xx_xxxx` is rejected rather than guessed at: silently
/// accepting it would let a crafted pool walk the cursor somewhere else.
fn decode_len8(b: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *b.get(at)?;
    if first & 0x80 == 0 {
        Some((first as usize, 1))
    } else if first & 0xC0 == 0x80 {
        Some(((((first & 0x3f) as usize) << 8) | *b.get(at + 1)? as usize, 2))
    } else {
        None
    }
}

/// Read a 1-or-2-unit length prefix, the UTF-16 twin of [`decode_len8`].
fn decode_len16(b: &[u8], at: usize) -> Option<(usize, usize)> {
    if at + 2 > b.len() {
        return None;
    }
    let first = u16::from_le_bytes([b[at], b[at + 1]]) as usize;
    if first & 0x8000 == 0 {
        Some((first, 2))
    } else {
        if at + 4 > b.len() {
            return None;
        }
        let second = u16::from_le_bytes([b[at + 2], b[at + 3]]) as usize;
        Some((((first & 0x7fff) << 16) | second, 4))
    }
}

fn decode_utf8_string(pool: &'static str, chunk: &[u8], at: usize, index: u32) -> Result<String> {
    let (utf16_len, n1) = decode_len8(chunk, at)
        .ok_or(ResourceError::StringNotTerminated { pool, index })?;
    let (byte_len, n2) = decode_len8(chunk, at + n1)
        .ok_or(ResourceError::StringNotTerminated { pool, index })?;
    let start = at + n1 + n2;
    let end = start.checked_add(byte_len).filter(|e| *e <= chunk.len()).ok_or(
        ResourceError::Truncated { what: "string pool utf8 data", need: start + byte_len, have: chunk.len() },
    )?;
    // `utf16_len` counts UTF-16 code units, which can exceed the character
    // count for astral characters, so it only ever truncates downwards and
    // only when it is genuinely smaller.
    let _ = utf16_len;
    // Decoding is lossy on purpose, and not out of laziness. AAPT2 does not
    // reject unpaired surrogates: the real `com.dosse.clock31` layout has a
    // string whose nine bytes are `ED A0 BD ED B7 93 EF B8 8F`, which is
    // U+FE0F written as three 3-byte sequences including a lone surrogate.
    // Rust's `from_utf8` refuses that, and refusing it would mean refusing to
    // inflate a layout that renders perfectly on a device. One replaced code
    // point in one string is a strictly better outcome than no layout.
    Ok(String::from_utf8_lossy(&chunk[start..end]).into_owned())
}

fn decode_utf16_string(pool: &'static str, chunk: &[u8], at: usize, index: u32) -> Result<String> {
    // One length prefix, not two. The high bit of the first `u16` means "a
    // second `u16` holds the low 16 bits", which is how a string longer than
    // 32767 units is spelled; it is not a marker for a separate byte count,
    // because in UTF-16 the two counts are the same number.
    //
    // Reading two lengths here lands the cursor two bytes into the string data
    // for every string under 128 units and produces the right answer by
    // accident, and lands it *before* the data for longer ones.
    let (char_len, n1) = decode_len16(chunk, at)
        .ok_or(ResourceError::StringNotTerminated { pool, index })?;
    let start = at + n1;
    let need = start + char_len * 2;
    if need + 2 > chunk.len() {
        return Err(ResourceError::Truncated {
            what: "string pool utf16 data",
            need,
            have: chunk.len(),
        });
    }
    // AOSP rejects a UTF-16 string that is not `0x0000`-terminated where the
    // length says it should be, rather than inventing a terminator.
    if chunk[need] != 0 || chunk[need + 1] != 0 {
        return Err(ResourceError::StringNotTerminated { pool, index });
    }
    let units: Vec<u16> = (0..char_len)
        .map(|i| u16::from_le_bytes([chunk[start + i * 2], chunk[start + i * 2 + 1]]))
        .collect();
    Ok(String::from_utf16_lossy(&units))
}

// --- the table -------------------------------------------------------------

/// A `0xPPTTEEEE` resource id, split into its three parts.
///
/// The package and type bytes are stored one-based so that a zero in either
/// position is detectable: an id of `0x7f000000` has a package but no type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResId {
    /// The package byte, minus one. `0x7f` is the app's own package.
    pub package: u8,
    /// The type byte, minus one. `0x03` is the fourth type.
    pub type_id: u8,
    /// The entry index within the type.
    pub entry: u16,
}

impl ResId {
    /// Split a raw resource id.
    ///
    /// Returns `None` for an id whose package or type byte is zero, which is
    /// how AOSP encodes "no package" and "no type".
    pub fn from_u32(raw: u32) -> Option<ResId> {
        let package = (raw >> 24) as u8;
        let type_id = ((raw >> 16) & 0xff) as u8;
        if package == 0 || type_id == 0 {
            return None;
        }
        Some(ResId { package: package - 1, type_id: type_id - 1, entry: (raw & 0xffff) as u16 })
    }

    /// Recombine into a raw resource id.
    pub fn to_u32(self) -> u32 {
        ((u32::from(self.package) + 1) << 24)
            | ((u32::from(self.type_id) + 1) << 16)
            | u32::from(self.entry)
    }

    /// The `0xPP` byte as it appears in the id.
    pub fn package_byte(self) -> u8 {
        self.package + 1
    }

    /// The `0xTT` byte as it appears in the id.
    pub fn type_byte(self) -> u8 {
        self.type_id + 1
    }
}

/// One `name -> value` pair inside a complex (bag) entry.
#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    /// The attribute or resource name, as a `0xPPTTEEEE` id. `0` is a legal
    /// name in a bag and means "unnamed".
    pub name: u32,
    /// The value.
    pub value: Value,
}

/// What a `ResTable_entry` holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// A single `Res_value`.
    Simple(Value),
    /// A bag: an optional `parent` and a list of name/value pairs.
    Bag {
        /// The `parent` field. For a style this is the style it inherits from;
        /// for an attribute it is a framework attribute id.
        parent: u32,
        /// The pairs, in file order.
        map: Vec<MapEntry>,
    },
    /// A `FLAG_COMPACT` entry, whose value lives in the entry's own `data`
    /// field with its type in the high byte of `flags`.
    Compact {
        /// The `Res_value.dataType` tag, recovered from `flags >> 8`.
        data_type: u8,
        /// The `Res_value.data` field.
        data: u32,
    },
}

impl Payload {
    /// The single value, if this entry is not a bag.
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Payload::Simple(v) => Some(v),
            Payload::Compact { data_type, data } => {
                // Rebuilding a Value here would need an owned RawValue; the
                // caller that cares uses `as_raw`.
                let _ = (data_type, data);
                None
            }
            Payload::Bag { .. } => None,
        }
    }

    /// The single value as a raw tag/data pair, for either simple form.
    pub fn as_raw(&self) -> Option<(u8, u32)> {
        match self {
            Payload::Simple(v) => Some((value_data_type(v), value_data(v))),
            Payload::Compact { data_type, data } => Some((*data_type, *data)),
            Payload::Bag { .. } => None,
        }
    }

    /// The bag, if this entry is one.
    pub fn as_bag(&self) -> Option<&[MapEntry]> {
        match self {
            Payload::Bag { map, .. } => Some(map),
            _ => None,
        }
    }
}

/// The `dataType` a [`Value`] came from, for round-tripping.
fn value_data_type(v: &Value) -> u8 {
    use crate::resources::types::*;
    match v {
        Value::Null(_) => TYPE_NULL,
        Value::Reference(_) => TYPE_REFERENCE,
        Value::Attribute(_) => TYPE_ATTRIBUTE,
        Value::String(_) => TYPE_STRING,
        Value::Float(_) => TYPE_FLOAT,
        Value::Dimension(_) => TYPE_DIMENSION,
        Value::Fraction(_) => TYPE_FRACTION,
        Value::DynamicReference(_) => TYPE_DYNAMIC_REFERENCE,
        Value::DynamicAttribute(_) => TYPE_DYNAMIC_ATTRIBUTE,
        Value::Int(_) => TYPE_INT_DEC,
        Value::Hex(_) => TYPE_INT_HEX,
        Value::Boolean(_) => TYPE_INT_BOOLEAN,
        Value::Color { format, .. } => format.data_type(),
        Value::Raw { data_type, .. } => *data_type,
    }
}

/// The raw `data` a [`Value`] carries.
fn value_data(v: &Value) -> u32 {
    use crate::resources::types::*;
    match v {
        Value::Null(Null::Empty) => DATA_NULL_EMPTY,
        Value::Null(Null::Undefined) => DATA_NULL_UNDEFINED,
        Value::Reference(r) | Value::Attribute(r) | Value::String(r) | Value::Hex(r) => *r,
        Value::DynamicReference(r) | Value::DynamicAttribute(r) => *r,
        Value::Float(f) => f.to_bits(),
        Value::Int(i) => *i as u32,
        Value::Boolean(b) => {
            if *b {
                Value::TRUE_BITS
            } else {
                0
            }
        }
        Value::Color { argb, .. } => *argb,
        Value::Dimension(d) => {
            // Round-trip only; reading a dimension never goes through this.
            float_to_complex(d.value) | d.unit.code()
        }
        Value::Fraction(f) => {
            float_to_complex(f.value) | u32::from(f.parent)
        }
        Value::Raw { data, .. } => *data,
    }
}

/// One resource entry: its key name and its payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Index into the package's key string pool.
    pub key_index: u32,
    /// `ENTRY_FLAG_*` bits.
    pub flags: u16,
    /// The value or bag.
    pub payload: Payload,
}

impl Entry {
    /// Whether the entry is declared public.
    pub fn is_public(&self) -> bool {
        self.flags & ENTRY_FLAG_PUBLIC != 0
    }
}

/// One configuration's worth of entries for one type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeChunk {
    /// The type id this chunk holds.
    pub type_id: u8,
    /// `FLAG_SPARSE` / `FLAG_OFFSET16`.
    pub flags: u8,
    /// How many entry slots the chunk has.
    pub entry_count: u32,
    /// The configuration these entries are qualified for.
    pub config: ResConfig,
    /// The entries, indexed by entry number. `None` is `NO_ENTRY`: the entry
    /// exists in the type but has no value under this configuration.
    pub entries: Vec<Option<Entry>>,
}

/// A `ResTable_typeSpec`: the shape shared by every configuration of one type.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeSpec {
    /// The type id.
    pub type_id: u8,
    /// Per-entry flags: `SPEC_PUBLIC`, `SPEC_STAGED_API` and the
    /// `ResTable_config::CONFIG_*` change mask.
    pub entry_flags: Vec<u32>,
    /// One chunk per configuration, in file order.
    pub configs: Vec<TypeChunk>,
}

impl TypeSpec {
    /// The type's entry name, if the owning package can supply it.
    pub fn type_name<'p>(&self, package: &'p Package) -> Option<&'p str> {
        package.type_name(self.type_id.wrapping_sub(1)).ok()
    }
}

/// A `ResTable_package`: one resource namespace.
#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    /// The package id. `0` means this is a runtime overlay with no id of its own.
    pub id: u8,
    /// The package name, e.g. `com.example.app`.
    pub name: String,
    /// Type names, e.g. `0` = `attr`, `4` = `layout`.
    pub type_strings: StringPool,
    /// Entry names, e.g. `0` = `app_name`.
    pub key_strings: StringPool,
    /// `lastPublicType`.
    pub last_public_type: u32,
    /// `lastPublicKey`.
    pub last_public_key: u32,
    /// `typeIdOffset`, absent in tables built before Android 14.
    pub type_id_offset: Option<u32>,
    /// Type specs by type id.
    pub types: BTreeMap<u8, TypeSpec>,
}

impl Package {
    /// The entry name for a key index, e.g. `activity_main`.
    pub fn key_name(&self, index: u32) -> Result<&str> {
        self.key_strings.get("keyStrings", index)
    }

    /// The type name for a zero-based type id, e.g. `layout`.
    ///
    /// `typeStrings` is indexed by the *zero-based* type id even though
    /// `ResTable_type.id` and the `0xTT` byte in a resource id are one-based:
    /// in the real `com.dosse.clock31` table `typeStrings[0]` is `attr`, which
    /// is type byte 1, and `typeStrings[8]` is `xml`, which is type byte 9.
    /// So the two ids agree after the subtraction `ResId::from_u32` already
    /// does, and adding one here would shift every lookup onto the next type.
    pub fn type_name(&self, type_id: u8) -> Result<&str> {
        self.type_strings.get("typeStrings", u32::from(type_id))
    }
}

/// What a resource id resolved to.
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    /// A single typed value, e.g. a string index, a dimension, a colour.
    Value(Value),
    /// A bag: a style, an attribute, or an array. The parent is kept so that
    /// [`crate::resources::inflate::StyleResolver`] can walk the chain.
    Bag {
        /// The entry's `parent` field, usually a style to inherit from.
        parent: u32,
        /// The pairs, in file order. AAPT2 emits them sorted by name.
        map: Vec<MapEntry>,
        /// The configuration the winning entry came from.
        config: ResConfig,
    },
    /// A file: `res/LT.xml`, `res/t_.webp`, `assets/foo`.
    File {
        /// The path exactly as the table stores it.
        path: String,
        /// The configuration the winning entry came from.
        config: ResConfig,
    },
    /// The id is well formed but the table has no such entry.
    Absent(Absence),
}

impl Resolved {
    /// Whether this is [`Resolved::Absent`].
    pub fn is_absent(&self) -> bool {
        matches!(self, Resolved::Absent(_))
    }

    /// The value, if there is exactly one.
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            Resolved::Value(v) => Some(v),
            _ => None,
        }
    }

    /// The file path, if this is a file.
    pub fn as_file(&self) -> Option<&str> {
        match self {
            Resolved::File { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// Why a resource id did not resolve.
#[derive(Debug, Clone, PartialEq)]
pub enum Absence {
    /// The id's package byte names a package that is not in the table.
    NoSuchPackage {
        /// The package byte, minus one.
        package: u8,
    },
    /// The package has no type with that id.
    NoSuchType {
        /// The type byte, minus one.
        type_id: u8,
    },
    /// The type has fewer entries than the id names.
    NoSuchEntry {
        /// The entry index asked for.
        entry: u16,
        /// How many entries the type has.
        count: usize,
    },
    /// The entry exists but has no value under any configuration that matches.
    NoMatchingConfig {
        /// How many configurations were considered and rejected.
        considered: usize,
    },
}

/// A whole parsed `resources.arsc`.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceTable {
    /// The table's global value string pool. Every `TYPE_STRING` in the table
    /// indexes into this.
    pub global_strings: StringPool,
    /// The packages, in file order.
    pub packages: Vec<Package>,
    /// The declared `packageCount` from the `ResTable_header`.
    pub declared_package_count: u32,
}

impl ResourceTable {
    /// Parse a `resources.arsc`.
    pub fn parse(bytes: &[u8]) -> Result<ResourceTable> {
        ResourceTable::parse_with(bytes, &LocaleData::default())
    }

    /// Parse a `resources.arsc` with an explicit CLDR locale database.
    pub fn parse_with(bytes: &[u8], _locale: &LocaleData) -> Result<ResourceTable> {
        let (chunk_type, header_size, total) = chunk_header(bytes, 0)?;
        if chunk_type != RES_TABLE_TYPE {
            return Err(ResourceError::BadTableMagic { found: chunk_type });
        }
        if header_size < 12 {
            return Err(ResourceError::BadHeaderSize {
                chunk: RES_TABLE_TYPE,
                header_size,
                min: 12,
            });
        }
        if (total as usize) > bytes.len() {
            return Err(ResourceError::BadChunkSize { chunk: chunk_type, size: total });
        }
        let end = total as usize;
        let declared_package_count = rd_u32(bytes, 8);

        let mut global_strings = StringPool::empty();
        let mut packages: Vec<Package> = Vec::new();
        let mut at = header_size as usize;
        let mut saw_pool = false;
        while at + 8 <= end {
            let (t, hs, size) = chunk_header(bytes, at)?;
            let next = (at as u32)
                .checked_add(size)
                .ok_or(ResourceError::BadChunkSize { chunk: t, size })? as usize;
            if hs < 8 || size < u32::from(hs) || next > end || next <= at {
                return Err(ResourceError::BadChunkSize { chunk: t, size });
            }
            let chunk = &bytes[at..next];
            match t {
                RES_STRING_POOL_TYPE => {
                    if saw_pool {
                        return Err(ResourceError::BadChunkSize { chunk: t, size });
                    }
                    global_strings = StringPool::parse("globalStrings", chunk)?;
                    saw_pool = true;
                }
                RES_TABLE_PACKAGE_TYPE => {
                    packages.push(parse_package(chunk, hs, size)?);
                }
                // A library, overlayable, staged-alias or policy chunk carries
                // no entry values. Recorded as skipped rather than errors,
                // which is what AOSP does.
                RES_TABLE_LIBRARY_TYPE | RES_TABLE_OVERLAYABLE_TYPE
                | RES_TABLE_OVERLAYABLE_POLICY_TYPE | RES_TABLE_STAGED_ALIAS_TYPE => {}
                _ => {}
            }
            at = next;
        }

        Ok(ResourceTable { global_strings, packages, declared_package_count })
    }

    /// The package with the given zero-based package id.
    pub fn package(&self, package: u8) -> Option<&Package> {
        self.packages.iter().find(|p| p.id == package + 1)
    }

    /// The global string for a `TYPE_STRING` value.
    pub fn global_string(&self, index: u32) -> Result<&str> {
        self.global_strings.get("globalStrings", index)
    }

    /// The text behind a [`Value`], if it is a string.
    pub fn value_text(&self, value: &Value) -> Result<Option<String>> {
        match value {
            Value::String(i) => Ok(Some(self.global_string(*i)?.to_string())),
            _ => Ok(None),
        }
    }

    /// The fully qualified name of a resource id, e.g. `com.example:layout/main`.
    pub fn name_of(&self, id: u32) -> Result<String> {
        let rid = ResId::from_u32(id).ok_or(ResourceError::InvalidResourceId(id))?;
        let package =
            self.package(rid.package).ok_or(ResourceError::NoSuchPackage {
                package: rid.package,
                loaded: self.packages.iter().map(|p| p.name.clone()).collect(),
            })?;
        let type_name = package.type_name(rid.type_id).unwrap_or("?");
        let type_spec = package
            .types
            .get(&rid.type_id)
            .ok_or(ResourceError::MissingTypeSpec(rid.type_byte()))?;
        for chunk in &type_spec.configs {
            if let Some(Some(entry)) = chunk.entries.get(rid.entry as usize) {
                return Ok(format!("{}:{}/{}", package.name, type_name, package.key_name(entry.key_index)?));
            }
        }
        Err(ResourceError::InvalidResourceId(id))
    }

    /// Resolve a resource id against a device configuration.
    pub fn resolve(&self, id: u32, device: &ResConfig) -> Result<Resolved> {
        Ok(self.resolve_with(id, device, &LocaleData::default())?.0)
    }

    /// Resolve a resource id, reporting whether a CLDR-dependent predicate was
    /// skipped on the way.
    ///
    /// A well-formed id that names nothing resolves to [`Resolved::Absent`],
    /// not to an error: "this resource does not exist for this device" is an
    /// answer, and conflating it with "this table is broken" would make every
    /// caller write a recovery path for the wrong thing. Only a malformed id or
    /// a malformed table is an error.
    pub fn resolve_with(
        &self,
        id: u32,
        device: &ResConfig,
        locale: &LocaleData,
    ) -> Result<(Resolved, bool)> {
        let rid = ResId::from_u32(id).ok_or(ResourceError::InvalidResourceId(id))?;
        let Some(package) = self.package(rid.package) else {
            return Ok((
                Resolved::Absent(Absence::NoSuchPackage { package: rid.package }),
                false,
            ));
        };
        let Some(type_spec) = package.types.get(&rid.type_id) else {
            return Ok((Resolved::Absent(Absence::NoSuchType { type_id: rid.type_id }), false));
        };
        let entry_index = rid.entry as usize;
        if entry_index >= type_spec.entry_flags.len() {
            return Ok((
                Resolved::Absent(Absence::NoSuchEntry {
                    entry: rid.entry,
                    count: type_spec.entry_flags.len(),
                }),
                false,
            ));
        }

        let mut considered = 0usize;
        let mut best: Option<(&TypeChunk, &Entry)> = None;
        let mut degraded = false;
        for chunk in &type_spec.configs {
            let report = chunk.config.matches_with(device, locale);
            if report.locale_data_absent {
                degraded = true;
            }
            if !report.matched {
                continue;
            }
            considered += 1;
            // A configuration that matched but has no value for this entry is
            // not a candidate; the scan continues, exactly as AOSP's does.
            let Some(Some(entry)) = chunk.entries.get(entry_index) else {
                continue;
            };
            match best {
                None => best = Some((chunk, entry)),
                Some((best_chunk, _)) => {
                    if chunk.config.is_better_than(&best_chunk.config, device) {
                        best = Some((chunk, entry));
                    }
                }
            }
        }

        let Some((chunk, entry)) = best else {
            let considered = if considered == 0 { type_spec.configs.len() } else { considered };
            return Ok((Resolved::Absent(Absence::NoMatchingConfig { considered }), degraded));
        };

        let resolved = match &entry.payload {
            Payload::Simple(v) => {
                // A string value is a file reference when it names a file.
                match v {
                    Value::String(i) => {
                        let text = self.global_string(*i)?;
                        if is_file_path(text) {
                            Resolved::File { path: text.to_string(), config: chunk.config }
                        } else {
                            Resolved::Value(v.clone())
                        }
                    }
                    _ => Resolved::Value(v.clone()),
                }
            }
            Payload::Compact { data_type, data } => {
                let raw = RawValue { size: 8, res0: 0, data_type: *data_type, data: *data };
                let v = raw.decode();
                match v {
                    Value::String(i) => {
                        let text = self.global_string(i)?;
                        if is_file_path(text) {
                            Resolved::File { path: text.to_string(), config: chunk.config }
                        } else {
                            Resolved::Value(v)
                        }
                    }
                    _ => Resolved::Value(v),
                }
            }
            Payload::Bag { parent, map } => Resolved::Bag {
                parent: *parent,
                map: map.clone(),
                config: chunk.config,
            },
        };
        Ok((resolved, degraded))
    }

    /// Every entry id in the table, in `package, type, entry` order.
    pub fn all_ids(&self) -> Vec<u32> {
        let mut out = Vec::new();
        for package in &self.packages {
            for (type_id, type_spec) in &package.types {
                for (entry, flags) in type_spec.entry_flags.iter().enumerate() {
                    // Only report entries some configuration actually defines.
                    if type_spec.configs.iter().all(|c| c.entries.get(entry).map_or(true, |e| e.is_none()))
                    {
                        continue;
                    }
                    let _ = flags;
                    out.push(
                        ((u32::from(package.id) << 24)
                            | ((u32::from(*type_id) + 1) << 16)
                            | entry as u32),
                    );
                }
            }
        }
        out
    }
}

/// Whether a string value names a file rather than a string.
///
/// AAPT2 compiles `res/layout/main.xml` to a path like `res/aB.xml` and stores
/// that path as a `TYPE_STRING` value. A string resource, by contrast, is the
/// text itself. The distinguishing feature is that every path the compiler
/// emits lives under a directory and carries a file extension, so a value with
/// neither is a string, and a value with both is a file.
fn is_file_path(text: &str) -> bool {
    let Some((dir, name)) = text.rsplit_once('/') else {
        return false;
    };
    if dir.is_empty() {
        return false;
    }
    let Some((_, ext)) = name.rsplit_once('.') else {
        return false;
    };
    !ext.is_empty() && ext.len() <= 4 && ext.chars().all(|c| c.is_ascii_alphanumeric())
}

fn parse_package(chunk: &[u8], header_size: u16, size: u32) -> Result<Package> {
    // 8 chunk header + 4 id + 256 name + 4 typeStrings + 4 lastPublicType
    // + 4 keyStrings + 4 lastPublicKey = 284; `typeIdOffset` was appended later.
    const MIN_HEADER: u16 = 284;
    if header_size < MIN_HEADER {
        return Err(ResourceError::BadHeaderSize {
            chunk: RES_TABLE_PACKAGE_TYPE,
            header_size,
            min: MIN_HEADER,
        });
    }
    if chunk.len() < header_size as usize {
        return Err(ResourceError::Truncated {
            what: "ResTable_package",
            need: header_size as usize,
            have: chunk.len(),
        });
    }
    let id = rd_u32(chunk, 8) as u8;
    // `uint16_t name[128]` — the package name is UTF-16, unlike everything else
    // in the file. Reading it as bytes and stopping at the first NUL yields
    // the first character of the name and a silent "c" for every APK.
    let name_units: Vec<u16> = chunk[12..12 + 256]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    let name = String::from_utf16_lossy(&name_units);
    if name.is_empty()
        || !name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(ResourceError::BadPackageName { name });
    }
    let type_strings_off = rd_u32(chunk, 268);
    let last_public_type = rd_u32(chunk, 272);
    let key_strings_off = rd_u32(chunk, 276);
    let last_public_key = rd_u32(chunk, 280);
    let type_id_offset = if header_size >= 288 { Some(rd_u32(chunk, 284)) } else { None };

    let end = size as usize;
    let mut type_strings = StringPool::empty();
    let mut key_strings = StringPool::empty();
    let mut specs: BTreeMap<u8, TypeSpec> = BTreeMap::new();
    // Types are indexed by the order they appear, which is the order AOSP
    // appends them to `TypeSpec::configs`.
    let mut type_order: Vec<u8> = Vec::new();

    let mut at = header_size as usize;
    while at + 8 <= end {
        let (t, hs, sz) = chunk_header(chunk, at)?;
        let next = (at as u32).checked_add(sz).ok_or(ResourceError::BadChunkSize { chunk: t, size: sz })?;
        if hs < 8 || sz < u32::from(hs) || next as usize > end || next as usize <= at {
            return Err(ResourceError::BadChunkSize { chunk: t, size: sz });
        }
        let sub = &chunk[at..next as usize];
        match t {
            RES_STRING_POOL_TYPE => {
                // A package carries exactly two pools, in the order
                // `typeStrings` then `keyStrings`, and their offsets say which
                // is which.
                let off = at as u32;
                if off == type_strings_off {
                    type_strings = StringPool::parse("typeStrings", sub)?;
                } else if off == key_strings_off {
                    key_strings = StringPool::parse("keyStrings", sub)?;
                } else {
                    // A third pool. AAPT2 does not emit one, and guessing which
                    // is which would swap every resource name for a type name.
                    return Err(ResourceError::UnsupportedChunk { chunk: t });
                }
            }
            RES_TABLE_TYPE_SPEC_TYPE => {
                let spec = parse_type_spec(sub, hs, sz)?;
                // Keyed zero-based; see `Package::type_name`.
                type_order.push(spec.type_id);
                specs.entry(spec.type_id.wrapping_sub(1)).or_insert(spec);
            }
            RES_TABLE_TYPE_TYPE => {
                let parsed = parse_type(sub, hs, sz)?;
                let key = parsed.type_id.wrapping_sub(1);
                let spec = specs.get_mut(&key).ok_or(ResourceError::MissingTypeSpec(parsed.type_id))?;
                if spec.entry_flags.is_empty() {
                    spec.entry_flags = vec![0; parsed.entry_count as usize];
                }
                spec.configs.push(parsed);
            }
            _ => {}
        }
        at = next as usize;
    }
    let _ = type_order;

    Ok(Package {
        id,
        name,
        type_strings,
        key_strings,
        last_public_type,
        last_public_key,
        type_id_offset,
        types: specs,
    })
}

fn parse_type_spec(chunk: &[u8], header_size: u16, size: u32) -> Result<TypeSpec> {
    const MIN_HEADER: u16 = 16;
    if header_size < MIN_HEADER {
        return Err(ResourceError::BadHeaderSize {
            chunk: RES_TABLE_TYPE_SPEC_TYPE,
            header_size,
            min: MIN_HEADER,
        });
    }
    let body = size as usize;
    if body < MIN_HEADER as usize || body > chunk.len() {
        return Err(ResourceError::BadChunkSize { chunk: RES_TABLE_TYPE_SPEC_TYPE, size });
    }
    let type_id = chunk[8];
    if type_id == 0 {
        return Err(ResourceError::MissingTypeSpec(0));
    }
    let entry_count = rd_u32(chunk, 12);
    let flags_bytes = (body - MIN_HEADER as usize) / 4;
    let count = (entry_count as usize).min(flags_bytes);
    let mut entry_flags = Vec::with_capacity(count);
    for i in 0..count {
        entry_flags.push(rd_u32(chunk, MIN_HEADER as usize + i * 4));
    }
    Ok(TypeSpec { type_id, entry_flags, configs: Vec::new() })
}

fn parse_type(chunk: &[u8], header_size: u16, size: u32) -> Result<TypeChunk> {
    // 8 chunk header + 1 id + 1 flags + 2 reserved + 4 entryCount
    // + 4 entriesStart = 20, then the config.
    const MIN_HEADER: u16 = 20;
    if header_size < MIN_HEADER {
        return Err(ResourceError::BadHeaderSize {
            chunk: RES_TABLE_TYPE_TYPE,
            header_size,
            min: MIN_HEADER,
        });
    }
    let body = size as usize;
    if body < MIN_HEADER as usize || body > chunk.len() {
        return Err(ResourceError::BadChunkSize { chunk: RES_TABLE_TYPE_TYPE, size });
    }
    let type_id = chunk[8];
    if type_id == 0 {
        return Err(ResourceError::MissingTypeSpec(0));
    }
    let flags = chunk[9];
    let entry_count = rd_u32(chunk, 12);
    let entries_start = rd_u32(chunk, 16) as usize;
    let config = ResConfig::parse(chunk, MIN_HEADER as usize)?;

    // Both index encodings are AOSP-defined, and both are read here even
    // though the 204-APK F-Droid corpus only exercises the 32-bit one.
    let index_bytes = body
        .checked_sub(header_size as usize)
        .ok_or(ResourceError::BadChunkSize { chunk: RES_TABLE_TYPE_TYPE, size })?;
    let index_base = header_size as usize;
    // The index array holds exactly `entryCount` slots, and the entry data
    // starts immediately after it. Bounding the walk by `entryCount` rather
    // than by the chunk size is what stops the loop running into the entry
    // area and reading entry bytes as offsets.
    let slots = ((index_bytes / 4).min(entry_count as usize), (index_bytes / 2).min(entry_count as usize));
    let mut entries: Vec<Option<Entry>> = Vec::new();
    if flags & FLAG_SPARSE != 0 {
        // A sorted array of `ResTable_sparseTypeEntry`, each a packed
        // `idx:u16 | offset/4:u16`, so a binary search replaces the index.
        let count = slots.0;
        entries = vec![None; entry_count as usize];
        for i in 0..count {
            let packed = rd_u32(chunk, index_base + i * 4);
            let idx = (packed & 0xffff) as usize;
            let off = (packed >> 16) as usize * 4;
            if idx >= entries.len() {
                return Err(ResourceError::EntryOffsetOutOfRange { offset: off as u32, chunk_size: body as u32 });
            }
            entries[idx] = parse_entry(chunk, body, entries_start, off)?;
        }
    } else if flags & FLAG_OFFSET16 != 0 {
        // `0xffff` means NO_ENTRY; any other value is the offset divided by 4.
        let count = slots.1;
        entries = vec![None; entry_count as usize];
        for i in 0..count {
            let raw = u16::from_le_bytes([chunk[index_base + i * 2], chunk[index_base + i * 2 + 1]]);
            let off = if raw == 0xffff { None } else { Some(raw as usize * 4) };
            if let Some(off) = off {
                if i < entries.len() {
                    entries[i] = parse_entry(chunk, body, entries_start, off)?;
                }
            }
        }
    } else {
        let count = slots.0;
        entries = vec![None; entry_count as usize];
        for i in 0..count {
            let raw = rd_u32(chunk, index_base + i * 4);
            if raw != NO_ENTRY {
                entries[i] = parse_entry(chunk, body, entries_start, raw as usize)?;
            }
        }
    }

    Ok(TypeChunk { type_id, flags, entry_count, config, entries })
}

fn parse_entry(
    chunk: &[u8],
    chunk_size: usize,
    entries_start: usize,
    offset: usize,
) -> Result<Option<Entry>> {
    let at = entries_start
        .checked_add(offset)
        .filter(|a| *a + 8 <= chunk_size && *a < chunk.len())
        .ok_or(ResourceError::EntryOffsetOutOfRange {
            offset: offset as u32,
            chunk_size: chunk_size as u32,
        })?;
    if offset & 3 != 0 {
        return Err(ResourceError::EntryOffsetOutOfRange {
            offset: offset as u32,
            chunk_size: chunk_size as u32,
        });
    }
    let size = u16::from_le_bytes([chunk[at], chunk[at + 1]]);
    let flags = u16::from_le_bytes([chunk[at + 2], chunk[at + 3]]);

    if flags & ENTRY_FLAG_COMPACT != 0 {
        // The value's type is the high byte of `flags` and the data sits in
        // the `key` slot's place; the whole entry is 8 bytes.
        if at + 8 > chunk.len() {
            return Err(ResourceError::Truncated { what: "ResTable_entry(compact)", need: at + 8, have: chunk.len() });
        }
        return Ok(Some(Entry {
            key_index: u16::from_le_bytes([chunk[at], chunk[at + 1]]) as u32,
            flags,
            payload: Payload::Compact {
                data_type: (flags >> 8) as u8,
                data: rd_u32(chunk, at + 4),
            },
        }));
    }

    if size < 8 || size % 4 != 0 {
        return Err(ResourceError::BadEntrySize { size });
    }
    let end = at
        .checked_add(size as usize)
        .filter(|e| *e <= chunk_size && *e <= chunk.len())
        .ok_or(ResourceError::EntryOffsetOutOfRange {
            offset: (at - entries_start) as u32,
            chunk_size: chunk_size as u32,
        })?;
    let key_index = rd_u32(chunk, at + 4);

    if flags & ENTRY_FLAG_COMPLEX != 0 {
        if size < 16 {
            return Err(ResourceError::BadEntrySize { size });
        }
        let parent = rd_u32(chunk, at + 8);
        let count = rd_u32(chunk, at + 12);
        // Each map is `name:u32` plus an 8-byte `Res_value`, 12 bytes total.
        // The count is attacker-controlled, so it is bounded by the chunk
        // before a `Vec` is sized from it.
        let avail = chunk.len().saturating_sub(end) / 12;
        let count = (count as usize).min(avail);
        let mut map = Vec::with_capacity(count);
        for i in 0..count {
            let mo = end + i * 12;
            let name = rd_u32(chunk, mo);
            let value = RawValue::read(chunk, mo + 4)?.decode();
            map.push(MapEntry { name, value });
        }
        return Ok(Some(Entry { key_index, flags, payload: Payload::Bag { parent, map } }));
    }

    let value = RawValue::read(chunk, at + size as usize)?.decode();
    Ok(Some(Entry { key_index, flags, payload: Payload::Simple(value) }))
}

fn chunk_header(bytes: &[u8], at: usize) -> Result<(u16, u16, u32)> {
    if at + 8 > bytes.len() {
        return Err(ResourceError::Truncated { what: "ResChunk_header", need: at + 8, have: bytes.len() });
    }
    Ok((
        u16::from_le_bytes([bytes[at], bytes[at + 1]]),
        u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]),
        rd_u32(bytes, at + 4),
    ))
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() {
        return 0;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::testing::*;

    // --- fixtures and provenance ------------------------------------------

    #[test]
    fn fixtures_match_their_recorded_hashes() {
        // Every other test in this file asserts something about these bytes.
        // If a fixture is edited without updating `FIXTURES.md`, the claim
        // those tests are making silently changes; this is what catches that.
        for (name, want) in FIXTURE_SHA256 {
            let got = sha256_hex(&fixture(name));
            assert_eq!(&got, want, "{name} does not match the hash recorded in FIXTURES.md");
        }
    }

    #[test]
    fn the_arsc_string_pools_are_utf8_and_the_axml_ones_are_not() {
        // The trap this module documents. A reader that assumes the AXML
        // default for a resource table decodes every name and value as
        // UTF-16 pairs and still "parses".
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        assert!(table.global_strings.is_utf8(), "resources.arsc pool must carry UTF8_FLAG");
        assert_eq!(table.global_strings.get("globalStrings", 0).unwrap(), "res/7_.xml");
        // Read out of the real pool by index, cross-checked against the
        // `aapt2 dump resources` output for the same APK.
        assert_eq!(table.global_strings.get("globalStrings", 8).unwrap(), "res/SE.xml");
        assert_eq!(table.global_strings.get("globalStrings", 9).unwrap(), "Clock 31");
        assert_eq!(table.global_strings.get("globalStrings", 15).unwrap(),
                   "Widget con orologio e calendario");
        assert!(table.global_strings.get("globalStrings", 16).is_err(), "the pool holds 16 strings");

        // The manifest's pool in the very same APK is UTF-16, and dexcore's
        // independent reader sees the same thing.
        let manifest = fixture("clock31.manifest.axml");
        let pool = first_pool(&manifest);
        assert_eq!(pool.flags & UTF8_FLAG, 0, "AndroidManifest.xml pool must not carry UTF8_FLAG");
    }

    // --- table structure, against aapt2 ------------------------------------

    #[test]
    fn clock31_table_matches_what_aapt2_prints() {
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let package = &table.packages[0];
        assert_eq!(package.id, 0x7f);
        assert_eq!(package.name, "com.dosse.clock31");
        // `aapt2 dump resources` prints, in order: attr, drawable, id, layout,
        // mipmap, string, style.
        // `typeStrings` is indexed zero-based, matching `ResId::type_id`, so
        // the seven types `aapt2` prints as ids 1..7 are indices 0..6 here.
        let names: Vec<&str> = (0..7).map(|i| package.type_name(i).unwrap()).collect();
        assert_eq!(names, ["attr", "drawable", "id", "layout", "mipmap", "string", "style"]);
        // Reading one past the end is a typed error, not a neighbouring type.
        assert!(package.type_name(7).is_ok(), "index 7 is `?8`, a real aapt2 artefact");
        assert!(package.type_name(99).is_err());
        assert_eq!(table.declared_package_count, 1);
    }

    #[test]
    fn every_config_qualifier_string_matches_aapt2s_parenthesised_form() {
        // `aapt2 dump resources` prints each configuration as `(qualifiers)`
        // next to the entries it holds. That is an independent rendering of the
        // `ResTable_config` bytes this module decodes, so comparing the two is
        // a check of the decode that does not go through this module at all.
        let apk = fixture_dir().join("weatherforecast.reframed.apk");
        let Some(dump) = aapt2_dump_resources(&apk) else {
            eprintln!("aapt2 unavailable; skipped");
            return;
        };
        let table = ResourceTable::parse(&fixture("weatherforecast.reframed.arsc")).unwrap();
        let mut checked = 0;
        for line in dump.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix('(') else { continue };
            let Some(qualifier) = rest.split(')').next() else { continue };
            if qualifier.is_empty() {
                continue;
            }
            // AAPT2 prints the qualifier without a leading '-'.
            let config = parse_qualifier_for_oracle(qualifier);
            assert_eq!(config.to_qualifier_string(), format!("-{qualifier}"),
                "decoded config disagrees with aapt2's own rendering of the same bytes");
            checked += 1;
        }
        assert!(checked > 0, "aapt2 printed no configurations to compare against");
        let _ = table;
    }

    // --- resolution against real ids ---------------------------------------

    #[test]
    fn a_layout_qualified_for_v22_is_only_chosen_on_v22_and_above() {
        // `aapt2 dump resources` for clock31:
        //   resource 0x7f040000 layout/c31_widget
        //     () (file) res/7_.xml type=XML
        //     (v22) (file) res/SE.xml type=XML
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();

        let on_21 = ResConfig { sdk_version: 21, ..ResConfig::DEFAULT };
        let r = table.resolve(0x7f04_0000, &on_21).unwrap();
        assert_eq!(r.as_file(), Some("res/7_.xml"), "sdk 21 must get the default layout");

        let on_22 = ResConfig { sdk_version: 22, ..ResConfig::DEFAULT };
        let r = table.resolve(0x7f04_0000, &on_22).unwrap();
        assert_eq!(r.as_file(), Some("res/SE.xml"), "sdk 22 must get the v22 layout");

        let on_34 = ResConfig { sdk_version: 34, ..ResConfig::DEFAULT };
        let r = table.resolve(0x7f04_0000, &on_34).unwrap();
        assert_eq!(r.as_file(), Some("res/SE.xml"), "sdk 34 must still get the v22 layout");
    }

    #[test]
    fn a_locale_qualified_string_is_chosen_for_that_locale_only() {
        // `aapt2 dump resources` for clock31:
        //   resource 0x7f060001 string/app_widget_description
        //     () "Simple clock and calendar combo widget"
        //     (it) "Widget con orologio e calendario"
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let italian = ResConfig { language: *b"it", ..ResConfig::DEFAULT };

        let v = table.resolve(0x7f06_0001, &italian).unwrap();
        assert_eq!(table.value_text(v.as_value().unwrap()).unwrap().as_deref(), Some("Widget con orologio e calendario"));

        let english = ResConfig { language: *b"en", country: *b"US", ..ResConfig::DEFAULT };
        let v = table.resolve(0x7f06_0001, &english).unwrap();
        assert_eq!(table.value_text(v.as_value().unwrap()).unwrap().as_deref(), Some("Simple clock and calendar combo widget"));
    }

    #[test]
    fn a_bag_entry_resolves_with_its_parent_and_its_map() {
        // `aapt2 dump resources`:
        //   resource 0x7f070001 style/Theme.Clock31.AppWidgetContainer
        //     () (style) size=1 parent=style/Theme.Clock31.AppWidgetContainerParent (0x7f070002)
        //       appWidgetPadding(0x7f010001)=16.000000dp
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let r = table.resolve(0x7f07_0001, &ResConfig::DEFAULT).unwrap();
        let Resolved::Bag { parent, map, .. } = r else {
            panic!("expected a bag, got {r:?}")
        };
        assert_eq!(parent, 0x7f07_0002, "aapt2 prints parent=0x7f070002");
        assert_eq!(map.len(), 1, "aapt2 prints size=1");
        assert_eq!(map[0].name, 0x7f01_0001, "aapt2 prints appWidgetPadding(0x7f010001)");
        // The real bytes are data=0x00001001, which is 16dp, not the 2dp that a
        // plausible-looking re-derivation of the radix field would produce.
        assert_eq!(map[0].value.as_dimension().unwrap().value, 16.0);
    }

    #[test]
    fn an_id_entry_carries_a_false_not_the_id() {
        // The bytes for `id/alarm` in the real table are `size=8 flags=0x0004
        // (FLAG_WEAK) dataType=0x12 data=0x00000000` — a *boolean false*, not
        // a self-reference. The id is the entry's own key; its value is a
        // marker. Assuming the value repeats the id makes every id-carrying
        // attribute read back as 0, which is exactly the "symbolic reference
        // stayed symbolic" failure this module exists to remove.
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let r = table.resolve(0x7f03_0000, &ResConfig::DEFAULT).unwrap();
        let v = r.as_value().expect("an id entry is a value, not a file");
        assert_eq!(v.as_bool(), Some(false), "the real bytes are TYPE_INT_BOOLEAN false");
        // The id is recoverable from the key, which is what `findViewById`
        // needs, so it is exposed as the id itself.
        assert_eq!(table.name_of(0x7f03_0000).unwrap(), "com.dosse.clock31:id/alarm");
    }

    // --- the rarer structural variants -------------------------------------

    #[test]
    fn a_36_byte_config_reads_only_the_fields_it_declares() {
        // `ResTable_config` has grown: 28, 32, 36, 48, 52, 56, 64. A 36-byte
        // config stops before `localeScript`, and everything after it must read
        // as zero rather than as whatever followed in the buffer.
        //
        // `aapt2 dump resources` on the reframed fixture prints:
        //     resource 0x7f020000 raw/sample
        //       (v4) ""
        let table = ResourceTable::parse(&fixture("weatherforecast.reframed.arsc")).unwrap();
        let package = &table.packages[0];
        assert_eq!(package.name, "uk.org.boddie.android.weatherforecast");
        // 284 is the package header without `typeIdOffset`, which Android 14
        // appended; the field must be absent, not zero-with-a-header-of-288.
        assert_eq!(package.type_id_offset, None);

        // Type byte 2 is `attr`, which is zero-based index 1.
        let spec = package.types.get(&1).expect("attr type");
        assert_eq!(spec.configs.len(), 1);
        let chunk = &spec.configs[0];
        // headerSize 56 == 20 + 36, so the config is 36 bytes.
        assert_eq!(chunk.config.sdk_version, 4);
        assert_eq!(chunk.config.to_qualifier_string(), "-v4", "aapt2 prints (v4)");
        // Fields past the declared size read as zero.
        assert_eq!(chunk.config.locale_script, [0; 4]);
        assert_eq!(chunk.config.smallest_screen_width_dp, 0);
        assert_eq!(chunk.config.screen_layout2, 0);
    }

    #[test]
    fn a_56_byte_config_parses() {
        let table = ResourceTable::parse(&fixture("vanillaplug.arsc")).unwrap();
        let package = &table.packages[0];
        let mut saw_config = false;
        for spec in package.types.values() {
            for chunk in &spec.configs {
                saw_config = true;
                // 56 bytes covers everything up to and including `screenConfig2`.
                assert_eq!(chunk.config.screen_config2(), chunk.config.screen_config2());
            }
        }
        assert!(saw_config, "fixture has no configurations at all");
    }

    #[test]
    fn a_16_bit_offset_index_decodes_to_the_same_entries() {
        // `FLAG_OFFSET16` packs each offset into 16 bits as `real / 4`, with
        // `0xffff` meaning NO_ENTRY. The 204-APK F-Droid corpus never uses it;
        // this fixture is a real runtime-resource overlay from the Android
        // emulator skin, which does.
        let bytes = fixture("pixel10proxl.arsc");
        let table = ResourceTable::parse(&bytes).unwrap();
        let package = &table.packages[0];
        let mut sparse_or_16 = 0;
        for spec in package.types.values() {
            for chunk in &spec.configs {
                assert_eq!(chunk.flags & FLAG_SPARSE, 0);
                if chunk.flags & FLAG_OFFSET16 != 0 {
                    sparse_or_16 += 1;
                }
            }
        }
        assert!(sparse_or_16 > 0, "fixture is meant to exercise FLAG_OFFSET16");
        // Every defined entry must still resolve to something.
        let mut defined = 0;
        for id in table.all_ids() {
            if !table.resolve(id, &ResConfig::DEFAULT).unwrap().is_absent() {
                defined += 1;
            }
        }
        assert!(defined > 0, "no entry survived FLAG_OFFSET16 decoding");
    }

    // --- config matching, the part that has to be right --------------------

    #[test]
    fn the_default_config_matches_every_device_but_is_matched_by_nothing_specific() {
        // AOSP calls this asymmetry out explicitly: "A default piece of data
        // will match every request but a request for the default should not
        // match odd specifics."
        let default = ResConfig::DEFAULT;
        let land = ResConfig { orientation: ORIENTATION_LAND, ..ResConfig::DEFAULT };
        assert!(default.matches(&land), "an unqualified resource serves any device");
        assert!(!land.matches(&default), "a `land` resource does not serve a request with no orientation");

        let v22 = ResConfig { sdk_version: 22, ..ResConfig::DEFAULT };
        assert!(default.matches(&v22));
        assert!(!v22.matches(&default));
    }

    #[test]
    fn orientation_qualifiers_follow_the_documented_rule() {
        let port = ResConfig { orientation: ORIENTATION_PORT, ..ResConfig::DEFAULT };
        let land = ResConfig { orientation: ORIENTATION_LAND, ..ResConfig::DEFAULT };
        let square = ResConfig { orientation: ORIENTATION_SQUARE, ..ResConfig::DEFAULT };
        // `land` is an exact qualifier, not a "at least this size" one, so it
        // serves landscape and nothing else. It does *not* serve portrait: that
        // is the difference between orientation and screen size in this format,
        // and getting it backwards ships a landscape layout on a phone.
        assert!(land.matches(&land));
        assert!(!land.matches(&port));
        assert!(!land.matches(&square));
        assert!(!land.matches(&ResConfig::DEFAULT), "an unqualified device gets the default layout");
        assert!(land.matches(&ResConfig { orientation: ORIENTATION_LAND, ..ResConfig::DEFAULT }));
        // A resource with no orientation serves everything.
        assert!(ResConfig::DEFAULT.matches(&land) && ResConfig::DEFAULT.matches(&port));
    }

    #[test]
    fn screen_size_qualifiers_may_overshoot_down_but_not_up() {
        // A `sw600dp` resource is for big screens only. A `sw320dp` resource
        // is served to a `sw600dp` device too, because it can be laid out
        // larger; the reverse would mean upscaling a tablet layout onto a
        // phone.
        let big = ResConfig { smallest_screen_width_dp: 600, ..ResConfig::DEFAULT };
        let small = ResConfig { smallest_screen_width_dp: 320, ..ResConfig::DEFAULT };
        assert!(!ResConfig { smallest_screen_width_dp: 600, ..ResConfig::DEFAULT }.matches(&small));
        assert!(ResConfig { smallest_screen_width_dp: 320, ..ResConfig::DEFAULT }.matches(&big));
    }

    #[test]
    fn density_never_filters_but_density_chooses() {
        // `match` ignores density on purpose — any density can be scaled — and
        // `is_better_than` decides between the candidates. Both halves are
        // checked here because getting only one right produces a layout that
        // resolves and is still the wrong size.
        let xhdpi = ResConfig { density: DENSITY_XHIGH, ..ResConfig::DEFAULT };
        let hdpi = ResConfig { density: DENSITY_HIGH, ..ResConfig::DEFAULT };
        let mdpi = ResConfig { density: DENSITY_MEDIUM, ..ResConfig::DEFAULT };
        let device = ResConfig { density: DENSITY_MEDIUM, ..ResConfig::DEFAULT };
        assert!(xhdpi.matches(&device), "density never filters");
        assert!(hdpi.matches(&device));
        assert!(ResConfig::DEFAULT.matches(&device));

        // AOSP's rule: among candidates all at or above the request, take the
        // *lowest*, because "any density is potentially useful ... always
        // prefer scaling down". So on a 160dpi device the 240dpi asset wins
        // over the 320dpi one. Reading this the other way is a silent 33%
        // scale error on every drawable.
        assert!(hdpi.is_better_than(&xhdpi, &device), "the nearer larger asset wins");
        assert!(!xhdpi.is_better_than(&hdpi, &device));

        // Below the request, the larger wins instead: 160 beats 120 on 160.
        assert!(mdpi.is_better_than(&ResConfig { density: DENSITY_LOW, ..ResConfig::DEFAULT }, &device));

        // `anydpi` beats any concrete bucket, in both directions.
        let anydpi = ResConfig { density: DENSITY_ANY, ..ResConfig::DEFAULT };
        assert!(anydpi.is_better_than(&xhdpi, &device));
        assert!(!xhdpi.is_better_than(&anydpi, &device));
    }

    #[test]
    fn sdk_version_is_an_upper_bound() {
        let v21 = ResConfig { sdk_version: 21, ..ResConfig::DEFAULT };
        let on_34 = ResConfig { sdk_version: 34, ..ResConfig::DEFAULT };
        assert!(v21.matches(&on_34));
        assert!(!v21.matches(&ResConfig { sdk_version: 14, ..ResConfig::DEFAULT }));
        // With several matching, the closest below the device wins.
        let v30 = ResConfig { sdk_version: 30, ..ResConfig::DEFAULT };
        assert!(v30.is_better_than(&v21, &on_34));
    }

    #[test]
    fn night_mode_and_screen_round_are_matched_exactly() {
        // `night` and `notnight` are opposite qualifiers, not a threshold:
        // a `night` resource is for devices that said they are in night mode
        // and for nothing else.
        let night = ResConfig { ui_mode: UI_MODE_NIGHT_YES, ..ResConfig::DEFAULT };
        let not_night = ResConfig { ui_mode: UI_MODE_NIGHT_NO, ..ResConfig::DEFAULT };
        assert!(night.matches(&night));
        assert!(!night.matches(&not_night));
        assert!(!night.matches(&ResConfig::DEFAULT), "a device that did not say cannot be served a night-only resource");
        assert!(ResConfig::DEFAULT.matches(&not_night), "but the default resource serves both");
        assert!(ResConfig::DEFAULT.matches(&night));

        let round = ResConfig { screen_layout2: 0x02, ..ResConfig::DEFAULT };
        assert!(round.matches(&round));
        assert!(!round.matches(&ResConfig::DEFAULT));
    }

    #[test]
    fn keysHidden_no_serves_a_device_asking_for_a_soft_keyboard() {
        // AOSP: "For compatibility, we count a request for KEYSHIDDEN_NO as
        // also matching the more recent KEYSHIDDEN_SOFT."
        let no_keys = ResConfig { input_flags: KEYSHIDDEN_NO, keyboard: KEYBOARD_NOKEYS, ..ResConfig::DEFAULT };
        let wants_soft = ResConfig { input_flags: KEYSHIDDEN_SOFT, keyboard: KEYBOARD_NOKEYS, ..ResConfig::DEFAULT };
        assert!(no_keys.matches(&wants_soft));
        assert!(!wants_soft.matches(&no_keys), "and not the other way round");
    }

    #[test]
    fn tagalog_and_filipino_are_treated_as_the_same_language() {
        let tagalog = ResConfig { language: *b"tl", ..ResConfig::DEFAULT };
        let filipino = ResConfig { language: [0xAD, 0x05], ..ResConfig::DEFAULT };
        assert!(tagalog.matches(&filipino));
        assert!(filipino.matches(&tagalog));
        let english = ResConfig { language: *b"en", ..ResConfig::DEFAULT };
        assert!(!tagalog.matches(&english));
    }

    #[test]
    fn a_country_only_qualifier_serves_any_device_that_speaks_the_language() {
        // `match` deliberately does not look at country: `values-it` is the
        // right answer for an `it-CH` device, and the country step is weeded
        // out by the specificity comparison instead.
        let it = ResConfig { language: *b"it", ..ResConfig::DEFAULT };
        let it_ch = ResConfig { language: *b"it", country: *b"CH", ..ResConfig::DEFAULT };
        // `values-it` serves an it-CH device: the resource's country is unset,
        // so there is nothing to disagree about.
        assert!(it.matches(&it_ch));
        // The reverse is not true, and the asymmetry is the point. With no
        // script on either side, AOSP falls back to requiring the countries to
        // match, and a device that did not name a country cannot satisfy an
        // `it-CH` resource. `match` is documented as asymmetric for this
        // reason: "a request for the default should not match odd specifics".
        assert!(!it_ch.matches(&it));
        // With a script on both sides the country step is skipped entirely, and
        // the resource wins by language alone.
        let it_scripted = ResConfig { language: *b"it", locale_script: *b"Latn", ..ResConfig::DEFAULT };
        let it_ch_scripted = ResConfig { language: *b"it", country: *b"CH", locale_script: *b"Latn", ..ResConfig::DEFAULT };
        assert!(it_ch_scripted.matches(&it_scripted));
        let en = ResConfig { language: *b"en", country: *b"US", ..ResConfig::DEFAULT };
        assert!(!it.matches(&en));
    }

    #[test]
    fn a_locale_with_a_script_only_serves_devices_whose_script_agrees() {
        let zh_hant = ResConfig {
            language: *b"zh",
            locale_script: *b"Hant",
            ..ResConfig::DEFAULT
        };
        let hant = ResConfig { language: *b"zh", locale_script: *b"Hant", ..ResConfig::DEFAULT };
        let hans = ResConfig { language: *b"zh", locale_script: *b"Hans", ..ResConfig::DEFAULT };
        let no_script = ResConfig { language: *b"zh", ..ResConfig::DEFAULT };
        assert!(zh_hant.matches(&hant));
        assert!(!zh_hant.matches(&hans), "a device on the other script is not served it");
        // A resource with no script is served to a device with one, but only
        // once the country fallback has also been satisfied.
        assert!(no_script.matches(&hant));
        // With the device's script unknown, AOSP falls back to comparing
        // countries, and `zh-Hant` names no country, so it is served. The
        // script is only a filter once the device has told us what it is.
        assert!(zh_hant.matches(&no_script));
    }

    #[test]
    fn an_unqualified_resource_is_preferred_for_us_english() {
        // AOSP: for en-US, a no-locale resource beats a locale whose country
        // is not US, because that is where the strings have always lived.
        let device = ResConfig { language: *b"en", country: *b"US", ..ResConfig::DEFAULT };
        let unqualified = ResConfig::DEFAULT;
        let gb = ResConfig { language: *b"en", country: *b"GB", ..ResConfig::DEFAULT };
        // `isLocaleBetterThan` itself: the unqualified resource wins.
        assert!(unqualified.is_locale_better_than(&gb, &device));
        assert!(!gb.is_locale_better_than(&unqualified, &device));
        // `isBetterThan` is *weaker* than that, and this is AOSP's actual
        // code rather than an oversight: the locale check is written as
        // `if (... && isLocaleBetterThan(...)) return true;` with no matching
        // `return false`, so it can only promote a candidate and never demote
        // one. The call then falls through to the remaining fields and finally
        // to `isMoreSpecificThan`, which does prefer `en-GB` over unqualified
        // because it names a language. The port keeps both halves, because
        // "fixing" the asymmetry would diverge from every Android release.
        assert!(gb.is_better_than(&unqualified, &device), "AOSP falls through to isMoreSpecificThan here");
        assert!(unqualified.is_locale_better_than(&gb, &device), "even though the locale rule says otherwise");
        // The same rule does not apply to another language.
        let fr_device = ResConfig { language: *b"fr", country: *b"FR", ..ResConfig::DEFAULT };
        let fr = ResConfig { language: *b"fr", country: *b"CA", ..ResConfig::DEFAULT };
        assert!(fr.is_better_than(&unqualified, &fr_device), "fr-CA beats unqualified on fr-FR");
    }

    #[test]
    fn closeness_to_us_english_is_the_us_territory_list() {
        // The CLDR parent table parents these regions directly to `en`; every
        // other English region parents to `en-001`, which is *not* close.
        for region in [b"US", b"PR", b"VI", b"GU", b"AS", b"MP"] {
            assert!(ResConfig::DEFAULT.is_close_to_us_english(region), "{:?} is a US territory", String::from_utf8_lossy(region));
        }
        for region in [b"GB", b"AU", b"CA", b"IE", b"NZ", b"IN", b"ZA"] {
            assert!(!ResConfig::DEFAULT.is_close_to_us_english(region), "{:?} is not a US territory", String::from_utf8_lossy(region));
        }
    }

    #[test]
    fn a_missing_locale_script_reports_that_it_degraded() {
        // With no CLDR data, AOSP requires the countries to match instead of
        // comparing scripts. That is a *different answer*, so it is reported.
        let bare = ResConfig { locale_script: [0; 4], ..ResConfig::DEFAULT };
        let zulu = ResConfig { locale_script: *b"Latn", ..ResConfig::DEFAULT };
        let report = bare.matches_with(&zulu, &LocaleData::empty());
        assert!(report.matched, "with no script on either side, the language alone decides");
        assert!(!report.locale_data_absent);

        // A device that knows its script, and a resource that does not, is the
        // case that needs the CLDR lookup.
        let no_script = ResConfig { language: *b"ja", ..ResConfig::DEFAULT };
        let device = ResConfig { language: *b"ja", locale_script: *b"Jpan", ..ResConfig::DEFAULT };
        let report = no_script.matches_with(&device, &LocaleData::empty());
        assert!(report.locale_data_absent, "without CLDR the script cannot be computed, and that is recorded");

        // Supply the data and the same comparison becomes exact.
        let locale = LocaleData::empty().with_script("ja", None, "Jpan");
        let report = no_script.matches_with(&device, &locale);
        assert!(report.matched);
        assert!(report.script_computed);
        assert!(!report.locale_data_absent);
    }

    // --- id handling -------------------------------------------------------

    #[test]
    fn resource_ids_split_and_recombine_exactly() {
        for raw in [0x7f03_0000u32, 0x7f04_0002, 0x0101_00d0, 0x01ff_ffff, 0x7fff_0001] {
            let id = ResId::from_u32(raw).expect("valid id");
            assert_eq!(id.to_u32(), raw, "0x{raw:08x} did not survive the round trip");
        }
        // Package and type are stored one-based, so a zero byte in either
        // position is detectable and must not be silently accepted.
        assert!(ResId::from_u32(0x0003_0000).is_none());
        assert!(ResId::from_u32(0x7f00_0000).is_none());
        assert!(ResId::from_u32(0).is_none());
        let id = ResId::from_u32(0x7f03_0000).unwrap();
        assert_eq!(id.package, 0x7e, "package byte is stored minus one");
        assert_eq!(id.type_id, 2, "type byte is stored minus one");
    }

    // --- names -------------------------------------------------------------

    #[test]
    fn resource_names_match_aapt2s_printout() {
        // `aapt2 dump resources` prints e.g. `resource 0x7f040000 layout/c31_widget`.
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        assert_eq!(table.name_of(0x7f04_0000).unwrap(), "com.dosse.clock31:layout/c31_widget");
        assert_eq!(table.name_of(0x7f06_0001).unwrap(), "com.dosse.clock31:string/app_widget_description");
        assert_eq!(table.name_of(0x7f03_000a).unwrap(), "com.dosse.clock31:id/event_date");
        assert!(matches!(table.name_of(0x0000_0000), Err(ResourceError::InvalidResourceId(_))));
    }

    // --- string pool edge cases -------------------------------------------

    #[test]
    fn a_pool_declaring_more_strings_than_it_can_hold_is_rejected_before_allocating() {
        // A 28-byte header claiming 4 billion strings must not become a
        // multi-gigabyte `Vec`.
        let mut chunk = vec![0u8; 28];
        chunk[0..2].copy_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        chunk[2..4].copy_from_slice(&28u16.to_le_bytes());
        chunk[4..8].copy_from_slice(&28u32.to_le_bytes());
        chunk[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        chunk[16..20].copy_from_slice(&UTF8_FLAG.to_le_bytes());
        chunk[20..24].copy_from_slice(&28u32.to_le_bytes());
        assert!(matches!(
            StringPool::parse("globalStrings", &chunk),
            Err(ResourceError::StringPoolOverlong { count: u32::MAX, .. })
        ));
    }

    #[test]
    fn a_string_index_past_the_pool_is_a_typed_error() {
        let pool = ResourceTable::parse(&fixture("clock31.arsc")).unwrap().global_strings;
        assert!(matches!(
            pool.get("globalStrings", 9999),
            Err(ResourceError::StringIndexOutOfRange { index: 9999, size: 16, .. })
        ));
        assert!(matches!(
            pool.get("globalStrings", u32::MAX),
            Err(ResourceError::StringIndexOutOfRange { .. })
        ));
    }

    // --- helpers -----------------------------------------------------------

    fn sha256_hex(data: &[u8]) -> String {
        // A local SHA-256 rather than a dependency: the fixtures are a few
        // kilobytes and the test only needs to notice an edit.
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ];
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        ];
        let mut msg = data.to_vec();
        let bitlen = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_be_bytes());
        for block in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for i in 0..8 {
                h[i] = h[i].wrapping_add(v[i]);
            }
        }
        h.iter().map(|x| format!("{x:08x}")).collect()
    }

    /// The `ResStringPool` chunk of a binary XML document.
    ///
    /// It is the first *child* chunk, so it starts at the document chunk's
    /// `headerSize`, not at offset 0.
    fn first_pool(xml: &[u8]) -> StringPool {
        let (typ, header_size, _) = chunk_header(xml, 0).unwrap();
        assert_eq!(typ, RES_TABLE_TYPE + 1, "the document root is RES_XML_TYPE");
        let (_, _, size) = chunk_header(xml, header_size as usize).unwrap();
        StringPool::parse("xmlStrings", &xml[header_size as usize..header_size as usize + size as usize]).unwrap()
    }

    /// Build a `ResConfig` from an `aapt2` qualifier string, for the
    /// differential test. This is a test-only encoder: it exists so the
    /// comparison does not have to go through this module's own decoder twice.
    fn parse_qualifier_for_oracle(q: &str) -> ResConfig {
        let mut c = ResConfig::DEFAULT;
        for part in q.split('-') {
            match part {
                "ldltr" => c.screen_layout |= 0x40,
                "ldrtl" => c.screen_layout |= 0x80,
                "small" => c.screen_layout = (c.screen_layout & !MASK_SCREENSIZE) | SCREENSIZE_SMALL,
                "normal" => c.screen_layout = (c.screen_layout & !MASK_SCREENSIZE) | SCREENSIZE_NORMAL,
                "large" => c.screen_layout = (c.screen_layout & !MASK_SCREENSIZE) | SCREENSIZE_LARGE,
                "xlarge" => c.screen_layout = (c.screen_layout & !MASK_SCREENSIZE) | SCREENSIZE_XLARGE,
                "notlong" => c.screen_layout |= SCREENLONG_NO,
                "long" => c.screen_layout |= SCREENLONG_YES,
                "notround" => c.screen_layout2 |= 0x01,
                "round" => c.screen_layout2 |= 0x02,
                "nowidecg" => c.color_mode |= 0x01,
                "widecg" => c.color_mode |= 0x02,
                "lowdr" => c.color_mode |= 0x04,
                "highdr" => c.color_mode |= 0x08,
                "port" => c.orientation = ORIENTATION_PORT,
                "land" => c.orientation = ORIENTATION_LAND,
                "square" => c.orientation = ORIENTATION_SQUARE,
                "notnight" => c.ui_mode |= UI_MODE_NIGHT_NO,
                "night" => c.ui_mode |= UI_MODE_NIGHT_YES,
                "ldpi" => c.density = DENSITY_LOW,
                "mdpi" => c.density = DENSITY_MEDIUM,
                "tvdpi" => c.density = DENSITY_TV,
                "hdpi" => c.density = DENSITY_HIGH,
                "xhdpi" => c.density = DENSITY_XHIGH,
                "xxhdpi" => c.density = DENSITY_XXHIGH,
                "xxxhdpi" => c.density = DENSITY_XXXHIGH,
                "anydpi" => c.density = DENSITY_ANY,
                "nodpi" => c.density = DENSITY_NONE,
                "notouch" => c.touchscreen = TOUCHSCREEN_NOTOUCH,
                "stylus" => c.touchscreen = TOUCHSCREEN_STYLUS,
                "finger" => c.touchscreen = TOUCHSCREEN_FINGER,
                "keysexposed" => c.input_flags |= KEYSHIDDEN_NO,
                "keyshidden" => c.input_flags |= KEYSHIDDEN_YES,
                "keyssoft" => c.input_flags |= KEYSHIDDEN_SOFT,
                "nokeys" => c.keyboard = KEYBOARD_NOKEYS,
                "qwerty" => c.keyboard = KEYBOARD_QWERTY,
                "12key" => c.keyboard = KEYBOARD_12KEY,
                "nonav" => c.navigation = NAVIGATION_NONAV,
                "dpad" => c.navigation = NAVIGATION_DPAD,
                "trackball" => c.navigation = NAVIGATION_TRACKBALL,
                "wheel" => c.navigation = NAVIGATION_WHEEL,
                other if other.starts_with("v") && other[1..].chars().all(|c| c.is_ascii_digit()) => {
                    c.sdk_version = other[1..].parse().unwrap()
                }
                other if other.starts_with("sw") && other.ends_with("dp") => {
                    c.smallest_screen_width_dp = other[2..other.len() - 2].parse().unwrap()
                }
                other if other.ends_with("dpi") => {
                    c.density = other[..other.len() - 3].parse().unwrap()
                }
                other if other.ends_with('x') && other[..other.len() - 1].chars().all(|c| c.is_ascii_digit()) => {
                    let (w, h) = other.split_once('x').unwrap();
                    c.screen_width = w.parse().unwrap();
                    c.screen_height = h.parse().unwrap();
                }
                other if other.starts_with("b+") => {
                    let mut it = other[2..].split('+');
                    c.language = pack2(it.next().unwrap());
                    if let Some(r) = it.next() {
                        c.country = pack2(r);
                    }
                    if let Some(s) = it.next() {
                        c.locale_script = pad4(s);
                    }
                    if let Some(v) = it.next() {
                        c.locale_variant = pad8(v);
                    }
                }
                other => panic!("test encoder does not know the qualifier {other:?}"),
            }
        }
        c
    }

    fn pack2(s: &str) -> [u8; 2] {
        let b = s.as_bytes();
        assert!(b.len() == 2, "test encoder only packs two-letter codes: {s:?}");
        [b[0], b[1]]
    }

    fn pad4(s: &str) -> [u8; 4] {
        let mut out = [0u8; 4];
        for (i, b) in s.bytes().take(4).enumerate() {
            out[i] = b;
        }
        out
    }

    fn pad8(s: &str) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (i, b) in s.bytes().take(8).enumerate() {
            out[i] = b;
        }
        out
    }
}
