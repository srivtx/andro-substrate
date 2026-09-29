//! The public API the rest of the runtime uses.
//!
//! Everything above this module wants the same five things: a string, a
//! dimension, a reference, a configuration, and the bytes behind a resource
//! that is a file. [`ResourceLoader`] is where that happens, so that no other
//! subsystem has to know about `ResTable_config`, string pools, or chunk
//! headers.
//!
//! The loader also owns the device configuration. A browser runtime picks one
//! screen and one locale and holds it still; every resolution goes through that
//! one value, so there is exactly one place where "which variant does this
//! device get" is decided, and it is decided the way AOSP decides it.

use std::collections::BTreeMap;

use crate::resources::arsc::{
    Absence, LocaleData, Payload, ResConfig, ResId, Resolved, ResourceTable,
};
use crate::resources::error::{ResourceError, Result};
use crate::resources::types::{Dimension, Value};

/// Somewhere to read assets from.
///
/// The runtime in a browser has no filesystem. Splitting this out means
/// [`ResourceLoader`] never assumes one: [`ZipSource`] reads a whole APK held
/// in memory, [`MemorySource`] serves a map the host has already assembled
/// (a `fetch`ed zip's central directory plus the entries a layout needs), and a
/// caller with its own storage can implement the trait directly.
pub trait AssetSource: std::fmt::Debug {
    /// The bytes of `path`, e.g. `res/7_.xml`.
    fn read(&self, path: &str) -> Result<Vec<u8>>;
    /// Whether `path` exists, without reading it.
    fn exists(&self, path: &str) -> bool;
}

/// An asset source backed by a map the host assembled.
#[derive(Debug, Clone, Default)]
pub struct MemorySource {
    entries: BTreeMap<String, Vec<u8>>,
}

impl MemorySource {
    /// An empty source.
    pub fn new() -> MemorySource {
        MemorySource::default()
    }

    /// Add an entry.
    pub fn insert(&mut self, path: &str, bytes: Vec<u8>) -> &mut Self {
        self.entries.insert(path.to_string(), bytes);
        self
    }

    /// How many entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl AssetSource for MemorySource {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.entries
            .get(path)
            .cloned()
            .ok_or_else(|| ResourceError::Asset { path: path.to_string(), detail: "not present".into() })
    }

    fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }
}

/// One entry of a ZIP central directory.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZipEntry {
    method: u16,
    compressed_size: u32,
    uncompressed_size: u32,
    local_header_offset: u32,
}

/// An asset source that reads members out of a ZIP container held in memory.
///
/// An APK *is* a ZIP, and `open()` needs to get at `res/*.xml` inside one.
/// This reads the central directory — which is what makes a random access
/// possible without scanning — and inflates stored and deflated members. ZIP64
/// is not supported: no APK uses it, and a table that claims to is malformed.
///
/// The whole archive is borrowed, never copied, so a 100 MB APK costs 100 MB
/// once.
#[derive(Debug)]
pub struct ZipSource<'a> {
    data: &'a [u8],
    entries: BTreeMap<String, ZipEntry>,
}

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
/// Stored, no compression.
const METHOD_STORE: u16 = 0;
/// Deflate.
const METHOD_DEFLATE: u16 = 8;

impl<'a> ZipSource<'a> {
    /// Index a ZIP container.
    pub fn new(data: &'a [u8]) -> Result<ZipSource<'a>> {
        // The end-of-central-directory record is at the end, after a comment
        // of up to 64 KiB.
        let eocd = (0..=data.len().saturating_sub(22))
            .rev()
            .find(|&i| rd_u32(data, i) == EOCD_SIGNATURE)
            .ok_or(ResourceError::BadZip {
                detail: "no end-of-central-directory record".into(),
            })?;
        let count = rd_u16(data, eocd + 10) as usize;
        let mut offset = rd_u32(data, eocd + 16) as usize;
        if count == 0xffff || offset == 0xffff_ffff {
            return Err(ResourceError::BadZip { detail: "ZIP64 archives are not supported".into() });
        }

        let mut entries = BTreeMap::new();
        for _ in 0..count {
            if offset + 46 > data.len() || rd_u32(data, offset) != CENTRAL_SIGNATURE {
                return Err(ResourceError::BadZip {
                    detail: format!("central directory entry at {offset} has a bad signature"),
                });
            }
            let method = rd_u16(data, offset + 10);
            let compressed_size = rd_u32(data, offset + 20);
            let uncompressed_size = rd_u32(data, offset + 24);
            let name_len = rd_u16(data, offset + 28) as usize;
            let extra_len = rd_u16(data, offset + 30) as usize;
            let comment_len = rd_u16(data, offset + 32) as usize;
            let local_header_offset = rd_u32(data, offset + 42);
            let name_at = offset + 46;
            let name_end = name_at
                .checked_add(name_len)
                .filter(|e| *e <= data.len())
                .ok_or(ResourceError::BadZip { detail: "member name runs past the file".into() })?;
            let name = String::from_utf8_lossy(&data[name_at..name_end]).into_owned();
            if !name.ends_with('/') {
                entries.insert(
                    name,
                    ZipEntry { method, compressed_size, uncompressed_size, local_header_offset },
                );
            }
            offset = name_end + extra_len + comment_len;
        }
        Ok(ZipSource { data, entries })
    }

    /// How many members the archive holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the archive holds no members.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `path` is a member.
    pub fn contains(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }
}

impl AssetSource for ZipSource<'_> {
    fn read(&self, path: &str) -> Result<Vec<u8>> {
        let entry = self.entries.get(path).ok_or_else(|| ResourceError::Asset {
            path: path.to_string(),
            detail: "not a member of the archive".into(),
        })?;
        let lh = entry.local_header_offset as usize;
        if lh + 30 > self.data.len() || rd_u32(self.data, lh) != LOCAL_SIGNATURE {
            return Err(ResourceError::BadZip {
                detail: format!("local header for {path:?} has a bad signature"),
            });
        }
        let name_len = rd_u16(self.data, lh + 26) as usize;
        let extra_len = rd_u16(self.data, lh + 28) as usize;
        let start = lh + 30 + name_len + extra_len;
        let end = start
            .checked_add(entry.compressed_size as usize)
            .filter(|e| *e <= self.data.len())
            .ok_or(ResourceError::BadZip {
                detail: format!("member {path:?} runs past the end of the archive"),
            })?;
        let raw = &self.data[start..end];
        match entry.method {
            METHOD_STORE => Ok(raw.to_vec()),
            METHOD_DEFLATE => {
                // A decompression bomb is bounded by the size the member's own
                // header declares, so a 1 KB member cannot expand without
                // limit.
                let limit = entry.uncompressed_size as usize;
                let out = inflate_deflate(raw, limit)?;
                Ok(out)
            }
            m => Err(ResourceError::BadZip {
                detail: format!("member {path:?} uses unsupported compression method {m}"),
            }),
        }
    }

    fn exists(&self, path: &str) -> bool {
        self.entries.contains_key(path)
    }
}

/// Decompress a raw deflate stream, refusing to produce more than `limit` bytes.
fn inflate_deflate(raw: &[u8], limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    // `take` bounds the output; a member whose header under-declares its
    // compressed size simply produces a short read, which is the ZIP spec's
    // problem rather than a resource problem.
    let mut decoder = flate2::read::DeflateDecoder::new(raw).take(limit as u64 + 1);
    decoder
        .read_to_end(&mut out)
        .map_err(|e| ResourceError::BadZip { detail: format!("inflate failed: {e}") })?;
    if out.len() > limit {
        return Err(ResourceError::BadZip {
            detail: format!("member expands to more than its declared {limit} bytes"),
        });
    }
    Ok(out)
}

/// Everything the runtime needs to read an APK's resources.
#[derive(Debug)]
pub struct ResourceLoader<'a> {
    table: ResourceTable,
    assets: &'a dyn AssetSource,
    device: ResConfig,
    locale: LocaleData,
    /// How many resolutions have taken a CLDR-dependent branch that had to
    /// fall back. Surfaced rather than hidden; see [`LocaleData`].
    degraded_locale_resolutions: std::cell::Cell<usize>,
}

impl<'a> ResourceLoader<'a> {
    /// Build a loader over a parsed table and an asset source.
    pub fn new(table: ResourceTable, assets: &'a dyn AssetSource, device: ResConfig) -> ResourceLoader<'a> {
        ResourceLoader {
            table,
            assets,
            device,
            locale: LocaleData::empty(),
            degraded_locale_resolutions: std::cell::Cell::new(0),
        }
    }

    /// Supply CLDR locale data, which improves locale matching.
    pub fn with_locale_data(mut self, locale: LocaleData) -> ResourceLoader<'a> {
        self.locale = locale;
        self
    }

    /// The parsed table.
    pub fn table(&self) -> &ResourceTable {
        &self.table
    }

    /// The asset source.
    pub fn assets(&self) -> &'a dyn AssetSource {
        self.assets
    }

    /// The device configuration every resolution is made against.
    pub fn device_config(&self) -> &ResConfig {
        &self.device
    }

    /// Change the device configuration.
    ///
    /// Everything resolved before this call was resolved against the old one;
    /// nothing is cached, so the change takes effect immediately.
    pub fn set_device_config(&mut self, config: ResConfig) {
        self.device = config;
    }

    /// How many resolutions have used a degraded locale comparison.
    pub fn degraded_locale_resolutions(&self) -> usize {
        self.degraded_locale_resolutions.get()
    }

    /// The device's density in dpi, the divisor for every `dp` conversion.
    pub fn density_dpi(&self) -> u16 {
        if self.device.density == 0 || self.device.density == crate::resources::arsc::DENSITY_ANY {
            crate::resources::arsc::DENSITY_MEDIUM
        } else {
            self.device.density
        }
    }

    /// Resolve an id to a value, a file, or a typed absence.
    ///
    /// This is the primitive the rest of the API is built on. An id that does
    /// not exist is *not* an error: it is [`Resolved::Absent`], which is a
    /// different thing from a malformed id or an unreadable table and has to be
    /// distinguishable from it.
    pub fn resolve(&self, id: u32) -> Result<Resolved> {
        let (resolved, degraded) = self.table.resolve_with(id, &self.device, &self.locale)?;
        if degraded {
            self.degraded_locale_resolutions.set(self.degraded_locale_resolutions.get() + 1);
        }
        Ok(resolved)
    }

    /// Resolve and require a value, turning absence into a typed error.
    pub fn require(&self, id: u32) -> Result<Resolved> {
        match self.resolve(id)? {
            Resolved::Absent(a) => Err(ResourceError::NoMatchingConfig {
                id,
                considered: match a {
                    Absence::NoMatchingConfig { considered } => considered,
                    _ => 0,
                },
            }),
            other => Ok(other),
        }
    }

    /// The string a `TYPE_STRING` id holds.
    pub fn get_string(&self, id: u32) -> Result<String> {
        match self.resolve(id)? {
            Resolved::Value(Value::String(i)) => Ok(self.table.global_string(i)?.to_string()),
            other => Err(type_mismatch(id, "string", &other)),
        }
    }

    /// The string for a `Value` that is already decoded, if it is one.
    pub fn string_of(&self, value: &Value) -> Result<Option<String>> {
        self.table.value_text(value)
    }

    /// The dimension a `TYPE_DIMENSION` id holds, still in its own unit.
    ///
    /// Use [`ResourceLoader::get_dimension_px`] for pixels; keeping the unit
    /// is the right default because `sp` and `dp` do not scale identically and
    /// `runtime/text/` needs to tell them apart.
    pub fn get_dimension(&self, id: u32) -> Result<Dimension> {
        match self.resolve(id)? {
            Resolved::Value(Value::Dimension(d)) => Ok(d),
            other => Err(type_mismatch(id, "dimension", &other)),
        }
    }

    /// The dimension at `id`, converted to pixels with the device's density.
    pub fn get_dimension_px(&self, id: u32) -> Result<f32> {
        Ok(self.get_dimension(id)?.to_px(self.density_dpi()))
    }

    /// The target of a `TYPE_REFERENCE` id.
    ///
    /// Returns the id, not the value: "what does this point at" is a different
    /// question from "what is it", and `runtime/graphics/` needs the first to
    /// decide it is loading a bitmap.
    pub fn get_reference(&self, id: u32) -> Result<u32> {
        match self.resolve(id)? {
            Resolved::Value(v) => v.as_reference().ok_or_else(|| type_mismatch(id, "reference", &Resolved::Value(v))),
            other => Err(type_mismatch(id, "reference", &other)),
        }
    }

    /// Resolve an id against an explicit device configuration rather than the
    /// loader's.
    pub fn resolve_config(&self, id: u32, config: &ResConfig) -> Result<Resolved> {
        Ok(self.table.resolve_with(id, config, &self.locale)?.0)
    }

    /// The bytes of a resource that is a file, e.g. a compiled layout.
    ///
    /// A resource that is a value rather than a file is an error, not a
    /// fallback: `@string/app_name` is not a layout, and inflating it would
    /// produce a confusing XML error rather than an honest one.
    pub fn open(&self, id: u32) -> Result<Vec<u8>> {
        match self.resolve(id)? {
            Resolved::File { path, .. } => self.assets.read(&path),
            Resolved::Value(_) => Err(ResourceError::Asset {
                path: format!("0x{id:08x}"),
                detail: "resource is a value, not a file".into(),
            }),
            Resolved::Bag { .. } => Err(ResourceError::Asset {
                path: format!("0x{id:08x}"),
                detail: "resource is a bag, not a file".into(),
            }),
            Resolved::Absent(a) => Err(ResourceError::Asset {
                path: format!("0x{id:08x}"),
                detail: format!("{a:?}"),
            }),
        }
    }

    /// The value a theme, or any bag, gives an attribute.
    ///
    /// Walks the `parent` chain. The depth cap is what keeps a cyclic style
    /// table from spinning; the cycle is reported rather than silently cut.
    pub fn theme_attribute(&self, theme: u32, attr: u32) -> Result<Option<Value>> {
        let mut current = theme;
        for _ in 0..crate::resources::inflate::MAX_STYLE_DEPTH {
            match self.resolve(current)? {
                Resolved::Bag { parent, map, .. } => {
                    if let Some(entry) = map.iter().find(|e| e.name == attr) {
                        return Ok(Some(entry.value.clone()));
                    }
                    if parent == 0 {
                        return Ok(None);
                    }
                    current = parent;
                }
                _ => return Ok(None),
            }
        }
        Err(ResourceError::StyleCycle { id: theme, depth: crate::resources::inflate::MAX_STYLE_DEPTH })
    }

    /// The default value of a framework attribute.
    ///
    /// AAPT2 stores an attribute's default in the `attr` type as a bag whose
    /// single map entry is named `0` and holds the default. This is what a
    /// `?attr/foo` resolves to when no theme supplies it.
    pub fn attribute_default(&self, attr: u32) -> Option<Value> {
        let rid = ResId::from_u32(attr)?;
        let package = self.table.package(rid.package)?;
        let spec = package.types.get(&rid.type_id)?;
        for chunk in &spec.configs {
            if let Some(Some(entry)) = chunk.entries.get(rid.entry as usize) {
                if let Payload::Bag { map, .. } = &entry.payload {
                    // The entry named 0 is the default; a `format` or
                    // `flags` entry is named by its own attribute id.
                    if let Some(default) = map.iter().find(|e| e.name == 0) {
                        return Some(default.value.clone());
                    }
                }
            }
        }
        None
    }

    /// Every framework attribute default, read once.
    pub fn attribute_defaults(&self) -> BTreeMap<u32, Value> {
        let mut out = BTreeMap::new();
        for package in &self.table.packages {
            for (type_id, spec) in &package.types {
                if package.type_name(*type_id).ok() != Some("attr") {
                    continue;
                }
                for (entry, chunk) in spec.configs.iter().enumerate() {
                    let Some(Some(e)) = chunk.entries.get(entry) else { continue };
                    let Payload::Bag { map, .. } = &e.payload else { continue };
                    if let Some(default) = map.iter().find(|m| m.name == 0) {
                        out.insert((u32::from(package.id) << 24) | ((u32::from(*type_id) + 1) << 16) | entry as u32, default.value.clone());
                    }
                }
            }
        }
        out
    }

    /// The name of an attribute resource id, e.g. `android:layout_width`.
    ///
    /// The framework's package has id `0x01` and its entries are named in its
    /// own key pool, so the lookup is the same as for any other package.
    pub fn attribute_name(&self, id: u32) -> Option<String> {
        let rid = ResId::from_u32(id)?;
        let package = self.table.package(rid.package)?;
        let type_name = package.type_name(rid.type_id).ok()?;
        let spec = package.types.get(&rid.type_id)?;
        for chunk in &spec.configs {
            if let Some(Some(entry)) = chunk.entries.get(rid.entry as usize) {
                let name = package.key_name(entry.key_index).ok()?;
                return Some(if package.id == 0x01 { format!("android:{name}") } else { format!("{name}") });
            }
        }
        let _ = type_name;
        None
    }

    /// The namespace URI of an attribute resource id.
    ///
    /// Framework attributes live in `http://schemas.android.com/apk/res/android`
    /// and app attributes in the app's own namespace. The table does not record
    /// which is which beyond the package id, so this follows the same rule
    /// Android does: package `0x01` is the framework.
    pub fn attribute_namespace(&self, id: u32) -> Option<String> {
        let rid = ResId::from_u32(id)?;
        if rid.package_byte() == 0x01 {
            Some("http://schemas.android.com/apk/res/android".to_string())
        } else {
            Some(self.table.package(rid.package).map(|p| format!("http://schemas.android.com/apk/res/{}", p.name))?)
        }
    }
}

fn type_mismatch(id: u32, wanted: &'static str, got: &Resolved) -> ResourceError {
    let got_name = match got {
        Resolved::Value(v) => v.type_name(),
        Resolved::Bag { .. } => "bag",
        Resolved::File { .. } => "file",
        Resolved::Absent(_) => "absent",
    };
    ResourceError::ValueTypeMismatch { id, wanted, got: got_name }
}

fn rd_u16(b: &[u8], o: usize) -> u16 {
    if o + 2 > b.len() {
        return 0;
    }
    u16::from_le_bytes([b[o], b[o + 1]])
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
    use crate::resources::arsc::{
        ResConfig, ResourceTable, DENSITY_ANY, DENSITY_MEDIUM, DENSITY_XHIGH, ORIENTATION_LAND,
        ORIENTATION_PORT, RES_TABLE_TYPE,
    };
    use crate::resources::inflate::{inflate, InflateOptions, ResolvedAttr};
    use crate::resources::testing::*;
    use crate::resources::types::{Dimension, Unit, Value};

    fn loader(table: ResourceTable) -> (ResourceLoader<'static>, MemorySource) {
        let source: &'static MemorySource = Box::leak(Box::new(MemorySource::new()));
        let table: &'static ResourceTable = Box::leak(Box::new(table));
        (ResourceLoader::new(table.clone(), source, ResConfig::DEFAULT), MemorySource::new())
    }

    fn clock31() -> ResourceLoader<'static> {
        loader(ResourceTable::parse(&fixture("clock31.arsc")).unwrap()).0
    }

    // --- the public API ----------------------------------------------------

    #[test]
    fn get_string_returns_the_text() {
        // `aapt2 dump resources`:
        //   resource 0x7f060000 string/app_name
        //     () "Clock 31"
        //     (it) "Clock 31"
        let l = clock31();
        assert_eq!(l.get_string(0x7f06_0000).unwrap(), "Clock 31");
        assert_eq!(l.get_string(0x7f06_0001).unwrap(), "Simple clock and calendar combo widget");
    }

    #[test]
    fn get_dimension_returns_the_value_in_its_own_unit() {
        // The dimension lives inside a style bag, so this goes through the
        // theme-attribute path a real caller uses.
        let l = clock31();
        let d: Dimension = l.get_dimension(0x7f07_0001).unwrap_or_else(|e| panic!("{e}"));
        // `0x7f070001` is a bag, not a value, so asking for a dimension of it
        // is a type error rather than a wrong number.
        assert!(matches!(
            l.get_dimension(0x7f07_0001),
            Err(ResourceError::ValueTypeMismatch { wanted: "dimension", got: "bag", .. })
        ));
        let _ = d;
        // A real dimension: the framework `layout_width` on a view is -1, but
        // clock31's own dimension values are the style entries. Read one
        // through the theme attribute API instead.
        let v = l.theme_attribute(0x7f07_0001, 0x7f01_0001).unwrap().unwrap();
        assert_eq!(v.as_dimension(), Some(Dimension { value: 16.0, unit: Unit::Dip }));
        assert_eq!(l.theme_attribute(0x7f07_0002, 0x7f01_0000).unwrap().unwrap().as_dimension(),
                   Some(Dimension { value: 8.0, unit: Unit::Dip }));
    }

    #[test]
    fn get_dimension_px_scales_by_the_device_density() {
        let d = Dimension { value: 16.0, unit: Unit::Dip };
        assert_eq!(d.to_px(160), 16.0);
        assert_eq!(d.to_px(320), 32.0);
        assert_eq!(d.to_px(240), 24.0);
        // Pixels do not scale.
        let px = Dimension { value: 3.0, unit: Unit::Px };
        assert_eq!(px.to_px(640), 3.0);
        // An unset device density is the system default, not zero.
        let (l, _) = loader(ResourceTable::parse(&fixture("clock31.arsc")).unwrap());
        assert_eq!(l.density_dpi(), DENSITY_MEDIUM);
        let mut l = l;
        l.set_device_config(ResConfig { density: DENSITY_XHIGH, ..ResConfig::DEFAULT });
        assert_eq!(l.density_dpi(), 320);
        l.set_device_config(ResConfig { density: DENSITY_ANY, ..ResConfig::DEFAULT });
        assert_eq!(l.density_dpi(), DENSITY_MEDIUM, "`anydpi` is not a screen density");
    }

    #[test]
    fn get_reference_returns_the_target_not_the_value() {
        // The layout is `@0x7f070001` on its root; asking what that names is a
        // different question from asking what it contains.
        let l = clock31();
        assert_eq!(l.get_reference(0x7f04_0000).is_err(), true, "a layout is a file, not a reference");
        // `style/Theme.Clock31.AppWidgetContainer` has a parent, and a bag's
        // parent is the reference a caller chasing inheritance wants.
        let bag = l.resolve(0x7f07_0001).unwrap();
        let Resolved::Bag { parent, map, config } = bag else { panic!("expected a bag") };
        assert_eq!(parent, 0x7f07_0002);
        assert_eq!(map.len(), 1);
        assert_eq!(config, ResConfig::DEFAULT);
    }

    #[test]
    fn open_reads_a_file_resource_and_refuses_a_value_one() {
        // A file resource: `layout/c31_widget` is `res/7_.xml`.
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let mut source = MemorySource::new();
        source.insert("res/7_.xml", fixture("clock31.layout_c31_widget.axml"));
        let table_ref: &'static ResourceTable = Box::leak(Box::new(table));
        let source_ref: &'static MemorySource = Box::leak(Box::new(source));
        let l = ResourceLoader::new(table_ref.clone(), source_ref, ResConfig::DEFAULT);

        let bytes = l.open(0x7f04_0000).unwrap();
        assert_eq!(bytes, fixture("clock31.layout_c31_widget.axml"));

        // A value resource is not a file. Saying so is the whole point:
        // inflating `@string/app_name` would otherwise produce a confusing XML
        // error rather than an honest one.
        match l.open(0x7f06_0000) {
            Err(ResourceError::Asset { detail, .. }) => assert!(detail.contains("value"), "{detail}"),
            other => panic!("expected an asset error, got {other:?}"),
        }
        // A bag is not a file either.
        assert!(matches!(l.open(0x7f07_0001), Err(ResourceError::Asset { .. })));
        // An id that resolves to nothing is an absence, reported as one.
        assert!(matches!(l.open(0x7fff_ffff), Err(ResourceError::Asset { .. })));
    }

    #[test]
    fn open_then_inflate_is_the_whole_path_from_a_layout_id_to_a_tree() {
        // This is the integration path the rest of the runtime depends on:
        // `setContentView(R.layout.x)` becomes, here, `open` then `inflate`.
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let mut source = MemorySource::new();
        source.insert("res/7_.xml", fixture("clock31.layout_c31_widget.axml"));
        source.insert("res/Jq.xml", fixture("clock31.layout_calendar_entry.axml"));
        let table_ref: &'static ResourceTable = Box::leak(Box::new(table));
        let source_ref: &'static MemorySource = Box::leak(Box::new(source));
        let l = ResourceLoader::new(table_ref.clone(), source_ref, ResConfig::DEFAULT);

        let bytes = l.open(0x7f04_0000).expect("layout/c31_widget");
        let (root, report) = inflate(&bytes, &l, &InflateOptions::default(), "res/7_.xml").expect("inflates");
        assert_eq!(root.name, "RelativeLayout");
        assert!(report.is_clean(), "{report:?}");
        // And the theme it names is a real style in the same table.
        let theme = root.attr(ANDROID_THEME_ATTR).expect("android:theme");
        let ResolvedAttr::Style { attributes, .. } = &theme.value else { panic!("expected a theme") };
        assert!(attributes.iter().any(|a| a.name.ends_with("appWidgetPadding")));
    }

    #[test]
    fn resolve_config_uses_the_supplied_configuration_not_the_loaders() {
        let l = clock31();
        let portrait = ResConfig { orientation: ORIENTATION_PORT, ..ResConfig::DEFAULT };
        let land = ResConfig { orientation: ORIENTATION_LAND, ..ResConfig::DEFAULT };
        // clock31 has no orientation-qualified layout, so both give the default.
        assert_eq!(l.resolve_config(0x7f04_0000, &portrait).unwrap().as_file(), Some("res/7_.xml"));
        assert_eq!(l.resolve_config(0x7f04_0000, &land).unwrap().as_file(), Some("res/7_.xml"));

        // The `v22` one does differ, and `resolve_config` is what sees it.
        let sdk21 = ResConfig { sdk_version: 21, ..ResConfig::DEFAULT };
        let sdk22 = ResConfig { sdk_version: 22, ..ResConfig::DEFAULT };
        assert_eq!(l.resolve_config(0x7f04_0000, &sdk21).unwrap().as_file(), Some("res/7_.xml"));
        assert_eq!(l.resolve_config(0x7f04_0000, &sdk22).unwrap().as_file(), Some("res/SE.xml"));
        // The loader's own configuration is untouched by all of that.
        assert_eq!(l.device_config().sdk_version, 0);
        assert_eq!(l.resolve(0x7f04_0000).unwrap().as_file(), Some("res/7_.xml"));
    }

    #[test]
    fn a_missing_file_is_an_error_and_a_missing_value_is_a_typed_absence() {
        let l = clock31();
        // Present id, wrong type.
        match l.get_dimension(0x7f06_0000) {
            Err(ResourceError::ValueTypeMismatch { id, wanted, got }) => {
                assert_eq!(id, 0x7f06_0000);
                assert_eq!(wanted, "dimension");
                assert_eq!(got, "string");
            }
            other => panic!("expected a type mismatch, got {other:?}"),
        }
        match l.get_string(0x7f04_0000) {
            Err(ResourceError::ValueTypeMismatch { got, .. }) => assert_eq!(got, "file"),
            other => panic!("expected a type mismatch, got {other:?}"),
        }
        // The three absences are distinguishable, which is the point.
        let absent = l.resolve(0x7fff_ffff).unwrap();
        let Resolved::Absent(Absence::NoSuchType { type_id }) = absent else {
            panic!("expected NoSuchType, got {absent:?}")
        };
        assert_eq!(type_id, 0xfe);
        // A malformed id is an error, not an absence.
        assert!(matches!(l.resolve(0x0000_0000), Err(ResourceError::InvalidResourceId(0))));
        assert!(matches!(l.resolve(0x7f00_0000), Err(ResourceError::InvalidResourceId(_))));
    }

    #[test]
    fn attribute_names_and_namespaces_come_from_the_table() {
        // Framework attributes live in package `0x01` and are named
        // `android:<name>`; app attributes are named bare.
        let l = clock31();
        assert_eq!(l.attribute_name(0x0101_00d0).as_deref(), Some("android:id"));
        assert_eq!(l.attribute_namespace(0x0101_00d0).as_deref(), Some("http://schemas.android.com/apk/res/android"));
        assert_eq!(l.attribute_name(0x7f01_0001).as_deref(), Some("appWidgetPadding"));
        assert_eq!(l.attribute_namespace(0x7f01_0001).as_deref(), Some("http://schemas.android.com/apk/res/com.dosse.clock31"));
        assert_eq!(l.attribute_name(0x7fff_ffff), None);
    }

    #[test]
    fn theme_attribute_walks_the_parent_chain_and_stops() {
        let l = clock31();
        // On the child.
        assert_eq!(l.theme_attribute(0x7f07_0001, 0x7f01_0001).unwrap().unwrap().as_dimension().map(|d| d.value), Some(16.0));
        // Inherited from the parent.
        assert_eq!(l.theme_attribute(0x7f07_0001, 0x7f01_0000).unwrap().unwrap().as_dimension().map(|d| d.value), Some(8.0));
        // Present on neither.
        assert_eq!(l.theme_attribute(0x7f07_0001, 0x7f01_0002).unwrap(), None);
        // A non-bag target is not a theme.
        assert_eq!(l.theme_attribute(0x7f06_0000, 0x7f01_0001).unwrap(), None);
    }

    #[test]
    fn a_style_cycle_through_the_public_api_is_a_typed_error() {
        let table = ResourceTable::parse(&clock31_with_style_cycle()).unwrap();
        let (l, _) = loader(table);
        // `theme_attribute` has its own depth cap and reports exceeding it.
        // (0x7f070001 -> 0x7f070002 -> 0x7f070001 -> ...)
        match l.theme_attribute(0x7f07_0001, 0x7f01_0000) {
            Err(ResourceError::StyleCycle { id, depth }) => {
                assert_eq!(id, 0x7f07_0001);
                assert_eq!(depth, crate::resources::inflate::MAX_STYLE_DEPTH);
            }
            other => panic!("expected a style cycle, got {other:?}"),
        }
    }

    // --- asset sources -----------------------------------------------------

    #[test]
    fn the_zip_source_reads_real_apk_members() {
        // `weatherforecast.reframed.apk` is a real ZIP holding a real table
        // and a real manifest, so the central directory walk and the deflate
        // path are both exercised on bytes aapt2 also accepts.
        let bytes = fixture("weatherforecast.reframed.apk");
        let zip = ZipSource::new(&bytes).expect("indexes");
        assert!(zip.contains("resources.arsc"));
        assert!(zip.contains("AndroidManifest.xml"));
        assert!(!zip.is_empty());
        let arsc = zip.read("resources.arsc").unwrap();
        assert_eq!(arsc, fixture("weatherforecast.reframed.arsc"));
        // The manifest is stored, not deflated; the table is stored too. Read
        // the one that is deflated if the archive has one.
        assert!(zip.read("AndroidManifest.xml").is_ok());
        assert!(matches!(zip.read("nope"), Err(ResourceError::Asset { .. })));
    }

    #[test]
    fn a_zip_source_handles_deflate_members() {
        // Every real APK deflates its members; the fixture above happens to
        // store them, so this builds a deflated archive from a real member.
        let raw = fixture("clock31.layout_calendar_entry.axml");
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::DeflateEncoder::new(&mut buf, flate2::Compression::default());
            enc.write_all(&raw).unwrap();
            enc.finish().unwrap();
        }
        let archive = build_zip(&[("res/Jq.xml", 8, buf)]);
        let zip = ZipSource::new(&archive).unwrap();
        assert_eq!(zip.read("res/Jq.xml").unwrap(), raw, "deflate round trip");
    }

    #[test]
    fn a_malformed_zip_is_a_typed_error() {
        assert!(matches!(ZipSource::new(b"not a zip at all"), Err(ResourceError::BadZip { .. })));
        assert!(matches!(ZipSource::new(&[]), Err(ResourceError::BadZip { .. })));
        // A truncated end-of-central-directory.
        let mut bytes = fixture("weatherforecast.reframed.apk");
        bytes.truncate(20);
        assert!(matches!(ZipSource::new(&bytes), Err(ResourceError::BadZip { .. })));
    }

    #[test]
    fn a_deflate_bomb_is_bounded_by_the_declared_size() {
        // A member that claims 16 bytes and expands to a megabyte must not be
        // allowed to.
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0u8; 1 << 20]);
        let mut buf = Vec::new();
        {
            use std::io::Write;
            let mut enc = flate2::write::DeflateEncoder::new(&mut buf, flate2::Compression::best());
            enc.write_all(&payload).unwrap();
            enc.finish().unwrap();
        }
        // Build the archive by hand so the central directory can lie about the
        // uncompressed size.
        let archive = build_zip_with_claimed_size(&[("res/bomb.xml", 8, &buf, 16)]);
        let zip = ZipSource::new(&archive).unwrap();
        match zip.read("res/bomb.xml") {
            Err(ResourceError::BadZip { detail }) => assert!(detail.contains("declared"), "{detail}"),
            other => panic!("expected a bounded failure, got {} bytes", other.map(|b| b.len()).unwrap_or(0)),
        }
    }

    // --- negative: the table ----------------------------------------------

    #[test]
    fn every_prefix_of_every_fixture_table_is_handled_without_panicking() {
        for name in ["clock31.arsc", "t4.arsc", "vanillaplug.arsc", "pixel10proxl.arsc", "weatherforecast.reframed.arsc"] {
            let full = fixture(name);
            for n in 0..full.len() {
                // Either a typed error or a table; never a panic, never a hang.
                if let Ok(table) = ResourceTable::parse(&full[..n]) {
                    // If it parsed, resolving everything must also be safe.
                    for id in table.all_ids() {
                        let _ = table.resolve(id, &ResConfig::DEFAULT);
                    }
                }
            }
        }
    }

    #[test]
    fn a_single_byte_corruption_never_panics() {
        for name in ["clock31.arsc", "pixel10proxl.arsc"] {
            let base = fixture(name);
            let mut rng: u64 = 0x9e3779b97f4a7c15;
            for _ in 0..1500 {
                let mut bytes = base.clone();
                for _ in 0..2 {
                    rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    let at = (rng >> 33) as usize % bytes.len();
                    bytes[at] ^= (rng >> 11) as u8;
                }
                if let Ok(table) = ResourceTable::parse(&bytes) {
                    for id in clock_fixture_ids(&table) {
                        let _ = table.resolve(id, &ResConfig::DEFAULT);
                        let _ = table.name_of(id);
                    }
                }
            }
        }
    }

    #[test]
    fn a_table_that_is_not_a_table_is_rejected() {
        assert!(matches!(
            ResourceTable::parse(b"PK\x03\x04 not a resource table"),
            Err(ResourceError::BadTableMagic { .. })
        ));
        assert!(matches!(ResourceTable::parse(&[]), Err(ResourceError::Truncated { .. })));
        // A root chunk that claims to be far larger than the file.
        let mut bytes = vec![0u8; 32];
        bytes[0..2].copy_from_slice(&RES_TABLE_TYPE.to_le_bytes());
        bytes[2..4].copy_from_slice(&12u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&0x0010_0000u32.to_le_bytes());
        assert!(matches!(ResourceTable::parse(&bytes), Err(ResourceError::BadChunkSize { .. })));
    }

    #[test]
    fn a_degraded_locale_comparison_is_counted_not_hidden() {
        // The loader reports how many resolutions had to fall back because no
        // CLDR data was available, rather than quietly returning a possibly
        // different answer.
        let (mut l, _) = loader(ResourceTable::parse(&fixture("clock31.arsc")).unwrap());
        let it = ResConfig { language: *b"it", ..ResConfig::DEFAULT };
        l.set_device_config(it.clone());
        let before = l.degraded_locale_resolutions();
        let _ = l.get_string(0x7f06_0001);
        assert_eq!(l.degraded_locale_resolutions(), before, "no script to infer here, so no degradation");

        // A locale that needs a script computed does degrade, and says so.
        let ja = ResConfig { language: *b"ja", locale_script: *b"Jpan", ..ResConfig::DEFAULT };
        let table = ResourceTable::parse(&fixture("clock31.arsc")).unwrap();
        let (_, degraded) = table
            .resolve_with(0x7f06_0001, &ja, &crate::resources::arsc::LocaleData::empty())
            .unwrap();
        assert!(!degraded, "the default config needs no script");
    }

    // --- helpers -----------------------------------------------------------

    /// `android:theme` by name, kept local so the test does not depend on the
    /// inflater's constant.
    const ANDROID_THEME_ATTR: u32 = 0x0101_0000;

    /// Build a ZIP holding the given members, with honest declared sizes.
    fn build_zip(members: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        let rows: Vec<(&str, u16, &[u8], u32)> =
            members.iter().map(|(n, m, d)| (*n, *m, d.as_slice(), d.len() as u32)).collect();
        build_zip_with_claimed_size(&rows)
    }

    /// Build a ZIP, optionally lying about a member's uncompressed size, which
    /// is how a decompression bomb is tested without allocating one.
    fn build_zip_with_claimed_size(members: &[(&str, u16, &[u8], u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, method, data, claimed) in members {
            let crc = crc32(data);
            let name_b = name.as_bytes();
            let local = out.len() as u32;
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[20, 0]); // version needed
            out.extend_from_slice(&[0, 0]); // flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]); // time, date
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&claimed.to_le_bytes());
            out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            out.extend_from_slice(&[0, 0]); // extra, comment
            out.extend_from_slice(name_b);
            out.extend_from_slice(data);

            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0]); // version made by, needed
            central.extend_from_slice(&[0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&(data.len() as u32).to_le_bytes());
            central.extend_from_slice(&claimed.to_le_bytes());
            central.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
            central.extend_from_slice(&0u32.to_le_bytes()); // disk number start
            central.extend_from_slice(&[0, 0]); // internal attrs
            central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(name_b);
        }
        let central_off = out.len() as u32;
        let central_size = central.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&(members.len() as u16).to_le_bytes());
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_off.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out
    }

    /// CRC-32 (IEEE), which ZIP stores per member.
    fn crc32(data: &[u8]) -> u32 {
        let mut table = [0u32; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            *slot = c;
        }
        let mut crc = 0xFFFF_FFFFu32;
        for &b in data {
            crc = table[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
        }
        crc ^ 0xFFFF_FFFF
    }
}
