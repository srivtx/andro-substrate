//! Android binary XML (AXML) reader, for `AndroidManifest.xml` and
//! `resources.arsc`-adjacent files.
//!
//! AAPT2 does not ship plain XML inside an APK. It compiles it into a chunked
//! binary format whose string pool is UTF-16 rather than MUTF-8, whose integers
//! are a packed variable-length encoding, and whose attribute values are
//! themselves encoded. This module turns that back into a tree.
//!
//! # Chunk layout
//!
//! ```text
//! ResChunk_header { u16 type, u16 headerSize, u32 size }
//! XML_FILE      0x0003  the root chunk
//!   STRING_POOL  0x0001  the attribute and element name pool
//!   RESOURCE_MAP 0x0180  parallel array of framework resource ids
//!   START_NS     0x0100
//!   END_NS       0x0101
//!   START_TAG    0x0102
//!   END_TAG      0x0103
//!   CDATA        0x0104
//! ```
//!
//! Reference: the `ResourceTypes.h` / `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h`
//! header in AOSP, which is the normative description of these structures.

use crate::error::{Error, Result};
use serde::Serialize;

/// `ResChunk_header.type` for the whole file.
pub const RES_XML_TYPE: u16 = 0x0003;
/// `ResStringPool_header.type`.
pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
/// `ResTable_resource_map_header.type`.
pub const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
/// `ResXMLTree_node` for a namespace declaration.
pub const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
/// `ResXMLTree_node` for the end of a namespace declaration.
pub const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
/// `ResXMLTree_node` for an element start tag.
pub const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
/// `ResXMLTree_node` for an element end tag.
pub const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
/// `ResXMLTree_node` for character data.
pub const RES_XML_CDATA_TYPE: u16 = 0x0104;

/// Set when the pool's string offsets are sorted by content. AAPT2 emits it;
/// this reader sorts nothing and does not rely on it.
#[allow(dead_code)]
const SORTED_FLAG: u32 = 1 << 0;
/// The pool's strings are UTF-8 rather than UTF-16.
const UTF8_FLAG: u32 = 1 << 8;

/// A parsed string pool chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringPool {
    /// Decoded strings, indexed as the file refers to them.
    pub strings: Vec<String>,
    /// Framework resource ids from the resource map chunk, if present.
    pub resource_ids: Vec<u32>,
}

/// One attribute of an element.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Attribute {
    /// Attribute name, e.g. `android:name`.
    pub name: String,
    /// Framework resource id, if the resource map covered this index.
    pub resource_id: Option<u32>,
    /// Index into [`StringPool::strings`] for the raw (unformatted) value.
    pub raw_value_idx: Option<usize>,
    /// The raw value exactly as stored.
    pub raw_value: Option<String>,
    /// `android:value` after resource-id resolution and typed-value decoding.
    pub value: AttributeValue,
}

/// A decoded `Res_value`.
///
/// AAPT2 stores a type tag alongside every value, so an integer attribute and
/// a string attribute share one representation on disk and diverge only here.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value")]
pub enum AttributeValue {
    /// A string from the pool.
    String(String),
    /// A 32-bit integer, or a 32-bit float reinterpreted as bits.
    Int(i32),
    /// A 32-bit float.
    Float(f32),
    /// A 64-bit integer, or a 64-bit double reinterpreted as bits.
    Long(i64),
    /// A 64-bit double.
    Double(f64),
    /// A colour, as `0xAARRGGBB`.
    Color(u32),
    /// A reference to another resource.
    Reference(u32),
    /// An attribute resource.
    Attribute(u32),
    /// An opaque `Res_value` this decoder does not interpret.
    Raw {
        /// The `Res_value.dataType` tag.
        data_type: u8,
        /// The raw `Res_value.data` field.
        data: u32,
    },
    /// The attribute is absent, or its value is one of the empty sentinels.
    Null,
}

impl AttributeValue {
    /// The value as a string, for manifests and resource tables where every
    /// value is ultimately textual.
    pub fn as_text(&self) -> Option<String> {
        match self {
            AttributeValue::String(s) => Some(s.clone()),
            AttributeValue::Int(i) => Some(i.to_string()),
            AttributeValue::Long(i) => Some(i.to_string()),
            AttributeValue::Float(f) => Some(f.to_string()),
            AttributeValue::Double(d) => Some(d.to_string()),
            AttributeValue::Color(c) => Some(format!("#{c:08x}")),
            AttributeValue::Reference(r) => Some(format!("@{r:08x}")),
            AttributeValue::Attribute(r) => Some(format!("?{r:08x}")),
            _ => None,
        }
    }
}

/// An element in the tree.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Element {
    /// Tag name, e.g. `activity`.
    pub name: String,
    /// Attribute namespace URIs, in declaration order.
    pub namespaces: Vec<String>,
    pub attributes: Vec<Attribute>,
    pub children: Vec<Element>,
}

impl Element {
    /// The value of an attribute by name, e.g. `android:name`.
    pub fn attribute(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// The text value of an attribute by name.
    pub fn attribute_value(&self, name: &str) -> Option<String> {
        self.attribute(name).and_then(|a| a.value.as_text().or_else(|| a.raw_value.clone()))
    }

    /// Direct children with the given tag name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Element> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Every element in the subtree with the given tag name, depth first.
    pub fn find_all(&self, name: &str) -> Vec<&Element> {
        let mut out = Vec::new();
        for c in &self.children {
            if c.name == name {
                out.push(c);
            }
            out.extend(c.find_all(name));
        }
        out
    }
}

/// A parsed binary XML document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AxmlDocument {
    /// The root element, normally `manifest`.
    pub root: Element,
    /// Every string in the pool, in file order.
    pub strings: StringPool,
    /// Namespace prefix-to-URI bindings, in declaration order.
    pub namespaces: Vec<(String, String)>,
}

impl AxmlDocument {
    /// The `package` attribute of the root element.
    pub fn package_name(&self) -> Option<String> {
        self.root.attribute_value("package")
    }

    /// Every element in the document with the given tag name.
    pub fn find_all(&self, name: &str) -> Vec<&Element> {
        let mut out: Vec<&Element> = std::iter::once(&self.root)
            .filter(|r| r.name == name)
            .collect();
        out.extend(self.root.find_all(name));
        out
    }
}

/// Parse a binary XML document.
pub fn parse(bytes: &[u8]) -> Result<AxmlDocument> {
    let (typ, header_size, total) = chunk_header(bytes, 0)?;
    if typ != RES_XML_TYPE {
        return Err(Error::BadAxmlMagic { found: bytes[..2.min(bytes.len())].to_vec() });
    }
    if header_size < 8 || (total as usize) > bytes.len() {
        return Err(Error::BadChunkSize { chunk: typ, size: total });
    }
    let end = total as usize;

    let mut pool: Option<StringPool> = None;
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    // A prefix -> URI map, so that attribute names can be qualified.
    let mut bindings: Vec<(String, String)> = Vec::new();

    let mut at = header_size as usize;
    while at + 8 <= end {
        let (typ, node_header, size) = chunk_header(bytes, at)?;
        if node_header < 8 || size < node_header as u32 {
            return Err(Error::BadChunkSize { chunk: typ, size });
        }
        let node_end = (at as u32).checked_add(size).ok_or(Error::BadChunkSize { chunk: typ, size })?;
        if node_end as usize > end {
            return Err(Error::BadChunkSize { chunk: typ, size });
        }
        let node = &bytes[at..node_end as usize];

        match typ {
            RES_STRING_POOL_TYPE => {
                // The string pool has to be the first chunk; nothing before it
                // can be resolved without it.
                if pool.is_some() {
                    return Err(Error::BadChunkSize { chunk: typ, size });
                }
                pool = Some(parse_string_pool(node)?);
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                let ids = parse_resource_map(node)?;
                if let Some(p) = pool.as_mut() {
                    p.resource_ids = ids;
                } else {
                    return Err(Error::BadChunkSize { chunk: typ, size });
                }
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let (prefix, uri) = namespace_pair(node, node_header, pool.as_ref())?;
                bindings.push((prefix.clone(), uri.clone()));
                namespaces.push((prefix, uri));
            }
            RES_XML_END_NAMESPACE_TYPE => {
                let (prefix, _) = namespace_pair(node, node_header, pool.as_ref())?;
                bindings.retain(|(p, _)| *p != prefix);
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool_ref = pool.as_ref().ok_or(Error::BadChunkSize { chunk: typ, size })?;
                stack.push(parse_start_element(node, node_header, pool_ref, &bindings)?);
            }
            RES_XML_END_ELEMENT_TYPE => {
                let pool_ref = pool.as_ref().ok_or(Error::BadChunkSize { chunk: typ, size })?;
                let name = element_name(node, node_header, pool_ref, &bindings)?;
                let el = stack.pop().ok_or(Error::BadChunkSize { chunk: typ, size })?;
                if el.name != name {
                    return Err(Error::BadAxmlString(usize::MAX));
                }
                // Close it against its parent, or make it the root.
                match stack.last_mut() {
                    Some(parent) => parent.children.push(el),
                    None if root.is_none() => root = Some(el),
                    None => return Err(Error::BadChunkSize { chunk: typ, size }),
                }
            }
            RES_XML_CDATA_TYPE => { /* character data is not meaningful here */ }
            _ => { /* unknown chunk types are skipped, as aapt2 expects */ }
        }
        at = node_end as usize;
    }

    let root = root.ok_or(Error::BadChunkSize { chunk: typ, size: total })?;
    let pool = pool.ok_or(Error::BadChunkSize { chunk: typ, size: total })?;
    Ok(AxmlDocument { root, strings: pool, namespaces })
}

fn chunk_header(bytes: &[u8], at: usize) -> Result<(u16, u16, u32)> {
    if at + 8 > bytes.len() {
        return Err(Error::Truncated { what: "AXML chunk header", need: at + 8, have: bytes.len() });
    }
    let typ = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    let header_size = u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]);
    let size = u32::from_le_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
    Ok((typ, header_size, size))
}

/// Parse a `ResStringPool_header` plus its string data.
fn parse_string_pool(chunk: &[u8]) -> Result<StringPool> {
    // ResStringPool_header is 28 bytes: the chunk header, stringCount, styleCount,
    // flags, stringsStart, then stylesStart.
    if chunk.len() < 28 {
        return Err(Error::Truncated { what: "AXML string pool header", need: 28, have: chunk.len() });
    }
    let rd = |o: usize| u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
    let string_count = rd(8);
    let _style_count = rd(12);
    let flags = rd(16);
    let strings_start = rd(20);
    // A pool with more strings than the chunk can hold is malformed; bail before
    // allocating on the strength of the declared count. The bound is the same for
    // both encodings because both prefix each string with a two-byte offset
    // array entry, and the real entries are never smaller than that.
    let max = chunk.len().saturating_sub(strings_start as usize) / 2 + 1;
    if string_count as usize > max.max(1) {
        return Err(Error::Truncated {
            what: "AXML string pool data",
            need: strings_start as usize + (string_count as usize) * 4,
            have: chunk.len(),
        });
    }

    let offsets_start = 28usize;
    let mut strings = Vec::with_capacity((string_count as usize).min(4096));
    for i in 0..string_count as usize {
        let o = offsets_start + i * 4;
        if o + 4 > chunk.len() {
            return Err(Error::BadAxmlString(i));
        }
        let off = u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]) as usize;
        let abs = strings_start as usize + off;
        if abs >= chunk.len() {
            return Err(Error::BadAxmlString(i));
        }
        let s = if flags & UTF8_FLAG != 0 {
            decode_pool_utf8(&chunk[abs..], i)?
        } else {
            decode_pool_utf16(&chunk[abs..], i)?
        };
        strings.push(s);
    }
    Ok(StringPool { strings, resource_ids: Vec::new() })
}

fn decode_pool_utf16(b: &[u8], index: usize) -> Result<String> {
    // Two little-endian lengths, in UTF-16 code units and in bytes, then the
    // UTF-16 data, then a terminating 0x0000.
    let (char_len, n) = read_len16(b).ok_or(Error::BadAxmlString(index))?;
    let (_byte_len, n2) = read_len16(&b[n..]).ok_or(Error::BadAxmlString(index))?;
    let data = &b[n + n2..];
    let units = (char_len as usize).min(data.len() / 2);
    let mut u16s = Vec::with_capacity(units);
    for i in 0..units {
        u16s.push(u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]));
    }
    Ok(String::from_utf16_lossy(&u16s))
}

fn decode_pool_utf8(b: &[u8], index: usize) -> Result<String> {
    // Same shape, with the two lengths in characters and bytes. The bytes are
    // *not* NUL-terminated, so the declared length bounds the slice.
    let (char_len, n) = read_len8(b).ok_or(Error::BadAxmlString(index))?;
    let (byte_len, n2) = read_len8(&b[n..]).ok_or(Error::BadAxmlString(index))?;
    let data = &b[n + n2..n + n2 + (byte_len as usize).min(b.len().saturating_sub(n + n2))];
    let s = String::from_utf8_lossy(data).into_owned();
    // `char_len` counts UTF-16 units, which can exceed the character count for
    // astral characters; only truncate when it is genuinely smaller.
    if char_len as usize >= s.chars().count() {
        Ok(s)
    } else {
        Ok(s.chars().take(char_len as usize).collect())
    }
}

/// Read a `u16` length, accepting the 1- and 2-byte variable-width encodings
/// AAPT2 emits.
fn read_len16(b: &[u8]) -> Option<(u32, usize)> {
    let a = *b.first()?;
    if a & 0x80 == 0 {
        Some((a as u16 as u32, 1))
    } else if a & 0xc0 == 0x80 {
        Some(((((a & 0x3f) as u32) << 8) | *b.get(1)? as u32, 2))
    } else {
        None
    }
}

/// Read a `u8` length, accepting the 1- and 2-byte encodings.
fn read_len8(b: &[u8]) -> Option<(u32, usize)> {
    let a = *b.first()?;
    if a & 0x80 == 0 {
        Some((a as u32, 1))
    } else if a & 0xc0 == 0x80 {
        Some(((((a & 0x3f) as u32) << 8) | *b.get(1)? as u32, 2))
    } else {
        None
    }
}

/// Parse a `ResTable_resource_map`, which is a bare array of `u32` ids.
fn parse_resource_map(chunk: &[u8]) -> Result<Vec<u32>> {
    let header_size = u16::from_le_bytes([chunk[2], chunk[3]]) as usize;
    if header_size < 8 {
        return Err(Error::BadChunkSize { chunk: RES_XML_RESOURCE_MAP_TYPE, size: chunk.len() as u32 });
    }
    let body = chunk
        .get(header_size..)
        .ok_or(Error::Truncated { what: "AXML resource map", need: header_size, have: chunk.len() })?;
    Ok(body
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// Extract the prefix and URI from a `ResXMLTree_namespaceExtChunk`.
fn namespace_pair(node: &[u8], header: u16, pool: Option<&StringPool>) -> Result<(String, String)> {
    let pool = pool.ok_or(Error::Truncated { what: "AXML namespace", need: header as usize, have: node.len() })?;
    let prefix = pool_string(pool, rd32(node, header as usize))?;
    let uri = pool_string(pool, rd32(node, header as usize + 4))?;
    Ok((prefix, uri))
}

/// Qualified name of a start/end element, from `ResXMLTree_attrExt`.
fn element_name(
    node: &[u8],
    header: u16,
    pool: &StringPool,
    bindings: &[(String, String)],
) -> Result<String> {
    let ns = rd32(node, header as usize);
    let name = rd32(node, header as usize + 4);
    Ok(qualify(pool_string(pool, name)?, &pool_string(pool, ns)?, bindings))
}

fn parse_start_element(
    node: &[u8],
    header: u16,
    pool: &StringPool,
    bindings: &[(String, String)],
) -> Result<Element> {
    let base = header as usize;
    // ResXMLTree_attrExt is: ns (u32), name (u32), then attributeStart,
    // attributeSize, attributeCount, idIndex, classIndex and styleIndex — all
    // *uint16*, not uint32. attributeStart is measured from the start of this
    // structure.
    let name_idx = rd32(node, base + 4);
    let attribute_start = rd16(node, base + 8) as usize;
    let attribute_size = rd16(node, base + 10) as usize;
    let attribute_count = rd16(node, base + 12) as usize;

    // ResXMLTree_attribute is ns, name, rawValue (u32 each) then a Res_value
    // of 8 bytes, so 20 bytes in total.
    if attribute_size < 20 {
        return Err(Error::BadAxmlString(usize::MAX));
    }
    let mut attributes = Vec::with_capacity(attribute_count.min(1024));
    for i in 0..attribute_count {
        let o = base + attribute_start + i * attribute_size;
        if o + 20 > node.len() {
            return Err(Error::Truncated { what: "AXML attribute", need: o + 20, have: node.len() });
        }
        // ResXMLTree_attribute: ns, name, rawValue, then a 4-byte Res_value
        // (u16 size, u8 res0, u8 dataType, u32 data).
        let ns = rd32(node, o);
        let attr_name = rd32(node, o + 4);
        let raw_idx = rd32(node, o + 8);
        let data_type = node[o + 15];
        let data = rd32(node, o + 16);
        let resolved_name = qualify(
            pool_string(pool, attr_name)?,
            &pool_string(pool, ns)?,
            bindings,
        );
        attributes.push(Attribute {
            resource_id: pool.resource_ids.get(attr_name as usize).copied(),
            raw_value_idx: if raw_idx == NO_STRING { None } else { Some(raw_idx as usize) },
            raw_value: if raw_idx == NO_STRING {
                None
            } else {
                Some(pool_string(pool, raw_idx).unwrap_or_default())
            },
            name: resolved_name,
            value: decode_typed_value(data_type, data, pool),
        });
    }

    Ok(Element {
        name: qualify(
            pool_string(pool, name_idx)?,
            &pool_string(pool, rd32(node, base))?,
            bindings,
        ),
        namespaces: bindings.iter().map(|(p, u)| format!("{p}={u}")).collect(),
        attributes,
        children: Vec::new(),
    })
}

/// Decode a `Res_value` into a typed [`AttributeValue`].
///
/// Type tags follow `android.util.TypedValue`: 0x03 is a string, 0x10 an int,
/// 0x11 a hex int, 0x12 a boolean, 0x1c an attribute, 0x1d a colour and 0x01 a
/// reference. AAPT2 stores booleans as 0xFFFFFFFF or 0.
fn decode_typed_value(data_type: u8, data: u32, pool: &StringPool) -> AttributeValue {
    match data_type {
        0x03 => match pool.strings.get(data as usize) {
            Some(s) => AttributeValue::String(s.clone()),
            None => AttributeValue::Null,
        },
        0x01 | 0x02 => AttributeValue::Reference(data),
        0x04 => AttributeValue::Float(f32::from_bits(data)),
        0x05 => AttributeValue::Double(f64::from_bits(data as u64)),
        0x06 => AttributeValue::Long(data as i32 as i64),
        0x10 => AttributeValue::Int(data as i32),
        0x11 => AttributeValue::Int(data as i32),
        0x12 => AttributeValue::Int((data != 0) as i32),
        0x1c => AttributeValue::Attribute(data),
        0x1d => AttributeValue::Color(data),
        _ => AttributeValue::Raw { data_type, data },
    }
}

fn qualify(local: String, ns: &str, bindings: &[(String, String)]) -> String {
    if ns.is_empty() {
        return local;
    }
    match bindings.iter().find(|(_, uri)| uri == ns) {
        Some((prefix, _)) => format!("{prefix}:{local}"),
        None => local,
    }
}

/// `0xFFFFFFFF` in a string field means "absent", not "index 4294967295".
const NO_STRING: u32 = 0xffff_ffff;

fn pool_string(pool: &StringPool, idx: u32) -> Result<String> {
    if idx == NO_STRING {
        return Ok(String::new());
    }
    pool.strings
        .get(idx as usize)
        .cloned()
        .ok_or(Error::Truncated { what: "AXML string index", need: idx as usize, have: pool.strings.len() })
}

fn rd16(b: &[u8], o: usize) -> u16 {
    if o + 2 > b.len() {
        return u16::MAX;
    }
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn rd32(b: &[u8], o: usize) -> u32 {
    if o + 4 > b.len() {
        return u32::MAX;
    }
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Every chunk type this module understands, for tests and diagnostics.
pub const KNOWN_CHUNK_TYPES: [u16; 7] = [
    RES_XML_TYPE,
    RES_STRING_POOL_TYPE,
    RES_XML_RESOURCE_MAP_TYPE,
    RES_XML_START_NAMESPACE_TYPE,
    RES_XML_END_NAMESPACE_TYPE,
    RES_XML_START_ELEMENT_TYPE,
    RES_XML_END_ELEMENT_TYPE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_lengths_decode() {
        // One byte when the top bit is clear.
        assert_eq!(read_len16(&[0x05, 0, 0, 0]), Some((5, 1)));
        assert_eq!(read_len8(&[0x7f, 0, 0, 0]), Some((0x7f, 1)));
        // Two bytes when it is set: the value is ((a & 0x3f) << 8) | b.
        assert_eq!(read_len16(&[0x85, 0x01, 0, 0]), Some((0x501, 2)));
        assert_eq!(read_len8(&[0x85, 0x01, 0, 0]), Some((0x501, 2)));
        assert_eq!(read_len16(&[]), None);
        assert_eq!(read_len8(&[]), None);
        assert_eq!(read_len8(&[0x00]), Some((0, 1)));
    }

    #[test]
    fn rejects_non_axml_input() {
        let mut b = vec![0u8; 32];
        b[0] = 0xff;
        b[1] = 0xff;
        assert!(matches!(parse(&b), Err(Error::BadAxmlMagic { .. })));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(matches!(parse(&[]), Err(Error::Truncated { .. })));
        assert!(matches!(parse(&[0x03, 0x00]), Err(Error::Truncated { .. })));
    }

    #[test]
    fn rejects_oversized_chunk() {
        // A root chunk claiming 0x10000 bytes in a 32-byte buffer.
        let mut b = vec![0u8; 32];
        b[0..2].copy_from_slice(&RES_XML_TYPE.to_le_bytes());
        b[2..4].copy_from_slice(&8u16.to_le_bytes());
        b[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
        assert!(matches!(parse(&b), Err(Error::BadChunkSize { .. })));
    }

    #[test]
    fn attribute_values_render_as_text() {
        assert_eq!(AttributeValue::Int(-1).as_text().unwrap(), "-1");
        assert_eq!(AttributeValue::String("x".into()).as_text().unwrap(), "x");
        assert_eq!(AttributeValue::Color(0xff00ff00).as_text().unwrap(), "#ff00ff00");
        assert_eq!(AttributeValue::Reference(0x7f010001).as_text().unwrap(), "@7f010001");
        assert_eq!(AttributeValue::Null.as_text(), None);
    }
}
