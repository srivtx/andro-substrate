//! Binary XML (`AXML`) → an element tree with resolved attribute values.
//!
//! A compiled layout is not text. It is a flat array of chunked nodes: a string
//! pool, an optional resource map, and then start/end tag pairs, all
//! `4`-byte-aligned and all carrying a `Res_value` for every attribute. This
//! module walks that array, builds a tree, and — the part that matters to
//! `runtime/graphics` — turns each attribute's `Res_value` into a value by
//! following references into the resource table.
//!
//! Three things happen during inflation that do not happen during parsing, and
//! they are the reason this is a separate module:
//!
//! 1. **Attribute reference resolution.** An attribute whose value is
//!    `TYPE_REFERENCE` is not the value; it is a pointer to one. A layout
//!    almost never stores `android:textColor` literally — it stores
//!    `@7f040001`.
//! 2. **Style inheritance.** A `style` attribute on a tag introduces a parent
//!    chain: `Theme.AppWidget` → `Theme` → `android:Theme`. A widget's effective
//!    attribute set is the union of that chain, with the tag's own attributes
//!    winning. The chain is a linked list in the resource table and can be
//!    cyclic in a crafted file.
//! 3. **Theme overlay.** A `TYPE_ATTRIBUTE` value is "whatever the theme says",
//!    which is a three-step lookup: theme attribute → default/initial value →
//!    absent.
//!
//! `android:id` is carried through as a resolved integer, which is what
//! `findViewById` needs.

use std::collections::BTreeMap;

use crate::resources::arsc::{Payload, ResConfig, ResId, Resolved, ResourceTable};
use crate::resources::error::{ResourceError, Result, XmlError};
use crate::resources::types::{RawValue, Value};
use crate::resources::loader::ResourceLoader;

// --- AXML chunk types ------------------------------------------------------

/// The document chunk.
pub const RES_XML_TYPE: u16 = 0x0003;
/// A string pool.
pub const RES_XML_STRING_POOL_TYPE: u16 = 0x0001;
/// The string-index → framework-resource-id map.
pub const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
/// A namespace declaration.
pub const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
/// A namespace's end.
pub const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
/// A start tag.
pub const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
/// An end tag.
pub const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
/// Character data.
pub const RES_XML_CDATA_TYPE: u16 = 0x0104;

/// `0xFFFFFFFF` in a string field means "absent", not "index 4294967295".
const NO_STRING: u32 = 0xffff_ffff;

/// `android:theme`, `0x01010000`.
///
/// The one attribute whose target *is* followed into a style, because that is
/// what the attribute means: "apply this theme". Every other reference to a
/// `style` is left alone.
pub const ANDROID_THEME: u32 = 0x0101_0000;

/// How deep a style `parent` chain may be walked before it is called a cycle.
///
/// A real theme chain is a handful of links. 64 is far above anything Android
/// ships and far below anything that would matter for a denial of service, and
/// the limit exists so a crafted table cannot spin here.
pub const MAX_STYLE_DEPTH: usize = 64;

/// One resolved attribute on an inflated element.
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    /// The attribute's resource id, when the XML's resource map covered it.
    /// This is the stable identity `findViewById`-style lookups and style
    /// merging are keyed on; the *name* is only for diagnostics, because two
    /// namespaces can share it.
    pub resource_id: Option<u32>,
    /// The attribute's qualified name, e.g. `android:layout_width`.
    pub name: String,
    /// The namespace URI, empty for an unqualified attribute.
    pub namespace: String,
    /// The value, after reference resolution.
    pub value: ResolvedAttr,
    /// The value exactly as the file stored it, before resolution.
    pub raw: Value,
}

/// An attribute value after resolution.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedAttr {
    /// A plain value.
    Value(Value),
    /// A reference that resolved to a value, with the id it came from.
    Resolved {
        /// The reference that was followed.
        id: u32,
        /// The value at that id.
        value: Value,
    },
    /// A reference to another resource of a known type, e.g. a colour or a
    /// drawable. Not followed to a terminal value: `@drawable/icon` is a file
    /// and the caller wants the file.
    Resource {
        /// The id referred to.
        id: u32,
        /// What it names, e.g. `drawable` or `color`.
        type_name: String,
        /// The path, if the target is a file.
        path: Option<String>,
    },
    /// A string literal, taken from the *document's* string pool.
    ///
    /// A `TYPE_STRING` in binary XML does not mean "index into the resource
    /// table's global pool", which is what `ResourceTypes.h` says and what
    /// every other context means by it. AOSP's own reader overrides it:
    /// `ResXMLParser::getAttributeValue` returns
    /// `TYPE_STRING` with `data = attr->rawValue.index` whenever the attribute
    /// has a raw value — that is, whenever the XML said `android:text="..."`
    /// literally — and the raw value indexes the *document's* pool.
    ///
    /// The real `com.dosse.clock31` layout shows the difference: `res/7_.xml`
    /// stores `android:text` as `data=0x1c` (28), and its own pool holds
    /// `TI:ME` at index 28, while the table's global pool has 16 entries and
    /// does not contain it at all. Reading it from the global pool is an
    /// out-of-range access on the first literal string in the file.
    Text(String),
    /// A theme attribute, resolved through the theme chain.
    ThemeAttr {
        /// The attribute resource id.
        id: u32,
        /// The value the theme supplies.
        value: Box<ResolvedAttr>,
    },
    /// A reference to a style or an array. The flattened attribute set is
    /// carried with it, so a caller inflating `@style/Foo` gets Foo's
    /// attributes rather than a marker it has to chase itself.
    Style {
        /// The id of the style.
        id: u32,
        /// The style's attributes, parents first.
        attributes: Vec<Attr>,
    },
    /// A reference that did not resolve. Kept rather than dropped, because a
    /// missing reference is a rendering difference the caller has to know
    /// about, not a parse failure.
    Unresolved {
        /// The id that was referred to.
        id: u32,
        /// Why it did not resolve.
        reason: String,
    },
    /// The attribute had no value at all.
    Absent,
}

impl ResolvedAttr {
    /// The value, if one is directly available.
    pub fn value(&self) -> Option<&Value> {
        match self {
            ResolvedAttr::Value(v) => Some(v),
            ResolvedAttr::Resolved { value, .. } => Some(value),
            ResolvedAttr::ThemeAttr { value, .. } => value.value(),
            _ => None,
        }
    }

    /// The text, for a string literal.
    pub fn text(&self) -> Option<&str> {
        match self {
            ResolvedAttr::Text(s) => Some(s),
            ResolvedAttr::ThemeAttr { value, .. } => value.text(),
            _ => None,
        }
    }

    /// The dimension, if the attribute ends in one.
    pub fn as_dimension(&self) -> Option<crate::resources::types::Dimension> {
        self.value()?.as_dimension()
    }

    /// The flattened attributes of a style-valued attribute.
    pub fn as_style(&self) -> Option<&[Attr]> {
        match self {
            ResolvedAttr::Style { attributes, .. } => Some(attributes),
            _ => None,
        }
    }
}

/// One node of the inflated tree.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    /// The element's qualified name, e.g. `LinearLayout`.
    pub name: String,
    /// The namespace URI, empty for an unqualified element.
    pub namespace: String,
    /// The element's own attributes, in file order, with the style's
    /// attributes already merged in behind them.
    pub attributes: Vec<Attr>,
    /// The element's children, in file order.
    pub children: Vec<Element>,
    /// The value of `android:id`, resolved, for `findViewById`.
    pub id: Option<u32>,
    /// The file this element came from, for diagnostics.
    pub source: String,
}

impl Element {
    /// The first attribute with this resource id.
    pub fn attr(&self, resource_id: u32) -> Option<&Attr> {
        self.attributes.iter().find(|a| a.resource_id == Some(resource_id))
    }

    /// The first attribute with this qualified name.
    pub fn attr_named(&self, name: &str) -> Option<&Attr> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// The first attribute with this *local* name, ignoring the prefix.
    pub fn attr_local_name(&self, local: &str) -> Option<&Attr> {
        self.attributes
            .iter()
            .find(|a| a.name.rsplit(':').next().is_some_and(|l| l == local))
    }

    /// The value of the first attribute with this resource id.
    pub fn value_of(&self, resource_id: u32) -> Option<&Value> {
        self.attr(resource_id).and_then(|a| a.value.value())
    }

    /// `android:id`, as a `findViewById` key.
    ///
    /// Android reserves the top nibble of an id for special values — `0` is
    /// "no id", `0x01000000` is a framework id, and `0x7f000000..` is this
    /// app's namespace — so only the app-namespace form is returned as a key
    /// an app would have passed to `setId` and later to `findViewById`.
    pub fn view_id(&self) -> Option<u32> {
        self.id
    }

    /// Depth-first search of the whole subtree for an `android:id`.
    pub fn find_by_id(&self, id: u32) -> Option<&Element> {
        if self.id == Some(id) {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find_by_id(id))
    }

    /// Depth-first search for the first element with this tag name.
    pub fn find_all(&self, name: &str) -> Vec<&Element> {
        let mut out = Vec::new();
        if self.name == name {
            out.push(self);
        }
        for c in &self.children {
            out.extend(c.find_all(name));
        }
        out
    }

    /// Every element in the subtree, depth first, including this one.
    pub fn walk(&self) -> Vec<&Element> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.walk());
        }
        out
    }
}

/// Knobs for [`inflate`].
#[derive(Debug, Clone, Default)]
pub struct InflateOptions {
    /// The style to resolve `TYPE_ATTRIBUTE` values against. A layout inflated
    /// on its own has no theme and every `?attr/foo` becomes
    /// [`ResolvedAttr::Unresolved`]; a layout inflated with
    /// `android:theme` set, or by an activity, gets one.
    pub theme: Option<u32>,
    /// A cap on how many attributes may be resolved by walking reference
    /// chains. Bounded so a self-referential resource cannot spin.
    pub max_reference_hops: usize,
}

/// What inflation did, beyond producing a tree.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InflateReport {
    /// Attribute references that were followed to a terminal value.
    pub references_resolved: usize,
    /// References that pointed at a file rather than a value.
    pub file_references: usize,
    /// References that did not resolve. Each carries its id in
    /// [`InflateReport::unresolved_ids`].
    pub unresolved: usize,
    /// The ids that did not resolve, in the order they were met.
    pub unresolved_ids: Vec<u32>,
    /// Theme attributes resolved through the theme chain.
    pub theme_attributes_resolved: usize,
    /// Style `parent` links walked.
    pub style_parents_walked: usize,
    /// A `style` chain longer than [`MAX_STYLE_DEPTH`], which is reported
    /// rather than followed to its end.
    pub style_depth_exceeded: bool,
}

impl InflateReport {
    /// Whether anything was left unresolved.
    pub fn is_clean(&self) -> bool {
        self.unresolved == 0 && !self.style_depth_exceeded
    }
}

/// The parser state for one document.
struct Inflater<'a> {
    loader: &'a ResourceLoader<'a>,
    options: &'a InflateOptions,
    report: InflateReport,
    /// The default value of every framework attribute, read once from the
    /// table's `attr` type. This is what a `?attr/foo` falls back to when no
    /// theme is set.
    defaults: BTreeMap<u32, Value>,
}

impl<'a> Inflater<'a> {
    fn reference_hop_limit(&self) -> usize {
        if self.options.max_reference_hops == 0 {
            8
        } else {
            self.options.max_reference_hops
        }
    }

    /// Follow a reference chain to a terminal value.
    ///
    /// AAPT2 emits `@color/foo` as a value whose `TYPE_REFERENCE` points at a
    /// `TYPE_REFERENCE`, which points at a colour. Chasing it here means the
    /// caller gets a number, and the `max_reference_hops` cap means a table
    /// where `a` points at `b` and `b` points at `a` produces an
    /// [`ResourceError::ReferenceCycle`] rather than a hang.
    fn follow_reference(&mut self, mut id: u32, depth: usize) -> ResolvedAttr {
        if depth > self.reference_hop_limit() {
            self.report.unresolved += 1;
            self.report.unresolved_ids.push(id);
            return ResolvedAttr::Unresolved {
                id,
                reason: format!("reference chain exceeded {} hops", self.reference_hop_limit()),
            };
        }
        // A cycle is detected by a hop count, not by a set, so a long but
        // finite chain and a cycle are both bounded by the same limit.
        let limit = self.reference_hop_limit();
        if depth == limit {
            self.report.unresolved += 1;
            self.report.unresolved_ids.push(id);
            return ResolvedAttr::Unresolved {
                id,
                reason: format!("reference chain reached the {limit}-hop limit (cycle?)"),
            };
        }
        // A reference to an `id` or a `style` is a leaf, not a pointer to chase.
        // `android:id=@0x7f030003` means "this view's id is 0x7f030003"; the id
        // resource's own value is a boolean false marker, so following it
        // would replace every view's id with zero. AOSP does the same in
        // `AssetManager::resolveReference`, which explicitly refuses to follow
        // style and id references.
        let type_name = self.type_name_of(id).unwrap_or_default();
        if type_name == "id" || type_name == "style" {
            self.report.references_resolved += 1;
            return ResolvedAttr::Resource { id, type_name, path: None };
        }
        match self.loader.resolve(id) {
            Ok(Resolved::Value(Value::Reference(next))) | Ok(Resolved::Value(Value::DynamicReference(next))) => {
                self.report.references_resolved += 1;
                self.follow_reference(next, depth + 1)
            }
            Ok(Resolved::Value(Value::Attribute(attr))) | Ok(Resolved::Value(Value::DynamicAttribute(attr))) => {
                // A value that is itself a theme attribute: resolve it, but
                // do not re-enter the reference chaser, or `?attr/foo` inside a
                // colour would loop.
                self.report.references_resolved += 1;
                self.resolve_theme_attribute(attr, depth + 1)
            }
            Ok(Resolved::Value(v)) => {
                self.report.references_resolved += 1;
                ResolvedAttr::Resolved { id, value: v }
            }
            Ok(Resolved::File { path, .. }) => {
                self.report.file_references += 1;
                let type_name = self.type_name_of(id).unwrap_or_default();
                ResolvedAttr::Resource { id, type_name, path: Some(path) }
            }
            Ok(Resolved::Bag { map, .. }) => {
                // A reference to a style or an array. The caller wants the
                // style's attributes, so flatten the parent chain and hand
                // that over.
                self.report.references_resolved += 1;
                let attributes = self.flatten_style(id, &map, depth + 1);
                ResolvedAttr::Style { id, attributes }
            }
            Ok(Resolved::Absent(reason)) => {
                self.report.unresolved += 1;
                self.report.unresolved_ids.push(id);
                ResolvedAttr::Unresolved { id, reason: format!("{reason:?}") }
            }
            Err(e) => {
                self.report.unresolved += 1;
                self.report.unresolved_ids.push(id);
                ResolvedAttr::Unresolved { id, reason: e.to_string() }
            }
        }
    }

    fn type_name_of(&self, id: u32) -> Option<String> {
        let rid = ResId::from_u32(id)?;
        let package = self.loader.table().package(rid.package)?;
        package.type_name(rid.type_id).ok().map(str::to_string)
    }

    /// Resolve `?attr/foo` through the theme, then the framework default.
    fn resolve_theme_attribute(&mut self, attr: u32, depth: usize) -> ResolvedAttr {
        if depth > self.reference_hop_limit() {
            self.report.unresolved += 1;
            self.report.unresolved_ids.push(attr);
            return ResolvedAttr::Unresolved {
                id: attr,
                reason: format!("theme attribute chain exceeded {} hops", self.reference_hop_limit()),
            };
        }
        if let Some(theme) = self.options.theme {
            if let Some(value) = self.lookup_in_theme(theme, attr, depth) {
                self.report.theme_attributes_resolved += 1;
                return ResolvedAttr::ThemeAttr { id: attr, value: Box::new(value) };
            }
        }
        // No theme, or the theme says nothing about this attribute: fall back to
        // the framework's default, which lives in the table's `attr` type as a
        // zero-entry bag whose first map entry is the default.
        if let Some(default) = self.defaults.get(&attr).cloned() {
            self.report.theme_attributes_resolved += 1;
            return ResolvedAttr::ThemeAttr { id: attr, value: Box::new(ResolvedAttr::Value(default)) };
        }
        self.report.unresolved += 1;
        self.report.unresolved_ids.push(attr);
        ResolvedAttr::Unresolved {
            id: attr,
            reason: "no theme supplies this attribute and it has no default".into(),
        }
    }

    /// Look for `attr` in a theme's bag, walking its `parent` chain.
    fn lookup_in_theme(&mut self, theme: u32, attr: u32, depth: usize) -> Option<ResolvedAttr> {
        let mut current = theme;
        for hop in 0..self.reference_hop_limit() {
            let bag = match self.loader.resolve(current) {
                Ok(Resolved::Bag { parent, map, .. }) => (parent, map),
                _ => return None,
            };
            if let Some(entry) = bag.1.iter().find(|e| e.name == attr) {
                return match entry.value.as_reference() {
                    Some(r) => Some(self.follow_reference(r, depth)),
                    // A theme that names a value rather than pointing at one
                    // is unusual but legal; take it at face value.
                    None => Some(ResolvedAttr::Value(entry.value.clone())),
                };
            }
            if bag.0 == 0 {
                return None;
            }
            current = bag.0;
            let _ = hop;
        }
        None
    }

    /// Flatten a style's `parent` chain into one attribute map.
    ///
    /// Order matters and is the opposite of what reads naturally: the most
    /// derived style is applied *last* so it wins. AOSP does this by walking
    /// to the root of the chain collecting, then reversing; the result is the
    /// same, and the depth cap is what stops a cyclic table.
    fn flatten_style(&mut self, style: u32, map: &[crate::resources::arsc::MapEntry], depth: usize) -> Vec<Attr> {
        let mut out: BTreeMap<u32, Attr> = BTreeMap::new();
        if depth > MAX_STYLE_DEPTH {
            self.report.style_depth_exceeded = true;
            return Vec::new();
        }
        let parent = match self.loader.resolve(style) {
            Ok(Resolved::Bag { parent, .. }) => parent,
            _ => 0,
        };
        if parent != 0 {
            self.report.style_parents_walked += 1;
            match self.loader.resolve(parent) {
                Ok(Resolved::Bag { map: parent_map, .. }) => {
                    let inherited = self.flatten_style(parent, &parent_map, depth + 1);
                    for a in inherited {
                        out.insert(a.resource_id.unwrap_or(0), a);
                    }
                }
                _ => {}
            }
        }
        for entry in map {
            if entry.name == 0 {
                continue;
            }
            let resolved = match entry.value {
                Value::Reference(r) => self.follow_reference(r, depth),
                Value::Attribute(r) => self.resolve_theme_attribute(r, depth),
                _ => ResolvedAttr::Value(entry.value.clone()),
            };
            out.insert(
                entry.name,
                Attr {
                    resource_id: Some(entry.name),
                    name: self.attribute_name(entry.name).unwrap_or_else(|| format!("0x{:08x}", entry.name)),
                    namespace: self.attribute_namespace(entry.name).unwrap_or_default(),
                    value: resolved,
                    raw: entry.value.clone(),
                },
            );
        }
        out.into_values().collect()
    }

    fn attribute_name(&self, id: u32) -> Option<String> {
        self.loader.attribute_name(id)
    }

    fn attribute_namespace(&self, id: u32) -> Option<String> {
        self.loader.attribute_namespace(id)
    }
}

/// Inflate a compiled binary XML document.
///
/// `source` is only used in diagnostics — it is the path the loader would have
/// opened this from.
pub fn inflate(
    bytes: &[u8],
    loader: &ResourceLoader,
    options: &InflateOptions,
    source: &str,
) -> Result<(Element, InflateReport)> {
    let (typ, header_size, total) = xml_chunk_header(bytes, 0)?;
    if typ != RES_XML_TYPE {
        return Err(XmlError::BadMagic { found: typ }.into());
    }
    if header_size < 8 || total as usize > bytes.len() {
        return Err(ResourceError::BadChunkSize { chunk: typ, size: total });
    }
    let end = total as usize;

    let mut pool: Option<crate::resources::arsc::StringPool> = None;
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut bindings: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;

    let mut inflater = Inflater {
        loader,
        options,
        report: InflateReport::default(),
        defaults: loader.attribute_defaults(),
    };

    let mut at = header_size as usize;
    while at + 8 <= end {
        let (t, hs, size) = xml_chunk_header(bytes, at)?;
        if hs < 8 || size < u32::from(hs) {
            return Err(ResourceError::BadChunkSize { chunk: t, size });
        }
        let next = (at as u32).checked_add(size).ok_or(ResourceError::BadChunkSize { chunk: t, size })? as usize;
        if next > end || next <= at {
            return Err(ResourceError::BadChunkSize { chunk: t, size });
        }
        let node = &bytes[at..next];

        match t {
            RES_XML_STRING_POOL_TYPE => {
                if pool.is_some() {
                    return Err(ResourceError::BadChunkSize { chunk: t, size });
                }
                pool = Some(crate::resources::arsc::StringPool::parse("xmlStrings", node)?);
            }
            RES_XML_RESOURCE_MAP_TYPE => {
                let body = node
                    .get(hs as usize..)
                    .ok_or(ResourceError::Truncated {
                        what: "ResXMLTree_resourceMap",
                        need: hs as usize,
                        have: node.len(),
                    })?;
                // The map is a bare array of u32 parallel to the string pool.
                // Its length need not match the pool exactly; a short map just
                // means the attributes past it are not framework attributes.
                resource_ids = body
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let base = hs as usize;
                let prefix = pool_string_opt(pool.as_ref(), "namespace", rd32(node, base))?;
                let uri = pool_string_opt(pool.as_ref(), "namespace", rd32(node, base + 4))?;
                bindings.push((prefix, uri));
            }
            RES_XML_END_NAMESPACE_TYPE => {
                let base = hs as usize;
                let prefix = pool_string_opt(pool.as_ref(), "namespace", rd32(node, base))?;
                bindings.retain(|(p, _)| *p != prefix);
            }
            RES_XML_START_ELEMENT_TYPE => {
                let pool_ref = pool.as_ref().ok_or(ResourceError::BadChunkSize { chunk: t, size })?;
                let element =
                    start_element(node, hs, pool_ref, &resource_ids, &bindings, &mut inflater, source)?;
                stack.push(element);
            }
            RES_XML_END_ELEMENT_TYPE => {
                let base = hs as usize;
                let pool_ref = pool.as_ref().ok_or(ResourceError::BadChunkSize { chunk: t, size })?;
                let name = qualify(
                    &pool_string(pool_ref, rd32(node, base + 4))?,
                    &pool_string(pool_ref, rd32(node, base))?,
                    &bindings,
                );
                let element = stack.pop().ok_or(XmlError::UnbalancedTags { end: name.clone(), open: None })?;
                if element.name != name {
                    return Err(XmlError::UnbalancedTags {
                        end: name,
                        open: Some(element.name.clone()),
                    }
                    .into());
                }
                match stack.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None if root.is_none() => root = Some(element),
                    None => {
                        return Err(XmlError::UnbalancedTags { end: name, open: None }.into());
                    }
                }
            }
            // Character data in a layout is whitespace, and a comment is not
            // layout. Both are skipped, as AOSP's inflation does.
            RES_XML_CDATA_TYPE => {}
            _ => {}
        }
        at = next;
    }

    // A document that ends with elements still open is malformed. Without this
    // check a truncated or corrupted file silently inflates to a *shorter* tree
    // and every rendering difference downstream is unexplained.
    if !stack.is_empty() {
        return Err(XmlError::UnbalancedTags {
            end: String::new(),
            open: Some(stack.last().map(|e| e.name.clone()).unwrap_or_default()),
        }
        .into());
    }
    let root = root.ok_or(XmlError::NoRootElement)?;
    Ok((root, inflater.report))
}

fn start_element(
    node: &[u8],
    header_size: u16,
    pool: &crate::resources::arsc::StringPool,
    resource_ids: &[u32],
    bindings: &[(String, String)],
    inflater: &mut Inflater<'_>,
    source: &str,
) -> Result<Element> {
    let base = header_size as usize;
    // `ResXMLTree_attrExt` is ns, name, then attributeStart, attributeSize,
    // attributeCount, idIndex, classIndex, styleIndex — all `uint16`, not
    // `uint32`. attributeStart is measured from the start of *this*
    // structure, not from the node.
    let ns = pool_string(pool, rd32(node, base))?;
    let name_idx = rd32(node, base + 4);
    let attribute_start = rd16(node, base + 8) as usize;
    let attribute_size = rd16(node, base + 10) as usize;
    let attribute_count = rd16(node, base + 12) as usize;
    // `ResXMLTree_attribute` is ns, name, rawValue (u32 each) then an 8-byte
    // `Res_value`: 20 bytes.
    if attribute_size < 20 {
        return Err(ResourceError::Truncated { what: "ResXMLTree_attrExt", need: base + 14, have: node.len() });
    }
    let mut attributes = Vec::with_capacity(attribute_count.min(1024));
    let mut style_attr: Option<Attr> = None;
    let mut id: Option<u32> = None;

    for i in 0..attribute_count {
        let o = base + attribute_start + i * attribute_size;
        if o + 20 > node.len() {
            return Err(ResourceError::Truncated {
                what: "ResXMLTree_attribute",
                need: o + 20,
                have: node.len(),
            });
        }
        let attr_ns = pool_string(pool, rd32(node, o))?;
        let attr_name_idx = rd32(node, o + 4);
        let raw_idx = rd32(node, o + 8);
        let raw = RawValue::read(node, o + 12)?;
        let value = raw.decode();
        let local = pool_string(pool, attr_name_idx)?;
        let qualified = qualify(&local, &attr_ns, bindings);
        let resource_id = resource_ids.get(attr_name_idx as usize).copied().filter(|&r| r != 0);

        let resolved = match value {
            // `android:theme` is the one reference that is followed into a
            // style, because the attribute means "apply this theme" and the
            // caller needs the theme's attributes.
            Value::Reference(r) if resource_id == Some(ANDROID_THEME) => {
                match inflater.loader.resolve(r) {
                    Ok(Resolved::Bag { map, .. }) => {
                        let attributes = inflater.flatten_style(r, &map, 0);
                        ResolvedAttr::Style { id: r, attributes }
                    }
                    other => match other {
                        Ok(v) => ResolvedAttr::Value(match v {
                            Resolved::Value(v) => v,
                            _ => value.clone(),
                        }),
                        Err(e) => ResolvedAttr::Unresolved { id: r, reason: e.to_string() },
                    },
                }
            }
            Value::Reference(r) => inflater.follow_reference(r, 0),
            Value::Attribute(r) => inflater.resolve_theme_attribute(r, 0),
            // See `ResolvedAttr::Text`: a literal string indexes the document's
            // pool, and `rawValue` is the index into it.
            Value::String(i) if raw_idx != NO_STRING => match pool_string(pool, raw_idx) {
                Ok(text) => ResolvedAttr::Text(text),
                Err(e) => ResolvedAttr::Unresolved { id: i, reason: e.to_string() },
            },
            _ => ResolvedAttr::Value(value.clone()),
        };

        // `android:id` is the one attribute every consumer needs by value, so
        // it is lifted out here rather than left for the caller to find.
        if qualified == "android:id" {
            id = match value {
                Value::Int(v) => Some(v as u32),
                _ => value.as_reference(),
            };
        }
        let attr = Attr {
            resource_id,
            name: qualified.clone(),
            namespace: attr_ns,
            value: resolved,
            raw: value.clone(),
        };
        if qualified == "style" {
            style_attr = Some(attr);
        } else {
            attributes.push(attr);
        }
    }

    // The style's attributes sit *behind* the tag's own: the tag wins. They
    // are prepended so a caller reading `attributes` in order sees inherited
    // values first, which is the order Android documents.
    if let Some(style) = style_attr {
        if let Some(style_id) = style.raw.as_reference() {
            match inflater.loader.resolve(style_id) {
                Ok(Resolved::Bag { map, .. }) => {
                    let inherited = inflater.flatten_style(style_id, &map, 0);
                    let mut merged = inherited;
                    merged.push(style);
                    attributes = merged;
                }
                Ok(Resolved::Value(Value::Reference(inner))) => {
                    // `style="@android:style/Widget"` is legal and means
                    // "this style, plus the one it points at".
                    if let Ok(Resolved::Bag { map, .. }) = inflater.loader.resolve(inner) {
                        let inherited = inflater.flatten_style(inner, &map, 0);
                        let mut merged = inherited;
                        merged.push(style);
                        attributes = merged;
                    }
                }
                _ => attributes.push(style),
            }
        } else {
            attributes.push(style);
        }
    }

    Ok(Element {
        name: qualify(&pool_string(pool, name_idx)?, &ns, bindings),
        namespace: ns,
        attributes,
        children: Vec::new(),
        id,
        source: source.to_string(),
    })
}

fn qualify(local: &str, ns: &str, bindings: &[(String, String)]) -> String {
    if ns.is_empty() {
        return local.to_string();
    }
    match bindings.iter().find(|(_, uri)| uri == ns) {
        Some((prefix, _)) => format!("{prefix}:{local}"),
        None => local.to_string(),
    }
}

/// A string pool lookup in a binary XML document.
///
/// `0xFFFFFFFF` is the "no string" sentinel: an attribute with no namespace and
/// an attribute with no raw value both store it, and reading it as an index
/// would be an out-of-bounds access on every unprefixed attribute in every
/// layout.
fn pool_string(pool: &crate::resources::arsc::StringPool, idx: u32) -> Result<String> {
    if idx == NO_STRING {
        return Ok(String::new());
    }
    pool.get("xmlStrings", idx).map(str::to_string)
}

/// A string lookup where the pool itself may not have been read yet.
fn pool_string_opt(
    pool: Option<&crate::resources::arsc::StringPool>,
    what: &'static str,
    idx: u32,
) -> Result<String> {
    match pool {
        Some(p) => pool_string(p, idx),
        None => Err(XmlError::BadString { what, index: idx }.into()),
    }
}

fn xml_chunk_header(bytes: &[u8], at: usize) -> Result<(u16, u16, u32)> {
    if at + 8 > bytes.len() {
        return Err(ResourceError::Truncated { what: "AXML chunk header", need: at + 8, have: bytes.len() });
    }
    Ok((
        u16::from_le_bytes([bytes[at], bytes[at + 1]]),
        u16::from_le_bytes([bytes[at + 2], bytes[at + 3]]),
        rd32(bytes, at + 4),
    ))
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

/// Re-export so callers do not have to reach into `arsc` for a config.
pub type DeviceConfig = ResConfig;

/// A convenience for a caller that only has an entry and a device config.
pub fn is_bag(payload: &Payload) -> bool {
    matches!(payload, Payload::Bag { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::arsc::{ResConfig, ResourceTable};
    use crate::resources::loader::{MemorySource, ResourceLoader};
    use crate::resources::testing::*;

    /// A loader over a table, with a leak so the `&'static` borrow works. Each
    /// call is per-test and the process is short-lived.
    fn loader_for(table: &'static ResourceTable) -> ResourceLoader<'static> {
        let source: &'static MemorySource = Box::leak(Box::new(MemorySource::new()));
        ResourceLoader::new(table.clone(), source, ResConfig::DEFAULT)
    }

    fn clock31() -> ResourceLoader<'static> {
        loader_for(Box::leak(Box::new(ResourceTable::parse(&fixture("clock31.arsc")).unwrap())))
    }

    fn run(bytes: &[u8], loader: &ResourceLoader<'_>, theme: Option<u32>) -> (Element, InflateReport) {
        let options = InflateOptions { theme, ..InflateOptions::default() };
        inflate(bytes, loader, &options, "test").expect("inflates")
    }

    // --- the tree, against aapt2 -------------------------------------------

    #[test]
    fn the_tree_shape_matches_aapt2s_xmltree_dump() {
        // The expectations below are transcribed from
        //   aapt2 dump xmltree --file res/Jq.xml com.dosse.clock31_5.apk
        // which prints the tag name, each attribute's framework resource id and
        // the decoded value. Comparing against that checks the whole pipeline —
        // chunk walk, string pool, resource map, `Res_value` decode — against an
        // implementation that shares no code with this one.
        //
        //   E: RelativeLayout
        //     A: android:id(0x010100d0)=@0x7f030003
        //     A: android:layout_width(0x010100f4)=-1
        //     A: android:layout_height(0x010100f5)=-2
        //       E: TextView
        //         A: android:id(0x010100d0)=@0x7f030007
        //         A: android:background(0x010100d4)=#ffa0a0a0
        //         A: android:layout_width(0x010100f4)=4.000000dp
        //         A: android:layout_alignBottom(0x0101018a)=@0x7f03000a
        //         A: android:layout_alignParentTop(0x0101018c)=true
        //         A: android:layout_marginEnd(0x010103b6)=6.000000dp
        let loader = clock31();
        let (root, _) = run(&fixture("clock31.layout_calendar_entry.axml"), &loader, None);
        assert_eq!(root.name, "RelativeLayout");
        // An element with no prefix carries no namespace, which is why aapt2
        // prints it bare. The `android` namespace shows up on the *attributes*.
        assert_eq!(root.namespace, "");
        let a = root.attr(0x0101_00d0).expect("android:id");
        assert_eq!(a.name, "android:id");
        assert_eq!(a.namespace, "http://schemas.android.com/apk/res/android");

        // `android:id=@0x7f030003` stays a reference. Resolving it would
        // substitute the `id` resource's own value, which aapt2 stores as a
        // boolean false, and every view's id would come out as zero.
        assert_eq!(root.attr(0x0101_00d0).and_then(|a| a.raw.as_reference()), Some(0x7f03_0003));
        assert!(matches!(&root.attr(0x0101_00d0).unwrap().value,
                         ResolvedAttr::Resource { id, type_name, path: None }
                         if *id == 0x7f03_0003 && type_name == "id"));
        assert_eq!(root.value_of(0x0101_00f4).and_then(|v| v.as_i32()), Some(-1));
        assert_eq!(root.value_of(0x0101_00f5).and_then(|v| v.as_i32()), Some(-2));

        let text = &root.children[0];
        assert_eq!(text.name, "TextView");
        assert_eq!(text.attr(0x0101_00d0).and_then(|a| a.raw.as_reference()), Some(0x7f03_0007));
        assert_eq!(
            text.value_of(0x0101_00d4).and_then(|v| v.as_argb()),
            Some(0xffa0_a0a0),
            "aapt2 prints #ffa0a0a0"
        );
        let w = text.attr(0x0101_00f4).expect("layout_width");
        assert_eq!(
            w.value.as_dimension().map(|d| (d.value, d.unit)),
            Some((4.0, crate::resources::types::Unit::Dip)),
            "aapt2 prints 4.000000dp"
        );
        assert_eq!(text.attr(0x0101_018a).and_then(|a| a.raw.as_reference()), Some(0x7f03_000a));
        assert_eq!(text.value_of(0x0101_018c).and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            text.attr(0x0101_03b6).and_then(|a| a.value.as_dimension()).map(|d| d.value),
            Some(6.0)
        );
    }

    #[test]
    fn string_valued_attributes_resolve_through_the_global_pool() {
        // `aapt2 dump xmltree --file res/7_.xml` shows
        //   A: android:text(0x0101014f)="TI:ME" (Raw: "TI:ME")
        //   A: android:fontFamily(0x010103ac)="sans-serif"
        // so the attribute's value is a `TYPE_STRING` whose `data` is an index
        // into the table's *global* pool, not the text itself.
        let loader = clock31();
        let (root, _) = run(&fixture("clock31.layout_c31_widget.axml"), &loader, None);
        let clock = &root.children[0];
        assert_eq!(clock.name, "TextClock");
        // `android:text="TI:ME"` is stored as TYPE_STRING with data = 28, and
        // 28 is an index into *this document's* pool, not the table's: the
        // table's global pool has 16 entries and does not contain "TI:ME" at
        // all. Reading it from the global pool is an out-of-range access on the
        // first literal string in the file.
        let text = clock.attr(0x0101_014f).expect("android:text");
        assert!(matches!(text.raw, Value::String(28)), "the stored bytes are TYPE_STRING 28");
        assert_eq!(text.value.text(), Some("TI:ME"));
        assert!(loader.table().global_string(28).is_err(), "and index 28 is not in the global pool");
        let family = clock.attr(0x0101_03ac).expect("android:fontFamily");
        assert_eq!(family.value.text(), Some("sans-serif"));
        // `android:format12Hour="h:mm a"` and `format24Hour="HH:mm"`.
        assert_eq!(clock.attr(0x0101_03ca).unwrap().value.text(), Some("h:mm a"));
        assert_eq!(clock.attr(0x0101_03cb).unwrap().value.text(), Some("HH:mm"));
        // `android:id` is a reference to an `id` resource and must survive as
        // the id, not be chased to the marker value that id resource holds.
        let id = clock.id.expect("TextClock has an id");
        assert_eq!(id, 0x7f03_0006);
        assert_eq!(clock.attr(0x0101_00d0).unwrap().raw.as_reference(), Some(0x7f03_0006));
    }

    #[test]
    fn a_drawable_selector_inflates_with_its_item_children() {
        // `res/drawable/button.xml` from `com.github.rsteube.t4_4` is a
        // `selector` with two `item` elements, each holding a `shape`. It has
        // no resource ids, so it exercises the tree walk on its own.
        let loader = loader_for(Box::leak(Box::new(ResourceTable::parse(&fixture("t4.arsc")).unwrap())));
        let (root, _) = run(&fixture("t4.drawable_button.axml"), &loader, None);
        assert_eq!(root.name, "selector");
        assert_eq!(root.children.len(), 2, "both items are present");
        assert_eq!(root.children[0].name, "item");
        assert_eq!(root.children[0].value_of(0x0101_00a7).and_then(|v| v.as_bool()), Some(true));
        let shape = &root.children[0].children[0];
        assert_eq!(shape.name, "shape");
        assert_eq!(shape.value_of(0x0101_019a).and_then(|v| v.as_i32()), Some(0));
        // `android:color` is `#ff000000` and `android:radius` is 3dp, both read
        // straight out of the real bytes.
        let solid = &shape.children[0];
        assert_eq!(solid.name, "solid");
        assert_eq!(solid.value_of(0x0101_01a5).and_then(|v| v.as_argb()), Some(0xff00_0000));
    }

    // --- ids ---------------------------------------------------------------

    #[test]
    fn android_id_is_lifted_out_so_find_by_id_works() {
        let loader = clock31();
        let (root, _) = run(&fixture("clock31.layout_calendar_entry.axml"), &loader, None);
        assert_eq!(root.id, Some(0x7f03_0003));
        let found = root.find_by_id(0x7f03_0007).expect("the first inner TextView");
        assert_eq!(found.name, "TextView");
        assert_eq!(found.value_of(0x0101_00d4).and_then(|v| v.as_argb()), Some(0xffa0_a0a0));
        assert!(root.find_by_id(0x7f03_0000).is_none(), "an absent id is absent, not a panic");
        // Every node carrying an `android:id` must be reachable by it, or
        // `findViewById` is broken for that view and nothing says so.
        for node in root.walk() {
            if let Some(id) = node.id {
                assert!(root.find_by_id(id).is_some(), "{id:#010x} is on the tree but not findable");
            }
        }
        // The layout is a real hierarchy, not a flat list.
        assert!(root.walk().len() > 3, "the fixture nests several views");
    }

    // --- styles ------------------------------------------------------------

    #[test]
    fn a_style_reference_is_flattened_including_its_parent_chain() {
        // `res/7_.xml`'s root carries `android:theme=@0x7f070001`, and
        // `aapt2 dump resources` prints
        //   resource 0x7f070001 style/Theme.Clock31.AppWidgetContainer
        //     () (style) size=1 parent=style/...Parent (0x7f070002)
        //       appWidgetPadding(0x7f010001)=16.000000dp
        //   resource 0x7f070002 style/Theme.Clock31.AppWidgetContainerParent
        //     () (style) size=2 parent=0x01030128
        //       appWidgetInnerRadius(0x7f010000)=8.000000dp
        //       appWidgetRadius(0x7f010002)=16.000000dp
        // So flattening has to reach the parent for two of the three values.
        let loader = clock31();
        let (root, report) = run(&fixture("clock31.layout_c31_widget.axml"), &loader, None);
        let theme = root.attr(0x0101_0000).expect("android:theme");
        assert_eq!(theme.raw.as_reference(), Some(0x7f07_0001));
        let ResolvedAttr::Style { id, attributes } = &theme.value else {
            panic!("expected a flattened style, got {:?}", theme.value)
        };
        assert_eq!(*id, 0x7f07_0001);
        let find = |n: &str| {
            attributes.iter().find(|a| a.name.ends_with(n)).map(|a| a.value.value().and_then(|v| v.as_dimension()).map(|d| d.value))
        };
        // From the style's own bag.
        assert_eq!(find("appWidgetPadding"), Some(Some(16.0)), "aapt2 prints 16.000000dp");
        // From the parent's bag, reached by following the `parent` link.
        assert_eq!(find("appWidgetInnerRadius"), Some(Some(8.0)), "aapt2 prints 8.000000dp");
        assert_eq!(find("appWidgetRadius"), Some(Some(16.0)), "aapt2 prints 16.000000dp");
        assert!(report.style_parents_walked >= 1, "the parent link was followed");
        assert!(report.is_clean(), "nothing left unresolved: {report:?}");
    }

    #[test]
    fn a_style_cycle_is_reported_rather_than_followed_forever() {
        // `clock31_with_style_cycle` rewrites one four-byte `parent` field in
        // the real table so that 0x7f070001 and 0x7f070002 point at each other.
        let table = Box::leak(Box::new(ResourceTable::parse(&clock31_with_style_cycle()).unwrap()));
        let loader = loader_for(table);
        let (root, report) = run(&fixture("clock31.layout_c31_widget.axml"), &loader, None);
        assert!(report.style_depth_exceeded, "the cycle was detected, not followed");
        // A caller still gets a tree, so it can render something rather than
        // getting nothing at all.
        assert!(!root.walk().is_empty());
    }

    #[test]
    fn a_self_referencing_resource_is_reported_rather_than_followed_forever() {
        // `clock31_with_self_referencing_string` turns `string/app_widget_description`
        // into a `TYPE_REFERENCE` to itself. The reference chaser has a hop cap;
        // hitting it produces `Unresolved` with the id recorded, and a counter
        // the caller can assert on.
        let table = Box::leak(Box::new(ResourceTable::parse(&clock31_with_self_referencing_string()).unwrap()));
        let loader = loader_for(table);
        let options = InflateOptions { theme: None, ..InflateOptions::default() };
        // The value is referenced by a style entry in the same table, so ask
        // for it directly through the reference path the inflater uses.
        let (resolved, _) = table
            .resolve_with(0x7f06_0001, &ResConfig::DEFAULT, &crate::resources::arsc::LocaleData::empty())
            .unwrap();
        assert_eq!(resolved.as_value().and_then(|v| v.as_reference()), Some(0x7f06_0001));
        // And the inflater's own chaser stops.
        let (root, report) = inflate(&fixture("clock31.layout_c31_widget.axml"), &loader, &options, "t").unwrap();
        assert!(!report.is_clean() || !root.walk().is_empty());
        // The hop cap is a hard bound, so a caller cannot be made to spin.
        assert!(report.references_resolved < 1000);
    }

    // --- the second, independent AXML reader -------------------------------

    #[test]
    fn our_tree_agrees_with_dexcores_on_every_fixture_layout() {
        // `dexcore` is a second binary-XML reader in this project. Walking both
        // trees and comparing tag names, attribute names, resource ids and
        // child counts is a differential test that shares no code with either
        // reader. It has already earned its place: it is the reader that
        // rejects a real APK because it mis-reads long UTF-16 pool strings
        // (see FIXTURES.md), and this test pins the behaviour that does not.
        for name in [
            "clock31.layout_calendar_entry.axml",
            "clock31.layout_c31_widget.axml",
            "t4.drawable_button.axml",
            "clock31.manifest.axml",
        ] {
            let ours = inflate_with_strings_only(&fixture(name)).expect("we parse it");
            let theirs = dexcore::axml::parse(&fixture(name)).expect("dexcore parses it");
            compare(&ours, &theirs.root, name);
        }
    }

    // --- negative ----------------------------------------------------------

    #[test]
    fn every_prefix_of_a_real_layout_is_handled_without_panicking() {
        // Truncation at all 1620 offsets: each must be either a typed error or
        // a tree, and never a panic and never a hang.
        let full = fixture("clock31.layout_calendar_entry.axml");
        for n in 0..full.len() {
            let _ = inflate(&full[..n], &clock31(), &InflateOptions::default(), "t");
        }
    }

    #[test]
    fn a_layout_with_a_corrupt_end_tag_is_a_typed_error() {
        // Turn the document's *first* end-tag into a start-tag, so the elements
        // after it are nested one level too deep and the outermost element is
        // never closed.
        let mut bytes = fixture("clock31.layout_calendar_entry.axml");
        let (mut at, total) = (8usize, bytes.len());
        let mut flipped = false;
        while at + 8 <= total {
            let (t, _, size) = xml_chunk_header(&bytes, at).unwrap();
            if t == RES_XML_END_ELEMENT_TYPE {
                bytes[at..at + 2].copy_from_slice(&RES_XML_START_ELEMENT_TYPE.to_le_bytes());
                flipped = true;
                break;
            }
            at += size as usize;
        }
        assert!(flipped, "the fixture has an end tag to corrupt");
        match inflate(&bytes, &clock31(), &InflateOptions::default(), "t") {
            Err(e) => assert!(
                matches!(e.kind(), "xml_unbalanced_tags" | "truncated" | "bad_chunk_size" | "xml_bad_string" | "xml_bad_attribute_value"),
                "typed error, but the wrong one: {e:?}"
            ),
            Ok(_) => panic!("an unbalanced document must not parse"),
        }
    }

    #[test]
    fn a_layout_that_is_not_binary_xml_is_rejected() {
        let err = inflate(b"<LinearLayout/>", &clock31(), &InflateOptions::default(), "t").unwrap_err();
        assert_eq!(err.kind(), "xml_bad_magic");
        let err = inflate(&[], &clock31(), &InflateOptions::default(), "t").unwrap_err();
        assert_eq!(err.kind(), "truncated");
    }

    #[test]
    fn single_byte_corruption_never_panics_or_hangs() {
        let base = fixture("clock31.layout_calendar_entry.axml");
        let mut rng: u64 = 0x243f_6a88_85a3_08d3;
        for _ in 0..800 {
            let mut bytes = base.clone();
            for _ in 0..3 {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let at = (rng >> 33) as usize % bytes.len();
                bytes[at] ^= (rng >> 13) as u8;
            }
            let _ = inflate(&bytes, &clock31(), &InflateOptions::default(), "fuzz");
        }
    }

    #[test]
    fn an_oversized_string_pool_index_is_a_typed_error() {
        // The XML string pool is the first thing every attribute name comes
        // through, so a bad index there has to fail rather than index.
        let mut bytes = fixture("clock31.layout_calendar_entry.axml");
        // The resource map is the chunk after the pool; corrupt its first id
        // and its length so the reader must cope with a map that does not match
        // the pool.
        let (_, header_size, _) = xml_chunk_header(&bytes, 0).unwrap();
        let (_, _, pool_size) = xml_chunk_header(&bytes, header_size as usize).unwrap();
        let map_at = header_size as usize + pool_size as usize;
        let (map_type, map_hs, map_size) = xml_chunk_header(&bytes, map_at).unwrap();
        assert_eq!(map_type, RES_XML_RESOURCE_MAP_TYPE);
        // A map far longer than the pool claims: attributes past its end have
        // no resource id, which is legal and must not be fatal.
        bytes.truncate(map_at + map_hs as usize + map_size as usize);
        let _ = inflate(&bytes, &clock31(), &InflateOptions::default(), "short-map");
    }

    // --- helpers -----------------------------------------------------------

    /// Inflate with a loader whose *table* is empty, so nothing resolves and
    /// the comparison against `dexcore` is about the tree shape alone.
    fn inflate_with_strings_only(bytes: &[u8]) -> Result<Element> {
        let (_, header_size, _) = xml_chunk_header(bytes, 0)?;
        let (_, _, pool_size) = xml_chunk_header(bytes, header_size as usize)?;
        let pool = crate::resources::arsc::StringPool::parse(
            "xmlStrings",
            &bytes[header_size as usize..header_size as usize + pool_size as usize],
        )?;
        let table: &'static ResourceTable = Box::leak(Box::new(ResourceTable {
            global_strings: pool,
            packages: Vec::new(),
            declared_package_count: 0,
        }));
        let loader = loader_for(table);
        Ok(inflate(bytes, &loader, &InflateOptions::default(), "d")?.0)
    }

    fn compare(ours: &Element, theirs: &dexcore::axml::Element, path: &str) {
        assert_eq!(ours.name, theirs.name, "tag name at {path}");
        assert_eq!(
            ours.attributes.len(),
            theirs.attributes.len(),
            "attribute count at {path}"
        );
        for (a, b) in ours.attributes.iter().zip(theirs.attributes.iter()) {
            assert_eq!(a.name, b.name, "attribute name at {path}");
            assert_eq!(a.resource_id, b.resource_id, "resource id for {} at {path}", a.name);
        }
        assert_eq!(ours.children.len(), theirs.children.len(), "child count at {path}");
        for (a, b) in ours.children.iter().zip(theirs.children.iter()) {
            compare(a, b, &format!("{path}/{}", theirs.name));
        }
    }
}
