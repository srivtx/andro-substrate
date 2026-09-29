//! Typed errors for the resource subsystem.
//!
//! Every fallible entry point in this module returns [`Result`]. Nothing in a
//! parse path indexes a slice before a bounds check and nothing recurses
//! without a depth limit, so an untrusted `resources.arsc` produces a typed
//! error rather than a panic or a hang.
//!
//! [`ResourceError::kind`] gives a stable machine-readable discriminant, in the
//! same spirit as `dexcore`'s `Error::kind`.

use std::fmt;

/// Result alias used throughout the resource subsystem.
pub type Result<T> = std::result::Result<T, ResourceError>;

/// Everything that can go wrong reading `resources.arsc`, inflating binary XML,
/// or reading an asset out of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceError {
    /// A fixed-size structure ran past the end of the buffer.
    Truncated {
        /// What was being read.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// The file does not start with a `RES_TABLE_TYPE` chunk.
    BadTableMagic {
        /// The chunk type that was found.
        found: u16,
    },
    /// A chunk declared a size that cannot be walked.
    BadChunkSize {
        /// Chunk type as declared in the header.
        chunk: u16,
        /// Declared size.
        size: u32,
    },
    /// A chunk declared a `headerSize` smaller than the structure it introduces.
    BadHeaderSize {
        /// Chunk type as declared in the header.
        chunk: u16,
        /// Declared `headerSize`.
        header_size: u16,
        /// Smallest value that could be valid.
        min: u16,
    },
    /// A chunk extends past the end of its parent chunk.
    ChunkOutOfRange {
        /// Chunk type as declared in the header.
        chunk: u16,
        /// Declared start offset, relative to the parent.
        off: u32,
        /// Declared size.
        size: u32,
        /// Size of the parent.
        parent: u32,
    },
    /// A chunk type this reader does not model appeared where it mattered.
    ///
    /// Unknown chunk types are *skipped* almost everywhere, exactly as AOSP
    /// does, so this only fires for a type that carries data we would otherwise
    /// silently drop in a position where dropping it is a correctness problem.
    UnsupportedChunk {
        /// Chunk type as declared in the header.
        chunk: u16,
    },
    /// A string pool index pointed outside the pool.
    StringIndexOutOfRange {
        /// Which pool (`global`, `typeStrings`, `keyStrings`, `xml`).
        pool: &'static str,
        /// The offending index.
        index: u32,
        /// Number of strings in the pool.
        size: u32,
    },
    /// A string pool declared more strings than the chunk can physically hold.
    ///
    /// Checked before any allocation, because the declared count is attacker
    /// controlled and `Vec::with_capacity` is not.
    StringPoolOverlong {
        /// Which pool.
        pool: &'static str,
        /// Declared `stringCount`.
        count: u32,
        /// Bytes of string data the chunk actually has.
        have: usize,
    },
    /// A string in a UTF-16 pool was not `0x0000`-terminated where AOSP requires.
    ///
    /// AOSP rejects these (`ResourceTypes.cpp`, `ResStringPool::stringAt`), so
    /// we do too rather than invent a length the file does not vouch for.
    StringNotTerminated {
        /// Which pool.
        pool: &'static str,
        /// The offending index.
        index: u32,
    },
    /// A `ResTable_config` declared a `size` this reader cannot interpret.
    BadConfigSize {
        /// Declared `ResTable_config.size`.
        size: u32,
    },
    /// A package chunk declared a `name` that is not a usable package name.
    BadPackageName {
        /// The raw bytes found, NUL-trimmed.
        name: String,
    },
    /// An entry offset pointed outside the `ResTable_type` chunk.
    EntryOffsetOutOfRange {
        /// Entry offset from `entriesStart`.
        offset: u32,
        /// Chunk size, which bounds the offset.
        chunk_size: u32,
    },
    /// A `ResTable_entry` declared a size this reader cannot interpret.
    BadEntrySize {
        /// Declared size.
        size: u16,
    },
    /// A `ResTable_type` referenced a type id that has no `ResTable_typeSpec`.
    MissingTypeSpec(u8),
    /// The resource id's package byte names a package that is not loaded.
    NoSuchPackage {
        /// Package byte from the id (`0xPP`).
        package: u8,
        /// Package names that *are* loaded.
        loaded: Vec<String>,
    },
    /// The resource id has no type or entry, i.e. it is not a valid id.
    InvalidResourceId(u32),
    /// No configuration of this resource matches the requested device.
    ///
    /// This is a *distinct* outcome from "the resource does not exist": the id
    /// resolved, the entry was found, but every configuration was filtered out
    /// by `ResTable_config::match`.
    NoMatchingConfig {
        /// The resource id that was asked for.
        id: u32,
        /// How many configurations were considered and rejected.
        considered: usize,
    },
    /// A reference cycle was found while walking `parent` style links.
    StyleCycle {
        /// The resource id the cycle closes on.
        id: u32,
        /// How many links were followed before the cycle was detected.
        depth: usize,
    },
    /// A reference cycle was found while following a `TYPE_REFERENCE` chain.
    ReferenceCycle {
        /// The resource id the cycle closes on.
        id: u32,
        /// How many hops were taken before the cycle was detected.
        depth: usize,
    },
    /// A `Res_value` had a `dataType` this reader does not model.
    UnknownValueType {
        /// The `Res_value.dataType` tag.
        data_type: u8,
        /// Where the value came from.
        at: u32,
    },
    /// A value of the wrong type was requested, e.g. `get_dimension` on a string.
    ValueTypeMismatch {
        /// The resource id that was asked.
        id: u32,
        /// The type the API wanted.
        wanted: &'static str,
        /// The type actually stored.
        got: &'static str,
    },
    /// Binary XML parsing failed. Kept separate from the table errors so a
    /// caller can tell "your APK is broken" from "this layout is broken".
    Xml(XmlError),
    /// An asset could not be read from the package.
    Asset {
        /// The path as written in the resource table.
        path: String,
        /// What went wrong.
        detail: String,
    },
    /// A package (ZIP) container is malformed.
    BadZip {
        /// What went wrong.
        detail: String,
    },
    /// A recursion or chain-walk limit was reached. Always a bug in the input,
    /// never a silent truncation.
    DepthLimit {
        /// What was being walked.
        what: &'static str,
        /// The limit that was hit.
        limit: usize,
    },
}

impl ResourceError {
    /// A stable, machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            ResourceError::Truncated { .. } => "truncated",
            ResourceError::BadTableMagic { .. } => "bad_table_magic",
            ResourceError::BadChunkSize { .. } => "bad_chunk_size",
            ResourceError::BadHeaderSize { .. } => "bad_header_size",
            ResourceError::ChunkOutOfRange { .. } => "chunk_out_of_range",
            ResourceError::UnsupportedChunk { .. } => "unsupported_chunk",
            ResourceError::StringIndexOutOfRange { .. } => "string_index_out_of_range",
            ResourceError::StringPoolOverlong { .. } => "string_pool_overlong",
            ResourceError::StringNotTerminated { .. } => "string_not_terminated",
            ResourceError::BadConfigSize { .. } => "bad_config_size",
            ResourceError::BadPackageName { .. } => "bad_package_name",
            ResourceError::EntryOffsetOutOfRange { .. } => "entry_offset_out_of_range",
            ResourceError::BadEntrySize { .. } => "bad_entry_size",
            ResourceError::MissingTypeSpec(_) => "missing_type_spec",
            ResourceError::NoSuchPackage { .. } => "no_such_package",
            ResourceError::InvalidResourceId(_) => "invalid_resource_id",
            ResourceError::NoMatchingConfig { .. } => "no_matching_config",
            ResourceError::StyleCycle { .. } => "style_cycle",
            ResourceError::ReferenceCycle { .. } => "reference_cycle",
            ResourceError::UnknownValueType { .. } => "unknown_value_type",
            ResourceError::ValueTypeMismatch { .. } => "value_type_mismatch",
            ResourceError::Xml(e) => e.kind(),
            ResourceError::Asset { .. } => "asset",
            ResourceError::BadZip { .. } => "bad_zip",
            ResourceError::DepthLimit { .. } => "depth_limit",
        }
    }
}

/// Everything that can go wrong inflating a binary XML (`AXML`) document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmlError {
    /// The file does not start with a `RES_XML_TYPE` chunk.
    BadMagic {
        /// The chunk type found.
        found: u16,
    },
    /// A start tag named a string that is not in the pool.
    BadString {
        /// Which pool lookup failed.
        what: &'static str,
        /// The index that was asked for.
        index: u32,
    },
    /// The document's tags nest incorrectly.
    UnbalancedTags {
        /// Tag name that was closed.
        end: String,
        /// Tag name that was actually open, if any.
        open: Option<String>,
    },
    /// The document has no root element.
    NoRootElement,
    /// An attribute's `Res_value` had a `dataType` this reader does not model.
    BadAttributeValue {
        /// The `Res_value.dataType` tag.
        data_type: u8,
    },
    /// Any other failure, carried through from the shared error type.
    Other(Box<ResourceError>),
}

impl XmlError {
    /// A stable, machine-readable discriminant.
    pub fn kind(&self) -> &'static str {
        match self {
            XmlError::BadMagic { .. } => "xml_bad_magic",
            XmlError::BadString { .. } => "xml_bad_string",
            XmlError::UnbalancedTags { .. } => "xml_unbalanced_tags",
            XmlError::NoRootElement => "xml_no_root_element",
            XmlError::BadAttributeValue { .. } => "xml_bad_attribute_value",
            XmlError::Other(e) => e.kind(),
        }
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceError::Truncated { what, need, have } => {
                write!(f, "truncated while reading {what}: need {need} bytes, have {have}")
            }
            ResourceError::BadTableMagic { found } => {
                write!(f, "not a resource table: root chunk type is 0x{found:04x}, expected 0x0002")
            }
            ResourceError::BadChunkSize { chunk, size } => {
                write!(f, "chunk 0x{chunk:04x} declares implausible size {size}")
            }
            ResourceError::BadHeaderSize { chunk, header_size, min } => {
                write!(f, "chunk 0x{chunk:04x} declares headerSize {header_size}, minimum is {min}")
            }
            ResourceError::ChunkOutOfRange { chunk, off, size, parent } => {
                write!(f, "chunk 0x{chunk:04x} at {off} of {size} bytes runs past its parent's {parent} bytes")
            }
            ResourceError::UnsupportedChunk { chunk } => {
                write!(f, "chunk type 0x{chunk:04x} is not modelled here")
            }
            ResourceError::StringIndexOutOfRange { pool, index, size } => {
                write!(f, "{pool} string index {index} out of range (pool holds {size})")
            }
            ResourceError::StringPoolOverlong { pool, count, have } => {
                write!(f, "{pool} declares {count} strings but only {have} bytes of data")
            }
            ResourceError::StringNotTerminated { pool, index } => {
                write!(f, "{pool} string {index} is not NUL-terminated")
            }
            ResourceError::BadConfigSize { size } => {
                write!(f, "ResTable_config.size is {size}, which is too small to hold a size field")
            }
            ResourceError::BadPackageName { name } => {
                write!(f, "package name {name:?} is not a usable package name")
            }
            ResourceError::EntryOffsetOutOfRange { offset, chunk_size } => {
                write!(f, "entry offset {offset} is past the end of a {chunk_size}-byte type chunk")
            }
            ResourceError::BadEntrySize { size } => {
                write!(f, "ResTable_entry.size is {size}, which cannot be interpreted")
            }
            ResourceError::MissingTypeSpec(id) => {
                write!(f, "type id {id} has entries but no ResTable_typeSpec")
            }
            ResourceError::NoSuchPackage { package, loaded } => {
                write!(f, "no loaded package has id {package} (loaded: {loaded:?})")
            }
            ResourceError::InvalidResourceId(id) => {
                write!(f, "0x{id:08x} is not a valid resource id")
            }
            ResourceError::NoMatchingConfig { id, considered } => {
                write!(f, "0x{id:08x} exists but none of its {considered} configurations match this device")
            }
            ResourceError::StyleCycle { id, depth } => {
                write!(f, "style inheritance cycle through 0x{id:08x} after {depth} parents")
            }
            ResourceError::ReferenceCycle { id, depth } => {
                write!(f, "reference cycle through 0x{id:08x} after {depth} hops")
            }
            ResourceError::UnknownValueType { data_type, at } => {
                write!(f, "0x{at:08x} has unknown Res_value dataType 0x{data_type:02x}")
            }
            ResourceError::ValueTypeMismatch { id, wanted, got } => {
                write!(f, "0x{id:08x} is a {got}, but a {wanted} was requested")
            }
            ResourceError::Xml(e) => write!(f, "{e}"),
            ResourceError::Asset { path, detail } => write!(f, "cannot read asset {path:?}: {detail}"),
            ResourceError::BadZip { detail } => write!(f, "malformed package: {detail}"),
            ResourceError::DepthLimit { what, limit } => {
                write!(f, "{what} exceeded the depth limit of {limit}")
            }
        }
    }
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XmlError::BadMagic { found } => {
                write!(f, "not a binary XML file: root chunk type is 0x{found:04x}, expected 0x0003")
            }
            XmlError::BadString { what, index } => {
                write!(f, "{what} names string {index}, which is not in the pool")
            }
            XmlError::UnbalancedTags { end, open } => match open {
                Some(o) => write!(f, "closing tag {end:?} does not match open tag {o:?}"),
                None => write!(f, "closing tag {end:?} with no open tag"),
            },
            XmlError::NoRootElement => write!(f, "binary XML document has no root element"),
            XmlError::BadAttributeValue { data_type } => {
                write!(f, "attribute has unknown Res_value dataType 0x{data_type:02x}")
            }
            XmlError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResourceError {}
impl std::error::Error for XmlError {}

impl From<XmlError> for ResourceError {
    fn from(e: XmlError) -> Self {
        match e {
            XmlError::Other(inner) => *inner,
            other => ResourceError::Xml(other),
        }
    }
}
