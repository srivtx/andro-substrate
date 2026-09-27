//! Typed errors.
//!
//! Every fallible entry point in this crate returns [`Result`]. Nothing in the
//! parse path indexes a slice before a bounds check, so malformed input
//! produces a typed error rather than a panic. The `wasm` layer converts any
//! `Error` into a JSON object with a stable `kind` discriminant.

use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while reading or writing a DEX container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A fixed-size structure ran past the end of the buffer.
    Truncated {
        /// What was being read (`header`, `file`, `code`, ...).
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// The file does not start with `dex\n<version>\0`.
    BadMagic {
        /// The first bytes that were found.
        found: Vec<u8>,
    },
    /// `header_size` was neither 0x70 nor 0x78.
    BadHeaderSize(u32),
    /// `endian_tag` was not `0x12345678`.
    BadEndianTag(u32),
    /// A section declared a non-zero size but a zero offset.
    MissingSection(&'static str),
    /// A section's declared extent does not fit inside the declared file size.
    SectionOutOfRange {
        /// Section name.
        name: String,
        /// Declared offset.
        off: u32,
        /// Declared element count.
        size: u32,
        /// Exclusive end offset the section would need.
        need: u64,
        /// Declared file size.
        have: u64,
    },
    /// A pool index was outside its section.
    IndexOutOfRange {
        /// Pool being indexed.
        pool: &'static str,
        /// The offending index.
        index: u32,
        /// Number of elements in the pool.
        size: u32,
    },
    /// The file did not start with a binary-XML chunk header.
    BadAxmlMagic {
        /// The bytes that were found.
        found: Vec<u8>,
    },
    /// An AXML chunk declared an implausible size.
    BadChunkSize {
        /// Chunk type as declared in the header.
        chunk: u16,
        /// Declared size.
        size: u32,
    },
    /// An AXML string was not valid UTF-16.
    BadAxmlString(usize),
    /// A ULEB128 value ran off the end of the buffer or exceeded 32 bits.
    BadUleb128 {
        /// Offset the value started at.
        at: usize,
    },
    /// A MUTF-8 sequence was malformed.
    BadMutf8 {
        /// Byte offset within the string.
        at: usize,
    },
    /// Adler-32 in the header disagrees with the file.
    ChecksumMismatch {
        /// Value stored in the header.
        declared: u32,
        /// Value computed from the file.
        computed: u32,
    },
    /// SHA-1 in the header disagrees with the file.
    SignatureMismatch {
        /// Value stored in the header, hex.
        declared: String,
        /// Value computed from the file, hex.
        computed: String,
    },
    /// A `map_list` entry pointed outside the file.
    BadMapEntry {
        /// `map_item.type` as declared.
        item_type: u16,
        /// Declared offset.
        off: u32,
        /// Declared element count.
        size: u32,
    },
    /// Instruction decoding hit an opcode or a length that cannot be walked.
    BadInstruction {
        /// Offset within the code item, in bytes.
        at: usize,
        /// Human-readable reason.
        detail: String,
    },
    /// The writer was given a class whose superclass is not present in the file.
    MissingSuperclass(String),
    /// The writer was given two classes with the same descriptor.
    DuplicateClass(String),
    /// A `map_list` entry would not be sorted by offset, or sections overlap.
    UnsortedMap,
    /// A value that does not fit the DEX field it has to go in.
    ValueOutOfRange {
        /// What was being written.
        what: &'static str,
        /// The value.
        value: u64,
    },
    /// The writer was asked to emit a class with methods but no code.
    MissingCode(String),
    /// The staged classes form a cycle, so no valid `class_defs` order exists.
    CyclicClassHierarchy(usize),
}

impl Error {
    /// A stable, machine-readable discriminant for the JSON error envelope.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Truncated { .. } => "truncated",
            Error::BadMagic { .. } => "bad_magic",
            Error::BadHeaderSize(_) => "bad_header_size",
            Error::BadEndianTag(_) => "bad_endian_tag",
            Error::MissingSection(_) => "missing_section",
            Error::SectionOutOfRange { .. } => "section_out_of_range",
            Error::IndexOutOfRange { .. } => "index_out_of_range",
            Error::BadAxmlMagic { .. } => "bad_axml_magic",
            Error::BadChunkSize { .. } => "bad_chunk_size",
            Error::BadAxmlString(_) => "bad_axml_string",
            Error::BadUleb128 { .. } => "bad_uleb128",
            Error::BadMutf8 { .. } => "bad_mutf8",
            Error::ChecksumMismatch { .. } => "checksum_mismatch",
            Error::SignatureMismatch { .. } => "signature_mismatch",
            Error::BadMapEntry { .. } => "bad_map_entry",
            Error::BadInstruction { .. } => "bad_instruction",
            Error::MissingSuperclass(_) => "missing_superclass",
            Error::DuplicateClass(_) => "duplicate_class",
            Error::UnsortedMap => "unsorted_map",
            Error::ValueOutOfRange { .. } => "value_out_of_range",
            Error::MissingCode(_) => "missing_code",
            Error::CyclicClassHierarchy(_) => "cyclic_class_hierarchy",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { what, need, have } => {
                write!(f, "truncated while reading {what}: need {need} bytes, have {have}")
            }
            Error::BadMagic { found } => {
                write!(f, "not a DEX file: magic is {}", printable(found))
            }
            Error::BadHeaderSize(n) => write!(f, "header_size is 0x{n:x}, expected 0x70 or 0x78"),
            Error::BadEndianTag(n) => write!(f, "endian_tag is 0x{n:08x}, expected 0x12345678"),
            Error::MissingSection(s) => write!(f, "section {s} has non-zero size but zero offset"),
            Error::SectionOutOfRange { name, off, size, need, have } => write!(
                f,
                "section {name} at {off} ({size} items) ends at {need}, past file size {have}"
            ),
            Error::IndexOutOfRange { pool, index, size } => {
                write!(f, "{pool} index {index} out of range (size {size})")
            }
            Error::BadAxmlMagic { found } => {
                write!(f, "not an AXML file: magic is {}", printable(found))
            }
            Error::BadChunkSize { chunk, size } => {
                write!(f, "AXML chunk 0x{chunk:04x} declares implausible size {size}")
            }
            Error::BadAxmlString(i) => write!(f, "AXML string {i} is not valid UTF-16"),
            Error::BadUleb128 { at } => write!(f, "malformed ULEB128 at offset {at}"),
            Error::BadMutf8 { at } => write!(f, "malformed MUTF-8 at byte {at}"),
            Error::ChecksumMismatch { declared, computed } => write!(
                f,
                "adler32 mismatch: header says 0x{declared:08x}, file computes 0x{computed:08x}"
            ),
            Error::SignatureMismatch { declared, computed } => {
                write!(f, "sha1 mismatch: header says {declared}, file computes {computed}")
            }
            Error::BadMapEntry { item_type, off, size } => write!(
                f,
                "map entry 0x{item_type:04x} at {off} ({size} items) is out of range"
            ),
            Error::BadInstruction { at, detail } => {
                write!(f, "cannot decode instruction at code offset {at}: {detail}")
            }
            Error::MissingSuperclass(c) => write!(f, "class {c} extends a class not in this dex"),
            Error::DuplicateClass(c) => write!(f, "class {c} defined twice"),
            Error::UnsortedMap => write!(f, "map_list entries are not ordered by offset"),
            Error::ValueOutOfRange { what, value } => {
                write!(f, "{what} value {value} does not fit its dex field")
            }
            Error::MissingCode(c) => write!(f, "class {c} has concrete methods with no code item"),
            Error::CyclicClassHierarchy(n) => write!(
                f,
                "{n} class(es) form an inheritance or interface cycle; no valid class_defs order exists"
            ),
        }
    }
}

impl std::error::Error for Error {}

fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x20..0x7f).contains(&c) {
                (c as char).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}
