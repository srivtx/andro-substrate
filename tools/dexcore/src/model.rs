//! Structured model of the DEX items the reader exposes.
//!
//! These types are the boundary between "bytes on disk" and "something the
//! runtime can reason about". They are deliberately index-based: pool entries
//! keep their `*_idx` fields so that a caller can correlate them without
//! building a parallel object graph.

use serde::Serialize;

/// A `string_id_item` plus its lazily decoded contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexString {
    /// Index in `string_ids`.
    pub index: u32,
    /// Offset of the `string_data_item`, which lives in the data section.
    pub string_data_off: u32,
    /// `utf16_size` as stored in the file: the length in UTF-16 code units.
    pub utf16_size: u32,
    /// Decoded contents, with surrogate pairs reassembled.
    pub value: String,
}

/// A `type_id_item` resolved to its descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexType {
    pub index: u32,
    /// Index into `string_ids`.
    pub descriptor_idx: u32,
    /// The descriptor, e.g. `Ljava/lang/String;` or `[I`.
    pub descriptor: String,
}

impl DexType {
    /// True for `V`, `Z`, `B`, `S`, `C`, `I`, `J`, `F`, `D`.
    pub fn is_primitive(&self) -> bool {
        matches!(self.descriptor.as_str(), "V" | "Z" | "B" | "S" | "C" | "I" | "J" | "F" | "D")
    }

    /// True for descriptors starting with `[`.
    pub fn is_array(&self) -> bool {
        self.descriptor.starts_with('[')
    }
}

/// A `proto_id_item` resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexProto {
    pub index: u32,
    pub shorty_idx: u32,
    /// The short-form descriptor, e.g. `VL`.
    pub shorty: String,
    pub return_type_idx: u32,
    /// The return type descriptor.
    pub return_type: String,
    /// `parameters_off`, or 0 when the proto takes no arguments.
    pub parameters_off: u32,
    /// Parameter type descriptors, empty when there is no `type_list`.
    pub parameters: Vec<String>,
}

impl DexProto {
    /// Human-readable signature, e.g. `(Ljava/lang/String;I)V`.
    pub fn signature(&self) -> String {
        format!("({}){}", self.parameters.join(""), self.return_type)
    }
}

/// A `field_id_item` resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexField {
    pub index: u32,
    pub class_idx: u32,
    pub name_idx: u32,
    pub type_idx: u32,
    /// Descriptor of the defining class.
    pub class: String,
    pub name: String,
    /// Descriptor of the field's type.
    pub type_descriptor: String,
}

impl DexField {
    /// e.g. `Lcom/x/Y;.z:I`.
    pub fn signature(&self) -> String {
        format!("{}.{}:{}", self.class, self.name, self.type_descriptor)
    }
}

/// A `method_id_item` resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexMethod {
    pub index: u32,
    pub class_idx: u32,
    pub name_idx: u32,
    pub proto_idx: u32,
    pub class: String,
    pub name: String,
    pub shorty: String,
    pub return_type: String,
    pub parameters: Vec<String>,
}

impl DexMethod {
    /// e.g. `Lcom/x/Y;.z(Ljava/lang/String;I)V`.
    pub fn signature(&self) -> String {
        format!("{}.{}({}){}", self.class, self.name, self.parameters.join(""), self.return_type)
    }
}

/// One `access_flags` value.
pub mod access {
    pub const ACC_PUBLIC: u32 = 0x0001;
    pub const ACC_PRIVATE: u32 = 0x0002;
    pub const ACC_PROTECTED: u32 = 0x0004;
    pub const ACC_STATIC: u32 = 0x0008;
    pub const ACC_FINAL: u32 = 0x0010;
    pub const ACC_SYNCHRONIZED: u32 = 0x0020;
    pub const ACC_SUPER: u32 = 0x0020;
    pub const ACC_VOLATILE: u32 = 0x0040;
    pub const ACC_BRIDGE: u32 = 0x0040;
    pub const ACC_TRANSIENT: u32 = 0x0080;
    pub const ACC_VARARGS: u32 = 0x0080;
    pub const ACC_NATIVE: u32 = 0x0100;
    pub const ACC_INTERFACE: u32 = 0x0200;
    pub const ACC_ABSTRACT: u32 = 0x0400;
    pub const ACC_STRICT: u32 = 0x0800;
    pub const ACC_SYNTHETIC: u32 = 0x1000;
    pub const ACC_ANNOTATION: u32 = 0x2000;
    pub const ACC_ENUM: u32 = 0x4000;
    pub const ACC_CONSTRUCTOR: u32 = 0x10000;
    pub const ACC_DECLARED_SYNCHRONIZED: u32 = 0x20000;
}

/// An `encoded_field` from a `class_data_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EncodedField {
    /// Absolute `field_ids` index (deltas have been accumulated).
    pub field_idx: u32,
    pub access_flags: u32,
}

/// An `encoded_method` from a `class_data_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct EncodedMethod {
    /// Absolute `method_ids` index (deltas have been accumulated).
    pub method_idx: u32,
    pub access_flags: u32,
    /// Offset of the `code_item`, or 0 for abstract/native methods.
    pub code_off: u32,
}

/// A decoded `class_data_item`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ClassData {
    /// Each list is sorted by increasing `field_idx` / `method_idx` on disk and
    /// is preserved in that order here.
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

/// A `class_def_item` resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DexClass {
    /// Index into `class_defs`.
    pub index: u32,
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    /// `NO_INDEX` for root classes.
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    /// Descriptor of the class itself.
    pub descriptor: String,
    /// Descriptor of the superclass, empty when there is none.
    pub superclass: String,
    /// Interface descriptors.
    pub interfaces: Vec<String>,
    /// Source file name, empty when absent.
    pub source_file: String,
    /// Empty when the class has no `class_data_item` (e.g. marker interfaces).
    pub class_data: Option<ClassData>,
}

/// One `map_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MapItem {
    /// `TYPE_*` constant.
    pub item_type: u16,
    /// Always zero; the specification reserves it.
    pub unused: u16,
    /// Number of items of this type.
    pub size: u32,
    /// Offset of the first one.
    pub offset: u32,
}

/// `map_item.type` values.
pub mod map_type {
    pub const HEADER_ITEM: u16 = 0x0000;
    pub const STRING_ID_ITEM: u16 = 0x0001;
    pub const TYPE_ID_ITEM: u16 = 0x0002;
    pub const PROTO_ID_ITEM: u16 = 0x0003;
    pub const FIELD_ID_ITEM: u16 = 0x0004;
    pub const METHOD_ID_ITEM: u16 = 0x0005;
    pub const CLASS_DEF_ITEM: u16 = 0x0006;
    pub const CALL_SITE_ID_ITEM: u16 = 0x0007;
    pub const METHOD_HANDLE_ITEM: u16 = 0x0008;
    pub const MAP_LIST: u16 = 0x1000;
    pub const TYPE_LIST: u16 = 0x1001;
    pub const ANNOTATION_SET_REF_LIST: u16 = 0x1002;
    pub const ANNOTATION_SET_ITEM: u16 = 0x1003;
    pub const CLASS_DATA_ITEM: u16 = 0x2000;
    pub const CODE_ITEM: u16 = 0x2001;
    pub const STRING_DATA_ITEM: u16 = 0x2002;
    pub const DEBUG_INFO_ITEM: u16 = 0x2003;
    pub const ANNOTATION_ITEM: u16 = 0x2004;
    pub const ENCODED_ARRAY_ITEM: u16 = 0x2005;
    pub const ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;
    pub const HIDDENAPI_CLASS_DATA_ITEM: u16 = 0xf000;

    /// A human-readable name, for the wasm summary and error messages.
    pub fn name(t: u16) -> &'static str {
        match t {
            HEADER_ITEM => "header_item",
            STRING_ID_ITEM => "string_id_item",
            TYPE_ID_ITEM => "type_id_item",
            PROTO_ID_ITEM => "proto_id_item",
            FIELD_ID_ITEM => "field_id_item",
            METHOD_ID_ITEM => "method_id_item",
            CLASS_DEF_ITEM => "class_def_item",
            CALL_SITE_ID_ITEM => "call_site_id_item",
            METHOD_HANDLE_ITEM => "method_handle_item",
            MAP_LIST => "map_list",
            TYPE_LIST => "type_list",
            ANNOTATION_SET_REF_LIST => "annotation_set_ref_list",
            ANNOTATION_SET_ITEM => "annotation_set_item",
            CLASS_DATA_ITEM => "class_data_item",
            CODE_ITEM => "code_item",
            STRING_DATA_ITEM => "string_data_item",
            DEBUG_INFO_ITEM => "debug_info_item",
            ANNOTATION_ITEM => "annotation_item",
            ENCODED_ARRAY_ITEM => "encoded_array_item",
            ANNOTATIONS_DIRECTORY_ITEM => "annotations_directory_item",
            HIDDENAPI_CLASS_DATA_ITEM => "hiddenapi_class_data_item",
            _ => "unknown",
        }
    }
}

/// A `code_item` header, with the instruction stream left as raw units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodeItem {
    pub offset: u32,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    /// Byte offset of `insns` within the file.
    pub insns_off: u32,
    /// Offset of the `tries` array, or 0 when there are none.
    pub tries_off: u32,
    /// Raw `try_item` bytes, kept opaque; not decoded.
    pub try_items: Vec<u8>,
    /// Opaque handler bytes following the try items, if any.
    pub encoded_catch_handler_list: Vec<u8>,
}

/// One decoded `try_item`: `uint start_addr; ushort insn_count; ushort handler_off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TryItem {
    /// Start address, in code units, of the protected range.
    pub start_addr: u32,
    /// Length of the protected range, in code units. The last covered unit is
    /// `start_addr + insn_count - 1`, inclusive.
    pub insn_count: u32,
    /// Byte offset from the start of the `encoded_catch_handler_list` to the
    /// `encoded_catch_handler` this try block uses. The list's own `size` prefix
    /// is included in the measurement.
    pub handler_off: u32,
}
