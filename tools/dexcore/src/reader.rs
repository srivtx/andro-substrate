//! [`DexReader`]: a bounds-checked view over a DEX byte slice.
//!
//! The reader owns no allocations beyond the strings it is asked to decode and
//! never panics: every accessor validates its index against the section size
//! before touching the byte slice, and every offset it dereferences is checked
//! against the buffer length. Truncated or hostile input therefore surfaces as
//! a typed [`Error`](crate::error::Error).
//!
//! Pools are resolved lazily, one entry at a time, so that opening a
//! hundred-megabyte `classes.dex` costs one header parse.

use crate::error::{Error, Result};
use crate::header::{DexHeader, NO_INDEX};
use crate::insn::{FillArrayData, Instruction, PackedSwitch, Payload, SparseSwitch};
use crate::model::*;
use crate::mutf8;
use serde::Serialize;

/// A read-only view over a single `classes.dex` container.
#[derive(Debug, Clone)]
pub struct DexReader<'a> {
    bytes: &'a [u8],
    header: DexHeader,
}

impl<'a> DexReader<'a> {
    /// Open a DEX file, validating magic, section extents and endianness but
    /// not the checksum or signature. Use [`DexReader::open_checked`] for that.
    pub fn open(bytes: &'a [u8]) -> Result<DexReader<'a>> {
        Ok(DexReader { header: DexHeader::parse(bytes)?, bytes })
    }

    /// Open a DEX file and require the Adler-32 and SHA-1 to match.
    pub fn open_checked(bytes: &'a [u8]) -> Result<DexReader<'a>> {
        Ok(DexReader { header: DexHeader::parse_checked(bytes)?, bytes })
    }

    /// The underlying bytes.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The parsed header.
    pub fn header(&self) -> &DexHeader {
        &self.header
    }

    /// Verify the file's Adler-32 and SHA-1 against the header.
    pub fn verify_integrity(&self) -> Result<()> {
        self.header.verify_integrity(self.bytes)
    }

    // ---------------------------------------------------------------- slices

    /// Bounds-checked sub-slice of `len` bytes at `off`.
    ///
    /// This is the single choke point through which every offset in this crate
    /// reaches the byte slice, so no other method needs its own check.
    fn span(&self, off: u32, len: u64) -> Result<&'a [u8]> {
        let start = off as usize;
        let end = (start as u64).checked_add(len).ok_or(Error::Truncated {
            what: "section",
            need: usize::MAX,
            have: self.bytes.len(),
        })?;
        if end > self.bytes.len() as u64 {
            return Err(Error::Truncated {
                what: "section",
                need: end as usize,
                have: self.bytes.len(),
            });
        }
        Ok(&self.bytes[start..end as usize])
    }

    /// The `idx`-th element of a fixed-width id section: the `elem_size` bytes
    /// at `base + idx * elem_size`.
    fn elem(&self, base: u32, idx: u32, elem_size: u32) -> Result<&'a [u8]> {
        let off = (base as u64) + (idx as u64) * (elem_size as u64);
        if off > u32::MAX as u64 {
            return Err(Error::Truncated {
                what: "section",
                need: usize::MAX,
                have: self.bytes.len(),
            });
        }
        self.span(off as u32, elem_size as u64)
    }

    /// Read one `u32` at `off`.
    fn u32_at(&self, off: u32) -> Result<u32> {
        let s = self.slice_at(off, 4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Bounds-checked sub-slice at `off`.
    fn slice_at(&self, off: u32, len: usize) -> Result<&'a [u8]> {
        let start = off as usize;
        let end = start.checked_add(len).ok_or(Error::Truncated {
            what: "field",
            need: usize::MAX,
            have: self.bytes.len(),
        })?;
        if end > self.bytes.len() {
            return Err(Error::Truncated { what: "field", need: end, have: self.bytes.len() });
        }
        Ok(&self.bytes[start..end])
    }

    /// Reject a pool index that is outside its section.
    fn check_index(&self, pool: &'static str, index: u32, size: u32) -> Result<()> {
        if index >= size {
            return Err(Error::IndexOutOfRange { pool, index, size });
        }
        Ok(())
    }

    // ---------------------------------------------------------------- pools

    /// Number of entries in `string_ids`.
    pub fn string_count(&self) -> u32 {
        self.header.string_ids_size
    }

    /// Decode `string_ids[idx]`.
    ///
    /// The pool is MUTF-8, not UTF-8; see [`crate::mutf8`].
    pub fn string(&self, idx: u32) -> Result<DexString> {
        self.check_index("string_ids", idx, self.header.string_ids_size)?;
        let id = self.elem(self.header.string_ids_off, idx, 4)?;
        let string_data_off = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
        if string_data_off as usize >= self.bytes.len() {
            return Err(Error::Truncated {
                what: "string_data_item",
                need: string_data_off as usize + 1,
                have: self.bytes.len(),
            });
        }
        let rest = &self.bytes[string_data_off as usize..];
        // utf16_size is a ULEB128 immediately before the MUTF-8 body.
        let (utf16_size, hdr_len) = mutf8::read_uleb128(rest, 0)?;
        let (value, _) = mutf8::decode(&rest[hdr_len..])?;
        Ok(DexString { index: idx, string_data_off, utf16_size, value })
    }

    /// Decode every string in the pool.
    pub fn strings(&self) -> Result<Vec<DexString>> {
        (0..self.header.string_ids_size).map(|i| self.string(i)).collect()
    }

    /// Number of entries in `type_ids`.
    pub fn type_count(&self) -> u32 {
        self.header.type_ids_size
    }

    /// Resolve `type_ids[idx]` to its descriptor.
    pub fn type_at(&self, idx: u32) -> Result<DexType> {
        self.check_index("type_ids", idx, self.header.type_ids_size)?;
        let id = self.elem(self.header.type_ids_off, idx, 4)?;
        let descriptor_idx = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
        let descriptor = self.string(descriptor_idx)?.value;
        Ok(DexType { index: idx, descriptor_idx, descriptor })
    }

    /// Resolve every type in the pool.
    pub fn types(&self) -> Result<Vec<DexType>> {
        (0..self.header.type_ids_size).map(|i| self.type_at(i)).collect()
    }

    /// The type descriptor for `idx`, as a string.
    pub fn type_name(&self, idx: u32) -> Result<String> {
        Ok(self.type_at(idx)?.descriptor)
    }

    /// Number of entries in `proto_ids`.
    pub fn proto_count(&self) -> u32 {
        self.header.proto_ids_size
    }

    /// Resolve `proto_ids[idx]`, including its parameter `type_list`.
    pub fn proto_at(&self, idx: u32) -> Result<DexProto> {
        self.check_index("proto_ids", idx, self.header.proto_ids_size)?;
        let id = self.elem(self.header.proto_ids_off, idx, 12)?;
        let shorty_idx = u32::from_le_bytes([id[0], id[1], id[2], id[3]]);
        let return_type_idx = u32::from_le_bytes([id[4], id[5], id[6], id[7]]);
        let parameters_off = u32::from_le_bytes([id[8], id[9], id[10], id[11]]);
        let parameters =
            if parameters_off == 0 { Vec::new() } else { self.type_list(parameters_off)? };
        let parameters = parameters
            .into_iter()
            .map(|t| self.type_name(t))
            .collect::<Result<Vec<_>>>()?;
        Ok(DexProto {
            index: idx,
            shorty_idx,
            shorty: self.string(shorty_idx)?.value,
            return_type_idx,
            return_type: self.type_name(return_type_idx)?,
            parameters_off,
            parameters,
        })
    }

    /// Resolve every proto in the pool.
    pub fn protos(&self) -> Result<Vec<DexProto>> {
        (0..self.header.proto_ids_size).map(|i| self.proto_at(i)).collect()
    }

    /// Read a `type_list` at `off`, returning the raw type indices.
    pub fn type_list(&self, off: u32) -> Result<Vec<u32>> {
        let size = self.u32_at(off)?;
        // Each element is 2 bytes; bound the count by what the file can hold so
        // a hostile size cannot make us allocate.
        let max = ((self.bytes.len() as u32).saturating_sub(off + 4)) / 2;
        if size > max {
            return Err(Error::Truncated {
                what: "type_list",
                need: (off as usize) + 4 + (size as usize) * 2,
                have: self.bytes.len(),
            });
        }
        let body = self.slice_at(off + 4, (size as usize) * 2)?;
        Ok(body.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]) as u32).collect())
    }

    /// Number of entries in `field_ids`.
    pub fn field_count(&self) -> u32 {
        self.header.field_ids_size
    }

    /// Resolve `field_ids[idx]`.
    pub fn field_at(&self, idx: u32) -> Result<DexField> {
        self.check_index("field_ids", idx, self.header.field_ids_size)?;
        let id = self.elem(self.header.field_ids_off, idx, 8)?;
        let class_idx = u16::from_le_bytes([id[0], id[1]]) as u32;
        let type_idx = u16::from_le_bytes([id[2], id[3]]) as u32;
        let name_idx = u32::from_le_bytes([id[4], id[5], id[6], id[7]]);
        Ok(DexField {
            index: idx,
            class_idx,
            name_idx,
            type_idx,
            class: self.type_name(class_idx)?,
            name: self.string(name_idx)?.value,
            type_descriptor: self.type_name(type_idx)?,
        })
    }

    /// Number of entries in `method_ids`.
    pub fn method_count(&self) -> u32 {
        self.header.method_ids_size
    }

    /// Resolve `method_ids[idx]`.
    pub fn method_at(&self, idx: u32) -> Result<DexMethod> {
        self.check_index("method_ids", idx, self.header.method_ids_size)?;
        let id = self.elem(self.header.method_ids_off, idx, 8)?;
        let class_idx = u16::from_le_bytes([id[0], id[1]]) as u32;
        let let_proto = u16::from_le_bytes([id[2], id[3]]) as u32;
        let proto_idx = let_proto;
        let name_idx = u32::from_le_bytes([id[4], id[5], id[6], id[7]]);
        let proto = self.proto_at(proto_idx)?;
        Ok(DexMethod {
            index: idx,
            class_idx,
            name_idx,
            proto_idx,
            class: self.type_name(class_idx)?,
            name: self.string(name_idx)?.value,
            shorty: proto.shorty,
            return_type: proto.return_type,
            parameters: proto.parameters,
        })
    }

    // --------------------------------------------------------------- classes

    /// Number of `class_def_item`s.
    pub fn class_def_count(&self) -> u32 {
        self.header.class_defs_size
    }

    /// Decode the `class_data_item` at `off`.
    ///
    /// `encoded_field`/`encoded_method` store *deltas*; the reader accumulates
    /// them so that every entry carries an absolute pool index. The lists are
    /// not re-sorted: the specification requires the producer to have sorted
    /// them, and preserving the on-disk order makes this a faithful decoder.
    pub fn class_data(&self, off: u32) -> Result<ClassData> {
        let base = off as usize;
        let buf = self.bytes.get(base..).ok_or(Error::Truncated {
            what: "class_data",
            need: base,
            have: self.bytes.len(),
        })?;
        let mut cur = Cursor { buf, at: 0 };

        let static_fields_size = cur.uleb()?;
        let instance_fields_size = cur.uleb()?;
        let direct_methods_size = cur.uleb()?;
        let virtual_methods_size = cur.uleb()?;

        // Each list is a run of (delta, value) pairs; the deltas accumulate into
        // absolute pool indices. `delta == 0` on the first entry means index 0.
        fn read_fields(cur: &mut Cursor<'_>, count: u32) -> Result<Vec<EncodedField>> {
            let mut out = Vec::with_capacity((count as usize).min(4096));
            let mut idx = 0u32;
            for _ in 0..count {
                let delta = cur.uleb()?;
                let access_flags = cur.uleb()?;
                idx = idx.checked_add(delta).ok_or(Error::BadUleb128 { at: cur.at })?;
                out.push(EncodedField { field_idx: idx, access_flags });
            }
            Ok(out)
        }

        fn read_methods(cur: &mut Cursor<'_>, count: u32) -> Result<Vec<EncodedMethod>> {
            let mut out = Vec::with_capacity((count as usize).min(4096));
            let mut idx = 0u32;
            for _ in 0..count {
                let delta = cur.uleb()?;
                let access_flags = cur.uleb()?;
                let code_off = cur.uleb()?;
                idx = idx.checked_add(delta).ok_or(Error::BadUleb128 { at: cur.at })?;
                out.push(EncodedMethod { method_idx: idx, access_flags, code_off });
            }
            Ok(out)
        }

        Ok(ClassData {
            static_fields: read_fields(&mut cur, static_fields_size)?,
            instance_fields: read_fields(&mut cur, instance_fields_size)?,
            direct_methods: read_methods(&mut cur, direct_methods_size)?,
            virtual_methods: read_methods(&mut cur, virtual_methods_size)?,
        })
    }

    /// Read the `class_def_item` at `class_defs[idx]`, without its class data.
    ///
    /// The eight fields are returned in file order; see [`crate::model::DexClass`]
    /// for what each one means.
    pub fn class_def_raw(&self, idx: u32) -> Result<RawClassDef> {
        self.check_index("class_defs", idx, self.header.class_defs_size)?;
        let d = self.elem(self.header.class_defs_off, idx, 32)?;
        let g = |i: usize| u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
        Ok((g(0), g(4), g(8), g(12), g(16), g(20), g(24), g(28)))
    }

    /// Decode `class_defs[idx]` together with its class data.
    pub fn class_def(&self, idx: u32) -> Result<DexClass> {
        let (class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off) =
            self.class_def_raw(idx)?;

        let interfaces = if interfaces_off == 0 {
            Vec::new()
        } else {
            self.type_list(interfaces_off)?
                .into_iter()
                .map(|t| self.type_name(t))
                .collect::<Result<Vec<_>>>()?
        };
        let source_file = if source_file_idx == u32::MAX {
            String::new()
        } else {
            self.string(source_file_idx)?.value
        };
        let superclass = if superclass_idx == NO_INDEX {
            String::new()
        } else {
            self.type_name(superclass_idx)?
        };
        let class_data =
            if class_data_off == 0 { None } else { Some(self.class_data(class_data_off)?) };

        Ok(DexClass {
            index: idx,
            class_idx,
            access_flags,
            superclass_idx,
            interfaces_off,
            source_file_idx,
            annotations_off,
            class_data_off,
            static_values_off,
            descriptor: self.type_name(class_idx)?,
            superclass,
            interfaces,
            source_file,
            class_data,
        })
    }

    /// Every class in the file, in `class_defs` order.
    pub fn classes(&self) -> Result<Vec<DexClass>> {
        (0..self.header.class_defs_size).map(|i| self.class_def(i)).collect()
    }

    /// Index into `class_defs` of the class with the given descriptor.
    pub fn find_class(&self, descriptor: &str) -> Result<Option<u32>> {
        for i in 0..self.header.class_defs_size {
            let (class_idx, ..) = self.class_def_raw(i)?;
            if self.type_name(class_idx)? == descriptor {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }

    // ------------------------------------------------------------------ code

    /// Read the `code_item` header and raw instruction stream at `off`.
    pub fn code_item(&self, off: u32) -> Result<CodeItem> {
        let hdr = self.slice_at(off, 16)?;
        let g16 = |i: usize| u16::from_le_bytes([hdr[i], hdr[i + 1]]);
        let mut code = CodeItem {
            offset: off,
            registers_size: g16(0),
            ins_size: g16(2),
            outs_size: g16(4),
            tries_size: g16(6),
            debug_info_off: u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
            insns_size: u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
            insns_off: off + 16,
            tries_off: 0,
            try_items: Vec::new(),
            encoded_catch_handler_list: Vec::new(),
        };
        let insns_len = (code.insns_size as u64) * 2;
        if insns_len > usize::MAX as u64 || (off as u64) + 16 + insns_len > self.bytes.len() as u64 {
            return Err(Error::Truncated {
                what: "code_item insns",
                need: (off as usize) + 16 + insns_len as usize,
                have: self.bytes.len(),
            });
        }
        if code.tries_size > 0 {
            // Two bytes of padding when insns_size is odd, so the try table is
            // 4-byte aligned. Note the round *up*: 1412 + 16 + 115*2 = 1658
            // puts the try array at 1660, not 1656.
            let base = (off + 16 + code.insns_size * 2 + 3) & !3;
            code.tries_off = base;
            let len = (code.tries_size as u32) * 8;
            code.try_items = self.slice_at(base, len as usize)?.to_vec();
            // The encoded_catch_handler_list follows the try array; its length
            // is not derivable, so slice to the end of the file and measure it.
            let tail_start = (base + len) as usize;
            let tail = self.bytes.get(tail_start..).unwrap_or(&[]);
            let (handler_bytes, _) = scan_catch_handlers(tail, code.tries_size as usize)?;
            code.encoded_catch_handler_list = handler_bytes;
        }
        Ok(code)
    }

    /// The raw `u16` instruction stream of the `code_item` at `off`.
    pub fn code_units(&self, off: u32) -> Result<&'a [u8]> {
        let c = self.code_item(off)?;
        self.slice_at(c.insns_off, (c.insns_size as usize) * 2)
    }

    /// Decode the `try_item` array of a `code_item`.
    pub fn try_items(&self, off: u32) -> Result<Vec<TryItem>> {
        let c = self.code_item(off)?;
        // try_item is `uint start_addr; ushort insn_count; ushort handler_off`,
        // which is 8 bytes in total — not three 32-bit fields.
        Ok(c.try_items
            .chunks_exact(8)
            .map(|t| TryItem {
                start_addr: u32::from_le_bytes([t[0], t[1], t[2], t[3]]),
                insn_count: u16::from_le_bytes([t[4], t[5]]) as u32,
                handler_off: u16::from_le_bytes([t[6], t[7]]) as u32,
            })
            .collect())
    }

    // ------------------------------------------------------------------- map

    /// Read the `map_list` as declared in the header.
    pub fn map_list(&self) -> Result<Vec<MapItem>> {
        if self.header.map_off == 0 {
            return Ok(Vec::new());
        }
        let size = self.u32_at(self.header.map_off)?;
        let max = (self.bytes.len() as u32).saturating_sub(self.header.map_off + 4) / 12;
        if size > max {
            return Err(Error::Truncated {
                what: "map_list",
                need: (self.header.map_off as usize) + 4 + (size as usize) * 12,
                have: self.bytes.len(),
            });
        }
        let body = self.slice_at(self.header.map_off + 4, (size as usize) * 12)?;
        Ok(body
            .chunks_exact(12)
            .map(|m| MapItem {
                item_type: u16::from_le_bytes([m[0], m[1]]),
                unused: u16::from_le_bytes([m[2], m[3]]),
                size: u32::from_le_bytes([m[4], m[5], m[6], m[7]]),
                offset: u32::from_le_bytes([m[8], m[9], m[10], m[11]]),
            })
            .collect())
    }
}

/// The eight `u32` fields of a `class_def_item`, in file order.
pub type RawClassDef = (u32, u32, u32, u32, u32, u32, u32, u32);

/// A forward-only cursor over a ULEB128-encoded region.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn uleb(&mut self) -> Result<u32> {
        let (v, n) = mutf8::read_uleb128(self.buf, self.at)?;
        self.at += n;
        Ok(v)
    }
}

/// Consume an `encoded_catch_handler_list`, returning its raw bytes.
///
/// The layout is `uleb128 handlers_size`, then that many `encoded_catch_handler`
/// items concatenated with no padding. Each item is a signed `size` (the
/// number of typed clauses, negated when a catch-all is present), that many
/// interleaved `(type_idx, addr)` ULEB128 pairs, and — when `size` is
/// non-positive — a final `catch_all_addr` ULEB128.
///
/// The raw bytes are handed to the caller rather than decoded here: the runtime
///'s exception agent needs the typed clause list, and keeping the shape in one
/// place avoids two decoders drifting apart.
fn scan_catch_handlers(bytes: &[u8], tries_size: usize) -> Result<(Vec<u8>, usize)> {
    let bad = || Error::BadUleb128 { at: 0 };
    let (list_size, mut p) = mutf8::read_uleb128(bytes, 0)?;
    // A well-formed file never declares more handler lists than try items, and
    // the cap keeps a hostile value from making us walk the whole tail.
    if list_size as usize > tries_size {
        return Err(bad());
    }
    for _ in 0..list_size {
        let (size, n) = mutf8::read_sleb128(bytes, p)?;
        p += n;
        let clauses = size.unsigned_abs() as usize;
        if clauses > tries_size {
            return Err(bad());
        }
        for _ in 0..clauses {
            let (_, n) = mutf8::read_uleb128(bytes, p)?;
            p += n;
            let (_, n) = mutf8::read_uleb128(bytes, p)?;
            p += n;
        }
        if size <= 0 {
            let (_, n) = mutf8::read_uleb128(bytes, p)?;
            p += n;
        }
    }
    let p = p.min(bytes.len());
    Ok((bytes[..p].to_vec(), p))
}

/// Decode one instruction from `units` at index `at` (in code units).
///
/// Returns the instruction and the number of code units it occupies. Branch
/// offsets are returned raw and relative; resolving them needs a code-item
/// base address, which the caller has.
pub fn decode_one(units: &[u16], at: usize) -> Result<(Instruction, usize)> {
    let unit = *units.get(at).ok_or(Error::BadInstruction {
        at: at * 2,
        detail: "read past end of instruction stream".into(),
    })?;
    let byte_off = at * 2;

    if let Some(kind) = crate::opcodes::PayloadKind::from_unit(unit) {
        return decode_payload(kind, units, at, byte_off);
    }

    let op = (unit & 0xff) as u8;
    let entry = crate::opcodes::opcode(op);
    let width_units = entry.format.code_units() as usize;
    if width_units == 0 {
        return Err(Error::BadInstruction {
            at: byte_off,
            detail: format!("opcode 0x{op:02x} has no operand format"),
        });
    }
    // Word k is the k-th u16 from `at`; the opcode occupies byte lanes 0 of w0.
    let w = |k: usize| -> u16 { units.get(at + k).copied().unwrap_or(0) };
    if at + width_units > units.len() {
        return Err(Error::BadInstruction {
            at: byte_off,
            detail: format!(
                "opcode 0x{op:02x} ({}) needs {width_units} code units, only {} remain",
                entry.mnemonic,
                units.len() - at
            ),
        });
    }

    use crate::opcodes::Format as F;
    let insn = match entry.format {
        F::F10X => Instruction::F10X { op },
        // 10t: `op AA` — the offset is the *high* byte of the first unit.
        F::F10T => Instruction::F10T { op, offset: ((w(0) >> 8) as u8) as i8 },
        F::F11N => {
            // `B|A|op` — A is the low nibble of byte 1, B the high nibble.
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F11N { op, a, b, literal: sign_extend(b, 4) }
        }
        F::F11X => Instruction::F11X { op, a: (w(0) >> 8) as u8 },
        F::F12X => {
            // Byte lanes are B|A|op, so A is bits 8..12 and B is bits 12..16.
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F12X { op, a, b }
        }
        F::F20T => Instruction::F20T { op, offset: w(1) as i16 },
        F::F20BC => Instruction::F20BC { op, a: (w(0) >> 8) as u8, index: w(1) },
        F::F21C => Instruction::F21C { op, a: (w(0) >> 8) as u8, index: w(1) },
        F::F21H => Instruction::F21H { op, a: (w(0) >> 8) as u8, literal: w(1) as i16 },
        F::F21S => Instruction::F21S { op, a: (w(0) >> 8) as u8, literal: w(1) as i16 },
        F::F21T => Instruction::F21T { op, a: (w(0) >> 8) as u8, offset: w(1) as i16 },
        // 22b: `op AA vBB, #+CC`. A is the high byte of unit 0; B and CC are
        // the low and high bytes of unit 1 respectively.
        F::F22B => Instruction::F22B {
            op,
            a: (w(0) >> 8) as u8,
            b: w(1) as u8,
            literal: ((w(1) >> 8) as u8) as i8,
        },
        F::F22X => Instruction::F22X { op, a: (w(0) >> 8) as u8, b: w(1) },
        F::F22C => {
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F22C { op, a, b, index: w(1) }
        }
        F::F22S => {
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F22S { op, a, b, literal: w(1) as i16 }
        }
        F::F22T => {
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F22T { op, a, b, offset: w(1) as i16 }
        }
        F::F22CS => {
            let a = ((w(0) >> 8) & 0x0f) as u8;
            let b = ((w(0) >> 12) & 0x0f) as u8;
            Instruction::F22CS { op, a, b, index: w(1) }
        }
        // 23x: `op AA vBB, vCC`. A is the high byte of unit 0; B and C are the
        // low and high bytes of unit 1 respectively.
        F::F23X => {
            Instruction::F23X { op, a: (w(0) >> 8) as u8, b: w(1) as u8, c: (w(1) >> 8) as u8 }
        }
        F::F30T => Instruction::F30T { op, offset: u32_at(units, at + 1) as i32 },
        F::F31C => Instruction::F31C { op, a: (w(0) >> 8) as u8, index: u32_at(units, at + 1) },
        F::F31I => Instruction::F31I { op, a: (w(0) >> 8) as u8, literal: u32_at(units, at + 1) as i32 },
        F::F31T => Instruction::F31T { op, a: (w(0) >> 8) as u8, offset: u32_at(units, at + 1) as i32 },
        F::F32X => Instruction::F32X { op, a: w(0), b: w(1) },
        // 35c: byte 1 is `A|G` with A in the *high* nibble and G in the low one,
        // then the method index, then `C|D|E|F`. The packed argument registers
        // live in the third code unit, and the fifth in G.
        F::F35C => {
            let regs = unpack_regs(w(2), ((w(0) >> 8) & 0x0f) as u8);
            Instruction::F35C { op, a: ((w(0) >> 12) & 0x0f) as u8, g: ((w(0) >> 8) & 0x0f) as u8, index: w(1), regs }
        }
        F::F35MI => {
            let regs = unpack_regs(w(2), ((w(0) >> 8) & 0x0f) as u8);
            Instruction::F35MI { op, a: ((w(0) >> 12) & 0x0f) as u8, g: ((w(0) >> 8) & 0x0f) as u8, index: w(1), regs }
        }
        F::F35MS => Instruction::F35MS {
            op,
            a: ((w(0) >> 12) & 0x0f) as u8,
            g: ((w(0) >> 8) & 0x0f) as u8,
            index: w(1),
            first_reg: w(2),
            reg_count: (w(0) >> 8),
        },
        // 3rc: byte 1 is AA, the *whole byte* register count, then the method
        // index, then the first register of the contiguous range.
        F::F3RC => Instruction::F3RC {
            op,
            a: (w(0) >> 8) as u8,
            index: w(1),
            first_reg: w(2),
            reg_count: (w(0) >> 8),
        },
        F::F3RMI => Instruction::F3RMI {
            op,
            a: (w(0) >> 8) as u8,
            index: w(1),
            first_reg: w(2),
            reg_count: (w(0) >> 8),
        },
        F::F3RMS => Instruction::F3RMS {
            op,
            a: (w(0) >> 8) as u8,
            index: w(1),
            first_reg: w(2),
            reg_count: (w(0) >> 8),
        },
        F::F45CC => {
            let regs = unpack_regs(w(2), ((w(0) >> 8) & 0x0f) as u8);
            Instruction::F45CC { op, a: ((w(0) >> 12) & 0x0f) as u8, g: ((w(0) >> 8) & 0x0f) as u8, index: w(1), regs, proto: w(3) }
        }
        F::F4RCC => Instruction::F4RCC {
            op,
            a: (w(0) >> 8) as u8,
            index: w(1),
            first_reg: w(2),
            reg_count: (w(0) >> 8),
            proto: w(3),
        },
        F::F51L => {
            let lo = u32_at(units, at + 1) as u64;
            let hi = u32_at(units, at + 3) as u64;
            Instruction::F51L { op, a: (w(0) >> 8) as u8, literal: ((hi << 32) | lo) as i64 }
        }
        F::F52C => Instruction::F52C { op, a: w(0), b: w(1), index: u32_at(units, at + 2) },
        F::F5RC => Instruction::F5RC { op, index: u32_at(units, at + 1), first_reg: w(3), reg_count: w(2) },
        // Foreign formats. No Dalvik opcode uses these, but decoding them
        // costs nothing and keeps a malformed file from failing hard.
        F::F40SC => Instruction::F20BC { op, a: (w(1) >> 8) as u8, index: w(1) & 0xff },
        F::F41C => Instruction::F20BC { op, a: (w(1) >> 8) as u8, index: w(0) },
        F::F00X => {
            return Err(Error::BadInstruction {
                at: byte_off,
                detail: format!("opcode 0x{op:02x} has format 00x"),
            })
        }
    };

    if !entry.valid {
        return Ok((Instruction::Unused { op }, width_units));
    }
    Ok((insn, width_units))
}

fn decode_payload(
    kind: crate::opcodes::PayloadKind,
    units: &[u16],
    at: usize,
    byte_off: usize,
) -> Result<(Instruction, usize)> {
    use crate::opcodes::PayloadKind as K;
    let bad = |d: &str| Error::BadInstruction { at: byte_off, detail: d.to_string() };
    let need = |n: usize| -> Result<()> {
        if at + n > units.len() {
            Err(bad("payload runs past end of instruction stream"))
        } else {
            Ok(())
        }
    };
    // 32-bit payload fields are indexed by *word*, not by code unit: word `w`
    // occupies code units `2*w` and `2*w + 1`.
    let word = |w: usize| -> u32 {
        (units.get(at + 2 * w).copied().unwrap_or(0) as u32)
            | ((units.get(at + 2 * w + 1).copied().unwrap_or(0) as u32) << 16)
    };
    let word_i = |w: usize| -> i32 { word(w) as i32 };

    match kind {
        // packed-switch-payload: ident(u16), size(u16), first_key(i32),
        // targets[size](i32). `size` is a *short*, not a u32.
        K::PackedSwitch => {
            need(3)?;
            let size = units[at + 1] as usize;
            // words 0..=2+size are read (ident, size, first_key, targets),
            // so the advance must be 2*(2+size) units, not 4+size.
            let total = 4 + 2 * size;
            need(total)?;
            // first_key is 32-bit word 1; targets follow as 32-bit words.
            let first_key = word_i(1);
            let targets = (0..size).map(|i| word_i(2 + i)).collect();
            Ok((
                Instruction::Payload(Payload::PackedSwitch(PackedSwitch {
                    ident: units[at],
                    first_key,
                    targets,
                })),
                total,
            ))
        }
        // sparse-switch-payload: ident(u16), size(u16), keys[size](i32),
        // targets[size](i32).
        K::SparseSwitch => {
            need(2)?;
            let size = units[at + 1] as usize;
            // words 0..=1+2*size are read (ident, size, keys, targets).
            let total = 2 + 4 * size;
            need(total)?;
            let keys = (0..size).map(|i| word_i(1 + i)).collect();
            let targets = (0..size).map(|i| word_i(1 + size + i)).collect();
            Ok((
                Instruction::Payload(Payload::SparseSwitch(SparseSwitch {
                    ident: units[at],
                    keys,
                    targets,
                })),
                total,
            ))
        }
        // fill-array-data-payload: ident(u16), element_width(u16), size(u32),
        // then element_width*size bytes, padded to a whole code unit.
        K::FillArrayData => {
            need(4)?;
            let element_width = units[at + 1];
            let size = word(1);
            let data_bytes = (element_width as u64) * (size as u64);
            if data_bytes > units.len() as u64 * 2 {
                return Err(bad("fill-array-data payload length exceeds the code item"));
            }
            let total = 4 + data_bytes.div_ceil(2) as usize;
            need(total)?;
            // Reinterpret the code units as little-endian bytes.
            let start = (at + 4) * 2;
            let mut data = Vec::with_capacity(data_bytes as usize);
            for k in 0..(data_bytes as usize / 2) {
                let u = units[start / 2 + k];
                data.extend_from_slice(&u.to_le_bytes());
            }
            if data_bytes % 2 == 1 {
                data.push(units[start / 2 + data_bytes as usize / 2] as u8);
            }
            Ok((
                Instruction::Payload(Payload::FillArrayData(FillArrayData {
                    ident: units[at],
                    element_width,
                    size,
                    data,
                })),
                total,
            ))
        }
    }
}

/// Unpack a `35c`-family third code unit: `C|D|E|F` in nibbles 0..4.
#[inline]
fn unpack_cdef(third_word: u16) -> [u8; 4] {
    [
        (third_word & 0x0f) as u8,
        ((third_word >> 4) & 0x0f) as u8,
        ((third_word >> 8) & 0x0f) as u8,
        ((third_word >> 12) & 0x0f) as u8,
    ]
}

/// Full packed argument register list `[C, D, E, F, G]` for a `35c` instruction.
#[inline]
fn unpack_regs(third_word: u16, g: u8) -> [u8; 5] {
    let cdef = unpack_cdef(third_word);
    [cdef[0], cdef[1], cdef[2], cdef[3], g]
}

#[inline]
fn u32_at(units: &[u16], at: usize) -> u32 {
    let lo = units.get(at).copied().unwrap_or(0) as u32;
    let hi = units.get(at + 1).copied().unwrap_or(0) as u32;
    lo | (hi << 16)
}

#[inline]
fn sign_extend(v: u8, bits: u32) -> i8 {
    let shift = 8 - bits;
    ((v << shift) as i8) >> shift
}

/// One decoded instruction together with its position.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Located {
    /// Offset within the code item, in code units.
    pub unit_offset: u32,
    /// Offset within the code item, in bytes.
    pub byte_offset: u32,
    pub instruction: Instruction,
}

/// Walk an entire instruction stream linearly, decoding every instruction.
///
/// This is the entry point the runtime uses to build a control-flow graph, and
/// the one place where a corrupt stream could otherwise loop forever, so it is
/// also the place that guarantees forward progress: every step consumes at
/// least one code unit.
pub fn decode_all(units: &[u16]) -> Result<Vec<Located>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < units.len() {
        let (insn, n) = decode_one(units, at)?;
        debug_assert!(n >= 1, "decode_one must consume at least one code unit");
        out.push(Located {
            unit_offset: at as u32,
            byte_offset: (at * 2) as u32,
            instruction: insn,
        });
        at += n;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble little-endian code units from byte pairs for the tests below.
    fn units(bytes: &[u8]) -> Vec<u16> {
        bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    }

    #[test]
    fn decodes_12x_nibble_order() {
        // move vA, vB  =>  byte lanes B|A|op, so byte0 = op and byte1 = (B<<4)|A
        let u = units(&[0x01, 0xba]);
        let (i, n) = decode_one(&u, 0).unwrap();
        assert_eq!(i, Instruction::F12X { op: 0x01, a: 0xa, b: 0xb });
        assert_eq!(n, 1);
        assert_eq!(i.mnemonic(), "move");
    }

    #[test]
    fn decodes_11n_signed_nibble() {
        // const/4 vA, #+B  =>  B|A|op
        // const/4 vE, #+2  =>  byte1 = (B << 4) | A = 0x2E
        let (i, n) = decode_one(&units(&[0x12, 0x2e]), 0).unwrap();
        assert_eq!(i, Instruction::F11N { op: 0x12, a: 0xe, b: 0x2, literal: 2 });
        assert_eq!(n, 1);
        // Negative literal: B = 0xf sign-extends to -1.
        // const/4 vF, #-1  =>  byte1 = 0xFF
        let (i, _) = decode_one(&units(&[0x12, 0xff]), 0).unwrap();
        assert_eq!(i, Instruction::F11N { op: 0x12, a: 0xf, b: 0xf, literal: -1 });
    }

    #[test]
    fn decodes_23x_byte_lanes() {
        // aget v3, v1, v2  =>  op AA vBB, vCC, so byte2 is BB and byte3 is CC.
        let (i, n) = decode_one(&units(&[0x44, 0x03, 0x01, 0x02]), 0).unwrap();
        assert_eq!(i, Instruction::F23X { op: 0x44, a: 3, b: 1, c: 2 });
        assert_eq!(n, 2);
    }

    #[test]
    fn decodes_22b_byte_lanes() {
        // add-int/lit8 v0, v0, #-1  =>  op AA vBB, #+CC. These exact bytes were
        // cross-checked against androguard's disassembly of a real DEX file.
        let (i, n) = decode_one(&units(&[0xd8, 0x00, 0x00, 0xff]), 0).unwrap();
        assert_eq!(i, Instruction::F22B { op: 0xd8, a: 0, b: 0, literal: -1 });
        assert_eq!(n, 2);

        let (i, _) = decode_one(&units(&[0xd8, 0x01, 0x00, 0x01]), 0).unwrap();
        assert_eq!(i, Instruction::F22B { op: 0xd8, a: 1, b: 0, literal: 1 });
    }

    #[test]
    fn decodes_21c_pool_index() {
        // const-string v0, string@7
        let (i, n) = decode_one(&units(&[0x1a, 0x00, 0x07, 0x00]), 0).unwrap();
        assert_eq!(i, Instruction::F21C { op: 0x1a, a: 0, index: 7 });
        assert_eq!(n, 2);
        assert_eq!(i.mnemonic(), "const-string");
    }

    #[test]
    fn decodes_31i_32bit_literal() {
        let (i, n) = decode_one(&units(&[0x14, 0x00, 0xff, 0xff, 0xff, 0x7f]), 0).unwrap();
        assert_eq!(i, Instruction::F31I { op: 0x14, a: 0, literal: i32::MAX });
        assert_eq!(n, 3);
    }

    #[test]
    fn decodes_51l_64bit_literal() {
        let mut b = vec![0x18, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x80];
        b.extend_from_slice(&i64::MIN.to_le_bytes()[4..]);
        let (i, n) = decode_one(&units(&b), 0).unwrap();
        assert_eq!(i, Instruction::F51L { op: 0x18, a: 0, literal: i64::MIN });
        assert_eq!(n, 5);
    }

    #[test]
    fn decodes_35c_packed_registers() {
        // These exact bytes are androguard's raw output for
        // `invoke-virtual v2, La;->hasNext()Z` in a real DEX file: byte 1 is
        // 0x10, so A = 1 (the argument count d8 writes) and G = 0; the packed
        // arguments C, D are 2, 0 in the third code unit.
        let (i, n) = decode_one(&units(&[0x6e, 0x10, 0x01, 0x00, 0x02, 0x00]), 0).unwrap();
        assert_eq!(
            i,
            Instruction::F35C { op: 0x6e, a: 1, g: 0, index: 1, regs: [2, 0, 0, 0, 0] }
        );
        assert_eq!(n, 3);
        assert_eq!(i.argument_registers(), vec![2]);
    }

    #[test]
    fn decodes_3rc_register_range() {
        // androguard's raw output for `invoke-virtual/range v25, method@1`.
        let (i, n) = decode_one(&units(&[0x74, 0x01, 0x01, 0x00, 0x19, 0x00]), 0).unwrap();
        assert_eq!(i, Instruction::F3RC { op: 0x74, a: 1, index: 1, first_reg: 25, reg_count: 1 });
        assert_eq!(n, 3);
        assert_eq!(i.argument_registers(), vec![25]);
    }

    #[test]
    fn decodes_45cc_polymorphic() {
        let (i, n) = decode_one(&units(&[0xfa, 0x10, 0x05, 0x00, 0x21, 0x00, 0x0a, 0x00]), 0)
            .unwrap();
        assert_eq!(i.mnemonic(), "invoke-polymorphic");
        assert_eq!(n, 4);
        match i {
            Instruction::F45CC { proto, index, .. } => {
                assert_eq!(proto, 10);
                assert_eq!(index, 5);
            }
            other => panic!("expected F45CC, got {other:?}"),
        }
    }

    #[test]
    fn decodes_negative_branch_offsets() {
        let (i, _) = decode_one(&units(&[0x28, 0xf0]), 0).unwrap(); // goto -16
        assert_eq!(i, Instruction::F10T { op: 0x28, offset: -16 });
        let (i, _) = decode_one(&units(&[0x29, 0x00, 0xfe, 0xff]), 0).unwrap(); // goto/16 -2
        assert_eq!(i, Instruction::F20T { op: 0x29, offset: -2 });
    }

    #[test]
    fn decodes_packed_switch_payload() {
        // ident 0x0100, size 2, first_key 10, targets 0 and 5
        let mut b = vec![0x00, 0x01, 0x02, 0x00];
        b.extend_from_slice(&10i32.to_le_bytes());
        b.extend_from_slice(&0i32.to_le_bytes());
        b.extend_from_slice(&5i32.to_le_bytes());
        let (i, n) = decode_one(&units(&b), 0).unwrap();
        assert_eq!(n, 8);
        match i {
            Instruction::Payload(Payload::PackedSwitch(ref p)) => {
                assert_eq!(p.first_key, 10);
                assert_eq!(p.targets, vec![0, 5]);
            }
            other => panic!("expected packed switch, got {other:?}"),
        }
        assert_eq!(i.width(), 16);
    }

    #[test]
    fn decodes_sparse_switch_payload() {
        let mut b = vec![0x00, 0x02, 0x02, 0x00];
        for v in [100i32, 200, 1, 2] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let (i, n) = decode_one(&units(&b), 0).unwrap();
        // 2 ident/size + 2 keys + 2 targets words = 5 words = 10 units.
        assert_eq!(n, 10);
        match i {
            Instruction::Payload(Payload::SparseSwitch(ref s)) => {
                assert_eq!(s.keys, vec![100, 200]);
                assert_eq!(s.targets, vec![1, 2]);
            }
            other => panic!("expected sparse switch, got {other:?}"),
        }
    }

    #[test]
    fn decodes_fill_array_data_payload_with_odd_length() {
        // element_width 1, size 3, data 01 02 03, padded to a whole unit.
        let mut b = vec![0x00, 0x03, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00];
        b.extend_from_slice(&[0x01, 0x02, 0x03, 0x00]);
        let (i, n) = decode_one(&units(&b), 0).unwrap();
        assert_eq!(n, 6);
        match i {
            Instruction::Payload(Payload::FillArrayData(ref f)) => {
                assert_eq!(f.element_width, 1);
                assert_eq!(f.size, 3);
                assert_eq!(f.data, vec![1, 2, 3]);
            }
            other => panic!("expected fill array data, got {other:?}"),
        }
        assert_eq!(i.width(), 12);
    }

    #[test]
    fn fill_array_data_handles_wide_elements() {
        // element_width 4, size 2 => 8 data bytes => 4 code units of data.
        let mut b = vec![0x00, 0x03, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00];
        for v in [0x1122_3344u32, 0x5566_7788] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        let (i, n) = decode_one(&units(&b), 0).unwrap();
        assert_eq!(n, 8);
        match i {
            Instruction::Payload(Payload::FillArrayData(ref f)) => {
                assert_eq!(f.element_width, 4);
                assert_eq!(f.data.len(), 8);
                assert_eq!(&f.data[0..4], &0x1122_3344u32.to_le_bytes());
            }
            other => panic!("expected fill array data, got {other:?}"),
        }
    }

    #[test]
    fn unused_opcode_advances_by_two_bytes() {
        let (i, n) = decode_one(&units(&[0x73, 0x00, 0x00, 0x00]), 0).unwrap();
        assert_eq!(i, Instruction::Unused { op: 0x73 });
        assert_eq!(n, 1);
    }

    #[test]
    fn truncated_instruction_is_an_error_not_a_panic() {
        // goto/32 claims 3 units but only 2 are present.
        let u = units(&[0x2a, 0x00, 0x00, 0x00]);
        let e = decode_one(&u, 0).unwrap_err();
        assert!(matches!(e, Error::BadInstruction { .. }), "got {e:?}");
    }

    #[test]
    fn payload_running_past_end_is_an_error() {
        // packed-switch payload claiming 100 entries with none present.
        let u = units(&[0x00, 0x01, 0x64, 0x00]);
        assert!(matches!(decode_one(&u, 0), Err(Error::BadInstruction { .. })));
    }

    #[test]
    fn decode_all_walks_a_whole_stream() {
        // const/4 v0, #1 ; const/4 v1, #2 ; return v0
        let u = units(&[0x12, 0x10, 0x12, 0x21, 0x0f, 0x00]);
        let all = decode_all(&u).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].unit_offset, 0);
        assert_eq!(all[1].unit_offset, 1);
        assert_eq!(all[2].unit_offset, 2);
        assert_eq!(all[2].instruction.mnemonic(), "return");
    }

    #[test]
    fn decode_all_terminates_on_a_stream_of_unused_opcodes() {
        let u: Vec<u16> = (0..100).map(|_| 0x0073).collect();
        let all = decode_all(&u).unwrap();
        assert_eq!(all.len(), 100);
    }
}
