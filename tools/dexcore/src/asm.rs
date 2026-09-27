//! Instruction encoder.
//!
//! [`Assembler`] builds the `insns` byte stream for a [`CodeBody`]. It covers
//! the instruction formats a synthetic `android.*` shim actually needs — the
//! constructors, field accesses, calls, constants, type operations and control
//! flow an app touches when it calls into the framework — rather than the whole
//! 256-opcode set.
//!
//! Every emitted instruction is a pure function of its operands, and the
//! integration tests round-trip each one through [`crate::reader::decode_all`]
//! to prove the encoding and the decoder agree.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

use crate::error::{Error, Result};
use crate::writer::CodeBody;

/// Accumulates little-endian instruction units.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assembler {
    bytes: Vec<u8>,
}

impl Assembler {
    /// An empty assembler.
    pub fn new() -> Assembler {
        Assembler::default()
    }

    /// The assembled bytes, ready for [`CodeBody::insns`].
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// The assembled bytes without consuming the assembler.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of 16-bit code units emitted so far.
    pub fn len_units(&self) -> usize {
        self.bytes.len() / 2
    }

    /// True if nothing has been emitted.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Build a [`CodeBody`] with the given register frame and this stream.
    pub fn into_code(self, registers_size: u16, ins_size: u16, outs_size: u16) -> CodeBody {
        CodeBody {
            registers_size,
            ins_size,
            outs_size,
            insns: self.bytes,
            tries: Vec::new(),
        }
    }

    fn u16le(&mut self, v: u16) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    fn u32le(&mut self, v: u32) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    /// `nop` (`10x`).
    pub fn nop(&mut self) -> &mut Self {
        self.u16le(0x0000);
        self
    }

    /// `return-void` (`10x`).
    pub fn return_void(&mut self) -> &mut Self {
        self.u16le(0x000e);
        self
    }

    /// `return vAA` (`11x`).
    pub fn r#return(&mut self, a: u8) -> &mut Self {
        self.u16le(0x000f | ((a as u16) << 8));
        self
    }

    /// `return-wide vAA` (`11x`).
    pub fn return_wide(&mut self, a: u8) -> &mut Self {
        self.u16le(0x0010 | ((a as u16) << 8));
        self
    }

    /// `return-object vAA` (`11x`).
    pub fn return_object(&mut self, a: u8) -> &mut Self {
        self.u16le(0x0011 | ((a as u16) << 8));
        self
    }

    /// `goto offset` (`10t`), a signed 8-bit branch in code units.
    pub fn goto(&mut self, offset: i8) -> &mut Self {
        self.u16le(0x0028 | ((offset as u8 as u16) << 8));
        self
    }

    /// `goto/16 offset` (`20t`).
    pub fn goto16(&mut self, offset: i16) -> &mut Self {
        self.u16le(0x0029);
        self.u16le(offset as u16);
        self
    }

    /// `goto/32 offset` (`30t`).
    pub fn goto32(&mut self, offset: i32) -> &mut Self {
        self.u16le(0x002a);
        self.u32le(offset as u32);
        self
    }

    /// `move vA, vB` (`12x`).
    pub fn move_(&mut self, a: u8, b: u8) -> Result<&mut Self> {
        self.nibble2(0x01, a, b)
    }

    /// `move/from16 vAA, vBBBB` (`22x`).
    pub fn move_from16(&mut self, a: u8, b: u16) -> &mut Self {
        self.u16le(0x0002 | ((a as u16) << 8));
        self.u16le(b);
        self
    }

    /// `move-result vAA` (`11x`).
    pub fn move_result(&mut self, a: u8) -> &mut Self {
        self.u16le(0x000a | ((a as u16) << 8));
        self
    }

    /// `move-result-object vAA` (`11x`).
    pub fn move_result_object(&mut self, a: u8) -> &mut Self {
        self.u16le(0x000c | ((a as u16) << 8));
        self
    }

    /// `move-exception vAA` (`11x`).
    pub fn move_exception(&mut self, a: u8) -> &mut Self {
        self.u16le(0x000d | ((a as u16) << 8));
        self
    }

    /// `const/4 vA, #+B` (`11n`). Layout is `B|A|op`, so byte 1 is
    /// `(B << 4) | A`; only the low four bits of `literal` survive.
    pub fn const4(&mut self, a: u8, literal: i8) -> Result<&mut Self> {
        let b = ((literal as u16) & 0x000f) << 12;
        self.u16le(0x0012 | (((a as u16) & 0x000f) << 8) | b);
        Ok(self)
    }

    /// `const/16 vAA, #+BBBB` (`21s`).
    pub fn const16(&mut self, a: u8, literal: i16) -> &mut Self {
        self.u16le(0x0013 | ((a as u16) << 8));
        self.u16le(literal as u16);
        self
    }

    /// `const vAA, #+BBBBBBBB` (`31i`).
    pub fn const32(&mut self, a: u8, literal: i32) -> &mut Self {
        self.u16le(0x0014 | ((a as u16) << 8));
        self.u32le(literal as u32);
        self
    }

    /// `const-string vAA, string@BBBB` (`21c`).
    pub fn const_string(&mut self, a: u8, string_idx: u16) -> &mut Self {
        self.u16le(0x001a | ((a as u16) << 8));
        self.u16le(string_idx);
        self
    }

    /// `const-class vAA, type@BBBB` (`21c`).
    pub fn const_class(&mut self, a: u8, type_idx: u16) -> &mut Self {
        self.u16le(0x001c | ((a as u16) << 8));
        self.u16le(type_idx);
        self
    }

    /// `new-instance vAA, type@BBBB` (`21c`).
    pub fn new_instance(&mut self, a: u8, type_idx: u16) -> &mut Self {
        self.u16le(0x0022 | ((a as u16) << 8));
        self.u16le(type_idx);
        self
    }

    /// `array-length vA, vB` (`12x`).
    pub fn array_length(&mut self, a: u8, b: u8) -> Result<&mut Self> {
        self.nibble2(0x0021, a, b)
    }

    /// `check-cast vAA, type@BBBB` (`21c`).
    pub fn check_cast(&mut self, a: u8, type_idx: u16) -> &mut Self {
        self.u16le(0x001f | ((a as u16) << 8));
        self.u16le(type_idx);
        self
    }

    /// `instance-of vA, vB, type@CCCC` (`22c`).
    pub fn instance_of(&mut self, a: u8, b: u8, type_idx: u16) -> Result<&mut Self> {
        self.nibble2_index(0x0020, a, b, type_idx)
    }

    /// `throw vAA` (`11x`).
    pub fn throw(&mut self, a: u8) -> &mut Self {
        self.u16le(0x0027 | ((a as u16) << 8));
        self
    }

    /// `iget vA, vB, field@CCCC` (`22c`).
    pub fn iget(&mut self, opcode: u8, a: u8, b: u8, field_idx: u16) -> Result<&mut Self> {
        if !(0x52..=0x58).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "iget opcode", value: opcode as u64 });
        }
        self.nibble2_index(opcode, a, b, field_idx)
    }

    /// `iput vA, vB, field@CCCC` (`22c`).
    pub fn iput(&mut self, opcode: u8, a: u8, b: u8, field_idx: u16) -> Result<&mut Self> {
        if !(0x59..=0x5f).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "iput opcode", value: opcode as u64 });
        }
        self.nibble2_index(opcode, a, b, field_idx)
    }

    /// `sget vAA, field@BBBB` (`21c`).
    pub fn sget(&mut self, opcode: u8, a: u8, field_idx: u16) -> Result<&mut Self> {
        if !(0x60..=0x66).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "sget opcode", value: opcode as u64 });
        }
        self.u16le((opcode as u16) | ((a as u16) << 8));
        self.u16le(field_idx);
        Ok(self)
    }

    /// `sput vAA, field@BBBB` (`21c`).
    pub fn sput(&mut self, opcode: u8, a: u8, field_idx: u16) -> Result<&mut Self> {
        if !(0x67..=0x6d).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "sput opcode", value: opcode as u64 });
        }
        self.u16le((opcode as u16) | ((a as u16) << 8));
        self.u16le(field_idx);
        Ok(self)
    }

    /// `invoke-kind {regs}, method@BBBB` (`35c`).
    ///
    /// `opcode` must be one of `invoke-virtual` (0x6e), `invoke-super` (0x6f),
    /// `invoke-direct` (0x70), `invoke-static` (0x71) or `invoke-interface`
    /// (0x72).
    ///
    /// `regs` holds the argument registers in order, including the implicit
    /// `this` for the non-static forms. At most five fit in `35c`; use
    /// [`Assembler::invoke_range`] for more.
    ///
    /// The `A` nibble receives the argument count. That is what d8 emits, and
    /// it is what every APK in the wild contains; the call's result is
    /// delivered by a following `move-result` rather than encoded here.
    pub fn invoke(&mut self, opcode: u8, regs: &[u8], method_idx: u16) -> Result<&mut Self> {
        if !(0x6e..=0x72).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "invoke opcode", value: opcode as u64 });
        }
        if regs.is_empty() || regs.len() > 5 {
            return Err(Error::ValueOutOfRange {
                what: "invoke register count (35c takes 1..=5)",
                value: regs.len() as u64,
            });
        }
        if regs.iter().any(|&r| r > 15) {
            return Err(Error::ValueOutOfRange { what: "invoke register (must fit 4 bits)", value: 0 });
        }
        // C..F take the first four arguments; a fifth goes in the G nibble.
        let g = if regs.len() == 5 { regs[4] as u16 } else { 0 };
        let cdef = pack_nibbles(&regs[..regs.len().min(4)]);
        self.u16le((opcode as u16) | (g << 8) | ((regs.len() as u16) << 12));
        self.u16le(method_idx);
        self.u16le(cdef);
        Ok(self)
    }

    /// `invoke-kind/range {vCCCC .. vNNNN}, method@BBBB` (`3rc`).
    pub fn invoke_range(
        &mut self,
        opcode: u8,
        first_reg: u16,
        reg_count: u16,
        method_idx: u16,
    ) -> Result<&mut Self> {
        if !(0x74..=0x78).contains(&opcode) {
            return Err(Error::ValueOutOfRange { what: "invoke/range opcode", value: opcode as u64 });
        }
        if reg_count == 0 || reg_count > 255 {
            return Err(Error::ValueOutOfRange { what: "invoke/range register count", value: reg_count as u64 });
        }
        self.u16le((opcode as u16) | ((reg_count & 0xff) << 8));
        self.u16le(method_idx);
        self.u16le(first_reg);
        Ok(self)
    }

    /// `add-int vA, vB, vC` (`23x`). The other integer `23x` opcodes use the
    /// same layout; see [`Assembler::raw_23x`].
    pub fn add_int(&mut self, a: u8, b: u8, c: u8) -> &mut Self {
        self.raw_23x(0x90, a, b, c)
    }

    /// `aget vAA, vBB, vCC` (`23x`).
    pub fn aget(&mut self, a: u8, b: u8, c: u8) -> &mut Self {
        self.raw_23x(0x44, a, b, c)
    }

    /// `aput vAA, vBB, vCC` (`23x`).
    pub fn aput(&mut self, a: u8, b: u8, c: u8) -> &mut Self {
        self.raw_23x(0x4b, a, b, c)
    }

    /// Emit any `23x` instruction by opcode. Layout is `op AA vBB, vCC`: `a` is
    /// the high byte of the first unit, `b` and `c` are the two bytes of the
    /// second.
    pub fn raw_23x(&mut self, opcode: u8, a: u8, b: u8, c: u8) -> &mut Self {
        self.u16le((opcode as u16) | ((a as u16) << 8));
        self.u16le(((c as u16) << 8) | b as u16);
        self
    }

    /// `add-int/lit8 vA, vB, #+CC` (`22b`).
    pub fn add_int_lit8(&mut self, a: u8, b: u8, literal: i8) -> &mut Self {
        self.u16le(0x00d8 | ((a as u16) << 8));
        self.u16le(((literal as u16 as u8 as u16) << 8) | b as u16);
        self
    }

    /// Append a `fill-array-data-payload` (`31t`-addressed).
    ///
    /// The payload is a pseudo-instruction that follows the `fill-array-data`
    /// branch, so the branch offset is relative to it. `element_width` is 1, 2
    /// or 4 for the primitive widths Dalvik generates, or 8 for `long` and
    /// `double`. The body is padded to a whole number of code units, which is
    /// what the decoder's width calculation assumes.
    pub fn fill_array_data(
        &mut self,
        reg: u8,
        payload_start: u16,
        element_width: u16,
        count: u32,
        data: &[u8],
    ) -> Result<&mut Self> {
        if ![1u16, 2, 4, 8].contains(&element_width) {
            return Err(Error::ValueOutOfRange { what: "fill-array-data element width", value: element_width as u64 });
        }
        if (element_width as usize) * (count as usize) != data.len() {
            return Err(Error::ValueOutOfRange {
                what: "fill-array-data length (must be element_width * count)",
                value: data.len() as u64,
            });
        }
        // The branch offset is measured from the fill-array-data instruction to
        // the first code unit of the payload.
        let here = self.len_units() as i64;
        let offset = payload_start as i64 - here;
        if !(-2147483648..=2147483647).contains(&offset) {
            return Err(Error::ValueOutOfRange { what: "fill-array-data branch offset", value: offset as u64 });
        }
        self.fill_array_data_branch(reg, offset as i32);
        // ident, element_width, size, then the data padded to a code unit.
        self.u16le(0x0300);
        self.u16le(element_width);
        let mut w = Vec::with_capacity(4);
        w.extend_from_slice(&count.to_le_bytes());
        self.bytes.extend_from_slice(&w);
        self.bytes.extend_from_slice(data);
        if data.len() % 2 == 1 {
            self.bytes.push(0);
        }
        Ok(self)
    }

    /// `fill-array-data vAA, +BBBBBBBB` (`31t`).
    pub fn fill_array_data_branch(&mut self, reg: u8, offset: i32) -> &mut Self {
        self.u16le(0x0026 | ((reg as u16) << 8));
        self.u32le(offset as u32);
        self
    }

    /// `if-eqz vAA, +BBBB` (`21t`).
    pub fn if_eqz(&mut self, a: u8, offset: i16) -> &mut Self {
        self.u16le(0x0038 | ((a as u16) << 8));
        self.u16le(offset as u16);
        self
    }

    /// `if-nez vAA, +BBBB` (`21t`).
    pub fn if_nez(&mut self, a: u8, offset: i16) -> &mut Self {
        self.u16le(0x0039 | ((a as u16) << 8));
        self.u16le(offset as u16);
        self
    }

    /// `if-eq vA, vB, +CCCC` (`22t`).
    pub fn if_eq(&mut self, a: u8, b: u8, offset: i16) -> Result<&mut Self> {
        self.branch22t(0x0032, a, b, offset)
    }

    /// `if-ne vA, vB, +CCCC` (`22t`).
    pub fn if_ne(&mut self, a: u8, b: u8, offset: i16) -> Result<&mut Self> {
        self.branch22t(0x0033, a, b, offset)
    }

    fn branch22t(&mut self, opcode: u16, a: u8, b: u8, offset: i16) -> Result<&mut Self> {
        self.nibble2(opcode as u8, a, b)?;
        self.u16le(offset as u16);
        Ok(self)
    }

    // ---------------------------------------------------------- internals

    /// Emit a `12x` instruction: byte lanes are `B|A|op`.
    fn nibble2(&mut self, opcode: u8, a: u8, b: u8) -> Result<&mut Self> {
        if a > 15 || b > 15 {
            return Err(Error::ValueOutOfRange { what: "12x register (must fit 4 bits)", value: a.max(b) as u64 });
        }
        self.u16le((opcode as u16) | ((a as u16) << 8) | ((b as u16) << 12));
        Ok(self)
    }

    /// Emit a `22c` instruction: `B|A|op` then `CCCC`.
    fn nibble2_index(&mut self, opcode: u8, a: u8, b: u8, index: u16) -> Result<&mut Self> {
        self.nibble2(opcode, a, b)?;
        self.u16le(index);
        Ok(self)
    }
}

/// Pack up to four registers into the `C|D|E|F` nibbles of a `35c` last word.
fn pack_nibbles(regs: &[u8]) -> u16 {
    let mut v = 0u16;
    for (i, &r) in regs.iter().enumerate() {
        v |= ((r as u16) & 0x0f) << (i * 4);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::decode_all;

    fn units(a: &Assembler) -> Vec<u16> {
        a.as_bytes().chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    }

    #[test]
    fn nibble_order_is_b_then_a() {
        let mut a = Assembler::new();
        a.move_(0xa, 0xb).unwrap();
        // Byte lanes: byte0 = op, byte1 = (B << 4) | A
        assert_eq!(a.as_bytes(), &[0x01, 0xba]);
    }

    #[test]
    fn const4_packs_the_literal_into_the_high_nibble() {
        let mut a = Assembler::new();
        a.const4(0, 5).unwrap();
        // byte1 = (B << 4) | A = 0x50
        assert_eq!(a.as_bytes(), &[0x12, 0x50]);
    }

    #[test]
    fn lit8_and_23x_match_androguard_bytes() {
        // Both encodings were cross-checked against androguard's raw output for
        // real DEX files; see the note in `decode_22b_byte_lanes`.
        let mut a = Assembler::new();
        a.add_int_lit8(0, 0, -1);
        assert_eq!(a.as_bytes(), &[0xd8, 0x00, 0x00, 0xff]);
        let mut b = Assembler::new();
        b.add_int_lit8(1, 0, 1);
        assert_eq!(b.as_bytes(), &[0xd8, 0x01, 0x00, 0x01]);
        let mut c = Assembler::new();
        c.aget(3, 1, 2);
        assert_eq!(c.as_bytes(), &[0x44, 0x03, 0x01, 0x02]);
    }

    #[test]
    fn const32_is_three_code_units() {
        let mut a = Assembler::new();
        a.const32(2, -1);
        assert_eq!(a.len_units(), 3);
        let ins = decode_all(&units(&a)).unwrap();
        assert_eq!(ins.len(), 1);
    }

    #[test]
    fn invoke_packs_arguments_into_cdef() {
        let mut a = Assembler::new();
        a.invoke(0x6e, &[1, 2], 0x1234).unwrap();
        assert_eq!(a.len_units(), 3);
        let all = decode_all(&units(&a)).unwrap();
        match &all[0].instruction {
            crate::insn::Instruction::F35C { op, a: count, index, regs, .. } => {
                assert_eq!(*op, 0x6e);
                assert_eq!(*count, 2, "A carries the argument count, as d8 emits");
                assert_eq!(*index, 0x1234);
                assert_eq!(&regs[..2], &[1, 2]);
            }
            other => panic!("expected 35c, got {other:?}"),
        }
    }

    #[test]
    fn invoke_with_five_args_uses_the_g_nibble() {
        let mut a = Assembler::new();
        a.invoke(0x71, &[0, 1, 2, 3, 4], 7).unwrap();
        let all = decode_all(&units(&a)).unwrap();
        match &all[0].instruction {
            crate::insn::Instruction::F35C { a: count, g, regs, .. } => {
                assert_eq!(*count, 5);
                assert_eq!(*g, 4, "the fifth argument lives in G");
                assert_eq!(&regs[..4], &[0, 1, 2, 3]);
            }
            other => panic!("expected 35c, got {other:?}"),
        }
    }

    #[test]
    fn invoke_range_encodes_the_count_in_the_high_nibble() {
        let mut a = Assembler::new();
        a.invoke_range(0x74, 4, 3, 9).unwrap();
        assert_eq!(a.as_bytes(), &[0x74, 0x03, 0x09, 0x00, 0x04, 0x00]);
        // And androguard's real bytes for `invoke-virtual/range v25, method@1`.
        let mut b = Assembler::new();
        b.invoke_range(0x74, 25, 1, 1).unwrap();
        assert_eq!(b.as_bytes(), &[0x74, 0x01, 0x01, 0x00, 0x19, 0x00]);
    }

    #[test]
    fn field_accessors_reject_wrong_opcode_ranges() {
        let mut a = Assembler::new();
        // 0x52..=0x58 are iget-*, 0x59..=0x5f iput-*, 0x60..=0x66 sget-*
        // and 0x67..=0x6d sput-*.
        assert!(a.iget(0x51, 0, 0, 0).is_err(), "0x51 is aput-short, not iget");
        assert!(a.iget(0x59, 0, 0, 0).is_err(), "0x59 is iput, not iget");
        assert!(a.iget(0x52, 0, 0, 0).is_ok());
        assert!(a.iget(0x58, 0, 0, 0).is_ok());
        assert!(a.iput(0x5f, 0, 0, 0).is_ok());
        assert!(a.sget(0x60, 0, 0).is_ok());
        assert!(a.sget(0x67, 0, 0).is_err());
        assert!(a.sput(0x6d, 0, 0).is_ok());
        assert!(a.sput(0x60, 0, 0).is_err());
    }

    #[test]
    fn too_many_invoke_registers_is_rejected() {
        let mut a = Assembler::new();
        assert!(a.invoke(0x71, &[0, 1, 2, 3, 4, 5], 0).is_err());
        assert!(a.invoke(0x71, &[], 0).is_err());
        assert!(a.invoke(0x71, &[16], 0).is_err());
        assert!(a.invoke(0x50, &[0], 0).is_err());
    }

    #[test]
    fn every_emitted_instruction_decodes_back() {
        let mut a = Assembler::new();
        a.nop();
        a.const4(0, 1).unwrap();
        a.const16(1, 1000);
        a.const32(2, -70000);
        a.const_string(3, 12);
        a.const_class(4, 13);
        a.new_instance(5, 14);
        a.move_(6, 0).unwrap();
        a.move_from16(7, 1);
        a.invoke(0x6e, &[5, 1, 2], 20).unwrap();
        a.move_result(8);
        a.move_result_object(9);
        a.add_int(9, 8, 1);
        a.return_void();

        let all = decode_all(&units(&a)).unwrap();
        assert_eq!(all.len(), 14, "decoded {all:#?}");
        for l in &all {
            assert!(l.instruction.entry().map(|e| e.valid).unwrap_or(false));
        }
    }

    #[test]
    fn branches_survive_a_round_trip() {
        let mut a = Assembler::new();
        a.const4(0, 0).unwrap();
        a.if_eqz(0, 2);
        a.goto(0);
        a.return_void();
        let all = decode_all(&units(&a)).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[1].instruction.mnemonic(), "if-eqz");
        assert_eq!(all[2].instruction.mnemonic(), "goto");
    }

    #[test]
    fn into_code_produces_a_writable_body() {
        let mut a = Assembler::new();
        a.return_void();
        let body = a.into_code(1, 0, 0);
        assert_eq!(body.registers_size, 1);
        assert_eq!(body.insns, vec![0x0e, 0x00]);
    }
}
