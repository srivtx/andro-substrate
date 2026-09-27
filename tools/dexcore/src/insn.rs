//! Decoded Dalvik instructions.
//!
//! [`Instruction`] is an enum over *instruction formats*, not over mnemonics:
//! a single format such as `12x` backs thirty-odd distinct operations (`move`,
//! `array-length`, `neg-int`, `add-int/2addr`, ...), so keying on the mnemonic
//! would produce a 256-variant enum that carries no information. Each variant
//! instead names the operand registers and literals that are actually present,
//! which is what an interpreter or a static analyser needs.
//!
//! Every variant also carries `op`, the raw opcode byte. The format alone does
//! not identify the operation — `35c` covers `invoke-virtual`, `invoke-super`,
//! `invoke-direct`, `invoke-static`, `invoke-interface` *and*
//! `filled-new-array`, and a runtime that cannot tell those apart is useless —
//! so the opcode is stored rather than reconstructed.
//!
//! Field order within each variant follows the on-disk code unit order, so
//! encoding an instruction is a straight concatenation of little-endian halves.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

use crate::opcodes::{opcode, Format, Opcode, PayloadKind};
use serde::Serialize;

/// A decoded instruction, or a data payload pseudo-instruction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Instruction {
    /// `10x` — no operands (`nop`, `return-void`).
    F10X {
        op: u8,
    },
    /// `10t` — signed 8-bit branch offset (`goto`).
    F10T {
        op: u8,
        /// Signed branch offset in code units, relative to this instruction.
        offset: i8,
    },
    /// `11n` — 4-bit destination, 4-bit signed literal (`const/4`).
    F11N {
        op: u8,
        a: u8,
        b: u8,
        /// Sign-extended from 4 bits.
        literal: i8,
    },
    /// `11x` — 8-bit destination (`move-result`, `throw`, `monitor-enter`, ...).
    F11X {
        op: u8,
        a: u8,
    },
    /// `12x` — two 4-bit registers (`move`, `add-int/2addr`, `neg-int`, ...).
    F12X {
        op: u8,
        a: u8,
        b: u8,
    },
    /// `20t` — signed 16-bit branch offset (`goto/16`).
    F20T {
        op: u8,
        offset: i16,
    },
    /// `20bc` — 8-bit destination, 16-bit index (not used by Dalvik proper).
    F20BC {
        op: u8,
        a: u8,
        index: u16,
    },
    /// `21c` — 8-bit destination, 16-bit pool index (`const-string`,
    /// `check-cast`, `sget-*`, `sput-*`, `const-method-handle`, ...).
    F21C {
        op: u8,
        a: u8,
        index: u16,
    },
    /// `21h` — 8-bit destination, 16-bit literal shifted left 16
    /// (`const/high16`, `const-wide/high16`).
    F21H {
        op: u8,
        a: u8,
        /// The stored 16-bit value; the effective literal is this `<< 16`.
        literal: i16,
    },
    /// `21s` — 8-bit destination, signed 16-bit literal (`const/16`).
    F21S {
        op: u8,
        a: u8,
        literal: i16,
    },
    /// `21t` — 8-bit test register, signed 16-bit branch offset (`if-eqz`, ...).
    F21T {
        op: u8,
        a: u8,
        offset: i16,
    },
    /// `22b` — two 8-bit registers and a signed 8-bit literal (`add-int/lit8`).
    F22B {
        op: u8,
        a: u8,
        b: u8,
        literal: i8,
    },
    /// `22x` — 8-bit destination, 16-bit source (`move/from16`).
    F22X {
        op: u8,
        a: u8,
        b: u16,
    },
    /// `22c` — two 4-bit registers and a 16-bit pool index (`new-array`,
    /// `instance-of`, `iget-*`, `iput-*`).
    F22C {
        op: u8,
        a: u8,
        b: u8,
        index: u16,
    },
    /// `22s` — two 4-bit registers and a signed 16-bit literal (`add-int/lit16`).
    F22S {
        op: u8,
        a: u8,
        b: u8,
        literal: i16,
    },
    /// `22t` — two 4-bit test registers and a signed 16-bit branch offset (`if-eq`).
    F22T {
        op: u8,
        a: u8,
        b: u8,
        offset: i16,
    },
    /// `22cs` — variant of `22c` seen in foreign DEX files.
    F22CS {
        op: u8,
        a: u8,
        b: u8,
        index: u16,
    },
    /// `23x` — three 8-bit registers (`add-int`, `aget`, `aput`).
    F23X {
        op: u8,
        a: u8,
        b: u8,
        c: u8,
    },
    /// `30t` — signed 32-bit branch offset (`goto/32`).
    F30T {
        op: u8,
        offset: i32,
    },
    /// `31c` — 8-bit destination, 32-bit pool index (`const-string/jumbo`).
    F31C {
        op: u8,
        a: u8,
        index: u32,
    },
    /// `31i` — 8-bit destination, 32-bit literal (`const`).
    F31I {
        op: u8,
        a: u8,
        literal: i32,
    },
    /// `31t` — 8-bit register, signed 32-bit branch offset
    /// (`fill-array-data`, `packed-switch`, `sparse-switch`).
    F31T {
        op: u8,
        a: u8,
        offset: i32,
    },
    /// `32x` — two 16-bit registers (`move/16`).
    F32X {
        op: u8,
        a: u16,
        b: u16,
    },
    /// `35c` — up to five 4-bit argument registers, plus a 16-bit method index
    /// (`invoke-virtual`, `invoke-static`, `filled-new-array`, `invoke-custom`).
    F35C {
        op: u8,
        /// Destination register, or the argument count for `filled-new-array`.
        a: u8,
        /// Extra argument register when there are more than five.
        g: u8,
        index: u16,
        /// Argument registers, already expanded from the packed `C|D|E|F` nibbles
        /// and zero-padded to five.
        regs: [u8; 5],
    },
    /// `35ms` — contiguous-register variant of `35c` seen in foreign DEX files.
    F35MS {
        op: u8,
        a: u8,
        g: u8,
        index: u16,
        first_reg: u16,
        reg_count: u16,
    },
    /// `35mi` — short-index variant of `35c`.
    F35MI {
        op: u8,
        a: u8,
        g: u8,
        index: u16,
        regs: [u8; 5],
    },
    /// `3rc` — contiguous register range and a 16-bit method index
    /// (`invoke-virtual/range`, `invoke-custom/range`).
    F3RC {
        op: u8,
        a: u8,
        index: u16,
        first_reg: u16,
        reg_count: u16,
    },
    /// `3rms` — move-range variant of `3rc`.
    F3RMS {
        op: u8,
        a: u8,
        index: u16,
        first_reg: u16,
        reg_count: u16,
    },
    /// `3rmi` — short-index variant of `3rc`.
    F3RMI {
        op: u8,
        a: u8,
        index: u16,
        first_reg: u16,
        reg_count: u16,
    },
    /// `45cc` — `35c` plus a trailing `proto_ids` index (`invoke-polymorphic`).
    F45CC {
        op: u8,
        a: u8,
        g: u8,
        index: u16,
        regs: [u8; 5],
        /// Index into `proto_ids`, the trailing method type.
        proto: u16,
    },
    /// `4rcc` — `3rc` plus a trailing `proto_ids` index
    /// (`invoke-polymorphic/range`).
    F4RCC {
        op: u8,
        a: u8,
        index: u16,
        first_reg: u16,
        reg_count: u16,
        /// Index into `proto_ids`.
        proto: u16,
    },
    /// `51l` — 8-bit destination, 64-bit literal (`const-wide`).
    F51L {
        op: u8,
        a: u8,
        literal: i64,
    },
    /// `52c` — variant seen in foreign DEX files; not Dalvik.
    F52C {
        op: u8,
        a: u16,
        b: u16,
        index: u32,
    },
    /// `5rc` — variant seen in foreign DEX files; not Dalvik.
    F5RC {
        op: u8,
        index: u32,
        first_reg: u16,
        reg_count: u16,
    },
    /// An opcode the specification marks `(unused)`.
    ///
    /// Still reports a width, so that a linear walk over corrupt data advances
    /// instead of spinning.
    Unused {
        op: u8,
    },
    /// A data payload pseudo-instruction.
    Payload(Payload),
}

/// The body of a data payload pseudo-instruction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Payload {
    /// `packed-switch-payload`.
    PackedSwitch(PackedSwitch),
    /// `sparse-switch-payload`.
    SparseSwitch(SparseSwitch),
    /// `fill-array-data-payload`.
    FillArrayData(FillArrayData),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PackedSwitch {
    /// `ident`, always `0x0100`.
    pub ident: u16,
    /// The value corresponding to the first target.
    pub first_key: i32,
    /// Branch targets in code units, relative to the `packed-switch` that
    /// references this payload.
    pub targets: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SparseSwitch {
    /// `ident`, always `0x0200`.
    pub ident: u16,
    pub keys: Vec<i32>,
    pub targets: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FillArrayData {
    /// `ident`, always `0x0300`.
    pub ident: u16,
    /// Bytes per element. Dalvik emits 1, 2 or 4 for the primitive widths it
    /// generates, and 8 for `long`/`double` payloads.
    pub element_width: u16,
    /// Number of elements.
    pub size: u32,
    /// Raw element bytes, `element_width * size` long.
    pub data: Vec<u8>,
}

/// Extract the `op` field from any non-payload variant.
macro_rules! op_field {
    ($self:expr) => {
        match $self {
            Instruction::F10X { op }
            | Instruction::F10T { op, .. }
            | Instruction::F11N { op, .. }
            | Instruction::F11X { op, .. }
            | Instruction::F12X { op, .. }
            | Instruction::F20T { op, .. }
            | Instruction::F20BC { op, .. }
            | Instruction::F21C { op, .. }
            | Instruction::F21H { op, .. }
            | Instruction::F21S { op, .. }
            | Instruction::F21T { op, .. }
            | Instruction::F22B { op, .. }
            | Instruction::F22X { op, .. }
            | Instruction::F22C { op, .. }
            | Instruction::F22S { op, .. }
            | Instruction::F22T { op, .. }
            | Instruction::F22CS { op, .. }
            | Instruction::F23X { op, .. }
            | Instruction::F30T { op, .. }
            | Instruction::F31C { op, .. }
            | Instruction::F31I { op, .. }
            | Instruction::F31T { op, .. }
            | Instruction::F32X { op, .. }
            | Instruction::F35C { op, .. }
            | Instruction::F35MS { op, .. }
            | Instruction::F35MI { op, .. }
            | Instruction::F3RC { op, .. }
            | Instruction::F3RMS { op, .. }
            | Instruction::F3RMI { op, .. }
            | Instruction::F45CC { op, .. }
            | Instruction::F4RCC { op, .. }
            | Instruction::F51L { op, .. }
            | Instruction::F52C { op, .. }
            | Instruction::F5RC { op, .. }
            | Instruction::Unused { op } => Some(*op),
            Instruction::Payload(_) => None,
        }
    };
}

impl Instruction {
    /// Raw opcode byte, or `None` for payloads, which are identified by the
    /// full 16-bit ident unit rather than the low byte.
    pub fn opcode(&self) -> Option<u8> {
        op_field!(self)
    }

    /// The table row for this instruction, or `None` for payloads.
    pub fn entry(&self) -> Option<&'static Opcode> {
        self.opcode().filter(|&op| op != 0 || matches!(self, Instruction::F10X { .. } | Instruction::Unused { .. })).map(opcode)
    }

    /// Specification mnemonic, or `"<payload>"` for payloads.
    pub fn mnemonic(&self) -> &'static str {
        match (self.opcode(), self) {
            (_, Instruction::Payload(_)) => "<payload>",
            (Some(0x00), Instruction::F20BC { .. } | Instruction::F22CS { .. }) => "foreign",
            (Some(0x00), _) => "foreign",
            (Some(op), _) => opcode(op).mnemonic,
            (None, _) => "foreign",
        }
    }

    /// Operand format. Payloads and foreign formats report `None`.
    pub fn format(&self) -> Option<Format> {
        match self {
            Instruction::Payload(_) | Instruction::Unused { .. } => None,
            other => other.entry().map(|e| e.format),
        }
    }

    /// Width in bytes.
    pub fn width(&self) -> u16 {
        match self {
            Instruction::Payload(p) => p.width(),
            Instruction::Unused { op } => crate::opcodes::width_of(*op),
            other => other.format().map(|f| f.width()).unwrap_or(2),
        }
    }

    /// True for any of the ten `invoke-*` opcodes, which is the set a runtime
    /// most needs to intercept.
    pub fn is_invoke(&self) -> bool {
        matches!(
            self.opcode(),
            Some(0x6e | 0x6f | 0x70 | 0x71 | 0x72 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78 | 0xfa | 0xfb | 0xfc | 0xfd)
        )
    }

    /// The pool index operand for reference-carrying instructions.
    pub fn index_operand(&self) -> Option<u32> {
        use Instruction::*;
        match self {
            F20BC { index, .. } | F21C { index, .. } | F22C { index, .. } | F22CS { index, .. } => {
                Some(*index as u32)
            }
            F31C { index, .. } | F52C { index, .. } | F5RC { index, .. } => Some(*index),
            F35C { index, .. } | F35MS { index, .. } | F35MI { index, .. } | F3RC { index, .. }
            | F3RMS { index, .. } | F3RMI { index, .. } | F45CC { index, .. } | F4RCC { index, .. } => {
                Some(*index as u32)
            }
            _ => None,
        }
    }

    /// The packed argument registers of a `35c`-family instruction,
    /// `[C, D, E, F, G]`, zero-padded to five.
    ///
    /// Zero is a legal register, so this cannot be used to infer arity. Use
    /// [`Instruction::argument_registers`] for the exact list.
    pub fn packed_registers(&self) -> [u8; 5] {
        use Instruction::*;
        match self {
            F35C { regs, .. } | F35MI { regs, .. } | F45CC { regs, .. } => *regs,
            _ => [0; 5],
        }
    }

    /// The `A` nibble of a `35c` instruction.
    ///
    /// d8 — and therefore every APK in the wild — writes the *argument count*
    /// here rather than a destination register, with the result delivered to
    /// the following `move-result`. The specification describes the field as
    /// the destination register; the two readings agree whenever the call has
    /// no result, and only the destination reading is meaningful for a call
    /// that has one, so treat this as a hint rather than as ground truth.
    pub fn argument_count_hint(&self) -> Option<u8> {
        match self {
            Instruction::F35C { a, .. } | Instruction::F35MI { a, .. } | Instruction::F45CC { a, .. } => {
                Some(*a)
            }
            _ => None,
        }
    }

    /// The argument registers of an `invoke`, in argument order.
    ///
    /// The range forms carry their own count, so they are exact. The packed
    /// `35c` forms do not: the trailing zero nibbles are padding *unless* the
    /// last argument really is `v0`, so the list is trimmed at the last
    /// non-zero nibble. That is correct for every well-formed `35c` produced by
    /// a compiler except one whose final argument is `v0`; callers that know
    /// the arity from the target method's prototype should use
    /// [`Instruction::packed_registers`] and slice it themselves.
    pub fn argument_registers(&self) -> Vec<u8> {
        use Instruction::*;
        match self {
            F35C { regs, .. } | F35MI { regs, .. } | F45CC { regs, .. } => {
                let last = regs.iter().rposition(|&r| r != 0).map(|i| i + 1).unwrap_or(0);
                regs[..last].to_vec()
            }
            F3RC { first_reg, reg_count, .. }
            | F3RMS { first_reg, reg_count, .. }
            | F3RMI { first_reg, reg_count, .. }
            | F4RCC { first_reg, reg_count, .. }
            | F35MS { first_reg, reg_count, .. } => (*first_reg..first_reg + reg_count)
                .map(|r| r as u8)
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl Payload {
    /// Which kind of payload this is.
    pub fn kind(&self) -> PayloadKind {
        match self {
            Payload::PackedSwitch(_) => PayloadKind::PackedSwitch,
            Payload::SparseSwitch(_) => PayloadKind::SparseSwitch,
            Payload::FillArrayData(_) => PayloadKind::FillArrayData,
        }
    }

    /// Total width in bytes: ident, body, and padding up to a code unit.
    ///
    /// * `packed-switch-payload`: `ident(2) size(2) first_key(4) targets(4n)`
    ///   = `8 + 4n` bytes, so `4 + 2n` code units.
    /// * `sparse-switch-payload`: `ident(2) size(2) keys(4n) targets(4n)`
    ///   = `4 + 8n` bytes, so `2 + 4n` code units.
    /// * `fill-array-data-payload`: `ident(2) element_width(2) size(4) data`
    ///   = `8 + data` bytes, so `4 + ceil(data/2)` code units.
    ///
    /// The two switch counts previously treated each 32-bit array element as
    /// if it were 16 bits, so both were short by a factor of two and
    /// disagreed with the very 32-bit words the decoder reads for them. The
    /// symptom is silent: a linear sweep still tiles, because the unconsumed
    /// remainder simply decodes as further instructions, so the fixture
    /// tiling test passed. What breaks is branch-target fixup.
    pub fn width(&self) -> u16 {
        let units: u32 = match self {
            Payload::PackedSwitch(p) => 4 + 2 * p.targets.len() as u32,
            Payload::SparseSwitch(s) => 2 + 4 * s.keys.len() as u32,
            Payload::FillArrayData(f) => 4 + (f.data.len() as u32).div_ceil(2),
        };
        (units * 2) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_widths_match_the_spec() {
        let p = Payload::PackedSwitch(PackedSwitch { ident: 0x0100, first_key: 0, targets: vec![0; 3] });
        assert_eq!(p.width(), 20);

        let s = Payload::SparseSwitch(SparseSwitch {
            ident: 0x0200,
            keys: vec![0; 4],
            targets: vec![0; 4],
        });
        assert_eq!(s.width(), 36);

        // An odd number of payload bytes still occupies a whole code unit.
        let f = Payload::FillArrayData(FillArrayData {
            ident: 0x0300,
            element_width: 1,
            size: 3,
            data: vec![0; 3],
        });
        assert_eq!(f.width(), 6 * 2);
    }

    #[test]
    fn mnemonics_and_widths_come_from_the_table() {
        let i = Instruction::F11X { op: 0x0a, a: 3 };
        assert_eq!(i.mnemonic(), "move-result");
        assert_eq!(i.width(), 2);

        let i = Instruction::F51L { op: 0x18, a: 0, literal: -1 };
        assert_eq!(i.mnemonic(), "const-wide");
        assert_eq!(i.width(), 10);

        let i = Instruction::Unused { op: 0x73 };
        assert_eq!(i.width(), 2);
        assert_eq!(i.format(), None);
    }

    #[test]
    fn same_format_different_opcode_keeps_its_identity() {
        // This is the whole reason `op` is stored rather than reconstructed.
        let v = Instruction::F35C { op: 0x6e, a: 1, g: 0, index: 1, regs: [1, 0, 0, 0, 0] };
        let s = Instruction::F35C { op: 0x71, a: 1, g: 0, index: 1, regs: [1, 0, 0, 0, 0] };
        assert_eq!(v.mnemonic(), "invoke-virtual");
        assert_eq!(s.mnemonic(), "invoke-static");
        assert_ne!(v, s);
        assert!(v.is_invoke() && s.is_invoke());
        assert_eq!(v.index_operand(), Some(1));
        assert_eq!(v.argument_registers(), vec![1]);
        assert_eq!(v.argument_count_hint(), Some(1));
    }

    #[test]
    fn range_invokes_expand_their_registers() {
        let i = Instruction::F3RC { op: 0x74, a: 3, index: 7, first_reg: 4, reg_count: 3 };
        assert_eq!(i.argument_registers(), vec![4, 5, 6]);
        assert_eq!(i.mnemonic(), "invoke-virtual/range");
    }
}
