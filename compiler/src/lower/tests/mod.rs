//! The lowering's verification suite.
//!
//! # What is verified, and what is not
//!
//! `dexinterp` is the oracle ([`IR.md`](../../../IR.md) § Verification), and the
//! end-to-end equality test — same inputs, same results, same exception kinds,
//! through the interpreter and through a compiled module — belongs to A2, who
//! owns code generation. This layer has no code to run, so what it can check is
//! everything *upstream* of running, and it checks all of it:
//!
//! | file | what it proves |
//! |---|---|
//! | [`moves`], [`consts`], [`arith`], [`memory`], [`invoke`], [`control`], [`types`], [`arrays`] | one `#[test]` per opcode, asserting the exact [`IrOp`] it produces and the reason it is that one |
//! | [`payloads`] | the three data payloads, including their code-unit widths |
//! | [`reserved`] | all 32 unassigned slots and all 8 reachable foreign encodings become a *typed* refusal, and never nothing |
//! | [`coverage`] | the totals: 256 opcode bytes accounted for, 224 defined opcodes pinned, 0 unhandled, 2 refusals and why |
//! | [`structural`] | on six real F-Droid `classes.dex` files: the body is in source order, every instruction is covered, and the operands on an [`IrOp`] are the operands of the instruction it came from |
//! | [`encodings`] | the samples above are what `dexcore`'s decoder really produces, checked by assembling with `dexcore`'s own encoder and decoding back |
//! | [`differential`] | the arithmetic's *operand selection* — which operation, which class, which order — against the oracle's own primitive table |
//!
//! # The one thing that is deliberately not claimed
//!
//! No test here executes the IR. A test that evaluated the IR against the oracle
//! would be a second implementation of the IR's semantics, and a disagreement
//! between two implementations written from the same reading is evidence about
//! the *reading*, not about the compiler. So [`differential`] compares
//! **operand selection** — that opcode `0x98` selects [`IrOp::ShlI32`] and not
//! [`IrOp::ShrI32`], that the destination is the left operand, that the class is
//! `I32` — and leaves execution to A2. That is a weaker claim than a
//! differential test and it is stated as one.

// The crate forbids `unwrap` and `expect` because a value that came out of a file
// must never be able to kill the process. Every value unwrapped below was built by
// the test itself, and a test that cannot reach its own fixture should fail
// loudly rather than contort itself around a type it has already proven.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::ir::{Label, Origin};
use dexcore::insn::Instruction;
use dexcore::opcodes::Format;

/// The five typed register constructors and the class-free one, as functions.
///
/// A case file writes `I(1)` rather than `I32Reg::new(1)`, so a row of the
/// opcode table reads as a list of registers rather than as a list of constructor
/// calls. Functions rather than type aliases because a type alias is not
/// callable, and the whole point is that these read as registers.
pub const fn I(n: u16) -> crate::ir::I32Reg {
    crate::ir::I32Reg::new(n)
}
/// A `J` register.
pub const fn L(n: u16) -> crate::ir::I64Reg {
    crate::ir::I64Reg::new(n)
}
/// An `F` register.
pub const fn F(n: u16) -> crate::ir::F32Reg {
    crate::ir::F32Reg::new(n)
}
/// A `D` register.
pub const fn D(n: u16) -> crate::ir::F64Reg {
    crate::ir::F64Reg::new(n)
}
/// A reference register.
pub const fn O(n: u16) -> crate::ir::ObjectReg {
    crate::ir::ObjectReg::new(n)
}
/// A class-free register, for the two places the input does not determine a class.
pub const fn R(n: u16) -> crate::ir::Reg {
    crate::ir::Reg(n)
}
use crate::lower::{lower_one, Ctx, LowerError};

/// The code-unit length every sample method pretends to have.
///
/// Large enough that every branch offset the samples use resolves, small enough
/// that an out-of-range one is still caught.
pub const UNITS: u32 = 64;

/// A `ClassCtx` for the sample methods. Only the signature and static-ness
/// matter to the per-opcode tests, which never build a `Function`.
pub fn sample_ctx() -> crate::ir::ClassCtx {
    crate::ir::ClassCtx::new(
        "Lcom/example/Sample;",
        0,
        7,
        "sample",
        "()V",
        dexcore::model::access::ACC_PUBLIC | dexcore::model::access::ACC_STATIC,
    )
}

/// The pool index every sample instruction carries. Distinct from every
/// register number the samples use, so a test that mistook one for the other
/// fails.
pub const INDEX: u16 = 0x1234;
/// The 32-bit pool index, for the one instruction that has one.
pub const WIDE_INDEX: u32 = 0x1234_5678;
/// The 64-bit literal every 64-bit constant sample carries.
pub const WIDE_LITERAL: i64 = 0x0123_4567_89ab_cdef;
/// The `proto_ids` index the signature-polymorphic samples carry.
pub const PROTO: u16 = 0x0056;
/// The branch offset every control sample carries, and therefore the label it
/// resolves to from an instruction at unit 0.
pub const BRANCH: i8 = 1;

/// A representative decoded instruction for an opcode byte.
///
/// Keyed on the opcode's *format*, which is what `Instruction` is keyed on, and
/// given **distinctive operands**: destination 1, first source 2, second source
/// 3, range 4..7, and a pool index that is not a register number. A test that
/// transposed two operands, dropped one, or mistook the index for a register
/// therefore fails on the value rather than on the shape.
///
/// The two format-specific hazards are built in deliberately:
///
/// * a `32x` sample carries `(3 << 8) | op` in its `a` field, which is what
///   `dexcore` really hands back, so a lowering that forgot the shift would
///   address register `0x0303` and fail;
/// * the branch samples carry a *relative* offset of 1 from an instruction at
///   unit 0, so a lowering that forgot to resolve it would produce a label of
///   1 — which is also the right answer, deliberately not: the harness
///   re-bases the instruction to unit 10 in [`assert_lowers_at`], where the
///   correct answer is 11 and the un-resolved one is 1.
pub fn sample(op: u8) -> Option<Instruction> {
    let entry = dexcore::opcodes::opcode(op);
    if !entry.valid {
        return Some(Instruction::Unused { op });
    }
    Some(match entry.format {
        Format::F10X => Instruction::F10X { op },
        Format::F10T => Instruction::F10T { op, offset: BRANCH },
        // `11n` is one code unit, `op A|B`, and the literal *is* the high nibble: the
        // decoder sign-extends `B` into `literal`, so `b` and `literal` cannot be chosen
        // independently and the sample sets both.
        Format::F11N => Instruction::F11N { op, a: 1, b: 3, literal: 3 },
        Format::F11X => Instruction::F11X { op, a: 1 },
        Format::F12X => Instruction::F12X { op, a: 1, b: 2 },
        Format::F20T => Instruction::F20T { op, offset: i16::from(BRANCH) },
        Format::F21C => Instruction::F21C { op, a: 1, index: INDEX },
        Format::F21H => Instruction::F21H { op, a: 1, literal: i16::from_le_bytes(INDEX.to_le_bytes()) },
        Format::F21S => Instruction::F21S { op, a: 1, literal: i16::from_le_bytes(INDEX.to_le_bytes()) },
        Format::F21T => Instruction::F21T { op, a: 1, offset: i16::from(BRANCH) },
        Format::F22B => Instruction::F22B { op, a: 1, b: 2, literal: 5 },
        Format::F22X => Instruction::F22X { op, a: 1, b: 2 },
        Format::F22C => Instruction::F22C { op, a: 1, b: 2, index: INDEX },
        Format::F22S => Instruction::F22S { op, a: 1, b: 2, literal: i16::from_le_bytes(INDEX.to_le_bytes()) },
        Format::F22T => Instruction::F22T { op, a: 1, b: 2, offset: i16::from(BRANCH) },
        Format::F23X => Instruction::F23X { op, a: 1, b: 2, c: 3 },
        Format::F30T => Instruction::F30T { op, offset: i32::from(BRANCH) },
        Format::F31C => Instruction::F31C { op, a: 1, index: WIDE_INDEX },
        Format::F31I => Instruction::F31I { op, a: 1, literal: WIDE_INDEX as i32 },
        Format::F31T => Instruction::F31T { op, a: 1, offset: i32::from(BRANCH) },
        Format::F32X => Instruction::F32X { op, a: (3 << 8) | u16::from(op), b: 2 },
        Format::F35C => Instruction::F35C { op, a: 3, g: 0, index: INDEX, regs: [1, 2, 3, 0, 0] },
        Format::F3RC => Instruction::F3RC { op, a: 3, index: INDEX, first_reg: 4, reg_count: 3 },
        Format::F45CC => {
            Instruction::F45CC { op, a: 3, g: 0, index: INDEX, regs: [1, 2, 3, 0, 0], proto: PROTO }
        }
        Format::F4RCC => {
            Instruction::F4RCC { op, a: 3, index: INDEX, first_reg: 4, reg_count: 3, proto: PROTO }
        }
        Format::F51L => Instruction::F51L { op, a: 1, literal: WIDE_LITERAL },
        // The eight foreign encodings a decoder can actually produce. The two
        // formats with no `Instruction` variant — `40sc` and `41c` — are absent
        // because `decode_one` has no arm for them, and
        // `coverage::the_foreign_encodings_are_eight_of_nine` says so out loud.
        Format::F20BC => Instruction::F20BC { op, a: 1, index: INDEX },
        Format::F22CS => Instruction::F22CS { op, a: 1, b: 2, index: INDEX },
        Format::F35MS => {
            Instruction::F35MS { op, a: 3, g: 0, index: INDEX, first_reg: 4, reg_count: 3 }
        }
        Format::F35MI => {
            Instruction::F35MI { op, a: 3, g: 0, index: INDEX, regs: [1, 2, 3, 0, 0] }
        }
        Format::F3RMS => {
            Instruction::F3RMS { op, a: 3, index: INDEX, first_reg: 4, reg_count: 3 }
        }
        Format::F3RMI => {
            Instruction::F3RMI { op, a: 3, index: INDEX, first_reg: 4, reg_count: 3 }
        }
        Format::F52C => Instruction::F52C { op, a: 1, b: 2, index: WIDE_INDEX },
        Format::F5RC => Instruction::F5RC { op, index: WIDE_INDEX, first_reg: 4, reg_count: 3 },
        // `F00X` belongs to the unassigned slots, which the `!entry.valid` arm
        // above already handled. `F40SC` and `F41C` are the two formats the wider
        // ecosystem uses and the specification does not, and `decode_one` has no
        // `Instruction` variant for either — so a sample cannot be built for
        // them and `reserved` says so out loud.
        Format::F00X => Instruction::F10X { op },
        Format::F40SC | Format::F41C => return None,
    })
}

/// The label a branch of offset [`BRANCH`] from code unit 10 resolves to.
///
/// Deliberately not 1: a lowering that forgot to resolve a relative offset would
/// produce 1 here and be caught.
pub const RESOLVED: Label = Label(10 + BRANCH as u32);

/// Assert that opcode `op` lowers, at code unit 0, to exactly `expected`.
///
/// Every per-opcode test in this suite goes through here, so the four things
/// checked are the same for all 224: the lowering succeeded, it produced
/// **exactly one** instruction, the operation is the one named, and the origin is
/// the one the source instruction was at.
pub fn assert_lowers(op: u8, expected: crate::ir::IrOp, why: &'static str) {
    assert_lowers_at(op, 0, expected, why)
}

/// [`assert_lowers`], with the instruction placed at a code-unit offset that is
/// not zero, so a lowering that ignored `at` in resolving a branch offset fails.
pub fn assert_lowers_at(op: u8, at: u32, expected: crate::ir::IrOp, why: &'static str) {
    let insn = sample(op)
        .unwrap_or_else(|| panic!("0x{op:02x} has no decoded form, so it cannot be lowered"));
    let mut out = Vec::new();
    let res = lower_one(&insn, at, &Ctx::new(UNITS), &mut out);
    match res {
        Ok(()) => {}
        Err(e) => panic!(
            "0x{op:02x} ({}) did not lower: {e}\n  expected: {why}",
            dexcore::opcodes::mnemonic(op)
        ),
    }
    let expected_origin = Origin::at(at);
    assert_eq!(
        out.len(),
        1,
        "0x{op:02x} ({}) produced {} instructions; every opcode produces exactly one\n  \
         {why}\n  produced: {out:#?}",
        dexcore::opcodes::mnemonic(op),
        out.len()
    );
    assert_eq!(
        out[0].op, expected,
        "0x{op:02x} ({}) lowered to the wrong operation\n  {why}",
        dexcore::opcodes::mnemonic(op)
    );
    assert_eq!(
        out[0].origin, expected_origin,
        "0x{op:02x} ({}) lost its origin",
        dexcore::opcodes::mnemonic(op)
    );
}

/// Assert that opcode `op` lowers to exactly one [`IrOp::Unsupported`] with the
/// given reason.
pub fn assert_refused(
    op: u8,
    reason: crate::ir::UnsupportedReason,
    why: &'static str,
) {
    assert_lowers(op, crate::ir::IrOp::Unsupported { reason }, why)
}

/// Generate one `#[test]` per opcode, plus the list of opcode bytes the module
/// pins, each run with the instruction placed at a named code-unit offset.
///
/// The offset is a parameter rather than a constant because it is the difference
/// between a branch-offset test and a no-op. At unit 0 a relative offset of 1
/// resolves to 1, which is also what an *unresolved* offset would be; at any
/// other unit the two differ, so the whole module — not just one test — has a
/// resolved offset in every one of its cases.
///
/// The list is what makes "every opcode has a test" a *checkable* claim rather
/// than a hope: [`coverage`] gathers every module's list and compares it with
/// `dexcore`'s own table, so an opcode that is defined, lowerable, and missing a
/// test fails the build by name.
#[macro_export]
macro_rules! lowering_cases {
    (at $at:expr, { $( $test:ident : $op:literal => $expected:expr , $why:literal ; )* }) => {
        $(
            #[doc = $why]
            #[test]
            fn $test() {
                $crate::lower::tests::assert_lowers_at($op, $at, $expected, $why);
            }
        )*

        /// The opcode bytes this module pins, for the coverage arithmetic.
        pub const OPS: &[u8] = &[$($op),*];
    };
}

/// Lower an instruction and return the single instruction it produced, for a
/// test that wants to inspect it rather than compare it.
pub fn lower_sample(op: u8) -> crate::ir::Inst {
    let insn = sample(op).expect("every sample opcode decodes");
    let mut out = Vec::new();
    lower_one(&insn, 0, &Ctx::new(UNITS), &mut out).expect("the sample lowers");
    assert_eq!(out.len(), 1, "the sample produced one instruction");
    out.into_iter().next().expect("one instruction")
}

/// Lower an instruction, expecting failure, and return the error.
pub fn lower_sample_err(op: u8, at: u32) -> LowerError {
    let insn = sample(op).expect("every sample opcode decodes");
    let mut out = Vec::new();
    lower_one(&insn, at, &Ctx::new(UNITS), &mut out).expect_err("this opcode must not lower")
}

pub mod arith;
pub mod arrays;
pub mod consts;
pub mod control;
pub mod coverage;
pub mod differential;
pub mod encodings;
pub mod invoke;
pub mod memory;
pub mod moves;
pub mod payloads;
pub mod reserved;
pub mod structural;
pub mod types;

/// Re-exported so every case file can spell its operands without a `use` per
/// file.

pub mod prelude {
    pub use super::{D, F, I, L, O, R, INDEX, PROTO, RESOLVED, WIDE_INDEX};
    pub use crate::ir::Reg;
    pub use crate::ir::{
        Call, CallTarget, FieldRef, InvokeKind, IrOp, Label, Narrow, Payload, SwitchKind,
        UnsupportedReason, WideClass, Word, WordClass,
    };
    pub use crate::lower::LowerError;
    pub use dexcore::insn::Instruction;
    pub use std::boxed::Box;
    pub use std::vec;
    pub use std::vec::Vec;
}

/// A `field_ids` reference carrying the sample pool index.
pub fn field() -> crate::ir::FieldRef {
    crate::ir::FieldRef { index: u32::from(INDEX) }
}

/// The sample argument list for a packed call form: registers 1, 2 and 3, with
/// the trailing two nibbles trimmed as padding.
pub fn packed_args() -> std::boxed::Box<[crate::ir::Reg]> {
    vec![R(1), R(2), R(3)].into()
}

/// The sample argument list for a range call form: registers 4, 5 and 6.
pub fn ranged_args() -> std::boxed::Box<[crate::ir::Reg]> {
    vec![R(4), R(5), R(6)].into()
}

/// The [`Ctx`] the tests lower into: a code item of [`UNITS`] code units.
pub fn unit_ctx() -> Ctx {
    Ctx::new(UNITS)
}

/// Whether an opcode byte is one of the fourteen branch or jump forms.
///
/// Not a re-derivation of the classifier: it is the list of opcodes whose
/// instruction carries a relative offset, written out, so a test that walks the
/// whole table can pick them out without a second copy of the family map.
pub fn is_branch(op: u8) -> bool {
    matches!(
        op,
        0x28 | 0x29 | 0x2a | 0x2b | 0x2c | 0x32..=0x3d | 0x26
    )
}
