//! Branches, jumps, switches, returns, `throw` and the monitors.
//!
//! # Branch offsets
//!
//! Every offset in the input is **relative to the branching instruction** and
//! measured in code units. The IR stores [`Label`]s, which are *absolute* code
//! unit offsets, so this module is where relative becomes absolute — once, in
//! one place, with a checked `i64` addition. An offset that leaves the code item
//! is a malformed file, and reporting it here is the difference between a
//! rejected input and a branch that wraps around into the middle of a method and
//! produces a plausible wrong answer.
//!
//! # The word comparisons
//!
//! `if-eq` and `if-ne` are specified over 32-bit *words*, and a reference is one
//! word, so d8 emits them for both integer comparison and reference identity —
//! `x == null` is `if-nez v0, +2`, and there is no other way to write it. The IR
//! keeps that as [`Word`], and the lowerer emits [`Word::Unresolved`]: the input
//! does not determine which, resolving it needs a verifier this component does
//! not have, and both lower to the same `i32.eq` anyway. The oracle resolves it
//! at run time by asking what the register held, and reports a type error if the
//! comparison turns out to be between two different things.
//!
//! The ordering forms (`lt`, `ge`, `gt`, `le` and their zero forms) are integer
//! only in the input and stay integer only here.

use dexcore::insn::Instruction;

use crate::ir::{
    I32Reg, Inst, IrOp, ObjectReg, Origin, Reg, SwitchKind, WideClass, Word,
};

use super::{unhandled, Ctx, LowerResult};

/// Lower one instruction of the control family.
pub fn lower(op: u8, insn: &Instruction, at: u32, ctx: &Ctx, out: &mut Vec<Inst>) -> LowerResult<()> {
    let origin = Origin::at(at);
    use Instruction as I;
    match insn {
        // ---- `10x` — `return-void`.
        I::F10X { op: 0x0e } => out.push(Inst::new(IrOp::ReturnVoid, origin)),

        // ---- `11x` — the other three returns, `throw`, and the monitors. All
        // four are `11x` and land here together because the *format* does not
        // separate them; the opcode does.
        I::F11X { a, .. } => {
            out.push(Inst::new(match op {
                0x0f => IrOp::ReturnI32 { src: I32Reg::new(u16::from(*a)) },
                0x10 => IrOp::ReturnWide { src: Reg(u16::from(*a)), class: WideClass::Unresolved },
                0x11 => IrOp::ReturnObject { src: ObjectReg::new(u16::from(*a)) },
                0x1d => IrOp::MonitorEnter { object: ObjectReg::new(u16::from(*a)) },
                0x1e => IrOp::MonitorExit { object: ObjectReg::new(u16::from(*a)) },
                0x27 => IrOp::Throw { exception: ObjectReg::new(u16::from(*a)) },
                _ => return Err(unhandled(op, "control", at)),
            }
            , origin));
        }

        // ---- `10t` / `20t` / `30t` — the unconditional jumps, at three widths.
        I::F10T { offset, .. } => out.push(Inst::new(
            IrOp::Jump { target: ctx.target(at, i64::from(*offset))? },
            origin,
        )),
        I::F20T { offset, .. } => out.push(Inst::new(
            IrOp::Jump { target: ctx.target(at, i64::from(*offset))? },
            origin,
        )),
        I::F30T { offset, .. } => out.push(Inst::new(
            IrOp::Jump { target: ctx.target(at, i64::from(*offset))? },
            origin,
        )),

        // ---- `22t` — two-register comparisons.
        I::F22T { a, b, offset, .. } => {
            let to = ctx.target(at, i64::from(*offset))?;
            let (ra, rb) = (u16::from(*a), u16::from(*b));
            out.push(Inst::new(match op {
                0x32 => IrOp::BrEq { a: word(ra), b: word(rb), target: to },
                0x33 => IrOp::BrNe { a: word(ra), b: word(rb), target: to },
                0x34 => IrOp::BrLt { a: I32Reg::new(ra), b: I32Reg::new(rb), target: to },
                0x35 => IrOp::BrGe { a: I32Reg::new(ra), b: I32Reg::new(rb), target: to },
                0x36 => IrOp::BrGt { a: I32Reg::new(ra), b: I32Reg::new(rb), target: to },
                0x37 => IrOp::BrLe { a: I32Reg::new(ra), b: I32Reg::new(rb), target: to },
                _ => return Err(unhandled(op, "control", at)),
            }
            , origin));
        }

        // ---- `21t` — one-register comparisons.
        I::F21T { a, offset, .. } => {
            let to = ctx.target(at, i64::from(*offset))?;
            let reg = I32Reg::new(u16::from(*a));
            out.push(Inst::new(match op {
                0x38 => IrOp::BrEqZ { a: word(reg.index()), target: to },
                0x39 => IrOp::BrNeZ { a: word(reg.index()), target: to },
                0x3a => IrOp::BrLtZ { a: reg, target: to },
                0x3b => IrOp::BrGeZ { a: reg, target: to },
                0x3c => IrOp::BrGtZ { a: reg, target: to },
                0x3d => IrOp::BrLeZ { a: reg, target: to },
                _ => return Err(unhandled(op, "control", at)),
            }
            , origin));
        }

        // ---- `31t` — the two table-driven dispatches.
        I::F31T { a, offset, .. } => {
            let kind = match op {
                0x2b => SwitchKind::Packed,
                0x2c => SwitchKind::Sparse,
                _ => return Err(unhandled(op, "control", at)),
            }
            ;
            out.push(Inst::new(
                IrOp::Switch {
                    kind,
                    reg: I32Reg::new(u16::from(*a)),
                    payload: ctx.target(at, i64::from(*offset))?,
                },
                origin,
            ))
        }

        _ => return Err(unhandled(op, "control", at)),
    }
    
    Ok(())
}

/// A 32-bit word whose class the input does not determine.
///
/// Emitted as [`Word::Unresolved`] rather than as an integer or a reference,
/// because the input does not say and the two lower to the same instruction.
/// See the module documentation.
fn word(reg: u16) -> Word {
    Word::Unresolved(Reg(reg))
}
