//! Register-to-register moves, call results, and the exception register.
//!
//! # The `32x` normalisation
//!
//! Three opcodes — the three `16`-register move forms — are encoded in **two**
//! code units as `AA|op BBBB`, and the destination is the *high byte* of the
//! first unit. `dexcore` reports that first unit whole, as `a: u16`, so a
//! consumer that reads `a` as a register number reads `0x0303` where the
//! instruction meant register 3.
//!
//! The shift is applied here rather than in `dexcore` for two reasons. First,
//! the oracle applies it too, at `dexinterp::exec`, and the study's numbers are
//! taken against the oracle *as it stands*: patching a shared file mid-study
//! would change the instrument the measurements were taken with. Second, it is
//! not obvious that the fix belongs upstream — a `u16` field that holds a code
//! unit rather than a register is arguably a different type, and
//! `Instruction::F32X { a: u16 }` already says so. Either way it is reported,
//! not worked around silently, and `lower::tests::structural` runs it over
//! every move instruction in every method of six real F-Droid files, so a
//! regression here is a test failure rather than a mystery.

use dexcore::insn::Instruction;

use crate::ir::{
    I32Reg, Inst, IrOp, ObjectReg, Origin, Reg, WideClass,
};

use super::{unhandled, Ctx, LowerResult};

/// The destination register of a `32x` instruction.
///
/// `dexcore` hands back the whole first code unit, whose high byte is the
/// register. The mask is applied twice — a shift and a truncation to a byte —
/// because the low byte is the *opcode*, and a consumer that forgot the mask
/// would address register 255 rather than register 3.
pub fn wide_dst_register(a: u16) -> u16 {
    (a >> 8) & 0xff
}

/// Lower one instruction of the move family.
pub fn lower(
    op: u8,
    insn: &Instruction,
    at: u32,
    _ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let origin = Origin::at(at);
    use Instruction as I;
    match insn {
        // ---- `10x` — `nop`.
        I::F10X { op: 0x00 } => out.push(Inst::nop(origin)),

        // ---- `12x` — the short moves.
        I::F12X { a, b, .. } => {
            let (dst, src) = (I32Reg::new(u16::from(*a)), I32Reg::new(u16::from(*b)));
            match op {
                0x01 => out.push(Inst::new(IrOp::MoveI32 { dst, src }, origin)),
                0x04 => out.push(Inst::new(
                    IrOp::MoveWide { dst: dst.reg(), src: src.reg(), class: WideClass::Unresolved },
                    origin,
                )),
                0x07 => {
                    let (d, s) = (ObjectReg::new(u16::from(*a)), ObjectReg::new(u16::from(*b)));
                    out.push(Inst::new(IrOp::MoveObject { dst: d, src: s }, origin))
                }
                _ => return Err(unhandled(op, "move", at)),
            }
            
        }

        // ---- `22x` — the medium moves.
        I::F22X { a, b, .. } => {
            let b = *b;
            match op {
                0x02 => out.push(Inst::new(
                    IrOp::MoveI32 { dst: I32Reg::new(u16::from(*a)), src: I32Reg::new(b) },
                    origin,
                )),
                0x05 => out.push(Inst::new(
                    IrOp::MoveWide {
                        dst: Reg(u16::from(*a)),
                        src: Reg(b),
                        class: WideClass::Unresolved,
                    },
                    origin,
                )),
                0x08 => out.push(Inst::new(
                    IrOp::MoveObject {
                        dst: ObjectReg::new(u16::from(*a)),
                        src: ObjectReg::new(b),
                    },
                    origin,
                )),
                _ => return Err(unhandled(op, "move", at)),
            }
            
        }

        // ---- `32x` — the long moves, and the register extraction described at
        // the top of this file.
        I::F32X { a, b, .. } => {
            let a = wide_dst_register(*a);
            match op {
                0x03 => out.push(Inst::new(
                    IrOp::MoveI32 { dst: I32Reg::new(a), src: I32Reg::new(*b) },
                    origin,
                )),
                0x06 => out.push(Inst::new(
                    IrOp::MoveWide {
                        dst: Reg(a),
                        src: Reg(*b),
                        class: WideClass::Unresolved,
                    },
                    origin,
                )),
                0x09 => out.push(Inst::new(
                    IrOp::MoveObject {
                        dst: ObjectReg::new(a),
                        src: ObjectReg::new(*b),
                    },
                    origin,
                )),
                _ => return Err(unhandled(op, "move", at)),
            }
            
        }

        // ---- `11x` — the call results and the exception register.
        I::F11X { a, .. } => match op {
            0x0a => out.push(Inst::new(IrOp::MoveResultI32 { dst: I32Reg::new(u16::from(*a)) }, origin)),
            0x0b => out.push(Inst::new(
                IrOp::MoveResultWide { dst: Reg(u16::from(*a)), class: WideClass::Unresolved },
                origin,
            )),
            0x0c => out.push(Inst::new(IrOp::MoveResultObject { dst: ObjectReg::new(u16::from(*a)) }, origin)),
            0x0d => {
                out.push(Inst::new(IrOp::MoveException { dst: ObjectReg::new(u16::from(*a)) }, origin))
            }
            _ => return Err(unhandled(op, "move", at)),
        }
        ,

        _ => return Err(unhandled(op, "move", at)),
    }
    
    Ok(())
}
