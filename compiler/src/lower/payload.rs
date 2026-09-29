//! The three data payloads.
//!
//! # A payload is not an instruction
//!
//! The format calls these pseudo-instructions, and a linear sweep decodes them
//! as if they were. They are not: they are data that happens to be addressed
//! like an instruction, and the two ways to reach one are a branch from the
//! switch that reads it and falling into it from above. The first is legal; the
//! second is a malformed file, and the oracle reports it as
//! `Malformed::BadPayload`.
//!
//! The IR keeps the distinction by giving a payload its own [`IrOp::Payload`]
//! rather than letting it share the instruction space, and by requiring
//! `Function::new` to see that nothing but a [`IrOp::Switch`] or an
//! [`IrOp::FillArrayData`] names one.
//!
//! # The switch targets are relative to the *switch*
//!
//! This is the one addressing mode in the format that is not a code-unit offset
//! from the start of the stream: a packed or sparse switch's targets are relative
//! to the switching instruction. The IR stores them exactly as the input has
//! them, and says so on [`Payload::PackedSwitch`], so a `codegen` that relocates
//! the switch has to re-base them and cannot mistake them for labels. That is
//! deliberate: a lowering that pre-computed them would need to know where the
//! switch ends up, which is `codegen`'s decision and not this one's.

use dexcore::insn::{Instruction, Payload as DexPayload};

use crate::ir::{Inst, IrOp, Origin, Payload};

use super::{Ctx, LowerResult};

/// Lower one payload.
pub fn lower(p: &DexPayload, at: u32, _ctx: &Ctx, out: &mut Vec<Inst>) -> LowerResult<()> {
    let origin = Origin::at(at);
    let payload = match p {
        DexPayload::PackedSwitch(s) => Payload::PackedSwitch {
            first_key: s.first_key,
            targets: s.targets.clone().into(),
        },
        DexPayload::SparseSwitch(s) => Payload::SparseSwitch {
            keys: s.keys.clone().into(),
            targets: s.targets.clone().into(),
        },
        DexPayload::FillArrayData(f) => Payload::FillArrayData {
            element_width: f.element_width,
            element_count: f.size,
            data: f.data.clone().into(),
        },
    };
    out.push(Inst::new(IrOp::Payload { payload: Box::new(payload) }, origin));
    Ok(())
}

/// The number of code units a payload occupies, for a report that walks a
/// stream without lowering it.
pub fn units_of(p: &Instruction) -> u32 {
    match p {
        Instruction::Payload(payload) => match payload {
            DexPayload::PackedSwitch(s) => 4 + 2 * s.targets.len() as u32,
            DexPayload::SparseSwitch(s) => 2 + 4 * s.keys.len() as u32,
            DexPayload::FillArrayData(f) => 4 + (f.data.len() as u32).div_ceil(2),
        },
        _ => 0,
    }
}
