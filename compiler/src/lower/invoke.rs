//! The fourteen call forms.
//!
//! # There is no destination
//!
//! A call that has a result does not write it to a register named by the
//! instruction. The result lands in an implicit slot, and the *following*
//! instruction — a `move-result` — reads it. Every compiler writes it that way,
//! which is why [`IrOp::Invoke`] has no destination and [`IrOp::MoveResultI32`]
//! and its siblings exist at all.
//!
//! Keeping the result in a second channel rather than in an operand is what
//! keeps `codegen`'s value stack to one: the call leaves its result in a local,
//! and `move-result` copies it to where the program wants it. It also means the
//! IR does not have to resolve the callee's prototype to lower a call — which
//! matters, because the target is a `method_ids` index and the prototype is the
//! next pool entry.
//!
//! # The arity is not in the instruction
//!
//! The packed five-argument form stores its arguments in nibbles zero-padded to
//! five. Zero is a legal register, so a trailing `v0` argument and two padding
//! zeros are the *same three nibbles*. The encoding alone therefore cannot say
//! how many arguments there are.
//!
//! So [`Call`] records three things and trusts none of them blindly: the
//! register list as the encoding gives it, whether it came from a range (in
//! which case the count is exact) or from packed nibbles (in which case it is
//! padded), and the instruction's own count field. **The arity that matters is
//! the target method's own prototype**, which lives in `method_ids`. Slicing
//! `args` to that arity is A2's and A6's job, and it is the same job the oracle
//! does at run time — which is why the lowerer records what it saw and guesses
//! nothing. Getting this wrong is a silent miscompile rather than an error, so
//! it is called out in `IR.md` § 5 of A1's report as a contract gap.
//!
//! # `invoke-custom` targets a different pool
//!
//! The two signature-polymorphic forms and the two `invoke-custom` forms do not
//! name a `method_ids` entry. `invoke-custom` names a `call_site_ids` entry,
//! resolved by a bootstrap method the file may not even contain, so
//! [`CallTarget`] has two arms rather than one index. The IR describes the call
//! site exactly; what the host does with it is A5's, and the divergence
//! taxonomy's `SUB.FW.INVOKEDYNAMIC` entry is where the absence gets counted.

use dexcore::insn::Instruction;

use crate::ir::{Call, CallTarget, Inst, IrOp, InvokeKind, Origin, Reg};

use super::{unhandled, Ctx, LowerError, LowerResult};

/// Lower one instruction of the invoke family.
pub fn lower(
    op: u8,
    insn: &Instruction,
    at: u32,
    _ctx: &Ctx,
    out: &mut Vec<Inst>,
) -> LowerResult<()> {
    let origin = Origin::at(at);
    use Instruction as I;
    let call = match insn {
        // ---- `35c` — up to five arguments in packed nibbles, plus a `45cc`
        // form that appends a method type.
        I::F35C { a, index, regs, .. } => {
            packed(op, at, *a, u32::from(*index), regs, None)?
        }
        I::F45CC { a, index, regs, proto, .. } => {
            packed(op, at, *a, u32::from(*index), regs, Some(u32::from(*proto)))?
        }

        // ---- `3rc` — a contiguous argument range, plus a `4rcc` form.
        I::F3RC { a, index, first_reg, reg_count, .. } => {
            ranged(op, at, *a, u32::from(*index), *first_reg, *reg_count, None)?
        }
        I::F4RCC { a, index, first_reg, reg_count, proto, .. } => {
            ranged(
                op,
                at,
                *a,
                u32::from(*index),
                *first_reg,
                *reg_count,
                Some(u32::from(*proto)),
            )?
        }

        _ => return Err(unhandled(op, "invoke", at)),
    }
    ;
    out.push(Inst::new(IrOp::Invoke { call: Box::new(call) }, origin));
    Ok(())
}

/// The packed-nibble argument forms.
fn packed(
    op: u8,
    at: u32,
    declared: u8,
    index: u32,
    regs: &[u8; 5],
    proto: Option<u32>,
) -> LowerResult<Call> {
    let kind = kind_of(op).ok_or(LowerError::Unhandled { op, family: "invoke", at })?;
    // Trim the padding. The trailing nibbles are zero unless the final argument
    // really is `v0`, which is why the trimmed list is a *hint* and the
    // prototype is the truth; see the module documentation.
    let last = regs.iter().rposition(|r| *r != 0).map_or(0, |i| i + 1);
    Ok(Call {
        target: target_of(kind, index),
        kind,
        args: regs[..last].iter().map(|r| Reg(u16::from(*r))).collect::<Vec<_>>().into(),
        ranged: false,
        declared,
        proto,
    })
}

/// The contiguous-range argument forms, whose count is exact.
fn ranged(
    op: u8,
    at: u32,
    declared: u8,
    index: u32,
    first: u16,
    count: u16,
    proto: Option<u32>,
) -> LowerResult<Call> {
    let kind = kind_of(op).ok_or(LowerError::Unhandled { op, family: "invoke", at })?;
    let end = u32::from(first) + u32::from(count);
    if end > u32::from(u16::MAX) + 1 {
        return Err(LowerError::BadRegisterRange {
            at,
            first: u32::from(first),
            count: u32::from(count),
        });
    }
    Ok(Call {
        target: target_of(kind, index),
        kind,
        args: (u32::from(first)..end).map(|r| Reg(r as u16)).collect::<Vec<_>>().into(),
        ranged: true,
        declared,
        proto,
    })
}

/// Which call form an opcode names.
fn kind_of(op: u8) -> Option<InvokeKind> {
    Some(match op {
        0x6e | 0x74 => InvokeKind::Virtual,
        0x6f | 0x75 => InvokeKind::Super,
        0x70 | 0x76 => InvokeKind::Direct,
        0x71 | 0x77 => InvokeKind::Static,
        0x72 | 0x78 => InvokeKind::Interface,
        0xfa | 0xfb => InvokeKind::Polymorphic,
        0xfc | 0xfd => InvokeKind::Custom,
        _ => return None,
    })
}

/// Which pool the call form's index operand refers to.
///
/// `invoke-custom` is the odd one out: its index is into `call_site_ids`, and
/// putting it in `method_ids` would point at an unrelated method and produce a
/// call to something plausible.
fn target_of(kind: InvokeKind, index: u32) -> CallTarget {
    match kind {
        InvokeKind::Custom => CallTarget::CallSite(index),
        _ => CallTarget::Method(index),
    }
}
