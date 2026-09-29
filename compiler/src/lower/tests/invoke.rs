//! The call family: all fourteen forms, opcodes `0x6e`–`0x72`, `0x74`–`0x78` and
//! `0xfa`–`0xfd`.

use crate::lower::tests::prelude::*;
use crate::lower::tests::{ packed_args, ranged_args};

/// The call every case in this module builds, with the fields a case varies.
fn call(kind: InvokeKind, target: CallTarget, ranged: bool, proto: Option<u32>) -> IrOp {
    let (args, declared) = if ranged {
        (ranged_args(), 3)
    } else {
        (packed_args(), 3)
    };
    IrOp::Invoke { call: Box::new(Call { target, kind, args, ranged, declared, proto }) }
}

lowering_cases! {
    at 0,
    {
        // ---- the five dispatching and direct forms, in both encodings.
        invoke_virtual: 0x6e => call(InvokeKind::Virtual, CallTarget::Method(0x1234), false, None),
            "dispatches on the receiver's runtime class; the target is a `method_ids` index \
             and the dispatch is `codegen`'s to emit";
        invoke_super: 0x6f => call(InvokeKind::Super, CallTarget::Method(0x1234), false, None),
            "the same dispatch starting the search at the receiver's direct superclass, which \
             is the call a `super.` produces and the reason the kind exists";
        invoke_direct: 0x70 => call(InvokeKind::Direct, CallTarget::Method(0x1234), false, None),
            "no dispatch at all: a private call, a same-class call or a constructor, and the \
             only way the compiler is entitled to bind it statically";
        invoke_static: 0x71 => call(InvokeKind::Static, CallTarget::Method(0x1234), false, None),
            "no receiver, so every argument is in the outgoing-argument window; the calling \
             convention in `IR.md` is the authority and this component is not";
        invoke_interface: 0x72 => call(InvokeKind::Interface, CallTarget::Method(0x1234), false, None),
            "dispatch through an interface method table, which the reachability pass (A4) has \
             to close over *every* implementor of, not just the one that happens to be loaded";

        invoke_virtual_range: 0x74 => call(InvokeKind::Virtual, CallTarget::Method(0x1234), true, None),
            "as `invoke-virtual`, with a contiguous argument range whose count is exact";
        invoke_super_range: 0x75 => call(InvokeKind::Super, CallTarget::Method(0x1234), true, None),
            "as `invoke-super`, ranged";
        invoke_direct_range: 0x76 => call(InvokeKind::Direct, CallTarget::Method(0x1234), true, None),
            "as `invoke-direct`, ranged";
        invoke_static_range: 0x77 => call(InvokeKind::Static, CallTarget::Method(0x1234), true, None),
            "as `invoke-static`, ranged";
        invoke_interface_range: 0x78 => call(InvokeKind::Interface, CallTarget::Method(0x1234), true, None),
            "as `invoke-interface`, ranged";

        // ---- the two signature-polymorphic forms. The call site is fully
        // described — a method index, an argument list and a method type — so the
        // IR represents it and leaves the missing `MethodHandle` machinery to the
        // host. The oracle *refuses* to execute these, with the same reasoning.
        invoke_polymorphic: 0xfa => call(InvokeKind::Polymorphic, CallTarget::Method(0x1234), false, Some(0x0056)),
            "the signature comes from a `proto_ids` entry the instruction does not otherwise \
             name, and the only legal receiver is a `MethodHandle` — a class the IR has no \
             way to represent. The instruction is still described exactly, so a host that \
             grows the machinery needs no change here";
        invoke_polymorphic_range: 0xfb => call(InvokeKind::Polymorphic, CallTarget::Method(0x1234), true, Some(0x0056)),
            "as `invoke-polymorphic`, ranged";

        // ---- the two call-site forms. These are the only opcodes whose index is
        // **not** into `method_ids`.
        invoke_custom: 0xfc => call(InvokeKind::Custom, CallTarget::CallSite(0x1234), false, None),
            "the index is into `call_site_ids`, resolved by a bootstrap method the file may \
             not contain. Putting it in `method_ids` would name an unrelated method and \
             produce a call to something plausible, which is why `CallTarget` has two arms";
        invoke_custom_range: 0xfd => call(InvokeKind::Custom, CallTarget::CallSite(0x1234), true, None),
            "as `invoke-custom`, ranged";
    }
}

/// No call has a destination register, and that is the design.
///
/// A call that has a result leaves it in an implicit slot which the following
/// `move-result` reads. Keeping it out of the operand list is what lets
/// `codegen`'s value stack stay one deep, and it is why `MoveResultI32` and its
/// siblings exist as separate instructions.
#[test]
fn a_call_has_no_destination() {
    for op in [0x6eu8, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfa, 0xfb, 0xfc, 0xfd] {
        let inst = crate::lower::tests::lower_sample(op);
        assert!(
            inst.op.writes().is_empty(),
            "0x{op:02x} must not write a register; the result arrives via `move-result`"
        );
        assert_eq!(
            inst.op.reads().len(),
            3,
            "0x{op:02x} should read exactly its three sample arguments"
        );
    }
}

/// The two `invoke-custom` forms are the only ones whose index is a
/// `call_site_ids` entry, and getting that wrong names the wrong method.
#[test]
fn invoke_custom_targets_the_call_site_pool() {
    for op in [0xfcu8, 0xfd] {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert_eq!(call.target, CallTarget::CallSite(0x1234), "0x{op:02x} must not name a method");
        assert!(call.kind.is_indirect());
        assert_eq!(call.proto, None, "a call site carries no trailing method type");
    }
    for op in [0x6eu8, 0x74, 0xfa] {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert!(matches!(call.target, CallTarget::Method(_)));
    }
}

/// Only the two polymorphic forms carry a `proto_ids` index, and they must.
#[test]
fn only_the_polymorphic_calls_carry_a_method_type() {
    for op in [0xfau8, 0xfb] {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert_eq!(call.proto, Some(0x0056), "0x{op:02x} must carry its method type");
    }
    for op in [0x6eu8, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfc, 0xfd] {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert_eq!(call.proto, None, "0x{op:02x} has no trailing method type");
    }
}

/// The five forms that bind statically, and the five that do not.
#[test]
fn the_call_kinds_split_into_dispatching_and_static() {
    let dispatching = [0x6eu8, 0x6f, 0x72, 0x74, 0x75, 0x78];
    for op in dispatching {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert!(call.kind.is_dispatching(), "0x{op:02x} dispatches on the runtime class");
    }
    let static_binding = [0x70u8, 0x71, 0x76, 0x77];
    for op in static_binding {
        let IrOp::Invoke { call } = crate::lower::tests::lower_sample(op).op else {
            panic!("0x{op:02x} is an Invoke")
        };
        assert!(!call.kind.is_dispatching(), "0x{op:02x} binds statically");
    }
    // The reachability pass has to close the dispatching ones over every
    // implementor; the static ones it follows directly.
    assert!(!InvokeKind::Direct.is_indirect());
    assert!(InvokeKind::Custom.is_indirect());
}

/// The packed form's argument count is a hint, and the range form's is exact.
///
/// This is the property the whole `Call` shape exists to record. Reading the
/// packed form's length as authoritative drops a trailing `v0` argument
/// silently, and no later stage can detect it.
#[test]
fn the_packed_argument_count_is_a_hint_and_the_range_one_is_not() {
    let IrOp::Invoke { call } = crate::lower::tests::lower_sample(0x6e).op else {
        panic!("0x6e is an Invoke")
    };
    assert!(!call.ranged);
    assert_eq!(call.declared, 3, "the count field is recorded, not trusted");
    assert_eq!(call.encoded_arity(), 3, "the packed list is trimmed at the last non-zero nibble");

    let IrOp::Invoke { call } = crate::lower::tests::lower_sample(0x74).op else {
        panic!("0x74 is an Invoke")
    };
    assert!(call.ranged);
    assert_eq!(call.args.as_ref(), &[R(4), R(5), R(6)]);
}

/// A range whose end overflows a 16-bit register file is refused.
#[test]
fn an_impossible_register_range_is_refused() {
    let insn = dexcore::insn::Instruction::F3RC {
        op: 0x74,
        a: 3,
        index: 1,
        first_reg: 0xfffe,
        reg_count: 0xffff,
    };
    let mut out = Vec::new();
    let err = crate::lower::tests::lower_one(
        &insn,
        0,
        &crate::lower::tests::unit_ctx(),
        &mut out,
    )
    .expect_err("a range past the end of the register file must be refused");
    assert!(matches!(err, LowerError::BadRegisterRange { .. }), "got {err:?}");
    assert!(out.is_empty());
}
