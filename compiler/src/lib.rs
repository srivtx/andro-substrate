//! # andro-substrate compiler
//!
//! The DEX to WebAssembly compiler described by [`IR.md`](../IR.md). This crate
//! is its **front end** and nothing else: it reads a decoded `dexcore` method
//! and produces a lowered, machine-independent intermediate representation that
//! `codegen` can turn into `wasm32-unknown-unknown` without re-deriving
//! anything.
//!
//! ## Module map
//!
//! | module | role | owner |
//! |---|---|---|
//! | [`ir`] | the IR: types, [`IrOp`](ir::IrOp), [`Function`](ir::Function) | A1 |
//! | [`lower`] | `dexcore::Instruction` -> IR, one module per opcode family | A1 |
//! | `codegen` | IR -> Wasm text/binary | A2 |
//! | `pools`, `heap` | the pool images and the guest heap layout | A3 |
//! | `reach` | the call-graph closure | A4 |
//! | `hostgen` | generated host stubs | A5 |
//! | `abi`, `marshal` | the calling convention and marshalling | A6 |
//!
//! Only the first two exist yet. They are declared here so that the crate
//! compiles; the rest are added by their owners.
//!
//! ## The division of labour that matters
//!
//! [`ir`] contains **no Dalvik**. There is no opcode byte, no instruction
//! format, no `try_item` field layout and no `access_flags` *meaning* in it —
//! only the flags themselves, because a flag is a value and A2 has to test it.
//! Everything that knows what a Dalvik opcode means lives in [`lower`], in the
//! `DexOpcode -> IrOp` table and the family modules behind it. That is what
//! makes the IR replaceable: a different source language would replace `lower/`
//! and leave [`ir`] alone.
//!
//! ## The type discipline
//!
//! `i32`, `i64`, `f32`, `f64` and a heap handle are five different things, and
//! the IR says so in its types rather than in a comment:
//!
//! * every narrow operand is a *distinct* register newtype ([`I32Reg`],
//!   [`I64Reg`], [`F32Reg`], [`F64Reg`], [`ObjectReg`]), so `AddI64` cannot be
//!   handed an [`I32Reg`] — that is a `rustc` error, not a runtime surprise;
//! * [`Handle`] is a newtype over `u32` with **no** `From<u32>`, **no**
//!   `Into<u32>`, no `Deref` and no arithmetic, so a handle cannot quietly
//!   become an index and a number cannot quietly become a handle;
//! * where Dalvik itself does not determine a type — `aget-wide` does not say
//!   whether the element is a `long` or a `double`, and `if-eq` does not say
//!   whether it compares integers or references — the IR records that
//!   ambiguity explicitly as [`WideClass::Unresolved`] or [`Word`] rather than
//!   guessing. Those are the two places a type error is genuinely *in the
//!   input*, and the IR is where it has to live.
//!
//! ## Example
//!
//! ```
//! use andro_compiler::ir::{ClassCtx, Frame, Function, IrOp, Inst, Origin, Ty};
//! use dexcore::model::access;
//!
//! let ctx = ClassCtx::new(
//!     "Lcom/example/App;",
//!     0,
//!     0,
//!     "add",
//!     "(II)I",
//!     access::ACC_PUBLIC | access::ACC_STATIC,
//! );
//! let body = vec![Inst::new(IrOp::Nop, Origin::at(0))];
//! let f = Function::new(ctx, Frame::new(4, 2, 0, 1), body, Vec::new())
//!     .expect("a well-formed function");
//! assert_eq!(f.result, Ty::I32);
//! assert_eq!(f.params.len(), 2);
//! assert_eq!(f.locals.len(), 2);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod heap;
pub mod ir;
pub mod lower;
pub mod pools;
pub mod reach;

pub use ir::{ClassCtx, Function, FunctionError, IrOp, Inst, Ty};
pub use lower::{lower_code, lower_method, LowerError, Lowered};
