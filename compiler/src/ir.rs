//! The intermediate representation: a lowered, machine-independent, typed form
//! of a DEX method.
//!
//! # What this file is, and what it deliberately is not
//!
//! This is the **index**. It knows nothing about Dalvik: there is no opcode
//! byte, no instruction format, no `code_item` field layout, no branch-offset
//! unit and no `(unused)` slot anywhere below. Every one of those lives in
//! [`crate::lower`], which is the single place in the compiler that knows what a
//! Dalvik opcode means. A second source language would replace `lower/` and
//! leave this file untouched.
//!
//! # Lowered, not decoded
//!
//! The IR is not a transliteration of the input. Three normalisations happen
//! during lowering, and each of them exists because WebAssembly has no
//! corresponding form:
//!
//! 1. **Every arithmetic instruction is three-address.** The two-address and
//!    immediate forms of the input become `dst, a, b` with all three
//!    explicit. WebAssembly has no two-address instruction and no immediate on
//!    `i32.shl`, so keeping the distinction would push a re-derivation onto
//!    `codegen`. The literal forms emit a separate [`IrOp::ConstI32`], so a
//!    literal is a value in a register, exactly as it is in the input.
//! 2. **Branch and payload targets are indices, not byte offsets** — see
//!    [`Label`].
//! 3. **Wide values are 64-bit slots, not register pairs.** A `long` or a
//!    `double` occupies one [`I64Reg`]/[`F64Reg`]-shaped slot. The input's
//!    "high word is poison" convention is an artifact of a 32-bit register file
//!    and has no meaning here.
//!
//! # The type discipline
//!
//! The five machine types are five different things, and the IR says so in its
//! types rather than in a comment:
//!
//! * each narrow operand is a **distinct register newtype** — [`I32Reg`],
//!   [`I64Reg`], [`F32Reg`], [`F64Reg`], [`ObjectReg`]. `IrOp::AddI64` cannot be
//!   handed an [`I32Reg`]; that is a `rustc` error, not a runtime surprise.
//! * [`Handle`] is a newtype over `u32` with no `From<u32>`, no `Into<u32>`, no
//!   `Deref` and no arithmetic, so a handle cannot quietly become an index and a
//!   number cannot quietly become a handle.
//! * where the input genuinely does not determine a type, the IR records the
//!   ambiguity instead of resolving it: [`WideClass::Unresolved`] for the
//!   64-bit family and [`Word`] for the integer-or-reference comparisons. These
//!   are the only two places a type error can legitimately be present, because
//!   they are the only two places it is present **in the input**.
//!
//! What the type system cannot express — a register's type at an arbitrary point
//! in a straight-line block, which needs a verifier — is checked by
//! [`Function::new`], which is the only way to build a [`Function`]. A
//! malformed function is a typed [`FunctionError`], never a `codegen` surprise.
//!
//! # The calling convention
//!
//! As fixed by [`IR.md`](../IR.md): `Z B S C I` are `i32`, `J` is `i64`, `F` is
//! `f32`, `D` is `f64`, an object, array or `null` is an `i32` handle, and `void`
//! is no result. [`Ty`] is that table, and [`Ty::of_descriptor`] is its
//! parser.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

use std::fmt;

// ====================================================================== types

/// The IR type of a value: the calling convention of [`IR.md`](../IR.md), one
/// variant per WebAssembly value type plus `Void`.
///
/// `Z`, `B`, `S`, `C` and `I` are all [`Ty::I32`]. The *narrowing* of an
/// `I32` to a `B` is an instruction ([`IrOp::I32ToByte`]) and never a type,
/// because a Dalvik register is a 32-bit word and the store truncates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ty {
    /// `Z B S C I`, and the wide integer family.
    I32,
    /// `J`.
    I64,
    /// `F`.
    F32,
    /// `D`.
    F64,
    /// An object, an array, or `null` — an `i32` handle.
    Object,
    /// `V`. Only ever a function's result type; never an operand.
    Void,
}

impl Ty {
    /// The 32-bit types: everything a `Word32` slot might hold.
    pub const WORD32: [Ty; 2] = [Ty::I32, Ty::F32];
    /// The 64-bit types: everything a [`WideClass`] might name.
    pub const WIDE: [Ty; 2] = [Ty::I64, Ty::F64];

    /// The type a type descriptor denotes.
    ///
    /// Total by construction, and deliberately so: a descriptor that is not a
    /// type at all becomes [`Ty::Object`], which keeps it nameable and
    /// reportable instead of failing in the middle of a method. This mirrors
    /// `dexinterp::JType::parse`, so the two never disagree about a corrupt
    /// file.
    pub fn of_descriptor(descriptor: &str) -> Ty {
        let bytes = descriptor.as_bytes();
        match bytes.first() {
            Some(b'V') => Ty::Void,
            Some(b'Z' | b'B' | b'S' | b'C' | b'I') => Ty::I32,
            Some(b'J') => Ty::I64,
            Some(b'F') => Ty::F32,
            Some(b'D') => Ty::F64,
            // `L...;`, `[...`, and anything else. A garbage descriptor is a
            // reference for the same reason a garbage one is in the oracle: the
            // failure is reportable, and a reference at least keeps the name.
            _ => Ty::Object,
        }
    }

    /// The width of a value of this type in the input's 32-bit register file:
    /// 2 for `J` and `D`, 0 for `V`, 1 otherwise.
    ///
    /// This is how the *incoming-argument window* is measured, and the receiver
    /// counts as one word of it.
    ///
    /// The IR does **not** use this for layout — a [`I64Reg`] is one slot here
    /// regardless — but `codegen` and `marshal` need it to place an incoming
    /// argument window, and so does the frame reconstruction in
    /// [`Frame`]'s documentation.
    pub const fn slots(self) -> u16 {
        match self {
            Ty::Void => 0,
            Ty::I64 | Ty::F64 => 2,
            _ => 1,
        }
    }

    /// True for anything that can hold an object handle.
    pub const fn is_reference(self) -> bool {
        matches!(self, Ty::Object)
    }

    /// The name used in diagnostics and in the emitted `.wat` comments.
    pub const fn as_str(self) -> &'static str {
        match self {
            Ty::I32 => "i32",
            Ty::I64 => "i64",
            Ty::F32 => "f32",
            Ty::F64 => "f64",
            Ty::Object => "handle",
            Ty::Void => "void",
        }
    }
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A heap handle: a byte offset into the guest heap, per the handle model of
/// [`IR.md`](../IR.md).
///
/// # The discipline
///
/// There is deliberately no `impl From<u32> for Handle`, no `impl From<Handle>
/// for u32`, no `Deref`, and no arithmetic operators. A handle is not an
/// integer: it is an address into a heap the host owns, and the whole point of
/// the distinction is that `codegen` must not be able to do arithmetic on one by
/// accident. The two directions are named [`Handle::new`] and
/// [`Handle::offset`] so that each is a visible decision rather than a coercion.
///
/// `Handle::NULL` is offset 0, which the handle model reserves for `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(u32);

impl Handle {
    /// The `null` handle. The handle model reserves offset 0 for it.
    pub const NULL: Handle = Handle(0);

    /// Wrap a byte offset. The one explicit way a `u32` becomes a handle.
    pub const fn new(offset: u32) -> Handle {
        Handle(offset)
    }

    /// The byte offset. The one explicit way a handle becomes a `u32`.
    ///
    /// Named rather than implicit because this is the operation a bug performs
    /// by accident: it is address arithmetic dressed as a cast.
    pub const fn offset(self) -> u32 {
        self.0
    }

    /// True for the `null` handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            f.write_str("null")
        } else {
            write!(f, "h{}", self.0)
        }
    }
}

/// The 64-bit class of a value: `long` or `double`.
///
/// Several input operations move a 64-bit value without saying which of the two
/// it is — `move-wide`, `const-wide`, `aget-wide`, `iget-wide`, `return-wide` …
/// The specification leaves that to the verifier, and failing that to the array
/// or field the value lives in. The IR does **not** re-derive it: it records
/// [`WideClass::Unresolved`], and `codegen` emits the class-agnostic 64-bit move
/// that both the hardware and WebAssembly do. A class *is* filled in when the
/// pool entry that determines it is in hand, and the field is then `Long` or
/// `Double`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WideClass {
    /// `J`.
    Long,
    /// `D`.
    Double,
    /// The input does not determine the class.
    Unresolved,
}

impl WideClass {
    /// The type this class names, or `None` when it is unresolved.
    pub const fn ty(self) -> Option<Ty> {
        match self {
            WideClass::Long => Some(Ty::I64),
            WideClass::Double => Some(Ty::F64),
            WideClass::Unresolved => None,
        }
    }
}

/// The 32-bit class of a value: `int` or `float`.
///
/// The same problem as [`WideClass`], one width down. `aget` and `aput` are
/// specified over "one 32-bit element", which is an `int` in an `int[]` and a
/// `float` in a `float[]`, and `iget`/`iput` on a `float` field say the same
/// thing. The *instruction* does not; the array or field does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WordClass {
    /// `I`.
    Int,
    /// `F`.
    Float,
    /// The input does not determine the class.
    Unresolved,
}

impl WordClass {
    /// The type this class names, or `None` when it is unresolved.
    pub const fn ty(self) -> Option<Ty> {
        match self {
            WordClass::Int => Some(Ty::I32),
            WordClass::Float => Some(Ty::F32),
            WordClass::Unresolved => None,
        }
    }
}

/// How a sub-word element or field is widened into, or narrowed out of, a
/// 32-bit register.
///
/// This is the whole content of the `aget-boolean` … `aget-short` and
/// `iget-boolean` … `iget-short` families, and getting the sign wrong turns
/// every `byte` in a real APK into a plausible wrong answer.
///
/// # The two directions are not inverses
///
/// [`Narrow::widen`] and [`Narrow::truncate`] are separate functions because
/// they are not inverses of one another, and the asymmetry is the
/// specification's rather than a detail this IR invented:
///
/// * a `boolean` **element is 0 or 1**, so a load is `raw != 0` — a stored
///   `0xFF` reads back as 1 and not 255 — while a store is `v & 1`;
/// * a `char` is zero-extended on a load and truncated to 16 bits on a store,
///   which *are* inverses, unlike the boolean;
/// * a `byte` and a `short` sign-extend on a load, which is again the inverse of
///   the store.
///
/// So `AgetNarrow` and `AputNarrow` share this enum and nothing else, and
/// `codegen` calls [`Narrow::widen`] on the load side and [`Narrow::truncate`]
/// on the store side. Both are checked against the oracle's `narrow_on_load` and
/// `narrow_on_store` in `lower::tests::differential`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Narrow {
    /// A full 32-bit `int`. No extension and no truncation.
    Int,
    /// A `boolean`: one byte holding 0 or 1.
    Boolean,
    /// One byte, **zero**-extended.
    Byte,
    /// One byte, **sign**-extended. `byte`.
    SByte,
    /// Two bytes, **zero**-extended. `char` on the way out: `0xFFFF` is 65535,
    /// not -1.
    Char,
    /// Two bytes, **sign**-extended. `short`.
    Short,
}

impl Narrow {
    /// Every variant, for a test that checks both directions of all of them.
    pub const ALL: [Narrow; 6] = [
        Narrow::Int,
        Narrow::Boolean,
        Narrow::Byte,
        Narrow::SByte,
        Narrow::Char,
        Narrow::Short,
    ];

    /// The number of bytes the element or field occupies in the heap.
    pub const fn byte_width(self) -> u8 {
        match self {
            Narrow::Int => 4,
            Narrow::Boolean | Narrow::Byte | Narrow::SByte => 1,
            Narrow::Char | Narrow::Short => 2,
        }
    }

    /// Widen a raw little-endian element read at [`Narrow::byte_width`] bytes.
    ///
    /// The load direction. A `boolean` is read as *non-zero*, not as a
    /// zero-extended byte — see the type's documentation for why the two
    /// differ.
    pub fn widen(self, raw: u32) -> i32 {
        match self {
            Narrow::Int => raw as i32,
            Narrow::Boolean => i32::from(raw & 0xff != 0),
            Narrow::Byte => i32::from(raw as u8),
            Narrow::SByte => i32::from(raw as u8 as i8),
            Narrow::Char => i32::from(raw as u16),
            Narrow::Short => i32::from(raw as u16 as i16),
        }
    }

    /// Narrow a 32-bit value to this element's stored representation.
    ///
    /// The store direction. A `boolean` is reduced to its low bit.
    pub fn truncate(self, value: i32) -> i32 {
        match self {
            Narrow::Int => value,
            Narrow::Boolean => i32::from(value & 1 != 0),
            Narrow::Byte => i32::from(value as u8),
            Narrow::SByte => i32::from(value as i8),
            Narrow::Char => i32::from(value as u16),
            Narrow::Short => i32::from(value as i16),
        }
    }
}

/// A 32-bit word that may hold an integer or a reference.
///
/// `if-eq`, `if-ne`, `if-eqz` and `if-nez` are specified over 32-bit *words*, and
/// a reference is one word, so `x == null` is written `if-nez v0, +2` and every
/// object identity test in a real APK is an integer comparison written with a
/// reference in it. WebAssembly represents both as `i32`, so `codegen` emits one
/// `i32.eq` either way; the distinction is kept because it is the distinction
/// the **oracle** makes, and dropping it here would drop it everywhere
/// downstream. [`Word::Unresolved`] is what the lowerer emits, because the
/// input does not determine it without a verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Word {
    /// Read as an `i32`.
    Int(I32Reg),
    /// Read as a handle.
    Object(ObjectReg),
    /// The input does not determine which.
    Unresolved(Reg),
}

impl Word {
    /// The register, whatever its class.
    pub const fn reg(self) -> Reg {
        match self {
            Word::Int(r) => r.reg(),
            Word::Object(r) => r.reg(),
            Word::Unresolved(r) => r,
        }
    }

    /// The type, when it is known.
    pub const fn ty(self) -> Option<Ty> {
        match self {
            Word::Int(_) => Some(Ty::I32),
            Word::Object(_) => Some(Ty::Object),
            Word::Unresolved(_) => None,
        }
    }
}

// ================================================================== registers

/// A register number. The plain, class-free form, used only where the input
/// genuinely does not determine a class (see [`WideClass`] and [`Word`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Reg(pub u16);

impl Reg {
    /// The register number.
    pub const fn index(self) -> u16 {
        self.0
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Marker types for [`TypedReg`]. Not a public API: the public API is the five
/// register aliases.
pub mod marker {
    /// Marker for [`super::I32Reg`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct I32;
    /// Marker for [`super::I64Reg`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct I64;
    /// Marker for [`super::F32Reg`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct F32;
    /// Marker for [`super::F64Reg`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct F64;
    /// Marker for [`super::ObjectReg`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Object;
}

/// A register of a known class.
///
/// The class is a type parameter rather than a field, which is the whole
/// mechanism: `I32Reg` and `I64Reg` are different types, so no instruction can
/// be handed the wrong one, and the compiler — not a validator, not a test —
/// is what catches it.
///
/// `C` is carried by `PhantomData<fn() -> C>` so that `TypedReg<C>` is `Copy`
/// and `Send` regardless of `C` and does not constrain its variance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypedReg<C> {
    index: u16,
    _class: std::marker::PhantomData<fn() -> C>,
}

impl<C> TypedReg<C> {
    /// The register number.
    pub const fn index(self) -> u16 {
        self.index
    }

    /// Widen to the class-free form. The one direction that is always safe: it
    /// forgets the class rather than changing it.
    pub const fn reg(self) -> Reg {
        Reg(self.index)
    }
}

/// Generate one typed register newtype and its conversions.
macro_rules! typed_reg {
    ($name:ident, $marker:ident, $variant:ident) => {
        impl $name {
            /// A register of this class at register number `index`.
            pub const fn new(index: u16) -> $name {
                $name { index, _class: std::marker::PhantomData }
            }

            /// The [`Ty`] this register class holds.
            pub const fn ty(self) -> Ty {
                Ty::$variant
            }
        }

        impl From<Reg> for $name {
            fn from(r: Reg) -> $name {
                $name::new(r.0)
            }
        }

        impl From<$name> for Reg {
            fn from(r: $name) -> Reg {
                r.reg()
            }
        }
    };
}

/// A 32-bit integer register: `Z`, `B`, `S`, `C` and `I`.
pub type I32Reg = TypedReg<marker::I32>;
/// A 64-bit integer register: `J`.
pub type I64Reg = TypedReg<marker::I64>;
/// A `float` register: `F`.
pub type F32Reg = TypedReg<marker::F32>;
/// A `double` register: `D`.
pub type F64Reg = TypedReg<marker::F64>;
/// A reference register: an object, an array, or `null`.
pub type ObjectReg = TypedReg<marker::Object>;

typed_reg!(I32Reg, I32, I32);
typed_reg!(I64Reg, I64, I64);
typed_reg!(F32Reg, F32, F32);
typed_reg!(F64Reg, F64, F64);
typed_reg!(ObjectReg, Object, Object);

/// A register paired with its class, for the places where registers are
/// heterogeneous: a function's incoming-argument window.
///
/// This is the *only* type in the IR that mixes classes, and it is a container
/// rather than an operand, so nothing in an [`IrOp`] can be built from it
/// without a class already being chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypedRegAny {
    /// An `i32` register.
    Int(I32Reg),
    /// An `i64` register.
    Long(I64Reg),
    /// An `f32` register.
    Float(F32Reg),
    /// An `f64` register.
    Double(F64Reg),
    /// A reference register.
    Object(ObjectReg),
}

impl TypedRegAny {
    /// A register of class `ty` at `reg`, defaulting every register number to
    /// zero, which the validation of [`Function`] then checks.
    pub const fn new(ty: Ty, reg: Reg) -> Option<TypedRegAny> {
        match ty {
            Ty::I32 => Some(TypedRegAny::Int(I32Reg::new(reg.0))),
            Ty::I64 => Some(TypedRegAny::Long(I64Reg::new(reg.0))),
            Ty::F32 => Some(TypedRegAny::Float(F32Reg::new(reg.0))),
            Ty::F64 => Some(TypedRegAny::Double(F64Reg::new(reg.0))),
            Ty::Object => Some(TypedRegAny::Object(ObjectReg::new(reg.0))),
            // `void` is a result type, never an operand; `Function::new` turns
            // this into a `FunctionError` rather than letting it reach an
            // instruction.
            Ty::Void => None,
        }
    }

    /// The class.
    pub const fn ty(self) -> Ty {
        match self {
            TypedRegAny::Int(_) => Ty::I32,
            TypedRegAny::Long(_) => Ty::I64,
            TypedRegAny::Float(_) => Ty::F32,
            TypedRegAny::Double(_) => Ty::F64,
            TypedRegAny::Object(_) => Ty::Object,
        }
    }

    /// The class-free register.
    pub const fn reg(self) -> Reg {
        match self {
            TypedRegAny::Int(r) => r.reg(),
            TypedRegAny::Long(r) => r.reg(),
            TypedRegAny::Float(r) => r.reg(),
            TypedRegAny::Double(r) => r.reg(),
            TypedRegAny::Object(r) => r.reg(),
        }
    }
}

// ==================================================================== operands

/// A branch or payload target: an index into the source code item's code units.
///
/// The IR keeps the input's addressing rather than inventing one. A
/// [`Function`]'s body is in the same order as the source instruction stream,
/// so the *instruction* index of a target is a lookup and the *code-unit* offset
/// is what `codegen` needs for a debug map and what the branch-offset fixups in
/// a switch payload are expressed in. Inventing a basic-block numbering here
/// would be a control-flow graph, and a CFG is a derived product that
/// `codegen` and the reachability pass want to build differently.
///
/// A label may name a payload, which is how a `packed-switch` reaches its
/// table. `codegen` must place every [`IrOp::Payload`] in the module's data
/// section and never fall into one; [`Function::new`] rejects a label that
/// names a payload from anywhere other than a switch or a `fill-array-data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Label(pub u32);

impl Label {
    /// The code-unit offset this label names.
    pub const fn offset(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// A `field_ids` index and the shape the accessing instruction gives it.
///
/// `index` is the *only* thing in the IR that indexes a pool, and it is `u32`
/// because the pools are. Resolving it to a class, a name and a type is
/// `pools`' job (A3), and the class-resolution order of [`IR.md`](../IR.md)
/// applies there; the IR never resolves anything, because resolving it here
/// would mean `lower/` needed the whole file and would make a pool edit a
/// recompile of every method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldRef {
    /// Index into `field_ids`.
    pub index: u32,
}

/// A `type_ids` index, for the operations that name a type.
pub type TypeRef = u32;

/// A `string_ids` index, for the operations that name a string.
pub type StringRef = u32;

/// A `proto_ids` index, carried by the signature-polymorphic calls.
pub type ProtoRef = u32;

/// Which of the five call forms an [`IrOp::Invoke`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvokeKind {
    /// Dispatch on the runtime class of the receiver.
    Virtual,
    /// Dispatch starting the search at the receiver's direct superclass.
    Super,
    /// A private, a constructor or a same-class call: no dispatch.
    Direct,
    /// No receiver; an argument to the outgoing-argument window.
    Static,
    /// Dispatch on the runtime class, through an interface method table.
    Interface,
    /// A signature-polymorphic call, whose signature comes from a `proto_ids`
    /// entry the instruction does not otherwise name. Only legal on
    /// `java.lang.invoke.MethodHandle` members, which is why it cannot be
    /// lowered to a call: there is no receiver of a known type to dispatch on.
    Polymorphic,
    /// A call through a `call_site_ids` entry, resolved by a bootstrap method
    /// the input does not contain. The target is therefore *not* in
    /// `method_ids` at all, which is why [`CallTarget`] has two arms.
    Custom,
}

impl InvokeKind {
    /// True for the forms that dispatch on a receiver's runtime class.
    pub const fn is_dispatching(self) -> bool {
        matches!(self, InvokeKind::Virtual | InvokeKind::Super | InvokeKind::Interface)
    }

    /// True for the forms whose target is a `call_site_ids` entry rather than a
    /// `method_ids` one.
    pub const fn is_indirect(self) -> bool {
        matches!(self, InvokeKind::Custom | InvokeKind::Polymorphic)
    }
}

/// What an [`IrOp::Invoke`] calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallTarget {
    /// Index into `method_ids`.
    Method(u32),
    /// Index into `call_site_ids`. Only `invoke-custom` names one.
    CallSite(u32),
}

impl CallTarget {
    /// The pool index, whichever pool it indexes.
    pub const fn index(self) -> u32 {
        match self {
            CallTarget::Method(i) | CallTarget::CallSite(i) => i,
        }
    }
}

/// One call, with its arguments in argument order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Which call form, and what it targets.
    pub target: CallTarget,
    /// The five-argument forms.
    pub kind: InvokeKind,
    /// The registers holding the arguments, in argument order.
    ///
    /// # Why this list is not trusted
    ///
    /// The packed five-argument form stores its arguments in nibbles
    /// zero-padded to five, and zero is a legal register, so the encoding alone
    /// cannot say how many arguments there are: the padding is
    /// indistinguishable from trailing `v0`s. The contiguous-register forms
    /// carry an explicit count and are exact.
    ///
    /// [`Call::declared`] records what the instruction's count field said, and
    /// [`Call::ranged`] says which form produced the list, but **the arity that
    /// matters is the target method's own prototype**, which is in `method_ids`
    /// and which no instruction operand contains. Slicing this list to a
    /// prototype-declared arity is `codegen`'s and `marshal`'s job (A2, A6),
    /// and it is the same job the oracle does at run time. The lowerer records
    /// what it saw and guesses nothing.
    pub args: Box<[Reg]>,
    /// True when the operands came from a contiguous range, so [`Call::args`] is
    /// exact rather than padded.
    pub ranged: bool,
    /// The instruction's own count field: the `A` nibble of the packed form, the
    /// `AA` byte of the range form.
    ///
    /// Every compiler writes the argument count there. The specification
    /// describes the same field as the *destination* register for a call with a
    /// result, and the two readings agree whenever the call has no result —
    /// which is every call whose result is consumed by the following
    /// `move-result`, i.e. all of them in practice.
    pub declared: u8,
    /// The trailing `proto_ids` index of the signature-polymorphic forms.
    pub proto: Option<ProtoRef>,
}

impl Call {
    /// The number of arguments the encoding carries, before any prototype has
    /// been consulted.
    pub fn encoded_arity(&self) -> usize {
        self.args.len()
    }
}

/// A data payload: the body of one of the three pseudo-instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// A dense switch: a first key and one target per consecutive value.
    PackedSwitch {
        /// The value corresponding to the first target.
        first_key: i32,
        /// One target per key, in ascending key order.
        ///
        /// The offsets are **relative to the switching instruction**, not to the
        /// payload and not absolute — the input specifies it that way and it is
        /// the one addressing mode in the format that is not a code-unit offset
        /// from the stream start. A `codegen` that relocates the switching
        /// instruction has to re-base them; the lowerer deliberately leaves
        /// them alone so the value is the input's.
        targets: Box<[i32]>,
    },
    /// A sparse switch: parallel key and target arrays.
    SparseSwitch {
        /// The keys, in strictly ascending order.
        keys: Box<[i32]>,
        /// One target per key, positioned as in [`Payload::PackedSwitch`].
        targets: Box<[i32]>,
    },
    /// Raw element data for `fill-array-data`.
    FillArrayData {
        /// Bytes per element. 1, 2, 4 or 8 for a primitive array; 4 for an
        /// object array.
        element_width: u16,
        /// Number of elements. `element_width * element_count == data.len()`.
        element_count: u32,
        /// The element bytes, little-endian, in stream order.
        data: Box<[u8]>,
    },
}

impl Payload {
    /// The number of code units this payload occupies, which is what the
    /// lowering's linear walk advances by.
    pub const fn units(&self) -> u32 {
        match self {
            Payload::PackedSwitch { targets, .. } => 4 + 2 * targets.len() as u32,
            Payload::SparseSwitch { keys, .. } => 2 + 4 * keys.len() as u32,
            Payload::FillArrayData { data, .. } => 4 + (data.len() as u32).div_ceil(2),
        }
    }
}

/// Which switch the [`IrOp::Switch`] selects between.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchKind {
    /// A contiguous run of values, indexed by `value - first_key`.
    Packed,
    /// An arbitrary set of values, searched by key.
    Sparse,
}

// ================================================================= instructions

/// The lowered instruction set.
///
/// Every variant states its own types in its own fields, so a type error in the
/// IR is a `rustc` error. Where the input does not determine a type, the
/// variant carries [`WideClass`] or [`WordClass`] saying so rather than
/// guessing.
#[derive(Debug, Clone, PartialEq)]
#[allow(non_camel_case_types)]
pub enum IrOp {
    // ------------------------------------------------------------- no effect
    /// No operation. Present in the input and preserved, because a `nop` is a
    /// branch target and a `nop` is a padding unit, and dropping it would move
    /// every label after it.
    Nop,

    // ----------------------------------------------------------- data movement
    /// `dst = src` for a 32-bit integer (`Z`/`B`/`S`/`C`/`I`).
    MoveI32 { dst: I32Reg, src: I32Reg },
    /// `dst = src` for an object reference.
    MoveObject { dst: ObjectReg, src: ObjectReg },
    /// `dst = src` for a 64-bit value, whose class the input does not state.
    MoveWide { dst: Reg, src: Reg, class: WideClass },
    /// `dst = ` the result of the immediately preceding call or allocation.
    MoveResultI32 { dst: I32Reg },
    /// `dst = ` the immediately preceding call's reference result.
    MoveResultObject { dst: ObjectReg },
    /// `dst = ` the immediately preceding call's 64-bit result, whose class the
    /// input does not state.
    MoveResultWide { dst: Reg, class: WideClass },
    /// `dst = ` the exception currently being handled.
    MoveException { dst: ObjectReg },

    // ------------------------------------------------------------------ return
    /// Return no value.
    ReturnVoid,
    /// Return a 32-bit integer.
    ReturnI32 { src: I32Reg },
    /// Return a reference.
    ReturnObject { src: ObjectReg },
    /// Return a 64-bit value, whose class the input does not state.
    ReturnWide { src: Reg, class: WideClass },

    // -------------------------------------------------------------- constants
    /// `dst = value`.
    ///
    /// The 32-bit immediate family. Dalvik has **no** float literal, so this
    /// variant can never hold an `f32`: a float constant is a `const` of the bit
    /// pattern followed by a conversion, and the IR records it as exactly that.
    ConstI32 { dst: I32Reg, value: i32 },
    /// `dst = bits`, interpreted as a `long` or as a `double`'s IEEE-754
    /// pattern.
    ///
    /// The 64-bit immediate family. The class is unresolved because the input
    /// does not say: the same encoding materialises `0x3fe0000000000000` as the
    /// `double` 0.5 and as the `long` 4607182418800017408 depending on what the
    /// verifier made of the register pair. `codegen` must load the pattern
    /// as-is and let the class decide; reading it as a number turns every double
    /// constant in a real APK into a plausible wrong answer.
    ConstWide { dst: Reg, bits: u64, class: WideClass },
    /// `dst = ` the interned string at `index`.
    ConstString { dst: ObjectReg, index: StringRef },
    /// `dst = ` the class object for the type at `index`.
    ConstClass { dst: ObjectReg, index: TypeRef },

    // ------------------------------------------------------------- unary maths
    /// `dst = -src`.
    NegI32 { dst: I32Reg, src: I32Reg },
    /// `dst = -src`.
    NegI64 { dst: I64Reg, src: I64Reg },
    /// `dst = -src`.
    NegF32 { dst: F32Reg, src: F32Reg },
    /// `dst = -src`.
    NegF64 { dst: F64Reg, src: F64Reg },
    /// `dst = ~src`.
    NotI32 { dst: I32Reg, src: I32Reg },
    /// `dst = ~src`.
    NotI64 { dst: I64Reg, src: I64Reg },

    // ------------------------------------------------------------- conversions
    /// `dst = (i64) src`.
    I32ToI64 { dst: I64Reg, src: I32Reg },
    /// `dst = (f32) src`.
    I32ToF32 { dst: F32Reg, src: I32Reg },
    /// `dst = (f64) src`.
    I32ToF64 { dst: F64Reg, src: I32Reg },
    /// `dst = (i32) src`, truncating the low 32 bits.
    I64ToI32 { dst: I32Reg, src: I64Reg },
    /// `dst = (f32) src`, rounding to nearest.
    I64ToF32 { dst: F32Reg, src: I64Reg },
    /// `dst = (f64) src`.
    I64ToF64 { dst: F64Reg, src: I64Reg },

    /// `dst = ` `src` as an `i32`, **saturating**.
    ///
    /// # This is not a WebAssembly truncation
    ///
    /// `i32.trunc_f32_s` traps on NaN and on anything out of range. The
    /// language-level conversion saturates: NaN becomes 0, +∞ becomes
    /// `i32::MAX`, -∞ becomes `i32::MIN`. `codegen` must emit a saturating
    /// sequence, not the truncating instruction of the same name; the two agree
    /// on ordinary values and differ on every value a program is most likely to
    /// be surprised by. The oracle's `dexinterp::ops::f32_to_int` is the
    /// reference.
    F32ToI32 { dst: I32Reg, src: F32Reg },
    /// `dst = ` `src` as an `i64`, **saturating**. See [`IrOp::F32ToI32`].
    F32ToI64 { dst: I64Reg, src: F32Reg },
    /// `dst = (f64) src`.
    F32ToF64 { dst: F64Reg, src: F32Reg },
    /// `dst = ` `src` as an `i32`, **saturating**. See [`IrOp::F32ToI32`].
    F64ToI32 { dst: I32Reg, src: F64Reg },
    /// `dst = ` `src` as an `i64`, **saturating**. See [`IrOp::F32ToI32`].
    F64ToI64 { dst: I64Reg, src: F64Reg },
    /// `dst = (f32) src`, rounding to nearest.
    F64ToF32 { dst: F32Reg, src: F64Reg },

    /// `dst = (byte) src`: the low 8 bits, **sign**-extended.
    I32ToByte { dst: I32Reg, src: I32Reg },
    /// `dst = (char) src`: the low 16 bits, **zero**-extended. `0xFFFF` is
    /// 65535, not -1.
    I32ToChar { dst: I32Reg, src: I32Reg },
    /// `dst = (short) src`: the low 16 bits, **sign**-extended.
    I32ToShort { dst: I32Reg, src: I32Reg },

    // -------------------------------------------------------------- arithmetic
    //
    // One variant per (class, operator) rather than one variant per operator
    // with a class parameter, for the same reason the registers are distinct
    // newtypes: it puts the operand types in the *type* of the operand, so
    // `AddI64` cannot be handed an `I32Reg` and `codegen` gets one flat arm per
    // WebAssembly instruction it has to emit. This is the shape Cranelift, LLVM
    // and WebAssembly itself use.
    //
    // Each variant serves all three of the input's shapes: the three-address
    // form, the two-address form (in which `a` and `dst` are the same
    // register), and the immediate forms (which the lowerer expand into a
    // preceding `ConstI32` and then this). WebAssembly has no two-address
    // instruction and no immediate on `i32.shl`, so there is nothing for the
    // distinction to survive as.

    /// `dst = a + b` over 32-bit integers.
    AddI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a - b` over 32-bit integers.
    SubI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a * b` over 32-bit integers.
    MulI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a / b` over 32-bit integers, throwing on a zero divisor and on
    /// `i32::MIN / -1`, which overflows rather than wrapping.
    DivI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a % b` over 32-bit integers, throwing on a zero divisor. The
    /// sign of the result is the dividend's, and `i32::MIN % -1` is 0 rather
    /// than an overflow.
    RemI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a & b` over 32-bit integers.
    AndI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a | b` over 32-bit integers.
    OrI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a ^ b` over 32-bit integers.
    XorI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a << b` over 32-bit integers, with the count taken **modulo 32**
    /// — the Java language rule, and the one `i32.shl` does *not* implement.
    ShlI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a >> b`, arithmetic, count modulo 32.
    ShrI32 { dst: I32Reg, a: I32Reg, b: I32Reg },
    /// `dst = a >>> b`, logical, count modulo 32.
    UShrI32 { dst: I32Reg, a: I32Reg, b: I32Reg },

    // ---- the immediate forms, which the 32-bit integer class alone has.
    //
    // These are kept as immediates rather than expanded into a preceding
    // `ConstI32`, for one reason: WebAssembly is a stack machine, so
    // `local.get v0; i32.const 5; i32.add` *is* the immediate form. Expanding
    // would invent a register the input never had, and the register file's
    // layout is the one thing in this IR a consumer has to agree with the
    // calling convention on exactly.
    //
    // The shift forms are the interesting ones: the shift *count* is the
    // immediate, and it is masked (`count & 31`) before use.

    /// `dst = a + lit`.
    AddI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = lit - a`. The only reversed form; the result is the opposite
    /// subtraction, so `codegen` emits `lit` then `a` then `i32.sub`.
    RsubI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a * lit`.
    MulI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a / lit`. Throws as [`IrOp::DivI32`] does, and `lit == 0` is a
    /// *constant* zero divisor, which the compiler can see and reject.
    DivI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a % lit`. Throws as [`IrOp::RemI32`] does.
    RemI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a & lit`.
    AndI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a | lit`.
    OrI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a ^ lit`.
    XorI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a << (lit & 31)`.
    ShlI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a >> (lit & 31)`, arithmetic.
    ShrI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },
    /// `dst = a >>> (lit & 31)`, logical.
    UShrI32Lit { dst: I32Reg, a: I32Reg, lit: i32 },

    /// `dst = a + b` over 64-bit integers.
    AddI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a - b` over 64-bit integers.
    SubI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a * b` over 64-bit integers.
    MulI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a / b` over 64-bit integers. Throws as [`IrOp::DivI32`] does.
    DivI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a % b` over 64-bit integers. Throws as [`IrOp::RemI32`] does.
    RemI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a & b` over 64-bit integers.
    AndI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a | b` over 64-bit integers.
    OrI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a ^ b` over 64-bit integers.
    XorI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a << b` over 64-bit integers, count modulo 64.
    ShlI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a >> b`, arithmetic, count modulo 64.
    ShrI64 { dst: I64Reg, a: I64Reg, b: I64Reg },
    /// `dst = a >>> b`, logical, count modulo 64.
    UShrI64 { dst: I64Reg, a: I64Reg, b: I64Reg },

    /// `dst = a + b` over `float`s. NaN, ±0 and ±∞ follow IEEE-754; nothing
    /// here throws.
    AddF32 { dst: F32Reg, a: F32Reg, b: F32Reg },
    /// `dst = a - b` over `float`s.
    SubF32 { dst: F32Reg, a: F32Reg, b: F32Reg },
    /// `dst = a * b` over `float`s.
    MulF32 { dst: F32Reg, a: F32Reg, b: F32Reg },
    /// `dst = a / b` over `float`s. A zero divisor is ±∞ or NaN, **not** a
    /// throwable — which is the whole difference from [`IrOp::DivI32`].
    DivF32 { dst: F32Reg, a: F32Reg, b: F32Reg },
    /// `dst = a % b` over `float`s, which is the IEEE remainder: the sign of
    /// the result is the dividend's, and a zero divisor is NaN.
    RemF32 { dst: F32Reg, a: F32Reg, b: F32Reg },

    /// `dst = a + b` over `double`s.
    AddF64 { dst: F64Reg, a: F64Reg, b: F64Reg },
    /// `dst = a - b` over `double`s.
    SubF64 { dst: F64Reg, a: F64Reg, b: F64Reg },
    /// `dst = a * b` over `double`s.
    MulF64 { dst: F64Reg, a: F64Reg, b: F64Reg },
    /// `dst = a / b` over `double`s. A zero divisor is ±∞ or NaN, not a
    /// throwable.
    DivF64 { dst: F64Reg, a: F64Reg, b: F64Reg },
    /// `dst = a % b` over `double`s, the IEEE remainder.
    RemF64 { dst: F64Reg, a: F64Reg, b: F64Reg },

    // -------------------------------------------------------------- comparison
    /// `dst = sign(x - y)` for two `long`s.
    CmpLong { dst: I32Reg, a: I64Reg, b: I64Reg },
    /// `dst = ` the `float` comparison of `a` and `b`, yielding -1, 0 or 1, with
    /// **-1 for NaN**.
    CmpF32L { dst: I32Reg, a: F32Reg, b: F32Reg },
    /// As [`IrOp::CmpF32L`], with **1 for NaN**.
    CmpF32G { dst: I32Reg, a: F32Reg, b: F32Reg },
    /// As [`IrOp::CmpF32L`] over `double`s, with **-1 for NaN**.
    CmpF64L { dst: I32Reg, a: F64Reg, b: F64Reg },
    /// As [`IrOp::CmpF64L`], with **1 for NaN**.
    CmpF64G { dst: I32Reg, a: F64Reg, b: F64Reg },

    // ------------------------------------------------------------- control flow
    /// Branch unconditionally.
    Jump { target: Label },
    /// Branch to `target` if the two words are equal.
    BrEq { a: Word, b: Word, target: Label },
    /// Branch to `target` if the two words differ.
    BrNe { a: Word, b: Word, target: Label },
    /// Branch to `target` if `a < b`, signed.
    BrLt { a: I32Reg, b: I32Reg, target: Label },
    /// Branch to `target` if `a >= b`, signed.
    BrGe { a: I32Reg, b: I32Reg, target: Label },
    /// Branch to `target` if `a > b`, signed.
    BrGt { a: I32Reg, b: I32Reg, target: Label },
    /// Branch to `target` if `a <= b`, signed.
    BrLe { a: I32Reg, b: I32Reg, target: Label },
    /// Branch to `target` if the word is zero — which for a reference is
    /// `x == null`.
    BrEqZ { a: Word, target: Label },
    /// Branch to `target` if the word is non-zero — for a reference,
    /// `x != null`.
    BrNeZ { a: Word, target: Label },
    /// Branch to `target` if `a < 0`, signed.
    BrLtZ { a: I32Reg, target: Label },
    /// Branch to `target` if `a >= 0`, signed.
    BrGeZ { a: I32Reg, target: Label },
    /// Branch to `target` if `a > 0`, signed.
    BrGtZ { a: I32Reg, target: Label },
    /// Branch to `target` if `a <= 0`, signed.
    BrLeZ { a: I32Reg, target: Label },
    /// Dispatch on `reg` through the payload at `payload`.
    Switch { kind: SwitchKind, reg: I32Reg, payload: Label },
    /// Throw `exception`.
    Throw { exception: ObjectReg },
    /// Enter the monitor of `object`.
    MonitorEnter { object: ObjectReg },
    /// Exit the monitor of `object`.
    MonitorExit { object: ObjectReg },

    // ------------------------------------------------------------------- types
    /// Narrow `object` to the type at `index`, in place, throwing on failure.
    CheckCast { object: ObjectReg, index: TypeRef },
    /// `dst = 1` if `object` is an instance of the type at `index`, else 0.
    InstanceOf { dst: I32Reg, object: ObjectReg, index: TypeRef },

    // ------------------------------------------------------------------ arrays
    /// Allocate an uninitialised object of the type at `index`.
    NewInstance { dst: ObjectReg, index: TypeRef },
    /// Allocate an array of `size` elements of the type at `type_index`.
    NewArray { dst: ObjectReg, type_index: TypeRef, size: I32Reg },
    /// `dst = ` the length of `array`.
    ArrayLength { dst: I32Reg, array: ObjectReg },
    /// `dst = ` the 32-bit element at `index` of `array`, whose class is the
    /// array's component type rather than the instruction's.
    AgetWord { dst: Reg, array: ObjectReg, index: I32Reg, class: WordClass },
    /// `dst = ` the sub-word element at `index` of `array`, widened by `narrow`.
    AgetNarrow { dst: I32Reg, array: ObjectReg, index: I32Reg, narrow: Narrow },
    /// `dst = ` the 64-bit element at `index` of `array`.
    AgetWide { dst: Reg, array: ObjectReg, index: I32Reg, class: WideClass },
    /// `dst = ` the reference element at `index` of `array`.
    AgetObject { dst: ObjectReg, array: ObjectReg, index: I32Reg },
    /// Store a 32-bit `value` at `index` of `array`, whose class is the array's
    /// component type rather than the instruction's.
    AputWord { array: ObjectReg, index: I32Reg, value: Reg, class: WordClass },
    /// Store a sub-word `value` at `index` of `array`, truncated by `narrow`.
    AputNarrow { array: ObjectReg, index: I32Reg, value: I32Reg, narrow: Narrow },
    /// Store a 64-bit `value` at `index` of `array`.
    AputWide { array: ObjectReg, index: I32Reg, value: Reg, class: WideClass },
    /// Store a reference `value` at `index` of `array`.
    AputObject { array: ObjectReg, index: I32Reg, value: ObjectReg },
    /// Allocate an array of the type at `type_index` holding the arguments, in
    /// order.
    ///
    /// # There is no destination, and that is not an oversight
    ///
    /// This is a call, and the instruction does not name a destination for it.
    /// The count field carries the *argument* count, exactly as it does for the
    /// fourteen `invoke-*` forms, and the array reference arrives in the same
    /// implicit result slot that a call's does — which the following
    /// [`IrOp::MoveResultObject`] normally reads. Reading that field as a
    /// destination register would write the array into whatever register
    /// happened to hold the argument count, clobbering a live value.
    ///
    /// `args` has the same trust caveat as [`Call::args`]: the packed form's
    /// trailing zero nibbles are padding unless the last element really is
    /// `v0`, so the *array's* prototype is the only authority on the length.
    FilledNewArray {
        /// Index into `type_ids`: the array type, not the element type.
        type_index: TypeRef,
        /// The element values, in order.
        args: Box<[Reg]>,
        /// True when the operands came from a contiguous range, in which case
        /// [`IrOp::FilledNewArray::declared`] is exact.
        ranged: bool,
        /// The instruction's own count field: the `A` nibble of the packed form,
        /// the `AA` byte of the range form. For the range form this *is* the
        /// argument count, because the encoding has only one field for it.
        declared: u8,
    },
    /// Copy the payload's element bytes into `array`, starting at index 0.
    FillArrayData { array: ObjectReg, payload: Label },

    // ------------------------------------------------------------------ fields
    /// `dst = object.field`, a 32-bit field whose class the field itself
    /// determines.
    IgetWord { dst: Reg, object: ObjectReg, field: FieldRef, class: WordClass },
    /// `dst = object.field`, a sub-word field widened by `narrow`.
    IgetNarrow { dst: I32Reg, object: ObjectReg, field: FieldRef, narrow: Narrow },
    /// `dst = object.field`, a 64-bit field.
    IgetWide { dst: Reg, object: ObjectReg, field: FieldRef, class: WideClass },
    /// `dst = object.field`, a reference field.
    IgetObject { dst: ObjectReg, object: ObjectReg, field: FieldRef },
    /// `object.field = value`, a 32-bit field.
    IputWord { object: ObjectReg, field: FieldRef, value: Reg, class: WordClass },
    /// `object.field = value`, a sub-word field truncated by `narrow`.
    IputNarrow { object: ObjectReg, field: FieldRef, value: I32Reg, narrow: Narrow },
    /// `object.field = value`, a 64-bit field.
    IputWide { object: ObjectReg, field: FieldRef, value: Reg, class: WideClass },
    /// `object.field = value`, a reference field.
    IputObject { object: ObjectReg, field: FieldRef, value: ObjectReg },
    /// `dst = Class.field`, a 32-bit static field.
    SgetWord { dst: Reg, field: FieldRef, class: WordClass },
    /// `dst = Class.field`, a sub-word static field widened by `narrow`.
    SgetNarrow { dst: I32Reg, field: FieldRef, narrow: Narrow },
    /// `dst = Class.field`, a 64-bit static field.
    SgetWide { dst: Reg, field: FieldRef, class: WideClass },
    /// `dst = Class.field`, a reference static field.
    SgetObject { dst: ObjectReg, field: FieldRef },
    /// `Class.field = value`, a 32-bit static field.
    SputWord { field: FieldRef, value: Reg, class: WordClass },
    /// `Class.field = value`, a sub-word static field truncated by `narrow`.
    SputNarrow { field: FieldRef, value: I32Reg, narrow: Narrow },
    /// `Class.field = value`, a 64-bit static field.
    SputWide { field: FieldRef, value: Reg, class: WideClass },
    /// `Class.field = value`, a reference static field.
    SputObject { field: FieldRef, value: ObjectReg },

    // ----------------------------------------------------------------- calling
    /// Call, with the arguments already in the register file.
    ///
    /// There is no destination: a call that has a result leaves it in an
    /// implicit slot which the following [`IrOp::MoveResultI32`] and its
    /// siblings read, and which a call that has no result leaves untouched.
    /// Making that a second channel rather than an operand is what keeps
    /// `codegen`'s value stack to one, and it is why `MoveResult*` exists as a
    /// separate instruction rather than as a destination on the call.
    Invoke { call: Box<Call> },

    // ---------------------------------------------------------------- payloads
    /// A data payload. Not an instruction: it is data that happens to be
    /// addressed like one.
    ///
    /// `codegen` must place every payload in the module's data section and must
    /// never emit a branch to one, except from the [`IrOp::Switch`] or
    /// [`IrOp::FillArrayData`] that reads it. [`Function::new`] rejects every
    /// other reference.
    Payload { payload: Box<Payload> },

    // ------------------------------------------------------------ unsupported
    /// An input instruction this IR does not implement, and why.
    ///
    /// Never "nothing". An input instruction with no [`IrOp`] is a hole in the
    /// lowering, and a hole is exactly how a plausible wrong answer ships. A
    /// rejected instruction still appears in the body, still carries its
    /// [`Origin`], and still counts towards the structural-equivalence check, so
    /// the report can say exactly how many instructions of a method were not
    /// compiled and which.
    Unsupported { reason: UnsupportedReason },
}

impl IrOp {
    /// Every register this instruction reads.
    pub fn reads(&self) -> Vec<Reg> {
        let mut out = Vec::new();
        let mut visit = |role: RegRole, reg: Reg, _| {
            if matches!(role, RegRole::Read | RegRole::ReadWrite) {
                out.push(reg);
            }
        };
        self.for_each_reg(&mut visit);
        out
    }

    /// Every register this instruction writes.
    pub fn writes(&self) -> Vec<Reg> {
        let mut out = Vec::new();
        let mut visit = |role: RegRole, reg: Reg, _| {
            if matches!(role, RegRole::Write | RegRole::ReadWrite) {
                out.push(reg);
            }
        };
        self.for_each_reg(&mut visit);
        out
    }

    /// True if control cannot fall out of the bottom of this instruction.
    pub const fn is_terminator(&self) -> bool {
        matches!(
            self,
            IrOp::ReturnVoid
                | IrOp::ReturnI32 { .. }
                | IrOp::ReturnObject { .. }
                | IrOp::ReturnWide { .. }
                | IrOp::Throw { .. }
                | IrOp::Unsupported { .. }
        )
    }

    /// True if this instruction ends a basic block: a terminator, a branch, or
    /// the first of a two-instruction branch sequence.
    pub const fn ends_block(&self) -> bool {
        matches!(
            self,
            IrOp::Jump { .. }
                | IrOp::BrEq { .. }
                | IrOp::BrNe { .. }
                | IrOp::BrLt { .. }
                | IrOp::BrGe { .. }
                | IrOp::BrGt { .. }
                | IrOp::BrLe { .. }
                | IrOp::BrEqZ { .. }
                | IrOp::BrNeZ { .. }
                | IrOp::BrLtZ { .. }
                | IrOp::BrGeZ { .. }
                | IrOp::BrGtZ { .. }
                | IrOp::BrLeZ { .. }
                | IrOp::Switch { .. }
        ) || self.is_terminator()
    }

    /// Every label this instruction can transfer control to.
    pub fn labels(&self) -> Vec<Label> {
        match self {
            IrOp::Jump { target }
            | IrOp::BrEq { target, .. }
            | IrOp::BrNe { target, .. }
            | IrOp::BrLt { target, .. }
            | IrOp::BrGe { target, .. }
            | IrOp::BrGt { target, .. }
            | IrOp::BrLe { target, .. }
            | IrOp::BrEqZ { target, .. }
            | IrOp::BrNeZ { target, .. }
            | IrOp::BrLtZ { target, .. }
            | IrOp::BrGeZ { target, .. }
            | IrOp::BrGtZ { target, .. }
            | IrOp::BrLeZ { target, .. } => vec![*target],
            IrOp::Switch { payload, .. } | IrOp::FillArrayData { payload, .. } => vec![*payload],
            _ => Vec::new(),
        }
    }

    /// Walk every register operand, naming its role.
    ///
    /// The visitor is exhaustive over `IrOp` and `rustc` checks that: an
    /// `IrOp` variant added later without its operands listed here is a
    /// compile error, not a silent omission from A2's liveness analysis.
    pub fn for_each_reg(&self, f: &mut impl FnMut(RegRole, Reg, Option<Ty>)) {
        use IrOp as I;
        let (d, a, b, c) = (RegRole::Write, RegRole::Read, RegRole::Read, RegRole::Read);
        match self {
            I::Nop | I::ReturnVoid | I::Payload { .. } => {}
            I::Unsupported { .. } => {}

            I::MoveI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::MoveObject { dst, src } => {
                f(d, dst.reg(), Some(Ty::Object));
                f(a, src.reg(), Some(Ty::Object));
            }
            I::MoveWide { dst, src, class } => {
                f(d, *dst, class.ty());
                f(a, *src, class.ty());
            }
            I::MoveResultI32 { dst } => f(d, dst.reg(), Some(Ty::I32)),
            I::MoveResultObject { dst } => f(d, dst.reg(), Some(Ty::Object)),
            I::MoveResultWide { dst, class } => f(d, *dst, class.ty()),
            I::MoveException { dst } => f(d, dst.reg(), Some(Ty::Object)),

            I::ReturnI32 { src } => f(a, src.reg(), Some(Ty::I32)),
            I::ReturnObject { src } => f(a, src.reg(), Some(Ty::Object)),
            I::ReturnWide { src, class } => f(a, *src, class.ty()),

            I::ConstI32 { dst, .. } => f(d, dst.reg(), Some(Ty::I32)),
            I::ConstWide { dst, class, .. } => f(d, *dst, class.ty()),
            I::ConstString { dst, .. } | I::ConstClass { dst, .. } => {
                f(d, dst.reg(), Some(Ty::Object))
            }

            I::NegI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::NegI64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I64));
                f(a, src.reg(), Some(Ty::I64));
            }
            I::NegF32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F32));
                f(a, src.reg(), Some(Ty::F32));
            }
            I::NegF64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F64));
                f(a, src.reg(), Some(Ty::F64));
            }
            I::NotI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::NotI64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I64));
                f(a, src.reg(), Some(Ty::I64));
            }

            I::I32ToI64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I64));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::I32ToF32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F32));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::I32ToF64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F64));
                f(a, src.reg(), Some(Ty::I32));
            }
            I::I64ToI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::I64));
            }
            I::I64ToF32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F32));
                f(a, src.reg(), Some(Ty::I64));
            }
            I::I64ToF64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F64));
                f(a, src.reg(), Some(Ty::I64));
            }
            I::F32ToI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::F32));
            }
            I::F32ToI64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I64));
                f(a, src.reg(), Some(Ty::F32));
            }
            I::F32ToF64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F64));
                f(a, src.reg(), Some(Ty::F32));
            }
            I::F64ToI32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::F64));
            }
            I::F64ToI64 { dst, src } => {
                f(d, dst.reg(), Some(Ty::I64));
                f(a, src.reg(), Some(Ty::F64));
            }
            I::F64ToF32 { dst, src } => {
                f(d, dst.reg(), Some(Ty::F32));
                f(a, src.reg(), Some(Ty::F64));
            }
            I::I32ToByte { dst, src } | I::I32ToChar { dst, src } | I::I32ToShort { dst, src } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, src.reg(), Some(Ty::I32));
            }

            I::CmpLong { dst, a: x, b: y } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, x.reg(), Some(Ty::I64));
                f(b, y.reg(), Some(Ty::I64));
            }
            I::CmpF32L { dst, a: x, b: y } | I::CmpF32G { dst, a: x, b: y } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, x.reg(), Some(Ty::F32));
                f(b, y.reg(), Some(Ty::F32));
            }
            I::CmpF64L { dst, a: x, b: y } | I::CmpF64G { dst, a: x, b: y } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, x.reg(), Some(Ty::F64));
                f(b, y.reg(), Some(Ty::F64));
            }

            I::Jump { .. } => {}
            I::BrEq { a: x, b: y, .. } | I::BrNe { a: x, b: y, .. } => {
                f(a, x.reg(), x.ty());
                f(b, y.reg(), y.ty());
            }
            I::BrLt { a: x, b: y, .. }
            | I::BrGe { a: x, b: y, .. }
            | I::BrGt { a: x, b: y, .. }
            | I::BrLe { a: x, b: y, .. } => {
                f(a, x.reg(), Some(Ty::I32));
                f(b, y.reg(), Some(Ty::I32));
            }
            I::BrEqZ { a: x, .. } | I::BrNeZ { a: x, .. } => f(a, x.reg(), x.ty()),
            I::BrLtZ { a: x, .. } | I::BrGeZ { a: x, .. } | I::BrGtZ { a: x, .. }
            | I::BrLeZ { a: x, .. } => f(a, x.reg(), Some(Ty::I32)),
            I::Switch { reg, .. } => f(a, reg.reg(), Some(Ty::I32)),
            I::Throw { exception } => f(a, exception.reg(), Some(Ty::Object)),
            I::MonitorEnter { object } | I::MonitorExit { object } => {
                f(c, object.reg(), Some(Ty::Object))
            }

            I::CheckCast { object, .. } => f(c, object.reg(), Some(Ty::Object)),
            I::InstanceOf { dst, object, .. } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, object.reg(), Some(Ty::Object));
            }

            I::NewInstance { dst, .. } => f(d, dst.reg(), Some(Ty::Object)),
            I::NewArray { dst, size, .. } => {
                f(d, dst.reg(), Some(Ty::Object));
                f(a, size.reg(), Some(Ty::I32));
            }
            I::ArrayLength { dst, array } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, array.reg(), Some(Ty::Object));
            }
            I::AgetWord { dst, array, index, class } => {
                f(d, *dst, class.ty());
                f(a, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
            }
            I::AgetNarrow { dst, array, index, .. } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
            }
            I::AgetWide { dst, array, index, class } => {
                f(d, *dst, class.ty());
                f(a, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
            }
            I::AgetObject { dst, array, index } => {
                f(d, dst.reg(), Some(Ty::Object));
                f(a, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
            }
            I::AputWord { array, index, value, class } => {
                f(c, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
                f(a, *value, class.ty());
            }
            I::AputNarrow { array, index, value, .. } => {
                f(c, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
                f(a, value.reg(), Some(Ty::I32));
            }
            I::AputWide { array, index, value, class } => {
                f(c, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
                f(a, *value, class.ty());
            }
            I::AputObject { array, index, value } => {
                f(c, array.reg(), Some(Ty::Object));
                f(b, index.reg(), Some(Ty::I32));
                f(a, value.reg(), Some(Ty::Object));
            }
            I::FilledNewArray { args, .. } => {
                for r in args.iter() {
                    f(a, *r, None);
                }
            }
            I::FillArrayData { array, .. } => f(a, array.reg(), Some(Ty::Object)),

            I::IgetWord { dst, object, class, .. } => {
                f(d, *dst, class.ty());
                f(a, object.reg(), Some(Ty::Object));
            }
            I::IgetNarrow { dst, object, .. } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, object.reg(), Some(Ty::Object));
            }
            I::IgetWide { dst, object, class, .. } => {
                f(d, *dst, class.ty());
                f(a, object.reg(), Some(Ty::Object));
            }
            I::IgetObject { dst, object, .. } => {
                f(d, dst.reg(), Some(Ty::Object));
                f(a, object.reg(), Some(Ty::Object));
            }
            I::IputWord { object, value, class, .. } => {
                f(c, object.reg(), Some(Ty::Object));
                f(a, *value, class.ty());
            }
            I::IputNarrow { object, value, .. } => {
                f(c, object.reg(), Some(Ty::Object));
                f(a, value.reg(), Some(Ty::I32));
            }
            I::IputWide { object, value, class, .. } => {
                f(c, object.reg(), Some(Ty::Object));
                f(a, *value, class.ty());
            }
            I::IputObject { object, value, .. } => {
                f(c, object.reg(), Some(Ty::Object));
                f(a, value.reg(), Some(Ty::Object));
            }
            I::SgetWord { dst, class, .. } => f(d, *dst, class.ty()),
            I::SgetNarrow { dst, .. } => f(d, dst.reg(), Some(Ty::I32)),
            I::SgetWide { dst, class, .. } => f(d, *dst, class.ty()),
            I::SgetObject { dst, .. } => f(d, dst.reg(), Some(Ty::Object)),
            I::SputWord { value, class, .. } => f(a, *value, class.ty()),
            I::SputNarrow { value, .. } => f(a, value.reg(), Some(Ty::I32)),
            I::SputWide { value, class, .. } => f(a, *value, class.ty()),
            I::SputObject { value, .. } => f(a, value.reg(), Some(Ty::Object)),

            I::Invoke { call } => {
                for r in call.args.iter() {
                    f(a, *r, None);
                }
            }

            // The binary arithmetic family, one arm per variant. Named so that
            // a new one cannot be added without appearing here.
            I::AddI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::SubI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::MulI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::DivI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::RemI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::AndI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::OrI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::XorI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::ShlI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::ShrI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::UShrI32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I32), f),
            I::AddI32Lit { dst, a: x, .. } | I::RsubI32Lit { dst, a: x, .. } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, x.reg(), Some(Ty::I32));
            }
            I::MulI32Lit { dst, a: x, .. }
            | I::DivI32Lit { dst, a: x, .. }
            | I::RemI32Lit { dst, a: x, .. }
            | I::AndI32Lit { dst, a: x, .. }
            | I::OrI32Lit { dst, a: x, .. }
            | I::XorI32Lit { dst, a: x, .. }
            | I::ShlI32Lit { dst, a: x, .. }
            | I::ShrI32Lit { dst, a: x, .. }
            | I::UShrI32Lit { dst, a: x, .. } => {
                f(d, dst.reg(), Some(Ty::I32));
                f(a, x.reg(), Some(Ty::I32));
            }
            I::AddI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::SubI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::MulI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::DivI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::RemI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::AndI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::OrI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::XorI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::ShlI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::ShrI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::UShrI64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::I64), f),
            I::AddF32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F32), f),
            I::SubF32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F32), f),
            I::MulF32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F32), f),
            I::DivF32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F32), f),
            I::RemF32 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F32), f),
            I::AddF64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F64), f),
            I::SubF64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F64), f),
            I::MulF64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F64), f),
            I::DivF64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F64), f),
            I::RemF64 { dst, a: x, b: y } => bin(d, a, b, dst.reg(), x.reg(), y.reg(), Some(Ty::F64), f),
        }
    }
}

/// The shared shape of every binary arithmetic instruction: one write, two
/// reads, all of one class.
#[allow(clippy::too_many_arguments)]
fn bin(
    d: RegRole,
    a: RegRole,
    b: RegRole,
    dst: Reg,
    x: Reg,
    y: Reg,
    ty: Option<Ty>,
    f: &mut impl FnMut(RegRole, Reg, Option<Ty>),
) {
    f(d, dst, ty);
    f(a, x, ty);
    f(b, y, ty);
}

/// Why an input instruction did not become a real [`IrOp`].
///
/// Every variant is a *structural* absence — a thing the IR has no way to
/// represent — rather than "not implemented yet". An unimplemented-but-plausible
/// operation would be a [`IrOp`] that does the wrong thing, which is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnsupportedReason {
    /// One of the instruction slots the input format leaves unassigned.
    ///
    /// Reaching one means the file is not the format it claims to be. It is not
    /// a crash and not a missing feature, and the IR records it as its own
    /// reason rather than folding it into "foreign" so the two stay countable
    /// separately — the oracle keeps them apart for the same reason.
    UnassignedSlot,
    /// An instruction encoding from the wider ecosystem but not from the format
    /// proper: a foreign DEX variant or a third-party obfuscator.
    ///
    /// Not Dalvik, and not something `codegen` should ever be asked to compile.
    ForeignFormat,
    /// `const-method-handle`: the result is a `java.lang.invoke.MethodHandle`.
    ///
    /// Not refused for want of a heap: a handle *is* a handle. Refused because
    /// a `MethodHandle` is a *callable*, with identity, a signature, and
    /// resolution rules of its own, and the handle model of [`IR.md`](../IR.md)
    /// has nowhere to put behaviour — only offsets. Which is a **host** concern:
    /// `hostgen` (A5) is where a fabricated `MethodHandle` and the table that
    /// can invoke it belong. When that table exists this becomes
    /// `ConstMethodHandle` and only `lower/` changes.
    MethodHandle,
    /// `const-method-type`: the result is a `java.lang.invoke.MethodType`, for
    /// the same reason as [`UnsupportedReason::MethodHandle`].
    MethodType,
}

impl UnsupportedReason {
    /// The stable discriminant, for a coverage report and for `codegen`'s trap
    /// messages. Never "unsupported": that word is a claim about the substrate
    /// and these four are claims about the IR.
    pub const fn as_str(self) -> &'static str {
        match self {
            UnsupportedReason::UnassignedSlot => "unassigned_slot",
            UnsupportedReason::ForeignFormat => "foreign_format",
            UnsupportedReason::MethodHandle => "method_handle_object",
            UnsupportedReason::MethodType => "method_type_object",
        }
    }

    /// A sentence a reader can check, for a report or a compiler diagnostic.
    pub const fn explain(self) -> &'static str {
        match self {
            UnsupportedReason::UnassignedSlot => {
                "the input format leaves this instruction slot unassigned, so a file that \
                 reaches one is not the format it claims to be."
            }
            UnsupportedReason::ForeignFormat => {
                "this instruction encoding is not part of the input format proper, so it comes \
                 from a foreign file variant or a third-party obfuscator rather than from a \
                 file this compiler should be asked to compile."
            }
            UnsupportedReason::MethodHandle => {
                "the result is a callable method handle, which has behaviour and identity the \
                 handle model has nowhere to represent; it belongs in a generated host object."
            }
            UnsupportedReason::MethodType => {
                "the result is a method type, which is a signature object with identity the \
                 handle model has nowhere to represent; it belongs in a generated host object."
            }
        }
    }
}

/// Whether a register operand is read, written, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegRole {
    /// Read only.
    Read,
    /// Written only.
    Write,
    /// Read and written. The two-address form's destination.
    ReadWrite,
}

/// Where in the source method an [`Inst`] came from.
///
/// The IR is a lowering, not a copy, so one source instruction can produce
/// several IR instructions (the immediate forms expand into a constant and an
/// operation) and one IR instruction never comes from two source instructions.
/// This is what makes the structural-equivalence check checkable: the origins in
/// a [`Function::body`] are non-decreasing, and every source unit offset is
/// covered by at least one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin {
    /// The code-unit offset of the source instruction, relative to the start of
    /// the code item.
    pub unit: u32,
}

impl Origin {
    /// An origin at a code-unit offset.
    pub const fn at(unit: u32) -> Origin {
        Origin { unit }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.unit)
    }
}

/// One lowered instruction.
#[derive(Debug, Clone, PartialEq)]
pub struct Inst {
    /// The operation, with every operand resolved and every class explicit.
    pub op: IrOp,
    /// Which source instruction this came from.
    pub origin: Origin,
}

impl Inst {
    /// An instruction from a source unit offset.
    pub const fn new(op: IrOp, origin: Origin) -> Inst {
        Inst { op, origin }
    }

    /// A non-operation from a source unit offset.
    pub const fn nop(origin: Origin) -> Inst {
        Inst { op: IrOp::Nop, origin }
    }
}

// =================================================================== functions

/// The declaring class and identity of a method.
///
/// Carries the class, the static-ness and the `method_ids` index, because all
/// three are needed by every consumer downstream and none of them can be derived
/// from a body: the class-resolution order of [`IR.md`](../IR.md) keys on the
/// class, the calling convention keys on static-ness, and reachability (A4) keys
/// on the `method_ids` index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassCtx {
    /// The declaring class's descriptor, e.g. `Lcom/example/App;`.
    pub class: String,
    /// Index of the declaring class in `class_defs`.
    pub class_def_index: u32,
    /// Index of this method in `method_ids`. Stable for the file, and the
    /// identity every cross-component record uses.
    pub method_index: u32,
    /// The method's simple name, e.g. `onCreate`.
    pub name: String,
    /// The **prototype**: the parameter list and the return type, e.g.
    /// `(Landroid/os/Bundle;)V`.
    ///
    /// Not the method signature, which in the input also carries the class and
    /// the method name. The distinction matters because the frame's
    /// incoming-argument window is checked against this and the receiver is a
    /// word of that window that this does not name — see [`Function::new`].
    pub signature: String,
    /// `access_flags`, verbatim.
    ///
    /// Stored rather than interpreted: the flags are a value, and A2 has to
    /// test `ACC_STATIC` without a second copy of the constant table. The
    /// accessors below are the only place they are interpreted.
    pub access_flags: u32,
}

impl ClassCtx {
    /// A context from its parts.
    pub fn new(
        class: impl Into<String>,
        class_def_index: u32,
        method_index: u32,
        name: impl Into<String>,
        signature: impl Into<String>,
        access_flags: u32,
    ) -> ClassCtx {
        ClassCtx {
            class: class.into(),
            class_def_index,
            method_index,
            name: name.into(),
            signature: signature.into(),
            access_flags,
        }
    }

    /// `ACC_STATIC`: no receiver, and the outgoing-argument window carries every
    /// argument.
    pub const fn is_static(&self) -> bool {
        self.access_flags & dexcore::model::access::ACC_STATIC != 0
    }

    /// `ACC_NATIVE`: no body exists. Such a method never becomes a `Function`.
    pub const fn is_native(&self) -> bool {
        self.access_flags & dexcore::model::access::ACC_NATIVE != 0
    }

    /// `ACC_ABSTRACT`: no body exists.
    pub const fn is_abstract(&self) -> bool {
        self.access_flags & dexcore::model::access::ACC_ABSTRACT != 0
    }

    /// `ACC_CONSTRUCTOR`: `<init>` or `<clinit>`.
    pub const fn is_constructor(&self) -> bool {
        let n = dexcore::model::access::ACC_CONSTRUCTOR;
        self.access_flags & n != 0
    }
}

/// The shape of a method's register file.
///
/// The four fields are the code item's header, copied verbatim rather than
/// consumed, because three of them mean something to `codegen` and one of them
/// ([`Frame::outs_size`]) means something only to the caller. `codegen` allocates
/// one WebAssembly local per 32-bit word here, minus the wide pair collapse
/// described on [`Frame::registers_size`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Total size of the register file in 32-bit words, incoming arguments
    /// included.
    ///
    /// The IR does **not** lay the file out this way: a `long` or a `double`
    /// occupies one [`I64Reg`] or [`F64Reg`] here, where the input spends two
    /// words and poisons the second. `codegen` therefore allocates
    /// `registers_size - (number of wide incoming parameters)` locals, and
    /// `Function::new` checks the two counts against the prototype so that
    /// neither side has to.
    pub registers_size: u16,
    /// Width of the incoming-argument window, in 32-bit words. The window is the
    /// *last* `ins_size` words of the register file.
    pub ins_size: u16,
    /// Width of the outgoing-argument window, in 32-bit words. Only the caller
    /// needs it, and only for the `slow` calling convention; see
    /// [`IR.md`](../IR.md) § Calling convention.
    pub outs_size: u16,
    /// Total code units in the source code item, which every [`Label`] is
    /// relative to.
    pub units: u32,
}

impl Frame {
    /// A frame from the four code-item header fields.
    pub const fn new(registers_size: u16, ins_size: u16, outs_size: u16, units: u32) -> Frame {
        Frame { registers_size, ins_size, outs_size, units }
    }

    /// The first register of the incoming-argument window, or
    /// `registers_size` when there is no window.
    pub const fn first_param(&self) -> u16 {
        self.registers_size.saturating_sub(self.ins_size)
    }
}

/// One clause of a catch handler: a type to test and an address to go to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchClause {
    /// The caught type's descriptor, or `None` for a catch-all. A catch-all is
    /// last in every well-formed list, and [`Function::new`] checks that.
    pub type_descriptor: Option<String>,
    /// The handler's code-unit address.
    pub address: u32,
}

/// A protected range and its handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryRegion {
    /// First protected code unit, inclusive.
    pub start: u32,
    /// Last protected code unit, inclusive.
    pub end: u32,
    /// The clauses, in the order they are tested. The catch-all, if any, is
    /// last.
    pub handlers: Vec<CatchClause>,
}

/// A lowered method.
///
/// # The only way to build one
///
/// [`Function::new`] is the sole constructor, and it validates. There is no
/// `Default`, no public field, and no `..`-update elsewhere in the compiler, so
/// an ill-typed function cannot reach `codegen` even by accident. What it
/// checks is listed on [`Function::new`].
///
/// # The verification contract
///
/// [`IR.md`](../IR.md) § Verification makes `dexinterp` the oracle: a compiled
/// method is correct when running it through the interpreter and through the
/// compiled module give identical results. That is A2's test, and it needs a
/// `Function` whose body is a faithful lowering first. The property this type
/// guarantees towards it is *structural*, and is what
/// `lower::tests::structural` checks on real files: the body is in source order,
/// every source instruction is covered, and the operands on an [`IrOp`] are the
/// operands of the instruction they came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    /// The declaring class and identity.
    pub ctx: ClassCtx,
    /// The register file's shape.
    pub frame: Frame,
    /// The incoming-argument window, in register order, each with its class.
    ///
    /// For a non-static method the first entry is the receiver, whose class is
    /// always [`Ty::Object`] and which is **not** named by the signature. So a
    /// one-parameter instance method has a two-entry window and a two-word
    /// `ins_size`; the receiver is a word of the window that the prototype does
    /// not mention. A `void` parameter descriptor, which is malformed input, is
    /// rejected by [`Function::new`].
    pub params: Vec<TypedRegAny>,
    /// The registers that are not in the incoming window, ascending.
    pub locals: Vec<Reg>,
    /// The result type, or [`Ty::Void`].
    pub result: Ty,
    /// The body, in source order.
    pub body: Vec<Inst>,
    /// The protected ranges, in code-item order.
    pub tries: Vec<TryRegion>,
    /// Total code units in the source code item.
    pub units: u32,
}

/// A function that does not describe a possible frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionError {
    /// The signature's parameter list and the frame's incoming-argument window
    /// disagree.
    ///
    /// The window is `ins_size` 32-bit words wide; the prototype's parameters
    /// are one slot each in this IR, with a `long` or a `double` counting two.
    FrameArity {
        /// The window width the code item declares, in words.
        ins_size: u16,
        /// The width the signature implies, in words.
        from_signature: u32,
        /// The signature, for the message.
        signature: String,
    },
    /// The window reaches below register zero.
    FrameWindow {
        /// `ins_size`.
        ins_size: u16,
        /// `registers_size`.
        registers_size: u16,
    },
    /// An instruction names a register outside the register file.
    RegisterOutOfRange {
        /// The offending register.
        reg: Reg,
        /// The register file's size.
        registers_size: u16,
        /// The code-unit offset of the instruction that named it.
        unit: u32,
    },
    /// A label names a code unit outside the code item, or a unit that is not
    /// the start of an instruction.
    BadLabel {
        /// The label.
        label: Label,
        /// What is wrong with it.
        why: &'static str,
    },
    /// A control transfer targets a data payload.
    ///
    /// Only a switch or a `fill-array-data` may name a payload, and only to
    /// read it. Anything else would be a fall-through or a branch into data,
    /// which is what makes a linear sweep's "the widths still add up" test
    /// worthless as a correctness argument.
    LabelIntoPayload {
        /// The label.
        label: Label,
        /// The code-unit offset of the instruction that made the reference.
        unit: u32,
    },
    /// A protected range or a handler address is outside the code item, or the
    /// range is empty.
    BadTryRegion {
        /// The range's start.
        start: u32,
        /// The range's end, inclusive.
        end: u32,
        /// The code item's length in code units.
        units: u32,
    },
    /// A catch-all clause is not last.
    CatchAllNotLast {
        /// The clause's index in its handler list.
        index: usize,
    },
    /// A handler list is empty, which no encoding permits.
    EmptyHandlerList,
    /// The body names a code unit at or past the end of the code item.
    OriginOutOfRange {
        /// The offending origin.
        unit: u32,
        /// The code item's length in code units.
        units: u32,
    },
    /// The body does not start at unit 0, so the first source instruction is
    /// not covered.
    BodyDoesNotStartAtZero,
    /// The origins in the body go backwards, so the body is not in source order.
    OriginsOutOfOrder {
        /// The unit of the offending instruction.
        unit: u32,
        /// The unit of the one before it.
        previous: u32,
    },
    /// A `Word` comparison reads its two operands at different classes, which
    /// the comparison itself does not determine and the input does not permit.
    MixedWordComparison {
        /// The left operand's class, when known.
        left: Option<Ty>,
        /// The right operand's class, when known.
        right: Option<Ty>,
        /// The code-unit offset of the instruction.
        unit: u32,
    },
    /// A `fill-array-data` payload's `element_width * element_count` disagrees
    /// with its byte count.
    FillArrayDataArity {
        /// `element_width * element_count`.
        declared: u64,
        /// The actual byte count.
        actual: usize,
    },
}

impl fmt::Display for FunctionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FunctionError::FrameArity { ins_size, from_signature, signature } => write!(
                f,
                "the incoming-argument window is {ins_size} words but the signature \
                 `{signature}` needs {from_signature}"
            ),
            FunctionError::FrameWindow { ins_size, registers_size } => write!(
                f,
                "an incoming-argument window of {ins_size} words does not fit a \
                 {registers_size}-word register file"
            ),
            FunctionError::RegisterOutOfRange { reg, registers_size, unit } => write!(
                f,
                "{unit}: {reg} is outside a {registers_size}-word register file"
            ),
            FunctionError::BadLabel { label, why } => write!(f, "{label}: {why}"),
            FunctionError::LabelIntoPayload { label, unit } => write!(
                f,
                "{unit}: {label} names a data payload, and only a switch or a \
                 fill-array-data may read one"
            ),
            FunctionError::BadTryRegion { start, end, units } => write!(
                f,
                "protected range {start}..={end} is empty or runs past the {units} \
                 code units of the code item"
            ),
            FunctionError::CatchAllNotLast { index } => {
                write!(f, "the catch-all clause at index {index} is not last")
            }
            FunctionError::EmptyHandlerList => write!(f, "a handler list has no clauses"),
            FunctionError::OriginOutOfRange { unit, units } => {
                write!(f, "{unit}: past the {units} code units of the code item")
            }
            FunctionError::BodyDoesNotStartAtZero => {
                write!(f, "the body does not begin at code unit 0")
            }
            FunctionError::OriginsOutOfOrder { unit, previous } => {
                write!(f, "{unit}: the body goes backwards from {previous}")
            }
            FunctionError::MixedWordComparison { left, right, unit } => write!(
                f,
                "{unit}: a word comparison reads {left:?} and {right:?}; the two \
                 operands are compared as the same 32-bit word"
            ),
            FunctionError::FillArrayDataArity { declared, actual } => write!(
                f,
                "fill-array-data declares {declared} bytes of elements but carries {actual}"
            ),
        }
    }
}

impl std::error::Error for FunctionError {}

impl Function {
    /// Build and validate a function.
    ///
    /// This is the gate the whole compiler's type discipline rests on, so it is
    /// worth being exact about what it does and does not check.
    ///
    /// **Checked here** — anything the IR itself can decide:
    ///
    /// * the signature's parameter list and the frame's incoming-argument
    ///   window describe the same width;
    /// * every register any instruction names is inside the register file;
    /// * every label is inside the code item, and lands on the start of an
    ///   instruction rather than inside one;
    /// * no control transfer targets a data payload, and no payload is a branch
    ///   target except from the switch or `fill-array-data` that reads it;
    /// * protected ranges are non-empty and in bounds, and a catch-all clause is
    ///   last;
    /// * the body starts at code unit 0 and its origins never go backwards;
    /// * a `Word` comparison reads both operands at the same class;
    /// * a `fill-array-data` payload's declared size matches its bytes.
    ///
    /// **Not checked here** — things the IR has no evidence for:
    ///
    /// * *does this register actually hold a `long` here?* That needs a
    ///   verifier, and the contract is explicit that this component does not
    ///   have one. The oracle checks it at run time and reports
    ///   `Malformed::TypeMismatch`; the IR's job is to make the check
    ///   *possible*, which is what the typed register newtypes are for.
    /// * *does every path reach a return?* That needs a control-flow graph, and
    ///   a CFG is a derived product whose shape belongs to whoever consumes it.
    pub fn new(
        ctx: ClassCtx,
        frame: Frame,
        body: Vec<Inst>,
        tries: Vec<TryRegion>,
    ) -> Result<Function, FunctionError> {
        let units = frame.units;

        // ---- the frame and the signature must agree.
        if frame.ins_size > frame.registers_size {
            return Err(FunctionError::FrameWindow {
                ins_size: frame.ins_size,
                registers_size: frame.registers_size,
            });
        }
        let (param_tys, result) = parse_signature(&ctx.signature);
        if let Some(v) = param_tys.iter().position(|t| *t == Ty::Void) {
            return Err(FunctionError::FrameArity {
                ins_size: frame.ins_size,
                from_signature: words_of(&param_tys) + u32::from(!ctx.is_static()),
                signature: format!("{} has `void` at parameter {v}", ctx.signature),
            });
        }
        // The incoming-argument window counts the **receiver** as well as the
        // declared parameters, for an instance method. That is the convention the
        // input uses and it is the one `IR.md` inherits; getting it wrong rejects
        // every instance method in a real APK, because a one-parameter instance
        // method has a two-word window.
        let from_signature = words_of(&param_tys) + u32::from(!ctx.is_static());
        if from_signature != u32::from(frame.ins_size) {
            return Err(FunctionError::FrameArity {
                ins_size: frame.ins_size,
                from_signature,
                signature: ctx.signature.clone(),
            });
        }

        // ---- build the incoming window, receiver first.
        //
        // The receiver is emitted BEFORE the declared parameters, not inside
        // the loop over them. Emitting it on iteration `i == 0` consumed the
        // first declared parameter: for `(Landroid/os/Bundle;)V` on an
        // instance method the window came out as `[this]` alone, so
        // `ins_size == 2` but one word was unaccounted for and every instance
        // method's arguments were off by one.
        let mut params = Vec::with_capacity(param_tys.len() + usize::from(!ctx.is_static()));
        let mut next = frame.first_param();
        if !ctx.is_static() {
            // The receiver is a handle whatever the signature says, and it is
            // the first word of the window.
            params.push(
                TypedRegAny::new(Ty::Object, Reg(next))
                    .unwrap_or(TypedRegAny::Object(ObjectReg::new(next))),
            );
            next += 1;
        }
        for (i, ty) in param_tys.iter().copied().enumerate() {
            match TypedRegAny::new(ty, Reg(next)) {
                Some(p) => params.push(p),
                // `void` was rejected above, so this arm is unreachable; it
                // exists so the function is total rather than panicking.
                None => {
                    return Err(FunctionError::FrameArity {
                        ins_size: frame.ins_size,
                        from_signature,
                        signature: format!("{}: parameter {i} is `void`", ctx.signature),
                    })
                }
            }
            next += ty.slots();
        }
        let locals = (0..frame.first_param()).map(Reg).collect();

        let f = Function { ctx, frame, params, locals, result, body, tries, units };
        f.validate()?;
        Ok(f)
    }

    /// Run every check [`Function::new`] runs, for a function that was already
    /// built. `Function::new` calls it; it is public so that a consumer which
    /// legitimately mutates a body — A2, laying out blocks — can re-check.
    pub fn validate(&self) -> Result<(), FunctionError> {
        let units = self.units;

        // ---- the code units the IR knows how to land on.
        //
        // Two maps, not one. `starts` is the set of units an instruction begins
        // at, which is what a label has to name. `payload_start` and
        // `payload_body` say which of those units are data: a label naming a
        // payload's first unit is only legal from the switch or
        // `fill-array-data` that reads it, and a label naming any unit inside
        // one is never legal, because those units are not instructions.
        let mut starts = vec![false; units as usize];
        let mut payload_start = vec![false; units as usize];
        let mut payload_body = vec![false; units as usize];
        for inst in &self.body {
            let at = inst.origin.unit;
            if at >= units {
                return Err(FunctionError::OriginOutOfRange { unit: at, units });
            }
            starts[at as usize] = true;
            if let IrOp::Payload { payload } = &inst.op {
                payload_start[at as usize] = true;
                let end = at.saturating_add(payload.units()).min(units);
                for slot in payload_body.iter_mut().take(end as usize).skip(at as usize) {
                    *slot = true;
                }
            }
        }
        // Origins must be non-decreasing and start at 0.
        if self.body.first().map(|i| i.origin.unit) != Some(0) && !self.body.is_empty() {
            return Err(FunctionError::BodyDoesNotStartAtZero);
        }
        for w in self.body.windows(2) {
            let (prev, next) = (w[0].origin.unit, w[1].origin.unit);
            if next < prev {
                return Err(FunctionError::OriginsOutOfOrder { unit: next, previous: prev });
            }
        }

        // ---- registers.
        for inst in &self.body {
            for reg in inst.op.reads().into_iter().chain(inst.op.writes()) {
                if reg.0 >= self.frame.registers_size {
                    return Err(FunctionError::RegisterOutOfRange {
                        reg,
                        registers_size: self.frame.registers_size,
                        unit: inst.origin.unit,
                    });
                }
            }
        }

        // ---- labels.
        for inst in &self.body {
            for label in inst.op.labels() {
                let at = label.offset();
                if at >= units {
                    return Err(FunctionError::BadLabel {
                        label,
                        why: "the offset is past the end of the code item",
                    });
                }
                if !starts[at as usize] {
                    return Err(FunctionError::BadLabel {
                        label,
                        why: "the offset is not the start of an instruction",
                    });
                }
                // Only a switch and a fill-array-data may name a payload.
                let reads_a_payload =
                    matches!(inst.op, IrOp::Switch { .. } | IrOp::FillArrayData { .. });
                if payload_start[at as usize] && !reads_a_payload {
                    return Err(FunctionError::LabelIntoPayload {
                        label,
                        unit: inst.origin.unit,
                    });
                }
                if payload_body[at as usize] && !payload_start[at as usize] {
                    return Err(FunctionError::LabelIntoPayload {
                        label,
                        unit: inst.origin.unit,
                    });
                }
            }
        }

        // ---- try regions.
        for region in &self.tries {
            if region.end < region.start || region.end >= units {
                return Err(FunctionError::BadTryRegion {
                    start: region.start,
                    end: region.end,
                    units,
                });
            }
            if region.handlers.is_empty() {
                return Err(FunctionError::EmptyHandlerList);
            }
            for (i, clause) in region.handlers.iter().enumerate() {
                if clause.type_descriptor.is_none() && i + 1 != region.handlers.len() {
                    return Err(FunctionError::CatchAllNotLast { index: i });
                }
                if clause.address >= units || !starts[clause.address as usize] {
                    return Err(FunctionError::BadLabel {
                        label: Label(clause.address),
                        why: "a catch handler must start at an instruction",
                    });
                }
            }
        }

        // ---- payload self-consistency, and word-comparison agreement.
        for inst in &self.body {
            match &inst.op {
                IrOp::Payload { payload } => {
                    if let Payload::FillArrayData { element_width, element_count, data } =
                        &**payload
                    {
                        let declared = u64::from(*element_width) * u64::from(*element_count);
                        if declared != data.len() as u64 {
                            return Err(FunctionError::FillArrayDataArity {
                                declared,
                                actual: data.len(),
                            });
                        }
                    }
                }
                IrOp::BrEq { a, b, .. } | IrOp::BrNe { a, b, .. } => {
                    if let (Some(l), Some(r)) = (a.ty(), b.ty()) {
                        if l != r {
                            return Err(FunctionError::MixedWordComparison {
                                left: Some(l),
                                right: Some(r),
                                unit: inst.origin.unit,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// The number of instructions in the body, including the ones that lowered
    /// to [`IrOp::Unsupported`].
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// True when the body is empty.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Every instruction that did not become a real operation, with its origin.
    pub fn unsupported(&self) -> Vec<Origin> {
        self.body
            .iter()
            .filter(|i| matches!(i.op, IrOp::Unsupported { .. }))
            .map(|i| i.origin)
            .collect()
    }
}

/// Split a prototype descriptor into its parameter types and its result type.
///
/// Total: a descriptor that does not start with `(` is treated as a bare return
/// type with no parameters, which is the same degradation the oracle performs.
/// A malformed descriptor therefore produces a function that fails
/// [`Function::new`]'s arity check with a message, rather than a panic.
pub fn parse_signature(signature: &str) -> (Vec<Ty>, Ty) {
    let Some(rest) = signature.strip_prefix('(') else {
        return (Vec::new(), Ty::of_descriptor(signature));
    };
    let mut params = Vec::new();
    let mut at = 0usize;
    let mut result = Ty::Void;
    while let Some(&byte) = rest.as_bytes().get(at) {
        if byte == b')' {
            result = Ty::of_descriptor(rest.get(at + 1..).unwrap_or(""));
            break;
        }
        let width = descriptor_width(rest, at);
        if width == 0 {
            break;
        }
        params.push(Ty::of_descriptor(rest.get(at..at + width).unwrap_or("")));
        at += width;
    }
    (params, result)
}

/// The number of 32-bit words a parameter list occupies: one per slot, two for
/// `J` and `D`, zero for `void`.
fn words_of(tys: &[Ty]) -> u32 {
    tys.iter().map(|t| u32::from(t.slots())).sum()
}

/// The byte length of the descriptor starting at `at`: one for a primitive, up
/// to and including the `;` for a class, and `[` plus the element for an array.
fn descriptor_width(s: &str, at: usize) -> usize {
    let bytes = s.as_bytes();
    match bytes.get(at) {
        None => 0,
        Some(b'[') => 1 + descriptor_width(s, at + 1),
        Some(b'L') => s.get(at..).and_then(|t| t.find(';')).map(|i| at + i + 1).unwrap_or(0),
        Some(_) => 1,
    }
}
