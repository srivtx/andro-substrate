//! The host ↔ guest boundary.
//!
//! `IR.md` puts a single line in the middle of the whole design:
//!
//! ```ts
//! export type HostImpl = (recv: Handle, args: Handle[]) => Handle | number | bigint;
//! ```
//!
//! and every hard decision in this module comes from reading that line closely
//! and then deciding what it *cannot* mean.
//!
//! # What the boundary is for
//!
//! The guest heap is a bump-allocated region inside the module's linear memory
//! and a handle is a byte offset into it. "The host never dereferences them" is
//! `IR.md`'s rule, and it is not a convention here: [`abi::Handle`] has no
//! `Deref`, no arithmetic and no conversion to or from any number, so the only
//! way to get something dereferenceable out of a handle is
//! [`abi::Handle::require`], which produces a [`abi::NonNullHandle`] — a
//! different type — and the only thing in this module that accepts a
//! `NonNullHandle` is [`HostApi`]. A host implementation physically cannot read
//! guest memory; it has to call the host API, and that call site is where the
//! null check lives.
//!
//! # Totality, which is the actual requirement
//!
//! A hostile DEX can declare any descriptor it likes. Everything here is total
//! over that input, and "total" has a specific meaning in this project: **no
//! panic, no coercion, no silent zero**. An unrecognised or self-inconsistent
//! descriptor produces a [`MarshalError`] carrying a discriminant, the
//! descriptor, the position and a human-readable detail. Not a default value —
//! a default value at this boundary is a wrong program that runs.
//!
//! The three ways that usually goes wrong, and what stops each here:
//!
//! * **A descriptor that does not parse.** [`abi::DexType::parse`] is strict, so
//!   `L`, `[V` and `(I` are errors rather than guesses.
//! * **A value of the wrong shape.** A guest word is a *tagged* union
//!   ([`GuestWord`]), not a raw `i64`, so a `f64` where the prototype declares
//!   `I` is detectable. Passing a bit pattern through unchecked is how an
//!   `f64` becomes an object index.
//! * **A host that returns the wrong type.** [`pack`] checks the host's answer
//!   against the declared return type, and a `number` where a reference is
//!   declared is an error — see
//!   `no_path_moves_a_float_bit_pattern_into_a_handle`.
//!
//! # A comment on `IR.md`, filed rather than applied
//!
//! `IR.md` §"Host stub ABI" types the arguments as `Handle[]`. That is only
//! correct for a method whose parameters are all references: `String.length(I)I`
//! passes an `int`, and `Locale.getDefault()` passes nothing at all. The
//! argument array is heterogeneous — an `i32` is a JS `number`, a `J` must be a
//! `bigint` because a `f64` cannot hold every `i64`, a `F`/`D` is a `number`, and
//! a reference is a `Handle` — so `args` is modelled here as a `Vec<Slot>`, each
//! carrying its declared type alongside the value.
//!
//! `IR.md` asks an agent needing a change to file a comment in its report rather
//! than edit the file, and this is that comment. The recommendation is
//! `args: readonly Slot[]`. Nothing else in the signature is wrong: the receiver
//! genuinely is a `Handle`, and `Handle | number | bigint` genuinely is the right
//! union for a return.
//!
//! # The fabricated value, and where it is labelled
//!
//! The interpreter's answer to an unimplemented host call is "substitute the
//! return type's zero value and carry on", which is the right choice for an
//! instrument and a dangerous one for a compiler. This module does not make
//! that choice: [`Marshaller::call`] returns
//! [`CallOutcome::NotImplemented`] and lets the *caller* decide, because a
//! substituted zero that nobody recorded is exactly the kind of silently wrong
//! answer `IR.md` prohibits, and a recording that claims a host call produced
//! `0` when it produced nothing is worse than one that says so.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

use std::fmt;

use crate::abi::{
    convert, narrow_on_store, AbiValue, Conversion, DexType, Handle, Narrowing, NonNullHandle,
    Notes, Prototype, Wasm,
};

// ================================================================== errors

/// A stable discriminant for every way marshalling can fail.
///
/// Kept as a flat enum rather than a string so that a recording can group
/// failures without parsing prose, and so that adding a case is a compile error
/// at every match rather than a silently unhandled value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MarshalErrorKind {
    /// The descriptor text could not be parsed.
    MalformedDescriptor,
    /// A parameter list that does not agree with the arguments supplied.
    ArityMismatch,
    /// A guest word whose WebAssembly type contradicts the declared type.
    ArgumentTypeMismatch,
    /// A host answer whose JavaScript type contradicts the declared return type.
    ReturnTypeMismatch,
    /// A `number` for an integral return that is not a whole number.
    NotIntegral,
    /// A `number` for an integral return that does not fit the target width.
    OutOfRange,
    /// A `NaN` or infinity offered for an integral return.
    NotFinite,
    /// A null handle where a real object was required.
    NullHandle,
    /// A host API operation that is not available.
    HostApiUnavailable,
    /// A handle whose class does not match the one the operation needs.
    ClassMismatch,
    /// A host method the API does not know.
    NoSuchMember,
    /// Anything the boundary cannot express, named rather than defaulted.
    Unsupported,
}

impl MarshalErrorKind {
    /// A stable, machine-readable name for recordings.
    pub fn as_str(self) -> &'static str {
        match self {
            MarshalErrorKind::MalformedDescriptor => "malformed_descriptor",
            MarshalErrorKind::ArityMismatch => "arity_mismatch",
            MarshalErrorKind::ArgumentTypeMismatch => "argument_type_mismatch",
            MarshalErrorKind::ReturnTypeMismatch => "return_type_mismatch",
            MarshalErrorKind::NotIntegral => "not_integral",
            MarshalErrorKind::OutOfRange => "out_of_range",
            MarshalErrorKind::NotFinite => "not_finite",
            MarshalErrorKind::NullHandle => "null_handle",
            MarshalErrorKind::HostApiUnavailable => "host_api_unavailable",
            MarshalErrorKind::ClassMismatch => "class_mismatch",
            MarshalErrorKind::NoSuchMember => "no_such_member",
            MarshalErrorKind::Unsupported => "unsupported",
        }
    }

    /// Every kind, for a test that checks the text encoding is total over the
    /// whole enumeration rather than over the cases someone remembered.
    pub const ALL: [MarshalErrorKind; 12] = [
        MarshalErrorKind::MalformedDescriptor,
        MarshalErrorKind::ArityMismatch,
        MarshalErrorKind::ArgumentTypeMismatch,
        MarshalErrorKind::ReturnTypeMismatch,
        MarshalErrorKind::NotIntegral,
        MarshalErrorKind::OutOfRange,
        MarshalErrorKind::NotFinite,
        MarshalErrorKind::NullHandle,
        MarshalErrorKind::HostApiUnavailable,
        MarshalErrorKind::ClassMismatch,
        MarshalErrorKind::NoSuchMember,
        MarshalErrorKind::Unsupported,
    ];
}

/// A marshalling failure, with everything a recording needs and nothing that
/// could not survive a round trip through text.
///
/// The fields are ordered `[kind, descriptor, position, detail]` and the text
/// encoding below preserves that order, so a parse of a marshal error is a real
/// inverse rather than an approximation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarshalError {
    /// What went wrong.
    pub kind: MarshalErrorKind,
    /// The descriptor involved, when there was one.
    pub descriptor: Option<String>,
    /// Which argument, parameter or register — `None` when it is not about one.
    pub position: Option<usize>,
    /// A human-readable detail. Never the only carrier of the diagnosis: the
    /// [`MarshalErrorKind`] is what a machine reads.
    pub detail: String,
}

impl MarshalError {
    /// An error with only a kind and a detail.
    pub fn new(kind: MarshalErrorKind, detail: impl Into<String>) -> MarshalError {
        MarshalError {
            kind,
            descriptor: None,
            position: None,
            detail: detail.into(),
        }
    }

    /// Attach the descriptor this error is about.
    pub fn with_descriptor(mut self, d: &DexType) -> MarshalError {
        self.descriptor = Some(d.descriptor());
        self
    }

    /// Attach the descriptor text verbatim, for a descriptor that failed to
    /// parse and so has no [`DexType`].
    pub fn with_raw_descriptor(mut self, d: &str) -> MarshalError {
        self.descriptor = Some(d.to_string());
        self
    }

    /// Attach the position — which argument or parameter.
    pub fn at(mut self, position: usize) -> MarshalError {
        self.position = Some(position);
        self
    }

    /// The stable discriminant.
    pub fn kind(&self) -> MarshalErrorKind {
        self.kind
    }

    /// The discriminant's stable name, for a test that asserts on a category
    /// rather than on a variant.
    pub fn kind_str(&self) -> &'static str {
        self.kind.as_str()
    }

    /// A total, injective text encoding.
    ///
    /// Four fields, each tagged with its own key: `kind`, `at:`, `desc:` and the
    /// trailing detail. The two optional fields carry an explicit `+`/`-` marker
    /// rather than a bare sentinel, because a bare sentinel is not injective —
    /// the fuzzer generated a descriptor of literally `"-"` and it came back as
    /// "absent", which is precisely the kind of quiet data loss a recording
    /// cannot afford. With the marker, `Some("")` encodes as `desc:+` and
    /// `None` as `desc:-`, and every value in between is escaped data.
    ///
    /// Total and injective is the point, and both halves are tested: the fuzzer
    /// generates errors with arbitrary bytes in every field and asserts that
    /// `from_text(to_text(e)) == e`. A recording that cannot be read back is not
    /// a recording.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(self.kind.as_str());
        out.push('|');
        out.push_str("at:");
        match self.position {
            None => out.push('-'),
            Some(p) => {
                out.push('+');
                out.push_str(&p.to_string());
            }
        }
        out.push_str("|desc:");
        match &self.descriptor {
            None => out.push('-'),
            Some(d) => {
                out.push('+');
                escape_into(d, &mut out);
            }
        }
        out.push('|');
        escape_into(&self.detail, &mut out);
        out
    }

    /// The inverse of [`MarshalError::to_text`]. A malformed encoding produces a
    /// `MalformedDescriptor` error rather than a panic, so this is total too.
    ///
    /// The fields are split by a scanner that **respects the escape**, not by
    /// `str::split`. Escaping `|` as `\|` and then splitting on `|` anyway is the
    /// bug this comment exists to prevent: a descriptor containing a `|` — which
    /// a hostile DEX can supply, and which `to_text` promises to escape — would
    /// come back with its fields shifted and the error unparseable. The fuzzer
    /// found it; `a_marshal_error_round_trips_through_its_text_encoding` is what
    /// keeps it fixed.
    pub fn from_text(text: &str) -> Result<MarshalError, MarshalError> {
        let bad = |why: &str| {
            MarshalError::new(
                MarshalErrorKind::MalformedDescriptor,
                format!("marshal error text is not parseable: {why}"),
            )
            .with_raw_descriptor(text)
        };
        let mut fields: Vec<String> = Vec::with_capacity(3);
        let mut cur = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => match chars.next() {
                    Some(escaped) => cur.push(escaped),
                    None => return Err(bad("a dangling escape")),
                },
                // An *unescaped* `|` is always a separator, because `to_text`
                // escapes every `|` that is data. A fifth field therefore means
                // the text was not produced by `to_text`, which is an error
                // rather than something to guess at.
                '|' => {
                    if fields.len() == 3 {
                        return Err(bad("too many fields"));
                    }
                    fields.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
        if fields.len() != 3 {
            return Err(bad("expected four fields"));
        }
        let kind = MarshalErrorKind::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == fields[0])
            .ok_or_else(|| bad("unknown kind"))?;
        let position_field = fields[1]
            .strip_prefix("at:")
            .ok_or_else(|| bad("the position field is not tagged"))?;
        let position = match position_field {
            "-" => None,
            rest => match rest.strip_prefix('+') {
                None => return Err(bad("the position field has no presence marker")),
                Some(digits) => Some(
                    digits
                        .parse::<usize>()
                        .map_err(|_| bad("position is not a number"))?,
                ),
            },
        };
        let descriptor_field = fields[2]
            .strip_prefix("desc:")
            .ok_or_else(|| bad("the descriptor field is not tagged"))?;
        let descriptor = match descriptor_field {
            "-" => None,
            rest => match rest.strip_prefix('+') {
                None => return Err(bad("the descriptor field has no presence marker")),
                Some(text) => Some(text.to_string()),
            },
        };
        Ok(MarshalError {
            kind,
            descriptor,
            position,
            detail: cur,
        })
    }
}

fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '|' => out.push_str("\\|"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
}

impl fmt::Display for MarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind.as_str())?;
        if let Some(d) = &self.descriptor {
            write!(f, " [{d}]")?;
        }
        if let Some(p) = self.position {
            write!(f, " at {p}")?;
        }
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for MarshalError {}

impl From<crate::abi::AbiError> for MarshalError {
    /// An ABI failure becomes a marshalling failure with the same information.
    /// Nothing is flattened to a string, because the discriminant is what a
    /// recording groups on.
    fn from(e: crate::abi::AbiError) -> MarshalError {
        let kind = match &e {
            crate::abi::AbiError::DescriptorEmpty
            | crate::abi::AbiError::UnterminatedClass { .. }
            | crate::abi::AbiError::EmptyClassName
            | crate::abi::AbiError::InvalidByte { .. }
            | crate::abi::AbiError::TrailingBytes { .. }
            | crate::abi::AbiError::ArrayOfVoid
            | crate::abi::AbiError::ArrayDepthExceeded { .. } => {
                MarshalErrorKind::MalformedDescriptor
            }
            crate::abi::AbiError::MissingOpenParenthesis
            | crate::abi::AbiError::UnclosedParameterList
            | crate::abi::AbiError::VoidParameter { .. }
            | crate::abi::AbiError::TooManyParameters { .. } => {
                MarshalErrorKind::MalformedDescriptor
            }
            crate::abi::AbiError::ValueTypeMismatch { .. } => {
                MarshalErrorKind::ArgumentTypeMismatch
            }
            crate::abi::AbiError::NoConversion { .. } => MarshalErrorKind::ArgumentTypeMismatch,
            crate::abi::AbiError::NullHandle { .. } => MarshalErrorKind::NullHandle,
            crate::abi::AbiError::VarargsOutOfBounds { .. } => MarshalErrorKind::ArityMismatch,
        };
        MarshalError {
            kind,
            descriptor: e.kind().split('_').next().map(|_| None).unwrap_or(None),
            position: None,
            detail: e.to_string(),
        }
    }
}

/// Result alias for anything in this module that can fail on untrusted input.
pub type MarshalResult<T> = Result<T, MarshalError>;

// ============================================================== guest words

/// One WebAssembly value as the guest hands it over.
///
/// A tagged union, and that is the whole design: a `codegen` reads a stack slot
/// according to the *declared* type, and if it read the wrong one there is no
/// way to tell from an untyped `i64` — a `f64` and an `i32` have the same
/// width and no common bit pattern that would flag the mistake. Tagging makes
/// the mistake detectable, which turns a silent reinterpretation into a
/// [`MarshalErrorKind::ArgumentTypeMismatch`].
///
/// `Void` is present so a `void` method's (absent) result is representable
/// without an `Option` at every call site.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum GuestWord {
    /// `i32` — also `Z B S C I` and every handle.
    I32(i32),
    /// `i64` — `J`.
    I64(i64),
    /// `f32` — `F`.
    F32(f32),
    /// `f64` — `D`.
    F64(f64),
    /// No value: a `void` result.
    Void,
}

impl GuestWord {
    /// The WebAssembly type this word occupies, or `None` for `Void`.
    pub fn wasm_ty(&self) -> Option<Wasm> {
        Some(match self {
            GuestWord::I32(_) => Wasm::I32,
            GuestWord::I64(_) => Wasm::I64,
            GuestWord::F32(_) => Wasm::F32,
            GuestWord::F64(_) => Wasm::F64,
            GuestWord::Void => return None,
        })
    }

    /// A short name for diagnostics.
    pub fn type_name(&self) -> &'static str {
        match self {
            GuestWord::I32(_) => "i32",
            GuestWord::I64(_) => "i64",
            GuestWord::F32(_) => "f32",
            GuestWord::F64(_) => "f64",
            GuestWord::Void => "void",
        }
    }

    /// The `i32` payload, or `None` for the other three types and for `Void`.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            GuestWord::I32(i) => Some(*i),
            _ => None,
        }
    }
}

// ============================================================== host values

/// A value on the host side of the boundary.
///
/// This is the union `IR.md` names as `Handle | number | bigint`, split by
/// width so that a `J` cannot be silently carried as a `number` — a `f64` holds
/// 53 bits of significand and an `i64` needs 63, so a `long` returned as a JS
/// `number` is already wrong before any code looks at it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HostValue {
    /// A 32-bit integer: `Z B S C I`. Also a JS `number` for a `F`/`D` that
    /// happens to be integral — see [`HostValue::from_number`].
    Int(i32),
    /// A 64-bit integer: `J`. A JS `bigint`, never a `number`.
    Long(i64),
    /// A `float`. Bit-exact, so a `NaN` payload survives the crossing.
    Float(f32),
    /// A `double`. Bit-exact.
    Double(f64),
    /// A reference. Opaque, and not dereferenceable from here.
    Ref(Handle),
}

impl HostValue {
    /// The JS type name, for a recording. `number` covers `Z B S C I F D`;
    /// `bigint` is `J`; `Handle` is a reference.
    pub fn js_type(&self) -> &'static str {
        match self {
            HostValue::Int(_) | HostValue::Float(_) | HostValue::Double(_) => "number",
            HostValue::Long(_) => "bigint",
            HostValue::Ref(_) => "Handle",
        }
    }

    /// The value as a JS `number`, where that is representable. `None` for a
    /// `J` and for a `Handle`, because neither is a `number` and pretending
    /// otherwise is the bug this module exists to prevent.
    pub fn as_number(&self) -> Option<f64> {
        match self {
            HostValue::Int(i) => Some(f64::from(*i)),
            HostValue::Float(f) => Some(f64::from(*f)),
            HostValue::Double(d) => Some(*d),
            HostValue::Long(_) | HostValue::Ref(_) => None,
        }
    }

    /// The value as a JS `bigint`, where that is the right type. `None`
    /// otherwise.
    pub fn as_bigint(&self) -> Option<i64> {
        match self {
            HostValue::Long(l) => Some(*l),
            _ => None,
        }
    }

    /// The handle, if this is one.
    pub fn as_handle(&self) -> Option<Handle> {
        match self {
            HostValue::Ref(h) => Some(*h),
            _ => None,
        }
    }
}

/// One argument, with the type it was declared as.
///
/// The declared type travels with the value because the value alone is not
/// enough: a host receiving `65` cannot tell a `char` from an `int` from a
/// `short`, and `String.charAt(65)` is a different call from `substring(65)`.
#[derive(Clone, Debug, PartialEq)]
pub struct Slot {
    /// The declared DEX type.
    pub ty: DexType,
    /// The value.
    pub value: HostValue,
    /// What the crossing did to the value, if anything.
    pub notes: Notes,
}

impl Slot {
    /// A slot with no recorded transformation.
    pub fn new(ty: DexType, value: HostValue) -> Slot {
        Slot {
            ty,
            value,
            notes: Notes::default(),
        }
    }

    /// The JS type name of this slot's value.
    pub fn js_type(&self) -> &'static str {
        self.value.js_type()
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.ty, self.value.js_type())
    }
}

// ================================================================ unpack

/// A call ready to be handed to a host implementation.
#[derive(Clone, Debug, PartialEq)]
pub struct HostCall {
    /// The receiver. Always a handle; `0` for a static method and for a
    /// `null` receiver.
    pub recv: Handle,
    /// The prototype's parameters, in order, receiver excluded.
    pub args: Vec<Slot>,
    /// Whether the method is static, which is what tells a host impl that
    /// `recv` carries no meaning.
    pub is_static: bool,
}

impl HostCall {
    /// The descriptor of the whole prototype, for an error message.
    pub fn prototype(&self) -> Prototype {
        Prototype {
            params: self.args.iter().map(|s| s.ty.clone()).collect(),
            ret: DexType::Void,
        }
    }

    /// Argument `i`, or `None` rather than a panic.
    pub fn arg(&self, i: usize) -> Option<&Slot> {
        self.args.get(i)
    }
}

/// Unpack a guest call into host values.
///
/// Total over every input, including descriptors that never parsed. The checks
/// in order, and each one is a failure mode rather than a formality:
///
/// 1. the word count matches the prototype, receiver included — a mismatch here
///    is a `codegen` bug, and reporting it beats reading past the end;
/// 2. each word's WebAssembly type matches the declared type's, so an `f64`
///    where an `I` is declared is an error rather than a bit pattern
///    reinterpreted as an index;
/// 3. the value is put through the *tested* conversion matrix, so a `Z`
///    arriving as 42 is folded to 0 and the folding is recorded, and a `B` whose
///    register was not narrowed is narrowed here rather than trusted.
pub fn unpack(
    proto: &Prototype,
    is_static: bool,
    recv: GuestWord,
    words: &[GuestWord],
) -> MarshalResult<HostCall> {
    let want = proto.params.len() + usize::from(!is_static);
    if words.len() != want {
        return Err(MarshalError::new(
            MarshalErrorKind::ArityMismatch,
            format!(
                "prototype declares {want} registers, {words_len} were supplied",
                words_len = words.len()
            ),
        )
        .with_raw_descriptor(&proto.descriptor()));
    }

    let mut at = 0usize;
    let receiver = if is_static {
        Handle::NULL
    } else {
        let h = match recv {
            GuestWord::I32(bits) => Handle::from_bits(bits as u32),
            other => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArgumentTypeMismatch,
                    format!("a receiver is an i32 handle, not {}", other.type_name()),
                )
                .at(0)
                .with_raw_descriptor(&proto.descriptor()))
            }
        };
        at += 1;
        h
    };

    let mut args = Vec::with_capacity(proto.params.len());
    for (i, ty) in proto.params.iter().enumerate() {
        let word = match words.get(at) {
            Some(w) => *w,
            None => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArityMismatch,
                    "ran out of registers",
                )
                .at(i)
                .with_descriptor(ty))
            }
        };
        at += 1;
        args.push(unpack_one(ty, word, i)?);
    }

    Ok(HostCall {
        recv: receiver,
        args,
        is_static,
    })
}

/// The per-argument half of [`unpack`].
fn unpack_one(ty: &DexType, word: GuestWord, i: usize) -> MarshalResult<Slot> {
    // (2) The declared type's WebAssembly type must be the one the guest read.
    // A `void` parameter is not a type, and a descriptor that reached here with
    // one would be a `Prototype::parse` bug rather than a DEX bug; it is
    // reported rather than assumed away.
    let declared_wasm = ty.wasm_ty();
    let got_wasm = word.wasm_ty();
    if declared_wasm != got_wasm {
        return Err(MarshalError::new(
            MarshalErrorKind::ArgumentTypeMismatch,
            format!(
                "declared {} needs {}, the guest supplied {}",
                ty,
                match declared_wasm {
                    Some(w) => w.to_string(),
                    None => "no value".to_string(),
                },
                word.type_name()
            ),
        )
        .at(i)
        .with_descriptor(ty));
    }

    // (3) Put the raw word through the conversion matrix. The word is offered as
    // the *widest* int-family type, because that is what an `i32` register is
    // before the declared type's truncation is applied, and the matrix is the
    // thing that was checked against the interpreter.
    let (raw, conv): (AbiValue, Conversion) = match word {
        GuestWord::I32(bits) => match ty {
            // A reference *is* an `i32`: a byte offset into the guest heap. This
            // is the one place a number becomes a handle, and it happens here
            // and only here, from a value the declared type already said was a
            // reference.
            DexType::Ref(_) | DexType::Array(_) => {
                let h = Handle::from_bits(bits as u32);
                (
                    AbiValue::Ref(h),
                    Conversion {
                        value: AbiValue::Ref(h),
                        notes: Notes::default(),
                    },
                )
            }
            DexType::Long | DexType::Float | DexType::Double => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArgumentTypeMismatch,
                    format!("declared {ty}, which is not an i32 type, but the register holds one"),
                )
                .at(i)
                .with_descriptor(ty))
            }
            _ => {
                let from = DexType::Int;
                let c = convert(&from, ty, AbiValue::Int(bits))?;
                (c.value, c)
            }
        },
        GuestWord::I64(bits) => match ty {
            DexType::Long => (
                AbiValue::Long(bits),
                Conversion {
                    value: AbiValue::Long(bits),
                    notes: Notes::default(),
                },
            ),
            _ => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArgumentTypeMismatch,
                    format!("declared {ty} but the register holds an i64"),
                )
                .at(i)
                .with_descriptor(ty))
            }
        },
        GuestWord::F32(bits) => match ty {
            DexType::Float => (
                AbiValue::Float(bits),
                Conversion {
                    value: AbiValue::Float(bits),
                    notes: Notes::default(),
                },
            ),
            _ => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArgumentTypeMismatch,
                    format!("declared {ty} but the register holds an f32"),
                )
                .at(i)
                .with_descriptor(ty))
            }
        },
        GuestWord::F64(bits) => match ty {
            DexType::Double => (
                AbiValue::Double(bits),
                Conversion {
                    value: AbiValue::Double(bits),
                    notes: Notes::default(),
                },
            ),
            _ => {
                return Err(MarshalError::new(
                    MarshalErrorKind::ArgumentTypeMismatch,
                    format!("declared {ty} but the register holds an f64"),
                )
                .at(i)
                .with_descriptor(ty))
            }
        },
        GuestWord::Void => {
            return Err(MarshalError::new(
                MarshalErrorKind::ArgumentTypeMismatch,
                format!("declared {ty} but there is no value"),
            )
            .at(i)
            .with_descriptor(ty))
        }
    };

    let value = host_value_of(&raw);
    Ok(Slot {
        ty: ty.clone(),
        value,
        notes: conv.notes,
    })
}

/// The host representation of an [`AbiValue`], which is the union `IR.md` names.
fn host_value_of(v: &AbiValue) -> HostValue {
    match v {
        AbiValue::Void => HostValue::Int(0),
        AbiValue::Boolean(b) => HostValue::Int(b.as_i32()),
        AbiValue::Byte(x) => HostValue::Int(i32::from(*x)),
        AbiValue::Short(x) => HostValue::Int(i32::from(*x)),
        AbiValue::Char(x) => HostValue::Int(i32::from(*x)),
        AbiValue::Int(i) => HostValue::Int(*i),
        AbiValue::Long(l) => HostValue::Long(*l),
        AbiValue::Float(f) => HostValue::Float(*f),
        AbiValue::Double(d) => HostValue::Double(*d),
        AbiValue::Ref(h) => HostValue::Ref(*h),
    }
}

// ================================================================== pack

/// What a host implementation returned.
///
/// Deliberately narrower than [`HostValue`]: `IR.md`'s signature is
/// `Handle | number | bigint`, and this keeps the three apart so that
/// [`pack`] can check the declared return type against what actually arrived
/// rather than against a number it has already flattened.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HostReturn {
    /// A JS `number`: an `i32`, a `F` or a `D`.
    Number(f64),
    /// A JS `bigint`: a `J`.
    BigInt(i64),
    /// A `Handle`.
    Handle(Handle),
    /// Nothing — a `void` method, or an explicit "I do not implement this".
    Nothing,
}

/// A packed result, and what repacking did to it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Packed {
    /// The value, or `None` for a `void` method.
    pub word: Option<GuestWord>,
    /// What the crossing did.
    pub notes: PackNotes,
}

/// What repacking did to a host's answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackNotes {
    /// A value was returned for a `void` method and discarded. Recorded rather
    /// than treated as an error, because a JavaScript function cannot be
    /// prevented from returning and the value genuinely has nowhere to go.
    pub discarded_return: bool,
    /// A `Z` outside `{0, 1}` was folded on the way out.
    pub boolean_normalised: bool,
    /// A value was truncated to fit the declared return type.
    pub narrowed: Option<Narrowing>,
}

/// Repack a host's answer into a guest word.
///
/// Total, and the interesting rejections are all here:
///
/// * a `number` where a reference is declared is a [`ReturnTypeMismatch`]. This
///   is the direction a `f64` bit pattern would take to become an object index,
///   and it is refused rather than reinterpreted;
/// * a `Handle` where a numeric type is declared is a `ReturnTypeMismatch` for
///   the same reason in the other direction;
/// * a `NaN` or infinity for an integral return is a
///   [`MarshalErrorKind::NotFinite`], **not** the `0` that
///   `float-to-int` produces. The `0` is the *conversion opcode's* answer for a
///   value the guest itself computed; a host handing back a `NaN` for a method
///   declared `I` is a bug in the host, and reporting it is the only way it gets
///   fixed;
/// * a non-integral or out-of-range `number` for an integral return is
///   `NotIntegral` or `OutOfRange`, never a silent truncation.
pub fn pack(ret: &DexType, host: HostReturn) -> MarshalResult<Packed> {
    let word = match (ret, host) {
        (DexType::Void, HostReturn::Nothing) => None,
        (DexType::Void, _) => {
            return Ok(Packed {
                word: None,
                notes: PackNotes {
                    discarded_return: true,
                    ..PackNotes::default()
                },
            })
        }
        (_, HostReturn::Nothing) => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                format!("declared {ret} but the host returned nothing"),
            )
            .with_descriptor(ret))
        }

        // --- references: a Handle or nothing ------------------------------
        (t, HostReturn::Handle(h)) if t.is_reference() => {
            // A handle is an `i32` and crosses as one. Note that the *only*
            // constructor on this path is the host's own `Handle` value, so a
            // `f64` cannot arrive here however the host was written.
            return Ok(Packed {
                word: Some(GuestWord::I32(h.bits() as i32)),
                notes: PackNotes::default(),
            });
        }
        (t, HostReturn::Number(_)) if t.is_reference() => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                format!(
                    "declared {t}: a number is not a reference, and no bit \\
                          pattern is reinterpreted as one"
                ),
            )
            .with_descriptor(t))
        }
        (t, HostReturn::BigInt(_)) if t.is_reference() => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                format!("declared {t}: a bigint is not a reference"),
            )
            .with_descriptor(t))
        }

        // --- a handle where a number is declared ---------------------------
        (t, HostReturn::Handle(_)) => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                format!("declared {t}, which is not a reference, but the host returned a Handle"),
            )
            .with_descriptor(t))
        }

        // --- J: a bigint. A `number` is refused, not widened ---------------
        (DexType::Long, HostReturn::BigInt(l)) => Some(GuestWord::I64(l)),
        (DexType::Long, HostReturn::Number(_)) => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                "a long crosses as a bigint, never as a number: a double holds 53 \\
                 significand bits and a long needs 63, so every value past 2^53 \\
                 would come back wrong",
            )
            .with_descriptor(ret))
        }

        // --- the int family: a whole number that fits the declared width ----
        (t, HostReturn::Number(n)) if t.is_int_family() => {
            if n.is_nan() {
                return Err(MarshalError::new(
                    MarshalErrorKind::NotFinite,
                    "a NaN for an integral return is a host bug, not the 0 that \\
                     float-to-int produces for a value the guest itself computed",
                )
                .with_descriptor(t));
            }
            if !n.is_finite() {
                return Err(MarshalError::new(
                    MarshalErrorKind::NotFinite,
                    "an infinity for an integral return does not fit any width",
                )
                .with_descriptor(t));
            }
            if n.fract() != 0.0 {
                return Err(MarshalError::new(
                    MarshalErrorKind::NotIntegral,
                    format!("{n} is not a whole number"),
                )
                .with_descriptor(t));
            }
            // The range is the *declared* width, not the widest one, so a method
            // declared `(B)I` returning 300 is reported rather than narrowed to
            // 44. A host that wants to truncate says so in its own code.
            let (lo, hi) = int_bounds(t);
            if n < f64::from(lo) || n > f64::from(hi) {
                return Err(MarshalError::new(
                    MarshalErrorKind::OutOfRange,
                    format!("{n} is outside {lo}..={hi}, the range of {t}"),
                )
                .with_descriptor(t));
            }
            // Put the whole number through the *tested* store coercion, so a
            // `char` returning 0xFFFF arrives as 65535 and a `byte` returning
            // 0xFF arrives as -1 — identical to a guest-side store, which is the
            // property that stops the two sides disagreeing.
            let stored = narrow_on_store(t, AbiValue::Int(n as i32));
            let final_i = match host_value_of(&stored) {
                HostValue::Int(v) => v,
                // Unreachable: `narrow_on_store` into an int-family type always
                // yields an int. Reported rather than assumed, because a
                // fallback `0` here would be exactly the silent zero this
                // module refuses everywhere else.
                _ => {
                    return Err(MarshalError::new(
                        MarshalErrorKind::ReturnTypeMismatch,
                        format!("narrowing a whole number into {t} did not produce an integer"),
                    )
                    .with_descriptor(t))
                }
            };
            return Ok(Packed {
                word: Some(GuestWord::I32(final_i)),
                notes: PackNotes {
                    boolean_normalised: t == &DexType::Boolean && !matches!(final_i, 0 | 1),
                    narrowed: int_narrowing(t),
                    ..PackNotes::default()
                },
            });
        }

        // --- F and D: a number, exactly ------------------------------------
        (DexType::Float, HostReturn::Number(n)) => Some(GuestWord::F32(n as f32)),
        (DexType::Double, HostReturn::Number(n)) => Some(GuestWord::F64(n)),

        (t, other) => {
            return Err(MarshalError::new(
                MarshalErrorKind::ReturnTypeMismatch,
                format!("declared {t}, the host returned {}", return_name(other)),
            )
            .with_descriptor(t))
        }
    };

    Ok(Packed {
        word,
        notes: PackNotes::default(),
    })
}

fn return_name(r: HostReturn) -> &'static str {
    match r {
        HostReturn::Number(_) => "a number",
        HostReturn::BigInt(_) => "a bigint",
        HostReturn::Handle(_) => "a Handle",
        HostReturn::Nothing => "nothing",
    }
}

/// The inclusive value range of an int-family type, in `i32` terms.
fn int_bounds(t: &DexType) -> (i32, i32) {
    match t {
        DexType::Boolean => (0, 1),
        DexType::Byte => (i32::from(i8::MIN), i32::from(i8::MAX)),
        DexType::Short => (i32::from(i16::MIN), i32::from(i16::MAX)),
        DexType::Char => (0, 65535),
        _ => (i32::MIN, i32::MAX),
    }
}

/// Which truncation a repack into an int-family type performs, if any.
///
/// `I` truncates nothing, and `Z` folds to the low bit — which the range check
/// above has already made impossible, so the flag is `false` for every value
/// that reaches here. It is still reported, because a flag that is always
/// false is a claim that should be visible rather than implied.
fn int_narrowing(t: &DexType) -> Option<Narrowing> {
    match t {
        DexType::Byte => Some(Narrowing::Byte),
        DexType::Short => Some(Narrowing::Short),
        DexType::Char => Some(Narrowing::Char),
        DexType::Boolean => Some(Narrowing::Boolean),
        _ => None,
    }
}

// ============================================================== the host API

/// The only way a host can see what a handle points at.
///
/// Every method takes a [`NonNullHandle`], which is the mechanism behind "the
/// host never dereferences them": a `Handle` is not enough to call any of them,
/// so a host implementation that has a `null` handle cannot read a field by
/// accident. It has to ask, and the answer is a `Result`.
pub trait HostApi {
    /// The descriptor of an object's class.
    fn class_of(&self, object: NonNullHandle) -> String;

    /// Read a field.
    fn field(&mut self, object: NonNullHandle, name: &str) -> MarshalResult<HostValue>;

    /// Call a method on an object.
    fn invoke(
        &mut self,
        object: NonNullHandle,
        name: &str,
        args: &[Slot],
    ) -> MarshalResult<HostValue>;
}

/// The handle a host implementation holds, plus the API it must go through.
///
/// A host implementation receives this rather than a bare `Handle`, so the only
/// thing it can do with a reference is ask the API about it. That is the whole
/// point of the type: forgetting the null check is not possible, because
/// [`HostCtx::object`] is the only door and it returns a `Result`.
pub struct HostCtx<'a> {
    api: &'a mut dyn HostApi,
    recv: Handle,
    call: &'a HostCall,
}

impl fmt::Debug for HostCtx<'_> {
    /// Hand-written because the API is a trait object, and a `Debug` bound on
    /// [`HostApi`] would be a requirement on every host implementation for the
    /// sake of this one line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostCtx")
            .field("recv", &self.recv)
            .field("args", &self.call.args)
            .field("is_static", &self.call.is_static)
            .finish()
    }
}

impl<'a> HostCtx<'a> {
    /// Wrap an API and a call.
    pub fn new(api: &'a mut dyn HostApi, call: &'a HostCall) -> HostCtx<'a> {
        HostCtx {
            api,
            recv: call.recv,
            call,
        }
    }

    /// The receiver as a handle. Not dereferenceable — see [`HostCtx::object`].
    pub fn receiver(&self) -> Handle {
        self.recv
    }

    /// The call's arguments.
    pub fn args(&self) -> &'a [Slot] {
        &self.call.args
    }

    /// Argument `i`, or `None`.
    pub fn arg(&self, i: usize) -> Option<&'a Slot> {
        self.call.args.get(i)
    }

    /// The door. A null receiver is a [`MarshalErrorKind::NullHandle`], which is
    /// what turns a missed check into a report rather than a read at offset 0.
    pub fn object(&self, what: &'static str) -> MarshalResult<NonNullHandle> {
        self.recv
            .require(what)
            .map_err(|_| MarshalError::new(MarshalErrorKind::NullHandle, what))
    }

    /// The descriptor of the receiver's class.
    pub fn receiver_class(&self) -> MarshalResult<String> {
        Ok(self.api.class_of(self.object("receiver class")?))
    }

    /// Read a field of the receiver.
    pub fn field(&mut self, name: &str) -> MarshalResult<HostValue> {
        let h = self.object("field access")?;
        self.api.field(h, name)
    }

    /// Call a method on the receiver.
    pub fn invoke(&mut self, name: &str, args: &[Slot]) -> MarshalResult<HostValue> {
        let h = self.object("method call")?;
        self.api.invoke(h, name, args)
    }
}

/// What a host implementation is: the `HostImpl` of `IR.md`, with the argument
/// array typed as the `Slot`s this module actually produces.
pub trait HostImpl {
    /// Answer a call, or decline it.
    ///
    /// Returning `Err` is a typed refusal that the caller records; it is not an
    /// app-visible exception, because the host is the substrate and a refusal
    /// here is a *finding*, not a behaviour of the program under test.
    fn call(&mut self, ctx: &mut HostCtx<'_>) -> MarshalResult<HostReturn>;
}

// ============================================================== marshaller

/// The result of one boundary crossing.
#[derive(Clone, Debug, PartialEq)]
pub enum CallOutcome {
    /// The host answered, and the answer packed.
    Value(Packed),
    /// The host declined. The caller decides what that means; this module does
    /// not substitute a zero on its own, because a zero nobody recorded is a
    /// silently wrong program.
    NotImplemented,
    /// The host raised a typed error.
    Refused(MarshalError),
}

/// A prototype plus the API its implementations call through.
pub struct Marshaller<'a> {
    proto: Prototype,
    is_static: bool,
    api: &'a mut dyn HostApi,
}

impl fmt::Debug for Marshaller<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Marshaller")
            .field("proto", &self.proto.descriptor())
            .field("is_static", &self.is_static)
            .finish()
    }
}

impl<'a> Marshaller<'a> {
    /// Bind a prototype to a host API.
    pub fn new(proto: Prototype, is_static: bool, api: &'a mut dyn HostApi) -> Marshaller<'a> {
        Marshaller {
            proto,
            is_static,
            api,
        }
    }

    /// The prototype.
    pub fn prototype(&self) -> &Prototype {
        &self.proto
    }

    /// Unpack, dispatch and repack.
    pub fn call(
        &mut self,
        recv: GuestWord,
        words: &[GuestWord],
        impl_: &mut dyn HostImpl,
    ) -> CallOutcome {
        let call = match unpack(&self.proto, self.is_static, recv, words) {
            Ok(c) => c,
            Err(e) => return CallOutcome::Refused(e),
        };
        let mut ctx = HostCtx::new(self.api, &call);
        match impl_.call(&mut ctx) {
            Ok(HostReturn::Nothing) => CallOutcome::NotImplemented,
            Ok(answer) => match pack(&self.proto.ret, answer) {
                Ok(p) => CallOutcome::Value(p),
                Err(e) => CallOutcome::Refused(e),
            },
            Err(e) => CallOutcome::Refused(e),
        }
    }

    /// The zero value for a type, for the caller that decides
    /// [`CallOutcome::NotImplemented`] should continue.
    ///
    /// A named function rather than a literal at the call site, so that a
    /// recording of a substituted value can point at where the value came from.
    pub fn zero_for_ret(&self) -> GuestWord {
        match AbiValue::zero_of(&self.proto.ret) {
            None | Some(AbiValue::Void) => GuestWord::Void,
            Some(v) => match host_value_of(&v) {
                HostValue::Int(i) => GuestWord::I32(i),
                HostValue::Long(l) => GuestWord::I64(l),
                HostValue::Float(f) => GuestWord::F32(f),
                HostValue::Double(d) => GuestWord::F64(d),
                HostValue::Ref(h) => GuestWord::I32(h.bits() as i32),
            },
        }
    }
}

// =================================================================== tests

#[cfg(test)]
mod tests {
    // The crate forbids `unwrap` on anything that came out of a file, and that
    // ban is what keeps a malformed DEX from killing the process. It has no
    // business in a test: every value unwrapped below was built by the test
    // itself, and a test that cannot reach its own fixture should fail loudly
    // rather than contort itself around a value it has already proven.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::abi::Bool;

    /// A deterministic PRNG, so a failing case is reproducible and the crate
    /// needs no dependency it has no business having.
    ///
    /// xorshift64*: not cryptographic and not trying to be. What a test needs is
    /// that a seed reproduces a run, which `cargo test` needs far more than
    /// unpredictability does.
    struct Rng(u64);

    impl Rng {
        fn new(seed: u64) -> Rng {
            Rng(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % (n as u64)) as usize
        }
        /// A byte, biased towards the characters that appear in descriptors so
        /// that a random string is usually *nearly* a descriptor rather than
        /// uniformly noise.
        fn descriptor_byte(&mut self) -> u8 {
            const LIKELY: &[u8] = b"ZBSCIJFDLV[]();/0123456789_-\\ ";
            match self.below(4) {
                0 => LIKELY[self.below(LIKELY.len())],
                _ => (self.next_u64() & 0xff) as u8,
            }
        }
    }

    fn proto(text: &str) -> Prototype {
        Prototype::parse(text).unwrap_or_else(|e| panic!("`{text}`: {e}"))
    }

    fn js_type_of(ty: &DexType) -> &'static str {
        match ty {
            DexType::Long => "bigint",
            DexType::Ref(_) | DexType::Array(_) => "Handle",
            _ => "number",
        }
    }

    // ------------------------------------------------------ descriptor classes

    /// Every descriptor class crosses the boundary and arrives as the JS type
    /// `IR.md`'s `Handle | number | bigint` union implies for it. A `J` as a
    /// `number` is the failure this table exists to prevent, so each parameter
    /// is checked against *its own* declared type rather than against a single
    /// expectation for the signature.
    #[test]
    fn every_descriptor_class_crosses_as_the_right_js_type() {
        let cases: &[(&str, Vec<GuestWord>)] = &[
            ("(Z)V", vec![GuestWord::I32(1)]),
            ("(B)V", vec![GuestWord::I32(-1)]),
            ("(S)V", vec![GuestWord::I32(-1)]),
            ("(C)V", vec![GuestWord::I32(65535)]),
            ("(I)V", vec![GuestWord::I32(-1)]),
            ("(J)V", vec![GuestWord::I64(-1)]),
            ("(F)V", vec![GuestWord::F32(1.5)]),
            ("(D)V", vec![GuestWord::F64(1.5)]),
            ("(Ljava/lang/Object;)V", vec![GuestWord::I32(8)]),
            ("([I)V", vec![GuestWord::I32(8)]),
            ("([[Ljava/lang/String;)V", vec![GuestWord::I32(8)]),
            (
                "(I[IJFDLjava/lang/Object;)V",
                vec![
                    GuestWord::I32(1),
                    GuestWord::I32(8),
                    GuestWord::I64(2),
                    GuestWord::F32(3.0),
                    GuestWord::F64(4.0),
                    GuestWord::I32(9),
                ],
            ),
        ];
        for (sig, words) in cases {
            let p = proto(sig);
            let call =
                unpack(&p, true, GuestWord::I32(0), words).unwrap_or_else(|e| panic!("{sig}: {e}"));
            assert_eq!(call.args.len(), p.params.len(), "{sig}");
            for (i, slot) in call.args.iter().enumerate() {
                assert_eq!(slot.js_type(), js_type_of(&p.params[i]), "{sig} arg {i}");
                assert_eq!(slot.ty, p.params[i], "{sig} arg {i} keeps its type");
            }
        }
    }

    /// A `J` crosses as a `bigint` and comes back as one. A `f64` has 53
    /// significand bits and an `i64` needs 63, so a long carried as a number is
    /// already wrong before anything reads it.
    #[test]
    fn a_long_crosses_as_a_bigint_and_never_as_a_number() {
        let p = proto("(J)J");
        let call = unpack(&p, true, GuestWord::I32(0), &[GuestWord::I64(i64::MIN)]).unwrap();
        assert_eq!(call.args[0].value, HostValue::Long(i64::MIN));
        assert_eq!(call.args[0].js_type(), "bigint");
        let back = pack(&DexType::Long, HostReturn::BigInt(i64::MIN)).unwrap();
        assert_eq!(back.word, Some(GuestWord::I64(i64::MIN)));
        // A number offered for a `long` is refused rather than widened, because
        // widening it would be the widening that is already wrong.
        let e = pack(&DexType::Long, HostReturn::Number(1.0)).unwrap_err();
        assert_eq!(e.kind(), MarshalErrorKind::ReturnTypeMismatch);
    }

    /// A `Z` arriving from the guest as something other than 0 or 1 is folded,
    /// and the folding is *recorded* — the `IR.md` rule that a fabricated value
    /// is labelled as fabricated.
    #[test]
    fn an_out_of_range_boolean_from_the_guest_is_folded_and_labelled() {
        let p = proto("(Z)V");
        for (word, want, labelled) in [
            (GuestWord::I32(0), 0, false),
            (GuestWord::I32(1), 1, false),
            (GuestWord::I32(2), 0, true),
            (GuestWord::I32(42), 0, true),
            (GuestWord::I32(-1), 1, true),
        ] {
            let call = unpack(&p, true, GuestWord::I32(0), &[word]).unwrap();
            assert_eq!(call.args[0].value, HostValue::Int(want), "{word:?}");
            assert_eq!(
                call.args[0].notes.boolean_normalised, labelled,
                "the fold of {word:?} must be labelled {labelled}"
            );
        }
    }

    /// A `B` whose register was never narrowed is narrowed *here*, so the host
    /// sees the same value a guest-side narrowing would have produced. The
    /// narrowing is the tested conversion matrix rather than a fresh `as`.
    #[test]
    fn a_byte_whose_register_was_not_narrowed_is_narrowed_at_the_boundary() {
        let p = proto("(B)V");
        let call = unpack(&p, true, GuestWord::I32(0), &[GuestWord::I32(0x1234)]).unwrap();
        assert_eq!(call.args[0].value, HostValue::Int(0x34));
        let c = proto("(C)V");
        let call = unpack(&c, true, GuestWord::I32(0), &[GuestWord::I32(-1)]).unwrap();
        assert_eq!(call.args[0].value, HostValue::Int(65535));
        let sh = proto("(S)V");
        let call = unpack(&sh, true, GuestWord::I32(0), &[GuestWord::I32(0xffff)]).unwrap();
        assert_eq!(call.args[0].value, HostValue::Int(-1));
    }

    // ------------------------------------------------------- malformed input

    /// A malformed or truncated descriptor is a typed error: never a coercion,
    /// never a panic, never a silent zero. Every one of these can arrive from a
    /// hostile DEX.
    #[test]
    fn a_malformed_descriptor_is_a_typed_error_and_never_a_panic() {
        let malformed = [
            "",
            "L",
            "L;",
            "[V",
            "Q",
            "Igarbage",
            "(",
            ")",
            "(I",
            "(V)V",
            "(I)",
            "()",
            "[[[[V",
            "[",
            "Ljava/lang/String",
            "(Ljava/lang/String",
            "(I)L;",
            " ",
            "\u{0}",
            "[I][I",
        ];
        for text in malformed {
            // Two things are checked: `Prototype::parse` refuses it, and the
            // refusal becomes a *single* `MalformedDescriptor` at this layer,
            // because a caller at the boundary should not have to know the ABI's
            // internal subdivision of "this descriptor is not a descriptor".
            match Prototype::parse(text) {
                Err(e) => {
                    let m: MarshalError = e.into();
                    assert_eq!(
                        m.kind(),
                        MarshalErrorKind::MalformedDescriptor,
                        "`{text}`: {m}"
                    );
                    assert!(!m.detail.is_empty(), "`{text}` produced an empty reason");
                }
                Ok(p) => panic!("`{text}` parsed as {p} rather than erroring"),
            }
        }
        // Past the parameter limit: still a typed error, not an allocation the
        // size of the descriptor.
        let many = format!("({})V", "I".repeat(400));
        let e = Prototype::parse(&many).unwrap_err();
        assert_eq!(e.kind(), "too_many_parameters");
        // The absence of a `(` is a *different* ABI diagnostic that this layer
        // collapses, so a caller at the boundary sees one category. Checked
        // here so the collapse is deliberate rather than incidental.
        assert_eq!(
            MarshalError::from(Prototype::parse("no parens").unwrap_err()).kind(),
            MarshalErrorKind::MalformedDescriptor
        );
        // ...and the well-formed ones are not on the list by accident.
        for good in ["()V", "(I)V", "([I)Ljava/lang/Object;"] {
            assert!(Prototype::parse(good).is_ok(), "`{good}` should parse");
        }
    }

    /// A word of the wrong WebAssembly type is refused. This is the check that
    /// stops an `f64` being read as an `i32`, and it is why [`GuestWord`] is a
    /// tagged union rather than a raw `i64`.
    #[test]
    fn a_word_of_the_wrong_wasm_type_is_refused_rather_than_reinterpreted() {
        let p = proto("(I)V");
        for word in [
            GuestWord::F64(1.0),
            GuestWord::F32(1.0),
            GuestWord::I64(1),
            GuestWord::Void,
        ] {
            let e = unpack(&p, true, GuestWord::I32(0), &[word]).unwrap_err();
            assert_eq!(
                e.kind(),
                MarshalErrorKind::ArgumentTypeMismatch,
                "{word:?} into an I"
            );
            assert_eq!(e.position, Some(0), "the error names which argument");
        }
        // And the other direction: an i64 where an `F` is declared.
        let pf = proto("(F)V");
        let e = unpack(&pf, true, GuestWord::I32(0), &[GuestWord::I64(1)]).unwrap_err();
        assert_eq!(e.kind(), MarshalErrorKind::ArgumentTypeMismatch);
    }

    /// The register count has to match the prototype, and the receiver is
    /// counted for the instance forms.
    #[test]
    fn the_register_count_must_match_the_prototype() {
        let p = proto("(III)V");
        let three = [GuestWord::I32(1), GuestWord::I32(2), GuestWord::I32(3)];
        assert!(unpack(&p, true, GuestWord::I32(0), &three).is_ok());
        // A static call does not read a receiver, so three registers is right.
        let e = unpack(&p, true, GuestWord::I32(0), &three[..2]).unwrap_err();
        assert_eq!(e.kind(), MarshalErrorKind::ArityMismatch);
        // An instance call reads four.
        assert!(unpack(&p, false, GuestWord::I32(8), &three).is_err());
        let mut four = three.to_vec();
        four.push(GuestWord::I32(8));
        assert!(unpack(&p, false, GuestWord::I32(8), &four).is_ok());
        // A non-handle receiver is refused: `this` is an `i32` handle and
        // nothing else.
        let e = unpack(&p, false, GuestWord::F64(8.0), &four).unwrap_err();
        assert_eq!(e.kind(), MarshalErrorKind::ArgumentTypeMismatch);
    }

    /// Every failure of `pack` is one of the named kinds, and none of them is a
    /// zero. A `NaN` for an integral return is the one worth stating: it is
    /// *not* the `0` that `float-to-int` produces, because that `0` is the
    /// conversion opcode's answer for a value the guest computed, and a host
    /// handing back a `NaN` is a bug that has to be visible.
    #[test]
    fn a_host_answer_that_does_not_fit_the_return_type_is_reported_never_zeroed() {
        let i = DexType::Int;
        let cases: &[(HostReturn, &str)] = &[
            (HostReturn::Number(f64::NAN), "not_finite"),
            (HostReturn::Number(f64::INFINITY), "not_finite"),
            (HostReturn::Number(1.5), "not_integral"),
            (HostReturn::Number(3e9), "out_of_range"),
            (HostReturn::BigInt(1), "return_type_mismatch"),
            (
                HostReturn::Handle(Handle::from_bits(4)),
                "return_type_mismatch",
            ),
            (HostReturn::Nothing, "return_type_mismatch"),
        ];
        for (answer, kind) in cases {
            let e = pack(&i, *answer).unwrap_err();
            assert_eq!(e.kind_str(), *kind, "packing {answer:?} into an I");
        }
        // ...and the width is the *declared* one, not the widest.
        let b = DexType::Byte;
        assert!(
            pack(&b, HostReturn::Number(300.0)).is_err(),
            "300 is not a byte"
        );
        assert!(pack(&b, HostReturn::Number(127.0)).is_ok());
        assert!(pack(&b, HostReturn::Number(-128.0)).is_ok());
        assert!(pack(&b, HostReturn::Number(-129.0)).is_err());
        let c = DexType::Char;
        assert!(pack(&c, HostReturn::Number(65535.0)).is_ok());
        assert!(
            pack(&c, HostReturn::Number(-1.0)).is_err(),
            "a char is not negative"
        );
        // A `char` repacked comes back as the `char` the guest-side store would
        // have produced.
        let p = pack(&c, HostReturn::Number(65535.0)).unwrap();
        assert_eq!(p.word, Some(GuestWord::I32(65535)));
        assert_eq!(p.notes.narrowed, Some(Narrowing::Char));
    }

    /// A `void` method has no result, and a value returned for one is discarded
    /// *and recorded* rather than becoming a zero.
    #[test]
    fn a_void_method_discards_a_returned_value_and_says_so() {
        let v = DexType::Void;
        assert_eq!(pack(&v, HostReturn::Nothing).unwrap().word, None);
        let p = pack(&v, HostReturn::Number(7.0)).unwrap();
        assert_eq!(p.word, None, "there is nowhere for the value to go");
        assert!(p.notes.discarded_return, "and the crossing records that");
    }

    // ------------------------------------------- the f64 <-> Handle barrier

    /// The direction that matters most. A `number` where a reference is declared
    /// is refused, so no `f64` bit pattern can become an object index however the
    /// host was written.
    #[test]
    fn no_path_moves_a_float_bit_pattern_into_a_handle() {
        let reference = DexType::object();
        // Every f64 bit pattern that *looks* like a small integer, plus the
        // specials, plus the extremes. If any of them crossed, the host would be
        // handed an object index it did not allocate.
        let patterns: &[u64] = &[
            0,
            0x8000_0000_0000_0000,
            0x0000_0000_0000_0001,
            0x3ff0_0000_0000_0000, // 1.0
            0xbff0_0000_0000_0000, // -1.0
            0x3fe0_0000_0000_0000, // 0.5
            0x7ff0_0000_0000_0000, // +inf
            0xfff0_0000_0000_0000, // -inf
            0x7ff8_0000_0000_0000, // NaN
            0x7ff0_0000_0000_1234, // a signalling-looking NaN payload
            0x0000_0000_0000_1234,
            0x0000_0000_0000_0008,
            0x7fef_ffff_ffff_ffff,
            0x0010_0000_0000_0000,
        ];
        for bits in patterns {
            let n = f64::from_bits(*bits);
            for ret in [
                &reference,
                &DexType::Ref("Ljava/lang/Object;".into()),
                &DexType::Array(Box::new(DexType::Int)),
            ] {
                let e = pack(ret, HostReturn::Number(n)).unwrap_err();
                assert_eq!(
                    e.kind(),
                    MarshalErrorKind::ReturnTypeMismatch,
                    "f64 {n} ({bits:#018x}) must not become a handle"
                );
                let e = pack(ret, HostReturn::BigInt(*bits as i64)).unwrap_err();
                assert_eq!(e.kind(), MarshalErrorKind::ReturnTypeMismatch);
            }
            // And a handle declared as a number is refused in the other
            // direction, so a handle cannot be read back as a double either.
            for ret in [
                &DexType::Int,
                &DexType::Long,
                &DexType::Float,
                &DexType::Double,
            ] {
                let e = pack(ret, HostReturn::Handle(Handle::from_bits(*bits as u32))).unwrap_err();
                assert_eq!(e.kind(), MarshalErrorKind::ReturnTypeMismatch);
            }
        }
        // The conversion matrix refuses the crossing in its own right, so the
        // refusal does not depend on `pack` being on the path.
        assert_eq!(
            convert(
                &DexType::Double,
                &reference,
                AbiValue::Double(f64::from_bits(0x1234))
            )
            .unwrap_err()
            .kind(),
            "no_conversion"
        );
        // A real handle does cross, and crosses as an `i32` — the only
        // representation a handle has on the wire.
        let h = Handle::from_bits(0x1234);
        let p = pack(&reference, HostReturn::Handle(h)).unwrap();
        assert_eq!(p.word, Some(GuestWord::I32(0x1234)));
    }

    // ------------------------------------------------- MarshalError round trip

    /// The text encoding of a [`MarshalError`] is total and injective over
    /// arbitrary content in every field. A recording that cannot be read back is
    /// not a recording, and an encoder that drops a field loses the *position*,
    /// which is the part that says which argument went wrong.
    #[test]
    fn a_marshal_error_round_trips_through_its_text_encoding() {
        let mut rng = Rng::new(0x5EED_1234_ABCD_0001);
        let mut checked = 0u32;
        for i in 0..4000 {
            let kind = MarshalErrorKind::ALL[rng.below(MarshalErrorKind::ALL.len())];
            let descriptor = match rng.below(3) {
                0 => None,
                1 => Some(String::new()),
                _ => {
                    let n = rng.below(24);
                    let mut s = String::new();
                    for _ in 0..n {
                        s.push(rng.descriptor_byte() as char);
                    }
                    Some(s)
                }
            };
            let position = match rng.below(3) {
                0 => None,
                1 => Some(0),
                _ => Some(rng.below(1 << 20)),
            };
            let n = rng.below(40);
            let mut detail = String::new();
            for _ in 0..n {
                detail.push(rng.descriptor_byte() as char);
            }
            let e = MarshalError {
                kind,
                descriptor,
                position,
                detail,
            };
            let text = e.to_text();
            let back = MarshalError::from_text(&text)
                .unwrap_or_else(|err| panic!("case {i}: {e} encoded as {text:?}: {err}"));
            assert_eq!(back, e, "case {i} did not round trip through {text:?}");
            checked += 1;
        }
        assert_eq!(checked, 4000);
    }

    /// Every kind in the enumeration encodes and parses, so a new variant cannot
    /// be added without the encoder handling it.
    #[test]
    fn every_error_kind_survives_the_text_encoding() {
        for kind in MarshalErrorKind::ALL {
            let e = MarshalError::new(kind, "detail");
            let back = MarshalError::from_text(&e.to_text()).unwrap();
            assert_eq!(back.kind, kind);
            assert_eq!(back, e);
        }
        // ...and an unknown discriminant is refused rather than defaulted.
        let e = MarshalError::from_text("not_a_kind|at:-|desc:-|x").unwrap_err();
        assert_eq!(e.kind(), MarshalErrorKind::MalformedDescriptor);
        // A truncated or mistagged encoding is refused rather than guessed at.
        assert!(MarshalError::from_text("return_type_mismatch").is_err());
        assert!(MarshalError::from_text("return_type_mismatch|x").is_err());
        assert!(MarshalError::from_text("return_type_mismatch|at:-|desc:").is_err());
        assert!(
            MarshalError::from_text("return_type_mismatch|7|desc:+I|x").is_err(),
            "an untagged position is not a position"
        );
        // The presence marker is what makes the encoding injective, so `Some("")`
        // and `None` must not collide.
        let empty = MarshalError {
            kind: MarshalErrorKind::Unsupported,
            descriptor: Some(String::new()),
            position: None,
            detail: String::new(),
        };
        let absent = MarshalError {
            kind: MarshalErrorKind::Unsupported,
            descriptor: None,
            position: None,
            detail: String::new(),
        };
        assert_ne!(empty.to_text(), absent.to_text());
        assert_eq!(MarshalError::from_text(&empty.to_text()).unwrap(), empty);
        assert_eq!(MarshalError::from_text(&absent.to_text()).unwrap(), absent);
    }

    /// The fuzzer's other half: `unpack` and `pack` are *total*. Ten thousand
    /// random descriptor/word/return combinations, and not one of them may
    /// panic — the property `IR.md` states as a non-negotiable and the one this
    /// module would most easily lose to an index or a slice.
    #[test]
    fn unpacking_and_packing_are_total_over_arbitrary_input() {
        let mut rng = Rng::new(0xC0FF_EE00_1234_5678);
        let mut ok = 0u32;
        let mut refused = 0u32;
        for _ in 0..10_000 {
            // A descriptor, usually nearly well formed.
            let n = rng.below(12) + 1;
            let mut sig = String::from("(");
            for _ in 0..n {
                match rng.below(8) {
                    0 => sig.push('['),
                    1 => sig.push_str("Ljava/lang/String;"),
                    2 => sig.push(rng.descriptor_byte() as char),
                    3 => {
                        let t = b"ZBSCIJFD"[rng.below(8)];
                        sig.push(t as char);
                    }
                    _ => sig.push(b"VZBSCIJFD"[rng.below(9)] as char),
                }
            }
            sig.push(')');
            if rng.below(4) == 0 {
                sig.push_str("Ljava/lang/Object;");
            } else if rng.below(4) == 0 {
                sig.push(b"VZBSCIJFD"[rng.below(9)] as char);
            }

            let words: Vec<GuestWord> = (0..rng.below(8))
                .map(|_| match rng.below(5) {
                    0 => GuestWord::I32(rng.next_u64() as i32),
                    1 => GuestWord::I64(rng.next_u64() as i64),
                    2 => GuestWord::F32(f32::from_bits(rng.next_u64() as u32)),
                    3 => GuestWord::F64(f64::from_bits(rng.next_u64())),
                    _ => GuestWord::Void,
                })
                .collect();

            match Prototype::parse(&sig) {
                Err(_) => refused += 1,
                Ok(p) => {
                    let is_static = rng.below(2) == 0;
                    let recv = match rng.below(6) {
                        0 => GuestWord::I32(rng.next_u64() as i32),
                        1 => GuestWord::F64(f64::from_bits(rng.next_u64())),
                        _ => GuestWord::I32(0),
                    };
                    let _ = unpack(&p, is_static, recv, &words);
                    ok += 1;
                }
            }

            // ...and `pack` over a random return type and answer.
            let ret = match rng.below(10) {
                0 => DexType::Void,
                1 => DexType::object(),
                2 => DexType::Long,
                3 => DexType::Float,
                4 => DexType::Double,
                5 => DexType::Char,
                6 => DexType::Byte,
                7 => DexType::Boolean,
                8 => DexType::Short,
                _ => DexType::Int,
            };
            let answer = match rng.below(6) {
                0 => HostReturn::Number(f64::from_bits(rng.next_u64())),
                1 => HostReturn::BigInt(rng.next_u64() as i64),
                2 => HostReturn::Handle(Handle::from_bits(rng.next_u64() as u32)),
                3 => HostReturn::Nothing,
                _ => HostReturn::Number((rng.next_u64() % 1000) as f64),
            };
            let _ = pack(&ret, answer);
        }
        assert_eq!(ok + refused, 10_000);
        assert!(
            ok > 500,
            "only {ok} descriptors were well formed; the fuzzer is weak"
        );
    }

    // ------------------------------------------------------ the host boundary

    /// A host implementation cannot dereference a handle; it has to ask the API,
    /// and the API is the only thing that takes a `NonNullHandle`.
    struct Api {
        seen: Vec<String>,
    }

    impl HostApi for Api {
        fn class_of(&self, object: NonNullHandle) -> String {
            format!("class@{}", object.bits())
        }
        fn field(&mut self, object: NonNullHandle, name: &str) -> MarshalResult<HostValue> {
            self.seen.push(format!("field {name}@{}", object.bits()));
            Ok(HostValue::Int(7))
        }
        fn invoke(
            &mut self,
            object: NonNullHandle,
            name: &str,
            _args: &[Slot],
        ) -> MarshalResult<HostValue> {
            self.seen.push(format!("call {name}@{}", object.bits()));
            Ok(HostValue::Int(7))
        }
    }

    struct Reader;

    impl HostImpl for Reader {
        fn call(&mut self, ctx: &mut HostCtx<'_>) -> MarshalResult<HostReturn> {
            let class = ctx.receiver_class()?;
            let v = ctx.field("length")?;
            let _ = ctx.invoke("hashCode", &[])?;
            let _ = class;
            Ok(match v {
                HostValue::Int(i) => HostReturn::Number(f64::from(i)),
                other => HostReturn::Number(other.as_number().unwrap_or(0.0)),
            })
        }
    }

    #[test]
    fn a_host_impl_reaches_an_object_only_through_the_api() {
        let mut api = Api { seen: Vec::new() };
        let p = proto("(I)I");
        let mut m = Marshaller::new(p, false, &mut api);
        let mut host = Reader;
        let words = [GuestWord::I32(8), GuestWord::I32(3)];
        match m.call(GuestWord::I32(16), &words, &mut host) {
            CallOutcome::Value(packed) => {
                assert_eq!(packed.word, Some(GuestWord::I32(7)));
            }
            other => panic!("unexpected {other:?}"),
        }
        // The API saw the receiver, not a number.
        assert_eq!(api.seen, vec!["field length@16", "call hashCode@16"]);
    }

    #[test]
    fn a_null_receiver_is_a_typed_error_and_not_a_read_at_offset_zero() {
        let mut api = Api { seen: Vec::new() };
        let p = proto("()I");
        let mut m = Marshaller::new(p, false, &mut api);
        let mut host = Reader;
        // An instance method with no parameters still reads one register: the
        // receiver. It is `0`, which is `null`.
        match m.call(GuestWord::I32(0), &[GuestWord::I32(0)], &mut host) {
            CallOutcome::Refused(e) => assert_eq!(e.kind(), MarshalErrorKind::NullHandle),
            other => panic!("a null receiver produced {other:?}"),
        }
        assert!(api.seen.is_empty(), "the API was called on a null handle");
    }

    /// A host that declines is reported as a decline. The caller decides what
    /// that means; this module does not substitute a zero, because a zero
    /// nobody recorded is a silently wrong program.
    #[test]
    fn a_declining_host_is_reported_rather_than_substituted() {
        struct Declines;
        impl HostImpl for Declines {
            fn call(&mut self, _ctx: &mut HostCtx<'_>) -> MarshalResult<HostReturn> {
                Ok(HostReturn::Nothing)
            }
        }
        let mut api = Api { seen: Vec::new() };
        let p = proto("(I)Ljava/lang/String;");
        let mut m = Marshaller::new(p, true, &mut api);
        let mut host = Declines;
        let out = m.call(GuestWord::I32(0), &[GuestWord::I32(1)], &mut host);
        assert_eq!(out, CallOutcome::NotImplemented);
        // The zero the caller *may* substitute is a named function, so a
        // recording of a substituted value can point at where it came from.
        assert_eq!(m.zero_for_ret(), GuestWord::I32(0));
        let p = proto("(I)J");
        let m = Marshaller::new(p, true, &mut api);
        assert_eq!(m.zero_for_ret(), GuestWord::I64(0));
        let p = proto("(I)V");
        let m = Marshaller::new(p, true, &mut api);
        assert_eq!(m.zero_for_ret(), GuestWord::Void);
    }

    /// The `Slot` carries the declared type, because a host receiving `65`
    /// cannot otherwise tell a `char` from an `int`.
    #[test]
    fn a_slot_carries_its_declared_type_and_its_js_type() {
        let p = proto("(CILjava/lang/String;J)V");
        let call = unpack(
            &p,
            true,
            GuestWord::I32(0),
            &[
                GuestWord::I32(65),
                GuestWord::I32(1),
                GuestWord::I32(8),
                GuestWord::I64(9),
            ],
        )
        .unwrap();
        assert_eq!(call.args[0].ty, DexType::Char);
        assert_eq!(call.args[0].value, HostValue::Int(65));
        assert_eq!(call.args[1].ty, DexType::Int);
        assert_eq!(call.args[2].ty, DexType::Ref("Ljava/lang/String;".into()));
        assert_eq!(call.args[2].js_type(), "Handle");
        assert_eq!(call.args[3].js_type(), "bigint");
        // ...and indexing past the end is `None`, not a panic.
        assert!(call.arg(4).is_none());
        assert!(call.arg(usize::MAX).is_none());
    }

    /// A `Bool` reaches a host as 0 or 1 and a `number` from the host comes back
    /// as 0 or 1, because the range check on the way out uses the declared
    /// width rather than the widest one.
    #[test]
    fn a_boolean_crosses_in_both_directions_as_zero_or_one() {
        let p = proto("(Z)Z");
        for v in [0i32, 1, 2, 42, -1] {
            let call = unpack(&p, true, GuestWord::I32(0), &[GuestWord::I32(v)]).unwrap();
            let got = match call.args[0].value {
                HostValue::Int(i) => i,
                other => panic!("{other:?}"),
            };
            assert!(got == 0 || got == 1, "{v} crossed as {got}");
        }
        for good in [0.0f64, 1.0] {
            let p = pack(&DexType::Boolean, HostReturn::Number(good)).unwrap();
            assert_eq!(p.word, Some(GuestWord::I32(good as i32)));
            assert!(!p.notes.boolean_normalised, "{good} needed no folding");
        }
        // Out of the 0/1 range.
        for bad in [2.0f64, 3.0, -1.0] {
            let e = pack(&DexType::Boolean, HostReturn::Number(bad)).unwrap_err();
            assert_eq!(e.kind(), MarshalErrorKind::OutOfRange, "{bad}");
        }
        // Not a whole number at all, which is reported as such rather than
        // reached by the range check.
        for frac in [0.5f64, -0.5, 1.5] {
            let e = pack(&DexType::Boolean, HostReturn::Number(frac)).unwrap_err();
            assert_eq!(e.kind(), MarshalErrorKind::NotIntegral, "{frac}");
        }
    }

    /// `IR.md`'s note that a `Z` is 0/1 survives into the marshaller's own
    /// `Bool`, so a host never has to remember it.
    #[test]
    fn the_boolean_fold_and_the_abi_fold_agree() {
        for v in [0i32, 1, 2, 3, 42, -1, i32::MAX, i32::MIN] {
            assert_eq!(
                unpack(
                    &proto("(Z)V"),
                    true,
                    GuestWord::I32(0),
                    &[GuestWord::I32(v)]
                )
                .unwrap()
                .args[0]
                    .value,
                HostValue::Int(Bool::normalise(v).as_i32()),
                "{v}"
            );
        }
    }
}
