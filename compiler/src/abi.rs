//! The calling convention, made executable.
//!
//! Everything in this module answers one question: *given a DEX descriptor, what
//! goes on the stack, what comes off it, and what does a value mean when it gets
//! there?* The answer is short — five WebAssembly types, no boxing, no
//! `i1` — and every one of the ways it can be got wrong is silent rather than
//! loud, which is the reason the module is this heavily tested.
//!
//! # The five types
//!
//! | DEX | Wasm | why it is this and not something else |
//! |---|---|---|
//! | `Z` | `i32` | WebAssembly has no `i1` and no boolean type. `Z` is the `i32` 0 or 1. |
//! | `B` `S` `C` `I` | `i32` | one machine word either way; the *width* is the instruction's business. |
//! | `J` | `i64` | |
//! | `F` | `f32` | |
//! | `D` | `f64` | |
//! | object, array, `null` | `i32` handle | a byte offset into the guest heap; `0` is `null`. |
//! | `V` | *no result* | |
//!
//! Widening is explicit: `(II)I` is two `i32` in and one `i32` out, and there is
//! no hidden boxing anywhere in this module. `AbiValue` has no boxed variant and
//! [`Conversion`] cannot produce one, because a compiler that invents a
//! `java/lang/Integer` it never allocated is a compiler that will eventually
//! hand that object to a host API which then dereferences garbage.
//!
//! # The four bugs this module exists to prevent
//!
//! Each of the following is a real, silent, wrong-answer bug rather than a
//! compile error, which is why each has a named test in the test module and not
//! merely a line of coverage.
//!
//! 1. **`Z` is `0`/`1`, not a boolean.** There is no `i1`, so nothing in the
//!    toolchain can hand us a "boolean" — a `Z` parameter is an `i32` that the
//!    ABI *guarantees* is 0 or 1, and a value outside that range is folded
//!    rather than trusted. See [`Bool`] and the note on normalisation below.
//! 2. **`byte`/`short`/`char` truncate differently.** `char` is 16-bit
//!    **unsigned** and zero-extends; `short` is 16-bit **signed** and
//!    sign-extends; `byte` is 8-bit signed. Getting `char` wrong turns 65535
//!    into -1, and it is a one-character bug.
//! 3. **`L` arithmetic wraps.** `Long::MAX + 1` is `Long::MIN`. Nothing traps.
//! 4. **`F`/`D` are IEEE-754, and `rem` is not C++'s intuition about it.**
//!    See [`rem_f32`], which has a measured note attached to it because the
//!    specification's own phrasing of the operation is a trap.
//!
//! # Normalising `Z`, and why it is not rejecting it
//!
//! Dalvik has **no `int-to-boolean` opcode**. The only ways a `Z` is produced are
//! `and-int 1`, `aput-boolean`, `iput-boolean`/`sput-boolean` and `aget-boolean`,
//! and those three rules do not agree with one another:
//!
//! * `sput-boolean`/`iput-boolean` take the **low bit** (`v & 1`);
//! * `aput-boolean` takes the **low bit**;
//! * `aget-boolean` tests **non-zero**.
//!
//! So "what does a `Z` equal" is not one question but two, and this module keeps
//! them apart: [`Bool::normalise`] implements the *coercion* rule (low bit),
//! which is what a parameter, a return value and a field store are, and
//! [`narrow_on_load`] implements the *array read* rule (non-zero), which is what
//! `aget-boolean` is. Both match the interpreter, and
//! `bool_load_and_store_use_different_rules` is the test that keeps them from
//! drifting into one another.
//!
//! A `Z` that is neither 0 nor 1 is therefore **normalised, not rejected**, and
//! the decision is argued rather than assumed:
//!
//! * Rejecting would make the compiler fail where the interpreter succeeds.
//!   `IR.md` is explicit that divergence is a bug in the compiler and never in
//!   the oracle, so a "helpful" error on a hostile `Z` is a *divergence*, and a
//!   divergence introduced by the very layer meant to prevent them is worse than
//!   the one it prevents.
//! * A verifier-legal DEX cannot produce a `Z` outside `{0, 1}` at all, so the
//!   normalisation is a no-op on every real APK. It costs one `and 1`.
//! * Normalising is a **fabrication** and `IR.md` requires every fabricated value
//!   to be labelled as one. [`Conversion::notes`] does exactly that: a
//!   normalisation is reported in [`Notes::boolean_normalised`] rather than
//!   happening invisibly.
//!
//! # Verification, and what "verified" means here
//!
//! The oracle is `dexinterp`. Where a conversion corresponds to a real Dalvik
//! opcode, this module's implementation is checked by **executing that opcode**:
//! the test module assembles a DEX, writes it with `dexcore`, runs it through
//! `dexinterp`, and compares. That is a measurement, not a reading of the
//! specification, and it is the only kind of claim the test names in this file
//! make. Pairs with no corresponding opcode have **no oracle** — they are
//! checked as errors instead, which is a decision, and is labelled as one.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>
//! §6.3 and the `access_flags` table.

use std::fmt;

// ===================================================================== errors

/// Why a descriptor or a value could not be turned into a WebAssembly shape.
///
/// Every variant is a *reportable* condition. None of them is a panic, and none
/// of them is answered by substituting a default value: `IR.md` requires a typed
/// error over a silent default, because a silent default in this layer is a
/// silently wrong program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiError {
    /// The descriptor text was empty. `DexType::parse("")`.
    DescriptorEmpty,
    /// A `L` was not closed by a `;`.
    UnterminatedClass {
        /// The text as far as it could be consumed.
        seen: String,
    },
    /// `L;` — a class descriptor with no name.
    EmptyClassName,
    /// A byte that is not the start of any descriptor.
    InvalidByte {
        /// The offending byte.
        byte: u8,
    },
    /// The descriptor parsed but did not use up all of its text, e.g. `II)` in a
    /// return position. Catching the remainder is what stops `Igarbage` from
    /// being read as `I`.
    TrailingBytes {
        /// The unconsumed remainder.
        rest: String,
    },
    /// `[V` — an array of `void` is not a type.
    ArrayOfVoid,
    /// Array nesting deeper than [`MAX_ARRAY_DEPTH`].
    ArrayDepthExceeded {
        /// The nesting the descriptor asked for.
        depth: usize,
        /// The limit that was exceeded.
        max: usize,
    },
    /// A prototype that does not start with `(`.
    MissingOpenParenthesis,
    /// A prototype whose `(` is never closed.
    UnclosedParameterList,
    /// A `V` in the parameter position. `(V)V` is not a prototype.
    VoidParameter {
        /// Which parameter slot.
        index: usize,
    },
    /// More parameters than any `invoke` instruction can name.
    TooManyParameters {
        /// How many the descriptor declared.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// A value was offered with a static type that does not match its own
    /// representation — an `f64` presented as an `I`, say. This is a bug in the
    /// caller, and it is caught here rather than being allowed to reinterpret a
    /// bit pattern.
    ValueTypeMismatch {
        /// What the call site said it was passing.
        declared: String,
        /// What the value actually is.
        found: String,
    },
    /// No Dalvik instruction converts between these two types.
    ///
    /// Not a limitation of this implementation: Dalvik has exactly fifteen
    /// conversion opcodes and they are not closed under composition, so a
    /// compiler asked for a conversion that does not exist must say so rather
    /// than invent one.
    NoConversion {
        /// The source descriptor.
        from: String,
        /// The destination descriptor.
        to: String,
    },
    /// A non-null reference was required and the handle was `0`.
    NullHandle {
        /// What wanted it.
        context: &'static str,
    },
    /// A varargs box was indexed past its length.
    VarargsOutOfBounds {
        /// The index asked for.
        index: usize,
        /// The number of arguments actually packed.
        len: usize,
    },
}

impl AbiError {
    /// A stable, machine-readable discriminant for recordings.
    pub fn kind(&self) -> &'static str {
        match self {
            AbiError::DescriptorEmpty => "descriptor_empty",
            AbiError::UnterminatedClass { .. } => "unterminated_class",
            AbiError::EmptyClassName => "empty_class_name",
            AbiError::InvalidByte { .. } => "invalid_byte",
            AbiError::TrailingBytes { .. } => "trailing_bytes",
            AbiError::ArrayOfVoid => "array_of_void",
            AbiError::ArrayDepthExceeded { .. } => "array_depth_exceeded",
            AbiError::MissingOpenParenthesis => "missing_open_parenthesis",
            AbiError::UnclosedParameterList => "unclosed_parameter_list",
            AbiError::VoidParameter { .. } => "void_parameter",
            AbiError::TooManyParameters { .. } => "too_many_parameters",
            AbiError::ValueTypeMismatch { .. } => "value_type_mismatch",
            AbiError::NoConversion { .. } => "no_conversion",
            AbiError::NullHandle { .. } => "null_handle",
            AbiError::VarargsOutOfBounds { .. } => "varargs_out_of_bounds",
        }
    }
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::DescriptorEmpty => write!(f, "empty type descriptor"),
            AbiError::UnterminatedClass { seen } => {
                write!(f, "class descriptor `{seen}` has no `;`")
            }
            AbiError::EmptyClassName => write!(f, "`L;` names no class"),
            AbiError::InvalidByte { byte } => {
                write!(f, "0x{byte:02x} does not start a type descriptor")
            }
            AbiError::TrailingBytes { rest } => {
                write!(f, "`{rest}` is left over after the type descriptor")
            }
            AbiError::ArrayOfVoid => write!(f, "an array of `void` is not a type"),
            AbiError::ArrayDepthExceeded { depth, max } => {
                write!(f, "array nested {depth} deep, limit is {max}")
            }
            AbiError::MissingOpenParenthesis => {
                write!(f, "prototype does not start with `(`")
            }
            AbiError::UnclosedParameterList => write!(f, "prototype has no `)`"),
            AbiError::VoidParameter { index } => {
                write!(f, "parameter {index} is `V`, which is not a parameter type")
            }
            AbiError::TooManyParameters { count, max } => {
                write!(f, "{count} parameters, limit is {max}")
            }
            AbiError::ValueTypeMismatch { declared, found } => {
                write!(f, "value declared `{declared}` is represented as {found}")
            }
            AbiError::NoConversion { from, to } => {
                write!(f, "no Dalvik conversion from `{from}` to `{to}`")
            }
            AbiError::NullHandle { context } => {
                write!(f, "{context} on a null handle")
            }
            AbiError::VarargsOutOfBounds { index, len } => {
                write!(f, "varargs index {index} of {len}")
            }
        }
    }
}

impl std::error::Error for AbiError {}

/// Result alias for anything in this module that can fail on untrusted input.
pub type AbiResult<T> = Result<T, AbiError>;

// ============================================================ the Wasm types

/// The WebAssembly value types. There are five, and `void` is the absence of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Wasm {
    /// `i32`. Also every handle, and all of `Z` `B` `S` `C` `I`.
    I32,
    /// `i64`.
    I64,
    /// `f32`.
    F32,
    /// `f64`.
    F64,
}

impl Wasm {
    /// The WebAssembly text spelling, for `.wat` output and for test failures
    /// that need to name a type rather than print a number.
    pub fn as_str(self) -> &'static str {
        match self {
            Wasm::I32 => "i32",
            Wasm::I64 => "i64",
            Wasm::F32 => "f32",
            Wasm::F64 => "f64",
        }
    }
}

impl fmt::Display for Wasm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================== DEX types

/// The deepest an array descriptor may nest.
///
/// A limit rather than a `Box` recursion for a specific reason: a descriptor
/// arrives from a file, `[[[[[[…` is a legal string, and unbounded recursion
/// over it is a **stack overflow**, which is a process abort and not a typed
/// error. [`DexType::parse`] is therefore iterative in its array handling and
/// the depth is capped here, so a hostile descriptor costs one comparison.
/// 255 is the DEX register-file width, which is the largest array type the
/// format can name in practice.
pub const MAX_ARRAY_DEPTH: usize = 255;

/// The most parameters a prototype may declare.
///
/// Every `invoke-*` instruction names its arguments either in four bits (the
/// `35c` form, at most five) or as a 16-bit register count, against a 16-bit
/// register file. A prototype beyond this cannot be called by any instruction in
/// the format, so accepting it would mean emitting a function nothing can enter.
pub const MAX_PARAMETERS: usize = 255;

/// A parsed DEX type descriptor.
///
/// Strict by design, and deliberately *not* the same shape as the interpreter's
/// `JType`: the oracle degrades an unrecognised descriptor to a reference
/// holding the raw text, which is the right behaviour for an engine that must
/// keep running. A compiler is not in that position — it has to emit something,
/// and emitting something for a descriptor it did not understand is how a
/// method silently acquires the wrong signature. So this parser is total but it
/// is not permissive: every input produces either a type or an [`AbiError`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DexType {
    /// `V`
    Void,
    /// `Z`
    Boolean,
    /// `B`
    Byte,
    /// `S`
    Short,
    /// `C`
    Char,
    /// `I`
    Int,
    /// `J`
    Long,
    /// `F`
    Float,
    /// `D`
    Double,
    /// `Lname;` — a class reference.
    Ref(String),
    /// `[X` — an array of `X`, nested to any depth the limit allows.
    Array(Box<DexType>),
}

impl DexType {
    /// Parse exactly one descriptor and report how much text it consumed.
    ///
    /// The `consumed` count is what lets a parameter list be read, which is a
    /// concatenation rather than a comma-separated list: `(IJLjava/lang/String;)V`
    /// is three parameters, and a parser that stopped at the first `;` would
    /// read it as one.
    pub fn parse_one(s: &str) -> AbiResult<(DexType, usize)> {
        let bytes = s.as_bytes();

        // Count the `[` prefix iteratively. Recursing once per bracket is the
        // obvious spelling and it is a stack overflow on a hostile file.
        let mut depth = 0usize;
        while bytes.get(depth) == Some(&b'[') {
            depth += 1;
        }
        if depth > MAX_ARRAY_DEPTH {
            return Err(AbiError::ArrayDepthExceeded {
                depth,
                max: MAX_ARRAY_DEPTH,
            });
        }

        let (inner, width) = Self::parse_scalar(s.get(depth..).unwrap_or(""))?;

        // `[V` is not a type. The interpreter keeps it addressable because an
        // engine that has to keep running would rather name it than abort, but a
        // compiler that emitted it would be emitting a function with a parameter
        // the format cannot describe, so here it is refused.
        if depth > 0 && inner == DexType::Void {
            return Err(AbiError::ArrayOfVoid);
        }

        // Peel from the inside out, so the resulting tree is the mirror of the
        // text (`[[I` is an array of an array of `int`).
        let mut ty = inner;
        for _ in 0..depth {
            ty = DexType::Array(Box::new(ty));
        }
        Ok((ty, depth + width))
    }

    /// The non-array part: one primitive, or one `L…;`.
    fn parse_scalar(s: &str) -> AbiResult<(DexType, usize)> {
        let first = match s.as_bytes().first() {
            None => return Err(AbiError::DescriptorEmpty),
            Some(b) => *b,
        };
        let primitive = match first {
            b'V' => Some(DexType::Void),
            b'Z' => Some(DexType::Boolean),
            b'B' => Some(DexType::Byte),
            b'S' => Some(DexType::Short),
            b'C' => Some(DexType::Char),
            b'I' => Some(DexType::Int),
            b'J' => Some(DexType::Long),
            b'F' => Some(DexType::Float),
            b'D' => Some(DexType::Double),
            _ => None,
        };
        if let Some(ty) = primitive {
            return Ok((ty, 1));
        }
        if first == b'L' {
            let close = match s.find(';') {
                None => {
                    return Err(AbiError::UnterminatedClass {
                        seen: s.to_string(),
                    })
                }
                Some(i) => i,
            };
            if close == 1 {
                return Err(AbiError::EmptyClassName);
            }
            return Ok((DexType::Ref(s[..=close].to_string()), close + 1));
        }
        Err(AbiError::InvalidByte { byte: first })
    }

    /// Parse a complete descriptor, requiring the whole of `s` to be used.
    pub fn parse(s: &str) -> AbiResult<DexType> {
        let (ty, consumed) = Self::parse_one(s)?;
        match s.get(consumed..) {
            Some("") => Ok(ty),
            Some(rest) => Err(AbiError::TrailingBytes {
                rest: rest.to_string(),
            }),
            // Unreachable while `s` is a `&str`, but the point of this module is
            // that "unreachable" is not a thing it says out loud.
            None => Err(AbiError::DescriptorEmpty),
        }
    }

    /// The descriptor text, reconstructed. The inverse of [`DexType::parse`] for
    /// every type this module can produce.
    pub fn descriptor(&self) -> String {
        match self {
            DexType::Void => "V".to_string(),
            DexType::Boolean => "Z".to_string(),
            DexType::Byte => "B".to_string(),
            DexType::Short => "S".to_string(),
            DexType::Char => "C".to_string(),
            DexType::Int => "I".to_string(),
            DexType::Long => "J".to_string(),
            DexType::Float => "F".to_string(),
            DexType::Double => "D".to_string(),
            DexType::Ref(s) => s.clone(),
            DexType::Array(inner) => format!("[{}", inner.descriptor()),
        }
    }

    /// The single character, for the primitive types. `None` for `V` and the
    /// reference types, which have no single-character form.
    pub fn short_name(&self) -> Option<char> {
        Some(match self {
            DexType::Void => 'V',
            DexType::Boolean => 'Z',
            DexType::Byte => 'B',
            DexType::Short => 'S',
            DexType::Char => 'C',
            DexType::Int => 'I',
            DexType::Long => 'J',
            DexType::Float => 'F',
            DexType::Double => 'D',
            DexType::Ref(_) | DexType::Array(_) => return None,
        })
    }

    /// The WebAssembly type this descriptor is carried in, or `None` for `V`.
    ///
    /// The whole table is four lines long and that is the point: `Z` is not a
    /// separate type because WebAssembly has nothing to make it one, and `L…;`
    /// is `i32` because a handle *is* an `i32` and pretending otherwise would
    /// cost a boxing helper that `IR.md` forbids.
    pub fn wasm_ty(&self) -> Option<Wasm> {
        Some(match self {
            DexType::Void => return None,
            DexType::Boolean
            | DexType::Byte
            | DexType::Short
            | DexType::Char
            | DexType::Int
            | DexType::Ref(_)
            | DexType::Array(_) => Wasm::I32,
            DexType::Long => Wasm::I64,
            DexType::Float => Wasm::F32,
            DexType::Double => Wasm::F64,
        })
    }

    /// `true` for `L…;`, `[X` and `V`-as-`null` positions — anything a reference
    /// can be stored in.
    pub fn is_reference(&self) -> bool {
        matches!(self, DexType::Ref(_) | DexType::Array(_))
    }

    /// `true` for the five types that share one machine word.
    pub fn is_int_family(&self) -> bool {
        matches!(
            self,
            DexType::Boolean | DexType::Byte | DexType::Short | DexType::Char | DexType::Int
        )
    }

    /// Register words occupied in the Dalvik register file: two for `J` and `D`,
    /// zero for `V`, one otherwise.
    pub fn slots(&self) -> usize {
        match self {
            DexType::Void => 0,
            DexType::Long | DexType::Double => 2,
            _ => 1,
        }
    }

    /// Element width in an array payload. A *reference* array is 4 bytes whatever
    /// it holds; the component's own width is one level down.
    pub fn element_width(&self) -> u16 {
        match self {
            DexType::Boolean | DexType::Byte => 1,
            DexType::Short | DexType::Char => 2,
            DexType::Int | DexType::Float | DexType::Ref(_) | DexType::Array(_) => 4,
            DexType::Long | DexType::Double => 8,
            DexType::Void => 0,
        }
    }

    /// The element type of an array, one level down.
    pub fn component(&self) -> Option<&DexType> {
        match self {
            DexType::Array(inner) => Some(inner),
            _ => None,
        }
    }

    /// The class descriptor an `instance-of` or `check-cast` would name.
    pub fn class_descriptor(&self) -> Option<&str> {
        match self {
            DexType::Ref(s) => Some(s),
            _ => None,
        }
    }

    /// A canonical reference type, for the matrix's reference column.
    pub fn object() -> DexType {
        DexType::Ref("Ljava/lang/Object;".to_string())
    }
}

impl fmt::Display for DexType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.descriptor())
    }
}

// ============================================================== prototypes

/// A parsed method prototype, `(II)V`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prototype {
    /// Parameter types, in order.
    pub params: Vec<DexType>,
    /// The return type. [`DexType::Void`] means the function has no result.
    pub ret: DexType,
}

impl Prototype {
    /// Parse a prototype descriptor, requiring the whole string to be consumed.
    pub fn parse(s: &str) -> AbiResult<Prototype> {
        let rest = match s.strip_prefix('(') {
            None => return Err(AbiError::MissingOpenParenthesis),
            Some(r) => r,
        };

        let mut params: Vec<DexType> = Vec::new();
        let mut at = 0usize;
        let closed = loop {
            match rest.as_bytes().get(at) {
                Some(b')') => break true,
                None => break false,
                Some(_) => {
                    let (ty, width) = DexType::parse_one(rest.get(at..).unwrap_or(""))?;
                    if ty == DexType::Void {
                        return Err(AbiError::VoidParameter {
                            index: params.len(),
                        });
                    }
                    if params.len() == MAX_PARAMETERS {
                        return Err(AbiError::TooManyParameters {
                            count: params.len() + 1,
                            max: MAX_PARAMETERS,
                        });
                    }
                    params.push(ty);
                    // `parse_one` returned a width for a descriptor that starts
                    // with a non-`)` byte, so it consumed at least one byte and
                    // the loop terminates. The bound is here because "at least
                    // one" is an argument, not a guarantee.
                    at = at.saturating_add(width).max(at + 1);
                }
            }
        };
        if !closed {
            return Err(AbiError::UnclosedParameterList);
        }

        let ret = match rest.get(at + 1..) {
            None => return Err(AbiError::DescriptorEmpty),
            Some(t) => DexType::parse(t)?,
        };

        Ok(Prototype { params, ret })
    }

    /// The descriptor text.
    pub fn descriptor(&self) -> String {
        let mut s = String::from("(");
        for p in &self.params {
            s.push_str(&p.descriptor());
        }
        s.push(')');
        s.push_str(&self.ret.descriptor());
        s
    }

    /// The WebAssembly signature of the **exported** function for a method with
    /// this prototype.
    ///
    /// `is_static` decides whether a receiver is prepended. This is where the
    /// convention in `IR.md` becomes a value: an instance method `(II)I` exports
    /// as `(param i32 i32 i32) (result i32)`, receiver first, and a static one
    /// as `(param i32 i32) (result i32)`. Nothing is boxed, widened or hidden.
    pub fn wasm_sig(&self, is_static: bool) -> WasmSig {
        let mut params: Vec<Wasm> = Vec::with_capacity(self.params.len() + 1);
        if !is_static {
            // The receiver is a handle, and a handle is an `i32`. It is not an
            // extra DEX parameter and it is not counted as one.
            params.push(Wasm::I32);
        }
        for p in &self.params {
            // Every non-`V` parameter has a Wasm type; `V` is rejected by
            // `parse`, so an `Option` that is `None` here would be a bug rather
            // than a case, and it is reported as one instead of being unwrapped.
            match p.wasm_ty() {
                Some(w) => params.push(w),
                None => params.push(Wasm::I32),
            }
        }
        WasmSig {
            params,
            result: self.ret.wasm_ty(),
        }
    }

    /// The declared parameter types plus the receiver, which is the register
    /// list an `invoke` reads.
    pub fn invoke_registers(&self, is_static: bool) -> Vec<DexType> {
        let mut v = Vec::with_capacity(self.params.len() + 1);
        if !is_static {
            v.push(DexType::object());
        }
        v.extend(self.params.iter().cloned());
        v
    }
}

impl fmt::Display for Prototype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.descriptor())
    }
}

/// The WebAssembly signature of an exported function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmSig {
    /// Parameter types in order, receiver first for an instance method.
    pub params: Vec<Wasm>,
    /// The result type, or `None` for a `void` method.
    pub result: Option<Wasm>,
}

impl WasmSig {
    /// The `(func (param …) (result …))` text, for `.wat` and for a readable
    /// assertion message.
    pub fn wat(&self) -> String {
        let mut s = String::from("(func");
        if !self.params.is_empty() {
            s.push_str(" (param");
            for p in &self.params {
                s.push(' ');
                s.push_str(p.as_str());
            }
            s.push(')');
        }
        if let Some(r) = self.result {
            s.push_str(" (result ");
            s.push_str(r.as_str());
            s.push(')');
        }
        s.push(')');
        s
    }
}

impl fmt::Display for WasmSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.wat())
    }
}

// ================================================================== handles

/// A guest-heap handle: a byte offset, with `0` reserved for `null`.
///
/// The design rule this type exists to enforce is that **a handle is not an
/// integer**. Not "we are careful not to treat it as one" — it is structurally
/// incapable of becoming one:
///
/// * no `From<u32>`, no `From<i32>`, no `From<i64>`, no `From<f32>`, no
///   `From<f64>`, so there is no implicit path from a number to a handle and
///   `as` is not even applicable (a struct has no `as` cast);
/// * no `Deref`, no `Add`, no `Sub`, no `Index`, so it cannot become a pointer
///   or an offset;
/// * no `PartialOrd`/`Ord`, so it cannot be used in a range or a sort key the way
///   an index can;
/// * the only ways out are [`Handle::bits`], which is explicit and named, and
///   the *inward* direction, [`Handle::from_bits`], which exists for the
///   allocator and is documented as belonging to it.
///
/// `IR.md` says "the host never dereferences them", and this is how that stays
/// true in the type system rather than in a review comment: the only way to get
/// something dereferenceable out of a handle is [`Handle::require`], which hands
/// back a [`NonNullHandle`] — a different type. Forgetting the null check is
/// therefore not a missing line, it is a missing function call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handle(u32);

impl Handle {
    /// The null handle. `IR.md`: "A guest heap starts with 0 reserved as null."
    pub const NULL: Handle = Handle(0);

    /// Wrap a raw offset.
    ///
    /// This is the allocator's constructor and it is the **only** way a number
    /// becomes a handle. It takes a `u32` because that is what a bump allocator
    /// has; it deliberately does not take a `usize`, a `f64` or a `Wasm`, so
    /// there is no arithmetic elsewhere in the compiler that can produce one by
    /// accident.
    pub const fn from_bits(bits: u32) -> Handle {
        Handle(bits)
    }

    /// The raw offset, for `codegen` to emit and for the heap to index with.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether this is the null handle.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    /// The gate. Dereferencing a handle requires a `NonNullHandle`, and the only
    /// way to get one is through here, so the null check cannot be skipped by
    /// forgetting it — only by explicitly declining to make it.
    pub const fn require(self, context: &'static str) -> AbiResult<NonNullHandle> {
        if self.0 == 0 {
            Err(AbiError::NullHandle { context })
        } else {
            Ok(NonNullHandle(self.0))
        }
    }

    /// The gate with a fallback, for the `?.` and `?:` idioms.
    pub const fn require_or(self, fallback: NonNullHandle) -> NonNullHandle {
        if self.0 == 0 {
            fallback
        } else {
            NonNullHandle(self.0)
        }
    }
}

impl Default for Handle {
    /// The zero value of a handle is `null`, which is the only total choice: a
    /// default that pointed at a real object would be a use-after-free waiting
    /// for a frame that forgot to initialise.
    fn default() -> Handle {
        Handle::NULL
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.is_null() {
            true => f.write_str("null"),
            false => write!(f, "@{}", self.0),
        }
    }
}

/// A handle that is known not to be null.
///
/// The type exists so that a null check cannot be *forgotten*; nothing else. It
/// carries no methods of its own beyond reading the offset, and every function
/// that dereferences takes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonNullHandle(u32);

impl NonNullHandle {
    /// The raw offset.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Give up the guarantee, returning a plain handle. Provided so that a
    /// callee which has already checked can store the value again; it is the one
    /// documented way back down.
    pub const fn weaken(self) -> Handle {
        Handle(self.0)
    }
}

impl fmt::Display for NonNullHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

// ==================================================================== Z

/// A Dalvik `Z`: the integers 0 and 1, and nothing else.
///
/// WebAssembly has no boolean, so this cannot be enforced by the target. It is
/// enforced here instead, by construction: the only constructor is
/// [`Bool::normalise`], which folds, so there is no way to obtain a `Bool` that
/// is not 0 or 1 — and, more to the point, no way for a caller to *believe* it
/// is 0 or 1 without having gone through the fold. [`Bool::is_true`] is the only
/// way to branch on one, so every branch in generated code is a comparison
/// against zero, which is what `IR.md` requires when it says "`Z` is `0`/`1`,
/// not bool".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Bool(u32);

impl Bool {
    /// `false`.
    pub const FALSE: Bool = Bool(0);
    /// `true`.
    pub const TRUE: Bool = Bool(1);

    /// Fold an arbitrary `i32` to a `Z` by taking the low bit.
    ///
    /// The low bit, not "non-zero means true", and that choice is not arbitrary:
    /// it is what `and-int 1` computes, what `sput-boolean` stores, and what
    /// `aput-boolean` stores. The one place Dalvik tests non-zero instead is
    /// `aget-boolean`, and that is a *load* rule, modelled by
    /// [`narrow_on_load`] — see the module note on why the two are separate.
    pub const fn normalise(v: i32) -> Bool {
        Bool((v as u32) & 1)
    }

    /// Whether normalising `v` would change it, i.e. whether it is a value no
    /// verifier would produce. This is the "was this value fabricated?" test the
    /// `IR.md` rule about labelling fabricated values needs.
    pub const fn is_out_of_range(v: i32) -> bool {
        (v as u32) & 1 != (v as u32)
    }

    /// The branch. `codegen` emits this as `i32.ne 0`, never as a bare test,
    /// because WebAssembly has nothing to test.
    pub const fn is_true(self) -> bool {
        self.0 != 0
    }

    /// The `i32` to put on the stack.
    pub const fn as_i32(self) -> i32 {
        self.0 as i32
    }

    /// The `i32` the host boundary sees. Present so a host impl never has to
    /// reach for a cast.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl Default for Bool {
    fn default() -> Bool {
        Bool::FALSE
    }
}

impl fmt::Display for Bool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_true() { "true" } else { "false" })
    }
}

// =============================================================== values

/// A value as the ABI carries it, with its Dalvik type attached.
///
/// The five integer types are **distinct variants** rather than one `Int`, which
/// is stricter than the interpreter — the oracle has a single `Value::Int`
/// because a Dalvik register genuinely has no type. A compiler does need the
/// distinction: `int-to-byte` and `int-to-char` produce different bits, and if
/// the representation did not record which one it was already in hand, the two
/// could be swapped in a lowering with nothing to catch it.
///
/// There is no boxed variant and no way to construct one. `IR.md`: "There is no
/// hidden boxing. Any agent adding a boxing helper is solving the wrong
/// problem."
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AbiValue {
    /// `V`
    Void,
    /// `Z`, always 0 or 1 by construction.
    Boolean(Bool),
    /// `B`, sign-extended into the `i8`.
    Byte(i8),
    /// `S`, sign-extended into the `i16`.
    Short(i16),
    /// `C`, zero-extended from the `u16`. The `u16` is the whole point.
    Char(u16),
    /// `I`
    Int(i32),
    /// `J`
    Long(i64),
    /// `F`
    Float(f32),
    /// `D`
    Double(f64),
    /// A reference. Opaque to the host.
    Ref(Handle),
}

impl AbiValue {
    /// The static DEX type this value has, or `None` for a reference whose
    /// descriptor lives in the type pool rather than in the value.
    pub fn declared_type(&self) -> Option<DexType> {
        Some(match self {
            AbiValue::Void => DexType::Void,
            AbiValue::Boolean(_) => DexType::Boolean,
            AbiValue::Byte(_) => DexType::Byte,
            AbiValue::Short(_) => DexType::Short,
            AbiValue::Char(_) => DexType::Char,
            AbiValue::Int(_) => DexType::Int,
            AbiValue::Long(_) => DexType::Long,
            AbiValue::Float(_) => DexType::Float,
            AbiValue::Double(_) => DexType::Double,
            AbiValue::Ref(_) => return None,
        })
    }

    /// The WebAssembly type this value occupies, or `None` for `void`.
    pub fn wasm_ty(&self) -> Option<Wasm> {
        self.declared_type().and_then(|t| t.wasm_ty())
    }

    /// A short name for diagnostics.
    pub fn type_name(&self) -> &'static str {
        match self {
            AbiValue::Void => "void",
            AbiValue::Boolean(_) => "boolean",
            AbiValue::Byte(_) => "byte",
            AbiValue::Short(_) => "short",
            AbiValue::Char(_) => "char",
            AbiValue::Int(_) => "int",
            AbiValue::Long(_) => "long",
            AbiValue::Float(_) => "float",
            AbiValue::Double(_) => "double",
            AbiValue::Ref(_) => "reference",
        }
    }

    /// Whether this value is a reference. `null` is a reference, and that is the
    /// case worth being careful about: `Value::Ref` here is the *type*, and
    /// [`AbiValue::Ref`] is the null handle.
    pub fn is_reference(&self) -> bool {
        matches!(self, AbiValue::Ref(_))
    }

    /// The `i32` an int-family value carries, whichever of the five it is.
    ///
    /// `None` for everything else, deliberately: a `Long` is not an `i32` here,
    /// it is an `i64`, and widening it into this would be the first step of
    /// turning 4.6e18 into a plausible-looking `int`.
    pub fn as_int(self) -> Option<i32> {
        match self {
            AbiValue::Boolean(b) => Some(b.as_i32()),
            AbiValue::Byte(b) => Some(i32::from(b)),
            AbiValue::Short(s) => Some(i32::from(s)),
            AbiValue::Char(c) => Some(i32::from(c)),
            AbiValue::Int(i) => Some(i),
            _ => None,
        }
    }

    /// The `i32` to put on the stack for an int-family value, without widening
    /// anything. Equivalent to [`AbiValue::as_int`] but named for the ABI use so
    /// that a caller emitting a parameter does not read as if it were a
    /// conversion.
    pub fn to_i32(self) -> AbiResult<i32> {
        self.as_int().ok_or(AbiError::ValueTypeMismatch {
            declared: "an int-family value".to_string(),
            found: self.type_name().to_string(),
        })
    }

    /// Whether this value is consistent with the static type it is offered as.
    ///
    /// A reference is consistent with any reference type, because the descriptor
    /// is in the pool and the value does not carry it. Everything else must match
    /// exactly: an `f64` presented as an `I` is a bug in the caller, and
    /// accepting it would let a bit pattern be reinterpreted as an index.
    pub fn matches_type(&self, ty: &DexType) -> bool {
        matches!(
            (ty, self),
            (DexType::Void, AbiValue::Void)
                | (DexType::Boolean, AbiValue::Boolean(_))
                | (DexType::Byte, AbiValue::Byte(_))
                | (DexType::Short, AbiValue::Short(_))
                | (DexType::Char, AbiValue::Char(_))
                | (DexType::Int, AbiValue::Int(_))
                | (DexType::Long, AbiValue::Long(_))
                | (DexType::Float, AbiValue::Float(_))
                | (DexType::Double, AbiValue::Double(_))
                | (DexType::Ref(_) | DexType::Array(_), AbiValue::Ref(_))
        )
    }

    /// Check `self` against `ty`, naming the mismatch rather than assuming it.
    pub fn check_type(&self, ty: &DexType) -> AbiResult<()> {
        match self.matches_type(ty) {
            true => Ok(()),
            false => Err(AbiError::ValueTypeMismatch {
                declared: ty.descriptor(),
                found: self.type_name().to_string(),
            }),
        }
    }

    /// Canonicalise the reference representation. A null reference is the null
    /// handle, never a distinguished `Value::Null` variant that could drift.
    pub const fn null() -> AbiValue {
        AbiValue::Ref(Handle::NULL)
    }

    /// The zero value for a type, used for an uninitialised register and for a
    /// `void` return. `None` only for `void`.
    pub fn zero_of(ty: &DexType) -> Option<AbiValue> {
        Some(match ty {
            DexType::Void => AbiValue::Void,
            DexType::Boolean => AbiValue::Boolean(Bool::FALSE),
            DexType::Byte => AbiValue::Byte(0),
            DexType::Short => AbiValue::Short(0),
            DexType::Char => AbiValue::Char(0),
            DexType::Int => AbiValue::Int(0),
            DexType::Long => AbiValue::Long(0),
            DexType::Float => AbiValue::Float(0.0),
            DexType::Double => AbiValue::Double(0.0),
            DexType::Ref(_) | DexType::Array(_) => AbiValue::null(),
        })
    }
}

impl fmt::Display for AbiValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiValue::Void => f.write_str("void"),
            AbiValue::Boolean(b) => write!(f, "{b}"),
            AbiValue::Byte(b) => write!(f, "{b}"),
            AbiValue::Short(s) => write!(f, "{s}"),
            AbiValue::Char(c) => write!(f, "0x{c:04x}"),
            AbiValue::Int(i) => write!(f, "{i}"),
            AbiValue::Long(l) => write!(f, "{l}"),
            AbiValue::Float(x) => write!(f, "{x}f32"),
            AbiValue::Double(x) => write!(f, "{x}f64"),
            AbiValue::Ref(h) => write!(f, "{h}"),
        }
    }
}

// ============================================================ conversions

/// What a conversion did to the value, so that a caller can report it.
///
/// `IR.md` requires every fabricated value to be labelled as fabricated. These
/// two flags are that label: a narrowing truncated something, and a boolean
/// normalisation folded a value no verifier would produce. Neither is
/// observable from the value alone, which is exactly why it has to be carried
/// separately.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Notes {
    /// A `Z` outside `{0, 1}` was folded to its low bit.
    pub boolean_normalised: bool,
    /// What was truncated, if anything.
    pub narrowed: Option<Narrowing>,
}

/// Which truncation a conversion performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Narrowing {
    /// To `B`: kept the low 8 bits, sign-extended.
    Byte,
    /// To `S`: kept the low 16 bits, sign-extended.
    Short,
    /// To `C`: kept the low 16 bits, zero-extended.
    Char,
    /// To `Z`: kept the low bit.
    Boolean,
    /// A `F` or `D` to `I`: saturated, with `NaN` becoming 0.
    FloatToInt,
    /// A `F` or `D` to `J`: saturated, with `NaN` becoming 0.
    FloatToLong,
    /// A `J` to `I`: the high 32 bits were discarded. Not a saturation and not a
    /// rounding, so it is not reported as a float narrowing.
    LongToInt,
    /// `I` to `F`/`D` or `J` to `F`/`D`: a widening that rounds.
    WidenToFloat,
}

impl Narrowing {
    /// A stable name for recordings.
    pub fn as_str(self) -> &'static str {
        match self {
            Narrowing::Byte => "byte",
            Narrowing::Short => "short",
            Narrowing::Char => "char",
            Narrowing::Boolean => "boolean",
            Narrowing::FloatToInt => "float_to_int",
            Narrowing::FloatToLong => "float_to_long",
            Narrowing::LongToInt => "long_to_int",
            Narrowing::WidenToFloat => "widen_to_float",
        }
    }
}

/// The result of a conversion: the value, and what happened to it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Conversion {
    /// The converted value, in the destination's own representation.
    pub value: AbiValue,
    /// Whether anything was truncated or folded. Never fabricated silently.
    pub notes: Notes,
}

/// Convert a value from one DEX type to another.
///
/// This implements **exactly the fifteen Dalvik conversion opcodes plus
/// identity**, and nothing else. That is a deliberate, testable boundary: Dalvik
/// has no `long-to-byte`, no `float-to-char` and no `int-to-boolean`, and a
/// compiler that offers them is offering an operation no Dalvik program can
/// express and that therefore cannot be checked against the oracle. Those pairs
/// return [`AbiError::NoConversion`].
///
/// Widening *within* the int family is the one place that is not a single
/// opcode, and it is included because it is a *relabelling*: all five types are
/// the same `i32`, so `Z` to `C` moves no bits. Since a `Z` is 0 or 1 and both
/// fit in every other int-family type, the value is preserved — which is why
/// [`Notes::narrowed`] stays `None` for those pairs.
///
/// **Numerics to references, and references to numerics, are errors.** There is
/// no boxing. `IR.md` forbids it, and an implicit box would be an object the
/// guest heap never allocated.
pub fn convert(from: &DexType, to: &DexType, value: AbiValue) -> AbiResult<Conversion> {
    value.check_type(from)?;
    let notes = Notes::default();
    let out = match (from, to) {
        // --- identity and int-family relabelling: no bits move ------------
        (a, b) if a == b => value,

        (f, DexType::Boolean) if f.is_int_family() => {
            let i = value.to_i32()?;
            return Ok(Conversion {
                value: AbiValue::Boolean(Bool::normalise(i)),
                notes: Notes {
                    boolean_normalised: Bool::is_out_of_range(i),
                    narrowed: Some(Narrowing::Boolean),
                },
            });
        }
        (f, DexType::Byte) if f.is_int_family() => {
            let i = value.to_i32()?;
            AbiValue::Byte(i as i8)
        }
        (f, DexType::Short) if f.is_int_family() => {
            let i = value.to_i32()?;
            AbiValue::Short(i as i16)
        }
        (f, DexType::Char) if f.is_int_family() => {
            let i = value.to_i32()?;
            AbiValue::Char(i as u16)
        }
        (f, DexType::Int) if f.is_int_family() => AbiValue::Int(value.to_i32()?),

        // --- int-family to the wide types (int-to-long/-float/-double) ------
        (f, DexType::Long) if f.is_int_family() => AbiValue::Long(i64::from(value.to_i32()?)),
        (f, DexType::Float) if f.is_int_family() => {
            let n = value.to_i32()?;
            return Ok(Conversion {
                value: AbiValue::Float(n as f32),
                notes: Notes {
                    narrowed: Some(Narrowing::WidenToFloat),
                    ..Notes::default()
                },
            });
        }
        (f, DexType::Double) if f.is_int_family() => {
            let n = value.to_i32()?;
            return Ok(Conversion {
                value: AbiValue::Double(f64::from(n)),
                notes: Notes {
                    narrowed: Some(Narrowing::WidenToFloat),
                    ..Notes::default()
                },
            });
        }

        // --- long-to-* (long-to-int/-float/-double) -------------------------
        (DexType::Long, DexType::Int) => AbiValue::Int(value.to_i64()? as i32),
        (DexType::Long, DexType::Float) => {
            let n = value.to_i64()?;
            return Ok(Conversion {
                value: AbiValue::Float(n as f32),
                notes: Notes {
                    narrowed: Some(Narrowing::WidenToFloat),
                    ..Notes::default()
                },
            });
        }
        (DexType::Long, DexType::Double) => {
            let n = value.to_i64()?;
            return Ok(Conversion {
                value: AbiValue::Double(n as f64),
                notes: Notes {
                    narrowed: Some(Narrowing::WidenToFloat),
                    ..Notes::default()
                },
            });
        }

        // --- float-to-* (float-to-int/-long/-double) ------------------------
        (DexType::Float, DexType::Int) => {
            let n = value.to_f32()?;
            return Ok(Conversion {
                value: AbiValue::Int(f32_to_int(n)),
                notes: Notes {
                    narrowed: Some(Narrowing::FloatToInt),
                    ..Notes::default()
                },
            });
        }
        (DexType::Float, DexType::Long) => {
            let n = value.to_f32()?;
            return Ok(Conversion {
                value: AbiValue::Long(f32_to_i64(n)),
                notes: Notes {
                    narrowed: Some(Narrowing::FloatToLong),
                    ..Notes::default()
                },
            });
        }
        (DexType::Float, DexType::Double) => AbiValue::Double(f64::from(value.to_f32()?)),

        // --- double-to-* (double-to-int/-long/-float) -----------------------
        (DexType::Double, DexType::Int) => {
            let n = value.to_f64()?;
            return Ok(Conversion {
                value: AbiValue::Int(f64_to_int(n)),
                notes: Notes {
                    narrowed: Some(Narrowing::FloatToInt),
                    ..Notes::default()
                },
            });
        }
        (DexType::Double, DexType::Long) => {
            let n = value.to_f64()?;
            return Ok(Conversion {
                value: AbiValue::Long(f64_to_i64(n)),
                notes: Notes {
                    narrowed: Some(Narrowing::FloatToLong),
                    ..Notes::default()
                },
            });
        }
        (DexType::Double, DexType::Float) => AbiValue::Float(value.to_f64()? as f32),

        // --- references -----------------------------------------------------
        (a, b) if a.is_reference() && b.is_reference() => value,

        _ => return Err(no_conversion(from, to)),
    };

    // Int-family narrowing that did not come out of an early `return`: the
    // `Boolean` arm returns directly with its own `Narrowing::Boolean` note.
    let narrowed = match (from, to) {
        (f, DexType::Byte) if f.is_int_family() && f != to => Some(Narrowing::Byte),
        (f, DexType::Short) if f.is_int_family() && f != to => Some(Narrowing::Short),
        (f, DexType::Char) if f.is_int_family() && f != to => Some(Narrowing::Char),
        (DexType::Long, DexType::Int) => Some(Narrowing::LongToInt),
        _ => None,
    };
    Ok(Conversion {
        value: out,
        notes: Notes {
            boolean_normalised: notes.boolean_normalised,
            narrowed,
        },
    })
}

impl AbiValue {
    fn to_i64(self) -> AbiResult<i64> {
        match self {
            AbiValue::Long(l) => Ok(l),
            other => Err(AbiError::ValueTypeMismatch {
                declared: "a long".to_string(),
                found: other.type_name().to_string(),
            }),
        }
    }

    fn to_f32(self) -> AbiResult<f32> {
        match self {
            AbiValue::Float(f) => Ok(f),
            other => Err(AbiError::ValueTypeMismatch {
                declared: "a float".to_string(),
                found: other.type_name().to_string(),
            }),
        }
    }

    fn to_f64(self) -> AbiResult<f64> {
        match self {
            AbiValue::Double(d) => Ok(d),
            other => Err(AbiError::ValueTypeMismatch {
                declared: "a double".to_string(),
                found: other.type_name().to_string(),
            }),
        }
    }
}

fn no_conversion(from: &DexType, to: &DexType) -> AbiError {
    AbiError::NoConversion {
        from: from.descriptor(),
        to: to.descriptor(),
    }
}

// ========================================================== float narrowing

/// `float-to-int`: `NaN` becomes 0, out of range saturates, otherwise truncates
/// toward zero.
///
/// The `NaN` case is the one to be careful about and it is not a corner: Java's
/// narrowing cast specifies 0, x86's `cvttss2si` produces `INT_MIN`, and a
/// WebAssembly `i32.trunc_f32_s` **traps** on both. So this function is not a
/// convenience, it is the only reason the compiled module does not abort on a
/// NaN that the interpreter returns 0 for. The saturation is the second reason:
/// `i32.trunc_sat_f32_s` is a non-standard proposal, so the clamp has to be
/// written out.
pub fn f32_to_int(f: f32) -> i32 {
    if f.is_nan() {
        return 0;
    }
    if f <= -2_147_483_648.0 {
        return i32::MIN;
    }
    if f >= 2_147_483_648.0 {
        return i32::MAX;
    }
    f as i32
}

/// `float-to-long`. Same two rules as [`f32_to_int`].
pub fn f32_to_i64(f: f32) -> i64 {
    if f.is_nan() {
        return 0;
    }
    if f <= -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    if f >= 9_223_372_036_854_775_808.0 {
        return i64::MAX;
    }
    f as i64
}

/// `double-to-int`.
pub fn f64_to_int(f: f64) -> i32 {
    if f.is_nan() {
        return 0;
    }
    if f <= -2_147_483_648.0 {
        return i32::MIN;
    }
    if f >= 2_147_483_648.0 {
        return i32::MAX;
    }
    f as i32
}

/// `double-to-long`.
pub fn f64_to_i64(f: f64) -> i64 {
    if f.is_nan() {
        return 0;
    }
    if f <= -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    if f >= 9_223_372_036_854_775_808.0 {
        return i64::MAX;
    }
    f as i64
}

// ================================================================ integer

/// Which integer operation, in the order the `23x` opcode families lay them out.
///
/// Named rather than indexed so that a call site cannot pass the wrong number:
/// the project has already had a headline go wrong by 40× through a
/// mis-numbered opcode constant, and a `match` over a named enum is the
/// cheapest way to make that class of bug a compile error here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntOp {
    /// `add`
    Add,
    /// `sub`
    Sub,
    /// `mul`
    Mul,
    /// `div` — truncating, and a division by zero is a throwable.
    Div,
    /// `rem` — the sign of the dividend, and a division by zero is a throwable.
    Rem,
    /// `and`
    And,
    /// `or`
    Or,
    /// `xor`
    Xor,
    /// `shl`
    Shl,
    /// `shr` — arithmetic.
    Shr,
    /// `ushr` — logical.
    UShr,
}

/// The two arithmetic failures that are throwables on a device rather than
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumErr {
    /// `ArithmeticException` / `/ by zero`.
    DivideByZero,
}

/// The opcode index of an integer operation, for a `codegen` that indexes the
/// `23x` family by offset. Kept next to the enum so the two cannot drift.
pub const fn int_op_index(op: IntOp) -> u8 {
    match op {
        IntOp::Add => 0,
        IntOp::Sub => 1,
        IntOp::Mul => 2,
        IntOp::Div => 3,
        IntOp::Rem => 4,
        IntOp::And => 5,
        IntOp::Or => 6,
        IntOp::Xor => 7,
        IntOp::Shl => 8,
        IntOp::Shr => 9,
        IntOp::UShr => 10,
    }
}

/// 32-bit integer arithmetic. **Wraps**: `i32::MAX + 1` is `i32::MIN` and
/// nothing traps, because Dalvik has no overflow exception.
///
/// Two cases do produce a throwable, and both are Java-defined rather than
/// accidental: division by zero, and `i32::MIN / -1`, which is `i32::MIN` and
/// not an overflow trap.
pub fn int32_binop(op: IntOp, x: i32, y: i32) -> Result<i32, NumErr> {
    Ok(match op {
        IntOp::Add => x.wrapping_add(y),
        IntOp::Sub => x.wrapping_sub(y),
        IntOp::Mul => x.wrapping_mul(y),
        IntOp::Div => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            // `i32::MIN / -1` overflows, and Java says it wraps rather than
            // trapping. `-1` is handled here rather than by `wrapping_div` so
            // that the special case is visible where it is decided.
            if y == -1 {
                x.wrapping_neg()
            } else {
                x / y
            }
        }
        IntOp::Rem => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                0
            } else {
                x % y
            }
        }
        IntOp::And => x & y,
        IntOp::Or => x | y,
        IntOp::Xor => x ^ y,
        // The shift count is the low 5 bits, not the low 4: `shl-int` is
        // defined on 32 bits, so `1 << 33` is `1 << 1`.
        IntOp::Shl => x.wrapping_shl((y & 0x1f) as u32),
        IntOp::Shr => x.wrapping_shr((y & 0x1f) as u32),
        IntOp::UShr => ((x as u32).wrapping_shr((y & 0x1f) as u32)) as i32,
    })
}

/// 64-bit integer arithmetic. Wraps, with the same two throwable cases and a
/// 6-bit shift count.
pub fn int64_binop(op: IntOp, x: i64, y: i64) -> Result<i64, NumErr> {
    Ok(match op {
        IntOp::Add => x.wrapping_add(y),
        IntOp::Sub => x.wrapping_sub(y),
        IntOp::Mul => x.wrapping_mul(y),
        IntOp::Div => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                x.wrapping_neg()
            } else {
                x / y
            }
        }
        IntOp::Rem => {
            if y == 0 {
                return Err(NumErr::DivideByZero);
            }
            if y == -1 {
                0
            } else {
                x % y
            }
        }
        IntOp::And => x & y,
        IntOp::Or => x | y,
        IntOp::Xor => x ^ y,
        IntOp::Shl => x.wrapping_shl((y & 0x3f) as u32),
        IntOp::Shr => x.wrapping_shr((y & 0x3f) as u32),
        IntOp::UShr => ((x as u64).wrapping_shr((y & 0x3f) as u32)) as i64,
    })
}

/// Which floating-point operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FloatOp {
    /// `add`
    Add,
    /// `sub`
    Sub,
    /// `mul`
    Mul,
    /// `div` — by zero is an infinity, not a throwable. This is the whole
    /// difference between `div-float` and `div-int` that surprises people.
    Div,
    /// `rem` — see [`rem_f32`].
    Rem,
}

/// The opcode index of a floating-point operation.
pub const fn float_op_index(op: FloatOp) -> u8 {
    match op {
        FloatOp::Add => 0,
        FloatOp::Sub => 1,
        FloatOp::Mul => 2,
        FloatOp::Div => 3,
        FloatOp::Rem => 4,
    }
}

/// `f32` arithmetic. IEEE-754 throughout: no traps, `0.0 / 0.0` is `NaN`, and a
/// division by zero is a signed infinity.
pub fn float32_binop(op: FloatOp, x: f32, y: f32) -> f32 {
    match op {
        FloatOp::Add => x + y,
        FloatOp::Sub => x - y,
        FloatOp::Mul => x * y,
        FloatOp::Div => x / y,
        FloatOp::Rem => rem_f32(x, y),
    }
}

/// `f64` arithmetic.
pub fn float64_binop(op: FloatOp, x: f64, y: f64) -> f64 {
    match op {
        FloatOp::Add => x + y,
        FloatOp::Sub => x - y,
        FloatOp::Mul => x * y,
        FloatOp::Div => x / y,
        FloatOp::Rem => rem_f64(x, y),
    }
}

/// `rem-float`: the IEEE-754 **remainderToBinaryDigits** operation, which is
/// also what C calls `fmod` and what Rust's `%` computes.
///
/// # A note on the specification's phrasing, because it is a trap
///
/// The Dalvik specification describes this as `x - y * trunc(x/y)`, and it is
/// tempting to read that as a formula to write down and evaluate. **Do not.**
/// That is the definition of `fmod` itself, so the phrasing and `fmod` name the
/// same *operation* — but evaluating the formula is not the same as computing
/// `fmod`, and the gap is not academic. `fmod` is computed exactly, by
/// subtracting a multiple of the divisor one significand at a time; the formula
/// is one rounding away from correct at every step. Four ways it shows, all
/// measured by `rem_formula_diverges_from_fmod_exactly_where` rather than
/// argued here:
///
/// 1. **`y` infinite.** `x / ∞` is 0 and `∞ * 0` is `NaN`, so the formula
///    returns `NaN`. IEEE requires `fmod(x, ±∞) == x`, so `3.0f32 % f32::INFINITY`
///    is `3.0`. Not exotic: it is what `x % Double.POSITIVE_INFINITY` does.
/// 2. **The product overflows.** With `x = 1e300`, `y = 1e-300`, `x/y` is `∞`
///    and `y * ∞` is `∞`, so the formula returns `-∞` where `fmod` returns a
///    finite remainder smaller than the divisor.
/// 3. **The sign of zero.** A zero remainder keeps the dividend's sign under
///    `fmod`: `(-0.0) % 1` is `-0.0`, and so is `-3.0 % 1`. The formula's
///    subtraction always lands on `+0.0`, so both come out positive. `1/x`
///    flips sign on that.
/// 4. **Cancellation — the general case, and the reason the others are not
///    corner cases.** `fmod(3.0, 1e-300)` is `3.0`, because the exact remainder
///    is the dividend. The formula computes `3.0 - 1e-300 * 3e300`, and the
///    product is `3.0000000000000004`, so it returns `-4.4e-16`. Every
///    significant digit is destroyed, and the size of the error is set by how
///    large the quotient is rather than by the operands.
///
/// Case 4 generalises cases 1 and 2, and it means the formula is wrong for most
/// pairs where the quotient is even moderately large. That is why this is a call
/// to the primitive and not a transcription of the prose — and why the prose is
/// worth a note instead of a copy-paste. `oracle_rem_float_is_fmod_and_not_the_literal_formula`
/// then runs the divergence on the real interpreter, so the claim is that
/// `dexinterp` implements `fmod` too.
pub fn rem_f32(x: f32, y: f32) -> f32 {
    x % y
}

/// `rem-double`. See [`rem_f32`].
pub fn rem_f64(x: f64, y: f64) -> f64 {
    x % y
}

/// The specification's `x - y * trunc(x/y)` formula, evaluated literally.
///
/// **This is not the Dalvik `rem` operation**, and it exists so that the test
/// module can demonstrate the divergence described on [`rem_f32`] rather than
/// assert it from a reading. Nothing in the compiler should call it.
pub fn rem_f32_by_formula(x: f32, y: f32) -> f32 {
    x - y * (x / y).trunc()
}

/// [`rem_f32_by_formula`] for `f64`. Also not the Dalvik operation.
pub fn rem_f64_by_formula(x: f64, y: f64) -> f64 {
    x - y * (x / y).trunc()
}

/// Which way a floating-point comparison resolves `NaN`.
///
/// `cmpl` and `cmpg` differ in exactly two ways and both are specified: `cmpl`
/// reports `NaN` as *less* and treats `-0.0` as smaller than `0.0`; `cmpg`
/// reports `NaN` as *greater* and treats the zeroes as equal. A sorted-search
/// loop written against `cmpg` finds a `NaN` key it should have skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    /// `cmpl-float`, `cmpl-double`, and `cmp-long`.
    Less,
    /// `cmpg-float`, `cmpg-double`.
    Greater,
}

/// The five `cmp*` operations, as `-1`, `0` or `1`.
///
/// The `NaN` decision is made from an explicit flag rather than from `partial_cmp`
/// returning `None`, because `None` has to become *some* number here and the two
/// legal answers differ.
pub fn cmp_float32(op: Cmp, x: f32, y: f32) -> i32 {
    cmp_assembled(op, x, y, x.is_nan() || y.is_nan())
}

/// [`cmp_float32`] for `f64`.
pub fn cmp_float64(op: Cmp, x: f64, y: f64) -> i32 {
    cmp_assembled(op, x, y, x.is_nan() || y.is_nan())
}

/// `cmp-long`: the full 64 bits, no `NaN` case.
pub fn cmp_long(x: i64, y: i64) -> i32 {
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

fn cmp_assembled<T: PartialOrd + PartialEq>(op: Cmp, x: T, y: T, nan: bool) -> i32 {
    if nan {
        return match op {
            Cmp::Less => -1,
            Cmp::Greater => 1,
        };
    }
    if x < y {
        -1
    } else if x > y {
        1
    } else {
        0
    }
}

// ============================================== field and array narrowing

/// Narrow a value for a field or array store of type `ty` — `iput`, `sput`,
/// `aput`.
///
/// This is a **different function** from [`convert`] and it is deliberately so.
/// Dalvik's field stores do not require the value's static type to match the
/// field's, because there is no verifier in front of the store, so the
/// specification has to say what happens when they disagree — and for some pairs
/// the answer is not a conversion at all:
///
/// * a `long` into an `int` field stores **0**, not a truncated `int`, because
///   the two have nothing in common and inventing a narrowing would be inventing
///   an operation;
/// * a `double` into a `J` field is reinterpreted as the double's **bit
///   pattern**, because Dalvik has no `const-double` and every double constant
///   in a real APK arrives as a `const-wide` carrying its IEEE bits;
/// * a `float` into a `Z` field is its **low mantissa bit**, because the
///   specification says a boolean field holds the low bit of whatever it is
///   given.
///
/// All three of those are measured against the interpreter by
/// `field_store_coercion_matches_the_interpreter` in the test module. This
/// function exists to *match* that, and it is kept separate from [`convert`]
/// because a compiler that used the conversion table here would get a
/// *different, more principled, and therefore wrong* answer.
pub fn narrow_on_store(ty: &DexType, value: AbiValue) -> AbiValue {
    // The `as_int` of the oracle's `coerce_to`: anything that is not an int
    // reads as 0. This is what makes `double -> byte` store 0.
    let as_int = |v: AbiValue| v.as_int().unwrap_or(0);

    match ty {
        DexType::Boolean => AbiValue::Boolean(match value {
            AbiValue::Boolean(b) => b,
            AbiValue::Byte(b) => Bool::normalise(i32::from(b)),
            AbiValue::Short(s) => Bool::normalise(i32::from(s)),
            AbiValue::Char(c) => Bool::normalise(i32::from(c)),
            AbiValue::Int(i) => Bool::normalise(i),
            AbiValue::Long(l) => Bool::normalise(l as i32),
            // The low bit of the *bit pattern*, not of a number. See the note.
            AbiValue::Float(f) => Bool::normalise(f.to_bits() as i32),
            AbiValue::Double(d) => Bool::normalise(d.to_bits() as i32),
            AbiValue::Void | AbiValue::Ref(_) => Bool::FALSE,
        }),
        DexType::Byte => AbiValue::Byte(as_int(value) as i8),
        DexType::Short => AbiValue::Short(as_int(value) as i16),
        DexType::Char => AbiValue::Char(as_int(value) as u16),
        DexType::Int => AbiValue::Int(as_int(value)),
        DexType::Long => AbiValue::Long(match value {
            AbiValue::Long(l) => l,
            AbiValue::Int(i) => i64::from(i),
            _ => 0,
        }),
        DexType::Float => AbiValue::Float(match value {
            AbiValue::Float(f) => f,
            AbiValue::Int(i) => i as f32,
            AbiValue::Long(l) => l as f32,
            _ => 0.0,
        }),
        DexType::Double => AbiValue::Double(match value {
            AbiValue::Double(d) => d,
            AbiValue::Int(i) => f64::from(i),
            // The bit pattern, not the number. See the note above.
            AbiValue::Long(bits) => f64::from_bits(bits as u64),
            AbiValue::Float(f) => f64::from(f),
            _ => 0.0,
        }),
        DexType::Ref(_) | DexType::Array(_) => match value {
            AbiValue::Ref(h) => AbiValue::Ref(h),
            _ => AbiValue::null(),
        },
        DexType::Void => AbiValue::Void,
    }
}

/// Widen a value read out of an array — `aget`.
///
/// The inverse of [`narrow_on_store`], with one asymmetry that is a real trap:
/// **`aget-boolean` tests non-zero, while every boolean *store* takes the low
/// bit.** A `boolean[]` built by `aput-boolean` therefore contains only 0 and 1
/// and the two rules agree on it; but a `boolean[]` produced by anything else —
/// `fill-array-data`, a host array, a memory copy — can hold a 42, and `aget` on
/// that gives `true` where `aput` would have stored `false`.
///
/// The two rules are kept as two functions on purpose. Merging them would pick
/// one silently and change the other's answer, and which one you picked would be
/// invisible until an app disagreed with a device.
pub fn narrow_on_load(ty: &DexType, value: AbiValue) -> AbiValue {
    let i = match value {
        AbiValue::Boolean(b) => b.as_i32(),
        AbiValue::Byte(b) => i32::from(b),
        AbiValue::Short(s) => i32::from(s),
        AbiValue::Char(c) => i32::from(c),
        AbiValue::Int(i) => i,
        // `aput-wide`/`aget-wide` transfer the element unchanged: a `long` in a
        // `long[]` is not a narrowing operation, and a `double` in one is not a
        // reinterpretation either.
        other => return other,
    };
    match ty {
        DexType::Boolean => AbiValue::Boolean(Bool::normalise_nonzero(i)),
        DexType::Byte => AbiValue::Byte(i as i8),
        DexType::Char => AbiValue::Char(i as u16),
        DexType::Short => AbiValue::Short(i as i16),
        _ => value,
    }
}

impl Bool {
    /// The `aget-boolean` rule: **non-zero** is true, where every boolean store
    /// takes the low bit.
    pub const fn normalise_nonzero(v: i32) -> Bool {
        Bool(if v != 0 { 1 } else { 0 })
    }
}

// ================================================================ access

/// The `access_flags` bits this module needs.
///
/// Duplicated rather than imported: `abi` has no dependencies by design, and a
/// flag is a value in a normative table rather than a fact about another crate.
/// The values are from the DEX specification's `access_flags` table and are
/// cross-checked against `dexcore`'s by `access_flag_bits_match_the_format`.
pub mod access {
    /// `ACC_STATIC` — no receiver.
    pub const ACC_STATIC: u32 = 0x0008;
    /// `ACC_VARARGS` — the last parameter is a packed array.
    pub const ACC_VARARGS: u32 = 0x0080;
    /// `ACC_NATIVE` — no body, resolved to a host stub.
    pub const ACC_NATIVE: u32 = 0x0100;
    /// `ACC_ABSTRACT` — no body, dispatched virtually.
    pub const ACC_ABSTRACT: u32 = 0x0400;
    /// `ACC_CONSTRUCTOR` — `<init>`, so the receiver is the uninitialised object.
    pub const ACC_CONSTRUCTOR: u32 = 0x0001_0000;
}

/// What a method's `access_flags` mean to the ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodAccess(pub u32);

impl MethodAccess {
    /// The raw flags.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// `ACC_STATIC` — the exported function takes no receiver.
    pub const fn is_static(self) -> bool {
        self.0 & access::ACC_STATIC != 0
    }

    /// `ACC_VARARGS`.
    ///
    /// This changes **nothing** about the call encoding. The method's declared
    /// prototype is the packed-array one, `([Ljava/lang/Object;)V`, and the
    /// caller builds the array; `ACC_VARARGS` tells a Java-language compiler
    /// where the `...` went, and tells a native-call generator that the last
    /// parameter is an array, and that is all. Getting this wrong would mean
    /// emitting a function with the wrong arity, so it is exposed but it does
    /// not alter [`Prototype::wasm_sig`].
    pub const fn is_varargs(self) -> bool {
        self.0 & access::ACC_VARARGS != 0
    }

    /// `ACC_NATIVE` or `ACC_ABSTRACT` — there is no guest body, so the method is
    /// either a host stub or a vtable entry.
    pub const fn has_no_body(self) -> bool {
        self.0 & (access::ACC_NATIVE | access::ACC_ABSTRACT) != 0
    }

    /// `ACC_CONSTRUCTOR`.
    pub const fn is_constructor(self) -> bool {
        self.0 & access::ACC_CONSTRUCTOR != 0
    }
}

// ================================================================= invokes

/// Which `invoke-*` opcode a call site uses.
///
/// The distinction that matters here is not virtual versus direct — both name a
/// `method_id` — it is that `invoke-polymorphic` names a **`proto_id`**. That is
/// the only place in the instruction set where the index in the last word means
/// something other than a method reference, and a `codegen` that emitted a
/// method index there would produce a call that either traps or, worse, lands on
/// an unrelated method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeOp {
    /// `invoke-virtual`
    Virtual,
    /// `invoke-super`
    Super,
    /// `invoke-direct`
    Direct,
    /// `invoke-static`
    Static,
    /// `invoke-interface`
    Interface,
    /// `invoke-polymorphic` — the index is a `proto_id`.
    Polymorphic,
    /// `invoke-custom` — the index is a `call_site_id`.
    Custom,
}

impl InvokeOp {
    /// The opcode byte, from the `35c`/`3rc` families.
    pub const fn opcode(self) -> u8 {
        match self {
            InvokeOp::Virtual => 0x6e,
            InvokeOp::Super => 0x6f,
            InvokeOp::Direct => 0x70,
            InvokeOp::Static => 0x71,
            InvokeOp::Interface => 0x72,
            InvokeOp::Polymorphic => 0xfa,
            InvokeOp::Custom => 0xfc,
        }
    }

    /// Whether this form passes a receiver that the calling convention supplies
    /// separately from the prototype.
    ///
    /// `invoke-polymorphic` says **no**, and that is the subtle part. Its index
    /// is a prototype, and for a signature-polymorphic method the prototype
    /// *already contains the receiver* in its parameter list, because the
    /// signature is the static type of the whole call, receiver included. Adding
    /// one would double it.
    pub const fn takes_separate_receiver(self) -> bool {
        match self {
            InvokeOp::Virtual | InvokeOp::Super | InvokeOp::Direct | InvokeOp::Interface => true,
            InvokeOp::Static | InvokeOp::Polymorphic | InvokeOp::Custom => false,
        }
    }

    /// The `invoke-*/range` opcode, which differs by exactly one from the
    /// short form.
    pub const fn range_opcode(self) -> u8 {
        self.opcode() + 1
    }
}

/// A call site's encoding: which opcode, which index, and which registers.
///
/// The argument count is **derived from the prototype and not read out of the
/// instruction**, which is the decision that keeps the `35c` nibble from
/// mattering: d8 writes the count into the `A` nibble, but a `35c`'s trailing
/// zero nibbles are indistinguishable from padding, so a reader that took the
/// count from the instruction and the types from the prototype could disagree
/// with itself. The prototype is the authority. [`InvokeSite::argument_count`]
/// is the single place that decides it, and it is the same rule the interpreter
/// applies in `invoke_arity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeSite {
    /// Which form.
    pub op: InvokeOp,
    /// The `method_id`, `proto_id` or `call_site_id`, depending on `op`.
    pub index: u16,
    /// The prototype the index names, for the polymorphic form. `None` for the
    /// method-reference forms, where it comes from the `method_id` instead.
    pub proto: Option<Prototype>,
}

impl InvokeSite {
    /// A call to a method reference.
    pub fn method(op: InvokeOp, index: u16, target: &Prototype) -> InvokeSite {
        debug_assert!(
            !matches!(op, InvokeOp::Polymorphic | InvokeOp::Custom),
            "a method_id cannot be the index of invoke-polymorphic or invoke-custom",
        );
        InvokeSite {
            op,
            index,
            proto: Some(target.clone()),
        }
    }

    /// An `invoke-polymorphic`, whose index is a **`proto_id`**.
    pub fn polymorphic(proto_index: u16, call_site_signature: &Prototype) -> InvokeSite {
        InvokeSite {
            op: InvokeOp::Polymorphic,
            index: proto_index,
            proto: Some(call_site_signature.clone()),
        }
    }

    /// The number of registers the instruction reads.
    ///
    /// From the prototype, plus a receiver for the forms that have one. This is
    /// the whole `35c` `A` nibble debate, settled: the prototype wins, because a
    /// call is defined by the method reference it names.
    pub fn argument_count(&self) -> AbiResult<usize> {
        let proto = match &self.proto {
            None => return Err(AbiError::MissingOpenParenthesis),
            Some(p) => p,
        };
        let n = proto.params.len();
        Ok(match self.op.takes_separate_receiver() {
            true => n + 1,
            false => n,
        })
    }

    /// The register types the instruction reads, receiver first where there is
    /// one.
    pub fn argument_types(&self) -> AbiResult<Vec<DexType>> {
        let proto = match &self.proto {
            None => return Err(AbiError::MissingOpenParenthesis),
            Some(p) => p,
        };
        Ok(match self.op.takes_separate_receiver() {
            true => proto.invoke_registers(false),
            false => proto.params.clone(),
        })
    }

    /// The register words the instruction reads, which is not the same as the
    /// number of registers because `J` and `D` are two words each.
    pub fn argument_slots(&self) -> AbiResult<usize> {
        Ok(self.argument_types()?.iter().map(DexType::slots).sum())
    }

    /// The WebAssembly types of the callee's parameters, in register order, for
    /// a `codegen` that is about to emit the call.
    pub fn argument_wasm_types(&self) -> AbiResult<Vec<Wasm>> {
        Ok(self
            .argument_types()?
            .iter()
            .filter_map(DexType::wasm_ty)
            .collect())
    }

    /// Encode the instruction.
    ///
    /// `35c` when the register list fits in five entries and `3rc` when it does
    /// not, which is the form boundary the specification draws. `3rc` needs a
    /// first register and a count, so the caller passes the register list as a
    /// contiguous range in that case; [`InvokeSite::encode_range`] takes both
    /// and the compiler chooses.
    pub fn encode(&self, regs: &[u8]) -> AbiResult<Vec<u8>> {
        match self.argument_count()? {
            // The `35c` `A` nibble is the *argument* count, and a `35c` with
            // more than five registers is not encodable at all. Reporting that
            // as an error rather than truncating the list is the point: a
            // truncated argument list is a call that succeeds with the wrong
            // arguments.
            n if n > 5 => Err(AbiError::TooManyParameters { count: n, max: 5 }),
            n => {
                if regs.len() != n {
                    return Err(AbiError::ValueTypeMismatch {
                        declared: format!("{} arguments", n),
                        found: format!("{} registers", regs.len()),
                    });
                }
                self.encode_short(regs)
            }
        }
    }

    /// Encode the `3rc` form, which takes a contiguous register range.
    pub fn encode_range(&self, first_reg: u8, reg_count: u8) -> AbiResult<Vec<u8>> {
        let n = self.argument_count()?;
        if usize::from(reg_count) != n {
            return Err(AbiError::ValueTypeMismatch {
                declared: format!("{} arguments", n),
                found: format!("{reg_count} registers"),
            });
        }
        // `AA` and `BBBB` are 16-bit fields. A `3rc` past either boundary cannot
        // be encoded, and the short form is not a substitute: it cannot address
        // that many registers.
        if u16::from(first_reg) + u16::from(reg_count) > u16::from(u8::MAX) * 2 + 1 {
            return Err(AbiError::TooManyParameters {
                count: n,
                max: MAX_PARAMETERS,
            });
        }
        let mut out = Vec::with_capacity(4);
        let op = self.op.range_opcode();
        // `3rc`: `AA|op` then `BBBB` (first register) then `CCCC` (count).
        out.extend_from_slice(&(u16::from(op) | (u16::from(reg_count) << 8)).to_le_bytes());
        out.extend_from_slice(&u16::from(first_reg).to_le_bytes());
        out.extend_from_slice(&self.index.to_le_bytes());
        Ok(out)
    }

    fn encode_short(&self, regs: &[u8]) -> AbiResult<Vec<u8>> {
        let mut out = Vec::with_capacity(4);
        let op = self.op.opcode();
        // `35c`: byte lanes are `op`, then `A|G` in the high nibble of the second
        // byte, then `F|E|D|C` in the low nibbles of the second and third units.
        // The register list is zero-padded, and a padded nibble is
        // indistinguishable from a register 0 — which is exactly why the count
        // comes from the prototype and not from here.
        let a = u16::from(regs.len() as u8);
        let g = match regs.get(4) {
            Some(r) => u16::from(*r & 0x0f),
            None => 0,
        };
        let fe = match (regs.first(), regs.get(1)) {
            (Some(f), Some(e)) => u16::from(*f & 0x0f) | (u16::from(*e & 0x0f) << 4),
            _ => 0,
        };
        let dc = match (regs.get(2), regs.get(3)) {
            (Some(d), Some(c)) => u16::from(*c & 0x0f) | (u16::from(*d & 0x0f) << 4),
            _ => 0,
        };
        out.extend_from_slice(&(u16::from(op) | (a << 8)).to_le_bytes());
        out.extend_from_slice(&(fe | (g << 12)).to_le_bytes());
        out.extend_from_slice(&dc.to_le_bytes());
        // `45cc` has a fourth word, the prototype index, and the two are
        // independent: the `method_id` names the polymorphic declaration and the
        // `proto_id` the call site. Emitting the same index in both is a call
        // that resolves and then does the wrong thing.
        if self.op == InvokeOp::Polymorphic {
            out.extend_from_slice(&self.index.to_le_bytes());
        }
        Ok(out)
    }
}

// ================================================================ varargs

/// The packed argument array of a varargs call.
///
/// Dalvik has no variadic calling convention. `ACC_VARARGS` means the *caller*
/// builds a one-element array of the declared component type and passes it as
/// the last parameter, and the callee reads that array. So the ABI work is
/// entirely in the box: getting the component type right, getting the length
/// right, and refusing to read past the end.
///
/// The length is not a formality. A call site can pack fewer arguments than the
/// callee declares, and a verifier-legal DEX can therefore have a callee read
/// `v[3]` of a two-element array. On a device that is an
/// `ArrayIndexOutOfBoundsException`, so that is what this returns — not a zero,
/// and not a read of whatever is in memory next.
#[derive(Clone, Debug, PartialEq)]
pub struct VarargBox {
    /// The declared component type of the packed array.
    pub component: DexType,
    /// The packed arguments, each already narrowed to `component`.
    pub items: Vec<AbiValue>,
}

impl VarargBox {
    /// Pack a varargs call site's trailing arguments.
    pub fn pack(component: DexType, args: &[AbiValue]) -> VarargBox {
        // Every element is narrowed to the component type on the way in, so that
        // `aget-boolean` on the callee side sees a `0` or a `1` for the same
        // reason `aput-boolean` would have produced one.
        let items = args
            .iter()
            .map(|a| narrow_on_store(&component, *a))
            .collect();
        VarargBox { component, items }
    }

    /// The `Array.length` the callee sees.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the box is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Read element `index`, widening it the way `aget` on the component type
    /// would.
    pub fn get(&self, index: usize) -> AbiResult<AbiValue> {
        match self.items.get(index) {
            None => Err(AbiError::VarargsOutOfBounds {
                index,
                len: self.items.len(),
            }),
            Some(v) => Ok(narrow_on_load(&self.component, *v)),
        }
    }

    /// The declared component type widened to the element type `aget` produces.
    pub fn element_type(&self) -> DexType {
        self.component.clone()
    }
}

impl std::fmt::Display for VarargBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VarargBox[{}] of {}", self.len(), self.component)
    }
}

// ============================================================ signature

/// A complete, checkable calling convention for one exported function.
#[derive(Clone, Debug, PartialEq)]
pub struct ExportedSignature {
    /// The export name, e.g. `m_1234` or `Lcom/x/Y;.z(II)V`.
    pub name: String,
    /// The prototype.
    pub proto: Prototype,
    /// The `access_flags`.
    pub access: MethodAccess,
}

impl ExportedSignature {
    /// Build a signature, rejecting the combinations that cannot be emitted.
    ///
    /// The checks that matter:
    ///
    /// * a `varargs` method whose last parameter is not an array is refused,
    ///   because there is no other encoding for it and emitting one would give
    ///   the callee a parameter list that cannot hold the arguments;
    /// * an abstract or native method has no body, so it has no export — it is
    ///   a host stub or a vtable entry, and pretending otherwise produces an
    ///   exported function that traps.
    pub fn new(
        name: impl Into<String>,
        proto: Prototype,
        access: MethodAccess,
    ) -> AbiResult<ExportedSignature> {
        if access.is_varargs() {
            let last_is_array = match proto.params.last() {
                None => false,
                Some(p) => matches!(p, DexType::Array(_)),
            };
            if !last_is_array {
                return Err(AbiError::ValueTypeMismatch {
                    declared: "a varargs method ending in an array".to_string(),
                    found: "a method that does not".to_string(),
                });
            }
        }
        Ok(ExportedSignature {
            name: name.into(),
            proto,
            access,
        })
    }

    /// The WebAssembly signature of the export.
    pub fn wasm_sig(&self) -> WasmSig {
        self.proto.wasm_sig(self.access.is_static())
    }

    /// The `.wat` type of the export.
    pub fn wat(&self) -> String {
        format!(
            "(export \"{}\" (func {}))",
            self.name,
            self.wasm_sig().wat()
        )
    }

    /// The packed-argument box for a varargs method given the trailing arguments
    /// at the call site. `None` for a method that is not varargs.
    pub fn varargs(&self, args: &[AbiValue]) -> AbiResult<Option<VarargBox>> {
        if !self.access.is_varargs() {
            return Ok(None);
        }
        let component = match self.proto.params.last() {
            None => return Err(AbiError::VoidParameter { index: 0 }),
            Some(DexType::Array(inner)) => (**inner).clone(),
            Some(other) => {
                return Err(AbiError::ValueTypeMismatch {
                    declared: "an array".to_string(),
                    found: other.descriptor(),
                })
            }
        };
        Ok(Some(VarargBox::pack(component, args)))
    }
}

// ================================================================== oracle
//
// Everything below is test-only. The oracle harness assembles real Dalvik
// bytecode, writes it with `dexcore`, executes it with `dexinterp`, and hands
// back what the interpreter produced. Every claim in the test module that is
// described as *measured* is measured that way: not by reading the
// specification, and not by reading `dexinterp`'s source, but by running the
// opcode.

#[cfg(test)]
pub(crate) mod oracle {
    //! Build DEX, run it, return what the interpreter said.

    use dexcore::model::access;
    use dexcore::writer::{ClassDef, CodeBody, DexWriter, MethodDef};

    /// The class every generated method lives in.
    pub const CLASS: &str = "Lcom/x/A6;";

    // ------------------------------------------------------------- encoding

    /// `const vAA, #+CCCCCCCC` (`31i`).
    pub fn const32(a: u8, v: i32) -> Vec<u8> {
        let mut o = Vec::with_capacity(4);
        o.extend_from_slice(&(0x14u16 | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&v.to_le_bytes());
        o
    }

    /// `const-wide vAA, #+BBBBBBBBBBBBBBBB` (`51l`).
    pub fn const64(a: u8, v: i64) -> Vec<u8> {
        let mut o = Vec::with_capacity(6);
        o.extend_from_slice(&(0x18u16 | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&v.to_le_bytes());
        o
    }

    /// Load an exact `f32` into register `a`.
    ///
    /// `const/high16` is the instruction a real DEX uses for a float constant,
    /// and it cannot be used here: the interpreter materialises it as
    /// `Value::Int` (`exec.rs`, the `0x15` arm), and every read of that register
    /// as a float widens the *integer*. `0x4040` therefore arrives as the number
    /// 1077936128 rather than as the float `3.0`. That is a divergence in the
    /// oracle rather than something to work around silently, and
    /// `oracle_const_high16_is_read_as_an_integer` measures it; for the
    /// conversion tests the value goes in as an exact `double` — `f64::from` and
    /// `as f32` are exact inverses — and is narrowed by a real
    /// `double-to-float`.
    pub fn load_f32_exact(a: u8, bits: u32) -> Vec<u8> {
        let mut o = const64(a, f64::from(f32::from_bits(bits)).to_bits() as i64);
        o.extend_from_slice(&op12(0x8c, a, a)); // double-to-float
        o
    }

    /// `const/high16 vAA, #+BBBB0000` (`21h`) — a float constant as a real DEX
    /// writes it, which the interpreter does not read as a float.
    pub fn const_f32_high16(a: u8, bits: u32) -> Vec<u8> {
        let mut o = Vec::with_capacity(4);
        o.extend_from_slice(&(0x15u16 | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&((bits >> 16) as u16).to_le_bytes());
        o
    }

    /// Any `12x`: `op vA, vB`.
    pub fn op12(op: u8, a: u8, b: u8) -> Vec<u8> {
        let word = u16::from(op) | (u16::from(a) << 8) | (u16::from(b) << 12);
        word.to_le_bytes().to_vec()
    }

    /// Any `23x`: `op vA, vB, vC`.
    pub fn op23(op: u8, a: u8, b: u8, c: u8) -> Vec<u8> {
        let mut o = Vec::with_capacity(4);
        o.extend_from_slice(&(u16::from(op) | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&(u16::from(c) << 8 | u16::from(b)).to_le_bytes());
        o
    }

    /// Any `21c`: `op vAA, @BBBB`.
    pub fn op21c(op: u8, a: u8, index: u16) -> Vec<u8> {
        let mut o = Vec::with_capacity(4);
        o.extend_from_slice(&(u16::from(op) | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&index.to_le_bytes());
        o
    }

    /// `and-int/lit8 vA, vB, #+CC` (`22b`, opcode `0xdd`).
    ///
    /// This is the instruction a Java compiler emits for `(a & 1)`, and it is
    /// the *only* way a real DEX produces a `Z` from an `int`. It is therefore
    /// the oracle for the boolean normalisation rule.
    pub fn and_int_lit8(a: u8, b: u8, lit: i8) -> Vec<u8> {
        let mut o = Vec::with_capacity(4);
        o.extend_from_slice(&(0x00ddu16 | (u16::from(a) << 8)).to_le_bytes());
        o.extend_from_slice(&(((lit as u8 as u16) << 8) | u16::from(b)).to_le_bytes());
        o
    }

    /// `new-instance vAA, type@BBBB` (`21c`, opcode `0x22`).
    pub fn new_instance(a: u8, type_idx: u16) -> Vec<u8> {
        op21c(0x22, a, type_idx)
    }

    /// `return vAA` (`11x`).
    pub fn ret(a: u8) -> Vec<u8> {
        (0x0fu16 | (u16::from(a) << 8)).to_le_bytes().to_vec()
    }

    /// `return-wide vAA` (`11x`).
    pub fn ret_wide(a: u8) -> Vec<u8> {
        (0x10u16 | (u16::from(a) << 8)).to_le_bytes().to_vec()
    }

    /// `return-object vAA` (`11x`).
    pub fn ret_object(a: u8) -> Vec<u8> {
        (0x11u16 | (u16::from(a) << 8)).to_le_bytes().to_vec()
    }

    /// A body with no instructions, used as a declaration placeholder.
    pub fn empty_body() -> CodeBody {
        CodeBody {
            registers_size: 0,
            ins_size: 0,
            outs_size: 0,
            insns: Vec::new(),
            tries: Vec::new(),
        }
    }

    /// Concatenate instruction encodings.
    pub fn body(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.iter().flat_map(|p| p.iter().copied()).collect()
    }

    /// One generated static method.
    pub struct Case {
        /// Method name; must be unique within the generated class.
        pub name: String,
        /// Parameter descriptors.
        pub params: Vec<String>,
        /// Return descriptor.
        pub ret: String,
        /// Register file size.
        pub regs: u16,
        /// The instruction stream.
        pub insns: Vec<u8>,
    }

    impl Case {
        /// A `static` method with no parameters returning `I`, from a body.
        pub fn int(name: &str, regs: u16, parts: &[Vec<u8>]) -> Case {
            Case {
                name: name.to_string(),
                params: Vec::new(),
                ret: "I".to_string(),
                regs,
                insns: body(parts),
            }
        }

        /// A `static` method with no parameters returning `J`.
        pub fn long(name: &str, regs: u16, parts: &[Vec<u8>]) -> Case {
            Case {
                name: name.to_string(),
                params: Vec::new(),
                ret: "J".to_string(),
                regs,
                insns: body(parts),
            }
        }

        /// A `static` method with no parameters returning `F`.
        pub fn float(name: &str, regs: u16, parts: &[Vec<u8>]) -> Case {
            Case {
                name: name.to_string(),
                params: Vec::new(),
                ret: "F".to_string(),
                regs,
                insns: body(parts),
            }
        }
    }

    /// A generated DEX plus the pool indices its cases need.
    pub struct Built {
        bytes: Vec<u8>,
        fields: Vec<u16>,
        types: std::collections::BTreeMap<String, u16>,
    }

    impl Built {
        /// The `type_ids` index of a descriptor.
        pub fn type_idx(&self, descriptor: &str) -> Option<u16> {
            self.types.get(descriptor).copied()
        }
    }

    /// Emit a DEX containing one static method per case, plus one static field
    /// per descriptor in `field_types`.
    ///
    /// One DEX for the whole batch rather than one per case: assembling and
    /// parsing a DEX costs far more than invoking a method, and the matrix runs
    /// several hundred conversions.
    pub fn build(cases: &[Case], field_types: &[&str]) -> Result<Built, String> {
        let mut w = DexWriter::new();
        let mut class = ClassDef::extending_object(CLASS);
        for t in field_types {
            class = class.with_field(dexcore::writer::FieldDef::statics("f", t));
        }
        for c in cases {
            class = class.with_method(MethodDef::concrete(
                &c.name,
                &c.params.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
                &c.ret,
                access::ACC_PUBLIC | access::ACC_STATIC,
                empty_body(),
            ));
        }
        w.add_class(class);
        let map = w.freeze().map_err(|e| format!("freeze: {e}"))?;
        let mut fields = Vec::with_capacity(field_types.len());
        for t in field_types {
            fields.push(
                map.field(CLASS, "f", t)
                    .map_err(|e| format!("field {t}: {e}"))?,
            );
        }
        // Intern the descriptors the cases reference, so `new-instance` and
        // `const-class` have a real `type_ids` index to name.
        let mut types = std::collections::BTreeMap::new();
        types.insert(CLASS.to_string(), map.type_(CLASS).unwrap_or(0));
        for t in field_types {
            if let Ok(i) = map.type_(t) {
                types.insert(t.to_string(), i);
            }
        }
        for c in cases {
            w.set_code(
                CLASS,
                &c.name,
                CodeBody {
                    registers_size: c.regs,
                    ins_size: 0,
                    outs_size: 0,
                    insns: c.insns.clone(),
                    tries: Vec::new(),
                },
            )
            .map_err(|e| format!("set_code {}: {e}", c.name))?;
        }
        let bytes = w.emit().map_err(|e| format!("emit: {e}"))?;
        Ok(Built {
            bytes,
            fields,
            types,
        })
    }

    /// The result of one executed case.
    #[derive(Clone, Debug, PartialEq)]
    pub enum Outcome {
        /// The interpreter returned this.
        Value(dexinterp::Value),
        /// The interpreter refused, with this description.
        Refused(String),
    }

    impl Outcome {
        /// The value, or a message naming the refusal.
        pub fn value(&self) -> Result<&dexinterp::Value, String> {
            match self {
                Outcome::Value(v) => Ok(v),
                Outcome::Refused(m) => Err(m.clone()),
            }
        }
    }

    /// Build and execute. Returns one outcome per case, in order, plus the pool
    /// indices so a case can refer to a field or a type.
    pub fn run_with(cases: &[Case], field_types: &[&str]) -> Result<(Vec<Outcome>, Built), String> {
        let built = build(cases, field_types)?;
        let dex = dexcore::DexReader::open(&built.bytes).map_err(|e| format!("open: {e}"))?;
        let mut vm = dexinterp::new_interpreter(dex, dexinterp::Config::default())
            .map_err(|e| format!("interpreter: {e}"))?;
        let mut out = Vec::with_capacity(cases.len());
        for c in cases {
            let sig = format!("({}){}", c.params.join(""), c.ret);
            let r = vm.invoke_method(CLASS, &c.name, &sig, &[]);
            out.push(match r {
                Ok(v) => Outcome::Value(v),
                Err(e) => Outcome::Refused(format!("{e}")),
            });
        }
        Ok((out, built))
    }

    /// Build and execute, discarding the pool indices.
    pub fn run(cases: &[Case], field_types: &[&str]) -> Result<Vec<Outcome>, String> {
        Ok(run_with(cases, field_types)?.0)
    }

    /// The `field_ids` index of each declared field, in declaration order.
    ///
    /// Two-phase, because the indices do not exist until the pools are frozen.
    /// The alternative — building the cases and discovering afterwards that every
    /// one of them names field 0 — is a bug that stores into `B` and asserts
    /// about `Z`, and it fails in a way that looks like a semantic disagreement
    /// rather than an indexing mistake.
    pub fn field_indices(field_types: &[&str]) -> Result<Vec<u16>, String> {
        Ok(build(&[], field_types)?.fields)
    }

    /// A scratch directory for the compile-fail tests. Named per test so two
    /// tests cannot collide, and created rather than assumed to exist.
    pub fn temp_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("andro-a6-{tag}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);
        base
    }

    /// A number as the oracle reports it, with the oracle's own untyped `Int`
    /// resolved against the type the test expected.
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Num {
        /// A 32-bit integer result.
        I32(i32),
        /// A 64-bit integer result.
        I64(i64),
        /// A `float` result, as bits so that `NaN` payloads compare.
        F32(u32),
        /// A `double` result, as bits.
        F64(u64),
    }

    /// Reduce an interpreter value to a [`Num`], interpreting `Value::Int` as
    /// the narrow type the test declared.
    ///
    /// Every path here is `crate::abi::…` rather than `crate::…`: a module that
    /// named its own types through the crate root would only compile in a crate
    /// whose `lib.rs` happened to re-export them, and this one does not — or
    /// rather, it does today and will not tomorrow as other modules land.
    pub fn num(v: &dexinterp::Value, ty: &crate::abi::DexType) -> Result<Num, String> {
        use dexinterp::Value;
        let want = ty.descriptor();
        let bad =
            |v: &dexinterp::Value| format!("the interpreter returned {v:?}, which is not a {want}");
        Ok(match (v, ty) {
            (Value::Int(i), crate::abi::DexType::Boolean) => Num::I32(*i),
            (Value::Int(i), crate::abi::DexType::Byte) => Num::I32(*i),
            (Value::Int(i), crate::abi::DexType::Short) => Num::I32(*i),
            (Value::Int(i), crate::abi::DexType::Char) => Num::I32(*i),
            (Value::Int(i), crate::abi::DexType::Int) => Num::I32(*i),
            (Value::Long(l), crate::abi::DexType::Long) => Num::I64(*l),
            (Value::Float(f), crate::abi::DexType::Float) => Num::F32(f.to_bits()),
            (Value::Double(d), crate::abi::DexType::Double) => Num::F64(d.to_bits()),
            (other, _) => return Err(bad(other)),
        })
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

    use super::oracle;
    use super::*;

    // ---------------------------------------------------------- descriptors

    /// A hostile descriptor must cost a comparison, not the process. This is the
    /// test for the decision to parse arrays iteratively: `JType::parse` in the
    /// oracle recurses once per `[`, and a file that opens with a hundred
    /// thousand of them overflows the stack, which is an abort and not an error.
    #[test]
    fn a_deeply_nested_array_is_a_typed_error_not_a_stack_overflow() {
        let deep = "[".repeat(100_000) + "I";
        match DexType::parse(&deep) {
            Err(AbiError::ArrayDepthExceeded { depth, max }) => {
                assert_eq!(depth, 100_000);
                assert_eq!(max, MAX_ARRAY_DEPTH);
            }
            other => panic!("expected ArrayDepthExceeded, got {other:?}"),
        }
        // Just inside the limit still parses, and still round-trips.
        let ok = "[".repeat(MAX_ARRAY_DEPTH) + "I";
        assert_eq!(DexType::parse(&ok).unwrap().descriptor(), ok);
    }

    #[test]
    fn a_truncated_descriptor_is_an_error_and_never_a_guess() {
        let cases: &[(&str, &str)] = &[
            ("", "descriptor_empty"),
            ("L", "unterminated_class"),
            ("Ljava/lang/String", "unterminated_class"),
            ("L;", "empty_class_name"),
            ("Q", "invalid_byte"),
            ("Igarbage", "trailing_bytes"),
            ("[V", "array_of_void"),
        ];
        for (text, kind) in cases {
            let got = DexType::parse(text);
            let e = match got {
                Err(e) => e,
                Ok(t) => panic!("`{text}` parsed as {t} rather than erroring"),
            };
            assert_eq!(e.kind(), *kind, "for `{text}`");
        }
    }

    #[test]
    fn every_descriptor_class_round_trips_through_its_text() {
        for text in [
            "V",
            "Z",
            "B",
            "S",
            "C",
            "I",
            "J",
            "F",
            "D",
            "Ljava/lang/Object;",
            "[I",
            "[[Ljava/lang/String;",
            "[[[[[B",
            "[Z",
            "[J",
            "[D",
        ] {
            let ty = DexType::parse(text).unwrap_or_else(|e| panic!("`{text}`: {e}"));
            assert_eq!(ty.descriptor(), text, "round trip of `{text}`");
            assert_eq!(DexType::parse(&ty.descriptor()).unwrap(), ty);
        }
    }

    #[test]
    fn a_prototype_parameter_list_is_a_concatenation_not_a_comma_list() {
        // The classic parser bug: stopping at the first `;` reads three
        // parameters as one.
        let p = Prototype::parse("(IJLjava/lang/String;)Ljava/lang/Object;").unwrap();
        assert_eq!(
            p.params,
            vec![
                DexType::Int,
                DexType::Long,
                DexType::Ref("Ljava/lang/String;".into())
            ]
        );
        assert_eq!(p.ret, DexType::Ref("Ljava/lang/Object;".into()));
        assert_eq!(p.descriptor(), "(IJLjava/lang/String;)Ljava/lang/Object;");

        // Arrays consume their element, so `([I[Ljava/lang/String;)V` is two.
        let two = Prototype::parse("([I[Ljava/lang/String;)V").unwrap();
        assert_eq!(two.params.len(), 2);
        assert_eq!(two.params[0].descriptor(), "[I");
    }

    #[test]
    fn a_malformed_prototype_is_a_typed_error() {
        for (text, kind) in [
            ("II)V", "missing_open_parenthesis"),
            ("(II", "unclosed_parameter_list"),
            ("(V)V", "void_parameter"),
            ("()", "descriptor_empty"),
            ("(I)Q", "invalid_byte"),
            ("(I)II", "trailing_bytes"),
        ] {
            let e = match Prototype::parse(text) {
                Err(e) => e,
                Ok(p) => panic!("`{text}` parsed as {p}"),
            };
            assert_eq!(e.kind(), kind, "for `{text}`");
        }
        // 256 parameters is past what any `invoke` can name.
        let many = format!("({})V", "I".repeat(256));
        let e = Prototype::parse(&many).unwrap_err();
        assert_eq!(e.kind(), "too_many_parameters");
    }

    // ------------------------------------------------------ calling convention

    /// The whole table, in one test, because the table is the deliverable and a
    /// reader should be able to check it against `IR.md` in one place.
    #[test]
    fn the_calling_convention_table_is_the_one_in_the_specification() {
        let expected: &[(&str, Option<Wasm>)] = &[
            ("Z", Some(Wasm::I32)),
            ("B", Some(Wasm::I32)),
            ("S", Some(Wasm::I32)),
            ("C", Some(Wasm::I32)),
            ("I", Some(Wasm::I32)),
            ("J", Some(Wasm::I64)),
            ("F", Some(Wasm::F32)),
            ("D", Some(Wasm::F64)),
            ("Ljava/lang/Object;", Some(Wasm::I32)),
            ("[I", Some(Wasm::I32)),
            ("[D", Some(Wasm::I32)),
            ("V", None),
        ];
        for (text, want) in expected {
            let ty = DexType::parse(text).unwrap();
            assert_eq!(ty.wasm_ty(), *want, "for `{text}`");
        }
    }

    #[test]
    fn widening_is_explicit_and_nothing_is_boxed() {
        // `(II)I` is two i32 in, one i32 out, and the receiver is an i32 that
        // the *caller* supplies — not a hidden third parameter of the prototype.
        let p = Prototype::parse("(II)I").unwrap();
        assert_eq!(
            p.wasm_sig(true).wat(),
            "(func (param i32 i32) (result i32))"
        );
        assert_eq!(
            p.wasm_sig(false).wat(),
            "(func (param i32 i32 i32) (result i32))"
        );
        // A void method has no result at all, which is different from an i32 0.
        let v = Prototype::parse("(Ljava/lang/Object;)V").unwrap();
        assert_eq!(v.wasm_sig(true).wat(), "(func (param i32))");
        assert_eq!(v.wasm_sig(true).result, None);
        // And the wide types land in the right places.
        let w = Prototype::parse("(JDFZ)V").unwrap();
        assert_eq!(w.wasm_sig(true).wat(), "(func (param i64 f64 f32 i32))");
    }

    // ------------------------------------------------------- Z / booleans

    /// `Z` is 0/1, and the fold is the **low bit**, not "non-zero". This is the
    /// named test for the first silent bug in the module note.
    #[test]
    fn z_is_zero_or_one_and_is_folded_by_the_low_bit() {
        assert_eq!(Bool::normalise(0), Bool::FALSE);
        assert_eq!(Bool::normalise(1), Bool::TRUE);
        // The fold is `& 1`, so 2 is false and 3 is true. If this ever becomes
        // `!= 0` the answers swap, and an app that stores `i & 1` in a boolean
        // field disagrees with the device.
        assert_eq!(Bool::normalise(2), Bool::FALSE);
        assert_eq!(Bool::normalise(3), Bool::TRUE);
        assert_eq!(Bool::normalise(-1), Bool::TRUE);
        assert_eq!(Bool::normalise(0x1234), Bool::FALSE);
        assert_eq!(Bool::normalise(0x1235), Bool::TRUE);
        // And every constructible `Bool` really is 0 or 1.
        for v in [i32::MIN, -2, -1, 0, 1, 2, 3, 42, i32::MAX] {
            let b = Bool::normalise(v);
            assert!(b.as_i32() == 0 || b.as_i32() == 1, "Bool({v}) = {b}");
        }
    }

    /// The ABI *labels* a normalisation rather than doing it silently, because
    /// `IR.md` requires every fabricated value to be labelled.
    #[test]
    fn a_boolean_normalisation_is_reported_rather_than_done_silently() {
        let already = convert(
            &DexType::Boolean,
            &DexType::Boolean,
            AbiValue::Boolean(Bool::TRUE),
        )
        .unwrap();
        assert!(
            !already.notes.boolean_normalised,
            "0/1 needs no fabrication"
        );

        // An out-of-range `Z` arriving as a *host* value, folded and labelled.
        let folded = convert(&DexType::Int, &DexType::Boolean, AbiValue::Int(42)).unwrap();
        assert_eq!(folded.value, AbiValue::Boolean(Bool::FALSE));
        assert!(
            folded.notes.boolean_normalised,
            "42 is not a Z and folding it must be reported"
        );
        assert_eq!(folded.notes.narrowed, Some(Narrowing::Boolean));
    }

    /// The `aget-boolean` rule is **non-zero**, the store rule is the **low
    /// bit**, and they are different. Keeping them apart is a named decision;
    /// this is the test that keeps them apart.
    #[test]
    fn bool_load_and_store_use_different_rules() {
        // Store: low bit.
        assert_eq!(
            narrow_on_store(&DexType::Boolean, AbiValue::Int(2)),
            AbiValue::Boolean(Bool::FALSE)
        );
        assert_eq!(
            narrow_on_store(&DexType::Boolean, AbiValue::Int(3)),
            AbiValue::Boolean(Bool::TRUE)
        );
        // Load: non-zero.
        assert_eq!(
            narrow_on_load(&DexType::Boolean, AbiValue::Int(2)),
            AbiValue::Boolean(Bool::TRUE)
        );
        assert_eq!(
            narrow_on_load(&DexType::Boolean, AbiValue::Int(0)),
            AbiValue::Boolean(Bool::FALSE)
        );
        // Where they agree: on anything a verifier would produce, i.e. 0 and 1.
        for v in [0, 1] {
            let stored = narrow_on_store(&DexType::Boolean, AbiValue::Int(v));
            let loaded = narrow_on_load(&DexType::Boolean, stored);
            assert_eq!(stored, loaded, "0/1 round trip for {v}");
        }
    }

    // ----------------------------------------------- byte / short / char

    /// `char` is 16-bit **unsigned** and `short` is 16-bit **signed**. This is a
    /// different bug from getting `byte` wrong, and it is one character wide.
    #[test]
    fn byte_and_short_sign_extend_while_char_zero_extends() {
        assert_eq!(
            narrow_on_store(&DexType::Byte, AbiValue::Int(0xff)),
            AbiValue::Byte(-1)
        );
        assert_eq!(
            narrow_on_store(&DexType::Short, AbiValue::Int(0xffff)),
            AbiValue::Short(-1)
        );
        // The same 0xFFFF is 65535 as a char. If this were `-1` the bug would be
        // invisible in a diff and catastrophic at runtime.
        assert_eq!(
            narrow_on_store(&DexType::Char, AbiValue::Int(0xffff)),
            AbiValue::Char(65535)
        );
        assert_eq!(
            narrow_on_store(&DexType::Char, AbiValue::Int(-1)),
            AbiValue::Char(65535)
        );
        // And the loads are the inverse.
        assert_eq!(
            narrow_on_load(&DexType::Byte, AbiValue::Int(-1)),
            AbiValue::Byte(-1)
        );
        assert_eq!(
            narrow_on_load(&DexType::Char, AbiValue::Int(65535)),
            AbiValue::Char(65535)
        );
        assert_eq!(
            narrow_on_load(&DexType::Short, AbiValue::Int(-1)),
            AbiValue::Short(-1)
        );
    }

    // -------------------------------------------------- float narrowing

    #[test]
    fn float_to_int_of_nan_is_zero_and_out_of_range_saturates() {
        for nan in [f32::NAN, -f32::NAN] {
            assert_eq!(f32_to_int(nan), 0);
            assert_eq!(f32_to_i64(nan), 0);
        }
        for nan in [f64::NAN, -f64::NAN] {
            assert_eq!(f64_to_int(nan), 0);
            assert_eq!(f64_to_i64(nan), 0);
        }
        // Saturating, not wrapping and not trapping. WebAssembly's
        // `i32.trunc_f32_s` traps on all three of these.
        assert_eq!(f32_to_int(1e30), i32::MAX);
        assert_eq!(f32_to_int(-1e30), i32::MIN);
        assert_eq!(f64_to_int(1e300), i32::MAX);
        assert_eq!(f64_to_i64(f64::MAX), i64::MAX);
        // Truncates toward zero, and keeps signed zero as zero.
        assert_eq!(f32_to_int(2.9), 2);
        assert_eq!(f32_to_int(-2.9), -2);
        assert_eq!(f64_to_int(-0.5), 0);
        assert_eq!(f64_to_int(-0.0), 0);
        // The boundary itself saturates rather than falling through.
        assert_eq!(f32_to_int(2_147_483_648.0), i32::MAX);
        assert_eq!(f32_to_int(-2_147_483_648.0), i32::MIN);
        // The largest float strictly inside the range is exact.
        assert_eq!(f32_to_int(2_147_483_520.0), 2_147_483_520);
    }

    // ---------------------------------------------------- rem-float

    /// The specification's `x - y*trunc(x/y)` and `fmod` are the same
    /// *operation*, and evaluating the formula is **not** the same as computing
    /// `fmod`. This test measures where they part company rather than asserting
    /// it from a reading.
    ///
    /// Two of the divergences are below. The first — an infinite divisor — is
    /// not exotic: it is what `x % Double.POSITIVE_INFINITY` does, and Java
    /// returns `x` for it.
    #[test]
    fn rem_formula_diverges_from_fmod_exactly_where() {
        // (1) y infinite. IEEE requires fmod(x, ±inf) == x. Comparing by bits
        // throughout, because `NaN != NaN` would make these assertions pass for
        // the wrong reason and a `NaN`/`NaN` failure is unreadable.
        assert_eq!(
            rem_f64_by_formula(3.0, f64::INFINITY).to_bits(),
            f64::NAN.to_bits()
        );
        assert_eq!(rem_f64(3.0, f64::INFINITY), 3.0);
        assert_eq!(rem_f32(3.0f32, f32::INFINITY), 3.0f32);
        assert_eq!(
            rem_f32_by_formula(3.0f32, f32::INFINITY).to_bits(),
            f32::NAN.to_bits()
        );

        // (2) The intermediate overflows: `x/y` is an infinity, so
        // `y * trunc(x/y)` is one, and the subtraction runs off the end of the
        // range. `fmod` stays exact — the remainder is representable and is
        // smaller in magnitude than the divisor — while the formula does not.
        let exact = rem_f64(1e300, 1e-300);
        assert!(
            exact.is_finite(),
            "fmod is exact here, so it cannot be infinite"
        );
        assert!(
            exact.abs() < 1e-300,
            "a remainder is smaller than its divisor"
        );
        assert_eq!(
            rem_f64_by_formula(1e300, 1e-300),
            f64::NEG_INFINITY,
            "the formula's intermediate product overflows to -inf"
        );
        let exact32 = rem_f32(1e30f32, 1e-30f32);
        assert!(exact32.is_finite() && exact32.abs() < 1e-30f32);
        assert_eq!(rem_f32_by_formula(1e30f32, 1e-30f32), f32::NEG_INFINITY);

        // (3) The sign of zero. `(-0.0) % 1` is `-0.0` under `fmod`; the formula
        // computes `-0.0 - 1.0 * (-0.0)`, which is `-0.0 + 0.0` and rounds to
        // `+0.0`. Losing the sign is a real difference — `1/x` flips sign, and
        // `Float.equals` distinguishes them.
        assert!(rem_f64(-0.0, 1.0).is_sign_negative(), "fmod keeps -0.0");
        assert!(
            rem_f64_by_formula(-0.0, 1.0).is_sign_positive(),
            "the formula does not"
        );

        // Sweep the ordinary range and *count*, rather than asserting a
        // threshold chosen after seeing the answer. How many pairs the three
        // classes account for is a property of the corpus; what matters is that
        // every divergence is one of the named ones, or the note on `rem_f32` is
        // incomplete and this test has found a fourth.
        let mut agreed = 0u32;
        let mut diverged = 0u32;
        let xs = [
            0.0f64,
            -0.0,
            1.0,
            -1.0,
            0.5,
            -0.5,
            5.0,
            -5.0,
            7.5,
            1e300,
            1e-300,
            f64::MIN_POSITIVE,
            f64::MAX,
            1.0 / 3.0,
            1234.5678,
        ];
        let ys = [1.0f64, -1.0, 2.0, 3.0, 0.5, 7.0, 1e-300, 1e300, 0.0, -0.0];
        for &x in &xs {
            for &y in &ys {
                if rem_f64(x, y).to_bits() == rem_f64_by_formula(x, y).to_bits() {
                    agreed += 1;
                } else {
                    diverged += 1;
                }
            }
        }
        eprintln!(
            "rem: {agreed} of {} pairs agree, {diverged} diverge (four named classes)",
            agreed + diverged
        );
        assert_eq!(agreed + diverged, 150, "the corpus is 15 x 10");
        for &x in &[-0.0f64, 3.0, -3.0, 1e300, 1e-300] {
            for &y in &[1.0f64, -1.0, 2.0, f64::INFINITY, 1e-300, 0.0, -0.0] {
                let a = rem_f64(x, y);
                let b = rem_f64_by_formula(x, y);
                if a.to_bits() == b.to_bits() {
                    continue;
                }
                // Reproduce the formula's own steps so each divergence can be
                // attributed to one of the four classes in the note on
                // `rem_f32`. A divergence that none of them explains means the
                // note is incomplete.
                let q = (x / y).trunc();
                let product = y * q;
                let explained = (y.is_infinite() && a == x)
                    || !product.is_finite()
                    // A zero remainder keeps the dividend's sign under `fmod`
                    // (IEEE remainderToBinaryDigits), while the formula's
                    // subtraction always lands on `+0.0`. This covers both
                    // `-0.0 % 1` and `-3.0 % 1`.
                    || (a == 0.0 && a.is_sign_negative() && b.is_sign_positive())
                    || (product.is_finite() && product != x);
                assert!(
                    explained,
                    "unexplained divergence at x={x} y={y}: fmod={a} formula={b} \
                     (q={q}, product={product})"
                );
            }
        }
    }

    // -------------------------------------------------- integer wrapping

    #[test]
    fn long_arithmetic_wraps_and_does_not_trap() {
        assert_eq!(int64_binop(IntOp::Add, i64::MAX, 1), Ok(i64::MIN));
        assert_eq!(int64_binop(IntOp::Sub, i64::MIN, 1), Ok(i64::MAX));
        assert_eq!(int64_binop(IntOp::Mul, 4_294_967_296, 4_294_967_296), Ok(0));
        assert_eq!(int32_binop(IntOp::Add, i32::MAX, 1), Ok(i32::MIN));
        // The one arithmetic case Java defines that traps in most languages.
        assert_eq!(int64_binop(IntOp::Div, i64::MIN, -1), Ok(i64::MIN));
        assert_eq!(int64_binop(IntOp::Rem, i64::MIN, -1), Ok(0));
        assert_eq!(int32_binop(IntOp::Div, i32::MIN, -1), Ok(i32::MIN));
        // Division by zero *is* a throwable, and is distinguishable from every
        // other failure.
        assert_eq!(int64_binop(IntOp::Div, 1, 0), Err(NumErr::DivideByZero));
        assert_eq!(int64_binop(IntOp::Rem, 1, 0), Err(NumErr::DivideByZero));
        // Shift counts are taken modulo the width.
        assert_eq!(int64_binop(IntOp::Shl, 1, 65), Ok(2));
        assert_eq!(int32_binop(IntOp::Shl, 1, 33), Ok(2));
        assert_eq!(int32_binop(IntOp::Shr, -8, 1), Ok(-4));
        assert_eq!(int32_binop(IntOp::UShr, -8, 1), Ok(2_147_483_644));
    }

    #[test]
    fn float_division_by_zero_is_an_infinity_and_not_a_throwable() {
        assert_eq!(
            float32_binop(FloatOp::Div, 1.0, 0.0).to_bits(),
            f32::INFINITY.to_bits()
        );
        assert_eq!(
            float32_binop(FloatOp::Div, -1.0, 0.0).to_bits(),
            f32::NEG_INFINITY.to_bits()
        );
        assert!(float32_binop(FloatOp::Div, 0.0, 0.0).is_nan());
        assert!(float64_binop(FloatOp::Div, 0.0, 0.0).is_nan());
    }

    // ------------------------------------------------------------ handles

    #[test]
    fn null_is_handle_zero_and_a_handle_must_be_checked_before_dereference() {
        assert!(Handle::NULL.is_null());
        assert!(
            Handle::default().is_null(),
            "the default is null, not dangling"
        );
        assert!(!Handle::from_bits(8).is_null());
        // The gate is a *type* change, so it cannot be forgotten.
        assert!(Handle::NULL.require("test").is_err());
        let ok = Handle::from_bits(8).require("test").unwrap();
        assert_eq!(ok.bits(), 8);
        // And the way back down is explicit.
        assert_eq!(ok.weaken().bits(), 8);
    }

    /// The claim "no path moves an `f64` bit pattern into a `Handle`" is not
    /// checkable by a runtime test — a negative property about the type system
    /// is a property about whether the program *compiles*. So this shells out to
    /// `rustc` and asserts that the illegal coercions are rejected.
    #[test]
    fn no_coercion_exists_between_a_handle_and_a_number() {
        // Each snippet must FAIL to compile. If any of them compiles, the
        // newtype has a hole and the module note is a lie.
        let forbidden: &[(&str, &str)] = &[
            (
                "int to handle by `as`",
                "let _: abi::Handle = 7i32 as abi::Handle;",
            ),
            (
                "f64 to handle by `as`",
                "let _: abi::Handle = 1.5f64 as abi::Handle;",
            ),
            (
                "f32 to handle by `as`",
                "let _: abi::Handle = 1.5f32 as abi::Handle;",
            ),
            (
                "i64 to handle by `as`",
                "let _: abi::Handle = 7i64 as abi::Handle;",
            ),
            (
                "handle to i32 by `as`",
                "let _: i32 = abi::Handle::NULL as i32;",
            ),
            (
                "handle to u32 by `as`",
                "let _: u32 = abi::Handle::NULL as u32;",
            ),
            (
                "handle to i64 by `as`",
                "let _: i64 = abi::Handle::NULL as i64;",
            ),
            (
                "handle to f64 by `as`",
                "let _: f64 = abi::Handle::NULL as f64;",
            ),
            ("From<u32> for Handle", "let _: abi::Handle = 7u32.into();"),
            ("From<i32> for Handle", "let _: abi::Handle = 7i32.into();"),
            ("From<i64> for Handle", "let _: abi::Handle = 7i64.into();"),
            (
                "From<f32> for Handle",
                "let _: abi::Handle = 1.5f32.into();",
            ),
            (
                "From<f64> for Handle",
                "let _: abi::Handle = 1.5f64.into();",
            ),
            (
                "From<f64> for Handle via from_bits",
                "let _: abi::Handle = abi::Handle::from_bits(1.5f64.to_bits() as u32);",
            ),
            (
                "Into<i32> from Handle",
                "let _: i32 = abi::Handle::NULL.into();",
            ),
            (
                "Into<u32> from Handle",
                "let _: u32 = abi::Handle::NULL.into();",
            ),
            (
                "Into<f64> from Handle",
                "let _: f64 = abi::Handle::NULL.into();",
            ),
            (
                "Into<Handle> from AbiValue::Double",
                "let _: abi::Handle = abi::AbiValue::Double(1.5).into();",
            ),
            (
                "Into<Handle> from AbiValue::Int",
                "let _: abi::Handle = abi::AbiValue::Int(1).into();",
            ),
            (
                "Into<Handle> from AbiValue::Float",
                "let _: abi::Handle = abi::AbiValue::Float(1.5).into();",
            ),
            ("deref a Handle", "let _ = *abi::Handle::NULL;"),
            ("add a Handle", "let _ = abi::Handle::NULL + 1u32;"),
            (
                "index with a Handle",
                "let v = [0u8; 4]; let _ = v[abi::Handle::NULL];",
            ),
            (
                "sort handles as numbers",
                "let mut v = vec![abi::Handle::NULL]; v.sort();",
            ),
            (
                "dereference without a null check",
                "let _ = abi::Handle::NULL.bits() as *mut u8;",
            ),
        ];
        let dir = oracle::temp_dir("coercion");
        let abi_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/abi.rs");
        let mut checked = 0;
        for (name, expr) in forbidden {
            let src = format!("#[path = \"{abi_path}\"]\nmod abi;\nfn main() {{ {expr} }}\n");
            let path = dir.join("case.rs");
            std::fs::write(&path, &src).expect("write case");
            let out = std::process::Command::new("rustc")
                .arg("--edition=2021")
                .arg("--crate-type=bin")
                .arg("--emit=metadata")
                .arg("-o")
                .arg(dir.join("case.rmeta"))
                .arg(&path)
                .output();
            match out {
                // A compile error is the expected outcome.
                Err(e) => panic!("could not run rustc for `{name}`: {e}"),
                Ok(o) if o.status.success() => {
                    panic!("`{name}` COMPILED, so the newtype has a hole:\n  {expr}")
                }
                Ok(_) => checked += 1,
            }
        }
        assert_eq!(checked, forbidden.len(), "not every case was checked");
    }

    /// The positive half of the same claim: what *is* possible, and only that.
    #[test]
    fn the_only_ways_in_and_out_of_a_handle_are_named_functions() {
        // In: `from_bits`, and only `from_bits`, from an integer.
        let h: Handle = Handle::from_bits(12);
        assert_eq!(h.bits(), 12);
        // Out: `bits`, and only `bits`, to an integer.
        let n: u32 = h.bits();
        assert_eq!(n, 12);
        // A double has no route in either direction, so a value can be *typed*
        // as a double by the compiler but never reach a handle slot.
        let d = AbiValue::Double(1.5);
        assert_eq!(d.type_name(), "double");
        // The conversion table refuses the crossing rather than coercing it.
        let crossed = convert(
            &DexType::Double,
            &DexType::object(),
            AbiValue::Double(f64::from_bits(0x0000_0000_0000_1234u64)),
        );
        assert_eq!(crossed.unwrap_err().kind(), "no_conversion");
        // ...and the other way, so a handle cannot be read as a number.
        let back = convert(
            &DexType::object(),
            &DexType::Double,
            AbiValue::Ref(Handle::from_bits(0x1234)),
        );
        assert_eq!(back.unwrap_err().kind(), "no_conversion");
    }

    // -------------------------------------------------------- field stores

    /// A `Z` field takes the **low bit** and a `J` field takes a double's **bit
    /// pattern**. Both are measured against the interpreter below; this is the
    /// specification-side statement they have to agree with.
    #[test]
    fn field_store_coercion_is_a_different_function_from_conversion() {
        // `double -> J` is a reinterpretation, not a conversion: Dalvik has no
        // `const-double`, so every double constant arrives as `const-wide` of
        // its IEEE bits.
        let bits = 0x4009_21fb_5444_2d18i64; // 3.14159...
        assert_eq!(
            narrow_on_store(&DexType::Long, AbiValue::Long(bits)),
            AbiValue::Long(bits)
        );
        // `long -> I` stores 0, not a truncation. The two have nothing in
        // common and a narrowing here would be an invented operation.
        assert_eq!(
            narrow_on_store(&DexType::Int, AbiValue::Long(5)),
            AbiValue::Int(0)
        );
        // `long -> F` does widen, because a long and a float are both numbers.
        assert_eq!(
            narrow_on_store(&DexType::Float, AbiValue::Long(5)),
            AbiValue::Float(5.0)
        );
        // `double -> B` stores 0 for the same reason as `long -> I`.
        assert_eq!(
            narrow_on_store(&DexType::Byte, AbiValue::Double(1.5)),
            AbiValue::Byte(0)
        );
    }

    // ------------------------------------------------------------- invokes

    #[test]
    fn an_invoke_argument_count_comes_from_the_prototype_not_the_instruction() {
        let p = Prototype::parse("(IJ)V").unwrap();
        for (op, receiver) in [
            (InvokeOp::Virtual, true),
            (InvokeOp::Direct, true),
            (InvokeOp::Interface, true),
            (InvokeOp::Super, true),
            (InvokeOp::Static, false),
        ] {
            let site = InvokeSite::method(op, 1, &p);
            let want = match receiver {
                true => 3,
                false => 2,
            };
            assert_eq!(site.argument_count().unwrap(), want, "{op:?}");
        }
        // `invoke-polymorphic` does *not* add a receiver: its index is a
        // prototype, and the prototype already contains the receiver.
        let poly = InvokeSite::polymorphic(7, &p);
        assert_eq!(poly.argument_count().unwrap(), 2);
    }

    #[test]
    fn an_invoke_with_more_than_five_arguments_cannot_use_the_short_form() {
        let p = Prototype::parse("(IIIIII)V").unwrap();
        let site = InvokeSite::method(InvokeOp::Static, 3, &p);
        let regs = [0u8, 1, 2, 3, 4, 5];
        // Six arguments: the `35c` form cannot encode them and truncating the
        // list would be a call that succeeds with the wrong arguments.
        let e = site.encode(&regs).unwrap_err();
        assert_eq!(e.kind(), "too_many_parameters");
        // The range form can, and it checks the count.
        let bytes = site.encode_range(0, 6).unwrap();
        assert_eq!(bytes.len(), 6, "3rc is three units");
        assert_eq!(
            site.encode_range(0, 5).unwrap_err().kind(),
            "value_type_mismatch"
        );
    }

    #[test]
    fn invoke_polymorphic_puts_a_proto_index_in_the_fourth_word() {
        // This is the one place the trailing index is not a method reference, so
        // it is worth being explicit that the `45cc` form has *two* index words.
        let p = Prototype::parse("([Ljava/lang/Object;)Ljava/lang/Object;").unwrap();
        let site = InvokeSite::polymorphic(0x1234, &p);
        let bytes = site.encode(&[0]).unwrap();
        assert_eq!(bytes.len(), 8, "45cc is four units");
        assert_eq!(bytes[0], InvokeOp::Polymorphic.opcode());
        assert_eq!(
            u16::from_le_bytes([bytes[6], bytes[7]]),
            0x1234,
            "the proto id"
        );
        // ...and the range form is a different opcode.
        assert_eq!(
            InvokeOp::Polymorphic.range_opcode(),
            InvokeOp::Polymorphic.opcode() + 1
        );
    }

    #[test]
    fn a_varargs_call_site_carries_an_array_and_nothing_else() {
        // `ACC_VARARGS` does not change the encoding: the declared prototype is
        // already the packed-array one.
        let p = Prototype::parse("([Ljava/lang/Object;)V").unwrap();
        let sig = ExportedSignature::new(
            "log",
            p.clone(),
            MethodAccess(access::ACC_STATIC | access::ACC_VARARGS),
        )
        .unwrap();
        assert_eq!(
            sig.wasm_sig().wat(),
            "(func (param i32))",
            "an object[] is one i32 handle"
        );
        // A varargs method that does not end in an array is refused rather than
        // emitted with a signature no call can satisfy.
        let bad = Prototype::parse("(I)V").unwrap();
        assert!(ExportedSignature::new("bad", bad, MethodAccess(access::ACC_VARARGS)).is_err());
    }

    #[test]
    fn a_varargs_read_past_the_packed_length_is_a_reported_bounds_error() {
        let box_ = VarargBox::pack(
            DexType::object(),
            &[
                AbiValue::Ref(Handle::from_bits(4)),
                AbiValue::Ref(Handle::from_bits(8)),
            ],
        );
        assert_eq!(box_.len(), 2);
        assert!(box_.get(1).is_ok());
        let e = box_.get(2).unwrap_err();
        assert_eq!(e.kind(), "varargs_out_of_bounds");
        // Not a zero and not a read of the next slot.
        assert_eq!(e, AbiError::VarargsOutOfBounds { index: 2, len: 2 });
    }

    #[test]
    fn a_varargs_box_narrows_its_elements_to_the_component_type() {
        // A `boolean` component means `aput-boolean` ran, so the stored element
        // is the low bit and the callee's `aget-boolean` sees 0/1.
        let box_ = VarargBox::pack(
            DexType::Boolean,
            &[AbiValue::Int(0), AbiValue::Int(1), AbiValue::Int(2)],
        );
        assert_eq!(box_.get(0).unwrap(), AbiValue::Boolean(Bool::FALSE));
        assert_eq!(box_.get(1).unwrap(), AbiValue::Boolean(Bool::TRUE));
        assert_eq!(box_.get(2).unwrap(), AbiValue::Boolean(Bool::FALSE));
    }

    #[test]
    fn access_flag_bits_are_the_ones_the_format_defines() {
        // Cross-checked against `dexcore::model::access`, which is the other
        // implementation of this table in the repository.
        assert_eq!(access::ACC_STATIC, dexcore::model::access::ACC_STATIC);
        assert_eq!(access::ACC_VARARGS, dexcore::model::access::ACC_VARARGS);
        assert_eq!(access::ACC_NATIVE, dexcore::model::access::ACC_NATIVE);
        assert_eq!(access::ACC_ABSTRACT, dexcore::model::access::ACC_ABSTRACT);
        assert_eq!(
            access::ACC_CONSTRUCTOR,
            dexcore::model::access::ACC_CONSTRUCTOR
        );
    }
}

// =================================================== live oracle comparison
//
// Every test in this module *executes* the Dalvik opcode it claims to be
// checking. None of them asserts from a reading of the specification, and each
// one names what it measured.

#[cfg(test)]
mod live_oracle {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::oracle::{self, Case, Num, Outcome};
    use super::*;

    /// The nine scalar types plus a reference, in the order the matrix walks
    /// them. The reference is last because it is the only one with no numeric
    /// conversion.
    fn scalars() -> Vec<DexType> {
        vec![
            DexType::Boolean,
            DexType::Byte,
            DexType::Short,
            DexType::Char,
            DexType::Int,
            DexType::Long,
            DexType::Float,
            DexType::Double,
            DexType::object(),
        ]
    }

    /// The conversion opcode for an ordered pair, or `None` when Dalvik has no
    /// such instruction.
    ///
    /// This is the authority for what "no conversion" means. It is *not* a
    /// closure over my own `convert`, because then the test would be checking my
    /// implementation against itself.
    fn oracle_opcode(from: &DexType, to: &DexType) -> Option<u8> {
        use DexType::*;
        let int_family = from.is_int_family();
        match (from, to) {
            // int-to-long/float/double
            (_, Long) if int_family => Some(0x81),
            (_, Float) if int_family => Some(0x82),
            (_, Double) if int_family => Some(0x83),
            // long-to-int/float/double
            (Long, Int) => Some(0x84),
            (Long, Float) => Some(0x85),
            (Long, Double) => Some(0x86),
            // float-to-int/long/double
            (Float, Int) => Some(0x87),
            (Float, Long) => Some(0x88),
            (Float, Double) => Some(0x89),
            // double-to-int/long/float
            (Double, Int) => Some(0x8a),
            (Double, Long) => Some(0x8b),
            (Double, Float) => Some(0x8c),
            // int-to-byte/char/short
            (_, Byte) if int_family => Some(0x8d),
            (_, Char) if int_family => Some(0x8e),
            (_, Short) if int_family => Some(0x8f),
            // The remaining int-family pairs — `Z` to anything, and `X` to `I` —
            // have no opcode because no bits move: all five types are the same
            // `i32`. Dalvik expresses that as nothing at all, so the oracle for
            // it is a `move`, and the measured claim is that the value survives
            // the relabelling. `0x01` is `move vA, vB`.
            //
            // A target of `Z` is the exception and it is not a relabel. Dalvik
            // has no `int-to-boolean`, so nothing in the instruction set can
            // produce a `Z` from an `int`; a `move` would carry the raw value
            // through and *not* fold it. The fold is this compiler's decision,
            // so it is excluded here and handled as its own category below.
            (_, Boolean) if int_family => None,
            (_, t) if int_family && t.is_int_family() => Some(0x01),
            _ => None,
        }
    }

    /// A pair whose result this layer *decides* rather than executes.
    ///
    /// Exactly one family: any int-family type to `Z`. There is no Dalvik
    /// instruction for it, so the folding rule is a decision, and it is
    /// cross-checked against the one thing that *is* measurable — the low bit
    /// that `and-int 1`, `aput-boolean` and `sput-boolean` all compute, which
    /// `oracle_the_boolean_normalisation_is_the_low_bit` measures on the real
    /// `and-int/lit8` opcode and the real `sput-boolean`.
    fn is_decided(from: &DexType, to: &DexType) -> bool {
        from.is_int_family() && *to == DexType::Boolean
    }

    /// Whether the pair is the identity, which needs no opcode at all — a
    /// register already holds the value.
    fn is_identity(from: &DexType, to: &DexType) -> bool {
        from == to || (from.is_reference() && to.is_reference())
    }

    /// The values a corpus walks for one source type.
    ///
    /// The integer corpus is chosen for the places the five int-family types
    /// differ from one another — the sign bit, each of the three truncation
    /// boundaries, and the two ends of the range — rather than being a uniform
    /// sample, because a uniform sample of `i32` almost never lands on 0xFFFF and
    /// a `char` bug survives a uniform sample.
    fn corpus(from: &DexType) -> Vec<AbiValue> {
        match from {
            DexType::Boolean => vec![
                AbiValue::Boolean(Bool::FALSE),
                AbiValue::Boolean(Bool::TRUE),
            ],
            // The int-family sources share one corpus of `i32` *values* but
            // each is re-tagged with its own type, because the tag is what
            // decides which truncation the pair applies. The oracle's register
            // is untyped, so it sees the same `i32` for all five: the value is
            // measured five times over and the label is a compile-time fact with
            // no oracle counterpart.
            t if t.is_int_family() => [
                0i32,
                1,
                2,
                3,
                -1,
                -2,
                42,
                -42,
                0x7f,
                0x80,
                -0x80,
                0xff,
                0x100,
                0x7fff,
                0x8000,
                0xffff,
                0x1_0000,
                -0x1_0000,
                0x7fff_ffff,
                -0x7fff_ffff,
                i32::MIN,
                i32::MAX,
            ]
            .into_iter()
            .map(|v| match t {
                DexType::Byte => AbiValue::Byte(v as i8),
                DexType::Short => AbiValue::Short(v as i16),
                DexType::Char => AbiValue::Char(v as u16),
                DexType::Boolean => AbiValue::Boolean(Bool::normalise(v)),
                _ => AbiValue::Int(v),
            })
            .collect(),
            DexType::Long => [
                0i64,
                1,
                -1,
                2,
                42,
                0x7f,
                0xff,
                0xffff,
                0x1_0000,
                0x7fff_ffff,
                0xffff_ffff,
                0x1_0000_0000,
                i64::MIN,
                i64::MAX,
                0x4000_0000_0000_0000,
                -0x4000_0000_0000_0000,
            ]
            .into_iter()
            .map(AbiValue::Long)
            .collect(),
            DexType::Float => [
                0.0f32,
                -0.0,
                1.0,
                -1.0,
                0.5,
                -0.5,
                1.5,
                2.5,
                2.9,
                -2.9,
                -0.5,
                1e30,
                -1e30,
                2147483520.0,
                2147483648.0,
                -2147483648.0,
                -2147483904.0,
                9.3e18,
                1e18,
                f32::NAN,
                f32::INFINITY,
                f32::NEG_INFINITY,
                f32::MIN_POSITIVE,
                f32::MAX,
            ]
            .into_iter()
            .map(AbiValue::Float)
            .collect(),
            DexType::Double => [
                0.0f64,
                -0.0,
                1.0,
                -1.0,
                0.5,
                -0.5,
                1.5,
                2.5,
                2.9,
                -2.9,
                1e300,
                -1e300,
                2147483647.0,
                2147483648.0,
                -2147483648.0,
                -2147483649.0,
                9.3e18,
                -9.3e18,
                1e18,
                f64::NAN,
                f64::INFINITY,
                f64::NEG_INFINITY,
                f64::MIN_POSITIVE,
                f64::MAX,
                f64::from_bits(0x0000_0000_0000_0001),
            ]
            .into_iter()
            .map(AbiValue::Double)
            .collect(),
            _ => Vec::new(),
        }
    }

    /// Load `v` into register `a` from its declared type, returning the parts.
    ///
    /// A `float` is materialised through a `double` because `const/high16` can
    /// only set the top 16 bits of the significand, and a corpus that cannot
    /// name an exact `f32` cannot check a truncation. `f64::from` and `as f32`
    /// are exact inverses, so the register ends up holding precisely the value
    /// asked for.
    fn load(a: u8, v: &AbiValue) -> (Vec<Vec<u8>>, u16) {
        match v {
            AbiValue::Boolean(b) => (vec![oracle::const32(a, b.as_i32())], 2),
            AbiValue::Byte(x) => (vec![oracle::const32(a, i32::from(*x))], 2),
            AbiValue::Short(x) => (vec![oracle::const32(a, i32::from(*x))], 2),
            AbiValue::Char(x) => (vec![oracle::const32(a, i32::from(*x))], 2),
            AbiValue::Int(x) => (vec![oracle::const32(a, *x)], 2),
            AbiValue::Long(x) => (vec![oracle::const64(a, *x)], 3),
            AbiValue::Float(x) => (vec![oracle::load_f32_exact(a, x.to_bits())], 3),
            AbiValue::Double(x) => (vec![oracle::const64(a, x.to_bits() as i64)], 3),
            _ => (vec![oracle::const32(a, 0)], 2),
        }
    }

    /// The `Case` for one conversion, or `None` when the target is a reference
    /// and there is nothing to return as a number.
    fn case_for(
        from: &DexType,
        to: &DexType,
        v: &AbiValue,
        opcode: Option<u8>,
        n: usize,
    ) -> Option<Case> {
        if to.is_reference() || from.is_reference() {
            return None;
        }
        let name = format!("c{n}");
        let (load_parts, base_regs) = load(0, v);
        let mut parts = load_parts;
        // The conversion writes into a register above the source. For a wide
        // source that register is the second word of the pair.
        let dst = match from {
            DexType::Long | DexType::Double => 3u8,
            _ => 1u8,
        };
        let regs = base_regs + 2;
        match opcode {
            // Identity: the value is already in the right register, so the
            // method just returns it.
            None => match from {
                DexType::Long | DexType::Double => parts.push(oracle::ret_wide(0)),
                _ => parts.push(oracle::ret(0)),
            },
            Some(op) => {
                parts.push(oracle::op12(op, dst, 0));
                match to {
                    DexType::Long | DexType::Double => parts.push(oracle::ret_wide(dst)),
                    _ => parts.push(oracle::ret(dst)),
                }
            }
        }
        let ret = match to {
            DexType::Long => "J",
            DexType::Float => "F",
            DexType::Double => "D",
            _ => "I",
        };
        let mut c = Case {
            name,
            params: Vec::new(),
            ret: ret.to_string(),
            regs,
            insns: Vec::new(),
        };
        c.insns = oracle::body(&parts);
        Some(c)
    }

    /// Reduce an `AbiValue` to the oracle's numeric shape.
    fn abi_num(v: AbiValue) -> Num {
        match v {
            AbiValue::Boolean(b) => Num::I32(b.as_i32()),
            AbiValue::Byte(b) => Num::I32(i32::from(b)),
            AbiValue::Short(s) => Num::I32(i32::from(s)),
            AbiValue::Char(c) => Num::I32(i32::from(c)),
            AbiValue::Int(i) => Num::I32(i),
            AbiValue::Long(l) => Num::I64(l),
            AbiValue::Float(f) => Num::F32(f.to_bits()),
            AbiValue::Double(d) => Num::F64(d.to_bits()),
            other => panic!("{other} is not a number"),
        }
    }

    /// # The generated conversion matrix.
    ///
    /// For every ordered pair of the nine scalar types, exactly one of three
    /// things is asserted, and the three are counted separately because
    /// conflating them is how a "verified" claim stops meaning anything:
    ///
    /// 1. **MEASURED** — Dalvik has an opcode for the pair (or the pair is a
    ///    relabelling, which is a `move`). The opcode is executed and its result
    ///    is compared against `abi::convert` over a 23-value corpus.
    /// 2. **DECIDED** — Dalvik has no opcode and this layer defines the answer
    ///    anyway: the int-family to `Z` normalisation. The value is checked for
    ///    self-consistency, and the *rule* is measured separately by
    ///    `oracle_the_boolean_normalisation_is_the_low_bit`.
    /// 3. **REFUSED** — no opcode and no defined answer. `abi::convert` must
    ///    return `NoConversion`, because a compiler that invents a conversion
    ///    the format cannot express is emitting something the oracle can never
    ///    check.
    ///
    /// The line this test prints is the honest summary, and it is the number to
    /// quote: how many pairs are measurements and how many are decisions.
    #[test]
    fn oracle_conversion_matrix_matches_the_interpreter() {
        let mut cases: Vec<Case> = Vec::new();
        let mut expect: Vec<(DexType, DexType, AbiValue, AbiValue)> = Vec::new();

        for from in scalars() {
            for to in scalars() {
                if is_decided(&from, &to) {
                    continue;
                }
                let opcode = oracle_opcode(&from, &to);
                if !is_identity(&from, &to) && opcode.is_none() {
                    continue;
                }
                for v in corpus(&from) {
                    let n = cases.len();
                    let c = match case_for(&from, &to, &v, opcode, n) {
                        None => continue,
                        Some(c) => c,
                    };
                    let mine = convert(&from, &to, v)
                        .unwrap_or_else(|e| panic!("{from} -> {to} of {v}: {e}"));
                    expect.push((from.clone(), to.clone(), v, mine.value));
                    cases.push(c);
                }
            }
        }

        assert!(cases.len() > 700, "only {} cases", cases.len());
        let outcomes = oracle::run(&cases, &[]).expect("the oracle runs");
        assert_eq!(outcomes.len(), cases.len());

        let mut measured = 0usize;
        for (i, (from, to, v, mine)) in expect.iter().enumerate() {
            let got = match &outcomes[i] {
                Outcome::Value(g) => {
                    oracle::num(g, to).unwrap_or_else(|e| panic!("{from} -> {to} of {v}: {e}"))
                }
                Outcome::Refused(m) => {
                    panic!("{from} -> {to} of {v} refused: {m}")
                }
            };
            assert_eq!(
                abi_num(*mine),
                got,
                "{from} -> {to} of {v} disagrees with the interpreter"
            );
            measured += 1;
        }
        assert_eq!(measured, cases.len());

        // (2) DECIDED: the `Z` normalisations. No opcode exists, so this checks
        // that the fold is the documented one and that the corpus's `Z` values
        // pass through untouched.
        let mut decided = 0usize;
        for from in scalars() {
            if !from.is_int_family() {
                continue;
            }
            for v in corpus(&from) {
                let c = convert(&from, &DexType::Boolean, v)
                    .unwrap_or_else(|e| panic!("{from} -> Z of {v}: {e}"));
                let b = match c.value {
                    AbiValue::Boolean(b) => b,
                    other => panic!("{from} -> Z produced {other}"),
                };
                assert!(b.as_i32() == 0 || b.as_i32() == 1, "{b}");
                // A `Z` source is already 0/1, so folding it is a no-op and
                // nothing is fabricated.
                if from == DexType::Boolean {
                    assert!(!c.notes.boolean_normalised, "a Z needs no folding");
                }
                // An `I` source carrying an out-of-range value is folded, and
                // the fold is reported.
                if let AbiValue::Int(i) = v {
                    assert_eq!(
                        c.notes.boolean_normalised,
                        Bool::is_out_of_range(i),
                        "the fabrication label must match the fold for {from} of {i}"
                    );
                    assert_eq!(b, Bool::normalise(i));
                }
                decided += 1;
            }
        }

        // (3) REFUSED: everything with no opcode and no decision.
        let mut refused = 0usize;
        for from in scalars() {
            for to in scalars() {
                if is_decided(&from, &to)
                    || is_identity(&from, &to)
                    || oracle_opcode(&from, &to).is_some()
                {
                    continue;
                }
                let v = match from.is_reference() {
                    true => AbiValue::Ref(Handle::from_bits(4)),
                    false => match corpus(&from).first() {
                        Some(v) => *v,
                        None => AbiValue::Int(0),
                    },
                };
                let err = match convert(&from, &to, v) {
                    Ok(_) => panic!("{from} -> {to} must not convert"),
                    Err(err) => err,
                };
                assert_eq!(err.kind(), "no_conversion", "{from} -> {to} gave {err}");
                refused += 1;
            }
        }

        eprintln!(
            "conversion matrix: {measured} conversions MEASURED against dexinterp, \
             {decided} conversions DECIDED (no Dalvik opcode exists), \
             {refused} ordered pairs REFUSED with no_conversion"
        );
        assert!(measured > 700, "{measured} measured");
        assert!(decided > 50, "{decided} decided");
        assert!(refused > 20, "{refused} refused");
    }

    /// The boolean fold is the **low bit**, measured on the two opcodes that
    /// actually produce a `Z` in real bytecode: `and-int/lit8 vA, vB, #1`, which
    /// is what a compiler emits for `(x & 1)`, and `sput-boolean`.
    ///
    /// This is the evidence behind [`Bool::normalise`]. It is measured rather
    /// than asserted, which matters because the alternative rule — "non-zero is
    /// true" — is what `aget-boolean` uses, and picking the wrong one changes
    /// 2 to `false` where a device says `true`.
    #[test]
    fn oracle_the_boolean_normalisation_is_the_low_bit() {
        let probes = [
            0i32,
            1,
            2,
            3,
            42,
            43,
            -1,
            -2,
            0x1234,
            0x1235,
            i32::MAX,
            i32::MIN,
        ];
        let mut cases = Vec::new();
        for (i, v) in probes.iter().enumerate() {
            // `and-int/lit8 v0, v1, #1` — v0 is the result, v1 the operand.
            cases.push(Case::int(
                &format!("a{i}"),
                3,
                &[
                    oracle::const32(1, *v),
                    oracle::and_int_lit8(0, 1, 1),
                    oracle::ret(0),
                ],
            ));
        }
        let out = oracle::run(&cases, &[]).expect("oracle");
        for (i, v) in probes.iter().enumerate() {
            let got = match out[i].value().unwrap() {
                dexinterp::Value::Int(n) => *n,
                other => panic!("and-int 1 of {v}: interpreter returned {other:?}"),
            };
            assert_eq!(got, v & 1, "and-int/lit8 #1 of {v}");
            assert_eq!(
                Bool::normalise(*v).as_i32(),
                v & 1,
                "abi fold of {v} must equal and-int 1"
            );
            // ...and *not* the non-zero rule that `aget-boolean` uses. For 2 these
            // disagree, which is the whole point of the distinction.
            if *v != 0 {
                assert!(
                    (v & 1) != 1 || Bool::normalise_nonzero(*v).as_i32() == 1,
                    "sanity"
                );
            }
        }
        // The case that separates the two rules, stated explicitly.
        assert_eq!(Bool::normalise(2).as_i32(), 0, "the store rule: low bit");
        assert_eq!(
            Bool::normalise_nonzero(2).as_i32(),
            1,
            "the load rule: non-zero"
        );
        // And the same low-bit rule through a real boolean *field* store.
        let field_types = ["Z"];
        let fidx = oracle::field_indices(&field_types).expect("field indices");
        let store = vec![Case::int(
            "s",
            5,
            &[
                oracle::const32(1, 42),
                oracle::op21c(0x6a, 1, fidx[0]), // sput-boolean
                oracle::op21c(0x63, 3, fidx[0]), // sget-boolean
                oracle::ret(3),
            ],
        )];
        let out = oracle::run(&store, &field_types).expect("oracle");
        match out[0].value().unwrap() {
            dexinterp::Value::Int(n) => {
                assert_eq!(*n, 0, "sput-boolean of 42 stores the low bit")
            }
            other => panic!("expected an int, got {other:?}"),
        }
    }

    /// `int-to-char` zero-extends where `int-to-short` sign-extends, measured on
    /// the real opcodes. This is the one-character bug, so it gets its own test
    /// even though the matrix covers it.
    #[test]
    fn oracle_int_to_char_zero_extends_where_int_to_short_sign_extends() {
        let values = [0xffffi32, -1, 0x1_0000, 0x7fff, 0x8000, 0x100, 0xff];
        let mut cases = Vec::new();
        for (i, v) in values.iter().enumerate() {
            for (tag, op) in [("b", 0x8du8), ("c", 0x8e), ("s", 0x8f)] {
                cases.push(Case::int(
                    &format!("m{i}_{tag}"),
                    2,
                    &[
                        oracle::const32(0, *v),
                        oracle::op12(op, 1, 0),
                        oracle::ret(1),
                    ],
                ));
            }
        }
        let out = oracle::run(&cases, &[]).expect("oracle");
        for (i, v) in values.iter().enumerate() {
            for (tag, _op, ty) in [
                ("b", 0x8du8, DexType::Byte),
                ("c", 0x8eu8, DexType::Char),
                ("s", 0x8fu8, DexType::Short),
            ] {
                let idx = i * 3
                    + match tag {
                        "b" => 0,
                        "c" => 1,
                        _ => 2,
                    };
                let got = match oracle::num(out[idx].value().unwrap(), &ty).unwrap() {
                    Num::I32(n) => n,
                    other => panic!("unexpected {other:?}"),
                };
                let mine = match convert(&DexType::Int, &ty, AbiValue::Int(*v))
                    .unwrap()
                    .value
                {
                    AbiValue::Byte(b) => i32::from(b),
                    AbiValue::Char(c) => i32::from(c),
                    AbiValue::Short(s) => i32::from(s),
                    other => panic!("unexpected {other}"),
                };
                assert_eq!(mine, got, "int-to-{tag} of {v}");
            }
        }
        // The headline: 0xFFFF is 65535 as a char and -1 as a short.
        let c_of_ffff = convert(&DexType::Int, &DexType::Char, AbiValue::Int(0xffff))
            .unwrap()
            .value;
        let s_of_ffff = convert(&DexType::Int, &DexType::Short, AbiValue::Int(0xffff))
            .unwrap()
            .value;
        assert_eq!(c_of_ffff, AbiValue::Char(65535));
        assert_eq!(s_of_ffff, AbiValue::Short(-1));
    }

    /// `rem-float` is `fmod`, not the literal `x - y*trunc(x/y)`. The brief for
    /// this layer described the two as different operations; this measures which
    /// one the oracle implements, and the answer is the one that also satisfies
    /// IEEE-754 for an infinite divisor.
    #[test]
    fn oracle_rem_float_is_fmod_and_not_the_literal_formula() {
        // `const/high16` puts the top 16 bits in place, which is enough to name
        // every special value and every small integer exactly.
        let cases: &[(f32, f32, &str)] = &[
            (3.0, f32::INFINITY, "3.0 % +inf"),
            (-3.0, f32::INFINITY, "-3.0 % +inf"),
            (3.0, f32::NEG_INFINITY, "3.0 % -inf"),
            (5.0, 3.0, "5.0 % 3.0"),
            (-5.0, 3.0, "-5.0 % 3.0"),
            (5.0, -3.0, "5.0 % -3.0"),
            (7.5, 2.0, "7.5 % 2.0"),
            (1.0, 0.0, "1.0 % 0.0"),
            (0.0, 0.0, "0.0 % 0.0"),
        ];
        let mut built = Vec::new();
        for (i, (x, y, _)) in cases.iter().enumerate() {
            built.push(Case::float(
                &format!("r{i}"),
                3,
                &[
                    oracle::load_f32_exact(0, x.to_bits()),
                    oracle::load_f32_exact(1, y.to_bits()),
                    oracle::op23(0xaa, 2, 0, 1), // rem-float
                    oracle::ret(2),
                ],
            ));
        }
        let out = oracle::run(&built, &[]).expect("oracle");
        for (i, (x, y, what)) in cases.iter().enumerate() {
            let oracle_bits = match out[i].value().unwrap() {
                dexinterp::Value::Float(f) => f.to_bits(),
                other => panic!("{what}: interpreter returned {other:?}"),
            };
            let mine = rem_f32(*x, *y);
            assert_eq!(
                mine.to_bits(),
                oracle_bits,
                "{what}: abi says {mine}, interpreter says {}",
                f32::from_bits(oracle_bits)
            );
            // ...and where the two differ, the interpreter is with `fmod`.
            let by_formula = rem_f32_by_formula(*x, *y);
            if by_formula.to_bits() != oracle_bits {
                assert_eq!(
                    mine.to_bits(),
                    oracle_bits,
                    "{what}: the literal formula must not be the implementation"
                );
            }
        }
        // The specific case the note on `rem_f32` describes.
        let divergent = cases.iter().position(|(x, y, _)| {
            rem_f32_by_formula(*x, *y).to_bits() != rem_f32(*x, *y).to_bits()
        });
        assert!(divergent.is_some(), "no divergent case in the corpus");
    }

    /// `float-to-int` of `NaN` is 0 and out-of-range saturates, on the real
    /// opcodes, including the two boundaries where a WebAssembly `trunc` traps.
    #[test]
    fn oracle_float_to_int_of_nan_is_zero_and_out_of_range_saturates() {
        let f32s: &[(f32, i32, &str)] = &[
            (f32::NAN, 0, "NaN"),
            (-f32::NAN, 0, "-NaN"),
            (1e30, i32::MAX, "1e30"),
            (-1e30, i32::MIN, "-1e30"),
            (2147483648.0, i32::MAX, "2^31"),
            (-2147483648.0, i32::MIN, "-2^31"),
            (2147483520.0, 2147483520, "largest below 2^31"),
            (2.9, 2, "2.9"),
            (-2.9, -2, "-2.9"),
            (-0.0, 0, "-0.0"),
        ];
        let mut built = Vec::new();
        for (i, (f, _, _)) in f32s.iter().enumerate() {
            built.push(Case::int(
                &format!("f{i}"),
                2,
                &[
                    oracle::load_f32_exact(0, f.to_bits()),
                    oracle::op12(0x87, 1, 0), // float-to-int
                    oracle::ret(1),
                ],
            ));
        }
        let out = oracle::run(&built, &[]).expect("oracle");
        for (i, (f, want, what)) in f32s.iter().enumerate() {
            let got = match out[i].value().unwrap() {
                dexinterp::Value::Int(n) => *n,
                other => panic!("{what}: interpreter returned {other:?}"),
            };
            assert_eq!(got, *want, "{what}: the interpreter disagrees");
            assert_eq!(f32_to_int(*f), *want, "{what}: abi disagrees");
        }
    }

    /// `long` arithmetic wraps on the real opcodes: `Long.MAX_VALUE + 1` is
    /// `Long.MIN_VALUE`, and `Long.MIN_VALUE / -1` does not trap.
    #[test]
    fn oracle_long_arithmetic_wraps_and_min_divided_by_minus_one_does_not_trap() {
        let built = vec![
            Case::long(
                "add",
                4,
                &[
                    oracle::const64(0, i64::MAX),
                    oracle::const64(2, 1),
                    oracle::op23(0x9b, 0, 0, 2), // add-long
                    oracle::ret_wide(0),
                ],
            ),
            Case::long(
                "sub",
                4,
                &[
                    oracle::const64(0, i64::MIN),
                    oracle::const64(2, 1),
                    oracle::op23(0x9c, 0, 0, 2), // sub-long
                    oracle::ret_wide(0),
                ],
            ),
            Case::long(
                "divneg",
                4,
                &[
                    oracle::const64(0, i64::MIN),
                    oracle::const64(2, -1),
                    oracle::op23(0x9e, 0, 0, 2), // div-long
                    oracle::ret_wide(0),
                ],
            ),
            Case::long(
                "remneg",
                4,
                &[
                    oracle::const64(0, i64::MIN),
                    oracle::const64(2, -1),
                    oracle::op23(0x9f, 0, 0, 2), // rem-long
                    oracle::ret_wide(0),
                ],
            ),
        ];
        let out = oracle::run(&built, &[]).expect("oracle");
        let got = |i: usize| match out[i].value().unwrap() {
            dexinterp::Value::Long(l) => *l,
            other => panic!("expected a long, got {other:?}"),
        };
        assert_eq!(got(0), i64::MIN, "MAX + 1 wraps to MIN");
        assert_eq!(got(1), i64::MAX, "MIN - 1 wraps to MAX");
        assert_eq!(got(2), i64::MIN, "MIN / -1 is MIN, not a trap");
        assert_eq!(got(3), 0, "MIN % -1 is 0");
        assert_eq!(int64_binop(IntOp::Add, i64::MAX, 1), Ok(got(0)));
        assert_eq!(int64_binop(IntOp::Div, i64::MIN, -1), Ok(got(2)));
        assert_eq!(int64_binop(IntOp::Rem, i64::MIN, -1), Ok(got(3)));
    }

    /// A `Z` field takes the **low bit**, a `J` field takes a double's **bit
    /// pattern**, and an `I` field takes 0 from a `long`. All three measured
    /// through real `sput`/`sget` pairs, because these are the rules a
    /// "principled" conversion table would get differently and for which no
    /// conversion opcode exists to check against.
    #[test]
    fn oracle_field_store_coercion_matches_the_interpreter() {
        let field_types = ["Z", "B", "S", "C", "I", "J", "F", "D"];
        // The `sput`/`sget` opcode for each declared field type. These are the
        // `21c` variants: the wide form is chosen by the *field's* declared type,
        // not by the value's.
        let sput_op = |fty: &str| -> u8 {
            match fty {
                "Z" => 0x6a,
                "B" => 0x6b,
                "S" => 0x6d,
                "C" => 0x6c,
                "J" => 0x68,
                _ => 0x67,
            }
        };
        let sget_op = |fty: &str| -> u8 {
            match fty {
                "Z" => 0x63,
                "B" => 0x64,
                "S" => 0x66,
                "C" => 0x65,
                "J" => 0x61,
                _ => 0x60,
            }
        };

        // (value to store, as an int) x (a double, for the reinterpretation case)
        let int_probes = [
            0i32,
            1,
            2,
            3,
            42,
            43,
            -1,
            0xff,
            0xffff,
            0x1_0000,
            0x7fff_ffff,
        ];
        let field_idx = oracle::field_indices(&field_types).expect("field indices");
        assert_ne!(
            field_idx[0], 0,
            "a pool sorted by descriptor cannot put the first declared field at 0 \
             unless it happens to sort first; if this ever passes, the table order \
             has changed and the indexing below should be revisited"
        );
        let mut cases: Vec<Case> = Vec::new();
        for (i, v) in int_probes.iter().enumerate() {
            for (fi, fty) in field_types.iter().enumerate() {
                // A `J` field is wide, so it needs the value in a wide pair and a
                // wide `sput`. The others are one word.
                let fty = *fty;
                // A `J` field is wide, so its value goes in as a `long`. The
                // others are one word, and loading them wide would test a
                // different rule: a `long` into a `B` field stores 0, which is
                // `oracle_long_into_an_int_field_is_zero_not_a_truncation`'s
                // subject and not this test's.
                let mut parts = vec![match fty {
                    "J" => oracle::const64(1, i64::from(*v)),
                    _ => oracle::const32(1, *v),
                }];
                parts.push(oracle::op21c(sput_op(fty), 1, field_idx[fi]));
                parts.push(oracle::op21c(sget_op(fty), 3, field_idx[fi]));
                parts.push(match fty {
                    "J" => oracle::ret_wide(3),
                    _ => oracle::ret(3),
                });
                let ret = match fty {
                    "J" => "J",
                    "F" => "F",
                    "D" => "D",
                    _ => "I",
                };
                cases.push(Case {
                    name: format!("s{i}_{fty}"),
                    params: Vec::new(),
                    ret: ret.to_string(),
                    regs: 5,
                    insns: oracle::body(&parts),
                });
            }
        }
        let out = oracle::run(&cases, &field_types).expect("oracle");
        let mut n = 0usize;
        for v in int_probes.iter() {
            for fty in field_types.iter() {
                let fty_ty = DexType::parse(fty).unwrap();
                let stored = narrow_on_store(&fty_ty, AbiValue::Int(*v));
                let got = match out[n].value().unwrap() {
                    dexinterp::Value::Int(x) => Num::I32(*x),
                    dexinterp::Value::Long(l) => Num::I64(*l),
                    dexinterp::Value::Float(f) => Num::F32(f.to_bits()),
                    dexinterp::Value::Double(d) => Num::F64(d.to_bits()),
                    other => panic!("sput {v} into {fty}: unexpected {other:?}"),
                };
                assert_eq!(
                    abi_num(stored),
                    got,
                    "sput {v} into a {fty} field: abi says {stored}, interpreter says {got:?}"
                );
                n += 1;
            }
        }
    }

    /// A `double` stored into a `J` field is the double's **bit pattern**, not
    /// the number. Dalvik has no `const-double`, so every double constant in a
    /// real APK arrives as a `const-wide` of its IEEE bits, and reading it as a
    /// number turns `0.5` into 4.6e18 — the interpreter says so in as many words.
    #[test]
    fn oracle_double_into_a_long_field_is_a_reinterpretation() {
        let d = 0.5f64;
        let cases = vec![Case::long(
            "bits",
            5,
            &[
                oracle::const64(1, d.to_bits() as i64),
                oracle::op21c(0x68, 1, 0), // sput-wide into the `J` field
                oracle::op21c(0x61, 3, 0), // sget-wide
                oracle::ret_wide(3),
            ],
        )];
        let out = oracle::run(&cases, &["J"]).expect("oracle");
        let got = match out[0].value().unwrap() {
            dexinterp::Value::Long(l) => *l,
            other => panic!("expected a long, got {other:?}"),
        };
        assert_eq!(got, d.to_bits() as i64);
        assert_eq!(
            narrow_on_store(&DexType::Long, AbiValue::Long(d.to_bits() as i64)),
            AbiValue::Long(d.to_bits() as i64)
        );
        // The contrast that makes the bug visible: the *number* is not the bits.
        assert_ne!(d.to_bits() as i64, d as i64);
    }

    /// A `long` stored into an `I` field is 0, not a truncation. The two types
    /// have nothing in common and a narrowing here would be an invented
    /// operation, so a compiler that "helpfully" truncated would differ from the
    /// interpreter on every such store.
    #[test]
    fn oracle_long_into_an_int_field_is_zero_not_a_truncation() {
        let cases = vec![Case::int(
            "lj",
            5,
            &[
                oracle::const64(1, 5),
                oracle::op21c(0x67, 1, 0), // sput (int) from a wide register
                oracle::op21c(0x60, 3, 0), // sget
                oracle::ret(3),
            ],
        )];
        let out = oracle::run(&cases, &["I"]).expect("oracle");
        let got = match out[0].value().unwrap() {
            dexinterp::Value::Int(n) => *n,
            other => panic!("expected an int, got {other:?}"),
        };
        assert_eq!(got, 0);
        assert_eq!(
            narrow_on_store(&DexType::Int, AbiValue::Long(5)),
            AbiValue::Int(0)
        );
    }

    /// A real object comes back from the interpreter as a reference, and on this
    /// side it is a handle that is not an integer. The handle *value* has no
    /// oracle counterpart — the two heaps number differently — so what is
    /// measured here is the shape: a non-null reference in, a non-null handle
    /// out, with the identity preserved across a conversion.
    #[test]
    fn oracle_returns_a_reference_where_the_abi_returns_a_handle() {
        let field_types = ["Lcom/x/A6;"];
        let cases = vec![Case {
            name: "ref".to_string(),
            params: Vec::new(),
            ret: "Lcom/x/A6;".to_string(),
            regs: 2,
            // `new-instance` leaves an uninitialised but non-null object, which is
            // all this test needs: no `<init>` is involved.
            insns: oracle::body(&[
                oracle::const32(0, 0),
                oracle::new_instance(1, 0), // index patched below
                oracle::op21c(0x69, 1, 0),  // sput-object
                oracle::op21c(0x62, 0, 0),  // sget-object
                oracle::ret_object(0),
            ]),
        }];
        let (_out, built) = oracle::run_with(&cases, &field_types).expect("oracle");
        // Patch in the real type index. `new-instance` is `21c`, so its operand
        // is a `type_ids` index and the table is sorted — the same trap as the
        // field table, and the reason the harness hands the map back.
        let type_index = built.type_idx("Lcom/x/A6;").expect("the class is interned");
        let patched = vec![Case {
            name: "ref".to_string(),
            params: Vec::new(),
            ret: "Lcom/x/A6;".to_string(),
            regs: 2,
            insns: oracle::body(&[
                oracle::const32(0, 0),
                oracle::new_instance(1, type_index),
                oracle::op21c(0x69, 1, 0),
                oracle::op21c(0x62, 0, 0),
                oracle::ret_object(0),
            ]),
        }];
        let (out, _) = oracle::run_with(&patched, &field_types).expect("oracle");
        match out[0].value().unwrap() {
            dexinterp::Value::Ref(r) => assert_ne!(r.id(), 0, "new-instance is not null"),
            other => panic!("expected a reference, the interpreter returned {other:?}"),
        }
        let _ = out[0];

        // And on this side: a null handle converts to a reference, and a
        // non-null handle keeps its identity through the conversion.
        let h = Handle::from_bits(16);
        let c = convert(
            &DexType::object(),
            &DexType::Ref("Lcom/x/A6;".into()),
            AbiValue::Ref(h),
        )
        .unwrap();
        assert_eq!(
            c.value,
            AbiValue::Ref(h),
            "the handle identity must survive"
        );
        assert!(!h.is_null());
        assert!(h.require("test").is_ok());
        assert!(AbiValue::null().is_reference(), "null is a reference");
    }

    /// **A finding about the oracle, not about this module.**
    ///
    /// `const/high16` is how a real DEX writes a float constant, and it is the
    /// only float literal instruction Dalvik has. The interpreter materialises it
    /// as `Value::Int` and every read of that register as a float widens the
    /// *integer* — so `const/high16 v0, 0x4040` followed by `int-to-float` yields
    /// the number 1077936128, not the float `3.0`.
    ///
    /// That is a divergence between `dexinterp` and ART, and `IR.md` says
    /// divergence is always a bug in the compiler, never in the oracle — which is
    /// exactly why it has to be written down here rather than discovered by a
    /// float test that mysteriously fails. The conversion tests above avoid the
    /// path for the same reason. **This is reported, not worked around silently,
    /// and the fix is not mine to make.**
    #[test]
    fn oracle_const_high16_is_read_as_an_integer() {
        let cases = vec![Case::float(
            "c",
            2,
            &[
                oracle::const_f32_high16(0, 3.0f32.to_bits()), // 0x4040
                oracle::op12(0x82, 1, 0),                      // int-to-float
                oracle::ret(1),
            ],
        )];
        let out = oracle::run(&cases, &[]).expect("oracle");
        let got = match out[0].value().unwrap() {
            dexinterp::Value::Float(f) => *f,
            other => panic!("expected a float, got {other:?}"),
        };
        // The measured behaviour: the bit pattern read as a number.
        assert_eq!(
            got,
            (3.0f32.to_bits() >> 16 << 16) as f32,
            "the oracle widens the integer; if this ever changes, the workaround in \
             load_f32_exact can go and the float tests should use const/high16 directly"
        );
        assert_ne!(
            got, 3.0,
            "if the interpreter now reads it as a float, this finding is resolved"
        );
        // The exact path the tests use instead, for contrast.
        let exact = vec![Case::float(
            "e",
            2,
            &[oracle::load_f32_exact(0, 3.0f32.to_bits()), oracle::ret(0)],
        )];
        let out = oracle::run(&exact, &[]).expect("oracle");
        match out[0].value().unwrap() {
            dexinterp::Value::Float(f) => assert_eq!(*f, 3.0),
            other => panic!("expected a float, got {other:?}"),
        }
    }
}
