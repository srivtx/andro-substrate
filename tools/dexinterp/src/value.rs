//! Register values and the type lattice.
//!
//! A Dalvik register file is an array of 32-bit *words*; `long` and `double`
//! occupy two consecutive words and everything else occupies one. This module
//! models that faithfully rather than pretending the register file is a stack
//! of tagged values:
//!
//! * a `long`/`double` value lives in the **low** word of its pair;
//! * the **high** word holds [`Value::WidePad`], a poison value.
//!
//! The consequence is the point of the design. `move-wide v0, v2` is two
//! register writes, not a struct copy; `return-wide v0` reads one value; and
//! reading the high word directly — which the Dalvik verifier forbids and
//! well-formed bytecode never does — produces a *type error* rather than the
//! silently wrong half of a number. An interpreter that quietly returned the
//! wrong value would be the worst possible instrument for this study, because
//! the taxonomy's `MISBEHAVE` class is exactly the failure it must not hide.
//!
//! Because there is no verifier (see `docs/decisions/0003-execution-engine.md`),
//! type errors are *detected at run time* instead of before execution. They
//! are reported as [`ExecError::Malformed`](crate::error::ExecError::Malformed)
//! with [`Malformed::TypeMismatch`](crate::error::Malformed::TypeMismatch),
//! which the study records as "the engine reached bytecode ART would have
//! rejected at install time" — a real and reportable divergence.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

use std::fmt;

/// A heap object handle. `Ref(0)` is never constructed; use [`Value::Null`].
///
/// Handles are indices into [`Heap`](crate::heap::Heap) and are stable for the
/// lifetime of the interpreter. Because they are `Copy` and comparable, a
/// [`Host`](crate::host::Host) implementation can use one as a map key to
/// remember which of *its* objects a given app object corresponds to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ref(pub u32);

impl Ref {
    /// The raw heap index.
    pub fn id(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ref({})", self.0)
    }
}

impl fmt::Display for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.0)
    }
}

/// One value in a Dalvik register.
///
/// Integer-family types (`Z`, `B`, `S`, `C`, `I`) all live in [`Value::Int`];
/// a Dalvik register has no type, and the *widths* are handled by the specific
/// opcodes (`int-to-byte`, `int-to-char`, `aget-short`, ...), not by the
/// register. See [`JType`] for the static side.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub enum Value {
    /// A register that has never been written. The verifier guarantees no
    /// instruction reads one; without a verifier, reading one is a
    /// [`Malformed::UninitialisedRegister`](crate::error::Malformed::UninitialisedRegister).
    #[default]
    Uninit,
    /// The result of `return-void`. Never stored in a register.
    Void,
    /// The null reference.
    Null,
    /// Any 32-bit integer type: `Z`, `B`, `S`, `C`, `I`.
    Int(i32),
    /// A `long`. Occupies two register words.
    Long(i64),
    /// A `float`.
    Float(f32),
    /// A `double`. Occupies two register words.
    Double(f64),
    /// A reference to a heap object.
    Ref(Ref),
    /// The high word of a `long` or `double` pair. Poison: reading it is a type
    /// error, and overwriting it is a bug the engine reports.
    WidePad,
}

impl Value {
    /// How many 32-bit register words this value occupies.
    pub fn slots(self) -> usize {
        match self {
            Value::Long(_) | Value::Double(_) => 2,
            _ => 1,
        }
    }

    /// A short name for diagnostics: `"int"`, `"ref"`, `"long"`, ...
    pub fn type_name(self) -> &'static str {
        match self {
            Value::Uninit => "uninitialised",
            Value::Void => "void",
            Value::Null => "null",
            Value::Int(_) => "int",
            Value::Long(_) => "long",
            Value::Float(_) => "float",
            Value::Double(_) => "double",
            Value::Ref(_) => "reference",
            Value::WidePad => "wide-high-word",
        }
    }

    /// True for `Null` and `Ref`, the two values a `catch` type test accepts.
    pub fn is_reference(self) -> bool {
        matches!(self, Value::Null | Value::Ref(_))
    }

    /// The zero value for a descriptor, or `None` for `V` and for descriptors
    /// this module does not model.
    pub fn default_for(ty: &JType) -> Option<Value> {
        Some(match ty {
            JType::Void => Value::Void,
            JType::Boolean | JType::Byte | JType::Short | JType::Char | JType::Int => Value::Int(0),
            JType::Long => Value::Long(0),
            JType::Float => Value::Float(0.0),
            JType::Double => Value::Double(0.0),
            JType::Ref(_) | JType::Array(_) => Value::Null,
        })
    }

    /// Read this value as an `int`. Strict: only [`Value::Int`] is accepted.
    pub fn as_int(self, what: &'static str) -> Result<i32, WrongType> {
        match self {
            Value::Int(i) => Ok(i),
            other => Err(WrongType {
                expected: "int",
                found: other.type_name(),
                what,
            }),
        }
    }

    /// Read this value as a `long`.
    ///
    /// `Int` is accepted and widened, because ART reads 64-bit operand words
    /// without a run-time type check and a widening is the only value that can
    /// be right; `Double` is not, because the two have nothing in common.
    pub fn as_long(self, what: &'static str) -> Result<i64, WrongType> {
        match self {
            Value::Long(l) => Ok(l),
            Value::Int(i) => Ok(i64::from(i)),
            other => Err(WrongType {
                expected: "long",
                found: other.type_name(),
                what,
            }),
        }
    }

    /// Read this value as a `float`. `Int` is widened.
    ///
    /// A `long` is *not* accepted, and the reason is the register model rather
    /// than caution: a `float` occupies one register word, and the only things
    /// that can put a number in one word are `const`/`const-string` (an `int`),
    /// `int-to-float`/`double-to-float` (a `float`) and a shim. A `long` in a
    /// float operand slot is a type error, and widening it would invent a huge
    /// number that looks like a plausible result.
    pub fn as_float(self, what: &'static str) -> Result<f32, WrongType> {
        match self {
            Value::Float(f) => Ok(f),
            Value::Int(i) => Ok(i as f32),
            other => Err(WrongType {
                expected: "float",
                found: other.type_name(),
                what,
            }),
        }
    }

    /// Read this value as a `double`.
    ///
    /// **A `long` is reinterpreted, not converted.** Dalvik has no
    /// `const-double`: a double literal is materialised with `const-wide`, whose
    /// payload *is* the IEEE-754 bit pattern, and the Dalvik verifier types the
    /// register pair as a `double` by context. So `const-wide v0, 0x3fe0000000000000L`
    /// followed by `add-double v2, v0, v4` is how a compiler writes `0.5 + x`, and
    /// this engine holds those two words as [`Value::Long`]. Reading them as a
    /// *number* — `0x3fe0000000000000 as f64`, which is 4.6e18 — turns every
    /// double constant in a real APK into a plausible wrong answer, which is the
    /// single worst failure mode an instrument like this can have.
    ///
    /// `int` is not accepted: a `double` in one register word does not exist, and
    /// accepting it would hide the same class of bug on the other side.
    pub fn as_double(self, what: &'static str) -> Result<f64, WrongType> {
        match self {
            Value::Double(d) => Ok(d),
            Value::Long(bits) => Ok(f64::from_bits(bits as u64)),
            other => Err(WrongType {
                expected: "double",
                found: other.type_name(),
                what,
            }),
        }
    }

    /// Read this value as a reference. Only `Null` and `Ref` are accepted.
    pub fn as_ref(self, what: &'static str) -> Result<Ref, WrongType> {
        match self {
            Value::Ref(r) => Ok(r),
            Value::Null => Err(WrongType {
                expected: "non-null reference",
                found: "null",
                what,
            }),
            other => Err(WrongType {
                expected: "reference",
                found: other.type_name(),
                what,
            }),
        }
    }

    /// Like [`Value::as_ref`] but tolerating `null`, returning `None` for it.
    pub fn ref_or_null(self, what: &'static str) -> Result<Option<Ref>, WrongType> {
        match self {
            Value::Ref(r) => Ok(Some(r)),
            Value::Null => Ok(None),
            other => Err(WrongType {
                expected: "reference",
                found: other.type_name(),
                what,
            }),
        }
    }
}

/// A value read with the wrong type, or a value that is null where an object
/// was required. Carries the *instruction* that wanted the value, so the error
/// can point at a `check-cast`, an `iget`, a `div-int`, ... rather than at the
/// engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrongType {
    /// What the instruction needed.
    pub expected: &'static str,
    /// What the register actually held.
    pub found: &'static str,
    /// The instruction that needed it, e.g. `"div-int v0, v1, v2"`.
    pub what: &'static str,
}

impl fmt::Display for WrongType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: expected {}, register held {}",
            self.what, self.expected, self.found
        )
    }
}

/// A parsed type descriptor.
///
/// Parsing is total for anything that starts with `V`, one of `ZBCSIJFD`, `L`
/// or `[`: the recursion consumes exactly one descriptor at each `[`. A
/// malformed descriptor produces [`JType::Ref`] holding the raw text, so a
/// corrupt file degrades into a type whose name can still be reported and
/// compared, rather than into a hard failure in the middle of `new-instance`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum JType {
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
    /// `L...;` — a class reference, or a descriptor that did not parse.
    Ref(String),
    /// `[X` — an array of `X`.
    Array(Box<JType>),
}

impl JType {
    /// The single-character descriptors, in the order the specification lists
    /// them. Anything not in this table is a class or array reference.
    const PRIMITIVES: [(&'static str, JType); 9] = [
        ("V", JType::Void),
        ("Z", JType::Boolean),
        ("B", JType::Byte),
        ("S", JType::Short),
        ("C", JType::Char),
        ("I", JType::Int),
        ("J", JType::Long),
        ("F", JType::Float),
        ("D", JType::Double),
    ];

    /// Parse a type descriptor. Total: unrecognised text becomes
    /// [`JType::Ref`] verbatim.
    pub fn parse(descriptor: &str) -> JType {
        let bytes = descriptor.as_bytes();
        if bytes.is_empty() {
            return JType::Ref(descriptor.to_string());
        }
        if let Some(element) = descriptor.strip_prefix('[') {
            // `[V` is not a legal array type, but keeping it addressable is
            // better than failing, and it can only come from a corrupt file.
            return JType::Array(Box::new(JType::parse(element)));
        }
        for (name, ty) in JType::PRIMITIVES {
            if descriptor == name {
                return ty;
            }
        }
        JType::Ref(descriptor.to_string())
    }

    /// The descriptor text, reconstructing it from a parsed type.
    pub fn descriptor(&self) -> String {
        match self {
            JType::Void => "V".to_string(),
            JType::Boolean => "Z".to_string(),
            JType::Byte => "B".to_string(),
            JType::Short => "S".to_string(),
            JType::Char => "C".to_string(),
            JType::Int => "I".to_string(),
            JType::Long => "J".to_string(),
            JType::Float => "F".to_string(),
            JType::Double => "D".to_string(),
            JType::Ref(s) => s.clone(),
            JType::Array(inner) => format!("[{}", inner.descriptor()),
        }
    }

    /// Number of 32-bit register words: 2 for `long`/`double`, 0 for `void`,
    /// 1 otherwise.
    pub fn slots(&self) -> usize {
        match self {
            JType::Void => 0,
            JType::Long | JType::Double => 2,
            _ => 1,
        }
    }

    /// Byte width in an array, for `aput`/`aget` and `fill-array-data`.
    pub fn element_width(&self) -> u16 {
        match self {
            JType::Boolean | JType::Byte => 1,
            JType::Char | JType::Short => 2,
            JType::Int | JType::Float => 4,
            JType::Long | JType::Double => 8,
            JType::Void => 0,
            JType::Ref(_) | JType::Array(_) => 4,
        }
    }

    /// True for anything that can hold a `Ref` or `Null`.
    pub fn is_reference(&self) -> bool {
        matches!(self, JType::Ref(_) | JType::Array(_))
    }

    /// The class descriptor an `instance-of`/`check-cast` names, if any.
    ///
    /// `[[I` is a reference type but is not castable to a class, so this
    /// returns `None` for it.
    pub fn class_descriptor(&self) -> Option<&str> {
        match self {
            JType::Ref(s) => Some(s),
            _ => None,
        }
    }

    /// The element type of an array, or `None` if this is not an array.
    pub fn component(&self) -> Option<&JType> {
        match self {
            JType::Array(inner) => Some(inner),
            _ => None,
        }
    }

    /// The declared parameter list of a prototype descriptor `(II)V`.
    ///
    /// Returns the parameter types and the return type. A descriptor that does
    /// not start with `(` yields an empty parameter list and the whole string
    /// as the return type, so a malformed proto cannot panic the parser.
    pub fn parse_prototype(signature: &str) -> (Vec<JType>, JType) {
        let rest = match signature.strip_prefix('(') {
            Some(r) => r,
            None => return (Vec::new(), JType::parse(signature)),
        };
        // The parameter list is a *concatenation* of descriptors, so it has to be
        // consumed one descriptor at a time. Splitting on the first `)` would
        // read `(IJLjava/lang/String;)` as a single parameter, and a reference
        // type is the only place the difference shows up — which is most of
        // what a real DEX method takes.
        let mut params = Vec::new();
        let mut at = 0usize;
        while at < rest.len() {
            match rest.as_bytes().get(at) {
                Some(b')') => {
                    at += 1;
                    break;
                }
                Some(b'[') => {
                    // Consume every '[' plus the element descriptor.
                    let mut end = at;
                    while rest.as_bytes().get(end) == Some(&b'[') {
                        end += 1;
                    }
                    let one = descriptor_width(&rest[end..]);
                    end += one;
                    params.push(JType::parse(rest.get(at..end).unwrap_or("")));
                    at = end;
                }
                Some(_) => {
                    let end = at + descriptor_width(&rest[at..]);
                    params.push(JType::parse(rest.get(at..end).unwrap_or("")));
                    at = end;
                }
                None => break,
            }
        }
        (params, JType::parse(rest.get(at..).unwrap_or("")))
    }

    /// Whether this type is assignable to `other`, used only where the spec
    /// says so: `aput` into an object array, and `filled-new-array` targets.
    pub fn is_assignable_from(&self, other: &JType) -> bool {
        if self == other {
            return true;
        }
        match (self, other) {
            (JType::Array(a), JType::Ref(_)) => a.is_reference(),
            _ => false,
        }
    }
}

/// The byte length of the descriptor starting at the front of `s`: one byte for
/// a primitive, up to the `;` for a class, and `[` plus the element for an
/// array.
fn descriptor_width(s: &str) -> usize {
    let b = s.as_bytes();
    match b.first() {
        None => 0,
        Some(b'[') => 1 + descriptor_width(s.get(1..).unwrap_or("")),
        Some(b'L') => s.find(';').map(|i| i + 1).unwrap_or(b.len()),
        Some(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    // The crate forbids `unwrap` on anything that came out of a file, and that
    // ban is what keeps a malformed DEX from killing the process. It has no
    // business in a test: every value unwrapped below was built by the test
    // itself, and a test that cannot reach its own fixture should fail loudly
    // rather than contort itself around a type it has already proven.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn a_descriptor_is_consumed_one_at_a_time() {
        // The whole point: `(IJLjava/lang/String;)` is three parameters, not one.
        assert_eq!(
            descriptor_width("IJLjava/lang/String;)V"),
            1,
            "a primitive is one byte"
        );
        assert_eq!(
            descriptor_width("Ljava/lang/String;)V"),
            18,
            "`Ljava/lang/String;` is 18 bytes"
        );
        assert_eq!(descriptor_width("[I"), 2);
        assert_eq!(
            descriptor_width("[[Ljava/lang/String;"),
            20,
            "two `[` plus the 18-byte class"
        );
        assert_eq!(descriptor_width("I"), 1);
    }

    #[test]
    fn primitives_parse_and_round_trip() {
        for (text, ty) in JType::PRIMITIVES {
            assert_eq!(JType::parse(text), ty);
            assert_eq!(ty.descriptor(), text);
        }
    }

    #[test]
    fn arrays_nest_to_arbitrary_depth() {
        let t = JType::parse("[[[[I");
        assert_eq!(t.element_width(), 4);
        let mut cur = &t;
        let mut depth = 0;
        while let JType::Array(inner) = cur {
            cur = inner;
            depth += 1;
        }
        assert_eq!(depth, 4);
        assert_eq!(*cur, JType::Int);
        assert_eq!(t.descriptor(), "[[[[I");
    }

    #[test]
    fn object_array_component_width_is_a_pointer() {
        // An array *reference* is 4 bytes whatever it holds; the component width
        // is one level down, which is what `fill-array-data` compares against.
        assert_eq!(JType::parse("[Ljava/lang/String;").element_width(), 4);
        assert_eq!(JType::parse("[Z").element_width(), 4);
        assert_eq!(JType::parse("Z").element_width(), 1);
        assert_eq!(
            JType::parse("[C").component().map(|c| c.element_width()),
            Some(2)
        );
        assert_eq!(
            JType::parse("[J").component().map(|c| c.element_width()),
            Some(8)
        );
        assert_eq!(
            JType::parse("[[I").component().map(|c| c.element_width()),
            Some(4)
        );
        // `[[I` is an array of `int[]`: each level is a 4-byte reference, and the
        // `int` at the bottom is 4 bytes too. A `fill-array-data` payload for a
        // `int[]` is therefore 4 bytes per element, not 16 and not 1.
        let two = JType::parse("[[I");
        assert_eq!(
            two.component()
                .and_then(|c| c.component())
                .map(|c| c.element_width()),
            Some(4)
        );
        assert_eq!(two.component().map(|c| c.element_width()), Some(4));
        // `byte[][]` bottoms out at 1, one level further down.
        let bytes = JType::parse("[[B");
        assert_eq!(
            bytes
                .component()
                .and_then(|c| c.component())
                .map(|c| c.element_width()),
            Some(1)
        );
    }

    #[test]
    fn a_garbage_descriptor_degrades_to_a_reference() {
        // Total by construction: no panic, no error, still nameable.
        assert_eq!(JType::parse("garbage"), JType::Ref("garbage".into()));
        assert_eq!(JType::parse(""), JType::Ref("".into()));
        assert_eq!(JType::parse("[V"), JType::Array(Box::new(JType::Void)));
    }

    #[test]
    fn prototypes_split_on_the_first_closing_paren() {
        let (p, r) = JType::parse_prototype("(IJLjava/lang/String;)Ljava/lang/Object;");
        assert_eq!(
            p,
            vec![
                JType::Int,
                JType::Long,
                JType::Ref("Ljava/lang/String;".into())
            ]
        );
        assert_eq!(r, JType::Ref("Ljava/lang/Object;".into()));

        let (p, r) = JType::parse_prototype("()V");
        assert!(p.is_empty());
        assert_eq!(r, JType::Void);

        // Not a prototype at all: the whole thing is the return type.
        let (p, r) = JType::parse_prototype("I");
        assert!(p.is_empty());
        assert_eq!(r, JType::Int);
    }

    #[test]
    fn slot_widths_match_the_register_file_model() {
        assert_eq!(Value::Long(1).slots(), 2);
        assert_eq!(Value::Double(1.0).slots(), 2);
        assert_eq!(Value::Int(1).slots(), 1);
        assert_eq!(JType::Long.slots(), 2);
        assert_eq!(JType::Void.slots(), 0);
    }

    #[test]
    fn widened_integer_reads_are_the_only_lenient_ones() {
        assert_eq!(Value::Int(7).as_long("add-long").unwrap(), 7);
        assert_eq!(Value::Int(7).as_float("int-to-float").unwrap(), 7.0);
        assert!(Value::Double(1.0).as_long("add-long").is_err());
        assert!(Value::Ref(Ref(1)).as_int("add-int").is_err());
        assert!(Value::Null.as_ref("monitor-enter").is_err());
        assert_eq!(Value::Null.ref_or_null("check-cast").unwrap(), None);
    }

    #[test]
    fn a_double_and_a_ref_never_compare_equal() {
        assert_ne!(Value::Double(0.0), Value::Int(0));
        assert_ne!(Value::Ref(Ref(1)), Value::Ref(Ref(2)));
    }
}
