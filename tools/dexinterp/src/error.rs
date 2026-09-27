//! The execution error taxonomy.
//!
//! This module exists because the study needs to tell four outcomes apart, and
//! because the pre-registered protocol forbids reporting a single
//! "runs / does not run" number ([`docs/research-protocol.md`](../../docs/research-protocol.md)
//! §3, and taxonomy §0.3, "a refusal is a result"). Collapsing any two of the
//! four into one "failure" bucket would destroy the measurement, so they are
//! four distinct [`ExecError`] variants with four distinct [`Termination`]
//! values, and there is no path through the interpreter that produces one
//! while claiming to have produced another.
//!
//! | terminal condition | variant | what it means for the study |
//! |---|---|---|
//! | the app crashed | [`ExecError::ExceptionRaised`] | an *app* terminated by an uncaught throwable. A data point about the app, not the substrate. |
//! | the engine declined | [`ExecError::Unsupported`] | the substrate could not express a construct. Attributes to `SUB.FW.*`. |
//! | we ran out of road | [`ExecError::BudgetExhausted`], [`ExecError::StackOverflow`] | the app is *too slow* or *too deep*, not broken. Attributes to `SUB.CPU.TIERING`. |
//! | the engine broke | [`ExecError::Malformed`], [`ExecError::OutOfMemory`] | bytecode that ART would have rejected at install time, or a bug in this crate. Never reported as an app failure. |
//!
//! # Why budget exhaustion must never be a crash
//!
//! `SUB.CPU.TIERING` predicts that interpreted code is 100–1000× slower than
//! ART and that apps therefore fail *looking like flakiness*. If a run that hit
//! the instruction budget were recorded as a crash, the study would report
//! "the app crashed" for an app that is perfectly correct and would have
//! finished given a hundred times the budget — the exact misreading taxonomy
//! §17.2 warns about. [`Budget`](crate::error::Budget) is therefore a separate
//! variant with its own `kind()` string, and [`Termination::BudgetExhausted`]
//! never appears in the same bucket as an exception.
//!
//! Reference: <https://source.android.com/docs/core/runtime/dex-format>

use std::fmt;

use crate::value::Value;

/// Result alias for anything the interpreter can fail at.
pub type ExecResult<T> = Result<T, ExecError>;

/// Where an error was raised: enough to locate it in a disassembly, and
/// stable enough to put in a recording.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Site {
    /// `Lcom/x/Y;.m(II)V` of the method being executed, or `None` before the
    /// first frame is pushed.
    pub method: Option<String>,
    /// Instruction offset in code units within that method.
    pub unit: u32,
    /// The opcode byte being executed, when the error is tied to one.
    pub opcode: Option<u8>,
}

impl fmt::Display for Site {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.method, self.opcode) {
            (Some(m), Some(op)) => write!(f, "{m} at unit {} (opcode 0x{op:02x})", self.unit),
            (Some(m), None) => write!(f, "{m} at unit {}", self.unit),
            (None, Some(op)) => write!(f, "unit {} (opcode 0x{op:02x})", self.unit),
            (None, None) => write!(f, "before the first frame"),
        }
    }
}

/// A construct the engine deliberately does not implement.
///
/// These are the substrate's *known* gaps. Each one maps to an entry in
/// `docs/divergence-taxonomy.md`, and none of them is an accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// A class descriptor that is in neither the DEX nor the builtin table,
    /// and phantom classes are disabled in the configuration. `SUB.FW.CLASS_LOADER`.
    ClassNotFound,
    /// A method with no `code_item` (abstract or native) that no host
    /// implemented. `SUB.NATIVE.JNI_ENTRY`, or a missing shim method.
    MethodNotImplemented,
    /// `invoke-custom` reached with no bootstrap method available: either the
    /// dex declares no `call_site_ids`/`method_handles`, or the class owning
    /// the bootstrap method is not present. `SUB.FW.INVOKEDYNAMIC`.
    BootstrapMethodMissing,
    /// `invoke-custom` whose call site was found and decoded, but whose target
    /// could not be determined — no `LambdaMetafactory` equivalent. This is
    /// the same taxonomy entry as [`Unsupported::BootstrapMethodMissing`], kept
    /// separate so the study can tell "no bootstrap in the file at all" from
    /// "bootstrap present, substrate cannot run it".
    CallSiteUnresolved,
    /// `invoke-polymorphic` / `invoke-polymorphic/range`.
    PolymorphicCall,
    /// A method handle that no host can turn into a callable target.
    MethodHandleUnresolved,
    /// An opcode that is not Dalvik: a foreign DEX variant such as `22cs` or
    /// `3rms`. Not a crash and not an app failure — a file format we do not
    /// implement.
    ForeignFormat,
    /// One of the 32 opcodes the specification marks `(unused)`. Reaching one
    /// means the file is not valid Dalvik.
    UnusedOpcode,
}

impl Unsupported {
    /// Stable discriminant, for the JSON envelope and for grouping results.
    pub fn as_str(self) -> &'static str {
        match self {
            Unsupported::ClassNotFound => "class_not_found",
            Unsupported::MethodNotImplemented => "method_not_implemented",
            Unsupported::BootstrapMethodMissing => "bootstrap_method_missing",
            Unsupported::CallSiteUnresolved => "call_site_unresolved",
            Unsupported::PolymorphicCall => "polymorphic_call",
            Unsupported::MethodHandleUnresolved => "method_handle_unresolved",
            Unsupported::ForeignFormat => "foreign_format",
            Unsupported::UnusedOpcode => "unused_opcode",
        }
    }
}

/// Bytecode that is not well formed, or that violates a type rule the Dalvik
/// verifier would have checked at install time.
///
/// A real APK cannot contain these — ART refuses to install a DEX that fails
/// verification — so in practice these are *our* findings about a file, not the
/// app's. They are kept apart from [`Unsupported`] precisely so that a
/// miscounted here cannot be read as "the substrate lacks a feature".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// A register number outside the frame's `registers_size`.
    BadRegister,
    /// A `code_item` that cannot be decoded: truncated, a payload that runs
    /// past the end, an odd `insns_size`.
    BadCode,
    /// A pool index that does not exist in the file.
    BadPoolIndex,
    /// A branch, switch or payload reference to a unit that is not the start of
    /// an instruction.
    BadBranchTarget,
    /// A register read or written with the wrong type. Without a verifier this
    /// is detected at run time, at the point of use.
    TypeMismatch,
    /// A register read before anything wrote it.
    UninitialisedRegister,
    /// `aput` of a value that is not assignable to the array's component type.
    ArrayStore,
    /// Execution ran off the end of a `code_item` without a `return`. The
    /// verifier rejects this; the engine reports it rather than inventing a
    /// `return-void`.
    MissingReturn,
    /// A `fill-array-data` / `packed-switch` / `sparse-switch` payload whose
    /// shape does not match the instruction that referenced it.
    BadPayload,
    /// The static field initialisers in an `encoded_array` that cannot be
    /// decoded, so the class's statics are unavailable.
    BadStaticValues,
}

impl Malformed {
    /// Stable discriminant.
    pub fn as_str(self) -> &'static str {
        match self {
            Malformed::BadRegister => "bad_register",
            Malformed::BadCode => "bad_code",
            Malformed::BadPoolIndex => "bad_pool_index",
            Malformed::BadBranchTarget => "bad_branch_target",
            Malformed::TypeMismatch => "type_mismatch",
            Malformed::UninitialisedRegister => "uninitialised_register",
            Malformed::ArrayStore => "array_store",
            Malformed::MissingReturn => "missing_return",
            Malformed::BadPayload => "bad_payload",
            Malformed::BadStaticValues => "bad_static_values",
        }
    }
}

/// Which configured limit was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Budget {
    /// Instructions executed in one top-level `invoke_method` call.
    Instructions,
    /// Objects allocated.
    Objects,
    /// Bytes allocated.
    Bytes,
}

impl Budget {
    /// Stable discriminant.
    pub fn as_str(self) -> &'static str {
        match self {
            Budget::Instructions => "instructions",
            Budget::Objects => "objects",
            Budget::Bytes => "bytes",
        }
    }
}

/// Everything that can stop execution.
#[derive(Clone, Debug, PartialEq)]
pub enum ExecError {
    /// An exception reached the top of the frame stack with no handler.
    ///
    /// On a device this is a process death: `am_crash`. The value is the
    /// throwable object, so the study can record its class and message.
    ExceptionRaised {
        /// The throwable, a real instance of a real class in the heap.
        object: Value,
        /// Its class descriptor, e.g. `Ljava/lang/NullPointerException;`.
        class: String,
        /// `Throwable.getMessage()`, when the interpreter can supply one.
        message: Option<String>,
        /// Where it was thrown or raised.
        site: Site,
    },
    /// The engine cannot execute this construct. See [`Unsupported`].
    Unsupported {
        /// Which gap.
        kind: Unsupported,
        /// Human-readable specifics: the descriptor, the call site chain, the
        /// format name. This is the field the study quotes.
        detail: String,
        /// Where.
        site: Site,
    },
    /// Bytecode that is not well formed. See [`Malformed`].
    Malformed {
        /// Which rule was broken.
        kind: Malformed,
        /// Human-readable specifics.
        detail: String,
        /// Where.
        site: Site,
    },
    /// The call-depth limit was reached: unbounded recursion, or bytecode that
    /// is simply too deep for a browser tab.
    ///
    /// Distinct from [`ExecError::BudgetExhausted`] because the remedy is
    /// different — a deeper budget does not help, a bigger stack might — and
    /// because "stack overflow" is a well-known Android symptom
    /// (`SUB.MEM.LARGE_HEAP`) while "budget exhausted" is `SUB.CPU.TIERING`.
    StackOverflow {
        /// The configured `max_call_depth`.
        limit: u32,
        /// Where the deepest call was made.
        site: Site,
    },
    /// A configured limit was reached during normal execution.
    ///
    /// **This is not a crash.** It means the app was still making progress
    /// when we stopped counting. Never report it as a failure of the app.
    BudgetExhausted {
        /// Which limit.
        kind: Budget,
        /// The limit's value.
        limit: u64,
        /// Where the limit was hit.
        site: Site,
    },
    /// The heap limit was reached while allocating.
    ///
    /// Also not a crash, and also not the same thing as
    /// [`ExecError::BudgetExhausted`]: a real device would raise
    /// `OutOfMemoryError` here, which this engine would then have to catch like
    /// any other throwable, so the limit is reported as a limit rather than
    /// faked as an exception.
    OutOfMemory {
        /// Which limit: object count or bytes.
        kind: Budget,
        /// The limit's value.
        limit: u64,
        /// What the allocation asked for.
        requested: u64,
        /// Where.
        site: Site,
    },
}

impl ExecError {
    /// A stable, machine-readable discriminant for the whole taxonomy.
    ///
    /// These six strings are the wire format. A recording that carries
    /// `{"kind": "budget_exhausted", ...}` means one thing for ever, even if
    /// the enum is later split or renamed.
    pub fn kind(&self) -> &'static str {
        match self {
            ExecError::ExceptionRaised { .. } => "exception_raised",
            ExecError::Unsupported { .. } => "unsupported",
            ExecError::Malformed { .. } => "malformed",
            ExecError::StackOverflow { .. } => "stack_overflow",
            ExecError::BudgetExhausted { .. } => "budget_exhausted",
            ExecError::OutOfMemory { .. } => "out_of_memory",
        }
    }

    /// Which of the study's terminal conditions this is.
    ///
    /// The four the protocol needs to keep apart map one-to-one onto
    /// [`Termination`] variants, with the two engine-level faults folded
    /// together as [`Termination::EngineFault`].
    pub fn termination(&self) -> Termination {
        match self {
            ExecError::ExceptionRaised { .. } => Termination::ExceptionRaised,
            ExecError::Unsupported { .. } => Termination::Unsupported,
            ExecError::StackOverflow { .. } | ExecError::BudgetExhausted { .. } => {
                Termination::BudgetExhausted
            }
            ExecError::Malformed { .. } | ExecError::OutOfMemory { .. } => Termination::EngineFault,
        }
    }

    /// The exception object, if this is [`ExecError::ExceptionRaised`].
    pub fn thrown(&self) -> Option<Value> {
        match self {
            ExecError::ExceptionRaised { object, .. } => Some(*object),
            _ => None,
        }
    }
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecError::ExceptionRaised { class, message, site, .. } => match message {
                Some(m) => write!(f, "uncaught {class}: {m} ({site})"),
                None => write!(f, "uncaught {class} ({site})"),
            },
            ExecError::Unsupported { kind, detail, site } => {
                write!(f, "unsupported ({}): {detail} [{site}]", kind.as_str())
            }
            ExecError::Malformed { kind, detail, site } => {
                write!(f, "malformed ({}): {detail} [{site}]", kind.as_str())
            }
            ExecError::StackOverflow { limit, site } => {
                write!(f, "call depth limit {limit} reached [{site}]")
            }
            ExecError::BudgetExhausted { kind, limit, site } => {
                write!(f, "{} budget of {limit} exhausted [{site}]", kind.as_str())
            }
            ExecError::OutOfMemory { kind, limit, requested, site } => write!(
                f,
                "{} allocation of {requested} bytes refused, limit {limit} [{site}]",
                kind.as_str()
            ),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<dexcore::Error> for ExecError {
    /// A parse failure in the *file* becomes a `Malformed`, never an
    /// `Unsupported`: `dexcore` could not read it, which is a statement about the
    /// bytes rather than about a capability the substrate lacks.
    fn from(e: dexcore::Error) -> ExecError {
        ExecError::Malformed {
            kind: Malformed::BadCode,
            detail: format!("dex file: {e}"),
            site: Site::default(),
        }
    }
}

/// The terminal condition of a top-level `invoke_method` call.
///
/// This is the unit the study counts. Note what is *absent*: there is no
/// "failed" bucket, and no variant that means "the app did not work" in
/// general. Each value is a different claim with a different cause.
#[derive(Clone, Debug, PartialEq)]
pub enum Termination {
    /// The method returned normally, with this value.
    Returned(Value),
    /// An uncaught throwable: the app crashed. A statement about the app.
    ExceptionRaised,
    /// The engine declined to execute a construct. A statement about the
    /// substrate, attributable to a `SUB.FW.*` entry.
    Unsupported,
    /// A limit was reached: still making progress, or too deep. A statement
    /// about speed or stack depth, not about correctness.
    BudgetExhausted,
    /// The bytecode was not executable at all. A statement about the *file*,
    /// or a bug in this crate — never about the app.
    EngineFault,
}

impl Termination {
    /// Stable discriminant, and the field the study groups by.
    pub fn as_str(&self) -> &'static str {
        match self {
            Termination::Returned(_) => "returned",
            Termination::ExceptionRaised => "exception_raised",
            Termination::Unsupported => "unsupported",
            Termination::BudgetExhausted => "budget_exhausted",
            Termination::EngineFault => "engine_fault",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site() -> Site {
        Site { method: Some("La;.m()V".into()), unit: 3, opcode: Some(0x0f) }
    }

    #[test]
    fn the_four_terminal_conditions_are_four_different_kinds() {
        let errs = [
            ExecError::ExceptionRaised {
                object: Value::Null,
                class: "Ljava/lang/Error;".into(),
                message: None,
                site: site(),
            },
            ExecError::Unsupported {
                kind: Unsupported::BootstrapMethodMissing,
                detail: "x".into(),
                site: site(),
            },
            ExecError::BudgetExhausted { kind: Budget::Instructions, limit: 1, site: site() },
            ExecError::Malformed {
                kind: Malformed::TypeMismatch,
                detail: "y".into(),
                site: site(),
            },
        ];
        let kinds: Vec<&str> = errs.iter().map(ExecError::kind).collect();
        let mut sorted = kinds.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 4, "kinds collided: {kinds:?}");
        let terms: Vec<&str> = errs.iter().map(|e| e.termination().as_str()).collect();
        assert_eq!(terms, vec!["exception_raised", "unsupported", "budget_exhausted", "engine_fault"]);
    }

    #[test]
    fn stack_overflow_and_instruction_budget_share_a_category_but_not_a_kind() {
        let so = ExecError::StackOverflow { limit: 3, site: site() };
        let be = ExecError::BudgetExhausted { kind: Budget::Instructions, limit: 3, site: site() };
        assert_ne!(so.kind(), be.kind());
        assert_eq!(so.termination(), be.termination());
        // ...but a stack overflow is not reported as a heap failure.
        let oom = ExecError::OutOfMemory {
            kind: Budget::Bytes,
            limit: 1,
            requested: 2,
            site: site(),
        };
        assert_eq!(oom.termination(), Termination::EngineFault);
    }

    #[test]
    fn discriminants_are_snake_case_and_stable() {
        let all = [
            Unsupported::ClassNotFound,
            Unsupported::MethodNotImplemented,
            Unsupported::BootstrapMethodMissing,
            Unsupported::CallSiteUnresolved,
            Unsupported::PolymorphicCall,
            Unsupported::MethodHandleUnresolved,
            Unsupported::ForeignFormat,
            Unsupported::UnusedOpcode,
        ];
        for u in all {
            assert!(!u.as_str().is_empty());
            assert_eq!(u.as_str(), u.as_str().to_lowercase());
        }
    }
}
