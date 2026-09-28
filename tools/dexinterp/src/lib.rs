//! # dexinterp — a Dalvik interpreter
//!
//! `dexcore` reads, decodes and writes DEX. This crate **executes** it: it runs
//! decoded Dalvik bytecode to completion, with a typed register file, a real
//! heap, virtual dispatch, a real exception hierarchy, and a boundary at which
//! everything the engine does *not* implement is handed to a framework shim and
//! recorded.
//!
//! ## Why this exists
//!
//! andro-substrate executes untrusted Android APK bytecode in a browser with no
//! kernel, no native code and no egress, and its job is to run an app's
//! `Application` + `Activity` lifecycle to completion and **record every side
//! effect**. 44.76% of the F-Droid corpus in
//! [`corpus/report.md`](../../corpus/report.md) contains no native code; that is
//! the ceiling on the project's reach, and it says nothing about whether the
//! remaining bytecode runs. The interpreter is the instrument that turns "it did
//! not work" into a located cause.
//!
//! ## The three properties that shape the design
//!
//! **Four terminal conditions, never conflated.** A crash, a budget exhaustion,
//! an unsupported construct and a malformed bytecode are four different claims
//! with four different causes, and the pre-registered protocol forbids reporting
//! a single "runs / does not run" number. [`ExecError`] has a variant for each,
//! each with a stable `kind()` string, and [`Termination`] is the axis the study
//! counts on. A run that hit the instruction budget was an app that was *still
//! making progress*; recording it as a crash would report `SUB.CPU.TIERING` as
//! `SUB.FW.CLASS_LOADER`.
//!
//! **No panics, no unbounded recursion.** The frame stack is a `Vec` and
//! exception unwinding is a `pop` loop, so there is no host stack to overflow
//! and the call-depth limit is a typed error at a chosen depth rather than a
//! `SIGSEGV` in a browser tab. Every register, array index and pool index is
//! bounds-checked, and the two places a *declared* count could drive an
//! allocation are bounded by the bytes that remain.
//!
//! **A refusal is a result.** "Fails at `invokedynamic`" is a finding, so the
//! `invoke-custom` path decodes the whole resolution chain — call site, method
//! handle, bootstrap method, its defining class, whether that class is in the
//! file — and reports which link is missing. `SUB.FW.INVOKEDYNAMIC` is a
//! pre-registered hypothesis and this engine is the thing that tests it.
//!
//! ## What is deliberately not here
//!
//! * **No verifier.** Register typing is checked at run time, at the point of
//!   use, and reported as [`Malformed::TypeMismatch`] naming the instruction.
//!   A verifier is a separate whole-program analysis whose findings are about
//!   the *file*; this crate's job is execution.
//! * **No garbage collector.** Memory grows until the run ends or a limit is
//!   hit, so [`Stats::bytes_allocated`] does not depend on when a collection
//!   happened — which is what makes it comparable between runs.
//! * **No threads.** `monitor-enter`/`monitor-exit` are a per-object reentrant
//!   lock, which gives mutual exclusion vacuously and gives happens-before
//!   nothing. See [`heap::Monitor`] for what that means for `SUB.CPU.ATOMIC`.
//! * **No framework.** `android.*` and `java.*` behaviour is the
//!   [`Host`](host::Host) trait's job. This crate declares the class *hierarchy*
//!   it needs for control flow and nothing else.
//!
//! ## Example
//!
//! ```no_run
//! # fn main() -> dexinterp::ExecResult<()> {
//! # let bytes: Vec<u8> = std::fs::read("classes.dex").unwrap();
//! # let dex = dexcore::DexReader::open(&bytes)?;
//! use dexinterp::{Config, Value};
//!
//! let mut vm = dexinterp::new_interpreter(dex, Config::default())?;
//! vm.set_host(Box::new(MyShim::new()));
//!
//! // Build an Activity and run its lifecycle callback.
//! let activity = vm.allocate("Lcom/example/App;MainActivity;")?;
//! match vm.invoke_method("Lcom/example/App;MainActivity;", "onCreate", "(Landroid/os/Bundle;)V", &[activity]) {
//!     Ok(v) => println!("onCreate returned {v:?} after {} instructions", vm.stats().instructions_executed),
//!     Err(e) => println!("onCreate: {} [{}]", e, e.termination().as_str()),
//! }
//! # Ok(())
//! # }
//! # struct MyShim;
//! # impl MyShim { fn new() -> Self { MyShim } }
//! # impl dexinterp::host::Host for MyShim {}
//! ```
//!
//! Reference: <https://source.android.com/docs/core/runtime/dalvik-bytecode>

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

pub mod classes;
pub mod config;
pub mod error;
pub mod exec;
pub mod heap;
pub mod host;
pub mod ops;
pub mod program;
pub mod value;

pub use config::{Config, ShimRecord, Stats, DEFAULT_INSTRUCTION_BUDGET, DEFAULT_MAX_CALL_DEPTH};
pub use error::{Budget, ExecError, ExecResult, Malformed, Site, Termination, Unsupported};
pub use exec::{new_interpreter, new_layered_interpreter, Interpreter};
pub use heap::{ClassId, Heap, Monitor, Object, ObjectKind};
pub use host::{
    with_host, Call, CallSite, FieldAccess, Host, HostOutcome, HostValue, InvokeKind, NoHost,
    ResolvedCallSite, ThrowSpec,
};
pub use program::{
    host_classes_from_dex, ClassMeta, ClassSource, DecodedCode, HostClass, Insn, MethodDecl,
    Program, VTableEntry,
};
pub use value::{JType, Ref, Value};
