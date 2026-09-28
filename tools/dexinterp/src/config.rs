//! Limits, and the accounting the study reads.
//!
//! Two things live here, and they are kept apart on purpose.
//!
//! [`Config`] is the *policy*: what the study decided in advance that the
//! engine would refuse to do. It is set once, before anything executes.
//!
//! [`Stats`] is the *measurement*: what actually happened. It is a value, not
//! a log line, so a run can be compared with another run field by field
//! instead of by reading two text logs side by side.
//!
//! # The budget policy, and why the default is finite
//!
//! The brief for this project is that slowness is acceptable and a crash is
//! not, but "acceptable" is not "unbounded". An app with a `while (true)` in
//! `onCreate` would otherwise hang a browser tab forever, and a hung tab
//! records nothing: it is neither a success nor a failure, which is the worst
//! of both. So [`Config::instruction_budget`] is `Some(_)` by default, and
//! hitting it produces [`Termination::BudgetExhausted`](crate::error::Termination::BudgetExhausted)
//! — a *recorded* outcome, not a lost one.
//!
//! The default of 25 million instructions is roughly 5–25 seconds of
//! interpreted work in a browser tab, which is comfortably more than
//! `onCreate` needs on a real device and comfortably less than a user will
//! wait. It is a pre-registered constant, not a tuned one: it was fixed before
//! any APK was run and is reported in every result so that a reader can
//! normalise for it.

use crate::value::Value;

/// The default instruction budget for one top-level call.
pub const DEFAULT_INSTRUCTION_BUDGET: u64 = 25_000_000;

/// The default call-depth limit.
pub const DEFAULT_MAX_CALL_DEPTH: u32 = 512;

/// Limits the engine refuses to exceed. Set once, before execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Maximum instructions in a single top-level [`Interpreter::invoke_method`]
    /// call, or `None` for unbounded.
    ///
    /// Unbounded is a deliberate choice available to a caller who has a
    /// different termination mechanism — a worker with a watchdog, say. It is
    /// not the default, because the default has to be safe for a browser tab.
    pub instruction_budget: Option<u64>,
    /// Maximum frames on the call stack. Exceeding it is
    /// [`StackOverflow`](crate::error::ExecError::StackOverflow), which is a
    /// different terminal condition from the instruction budget.
    pub max_call_depth: u32,
    /// Maximum live objects. `None` for unbounded.
    pub max_objects: Option<u64>,
    /// Maximum bytes of object storage. `None` for unbounded.
    pub max_bytes: Option<u64>,
    /// Whether a class descriptor that is in neither the DEX nor the builtin
    /// table is fabricated as an opaque placeholder.
    ///
    /// `true` by default, because it is what lets `check-cast` and
    /// `instance-of` work against `android.*` types before the framework shim
    /// exists — and the set of fabricated classes is recorded in
    /// [`Stats::phantom_classes`], so the cost of that decision is visible
    /// rather than hidden. An app that needs four hundred phantom classes is
    /// an app this study should be able to *see* is not going to run, and
    /// turning the setting off measures how many apps fail at class resolution
    /// instead of getting a little further.
    pub phantom_classes: bool,
    /// Whether to keep a bounded sample of framework calls in
    /// [`Stats::shim_log`]. Counting is always on; only the sample is optional,
    /// because a long run would otherwise accumulate an unbounded log.
    pub record_shim_log: bool,
    /// How many entries [`Stats::shim_log`] may hold.
    pub max_shim_log: usize,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            instruction_budget: Some(DEFAULT_INSTRUCTION_BUDGET),
            max_call_depth: DEFAULT_MAX_CALL_DEPTH,
            max_objects: None,
            max_bytes: None,
            phantom_classes: true,
            record_shim_log: true,
            max_shim_log: 4096,
        }
    }
}

/// One framework call, as the engine saw it.
///
/// This is the raw material for `oracle/RECORDING.md`'s side-effect lists. The
/// engine records *every* call into a class it does not implement, whether the
/// host answered it or not, because "the substrate refused this" and "the
/// substrate guessed at this" are different outcomes and both are results.
#[derive(Clone, Debug, PartialEq)]
pub struct ShimRecord {
    /// `Ljava/lang/String;` — the class named by the `method_ids` entry, which
    /// is not necessarily the receiver's dynamic class.
    pub class: String,
    /// Method name.
    pub name: String,
    /// Prototype descriptor, e.g. `(Ljava/lang/String;)Ljava/lang/String;`.
    pub signature: String,
    /// `Virtual`, `Direct`, `Static`, `Interface` or `Super`.
    pub kind: &'static str,
    /// The arguments, in order.
    pub args: Vec<Value>,
    /// Whether a [`Host`](crate::host::Host) implemented it. `false` means the
    /// engine substituted the return type's zero value and carried on.
    pub implemented: bool,
}

/// What one run cost. A value, not a log line.
#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    /// Instructions executed since the interpreter was created, across all
    /// top-level calls.
    pub instructions_executed: u64,
    /// Times the instruction budget stopped a run.
    pub budget_exhausted: bool,
    /// The instruction budget in force, for the record.
    pub instruction_budget: Option<u64>,

    /// Calls entered, including calls the host handled.
    pub method_invocations: u64,
    /// Deepest frame stack reached.
    pub max_call_depth: u32,

    /// Objects and arrays allocated.
    pub allocations: u64,
    /// Bytes of object and array storage allocated. `Object` has a fixed
    /// overhead plus its fields; an array is its component type plus its
    /// elements.
    pub bytes_allocated: u64,
    /// Objects live at the end of the run. There is no garbage collector, so
    /// this is the same as [`Stats::allocations`] unless an allocation failed.
    pub live_objects: u64,
    /// Storage live at the end of the run.
    pub live_bytes: u64,

    /// Throwables raised by the VM itself (`new-instance` on an unresolvable
    /// class, a null `check-cast` failure, a division by zero, ...).
    pub vm_exceptions: u64,
    /// Throwables thrown by `throw` in the app's own code.
    pub app_exceptions: u64,
    /// Throwables that a handler in the app's code caught.
    pub exceptions_caught: u64,
    /// Throwables that reached the top of the stack.
    pub exceptions_uncaught: u64,

    /// Calls into classes the engine has no bytecode for, whether the host
    /// answered them or not.
    pub framework_calls: u64,
    /// The subset the host did not answer.
    pub framework_calls_unimplemented: u64,
    /// Field accesses against classes with no bytecode, likewise.
    pub framework_field_accesses: u64,
    /// A bounded sample of framework calls, oldest first.
    pub shim_log: Vec<ShimRecord>,

    /// Classes fabricated because the file did not contain them and no shim
    /// declared them. Sorted and deduplicated.
    pub phantom_classes: Vec<String>,

    /// How many times each opcode was dispatched, indexed by opcode byte.
    /// The zero entries are the 32 `(unused)` opcodes.
    pub opcode_counts: [u32; 256],
}

impl Default for Stats {
    fn default() -> Stats {
        Stats {
            instructions_executed: 0,
            budget_exhausted: false,
            instruction_budget: None,
            method_invocations: 0,
            max_call_depth: 0,
            allocations: 0,
            bytes_allocated: 0,
            live_objects: 0,
            live_bytes: 0,
            vm_exceptions: 0,
            app_exceptions: 0,
            exceptions_caught: 0,
            exceptions_uncaught: 0,
            framework_calls: 0,
            framework_calls_unimplemented: 0,
            framework_field_accesses: 0,
            shim_log: Vec::new(),
            phantom_classes: Vec::new(),
            opcode_counts: [0; 256],
        }
    }
}

impl Stats {
    /// How many of the 256 opcode slots have been dispatched at least once.
    pub fn distinct_opcodes(&self) -> u32 {
        self.opcode_counts.iter().filter(|&&n| n > 0).count() as u32
    }

    /// Whether opcode `op` was ever dispatched.
    pub fn executed(&self, op: u8) -> bool {
        self.opcode_counts.get(op as usize).copied().unwrap_or(0) > 0
    }

    /// `true` when the shim log is full, so a reader knows it is a sample and
    /// not a complete record.
    pub fn shim_log_truncated(&self) -> bool {
        self.framework_calls > self.shim_log.len() as u64
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
    fn the_default_budget_is_finite_and_recorded() {
        let c = Config::default();
        assert_eq!(c.instruction_budget, Some(DEFAULT_INSTRUCTION_BUDGET));
        assert!(c.max_call_depth > 0);
        assert!(
            c.phantom_classes,
            "phantom classes are on by default, and recorded"
        );
    }

    #[test]
    fn opcode_histogram_is_totally_addressable() {
        let mut s = Stats::default();
        assert!(!s.executed(0xff));
        s.opcode_counts[0xff] = 3;
        assert!(s.executed(0xff));
        assert_eq!(s.distinct_opcodes(), 1);
        s.opcode_counts[0x00] = 1;
        assert_eq!(s.distinct_opcodes(), 2);
    }

    #[test]
    fn truncation_is_reported_rather_than_silent() {
        let mut s = Stats::default();
        s.shim_log.push(ShimRecord {
            class: "Ljava/lang/Object;".into(),
            name: "hashCode".into(),
            signature: "()I".into(),
            kind: "Virtual",
            args: vec![],
            implemented: false,
        });
        s.framework_calls = 9;
        assert!(s.shim_log_truncated());
    }
}
