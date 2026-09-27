//! The interpreter loop.
//!
//! One `loop`, one frame stack, and a `match` on the decoded instruction's
//! *format* with an inner match on the opcode byte. Two properties of that shape
//! are worth stating, because they are why it is written this way.
//!
//! **No Rust recursion.** Java recursion is a `Vec::push` here, and Java
//! exception unwinding is a `Vec::pop` loop. That is what makes the stack-depth
//! limit a *number* rather than a hazard: there is no host stack to overflow, so
//! `StackOverflow` is a typed error at a chosen depth instead of a `SIGSEGV` in
//! a browser tab. It is also why the negative suite can assert on unbounded
//! recursion without risking the test process.
//!
//! **Format first, opcode second.** `dexcore::Instruction` is an enum over
//! *formats*, because a format such as `12x` backs thirty-odd operations and a
//! 256-variant enum keyed on mnemonics would carry no information. But `35c`
//! covers `invoke-virtual` through `invoke-interface` *and* `filled-new-array`,
//! so the opcode byte is carried alongside the operands and is what the inner
//! match dispatches on. Any opcode that reaches the `foreign` fallback produces
//! [`Unsupported::ForeignFormat`], a discriminant the coverage test never
//! accepts as success — so "this opcode executed" and "this opcode was skipped"
//! can never be confused.
//!
//! # The program counter
//!
//! `pc` is advanced *past* the current instruction before `execute` runs, and
//! every relative branch is computed from [`Site::unit`] rather than from `pc`.
//! That distinction is not cosmetic: `goto +0` is a one-instruction infinite
//! loop if the base is off by one, and a `fill-array-data` payload sits at
//! `instruction_address + offset`, not at `pc + offset`.
//!
//! # A throwable set by a field access
//!
//! `iget`/`iput`/`sget`/`sput` can be turned into a throwable by the shim (a
//! `Bundle.getString` that finds nothing, a `getWindow()` that returns null).
//! Those arms are shared with instructions that return a `Flow`, so the
//! throwable is stashed in `pending_throw` and collected by the dispatch loop at
//! the end of the instruction. It is checked after *every* instruction, so it
//! cannot be forgotten by a new opcode.

use std::collections::HashMap;
use std::rc::Rc;

use dexcore::insn::{FillArrayData, Instruction, Payload};
use dexcore::reader::DexReader;

use crate::config::{Config, ShimRecord, Stats};
use crate::error::{Budget, ExecError, ExecResult, Malformed, Site, Unsupported};
use crate::heap::{ClassId, Heap, ObjectKind};
use crate::host::{Call, CallSite, FieldAccess, Host, HostOutcome, HostValue, InvokeKind, ThrowSpec};
use crate::ops::{self, NumErr};
use crate::program::{CallSiteMeta, ClassSource, DecodedCode, EncodedValue, MethodDecl, Program, VTableEntry};
use crate::value::{JType, Ref, Value};

/// One activation record.
#[derive(Debug)]
struct Frame {
    /// Rendered `Lcom/x/Y;.m(II)V`, for [`Site`].
    signature_text: String,
    /// The register file, exactly `registers_size` words.
    registers: Vec<Value>,
    /// The next code unit, already past the current instruction.
    pc: usize,
    /// The result of the most recent call, for `move-result*` and
    /// `move-exception`.
    result: Option<Value>,
    /// The decoded body.
    code: Rc<DecodedCode>,
    /// Monitors this frame holds, innermost last.
    ///
    /// A `synchronized` method is `monitor-enter` in the prologue, so a frame
    /// that returns while holding one has to release it or every later
    /// `monitor-exit` in the run fails.
    held: Vec<Ref>,
}

/// What an instruction did to control flow.
enum Flow {
    /// Continue at `pc`, which is already past the current instruction.
    Next,
    /// A value was returned; unwind one frame.
    Return(Value),
    /// An exception is in flight; unwind until a handler is found.
    Thrown(Value),
    /// A frame was pushed; the result arrives in the caller's `result` slot.
    Call,
}

/// Why an array operation could not proceed. Each is a *throwable* on a device,
/// not a fault, which is why they become exceptions rather than errors.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ArrayFault {
    /// The array reference was `null`.
    NullArray,
    /// The index was outside `[0, length)`.
    Index(i32, i32),
    /// `aput` of a value the component type cannot hold.
    Store,
    /// The reference is not an array.
    NotAnArray,
}

/// The outcome of one array access.
#[derive(Clone, Debug, PartialEq)]
enum ArrayOp {
    /// Succeeded. `aget` carries the element; `aput` carries `null`.
    Done(Value),
    /// Became an exception.
    Fault(ArrayFault),
}

/// A Dalvik interpreter for one `classes.dex`.
///
/// Build with [`new_interpreter`](crate::new_interpreter) and drive it with
/// [`Interpreter::invoke_method`]. The heap, the class table and the instruction
/// budget all live in the value, so one `Interpreter` can run a whole lifecycle
/// in sequence and report one [`Stats`] at the end.
pub struct Interpreter<'a> {
    dex: DexReader<'a>,
    program: Program,
    heap: Heap,
    config: Config,
    stats: Stats,
    frames: Vec<Frame>,
    host: Box<dyn Host>,
    /// The result of the last `invoke_method`, so a caller can branch once
    /// rather than matching at every call site.
    last: Option<ExecResult<Value>>,
    /// Instructions left in the current top-level call's budget.
    remaining: u64,
    /// `(class, key)` -> heap object, so a shim's `Opaque` values are stable.
    opaque: HashMap<(String, String), Ref>,
    /// Live static field values, keyed `(declaring class, field_ids index)`.
    ///
    /// Keyed by the *declaring* class because that is what a `field_ids` entry
    /// names, which is what makes field shadowing correct for free: a subclass
    /// writing an inherited static writes the superclass's storage.
    statics: HashMap<(ClassId, u32), Value>,
    /// A throwable a shim raised inside a field access, collected by the
    /// dispatch loop at the end of the instruction.
    pending_throw: Option<Value>,
}

impl std::fmt::Debug for Interpreter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interpreter")
            .field("classes", &self.program.classes.len())
            .field("methods", &self.program.methods.len())
            .field("frames", &self.frames.len())
            .field("heap_objects", &self.heap.len())
            .field("stats", &self.stats)
            .finish()
    }
}

/// Build an interpreter for `dex`.
///
/// The [`Program`] is built eagerly — class table, field layouts, vtables,
/// static initialisers — so a file whose hierarchy cannot be resolved is a
/// `Malformed` error at construction rather than a surprise in the middle of
/// `onCreate`. Method bodies are decoded lazily, on first call, because a real
/// APK declares tens of thousands of methods and running four of them should not
/// decode all of them.
pub fn new_interpreter<'a>(dex: DexReader<'a>, config: Config) -> ExecResult<Interpreter<'a>> {
    let program = Program::build(&dex)?;
    let mut stats = Stats::default();
    stats.instruction_budget = config.instruction_budget;
    Ok(Interpreter {
        dex,
        program,
        heap: Heap::new(),
        config,
        stats,
        frames: Vec::new(),
        host: Box::new(crate::host::NoHost),
        last: None,
        remaining: 0,
        opaque: HashMap::new(),
        statics: HashMap::new(),
        pending_throw: None,
    })
}

impl<'a> Interpreter<'a> {
    // ================================================================ public

    /// Install a framework shim, replacing any previous one.
    pub fn set_host(&mut self, host: Box<dyn Host>) {
        self.host = host;
    }

    /// Take the shim back out, so a caller can inspect or re-install it.
    pub fn take_host(&mut self) -> Box<dyn Host> {
        std::mem::replace(&mut self.host, Box::new(crate::host::NoHost))
    }

    /// The resolved program: classes, vtables, pools.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// The heap, for a caller that wants to inspect what an app built.
    pub fn heap(&self) -> &Heap {
        &self.heap
    }

    /// Mutable access to the heap, for building arguments before a call.
    pub fn heap_mut(&mut self) -> &mut Heap {
        &mut self.heap
    }

    /// What one run cost. A struct, not a log line.
    pub fn stats(&self) -> Stats {
        self.stats.clone()
    }

    /// Borrow the counters without copying.
    pub fn stats_ref(&self) -> &Stats {
        &self.stats
    }

    /// The terminal condition of the most recent call, or `None` before the
    /// first one.
    pub fn last_termination(&self) -> Option<crate::error::Termination> {
        self.last.as_ref().map(|r| match r {
            Ok(v) => crate::error::Termination::Returned(*v),
            Err(e) => e.termination(),
        })
    }

    /// The value the most recent call returned, if it returned one.
    pub fn last_value(&self) -> Option<Value> {
        self.last.as_ref().and_then(|r| r.as_ref().ok().copied())
    }

    /// Allocate an instance of `class` without running a constructor.
    ///
    /// A runtime has to build an `Activity` before it can call
    /// `Activity.onCreate` on it, and the constructor is app code that would
    /// need the shim. This is how the study's harness does it.
    pub fn allocate(&mut self, class: &str) -> ExecResult<Value> {
        self.new_instance(class)
    }

    /// Allocate an array whose elements are `component`.
    pub fn allocate_array(&mut self, component: &str, len: usize) -> ExecResult<Value> {
        self.new_array(component, len)
    }

    /// Make a `Ljava/lang/String;` object, for building arguments.
    pub fn new_string(&mut self, text: impl Into<String>) -> ExecResult<Value> {
        self.new_string_value(text.into())
    }

    /// The characters of a `Ljava/lang/String;` value, if it is one.
    pub fn string_value(&self, v: Value) -> Option<&str> {
        self.heap.string_of(v)
    }

    /// The class descriptor of a reference's dynamic class.
    pub fn class_of(&self, v: Value) -> Option<String> {
        self.class_id_of_object(v).map(|c| self.class_name(c))
    }

    /// Whether `v` is an instance of `descriptor`, interfaces included.
    pub fn is_instance_of(&mut self, v: Value, descriptor: &str) -> bool {
        let target = match self.class_id_for_test(descriptor).or_else(|| self.class_id_for(descriptor)) {
            Some(t) => t,
            None => return false,
        };
        match self.class_id_of_object(v) {
            Some(c) => self.program.is_a(c, target),
            None => false,
        }
    }

    /// Write an instance field by descriptor, for a harness setting up an object
    /// before handing it to the app's own code.
    pub fn put_field(
        &mut self,
        target: Value,
        class: &str,
        name: &str,
        ty: &str,
        value: Value,
    ) -> ExecResult<()> {
        let offset = self.instance_offset_for(class, name, ty)?;
        self.write_instance_field(target, offset, &JType::parse(ty), value)
    }

    /// Read an instance field by descriptor.
    pub fn get_field(
        &mut self,
        target: Value,
        class: &str,
        name: &str,
        ty: &str,
    ) -> ExecResult<Value> {
        let offset = self.instance_offset_for(class, name, ty)?;
        self.read_instance_field(target, offset, &JType::parse(ty), &Site::default())
    }

    /// Read a static field by descriptor.
    pub fn get_static(&mut self, class: &str, name: &str, ty: &str) -> ExecResult<Value> {
        let idx = self.field_index(class, name, ty)?;
        self.read_static(self.class_id_known(class), idx, &JType::parse(ty))
    }

    /// Write a static field by descriptor.
    pub fn put_static(
        &mut self,
        class: &str,
        name: &str,
        ty: &str,
        value: Value,
    ) -> ExecResult<()> {
        let idx = self.field_index(class, name, ty)?;
        self.write_static(self.class_id_known(class), idx, value, &JType::parse(ty))
    }

    // ================================================================= entry

    /// Call `class`.`name``signature` with `args`.
    ///
    /// `signature` is the prototype descriptor, `(II)V`. For an instance method
    /// the first element of `args` is the receiver. Returns the method's return
    /// value, or an [`ExecError`] whose [`termination`](ExecError::termination) is
    /// one of the conditions the study keeps apart.
    ///
    /// The instruction budget is **per call**: it is reset here, so
    /// [`Stats::instructions_executed`] accumulates across calls while the limit
    /// applies to each independently. That is the useful shape for a lifecycle
    /// run, where `onCreate` and `onResume` should each get a full budget rather
    /// than share one and have the second report as "budget exhausted" when it
    /// is really the first that was slow.
    pub fn invoke_method(
        &mut self,
        class: &str,
        name: &str,
        signature: &str,
        args: &[Value],
    ) -> ExecResult<Value> {
        self.frames.clear();
        self.pending_throw = None;
        self.remaining = self.config.instruction_budget.unwrap_or(u64::MAX);
        let outcome = self.invoke_top_level(class, name, signature, args);
        self.stats.live_objects = self.heap.len() as u64;
        self.stats.live_bytes = self.heap.bytes();
        self.last = Some(outcome.clone());
        outcome
    }

    fn invoke_top_level(
        &mut self,
        class: &str,
        name: &str,
        signature: &str,
        args: &[Value],
    ) -> ExecResult<Value> {
        let decl = self
            .class_id_known(class)
            .and_then(|c| self.program.find_method(c, name, signature).cloned());
        if let Some(d) = decl {
            if d.has_code() {
                self.push_frame(&d, args)?;
                return self.run();
            }
        }
        // The file either does not declare it, or declares it with no body. Both
        // are the same shape of question for a shim — `Bundle.getString` and a
        // `native` method on the app's own class differ only in who is asking.
        let kind = if args.is_empty() { InvokeKind::Static } else { InvokeKind::Direct };
        let call = Call { class, name, signature, kind, args };
        self.stats.framework_calls += 1;
        let outcome = self.host.invoke(&call);
        self.record_call(&call, &outcome);
        self.host_result_value(outcome, signature, &Site::default())
    }

    /// Turn a host outcome into a value or an error.
    ///
    /// A `HostOutcome::Value` counts as *unimplemented* for the accounting: a
    /// shim that answers with a guessed value has not implemented the method, and
    /// the study needs to be able to separate "the substrate knew" from "the
    /// substrate made something up".
    fn host_result_value(
        &mut self,
        outcome: HostOutcome,
        signature: &str,
        site: &Site,
    ) -> ExecResult<Value> {
        match outcome {
            HostOutcome::Value(v) => {
                self.stats.framework_calls_unimplemented += 1;
                self.materialise(v)
            }
            HostOutcome::NotImplemented => {
                self.stats.framework_calls_unimplemented += 1;
                let (_, ret) = JType::parse_prototype(signature);
                Ok(Value::default_for(&ret).unwrap_or(Value::Null))
            }
            HostOutcome::Throw(spec) => {
                let exc = self.raise(spec, site)?;
                Err(self.uncaught(exc, site))
            }
        }
    }

    // ================================================================ frames

    /// Push a frame for `decl`, laying the incoming arguments into the register
    /// window.
    ///
    /// Dalvik puts arguments in the *last* `ins_size` registers with `this` in
    /// the last of them, so the window fills from `registers_size - ins_size`
    /// upwards. Positions come from the prototype rather than from the values,
    /// so a `long` cannot shift every later argument.
    fn push_frame(&mut self, decl: &MethodDecl, args: &[Value]) -> ExecResult<()> {
        if self.frames.len() >= self.config.max_call_depth as usize {
            let site = self.site();
            return Err(ExecError::StackOverflow { limit: self.config.max_call_depth, site });
        }
        let code = self.program.code(&self.dex, decl.code_off)?;
        let registers_size = code.registers_size as usize;
        let window_start = (registers_size as i64) - i64::from(code.ins_size);
        let expected = decl.incoming_slots();
        if args.len() != expected {
            return Err(self.frame_error(
                decl,
                Malformed::TypeMismatch,
                format!(
                    "{}.{}{} takes {} argument word(s), the caller supplied {}",
                    self.class_name(decl.class),
                    decl.name,
                    decl.signature,
                    expected,
                    args.len()
                ),
            ));
        }
        if window_start < 0 {
            return Err(self.frame_error(
                decl,
                Malformed::BadCode,
                format!(
                    "registers_size {registers_size} is smaller than ins_size {}",
                    code.ins_size
                ),
            ));
        }

        let mut registers = vec![Value::Uninit; registers_size];
        let mut cursor = window_start as usize;
        for (i, arg) in args.iter().enumerate() {
            let is_this = i == 0 && !decl.is_static();
            if is_this && !arg.is_reference() {
                return Err(self.frame_error(
                    decl,
                    Malformed::TypeMismatch,
                    format!("`this` is {}, not a reference", arg.type_name()),
                ));
            }
            let slots = arg.slots();
            if cursor + slots > registers.len() {
                return Err(self.frame_error(
                    decl,
                    Malformed::BadCode,
                    format!(
                        "argument {i} needs {slots} word(s) but only {} remain",
                        registers.len().saturating_sub(cursor)
                    ),
                ));
            }
            if let Some(t) = registers.get_mut(cursor) {
                *t = *arg;
            }
            if slots == 2 {
                if let Some(t) = registers.get_mut(cursor + 1) {
                    *t = Value::WidePad;
                }
            }
            cursor += slots;
        }

        self.stats.method_invocations += 1;
        let depth = self.frames.len() as u32 + 1;
        if depth > self.stats.max_call_depth {
            self.stats.max_call_depth = depth;
        }
        self.frames.push(Frame {
            signature_text: render_signature(self, decl),
            registers,
            pc: 0,
            result: None,
            code,
            held: Vec::new(),
        });
        Ok(())
    }

    fn frame_error(&self, decl: &MethodDecl, kind: Malformed, detail: String) -> ExecError {
        ExecError::Malformed {
            kind,
            detail,
            site: Site { method: Some(render_signature(self, decl)), unit: 0, opcode: None },
        }
    }

    /// The site of the instruction the pc currently points at.
    fn site(&self) -> Site {
        match self.frames.last() {
            Some(f) => {
                let found = f
                    .code
                    .index_of_unit(f.pc as u32)
                    .and_then(|i| f.code.insns.get(i));
                let (unit, opcode) = match found {
                    Some(i) => (i.unit, i.instruction.opcode()),
                    None => (f.pc as u32, None),
                };
                Site { method: Some(f.signature_text.clone()), unit, opcode }
            }
            None => Site::default(),
        }
    }

    // =================================================================== run

    /// The dispatch loop. Runs until the frame stack empties or something stops
    /// it.
    fn run(&mut self) -> ExecResult<Value> {
        loop {
            let (instruction, site, width) = {
                let frame = match self.frames.last() {
                    Some(f) => f,
                    None => {
                        return Err(ExecError::Malformed {
                            kind: Malformed::BadCode,
                            detail: "the frame stack emptied without a return".to_string(),
                            site: Site::default(),
                        })
                    }
                };
                let pc = frame.pc;
                let index = match frame.code.index_of_unit(pc as u32) {
                    Some(i) => i,
                    None => {
                        // Falling off the end of a `code_item` without a
                        // `return` is something the verifier rejects and no
                        // compiler emits. It is reported rather than papered
                        // over with an implicit `return-void`, because inventing
                        // a return value is exactly the kind of plausible wrong
                        // answer this instrument must not produce.
                        return Err(ExecError::Malformed {
                            kind: Malformed::MissingReturn,
                            detail: format!(
                                "execution left the instruction stream at unit {pc} of {} \
                                 ({} units; the last starts at {})",
                                frame.signature_text,
                                frame.code.units,
                                frame.code.units.saturating_sub(1)
                            ),
                            site: Site {
                                method: Some(frame.signature_text.clone()),
                                unit: pc as u32,
                                opcode: None,
                            },
                        });
                    }
                };
                let insn = match frame.code.insns.get(index) {
                    Some(i) => i,
                    None => {
                        return Err(ExecError::Malformed {
                            kind: Malformed::BadCode,
                            detail: format!("instruction index {index} is out of range"),
                            site: Site::default(),
                        })
                    }
                };
                let site = Site {
                    method: Some(frame.signature_text.clone()),
                    unit: insn.unit,
                    opcode: insn.instruction.opcode(),
                };
                // `Instruction::width` is in *bytes*; the pc is in code units.
                // Dividing here rather than at every comparison keeps the one
                // conversion in the one place the two notions meet.
                let width = (insn.instruction.width() as usize / 2).max(1);
                (insn.instruction.clone(), site, width.max(1))
            };

            if self.remaining == 0 {
                self.stats.budget_exhausted = true;
                return Err(ExecError::BudgetExhausted {
                    kind: Budget::Instructions,
                    limit: self.config.instruction_budget.unwrap_or(u64::MAX),
                    site,
                });
            }
            self.remaining -= 1;
            self.stats.instructions_executed += 1;
            if let Some(op) = instruction.opcode() {
                if let Some(c) = self.stats.opcode_counts.get_mut(op as usize) {
                    *c += 1;
                }
            }

            // Advance past the instruction *before* executing it. Then `pc` is
            // always the next candidate, whichever way control flow goes, and
            // relative branches are computed from `site.unit`.
            if let Some(f) = self.frames.last_mut() {
                f.pc = site.unit as usize + width;
            }
            self.pending_throw = None;

            let flow = match self.execute(&instruction, &site) {
                Ok(f) => f,
                Err(e) => return Err(self.locate(e, &site)),
            };
            if let Some(exc) = self.pending_throw.take() {
                // A shim turned a field access into an exception.
                if self.unwind(exc, site.unit)? {
                    continue;
                }
                return Err(self.uncaught(exc, &site));
            }
            match flow {
                Flow::Next | Flow::Call => {}
                Flow::Return(value) => {
                    if let Some(v) = self.pop_frame(value) {
                        return Ok(v);
                    }
                }
                Flow::Thrown(exc) => {
                    if self.unwind(exc, site.unit)? {
                        continue;
                    }
                    return Err(self.uncaught(exc, &site));
                }
            }
        }
    }

    /// Attach `site` to an error that was built without one.
    fn locate(&self, e: ExecError, site: &Site) -> ExecError {
        let no_site = matches!(&e, ExecError::Unsupported { site, .. } | ExecError::Malformed { site, .. } if site.unit == 0 && site.method.is_none());
        if !no_site {
            return e;
        }
        match e {
            ExecError::Unsupported { kind, detail, .. } => {
                ExecError::Unsupported { kind, detail, site: site.clone() }
            }
            ExecError::Malformed { kind, detail, .. } => {
                ExecError::Malformed { kind, detail, site: site.clone() }
            }
            other => other,
        }
    }

    fn set_pc(&mut self, target: u32) {
        if let Some(f) = self.frames.last_mut() {
            f.pc = target as usize;
        }
    }

    /// Pop the current frame, delivering `value` to the caller. `None` means the
    /// stack is now empty and `value` is the top-level result.
    fn pop_frame(&mut self, value: Value) -> Option<Value> {
        let frame = self.frames.pop()?;
        for r in frame.held.iter().rev() {
            if let Some(obj) = self.heap.get_mut(*r) {
                let mut m = obj.monitor;
                m.exit();
                obj.monitor = m;
            }
        }
        if self.frames.is_empty() {
            return Some(value);
        }
        if let Some(caller) = self.frames.last_mut() {
            caller.result = Some(value);
        }
        None
    }

    /// Search for a handler for `exc`, popping frames until one is found.
    /// Returns `true` if a handler was entered.
    fn unwind(&mut self, exc: Value, throw_unit: u32) -> ExecResult<bool> {
        let exc_class = self.class_id_of_object(exc);
        loop {
            let (tries, ins_size, registers_len) = match self.frames.last() {
                Some(f) => (f.code.tries.clone(), f.code.ins_size as usize, f.registers.len()),
                None => return Ok(false),
            };
            let mut found: Option<u32> = None;
            for range in tries.iter() {
                if throw_unit < range.start || throw_unit > range.end {
                    continue;
                }
                for clause in range.handlers.iter() {
                    let matches = match &clause.type_descriptor {
                        // A catch-all always matches.
                        None => true,
                        Some(d) => match (exc_class, self.class_id_known(d)) {
                            (Some(c), Some(target)) => self.program.is_a(c, target),
                            // A null throwable, or a caught type this substrate
                            // does not have, cannot match a typed clause. Not
                            // matching is also what a device does when the class
                            // cannot be resolved: the clause is simply not
                            // entered.
                            _ => false,
                        },
                    };
                    if matches {
                        found = Some(clause.address);
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            match found {
                Some(address) => {
                    if self
                        .frames
                        .last()
                        .map(|f| f.code.index_of_unit(address))
                        .is_none()
                    {
                        return Err(ExecError::Malformed {
                            kind: Malformed::BadBranchTarget,
                            detail: format!("catch handler at unit {address} is not an instruction"),
                            site: Site::default(),
                        });
                    }
                    // Entering a handler clears the operand stack: everything
                    // outside the incoming-argument window is undefined, and
                    // leaving stale values there would let a handler read a
                    // register the specification says it cannot. A valid handler
                    // only ever reads `move-exception`'s destination, so nothing
                    // is lost.
                    let keep_from = registers_len.saturating_sub(ins_size);
                    if let Some(f) = self.frames.last_mut() {
                        for (i, r) in f.registers.iter_mut().enumerate() {
                            if i < keep_from {
                                *r = Value::Uninit;
                            }
                        }
                        f.result = Some(exc);
                    }
                    self.set_pc(address);
                    self.stats.exceptions_caught += 1;
                    return Ok(true);
                }
                None => {
                    // No handler here: the exception propagates to the caller.
                    self.frames.pop();
                    if self.frames.is_empty() {
                        return Ok(false);
                    }
                }
            }
        }
    }

    /// The terminal error for an exception that reached the bottom.
    fn uncaught(&mut self, exc: Value, site: &Site) -> ExecError {
        if self.frames.is_empty() {
            self.stats.exceptions_uncaught += 1;
        }
        let class =
            self.class_of(exc).unwrap_or_else(|| "Ljava/lang/Throwable;".to_string());
        let message = match exc {
            Value::Ref(r) => self.heap.get(r).and_then(|o| o.detail_message.clone()),
            _ => None,
        };
        ExecError::ExceptionRaised { object: exc, class, message, site: site.clone() }
    }

    // ============================================================ instruction

    /// Execute one decoded instruction.
    fn execute(&mut self, insn: &Instruction, site: &Site) -> ExecResult<Flow> {
        use Instruction as I;
        match insn {
            I::F10X { op } => match op {
                0x00 => Ok(Flow::Next),             // nop
                0x0e => Ok(Flow::Return(Value::Void)), // return-void
                _ => self.foreign(*op, site),
            },
            I::F10T { offset, .. } => self.branch(*offset as i32, site),
            I::F20T { offset, .. } => self.branch(*offset as i32, site),
            I::F30T { offset, .. } => self.branch(*offset, site),
            I::F11N { op, a, literal, .. } => match op {
                0x12 => {
                    self.sv(*a as usize, Value::Int(i32::from(*literal)))?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F11X { op, a } => self.op_11x(*op, *a as usize, site),
            I::F12X { op, a, b } => self.op_12x(*op, *a as usize, *b as usize, site),
            I::F21S { op, a, literal } => match op {
                0x13 => {
                    self.sv(*a as usize, Value::Int(i32::from(*literal)))?;
                    Ok(Flow::Next)
                }
                0x16 => {
                    self.set_wide(*a as usize, Value::Long(i64::from(*literal)))?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F21H { op, a, literal } => match op {
                0x15 => {
                    self.sv(*a as usize, Value::Int(i32::from(*literal) << 16))?;
                    Ok(Flow::Next)
                }
                0x19 => {
                    self.set_wide(*a as usize, Value::Long(i64::from(*literal) << 16))?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F31I { op, a, literal } => match op {
                0x14 => {
                    self.sv(*a as usize, Value::Int(*literal))?;
                    Ok(Flow::Next)
                }
                0x17 => {
                    // `const-wide/32` sign-extends 32 bits into 64.
                    self.set_wide(*a as usize, Value::Long(i64::from(*literal)))?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F51L { op, a, literal } => match op {
                0x18 => {
                    self.set_wide(*a as usize, Value::Long(*literal))?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F21C { op, a, index } => self.op_21c(*op, *a as usize, *index, site),
            I::F31C { op, a, index } => match op {
                0x1b => {
                    let text = self.string_at(*index, site)?;
                    let v = self.new_string_value(text)?;
                    self.sv(*a as usize, v)?;
                    Ok(Flow::Next)
                }
                _ => self.foreign(*op, site),
            },
            I::F22X { op, a, b } => self.op_move(*op, *a as usize, *b as usize, site),
            I::F32X { op, a, b } => self.op_move(*op, *a as usize, *b as usize, site),
            I::F22B { op, a, b, literal } => self.op_22b(*op, *a as usize, *b as usize, *literal, site),
            I::F22S { op, a, b, literal } => self.op_22s(*op, *a as usize, *b as usize, *literal, site),
            I::F23X { op, a, b, c } => self.op_23x(*op, *a as usize, *b as usize, *c as usize, site),
            I::F22C { op, a, b, index } => self.op_22c(*op, *a as usize, *b as usize, *index, site),
            I::F22T { op, a, b, offset } => {
                let x = self.gi(*a as usize, site)?;
                let y = self.gi(*b as usize, site)?;
                if int_compare(*op, x, y) {
                    self.branch(*offset as i32, site)
                } else {
                    Ok(Flow::Next)
                }
            }
            I::F21T { op, a, offset } => {
                let x = self.gi(*a as usize, site)?;
                if int_compare_zero(*op, x) {
                    self.branch(*offset as i32, site)
                } else {
                    Ok(Flow::Next)
                }
            }
            I::F31T { op, a, offset } => self.op_31t(*op, *a as usize, *offset, site),
            I::F35C { op, a, index, regs, .. } => {
                self.op_call_forms(*op, &regs.to_vec(), *index, *a, 0, None, site)
            }
            I::F3RC { op, index, first_reg, reg_count, .. } => {
                let list = range_regs(*first_reg, *reg_count);
                self.op_call_forms(*op, &list, *index, 0, *reg_count, None, site)
            }
            I::F45CC { op, a, index, regs, proto, .. } => {
                self.op_call_forms(*op, &regs.to_vec(), *index, *a, 0, Some(*proto), site)
            }
            I::F4RCC { op, index, first_reg, reg_count, proto, .. } => {
                let list = range_regs(*first_reg, *reg_count);
                self.op_call_forms(*op, &list, *index, 0, *reg_count, Some(*proto), site)
            }
            I::Payload(p) => self.execute_payload(p, site),
            I::Unused { op } => Err(ExecError::Unsupported {
                kind: Unsupported::UnusedOpcode,
                detail: format!("opcode 0x{op:02x} is marked (unused) by the specification"),
                site: site.clone(),
            }),
            I::F20BC { op, .. }
            | I::F22CS { op, .. }
            | I::F35MS { op, .. }
            | I::F35MI { op, .. }
            | I::F3RMS { op, .. }
            | I::F3RMI { op, .. }
            | I::F52C { op, .. }
            | I::F5RC { op, .. } => self.foreign(*op, site),
        }
    }

    /// A payload pseudo-instruction reached by falling through, which the
    /// specification permits in a stream but no compiler produces.
    fn execute_payload(&mut self, p: &Payload, site: &Site) -> ExecResult<Flow> {
        Err(ExecError::Malformed {
            kind: Malformed::BadPayload,
            detail: format!(
                "{} payload is data, not an instruction; execution fell into it",
                payload_name(p)
            ),
            site: site.clone(),
        })
    }

    /// A decode that produced an operation this engine does not implement.
    fn foreign(&mut self, op: u8, site: &Site) -> ExecResult<Flow> {
        Err(ExecError::Unsupported {
            kind: Unsupported::ForeignFormat,
            detail: format!("opcode 0x{op:02x} is not a Dalvik operation"),
            site: site.clone(),
        })
    }

    // ======================================================= register access

    fn gv(&self, r: usize, site: &Site) -> ExecResult<Value> {
        match self.frames.last().and_then(|f| f.registers.get(r)) {
            Some(v) => Ok(*v),
            None => Err(self.bad_register(r, site)),
        }
    }

    fn sv(&mut self, r: usize, v: Value) -> ExecResult<()> {
        match self.frames.last_mut().and_then(|f| f.registers.get_mut(r)) {
            Some(slot) => {
                *slot = v;
                Ok(())
            }
            None => {
                let site = self.site();
                Err(self.bad_register(r, &site))
            }
        }
    }

    fn bad_register(&self, r: usize, site: &Site) -> ExecError {
        let size = self.frames.last().map(|f| f.registers.len()).unwrap_or(0);
        ExecError::Malformed {
            kind: Malformed::BadRegister,
            detail: format!("register v{r} is outside the frame's {size} registers"),
            site: site.clone(),
        }
    }

    /// Write a value, and its high word if it is a wide one.
    fn set_wide(&mut self, r: usize, v: Value) -> ExecResult<()> {
        let slots = v.slots();
        self.sv(r, v)?;
        if slots == 2 {
            let high = r + 1;
            let fits =
                self.frames.last().map(|f| high < f.registers.len()).unwrap_or(false);
            if !fits {
                let site = self.site();
                return Err(self.bad_register(high, &site));
            }
            self.sv(high, Value::WidePad)?;
        }
        Ok(())
    }

    fn uninit(&self, r: usize, site: &Site) -> ExecError {
        ExecError::Malformed {
            kind: Malformed::UninitialisedRegister,
            detail: format!("v{r} was read before anything wrote it"),
            site: site.clone(),
        }
    }

    fn gi(&self, r: usize, site: &Site) -> ExecResult<i32> {
        let v = self.gv(r, site)?;
        if v == Value::Uninit {
            return Err(self.uninit(r, site));
        }
        v.as_int("integer operand").map_err(|e| self.wrong_type(e, site))
    }

    fn gl(&self, r: usize, site: &Site) -> ExecResult<i64> {
        let v = self.gv(r, site)?;
        if v == Value::Uninit {
            return Err(self.uninit(r, site));
        }
        v.as_long("long operand").map_err(|e| self.wrong_type(e, site))
    }

    fn gf(&self, r: usize, site: &Site) -> ExecResult<f32> {
        let v = self.gv(r, site)?;
        if v == Value::Uninit {
            return Err(self.uninit(r, site));
        }
        v.as_float("float operand").map_err(|e| self.wrong_type(e, site))
    }

    fn gd(&self, r: usize, site: &Site) -> ExecResult<f64> {
        let v = self.gv(r, site)?;
        if v == Value::Uninit {
            return Err(self.uninit(r, site));
        }
        v.as_double("double operand").map_err(|e| self.wrong_type(e, site))
    }

    fn gr(&self, r: usize, site: &Site) -> ExecResult<Option<Ref>> {
        let v = self.gv(r, site)?;
        if v == Value::Uninit {
            return Err(self.uninit(r, site));
        }
        v.ref_or_null("reference operand").map_err(|e| self.wrong_type(e, site))
    }

    fn wrong_type(&self, e: crate::value::WrongType, site: &Site) -> ExecError {
        ExecError::Malformed {
            kind: Malformed::TypeMismatch,
            detail: e.to_string(),
            site: site.clone(),
        }
    }

    // ================================================================ control

    /// Branch by a signed code-unit offset relative to the *current*
    /// instruction, which is [`Site::unit`].
    fn branch(&mut self, offset: i32, site: &Site) -> ExecResult<Flow> {
        let target = i64::from(site.unit) + i64::from(offset);
        if target < 0 || target > u32::MAX as i64 {
            return Err(ExecError::Malformed {
                kind: Malformed::BadBranchTarget,
                detail: format!(
                    "branch offset {offset} from unit {} leaves the method",
                    site.unit
                ),
                site: site.clone(),
            });
        }
        self.jump_to(target as u32, offset, site)?;
        Ok(Flow::Next)
    }

    fn jump_to(&mut self, target: u32, offset: i32, site: &Site) -> ExecResult<()> {
        let ok = self
            .frames
            .last()
            .and_then(|f| f.code.index_of_unit(target))
            .is_some();
        if !ok {
            return Err(ExecError::Malformed {
                kind: Malformed::BadBranchTarget,
                detail: format!(
                    "branch to unit {target} (offset {offset}) is not the start of an instruction"
                ),
                site: site.clone(),
            });
        }
        self.set_pc(target);
        Ok(())
    }

    // ============================================================== 11x ops

    fn op_11x(&mut self, op: u8, a: usize, site: &Site) -> ExecResult<Flow> {
        match op {
            0x0a | 0x0b | 0x0c => {
                let result = self
                    .frames
                    .last()
                    .and_then(|f| f.result)
                    .ok_or_else(|| self.no_result(site))?;
                if result == Value::Uninit {
                    return Err(self.uninit(a, site));
                }
                if op == 0x0b {
                    self.set_wide(a, result)?;
                } else {
                    self.sv(a, result)?;
                }
                Ok(Flow::Next)
            }
            0x0d => {
                let exc =
                    self.frames.last().and_then(|f| f.result).ok_or_else(|| self.no_result(site))?;
                self.sv(a, exc)?;
                Ok(Flow::Next)
            }
            0x0f | 0x10 | 0x11 => {
                let v = self.gv(a, site)?;
                Ok(Flow::Return(check_return(v, site)?))
            }
            0x1d => self.monitor_enter(a, site),
            0x1e => self.monitor_exit(a, site),
            0x27 => {
                let v = self.gv(a, site)?;
                match v {
                    Value::Ref(r) => {
                        self.stats.app_exceptions += 1;
                        Ok(Flow::Thrown(Value::Ref(r)))
                    }
                    other => Err(ExecError::Malformed {
                        kind: Malformed::TypeMismatch,
                        detail: format!(
                            "throw v{a}: v{a} is {}, not a reference",
                            other.type_name()
                        ),
                        site: site.clone(),
                    }),
                }
            }
            _ => self.foreign(op, site),
        }
    }

    fn no_result(&self, site: &Site) -> ExecError {
        ExecError::Malformed {
            kind: Malformed::UninitialisedRegister,
            detail: "move-result with no call before it in this frame".to_string(),
            site: site.clone(),
        }
    }

    // ============================================================== 12x ops

    fn op_12x(&mut self, op: u8, a: usize, b: usize, site: &Site) -> ExecResult<Flow> {
        match op {
            0x01 | 0x07 => {
                let v = self.gv(b, site)?;
                self.sv(a, v)?;
            }
            0x04 => {
                let v = self.gv(b, site)?;
                self.set_wide(a, v)?;
            }
            0x21 => {
                match self.gr(b, site)? {
                    None => {
                        return Ok(Flow::Thrown(self.new_throwable(
                            "Ljava/lang/NullPointerException;",
                            "array-length on null",
                        )?))
                    }
                    Some(r) => {
                        let len = match self.heap.get(r).map(|o| &o.kind) {
                            Some(ObjectKind::Array { elements, .. }) => elements.len() as i32,
                            _ => {
                                return Err(ExecError::Malformed {
                                    kind: Malformed::TypeMismatch,
                                    detail: format!("array-length on {}", self.describe(r)),
                                    site: site.clone(),
                                })
                            }
                        };
                        self.sv(a, Value::Int(len))?;
                    }
                }
            }
            0x7b..=0x8f => self.unary_12x(op, a, b, site)?,
            0xb0..=0xcf => {
                if let Some(f) = self.binary_2addr(op, a, b, site)? {
                    return Ok(f);
                }
            }
            _ => return self.foreign(op, site),
        }
        Ok(Flow::Next)
    }

    /// `neg-*`, `not-*` and the numeric conversions, all `12x`.
    fn unary_12x(&mut self, op: u8, a: usize, b: usize, site: &Site) -> ExecResult<()> {
        match op {
            0x7b => {
                let v = self.gi(b, site)?;
                self.sv(a, Value::Int(v.wrapping_neg()))
            }
            0x7c => {
                let v = self.gi(b, site)?;
                self.sv(a, Value::Int(!v))
            }
            0x7d => {
                let v = self.gl(b, site)?;
                self.set_wide(a, Value::Long(v.wrapping_neg()))
            }
            0x7e => {
                let v = self.gl(b, site)?;
                self.set_wide(a, Value::Long(!v))
            }
            0x7f => {
                let v = self.gf(b, site)?;
                self.sv(a, Value::Float(-v))
            }
            0x80 => {
                let v = self.gd(b, site)?;
                self.set_wide(a, Value::Double(-v))
            }
            0x81 => {
                let v = self.gi(b, site)?;
                self.set_wide(a, Value::Long(i64::from(v)))
            }
            0x82 => {
                let v = self.gi(b, site)?;
                self.sv(a, Value::Float(v as f32))
            }
            0x83 => {
                let v = self.gi(b, site)?;
                self.set_wide(a, Value::Double(f64::from(v)))
            }
            0x84 => {
                let v = self.gl(b, site)?;
                self.sv(a, Value::Int(v as i32))
            }
            0x85 => {
                let v = self.gl(b, site)?;
                self.sv(a, Value::Float(v as f32))
            }
            0x86 => {
                let v = self.gl(b, site)?;
                self.set_wide(a, Value::Double(v as f64))
            }
            0x87 => {
                let v = self.gf(b, site)?;
                self.sv(a, Value::Int(ops::f32_to_int(v)))
            }
            0x88 => {
                let v = self.gf(b, site)?;
                self.set_wide(a, Value::Long(ops::f32_to_i64(v)))
            }
            0x89 => {
                let v = self.gf(b, site)?;
                self.set_wide(a, Value::Double(f64::from(v)))
            }
            0x8a => {
                let v = self.gd(b, site)?;
                self.sv(a, Value::Int(ops::f64_to_int(v)))
            }
            0x8b => {
                let v = self.gd(b, site)?;
                self.set_wide(a, Value::Long(ops::f64_to_i64(v)))
            }
            0x8c => {
                let v = self.gd(b, site)?;
                self.sv(a, Value::Float(v as f32))
            }
            0x8d => {
                let v = self.gi(b, site)?;
                self.sv(a, Value::Int(i32::from(v as i8)))
            }
            0x8e => {
                // int-to-char zero-extends: 0xFFFF is 65535, not -1.
                let v = self.gi(b, site)?;
                self.sv(a, Value::Int(i32::from(v as u16)))
            }
            0x8f => {
                let v = self.gi(b, site)?;
                self.sv(a, Value::Int(i32::from(v as i16)))
            }
            _ => self.foreign(op, site).map(|_| ()),
        }
    }

    /// `add-int/2addr` and friends: `vA = vA op vB`.
    ///
    /// Returns `Some(flow)` when the operation became a throwable, which is how
    /// division by zero escapes without being confused with a type error.
    fn binary_2addr(
        &mut self,
        op: u8,
        a: usize,
        b: usize,
        site: &Site,
    ) -> ExecResult<Option<Flow>> {
        match op {
            0xbb..=0xc5 => {
                let x = self.gl(a, site)?;
                let y = self.gl(b, site)?;
                match ops::int64_binop(op - 0xbb, x, y) {
                    Ok(r) => {
                        self.set_wide(a, Value::Long(r))?;
                    }
                    Err(e) => return Ok(Some(self.num_throwable(e)?)),
                }
            }
            0xcb..=0xcf => {
                let x = self.gd(a, site)?;
                let y = self.gd(b, site)?;
                self.set_wide(a, Value::Double(ops::float64_binop(op - 0xcb, x, y)))?;
            }
            0xc6..=0xca => {
                let x = self.gf(a, site)?;
                let y = self.gf(b, site)?;
                self.sv(a, Value::Float(ops::float32_binop(op - 0xc6, x, y)))?;
            }
            _ => {
                let x = self.gi(a, site)?;
                let y = self.gi(b, site)?;
                match ops::int32_binop(op - 0xb0, x, y) {
                    Ok(r) => {
                        self.sv(a, Value::Int(r))?;
                    }
                    Err(e) => return Ok(Some(self.num_throwable(e)?)),
                }
            }
        }
        Ok(None)
    }

    fn num_throwable(&mut self, e: NumErr) -> ExecResult<Flow> {
        let v = match e {
            NumErr::DivideByZero => {
                self.new_throwable("Ljava/lang/ArithmeticException;", "divide by zero")?
            }
        };
        Ok(Flow::Thrown(v))
    }

    // ========================================================= 22x/32x moves

    fn op_move(&mut self, op: u8, a: usize, b: usize, site: &Site) -> ExecResult<Flow> {
        let v = self.gv(b, site)?;
        match op {
            0x02 | 0x03 | 0x08 | 0x09 => {
                self.sv(a, v)?;
            }
            0x05 | 0x06 => {
                self.set_wide(a, v)?;
            }
            _ => return self.foreign(op, site),
        }
        Ok(Flow::Next)
    }

    // ========================================================= 21c / 22c ops

    fn op_21c(&mut self, op: u8, a: usize, index: u16, site: &Site) -> ExecResult<Flow> {
        match op {
            0x1a => {
                let text = self.string_at(index as u32, site)?;
                let v = self.new_string_value(text)?;
                self.sv(a, v)?;
            }
            0x1c => {
                let d = self.type_at(index as u32, site)?;
                let v = self.new_class_value(&d)?;
                self.sv(a, v)?;
            }
            0x1f => {
                // check-cast
                let v = self.gv(a, site)?;
                if let Some(r) =
                    v.ref_or_null("check-cast").map_err(|e| self.wrong_type(e, site))?
                {
                    let d = self.type_at(index as u32, site)?;
                    let target = self.class_id_for_test(&d);
                    let actual = self.class_id_of_object(Value::Ref(r));
                    let ok = match (target, actual) {
                        (Some(t), Some(c)) => self.program.is_a(c, t),
                        // An unresolvable cast target cannot be checked, and
                        // `check-cast` throws only when the object is not an
                        // instance of it. A class this substrate does not have is
                        // not "not an instance", so it passes: otherwise every
                        // app that casts to an `android.*` type would fail, which
                        // is an artefact of the substrate and not a result.
                        _ => true,
                    };
                    if !ok {
                        let exc = self.new_throwable(
                            "Ljava/lang/ClassCastException;",
                            format!("{} cannot be cast to {d}", self.describe(r)),
                        )?;
                        return Ok(Flow::Thrown(exc));
                    }
                }
            }
            0x22 => {
                let d = self.type_at(index as u32, site)?;
                let v = self.new_instance(&d)?;
                self.sv(a, v)?;
            }
            0x60..=0x66 => self.sget(op, a, index as u32, site)?,
            0x67..=0x6d => self.sput(op, a, index as u32, site)?,
            0xfe => {
                let handle = self.program.method_handle(index as u32)?;
                let target = match (handle.method_idx, handle.field_idx) {
                    (Some(m), _) => self
                        .program
                        .methods
                        .get(m as usize)
                        .map(|(c, n, s)| format!("{c}.{n}{s}")),
                    (_, Some(f)) => self
                        .program
                        .fields
                        .get(f as usize)
                        .map(|(c, n, t)| format!("{c}.{n}:{t}")),
                    _ => None,
                };
                let v = self.new_method_handle(handle.kind, target)?;
                self.sv(a, v)?;
            }
            0xff => {
                let proto = self.proto_signature(index as u32, site)?;
                let v = self.new_method_type(&proto)?;
                self.sv(a, v)?;
            }
            _ => return self.foreign(op, site),
        }
        Ok(Flow::Next)
    }

    fn op_22c(&mut self, op: u8, a: usize, b: usize, index: u16, site: &Site) -> ExecResult<Flow> {
        match op {
            0x20 => {
                let r = self.gr(b, site)?;
                let d = self.type_at(index as u32, site)?;
                let result = match r {
                    None => false,
                    Some(r) => {
                        match (self.class_id_for_test(&d), self.class_id_of_object(Value::Ref(r))) {
                            (Some(t), Some(c)) => self.program.is_a(c, t),
                            _ => false,
                        }
                    }
                };
                self.sv(a, Value::Int(i32::from(result)))?;
            }
            0x23 => {
                let d = self.type_at(index as u32, site)?;
                let len = self.gi(b, site)?;
                if len < 0 {
                    return Ok(Flow::Thrown(self.new_throwable(
                        "Ljava/lang/NegativeArraySizeException;",
                        format!("{len}"),
                    )?));
                }
                let v = self.new_array(&d, len as usize)?;
                self.sv(a, v)?;
            }
            0x52..=0x58 => self.iget(op, a, b, index as u32, site)?,
            0x59..=0x5f => self.iput(op, a, b, index as u32, site)?,
            _ => return self.foreign(op, site),
        }
        Ok(Flow::Next)
    }

    // ============================================================ 23x ops

    fn op_23x(&mut self, op: u8, a: usize, b: usize, c: usize, site: &Site) -> ExecResult<Flow> {
        match op {
            0x2d..=0x31 => {
                let x = self.gv(b, site)?;
                let y = self.gv(c, site)?;
                let r = ops::compare_fp(op, x, y).map_err(|e| self.wrong_type(e, site))?;
                self.sv(a, Value::Int(r))?;
            }
            0x44..=0x4a => {
                let arr = self.gv(b, site)?;
                let i = self.gi(c, site)?;
                match self.array_get(op, arr, i) {
                    ArrayOp::Done(v) => {
                        if matches!(v, Value::Long(_) | Value::Double(_)) {
                            self.set_wide(a, v)?;
                        } else {
                            self.sv(a, v)?;
                        }
                    }
                    ArrayOp::Fault(f) => return self.array_throwable(f, site),
                }
            }
            0x4b..=0x51 => {
                let arr = self.gv(b, site)?;
                let i = self.gi(c, site)?;
                let v = self.gv(a, site)?;
                match self.array_put(op, arr, i, v) {
                    ArrayOp::Done(_) => {}
                    ArrayOp::Fault(f) => return self.array_throwable(f, site),
                }
            }
            0x90..=0x9a => {
                let x = self.gi(b, site)?;
                let y = self.gi(c, site)?;
                match ops::int32_binop(op - 0x90, x, y) {
                    Ok(r) => {
                        self.sv(a, Value::Int(r))?;
                    }
                    Err(e) => return self.num_throwable(e),
                }
            }
            0x9b..=0xa5 => {
                let x = self.gl(b, site)?;
                let y = self.gl(c, site)?;
                match ops::int64_binop(op - 0x9b, x, y) {
                    Ok(r) => {
                        self.set_wide(a, Value::Long(r))?;
                    }
                    Err(e) => return self.num_throwable(e),
                }
            }
            0xa6..=0xaa => {
                let x = self.gf(b, site)?;
                let y = self.gf(c, site)?;
                self.sv(a, Value::Float(ops::float32_binop(op - 0xa6, x, y)))?;
            }
            0xab..=0xaf => {
                let x = self.gd(b, site)?;
                let y = self.gd(c, site)?;
                self.set_wide(a, Value::Double(ops::float64_binop(op - 0xab, x, y)))?;
            }
            _ => return self.foreign(op, site),
        }
        Ok(Flow::Next)
    }

    // ======================================================= 22b / 22s ops

    fn op_22b(&mut self, op: u8, a: usize, b: usize, literal: i8, site: &Site) -> ExecResult<Flow> {
        let y = i32::from(literal);
        let x = self.gi(b, site)?;
        let r = match op {
            0xd8..=0xdf => match ops::int32_binop(op - 0xd8, x, y) {
                Ok(v) => v,
                Err(e) => return self.num_throwable(e),
            },
            // Shift amounts are taken modulo the width, so `-1 << 33` is
            // `-1 << 1` rather than a shift of 33 or of 0.
            0xe0 => x.wrapping_shl((y & 0x1f) as u32),
            0xe1 => x.wrapping_shr((y & 0x1f) as u32),
            0xe2 => ((x as u32).wrapping_shr((y & 0x1f) as u32)) as i32,
            _ => return self.foreign(op, site),
        };
        self.sv(a, Value::Int(r))?;
        Ok(Flow::Next)
    }

    fn op_22s(&mut self, op: u8, a: usize, b: usize, literal: i16, site: &Site) -> ExecResult<Flow> {
        let y = i32::from(literal);
        let x = self.gi(b, site)?;
        let r = match op {
            0xd0 => x.wrapping_add(y),
            // rsub-int is *literal* minus register: the one arithmetic opcode
            // whose operand order is the reverse of what the mnemonic suggests.
            0xd1 => y.wrapping_sub(x),
            0xd2 => x.wrapping_mul(y),
            0xd3 => match ops::int32_binop(3, x, y) {
                Ok(v) => v,
                Err(e) => return self.num_throwable(e),
            },
            0xd4 => match ops::int32_binop(4, x, y) {
                Ok(v) => v,
                Err(e) => return self.num_throwable(e),
            },
            0xd5 => x & y,
            0xd6 => x | y,
            0xd7 => x ^ y,
            _ => return self.foreign(op, site),
        };
        self.sv(a, Value::Int(r))?;
        Ok(Flow::Next)
    }

    // ============================================================ 31t ops

    fn op_31t(&mut self, op: u8, a: usize, offset: i32, site: &Site) -> ExecResult<Flow> {
        // A payload sits at `address_of_the_instruction + offset`, not at
        // `pc + offset`. Getting this wrong lands inside the payload, which the
        // branch validation then reports — but the arithmetic is here so the
        // error is never reached.
        let payload_unit = i64::from(site.unit) + i64::from(offset);
        if payload_unit < 0 || payload_unit > u32::MAX as i64 {
            return Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!(
                    "payload offset {offset} from unit {} leaves the method",
                    site.unit
                ),
                site: site.clone(),
            });
        }
        let payload = self.payload_at(payload_unit as u32, site)?;
        match (op, payload) {
            (0x26, Payload::FillArrayData(fill)) => {
                let arr = self.gv(a, site)?;
                if let Some(f) = self.fill_array(arr, &fill)? {
                    return Ok(f);
                }
            }
            (0x2b, Payload::PackedSwitch(p)) => {
                let key = self.gi(a, site)?;
                let idx = i64::from(key) - i64::from(p.first_key);
                if idx >= 0 && idx < p.targets.len() as i64 {
                    let offset = p.targets.get(idx as usize).copied().unwrap_or(0);
                    let target = switch_target(site.unit, offset, site)?;
                    self.jump_to(target, offset, site)?;
                }
            }
            (0x2c, Payload::SparseSwitch(p)) => {
                let key = self.gi(a, site)?;
                let found =
                    p.keys.iter().position(|k| *k == key).and_then(|i| p.targets.get(i).copied());
                if let Some(offset) = found {
                    let target = switch_target(site.unit, offset, site)?;
                    self.jump_to(target, offset, site)?;
                }
            }
            (op, other) => {
                return Err(ExecError::Malformed {
                    kind: Malformed::BadPayload,
                    detail: format!(
                        "opcode 0x{op:02x} points at a {} payload",
                        payload_name(&other)
                    ),
                    site: site.clone(),
                })
            }
        }
        Ok(Flow::Next)
    }

    /// The payload pseudo-instruction at `unit`, if any.
    fn payload_at(&self, unit: u32, site: &Site) -> ExecResult<Payload> {
        let found = self.frames.last().and_then(|f| {
            f.code
                .index_of_unit(unit)
                .and_then(|i| f.code.insns.get(i))
                .map(|i| i.instruction.clone())
        });
        match found {
            Some(Instruction::Payload(p)) => Ok(p),
            Some(_) => Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!("unit {unit} is an instruction, not a data payload"),
                site: site.clone(),
            }),
            None => Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!("payload at unit {unit} is outside the instruction stream"),
                site: site.clone(),
            }),
        }
    }

    // ==================================================== 35c / 3rc families

    /// Everything whose body is a pool index plus up to five argument
    /// registers: the five `invoke-*` forms, the two `filled-new-array` forms,
    /// the two `invoke-custom` forms and the two `invoke-polymorphic` forms.
    #[allow(clippy::too_many_arguments)]
    fn op_call_forms(
        &mut self,
        op: u8,
        all_regs: &[u8],
        index: u16,
        a: u8,
        reg_count: u16,
        proto: Option<u16>,
        site: &Site,
    ) -> ExecResult<Flow> {
        let ranged = reg_count > 0;
        match op {
            0x6e..=0x72 | 0x74..=0x78 => {
                let arity = self.invoke_arity(op, index)?;
                let list = select_regs(all_regs, arity, ranged);
                if list.len() != arity {
                    return self.arity_error(op, arity, list.len(), site);
                }
                self.do_invoke(op, &list, index as u32, site)
            }
            0x24 => {
                // filled-new-array. The array *type* fixes the element type; the
                // count comes from `A`, which is what d8 writes and what ART
                // reads, falling back to the trimmed nibble count for a producer
                // that wrote zeros.
                let d = self.type_at(index as u32, site)?;
                let component = component_descriptor(&d);
                let arity = if a != 0 { a as usize } else { trimmed_len(all_regs) };
                let list = select_regs(all_regs, arity, false);
                if list.len() != arity {
                    return self.arity_error(op, arity, list.len(), site);
                }
                let v = self.filled_new_array(&component, &list, site)?;
                self.set_result(v);
                Ok(Flow::Next)
            }
            0x25 => {
                let d = self.type_at(index as u32, site)?;
                let component = component_descriptor(&d);
                if all_regs.is_empty() {
                    return self.arity_error(op, 1, 0, site);
                }
                let v = self.filled_new_array(&component, all_regs, site)?;
                self.set_result(v);
                Ok(Flow::Next)
            }
            0xfc | 0xfd => {
                let call_site = self.program.call_site(index as u32)?;
                let arity = self.call_site_arity(&call_site);
                let list = select_regs(all_regs, arity, ranged);
                self.do_invoke_custom(&list, index as u32, site)
            }
            0xfa | 0xfb => {
                let _ = proto;
                self.polymorphic_unsupported(op, index, site)
            }
            _ => self.foreign(op, site),
        }
    }

    fn arity_error(&self, op: u8, want: usize, got: usize, site: &Site) -> ExecResult<Flow> {
        Err(ExecError::Malformed {
            kind: Malformed::TypeMismatch,
            detail: format!(
                "opcode 0x{op:02x} needs {want} argument register(s), the instruction offers {got}"
            ),
            site: site.clone(),
        })
    }

    fn set_result(&mut self, v: Value) {
        if let Some(f) = self.frames.last_mut() {
            f.result = Some(v);
        }
    }

    /// `invoke-polymorphic`, decoded as far as it can be.
    ///
    /// The target method, its name and its signature are all read, and what is
    /// missing — a `MethodHandle` to dispatch through — is named. "Fails at
    /// invokedynamic" is a result, and it has to be a *specific* one.
    fn polymorphic_unsupported(&self, op: u8, index: u16, site: &Site) -> ExecResult<Flow> {
        let (class_desc, name, sig) = match self.program.methods.get(index as usize) {
            Some(t) => t.clone(),
            None => {
                return Err(ExecError::Malformed {
                    kind: Malformed::BadPoolIndex,
                    detail: format!("opcode 0x{op:02x} names method@{index}, which does not exist"),
                    site: site.clone(),
                })
            }
        };
        Err(ExecError::Unsupported {
            kind: Unsupported::PolymorphicCall,
            detail: format!(
                "opcode 0x{op:02x}: {class_desc}.{name}{sig} is a signature-polymorphic method; \
                 this substrate has no java.lang.invoke.MethodHandle to dispatch through"
            ),
            site: site.clone(),
        })
    }

    /// Arity of an `invoke-*`, from its target prototype.
    ///
    /// d8 writes the argument count in the `A` nibble of a `35c` and the register
    /// count in `AA` of a `3rc`, but both are redundant with the prototype — and
    /// the prototype is the authority, because a `35c`'s trailing zero nibbles
    /// are indistinguishable from padding. Where the instruction disagrees, the
    /// prototype wins: a call is defined by its method reference.
    fn invoke_arity(&self, op: u8, index: u16) -> ExecResult<usize> {
        let (_, params, _) = self.method_proto(index as u32, &Site::default())?;
        let mut n = params;
        if op != 0x71 && op != 0x77 {
            // Every non-static form passes the receiver.
            n += 1;
        }
        Ok(n)
    }

    /// Arity of a call site: the parameter count of its own method type, which is
    /// the first bootstrap argument. A call-site type has no receiver, unlike a
    /// method reference, so nothing is added.
    fn call_site_arity(&self, call_site: &CallSiteMeta) -> usize {
        for arg in call_site.arguments.iter() {
            if let EncodedValue::MethodType(idx) = arg {
                if let Ok(sig) = self.proto_signature(*idx, &Site::default()) {
                    let (params, _) = JType::parse_prototype(&sig);
                    return params.len();
                }
            }
        }
        0
    }

    // ============================================================== invoking

    fn do_invoke(
        &mut self,
        op: u8,
        regs: &[u8],
        method_idx: u32,
        site: &Site,
    ) -> ExecResult<Flow> {
        let (class_desc, name, signature) = match self.program.methods.get(method_idx as usize) {
            Some(t) => t.clone(),
            None => {
                return Err(ExecError::Malformed {
                    kind: Malformed::BadPoolIndex,
                    detail: format!("invoke names method@{method_idx}, which does not exist"),
                    site: site.clone(),
                })
            }
        };
        let kind = invoke_kind(op);
        let mut args = Vec::with_capacity(regs.len());
        for r in regs {
            args.push(self.gv(*r as usize, site)?);
        }
        // A null receiver is the most common crash in an Android app, and the
        // most common divergence a substrate hits.
        let receiver = if kind == InvokeKind::Static {
            None
        } else {
            match args.first().copied() {
                None | Some(Value::Null) => {
                    return Ok(Flow::Thrown(self.new_throwable(
                        "Ljava/lang/NullPointerException;",
                        format!("{class_desc}.{name}{signature} on a null receiver"),
                    )?))
                }
                Some(v) => Some(v),
            }
        };
        let named = self.class_id_known(&class_desc);
        self.dispatch(kind, named, &class_desc, &name, &signature, args, receiver, site)
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
        kind: InvokeKind,
        named: Option<ClassId>,
        class_desc: &str,
        name: &str,
        signature: &str,
        args: Vec<Value>,
        receiver: Option<Value>,
        site: &Site,
    ) -> ExecResult<Flow> {
        // `invoke-super` resolves from the *superclass* of the named class, which
        // is what lets a subclass call `super.onCreate` without recursing into
        // itself.
        let lookup_class = match kind {
            InvokeKind::Super => {
                named.and_then(|c| self.program.class(c).and_then(|m| m.superclass))
            }
            _ => named,
        };

        let target: Option<MethodDecl> = match (kind, receiver) {
            (InvokeKind::Virtual | InvokeKind::Interface, Some(Value::Ref(r))) => {
                let rc = self.class_id_of_object(Value::Ref(r));
                let found = rc.and_then(|c| self.vtable_target(c, name, signature));
                if found.is_none() {
                    if let Some(c) = rc {
                        if self.has_bytecode(c) {
                            return Ok(Flow::Thrown(self.new_throwable(
                                "Ljava/lang/NoSuchMethodError;",
                                format!(
                                    "{class_desc}.{name}{signature} is not implemented by {}",
                                    self.class_name(c)
                                ),
                            )?));
                        }
                    }
                }
                found
            }
            (InvokeKind::Direct, _) => lookup_class
                .and_then(|c| self.program.find_own_method(c, name, signature).cloned()),
            _ => lookup_class.and_then(|c| self.program.find_method(c, name, signature).cloned()),
        };

        match target {
            Some(decl) if decl.has_code() => {
                if let Some(f) = self.frames.last_mut() {
                    f.result = None;
                }
                self.push_frame(&decl, &args)?;
                Ok(Flow::Call)
            }
            Some(_) => {
                // Declared with no body: abstract, native, or on a class with no
                // bytecode. All three are the shim's problem, and the same
                // problem, so they take the same path.
                self.call_host(kind, class_desc, name, signature, &args, site)
            }
            None => {
                if let Some(n) = named {
                    if self.has_bytecode(n) {
                        // The file declares the class but not the method. On a
                        // device that is a `NoSuchMethodError` at first use, and
                        // apps detect optional dependencies by catching exactly
                        // that, so it has to be a real throwable rather than a
                        // lookup failure.
                        return Ok(Flow::Thrown(self.new_throwable(
                            "Ljava/lang/NoSuchMethodError;",
                            format!("{} does not declare {name}{signature}", self.class_name(n)),
                        )?));
                    }
                }
                self.call_host(kind, class_desc, name, signature, &args, site)
            }
        }
    }

    fn has_bytecode(&self, c: ClassId) -> bool {
        self.program.class(c).map(|m| m.source.has_bytecode()).unwrap_or(false)
    }

    /// The vtable entry's target: a concrete declaration, or `None` when the slot
    /// is abstract or absent.
    fn vtable_target(&self, class: ClassId, name: &str, signature: &str) -> Option<MethodDecl> {
        match self.program.vtable_lookup(class, name, signature)? {
            VTableEntry::Concrete { method_idx } => self.program.decl(*method_idx).cloned(),
            VTableEntry::Abstract { .. } => None,
        }
    }

    /// Hand a call the engine cannot execute to the shim.
    fn call_host(
        &mut self,
        kind: InvokeKind,
        class: &str,
        name: &str,
        signature: &str,
        args: &[Value],
        site: &Site,
    ) -> ExecResult<Flow> {
        self.stats.framework_calls += 1;
        let call = Call { class, name, signature, kind, args };
        let outcome = self.host.invoke(&call);
        self.record_call(&call, &outcome);
        match outcome {
            HostOutcome::Value(v) => {
                let m = self.materialise(v)?;
                self.set_result(m);
                Ok(Flow::Next)
            }
            HostOutcome::NotImplemented => {
                self.stats.framework_calls_unimplemented += 1;
                let (_, ret) = JType::parse_prototype(signature);
                let zero = Value::default_for(&ret).unwrap_or(Value::Null);
                self.set_result(zero);
                let _ = site;
                Ok(Flow::Next)
            }
            HostOutcome::Throw(spec) => {
                let exc = self.raise(spec, site)?;
                Ok(Flow::Thrown(exc))
            }
        }
    }

    fn record_call(&mut self, call: &Call<'_>, outcome: &HostOutcome) {
        if !self.config.record_shim_log || self.stats.shim_log.len() >= self.config.max_shim_log {
            return;
        }
        self.stats.shim_log.push(ShimRecord {
            class: call.class.to_string(),
            name: call.name.to_string(),
            signature: call.signature.to_string(),
            kind: call.kind.as_str(),
            args: call.args.to_vec(),
            implemented: !matches!(outcome, HostOutcome::NotImplemented),
        });
    }

    /// `invoke-custom`: resolve the call site, then dispatch its target.
    ///
    /// The resolution chain is decoded in full before anything is reported, so the
    /// failure names the bootstrap method, its defining class, and whether that
    /// class is in the file. "The file has no `call_site_ids`", "the bootstrap's
    /// class is not in this dex" and "the bootstrap is here but the shim declined
    /// to resolve it" are three different results and the study needs all three.
    fn do_invoke_custom(&mut self, regs: &[u8], call_site_idx: u32, site: &Site) -> ExecResult<Flow> {
        let call_site = self.program.call_site(call_site_idx)?;
        let handle = &call_site.handle;
        let (bootstrap_owner, bootstrap_name, bootstrap_sig) = match handle.method_idx {
            Some(m) => match self.program.methods.get(m as usize) {
                Some((c, n, s)) => (c.clone(), n.clone(), s.clone()),
                None => {
                    return Err(ExecError::Unsupported {
                        kind: Unsupported::BootstrapMethodMissing,
                        detail: format!(
                            "call_site@{call_site_idx}: its method handle names method@{m}, \
                             which does not exist"
                        ),
                        site: site.clone(),
                    })
                }
            },
            None => (String::new(), String::new(), String::new()),
        };
        let mut args = Vec::with_capacity(regs.len());
        for r in regs {
            args.push(self.gv(*r as usize, site)?);
        }
        let mut arguments: Vec<Value> = Vec::with_capacity(call_site.arguments.len());
        for e in call_site.arguments.iter() {
            arguments.push(self.materialise_encoded(e)?);
        }

        let site_info = CallSite {
            index: call_site_idx,
            method_handle_type: handle.kind,
            bootstrap_owner: &bootstrap_owner,
            bootstrap_name: &bootstrap_name,
            bootstrap_signature: &bootstrap_sig,
            arguments: &arguments,
        };
        let resolved = match self.host.resolve_call_site(&site_info) {
            Some(r) => r,
            None => {
                let owner_known = !bootstrap_owner.is_empty()
                    && self.program.by_descriptor.contains_key(&bootstrap_owner);
                let handle_desc = match handle.field_idx {
                    Some(f) => self
                        .program
                        .fields
                        .get(f as usize)
                        .map(|(c, n, t)| format!("{c}.{n}:{t}"))
                        .unwrap_or_else(|| format!("field@{f}")),
                    None => match handle.method_idx {
                        Some(m) => format!("method@{m}"),
                        None => "an unreadable handle".to_string(),
                    },
                };
                return Err(ExecError::Unsupported {
                    kind: if owner_known {
                        Unsupported::CallSiteUnresolved
                    } else {
                        Unsupported::BootstrapMethodMissing
                    },
                    detail: format!(
                        "call_site@{call_site_idx}: bootstrap handle {handle_desc} names \
                         {bootstrap_owner}.{bootstrap_name}{bootstrap_sig}; that class is {} \
                         this dex, and the host resolved no call site. {} bootstrap argument(s).",
                        if owner_known { "present in" } else { "NOT present in" },
                        arguments.len()
                    ),
                    site: site.clone(),
                });
            }
        };

        let class_desc = resolved.class.clone().unwrap_or_default();
        let named = self.class_id_known(&class_desc);
        self.stats.framework_calls += 1;
        self.dispatch(
            resolved.kind,
            named,
            &class_desc,
            &resolved.name,
            &resolved.signature,
            args,
            None,
            site,
        )
    }

    // ================================================================ fields

    fn iget(&mut self, _op: u8, a: usize, b: usize, field_idx: u32, site: &Site) -> ExecResult<()> {
        let (class_desc, name, ty) = self.field_ref(field_idx, site)?;
        let declared = JType::parse(&ty);
        let r = match self.gr(b, site)? {
            None => {
                let exc = self.new_throwable(
                    "Ljava/lang/NullPointerException;",
                    format!("iget {class_desc}.{name} on a null reference"),
                )?;
                self.pending_throw = Some(exc);
                return Ok(());
            }
            Some(r) => r,
        };
        if !self.field_is_dex_backed(field_idx) {
            // A field declared on a class with no bytecode has no slot in any
            // object, so it belongs to the host. An app reading
            // `WindowManager.LayoutParams.screenBrightness` is reading a field
            // this substrate does not have.
            self.stats.framework_field_accesses += 1;
            let access = FieldAccess {
                class: &class_desc,
                name: &name,
                ty: &ty,
                target: Some(Value::Ref(r)),
            };
            match self.host.get_field(&access) {
                HostOutcome::Value(v) => {
                    let v = self.materialise(v)?;
                    self.write_field(a, v)?;
                }
                HostOutcome::NotImplemented => {
                    self.write_field(a, Value::default_for(&declared).unwrap_or(Value::Null))?;
                }
                HostOutcome::Throw(spec) => {
                    let exc = self.raise(spec, site)?;
                    self.pending_throw = Some(exc);
                }
            }
            return Ok(());
        }
        let offset = match self.instance_offset(field_idx) {
            Some(o) => o,
            None => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: format!("{class_desc} has no instance field {name}:{ty}"),
                    site: site.clone(),
                })
            }
        };
        let v = self.read_instance_field(Value::Ref(r), offset, &declared, site)?;
        self.write_field(a, v)
    }

    fn iput(&mut self, _op: u8, a: usize, b: usize, field_idx: u32, site: &Site) -> ExecResult<()> {
        let (class_desc, name, ty) = self.field_ref(field_idx, site)?;
        let declared = JType::parse(&ty);
        let value = self.gv(a, site)?;
        let r = match self.gr(b, site)? {
            None => {
                let exc = self.new_throwable(
                    "Ljava/lang/NullPointerException;",
                    format!("iput {class_desc}.{name} on a null reference"),
                )?;
                self.pending_throw = Some(exc);
                return Ok(());
            }
            Some(r) => r,
        };
        if !self.field_is_dex_backed(field_idx) {
            self.stats.framework_field_accesses += 1;
            let access = FieldAccess {
                class: &class_desc,
                name: &name,
                ty: &ty,
                target: Some(Value::Ref(r)),
            };
            let hv = self.to_host_value(value);
            if let HostOutcome::Throw(spec) = self.host.set_field(&access, hv) {
                let exc = self.raise(spec, site)?;
                self.pending_throw = Some(exc);
            }
            return Ok(());
        }
        let offset = match self.instance_offset(field_idx) {
            Some(o) => o,
            None => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: format!("{class_desc} has no instance field {name}:{ty}"),
                    site: site.clone(),
                })
            }
        };
        self.write_instance_field(Value::Ref(r), offset, &declared, value)
    }

    fn sget(&mut self, _op: u8, a: usize, field_idx: u32, site: &Site) -> ExecResult<()> {
        let (class_desc, name, ty) = self.field_ref(field_idx, site)?;
        let declared = JType::parse(&ty);
        if !self.field_is_dex_backed(field_idx) {
            self.stats.framework_field_accesses += 1;
            let access = FieldAccess { class: &class_desc, name: &name, ty: &ty, target: None };
            match self.host.get_field(&access) {
                HostOutcome::Value(v) => {
                    let v = self.materialise(v)?;
                    self.write_field(a, v)?;
                }
                HostOutcome::NotImplemented => {
                    self.write_field(a, Value::default_for(&declared).unwrap_or(Value::Null))?;
                }
                HostOutcome::Throw(spec) => {
                    let exc = self.raise(spec, site)?;
                    self.pending_throw = Some(exc);
                }
            }
            return Ok(());
        }
        let owner = self.field_owner(field_idx);
        let v = self.read_static(owner, field_idx, &declared)?;
        self.write_field(a, v)
    }

    fn sput(&mut self, _op: u8, a: usize, field_idx: u32, site: &Site) -> ExecResult<()> {
        let (class_desc, name, ty) = self.field_ref(field_idx, site)?;
        let declared = JType::parse(&ty);
        let value = self.gv(a, site)?;
        if !self.field_is_dex_backed(field_idx) {
            self.stats.framework_field_accesses += 1;
            let access = FieldAccess { class: &class_desc, name: &name, ty: &ty, target: None };
            let hv = self.to_host_value(value);
            if let HostOutcome::Throw(spec) = self.host.set_field(&access, hv) {
                let exc = self.raise(spec, site)?;
                self.pending_throw = Some(exc);
            }
            return Ok(());
        }
        let owner = self.field_owner(field_idx);
        self.write_static(owner, field_idx, value, &declared)
    }

    fn field_ref(&self, field_idx: u32, site: &Site) -> ExecResult<(String, String, String)> {
        self.program
            .fields
            .get(field_idx as usize)
            .cloned()
            .ok_or_else(|| ExecError::Malformed {
                kind: Malformed::BadPoolIndex,
                detail: format!("field reference {field_idx} does not exist"),
                site: site.clone(),
            })
    }

    /// The class a `field_ids` entry names, which is by definition the
    /// *declaring* class — so field shadowing needs no special handling.
    fn field_owner(&self, field_idx: u32) -> Option<ClassId> {
        self.program
            .fields
            .get(field_idx as usize)
            .and_then(|(c, _, _)| self.program.by_descriptor.get(c).copied())
    }

    fn field_is_dex_backed(&self, field_idx: u32) -> bool {
        match self.field_owner(field_idx) {
            Some(c) => self.has_bytecode(c),
            None => false,
        }
    }

    fn instance_offset(&self, field_idx: u32) -> Option<usize> {
        let owner = self.field_owner(field_idx)?;
        self.program.instance_field_offset(owner, field_idx).map(|(o, _)| o)
    }

    fn instance_offset_for(&self, class: &str, name: &str, ty: &str) -> ExecResult<usize> {
        let idx = self.field_index(class, name, ty)?;
        let owner = self.class_id_known(class);
        owner
            .and_then(|c| self.program.instance_field_offset(c, idx))
            .map(|(o, _)| o)
            .ok_or_else(|| ExecError::Malformed {
                kind: Malformed::TypeMismatch,
                detail: format!("{class} has no instance field {name}:{ty}"),
                site: Site::default(),
            })
    }

    fn field_index(&self, class: &str, name: &str, ty: &str) -> ExecResult<u32> {
        self.program
            .fields
            .iter()
            .position(|(c, n, t)| c == class && n == name && t == ty)
            .map(|i| i as u32)
            .ok_or_else(|| ExecError::Malformed {
                kind: Malformed::BadPoolIndex,
                detail: format!("no field_ids entry for {class}.{name}:{ty}"),
                site: Site::default(),
            })
    }

    fn write_field(&mut self, a: usize, v: Value) -> ExecResult<()> {
        if matches!(v, Value::Long(_) | Value::Double(_)) {
            self.set_wide(a, v)
        } else {
            self.sv(a, v)
        }
    }

    fn read_instance_field(
        &self,
        obj: Value,
        offset: usize,
        ty: &JType,
        site: &Site,
    ) -> ExecResult<Value> {
        let r = match obj {
            Value::Ref(r) => r,
            _ => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: "instance field read on a non-reference".to_string(),
                    site: site.clone(),
                })
            }
        };
        let obj = self.heap.get(r).ok_or_else(|| ExecError::Malformed {
            kind: Malformed::TypeMismatch,
            detail: format!("reference {r} does not point at an object"),
            site: site.clone(),
        })?;
        let v = match &obj.kind {
            ObjectKind::Instance { fields } => fields.get(offset).copied(),
            _ => None,
        };
        let v = v.ok_or_else(|| ExecError::Malformed {
            kind: Malformed::TypeMismatch,
            detail: format!("field slot {offset} is outside the object's layout"),
            site: site.clone(),
        })?;
        Ok(ops::coerce_to(v, ty))
    }

    fn write_instance_field(
        &mut self,
        obj: Value,
        offset: usize,
        ty: &JType,
        value: Value,
    ) -> ExecResult<()> {
        let r = match obj {
            Value::Ref(r) => r,
            _ => return Ok(()),
        };
        let v = ops::coerce_to(value, ty);
        let wide = matches!(v, Value::Long(_) | Value::Double(_));
        if let Some(o) = self.heap.get_mut(r) {
            if let ObjectKind::Instance { fields } = &mut o.kind {
                if let Some(t) = fields.get_mut(offset) {
                    *t = v;
                }
                if wide {
                    if let Some(t) = fields.get_mut(offset + 1) {
                        *t = Value::WidePad;
                    }
                }
            }
        }
        Ok(())
    }

    fn read_static(
        &mut self,
        owner: Option<ClassId>,
        field_idx: u32,
        declared: &JType,
    ) -> ExecResult<Value> {
        let id = match owner {
            Some(id) => id,
            None => return Ok(Value::default_for(declared).unwrap_or(Value::Null)),
        };
        if let Some(v) = self.statics.get(&(id, field_idx)) {
            return Ok(*v);
        }
        // Not yet materialised: decode the `encoded_array` entry, then cache.
        // Every `R` class is reached through this path on its first `sget`, and
        // an `R` class is nothing but constants.
        let encoded = self
            .program
            .class(id)
            .and_then(|m| m.static_defaults.get(&field_idx))
            .cloned();
        let value = match encoded {
            Some(e) => self
                .materialise_encoded(&e)
                .unwrap_or_else(|_| Value::default_for(declared).unwrap_or(Value::Null)),
            None => Value::default_for(declared).unwrap_or(Value::Null),
        };
        let value = ops::coerce_to(value, declared);
        self.statics.insert((id, field_idx), value);
        Ok(value)
    }

    fn write_static(
        &mut self,
        owner: Option<ClassId>,
        field_idx: u32,
        value: Value,
        declared: &JType,
    ) -> ExecResult<()> {
        if let Some(id) = owner {
            self.statics.insert((id, field_idx), ops::coerce_to(value, declared));
        }
        Ok(())
    }

    // ================================================================ arrays

    fn array_get(&self, op: u8, arr: Value, index: i32) -> ArrayOp {
        let r = match arr {
            Value::Ref(r) => r,
            Value::Null => return ArrayOp::Fault(ArrayFault::NullArray),
            _ => return ArrayOp::Fault(ArrayFault::NotAnArray),
        };
        let (component, elements) = match self.heap.get(r).map(|o| &o.kind) {
            Some(ObjectKind::Array { component, elements }) => (component, elements),
            _ => return ArrayOp::Fault(ArrayFault::NotAnArray),
        };
        let len = elements.len();
        let at = match checked_index(index, len) {
            Some(i) => i,
            None => return ArrayOp::Fault(ArrayFault::Index(index, len as i32)),
        };
        let raw = match elements.get(at) {
            Some(v) => *v,
            None => return ArrayOp::Fault(ArrayFault::Index(index, len as i32)),
        };
        ArrayOp::Done(ops::narrow_on_load(op, raw, component))
    }

    fn array_put(&mut self, op: u8, arr: Value, index: i32, value: Value) -> ArrayOp {
        let r = match arr {
            Value::Ref(r) => r,
            Value::Null => return ArrayOp::Fault(ArrayFault::NullArray),
            _ => return ArrayOp::Fault(ArrayFault::NotAnArray),
        };
        let (component, len) = match self.heap.get(r).map(|o| &o.kind) {
            Some(ObjectKind::Array { component, elements }) => (component.clone(), elements.len()),
            _ => return ArrayOp::Fault(ArrayFault::NotAnArray),
        };
        let at = match checked_index(index, len) {
            Some(i) => i,
            None => return ArrayOp::Fault(ArrayFault::Index(index, len as i32)),
        };
        let narrowed = match ops::narrow_on_store(op, value, &component) {
            Some(v) => v,
            None => return ArrayOp::Fault(ArrayFault::Store),
        };
        if let Some(ObjectKind::Array { elements, .. }) = self.heap.get_mut(r).map(|o| &mut o.kind) {
            if let Some(slot) = elements.get_mut(at) {
                *slot = narrowed;
            }
        }
        ArrayOp::Done(Value::Null)
    }

    /// Fill an array from a `fill-array-data` payload.
    ///
    /// The payload's `element_width` must match the array's component type: a
    /// mismatch is a malformed file, not a silently mis-parsed array.
    fn fill_array(
        &mut self,
        arr: Value,
        fill: &FillArrayData,
    ) -> ExecResult<Option<Flow>> {
        let r = match arr {
            Value::Ref(r) => r,
            Value::Null => {
                let exc =
                    self.new_throwable("Ljava/lang/NullPointerException;", "fill-array-data on null")?;
                return Ok(Some(Flow::Thrown(exc)));
            }
            _ => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: "fill-array-data on a non-array".to_string(),
                    site: self.site(),
                })
            }
        };
        let (component, len) = match self.heap.get(r).map(|o| &o.kind) {
            Some(ObjectKind::Array { component, elements }) => (component.clone(), elements.len()),
            _ => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: format!("fill-array-data on {}", self.describe(r)),
                    site: self.site(),
                })
            }
        };
        let declared = component.element_width();
        if declared != 0 && declared != fill.element_width {
            return Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!(
                    "fill-array-data payload has element_width {} but the array's component \
                     type {} is {declared} bytes",
                    fill.element_width,
                    component.descriptor()
                ),
                site: self.site(),
            });
        }
        let count = fill.size as usize;
        if count > len {
            return Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!(
                    "fill-array-data payload has {count} elements, the array has {len}"
                ),
                site: self.site(),
            });
        }
        let width = fill.element_width as usize;
        if width == 0 || fill.data.len() < count.saturating_mul(width) {
            return Err(ExecError::Malformed {
                kind: Malformed::BadPayload,
                detail: format!(
                    "fill-array-data payload is {} bytes; {count} elements of {width} need {}",
                    fill.data.len(),
                    count.saturating_mul(width)
                ),
                site: self.site(),
            });
        }
        let mut values: Vec<Value> = Vec::with_capacity(count);
        for i in 0..count {
            let at = i * width;
            let bytes = fill.data.get(at..at + width);
            let v = match (&component, bytes) {
                (JType::Boolean, Some(b)) => {
                    Value::Int(i32::from(b.first().copied().unwrap_or(0) != 0))
                }
                (JType::Byte, Some(b)) => Value::Int(i32::from(b.first().copied().unwrap_or(0) as i8)),
                (JType::Short, Some(b)) => Value::Int(i32::from(ops::read_i16(b))),
                (JType::Char, Some(b)) => Value::Int(i32::from(ops::read_u16(b))),
                (JType::Int, Some(b)) => Value::Int(ops::read_i32(b)),
                (JType::Long, Some(b)) => Value::Long(ops::read_i64(b)),
                (JType::Float, Some(b)) => Value::Float(f32::from_bits(ops::read_u32(b))),
                (JType::Double, Some(b)) => Value::Double(f64::from_bits(ops::read_u64(b))),
                // A reference array is filled with nulls; the payload's bytes are
                // ignored, exactly as ART ignores them.
                _ => Value::Null,
            };
            values.push(v);
        }
        if let Some(ObjectKind::Array { elements, .. }) = self.heap.get_mut(r).map(|o| &mut o.kind) {
            for (slot, v) in elements.iter_mut().zip(values) {
                *slot = v;
            }
        }
        Ok(None)
    }

    fn array_throwable(&mut self, f: ArrayFault, site: &Site) -> ExecResult<Flow> {
        let exc = match f {
            ArrayFault::NullArray => {
                self.new_throwable("Ljava/lang/NullPointerException;", "array access on null")?
            }
            ArrayFault::Index(i, len) => self.new_throwable(
                "Ljava/lang/ArrayIndexOutOfBoundsException;",
                format!("index {i} out of bounds for length {len}"),
            )?,
            ArrayFault::Store => {
                self.new_throwable("Ljava/lang/ArrayStoreException;", "incompatible value")?
            }
            ArrayFault::NotAnArray => {
                return Err(ExecError::Malformed {
                    kind: Malformed::TypeMismatch,
                    detail: "array access on a non-array".to_string(),
                    site: site.clone(),
                })
            }
        };
        Ok(Flow::Thrown(exc))
    }

    fn filled_new_array(&mut self, component: &str, regs: &[u8], site: &Site) -> ExecResult<Value> {
        let ty = JType::parse(component);
        let mut elements = Vec::with_capacity(regs.len());
        for r in regs {
            let v = self.gv(*r as usize, site)?;
            if !ops::value_fits(&ty, v) {
                // A verifier-valid `filled-new-array` never mixes shapes, so this
                // is only reachable from a file ART would have refused. It is
                // reported as a catchable `ArrayStoreException` rather than
                // silently truncating the value into the array.
                let exc = self.new_throwable(
                    "Ljava/lang/ArrayStoreException;",
                    format!("filled-new-array of {component} with an incompatible value"),
                )?;
                self.pending_throw = Some(exc);
                return Ok(Value::Null);
            }
            elements.push(v);
        }
        let class_id = self.array_class(component)?;
        let r = self.alloc(class_id, ObjectKind::Array { component: ty, elements }, None)?;
        Ok(Value::Ref(r))
    }

    /// The class for `[component`, fabricated on demand.
    ///
    /// There is no bound on the number of array types a file can name — one per
    /// component type in the file, plus every multi-dimensional combination — so
    /// they are created as they are reached rather than enumerated. They are not
    /// counted as phantom classes, because `new-array` on a type the app named
    /// itself is not a substrate gap.
    fn array_class(&mut self, component: &str) -> ExecResult<ClassId> {
        // `component` is an element descriptor; the class is `[component`.
        let array_descriptor = format!("[{component}");
        self.program.class_for(&array_descriptor, true).ok_or_else(|| {
            ExecError::Unsupported {
                kind: Unsupported::ClassNotFound,
                detail: format!("no class for array type {array_descriptor}"),
                site: self.site(),
            }
        })
    }

    /// Resolve a descriptor for a *type test* (`instance-of`, `check-cast`,
    /// `is_instance_of`).
    ///
    /// Array types are created on demand because an app's own array types are
    /// not substrate gaps; every other class must already be known, and an
    /// unknown one means the test cannot be answered rather than that it fails.
    fn class_id_for_test(&mut self, descriptor: &str) -> Option<ClassId> {
        if let Some(&id) = self.program.by_descriptor.get(descriptor) {
            return Some(id);
        }
        if descriptor.starts_with('[') {
            return self.program.class_for(descriptor, true);
        }
        None
    }

    // ============================================================ exceptions

    /// Allocate a throwable of `class`, with a message.
    ///
    /// `Throwable.detailMessage` is a field in `core.jar`, not in this dex, so
    /// the message is kept on the object rather than in a field slot. A shim that
    /// wants the field answers `get_field` for it; the engine only needs it for
    /// the error text.
    pub(crate) fn new_throwable(
        &mut self,
        class: &'static str,
        message: impl Into<String>,
    ) -> ExecResult<Value> {
        // The counter is bumped in `new_throwable_opt`, which is the one place a
        // throwable is actually allocated; bumping it here too counted every
        // shim-raised exception twice.
        let message = message.into();
        let spec =
            if message.is_empty() { None } else { Some(message) };
        self.new_throwable_opt(class, spec)
    }
    fn new_throwable_opt(&mut self, class: &'static str, message: Option<String>) -> ExecResult<Value> {
        self.stats.vm_exceptions += 1;
        // `class_id_for`, not `class_id_known`: a throwable the substrate raises
        // has to exist as a class. Falling back to class 0 would give the object
        // no hierarchy at all, and then a `catch (Error)` clause four levels up
        // would not match it -- the clause would look wrong when the throwable
        // is what is missing.
        let class_id = self.class_id_for(class).unwrap_or(ClassId(0));
        let slots = self.program.class(class_id).map(|m| m.instance_slots).unwrap_or(0);
        let mut fields = vec![Value::Uninit; slots];
        self.init_instance_fields(class_id, 0, &mut fields)?;
        let r = self.alloc(class_id, ObjectKind::Instance { fields }, message)?;
        Ok(Value::Ref(r))
    }

    /// Allocate a throwable the shim asked for.
    fn raise(&mut self, spec: ThrowSpec, _site: &Site) -> ExecResult<Value> {
        self.new_throwable_opt(spec.class, spec.message)
    }

    // ============================================================== monitors

    fn monitor_enter(&mut self, a: usize, site: &Site) -> ExecResult<Flow> {
        let r = match self.gv(a, site)? {
            Value::Ref(r) => r,
            Value::Null => {
                return Ok(Flow::Thrown(self.new_throwable(
                    "Ljava/lang/NullPointerException;",
                    "monitor-enter on null",
                )?))
            }
            other => {
                return Err(self.wrong_type(
                    crate::value::WrongType {
                        expected: "reference",
                        found: other.type_name(),
                        what: "monitor-enter",
                    },
                    site,
                ))
            }
        };
        if let Some(obj) = self.heap.get_mut(r) {
            let mut m = obj.monitor;
            m.enter();
            obj.monitor = m;
        }
        if let Some(f) = self.frames.last_mut() {
            f.held.push(r);
        }
        Ok(Flow::Next)
    }

    fn monitor_exit(&mut self, a: usize, site: &Site) -> ExecResult<Flow> {
        let r = match self.gv(a, site)? {
            Value::Ref(r) => r,
            Value::Null => {
                return Ok(Flow::Thrown(self.new_throwable(
                    "Ljava/lang/NullPointerException;",
                    "monitor-exit on null",
                )?))
            }
            other => {
                return Err(self.wrong_type(
                    crate::value::WrongType {
                        expected: "reference",
                        found: other.type_name(),
                        what: "monitor-exit",
                    },
                    site,
                ))
            }
        };
        // Reentrant, so the innermost hold is what an exit releases. An
        // unbalanced exit is reported as `Malformed` rather than ignored: see
        // `heap::Monitor` for why it is not an `IllegalMonitorStateException`.
        let held = self
            .frames
            .last()
            .map(|f| f.held.last().copied() == Some(r))
            .unwrap_or(false);
        if !held {
            return Err(ExecError::Malformed {
                kind: Malformed::TypeMismatch,
                detail: format!(
                    "monitor-exit on {} which this frame does not hold",
                    self.describe(r)
                ),
                site: site.clone(),
            });
        }
        if let Some(obj) = self.heap.get_mut(r) {
            let mut m = obj.monitor;
            m.exit();
            obj.monitor = m;
        }
        if let Some(f) = self.frames.last_mut() {
            f.held.pop();
        }
        Ok(Flow::Next)
    }

    // =============================================================== classes

    /// Resolve a descriptor to a class *without* fabricating one. Used where a
    /// missing class means "cannot check" rather than "must fail".
    fn class_id_known(&self, descriptor: &str) -> Option<ClassId> {
        self.program.by_descriptor.get(descriptor).copied()
    }

    /// Resolve a descriptor, fabricating a phantom if the configuration allows it
    /// and recording the fact.
    fn class_id_for(&mut self, descriptor: &str) -> Option<ClassId> {
        if let Some(&id) = self.program.by_descriptor.get(descriptor) {
            return Some(id);
        }
        let host_knows = self.host.class_known(descriptor);
        if !self.config.phantom_classes && !host_knows {
            return None;
        }
        let id = self.program.class_for(descriptor, true)?;
        self.note_phantom(descriptor, id);
        Some(id)
    }

    fn note_phantom(&mut self, descriptor: &str, id: ClassId) {
        if self.program.class(id).map(|m| m.source) == Some(ClassSource::Phantom)
            && !self.stats.phantom_classes.iter().any(|d| d == descriptor)
        {
            self.stats.phantom_classes.push(descriptor.to_string());
            self.stats.phantom_classes.sort();
            self.stats.phantom_classes.dedup();
        }
    }

    fn class_name(&self, id: ClassId) -> String {
        self.program
            .class(id)
            .map(|m| m.descriptor.clone())
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    fn class_id_of_object(&self, v: Value) -> Option<ClassId> {
        match v {
            Value::Ref(r) => self.heap.get(r).map(|o| o.class),
            _ => None,
        }
    }

    fn describe(&self, r: Ref) -> String {
        match self.heap.get(r) {
            Some(o) => format!("an instance of {}", self.class_name(o.class)),
            None => "a stale reference".to_string(),
        }
    }

    // =============================================================== objects

    fn new_instance(&mut self, descriptor: &str) -> ExecResult<Value> {
        let class = match self.class_id_for(descriptor) {
            Some(c) => c,
            None => {
                return Err(ExecError::Unsupported {
                    kind: Unsupported::ClassNotFound,
                    detail: format!(
                        "new-instance {descriptor}: the class is in neither this dex nor the \
                         builtin table, and phantom classes are disabled"
                    ),
                    site: self.site(),
                })
            }
        };
        let slots = self.program.class(class).map(|m| m.instance_slots).unwrap_or(0);
        let mut fields = vec![Value::Uninit; slots];
        self.init_instance_fields(class, 0, &mut fields)?;
        let r = self.alloc(class, ObjectKind::Instance { fields }, None)?;
        Ok(Value::Ref(r))
    }

    /// Fill an object's fields with their declared zero values, superclass
    /// first.
    ///
    /// The verifier guarantees `new-instance` is followed by `<init>`, which is
    /// where ART inserts the field zeroing. Doing it here means an object is
    /// readable before its constructor runs, which is what a harness needs when
    /// it builds an `Activity` itself.
    fn init_instance_fields(
        &mut self,
        class: ClassId,
        base: usize,
        fields: &mut [Value],
    ) -> ExecResult<()> {
        let (sup, sup_slots, own) = match self.program.class(class) {
            Some(m) => (
                m.superclass,
                m.superclass
                    .and_then(|s| self.program.class(s))
                    .map(|p| p.instance_slots)
                    .unwrap_or(0),
                m.instance_fields.clone(),
            ),
            None => (None, 0, Vec::new()),
        };
        if let Some(s) = sup {
            self.init_instance_fields(s, base, fields)?;
        }
        let mut at = base + sup_slots;
        for f in own {
            let zero = Value::default_for(&f.ty).unwrap_or(Value::Null);
            if let Some(t) = fields.get_mut(at) {
                *t = zero;
            }
            if f.slots == 2 {
                if let Some(t) = fields.get_mut(at + 1) {
                    *t = Value::WidePad;
                }
            }
            at += f.slots;
        }
        Ok(())
    }

    fn new_array(&mut self, array_descriptor: &str, len: usize) -> ExecResult<Value> {
        // `new-array` names the *array* type, but the array's own type is its
        // element type: `[[I` is an array of `int[]`, and the element width
        // `aput` compares against is the inner one. Storing the array
        // descriptor here would make every `aput-byte` look like a store of the
        // wrong shape.
        let ty = JType::parse(&component_descriptor(array_descriptor));
        // A multi-dimensional array is an array of arrays; the elements are
        // `null` until the app fills them in with `new-array`.
        let elements: Vec<Value> =
            (0..len).map(|_| Value::default_for(&ty).unwrap_or(Value::Null)).collect();
        let class_id = self.array_class(array_descriptor)?;
        let r = self.alloc(class_id, ObjectKind::Array { component: ty, elements }, None)?;
        Ok(Value::Ref(r))
    }

    // ================================================================== shim

    /// Turn a [`Value`] into the [`HostValue`] a shim recognises.
    fn to_host_value(&self, v: Value) -> HostValue {
        match v {
            Value::Int(i) => HostValue::Int(i),
            Value::Long(l) => HostValue::Long(l),
            Value::Float(f) => HostValue::Float(f),
            Value::Double(d) => HostValue::Double(d),
            Value::Null => HostValue::Null,
            Value::Ref(r) => match self.heap.get(r).map(|o| &o.kind) {
                Some(ObjectKind::Str { text }) => HostValue::Str(text.clone()),
                Some(ObjectKind::Class { descriptor }) => HostValue::Class(descriptor.clone()),
                Some(ObjectKind::Array { component, elements }) => HostValue::Array {
                    component: component.descriptor(),
                    items: elements.iter().map(|e| self.to_host_value(*e)).collect(),
                },
                Some(ObjectKind::Instance { .. }) => {
                    HostValue::Opaque { class: self.class_name_of(r), key: format!("id:{r}") }
                }
                _ => HostValue::Ref(v),
            },
            Value::Uninit | Value::Void | Value::WidePad => HostValue::Null,
        }
    }

    fn class_name_of(&self, r: Ref) -> String {
        match self.heap.get(r) {
            Some(o) => self.class_name(o.class),
            None => "Ljava/lang/Object;".to_string(),
        }
    }

    /// Materialise a value the host described, allocating if necessary.
    fn materialise(&mut self, v: HostValue) -> ExecResult<Value> {
        match v {
            HostValue::Null => Ok(Value::Null),
            HostValue::Int(i) => Ok(Value::Int(i)),
            HostValue::Long(l) => Ok(Value::Long(l)),
            HostValue::Float(f) => Ok(Value::Float(f)),
            HostValue::Double(d) => Ok(Value::Double(d)),
            HostValue::Str(s) => self.new_string_value(s),
            HostValue::Class(s) => self.new_class_value(&s),
            HostValue::MethodType(s) => self.new_method_type(&s),
            HostValue::Ref(v) => Ok(v),
            HostValue::Opaque { class, key } => {
                // A shim that returns the same `(class, key)` twice gets the
                // same object, which is what makes `getWindow()` then
                // `getAttributes()` expressible without the shim holding a heap
                // handle.
                if let Some(&r) = self.opaque.get(&(class.clone(), key.clone())) {
                    return Ok(Value::Ref(r));
                }
                let class_id = match self.class_id_for(&class) {
                    Some(c) => c,
                    None => {
                        return Err(ExecError::Unsupported {
                            kind: Unsupported::ClassNotFound,
                            detail: format!("the shim returned an instance of unknown class {class}"),
                            site: self.site(),
                        })
                    }
                };
                let slots = self.program.class(class_id).map(|m| m.instance_slots).unwrap_or(0);
                let mut fields = vec![Value::Uninit; slots];
                self.init_instance_fields(class_id, 0, &mut fields)?;
                let r = self.alloc(class_id, ObjectKind::Instance { fields }, None)?;
                self.opaque.insert((class, key), r);
                Ok(Value::Ref(r))
            }
            HostValue::Array { component, items } => {
                let mut elements = Vec::with_capacity(items.len());
                for it in items {
                    elements.push(self.materialise(it)?);
                }
                let class_id = self.array_class(&component)?;
                let ty = JType::parse(&component);
                let r = self.alloc(class_id, ObjectKind::Array { component: ty, elements }, None)?;
                Ok(Value::Ref(r))
            }
        }
    }

    /// Materialise a constant-pool value.
    fn materialise_encoded(&mut self, e: &EncodedValue) -> ExecResult<Value> {
        Ok(match e {
            EncodedValue::Byte(b) => Value::Int(i32::from(*b)),
            EncodedValue::Short(s) => Value::Int(i32::from(*s)),
            EncodedValue::Char(c) => Value::Int(i32::from(*c)),
            EncodedValue::Int(i) => Value::Int(*i),
            EncodedValue::Long(l) => Value::Long(*l),
            EncodedValue::Float(f) => Value::Float(*f),
            EncodedValue::Double(d) => Value::Double(*d),
            EncodedValue::Boolean(b) => Value::Int(i32::from(*b)),
            EncodedValue::Null => Value::Null,
            EncodedValue::String(i) => {
                let text = self.string_at(*i, &Site::default())?;
                self.new_string_value(text)?
            }
            EncodedValue::Type(i) => {
                let d = self.type_at(*i, &Site::default())?;
                self.new_class_value(&d)?
            }
            EncodedValue::MethodType(i) => {
                let s = self.proto_signature(*i, &Site::default())?;
                self.new_method_type(&s)?
            }
            EncodedValue::MethodHandle(i) => {
                let h = self.program.method_handle(*i)?;
                let target = h.method_idx.and_then(|m| {
                    self.program.methods.get(m as usize).map(|(c, n, s)| format!("{c}.{n}{s}"))
                });
                self.new_method_handle(h.kind, target)?
            }
            // A member reference is not a value: the JVM model represents a
            // `Field` or `Method` constant-pool entry used as a value as `null`,
            // and nothing in the interpreter can observe the difference.
            EncodedValue::Field(_)
            | EncodedValue::Method(_)
            | EncodedValue::Enum { .. }
            | EncodedValue::Annotation
            | EncodedValue::Unsupported(_) => Value::Null,
            EncodedValue::Array(items) => {
                let component = items
                    .first()
                    .and_then(|v| v.jtype(&self.program))
                    .map(|t| t.descriptor())
                    .unwrap_or_else(|| "Ljava/lang/Object;".to_string());
                let class_id = self.array_class(&component)?;
                let mut elements = Vec::with_capacity(items.len());
                for it in items {
                    elements.push(self.materialise_encoded(it)?);
                }
                let ty = JType::parse(&component);
                let r = self.alloc(class_id, ObjectKind::Array { component: ty, elements }, None)?;
                Value::Ref(r)
            }
        })
    }

    fn new_string_value(&mut self, text: String) -> ExecResult<Value> {
        let class = match self.class_id_known("Ljava/lang/String;") {
            Some(c) => c,
            None => {
                return Err(ExecError::Unsupported {
                    kind: Unsupported::ClassNotFound,
                    detail: "no class for Ljava/lang/String;".to_string(),
                    site: self.site(),
                })
            }
        };
        let r = self.alloc(class, ObjectKind::Str { text }, None)?;
        Ok(Value::Ref(r))
    }

    fn new_class_value(&mut self, descriptor: &str) -> ExecResult<Value> {
        // Make sure the class exists: `const-class` on an unresolvable type is a
        // `NoClassDefFoundError` on a device, and the class has to be in the
        // table for a later `instance-of` against it to mean anything.
        self.class_id_for(descriptor);
        let class = self.class_id_known("Ljava/lang/Class;").unwrap_or(ClassId(0));
        let r = self.alloc(class, ObjectKind::Class { descriptor: descriptor.to_string() }, None)?;
        Ok(Value::Ref(r))
    }

    fn new_method_type(&mut self, proto: &str) -> ExecResult<Value> {
        let class = self
            .class_id_known("Ljava/lang/reflect/MethodType;")
            .unwrap_or(ClassId(0));
        let r = self.alloc(class, ObjectKind::MethodType { proto: proto.to_string() }, None)?;
        Ok(Value::Ref(r))
    }

    fn new_method_handle(&mut self, kind: u16, target: Option<String>) -> ExecResult<Value> {
        let class = self
            .class_id_known("Ljava/lang/invoke/MethodHandle;")
            .unwrap_or(ClassId(0));
        let r = self.alloc(class, ObjectKind::MethodHandle { kind, target }, None)?;
        Ok(Value::Ref(r))
    }

    // ============================================================== plumbing

    fn alloc(
        &mut self,
        class: ClassId,
        kind: ObjectKind,
        detail_message: Option<String>,
    ) -> ExecResult<Ref> {
        match self.heap.alloc(class, kind, self.config.max_objects, self.config.max_bytes) {
            Ok(r) => {
                if let Some(m) = detail_message {
                    if let Some(obj) = self.heap.get_mut(r) {
                        obj.detail_message = Some(m);
                    }
                }
                self.stats.allocations += 1;
                self.stats.bytes_allocated = self.heap.bytes();
                Ok(r)
            }
            Err(limit) => {
                let kind = if self.heap.len() as u64 >= self.config.max_objects.unwrap_or(u64::MAX) {
                    Budget::Objects
                } else {
                    Budget::Bytes
                };
                let site = self.site();
                Err(ExecError::OutOfMemory { kind, limit, requested: 0, site })
            }
        }
    }

    fn string_at(&self, index: u32, site: &Site) -> ExecResult<String> {
        self.program.strings.get(index as usize).cloned().ok_or_else(|| {
            ExecError::Malformed {
                kind: Malformed::BadPoolIndex,
                detail: format!("string@{index} does not exist"),
                site: site.clone(),
            }
        })
    }

    fn type_at(&self, index: u32, site: &Site) -> ExecResult<String> {
        self.program.types.get(index as usize).cloned().ok_or_else(|| {
            ExecError::Malformed {
                kind: Malformed::BadPoolIndex,
                detail: format!("type@{index} does not exist"),
                site: site.clone(),
            }
        })
    }

    fn proto_signature(&self, index: u32, site: &Site) -> ExecResult<String> {
        self.dex.proto_at(index).map(|p| p.signature()).map_err(|e| {
            ExecError::Malformed {
                kind: Malformed::BadPoolIndex,
                detail: format!("proto@{index}: {e}"),
                site: site.clone(),
            }
        })
    }

    /// `(return descriptor, parameter count, parameter descriptors)` of a
    /// `method_ids` entry.
    fn method_proto(&self, method_idx: u32, site: &Site) -> ExecResult<(String, usize, Vec<String>)> {
        let (_, _, sig) = match self.program.methods.get(method_idx as usize) {
            Some(t) => t.clone(),
            None => {
                return Err(ExecError::Malformed {
                    kind: Malformed::BadPoolIndex,
                    detail: format!("method@{method_idx} does not exist"),
                    site: site.clone(),
                })
            }
        };
        let (params, ret) = JType::parse_prototype(&sig);
        Ok((ret.descriptor(), params.len(), params.iter().map(|p| p.descriptor()).collect()))
    }
}

// ==================================================================== helpers

fn invoke_kind(op: u8) -> InvokeKind {
    match op {
        0x6e | 0x74 => InvokeKind::Virtual,
        0x6f | 0x75 => InvokeKind::Super,
        0x70 | 0x76 => InvokeKind::Direct,
        0x71 | 0x77 => InvokeKind::Static,
        0xfa | 0xfb => InvokeKind::Polymorphic,
        0xfc | 0xfd => InvokeKind::Custom,
        _ => InvokeKind::Interface,
    }
}

fn int_compare(op: u8, x: i32, y: i32) -> bool {
    match op {
        0x32 => x == y,
        0x33 => x != y,
        0x34 => x < y,
        0x35 => x >= y,
        0x36 => x > y,
        0x37 => x <= y,
        _ => false,
    }
}

fn int_compare_zero(op: u8, x: i32) -> bool {
    match op {
        0x38 => x == 0,
        0x39 => x != 0,
        0x3a => x < 0,
        0x3b => x >= 0,
        0x3c => x > 0,
        0x3d => x <= 0,
        _ => false,
    }
}

fn render_signature(vm: &Interpreter<'_>, decl: &MethodDecl) -> String {
    format!("{}.{}{}", vm.class_name(decl.class), decl.name, decl.signature)
}

/// The contiguous register list of a `3rc`-family instruction.
fn range_regs(first: u16, count: u16) -> Vec<u8> {
    (0..count)
        .filter_map(|i| first.checked_add(i).map(|r| r.min(u16::MAX as u8 as u16) as u8))
        .collect()
}

/// Take `arity` registers from `all`, or all of them when the form carries its
/// own count.
fn select_regs(all: &[u8], arity: usize, ranged: bool) -> Vec<u8> {
    if ranged {
        all.to_vec()
    } else {
        all.iter().copied().take(arity).collect()
    }
}

/// The number of *meaningful* registers in a packed `35c` register list.
///
/// A trailing `v0` argument is indistinguishable from padding, which
/// `dexcore::Instruction::argument_registers` documents; this is the same rule
/// and it is only used where the alternative (`A`) is zero.
fn trimmed_len(regs: &[u8]) -> usize {
    regs.iter().rposition(|&r| r != 0).map(|i| i + 1).unwrap_or(0)
}

/// A switch target, which is relative to the switch instruction.
fn switch_target(from: u32, offset: i32, site: &Site) -> ExecResult<u32> {
    let t = i64::from(from) + i64::from(offset);
    if t < 0 || t > u32::MAX as i64 {
        return Err(ExecError::Malformed {
            kind: Malformed::BadBranchTarget,
            detail: format!("switch target {offset} from unit {from} leaves the method"),
            site: site.clone(),
        });
    }
    Ok(t as u32)
}

fn checked_index(index: i32, len: usize) -> Option<usize> {
    if index < 0 {
        return None;
    }
    let i = index as usize;
    if i < len {
        Some(i)
    } else {
        None
    }
}

/// The component descriptor of an array descriptor, e.g. `[I` -> `I`.
fn component_descriptor(array_descriptor: &str) -> String {
    match array_descriptor.strip_prefix('[') {
        Some(rest) => rest.to_string(),
        None => array_descriptor.to_string(),
    }
}

fn payload_name(p: &Payload) -> &'static str {
    match p {
        Payload::PackedSwitch(_) => "packed-switch",
        Payload::SparseSwitch(_) => "sparse-switch",
        Payload::FillArrayData(_) => "fill-array-data",
    }
}

fn check_return(v: Value, site: &Site) -> ExecResult<Value> {
    if v == Value::Uninit {
        return Err(ExecError::Malformed {
            kind: Malformed::UninitialisedRegister,
            detail: "return of a register that was never written".to_string(),
            site: site.clone(),
        });
    }
    if v == Value::Void {
        return Err(ExecError::Malformed {
            kind: Malformed::TypeMismatch,
            detail: "return of a void value from a value-returning method".to_string(),
            site: site.clone(),
        });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_argument_lists_trim_trailing_zeroes() {
        // `packed_registers` cannot distinguish a trailing `v0` from padding, so
        // the trimmed length is the fallback arity and `A` is the primary one.
        assert_eq!(trimmed_len(&[1, 2, 0, 0, 0]), 2);
        assert_eq!(trimmed_len(&[0, 0, 0, 0, 0]), 0);
        assert_eq!(trimmed_len(&[3, 0, 0, 0, 0]), 1);
    }

    #[test]
    fn range_registers_are_contiguous_and_bounded() {
        assert_eq!(range_regs(4, 3), vec![4, 5, 6]);
        assert_eq!(range_regs(25, 1), vec![25]);
        assert!(range_regs(u16::MAX, 4).len() <= 4);
    }

    #[test]
    fn a_switch_target_is_relative_to_the_switch_not_the_payload() {
        let s = Site { method: None, unit: 10, opcode: Some(0x2b) };
        assert_eq!(switch_target(10, 5, &s), Ok(15));
        assert_eq!(switch_target(10, -3, &s), Ok(7));
        assert!(switch_target(0, -1, &s).is_err());
    }

    #[test]
    fn array_indices_are_checked_in_both_directions() {
        assert_eq!(checked_index(0, 0), None);
        assert_eq!(checked_index(-1, 4), None);
        assert_eq!(checked_index(3, 4), Some(3));
        assert_eq!(checked_index(4, 4), None);
        // An index so large it would overflow a usize cast is still refused.
        assert_eq!(checked_index(i32::MAX, 4), None);
    }

    #[test]
    fn component_descriptor_strips_exactly_one_dimension() {
        assert_eq!(component_descriptor("[I"), "I");
        assert_eq!(component_descriptor("[[Ljava/lang/String;"), "[Ljava/lang/String;");
        assert_eq!(component_descriptor("Ljava/lang/String;"), "Ljava/lang/String;");
    }

    #[test]
    fn invoke_opcodes_map_to_the_right_dispatch_kind() {
        assert_eq!(invoke_kind(0x6e), InvokeKind::Virtual);
        assert_eq!(invoke_kind(0x74), InvokeKind::Virtual);
        assert_eq!(invoke_kind(0x6f), InvokeKind::Super);
        assert_eq!(invoke_kind(0x75), InvokeKind::Super);
        assert_eq!(invoke_kind(0x70), InvokeKind::Direct);
        assert_eq!(invoke_kind(0x72), InvokeKind::Interface);
        assert_eq!(invoke_kind(0x71), InvokeKind::Static);
        assert_eq!(invoke_kind(0x77), InvokeKind::Static);
        assert_eq!(invoke_kind(0xfa), InvokeKind::Polymorphic);
        assert_eq!(invoke_kind(0xfc), InvokeKind::Custom);
    }

    #[test]
    fn the_integer_comparisons_cover_all_twelve_opcodes() {
        assert!(int_compare(0x32, 1, 1));
        assert!(int_compare(0x33, 1, 2));
        assert!(int_compare(0x34, 1, 2));
        assert!(int_compare(0x35, 2, 1));
        assert!(int_compare(0x36, 2, 1));
        assert!(int_compare(0x37, 1, 2));
        assert!(!int_compare(0x34, 2, 1));
        for (op, x, want) in
            [(0x38u8, 0i32, true), (0x39, 0, false), (0x3a, -1, true), (0x3b, -1, false), (0x3c, 1, true), (0x3d, 1, false)]
        {
            assert_eq!(int_compare_zero(op, x), want, "opcode 0x{op:02x}");
        }
    }
}
