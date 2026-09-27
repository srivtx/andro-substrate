//! The object heap.
//!
//! There is no garbage collector. That is a design decision with a
//! consequence, so it is stated rather than left to be discovered: the engine
//! is asked to run one lifecycle callback and report what it did, not to run a
//! workload. A collecting heap would need root scanning over the frame stack,
//! which the engine owns in a different module, and it would make
//! [`Stats::bytes_allocated`] depend on when a collection happened — which
//! would destroy the one accounting number the study most needs to be stable.
//! Memory therefore grows monotonically until the run ends or a limit is hit,
//! and [`Stats::live_bytes`](crate::config::Stats::live_bytes) is an honest
//! upper bound rather than a measurement of live data.
//!
//! The concrete types are:
//!
//! * **instances** — a class plus a flat `Vec<Value>` of instance fields,
//!   laid out superclass-first so a subclass's fields start where its
//!   superclass's end;
//! * **arrays** — a component type plus a `Vec<Value>`, with `long`/`double`
//!   elements taking one slot each (unlike registers, array elements are
//!   addressed by index and never by a register pair);
//! * **special objects** — `String`, `Class`, `MethodType` and `MethodHandle`,
//!   which have real payloads rather than fields, because the engine needs to
//!   be able to answer `const-string` and `const-class` without a shim.
//!
//! Every object records a monitor, so `monitor-enter`/`monitor-exit` have
//! somewhere to live. See [`Monitor`].

use std::fmt;

use crate::value::{JType, Ref, Value};

/// Runtime class identity.
///
/// A [`ClassId`] indexes the interpreter's combined class table, which holds
/// the classes from the DEX *and* the builtin framework classes *and* any
/// phantom placeholders. One numbering, so `instance-of` is one comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClassId(pub u32);

impl fmt::Display for ClassId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "class#{}", self.0)
    }
}

/// What an object actually is.
#[derive(Clone, Debug, PartialEq)]
pub enum ObjectKind {
    /// A plain object with instance fields.
    Instance {
        /// The instance fields, superclass-first.
        fields: Vec<Value>,
    },
    /// An array.
    Array {
        /// The element type.
        component: JType,
        /// The elements. A `long` or `double` element occupies one slot here.
        elements: Vec<Value>,
    },
    /// A `Ljava/lang/String;`, which the engine materialises for
    /// `const-string` so that string handling works before any shim exists.
    Str {
        /// The characters.
        text: String,
    },
    /// A `Ljava/lang/Class;`.
    Class {
        /// The descriptor of the class it stands for.
        descriptor: String,
    },
    /// A `Ljava/lang/reflect/MethodType;`.
    MethodType {
        /// The prototype descriptor, e.g. `(I)Ljava/lang/String;`.
        proto: String,
    },
    /// A `Ljava/lang/invoke/MethodHandle;`.
    MethodHandle {
        /// `METHOD_HANDLE_*` from the DEX specification.
        kind: u16,
        /// The referenced method or field signature, when there is one.
        target: Option<String>,
    },
}

/// A heap object.
#[derive(Clone, Debug, PartialEq)]
pub struct Object {
    /// The class.
    pub class: ClassId,
    /// The payload.
    pub kind: ObjectKind,
    /// The monitor, entered by `monitor-enter`.
    pub monitor: Monitor,
    /// `Throwable.detailMessage`, for a throwable the engine raised.
    ///
    /// It is a field in `core.jar` rather than in the APK, so the engine has
    /// nowhere to put it in the field layout. Keeping it beside the object is
    /// the only place it can go without inventing a slot, and it is what lets
    /// the study record *why* an app threw rather than only that it did.
    pub detail_message: Option<String>,
}

impl Object {
    /// Approximate storage in bytes, for [`Stats::bytes_allocated`].
    ///
    /// An object header of 16 bytes plus each field or element at its real
    /// width. The number is a model, not a measurement of anything a device
    /// would agree with; it is here so that allocation pressure is comparable
    /// between runs, and that is the only claim made about it.
    pub fn storage_bytes(&self) -> u64 {
        const HEADER: u64 = 16;
        let payload: u64 = match &self.kind {
            ObjectKind::Instance { fields } => sum_slots(fields),
            ObjectKind::Array { component, elements } => {
                sum_slots(elements).max(elements.len() as u64 * u64::from(component.element_width()))
            }
            ObjectKind::Str { text } => 16 + text.len() as u64,
            ObjectKind::Class { descriptor } => 16 + descriptor.len() as u64,
            ObjectKind::MethodType { proto } => 16 + proto.len() as u64,
            ObjectKind::MethodHandle { target, .. } => {
                24 + target.as_ref().map(|t| t.len() as u64).unwrap_or(0)
            }
        };
        HEADER + payload
    }
}

fn sum_slots(values: &[Value]) -> u64 {
    values
        .iter()
        .map(|v| match v {
            Value::Long(_) | Value::Double(_) => 8,
            _ => 4,
        })
        .sum()
}

/// A reentrant monitor.
///
/// # This is not a memory model
///
/// Dalvik's `monitor-enter`/`monitor-exit` implement `synchronized`, which is
/// mutual exclusion *plus* a happens-before edge: everything one thread wrote
/// before releasing a monitor is visible to the thread that acquires it. This
/// engine is single-threaded by construction — there is exactly one call stack
/// and no scheduler — so the mutual-exclusion half is vacuously satisfied and
/// the happens-before half has nothing to order.
///
/// What that costs, stated plainly because the study must not mistake this for
/// a working `synchronized`:
///
/// * A program that relies on a lock to serialise two threads runs with one
///   thread, so the interleaving never happens and any bug that depended on it
///   is invisible. Taxonomy `SUB.CPU.ATOMIC` and `SUB.IPC.BINDER_THREADPOOL` are
///   **unfalsifiable here**, and results from this engine must not be reported
///   as evidence about them either way.
/// * A program that deadlocks on a monitor cannot deadlock: `monitor-enter` on
///   a monitor this thread already holds is a *successful* reentrant acquire,
///   matching Java's semantics, so a self-deadlock in single-threaded code is
///   simply not detected. Real code reaches this through `synchronized` methods
///   on objects that a framework callback re-enters.
/// * `monitor-exit` on a monitor this thread does not hold is reported as a
///   [`Malformed`](crate::error::Malformed) rather than an
///   `IllegalMonitorStateException`, because no verifier checks monitor state
///   and silently ignoring the imbalance would hide a real bug in the app.
///
/// See `docs/decisions/0003-execution-engine.md` for why a single-threaded
/// interpreter was chosen anyway.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Monitor {
    /// How many times this thread has entered. Reentrant, so a count and not a
    /// flag.
    pub depth: u32,
    /// Total `monitor-enter`s over the run, for the record.
    pub entries: u64,
    /// Total `monitor-exit`s over the run.
    pub exits: u64,
}

impl Monitor {
    /// Enter, reentrantly.
    pub fn enter(&mut self) {
        self.depth = self.depth.saturating_add(1);
        self.entries = self.entries.saturating_add(1);
    }

    /// Leave one level. `false` if the monitor was not held.
    pub fn exit(&mut self) -> bool {
        if self.depth == 0 {
            self.exits = self.exits.saturating_add(1);
            return false;
        }
        self.depth -= 1;
        self.exits = self.exits.saturating_add(1);
        true
    }
}

/// The heap.
#[derive(Debug, Default)]
pub struct Heap {
    objects: Vec<Object>,
    bytes: u64,
}

impl Heap {
    /// An empty heap.
    pub fn new() -> Heap {
        Heap { objects: Vec::new(), bytes: 0 }
    }

    /// Allocate an object, returning its handle. `None` if the object count
    /// limit was reached; the caller turns that into
    /// [`OutOfMemory`](crate::error::ExecError::OutOfMemory).
    pub fn alloc(
        &mut self,
        class: ClassId,
        kind: ObjectKind,
        max_objects: Option<u64>,
        max_bytes: Option<u64>,
    ) -> Result<Ref, u64> {
        if let Some(limit) = max_objects {
            if self.objects.len() as u64 >= limit {
                return Err(limit);
            }
        }
        let obj = Object { class, kind, monitor: Monitor::default(), detail_message: None };
        let size = obj.storage_bytes();
        if let Some(limit) = max_bytes {
            let want = self.bytes.saturating_add(size);
            if want > limit {
                return Err(limit);
            }
        }
        let id = (self.objects.len() as u32).saturating_add(1);
        self.objects.push(obj);
        self.bytes = self.bytes.saturating_add(size);
        Ok(Ref(id))
    }

    /// Borrow an object. `None` for `null` and for out-of-range handles, which
    /// can only happen if a [`Value::Ref`] was fabricated by a caller.
    pub fn get(&self, r: Ref) -> Option<&Object> {
        self.objects.get(r.0.checked_sub(1)? as usize)
    }

    /// Mutably borrow an object, with the same validity rule as [`Heap::get`].
    pub fn get_mut(&mut self, r: Ref) -> Option<&mut Object> {
        self.objects.get_mut(r.0.checked_sub(1)? as usize)
    }

    /// Number of objects allocated.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// True if nothing has been allocated.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// Bytes in use, by the model in [`Object::storage_bytes`].
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The characters of a `Ljava/lang/String;` object, or `None` if `v` is not
    /// a string.
    pub fn string_of(&self, v: Value) -> Option<&str> {
        let r = match v {
            Value::Ref(r) => r,
            _ => return None,
        };
        match &self.get(r)?.kind {
            ObjectKind::Str { text } => Some(text),
            _ => None,
        }
    }

    /// The descriptor a `Ljava/lang/Class;` object stands for.
    pub fn class_of_object(&self, v: Value) -> Option<&str> {
        let r = match v {
            Value::Ref(r) => r,
            _ => return None,
        };
        match &self.get(r)?.kind {
            ObjectKind::Class { descriptor } => Some(descriptor),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heap_with(kinds: Vec<(ClassId, ObjectKind)>) -> Heap {
        let mut h = Heap::new();
        for (c, k) in kinds {
            // No limits in these unit tests; the interpreter applies them.
            let _ = h.alloc(c, k, None, None);
        }
        h
    }

    #[test]
    fn handles_are_one_based_so_zero_is_never_a_live_handle() {
        let mut h = heap_with(vec![(ClassId(0), ObjectKind::Class { descriptor: "LFoo;".into() })]);
        // `heap_with` already allocated one, so the next handle is 2.
        let r = h.alloc(ClassId(0), ObjectKind::Class { descriptor: "LBar;".into() }, None, None).unwrap();
        assert_eq!(r, Ref(2));
        assert_eq!(h.get(Ref(1)).map(|o| &o.class), Some(&ClassId(0)));
        assert!(h.get(Ref(0)).is_none(), "Ref(0) must never resolve");
    }

    #[test]
    fn strings_are_real_objects_and_readable_back() {
        let h = heap_with(vec![(ClassId(3), ObjectKind::Str { text: "hello ☃".into() })]);
        assert_eq!(h.string_of(Value::Ref(Ref(1))), Some("hello ☃"));
        assert_eq!(h.string_of(Value::Null), None);
        assert_eq!(h.string_of(Value::Int(1)), None);
    }

    #[test]
    fn monitors_are_reentrant_and_detect_imbalance() {
        let mut m = Monitor::default();
        m.enter();
        m.enter();
        assert_eq!(m.depth, 2);
        assert!(m.exit());
        assert!(m.exit());
        assert!(!m.exit(), "exiting a monitor that is not held must be reported");
        assert_eq!(m.entries, 2);
        assert_eq!(m.exits, 3);
    }

    #[test]
    fn limits_refuse_rather_than_grow() {
        let mut h = Heap::new();
        let k = ObjectKind::Class { descriptor: "Lx;".into() };
        assert!(h.alloc(ClassId(0), k.clone(), Some(1), None).is_ok());
        let e = h.alloc(ClassId(0), k.clone(), Some(1), None).unwrap_err();
        assert_eq!(e, 1, "the error carries the limit, not a message");
        assert!(h.alloc(ClassId(0), k, None, Some(4)).is_err());
    }

    #[test]
    fn storage_model_distinguishes_wide_from_narrow() {
        let narrow = Object {
            class: ClassId(0),
            kind: ObjectKind::Instance { fields: vec![Value::Int(0), Value::Int(0)] },
            monitor: Monitor::default(),
            detail_message: None,
        };
        let wide = Object {
            class: ClassId(0),
            kind: ObjectKind::Instance { fields: vec![Value::Long(0)] },
            monitor: Monitor::default(),
            detail_message: None,
        };
        assert_eq!(narrow.storage_bytes(), 16 + 8);
        assert_eq!(wide.storage_bytes(), 16 + 8);
        assert_eq!(Heap::new().bytes(), 0);
    }
}
