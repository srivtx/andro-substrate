//! The closure: a fixpoint over the call graph of an app plus the framework
//! it runs on.
//!
//! This is the boundary the project needs and the one it is most likely to get
//! wrong in either direction, so this module is deliberately conservative about
//! *claims* and liberal about *reporting*.
//!
//! # A closure is not a number, it is a number given a set of choices
//!
//! Each of these is a defensible reading of `IR.md`, they disagree by an order
//! of magnitude, and none is the one a reader will assume by default:
//!
//! | knob | type | readings |
//! |---|---|---|
//! | who can receive a virtual call | [`DispatchPolicy`] | `Cha` = every subtype in the universe; `Rta` = only allocated subtypes |
//! | is framework code analysable | [`FrameworkSource`] | black box (hosted) or DEX bodies followed |
//! | what a class-shaped string means | [`ReflectionPolicy`] | class only, or `forName` sites expand to the public surface |
//! | where the app starts | [`entry::EntryPolicy`] | `IR.md` verbatim, or the cold start Android performs |
//!
//! The report prints all four on its face, because a closure number without its
//! policies is not a measurement.
//!
//! # Soundness is a claim here, not a property
//!
//! `Rta` is not a sound over-approximation. It is sound only if no reachable
//! code obtains an instance by a means DEX cannot see — reflection, JNI,
//! deserialisation, a name built at run time and handed to a class loader. That
//! is precisely why [`Closure::unresolved_reflective`] is a first-class field:
//! the hole in `Rta` *is* the reflective-edge set, and a report that omits it
//! is asserting a soundness nobody checked.
//!
//! # Termination, and honesty about limits
//!
//! The universe is finite and countable ([`model::UniverseTotals`]) so the
//! worklist terminates. It can still be slow, and [`Config::max_rounds`] and
//! [`Config::max_edges`] exist so a pathological input costs bounded work.
//! When a bound is reached the closure carries `hit_method_limit` /
//! `hit_edge_limit` and the report says so. **A truncated closure is never
//! presented as a complete one.**
//!
//! # What is deliberately not done
//!
//! * **No tuning to a target.** Nothing here is calibrated against the
//!   empirical 4,649. [`validate`] compares the two and explains the gap.
//! * **No silent widening.** Every decision a reader might not expect is a
//!   field on [`Closure`], not a comment.

#![warn(missing_debug_implementations)]

pub mod entry;
pub mod model;
pub mod report;
pub mod validate;
pub mod zip;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use dexcore::insn::Instruction;
use dexcore::reader::decode_one;

use crate::reach::model::{ClassId, MethodId, Program};

/// Why an edge exists.
///
/// The first five are the five names `IR.md` gives. The last three are
/// additions this module had to make to describe what a DEX file actually
/// contains; [`EdgeKind::is_ir_md`] separates them so a reader can subtract
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// `invoke-static`, `invoke-direct`: exactly one target.
    Direct,
    /// `invoke-virtual`, `invoke-interface`, `invoke-super`, plus the override
    /// closure — a vtable slot is an edge in both directions.
    Virtual,
    /// A class in the closure drags its transitive superclass and interface
    /// chain. A class-level edge.
    Superclass,
    /// A `const-string` that names a class the universe contains.
    Reflective,
    /// A call to a method with no DEX body. The host must implement it and its
    /// successors are not analysable from DEX.
    Hostcall,
    // ---- additions beyond IR.md's five, each with a stated reason --------
    /// `invoke-polymorphic`: the method reference is named but the real target
    /// is chosen at run time by the trailing prototype.
    Polymorphic,
    /// `invoke-custom`: the target is a call site resolved by a bootstrap
    /// method, a hole of the same kind as reflection.
    Custom,
    /// A class descriptor reached by `new-instance`, `check-cast`,
    /// `instance-of`, an array creation, a field instruction or a signature.
    Type,
}

impl EdgeKind {
    /// Every kind, in report order.
    pub const ALL: [EdgeKind; 8] = [
        EdgeKind::Direct,
        EdgeKind::Virtual,
        EdgeKind::Superclass,
        EdgeKind::Reflective,
        EdgeKind::Hostcall,
        EdgeKind::Polymorphic,
        EdgeKind::Custom,
        EdgeKind::Type,
    ];

    /// True for the five kinds `IR.md` names.
    pub fn is_ir_md(self) -> bool {
        matches!(
            self,
            EdgeKind::Direct
                | EdgeKind::Virtual
                | EdgeKind::Superclass
                | EdgeKind::Reflective
                | EdgeKind::Hostcall
        )
    }

    /// True for the kinds that connect two *classes* rather than two methods.
    pub fn is_class_level(self) -> bool {
        matches!(
            self,
            EdgeKind::Superclass | EdgeKind::Type | EdgeKind::Reflective
        )
    }

    /// Name as printed.
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Direct => "direct",
            EdgeKind::Virtual => "virtual",
            EdgeKind::Superclass => "superclass",
            EdgeKind::Reflective => "reflective",
            EdgeKind::Hostcall => "hostcall",
            EdgeKind::Polymorphic => "polymorphic",
            EdgeKind::Custom => "custom",
            EdgeKind::Type => "type",
        }
    }
}

/// Whether an edge connects two methods or two classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeLevel {
    /// `from` and `to` are both methods and the record is in [`Closure::edges`].
    Method,
    /// The edge relates classes; it is counted in `class_edge_counts` and is
    /// not in [`Closure::edges`], which is method-level.
    Class,
}

/// One method-level edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Edge {
    pub from: MethodId,
    pub to: MethodId,
    pub kind: EdgeKind,
}

/// How a `const-string` that names a class becomes an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReflectionPolicy {
    /// The class enters the closure; its methods do not.
    ClassOnly,
    /// A literal consumed by `Class.forName`/`ClassLoader.loadClass` at the
    /// immediately following instruction additionally pulls in the class's
    /// whole overridable surface, because that is what
    /// `getMethod(...).invoke(...)` can reach.
    #[default]
    ForNameExpands,
}

impl ReflectionPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            ReflectionPolicy::ClassOnly => "class-only",
            ReflectionPolicy::ForNameExpands => {
                "class-only, with forName sites expanding to the overridable surface"
            }
        }
    }
}

/// Who can be the receiver of a virtual call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DispatchPolicy {
    /// Class hierarchy analysis: every transitive subtype in the universe.
    ///
    /// Sound with respect to the universe, and the reason a static closure over
    /// the full Android 13 boot classpath is not a usable synthesis target.
    /// That is a result, not a failure.
    Cha,
    /// Rapid type analysis: only subtypes some reachable code allocates.
    ///
    /// Sound only modulo reflection and the rest of the invisible-allocation
    /// set. This is the policy that produces a synthesisable number, and the
    /// one whose licence is the reflective-edge report.
    #[default]
    Rta,
}

impl DispatchPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            DispatchPolicy::Cha => "CHA (every subtype in the universe)",
            DispatchPolicy::Rta => "RTA (only allocated subtypes)",
        }
    }
}

/// Whether framework method bodies are followed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FrameworkSource {
    /// The framework is a black box: a framework method in the closure is a
    /// leaf. We host it, we do not compile it. This matches the project's
    /// architecture, in which the host *replaces* the framework.
    BlackBox,
    /// Walk framework DEX bodies too: the cost of implementing the framework
    /// rather than hosting it.
    #[default]
    Follow,
}

impl FrameworkSource {
    pub fn as_str(self) -> &'static str {
        match self {
            FrameworkSource::BlackBox => "framework as black box (hosted, not compiled)",
            FrameworkSource::Follow => "framework DEX bodies followed",
        }
    }
}

/// Every choice a closure depends on.
#[derive(Debug, Clone)]
pub struct Config {
    pub dispatch: DispatchPolicy,
    pub framework: FrameworkSource,
    pub reflection: ReflectionPolicy,
    pub entry: EntryPolicy,
    /// Add every overridable method each component declares, not just its
    /// lifecycle list. `IR.md` does not ask for it; a host without those
    /// vtable entries crashes on methods no call graph named.
    pub widen_to_full_surface: bool,
    /// Stop after this many fixpoint rounds and say so. `0` disables it.
    pub max_rounds: usize,
    /// Stop recording method edges past this many and say so.
    pub max_edges: usize,
    /// Methods the host will implement out of sight. Their successors are
    /// unanalysable; the report counts them as a hole.
    pub hostcall_seeds: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            dispatch: DispatchPolicy::default(),
            framework: FrameworkSource::default(),
            reflection: ReflectionPolicy::default(),
            entry: EntryPolicy::default(),
            widen_to_full_surface: false,
            max_rounds: 512,
            max_edges: 64_000_000,
            hostcall_seeds: Vec::new(),
        }
    }
}

/// What a class-shaped `const-string` turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReflectiveVerdict {
    /// Consumed by `Class.forName`/`ClassLoader.loadClass` at the immediately
    /// following instruction, in that argument position. The strongest evidence
    /// obtainable without a dataflow analysis, and the only verdict that
    /// expands a method set.
    ForNameSite,
    /// Names a class the universe contains. A real candidate: the app may load
    /// it, or the string may be an ordinary identifier.
    Resolved,
    /// Looks like a class name and the universe does not have it. Either the
    /// app loads a class that is genuinely absent, or the string is not a class
    /// name. **A static analysis cannot tell which, and this count is the size
    /// of that ignorance.**
    Unresolved,
    /// Does not look like a class name. Counted as the denominator only.
    NotAClass,
}

impl ReflectiveVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ReflectiveVerdict::ForNameSite => "forName-site",
            ReflectiveVerdict::Resolved => "resolved",
            ReflectiveVerdict::Unresolved => "unresolved",
            ReflectiveVerdict::NotAClass => "not-a-class",
        }
    }
}

/// One `const-string` that names a class: the record `IR.md` requires be
/// emitted and surfaced.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReflectiveEdge {
    /// The method the literal appears in.
    pub site: MethodId,
    /// Index of the instruction within the body, for locating it again.
    pub insn_index: u32,
    /// The literal, exactly as stored.
    pub literal: String,
    /// The descriptor it was normalised to, if it is class-shaped at all.
    pub descriptor: Option<String>,
    pub verdict: ReflectiveVerdict,
    /// The class it named, if the universe defines it.
    pub target: Option<ClassId>,
}

/// The result of one fixpoint run.
#[derive(Debug, Default)]
pub struct Closure {
    /// Methods in the closure.
    pub methods: BTreeSet<MethodId>,
    /// Classes in the closure.
    pub classes: BTreeSet<ClassId>,
    /// Distinct method-level edges, deduplicated per `(from, to, kind)`.
    pub edges: Vec<Edge>,
    /// Method-level edge totals, by kind.
    pub method_edge_counts: BTreeMap<EdgeKind, usize>,
    /// Class-level edge totals, by kind. These have no `Edge` record because an
    /// `Edge` names two methods.
    pub class_edge_counts: BTreeMap<EdgeKind, usize>,
    /// Every class-shaped `const-string` in the closure, deduplicated.
    pub reflective_edges: Vec<ReflectiveEdge>,
    /// Every `const-string` instruction decoded, class-shaped or not: the
    /// denominator that makes the reflective count interpretable.
    pub const_string_instructions: u64,
    /// Methods in the closure with no DEX body the host must implement.
    pub bodyless: BTreeSet<MethodId>,
    /// Methods that appear in `bodyless` because a call site reached them,
    /// as opposed to being seeds. Kept so the report can separate "the host
    /// must supply this because the app called it" from "…because nothing
    /// else can".
    pub bodyless_called: BTreeSet<MethodId>,
    /// `invoke-polymorphic` sites: named, but not statically resolved.
    pub polymorphic_sites: BTreeSet<MethodId>,
    /// `invoke-custom` sites: call-site-indirected targets.
    pub custom_sites: BTreeSet<MethodId>,
    /// Classes referenced by a descriptor but defined by no unit.
    pub unresolved_classes: BTreeSet<String>,
    /// Entry points that resolved to a method.
    pub entry: EntrySet,
    /// The configuration this closure was computed under.
    pub config: Config,
    /// Fixpoint rounds actually run.
    pub rounds: usize,
    /// Method bodies decoded and scanned.
    pub bodies_scanned: usize,
    /// Bodies that failed to decode. Non-zero is a soundness caveat: the edges
    /// out of those methods are missing and the report says by how much.
    pub bodies_failed: usize,
    /// Bodies that exist but were not followed because
    /// [`FrameworkSource::BlackBox`] was in force.
    pub bodies_skipped_by_policy: usize,
    /// `Config::max_rounds` stopped the fixpoint early.
    pub hit_method_limit: bool,
    /// `Config::max_edges` stopped edge recording early.
    pub hit_edge_limit: bool,
}

impl Closure {
    /// How many class-shaped literals could not be resolved to a class in the
    /// universe. **The number `IR.md` requires be stated.**
    pub fn unresolved_reflective(&self) -> usize {
        self.count_verdict(ReflectiveVerdict::Unresolved)
    }

    /// Class-shaped literals that did resolve.
    pub fn resolved_reflective(&self) -> usize {
        self.count_verdict(ReflectiveVerdict::Resolved)
    }

    /// Literals consumed by `Class.forName` at a syntactic site.
    pub fn forname_reflective(&self) -> usize {
        self.count_verdict(ReflectiveVerdict::ForNameSite)
    }

    /// Literals that are not class-shaped.
    pub fn nonclass_literals(&self) -> usize {
        self.count_verdict(ReflectiveVerdict::NotAClass)
    }

    fn count_verdict(&self, v: ReflectiveVerdict) -> usize {
        self.reflective_edges
            .iter()
            .filter(|e| e.verdict == v)
            .count()
    }

    /// Distinct class-shaped literals, ignoring which method they appear in.
    pub fn distinct_class_literals(&self) -> BTreeSet<&str> {
        self.reflective_edges
            .iter()
            .filter(|e| e.descriptor.is_some())
            .map(|e| e.literal.as_str())
            .collect()
    }

    /// Distinct unresolved literals.
    pub fn distinct_unresolved_literals(&self) -> BTreeSet<&str> {
        self.reflective_edges
            .iter()
            .filter(|e| e.verdict == ReflectiveVerdict::Unresolved)
            .map(|e| e.literal.as_str())
            .collect()
    }

    /// Method-level edges of one kind.
    pub fn method_edges_of(&self, kind: EdgeKind) -> usize {
        self.method_edge_counts.get(&kind).copied().unwrap_or(0)
    }

    /// Class-level edges of one kind.
    pub fn class_edges_of(&self, kind: EdgeKind) -> usize {
        self.class_edge_counts.get(&kind).copied().unwrap_or(0)
    }

    /// Total edges of one kind, method-level plus class-level.
    pub fn edges_of(&self, kind: EdgeKind) -> usize {
        self.method_edges_of(kind) + self.class_edges_of(kind)
    }

    /// True when the fixpoint completed without hitting a configured bound.
    pub fn is_complete(&self) -> bool {
        !self.hit_method_limit && !self.hit_edge_limit
    }

    /// The methods in `set` whose winning body comes from a unit of `role`.
    pub fn count_role(program: &Program, set: &BTreeSet<MethodId>, role: UnitRole) -> usize {
        set.iter()
            .filter(|m| {
                program.methods[m.0 as usize]
                    .resolved()
                    .is_some_and(|(u, _, _)| program.units[u.0 as usize].role == role)
            })
            .count()
    }
}

/// Namespace prefixes treated as framework when comparing against an ART
/// trace, copied from `trace/parse.py` so the two measurements are computed the
/// same way. It is a convention, not a derivation from `/system/framework`, and
/// that is stated there and repeated here.
pub const FRAMEWORK_PREFIXES: &[&str] = &[
    "android.",
    "java.",
    "javax.",
    "jdk.",
    "sun.",
    "libcore.",
    "dalvik.",
    "org.apache.harmony.",
    "org.apache.http.",
    "org.conscrypt.",
    "org.json.",
    "org.w3c.",
    "org.xml.",
    "org.xmlpull.",
    "com.android.",
];

/// Namespaces under `com.android.` that are preinstalled applications, not
/// framework. From `trace/parse.py`.
pub const FRAMEWORK_PREFIX_EXCEPTIONS: &[&str] = &[
    "com.android.providers.",
    "com.android.vending.",
    "com.android.chrome.",
    "com.android.packageinstaller.",
    "com.android.settings.",
    "com.android.shell.",
    "com.android.bluetooth.",
    "com.android.nfc.",
    "com.android.printspooler.",
    "com.android.external.",
    "com.android.wallpaper.",
    "com.android.cellbroadcastreceiver.",
    "com.android.keychain.",
    "com.android.location.fused.",
    "com.android.mms.",
    "com.android.server.",
    "com.android.systemui.",
];

/// Turn a DEX descriptor into the dotted name an ART trace prints.
pub fn descriptor_to_dotted(descriptor: &str) -> String {
    match descriptor
        .strip_prefix('L')
        .and_then(|s| s.strip_suffix(';'))
    {
        Some(inner) => inner.replace('/', "."),
        None => descriptor.to_string(),
    }
}

/// True if a dotted class name is framework by the trace convention.
pub fn is_framework_dotted(name: &str) -> bool {
    if FRAMEWORK_PREFIX_EXCEPTIONS
        .iter()
        .any(|e| name.starts_with(e))
    {
        return false;
    }
    FRAMEWORK_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// True if a descriptor is framework by the trace convention.
pub fn is_framework_descriptor(descriptor: &str) -> bool {
    is_framework_dotted(&descriptor_to_dotted(descriptor))
}

/// One decoded instruction with its pool operand already resolved.
///
/// The scan runs in two phases because pool indices are *per unit* and the
/// reader borrows the unit: phase one resolves every reference into owned data
/// under an immutable borrow, phase two mutates the closure freely. Doing it
/// the other way round would need either a self-referential `Program` or an
/// interior-mutable cache; this is less machinery for the same result.
#[derive(Debug, Clone)]
struct Step {
    op: u8,
    /// Destination register, for `const-string`.
    reg: u8,
    /// Argument registers, for the `invoke` family.
    args: Vec<u8>,
    arg: Arg,
}

#[derive(Debug, Clone)]
enum Arg {
    None,
    Str(String),
    Type(String),
    Method {
        class: String,
        name: String,
        proto: String,
    },
    /// The component type of an array created by `filled-new-array`.
    ArrayElem(String),
}

impl Arg {
    fn as_type(&self) -> Option<&str> {
        match self {
            Arg::Type(t) | Arg::ArrayElem(t) => Some(t),
            Arg::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// The fixpoint driver.
#[derive(Debug)]
pub struct Analyzer<'a> {
    program: &'a mut Program,
    config: Config,
    methods: BTreeSet<MethodId>,
    classes: BTreeSet<ClassId>,
    /// Allocated types, under `DispatchPolicy::Rta`.
    instantiated: BTreeSet<ClassId>,
    class_work: VecDeque<ClassId>,
    method_work: VecDeque<MethodId>,
    edges: BTreeSet<Edge>,
    method_edge_counts: BTreeMap<EdgeKind, usize>,
    class_edge_counts: BTreeMap<EdgeKind, usize>,
    edge_limit_hit: bool,
    reflective: BTreeSet<ReflectiveEdge>,
    const_strings: u64,
    bodyless: BTreeSet<MethodId>,
    bodyless_called: BTreeSet<MethodId>,
    polymorphic: BTreeSet<MethodId>,
    custom: BTreeSet<MethodId>,
    virtual_sites: BTreeSet<(MethodId, ClassId, u32, u32)>,
    bodies_scanned: usize,
    bodies_failed: usize,
    bodies_skipped: usize,
}

impl<'a> Analyzer<'a> {
    /// Start an analysis over a universe.
    pub fn new(program: &'a mut Program, config: Config) -> Analyzer<'a> {
        Analyzer {
            program,
            config,
            methods: BTreeSet::new(),
            classes: BTreeSet::new(),
            instantiated: BTreeSet::new(),
            class_work: VecDeque::new(),
            method_work: VecDeque::new(),
            edges: BTreeSet::new(),
            method_edge_counts: BTreeMap::new(),
            class_edge_counts: BTreeMap::new(),
            edge_limit_hit: false,
            reflective: BTreeSet::new(),
            const_strings: 0,
            bodyless: BTreeSet::new(),
            bodyless_called: BTreeSet::new(),
            polymorphic: BTreeSet::new(),
            custom: BTreeSet::new(),
            virtual_sites: BTreeSet::new(),
            bodies_scanned: 0,
            bodies_failed: 0,
            bodies_skipped: 0,
        }
    }

    /// Add a method to the closure, closing the vtable upward as it goes.
    ///
    /// "Upward" is the half that is easy to get wrong. If `D.m` is in the
    /// closure then the method it shadows — say `C.m` — can also run, because
    /// the call may have arrived through the base type; and if `C.m` can run
    /// then so can `B.m`. Closing only one level is a real and silent
    /// under-approximation: the closure looks like it honours "an override of
    /// a method in the closure" and does not, for any class two or more levels
    /// up a hierarchy that does not itself get called. The downward half
    /// (overrides of a method in the closure) is the virtual-site
    /// re-resolution in the main loop, because that half depends on the
    /// instantiated set, which grows during the fixpoint.
    fn add_method(&mut self, m: MethodId) -> bool {
        if !self.methods.insert(m) {
            return false;
        }
        self.method_work.push_back(m);
        if self.program.methods[m.0 as usize].is_overridable() {
            if let Some(up) = self.overridden(m) {
                // The edge is recorded whether or not `up` was already present.
                // Conditional recording would lose every slot whose base method
                // the app also calls by name, which is most of them, and the
                // vtable graph is exactly what a host stub has to reproduce.
                self.add_method(up);
                self.push_edge(up, m, EdgeKind::Virtual);
            }
        }
        true
    }

    fn add_class(&mut self, c: ClassId, kind: EdgeKind) -> bool {
        if self.classes.insert(c) {
            *self.class_edge_counts.entry(kind).or_insert(0) += 1;
            self.class_work.push_back(c);
            true
        } else {
            false
        }
    }

    /// Close over the type hierarchy: every class drags its ancestors.
    ///
    /// The edge count is of *links traversed*, not of classes newly added: a
    /// class that is already in the closure still contributes a superclass edge
    /// out of the class that reached it, and counting only the new arrivals
    /// would under-report the strongest edge kind in the graph — which is
    /// exactly the kind of quiet under-count this module exists to avoid.
    fn drain_classes(&mut self) {
        while let Some(c) = self.class_work.pop_front() {
            let Some(info) = self.program.classes.get(c.0 as usize) else {
                continue;
            };
            let sups: Vec<ClassId> = info
                .resolved()
                .map(|d| {
                    d.superclass
                        .into_iter()
                        .chain(d.interfaces.iter().copied())
                        .collect()
                })
                .unwrap_or_default();
            for s in sups {
                *self
                    .class_edge_counts
                    .entry(EdgeKind::Superclass)
                    .or_insert(0) += 1;
                self.add_class(s, EdgeKind::Superclass);
            }
        }
    }

    /// The methods a virtual call on `class` can reach, under the active
    /// dispatch policy.
    fn virtual_targets(&mut self, class: ClassId, name: u32, proto: u32) -> Vec<MethodId> {
        let mut out = Vec::new();
        if let Some(b) = self.program.method(class, name, proto) {
            out.push(b);
        }
        let subs = self.program.transitive_subtypes(class);
        for s in subs.iter() {
            let keep = match self.config.dispatch {
                DispatchPolicy::Cha => true,
                DispatchPolicy::Rta => self.instantiated.contains(s),
            };
            if keep {
                if let Some(m) = self.program.method(*s, name, proto) {
                    out.push(m);
                }
            }
        }
        out
    }

    /// The nearest ancestor declaring the same name and prototype.
    fn overridden(&self, m: MethodId) -> Option<MethodId> {
        let info = self.program.methods.get(m.0 as usize)?;
        let start = self
            .program
            .classes
            .get(info.class.0 as usize)?
            .resolved()?;
        let mut frontier: Vec<ClassId> = start
            .superclass
            .into_iter()
            .chain(start.interfaces.iter().copied())
            .collect();
        let mut guard = 0usize;
        while let Some(c) = frontier.pop() {
            guard += 1;
            if guard > 64 {
                return None;
            }
            if let Some(hit) = self.program.method(c, info.name, info.proto) {
                return Some(hit);
            }
            if let Some(d) = self
                .program
                .classes
                .get(c.0 as usize)
                .and_then(|x| x.resolved())
            {
                frontier.extend(d.superclass.into_iter().chain(d.interfaces.iter().copied()));
            }
        }
        None
    }

    /// Add a method together with every override of it in the active
    /// implementor set.
    ///
    /// The upward half lives in [`Analyzer::add_method`]; this is the downward
    /// half, which depends on the instantiated set and so is only valid at the
    /// moment it runs.
    fn add_with_vtable(&mut self, m: MethodId) {
        if !self.add_method(m) {
            return;
        }
        let Some(info) = self.program.methods.get(m.0 as usize) else {
            return;
        };
        let (class, name, proto) = (info.class, info.name, info.proto);
        let subs = self.program.transitive_subtypes(class);
        for s in subs.iter() {
            let keep = match self.config.dispatch {
                DispatchPolicy::Cha => true,
                DispatchPolicy::Rta => self.instantiated.contains(s),
            };
            if !keep {
                continue;
            }
            if let Some(o) = self.program.method(*s, name, proto) {
                if self.add_method(o) {
                    self.push_edge(o, m, EdgeKind::Virtual);
                }
            }
        }
    }

    fn push_edge(&mut self, from: MethodId, to: MethodId, kind: EdgeKind) {
        if self.edges.len() >= self.config.max_edges {
            self.edge_limit_hit = true;
            return;
        }
        if self.edges.insert(Edge { from, to, kind }) {
            *self.method_edge_counts.entry(kind).or_insert(0) += 1;
        }
    }

    /// Seed the fixpoint from resolved entry points and hostcall seeds.
    pub fn seed(&mut self, entry: &EntrySet) {
        for p in &entry.points {
            let Some((class, name, proto)) = parse_method_string(&p.method) else {
                continue;
            };
            let Some(cid) = self.program.class(&class) else {
                continue;
            };
            if !self.program.classes[cid.0 as usize].is_defined() {
                continue;
            }
            let Some(m) = self.program.lookup(cid, &name, &proto) else {
                continue;
            };
            if self.program.methods[m.0 as usize].is_bodyless() {
                self.bodyless.insert(m);
            }
            self.add_with_vtable(m);
        }
        let seeds = self.config.hostcall_seeds.clone();
        for s in &seeds {
            let Some((class, name, proto)) = parse_method_string(s) else {
                continue;
            };
            let Some(cid) = self.program.class(&class) else {
                continue;
            };
            let Some(m) = self.program.lookup(cid, &name, &proto) else {
                continue;
            };
            self.bodyless.insert(m);
            self.add_with_vtable(m);
        }
    }

    /// Run the fixpoint to exhaustion, or to the configured bound.
    pub fn run(mut self, entry: &EntrySet) -> Closure {
        self.seed(entry);
        let mut rounds = 0usize;
        let mut hit_rounds = false;
        loop {
            rounds += 1;
            self.drain_classes();
            while let Some(m) = self.method_work.pop_front() {
                self.scan(m);
            }
            // Re-resolve every recorded virtual site: the instantiated set may
            // have grown since the site was first seen. This is what makes RTA
            // a fixpoint rather than a single pass.
            let sites: Vec<(MethodId, ClassId, u32, u32)> =
                self.virtual_sites.iter().copied().collect();
            for (site, cls, name, proto) in sites {
                for t in self.virtual_targets(cls, name, proto) {
                    self.add_method(t);
                    self.push_edge(site, t, EdgeKind::Virtual);
                }
            }
            if self.method_work.is_empty() && self.class_work.is_empty() {
                break;
            }
            if self.config.max_rounds != 0 && rounds >= self.config.max_rounds {
                hit_rounds = true;
                break;
            }
        }
        self.finish(entry, rounds, hit_rounds)
    }

    fn finish(self, entry: &EntrySet, rounds: usize, hit_rounds: bool) -> Closure {
        Closure {
            methods: self.methods,
            classes: self.classes,
            edges: self.edges.into_iter().collect(),
            method_edge_counts: self.method_edge_counts,
            class_edge_counts: self.class_edge_counts,
            reflective_edges: self.reflective.into_iter().collect(),
            const_string_instructions: self.const_strings,
            bodyless: self.bodyless,
            bodyless_called: self.bodyless_called,
            polymorphic_sites: self.polymorphic,
            custom_sites: self.custom,
            unresolved_classes: BTreeSet::new(),
            entry: entry.clone(),
            config: self.config,
            rounds,
            bodies_scanned: self.bodies_scanned,
            bodies_failed: self.bodies_failed,
            bodies_skipped_by_policy: self.bodies_skipped,
            hit_method_limit: hit_rounds,
            hit_edge_limit: self.edge_limit_hit,
        }
    }

    /// Decode one body and turn it into resolved steps.
    ///
    /// Returns `Err(())` when the body is missing, is bodyless, is excluded by
    /// policy, or fails to decode; the caller distinguishes those cases.
    fn decode(&self, m: MethodId) -> Result<Vec<Step>, ()> {
        let Some((uid, code_off, _)) = self
            .program
            .methods
            .get(m.0 as usize)
            .and_then(|x| x.resolved())
        else {
            return Err(());
        };
        if code_off == 0 {
            return Err(());
        }
        let unit = &self.program.units[uid.0 as usize];
        let reader = unit.reader().map_err(|_| ())?;
        let raw = reader.code_units(code_off).map_err(|_| ())?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();

        let mut steps: Vec<Step> = Vec::with_capacity(units.len() / 2);
        let mut at = 0usize;
        loop {
            match decode_one(&units, at) {
                Ok((insn, n)) if n >= 1 => {
                    steps.push(self.resolve_step(uid, &insn));
                    at += n;
                }
                Ok(_) => break,
                Err(_) => break,
            }
        }
        Ok(steps)
    }

    fn resolve_step(&self, uid: UnitId, insn: &Instruction) -> Step {
        let op = insn.opcode().unwrap_or(0);
        let reg = match insn {
            Instruction::F21C { a, .. } | Instruction::F31C { a, .. } => *a,
            _ => 0,
        };
        // `Instruction::argument_registers` trims the packed `35c` nibbles at
        // the last non-zero one, which loses the argument list entirely when
        // the only argument is `v0` — precisely the shape d8 emits for a
        // one-argument static call, which is the shape of every `Class.forName`
        // site. The `A` field carries the argument count for those forms, so
        // it is used here; the range forms have an exact count already.
        let args = if insn.is_invoke() {
            match insn.argument_count_hint() {
                Some(n) if n as usize <= 5 => insn.packed_registers()[..n as usize].to_vec(),
                _ => insn.argument_registers(),
            }
        } else {
            Vec::new()
        };
        let unit = &self.program.units[uid.0 as usize];
        let arg = match insn.index_operand() {
            None => Arg::None,
            Some(i) => {
                let Ok(reader) = unit.reader() else {
                    return Step {
                        op,
                        reg,
                        args,
                        arg: Arg::None,
                    };
                };
                match op {
                    0x1a | 0x1b => match reader.string(i) {
                        Ok(s) => Arg::Str(s.value),
                        Err(_) => Arg::None,
                    },
                    0x1c | 0x1f | 0x20 | 0x22 | 0x23 => match reader.type_at(i) {
                        Ok(t) => Arg::Type(t.descriptor),
                        Err(_) => Arg::None,
                    },
                    0x24 | 0x25 => match reader.proto_at(i) {
                        Ok(p) => Arg::ArrayElem(array_element(&p.return_type)),
                        Err(_) => Arg::None,
                    },
                    0x52..=0x6d => match reader.field_at(i) {
                        Ok(f) => Arg::Type(f.class),
                        Err(_) => Arg::None,
                    },
                    0x6e..=0x78 | 0xfa..=0xfd => match reader.method_at(i) {
                        // `bare_proto`, not `signature()`: the latter is
                        // fully qualified, and interning it would give every
                        // prototype a per-class identity, so every lookup
                        // against the method table would miss.
                        Ok(m) => {
                            let proto = model::bare_proto(&m);
                            Arg::Method {
                                class: m.class,
                                name: m.name,
                                proto,
                            }
                        }
                        Err(_) => Arg::None,
                    },
                    _ => Arg::None,
                }
            }
        };
        Step { op, reg, args, arg }
    }

    /// Scan one method body.
    fn scan(&mut self, m: MethodId) {
        let Some((uid, code_off, _)) = self
            .program
            .methods
            .get(m.0 as usize)
            .and_then(|x| x.resolved())
        else {
            self.bodyless.insert(m);
            return;
        };
        if code_off == 0 {
            self.bodyless.insert(m);
            return;
        }
        if self.config.framework == FrameworkSource::BlackBox
            && self.program.units[uid.0 as usize].role == UnitRole::Framework
        {
            self.bodyless.insert(m);
            self.bodies_skipped += 1;
            return;
        }
        let steps = match self.decode(m) {
            Ok(s) => s,
            Err(()) => {
                self.bodies_failed += 1;
                self.bodyless.insert(m);
                return;
            }
        };
        self.bodies_scanned += 1;
        self.scan_reflection(m, &steps);
        for s in &steps {
            self.scan_step(m, s);
        }
    }

    /// Resolve every `const-string` against the universe and record the verdict.
    fn scan_reflection(&mut self, m: MethodId, steps: &[Step]) {
        for (i, s) in steps.iter().enumerate() {
            if s.op != 0x1a && s.op != 0x1b {
                continue;
            }
            let Arg::Str(lit) = s.arg.clone() else {
                continue;
            };
            self.const_strings += 1;
            let forname = steps
                .get(i + 1)
                .filter(|n| matches!(n.op, 0x71 | 0x77) && n.args.contains(&s.reg))
                .map(|n| &n.arg)
                .is_some_and(is_class_factory);
            let descriptor = class_like_descriptor(&lit);
            let verdict = match (&descriptor, forname) {
                (Some(_), true) => ReflectiveVerdict::ForNameSite,
                (Some(d), false) => match self.program.class(d) {
                    Some(c) if self.program.classes[c.0 as usize].is_defined() => {
                        ReflectiveVerdict::Resolved
                    }
                    _ => ReflectiveVerdict::Unresolved,
                },
                (None, _) => ReflectiveVerdict::NotAClass,
            };
            let target = descriptor
                .as_deref()
                .and_then(|d| self.program.class(d))
                .filter(|c| self.program.classes[c.0 as usize].is_defined());
            if verdict != ReflectiveVerdict::NotAClass {
                if let Some(c) = target {
                    self.add_class(c, EdgeKind::Reflective);
                }
            }
            self.reflective.insert(ReflectiveEdge {
                site: m,
                insn_index: i as u32,
                literal: lit,
                descriptor,
                verdict,
                target,
            });
            if verdict == ReflectiveVerdict::ForNameSite
                && self.config.reflection == ReflectionPolicy::ForNameExpands
            {
                if let Some(c) = target {
                    for (n, p) in entry::overridable_surface(self.program, Some(c)) {
                        if let Some(t) = self.program.lookup(c, &n, &p) {
                            self.add_with_vtable(t);
                        }
                    }
                }
            }
        }
    }

    fn scan_step(&mut self, from: MethodId, s: &Step) {
        match s.op {
            0x6e | 0x74 | 0x72 | 0x78 | 0x6f | 0x75 => self.scan_invoke(from, s, EdgeKind::Virtual),
            0x70 | 0x76 | 0x71 | 0x77 => self.scan_invoke(from, s, EdgeKind::Direct),
            0xfa | 0xfb => self.scan_invoke(from, s, EdgeKind::Polymorphic),
            0xfc | 0xfd => {
                self.custom.insert(from);
            }
            0x22 => {
                // `new-instance`: the one instruction that proves a type is
                // allocated, and therefore the whole basis of RTA.
                if let Some(t) = s.arg.as_type() {
                    if let Some(c) = self.lookup_or_note(t) {
                        self.instantiated.insert(c);
                        self.add_class(c, EdgeKind::Type);
                    }
                }
            }
            0x24 | 0x25 => {
                if let Some(t) = s.arg.as_type() {
                    if let Some(c) = self.lookup_or_note(t) {
                        self.instantiated.insert(c);
                        self.add_class(c, EdgeKind::Type);
                    }
                }
            }
            0x1c | 0x1f | 0x20 | 0x23 | 0x52..=0x6d => {
                if let Some(t) = s.arg.as_type() {
                    if let Some(c) = self.lookup_or_note(t) {
                        self.add_class(c, EdgeKind::Type);
                    }
                }
            }
            _ => {}
        }
    }

    fn lookup_or_note(&mut self, descriptor: &str) -> Option<ClassId> {
        match self.program.class(descriptor) {
            Some(c) => Some(c),
            None => {
                self.program.note_class_use(descriptor);
                None
            }
        }
    }

    fn scan_invoke(&mut self, from: MethodId, s: &Step, kind: EdgeKind) {
        let Arg::Method { class, name, proto } = s.arg.clone() else {
            return;
        };
        let Some(cid) = self.lookup_or_note(&class) else {
            return;
        };
        let (nid, pid) = (
            self.program.strings.intern(&name),
            self.program.strings.intern(&proto),
        );
        self.add_class(cid, EdgeKind::Type);
        if kind == EdgeKind::Polymorphic {
            self.polymorphic.insert(from);
        }
        if kind == EdgeKind::Virtual {
            self.virtual_sites.insert((from, cid, nid, pid));
            for t in self.virtual_targets(cid, nid, pid) {
                self.add_method(t);
                self.push_edge(from, t, EdgeKind::Virtual);
            }
            return;
        }
        match self.program.method(cid, nid, pid) {
            Some(m) => {
                if self.program.methods[m.0 as usize].is_bodyless() {
                    self.bodyless.insert(m);
                    self.bodyless_called.insert(m);
                    self.push_edge(from, m, EdgeKind::Hostcall);
                }
                if self.add_method(m) {
                    self.push_edge(from, m, kind);
                }
            }
            None => {
                // A method reference no declaration in the universe backs.
                // `AbstractMethodError` or `NoSuchMethodError` territory; the
                // report counts the class as unresolved so it is visible.
                self.program.note_class_use(&class);
            }
        }
    }
}

/// True for the two static `String -> Class` factories an app reaches
/// immediately after a `const-string`: `Class.forName` and
/// `ClassLoader.loadClass`.
fn is_class_factory(arg: &Arg) -> bool {
    let Arg::Method { class, name, .. } = arg else {
        return false;
    };
    (class == "Ljava/lang/Class;" && name == "forName")
        || (class == "Ljava/lang/ClassLoader;" && name == "loadClass")
}

/// The element type of an array type descriptor, or the type itself.
fn array_element(descriptor: &str) -> String {
    descriptor
        .strip_prefix('[')
        .unwrap_or(descriptor)
        .to_string()
}

/// Split `Lcom/x/Y;.onCreate(Landroid/os/Bundle;)V` into its parts.
pub fn parse_method_string(s: &str) -> Option<(String, String, String)> {
    let (class, rest) = s.split_once('.')?;
    if !class.starts_with('L') || !class.ends_with(';') {
        return None;
    }
    let open = rest.find('(')?;
    Some((
        class.to_string(),
        rest[..open].to_string(),
        rest[open..].to_string(),
    ))
}

/// Split `onCreate(Landroid/os/Bundle;)V` into its name and prototype.
pub fn split_signature(s: &str) -> Option<(&str, &str)> {
    let open = s.find('(')?;
    Some((&s[..open], &s[open..]))
}

/// Normalise a string constant to a class descriptor if it plausibly names
/// one, or `None` if it plainly does not.
///
/// Deliberately conservative about what it *rejects* and liberal about what it
/// *accepts*: a false positive costs a spurious class edge, a false negative
/// hides a reflective edge `IR.md` requires be counted. The cost of that choice
/// is not hidden — it is the `Unresolved` bucket in the report, and its size is
/// the size of the analysis's ignorance.
pub fn class_like_descriptor(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() || s.len() > 512 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    if s.starts_with('L') && s.ends_with(';') && s.len() > 2 {
        let inner = &s[1..s.len() - 1];
        if inner.contains('/') && inner.chars().all(is_descriptor_char) {
            return Some(s.to_string());
        }
        return None;
    }
    let sep = if s.contains('/') {
        '/'
    } else if s.contains('.') {
        '.'
    } else {
        return None;
    };
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() < 2 || !parts.iter().all(|p| is_java_identifier(p)) {
        return None;
    }
    // A two-segment slashed name is a file path far more often than a class.
    if sep == '/' && parts.len() < 3 {
        return None;
    }
    Some(format!("L{};", parts.join("/")))
}

fn is_descriptor_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '/' | '<' | '>' | '-')
}

fn is_java_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    let head_ok =
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$');
    head_ok && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Everything a caller must hand the analyzer, gathered in one place.
#[derive(Debug)]
pub struct Job {
    pub inputs: Vec<DexInput>,
    pub manifest: Manifest,
    pub config: Config,
}

impl Job {
    /// Build the universe and run the fixpoint.
    pub fn run(&self) -> Result<(Program, Closure), model::ReachError> {
        let mut program = Program::build(self.inputs.clone())?;
        let entry = entry::entry_points(
            &program,
            &self.manifest,
            self.config.entry,
            self.config.widen_to_full_surface,
        );
        let analyzer = Analyzer::new(&mut program, self.config.clone());
        let mut closure = analyzer.run(&entry);
        closure.unresolved_classes = program
            .unresolved_classes
            .iter()
            .map(|(d, _)| d.clone())
            .collect();
        Ok((program, closure))
    }
}

/// Split an APK into app units plus its manifest.
pub fn app_inputs_from_apk(
    apk: &[u8],
) -> Result<(Vec<DexInput>, Option<Vec<u8>>), model::ReachError> {
    let ar = crate::reach::zip::ZipArchive::open(apk).map_err(|e| model::ReachError::Zip {
        unit: "apk".into(),
        source: e,
    })?;
    let mut names: Vec<String> = ar
        .entries()
        .iter()
        .filter(|e| is_classes_dex(&e.name))
        .map(|e| e.name.clone())
        .collect();
    names.sort_by_key(|n| dex_rank(n));
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let Some(e) = ar.find(&n) else { continue };
        let bytes = ar.read(apk, e).map_err(|source| model::ReachError::Zip {
            unit: n.clone(),
            source,
        })?;
        out.push(DexInput::new(n, UnitRole::App, bytes));
    }
    let manifest = ar
        .find("AndroidManifest.xml")
        .and_then(|e| ar.read(apk, e).ok());
    Ok((out, manifest))
}

/// Pull every `classes*.dex` member out of a boot-classpath jar.
pub fn framework_inputs_from_jar(
    jar: &[u8],
    unit_name: &str,
) -> Result<Vec<DexInput>, model::ReachError> {
    let ar = crate::reach::zip::ZipArchive::open(jar).map_err(|e| model::ReachError::Zip {
        unit: unit_name.to_string(),
        source: e,
    })?;
    let mut names: Vec<String> = ar
        .entries()
        .iter()
        .filter(|e| is_classes_dex(&e.name))
        .map(|e| e.name.clone())
        .collect();
    names.sort_by_key(|n| dex_rank(n));
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let Some(e) = ar.find(&n) else { continue };
        let bytes = ar.read(jar, e).map_err(|source| model::ReachError::Zip {
            unit: n.clone(),
            source,
        })?;
        out.push(DexInput::new(
            format!("{unit_name}!{n}"),
            UnitRole::Framework,
            bytes,
        ));
    }
    Ok(out)
}

fn is_classes_dex(name: &str) -> bool {
    if !name.ends_with(".dex") {
        return false;
    }
    let stem = name
        .trim_end_matches(".dex")
        .rsplit('/')
        .next()
        .unwrap_or(name);
    if stem == "classes" {
        return true;
    }
    match stem.strip_prefix("classes") {
        Some(rest) => !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}

fn dex_rank(name: &str) -> u32 {
    let stem = name
        .trim_end_matches(".dex")
        .rsplit('/')
        .next()
        .unwrap_or(name);
    stem.strip_prefix("classes")
        .and_then(|r| r.parse::<u32>().ok())
        .unwrap_or(1)
}

/// The role a method's winning body comes from.
pub fn role_of(program: &Program, m: MethodId) -> UnitRole {
    program
        .methods
        .get(m.0 as usize)
        .and_then(|x| x.resolved())
        .map(|(u, _, _)| program.units[u.0 as usize].role)
        .unwrap_or(UnitRole::App)
}

/// A one-line label for the closure, printed at the top of every report.
#[derive(Debug, Clone)]
pub struct ClosureLabel {
    pub app: String,
    pub entry_policy: &'static str,
    pub dispatch: &'static str,
    pub framework: &'static str,
    pub reflection: &'static str,
    pub window: String,
}

impl fmt::Display for ClosureLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} | entry: {} | {} | {} | {} | window: {}",
            self.app,
            self.entry_policy,
            self.dispatch,
            self.framework,
            self.reflection,
            self.window
        )
    }
}

pub use entry::{Component, ComponentKind, EntryPolicy, EntrySet, Manifest};
pub use model::{ClassId as ReachClassId, DexInput, MethodInfo, Program as Universe, UnitId, UnitRole};
pub use report::{ClosureReport, Figure, Provenance};
pub use validate::{validate_against_trace, ValidationReport};

#[cfg(test)]
mod unit {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn class_like_descriptor_accepts_real_names() {
        assert_eq!(
            class_like_descriptor("Landroid/app/Activity;").as_deref(),
            Some("Landroid/app/Activity;")
        );
        assert_eq!(
            class_like_descriptor("android.app.Activity").as_deref(),
            Some("Landroid/app/Activity;")
        );
        assert_eq!(
            class_like_descriptor("android.view.View$OnClickListener").as_deref(),
            Some("Landroid/view/View$OnClickListener;")
        );
    }

    #[test]
    fn class_like_descriptor_rejects_non_names() {
        for s in [
            "",
            "  ",
            "hello world",
            "3.14",
            "v1.2.3",
            "https://example.com/a",
            "a/b",
            "SELECT * FROM t",
            "12:30:45",
            "Landroid app Activity;",
        ] {
            assert_eq!(
                class_like_descriptor(s),
                None,
                "{s:?} must not be class-shaped"
            );
        }
    }

    #[test]
    fn dotted_conversion_matches_the_trace_convention() {
        assert_eq!(
            descriptor_to_dotted("Landroid/app/Activity;"),
            "android.app.Activity"
        );
        assert_eq!(descriptor_to_dotted("I"), "I");
        assert!(is_framework_descriptor("Landroid/app/Activity;"));
        assert!(is_framework_descriptor("Ljava/lang/String;"));
        assert!(!is_framework_descriptor("Leu/quelltext/gita/MainActivity;"));
        assert!(!is_framework_descriptor("Lcom/android/settings/Settings;"));
        assert!(is_framework_descriptor(
            "Lcom/android/internal/os/ZygoteInit;"
        ));
    }

    #[test]
    fn method_strings_split_correctly() {
        let (c, n, p) =
            parse_method_string("Landroid/app/Activity;.onCreate(Landroid/os/Bundle;)V")
                .expect("split");
        assert_eq!(c, "Landroid/app/Activity;");
        assert_eq!(n, "onCreate");
        assert_eq!(p, "(Landroid/os/Bundle;)V");
        assert!(parse_method_string("garbage").is_none());
        assert_eq!(
            split_signature("onCreate(Landroid/os/Bundle;)V"),
            Some(("onCreate", "(Landroid/os/Bundle;)V"))
        );
        assert_eq!(split_signature("nope"), None);
    }

    #[test]
    fn array_element_strips_one_bracket() {
        // `filled-new-array` only ever creates one-dimensional arrays, so one
        // strip is the whole job. A multi-dimensional descriptor here is
        // corrupt, and leaving the extra bracket is a visible signal rather
        // than a silent one.
        assert_eq!(array_element("[Ljava/lang/Object;"), "Ljava/lang/Object;");
        assert_eq!(array_element("[I"), "I");
        assert_eq!(array_element("[[I"), "[I");
        assert_eq!(array_element("I"), "I");
    }
}
