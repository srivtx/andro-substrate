//! The universe reachability is computed over: loaded DEX, indexed.
//!
//! # What a "universe" is here
//!
//! IR.md's reachability rule says an `invoke-virtual` reaches "every
//! implementor of C present in the loaded DEX". That phrase is doing a lot of
//! work, because for a substrate the loaded DEX is *two different things at
//! once*:
//!
//! * the **app's** DEX, which we fully control, and
//! * the **framework's** DEX, which on a real device is the boot classpath
//!   (`BOOTCLASSPATH`, 30 jars and 34 `classes*.dex` on the Android 13 image
//!   this project measures on) and which the project's own architecture
//!   replaces with *generated host stubs*.
//!
//! Both are modelled here, tagged by [`UnitRole`], because the difference
//! between them is the project's single largest threat to validity: a
//! property of the app and a property of the host look identical in a method
//! trace, and the only place they can be told apart is at this boundary.
//!
//! # Superseeding
//!
//! A class name can be declared by more than one unit. On a real device the
//! boot classpath is the *parent* of the app class loader, so a framework
//! definition wins — which is also IR.md's "host > app" supersede rule. This
//! module implements that, and **records every shadowing event** rather than
//! silently preferring one, as IR.md requires.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use dexcore::error::Error as DexError;
use dexcore::model::access;
use dexcore::reader::DexReader;

/// Why a unit is in the universe, which decides both supersede precedence and
/// how a method in it is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnitRole {
    /// Platform code. The host replaces it; a substrate never ships it.
    Framework,
    /// The application's own code. We compile or interpret all of it.
    App,
}

impl UnitRole {
    /// Lower sorts first and therefore wins a supersede contest.
    pub fn precedence(self) -> u8 {
        match self {
            UnitRole::Framework => 0,
            UnitRole::App => 1,
        }
    }

    /// Name as printed in the report.
    pub fn as_str(self) -> &'static str {
        match self {
            UnitRole::Framework => "framework",
            UnitRole::App => "app",
        }
    }
}

/// Index of a class in [`Program::classes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId(pub u32);

/// Index of a method in [`Program::methods`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MethodId(pub u32);

/// Index of a loaded DEX unit in [`Program::units`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub u32);

/// Everything that can go wrong building a universe.
#[derive(Debug)]
pub enum ReachError {
    /// A unit's bytes are not a DEX this reader accepts.
    Dex { unit: String, source: DexError },
    /// The same unit name was loaded twice.
    DuplicateUnit(String),
    /// A zip structure was malformed.
    Zip {
        unit: String,
        source: crate::reach::zip::ZipError,
    },
}

impl fmt::Display for ReachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReachError::Dex { unit, source } => write!(f, "reach: {unit}: {source}"),
            ReachError::DuplicateUnit(u) => write!(f, "reach: unit {u} loaded twice"),
            ReachError::Zip { unit, source } => write!(f, "reach: {unit}: {source}"),
        }
    }
}

impl std::error::Error for ReachError {}

/// One `classes*.dex` handed to the builder.
#[derive(Debug, Clone)]
pub struct DexInput {
    /// Display name, e.g. `classes.dex` or `framework.jar!classes2.dex`.
    pub name: String,
    /// Whether this is platform or application code.
    pub role: UnitRole,
    /// The raw container.
    pub bytes: Vec<u8>,
}

impl DexInput {
    /// Convenience constructor.
    pub fn new(name: impl Into<String>, role: UnitRole, bytes: Vec<u8>) -> DexInput {
        DexInput {
            name: name.into(),
            role,
            bytes,
        }
    }
}

/// A method as one unit declares it.
#[derive(Debug, Clone, Copy)]
pub struct DeclaredMethod {
    /// Interned name.
    pub name: u32,
    /// Interned prototype, in descriptor form, `(Ljava/lang/String;)V`.
    pub proto: u32,
    /// `access_flags`.
    pub flags: u32,
    /// Offset of the `code_item`, or 0 when abstract or native.
    pub code_off: u32,
}

/// A field as one unit declares it.
#[derive(Debug, Clone, Copy)]
pub struct DeclaredField {
    pub name: u32,
    pub type_id: u32,
    pub flags: u32,
}

/// One unit's `class_def` for a class.
#[derive(Debug, Clone)]
pub struct ClassDecl {
    /// Which unit this declaration came from.
    pub unit: UnitId,
    pub flags: u32,
    pub superclass: Option<ClassId>,
    pub interfaces: Vec<ClassId>,
    pub methods: Vec<DeclaredMethod>,
    pub fields: Vec<DeclaredField>,
}

impl ClassDecl {
    /// True when a subclass could override one of this class's methods.
    pub fn is_inheritable(&self) -> bool {
        self.flags & access::ACC_FINAL == 0
    }
}

/// A class in the universe, whether or not any unit defines it.
#[derive(Debug, Clone, Default)]
pub struct ClassInfo {
    /// Interned descriptor, e.g. `Landroid/app/Activity;`.
    pub descriptor: u32,
    /// Every declaration, sorted so the winner is first.
    pub decls: Vec<ClassDecl>,
    /// Union of the methods any declaration introduces, as `(name, proto)`.
    pub declared: Vec<(u32, u32)>,
    /// Direct subtypes, filled in by [`Program::index_hierarchy`].
    pub children: Vec<ClassId>,
}

impl ClassInfo {
    /// The declaration that wins supersede, or `None` if no unit defines it.
    pub fn resolved(&self) -> Option<&ClassDecl> {
        self.decls.first()
    }

    /// True when at least one unit defines this class.
    pub fn is_defined(&self) -> bool {
        !self.decls.is_empty()
    }

    /// True when the winning declaration is an interface.
    pub fn is_interface(&self) -> bool {
        self.resolved()
            .is_some_and(|d| d.flags & access::ACC_INTERFACE != 0)
    }

    /// True when the winning declaration is abstract.
    pub fn is_abstract(&self) -> bool {
        self.resolved()
            .is_some_and(|d| d.flags & access::ACC_ABSTRACT != 0)
    }
}

/// A method identity and every body that claims to be it.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    /// The class that declares it — not necessarily the class that defines the
    /// winning body.
    pub class: ClassId,
    pub name: u32,
    pub proto: u32,
    /// `(unit, code_off, flags)`, sorted by supersede precedence.
    pub bodies: Vec<(UnitId, u32, u32)>,
}

impl MethodInfo {
    /// The body that would actually execute, following host > app.
    pub fn resolved(&self) -> Option<(UnitId, u32, u32)> {
        self.bodies.first().copied()
    }

    /// True when every declaration is `native` or the method is `abstract`, so
    /// no DEX body exists and the host must supply one.
    pub fn is_bodyless(&self) -> bool {
        self.bodies.iter().all(|(_, off, flags)| {
            *off == 0 || flags & (access::ACC_NATIVE | access::ACC_ABSTRACT) != 0
        })
    }

    /// True when the winning declaration is `ACC_NATIVE`.
    pub fn is_native(&self) -> bool {
        self.resolved()
            .is_some_and(|(_, _, f)| f & access::ACC_NATIVE != 0)
    }

    /// True when a subclass is allowed to override it: not `static`, not
    /// `private`, not `final`, and not a constructor.
    pub fn is_overridable(&self) -> bool {
        let Some((_, _, f)) = self.resolved() else {
            return false;
        };
        f & (access::ACC_STATIC | access::ACC_PRIVATE | access::ACC_FINAL) == 0
            && f & access::ACC_CONSTRUCTOR == 0
    }
}

/// One loaded unit.
#[derive(Debug, Clone)]
pub struct Unit {
    pub id: UnitId,
    pub name: String,
    pub role: UnitRole,
    /// The raw container, kept so method bodies can be decoded lazily. Holding
    /// the bytes rather than the reader is what makes a self-referential
    /// `Program` unnecessary.
    bytes: Vec<u8>,
    /// Header-reported counts, recorded as measured figures in the report.
    pub method_ids: u32,
    pub class_defs: u32,
}

impl Unit {
    /// A reader over this unit. Cheap: `open` parses a 0x70-byte header.
    pub fn reader(&self) -> Result<DexReader<'_>, DexError> {
        DexReader::open(&self.bytes)
    }
}

/// A string interner. Descriptors, method names and prototypes are all
/// interned so the fixpoint can work on `u32` rather than `String`.
#[derive(Debug, Default)]
pub struct Interner {
    map: HashMap<Arc<str>, u32>,
    items: Vec<Arc<str>>,
}

impl Interner {
    /// Intern a string, returning its id.
    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let arc: Arc<str> = Arc::from(s);
        let id = self.items.len() as u32;
        self.map.insert(Arc::clone(&arc), id);
        self.items.push(arc);
        id
    }

    /// The string behind an id, or `""` for an id that was never issued.
    pub fn get(&self, id: u32) -> &str {
        self.items
            .get(id as usize)
            .map(|s| s.as_ref())
            .unwrap_or("")
    }

    /// The id of an already-interned string, without interning it.
    pub fn get_id(&self, s: &str) -> Option<u32> {
        self.map.get(s).copied()
    }

    /// How many distinct strings are interned.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when nothing is interned.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The indexed universe.
#[derive(Debug, Default)]
pub struct Program {
    pub strings: Interner,
    pub classes: Vec<ClassInfo>,
    pub units: Vec<Unit>,
    class_index: HashMap<String, ClassId>,
    method_index: HashMap<(ClassId, u32, u32), MethodId>,
    pub methods: Vec<MethodInfo>,
    /// `(name, proto)` lookup inside one class, for override and override-of
    /// queries.
    by_class: HashMap<ClassId, HashMap<(u32, u32), MethodId>>,
    /// Memoised transitive subtype sets, filled in by
    /// [`Program::transitive_subtypes`].
    subtype_cache: HashMap<ClassId, Arc<[ClassId]>>,
    /// A class name declared by more than one unit: `(descriptor, [units])`.
    pub shadowed: Vec<(String, Vec<String>)>,
    /// A class referenced but defined by no unit: `(descriptor, [users])`.
    pub unresolved_classes: Vec<(String, u32)>,
}

impl Program {
    /// Index a set of units.
    ///
    /// This is the expensive half of reachability — it reads every `class_def`
    /// of every unit — and it is deliberately *not* the part that walks method
    /// bodies. Bodies are decoded on demand by [`Program::body`], so a universe
    /// that is never queried for a method costs nothing for that method.
    pub fn build(inputs: Vec<DexInput>) -> Result<Program, ReachError> {
        let mut p = Program::default();
        let mut seen: HashMap<String, ()> = HashMap::new();

        for input in inputs {
            if seen.insert(input.name.clone(), ()).is_some() {
                return Err(ReachError::DuplicateUnit(input.name.clone()));
            }
            p.add_unit(&input)?;
        }

        p.index_hierarchy();
        p.index_methods();
        Ok(p)
    }

    fn add_unit(&mut self, input: &DexInput) -> Result<(), ReachError> {
        let reader = DexReader::open(&input.bytes).map_err(|e| ReachError::Dex {
            unit: input.name.clone(),
            source: e,
        })?;
        let uid = UnitId(self.units.len() as u32);
        self.units.push(Unit {
            id: uid,
            name: input.name.clone(),
            role: input.role,
            method_ids: reader.header().method_ids_size,
            class_defs: reader.header().class_defs_size,
            bytes: input.bytes.clone(),
        });

        let mut classes = reader.classes().map_err(|e| ReachError::Dex {
            unit: input.name.clone(),
            source: e,
        })?;
        classes.sort_by_key(|c| c.descriptor.clone());
        for c in &classes {
            self.intern_class(&c.descriptor);
        }

        for c in classes {
            let cid = match self.intern_class(&c.descriptor) {
                Some(id) => id,
                None => continue,
            };
            let superclass = if c.superclass.is_empty() {
                None
            } else {
                self.intern_class(&c.superclass)
            };
            let interfaces: Vec<ClassId> = c
                .interfaces
                .iter()
                .filter_map(|i| self.intern_class(i))
                .collect();
            let (methods, fields) = match &c.class_data {
                None => (Vec::new(), Vec::new()),
                Some(cd) => {
                    let mut ms =
                        Vec::with_capacity(cd.direct_methods.len() + cd.virtual_methods.len());
                    for em in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                        let Ok(m) = reader.method_at(em.method_idx) else {
                            continue;
                        };
                        let name = self.strings.intern(&m.name);
                        // `DexMethod::signature()` is fully qualified
                        // (`Lclass;.name(sig)ret`). Interning *that* would make
                        // every prototype unique per class, so a lookup by the
                        // bare `(sig)ret` an instruction or a manifest names
                        // would silently miss. The bare form is the one DEX
                        // `proto_id`s are keyed by and the one this module
                        // reports.
                        let proto = self.strings.intern(&bare_proto(&m));
                        ms.push(DeclaredMethod {
                            name,
                            proto,
                            flags: em.access_flags,
                            code_off: em.code_off,
                        });
                    }
                    let mut fs = Vec::new();
                    for ef in cd.static_fields.iter().chain(cd.instance_fields.iter()) {
                        let Ok(f) = reader.field_at(ef.field_idx) else {
                            continue;
                        };
                        let name = self.strings.intern(&f.name);
                        let ty = self.strings.intern(&f.type_descriptor);
                        fs.push(DeclaredField {
                            name,
                            type_id: ty,
                            flags: ef.access_flags,
                        });
                    }
                    (ms, fs)
                }
            };

            // A body reference drags in the classes named by its prototype and
            // by its declaring class, so the universe is closed over types even
            // before any code is walked.
            for m in &methods {
                for t in descriptor_types(self.strings.get(m.proto)) {
                    self.intern_class(&t);
                }
            }

            for f in &fields {
                let d = self.strings.get(f.type_id).to_string();
                self.intern_class(&d);
            }

            let decl = ClassDecl {
                unit: uid,
                flags: c.access_flags,
                superclass,
                interfaces,
                methods,
                fields,
            };
            let info = &mut self.classes[cid.0 as usize];
            info.descriptor = self.strings.intern(&c.descriptor);
            info.decls.push(decl);
        }

        // Class descriptors can also arrive from `field_id`s and `proto_id`s
        // that no `class_def` mentions, so sweep those too.
        for idx in 0..reader.type_count() {
            if let Ok(t) = reader.type_at(idx) {
                self.intern_class(&t.descriptor);
            }
        }

        self.finalise_unit(uid);
        Ok(())
    }

    /// Sort declarations into supersede order, build the method table and
    /// record shadowing.
    fn finalise_unit(&mut self, _uid: UnitId) {
        let mut shadowed: Vec<(String, Vec<String>)> = Vec::new();
        for info in &mut self.classes {
            if info.decls.len() > 1 {
                info.decls
                    .sort_by_key(|d| (self.units[d.unit.0 as usize].role.precedence(), d.unit.0));
                let names: Vec<String> = info
                    .decls
                    .iter()
                    .map(|d| self.units[d.unit.0 as usize].name.clone())
                    .collect();
                shadowed.push((self.strings.get(info.descriptor).to_string(), names));
            }
            if info.decls.is_empty() {
                continue;
            }
            let declared = info.decls[0]
                .methods
                .iter()
                .map(|m| (m.name, m.proto))
                .collect::<Vec<_>>();
            info.declared = declared;
        }
        self.shadowed = shadowed;
    }

    /// Build the method table. Called by [`Program::build`]; public because a
    /// caller that adds units incrementally needs to re-run it.
    pub fn index_methods(&mut self) {
        for (ci, info) in self.classes.iter().enumerate() {
            let cid = ClassId(ci as u32);
            let mut per_class: HashMap<(u32, u32), MethodId> = HashMap::new();
            for decl in &info.decls {
                for m in &decl.methods {
                    let key = (m.name, m.proto);
                    let mid = *per_class.entry(key).or_insert_with(|| {
                        let id = MethodId(self.methods.len() as u32);
                        self.methods.push(MethodInfo {
                            class: cid,
                            name: m.name,
                            proto: m.proto,
                            bodies: Vec::new(),
                        });
                        id
                    });
                    self.methods[mid.0 as usize]
                        .bodies
                        .push((decl.unit, m.code_off, m.flags));
                }
            }
            if !per_class.is_empty() {
                self.by_class.insert(cid, per_class);
            }
        }
        // Re-key the global map from the same data so it cannot drift.
        self.method_index.clear();
        for (i, m) in self.methods.iter().enumerate() {
            self.method_index
                .insert((m.class, m.name, m.proto), MethodId(i as u32));
        }
        for m in &mut self.methods {
            m.bodies
                .sort_by_key(|(u, _, _)| (self.units[u.0 as usize].role.precedence(), u.0));
        }
    }

    /// Fill `ClassInfo::children` and seed the transitive-subtype cache.
    pub fn index_hierarchy(&mut self) {
        for info in &mut self.classes {
            info.children.clear();
        }
        let mut edges: Vec<(ClassId, ClassId)> = Vec::new();
        for (i, info) in self.classes.iter().enumerate() {
            let cid = ClassId(i as u32);
            for sup in info
                .decls
                .iter()
                .filter(|d| d.unit.0 < u32::MAX)
                .flat_map(|d| d.superclass.into_iter().chain(d.interfaces.iter().copied()))
            {
                edges.push((sup, cid));
            }
        }
        for (sup, sub) in edges {
            self.classes[sup.0 as usize].children.push(sub);
        }
        for info in &mut self.classes {
            info.children.sort_unstable();
            info.children.dedup();
        }
        self.subtype_cache.clear();
    }

    /// Intern a class descriptor, returning its id and whether it is new.
    fn intern_class(&mut self, descriptor: &str) -> Option<ClassId> {
        if descriptor.is_empty() {
            return None;
        }
        if let Some(&id) = self.class_index.get(descriptor) {
            return Some(id);
        }
        let id = ClassId(self.classes.len() as u32);
        let d = self.strings.intern(descriptor);
        self.class_index.insert(descriptor.to_string(), id);
        self.classes.push(ClassInfo {
            descriptor: d,
            ..ClassInfo::default()
        });
        Some(id)
    }

    /// Record a reference to a class descriptor.
    ///
    /// At the moment a body is being scanned the class may or may not have been
    /// interned yet, so this counts every reference and [`Program::unresolved`]
    /// does the defined/undefined split once the universe is complete. A
    /// descriptor that no unit defines is a real finding: at run time the class
    /// loader will fail on it, and a static closure that silently dropped it
    /// would not be able to say so.
    pub fn note_class_use(&mut self, descriptor: &str) {
        if descriptor.is_empty() {
            return;
        }
        if let Some(slot) = self
            .unresolved_classes
            .iter_mut()
            .find(|(d, _)| d == descriptor)
        {
            slot.1 += 1;
        } else {
            self.unresolved_classes.push((descriptor.to_string(), 1));
        }
    }

    /// Referenced descriptors that no unit defines, with their reference
    /// counts, sorted by descriptor.
    pub fn unresolved(&self) -> Vec<(String, u32)> {
        let mut out: Vec<(String, u32)> = self
            .unresolved_classes
            .iter()
            .filter(|(d, _)| {
                self.class_index
                    .get(d)
                    .is_none_or(|&c| !self.classes[c.0 as usize].is_defined())
            })
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Look a class up by descriptor.
    pub fn class(&self, descriptor: &str) -> Option<ClassId> {
        self.class_index.get(descriptor).copied()
    }

    /// The interned string behind an id.
    pub fn str(&self, id: u32) -> &str {
        self.strings.get(id)
    }

    /// The descriptor of a class.
    pub fn descriptor(&self, id: ClassId) -> &str {
        self.strings
            .get(self.classes.get(id.0 as usize).map_or(0, |c| c.descriptor))
    }

    /// The interned descriptor of a class, for building a [`MethodRef`].
    pub fn descriptor_id(&self, id: ClassId) -> u32 {
        self.classes.get(id.0 as usize).map_or(0, |c| c.descriptor)
    }

    /// Look up a method id from its parts.
    pub fn method(&self, class: ClassId, name: u32, proto: u32) -> Option<MethodId> {
        self.method_index.get(&(class, name, proto)).copied()
    }

    /// The interned name of a method.
    pub fn method_name(&self, m: MethodId) -> &str {
        self.strings
            .get(self.methods.get(m.0 as usize).map_or(0, |x| x.name))
    }

    /// The interned prototype of a method.
    pub fn method_proto(&self, m: MethodId) -> &str {
        self.strings
            .get(self.methods.get(m.0 as usize).map_or(0, |x| x.proto))
    }

    /// The declaring class of a method.
    pub fn method_class(&self, m: MethodId) -> ClassId {
        self.methods
            .get(m.0 as usize)
            .map_or(ClassId(0), |x| x.class)
    }

    /// Methods a class declares, as ids.
    pub fn declared_methods(&self, c: ClassId) -> impl Iterator<Item = MethodId> + '_ {
        self.by_class
            .get(&c)
            .map(|m| m.values().copied())
            .into_iter()
            .flatten()
    }

    /// The method a class declares with a given name and prototype, if any.
    pub fn lookup(&self, c: ClassId, name: &str, proto: &str) -> Option<MethodId> {
        let name_id = self.strings.map.get(name)?;
        let proto_id = self.strings.map.get(proto)?;
        self.by_class
            .get(&c)
            .and_then(|m| m.get(&(*name_id, *proto_id)))
            .copied()
    }

    /// The transitive subtypes of a class or interface, memoised.
    ///
    /// A malformed DEX can contain an interface cycle, so this is a worklist
    /// fixpoint rather than a topological sweep: it terminates on a cycle and
    /// the cycle itself is a finding, not a hang.
    pub fn transitive_subtypes(&mut self, c: ClassId) -> Arc<[ClassId]> {
        if let Some(hit) = self.subtype_cache.get(&c) {
            return Arc::clone(hit);
        }
        let mut out: Vec<ClassId> = Vec::new();
        let mut seen: HashMap<ClassId, ()> = HashMap::new();
        let mut stack: Vec<ClassId> = self.classes[c.0 as usize].children.clone();
        while let Some(n) = stack.pop() {
            if seen.insert(n, ()).is_some() {
                continue;
            }
            out.push(n);
            stack.extend(self.classes[n.0 as usize].children.iter().copied());
        }
        out.sort_unstable();
        let arc: Arc<[ClassId]> = Arc::from(out.into_boxed_slice());
        self.subtype_cache.insert(c, Arc::clone(&arc));
        arc
    }

    /// Decode a method body's instruction units, or `None` when it has none.
    pub fn body(&self, m: MethodId) -> Option<Result<Vec<u16>, DexError>> {
        let (uid, code_off, _) = self.methods.get(m.0 as usize)?.resolved()?;
        if code_off == 0 {
            return None;
        }
        let unit = &self.units[uid.0 as usize];
        Some((|| {
            let reader = unit.reader()?;
            let raw = reader.code_units(code_off)?;
            let mut units = Vec::with_capacity(raw.len() / 2);
            for c in raw.chunks_exact(2) {
                units.push(u16::from_le_bytes([c[0], c[1]]));
            }
            Ok(units)
        })())
    }

    /// Every distinct class descriptor in the universe, for namespace
    /// classification. Sorted.
    pub fn all_descriptors(&self) -> Vec<String> {
        let mut v: Vec<String> = self.class_index.keys().cloned().collect();
        v.sort();
        v
    }

    /// Counts that describe the universe itself rather than any closure.
    pub fn totals(&self) -> UniverseTotals {
        UniverseTotals {
            units: self.units.len(),
            app_units: self
                .units
                .iter()
                .filter(|u| u.role == UnitRole::App)
                .count(),
            framework_units: self
                .units
                .iter()
                .filter(|u| u.role == UnitRole::Framework)
                .count(),
            header_method_ids: self.units.iter().map(|u| u.method_ids as usize).sum(),
            header_class_defs: self.units.iter().map(|u| u.class_defs as usize).sum(),
            indexed_classes: self.classes.len(),
            defined_classes: self.classes.iter().filter(|c| c.is_defined()).count(),
            indexed_methods: self.methods.len(),
            shadowed_classes: self.shadowed.len(),
        }
    }
}

/// Size of the universe, all of it measured off the DEX headers or the
/// `class_def` tables rather than estimated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniverseTotals {
    pub units: usize,
    pub app_units: usize,
    pub framework_units: usize,
    pub header_method_ids: usize,
    pub header_class_defs: usize,
    pub indexed_classes: usize,
    pub defined_classes: usize,
    pub indexed_methods: usize,
    pub shadowed_classes: usize,
}

/// The bare prototype of a method: `(Ljava/lang/String;I)V`.
///
/// `DexMethod::signature()` prefixes the defining class and the method name,
/// which is right for a report line and wrong for a lookup key.
pub fn bare_proto(m: &dexcore::model::DexMethod) -> String {
    format!("({}){}", m.parameters.join(""), m.return_type)
}

/// Every class descriptor mentioned by a prototype, in order.
pub fn descriptor_types(proto: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes: Vec<char> = proto.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            'L' => {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] != ';' {
                    j += 1;
                }
                if j < bytes.len() {
                    out.push(bytes[i..=j].iter().collect());
                    i = j + 1;
                } else {
                    break;
                }
            }
            '[' => i += 1,
            _ => i += 1,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn interning_is_stable() {
        let mut i = Interner::default();
        let a = i.intern("Ljava/lang/Object;");
        let b = i.intern("Ljava/lang/Object;");
        let c = i.intern("Ljava/lang/String;");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(i.get(a), "Ljava/lang/Object;");
        assert_eq!(i.len(), 2);
    }

    #[test]
    fn prototype_types_are_extracted() {
        assert_eq!(
            descriptor_types("(Ljava/lang/String;I)V"),
            vec!["Ljava/lang/String;"]
        );
        assert_eq!(
            descriptor_types("([Landroid/content/pm/ApplicationInfo;J)Ljava/lang/Object;"),
            vec!["Landroid/content/pm/ApplicationInfo;", "Ljava/lang/Object;"]
        );
        assert!(descriptor_types("()V").is_empty());
        // A truncated descriptor must not loop or panic.
        assert!(descriptor_types("(Ljava/lang/Str").is_empty());
    }
}
