//! Turning a `classes.dex` into something executable.
//!
//! `dexcore` hands back a faithful, *unresolved* view of the file: pools, class
//! defs, code items. This module does the resolution an interpreter needs and
//! the format deliberately leaves to a runtime:
//!
//! * one class table containing the file's classes, the builtin framework
//!   classes and any phantom placeholders, so `instance-of` is one comparison
//!   ([`ClassId`]);
//! * an instance-field layout per class, superclass-first, so an `iget` of an
//!   inherited field is an index rather than a search;
//! * a real **vtable** per class — the superclass's vtable with overrides
//!   replaced in place and new virtuals appended — so `invoke-virtual` is a
//!   table lookup rather than a walk;
//! * static field initialisers, decoded from `encoded_array`, which dexcore
//!   skips entirely and which is all an `R` class is;
//! * `call_site_id_item` and `method_handle_item`, neither of which dexcore
//!   exposes, so `invoke-custom` can be *resolved* before it is reported as
//!   unsupported;
//! * each method's decoded instruction stream, with a unit-offset index for
//!   branch targets and a decoded try table.
//!
//! # No verifier
//!
//! Nothing here checks register typing, type assignment, or that `move-result`
//! follows a call. That division of labour is deliberate: a verifier is a
//! separate whole-program analysis whose findings are about the *file*, and
//! this study's questions are about *execution*. Where the verifier would have
//! rejected a file outright, the interpreter instead produces a typed
//! [`Malformed`](crate::error::Malformed) error at the point of use, which is
//! strictly more informative than "verification failed" and cannot silently
//! produce a wrong answer.
//!
//! # Ordering
//!
//! The DEX specification requires a superclass to precede its subclass in
//! `class_defs`, and the builtin table is written parents-first, so one pass
//! would usually do. It is not relied on: [`Program::resolve_all`] uses a
//! worklist, and a class whose parents are not ready is re-queued. A cyclic
//! hierarchy — which no real file has — is detected by a re-queue counter and
//! processed anyway, so it produces a defined result rather than a hang.
//!
//! # `encoded_value`
//!
//! The leading nibble is a `VALUE_*` tag and the payload width follows from the
//! tag, not from the encoded byte, which is where a hand-written decoder goes
//! wrong: `VALUE_FLOAT` occupies a `value_arg`-dependent number of *bytes*, and
//! `VALUE_BOOLEAN` occupies one byte whose `value_arg` nibble is the value.
//! [`parse_encoded_array`] implements the table from the specification.

use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

use dexcore::error::Error as DexError;
use dexcore::insn::{Instruction, Payload};
use dexcore::model::access;
use dexcore::mutf8;
use dexcore::reader::DexReader;

use crate::classes;
use crate::error::{ExecError, ExecResult, Malformed, Site};
use crate::heap::ClassId;
use crate::value::JType;

/// Where a class in the combined table came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassSource {
    /// A `class_def_item` in this file.
    Dex(u32),
    /// One of the builtin framework classes.
    Builtin,
    /// Fabricated because nothing declared it.
    Phantom,
    /// Declared by the **framework layer**: a class the shim's own DEX defines.
    ///
    /// Distinct from `Dex` because the difference is the whole boundary. A
    /// `Dex` class has a body and the engine runs it; a `Host` class never has
    /// a body the engine will execute — every one of its methods is
    /// `ACC_NATIVE` with no `code_item`, so a call on it is a call on the host.
    /// Blurring the two is how an instrument ends up running shim code as if it
    /// were the app's, which would make every observation after that point
    /// unattributable.
    Host,
}

impl ClassSource {
    /// True when the class carries bytecode the engine itself will run.
    pub fn has_bytecode(self) -> bool {
        matches!(self, ClassSource::Dex(_))
    }
}

/// A class the framework layer declares, with no bytecode.
///
/// This is the *declaration half* of the supersede boundary described in
/// [`crate::host`] and `docs/decisions/0005-shim-and-observation.md`: the shim's
/// DEX is read for its `class_def_item`s — superclass, interfaces, instance
/// fields, method prototypes — and those are the parts the engine needs in
/// order to lay out a class, build a vtable and resolve a `catch` type. The
/// bodies are never read, because there are none: `shim::emit` marks every
/// method `ACC_NATIVE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostClass {
    /// The type descriptor, e.g. `Landroid/app/Activity;`.
    pub descriptor: String,
    /// Superclass descriptor as declared, or `None` for a root.
    pub superclass: Option<String>,
    /// Directly implemented interface descriptors, as declared.
    pub interfaces: Vec<String>,
    /// `access_flags` from the `class_def_item`.
    pub access_flags: u32,
    /// Instance fields as `(name, type descriptor)`, in declaration order.
    pub instance_fields: Vec<(String, String)>,
    /// Static fields as `(name, type descriptor)`, in declaration order.
    ///
    /// Read for the census, not for a value: a host class's static storage is
    /// the shim's business and is answered by `ShimCaller::read_static`.
    pub static_fields: Vec<(String, String)>,
    /// Methods as `(name, prototype descriptor, access_flags)`, in declaration
    /// order. `access_flags` is preserved so `ACC_STATIC` decides whether a
    /// vtable slot exists and `ACC_ABSTRACT` is preserved so a host can tell an
    /// abstract method from a native one.
    pub methods: Vec<(String, String, u32)>,
    /// Whether any declared method carried a `code_item` in the DEX this was
    /// read from.
    ///
    /// Recorded and then **ignored**: the engine never gives a `ClassSource::Host`
    /// method a `code_off`, so a framework body is unreachable by construction.
    /// The flag exists so the refusal is countable instead of invisible.
    pub has_body: bool,
}

impl HostClass {
    /// Whether the class declares a non-static method with the given prototype.
    pub fn declares(&self, name: &str, signature: &str) -> bool {
        self.methods
            .iter()
            .any(|(n, s, _)| n == name && s == signature)
    }
}

/// An instance field's slot in a class's flat field vector.
#[derive(Clone, Debug)]
pub struct FieldSlot {
    /// `field_ids` index. `u32::MAX` for a builtin field, of which there are
    /// none.
    pub field_idx: u32,
    /// The field's type.
    pub ty: JType,
    /// The field's descriptor text.
    pub descriptor: String,
    /// Register words this field occupies.
    pub slots: usize,
}

/// One vtable slot.
#[derive(Clone, Debug, PartialEq)]
pub enum VTableEntry {
    /// A method with a `code_item` in this file.
    Concrete {
        /// `method_ids` index of the body the vtable resolved to.
        method_idx: u32,
    },
    /// A method with no body: abstract, native, or declared on a class with no
    /// bytecode. Dispatch on one of these goes to the [`Host`].
    ///
    /// [`Host`]: crate::host::Host
    Abstract {
        /// The class that declares it.
        class: ClassId,
        /// The method name.
        name: String,
        /// The prototype descriptor.
        signature: String,
    },
}

/// A resolved class.
#[derive(Clone, Debug)]
pub struct ClassMeta {
    /// The descriptor.
    pub descriptor: String,
    /// The resolved superclass, or `None` for a root.
    pub superclass: Option<ClassId>,
    /// Directly implemented interfaces, resolved.
    pub interfaces: Vec<ClassId>,
    /// The superclass descriptor as written in the file, for diagnostics.
    pub declared_superclass: Option<String>,
    /// Interface descriptors as written in the file, for diagnostics.
    pub declared_interfaces: Vec<String>,
    /// Whether `ACC_INTERFACE` is set.
    pub is_interface: bool,
    /// Where it came from.
    pub source: ClassSource,
    /// `access_flags` from the `class_def_item`; `ACC_PUBLIC` for builtins.
    pub access_flags: u32,

    /// This class's own instance fields, in `class_data` order.
    pub instance_fields: Vec<FieldSlot>,
    /// Total 32-bit words of instance storage, inherited included.
    pub instance_slots: usize,
    /// `static_values` for this class's own static fields, decoded but not yet
    /// materialised (materialising a string needs the heap, which lives in
    /// [`Interpreter`](crate::Interpreter)).
    pub static_defaults: HashMap<u32, EncodedValue>,

    /// Virtual methods in `class_data` order, as `method_ids` indices. This is
    /// the order the specification uses for vtable slots.
    pub virtual_order: Vec<u32>,
    /// The vtable: `(name, signature, entry)`, superclass slots first.
    pub vtable: Vec<(String, String, VTableEntry)>,
    /// `(name, signature)` -> vtable index, inherited entries included.
    pub vtable_index: HashMap<(String, String), u32>,
}

/// A method declaration, resolved.
#[derive(Clone, Debug)]
pub struct MethodDecl {
    /// The declaring class.
    pub class: ClassId,
    /// `method_ids` index.
    pub method_idx: u32,
    /// The method name.
    pub name: String,
    /// The prototype descriptor, e.g. `(I)Ljava/lang/String;`.
    pub signature: String,
    /// `access_flags`.
    pub access_flags: u32,
    /// `code_item` offset, 0 for abstract and native methods.
    pub code_off: u32,
}

impl MethodDecl {
    /// True when the method has bytecode to run.
    pub fn has_code(&self) -> bool {
        self.code_off != 0
    }

    /// True for `ACC_STATIC`.
    pub fn is_static(&self) -> bool {
        self.access_flags & access::ACC_STATIC != 0
    }

    /// True for `ACC_ABSTRACT` or `ACC_NATIVE`.
    pub fn is_unimplemented(&self) -> bool {
        self.access_flags & (access::ACC_ABSTRACT | access::ACC_NATIVE) != 0
    }

    /// Parameter descriptors, `this` excluded.
    pub fn parameters(&self) -> Vec<String> {
        let (params, _) = JType::parse_prototype(&self.signature);
        params.iter().map(|p| p.descriptor()).collect()
    }

    /// The return descriptor.
    pub fn return_type(&self) -> String {
        let (_, r) = JType::parse_prototype(&self.signature);
        r.descriptor()
    }

    /// Register words the incoming arguments occupy, `this` included.
    ///
    /// A `long`/`double` parameter counts as two, which is what decides where
    /// each argument lands in the callee's register window.
    pub fn incoming_slots(&self) -> usize {
        let params: usize = self
            .parameters()
            .iter()
            .map(|p| JType::parse(p).slots().max(1))
            .sum();
        params + usize::from(!self.is_static())
    }

    /// How many *values* a caller has to pass, `this` included.
    ///
    /// This is not [`MethodDecl::incoming_slots`]: a `long` parameter is two
    /// register words but one `Value`, and the arity check has to count the thing
    /// the caller actually supplies. Conflating the two makes every method with
    /// a `long` or `double` parameter unreachable — with a real
    /// `(Context, long, Notification)V` in `fr.smarquis.sleeptimer_16200` as the
    /// witness, where the three-value call was rejected as "4 argument words".
    pub fn incoming_values(&self) -> usize {
        self.parameters().len() + usize::from(!self.is_static())
    }
}

/// One decoded instruction and its position.
#[derive(Clone, Debug)]
pub struct Insn {
    /// Code-unit offset within the method.
    pub unit: u32,
    /// The instruction.
    pub instruction: Instruction,
    /// How many code units this instruction occupies, as *this crate* computed
    /// it.
    ///
    /// Recorded rather than re-derived from
    /// [`Instruction::width`](dexcore::insn::Instruction::width) at run time,
    /// because the run loop's program counter and the linear walk that produced
    /// this list have to agree exactly. Two cases already force the engine to
    /// override what the decoder claims, and both are in
    /// [`Program::decode_code`]:
    ///
    /// * a `32x` instruction (`move/16`, `move-wide/16`, `move-object/16`) is
    ///   encoded in **two** code units — `AA|op BBBB` — while
    ///   `Format::F32X::width()` reports three, because the format's AOSP
    ///   identifier happens to begin with a `3` that is not its width. Taking
    ///   the claim at face value advances the pc one unit too far and
    ///   desynchronises the whole rest of the method, so every branch target
    ///   after it is wrong and the method dies as `missing_return` or
    ///   `bad_branch_target`.
    /// * a data payload's width follows from its own decoded contents, as the
    ///   specification's layouts give.
    ///
    /// The run loop reads this field, so one place decides every width and the
    /// two consumers cannot disagree.
    pub units: u16,
}

/// One clause of an `encoded_catch_handler`.
#[derive(Clone, Debug, PartialEq)]
pub struct CatchClause {
    /// The caught type's descriptor, or `None` for a catch-all.
    pub type_descriptor: Option<String>,
    /// The handler's code-unit address.
    pub address: u32,
}

/// A protected range and its handler list.
#[derive(Clone, Debug, PartialEq)]
pub struct TryRange {
    /// First protected code unit, inclusive.
    pub start: u32,
    /// Last protected code unit, inclusive.
    pub end: u32,
    /// The clauses, in the order they should be tested. The catch-all, if any,
    /// is last, as the encoding requires.
    pub handlers: Vec<CatchClause>,
}

/// A method's decoded instruction stream and its try table.
#[derive(Debug)]
pub struct DecodedCode {
    /// The instructions, in stream order, including payload pseudo-instructions.
    pub insns: Vec<Insn>,
    /// Code-unit offset -> index into `insns`, or [`u32::MAX`] for a unit inside
    /// a payload. Branch targets are validated against this, so a branch into
    /// the middle of a `fill-array-data` payload is reported instead of
    /// decoding nonsense.
    pub unit_index: Vec<u32>,
    /// Protected ranges, in `try_item` order.
    pub tries: Vec<TryRange>,
    /// Total code units in the `code_item`.
    pub units: usize,
    /// The code item's `registers_size`, which is the frame's register count.
    pub registers_size: u16,
    /// The code item's `ins_size`: the width of the incoming-argument window,
    /// at the *end* of the register file.
    pub ins_size: u16,
}

impl DecodedCode {
    /// The index of the instruction starting at `unit`, if there is one.
    pub fn index_of_unit(&self, unit: u32) -> Option<usize> {
        match self.unit_index.get(unit as usize) {
            Some(&i) if i != u32::MAX => Some(i as usize),
            _ => None,
        }
    }
}

/// A `method_handle_item`, decoded.
#[derive(Clone, Debug)]
pub struct MethodHandleMeta {
    /// `METHOD_HANDLE_*`: 0 static, 1 instance, 2 constructor, 3 interface,
    /// 4 field get, 5 field put.
    pub kind: u16,
    /// The referenced `method_ids` index for kinds 0–3.
    pub method_idx: Option<u32>,
    /// The referenced `field_ids` index for kinds 4–5.
    pub field_idx: Option<u32>,
}

/// A `call_site_item`, decoded but not yet materialised.
#[derive(Clone, Debug)]
pub struct CallSiteMeta {
    /// The bootstrap method handle.
    pub handle: MethodHandleMeta,
    /// The bootstrap arguments as `encoded_value`s, in order.
    pub arguments: Vec<EncodedValue>,
}

/// Everything resolved out of one `classes.dex`.
#[derive(Debug)]
pub struct Program {
    /// The classes, indexed by [`ClassId`].
    pub classes: Vec<ClassMeta>,
    /// Descriptor -> class.
    pub by_descriptor: HashMap<String, ClassId>,
    /// The file's string pool, decoded once.
    pub strings: Vec<String>,
    /// `type_ids` index -> descriptor.
    pub types: Vec<String>,
    /// `field_ids` index -> `(class descriptor, name, type descriptor)`.
    pub fields: Vec<(String, String, String)>,
    /// `method_ids` index -> `(class descriptor, name, prototype descriptor)`.
    pub methods: Vec<(String, String, String)>,
    /// Every method the file declares, indexed by `method_ids`.
    pub decls: Vec<Option<MethodDecl>>,
    /// `call_site_ids` item offset and count from the `map_list`.
    call_sites_section: Option<(u32, u32)>,
    /// `method_handles` item offset and count from the `map_list`.
    method_handles_section: Option<(u32, u32)>,
    /// Decoded call sites, by `call_site_ids` index.
    pub call_sites: HashMap<u32, CallSiteMeta>,
    /// Decoded method handles, by `method_handles` index.
    pub method_handles: HashMap<u32, MethodHandleMeta>,
    /// Descriptors of the phantom classes that were fabricated, sorted.
    pub phantoms: Vec<String>,
    /// Classes the framework layer declared, sorted by descriptor.
    pub host_classes: Vec<HostClass>,
    /// Classes the app's own DEX defined **and** the framework layer also
    /// defines, so the shim's definition superseded the app's. Sorted.
    ///
    /// The security property from ADR 0005, made measurable: a non-empty vector
    /// is a list of framework classes an app tried to define, and each one is a
    /// class whose body did not run.
    pub shadowed: Vec<String>,
    /// Declared members of a host class that carried a `code_item`.
    ///
    /// Always empty for a well-formed shim DEX, where every method is
    /// `ACC_NATIVE`. Non-empty means the shim's own DEX has a body the layered
    /// build refused to make executable, which is worth a number rather than a
    /// silent truncation.
    pub host_classes_with_bodies: Vec<String>,
    /// Lazily decoded method bodies, keyed by `code_off`.
    code_cache: HashMap<u32, Rc<DecodedCode>>,
    /// The raw file, for the sections dexcore does not decode.
    bytes: Vec<u8>,
}

impl Program {
    /// Resolve a `classes.dex` into a [`Program`].
    ///
    /// The `map_list` is consulted for `call_site_ids` and `method_handles`,
    /// because a v40 header has no fields for them: they are located by
    /// `map_item` alone, exactly as dexlib2 does it.
    pub fn build(dex: &DexReader<'_>) -> ExecResult<Program> {
        build_program(dex, &[])
    }

    /// Resolve a `classes.dex` with a **framework layer** in front of it.
    ///
    /// This is the supersede boundary (ADR 0005) expressed as a class-table
    /// rule rather than as a merge. `host` supplies the shim's classes; every
    /// app class whose descriptor also appears in `host` is **dropped**, so the
    /// app's own `Landroid/app/Activity;` never becomes a runnable class and
    /// every call on it goes to the host. [`Program::shadowed`] names each one.
    ///
    /// The alternative — merging the two files into one DEX — is not attempted
    /// and is not a container operation; ADR 0005 enumerates the six missing
    /// writer features. This path needs none of them, because it never renumbers
    /// a pool: the app's `method_ids` indices are untouched, and a host method
    /// the app's instructions reference is already in the app's pool as a bodiless
    /// entry, which is exactly how the engine decided to ask a host even before
    /// this existed.
    pub fn build_layered(dex: &DexReader<'_>, host: &[HostClass]) -> ExecResult<Program> {
        build_program(dex, host)
    }
}

/// The one build, with an optional framework layer.
fn build_program(dex: &DexReader<'_>, host: &[HostClass]) -> ExecResult<Program> {
    let mut classes: Vec<ClassMeta> = Vec::new();
    let mut by_descriptor: HashMap<String, ClassId> = HashMap::new();
    let mut shadowed: Vec<String> = Vec::new();

    let push = |classes: &mut Vec<ClassMeta>,
                by_descriptor: &mut HashMap<String, ClassId>,
                descriptor: String,
                source: ClassSource,
                access_flags: u32,
                is_interface: bool| {
        let id = ClassId(classes.len() as u32);
        by_descriptor.insert(descriptor.clone(), id);
        classes.push(ClassMeta {
            descriptor,
            superclass: None,
            interfaces: Vec::new(),
            declared_superclass: None,
            declared_interfaces: Vec::new(),
            is_interface,
            source,
            access_flags,
            instance_fields: Vec::new(),
            instance_slots: 0,
            static_defaults: HashMap::new(),
            virtual_order: Vec::new(),
            vtable: Vec::new(),
            vtable_index: HashMap::new(),
        });
    };

    // The app's own classes first, minus anything the framework layer claims.
    // A `BTreeSet` rather than a linear scan: a real APK's DEX has thousands of
    // `class_def_item`s and a shim has hundreds of classes, so the naive shape
    // is millions of string comparisons before anything runs.
    let shadow_set: BTreeSet<&str> = host.iter().map(|h| h.descriptor.as_str()).collect();
    for i in 0..dex.class_def_count() {
        let def = dex.class_def(i).map_err(dex_err)?;
        if shadow_set.contains(def.descriptor.as_str()) {
            shadowed.push(def.descriptor.clone());
            continue;
        }
        push(
            &mut classes,
            &mut by_descriptor,
            def.descriptor.clone(),
            ClassSource::Dex(i),
            def.access_flags,
            def.access_flags & access::ACC_INTERFACE != 0,
        );
    }
    // Then the framework layer, which therefore wins every collision.
    for h in host {
        push(
            &mut classes,
            &mut by_descriptor,
            h.descriptor.clone(),
            ClassSource::Host,
            h.access_flags,
            h.access_flags & access::ACC_INTERFACE != 0,
        );
    }
    for b in classes::BUILTINS {
        if by_descriptor.contains_key(b.descriptor) {
            // The file — or the framework layer — defines it, and wins: a DEX
            // that declares `Ljava/lang/String;` is unusual but legal, and the
            // file's version is the one the app was compiled against. Under
            // supersede the *framework layer's* version outranks the app's for
            // the same reason it outranks an app's own `Landroid/app/Activity;`.
            continue;
        }
        push(
            &mut classes,
            &mut by_descriptor,
            b.descriptor.to_string(),
            ClassSource::Builtin,
            access::ACC_PUBLIC,
            false,
        );
        // Record the builtin table's own parent as a *declaration*, so the
        // edge-filling pass below resolves it. Without this a builtin is
        // pushed with no superclass at all, and `is_a` answers `false` for
        // every hierarchy question about it -- which shows up as a
        // `catch (Error)` clause silently failing to catch a
        // `NoSuchMethodError` the shim raised.
        let last = classes.len() - 1;
        classes[last].declared_superclass = b.superclass.map(|s| s.to_string());
        classes[last].declared_interfaces = b.interfaces.iter().map(|i| (*i).to_string()).collect();
    }

    let mut p = Program {
        classes,
        by_descriptor,
        strings: Vec::new(),
        types: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        decls: Vec::new(),
        call_sites_section: None,
        method_handles_section: None,
        call_sites: HashMap::new(),
        method_handles: HashMap::new(),
        phantoms: Vec::new(),
        host_classes: host.to_vec(),
        shadowed: {
            shadowed.sort();
            shadowed.dedup();
            shadowed
        },
        host_classes_with_bodies: Vec::new(),
        code_cache: HashMap::new(),
        bytes: dex.bytes().to_vec(),
    };
    p.read_pools(dex).map_err(dex_err)?;
    p.read_class_defs(dex)?;
    p.read_host_classes();
    p.find_invoke_dynamic_sections(dex)?;
    p.link_hierarchy(dex, true);
    p.resolve_all(dex, true)?;
    Ok(p)
}

/// Read a shim DEX's `class_def_item`s into framework-layer declarations.
///
/// The returned `HostClass`es carry **no `code_off`**, by construction: see
/// [`Program::build_layered`]. A `code_item` in the framework DEX is therefore
/// invisible to the engine by design, and [`HostClass::has_body`] says whether
/// one was there so the refusal is a number.
///
/// Reading declarations from a second DEX is a *read*, not a merge: no index
/// from the second file is ever mixed into the first file's operand space, so
/// the app's instructions keep meaning exactly what they meant.
pub fn host_classes_from_dex(shim: &DexReader<'_>) -> ExecResult<Vec<HostClass>> {
    let mut out: Vec<HostClass> = Vec::new();
    for i in 0..shim.class_def_count() {
        let def = shim.class_def(i).map_err(dex_err)?;
        let data = match &def.class_data {
            Some(d) => d,
            None => {
                out.push(HostClass {
                    descriptor: def.descriptor.clone(),
                    superclass: if def.superclass.is_empty() {
                        None
                    } else {
                        Some(def.superclass.clone())
                    },
                    interfaces: def.interfaces.clone(),
                    access_flags: def.access_flags,
                    instance_fields: Vec::new(),
                    static_fields: Vec::new(),
                    methods: Vec::new(),
                    has_body: false,
                });
                continue;
            }
        };
        let mut instance_fields = Vec::new();
        for f in &data.instance_fields {
            let (name, ty) = match shim
                .field_at(f.field_idx)
                .map(|x| (x.name, x.type_descriptor))
            {
                Ok(v) => v,
                Err(_) => continue,
            };
            instance_fields.push((name, ty));
        }
        let mut static_fields = Vec::new();
        for f in &data.static_fields {
            if let Ok(x) = shim.field_at(f.field_idx) {
                static_fields.push((x.name, x.type_descriptor));
            }
        }
        let mut methods = Vec::new();
        let mut has_body = false;
        for m in data
            .direct_methods
            .iter()
            .chain(data.virtual_methods.iter())
        {
            let (name, sig) = match shim.method_at(m.method_idx) {
                Ok(x) => (
                    x.name,
                    format!("({}){}", x.parameters.join(""), x.return_type),
                ),
                Err(_) => continue,
            };
            if m.code_off != 0 {
                has_body = true;
            }
            methods.push((name, sig, m.access_flags));
        }
        out.push(HostClass {
            descriptor: def.descriptor.clone(),
            superclass: if def.superclass.is_empty() {
                None
            } else {
                Some(def.superclass.clone())
            },
            interfaces: def.interfaces.clone(),
            access_flags: def.access_flags,
            instance_fields,
            static_fields,
            methods,
            has_body,
        });
    }
    out.sort_by(|a, b| a.descriptor.cmp(&b.descriptor));
    Ok(out)
}

impl Program {
    fn read_pools(&mut self, dex: &DexReader<'_>) -> dexcore::Result<()> {
        self.strings = dex.strings()?.into_iter().map(|s| s.value).collect();
        self.types = (0..dex.type_count())
            .map(|i| dex.type_name(i))
            .collect::<dexcore::Result<_>>()?;
        self.fields = (0..dex.field_count())
            .map(|i| {
                dex.field_at(i)
                    .map(|f| (f.class, f.name, f.type_descriptor))
            })
            .collect::<dexcore::Result<_>>()?;
        self.methods = (0..dex.method_count())
            .map(|i| {
                dex.method_at(i).map(|m| {
                    let sig = format!("({}){}", m.parameters.join(""), m.return_type);
                    (m.class, m.name, sig)
                })
            })
            .collect::<dexcore::Result<_>>()?;
        self.decls = vec![None; self.methods.len()];
        Ok(())
    }

    /// Copy every `class_def_item`'s field and method lists into the table.
    fn read_class_defs(&mut self, dex: &DexReader<'_>) -> ExecResult<()> {
        for i in 0..dex.class_def_count() {
            let def = dex.class_def(i).map_err(dex_err)?;
            let id = match self.by_descriptor.get(&def.descriptor).copied() {
                Some(id) => id,
                None => continue,
            };
            let data = match &def.class_data {
                Some(d) => d.clone(),
                // A class with no `class_data_item` is legal: a marker
                // interface, or a class referenced only by annotations.
                None => continue,
            };
            {
                if let Some(meta) = self.classes.get_mut(id.0 as usize) {
                    meta.declared_superclass = if def.superclass.is_empty() {
                        None
                    } else {
                        Some(def.superclass.clone())
                    };
                    meta.declared_interfaces = def.interfaces.clone();
                }
            }

            let mut own_fields: Vec<FieldSlot> = Vec::new();
            for f in data.instance_fields.iter() {
                let desc = match self.fields.get(f.field_idx as usize) {
                    Some((_, _, ty)) => ty.clone(),
                    None => continue,
                };
                let ty = JType::parse(&desc);
                own_fields.push(FieldSlot {
                    field_idx: f.field_idx,
                    slots: ty.slots().max(1),
                    ty,
                    descriptor: desc,
                });
            }
            for f in data.static_fields.iter() {
                // Static fields carry no slot; the encoded array is paired with
                // them positionally in `load_class_statics`.
                let _ = f;
            }
            if let Some(meta) = self.classes.get_mut(id.0 as usize) {
                meta.instance_fields = own_fields;
            }

            // Methods: one flat table, plus the virtual ordering the vtable
            // needs. `class_data` orders direct methods before virtual ones, and
            // a `method_ids` index is declared at most once per class, so a
            // single pass over both lists is enough.
            for m in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                let (class_desc, name, sig) = match self.methods.get(m.method_idx as usize) {
                    Some(t) => t.clone(),
                    None => continue,
                };
                let _ = class_desc;
                if let Some(slot) = self.decls.get_mut(m.method_idx as usize) {
                    *slot = Some(MethodDecl {
                        class: id,
                        method_idx: m.method_idx,
                        name,
                        signature: sig,
                        access_flags: m.access_flags,
                        code_off: m.code_off,
                    });
                }
            }
            let virtual_idx: Vec<u32> = data.virtual_methods.iter().map(|m| m.method_idx).collect();
            if let Some(meta) = self.classes.get_mut(id.0 as usize) {
                meta.virtual_order = virtual_idx;
            }
        }
        Ok(())
    }

    /// Locate the `call_site_ids` and `method_handles` sections through the
    /// `map_list`. Neither has a header field.
    fn find_invoke_dynamic_sections(&mut self, dex: &DexReader<'_>) -> ExecResult<()> {
        let map = dex.map_list().map_err(dex_err)?;
        for m in map {
            match m.item_type {
                dexcore::model::map_type::CALL_SITE_ID_ITEM => {
                    self.call_sites_section = Some((m.offset, m.size))
                }
                dexcore::model::map_type::METHOD_HANDLE_ITEM => {
                    self.method_handles_section = Some((m.offset, m.size))
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Copy every framework-layer class's fields and methods into the table.
    ///
    /// Field and method entries are **appended** to the app's pools rather than
    /// replacing anything, so every index an app instruction carries still means
    /// what it meant. A host method therefore lives at an index the app's
    /// bytecode never names — which is correct, because an instruction can only
    /// name a method the app's own `method_ids` already contained, and a
    /// bodiless entry there is exactly what makes the engine ask a host in the
    /// first place.
    ///
    /// Every host method gets `code_off = 0` unconditionally. A `code_item` in
    /// the framework DEX is a body the engine refuses to run, and a host class
    /// that has one is recorded in [`Program::host_classes_with_bodies`] so the
    /// refusal is a number and not a silence.
    fn read_host_classes(&mut self) {
        let layer: Vec<HostClass> = self.host_classes.clone();
        for h in &layer {
            let id = match self.by_descriptor.get(&h.descriptor).copied() {
                Some(id) => id,
                None => continue,
            };
            if h.has_body {
                self.host_classes_with_bodies.push(h.descriptor.clone());
            }
            // A class the app also defined was dropped at push time, so the id
            // found here is always the host's. Belt and braces: a host class the
            // app defined *and* that somehow survived must not have the app's
            // field layout left in place.
            if self.classes.get(id.0 as usize).map(|m| m.source) != Some(ClassSource::Host) {
                continue;
            }
            let mut own_fields: Vec<FieldSlot> = Vec::new();
            for (name, desc) in &h.instance_fields {
                let field_idx = self.intern_field(&h.descriptor, name, desc);
                let ty = JType::parse(desc);
                own_fields.push(FieldSlot {
                    field_idx,
                    slots: ty.slots().max(1),
                    ty,
                    descriptor: desc.clone(),
                });
            }
            // Static fields are declared but not given a slot: a host class's
            // static storage is answered by `ShimCaller::read_static`, and a
            // value invented here would be a fabrication the shim never made.
            let mut virtual_order: Vec<u32> = Vec::new();
            let mut decls: Vec<(u32, String, String, u32)> = Vec::new();
            for (name, sig, flags) in &h.methods {
                let method_idx = self.intern_method(&h.descriptor, name, sig);
                if flags & access::ACC_STATIC == 0 {
                    // Every non-static method goes into the virtual order, in
                    // declaration order. The shim's writer puts its native
                    // methods wherever `class_data` says, and a vtable slot that
                    // a `invoke-virtual` cannot find is a `NoSuchMethodError` the
                    // app would never see on a device.
                    virtual_order.push(method_idx);
                }
                decls.push((method_idx, name.clone(), sig.clone(), *flags));
            }
            for (method_idx, name, sig, flags) in decls {
                if let Some(slot) = self.decls.get_mut(method_idx as usize) {
                    *slot = Some(MethodDecl {
                        class: id,
                        method_idx,
                        name,
                        signature: sig,
                        access_flags: flags,
                        code_off: 0,
                    });
                }
            }

            if let Some(meta) = self.classes.get_mut(id.0 as usize) {
                meta.declared_superclass = h.superclass.clone();
                meta.declared_interfaces = h.interfaces.clone();
                meta.instance_fields = own_fields;
                meta.virtual_order = virtual_order;
                meta.is_interface = h.access_flags & access::ACC_INTERFACE != 0;
            }
        }
    }

    /// Append a `(class, name, type)` triple to the field pool if it is not
    /// already there, and return its index.
    ///
    /// Deduplication matters: the app's own DEX very often declares
    /// `Landroid/os/Build;.SDK_INT` in its `field_ids` because it reads it, and
    /// reusing that index keeps one pool entry per real field instead of two.
    fn intern_field(&mut self, class: &str, name: &str, ty: &str) -> u32 {
        if let Some(i) = self
            .fields
            .iter()
            .position(|(c, n, t)| c == class && n == name && t == ty)
        {
            return i as u32;
        }
        self.fields
            .push((class.to_string(), name.to_string(), ty.to_string()));
        (self.fields.len() - 1) as u32
    }

    /// Append a `(class, name, signature)` triple to the method pool, reusing an
    /// existing entry when the app's DEX already declared it **bodiless**.
    ///
    /// Reuse is the common case and the right one: the app's `method_ids` pool
    /// already contains `(Landroid/app/Activity;, onCreate, (Landroid/os/Bundle;)V)`
    /// for any app that calls `super.onCreate(b)`, and attaching a bodiless
    /// declaration to that entry is what turns the app's `invoke-super` into a
    /// host call instead of a `Malformed`.
    ///
    /// An existing entry that *does* have a body is left alone and a fresh index
    /// is allocated instead. That cannot happen for a shadowed class — its
    /// `class_data` was never read — but "cannot happen" is not a property a
    /// boundary should depend on, and clobbering a runnable method because a
    /// class table changed shape is exactly the failure mode supersede exists to
    /// prevent, in the other direction.
    fn intern_method(&mut self, class: &str, name: &str, signature: &str) -> u32 {
        if let Some(i) = self
            .methods
            .iter()
            .position(|(c, n, s)| c == class && n == name && s == signature)
        {
            let runnable = self
                .decls
                .get(i)
                .and_then(|d| d.as_ref())
                .map(|d| d.has_code())
                .unwrap_or(false);
            if !runnable {
                return i as u32;
            }
        }
        self.methods
            .push((class.to_string(), name.to_string(), signature.to_string()));
        let idx = (self.methods.len() - 1) as u32;
        // `decls` is positional over the method pool, so growing one without the
        // other would leave `decl(idx)` reading whatever the previous entry said.
        self.decls.push(None);
        idx
    }

    /// Resolve superclass and interface descriptors to [`ClassId`]s, creating
    /// phantom classes for anything undeclared.
    fn link_hierarchy(&mut self, dex: &DexReader<'_>, allow_phantom: bool) {
        for i in 0..self.classes.len() {
            let (sup, ifaces) = {
                let meta = match self.classes.get(i) {
                    Some(m) => m,
                    None => continue,
                };
                (
                    meta.declared_superclass.clone(),
                    meta.declared_interfaces.clone(),
                )
            };
            let _ = dex;
            let sup_id = match sup {
                Some(s) => self.class_for(&s, allow_phantom),
                None => None,
            };
            let mut iface_ids = Vec::with_capacity(ifaces.len());
            for s in &ifaces {
                if let Some(id) = self.class_for(s, allow_phantom) {
                    iface_ids.push(id);
                }
            }
            if let Some(meta) = self.classes.get_mut(i) {
                meta.superclass = sup_id;
                meta.interfaces = iface_ids;
            }
        }
        // Builtins whose parent is a builtin that the file also defines, or a
        // phantom created above, need their own edges filled in. Walking the
        // builtin list in order makes each parent available by the time its
        // child is reached.
        for b in classes::BUILTINS {
            let id = match self.by_descriptor.get(b.descriptor).copied() {
                Some(id) => id,
                None => continue,
            };
            let (sup, ifaces, already) = {
                let meta = match self.classes.get(id.0 as usize) {
                    Some(m) => m,
                    None => continue,
                };
                // `already` is "this class's own declaration has been turned
                // into an edge". A class that declared *no* superclass is not
                // already resolved: `Ljava/lang/Object;` is the one descriptor
                // that really has no parent, and every other parentless class is
                // one whose declaration has not been read yet.
                (
                    meta.declared_superclass.clone(),
                    meta.declared_interfaces.clone(),
                    meta.superclass.is_some()
                        || (meta.declared_superclass.is_none()
                            && meta.descriptor == "Ljava/lang/Object;"),
                )
            };
            if already {
                continue;
            }
            let sup_id = sup
                .as_deref()
                .and_then(|s| self.by_descriptor.get(s).copied());
            let iface_ids: Vec<ClassId> = ifaces
                .iter()
                .filter_map(|s| self.by_descriptor.get(s).copied())
                .collect();
            if let Some(meta) = self.classes.get_mut(id.0 as usize) {
                meta.superclass = sup_id;
                meta.interfaces = iface_ids;
            }
        }
    }

    /// Resolve a descriptor to a class, fabricating a phantom if allowed.
    ///
    /// `None` means "this class does not exist and phantoms are disabled",
    /// which the caller turns into
    /// [`Unsupported::ClassNotFound`](crate::error::Unsupported::ClassNotFound).
    pub fn class_for(&mut self, descriptor: &str, allow_phantom: bool) -> Option<ClassId> {
        if let Some(&id) = self.by_descriptor.get(descriptor) {
            return Some(id);
        }
        if !allow_phantom {
            return None;
        }
        let id = self.add_phantom(descriptor);
        // A phantom is not a blank slate. The builtin table is this substrate's
        // model of the framework, and a throwable the shim invents has to sit
        // in it: with `superclass` left as `Object`, a `catch (Error)` clause
        // would not match a `NoSuchMethodError`, and the clause would look wrong
        // when the missing link is here. So the builtin chain is materialised
        // as real class entries, parents included, and each one is recorded as a
        // phantom too rather than pretending the file declared it.
        self.materialise_builtin_chain(descriptor);
        let superclass = crate::classes::lookup(descriptor)
            .map(|b| b.superclass)
            .unwrap_or(Some("Ljava/lang/Object;"))
            .and_then(|s| self.by_descriptor.get(s).copied());
        let interfaces = crate::classes::lookup(descriptor)
            .map(|b| b.interfaces.to_vec())
            .unwrap_or_default()
            .iter()
            .filter_map(|i| self.by_descriptor.get(*i).copied())
            .collect();
        if let Some(meta) = self.classes.get_mut(id.0 as usize) {
            meta.superclass = superclass;
            meta.declared_superclass = Some(
                crate::classes::lookup(descriptor)
                    .and_then(|b| b.superclass)
                    .unwrap_or("Ljava/lang/Object;")
                    .to_string(),
            );
            meta.interfaces = interfaces;
        }
        self.phantoms.push(descriptor.to_string());
        self.phantoms.sort();
        self.phantoms.dedup();
        Some(id)
    }

    /// Add every class in `descriptor`'s builtin ancestry as a phantom.
    ///
    /// Iterative rather than recursive so a table with a cycle in it terminates
    /// instead of overflowing the stack; the `seen` set makes the second visit a
    /// no-op.
    fn materialise_builtin_chain(&mut self, descriptor: &str) {
        const MAX_DEPTH: usize = 64;
        let mut pending = vec![descriptor.to_string()];
        let mut seen: Vec<String> = Vec::new();
        let mut depth = 0usize;
        while let Some(current) = pending.pop() {
            depth += 1;
            if depth > MAX_DEPTH {
                break;
            }
            if seen.contains(&current) {
                continue;
            }
            seen.push(current.clone());
            let builtin = match crate::classes::lookup(&current) {
                Some(b) => b,
                None => continue,
            };
            if let Some(s) = builtin.superclass {
                pending.push(s.to_string());
            }
            for i in builtin.interfaces {
                pending.push((*i).to_string());
            }
            if self.by_descriptor.contains_key(&current) {
                continue;
            }
            self.add_phantom(&current);
        }
    }

    /// Add one class entry with no members, source [`ClassSource::Phantom`].
    ///
    /// The caller is responsible for giving it a superclass and interfaces; a
    /// bare entry is a class that extends nothing, which would make
    /// [`Program::is_a`] answer `false` for every hierarchy question about it.
    fn add_phantom(&mut self, descriptor: &str) -> ClassId {
        let id = ClassId(self.classes.len() as u32);
        self.by_descriptor.insert(descriptor.to_string(), id);
        self.classes.push(ClassMeta {
            descriptor: descriptor.to_string(),
            superclass: None,
            interfaces: Vec::new(),
            declared_superclass: None,
            declared_interfaces: Vec::new(),
            is_interface: false,
            source: ClassSource::Phantom,
            access_flags: access::ACC_PUBLIC,
            instance_fields: Vec::new(),
            instance_slots: 0,
            static_defaults: HashMap::new(),
            virtual_order: Vec::new(),
            vtable: Vec::new(),
            vtable_index: HashMap::new(),
        });
        self.phantoms.push(descriptor.to_string());
        self.phantoms.sort();
        self.phantoms.dedup();
        id
    }

    /// Build field layouts and vtables for every class, parents first.
    ///
    /// A worklist rather than a single pass, because a DEX that resolves a
    /// superclass declared *later* in `class_defs` is malformed but must still
    /// produce a defined result. A class re-queued more than
    /// [`MAX_REQUEUES`] times is part of a cycle and is processed anyway, which
    /// terminates the loop without inventing an answer.
    fn resolve_all(&mut self, dex: &DexReader<'_>, allow_phantom: bool) -> ExecResult<()> {
        const MAX_REQUEUES: u32 = 64;
        let n = self.classes.len();
        let mut done = vec![false; n];
        let mut requeues = vec![0u32; n];
        let mut queue: Vec<ClassId> = (0..n as u32).map(ClassId).rev().collect();
        let mut processed = 0usize;
        while let Some(id) = queue.pop() {
            let i = id.0 as usize;
            if done[i] {
                continue;
            }
            let (sup, ifaces) = {
                let meta = match self.classes.get(i) {
                    Some(m) => m,
                    None => {
                        done[i] = true;
                        continue;
                    }
                };
                (meta.superclass, meta.interfaces.clone())
            };
            let mut missing = Vec::new();
            // A class is missing a parent that has not been laid out yet, which
            // means the parent's index is in range and its `done` flag is still
            // false. Written as one expression so that it cannot be read two ways:
            // the previous form was `if !(i) < n || !done[i] { if !done[i] { .. } }`,
            // whose outer condition was an inverted comparison that only happened
            // to behave because the inner test repeated it.
            if let Some(s) = sup {
                if !done.get(s.0 as usize).copied().unwrap_or(true) {
                    missing.push(s);
                }
            }
            for iface in &ifaces {
                if !done.get(iface.0 as usize).copied().unwrap_or(true) {
                    missing.push(*iface);
                }
            }
            if !missing.is_empty() && requeues[i] < MAX_REQUEUES {
                requeues[i] += 1;
                for m in missing.into_iter().rev() {
                    queue.push(m);
                }
                queue.push(id);
                continue;
            }
            done[i] = true;
            processed += 1;
            self.layout_fields(id, sup, allow_phantom);
            self.layout_vtable(id, ifaces, allow_phantom);
            self.load_class_statics(dex, id);
        }
        debug_assert_eq!(processed, n);
        Ok(())
    }

    fn layout_fields(&mut self, id: ClassId, sup: Option<ClassId>, _allow_phantom: bool) {
        let sup_slots = sup
            .and_then(|s| self.classes.get(s.0 as usize))
            .map(|m| m.instance_slots)
            .unwrap_or(0);
        let own = match self.classes.get(id.0 as usize) {
            Some(m) => m.instance_fields.clone(),
            None => return,
        };
        let total = sup_slots + own.iter().map(|f| f.slots).sum::<usize>();
        if let Some(meta) = self.classes.get_mut(id.0 as usize) {
            meta.instance_slots = total;
        }
    }

    fn layout_vtable(&mut self, id: ClassId, ifaces: Vec<ClassId>, allow_phantom: bool) {
        let mut vtable: Vec<(String, String, VTableEntry)> = Vec::new();
        let mut index: HashMap<(String, String), u32> = HashMap::new();

        // Superclass slots first, then the interfaces' (default methods), then
        // this class's own virtuals. An override replaces the slot in place, so
        // a subclass never changes the vtable layout of its superclass.
        let sup = self.classes.get(id.0 as usize).and_then(|m| m.superclass);
        if let Some(s) = sup {
            if let Some(meta) = self.classes.get(s.0 as usize) {
                for (name, sig, entry) in meta.vtable.iter() {
                    let slot = vtable.len() as u32;
                    index.insert((name.clone(), sig.clone()), slot);
                    vtable.push((name.clone(), sig.clone(), entry.clone()));
                }
            }
        }
        for iface in ifaces {
            let parent = self
                .classes
                .get(iface.0 as usize)
                .map(|m| m.vtable.clone())
                .unwrap_or_default();
            for (name, sig, entry) in parent {
                index.entry((name.clone(), sig.clone())).or_insert_with(|| {
                    let slot = vtable.len() as u32;
                    vtable.push((name.clone(), sig.clone(), entry.clone()));
                    slot
                });
            }
        }
        let order = self
            .classes
            .get(id.0 as usize)
            .map(|m| m.virtual_order.clone())
            .unwrap_or_default();
        for method_idx in order {
            let decl = match self.decls.get(method_idx as usize).and_then(|d| d.as_ref()) {
                Some(d) => d.clone(),
                None => continue,
            };
            let entry = if decl.has_code() {
                VTableEntry::Concrete { method_idx }
            } else {
                VTableEntry::Abstract {
                    class: decl.class,
                    name: decl.name.clone(),
                    signature: decl.signature.clone(),
                }
            };
            let key = (decl.name.clone(), decl.signature.clone());
            match index.get(&key) {
                Some(&slot) => {
                    if let Some(t) = vtable.get_mut(slot as usize) {
                        t.2 = entry;
                    }
                }
                None => {
                    let slot = vtable.len() as u32;
                    index.insert(key, slot);
                    vtable.push((decl.name.clone(), decl.signature.clone(), entry));
                }
            }
        }
        let _ = allow_phantom;
        if let Some(meta) = self.classes.get_mut(id.0 as usize) {
            meta.vtable = vtable;
            meta.vtable_index = index;
        }
    }

    /// Decode this class's `static_values` into `static_defaults`.
    ///
    /// The entries correspond *positionally* to `class_data.static_fields`, so
    /// a file with a different order silently gives every constant the wrong
    /// value — which is why the pairing is positional and asserted by the
    /// fixture test, not by name.
    fn load_class_statics(&mut self, dex: &DexReader<'_>, id: ClassId) {
        let class_idx = match self.classes.get(id.0 as usize) {
            Some(m) => match m.source {
                ClassSource::Dex(i) => i,
                _ => return,
            },
            None => return,
        };
        let (static_values_off, static_field_idxs) = {
            let def = match dex.class_def(class_idx) {
                Ok(d) => d,
                Err(_) => return,
            };
            let idxs: Vec<u32> = def
                .class_data
                .as_ref()
                .map(|d| d.static_fields.iter().map(|f| f.field_idx).collect())
                .unwrap_or_default();
            (def.static_values_off, idxs)
        };
        if static_values_off == 0 || static_field_idxs.is_empty() {
            return;
        }
        let (values, _used) =
            match parse_encoded_array(&self.bytes, static_values_off as usize, self) {
                Ok(v) => v,
                Err(_) => return,
            };
        let mut defaults = HashMap::new();
        for (field_idx, value) in static_field_idxs.into_iter().zip(values) {
            defaults.insert(field_idx, value);
        }
        if let Some(meta) = self.classes.get_mut(id.0 as usize) {
            meta.static_defaults = defaults;
        }
    }

    // ------------------------------------------------------------- queries

    /// Borrow a class, or `None`.
    pub fn class(&self, id: ClassId) -> Option<&ClassMeta> {
        self.classes.get(id.0 as usize)
    }

    /// The [`MethodDecl`] for a `method_ids` index.
    pub fn decl(&self, method_idx: u32) -> Option<&MethodDecl> {
        self.decls.get(method_idx as usize).and_then(|d| d.as_ref())
    }

    /// Does `sub` lie in `sup`'s hierarchy, interfaces included?
    pub fn is_a(&self, sub: ClassId, sup: ClassId) -> bool {
        if sub == sup {
            return true;
        }
        let mut cursor = Some(sub);
        let mut guard = 0u32;
        while let Some(c) = cursor {
            guard += 1;
            if guard > 4096 {
                // A cyclic hierarchy is malformed; refuse rather than spin.
                return false;
            }
            let meta = match self.classes.get(c.0 as usize) {
                Some(m) => m,
                None => return false,
            };
            if meta.superclass == Some(sup) {
                return true;
            }
            for iface in &meta.interfaces {
                if self.is_a(*iface, sup) {
                    return true;
                }
            }
            cursor = meta.superclass;
        }
        false
    }

    /// The slot of a field in a class's flat field vector, searching up the
    /// superclass chain.
    pub fn instance_field_offset(&self, class: ClassId, field_idx: u32) -> Option<(usize, JType)> {
        let mut cursor = Some(class);
        let mut guard = 0u32;
        while let Some(c) = cursor {
            guard += 1;
            if guard > 4096 {
                return None;
            }
            let meta = self.classes.get(c.0 as usize)?;
            let mut base = meta
                .superclass
                .and_then(|s| self.classes.get(s.0 as usize))
                .map(|m| m.instance_slots)
                .unwrap_or(0);
            for f in &meta.instance_fields {
                if f.field_idx == field_idx {
                    return Some((base, f.ty.clone()));
                }
                base += f.slots;
            }
            cursor = meta.superclass;
        }
        None
    }

    /// Find a method by name and prototype on `class`, then up its superclass
    /// chain and across its interfaces.
    ///
    /// This is `invoke-static` and `invoke-direct` resolution. For
    /// `invoke-virtual` the vtable is the authority, because the receiver's
    /// dynamic class decides.
    pub fn find_method(&self, class: ClassId, name: &str, signature: &str) -> Option<&MethodDecl> {
        let mut cursor = Some(class);
        let mut guard = 0u32;
        while let Some(c) = cursor {
            guard += 1;
            if guard > 4096 {
                return None;
            }
            if let Some(found) = self.find_own_method(c, name, signature) {
                return Some(found);
            }
            let meta = self.classes.get(c.0 as usize)?;
            for iface in &meta.interfaces {
                if let Some(found) = self.find_inherited_method(*iface, name, signature, 0) {
                    return Some(found);
                }
            }
            cursor = meta.superclass;
        }
        None
    }

    fn find_inherited_method(
        &self,
        class: ClassId,
        name: &str,
        sig: &str,
        depth: u32,
    ) -> Option<&MethodDecl> {
        if depth > 64 {
            return None;
        }
        if let Some(found) = self.find_own_method(class, name, sig) {
            return Some(found);
        }
        let meta = self.classes.get(class.0 as usize)?;
        for iface in &meta.interfaces {
            if let Some(found) = self.find_inherited_method(*iface, name, sig, depth + 1) {
                return Some(found);
            }
        }
        self.find_inherited_method(meta.superclass?, name, sig, depth + 1)
    }

    /// Find a method declared directly on `class`, ignoring inheritance.
    pub fn find_own_method(
        &self,
        class: ClassId,
        name: &str,
        signature: &str,
    ) -> Option<&MethodDecl> {
        self.classes.get(class.0 as usize)?;
        self.decls
            .iter()
            .flatten()
            .find(|d| d.class == class && d.name == name && d.signature == signature)
    }

    /// Every method declared directly on `class`, in declaration order.
    pub fn own_methods(&self, class: ClassId) -> Vec<&MethodDecl> {
        self.decls
            .iter()
            .flatten()
            .filter(|d| d.class == class)
            .collect()
    }

    /// The `code_item` offset of `class`.`name``signature`, resolved through the
    /// hierarchy, or `None` for a declaration with no body.
    ///
    /// Exposed for the one thing a `Program` consumer cannot otherwise do:
    /// ask *where* a method's bytes are, so a tool can decode them without
    /// running anything. A method's address is not a secret and is not a risk;
    /// the alternative is a re-implementation of the resolver.
    pub fn method_code_offset(&self, class: &str, name: &str, signature: &str) -> Option<u32> {
        let c = self.by_descriptor.get(class).copied()?;
        let d = self.find_method(c, name, signature)?;
        if d.has_code() {
            Some(d.code_off)
        } else {
            None
        }
    }

    /// Every prototype descriptor `class` can be asked for as `name`, including
    /// inherited ones. Sorted and deduplicated.
    ///
    /// A driver, not a verifier: the DEX says `Activity` has two
    /// `onCreate(Bundle)` overloads only in the sense that an app may declare
    /// `onCreate(Bundle)`, `onCreate(Bundle,PersistableBundle)` and
    /// `onCreate(Bundle,PersistableBundle,ProcessState)` and a hard-coded
    /// signature in a lifecycle runner is a lie about which one it called. The
    /// engine can execute a method only when the caller names its real
    /// prototype, so the caller has to be able to ask.
    pub fn prototypes(&self, class: &str, name: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut cursor = self.by_descriptor.get(class).copied();
        let mut guard = 0u32;
        while let Some(c) = cursor {
            guard += 1;
            if guard > 4096 {
                break;
            }
            for d in self.own_methods(c) {
                if d.name == name && !out.contains(&d.signature) {
                    out.push(d.signature.clone());
                }
            }
            cursor = self.classes.get(c.0 as usize).and_then(|m| m.superclass);
        }
        out.sort();
        out
    }

    /// The vtable entry for `(name, signature)` on `class`, inherited
    /// included.
    pub fn vtable_lookup(
        &self,
        class: ClassId,
        name: &str,
        signature: &str,
    ) -> Option<&VTableEntry> {
        let meta = self.classes.get(class.0 as usize)?;
        let slot = meta
            .vtable_index
            .get(&(name.to_string(), signature.to_string()))?;
        meta.vtable.get(*slot as usize).map(|(_, _, e)| e)
    }

    // ---------------------------------------------------------------- code

    /// Decode a method body, caching the result.
    pub fn code(&mut self, dex: &DexReader<'_>, code_off: u32) -> ExecResult<Rc<DecodedCode>> {
        if let Some(c) = self.code_cache.get(&code_off) {
            return Ok(Rc::clone(c));
        }
        let decoded = self.decode_code(dex, code_off)?;
        let rc = Rc::new(decoded);
        self.code_cache.insert(code_off, Rc::clone(&rc));
        Ok(rc)
    }

    fn decode_code(&self, dex: &DexReader<'_>, code_off: u32) -> ExecResult<DecodedCode> {
        let item = dex.code_item(code_off).map_err(dex_err)?;
        if item.insns_size == 0 {
            return Err(malformed(
                Malformed::BadCode,
                format!("code_item at {code_off} has no instructions"),
            ));
        }
        let raw = dex.code_units(code_off).map_err(dex_err)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if units.len() < item.insns_size as usize {
            return Err(malformed(
                Malformed::BadCode,
                "code item is shorter than its insns_size".to_string(),
            ));
        }
        let mut insns = Vec::new();
        let mut unit_index = vec![u32::MAX; item.insns_size as usize];
        let mut at = 0usize;
        while at < item.insns_size as usize {
            let (instruction, mut n) = dexcore::decode_one(&units, at).map_err(dex_err)?;
            // Two widths are recomputed rather than taken from the decoder, and
            // both are documented on `Insn::units`.
            match &instruction {
                // A `32x` instruction is two code units, not the three its
                // format identifier suggests.
                Instruction::F32X { .. } => n = 2,
                // A payload's width is recomputed from its own decoded contents.
                // `dexcore` reports `4 + targets` code units for a packed-switch
                // payload and `2 + 2*keys` for a sparse one, but the specification
                // gives `ident size first_key targets[size]` and
                // `ident size keys[size] targets[size]`, so each 32-bit field is
                // *two* code units: the real widths are `4 + 2*targets` and
                // `2 + 4*keys`. Both are a factor of two short on the array half,
                // and the error is invisible to a linear walk because the remainder
                // of the payload decodes as more instructions and the sum of widths
                // still comes to `insns_size`.
                // `fr.smarquis.sleeptimer_16200` has a real eight-target
                // packed-switch payload in `SleepActionReceiver.onReceive`, which
                // is where this was found.
                Instruction::Payload(p) => {
                    n = match p {
                        Payload::PackedSwitch(s) => 4 + 2 * s.targets.len(),
                        Payload::SparseSwitch(s) => 2 + 4 * s.keys.len(),
                        Payload::FillArrayData(f) => 4 + f.data.len().div_ceil(2),
                    }
                }
                _ => {}
            }
            // A width of zero would stop the walk advancing, so the progress
            // guarantee `decode_all` documents is enforced here as well: the
            // engine's own walk cannot be the thing that loops.
            let units = u16::try_from(n).unwrap_or(u16::MAX).max(1);
            for slot in unit_index.iter_mut().skip(at).take(units as usize) {
                *slot = u32::MAX;
            }
            if let Some(slot) = unit_index.get_mut(at) {
                *slot = insns.len() as u32;
            }
            insns.push(Insn {
                unit: at as u32,
                instruction,
                units,
            });
            at += units as usize;
        }
        let tries = self.decode_tries(dex, &item)?;
        Ok(DecodedCode {
            insns,
            unit_index,
            tries,
            units: item.insns_size as usize,
            registers_size: item.registers_size,
            ins_size: item.ins_size,
        })
    }

    /// Decode a code item's try table and its `encoded_catch_handler_list`.
    ///
    /// dexcore returns the handler list's raw bytes *without* the leading
    /// `uleb128` size prefix, while `try_item.handler_off` is measured from the
    /// start of the list *including* that prefix. The prefix length is
    /// therefore recovered by re-reading it here rather than assumed to be one
    /// byte — which it is not for a list with more than 127 handlers.
    fn decode_tries(
        &self,
        dex: &DexReader<'_>,
        item: &dexcore::model::CodeItem,
    ) -> ExecResult<Vec<TryRange>> {
        if item.tries_size == 0 {
            return Ok(Vec::new());
        }
        // `tries_off` points at the *first* `try_item`, and the handler list --
        // with its `uleb128` size prefix -- only begins after all of them. A
        // `try_item` is 8 bytes, so the prefix lives at
        // `tries_off + 8 * tries_size`; reading the size at `tries_off` itself
        // silently reads the low half of the first item's `start_addr`, which
        // makes every handler look like it sits at unit 0 and sends a caught
        // exception back to the top of its own protected range.
        let list_start = item.tries_off as usize + 8 * item.tries_size as usize;
        let (list_size, prefix) = mutf8::read_uleb128(&self.bytes, list_start).map_err(|_| {
            malformed(
                Malformed::BadCode,
                format!("code item at {}: malformed handler list size", item.offset),
            )
        })?;
        if list_size as usize > item.tries_size as usize {
            return Err(malformed(
                Malformed::BadCode,
                format!(
                    "handler list declares {list_size} handlers for {} try items",
                    item.tries_size
                ),
            ));
        }
        let try_items = dex.try_items(item.offset).map_err(dex_err)?;
        let body_start = list_start.checked_add(prefix).ok_or_else(|| {
            malformed(
                Malformed::BadCode,
                "handler list offset overflows".to_string(),
            )
        })?;
        let body = self.bytes.get(body_start..).ok_or_else(|| {
            malformed(
                Malformed::BadCode,
                "handler list runs past the file".to_string(),
            )
        })?;
        let mut out = Vec::with_capacity(try_items.len());
        for t in &try_items {
            if t.insn_count == 0 {
                return Err(malformed(
                    Malformed::BadCode,
                    "try_item with zero length".to_string(),
                ));
            }
            let end = t
                .start_addr
                .checked_add(t.insn_count)
                .map(|e| e - 1)
                .ok_or_else(|| {
                    malformed(Malformed::BadCode, "try_item range overflows".to_string())
                })?;
            if end >= item.insns_size {
                return Err(malformed(
                    Malformed::BadCode,
                    format!(
                        "try_item range {}-{} runs past the {} units of the code item",
                        t.start_addr, end, item.insns_size
                    ),
                ));
            }
            let rel = (t.handler_off as usize)
                .checked_sub(prefix)
                .ok_or_else(|| {
                    malformed(
                        Malformed::BadCode,
                        format!(
                            "handler_off {} points inside the handler list's own size prefix",
                            t.handler_off
                        ),
                    )
                })?;
            let handlers = decode_catch_handler(body, rel, t.handler_off, dex)?;
            out.push(TryRange {
                start: t.start_addr,
                end,
                handlers,
            });
        }
        Ok(out)
    }

    // -------------------------------------------------------- invoke/custom

    /// Decode a `method_handles` entry, caching it.
    pub fn method_handle(&mut self, index: u32) -> ExecResult<MethodHandleMeta> {
        if let Some(h) = self.method_handles.get(&index) {
            return Ok(h.clone());
        }
        let (off, size) = match self.method_handles_section {
            Some(s) => s,
            None => {
                return Err(unsupported(
                    crate::error::Unsupported::MethodHandleUnresolved,
                    format!(
                    "this dex has no method_handles section, so method_handle@{index} cannot exist"
                ),
                ))
            }
        };
        if index >= size {
            return Err(unsupported(
                crate::error::Unsupported::MethodHandleUnresolved,
                format!("method_handle@{index} is outside the {size}-entry method_handles section"),
            ));
        }
        let at = off as usize + (index as usize) * 8;
        let kind = self.u16_at(at)?;
        let value = self.u32_at(at + 4)?;
        let meta = match kind {
            0..=3 => MethodHandleMeta {
                kind,
                method_idx: Some(value),
                field_idx: None,
            },
            4 | 5 => MethodHandleMeta {
                kind,
                method_idx: None,
                field_idx: Some(value),
            },
            other => {
                return Err(unsupported(
                    crate::error::Unsupported::MethodHandleUnresolved,
                    format!("method_handle@{index} has unknown type {other}"),
                ))
            }
        };
        self.method_handles.insert(index, meta.clone());
        Ok(meta)
    }

    /// Decode a `call_site_ids` entry, caching it.
    pub fn call_site(&mut self, index: u32) -> ExecResult<CallSiteMeta> {
        if let Some(c) = self.call_sites.get(&index) {
            return Ok(c.clone());
        }
        let (off, size) = match self.call_sites_section {
            Some(s) => s,
            None => {
                return Err(unsupported(
                    crate::error::Unsupported::BootstrapMethodMissing,
                    "this dex declares no call_site_ids, so it contains no invokedynamic instruction that could work".to_string(),
                ))
            }
        };
        if index >= size {
            return Err(unsupported(
                crate::error::Unsupported::BootstrapMethodMissing,
                format!("call_site@{index} is outside the {size}-entry call_site_ids section"),
            ));
        }
        let id_off = self.u32_at(off as usize + index as usize * 4)?;
        if id_off == 0 {
            return Err(unsupported(
                crate::error::Unsupported::BootstrapMethodMissing,
                format!("call_site@{index} has a zero call_site_off"),
            ));
        }
        let args_off = self.u32_at(id_off as usize)?;
        let handle_off = self.u32_at(id_off as usize + 4)?;
        if handle_off == 0 {
            return Err(unsupported(
                crate::error::Unsupported::BootstrapMethodMissing,
                format!("call_site@{index} has a zero method_handle_off"),
            ));
        }
        let kind = self.u16_at(handle_off as usize)?;
        let value = self.u32_at(handle_off as usize + 4)?;
        let handle = match kind {
            0..=3 => MethodHandleMeta {
                kind,
                method_idx: Some(value),
                field_idx: None,
            },
            4 | 5 => MethodHandleMeta {
                kind,
                method_idx: None,
                field_idx: Some(value),
            },
            other => {
                return Err(unsupported(
                    crate::error::Unsupported::BootstrapMethodMissing,
                    format!("call_site@{index} has method handle type {other}"),
                ))
            }
        };
        let (arguments, _) = if args_off == 0 {
            (Vec::new(), 0)
        } else {
            parse_encoded_array(&self.bytes, args_off as usize, self)?
        };
        let meta = CallSiteMeta { handle, arguments };
        self.call_sites.insert(index, meta.clone());
        Ok(meta)
    }

    fn u16_at(&self, at: usize) -> ExecResult<u16> {
        let s = self.bytes.get(at..at + 2).ok_or_else(|| {
            malformed(
                Malformed::BadPoolIndex,
                format!("two-byte read at {at} runs past the end of the file"),
            )
        })?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32_at(&self, at: usize) -> ExecResult<u32> {
        let s = self.bytes.get(at..at + 4).ok_or_else(|| {
            malformed(
                Malformed::BadPoolIndex,
                format!("four-byte read at {at} runs past the end of the file"),
            )
        })?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// Decode one `encoded_catch_handler` at byte `rel` within the handler list
/// body. `label` is the `try_item`'s `handler_off`, used only in messages.
pub fn decode_catch_handler(
    list: &[u8],
    rel: usize,
    label: u32,
    dex: &DexReader<'_>,
) -> ExecResult<Vec<CatchClause>> {
    let bad = |d: String| {
        malformed(
            Malformed::BadCode,
            format!("catch handler at handler_off {label}: {d}"),
        )
    };
    if rel >= list.len() {
        return Err(bad("offset is past the end of the handler list".to_string()));
    }
    let (size_signed, n) =
        mutf8::read_sleb128(list, rel).map_err(|_| bad("malformed clause count".to_string()))?;
    let mut p = rel + n;
    let mut clauses = Vec::new();
    // A negative `size` means "n typed clauses *and* a catch-all".
    let typed = size_signed.unsigned_abs() as usize;
    for _ in 0..typed {
        let (type_idx, n) = mutf8::read_uleb128(list, p)
            .map_err(|_| bad("malformed caught type index".to_string()))?;
        p += n;
        let (addr, n) = mutf8::read_uleb128(list, p)
            .map_err(|_| bad("malformed handler address".to_string()))?;
        p += n;
        let descriptor = dex
            .type_name(type_idx)
            .map_err(|_| bad(format!("caught type index {type_idx} does not exist")))?;
        clauses.push(CatchClause {
            type_descriptor: Some(descriptor),
            address: addr,
        });
    }
    if size_signed <= 0 {
        let (addr, n) = mutf8::read_uleb128(list, p)
            .map_err(|_| bad("malformed catch-all address".to_string()))?;
        let _ = n;
        clauses.push(CatchClause {
            type_descriptor: None,
            address: addr,
        });
    }
    if clauses.is_empty() {
        return Err(bad("a handler must have at least one clause".to_string()));
    }
    Ok(clauses)
}

/// One decoded `encoded_value`.
#[derive(Clone, Debug, PartialEq)]
pub enum EncodedValue {
    /// `VALUE_BYTE`
    Byte(i8),
    /// `VALUE_SHORT`
    Short(i16),
    /// `VALUE_CHAR`
    Char(u16),
    /// `VALUE_INT`
    Int(i32),
    /// `VALUE_LONG`
    Long(i64),
    /// `VALUE_FLOAT`
    Float(f32),
    /// `VALUE_DOUBLE`
    Double(f64),
    /// `VALUE_STRING`, holding a `string_ids` index.
    String(u32),
    /// `VALUE_TYPE`, holding a `type_ids` index.
    Type(u32),
    /// `VALUE_FIELD`, holding a `field_ids` index.
    Field(u32),
    /// `VALUE_METHOD`, holding a `method_ids` index.
    Method(u32),
    /// `VALUE_METHOD_TYPE`, holding a `proto_ids` index. The index cannot be
    /// interpreted without a proto table, so it is kept as-is.
    MethodType(u32),
    /// `VALUE_METHOD_HANDLE`, holding a `method_handles` index.
    MethodHandle(u32),
    /// `VALUE_ENUM`: a `type_ids` index and a `value_idx`.
    Enum { ty: u32, value: u32 },
    /// `VALUE_ARRAY`
    Array(Vec<EncodedValue>),
    /// `VALUE_ANNOTATION`, kept opaque — a constant-pool annotation is not a
    /// value the interpreter needs.
    Annotation,
    /// `VALUE_NULL`
    Null,
    /// `VALUE_BOOLEAN`, whose value is in the `value_arg` nibble rather than
    /// the payload.
    Boolean(bool),
    /// A tag this decoder does not implement.
    Unsupported(u8),
}

impl EncodedValue {
    /// The type this constant has, for materialising it.
    pub fn jtype(&self, program: &Program) -> Option<JType> {
        Some(match self {
            EncodedValue::Byte(_)
            | EncodedValue::Short(_)
            | EncodedValue::Char(_)
            | EncodedValue::Int(_) => JType::Int,
            EncodedValue::Long(_) => JType::Long,
            EncodedValue::Float(_) => JType::Float,
            EncodedValue::Double(_) => JType::Double,
            EncodedValue::Boolean(_) => JType::Boolean,
            EncodedValue::String(_) => JType::Ref("Ljava/lang/String;".into()),
            EncodedValue::Type(idx) => JType::Ref(program.types.get(*idx as usize)?.clone()),
            EncodedValue::MethodType(_) => JType::Ref("Ljava/lang/reflect/MethodType;".into()),
            EncodedValue::MethodHandle(_) => JType::Ref("Ljava/lang/invoke/MethodHandle;".into()),
            EncodedValue::Field(_) | EncodedValue::Method(_) | EncodedValue::Enum { .. } => {
                JType::Ref("<member>".into())
            }
            EncodedValue::Array(items) => {
                let component = items
                    .first()
                    .and_then(|v| v.jtype(program))
                    .unwrap_or(JType::Ref("Ljava/lang/Object;".into()));
                JType::Array(Box::new(component))
            }
            EncodedValue::Annotation | EncodedValue::Null | EncodedValue::Unsupported(_) => {
                JType::Ref("<none>".into())
            }
        })
    }
}

/// How deeply `encoded_value` arrays may nest. A real file nests one level; a
/// hostile one can nest until it runs out of bytes, and the reader is
/// recursive, so the depth is bounded explicitly.
const ENCODED_ARRAY_MAX_DEPTH: u32 = 32;

/// Decode an `encoded_array` starting at `at`, returning the values and the
/// number of bytes consumed.
///
/// This fills a gap in dexcore, which reads the section boundaries but skips
/// the contents. Everything the engine needs here comes from `static_values`:
/// an `R` class is nothing but a table of `int` constants, and `sget` on one is
/// the first thing a real `onCreate` does.
pub fn parse_encoded_array(
    bytes: &[u8],
    at: usize,
    _program: &Program,
) -> Result<(Vec<EncodedValue>, usize), ExecError> {
    let bad = |d: &str| malformed(Malformed::BadStaticValues, d.to_string());
    let (count, n) =
        mutf8::read_uleb128(bytes, at).map_err(|_| bad("malformed encoded_array size"))?;
    // Every value costs at least one byte, so a declared count larger than the
    // remaining bytes is impossible. This is the bound that stops a hostile
    // count from driving an allocation.
    if count as usize > bytes.len().saturating_sub(at + n) {
        return Err(bad(
            "encoded_array declares more values than there are bytes for",
        ));
    }
    let mut p = at + n;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (value, used) = parse_encoded_value(bytes, p, 0)?;
        p += used;
        out.push(value);
    }
    Ok((out, p - at))
}

/// Decode a `VALUE_ARRAY` payload without the enclosing program, which the
/// nested form does not need: an element's type comes from the element.
fn parse_nested_array(
    bytes: &[u8],
    at: usize,
    depth: u32,
) -> Result<(Vec<EncodedValue>, usize), ExecError> {
    let bad = |d: &str| malformed(Malformed::BadStaticValues, d.to_string());
    let (count, n) =
        mutf8::read_uleb128(bytes, at).map_err(|_| bad("malformed encoded_array size"))?;
    if count as usize > bytes.len().saturating_sub(at + n) {
        return Err(bad(
            "encoded_array declares more values than there are bytes for",
        ));
    }
    let mut p = at + n;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (value, used) = parse_encoded_value(bytes, p, depth + 1)?;
        p += used;
        out.push(value);
    }
    Ok((out, p - at))
}

fn parse_encoded_value(
    bytes: &[u8],
    at: usize,
    depth: u32,
) -> Result<(EncodedValue, usize), ExecError> {
    let bad = |d: &str| malformed(Malformed::BadStaticValues, d.to_string());
    if depth > ENCODED_ARRAY_MAX_DEPTH {
        return Err(bad("encoded_value nests too deeply"));
    }
    let head = *bytes
        .get(at)
        .ok_or_else(|| bad("encoded_value starts past the end of the file"))?;
    let tag = head & 0x1f;
    let value_arg = (head >> 5) & 0x07;
    let start = at;
    let mut p = at + 1;

    let fixed = |n: usize, p: &mut usize| -> Result<(), ExecError> {
        if *p + n > bytes.len() {
            Err(bad("encoded_value payload runs past the end of the file"))
        } else {
            *p += n;
            Ok(())
        }
    };
    let index = |p: &mut usize| -> Result<u32, ExecError> {
        let (v, n) = mutf8::read_uleb128(bytes, *p)
            .map_err(|_| bad("malformed ULEB128 index in encoded_value"))?;
        *p += n;
        Ok(v)
    };

    let value = match tag {
        0x00 => {
            fixed(1, &mut p)?;
            EncodedValue::Byte(*bytes.get(start + 1).unwrap_or(&0) as i8)
        }
        0x02 => {
            fixed(2, &mut p)?;
            let s = bytes.get(start + 1..start + 3).unwrap_or(&[0, 0]);
            EncodedValue::Short(i16::from_le_bytes([s[0], s[1]]))
        }
        0x03 => {
            fixed(2, &mut p)?;
            let s = bytes.get(start + 1..start + 3).unwrap_or(&[0, 0]);
            EncodedValue::Char(u16::from_le_bytes([s[0], s[1]]))
        }
        0x04 => {
            fixed(4, &mut p)?;
            let s = bytes.get(start + 1..start + 5).unwrap_or(&[0; 4]);
            EncodedValue::Int(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
        0x06 => {
            fixed(8, &mut p)?;
            let s = bytes.get(start + 1..start + 9).unwrap_or(&[0; 8]);
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            EncodedValue::Long(i64::from_le_bytes(a))
        }
        0x10 => {
            fixed(4, &mut p)?;
            let s = bytes.get(start + 1..start + 5).unwrap_or(&[0; 4]);
            EncodedValue::Float(f32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        }
        0x11 => {
            fixed(8, &mut p)?;
            let s = bytes.get(start + 1..start + 9).unwrap_or(&[0; 8]);
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            EncodedValue::Double(f64::from_le_bytes(a))
        }
        0x15 => EncodedValue::MethodType(index(&mut p)?),
        0x16 => EncodedValue::MethodHandle(index(&mut p)?),
        0x17 => EncodedValue::String(index(&mut p)?),
        0x18 => EncodedValue::Type(index(&mut p)?),
        0x19 => EncodedValue::Field(index(&mut p)?),
        0x1a => EncodedValue::Method(index(&mut p)?),
        0x1b => {
            let ty = index(&mut p)?;
            let value = index(&mut p)?;
            EncodedValue::Enum { ty, value }
        }
        0x1c => {
            let (items, used) = parse_nested_array(bytes, p, depth)?;
            p += used;
            EncodedValue::Array(items)
        }
        0x1d => {
            let _ty = index(&mut p)?;
            let size = index(&mut p)?;
            for _ in 0..size {
                let _name = index(&mut p)?;
                let (_, used) = parse_encoded_value(bytes, p, depth + 1)?;
                p += used;
            }
            EncodedValue::Annotation
        }
        0x1e => EncodedValue::Null,
        0x1f => EncodedValue::Boolean(value_arg != 0),
        other => EncodedValue::Unsupported(other),
    };
    Ok((value, p - start))
}

fn dex_err(e: DexError) -> ExecError {
    malformed(Malformed::BadCode, format!("dex file: {e}"))
}

pub(crate) fn malformed(kind: Malformed, detail: String) -> ExecError {
    ExecError::Malformed {
        kind,
        detail,
        site: Site::default(),
    }
}

pub(crate) fn unsupported(kind: crate::error::Unsupported, detail: String) -> ExecError {
    ExecError::Unsupported {
        kind,
        detail,
        site: Site::default(),
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

    fn empty_program() -> Program {
        Program {
            classes: Vec::new(),
            by_descriptor: HashMap::new(),
            strings: Vec::new(),
            types: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            decls: Vec::new(),
            call_sites_section: None,
            method_handles_section: None,
            call_sites: HashMap::new(),
            method_handles: HashMap::new(),
            phantoms: Vec::new(),
            host_classes: Vec::new(),
            shadowed: Vec::new(),
            host_classes_with_bodies: Vec::new(),
            code_cache: HashMap::new(),
            bytes: Vec::new(),
        }
    }

    #[test]
    fn encoded_array_reads_every_primitive_width() {
        // size 6, then int, long, float, double, char, boolean(@true).
        let mut b = vec![6u8];
        b.push(0x04);
        b.extend_from_slice(&(-7i32).to_le_bytes());
        b.push(0x06);
        b.extend_from_slice(&(-8i64).to_le_bytes());
        b.push(0x10);
        b.extend_from_slice(&1.5f32.to_le_bytes());
        b.push(0x11);
        b.extend_from_slice(&2.5f64.to_le_bytes());
        b.push(0x03);
        b.extend_from_slice(&0xBEEFu16.to_le_bytes());
        b.push(0x3f); // VALUE_BOOLEAN with value_arg = 1

        let (values, used) = parse_encoded_array(&b, 0, &empty_program()).unwrap();
        assert_eq!(used, b.len());
        assert_eq!(values[0], EncodedValue::Int(-7));
        assert_eq!(values[1], EncodedValue::Long(-8));
        assert_eq!(values[2], EncodedValue::Float(1.5));
        assert_eq!(values[3], EncodedValue::Double(2.5));
        assert_eq!(values[4], EncodedValue::Char(0xBEEF));
        assert_eq!(values[5], EncodedValue::Boolean(true));
    }

    #[test]
    fn a_boolean_lives_in_the_value_arg_nibble_not_the_payload() {
        // The tag byte *is* 0x1f for VALUE_BOOLEAN, with the value in the top
        // three bits, so `@false` is 0x1f and `@true` is 0x3f. There is no
        // payload: getting this wrong makes every `static final boolean` in the
        // file parse as a byte instead.
        let b = vec![1u8, 0x1f];
        let (v, used) = parse_encoded_array(&b, 0, &empty_program()).unwrap();
        assert_eq!(v, vec![EncodedValue::Boolean(false)]);
        assert_eq!(used, 2);
        let b = vec![1u8, 0x3f];
        let (v, _) = parse_encoded_array(&b, 0, &empty_program()).unwrap();
        assert_eq!(v, vec![EncodedValue::Boolean(true)]);
    }

    #[test]
    fn an_absurd_count_is_refused_rather_than_allocated() {
        // 200 million values in a two-byte file.
        let b = vec![0xff, 0xff, 0xff, 0xff, 0x07];
        let e = parse_encoded_array(&b, 0, &empty_program()).unwrap_err();
        assert!(
            matches!(
                e,
                ExecError::Malformed {
                    kind: Malformed::BadStaticValues,
                    ..
                }
            ),
            "got {e:?}"
        );
    }

    #[test]
    fn a_truncated_payload_is_an_error_not_a_read_past_the_end() {
        // VALUE_INT with only two of its four bytes present.
        let b = vec![1u8, 0x04, 0x01, 0x02];
        assert!(parse_encoded_array(&b, 0, &empty_program()).is_err());
        // A declared count with no values behind it.
        assert!(parse_encoded_array(&[1u8], 0, &empty_program()).is_err());
        // ...but a zero-length array is legal, not an error.
        let (v, used) = parse_encoded_array(&[0u8], 0, &empty_program()).unwrap();
        assert!(v.is_empty());
        assert_eq!(used, 1);
    }

    #[test]
    fn nesting_is_bounded() {
        // A self-similar array header repeated past the depth limit: a count of
        // one, then `VALUE_ARRAY`, over and over.
        let mut b = vec![1u8];
        for _ in 0..(ENCODED_ARRAY_MAX_DEPTH + 4) {
            b.push(0x1c);
            b.push(1u8);
        }
        assert!(
            parse_encoded_array(&b, 0, &empty_program()).is_err(),
            "nesting must be bounded, not recursed until the stack runs out"
        );
    }

    #[test]
    fn unknown_tags_degrade_rather_than_fail() {
        let b = vec![1u8, 0x07];
        let (v, _) = parse_encoded_array(&b, 0, &empty_program()).unwrap();
        assert_eq!(v, vec![EncodedValue::Unsupported(0x07)]);
        assert!(
            v[0].jtype(&empty_program()).is_some(),
            "even an unknown tag has a type"
        );
    }
}
