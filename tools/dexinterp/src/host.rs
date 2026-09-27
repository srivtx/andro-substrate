//! The framework shim boundary.
//!
//! # The problem
//!
//! 44.76% of the F-Droid corpus in [`corpus/report.md`](../../corpus/report.md)
//! contains no native code. That is the ceiling on this project's reach, and
//! it says nothing about whether the remaining bytecode can run. What it does
//! mean is that *all* of the interesting failures are failures to run
//! **framework** code: `Landroid/app/Activity;` has no `classes.dex` inside
//! any APK, and neither does `java.lang.String`.
//!
//! So the execution engine has to be able to execute app code and *not* execute
//! framework code, and the boundary between the two has to be a stable,
//! documented interface rather than an `if descriptor.starts_with("android/")`
//! scattered through the interpreter.
//!
//! # The contract
//!
//! [`Host`] is that interface. It is asked to answer four kinds of question:
//!
//! 1. **What does this method do?** [`Host::invoke`], for any method whose
//!    class has no bytecode in this dex. That includes `abstract` and `native`
//!    methods *of the app's own classes*, which is not a framework concern at
//!    all — a `native` method in a DEX-only APK is something the shim has to
//!    answer or the app is simply broken.
//! 2. **What is this field's value?** [`Host::get_field`] and
//!    [`Host::set_field`], for fields declared on a class with no bytecode.
//! 3. **What does this call site resolve to?** [`Host::resolve_call_site`], for
//!    `invoke-custom`.
//! 4. **What class is this?** [`Host::class_known`], consulted only when the
//!    descriptor is in neither the file nor the builtin table.
//!
//! Every method has a **default implementation that returns
//! [`HostOutcome::NotImplemented`]**, and the engine's response to
//! `NotImplemented` is defined: record the call in [`Stats`], substitute the
//! return type's zero value, and carry on. That is a deliberate choice and it
//! is the most consequential decision in this module, so it is argued rather
//! than asserted — see "Why NotImplemented is a stub and not an error" below.
//!
//! # Objects the host hands back
//!
//! A host cannot hand back a [`Value`], because only the engine owns the heap
//! and only the engine may allocate. It hands back a [`HostValue`], a
//! description, and the engine materialises it. [`HostValue::Opaque`] carries a
//! caller-chosen `key`, and the engine keeps a bijection from `(class, key)` to
//! a heap object, so a host that returns `Opaque { class: "Landroid/view/Window;",
//! key: "w1" }` twice gets the same object twice and can therefore implement
//! `getWindow().getAttributes()` as ordinary state in its own `HashMap`.
//!
//! Reference: `SUB.FW.CLASS_LOADER`, `SUB.FW.REFLECTION`, `SUB.FW.INVOKEDYNAMIC`
//! in [`docs/divergence-taxonomy.md`](../../docs/divergence-taxonomy.md).

use crate::value::{JType, Value};

/// Which `invoke-*` opcode asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvokeKind {
    /// `invoke-virtual`, dispatched through the receiver's vtable.
    Virtual,
    /// `invoke-super`, resolved from the named class's superclass.
    Super,
    /// `invoke-direct`, resolved on the named class, no dispatch.
    Direct,
    /// `invoke-static`.
    Static,
    /// `invoke-interface`, dispatched through the receiver's vtable with
    /// interface-method resolution.
    Interface,
    /// `invoke-polymorphic` and `invoke-polymorphic/range`.
    Polymorphic,
    /// `invoke-custom` and `invoke-custom/range`, after the call site resolved.
    Custom,
}

impl InvokeKind {
    /// Stable name for recordings.
    pub fn as_str(self) -> &'static str {
        match self {
            InvokeKind::Virtual => "virtual",
            InvokeKind::Super => "super",
            InvokeKind::Direct => "direct",
            InvokeKind::Static => "static",
            InvokeKind::Interface => "interface",
            InvokeKind::Polymorphic => "polymorphic",
            InvokeKind::Custom => "custom",
        }
    }
}

/// A method call the engine could not execute itself.
#[derive(Clone, Debug, PartialEq)]
pub struct Call<'a> {
    /// The class named by the `method_ids` entry. For a virtual call this is
    /// the *static* type, which is not the receiver's dynamic class; a host
    /// that needs the receiver should look at `args[0]`.
    pub class: &'a str,
    /// The method name.
    pub name: &'a str,
    /// The prototype descriptor, e.g. `(Ljava/lang/String;)I`.
    pub signature: &'a str,
    /// Which opcode asked.
    pub kind: InvokeKind,
    /// The arguments, receiver first for the instance forms.
    pub args: &'a [Value],
}

impl Call<'_> {
    /// The receiver, for the instance forms. `None` for `Static`/`Custom`, and
    /// `Some(None)` when the receiver was `null` (in which case the engine
    /// raises `NullPointerException` before ever asking, so a host that sees
    /// this is looking at a bug).
    pub fn receiver(&self) -> Option<Value> {
        match self.kind {
            InvokeKind::Static | InvokeKind::Custom => None,
            _ => self.args.first().copied(),
        }
    }
}

/// A field access the engine could not execute itself.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldAccess<'a> {
    /// The class named by the `field_ids` entry.
    pub class: &'a str,
    /// The field name.
    pub name: &'a str,
    /// The field's type descriptor.
    pub ty: &'a str,
    /// The instance, or `None` for a static field.
    pub target: Option<Value>,
}

/// A throwable the host wants raised.
///
/// The host names a class and the engine allocates the object, so the heap
/// stays encapsulated and the resulting exception is a *real* instance of a
/// *real* class in the hierarchy — `catch (Ljava/lang/Error;)` sees it, and
/// `instance-of` on it behaves the way it would on a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThrowSpec {
    /// Class descriptor, e.g. `Ljava/lang/NullPointerException;`.
    pub class: &'static str,
    /// Value for `Throwable.detailMessage`.
    pub message: Option<String>,
}

impl ThrowSpec {
    /// A throwable with a message.
    pub fn new(class: &'static str, message: impl Into<String>) -> ThrowSpec {
        ThrowSpec { class, message: Some(message.into()) }
    }

    /// A throwable with no message.
    pub fn bare(class: &'static str) -> ThrowSpec {
        ThrowSpec { class, message: None }
    }
}

/// What a host returns.
#[derive(Clone, Debug, PartialEq)]
pub enum HostOutcome {
    /// A concrete result.
    Value(HostValue),
    /// "I do not implement this."
    ///
    /// The engine records the call, substitutes the return type's zero value
    /// (`0`, `null`, …) and continues. See the module documentation for why.
    NotImplemented,
    /// Raise a throwable in the app's code. The value of the `invoke` that
    /// raised it is discarded, exactly as on a device.
    Throw(ThrowSpec),
}

/// A description of a value the host wants the engine to materialise.
#[derive(Clone, Debug, PartialEq)]
pub enum HostValue {
    /// `null`.
    Null,
    /// An `int`, `boolean`, `byte`, `short` or `char`.
    Int(i32),
    /// A `long`.
    Long(i64),
    /// A `float`.
    Float(f32),
    /// A `double`.
    Double(f64),
    /// A real `Ljava/lang/String;` object. Strings are first-class here
    /// because a large fraction of app logic is string logic, and because
    /// `const-string` has to produce one anyway.
    Str(String),
    /// A real `Ljava/lang/Class;` object, for `Class.forName` and
    /// `getClass().getName()`.
    Class(String),
    /// A real `Ljava/lang/reflect/MethodType;` object.
    MethodType(String),
    /// An instance of a class with no bytecode in this dex.
    ///
    /// `key` is the host's own identity for the object. Two calls with the
    /// same `(class, key)` produce the same heap object, which is what makes
    /// multi-step framework protocols (`getWindow()` then
    /// `getAttributes()` then `setAttributes()`) expressible in a host without
    /// the host holding any heap handles.
    Opaque {
        /// The class descriptor to instantiate.
        class: String,
        /// The host's identity for this object.
        key: String,
    },
    /// An array, given its component descriptor and elements.
    Array {
        /// The component descriptor, e.g. `Ljava/lang/String;` or `I`.
        component: String,
        /// The elements, in index order.
        items: Vec<HostValue>,
    },
    /// An object the engine already allocated — usually one the host was handed
    /// as an argument and wants to return unchanged (`setAttributes(lp)`
    /// returning `lp`).
    Ref(Value),
}

impl HostValue {
    /// A convenient `Ljava/lang/String;` result.
    pub fn string(s: impl Into<String>) -> HostValue {
        HostValue::Str(s.into())
    }

    /// The type this value has, for checking against a declared return type.
    pub fn jtype(&self) -> JType {
        match self {
            HostValue::Null => JType::Ref("<null>".into()),
            HostValue::Int(_) => JType::Int,
            HostValue::Long(_) => JType::Long,
            HostValue::Float(_) => JType::Float,
            HostValue::Double(_) => JType::Double,
            HostValue::Str(_) => JType::Ref("Ljava/lang/String;".into()),
            HostValue::Class(_) => JType::Ref("Ljava/lang/Class;".into()),
            HostValue::MethodType(_) => JType::Ref("Ljava/lang/reflect/MethodType;".into()),
            HostValue::Opaque { class, .. } => JType::Ref(class.clone()),
            HostValue::Array { component, .. } => JType::Array(Box::new(JType::parse(component))),
            HostValue::Ref(_) => JType::Ref("<ref>".into()),
        }
    }
}

/// A decoded `call_site_item`, offered to the host for resolution.
#[derive(Clone, Debug, PartialEq)]
pub struct CallSite<'a> {
    /// Index into `call_site_ids`, as the instruction wrote it.
    pub index: u32,
    /// `METHOD_HANDLE_STATIC`, `METHOD_HANDLE_INSTANCE`, `METHOD_HANDLE_CONSTRUCTOR`
    /// or `METHOD_HANDLE_INTERFACE`.
    pub method_handle_type: u16,
    /// The class that *defines* the bootstrap method — the class of the
    /// method handle, per the DEX specification.
    pub bootstrap_owner: &'a str,
    /// The bootstrap method's name.
    pub bootstrap_name: &'a str,
    /// The bootstrap method's prototype.
    pub bootstrap_signature: &'a str,
    /// The remaining bootstrap arguments, in order, as values. The first
    /// bootstrap argument is the call site's own method type, and the second,
    /// when present, is the method handle being invoked; the rest are
    /// `LambdaMetafactory`'s markers, which is why they are handed over as
    /// values rather than being interpreted here.
    pub arguments: &'a [Value],
}

/// A resolved call site: what `invoke-custom` should actually call.
#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedCallSite {
    /// The class to dispatch on, or `None` for a static target.
    pub class: Option<String>,
    /// The method name.
    pub name: String,
    /// The prototype descriptor.
    pub signature: String,
    /// Which form to dispatch with.
    pub kind: InvokeKind,
}

/// The framework shim.
///
/// Every method has a default that declines, so an implementation can start
/// with one method and grow. Implementations must not panic and must not
/// recurse into the interpreter: the engine calls a host while holding its
/// frame stack, and a re-entrant call would need a second interpreter. (The
/// alternative — an explicit re-entrancy token in `Call` — was rejected
/// because a shim that needs to call back into app code is better served by
/// returning [`HostOutcome::Value`] with a value it computed, which is what
/// every shim that exists actually does.)
pub trait Host {
    /// Answer a call the engine has no bytecode for.
    fn invoke(&mut self, _call: &Call<'_>) -> HostOutcome {
        HostOutcome::NotImplemented
    }

    /// Read a field declared on a class with no bytecode.
    fn get_field(&mut self, _field: &FieldAccess<'_>) -> HostOutcome {
        HostOutcome::NotImplemented
    }

    /// Write a field declared on a class with no bytecode.
    fn set_field(&mut self, _field: &FieldAccess<'_>, _value: HostValue) -> HostOutcome {
        HostOutcome::NotImplemented
    }

    /// Resolve a call site for `invoke-custom`. `None` declines.
    ///
    /// Returning `None` produces
    /// [`Unsupported::CallSiteUnresolved`](crate::error::Unsupported::CallSiteUnresolved),
    /// which is a *different* recorded outcome from
    /// `BootstrapMethodMissing` — the file had a bootstrap method and the
    /// substrate could not run it, which is the `SUB.FW.INVOKEDYNAMIC` claim.
    fn resolve_call_site(&mut self, _site: &CallSite<'_>) -> Option<ResolvedCallSite> {
        None
    }

    /// Whether a class exists, for descriptors in neither the file nor the
    /// builtin table. Declaring a class makes `new-instance` work on it and
    /// stops the engine fabricating a phantom placeholder.
    fn class_known(&mut self, _descriptor: &str) -> bool {
        false
    }
}

/// The host used when none is installed: declines everything, so the engine
/// records every framework call and substitutes defaults.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoHost;

impl Host for NoHost {}

/// Install a host.
///
/// Convenient for callers that build the interpreter in one expression.
pub fn with_host<'a, H: Host + 'static>(dex: dexcore::DexReader<'a>, config: crate::config::Config, host: H) -> crate::ExecResult<crate::Interpreter<'a>> {
    let mut vm = crate::new_interpreter(dex, config)?;
    vm.set_host(Box::new(host));
    Ok(vm)
}
