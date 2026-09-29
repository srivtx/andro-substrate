//! Shared test support: fixture loading and synthetic DEX construction.
//!
//! Two kinds of input, deliberately kept apart:
//!
//! - **Real fixtures** (`tests/fixtures/*.dex`) are extracted `.dex` files from
//!   genuine multidex F-Droid APKs. They are the only way to test that the
//!   loader survives real build output, and they are committed as small `.dex`
//!   files rather than APKs. See `../FIXTURES.md` for provenance and SHA-256.
//! - **Synthetic DEX** is built here with `dexcore`'s writer, because the
//!   adversarial cases a negative suite needs — a class declared in two files,
//!   a method split across files, the same method defined differently — do not
//!   occur in a well-formed `dx` build. `dx` never splits a `class_def`, and a
//!   genuine duplicate class is a build bug. Testing the merge and ambiguity
//!   rules therefore *requires* synthesising the shapes a real APK will not
//!   produce, and pretending otherwise would leave the rules untested.
//!
//! Everything here is `#![allow(dead_code)]` because each test binary uses a
//! different subset.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use dexcore::model::access;
use dexcore::writer::{ClassDef, CodeBody, DexWriter, FieldDef, MethodDef};
use substrate_runtime::multidex::DexSource;

/// Path to a committed `.dex` fixture.
pub fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("multidex/tests/fixtures")
        .join(name)
}

/// Read a committed fixture's bytes, panicking with a clear message if absent.
///
/// A `panic!` here is correct: a missing fixture is a broken checkout, not
/// untrusted input, and the no-panic requirement is about *APK* bytes.
pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let p = fixture(name);
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("fixture {} unreadable at {}: {e}", name, p.display()))
}

/// The real multidex pair: `classes.dex` + `classes2.dex` from
/// `org.fcitx.fcitx5.android.plugin.sayura_114`.
pub fn sayura_sources() -> Vec<DexSource> {
    vec![
        DexSource::new("classes.dex", fixture_bytes("sayura_classes.dex")),
        DexSource::new("classes2.dex", fixture_bytes("sayura_classes2.dex")),
    ]
}

/// A trivial but valid instruction stream, used to make two bodies differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// `return-void` (`0x0e 0x00`).
    ReturnVoid,
    /// `return v0` (`0x0f 0x00`) — a different instruction stream.
    ReturnV0,
    /// `return v1` (`0x0f 0x01`) — a third, so three-way conflicts are testable.
    ReturnV1,
}

impl Body {
    /// The code unit for this body.
    pub fn units(self) -> [u8; 2] {
        match self {
            Body::ReturnVoid => [0x0e, 0x00],
            Body::ReturnV0 => [0x0f, 0x00],
            Body::ReturnV1 => [0x0f, 0x01],
        }
    }

    /// A `CodeBody` carrying just this instruction.
    pub fn code(self) -> CodeBody {
        CodeBody {
            registers_size: 2,
            ins_size: 0,
            outs_size: 0,
            insns: self.units().to_vec(),
            tries: Vec::new(),
        }
    }
}

/// A method to declare on a synthetic class.
#[derive(Debug, Clone)]
pub struct Meth {
    pub name: String,
    pub parameters: Vec<String>,
    pub return_descriptor: String,
    pub access_flags: u32,
    pub body: Option<Body>,
}

impl Meth {
    /// A public method with a body.
    pub fn concrete(name: &str, ret: &str, body: Body) -> Meth {
        Meth {
            name: name.to_string(),
            parameters: Vec::new(),
            return_descriptor: ret.to_string(),
            access_flags: access::ACC_PUBLIC,
            body: Some(body),
        }
    }

    /// A public method with parameters, e.g. `run(Ljava/lang/String;)V`.
    pub fn concrete_p(name: &str, params: &[&str], ret: &str, body: Body) -> Meth {
        Meth {
            name: name.to_string(),
            parameters: params.iter().map(|s| s.to_string()).collect(),
            return_descriptor: ret.to_string(),
            access_flags: access::ACC_PUBLIC,
            body: Some(body),
        }
    }

    /// An abstract declaration with no body.
    pub fn abstract_(name: &str, params: &[&str], ret: &str) -> Meth {
        Meth {
            name: name.to_string(),
            parameters: params.iter().map(|s| s.to_string()).collect(),
            return_descriptor: ret.to_string(),
            access_flags: access::ACC_PUBLIC | access::ACC_ABSTRACT,
            body: None,
        }
    }

    /// The same method with a different body, for ambiguity tests.
    pub fn with_body(mut self, b: Body) -> Meth {
        self.body = Some(b);
        self
    }

    /// The same method with different access flags, for ambiguity tests.
    pub fn with_flags(mut self, f: u32) -> Meth {
        self.access_flags = f;
        self
    }

    /// The same method declared abstract rather than concrete.
    pub fn declared_abstract(mut self) -> Meth {
        self.body = None;
        self.access_flags = access::ACC_PUBLIC | access::ACC_ABSTRACT;
        self
    }
}

/// A class to declare in a synthetic DEX.
#[derive(Debug, Clone)]
pub struct Klass {
    pub descriptor: String,
    pub superclass: Option<String>,
    pub access_flags: u32,
    pub interfaces: Vec<String>,
    pub methods: Vec<Meth>,
    pub fields: Vec<FieldDef>,
}

impl Klass {
    /// A class extending `Ljava/lang/Object;`.
    pub fn new(descriptor: &str) -> Klass {
        Klass {
            descriptor: descriptor.to_string(),
            superclass: Some("Ljava/lang/Object;".to_string()),
            access_flags: access::ACC_PUBLIC,
            interfaces: Vec::new(),
            methods: Vec::new(),
            fields: Vec::new(),
        }
    }

    /// A root class, with no superclass.
    pub fn root(descriptor: &str) -> Klass {
        let mut k = Klass::new(descriptor);
        k.superclass = None;
        k
    }

    /// With different access flags.
    pub fn with_flags(mut self, f: u32) -> Klass {
        self.access_flags = f;
        self
    }

    /// With a different superclass.
    pub fn extending(mut self, s: &str) -> Klass {
        self.superclass = Some(s.to_string());
        self
    }

    /// With an extra method.
    pub fn with(mut self, m: Meth) -> Klass {
        self.methods.push(m);
        self
    }

    /// With a public static field.
    pub fn with_static_field(mut self, name: &str, ty: &str) -> Klass {
        self.fields.push(FieldDef::statics(name, ty));
        self
    }

    /// With a public instance field.
    pub fn with_instance_field(mut self, name: &str, ty: &str) -> Klass {
        self.fields.push(FieldDef::instance(name, ty));
        self
    }
}

impl From<&Klass> for Klass {
    fn from(k: &Klass) -> Klass {
        k.clone()
    }
}

/// Build a DEX file containing `Ljava/lang/Object;` plus the given classes.
///
/// The root class is added unconditionally: `dexcore`'s writer rejects a class
/// whose superclass is absent, and every synthetic class here extends
/// `Ljava/lang/Object;`. It is skipped when a caller declares it themselves.
///
/// Bodies go in via the writer's documented two-phase flow — declare with
/// `CodeBody::default()` so `freeze()` interns every prototype, then
/// `set_code()` — because `emit` refuses a file that declared code it was
/// never given. That two-phase dance is a real constraint of the writer, and
/// routing around it here keeps the test helpers honest.
pub fn build_dex(classes: &[Klass]) -> Vec<u8> {
    let mut writer = DexWriter::new();
    let declared: Vec<&str> = classes.iter().map(|k| k.descriptor.as_str()).collect();
    if !declared.contains(&"Ljava/lang/Object;") {
        writer.add_class(ClassDef::root("Ljava/lang/Object;"));
    }
    for k in classes {
        let mut def = ClassDef::new(k.descriptor.clone(), k.superclass.clone());
        def.access_flags = k.access_flags;
        def.interfaces = k.interfaces.clone();
        def.static_fields = k
            .fields
            .iter()
            .filter(|f| f.access_flags & access::ACC_STATIC != 0)
            .cloned()
            .collect();
        def.instance_fields = k
            .fields
            .iter()
            .filter(|f| f.access_flags & access::ACC_STATIC == 0)
            .cloned()
            .collect();
        for m in &k.methods {
            let params: Vec<&str> = m.parameters.iter().map(String::as_str).collect();
            let md = if m.body.is_some() {
                MethodDef::concrete(
                    &m.name,
                    &params,
                    &m.return_descriptor,
                    m.access_flags,
                    CodeBody::default(),
                )
            } else {
                MethodDef {
                    name: m.name.clone(),
                    parameters: m.parameters.clone(),
                    return_descriptor: m.return_descriptor.clone(),
                    access_flags: m.access_flags,
                    code: None,
                }
            };
            // The writer's own routing rule, applied here so the emitted
            // `class_data_item` lists methods where a conforming build would.
            if m.access_flags & (access::ACC_STATIC | access::ACC_PRIVATE | access::ACC_CONSTRUCTOR)
                != 0
            {
                def.direct_methods.push(md);
            } else {
                def.virtual_methods.push(md);
            }
        }
        writer.add_class(def);
    }

    // Phase two: intern, then install bodies.
    writer.freeze().expect("synthetic DEX must freeze");
    for k in classes {
        for m in &k.methods {
            if let Some(b) = m.body {
                writer
                    .set_code(&k.descriptor, &m.name, b.code())
                    .expect("declared method must accept a body");
            }
        }
    }
    writer.emit().expect("synthetic DEX must emit")
}

/// A source named `classes.dex` carrying the given classes.
pub fn primary(classes: &[Klass]) -> DexSource {
    DexSource::new("classes.dex", build_dex(classes))
}

/// A `classes.dex` carrying exactly one class.
///
/// Exists so tests that duplicate a single class do not have to write
/// `&[k.clone()]`, which clippy rightly flags as a `clone` that should be a
/// borrow.
pub fn primary1(class: &Klass) -> DexSource {
    DexSource::new("classes.dex", build_dex(std::slice::from_ref(class)))
}

/// A source named `classes<N>.dex` carrying the given classes.
pub fn secondary(n: u32, classes: &[Klass]) -> DexSource {
    DexSource {
        name: format!("classes{n}.dex"),
        bytes: Arc::new(build_dex(classes)),
    }
}

/// A `classes<N>.dex` carrying exactly one class. See [`primary1`].
pub fn secondary1(n: u32, class: &Klass) -> DexSource {
    secondary(n, std::slice::from_ref(class))
}
