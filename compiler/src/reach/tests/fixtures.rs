//! Builders for synthetic DEX, and accessors for the committed real-app
//! fixtures.
//!
//! # Why both
//!
//! The two kinds of test answer different questions and neither substitutes for
//! the other:
//!
//! * **Synthetic DEX**, built here through `dexcore`'s writer, is the only way
//!   to state a property like "a virtual call on C reaches every implementor"
//!   with the answer known in advance. A real APK cannot demonstrate it,
//!   because you cannot make an APK that has exactly the hierarchy you want.
//! * **The committed fixtures** under `tools/dexcore/tests/fixtures` are real
//!   `classes.dex` files extracted from F-Droid APKs, which is the only way to
//!   assert "the reflective-edge count is non-zero on a real app" rather than
//!   on a construction that was designed to make the assertion pass.

// A test that does not panic is a test that asserted nothing, so `expect` is
// the right tool here. The crate denies it for library code, where a panic is
// a defect; in a test it is the assertion.
#![allow(clippy::expect_used, clippy::unwrap_used)]
#![allow(dead_code)]

use dexcore::asm::Assembler;
use dexcore::model::access;
use dexcore::writer::{ClassDef, CodeBody, DexWriter, IndexMap, MethodDef};

/// A DEX under construction.
///
/// The dexcore writer is two-phase: intern every pool reference, freeze to get
/// the sorted indices, then assemble bodies against them. This holds both
/// halves so a test reads as a declaration followed by bodies.
pub struct Builder {
    w: DexWriter,
}

impl Builder {
    /// A fresh builder.
    pub fn new() -> Builder {
        Builder {
            w: DexWriter::new(),
        }
    }

    /// Intern a string constant.
    pub fn string(&mut self, s: &str) {
        self.w.add_string(s);
    }

    /// Intern a type descriptor.
    pub fn ty(&mut self, descriptor: &str) {
        self.w.add_type(descriptor);
    }

    /// Intern a method reference so a body can call it.
    pub fn method_ref(&mut self, class: &str, name: &str, params: &[&str], ret: &str) {
        let _ = self.w.add_method(class, name, params, ret);
    }

    /// Add a class.
    pub fn class(&mut self, c: ClassDef) {
        self.w.add_class(c);
    }

    /// Sort the pools and hand back the final indices.
    pub fn freeze(mut self) -> Frozen {
        let idx = self.w.freeze().expect("a hand-built DEX must be freezable");
        Frozen { w: self.w, idx }
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new()
    }
}

/// A builder whose pools are frozen, so bodies can reference real indices.
pub struct Frozen {
    w: DexWriter,
    pub idx: IndexMap,
}

impl Frozen {
    /// A string index. `freeze` sorts the pool, so a string interned after it
    /// would not have the index this returns: the assertion is the loud
    /// failure for a test that forgets to intern up front.
    pub fn string(&self, s: &str) -> u16 {
        assert!(
            self.idx.has_string(s),
            "string {s:?} was not interned before freeze"
        );
        self.idx.string(s)
    }

    /// A type index.
    pub fn ty(&self, descriptor: &str) -> u16 {
        self.idx
            .type_(descriptor)
            .unwrap_or_else(|e| panic!("type {descriptor} not interned: {e}"))
    }

    /// A method index.
    pub fn method(&self, class: &str, name: &str, params: &[&str], ret: &str) -> u16 {
        self.idx
            .method(class, name, params, ret)
            .unwrap_or_else(|e| panic!("method {class}.{name} not interned: {e}"))
    }

    /// Install a body.
    pub fn code(&mut self, class: &str, method: &str, body: CodeBody) {
        self.w
            .set_code(class, method, body)
            .unwrap_or_else(|e| panic!("set_code: {e}"));
    }

    /// Emit the container.
    pub fn emit(self) -> Vec<u8> {
        self.w.emit().expect("a hand-built DEX must be emittable")
    }
}

/// The smallest DEX that loads: `Ljava/lang/Object;` and nothing else.
pub fn minimal_dex() -> Vec<u8> {
    let mut b = Builder::new();
    b.ty("Ljava/lang/Object;");
    b.class(class_with_method("Ljava/lang/Object;", None, "<init>"));
    let mut f = b.freeze();
    f.code("Ljava/lang/Object;", "<init>", empty_void());
    f.emit()
}

/// `()V { }` — the smallest legal body.
pub fn empty_void() -> CodeBody {
    let mut a = Assembler::new();
    a.return_void();
    a.into_code(0, 0, 0)
}

/// `static void go() { }` for a class that needs a static entry.
pub fn static_void_body() -> CodeBody {
    empty_void()
}

/// A constructor every fixture class gets, so a body that allocates one has a
/// real `invoke-direct <init>` to point at — which is what a d8-compiled APK
/// looks like, and what `RTA` needs in order to see the allocation.
pub fn with_ctor(mut c: ClassDef) -> ClassDef {
    let declared = c
        .direct_methods
        .iter()
        .chain(c.virtual_methods.iter())
        .any(|m| m.name == "<init>");
    if !declared {
        c.direct_methods.push(MethodDef::concrete(
            "<init>",
            &[],
            "V",
            access::ACC_PUBLIC | access::ACC_CONSTRUCTOR,
            CodeBody::default(),
        ));
    } else {
        // `with_method` routes a bare ACC_PUBLIC `<init>` into virtual_methods,
        // which the writer rejects. Move it where a constructor belongs.
        if let Some(i) = c.virtual_methods.iter().position(|m| m.name == "<init>") {
            let m = c.virtual_methods.remove(i);
            c.direct_methods.push(m);
        }
    }
    c
}

/// A class with a concrete no-arg public method `name`, so `ClassDef` has
/// something to attach a body to. `superclass` of `None` makes it a root class.
pub fn class_with_method(descriptor: &str, superclass: Option<&str>, name: &str) -> ClassDef {
    let c = ClassDef::new(descriptor, superclass.map(str::to_string));
    with_ctor(c.with_method(MethodDef::concrete(
        name,
        &[],
        "V",
        access::ACC_PUBLIC,
        CodeBody::default(),
    )))
}

/// A class extending `superclass` with a concrete `()V` method `name`.
pub fn override_class(descriptor: &str, superclass: &str, name: &str) -> ClassDef {
    with_ctor(
        ClassDef::new(descriptor, Some(superclass.to_string())).with_method(MethodDef::concrete(
            name,
            &[],
            "V",
            access::ACC_PUBLIC,
            CodeBody::default(),
        )),
    )
}

/// An interface declaring `name`.
pub fn interface(descriptor: &str, name: &str) -> ClassDef {
    let mut c = ClassDef::new(descriptor, Some("Ljava/lang/Object;".to_string()));
    c.access_flags = access::ACC_PUBLIC | access::ACC_INTERFACE | access::ACC_ABSTRACT;
    c.interfaces.clear();
    c.with_method(MethodDef::abstract_(name, &[], "V"))
}

/// A class implementing `iface`, with a concrete `name`.
pub fn implementor(descriptor: &str, superclass: &str, iface: &str, name: &str) -> ClassDef {
    let mut c = ClassDef::new(descriptor, Some(superclass.to_string()));
    c.interfaces = vec![iface.to_string()];
    with_ctor(c.with_method(MethodDef::concrete(
        name,
        &[],
        "V",
        access::ACC_PUBLIC,
        CodeBody::default(),
    )))
}

/// A class implementing `iface` and extending `Ljava/lang/Object;`.
pub fn object_implementor(descriptor: &str, iface: &str, name: &str) -> ClassDef {
    implementor(descriptor, "Ljava/lang/Object;", iface, name)
}

/// Assemble `static void go(Base b) { b.run(); }`.
pub fn call_virtual_body(idx: &Frozen, target_class: &str, target_name: &str) -> CodeBody {
    let mi = idx.method(target_class, target_name, &[], "V");
    let mut a = Assembler::new();
    a.const4(0, 0).expect("const4");
    a.invoke(0x6e, &[0], mi).expect("invoke-virtual");
    a.return_void();
    a.into_code(1, 1, 1)
}

/// Assemble `static void go() { new T(); }` — the only instruction that
/// proves a type is allocated, and therefore the whole basis of RTA.
pub fn allocate_body(idx: &Frozen, descriptor: &str) -> CodeBody {
    let ti = idx.ty(descriptor);
    let init = idx.method(descriptor, "<init>", &[], "V");
    let mut a = Assembler::new();
    a.new_instance(0, ti);
    a.invoke(0x70, &[0], init).expect("invoke-direct");
    a.return_void();
    a.into_code(1, 0, 1)
}

/// Assemble `static void go() { Class.forName("<lit>"); }` — a string constant
/// consumed by the reflection factory at the immediately following
/// instruction, which is the syntactic evidence the reflective-edge report is
/// built on.
pub fn forname_body(idx: &Frozen, literal: &str) -> CodeBody {
    let s = idx.string(literal);
    let forname = idx.method(
        "Ljava/lang/Class;",
        "forName",
        &["Ljava/lang/String;"],
        "Ljava/lang/Class;",
    );
    let mut a = Assembler::new();
    a.const_string(0, s);
    a.invoke(0x71, &[0], forname).expect("invoke-static");
    a.return_void();
    a.into_code(1, 0, 1)
}

/// Assemble `static void go() { String s = "<lit>"; }` — a bare string
/// constant that names a class but is *not* consumed by anything, so the
/// analysis has to report it as an unresolved candidate rather than resolve it.
pub fn bare_string_body(idx: &Frozen, literal: &str) -> CodeBody {
    let s = idx.string(literal);
    let mut a = Assembler::new();
    a.const_string(0, s);
    a.return_void();
    a.into_code(1, 0, 0)
}

// ---------------------------------------------------------------------------
// Committed real-app fixtures
// ---------------------------------------------------------------------------

/// One committed fixture: a real `classes.dex` and `AndroidManifest.xml`
/// extracted from an F-Droid APK.
pub struct RealApp {
    pub name: &'static str,
    pub dex: &'static [u8],
    pub axml: &'static [u8],
}

/// The committed fixtures, reachable from `compiler/src/reach/tests/`.
///
/// These are the same files `tools/dexcore`'s own suite uses, addressed
/// relatively so the compiler crate needs no new data of its own and no APK is
/// ever committed.
pub fn real_apps() -> Vec<RealApp> {
    vec![
        RealApp {
            name: "pro.rudloff.search_to_browser_2",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//pro.rudloff.search_to_browser_2.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//pro.rudloff.search_to_browser_2.axml"
            ),
        },
        RealApp {
            name: "org.vi_server.red_screen_3",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//org.vi_server.red_screen_3.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//org.vi_server.red_screen_3.axml"
            ),
        },
        RealApp {
            name: "com.android.adbkeyboard_2",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.android.adbkeyboard_2.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.android.adbkeyboard_2.axml"
            ),
        },
        RealApp {
            name: "com.oF2pks.neolinker_7",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.oF2pks.neolinker_7.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.oF2pks.neolinker_7.axml"
            ),
        },
        RealApp {
            name: "com.termux.boot_1000",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.termux.boot_1000.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//com.termux.boot_1000.axml"
            ),
        },
        RealApp {
            name: "fr.smarquis.sleeptimer_16200",
            dex: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//fr.smarquis.sleeptimer_16200.dex"
            ),
            axml: include_bytes!(
                "../../../../tools/dexcore/tests/fixtures//fr.smarquis.sleeptimer_16200.axml"
            ),
        },
    ]
}

/// A real app whose manifest declares a `MAIN`+`LAUNCHER` activity, so the
/// `IR.md` entry rule has something to bite on.
pub fn launcher_app() -> Option<RealApp> {
    real_apps().into_iter().find(|a| {
        crate::reach::entry::Manifest::parse(a.axml)
            .map(|m| m.launcher().is_some())
            .unwrap_or(false)
    })
}
