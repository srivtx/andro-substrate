//! Entry points, from the manifest, per `IR.md`.
//!
//! IR.md fixes the entry set normatively:
//!
//! > Entry points: the launch activity's `onCreate`, plus anything the
//! > manifest marks `exported=true`.
//!
//! That is the floor, and [`EntryPolicy::IrMd`] implements exactly it. It is
//! not a cold start: Android runs the `Application` object, then every
//! declared `ContentProvider`, and only then the activity, and the framework
//! reaches all three through its own `ActivityThread` handlers. A closure
//! computed from `onCreate` alone therefore *under*-counts any real launch.
//!
//! Rather than quietly widen the spec, this module offers three policies, all
//! of which the report names on its face:
//!
//! | policy | seeds |
//! |---|---|
//! | [`EntryPolicy::IrMd`] | `IR.md` verbatim |
//! | [`EntryPolicy::Extended`] | the above, plus the `Application`/`ContentProvider` lifecycle the manifest declares and the framework handlers that reach them |
//! | [`EntryPolicy::ColdStart`] | the above, plus `ActivityThread.main`, so the framework's own side of the start is in the closure |
//!
//! # The `exported` default
//!
//! A component with an `<intent-filter>` and no explicit `android:exported`
//! is exported on every API level this project targets; that default changed
//! only for components *without* an intent filter, where `targetSdk >= 31`
//! requires it to be stated. [`Component::exported`] implements the
//! intent-filter rule and reports which branch it took, because getting this
//! wrong in the permissive direction inflates the closure and in the strict
//! direction misses real entry points.

use std::collections::BTreeSet;
use std::fmt;

use dexcore::axml::{self, AxmlDocument, Element};

use crate::reach::model::{ClassId, MethodId, Program, UnitRole};

/// A manifest failure that changes the closure, as opposed to a parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestGap {
    /// The binary XML did not parse.
    Unparseable(String),
    /// There is no `<manifest>` element.
    NoManifestElement,
    /// No component carries `MAIN` + `LAUNCHER`.
    NoLauncherActivity,
    /// A component's `android:name` is absent or could not be expanded.
    UnnamedComponent { component: String },
}

impl fmt::Display for ManifestGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestGap::Unparseable(w) => write!(f, "manifest did not parse: {w}"),
            ManifestGap::NoManifestElement => write!(f, "no <manifest> element"),
            ManifestGap::NoLauncherActivity => {
                write!(
                    f,
                    "no component declares MAIN + LAUNCHER (so there is no launch activity)"
                )
            }
            ManifestGap::UnnamedComponent { component } => {
                write!(f, "<{component}> has no usable android:name")
            }
        }
    }
}

/// Which entry set to close over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EntryPolicy {
    /// `IR.md` verbatim: launch activity `onCreate` plus every component the
    /// manifest marks `exported=true`.
    #[default]
    IrMd,
    /// `IR.md` plus the manifest-declared `Application` and `ContentProvider`
    /// lifecycle, and the framework handlers that reach them.
    Extended,
    /// `Extended` plus `ActivityThread.main`, so the framework's own start-up
    /// path is in the closure too.
    ColdStart,
}

impl EntryPolicy {
    /// Name as printed in the report.
    pub fn as_str(self) -> &'static str {
        match self {
            EntryPolicy::IrMd => "ir.md (launch onCreate + exported components)",
            EntryPolicy::Extended => {
                "extended (IR.md + Application/ContentProvider + ActivityThread handlers)"
            }
            EntryPolicy::ColdStart => "cold-start (extended + ActivityThread.main)",
        }
    }

    /// True when the framework-side seeds are included.
    pub fn includes_framework_seeds(self) -> bool {
        matches!(self, EntryPolicy::Extended | EntryPolicy::ColdStart)
    }

    /// True when the process entry point is included.
    pub fn includes_process_entry(self) -> bool {
        matches!(self, EntryPolicy::ColdStart)
    }
}

/// What kind of manifest component an entry point came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentKind {
    Application,
    Activity,
    Service,
    Receiver,
    Provider,
}

impl ComponentKind {
    /// The manifest tag this kind is read from.
    pub fn tag(self) -> &'static str {
        match self {
            ComponentKind::Application => "application",
            ComponentKind::Activity => "activity",
            ComponentKind::Service => "service",
            ComponentKind::Receiver => "receiver",
            ComponentKind::Provider => "provider",
        }
    }

    /// Class descriptor a component's name expands to.
    pub fn descriptor(self, name: &str) -> String {
        format!("L{};", name.replace('.', "/"))
    }
}

/// One component declared in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub kind: ComponentKind,
    /// Fully-qualified class name with `.` separators.
    pub name: String,
    /// The descriptor form, `Lcom/x/Y;`.
    pub descriptor: String,
    /// The resolved `android:exported` value.
    pub exported: bool,
    /// How the exported value was decided.
    pub exported_from: ExportedFrom,
    /// True when this is the `MAIN` + `LAUNCHER` activity.
    pub is_launcher: bool,
}

/// Where an `exported` value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportedFrom {
    /// `android:exported` was stated.
    Explicit,
    /// Defaulted to true because the component has an `<intent-filter>`.
    IntentFilterDefault,
    /// Defaulted to false: no intent filter, so nothing states it.
    DefaultFalse,
}

impl ExportedFrom {
    pub fn as_str(self) -> &'static str {
        match self {
            ExportedFrom::Explicit => "explicit",
            ExportedFrom::IntentFilterDefault => "default (intent-filter present)",
            ExportedFrom::DefaultFalse => "default (no intent filter)",
        }
    }
}

/// One entry point: a method, and why it is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    /// `Lcom/x/Y;.onCreate(Landroid/os/Bundle;)V`.
    pub method: String,
    pub kind: ComponentKind,
    /// The component that contributed it, as a class name.
    pub component: String,
    /// `onCreate`, `onBind`, `ActivityThread.main`, ...
    pub reason: String,
}

/// Everything read out of `AndroidManifest.xml`.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    /// The `package` attribute, if present.
    pub package: Option<String>,
    pub components: Vec<Component>,
    /// The application object's class, if `android:name` is set.
    pub application_class: Option<String>,
}

impl Manifest {
    /// Parse a binary `AndroidManifest.xml`.
    pub fn parse(bytes: &[u8]) -> Result<Manifest, ManifestGap> {
        let doc: AxmlDocument =
            axml::parse(bytes).map_err(|e| ManifestGap::Unparseable(e.to_string()))?;
        Ok(Manifest::from_document(&doc))
    }

    /// Extract components from an already-parsed document.
    pub fn from_document(doc: &AxmlDocument) -> Manifest {
        let package = doc.package_name();
        let mut m = Manifest {
            package: package.clone(),
            ..Manifest::default()
        };
        let Some(app) = doc.root.find_all("application").into_iter().next() else {
            return m;
        };
        if let Some(n) = app.attribute_value("android:name") {
            m.application_class = expand(&n, package.as_deref());
        }
        for (tag, kind) in [
            ("activity", ComponentKind::Activity),
            ("activity-alias", ComponentKind::Activity),
            ("service", ComponentKind::Service),
            ("receiver", ComponentKind::Receiver),
            ("provider", ComponentKind::Provider),
        ] {
            for e in app.find_all(tag) {
                let Some(n) = e.attribute_value("android:name") else {
                    continue;
                };
                let Some(name) = expand(&n, package.as_deref()) else {
                    continue;
                };
                let has_filter = !e.find_all("intent-filter").is_empty()
                    || e.children_named("intent-filter").next().is_some();
                let (exported, exported_from) = match e.attribute_value("android:exported") {
                    Some(v) => (parse_bool(&v), ExportedFrom::Explicit),
                    None if has_filter => (true, ExportedFrom::IntentFilterDefault),
                    None => (false, ExportedFrom::DefaultFalse),
                };
                let is_launcher = kind == ComponentKind::Activity && is_launcher(e);
                m.components.push(Component {
                    kind,
                    descriptor: kind.descriptor(&name),
                    name,
                    exported,
                    exported_from,
                    is_launcher,
                });
            }
        }
        m
    }

    /// The `MAIN` + `LAUNCHER` activity, if the manifest declares one.
    pub fn launcher(&self) -> Option<&Component> {
        self.components.iter().find(|c| c.is_launcher)
    }

    /// The declared `ContentProvider`s, which Android instantiates and
    /// `onCreate`s before the `Application` object.
    pub fn providers(&self) -> impl Iterator<Item = &Component> {
        self.components
            .iter()
            .filter(|c| c.kind == ComponentKind::Provider)
    }

    /// A short, stable description for the report.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        for kind in [
            ComponentKind::Application,
            ComponentKind::Activity,
            ComponentKind::Service,
            ComponentKind::Receiver,
            ComponentKind::Provider,
        ] {
            let n = self.components.iter().filter(|c| c.kind == kind).count();
            let extra = if kind == ComponentKind::Application && self.application_class.is_some() {
                1
            } else {
                0
            };
            if n + extra > 0 {
                parts.push(format!("{}={}", kind.tag(), n + extra));
            }
        }
        parts.join(" ")
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(v.trim(), "true" | "1")
}

fn is_launcher(e: &Element) -> bool {
    let mut main = false;
    let mut launcher = false;
    for f in e.find_all("intent-filter") {
        for a in f.children_named("action") {
            if a.attribute_value("android:name").as_deref() == Some("android.intent.action.MAIN") {
                main = true;
            }
        }
        for c in f.children_named("category") {
            if c.attribute_value("android:name").as_deref()
                == Some("android.intent.category.LAUNCHER")
            {
                launcher = true;
            }
        }
    }
    main && launcher
}

/// Expand an `android:name` into a fully-qualified class name.
///
/// `.Foo` and bare `Foo` are relative to the manifest's `package`; a name
/// containing a `.` in first position with nothing else is a malformed
/// component and returns `None` rather than a guess.
pub fn expand(name: &str, package: Option<&str>) -> Option<String> {
    let n = name.trim();
    if n.is_empty() {
        return None;
    }
    if let Some(rest) = n.strip_prefix('.') {
        if rest.is_empty() {
            return None;
        }
        return Some(format!("{}.{}", package?, rest));
    }
    if !n.contains('.') {
        return package.map(|p| format!("{p}.{n}"));
    }
    Some(n.to_string())
}

/// The lifecycle methods a component kind contributes, before the
/// overridable-surface widening in [`entry_points`].
fn lifecycle_seeds(kind: ComponentKind) -> &'static [(&'static str, &'static str)] {
    match kind {
        ComponentKind::Application => &[("onCreate", "()V"), ("attachBaseContext", "(Landroid/content/Context;)V")],
        ComponentKind::Activity => &[
            // IR.md names `onCreate`; the three-argument form is API 21+ and is
            // a separate slot in the vtable, so a subclass that overrides it is
            // not reachable from the two-argument one.
            ("onCreate", "(Landroid/os/Bundle;)V"),
            ("onCreate", "(Landroid/os/Bundle;Landroid/os/PersistableBundle;)V"),
            ("onStart", "()V"),
            ("onRestart", "()V"),
            ("onResume", "()V"),
            ("onPostCreate", "(Landroid/os/Bundle;)V"),
            ("onPostResume", "()V"),
            ("onWindowFocusChanged", "(Z)V"),
        ],
        ComponentKind::Service => &[
            ("onCreate", "()V"),
            ("onBind", "(Landroid/content/Intent;)Landroid/os/IBinder;"),
            ("onStartCommand", "([Landroid/content/Intent;II)I"),
            ("onHandleIntent", "(Landroid/content/Intent;)V"),
            ("onUnbind", "(Landroid/content/Intent;)Z"),
            ("onRebind", "(Landroid/content/Intent;)V"),
            ("onTaskRemoved", "(Landroid/content/Intent;)V"),
            ("onDestroy", "()V"),
        ],
        ComponentKind::Receiver => &[
            ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V"),
            ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;I)V"),
        ],
        ComponentKind::Provider => &[
            ("onCreate", "()Z"),
            ("query", "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;"),
            ("insert", "(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;"),
            ("update", "(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I"),
            ("delete", "(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I"),
            ("getType", "(Landroid/net/Uri;)Ljava/lang/String;"),
            ("call", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;"),
            ("openFile", "(Landroid/net/Uri;Ljava/lang/String;)Ljava/io/FileNotFoundException;"),
            ("openAssetFile", "(Landroid/net/Uri;Ljava/lang/String;)Ljava/io/InputStream;"),
        ],
    }
}

/// A framework-side seed: a method the platform calls, which therefore has to be
/// in the closure for a host to be complete even though the app never names it.
///
/// `sig` is `None` for **every overload**, deliberately. A framework seed named
/// by its full prototype is a seed that silently stops resolving the moment the
/// platform changes: `ActivityThread.main` is `()V` on some API levels and
/// `([Ljava/lang/String;)V` on Android 13, and `handleLaunchActivity` has been
/// re-signatured at least three times. A name-only seed over-approximates
/// across overloads, which is the direction this module is allowed to err in,
/// and — more importantly — a seed that fails to resolve is *reported* in
/// `EntrySet::missing` rather than quietly producing a smaller closure.
pub type FrameworkSeed = (&'static str, &'static str, Option<&'static str>);

/// The framework handlers that actually invoke each component kind.
pub const FRAMEWORK_SEEDS: &[FrameworkSeed] = &[
    ("Landroid/app/ActivityThread;", "main", None),
    ("Landroid/app/ActivityThread;", "handleLaunchActivity", None),
    ("Landroid/app/ActivityThread;", "handleStartActivity", None),
    ("Landroid/app/ActivityThread;", "handleResumeActivity", None),
    ("Landroid/app/ActivityThread;", "handleNewIntent", None),
    ("Landroid/app/ActivityThread;", "handleCreateService", None),
    ("Landroid/app/ActivityThread;", "handleBindService", None),
    ("Landroid/app/ActivityThread;", "handleReceiver", None),
    ("Landroid/app/ActivityThread;", "handleInstallProvider", None),
    ("Landroid/app/ActivityThread;", "installProvider", None),
    ("Landroid/app/ActivityThread;", "installContentProviders", None),
];

/// The framework methods that reach *into* a component, seeded so the framework
/// side of the boundary is in the closure and not just the app side.
pub const LOCAL_SEEDS: &[FrameworkSeed] = &[
    ("Landroid/app/Activity;", "attach", None),
    ("Landroid/app/Activity;", "performCreate", None),
    ("Landroid/app/Activity;", "onCreate", Some("(Landroid/os/Bundle;)V")),
    ("Landroid/app/Instrumentation;", "callActivityOnCreate", None),
    ("Landroid/content/ContentProvider;", "attachInfo", None),
];

/// What the caller asked for, and what was produced.
#[derive(Debug, Clone, Default)]
pub struct EntrySet {
    /// Every seed, as `Lclass;.name(sig)ret`.
    pub points: Vec<EntryPoint>,
    /// A seed that names a class the universe does not contain.
    pub unresolved: Vec<EntryPoint>,
    /// A seed whose class is present but which declares no such method.
    pub missing: Vec<EntryPoint>,
    /// Manifest problems that change the closure.
    pub manifest_gaps: Vec<ManifestGap>,
    /// Whether the overridable surface of each component was added beyond the
    /// fixed lifecycle list.
    pub widened_to_full_surface: bool,
}

impl EntrySet {
    /// The number of seeds that resolved to a method in the universe.
    pub fn resolved(&self) -> usize {
        self.points.len()
    }

    /// A one-line description for the report.
    pub fn summary(&self) -> String {
        format!(
            "{} resolved, {} class-not-in-universe, {} method-not-declared",
            self.points.len(),
            self.unresolved.len(),
            self.missing.len()
        )
    }
}

/// An entry set named directly, for a caller that already knows its entry
/// points and does not want them filtered through a manifest.
///
/// The synthetic tests use this, and so can a host that drives the app from
/// somewhere other than `am start` — a BroadcastReceiver under test, a
/// ContentProvider query, a deliberately-constructed dispatch.
pub fn explicit_entry_points(program: &Program, methods: &[&str]) -> EntrySet {
    let mut set = EntrySet::default();
    for m in methods {
        let Some((class, name, proto)) = crate::reach::parse_method_string(m) else {
            set.manifest_gaps.push(ManifestGap::UnnamedComponent {
                component: format!("{m} (unparseable)"),
            });
            continue;
        };
        let ep = EntryPoint {
            method: m.to_string(),
            kind: ComponentKind::Application,
            component: class.clone(),
            reason: "explicitly named by the caller".to_string(),
        };
        match program.class(&class) {
            Some(cid) if program.classes[cid.0 as usize].is_defined() => {
                match program.lookup(cid, &name, &proto) {
                    Some(_) => set.points.push(ep),
                    None => set.missing.push(ep),
                }
            }
            _ => set.unresolved.push(ep),
        }
    }
    set
}

/// Every method in the universe, as an entry set.
///
/// Not a closure — this is the *static* surface of a DEX, every method it
/// declares, with no call graph at all. It is the quantity
/// `analysis/candidates.md` measures, and it is kept here because the two are
/// the same question asked at different depths: "what does this APK mention"
/// versus "what can run before the first frame". The gap between them is the
/// project's central claim, and a tool that can only compute one of them
/// cannot state it.
pub fn all_method_roots(program: &Program) -> EntrySet {
    let mut set = EntrySet {
        widened_to_full_surface: true,
        ..EntrySet::default()
    };
    for (i, m) in program.methods.iter().enumerate() {
        set.points.push(EntryPoint {
            method: format!(
                "{}.{}{}",
                program.descriptor(m.class),
                program.strings.get(m.name),
                program.strings.get(m.proto)
            ),
            kind: ComponentKind::Application,
            component: program.descriptor(m.class).to_string(),
            reason: "static surface: every declared method".to_string(),
        });
        let _ = i;
    }
    set
}

/// Compute the entry set for a policy.
pub fn entry_points(
    program: &Program,
    manifest: &Manifest,
    policy: EntryPolicy,
    widen_to_full_surface: bool,
) -> EntrySet {
    let mut set = EntrySet {
        widened_to_full_surface: widen_to_full_surface,
        ..EntrySet::default()
    };
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut add = |set: &mut EntrySet,
                   class: &str,
                   name: &str,
                   sig: &str,
                   kind: ComponentKind,
                   comp: &str,
                   reason: &str| {
        let m = format!("{class}.{name}{sig}");
        if !seen.insert(m.clone()) {
            return;
        }
        let ep = EntryPoint {
            method: m,
            kind,
            component: comp.to_string(),
            reason: reason.to_string(),
        };
        match program
            .class(class)
            .filter(|c| program.classes[c.0 as usize].is_defined())
        {
            Some(cid) => match program.lookup(cid, name, sig) {
                Some(_) => set.points.push(ep),
                None => set.missing.push(ep),
            },
            None => set.unresolved.push(ep),
        }
    };

    if let Some(app) = &manifest.application_class {
        let d = ComponentKind::Application.descriptor(app);
        add(
            &mut set,
            &d,
            "onCreate",
            "()V",
            ComponentKind::Application,
            app,
            "Application.onCreate",
        );
        if policy != EntryPolicy::IrMd {
            add(
                &mut set,
                &d,
                "attachBaseContext",
                "(Landroid/content/Context;)V",
                ComponentKind::Application,
                app,
                "Application.attachBaseContext",
            );
        }
    }

    for c in &manifest.components {
        let selected = if c.kind == ComponentKind::Activity {
            c.is_launcher || c.exported
        } else {
            c.exported || (policy != EntryPolicy::IrMd && c.kind == ComponentKind::Provider)
        };
        if !selected {
            continue;
        }
        let why = if c.is_launcher {
            "launcher"
        } else {
            "exported"
        };
        for (name, sig) in lifecycle_seeds(c.kind) {
            add(&mut set, &c.descriptor, name, sig, c.kind, &c.name, why);
        }
        if widen_to_full_surface {
            for (name, proto) in overridable_surface(program, program.class(&c.descriptor)) {
                if let Some(cid) = program.class(&c.descriptor) {
                    if let Some(mid) = program.lookup(cid, &name, &proto) {
                        let _ = mid;
                    }
                }
                add(
                    &mut set,
                    &c.descriptor,
                    &name,
                    &proto,
                    c.kind,
                    &c.name,
                    "full exported surface",
                );
            }
        }
    }

    if policy.includes_framework_seeds() {
        for (class, name, sig) in LOCAL_SEEDS {
            add_framework(&mut set, program, class, name, *sig, "framework entry into the app");
        }
        for (class, name, sig) in FRAMEWORK_SEEDS {
            if !policy.includes_process_entry() && *name == "main" {
                continue;
            }
            add_framework(
                &mut set,
                program,
                class,
                name,
                *sig,
                "framework component dispatch",
            );
        }
    }
    set
}

/// Resolve one framework seed, by prototype when given and by name otherwise,
/// and record it as resolved, missing or unresolved.
fn add_framework(
    set: &mut EntrySet,
    program: &Program,
    class: &str,
    name: &str,
    sig: Option<&str>,
    reason: &str,
) {
    let Some(cid) = program.class(class) else {
        set.unresolved.push(EntryPoint {
            method: format!("{class}.{name}{}", sig.unwrap_or("")),
            kind: ComponentKind::Application,
            component: class.to_string(),
            reason: reason.to_string(),
        });
        return;
    };
    if !program.classes[cid.0 as usize].is_defined() {
        set.unresolved.push(EntryPoint {
            method: format!("{class}.{name}{}", sig.unwrap_or("")),
            kind: ComponentKind::Application,
            component: class.to_string(),
            reason: reason.to_string(),
        });
        return;
    }
    let mut hits = 0usize;
    for (n, p) in &program.classes[cid.0 as usize].declared {
        if program.str(*n) != name {
            continue;
        }
        if let Some(want) = sig {
            if program.str(*p) != want {
                continue;
            }
        }
        hits += 1;
        set.points.push(EntryPoint {
            method: format!("{class}.{name}{}", program.str(*p)),
            kind: ComponentKind::Application,
            component: class.to_string(),
            reason: reason.to_string(),
        });
    }
    if hits == 0 {
        set.missing.push(EntryPoint {
            method: format!("{class}.{name}{}", sig.unwrap_or("")),
            kind: ComponentKind::Application,
            component: class.to_string(),
            reason: reason.to_string(),
        });
    }
}

/// Every method a class declares, walking up its own hierarchy and stopping at
/// the first class the platform defines.
///
/// This is the "what could the host dispatch to" surface: a host that does not
/// implement a `ContentProvider` subclass's `getType` has no vtable entry for
/// it, and the app crashes on a method the static call graph never named.
pub fn overridable_surface(program: &Program, start: Option<ClassId>) -> Vec<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    let Some(mut cur) = start else {
        return Vec::new();
    };
    let mut guard = 0usize;
    loop {
        guard += 1;
        if guard > 64 {
            break; // a cyclic hierarchy; 64 is far past any real one
        }
        let Some(info) = program.classes.get(cur.0 as usize) else {
            break;
        };
        let stop = info
            .resolved()
            .is_some_and(|d| program.units[d.unit.0 as usize].role == UnitRole::Framework);
        for (n, p) in &info.declared {
            let (Some(d), true) = (info.resolved(), !stop) else {
                break;
            };
            if let Some(m) = d.methods.iter().find(|m| m.name == *n && m.proto == *p) {
                let flags = m.flags;
                if flags
                    & (dexcore::model::access::ACC_STATIC
                        | dexcore::model::access::ACC_PRIVATE
                        | dexcore::model::access::ACC_FINAL)
                    == 0
                    && flags & dexcore::model::access::ACC_CONSTRUCTOR == 0
                {
                    out.insert((program.str(*n).to_string(), program.str(*p).to_string()));
                }
            }
        }
        if stop {
            break;
        }
        match info.resolved().and_then(|d| d.superclass) {
            Some(s) => cur = s,
            None => break,
        }
    }
    out.into_iter().collect()
}

/// A method's `Lclass;.name(sig)ret` string, for report and comparison.
pub fn method_string(program: &Program, m: MethodId) -> String {
    let c = program.method_class(m);
    format!(
        "{}.{}{}",
        program.descriptor(c),
        program.method_name(m),
        program.method_proto(m)
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn relative_names_expand_against_the_package() {
        assert_eq!(expand(".Main", Some("a.b")), Some("a.b.Main".into()));
        assert_eq!(expand("Main", Some("a.b")), Some("a.b.Main".into()));
        assert_eq!(expand("a.b.Main", Some("a.b")), Some("a.b.Main".into()));
        assert_eq!(expand("", Some("a.b")), None);
        assert_eq!(expand(".", Some("a.b")), None);
        assert_eq!(expand(".Main", None), None);
    }

    #[test]
    fn descriptor_slashes_are_normalised() {
        assert_eq!(ComponentKind::Activity.descriptor("a.b.C"), "La/b/C;");
    }
}
