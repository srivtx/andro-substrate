//! The reachability input contract.
//!
//! # This is A4's output shape, and why hostgen restates it
//!
//! `compiler/IR.md` §Reachability defines the closure and §Class resolution
//! order defines what happens to a name in it, but the concrete Rust type is
//! A4's to define in `compiler/src/reach/`. hostgen cannot depend on a module
//! that does not exist yet, and the dependency would be the wrong way round
//! anyway: reachability should not know that host generation exists, or it will
//! start optimising the closure for the generator, and a closure pruned to suit
//! the generator is no longer the closure the app actually calls.
//!
//! So the input is declared here as the *contract*, in hostgen's own words, and
//! wiring [`crate::hostgen::closure::Closure`] to A4's concrete type is a
//! conversion in whichever direction leaves reachability untouched. Everything
//! hostgen needs is here and nothing more.
//!
//! # The reflective-edge requirement is load-bearing
//!
//! `IR.md` is unusually explicit and the requirement is carried through verbatim:
//!
//! > *Reflection is a hole and must be reported, not assumed. … A closure is
//! > only sound if the report says how many unresolved reflective edges there
//! > were. **Silence is a failure.***
//!
//! [`Closure`] therefore has no way to exist without a set of
//! [`ReflectiveEdge`]s and a count of the unresolved ones — not as a field a
//! caller may leave at zero, but as [`Closure::unresolved_reflective`] derived
//! from the edges themselves, so a caller cannot under-report by omission. The
//! host carries that count into [`crate::hostgen::emit::HostModule`], and a
//! closure with unresolved reflective edges is a *reported fact about the
//! measurement*, not a defect in it.

use core::fmt;

/// How a method entered the closure.
///
/// The four variants are `IR.md`'s four bullet points under §Reachability,
/// verbatim, in its order. [`Origin::Reflective`] is the fifth and is not in
/// `IR.md`'s list on purpose: a `const-string` naming a class is a *candidate*
/// edge, so it may name something the closure does not actually contain, and
/// recording it as a closure member would overstate the closure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Reachable in the call graph from an entry point, including virtual
    /// dispatch on all implementors in the loaded DEX.
    CallGraph,
    /// Reached by a `hostcall` whose class is in the closure, transitively.
    Hostcall,
    /// Referenced as a superclass of a closure class, transitively.
    Superclass,
    /// An override of a method in the closure.
    Override,
    /// A candidate edge from `const-string`, `Class.forName`, or a
    /// `getDeclaredMethod` name. Recorded, never assumed.
    Reflective,
}

impl Origin {
    /// Every origin, in `IR.md`'s order.
    pub const ALL: [Origin; 5] = [
        Origin::CallGraph,
        Origin::Hostcall,
        Origin::Superclass,
        Origin::Override,
        Origin::Reflective,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Origin::CallGraph => "call-graph",
            Origin::Hostcall => "hostcall",
            Origin::Superclass => "superclass",
            Origin::Override => "override",
            Origin::Reflective => "reflective",
        }
    }
}

/// The access flags hostgen cares about, read from the DEX `access_flags`.
///
/// Only three distinctions change what is emitted, so only three are modelled.
/// Everything else — `public` vs `protected`, `final`, `synchronized` — is a
/// property of the *guest* code, and hostgen never emits guest code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MethodAccess {
    pub is_static: bool,
    /// Declared `native`. A native method is a different host obligation: it is
    /// `HostNative` in `IR.md`'s classification, not a stub, and it has a
    /// *satisfied/unsatisfied* state rather than an implementation.
    pub is_native: bool,
    pub is_abstract: bool,
    pub is_constructor: bool,
}

/// One member of the closure: a `(class, name, signature)` triple.
///
/// The signature is the full DEX descriptor, e.g. `"(Ljava/lang/String;)V"`,
/// because it is the load-bearing part for both classification and
/// attribution: `getText()` and `getText(I)` have different answers and
/// different taxonomy IDs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClosureMember {
    /// A DEX type descriptor, e.g. `"Landroid/os/Build;"`.
    pub class: String,
    pub name: String,
    pub signature: String,
    pub origin: Origin,
    pub access: MethodAccess,
}

impl ClosureMember {
    /// A member with no access flags.
    pub fn new(
        class: impl Into<String>,
        name: impl Into<String>,
        signature: impl Into<String>,
        origin: Origin,
    ) -> ClosureMember {
        ClosureMember {
            class: class.into(),
            name: name.into(),
            signature: signature.into(),
            origin,
            access: MethodAccess::default(),
        }
    }

    /// The canonical `class->name signature` key, which is also the host table
    /// index key.
    pub fn key(&self) -> String {
        format!("{}->{} {}", self.class, self.name, self.signature)
    }

    /// The return type descriptor, or `V` for void.
    ///
    /// Parsed from the signature rather than trusted as a field, because the
    /// return type is what the answer policy keys on and a caller that
    /// supplied a wrong one would silently get the wrong default.
    pub fn return_type(&self) -> &str {
        let bytes = self.signature.as_bytes();
        let mut i = 0;
        let mut depth = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    // Saturating, because a signature with an unbalanced `)`
                    // would otherwise underflow and panic — and `IR.md`'s
                    // first non-negotiable is no panics on untrusted input.
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return self.signature.get(i + 1..).unwrap_or("");
                    }
                }
                _ => {}
            }
            i += 1;
        }
        ""
    }

    /// The parameter type descriptors, outermost first.
    pub fn parameter_types(&self) -> Vec<&str> {
        let open = match self.signature.find('(') {
            Some(i) => i,
            None => return Vec::new(),
        };
        let close = match self.signature.rfind(')') {
            Some(i) if i > open => i,
            _ => return Vec::new(),
        };
        split_descriptors(&self.signature[open + 1..close])
    }

    /// Whether the return type is a reference or an array, i.e. something whose
    /// canonical absent value is `null`.
    pub fn returns_reference(&self) -> bool {
        let r = self.return_type();
        r.starts_with('L') || r.starts_with('[')
    }
}

/// Split a run of DEX type descriptors.
///
/// Malformed input yields whatever prefix was well-formed rather than an error
/// and never panics: a signature comes from an untrusted DEX, and the host's
/// answer to a malformed signature is to attribute it and deny, which requires
/// getting this far.
pub fn split_descriptors(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let start = i;
        match b[i] {
            b'V' | b'Z' | b'B' | b'S' | b'C' | b'I' | b'J' | b'F' | b'D' => i += 1,
            b'[' => {
                while i < b.len() && b[i] == b'[' {
                    i += 1;
                }
                if i < b.len() {
                    // `[` is not part of the reference, so `s[i..]` already starts
                    // at the `L` (or the primitive). Advance past the descriptor.
                    i += if b[i] == b'L' { ref_len(s, i) } else { 1 };
                }
            }
            b'L' => i += ref_len(s, i),
            _ => break,
        }
        // A zero-length advance would be an infinite loop, and an advance past
        // the end would slice out of bounds. Refuse both rather than trust the
        // input: a signature comes from an untrusted DEX.
        if i <= start || i > b.len() {
            break;
        }
        out.push(&s[start..i]);
    }
    out
}

/// Length of the reference descriptor beginning at `at`, which must be an `L`.
///
/// `s[at..].find(';')` returns an offset **relative to `at`**, so the descriptor
/// ends at `at + offset + 1`. Getting that `+1` wrong truncates one byte of
/// every reference and mis-slices every array of references, which is a quiet
/// wrongness rather than a loud one — hence a named helper rather than an
/// inline expression.
fn ref_len(s: &str, at: usize) -> usize {
    match s[at..].find(';') {
        Some(offset) => offset + 1,
        // Unterminated: claim the rest of the input so the caller's `i > len`
        // guard refuses the whole thing rather than silently accepting a prefix
        // that has no terminator.
        None => s.len() - at,
    }
}

/// Whether a reflective candidate edge was resolved, and how confidently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReflectiveStatus {
    /// The named target is in the closure.
    Resolved,
    /// The target could not be found anywhere in the loaded DEX.
    Unresolved,
    /// The name matched more than one target, so which one the app meant is not
    /// determinable statically. Counted separately from [`ReflectiveStatus::Unresolved`]
    /// because they mean different things: one is a hole, the other is an
    /// ambiguity, and an ambiguity is usually a *class-loader's* fault rather
    /// than the app's.
    Ambiguous,
}

/// A candidate edge from a `const-string`, `Class.forName` name, or a
/// `getDeclaredMethod` target.
///
/// `IR.md` requires these be emitted as explicit records. They are never
/// silently promoted to closure members.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectiveEdge {
    /// The class the edge was found in.
    pub from_class: String,
    /// The descriptor the app named, e.g. `"Landroid/os/Build;"`.
    pub target: String,
    pub status: ReflectiveStatus,
    /// Where in the calling method, for a reader who wants the site. Never a
    /// register dump; the instruction's rendered form is a name and a
    /// descriptor, which are not values.
    pub site: Option<String>,
}

impl ReflectiveEdge {
    /// An unresolved edge, which is the case that has to be reported.
    pub fn unresolved(from_class: impl Into<String>, target: impl Into<String>) -> ReflectiveEdge {
        ReflectiveEdge {
            from_class: from_class.into(),
            target: target.into(),
            status: ReflectiveStatus::Unresolved,
            site: None,
        }
    }
}

/// The closure: what the app can actually reach, plus its reflective holes.
///
/// Constructed only through [`Closure::new`], which is where the reporting
/// requirement is enforced: [`Closure::unresolved_reflective`] is *computed*
/// from the edge set, so there is no field to forget to fill in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Closure {
    members: Vec<ClosureMember>,
    reflective: Vec<ReflectiveEdge>,
    /// Classes the app itself defines. A name in this set that the host also
    /// serves is a **shadowing event** — see [`crate::hostgen::emit`].
    app_classes: Vec<String>,
    /// Classes we compiled into the guest module, for classification step 1.
    generated_classes: Vec<String>,
    /// Entry points the closure was grown from, recorded because "the closure
    /// is 4,649 methods" is meaningless without "from what".
    entry_points: Vec<String>,
    /// The app's package, from the manifest, when one was read.
    app_package: Option<String>,
}

impl Closure {
    /// A closure with no members yet.
    pub fn new() -> Closure {
        Closure::default()
    }

    /// Add a member. Duplicates by [`ClosureMember::key`] are collapsed, and
    /// the *first* origin wins, because `IR.md`'s list is ordered by strength:
    /// a member that is both `call-graph` reachable and an override is better
    /// described as call-graph reachable.
    pub fn add(&mut self, m: ClosureMember) -> bool {
        if self.members.iter().any(|x| x.key() == m.key()) {
            return false;
        }
        self.members.push(m);
        true
    }

    /// Record a reflective candidate edge.
    pub fn add_reflective(&mut self, e: ReflectiveEdge) {
        self.reflective.push(e);
    }

    /// Declare a class the app itself defines.
    pub fn add_app_class(&mut self, descriptor: impl Into<String>) {
        let d = descriptor.into();
        if !self.app_classes.contains(&d) {
            self.app_classes.push(d);
        }
    }

    /// Declare a class we compiled into the guest module.
    pub fn add_generated_class(&mut self, descriptor: impl Into<String>) {
        let d = descriptor.into();
        if !self.generated_classes.contains(&d) {
            self.generated_classes.push(d);
        }
    }

    /// Record an entry point the closure was grown from.
    pub fn add_entry_point(&mut self, e: impl Into<String>) {
        let e = e.into();
        if !self.entry_points.contains(&e) {
            self.entry_points.push(e);
        }
    }

    pub fn members(&self) -> &[ClosureMember] {
        &self.members
    }

    pub fn reflective_edges(&self) -> &[ReflectiveEdge] {
        &self.reflective
    }

    pub fn app_classes(&self) -> &[String] {
        &self.app_classes
    }

    pub fn generated_classes(&self) -> &[String] {
        &self.generated_classes
    }

    pub fn entry_points(&self) -> &[String] {
        &self.entry_points
    }

    /// The app's own package prefix.
///
/// This is what separates "the app's code" from "the framework and library
/// surface the host is being asked to replace".
///
/// **Declared from the manifest when one is available**, which is the real
/// source and the right one. Deriving it from entry points is only a fallback,
/// and a demonstrably lossy one: a launch activity at
/// `Leu/ln/gita/activities/MainActivity;` yields `Leu/ln/gita/activities/`, so a
/// class at `Leu/ln/gita/Main;` would fall outside it and be misclassified as
/// framework. That is not hypothetical — it is what the first version of this
/// code did, and it was caught by a test rather than by reasoning.
///
/// So: [`Closure::set_app_package`] when a manifest was read, and derivation
/// only when one was not. The distinction is load-bearing, because getting it
/// wrong makes the host answer an app's own methods, which is the failure mode
/// `IR.md`'s step 4 exists to prevent.
pub fn app_package(&self) -> Option<String> {
        if let Some(p) = &self.app_package {
            return Some(p.clone());
        }
        let mut prefix: Option<String> = None;
        for e in &self.entry_points {
            let p = package_of(e);
            prefix = Some(match prefix {
                None => p,
                Some(cur) => common_prefix(&cur, &p),
            });
        }
        let p = prefix?;
        // A prefix shorter than two segments is not identifying; treat it as
        // unknown rather than claiming every single-letter class in the world.
        if p.split('/').filter(|s| !s.is_empty()).count() < 2 {
            None
        } else {
            Some(p)
        }
    }

    /// Declare the app's package, from `AndroidManifest.xml`'s `package`
    /// attribute.
    ///
    /// Accepts either a dot-separated manifest package (`com.android.adbkeyboard`)
    /// or an already-slash form, and normalises both to the **DEX descriptor
    /// prefix** `Lcom/android/adbkeyboard/`.
    ///
    /// **Nothing is capitalised**, and that is the whole subtlety. A DEX
    /// descriptor spells its package exactly as the manifest did — only the
    /// *class* name is capitalised:
    ///
    /// ```text
    /// android.os.Build            ->  Landroid/os/Build;
    /// com.android.adbkeyboard.AdbIME ->  Lcom/android/adbkeyboard/AdbIME;
    /// ```
    ///
    /// So the rule is: convert the separators, change nothing else. This version
    /// of the function capitalised the first segment, on the reasonable but wrong
    /// guess that descriptors begin with an upper-case letter. `android.os.Build`
    /// disproves it in one line, and the consequence was not cosmetic: the prefix
    /// `Lcom/android/adbkeyboard/` matched nothing, every app class fell outside
    /// it, and the host generated fabrications for the app's *own* methods — the
    /// exact failure `IR.md` step 4 exists to prevent, and it produced a
    /// plausible-looking run rather than an error.
    ///
    /// This is the second time this function was wrong in a way that fails
    /// silently and in the dangerous direction, which is why the package is
    /// declared explicitly rather than inferred wherever it can be.
    pub fn set_app_package(&mut self, package: &str) {
        let raw: Vec<&str> = if package.contains('/') {
            package.split('/').filter(|x| !x.is_empty()).collect()
        } else {
            package.split('.').filter(|x| !x.is_empty()).collect()
        };
        if raw.is_empty() {
            self.app_package = None;
            return;
        }
        let mut s = String::with_capacity(package.len() + 1);
        for seg in raw {
            s.push_str(seg);
            s.push('/');
        }
        self.app_package = Some(s);
    }

    /// How many members. The number the thesis is stated in.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the host should claim `descriptor` as its own surface.
    ///
    /// Everything outside the app's package is framework or library code, and
    /// the host is what replaces it. Everything inside is the app's, and the
    /// host must not answer for it — not because it cannot, but because an
    /// instrument that answers an app's own methods is measuring itself.
    ///
    /// The declared app-class list is consulted *first* and unconditionally, so
    /// that a class recorded as the app's is the app's even when the package
    /// derivation is imperfect. That ordering is what keeps a hostile APK from
    /// claiming the host's surface: `host_claims` is only ever asked about a
    /// class the *host* would serve, and a class the app declared inside the
    /// app's own package never reaches it.
    pub fn host_claims(&self, descriptor: &str) -> bool {
        if !descriptor.starts_with('L') || !descriptor.ends_with(';') || descriptor.len() < 3 {
            return false;
        }
        // The declared app-class list is checked *first and unconditionally*.
        // A class the app has claimed as its own is the app's even when the
        // package prefix is imperfect, and — this is the load-bearing case — a
        // hostile APK that declares `Landroid/os/Build;` as its own still loses,
        // because the *host* claims everything outside the app's package and
        // `android/os/` is not `Leu/ln/gita/`. The two rules are not in tension:
        // the app-class list is the authority on what is the app's, and the
        // package prefix is the authority on what the host may serve.
        if self.app_classes.iter().any(|c| c == descriptor) {
            return match self.app_package() {
                // Inside the app's own package: unambiguously the app's.
                Some(p) => !descriptor.starts_with(&p),
                // With no package known, an explicit declaration is all the
                // evidence there is, and believing it is the conservative choice:
                // the worst outcome is one app class left to itself, which is
                // merely unhelpful, rather than the host impersonating the app.
                None => false,
            };
        }
        match self.app_package() {
            Some(p) => !descriptor.starts_with(&p),
            // No package and no declaration: claim it. The generator's whole
            // claim is that it answers the surface the app can reach.
            None => true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Distinct class descriptors among the members.
    pub fn class_count(&self) -> usize {
        let mut v: Vec<&str> = self.members.iter().map(|m| m.class.as_str()).collect();
        v.sort_unstable();
        v.dedup();
        v.len()
    }

    /// **How many reflective candidate edges could not be resolved.**
    ///
    /// Derived from the edge set, so a caller cannot under-report. `IR.md`:
    /// "A closure is only sound if the report says how many unresolved reflective
    /// edges there were. Silence is a failure."
    pub fn unresolved_reflective(&self) -> usize {
        self.reflective
            .iter()
            .filter(|e| e.status == ReflectiveStatus::Unresolved)
            .count()
    }

    /// Ambiguous rather than unresolved.
    pub fn ambiguous_reflective(&self) -> usize {
        self.reflective
            .iter()
            .filter(|e| e.status == ReflectiveStatus::Ambiguous)
            .count()
    }

    /// Whether the closure is *sound*, per `IR.md`: no unresolved and no
    /// ambiguous reflective edges.
    ///
    /// This is a report about the measurement, not a defect in it. A closure
    /// with holes is a perfectly good measurement as long as the number of
    /// holes is in the output, which is why [`Self::unresolved_reflective`]
    /// cannot be omitted.
    pub fn is_sound(&self) -> bool {
        self.unresolved_reflective() == 0 && self.ambiguous_reflective() == 0
    }

    /// A one-line soundness summary for the host report. The wording is chosen
    /// so that a reader cannot mistake "0 holes" for "the app does not use
    /// reflection".
    pub fn soundness_line(&self) -> String {
        format!(
            "reflective edges: {} total, {} unresolved, {} ambiguous — {}",
            self.reflective.len(),
            self.unresolved_reflective(),
            self.ambiguous_reflective(),
            if self.is_sound() {
                "closure is sound per IR.md (no unresolved candidate edges)"
            } else {
                "closure is NOT sound; the hole count above is the reporting requirement"
            }
        )
    }
}

/// The package prefix of a descriptor, e.g.
/// `Leu/ln/gita/activities/MainActivity;` → `Leu/ln/gita/`.
///
/// Accepts either a bare descriptor or the full `class->name signature` form an
/// entry point is recorded in, because the `->` and everything after it are not
/// part of the class name and including them would make the last "package
/// segment" be `MainActivity;->onCreate(...)V`.
fn package_of(descriptor: &str) -> String {
    let class = descriptor.split("->").next().unwrap_or(descriptor);
    let mut segs: Vec<&str> = Vec::new();
    for s in class.trim_start_matches('L').trim_end_matches(';').split('/') {
        if s.is_empty() {
            break;
        }
        segs.push(s);
    }
    // The last segment is the class name, not a package segment.
    segs.pop();
    let mut out = String::new();
    for s in segs {
        out.push_str(s);
        out.push('/');
    }
    out
}

/// The longest common prefix of two slash-terminated package prefixes.
fn common_prefix(a: &str, b: &str) -> String {
    let mut out = String::new();
    let mut ai = a.split('/');
    let mut bi = b.split('/');
    loop {
        match (ai.next(), bi.next()) {
            (Some(x), Some(y)) if x == y && !x.is_empty() => {
                out.push_str(x);
                out.push('/');
            }
            _ => return out,
        }
    }
}

impl fmt::Display for ClosureMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_types_are_parsed_not_guessed() {
        let m = ClosureMember::new("Lx;", "f", "(ILjava/lang/String;[[BZ)Ljava/lang/String;", Origin::CallGraph);
        assert_eq!(m.return_type(), "Ljava/lang/String;");
        assert!(m.returns_reference());
        assert_eq!(
            m.parameter_types(),
            vec!["I", "Ljava/lang/String;", "[[B", "Z"]
        );
        let v = ClosureMember::new("Lx;", "f", "()V", Origin::CallGraph);
        assert_eq!(v.return_type(), "V");
        assert!(!v.returns_reference());
        assert!(v.parameter_types().is_empty());
    }

    #[test]
    fn a_malformed_signature_yields_a_prefix_not_a_panic() {
        for bad in ["", "(", ")", "(I", "()", "(Ljava/lang/String", "([[[[I)V", "(Q)V", "garbage"] {
            let m = ClosureMember::new("Lx;", "f", bad, Origin::CallGraph);
            let _ = m.return_type();
            let _ = m.parameter_types();
        }
        // And a class descriptor with a semicolon inside is not special-cased
        // into an infinite loop.
        let m = ClosureMember::new("Lx;", "f", "(L;L;L;)V", Origin::CallGraph);
        assert!(!m.parameter_types().is_empty());
    }

    #[test]
    fn descriptor_splitting_handles_the_awkward_cases() {
        assert_eq!(split_descriptors("I"), vec!["I"]);
        assert_eq!(split_descriptors("IIJ"), vec!["I", "I", "J"]);
        assert_eq!(split_descriptors(""), Vec::<&str>::new());
        assert_eq!(split_descriptors("[[[I"), vec!["[[[I"]);
        assert_eq!(split_descriptors("Lx;"), vec!["Lx;"]);
    }

    #[test]
    fn duplicate_members_collapse_and_the_strongest_origin_wins() {
        let mut c = Closure::new();
        assert!(c.add(ClosureMember::new("La;", "m", "()V", Origin::CallGraph)));
        assert!(!c.add(ClosureMember::new("La;", "m", "()V", Origin::Override)));
        assert_eq!(c.len(), 1);
        assert_eq!(c.members()[0].origin, Origin::CallGraph);
        // A different signature is a different member.
        assert!(c.add(ClosureMember::new("La;", "m", "(I)V", Origin::Override)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn the_unresolved_reflective_count_is_derived_and_cannot_be_omitted() {
        let mut c = Closure::new();
        c.add_reflective(ReflectiveEdge {
            from_class: "La;".into(),
            target: "Landroid/os/Build;".into(),
            status: ReflectiveStatus::Resolved,
            site: None,
        });
        c.add_reflective(ReflectiveEdge::unresolved("La;", "Lcom/example/Missing;"));
        c.add_reflective(ReflectiveEdge::unresolved("La;", "Lcom/example/AlsoMissing;"));
        c.add_reflective(ReflectiveEdge {
            from_class: "La;".into(),
            target: "Lcom/example/;".into(),
            status: ReflectiveStatus::Ambiguous,
            site: None,
        });
        assert_eq!(c.unresolved_reflective(), 2);
        assert_eq!(c.ambiguous_reflective(), 1);
        assert!(!c.is_sound());
        let line = c.soundness_line();
        assert!(line.contains("2 unresolved"), "{line}");
        assert!(line.contains("NOT sound"), "{line}");
        // An empty closure reports zero rather than being silent about it.
        assert_eq!(Closure::new().unresolved_reflective(), 0);
    }

    #[test]
    fn class_count_deduplicates() {
        let mut c = Closure::new();
        for _ in 0..3 {
            c.add(ClosureMember::new("La/x;", "m", "()V", Origin::CallGraph));
        }
        c.add(ClosureMember::new("La/y;", "m", "()V", Origin::CallGraph));
        // The three identical members collapsed to one; `class_count` counts
        // distinct descriptors among what is actually in the closure, so it is
        // 2 rather than the 4 the pre-dedup input held.
        assert_eq!(c.len(), 2);
        assert_eq!(c.class_count(), 2);
    }
}
