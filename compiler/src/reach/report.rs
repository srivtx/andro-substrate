//! The closure report: every number, labelled, with its holes on the face.
//!
//! # Why this file is so defensive
//!
//! `IR.md` says "Every figure is labelled measured, derived, or conjecture", and
//! the project's founding error was a number published without the conditions
//! that produced it. So the report does not have a "just the headline" mode.
//! [`Provenance`] is attached to each figure at construction, [`Figure::note`]
//! carries the caveat, and the renderer refuses to print a figure without a
//! label.
//!
//! # The two things a reader must not miss
//!
//! 1. **The closure is a function of four policies and an entry set**, all
//!    printed in the header. A bare number means nothing without them.
//! 2. **The reflective-edge table.** `Closure::unresolved_reflective` is the
//!    size of what a static analysis cannot see, and `Cha` versus `Rta` differ
//!    in *soundness* because of it. It is printed before the totals, not after.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use crate::reach::model::{Program, UnitRole};
use crate::reach::{
    descriptor_to_dotted, is_framework_dotted, Closure, Config, EdgeKind, MethodId,
    ReflectiveVerdict,
};

/// Where a figure came from. `IR.md` requires every one to be labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Read directly off a file or a count over one, with no model in between.
    Measured,
    /// A computation over measured values, reproducible from the inputs.
    Derived,
    /// An interpretation. Not a measurement, and labelled as one so it cannot
    /// be quoted as one.
    Conjecture,
}

impl Provenance {
    /// The bracket tag printed in front of the value.
    pub fn tag(self) -> &'static str {
        match self {
            Provenance::Measured => "[measured]",
            Provenance::Derived => "[derived]",
            Provenance::Conjecture => "[conjecture]",
        }
    }
}

/// A number, its label, and the condition that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Figure {
    pub name: String,
    pub value: String,
    pub provenance: Provenance,
    /// Why this number is what it is. Never empty: a figure with no note is a
    /// figure that will be quoted out of context.
    pub note: String,
}

impl Figure {
    /// A figure counted off a file.
    pub fn measured(name: &str, value: impl std::fmt::Display, note: &str) -> Figure {
        Figure {
            name: name.into(),
            value: value.to_string(),
            provenance: Provenance::Measured,
            note: note.into(),
        }
    }

    /// A figure computed from measured values.
    pub fn derived(name: &str, value: impl std::fmt::Display, note: &str) -> Figure {
        Figure {
            name: name.into(),
            value: value.to_string(),
            provenance: Provenance::Derived,
            note: note.into(),
        }
    }

    /// An interpretation, labelled as one.
    pub fn conjecture(name: &str, value: impl std::fmt::Display, note: &str) -> Figure {
        Figure {
            name: name.into(),
            value: value.to_string(),
            provenance: Provenance::Conjecture,
            note: note.into(),
        }
    }
}

impl std::fmt::Display for Figure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} — {}",
            self.provenance.tag(),
            self.value,
            self.name
        )?;
        if !self.note.is_empty() {
            write!(f, " ({})", self.note)?;
        }
        Ok(())
    }
}

/// The rendered report.
#[derive(Debug, Clone, Default)]
pub struct ClosureReport {
    pub title: String,
    /// The four policies plus the entry policy and the window, as one line.
    pub header: String,
    pub manifest_summary: String,
    pub figures: Vec<Figure>,
    /// `kind: count` per edge kind, in `EdgeKind::ALL` order.
    pub edge_table: Vec<(EdgeKind, &'static str, usize, usize)>,
    /// Every reflective edge that could not be resolved, as
    /// `site -> literal`, sorted.
    pub unresolved_reflective: Vec<String>,
    /// Every class-shaped literal that did resolve, as `literal -> class`.
    pub resolved_reflective: Vec<String>,
    /// The entry points, in the order they were computed.
    pub entry_points: Vec<(String, String, String)>,
    /// Entry points whose class is not in the universe.
    pub entry_unresolved: Vec<String>,
    /// Entry points whose class is present but which declare no such method.
    pub entry_missing: Vec<String>,
    /// Manifest problems that change the closure.
    pub manifest_gaps: Vec<String>,
    /// Referenced classes no unit defines, with reference counts.
    pub unresolved_classes: Vec<(String, u32)>,
    /// Classes declared by more than one unit.
    pub shadowed: Vec<String>,
    /// Non-empty when a configured bound stopped the fixpoint.
    pub limits_hit: Vec<String>,
    /// The raw count of class-shaped literals, for the ratio.
    pub const_string_instructions: u64,
}

impl ClosureReport {
    /// Build a report from a closure and the universe it was computed over.
    pub fn build(
        program: &Program,
        closure: &Closure,
        app_label: &str,
        window_definition: &str,
    ) -> ClosureReport {
        let config: &Config = &closure.config;
        let header = format!(
            "app: {app_label} | entry: {} | {} | {} | {} | window: {window_definition}",
            config.entry.as_str(),
            config.dispatch.as_str(),
            config.framework.as_str(),
            config.reflection.as_str(),
        );

        let mut figures = Vec::new();
        let totals = program.totals();
        figures.push(Figure::derived(
            "closure size (methods)",
            closure.methods.len(),
            "distinct methods in the fixpoint, under the four policies in the header",
        ));
        figures.push(Figure::derived(
            "closure classes",
            closure.classes.len(),
            "distinct classes in the fixpoint, including the transitive superclass chain of every class in it",
        ));
        figures.push(Figure::measured(
            "const-string instructions decoded",
            closure.const_string_instructions,
            "every const-string and const-string/jumbo in every scanned body; the denominator for the reflective table",
        ));
        figures.push(Figure::measured(
            "class-shaped literals",
            closure
                .reflective_edges
                .iter()
                .filter(|e| e.descriptor.is_some())
                .count(),
            "literals that normalise to a class descriptor; the numerator",
        ));
        figures.push(Figure::measured(
            "unresolved reflective edges",
            closure.unresolved_reflective(),
            "IR.md: a closure is only sound if this is stated. Each is a literal that names a class the universe does not contain",
        ));
        figures.push(Figure::measured(
            "resolved reflective edges",
            closure.resolved_reflective(),
            "class-shaped literals whose class is in the universe; the class is in the closure, its methods are not unless it is a forName site",
        ));
        figures.push(Figure::measured(
            "Class.forName sites",
            closure.forname_reflective(),
            "literal passed to Class.forName/ClassLoader.loadClass at the next instruction in that argument position",
        ));
        figures.push(Figure::measured(
            "bodyless methods in the closure",
            closure.bodyless.len(),
            "no DEX body: native, abstract, or excluded by FrameworkSource::BlackBox. The host must implement each",
        ));
        figures.push(Figure::measured(
            "bodyless methods reached by a call site",
            closure.bodyless_called.len(),
            "the subset of the above the app's own bytecode asked for, as opposed to being an entry seed",
        ));
        figures.push(Figure::measured(
            "invoke-polymorphic methods in the closure",
            closure.polymorphic_sites.len(),
            "the method reference is named but the target is chosen at run time, so this is an under-approximation of a known size",
        ));
        figures.push(Figure::measured(
            "invoke-custom methods in the closure",
            closure.custom_sites.len(),
            "call-site-indirected targets: a hole of the same kind as reflection, and counted as one",
        ));
        figures.push(Figure::measured(
            "method bodies scanned",
            closure.bodies_scanned,
            "decoded and walked; every edge out of a body comes from one of these",
        ));
        figures.push(Figure::measured(
            "method bodies that failed to decode",
            closure.bodies_failed,
            "the edges out of these methods are missing from the closure. Non-zero is a soundness caveat",
        ));
        figures.push(Figure::measured(
            "method bodies skipped by FrameworkSource::BlackBox",
            closure.bodies_skipped_by_policy,
            "present in DEX, deliberately not walked",
        ));
        figures.push(Figure::derived(
            "fixpoint rounds",
            closure.rounds,
            "drain-and-re-resolve iterations actually run",
        ));
        figures.push(Figure::measured(
            "app methods in the closure",
            Closure::count_role(program, &closure.methods, UnitRole::App),
            "winning body comes from an app unit",
        ));
        figures.push(Figure::measured(
            "framework methods in the closure",
            Closure::count_role(program, &closure.methods, UnitRole::Framework),
            "winning body comes from a platform unit: the host-synthesis target",
        ));
        figures.push(Figure::derived(
            "app classes in the closure",
            closure
                .classes
                .iter()
                .filter(|c| {
                    program.classes[c.0 as usize]
                        .resolved()
                        .is_some_and(|d| program.units[d.unit.0 as usize].role == UnitRole::App)
                })
                .count(),
            "class-level counterpart of the app/host split",
        ));

        // Namespace view, the one comparable to an ART trace.
        let (ns_framework, ns_app) = namespace_split(program, &closure.methods);
        figures.push(Figure::derived(
            "framework-namespace methods (trace convention)",
            ns_framework,
            "class name starts with one of the trace/parse.py FRAMEWORK_PREFIXES and none of the exceptions; a convention, not a derivation from /system/framework",
        ));
        figures.push(Figure::derived(
            "app-namespace methods",
            ns_app,
            "everything else, including any third-party library the APK bundles",
        ));

        figures.push(Figure::measured(
            "universe units",
            totals.units,
            "DEX containers loaded for this run",
        ));
        figures.push(Figure::measured(
            "universe method_ids (DEX headers)",
            totals.header_method_ids,
            "sum of the u32 at DEX offset 0x58 over every loaded container; the arithmetic bound on how large any closure can be",
        ));
        figures.push(Figure::measured(
            "universe class_defs (DEX headers)",
            totals.header_class_defs,
            "sum of the u32 at DEX offset 0x38 over every loaded container",
        ));
        figures.push(Figure::measured(
            "universe classes indexed",
            totals.indexed_classes,
            "class_defs plus every type named by a field, prototype or string; classes referenced but defined nowhere are included",
        ));
        figures.push(Figure::measured(
            "universe methods indexed",
            totals.indexed_methods,
            "distinct (class, name, prototype) triples across all units",
        ));
        figures.push(Figure::measured(
            "shadowed classes",
            totals.shadowed_classes,
            "declared by more than one unit; host > app wins, per IR.md's supersede rule",
        ));

        let edge_table = EdgeKind::ALL
            .iter()
            .map(|k| {
                (
                    *k,
                    level_word(*k),
                    closure.method_edges_of(*k),
                    closure.class_edges_of(*k),
                )
            })
            .collect();

        let unresolved_reflective = closure
            .distinct_unresolved_literals()
            .into_iter()
            .map(|l| l.to_string())
            .collect();
        let resolved_reflective = {
            let mut set: BTreeSet<(String, String)> = BTreeSet::new();
            for e in &closure.reflective_edges {
                if e.verdict == ReflectiveVerdict::Resolved
                    || e.verdict == ReflectiveVerdict::ForNameSite
                {
                    set.insert((e.literal.clone(), e.descriptor.clone().unwrap_or_default()));
                }
            }
            set.into_iter()
                .map(|(l, d)| format!("{l} -> {d}"))
                .collect()
        };

        let entry_points = closure
            .entry
            .points
            .iter()
            .map(|p| (p.method.clone(), p.kind.tag().to_string(), p.reason.clone()))
            .collect();
        let entry_unresolved = closure
            .entry
            .unresolved
            .iter()
            .map(|p| p.method.clone())
            .collect();
        let entry_missing = closure
            .entry
            .missing
            .iter()
            .map(|p| p.method.clone())
            .collect();

        let mut limits_hit = Vec::new();
        if closure.hit_method_limit {
            limits_hit.push(format!(
                "max_rounds={} reached with work still queued: the closure is INCOMPLETE",
                config.max_rounds
            ));
        }
        if closure.hit_edge_limit {
            limits_hit.push(format!(
                "max_edges={} reached: edge counts are a LOWER BOUND",
                config.max_edges
            ));
        }

        ClosureReport {
            title: format!("closure report — {app_label}"),
            header,
            manifest_summary: format!(
                "manifest: {} | entry set: {} | surface widened: {}",
                entry_points_summary(closure),
                closure.entry.summary(),
                config.widen_to_full_surface
            ),
            figures,
            edge_table,
            unresolved_reflective,
            resolved_reflective,
            entry_points,
            entry_unresolved,
            entry_missing,
            manifest_gaps: Vec::new(),
            unresolved_classes: program.unresolved().into_iter().rev().collect(),
            shadowed: program
                .shadowed
                .iter()
                .map(|(d, u)| format!("{d} <- {}", u.join(", ")))
                .collect(),
            limits_hit,
            const_string_instructions: closure.const_string_instructions,
        }
    }

    /// The closure's headline number, with its label.
    pub fn closure_size(&self) -> Option<&Figure> {
        self.figures
            .iter()
            .find(|f| f.name == "closure size (methods)")
    }

    /// The reflective holes, which `IR.md` requires be visible.
    pub fn unresolved_reflective(&self) -> &[String] {
        &self.unresolved_reflective
    }

    /// True when the fixpoint finished inside every configured bound.
    pub fn is_complete(&self) -> bool {
        self.limits_hit.is_empty()
    }

    /// Render as Markdown.
    pub fn to_markdown(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "# {}", self.title);
        let _ = writeln!(o);
        let _ = writeln!(o, "```");
        let _ = writeln!(o, "{}", self.header);
        let _ = writeln!(o, "```");
        let _ = writeln!(o);
        let _ = writeln!(o, "## Figures");
        let _ = writeln!(o);
        let _ = writeln!(o, "| figure | value | provenance | condition |");
        let _ = writeln!(o, "|---|---:|---|---|");
        for f in &self.figures {
            let _ = writeln!(
                o,
                "| {} | `{}` | {} | {} |",
                f.name,
                f.value,
                f.provenance.tag(),
                f.note
            );
        }
        let _ = writeln!(o);
        let _ = writeln!(o, "## Edges by kind");
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "| kind | level | in IR.md's five | method-level | class-level |"
        );
        let _ = writeln!(o, "|---|---|---|---:|---:|");
        for (k, level, m, c) in &self.edge_table {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} |",
                k.as_str(),
                level,
                if k.is_ir_md() {
                    "yes"
                } else {
                    "**no — added here**"
                },
                m,
                c
            );
        }
        let _ = writeln!(o);
        let _ = writeln!(o, "## Reflection");
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "`const-string` instructions decoded: **{}** [measured]. A closure is only sound if the report says how many reflective edges were unresolved, and the answer is: **{}** [measured].",
            self.const_string_instructions,
            self.unresolved_reflective.len()
        );
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "### Unresolved reflective edges ({})",
            self.unresolved_reflective.len()
        );
        let _ = writeln!(o);
        if self.unresolved_reflective.is_empty() {
            let _ = writeln!(
                o,
                "_None. That is a claim worth distrusting, not a certificate._"
            );
        } else {
            let _ = writeln!(o, "Each is a string constant that normalises to a class descriptor the universe does not contain.");
            let _ = writeln!(o);
            for l in &self.unresolved_reflective {
                let _ = writeln!(o, "- `{l}`");
            }
        }
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "### Resolved reflective edges ({})",
            self.resolved_reflective.len()
        );
        let _ = writeln!(o);
        for l in &self.resolved_reflective {
            let _ = writeln!(o, "- `{l}`");
        }
        let _ = writeln!(o);
        let _ = writeln!(o, "## Entry points ({})", self.entry_points.len());
        let _ = writeln!(o);
        let _ = writeln!(o, "{}", self.manifest_summary);
        let _ = writeln!(o);
        let _ = writeln!(o, "| entry point | kind | why |");
        let _ = writeln!(o, "|---|---|---|");
        for (m, k, r) in &self.entry_points {
            let _ = writeln!(o, "| `{m}` | {k} | {r} |");
        }
        if !self.entry_unresolved.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "### Entry points whose class is not in the universe ({})",
                self.entry_unresolved.len()
            );
            for m in &self.entry_unresolved {
                let _ = writeln!(o, "- `{m}`");
            }
        }
        if !self.entry_missing.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "### Entry points whose class declares no such method ({})",
                self.entry_missing.len()
            );
            for m in &self.entry_missing {
                let _ = writeln!(o, "- `{m}`");
            }
        }
        if !self.unresolved_classes.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "## Referenced classes no unit defines ({})",
                self.unresolved_classes.len()
            );
            let _ = writeln!(o);
            let _ = writeln!(o, "| class | references |");
            let _ = writeln!(o, "|---|---:|");
            for (d, n) in self.unresolved_classes.iter().take(200) {
                let _ = writeln!(o, "| `{d}` | {n} |");
            }
            if self.unresolved_classes.len() > 200 {
                let _ = writeln!(o);
                let _ = writeln!(
                    o,
                    "_… and {} more; this table is truncated in the render, not in the count._",
                    self.unresolved_classes.len() - 200
                );
            }
        }
        if !self.shadowed.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(o, "## Shadowed classes ({})", self.shadowed.len());
            for s in &self.shadowed {
                let _ = writeln!(o, "- `{s}`");
            }
        }
        if !self.limits_hit.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(o, "## Limits hit");
            for l in &self.limits_hit {
                let _ = writeln!(o, "- **{l}**");
            }
        }
        o
    }

    /// Render as JSON. Hand-rolled: the crate has no dependencies and adding
    /// `serde` for a report nobody parses at run time is not worth the coupling.
    pub fn to_json(&self) -> String {
        let mut o = String::new();
        o.push_str("{\n");
        let _ = writeln!(o, "  \"title\": {},", json_str(&self.title));
        let _ = writeln!(o, "  \"header\": {},", json_str(&self.header));
        let _ = writeln!(o, "  \"complete\": {},", self.is_complete());
        o.push_str("  \"figures\": [\n");
        for (i, f) in self.figures.iter().enumerate() {
            let comma = if i + 1 == self.figures.len() { "" } else { "," };
            let tag = match f.provenance {
                Provenance::Measured => "measured",
                Provenance::Derived => "derived",
                Provenance::Conjecture => "conjecture",
            };
            let _ = writeln!(
                o,
                "    {{\"name\": {}, \"value\": {}, \"provenance\": \"{}\", \"note\": {}}}{comma}",
                json_str(&f.name),
                json_str(&f.value),
                tag,
                json_str(&f.note)
            );
        }
        o.push_str("  ],\n");
        o.push_str("  \"edges\": [\n");
        for (i, (k, level, m, c)) in self.edge_table.iter().enumerate() {
            let comma = if i + 1 == self.edge_table.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                o,
                "    {{\"kind\": \"{}\", \"level\": \"{}\", \"ir_md\": {}, \"method_level\": {}, \"class_level\": {}}}{comma}",
                k.as_str(),
                level,
                k.is_ir_md(),
                m,
                c
            );
        }
        o.push_str("  ],\n");
        let _ = writeln!(
            o,
            "  \"unresolved_reflective_edges\": {},",
            json_list(&self.unresolved_reflective)
        );
        let _ = writeln!(
            o,
            "  \"resolved_reflective_edges\": {},",
            json_list(&self.resolved_reflective)
        );
        o.push_str("  \"entry_points\": [\n");
        for (i, (m, k, r)) in self.entry_points.iter().enumerate() {
            let comma = if i + 1 == self.entry_points.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                o,
                "    {{\"method\": {}, \"kind\": \"{}\", \"why\": \"{}\"}}{comma}",
                json_str(m),
                k,
                r
            );
        }
        o.push_str("  ],\n");
        let _ = writeln!(
            o,
            "  \"entry_unresolved\": {},",
            json_list(&self.entry_unresolved)
        );
        let _ = writeln!(
            o,
            "  \"entry_missing\": {},",
            json_list(&self.entry_missing)
        );
        let _ = writeln!(
            o,
            "  \"manifest_gaps\": {},",
            json_list(&self.manifest_gaps)
        );
        let _ = writeln!(o, "  \"limits_hit\": {},", json_list(&self.limits_hit));
        o.push_str("  \"unresolved_classes\": [\n");
        for (i, (d, n)) in self.unresolved_classes.iter().enumerate() {
            let comma = if i + 1 == self.unresolved_classes.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                o,
                "    {{\"class\": {}, \"references\": {}}}{comma}",
                json_str(d),
                n
            );
        }
        o.push_str("  ],\n");
        let _ = writeln!(o, "  \"shadowed\": {}", json_list(&self.shadowed));
        o.push_str("}\n");
        o
    }
}

fn entry_points_summary(closure: &Closure) -> String {
    let mut n = std::collections::BTreeMap::new();
    for p in &closure.entry.points {
        *n.entry(p.kind.tag().to_string()).or_insert(0usize) += 1;
    }
    if n.is_empty() {
        return "no entry point resolved".into();
    }
    n.into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn level_word(k: EdgeKind) -> &'static str {
    if k.is_class_level() {
        "class"
    } else {
        "method"
    }
}

/// Split a method set by the trace's namespace convention.
pub fn namespace_split(program: &Program, methods: &BTreeSet<MethodId>) -> (usize, usize) {
    let mut fw = 0usize;
    let mut app = 0usize;
    for m in methods {
        let c = program.method_class(*m);
        if is_framework_dotted(&descriptor_to_dotted(program.descriptor(c))) {
            fw += 1;
        } else {
            app += 1;
        }
    }
    (fw, app)
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", c as u32);
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json_list(items: &[String]) -> String {
    let mut o = String::new();
    o.push('[');
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            o.push_str(", ");
        }
        o.push_str(&json_str(s));
    }
    o.push(']');
    o
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn json_escapes_control_characters() {
        assert_eq!(json_str("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
        assert_eq!(json_str("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn a_figure_always_prints_its_provenance() {
        let f = Figure::measured("n", 3usize, "counted");
        assert!(f.to_string().starts_with("[measured] 3"));
        let f = Figure::derived("n", 3usize, "computed");
        assert!(f.to_string().starts_with("[derived] 3"));
        let f = Figure::conjecture("n", "about 3", "guess");
        assert!(f.to_string().starts_with("[conjecture] about 3"));
    }
}
