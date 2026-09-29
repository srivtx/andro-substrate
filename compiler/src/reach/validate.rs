//! Cross-checking the static closure against an ART trace, and refusing to
//! make the two agree.
//!
//! # The point of this file
//!
//! The project's ground truth is a measurement: `eu.quelltext.gita` executed on
//! an Android 13 emulator calls **4,649 framework methods** over 894 classes in
//! a pinned window (`trace/FINDINGS.md`, `docs/analysis/0002-…`). A static
//! closure is a different quantity, and the useful thing to compute is not the
//! closest number but the **shape of the disagreement**:
//!
//! * `trace \ closure` — methods that demonstrably ran and the static analysis
//!   did not include. **This set must be empty for the closure to be a sound
//!   over-approximation.** If it is not empty, the closure is wrong, in the
//!   direction that hides work, and that is the direction this project has
//!   already been wrong in twice.
//! * `closure \ trace` — methods the analysis includes and nothing ran. The
//!   expected direction for any sound over-approximation, and the size of the
//!   synthesis bill.
//!
//! Neither direction is tuned. [`ValidationReport::render`] prints both, with
//! the reason each disagreement exists.
//!
//! # The trace reader is not a convenience
//!
//! `trace/FINDINGS.md` §7 documents two parser defects that each moved the
//! headline number: scanning past `*end` (1.6×–13.1× inflation) and reading the
//! header as method rows. Both are reproduced as defended-against behaviours
//! here, and the row accounting is closed — `table_rows == distinct +
//! duplicates + rejected` — so a reader cannot lose a row without it being
//! counted. A trace that reports `data-file-overflow=true` is labelled
//! `truncated`, and a truncated trace can only support a lower bound.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::reach::model::Program;
use crate::reach::{descriptor_to_dotted, is_framework_dotted, Closure, Config};

/// The ART trace layouts. Only the batched one carries an overflow flag, which
/// is why the continuous one cannot support an `exhaustive` claim at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `*version` … `*methods` … `*end`; text method table, overflow flag
    /// present.
    Batched,
    /// A binary 14-byte-record stream with no preamble and no flag. Not
    /// parsed here: its truncation is undetectable, so a count from it cannot
    /// be called exhaustive and parsing it would only invite that reading.
    Continuous,
    /// The file does not start like either.
    Undetermined,
}

impl Layout {
    pub fn as_str(self) -> &'static str {
        match self {
            Layout::Batched => "batched",
            Layout::Continuous => "continuous",
            Layout::Undetermined => "undetermined",
        }
    }
}

/// What a trace can support as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// No overflow flag was set. Every method entry the tracer wrote is here.
    Exhaustive,
    /// ART's own buffer overflowed, so this is a subset of what ran.
    Truncated,
    /// The layout carries no flag, so overflow cannot be checked.
    Unverifiable,
    /// The capture record is missing, so the file is not trusted.
    Untrusted,
}

impl Coverage {
    pub fn as_str(self) -> &'static str {
        match self {
            Coverage::Exhaustive => "exhaustive",
            Coverage::Truncated => "TRUNCATED (data-file-overflow) — lower bound",
            Coverage::Unverifiable => {
                "overflow NOT verifiable — cannot support an exhaustive claim"
            }
            Coverage::Untrusted => "untrusted",
        }
    }

    /// True only for a capture that can bound a closure from above.
    pub fn is_exhaustive(self) -> bool {
        matches!(self, Coverage::Exhaustive)
    }
}

/// A parsed ART trace method table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFile {
    pub path: String,
    pub layout: Layout,
    pub coverage: Coverage,
    pub version: Option<u32>,
    pub elapsed_usec: Option<u64>,
    pub num_method_calls: Option<u64>,
    /// Rows between `*methods` and `*end`, one per method entry.
    pub table_rows: usize,
    /// Distinct `Lclass;.name(sig)ret` keys, framework namespaces only.
    pub distinct: BTreeSet<String>,
    /// Distinct keys including the app's own namespaces.
    pub distinct_all: BTreeSet<String>,
    pub duplicates: usize,
    /// Rejection reason -> count. Sums with `distinct_all` and `duplicates` to
    /// `table_rows`.
    pub rejected: BTreeMap<String, usize>,
}

impl TraceFile {
    /// Rejection accounting, closed by construction.
    pub fn accounting_ok(&self) -> bool {
        let rejected: usize = self.rejected.values().sum();
        self.table_rows == self.distinct_all.len() + self.duplicates + rejected
    }

    /// Total rejections.
    pub fn rejected_total(&self) -> usize {
        self.rejected.values().sum()
    }
}

/// Why a trace could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    Empty,
    UndeterminedLayout,
    NoMethodsSection,
    NoEndMarker,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::Empty => write!(
                f,
                "trace file is 0 bytes; a failed capture is not a measurement"
            ),
            TraceError::UndeterminedLayout => {
                write!(f, "trace is neither the batched nor the continuous layout")
            }
            TraceError::NoMethodsSection => write!(f, "trace has no *methods section"),
            TraceError::NoEndMarker => write!(
                f,
                "trace has no *end marker; rows past it are not method entries"
            ),
        }
    }
}

impl std::error::Error for TraceError {}

/// Parse a batched ART trace.
///
/// Two defences, both of which `trace/FINDINGS.md` §7 records as load-bearing:
/// the method table is read **only** between `*methods` and `*end`, and every
/// row's four fields are validated independently so a misaligned read is
/// rejected with a reason rather than accepted as a class named `628`.
pub fn parse_trace(path: &str, bytes: &[u8]) -> Result<TraceFile, TraceError> {
    if bytes.is_empty() {
        return Err(TraceError::Empty);
    }
    if bytes.starts_with(b"SLOW") {
        return Err(TraceError::UndeterminedLayout);
    }
    let text = String::from_utf8_lossy(bytes);
    let start = text
        .find("\n*methods\n")
        .ok_or(TraceError::NoMethodsSection)?
        + "\n*methods\n".len();
    let end = text[start..]
        .find("\n*end")
        .ok_or(TraceError::NoEndMarker)?
        + start;
    let head = &text[..start];

    let mut version = None;
    let mut overflow = None;
    let mut elapsed = None;
    let mut calls = None;
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("*version") {
            version = v.trim().parse().ok();
        }
        if let Some(v) = line.strip_prefix("data-file-overflow=") {
            overflow = Some(v.trim() == "true");
        }
        if let Some(v) = line.strip_prefix("elapsed-time-usec=") {
            elapsed = v.trim().parse().ok();
        }
        if let Some(v) = line.strip_prefix("num-method-calls=") {
            calls = v.trim().parse().ok();
        }
    }

    let mut t = TraceFile {
        path: path.to_string(),
        layout: Layout::Batched,
        coverage: match overflow {
            Some(true) => Coverage::Truncated,
            Some(false) => Coverage::Exhaustive,
            // The batched layout always writes the flag; a file without one is
            // not something to guess about.
            None => Coverage::Untrusted,
        },
        version,
        elapsed_usec: elapsed,
        num_method_calls: calls,
        table_rows: 0,
        distinct: BTreeSet::new(),
        distinct_all: BTreeSet::new(),
        duplicates: 0,
        rejected: BTreeMap::new(),
    };

    for line in text[start..end].lines() {
        if line.is_empty() {
            continue;
        }
        t.table_rows += 1;
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 4 {
            *t.rejected.entry("too-few-fields".into()).or_insert(0) += 1;
            continue;
        }
        if !is_dotted_identifier(f[1]) {
            *t.rejected
                .entry("class-not-a-dotted-identifier".into())
                .or_insert(0) += 1;
            continue;
        }
        if !is_jvm_descriptor(f[3]) {
            *t.rejected
                .entry("signature-not-a-descriptor".into())
                .or_insert(0) += 1;
            continue;
        }
        let key = format!("L{};.{}{}", f[1].replace('.', "/"), f[2], f[3]);
        if !t.distinct_all.insert(key) {
            t.duplicates += 1;
        }
        if is_framework_dotted(f[1]) {
            let k = format!("L{};.{}{}", f[1].replace('.', "/"), f[2], f[3]);
            t.distinct.insert(k);
        }
    }
    Ok(t)
}

fn is_java_ident(s: &str) -> bool {
    let mut c = s.chars();
    let head_ok = matches!(c.next(), Some(x) if x.is_ascii_alphabetic() || x == '_' || x == '$');
    head_ok && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '$')
}

fn is_dotted_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.').all(is_java_ident)
}

/// A syntactically valid JVM method descriptor, including the array and
/// `L...;` forms that a first cut of this grammar rejected and which turned out
/// to be 1,076 of gita's 4,649 real framework methods.
///
/// `V` is accepted as a return type and rejected as a parameter, as the JVM
/// requires.
pub fn is_jvm_descriptor(s: &str) -> bool {
    let b: Vec<char> = s.chars().collect();
    if b.first() != Some(&'(') {
        return false;
    }
    // A field descriptor never contains `)` outside `L...;`, and `)` is not a
    // legal character inside one, so the first `)` is the matching one.
    let Some(close) = b.iter().position(|&c| c == ')') else {
        return false;
    };
    let mut i = 1usize;
    while i < close {
        if consume_field_descriptor(&b, &mut i, false).is_none() {
            return false;
        }
    }
    let mut r = close + 1;
    if r >= b.len() {
        return false;
    }
    consume_field_descriptor(&b, &mut r, true).is_some() && r == b.len()
}

/// Consume one field descriptor at `*i`, returning its length in characters.
fn consume_field_descriptor(b: &[char], i: &mut usize, allow_void: bool) -> Option<usize> {
    let start = *i;
    while *i < b.len() && b[*i] == '[' {
        *i += 1;
    }
    if *i >= b.len() {
        return None;
    }
    match b[*i] {
        'L' => {
            let mut j = *i + 1;
            let mut saw = false;
            while j < b.len() && b[j] != ';' {
                if !(b[j].is_ascii_alphanumeric() || b[j] == '_' || b[j] == '$' || b[j] == '/') {
                    return None;
                }
                saw = true;
                j += 1;
            }
            if j >= b.len() || !saw {
                return None;
            }
            *i = j + 1;
            Some(*i - start)
        }
        'V' if allow_void => {
            *i += 1;
            Some(*i - start)
        }
        'Z' | 'B' | 'S' | 'C' | 'I' | 'J' | 'F' | 'D' => {
            *i += 1;
            Some(*i - start)
        }
        _ => None,
    }
}

/// The comparison of a static closure against a measured trace.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub trace_path: String,
    pub coverage: Coverage,
    /// Distinct framework methods ART recorded.
    pub trace_methods: usize,
    /// Distinct classes those methods live on.
    pub trace_classes: usize,
    /// Closure methods in the trace's framework namespaces — the number
    /// directly comparable to `trace_methods`.
    pub static_framework_methods: usize,
    /// Every method in the closure, framework or not.
    pub static_all_methods: usize,
    /// `closure ∩ trace`.
    pub intersection: usize,
    /// `trace \ closure`. Must be empty for the closure to sound.
    pub missing: BTreeSet<String>,
    /// `closure \ trace`, the synthesis bill.
    pub extra: usize,
    pub jaccard: Option<f64>,
    /// `intersection / trace_methods`: how much of the ground truth the static
    /// analysis explains.
    pub containment: f64,
    /// `static_framework_methods / trace_methods`.
    pub ratio: f64,
    /// What the static closure is called, so a number never appears without it.
    pub closure_label: String,
    /// Per-namespace counts of what is missing, largest first.
    pub missing_by_namespace: Vec<(String, usize)>,
    /// Rows the trace reader rejected, with reasons.
    pub trace_rejections: BTreeMap<String, usize>,
    pub trace_table_rows: usize,
    pub trace_duplicates: usize,
}

impl ValidationReport {
    /// True when the closure is an over-approximation of the trace, which is
    /// the property `IR.md`'s closure has to have to be worth anything.
    pub fn is_over_approximation(&self) -> bool {
        self.missing.is_empty()
    }

    /// The honest summary line.
    pub fn verdict(&self) -> String {
        let dir = if self.is_over_approximation() {
            "over-approximation of the trace"
        } else {
            "NOT an over-approximation — the closure omits methods that ran"
        };
        format!(
            "static {} vs trace {} ({}) — {dir}; {} of {} traced methods missing",
            self.static_framework_methods,
            self.trace_methods,
            self.coverage.as_str(),
            self.missing.len(),
            self.trace_methods
        )
    }

    /// Render as Markdown, with every difference explained rather than tuned.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut o = String::new();
        let _ = writeln!(o, "## Validation — static closure against ART trace");
        let _ = writeln!(o);
        let _ = writeln!(o, "```");
        let _ = writeln!(o, "closure: {}", self.closure_label);
        let _ = writeln!(
            o,
            "trace:   {} — {}",
            self.trace_path,
            self.coverage.as_str()
        );
        let _ = writeln!(o, "```");
        let _ = writeln!(o);
        let _ = writeln!(
            o,
            "| | static [derived] | measured [measured] | ratio [derived] |"
        );
        let _ = writeln!(o, "|---|---:|---:|---:|");
        let _ = writeln!(
            o,
            "| framework methods | {} | {} | {:.2}× |",
            self.static_framework_methods, self.trace_methods, self.ratio
        );
        let _ = writeln!(
            o,
            "| all methods in the closure | {} | — | — |",
            self.static_all_methods
        );
        let _ = writeln!(o, "| classes | — | {} | — |", self.trace_classes);
        let _ = writeln!(o);
        let _ = writeln!(o, "- **intersection** (in both): **{}**", self.intersection);
        let _ = writeln!(
            o,
            "- **containment** (share of the trace the static closure explains): **{:.4}**",
            self.containment
        );
        let _ = writeln!(
            o,
            "- **Jaccard**: {}",
            self.jaccard
                .map(|j| format!("{j:.4}"))
                .unwrap_or_else(|| "undefined (a set is empty)".into())
        );
        let _ = writeln!(
            o,
            "- **missing** (traced but not in the closure): **{}**",
            self.missing.len()
        );
        let _ = writeln!(
            o,
            "- **extra** (in the closure, never traced): **{}**",
            self.extra
        );
        let _ = writeln!(o);
        let _ = writeln!(o, "### Reading");
        let _ = writeln!(o);
        if self.missing.is_empty() {
            let _ = writeln!(
                o,
                "Every framework method ART recorded for this window is in the static closure. That is the \
                 necessary condition for soundness, and it is satisfied here — but only *for this window and \
                 this entry state*, and only given the reflective-edge count in the closure report."
            );
        } else {
            let _ = writeln!(
                o,
                "**{} traced methods are absent from the static closure.** That is a defect, not a \
                 tightness result: a sound over-approximation cannot omit anything that ran. The causes, \
                 in the order they should be ruled out:",
                self.missing.len()
            );
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "1. **Reflection.** A `Class.forName`/`getMethod`/`invoke` path reaches a method DEX never \
                   names. This is the expected explanation and it is exactly what the closure's \
                   `unresolved reflective edges` figure measures."
            );
            let _ = writeln!(
                o,
                "2. **A window or entry-state mismatch.** The trace covers a cold start; the closure is \
                   seeded from whatever `EntryPolicy` the header names. Teardown-only work, and work after \
                   the app settles, are in the trace and not in the closure."
            );
            let _ = writeln!(
                o,
                "3. **Framework code that DEX cannot reach from an app entry.** System-side callbacks, \
                   `ContentProvider` plumbing and the ActivityThread handlers the app never names."
            );
            if !self.missing_by_namespace.is_empty() {
                let _ = writeln!(o);
                let _ = writeln!(o, "Missing methods by namespace:");
                let _ = writeln!(o);
                for (ns, n) in &self.missing_by_namespace {
                    let _ = writeln!(o, "- `{ns}`: {n}");
                }
            }
            let _ = writeln!(o);
            let _ = writeln!(o, "First twenty:");
            for m in self.missing.iter().take(20) {
                let _ = writeln!(o, "- `{m}`");
            }
        }
        if !self.trace_rejections.is_empty() {
            let _ = writeln!(o);
            let _ = writeln!(o, "### Trace reader accounting");
            let _ = writeln!(o);
            let _ = writeln!(
                o,
                "rows {} = distinct {} + duplicates {} + rejected {}",
                self.trace_table_rows,
                self.trace_methods,
                self.trace_duplicates,
                self.trace_rejections.values().sum::<usize>()
            );
            for (r, n) in &self.trace_rejections {
                let _ = writeln!(o, "- `{r}`: {n}");
            }
        }
        o
    }
}

/// Compare a closure against a parsed trace.
pub fn validate_against_trace(
    program: &Program,
    closure: &Closure,
    trace: &TraceFile,
    closure_label: &str,
) -> ValidationReport {
    let mut static_keys: BTreeSet<String> = BTreeSet::new();
    let mut static_classes: BTreeSet<String> = BTreeSet::new();
    for m in &closure.methods {
        let c = program.method_class(*m);
        let dotted = descriptor_to_dotted(program.descriptor(c));
        if is_framework_dotted(&dotted) {
            static_keys.insert(format!(
                "{}.{}{}",
                program.descriptor(c),
                program.method_name(*m),
                program.method_proto(*m)
            ));
            static_classes.insert(dotted);
        }
    }
    let trace_classes: BTreeSet<String> = trace
        .distinct
        .iter()
        .map(|k| descriptor_to_dotted(&k[..k.find(';').unwrap_or(0) + 1]))
        .collect();

    let intersection = static_keys.intersection(&trace.distinct).count();
    let missing: BTreeSet<String> = trace.distinct.difference(&static_keys).cloned().collect();
    let extra = static_keys.difference(&trace.distinct).count();
    let union = static_keys.union(&trace.distinct).count();

    let mut missing_by_namespace: BTreeMap<String, usize> = BTreeMap::new();
    for m in &missing {
        let dotted = descriptor_to_dotted(&m[..m.find(';').unwrap_or(0) + 1]);
        *missing_by_namespace
            .entry(first_two_segments(&dotted))
            .or_insert(0) += 1;
    }
    let mut missing_by_namespace: Vec<(String, usize)> = missing_by_namespace.into_iter().collect();
    missing_by_namespace.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    ValidationReport {
        trace_path: trace.path.clone(),
        coverage: trace.coverage,
        trace_methods: trace.distinct.len(),
        trace_classes: trace_classes.len(),
        static_framework_methods: static_keys.len(),
        static_all_methods: closure.methods.len(),
        intersection,
        missing,
        extra,
        jaccard: if union == 0 {
            None
        } else {
            Some(intersection as f64 / union as f64)
        },
        containment: if trace.distinct.is_empty() {
            0.0
        } else {
            intersection as f64 / trace.distinct.len() as f64
        },
        ratio: if trace.distinct.is_empty() {
            f64::INFINITY
        } else {
            static_keys.len() as f64 / trace.distinct.len() as f64
        },
        closure_label: closure_label.to_string(),
        missing_by_namespace,
        trace_rejections: trace.rejected.clone(),
        trace_table_rows: trace.table_rows,
        trace_duplicates: trace.duplicates,
    }
}

fn first_two_segments(dotted: &str) -> String {
    let mut it = dotted.split('.');
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => format!("{a}.{b}"),
        (Some(a), None) => a.to_string(),
        _ => ".".into(),
    }
}

/// One cell of a policy sweep: the closure under a named configuration.
#[derive(Debug)]
pub struct SweepCell {
    pub name: String,
    pub closure: Closure,
}

/// Run several configurations over one universe.
///
/// Building the universe is the expensive half and does not depend on any
/// policy, so it is built once here and handed to each analyzer in turn. This
/// is what makes the range in the report cheap to produce and therefore hard to
/// forget.
pub fn run_sweep(
    mut program: Program,
    manifest: &crate::reach::entry::Manifest,
    configs: Vec<(String, Config)>,
) -> (Program, Vec<SweepCell>) {
    let mut cells = Vec::with_capacity(configs.len());
    for (name, config) in configs {
        let entry = crate::reach::entry::entry_points(
            &program,
            manifest,
            config.entry,
            config.widen_to_full_surface,
        );
        let analyzer = crate::reach::Analyzer::new(&mut program, config);
        let mut closure = analyzer.run(&entry);
        closure.unresolved_classes = program
            .unresolved_classes
            .iter()
            .map(|(d, _)| d.clone())
            .collect();
        cells.push(SweepCell { name, closure });
    }
    (program, cells)
}

/// The configuration grid the report sweeps, named so each row is a claim.
///
/// The axes are chosen to bracket the answer rather than to sample it: the two
/// dispatch policies differ in *soundness*, the two framework policies differ in
/// *architecture*, and the two entry policies differ in *what "before first
/// frame" means*.
pub fn default_grid() -> Vec<(String, Config)> {
    use crate::reach::{DispatchPolicy, FrameworkSource, ReflectionPolicy};
    let base = Config::default();
    let mut out = Vec::new();
    let mut cell = |name: &str, d: DispatchPolicy, f: FrameworkSource, r: ReflectionPolicy, e| {
        let mut c = base.clone();
        c.dispatch = d;
        c.framework = f;
        c.reflection = r;
        c.entry = e;
        out.push((name.to_string(), c));
    };
    cell(
        "RTA / framework followed / IR.md entry",
        DispatchPolicy::Rta,
        FrameworkSource::Follow,
        ReflectionPolicy::ForNameExpands,
        crate::reach::entry::EntryPolicy::IrMd,
    );
    cell(
        "RTA / framework black-box / IR.md entry",
        DispatchPolicy::Rta,
        FrameworkSource::BlackBox,
        ReflectionPolicy::ForNameExpands,
        crate::reach::entry::EntryPolicy::IrMd,
    );
    cell(
        "RTA / framework black-box / cold-start entry",
        DispatchPolicy::Rta,
        FrameworkSource::BlackBox,
        ReflectionPolicy::ForNameExpands,
        crate::reach::entry::EntryPolicy::ColdStart,
    );
    cell(
        "CHA / framework followed / IR.md entry",
        DispatchPolicy::Cha,
        FrameworkSource::Follow,
        ReflectionPolicy::ForNameExpands,
        crate::reach::entry::EntryPolicy::IrMd,
    );
    out
}

/// Which methods a closure holds, as trace keys, for a caller that wants the
/// set rather than the comparison.
pub fn trace_keys(program: &Program, closure: &Closure) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for m in &closure.methods {
        let c = program.method_class(*m);
        out.insert(format!(
            "{}.{}{}",
            program.descriptor(c),
            program.method_name(*m),
            program.method_proto(*m)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn descriptor_grammar_accepts_what_real_traces_contain() {
        // These four forms are exactly the ones trace/FINDINGS.md §7 records a
        // first cut of the grammar rejecting, and 1,076 of gita's 4,649 rows.
        assert!(is_jvm_descriptor("()[Ljava/lang/Object;"));
        assert!(is_jvm_descriptor("()[I"));
        assert!(is_jvm_descriptor(
            "(I)[Landroid/content/pm/ApplicationInfo;"
        ));
        assert!(is_jvm_descriptor("()Ljava/lang/String;"));
        assert!(is_jvm_descriptor(
            "(Ljava/lang/String;Ljava/lang/ClassLoader;Z)Ljava/lang/Class;"
        ));
        assert!(is_jvm_descriptor("(Landroid/view/View$OnClickListener;)V"));
    }

    #[test]
    fn descriptor_grammar_rejects_misaligned_reads() {
        assert!(!is_jvm_descriptor("628"));
        assert!(!is_jvm_descriptor("()"));
        assert!(!is_jvm_descriptor("Ljava/lang/String;"));
        assert!(!is_jvm_descriptor("(Q)V"));
        assert!(!is_jvm_descriptor("()[Ljava/lang/Object"));
    }

    #[test]
    fn an_empty_trace_is_an_error_not_an_empty_set() {
        // A zero-byte capture is a failed capture. Returning an empty method set
        // would make it score as a perfect match against an empty closure.
        assert_eq!(parse_trace("t", b""), Err(TraceError::Empty));
    }

    #[test]
    fn the_continuous_layout_is_refused_rather_than_misread() {
        let mut f = b"SLOW".to_vec();
        f.extend_from_slice(&[0u8; 32]);
        assert_eq!(parse_trace("t", &f), Err(TraceError::UndeterminedLayout));
    }

    #[test]
    fn a_missing_end_marker_is_refused() {
        let body = "*version\n3\ndata-file-overflow=false\n*methods\n0x1\ta.b.C\tm\t()V\tC.java\n";
        assert_eq!(
            parse_trace("t", body.as_bytes()),
            Err(TraceError::NoEndMarker)
        );
    }

    #[test]
    fn rows_past_the_end_marker_are_not_method_entries() {
        // The defect trace/FINDINGS.md §7 quantifies: scanning to EOF instead of
        // stopping at *end inflated gita's table 13.1x.
        let mut f = String::from("*version\n3\ndata-file-overflow=false\n*methods\n");
        for i in 0..3 {
            let _ = std::fmt::Write::write_fmt(
                &mut f,
                format_args!("0x{i}\ta.b.C\tm{i}\t()V\tC.java\n"),
            );
        }
        f.push_str("*end\n");
        for i in 100..140 {
            let _ = std::fmt::Write::write_fmt(
                &mut f,
                format_args!("0x{i}\ta.b.C\tm{i}\t()V\tC.java\n"),
            );
        }
        let t = parse_trace("t", f.as_bytes()).expect("parse");
        assert_eq!(t.table_rows, 3, "rows after *end must not be counted");
        assert_eq!(t.distinct_all.len(), 3);
        assert!(t.accounting_ok());
        assert_eq!(t.coverage, Coverage::Exhaustive);
    }

    #[test]
    fn a_header_read_as_a_row_is_rejected_with_a_reason() {
        let mut f = String::from("*version\n3\ndata-file-overflow=false\n*methods\n");
        f.push_str("0x1\ta.b.C\tm\t()V\tC.java\n");
        f.push_str(
            "*version\t3\tdata-file-overflow=false\tclock=dual\telapsed-time-usec=6289722\n",
        );
        f.push_str("*end\n");
        let t = parse_trace("t", f.as_bytes()).expect("parse");
        assert_eq!(t.table_rows, 2);
        assert_eq!(
            t.rejected.get("class-not-a-dotted-identifier").copied(),
            Some(1)
        );
        assert!(t.accounting_ok());
    }

    #[test]
    fn overflow_downgrades_coverage_to_truncated() {
        let f =
            "*version\n3\ndata-file-overflow=true\n*methods\n0x1\ta.b.C\tm\t()V\tC.java\n*end\n";
        let t = parse_trace("t", f.as_bytes()).expect("parse");
        assert_eq!(t.coverage, Coverage::Truncated);
        assert!(!t.coverage.is_exhaustive());
    }

    #[test]
    fn app_namespaces_are_excluded_from_the_framework_set() {
        let f = "*version\n3\ndata-file-overflow=false\n*methods\n\
                 0x1\tandroid.app.Activity\tonCreate\t(Landroid/os/Bundle;)V\tActivity.java\n\
                 0x2\teu.quelltext.gita.MainActivity\tonCreate\t(Landroid/os/Bundle;)V\tMainActivity.java\n\
                 *end\n";
        let t = parse_trace("t", f.as_bytes()).expect("parse");
        assert_eq!(t.distinct_all.len(), 2);
        assert_eq!(t.distinct.len(), 1);
        assert!(t
            .distinct
            .iter()
            .next()
            .expect("one")
            .starts_with("Landroid/app/Activity;"));
    }
}
