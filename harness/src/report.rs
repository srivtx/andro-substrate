//! The run report: a plain-text summary a researcher can read without opening
//! the recording.
//!
//! # Why a second document
//!
//! The recording is the deliverable and it is a `ground-truth/1` document, which
//! is a schema for a *capture* and not for a *failure analysis*. The single most
//! important fact this project produced so far — how much framework surface an
//! app needs before it stops — has nowhere to live in that schema that would not
//! either overstate it (it is not an observation of the app) or bury it (an
//! `exceptions[]` entry says the app threw, not what the shim lacks).
//!
//! So there are two artefacts and neither pretends to be the other. The
//! recording validates and can be diffed against a device capture. The report is
//! a table with a rung, a count and an error string, and it says which of those
//! three is a measurement and which is a bound.

use std::fmt::Write as _;

/// What one run produced, in the shape the report wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// The APK's package.
    pub package: String,
    /// The `--policy` value as written.
    pub policy: String,
    /// The terminal the lifecycle ladder derived.
    pub terminal: String,
    /// The stage the run stopped at, as a line of prose.
    pub stopped_because: String,
    /// Per-stage outcomes, already rendered.
    pub stages: Vec<StageLine>,
    /// Framework methods the shim does not have, over the whole run.
    pub missing_surface: Vec<String>,
    /// Every `(class, name, signature)` nothing could answer, engine-wide.
    pub unresolved: Vec<String>,
    /// App classes the shim's class table shadowed.
    pub shadowed: Vec<String>,
    /// `invokedynamic` bootstrap owners refused.
    pub indy_refused: Vec<String>,
    /// Instructions executed.
    pub instructions: u64,
    /// Framework calls made.
    pub framework_calls: u64,
    /// Of those, the ones the shim did not implement.
    pub unimplemented: u64,
    /// Distinct opcodes the engine dispatched.
    pub opcodes: u32,
    /// Calls declined because an argument had no shim-side representation.
    pub unrepresentable: u64,
    /// `classes2.dex` and later, not loaded.
    pub extra_dex_files: usize,
    /// Native libraries the APK declares.
    pub native_libs: Vec<String>,
}

/// One stage, as a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageLine {
    /// The entry point kind.
    pub kind: &'static str,
    /// `Lcom/example/Foo;.bar()V`.
    pub target: String,
    /// `ok`, or the engine's terminal condition.
    pub outcome: String,
    /// Instructions.
    pub instructions: u64,
    /// Framework calls.
    pub framework_calls: u64,
    /// Framework surface first requested in this stage.
    pub missing: Vec<String>,
    /// The full error, when there was one.
    pub error: Option<String>,
}

/// Render the report.
pub fn render_report(s: &RunSummary) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "andro-substrate — real APK run report");
    let _ = writeln!(
        o,
        "================================================================"
    );
    let _ = writeln!(o, "package                {}", s.package);
    let _ = writeln!(o, "substrate policy       {}", s.policy);
    let _ = writeln!(o, "lifecycle.terminal     {}", s.terminal);
    let _ = writeln!(o);
    let _ = writeln!(o, "STOPPED BECAUSE");
    let _ = writeln!(o, "  {}", s.stopped_because);
    let _ = writeln!(o);
    let _ = writeln!(o, "STAGES");
    for st in &s.stages {
        let _ = writeln!(
            o,
            "  {:<22} {:<52} {:<22} {:>9} ins  {:>6} fw",
            st.kind, st.target, st.outcome, st.instructions, st.framework_calls
        );
        if !st.missing.is_empty() {
            let _ = writeln!(
                o,
                "  {:<22} framework surface first requested here: {}",
                "",
                st.missing.len()
            );
            for m in st.missing.iter().take(12) {
                let _ = writeln!(o, "      {m}");
            }
            if st.missing.len() > 12 {
                let _ = writeln!(o, "      … and {} more", st.missing.len() - 12);
            }
        }
        if let Some(e) = &st.error {
            let _ = writeln!(o, "  {:<22} error: {e}", "");
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "ENGINE");
    let _ = writeln!(o, "  instructions executed      {}", s.instructions);
    let _ = writeln!(o, "  distinct opcodes           {}", s.opcodes);
    let _ = writeln!(o, "  framework calls            {}", s.framework_calls);
    let _ = writeln!(o, "  … of those unimplemented   {}", s.unimplemented);
    let _ = writeln!(o, "  … args untranslatable     {}", s.unrepresentable);
    let _ = writeln!(o, "  extra classes*.dex skipped {}", s.extra_dex_files);
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "SHIM SURFACE THIS APK NEEDED AND DID NOT HAVE — {}",
        s.missing_surface.len()
    );
    if s.missing_surface.is_empty() {
        let _ = writeln!(
            o,
            "  none: the app reached the end of the driver's stages without asking for a framework \
             method the shim lacks"
        );
    } else {
        for m in &s.missing_surface {
            let _ = writeln!(o, "  {m}");
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "UNRESOLVED — nothing declared these, engine-wide: {}",
        s.unresolved.len()
    );
    for u in &s.unresolved {
        let _ = writeln!(o, "  {u}");
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "SUPERSEDE — app classes the shim shadowed: {}",
        s.shadowed.len()
    );
    for c in &s.shadowed {
        let _ = writeln!(o, "  {c}");
    }
    let _ = writeln!(
        o,
        "INVOKEDYNAMIC — bootstrap owners refused: {}",
        s.indy_refused.len()
    );
    for b in &s.indy_refused {
        let _ = writeln!(o, "  {b}");
    }
    if !s.native_libs.is_empty() {
        let _ = writeln!(
            o,
            "NATIVE — the APK ships {} librar{}, none of which can load here",
            s.native_libs.len(),
            if s.native_libs.len() == 1 { "y" } else { "ies" }
        );
    }
    o
}
