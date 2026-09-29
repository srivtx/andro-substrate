//! `reach-report` — compute a closure for an APK and print the report.
//!
//! ```text
//! reach-report <apk>... --framework <dir-of-boot-classpath-jars> [--json]
//!               [--trace <art-trace>]... [--window <label>] [--no-framework]
//! ```
//!
//! # Why a binary at all
//!
//! A closure is a function of four policies and a universe, and the policies
//! live in the library. A driver that names them on the command line and
//! prints the report is what makes "the number" reproducible by someone who did
//! not write the analysis: every invocation is a complete specification of what
//! was computed.
//!
//! # The framework directory
//!
//! `--framework` takes the boot classpath as a directory of jars, in
//! `BOOTCLASSPATH` order. On a device that is
//! `adb shell 'echo $BOOTCLASSPATH'` and one `adb pull` per entry. Without it,
//! the framework is absent from the universe and the report says so on its
//! face: a closure over an app's own DEX is a different, much smaller quantity,
//! and printing it without that caveat is how a 40-method number gets quoted as
//! an app's framework surface.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use andro_compiler::reach::entry::Manifest;
use andro_compiler::reach::model::Program;
use andro_compiler::reach::report::ClosureReport;
use andro_compiler::reach::validate::{self, Coverage};
use andro_compiler::reach::{
    app_inputs_from_apk, framework_inputs_from_jar, Analyzer, Config, DexInput, DispatchPolicy,
    EntryPolicy, FrameworkSource, ReflectionPolicy, UnitRole,
};

#[derive(Debug, Default)]
struct Args {
    apks: Vec<PathBuf>,
    framework_dir: Option<PathBuf>,
    boot_classpath: Option<PathBuf>,
    traces: Vec<PathBuf>,
    window: String,
    json: bool,
    sweep: bool,
    widen: bool,
}

const USAGE: &str = "\
reach-report — the static closure of an APK, with its policies and its holes

usage:
  reach-report <apk>... [options]

options:
  --framework <dir>        directory of boot-classpath jars (in BOOTCLASSPATH order)
  --boot-classpath <file>  a file whose lines are jar paths; overrides --framework
  --trace <file>           an ART trace to cross-check against; repeatable
  --window <label>         the window definition to print on the report header
  --json                   emit JSON instead of Markdown
  --sweep                  run the default policy grid and tabulate the range
  --widen                 add each component's whole overridable surface to the entry set
  -h, --help               this text
";

fn main() -> ExitCode {
    let mut args = Args { window: "unspecified — pass --window to state it".into(), ..Default::default() };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--framework" => args.framework_dir = it.next().map(PathBuf::from),
            "--boot-classpath" => args.boot_classpath = it.next().map(PathBuf::from),
            "--trace" => args.traces.push(it.next().map(PathBuf::from).unwrap_or_default()),
            "--window" => args.window = it.next().unwrap_or_else(|| "unspecified".into()),
            "--json" => args.json = true,
            "--sweep" => args.sweep = true,
            "--widen" => args.widen = true,
            other if other.starts_with('-') => {
                eprintln!("reach-report: unknown option {other}\n\n{USAGE}");
                return ExitCode::FAILURE;
            }
            other => args.apks.push(PathBuf::from(other)),
        }
    }
    if args.apks.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    }

    let framework = match load_framework(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("reach-report: framework load failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if framework.is_empty() {
        eprintln!(
            "reach-report: WARNING — no framework DEX supplied. The closure below is over the app's own \
             DEX only and is NOT comparable to a framework method count from a trace. Pass \
             --framework <boot-classpath-dir> to get the real number."
        );
    }

    let mut failures = 0usize;
    for apk in &args.apks {
        match run_one(apk, &framework, &args) {
            Ok(code) => failures += usize::from(code != ExitCode::SUCCESS),
            Err(e) => {
                eprintln!("reach-report: {}: {e}", apk.display());
                failures += 1;
            }
        }
    }
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn load_framework(args: &Args) -> std::io::Result<Vec<DexInput>> {
    let mut jars: Vec<PathBuf> = Vec::new();
    if let Some(list) = &args.boot_classpath {
        let text = std::fs::read_to_string(list)?;
        for line in text.lines() {
            let l = line.trim();
            if !l.is_empty() {
                jars.push(PathBuf::from(l));
            }
        }
    } else if let Some(dir) = &args.framework_dir {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "jar"))
            .collect();
        // `BOOTCLASSPATH` order decides supersede precedence between jars, so
        // an explicit list is the only way to get it right. Directory order is
        // alphabetical here, which is deterministic but arbitrary; the report
        // therefore prints the unit names in the order they were loaded.
        entries.sort();
        jars = entries;
    }
    let mut out = Vec::new();
    for j in jars {
        let bytes = std::fs::read(&j)?;
        let name = j.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| j.display().to_string());
        match framework_inputs_from_jar(&bytes, &name) {
            Ok(mut units) => {
                eprintln!("reach-report: {} -> {} dex", name, units.len());
                out.append(&mut units);
            }
            Err(e) => eprintln!("reach-report: skipping {name}: {e}"),
        }
    }
    Ok(out)
}

fn run_one(apk: &Path, framework: &[DexInput], args: &Args) -> Result<ExitCode, String> {
    let bytes = std::fs::read(apk).map_err(|e| e.to_string())?;
    let (mut inputs, manifest_bytes) = app_inputs_from_apk(&bytes).map_err(|e| e.to_string())?;
    let manifest = match manifest_bytes.as_deref() {
        Some(m) => Manifest::parse(m).map_err(|e| e.to_string())?,
        None => Manifest::default(),
    };
    let name = apk.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let pkg = manifest.package.clone().unwrap_or_else(|| name.clone());
    inputs.extend(framework.iter().cloned());
    let framework_units = framework.len();

    if args.sweep {
        sweep(&pkg, inputs, &manifest, args)
    } else {
        let config = Config {
            dispatch: DispatchPolicy::Rta,
            framework: FrameworkSource::Follow,
            reflection: ReflectionPolicy::ForNameExpands,
            entry: EntryPolicy::ColdStart,
            widen_to_full_surface: args.widen,
            ..Config::default()
        };
        let (program, closure) = analyse(inputs, manifest.clone(), config)?;
        emit(&pkg, &program, &closure, args, framework_units)?;
        for t in &args.traces {
            cross_check(&program, &closure, t, &pkg, args)?;
        }
        Ok(ExitCode::SUCCESS)
    }
}

fn analyse(
    inputs: Vec<DexInput>,
    manifest: Manifest,
    config: Config,
) -> Result<(Program, andro_compiler::reach::Closure), String> {
    let mut program = Program::build(inputs).map_err(|e| e.to_string())?;
    let entry = andro_compiler::reach::entry::entry_points(
        &program,
        &manifest,
        config.entry,
        config.widen_to_full_surface,
    );
    let analyzer = Analyzer::new(&mut program, config);
    let mut closure = analyzer.run(&entry);
    closure.unresolved_classes = program.unresolved().into_iter().map(|(d, _)| d).collect();
    Ok((program, closure))
}

fn emit(
    name: &str,
    program: &Program,
    closure: &andro_compiler::reach::Closure,
    args: &Args,
    framework_units: usize,
) -> Result<(), String> {
    let report = ClosureReport::build(
        program,
        closure,
        name,
        &format!(
            "{} (framework units loaded: {framework_units}; the window is a property of the capture, \
             not of the analysis)",
            args.window
        ),
    );
    if args.json {
        print!("{}", report.to_json());
    } else {
        println!("{}", report.to_markdown());
    }
    Ok(())
}

fn sweep(pkg: &str, inputs: Vec<DexInput>, manifest: &Manifest, args: &Args) -> Result<ExitCode, String> {
    let grid = andro_compiler::reach::validate::default_grid();
    let mut rows: Vec<(String, usize, usize, usize, usize, usize, bool)> = Vec::new();
    let mut program: Option<Program> = None;
    for (label, config) in grid {
        let mut cfg = config;
        cfg.widen_to_full_surface = args.widen;
        let (p, c) = analyse(inputs.clone(), manifest.clone(), cfg)?;
        let fw = andro_compiler::reach::Closure::count_role(
            &p,
            &c.methods,
            UnitRole::Framework,
        );
        let app = andro_compiler::reach::Closure::count_role(&p, &c.methods, UnitRole::App);
        let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
        for (k, _, m, cl) in [
            (andro_compiler::reach::EdgeKind::Direct, "", c.method_edges_of(andro_compiler::reach::EdgeKind::Direct), 0),
            (andro_compiler::reach::EdgeKind::Virtual, "", c.method_edges_of(andro_compiler::reach::EdgeKind::Virtual), 0),
            (andro_compiler::reach::EdgeKind::Reflective, "", c.class_edges_of(andro_compiler::reach::EdgeKind::Reflective), 0),
            (andro_compiler::reach::EdgeKind::Superclass, "", c.class_edges_of(andro_compiler::reach::EdgeKind::Superclass), 0),
        ] {
            by_kind.insert(k.as_str(), m + cl);
        }
        rows.push((
            label,
            c.methods.len(),
            fw,
            app,
            c.unresolved_reflective(),
            c.classes.len(),
            c.is_complete(),
        ));
        program = Some(p);
    }
    println!("# closure sweep — {pkg} [measured: computed over the universe printed per row]");
    println!();
    println!("| policy | closure methods | framework-namespace | app-namespace | classes | unresolved reflective | complete |");
    println!("|---|---:|---:|---:|---:|---:|---|");
    for (label, m, fw, app, unres, classes, complete) in &rows {
        println!(
            "| {label} | {m} | {fw} | {app} | {classes} | {unres} | {} |",
            if *complete { "yes" } else { "**NO — a configured bound was hit**" }
        );
    }
    println!();
    let _ = program;
    Ok(ExitCode::SUCCESS)
}

fn cross_check(
    program: &Program,
    closure: &andro_compiler::reach::Closure,
    trace_path: &Path,
    pkg: &str,
    args: &Args,
) -> Result<(), String> {
    let bytes = std::fs::read(trace_path).map_err(|e| e.to_string())?;
    let trace = match validate::parse_trace(&trace_path.display().to_string(), &bytes) {
        Ok(t) => t,
        Err(e) => {
            println!("\n## cross-check against `{}`\n\nnot usable: {e}\n", trace_path.display());
            return Ok(());
        }
    };
    let label = format!("{pkg} [{}]", args.window);
    let v = validate::validate_against_trace(program, closure, &trace, &label);
    if args.json {
        println!(
            "\n// cross-check {}: static={} trace={} coverage={:?} intersection={} missing={} extra={}",
            trace_path.display(),
            v.static_framework_methods,
            v.trace_methods,
            v.coverage,
            v.intersection,
            v.missing.len(),
            v.extra
        );
    } else {
        println!("\n{}", v.render());
    }
    if v.coverage == Coverage::Exhaustive && !v.is_over_approximation() {
        eprintln!(
            "reach-report: {}: the static closure is NOT an over-approximation of the trace; \
             {} traced methods are missing. Reported above, not tuned away.",
            trace_path.display(),
            v.missing.len()
        );
    }
    Ok(())
}
