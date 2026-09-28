//! `apk-run` — run one real APK under one named substrate policy.
//!
//! ```text
//! apk-run <app.apk> [--policy NAME|axis=value;…] [--method Lcls;.m()V] [--static]
//!                 [--budget N] [--out FILE] [--report FILE] [--quiet]
//! ```
//!
//! | flag | meaning |
//! |---|---|
//! | `--policy` | `default`, `loud`, `refusing`, `loopback`, or `axis=value;…`. Default `default`. |
//! | `--method` | run one named method instead of the lifecycle. `Lcom/x/Y;.m()V`. |
//! | `--static` | the `--method` target is `static` (no receiver). |
//! | `--budget` | instruction budget per stage. Default 25 000 000. `0` means unbounded. |
//! | `--out` | write the recording here instead of stdout. |
//! | `--report` | write the run report here instead of stderr. |
//! | `--quiet` | suppress the report on stderr. |
//!
//! ## Exit codes
//!
//! | code | meaning |
//! |---|---|
//! | 0 | a recording was produced and passed the shim's own privacy scrub |
//! | 1 | the APK could not be read, or the run could not be started |
//! | 2 | the recording failed the privacy scrub — a redaction regression |
//! | 3 | the recording was produced but the app did not complete any stage |
//!
//! `3` is not a failure of the tool. It is the tool's way of saying the run
//! produced a valid, honest document about an app that stopped, and a script
//! that wants to keep going over a corpus can tell the two apart without parsing
//! the report.
//!
//! ## Why it prints to stdout by default
//!
//! The same reason `shim-record` does: it makes the redirection the caller's
//! decision and keeps the binary honest about what it touches. With `--out` the
//! harness writes exactly one file, the recording, and `--report` writes exactly
//! one more.

use std::io::Write as _;
use std::process::ExitCode;

use substrate_harness::apk::open_apk;
use substrate_harness::policy_named::parse_policy;
use substrate_harness::report::{render_report, RunSummary, StageLine};
use substrate_harness::zip::ZipError;

use shim::realdex::{self, ApkIdentity, Plan};

const USAGE: &str = "\
apk-run — run a real APK under the andro-substrate framework shim

usage: apk-run <app.apk> [options]

  --policy NAME      default | loud | refusing | loopback, or
                     'axis=value;axis=value' over
                     identity, system_fs, cross_app_packages, network, time
                     (default: default)
  --method SIG       run one method instead of the lifecycle, e.g.
                     'Lcom/example/Foo;.compute()I'
  --static           the --method target is static (no receiver)
  --budget N         instruction budget per stage; 0 = unbounded
                     (default: 25000000)
  --out FILE         write the recording here instead of stdout
  --report FILE      write the run report here instead of stderr
  --quiet            do not print the run report
  -h, --help         this text

exit: 0 recorded | 1 could not run | 2 redaction regression | 3 recorded, app stopped
";

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("apk-run: {e}");
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<ExitCode, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(ExitCode::SUCCESS);
    }
    let mut apk_path: Option<String> = None;
    let mut policy_name = "default".to_string();
    let mut method: Option<String> = None;
    let mut static_call = false;
    let mut budget: u64 = shim::realdex::Config::default()
        .instruction_budget
        .unwrap_or(0);
    let mut out: Option<String> = None;
    let mut report_path: Option<String> = None;
    let mut quiet = false;

    let mut i = 0usize;
    while i < argv.len() {
        let a = argv[i].as_str();
        let mut need = |what: &str| -> Result<String, String> {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{what} needs a value"))
        };
        match a {
            "--policy" => policy_name = need("--policy")?,
            "--method" => method = Some(need("--method")?),
            "--static" => static_call = true,
            "--budget" => {
                let v = need("--budget")?;
                budget = v
                    .parse::<u64>()
                    .map_err(|_| format!("--budget {v:?} is not a number"))?;
            }
            "--out" => out = Some(need("--out")?),
            "--report" => report_path = Some(need("--report")?),
            "--quiet" => quiet = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}; try --help"))
            }
            other => {
                if apk_path.is_some() {
                    return Err(format!("two APKs named ({other:?}); this tool runs one"));
                }
                apk_path = Some(other.to_string());
            }
        }
        i += 1;
    }
    let apk_path = apk_path.ok_or_else(|| "no APK named; try --help".to_string())?;
    let spec = parse_policy(&policy_name).map_err(|e| e.to_string())?;

    let apk = open_apk(std::path::Path::new(&apk_path)).map_err(describe_apk_error)?;
    let dex = apk.classes_dex().map_err(describe_apk_error)?;
    let native_libs = apk.native_libs();
    let extra = apk.dex_names.len().saturating_sub(1);

    let identity = ApkIdentity {
        package: if apk.manifest.package.is_empty() {
            "<unknown>".to_string()
        } else {
            apk.manifest.package.clone()
        },
        version_code: apk.manifest.version_code,
        version_name: apk.manifest.version_name.clone(),
        min_sdk: apk.manifest.min_sdk,
        target_sdk: apk.manifest.target_sdk,
        permissions: apk.manifest.permissions.clone(),
        application: apk.manifest.application.clone(),
        launcher_activity: apk.manifest.launcher_activity.clone(),
        activities: apk.manifest.activities.clone(),
        extra_dex_files: extra,
        apk_sha256: apk.sha256(),
        apk_size_bytes: apk.bytes().len() as u64,
        dex_sha256: substrate_harness::apk::sha256_hex(&dex),
    };

    let plan = match &method {
        None => Plan::Lifecycle,
        Some(sig) => {
            let (class, rest) = sig
                .split_once(';')
                .ok_or_else(|| format!("--method {sig:?} is not Lclass;.name()RET"))?;
            let (name, proto) = rest
                .split_once('(')
                .ok_or_else(|| format!("--method {sig:?} has no prototype"))?;
            Plan::OneMethod {
                class: class.to_string(),
                method: name.to_string(),
                signature: format!("({proto}"),
                static_call,
            }
        }
    };

    let config = shim::realdex::Config {
        instruction_budget: if budget == 0 { None } else { Some(budget) },
        // The framework-surface census is the deliverable of a run, so the
        // engine's log of framework calls is raised to a bound a real lifecycle
        // cannot reach rather than left at the 4096 the library default uses.
        max_shim_log: 65_536,
        ..shim::realdex::Config::default()
    };

    let run = realdex::run(&dex, &spec.policy, &identity, &plan, config)
        .map_err(|e| format!("the run could not be started: {e}"))?;

    // The last gate before anything is written, exactly as in `shim-record`. A
    // redaction regression must fail loudly here rather than produce a file full
    // of tokens.
    let rendered = serde_json::to_string_pretty(&run.document)
        .map_err(|e| format!("the recording did not serialise: {e}"))?;
    if let Err(v) = shim::redact::scrub(&rendered, &[]) {
        eprintln!("apk-run: REFUSING TO EMIT: the recording violates the privacy policy");
        for violation in v {
            eprintln!("  at {}: {}", violation.at, violation.what);
        }
        return Ok(ExitCode::from(2));
    }

    let summary = RunSummary {
        package: identity.package.clone(),
        policy: spec.name.clone(),
        terminal: run.terminal.to_string(),
        stopped_because: realdex::describe_stop(&run.stages, run.stopped_at),
        stages: run
            .stages
            .iter()
            .map(|s| StageLine {
                kind: s.kind.as_str(),
                target: format!("{}.{}{}", s.class, s.method, s.signature),
                outcome: s.error_kind.clone().unwrap_or_else(|| "ok".to_string()),
                instructions: s.instructions,
                framework_calls: s.framework_calls,
                missing: s.missing_surface.clone(),
                error: s.error.clone(),
            })
            .collect(),
        missing_surface: run.missing_surface.clone(),
        unresolved: run.unresolved.clone(),
        shadowed: run.shadowed.clone(),
        indy_refused: run.indy_refused.clone(),
        instructions: run.stats.instructions_executed,
        framework_calls: run.stats.framework_calls,
        unimplemented: run.stats.framework_calls_unimplemented,
        opcodes: run.stats.distinct_opcodes(),
        unrepresentable: run.unrepresentable,
        extra_dex_files: extra,
        native_libs,
    };
    let report = render_report(&summary);

    match &out {
        Some(p) => {
            let mut f = std::fs::File::create(p).map_err(|e| format!("cannot write {p}: {e}"))?;
            f.write_all(rendered.as_bytes())
                .and_then(|_| f.write_all(b"\n"))
                .map_err(|e| format!("cannot write {p}: {e}"))?;
        }
        None => {
            println!("{rendered}");
        }
    }
    match &report_path {
        Some(p) => std::fs::write(p, &report).map_err(|e| format!("cannot write {p}: {e}"))?,
        None if !quiet => eprint!("{report}"),
        None => {}
    }

    if run.stopped_at.is_some() {
        Ok(ExitCode::from(3))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn describe_apk_error(e: substrate_harness::ApkError) -> String {
    match &e {
        substrate_harness::ApkError::Zip(ZipError::NoCentralDirectory) => format!(
            "{e}. This is what a truncated download looks like, and it is deliberately not \
             reported as an APK with no classes: an empty archive and a broken one are \
             different facts."
        ),
        _ => e.to_string(),
    }
}
