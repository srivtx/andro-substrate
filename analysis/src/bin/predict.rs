//! `predict` — the per-app driver.
//!
//! Reads one APK and writes one JSON analysis object to stdout, or a JSONL row
//! to `--out`. Exit status is `0` for an analysable APK and `2` for one that
//! is not, so a batch run can keep going and still report how many apps it lost
//! — the failure mode the corpus census hit repeatedly, losing a different app
//! to a different transient error on each run.
//!
//! ```text
//! predict app.apk                       # pretty JSON to stdout
//! predict --out rows.jsonl a.apk b.apk  # one compact row per APK
//! predict --summary                     # the JSON without the raw per-DEX scans
//! ```

use std::io::Write;
use std::process::ExitCode;

use substrate_predictor::analysis::AppFacts;
use substrate_predictor::score::Prediction;
use substrate_predictor::{analyze_apk, Error};

/// The emitted document. A thin wrapper so `--summary` can drop the heaviest
/// field without duplicating the struct.
#[derive(serde::Serialize)]
struct Row<'a> {
    predictor_version: &'a str,
    apk_path: String,
    facts: &'a AppFacts,
    prediction: &'a Prediction,
}

#[derive(serde::Serialize)]
struct SummaryRow<'a> {
    predictor_version: &'a str,
    apk_path: String,
    analysable: bool,
    error: Option<Error>,
    prediction: &'a Prediction,
    taxonomy_hits: &'a [substrate_predictor::TaxonomyHit],
    code: &'a substrate_predictor::analysis::CodeFacts,
    native: &'a substrate_predictor::analysis::NativeFacts,
    build: &'a substrate_predictor::analysis::BuildFacts,
    trust: &'a substrate_predictor::analysis::TrustFacts,
    paths: &'a substrate_predictor::analysis::PathFacts,
}

struct Args {
    paths: Vec<String>,
    out: Option<String>,
    summary: bool,
    pretty: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        paths: Vec::new(),
        out: None,
        summary: false,
        pretty: true,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => {
                args.out = Some(it.next().ok_or("--out needs a path")?);
            }
            "--jsonl" => args.pretty = false,
            "--summary" => args.summary = true,
            "-h" | "--help" => {
                println!("{}", HELP);
                std::process::exit(0);
            }
            other => {
                if let Some(v) = other.strip_prefix("--out=") {
                    args.out = Some(v.to_string());
                } else if other.starts_with("--jsonl=") {
                    args.pretty = false;
                } else if other.starts_with('-') {
                    return Err(format!("unknown flag {other}"));
                } else {
                    args.paths.push(other.to_string());
                }
            }
        }
    }
    Ok(args)
}

const HELP: &str = "predict <apk>...  |  --out FILE  |  --jsonl  |  --summary";

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("predict: {e}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    if args.paths.is_empty() {
        eprintln!("predict: no APK paths given\n\n{HELP}");
        return ExitCode::from(2);
    }

    let mut writer: Box<dyn Write> = match &args.out {
        Some(p) => match std::fs::File::create(p) {
            Ok(f) => Box::new(f),
            Err(e) => {
                eprintln!("predict: cannot write {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => Box::new(std::io::stdout()),
    };

    let mut unanalysable = 0usize;
    for path in &args.paths {
        let facts = match std::fs::read(path) {
            Ok(b) => analyze_apk(b),
            Err(e) => AppFacts {
                analysable: false,
                error: Some(Error::Io(e.to_string())),
                ..Default::default()
            },
        };
        if !facts.analysable {
            unanalysable += 1;
        }
        let prediction = Prediction::compute(&facts);
        let text = if args.summary {
            let row = SummaryRow {
                predictor_version: substrate_predictor::VERSION,
                apk_path: path.clone(),
                analysable: facts.analysable,
                error: facts.error.clone(),
                prediction: &prediction,
                taxonomy_hits: &facts.taxonomy_hits,
                code: &facts.code,
                native: &facts.native,
                build: &facts.build,
                trust: &facts.trust,
                paths: &facts.paths,
            };
            to_json(&row, args.pretty)
        } else {
            let row = Row {
                predictor_version: substrate_predictor::VERSION,
                apk_path: path.clone(),
                facts: &facts,
                prediction: &prediction,
            };
            to_json(&row, args.pretty)
        };
        if writeln!(writer, "{text}").is_err() {
            return ExitCode::from(2);
        }
    }
    let _ = writer.flush();

    if unanalysable == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "predict: {unanalysable} of {} APK(s) could not be analysed",
            args.paths.len()
        );
        ExitCode::from(2)
    }
}

fn to_json<T: serde::Serialize>(value: &T, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(value).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    } else {
        serde_json::to_string(value).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}
