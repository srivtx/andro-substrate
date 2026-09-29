//! The calibration harness's command line.
//!
//! ```text
//! cargo run --bin text-calibrate -- corpus > cases.jsonl
//! cargo run --bin text-calibrate -- report device.jsonl FONT.ttf ofl11
//! ```
//!
//! `tools/run_calibration.sh` drives the whole loop including the device. This
//! binary is the two halves of it that do not need a device, so a reviewer can
//! regenerate the corpus and re-run the arithmetic without an emulator.

use std::process::ExitCode;

use substrate_text::metrics;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("corpus") => {
            print!("{}", metrics::corpus_jsonl());
            ExitCode::SUCCESS
        }
        Some("count") => {
            let c = metrics::corpus();
            let mut by_kind = [0usize; 3];
            let mut by_script: std::collections::BTreeMap<&str, usize> = Default::default();
            for case in &c {
                match case {
                    metrics::Case::Measure(_) => by_kind[0] += 1,
                    metrics::Case::Ellipsize(_) => by_kind[1] += 1,
                    metrics::Case::Layout(_) => by_kind[2] += 1,
                }
                *by_script.entry(case.script()).or_default() += 1;
            }
            println!("total   {}", c.len());
            println!("measure {}", by_kind[0]);
            println!("ellipsize {}", by_kind[1]);
            println!("layout  {}", by_kind[2]);
            for (s, n) in by_script {
                println!("  script {s:18} {n}");
            }
            ExitCode::SUCCESS
        }
        Some("report") => {
            let Some(device_path) = args.get(2) else {
                eprintln!("usage: text-calibrate report DEVICE.jsonl FONT.ttf [licence]");
                return ExitCode::FAILURE;
            };
            let Some(font_path) = args.get(3) else {
                eprintln!("usage: text-calibrate report DEVICE.jsonl FONT.ttf [licence]");
                return ExitCode::FAILURE;
            };
            let licence = match args.get(4).map(String::as_str) {
                Some("ofl11") | None => substrate_text::License::Ofl11,
                Some("apache2") => substrate_text::License::Apache2,
                Some("dejavu") => substrate_text::License::DejaVu,
                Some("unknown") => substrate_text::License::Unknown,
                Some(other) => {
                    eprintln!("unknown licence '{other}'");
                    return ExitCode::FAILURE;
                }
            };
            let jsonl = match std::fs::read_to_string(device_path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("cannot read {device_path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let recording = match metrics::parse_device(&jsonl) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("device recording is not usable: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let bytes = match std::fs::read(font_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("cannot read {font_path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let face = match metrics::parse_bundled(&bytes, licence) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("cannot parse {font_path}: {e}");
                    return ExitCode::FAILURE;
                }
            };
            eprintln!(
                "font: {} / {}  ({}, {} bytes, sha256 {})",
                face.family(),
                face.style(),
                face.provenance.licence,
                face.provenance.byte_len,
                face.provenance.sha256
            );
            let cases = metrics::corpus();
            let report = metrics::compare(&cases, &recording, &face, metrics::Model::PerGlyph);
            println!("{report}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: text-calibrate <corpus|count|report>");
            ExitCode::FAILURE
        }
    }
}
