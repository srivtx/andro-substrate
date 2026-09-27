//! `shim-record` — the offline harness that writes a substrate recording.
//!
//! # Deliberately writes to stdout, not to a file
//!
//! The regeneration command is
//!
//! ```sh
//! cargo run --quiet --manifest-path shim/Cargo.toml --bin shim-record \
//!     > shim/recordings/synthetic.recording.json
//! ```
//!
//! and it prints to stdout rather than opening a path. That is not asceticism:
//! it means this crate's `std::fs` surface is **empty**, which is one of the two
//! halves of the egress/fs invariant `tests/no_side_channels.rs` checks. There is
//! no code path in the library or in this binary that can open a file, so the
//! invariant is a property of the build rather than a promise in a document.
//!
//! The committed recording is verified to be byte-identical to what this binary
//! prints, by `tests/recording.rs`. Regeneration is therefore *checked*, not
//! asserted.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |---|---|
//! | 0 | the document was produced and passed the shim's own privacy scrub |
//! | 1 | the shim could not produce a document |
//! | 2 | the document failed the privacy scrub — a redaction regression |

use std::process::ExitCode;

fn main() -> ExitCode {
    let out = match shim::scenario::run() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("shim-record: the shim could not produce a document: {e}");
            return ExitCode::from(1);
        }
    };

    let rendered = match serde_json::to_string_pretty(&out.document) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("shim-record: the document did not serialise: {e}");
            return ExitCode::from(1);
        }
    };

    // The last gate before anything is printed. A redaction regression must fail
    // loudly here rather than produce a file full of tokens.
    if let Err(v) = shim::redact::scrub(&rendered, &[]) {
        eprintln!("shim-record: REFUSING TO EMIT: the document violates the privacy policy");
        for violation in v {
            eprintln!("  at {}: {}", violation.at, violation.what);
        }
        return ExitCode::from(2);
    }

    println!("{rendered}");
    ExitCode::SUCCESS
}
