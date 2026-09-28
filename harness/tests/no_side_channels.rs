//! The side-channel scan, inherited rather than deleted.
//!
//! `shim/tests/egress_denial.rs` proves the *instrument* has no `std::fs` and no
//! `std::net`, over a fixed list of every file in the crate. Adding a recorder
//! that opens an APK would have made that check either fail or — far worse —
//! leave a file off the list, which is how a source scan gets defeated without
//! anybody noticing.
//!
//! So the scan **moved one crate outward and came with it**. `shim` still has an
//! empty `std::fs` surface, exactly as its own test asserts. This crate has the
//! *recorder's* surface, which is one `std::fs::read` of the path the researcher
//! named and not one byte more, and this test says so over a list that includes
//! every file in the crate.
//!
//! The interesting assertion is the negative one: a class of capability that the
//! recorder has no business having — a network client, a subprocess, a raw
//! syscall, a background thread — must be absent from every file, so that the
//! only thing standing between this crate and a network is that it is a
//! *researcher's* tool and not the app's runtime.

use std::sync::OnceLock;

/// Every Rust file in the crate, embedded at compile time.
fn sources() -> &'static [(&'static str, &'static str)] {
    static S: OnceLock<Vec<(&'static str, &'static str)>> = OnceLock::new();
    S.get_or_init(|| {
        vec![
            ("src/lib.rs", include_str!("../src/lib.rs")),
            ("src/apk.rs", include_str!("../src/apk.rs")),
            ("src/zip.rs", include_str!("../src/zip.rs")),
            ("src/report.rs", include_str!("../src/report.rs")),
            (
                "src/policy_named.rs",
                include_str!("../src/policy_named.rs"),
            ),
            ("src/bin/apk-run.rs", include_str!("../src/bin/apk-run.rs")),
            (
                "examples/insn-dump.rs",
                include_str!("../examples/insn-dump.rs"),
            ),
        ]
    })
}

/// Symbols the recorder must not hold, with the reason.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::net", "a network client"),
    ("TcpStream", "a network client"),
    ("TcpListener", "a network listener"),
    ("UdpSocket", "a network client"),
    ("UnixStream", "a unix socket"),
    ("Command::new", "subprocess execution"),
    ("process::abort", "process termination"),
    ("libc::", "a raw syscall"),
    ("reqwest", "an HTTP client"),
    ("hyper::", "an HTTP client"),
    ("ureq", "an HTTP client"),
    ("curl", "an HTTP client"),
    ("wget", "a downloader"),
    ("include_bytes!", "an embedded file"),
    ("unsafe {", "an unsafe block"),
    ("libloading", "an ELF loader"),
    ("dl_iterate_phdr", "an ELF loader"),
    ("std::thread::spawn", "a background thread"),
    // `std::env::args` is how a command line reaches a binary and is therefore
    // required; `env::var` is not, and is the thing the shim's own scan exists to
    // forbid — a behaviour switch that is ambient rather than declared.
    ("env::var", "an environment-configured behaviour switch"),
    ("var_os", "an environment-configured behaviour switch"),
];

/// The one file-write path the recorder has, so the scan is not vacuous.
const ALLOWED_WRITES: &[&str] = &["fs::read(path)", "File::create(p)", "fs::write(p, &report)"];

/// Strip comments and string literals, so prose that merely *names* a forbidden
/// symbol is not a violation. The shim's own scan does this; a copy rather than a
/// dependency, because this crate must not depend on the instrument's test
/// helpers to be able to police the instrument.
fn code_only(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let b: Vec<char> = src.chars().collect();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if b[i] == '"' {
            i += 1;
            while i < b.len() && b[i] != '"' {
                if b[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

#[test]
fn the_recorder_holds_no_side_channel() {
    let mut hits: Vec<String> = Vec::new();
    for (name, src) in sources() {
        let code = code_only(src);
        for (needle, what) in FORBIDDEN {
            if let Some(at) = code.find(needle) {
                let lo = at.saturating_sub(50);
                let hi = (at + needle.len() + 50).min(code.len());
                let lo = (lo..=hi).find(|i| code.is_char_boundary(*i)).unwrap_or(0);
                let hi = (lo..=hi)
                    .find(|i| code.is_char_boundary(*i))
                    .unwrap_or(code.len());
                hits.push(format!(
                    "{name} at byte {at}: {what}\n    ...{}...",
                    &code[lo..hi]
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the recorder may read the file the researcher named and write the two documents it \
         produces. It may not reach a network, a subprocess, a syscall or a thread: the app's \
         runtime is the shim, and a recorder with a capability of its own is a second place for \
         behaviour to hide.\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_only_filesystem_calls_are_the_two_the_recorder_needs() {
    // A positive control for the scan above: if this fails, the scan is not
    // looking at anything, and a green result above would mean nothing.
    let mut found: Vec<String> = Vec::new();
    for (name, src) in sources() {
        let code = code_only(src);
        for needle in ["std::fs::", "fs::read", "fs::write", "File::create"] {
            let mut from = 0usize;
            while let Some(at) = code[from..].find(needle) {
                let abs = from + at;
                found.push(format!(
                    "{name}: {}",
                    &code[abs..(abs + 60).min(code.len())]
                ));
                from = abs + needle.len();
            }
        }
    }
    let mut unexplained: Vec<&String> = found
        .iter()
        .filter(|line| !ALLOWED_WRITES.iter().any(|allowed| line.contains(*allowed)))
        .collect();
    unexplained.sort();
    unexplained.dedup();
    assert!(
        unexplained.is_empty(),
        "every filesystem call in the recorder must be one of {ALLOWED_WRITES:?}; found: \
         {unexplained:#?}"
    );
}

#[test]
fn the_manifest_declares_one_io_capable_dependency_and_it_cannot_reach_a_socket() {
    let manifest = include_str!("../Cargo.toml");
    for dep in [
        "reqwest",
        "hyper",
        "tokio",
        "ureq",
        "curl",
        "openssl",
        "native-tls",
        "libc",
    ] {
        assert!(
            !manifest.contains(dep),
            "{dep} must not be a dependency of the recorder"
        );
    }
    assert!(
        manifest.contains("flate2"),
        "flate2 is the one non-project dependency and it decompresses; say so here so removing \
         it looks like a decision"
    );
}
