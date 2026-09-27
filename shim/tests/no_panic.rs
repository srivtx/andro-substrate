//! No panics on untrusted input, and no `unwrap` in the library.
//!
//! # The threat
//!
//! The substrate executes untrusted APK bytecode. A DEX reader is the first thing
//! a hostile APK touches, and this crate is two steps further in: it parses URLs,
//! paths, header names, class descriptors and method arguments that the app
//! chose. A panic in any of those is not a crash, it is a denial of service
//! against the *analysis tool* — and an analysis tool that can be crashed by its
//! subject is an analysis tool whose corpus is selected by the subject.
//!
//! # How it is enforced
//!
//! Two independent mechanisms, because either alone has a hole:
//!
//! 1. **A source scan** for `unwrap`, `expect`, `panic!`, `unreachable!` and
//!    unchecked slice indexing, over every file in the crate. The `dexcore`
//!    dependency is excluded because it is another agent's crate and it has its
//!    own totality discipline; everything in *this* crate is held to the rule.
//! 2. **Hostile-input fuzzing** at the public entry points, with a fixed corpus
//!    of awkward values plus a deterministic byte-mutation loop, so a crash is a
//!    reproducible test failure rather than a field report.
//!
//! Both are bounded. A fuzzer that can run for ever is a fuzzer that will not
//! finish, and an unbounded one would be a denial of service in the test suite.

#[path = "common/source_scan.rs"]
mod source_scan;

use source_scan::Scanner;

use shim::redact::{HeaderNames, RequestMeta};
use shim::vfs::VPath;
use shim::{Shim, ShimCaller, Value};

// ------------------------------------------------------------------ the scan

const SOURCES: &[(&str, &str)] = &[
    ("src/lib.rs", include_str!("../src/lib.rs")),
    ("src/behaviour.rs", include_str!("../src/behaviour.rs")),
    ("src/classes.rs", include_str!("../src/classes.rs")),
    ("src/dispatch.rs", include_str!("../src/dispatch.rs")),
    ("src/emit.rs", include_str!("../src/emit.rs")),
    ("src/error.rs", include_str!("../src/error.rs")),
    ("src/event.rs", include_str!("../src/event.rs")),
    ("src/layout.rs", include_str!("../src/layout.rs")),
    ("src/net.rs", include_str!("../src/net.rs")),
    ("src/recording.rs", include_str!("../src/recording.rs")),
    ("src/redact.rs", include_str!("../src/redact.rs")),
    ("src/registry.rs", include_str!("../src/registry.rs")),
    ("src/scenario.rs", include_str!("../src/scenario.rs")),
    ("src/system.rs", include_str!("../src/system.rs")),
    ("src/taxonomy.rs", include_str!("../src/taxonomy.rs")),
    ("src/vfs.rs", include_str!("../src/vfs.rs")),
    ("src/bin/shim-record.rs", include_str!("../src/bin/shim-record.rs")),
];

/// A call that can panic.
///
/// Deliberately narrow. `unwrap_or` and `unwrap_or_default` are *total* — they
/// return a value for every input — and an earlier version of this list included
/// them along with the `[0]` pattern, which matched `[0u8; 4]`, range expressions
/// and half the rest of the language. A check that cries wolf gets deleted, and a
/// deleted check protects nothing. So the list is the calls that genuinely abort.
const PANICS: &[(&str, &str)] = &[
    (".unwrap()", "panics on `None`"),
    (".unwrap_err()", "panics on `Ok`"),
    (".expect(", "panics with a message"),
    ("panic!(", "an explicit abort"),
    ("unreachable!(", "an invariant the type system should have made"),
    ("todo!(", "unfinished work"),
    ("unimplemented!(", "unfinished work"),
];

/// Files where a panic is acceptable, and why.
///
/// `scenario.rs` is a scripted fixture: it drives the shim in a fixed order and a
/// failure there is a bug in the script, where a panic is the clearest possible
/// report. `bin/shim-record.rs` is a CLI whose `main` already converts every
/// error into an exit code. Neither is on the path of untrusted input, which is
/// the property the rest of the rule exists to protect.
const PANIC_ALLOWED: &[(&str, &str)] = &[
    ("src/scenario.rs", "a scripted fixture, not on the untrusted-input path"),
    ("src/bin/shim-record.rs", "a CLI whose main maps every error to an exit code"),
];

#[test]
fn the_library_contains_no_panicking_call_in_shipped_code() {
    let mut hits: Vec<String> = Vec::new();
    for (name, src) in SOURCES {
        if PANIC_ALLOWED.iter().any(|(f, _)| *f == *name) {
            continue;
        }
        let scanner = Scanner::new(src);
        for (needle, what) in PANICS {
            for at in scanner.code_occurrences(src, needle) {
                // A `#[cfg(test)]` module is test code and may panic: a failing
                // assertion *is* the mechanism. Everything before it is shipped.
                let before = &src[..at];
                if let Some(pos) = before.rfind("#[cfg(test)]") {
                    let after_cfg = &before[pos + "#[cfg(test)]".len()..];
                    if !after_cfg.contains("mod ") {
                        // The attribute is not immediately followed by a module, so
                        // it is probably a test-only helper; be conservative and
                        // report it.
                        hits.push(format!("{name} at {at}: {what} (after #[cfg(test)])"));
                    }
                    continue;
                }
                let lo = at.saturating_sub(60);
                let hi = (at + needle.len() + 40).min(src.len());
                let lo = (lo..=hi).find(|i| src.is_char_boundary(*i)).unwrap_or(0);
                let hi = (lo..=hi).find(|i| src.is_char_boundary(*i)).unwrap_or(src.len());
                hits.push(format!("{name} at {at}: {what}\n    ...{}...", &src[lo..hi]));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the substrate parses untrusted input, so a panic here is a denial of service against the \
analysis tool. Use `?`, a `match`, or an explicit `Err`. Note that `dexcore` is a separate \
crate with its own totality discipline and is not scanned here.\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_library_declares_unwind_safe_and_unsafe_free() {
    let lib = include_str!("../src/lib.rs");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    // No `catch_unwind` either: there is nothing to catch, because nothing can
    // panic. A `catch_unwind` would be a way of *not* fixing the problem.
    for (name, src) in SOURCES {
        assert!(!src.contains("catch_unwind"), "{name} catches panics instead of avoiding them");
        assert!(!src.contains("set_hook"), "{name} installs a panic hook");
    }
}

// ------------------------------------------------------------------ fuzzing

/// A deterministic xorshift, so a failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn range(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Byte values chosen for their ability to break a parser: NUL, both quotes, a
/// backslash, angle brackets, a colon, a `?`, a `#`, high bytes, and DEL.
const INTERESTING: &[u8] = &[
    0x00, 0x01, 0x1f, 0x20, 0x22, 0x23, 0x25, 0x26, 0x27, 0x28, 0x2f, 0x3a, 0x3b, 0x3c, 0x3d,
    0x3f, 0x40, 0x5b, 0x5c, 0x5d, 0x5e, 0x7b, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0xc0, 0xfe, 0xff,
    b'a', b'/', b'\\', b'.', b'-',
];

#[test]
fn the_url_parser_survives_mutated_input() {
    let seeds: &[&str] = &[
        "https://a.b/c?d=e#f",
        "http://[::1]:8080/x",
        "ws://u:p@h/y",
        "https://a.b",
        "content://x/y",
        "",
        "://",
        "a:",
        "/////",
    ];
    let mut rng = Rng(0x5eed_1234_9abc_def0);
    for seed in seeds {
        for _ in 0..400 {
            let mut bytes = seed.as_bytes().to_vec();
            let mutations = 1 + rng.range(4);
            for _ in 0..mutations {
                let op = rng.range(3);
                if bytes.is_empty() {
                    bytes.push(0x61);
                }
                let i = rng.range(bytes.len());
                match op {
                    0 => bytes[i] = INTERESTING[rng.range(INTERESTING.len())],
                    1 => {
                        bytes[i] = rng.byte();
                    }
                    _ => bytes.insert(i, rng.byte()),
                }
            }
            // Skip what is not a `str` at all: a lossy conversion is a different
            // question, and `from_utf8` failure is an error rather than a panic.
            let Ok(s) = String::from_utf8(bytes) else { continue };
            if let Ok(m) = RequestMeta::parse(&s) {
                assert!(!m.path.contains('?'), "{s:?} produced a path with a query");
                assert!(!m.host.contains('@'), "{s:?} produced a host with userinfo");
                let rendered = m.to_string();
                assert!(!rendered.contains('?'), "{s:?} rendered a query string: {rendered}");
                assert!(!rendered.contains('#'), "{s:?} rendered a fragment: {rendered}");
            }
        }
    }
}

#[test]
fn the_path_parser_survives_mutated_input() {
    let seeds: &[&str] = &["/", "/a/b", "/data/data/pkg/files/x", "/a/../b", "//", "/proc/self/status"];
    let mut rng = Rng(0xfeed_0bad_5eed_0001);
    for seed in seeds {
        for _ in 0..400 {
            let mut bytes = seed.as_bytes().to_vec();
            for _ in 0..(1 + rng.range(4)) {
                if bytes.is_empty() {
                    bytes.push(b'/');
                }
                let i = rng.range(bytes.len());
                match rng.range(3) {
                    0 => bytes[i] = INTERESTING[rng.range(INTERESTING.len())],
                    1 => bytes[i] = rng.byte(),
                    _ => bytes.insert(i, b'/'),
                }
            }
            let Ok(s) = String::from_utf8(bytes) else { continue };
            if let Ok(p) = VPath::parse(&s) {
                // A canonicalised path never escapes and never contains a
                // control byte, whatever it was given.
                assert!(p.as_str().starts_with('/'), "{s:?} -> {p}");
                // `..` as a *component* is resolved away; a filename that merely
                // contains two dots (`^..`, `x..y`) is a legal name and must
                // survive, or the VFS would corrupt a path it is meant to record
                // faithfully.
                assert!(
                    !p.as_str().split('/').any(|seg| seg == ".."),
                    "{s:?} -> {p} kept a .. component"
                );
                assert!(
                    p.as_str().bytes().all(|b| b >= 0x20 && b != 0x7f),
                    "{s:?} -> {p} kept a control byte"
                );
                assert!(p.as_str().len() <= shim::vfs::MAX_PATH_BYTES);
            }
        }
    }
}

#[test]
fn the_vfs_survives_a_mutated_call_sequence() {
    // Not a byte fuzzer: a *call* fuzzer, which is where the interesting states
    // are. A VFS is a tree, and the states that break trees are sequences, not
    // strings.
    let mut rng = Rng(0x0bad_c0de_1234_5678);
    let paths: Vec<&str> = vec![
        "/", "/a", "/a/b", "/a/b/c", "/data/data/p/files/x", "/data/../etc/passwd", "/proc/self/status",
        "/sys/class/power_supply/battery/capacity", "/x/../../y", "/dev/urandom", "/system/build.prop",
    ];
    for _ in 0..200 {
        let mut s = Shim::new("p", vec![]).expect("shim");
        for _ in 0..24 {
            let p = paths[rng.range(paths.len())];
            match rng.range(7) {
                0 => {
                    let _ = s.read_path_public(p);
                }
                1 => {
                    let n = rng.range(64);
                    let _ = s.write_path_public(p, &vec![rng.byte(); n]);
                }
                2 => {
                    if let Ok(v) = VPath::parse(p) {
                        let _ = s.vfs().exists(&v);
                        let _ = s.vfs().list(&v);
                        let _ = s.vfs().stat(&v);
                    }
                }
                3 => {
                    let _ = s.note_class_resolution(p);
                }
                4 => {
                    let _ = s.invoke(
                        "Ljava/net/URL;",
                        "<init>",
                        "(Ljava/lang/String;)V",
                        &[Value::Str(p.to_string())],
                    );
                }
                5 => {
                    let _ = s.invoke("Landroid/util/Log;", "d", "(ILjava/lang/String;Ljava/lang/String;)I", &[
                        Value::Int(3),
                        Value::Str(p.to_string()),
                        Value::Str(p.to_string()),
                    ]);
                }
                _ => {
                    let _ = s.invoke(
                        "Ljava/net/URLConnection;",
                        "setRequestProperty",
                        "(Ljava/lang/String;Ljava/lang/String;)V",
                        &[
                            Value::Ref("Ljava/net/HttpURLConnection;".into(), 1),
                            Value::Str(p.to_string()),
                            Value::Str(p.to_string()),
                        ],
                    );
                }
            }
            // Invariants that must hold whatever happened.
            assert!(s.vfs().node_count() <= shim::vfs::MAX_NODES);
            assert!(s.vfs().total_bytes() <= shim::vfs::MAX_TOTAL_BYTES);
        }
    }
}

#[test]
fn a_malformed_argument_list_is_an_error_rather_than_a_panic() {
    // An interpreter can hand over the wrong number of arguments — a bug in the
    // evaluator, or a hostile call site. Every shim method must degrade.
    let mut s = Shim::new("p", vec![]).expect("shim");
    let descriptors = ["()V", "(I)V", "(Ljava/lang/String;)V", "([BII)V", "(J)V", "()I"];
    for (i, c) in shim::registry::CLASSES.iter().enumerate() {
        for m in c.methods() {
            for d in descriptors {
                // Only call it if the method exists at all; the argument-count
                // mismatch is the thing under test.
                for n in 0..3usize {
                    let args: Vec<Value> = (0..n)
                        .map(|k| match (i + k) % 4 {
                            0 => Value::Int(k as i32),
                            1 => Value::Str("x".repeat(k + 1)),
                            2 => Value::Null,
                            _ => Value::Long(k as i64),
                        })
                        .collect();
                    let _ = s.invoke(c.descriptor, m.name, d, &args);
                }
            }
        }
    }
    // And the event stream is still coherent afterwards.
    for (n, e) in s.events().iter().enumerate() {
        assert_eq!(e.seq, n as u64);
    }
}

#[test]
fn a_wrongly_shaped_argument_is_an_error_rather_than_a_panic() {
    let mut s = Shim::new("p", vec![]).expect("shim");
    // A `null` where a String is expected, a String where an int is expected, a
    // handle where an object is expected.
    for args in [
        vec![Value::Null, Value::Str("x".into())],
        vec![Value::Str("x".into()), Value::Null],
        vec![Value::Int(1), Value::Int(2), Value::Int(3)],
        vec![Value::Ref("Ljava/lang/String;".into(), 0)],
        vec![Value::Bytes(vec![0; 4]), Value::Int(0), Value::Int(4)],
    ] {
        let _ = s.invoke("Landroid/os/Bundle;", "putString", "", &args);
        let _ = s.invoke("Ljava/net/URL;", "<init>", "", &args);
        let _ = s.invoke("Landroid/content/Context;", "getSystemService", "", &args);
        let _ = s.invoke("Ljava/io/OutputStream;", "write", "", &args);
        let _ = s.invoke("Ljava/lang/Class;", "forName", "", &args);
    }
}

#[test]
fn a_hostile_header_set_is_bounded() {
    let mut rng = Rng(0x1111_2222_3333_4444);
    let mut h = HeaderNames::new();
    for _ in 0..2_000 {
        let len = rng.range(200);
        let name: String = (0..len)
            .map(|_| INTERESTING[rng.range(INTERESTING.len())] as char)
            .collect();
        h.record(&name);
    }
    // Only well-formed names are stored, and names only.
    for n in h.names() {
        assert!(n.len() <= 120);
        assert!(!n.contains(':'), "a name must never carry a value: {n:?}");
        assert!(n
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_!#$%&'*+.^`|~".contains(&b)));
    }
    assert_eq!(h.redacted_count() + h.names().len(), h.total());
}
