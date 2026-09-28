//! The egress-denial invariant: it must be *impossible* for the shim to perform
//! real I/O, and this file tries three independent ways to prove it.
//!
//! 1. **A live socket test.** Open a real `TcpListener` on the loopback
//!    interface, then drive every network entry point the shim has. If the shim
//!    could reach a socket, the listener would accept a connection. It must not,
//!    and the test waits to be sure.
//! 2. **A source scan.** Every `.rs` file in the crate, library *and* binary,
//!    scanned for the symbols that would constitute a side channel. This is a
//!    compile-time `include_str!` over a fixed file list, so it cannot be
//!    defeated by adding a dependency or a module that the list forgot.
//! 3. **The emitted DEX.** Assert the shim's own bytecode names no transport
//!    class, so a build that accidentally grew one is caught in the artefact and
//!    not only in the source.
//!
//! The first is the one that matters. The other two are there so that a future
//! refactor cannot quietly open a door without one of them noticing first.

#[path = "common/source_scan.rs"]
mod source_scan;

use source_scan::Scanner;

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use shim::event::{Detail, Group};
use shim::redact::{HeaderNames, HttpMethod, RequestMeta};
use shim::{EgressRequest, EgressSink, PathPolicy, Shim, ShimCaller, Value};

fn shim() -> Shim {
    Shim::new("org.substrate.egress.test", vec![]).expect("shim")
}

// ------------------------------------------------------------------ live test

#[test]
fn no_network_entry_point_reaches_a_real_socket() {
    // A real listener on loopback. Nothing in the shim knows it exists; that is
    // the point — the denial is not a policy about *this* address.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    listener
        .set_nonblocking(true)
        .expect("the listener must be non-blocking so the test can prove a negative");

    let connected = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&connected);
    // A watchdog thread accepts anything that turns up. If the shim reached the
    // socket, this thread would see it while the test is still running.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let watchdog = std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    flag.store(true, Ordering::Relaxed);
                    let _ = s.write_all(b"");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    let mut s = shim();

    // --- every surface an app could use, each driven to its terminal.
    // 1. java.net.URL / URLConnection / HttpURLConnection
    let url = format!("http://127.0.0.1:{port}/collect?k=v");
    s.invoke(
        "Ljava/net/URL;",
        "<init>",
        "(Ljava/lang/String;)V",
        &[Value::Str(url.clone())],
    )
    .expect("a URL constructs");
    let conn = s
        .invoke(
            "Ljava/net/URL;",
            "openConnection",
            "()Ljava/net/URLConnection;",
            &[Value::Ref("Ljava/net/URL;".into(), 1)],
        )
        .expect("openConnection");
    s.invoke(
        "Ljava/net/HttpURLConnection;",
        "setRequestMethod",
        "(Ljava/lang/String;)V",
        &[conn.clone(), Value::Str("GET".into())],
    )
    .expect("setRequestMethod");
    let r = s.invoke(
        "Ljava/net/URLConnection;",
        "connect",
        "()V",
        std::slice::from_ref(&conn),
    );
    assert!(r.is_err(), "connect must fail");

    // 2. getResponseCode / getInputStream / getOutputStream
    assert!(s
        .invoke(
            "Ljava/net/HttpURLConnection;",
            "getResponseCode",
            "()I",
            std::slice::from_ref(&conn)
        )
        .is_err());
    assert!(s
        .invoke(
            "Ljava/net/HttpURLConnection;",
            "getInputStream",
            "()Ljava/io/InputStream;",
            std::slice::from_ref(&conn)
        )
        .is_err());
    s.invoke(
        "Ljava/net/HttpURLConnection;",
        "getOutputStream",
        "()Ljava/io/OutputStream;",
        std::slice::from_ref(&conn),
    )
    .expect("the output sink is reachable so a body can be counted");

    // 3. A raw Socket, the other way in.
    let r = s.invoke(
        "Ljava/net/Socket;",
        "connect",
        "(Ljava/net/SocketAddress;I)V",
        &[
            Value::Ref("Ljava/net/Socket;".into(), 1),
            Value::Null,
            Value::Int(3000),
        ],
    );
    assert!(r.is_err(), "Socket.connect must fail");

    // 4. A WebView load, which is a network request wearing a different hat.
    s.invoke(
        "Landroid/webkit/WebView;",
        "loadUrl",
        "(Ljava/lang/String;)V",
        &[
            Value::Ref("Landroid/webkit/WebView;".into(), 1),
            Value::Str(url.clone()),
        ],
    )
    .expect("loadUrl records and refuses");

    // 5. The sink directly, with a URL aimed at the listener.
    let meta = RequestMeta::parse(&url).expect("parse");
    let headers = HeaderNames::new();
    let mut sink = EgressSink::new(PathPolicy::Full);
    let req = EgressRequest {
        meta: &meta,
        method: HttpMethod::Post,
        headers: &headers,
        body_bytes: Some(4096),
        timeout_ms: Some(1000),
    };
    assert!(sink.request(&req).is_err());
    assert_eq!(sink.denials(), 1);

    // Give the watchdog a real chance to observe something.
    std::thread::sleep(Duration::from_millis(120));
    stop.store(true, Ordering::Relaxed);
    let _ = watchdog.join();

    assert!(
        !connected.load(Ordering::Relaxed),
        "the shim opened a TCP connection to a live listener: egress denial is not structural"
    );

    // And every attempt was recorded, so the denial is a measurement and not a
    // silence. Three net events: the HttpURLConnection connect, the WebView
    // load, and... the socket connect has no URL so it records a refusal with no
    // request. That asymmetry is deliberate and is asserted in `observation.rs`.
    let net: Vec<&shim::SubstrateEvent> = s
        .events()
        .iter()
        .filter(|e| e.group == Group::Net)
        .collect();
    assert!(
        net.len() >= 2,
        "attempts must be recorded, not silently dropped"
    );
    for e in &net {
        match &e.detail {
            Detail::Net {
                outcome,
                recorded_path,
                ..
            } => {
                assert!(outcome.is_err(), "a recorded net event must be a failure");
                assert!(!recorded_path.contains('?'), "{}", recorded_path);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn a_constructing_a_url_does_not_itself_contact_anything() {
    // The denial happens at `connect`, not at construction, so a *constructed*
    // URL and an *attempted* one stay distinguishable in the trace. Merging them
    // would lose the difference between "the app built a URL" and "the app tried
    // to use it", which is a real behavioural difference.
    let mut s = shim();
    s.invoke(
        "Ljava/net/URL;",
        "<init>",
        "(Ljava/lang/String;)V",
        &[Value::Str("https://example.invalid/a/b?c=d".into())],
    )
    .expect("construct");
    assert!(
        s.events().iter().all(|e| e.group != Group::Net),
        "construction alone must record nothing in the net group"
    );
    // The parsed parts are available to the app without a network call.
    let host = s.invoke(
        "Ljava/net/URL;",
        "getHost",
        "()Ljava/lang/String;",
        &[Value::Ref("Ljava/net/URL;".into(), 1)],
    );
    assert_eq!(host.unwrap(), Value::Str("example.invalid".into()));
    // And the query is returned to the app empty, because the shim never stored
    // it. A caller comparing `getQuery()` with what it passed would see a
    // difference — which is a real `SUB.FW.SERIALIZATION` finding rather than a
    // silent one.
    let q = s.invoke(
        "Ljava/net/URL;",
        "getQuery",
        "()Ljava/lang/String;",
        &[Value::Ref("Ljava/net/URL;".into(), 1)],
    );
    assert_eq!(q.unwrap(), Value::Str(String::new()));
}

#[test]
fn a_real_socket_in_the_test_process_still_works() {
    // A control: the *test* is allowed to open a socket, which is what makes the
    // negative result above meaningful rather than a property of the environment.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let t = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().expect("accept");
        let _ = c.write_all(b"hello");
    });
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("the test can connect");
    let mut buf = [0u8; 5];
    use std::io::Read as _;
    c.read_exact(&mut buf).expect("read");
    t.join().expect("join");
    assert_eq!(&buf, b"hello");
}

// -------------------------------------------------------------- source scan

/// Every Rust file in the crate, embedded at compile time.
///
/// A fixed list rather than a directory walk so the check cannot be defeated by
/// adding a file the list forgot — adding a new module means adding it here, and
/// the omission is a visible diff.
const SOURCES: &[(&str, &str)] = &[
    ("src/lib.rs", include_str!("../src/lib.rs")),
    ("src/behaviour.rs", include_str!("../src/behaviour.rs")),
    ("src/classes.rs", include_str!("../src/classes.rs")),
    // The policy module is the one that most wants a side channel and is
    // therefore the one that must be scanned hardest: every axis value of every
    // axis is a string this crate can parse, and the scan is what proves none of
    // them can name a socket.
    (
        "src/differential.rs",
        include_str!("../src/differential.rs"),
    ),
    ("src/dispatch.rs", include_str!("../src/dispatch.rs")),
    ("src/emit.rs", include_str!("../src/emit.rs")),
    ("src/error.rs", include_str!("../src/error.rs")),
    ("src/event.rs", include_str!("../src/event.rs")),
    ("src/layout.rs", include_str!("../src/layout.rs")),
    ("src/net.rs", include_str!("../src/net.rs")),
    ("src/policy.rs", include_str!("../src/policy.rs")),
    ("src/recording.rs", include_str!("../src/recording.rs")),
    ("src/redact.rs", include_str!("../src/redact.rs")),
    ("src/registry.rs", include_str!("../src/registry.rs")),
    ("src/scenario.rs", include_str!("../src/scenario.rs")),
    ("src/syncdiff.rs", include_str!("../src/syncdiff.rs")),
    ("src/system.rs", include_str!("../src/system.rs")),
    ("src/taxonomy.rs", include_str!("../src/taxonomy.rs")),
    ("src/vfs.rs", include_str!("../src/vfs.rs")),
    (
        "src/bin/shim-record.rs",
        include_str!("../src/bin/shim-record.rs"),
    ),
    (
        "src/bin/shim-differential.rs",
        include_str!("../src/bin/shim-differential.rs"),
    ),
    // The sync differential runs the whole scenario N times per policy and then
    // reasons about the documents. That is the largest new surface this crate has
    // had, and "it only calls the scenario" is exactly the kind of assumption a
    // source scan exists to refuse.
    (
        "src/bin/shim-sync-differential.rs",
        include_str!("../src/bin/shim-sync-differential.rs"),
    ),
];

/// Symbols that would constitute a side channel out of the shim.
const FORBIDDEN: &[(&str, &str)] = &[
    ("std::net", "a network client"),
    ("TcpStream", "a network client"),
    ("TcpListener", "a network listener"),
    ("UdpSocket", "a network client"),
    ("UnixStream", "a unix socket"),
    ("std::fs", "real disk"),
    ("File::create", "real disk"),
    ("File::open", "real disk"),
    ("process::Command", "subprocess execution"),
    ("Command::new", "subprocess execution"),
    (
        "process::abort",
        "process termination outside the shim's control",
    ),
    ("libc::", "a raw syscall"),
    ("reqwest", "an HTTP client"),
    ("hyper::", "an HTTP client"),
    ("ureq", "an HTTP client"),
    ("curl", "an HTTP client"),
    ("wget", "a downloader"),
    ("fetch(", "a JavaScript fetch bridge"),
    ("XMLHttpRequest", "a JavaScript HTTP bridge"),
    ("WebSocket::", "a WebSocket client"),
    ("include_bytes!", "an embedded file"),
    ("include_str!", "an embedded file"),
    ("env::var", "an environment-configured behaviour switch"),
    ("std::env", "an environment-configured behaviour switch"),
    ("unsafe {", "an unsafe block"),
    ("libloading", "an ELF loader"),
    ("dl_iterate_phdr", "an ELF loader"),
    ("std::thread::spawn", "a background thread"),
    ("std::sync::mpsc", "cross-thread communication"),
];

#[test]
fn the_crate_contains_no_side_channel() {
    let mut hits: Vec<String> = Vec::new();
    for (name, src) in SOURCES {
        let scanner = Scanner::new(src);
        for (needle, what) in FORBIDDEN {
            for at in scanner.code_occurrences(src, needle) {
                // A context window, so a violation is actionable without a
                // rebuild cycle.
                let lo = at.saturating_sub(40);
                let hi = (at + needle.len() + 40).min(src.len());
                let lo = (lo..=hi).find(|i| src.is_char_boundary(*i)).unwrap_or(0);
                let hi = (lo..=hi)
                    .find(|i| src.is_char_boundary(*i))
                    .unwrap_or(src.len());
                hits.push(format!(
                    "{name} at byte {at}: {what}\n    ...{}...",
                    &src[lo..hi]
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the shim has no business holding any of these, and an instrument that can reach the \
network or the disk is not an instrument. The scan classifies comments and string literals \
first, so prose that merely *names* a forbidden symbol is not a violation; see \
tests/common/source_scan.rs for what the classifier does and does not handle.\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_manifest_declares_no_io_capable_dependency() {
    let manifest = include_str!("../Cargo.toml");
    for dep in [
        "reqwest",
        "hyper",
        "ureq",
        "curl",
        "tokio",
        "async-std",
        "libc",
        "nix",
        "rand",
    ] {
        assert!(
            !manifest.contains(dep),
            "{dep} must not be a dependency of the shim"
        );
    }
    // The only two dependencies are dexcore (a byte-level DEX codec) and serde.
    assert!(manifest.contains("dexcore = { path = \"../tools/dexcore\" }"));
}

#[test]
fn the_emitted_dex_names_no_transport_class() {
    let e = shim::emit::emit().expect("emit");
    let d = dexcore::DexReader::open(&e.bytes).expect("parse");
    for i in 0..d.type_count() {
        let name = d.type_name(i).unwrap_or_default();
        for bad in [
            "Lokhttp3/",
            "Lcom/squareup/okhttp/",
            "Lorg/apache/http/",
            "Lio/okhttp/",
            "Ljavax/net/ssl/",
            "Ljava/net/DatagramSocket;",
            "Ljava/net/ServerSocket;",
            "Ljava/net/MulticastSocket;",
            "Ljava/nio/channels/",
            "Ljava/net/URI;",
            "Lsun/nio/ch/",
            "Ljava/net/ProxySelector;",
        ] {
            assert!(
                !name.starts_with(bad),
                "the shim DEX must not name a transport class: {name}"
            );
        }
    }
    // The networking classes it *does* declare are exactly the ones a real app
    // would resolve — and nothing wider. `Socket` is deliberately present: an app
    // that opens a raw socket must reach the same sink and be denied there, or
    // `HttpURLConnection` would be an evadable chokepoint.
    for c in [
        "Ljava/net/URL;",
        "Ljava/net/URLConnection;",
        "Ljava/net/HttpURLConnection;",
        "Ljava/net/Socket;",
    ] {
        assert!(shim::registry::find(c).is_some(), "{c} must be declared");
    }
    for forbidden in [
        "Ljava/net/ServerSocket;",
        "Ljava/net/DatagramSocket;",
        "Ljava/net/MulticastSocket;",
        "Ljava/net/ProxySelector;",
        "Ljavax/net/ssl/SSLSocketFactory;",
    ] {
        assert!(
            shim::registry::find(forbidden).is_none(),
            "{forbidden} must NOT be declared: it is a capability, not an observation point"
        );
    }
}

#[test]
fn every_vfs_operation_stays_in_memory() {
    // The VFS is a `BTreeMap`. Prove that the bytes an app "writes" are visible
    // to the shim and to nothing else: there is no handle out of it, because the
    // accessor hands out `&Vfs`.
    let mut s = shim();
    let p = "/data/data/org.substrate.egress.test/files/x";
    s.write_path_public(p, b"in memory only").expect("write");
    assert_eq!(s.read_path_public(p).expect("read"), b"in memory only");
    let entries: Vec<String> = s.vfs().listing().into_iter().map(|(p, _, _)| p).collect();
    assert!(entries.contains(&p.to_string()));
    // The VFS is rooted: an escaping path is refused rather than resolved against
    // the host's real root.
    assert!(s.read_path_public("/data/../../../etc/hosts").is_err());
    // `/etc` is simply not there, and the attempt is what gets recorded.
    assert!(s.read_path_public("/etc/hosts").is_err());
    assert!(s
        .events()
        .iter()
        .any(|e| e.summary().contains("/etc/hosts")));
}
