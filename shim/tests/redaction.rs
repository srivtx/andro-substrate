//! The redaction invariant, and the canaries that would catch its failure.
//!
//! # The invariant
//!
//! **No value that could carry a credential exists in any struct the recorder
//! holds, and the parser that would have to hold one drops it on the floor.**
//!
//! The tests below are layered, and the layers are ordered by how much they would
//! catch:
//!
//! | layer | catches |
//! |---|---|
//! | canary strings, end to end | a real value reaching a real recording |
//! | a type-level check on `RequestMeta`'s fields | someone adding a `raw` field |
//! | a type-level check on `HeaderNames`' API | someone adding a value parameter |
//! | hostile-input fuzzing | a parser that panics or leaks on a crafted URL |
//! | `redact::scrub` on the serialised document | anything that gets past the above |
//!
//! # Why canaries and not assertions on the shape
//!
//! A shape assertion says "there is no field for a body". A canary says "put
//! `sig-9f3a1c7e` in a query string and prove it is nowhere in the output". The
//! second survives a refactor that renames or reorders fields, and it fails when
//! a *value* leaks, which is the thing that actually matters.

use shim::event::Group;
use shim::redact::{self, HeaderNames, PathPolicy, RequestMeta, Scheme};
use shim::{Shim, ShimCaller, Value};

/// A token that must never appear in a recording.
const CANARY_QUERY: &str = "sig-9f3a1c7e-do-not-record";
/// A bearer token that must never appear in a recording.
const CANARY_BEARER: &str = "Bearer canary-4b7e2a91-do-not-record";
/// A value that would identify a user if it survived.
const CANARY_USER: &str = "user-9182-alice@example.invalid";

fn shim() -> Shim {
    Shim::new("org.substrate.redaction.test", vec![]).expect("shim")
}

/// Everything the shim holds after a run, rendered for a substring search.
fn everything(s: &Shim) -> String {
    format!("{:?}\n{:?}\n{:?}", s.events(), s.vfs().listing(), s.build())
}

// ------------------------------------------------------------- end to end

#[test]
fn a_signed_url_reaches_the_recording_without_its_signature() {
    let mut s = shim();
    let url = format!(
        "https://api.substrate.invalid/v1/sync?X-Amz-Signature={CANARY_QUERY}&user={CANARY_USER}#frag"
    );
    s.invoke(
        "Ljava/net/URL;",
        "<init>",
        "(Ljava/lang/String;)V",
        &[Value::Str(url)],
    )
    .expect("construct");
    let conn = s
        .invoke(
            "Ljava/net/URL;",
            "openConnection",
            "()Ljava/net/URLConnection;",
            &[Value::Ref("Ljava/net/URL;".into(), 1)],
        )
        .expect("openConnection");
    s.invoke(
        "Ljava/net/URLConnection;",
        "setRequestProperty",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            conn.clone(),
            Value::Str("Authorization".into()),
            Value::Str(CANARY_BEARER.into()),
        ],
    )
    .expect("setRequestProperty");
    assert!(
        s.invoke("Ljava/net/URLConnection;", "connect", "()V", &[conn])
            .is_err(),
        "connect records the attempt and then throws"
    );

    let blob = everything(&s);
    for canary in [CANARY_QUERY, CANARY_BEARER, CANARY_USER] {
        assert!(
            !blob.contains(canary),
            "{canary:?} survived into the shim's state"
        );
    }
    // The *names* do survive, because a signed-URL finding is only useful if the
    // reader can see that a signature was sent at all.
    assert!(
        blob.contains("X-Amz-Signature"),
        "parameter names are the finding"
    );
    assert!(blob.contains("authorization"), "so is the header name");
    assert!(!blob.contains('?'), "no path may carry a query string");
}

#[test]
fn the_committed_recording_contains_no_canary() {
    // The end-to-end check on the artefact itself, using the same canaries the
    // scenario puts into its URL and its header value.
    let committed = include_str!("../recordings/synthetic.recording.json");
    let rendered = shim::scenario::run().expect("run the scenario").document;
    let fresh = serde_json::to_string(&rendered).expect("serialise");
    for canary in [
        shim::scenario::CANARY_QUERY_VALUE,
        shim::scenario::CANARY_HEADER_VALUE,
    ] {
        assert!(
            !committed.contains(canary),
            "{canary:?} is in the committed recording"
        );
        assert!(
            !fresh.contains(canary),
            "{canary:?} is in a freshly generated recording"
        );
    }
    // And the committed file is exactly what the recorder produces, so the two
    // checks are about the same bytes.
    assert_eq!(
        committed.trim_end(),
        serde_json::to_string_pretty(&rendered)
            .expect("serialise")
            .trim_end(),
        "shim/recordings/synthetic.recording.json is stale; regenerate it with the command in \
shim/recordings/README.md"
    );
    assert!(redact::scrub(committed, &[]).is_ok());
}

// ---------------------------------------------------------------- type-level

#[test]
fn request_meta_has_no_field_that_could_hold_a_credential() {
    // A structural check, so the invariant is not only "nobody has written the
    // code yet". If a `raw_url`, `query` or `body` field ever appears, this fails
    // and the author has to decide, deliberately, to weaken the invariant.
    let src = include_str!("../src/redact.rs");
    let body = src
        .split("pub struct RequestMeta {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("the RequestMeta body");
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();
    assert_eq!(
        fields,
        vec![
            "scheme",
            "host",
            "port",
            "path",
            "query_param_names",
            "query_present",
            "fragment_present",
        ],
        "RequestMeta's field set is the redaction invariant; changing it is a deliberate act \
and this test must be updated in the same commit, with a reason"
    );
    // And there is no accessor that could reassemble the input.
    assert!(
        !src.contains("fn raw") && !src.contains("fn original"),
        "there must be no accessor that hands back the pre-redaction text"
    );
}

#[test]
fn header_names_has_no_api_that_accepts_a_value() {
    let mut h = HeaderNames::new();
    // The only mutating operation takes one argument and it must be a name.
    let src = include_str!("../src/redact.rs");
    // Brace-matched, so the check covers the whole impl block and does not depend
    // on where the first method happens to end.
    let start = src.find("impl HeaderNames {").expect("the impl block");
    let open = src[start..]
        .find('{')
        .map(|i| start + i)
        .expect("open brace");
    let mut depth = 0usize;
    let mut end = src.len();
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &src[open..end];
    let mut seen: Vec<String> = Vec::new();
    for line in body.lines() {
        let l = line.trim();
        if let Some(name) = l.strip_prefix("pub fn ") {
            let sig = name
                .split('<')
                .next()
                .unwrap_or("")
                .split('(')
                .next()
                .unwrap_or("")
                .to_string();
            seen.push(sig);
        }
    }
    assert_eq!(
        seen,
        vec![
            "new",
            "record",
            "record_all",
            "names",
            "redacted_count",
            "total",
            "sensitive_names",
            "has_sensitive",
        ],
        "an unexpected public HeaderNames method appeared; none of them may take a header value"
    );
    // And the struct holds names and a count, never a value.
    let sdef = src
        .split("pub struct HeaderNames {")
        .nth(1)
        .and_then(|s| s.split("\n}").next())
        .expect("the struct body");
    assert!(sdef.contains("names: Vec<String>"));
    assert!(sdef.contains("redacted_count: usize"));
    // A name that would smuggle a value is rejected rather than stored.
    assert!(!h.record("Authorization: Bearer abc"));
    assert!(!h.record("X\r\nY"));
    assert!(h.record("Authorization"));
    assert!(h.has_sensitive());
    assert!(h.redacted_count() >= 1);
}

#[test]
fn a_body_is_never_digested_either() {
    // The oracle format permits `body_sha256`. The shim sets it to `null`, and
    // the reason is a security argument rather than an oversight: a digest over a
    // low-entropy body — a four-digit PIN field, an `"ok"` acknowledgement — is
    // reversible by brute force, so "we hashed it" would be a false assurance.
    // Length only.
    let out = shim::scenario::run().expect("run").document;
    for attempt in out["network"]["attempts"].as_array().expect("attempts") {
        assert_eq!(attempt["body_captured"], serde_json::json!(false));
        assert_eq!(
            attempt["body_sha256"],
            serde_json::json!(null),
            "bodies must not be digested, and a null here is the recorded reason why"
        );
    }
    // And a zero-length body stays distinct from an unknown one, which the
    // oracle makes load-bearing.
    let lengths: Vec<serde_json::Value> = out["network"]["attempts"]
        .as_array()
        .expect("attempts")
        .iter()
        .map(|a| a["body_bytes"].clone())
        .collect();
    assert!(
        lengths.contains(&serde_json::json!(512)),
        "the scenario writes 512 bytes to the output sink, and the attempt must record that \
length so a reader can tell an app that sent data from one that never got as far as the \
body; got {lengths:?}"
    );
    assert!(
        lengths.contains(&serde_json::Value::Null),
        "and the WebView load has no body, which is a different fact from an empty one"
    );
    // The sensitive header NAMES are recorded, which the oracle explicitly
    // permits and which makes the finding actionable.
    let auth: Vec<serde_json::Value> = out["network"]["attempts"]
        .as_array()
        .expect("attempts")
        .iter()
        .map(|a| a["auth_header_names"].clone())
        .collect();
    assert!(
        auth.iter().any(|v| v
            .as_array()
            .map(|a| a.contains(&serde_json::json!("authorization")))
            .unwrap_or(false)),
        "an Authorization header was set, and its name is a finding: {auth:?}"
    );
    assert!(
        auth.iter().all(|v| v
            .as_array()
            .map(|a| a
                .iter()
                .all(|n| n.as_str().map(|s| s.len() < 40).unwrap_or(false)))
            .unwrap_or(true)),
        "and a name is all that is recorded"
    );
}

// ----------------------------------------------------------------- path policy

#[test]
fn the_path_policy_is_a_choice_and_is_recorded() {
    // A request path is not automatically innocent: REST designs put identifiers
    // in path segments. So the policy is a parameter, and which one was used goes
    // into `privacy.notes` where the oracle asks a recorder to state its residual
    // risk.
    let out = shim::scenario::run().expect("run").document;
    let notes = out["privacy"]["notes"].as_str().expect("notes");
    assert!(notes.contains("path=full"), "{notes}");
    assert!(notes.contains("RESIDUAL RISK"), "{notes}");
    assert!(
        notes.contains("BODIES ARE NOT DIGESTED"),
        "the reason for the null digest must travel with the recording: {notes}"
    );

    // And the other policies really do remove more.
    let m = RequestMeta::parse("https://h.invalid/users/9182/orders?sig=1").expect("parse");
    assert_eq!(m.path, "/users/9182/orders");
    assert_eq!(m.path_under(PathPolicy::Full), "/users/9182/orders");
    assert_eq!(m.path_under(PathPolicy::ShapeOnly), "/:5/:4/:6");
    assert_eq!(m.path_under(PathPolicy::Opaque), "/3-segments");
    for p in [PathPolicy::ShapeOnly, PathPolicy::Opaque] {
        assert!(!m.path_under(p).contains("9182"));
    }
}

#[test]
fn hostname_policy_leaves_nothing_to_reidentify() {
    // The scenario uses RFC 2606 reserved names, so `privacy.hostnames: plain` is
    // safe here and the `host` field is populated — which is what makes a
    // substrate capture diffable against a device capture. The alternative,
    // `hmac`, needs a key held out of band, which a fixture cannot have.
    let out = shim::scenario::run().expect("run").document;
    assert_eq!(out["privacy"]["hostnames"], serde_json::json!("plain"));
    let mut saw_host = false;
    for a in out["network"]["attempts"].as_array().expect("attempts") {
        if let Some(h) = a["host"].as_str() {
            saw_host = true;
            assert!(
                h.ends_with(".invalid"),
                "a substrate fixture has no real network to attribute, so a real hostname here \
would be a fabrication: {h}"
            );
        }
    }
    assert!(saw_host);
}

// -------------------------------------------------------------- hostile input

#[test]
fn hostile_urls_error_rather_than_panic_or_leak() {
    let cases: &[&str] = &[
        "",
        ":",
        "://",
        "http://",
        "http:///path",
        "http://user:pw@h/",
        "http://h:0/",
        "http://h:65536/",
        "http://h:99999999/",
        "http://h:-1/",
        "http://[::1/",
        "http://[::1]x/",
        "ftp://h/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "content://media/external/file/1",
        "intent://scan/#Intent;scheme=zxing;end",
        "http://h/\u{0}",
        "http://h/ a",
        "http://h/../../etc",
        "http://.",
        "http://..",
    ];
    for c in cases {
        match RequestMeta::parse(c) {
            Err(_) => {}
            Ok(m) => {
                // If it parses, it must be safe to hold: no `?` in the path, and
                // no query value recoverable.
                assert!(
                    !m.path.contains('?'),
                    "{c:?} produced a path with a query: {m:?}"
                );
                assert!(m.port > 0 || m.scheme == Scheme::Other, "{c:?} -> {m:?}");
            }
        }
    }
}

#[test]
fn a_very_long_url_is_refused_rather_than_truncated() {
    // A truncated URL is a *different* URL, and recording one as if it were the
    // other is exactly the quiet wrongness the format forbids.
    let long = format!("https://h.invalid/{}", "a".repeat(redact::MAX_URL_BYTES));
    assert!(RequestMeta::parse(&long).is_err());
    let deep_path = format!("https://h.invalid/{}", "a".repeat(redact::MAX_PATH_BYTES));
    assert!(RequestMeta::parse(&deep_path).is_err());
}

#[test]
fn scrub_catches_the_shapes_the_schema_cannot() {
    // A last-line check that the recorder applies to its own output, and that the
    // tests use as an assertion helper.
    assert!(redact::scrub(r#"{"path":"/v1?token=abc"}"#, &[]).is_err());
    assert!(redact::scrub(r#"{"body":"secret"}"#, &[]).is_err());
    assert!(redact::scrub(r#"{"body_sha256":"x","body":"y"}"#, &[]).is_err());
    assert!(redact::scrub(r#"{"path":"/v1/sync"}"#, &[]).is_ok());
    // A declared secret, wherever it appears.
    assert!(redact::scrub(r#"{"notes":"see canary-4b7e2a91"}"#, &["canary-4b7e2a91"]).is_err());
    // A path with an escaped question mark is still a query string.
    assert!(redact::scrub(r#"{"path":"/v1\?token=abc"}"#, &[]).is_err());
}

#[test]
fn a_log_message_is_recorded_by_tag_only() {
    // `Log.e(TAG, message)` is where an app's own text goes, and it routinely
    // contains a URL, a user id and a stack fragment. The tag survives; the
    // message does not.
    let mut s = shim();
    s.invoke(
        "Landroid/util/Log;",
        "e",
        "(ILjava/lang/String;Ljava/lang/String;)I",
        &[
            Value::Int(6),
            Value::Str("SyncAdapter".into()),
            Value::Str(format!("POST failed for {CANARY_USER} at {CANARY_BEARER}")),
        ],
    )
    .expect("Log.e");
    let blob = everything(&s);
    assert!(blob.contains("SyncAdapter"), "the tag is a useful constant");
    assert!(!blob.contains(CANARY_USER));
    assert!(!blob.contains(CANARY_BEARER));
    assert!(!blob.contains("SyncAdapter\" message"));
}

#[test]
fn a_bundle_value_is_held_for_the_app_but_never_recorded() {
    // An Intent's extras carry identifiers, so the shim holds them in memory (the
    // app must read them back) and records only the key.
    let mut s = shim();
    s.invoke(
        "Landroid/os/Bundle;",
        "putString",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            Value::Ref("Landroid/os/Bundle;".into(), 1),
            Value::Str("auth_token".into()),
            Value::Str(CANARY_BEARER.into()),
        ],
    )
    .expect("putString");
    // The app can read it back, which is the point of holding it.
    let back = s
        .invoke(
            "Landroid/os/Bundle;",
            "getString",
            "(Ljava/lang/String;)Ljava/lang/String;",
            &[
                Value::Ref("Landroid/os/Bundle;".into(), 1),
                Value::Str("auth_token".into()),
            ],
        )
        .expect("getString");
    assert_eq!(back, Value::Str(CANARY_BEARER.into()));
    // And it is in no event.
    let blob = everything(&s);
    assert!(blob.contains("auth_token"), "the key is the finding");
    assert!(
        !blob.contains(CANARY_BEARER),
        "the value must not be recorded"
    );
    // So no event carries it.
    for e in s.events() {
        assert!(!format!("{:?}", e.detail).contains(CANARY_BEARER));
    }
    let _ = Group::Probes;
}

#[test]
fn view_text_never_reaches_a_box_tree_by_default() {
    // An `EditText` holds whatever the user typed. The box tree records the
    // string's shape, never a character.
    let mut v = shim::View::text(
        "pw",
        "EditText",
        shim::layout::NodeKind::EditText,
        CANARY_BEARER,
    );
    v.layout_params.width = shim::layout::Dimension::MatchParent;
    let mut root = shim::View::group(
        "root",
        "LinearLayout",
        shim::layout::NodeKind::LinearLayout,
        shim::layout::Orientation::Vertical,
    );
    root.layout_params.width = shim::layout::Dimension::MatchParent;
    root.add(v);
    let tree = root.run(
        shim::layout::Size {
            width: 360,
            height: 640,
        },
        shim::layout::TextPolicy::ShapeOnly,
    );
    let json = shim::layout::tree_to_json(&tree).expect("json");
    assert!(
        !json.contains(CANARY_BEARER),
        "text leaked into the box tree: {json}"
    );
    // The shape is enough to say "this field is long" without holding it.
    let node = tree.children.first().expect("child");
    let shape = node.text.as_ref().expect("a shape");
    assert_eq!(shape.chars, CANARY_BEARER.chars().count());
    assert!(shape.text.is_none());
}
