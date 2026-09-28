//! Redaction at the point of capture.
//!
//! The oracle's privacy policy is unusually specific, and the reason is
//! mundane: a network trace is where credentials live. `oracle/RECORDING.md`
//! §5 forbids request/response bodies in whole or in part, forbids header values
//! outside a low-sensitivity allowlist, and forbids query strings, because
//! pre-signed URLs and OAuth callbacks put live tokens in the query.
//!
//! # Redact at capture, not downstream
//!
//! The tempting design is to capture everything into a struct and redact on
//! serialisation. It is the wrong design and this module is the argument
//! against it. A downstream redactor is one refactor, one debug `println!`, one
//! `--capture-raw` flag or one `serde(skip_serializing)` mistake away from
//! writing a real token to disk, and nothing in the type system objects. So the
//! redaction happens *in the parser*: [`RequestMeta::parse`] is the only way to
//! get a network observation into the recorder, it destructures a URL into
//! capture-safe parts, and the query values, the fragment and the userinfo are
//! **dropped on the floor inside that function**. There is no field to forget to
//! scrub because there is no field to hold them.
//!
//! The same applies to headers. [`HeaderNames`] has exactly one operation,
//! [`HeaderNames::record`], which takes a name and rejects anything containing
//! `:` — the character that would let an app smuggle `Authorization: Bearer …`
//! in as a single "name". A value cannot be passed, because there is no
//! parameter that would accept one.
//!
//! # The residual risk, stated rather than assumed away
//!
//! The oracle allows a request `path`, and so does the shim, because a path is
//! how a substrate capture and a device capture are made comparable: the whole
//! point is to know the app talked to `/v1/sync` rather than to
//! `/v1/heartbeat`. But a path is not automatically innocent — REST designs do
//! put identifiers in path segments, and
//! `GET /users/{userId}/orders` carries a user id in the clear. So path handling
//! is a *policy*, not a constant: [`PathPolicy::Full`] keeps the path for
//! maximum comparability, [`PathPolicy::ShapeOnly`] keeps only its structure,
//! and [`PathPolicy::Opaque`] keeps only a digest and a depth. Which one a
//! capture used is recorded in `privacy.notes` alongside the residual risk,
//! which is exactly what `oracle/RECORDING.md` §5 asks a recorder to do.
//!
//! Bodies are *not* digested, unlike the oracle format which permits
//! `body_sha256`. A digest over a low-entropy body — a four-character PIN field,
//! a `"ok"` acknowledgement — is reversible by brute force in under a second, so
//! "we hashed it" would be a false assurance. Length only, and the reason is
//! written into the recording's `privacy.notes` so no analyst assumes a digest
//! exists and is merely missing.

use std::fmt;

use crate::error::{ShimError, UrlProblem};

/// Longest URL the parser will look at. Longer input is refused rather than
/// truncated: a truncated URL is a *different* URL, and recording one as if it
/// were the other is exactly the kind of quiet wrongness the format forbids.
pub const MAX_URL_BYTES: usize = 4096;

/// Longest path the parser will look at; matches the oracle's `android_path`
/// ceiling of 1024.
pub const MAX_PATH_BYTES: usize = 1024;

/// How much of a request path reaches the recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathPolicy {
    /// Keep the path verbatim, minus the query string. Maximum comparability
    /// with a device capture; maximum PII exposure.
    #[default]
    Full,
    /// Keep `/a/b/c` as `/:1/:2/:3`: shape and depth, no literal segments.
    ShapeOnly,
    /// Keep nothing but the number of segments, and a keyed-free digest is not
    /// offered because a digest of a path is a dictionary attack away from the
    /// path.
    Opaque,
}

impl PathPolicy {
    /// The oracle `privacy.hostnames`-style token used in `privacy.notes`.
    pub fn as_str(self) -> &'static str {
        match self {
            PathPolicy::Full => "path=full",
            PathPolicy::ShapeOnly => "path=shape-only",
            PathPolicy::Opaque => "path=opaque",
        }
    }

    fn apply(self, path: &str) -> String {
        match self {
            PathPolicy::Full => path.to_string(),
            PathPolicy::ShapeOnly => {
                let mut out = String::new();
                for seg in path.split('/').filter(|s| !s.is_empty()) {
                    out.push('/');
                    out.push(':');
                    out.push_str(&seg.len().to_string());
                }
                if out.is_empty() {
                    out.push('/');
                }
                out
            }
            PathPolicy::Opaque => {
                let n = path.split('/').filter(|s| !s.is_empty()).count();
                format!("/{n}-segments")
            }
        }
    }
}

/// A network scheme. The shim recognises exactly the schemes a real device would
/// see from an app, and nothing else: an unrecognised scheme is refused rather
/// than normalised, because a normalising parser is where `javascript:` and
/// `file:` get waved through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Ws,
    Wss,
    /// A scheme the shim does not model, kept as `other` in the recording.
    Other,
}

impl Scheme {
    /// The oracle `network_attempt.scheme` token.
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ws => "ws",
            Scheme::Wss => "wss",
            Scheme::Other => "other",
        }
    }
}

/// An HTTP method, as the oracle spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    #[default]
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Other,
    Unknown,
}

impl HttpMethod {
    /// The oracle `network_attempt.method` token.
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Head => "HEAD",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Other => "OTHER",
            HttpMethod::Unknown => "UNKNOWN",
        }
    }

    /// Parse a method name from a shim call. Case-insensitive, because both
    /// spellings appear in real app code.
    pub fn parse(s: &str) -> HttpMethod {
        match s.to_ascii_uppercase().as_str() {
            "GET" => HttpMethod::Get,
            "HEAD" => HttpMethod::Head,
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            "OPTIONS" => HttpMethod::Options,
            "" => HttpMethod::Unknown,
            _ => HttpMethod::Other,
        }
    }
}

/// The set of header *names* on a request.
///
/// # Why this type exists
///
/// It exists because there is no other way to hand a header to the recorder.
/// There is no `insert(name, value)`, no `Vec<(String, String)>`, and
/// [`HeaderNames::record`] rejects a name containing `:` — so the presence of an
/// `Authorization` header is recordable and its contents are not, which is
/// precisely the oracle's rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderNames {
    names: Vec<String>,
    /// Names that were present but are not on the low-sensitivity allowlist.
    /// Their *values* are dropped here and never stored anywhere.
    redacted_count: usize,
}

/// Header names whose values the oracle permits verbatim. Anything not here is
/// counted in [`HeaderNames::redacted_count`] and its value discarded.
///
/// Note the asymmetry with the shim's own policy: the shim records **no**
/// values at all, not even these, because a substrate capture has no legitimate
/// need for a `User-Agent` and no business holding one. The list is kept so the
/// recorder can *name* the difference in `privacy.notes` rather than leave a
/// reader guessing whether the omission is an oversight.
pub const LOW_SENSITIVITY_ALLOWLIST: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "content-length",
    "content-type",
    "range",
    "transfer-encoding",
    "user-agent",
];

impl HeaderNames {
    /// An empty set.
    pub fn new() -> HeaderNames {
        HeaderNames::default()
    }

    /// Record one header by name.
    ///
    /// Returns `false` if the name was rejected, which happens when it is empty,
    /// longer than 120 bytes, contains `:` (a smuggled value), a control
    /// character, or any byte outside the HTTP token set. A rejected header is
    /// still counted, because "an app sent something the recorder would not
    /// name" is itself a finding.
    pub fn record(&mut self, name: &str) -> bool {
        let lowered = name.trim().to_ascii_lowercase();
        let ok = !lowered.is_empty()
            && lowered.len() <= 120
            && lowered
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_!#$%&'*+.^`|~".contains(&b));
        if ok {
            self.names.push(lowered.clone());
        }
        if !LOW_SENSITIVITY_ALLOWLIST.contains(&lowered.as_str()) {
            self.redacted_count = self.redacted_count.saturating_add(1);
        }
        ok
    }

    /// Record many names, in order.
    pub fn record_all<'a, I: IntoIterator<Item = &'a str>>(&mut self, names: I) {
        for n in names {
            self.record(n);
        }
    }

    /// The recorded names, in the order they were seen, deduplicated.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.names.len());
        for n in &self.names {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    /// How many headers were present whose value was dropped. The oracle records
    /// this as `redacted_header_count`, and the shim's value is the full header
    /// count minus the allowlisted ones, which is a larger number on purpose.
    pub fn redacted_count(&self) -> usize {
        self.redacted_count
    }

    /// Total headers seen, whether or not the name was acceptable.
    pub fn total(&self) -> usize {
        self.names.len() + self.redacted_count
    }

    /// The names of the sensitive headers that were present.
    ///
    /// The oracle's `auth_header_names` permits exactly this: a name, never a
    /// value. The finding is "this request carried credentials", and a name is
    /// what makes it actionable — `X-Api-Key` and `Authorization` call for
    /// different follow-up. Nothing here is a value, so nothing here can leak.
    pub fn sensitive_names(&self) -> Vec<String> {
        self.names
            .iter()
            .filter(|n| {
                matches!(
                    n.as_str(),
                    "authorization"
                        | "cookie"
                        | "proxy-authorization"
                        | "x-api-key"
                        | "x-auth-token"
                )
            })
            .cloned()
            .collect()
    }

    /// Whether a sensitive header was present.
    pub fn has_sensitive(&self) -> bool {
        !self.sensitive_names().is_empty()
    }
}

/// Everything about a request that is safe to record, and nothing that is not.
///
/// The field list is the invariant. A test asserts it, and there is no
/// constructor that accepts a header value, a query string or a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub scheme: Scheme,
    /// Verbatim hostname. Substrate captures use RFC 2606 reserved names
    /// (`.invalid`), because there is no real network to attribute.
    pub host: String,
    pub port: u16,
    /// Path only. Guaranteed to contain no `?`, by construction.
    pub path: String,
    /// Query parameter *names*, never values. A signed-URL credential lives in
    /// a value, so keeping names costs nothing.
    pub query_param_names: Vec<String>,
    /// Whether a query string was present at all. Distinct from an empty list,
    /// because "no query" and "a query whose parameters were all empty-named"
    /// are different facts.
    pub query_present: bool,
    /// Whether a fragment was present, and therefore dropped.
    pub fragment_present: bool,
}

impl RequestMeta {
    /// Split a URL into capture-safe parts.
    ///
    /// This function is the redaction. `userinfo`, every query *value* and the
    /// fragment are read and then discarded, and no field of [`RequestMeta`]
    /// can hold them. There is no `raw` field, no `original` field, and no
    /// `Display` that would reassemble the input.
    pub fn parse(url: &str) -> Result<RequestMeta, ShimError> {
        if url.len() > MAX_URL_BYTES {
            return Err(url_err(UrlProblem::TooLong));
        }
        if url.is_empty() {
            return Err(url_err(UrlProblem::Empty));
        }
        if url.bytes().any(|b| b < 0x21 || b == 0x7f || b >= 0x80) {
            return Err(url_err(UrlProblem::IllegalByte));
        }

        let (scheme_str, rest) = match url.find("://") {
            Some(i) => (&url[..i], &url[i + 3..]),
            None => match url.find(':') {
                Some(i) => (&url[..i], &url[i + 1..]),
                None => return Err(url_err(UrlProblem::NoScheme)),
            },
        };
        let scheme = match scheme_str.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            "ws" => Scheme::Ws,
            "wss" => Scheme::Wss,
            _ => return Err(url_err(UrlProblem::UnsupportedScheme)),
        };

        // Authority ends at the first '/', '?' or '#'.
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let tail = &rest[auth_end..];

        if authority.is_empty() {
            return Err(url_err(UrlProblem::NoHost));
        }
        if authority.contains('@') {
            // Not redacted: refused. A URL carrying `user:pass@` is an app
            // putting a credential somewhere it should not, and the right
            // response is to notice, not to quietly strip it and move on.
            return Err(url_err(UrlProblem::UserInfo));
        }

        // Bracketed IPv6 literal, else the last ':' is the port separator.
        let (host_raw, port_str) = if let Some(stripped) = authority.strip_prefix('[') {
            match stripped.find(']') {
                None => return Err(url_err(UrlProblem::NoHost)),
                Some(close) => {
                    let h = &stripped[..close];
                    let after = &stripped[close + 1..];
                    match after.strip_prefix(':') {
                        Some(p) => (h, Some(p)),
                        None if after.is_empty() => (h, None),
                        None => return Err(url_err(UrlProblem::NoHost)),
                    }
                }
            }
        } else {
            match authority.rfind(':') {
                Some(i) => (&authority[..i], Some(&authority[i + 1..])),
                None => (authority, None),
            }
        };

        if host_raw.is_empty()
            || host_raw.len() > 253
            || !host_raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_[]:".contains(&b))
        {
            return Err(url_err(UrlProblem::NoHost));
        }
        // A bracketed IPv6 literal is stored with its brackets, so a recorded
        // host round-trips as a URL: `::1` alone is ambiguous with host:port.
        let host_storage;
        let host_raw = if host_raw.contains(':') {
            host_storage = format!("[{host_raw}]");
            host_storage.as_str()
        } else {
            host_raw
        };
        let port = match port_str {
            None => match scheme {
                Scheme::Http | Scheme::Ws => 80,
                Scheme::Https | Scheme::Wss => 443,
                Scheme::Other => 0,
            },
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(url_err(UrlProblem::BadPort));
                }
                match p.parse::<u32>() {
                    Ok(n) if (1..=65535).contains(&n) => n as u16,
                    _ => return Err(url_err(UrlProblem::BadPort)),
                }
            }
        };

        // `tail` is /path?query#fragment. Split at '#' first: everything after it
        // is dropped wholesale.
        let (before_fragment, fragment) = match tail.find('#') {
            Some(i) => (&tail[..i], true),
            None => (tail, false),
        };
        let (path_raw, query) = match before_fragment.find('?') {
            Some(i) => (&before_fragment[..i], Some(&before_fragment[i + 1..])),
            None => (before_fragment, None),
        };

        if path_raw.len() > MAX_PATH_BYTES {
            return Err(url_err(UrlProblem::TooLong));
        }
        if path_raw.is_empty() {
            return Err(url_err(UrlProblem::NoHost));
        }
        if path_raw.bytes().any(|b| b < 0x21 || b == 0x7f) {
            return Err(url_err(UrlProblem::IllegalByte));
        }
        // Belt and braces: the split above cannot produce a '?' but the
        // invariant is load-bearing enough to assert rather than reason about.
        debug_assert!(!path_raw.contains('?'));

        let mut query_param_names: Vec<String> = Vec::new();
        if let Some(q) = query {
            for pair in q.split('&') {
                if pair.is_empty() {
                    continue;
                }
                // The value is what may be a credential. Only the name is read.
                let name = match pair.find('=') {
                    Some(i) => &pair[..i],
                    None => pair,
                };
                if name.is_empty() || name.len() > 80 {
                    continue;
                }
                let decoded_ok = name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.%~".contains(&b));
                let clean = if decoded_ok {
                    name.to_string()
                } else {
                    ":opaque".to_string()
                };
                if !query_param_names.contains(&clean) {
                    query_param_names.push(clean);
                }
            }
        }

        Ok(RequestMeta {
            scheme,
            host: host_raw.to_ascii_lowercase(),
            port,
            path: path_raw.to_string(),
            query_param_names,
            query_present: query.is_some(),
            fragment_present: fragment,
        })
    }

    /// The path under a given policy. The policy is applied *here*, at capture,
    /// so the unredacted form never leaves the parser either.
    pub fn path_under(&self, policy: PathPolicy) -> String {
        policy.apply(&self.path)
    }

    /// A one-line `host:port/path` rendering for logs and for the `notes` fields
    /// that the oracle allows. It never includes the query, and never a
    /// userinfo, because neither survived parsing.
    pub fn endpoint(&self, path_policy: PathPolicy) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path_under(path_policy)
        )
    }
}

impl fmt::Display for RequestMeta {
    /// The `endpoint` rendering with the conservative default policy. A
    /// `Display` that leaked the query string would be the most likely way for
    /// a redaction regression to escape into a log, so `Display` is defined as
    /// the *safe* rendering and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.endpoint(PathPolicy::Full))
    }
}

fn url_err(reason: UrlProblem) -> ShimError {
    ShimError::UnparseableUrl { reason }
}

/// A last-line check on a serialised recording, used by the recorder before it
/// hands a document out and by the tests as an assertion helper.
///
/// This is deliberately redundant with the type-level redaction. A redundant
/// check of an invariant that carries credentials is worth its cost, and this
/// one costs one linear scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubViolation {
    /// JSON Pointer-ish path to the offending value.
    pub at: String,
    /// What was found.
    pub what: String,
}

/// Serialised `body` / `body_bytes`-adjacent keys are legal — the *length* is
/// what the schema wants. These are the keys whose presence would mean content
/// had leaked alongside a length.
const FORBIDDEN_BODY_KEYS: &[&str] = &[
    "\"body\"",
    "\"body_value\"",
    "\"bodyBase64\"",
    "\"body_text\"",
    "\"request_body\"",
    "\"response_body\"",
];

/// Check a serialised recording for the shapes the privacy policy forbids.
///
/// `secrets` is a list of strings the caller knows are secret (a test's canary
/// token, for instance). In production it is empty and only the structural rules
/// run; the structural rules are the ones that matter, and they are the ones a
/// schema cannot express.
pub fn scrub(document: &str, secrets: &[&str]) -> Result<(), Vec<ScrubViolation>> {
    let mut out = Vec::new();

    for key in FORBIDDEN_BODY_KEYS {
        if let Some(i) = document.find(key) {
            out.push(ScrubViolation {
                at: format!("byte offset {i}"),
                what: format!("forbidden key {key} present"),
            });
        }
    }

    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if let Some(i) = document.find(secret) {
            out.push(ScrubViolation {
                at: format!("byte offset {i}"),
                what: "a declared secret appears verbatim in the document".to_string(),
            });
        }
    }

    // Any `path` value carrying a `?` is a query string that reached the
    // recording. The oracle validator rejects these too; checking here means the
    // shim refuses to *emit* one rather than emitting and being told off.
    //
    // Byte-oriented on purpose: this is scanning a serialised document, and
    // slicing a `str` at a non-boundary index is exactly the panic the crate
    // forbids. A `?` is ASCII, so a byte scan can never land mid-codepoint.
    let bytes = document.as_bytes();
    let mut j = 0usize;
    while j + 6 <= bytes.len() {
        if &bytes[j..j + 6] == b"\"path\"" {
            let start = j + 6;
            let mut k = start;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b':' {
                k += 1;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b'"' {
                    let vstart = k + 1;
                    let mut v = vstart;
                    while v < bytes.len() && bytes[v] != b'"' {
                        if bytes[v] == b'\\' {
                            v += 1;
                        }
                        if v < bytes.len() && bytes[v] == b'?' {
                            out.push(ScrubViolation {
                                at: format!("byte offset {vstart}"),
                                what: "a path carries a query string".to_string(),
                            });
                            break;
                        }
                        v += 1;
                    }
                    j = v.max(start);
                    continue;
                }
            }
        }
        j += 1;
    }

    if out.is_empty() {
        Ok(())
    } else {
        Err(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_VALUE: &str = "s3cr3t-token-value";
    const CANARY_QUERY: &str = "s3cr3t-query-value";

    #[test]
    fn query_values_are_dropped_at_parse_time() {
        let m = RequestMeta::parse(&format!(
            "https://api.example.invalid/v1/sync?token={CANARY_QUERY}&state=open#frag"
        ))
        .expect("well-formed URL");
        assert_eq!(m.path, "/v1/sync");
        assert_eq!(
            m.query_param_names,
            vec!["token".to_string(), "state".to_string()]
        );
        assert!(m.query_present);
        assert!(m.fragment_present);
        // And nothing that could be re-serialised back into a credential.
        assert!(!m.to_string().contains(CANARY_QUERY));
    }

    #[test]
    fn userinfo_is_refused_not_redacted() {
        let e = RequestMeta::parse("https://user:pw@api.example.invalid/v1").unwrap_err();
        assert_eq!(e.kind(), "UnparseableUrl");
    }

    #[test]
    fn header_names_reject_a_smuggled_value() {
        let mut h = HeaderNames::new();
        assert!(!h.record("Authorization: Bearer abc123"));
        assert!(!h.record(""));
        assert!(!h.record("X-Bad\nName"));
        assert!(h.record("Authorization"));
        assert!(h.record("Content-Type"));
        assert!(h.has_sensitive());
        // The value never had anywhere to go.
        assert!(!format!("{h:?}").contains("abc123"));
    }

    #[test]
    fn path_policies_change_only_the_path() {
        let m = RequestMeta::parse("https://h.invalid/users/12345/orders").unwrap();
        assert_eq!(m.path_under(PathPolicy::Full), "/users/12345/orders");
        assert_eq!(m.path_under(PathPolicy::ShapeOnly), "/:5/:5/:6");
        assert_eq!(m.path_under(PathPolicy::Opaque), "/3-segments");
        assert_eq!(m.host, "h.invalid");
    }

    #[test]
    fn hostile_urls_error_rather_than_panic() {
        let cases = [
            "",
            ":",
            "://",
            "http://",
            "http://h",
            "http://h:0/",
            "http://h:99999/",
            "http://h:abc/",
            "http://[::1/",
            "ftp://h/x",
            "http://h/\u{0}",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ];
        for c in cases {
            let r = RequestMeta::parse(c);
            assert!(r.is_err(), "{c:?} unexpectedly parsed as {r:?}");
        }
    }

    #[test]
    fn ipv6_and_default_ports() {
        let m = RequestMeta::parse("http://[::1]:8080/x").unwrap();
        assert_eq!(m.host, "[::1]");
        assert_eq!(m.port, 8080);
        let m = RequestMeta::parse("https://a.b/").unwrap();
        assert_eq!(m.port, 443);
        let m = RequestMeta::parse("ws://a.b/").unwrap();
        assert_eq!(m.port, 80);
    }

    #[test]
    fn scrub_catches_a_query_string_in_a_path() {
        let doc = r#"{"path":"/v1?token=abc"}"#;
        assert!(scrub(doc, &[]).is_err());
    }

    #[test]
    fn scrub_catches_a_leaked_body() {
        let doc = format!(r#"{{"body":"{CANARY_VALUE}"}}"#);
        assert!(scrub(&doc, &[]).is_err());
    }
}
