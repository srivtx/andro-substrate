//! Redaction at the point of capture, ported from `shim/src/redact.rs` and
//! **generalised**, because a generated host sees a different and larger
//! surface than the hand-written one.
//!
//! # The port, and what it costs
//!
//! The shim's redaction problem is one problem: a network trace is where
//! credentials live, so a URL is destructured and the query *values*, the
//! fragment and the userinfo are dropped on the floor. That is ported here
//! essentially unchanged, because it was already right.
//!
//! The generated host has a strictly larger problem, and this is the reason the
//! port is not a copy. A hand-written shim calls a few hundred methods a run,
//! each hand-picked, and the author could see every argument as it went past. A
//! generated host is invoked for **every one of the 4,649 methods in a
//! closure**, with whatever arguments the app produced, including strings that
//! are bearer tokens, keystrokes, SQL, file contents and pre-signed URLs. There
//! is no hand-picking to do.
//!
//! So the invariant here is stated one level higher than the shim's:
//!
//! > **No type in this module, and no type reachable from the host's recording
//! > types, can hold a request body, a header value, a query-string value, or an
//! > argument value.**
//!
//! [`ArgFacts`] is the load-bearing type: it is what a call's arguments become,
//! and it holds counts, type descriptors and string *shapes*. The shape is enough
//! to say "this argument was 1,024 bytes of non-ASCII" and not enough to
//! reconstruct anything. There is no field for the value and no constructor that
//! takes one, so there is no refactor that leaks.
//!
//! # Why not redact downstream
//!
//! The argument from `shim/src/redact.rs` holds and is worth restating, because
//! the temptation scales with the code generated: capture everything into a
//! struct, scrub on serialisation. A downstream redactor is one debug
//! `println!`, one `serde(skip_serializing)` typo, or one new recording field
//! away from writing a real token to disk, and **nothing in the type system
//! objects**. So redaction happens in the parser: [`RequestMeta::parse`] is the
//! only way to get a network observation in, [`Args::reduce`] is the only way to
//! get an argument list in, and both drop what must be dropped before a value
//! ever becomes a field.
//!
//! # The one thing a recording still holds
//!
//! [`ArgFacts`] holds **parameter names and string shapes, never string
//! content**. `requestParamNames` is a finding — "this request carried an
//! `X-Amz-Signature`" is actionable — and a name cannot be a secret. A shape
//! (`chars`, `bytes`, `ascii`, `distinct_bytes`) says an argument was present
//! and how big it was, which is what distinguishes "the app sent a token" from
//! "the app sent nothing", and it cannot be inverted.

use core::fmt;

use crate::hostgen::path::{PathProblem, RootedPath};

/// Longest URL the parser will look at. Longer is refused, not truncated: a
/// truncated URL is a *different* URL.
pub const MAX_URL_BYTES: usize = 4096;

/// How much of a request path reaches the recording.
///
/// A path is the shim's residual risk and it is this module's too: REST designs
/// put identifiers in path segments, and `GET /users/{userId}/orders` carries a
/// user id in the clear. So the policy is a parameter, not a constant, and
/// which policy a capture used is recorded in [`PathPolicy::as_str`] — the
/// equivalent of the shim's `privacy.notes` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum PathPolicy {
    /// Keep the path verbatim, minus the query. Maximum comparability with a
    /// device capture; maximum PII exposure.
    #[default]
    Full,
    /// Keep `/a/b/c` as `/:1/:2/:3`: shape and depth, no literal segments.
    ShapeOnly,
    /// Keep only the segment count. A digest is *not* offered, because a digest
    /// of a path is a dictionary attack away from the path.
    Opaque,
}

impl PathPolicy {
    /// The token a recording declares this policy under.
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
            PathPolicy::Opaque => format!(
                "/{}-segments",
                path.split('/').filter(|s| !s.is_empty()).count()
            ),
        }
    }
}

/// Why a URL was refused. Every variant is a refusal; none is a rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlProblem {
    Empty,
    TooLong,
    IllegalByte,
    NoScheme,
    /// A scheme the substrate does not model. Refused rather than normalised,
    /// because a normalising parser is where `javascript:` gets waved through.
    UnsupportedScheme,
    NoHost,
    /// The URL carried `user:pass@`. **Refused, not redacted**: an app putting a
    /// credential in the authority is doing something worth noticing, and the
    /// right response is to notice.
    UserInfo,
    BadPort,
}

impl fmt::Display for UrlProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            UrlProblem::Empty => "empty URL",
            UrlProblem::TooLong => "URL exceeds the length ceiling",
            UrlProblem::IllegalByte => "URL carries a control byte",
            UrlProblem::NoScheme => "URL has no scheme",
            UrlProblem::UnsupportedScheme => "scheme is not one this substrate models",
            UrlProblem::NoHost => "URL has no host",
            UrlProblem::UserInfo => "URL carries userinfo",
            UrlProblem::BadPort => "URL has an out-of-range or non-numeric port",
        };
        f.write_str(s)
    }
}

/// A network scheme. Exactly the four a real device sees from an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Ws,
    Wss,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Ws => "ws",
            Scheme::Wss => "wss",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Scheme::Http | Scheme::Ws => 80,
            Scheme::Https | Scheme::Wss => 443,
        }
    }
}

/// An HTTP method, as a recording spells it.
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

    /// Parse a method name. Case-insensitive, because both spellings appear in
    /// real app code.
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

/// Header *names* on a request.
///
/// # Why this type exists
///
/// Because there is no other way to hand a header to a recorder. There is no
/// `insert(name, value)`, no `Vec<(String, String)>`, and
/// [`HeaderNames::record`] takes one argument and rejects a name containing
/// `:` — the character that would smuggle `Authorization: Bearer …` in as one
/// "name". The presence of an `Authorization` header is recordable; its
/// contents are not, and there is no parameter that would accept them.
///
/// `tests/redaction.rs` asserts the field list and the public method list, so
/// weakening this takes a deliberate edit rather than an oversight.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderNames {
    names: Vec<String>,
    /// Names that were present but are not low-sensitivity. Their *values* were
    /// dropped on the way in and never stored anywhere.
    redacted_count: usize,
}

/// Header names the *oracle* permits verbatim. This host records **no** values
/// at all, not even these: a substrate capture has no legitimate need for a
/// `User-Agent` and no business holding one. The list exists so the recording
/// can *name* the difference rather than leave a reader guessing whether the
/// omission was an oversight.
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
    pub fn new() -> HeaderNames {
        HeaderNames::default()
    }

    /// Record one header **by name**. Returns `false` if the name was rejected.
    ///
    /// Rejection: empty, over 120 bytes, containing `:`, a control character, or
    /// any byte outside the HTTP token set. A rejected header is still counted,
    /// because "the app sent something the recorder would not name" is itself a
    /// finding.
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

    /// The recorded names, in order, deduplicated.
    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(self.names.len());
        for n in &self.names {
            if !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }

    /// How many headers were present whose value was dropped.
    pub fn redacted_count(&self) -> usize {
        self.redacted_count
    }

    /// Total headers seen, acceptable name or not.
    pub fn total(&self) -> usize {
        self.names.len().saturating_add(self.redacted_count)
    }

    /// The names of the credential-bearing headers that were present.
    ///
    /// The finding is "this request carried credentials", and a *name* is what
    /// makes it actionable — `X-Api-Key` and `Authorization` call for different
    /// follow-up. Nothing here is a value, so nothing here can leak.
    pub fn sensitive_names(&self) -> Vec<String> {
        self.names
            .iter()
            .filter(|n| {
                matches!(
                    n.as_str(),
                    "authorization" | "cookie" | "proxy-authorization" | "x-api-key" | "x-auth-token"
                )
            })
            .cloned()
            .collect()
    }

    /// Whether a credential-bearing header was present.
    pub fn has_sensitive(&self) -> bool {
        !self.sensitive_names().is_empty()
    }
}

/// Everything about a request that is safe to record, and nothing that is not.
///
/// **The field list is the invariant.** A test asserts it. There is no
/// constructor that accepts a body, a header value, or a query value, and no
/// accessor that reassembles the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestMeta {
    pub scheme: Scheme,
    /// Verbatim hostname. Substrate captures use RFC 2606 reserved names
    /// (`.invalid`), because there is no real network to attribute.
    pub host: String,
    pub port: u16,
    /// Path only. Guaranteed to contain no `?`, by construction.
    pub path: String,
    /// Query parameter **names**, never values. A signed-URL credential lives in
    /// a value, so keeping names costs nothing.
    pub query_param_names: Vec<String>,
    /// Whether a query was present at all. Distinct from an empty list: "no
    /// query" and "a query whose parameters were all unnamed" are different
    /// facts, and the second is suspicious.
    pub query_present: bool,
    /// Whether a fragment was present, and therefore dropped.
    pub fragment_present: bool,
}

impl RequestMeta {
    /// Split a URL into capture-safe parts. **This function is the redaction.**
    ///
    /// `userinfo`, every query *value* and the fragment are read and then
    /// discarded, and no field of [`RequestMeta`] can hold them.
    pub fn parse(url: &str) -> Result<RequestMeta, UrlProblem> {
        if url.is_empty() {
            return Err(UrlProblem::Empty);
        }
        if url.len() > MAX_URL_BYTES {
            return Err(UrlProblem::TooLong);
        }
        if url.bytes().any(|b| b < 0x21 || b == 0x7f || b >= 0x80) {
            return Err(UrlProblem::IllegalByte);
        }

        let (scheme_str, rest) = match url.find("://") {
            Some(i) => (&url[..i], &url[i + 3..]),
            None => match url.find(':') {
                Some(i) => (&url[..i], &url[i + 1..]),
                None => return Err(UrlProblem::NoScheme),
            },
        };
        let scheme = match scheme_str.to_ascii_lowercase().as_str() {
            "http" => Scheme::Http,
            "https" => Scheme::Https,
            "ws" => Scheme::Ws,
            "wss" => Scheme::Wss,
            _ => return Err(UrlProblem::UnsupportedScheme),
        };

        // The authority ends at the first '/', '?' or '#'.
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        let tail = &rest[auth_end..];
        if authority.is_empty() {
            return Err(UrlProblem::NoHost);
        }
        if authority.contains('@') {
            return Err(UrlProblem::UserInfo);
        }

        let (host_raw, port_str) = if let Some(stripped) = authority.strip_prefix('[') {
            // Bracketed IPv6 literal.
            match stripped.find(']') {
                None => return Err(UrlProblem::NoHost),
                Some(close) => {
                    let h = &stripped[..close];
                    match stripped[close + 1..].strip_prefix(':') {
                        Some(p) => (h, Some(p)),
                        None if stripped[close + 1..].is_empty() => (h, None),
                        None => return Err(UrlProblem::NoHost),
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
            return Err(UrlProblem::NoHost);
        }
        // A bracketed IPv6 literal is stored bracketed, so a recorded host
        // round-trips as a URL: `::1` alone is ambiguous with host:port.
        let bracketed;
        let host_raw = if host_raw.contains(':') {
            bracketed = format!("[{host_raw}]");
            bracketed.as_str()
        } else {
            host_raw
        };

        let port = match port_str {
            None => scheme.default_port(),
            Some(p) => {
                if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UrlProblem::BadPort);
                }
                match p.parse::<u32>() {
                    Ok(n) if (1..=65535).contains(&n) => n as u16,
                    _ => return Err(UrlProblem::BadPort),
                }
            }
        };

        // `tail` is /path?query#fragment. Split at '#' first: everything after
        // is dropped wholesale.
        let (before_fragment, fragment_present) = match tail.find('#') {
            Some(i) => (&tail[..i], true),
            None => (tail, false),
        };
        let (path_raw, query) = match before_fragment.find('?') {
            Some(i) => (&before_fragment[..i], Some(&before_fragment[i + 1..])),
            None => (before_fragment, None),
        };

        if path_raw.is_empty() {
            return Err(UrlProblem::NoHost);
        }
        if path_raw.len() > crate::hostgen::redact::MAX_PATH_BYTES {
            return Err(UrlProblem::TooLong);
        }
        if path_raw.bytes().any(|b| b < 0x21 || b == 0x7f) {
            return Err(UrlProblem::IllegalByte);
        }
        // Belt and braces: the split above cannot produce a '?', and the
        // invariant carries credentials, so assert rather than reason.
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
                let clean = if name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.%~".contains(&b))
                {
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
            fragment_present,
        })
    }

    /// The path under a given policy. Applied *here*, at capture, so the
    /// unredacted form never leaves the parser either.
    pub fn path_under(&self, policy: PathPolicy) -> String {
        policy.apply(&self.path)
    }

    /// A one-line `scheme://host:port/path` rendering. Never includes the query
    /// and never a userinfo, because neither survived parsing.
    pub fn endpoint(&self, policy: PathPolicy) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            self.host,
            self.port,
            self.path_under(policy)
        )
    }
}

impl fmt::Display for RequestMeta {
    /// The conservative-default rendering. A `Display` that leaked the query
    /// would be the most likely way for a redaction regression to escape into a
    /// log, so `Display` *is* the safe rendering and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.endpoint(PathPolicy::Full))
    }
}

/// Ceiling on a recorded request path. Matches the oracle's `android_path`.
pub const MAX_PATH_BYTES: usize = crate::hostgen::path::MAX_PATH_BYTES;

// =========================================================== argument reduction

/// The shape of one string argument, with its content discarded.
///
/// The fields are chosen so that a shape is informative about the *kind* of
/// thing that passed and useless for reconstructing it:
///
/// * `chars` / `bytes` — how big it was, which distinguishes a token from a
///   blank;
/// * `distinct_bytes` — a crude entropy proxy. `0x7f`-ish distinct bytes in a
///   32-char string is a bearer token; 3 distinct bytes in a 30-char string is a
///   path or an enum. This is the field that lets an analyst triage without
///   ever holding the value;
/// * `class` — a coarse label (`Token`/`Path`/`Url`/`Opaque`) derived from
///   *shape only*, never from content.
///
/// What is absent is the point: no prefix, no sample, no "redacted" stand-in
/// that is actually the first four characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringShape {
    pub chars: usize,
    pub bytes: usize,
    pub distinct_bytes: u16,
    pub class: StringClass,
}

/// A coarse label for a string argument, derived from shape alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringClass {
    Empty,
    /// Looks like an absolute path: many `/`, few distinct bytes.
    Path,
    /// Starts with a scheme separator. **This is a shape fact, not a URL**: the
    /// host and query are not read.
    UrlShaped,
    /// High distinct-byte ratio at a plausible credential length.
    TokenShaped,
    /// Printable, low entropy: an enum name, a tag, a constant.
    Word,
    /// Not printable as text, or too large to classify.
    Binary,
}

impl StringShape {
    /// Reduce a string to its shape. **This is where the content dies.**
    pub fn of(s: &str) -> StringShape {
        if s.is_empty() {
            return StringShape {
                chars: 0,
                bytes: 0,
                distinct_bytes: 0,
                class: StringClass::Empty,
            };
        }
        // A fixed 256-bit bloom, not a `HashSet`: no allocation per argument,
        // and the count it produces is capped at 256 which fits the field.
        let mut seen = [false; 256];
        let mut distinct = 0u16;
        let mut printable = 0usize;
        let mut slashes = 0usize;
        let mut scheme_sep = false;
        for b in s.as_bytes() {
            if !seen[*b as usize] {
                seen[*b as usize] = true;
                distinct = distinct.saturating_add(1);
            }
            if b.is_ascii_graphic() || *b == b' ' {
                printable = printable.saturating_add(1);
            }
            if *b == b'/' {
                slashes = slashes.saturating_add(1);
            }
            if *b == b':' && scheme_sep == false && s.len() >= 5 && scheme_prefix_len(s).is_some() {
                scheme_sep = true;
            }
        }
        let bytes = s.len();
        let chars = s.chars().count();
        let printable_ratio = printable as f64 / bytes as f64;
        let slash_ratio = slashes as f64 / bytes as f64;
        let distinct_ratio = f64::from(distinct) / bytes as f64;

        let class = if scheme_sep {
            StringClass::UrlShaped
        } else if printable_ratio < 0.85 {
            StringClass::Binary
        } else if slashes >= 2 && slash_ratio > 0.12 {
            // Slash density, not byte diversity, is the reliable path signal.
            // `/data/data/pkg/f` has eight distinct bytes in sixteen — a
            // *token* threshold would call it a credential — while a credential
            // has essentially no slashes, because no base64 alphabet uses `/`.
            StringClass::Path
        } else if (8..=4096).contains(&chars) && distinct_ratio > 0.45 {
            StringClass::TokenShaped
        } else if distinct_ratio < 0.35 {
            StringClass::Word
        } else {
            StringClass::Binary
        };

        StringShape {
            chars,
            bytes,
            distinct_bytes: distinct,
            class,
        }
    }
}

/// The length of a recognised URL scheme prefix, or `None`.
///
/// Only the *scheme* is examined. The rest of the string is never parsed, so
/// this cannot become a path to the query or the authority.
fn scheme_prefix_len(s: &str) -> Option<usize> {
    const SCHEMES: [&str; 6] = ["http", "https", "ws", "wss", "file", "content"];
    for sc in SCHEMES {
        if s.len() > sc.len()
            && s.as_bytes()[..sc.len()].eq_ignore_ascii_case(sc.as_bytes())
            && s.as_bytes()[sc.len()] == b':'
        {
            return Some(sc.len());
        }
    }
    None
}

/// What a call's arguments were reduced to.
///
/// **This is the hostgen redaction invariant in one type.** It holds arity, type
/// descriptors, a shape per string and a byte count per byte-array — and there
/// is no field, no constructor parameter and no accessor that could carry a
/// value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArgFacts {
    /// Number of arguments.
    pub argc: usize,
    /// One entry per argument: the DEX type descriptor, or a coarse kind for
    /// the ones that are not describable by a descriptor alone.
    pub kinds: Vec<ArgKind>,
    /// One shape per string-shaped argument.
    pub strings: Vec<StringShape>,
    /// Total bytes across every byte-array argument. Never the bytes.
    pub byte_array_total: u64,
}

/// The coarse kind of one argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgKind {
    Int,
    Long,
    Float,
    Double,
    Boolean,
    Char,
    /// A reference. The descriptor's class name is recorded in
    /// [`ArgFacts::kinds`]'s sibling — actually the class is *not* recorded,
    /// only that a reference was passed, because a class name can be a
    /// user-defined type carrying an identity. See [`ArgFacts::ref_classes`].
    Ref,
    Array,
    /// An array whose element width is a byte.
    ByteArray,
}

impl ArgFacts {
    /// Reduce an argument list to facts. **The only way in.**
    ///
    /// `descriptors` are DEX type descriptors, which name *types*, never
    /// values. `strings` are consumed and dropped. `byte_lengths` are counts.
    pub fn reduce(
        descriptors: &[String],
        strings: &[&str],
        byte_lengths: &[u64],
    ) -> ArgFacts {
        let mut kinds = Vec::with_capacity(descriptors.len());
        let mut byte_array_total: u64 = 0;
        for d in descriptors {
            kinds.push(ArgKind::of_descriptor(d));
        }
        for &n in byte_lengths {
            byte_array_total = byte_array_total.saturating_add(n);
        }
        ArgFacts {
            argc: descriptors.len(),
            kinds,
            strings: strings.iter().map(|s| StringShape::of(s)).collect(),
            byte_array_total,
        }
    }

    /// Class names of the reference arguments, deduplicated.
    ///
    /// A class name is not a value — `Ljava/lang/String;` carries nothing about
    /// its instance — and it is the difference between "the app passed an
    /// intent" and "the app passed a string", which a recording needs.
    pub fn ref_classes(descriptors: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::with_capacity(descriptors.len());
        for d in descriptors {
            if d.starts_with('L') && d.ends_with(';') {
                let c = d.trim_matches(|c| c == 'L' || c == ';').to_string();
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
        out
    }

    /// Total characters across every string argument.
    pub fn string_chars(&self) -> usize {
        self.strings.iter().map(|s| s.chars).sum()
    }
}

impl ArgKind {
    /// Classify a DEX type descriptor.
    pub fn of_descriptor(d: &str) -> ArgKind {
        match d.as_bytes().first() {
            Some(b'Z') => ArgKind::Boolean,
            Some(b'B') => ArgKind::ByteArray,
            Some(b'C') => ArgKind::Char,
            Some(b'S') => ArgKind::Int,
            Some(b'I') => ArgKind::Int,
            Some(b'J') => ArgKind::Long,
            Some(b'F') => ArgKind::Float,
            Some(b'D') => ArgKind::Double,
            Some(b'[') => {
                if d.starts_with("[B") {
                    ArgKind::ByteArray
                } else {
                    ArgKind::Array
                }
            }
            Some(b'L') => ArgKind::Ref,
            _ => ArgKind::Int,
        }
    }
}

// ================================================================ last-line scrub

/// A place a serialised document violated the privacy policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScrubViolation {
    /// Where, in a form an operator can act on.
    pub at: String,
    /// What was found.
    pub what: String,
}

impl fmt::Display for ScrubViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.what)
    }
}

/// Keys whose presence would mean content leaked alongside a length. Serialised
/// `body_sha256` is legal — the *length* is what the schema wants — so the
/// forbidden set is content-bearing keys only.
const FORBIDDEN_KEYS: &[&str] = &[
    "\"body\"",
    "\"body_value\"",
    "\"bodyBase64\"",
    "\"body_text\"",
    "\"request_body\"",
    "\"response_body\"",
    "\"raw_url\"",
    "\"original_url\"",
    "\"header_value\"",
    "\"arg_value\"",
];

/// Check a serialised document for the shapes the privacy policy forbids.
///
/// Deliberately redundant with the type-level redaction. A redundant check of an
/// invariant that carries credentials is worth its cost, and this one costs one
/// linear scan.
///
/// `secrets` is the caller's list of strings it knows are secret — a test's
/// canary, typically. In production it is empty and only the structural rules
/// run; the structural rules are the ones a schema cannot express.
pub fn scrub(document: &str, secrets: &[&str]) -> Result<(), Vec<ScrubViolation>> {
    let mut out = Vec::new();

    for key in FORBIDDEN_KEYS {
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
    // recording.
    //
    // Byte-oriented on purpose: this scans a serialised document, and slicing a
    // `str` at a non-boundary index is exactly the panic this crate forbids. A
    // `?` is ASCII, so a byte scan can never land mid-codepoint.
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

/// Resolve an app-supplied path for a file-system-shaped host method, or refuse.
///
/// A thin, named wrapper so that the *only* way the generated host turns a
/// string into a [`RootedPath`] is one that reports its refusals. The refusal is
/// a [`PathProblem`], never a substitute value.
pub fn rooted(path: &str) -> Result<RootedPath, PathProblem> {
    RootedPath::parse(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_QUERY: &str = "s3cr3t-token-value";

    #[test]
    fn query_values_are_dropped_at_parse_time() {
        let m = RequestMeta::parse(&format!(
            "https://api.example.invalid/v1/sync?token={CANARY_QUERY}&state=open#frag"
        ))
        .or(Err(UrlProblem::Empty))
        .map_err(|_| UrlProblem::Empty)
        .or_else(|e| Err(e));
        assert!(m.is_ok(), "{m:?}");
        let m = match m {
            Ok(v) => v,
            Err(_) => return,
        };
        assert_eq!(m.path, "/v1/sync");
        assert_eq!(
            m.query_param_names,
            vec!["token".to_string(), "state".to_string()]
        );
        assert!(m.query_present);
        assert!(m.fragment_present);
        assert!(!m.to_string().contains(CANARY_QUERY));
    }

    #[test]
    fn userinfo_is_refused_not_redacted() {
        assert_eq!(
            RequestMeta::parse("https://user:pw@api.example.invalid/v1"),
            Err(UrlProblem::UserInfo)
        );
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
        assert!(!format!("{h:?}").contains("abc123"));
        // A name is a finding; it is not a value.
        assert_eq!(h.sensitive_names(), vec!["authorization".to_string()]);
    }

    #[test]
    fn path_policies_change_only_the_path() {
        let m = RequestMeta::parse("https://h.invalid/users/12345/orders");
        assert!(m.is_ok());
        if let Ok(m) = m {
            assert_eq!(m.path_under(PathPolicy::Full), "/users/12345/orders");
            assert_eq!(m.path_under(PathPolicy::ShapeOnly), "/:5/:5/:6");
            assert_eq!(m.path_under(PathPolicy::Opaque), "/3-segments");
            assert_eq!(m.host, "h.invalid");
        }
    }

    #[test]
    fn hostile_urls_error_rather_than_panic() {
        for c in [
            "",
            ":",
            "://",
            "http://",
            "http:///path",
            "http://user:pw@h/",
            "http://h:0/",
            "http://h:99999/",
            "http://h:abc/",
            "http://[::1",
            "ftp://h/x",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,x",
            "content://media/external/file/1",
            "http://h/\u{0}",
        ] {
            assert!(
                RequestMeta::parse(c).is_err(),
                "{c:?} unexpectedly parsed"
            );
        }
    }

    #[test]
    fn ipv6_and_default_ports() {
        if let Ok(m) = RequestMeta::parse("http://[::1]:8080/x") {
            assert_eq!(m.host, "[::1]");
            assert_eq!(m.port, 8080);
        }
        if let Ok(m) = RequestMeta::parse("https://a.b/") {
            assert_eq!(m.port, 443);
        }
        if let Ok(m) = RequestMeta::parse("ws://a.b/") {
            assert_eq!(m.port, 80);
        }
    }

    #[test]
    fn scrub_catches_what_the_schema_cannot() {
        assert!(scrub(r#"{"path":"/v1?token=abc"}"#, &[]).is_err());
        assert!(scrub(r#"{"body":"secret"}"#, &[]).is_err());
        assert!(scrub(r#"{"body_sha256":"x","body":"y"}"#, &[]).is_err());
        assert!(scrub(r#"{"raw_url":"https://x/?a=b"}"#, &[]).is_err());
        assert!(scrub(r#"{"path":"/v1/sync"}"#, &[]).is_ok());
        assert!(scrub(r#"{"notes":"see c4b7e2a91"}"#, &["c4b7e2a91"]).is_err());
    }

    #[test]
    fn a_string_shape_carries_no_content() {
        let secret = "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let shape = StringShape::of(secret);
        assert_eq!(shape.bytes, secret.len());
        assert!(shape.distinct_bytes > 8, "a token has high byte diversity");
        let rendered = format!("{shape:?}");
        for frag in secret.split(|c: char| !c.is_ascii_alphanumeric()) {
            if frag.len() >= 4 {
                assert!(
                    !rendered.contains(frag),
                    "the shape leaked a fragment: {frag}"
                );
            }
        }
    }

    #[test]
    fn arg_facts_reduce_without_retaining() {
        let descriptors = vec![
            "Ljava/lang/String;".to_string(),
            "[B".to_string(),
            "I".to_string(),
        ];
        let strings = ["https://u:p@h.invalid/x?token=abc", "/data/data/pkg/f"];
        let facts = ArgFacts::reduce(&descriptors, &strings, &[4096]);
        assert_eq!(facts.argc, 3);
        assert_eq!(facts.byte_array_total, 4096);
        assert_eq!(facts.kinds[0], ArgKind::Ref);
        assert_eq!(facts.kinds[1], ArgKind::ByteArray);
        assert_eq!(facts.kinds[2], ArgKind::Int);
        assert_eq!(facts.strings[0].class, StringClass::UrlShaped);
        assert_eq!(facts.strings[1].class, StringClass::Path);
        let blob = format!("{facts:?}");
        assert!(!blob.contains("token=abc"));
        assert!(!blob.contains("u:p@"));
        assert!(!blob.contains("/data/data"));
    }
}
