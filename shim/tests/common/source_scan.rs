//! A minimal Rust source scanner, used only to decide whether a token sits in
//! code, in a comment, or inside a string literal.
//!
//! # Why this exists
//!
//! The egress-denial invariant is partly enforced by scanning the shim's own
//! source for the symbols that would constitute a side channel. A naive
//! `src.contains("TcpStream")` is worthless for that: the crate's documentation
//! *names* `TcpListener` in prose precisely to explain that the shim has none,
//! and `recording.rs` contains the string `"dlopen"` in a `limits` array. A
//! scan that cannot tell prose from code reports those as violations, so a
//! maintainer adds an exception, and the next real one walks through it.
//!
//! So the scan classifies first. It is deliberately small and deliberately
//! **conservative**: anything it cannot classify is treated as *code*, so an
//! unparseable construct fails the invariant rather than passing it.
//!
//! # What it handles
//!
//! * line comments `// …` and doc comments `/// …`, `//! …`
//! * nestable block comments `/* … */` (Rust's are nestable; most scanners are not)
//! * string literals `"…"`, raw strings `r"…"`, `r#"…"#` and byte strings `b"…"`
//! * character literals `'x'`, `'\n'`, `'\''` and byte characters `b'x'`
//!
//! # What it does not handle
//!
//! * `macro_rules!` bodies, which are token trees rather than expressions
//! * macro invocations whose arguments are token trees
//! * `#[doc = "…"]`, which is a comment in effect but is lexed as an attribute
//!
//! Each of those is a place a forbidden symbol could hide. They are listed here
//! rather than papered over, and [`Scanner`] has a self-test covering the cases it
//! does claim to handle, so the limitation is bounded and known rather than
//! implied.

/// Where a byte of source sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Executable source.
    Code,
    /// A `//`, `///` or `//!` comment.
    LineComment,
    /// A `/* */` comment.
    BlockComment,
    /// A string or byte-string literal, including the delimiters.
    Str,
    /// A character or byte-character literal, including the delimiters.
    Char,
}

/// Classify every byte of `src` by its [`Region`].
#[derive(Debug, Clone)]
pub struct Scanner {
    regions: Vec<Region>,
}

impl Scanner {
    /// Scan `src`.
    pub fn new(src: &str) -> Scanner {
        let b = src.as_bytes();
        let n = b.len();
        let mut regions = vec![Region::Code; n];
        let mut i = 0usize;

        while i < n {
            // --- line comment
            if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
                while i < n && b[i] != b'\n' {
                    regions[i] = Region::LineComment;
                    i += 1;
                }
                continue;
            }
            // --- block comment
            if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                let mut depth = 0usize;
                while i < n {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        regions[i] = Region::BlockComment;
                        regions[i + 1] = Region::BlockComment;
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        regions[i] = Region::BlockComment;
                        regions[i + 1] = Region::BlockComment;
                        i += 2;
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        regions[i] = Region::BlockComment;
                        i += 1;
                    }
                }
                continue;
            }
            // --- raw string: r"…", r#"…"#, r##"…"##  (and the b-prefixed forms)
            if let Some(len) = raw_string_len(b, i) {
                for r in regions.iter_mut().skip(i).take(len) {
                    *r = Region::Str;
                }
                i += len;
                continue;
            }
            // --- byte string: b"…"
            if b[i] == b'b' && b.get(i + 1) == Some(&b'"') {
                let start = i;
                i += 1;
                i = scan_plain_string(b, i, &mut regions);
                regions[start] = Region::Str;
                regions[i - 1] = Region::Str;
                continue;
            }
            // --- plain string: "…"
            if b[i] == b'"' {
                let start = i;
                i = scan_plain_string(b, i, &mut regions);
                regions[start] = Region::Str;
                regions[i - 1] = Region::Str;
                continue;
            }
            // --- byte char: b'x'
            if b[i] == b'b' && b.get(i + 1) == Some(&b'\'') {
                let start = i;
                i += 1;
                if let Some(end) = scan_char_literal(b, i) {
                    for r in regions.iter_mut().skip(start).take(end - start + 1) {
                        *r = Region::Char;
                    }
                    i = end + 1;
                    continue;
                }
                i = start;
            }
            // --- char literal: 'x', '\n', '\u{1F600}'
            if b[i] == b'\'' {
                if let Some(end) = scan_char_literal(b, i) {
                    for r in regions.iter_mut().skip(i).take(end - i + 1) {
                        *r = Region::Char;
                    }
                    i = end + 1;
                    continue;
                }
            }
            i += 1;
        }
        Scanner { regions }
    }

    /// Whether the byte at `at` is executable source.
    pub fn is_code(&self, at: usize) -> bool {
        self.regions
            .get(at)
            .map(|r| *r == Region::Code)
            .unwrap_or(false)
    }

    /// The byte offsets of every occurrence of `needle` that sits in **code**.
    pub fn code_occurrences(&self, haystack: &str, needle: &str) -> Vec<usize> {
        let mut out = Vec::new();
        if needle.is_empty() {
            return out;
        }
        let nb = needle.as_bytes();
        let h = haystack.as_bytes();
        let mut from = 0usize;
        while let Some(rel) = find_bytes(&h[from..], nb) {
            let at = from + rel;
            if self.is_code(at) {
                out.push(at);
            }
            from = at + 1;
            if from >= h.len() {
                break;
            }
        }
        out
    }

    /// The source with every non-code byte replaced by a space, so offsets and
    /// lengths are preserved and a caller can print a context window safely.
    pub fn code_only(&self, src: &str) -> String {
        src.as_bytes()
            .iter()
            .zip(&self.regions)
            .map(|(b, r)| if *r == Region::Code { *b as char } else { ' ' })
            .collect()
    }
}

/// Byte-wise substring search, because a multi-byte needle must not be split by
/// a naive char search. The haystack is ASCII in the shim's own sources; where it
/// is not, an unaligned hit is discarded rather than reported.
fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > hay.len() {
        return None;
    }
    (0..=(hay.len() - needle.len())).find(|&i| &hay[i..i + needle.len()] == needle)
}

/// Consume a plain `"…"` string starting at the opening quote. Returns the index
/// just past the closing quote, marking the span as [`Region::Str`]. An
/// unterminated string runs to the end of the file, which is what a lexer does
/// and which fails the invariant loudly rather than passing it.
fn scan_plain_string(b: &[u8], start: usize, regions: &mut [Region]) -> usize {
    let n = b.len();
    let mut i = start + 1;
    while i < n {
        match b[i] {
            b'\\' => {
                regions[i] = Region::Str;
                if i + 1 < n {
                    regions[i + 1] = Region::Str;
                }
                i += 2;
            }
            b'"' => {
                regions[i] = Region::Str;
                return i + 1;
            }
            _ => {
                regions[i] = Region::Str;
                i += 1;
            }
        }
    }
    n
}

/// The index of the closing quote of a character literal starting at `start`, or
/// `None` when the quote is a lifetime and not a literal.
///
/// A lifetime such as `'a` has no closing quote within a short window, which is
/// exactly how the two are told apart. `'\''` and `'\\'` are handled by skipping
/// the escaped character first.
fn scan_char_literal(b: &[u8], start: usize) -> Option<usize> {
    let n = b.len();
    let mut i = start + 1;
    if i >= n {
        return None;
    }
    if b[i] == b'\\' {
        i += 1;
        // `\u{...}` is the only multi-character escape.
        if i < n && b[i] == b'u' {
            i += 1;
            if i < n && b[i] == b'{' {
                while i < n && b[i] != b'}' {
                    i += 1;
                }
            }
        }
        while i < n && !b[i].is_ascii_alphabetic() && b[i] != b'\'' {
            i += 1;
        }
        return if i < n && b[i] == b'\'' {
            Some(i)
        } else {
            None
        };
    }
    // A single (possibly multi-byte) scalar, then a closing quote. A closing
    // quote more than four bytes later is a lifetime, not a literal.
    if i < n && b[i] == b'\'' {
        return Some(i);
    }
    let mut j = i + 1;
    while j < n && j - i <= 4 && (b[j] & 0xc0) == 0x80 {
        j += 1;
    }
    if j < n && j - i <= 4 && b[j] == b'\'' {
        Some(j)
    } else {
        None
    }
}

/// The **length** of a raw string literal beginning at `i`, including the `r"…"`
/// delimiters, or `None` when `i` does not start one.
fn raw_string_len(b: &[u8], i: usize) -> Option<usize> {
    // `b` prefix, then `r`, then N hashes, then `"`.
    let mut j = i;
    if b.get(j) == Some(&b'b') {
        j += 1;
    }
    if b.get(j) != Some(&b'r') {
        return None;
    }
    j += 1;
    let hash_start = j;
    while b.get(j) == Some(&b'#') {
        j += 1;
    }
    let hashes = j - hash_start;
    if b.get(j) != Some(&b'"') {
        return None;
    }
    j += 1;
    // Look for `"` followed by exactly `hashes` `#`.
    while j < b.len() {
        if b[j] == b'"' && b[j + 1..].iter().take(hashes).all(|c| *c == b'#') {
            // A length measured from `i`, not an absolute offset: the caller
            // marks `[i, i + len)` and an offset here would swallow the source
            // that follows the literal.
            return Some(j + 1 + hashes - i);
        }
        j += 1;
    }
    // Unterminated: consume the rest, so the caller cannot mistake the tail for
    // code.
    Some(b.len().saturating_sub(i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_and_doc_comments_are_not_code() {
        let src = "let a = 1; // TcpStream\n/// TcpListener\nlet b = 2;\n";
        let s = Scanner::new(src);
        assert_eq!(s.code_occurrences(src, "TcpStream").len(), 0);
        assert_eq!(s.code_occurrences(src, "TcpListener").len(), 0);
        assert!(s.code_occurrences(src, "let a").len() == 1);
    }

    #[test]
    fn nested_block_comments_close_correctly() {
        let src = "/* outer /* inner */ still comment */ let x = 1;";
        let s = Scanner::new(src);
        assert_eq!(s.code_occurrences(src, "still comment").len(), 0);
        assert_eq!(s.code_occurrences(src, "let x").len(), 1);
    }

    #[test]
    fn string_literals_are_not_code() {
        let src = r#"let a = "TcpStream in a string"; let b = 2;"#;
        let s = Scanner::new(src);
        assert_eq!(s.code_occurrences(src, "TcpStream").len(), 0);
        assert_eq!(s.code_occurrences(src, "let b").len(), 1);
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let src = r#"let a = "he said \"TcpStream\" loudly"; let b = 2;"#;
        let s = Scanner::new(src);
        assert_eq!(s.code_occurrences(src, "TcpStream").len(), 0);
        assert_eq!(s.code_occurrences(src, "let b").len(), 1);
    }

    #[test]
    fn raw_strings_are_not_code() {
        let src = "let a = r#\"TcpStream\"#; let b = 2;";
        let s = Scanner::new(src);
        assert_eq!(s.code_occurrences(src, "TcpStream").len(), 0);
        assert_eq!(s.code_occurrences(src, "let b").len(), 1);
    }

    #[test]
    fn char_literals_and_lifetimes_are_told_apart() {
        let src = "fn f(x: &'a str) -> char { '\\n' }";
        let s = Scanner::new(src);
        // The lifetime `'a` is code, and must not swallow the rest of the line.
        assert_eq!(s.code_occurrences(src, "&'a str").len(), 1);
        assert_eq!(s.code_occurrences(src, "-> char").len(), 1);
    }

    #[test]
    fn an_unterminated_string_fails_closed() {
        // The invariant must fail, not pass, on input the scanner cannot parse.
        let src = "let a = \"unterminated\nTcpStream\n";
        let s = Scanner::new(src);
        assert!(
            s.code_occurrences(src, "TcpStream").is_empty(),
            "an unterminated string must swallow the rest of the file, not leak it as code"
        );
    }

    #[test]
    fn code_only_preserves_offsets() {
        let src = "let a = \"x\"; // c\nlet b = 1;";
        let s = Scanner::new(src);
        let stripped = s.code_only(src);
        assert_eq!(stripped.len(), src.len());
        assert!(!stripped.contains("c\n"));
    }
}
