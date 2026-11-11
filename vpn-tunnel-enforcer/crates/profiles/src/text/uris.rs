//! Share-link candidates: whole lines that start with a known scheme, and links embedded in
//! free text (chat messages, HTML, JSON strings that no importer took).
use std::sync::LazyLock;

use regex::Regex;

/// Schemes taken as share links, lower case. `ssr` and `hysteria` (v1) are not supported, but
/// recognising them lets the importer report them instead of dropping them silently.
pub const URI_SCHEMES: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "socks",
    "hysteria2",
    "hy2",
    "hysteria",
    "tuic",
    "naive",
    "naive+https",
    "naive+quic",
    "anytls",
    "shadowtls",
    "wireguard",
    "wg",
];

/// True when `line`, leading whitespace aside, starts with `<scheme>://` for a scheme in
/// [`URI_SCHEMES`] (any case).
pub fn is_uri_line(line: &str) -> bool {
    let head = line.trim_start().as_bytes();
    let head = &head[..head.len().min(16)];
    head.windows(3)
        .position(|w| w == b"://")
        .is_some_and(|end| {
            URI_SCHEMES
                .iter()
                .any(|s| s.as_bytes().eq_ignore_ascii_case(&head[..end]))
        })
}

static EMBEDDED: LazyLock<Regex> = LazyLock::new(|| {
    let schemes: Vec<String> = URI_SCHEMES.iter().map(|s| regex::escape(s)).collect();
    let pattern = format!(r#"(?i)\b(?:{})://[^\s"'<>`\\]+"#, schemes.join("|"));
    // The pattern is built from the constant list above; the tests compile it.
    Regex::new(&pattern).expect("share-link pattern compiles")
});

/// Share links in `text`, in document order: a line that starts with a known scheme is taken
/// whole and trimmed (raw spaces in a name are legal), other lines are searched for embedded
/// links, which lose trailing sentence punctuation and unmatched closing brackets. Not
/// deduplicated: the importer reports repeats as duplicates.
pub fn uri_candidates(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    for line in text.split(['\n', '\r']).map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if is_uri_line(line) {
            out.push(line);
        } else {
            out.extend(EMBEDDED.find_iter(line).map(|m| trim_tail(m.as_str())));
        }
    }
    out
}

/// `…#Germany%20(1).` -> `…#Germany%20(1)`: sentence punctuation and closers without an opener
/// go, balanced pairs stay. Linear, whatever the input.
fn trim_tail(link: &str) -> &str {
    let balance = |open: u8, close: u8| {
        link.bytes().fold(0isize, |n, b| {
            n + isize::from(b == open) - isize::from(b == close)
        })
    };
    let (mut paren, mut bracket, mut brace) = (
        balance(b'(', b')'),
        balance(b'[', b']'),
        balance(b'{', b'}'),
    );
    let mut end = link.len();
    while let Some(&b) = link.as_bytes()[..end].last() {
        match b {
            b'.' | b',' | b';' | b':' | b'!' | b'?' => {}
            b')' if paren < 0 => paren += 1,
            b']' if bracket < 0 => bracket += 1,
            b'}' if brace < 0 => brace += 1,
            _ => break,
        }
        end -= 1;
    }
    &link[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const VLESS: &str =
        "vless://00000000-0000-4000-8000-000000000000@vless.example.com:443?security=tls#VLESS";
    const TUIC: &str = "tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC";
    const NAIVE: &str =
        "naive://user:pass@naive.example.com:443?sni=front.example.com#Naive%20Node";

    /// §7.1 "mixed lines": order is kept.
    #[test]
    fn whole_lines_in_order() {
        let text = format!("{VLESS}\n{TUIC}\r\n  {NAIVE}  \n");
        assert_eq!(uri_candidates(&text), [VLESS, TUIC, NAIVE]);
    }

    /// P-25: a raw-space name stays whole, and the line is not found a second time as free text.
    #[test]
    fn line_with_spaces_in_the_name_is_one_candidate() {
        let line =
            "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=tls#Germany (1)";
        assert_eq!(uri_candidates(line), [line]);
    }

    /// P-15: a CRLF blank line inside a body separates nothing.
    #[test]
    fn blank_crlf_lines_are_skipped() {
        let text = format!("{VLESS}\r\n\r\n{TUIC}\r\n\r\n");
        assert_eq!(uri_candidates(&text), [VLESS, TUIC]);
    }

    /// §7.1 "WG in prose".
    #[test]
    fn links_embedded_in_prose() {
        let text = "Check out: wireguard://cGFzc3dvcmQxMjM=@wg.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.2#MyWG and wg://cGFzc3dvcmQxMjM=@wg2.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.3#WG2";
        let got = uri_candidates(text);
        assert_eq!(got.len(), 2);
        assert!(got[0].starts_with("wireguard://") && got[0].ends_with("#MyWG"));
        assert!(got[1].starts_with("wg://") && got[1].ends_with("#WG2"));
    }

    /// §3.2: trailing punctuation and unmatched closers go, balanced pairs stay.
    #[test]
    fn embedded_links_lose_trailing_punctuation_only() {
        let cases = [
            (
                "See vless://u@h.example:443#Germany%20(1). Bye",
                "vless://u@h.example:443#Germany%20(1)",
            ),
            (
                "prefix vless://u@h.example:443#N, suffix",
                "vless://u@h.example:443#N",
            ),
            ("(trojan://p@h.example:443#T)", "trojan://p@h.example:443#T"),
            (
                "[ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:8388#n]!?",
                "ss://YWVzLTI1Ni1nY206cGFzcw==@h.example:8388#n",
            ),
            (
                "link: hy2://s@h.example:443?mport=1000-2000#H;",
                "hy2://s@h.example:443?mport=1000-2000#H",
            ),
            (
                "<a href=\"vless://u@h.example:443#A\">x</a>",
                "vless://u@h.example:443#A",
            ),
        ];
        for (text, want) in cases {
            assert_eq!(uri_candidates(text), [want], "{text}");
        }
    }

    /// Smoke `{"ok":true,"links":[…]}`: links inside JSON strings stop at the quote.
    #[test]
    fn links_inside_json_strings() {
        let text =
            r#"{"ok":true,"links":["vless://u@h.example:443#A","trojan://p@h.example:443#B"]}"#;
        assert_eq!(
            uri_candidates(text),
            ["vless://u@h.example:443#A", "trojan://p@h.example:443#B"]
        );
    }

    #[test]
    fn schemes_are_case_insensitive_and_limited_to_share_links() {
        let text = "VLESS://u@h.example:443#A\nssr://Zm9v\nhttps://example.com/sub\nhttp://x.example\nhappp://add/x\nhappy vmess://e30=\nnaive+https://u:p@h.example:443#N\nsee naive+quic://u:p@h.example:443#Q";
        assert_eq!(
            uri_candidates(text),
            [
                "VLESS://u@h.example:443#A",
                "ssr://Zm9v",
                "vmess://e30=",
                "naive+https://u:p@h.example:443#N",
                "naive+quic://u:p@h.example:443#Q",
            ]
        );
        assert!(is_uri_line("  Hy2://x"));
        assert!(!is_uri_line("xvless://x"));
        assert!(!is_uri_line("vless:/x"));
        assert!(!is_uri_line(""));
        // A scheme glued to a word is not a link.
        assert!(uri_candidates("abcvless://u@h:1").is_empty());
    }

    #[test]
    fn trimming_is_linear() {
        let text = format!("x vless://a{}", ")".repeat(200_000));
        let started = std::time::Instant::now();
        assert_eq!(uri_candidates(&text), ["vless://a"]);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
