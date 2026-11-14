//! Maximal JSON spans inside arbitrary text, found in one pass. P-04: the old scanner rescanned
//! to the end of the text for every bracket that never closed, so `'{'.repeat(80_000)` froze the
//! main process for close to a minute.
use std::collections::VecDeque;
use std::ops::Range;

use super::uris::is_uri_line;

/// Open brackets kept on the stack. Anything deeper can never parse (serde_json stops at 128).
const MAX_DEPTH: usize = 128;

/// Byte ranges of the outermost balanced `{…}` / `[…]` spans of `text`, in order, at most `max`.
/// Brackets inside JSON strings are ignored. A mismatched closer discards the brackets open before
/// it, so `{ garbage {"valid":1}` still yields the inner document. Lines that start with a share
/// link are skipped: raw JSON in a query value belongs to the link. The spans are candidates; the
/// caller parses them.
pub fn json_spans(text: &str, max: usize) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut stack: VecDeque<(u8, usize)> = VecDeque::new();
    let mut spans: Vec<Range<usize>> = Vec::new();
    let (mut in_string, mut escaped, mut line_start) = (false, false, true);
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            // JSON strings never hold a raw line break: resynchronise on every line.
            (in_string, escaped, line_start) = (false, false, true);
            i += 1;
            continue;
        }
        if line_start {
            line_start = false;
            let line_end = bytes[i..]
                .iter()
                .position(|&c| c == b'\n')
                .map_or(bytes.len(), |p| i + p);
            if is_uri_line(&text[i..line_end]) {
                i = line_end;
                continue;
            }
        }
        if in_string {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match b {
            // Quotes outside any bracket are prose, not JSON.
            b'"' if !stack.is_empty() => in_string = true,
            b'{' | b'[' => {
                if stack.len() == MAX_DEPTH {
                    stack.pop_front();
                }
                stack.push_back((b, i));
            }
            b'}' | b']' => {
                let opener = if b == b'}' { b'{' } else { b'[' };
                match stack.back() {
                    Some(&(open, start)) if open == opener => {
                        stack.pop_back();
                        // Spans nested in this one stop being outermost.
                        while spans.last().is_some_and(|s| s.start > start) {
                            spans.pop();
                        }
                        // Once full, a later span could only matter if a closer still to come
                        // enclosed listed spans, and that closer would enclose this one too.
                        if spans.len() < max {
                            spans.push(start..i + 1);
                        }
                        if spans.len() >= max && stack.is_empty() {
                            break;
                        }
                    }
                    _ => stack.clear(),
                }
            }
            _ => {}
        }
        i += 1;
    }
    spans
}

/// `text` with `spans` (as returned by [`json_spans`]) replaced by spaces, line breaks kept, so
/// later passes do not see the documents a JSON importer already took. Overlapping or invalid
/// ranges are ignored.
pub fn blank_spans(text: &str, spans: &[Range<usize>]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for span in spans {
        let (Some(before), Some(inner)) = (text.get(last..span.start), text.get(span.clone()))
        else {
            continue;
        };
        out.push_str(before);
        out.extend(inner.chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        last = span.end;
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn found(text: &str) -> Vec<&str> {
        json_spans(text, 64).into_iter().map(|r| &text[r]).collect()
    }

    const TROJAN: &str =
        r#"{"type":"trojan","server":"192.0.2.1","server_port":443,"password":"p"}"#;

    /// P-04: unclosed brackets cost one pass, not one pass each.
    #[test]
    fn unclosed_brackets_are_linear() {
        for opener in ["{", "["] {
            let text = opener.repeat(80_000);
            let started = Instant::now();
            assert!(json_spans(&text, 64).is_empty());
            assert!(
                started.elapsed() < Duration::from_millis(50),
                "{opener}: {:?}",
                started.elapsed()
            );
        }
        let text = format!("{}{TROJAN}", "{\"a\":".repeat(80_000));
        assert_eq!(found(&text), [TROJAN]);
    }

    /// P-04: a valid document inside garbage is still found.
    #[test]
    fn document_inside_garbage() {
        assert_eq!(found(&format!("garbage {{ x {TROJAN}")), [TROJAN]);
        assert_eq!(found(&format!("[{TROJAN}}} tail")), [TROJAN]);
        assert_eq!(found(&format!("}}]] {TROJAN} ]")), [TROJAN]);
    }

    #[test]
    fn only_outermost_spans_in_order() {
        let doc = r#"{"outbounds":[{"type":"direct"},{"type":"block"}]}"#;
        assert_eq!(
            found(&format!("Config: {doc}\nmore: [1, [2]] end")),
            [doc, "[1, [2]]"]
        );
        assert_eq!(found(doc), [doc]);
        assert_eq!(found("{}{}[]"), ["{}", "{}", "[]"]);
        assert!(found("no json here").is_empty());
    }

    #[test]
    fn brackets_in_strings_and_prose_quotes() {
        let doc = r#"{"name":"a } ] { [ \" quote","x":[1]}"#;
        assert_eq!(found(doc), [doc]);
        // A stray quote outside any bracket does not swallow the document after it.
        assert_eq!(found(&format!("5\" display {TROJAN}")), [TROJAN]);
        // A string left open by garbage ends at the line break.
        assert_eq!(found(&format!("{{\"broken\n{TROJAN}")), [TROJAN]);
    }

    #[test]
    fn share_link_lines_are_not_scanned() {
        let line = r#"vless://u@h.example:443?type=xhttp&extra={"xPaddingBytes":"100-1000"}#n"#;
        assert!(found(line).is_empty());
        assert!(found(&format!("  {line}\n")).is_empty());
        assert_eq!(found(&format!("{line}\n{TROJAN}")), [TROJAN]);
    }

    #[test]
    fn span_count_is_capped_without_losing_order() {
        let text = "{}".repeat(100);
        assert_eq!(json_spans(&text, 64).len(), 64);
        assert_eq!(json_spans(&text, 64)[63], 126..128);
        // Spans that a later closer swallows do not use up the budget.
        let nested = format!("[{}]", "{},".repeat(100));
        let spans = json_spans(&nested, 3);
        assert_eq!((spans.len(), spans[0].clone()), (1, 0..nested.len()));
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let deep = format!("{}{}", "[".repeat(1000), "]".repeat(1000));
        let spans = json_spans(&deep, 64);
        assert_eq!(spans.len(), 1);
        assert!(spans[0].len() <= 2 * MAX_DEPTH);
    }

    #[test]
    fn blanking_keeps_lines_and_the_rest() {
        let text = format!("a {TROJAN} b\nc [1,\n2] d");
        let spans = json_spans(&text, 64);
        let rest = blank_spans(&text, &spans);
        assert_eq!(rest.len(), text.len());
        assert_eq!(rest.lines().count(), 3);
        assert!(rest.starts_with("a ") && rest.contains(" b\nc ") && rest.ends_with("\n   d"));
        assert!(!rest.contains('{') && !rest.contains('['));
        assert_eq!(blank_spans("abc", &[5..9, 1..2]), "a c");
    }
}
