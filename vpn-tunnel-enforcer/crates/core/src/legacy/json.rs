//! Lenient JSON for files the old Electron build wrote.
use serde_json::Value;

/// Parses a document the way the old app read it, minus its failure modes: invalid UTF-8 becomes
/// U+FFFD (Node's `readFileSync(path, "utf8")` did the same), a BOM is ignored, and lone UTF-16
/// surrogate escapes become `�`. `JSON.stringify` writes those for a name cut in the middle of
/// an emoji, and serde_json would otherwise reject the whole file.
pub(super) fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = String::from_utf8_lossy(bytes);
    match serde_json::from_str(&text) {
        Ok(value) => Ok(value),
        Err(first) => match repair_surrogates(&text) {
            Some(fixed) => serde_json::from_str(&fixed).map_err(|_| first),
            None => Err(first),
        },
    }
}

/// Replaces `\uD800`-`\uDFFF` escapes that are not part of a valid pair; `None` if there are none.
fn repair_surrogates(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let unit = |at: usize| -> Option<u16> {
        if b.get(at) != Some(&b'\\') || b.get(at + 1) != Some(&b'u') {
            return None;
        }
        let hex = b.get(at + 2..at + 6)?;
        // `from_str_radix` alone would also take a sign (`\u+abc`).
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
    };
    let is_high = |u: u16| (0xD800..0xDC00).contains(&u);
    let is_low = |u: u16| (0xDC00..0xE000).contains(&u);

    let mut out = String::new();
    let (mut i, mut copied, mut in_string) = (0, 0, false);
    while i < b.len() {
        match b[i] {
            b'"' => {
                in_string = !in_string;
                i += 1;
            }
            b'\\' if in_string => match unit(i) {
                Some(u) if is_high(u) && unit(i + 6).is_some_and(is_low) => i += 12,
                Some(u) if is_high(u) || is_low(u) => {
                    // `i` sits on an ASCII backslash, so both slices end on char boundaries.
                    out.push_str(&text[copied..i]);
                    out.push_str("\\uFFFD");
                    i += 6;
                    copied = i;
                }
                Some(_) => i += 6,
                // Any other escape is two bytes; a malformed one is left for serde_json to report.
                None => i += 2,
            },
            _ => i += 1,
        }
    }
    if copied == 0 {
        return None;
    }
    out.push_str(&text[copied..]);
    Some(out)
}
