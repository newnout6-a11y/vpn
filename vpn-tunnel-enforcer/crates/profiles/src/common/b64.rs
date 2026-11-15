//! Strict base64: subscription layers, share-link payloads, key material and ECH configs all
//! arrive in either alphabet, padded or not, sometimes wrapped over lines. Strictness keeps plain
//! words and truncated blobs from decoding into garbage.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_PAD_INDIFFERENT;

/// Bytes of strict base64: standard or URL-safe alphabet (even mixed), padding optional, ASCII
/// whitespace ignored, canonical trailing bits. `None` for anything else or a blank input.
pub fn base64_bytes(text: &str) -> Option<Vec<u8>> {
    let symbol = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_');
    // Checked before allocating: most texts fail within their first bytes.
    if !text.bytes().all(|b| symbol(b) || b.is_ascii_whitespace()) {
        return None;
    }
    let compact: Vec<u8> = text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        })
        .collect();
    if compact.is_empty() {
        return None;
    }
    STANDARD_PAD_INDIFFERENT.decode(&compact).ok()
}

/// The UTF-8 text that `text` encodes when the whole of it is strict base64 (as `base64_bytes`)
/// of at least four symbols; a leading BOM is dropped. Never lossy: invalid UTF-8, a NUL or a
/// blank result is `None`.
pub fn base64_text(text: &str) -> Option<String> {
    if text.bytes().filter(|b| !b.is_ascii_whitespace()).count() < 4 {
        return None;
    }
    let decoded = String::from_utf8(base64_bytes(text)?).ok()?;
    let decoded = match decoded.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_owned(),
        None => decoded,
    };
    (!decoded.contains('\0') && !decoded.trim().is_empty()).then_some(decoded)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;

    #[test]
    fn both_alphabets_padding_and_wrapping() {
        assert_eq!(
            base64_text("aGVsbG8gd29ybGQ").as_deref(),
            Some("hello world")
        );
        assert_eq!(
            base64_text("aGVs bG8g\nd29y bGQ=").as_deref(),
            Some("hello world")
        );
        let url_safe = URL_SAFE_NO_PAD.encode([0xfb, 0xff, 0xbf]);
        assert_eq!(url_safe, "-_-_");
        assert_eq!(base64_bytes(&url_safe), Some(vec![0xfb, 0xff, 0xbf]));
        assert_eq!(base64_bytes("AQID"), Some(vec![1, 2, 3]));
        assert_eq!(base64_bytes("AQ"), Some(vec![1]));
    }

    #[test]
    fn plain_words_and_damaged_blobs_are_refused() {
        for text in [
            "",
            "   ",
            "true",
            "garbage",
            "abcde",
            "a-_b",
            "https://x.example",
        ] {
            assert_eq!(base64_text(text), None, "{text:?}");
        }
        assert_eq!(base64_bytes(""), None);
        assert_eq!(base64_bytes("YQ==YQ=="), None, "padding in the middle");
        assert_eq!(base64_bytes("YR=="), None, "non-canonical trailing bits");
        assert_eq!(
            base64_text(&STANDARD.encode([0xff, 0xfe, 0x00, 0x41])),
            None
        );
        assert_eq!(base64_text(&STANDARD.encode("a\0b")), None);
        assert_eq!(base64_text(&STANDARD.encode("   \n")), None);
        assert_eq!(
            base64_text(&STANDARD.encode("\u{feff}vless://x")).as_deref(),
            Some("vless://x")
        );
    }
}
