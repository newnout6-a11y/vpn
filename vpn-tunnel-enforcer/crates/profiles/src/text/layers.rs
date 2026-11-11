//! Strict base64 layers: a subscription body may be base64 of a list, or base64 of base64 of a
//! list. Strict decoding keeps plain words and truncated blobs from turning into garbage text.
use std::borrow::Cow;

use super::MAX_BASE64_DEPTH;

/// The UTF-8 text that `text` encodes when the whole of it is base64 (standard or URL-safe
/// alphabet, padding optional, line breaks allowed); `None` otherwise. Strict: canonical trailing
/// bits, valid UTF-8 (never lossy), no NUL, not blank.
pub use crate::common::b64::base64_text as decode_base64_layer;

/// `text`, then each nested base64 layer under it, outermost first (at most
/// [`MAX_BASE64_DEPTH`] decoded layers). Whether a layer holds profiles is the importers' call,
/// so `base64(base64(list))` is reachable (AT-04-003); the old "looks like profiles" test stopped
/// at the middle layer.
pub fn layers(text: &str) -> Vec<Cow<'_, str>> {
    let mut out = vec![Cow::Borrowed(text)];
    while out.len() <= MAX_BASE64_DEPTH {
        let Some(next) = out.last().and_then(|t| decode_base64_layer(t)) else {
            break;
        };
        out.push(Cow::Owned(next));
    }
    out
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    use super::*;

    const LINES: &str = "vless://00000000-0000-4000-8000-000000000001@a.example:443?security=tls#A\n\
        trojan://secret@b.example:443?sni=front.example.com#B\n\
        hy2://secret@c.example:443?sni=front.example.com#C";

    /// AT-04-003 / P-14: `base64(base64(<3 URI lines>))` reaches the lines.
    #[test]
    fn nested_layers_reach_the_list() {
        let twice = STANDARD.encode(STANDARD.encode(LINES));
        let got = layers(&twice);
        assert_eq!(got.len(), 3);
        assert_eq!(got[2], LINES);
    }

    #[test]
    fn url_safe_unpadded_and_wrapped_base64_is_accepted() {
        let encoded = URL_SAFE_NO_PAD.encode("ss://a?b=>>>#n\n");
        assert!(encoded.contains('-') || encoded.contains('_'));
        assert_eq!(
            decode_base64_layer(&encoded).as_deref(),
            Some("ss://a?b=>>>#n\n")
        );
        let wrapped: String = STANDARD
            .encode(LINES)
            .as_bytes()
            .chunks(76)
            .map(|c| format!("{}\r\n", std::str::from_utf8(c).unwrap()))
            .collect();
        assert_eq!(decode_base64_layer(&wrapped).as_deref(), Some(LINES));
        let bom = STANDARD.encode(format!("\u{feff}{LINES}"));
        assert_eq!(decode_base64_layer(&bom).as_deref(), Some(LINES));
    }

    #[test]
    fn plain_text_and_damaged_base64_are_not_layers() {
        assert_eq!(layers(LINES).len(), 1);
        for text in ["test", "garbage", "abc", "", "    ", "YWJj ZGVm!"] {
            assert_eq!(decode_base64_layer(text), None, "{text:?}");
        }
        // Truncated blob (length % 4 == 1), padding in the middle, non-canonical trailing bits.
        let full = STANDARD.encode(LINES);
        assert_eq!(decode_base64_layer(&full[..full.len() - 3]), None);
        assert_eq!(decode_base64_layer("YQ==YQ=="), None);
        assert_eq!(decode_base64_layer("YR=="), None);
        // Binary payloads are not text.
        assert_eq!(
            decode_base64_layer(&STANDARD.encode([0xff, 0xfe, 0x00, 0x41])),
            None
        );
        assert_eq!(decode_base64_layer(&STANDARD.encode("a\0b")), None);
        assert_eq!(decode_base64_layer(&STANDARD.encode("   \n")), None);
    }

    #[test]
    fn depth_is_bounded() {
        let mut text = String::from("vless://x@h:1");
        for _ in 0..6 {
            text = STANDARD.encode(text);
        }
        assert_eq!(layers(&text).len(), 1 + MAX_BASE64_DEPTH);
    }
}
