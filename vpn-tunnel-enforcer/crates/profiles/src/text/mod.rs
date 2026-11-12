//! Text pipeline building blocks: bounded decoding of pasted text and subscription bodies,
//! strict base64 layers, JSON spans, share-link candidates and subscription metadata lines.
//!
//! `parse_text` (crate `vpnte-servers`) strings these together. Every function here is pure and
//! linear in its input, so a hostile body cannot freeze the process that owns the kill switch.
mod body;
mod controls;
mod layers;
mod meta;
mod spans;
mod uris;

pub use body::{decode_body, prepare};
pub use controls::{AutoconnectPick, Controls, ProviderKeys, Relocation, body_keys, header_keys};
pub use layers::{decode_base64_layer, layers};
pub use meta::{apply_meta, body_meta, header_meta};
pub use spans::{blank_spans, json_spans};
pub use uris::{URI_SCHEMES, is_uri_line, uri_candidates};

/// Largest pasted input accepted, in bytes (profiles §6.5 #12).
pub const MAX_INPUT_BYTES: usize = 1 << 20;
/// Largest subscription body, in bytes, both as received and after decompression.
pub const MAX_BODY_BYTES: usize = 16 << 20;
/// Nested base64 layers decoded under one text.
pub const MAX_BASE64_DEPTH: usize = 3;
/// JSON documents taken from one text.
pub const MAX_JSON_SPANS: usize = 64;

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::model::SubscriptionMeta;

    /// P-14: a sing-box document followed by a share link. The span goes to the JSON importer
    /// (blank only the spans an importer took), the link is found in what is left.
    #[test]
    fn json_document_then_link() {
        let doc = r#"{"outbounds":[{"type":"trojan","server":"192.0.2.1","server_port":443,"password":"p"}]}"#;
        let link = "vless://00000000-0000-4000-8000-000000000000@h.example:443?security=tls#V";
        let text = format!("{doc}\n{link}\n");
        let (meta, body) = body_meta(&text);
        assert_eq!(meta, SubscriptionMeta::default());
        let layers = layers(body);
        assert_eq!(layers.len(), 1);
        let spans = json_spans(&layers[0], MAX_JSON_SPANS);
        assert_eq!(spans.len(), 1);
        assert!(serde_json::from_str::<serde_json::Value>(&layers[0][spans[0].clone()]).is_ok());
        assert_eq!(uri_candidates(&blank_spans(&layers[0], &spans)), [link]);
    }

    /// A Happ body: metadata lines, then a base64 list.
    #[test]
    fn metadata_then_base64_list() {
        let list = "vless://u@a.example:443#A\ntrojan://p@b.example:443#B";
        let body = format!(
            "#profile-title: Provider\r\n#profile-update-interval: 6\r\n{}\r\n",
            STANDARD.encode(list)
        );
        let (meta, rest) = body_meta(&body);
        assert_eq!(
            (meta.title.as_deref(), meta.refresh_hours),
            (Some("Provider"), Some(6))
        );
        let layers = layers(rest);
        assert_eq!(layers.len(), 2);
        assert_eq!(
            uri_candidates(&layers[1]),
            ["vless://u@a.example:443#A", "trojan://p@b.example:443#B"]
        );
    }
}
