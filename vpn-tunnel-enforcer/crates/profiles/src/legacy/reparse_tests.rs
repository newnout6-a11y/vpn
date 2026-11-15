use serde_json::json;

use super::*;
use crate::model::Source;

#[test]
fn share_link_wins_over_the_stored_outbound() {
    let line = "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example&type=ws&path=%2Fws#Link";
    let stored = json!({ "type": "vless", "server": "h.example", "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000001",
        "tls": { "enabled": true, "server_name": "front.example", "alpn": ["h2", "http/1.1"], "utls": { "enabled": true, "fingerprint": "chrome" } },
        "transport": { "type": "ws", "path": "/ws" } });
    let p = from_legacy("My server", "vless", &stored, Some(line)).expect("imports");
    assert_eq!(
        p.name, "My server",
        "the user's name wins over the link fragment"
    );
    assert_eq!(p.source, Source::Uri(line.to_owned()));
    let tls = p.tls.expect("tls");
    assert!(tls.alpn.is_empty() && tls.fingerprint.is_none(), "{tls:?}");
    // A feed URL is not a key: the stored outbound is used.
    let p = from_legacy(
        "Feed row",
        "vless",
        &stored,
        Some("https://sub.example.com/token"),
    )
    .expect("imports");
    assert_eq!(p.source, Source::Legacy);
}

/// P-05: only the stored outbound carries invented defaults; a link's explicit `fp` / `alpn` are
/// the provider's choice and survive, exactly as on the next subscription refresh.
#[test]
fn explicit_link_tls_choices_survive() {
    let line = "vless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls&sni=front.example&fp=chrome&alpn=h2%2Chttp%2F1.1#Link";
    let stored = json!({ "type": "vless", "server": "h.example", "server_port": 443, "uuid": "00000000-0000-4000-8000-000000000001" });
    let tls = from_legacy("Row", "vless", &stored, Some(line))
        .expect("imports")
        .tls
        .expect("tls");
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(tls.alpn, ["h2", "http/1.1"]);
}
