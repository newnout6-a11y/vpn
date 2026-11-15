//! VMess (both forms) and Trojan.
use serde_json::json;

use super::*;
use crate::model::{Note, Transport};

const ID1: &str = "00000000-0000-4000-8000-000000000001";

fn vmess_json(doc: serde_json::Value) -> String {
    format!("vmess://{}", b64(&doc.to_string()))
}

/// P-34: a `#name` after the base64 no longer breaks decoding; it names the key when `ps` is empty.
#[test]
fn vmess_base64_with_fragment() {
    let doc = json!({"v": "2", "ps": "", "add": "h.example", "port": "443", "id": ID1, "net": "tcp", "tls": "tls"});
    let p = ok(&format!("{}#Node%201", vmess_json(doc.clone())));
    assert_eq!((kind_label(&p), p.name.as_str()), ("vmess", "Node 1"));
    assert!(p.tls.is_some());
    // A query after the base64 is cut off too.
    assert_eq!(ok(&format!("{}?remarks=x#N", vmess_json(doc))).name, "N");
}

/// §7.1 "no tcp-only": plain VMess over TCP+TLS has no transport; `ps` wins over the fragment.
#[test]
fn vmess_tcp_tls() {
    let doc = json!({"add": "vmess.example.com", "port": "443", "id": ID1, "aid": "0", "scy": "auto", "tls": "tls", "ps": "VMess node"});
    let p = ok(&format!("{}#Fragment", vmess_json(doc)));
    assert_eq!(p.name, "VMess node");
    assert!(
        matches!(&p.kind, Kind::Vmess { uuid, security, .. } if uuid == ID1 && security == "auto")
    );
    assert!(p.transport.is_none() && p.notes.is_empty() && p.tls.is_some());
}

/// §7.2 smoke: VMess ws base64 JSON; numbers, URL-safe base64 without padding.
#[test]
fn vmess_ws_json() {
    let doc = json!({"v": "2", "ps": "vm", "add": "h.example", "port": 443, "id": ID1, "net": "ws", "host": "cdn.example", "path": "/ws?ed=2048", "tls": "tls", "allowInsecure": true});
    use base64::Engine as _;
    let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(doc.to_string());
    let p = ok(&format!("vmess://{url_safe}"));
    assert!(
        matches!(&p.transport, Some(Transport::Ws { path, host: Some(h), .. }) if path == "/ws?ed=2048" && h == "cdn.example")
    );
    assert!(p.tls.is_some_and(|t| t.insecure));
}

/// AT-04-002, P-24, ТЗ том 1 §3.4.4: alterId is normalised to 0 with a note; garbage counts as 0.
#[test]
fn vmess_alter_id_and_header() {
    let doc = json!({"add": "h.example", "port": 443, "id": ID1, "aid": 64, "net": "tcp", "type": "http", "host": "a.example", "path": "/p"});
    let p = ok(&vmess_json(doc));
    assert!(p.notes.contains(&Note::AlterIdNormalized(64)));
    assert_eq!(
        p.transport,
        Some(Transport::TcpHttpHeader {
            host: vec!["a.example".into()],
            path: vec!["/p".into()]
        })
    );
    let garbage = ok(&vmess_json(
        json!({"add": "h.example", "port": 443, "id": ID1, "aid": "abc"}),
    ));
    assert!(garbage.notes.is_empty());
    let plain = ok(&vmess_json(
        json!({"add": "h.example", "port": 443, "id": ID1, "scy": "none"}),
    ));
    assert_eq!(plain.notes, vec![Note::Unencrypted]);
}

#[test]
fn vmess_json_errors() {
    assert_eq!(
        err(&vmess_json(json!({"add": "h.example", "port": 443}))),
        SkipReason::MissingCredential
    );
    assert!(is_invalid(&err("vmess://not*base64")));
    assert!(is_invalid(&err(&format!("vmess://{}", b64("[1,2]")))));
    assert!(is_invalid(&err(&vmess_json(
        json!({"add": "h.example", "port": "0x1BB", "id": ID1})
    ))));
    let description = vmess_json(
        json!({"add": "h.example", "port": 443, "id": ID1, "serverDescription": b64("Fast")}),
    );
    assert_eq!(ok(&description).description.as_deref(), Some("Fast"));
}

/// AT-04-002, K14: v2rayN / 3x-ui keep the gRPC and XHTTP mode in `type`; an explicit `mode`
/// wins, `none` means unset. Their `pcs` pin and `vcn` names are read (AT-04-006).
#[test]
fn vmess_json_mode_in_type() {
    let doc = |net: &str, extra: serde_json::Value| {
        let mut doc = json!({"add": "h.example", "port": 443, "id": ID1, "net": net, "tls": "tls", "path": "svc"});
        doc.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        ok(&vmess_json(doc))
    };
    let grpc = |multi_mode| {
        Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode,
        })
    };
    assert_eq!(
        doc("grpc", json!({"type": "multi"})).transport,
        grpc(Some(true))
    );
    assert_eq!(doc("grpc", json!({"type": "none"})).transport, grpc(None));
    let explicit = doc("grpc", json!({"type": "multi", "mode": "gun"}));
    assert_eq!(explicit.transport, grpc(Some(false)));
    let xhttp = doc("xhttp", json!({"type": "packet-up"}));
    assert!(
        matches!(&xhttp.transport, Some(Transport::Xhttp { mode: Some(m), .. }) if m == "packet-up")
    );
    let pin = "ab".repeat(32);
    let pinned = doc(
        "ws",
        json!({"type": "none", "pcs": pin, "vcn": "n.example"}),
    );
    assert_eq!(pinned.notes, vec![Note::CertPinNotEnforced]);
    let tls = pinned.tls.expect("TLS");
    assert_eq!(
        tls.cert_pin_sha256,
        Some(pin),
        "pcs is Xray's pinnedPeerCertSha256"
    );
    assert_eq!(
        tls.cert_names(),
        Some("n.example"),
        "vcn is verifyPeerCertByName"
    );
}

/// Xray `pcs` (`pinnedPeerCertSha256`) is the key's certificate pin in every V2Ray-family link,
/// as in Xray JSON: next to `allowInsecure` the emitter refuses it on sing-box (Xray enforces
/// it) instead of dialing unverified. A pin that is no SHA-256 fails the link.
#[test]
fn xray_certificate_pin() {
    let pin = "cd".repeat(32);
    let p = ok(&format!(
        "vless://{ID1}@h.example:443?security=tls&allowInsecure=1&pcs={pin}%2C{}#P",
        "ef".repeat(32)
    ));
    let tls = p.tls.as_ref().expect("tls");
    assert!(tls.insecure);
    assert_eq!(tls.cert_pin_sha256, Some(pin), "first of the list");
    assert_eq!(p.notes, vec![Note::CertPinNotEnforced]);
    assert!(is_invalid(&err(
        "trojan://pw@h.example:443?allowInsecure=1&pcs=abc#P"
    )));
}

/// §7.3 new schemes: the Xray VMess URI form (`encryption` is the cipher).
#[test]
fn vmess_uri_form() {
    let p = ok(&format!(
        "vmess://{ID1}@h.example:443?type=ws&security=tls&path=%2Fws&host=cdn.example#VM"
    ));
    assert!(matches!(&p.kind, Kind::Vmess { security, .. } if security == "auto"));
    assert!(matches!(&p.transport, Some(Transport::Ws { path, .. }) if path == "/ws"));
    assert!(p.tls.is_some());
    assert_eq!(p.name, "VM");
    let cipher = ok(&format!(
        "vmess://{ID1}@h.example:443?encryption=chacha20-poly1305&aid=4"
    ));
    assert!(
        matches!(&cipher.kind, Kind::Vmess { security, .. } if security == "chacha20-poly1305")
    );
    assert_eq!(cipher.notes, vec![Note::AlterIdNormalized(4)]);
    assert_eq!(
        err("vmess://@h.example:443?security=tls"),
        SkipReason::MissingCredential
    );
}

/// AT-04-003, K1, F-045: one decode only — `p%2525ss` is the password `p%25ss`.
#[test]
fn trojan_password_decoded_once() {
    let p = ok("trojan://p%2525ss@t.example:443#T");
    assert!(matches!(&p.kind, Kind::Trojan { password } if password == "p%25ss"));
    // TLS is on by default for Trojan.
    assert!(p.tls.is_some() && p.notes.is_empty());
    let colon = ok("trojan://pa:ss@t.example:443");
    assert!(matches!(&colon.kind, Kind::Trojan { password } if password == "pa:ss"));
}

/// §7.1 passwordless vector and the §7.2 smoke trojan-ws line.
#[test]
fn trojan_passwordless_and_ws() {
    assert_eq!(
        err("trojan://@trojan.example.com:443?sni=front.example.com#Trojan"),
        SkipReason::MissingCredential
    );
    let p = ok("trojan://secret@t.example:443?type=ws&host=cdn.example.org&path=%2Fws#T");
    assert!(
        matches!(&p.transport, Some(Transport::Ws { path, host: Some(h), .. }) if path == "/ws" && h == "cdn.example.org")
    );
    // `host` is the last SNI alias, as in v2rayN.
    assert_eq!(
        p.tls.and_then(|t| t.server_name).as_deref(),
        Some("cdn.example.org")
    );
}

/// P-37: `security=none` keeps a TLS-less Trojan TLS-less, with a note.
#[test]
fn trojan_security_none() {
    let p = ok("trojan://p@h.example:443?security=none&type=ws&path=%2Fws#t");
    assert!(p.tls.is_none());
    assert_eq!(p.notes, vec![Note::Unencrypted]);
}
