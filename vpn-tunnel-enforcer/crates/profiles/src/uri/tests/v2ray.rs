//! VLESS, VMess, Trojan.
use super::*;
use crate::model::{HelloSplit, Mux, Note, Span, TlsTricks, Transport};

const ID0: &str = "00000000-0000-4000-8000-000000000000";
const ID1: &str = "00000000-0000-4000-8000-000000000001";
const PBK: &str = "SyntheticRealityPublicKey000000000000000000";

/// AT-04-001 mixed lines: the VLESS line of the protocol-coverage vector.
#[test]
fn vless_tls_line() {
    let p = ok(&format!(
        "vless://{ID1}@vless.example.com:443?security=tls#VLESS"
    ));
    assert_eq!(kind_label(&p), "vless");
    assert_eq!(
        (p.server.clone(), p.port),
        (domain("vless.example.com"), 443)
    );
    let tls = p.tls.expect("tls");
    // Provider values only: no uTLS / ALPN defaults are materialised by the parser (P-01, P-05).
    assert_eq!(
        (tls.fingerprint, tls.alpn.len(), tls.server_name),
        (None, 0, None)
    );
    assert!(p.transport.is_none() && p.mux.is_none() && p.notes.is_empty());
    assert_eq!(
        p.source,
        crate::model::Source::Uri(format!(
            "vless://{ID1}@vless.example.com:443?security=tls#VLESS"
        ))
    );
}

/// §7.2 REALITY spx: `spider_x` decoded once.
#[test]
fn vless_reality_spider_x() {
    let line = format!(
        "vless://{ID0}@reality.example.com:443?security=reality&pbk={PBK}&sid=1234&spx=%2Ftest-path#Reality"
    );
    let reality = ok(&line).tls.and_then(|t| t.reality).expect("reality");
    assert_eq!(reality.public_key, PBK);
    assert_eq!(reality.short_id, "1234");
    assert_eq!(reality.spider_x.as_deref(), Some("/test-path"));
}

/// §7.2 smoke: VLESS REALITY with vision flow and provider fingerprint.
#[test]
fn vless_reality_smoke() {
    let line = format!(
        "vless://{ID0}@r.example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk={PBK}&sid=1234&type=tcp&flow=xtls-rprx-vision#R"
    );
    let p = ok(&line);
    let Kind::Vless { flow, .. } = &p.kind else {
        panic!("not vless")
    };
    assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
    let tls = p.tls.expect("tls");
    assert!(tls.reality.is_some());
    assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
    assert_eq!(tls.server_name.as_deref(), Some("www.example.com"));
    assert!(p.transport.is_none());
}

#[test]
fn reality_without_public_key_is_invalid() {
    assert!(is_invalid(&err(&format!(
        "vless://{ID0}@r.example.com:443?security=reality&sid=12"
    ))));
}

/// `auditFixesRegression.test.ts` mux/padding; a non-UUID id is an Xray custom id and is kept.
#[test]
fn vless_mux_padding_and_custom_id() {
    let line = format!(
        "vless://uuid-123@1.2.3.4:443?security=reality&pbk={PBK}&sid=d34db33f&fp=chrome&sni=example.com&mux=1&padding=1#RealityMux"
    );
    let p = ok(&line);
    assert_eq!(
        p.mux,
        Some(Mux {
            enabled: true,
            padding: true,
            ..Mux::default()
        })
    );
    assert!(matches!(&p.kind, Kind::Vless { uuid, .. } if uuid == "uuid-123"));
    assert_eq!(p.server, ip("1.2.3.4"));
    assert_eq!(p.name, "RealityMux");
}

/// P-24/P-25: empty id is skipped; raw spaces in the fragment are a legal name.
#[test]
fn vless_credential_and_raw_space_name() {
    assert_eq!(
        err("vless://@h.example:443?security=tls"),
        SkipReason::MissingCredential
    );
    let p = ok(&format!(
        "vless://{ID0}@h.example:443?security=tls#Germany (1)"
    ));
    assert_eq!(p.name, "Germany (1)");
}

/// P-13: VLESS encryption (Xray only) and the TCP HTTP header mask are kept, not dropped.
#[test]
fn vless_encryption_and_http_header_kept() {
    let line = format!(
        "vless://{ID0}@h.example:443?encryption=mlkem768x25519plus.native.0rtt.SYNTH&type=tcp&headerType=http&host=a.example,b.example&path=%2Fx#E"
    );
    let p = ok(&line);
    assert!(
        matches!(&p.kind, Kind::Vless { encryption: Some(e), .. } if e.starts_with("mlkem768"))
    );
    let expected = Transport::TcpHttpHeader {
        host: vec!["a.example".into(), "b.example".into()],
        path: vec!["/x".into()],
    };
    assert_eq!(p.transport, Some(expected));
    // Encrypted by VLESS itself, so no "unencrypted" note even without TLS.
    assert!(p.tls.is_none() && p.notes.is_empty());
    let plain = ok(&format!(
        "vless://{ID0}@h.example:443?encryption=none&security=none"
    ));
    assert_eq!(plain.notes, vec![Note::Unencrypted]);
}

#[test]
fn unknown_security_and_header_types_are_rejected() {
    assert!(is_invalid(&err(&format!(
        "vless://{ID0}@h.example:443?security=xtls"
    ))));
    assert!(is_invalid(&err(&format!(
        "vless://{ID0}@h.example:443?headerType=srtp"
    ))));
    let kcp = err(&format!("vless://{ID0}@h.example:443?type=kcp"));
    assert_eq!(kcp, SkipReason::UnsupportedTransport("kcp".into()));
}

/// AT-04-006, P-13: Xray-only parameters the model cannot carry are noted, not dropped silently;
/// `fragment=` is carried now (item 18) and noted only when it cannot be read.
#[test]
fn unmodeled_xray_parameters_are_noted() {
    let line = format!(
        "vless://{ID0}@h.example:443?security=reality&pbk={PBK}&fragment=1,40-60,30-50&noises=SYNTH#F"
    );
    let p = ok(&line);
    // REALITY runs no tricks on any engine: the value stays for export, the loss is noted (a5).
    let fragment = Note::UnsupportedField("fragment".into());
    let noises = Note::UnsupportedField("noises".into());
    assert_eq!(p.notes, vec![fragment.clone(), noises.clone()]);
    let tls = ok(&line.replace("security=reality", "security=tls&sni=h.example"));
    assert_eq!(tls.notes, vec![noises]);
    let h3 = ok(&format!(
        "vless://{ID0}@h.example:443?security=tls&type=xhttp&alpn=h3&path=%2F&fragment=1,40-60,30-50#F"
    ));
    assert!(h3.notes.contains(&fragment), "{:?}", h3.notes);
    let split = HelloSplit {
        len: Span::new(40, 60),
        interval_ms: Span::new(30, 50),
    };
    let tricks = p.tls.as_ref().and_then(|tls| tls.tricks);
    assert_eq!(tricks, Some(TlsTricks::Hello(split)));
    let odd = ok(&format!(
        "vless://{ID0}@h.example:443?security=tls&fragment=2-4,10,5#F"
    ));
    assert_eq!(odd.notes, vec![Note::UnsupportedField("fragment".into())]);
    assert_eq!(odd.tls.as_ref().and_then(|tls| tls.tricks), None);
    let plain = ok(&format!(
        "vless://{ID0}@h.example:80?fragment=tlshello,100-200,10-20#F"
    ));
    let noted = Note::UnsupportedField("fragment".into());
    assert!(plain.notes.contains(&noted), "{:?}", plain.notes);
}

/// Item 18: Xray's order, Hiddify's `size,sleep,tlshello` and `fgsize` / `fgsleep` all reach
/// `Tls::tricks` (trojan and vmess share the reader).
#[test]
fn link_tls_tricks() {
    let tricks = |line: &str| ok(line).tls.and_then(|tls| tls.tricks);
    let strong = Some(TlsTricks::STRONG);
    let base = format!("vless://{ID0}@h.example:443?security=tls");
    assert_eq!(
        tricks(&format!("{base}&fragment=tlshello,100-200,10-20#F")),
        strong
    );
    assert_eq!(
        tricks(&format!("{base}&fragment=100-200,10-20,tlshello#F")),
        strong
    );
    assert_eq!(
        tricks(&format!("{base}&fragment=tlshello%2C100-200%2C0#F")),
        Some(TlsTricks::Record)
    );
    assert_eq!(
        tricks(&format!("{base}&fgsize=100-200&fgsleep=10-20#F")),
        Some(TlsTricks::Hello(HelloSplit::PRESET))
    );
    let trojan = "trojan://fake-pass@h.example:443?sni=h.example&fragment=tlshello,100-200,10-20#T";
    assert_eq!(tricks(trojan), strong);
}

/// REALITY sends the cover site's own hello: a link that also asks for ECH can never connect
/// (the emitter refuses it), so it is skipped at import.
#[test]
fn reality_with_ech_is_skipped() {
    let line = format!(
        "vless://{ID0}@h.example:443?security=reality&pbk={PBK}&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#R"
    );
    assert!(
        matches!(err(&line), SkipReason::Invalid { detail, .. } if detail == "REALITY cannot be combined with ECH"),
        "{line}"
    );
}
