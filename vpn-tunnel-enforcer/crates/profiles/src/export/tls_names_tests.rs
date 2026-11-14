//! Xray 26 TLS checks end to end (re-check item 5; AT-04-006, no silent loss of fields): `vcn`
//! (`verifyPeerCertByName`) and `pqv` (REALITY `mldsa65Verify`) are read from links, v2rayN
//! JSON and Xray JSON, written back by the exporters and kept off sing-box. Synthetic values.
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

use super::export_uri;
use crate::emit_singbox::{EmitError, EmitPolicy, emit_singbox};
use crate::json::parse_json;
use crate::model::{Note, Profile, Reality, SkipReason, Source, Tls};
use crate::uri::parse_uri;

const ID: &str = "00000000-0000-4000-8000-000000000001";
/// A well-formed X25519 public key (32 bytes of 0x01), base64url.
const PBK: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

/// A synthetic ML-DSA-65 public key: 1952 varied bytes, so both base64 alphabets differ.
fn pq_key() -> Vec<u8> {
    (0..1952u32).map(|i| (i * 7 % 256) as u8).collect()
}

fn pqv() -> String {
    URL_SAFE_NO_PAD.encode(pq_key())
}

fn ok(line: &str) -> Profile {
    parse_uri(line).unwrap_or_else(|e| panic!("{line}: {e:?}"))
}

fn tls(p: &Profile) -> &Tls {
    p.tls.as_ref().expect("TLS")
}

/// The exporter's own link (not the imported line) and the profile the importer reads from it.
fn round_trip(p: &Profile) -> (String, Profile) {
    let fresh = Profile {
        source: Source::Json,
        ..p.clone()
    };
    let link = export_uri(&fresh).unwrap_or_else(|| panic!("no link for {}", p.name));
    let back = ok(&link);
    (link, back)
}

/// `vcn` on a TLS link: names trimmed and empty items dropped, the SNI untouched, written back
/// as `vcn`; next to `allowInsecure` (kept for older clients) too.
#[test]
fn vcn_link_round_trip() {
    let line = format!(
        "vless://{ID}@h.example:443?security=tls&sni=white.example&vcn=real.example,%20,alt.example#N"
    );
    let p = ok(&line);
    assert!(p.notes.is_empty(), "{:?}", p.notes);
    assert_eq!(tls(&p).server_name.as_deref(), Some("white.example"));
    assert_eq!(tls(&p).cert_names(), Some("real.example,alt.example"));
    let (link, back) = round_trip(&p);
    assert!(link.contains("vcn=real.example%2Calt.example"), "{link}");
    assert_eq!(back.tls, p.tls);
    let trojan =
        ok("trojan://pw@h.example:443?sni=white.example&allowInsecure=1&vcn=real.example#T");
    assert!(tls(&trojan).insecure);
    assert_eq!(tls(&trojan).cert_names(), Some("real.example"));
    assert_eq!(round_trip(&trojan).1.tls, trojan.tls);
}

/// `pqv` on a REALITY link, in either base64 alphabet, padded or not, is stored as the unpadded
/// base64url Xray demands and written back; a key Xray would refuse fails the link.
#[test]
fn pqv_link_round_trip() {
    let canonical = pqv();
    for written in [canonical.clone(), STANDARD.encode(pq_key())] {
        let written = utf8_percent_encode(&written, NON_ALPHANUMERIC);
        let line = format!(
            "vless://{ID}@h.example:443?security=reality&sni=cover.example&pbk={PBK}&sid=0123abcd&fp=chrome&pqv={written}#R"
        );
        let p = ok(&line);
        assert!(p.notes.is_empty(), "{:?}", p.notes);
        let reality = tls(&p).reality.as_ref().expect("REALITY");
        assert_eq!(reality.mldsa65_key(), Some(canonical.as_str()));
        let (link, back) = round_trip(&p);
        assert!(link.contains(&format!("pqv={canonical}")), "{link}");
        assert_eq!(back.tls, p.tls);
    }
    let short = URL_SAFE_NO_PAD.encode([2u8; 32]);
    for bad in [short.as_str(), "SYNTH"] {
        let line = format!("vless://{ID}@h.example:443?security=reality&pbk={PBK}&pqv={bad}#R");
        assert!(
            matches!(parse_uri(&line), Err(SkipReason::Invalid { .. })),
            "{bad}"
        );
    }
}

/// Each check means nothing on the other security: dropped, with a visible note.
#[test]
fn checks_on_the_wrong_security_are_noted() {
    let pqv = pqv();
    let on_tls = ok(&format!(
        "vless://{ID}@h.example:443?security=tls&sni=h.example&pqv={pqv}#T"
    ));
    assert_eq!(on_tls.notes, vec![Note::UnsupportedField("pqv".into())]);
    let on_reality = ok(&format!(
        "vless://{ID}@h.example:443?security=reality&pbk={PBK}&vcn=real.example#R"
    ));
    assert_eq!(on_reality.notes, vec![Note::UnsupportedField("vcn".into())]);
    assert_eq!(tls(&on_reality).verify_peer_cert_by_name, None);
    let plain = ok(&format!("vless://{ID}@10.0.0.1:80?vcn=real.example#P"));
    assert!(plain.notes.contains(&Note::UnsupportedField("vcn".into())));
}

/// v2rayN's VMess JSON carries `vcn` both ways; it has no `pqv`, so such a key gets no VMess link.
#[test]
fn vmess_json_carries_vcn() {
    let doc = json!({"v": "2", "ps": "V", "add": "h.example", "port": 443, "id": ID, "aid": 0,
        "net": "tcp", "type": "none", "tls": "tls", "sni": "white.example", "vcn": "real.example"});
    let p = ok(&format!("vmess://{}", STANDARD.encode(doc.to_string())));
    assert!(p.notes.is_empty(), "{:?}", p.notes);
    assert_eq!(tls(&p).cert_names(), Some("real.example"));
    let (link, back) = round_trip(&p);
    let body = STANDARD
        .decode(link.trim_start_matches("vmess://"))
        .expect("base64");
    let written: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(written["vcn"], "real.example");
    assert_eq!(back.tls, p.tls);
    let reality = Profile {
        tls: Some(Tls {
            reality: Some(Reality {
                public_key: PBK.into(),
                mldsa65_verify: Some(pqv()),
                ..Reality::default()
            }),
            ..Tls::default()
        }),
        source: Source::Json,
        ..p
    };
    assert_eq!(export_uri(&reality), None);
}

/// Xray JSON: both keys are typed, so a lone outbound stays a plain profile; a malformed
/// `mldsa65Verify` (Xray refuses the whole config) skips the outbound.
#[test]
fn xray_json_reads_both() {
    let pqv = pqv();
    let outbound = |tag: &str, stream: Value| {
        json!({"tag": tag, "protocol": "vless", "settings": {"vnext": [{"address": "h.example",
            "port": 443, "users": [{"id": ID, "encryption": "none"}]}]}, "streamSettings": stream})
    };
    let reality = |key: &str| {
        json!({"network": "tcp", "security": "reality", "realitySettings": {
            "serverName": "cover.example", "password": PBK, "shortId": "0123abcd",
            "fingerprint": "chrome", "mldsa65Verify": key}})
    };
    let r = parse_json(&json!([
        outbound(
            "named",
            json!({"network": "tcp", "security": "tls", "tlsSettings": {
                "serverName": "white.example", "verifyPeerCertByName": "real.example, alt.example"}})
        ),
        outbound("pq", reality(&pqv)),
        outbound("broken", reality("FAKE")),
    ]));
    assert_eq!(r.profiles.len(), 2, "{:?}", r.skipped);
    assert_eq!(r.skipped.len(), 1, "{:?}", r.skipped);
    for p in &r.profiles {
        assert!(p.native_xray.is_none(), "{}", p.name);
        assert!(p.notes.is_empty(), "{}: {:?}", p.name, p.notes);
    }
    assert_eq!(
        tls(&r.profiles[0]).cert_names(),
        Some("real.example,alt.example")
    );
    let key = tls(&r.profiles[1])
        .reality
        .as_ref()
        .and_then(Reality::mldsa65_key);
    assert_eq!(key, Some(pqv.as_str()));
}

/// sing-box has neither check: the emitter refuses such a key with its visible reason instead
/// of running it without the check. Blank values are unset.
#[test]
fn sing_box_refuses_both() {
    let named = ok(&format!(
        "vless://{ID}@h.example:443?security=tls&sni=white.example&vcn=real.example#N"
    ));
    let pq = ok(&format!(
        "vless://{ID}@h.example:443?security=reality&pbk={PBK}&pqv={}#R",
        pqv()
    ));
    let policy = EmitPolicy::default();
    let refused = |p: &Profile| emit_singbox(p, "proxy", &policy).err();
    assert_eq!(
        refused(&named),
        Some(EmitError::XrayOnly("verifyPeerCertByName"))
    );
    assert_eq!(refused(&pq), Some(EmitError::XrayOnly("mldsa65Verify")));
    let mut blank = named.clone();
    if let Some(t) = blank.tls.as_mut() {
        t.verify_peer_cert_by_name = Some(" ".into());
    }
    assert_eq!(refused(&blank), None);
}

/// Only the V2Ray-family links define `vcn` / `pqv`: another scheme cannot carry them.
#[test]
fn other_schemes_cannot_carry_them() {
    let mut hy2 = ok("hysteria2://secret@hy2.example:443?sni=white.example#H");
    hy2.source = Source::Json;
    assert!(export_uri(&hy2).is_some());
    if let Some(t) = hy2.tls.as_mut() {
        t.verify_peer_cert_by_name = Some("real.example".into());
    }
    assert_eq!(export_uri(&hy2), None);
}
