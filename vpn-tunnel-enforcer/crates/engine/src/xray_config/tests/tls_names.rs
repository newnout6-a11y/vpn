//! Xray 26 TLS checks (re-check item 5): `verifyPeerCertByName` (`vcn`) and REALITY
//! `mldsa65Verify` (`pqv`) go from the share link through the engine choice into the Xray
//! config exactly as stored, and the bundled Xray accepts them (AT-04-002 link -> core config;
//! AT-00-004 engine choice). Synthetic names and keys only.
use serde_json::{Value, json};
use vpnte_base::types::{ClientDevice, Engine, EnginePref};
use vpnte_profiles::model::{Profile, Tls, Transport};
use vpnte_profiles::uri::parse_uri;

use super::config::endpoint;
use super::*;
use crate::test_support::xray_check;
use crate::xray_config::{
    Decision, Reject, SelectReason, SingBoxOnly, XrayConfigError, build_config, proxy_graph,
    select_engine, translate,
};

/// A synthetic ML-DSA-65 public key: 1952 bytes of 0x02 as unpadded base64url.
fn pqv() -> String {
    format!("{}AgI", "AgIC".repeat(650))
}

fn link(line: &str) -> Profile {
    parse_uri(line).unwrap_or_else(|e| panic!("{line}: {e:?}"))
}

/// A Trojan TLS key whose certificate is checked against `real.example` behind a whitelisted
/// SNI; `insecure` is what a provider adds for clients that predate `vcn`.
fn named(insecure: bool) -> Profile {
    let flag = if insecure { "&allowInsecure=1" } else { "" };
    link(&format!(
        "trojan://{PW}@nl.example:443?sni=white.example&vcn=real.example,alt.example{flag}#N"
    ))
}

fn pq() -> Profile {
    link(&format!(
        "vless://{UUID}@nl.example:443?security=reality&sni=yahoo.com&pbk={PBK}&sid={SID}&fp=chrome&pqv={}#R",
        pqv()
    ))
}

fn stream_of(p: &Profile) -> Value {
    translate(p, ClientDevice::Pc).expect("translates")["streamSettings"].clone()
}

/// The checks are Xray's alone: Auto and forced Xray pick it, forced sing-box gets the usual
/// refusal instead of a run without the check.
#[test]
fn checks_need_xray() {
    for p in [named(false), named(true), pq()] {
        let xray = Decision::Selected {
            engine: Engine::Xray,
            reason: SelectReason::XrayTransport,
        };
        assert_eq!(select_engine(&p, EnginePref::Auto), xray, "{}", p.name);
        assert_eq!(select_engine(&p, EnginePref::Xray), xray, "{}", p.name);
        assert_eq!(
            select_engine(&p, EnginePref::SingBox),
            Decision::Rejected(Reject::XrayTransport),
            "{}",
            p.name
        );
    }
}

/// `insecure` stays refused on its own; next to names the CA check stays on (against those
/// names), so the flag is not needed and never written.
#[test]
fn names_cover_an_insecure_flag() {
    let s = stream_of(&named(true));
    assert_eq!(
        s["tlsSettings"],
        json!({"serverName": "white.example", "fingerprint": "chrome",
               "verifyPeerCertByName": "real.example,alt.example"})
    );
    assert!(!s.to_string().contains("allowInsecure"));
    let bare = Profile {
        tls: Some(Tls {
            insecure: true,
            ..Tls::default()
        }),
        ..profile(trojan())
    };
    assert_eq!(
        translate(&bare, ClientDevice::Pc),
        Err(XrayConfigError::Feature(SingBoxOnly::InsecureWithoutPin))
    );
}

/// REALITY carries the ML-DSA-65 key as `mldsa65Verify`; names never go into REALITY settings.
#[test]
fn reality_carries_the_pq_key() {
    let r = &stream_of(&pq())["realitySettings"];
    assert_eq!(r["mldsa65Verify"], json!(pqv()));
    assert_eq!(r["serverName"], json!("yahoo.com"));
    let mut both = pq();
    if let Some(t) = both.tls.as_mut() {
        t.verify_peer_cert_by_name = Some("real.example".into());
    }
    assert!(
        !stream_of(&both)
            .to_string()
            .contains("verifyPeerCertByName")
    );
}

/// XHTTP `extra` may turn the CA check off next to names, as next to a pin; never alone.
#[test]
fn xhttp_extra_insecure_needs_a_pin_or_names() {
    let with_extra = |tls: Value| {
        let mut p = link(&format!(
            "vless://{UUID}@nl.example:443?security=tls&sni=nl.example&type=xhttp&path=%2Fx#X"
        ));
        let extra = json!({"downloadSettings": {"address": "dl.example", "port": 443,
            "network": "xhttp", "security": "tls", "tlsSettings": tls}});
        if let Some(Transport::Xhttp { extra: e, .. }) = p.transport.as_mut() {
            *e = extra.as_object().cloned();
        }
        translate(&p, ClientDevice::Pc)
    };
    let named = with_extra(json!({"allowInsecure": true, "verifyPeerCertByName": "real.example"}))
        .expect("names verify on their own");
    assert!(!named.to_string().contains("allowInsecure"));
    assert!(with_extra(json!({"allowInsecure": true, "verifyPeerCertByName": " , "})).is_err());
}

/// The bundled Xray 26.11.9 accepts both keys (skipped quietly without `resources/xray.exe`).
/// It refuses a short ML-DSA-65 key, so the key name is one Xray reads: an unknown key would
/// pass unnoticed. `verifyPeerCertByName` takes any text; its name is checked in the source.
#[test]
fn checks_pass_xray_test() {
    for p in [named(false), named(true), pq()] {
        let graph = proxy_graph(&p, ClientDevice::Pc).expect("translates");
        let config = build_config(&graph, &endpoint(20011));
        if let Err(out) = xray_check(&config) {
            panic!("{}: xray refused the config: {out}", p.name);
        }
    }
    let mut short = build_config(
        &proxy_graph(&pq(), ClientDevice::Pc).expect("translates"),
        &endpoint(20012),
    );
    let key = short["outbounds"]
        .as_array_mut()
        .and_then(|o| {
            o.iter_mut()
                .find_map(|o| o.pointer_mut("/streamSettings/realitySettings/mldsa65Verify"))
        })
        .expect("the key is emitted");
    *key = json!("AgIC");
    match xray_check(&short) {
        Ok(false) => {}
        Ok(true) => panic!("xray accepted a short mldsa65Verify"),
        Err(out) => assert!(out.contains("mldsa65Verify"), "{out}"),
    }
}
