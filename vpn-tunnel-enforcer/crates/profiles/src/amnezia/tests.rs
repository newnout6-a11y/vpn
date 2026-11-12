//! AmneziaVPN `vpn://` keys: decoding, containers, the import report. Every key here is built
//! by the test from synthetic data with fake keys.
use std::io::Write;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use serde_json::json;

use super::*;
use crate::deeplink::{DeepLinkError, unwrap_deeplink};
use crate::model::{AwgGeneration, Kind};

const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const PUB: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

/// `vpn://` + base64url(qCompress(text)), as AmneziaVPN's exporter writes it.
fn key(text: &str) -> String {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::new(8));
    z.write_all(text.as_bytes()).expect("compress");
    let mut data = u32::try_from(text.len())
        .expect("small")
        .to_be_bytes()
        .to_vec();
    data.extend(z.finish().expect("compress"));
    format!("vpn://{}", URL_SAFE_NO_PAD.encode(data))
}

/// An AmneziaWG 2.0 client config as AmneziaVPN stores it in `last_config.config`.
fn awg_conf() -> String {
    format!(
        "[Interface]\nAddress = 10.8.1.2/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nPrivateKey = {PRIV}\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 64\nS2 = 76\nS3 = 20\nS4 = 12\nH1 = 100000-200000\nH2 = 300000-400000\nH3 = 500000-600000\nH4 = 700000-800000\nI1 = <r 2><b 0x8580>\n\n[Peer]\nPublicKey = {PUB}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.7:51820\nPersistentKeepalive = 25\n"
    )
}

fn awg_container() -> serde_json::Value {
    let last = json!({ "config": awg_conf(), "hostName": "203.0.113.7", "port": 51820, "mtu": "1376",
        "client_priv_key": PRIV, "server_pub_key": PUB });
    json!({ "container": "amnezia-awg2", "awg": { "port": "51820", "transport_proto": "udp",
        "protocol_version": "2", "last_config": last.to_string() } })
}

fn xray_container() -> serde_json::Value {
    let last = json!({
        "inbounds": [{ "listen": "127.0.0.1", "port": 10808, "protocol": "socks" }],
        "outbounds": [{ "protocol": "vless", "settings": { "vnext": [{ "address": "203.0.113.9", "port": 443,
            "users": [{ "id": "00000000-0000-4000-8000-000000000001", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
            "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "www.example.com", "publicKey": "FAKE-REALITY-PUBLIC-KEY-0000000000000000000",
                "shortId": "ab", "fingerprint": "chrome" } } }]
    });
    json!({ "container": "amnezia-xray", "xray": { "port": "443", "last_config": last.to_string() } })
}

fn document(containers: Vec<serde_json::Value>) -> String {
    json!({ "containers": containers, "defaultContainer": "amnezia-awg2", "description": "Test server",
        "dns1": "1.1.1.1", "dns2": "1.0.0.1", "hostName": "203.0.113.7" })
    .to_string()
}

/// A pasted key unwraps to its server description; the description yields the AmneziaWG
/// profile with the DNS placeholders filled in and the MTU AmneziaVPN keeps beside the config.
#[test]
fn awg_key_imports_as_amneziawg() {
    let inner = unwrap_deeplink(&key(&document(vec![awg_container()])))
        .expect("decodes")
        .expect("a vpn:// key");
    let report = json::parse_json(&serde_json::from_str(&inner).expect("JSON"));
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);
    let [p] = &report.profiles[..] else {
        panic!("{report:?}")
    };
    let Kind::Amneziawg { wg, awg } = &p.kind else {
        panic!("{:?}", p.kind)
    };
    assert_eq!(p.name, "Test server");
    assert_eq!(awg.generation, AwgGeneration::V2_0);
    assert_eq!(
        (awg.jc, awg.s),
        (Some(4), [Some(64), Some(76), Some(20), Some(12)])
    );
    let dns: Vec<String> = wg.dns.iter().map(ToString::to_string).collect();
    assert_eq!(dns, ["1.1.1.1", "1.0.0.1"]);
    assert_eq!((wg.mtu, wg.private_key.as_str()), (Some(1376), PRIV));
    assert_eq!(
        (p.server.to_string(), p.port),
        ("203.0.113.7".to_owned(), 51820)
    );
}

/// Several containers: the importable ones become profiles (the Xray one through the Xray JSON
/// importer), every other one is named in the report, never dropped silently.
#[test]
fn every_container_is_imported_or_named() {
    let cloak = json!({ "container": "amnezia-openvpn-cloak", "cloak": { "port": "443" } });
    let ipsec = json!({ "container": "amnezia-ipsec", "ikev2": {} });
    let admin = json!({ "container": "amnezia-wireguard", "wireguard": { "port": "51820" } });
    let doc = document(vec![awg_container(), cloak, xray_container(), ipsec, admin]);
    let report = parse_payload(&doc);
    let labels: Vec<_> = report.profiles.iter().map(|p| p.kind.label()).collect();
    assert_eq!(labels, ["amneziawg", "vless"]);
    assert!(report.profiles.iter().all(|p| p.name == "Test server"));
    let reasons: Vec<_> = report.skipped.iter().map(|s| &s.reason).collect();
    assert_eq!(
        reasons[0],
        &SkipReason::UnsupportedProtocol("OpenVPN over Cloak".into())
    );
    assert_eq!(
        reasons[1],
        &SkipReason::UnsupportedProtocol("IKEv2 / IPsec".into())
    );
    assert!(
        matches!(reasons[2], SkipReason::Invalid { scheme, detail } if scheme == "vpn" && detail.contains("amnezia-wireguard"))
    );
    assert!(report.skipped.iter().all(|s| s.excerpt == "vpn://…"));
}

/// Amnezia Premium / Free keys need Amnezia's gateway: named, not imported.
#[test]
fn gateway_keys_are_named() {
    let doc =
        json!({ "api_key": "FAKE", "auth_data": { "api_key": "FAKE" }, "name": "Amnezia Free" });
    let report = parse_document(&doc).expect("an AmneziaVPN description");
    assert!(report.profiles.is_empty());
    assert!(
        matches!(&report.skipped[0].reason, SkipReason::UnsupportedProtocol(n) if n.contains("Amnezia Premium"))
    );
    // A `containers` list of something else is no AmneziaVPN description.
    assert_eq!(
        parse_document(&json!({ "containers": [{ "image": "x" }] })),
        None
    );
    assert_eq!(parse_document(&json!({ "containers": [] })), None);
}

/// The payload may be a bare `.conf` (also without `qCompress`), an OpenVPN config or garbage.
#[test]
fn bare_payloads_and_damage() {
    let raw = format!("vpn://{}", URL_SAFE_NO_PAD.encode(awg_conf()));
    let Some(Payload::Text(text)) = decode_key(&raw) else {
        panic!()
    };
    assert_eq!(parse_payload(&text).profiles[0].kind.label(), "amneziawg");
    assert_eq!(
        parse_key(&key(&awg_conf())).map(|p| p.name),
        Ok("AmneziaWG".into())
    );
    let ovpn = key("client\ndev tun\nproto udp\nremote 203.0.113.5 1194\n");
    assert_eq!(
        unwrap_deeplink(&ovpn),
        Err(DeepLinkError::AmneziaUnsupported("OpenVPN".into()))
    );
    assert_eq!(
        parse_key(&ovpn),
        Err(SkipReason::UnsupportedProtocol("OpenVPN".into()))
    );
    let mut cut = key(&document(vec![awg_container()]));
    cut.truncate(cut.len() - 20);
    for damaged in ["vpn://", "vpn://!!!!", cut.as_str()] {
        assert_eq!(
            unwrap_deeplink(damaged),
            Err(DeepLinkError::AmneziaDamaged),
            "{damaged}"
        );
        assert!(matches!(
            parse_key(damaged),
            Err(SkipReason::Invalid { .. })
        ));
    }
    // A length header far beyond the limit is not inflated.
    let mut bomb = (u32::MAX).to_be_bytes().to_vec();
    bomb.extend([0x78, 0x9c, 0x03, 0x00]);
    assert_eq!(q_uncompress(&bomb), None);
    let err = DeepLinkError::AmneziaUnsupported("OpenVPN".into()).msg();
    crate::test_locales::assert_localized(&err.key);
    crate::test_locales::assert_localized(&DeepLinkError::AmneziaDamaged.msg().key);
}

/// A `vpn://` line among other keys is a link candidate: one server comes in, its other
/// containers become notes; a key with several servers asks to be pasted alone.
#[test]
fn key_lines_among_other_keys() {
    let one = key(&document(vec![
        awg_container(),
        json!({ "container": "amnezia-openvpn", "openvpn": {} }),
    ]));
    let text = format!("trojan://pw@t.example:443#t\n{one}\n");
    assert_eq!(crate::text::uri_candidates(&text).len(), 2);
    let p = crate::uri::parse_uri(&one).expect("one server");
    assert_eq!(p.kind.label(), "amneziawg");
    assert_eq!(
        p.notes,
        [crate::model::Note::UnsupportedField("OpenVPN".into())]
    );
    let two = key(&document(vec![awg_container(), xray_container()]));
    assert!(matches!(
        crate::uri::parse_uri(&two),
        Err(SkipReason::Invalid { detail, .. }) if detail.contains("several")
    ));
    assert_eq!(crate::uri::excerpt(&two), "vpn://…");
}
