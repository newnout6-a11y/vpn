//! WireGuard (P-08, P-12, K21).
use ipnet::IpNet;

use super::*;
use crate::model::{Note, WireGuard};

fn wg(profile: &Profile) -> &WireGuard {
    match &profile.kind {
        Kind::Wireguard(config) => config,
        other => panic!("not wireguard: {other:?}"),
    }
}

fn net(text: &str) -> IpNet {
    text.parse().unwrap()
}

/// §7.1 WG round trip (import side).
#[test]
fn wireguard_vector() {
    let p = ok(
        "wireguard://privateKey@wg.example.com:51820?publicKey=peerKey&psk=sharedKey&address=10.0.0.2%2F32&dns=1.1.1.1&mtu=1420#WG",
    );
    let config = wg(&p);
    assert_eq!(config.private_key, "privateKey");
    assert_eq!(config.local_address, vec![net("10.0.0.2/32")]);
    assert_eq!(
        config.dns,
        vec!["1.1.1.1".parse::<std::net::IpAddr>().unwrap()]
    );
    assert_eq!(config.mtu, Some(1420));
    let peer = &config.peers[0];
    assert_eq!(
        (peer.public_key.as_str(), peer.pre_shared_key.as_deref()),
        ("peerKey", Some("sharedKey"))
    );
    assert_eq!(
        (peer.host.clone(), peer.port),
        (domain("wg.example.com"), 51820)
    );
    assert_eq!(
        (p.server.clone(), p.port, p.name.as_str()),
        (domain("wg.example.com"), 51820, "WG")
    );
    // Allowed IPs stay as given (empty): the emitter applies the full-tunnel default.
    assert!(peer.allowed_ips.is_empty() && p.tls.is_none() && p.notes.is_empty());
}

/// §7.1 "WG in prose": each extracted link (the extraction itself is the text pipeline's).
#[test]
fn wireguard_prose_links() {
    let first = ok(
        "wireguard://cGFzc3dvcmQxMjM=@wg.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.2#MyWG",
    );
    let second = ok(
        "wg://cGFzc3dvcmQxMjM=@wg2.example.com:51820?publicKey=cHVibGljS2V5MTIz&ip=10.0.0.3#WG2",
    );
    assert_eq!((first.name.as_str(), first.port), ("MyWG", 51820));
    assert_eq!((second.name.as_str(), second.port), ("WG2", 51820));
    assert_eq!(wg(&first).private_key, "cGFzc3dvcmQxMjM=");
    assert_eq!(wg(&second).local_address, vec![net("10.0.0.3/32")]);
}

/// P-08: `+` in a query value is literal; a bare address becomes /32.
#[test]
fn plus_is_literal() {
    let p = ok("wireguard://k@wg.example.com:51820?publicKey=ab+cd%2Bef=&ip=10.0.0.2");
    assert_eq!(wg(&p).peers[0].public_key, "ab+cd+ef=");
    assert_eq!(wg(&p).local_address, vec![net("10.0.0.2/32")]);
}

/// P-12: Happ lower-case keys, bracketed IPv6 endpoint stored unbracketed, `reserved`, and the
/// Happ `?serverDescription=` suffix in the name.
#[test]
fn happ_wireguard_link() {
    let p = ok(
        "wireguard://key@[2001:db8::1]:10803?publickey=PUB&address=10.0.0.2&mtu=1500&reserved=1,22,33#title?serverDescription=SGFwcCB0aGUgYmVzdA==",
    );
    assert_eq!((p.server.clone(), p.port), (ip("2001:db8::1"), 10803));
    assert_eq!(p.server.to_string(), "2001:db8::1");
    let config = wg(&p);
    assert_eq!(config.peers[0].public_key, "PUB");
    assert_eq!(config.peers[0].reserved, Some([1, 22, 33]));
    assert_eq!(config.mtu, Some(1500));
    assert_eq!(p.name, "title");
    assert_eq!(p.description.as_deref(), Some("Happ the best"));
}

/// WARP-style options: base64 `reserved`, keepalive, allowed IPs, IPv6 /128, compact form.
#[test]
fn warp_options_and_compact_form() {
    let p = ok(
        "wg://priv:pub@h.example?reserved=AQID&keepalive=25&allowedIPs=0.0.0.0/0,::/0&address=10.0.0.2,fd00::2",
    );
    let config = wg(&p);
    let peer = &config.peers[0];
    assert_eq!(
        (config.private_key.as_str(), peer.public_key.as_str()),
        ("priv", "pub")
    );
    assert_eq!(
        (peer.reserved, peer.keepalive_s, p.port),
        (Some([1, 2, 3]), Some(25), 51820)
    );
    assert_eq!(peer.allowed_ips, vec![net("0.0.0.0/0"), net("::/0")]);
    assert_eq!(
        config.local_address,
        vec![net("10.0.0.2/32"), net("fd00::2/128")]
    );
    assert!(is_invalid(&err("wg://priv:pub@h.example?reserved=1,2")));
    assert!(is_invalid(&err("wg://priv:pub@h.example?reserved=1,2,300")));
    assert!(is_invalid(&err(
        "wg://priv:pub@h.example?address=10.0.0.300"
    )));
}

#[test]
fn missing_keys_and_noted_fields() {
    assert_eq!(
        err("wireguard://wg.example.com:51820?publicKey=p"),
        SkipReason::MissingCredential
    );
    assert_eq!(
        err("wireguard://k@wg.example.com:51820"),
        SkipReason::MissingCredential
    );
    // AmneziaWG: junk packets only (h1 = its default) -> the server still answers plain WireGuard.
    let amnezia = ok("wg://k@h.example?publicKey=p&jc=4&jmin=40&h1=1");
    assert_eq!(
        amnezia.notes,
        vec![Note::Other("profiles.wgIni.amneziaJunkDropped".into())]
    );
    let amnezia = ok("wg://k@h.example?publicKey=p&s1=15&h1=12345");
    assert_eq!(
        amnezia.notes,
        vec![Note::Other("profiles.wgIni.amneziaIncompatible".into())]
    );
    let dns = ok("wg://k@h.example?publicKey=p&dns=1.1.1.1,dns.example&mtu=big");
    assert_eq!(wg(&dns).dns.len(), 1);
    let expected = vec![
        Note::UnsupportedField("mtu".into()),
        Note::UnsupportedField("dns".into()),
    ];
    assert_eq!(dns.notes, expected);
}
