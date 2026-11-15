use super::*;
use crate::model::Host;

const PRIV: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
const PUB: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
const PSK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

fn conf(interface_extra: &str, peer_extra: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.8.0.2/24, fd00::2\n{interface_extra}\n[Peer]\nPublicKey = {PUB}\nEndpoint = vpn.example:51820\n{peer_extra}"
    )
}

fn wg(p: &Profile) -> &WireGuard {
    match &p.kind {
        Kind::Wireguard(wg) => wg,
        other => panic!("{other:?}"),
    }
}

/// A wg-quick client config with every common key.
#[test]
fn full_client_config() {
    let text = format!(
        "# exported by a provider\n[Interface]\nPrivateKey = {PRIV}\nAddress = 10.8.0.2/24, fd00::2\nDNS = 1.1.1.1, 2606:4700:4700::1111, corp.example\nMTU = 1380\nListenPort = 51820\n\n[Peer]\nPublicKey = {PUB}\nPresharedKey = {PSK}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\nPersistentKeepalive = 25\n"
    );
    let p = parse_wg_ini(&text)
        .expect("a WireGuard config")
        .expect("valid");
    assert_eq!((p.name.as_str(), p.port), ("WireGuard", 51820));
    assert_eq!(p.server, Host::Domain("vpn.example".into()));
    assert_eq!(p.source, Source::WgIni);
    assert!(p.notes.is_empty(), "{:?}", p.notes);
    let wg = wg(&p);
    assert_eq!(wg.private_key, PRIV);
    let addresses: Vec<String> = wg.local_address.iter().map(ToString::to_string).collect();
    assert_eq!(addresses, ["10.8.0.2/24", "fd00::2/128"]);
    assert_eq!(wg.dns.len(), 2, "the search domain is not a resolver");
    assert_eq!(wg.mtu, Some(1380));
    let peer = &wg.peers[0];
    assert_eq!(
        (peer.public_key.as_str(), peer.pre_shared_key.as_deref()),
        (PUB, Some(PSK))
    );
    assert_eq!((peer.keepalive_s, peer.reserved), (Some(25), None));
    let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
    assert_eq!(allowed, ["0.0.0.0/0", "::/0"]);
}

/// Not a WireGuard config: no `[Interface]` section.
#[test]
fn other_text_is_none() {
    assert_eq!(parse_wg_ini("vless://u@h.example:443#n"), None);
    assert_eq!(parse_wg_ini("[Peer]\nPublicKey = x\n"), None);
    assert_eq!(parse_wg_ini("[Interfaces]\nPrivateKey = x\n"), None);
}

/// AT-04-004 / P-12: case-insensitive keys and sections, bracketed IPv6 endpoint stored
/// unbracketed, WARP `Reserved`, unpadded keys normalised. No AllowedIPs stays empty: the
/// emitter applies K21 (a lone peer carries everything).
#[test]
fn case_ipv6_reserved_and_defaults() {
    let text = format!(
        "[interface]\nprivatekey = {}\naddress = 172.16.0.2\n[PEER]\npublickey = {PUB}\nendpoint = [2001:db8::1]:2408\nreserved = 1,22,33\npersistentkeepalive = off\n",
        PRIV.trim_end_matches('=')
    );
    let p = parse_wg_ini(&text).expect("WireGuard").expect("valid");
    assert_eq!(p.server, Host::Ip("2001:db8::1".parse().unwrap()));
    assert_eq!(p.port, 2408);
    let wg = wg(&p);
    assert_eq!(wg.private_key, PRIV);
    assert_eq!(wg.local_address[0].to_string(), "172.16.0.2/32");
    assert_eq!(wg.peers[0].reserved, Some([1, 22, 33]));
    assert_eq!(wg.peers[0].keepalive_s, None);
    assert!(wg.peers[0].allowed_ips.is_empty());
}

/// Several peers: each keeps its own AllowedIPs; a file where one names none is skipped at
/// import (wg-quick routes nothing to it, and giving it the whole Internet would steal the
/// routes of the others), instead of being stored and refused by the emitter at connect.
#[test]
fn several_peers_keep_their_routes() {
    let text = format!(
        "{}\n[Peer]\nPublicKey = {PUB}\nEndpoint = lan.example:51821\nAllowedIPs = 10.9.0.0/16\n",
        conf("", "AllowedIPs = 0.0.0.0/0\n")
    );
    let p = parse_wg_ini(&text).expect("WireGuard").expect("valid");
    let wg = wg(&p);
    assert_eq!(wg.peers.len(), 2);
    assert_eq!(wg.peers[0].allowed_ips.len(), 1);
    assert_eq!(wg.peers[1].allowed_ips[0].to_string(), "10.9.0.0/16");
    assert_eq!(
        (p.server.to_string(), p.port),
        ("vpn.example".into(), 51820)
    );

    let unrouted = format!(
        "{}\n[Peer]\nPublicKey = {PUB}\nEndpoint = lan.example:51821\n",
        conf("", "AllowedIPs = 0.0.0.0/0\n")
    );
    assert!(matches!(
        parse_wg_ini(&unrouted),
        Some(Err(SkipReason::Invalid { detail, .. })) if detail.contains("AllowedIPs")
    ));
}

/// An AmneziaVPN 3.1 config (AWG keys in `[Interface]`, a keepalive range in `[Peer]`) is an
/// AmneziaWG profile with every parameter kept; nothing becomes a note.
#[test]
fn amnezia_config_is_amneziawg() {
    let interface = [
        "Jc = 5",
        "Jmin = 10",
        "Jmax = 50",
        "S1 = 12",
        "S2 = 12",
        "S3 = 12",
        "S4 = 12",
        "H1 = 1",
        "H2 = 2",
        "H3 = 3",
        "H4 = 4",
        "I1 = <r 2><b 0x8580>",
        "HeaderProtectionKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
        "ContentPaddingAddition = 10-100",
        "RekeyAfterTime = 100-120",
        "RandomTrailers = on",
        "DisableCookies = on",
    ];
    let text = conf(
        &interface.join("\n"),
        "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25-35",
    );
    let p = parse_wg_ini(&text).expect("WireGuard").expect("valid");
    let Kind::Amneziawg { wg, awg } = &p.kind else {
        panic!("{:?}", p.kind)
    };
    assert_eq!(
        (p.name.as_str(), p.kind.label()),
        ("AmneziaWG", "amneziawg")
    );
    assert_eq!(awg.generation, crate::model::AwgGeneration::V3);
    assert_eq!((awg.jc, awg.s), (Some(5), [Some(12); 4]));
    assert_eq!(awg.i[0].as_deref(), Some("<r 2><b 0x8580>"));
    let keepalive = awg.keepalive_range.map(|r| r.to_string());
    assert_eq!(keepalive.as_deref(), Some("25-35"));
    assert_eq!(
        (wg.peers[0].keepalive_s, wg.private_key.as_str()),
        (None, PRIV)
    );
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// Junk packets alone already make AmneziaWG (they are what passes DPI); every mechanism off is
/// plain WireGuard; broken parameters skip the file with every bad field named (AT-12-003).
#[test]
fn amnezia_keys_decide_the_kind() {
    let parse = |extra: &str| parse_wg_ini(&conf(extra, "")).expect("a WireGuard config");
    let junk = parse("Jc = 4\nJmin = 40\nJmax = 70\nH1 = 1").expect("valid");
    assert_eq!(junk.kind.label(), "amneziawg");
    let off = parse("Jc = 0\nS1 = 0\nH1 = 1").expect("valid");
    assert_eq!((off.kind.label(), off.notes.len()), ("wireguard", 0));
    let broken = parse("Jc = 400\nJmin = 90\nJmax = 70\nH1 = 100-200\nH2 = 150");
    let Err(SkipReason::AwgInvalid(invalid)) = broken else {
        panic!("{broken:?}")
    };
    assert_eq!(invalid.names(), "Jc, Jmin, Jmax, H1, H2");
}

/// AT-04-006: keys we cannot apply (hooks, routing table) are reported, not dropped silently;
/// a link pasted after the config is not a key, so no part of it lands in a Note.
#[test]
fn unknown_keys_are_reported() {
    let p = parse_wg_ini(&conf(
        "PostUp = iptables -A FORWARD\nTable = off",
        "Comment = x\nvless://00000000-0000-4000-8000-000000000001@h.example:443?security=tls#n",
    ))
    .expect("WireGuard")
    .expect("valid");
    let expected = [
        Note::UnsupportedField("PostUp".into()),
        Note::UnsupportedField("Table".into()),
        Note::UnsupportedField("Comment".into()),
    ];
    assert_eq!(p.notes, expected);
}

/// Broken configs are typed skips: missing key, bad key, no endpoint, no peer, bad address.
#[test]
fn broken_configs_are_skipped() {
    let missing = parse_wg_ini(
        "[Interface]\nAddress = 10.0.0.2\n[Peer]\nPublicKey = x\nEndpoint = h.example:1\n",
    );
    assert_eq!(missing, Some(Err(SkipReason::MissingCredential)));
    let detail = |text: &str| match parse_wg_ini(text) {
        Some(Err(SkipReason::Invalid { detail, .. })) => detail,
        other => panic!("{other:?}"),
    };
    assert!(detail(&conf("", "").replace(PUB, "not-a-key")).contains("32 bytes"));
    assert!(detail(&conf("", "").replace("Endpoint = vpn.example:51820", "")).contains("Endpoint"));
    assert!(
        detail(&format!(
            "[Interface]\nPrivateKey = {PRIV}\nAddress = 10.0.0.2\n"
        ))
        .contains("[Peer]")
    );
    assert!(detail(&conf("", "").replace("10.8.0.2/24", "10.8.0.300")).contains("Address"));
    assert!(
        detail(&conf("", "").replace("vpn.example:51820", "2001:db8::1:51820"))
            .contains("Endpoint")
    );
}
