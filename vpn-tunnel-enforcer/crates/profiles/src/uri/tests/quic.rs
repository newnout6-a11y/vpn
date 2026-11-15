//! Hysteria2 and TUIC (P-01, P-03, P-10).
use super::*;
use crate::model::{Hy2Obfs, Note};

const PIN: &str = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";

struct Hy2<'a> {
    password: &'a str,
    obfs: Option<&'a Hy2Obfs>,
    ports: &'a [(u16, u16)],
    hop: Option<u32>,
    up: Option<u32>,
    down: Option<u32>,
}

fn hy2(profile: &Profile) -> Hy2<'_> {
    match &profile.kind {
        Kind::Hysteria2 {
            password,
            obfs,
            ports,
            hop_interval_s,
            up_mbps,
            down_mbps,
            ..
        } => Hy2 {
            password,
            obfs: obfs.as_ref(),
            ports,
            hop: *hop_interval_s,
            up: *up_mbps,
            down: *down_mbps,
        },
        other => panic!("not hysteria2: {other:?}"),
    }
}

/// §7.1 HY2 advanced.
#[test]
fn hy2_advanced() {
    let p = ok(
        "hy2://secret@hy2.example.com:443?sni=front.example.com&obfs=salamander&obfs-password=pepper&mport=8443-8450&hop_interval=30s&upmbps=80&downmbps=200#HY2",
    );
    let h = hy2(&p);
    assert_eq!(h.password, "secret");
    assert_eq!(
        h.obfs,
        Some(&Hy2Obfs {
            kind: "salamander".into(),
            password: "pepper".into()
        })
    );
    assert_eq!(
        (h.ports, h.hop, h.up, h.down),
        (&[(8443, 8450)][..], Some(30), Some(80), Some(200))
    );
    assert_eq!(
        (p.port, p.name.as_str(), kind_label(&p)),
        (443, "HY2", "hysteria2")
    );
}

/// §7.1 HY2 comma ports.
#[test]
fn hy2_comma_ports() {
    let p = ok("hy2://secret@hy2.example.com:443?mport=8443-8450,9443,10443-10445#HY2");
    assert_eq!(hy2(&p).ports, &[(8443, 8450), (9443, 9443), (10443, 10445)]);
    assert_eq!(p.port, 443);
}

/// P-01: the parser adds no ALPN and no uTLS fingerprint to a QUIC protocol.
#[test]
fn hy2_no_injected_tls_defaults() {
    let tls = ok("hy2://secret@hy2.example.com:443?sni=front.example.com#H")
        .tls
        .expect("tls");
    assert!(tls.alpn.is_empty() && tls.fingerprint.is_none());
    assert_eq!(tls.server_name.as_deref(), Some("front.example.com"));
}

/// P-03: the certificate pin is stored with a note; `insecure` stays as the provider set it.
#[test]
fn hy2_pin_sha256() {
    let p = ok(&format!(
        "hy2://pw@a.example:443?sni=s.example&insecure=1&alpn=h3&obfs=salamander&obfs-password=op&pinSHA256={PIN}#h"
    ));
    let tls = p.tls.clone().expect("tls");
    assert!(tls.insecure);
    assert_eq!(tls.alpn, vec!["h3".to_owned()]);
    assert_eq!(
        tls.cert_pin_sha256,
        Some(PIN.replace(':', "").to_ascii_lowercase())
    );
    assert_eq!(p.notes, vec![Note::CertPinNotEnforced]);
    assert!(is_invalid(&err("hy2://pw@a.example:443?pinSHA256=abcd")));
}

/// P-10: official userpass auth, a port list in the authority, port-only `mport`.
#[test]
fn hy2_userpass_and_authority_ports() {
    assert_eq!(
        hy2(&ok("hysteria2://user:pass@h.example:443?sni=x#a")).password,
        "user:pass"
    );
    let list = ok("hysteria2://secret@h.example:443,20000-30000/?sni=x#b");
    assert_eq!(
        (list.port, hy2(&list).ports),
        (443, &[(443, 443), (20000, 30000)][..])
    );
    let range_only = ok("hy2://s@h.example:20000-30000");
    assert_eq!(
        (range_only.port, hy2(&range_only).ports),
        (20000, &[(20000, 30000)][..])
    );
    let mport_only = ok("hy2://s@h.example?mport=20000:30000,");
    assert_eq!(
        (mport_only.port, hy2(&mport_only).ports),
        (20000, &[(20000, 30000)][..])
    );
    assert_eq!(ok("hy2://s@h.example").port, 443);
    let v6 = ok("hy2://s@[2001:db8::2]:443,5000-6000");
    assert_eq!(
        (v6.server.clone(), hy2(&v6).ports.len()),
        (ip("2001:db8::2"), 2)
    );
    assert!(is_invalid(&err("hy2://s@h.example:443?mport=20000-70000")));
    assert!(is_invalid(&err("hy2://s@h.example:443?mport=500-100")));
}

/// Hop interval: Go durations, bare seconds, Happ `mportHopInt`; garbage is noted, not guessed.
#[test]
fn hy2_hop_interval_and_bandwidth() {
    assert_eq!(
        hy2(&ok("hy2://s@h.example:443?hop_interval=1m")).hop,
        Some(60)
    );
    assert_eq!(
        hy2(&ok("hy2://s@h.example:443?hopInterval=25")).hop,
        Some(25)
    );
    assert_eq!(
        hy2(&ok("hy2://s@h.example:443?mportHopInt=45")).hop,
        Some(45)
    );
    let bad_hop = ok("hy2://s@h.example:443?hop_interval=soon");
    assert_eq!(
        (hy2(&bad_hop).hop, bad_hop.notes.clone()),
        (None, vec![Note::UnsupportedField("hop_interval".into())])
    );
    let bw = ok("hy2://s@h.example:443?up=30%20Mbps&down_mbps=99.6");
    assert_eq!((hy2(&bw).up, hy2(&bw).down), (Some(30), Some(100)));
    let zero = ok("hy2://s@h.example:443?upmbps=0");
    assert_eq!((hy2(&zero).up, zero.notes.len()), (None, 1));
}

#[test]
fn hy2_obfs_rules_and_tls() {
    let gecko = ok("hy2://s@h.example:443?obfs=gecko&obfs-password=p&obfs-min-packet-size=600");
    assert_eq!(hy2(&gecko).obfs.map(|o| o.kind.as_str()), Some("gecko"));
    assert_eq!(
        gecko.notes,
        vec![Note::UnsupportedField("obfs-min-packet-size".into())]
    );
    assert!(is_invalid(&err(
        "hy2://s@h.example:443?obfs=xor&obfs-password=p"
    )));
    assert!(is_invalid(&err("hy2://s@h.example:443?obfs=salamander")));
    assert!(is_invalid(&err(
        "hy2://s@h.example:443?security=reality&pbk=k"
    )));
    // QUIC always runs TLS; a provider fingerprint is kept but flagged.
    let fp = ok("hy2://s@h.example:443?security=none&fp=firefox");
    assert_eq!(
        fp.tls.and_then(|t| t.fingerprint).as_deref(),
        Some("firefox")
    );
    assert_eq!(fp.notes, vec![Note::ProviderFpDroppedOnQuic]);
    assert_eq!(
        err("hy2://hy2.example.com:443?sni=front.example.com#HY2"),
        SkipReason::MissingCredential
    );
    assert!(
        matches!(&ok("hy2://h.example:443?auth=pw").kind, Kind::Hysteria2 { password, .. } if password == "pw")
    );
}

/// §7.1 tuic.
#[test]
fn tuic_vector() {
    let p = ok(
        "tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC",
    );
    let Kind::Tuic {
        uuid,
        password,
        congestion,
        udp_relay_mode,
        zero_rtt,
        heartbeat_s,
    } = &p.kind
    else {
        panic!("not tuic")
    };
    assert_eq!(
        (uuid.as_str(), password.as_str()),
        ("550e8400-e29b-41d4-a716-446655440000", "secret")
    );
    assert_eq!(
        (congestion.as_deref(), udp_relay_mode.as_deref()),
        (Some("bbr"), Some("native"))
    );
    assert_eq!((*zero_rtt, *heartbeat_s), (false, None));
    assert_eq!(
        p.tls.and_then(|t| t.server_name).as_deref(),
        Some("front.example.com")
    );
}

/// TUIC fixes: both credentials required; new keys; `new-reno` normalised.
#[test]
fn tuic_fixes() {
    assert_eq!(
        err("tuic://550e8400-e29b-41d4-a716-446655440000@h.example:443"),
        SkipReason::MissingCredential
    );
    let p = ok(
        "tuic://h.example:443?uuid=U&password=P&allow_insecure=1&disable_sni=1&reduce_rtt=1&heartbeat=10s&congestion_control=new-reno",
    );
    let Kind::Tuic {
        uuid,
        congestion,
        zero_rtt,
        heartbeat_s,
        ..
    } = &p.kind
    else {
        panic!("not tuic")
    };
    assert_eq!(
        (
            uuid.as_str(),
            congestion.as_deref(),
            *zero_rtt,
            *heartbeat_s
        ),
        ("U", Some("new_reno"), true, Some(10))
    );
    let tls = p.tls.expect("tls");
    assert!(tls.insecure && tls.disable_sni);
    assert!(is_invalid(&err("tuic://u:p@h.example")));
}
