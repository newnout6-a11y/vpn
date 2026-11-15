//! The outbounds added for the bundled Xray 26.11.9 (ENGINE-GAPS decision 1): Hysteria2,
//! WireGuard, SOCKS, HTTP, plus ECH, SS-2022 UDP-over-TCP and XHTTP connection reuse.
use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Ech, Hy2Obfs, Kind, Mux, Profile, Tls, Transport};

use super::*;
use crate::xray_config::{XrayConfigError, translate};

fn out(p: &Profile) -> Value {
    translate(p, ClientDevice::Pc).expect("translates")
}

fn hy2(edit: impl FnOnce(&mut Kind)) -> Profile {
    let mut kind = hysteria2();
    edit(&mut kind);
    Profile {
        tls: Some(Tls {
            server_name: Some("hy.example".into()),
            insecure: true,
            cert_pin_sha256: Some("ab".repeat(32)),
            ..Tls::default()
        }),
        ..profile(kind)
    }
}

/// Every Hysteria2 knob: salamander, port hopping with a random interval, Brutal bandwidth, the
/// BBR preset (any case) and the certificate pin instead of `insecure`.
#[test]
fn hysteria2_outbound() {
    let p = hy2(|k| {
        if let Kind::Hysteria2 {
            obfs,
            ports,
            hop_interval_s,
            hop_interval_max_s,
            up_mbps,
            down_mbps,
            bbr_profile,
            ..
        } = k
        {
            *obfs = Some(Hy2Obfs {
                kind: "Salamander".into(),
                password: "OBFS".into(),
            });
            *ports = vec![(30000, 20000), (443, 443), (0, 10)];
            (*hop_interval_s, *hop_interval_max_s) = (Some(10), Some(20));
            (*up_mbps, *down_mbps) = (Some(50), Some(0));
            *bbr_profile = Some("Aggressive".into());
        }
    });
    assert_eq!(
        out(&p),
        json!({"tag": "proxy", "protocol": "hysteria",
            "settings": {"version": 2, "address": "nl.example", "port": 443},
            "streamSettings": {"network": "hysteria", "security": "tls",
                "tlsSettings": {"serverName": "hy.example",
                    "pinnedPeerCertSha256": "ab".repeat(32)},
                "hysteriaSettings": {"version": 2, "auth": PW},
                "finalmask": {
                    "udp": [{"type": "salamander", "settings": {"password": "OBFS"}}],
                    "quicParams": {"brutalUp": "50 mbps", "bbrProfile": "aggressive",
                        "udpHop": {"ports": "20000-30000,443", "interval": "10-20"}}}}})
    );
}

/// gecko is salamander with sing-box's packet sizes; a lone short interval is raised to Xray's
/// minimum; no TLS settings still mean TLS (with the server as SNI); a provider ALPN is kept.
#[test]
fn hysteria2_variants() {
    let gecko = hy2(|k| {
        if let Kind::Hysteria2 {
            obfs,
            ports,
            hop_interval_s,
            ..
        } = k
        {
            *obfs = Some(Hy2Obfs {
                kind: "gecko".into(),
                password: "OBFS".into(),
            });
            *ports = vec![(20000, 20010)];
            *hop_interval_s = Some(2);
        }
    });
    let mask = &out(&gecko)["streamSettings"]["finalmask"];
    assert_eq!(
        mask["udp"],
        json!([{"type": "salamander", "settings": {"password": "OBFS", "packetSize": "512-1200"}}])
    );
    assert_eq!(
        mask["quicParams"],
        json!({"udpHop": {"ports": "20000-20010", "interval": 5}})
    );
    let bare = profile(hysteria2());
    let s = &out(&bare)["streamSettings"];
    assert_eq!(s["security"], "tls");
    assert_eq!(s["tlsSettings"], json!({"serverName": "nl.example"}));
    assert!(s.get("finalmask").is_none(), "{s}");
    let alpn = Profile {
        tls: Some(Tls {
            alpn: vec!["h3-29".into()],
            ..Tls::default()
        }),
        ..profile(hysteria2())
    };
    assert_eq!(
        out(&alpn)["streamSettings"]["tlsSettings"]["alpn"],
        json!(["h3-29"])
    );
    let bad_obfs = hy2(|k| {
        if let Kind::Hysteria2 { obfs, .. } = k {
            *obfs = Some(Hy2Obfs {
                kind: "unknown".into(),
                password: "OBFS".into(),
            });
        }
    });
    assert_eq!(
        translate(&bad_obfs, ClientDevice::Pc),
        Err(XrayConfigError::Invalid("obfs"))
    );
}

/// WireGuard: keys, CIDR addresses, peer endpoint (IPv6 bracketed), reserved from the peer and
/// the provider DNS as Xray's in-tunnel resolver.
#[test]
fn wireguard_outbound() {
    let p = profile(wireguard());
    assert_eq!(
        out(&p),
        json!({"tag": "proxy", "protocol": "wireguard", "settings": {
            "secretKey": KEY32, "address": ["10.0.0.2/32", "fd00::2/128"], "mtu": 1280,
            "reserved": [1, 2, 3], "remoteDNS": ["10.0.0.1"],
            "peers": [{"endpoint": "wg.example:51820", "publicKey": KEY32,
                "preSharedKey": KEY32, "keepAlive": 25, "allowedIPs": ["0.0.0.0/0"]}]}})
    );
    let mut v6 = p.clone();
    if let Kind::Wireguard(wg) = &mut v6.kind {
        wg.peers[0].host = ip("2001:db8::1");
        wg.peers[0].reserved = None;
        wg.dns.clear();
    }
    let s = &out(&v6)["settings"];
    assert_eq!(s["peers"][0]["endpoint"], "[2001:db8::1]:51820");
    assert!(
        s.get("reserved").is_none() && s.get("remoteDNS").is_none(),
        "{s}"
    );
}

/// SOCKS and HTTP use Xray's simple form; credentials only with a user name. HTTP over TLS takes
/// the common TLS path (uTLS fingerprint included).
#[test]
fn socks_and_http_outbounds() {
    assert_eq!(
        out(&profile(socks())),
        json!({"tag": "proxy", "protocol": "socks",
            "settings": {"address": "nl.example", "port": 443, "user": "user", "pass": PW},
            "streamSettings": {"network": "tcp", "security": "none"}})
    );
    let anonymous = profile(Kind::Http {
        username: None,
        password: Some(PW.into()),
    });
    assert_eq!(
        out(&anonymous)["settings"],
        json!({"address": "nl.example", "port": 443})
    );
    let https = Profile {
        tls: tls("proxy.example"),
        ..profile(http())
    };
    let v = out(&https);
    assert_eq!(v["protocol"], "http");
    assert_eq!(
        v["streamSettings"],
        json!({"network": "tcp", "security": "tls",
            "tlsSettings": {"serverName": "proxy.example", "fingerprint": "chrome"}})
    );
}

/// A static ECH config reaches `echConfigList` as standard padded base64, from a share link's
/// URL-safe text or a sing-box PEM block; a malformed one is refused before Xray dials.
#[test]
fn ech_config_list() {
    let with_ech = |lines: &[&str]| Profile {
        tls: Some(Tls {
            server_name: Some("front.example".into()),
            ech: Some(Ech {
                config_lines: lines.iter().map(|l| (*l).to_owned()).collect(),
                query_server_name: None,
            }),
            ..Tls::default()
        }),
        ..profile(vless())
    };
    let pem = [
        "-----BEGIN ECH CONFIGS-----",
        "AAT+DQAA",
        "-----END ECH CONFIGS-----",
    ];
    for lines in [&["AAT-DQAA"][..], &["AAT+DQAA"], &pem] {
        let tls = &out(&with_ech(lines))["streamSettings"]["tlsSettings"];
        assert_eq!(tls["echConfigList"], "AAT+DQAA", "{lines:?}");
    }
    // Not base64; and a length prefix that does not match the bytes.
    for bad in ["!!", "AAX+DQAA"] {
        assert_eq!(
            translate(&with_ech(&[bad]), ClientDevice::Pc),
            Err(XrayConfigError::Invalid("ech")),
            "{bad}"
        );
    }
}

/// SS-2022 UDP-over-TCP: version 1 stays 1, anything else is sing-box's default 2.
#[test]
fn shadowsocks_2022_udp_over_tcp() {
    for (version, expected) in [(1, 1), (2, 2), (0, 2)] {
        let mut p = profile(shadowsocks("2022-blake3-aes-256-gcm"));
        if let Kind::Shadowsocks { uot, .. } = &mut p.kind {
            *uot = Some(version);
        }
        let server = &out(&p)["settings"]["servers"][0];
        assert_eq!(server["uot"], true);
        assert_eq!(server["UoTVersion"], expected, "{version}");
    }
}

/// XHTTP gets explicit connection reuse unless the provider set its own, and never mux.cool
/// (the profile's sing-box mux does not leak into Xray's `mux`).
#[test]
fn xhttp_connection_reuse() {
    let xhttp = |extra: Option<Value>| Profile {
        tls: tls("front.example"),
        transport: Some(Transport::Xhttp {
            host: String::new(),
            path: "/x".into(),
            mode: None,
            extra: extra.and_then(|e| e.as_object().cloned()),
        }),
        mux: Some(Mux {
            enabled: true,
            ..Mux::default()
        }),
        ..profile(vless())
    };
    let v = out(&xhttp(None));
    assert_eq!(
        v["streamSettings"]["xhttpSettings"]["extra"],
        json!({"xmux": default_xmux()})
    );
    assert!(v.get("mux").is_none(), "{v}");
    let own = json!({"XMUX": {"maxConcurrency": "16-32"}});
    let v = out(&xhttp(Some(own.clone())));
    assert_eq!(v["streamSettings"]["xhttpSettings"]["extra"], own);
}
