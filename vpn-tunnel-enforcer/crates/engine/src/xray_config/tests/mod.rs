//! Tests of the Xray config package: the vectors of the xray-engine spec §7 (engine selection,
//! translation, config) and real `xray run -test` checks of every generated shape.
use serde_json::Map;
use vpnte_profiles::model::{
    DialPrefs, Host, Kind, Profile, Reality, Source, Tls, WgPeer, WireGuard,
};

use crate::test_locales::text;

mod check;
mod config;
mod endpoints;
mod outbounds;
mod resolve;
mod security;
mod select;
mod sniff;
mod translate;
mod warnings;

/// Obvious fakes. The public key is 32 bytes of 0x01 in base64url: well-formed for Xray.
const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PBK: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const SID: &str = "0123abcd";
const PW: &str = "SYNTHETIC_SECRET";
/// 32 bytes of 0x01 in standard base64: a well-formed WireGuard / SS-2022 key.
const KEY32: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
/// A synthetic ECHConfigList: length prefix 4, then 0xfe0d (the ECH version) and two zero bytes.
const ECH_CONFIG: &str = "AAT+DQAA";
/// Throwaway self-signed certificate (no private key anywhere) for the custom-CA mapping.
const CERT_PEM: &str = include_str!("test-cert.pem");

/// A profile for `nl.example:443` with the given protocol and nothing else.
fn profile(kind: Kind) -> Profile {
    Profile {
        name: "test".into(),
        description: None,
        server: Host::Domain("nl.example".into()),
        port: 443,
        kind,
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

fn vless() -> Kind {
    Kind::Vless {
        uuid: UUID.into(),
        flow: None,
        packet_encoding: None,
        encryption: None,
    }
}

fn vmess() -> Kind {
    Kind::Vmess {
        uuid: UUID.into(),
        security: "auto".into(),
        global_padding: false,
        authenticated_length: false,
    }
}

fn trojan() -> Kind {
    Kind::Trojan {
        password: PW.into(),
    }
}

fn shadowsocks(method: &str) -> Kind {
    Kind::Shadowsocks {
        method: method.into(),
        password: PW.into(),
        plugin: None,
        shadowtls: None,
        uot: None,
    }
}

fn hysteria2() -> Kind {
    Kind::Hysteria2 {
        password: PW.into(),
        obfs: None,
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    }
}

/// One peer at `wg.example:51820` with a pre-shared key and WARP-style reserved bytes.
fn wireguard() -> Kind {
    Kind::Wireguard(WireGuard {
        private_key: KEY32.into(),
        local_address: vec![
            "10.0.0.2/32".parse().expect("CIDR"),
            "fd00::2/128".parse().expect("CIDR"),
        ],
        mtu: Some(1280),
        dns: vec!["10.0.0.1".parse().expect("IP")],
        peers: vec![WgPeer {
            host: Host::Domain("wg.example".into()),
            port: 51820,
            public_key: KEY32.into(),
            pre_shared_key: Some(KEY32.into()),
            allowed_ips: vec!["0.0.0.0/0".parse().expect("CIDR")],
            keepalive_s: Some(25),
            reserved: Some([1, 2, 3]),
        }],
    })
}

fn socks() -> Kind {
    Kind::Socks {
        username: Some("user".into()),
        password: Some(PW.into()),
    }
}

fn http() -> Kind {
    Kind::Http {
        username: Some("user".into()),
        password: Some(PW.into()),
    }
}

fn tls(sni: &str) -> Option<Tls> {
    Some(Tls {
        server_name: Some(sni.into()),
        ..Tls::default()
    })
}

fn reality(sni: &str) -> Option<Tls> {
    Some(Tls {
        server_name: Some(sni.into()),
        reality: Some(Reality {
            public_key: PBK.into(),
            short_id: SID.into(),
            spider_x: None,
        }),
        ..Tls::default()
    })
}

fn ip(literal: &str) -> Host {
    Host::Ip(literal.parse().expect("IP literal"))
}

/// The connection reuse every typed XHTTP outbound gets when the provider sets none (ru-2026 R3).
fn default_xmux() -> serde_json::Value {
    serde_json::json!({"maxConnections": "4-6", "cMaxReuseTimes": "64-128",
        "hMaxRequestTimes": "600-900", "hMaxReusableSecs": "1800-3000", "hKeepAlivePeriod": 0})
}

/// Languages of the verbatim-text vectors (`text(RU, key)`).
const RU: &str = "ru";
const EN: &str = "en";
