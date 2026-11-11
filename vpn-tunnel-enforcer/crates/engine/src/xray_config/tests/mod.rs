//! Tests of the Xray config package: the vectors of the xray-engine spec §7 (engine selection,
//! translation, config) and real `xray run -test` checks of every generated shape.
use serde_json::Map;
use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Reality, Source, Tls};

use crate::test_locales::text;

mod check;
mod config;
mod endpoints;
mod resolve;
mod security;
mod select;
mod sniff;
mod translate;

/// Obvious fakes. The public key is 32 bytes of 0x01 in base64url: well-formed for Xray.
const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PBK: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const SID: &str = "0123abcd";
const PW: &str = "SYNTHETIC_SECRET";
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

/// Languages of the verbatim-text vectors (`text(RU, key)`).
const RU: &str = "ru";
const EN: &str = "en";
