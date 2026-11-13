use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::model::{DialPrefs, Mux, NativeEntry, NativeXray, Note, Reality, Source};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

fn vless() -> Profile {
    Profile {
        name: "Germany (1)".into(),
        description: None,
        server: Host::Domain("de.example.com".into()),
        port: 443,
        kind: Kind::Vless {
            uuid: UUID.into(),
            flow: None,
            packet_encoding: None,
            encryption: None,
        },
        tls: Some(Tls {
            server_name: Some("front.example.com".into()),
            ..Tls::default()
        }),
        transport: Some(Transport::Ws {
            path: "/ws".into(),
            host: None,
            max_early_data: None,
            early_data_header: None,
        }),
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Default::default(),
        source: Source::Json,
        notes: Vec::new(),
    }
}

fn with(edit: impl FnOnce(&mut Profile)) -> Profile {
    let mut p = vless();
    edit(&mut p);
    p
}

fn reality(p: &mut Profile, key: &str) {
    let reality = Reality {
        public_key: key.into(),
        short_id: "1234".into(),
        spider_x: None,
        ..Reality::default()
    };
    p.tls = Some(Tls {
        reality: Some(reality),
        ..Tls::default()
    });
}

/// Dedupe key (profiles §6.3, §7.3 "identity/dedup"): the same key under another name, with
/// other notes, mux, dial options, fingerprint or ALPN is the same server.
#[test]
fn identity_ignores_presentation_and_client_options() {
    let id = vless().identity();
    let same = [
        with(|p| p.name = "Другое имя".into()),
        with(|p| p.description = Some("text".into())),
        with(|p| p.notes = vec![Note::Unencrypted]),
        with(|p| {
            p.mux = Some(Mux {
                enabled: true,
                padding: true,
                ..Mux::default()
            })
        }),
        with(|p| p.dial.tcp_fast_open = true),
        with(|p| p.source = Source::Uri("vless://…".into())),
        with(|p| {
            let tls = p.tls.as_mut().unwrap();
            tls.fingerprint = Some("firefox".into());
            tls.alpn = vec!["h2".into()];
        }),
        // Spelling variants of the same UUID, host and SNI.
        with(|p| {
            p.kind = Kind::Vless {
                uuid: UUID.to_uppercase(),
                flow: None,
                packet_encoding: None,
                encryption: None,
            }
        }),
        with(|p| p.server = Host::Domain("DE.Example.com.".into())),
        with(|p| p.tls.as_mut().unwrap().server_name = Some("FRONT.example.com".into())),
    ];
    for p in same {
        assert_eq!(p.identity(), id, "{p:?}");
    }
}

#[test]
fn identity_separates_different_keys() {
    let id = vless().identity();
    let other = [
        with(|p| p.port = 8443),
        with(|p| p.server = Host::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        with(|p| {
            p.kind = Kind::Vless {
                uuid: "00000000-0000-4000-8000-000000000002".into(),
                flow: None,
                packet_encoding: None,
                encryption: None,
            }
        }),
        with(|p| {
            p.kind = Kind::Vmess {
                uuid: UUID.into(),
                security: "auto".into(),
                global_padding: false,
                authenticated_length: false,
            }
        }),
        with(|p| p.tls.as_mut().unwrap().server_name = Some("other.example.com".into())),
        with(|p| p.tls = None),
        with(|p| reality(p, "key-a")),
        with(|p| {
            p.transport = Some(Transport::Ws {
                path: "/other".into(),
                host: None,
                max_early_data: None,
                early_data_header: None,
            })
        }),
        with(|p| {
            p.transport = Some(Transport::Grpc {
                service_name: "/ws".into(),
                multi_mode: None,
            })
        }),
        with(|p| p.transport = None),
        with(|p| {
            p.native_xray = Some(NativeXray {
                version: 1,
                selected_tag: "proxy".into(),
                entry: NativeEntry {
                    outbound_tag: Some("proxy".into()),
                    balancer_tag: None,
                },
                outbounds: vec![serde_json::json!({"tag": "proxy", "protocol": "vless"})],
                routing: None,
                observatory: None,
                burst_observatory: None,
                policy: None,
            })
        }),
    ];
    for p in other {
        assert_ne!(p.identity(), id, "{p:?}");
    }
    assert_ne!(
        with(|p| reality(p, "key-a")).identity(),
        with(|p| reality(p, "key-b")).identity()
    );
}

fn hy2(ports: Vec<(u16, u16)>) -> Profile {
    with(|p| {
        p.kind = Kind::Hysteria2 {
            password: "secret".into(),
            obfs: None,
            ports,
            hop_interval_s: None,
            hop_interval_max_s: None,
            up_mbps: None,
            down_mbps: None,
            bbr_profile: None,
        };
        p.transport = None;
    })
}

fn ss(method: &str) -> Profile {
    with(|p| {
        p.kind = Kind::Shadowsocks {
            method: method.into(),
            password: "pass".into(),
            plugin: None,
            shadowtls: None,
            uot: None,
        };
        p.tls = None;
        p.transport = None;
    })
}

#[test]
fn identity_covers_hop_ports_and_cipher() {
    assert_ne!(hy2(vec![]).identity(), hy2(vec![(20000, 30000)]).identity());
    assert_ne!(
        hy2(vec![(20000, 30000)]).identity(),
        hy2(vec![(20000, 30001)]).identity()
    );
    assert_ne!(
        ss("aes-256-gcm").identity(),
        ss("chacha20-ietf-poly1305").identity()
    );
    assert_eq!(ss("aes-256-gcm").identity(), ss("AES-256-GCM").identity());
    // Naive over QUIC dials differently from Naive over HTTP/2: another server entry.
    let naive = |quic| {
        with(|p| {
            p.kind = Kind::Naive {
                username: "u".into(),
                password: "p".into(),
                quic,
                extra_headers: vec![],
                insecure_concurrency: None,
            };
            p.transport = None;
        })
        .identity()
    };
    assert_ne!(naive(false), naive(true));
}

fn graph(outbound: &str) -> [u8; 16] {
    with(|p| {
        p.native_xray = Some(NativeXray {
            version: 1,
            selected_tag: "proxy".into(),
            entry: NativeEntry {
                outbound_tag: Some("proxy".into()),
                balancer_tag: None,
            },
            outbounds: vec![serde_json::from_str(outbound).unwrap()],
            routing: None,
            observatory: None,
            burst_observatory: None,
            policy: None,
        })
    })
    .identity()
}

/// One key in two spellings: an absent SNI is the host (both engines send the address), and a
/// provider graph compares with sorted keys (the workspace's serde_json keeps insertion order).
#[test]
fn identity_reads_defaults_and_graphs_canonically() {
    let no_sni = with(|p| p.tls.as_mut().unwrap().server_name = None);
    let host_sni = with(|p| p.tls.as_mut().unwrap().server_name = Some("DE.example.com.".into()));
    assert_eq!(no_sni.identity(), host_sni.identity());
    assert_ne!(no_sni.identity(), vless().identity());
    assert_eq!(
        graph(r#"{"tag": "proxy", "settings": {"a": 1, "b": [{"c": 1, "d": 2}]}}"#),
        graph(r#"{"settings": {"b": [{"d": 2, "c": 1}], "a": 1}, "tag": "proxy"}"#)
    );
    assert_ne!(
        graph(r#"{"tag": "proxy", "settings": {"a": 1}}"#),
        graph(r#"{"tag": "proxy", "settings": {"a": 2}}"#)
    );
}

/// The identity is persisted to match servers across refreshes: its layout must not drift.
#[test]
fn identity_is_stable() {
    assert_eq!(hex::encode(vless().identity()), GOLDEN_IDENTITY);
}

const GOLDEN_IDENTITY: &str = "3f8bddc3d8b2dbee2be5f3ddf2b015e4";
