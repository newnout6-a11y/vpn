//! Golden shapes through the real `sing-box check` (AT-04-002). The bundled 1.14 binary decodes
//! outbounds with DisallowUnknownFields and builds every TLS / transport client, so an unknown
//! key or a refused combination fails here. It does not dial: uTLS on QUIC passes `check`,
//! which is why `tests` also asserts that structurally.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;

use super::tests::*;
use super::{EmitPolicy, SingBoxFragment, emit_singbox};
use crate::model::{
    Ech, HelloSplit, Hy2Obfs, Kind, Mux, Profile, ShadowTlsLayer, Span, SsPlugin, Tls, TlsTricks,
    Transport,
};

/// The bundled engine; `None` (tests skip quietly) when it is not on this machine.
pub(crate) fn sing_box() -> Option<PathBuf> {
    let exe = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../resources/sing-box.exe"
    ));
    exe.is_file().then_some(exe)
}

/// `exe args…` without a console window.
pub(super) fn command(exe: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(exe);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Wraps `fragment` into a minimal config and runs `sing-box check -c stdin`; the error carries
/// the engine's message and the config.
pub(crate) fn check(exe: &Path, fragment: &SingBoxFragment) -> Result<(), String> {
    let first = fragment
        .outbounds()
        .first()
        .or(fragment.endpoints().first());
    let tag = first
        .and_then(|v| v.get("tag"))
        .and_then(Value::as_str)
        .unwrap_or("proxy-out");
    let mut outbounds = fragment.outbounds().to_vec();
    outbounds.push(json!({ "type": "direct", "tag": "direct-out" }));
    let mut config = json!({
        "log": { "level": "error" },
        "dns": { "servers": [{ "type": "udp", "tag": "dns-bootstrap", "server": "1.1.1.1" }] },
        "outbounds": outbounds,
        "route": { "final": tag },
    });
    if !fragment.endpoints().is_empty() {
        config["endpoints"] = json!(fragment.endpoints());
    }
    let mut child = command(exe, &["check", "-c", "stdin", "--disable-color"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // stdin is closed at the end of the arm; the child is always reaped.
    let written = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(config.to_string().as_bytes()),
        None => Ok(()),
    };
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    match written {
        Ok(()) if out.status.success() => Ok(()),
        written => Err(format!(
            "{written:?} {}\n{config:#}",
            String::from_utf8_lossy(&out.stderr)
        )),
    }
}

fn with_tls(mut p: Profile, tls: Tls) -> Profile {
    p.tls = Some(tls);
    p
}

/// TLS with the key's own tricks (item 18).
fn tricky(tricks: TlsTricks) -> Tls {
    Tls {
        tricks: Some(tricks),
        ..tls("front.example.com")
    }
}

/// A provider's own split: other lengths, a pause range.
fn hello_split() -> HelloSplit {
    HelloSplit {
        len: Span::new(40, 60),
        interval_ms: Span::new(30, 50),
    }
}

fn with_transport(mut p: Profile, t: Transport) -> Profile {
    p.transport = Some(t);
    p
}

fn ws() -> Transport {
    Transport::Ws {
        path: "/ws".into(),
        host: Some("cdn.example.com".into()),
        max_early_data: Some(2048),
        early_data_header: Some("Sec-WebSocket-Protocol".into()),
    }
}

fn grpc() -> Transport {
    Transport::Grpc {
        service_name: "TunService".into(),
        multi_mode: None,
    }
}

fn reality_tls() -> Tls {
    Tls {
        reality: Some(reality()),
        fingerprint: Some("firefox".into()),
        ..tls("www.example.com")
    }
}

fn ech_tls() -> Tls {
    let url_safe = ECH_B64
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned();
    Tls {
        ech: Some(Ech {
            config_lines: vec![url_safe],
            query_server_name: Some("cloudflare-ech.com".into()),
        }),
        ..tls("front.example.com")
    }
}

/// Every protocol / transport / TLS combination the emitter produces, with the policy to use.
fn cases() -> Vec<(&'static str, Profile, EmitPolicy)> {
    let plain = EmitPolicy::default();
    let stealth = EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let android = EmitPolicy {
        device: Some(ClientDevice::Android),
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let resolver = EmitPolicy {
        domain_resolver: Some("dns-bootstrap".into()),
        ..EmitPolicy::default()
    };
    let mux = Mux {
        enabled: true,
        protocol: Some("h2mux".into()),
        max_connections: Some(4),
        padding: true,
        brutal: Some((50, 100)),
    };
    let vision = {
        let mut p = vless("reality.example.com");
        p.kind = Kind::Vless {
            uuid: UUID.into(),
            // Normalised by the emitter: sing-box refuses both forms verbatim.
            flow: Some("xtls-rprx-vision-udp443".into()),
            packet_encoding: Some("XUDP".into()),
            encryption: None,
        };
        with_tls(p, reality_tls())
    };
    let mut cases = vec![
        ("vless plain", vless("192.0.2.1"), plain.clone()),
        (
            "vless tls stealth",
            with_tls(vless("v.example.com"), tls("v.example.com")),
            stealth.clone(),
        ),
        ("vless reality vision", vision, android.clone()),
        // Item 18: each shape of the TLS tricks a key can carry, on sing-box 1.14.
        (
            "trojan tricks record",
            with_tls(trojan("t.example.com"), tricky(TlsTricks::Record)),
            plain.clone(),
        ),
        (
            "vless tricks hello",
            with_transport(
                with_tls(
                    vless("v.example.com"),
                    tricky(TlsTricks::Hello(hello_split())),
                ),
                ws(),
            ),
            plain.clone(),
        ),
        (
            "vless tricks both",
            with_tls(vless("v.example.com"), tricky(TlsTricks::STRONG)),
            plain.clone(),
        ),
        (
            "vless reality grpc",
            with_transport(with_tls(vless("r.example.com"), reality_tls()), grpc()),
            plain.clone(),
        ),
        (
            "vless ws tls",
            with_transport(
                with_tls(vless("v.example.com"), tls("cdn.example.com")),
                ws(),
            ),
            stealth.clone(),
        ),
        (
            "vless httpupgrade",
            with_transport(
                with_tls(vless("v.example.com"), tls("v.example.com")),
                Transport::HttpUpgrade {
                    host: "cdn.example.com".into(),
                    path: "/up".into(),
                },
            ),
            plain.clone(),
        ),
        (
            "vless http",
            with_transport(
                with_tls(vless("v.example.com"), tls("v.example.com")),
                Transport::Http {
                    hosts: vec!["a.example.com".into()],
                    path: "/h".into(),
                },
            ),
            plain.clone(),
        ),
        (
            "vless quic",
            with_transport(
                with_tls(
                    vless("v.example.com"),
                    Tls {
                        fingerprint: Some("chrome".into()),
                        ..tls("v.example.com")
                    },
                ),
                Transport::Quic,
            ),
            stealth.clone(),
        ),
        (
            "vmess ws",
            with_transport(with_tls(vmess("m.example.com"), tls("m.example.com")), ws()),
            android.clone(),
        ),
        ("vmess plain", vmess("2001:db8::10"), plain.clone()),
        (
            "trojan tls ech",
            with_tls(trojan("t.example.com"), ech_tls()),
            stealth.clone(),
        ),
        (
            "trojan grpc",
            with_transport(
                with_tls(trojan("t.example.com"), tls("t.example.com")),
                grpc(),
            ),
            plain.clone(),
        ),
        (
            "vmess grpc gun",
            with_transport(
                with_tls(vmess("m.example.com"), tls("m.example.com")),
                Transport::Grpc {
                    service_name: "TunService".into(),
                    multi_mode: Some(false),
                },
            ),
            plain.clone(),
        ),
        (
            "trojan insecure pins",
            with_tls(
                trojan("t.example.com"),
                Tls {
                    insecure: true,
                    alpn: vec!["h2".into(), "http/1.1".into()],
                    spki_pin_sha256: vec!["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into()],
                    min_version: Some("1.2".into()),
                    ..tls("t.example.com")
                },
            ),
            resolver.clone(),
        ),
        ("ss aead", ss("aes-256-gcm", "pass"), plain.clone()),
        (
            "ss 2022",
            ss("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA=="),
            plain.clone(),
        ),
        ("hy2 default", hy2("hy2.example.com"), stealth.clone()),
        (
            "hy2 insecure alpn",
            with_tls(
                hy2("192.0.2.2"),
                Tls {
                    insecure: true,
                    alpn: vec!["h3".into()],
                    ..tls("s.example.com")
                },
            ),
            plain.clone(),
        ),
        (
            "hy2 insecure public-key pin",
            with_tls(
                hy2("192.0.2.3"),
                Tls {
                    insecure: true,
                    cert_pin_sha256: Some("ab".repeat(32)),
                    spki_pin_sha256: vec!["47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into()],
                    ..tls("s.example.com")
                },
            ),
            plain.clone(),
        ),
        (
            "tuic",
            with_tls(tuic("tuic.example.com"), tls("front.example.com")),
            stealth.clone(),
        ),
        ("naive", naive("naive.example.com"), stealth.clone()),
        (
            "naive ech",
            with_tls(naive("naive.example.com"), ech_tls()),
            plain.clone(),
        ),
        (
            "anytls",
            with_tls(anytls("any.example.com"), tls("front.example.com")),
            stealth.clone(),
        ),
        (
            "socks",
            profile(
                "127.0.0.1",
                1080,
                Kind::Socks {
                    username: Some("u".into()),
                    password: Some("p".into()),
                },
            ),
            plain.clone(),
        ),
        (
            "http plain",
            profile(
                "proxy.example.com",
                8080,
                Kind::Http {
                    username: Some("u".into()),
                    password: Some("p".into()),
                },
            ),
            resolver.clone(),
        ),
        (
            "http tls",
            with_tls(
                profile(
                    "proxy.example.com",
                    443,
                    Kind::Http {
                        username: None,
                        password: None,
                    },
                ),
                tls("proxy.example.com"),
            ),
            stealth.clone(),
        ),
        (
            "wireguard lone",
            wireguard(vec![peer("203.0.113.5", &[])]),
            plain.clone(),
        ),
        (
            "wireguard multi",
            wireguard(vec![
                peer("wg.example.com", &["0.0.0.0/0"]),
                peer("2001:db8::1", &["fd00::/8"]),
            ]),
            resolver.clone(),
        ),
    ];
    for (name, base) in [
        ("vless mux", vless("v.example.com")),
        ("vmess mux", vmess("m.example.com")),
        (
            "trojan mux",
            with_tls(trojan("t.example.com"), tls("t.example.com")),
        ),
        ("ss mux", ss("aes-128-gcm", "p")),
    ] {
        let mut p = base;
        p.mux = Some(mux.clone());
        cases.push((name, p, plain.clone()));
    }
    cases.extend(protocol_knobs());
    cases
}

/// Protocol knobs, dial preferences, pasted extras and the ShadowTLS chain.
fn protocol_knobs() -> Vec<(&'static str, Profile, EmitPolicy)> {
    let plain = EmitPolicy::default();
    let stealth = EmitPolicy {
        tls_compat: true,
        ..EmitPolicy::default()
    };
    let resolver = EmitPolicy {
        domain_resolver: Some("dns-bootstrap".into()),
        ..EmitPolicy::default()
    };
    let mut hop = hy2("hy2.example.com");
    hop.kind = Kind::Hysteria2 {
        password: "secret".into(),
        obfs: Some(Hy2Obfs {
            kind: "salamander".into(),
            password: "pepper".into(),
        }),
        ports: vec![(8443, 8450), (9443, 9443)],
        hop_interval_s: Some(30),
        hop_interval_max_s: Some(60),
        up_mbps: Some(80),
        down_mbps: Some(200),
        bbr_profile: Some("aggressive".into()),
    };
    hop.singbox_extra.insert("network".into(), json!("tcp"));
    hop.singbox_extra
        .insert("disable_chrome_parrot".into(), json!(true));
    let mut gecko = hy2("hy2.example.com");
    gecko.kind = Kind::Hysteria2 {
        password: "secret".into(),
        obfs: Some(Hy2Obfs {
            kind: "gecko".into(),
            password: "pepper".into(),
        }),
        ports: Vec::new(),
        hop_interval_s: None,
        hop_interval_max_s: None,
        up_mbps: None,
        down_mbps: None,
        bbr_profile: None,
    };
    gecko
        .singbox_extra
        .insert("obfs.min_packet_size".into(), json!(600));
    let mut tuic_full = tuic("tuic.example.com");
    tuic_full.kind = Kind::Tuic {
        uuid: UUID.into(),
        password: "secret".into(),
        congestion: Some("cubic".into()),
        udp_relay_mode: Some("quic".into()),
        zero_rtt: true,
        heartbeat_s: Some(10),
    };
    let mut naive_quic = naive("naive.example.com");
    naive_quic.kind = Kind::Naive {
        username: "user".into(),
        password: "pass".into(),
        quic: true,
        extra_headers: vec![("X-Pad".into(), "1".into())],
        insecure_concurrency: Some(2),
    };
    naive_quic.singbox_extra.insert(
        "udp_over_tcp".into(),
        json!({ "enabled": true, "version": 2 }),
    );
    let mut idle = with_tls(anytls("any.example.com"), tls("front.example.com"));
    idle.kind = Kind::Anytls {
        password: "secret".into(),
        idle_check_s: Some(30),
        idle_timeout_s: Some(60),
        min_idle: Some(2),
    };
    idle.dial.tcp_fast_open = true;
    let ss_kind = |plugin: Option<SsPlugin>, shadowtls: Option<ShadowTlsLayer>, uot: Option<u8>| {
        Kind::Shadowsocks {
            method: "2022-blake3-aes-128-gcm".into(),
            password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
            plugin,
            shadowtls,
            uot,
        }
    };
    let obfs = SsPlugin {
        name: "obfs-local".into(),
        opts: "obfs=http;obfs-host=example.com".into(),
    };
    let v2ray = SsPlugin {
        name: "v2ray-plugin".into(),
        opts: "mode=websocket;host=example.com;path=/ws;tls".into(),
    };
    let layer = |version: u8| ShadowTlsLayer {
        version,
        password: "st-pass".into(),
        server_name: "front.example.com".into(),
    };
    let ss_with = |kind: Kind| {
        let mut p = ss("aes-128-gcm", "p");
        p.kind = kind;
        p
    };
    let mut chain_mux = ss_with(ss_kind(None, Some(layer(3)), Some(2)));
    chain_mux.mux = Some(Mux {
        enabled: true,
        protocol: Some("smux".into()),
        ..Mux::default()
    });
    let mut dial = with_transport(
        with_tls(vmess("m.example.com"), tls("m.example.com")),
        grpc(),
    );
    dial.kind = Kind::Vmess {
        uuid: UUID.into(),
        security: "chacha20-poly1305".into(),
        global_padding: true,
        authenticated_length: true,
    };
    dial.dial = crate::model::DialPrefs {
        connect_timeout_s: Some(5),
        tcp_fast_open: true,
        tcp_multi_path: true,
        udp_fragment: Some(true),
        dns_strategy: Some("prefer_ipv4".into()),
    };
    let mut extras = with_tls(vless("v.example.com"), tls("v.example.com"));
    extras.mux = Some(Mux {
        enabled: true,
        ..Mux::default()
    });
    for (key, value) in [
        ("tls.fragment", json!(true)),
        ("tls.fragment_fallback_delay", json!("300ms")),
        ("tls.curve_preferences", json!(["X25519"])),
        ("multiplex.min_streams", json!(4)),
        ("network", json!("tcp")),
        ("bind_interface", json!("Ethernet")),
        ("tls.certificate_path", json!("C:/nowhere.pem")),
    ] {
        extras.singbox_extra.insert(key.into(), value);
    }
    vec![
        ("hy2 hopping obfs", hop, stealth.clone()),
        ("hy2 gecko", gecko, plain.clone()),
        ("tuic full", tuic_full, plain.clone()),
        ("naive quic", naive_quic, plain.clone()),
        ("anytls idle tfo", idle, stealth.clone()),
        (
            "ss obfs-local",
            ss_with(ss_kind(Some(obfs), None, None)),
            plain.clone(),
        ),
        (
            "ss v2ray-plugin",
            ss_with(ss_kind(Some(v2ray), None, Some(1))),
            plain.clone(),
        ),
        (
            "ss shadowtls v3",
            ss_with(ss_kind(None, Some(layer(3)), None)),
            stealth.clone(),
        ),
        (
            "ss shadowtls v2 resolver",
            ss_with(ss_kind(None, Some(layer(2)), None)),
            resolver.clone(),
        ),
        ("ss shadowtls mux uot", chain_mux, plain.clone()),
        ("vmess grpc dial", dial, resolver),
        ("vless extras", extras, stealth),
        (
            "trojan httpupgrade",
            with_transport(
                with_tls(trojan("192.0.2.3"), tls("t.example.com")),
                Transport::HttpUpgrade {
                    host: String::new(),
                    path: String::new(),
                },
            ),
            plain,
        ),
    ]
}

/// sing-box parses WireGuard keys at construction: give the matrix real-looking (fake) keys.
fn valid_wireguard_keys(p: &mut Profile) {
    if let Kind::Wireguard(wg) = &mut p.kind {
        wg.private_key = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".into();
        for peer in &mut wg.peers {
            peer.public_key = "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=".into();
            peer.pre_shared_key = Some("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=".into());
            peer.keepalive_s = Some(25);
            peer.reserved = Some([1, 2, 3]);
        }
        wg.mtu = Some(1280);
    }
}

/// AT-04-002: every emitted shape passes the bundled sing-box 1.14 `check`; no hysteria2 /
/// tuic / QUIC-transport outbound carries uTLS (`check` cannot see that dial failure).
#[test]
fn every_shape_passes_sing_box_check() {
    let Some(exe) = sing_box() else { return };
    let mut failures = Vec::new();
    for (name, mut p, policy) in cases() {
        valid_wireguard_keys(&mut p);
        let fragment =
            emit_singbox(&p, "proxy-out", &policy).unwrap_or_else(|e| panic!("{name}: {e}"));
        for o in fragment.outbounds() {
            let quic = matches!(o["type"].as_str(), Some("hysteria2" | "tuic"))
                || o["transport"]["type"] == "quic";
            assert!(
                !(quic && o["tls"].get("utls").is_some()),
                "{name}: uTLS on QUIC"
            );
        }
        if let Err(e) = check(&exe, &fragment) {
            failures.push(format!("{name}: {e}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

/// The harness itself catches what it must: an unknown key (P-06) and uTLS on naive (P-02).
#[test]
fn check_rejects_what_the_emitter_must_never_write() {
    let Some(exe) = sing_box() else { return };
    let base = json!({ "type": "trojan", "tag": "proxy-out", "server": "t.example.com", "server_port": 443, "password": "p" });
    let mut udp = base.clone();
    udp["udp"] = json!(true);
    assert!(check(&exe, &SingBoxFragment::Outbound(udp)).is_err());
    let naive_utls = json!({ "type": "naive", "tag": "proxy-out", "server": "n.example.com", "server_port": 443,
                             "username": "u", "password": "p",
                             "tls": { "enabled": true, "utls": { "enabled": true, "fingerprint": "chrome" } } });
    assert!(check(&exe, &SingBoxFragment::Outbound(naive_utls)).is_err());
    assert!(check(&exe, &SingBoxFragment::Outbound(base)).is_ok());
}
