use serde_json::json;

use super::*;
use crate::model::{Host, Kind, Note, Source, Transport};

const UUID: &str = "00000000-0000-4000-8000-000000000001";

/// AT-04-004 / P-05: an old URI-parsed REALITY row: brackets go, the invented `chrome` + `h2,http/1.1`
/// defaults go, the provider's REALITY values (incl. `spider_x`) stay.
#[test]
fn old_reality_row() {
    let outbound = json!({ "type": "vless", "tag": "proxy-out", "server": "[2001:db8::1]", "server_port": 443,
        "uuid": UUID, "flow": "xtls-rprx-vision",
        "tls": { "enabled": true, "server_name": "[2001:db8::1]", "alpn": ["h2", "http/1.1"],
                 "utls": { "enabled": true, "fingerprint": "chrome" },
                 "reality": { "enabled": true, "public_key": "PBK-FAKE", "short_id": "", "spider_x": "/x" } } });
    let p = from_legacy("  Old\tname ", "vless", &outbound, None).expect("imports");
    assert_eq!(p.name, "Old name");
    assert_eq!(p.server, Host::Ip("2001:db8::1".parse().expect("ip")));
    let tls = p.tls.expect("tls");
    assert_eq!(tls.server_name.as_deref(), Some("2001:db8::1"));
    assert!(tls.alpn.is_empty() && tls.fingerprint.is_none());
    assert_eq!(tls.reality.and_then(|r| r.spider_x).as_deref(), Some("/x"));
    assert_eq!(p.source, Source::Legacy);
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// Spec §7.1 "caps HY2 tcp" input and the old HY2 shapes: comma-joined ports, bare-second hop
/// interval, float Mbps; the old `network: "tcp"` is dropped (K13).
#[test]
fn old_hysteria2_row() {
    let outbound = json!({ "type": "hysteria2", "server": "hy2.example.com", "server_port": 443, "password": "PW",
        "network": "tcp", "obfs": { "type": "salamander", "password": "pepper" },
        "server_ports": "8443:8450,9443", "hop_interval": "30", "up_mbps": 80.4,
        "tls": { "enabled": true, "server_name": "hy2.example.com", "alpn": ["h2", "http/1.1"],
                 "utls": { "enabled": true, "fingerprint": "firefox" } } });
    let p = from_legacy("HY2", "hysteria2", &outbound, None).expect("imports");
    let Kind::Hysteria2 {
        ports,
        hop_interval_s,
        up_mbps,
        obfs,
        ..
    } = &p.kind
    else {
        panic!()
    };
    assert_eq!(ports, &[(8443, 8450), (9443, 9443)]);
    assert_eq!((*hop_interval_s, *up_mbps), (Some(30), Some(80)));
    assert_eq!(obfs.as_ref().map(|o| o.password.as_str()), Some("pepper"));
    assert!(p.singbox_extra.is_empty(), "{:?}", p.singbox_extra);
    let tls = p.tls.expect("tls");
    assert!(tls.alpn.is_empty(), "forced ALPN breaks HY2 (P-01)");
    assert_eq!(
        tls.fingerprint.as_deref(),
        Some("firefox"),
        "a real provider choice is kept"
    );
}

/// AT-04-002: `alter_id` persisted as `null` (old NaN) is 0 without a Note; 64 gets one.
#[test]
fn vmess_alter_id() {
    let row = |alter: serde_json::Value| json!({ "type": "vmess", "server": "vm.example", "server_port": 443, "uuid": UUID, "security": "auto", "alter_id": alter });
    assert!(
        from_legacy("a", "vmess", &row(json!(null)), None)
            .expect("null")
            .notes
            .is_empty()
    );
    assert_eq!(
        from_legacy("b", "vmess", &row(json!(64)), None)
            .expect("64")
            .notes,
        [Note::AlterIdNormalized(64)]
    );
}

/// P-07: AnyTLS idle values stored in milliseconds (floats possible) become seconds.
#[test]
fn anytls_milliseconds() {
    let outbound = json!({ "type": "anytls", "server": "a.example", "server_port": 443, "password": "P",
        "idle_session_check_interval_ms": 30000, "idle_session_timeout_ms": 1.5, "min_idle_session": 2 });
    let p = from_legacy("A", "anytls", &outbound, None).expect("imports");
    assert_eq!(
        p.kind,
        Kind::Anytls {
            password: "P".into(),
            idle_check_s: Some(30),
            idle_timeout_s: Some(1),
            min_idle: Some(2)
        }
    );
    assert!(p.notes.is_empty(), "{:?}", p.notes);
}

/// Spec §7.2 "legacy XHTTP `method`": Clash imports stored the XHTTP mode under `method`.
#[test]
fn xhttp_mode_under_method() {
    let outbound = json!({ "type": "vless", "server": "x.example", "server_port": 443, "uuid": UUID, "encryption": "none",
        "udp": true, "transport": { "type": "splithttp", "host": "cdn.example", "path": "/x", "method": "stream-up" } });
    let p = from_legacy("X", "vless", &outbound, None).expect("imports");
    assert_eq!(
        p.transport,
        Some(Transport::Xhttp {
            host: "cdn.example".into(),
            path: "/x".into(),
            mode: Some("stream-up".into()),
            extra: None
        })
    );
    assert!(
        p.notes.is_empty(),
        "Clash `udp` / `encryption: none` are not notes: {:?}",
        p.notes
    );
}

/// The embedded Xray graph is kept as the model type; a malformed one refuses the row.
#[test]
fn native_graph() {
    let graph = json!({ "version": 1, "selectedTag": "proxy", "entry": { "balancerTag": "l1" },
        "outbounds": [{ "tag": "proxy", "protocol": "vless" }],
        "routing": { "rules": [], "balancers": [{ "tag": "l1", "selector": ["proxy"] }] } });
    let mut outbound = json!({ "type": "vless", "server": "n.example", "server_port": 443, "uuid": UUID, "vpnte_xray": graph });
    let p = from_legacy(
        "Norway",
        "vless",
        &outbound,
        Some("vless://ignored@n.example:443"),
    )
    .expect("imports");
    let native = p.native_xray.expect("graph kept");
    assert_eq!(
        (
            native.selected_tag.as_str(),
            native.entry.balancer_tag.as_deref()
        ),
        ("proxy", Some("l1"))
    );
    assert!(p.notes.is_empty(), "{:?}", p.notes);
    outbound["vpnte_xray"]["version"] = json!(2);
    assert_eq!(
        from_legacy("N", "vless", &outbound, None),
        Err(LegacyError::InvalidNativeGraph)
    );
}

/// The old WireGuard URI row (legacy outbound shape, bracketed IPv6 endpoint).
#[test]
fn wireguard_row() {
    let outbound = json!({ "type": "wireguard", "tag": "proxy-out", "server": "[2001:db8::1]", "server_port": 51820,
        "private_key": "PRIV", "peer_public_key": "PUB", "pre_shared_key": "PSK", "local_address": ["10.0.0.2"],
        "dns_servers": ["1.1.1.1"], "mtu": 1420, "reserved": [1, 22, 33] });
    let p = from_legacy("", "wireguard", &outbound, None).expect("imports");
    assert_eq!(p.name, "WireGuard");
    let Kind::Wireguard(wg) = &p.kind else {
        panic!()
    };
    assert_eq!(wg.local_address[0].to_string(), "10.0.0.2/32");
    assert_eq!(wg.dns, ["1.1.1.1".parse::<std::net::IpAddr>().expect("ip")]);
    assert_eq!(
        wg.peers[0].host,
        Host::Ip("2001:db8::1".parse().expect("ip"))
    );
    assert_eq!(
        (wg.peers[0].reserved, wg.peers[0].pre_shared_key.as_deref()),
        (Some([1, 22, 33]), Some("PSK"))
    );
}

/// Rows that cannot be imported say why; the AppError carries an i18n key.
#[test]
fn refusals() {
    assert_eq!(
        from_legacy("a", "vless", &json!([]), None),
        Err(LegacyError::NotAnObject)
    );
    assert_eq!(
        from_legacy("a", "sing-box", &json!({ "server": "x" }), None),
        Err(LegacyError::UnsupportedProtocol("sing-box".into()))
    );
    let standalone = json!({ "type": "shadowtls", "server": "s.example", "server_port": 443, "password": "P", "version": 3 });
    assert!(matches!(
        from_legacy("s", "shadowtls", &standalone, None),
        Err(LegacyError::Unusable(_))
    ));
    let err: AppError = LegacyError::UnsupportedProtocol("ssh".into()).into();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    assert_eq!(
        err.user_msg(),
        Msg::new("profiles.legacy.unsupportedProtocol").arg("protocol", "ssh")
    );
}
