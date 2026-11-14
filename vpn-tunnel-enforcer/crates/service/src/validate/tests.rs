//! Refused requests (security model §3.8: paths, raw JSON, sizes, non-loopback proxies).
use super::*;
use serde_json::{Value, json};
use vpnte_base::types::{AdaptiveMode, EnginePref, ProxyKind};
use vpnte_tunnel::api::Origin;
use vpnte_winnet::wfp::ExceptionTarget;

fn profile() -> Profile {
    vpnte_profiles::uri::parse_uri("trojan://fake-pass@example.com:443?security=tls#Test")
        .expect("test profile")
}

fn with_upstream(upstream: Upstream) -> TunnelStart {
    TunnelStart {
        upstream,
        routing: RoutingInputs::default(),
        protection: ProtectionSettings::default(),
        adaptive: AdaptiveMode::Baseline,
        engine: EnginePref::Auto,
        origin: Origin::User,
    }
}

fn server(p: Profile) -> TunnelStart {
    with_upstream(Upstream::Server(Box::new(ServerUpstream {
        id: "srv".into(),
        profile: p,
        device: None,
        engine: EnginePref::Auto,
        fresh: false,
        hints: Vec::new(),
    })))
}

fn local(addr: &str) -> TunnelStart {
    with_upstream(Upstream::LocalProxy {
        addr: addr.parse().expect("addr"),
        kind: ProxyKind::Socks5,
    })
}

fn kind(r: AppResult<()>) -> Option<ErrorKind> {
    r.err().map(|e| e.kind)
}

#[test]
fn local_proxy_must_be_loopback() {
    assert!(start(&local("127.0.0.1:10808")).is_ok());
    assert!(start(&local("[::1]:10808")).is_ok());
    assert_eq!(
        kind(start(&local("192.168.1.20:1080"))),
        Some(ErrorKind::Validation)
    );
    assert_eq!(
        kind(start(&local("127.0.0.1:0"))),
        Some(ErrorKind::Validation)
    );
}

#[test]
fn provider_singbox_keys_pass_only_the_allow_list() {
    let mut ok = profile();
    ok.singbox_extra.insert("tls.fragment".into(), json!(true));
    ok.singbox_extra.insert("network".into(), json!("tcp"));
    assert!(start(&server(ok)).is_ok());
    for key in [
        "tls.certificate_path",
        "log",
        "inbounds",
        "detour",
        "bind_interface",
        "tls.key_path",
        "experimental.cache_file",
    ] {
        let mut bad = profile();
        bad.singbox_extra
            .insert(key.into(), json!("C:/Windows/System32/x"));
        assert_eq!(
            kind(start(&server(bad))),
            Some(ErrorKind::Validation),
            "{key}"
        );
    }
    let mut many = profile();
    for i in 0..=MAX_EXTRA {
        many.singbox_extra.insert(format!("k{i}"), json!(1));
    }
    assert!(start(&server(many)).is_err());
}

#[test]
fn texts_and_lists_are_bounded() {
    let mut long = profile();
    long.name = "x".repeat(MAX_TEXT + 1);
    assert!(start(&server(long)).is_err());
    let mut control = server(profile());
    control.routing.split_direct = vec!["a\u{0}b".into()];
    assert!(start(&control).is_err());
    let mut many = server(profile());
    many.routing.split_vpn = vec!["(?i)^x$".into(); MAX_SPLIT + 1];
    assert!(start(&many).is_err());
    let mut fine = server(profile());
    fine.routing.split_vpn = vec![r"(?i)^C:\\Tools\\x\.exe$".into()];
    assert!(start(&fine).is_ok());
    // p-app-split: the app's own exe in the scope is checked like the split lists.
    let mut own = server(profile());
    own.routing.only_listed = Some(vec!["a\u{0}b".into()]);
    assert!(start(&own).is_err());
    own.routing.only_listed = Some(vec!["(?i)^x$".into(); MAX_SPLIT + 1]);
    assert!(start(&own).is_err());
    own.routing.only_listed = Some(vec![r"(?i)^C:\\App\\app\.exe$".into()]);
    assert!(start(&own).is_ok());
}

fn exception(target: ExceptionTarget) -> KillSwitchException {
    KillSwitchException {
        id: "e1".into(),
        target,
        label: "Test".into(),
    }
}

#[test]
fn exceptions_are_revalidated() {
    let settings = |e: KillSwitchException| ProtectionSettings {
        exceptions: vec![e],
        ..ProtectionSettings::default()
    };
    let ip = exception(ExceptionTarget::Ip("10.0.0.0/8".parse().expect("net")));
    assert!(protection(&settings(ip)).is_ok());
    let exe = std::env::current_exe().expect("test exe");
    let app = protection(&settings(exception(ExceptionTarget::App(exe)))).expect("own exe");
    assert!(matches!(app.exceptions[0].target, ExceptionTarget::App(_)));
    for raw in [
        r"\\server\share\tool.exe",
        r"C:\Windows\win.ini",
        r"C:\Windows\..\Windows\notepad.exe",
        "relative.exe",
    ] {
        let target = ExceptionTarget::App(raw.into());
        assert!(protection(&settings(exception(target))).is_err(), "{raw}");
    }
    let dup = ProtectionSettings {
        exceptions: vec![
            exception(ExceptionTarget::Ip("1.2.3.4/32".parse().expect("net"))),
            exception(ExceptionTarget::Ip("1.2.3.4/32".parse().expect("net"))),
        ],
        ..ProtectionSettings::default()
    };
    assert!(protection(&dup).is_err());
}

/// One outbound `p` (Trojan over TLS) with `tls` merged into its `tlsSettings`, as the graph of a
/// profile.
fn native(tls: Value) -> Profile {
    let mut outbound = json!({"tag": "p", "protocol": "trojan",
        "settings": {"servers": [{"address": "192.0.2.1", "port": 443, "password": "SYNTHETIC"}]},
        "streamSettings": {"network": "tcp", "security": "tls",
            "tlsSettings": {"serverName": "front.example.com"}}});
    let settings = &mut outbound["streamSettings"]["tlsSettings"];
    for (key, value) in tls.as_object().expect("tls object") {
        settings[key] = value.clone();
    }
    let graph = json!({"version": 1, "selectedTag": "p", "entry": {"outboundTag": "p"},
        "outbounds": [outbound]});
    let mut p = profile();
    p.native_xray = Some(serde_json::from_value(graph).expect("graph"));
    p
}

/// Review service-b1: Go's JSON decoder folds `ſ` (U+017F) to `s` and the Kelvin sign (U+212A)
/// to `k`, so these keys fill Xray's `masterKeyLog` (a file SYSTEM would create); the full import
/// checks run at the boundary too (an ASCII `MasterKeyLog` is a local file reference).
#[test]
fn provider_xray_keys_are_read_as_a_go_decoder_reads_them() {
    assert!(start(&server(native(json!({})))).is_ok());
    for key in ["ma\u{17f}terKeyLog", "master\u{212a}eyLog", "MasterKeyLog"] {
        let p = native(json!({ key: r"\\10.0.0.66\s\k.log" }));
        assert_eq!(
            kind(start(&server(p))),
            Some(ErrorKind::Validation),
            "{key}"
        );
    }
    // Go keeps the last of two keys equal but for case: "PROTOCOL" would win over "protocol".
    let mut twice = native(json!({}));
    if let Some(graph) = &mut twice.native_xray {
        graph.outbounds[0]["PROTOCOL"] = json!("freedom");
    }
    assert!(start(&server(twice)).is_err());
    let mut observatory = native(json!({}));
    if let Some(graph) = &mut observatory.native_xray {
        graph.observatory = Some(json!({"subjectSelector": ["p"], "probeUrl\u{17f}": "x"}));
    }
    assert!(start(&server(observatory)).is_err());
}

/// The same rule for an XHTTP `extra` and the values of provider sing-box keys.
#[test]
fn provider_json_keys_are_printable_ascii_and_distinct_ignoring_case() {
    let mut xhttp = profile();
    let extra = json!({"downloadSettings": {"tlsSettings": {"ma\u{17f}terKeyLog": "C:/x.log"}}});
    xhttp.transport = Some(Transport::Xhttp {
        host: "front.example.com".into(),
        path: "/x".into(),
        mode: None,
        extra: extra.as_object().cloned(),
    });
    assert!(start(&server(xhttp)).is_err());
    let mut headers = profile();
    headers
        .singbox_extra
        .insert("headers".into(), json!({"Host": "a", "host": "b"}));
    assert!(start(&server(headers)).is_err());
    let mut fine = profile();
    fine.singbox_extra
        .insert("headers".into(), json!({"Host": "a", "X-Id": ["1", "2"]}));
    assert!(start(&server(fine)).is_ok());
}
