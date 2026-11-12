//! Refused requests (security model §3.8: paths, raw JSON, sizes, non-loopback proxies).
use super::*;
use serde_json::json;
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
