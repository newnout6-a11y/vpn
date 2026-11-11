use serde_json::{Value, json};
use vpnte_base::types::{ClientDevice, EnginePref};
use vpnte_profiles::model::{Host, Reality, Tls, Transport};

use super::*;
use crate::test_support::{self, vless};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

/// Names with `host` already resolved (no lookup happens).
fn names(entries: &[(&str, &str)]) -> Names {
    let names = Names::default();
    for (host, ip) in entries {
        let ip = ip.parse().unwrap();
        names
            .cache
            .lock()
            .insert((*host).into(), (ip, Instant::now()));
    }
    names
}

async fn singbox_config(profile: &Profile, names: &Names) -> Value {
    let plan = prepare(profile, 17990, EngineChoice::default(), names)
        .await
        .unwrap();
    assert!(plan.xray.is_none());
    serde_json::from_slice(&plan.singbox).unwrap()
}

/// Spec external-proxy §7.3 (Rust vectors): a host name endpoint is pinned to the resolved
/// IP with no DNS machinery in the config; the provider SNI stays; an IP endpoint needs no
/// resolution at all.
#[tokio::test]
async fn hostname_endpoints_are_pinned() {
    let mut p = vless("vpn.example.test");
    p.tls = Some(Tls {
        server_name: Some("cdn.example.test".into()),
        ..Tls::default()
    });
    p.dial.dns_strategy = Some("prefer_ipv4".into());
    let original = p.clone();
    let names = names(&[("vpn.example.test", "203.0.113.5")]);
    let config = singbox_config(&p, &names).await;
    let out = &config["outbounds"][0];
    assert_eq!(out["server"], "203.0.113.5");
    assert_eq!(out["tag"], "proxy-out");
    assert_eq!(out["tls"]["server_name"], "cdn.example.test");
    for key in ["domain_strategy", "domain_resolver"] {
        assert!(out.get(key).is_none(), "{key}");
    }
    assert!(config.get("dns").is_none());
    assert!(config["route"].get("default_domain_resolver").is_none());
    assert_eq!(p, original);

    // No SNI of its own: the host name keeps the certificate check; ws gets its Host.
    p.tls = Some(Tls::default());
    p.transport = Some(Transport::Ws {
        path: "/x".into(),
        host: None,
        max_early_data: None,
        early_data_header: None,
    });
    let config = singbox_config(&p, &names).await;
    let out = &config["outbounds"][0];
    assert_eq!(out["tls"]["server_name"], "vpn.example.test");
    assert_eq!(out["transport"]["headers"]["Host"], "vpn.example.test");

    let ip = vless("203.0.113.10");
    let config = singbox_config(&ip, &Names::default()).await;
    assert_eq!(config["outbounds"][0]["server"], "203.0.113.10");
    assert!(config.get("dns").is_none());
}

/// Spec external-proxy §7.3: OS resolver first, DoH when it fails, IPv4 preferred, and a
/// clear error when both fail.
#[tokio::test]
async fn resolution_falls_back_to_doh() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let doh_only =
        |how| async move { (how == How::Doh).then(|| vec!["203.0.113.6".parse().unwrap()]) };
    assert_eq!(
        resolve_with("vpn.example.test", doh_only).await.unwrap(),
        ip("203.0.113.6")
    );
    let none = |_| async { None };
    let err = resolve_with("vpn.example.test", none).await.unwrap_err();
    assert_eq!(
        err,
        ProxyError::Engine("cannot resolve vpn.example.test".into())
    );
    let mixed = |_| async {
        Some(vec![
            "2001:db8::1".parse().unwrap(),
            "203.0.113.7".parse().unwrap(),
        ])
    };
    assert_eq!(
        resolve_with("vpn.example.test", mixed).await.unwrap(),
        ip("203.0.113.7")
    );
    assert!(dialable(ip("198.51.100.1")) && dialable(ip("10.0.0.1")));
    for blocked in [
        "127.0.0.1",
        "0.0.0.0",
        "0.1.2.3",
        "169.254.1.1",
        "255.255.255.255",
        "::",
    ] {
        assert!(!dialable(ip(blocked)), "{blocked}");
    }
}

fn wireguard() -> Profile {
    test_support::wireguard(Host::Ip("203.0.113.20".parse().unwrap()))
}

/// REALITY over VLESS: Xray is preferred (engine selection of the main tunnel). Fake keys.
fn reality() -> Profile {
    Profile {
        tls: Some(Tls {
            server_name: Some("www.example.com".into()),
            fingerprint: Some("chrome".into()),
            reality: Some(Reality {
                public_key: "fakefakefakefakefakefakefakefakefakefakefak".into(),
                short_id: "ab".into(),
                spider_x: None,
            }),
            ..Tls::default()
        }),
        ..vless("203.0.113.30")
    }
}

/// B-28 / B-27: WireGuard runs as a sing-box endpoint; an Xray profile runs behind a SOCKS5
/// bridge to its own Xray child; there is never a `block` outbound and the last rule
/// rejects (B-2).
#[tokio::test]
async fn wireguard_and_xray_shapes() {
    let config = singbox_config(&wireguard(), &Names::default()).await;
    assert_eq!(config["endpoints"][0]["tag"], "proxy-out");
    let outbounds = config["outbounds"].as_array().unwrap();
    assert!(
        outbounds
            .iter()
            .all(|o| o["type"] != "wireguard" && o["type"] != "block")
    );

    let plan = prepare(
        &reality(),
        17991,
        EngineChoice::default(),
        &Names::default(),
    )
    .await
    .unwrap();
    let xray = plan.xray.as_ref().unwrap();
    let config: Value = serde_json::from_slice(&plan.singbox).unwrap();
    let bridge = &config["outbounds"][0];
    let creds = xray.endpoint.creds();
    let expected = json!({
        "type": "socks", "tag": "proxy-out", "version": "5", "server": "127.0.0.1",
        "server_port": xray.endpoint.port(), "username": creds.user, "password": creds.pass,
        "udp_fragment": true,
    });
    assert_eq!(bridge, &expected);
    assert_eq!(
        config["route"]["rules"].as_array().unwrap().last(),
        Some(&json!({ "action": "reject" }))
    );
    let forced = EngineChoice {
        pref: EnginePref::SingBox,
        device: ClientDevice::Android,
    };
    let plan = prepare(&reality(), 17991, forced, &Names::default())
        .await
        .unwrap();
    assert!(plan.xray.is_none());
}

/// AT-02-008: the prepared configs pass the bundled engines' own checks (skipped quietly
/// when the binaries are not present).
#[tokio::test]
async fn prepared_configs_pass_the_engine_checks() {
    let resources = Path::new(RESOURCES);
    let (singbox, xray) = (resources.join("sing-box.exe"), resources.join("xray.exe"));
    if !singbox.exists() || !xray.exists() {
        return;
    }
    for profile in [vless("203.0.113.10"), wireguard(), reality()] {
        let plan = prepare(&profile, 17990, EngineChoice::default(), &Names::default())
            .await
            .unwrap();
        let checked = vpnte_engine::singbox_process::check_config(&singbox, &plan.singbox).await;
        assert!(checked.is_ok(), "{}: {checked:?}", profile.kind.label());
        if let Some(x) = plan.xray {
            let checked = vpnte_engine::xray_process::check_config(&xray, &x.launch.config).await;
            assert!(checked.is_ok(), "xray: {checked:?}");
        }
    }
}
