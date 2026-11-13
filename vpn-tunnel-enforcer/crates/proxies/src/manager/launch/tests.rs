use serde_json::{Value, json};
use vpnte_base::types::{ClientDevice, EnginePref};
use vpnte_profiles::model::{Host, Reality, Tls, Transport};

use super::*;
use crate::test_support::{self, spoofed, vless};

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

/// Spec external-proxy §7.3 with `resolve_server` (answers faked, no lookup): IPv4 preferred,
/// a last known address is dialed when DNS fails or is poisoned, and a clear error when there
/// is nothing to dial.
#[tokio::test]
async fn resolution_dials_live_or_last_known_addresses() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let found = |addrs: &[&str], last_known| {
        Ok(ServerAddrs {
            addrs: addrs.iter().map(|a| ip(a)).collect(),
            last_known,
        })
    };
    let host = "vpn.example.test";
    let mixed = found(&["2001:db8::1", "203.0.113.7"], false);
    assert_eq!(pick(host, mixed).unwrap(), ip("203.0.113.7"));
    let bridged = found(&["203.0.113.6"], true);
    assert_eq!(pick(host, bridged).unwrap(), ip("203.0.113.6"));
    let poisoned = pick(host, Err(ResolveError::Poisoned)).unwrap_err();
    assert_eq!(
        poisoned,
        ProxyError::Engine("cannot resolve vpn.example.test: the DNS answers were forged".into())
    );
    assert!(pick(host, found(&[], false)).is_err());

    // A literal never reaches a resolver; a block-page literal is refused.
    let names = Names::default();
    assert_eq!(
        names.resolve("203.0.113.8").await.unwrap(),
        ip("203.0.113.8")
    );
    assert!(names.resolve("127.0.0.1").await.is_err());
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
                ..Reality::default()
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

/// ENGINE-GAPS decision 2: a profile the chosen engine cannot run is refused with the
/// selection's own message (kind Validation in the UI), never moved to the other engine and
/// never English text with a raw key; nothing is resolved or built.
#[tokio::test]
async fn engine_refusal_is_its_own_message() {
    let tuic = vpnte_profiles::uri::parse_uri(
        "tuic://00000000-0000-4000-8000-000000000003:fake-password@203.0.113.13:443?sni=example.com#T",
    )
    .unwrap();
    let forced = EngineChoice {
        pref: EnginePref::Xray,
        device: ClientDevice::Pc,
    };
    let err = match prepare(&tuic, 17992, forced, &Names::default()).await {
        Err(err) => err,
        Ok(_) => panic!("forced Xray must refuse TUIC"),
    };
    let ProxyError::Refused(msg) = &err else {
        panic!("{err:?}");
    };
    assert_eq!(msg.key, "engine.xray.reject.noXrayClient");
    let app: vpnte_base::AppError = err.into();
    assert_eq!(app.kind, vpnte_base::ErrorKind::Validation);
}

/// Audit item 18 on the slot path: unelevated the spoof keys leave the slot config with the
/// row's note naming the server; elevated they stay and nothing is said.
#[test]
fn tls_spoof_needs_an_elevated_slot() {
    let emit = || emit_singbox(&spoofed(), PROXY_OUT_TAG, &EmitPolicy::default()).unwrap();
    let tls = |f: &SingBoxFragment| f.outbounds()[0]["tls"].clone();

    let mut kept = emit();
    assert_eq!(gate_spoof(&mut kept, "Spoofed", true), None);
    assert_eq!(tls(&kept)["spoof"], "decoy.example");

    let mut dropped = emit();
    let note = gate_spoof(&mut dropped, "Spoofed", false).expect("a note");
    assert_eq!(
        note,
        Msg::new("proxies.slot.spoofDropped").arg("name", "Spoofed")
    );
    let tls = tls(&dropped);
    assert!(
        tls.get("spoof").is_none() && tls.get("spoof_method").is_none(),
        "{tls}"
    );
    assert_eq!(tls["server_name"], "example.com", "the rest of tls stays");
}

/// The prepared slot config follows this process's rights (CI runs both: the workstation
/// unelevated, the CI job elevated), and the plan carries the note exactly when it dropped.
#[tokio::test]
async fn prepared_slot_config_follows_the_process_rights() {
    let plan = prepare(
        &spoofed(),
        17993,
        EngineChoice::default(),
        &Names::default(),
    )
    .await
    .unwrap();
    let config: Value = serde_json::from_slice(&plan.singbox).unwrap();
    let tls = &config["outbounds"][0]["tls"];
    if is_elevated() {
        assert_eq!(tls["spoof"], "decoy.example");
        assert!(plan.notice.is_none());
    } else {
        assert!(
            tls.get("spoof").is_none() && tls.get("spoof_method").is_none(),
            "{tls}"
        );
        let note = plan.notice.expect("the row's note");
        assert_eq!(note.key, "proxies.slot.spoofDropped");
    }
}
