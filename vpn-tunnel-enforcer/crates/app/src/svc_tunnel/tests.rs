//! Unit tests of the pure parts: connect target resolution, the settings-change decision table
//! and the traffic meter. Nothing here starts an engine, a TUN or touches the system proxy.
use std::time::Duration;

use vpnte_base::types::{KillSwitchLevel, ProxyKind};
use vpnte_core::settings::{ConnectionMode, ProxyOverride, RoutingMode, RuleSetMode, Settings};
use vpnte_tunnel::lifecycle::ConnectTarget;

use super::decide::{Change, Upstream, configured_upstream, connect_target, settings_change};
use super::traffic::Meter;

fn happ() -> Upstream {
    Upstream {
        addr: "127.0.0.1:10808".into(),
        kind: ProxyKind::Socks5,
    }
}

/// AT-02-007 (new): connection mode x routing mode picks the lifecycle target; Soft never turns
/// into Hard and the reverse, and a server connect ignores any proxy.
#[test]
fn connect_target_follows_both_modes() {
    use ConnectionMode::{DirectVpn, LocalProxy};
    use RoutingMode::{Hard, Soft};
    let up = || Some(happ());
    assert_eq!(
        connect_target(DirectVpn, Hard, up()),
        Some(ConnectTarget::DirectVpn { profile_id: None })
    );
    assert_eq!(
        connect_target(DirectVpn, Soft, None),
        Some(ConnectTarget::SoftVpn { profile_id: None })
    );
    let hard = ConnectTarget::LocalProxy {
        addr: "127.0.0.1:10808".into(),
        kind: ProxyKind::Socks5,
    };
    assert_eq!(connect_target(LocalProxy, Hard, up()), Some(hard));
    let soft = ConnectTarget::Soft {
        addr: "127.0.0.1:10808".into(),
        kind: ProxyKind::Socks5,
    };
    assert_eq!(connect_target(LocalProxy, Soft, up()), Some(soft));
}

/// Local-proxy mode without a configured or detected proxy has nothing to start.
#[test]
fn local_proxy_mode_needs_an_upstream() {
    for routing in [RoutingMode::Hard, RoutingMode::Soft] {
        assert_eq!(
            connect_target(ConnectionMode::LocalProxy, routing, None),
            None
        );
    }
}

/// The configured proxy wins over detection and carries the `proxy_type` setting.
#[test]
fn configured_upstream_is_the_override() {
    let mut s = Settings::default();
    assert_eq!(configured_upstream(&s), None);
    let (proxy, _) = ProxyOverride::parse("127.0.0.1:2080").expect("valid proxy");
    s.proxy_override = Some(proxy);
    s.proxy_type = ProxyKind::Http;
    assert_eq!(
        configured_upstream(&s),
        Some(Upstream {
            addr: "127.0.0.1:2080".into(),
            kind: ProxyKind::Http,
        })
    );
}

/// lifecycle-app §3.12 / tunnel-core §2.9: only public Wi-Fi compatibility and stealth restart
/// a running tunnel; nothing changed = nothing to do.
#[test]
fn tunnel_shaping_fields_restart() {
    let old = Settings::default();
    assert_eq!(settings_change(&old, &old), Change::default());
    let mut new = old.clone();
    new.public_wifi_compatibility = !old.public_wifi_compatibility;
    new.stealth_mode = !old.stealth_mode;
    let change = settings_change(&old, &new);
    assert_eq!(change.restart, ["publicWifiCompatibility", "stealthMode"]);
    assert_eq!(change.kill_switch, None);
    assert!(!change.rule_sets);
}

/// The kill switch goes to the protection, never through a restart (old `save-settings`).
#[test]
fn kill_switch_change_goes_to_the_protection() {
    let old = Settings::default();
    let mut new = old.clone();
    new.kill_switch = KillSwitchLevel::Standard;
    let change = settings_change(&old, &new);
    assert_eq!(change.kill_switch, Some(KillSwitchLevel::Standard));
    assert!(change.restart.is_empty());
}

/// Next-connect settings (engine, modes, local proxy, Smart RU maps) and live-read ones
/// (auto-restart) change nothing on a running tunnel.
#[test]
fn next_connect_settings_do_not_restart() {
    let old = Settings::default();
    let mut new = old.clone();
    new.routing_mode = RoutingMode::Soft;
    new.connection_mode = ConnectionMode::DirectVpn;
    new.proxy_type = ProxyKind::Http;
    new.proxy_engine = vpnte_base::types::EnginePref::Xray;
    new.smart_ru_maps_direct = !old.smart_ru_maps_direct;
    new.auto_restart_on_crash = !old.auto_restart_on_crash;
    new.adaptive_bypass = !old.adaptive_bypass;
    assert_eq!(settings_change(&old, &new), Change::default());
}

/// Smart RU / rule-set settings wake the rule-set refresh; the IP check period goes to the
/// monitor.
#[test]
fn rule_set_and_interval_changes() {
    let old = Settings::default();
    let mut new = old.clone();
    new.smart_ru_split = !old.smart_ru_split;
    assert!(settings_change(&old, &new).rule_sets);
    let mut new = old.clone();
    new.smart_ru_rule_set_mode = RuleSetMode::Managed;
    assert!(settings_change(&old, &new).rule_sets);
    let mut new = old.clone();
    new.check_interval_ms = 60_000;
    let change = settings_change(&old, &new);
    assert_eq!(change.check_interval, Some(Duration::from_secs(60)));
    assert!(change.restart.is_empty() && !change.rule_sets);
}

/// Rates come from deltas of the engine totals; the session total survives a new engine run
/// (crash or protected restart: a new endpoint, totals from zero) and an unreadable tick.
#[test]
fn meter_keeps_session_totals_across_runs() {
    let mut m = Meter::new(1_000);
    let s = m.tick(1_000, Some((1_000, 100)), "tun0".into());
    assert_eq!(
        (s.down_bps, s.session_down, s.session_up),
        (0.0, 1_000, 100)
    );
    assert!(s.running && s.adapter_found);
    let s = m.tick(2_000, Some((3_000, 600)), "tun0".into());
    assert_eq!((s.down_bps, s.up_bps), (2_000.0, 500.0));
    assert_eq!((s.session_down, s.peak_down_bps), (3_000, 2_000.0));
    let s = m.tick(3_000, None, "tun0".into());
    assert!(!s.adapter_found);
    assert_eq!((s.session_down, s.session_up), (3_000, 600));
    // Totals fell: the engine restarted without a new endpoint being seen.
    let s = m.tick(4_000, Some((500, 50)), "tun0".into());
    assert_eq!(
        (s.session_down, s.session_up, s.down_bps),
        (3_500, 650, 0.0)
    );
    m.new_run();
    let s = m.tick(5_000, Some((100, 10)), String::new());
    assert_eq!((s.session_down, s.session_up), (3_600, 660));
    assert_eq!(s.started_at_ms, Some(1_000));
}

/// The fragment pair has identical keys, and the keys are exactly the ones this module emits.
#[test]
fn locale_fragments_match_the_code() {
    let keys = |text: &str| -> Vec<String> {
        let doc: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
        let section = doc["app"]["tunnel"]
            .as_object()
            .expect("app.tunnel section");
        assert!(
            section
                .values()
                .all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        );
        section.keys().map(|k| format!("app.tunnel.{k}")).collect()
    };
    let ru = keys(include_str!("../../locales/app-tunnel.ru.json"));
    let en = keys(include_str!("../../locales/app-tunnel.en.json"));
    assert_eq!(ru, en);
    let code = [
        include_str!("ops.rs"),
        include_str!("leaks.rs"),
        include_str!("guard.rs"),
    ]
    .concat();
    let mut used: Vec<String> = code
        .match_indices("\"app.tunnel.")
        .map(|(at, _)| {
            let rest = &code[at + 1..];
            rest[..rest.find('"').expect("closed literal")].to_owned()
        })
        .collect();
    used.sort();
    used.dedup();
    let mut defined = ru;
    defined.sort();
    assert_eq!(used, defined);
}

/// Site-name lookups leave only through a running session: plain requests under the TUN, the
/// mixed inbound (SOCKS5, no credentials) under the proxy capture; idle, nowhere. The setting
/// is carried as is (off = the tick is not running at all).
#[test]
fn site_name_lookups_follow_the_session() {
    use vpnte_core::net::Route;
    use vpnte_tunnel::api::{CaptureKind, ProxyEndpoint, SessionEndpoints, TunStatus};

    use super::domains::enrich_inputs;

    let endpoint = |port| ProxyEndpoint {
        port,
        user: "u".into(),
        pass: "p".into(),
    };
    let running = |capture, proxy_port| TunStatus {
        running: true,
        capture: Some(capture),
        session: Some(SessionEndpoints {
            clash_port: 1,
            clash_secret: "0".repeat(32),
            direct: endpoint(20001),
            probe: None,
            tun_luid: None,
            tun_alias: None,
            proxy_port,
            logs: Vec::new(),
        }),
        ..TunStatus::default()
    };
    let idle = enrich_inputs(true, &TunStatus::default());
    assert!(idle.enabled && idle.route.is_none());
    let tun = enrich_inputs(true, &running(CaptureKind::Tun, None));
    assert_eq!(tun.route, Some(Route::Direct));
    let soft = enrich_inputs(false, &running(CaptureKind::Proxy, Some(20808)));
    assert!(!soft.enabled);
    let Some(Route::Proxy { url }) = soft.route else {
        panic!("the mixed inbound");
    };
    assert_eq!(url.as_str(), "socks5h://127.0.0.1:20808");
    // A proxy capture whose port is not known yet has nowhere to send a lookup.
    assert_eq!(
        enrich_inputs(true, &running(CaptureKind::Proxy, None)).route,
        None
    );
}
