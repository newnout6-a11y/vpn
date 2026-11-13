//! Settings tests: storage spec §7.1 / §7.2 vectors (AT tags in the doc comments).
use serde_json::json;
use vpnte_base::Msg;

use super::*;

fn parse(input: &str) -> Option<(ProxyOverride, Option<ProxyKind>)> {
    ProxyOverride::parse(input).ok()
}

/// B32: one parser for `[scheme://][user[:pass]@]host:port`; also the tunnel-core §7.23 vectors
/// (bootstrapRoute.test.ts) of the user's proxy setting.
#[test]
fn proxy_override_parser() {
    let (p, kind) = parse(" 127.0.0.1:1080 ").unwrap();
    assert_eq!(
        (p.addr.host().to_string(), p.addr.port(), kind),
        ("127.0.0.1".into(), 1080, None)
    );
    assert!(p.credentials.is_none() && p.creds().is_none());

    let (p, kind) = parse("socks5://user:p%40ss@proxy.local:1080/").unwrap();
    assert_eq!(
        (p.addr.to_string(), kind),
        ("proxy.local:1080".into(), Some(ProxyKind::Socks5))
    );
    let creds = p.creds().unwrap();
    assert_eq!((creds.user.as_str(), creds.pass.as_str()), ("user", "p@ss"));

    // The old store fixture: the old split at the last ':' produced host `http://user:<FAKE>@127.0.0.1`.
    let (p, kind) = parse("http://user:<FAKE>@127.0.0.1:8080").unwrap();
    assert_eq!(
        (p.addr.to_string(), kind),
        ("127.0.0.1:8080".into(), Some(ProxyKind::Http))
    );
    assert_eq!(p.creds().unwrap().pass, "<FAKE>");

    let (p, _) = parse("user:pass@Host.Example.:1080").unwrap();
    assert_eq!(
        p.addr.to_string(),
        "host.example:1080",
        "names are normalised"
    );
    let (p, _) = parse("SOCKS5H://[::1]:1080").unwrap();
    assert_eq!(
        (p.addr.host().to_string(), p.addr.to_string()),
        ("::1".into(), "[::1]:1080".into())
    );
    let (p, kind) = parse(" HTTP://localhost:8080").unwrap();
    assert_eq!(
        (p.addr.to_string(), kind),
        ("localhost:8080".into(), Some(ProxyKind::Http))
    );
    let (p, _) = parse("user@host:1").unwrap();
    assert_eq!(p.creds().unwrap().pass, "");
    // An unencoded '@' or ':' in a pasted password still splits at the last '@' and the first ':'.
    assert_eq!(parse("u:p@ss@h:2").unwrap().0.creds().unwrap().pass, "p@ss");
    let (p, _) = parse("socks5://user:p@ss:w@[::1]:1080").unwrap();
    let creds = p.creds().unwrap();
    assert_eq!(
        (creds.user.as_str(), creds.pass.as_str()),
        ("user", "p@ss:w")
    );

    for bad in [
        "",
        "host",
        "bad-port",
        "host:",
        "host:0",
        "host:70000",
        "127.0.0.1:99999",
        "host:+80",
        "127.0.0.1:10808abc",
        "::1:1080",
        "[::1]1080",
        "[nothost]:80",
        "[1.2.3.4]:80",
        "ftp://h:1",
        "https://h:1",
        "socks4://h:1",
        "h:1/path",
        "h:1?q",
        "@h:1",
        "h :80",
        "999.1.1.1:80",
        "127.1:80",
        "-a.example:80",
        "a_b c:1",
    ] {
        assert!(parse(bad).is_none(), "{bad:?} must be rejected");
    }
    let err = ProxyOverride::parse("nope").unwrap_err();
    assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "core.settings.proxyOverrideInvalid");
}

/// The stored shape stays `{host, port, credentials?}`; a host that fails the grammar is dropped
/// on load (lenient: default `None` with a warning), never handed to the engines.
#[test]
fn proxy_override_stored_shape() {
    let (p, _) = parse("[::1]:1080").unwrap();
    assert_eq!(
        serde_json::to_value(&p).unwrap(),
        json!({"host": "::1", "port": 1080})
    );
    let s: Settings =
        serde_json::from_value(json!({"proxyOverride": {"host": "Proxy.Local", "port": 3128}}))
            .unwrap();
    assert_eq!(
        s.proxy_override.unwrap().addr.to_string(),
        "proxy.local:3128"
    );
    for bad in [
        json!({"host": "a b", "port": 1}),
        json!({"host": "h", "port": 0}),
        json!({"host": "999.1.1.1", "port": 80}),
        json!("127.0.0.1:1080"),
    ] {
        let s: Settings = serde_json::from_value(json!({"proxyOverride": bad})).unwrap();
        assert_eq!(s.proxy_override, None, "{bad}");
    }
}

/// The override becomes an app-request route of the configured kind; the label never shows the
/// credentials.
#[test]
fn proxy_override_route() {
    let (p, _) = parse("FAKE-USER:FAKE%25PASS@127.0.0.1:10808").unwrap();
    let route = p.route(ProxyKind::Socks5);
    assert_eq!(route.label(), "socks5h://127.0.0.1:10808");
    assert_eq!(p.creds().unwrap().pass, "FAKE%PASS");
    let (p, _) = parse("[::1]:8080").unwrap();
    assert_eq!(p.route(ProxyKind::Http).label(), "http://[::1]:8080");
}

#[test]
fn proxy_credentials_are_sealed_in_settings_json() {
    let proxy = parse("socks5://FAKE-USER:FAKE-PASS@127.0.0.1:1080")
        .unwrap()
        .0;
    let s = Settings {
        proxy_override: Some(proxy),
        ..Settings::default()
    };
    let text = serde_json::to_string(&s).unwrap();
    assert!(
        !text.contains("FAKE-PASS") && !text.contains("FAKE-USER"),
        "{text}"
    );
    let back: Settings = serde_json::from_str(&text).unwrap();
    assert_eq!(back, s);
    assert_eq!(
        back.proxy_override.unwrap().creds().unwrap().pass,
        "FAKE-PASS"
    );
}

/// AT-09-013: a new credential is sealed once; later saves keep its ciphertext (serialising through
/// `serde(into)` sealed a clone, so every save re-encrypted the credentials).
#[test]
fn proxy_credentials_are_sealed_once() {
    let tmp = crate::test_support::TempDir::new("settings");
    let store = crate::store::Store::<Settings>::open(tmp.path());
    let sealed = || {
        let v: Value = serde_json::from_slice(&std::fs::read(store.path()).unwrap()).unwrap();
        v["proxyOverride"]["credentials"].clone()
    };
    let mut patch = SettingsPatch::default();
    patch
        .set_proxy_override("FAKE-USER:FAKE-PASS@127.0.0.1:1080")
        .unwrap();
    store.update(|s| s.apply(patch)).unwrap();
    let first = sealed();
    assert!(first.as_str().unwrap().starts_with("dpapi:v1:"), "{first}");
    store.update(|s| s.stealth_mode = true).unwrap();
    assert_eq!(sealed(), first);
}

#[test]
fn patch_sets_proxy_and_its_scheme() {
    let mut patch = SettingsPatch::default();
    patch.set_proxy_override("http://127.0.0.1:8080").unwrap();
    let mut s = Settings::default();
    s.apply(patch);
    assert_eq!(s.proxy_type, ProxyKind::Http);
    assert_eq!(
        s.proxy_override.as_ref().unwrap().addr.to_string(),
        "127.0.0.1:8080"
    );

    let mut patch = SettingsPatch::default();
    patch.set_proxy_override("10.0.0.1:1080").unwrap();
    s.apply(patch);
    assert_eq!(
        s.proxy_type,
        ProxyKind::Http,
        "no scheme: protocol unchanged"
    );

    let mut clear = SettingsPatch::default();
    clear.set_proxy_override("  ").unwrap();
    s.apply(clear);
    assert_eq!(s.proxy_override, None);
    assert!(SettingsPatch::default().set_proxy_override("bad").is_err());
}

/// Owner decision D-16 import rule (owner-decisions §7, derived from granularKillSwitch.ts:238-247).
#[test]
fn kill_switch_import_rule() {
    use KillSwitchLevel::*;
    assert_eq!(import_kill_switch(Some("strict"), Some(false)), Strict);
    assert_eq!(import_kill_switch(Some("strict"), None), Strict);
    assert_eq!(import_kill_switch(Some("standard"), Some(false)), Off);
    assert_eq!(import_kill_switch(Some("off"), Some(true)), Standard);
    assert_eq!(import_kill_switch(None, Some(true)), Standard);
    assert_eq!(import_kill_switch(None, None), Off);
    assert_eq!(import_kill_switch(Some("bogus"), Some(false)), Off);
}

/// AT-00-001: a fresh install has exactly the documented defaults; invasive features are off.
#[test]
fn defaults() {
    let s = Settings::default();
    assert!(!s.deep_inspection, "packet capture is opt-in");
    assert_eq!(s.kill_switch, KillSwitchLevel::Off);
    assert_eq!(s.connection_mode, ConnectionMode::LocalProxy);
    assert_eq!(s.routing_mode, RoutingMode::Hard);
    assert_eq!(
        (s.proxy_override.as_ref(), s.proxy_type),
        (None, ProxyKind::Socks5)
    );
    assert_eq!(s.bootstrap_route_mode, BootstrapRouteMode::Auto);
    assert_eq!(s.check_interval_ms, 30_000);
    assert_eq!(
        (s.deep_inspection_max_mb, s.smart_ru_rule_set_update_hours),
        (512, 24)
    );
    assert!(s.autopilot && s.minimize_to_tray && s.auto_restart_on_crash);
    assert!(s.desktop_notifications && s.public_wifi_compatibility);
    assert!(s.adaptive_bypass && s.adaptive_bypass_server_fallback);
    assert!(s.smart_ru_rule_set_auto_update && s.smart_ru_rule_set_use_proxy);
    assert!(!s.autostart && !s.disable_geo_lookup && !s.location_privacy);
    assert!(!s.domain_enrichment && !s.auto_network_baseline && !s.advanced_mode);
    assert!(!s.first_run_complete && !s.stealth_mode && !s.smart_ru_split);
    assert!(!s.smart_ru_maps_direct);
    assert_eq!(s.smart_ru_rule_set_mode, RuleSetMode::Managed);
    assert_eq!(s.proxy_engine, EnginePref::Auto);
    assert_eq!(
        (s.locale, s.active_theme_id.as_str()),
        (None, "builtin-system")
    );
    let n = &s.notifications;
    assert!(n.vpn_connect && n.vpn_disconnect && n.leak_detected && n.profile_rotation);
    assert!(n.schedule_triggered && n.connection_error && n.sound);
    assert_eq!(n.method, NotifyMethod::System);
    assert_eq!(s.ui, UiPrefs::default());
}

#[test]
fn json_names_and_spellings() {
    let mut s = Settings {
        proxy_engine: EnginePref::SingBox,
        locale: Some(Lang::Ru),
        ..Settings::default()
    };
    s.notifications.method = NotifyMethod::InApp;
    let v = serde_json::to_value(&s).unwrap();
    assert_eq!(v["connectionMode"], "localProxy");
    assert_eq!(v["bootstrapRouteMode"], "auto");
    assert_eq!(v["proxyType"], "socks5");
    assert_eq!(v["proxyEngine"], "sing-box");
    assert_eq!(v["killSwitch"], "off");
    assert_eq!(v["checkIntervalMs"], 30_000);
    assert_eq!(v["smartRuRuleSetUpdateHours"], 24);
    assert_eq!(v["locale"], "ru");
    assert_eq!(v["proxyOverride"], Value::Null);
    assert_eq!(v["notifications"]["method"], "inapp");
    assert_eq!(
        v["ui"],
        json!({"expandedGroups": [], "dismissedTips": [], "debugLog": false})
    );
    assert!(v.get("firewallKillSwitch").is_none() && v.get("extra").is_none());
}

fn every_field_changed() -> Settings {
    let mut s = Settings {
        connection_mode: ConnectionMode::DirectVpn,
        routing_mode: RoutingMode::Soft,
        proxy_override: Some(parse("u:p@10.1.2.3:3128").unwrap().0),
        proxy_type: ProxyKind::Http,
        bootstrap_route_mode: BootstrapRouteMode::LocalProxy,
        check_interval_ms: 6_000,
        disable_geo_lookup: true,
        autostart: true,
        autopilot: false,
        minimize_to_tray: false,
        location_privacy: true,
        domain_enrichment: true,
        auto_network_baseline: true,
        kill_switch: KillSwitchLevel::Strict,
        advanced_mode: true,
        first_run_complete: true,
        auto_restart_on_crash: false,
        desktop_notifications: false,
        public_wifi_compatibility: false,
        deep_inspection: true,
        deep_inspection_max_mb: 1_024,
        stealth_mode: true,
        adaptive_bypass: false,
        adaptive_bypass_server_fallback: false,
        smart_ru_split: true,
        smart_ru_maps_direct: true,
        smart_ru_rule_set_mode: RuleSetMode::Managed,
        smart_ru_rule_set_auto_update: false,
        smart_ru_rule_set_use_proxy: false,
        smart_ru_rule_set_update_hours: 48,
        proxy_engine: EnginePref::Xray,
        proxy_bypass: vec!["corp.example".into(), "10.*".into()],
        proxy_bypass_auto: false,
        locale: Some(Lang::En),
        active_theme_id: "custom-1".into(),
        notifications: NotificationPrefs {
            vpn_connect: false,
            vpn_disconnect: false,
            leak_detected: false,
            profile_rotation: false,
            schedule_triggered: false,
            connection_error: false,
            method: NotifyMethod::Both,
            sound: false,
            extra: Map::new(),
        },
        ui: UiPrefs {
            expanded_groups: vec!["g1".into()],
            dismissed_tips: ["tip".to_owned()].into(),
            debug_log: true,
            extra: Map::new(),
        },
        log_key: Some(crate::secret::Secret::new("ab".repeat(32))),
        extra: Map::new(),
    };
    s.extra.insert("newerKey".into(), json!({"x": 1}));
    s.notifications
        .extra
        .insert("newerToggle".into(), json!(true));
    s
}

/// The log pseudonym key is created once, sealed on disk and read back unchanged; an unusable
/// stored key (locked or not 32 bytes of hex) is replaced.
#[test]
fn log_key_is_created_once_and_kept() {
    let mut s = Settings::default();
    let key = s.ensure_log_key().unwrap();
    assert_eq!(s.ensure_log_key(), Some(key), "a second call keeps the key");
    let text = serde_json::to_string(&s).unwrap();
    assert!(text.contains("\"logKey\":\"dpapi:v1:") && !text.contains(&hex::encode(key)));
    let mut back: Settings = serde_json::from_str(&text).unwrap();
    assert_eq!(back.ensure_log_key(), Some(key));
    assert_eq!(back, s);

    let locked: Settings =
        serde_json::from_value(json!({ "logKey": "dpapi:v1:Zm9yZWlnbg==" })).unwrap();
    assert!(locked.log_key.as_ref().unwrap().is_locked());
    let unusable = ["not hex".to_owned(), "ab".repeat(31)].map(|text| Settings {
        log_key: Some(crate::secret::Secret::new(text)),
        ..Settings::default()
    });
    for mut s in [vec![locked], unusable.to_vec()].concat() {
        let fresh = s.ensure_log_key().unwrap();
        assert_eq!(s.ensure_log_key(), Some(fresh));
        assert!(!s.log_key.as_ref().unwrap().is_locked());
    }
    assert!(
        serde_json::to_value(Settings::default())
            .unwrap()
            .get("logKey")
            .is_none()
    );
}

/// B28: a read-only `settings.json` refuses the save but still yields its log key (the start-up
/// fallback of `API.md`), and the file is not touched.
#[test]
fn log_key_of_a_read_only_store() {
    let tmp = crate::test_support::TempDir::new("settings");
    let mut seeded = Settings::default();
    let key = seeded.ensure_log_key().unwrap();
    let mut doc = serde_json::to_value(&seeded).unwrap();
    doc["schemaVersion"] = json!(Settings::VERSION + 1);
    let text = doc.to_string();
    let path = tmp.write("settings.json", &text);
    let store = crate::store::Store::<Settings>::open(tmp.path());
    assert!(store.update(Settings::ensure_log_key).is_err());
    assert_eq!(store.snapshot().ensure_log_key(), Some(key));
    assert_eq!(std::fs::read_to_string(path).unwrap(), text);
}

/// Every field survives a write and a read (also proves the key names of the lenient reader).
#[test]
fn every_field_round_trips() {
    let s = every_field_changed();
    let text = serde_json::to_string(&s).unwrap();
    let back: Settings = serde_json::from_str(&text).unwrap();
    assert_eq!(back, s);
    assert_ne!(back, Settings::default());
}

/// Lenient load: each bad value falls back on its own; numbers are coerced and clamped (AT-00-001).
#[test]
fn lenient_per_field_loading() {
    let s: Settings = serde_json::from_value(json!({
        "routingMode": "turbo",
        "killSwitch": "maximum",
        "deepInspection": "yes",
        "autopilot": 0,
        "stealthMode": true,
        "checkIntervalMs": -5,
        "deepInspectionMaxMb": 5000,
        "smartRuRuleSetUpdateHours": 12.6,
        "proxyOverride": "127.0.0.1:1080",
        "locale": "de",
        "activeThemeId": 7,
        "notifications": {"sound": "loud", "method": "inapp"},
        "ui": [],
        "minimizeToTray": null,
        "somethingNew": [1]
    }))
    .unwrap();
    assert_eq!(s.routing_mode, RoutingMode::Hard);
    assert_eq!(
        s.kill_switch,
        KillSwitchLevel::Off,
        "garbage never arms the kill switch"
    );
    assert!(!s.deep_inspection, "garbage never enables capture");
    assert!(s.autopilot && s.stealth_mode && s.minimize_to_tray);
    assert_eq!(s.check_interval_ms, 5_000);
    assert_eq!(s.deep_inspection_max_mb, 2_048);
    assert_eq!(s.smart_ru_rule_set_update_hours, 13);
    assert_eq!((s.proxy_override, s.locale), (None, None));
    assert_eq!(s.active_theme_id, "builtin-system");
    assert!(s.notifications.sound);
    assert_eq!(s.notifications.method, NotifyMethod::InApp);
    assert_eq!(s.ui, UiPrefs::default());
    assert_eq!(s.extra.get("somethingNew"), Some(&json!([1])));
    assert!(
        serde_json::from_str::<Settings>("[]").is_err(),
        "not an object"
    );
}

/// Config import applies only the present keys, nested objects per key; `null` clears options.
#[test]
fn merge_keeps_absent_keys() {
    let mut s = every_field_changed();
    s.merge_json(
        json!({"stealthMode": false, "locale": null, "notifications": {"sound": true}})
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(!s.stealth_mode && s.notifications.sound && s.locale.is_none());
    assert!(!s.notifications.vpn_connect, "absent nested key kept");
    assert_eq!(s.kill_switch, KillSwitchLevel::Strict, "absent key kept");
}

/// AT-00-001: patches are typed and clamped.
#[test]
fn patch_assigns_and_clamps() {
    let mut s = Settings::default();
    s.apply(SettingsPatch {
        check_interval_ms: Some(0),
        deep_inspection_max_mb: Some(5_000),
        smart_ru_rule_set_update_hours: Some(0),
        deep_inspection: Some(true),
        ..SettingsPatch::default()
    });
    assert_eq!(s.check_interval_ms, 5_000);
    assert_eq!(s.deep_inspection_max_mb, 2_048);
    assert_eq!(s.smart_ru_rule_set_update_hours, 1);
    assert!(s.deep_inspection);
    assert!(s.minimize_to_tray, "absent fields untouched (B10)");
    let before = s.clone();
    s.apply(SettingsPatch::default());
    assert_eq!(s, before);
}

/// Old settings object (§2.5 rules + §6.3 rename table); AT-00-001 legacy clamps.
#[test]
fn legacy_settings_are_mapped() {
    let legacy = json!({"settings": {
        "connectionMode": "directVpn",
        "routingMode": "soft",
        "proxyType": "http",
        "bootstrapRouteMode": "localProxy",
        "checkInterval": -5,
        "autoStart": true,
        "autoPilotEnabled": false,
        "locationPrivacyEnabled": 1,
        "domainEnrichmentEnabled": "",
        "autoNetworkBaseline": true,
        "firewallKillSwitch": true,
        "deepTrafficInspectionEnabled": "yes",
        "deepTrafficInspectionMaxSizeMb": 5000,
        "deepTrafficInspectionRetainSessions": 7,
        "adaptiveBypassEnabled": "false",
        "smartRuRuleSetMode": "managed",
        "smartRuRuleSetUpdateIntervalHours": 0.5,
        "proxyEngine": "xray",
        "strictAdapterLockdown": false,
        "directVpnInput": "vless://FAKE-UUID@example.invalid:443",
        "directVpnSelectedIndex": 0.5,
        "directVpnCachedAt": null
    }, "schemaVersion": 2});
    let (s, warnings) = Settings::from_legacy(&legacy);
    assert!(warnings.is_empty());
    assert_eq!(s.connection_mode, ConnectionMode::DirectVpn);
    assert_eq!(s.routing_mode, RoutingMode::Soft);
    assert_eq!(s.proxy_type, ProxyKind::Http);
    assert_eq!(s.bootstrap_route_mode, BootstrapRouteMode::LocalProxy);
    assert_eq!(s.check_interval_ms, 5_000);
    assert!(s.autostart && !s.autopilot && s.location_privacy && !s.domain_enrichment);
    assert!(s.auto_network_baseline);
    assert_eq!(s.kill_switch, KillSwitchLevel::Standard);
    assert!(!s.deep_inspection, "'yes' is not `=== true`");
    assert_eq!(s.deep_inspection_max_mb, 2_048);
    assert!(s.adaptive_bypass, "the string \"false\" is not `false`");
    assert_eq!(s.smart_ru_rule_set_mode, RuleSetMode::Managed);
    assert_eq!(
        s.smart_ru_rule_set_update_hours, 1,
        "floor(0.5) = 0, clamped to 1"
    );
    assert_eq!(s.proxy_engine, EnginePref::Xray);
    // Legacy-only keys (some of them secrets) never reach the new document.
    assert!(s.extra.is_empty());
    let text = serde_json::to_string(&s).unwrap();
    assert!(
        !text.contains("FAKE-UUID") && !text.contains("directVpnInput"),
        "{text}"
    );
}

/// Re-check item 12a: an old explicit "bundled" choice is kept; absent or unknown means managed
/// list updates, today's default.
#[test]
fn legacy_rule_set_mode_keeps_an_explicit_bundled() {
    let mode = |v: serde_json::Value| {
        Settings::from_legacy(&json!({ "smartRuRuleSetMode": v }))
            .0
            .smart_ru_rule_set_mode
    };
    assert_eq!(mode(json!("bundled")), RuleSetMode::Bundled);
    assert_eq!(mode(json!("managed")), RuleSetMode::Managed);
    assert_eq!(mode(json!(null)), RuleSetMode::Managed);
    assert_eq!(mode(json!("weird")), RuleSetMode::Managed);
}

/// settingsForensicsDefault: missing / `null` values take the documented defaults (B10, B11).
#[test]
fn legacy_missing_and_null_values_take_defaults() {
    let (s, _) = Settings::from_legacy(&json!({
        "minimizeToTray": null,
        "firewallKillSwitch": null,
        "deepTrafficInspectionEnabled": null,
        "checkInterval": "abc",
        "directVpnCachedAt": null
    }));
    assert!(
        s.minimize_to_tray,
        "B10: an absent value no longer switches it off"
    );
    assert_eq!(s.kill_switch, KillSwitchLevel::Off);
    assert!(s.auto_restart_on_crash && !s.deep_inspection);
    assert_eq!(s.check_interval_ms, 30_000);
    let fresh = Settings::from_legacy(&json!({})).0;
    assert_eq!(fresh, Settings::default());
    assert_eq!(
        Settings::from_legacy(&json!({"settings": 5})).0,
        Settings::default()
    );
    assert_eq!(
        Settings::from_legacy(&json!("garbage")).0,
        Settings::default()
    );
    let (s, _) = Settings::from_legacy(
        &json!({"deepTrafficInspectionEnabled": true, "checkInterval": "60000.4"}),
    );
    assert!(s.deep_inspection);
    assert_eq!(s.check_interval_ms, 60_000);
}

/// B32: the legacy proxy string goes through the same parser; garbage is dropped and reported.
#[test]
fn legacy_proxy_override() {
    let (s, w) = Settings::from_legacy(&json!({
        "proxyType": "socks5",
        "proxyOverride": " http://user:FAKE-PASS@127.0.0.1:8080 "
    }));
    assert!(w.is_empty());
    assert_eq!(
        s.proxy_type,
        ProxyKind::Http,
        "the scheme wins over proxyType"
    );
    let p = s.proxy_override.unwrap();
    assert_eq!(
        (
            p.addr.to_string().as_str(),
            p.creds().unwrap().pass.as_str()
        ),
        ("127.0.0.1:8080", "FAKE-PASS")
    );

    for bad in [
        json!("user:pass@"),
        json!({"__vpnteSecretRef": "vpnte-safe-storage-v1"}),
    ] {
        let (s, w) = Settings::from_legacy(&json!({ "proxyOverride": bad }));
        assert_eq!(s.proxy_override, None);
        assert_eq!(w, [Msg::new("core.settings.legacyProxyDropped")]);
    }
    assert!(
        Settings::from_legacy(&json!({"proxyOverride": "  "}))
            .1
            .is_empty()
    );
}

#[test]
fn legacy_single_purpose_stores() {
    let mut s = Settings::default();
    s.apply_legacy_stores(
        Some(&json!({"locale": "en"})),
        Some(&json!({"activeThemeId": "custom-dark", "customThemes": []})),
        Some(
            &json!({"notificationPrefs": {"sound": false, "method": "inapp", "leakDetected": "x"}}),
        ),
    );
    assert_eq!(s.locale, Some(Lang::En));
    assert_eq!(s.active_theme_id, "custom-dark");
    assert!(!s.notifications.sound && s.notifications.leak_detected && s.notifications.vpn_connect);
    assert_eq!(s.notifications.method, NotifyMethod::InApp);
    s.apply_legacy_stores(
        Some(&json!({"locale": "fr"})),
        Some(&json!({"activeThemeId": ""})),
        None,
    );
    assert_eq!(
        (s.locale, s.active_theme_id.as_str()),
        (Some(Lang::En), "custom-dark")
    );
}

/// AT-09-013 and settingsNoop: saving an equal snapshot writes nothing; a real change persists.
#[test]
fn settings_store_writes_only_changes() {
    use crate::store::Store;
    let tmp = crate::test_support::TempDir::new("settings");
    let store = Store::<Settings>::open(tmp.path());
    assert_eq!(
        store.snapshot(),
        Settings::default(),
        "fresh store (no file)"
    );
    let prev = store.read(|s| s.check_interval_ms);
    store
        .update(|s| {
            s.apply(SettingsPatch {
                check_interval_ms: Some(prev + 5_000),
                deep_inspection: Some(true),
                ..SettingsPatch::default()
            })
        })
        .unwrap();
    let reopened = Store::<Settings>::open(tmp.path());
    assert_eq!(
        reopened.read(|s| (s.check_interval_ms, s.deep_inspection)),
        (prev + 5_000, true)
    );

    std::fs::remove_file(store.path()).unwrap();
    let same = store.snapshot();
    store
        .update(|s| {
            s.apply(SettingsPatch {
                check_interval_ms: Some(same.check_interval_ms),
                ..SettingsPatch::default()
            })
        })
        .unwrap();
    store.replace(same).unwrap();
    assert!(!store.path().exists(), "no write for an unchanged document");
}

/// settingsNoop: when storage cannot be read, even an empty patch fails and nothing is written.
#[test]
fn unreadable_settings_refuse_every_save() {
    use std::os::windows::fs::OpenOptionsExt;

    use crate::store::{Mode, ReadOnlyReason, Store};
    let tmp = crate::test_support::TempDir::new("settings");
    let path = tmp.path().join("settings.json");
    std::fs::write(&path, r#"{"schemaVersion":1,"stealthMode":true}"#).unwrap();
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let store = Store::<Settings>::open(tmp.path());
    drop(holder);
    assert_eq!(store.mode(), Mode::ReadOnly(ReadOnlyReason::Unreadable));
    assert!(store.update(|s| s.apply(SettingsPatch::default())).is_err());
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        r#"{"schemaVersion":1,"stealthMode":true}"#
    );
}
