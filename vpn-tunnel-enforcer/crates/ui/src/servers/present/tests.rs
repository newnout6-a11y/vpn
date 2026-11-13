use super::*;
use crate::servers::model::Archive;

fn server(id: &str, protocol: &str, group: Option<&str>) -> ServerView {
    ServerView {
        id: id.into(),
        name: id.into(),
        protocol: protocol.into(),
        host: "vpn.example.test".into(),
        port: 443,
        group_id: group.map(Into::into),
        enabled: true,
        ..ServerView::default()
    }
}

fn group(id: &str, source: GroupSource, imported_at: UnixMs) -> GroupView {
    GroupView {
        id: id.into(),
        name: id.into(),
        source,
        imported_at,
        ..GroupView::default()
    }
}

/// AT-01-008 "public profile display metadata": the badge comes from the backend's display
/// hint only (no outbound in the view, S-23).
#[test]
fn stealth_badges_from_display_metadata() {
    let cases = [
        (Stealth::Ech, "ECH", Tone::Neutral),
        (Stealth::Reality, "Reality", Tone::Neutral),
        (Stealth::Naive, "Naive", Tone::Neutral),
        (Stealth::Obfs, "OBFS", Tone::Neutral),
        (Stealth::Utls, "uTLS", Tone::Neutral),
        (Stealth::Tls, "TLS", Tone::Neutral),
        (Stealth::Plain, "Plain", Tone::Warn),
    ];
    for (stealth, label, tone) in cases {
        let (l, key, t) = stealth_badge(stealth);
        assert_eq!((l, t), (label, tone), "{stealth:?}");
        assert!(key.starts_with("ui.servers.stealth."));
    }
}

/// AT-01-008 `formatHappType`.
#[test]
fn happ_type_caption() {
    assert_eq!(happ_type("vless", true), "VLESS | JSON");
    assert_eq!(happ_type("vless", false), "VLESS");
    assert_eq!(happ_type("", false), "UNKNOWN");
}

/// `displayedServerPing` / `hasSuccessfulRowPing`: a fresh row ping wins, a failed one keeps
/// the persisted value, health latency never appears.
#[test]
fn ping_precedence() {
    assert_eq!(
        displayed_ping(Some(120), PingState::Done(Some(80))),
        Some(80)
    );
    assert_eq!(displayed_ping(Some(120), PingState::Unmeasured), Some(120));
    assert_eq!(displayed_ping(Some(120), PingState::Done(None)), Some(120));
    assert_eq!(
        displayed_ping(None, PingState::Measuring { last: Some(9) }),
        Some(9)
    );
    assert!(PingState::Done(Some(105)).fresh_ok());
    assert!(!PingState::Measuring { last: Some(105) }.fresh_ok());
    assert!(!PingState::Done(None).fresh_ok());
    assert_eq!(
        PingState::Done(Some(5)).measuring(),
        PingState::Measuring { last: Some(5) }
    );
}

#[test]
fn row_signal_order() {
    let dead = KeyHealth {
        online: false,
        latency_ms: Some(900),
        reason: Some(KeyHealthReason::Timeout),
        checked_at: 1,
    };
    let fresh = PingState::Done(Some(40));
    assert_eq!(
        row_signal(fresh, Some(&dead), OnlineStatus::Offline),
        RowSignal::FreshPing
    );
    assert_eq!(
        row_signal(PingState::Done(None), Some(&dead), OnlineStatus::Online),
        RowSignal::Dead(Some(KeyHealthReason::Timeout))
    );
    let alive = KeyHealth {
        online: true,
        ..dead
    };
    assert_eq!(
        row_signal(PingState::Unmeasured, Some(&alive), OnlineStatus::Offline),
        RowSignal::Alive
    );
    assert_eq!(
        row_signal(PingState::Unmeasured, None, OnlineStatus::Offline),
        RowSignal::Offline
    );
    assert_eq!(
        row_signal(PingState::Unmeasured, None, OnlineStatus::Unknown),
        RowSignal::Unknown
    );
}

/// ENGINE-GAPS decision 3: an engine refusal is its own neutral mark, never "dead key"; the
/// row menu's engine ids map to the three choices and nothing else.
#[test]
fn engine_verdict_and_menu_ids() {
    let refused = KeyHealth {
        online: false,
        latency_ms: None,
        reason: Some(KeyHealthReason::from_code("engine-setting")),
        checked_at: 1,
    };
    assert_eq!(refused.reason, Some(KeyHealthReason::EngineSetting));
    assert_eq!(KeyHealthReason::EngineSetting.code(), "engine-setting");
    assert_eq!(
        row_signal(PingState::Unmeasured, Some(&refused), OnlineStatus::Offline),
        RowSignal::Engine
    );
    use vpnte_base::types::{Engine, EnginePref};
    for (id, pref) in ENGINE_ITEMS {
        assert_eq!(engine_of_item(id), Some(pref));
    }
    assert_eq!(engine_of_item("ping"), None);
    assert_eq!(engine_name(Engine::SingBox), "sing-box");
    assert_eq!(engine_name(Engine::Xray), "Xray");
    assert_eq!(ENGINE_ITEMS[0].1, EnginePref::Auto);
}

/// The fingerprint line follows the emitters (RU 2026 plan fact 2): REALITY keys go out as
/// `chrome` under sing-box whatever the persona, Xray never sends `android` / `ios`, a provider
/// pin wins, a key without TLS has none.
#[test]
fn fingerprint_follows_the_engines() {
    use crate::servers::model::EnginePlan;
    use vpnte_base::Msg;
    use vpnte_base::types::{ClientDevice, Engine};
    let key = |device, stealth, engine: Option<Engine>| ServerView {
        device,
        stealth,
        engine_plan: engine.map(|engine| EnginePlan::Runs {
            engine,
            reason: Msg::new("x"),
        }),
        ..server("s", "vless", None)
    };
    let reality = Some(Stealth::Reality);
    let tls = Some(Stealth::Tls);
    let (sing, xray) = (Some(Engine::SingBox), Some(Engine::Xray));
    assert_eq!(
        fingerprint(&key(ClientDevice::Android, tls, sing)),
        "android"
    );
    assert_eq!(
        fingerprint(&key(ClientDevice::Android, reality, sing)),
        "chrome"
    );
    assert_eq!(
        fingerprint(&key(ClientDevice::Mac, reality, sing)),
        "chrome"
    );
    assert_eq!(fingerprint(&key(ClientDevice::Mac, tls, sing)), "safari");
    assert_eq!(fingerprint(&key(ClientDevice::Ios, tls, xray)), "chrome");
    assert_eq!(
        fingerprint(&key(ClientDevice::Mac, reality, xray)),
        "safari"
    );
    assert_eq!(fingerprint(&key(ClientDevice::Pc, tls, None)), "chrome");
    assert_eq!(
        fingerprint(&key(ClientDevice::Ios, reality, None)),
        "chrome"
    );
    let pinned = ServerView {
        fingerprint: Some("firefox".into()),
        ..key(ClientDevice::Android, reality, sing)
    };
    assert_eq!(fingerprint(&pinned), "firefox");
    let plain = key(ClientDevice::Pc, Some(Stealth::Plain), sing);
    assert_eq!(fingerprint(&plain), "—");
}

#[test]
fn health_reason_codes_round_trip() {
    for code in ["auth-failed", "hy2-udp-blocked", "no-outbound", "timeout"] {
        assert_eq!(KeyHealthReason::from_code(code).code(), code);
    }
    let other = KeyHealthReason::from_code("brand-new");
    assert_eq!(other, KeyHealthReason::Other("brand-new".into()));
    assert_eq!(other.code(), "brand-new");
}

/// D-7: one rule for row and detail; the 1-minute lag rule only for subscription groups.
#[test]
fn removed_from_subscription_rule() {
    let mut sub = group("g", GroupSource::Subscription, 1);
    sub.last_fetched_at = Some(200_000);
    let mut s = server("a", "vless", Some("g"));
    assert!(!is_removed_from_subscription(&s, Some(&sub)));
    s.last_seen_in_subscription_at = Some(150_000);
    assert!(!is_removed_from_subscription(&s, Some(&sub)), "49 s lag");
    s.last_seen_in_subscription_at = Some(140_000);
    assert!(is_removed_from_subscription(&s, Some(&sub)), "60 s lag");
    let manual = GroupView {
        source: GroupSource::Manual,
        ..sub.clone()
    };
    assert!(!is_removed_from_subscription(&s, Some(&manual)));
    let archive = |reason| Archive {
        reason,
        at: 5,
        purge_at: 5 + 30 * 86_400_000,
    };
    // The provider dropped it: shown as removed, still selectable by hand, never a proxy.
    let mut dropped = server("b", "vless", None);
    dropped.archived = Some(archive(ArchiveReason::Provider));
    assert!(is_removed_from_subscription(&dropped, None));
    assert_eq!(unusable(&dropped), None);
    assert!(!proxy_ready(&dropped, None));
    assert!(!proxy_ready(&s, Some(&sub)), "the lag rule counts too");
    // The user removed it (soft delete, S-34): not selectable until restored.
    let mut deleted = server("e", "vless", None);
    deleted.archived = Some(archive(ArchiveReason::User));
    assert!(is_deleted(&deleted));
    assert!(!is_removed_from_subscription(&deleted, None));
    assert_eq!(unusable(&deleted), Some(Unusable::Deleted));
    let mut off = server("c", "vless", None);
    off.enabled = false;
    assert_eq!(unusable(&off), Some(Unusable::Disabled));
    assert_eq!(unusable(&server("d", "vless", None)), None);
    assert!(proxy_ready(&server("d", "vless", None), None));
    // p-live-fix: a provider notice an older build stored is never a server, archived or not.
    let mut notice = server("n", "vless", None);
    notice.placeholder = true;
    assert_eq!(unusable(&notice), Some(Unusable::Placeholder));
    notice.archived = Some(archive(ArchiveReason::Provider));
    assert_eq!(unusable(&notice), Some(Unusable::Placeholder));
    assert!(!proxy_ready(&notice, None));
}

#[test]
fn groups_sort_subscriptions_first_then_newest() {
    let mut groups = vec![
        group("m1", GroupSource::Manual, 9),
        group("s1", GroupSource::Subscription, 1),
        group("s2", GroupSource::Subscription, 5),
        group("m0", GroupSource::Manual, 0),
    ];
    sort_groups(&mut groups);
    let ids: Vec<&str> = groups.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids, ["s2", "s1", "m1", "m0"]);
}

/// Orphans stay visible under a recovered header; group-less servers fall back to the first
/// manual group; without any group everything sits under «all servers».
#[test]
fn buckets_keep_every_server_visible() {
    let view = ServersView {
        groups: vec![
            group("sub", GroupSource::Subscription, 2),
            group("keys", GroupSource::Manual, 1),
        ],
        servers: vec![
            server("a", "vless", Some("sub")),
            server("b", "trojan", Some("gone")),
            server("c", "vless", None),
            server("d", "vless", Some("gone")),
        ],
        ..ServersView::default()
    };
    let b = buckets(&view);
    let shape: Vec<(&str, BucketKind, Vec<&str>)> = b
        .iter()
        .map(|b| {
            let ids = b.servers.iter().map(|s| s.id.as_str()).collect();
            (b.group.id.as_str(), b.kind, ids)
        })
        .collect();
    assert_eq!(
        shape,
        [
            ("sub", BucketKind::Real, vec!["a"]),
            ("keys", BucketKind::Real, vec!["c"]),
            ("gone", BucketKind::Recovered, vec!["b", "d"]),
        ]
    );
    let bare = ServersView {
        servers: vec![server("x", "vless", None), server("y", "ss", Some("old"))],
        ..ServersView::default()
    };
    let b = buckets(&bare);
    assert_eq!(b.len(), 2);
    assert_eq!(
        (b[0].kind, b[0].group.id.as_str()),
        (BucketKind::Recovered, "old")
    );
    assert_eq!(
        (b[1].kind, b[1].group.id.as_str()),
        (BucketKind::Virtual, VIRTUAL_ALL_GROUP)
    );
    assert!(buckets(&ServersView::default()).is_empty());
}

#[test]
fn protocol_sections_alphabetical_rows_stable() {
    let rows = vec![
        server("v1", "vless", None),
        server("t1", "trojan", None),
        server("v2", "vless", None),
        server("h1", "hysteria2", None),
        server("u", "", None),
    ];
    let sections = protocol_sections(&rows);
    let shape: Vec<(&str, Vec<&str>)> = sections
        .iter()
        .map(|(k, r)| (k.as_str(), r.iter().map(|s| s.id.as_str()).collect()))
        .collect();
    assert_eq!(
        shape,
        [
            ("hysteria2", vec!["h1"]),
            ("trojan", vec!["t1"]),
            ("unknown", vec!["u"]),
            ("vless", vec!["v1", "v2"]),
        ]
    );
}

#[test]
fn traffic_bar() {
    assert_eq!(traffic(50, 100), (50, Tone::Neutral, false));
    assert_eq!(traffic(81, 100), (81, Tone::Warn, false));
    assert_eq!(traffic(150, 100), (100, Tone::Fail, true));
    assert_eq!(traffic(5, 0), (0, Tone::Neutral, false));
}

/// Source-pinned values `auto,1,5,15,30,60,360,1440`, plus a non-standard stored value.
#[test]
fn refresh_choices_include_the_stored_value() {
    let plain: Vec<Option<u32>> = refresh_choices(None)
        .into_iter()
        .map(|o| o.map(NonZeroU32::get))
        .collect();
    assert_eq!(
        plain,
        [
            None,
            Some(1),
            Some(5),
            Some(15),
            Some(30),
            Some(60),
            Some(360),
            Some(1440)
        ]
    );
    let odd = refresh_choices(NonZeroU32::new(120));
    assert_eq!(odd.len(), 9);
    assert_eq!(odd[6].map(NonZeroU32::get), Some(120));
    assert_eq!(refresh_choices(NonZeroU32::new(60)).len(), 8);
    assert_eq!(
        refresh_label_key(NonZeroU32::new(120)),
        ("ui.servers.group.refreshEvery", Some(120))
    );
}

#[test]
fn only_plain_http_links_open() {
    assert_eq!(
        safe_http_url(" https://panel.example/x "),
        Some("https://panel.example/x")
    );
    assert_eq!(safe_http_url("HTTP://a.b"), Some("HTTP://a.b"));
    for bad in [
        "javascript:alert(1)",
        "file:///c:/x",
        "https://",
        "https://a b",
        "ms-settings:",
    ] {
        assert_eq!(safe_http_url(bad), None, "{bad}");
    }
}

#[test]
fn relative_time_in_both_languages() {
    crate::test_locales::init_locales();
    let now = 1_000_000_000;
    let min = 60_000;
    assert_eq!(relative_time(now, now, Lang::En), "now");
    assert_eq!(
        relative_time(now - 30 * min, now, Lang::En),
        "30 minutes ago"
    );
    assert_eq!(
        relative_time(now - 30 * min, now, Lang::Ru),
        "30 минут назад"
    );
    assert_eq!(
        relative_time(now + 2 * 60 * min, now, Lang::Ru),
        "через 2 часа"
    );
    assert_eq!(
        relative_time(now + 19 * 1440 * min, now, Lang::Ru),
        "через 19 дней"
    );
    assert_eq!(relative_time(now - 1440 * min, now, Lang::Ru), "вчера");
    assert_eq!(
        relative_time(now + 21 * 1440 * min, now, Lang::Ru),
        "через 21 день"
    );
    assert_eq!(relative_time(now - 1000, now, Lang::En), "1 second ago");
}

#[test]
fn local_stamp_formats_per_language() {
    // 2026-11-11 06:12 UTC = 09:12 in Moscow; the system zone only changes the hour.
    let ts = 1_794_377_520_000;
    let moscow = TimeZone::get("Europe/Moscow").expect("bundled tzdb");
    assert_eq!(stamp_in(ts, Lang::Ru, &moscow), "11.11.2026 09:12");
    assert_eq!(stamp_in(ts, Lang::En, &moscow), "2026-11-11 09:12");
    assert_eq!(local_stamp(ts, Lang::Ru).len(), 16);
    assert_eq!(local_stamp(i64::MIN, Lang::En), "—");
}

/// The flag coins follow the shared stylesheet: every detector country has one (the panels'
/// 65), anything else gets the code mark.
#[test]
fn flags_come_from_the_shared_stylesheet() {
    let panels: serde_json::Value =
        serde_json::from_str(include_str!("../../../locales/ui-panels.en.json")).expect("json");
    let countries = panels["ui"]["panels"]["country"]
        .as_object()
        .expect("countries");
    assert!(countries.len() >= 65);
    for code in countries.keys() {
        assert!(has_flag(code), "{code}");
    }
    for code in ["ZZ", "de", "", "DEU"] {
        assert!(!has_flag(code), "{code}");
    }
}
