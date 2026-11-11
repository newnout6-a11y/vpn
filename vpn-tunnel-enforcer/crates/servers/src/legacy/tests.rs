//! Electron import vectors (storage §7.3 / §7.4, servers §2.3). Values are synthetic.
use serde_json::json;
use vpnte_profiles::model::Source;

use vpnte_profiles::countries::Iso2;

use super::country::legacy_country;
use super::*;
use crate::model::tests::{UUID_A, UUID_B, UUID_C};
use crate::model::{
    ArchiveReason, Archived, CountrySource, GroupStatus, HealthReason, HealthRecord, ServerRow,
};

const NOW: UnixMs = 1_800_000_000_000;

fn outbound(host: &str, uuid: &str) -> Value {
    json!({ "type": "vless", "tag": "proxy", "server": host, "server_port": 443, "uuid": uuid,
            "tls": { "enabled": true, "server_name": host } })
}

/// An opened `server-picker` row.
fn row(
    id: &str,
    name: &str,
    host: &str,
    uuid: &str,
    group: Option<&str>,
    device: Option<&str>,
) -> Value {
    json!({ "id": id, "name": name, "protocol": "vless", "server": host, "port": 443,
            "outbound": outbound(host, uuid), "groupId": group, "clientDevice": device,
            "status": "unknown", "ping": null })
}

fn subscription(id: &str, name: &str, url: &str) -> Value {
    json!({ "id": id, "name": name, "source": "subscription", "sourceUrl": url, "importedAt": 5,
            "status": "active" })
}

fn by_id<'a>(doc: &'a ServersDoc, id: &str) -> &'a ServerRow {
    doc.row(&ProfileId::from(id)).expect("row imported")
}

/// Storage spec §7.3 (AT-00-006, AT-01-001): the fixtures import with ids and selection kept,
/// unknown keys ignored, and the result holds keys and the URL only sealed.
#[test]
fn storage_fixtures_import() {
    let link = format!("vless://{UUID_A}@vpn.test:443?security=tls&sni=vpn.test#Fixture");
    let picker = json!({ "schemaVersion": 2, "activeProfileId": "p1", "extension": { "preserve": [1, 2] },
        "profiles": [{ "id": "p1", "name": "Fixture", "protocol": "vless", "server": "vpn.test", "port": 443,
                       "outbound": outbound("vpn.test", UUID_A), "sourceUri": link }] });
    let groups = json!({ "groups": [{ "id": "g1", "name": "Fixture",
                                      "sourceUrl": "https://subscription.test/FAKE-TOKEN" }] });
    let (doc, report) = from_legacy(Some(&picker), Some(&groups), None, NOW);
    assert_eq!((report.imported, report.groups, report.locked), (1, 2, 0));
    assert!(report.skipped.is_empty());
    assert_eq!(doc.active_profile_id, Some(ProfileId::from("p1")));
    let g1 = doc.group(&GroupId::from("g1")).unwrap();
    assert_eq!(
        g1.url().unwrap().as_str(),
        "https://subscription.test/FAKE-TOKEN"
    );
    let p1 = by_id(&doc, "p1");
    assert_eq!(
        (p1.origin, p1.group_id == doc.manual_group().unwrap().id),
        (Origin::Manual, true)
    );
    assert_eq!(p1.profile().unwrap().source, Source::Uri(link));
    let json = serde_json::to_string(&doc).unwrap();
    assert!(
        !json.contains(UUID_A) && !json.contains("FAKE-TOKEN"),
        "{json}"
    );

    let (empty, report) = from_legacy(None, Some(&json!({ "groups": [] })), None, NOW);
    assert_eq!(
        (empty, report),
        (ServersDoc::default(), LegacyReport::default())
    );
}

/// Servers spec §7 #15c: a group whose rows carry several devices becomes one group per device
/// (same URL and metadata, ` · android` on the non-pc copy); rows follow their device.
#[test]
fn mixed_device_groups_are_split() {
    let picker = json!({ "profiles": [
        row("de-pc", "DE", "de.example.com", UUID_A, Some("g1"), None),
        row("nl-pc", "NL", "nl.example.com", UUID_B, Some("g1"), Some("pc")),
        row("de-android", "DE", "de.example.com", UUID_A, Some("g1"), Some("Android")),
    ] });
    let groups =
        json!({ "groups": [subscription("g1", "Provider", "https://sub.example.com/feed")] });
    let (doc, _) = from_legacy(Some(&picker), Some(&groups), None, NOW);
    assert_eq!(doc.groups.len(), 2);
    let pc = doc.group(&GroupId::from("g1")).unwrap();
    let android = doc.groups.iter().find(|g| g.id.as_str() != "g1").unwrap();
    assert_eq!(
        (pc.name.as_str(), pc.device()),
        ("Provider", Some(ClientDevice::Pc))
    );
    assert_eq!(
        (android.name.as_str(), android.device()),
        ("Provider · android", Some(ClientDevice::Android))
    );
    assert_eq!(android.url(), pc.url());
    assert_eq!(
        (android.fetch.clone(), android.info.clone()),
        (pc.fetch.clone(), pc.info.clone())
    );
    for (id, group) in [
        ("de-pc", &pc.id),
        ("nl-pc", &pc.id),
        ("de-android", &android.id),
    ] {
        let r = by_id(&doc, id);
        assert_eq!((&r.group_id, r.origin), (group, Origin::Feed), "{id}");
        assert_eq!(Some(r.device), doc.group(group).unwrap().device());
    }
}

/// Servers spec §7 #15b / §2.1: the feed URL JSON / Clash rows carried is dropped; a per-line
/// link is kept (the row is re-read from it).
#[test]
fn feed_urls_are_not_row_identities() {
    let mut rows = vec![
        row("a", "A", "a.example.com", UUID_A, Some("g1"), None),
        row("b", "B", "b.example.com", UUID_B, Some("g1"), None),
        row("c", "C", "c.example.com", UUID_C, Some("g1"), None),
    ];
    for r in &mut rows[..2] {
        r["sourceUri"] = json!("https://sub.example.com/feed");
    }
    let link = format!("vless://{UUID_C}@c.example.com:443?security=tls&sni=c.example.com#C");
    rows[2]["sourceUri"] = json!(link);
    let groups = json!({ "groups": [subscription("g1", "P", "https://sub.example.com/feed")] });
    let (doc, report) = from_legacy(Some(&json!({ "profiles": rows })), Some(&groups), None, NOW);
    assert_eq!(report.imported, 3);
    assert_eq!(by_id(&doc, "a").profile().unwrap().source, Source::Legacy);
    assert_eq!(by_id(&doc, "b").profile().unwrap().source, Source::Legacy);
    assert_eq!(
        by_id(&doc, "c").profile().unwrap().source,
        Source::Uri(link)
    );
}

/// Servers spec §2.3, S-19 / S-41: the first manual group takes in the other manual groups
/// ("Импортированные"), subscriptions with an unusable URL and rows of unknown groups; the
/// old default names become the default; metadata and the old status map to the new fields.
#[test]
fn groups_map_to_kinds() {
    let mut expired = subscription("g4", "Подписка", "happ://add/https://sub.example.com/feed");
    for (key, value) in [
        ("status", json!("expired")),
        ("refreshIntervalSeconds", json!(12)),
        ("refreshIntervalOverrideMinutes", json!(30)),
        ("trafficUploadBytes", json!(1)),
        ("trafficDownloadBytes", json!(2153701362_u64)),
        ("trafficTotalBytes", json!(0)),
        ("expiresAt", json!(NOW + 1)),
        ("profileTitle", json!("ALL VPN")),
        ("supportUrl", json!("https://t.me/x")),
        ("lastFetchedAt", json!(7)),
        ("lastFetchAttemptAt", json!(8.0)),
        ("lastRefreshProfilesCount", json!(1)),
        ("lastFetchError", json!("old text")),
    ] {
        expired[key] = value;
    }
    let groups = json!({ "groups": [
        { "id": "m1", "name": "Ручные ключи", "source": "manual", "importedAt": 1, "status": "unknown" },
        subscription("g2", "Bogus", "REDACTED"),
        { "id": "m3", "name": "Импортированные", "source": "manual", "importedAt": 2, "status": "unknown" },
        expired,
        { "__vpnteLocked": true },
    ] });
    let picker = json!({ "profiles": [
        row("r1", "1", "a.example.com", UUID_A, Some("m1"), None),
        row("r2", "2", "b.example.com", UUID_A, Some("g2"), None),
        row("r3", "3", "c.example.com", UUID_A, Some("m3"), None),
        row("r4", "4", "d.example.com", UUID_A, Some("g4"), None),
        row("r5", "5", "e.example.com", UUID_A, Some("zz"), None),
        row("r6", "6", "f.example.com", UUID_B, None, None),
    ] });
    let (doc, report) = from_legacy(Some(&picker), Some(&groups), None, NOW);
    assert_eq!((report.groups, report.locked, report.imported), (2, 1, 6));
    let m1 = GroupId::from("m1");
    assert_eq!(
        doc.manual_group().map(|g| (&g.id, g.name.as_str())),
        Some((&m1, ""))
    );
    for id in ["r1", "r2", "r3", "r5", "r6"] {
        assert_eq!(
            (&by_id(&doc, id).group_id, by_id(&doc, id).origin),
            (&m1, Origin::Manual),
            "{id}"
        );
    }
    let g4 = doc.group(&GroupId::from("g4")).unwrap();
    assert_eq!(
        (g4.name.as_str(), g4.url().unwrap().as_str()),
        ("", "https://sub.example.com/feed")
    );
    assert_eq!(
        g4.fetch,
        FetchState {
            last_attempt_at: Some(8),
            last_success_at: Some(7),
            last_outcome: Some(FetchOutcome::EmptyList),
            last_count: Some(1),
        }
    );
    assert_eq!(
        (g4.refresh_override_min, g4.info.refresh_hours),
        (Some(30), Some(12))
    );
    assert_eq!(
        (g4.info.upload, g4.info.download, g4.info.total),
        (Some(1), Some(2153701362), Some(0))
    );
    assert_eq!(
        (g4.info.title.as_deref(), g4.info.support_url.as_deref()),
        (Some("ALL VPN"), Some("https://t.me/x"))
    );
    assert_eq!(g4.status(NOW), GroupStatus::Expired);
    assert_eq!(by_id(&doc, "r4").origin, Origin::Feed);
}

/// Servers spec §2.3, S-11: archive state, verified country (CLDR names first), health and
/// timestamps carry over; storage §7.4: the row port wins and an invalid one gives 443.
#[test]
fn row_fields_map() {
    let mut rows = vec![
        row("a", "A", "a.example.com", UUID_A, None, None),
        row("b", "🇩🇪 B", "b.example.com", UUID_B, None, Some("weird")),
        row("c", "C", "c.example.com", UUID_C, None, None),
        row("a", "dup", "d.example.com", UUID_C, None, None),
    ];
    for (key, value) in [
        ("removedFromSubscriptionAt", json!(11)),
        ("lastSeenInSubscriptionAt", json!(10)),
        ("country", json!("Hong Kong SAR China")),
        ("countryVerifiedAt", json!(9)),
        ("countryVerifiedIp", json!("203.0.113.7")),
        ("healthStatus", json!("offline")),
        ("healthCheckedAt", json!(12)),
        ("healthReason", json!("hy2-udp-blocked")),
        ("healthLatencyMs", json!(812.4)),
        ("egressIp", json!("2001:db8::7")),
    ] {
        rows[0][key] = value;
    }
    rows[1]["enabled"] = json!(false);
    rows[1]["country"] = json!("Netherlands");
    rows[1]["port"] = json!(0);
    rows[1]["outbound"]["server_port"] = json!(8443);
    rows[2]["country"] = json!("Türkiye");
    rows[2]["countryVerifiedAt"] = json!(3);
    rows[2]["healthStatus"] = json!("unknown");
    rows[2].as_object_mut().unwrap().remove("port");
    rows[2]["outbound"]["server_port"] = json!("8443");
    rows[3]["country"] = json!("NL");
    rows[3]["countryVerifiedAt"] = json!(4);
    let (doc, report) = from_legacy(Some(&json!({ "profiles": rows })), None, None, NOW);
    assert_eq!(report.imported, 4);
    let a = by_id(&doc, "a");
    assert_eq!(
        a.archived,
        Some(Archived {
            at: 11,
            reason: ArchiveReason::Provider
        })
    );
    assert_eq!((a.last_seen_at, a.imported_at), (Some(10), NOW));
    let country = a.country.unwrap();
    assert_eq!(
        (country.iso2.as_str(), country.at, country.source),
        ("HK", 9, CountrySource::Legacy)
    );
    assert_eq!(country.ip, Some("203.0.113.7".parse().unwrap()));
    assert_eq!(
        a.health,
        Some(HealthRecord {
            online: false,
            at: 12,
            rtt_ms: Some(812),
            reason: Some(HealthReason::Hy2UdpBlocked),
            egress_ip: Some("2001:db8::7".parse().unwrap()),
        })
    );
    let b = by_id(&doc, "b");
    assert_eq!(
        (b.archived, b.country, b.device, b.port),
        (None, None, ClientDevice::Pc, 443)
    );
    assert_eq!(
        b.display_country().map(Iso2::as_str),
        Some("DE"),
        "claimed from the name"
    );
    let c = by_id(&doc, "c");
    assert_eq!(
        (c.country.map(|c| c.iso2.as_str()), c.health, c.port),
        (Some("TR"), None, 8443)
    );
    let dup = doc.profiles.iter().find(|r| r.name == "dup").unwrap();
    assert_ne!(dup.id.as_str(), "a", "a repeated id gets a fresh one");
    assert_eq!(dup.country.map(|c| c.iso2.as_str()), Some("NL"));
}

/// Storage spec §7.4 (AT-04-008): `normalizeServerPort(profile.port ?? outbound.server_port, 443)`,
/// and the outbound runs on the result.
#[test]
fn ports_are_normalised() {
    let cases = [
        (None, json!("8443"), 8443),
        (Some(json!(0)), json!(8443), 443),
        (Some(json!(65536)), json!(8443), 443),
        (Some(json!(443)), json!(8443), 443),
        (Some(Value::Null), json!(8443), 8443),
    ];
    for (n, (port, server_port, expected)) in cases.into_iter().enumerate() {
        let mut old = row("p", "P", "p.example.com", UUID_A, None, None);
        match port {
            Some(port) => old["port"] = port,
            None => drop(old.as_object_mut().unwrap().remove("port")),
        }
        old["outbound"]["server_port"] = server_port;
        let (doc, _) = from_legacy(Some(&json!({ "profiles": [old] })), None, None, NOW);
        let r = by_id(&doc, "p");
        assert_eq!((r.port, r.profile().unwrap().port), (expected, expected), "case {n}");
    }
}

fn reasons(report: &LegacyReport) -> Vec<(&str, &str)> {
    report
        .skipped
        .iter()
        .map(|s| (s.name.as_str(), s.reason.key.as_ref()))
        .collect()
}

/// Rows whose key waits for the old app's key are counted, broken ones reported by name; a
/// selection that was not imported is dropped.
#[test]
fn locked_and_broken_rows_are_reported() {
    let mut locked = row("l", "Locked", "l.example.com", UUID_A, None, None);
    locked["outbound"] = json!({ "__vpnteLocked": true });
    let mut missing = row("m", "Missing", "m.example.com", UUID_A, None, None);
    missing.as_object_mut().unwrap().remove("outbound");
    let mut ssr = row("s", "Odd", "s.example.com", UUID_A, None, None);
    ssr["outbound"] = json!({ "type": "ssr", "server": "s.example.com", "server_port": 443 });
    let picker = json!({ "activeProfileId": "l",
        "profiles": [locked, missing, ssr, "junk", row("ok", "Ok", "ok.example.com", UUID_B, None, None)] });
    let (doc, report) = from_legacy(Some(&picker), None, None, NOW);
    assert_eq!((report.imported, report.locked), (1, 1));
    assert_eq!(
        reasons(&report),
        [
            ("Missing", "servers.legacy.noOutbound"),
            ("Odd", "profiles.legacy.unsupportedProtocol"),
            ("", "servers.legacy.rowUnreadable"),
        ]
    );
    assert_eq!(doc.active_profile_id, None);
}

/// `backfillMissingOutbounds`: a row saved without its outbound takes it from the old settings
/// cache (same host and port, else same name).
#[test]
fn missing_outbound_comes_from_the_settings_cache() {
    let mut by_host = row("h", "Host", "h.example.com", UUID_A, None, None);
    by_host.as_object_mut().unwrap().remove("outbound");
    let mut by_name = row("n", "Named", "other.example.com", UUID_B, None, None);
    by_name.as_object_mut().unwrap().remove("outbound");
    let settings = json!({ "settings": { "directVpnInput": "", "directVpnCachedProfiles": [
        { "name": "x", "protocol": "vless", "outbound": outbound("h.example.com", UUID_A) },
        { "name": "Named", "protocol": "vless", "outbound": outbound("n.example.com", UUID_B) },
    ] } });
    let picker = json!({ "profiles": [by_host, by_name] });
    let (doc, report) = from_legacy(Some(&picker), None, Some(&settings), NOW);
    assert_eq!((report.imported, report.skipped.len()), (2, 0));
    assert_eq!(by_id(&doc, "h").server, "h.example.com");
    assert_eq!(by_id(&doc, "n").server, "n.example.com");
}

/// Storage spec §7.3 "legacy direct path", AT-09-014: an empty picker takes the accepted cache
/// (the selected index clamped); a cache of a key that was never accepted is ignored.
#[test]
fn direct_vpn_cache_fills_an_empty_list() {
    let settings = |cached: &str| {
        json!({ "settings": { "directVpnInput": " key ", "directVpnCachedInput": cached,
            "directVpnSelectedIndex": 5, "directVpnCachedProfiles": [
                { "name": "One", "protocol": "vless", "outbound": outbound("one.example.com", UUID_A) },
                { "protocol": "vless", "outbound": outbound("two.example.com", UUID_B) },
                { "name": "No outbound" },
            ] } })
    };
    let picker = json!({ "profiles": [], "activeProfileId": null });
    let (doc, report) = from_legacy(Some(&picker), None, Some(&settings("key")), NOW);
    assert_eq!((report.imported, report.groups), (2, 1));
    assert!(doc.profiles.iter().all(|r| r.origin == Origin::Manual));
    assert_eq!(doc.active_profile_id.as_ref(), Some(&doc.profiles[1].id));
    assert_eq!(
        (
            doc.profiles[0].name.as_str(),
            doc.profiles[1].server.as_str()
        ),
        ("One", "two.example.com")
    );

    let (doc, _) = from_legacy(Some(&picker), None, Some(&settings("other")), NOW);
    assert_eq!(doc, ServersDoc::default());
    let with_rows = json!({ "profiles": [row("r", "R", "r.example.com", UUID_C, None, None)] });
    let (doc, _) = from_legacy(Some(&with_rows), None, Some(&settings("key")), NOW);
    assert_eq!(
        doc.profiles.len(),
        1,
        "the cache never adds to an existing list"
    );
}

/// Storage spec §7.3 "legacy direct path": with an empty picker, an input whose cache is not the
/// accepted one (another input, or no cached entries) is handed on raw for an online import; an
/// accepted cache, an existing list or an empty input hand nothing on.
#[test]
fn direct_input_is_handed_on_when_its_cache_was_not_accepted() {
    let settings = |input: &str, cached: &str, entries: Value| {
        json!({ "settings": { "directVpnInput": input, "directVpnCachedInput": cached,
            "directVpnSelectedIndex": 3, "directVpnCachedProfiles": entries } })
    };
    let entry = json!([{ "name": "One", "protocol": "vless",
        "outbound": outbound("one.example.com", UUID_A) }]);
    let empty = json!({ "profiles": [] });
    let direct = |picker: &Value, settings: &Value| {
        from_legacy(Some(picker), None, Some(settings), NOW)
            .1
            .direct
    };
    let expected = Some(LegacyDirect {
        input: Secret::new("https://sub.example.com/feed/token"),
        selected: 3,
    });
    let other = settings(
        " https://sub.example.com/feed/token ",
        "vless://x",
        entry.clone(),
    );
    assert_eq!(direct(&empty, &other), expected);
    let no_entries = settings(
        "https://sub.example.com/feed/token",
        "https://sub.example.com/feed/token",
        json!([]),
    );
    assert_eq!(direct(&empty, &no_entries), expected);
    let (doc, report) = from_legacy(Some(&empty), None, Some(&no_entries), NOW);
    assert_eq!((doc, report.imported), (ServersDoc::default(), 0));

    let accepted = settings("key", "key", entry.clone());
    assert_eq!(direct(&empty, &accepted), None);
    let with_rows = json!({ "profiles": [row("r", "R", "r.example.com", UUID_C, None, None)] });
    assert_eq!(direct(&with_rows, &other), None);
    assert_eq!(direct(&empty, &settings("  ", "", entry)), None);
    assert!(
        !format!("{:?}", direct(&empty, &other)).contains("feed/token"),
        "Debug never shows the input"
    );
}

/// The old geo path stored CLDR English names; key health stored codes.
#[test]
fn legacy_country_names() {
    let cases = [
        ("Netherlands", "NL"),
        ("Türkiye", "TR"),
        ("Hong Kong SAR China", "HK"),
        ("North Macedonia", "MK"),
        ("St. Kitts & Nevis", "KN"),
        ("Bosnia & Herzegovina", "BA"),
        ("Côte d’Ivoire", "CI"),
        ("Congo - Kinshasa", "CD"),
        ("united states", "US"),
        ("de", "DE"),
        ("🇫🇮 Finland", "FI"),
    ];
    for (text, code) in cases {
        assert_eq!(legacy_country(text).map(Iso2::as_str), Some(code), "{text}");
    }
    assert_eq!(legacy_country("Atlantis"), None);
}
