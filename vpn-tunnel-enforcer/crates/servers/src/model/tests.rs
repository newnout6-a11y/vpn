//! Tests of the stored model, and the fixtures the other test modules of the crate share.
use vpnte_base::ErrorKind;
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::model::Profile;

use super::*;

/// Obvious fake credentials only (contract §4.9).
pub(crate) const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
pub(crate) const UUID_B: &str = "22222222-2222-4222-8222-222222222222";
pub(crate) const UUID_C: &str = "33333333-3333-4333-8333-333333333333";

/// A fresh directory under `%TEMP%`, removed on drop (tests never touch the real data dirs).
pub(crate) struct TempDir(pub(crate) std::path::PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vpnte-servers-{}-{:016x}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A VLESS profile `name` on `host:port` with `uuid`.
pub(crate) fn vless(name: &str, host: &str, port: u16, uuid: &str) -> Profile {
    let link = format!("vless://{uuid}@{host}:{port}?security=tls&sni={host}&type=tcp#{name}");
    vpnte_profiles::uri::parse_uri(&link).expect("test link parses")
}

fn group(outcome: Option<FetchOutcome>, expires_at: Option<UnixMs>) -> ServerGroup {
    let mut g = ServerGroup::manual(GroupId::from("g1"), 0);
    g.kind = GroupKind::Subscription {
        url: Secret::new("https://sub.example.com/feed/token"),
        device: ClientDevice::Pc,
    };
    g.fetch.last_outcome = outcome;
    g.info.expires_at = expires_at;
    g
}

/// AT-00-004 / AT-00-005, servers spec §7 #4, #5, #13 and S-23: status is derived from the
/// typed outcome; a passed plan date wins; the manual group has none.
#[test]
fn group_status_is_derived() {
    let now = 1_000_000;
    let ok = Some(FetchOutcome::Ok { partial: false });
    assert_eq!(group(ok, None).status(now), GroupStatus::Active);
    assert_eq!(
        group(ok, Some(now - 60_000)).status(now),
        GroupStatus::Expired
    );
    assert_eq!(
        group(ok, Some(now + 60_000)).status(now),
        GroupStatus::Active
    );
    let cases = [
        (FetchOutcome::EmptyList, GroupStatus::Expired),
        (FetchOutcome::Http(404), GroupStatus::Expired),
        (FetchOutcome::Http(410), GroupStatus::Expired),
        (FetchOutcome::Http(500), GroupStatus::Failed),
        // p-subs: a refused device is not an expired plan.
        (FetchOutcome::HwidRequired, GroupStatus::Failed),
        (FetchOutcome::DeviceLimit, GroupStatus::Failed),
        (
            FetchOutcome::Unparseable(BodyKind::Html),
            GroupStatus::Failed,
        ),
        (
            FetchOutcome::Network(NetFail::Dns),
            GroupStatus::Unreachable,
        ),
        (
            FetchOutcome::Network(NetFail::Tls),
            GroupStatus::Unreachable,
        ),
        (FetchOutcome::Timeout, GroupStatus::Unreachable),
    ];
    for (outcome, status) in cases {
        assert_eq!(
            group(Some(outcome), None).status(now),
            status,
            "{outcome:?}"
        );
    }
    assert_eq!(group(None, None).status(now), GroupStatus::Unknown);
    assert_eq!(
        ServerGroup::manual(GroupId::from("m"), 0).status(now),
        GroupStatus::Unknown
    );
}

/// Servers spec §2.3: the stored wire names of the outcome.
#[test]
fn fetch_outcome_wire_names() {
    let cases = [
        (
            FetchOutcome::Ok { partial: true },
            r#"{"ok":{"partial":true}}"#,
        ),
        (FetchOutcome::EmptyList, r#""empty-list""#),
        (FetchOutcome::HwidRequired, r#""hwid-required""#),
        (FetchOutcome::DeviceLimit, r#""device-limit""#),
        (
            FetchOutcome::Unparseable(BodyKind::Html),
            r#"{"unparseable":"html"}"#,
        ),
        (FetchOutcome::Http(404), r#"{"http":404}"#),
        (FetchOutcome::Network(NetFail::Dns), r#"{"network":"dns"}"#),
        (FetchOutcome::Timeout, r#""timeout""#),
    ];
    for (outcome, json) in cases {
        assert_eq!(serde_json::to_string(&outcome).unwrap(), json);
        assert_eq!(serde_json::from_str::<FetchOutcome>(json).unwrap(), outcome);
    }
}

#[test]
fn group_names_are_trimmed_and_capped() {
    assert_eq!(clean_group_name("  My \n  VPN  "), "My VPN");
    assert_eq!(
        clean_group_name(&"я".repeat(70)).chars().count(),
        GROUP_NAME_MAX_CHARS
    );
    assert_eq!(clean_group_name("   "), "");
    let mut g = ServerGroup::manual(GroupId::from("m"), 0);
    assert_eq!(g.title(), Msg::new("servers.group.manualDefault"));
    g.name = "Work".into();
    assert_eq!(
        g.title(),
        Msg::new("servers.group.title").arg("name", "Work")
    );
    assert_eq!(
        group(None, None).title(),
        Msg::new("servers.group.subscriptionDefault")
    );
}

/// Servers spec §7 #7: the claimed country comes from the name; a verified one wins.
#[test]
fn row_keeps_plain_copies_and_the_sealed_profile() {
    let p = vless("🇩🇪 Дарвин ВПН", "de.example.com", 8443, UUID_A);
    let mut row = ServerRow::new(
        &p,
        GroupId::from("g"),
        Origin::Feed,
        ClientDevice::Android,
        5,
    )
    .unwrap();
    assert_eq!(
        (row.name.as_str(), row.protocol.as_str()),
        ("🇩🇪 Дарвин ВПН", "vless")
    );
    assert_eq!((row.server.as_str(), row.port), ("de.example.com", 8443));
    assert_eq!(row.profile().unwrap(), p);
    assert_eq!(row.identity(), Some(p.identity()));
    assert_eq!(row.claimed_country(), Iso2::new("DE"));
    assert_eq!(row.display_country(), Iso2::new("DE"));
    row.country = Some(VerifiedCountry {
        iso2: Iso2::new("NL").unwrap(),
        at: 6,
        ip: None,
        source: CountrySource::ExitIp,
    });
    assert_eq!(row.display_country(), Iso2::new("NL"));
    let summary = format!("{:?}", ServerSummary::of(&row, None, false));
    assert!(!summary.contains(UUID_A), "summaries never carry secrets");
    row.set_profile(&vless("NL", "nl.example.com", 443, UUID_B))
        .unwrap();
    assert_eq!(
        (row.name.as_str(), row.server.as_str(), row.port),
        ("NL", "nl.example.com", 443)
    );
    assert_eq!(row.purge_at(), None);
    row.archived = Some(Archived {
        at: 10,
        reason: ArchiveReason::User,
    });
    assert_eq!(row.purge_at(), Some(10 + ARCHIVE_TTL_MS));
}

/// S-11 / S-12, servers spec §3.9: an entry-IP lookup never replaces exit evidence younger than
/// 30 days; anything replaces legacy data; the same kind of evidence: the newer wins.
#[test]
fn country_precedence() {
    let c = |source, at| VerifiedCountry {
        iso2: Iso2::new("DE").unwrap(),
        at,
        ip: None,
        source,
    };
    const DAY: UnixMs = 24 * 60 * 60 * 1000;
    assert!(!c(CountrySource::EntryIp, 9).supersedes(&c(CountrySource::ExitIp, 1)));
    assert!(!c(CountrySource::EntryIp, 30 * DAY - 1).supersedes(&c(CountrySource::HealthTrace, 0)));
    assert!(c(CountrySource::EntryIp, 30 * DAY).supersedes(&c(CountrySource::ExitIp, 0)));
    assert!(c(CountrySource::EntryIp, 1).supersedes(&c(CountrySource::Legacy, 9)));
    assert!(c(CountrySource::HealthTrace, 5).supersedes(&c(CountrySource::ExitIp, 4)));
    assert!(!c(CountrySource::ExitIp, 3).supersedes(&c(CountrySource::HealthTrace, 4)));
}

/// AT-01-001: the stored document carries keys and the subscription URL only DPAPI-sealed;
/// it reads back equal (real DPAPI, current user).
#[test]
fn document_round_trip_is_sealed() {
    let mut doc = ServersDoc::default();
    let mut g = group(Some(FetchOutcome::Ok { partial: false }), None);
    g.kind = GroupKind::Subscription {
        url: Secret::new("https://sub.example.com/feed/secret-token"),
        device: ClientDevice::Android,
    };
    doc.groups.push(g);
    let row = ServerRow::new(
        &vless("DE", "de.example.com", 443, UUID_A),
        GroupId::from("g1"),
        Origin::Feed,
        ClientDevice::Android,
        1,
    )
    .unwrap();
    doc.active_profile_id = Some(row.id.clone());
    doc.profiles.push(row);
    let json = serde_json::to_string_pretty(&doc).unwrap();
    assert!(
        !json.contains(UUID_A) && !json.contains("secret-token"),
        "{json}"
    );
    assert!(json.contains(r#""kind": "subscription""#) && json.contains(r#""device": "android""#));
    assert!(json.contains(r#""activeProfileId""#) && json.contains("dpapi:v1:"));
    let back: ServersDoc = serde_json::from_str(&json).unwrap();
    assert_eq!(back, doc);
    assert_eq!(
        back.groups[0].url().unwrap().as_str(),
        "https://sub.example.com/feed/secret-token"
    );
    assert_eq!(back.profiles[0].profile().unwrap().name, "DE");
}

/// A key sealed under another account stays stored, is reported locked and never opens.
#[test]
fn locked_profile_is_reported() {
    let mut row = ServerRow::new(
        &vless("DE", "de.example.com", 443, UUID_A),
        GroupId::from("g"),
        Origin::Manual,
        ClientDevice::Pc,
        1,
    )
    .unwrap();
    row.profile = Secret::from_stored("dpapi:v1:AAAA".into());
    assert!(row.is_locked() && row.identity().is_none());
    let err = row.profile().unwrap_err();
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "servers.locked")
    );
    assert!(ServerSummary::of(&row, None, false).locked);
}

/// AmneziaWG: a row of the new kind carries the protocol label `amneziawg` for the
/// lists, and its sealed profile keeps every AmneziaWG parameter.
#[test]
fn amneziawg_row() {
    let conf = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.1.2/32\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 18\nH1 = 1020325451\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.7:51820\n";
    let p = vpnte_profiles::wg_ini::parse_wg_ini(conf)
        .expect("a .conf")
        .expect("valid");
    let row = ServerRow::new(
        &p,
        GroupId::from("g"),
        Origin::Manual,
        ClientDevice::Android,
        5,
    )
    .unwrap();
    assert_eq!(
        (row.protocol.as_str(), row.server.as_str(), row.port),
        ("amneziawg", "203.0.113.7", 51820)
    );
    assert_eq!(row.profile().unwrap(), p);
    let summary = ServerSummary::of(&row, None, false);
    assert_eq!(summary.protocol, "amneziawg");
}

/// diag-a8: names a newer build writes into the same document version (a new health reason,
/// archive reason, country source, origin, fetch outcome, device or engine) read as their safe
/// fallbacks instead of failing the whole list.
#[test]
fn unknown_stored_names_keep_the_list_readable() {
    let mut doc = ServersDoc::default();
    let mut g = group(Some(FetchOutcome::EmptyList), None);
    g.kind = GroupKind::Subscription {
        url: Secret::new("https://sub.example.com/feed/fake-token"),
        device: ClientDevice::Android,
    };
    doc.groups.push(g);
    let mut row = ServerRow::new(
        &vless("DE", "de.example.com", 443, UUID_A),
        GroupId::from("g1"),
        Origin::Feed,
        ClientDevice::Android,
        1,
    )
    .unwrap();
    row.engine = vpnte_base::types::EnginePref::Xray;
    row.health = Some(HealthRecord {
        online: false,
        at: 2,
        rtt_ms: None,
        reason: Some(HealthReason::ConnectionRefused),
        egress_ip: None,
    });
    row.country = Some(VerifiedCountry {
        iso2: Iso2::new("DE").unwrap(),
        at: 3,
        ip: None,
        source: CountrySource::ExitIp,
    });
    row.archived = Some(Archived {
        at: 4,
        reason: ArchiveReason::Provider,
    });
    doc.profiles.push(row);
    let mut value = serde_json::to_value(&doc).unwrap();
    let newer = serde_json::json!("from-a-newer-build");
    value["groups"][0]["device"] = newer.clone();
    value["groups"][0]["fetch"]["lastOutcome"] = serde_json::json!({ "quic-blocked": 3 });
    let stored = &mut value["profiles"][0];
    for path in ["origin", "device", "engine"] {
        stored[path] = newer.clone();
    }
    stored["health"]["reason"] = newer.clone();
    stored["country"]["source"] = newer.clone();
    // twire-a2: a TLS tricks choice of a newer build, on the row and in the group's controls.
    stored["tlsTricks"] = serde_json::json!({ "set": { "mode": "quantum" } });
    value["groups"][0]["controls"]["tlsTricks"] = serde_json::json!({ "mode": "quantum" });
    let stored = &mut value["profiles"][0];
    stored["archived"]["reason"] = newer;
    let back: ServersDoc = serde_json::from_value(value).unwrap();
    assert_eq!(back.groups[0].device(), Some(ClientDevice::default()));
    assert_eq!(back.groups[0].fetch.last_outcome, None);
    let row = &back.profiles[0];
    assert_eq!(row.origin, Origin::Manual, "a refresh never archives it");
    assert_eq!(row.device, ClientDevice::default());
    assert_eq!(row.engine, vpnte_base::types::EnginePref::Auto);
    let health = row.health.unwrap();
    assert_eq!((health.online, health.reason), (false, None));
    assert_eq!(row.country.unwrap().source, CountrySource::Legacy);
    assert_eq!(
        row.archived.unwrap().reason,
        ArchiveReason::User,
        "never selectable by misreading"
    );
    assert_eq!(row.profile().unwrap().name, "DE");
    assert_eq!(row.tls_tricks, None);
    assert_eq!(back.groups[0].controls.tls_tricks, None);
}
