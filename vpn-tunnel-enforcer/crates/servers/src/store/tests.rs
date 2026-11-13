//! Tests of the server list: selection, adding, archive, groups, probe results, persistence.
use vpnte_base::ErrorKind;
use vpnte_core::secret::Secret;
use vpnte_profiles::model::Profile;

use super::*;
use crate::model::tests::{TempDir, UUID_A, UUID_B, UUID_C, vless};
use crate::model::{Archived, FetchOutcome, Origin};

fn open() -> (TempDir, Servers) {
    let dir = TempDir::new();
    let servers = Servers::open(&dir.0);
    (dir, servers)
}

fn keys(device: ClientDevice) -> AddTarget {
    AddTarget::Keys {
        group: None,
        device,
    }
}

fn sub(url: &str, device: ClientDevice) -> AddTarget {
    AddTarget::Subscription(Box::new(NewSubscription {
        url: url::Url::parse(url).unwrap(),
        device,
        info: SubscriptionMeta::default(),
        partial: false,
        send_hwid: false,
        headers: None,
        controls: Default::default(),
        fallback: None,
        moved_at: None,
    }))
}

const FEED: &str = "https://sub.example.com/feed/token";

fn three() -> Vec<Profile> {
    vec![
        vless("DE", "de.example.com", 443, UUID_A),
        vless("NL", "nl.example.com", 443, UUID_B),
        vless("FR", "fr.example.com", 443, UUID_C),
    ]
}

fn kind_and_key(err: AppError) -> (ErrorKind, String) {
    let key = err.user_msg().key.into_owned();
    (err.kind, key)
}

/// Servers spec §3.1: pasted keys land in the singleton manual group, the first one is
/// selected when nothing was, a repeated key is a duplicate (AT-04-007).
#[test]
fn keys_go_to_the_manual_group() {
    let (_dir, s) = open();
    let report = s
        .add(three()[..2].to_vec(), keys(ClientDevice::Ios))
        .unwrap();
    assert_eq!((report.added.len(), report.duplicates), (2, 0));
    assert_eq!(report.selected.as_ref(), report.added.first());
    let again = s.add(three(), keys(ClientDevice::Pc)).unwrap();
    assert_eq!(
        (again.added.len(), again.duplicates, again.selected),
        (1, 2, None)
    );
    assert_eq!(again.group, report.group);
    s.read(|doc| {
        assert_eq!(doc.groups.len(), 1);
        assert!(doc.groups[0].is_manual());
        assert!(doc.profiles.iter().all(|r| r.origin == Origin::Manual));
        assert_eq!(doc.profiles[0].device, ClientDevice::Ios);
        assert_eq!(doc.profiles[2].device, ClientDevice::Pc);
    });
    let view = s.view();
    assert_eq!(
        (view.active.as_ref(), view.fallback),
        (report.added.first(), false)
    );
    assert_eq!((view.groups[0].servers, view.groups[0].archived), (3, 0));
}

/// Nothing parsed: a validation error and nothing written.
#[test]
fn nothing_to_add_is_an_error() {
    let (dir, s) = open();
    let err = s.add(Vec::new(), keys(ClientDevice::Pc)).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Validation, "servers.parse.nothingFound".into())
    );
    assert!(!dir.0.join("profiles.json").exists());
}

/// Servers spec §7 #15, S-05 / S-21: the group key is (URL, device); a second import of the same
/// pair appends to its group, another device gets its own group; dedupe is per group.
#[test]
fn subscriptions_are_keyed_by_url_and_device() {
    let (_dir, s) = open();
    s.add(three()[..1].to_vec(), keys(ClientDevice::Pc))
        .unwrap();
    let first = s
        .add(three()[..2].to_vec(), sub(FEED, ClientDevice::Pc))
        .unwrap();
    assert_eq!(
        first.added.len(),
        2,
        "keys of the manual group are no duplicates here"
    );
    let url = url::Url::parse(FEED).unwrap();
    assert_eq!(
        s.find_subscription(&url, ClientDevice::Pc),
        Some(first.group.clone())
    );
    let same = s
        .add(three()[1..].to_vec(), sub(FEED, ClientDevice::Pc))
        .unwrap();
    assert_eq!(
        (same.group.clone(), same.added.len(), same.duplicates),
        (first.group.clone(), 1, 1)
    );
    let other = s.add(three(), sub(FEED, ClientDevice::Android)).unwrap();
    assert_ne!(other.group, first.group);
    assert_eq!(
        s.find_subscription(&url, ClientDevice::Android),
        Some(other.group.clone())
    );
    s.read(|doc| {
        let g = doc.group(&first.group).unwrap();
        assert_eq!(
            (g.name.as_str(), g.device()),
            ("sub.example.com", Some(ClientDevice::Pc))
        );
        assert_eq!(
            g.fetch.last_outcome,
            Some(FetchOutcome::Ok { partial: false })
        );
        assert_eq!(g.fetch.last_count, Some(2));
        assert!(g.fetch.last_success_at.is_some() && g.fetch.last_attempt_at.is_some());
        let feed = doc.profiles.iter().filter(|r| r.group_id == other.group);
        assert!(
            feed.clone()
                .all(|r| r.origin == Origin::Feed && r.device == ClientDevice::Android)
        );
        assert_eq!(feed.count(), 3);
    });
}

/// S-48 / servers spec §3.1: provider title, else web page host, else URL host; never the input.
#[test]
fn subscription_names() {
    let url = url::Url::parse(FEED).unwrap();
    let mut info = SubscriptionMeta {
        title: Some("  ALL   VPN ".into()),
        web_page_url: Some("https://panel.example.org/x".into()),
        ..Default::default()
    };
    assert_eq!(subscription_name(&url, &info), "ALL VPN");
    info.title = Some(" ".into());
    assert_eq!(subscription_name(&url, &info), "panel.example.org");
    info.web_page_url = Some("not a url".into());
    assert_eq!(subscription_name(&url, &info), "sub.example.com");
}

/// AT-04-010, servers spec §7 #15 / S-34: remove is a soft delete (not selectable, restorable,
/// purged 30 days later); re-adding the same key brings the row back.
#[test]
fn remove_restore_purge() {
    let (_dir, s) = open();
    let report = s.add(three(), keys(ClientDevice::Pc)).unwrap();
    let (a, b) = (report.added[0].clone(), report.added[1].clone());
    s.remove(&a).unwrap();
    let row = s.get(&a).unwrap();
    let archived = row.archived.unwrap();
    assert_eq!(archived.reason, ArchiveReason::User);
    assert_eq!(
        s.read(|d| d.active_profile_id.clone()),
        None,
        "a removed selection is cleared"
    );
    let err = s.select(&a, SelectBy::User).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.select.archived".into())
    );
    s.restore(&a).unwrap();
    assert!(s.get(&a).unwrap().archived.is_none());
    s.select(&a, SelectBy::User).unwrap();

    s.remove(&b).unwrap();
    let again = s
        .add(three()[1..2].to_vec(), keys(ClientDevice::Pc))
        .unwrap();
    assert_eq!(
        (again.added.len(), again.restored.clone()),
        (0, vec![b.clone()])
    );

    s.remove(&b).unwrap();
    let at = s.get(&b).unwrap().archived.unwrap().at;
    assert_eq!(
        s.purge_expired(at + crate::model::ARCHIVE_TTL_MS - 1)
            .unwrap(),
        0
    );
    assert_eq!(
        s.purge_expired(at + crate::model::ARCHIVE_TTL_MS).unwrap(),
        1
    );
    assert!(s.get(&b).is_none());
    s.purge(&a).unwrap();
    assert_eq!(
        s.read(|d| (d.profiles.len(), d.active_profile_id.clone())),
        (1, None)
    );
    let err = s.purge(&a).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.notFound".into())
    );
}

/// S-22: a key the provider dropped and the user pastes back into its group becomes a manual row
/// (with the paste's device), so the next refresh does not archive it again; a feed row the
/// user removed comes back as a feed row (the provider may still list it).
#[test]
fn pasted_back_provider_key_becomes_manual() {
    let (_dir, s) = open();
    let feed = s.add(three(), sub(FEED, ClientDevice::Pc)).unwrap();
    let (dropped, removed) = (feed.added[0].clone(), feed.added[1].clone());
    s.update(|doc| {
        let row = doc.row_mut(&dropped).unwrap();
        row.archived = Some(Archived {
            at: 1,
            reason: ArchiveReason::Provider,
        });
        row.missing_since = Some(1);
        Ok(())
    })
    .unwrap();
    s.remove(&removed).unwrap();
    let target = AddTarget::Keys {
        group: Some(feed.group.clone()),
        device: ClientDevice::Mac,
    };
    let report = s.add(three()[..2].to_vec(), target).unwrap();
    assert_eq!(report.restored, [dropped.clone(), removed.clone()]);
    let row = s.get(&dropped).unwrap();
    assert_eq!(
        (row.archived, row.missing_since, row.origin, row.device),
        (None, None, Origin::Manual, ClientDevice::Mac)
    );
    let row = s.get(&removed).unwrap();
    assert_eq!(
        (row.archived, row.origin, row.device),
        (None, Origin::Feed, ClientDevice::Pc)
    );
}

/// Servers spec §3.6 / §8 #1: the user may pick a provider-archived row (with a warning),
/// automation may not; a locked key is refused; every selection bumps the geo generation.
#[test]
fn selection_rules() {
    let (_dir, s) = open();
    let ids = s.add(three(), keys(ClientDevice::Pc)).unwrap().added;
    s.update(|doc| {
        doc.row_mut(&ids[1]).unwrap().archived = Some(Archived {
            at: 1,
            reason: ArchiveReason::Provider,
        });
        doc.row_mut(&ids[2]).unwrap().profile = Secret::from_stored("dpapi:v1:AAAA".into());
        Ok(())
    })
    .unwrap();
    let g0 = s.geo_generation();
    s.select(&ids[0], SelectBy::User).unwrap();
    s.select(&ids[0], SelectBy::User).unwrap();
    assert_eq!(
        s.geo_generation(),
        g0 + 2,
        "reselecting supersedes lookups too"
    );
    let err = s.select(&ids[1], SelectBy::Automation).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.select.archived".into())
    );
    s.select(&ids[1], SelectBy::User).unwrap();
    let active = s.active().unwrap();
    assert_eq!(
        (active.row.id.clone(), active.fallback),
        (ids[1].clone(), false)
    );
    let err = s.select(&ids[2], SelectBy::User).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.locked".into())
    );
    let err = s
        .select(&ProfileId::from("nope"), SelectBy::User)
        .unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.notFound".into())
    );
}

/// Storage spec §7.4 "get_profile with fallback", S-37: a selection that is gone falls back to
/// the first usable row and says so.
#[test]
fn active_falls_back_explicitly() {
    let (_dir, s) = open();
    assert!(s.active().is_none());
    let ids = s.add(three(), keys(ClientDevice::Pc)).unwrap().added;
    s.select(&ids[2], SelectBy::User).unwrap();
    let active = s.active().unwrap();
    assert_eq!((active.row.id, active.fallback), (ids[2].clone(), false));
    s.update(|doc| {
        doc.active_profile_id = Some(ids[1].clone());
        Ok(())
    })
    .unwrap();
    s.remove(&ids[1]).unwrap();
    let active = s.active().unwrap();
    assert_eq!(
        (active.row.id.clone(), active.fallback),
        (ids[0].clone(), true)
    );
    let view = s.view();
    assert_eq!((view.active, view.fallback), (Some(ids[0].clone()), true));
    assert!(view.servers[0].selected && !view.servers[2].selected);
    for id in &ids {
        s.remove(id).unwrap();
    }
    assert!(s.active().is_none());
}

/// Servers spec §3.5 / S-40: "keep servers" moves the rows into the manual group at once (as
/// manual rows); deleting with servers drops them and a selection inside.
#[test]
fn delete_group_moves_or_drops_rows() {
    let (_dir, s) = open();
    let feed = s
        .add(three()[..2].to_vec(), sub(FEED, ClientDevice::Android))
        .unwrap();
    s.select(&feed.added[0], SelectBy::User).unwrap();
    s.delete_group(&feed.group, false).unwrap();
    s.read(|doc| {
        assert_eq!(doc.groups.len(), 1);
        let manual = doc.manual_group().unwrap().id.clone();
        assert!(
            doc.profiles
                .iter()
                .all(|r| r.group_id == manual && r.origin == Origin::Manual)
        );
        assert_eq!(doc.profiles[0].device, ClientDevice::Android);
        assert_eq!(doc.active_profile_id.as_ref(), Some(&feed.added[0]));
    });
    let manual = s.read(|d| d.manual_group().unwrap().id.clone());
    let err = s.delete_group(&manual, false).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Validation, "servers.group.keepManual".into())
    );
    s.delete_group(&manual, true).unwrap();
    assert_eq!(
        s.read(|d| (
            d.groups.len(),
            d.profiles.len(),
            d.active_profile_id.clone()
        )),
        (0, 0, None)
    );
    let err = s.delete_group(&manual, true).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.group.notFound".into())
    );
}

/// "Keep servers" never doubles a key: one the manual group already holds stays there once,
/// the subscription's copy goes, and a selection of that copy follows its key.
#[test]
fn keeping_servers_skips_keys_the_manual_group_has() {
    let (_dir, s) = open();
    let mine = s
        .add(three()[..1].to_vec(), keys(ClientDevice::Pc))
        .unwrap();
    let feed = s
        .add(three()[..2].to_vec(), sub(FEED, ClientDevice::Android))
        .unwrap();
    s.select(&feed.added[0], SelectBy::User).unwrap();
    s.delete_group(&feed.group, false).unwrap();
    s.read(|doc| {
        let ids: Vec<&ProfileId> = doc.profiles.iter().map(|r| &r.id).collect();
        assert_eq!(
            ids,
            [&mine.added[0], &feed.added[1]],
            "one copy of each key"
        );
        assert_eq!(doc.active_profile_id.as_ref(), Some(&mine.added[0]));
    });
}

/// Servers spec §3.5 and §7 #11 (override part): rename trims and caps, an empty name changes
/// nothing; the override is 1..=1440 minutes or `None`; manual groups have none.
#[test]
fn group_settings() {
    let (_dir, s) = open();
    let g = s.add(three(), sub(FEED, ClientDevice::Pc)).unwrap().group;
    s.rename_group(&g, "  Work   VPN ").unwrap();
    s.rename_group(&g, "   ").unwrap();
    assert_eq!(s.read(|d| d.group(&g).unwrap().name.clone()), "Work VPN");
    let err = s.rename_group(&GroupId::from("nope"), "x").unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.group.notFound".into())
    );
    for ok in [Some(15), Some(1), Some(1440), None] {
        s.set_refresh_override(&g, ok).unwrap();
        assert_eq!(s.read(|d| d.group(&g).unwrap().refresh_override_min), ok);
    }
    for bad in [Some(0), Some(1441)] {
        let err = s.set_refresh_override(&g, bad).unwrap_err();
        assert_eq!(
            kind_and_key(err),
            (
                ErrorKind::Validation,
                "servers.group.overrideInvalid".into()
            )
        );
    }
    let err = s
        .set_refresh_override(&GroupId::from("nope"), Some(5))
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    let manual = s.add(three(), keys(ClientDevice::Pc)).unwrap().group;
    let err = s.set_refresh_override(&manual, Some(5)).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (
            ErrorKind::Validation,
            "servers.group.manualNoRefresh".into()
        )
    );
}

/// S-05: a subscription's device is a group property; feed rows follow it, hand-added rows in
/// the same group keep their own; the (URL, device) key stays unique.
#[test]
fn device_changes() {
    let (_dir, s) = open();
    let pc = s
        .add(three()[..1].to_vec(), sub(FEED, ClientDevice::Pc))
        .unwrap();
    let extra = AddTarget::Keys {
        group: Some(pc.group.clone()),
        device: ClientDevice::Mac,
    };
    let manual_row = s.add(three()[1..2].to_vec(), extra).unwrap().added[0].clone();
    assert_eq!(s.get(&manual_row).unwrap().origin, Origin::Manual, "S-22");
    s.add(three()[2..].to_vec(), sub(FEED, ClientDevice::Ios))
        .unwrap();
    let err = s
        .set_group_device(&pc.group, ClientDevice::Ios)
        .unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Conflict, "servers.group.deviceTaken".into())
    );
    s.set_group_device(&pc.group, ClientDevice::Android)
        .unwrap();
    assert_eq!(s.get(&pc.added[0]).unwrap().device, ClientDevice::Android);
    assert_eq!(s.get(&manual_row).unwrap().device, ClientDevice::Mac);
    let url = url::Url::parse(FEED).unwrap();
    assert_eq!(
        s.find_subscription(&url, ClientDevice::Android),
        Some(pc.group.clone())
    );
    let err = s
        .set_profile_device(&pc.added[0], ClientDevice::Pc)
        .unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Validation, "servers.deviceFollowsGroup".into())
    );
    s.set_profile_device(&manual_row, ClientDevice::Pc).unwrap();
    assert_eq!(s.get(&manual_row).unwrap().device, ClientDevice::Pc);
    let manual = s.add(three(), keys(ClientDevice::Pc)).unwrap().group;
    let err = s.set_group_device(&manual, ClientDevice::Ios).unwrap_err();
    assert_eq!(
        kind_and_key(err),
        (ErrorKind::Validation, "servers.group.manualNoDevice".into())
    );
}

/// ENGINE-GAPS decision 3: every row (feed rows too) keeps its own engine; `Auto` is not
/// written, so older files and rows without a choice keep their shape.
#[test]
fn engine_override_per_row() {
    use vpnte_base::types::EnginePref;
    let (_dir, s) = open();
    let feed = s
        .add(three()[..1].to_vec(), sub(FEED, ClientDevice::Pc))
        .unwrap();
    let id = feed.added[0].clone();
    assert_eq!(s.get(&id).unwrap().engine, EnginePref::Auto);
    s.set_profile_engine(&id, EnginePref::SingBox).unwrap();
    assert_eq!(s.get(&id).unwrap().engine, EnginePref::SingBox);
    let summary = s.view().servers.into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(summary.engine, EnginePref::SingBox);
    let json = serde_json::to_value(s.get(&id).unwrap()).unwrap();
    assert_eq!(json["engine"], "sing-box");
    s.set_profile_engine(&id, EnginePref::Auto).unwrap();
    let json = serde_json::to_value(s.get(&id).unwrap()).unwrap();
    assert!(json.get("engine").is_none(), "{json}");
    let gone = ProfileId::from("gone");
    let err = s.set_profile_engine(&gone, EnginePref::Xray).unwrap_err();
    assert_eq!(kind_and_key(err).1, "servers.notFound");
}

fn record(online: bool) -> HealthRecord {
    HealthRecord {
        online,
        at: 7,
        rtt_ms: Some(812),
        reason: None,
        egress_ip: Some("203.0.113.7".parse().unwrap()),
    }
}

fn country(code: &str, source: crate::model::CountrySource) -> VerifiedCountry {
    VerifiedCountry {
        iso2: vpnte_profiles::countries::Iso2::new(code).unwrap(),
        at: 7,
        ip: Some("203.0.113.7".parse().unwrap()),
        source,
    }
}

/// S-13, servers spec §3.11: a key that changed, vanished or was removed by the user while the
/// probe ran is skipped on its own; the others still land, with the trace's exit country.
#[test]
fn health_is_skipped_per_row() {
    use crate::model::CountrySource;
    let (_dir, s) = open();
    let mut ids = s.add(three(), keys(ClientDevice::Pc)).unwrap().added;
    ids.extend(
        s.add(
            vec![vless("SE", "se.example.com", 443, UUID_A)],
            keys(ClientDevice::Pc),
        )
        .unwrap()
        .added,
    );
    let probe: Vec<HealthUpdate> = ids
        .iter()
        .map(|id| HealthUpdate {
            id: id.clone(),
            identity: s.get(id).unwrap().identity().unwrap(),
            record: record(true),
            country: Some(country("FR", CountrySource::HealthTrace)),
        })
        .collect();
    s.update(|doc| {
        doc.row_mut(&ids[1])
            .unwrap()
            .set_profile(&vless("NL", "nl2.example.com", 443, UUID_B))
    })
    .unwrap();
    s.purge(&ids[2]).unwrap();
    s.remove(&ids[3]).unwrap();
    assert_eq!(s.record_health(probe).unwrap(), 1);
    let a = s.get(&ids[0]).unwrap();
    assert_eq!(
        (a.health, a.country.map(|c| c.iso2.as_str())),
        (Some(record(true)), Some("FR"))
    );
    assert_eq!(s.get(&ids[1]).unwrap().health, None);
    assert_eq!(s.get(&ids[3]).unwrap().health, None);
}

/// psmall-a2: a list check that ran for minutes lands after a later check of the same key: the
/// older record never replaces the newer one (as for verdicts).
#[test]
fn an_older_health_record_never_replaces_a_newer_one() {
    let (_dir, s) = open();
    let id = s.add(three(), keys(ClientDevice::Pc)).unwrap().added[0].clone();
    let identity = s.get(&id).unwrap().identity().unwrap();
    let at = |at, online| HealthUpdate {
        id: id.clone(),
        identity,
        record: HealthRecord {
            at,
            ..record(online)
        },
        country: None,
    };
    assert_eq!(s.record_health(vec![at(60, true)]).unwrap(), 1);
    assert_eq!(s.record_health(vec![at(10, false)]).unwrap(), 0);
    assert_eq!(
        s.get(&id).unwrap().health.map(|h| (h.at, h.online)),
        Some((60, true))
    );
    assert_eq!(s.record_health(vec![at(90, false)]).unwrap(), 1);
}

/// Servers spec §3.9 / S-12: an exit lookup started before a selection is discarded, an
/// entry-IP lookup is not (it does not depend on the selection) but never replaces exit evidence.
#[test]
fn country_needs_the_current_generation() {
    use crate::model::CountrySource;
    let (_dir, s) = open();
    let ids = s.add(three(), keys(ClientDevice::Pc)).unwrap().added;
    let before = s.geo_generation();
    s.select(&ids[1], SelectBy::User).unwrap();
    assert!(
        !s.record_country(&ids[1], country("DE", CountrySource::ExitIp), before)
            .unwrap()
    );
    assert!(
        s.record_country(&ids[0], country("SE", CountrySource::EntryIp), before)
            .unwrap()
    );
    let now = s.geo_generation();
    assert!(
        s.record_country(&ids[1], country("DE", CountrySource::ExitIp), now)
            .unwrap()
    );
    assert!(
        !s.record_country(&ids[1], country("NL", CountrySource::EntryIp), now)
            .unwrap()
    );
    assert_eq!(
        s.get(&ids[1])
            .unwrap()
            .display_country()
            .map(|c| c.as_str()),
        Some("DE")
    );
    assert!(
        !s.record_country(
            &ProfileId::from("nope"),
            country("DE", CountrySource::ExitIp),
            now
        )
        .unwrap()
    );
}

/// Servers spec §7 #24, S-10: pings live in memory only and are announced.
#[test]
fn pings_are_memory_only() {
    let dir = TempDir::new();
    let s = Servers::open(&dir.0);
    let id = s.add(three(), keys(ClientDevice::Pc)).unwrap().added[0].clone();
    let mut events = s.subscribe();
    s.record_ping(&id, Some(42));
    s.record_ping(&ProfileId::from("nope"), Some(1));
    assert_eq!(events.try_recv().unwrap(), ServersEvent::Ping(id.clone()));
    assert!(events.try_recv().is_err(), "unknown rows are ignored");
    let ping = s.view().servers[0].ping.unwrap();
    assert_eq!(ping.rtt_ms, Some(42));
    drop(s);
    let text = std::fs::read_to_string(dir.0.join("profiles.json")).unwrap();
    assert!(!text.contains("rttMs") && !text.contains("ping"));
    assert_eq!(Servers::open(&dir.0).view().servers[0].ping, None);
}

/// Listeners hear about a change only once it is saved; a no-op is silent.
#[test]
fn events_follow_saved_changes() {
    let (_dir, s) = open();
    let mut events = s.subscribe();
    let report = s.add(three(), keys(ClientDevice::Pc)).unwrap();
    assert_eq!(events.try_recv().unwrap(), ServersEvent::Changed);
    assert_eq!(
        events.try_recv().unwrap(),
        ServersEvent::ActiveChanged(report.selected.clone())
    );
    s.rename_group(&report.group, "  ").unwrap();
    s.select(&report.added[0], SelectBy::User).unwrap();
    assert!(events.try_recv().is_err(), "nothing changed, nothing sent");
}

/// A failing change leaves no trace: nothing half-applied is saved or announced.
#[test]
fn failed_update_is_rolled_back() {
    let (dir, s) = open();
    s.add(three(), keys(ClientDevice::Pc)).unwrap();
    let before = s.read(Clone::clone);
    let saved = std::fs::read(dir.0.join("profiles.json")).unwrap();
    let mut events = s.subscribe();
    let err = s
        .update(|doc| {
            doc.groups.clear();
            doc.profiles.truncate(1);
            Err::<(), _>(AppError::conflict(Msg::new("servers.notFound")))
        })
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    assert!(s.read(|doc| *doc == before));
    assert_eq!(std::fs::read(dir.0.join("profiles.json")).unwrap(), saved);
    assert!(events.try_recv().is_err());
}

/// AT-01-001: the list survives a restart; keys and the subscription URL are sealed on disk.
#[test]
fn persists_sealed_and_reloads() {
    let dir = TempDir::new();
    let report = {
        let s = Servers::open(&dir.0);
        s.add(three(), sub(FEED, ClientDevice::Pc)).unwrap()
    };
    let text = std::fs::read_to_string(dir.0.join("profiles.json")).unwrap();
    assert!(
        text.starts_with(
            "{
  \"schemaVersion\": 1"
        ),
        "{text}"
    );
    for secret in [UUID_A, UUID_B, UUID_C, "feed/token"] {
        assert!(!text.contains(secret), "{secret} leaked");
    }
    let s = Servers::open(&dir.0);
    let view = s.view();
    assert_eq!(
        (view.servers.len(), view.active.clone()),
        (3, report.selected.clone())
    );
    assert_eq!(view.groups[0].host.as_deref(), Some("sub.example.com"));
    assert!(
        !format!("{view:?}").contains("token"),
        "views never carry secrets"
    );
    assert_eq!(
        s.get(&report.added[0]).unwrap().profile().unwrap().name,
        "DE"
    );
}

/// Archive rows past 30 days are purged when the list is opened (servers spec §3.4).
#[test]
fn open_purges_old_archive() {
    let dir = TempDir::new();
    let ids = {
        let s = Servers::open(&dir.0);
        let ids = s.add(three(), keys(ClientDevice::Pc)).unwrap().added;
        s.update(|doc| {
            doc.row_mut(&ids[0]).unwrap().archived = Some(Archived {
                at: 1,
                reason: ArchiveReason::Provider,
            });
            Ok(())
        })
        .unwrap();
        ids
    };
    let s = Servers::open(&dir.0);
    assert!(s.get(&ids[0]).is_none());
    assert_eq!(
        s.read(|d| d.active_profile_id.clone()),
        None,
        "the purged selection is cleared"
    );
    assert_eq!(s.view().servers.len(), 2);
}

/// The one-time import only fills an empty list.
#[test]
fn legacy_import_only_into_an_empty_list() {
    let (_dir, s) = open();
    let mut doc = ServersDoc::default();
    let manual = doc.ensure_manual_group(1);
    doc.profiles
        .push(ServerRow::new(&three()[0], manual, Origin::Manual, ClientDevice::Pc, 1).unwrap());
    assert!(s.import_legacy(doc.clone()).unwrap());
    assert_eq!(s.read(Clone::clone), doc);
    assert!(!s.import_legacy(ServersDoc::default()).unwrap());
    assert_eq!(s.read(|d| d.profiles.len()), 1);
}

#[test]
fn all_hosts_are_distinct() {
    let (_dir, s) = open();
    s.add(three(), keys(ClientDevice::Pc)).unwrap();
    s.add(
        vec![vless("DE2", "DE.example.com", 8443, UUID_B)],
        keys(ClientDevice::Pc),
    )
    .unwrap();
    assert_eq!(
        s.all_hosts(),
        ["de.example.com", "nl.example.com", "fr.example.com"]
    );
}
