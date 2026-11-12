//! Tests of the refresh: intervals, the due rule, reconcile (servers §7 #1-#3, #6, #7, #15a-b,
//! S-22) and the orchestration over a loopback panel (#4, #8-#10, #15, sweep). Fake keys only.
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::{ClientDevice, Owner, UnixMs, now_ms};
use vpnte_core::net::Route;
use vpnte_core::ops::OperationRegistry;
use vpnte_core::secret::Secret;
use vpnte_profiles::model::{Profile, Source};

use super::*;
use crate::model::tests::{TempDir, UUID_A, UUID_B, UUID_C, vless};
use crate::model::{
    ArchiveReason, Archived, GroupKind, GroupStatus, HealthRecord, Origin, ProfileId,
    ServerReaction, ServerRow, ServerVerdict, VerdictRecord,
};

const MIN: UnixMs = 60_000;
const NOW: UnixMs = 1_800_000_000_000;

fn sub_group(id: &str, url: &str) -> ServerGroup {
    let mut group = ServerGroup::manual(GroupId::from(id), 0);
    group.kind = GroupKind::Subscription {
        url: Secret::new(url),
        device: ClientDevice::Pc,
    };
    group
}

fn row(group: &ServerGroup, profile: &Profile, origin: Origin) -> ServerRow {
    ServerRow::new(
        profile,
        group.id.clone(),
        origin,
        ClientDevice::Pc,
        NOW - 60 * MIN,
    )
    .unwrap()
}

/// The same key as read from a JSON / Clash feed: no per-line link.
fn no_line(mut profile: Profile) -> Profile {
    profile.source = Source::Json;
    profile
}

fn ids(rows: &[ServerRow]) -> Vec<&str> {
    rows.iter().map(|r| r.id.as_str()).collect()
}

/// Servers §7 #11 (S-06): override minutes, provider hours, default 30 min.
#[test]
fn refresh_interval_follows_override_then_provider() {
    let mut g = sub_group("g", "https://sub.example.com/feed");
    let secs = Duration::from_secs;
    assert_eq!(refresh_interval(&g), secs(30 * 60));
    for (hours, want) in [
        (1, 3600),
        (12, 12 * 3600),
        (24, 24 * 3600),
        (5000, 24 * 3600),
    ] {
        g.info.refresh_hours = Some(hours);
        assert_eq!(refresh_interval(&g), secs(want), "{hours} h");
    }
    g.info.refresh_hours = Some(0);
    assert_eq!(refresh_interval(&g), secs(30 * 60));
    g.info.refresh_hours = Some(12);
    g.refresh_override_min = Some(15);
    assert_eq!(refresh_interval(&g), secs(15 * 60));
    g.refresh_override_min = Some(1);
    assert_eq!(refresh_interval(&g), secs(60));
}

/// Servers §7 #12 and S-41: due by last attempt / import; never manual or unusable URLs.
#[test]
fn due_rule() {
    let mut g = sub_group("g", "https://sub.example.com/feed");
    g.imported_at = NOW - 30 * MIN;
    assert!(is_due(&g, NOW));
    g.fetch.last_attempt_at = Some(NOW - MIN);
    assert!(!is_due(&g, NOW));
    g.fetch.last_attempt_at = None;
    g.fetch.last_success_at = Some(NOW - 29 * MIN);
    assert!(!is_due(&g, NOW));
    g.fetch.last_success_at = Some(NOW + 365 * 24 * 60 * MIN);
    assert!(
        is_due(&g, NOW),
        "a stamp from a wrong clock does not stop refreshes"
    );
    let manual = ServerGroup::manual(GroupId::from("m"), 0);
    assert!(!is_due(&manual, NOW));
    let mut redacted = sub_group("r", "REDACTED");
    redacted.kind = GroupKind::Subscription {
        url: Secret::new("REDACTED"),
        device: ClientDevice::Pc,
    };
    assert!(!is_due(&redacted, NOW));
    let mut locked = sub_group("l", "https://sub.example.com/feed");
    locked.kind = GroupKind::Subscription {
        url: Secret::from_stored("dpapi:v1:AAAA".into()),
        device: ClientDevice::Pc,
    };
    assert!(!is_due(&locked, NOW));
}

/// AT-04-007, servers §7 #1 / #3: the same servers keep their ids, by line or (feed without lines)
/// by name.
#[test]
fn same_answer_keeps_ids_and_adds_nothing() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let de = vless("DE", "de.feodorn.com", 443, UUID_A);
    let nl = vless("NL", "nl.feodorn.com", 443, UUID_B);
    let mut rows = vec![row(&g, &de, Origin::Feed), row(&g, &nl, Origin::Feed)];
    let before: Vec<String> = ids(&rows).into_iter().map(str::to_owned).collect();
    for fresh in [
        vec![de.clone(), nl.clone()],
        vec![no_line(de.clone()), no_line(nl.clone())],
    ] {
        let report = reconcile(&g, &mut rows, fresh, true, NOW).unwrap();
        assert_eq!(
            (report.added.len(), report.updated, report.archived),
            (0, 2, 0)
        );
        assert_eq!(ids(&rows), before);
        assert!(
            rows.iter()
                .all(|r| r.last_seen_at == Some(NOW) && r.missing_since.is_none())
        );
    }
}

/// AT-04-007 / AT-04-010, servers §7 #2 (S-01 corrected): a missing key is marked, archived after
/// 15 min of complete
/// answers, and restored when it comes back; a partial answer never touches missing keys.
#[test]
fn missing_keys_wait_out_the_grace_then_archive_and_return() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let de = vless("DE", "de.feodorn.com", 443, UUID_A);
    let nl = vless("NL", "nl.feodorn.com", 443, UUID_B);
    let fr = vless("FR", "fr.feodorn.com", 443, UUID_C);
    let mut rows = vec![row(&g, &de, Origin::Feed), row(&g, &nl, Origin::Feed)];
    let (de_id, nl_id) = (rows[0].id.clone(), rows[1].id.clone());

    let r = reconcile(&g, &mut rows, vec![de.clone()], false, NOW).unwrap();
    assert!(r.partial && r.pending_absent == 0 && rows[1].missing_since.is_none());

    let r = reconcile(&g, &mut rows, vec![de.clone(), fr.clone()], true, NOW).unwrap();
    assert_eq!(
        (r.added.len(), r.updated, r.pending_absent, r.archived),
        (1, 1, 1, 0)
    );
    assert_eq!(rows[0].id, de_id);
    assert_eq!(rows[1].missing_since, Some(NOW));
    assert_eq!(rows.len(), 3);

    let r = reconcile(
        &g,
        &mut rows,
        vec![de.clone(), fr.clone()],
        true,
        NOW + 5 * MIN,
    )
    .unwrap();
    assert_eq!((r.pending_absent, r.archived), (1, 0));
    let later = NOW + 15 * MIN;
    let r = reconcile(&g, &mut rows, vec![de.clone(), fr.clone()], true, later).unwrap();
    assert_eq!((r.archived, r.added.len()), (1, 0));
    let archived = Archived {
        at: later,
        reason: ArchiveReason::Provider,
    };
    assert_eq!(rows[1].archived, Some(archived));
    // Archived rows stay archived on further answers without them.
    let r = reconcile(
        &g,
        &mut rows,
        vec![de.clone(), fr.clone()],
        true,
        later + MIN,
    )
    .unwrap();
    assert_eq!((r.archived, r.pending_absent), (0, 0));

    let r = reconcile(&g, &mut rows, vec![de, nl, fr], true, later + 2 * MIN).unwrap();
    assert_eq!((r.restored, r.updated, r.added.len()), (1, 2, 0));
    let nl_row = rows.iter().find(|r| r.id == nl_id).unwrap();
    assert!(nl_row.archived.is_none() && nl_row.missing_since.is_none());
    assert_eq!(rows.len(), 3);
}

/// Servers §7 #6 / #7 (S-02, S-03): a line appears for a row read without one (name pass); a
/// remark change keeps the row (identity pass) and always takes the fresh name.
#[test]
fn remark_and_line_changes_keep_the_row() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let stored = no_line(vless("DE Node", "de.example", 443, UUID_A));
    let mut rows = vec![row(&g, &stored, Origin::Feed)];
    let fresh = vless("DE%20Node", "de.example", 443, UUID_A);
    let r = reconcile(&g, &mut rows, vec![fresh.clone()], true, NOW).unwrap();
    assert_eq!((r.added.len(), r.updated, r.archived), (0, 1, 0));
    assert_eq!(rows[0].profile().unwrap().source, fresh.source);

    let proxy = vless("proxy", "srv.example", 443, UUID_B);
    let mut rows = vec![row(&g, &proxy, Origin::Feed)];
    let id = rows[0].id.clone();
    let mut renamed = no_line(proxy);
    renamed.name = "🇩🇪 Дарвин ВПН".into();
    let r = reconcile(&g, &mut rows, vec![renamed], true, NOW).unwrap();
    assert_eq!((r.added.len(), r.updated), (0, 1));
    assert_eq!(
        (rows[0].id.clone(), rows[0].name.as_str()),
        (id, "🇩🇪 Дарвин ВПН")
    );
    assert_eq!(rows[0].claimed_country().map(|c| c.as_str()), Some("DE"));
}

/// Servers §7 #15a: locations behind one bridge share host, port and UUID; only unambiguous
/// keys pair, so the selection is never re-pointed to another location.
#[test]
fn ambiguous_keys_never_pair() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let a = vless("DE", "bridge.example", 443, UUID_A);
    let b = vless("NL", "bridge.example", 443, UUID_A);
    let mut rows = vec![row(&g, &a, Origin::Feed), row(&g, &b, Origin::Feed)];
    let (a_id, b_id) = (rows[0].id.clone(), rows[1].id.clone());
    let r = reconcile(&g, &mut rows, vec![b.clone()], true, NOW).unwrap();
    assert_eq!((r.updated, r.added.len(), r.pending_absent), (1, 0, 1));
    assert_eq!(rows[1].id, b_id);
    assert_eq!(rows[1].missing_since, None);
    assert_eq!(
        (rows[0].id.clone(), rows[0].missing_since),
        (a_id, Some(NOW))
    );
    assert_eq!(rows[0].name, "DE", "A was not re-pointed to NL");

    let mut rows = vec![row(&g, &a, Origin::Feed), row(&g, &b, Origin::Feed)];
    let fresh = vec![
        no_line(vless("DE-10GB", "bridge.example", 443, UUID_A)),
        no_line(vless("NL-10GB", "bridge.example", 443, UUID_A)),
    ];
    let r = reconcile(&g, &mut rows, fresh, true, NOW).unwrap();
    assert_eq!((r.updated, r.added.len(), r.pending_absent), (0, 2, 2));
    assert_eq!(rows.len(), 4);
}

/// Servers §7 #15b: a JSON feed (no lines) with the same three servers keeps every id, in any
/// order, without cross-pairing.
#[test]
fn json_feed_rows_pair_by_name() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let keys = [
        ("A", "a.example", UUID_A),
        ("B", "b.example", UUID_B),
        ("C", "c.example", UUID_C),
    ]
    .map(|(n, h, u)| no_line(vless(n, h, 443, u)));
    let mut rows: Vec<ServerRow> = keys.iter().map(|k| row(&g, k, Origin::Feed)).collect();
    let before: Vec<(String, ProfileId)> = rows
        .iter()
        .map(|r| (r.name.clone(), r.id.clone()))
        .collect();
    let fresh = vec![keys[2].clone(), keys[0].clone(), keys[1].clone()];
    let r = reconcile(&g, &mut rows, fresh, true, NOW).unwrap();
    assert_eq!((r.updated, r.added.len()), (3, 0));
    let after: Vec<(String, ProfileId)> = rows
        .iter()
        .map(|r| (r.name.clone(), r.id.clone()))
        .collect();
    assert_eq!(after, before);
}

/// S-22 / S-34: manual rows of a subscription group and other groups' rows are never touched;
/// a row the user removed stays removed while its key is refreshed.
#[test]
fn manual_rows_and_user_archive_are_respected() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let other = sub_group("o", "https://other.example.com/feed");
    let feed = vless("DE", "de.example", 443, UUID_A);
    let pasted = vless("Mine", "mine.example", 443, UUID_B);
    let mut rows = vec![
        row(&g, &feed, Origin::Feed),
        row(&g, &pasted, Origin::Manual),
        row(&other, &pasted, Origin::Feed),
    ];
    rows[0].archived = Some(Archived {
        at: NOW - MIN,
        reason: ArchiveReason::User,
    });
    let mut fresh = feed.clone();
    fresh.port = 8443;
    let r = reconcile(&g, &mut rows, vec![no_line(fresh)], true, NOW).unwrap();
    assert_eq!(
        (r.updated, r.restored, r.added.len(), r.pending_absent),
        (1, 0, 0, 0)
    );
    assert!(rows[0].archived_for(ArchiveReason::User));
    assert_eq!(
        rows[0].port, 8443,
        "the removed row's key is still refreshed"
    );
    assert!(rows[1].missing_since.is_none() && rows[1].archived.is_none());
    assert!(rows[2].missing_since.is_none() && rows[2].last_seen_at.is_none());
}

/// A key the user holds in the group as a manual row (here: a provider-archived key pasted back)
/// is not added again when the provider lists it once more; another group's copy does not count.
#[test]
fn listed_again_key_held_as_manual_row_is_not_duplicated() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let other = sub_group("o", "https://other.example.com/feed");
    let back = vless("DE", "de.example", 443, UUID_A);
    let elsewhere = vless("NL", "nl.example", 443, UUID_B);
    let mut rows = vec![
        row(&g, &back, Origin::Manual),
        row(&other, &elsewhere, Origin::Manual),
    ];
    let r = reconcile(&g, &mut rows, vec![back, elsewhere], true, NOW).unwrap();
    assert_eq!((r.added.len(), r.updated), (1, 0));
    assert_eq!(rows.len(), 3);
    assert_eq!(
        (rows[2].group_id.as_str(), rows[2].name.as_str()),
        ("g", "NL")
    );
}

/// Servers §3.3: health (and the classifier verdict beside it) is cleared when host, port or
/// credential changed; a row whose key cannot be decrypted here is matched by its plain copies
/// and gets the fresh key.
#[test]
fn health_follows_the_endpoint_and_locked_rows_heal() {
    let g = sub_group("g", "https://sub.example.com/feed");
    let health = HealthRecord {
        online: true,
        at: NOW - MIN,
        rtt_ms: Some(40),
        reason: None,
        egress_ip: None,
    };
    let verdict = VerdictRecord {
        verdict: ServerVerdict::IpBanned,
        reaction: ServerReaction::SwitchServer,
        at: NOW - MIN,
    };
    let de = vless("DE", "de.example", 443, UUID_A);
    let nl = vless("NL", "nl.example", 443, UUID_B);
    let mut rows = vec![row(&g, &de, Origin::Feed), row(&g, &nl, Origin::Feed)];
    for row in &mut rows {
        row.health = Some(health);
        row.verdict = Some(verdict);
    }
    let rotated = vless("DE", "de.example", 443, UUID_C);
    let mut remark = no_line(nl.clone());
    remark.name = "NL fast".into();
    let r = reconcile(&g, &mut rows, vec![rotated, remark], true, NOW).unwrap();
    assert_eq!((r.updated, r.added.len()), (2, 0));
    assert_eq!(
        (rows[0].health, rows[0].verdict),
        (None, None),
        "new credential: the old verdicts are void"
    );
    assert_eq!(
        (rows[1].health, rows[1].verdict),
        (Some(health), Some(verdict))
    );

    let mut locked = vec![row(&g, &de, Origin::Feed)];
    locked[0].profile = Secret::from_stored("dpapi:v1:AAAA".into());
    assert!(locked[0].is_locked());
    let r = reconcile(&g, &mut locked, vec![de.clone()], true, NOW).unwrap();
    assert_eq!((r.updated, r.added.len()), (1, 0));
    assert!(!locked[0].is_locked());
    assert_eq!(locked[0].profile().unwrap(), de);
}

// --- orchestration over a loopback panel ---

use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

use parking_lot::Mutex;

use crate::subscription::tests::{KEY_A, KEY_B, Server, fetcher, reply};

struct Env {
    _dir: TempDir,
    servers: Arc<Servers>,
    ctx: RefreshCtx,
}

fn env() -> Env {
    let dir = TempDir::new();
    let servers = Arc::new(Servers::open(&dir.0));
    let ctx = RefreshCtx::new(
        Arc::new(fetcher(vec![Route::Direct])),
        OperationRegistry::new(),
    );
    Env {
        _dir: dir,
        servers,
        ctx,
    }
}

impl Env {
    async fn paste(&self, input: &str, device: ClientDevice) -> AppResult<AddOutcome> {
        let cancel = CancellationToken::new();
        self.servers
            .add_from_input(&self.ctx, input, None, device, cancel)
            .await
    }

    async fn refresh(&self, id: &GroupId, owner: Owner) -> AppResult<RefreshReport> {
        self.servers
            .refresh_group(&self.ctx, id, owner, CancellationToken::new())
            .await
    }

    /// Imports `url` and returns the new group.
    async fn import(&self, url: &Url) -> GroupId {
        match self.paste(url.as_str(), ClientDevice::Pc).await.unwrap() {
            AddOutcome::Added { report, .. } => report.group,
            other => panic!("expected a new group, got {other:?}"),
        }
    }

    fn group(&self, id: &GroupId) -> ServerGroup {
        self.servers.read(|doc| doc.group(id).cloned()).unwrap()
    }

    fn rows(&self) -> Vec<ServerRow> {
        self.servers.read(|doc| doc.profiles.clone())
    }
}

/// A panel serving `KEY_A` + `KEY_B`; `mode` picks the answer: 200 the list, 201 the list titled
/// `ALL VPN`, 0 an empty body, anything else that status.
async fn panel(mode: Arc<Mutex<u16>>) -> Server {
    Server::start(move |_| {
        let list = format!("{KEY_A}\n{KEY_B}\n");
        match *mode.lock() {
            200 => reply("200 OK", &[], list.as_bytes()),
            201 => reply(
                "200 OK",
                &[("profile-title", "base64:QUxMIFZQTg==")],
                list.as_bytes(),
            ),
            0 => reply("200 OK", &[], b""),
            code => reply(&format!("{code} Status"), &[], b""),
        }
    })
    .await
}

/// Servers §3.1, §7 #14 / #15 (S-05, S-20, S-45): a URL creates a subscription group with the
/// provider's title; the same subscription pasted again (any form) refreshes it; another device
/// gets its own group; pasted keys go to the manual group.
#[tokio::test]
async fn pasting_imports_then_refreshes() {
    let e = env();
    let server = panel(Arc::new(Mutex::new(201))).await;
    let url = server.url("/sub/token");
    let out = e.paste(url.as_str(), ClientDevice::Pc).await.unwrap();
    let AddOutcome::Added { report, skipped } = out else {
        panic!("{out:?}")
    };
    assert_eq!((report.added.len(), skipped.len()), (2, 0));
    assert_eq!(report.selected.as_ref(), report.added.first());
    let group = e.group(&report.group);
    assert_eq!(group.name, "ALL VPN");
    assert_eq!(group.status(now_ms()), GroupStatus::Active);

    let again = e
        .paste(&format!("happ://add/{url}"), ClientDevice::Pc)
        .await
        .unwrap();
    let AddOutcome::Refreshed {
        group: same,
        report: refreshed,
    } = again
    else {
        panic!("{again:?}")
    };
    assert_eq!(same, report.group);
    assert_eq!((refreshed.added.len(), refreshed.updated), (0, 2));

    let android = e.paste(url.as_str(), ClientDevice::Android).await.unwrap();
    let AddOutcome::Added { report: second, .. } = android else {
        panic!("{android:?}")
    };
    assert_ne!(second.group, report.group);
    assert_eq!(e.group(&second.group).device(), Some(ClientDevice::Android));
    let android_seen = server
        .seen()
        .last()
        .and_then(|s| s.header("x-device-os").map(str::to_owned));
    assert_eq!(android_seen.as_deref(), Some("Android"));

    let keys = e.paste(KEY_A, ClientDevice::Pc).await.unwrap();
    let AddOutcome::Added { report: manual, .. } = keys else {
        panic!("{keys:?}")
    };
    assert!(e.group(&manual.group).is_manual());
    assert_eq!(e.rows().len(), 5);
    let err = e.paste("no keys here", ClientDevice::Pc).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Validation);
}

/// AT-00-005 / AT-00-007, servers §7 #4, #8, #9: a failed or empty answer changes no row and keeps
/// the selection; the
/// typed outcome drives the status; a later success clears it; the provider title replaces a
/// host-derived name.
#[tokio::test]
async fn failures_keep_rows_and_selection() {
    let e = env();
    let mode = Arc::new(Mutex::new(200));
    let server = panel(mode.clone()).await;
    let id = e.import(&server.url("/feed")).await;
    assert_eq!(e.group(&id).name, "127.0.0.1");
    let (rows, active) = (e.rows(), e.servers.read(|d| d.active_profile_id.clone()));
    let success = e.group(&id).fetch.last_success_at;

    *mode.lock() = 500;
    let err = e.refresh(&id, Owner::Manual).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Network);
    assert_eq!(
        e.group(&id).fetch.last_outcome,
        Some(FetchOutcome::Http(500))
    );
    assert_eq!(e.group(&id).status(now_ms()), GroupStatus::Failed);
    assert_eq!(e.group(&id).fetch.last_success_at, success);

    *mode.lock() = 0;
    let err = e.refresh(&id, Owner::Manual).await.unwrap_err();
    assert_eq!(err.user_msg().key, "servers.fetch.emptyList");
    assert_eq!(e.group(&id).status(now_ms()), GroupStatus::Expired);
    assert_eq!(e.rows(), rows);
    assert_eq!(e.servers.read(|d| d.active_profile_id.clone()), active);

    *mode.lock() = 200;
    let report = e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!((report.added.len(), report.updated), (0, 2));
    assert_eq!(e.group(&id).status(now_ms()), GroupStatus::Active);
    assert_eq!(e.servers.read(|d| d.active_profile_id.clone()), active);

    *mode.lock() = 201;
    e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(
        e.group(&id).name,
        "ALL VPN",
        "a host-derived name follows the provider title"
    );
}

/// AT-00-003, servers §7 #10: the deadline records `Timeout` at that moment (status Unreachable,
/// not due again for the interval); a cancel returns promptly and records only the attempt time.
#[tokio::test]
async fn deadline_and_cancel_bookkeeping() {
    let mut e = env();
    let server = panel(Arc::new(Mutex::new(200))).await;
    let id = e.import(&server.url("/feed")).await;
    let rows = e.rows();
    server.set_delay(Duration::from_secs(30));
    let slow = fetcher(vec![Route::Direct]).with_request_timeout(Duration::from_secs(60));
    e.ctx = RefreshCtx {
        deadline: Duration::from_millis(400),
        ..RefreshCtx::new(Arc::new(slow), e.ctx.ops.clone())
    };
    let admitted = now_ms();
    let err = e.refresh(&id, Owner::Manual).await.unwrap_err();
    assert_eq!(err.kind, ErrorKind::Timeout);
    let group = e.group(&id);
    assert_eq!(group.fetch.last_outcome, Some(FetchOutcome::Timeout));
    assert_eq!(group.status(now_ms()), GroupStatus::Unreachable);
    let at = group.fetch.last_attempt_at.unwrap();
    assert!(
        at >= admitted + 300,
        "stamped at the deadline, not at admission"
    );
    assert!(!is_due(&group, at + MIN) && is_due(&group, at + 30 * MIN));
    assert_eq!(e.rows(), rows);

    e.ctx.deadline = Duration::from_secs(120);
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    });
    let started = Instant::now();
    let err = e
        .servers
        .refresh_group(&e.ctx, &id, Owner::Manual, cancel)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(started.elapsed() < Duration::from_millis(900));
    let after = e.group(&id);
    assert_eq!(
        after.fetch.last_outcome,
        Some(FetchOutcome::Timeout),
        "a cancel records no outcome"
    );
    assert!(after.fetch.last_attempt_at > Some(at));
    assert_eq!(e.rows(), rows);
}

/// Servers §7 #10: the deadline of a refresh whose group was re-pointed meanwhile (its device
/// changed: the Rust form of "URL replaced") writes nothing on the group.
#[tokio::test]
async fn deadline_after_a_device_change_writes_nothing() {
    let mut e = env();
    let server = panel(Arc::new(Mutex::new(200))).await;
    let id = e.import(&server.url("/feed")).await;
    server.set_delay(Duration::from_secs(30));
    let slow = fetcher(vec![Route::Direct]).with_request_timeout(Duration::from_secs(60));
    e.ctx = RefreshCtx {
        deadline: Duration::from_millis(400),
        ..RefreshCtx::new(Arc::new(slow), e.ctx.ops.clone())
    };
    let seen = server.seen().len();
    let (servers, ctx, gid) = (e.servers.clone(), e.ctx.clone(), id.clone());
    let run = tokio::spawn(async move {
        servers
            .refresh_group(&ctx, &gid, Owner::Manual, CancellationToken::new())
            .await
    });
    while server.seen().len() == seen {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let before = e.group(&id).fetch;
    e.servers
        .set_group_device(&id, ClientDevice::Android)
        .unwrap();
    let err = run.await.unwrap().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Timeout);
    assert_eq!(e.group(&id).fetch, before);
}

/// AT-00-003, servers §7 #10: a manual refresh pre-empts a scheduled one; only the manual result
/// persists.
#[tokio::test]
async fn manual_refresh_preempts_the_scheduled_one() {
    let e = env();
    let hits = Arc::new(AtomicUsize::new(0));
    let count = hits.clone();
    let server = Server::start(move |_| match count.fetch_add(1, AtomicOrdering::SeqCst) {
        1 => None,
        _ => reply("200 OK", &[], format!("{KEY_A}\n{KEY_B}\n").as_bytes()),
    })
    .await;
    let id = e.import(&server.url("/feed")).await;
    let (servers, ctx, gid) = (e.servers.clone(), e.ctx.clone(), id.clone());
    let scheduled = tokio::spawn(async move {
        servers
            .refresh_group(&ctx, &gid, Owner::Schedule, CancellationToken::new())
            .await
    });
    while server.seen().len() < 2 {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let report = e.refresh(&id, Owner::Manual).await.unwrap();
    assert_eq!(report.updated, 2);
    assert_eq!(
        scheduled.await.unwrap().unwrap_err().kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        e.group(&id).fetch.last_outcome,
        Some(FetchOutcome::Ok { partial: false })
    );
}

/// AT-00-007, servers §7 #10: a group deleted during the fetch is not resurrected (`Conflict`); a
/// rename made during the fetch survives the provider's title.
#[tokio::test]
async fn edits_during_a_fetch_win() {
    let e = env();
    let mode = Arc::new(Mutex::new(201));
    let server = panel(mode).await;
    let renamed = e.import(&server.url("/one")).await;
    let deleted = e.import(&server.url("/two")).await;
    server.set_delay(Duration::from_millis(500));
    for (id, edit) in [(&renamed, 0), (&deleted, 1)] {
        let (servers, ctx, gid) = (e.servers.clone(), e.ctx.clone(), id.clone());
        let seen = server.seen().len();
        let run = tokio::spawn(async move {
            servers
                .refresh_group(&ctx, &gid, Owner::Manual, CancellationToken::new())
                .await
        });
        while server.seen().len() == seen {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if edit == 0 {
            e.servers.rename_group(id, "Mine").unwrap();
            run.await.unwrap().unwrap();
            assert_eq!(e.group(id).name, "Mine");
        } else {
            e.servers.delete_group(id, true).unwrap();
            let err = run.await.unwrap().unwrap_err();
            assert_eq!(err.user_msg().key, "servers.refresh.groupChanged");
            assert!(e.servers.read(|d| d.group(id).is_none()));
            assert!(e.rows().iter().all(|r| &r.group_id != id));
        }
    }
}

/// Servers §7 #9: a sweep over [500, empty, ok] reports one refresh and two failures; the
/// scheduler stops promptly on shutdown.
#[tokio::test]
async fn sweep_counts_and_scheduler_stops() {
    let e = env();
    let modes = [
        Arc::new(Mutex::new(200)),
        Arc::new(Mutex::new(200)),
        Arc::new(Mutex::new(200)),
    ];
    let mut servers = Vec::new();
    for mode in &modes {
        let server = panel(mode.clone()).await;
        e.import(&server.url("/feed")).await;
        servers.push(server);
    }
    *modes[0].lock() = 500;
    *modes[1].lock() = 0;
    e.servers
        .update(|doc| {
            for g in &mut doc.groups {
                g.fetch.last_attempt_at = Some(now_ms() - 31 * MIN);
            }
            Ok(())
        })
        .unwrap();
    let report = e.servers.sweep(&e.ctx, &CancellationToken::new()).await;
    assert_eq!(
        report,
        SweepReport {
            refreshed: 1,
            failed: 2
        }
    );
    let again = e.servers.sweep(&e.ctx, &CancellationToken::new()).await;
    assert_eq!(again, SweepReport::default(), "nothing is due right after");

    let shutdown = CancellationToken::new();
    let handle = e.servers.spawn_scheduler(e.ctx.clone(), shutdown.clone());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .unwrap()
        .unwrap();
}

/// Storage spec §7.3 `import_legacy_direct`: the old single-key input goes in like a paste (keys
/// parsed, a subscription fetched as `pc`), the old selected index picks the selection (clamped),
/// and a list that is not empty any more is left alone.
#[tokio::test]
async fn legacy_direct_input_goes_in_like_a_paste() {
    use crate::legacy::LegacyDirect;
    let direct = |input: String, selected| LegacyDirect {
        input: Secret::new(input),
        selected,
    };
    let e = env();
    let keys = direct(format!("{KEY_A}\n{KEY_B}"), 1);
    let cancel = CancellationToken::new;
    let out = e
        .servers
        .import_legacy_direct(&e.ctx, &keys, cancel())
        .await;
    let Ok(Some(AddOutcome::Added { report, .. })) = out else {
        panic!("{out:?}")
    };
    assert_eq!(report.added.len(), 2);
    let active = e.servers.active().unwrap();
    assert_eq!((&active.row.id, active.fallback), (&report.added[1], false));
    let again = e
        .servers
        .import_legacy_direct(&e.ctx, &keys, cancel())
        .await;
    assert_eq!(again.unwrap(), None, "only into an empty list");

    let e = env();
    let server = panel(Arc::new(Mutex::new(200))).await;
    let feed = direct(server.url("/sub/token").to_string(), 7);
    let out = e
        .servers
        .import_legacy_direct(&e.ctx, &feed, cancel())
        .await;
    let Ok(Some(AddOutcome::Added { report, .. })) = out else {
        panic!("{out:?}")
    };
    assert!(!e.group(&report.group).is_manual());
    assert_eq!(e.group(&report.group).device(), Some(ClientDevice::Pc));
    let active = e.servers.active().unwrap().row.id;
    assert_eq!(
        Some(&active),
        report.added.last(),
        "index clamped to the list"
    );
}
