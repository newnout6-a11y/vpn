//! The probe-discipline verdicts on the page: the wire-name mapping both ways, the age rule
//! against the health record, and a stored verdict reaching the row through the snapshot.
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::{HealthReason, KeyCheck, KeyHealth};
use vpnte_servers::model::{HealthRecord, ProfileId, ServerReaction, ServerVerdict, VerdictRecord};
use vpnte_ui::servers::{AddTarget, ServersApi, SubscriptionRequest, VerdictAdvice, VerdictKind};

use super::super::ServersBackend;
use super::super::checks::{health_report, updates};
use super::super::verdict::{self, record, view};
use super::backend::{Env, until};
use super::locales;
use super::reports::PASTE;

const VERDICTS: [Verdict; 10] = [
    Verdict::Healthy,
    Verdict::Frozen,
    Verdict::Stalled,
    Verdict::HandshakeFailed,
    Verdict::KeyRejected,
    Verdict::IpBanned,
    Verdict::UdpBlocked,
    Verdict::Offline,
    Verdict::Deferred,
    Verdict::NotVerified,
];
const REACTIONS: [Reaction; 5] = [
    Reaction::None,
    Reaction::SwitchServer,
    Reaction::TryAnotherFingerprint,
    Reaction::PreferTcpTransport,
    Reaction::RetryLater,
];

fn classified(verdict: Verdict, reaction: Reaction) -> Classification {
    Classification { verdict, reaction }
}

/// Every classifier verdict and reaction survives the trip through the list and back to the row
/// with the probes' own sentences.
#[test]
fn verdict_names_map_both_ways() {
    for v in VERDICTS {
        for r in REACTIONS {
            let stored = record(&classified(v, r), 5);
            assert_ne!(stored.verdict, ServerVerdict::Unknown, "{v:?}");
            assert_ne!(stored.reaction, ServerReaction::Unknown, "{r:?}");
            let shown = view(&stored, None).expect("shown");
            assert_eq!((shown.detail, shown.advice_detail), (v.msg(), r.msg()));
            assert_eq!(shown.advice.is_some(), r != Reaction::None, "{r:?}");
            assert_eq!(shown.checked_at, 5);
        }
    }
    let banned = view(
        &record(&classified(Verdict::IpBanned, Reaction::SwitchServer), 1),
        None,
    );
    let banned = banned.expect("shown");
    assert_eq!(banned.kind, VerdictKind::IpBanned);
    assert_eq!(banned.advice, Some(VerdictAdvice::SwitchServer));
}

/// A verdict older than the row's health record is not shown beside it; the same check's is.
#[test]
fn a_younger_health_record_hides_an_older_verdict() {
    let stored = record(&classified(Verdict::Frozen, Reaction::SwitchServer), 100);
    let health = |at| HealthRecord {
        online: true,
        at,
        rtt_ms: Some(80),
        reason: None,
        egress_ip: None,
    };
    assert!(view(&stored, Some(&health(100))).is_some(), "same check");
    assert!(view(&stored, Some(&health(99))).is_some(), "older health");
    assert!(
        view(&stored, Some(&health(101))).is_none(),
        "a later check spoke"
    );
}

/// A name written by a newer version is not shown: nothing is invented.
#[test]
fn unknown_names_are_not_shown() {
    let unknown = VerdictRecord {
        verdict: ServerVerdict::Unknown,
        reaction: ServerReaction::SwitchServer,
        at: 1,
    };
    assert!(view(&unknown, None).is_none());
    let odd_advice = VerdictRecord {
        verdict: ServerVerdict::Stalled,
        reaction: ServerReaction::Unknown,
        at: 1,
    };
    let shown = view(&odd_advice, None).expect("the verdict stands alone");
    assert_eq!((shown.advice, shown.advice_detail), (None, None));
}

/// Keys left without a result (deferred by the budget, probe not started) are counted as not
/// checked, never folded into the total as if they had been checked.
#[test]
fn unchecked_keys_are_counted() {
    let check = KeyCheck {
        health: KeyHealth::offline(HealthReason::Timeout, None),
        verdict: classified(Verdict::Offline, Reaction::None),
    };
    let checked = vec![((ProfileId::from("a"), Some([1; 16])), check)];
    let report = health_report(&checked, 3);
    assert_eq!((report.results.len(), report.not_checked), (1, 2));
    assert_eq!(report.results[0].0, "a");
    assert!(!report.results[0].1.online);
    assert_eq!(health_report(&checked, 1).not_checked, 0);
}

/// A group check's result is stored beside the health record (identity taken before the probe)
/// and the row shows the verdict with its advice.
#[tokio::test]
async fn a_stored_verdict_reaches_the_row() {
    locales();
    let env = Env::new("verdict");
    let api = ServersBackend::start(env.backend.clone());
    let mut state = api.state();
    let paste = PASTE.to_owned();
    api.add(
        paste,
        AddTarget::Auto,
        ClientDevice::Pc,
        SubscriptionRequest::default(),
    )
    .await
    .unwrap();
    let row = env.backend.servers.read(|doc| doc.profiles[0].clone());
    let health = KeyHealth {
        at: now_ms(),
        ..KeyHealth::offline(HealthReason::Timeout, None)
    };
    let check = KeyCheck {
        health,
        verdict: classified(Verdict::Frozen, Reaction::SwitchServer),
    };
    let checked = vec![((row.id.clone(), row.identity()), check)];
    let servers = &env.backend.servers;
    assert_eq!(servers.record_health(updates(&checked)).unwrap(), 1);
    assert_eq!(
        servers.record_verdicts(verdict::updates(&checked)).unwrap(),
        1
    );
    let id = row.id.to_string();
    let view = until(&mut state, |v| {
        v.servers.iter().any(|s| s.id == id && s.verdict.is_some())
    })
    .await;
    let shown = view.servers.iter().find(|s| s.id == id);
    let shown = shown
        .and_then(|s| s.verdict.clone())
        .expect("verdict in the row");
    assert_eq!(shown.kind, VerdictKind::Frozen);
    assert_eq!(shown.advice, Some(VerdictAdvice::SwitchServer));
    assert_eq!(shown.detail.key, "probes.verdict.frozen");
}
