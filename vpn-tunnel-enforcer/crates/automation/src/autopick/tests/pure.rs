//! The pure parts: the launch rule, the ranking, the stall window, the warm-up pick, the texts.
use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::test_support::has_key;

/// RU item 7, the rule: the user's choice wins (an explicit Off over the provider's word); then
/// the provider's word; off by default. Review fix a10/b3: nothing else turns it on (the old
/// version's `autoPilotEnabled` was on by default and never connected server-list users).
#[test]
fn the_launch_rule_is_off_unless_someone_said_otherwise() {
    use LaunchChoice as C;
    use LaunchPick as P;
    use ProviderWord as W;
    let cases = [
        (None, None, None, LaunchSource::Default),
        (None, Some(W::Off), None, LaunchSource::Provider),
        (
            None,
            Some(W::On(P::LowestDelay)),
            Some(P::LowestDelay),
            LaunchSource::Provider,
        ),
        (
            None,
            Some(W::On(P::Random)),
            Some(P::Random),
            LaunchSource::Provider,
        ),
        (
            Some(C::Off),
            Some(W::On(P::LastUsed)),
            None,
            LaunchSource::User,
        ),
        (
            Some(C::LastUsed),
            Some(W::Off),
            Some(P::LastUsed),
            LaunchSource::User,
        ),
        (
            Some(C::LowestDelay),
            None,
            Some(P::LowestDelay),
            LaunchSource::User,
        ),
    ];
    for (choice, word, want, source) in cases {
        assert_eq!(launch_pick(choice, word), want, "{choice:?} {word:?}");
        assert_eq!(launch_source(choice, word), source, "{choice:?} {word:?}");
    }
}

#[test]
fn the_document_keeps_only_a_choice_made() {
    let none = serde_json::to_string(&AutoPickConfig::default()).unwrap();
    assert_eq!(none, "{}");
    let doc: AutoPickConfig = serde_json::from_str(r#"{"launch":"lowest-delay"}"#).unwrap();
    assert_eq!(doc.launch, Some(LaunchChoice::LowestDelay));
}

#[test]
fn ranking_puts_evidence_then_latency_then_store_order() {
    let mut dead = server("dead", "g");
    dead.alive = Some(false);
    let mut slow = server("slow", "g");
    (slow.alive, slow.latency_ms) = (Some(true), Some(300));
    let mut fast = server("fast", "g");
    (fast.alive, fast.latency_ms) = (Some(true), Some(80));
    let unknown = server("unknown", "g");
    let all = [dead, unknown, slow, fast];
    let ids: Vec<&str> = rank(&all, &Network::default(), |id| id == "skip")
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(ids, ["fast", "slow", "unknown", "dead"]);
    let ids: Vec<&str> = rank(&all, &Network::default(), |id| id == "fast")
        .iter()
        .map(|c| c.id.as_str())
        .collect();
    assert_eq!(ids, ["slow", "unknown", "dead"]);
}

fn counters(up: u64, down: u64) -> Counters {
    Counters {
        up,
        down,
        proxy_down: false,
    }
}

/// RU item 7: the upload grows for a whole window while the download stays flat.
#[test]
fn a_stall_needs_a_whole_window_of_upload_without_download() {
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let mut d = Detector::new();
    assert_eq!(d.push(at(0), counters(1_000, 50_000)), Suspicion::None);
    assert_eq!(d.push(at(15), counters(4_000, 50_100)), Suspicion::None);
    // 30 s: 8 KiB sent, 300 bytes received.
    assert_eq!(d.push(at(30), counters(9_200, 50_300)), Suspicion::Stalled);
    // A real answer arrives: the window holds download again.
    assert_eq!(d.push(at(35), counters(9_300, 90_000)), Suspicion::None);
}

#[test]
fn an_idle_session_and_a_working_one_are_no_stall() {
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let mut idle = Detector::new();
    idle.push(at(0), counters(100, 100));
    assert_eq!(idle.push(at(40), counters(300, 100)), Suspicion::None);
    let mut busy = Detector::new();
    busy.push(at(0), counters(0, 0));
    assert_eq!(
        busy.push(at(40), counters(20_000, 400_000)),
        Suspicion::None
    );
}

#[test]
fn a_new_engine_run_starts_the_window_over_and_the_watchdog_counts_at_once() {
    let t0 = Instant::now();
    let at = |s: u64| t0 + Duration::from_secs(s);
    let mut d = Detector::new();
    d.push(at(0), counters(50_000, 900_000));
    // Totals went back: a new run, no full window yet.
    assert_eq!(d.push(at(30), counters(9_000, 100)), Suspicion::None);
    let down = Counters {
        proxy_down: true,
        ..counters(9_100, 100)
    };
    assert_eq!(d.push(at(35), down), Suspicion::ProxyDown);
}

#[test]
fn the_warm_up_checks_the_stalest_of_the_next_candidates_never_the_running_one() {
    let now = 50 * 60 * 1000;
    let mut a = server("a", "g1");
    (a.alive, a.latency_ms, a.checked_at) = (Some(true), Some(50), Some(now - 60_000));
    let mut b = server("b", "g1");
    (b.alive, b.checked_at) = (Some(true), Some(now - 20 * 60_000));
    let c = server("c", "g2");
    let mut running = server("run", "g1");
    running.checked_at = None;
    let all = vec![running, a.clone(), b, c];
    // a is fresh; b (20 min) and c (never) are stale: never checked goes first.
    assert_eq!(
        next_to_warm(&all, &Network::default(), "run", now).map(|c| c.id.as_str()),
        Some("c")
    );
    let mut fresh = all.clone();
    fresh[3].checked_at = Some(now - 1_000);
    assert_eq!(
        next_to_warm(&fresh, &Network::default(), "run", now).map(|c| c.id.as_str()),
        Some("b")
    );
    fresh[2].checked_at = Some(now - 1_000);
    assert_eq!(next_to_warm(&fresh, &Network::default(), "run", now), None);
}

/// Review fix a8/b2/b10: the status carries no traffic claim of its own; every step shows the
/// live one, and every text exists.
#[test]
fn every_status_text_exists() {
    let phases = [
        Phase::Launching,
        Phase::Confirming,
        Phase::Refreshing,
        Phase::Trying,
        Phase::Waiting,
        Phase::GaveUp,
    ];
    let exposures = [
        Exposure::Direct,
        Exposure::Blocked,
        Exposure::ProxyBlocked,
        Exposure::Tunnel,
        Exposure::ProxyTunnel,
        Exposure::Unknown,
    ];
    for phase in phases {
        let status = PickStatus {
            phase,
            ..PickStatus::default()
        };
        let head = status.headline().unwrap();
        assert!(has_key(&head.key), "{}", head.key);
        for exposure in exposures {
            let line = status.exposure_line(exposure).unwrap();
            assert_eq!(line, exposure.msg());
            assert!(has_key(&line.key), "{}", line.key);
        }
    }
    assert_eq!(PickStatus::default().headline(), None);
    assert_eq!(PickStatus::default().exposure_line(Exposure::Direct), None);
    for key in [
        "launch.failed",
        "launch.connected",
        "rescue.recovered",
        "rescue.gaveUp",
    ] {
        assert!(has_key(&format!("automation.autopick.{key}")), "{key}");
    }
}
