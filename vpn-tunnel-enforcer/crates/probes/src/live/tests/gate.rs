//! The engine stage through the handshake budget (probe-discipline, fact a): dials one at a time
//! in order of value, what the budget does not allow before the deadline is left out and named,
//! never dialled in a burst and never reported as a failure.
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_profiles::model::Profile;

use super::engine::vless;
use super::socks::{Reply, fake_socks, http};
use crate::discipline::{Endpoint, budget};
use crate::live::check::hello_skip;
use crate::live::engine_probe::{Gate, assemble, measure};
use crate::live::model::{
    EgressStatus, EngineRoute, HandshakeStatus, MediaStatus, ThroughputStatus,
};
use crate::live::wire::Wire;
use crate::live_stages::NotCheckedReason;

/// The test profile under its own server name: the budget is process-wide.
fn named(name: &str) -> Profile {
    let mut p = vless();
    if let Some(tls) = p.tls.as_mut() {
        tls.server_name = Some(name.into());
    }
    p
}

fn answers(host: &str) -> Reply {
    match host {
        "1.1.1.1" => http("200 OK", b"fl=1\nip=95.165.12.34\nloc=DE\n"),
        "api.ipify.org" => http("200 OK", b"95.165.12.34"),
        "api6.ipify.org" => http("200 OK", b"2a02:6b8::1"),
        _ => http("200 OK", b""),
    }
}

/// Three slots per minute: the trace, the second IPv4 answer and the first media host go
/// through (400 ms apart); IPv6 and the second media host are left out and named.
#[tokio::test]
async fn the_budget_spaces_and_trims_the_dials() {
    let fake = fake_socks(answers).await;
    let profile = named("gate-trim.example.test");
    let gate = Gate::new(&profile, Some(Instant::now() + Duration::from_secs(30))).unwrap();
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let m = measure(&Wire::plain(), &fake.inbound, None, Some(&gate), &cancel).await;
    assert!(started.elapsed() >= Duration::from_millis(800), "spaced");
    assert_eq!((m.reflectors.len(), m.media.len(), m.deferred), (2, 1, 2));
    let mut dialled = fake.targets.lock().clone();
    dialled.sort();
    assert_eq!(
        dialled,
        ["1.1.1.1:443", "api.ipify.org:443", "usher.ttvnw.net:443"]
    );
    let stage = assemble(m, &profile, None, EngineRoute::PhysicalDirect, 1, "");
    assert_eq!(stage.handshake.status, HandshakeStatus::Ok);
    assert!(
        stage.handshake.note.is_some(),
        "the left-out dials are named"
    );
    assert_eq!(stage.egress.reflectors.len(), 2);
    assert_ne!(stage.media.status, MediaStatus::Skipped);
}

/// A budget already used up by other checks: nothing is dialled, the stage says why and does
/// not call the server broken.
#[tokio::test]
async fn an_exhausted_budget_dials_nothing() {
    let fake = fake_socks(answers).await;
    let profile = named("gate-full.example.test");
    let endpoint = Endpoint::of(&profile).unwrap();
    let cancel = CancellationToken::new();
    for _ in 0..3 {
        budget()
            .acquire(&endpoint, Duration::from_secs(2), &cancel)
            .await
            .unwrap();
    }
    let gate = Gate::new(&profile, Some(Instant::now() + Duration::from_secs(20))).unwrap();
    let m = measure(&Wire::plain(), &fake.inbound, None, Some(&gate), &cancel).await;
    assert_eq!(m.deferred, 5);
    assert!(fake.targets.lock().is_empty(), "no dial at all");
    let stage = assemble(m, &profile, None, EngineRoute::PhysicalDirect, 1, "");
    assert_eq!(stage.handshake.status, HandshakeStatus::Skipped);
    assert!(stage.handshake.error.is_none() && stage.handshake.note.is_some());
    assert_eq!(stage.media.status, MediaStatus::Skipped);
    // The exit was never asked: unknown, not an egress error.
    assert_eq!(stage.egress.status, EgressStatus::Skipped);
    assert!(stage.egress.error.is_none() && stage.egress.note.is_some());
}

/// Throughput asked for under a used-up budget: no sample is dialled and the section is
/// `skipped` with the deferred note, never a failed measurement.
#[tokio::test]
async fn a_deferred_throughput_series_is_skipped() {
    let fake = fake_socks(answers).await;
    let profile = named("gate-speed.example.test");
    let endpoint = Endpoint::of(&profile).unwrap();
    let cancel = CancellationToken::new();
    for _ in 0..3 {
        budget()
            .acquire(&endpoint, Duration::from_secs(2), &cancel)
            .await
            .unwrap();
    }
    let gate = Gate::new(&profile, Some(Instant::now() + Duration::from_secs(20))).unwrap();
    let route = Some(EngineRoute::PhysicalDirect);
    let m = measure(&Wire::plain(), &fake.inbound, route, Some(&gate), &cancel).await;
    assert!(fake.targets.lock().is_empty(), "no dial at all");
    let t = m.throughput.clone().unwrap();
    assert_eq!(t.status, ThroughputStatus::Skipped);
    assert!(t.error.is_none() && t.samples.is_empty() && t.detail.is_some());
    assert_eq!(m.deferred, 8);
}

/// A budget with one slot left and a refusing exit: the handshake fails on that one dial and
/// still names the four dials it never made (the verdict rests on one attempt).
#[tokio::test]
async fn a_failed_handshake_names_the_deferred_dials() {
    let fake = fake_socks(|_| Reply::Refuse(5)).await;
    let profile = named("gate-fail.example.test");
    let endpoint = Endpoint::of(&profile).unwrap();
    let cancel = CancellationToken::new();
    for _ in 0..2 {
        budget()
            .acquire(&endpoint, Duration::from_secs(2), &cancel)
            .await
            .unwrap();
    }
    let gate = Gate::new(&profile, Some(Instant::now() + Duration::from_secs(20))).unwrap();
    let m = measure(&Wire::plain(), &fake.inbound, None, Some(&gate), &cancel).await;
    assert_eq!((m.reflectors.len(), m.deferred), (1, 4));
    let stage = assemble(m, &profile, None, EngineRoute::PhysicalDirect, 1, "");
    // A refused CONNECT is `timeout` in the old failure ladder; any failure will do here.
    let status = stage.handshake.status;
    assert!(
        !matches!(status, HandshakeStatus::Ok | HandshakeStatus::Skipped),
        "{status:?}"
    );
    assert!(stage.handshake.error.is_some());
    assert!(
        stage.handshake.note.is_some(),
        "the skipped dials are named"
    );
}

/// Direct ClientHellos (the TLS and HTTPS stages) spend the same budget as the engine's dials: a
/// used-up budget leaves them `not_checked` (handshake-budget) without a socket; a stage skipped
/// for another reason (REALITY, basic mode) takes no slot; an endpoint check is not gated.
#[tokio::test]
async fn direct_hellos_spend_the_budget() {
    let profile = named("gate-hello.example.test");
    let gate = Gate::new(&profile, Some(Instant::now() + Duration::from_secs(20))).unwrap();
    let cancel = CancellationToken::new();
    let reality = Some(NotCheckedReason::Reality);
    assert_eq!(hello_skip(reality, Some(&gate), &cancel).await, reality);
    for _ in 0..3 {
        assert_eq!(hello_skip(None, Some(&gate), &cancel).await, None);
    }
    assert_eq!(
        hello_skip(None, Some(&gate), &cancel).await,
        Some(NotCheckedReason::HandshakeBudget)
    );
    assert_eq!(hello_skip(None, None, &cancel).await, None);
}

/// A loopback server (a local proxy) and a check without a deadline are not gated.
#[test]
fn local_servers_and_tests_are_not_gated() {
    let mut local = vless();
    local.server = vpnte_profiles::model::Host::Ip("127.0.0.1".parse().unwrap());
    if let Some(tls) = local.tls.as_mut() {
        tls.server_name = None;
    }
    let soon = Some(Instant::now() + Duration::from_secs(30));
    assert!(Gate::new(&local, soon).is_none());
    assert!(Gate::new(&vless(), None).is_none());
}
