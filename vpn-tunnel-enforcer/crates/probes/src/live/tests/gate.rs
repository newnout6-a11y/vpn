//! The engine stage through the handshake budget (probe-discipline, fact a): dials one at a time
//! in order of value, what the budget does not allow before the deadline is left out and named,
//! never dialled in a burst and never reported as a failure.
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_profiles::model::Profile;

use super::engine::vless;
use super::socks::{Reply, fake_socks, http};
use crate::discipline::{Endpoint, budget};
use crate::live::engine_probe::{Gate, assemble, measure};
use crate::live::model::{EngineRoute, HandshakeStatus, MediaStatus};
use crate::live::wire::Wire;

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
