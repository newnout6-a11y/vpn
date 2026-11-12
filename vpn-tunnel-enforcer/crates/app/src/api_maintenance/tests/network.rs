//! RU audit items 9 and 11 on the app side: the probes' report as the page shows it, the route
//! of the probes per capture, the single flight shared by the button and the automatic runs,
//! and the review fixes: a check that spans a network change is dropped, the automatic run
//! queues, UDP evidence teaches only the network memory, the automatic run never touches the
//! user's server.
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::reaction::Verdicts;
use vpnte_base::types::Verdict;
use vpnte_core::resolve::DohByName;
use vpnte_probes::discipline::{Reach, Transfer};
use vpnte_probes::netmode::{
    Canary, Facts, HostFacts, Mode, NetProbe, Outcome, UdpEvidence, report,
};
use vpnte_tunnel::api::{CaptureKind, ProxyEndpoint, SessionEndpoints, TunStatus};
use vpnte_ui::maintenance::{MaintenanceState, NetStepKind};
use vpnte_view::netmode::NetMode;

use super::super::network::{
    Flight, NetEpoch, Scope, direct_out, feed, measure, network_changed, publish, view,
};

fn ok() -> HostFacts {
    HostFacts {
        tcp: Outcome::Ok,
        tls: Outcome::Ok,
    }
}

const MUTE: [Outcome; 2] = [Outcome::Silent, Outcome::Silent];

/// A network that drops UDP: foreign TLS works, neither QUIC nor STUN answers.
fn udp_cut() -> Facts {
    Facts {
        system_dns: Outcome::Ok,
        doh_foreign: Outcome::Ok,
        doh_ru: Outcome::Ok,
        ru: vec![ok(), ok()],
        foreign: vec![ok(), ok()],
        transfer: Some(Transfer::Complete {
            bytes: 70_000,
            ms: 200,
        }),
        quic: MUTE.to_vec(),
        stun: MUTE.to_vec(),
        servers: Vec::new(),
    }
}

/// A UDP-cut network: steps in order, the canary line last, modes and advice carried over.
#[test]
fn report_as_the_page_shows_it() {
    let r = report(&udp_cut(), true);
    assert_eq!(r.modes, [Mode::UdpBlocked]);
    let v = view(&r, Some(Canary::Captured));
    let kinds: Vec<NetStepKind> = v.steps.iter().map(|s| s.kind).collect();
    use NetStepKind as K;
    assert_eq!(
        kinds,
        [K::Dns, K::Tcp, K::Tls, K::Bytes, K::Udp, K::DnsCapture]
    );
    assert_eq!(v.steps[4].verdict, Verdict::Fail);
    assert_eq!(v.steps[5].verdict, Verdict::Ok);
    assert_eq!(v.modes, [NetMode::UdpBlocked]);
    assert_eq!(v.verdict, Verdict::Warn);
    assert_eq!(v.headline, Mode::UdpBlocked.msg());
    assert_eq!(v.advice, [Mode::UdpBlocked.advice()]);
    assert!(v.via_session);
    // Proxy mode: the canary line says DNS is not captured and is never a pass.
    let soft = view(&r, Some(Canary::NotCaptured));
    let last = soft.steps.last().unwrap();
    assert_eq!(
        (last.verdict, &last.detail),
        (Verdict::NotChecked, &Canary::NotCaptured.msg())
    );
    // Idle: no capture line at all.
    assert!(view(&r, None).steps.iter().all(|s| s.kind != K::DnsCapture));
}

/// Review b7: only a clean pass takes the pass colour; no internet is a failure and an
/// unproven result is "not verified".
#[test]
fn result_colour_follows_the_summary() {
    let colour = |f: &Facts| view(&report(f, false), None).verdict;
    let open = Facts {
        quic: vec![Outcome::Ok; 2],
        stun: vec![Outcome::Ok; 2],
        ..udp_cut()
    };
    assert_eq!(colour(&open), Verdict::Ok);
    let offline = Facts {
        ru: vec![HostFacts::default(); 2],
        foreign: vec![HostFacts::default(); 2],
        transfer: None,
        ..udp_cut()
    };
    assert_eq!(colour(&offline), Verdict::Fail);
    let unproven = Facts {
        stun: vec![Outcome::NotRun; 2],
        ..open.clone()
    };
    assert_eq!(colour(&unproven), Verdict::NotChecked);
    assert_eq!(colour(&udp_cut()), Verdict::Warn);
}

fn status(capture: CaptureKind) -> TunStatus {
    TunStatus {
        running: true,
        capture: Some(capture),
        session: Some(SessionEndpoints {
            clash_port: 9090,
            clash_secret: "0".repeat(32),
            direct: ProxyEndpoint {
                port: 40001,
                user: "u".into(),
                pass: "p".into(),
            },
            probe: None,
            tun_luid: None,
            tun_alias: None,
            proxy_port: Some(40002),
            logs: Vec::new(),
        }),
        ..TunStatus::default()
    }
}

/// Under our TUN the probes take the session's direct-out; Soft and idle go direct.
#[test]
fn probes_leave_past_the_tunnel() {
    let tun = direct_out(&status(CaptureKind::Tun)).unwrap();
    assert_eq!(tun.port, 40001);
    assert_eq!(tun.creds.unwrap().user, "u");
    assert_eq!(direct_out(&status(CaptureKind::Proxy)), None);
    assert_eq!(direct_out(&TunStatus::default()), None);
}

/// One check at a time; the flag clears however the run ends.
#[test]
fn single_flight() {
    let state = watch::Sender::new(MaintenanceState::default());
    let first = Flight::begin(&state).unwrap();
    assert!(state.borrow().network.running);
    let busy = Flight::begin(&state).err().unwrap();
    assert_eq!(busy.user_msg().key, "app.maintenance.network.busy");
    drop(first);
    assert!(!state.borrow().network.running);
    assert!(Flight::begin(&state).is_ok());
}

/// Review a1/b4: the automatic run queues behind a running check instead of being refused,
/// and starts as soon as that check ends.
#[tokio::test]
async fn the_automatic_run_queues() {
    let state = watch::Sender::new(MaintenanceState::default());
    let cancel = CancellationToken::new();
    let button = Flight::begin(&state).unwrap();
    let queued = Flight::queued(&state, &cancel);
    tokio::pin!(queued);
    let waited = tokio::time::timeout(Duration::from_millis(50), &mut queued).await;
    assert!(waited.is_err(), "waits while the button's check runs");
    drop(button);
    let auto = tokio::time::timeout(Duration::from_secs(5), queued)
        .await
        .expect("starts once the check ended");
    assert!(auto.is_some() && state.borrow().network.running);
    drop(auto);
    // A quitting app stops the wait.
    let _held = Flight::begin(&state).unwrap();
    cancel.cancel();
    assert!(Flight::queued(&state, &cancel).await.is_none());
}

/// Review a1/b4: a check that spans a network change publishes nothing and teaches the new
/// network's memory nothing; a check of the current network does both.
#[test]
fn a_check_across_a_network_change_is_dropped() {
    let state = watch::Sender::new(MaintenanceState::default());
    let verdicts = Verdicts::new();
    let epoch = NetEpoch::default();
    let r = report(&udp_cut(), false);
    let began = epoch.current();
    network_changed(&epoch, &state);
    assert!(began.is_cancelled(), "the check in flight is told");
    let err = publish(&state, Some(&verdicts), &began, &r, None).unwrap_err();
    assert_eq!(err.user_msg().key, "app.maintenance.network.changed");
    assert_eq!(state.borrow().network.last, None);
    assert!(!verdicts.udp_blocked());
    let shown = publish(&state, Some(&verdicts), &epoch.current(), &r, None).unwrap();
    assert_eq!(state.borrow().network.last, Some(shown));
    assert!(verdicts.udp_blocked());
    // The next change clears the shown verdict: it described the network that is gone.
    network_changed(&epoch, &state);
    assert_eq!(state.borrow().network.last, None);
}

/// Review b1/a2: UDP evidence teaches the network memory only (no report about a server, so
/// no session is switched by it); an answer lifts the mark, no proof leaves it.
#[test]
fn udp_evidence_teaches_the_network_memory() {
    let verdicts = Verdicts::new();
    feed(&verdicts, UdpEvidence::Dropped);
    assert!(verdicts.udp_blocked());
    feed(&verdicts, UdpEvidence::Unclear);
    assert!(verdicts.udp_blocked(), "no proof either way");
    feed(&verdicts, UdpEvidence::Passes);
    assert!(!verdicts.udp_blocked());
    // QUIC on 443 silent while STUN answers is not "UDP blocked": it lifts the mark.
    let quic_cut = Facts {
        stun: vec![Outcome::Ok; 2],
        ..udp_cut()
    };
    feed(&verdicts, UdpEvidence::Dropped);
    feed(&verdicts, report(&quic_cut, false).udp);
    assert!(!verdicts.udp_blocked());
}

/// A network where everything answers; records which servers were probed.
#[derive(Default)]
struct Answering {
    reached: Mutex<Vec<SocketAddr>>,
}

impl NetProbe for Answering {
    async fn system_dns(&self, _: &str) -> Outcome {
        Outcome::Ok
    }
    async fn doh(&self, _: DohByName, _: &str) -> Outcome {
        Outcome::Ok
    }
    async fn https(&self, _: &str) -> HostFacts {
        ok()
    }
    async fn transfer(&self) -> Option<Transfer> {
        None
    }
    async fn quic(&self, _: &str) -> Outcome {
        Outcome::Ok
    }
    async fn stun(&self, _: &str, _: u16) -> Outcome {
        Outcome::Ok
    }
    async fn reach(&self, dst: SocketAddr) -> Reach {
        self.reached.lock().unwrap().push(dst);
        Reach::default()
    }
}

/// Review b2: the automatic run never resolves the user's server (no lookup of its name) and
/// never probes it; the button does both.
#[tokio::test]
async fn the_automatic_run_never_touches_the_server() {
    let cancel = CancellationToken::new();
    let server: SocketAddr = "203.0.113.9:443".parse().unwrap();
    for (scope, touched) in [(Scope::Automatic, false), (Scope::Button, true)] {
        let probe = Answering::default();
        let resolved = AtomicBool::new(false);
        let lookup = || async {
            resolved.store(true, Ordering::SeqCst);
            vec![server]
        };
        let facts = measure(&probe, scope, lookup, &cancel).await.unwrap();
        assert_eq!(resolved.load(Ordering::SeqCst), touched, "{scope:?}");
        let reached = probe.reached.lock().unwrap().clone();
        assert_eq!(reached.is_empty(), !touched, "{scope:?}");
        assert_eq!(facts.servers.len(), usize::from(touched));
    }
}
