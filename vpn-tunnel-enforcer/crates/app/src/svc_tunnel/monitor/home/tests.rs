//! The home-address reads against a scripted sampler and a hand-driven runtime status: no
//! request leaves the machine.
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use vpnte_probes::public_ip::IpSample;

use super::*;

const HOME: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
const MOVED: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));

/// Answers from a script; `during` runs inside the next read (a session coming up mid-read).
#[derive(Default)]
struct Script {
    answers: Mutex<VecDeque<Option<IpAddr>>>,
    calls: AtomicUsize,
    during: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Sampler for Script {
    fn sample<'a>(
        &'a self,
        route: &'a IpRoute,
        family: Family,
        _cancel: &'a CancellationToken,
    ) -> BoxFuture<'a, Option<IpSample>> {
        assert!(matches!(route, IpRoute::Direct), "the current network");
        assert_eq!(family, Family::V4);
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(hook) = self.during.lock().take() {
            hook();
        }
        let ip = self.answers.lock().pop_front().flatten();
        Box::pin(async move {
            ip.map(|ip| IpSample {
                ip,
                provider: 0,
                at: 1_700_000_000_000,
            })
        })
    }
}

struct Rig {
    script: Arc<Script>,
    ip: IpMonitor,
    status: Arc<watch::Sender<TunStatus>>,
    reads: HomeReads,
}

fn rig(lookups: bool, answers: &[Option<IpAddr>]) -> Rig {
    let script = Arc::new(Script::default());
    script.answers.lock().extend(answers.iter().copied());
    let ip = IpMonitor::new(script.clone());
    let status = Arc::new(watch::Sender::new(TunStatus::default()));
    let reads = HomeReads {
        sampler: script.clone(),
        ip: ip.clone(),
        geo: Geo::new(lookups),
        status: status.subscribe(),
    };
    Rig {
        script,
        ip,
        status,
        reads,
    }
}

fn running() -> TunStatus {
    TunStatus {
        running: true,
        ..TunStatus::default()
    }
}

/// The monitor's home address once it equals `want` (polled, at most 5 s).
async fn home_becomes(ip: &IpMonitor, want: IpAddr) {
    let mut evidence = ip.subscribe();
    tokio::time::timeout(
        Duration::from_secs(5),
        evidence.wait_for(|e| e.real_ip == Some(want)),
    )
    .await
    .expect("home address within 5 s")
    .expect("monitor alive");
}

fn change() -> NetChange {
    NetChange {
        before: 1,
        after: 2,
    }
}

fn calls(script: &Script) -> usize {
    script.calls.load(Ordering::SeqCst)
}

/// Owner decision 13: at start, before any session, the home address is read once through the
/// current network (the settled-off start page shows it with «ваш провайдер»).
#[tokio::test]
async fn reads_the_home_address_at_start() {
    let r = rig(true, &[Some(HOME)]);
    r.reads.run(None, CancellationToken::new()).await;
    assert_eq!(r.ip.evidence().real_ip, Some(HOME));
    assert_eq!(calls(&r.script), 1);
}

/// With online lookups disabled the app sends no address request, at start or later.
#[tokio::test]
async fn no_request_while_lookups_are_disabled() {
    let r = rig(false, &[Some(HOME)]);
    let (tx, rx) = mpsc::channel(4);
    let task = tokio::spawn(r.reads.run(Some(rx), CancellationToken::new()));
    tx.send(change()).await.expect("reads alive");
    drop(tx);
    task.await.expect("reads end");
    assert_eq!(calls(&r.script), 0);
    assert_eq!(r.ip.evidence().real_ip, None);
}

/// A network change while disconnected reads again: the start page follows the new network.
#[tokio::test]
async fn a_network_change_while_idle_reads_again() {
    let r = rig(true, &[Some(HOME), Some(MOVED)]);
    let (tx, rx) = mpsc::channel(4);
    let task = tokio::spawn(r.reads.run(Some(rx), CancellationToken::new()));
    home_becomes(&r.ip, HOME).await;
    tx.send(change()).await.expect("reads alive");
    home_becomes(&r.ip, MOVED).await;
    drop(tx);
    task.await.expect("reads end");
    assert_eq!(calls(&r.script), 2);
}

/// A read nobody answered keeps the address measured before.
#[tokio::test]
async fn an_unanswered_read_keeps_the_last_address() {
    let r = rig(true, &[Some(HOME), None]);
    let (tx, rx) = mpsc::channel(4);
    let task = tokio::spawn(r.reads.run(Some(rx), CancellationToken::new()));
    tx.send(change()).await.expect("reads alive");
    drop(tx);
    task.await.expect("reads end");
    assert_eq!(calls(&r.script), 2);
    assert_eq!(r.ip.evidence().real_ip, Some(HOME));
}

/// While a session runs nothing is read (its exit would pass for the home address): the
/// session reads the home address itself through the engine's direct-out.
#[tokio::test]
async fn nothing_is_read_while_a_session_runs() {
    let r = rig(true, &[Some(HOME)]);
    r.status.send_replace(running());
    let (tx, rx) = mpsc::channel(4);
    let task = tokio::spawn(r.reads.run(Some(rx), CancellationToken::new()));
    tx.send(change()).await.expect("reads alive");
    drop(tx);
    task.await.expect("reads end");
    assert_eq!(calls(&r.script), 0);
    assert_eq!(r.ip.evidence().real_ip, None);
}

/// A session that comes up during the read may have carried it: the sample is dropped.
#[tokio::test]
async fn a_session_starting_during_the_read_drops_the_sample() {
    let r = rig(true, &[Some(HOME)]);
    let status = r.status.clone();
    *r.script.during.lock() = Some(Box::new(move || {
        status.send_replace(running());
    }));
    r.reads.run(None, CancellationToken::new()).await;
    assert_eq!(calls(&r.script), 1);
    assert_eq!(r.ip.evidence().real_ip, None);
}
