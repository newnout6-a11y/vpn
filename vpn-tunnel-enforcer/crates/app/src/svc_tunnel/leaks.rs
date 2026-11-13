//! Background leak self-tests of a Hard (TUN) session (monitoring §3.3-3.4) and the re-checks
//! after a wake or a network change (RU audit item 11), for every TUN session wherever it runs.
//! The self-test runs every 30 s while a TUN session runs with the kill switch on (with it off
//! every run reads "possible leak", D-60) and after each network change: in this process when it
//! holds the WFP filters itself, else in the helper service, which sends each result with its
//! status (with "Always" its session runs before any app). Either way a leak marks the session
//! (history evidence) and is a toast. On a wake or a network change the filters are re-verified
//! at once where they live (the service does its own), and the DNS canary checks that the
//! system's DNS queries still end up at our engine (a plain lookup: no rights needed). Soft
//! blocks nothing to test.
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, Level, Notice, UnixMs};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::leak::{
    LeakEvent, LeakWatch, SelfTestResult, SelfTestVerdict, SelfTester, SystemEnv, WatchConfig,
    report, verdict,
};
use vpnte_probes::netmode::{Canary, WireLookup, dns_canary};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_tunnel::lifecycle::Lifecycle;
use vpnte_winnet::adapters::{self, NetChange};
use vpnte_winnet::wfp::Protection;

use super::remote::Remote;
use crate::svc_core::notify::{NoticeCategory, Notifier};

/// Debounce of the network-change watches behind the leak runs and the re-checks.
const NET_SETTLE: Duration = Duration::from_millis(1500);
/// Routes and the TUN resolver settle after a wake or a network change before the canary asks.
const RECHECK_DELAY: Duration = Duration::from_secs(3);

/// The running watch and the latest result (for the leak check card).
pub(super) struct Leaks {
    /// This process's own runs (idle unless it holds the filters).
    pub watch: LeakWatch,
    pub latest: Arc<Mutex<Option<SelfTestResult>>>,
    status: watch::Receiver<TunStatus>,
    /// Woken by [`Leaks::resumed`].
    resume: Arc<Notify>,
    /// The helper service's runs.
    service: watch::Receiver<Option<SelfTestResult>>,
}

impl Leaks {
    /// Starts the periodic self-test of this process, gated on "this process holds the filters
    /// (`local`), a TUN session runs and the kill switch is on"; every physical network change
    /// asks for a run as well. The service's results come from `remote`.
    pub fn spawn(
        status: watch::Receiver<TunStatus>,
        settings: Arc<Store<Settings>>,
        remote: &Remote,
        local: bool,
    ) -> Self {
        let tester = Arc::new(SelfTester::new(Arc::new(SystemEnv)));
        let level = settings.clone();
        let gate_status = status.clone();
        // An install from Settings moves the next TUN session into the service.
        let service = remote.clone();
        let gate = move || {
            let s = gate_status.borrow();
            local
                && !service.installed()
                && s.running
                && s.capture == Some(CaptureKind::Tun)
                && level.read(|x| x.kill_switch) != KillSwitchLevel::Off
        };
        let kill_switch = move || settings.read(|s| s.kill_switch);
        let changes = if local {
            net_changes("leak runs")
        } else {
            None
        };
        Self {
            watch: LeakWatch::spawn(tester, WatchConfig::default(), gate, kill_switch, changes),
            latest: Arc::new(Mutex::new(None)),
            status,
            resume: Arc::new(Notify::new()),
            service: remote.self_tests(),
        }
    }

    /// The machine woke from sleep or the session was unlocked.
    pub fn resumed(&self) {
        self.resume.notify_one();
    }

    /// Hands every result (this process's and the service's) to the session and the user (once
    /// the lifecycle exists), and starts the re-checks after a wake or a network change
    /// (`protection`: this process's WFP handle, `None` when the filters are the service's).
    pub fn forward(
        &self,
        lifecycle: Lifecycle,
        notifier: Arc<Notifier>,
        protection: Option<Arc<Protection>>,
        cancel: CancellationToken,
    ) {
        let results = Results {
            own: self.watch.subscribe(),
            service: Some(self.service.clone()),
            seen: None,
        };
        tokio::spawn(forward(
            results,
            self.latest.clone(),
            lifecycle,
            notifier.clone(),
            cancel.clone(),
        ));
        let recheck = Recheck {
            protection,
            status: self.status.clone(),
            notifier,
        };
        let changes = net_changes("protection re-checks");
        tokio::spawn(recheck.run(self.resume.clone(), changes, cancel));
    }
}

/// A network-change watch of its own (each consumer needs one); it ends with its receiver.
fn net_changes(what: &'static str) -> Option<mpsc::Receiver<NetChange>> {
    adapters::watch_network(NET_SETTLE, CancellationToken::new())
        .inspect_err(|err| tracing::warn!(%err, what, "no network-change watch"))
        .ok()
}

/// Both sources of finished self-tests: this process's watch and the helper service.
struct Results {
    own: broadcast::Receiver<LeakEvent>,
    /// `None` once the service's channel closed.
    service: Option<watch::Receiver<Option<SelfTestResult>>>,
    /// The time of the service's last run passed on (it resends its latest with every status).
    seen: Option<UnixMs>,
}

impl Results {
    /// The next finished run; `None` once this process's watch is gone (shutdown).
    async fn next(&mut self) -> Option<LeakEvent> {
        loop {
            tokio::select! {
                event = self.own.recv() => match event {
                    Ok(event) => return Some(event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                },
                result = next_service(&mut self.service) => {
                    if self.seen == Some(result.at) {
                        continue;
                    }
                    self.seen = Some(result.at);
                    let verdict = verdict(&result);
                    return Some(LeakEvent { reason: "service", verdict, result });
                }
            }
        }
    }
}

/// The service's next result as the remote passes it on; pends once its channel closed.
async fn next_service(rx: &mut Option<watch::Receiver<Option<SelfTestResult>>>) -> SelfTestResult {
    while let Some(r) = rx.as_mut() {
        match r.changed().await {
            Ok(()) => {
                if let Some(result) = r.borrow_and_update().clone() {
                    return result;
                }
            }
            Err(_) => *rx = None,
        }
    }
    std::future::pending().await
}

async fn forward(
    mut results: Results,
    latest: Arc<Mutex<Option<SelfTestResult>>>,
    lifecycle: Lifecycle,
    notifier: Arc<Notifier>,
    cancel: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            () = cancel.cancelled() => return,
            event = results.next() => event,
        };
        let Some(event) = event else {
            return;
        };
        if event.verdict == SelfTestVerdict::Leak {
            tracing::error!(
                reason = event.reason,
                "leak self-test: traffic left outside the tunnel"
            );
            lifecycle.leak_detected();
            let notice = Notice::new(Level::Error, Msg::new("app.tunnel.leakDetected"))
                .body(report(&event.result).headline);
            notifier.notify(notice, Some(NoticeCategory::LeakDetected));
        }
        *latest.lock() = Some(event.result);
    }
}

/// What a wake or a network change re-checks at once: the filters where this process holds
/// them (`protection`; the service checks its own on the same events), and the DNS canary of
/// every TUN session.
struct Recheck {
    protection: Option<Arc<Protection>>,
    status: watch::Receiver<TunStatus>,
    notifier: Arc<Notifier>,
}

impl Recheck {
    async fn run(
        self,
        resume: Arc<Notify>,
        mut changes: Option<mpsc::Receiver<NetChange>>,
        cancel: CancellationToken,
    ) {
        loop {
            let why = tokio::select! {
                () = cancel.cancelled() => return,
                () = resume.notified() => "resume",
                Some(_) = next_change(&mut changes) => "network change",
            };
            self.tick(why).await;
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(RECHECK_DELAY) => {}
            }
            self.canary(why).await;
        }
    }

    /// The watchdog's filter check now (it repairs what Windows dropped), off the runtime.
    async fn tick(&self, why: &'static str) {
        let Some(protection) = self.protection.clone() else {
            return;
        };
        tracing::info!(why, "protection re-verified now");
        if tokio::task::spawn_blocking(move || protection.watchdog_tick())
            .await
            .is_err()
        {
            tracing::warn!("protection watchdog tick did not finish");
        }
    }

    /// The DNS canary while a TUN session runs, here or in the service; an escape is a warning
    /// to the user. Proxy mode captures no DNS, so there is nothing to verify (and nothing is
    /// claimed).
    async fn canary(&self, why: &'static str) {
        let tun = {
            let s = self.status.borrow();
            s.running && s.capture == Some(CaptureKind::Tun)
        };
        if !tun {
            return;
        }
        let found = dns_canary(&WireLookup).await;
        tracing::info!(why, ?found, "DNS canary");
        if found == Canary::Escaped {
            let notice =
                Notice::new(Level::Warn, Msg::new("app.tunnel.dnsEscaped")).body(found.msg());
            self.notifier
                .notify(notice, Some(NoticeCategory::LeakDetected));
        }
    }
}

async fn next_change(changes: &mut Option<mpsc::Receiver<NetChange>>) -> Option<NetChange> {
    match changes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use vpnte_probes::leak::{AddrProbe, Reach};

    use super::*;

    fn run(at: UnixMs, reached: bool) -> SelfTestResult {
        let reach = if reached {
            Reach::Reached {
                ip: "198.51.100.7".parse().expect("ip"),
            }
        } else {
            Reach::NotReached { curl_exit: 7 }
        };
        SelfTestResult {
            at,
            kill_switch: KillSwitchLevel::Standard,
            default_v4: Some("203.0.113.1".parse().expect("ip")),
            probes: vec![AddrProbe {
                alias: "Ethernet".into(),
                local: "192.0.2.10".parse().expect("ip"),
                reach,
                stderr_tail: None,
            }],
            inspection_complete: true,
            services_disagree: None,
            cancelled: false,
        }
    }

    async fn next(results: &mut Results) -> LeakEvent {
        let next = tokio::time::timeout(Duration::from_secs(5), results.next());
        next.await.expect("in time").expect("open")
    }

    /// RU audit item 11: a run of the helper service is judged and passed on like this
    /// process's own, once per run although every status resends it; own runs pass as before.
    #[tokio::test]
    async fn service_runs_pass_once_each_and_own_runs_still_pass() {
        let (own, own_rx) = broadcast::channel(4);
        let service = watch::channel(None).0;
        let mut results = Results {
            own: own_rx,
            service: Some(service.subscribe()),
            seen: None,
        };
        service.send_replace(Some(run(1, true)));
        let first = next(&mut results).await;
        assert_eq!(
            (first.reason, first.verdict),
            ("service", SelfTestVerdict::Leak)
        );
        // The next status resends run 1: no news. Then run 2 arrives.
        service.send_replace(Some(run(1, true)));
        let quiet = tokio::time::timeout(Duration::from_millis(100), results.next()).await;
        assert!(quiet.is_err(), "a resent run is passed on once");
        service.send_replace(Some(run(2, false)));
        let second = next(&mut results).await;
        assert_eq!((second.result.at, second.verdict), (2, SelfTestVerdict::Ok));
        let local = LeakEvent {
            reason: "periodic",
            verdict: SelfTestVerdict::Ok,
            result: run(3, false),
        };
        own.send(local.clone()).expect("subscribed");
        assert_eq!(next(&mut results).await, local);
    }

    /// The service's channel closing (the remote dropped) neither spins nor ends own runs.
    #[tokio::test]
    async fn a_closed_service_channel_is_quiet() {
        let (own, own_rx) = broadcast::channel(4);
        let service = watch::channel(None).0;
        let mut results = Results {
            own: own_rx,
            service: Some(service.subscribe()),
            seen: None,
        };
        drop(service);
        let pending = tokio::time::timeout(Duration::from_millis(100), results.next()).await;
        assert!(pending.is_err(), "nothing to pass on");
        assert!(results.service.is_none());
        let local = LeakEvent {
            reason: "periodic",
            verdict: SelfTestVerdict::Ok,
            result: run(4, false),
        };
        own.send(local.clone()).expect("subscribed");
        assert_eq!(next(&mut results).await, local);
    }
}
