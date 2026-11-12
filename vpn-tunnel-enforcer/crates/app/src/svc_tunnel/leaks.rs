//! Background leak self-tests of a Hard (TUN) session (monitoring §3.3-3.4): every 30 s while a
//! TUN session runs with the kill switch on (with it off every run reads "possible leak", D-60),
//! and after each network change. A leak marks the session (history evidence) and is a toast.
//! On resume from sleep and on a network change (RU audit item 11) the protection's filters are
//! re-verified at once instead of at the next 30 s watchdog tick, and the DNS canary checks that
//! the system's DNS queries still end up at our engine. Exists only in an elevated process:
//! unelevated there is no TUN session to test, and Soft blocks nothing to test.
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{Notify, broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, Level, Notice};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::leak::{
    LeakEvent, LeakWatch, SelfTestResult, SelfTestVerdict, SelfTester, SystemEnv, WatchConfig,
    report,
};
use vpnte_probes::netmode::{Canary, WireLookup, dns_canary};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_tunnel::lifecycle::Lifecycle;
use vpnte_winnet::adapters::{self, NetChange};
use vpnte_winnet::wfp::Protection;

use crate::svc_core::notify::{NoticeCategory, Notifier};

/// Debounce of the network-change watches behind the leak runs and the re-checks.
const NET_SETTLE: Duration = Duration::from_millis(1500);
/// Routes and the TUN resolver settle after a wake or a network change before the canary asks.
const RECHECK_DELAY: Duration = Duration::from_secs(3);

/// The running watch and the latest result (for the leak check card).
pub(super) struct Leaks {
    pub watch: LeakWatch,
    pub latest: Arc<Mutex<Option<SelfTestResult>>>,
    status: watch::Receiver<TunStatus>,
    /// Woken by [`Leaks::resumed`].
    resume: Arc<Notify>,
}

impl Leaks {
    /// Starts the periodic self-test, gated on "a TUN session runs and the kill switch is on";
    /// every physical network change asks for a run as well.
    pub fn spawn(status: watch::Receiver<TunStatus>, settings: Arc<Store<Settings>>) -> Self {
        let tester = Arc::new(SelfTester::new(Arc::new(SystemEnv)));
        let level = settings.clone();
        let gate_status = status.clone();
        let gate = move || {
            let s = gate_status.borrow();
            s.running
                && s.capture == Some(CaptureKind::Tun)
                && level.read(|x| x.kill_switch) != KillSwitchLevel::Off
        };
        let kill_switch = move || settings.read(|s| s.kill_switch);
        Self {
            watch: LeakWatch::spawn(
                tester,
                WatchConfig::default(),
                gate,
                kill_switch,
                net_changes("leak runs"),
            ),
            latest: Arc::new(Mutex::new(None)),
            status,
            resume: Arc::new(Notify::new()),
        }
    }

    /// The machine woke from sleep or the session was unlocked.
    pub fn resumed(&self) {
        self.resume.notify_one();
    }

    /// Hands every result to the session and the user (once the lifecycle exists), and starts
    /// the re-checks after a wake or a network change (`protection`: the WFP handle).
    pub fn forward(
        &self,
        lifecycle: Lifecycle,
        notifier: Arc<Notifier>,
        protection: Option<Arc<Protection>>,
        cancel: CancellationToken,
    ) {
        let events = self.watch.subscribe();
        tokio::spawn(forward(
            events,
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

async fn forward(
    mut events: broadcast::Receiver<LeakEvent>,
    latest: Arc<Mutex<Option<SelfTestResult>>>,
    lifecycle: Lifecycle,
    notifier: Arc<Notifier>,
    cancel: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            () = cancel.cancelled() => return,
            event = events.recv() => event,
        };
        match event {
            Ok(event) => {
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
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// What a wake or a network change re-checks at once.
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

    /// The DNS canary while a TUN session runs; an escape is a warning to the user. Proxy mode
    /// captures no DNS, so there is nothing to verify (and nothing is claimed).
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
