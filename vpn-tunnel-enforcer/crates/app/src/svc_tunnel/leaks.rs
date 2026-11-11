//! Background leak self-tests of a Hard (TUN) session (monitoring §3.3-3.4): every 30 s while a
//! TUN session runs with the kill switch on (with it off every run reads "possible leak", D-60).
//! A leak marks the session (history evidence) and is a toast. Exists only in an elevated
//! process: unelevated there is no TUN session to test, and Soft blocks nothing to test.
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, Level, Notice};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::leak::{
    LeakEvent, LeakWatch, SelfTestResult, SelfTestVerdict, SelfTester, SystemEnv, WatchConfig,
    report,
};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_tunnel::lifecycle::Lifecycle;

use crate::svc_core::notify::{NoticeCategory, Notifier};

/// The running watch and the latest result (for the leak check card).
pub(super) struct Leaks {
    pub watch: LeakWatch,
    pub latest: Arc<Mutex<Option<SelfTestResult>>>,
}

impl Leaks {
    /// Starts the periodic self-test, gated on "a TUN session runs and the kill switch is on".
    pub fn spawn(status: watch::Receiver<TunStatus>, settings: Arc<Store<Settings>>) -> Self {
        let tester = Arc::new(SelfTester::new(Arc::new(SystemEnv)));
        let level = settings.clone();
        let gate = move || {
            let s = status.borrow();
            s.running
                && s.capture == Some(CaptureKind::Tun)
                && level.read(|x| x.kill_switch) != KillSwitchLevel::Off
        };
        let kill_switch = move || settings.read(|s| s.kill_switch);
        Self {
            watch: LeakWatch::spawn(tester, WatchConfig::default(), gate, kill_switch, None),
            latest: Arc::new(Mutex::new(None)),
        }
    }

    /// Hands every result to the session and the user (once the lifecycle exists).
    pub fn forward(
        &self,
        lifecycle: Lifecycle,
        notifier: Arc<Notifier>,
        cancel: CancellationToken,
    ) {
        let events = self.watch.subscribe();
        tokio::spawn(forward(
            events,
            self.latest.clone(),
            lifecycle,
            notifier,
            cancel,
        ));
    }
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
