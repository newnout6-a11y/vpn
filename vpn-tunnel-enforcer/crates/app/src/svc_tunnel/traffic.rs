//! [`Forensics`] of a session: traffic counters, the domain history and the system snapshots
//! around it (no packet capture).
//!
//! Counters come from the engine's Clash API totals for both captures: the forensics
//! `RateSampler` reads a TUN adapter by LUID, and a Soft (proxy capture) session has no adapter.
use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::{Map, Value};
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::clash_api::{ClashApi, ClashEndpoint as EngineEndpoint};
use vpnte_forensics::connections::ClashEndpoint;
use vpnte_forensics::domains::HistoryService;
use vpnte_forensics::traffic::{
    BURSTINESS_WINDOW, SAMPLE_INTERVAL, SMOOTHING_ALPHA, TrafficStats, burstiness, smooth,
};
use vpnte_probes::diagnostics::snapshot::AppState;
use vpnte_probes::diagnostics::{SnapshotReason, Snapshotter};
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::Forensics;

/// What a system snapshot records of the app: the runtime status (its session endpoints, which
/// hold secrets, are never serialized) and the protection settings in force.
pub(super) fn app_state(
    status: watch::Receiver<TunStatus>,
    settings: Arc<Store<Settings>>,
) -> AppState {
    Arc::new(move || {
        let mut state = Map::new();
        let tunnel = serde_json::to_value(&*status.borrow()).unwrap_or(Value::Null);
        state.insert("tunnel".into(), tunnel);
        let (routing, kill_switch) = settings.read(|s| {
            (
                serde_json::to_value(s.routing_mode).unwrap_or(Value::Null),
                serde_json::to_value(s.kill_switch).unwrap_or(Value::Null),
            )
        });
        state.insert("routingMode".into(), routing);
        state.insert("killSwitch".into(), kill_switch);
        state
    })
}

/// Counters and domain history of the running session.
pub(super) struct SessionForensics {
    tx: watch::Sender<TrafficStats>,
    status: watch::Receiver<TunStatus>,
    domains: Arc<HistoryService>,
    servers: Arc<Servers>,
    /// System snapshots around each session (support reads them in the diagnostics archive).
    snapshots: Arc<Snapshotter>,
    sampling: Mutex<Option<CancellationToken>>,
    shutdown: CancellationToken,
}

impl SessionForensics {
    pub fn new(
        status: watch::Receiver<TunStatus>,
        domains: Arc<HistoryService>,
        servers: Arc<Servers>,
        snapshots: Arc<Snapshotter>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            tx: watch::Sender::new(TrafficStats::empty("", now_ms())),
            status,
            domains,
            servers,
            snapshots,
            sampling: Mutex::new(None),
            shutdown,
        }
    }

    /// Counters of the running session, about once a second (`running: false` while idle).
    pub fn traffic(&self) -> watch::Receiver<TrafficStats> {
        self.tx.subscribe()
    }

    /// Writes the domain history out (app exit).
    pub async fn flush(&self) {
        if let Err(e) = self.domains.flush().await {
            tracing::warn!(error = %e, "domain history not flushed");
        }
    }

    /// A snapshot in the background: the session's start or stop never waits for it.
    fn snapshot(&self, reason: SnapshotReason) {
        let snapshots = self.snapshots.clone();
        tokio::spawn(async move { snapshots.capture(reason).await });
    }
}

#[async_trait]
impl Forensics for SessionForensics {
    fn start_session(&self, mode: SessionMode, _target: &str) {
        let token = self.shutdown.child_token();
        if let Some(old) = self.sampling.lock().replace(token.clone()) {
            old.cancel();
        }
        // Server names are infrastructure, not visited sites.
        self.domains.set_server_hosts(self.servers.all_hosts());
        tracing::info!(mode = mode.as_str(), "traffic counters started");
        tokio::spawn(sample(
            self.tx.clone(),
            self.status.clone(),
            self.domains.clone(),
            token,
        ));
        self.snapshot(SnapshotReason::TunPostStart);
    }

    async fn stop_session(&self, _reason: &str) -> bool {
        if let Some(token) = self.sampling.lock().take() {
            token.cancel();
        }
        if let Err(e) = self.domains.stop_polling().await {
            tracing::warn!(error = %e, "domain history polling did not stop cleanly");
        }
        self.tx.send_replace(TrafficStats::empty("", now_ms()));
        self.snapshot(SnapshotReason::TunPostStop);
        // No packet capture in this build: nothing whose stop could be unconfirmed.
        true
    }

    fn session_bytes(&self) -> (u64, u64) {
        let stats = self.tx.borrow();
        (stats.session_down, stats.session_up)
    }
}

/// Polls the Clash totals of whichever engine run serves the session; a new run (crash or
/// protected restart: new endpoint, totals from zero) re-points the domain history as well.
async fn sample(
    tx: watch::Sender<TrafficStats>,
    status: watch::Receiver<TunStatus>,
    domains: Arc<HistoryService>,
    cancel: CancellationToken,
) {
    let mut meter = Meter::new(now_ms());
    let mut run: Option<(EngineEndpoint, ClashApi)> = None;
    let mut ticker = tokio::time::interval(SAMPLE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let current = status.borrow().session.as_ref().map(|s| {
            let ep = EngineEndpoint {
                port: s.clash_port,
                secret: s.clash_secret.clone(),
            };
            (ep, s.tun_alias.clone().unwrap_or_default())
        });
        let Some((ep, adapter)) = current else {
            continue;
        };
        if run.as_ref().is_none_or(|(known, _)| *known != ep) {
            meter.new_run();
            let polled = ClashEndpoint {
                port: ep.port,
                secret: ep.secret.clone(),
            };
            if let Err(e) = domains.start_polling(&polled) {
                tracing::warn!(error = %e, "domain history polling not started");
            }
            run = match ClashApi::new(&ep) {
                Ok(api) => Some((ep, api)),
                Err(e) => {
                    tracing::warn!(error = %e, "clash api unusable");
                    None
                }
            };
        }
        let totals = match &run {
            Some((_, api)) => tokio::select! {
                () = cancel.cancelled() => return,
                read = api.connections() => read.ok().map(|c| (c.download_total, c.upload_total)),
            },
            None => None,
        };
        if cancel.is_cancelled() {
            // The session ended during the read: its zeroed stats must stay the last word.
            return;
        }
        tx.send_replace(meter.tick(now_ms(), totals, adapter));
    }
}

/// Rates and session totals out of per-run engine totals (pure; unit-tested).
#[derive(Debug, Default)]
pub(super) struct Meter {
    started: UnixMs,
    /// Bytes of the session's finished engine runs.
    base: (u64, u64),
    /// Last read of the current run: when, down, up.
    last: Option<(UnixMs, u64, u64)>,
    smooth: (f64, f64),
    peak: (f64, f64),
    window: VecDeque<(f64, f64)>,
}

impl Meter {
    pub fn new(started: UnixMs) -> Self {
        Self {
            started,
            ..Self::default()
        }
    }

    /// The engine run changed: its totals restart from zero.
    pub fn new_run(&mut self) {
        if let Some((_, down, up)) = self.last.take() {
            self.base.0 += down;
            self.base.1 += up;
        }
    }

    /// One sample: `totals` = (down, up) of the current run, `None` = not readable now.
    pub fn tick(
        &mut self,
        now: UnixMs,
        totals: Option<(u64, u64)>,
        adapter: String,
    ) -> TrafficStats {
        let mut stats = TrafficStats {
            ts_ms: now,
            running: true,
            adapter,
            adapter_found: totals.is_some(),
            started_at_ms: Some(self.started),
            ..TrafficStats::default()
        };
        if let Some((down, up)) = totals {
            if self.last.is_some_and(|(_, d, u)| down < d || up < u) {
                self.new_run();
            }
            let (rate_down, rate_up) = match self.last {
                Some((at, d, u)) if now > at => {
                    let secs = (now - at) as f64 / 1000.0;
                    ((down - d) as f64 / secs, (up - u) as f64 / secs)
                }
                _ => (0.0, 0.0),
            };
            self.last = Some((now, down, up));
            self.smooth = (
                smooth(self.smooth.0, rate_down, SMOOTHING_ALPHA),
                smooth(self.smooth.1, rate_up, SMOOTHING_ALPHA),
            );
            self.peak = (self.peak.0.max(rate_down), self.peak.1.max(rate_up));
            self.window.push_back((rate_down, rate_up));
            if self.window.len() > BURSTINESS_WINDOW {
                self.window.pop_front();
            }
            stats.down_bps = rate_down;
            stats.up_bps = rate_up;
            stats.total_down = down;
            stats.total_up = up;
        }
        let (down, up) = self.last.map_or((0, 0), |(_, d, u)| (d, u));
        stats.session_down = self.base.0 + down;
        stats.session_up = self.base.1 + up;
        stats.smooth_down_bps = self.smooth.0;
        stats.smooth_up_bps = self.smooth.1;
        stats.peak_down_bps = self.peak.0;
        stats.peak_up_bps = self.peak.1;
        let downs: Vec<f64> = self.window.iter().map(|w| w.0).collect();
        let ups: Vec<f64> = self.window.iter().map(|w| w.1).collect();
        stats.down_burst_pct = burstiness(&downs);
        stats.up_burst_pct = burstiness(&ups);
        stats
    }
}
