//! Watchdogs of a running session (tunnel-core §3.9 / §3.10). They never stop the tunnel:
//! with the upstream down the traffic waits inside the tunnel instead of leaking, and the status
//! only says so. Each runs as its own task and reports transitions to the actor.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_core::net::HostPort;
use vpnte_engine::clash_api::ClashEndpoint;

use super::actor::{Actor, Internal, Phase, Session};
use super::capture::{Capture, CaptureCheck, CaptureProof};
use super::engines::Engines;
use super::{Confirmations, Timings, config};
use crate::api::{Mode, TunStatusKind};

/// Consecutive failed checks before the upstream is reported down.
const FAILURES: u8 = 3;

fn every(period: Duration) -> tokio::time::Interval {
    let mut tick = tokio::time::interval_at(Instant::now() + period, period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick
}

/// Shared by the watchdog loops: report `up` or count a failure.
struct Verdicts {
    tx: mpsc::Sender<Internal>,
    generation: u64,
    failures: u8,
}

impl Verdicts {
    async fn report(&mut self, up: bool) {
        let report = if up {
            self.failures = 0;
            Internal::ProxyUp {
                generation: self.generation,
            }
        } else {
            self.failures = self.failures.saturating_add(1);
            if self.failures < FAILURES {
                tracing::debug!(failures = self.failures, "upstream check failed");
                return;
            }
            Internal::ProxyDown {
                generation: self.generation,
            }
        };
        let _ = self.tx.send(report).await;
    }
}

/// Local proxy: a TCP connect every period (or recent outside evidence).
async fn local_watch(
    addr: HostPort,
    confirmations: Option<Arc<dyn Confirmations>>,
    t: Timings,
    mut verdicts: Verdicts,
    cancel: CancellationToken,
) {
    let mut tick = every(t.proxy_watch);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        let connect = tokio::net::TcpStream::connect(addr.to_string());
        let answered = matches!(
            tokio::time::timeout(t.proxy_probe, connect).await,
            Ok(Ok(_))
        );
        let confirmed = confirmations
            .as_ref()
            .is_some_and(|c| c.confirmed_within(t.evidence_age));
        verdicts.report(answered || confirmed).await;
    }
}

/// Direct VPN: there is no local proxy to probe (and our own sockets may be blocked by the kill
/// switch while the tunnel is healthy), so evidence is traffic: download growth on connections
/// leaving through the upstream, or outside evidence (public IP, tunnel probe) within the age.
async fn egress_watch(
    engines: Arc<dyn Engines>,
    clash: ClashEndpoint,
    confirmations: Option<Arc<dyn Confirmations>>,
    t: Timings,
    mut verdicts: Verdicts,
    cancel: CancellationToken,
) {
    let mut tick = every(t.egress_watch);
    let mut seen: HashMap<String, u64> = HashMap::new();
    let mut last_growth: Option<Instant> = None;
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        if let Ok(now) = engines.upstream_downloads(&clash).await {
            let grew = now
                .iter()
                .any(|(id, down)| *down > seen.get(id).copied().unwrap_or(0));
            if grew {
                last_growth = Some(Instant::now());
            }
            seen = now.into_iter().collect();
        }
        let traffic = last_growth.is_some_and(|at| at.elapsed() <= t.evidence_age);
        let confirmed = confirmations
            .as_ref()
            .is_some_and(|c| c.confirmed_within(t.evidence_age));
        verdicts.report(traffic || confirmed).await;
    }
}

/// Capture-specific checks: at once, then every period.
async fn capture_watch(
    capture: Arc<dyn Capture>,
    proof: CaptureProof,
    t: Timings,
    tx: mpsc::Sender<Internal>,
    generation: u64,
    cancel: CancellationToken,
) {
    loop {
        let check = tokio::select! {
            () = cancel.cancelled() => return,
            check = capture.check(&proof) => check,
        };
        if tx
            .send(Internal::Capture { generation, check })
            .await
            .is_err()
        {
            return;
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(t.capture_watch) => {}
        }
    }
}

impl Actor {
    /// Starts the session's watchdogs; they end with `session.watch`.
    pub(super) fn spawn_watchdogs(&self, s: &Session) {
        let t = self.deps.timings.clone();
        let verdicts = Verdicts {
            tx: self.internal_tx.clone(),
            generation: s.generation,
            failures: 0,
        };
        let confirmations = self.deps.confirmations.clone();
        match &s.req.mode {
            Mode::LocalProxy { addr, .. } => match config::proxy_addr(addr) {
                Ok(addr) => {
                    let task =
                        local_watch(addr, confirmations, t.clone(), verdicts, s.watch.clone());
                    tokio::spawn(task);
                }
                Err(e) => tracing::warn!(error = %e, "proxy watchdog disabled: bad address"),
            },
            Mode::DirectVpn { .. } => {
                let engines = self.deps.engines.clone();
                let task = egress_watch(
                    engines,
                    s.clash.clone(),
                    confirmations,
                    t.clone(),
                    verdicts,
                    s.watch.clone(),
                );
                tokio::spawn(task);
            }
        }
        tokio::spawn(capture_watch(
            self.deps.capture.clone(),
            s.proof.clone(),
            t,
            self.internal_tx.clone(),
            s.generation,
            s.watch.clone(),
        ));
    }

    /// A watchdog report; reports of an earlier session are ignored.
    pub(super) async fn on_internal(&mut self, report: Internal) {
        let Phase::Running(s) = &mut self.phase else {
            return;
        };
        let current = s.generation;
        match report {
            Internal::ProxyDown { generation } if generation == current => {
                let reason = match &s.req.mode {
                    Mode::LocalProxy { addr, .. } => {
                        Msg::new("tunnel.runtime.watchdog.proxyDown").arg("addr", addr)
                    }
                    // The current name: an in-place switch changes it.
                    Mode::DirectVpn { profile } => Msg::new("tunnel.runtime.watchdog.upstreamDown")
                        .arg("name", &profile.profile.name),
                };
                self.proxy_down(reason);
            }
            Internal::ProxyUp { generation } if generation == current => self.proxy_up(),
            Internal::Capture { generation, check } if generation == current => {
                let kind = match check {
                    CaptureCheck::Competing(name) if s.competing.as_ref() != Some(&name) => {
                        tracing::warn!(foreign = %name, "a competing tunnel appeared");
                        s.competing = Some(name.clone());
                        TunStatusKind::CompetingTun { name }
                    }
                    CaptureCheck::Clear if s.competing.take().is_some() => {
                        TunStatusKind::CompetingTunCleared
                    }
                    _ => return,
                };
                self.announce(kind);
            }
            _ => {}
        }
    }
}
