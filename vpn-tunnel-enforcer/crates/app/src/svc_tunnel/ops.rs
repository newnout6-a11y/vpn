//! [`TunnelOps`] over the lifecycle, the kill-switch guard and the session collaborators. Lane
//! operations act as the user (`Owner::Manual`).
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, KillSwitchLevel, Owner};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::Source;
use vpnte_core::settings::{ConnectionMode, RoutingMode, Settings};
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::leak::CheckReport;
use vpnte_probes::ping::PingSample;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::SelectBy;
use vpnte_tunnel::api::{CaptureKind, ModeKind, Runtime, TunError, TunStatus};
use vpnte_tunnel::fsm::TunnelSnapshot;
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectReq, DisconnectReq, Done, SessionView, ShutdownReport, StopCause, SwitchReq,
};
use vpnte_winnet::wfp::{ExceptionKind, KillSwitchException, RemoveReport, Toggles};

use super::guard::Guard;
use super::{TunnelService, decide, probe};
use crate::services::{KillSwitchStatus, TunnelOps};
use crate::svc_core::needs_admin;

fn failed(e: AppError) -> ConnError {
    ConnError::Failed(TunError::from(e))
}

impl TunnelService {
    /// Runs a blocking guard operation (WFP calls, store writes) off the async threads.
    async fn guarded<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Guard) -> AppResult<T> + Send + 'static,
    ) -> AppResult<T> {
        let guard = self.guard.clone();
        tokio::task::spawn_blocking(move || f(&guard))
            .await
            .map_err(AppError::internal)?
    }

    fn status(&self) -> TunStatus {
        self.runtime.status().borrow().clone()
    }

    /// The local proxy to chain to: the configured one, else a detected one (Happ & co.).
    /// "Cancel" ends the detection.
    async fn upstream(&self, s: &Settings) -> Result<Option<decide::Upstream>, ConnError> {
        if let Some(up) = decide::configured_upstream(s) {
            return Ok(Some(up));
        }
        let token = CancellationToken::new();
        *self.pending.lock() = Some(token.clone());
        let found = tokio::select! {
            found = self.detector.detect() => found,
            () = token.cancelled() => {
                return Err(ConnError::Cancelled(Msg::new("tunnel.lifecycle.lane.startCancelled")));
            }
        };
        self.pending.lock().take();
        Ok(found.map(|p| decide::Upstream {
            addr: p.addr.to_string(),
            kind: p.kind,
        }))
    }
}

#[async_trait]
impl TunnelOps for TunnelService {
    async fn connect(&self, source: Source) -> Result<Done, ConnError> {
        let s = self.settings.snapshot();
        if s.routing_mode == RoutingMode::Hard && !self.tun_available() {
            // Never fall back to Soft silently (NOADMIN §2): the message offers it.
            return Err(ConnError::Failed(TunError::new(
                ErrorKind::Permission,
                Msg::new("tunnel.runtime.tunUnavailable"),
            )));
        }
        let upstream = match s.connection_mode {
            ConnectionMode::LocalProxy => self.upstream(&s).await?,
            ConnectionMode::DirectVpn => None,
        };
        let target = decide::connect_target(s.connection_mode, s.routing_mode, upstream)
            .ok_or_else(|| ConnError::NoServer(Msg::new("app.tunnel.noLocalProxy")))?;
        self.lifecycle
            .connect(ConnectReq::new(target, Owner::Manual, source))
            .await
    }

    async fn disconnect(&self, source: Source) -> Result<Done, ConnError> {
        self.lifecycle
            .disconnect(DisconnectReq::new(StopCause::User, Owner::Manual, source))
            .await
    }

    fn cancel(&self) {
        if let Some(detection) = self.pending.lock().take() {
            detection.cancel();
        }
        self.lifecycle.cancel_pending();
    }

    async fn switch_server(&self, id: ProfileId, source: Source) -> Result<Done, ConnError> {
        let servers = self.servers.clone();
        let pick = id.clone();
        tokio::task::spawn_blocking(move || servers.select(&pick, SelectBy::User))
            .await
            .map_err(|e| failed(AppError::internal(e)))?
            .map_err(failed)?;
        let status = self.status();
        if !(status.running && status.mode == Some(ModeKind::DirectVpn)) {
            // Idle, or a local-proxy session: the selection is all there is to do.
            return Ok(Done::default());
        }
        self.lifecycle
            .switch_upstream(SwitchReq::new(id.0, Owner::Manual, source))
            .await
    }

    async fn apply_settings_change(&self, old: Settings, new: Settings) -> Result<Done, ConnError> {
        let change = decide::settings_change(&old, &new);
        if let Some(every) = change.check_interval {
            self.ip.ip.set_interval(every);
        }
        if change.rule_sets {
            self.rule_sets.notify_one();
        }
        let level = match change.kill_switch {
            Some(level) => self.guarded(move |g| g.set_level(level)).await,
            None => Ok(()),
        };
        let done = if change.restart.is_empty() {
            Ok(Done::default())
        } else {
            let reason = format!("settings changed: {}", change.restart.join(", "));
            self.lifecycle
                .restart_with_last(reason, Owner::Manual, Source::Ui)
                .await
        };
        level.map_err(failed)?;
        done
    }

    fn snapshot(&self) -> watch::Receiver<TunnelSnapshot> {
        self.lifecycle.snapshot()
    }

    fn session(&self) -> watch::Receiver<Option<SessionView>> {
        self.lifecycle.session()
    }

    fn runtime_status(&self) -> watch::Receiver<TunStatus> {
        self.runtime.status()
    }

    async fn kill_switch(&self) -> KillSwitchStatus {
        match self.guarded(|g| Ok(g.status())).await {
            Ok(status) => status,
            Err(e) => {
                tracing::warn!(error = %e, "kill-switch read-back failed");
                self.guard.saved_status()
            }
        }
    }

    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        self.guarded(move |g| g.set_level(level)).await
    }

    async fn set_protection_toggles(&self, toggles: Toggles) -> AppResult<()> {
        let reshaped = self.guarded(move |g| g.set_toggles(toggles)).await?;
        // Leak protection selects the TUN form (dual stack, native DNS); a Soft session has none.
        if reshaped && self.status().capture == Some(CaptureKind::Tun) {
            self.lifecycle
                .restart_with_last("leak protection changed", Owner::Manual, Source::Ui)
                .await?;
        }
        Ok(())
    }

    async fn add_exception(
        &self,
        kind: ExceptionKind,
        value: String,
        label: String,
    ) -> AppResult<KillSwitchException> {
        self.guarded(move |g| g.add_exception(kind, &value, &label))
            .await
    }

    async fn remove_exception(&self, id: String) -> AppResult<()> {
        self.guarded(move |g| g.remove_exception(&id)).await
    }

    async fn release_kill_switch(&self) -> AppResult<RemoveReport> {
        if !self.tun_available() {
            return Err(needs_admin());
        }
        // An escape hatch: with the lane held, allowed in blocked / unknown / error states.
        let guard = self.guard.clone();
        self.lifecycle
            .maintenance(move || async move {
                tokio::task::spawn_blocking(move || guard.release())
                    .await
                    .map_err(AppError::internal)?
            })
            .await?
    }

    fn ip_evidence(&self) -> watch::Receiver<IpEvidence> {
        self.ip.ip.subscribe()
    }

    async fn leak_check(&self, cancel: CancellationToken) -> AppResult<CheckReport> {
        let settings = self.settings.snapshot();
        let status = self.status();
        let evidence = self.ip.ip.evidence();
        let self_test = self.ip.leaks.as_ref().and_then(|l| l.latest.lock().clone());
        probe::leak_check(
            self.ip.reader(),
            &settings,
            &status,
            evidence,
            self_test,
            &cancel,
        )
        .await
    }

    fn traffic(&self) -> watch::Receiver<TrafficStats> {
        self.forensics.traffic()
    }

    async fn ping(
        &self,
        ids: Vec<ProfileId>,
        cancel: CancellationToken,
    ) -> AppResult<Vec<(ProfileId, Option<PingSample>)>> {
        let net = probe::net_path(&self.runtime.status().borrow());
        probe::ping(&self.servers, ids, net, cancel).await
    }

    fn probe_ctx(&self, device: ClientDevice) -> ProbeCtx {
        let engine = self.settings.read(|s| s.proxy_engine);
        probe::probe_ctx(
            &self.engines,
            engine,
            device,
            &self.runtime.status().borrow(),
        )
    }

    fn tun_available(&self) -> bool {
        self.guard.wfp.is_some()
    }

    async fn shutdown(&self, budget: Duration) -> ShutdownReport {
        let deadline = Instant::now() + budget;
        let left = || {
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(500))
        };
        let mut report = self.lifecycle.shutdown(budget).await;
        // On exit the tweaks are always rolled back (NOADMIN §2), also when the lane ran out of
        // time; the journal is serialised, so a rollback still running in the lane is harmless.
        if self.soft.soft.is_applied() {
            report.soft_restored = matches!(
                tokio::time::timeout(left(), self.soft.restore()).await,
                Ok(Ok(()))
            );
        }
        if tokio::time::timeout(left(), self.forensics.flush())
            .await
            .is_err()
        {
            tracing::warn!("domain history flush timed out");
        }
        let guard = self.guard.clone();
        let closing = tokio::task::spawn_blocking(move || guard.shutdown());
        if tokio::time::timeout(left(), closing).await.is_err() {
            tracing::warn!("protection shutdown timed out");
        }
        report
    }
}
