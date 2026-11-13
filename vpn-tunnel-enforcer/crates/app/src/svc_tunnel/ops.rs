//! [`TunnelOps`] over the lifecycle, the kill-switch guard and the session collaborators. Lane
//! operations act as the user (`Owner::Manual`).
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_automation::scheduler::Wake;
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
    ConnError, DisconnectReq, Done, KillSwitchView, SessionView, ShutdownReport, StopCause,
    SwitchReq,
};
use vpnte_tunnel::runtime::{EngineExes, EngineStarts};
use vpnte_winnet::wfp::{ExceptionKind, KillSwitchException, RemoveReport, Toggles};

use super::guard::Guard;
use super::{TunnelService, decide, probe};
use crate::services::{Engines, KillSwitchStatus, TunnelOps};
use crate::svc_auto::UserAct;
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
        let detector = crate::svc_tunnel::make_detector(&self.detector);
        let found = tokio::select! {
            found = detector.detect() => found,
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
        // Through the coordinator: the adaptive bypass picks the mode of every start.
        self.coord.start(target, Owner::Manual, source).await
    }

    async fn disconnect(&self, source: Source) -> Result<Done, ConnError> {
        // Nothing automatic after it (a restore of a lost switch, the retries) until the user
        // connects again.
        self.coord.user_acted(UserAct::Stop);
        self.lifecycle
            .disconnect(DisconnectReq::new(StopCause::User, Owner::Manual, source))
            .await
    }

    fn cancel(&self) {
        let detection = self.pending.lock().take();
        // Cancel of a connect or switch in flight is the user's stop, also when the lane then
        // ends the session with an outcome automation reads as a fault; with nothing in flight
        // it still ends what automation had begun.
        let in_flight = detection.is_some() || self.lifecycle.busy();
        let act = if in_flight {
            UserAct::Stop
        } else {
            UserAct::Change
        };
        self.coord.user_acted(act);
        if let Some(detection) = detection {
            detection.cancel();
        }
        self.lifecycle.cancel_pending();
    }

    fn end_autopick(&self) {
        // Not the lane's Cancel: a switch the choice has in flight runs to its end (cutting it
        // would end the whole session and lift the protection, psmall-b1); the episode stops
        // after it and the session it leaves stays as it is (psmall-b2).
        self.coord.user_acted(UserAct::EndAuto);
    }

    async fn switch_server(&self, id: ProfileId, source: Source) -> Result<Done, ConnError> {
        // A server picked by hand ends every automatic path (and a restore on its way).
        self.coord.user_acted(UserAct::Pick);
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
        // A changed setting is the user's action: automatic paths that began before give up.
        self.coord.user_acted(UserAct::Change);
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
            // The adaptive bypass decides the mode of a settings restart (off → baseline).
            let running = self
                .lifecycle
                .session()
                .borrow()
                .as_ref()
                .map(|s| s.adaptive);
            let mode = running.map(|m| self.automation.adaptive.restart_mode(m));
            match (running, mode) {
                (Some(running), Some(mode)) if mode != running => {
                    self.lifecycle
                        .restart_adaptive(mode, None, Owner::Manual)
                        .await
                }
                _ => {
                    self.lifecycle
                        .restart_with_last(reason, Owner::Manual, Source::Ui)
                        .await
                }
            }
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
        self.coord.user_acted(UserAct::Change);
        self.guarded(move |g| g.set_level(level)).await?;
        // The live session follows the new level at once: a later drop pauses, or not, as the
        // user just chose (fix-ks a1).
        self.lifecycle.kill_switch_changed();
        // A level change ends a pause (research 5.2): with the kill switch off nothing should
        // hold the internet any more, so the paused session ends like «Продолжить без VPN».
        let paused = self.lifecycle.kill_switch().borrow().pause.is_some();
        if level == KillSwitchLevel::Off && paused {
            self.lifecycle
                .disconnect(DisconnectReq::new(
                    StopCause::User,
                    Owner::Manual,
                    Source::Ui,
                ))
                .await?;
        }
        Ok(())
    }

    async fn set_protection_toggles(&self, toggles: Toggles) -> AppResult<()> {
        // A changed setting (and its restart) is the user's doing, not a fault to repair.
        self.coord.user_acted(UserAct::Change);
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
            &Engines::from(&*self.exes.borrow()),
            engine,
            device,
            &self.runtime.status().borrow(),
        )
    }

    fn tun_available(&self) -> bool {
        self.guard.tun_available()
    }

    fn service_protocol(&self) -> Option<u32> {
        let remote = self.runtime.remote();
        remote.installed().then(|| remote.protocol()).flatten()
    }

    fn service_rule_sets(&self) -> Option<vpnte_service::proto::RuleSetsWire> {
        let remote = self.runtime.remote();
        let status = self.runtime.status();
        let status = status.borrow();
        // Only the service's own running session: its report says nothing of a proxy one.
        let tunnel = status.running && status.capture == Some(CaptureKind::Tun);
        (tunnel && remote.installed())
            .then(|| remote.rule_sets())
            .flatten()
    }

    fn service_present(&self) -> bool {
        self.runtime.remote().installed()
    }

    fn service_losses(&self) -> Option<watch::Receiver<u64>> {
        Some(self.runtime.remote().losses())
    }

    fn service_starting(&self) -> bool {
        self.runtime.remote().starting()
    }

    fn service_installed(&self) -> bool {
        let installed = self.runtime.remote().recheck();
        if installed {
            self.guard.service_installed();
        }
        installed
    }

    fn resumed(&self) {
        self.lifecycle.resumed();
        // The protection and the DNS capture are re-checked at once (RU audit item 11).
        self.ip.resumed();
        // A schedule boundary may have passed while the machine slept.
        self.automation.scheduler.wake(Wake::Resume);
    }

    fn proxies(&self) -> Option<crate::svc_proxies::ProxySlots> {
        Some(self.proxies.slots())
    }

    fn live_checks(&self) -> Option<std::sync::Arc<vpnte_probes::live::LiveCheckService>> {
        self.live.clone()
    }

    fn kill_switch_view(&self) -> watch::Receiver<KillSwitchView> {
        self.lifecycle.kill_switch()
    }

    async fn retry_now(&self) -> bool {
        self.coord.user_acted(UserAct::Change);
        self.lifecycle.retry_now().await
    }

    fn set_engines(&self, engines: Engines) -> bool {
        // An elevated process holding the WFP filters keeps the start's engines: its permits
        // name those paths, so a new file would be blocked.
        if self.guard.wfp.is_some() {
            return false;
        }
        self.exes.send_replace(EngineExes {
            singbox: engines.singbox,
            xray: engines.xray,
        });
        true
    }

    fn engine_starts(&self) -> Option<watch::Receiver<EngineStarts>> {
        Some(self.starts.clone())
    }

    fn engines(&self) -> Option<Engines> {
        Some(Engines::from(&*self.exes.borrow()))
    }

    async fn reconnect(&self, reason: String) -> Result<Done, ConnError> {
        self.coord.user_acted(UserAct::Change);
        self.lifecycle
            .restart_with_last(reason, Owner::Manual, Source::Ui)
            .await
    }

    fn always_available(&self) -> bool {
        self.guard.always_available()
    }

    fn proxy_taken(&self) -> watch::Receiver<bool> {
        super::soft::taken::subscribe()
    }

    async fn reclaim_proxy(&self) -> vpnte_base::AppResult<()> {
        self.soft.reclaim().await
    }

    async fn clear_traffic_history(&self) -> vpnte_base::AppResult<()> {
        self.domains.clear().await
    }

    async fn shutdown(&self, budget: Duration) -> ShutdownReport {
        let deadline = Instant::now() + budget;
        let left = || {
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(500))
        };
        let mut report = self.lifecycle.shutdown(budget).await;
        if tokio::time::timeout(left(), self.automation.privacy.session_down())
            .await
            .is_err()
        {
            tracing::warn!("location privacy rollback timed out");
        }
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
        // Slots stop with the app (their engines would die with the kill-on-close job anyway;
        // this ends them cleanly and closes the control API).
        if tokio::time::timeout(left(), self.proxies.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("external proxies shutdown timed out");
        }
        if let Some(live) = &self.live
            && tokio::time::timeout(left(), live.shutdown()).await.is_err()
        {
            tracing::warn!("live check shutdown timed out");
        }
        let guard = self.guard.clone();
        let closing = tokio::task::spawn_blocking(move || guard.shutdown());
        if tokio::time::timeout(left(), closing).await.is_err() {
            tracing::warn!("protection shutdown timed out");
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use vpnte_base::types::KillSwitchLevel;
    use vpnte_core::ops::Source;
    use vpnte_servers::model::ProfileId;

    use crate::api_settings::test_support::{FakeTunnel, TempDir, backend};

    /// Review fix b1/a2/a4 (the user always wins): Cancel, Disconnect, a server picked by hand
    /// and a changed setting reach the automatic paths as the user's actions; a Cancel with
    /// nothing in flight ends them without counting as a stop. Unelevated, nothing starts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_users_lane_actions_reach_automation() {
        let dir = TempDir::new("ops-user-acts");
        let b = backend(&dir, FakeTunnel::new(false));
        let built = super::super::build(&b).expect("tunnel service");
        let (t, acts) = (built.tunnel.clone(), built.automation.coord.user_acts());
        let now = || {
            let a = *acts.borrow();
            (a.seq, a.stopped)
        };
        t.cancel();
        assert_eq!(
            now(),
            (1, false),
            "nothing in flight: an action, not a stop"
        );
        let _ = t
            .switch_server(ProfileId::from("missing"), Source::Ui)
            .await;
        assert_eq!(now(), (2, false), "a server picked by hand");
        let _ = t.disconnect(Source::Ui).await;
        assert_eq!(
            now(),
            (3, true),
            "a stop: nothing automatic until a connect"
        );
        let settings = b.settings.snapshot();
        let _ = t.apply_settings_change(settings.clone(), settings).await;
        assert_eq!(now(), (4, true), "a changed setting");
        let _ = t.set_kill_switch_level(KillSwitchLevel::Off).await;
        assert_eq!(now(), (5, true), "the kill switch's level");
        let _ = t.shutdown(Duration::from_secs(5)).await;
        b.shutdown.cancel();
    }
}
