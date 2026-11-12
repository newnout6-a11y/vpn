//! The hub's operations behind the API methods. A state-changing one runs on its own backend
//! task, so it completes when the page is left mid-call, and publishes what it changed before it
//! returns; measurements (pings) stop with their caller instead.
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;
use vpnte_base::types::{Level, Notice, Verdict};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::ops::{FeatureKind, RunOpts, Source};
use vpnte_probes::leak::{CheckReport, CheckStatus};
use vpnte_probes::ping::PingSample;
use vpnte_servers::model::ProfileId;
use vpnte_tunnel::api::ModeKind;
use vpnte_tunnel::lifecycle::{ConnError, DEFAULT_TIMEOUT, Done};
use vpnte_ui::panels::Selected;
use vpnte_ui::tray::QuitMode;

use super::{Hub, project};
use crate::services::TunnelOps;
use crate::support::{blocking, detached};

/// The tunnel's share of the app-exit cleanup (the whole exit stays within ~15 s).
const QUIT_TUNNEL_BUDGET: Duration = Duration::from_secs(12);
/// Draining the feature operations at exit.
const QUIT_OPS_BUDGET: Duration = Duration::from_secs(3);

/// Who shows a lane call's warnings to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Shows {
    /// Nobody else: they become notices (connect, server switch).
    Notices,
    /// The call's own answer carries them («off, but …» of a disconnect).
    Answer,
}

/// Counts a lane call in `Hub::inflight` for its whole life, a panic included.
struct InFlight(Arc<Hub>);

impl InFlight {
    fn new(hub: &Arc<Hub>) -> Self {
        hub.inflight.send_modify(|n| *n += 1);
        Self(hub.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.inflight.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl Hub {
    fn tunnel(&self) -> AppResult<Arc<dyn TunnelOps>> {
        Ok(self.backend.tunnel()?.clone())
    }

    /// A lane call (connect, disconnect) on a backend task, counted for a cancel; the views are
    /// republished when it starts and when it ends. `shows` = who shows the call's warnings.
    pub(super) async fn lane<F, Fut>(self: &Arc<Self>, shows: Shows, call: F) -> AppResult<Done>
    where
        F: FnOnce(Arc<dyn TunnelOps>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<Done, ConnError>> + Send + 'static,
    {
        let tunnel = self.tunnel()?;
        let hub = self.clone();
        detached(async move {
            let counted = InFlight::new(&hub);
            hub.publish_all();
            let res = call(tunnel).await;
            hub.lane_ended(&res, shows);
            drop(counted);
            hub.publish_all();
            res.map_err(AppError::from)
        })
        .await
    }

    /// A lane call's warnings (Xray's dropped settings, unresolved names, …) reach the user
    /// (SERVICES: `Done::warnings` are extra messages to show): as notices unless the caller's
    /// answer carries them; while a cancel is pending they become its answer instead.
    fn lane_ended(&self, res: &Result<Done, ConnError>, shows: Shows) {
        let warnings = match res {
            Ok(done) => done.warnings.as_slice(),
            Err(err) => err.warnings(),
        };
        for w in warnings {
            tracing::warn!(key = %w.key, "connection call finished with a warning");
        }
        let mut local = self.local.lock();
        if local.conn.cancelling {
            local.cancel_warnings.extend_from_slice(warnings);
            return;
        }
        drop(local);
        if shows == Shows::Notices {
            for w in warnings {
                let notice = Notice::new(Level::Warn, w.clone());
                self.backend.notifier.notify(notice, None);
            }
        }
    }

    /// The «Отмена» button: publishes `cancelling` at once, stops the connect or switch in flight
    /// and answers when it is over (no lane call of ours left, no transition in the snapshot).
    pub(super) async fn cancel(self: &Arc<Self>) -> AppResult<Option<Msg>> {
        let tunnel = self.tunnel()?;
        let hub = self.clone();
        detached(async move {
            {
                let mut local = hub.local.lock();
                if local.conn.cancelling {
                    return Ok(None);
                }
                local.conn.cancelling = true;
                local.cancel_warnings.clear();
            }
            hub.publish_all();
            tunnel.cancel();
            let settled = timeout(DEFAULT_TIMEOUT, hub.idle()).await;
            let warnings = {
                let mut local = hub.local.lock();
                local.conn.cancelling = false;
                std::mem::take(&mut local.cancel_warnings)
            };
            hub.publish_all();
            match settled {
                Ok(()) => Ok(warnings.into_iter().next()),
                Err(_) => Err(AppError::timeout()),
            }
        })
        .await
    }

    /// Returns once no lane call of ours runs and the lifecycle shows no transition.
    async fn idle(&self) {
        let mut inflight = self.inflight.subscribe();
        let Some(mut snap) = self.watches.as_ref().map(|w| w.snapshot.clone()) else {
            return;
        };
        loop {
            let busy =
                *inflight.borrow_and_update() > 0 || snap.borrow_and_update().transition.is_some();
            if !busy {
                return;
            }
            tokio::select! {
                r = inflight.changed() => if r.is_err() { return },
                r = snap.changed() => if r.is_err() { return },
            }
        }
    }
}

impl Hub {
    /// Selects server `id`; a live server session switches over (the slab shows SWITCH with the
    /// target's name). The optimistic selection is published first.
    pub(super) async fn select(self: &Arc<Self>, id: String) -> AppResult<Selected> {
        let tunnel = self.tunnel()?;
        let hub = self.clone();
        detached(async move {
            let list = hub.backend.servers.view();
            if !list.fallback && list.active.as_ref().is_some_and(|a| a.as_str() == id) {
                return Ok(Selected::Done);
            }
            let name = list
                .servers
                .iter()
                .find(|s| s.id.as_str() == id)
                .map(|s| s.name.clone());
            let live = hub.watches.as_ref().is_some_and(|w| {
                let status = w.status.borrow();
                status.running && status.mode == Some(ModeKind::DirectVpn)
            });
            {
                let mut local = hub.local.lock();
                local.pending_active = Some(id.clone());
                local.conn.switching = name.filter(|_| live);
            }
            let counted = InFlight::new(&hub);
            hub.publish_all();
            let res = tunnel.switch_server(ProfileId::from(id), Source::Ui).await;
            hub.lane_ended(&res, Shows::Notices);
            {
                let mut local = hub.local.lock();
                local.pending_active = None;
                local.conn.switching = None;
            }
            drop(counted);
            hub.publish_all();
            match res {
                Ok(_) => Ok(Selected::Done),
                Err(ConnError::Cancelled(_)) => Ok(Selected::Cancelled),
                Err(err) => Err(err.into()),
            }
        })
        .await
    }

    /// Pings servers `ids`; the tunnel records each result in the server list as it lands. A
    /// measurement, not a change: it stops when the caller goes away (and at app exit).
    pub(super) async fn ping(
        &self,
        ids: Vec<ProfileId>,
    ) -> AppResult<Vec<(ProfileId, Option<PingSample>)>> {
        let tunnel = self.tunnel()?;
        let cancel = self.backend.shutdown.child_token();
        let _stop = cancel.clone().drop_guard();
        let res = tunnel.ping(ids, cancel).await;
        self.publish_servers();
        res
    }

    /// The leak check as a registry operation (one at a time, app-wide). Its verdict becomes the
    /// start page's fact unless a transition happened meanwhile; a failed run leaves no verdict.
    pub(super) async fn leak_check(self: &Arc<Self>, source: Source) -> AppResult<CheckReport> {
        let tunnel = self.tunnel()?;
        let hub = self.clone();
        detached(async move {
            let epoch = hub.local.lock().epoch;
            let opts = RunOpts {
                source,
                ..RunOpts::default()
            };
            let res = hub
                .backend
                .ops
                .run(FeatureKind::LeakCheck, opts, move |lease| async move {
                    let token = lease.token().clone();
                    lease
                        .wait(async move { tunnel.leak_check(token).await })
                        .await?
                })
                .await;
            {
                let mut local = hub.local.lock();
                if local.epoch == epoch {
                    local.leak = res
                        .as_ref()
                        .map_or(Verdict::NotChecked, project::leak_verdict);
                }
            }
            hub.publish_dashboard();
            if let Ok(report) = &res {
                // The page shows only the verdict; the log keeps which checks need attention.
                for item in &report.items {
                    if matches!(item.status, CheckStatus::Warn | CheckStatus::Fail) {
                        tracing::warn!(item = item.id, status = ?item.status, "leak check finding");
                    }
                }
            }
            res
        })
        .await
    }

    /// «Проверить маршрут» from the tray: the leak check, its verdict as a notice.
    pub(super) async fn check_route(self: &Arc<Self>) -> AppResult<()> {
        let report = self.leak_check(Source::Tray).await?;
        let notice = Notice {
            level: project::check_level(report.summary),
            title: Msg::new("app.dashboard.routeCheck"),
            body: Some(report.headline),
        };
        // Asked for by the user: no category, so no notification switch hides the answer.
        self.backend.notifier.notify(notice, None);
        Ok(())
    }
}

impl Hub {
    /// Reads the kill switch back (shown as «Проверяем» meanwhile); of overlapping reads only
    /// the latest one lands.
    pub(super) async fn read_firewall(&self) {
        let Some(w) = &self.watches else {
            return;
        };
        let seq = {
            let mut local = self.local.lock();
            local.firewall_seq += 1;
            local.firewall.checking = true;
            local.firewall_seq
        };
        self.publish_dashboard();
        let status = w.tunnel.kill_switch().await;
        {
            let mut local = self.local.lock();
            if local.firewall_seq != seq {
                return;
            }
            local.firewall = project::firewall(&status);
            local.kill_switch = project::kill_switch_engaged(&status);
        }
        self.publish_dashboard();
        self.publish_tray();
    }

    /// [`Hub::read_firewall`] on its own task.
    pub(super) fn refresh_firewall(self: &Arc<Self>) {
        let hub = self.clone();
        tokio::spawn(async move { hub.read_firewall().await });
    }

    /// «Перепроверить»: a fresh kill-switch read-back, published through the page.
    pub(super) async fn recheck_firewall(self: &Arc<Self>) -> AppResult<()> {
        let hub = self.clone();
        detached(async move {
            hub.read_firewall().await;
            Ok(())
        })
        .await
    }

    /// Removes our filters after a session (`Permission` unelevated, `Conflict` in a session);
    /// the read-back that follows shows what is left either way.
    pub(super) async fn release_kill_switch(self: &Arc<Self>) -> AppResult<()> {
        let tunnel = self.tunnel()?;
        let hub = self.clone();
        detached(async move {
            let res = tunnel.release_kill_switch().await;
            hub.read_firewall().await;
            let report = res?;
            tracing::info!(
                filters = report.filters,
                "kill-switch filters removed by the user"
            );
            Ok(())
        })
        .await
    }

    /// «Подключить» in the paused state: the paused session retries at once; `false` when nothing
    /// is paused any more (it just came back, or the user ended it).
    pub(super) async fn retry_now(self: &Arc<Self>) -> AppResult<bool> {
        let tunnel = self.tunnel()?;
        detached(async move { Ok(tunnel.retry_now().await) }).await
    }

    /// Puts the exit address on the secret clipboard (cleared after a minute).
    pub(super) async fn copy_ip(&self, ip: IpAddr) -> AppResult<()> {
        let backend = self.backend.clone();
        detached(async move {
            // Started on a backend task: the clipboard's owner task needs the runtime.
            let _ = backend.clipboard();
            blocking(move || backend.clipboard().copy(&ip.to_string()))
                .await
                .map(|_| ())
        })
        .await
    }

    /// Saves Smart RU. It applies on the next connect, as the page and the mascot say: a running
    /// tunnel is not restarted for it.
    pub(super) async fn set_smart_ru(self: &Arc<Self>, on: bool) -> AppResult<()> {
        let hub = self.clone();
        detached(async move {
            let settings = hub.backend.settings.clone();
            blocking(move || settings.update(|s| s.smart_ru_split = on)).await?;
            hub.publish_dashboard();
            Ok(())
        })
        .await
    }

    /// The bounded app-exit cleanup (SERVICES.md order). `Err` refuses the exit: under
    /// [`QuitMode::Restore`] when Soft's system proxy could not be rolled back.
    pub(super) async fn quit(self: &Arc<Self>, mode: QuitMode) -> AppResult<()> {
        let hub = self.clone();
        detached(async move {
            let backend = &hub.backend;
            backend.shutdown.cancel();
            if let Ok(tunnel) = backend.tunnel() {
                let report = tunnel.shutdown(QUIT_TUNNEL_BUDGET).await;
                tracing::info!(?report, ?mode, "app-exit cleanup of the tunnel");
                if mode == QuitMode::Restore && !report.soft_restored {
                    return Err(AppError::msg(
                        ErrorKind::Internal,
                        Msg::new("app.dashboard.restoreFailed"),
                    ));
                }
            }
            if timeout(QUIT_OPS_BUDGET, backend.ops.close()).await.is_err() {
                tracing::warn!("feature operations still draining at exit");
            }
            if let Some(clipboard) = backend.clipboard.get() {
                clipboard.shutdown();
            }
            tracing::info!("exit cleanup done");
            // Last: drains the app log (the process exits without running destructors).
            drop(backend.log.lock().take());
            Ok(())
        })
        .await
    }
}
