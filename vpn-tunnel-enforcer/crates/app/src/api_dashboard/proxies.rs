//! The start page's external-proxy column over the slots the tunnel hosts
//! (`TunnelOps::proxies`): rows from the manager's pushed snapshot (readiness re-derived at
//! every projection: it expires with the clock), picker choices from the server list, and the
//! four actions, each publishing the new column before it returns.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_proxies::manager::{ProxySnapshot, degradation_msg};
use vpnte_proxies::model::{
    Action, Health, InstanceStatus, ProxyError, ProxyOps, StartRequest, StopReason, StopScope,
};
use vpnte_proxies::slot::Slot;
use vpnte_servers::model::{ServerSummary, ServersView};
use vpnte_ui::panels::{ProxiesView, ProxyChoice, ProxyHealth, ProxyRowView};

use super::{Hub, project, set};

#[cfg(test)]
mod tests;

/// Coalesces bursts of server-list events (a ping-all) into one projection.
const DEBOUNCE: Duration = Duration::from_millis(60);

/// One action of the column.
pub(super) enum ProxyAction {
    /// «+»: the picked server on the slot the page chose (the lowest one without a process).
    Start {
        slot: u16,
        profile_id: String,
    },
    Stop(u16),
    Rotate(u16),
    /// «стоп все»: every slot without a lease (leased slots serve automation clients).
    StopAll,
}

/// The tunnel hosts no slots: the column stays empty and its actions say so.
pub(super) fn unavailable() -> AppError {
    AppError::msg(
        ErrorKind::Conflict,
        Msg::new("app.dashboard.proxiesUnavailable"),
    )
}

impl Hub {
    /// Projects the column from the latest snapshot and server list.
    pub(super) fn publish_proxies(&self) {
        if let Some(slots) = &self.slots {
            let snap = slots.state.borrow().clone();
            set(
                &self.proxies,
                view(&snap, &self.backend.servers.view(), now_ms()),
            );
        }
    }

    /// Runs `action` on its own backend task (it finishes even when the page drops the call),
    /// publishes the column and returns it (the page's toast reads it).
    pub(super) async fn proxy(self: &Arc<Self>, action: ProxyAction) -> AppResult<ProxiesView> {
        let ops = self.slots.as_ref().ok_or_else(unavailable)?.ops.clone();
        let hub = self.clone();
        let work = async move {
            let done = apply(&*ops, action).await;
            hub.publish_proxies();
            done.map_err(AppError::from)?;
            Ok(hub.proxies.borrow().clone())
        };
        tokio::spawn(work)
            .await
            .unwrap_or_else(|err| Err(AppError::internal(err)))
    }
}

/// One action over the slot operations.
async fn apply(ops: &dyn ProxyOps, action: ProxyAction) -> Result<(), ProxyError> {
    let slot = |n: u16| Slot::new(u64::from(n));
    match action {
        ProxyAction::Start {
            slot: n,
            profile_id,
        } => {
            let req = StartRequest {
                slot: Some(slot(n)?),
                profile_id: Some(profile_id),
                action: Action::Start,
                ..StartRequest::default()
            };
            ops.start(req).await.map(drop)
        }
        ProxyAction::Stop(n) => ops.stop(slot(n)?, StopReason::Ui).await.map(drop),
        ProxyAction::Rotate(n) => ops.rotate(slot(n)?, Some("ui".into())).await.map(drop),
        ProxyAction::StopAll => {
            ops.stop_all(StopScope::Unleased, StopReason::Ui).await;
            Ok(())
        }
    }
}

/// Keeps the column current: slot changes from the manager and server-list changes (names,
/// health, the VPN's server). Ends at app exit.
pub(super) fn spawn_feed(hub: &Arc<Hub>) {
    let Some(slots) = hub.slots.clone() else {
        return;
    };
    let hub = hub.clone();
    tokio::spawn(async move {
        let mut state = slots.state;
        let mut events = hub.backend.servers.subscribe();
        let cancel = hub.backend.shutdown.clone();
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                changed = state.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                event = events.recv() => {
                    if let Err(RecvError::Closed) = event {
                        return;
                    }
                    tokio::time::sleep(DEBOUNCE).await;
                    while events.try_recv().is_ok() {}
                }
            }
            hub.publish_proxies();
        }
    });
}

/// The column at `now`: every listed slot by number (failed and auto-disabled ones included, so
/// they can be stopped or restarted) and the servers the picker offers, in list order (archived
/// and locked keys left out).
pub(super) fn view(snap: &ProxySnapshot, list: &ServersView, now: UnixMs) -> ProxiesView {
    let snap = snap.refreshed(now);
    let mut rows: Vec<ProxyRowView> = snap.instances.iter().map(row).collect();
    rows.sort_by_key(|r| r.slot);
    let running = |id: &str| {
        snap.instances
            .iter()
            .any(|i| i.process_running && i.profile_id.as_deref() == Some(id))
    };
    let usable: Vec<ServerSummary> = list.servers.iter().filter(|s| !s.locked).cloned().collect();
    let choices = project::server_rows(&usable)
        .into_iter()
        .map(|r| ProxyChoice {
            in_proxy: running(&r.id),
            vpn_server: list.active.as_ref().is_some_and(|a| a.as_str() == r.id),
            id: r.id,
            name: r.name,
            country: r.country,
            protocol: r.protocol,
            health: r.health,
        })
        .collect();
    ProxiesView { rows, choices }
}

fn row(i: &InstanceStatus) -> ProxyRowView {
    ProxyRowView {
        slot: i.slot.get(),
        process_running: i.process_running,
        ready: i.ready,
        health: health(i.health),
        profile_name: i.profile_name.clone(),
        country: i.country.clone(),
        port: i.port,
        proxy_url: i.proxy_url.clone(),
        latency_ms: i.latency_ms,
        // The degradation says why in the user's language; other errors are technical English.
        last_error: i.degradation_reason.map(degradation_msg).or_else(|| {
            i.last_error
                .as_ref()
                .map(|e| Msg::new("app.proxies.detail").arg("detail", e))
        }),
    }
}

fn health(h: Health) -> ProxyHealth {
    match h {
        Health::Stopped => ProxyHealth::Stopped,
        Health::Starting => ProxyHealth::Starting,
        Health::Healthy => ProxyHealth::Healthy,
        Health::Degraded => ProxyHealth::Degraded,
        Health::Rotating => ProxyHealth::Rotating,
        Health::Quarantined => ProxyHealth::Quarantined,
        Health::Failed => ProxyHealth::Failed,
    }
}
