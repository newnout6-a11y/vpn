//! What the app lends the subscription fetcher (ru-2026 item 3, "try direct, then through the
//! active tunnel, then through any server that works"): the session's own route under the proxy
//! capture, and a short-lived external-proxy slot on a healthy server of the list when every route
//! failed. Installed once by [`super::contexts`], after the tunnel exists.
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Weak};

use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::ProxyKind;
use vpnte_core::net::{HostPort, Route};
use vpnte_proxies::model::{ProxyOps, StopReason};
use vpnte_servers::model::{ProfileId, ServerSummary, ServerVerdict, VerdictRecord};
use vpnte_servers::subscription::{Relays, Spare, SpareFuture};
use vpnte_tunnel::api::{CaptureKind, TunStatus};

use crate::services::Backend;

/// The relays over the running app; weak, so the fetcher inside the backend does not keep the
/// backend alive.
pub(super) struct AppRelays {
    backend: Weak<Backend>,
}

impl AppRelays {
    pub(super) fn new(backend: &Arc<Backend>) -> Self {
        Self {
            backend: Arc::downgrade(backend),
        }
    }
}

impl Relays for AppRelays {
    fn session_route(&self) -> Option<Route> {
        let backend = self.backend.upgrade()?;
        let status = backend.tunnel().ok()?.runtime_status();
        session_route(&status.borrow())
    }

    fn spare_route(&self, cancel: CancellationToken) -> SpareFuture<'_> {
        let backend = self.backend.upgrade();
        Box::pin(async move { borrow_slot(backend?, cancel).await })
    }
}

/// The session's route for the app's own requests: the proxy capture's mixed inbound (it takes no
/// credentials: loopback only, NOADMIN §2). Under the TUN capture a direct request already rides
/// the tunnel, and without a session there is nothing to add.
pub(super) fn session_route(status: &TunStatus) -> Option<Route> {
    match (status.capture, status.session.as_ref()) {
        (Some(CaptureKind::Proxy), Some(session)) => {
            let addr = HostPort::new("127.0.0.1", session.proxy_port?).ok()?;
            Some(Route::proxy(ProxyKind::Socks5, &addr, None))
        }
        _ => None,
    }
}

/// Starts a slot on the healthiest server (not the main VPN's) and hands it out until the fetch
/// drops it; the slot is stopped then.
async fn borrow_slot(backend: Arc<Backend>, cancel: CancellationToken) -> Option<Spare> {
    let tunnel = backend.tunnel().ok()?;
    let slots = tunnel.proxies()?;
    let avoid = tunnel
        .session()
        .borrow()
        .as_ref()
        .map(|s| ProfileId::from(s.profile_id.clone()));
    let servers = backend.servers.clone();
    let view = servers.view();
    let id = pick_healthy(&view.servers, &servers.verdicts(), avoid.as_ref())?;
    lend(start_spare(slots.ops.clone(), id.to_string()), cancel).await
}

/// Runs `start` (a slot start) in a task of its own and hands its spare over. A fetch cancelled
/// mid-start (the refresh deadline, a manual refresh, the user) drops this future, and a start
/// dropped half way would leave a configured slot that nothing stops; here the task finishes the
/// start and, with nobody left to take the spare, drops it, which stops the slot.
pub(super) async fn lend(
    start: impl Future<Output = Option<Spare>> + Send + 'static,
    cancel: CancellationToken,
) -> Option<Spare> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        if let Some(spare) = start.await.filter(|_| !cancel.is_cancelled()) {
            // A failed send hands the spare back, and dropping it stops the slot.
            drop(tx.send(spare));
        }
    });
    rx.await.ok()
}

/// Borrows a slot for `profile` ([`ProxyOps::borrow`]: never leased to a control API client, so
/// the stop of the spare's release cannot be refused).
async fn start_spare(ops: Arc<dyn ProxyOps>, profile: String) -> Option<Spare> {
    let started = match ops.borrow(profile.clone()).await {
        Ok(status) => status.instance,
        Err(err) => {
            tracing::info!(server = %profile, "subscription spare slot not started: {err}");
            return None;
        }
    };
    let slot = started.slot;
    let release = move || match tokio::runtime::Handle::try_current() {
        Ok(handle) => drop(handle.spawn(async move {
            if let Err(err) = ops.stop(slot, StopReason::Api).await {
                tracing::warn!(%slot, "subscription spare slot not stopped: {err}");
            }
        })),
        Err(_) => tracing::warn!(%slot, "subscription spare slot left to the VPN stop"),
    };
    let route = started
        .port
        .and_then(|port| HostPort::new("127.0.0.1", port).ok())
        .map(|addr| Route::proxy(ProxyKind::Socks5, &addr, None));
    let Some(route) = route else {
        release();
        return None;
    };
    Some(Spare::new(route, release))
}

/// The server a spare slot runs on: a usable row whose latest evidence (classifier verdict or key
/// check, whichever is newer) says it works, the most recent first; never `avoid` (the main VPN's
/// server: its slot is refused, and the session route tried it already). `None` when nothing is
/// known to work.
pub(super) fn pick_healthy(
    rows: &[ServerSummary],
    verdicts: &HashMap<ProfileId, VerdictRecord>,
    avoid: Option<&ProfileId>,
) -> Option<ProfileId> {
    rows.iter()
        .filter(|r| r.archived.is_none() && !r.locked && Some(&r.id) != avoid)
        .filter_map(|r| {
            let verdict = verdicts
                .get(&r.id)
                .map(|v| (v.at, v.verdict == ServerVerdict::Healthy));
            let health = r.health.map(|h| (h.at, h.online));
            let (at, works) = match (verdict, health) {
                (Some(v), Some(h)) => v.max(h),
                (v, h) => v.or(h)?,
            };
            works.then_some((at, &r.id))
        })
        .max_by_key(|(at, _)| *at)
        .map(|(_, id)| id.clone())
}
