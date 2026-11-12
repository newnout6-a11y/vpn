//! Background tasks that turn the backend's subscriptions into pushed views (nothing is polled):
//! settings, protection and server-list changes, the tunnel's watches, the exit's country and
//! network changes for the foreign-VPN scan. All stop with `backend.shutdown`.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Verdict;
use vpnte_probes::geo::{LookupOwner, geo_routes};
use vpnte_winnet::adapters;

use super::{Hub, project};

/// Debounce of the network-change watch (adapter added / removed, address changed).
const NET_SETTLE: Duration = Duration::from_millis(1500);

/// Starts the feeds and the first kill-switch read-back.
pub(super) fn spawn(hub: &Arc<Hub>) {
    let cancel = hub.backend.shutdown.child_token();
    tokio::spawn(app_feed(hub.clone(), cancel.clone()));
    if hub.watches.is_some() {
        tokio::spawn(tunnel_feed(hub.clone(), cancel.clone()));
        hub.refresh_firewall();
    }
    tokio::spawn(foreign_feed(hub.clone(), cancel));
}

/// Settings (mode, Smart RU, language, tray switch), the server list and the saved protection.
async fn app_feed(hub: Arc<Hub>, cancel: CancellationToken) {
    let mut settings = hub.backend.settings.subscribe();
    let mut servers = hub.backend.servers.subscribe();
    let mut protection = hub.backend.protection.subscribe();
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = settings.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.publish_dashboard();
                hub.publish_tray();
            }
            event = servers.recv() => match event {
                Ok(_) | Err(RecvError::Lagged(_)) => hub.publish_servers(),
                Err(RecvError::Closed) => return,
            },
            // A saved kill-switch level, switch or exception (Settings, the setup wizard, a
            // maintenance reset): the start page reads the kill switch back at once instead of
            // at the next connect. The store saves after the effect, so the read sees it.
            changed = protection.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.refresh_firewall();
            }
        }
    }
}

/// The lifecycle snapshot, the runtime status, the IP monitor and the traffic sampler.
async fn tunnel_feed(hub: Arc<Hub>, cancel: CancellationToken) {
    let Some(w) = &hub.watches else {
        return;
    };
    let mut snap = w.snapshot.clone();
    let mut status = w.status.clone();
    let mut evidence = w.evidence.clone();
    let mut traffic = w.traffic.clone();
    hub.on_snapshot();
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = snap.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.on_snapshot();
                hub.publish_all();
            }
            changed = status.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.publish_dashboard();
                hub.publish_tray();
            }
            changed = evidence.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.update_geo();
                hub.publish_dashboard();
                hub.publish_tray();
            }
            changed = traffic.changed() => {
                if changed.is_err() {
                    return;
                }
                hub.publish_traffic();
                hub.publish_tray();
            }
        }
    }
}

/// Scans for another VPN's adapter at start and after every network change.
async fn foreign_feed(hub: Arc<Hub>, cancel: CancellationToken) {
    let mut changes = adapters::watch_network(NET_SETTLE, cancel.clone())
        .inspect_err(
            |err| tracing::warn!(%err, "no network-change watch: foreign VPN scanned once"),
        )
        .ok();
    loop {
        let found = tokio::task::spawn_blocking(scan_foreign)
            .await
            .ok()
            .flatten();
        let changed = {
            let mut local = hub.local.lock();
            let changed = local.foreign != found;
            local.foreign = found;
            changed
        };
        if changed {
            hub.publish_dashboard();
        }
        let Some(rx) = changes.as_mut() else {
            return;
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            change = rx.recv() => if change.is_none() { return },
        }
    }
}

/// The first foreign tunnel adapter as `name (ip)`, route conflicts first (our own TUN aliases
/// are not foreign); `None` when the adapter table cannot be read.
fn scan_foreign() -> Option<String> {
    let own = adapters::alias::all_aliases();
    let own: Vec<&str> = own.iter().map(String::as_str).collect();
    match adapters::foreign_tun::detect(None, &own) {
        Ok(found) => found.first().map(|f| f.label()),
        Err(err) => {
            tracing::debug!(%err, "adapter table unreadable: no foreign VPN scan");
            None
        }
    }
}

/// A lookup owner that wants its answer until the token is cancelled.
struct Wanted(CancellationToken);

impl LookupOwner for Wanted {
    fn is_current(&self) -> bool {
        !self.0.is_cancelled()
    }
}

impl Hub {
    /// A new snapshot: every transition clears the leak verdict (a check in flight then lands
    /// nowhere), a settled one re-reads the kill switch, and the exit's country follows.
    fn on_snapshot(self: &Arc<Self>) {
        let Some(w) = &self.watches else {
            return;
        };
        let (phase, settled) = {
            let snap = w.snapshot.borrow();
            ((snap.state, snap.transition), snap.transition.is_none())
        };
        let changed = {
            let mut local = self.local.lock();
            let previous = local.phase.replace(phase);
            let changed = previous.is_some_and(|p| p != phase);
            if changed {
                local.leak = Verdict::NotChecked;
                local.epoch += 1;
            }
            changed
        };
        if changed && settled {
            self.refresh_firewall();
        }
        self.update_geo();
    }

    /// Starts or abandons the country lookup of the exit address: one per adopted exit of our
    /// running TUN; a lookup whose address is no longer the one to show is cancelled.
    fn update_geo(self: &Arc<Self>) {
        let Some(w) = &self.watches else {
            return;
        };
        let target = project::geo_target(&w.snapshot.borrow(), &w.evidence.borrow());
        let mut local = self.local.lock();
        if let Some((ip, job)) = &local.geo_job {
            if Some(*ip) == target {
                return;
            }
            job.cancel();
        }
        local.geo_job = None;
        let Some(ip) = target else {
            return;
        };
        if local.geo.is_some_and(|(at, _)| at == ip) {
            return;
        }
        let token = self.backend.shutdown.child_token();
        local.geo_job = Some((ip, token.clone()));
        drop(local);
        let routes = self.backend.settings.read(|s| geo_routes(s, true));
        let hub = self.clone();
        tokio::spawn(async move {
            let owner = Arc::new(Wanted(token.clone()));
            let found = hub.backend.geo.country(ip, routes, owner).await;
            {
                let mut local = hub.local.lock();
                if token.is_cancelled() {
                    return;
                }
                local.geo_job = None;
                if let Some(code) = found {
                    local.geo = Some((ip, code));
                }
            }
            hub.publish_dashboard();
        });
    }
}
