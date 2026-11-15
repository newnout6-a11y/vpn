//! The home address before and between sessions (owner decision 13): read through the current
//! network once at start and again after every network change while no session runs, so the
//! settled-off start page shows the real address with «ваш провайдер», as the old app did. While
//! the user has geo lookups disabled the app sends no address request of its own either.
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_probes::geo::Geo;
use vpnte_probes::ip_monitor::{IpMonitor, Sampler};
use vpnte_probes::public_ip::{Family, IpRoute};
use vpnte_tunnel::api::TunStatus;
use vpnte_winnet::adapters::NetChange;

/// The reads and what they need: the shared sampler (one 429 back-off for the process), the
/// monitor whose `real_ip` the start page shows when settled off, the lookup switch and the
/// runtime status.
pub(in crate::svc_tunnel) struct HomeReads {
    pub sampler: Arc<dyn Sampler>,
    pub ip: IpMonitor,
    pub geo: Geo,
    pub status: watch::Receiver<TunStatus>,
}

impl HomeReads {
    /// Reads now, then after every change `changes` reports, until `cancel` fires or the changes
    /// end; without a network watch only the start-up read happens.
    pub async fn run(
        mut self,
        mut changes: Option<mpsc::Receiver<NetChange>>,
        cancel: CancellationToken,
    ) {
        loop {
            self.read(&cancel).await;
            let Some(rx) = changes.as_mut() else {
                return;
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                change = rx.recv() => if change.is_none() { return },
            }
        }
    }

    /// One read over the current default route while the runtime is idle. A status change during
    /// the read drops the sample: a session that came up may have carried it, and every session
    /// reads the home address itself through the engine's direct-out.
    async fn read(&mut self, cancel: &CancellationToken) {
        if !self.geo.enabled() || !idle(&self.status.borrow_and_update()) {
            return;
        }
        let route = IpRoute::Direct;
        let Some(sample) = self.sampler.sample(&route, Family::V4, cancel).await else {
            tracing::debug!("home address not read: no provider answered");
            return;
        };
        if self.status.has_changed().unwrap_or(true) {
            tracing::debug!("home address dropped: the tunnel changed during the read");
            return;
        }
        self.ip.set_real_ip(Some(sample.ip));
    }
}

/// Nothing of ours carries traffic: no engine runs and no session is set up.
fn idle(status: &TunStatus) -> bool {
    !status.running && status.session.is_none()
}

#[cfg(test)]
mod tests;
