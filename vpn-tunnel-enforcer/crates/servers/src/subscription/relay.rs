//! What the app lends a subscription fetch while it runs (ru-2026 item 3: "try direct, then
//! through the active tunnel, then through any server that works"). This crate cannot reach the
//! tunnel or the proxy slots, so the app implements [`Relays`] and hands it to the fetcher.
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use tokio_util::sync::CancellationToken;
use vpnte_core::net::Route;

/// The future of [`Relays::spare_route`].
pub type SpareFuture<'a> = Pin<Box<dyn Future<Output = Option<Spare>> + Send + 'a>>;

/// Routes the app can lend a fetch.
pub trait Relays: Send + Sync {
    /// The running session's own route when the app's requests do not ride it by themselves: the
    /// proxy capture's mixed inbound. `None` without a session, and in TUN mode (a direct request
    /// already rides the tunnel there).
    fn session_route(&self) -> Option<Route>;
    /// A short-lived loopback route through a healthy server of the list, for one more try after
    /// every route failed; `None` when none can be had. Gives up when `cancel` fires.
    fn spare_route(&self, cancel: CancellationToken) -> SpareFuture<'_>;
}

/// A borrowed loopback route; dropping it hands the slot back.
pub struct Spare {
    route: Route,
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl Spare {
    /// `route` until the value is dropped, then `release` runs once (it must not block: spawn).
    pub fn new(route: Route, release: impl FnOnce() + Send + 'static) -> Self {
        Self {
            route,
            release: Some(Box::new(release)),
        }
    }

    /// The loopback route of the borrowed slot.
    pub fn route(&self) -> &Route {
        &self.route
    }
}

impl Drop for Spare {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

impl fmt::Debug for Spare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Spare").field(&self.route).finish()
    }
}
