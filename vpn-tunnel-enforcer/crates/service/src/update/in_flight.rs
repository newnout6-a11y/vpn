//! Host calls that may start a session or change the filters, counted from their first step
//! (review svcfix-a4): a start the host accepted is in flight while it applies its kill-switch
//! settings, long before the runtime says `StartBegan`. The host is wrapped, not changed: its
//! kill switch here ([`Counted`]) and its runtime in [`super::trial::Judged`]. The updater's
//! restart waits until no call is in flight and none ended within [`SETTLE`].
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::{broadcast, watch};
use tokio::time::Instant;
use vpnte_base::AppResult;
use vpnte_base::types::{KillSwitchLevel, Notice};
use vpnte_winnet::wfp::{ProtectionSettings, RemoveReport};

use crate::host::KillSwitch;
use crate::proto::ProtectionWire;

/// How long the restart still waits after a call ended: the host's next step of the same start
/// (the runtime's start after the kill-switch apply) runs on another task a moment later.
pub const SETTLE: Duration = Duration::from_secs(1);

/// The count of host calls in flight, shared by the wrapped kill switch, the judged runtime and
/// the updater.
#[derive(Clone)]
pub struct InFlight(Arc<Gauge>);

struct Gauge {
    calls: watch::Sender<usize>,
    ended: Mutex<Option<Instant>>,
}

/// What the restart has to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quiet {
    /// A call is in flight (wait for the count to change).
    Busy,
    /// The last call ended this long before the end of [`SETTLE`].
    Settling(Duration),
    /// Nothing in flight, nothing just ended.
    Yes,
}

impl Default for InFlight {
    fn default() -> Self {
        Self(Arc::new(Gauge {
            calls: watch::Sender::new(0),
            ended: Mutex::new(None),
        }))
    }
}

impl InFlight {
    /// Counts one call until the returned guard drops.
    pub fn enter(&self) -> Call {
        self.0.calls.send_modify(|n| *n += 1);
        Call(self.clone())
    }

    /// Whether a restart now would cut no host call.
    pub fn quiet(&self) -> Quiet {
        if *self.0.calls.borrow() > 0 {
            return Quiet::Busy;
        }
        let ended = *self.0.ended.lock();
        match ended.and_then(|at| SETTLE.checked_sub(at.elapsed())) {
            Some(left) if !left.is_zero() => Quiet::Settling(left),
            _ => Quiet::Yes,
        }
    }

    /// Changes of the count (a call began or ended).
    pub fn subscribe(&self) -> watch::Receiver<usize> {
        self.0.calls.subscribe()
    }
}

/// One host call in flight (until dropped).
pub struct Call(InFlight);

impl Drop for Call {
    fn drop(&mut self) {
        // The end time first: whoever the count change wakes reads it.
        *self.0.0.ended.lock() = Some(Instant::now());
        self.0.0.calls.send_modify(|n| *n = n.saturating_sub(1));
    }
}

/// The host's kill switch: settings changes and clean-ups count as calls in flight.
pub struct Counted<K> {
    inner: K,
    in_flight: InFlight,
}

impl<K> Counted<K> {
    pub fn new(inner: K, in_flight: InFlight) -> Self {
        Self { inner, in_flight }
    }
}

#[async_trait]
impl<K: KillSwitch> KillSwitch for Counted<K> {
    async fn apply(&self, settings: ProtectionSettings) -> AppResult<()> {
        let _call = self.in_flight.enter();
        self.inner.apply(settings).await
    }

    fn level(&self) -> KillSwitchLevel {
        self.inner.level()
    }

    fn level_in_force(&self) -> KillSwitchLevel {
        self.inner.level_in_force()
    }

    async fn status(&self) -> ProtectionWire {
        self.inner.status().await
    }

    fn notices(&self) -> broadcast::Receiver<Notice> {
        self.inner.notices()
    }

    async fn cleanup(&self) -> AppResult<RemoveReport> {
        let _call = self.in_flight.enter();
        self.inner.cleanup().await
    }

    async fn remove_all(&self) -> AppResult<()> {
        let _call = self.in_flight.enter();
        self.inner.remove_all().await
    }
}

#[cfg(test)]
mod tests;
