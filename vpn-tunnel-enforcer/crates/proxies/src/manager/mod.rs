//! The external proxy manager (spec 6.2–6.4): a registry of slots, each an unauthenticated
//! `mixed` listener on 127.0.0.1 backed by its own sing-box child (plus an Xray child for
//! profiles that run on Xray), health-probed through its data plane, rotated between servers and
//! leased to automation clients. [`ProxyManager`] implements [`ProxyOps`] for the control API
//! and the UI, and pushes a [`ProxySnapshot`] on every change.
//!
//! Locking: the registry sits behind one `parking_lot` mutex held only for validation and state
//! changes, never across an await. Engine starts, readiness waits, DNS and probes run outside it,
//! and every continuation re-checks the slot's generation before writing. Operations on the same
//! slot wait for that slot's async guard (as they waited for the old global lock); different
//! slots proceed in parallel (B-10).
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedMutexGuard, Semaphore, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, EnginePref, UnixMs, now_ms};
use vpnte_base::{AppResult, Msg};
use vpnte_profiles::model::Profile;

use crate::health::Timing;
use crate::model::{
    Aggregate, Degradation, GroupHealth, Health, InstanceStatus, ProxyStatus, ServerStatus,
    Unlimited, derive_readiness,
};
use crate::probe::{ProbeConfig, Prober};
use crate::slot::{self, CONTROL_HOST, Slot};

mod api;
mod launch;
mod ops;
mod pick;
mod registry;
mod run;
#[cfg(test)]
mod tests;

use launch::{Engines, Launch, Names};
use registry::Registry;

/// Probes in flight at once across all slots: a batch start must not open a burst of probe
/// tunnels (handshake bursts are what DPI and server rate limits punish).
const PROBE_CONCURRENCY: usize = 3;

/// A server the user can run as a proxy, as the app's server list describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyProfile {
    pub id: String,
    pub name: String,
    /// Country as stored with the server (ISO code, name or flag), if known.
    pub country: Option<String>,
    pub group_id: Option<String>,
    pub profile: Profile,
    /// Key health (`healthStatus` of the server, else its ping status).
    pub status: ServerStatus,
    pub ping_ms: Option<u32>,
    pub health_latency_ms: Option<u32>,
    pub health_reason: Option<String>,
    pub last_checked_at: Option<UnixMs>,
    /// False when the user disabled the server.
    pub enabled: bool,
    /// The server disappeared from its subscription (kept for history, never started).
    pub removed: bool,
}

impl ProxyProfile {
    /// May run as a proxy.
    pub fn usable(&self) -> bool {
        self.enabled && !self.removed
    }
}

/// Engine settings for new starts: the same selection rules as the main tunnel (B-27).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineChoice {
    pub pref: EnginePref,
    pub device: ClientDevice,
}

/// Where the manager gets servers from; the app implements it over its server list.
#[async_trait::async_trait]
pub trait ProfileSource: Send + Sync {
    /// Every server, in list order (the manager filters).
    fn profiles(&self) -> Vec<ProxyProfile>;
    /// The server the main VPN uses, if any: auto-picks avoid it (same exit IP).
    fn active_vpn_profile_id(&self) -> Option<String>;
    /// Engine preference and client device for new starts.
    fn engine_choice(&self) -> EngineChoice;
    /// Key health check of a server group (`POST /profiles/healthcheck`); the error's kind
    /// picks the HTTP status (see `ProxyError::group_health`).
    async fn check_group_health(&self, group_id: &str) -> AppResult<GroupHealth>;
}

/// What the UI renders: every configured or auto-disabled slot (failed ones included, B-8) and
/// the aggregate, with readiness derived at `at`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProxySnapshot {
    pub instances: Vec<InstanceStatus>,
    pub aggregate: Aggregate,
    pub control_url: Option<String>,
    pub at: UnixMs,
}

impl ProxySnapshot {
    /// The snapshot with readiness and the aggregate derived at `now`. Readiness depends on the
    /// clock (a route whose probes stall stops being ready), so a UI tick must call this
    /// instead of trusting the `ready` of a snapshot pushed earlier.
    pub fn refreshed(&self, now: UnixMs) -> ProxySnapshot {
        let mut instances = self.instances.clone();
        derive_readiness(&mut instances, now);
        let aggregate = Aggregate::of(&instances, now);
        ProxySnapshot {
            instances,
            aggregate,
            control_url: self.control_url.clone(),
            at: now,
        }
    }
}

/// The external proxy manager. Cheap to clone (one shared registry); hand it to the control
/// API as `Arc<dyn ProxyOps>`.
#[derive(Clone)]
pub struct ProxyManager {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ProxyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyManager").finish_non_exhaustive()
    }
}

impl ProxyManager {
    /// A manager that runs the bundled engines of `resources` (`DataDirs::resources`). Create
    /// it inside the tokio runtime (it starts the lease-expiry timer).
    pub fn new(source: Arc<dyn ProfileSource>, resources: &Path) -> Self {
        Self::with_parts(
            source,
            Arc::new(Engines::new(resources)),
            Arc::new(ProbeConfig::default()),
            Timing::default(),
        )
    }

    pub(crate) fn with_parts(
        source: Arc<dyn ProfileSource>,
        launcher: Arc<dyn Launch>,
        prober: Arc<dyn Prober>,
        timing: Timing,
    ) -> Self {
        let (snapshot, _) = watch::channel(ProxySnapshot::default());
        let inner = Arc::new(Inner {
            reg: Mutex::new(Registry::default()),
            source,
            launcher,
            prober,
            timing,
            names: Names::default(),
            permits: Arc::new(Semaphore::new(PROBE_CONCURRENCY)),
            snapshot,
            control_port: AtomicU16::new(0),
            guards: Mutex::new(HashMap::new()),
            batch: tokio::sync::Mutex::new(()),
            lease_wake: Arc::new(Notify::new()),
            closing: CancellationToken::new(),
        });
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(run::lease_timer(
                Arc::downgrade(&inner),
                inner.lease_wake.clone(),
                inner.closing.clone(),
            ));
        }
        Self { inner }
    }

    /// The UI's state: pushed on every change. Call [`ProxySnapshot::refreshed`] on a timer too:
    /// readiness expires with the clock, not with an event.
    pub fn snapshot(&self) -> watch::Receiver<ProxySnapshot> {
        self.inner.snapshot.subscribe()
    }

    /// App exit: stops every slot, leases notwithstanding, and refuses new starts. (The engines'
    /// kill-on-close Jobs end them anyway if the process dies first.)
    pub async fn shutdown(&self) {
        self.inner.shutdown().await;
    }
}

/// The shared state behind [`ProxyManager`].
struct Inner {
    reg: Mutex<Registry>,
    source: Arc<dyn ProfileSource>,
    launcher: Arc<dyn Launch>,
    prober: Arc<dyn Prober>,
    timing: Timing,
    names: Names,
    permits: Arc<Semaphore>,
    snapshot: watch::Sender<ProxySnapshot>,
    /// Port the control API bound (0 = not known yet).
    control_port: AtomicU16,
    /// Per-slot operation guards, awaited in FIFO order (B-10).
    guards: Mutex<HashMap<Slot, Arc<tokio::sync::Mutex<()>>>>,
    /// Serialises the allocating operations (add, batch start, prewarm) among themselves.
    batch: tokio::sync::Mutex<()>,
    lease_wake: Arc<Notify>,
    /// Parent of every slot task and start: cancelled by `shutdown` and on drop.
    closing: CancellationToken,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.closing.cancel();
    }
}

impl Inner {
    /// Waits for the operation guard of `slot`.
    async fn lock_slot(&self, slot: Slot) -> OwnedMutexGuard<()> {
        let guard = self.guards.lock().entry(slot).or_default().clone();
        guard.lock_owned().await
    }

    fn control_port(&self) -> Option<u16> {
        Some(self.control_port.load(Ordering::Relaxed)).filter(|p| *p != 0)
    }

    fn control_url(&self) -> Option<String> {
        self.control_port().map(slot::proxy_url)
    }

    /// `slot` plus every instance and the aggregate, derived now.
    fn proxy_status(&self, slot: Slot) -> ProxyStatus {
        let now = now_ms();
        let reg = self.reg.lock();
        let instances = reg.instances(now);
        let instance = reg.instance(slot, &instances);
        let aggregate = Aggregate::of(&instances, now);
        ProxyStatus {
            instance,
            control_host: CONTROL_HOST.into(),
            control_port: self.control_port(),
            control_url: self.control_url(),
            max_instances: Unlimited,
            instances,
            aggregate,
        }
    }

    /// The status of one slot, derived now.
    fn instance(&self, slot: Slot) -> InstanceStatus {
        let reg = self.reg.lock();
        let instances = reg.instances(now_ms());
        reg.instance(slot, &instances)
    }

    /// Pushes the snapshot if anything visible changed. Called with the registry locked.
    fn publish(&self, reg: &Registry) {
        let now = now_ms();
        let instances = reg.instances(now);
        let aggregate = Aggregate::of(&instances, now);
        let control_url = self.control_url();
        self.snapshot.send_if_modified(|current| {
            let same = current.instances == instances
                && current.aggregate == aggregate
                && current.control_url == control_url;
            if !same {
                *current = ProxySnapshot {
                    instances,
                    aggregate,
                    control_url,
                    at: now,
                };
            }
            !same
        });
    }
}

/// Short user-facing explanation of why a slot is not a usable route (row tooltip).
pub fn degradation_msg(reason: Degradation) -> Msg {
    Msg::new(match reason {
        Degradation::ProcessFailed => "proxies.degradation.processFailed",
        Degradation::LeasedRouteRecoveryBlocked => "proxies.degradation.leasedRouteRecoveryBlocked",
        Degradation::HealthFailureBudgetExhausted => {
            "proxies.degradation.healthFailureBudgetExhausted"
        }
        Degradation::EgressIpChangedWithoutRotation => {
            "proxies.degradation.egressIpChangedWithoutRotation"
        }
        Degradation::RotationDidNotChangeEgressIp => {
            "proxies.degradation.rotationDidNotChangeEgressIp"
        }
        Degradation::DuplicateEgressIp => "proxies.degradation.duplicateEgressIp",
        Degradation::EgressProbeFailed => "proxies.degradation.egressProbeFailed",
    })
}

/// User-facing name of a route health state.
pub fn health_msg(health: Health) -> Msg {
    Msg::new(match health {
        Health::Stopped => "proxies.health.stopped",
        Health::Starting => "proxies.health.starting",
        Health::Healthy => "proxies.health.healthy",
        Health::Degraded => "proxies.health.degraded",
        Health::Rotating => "proxies.health.rotating",
        Health::Quarantined => "proxies.health.quarantined",
        Health::Failed => "proxies.health.failed",
    })
}
