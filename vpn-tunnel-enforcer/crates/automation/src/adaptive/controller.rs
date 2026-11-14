//! The adaptive task: the single owner of verification state, driven by lifecycle events.
//!
//! Every engine (re)start reports its mode in `LifecycleEvent::Started` (fix A9). A start the app
//! prepared with [`Adaptive::begin`] carries the learning context; any other start (crash restart,
//! settings restart, AutoPilot, profile switch) is adopted and verified without learning. A start
//! this task did not ask for supersedes the running verification; `Stopped` ends it.
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Notify, broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, now_ms};
use vpnte_base::{AppResult, Msg};
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use super::learning::{AdaptiveDoc, Learning};
use super::reaction::Verdicts;
use super::window::Timing;
use super::{
    AdaptiveHost, AdaptiveStatus, Capabilities, NetworkSnapshot, Phase, ProfileView, capabilities,
};
use crate::coordinator::{
    Coordinator, LifecycleEvent, RuntimeId, SessionInfo, SessionKind, StopCause,
};

mod run;

/// Adaptive bypass service: [`Adaptive::run`] is its task; the rest is called by the app.
pub struct Adaptive<C: Coordinator, H: AdaptiveHost> {
    coord: Arc<C>,
    host: Arc<H>,
    settings: Arc<Store<Settings>>,
    learning: Learning,
    status: watch::Sender<AdaptiveStatus>,
    shared: Mutex<Shared>,
    retry: Notify,
    timing: Timing,
    /// What checks found on this network (see [`Adaptive::with_verdicts`]).
    verdicts: Option<Arc<Verdicts>>,
}

/// A prepared start nobody ended is dropped after this (its caller went away): longer than the
/// lane's 120 s budget.
const PENDING_MAX_AGE: Duration = Duration::from_secs(180);

/// A start prepared with [`Adaptive::begin`]: the mode to start in, and the ticket that ends
/// exactly this preparation when the start does not happen ([`Adaptive::start_failed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Begun {
    pub mode: AdaptiveMode,
    pub ticket: u64,
}

/// A prepared start (its ticket and when it was prepared).
struct Pending {
    ticket: u64,
    at: Instant,
    ctx: Context,
}

/// State shared between the app's calls and the task (lock held briefly, never across `.await`).
#[derive(Default)]
struct Shared {
    /// Prepared by `begin` for the starts in flight, oldest first: starts overlap (a higher owner
    /// pre-empts a lower one, a refused one ends while another runs), so each keeps its own
    /// context until its `Started` attaches it or its caller ends it.
    pending: Vec<Pending>,
    /// The context of the runtime being verified (re-used by `retry`).
    current: Option<(RuntimeId, Context)>,
    /// Bumped by `begin` / `start_failed`: status writes of an older run are dropped.
    generation: u64,
}

/// What one connection's verification knows.
#[derive(Debug, Clone)]
struct Context {
    kind: SessionKind,
    profile: Option<ProfileView>,
    caps: Capabilities,
    mode: AdaptiveMode,
    /// Learning key; `None`: this runtime never learns (adopted, network changed, sibling).
    key: Option<String>,
    identity: Option<NetworkSnapshot>,
    /// The mode came from a learned record (fix A1 applies when it fails).
    reused: bool,
}

/// The runtime a verification run is about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    runtime: RuntimeId,
    kind: SessionKind,
    profile_id: Option<String>,
    mode: AdaptiveMode,
}

impl From<&SessionInfo> for Target {
    fn from(s: &SessionInfo) -> Self {
        Self {
            runtime: s.runtime_id,
            kind: s.kind,
            profile_id: s.profile_id.clone(),
            mode: s.mode,
        }
    }
}

impl<C: Coordinator, H: AdaptiveHost> Adaptive<C, H> {
    /// Opens the learning key (see [`Learning::open`]); nothing runs until [`Adaptive::run`].
    pub fn new(
        coord: Arc<C>,
        host: Arc<H>,
        settings: Arc<Store<Settings>>,
        store: Arc<Store<AdaptiveDoc>>,
    ) -> Self {
        Self::with_timing(coord, host, settings, store, Timing::REAL)
    }

    pub(super) fn with_timing(
        coord: Arc<C>,
        host: Arc<H>,
        settings: Arc<Store<Settings>>,
        store: Arc<Store<AdaptiveDoc>>,
        timing: Timing,
    ) -> Self {
        Self {
            coord,
            host,
            settings,
            learning: Learning::open(store),
            status: watch::channel(AdaptiveStatus::idle(now_ms())).0,
            shared: Mutex::new(Shared::default()),
            retry: Notify::new(),
            timing,
            verdicts: None,
        }
    }

    /// Lets the check verdicts of this network steer the sibling fallback (`Reactions::verdicts`):
    /// a server a check ruled out here is never tried, TCP-based ones go first while UDP is cut.
    pub fn with_verdicts(mut self, verdicts: Arc<Verdicts>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// Status for the UI.
    pub fn status(&self) -> watch::Receiver<AdaptiveStatus> {
        self.status.subscribe()
    }

    /// Called by the app's connect path right before it starts a session over the server list
    /// (TUN or system proxy) or a local-proxy TUN: reads the network identity, looks up what worked
    /// here before and returns the mode to start in. `Baseline` when adaptive bypass is off (fix
    /// A3) or for a local proxy.
    pub async fn begin(&self, kind: SessionKind, profile: Option<ProfileView>) -> Begun {
        if kind == SessionKind::Soft {
            // A local proxy behind the system proxy is not verified (as the old Soft mode): its
            // upstream belongs to another client and nothing here could change it.
            let mut shared = self.shared.lock();
            prune(&mut shared.pending);
            if shared.pending.is_empty() {
                self.settle(&mut shared, None);
            }
            return Begun {
                mode: AdaptiveMode::Baseline,
                ticket: 0,
            };
        }
        let settings = self.settings.snapshot();
        let caps = capabilities(kind, profile.as_ref());
        let (mut identity, mut key, mut mode, mut reused) =
            (None, None, AdaptiveMode::Baseline, false);
        if settings.adaptive_bypass && !caps.external {
            identity = self.host.network_identity().await;
            key = identity
                .as_ref()
                .zip(profile.as_ref())
                .and_then(|(net, p)| self.learning.key(net, p));
            if let Some(learned) = key
                .as_deref()
                .and_then(|k| self.learning.lookup(k, |m| caps.allows(m), now_ms()))
            {
                (mode, reused) = (learned, true);
            } else if settings.stealth_mode {
                // Old seed: stealth starts in the compatibility mode it implies, when this start
                // has the knob (a proxy capture has no adapter MTU to shrink).
                let seed = if caps.tls {
                    AdaptiveMode::TlsCompatibility
                } else {
                    AdaptiveMode::MtuCompatibility
                };
                if caps.allows(seed) {
                    mode = seed;
                }
            }
        }
        tracing::info!(
            version = 3,
            known_network = identity.is_some(),
            reused,
            ?mode,
            "learning decision"
        );
        let external = caps.external;
        let context = Context {
            kind,
            profile,
            caps,
            mode,
            key,
            identity,
            reused,
        };
        let mut shared = self.shared.lock();
        shared.generation += 1;
        let ticket = shared.generation;
        prune(&mut shared.pending);
        shared.pending.push(Pending {
            ticket,
            at: Instant::now(),
            ctx: context,
        });
        let status = AdaptiveStatus {
            phase: Phase::Connecting,
            mode,
            external,
            attempts: 0,
            message: Msg::new("automation.adaptive.status.connecting"),
            reason: None,
            updated_at: now_ms(),
        };
        self.status.send_replace(status);
        Begun { mode, ticket }
    }
}

/// Drops preparations whose caller went away without ending them.
fn prune(pending: &mut Vec<Pending>) {
    pending.retain(|p| p.at.elapsed() < PENDING_MAX_AGE);
}

impl<C: Coordinator, H: AdaptiveHost> Adaptive<C, H> {
    /// The start prepared as `ticket` did not produce a tunnel: `Some(error)` shows `Failed`
    /// with the start error, `None` (cancelled) returns to `Idle`, unless another prepared start
    /// is still in flight (its own end decides then). A ticket already attached does nothing.
    pub fn start_failed(&self, ticket: u64, reason: Option<Msg>) {
        let mut shared = self.shared.lock();
        let Some(at) = shared.pending.iter().position(|p| p.ticket == ticket) else {
            return;
        };
        shared.pending.remove(at);
        prune(&mut shared.pending);
        if shared.pending.is_empty() {
            self.settle(&mut shared, reason);
        }
    }

    /// No start in flight any more: `Failed` with `reason`, or `Idle`; older runs stop
    /// publishing.
    fn settle(&self, shared: &mut Shared, reason: Option<Msg>) {
        shared.generation += 1;
        let status = match reason {
            Some(reason) => {
                let mut status = self.status.borrow().clone();
                status.phase = Phase::Failed;
                status.message = Msg::new("automation.adaptive.status.failed");
                status.reason = Some(reason);
                status.updated_at = now_ms();
                status
            }
            None => AdaptiveStatus::idle(now_ms()),
        };
        self.status.send_replace(status);
    }

    /// The mode a restart that continues the session (settings change, crash restart) must use:
    /// the running one, or `Baseline` once adaptive bypass is off (fix A3; stealth still applies).
    pub fn restart_mode(&self, running: AdaptiveMode) -> AdaptiveMode {
        if self.settings.read(|s| s.adaptive_bypass) {
            running
        } else {
            AdaptiveMode::Baseline
        }
    }

    /// Verifies the running tunnel again with a fresh budget; `false` when no tunnel runs.
    pub fn retry(&self) -> bool {
        let tunnel = self
            .coord
            .session()
            .is_some_and(|s| s.kind != SessionKind::Soft);
        if tunnel {
            self.retry.notify_one();
        }
        tunnel
    }

    /// Forgets every learned mode («Сбросить запомненные настройки сети»).
    pub fn reset_learning(&self) -> AppResult<()> {
        self.learning.clear()
    }

    /// The task: verifies every tunnel start until `cancel` fires.
    pub async fn run(&self, cancel: CancellationToken) {
        let mut events = self.coord.events();
        let mut next = self.coord.session().map(|s| Target::from(&s));
        loop {
            let target = match next.take() {
                Some(target) => target,
                None => match self.idle(&mut events, &cancel).await {
                    Some(target) => target,
                    None => return,
                },
            };
            match self.verify(target, &mut events, &cancel).await {
                run::Outcome::Next(target) => next = Some(target),
                run::Outcome::Idle => {}
                run::Outcome::Shutdown => return,
            }
        }
    }

    /// Waits for the next tunnel start (or a retry of the running one).
    async fn idle(
        &self,
        events: &mut broadcast::Receiver<LifecycleEvent>,
        cancel: &CancellationToken,
    ) -> Option<Target> {
        loop {
            let event = tokio::select! {
                biased;
                _ = cancel.cancelled() => return None,
                _ = self.retry.notified() => {
                    match self.coord.session() {
                        Some(s) => return Some(Target::from(&s)),
                        None => continue,
                    }
                }
                event = events.recv() => event,
            };
            match event {
                Ok(LifecycleEvent::Started {
                    runtime_id,
                    kind,
                    profile_id,
                    mode,
                    ..
                }) => {
                    return Some(Target {
                        runtime: runtime_id,
                        kind,
                        profile_id,
                        mode,
                    });
                }
                Ok(LifecycleEvent::Stopped { cause, .. }) => self.on_stopped(Some(cause)),
                Ok(_) => {}
                Err(RecvError::Lagged(_)) => match self.coord.session() {
                    Some(s) => return Some(Target::from(&s)),
                    None => self.on_stopped(None),
                },
                Err(RecvError::Closed) => return None,
            }
        }
    }

    /// No session any more: `Idle`, unless a start is being prepared or a failure must stay
    /// visible (a fault stop after a failed verification, e.g. an abandoned sibling).
    fn on_stopped(&self, cause: Option<StopCause>) {
        let mut shared = self.shared.lock();
        shared.current = None;
        prune(&mut shared.pending);
        if !shared.pending.is_empty() {
            return;
        }
        let failed = self.status.borrow().phase == Phase::Failed;
        if !(failed && cause == Some(StopCause::Fault)) {
            self.status.send_replace(AdaptiveStatus::idle(now_ms()));
        }
    }

    /// The context for `target`: the prepared one if it matches, the current one on a re-run of
    /// the same runtime, else an adopted context without learning.
    fn attach(&self, target: &Target) -> (Context, u64) {
        let mut shared = self.shared.lock();
        let same = |p: &Pending| {
            p.ctx.kind == target.kind
                && p.ctx.mode == target.mode
                && p.ctx.profile.as_ref().map(|v| v.id.as_str()) == target.profile_id.as_deref()
        };
        // The newest preparation of this very start; any other one of it was pre-empted or
        // refused (its caller's `start_failed` then finds nothing to end).
        let prepared =
            (shared.pending.iter().rposition(same)).map(|at| shared.pending.remove(at).ctx);
        if prepared.is_some() {
            shared.pending.retain(|p| !same(p));
        }
        let same_runtime = shared
            .current
            .as_ref()
            .filter(|(rid, _)| *rid == target.runtime)
            .map(|(_, ctx)| ctx.clone());
        let ctx = prepared.or(same_runtime).unwrap_or_else(|| {
            let profile = target
                .profile_id
                .as_deref()
                .and_then(|id| self.host.profile(id));
            Context {
                kind: target.kind,
                caps: capabilities(target.kind, profile.as_ref()),
                profile,
                mode: target.mode,
                key: None,
                identity: None,
                reused: false,
            }
        });
        shared.current = Some((target.runtime, ctx.clone()));
        (ctx, shared.generation)
    }

    /// Writes `status` unless a newer `begin` / `start_failed` happened since `generation`.
    fn publish(&self, generation: u64, status: AdaptiveStatus) -> bool {
        let shared = self.shared.lock();
        let current = shared.generation == generation;
        if current {
            self.status.send_replace(status);
        }
        current
    }
}
