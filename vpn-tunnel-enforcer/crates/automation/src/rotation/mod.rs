//! Profile rotation: the `rotation.json` document, the candidate pick, the timer and "rotate now".
//!
//! Rotation moves a running session over the server list (TUN or system proxy, NOADMIN §2) to the
//! next eligible server of the user's list through [`Coordinator::switch_profile`] (protected
//! restart, verify, commit; the previous server is restored on failure — owner decision 10.1-A).
//! The index advances only on success and the announcement follows the commit (fix R1).
//! Local-proxy sessions are never converted (R2); the timer acts only while a session over a
//! server runs (R8); without a session "rotate now" only changes the selected profile.
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Level, Notice, Owner, UnixMs, now_ms};
use vpnte_base::{AppResult, Msg};
use vpnte_core::store::Store;

use crate::adaptive::reaction::Verdicts;
use crate::coordinator::{Coordinator, NoticeCategory, OpError, SwitchError};

mod config;
#[cfg(test)]
mod tests;

use config::dedup;
pub use config::{INTERVAL_MINUTES, RotationConfig, RotationOrder, RotationPatch, clamp_interval};

/// The whole rotation (probes and the switch) runs under the old operation deadline.
const DEADLINE: Duration = Duration::from_secs(120);
/// An "online" verdict younger than this makes an idle profile eligible without a new probe.
const FRESH_STATUS_MS: i64 = 120_000;
/// Longest timer sleep: a clock change or a missed wake costs at most this much.
const MAX_SLEEP: Duration = Duration::from_secs(60);

/// Indices to try in order, never `current` (fix R5). Sequential: `current+1 … current+n-1`
/// (mod n); random: the other indices shuffled.
pub fn candidate_order(
    len: usize,
    current: usize,
    order: RotationOrder,
    rng: &mut fastrand::Rng,
) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let current = current % len;
    let mut out: Vec<usize> = (1..len).map(|k| (current + k) % len).collect();
    if order == RotationOrder::Random {
        rng.shuffle(&mut out);
    }
    out
}

/// Last health verdict of a profile's server, as the server list shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProfileStatus {
    #[default]
    Unknown,
    Online,
    Offline,
}

/// What rotation needs to know about a stored profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileFacts {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Removed from its subscription (kept for history, never connected to).
    pub archived: bool,
    /// Has a usable outbound configuration.
    pub has_outbound: bool,
    pub status: ProfileStatus,
    /// When `status` was measured.
    pub checked_at: Option<UnixMs>,
    /// Carried over UDP (Hysteria2, TUIC, WireGuard, a QUIC transport): tried after the
    /// TCP-based profiles while a check saw UDP cut on this network.
    pub udp: bool,
}

impl ProfileFacts {
    /// Exists, enabled, not archived and connectable (fix R4).
    fn usable(&self) -> bool {
        self.enabled && !self.archived && self.has_outbound
    }
}

/// The profile store and the offline server probe as rotation uses them; implemented by the app.
pub trait RotationProfiles: Send + Sync + 'static {
    /// Facts about a stored profile; `None` when it no longer exists.
    fn facts(&self, id: &str) -> Option<ProfileFacts>;
    /// Every stored profile in store order (to seed an empty list).
    fn all(&self) -> Vec<ProfileFacts>;
    /// Offline reachability of the profile's server (the server list's ICMP / TCP ping); only
    /// used while no tunnel runs, since a probe through the tunnel cannot tell servers apart.
    fn reachable(&self, id: &str) -> impl Future<Output = bool> + Send;
    /// Makes `id` the selected profile (rotation without a session); refuses unusable profiles.
    fn select(&self, id: &str) -> AppResult<()>;
}

/// Who started a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationTrigger {
    Timer,
    User,
}

/// Result of [`Rotation::rotate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationOutcome {
    /// The session (or, without a session, the selection) moved to `profile_id`.
    Rotated { profile_id: String },
    /// No other eligible profile; the current one stays (fix R5: never a restart onto itself).
    NothingToRotate,
    /// A local-proxy session runs, or the timer fired without a session over a server (R2, R8).
    NotDirect,
    /// The list is empty.
    NoProfiles,
    /// Neither another profile nor the current one is eligible.
    NoneAvailable,
    /// Refused or failed before the tunnel was touched (busy, preflight, refused selection).
    NotStarted { reason: Msg },
    /// Cancelled (config change, a higher-priority operation, shutdown) or past the deadline;
    /// the coordinator finishes or rolls back the switch on its own.
    Aborted { reason: Msg },
    /// The switch to `profile_id` failed; `restored_previous` says whether the old server runs.
    Failed {
        profile_id: String,
        reason: Msg,
        restored_previous: bool,
    },
}

impl RotationOutcome {
    /// Text for the UI after "rotate now"; `None` when a notice already said it.
    pub fn message(&self) -> Option<Msg> {
        match self {
            RotationOutcome::Rotated { .. } | RotationOutcome::Failed { .. } => None,
            RotationOutcome::NothingToRotate => {
                Some(Msg::new("automation.rotation.nothingToRotate"))
            }
            RotationOutcome::NotDirect => Some(Msg::new("automation.rotation.notDirect")),
            RotationOutcome::NoProfiles => Some(Msg::new("automation.rotation.noProfiles")),
            RotationOutcome::NoneAvailable => Some(Msg::new("automation.rotation.noneAvailable")),
            RotationOutcome::NotStarted { reason } | RotationOutcome::Aborted { reason } => {
                Some(reason.clone())
            }
        }
    }

    /// Variant name for the log (profile ids stay out of it).
    fn label(&self) -> &'static str {
        match self {
            RotationOutcome::Rotated { .. } => "rotated",
            RotationOutcome::NothingToRotate => "nothing-to-rotate",
            RotationOutcome::NotDirect => "not-direct",
            RotationOutcome::NoProfiles => "no-profiles",
            RotationOutcome::NoneAvailable => "none-available",
            RotationOutcome::NotStarted { .. } => "not-started",
            RotationOutcome::Aborted { .. } => "aborted",
            RotationOutcome::Failed { .. } => "failed",
        }
    }
}

/// Rotation config API, "rotate now" and the timer task ([`Rotation::run`]).
pub struct Rotation<C: Coordinator, P: RotationProfiles> {
    store: Arc<Store<RotationConfig>>,
    coord: Arc<C>,
    profiles: Arc<P>,
    /// What checks found on this network (see [`Rotation::with_verdicts`]).
    verdicts: Option<Arc<Verdicts>>,
    /// The rotation in flight (single flight); cancelled by a real config change.
    in_flight: Mutex<Option<CancellationToken>>,
}

impl<C: Coordinator, P: RotationProfiles> Rotation<C, P> {
    /// Rotation over the `rotation.json` store; the timer runs only inside [`Rotation::run`].
    pub fn new(store: Arc<Store<RotationConfig>>, coord: Arc<C>, profiles: Arc<P>) -> Self {
        Self {
            store,
            coord,
            profiles,
            verdicts: None,
            in_flight: Mutex::new(None),
        }
    }

    /// Lets the check verdicts of this network steer the pick (`Reactions::verdicts`): a server
    /// a check ruled out here is skipped, and TCP-based profiles go first while UDP is cut.
    pub fn with_verdicts(mut self, verdicts: Arc<Verdicts>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// The stored config (including the countdown).
    pub fn config(&self) -> RotationConfig {
        self.store.snapshot()
    }

    /// Generation of the stored config (bumped on every change, including the countdown).
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.store.subscribe()
    }

    /// Applies a patch. An unchanged result is a no-op (the rotation in flight and the countdown
    /// are kept); a real change cancels the rotation in flight and restarts the countdown.
    /// Enabling with an empty list seeds it with every usable profile.
    pub fn set_config(&self, patch: RotationPatch) -> AppResult<RotationConfig> {
        // The profile store is asked before the document is locked; the patch itself applies to
        // the live document, so a rotation committing meanwhile keeps its index and countdown.
        let may_seed = patch.profile_ids.is_none()
            && self
                .store
                .read(|c| patch.enabled.unwrap_or(c.enabled) && c.profile_ids.is_empty());
        let seed = may_seed.then(|| {
            let usable = self.profiles.all().into_iter().filter(ProfileFacts::usable);
            dedup(usable.map(|p| p.id).collect())
        });
        let now = now_ms();
        let (changed, next) = self.store.update(|current| {
            let mut next = current.clone();
            if let Some(enabled) = patch.enabled {
                next.enabled = enabled;
            }
            if let Some(minutes) = patch.interval_minutes {
                next.interval_minutes = clamp_interval(minutes);
            }
            if let Some(order) = patch.order {
                next.order = order;
            }
            if let Some(ids) = patch.profile_ids {
                next.profile_ids = dedup(ids);
            }
            if let Some(seed) = seed.filter(|_| next.enabled && next.profile_ids.is_empty()) {
                next.profile_ids = seed;
                next.current_index = 0;
            }
            if next.current_index >= next.profile_ids.len() {
                next.current_index = 0;
            }
            let changed = next != *current;
            if changed {
                next.next_rotation_at = next.countdown_from(now);
                *current = next.clone();
            }
            (changed, next)
        })?;
        if changed && let Some(token) = self.in_flight.lock().as_ref() {
            token.cancel();
        }
        Ok(next)
    }
}

impl RotationConfig {
    /// `now + interval` while rotation is on and has a list, else `None`.
    fn countdown_from(&self, now: UnixMs) -> Option<UnixMs> {
        (self.enabled && !self.profile_ids.is_empty()).then(|| now + self.interval_ms())
    }
}

/// Frees the single-flight slot when a rotation ends or its future is dropped.
struct InFlight<'a>(&'a Mutex<Option<CancellationToken>>);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        *self.0.lock() = None;
    }
}

impl<C: Coordinator, P: RotationProfiles> Rotation<C, P> {
    /// One rotation (timer tick or "rotate now"): single flight, 120 s deadline, owner `Rotation`.
    /// Every completed attempt restarts the countdown, so "rotate now" also resets the timer.
    pub async fn rotate(&self, trigger: RotationTrigger) -> RotationOutcome {
        let token = CancellationToken::new();
        {
            let mut slot = self.in_flight.lock();
            if slot.is_some() {
                let reason = Msg::new("automation.rotation.busy");
                return RotationOutcome::NotStarted { reason };
            }
            *slot = Some(token.clone());
        }
        let _slot = InFlight(&self.in_flight);
        let outcome = tokio::select! {
            // Biased: a finished attempt (already committed) wins over a late cancellation.
            biased;
            done = tokio::time::timeout(DEADLINE, self.attempt(trigger)) => done.unwrap_or_else(|_| {
                RotationOutcome::Aborted { reason: OpError::Timeout.reason() }
            }),
            () = token.cancelled() => RotationOutcome::Aborted { reason: OpError::Cancelled.reason() },
        };
        match &outcome {
            // Committed with the index already; nothing ran; or the timer re-arms by itself.
            RotationOutcome::Rotated { .. }
            | RotationOutcome::NoProfiles
            | RotationOutcome::Aborted { .. } => {}
            _ => self.settle(None),
        }
        outcome
    }

    async fn attempt(&self, trigger: RotationTrigger) -> RotationOutcome {
        let cfg = self.store.snapshot();
        let len = cfg.profile_ids.len();
        if len == 0 {
            return RotationOutcome::NoProfiles;
        }
        let session = self.coord.session();
        let running = session.as_ref().filter(|s| s.kind.server());
        let live = running.is_some();
        if !live && (trigger == RotationTrigger::Timer || session.is_some()) {
            return RotationOutcome::NotDirect;
        }
        let running_id = running.and_then(|s| s.profile_id.clone());
        let base = running_id
            .as_deref()
            .and_then(|id| cfg.profile_ids.iter().position(|p| p == id))
            .unwrap_or(cfg.current_index % len);
        // Lazy: probe candidates in rotation order and stop at the first eligible one.
        let mut next = None;
        let order = candidate_order(len, base, cfg.order, &mut fastrand::Rng::new());
        for idx in self.tcp_first(order, &cfg.profile_ids) {
            if let Some(facts) = self.eligible(&cfg.profile_ids[idx], live).await {
                next = Some(facts);
                break;
            }
        }
        let Some(next) = next else {
            let current = running_id.unwrap_or_else(|| cfg.profile_ids[base].clone());
            return match self.eligible(&current, live).await {
                Some(_) => RotationOutcome::NothingToRotate,
                None => RotationOutcome::NoneAvailable,
            };
        };
        if !live {
            return match self.profiles.select(&next.id) {
                Ok(()) => self.rotated(next),
                Err(e) => RotationOutcome::NotStarted {
                    reason: e.user_msg(),
                },
            };
        }
        match self.coord.switch_profile(Owner::Rotation, &next.id).await {
            Ok(()) => self.rotated(next),
            Err(SwitchError::NotStarted(OpError::Cancelled)) => RotationOutcome::Aborted {
                reason: OpError::Cancelled.reason(),
            },
            Err(SwitchError::NotStarted(e)) => {
                tracing::warn!(error = %e, "rotation switch not started");
                // Busy is routine (a higher operation runs); anything else is worth telling.
                if !matches!(e, OpError::Conflict) {
                    let title =
                        Msg::new("automation.rotation.failedNotStarted").arg("name", &next.name);
                    self.notify_failure(Level::Warn, title, e.reason());
                }
                RotationOutcome::NotStarted { reason: e.reason() }
            }
            Err(SwitchError::Failed {
                reason,
                restored_previous,
            }) => {
                tracing::warn!(error = %reason, restored_previous, "rotation switch failed");
                let title = if restored_previous {
                    let previous = running_id
                        .as_deref()
                        .map_or_else(String::new, |id| self.name_of(id));
                    Msg::new("automation.rotation.failedRestored")
                        .arg("name", &next.name)
                        .arg("previous", previous)
                } else {
                    Msg::new("automation.rotation.failedUnprotected").arg("name", &next.name)
                };
                let level = if restored_previous {
                    Level::Warn
                } else {
                    Level::Error
                };
                self.notify_failure(level, title, reason.reason());
                RotationOutcome::Failed {
                    profile_id: next.id,
                    reason: reason.reason(),
                    restored_previous,
                }
            }
        }
    }
}

impl<C: Coordinator, P: RotationProfiles> Rotation<C, P> {
    /// Eligibility (fix R4). Live: a probe would ride the tunnel and cannot tell servers apart,
    /// so an explicit offline verdict is authoritative and unknown is eligible. Idle: only a fresh
    /// "online" verdict or a probe now; unknown and stale verdicts never qualify by themselves.
    async fn eligible(&self, id: &str, live: bool) -> Option<ProfileFacts> {
        let facts = self.profiles.facts(id).filter(ProfileFacts::usable)?;
        if self.verdicts.as_ref().is_some_and(|v| v.avoided(id)) {
            // A check on this network found it banned, frozen, offline or refusing us.
            return None;
        }
        if live {
            return (facts.status != ProfileStatus::Offline).then_some(facts);
        }
        let age = facts.checked_at.map(|t| now_ms() - t);
        let fresh = facts.status == ProfileStatus::Online
            && age.is_some_and(|a| (0..=FRESH_STATUS_MS).contains(&a));
        if fresh || self.profiles.reachable(id).await {
            Some(facts)
        } else {
            None
        }
    }

    /// While a check saw UDP cut on this network, the TCP-based candidates go first (the order
    /// among each kind is kept): a UDP profile would only fail the switch and restore.
    fn tcp_first(&self, mut order: Vec<usize>, ids: &[String]) -> Vec<usize> {
        if self.verdicts.as_ref().is_some_and(|v| v.udp_blocked()) {
            order.sort_by_cached_key(|&idx| self.profiles.facts(&ids[idx]).is_some_and(|f| f.udp));
        }
        order
    }

    /// Commit, then announce (fix R1: no success notice before the switch held).
    fn rotated(&self, next: ProfileFacts) -> RotationOutcome {
        self.settle(Some(&next.id));
        let body = Msg::new("automation.rotation.switched").arg("name", &next.name);
        let notice = Notice::new(Level::Info, "automation.rotation.title").body(body);
        self.coord.notify(NoticeCategory::ProfileRotation, notice);
        RotationOutcome::Rotated {
            profile_id: next.id,
        }
    }

    /// Persists the new position (looked up by id: the list may have changed meanwhile) and
    /// restarts the countdown from now.
    fn settle(&self, moved_to: Option<&str>) {
        let now = now_ms();
        let saved = self.store.update(|c| {
            if let Some(pos) = moved_to.and_then(|id| c.profile_ids.iter().position(|p| p == id)) {
                c.current_index = pos;
            }
            c.next_rotation_at = c.countdown_from(now);
        });
        if let Err(e) = saved {
            tracing::warn!(error = %e, "rotation state not saved");
        }
    }

    fn notify_failure(&self, level: Level, title: Msg, reason: Msg) {
        let notice = Notice::new(level, title).body(reason);
        self.coord.notify(NoticeCategory::ConnectionError, notice);
    }

    fn name_of(&self, id: &str) -> String {
        self.profiles
            .facts(id)
            .map_or_else(|| id.to_owned(), |p| p.name)
    }

    /// When the timer fires next. A missing or past stored instant (app start after a pause, a
    /// cancelled rotation) becomes `now + interval`; a future one is honoured (fix R6).
    fn arm(&self) -> Option<UnixMs> {
        let now = now_ms();
        let cfg = self.store.snapshot();
        let due = match cfg.next_rotation_at {
            Some(at) if at > now && cfg.countdown_from(now).is_some() => Some(at),
            _ => cfg.countdown_from(now),
        };
        if due != cfg.next_rotation_at
            && let Err(e) = self.store.update(|c| c.next_rotation_at = due)
        {
            tracing::warn!(error = %e, "rotation countdown not saved");
        }
        due
    }

    /// The timer task: runs until `cancel`. Config changes (any writer) re-arm it.
    pub async fn run(&self, cancel: CancellationToken) {
        let mut changes = self.store.subscribe();
        changes.borrow_and_update();
        let mut due = self.arm();
        loop {
            if due.is_some_and(|at| at <= now_ms()) {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    outcome = self.rotate(RotationTrigger::Timer) => {
                        tracing::info!(outcome = outcome.label(), "timed rotation finished");
                    }
                }
                due = self.arm();
                continue;
            }
            // Wall-clock re-check at least every minute: sleep and clock changes cannot skew it.
            let wait = due.map_or(MAX_SLEEP, |at| {
                Duration::from_millis(u64::try_from(at - now_ms()).unwrap_or(0)).min(MAX_SLEEP)
            });
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                changed = changes.changed() => {
                    if changed.is_err() {
                        cancel.cancelled().await;
                        break;
                    }
                    due = self.arm();
                }
                () = tokio::time::sleep(wait), if due.is_some() => {}
            }
        }
    }
}
