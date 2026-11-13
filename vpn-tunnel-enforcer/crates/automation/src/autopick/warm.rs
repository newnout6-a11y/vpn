//! Keeping the next failover candidates checked while a session runs, so a switch goes to a
//! server checked recently: one check every few minutes at most, never of the running server,
//! each behind its server's handshake budget.
use std::time::Duration;

use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};

use super::launch::FRESH;
use super::task::AutoPick;
use super::{Candidate, Network, PickHost, rank};
use crate::coordinator::Coordinator;

/// At most one candidate check per this period.
pub const WARM_TICK: Duration = Duration::from_secs(120);
/// How many of the next candidates are kept checked.
pub const WARM_COUNT: usize = 3;

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// The warm-up task: at most one candidate check per period, only while a server session runs.
    pub(super) async fn warm(&self, cancel: CancellationToken) {
        let start = tokio::time::Instant::now() + WARM_TICK;
        let mut ticker = tokio::time::interval_at(start, WARM_TICK);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = ticker.tick() => {}
            }
            let Some(running) = self.coord.session().filter(|s| s.kind.server()) else {
                continue;
            };
            // Nothing automatic after the user's Disconnect or Cancel until they connect again.
            let acts = self.acts();
            if acts.stopped {
                continue;
            }
            // The retries dial on their own; a check now would take their budget.
            let Ok(idle) = self.episode.try_lock() else {
                continue;
            };
            let Some(running) = running.profile_id else {
                continue;
            };
            let servers = self.host.servers();
            let net = self.network(&servers).await;
            if let Some(next) = next_to_warm(&servers, &net, &running, now_ms()) {
                let id = next.id.clone();
                drop(idle);
                // The user's action ends a check in flight as well.
                let user = self.until_user_acts(acts.seq, &cancel);
                self.host.check(&id, user.token()).await;
            }
        }
    }
}

/// The candidate to check now: of the next [`WARM_COUNT`] in failover order on `net` (the
/// running server's group first, then the others), the one checked longest ago, if that is
/// older than [`FRESH`].
pub fn next_to_warm<'a>(
    servers: &'a [Candidate],
    net: &Network,
    running: &str,
    now: UnixMs,
) -> Option<&'a Candidate> {
    let group = servers.iter().find(|c| c.id == running)?.group.clone();
    let ranked = rank(servers, net, |id| id == running);
    let same = ranked.iter().filter(|c| c.group == group);
    let next = same
        .chain(ranked.iter().filter(|c| c.group != group))
        .copied();
    let stale = |c: &&Candidate| {
        c.checked_at
            .is_none_or(|at| now.saturating_sub(at) >= FRESH.as_millis() as i64)
    };
    next.take(WARM_COUNT)
        .filter(stale)
        .min_by_key(|c| c.checked_at.unwrap_or(i64::MIN))
}
