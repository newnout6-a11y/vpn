//! Connecting at launch: the last-used server, the lowest-delay one (measured one check at a time
//! under the handshake budget, never a burst), or as the provider's
//! `subscription-autoconnect-type` says for its group.
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Level, Owner, now_ms};
use vpnte_base::{ErrorKind, Msg};

use super::rescue::{Ended, Trigger};
use super::task::{AutoPick, UserWatch};
use super::{
    Candidate, LaunchPick, Network, NoRequest, Phase, PickHost, ProviderWord, launch_pick, rank,
};
use crate::coordinator::{Coordinator, OpError};

/// A stored check younger than this is used as it is (no new handshake).
pub(super) const FRESH: Duration = Duration::from_secs(10 * 60);
/// At most this many servers are measured for the lowest delay.
const MEASURED: usize = 3;

/// What the launch run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launched {
    /// Off, no server, a local-proxy upstream, or something else already holds the lane.
    Skipped,
    /// The user acted first (or meanwhile): nothing more is done.
    UserFirst,
    Connected {
        profile_id: String,
    },
    /// The connect failed (or cannot run here); the retries took over when allowed.
    Failed {
        profile_id: String,
    },
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// The one launch run, after the scheduler's first pass (a schedule run decides first).
    pub async fn launch(&self, cancel: CancellationToken) -> Launched {
        if !self.schedule_settled(&cancel).await {
            return Launched::Skipped;
        }
        if self.acts().seq != 0 {
            return Launched::UserFirst;
        }
        let last = self.host.last_used();
        let word = last.as_deref().and_then(|id| self.host.provider_word(id));
        let choice = self.choice();
        let Some(pick) = launch_pick(choice, word) else {
            return Launched::Skipped;
        };
        if self.lane_taken() {
            return Launched::Skipped;
        }
        let mut servers = self.host.servers();
        let last_row = last.and_then(|id| servers.iter().find(|c| c.id == id).cloned());
        // The provider speaks for its own subscription: its pick stays inside its group.
        if let Some(row) = last_row.as_ref()
            && choice.is_none()
            && matches!(word, Some(ProviderWord::On(_)))
        {
            servers.retain(|c| c.group == row.group);
        }
        // Whether a connect can follow at all, before a server is measured or dialled.
        let Some(first) = last_row.clone().or_else(|| servers.first().cloned()) else {
            return Launched::Skipped;
        };
        match self.host.request(&first.id) {
            Ok(_) => {}
            Err(NoRequest::LocalProxy) => return Launched::Skipped,
            Err(NoRequest::Refused(reason)) => return self.launch_failed(&first, reason),
        }
        let user = self.until_user_acts(0, &cancel);
        let target = self.launch_target(pick, last_row, &servers, &user).await;
        // The measuring took time: the user or a schedule may have come first.
        if self.acts().seq != 0 {
            return Launched::UserFirst;
        }
        let Some(target) = target.filter(|_| !cancel.is_cancelled() && !self.lane_taken()) else {
            return Launched::Skipped;
        };
        let Ok(req) = self.host.request(&target.id) else {
            return Launched::Skipped;
        };
        self.publish(Phase::Launching, Some(target.name.clone()), 0, None);
        let result = self.coord.connect(Owner::Autopilot, req).await;
        self.publish(Phase::Idle, None, 0, None);
        match result {
            Ok(_) => Launched::Connected {
                profile_id: target.id,
            },
            // Someone with a higher claim holds the lane, or a stop cancelled the start.
            Err(OpError::Conflict | OpError::Cancelled) => Launched::Skipped,
            Err(_) if self.acts().seq != 0 => Launched::UserFirst,
            // Without the rights the capture needs no other server would connect either.
            Err(OpError::Failed(e)) if e.kind == ErrorKind::Permission => {
                self.launch_failed(&target, e.user_msg())
            }
            Err(err) => {
                self.unproven.add_if_silent(&target.id, &err);
                // An episode tells how it ended itself; without one, the failure is the news.
                if self.rescue(&target.id, Trigger::Launch, &cancel).await == Ended::NotStarted {
                    return self.launch_failed(&target, err.reason());
                }
                Launched::Failed {
                    profile_id: target.id,
                }
            }
        }
    }

    fn launch_failed(&self, target: &Candidate, reason: Msg) -> Launched {
        let title = Msg::new("automation.autopick.launch.failed").arg("name", &target.name);
        self.notify(Level::Warn, title, Some(reason));
        Launched::Failed {
            profile_id: target.id.clone(),
        }
    }

    /// A session, an operation in flight, or what a session left (a kept block) holds the lane.
    pub(super) fn lane_taken(&self) -> bool {
        self.coord.session().is_some() || self.coord.busy() || self.coord.left_by().is_some()
    }

    /// The server a launch connects to; `in_group`: only from the last-used server's group.
    async fn launch_target(
        &self,
        pick: LaunchPick,
        last_row: Option<Candidate>,
        servers: &[Candidate],
        user: &UserWatch,
    ) -> Option<Candidate> {
        let net = self.network(servers).await;
        let best_ranked = || rank(servers, &net, |_| false).first().copied().cloned();
        match pick {
            LaunchPick::LastUsed => last_row.or_else(best_ranked),
            LaunchPick::Random => {
                if servers.is_empty() {
                    return None;
                }
                Some(servers[fastrand::usize(..servers.len())].clone())
            }
            LaunchPick::LowestDelay => (self.lowest_delay(servers, &net, user).await)
                .or(last_row)
                .or_else(best_ranked),
        }
    }

    /// The alive server with the lowest delay among the best-ranked few; stored checks younger
    /// than [`FRESH`] count as they are, the others are checked one after another.
    async fn lowest_delay(
        &self,
        servers: &[Candidate],
        net: &Network,
        user: &UserWatch,
    ) -> Option<Candidate> {
        let mut best: Option<(u32, Candidate)> = None;
        for c in rank(servers, net, |_| false).into_iter().take(MEASURED) {
            let fresh = c
                .checked_at
                .is_some_and(|at| now_ms().saturating_sub(at) < FRESH.as_millis() as i64);
            let latency = if fresh {
                c.alive.unwrap_or(false).then_some(c.latency_ms).flatten()
            } else {
                match self.host.check(&c.id, user.token()).await {
                    Some(checked) if checked.alive => checked.latency_ms,
                    _ => None,
                }
            };
            // The user acted, or someone else took the lane: measuring is pointless now.
            if user.gone() || self.lane_taken() {
                return None;
            }
            if let Some(ms) = latency
                && best.as_ref().is_none_or(|(b, _)| ms < *b)
            {
                best = Some((ms, c.clone()));
            }
        }
        best.map(|(_, c)| c)
    }
}
