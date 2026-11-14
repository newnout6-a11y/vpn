//! When the failed server cannot be kept: its subscription is fetched again once (Russian server
//! IPs live hours to days in Nov 2026, the provider may have re-issued its keys), its fresh keys
//! are tried, then, when the user allows switching, the other groups, in rounds with a growing
//! pause. A success is announced only after traffic passed through the new session.
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Level, Notice, Owner, now_ms};
use vpnte_base::{ErrorKind, Msg};

use super::task::{AutoPick, UserWatch};
use super::{Candidate, Confirmation, Network, Phase, PickHost, rank};
use crate::coordinator::{
    Coordinator, LifecycleEvent, NoticeCategory, OpError, RuntimeId, SessionInfo, SwitchError,
};

/// Rounds before the retries give up (about twenty minutes with the pauses below).
pub const ROUNDS: u8 = 6;
/// Pause after round n (the last value repeats).
const PAUSES: [Duration; 5] = [
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
    Duration::from_secs(600),
];
/// Servers dialled per round, besides the fresh keys of the first one.
pub(super) const PER_ROUND: usize = 3;
/// How long one dial waits for its handshake slot.
const SLOT_WAIT: Duration = Duration::from_secs(10);
/// A server dialled within this long is not dialled again (the RU freeze window).
const QUIET: Duration = Duration::from_secs(130);
/// How long a fault waits for the lane to settle: a restore of a lost switch waits up to 30 s
/// for the lane's own recovery stop, then starts.
const SETTLE: Duration = Duration::from_secs(35);
const SETTLE_TICK: Duration = Duration::from_millis(250);

/// What started an episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    /// The tracked run ended on its own (restarts and the same-group failover spent).
    Fault,
    /// The connect at launch failed.
    Launch,
    /// This run still runs and carries nothing after the reactions' grace.
    Stall(RuntimeId),
}

/// How an episode ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ended {
    /// Not started: not allowed, spent on this network, or the lane is not free for it.
    NotStarted,
    /// Traffic passed through a new session.
    Recovered,
    /// Ended without a notice: the user acted, the lane was taken, or a session runs whose
    /// transfer could not be proven either way.
    Quiet,
    GaveUp,
}

/// One dial's end.
enum Attempt {
    /// A session runs on the candidate: its transfer decides.
    Up,
    /// Someone else holds the lane, or nothing can connect: the episode ends quietly.
    Taken,
    Failed,
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// The retries after `failed` failed, as one episode: only when the user's settings allow
    /// it, the user did not stop, `failed` had no episode on this network yet, and (after a
    /// fault) the lane settled with nothing in it.
    pub(super) async fn rescue(
        &self,
        failed: &str,
        trigger: Trigger,
        cancel: &CancellationToken,
    ) -> Ended {
        let Ok(_one) = self.episode.try_lock() else {
            return Ended::NotStarted;
        };
        let allowed = self.host.allowed();
        let permitted = match trigger {
            Trigger::Fault | Trigger::Launch => allowed.reconnect,
            Trigger::Stall(_) => allowed.switch,
        };
        let acts = self.acts();
        if !permitted || acts.stopped || self.spent.lock().contains(failed) {
            return Ended::NotStarted;
        }
        let free = match trigger {
            Trigger::Fault => self.lane_free(cancel).await,
            Trigger::Launch => true,
            Trigger::Stall(run) => self.coord.session().is_some_and(|s| s.runtime_id == run),
        };
        if !free || self.acts() != acts {
            return Ended::NotStarted;
        }
        self.spent.lock().insert(failed.to_owned());
        let user = self.until_user_acts(acts.seq, cancel);
        let ended = self.episode(failed, trigger, allowed.switch, &user).await;
        if ended == Ended::Quiet {
            self.publish(Phase::Idle, None, 0, None);
        }
        ended
    }

    /// After a fault: waits until no lane operation runs, then tells whether the lane is free. A
    /// restore of a lost switch, the kill switch's kept block or any session means the end is
    /// not ours to repair (a kept block is never replaced by an automatic connect).
    async fn lane_free(&self, cancel: &CancellationToken) -> bool {
        let deadline = Instant::now() + SETTLE;
        while self.coord.busy() && Instant::now() < deadline {
            tokio::select! {
                () = cancel.cancelled() => return false,
                () = tokio::time::sleep(SETTLE_TICK) => {}
            }
        }
        !self.coord.busy() && self.coord.session().is_none() && self.coord.left_by().is_none()
    }
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// The rounds; `user` is cancelled the moment the user acts. Without the user's leave to
    /// switch only `failed` itself is dialled again (its new key, once its quiet window passed).
    async fn episode(
        &self,
        failed: &str,
        trigger: Trigger,
        switch: bool,
        user: &UserWatch,
    ) -> Ended {
        let name = self.name_of(failed).unwrap_or_default();
        let group = (self.host.servers().into_iter())
            .find(|c| c.id == failed)
            .map(|c| c.group);
        self.publish(Phase::Refreshing, Some(name), 1, None);
        let fresh = (self.host.refresh(failed, user.token()).await).unwrap_or_default();
        // A new key is another server as far as its exit proof goes.
        self.unproven.forgive(fresh.iter().map(String::as_str));
        let mut tried = vec![(failed.to_owned(), Instant::now())];
        let mut dialled: Vec<String> = Vec::new();
        for round in 1..=ROUNDS {
            let servers: Vec<Candidate> = (self.host.servers().into_iter())
                .filter(|c| (switch || c.id == failed) && !self.unproven.contains(&c.id))
                .collect();
            let net = self.network(&servers).await;
            let order = match round {
                1 => first_round(&servers, &net, &fresh, group.as_deref(), failed),
                _ => later_round(&servers, &net, &tried),
            };
            for c in order {
                if user.gone() {
                    return Ended::Quiet;
                }
                // Its own session still runs on it: only a new key is worth a restart there.
                if c.id == failed && self.runs_on(failed) && !fresh.contains(&c.id) {
                    continue;
                }
                self.publish(Phase::Trying, Some(c.name.clone()), round, None);
                let slot = self.host.slot(&c.id, SLOT_WAIT, user.token()).await;
                // The user may have acted during the wait: their Disconnect stays one.
                if user.gone() {
                    return Ended::Quiet;
                }
                if !slot {
                    continue;
                }
                tried.push((c.id.clone(), Instant::now()));
                dialled.push(c.id.clone());
                match self.attempt(&c.id, failed, trigger, &dialled).await {
                    Attempt::Taken => return Ended::Quiet,
                    Attempt::Failed => {}
                    Attempt::Up => match self.host.confirm(&c.id, user.token()).await {
                        Confirmation::Passed => {
                            self.proved(&c.id).await;
                            self.recovered(&c.name, trigger);
                            return Ended::Recovered;
                        }
                        // It runs and carries nothing: the next candidate moves it.
                        Confirmation::NoTraffic => self.unproven.add(&c.id),
                        Confirmation::Frozen => {}
                        // Data moved, or no proof was possible: the session stays, unclaimed.
                        Confirmation::Inconclusive | Confirmation::Deferred => return Ended::Quiet,
                    },
                }
            }
            if round == ROUNDS {
                break;
            }
            let pause = PAUSES[usize::from(round - 1).min(PAUSES.len() - 1)];
            let at = now_ms() + i64::try_from(pause.as_millis()).unwrap_or(i64::MAX);
            self.publish(Phase::Waiting, None, round, Some(at));
            if !self.pause(pause, user, failed, trigger, &dialled).await {
                return Ended::Quiet;
            }
        }
        self.publish(Phase::GaveUp, None, ROUNDS, None);
        let title = Msg::new("automation.autopick.rescue.gaveUp");
        self.notify(Level::Warn, title, Some(self.host.exposure().msg()));
        Ended::GaveUp
    }

    /// The session of server `id` runs.
    fn runs_on(&self, id: &str) -> bool {
        (self.coord.session())
            .is_some_and(|s| s.kind.server() && s.profile_id.as_deref() == Some(id))
    }

    /// A session this episode may move: the stalled one (or the coordinator's restore of it
    /// after a lost switch) and the ones on the episode's own candidates. Anything else (the
    /// user's, a schedule's, a reaction's) ends the episode.
    fn ours(&self, s: &SessionInfo, failed: &str, trigger: Trigger, dialled: &[String]) -> bool {
        let Some(p) = s.profile_id.as_deref().filter(|_| s.kind.server()) else {
            return false;
        };
        dialled.iter().any(|d| d == p) || (matches!(trigger, Trigger::Stall(_)) && p == failed)
    }

    /// One dial: our session moves (a switch, or a protected restart on the same server's new
    /// key); with no session a connect, never over a kept block or a restore on its way.
    async fn attempt(
        &self,
        id: &str,
        failed: &str,
        trigger: Trigger,
        dialled: &[String],
    ) -> Attempt {
        let Some(s) = self.coord.session() else {
            if self.coord.left_by().is_some() {
                return Attempt::Taken;
            }
            let Ok(req) = self.host.request(id) else {
                return Attempt::Taken;
            };
            return match self.coord.connect(Owner::Autopilot, req).await {
                Ok(_) => Attempt::Up,
                Err(e) => {
                    self.unproven.add_if_silent(id, &e);
                    failure(&e)
                }
            };
        };
        if !self.ours(&s, failed, trigger, dialled) {
            return Attempt::Taken;
        }
        let moved = if s.profile_id.as_deref() == Some(id) {
            // A protected restart reads the list again: the server's new key.
            let restarted = self
                .coord
                .adaptive_restart(Owner::AdaptiveRetry, s.mode, Some(id));
            restarted.await.map(drop).map_err(SwitchError::NotStarted)
        } else {
            self.coord.switch_profile(Owner::AdaptiveRetry, id).await
        };
        match moved {
            Ok(()) => Attempt::Up,
            Err(SwitchError::NotStarted(e) | SwitchError::Failed { reason: e, .. }) => {
                self.unproven.add_if_silent(id, &e);
                failure(&e)
            }
        }
    }
}

/// A refused or failed dial: the user's Cancel, a higher owner, or missing rights end the
/// episode (no other server would get further); anything else is this server's failure.
fn failure(e: &OpError) -> Attempt {
    match e {
        OpError::Conflict | OpError::Cancelled => Attempt::Taken,
        OpError::Failed(e) if e.kind == ErrorKind::Permission => Attempt::Taken,
        _ => Attempt::Failed,
    }
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// Waits `pause`; `false` when the user acted or someone else's session started meanwhile; a
    /// network change ends the pause early (a new network deserves a try now).
    async fn pause(
        &self,
        pause: Duration,
        user: &UserWatch,
        failed: &str,
        trigger: Trigger,
        dialled: &[String],
    ) -> bool {
        let mut events = self.coord.events();
        let sleep = tokio::time::sleep(pause);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = user.cancelled() => return false,
                () = &mut sleep => return true,
                event = events.recv() => match event {
                    Ok(LifecycleEvent::NetworkChanged) => {
                        // This episode goes on there; every other server gets a new chance.
                        let mut spent = self.spent.lock();
                        spent.clear();
                        spent.insert(failed.to_owned());
                        self.unproven.clear();
                        return true;
                    }
                    // The coordinator's restore of a lost switch of ours is no reason to stop.
                    Ok(LifecycleEvent::Started { .. }) => {
                        let session = self.coord.session();
                        if !session.is_some_and(|s| self.ours(&s, failed, trigger, dialled)) {
                            return false;
                        }
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return true,
                },
            }
        }
    }

    /// Traffic passed through the new session: the one success notice.
    fn recovered(&self, name: &str, trigger: Trigger) {
        let key = match trigger {
            Trigger::Launch => "automation.autopick.launch.connected",
            Trigger::Fault | Trigger::Stall(_) => "automation.autopick.rescue.recovered",
        };
        self.publish(Phase::Idle, None, 0, None);
        self.notify(Level::Info, Msg::new(key).arg("name", name), None);
    }

    pub(super) fn notify(&self, level: Level, title: Msg, body: Option<Msg>) {
        let notice = Notice::new(level, title);
        let notice = match body {
            Some(body) => notice.body(body),
            None => notice,
        };
        self.coord.notify(NoticeCategory::ConnectionError, notice);
    }
}

/// The first round: the failed server's fresh keys (its own new key first), then the best of
/// the other groups.
fn first_round(
    servers: &[Candidate],
    net: &Network,
    fresh: &[String],
    group: Option<&str>,
    failed: &str,
) -> Vec<Candidate> {
    let mut fresh_keys = rank(servers, net, |id| !fresh.iter().any(|f| f == id));
    fresh_keys.sort_by_key(|c| c.id != failed);
    let others = rank(servers, net, |id| id == failed)
        .into_iter()
        .filter(|c| group.is_none_or(|g| c.group != g));
    (fresh_keys.into_iter().take(PER_ROUND))
        .chain(others.take(PER_ROUND))
        .cloned()
        .collect()
}

/// A later round: the best of what was not dialled within the freeze window.
fn later_round(
    servers: &[Candidate],
    net: &Network,
    tried: &[(String, Instant)],
) -> Vec<Candidate> {
    let quiet = |id: &str| tried.iter().any(|(t, at)| t == id && at.elapsed() < QUIET);
    (rank(servers, net, quiet).into_iter().take(PER_ROUND))
        .cloned()
        .collect()
}
