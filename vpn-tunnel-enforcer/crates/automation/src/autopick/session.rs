//! The watch of the running server session: samples its VPN traffic, confirms a suspicion with
//! one transfer, hands a confirmed stall to the reactions, and starts the retries when the run it
//! tracks ends on its own or stays stalled past the reactions' grace.
use std::time::Duration;

use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Owner;

use super::rescue::Trigger;
use super::stall::{self, Detector, Suspicion};
use super::task::{AutoPick, USER_GRACE};
use super::{Confirmation, Phase, PickHost};
use crate::adaptive::reaction::{CheckReaction, CheckVerdict, Report};
use crate::coordinator::{Coordinator, LifecycleEvent, RuntimeId, StopCause};

/// After a reported stall the reactions get this long to move the session; a stall still there
/// after it goes to the retries (when the user allows switching).
pub(super) const REACT_GRACE: Duration = Duration::from_secs(90);
/// Backoff of the confirmations after a false alarm: doubles from the first to the last.
const FALSE_ALARM: (Duration, Duration) = (Duration::from_secs(60), Duration::from_secs(600));
/// Pause after an inconclusive transfer: a connection-count freeze lifts in about two minutes
/// and a new handshake inside it extends it (the probes' `FREEZE_BACKOFF`).
const INCONCLUSIVE: Duration = Duration::from_secs(130);

/// The watch of one engine run of a server session.
#[derive(Default)]
struct Watch {
    run: Option<RuntimeId>,
    server: Option<String>,
    detector: Detector,
    /// No confirmation before this (one per window; backoff after a false alarm).
    next_confirm: Option<Instant>,
    false_alarm: Option<Duration>,
    /// When the stall of this run was reported to the reactions, and the user's `seq` then.
    reported: Option<(Instant, u64)>,
    /// The stall of this run went to the retries, or could not: nothing more from the watch.
    settled: bool,
}

impl Watch {
    fn of(run: RuntimeId, server: Option<String>) -> Self {
        Self {
            run: Some(run),
            server,
            ..Self::default()
        }
    }
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// Samples the running server session and reacts to the end of the run it tracks.
    pub(super) async fn watch(&self, cancel: CancellationToken) {
        let mut events = self.coord.events();
        let mut acts = self.host.user_acts();
        let mut ticker = tokio::time::interval(stall::SAMPLE);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut w = self.tracked();
        let mut last_act: Option<Instant> = None;
        loop {
            let episode = tokio::select! {
                () = cancel.cancelled() => return,
                changed = acts.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    last_act = Some(Instant::now());
                    // An episode that gave up is over for the user now.
                    self.clear_gave_up();
                    None
                }
                event = events.recv() => match event {
                    Ok(LifecycleEvent::Started { runtime_id, kind, profile_id, .. }) => {
                        self.clear_gave_up();
                        w = Watch::of(runtime_id, profile_id.filter(|_| kind.server()));
                        None
                    }
                    // A stale or unknown run is not ours: the tracked one goes on.
                    Ok(LifecycleEvent::Stopped { runtime_id, .. })
                        if w.run != Some(runtime_id) => None,
                    Ok(LifecycleEvent::Stopped { owner, cause, .. }) => {
                        let ended = std::mem::take(&mut w);
                        // The user's action that came before this stop counts even when both
                        // arrived at once.
                        if acts.has_changed().unwrap_or(false) {
                            acts.borrow_and_update();
                            last_act = Some(Instant::now());
                        }
                        let user_recent = last_act.is_some_and(|at| at.elapsed() < USER_GRACE);
                        // Only a fault: a schedule run retries on its own, and a stop right
                        // after the user's own action (Cancel, a server picked by hand, a
                        // settings restart) is that action's doing.
                        (cause == StopCause::Fault && owner != Owner::Schedule && !user_recent)
                            .then_some(ended.server)
                            .flatten()
                            .map(|id| (id, Trigger::Fault))
                    }
                    Ok(LifecycleEvent::NetworkChanged) => {
                        self.spent.lock().clear();
                        self.clear_gave_up();
                        None
                    }
                    Ok(LifecycleEvent::Fault { .. }) => None,
                    Err(RecvError::Lagged(_)) => {
                        w = self.tracked();
                        None
                    }
                    Err(RecvError::Closed) => return,
                },
                _ = ticker.tick() => self.sample(&mut w, &cancel).await,
            };
            if let Some((id, trigger)) = episode {
                self.rescue(&id, trigger, &cancel).await;
                // What queued meanwhile is the episode's own doing (its switches, the restores
                // of lost ones): the session that runs now is the truth.
                events = events.resubscribe();
                w = self.tracked();
            }
        }
    }

    /// The watch of the session that runs now (a server session), or none.
    fn tracked(&self) -> Watch {
        match self.coord.session().filter(|s| s.kind.server()) {
            Some(s) => Watch::of(s.runtime_id, s.profile_id),
            None => Watch::default(),
        }
    }

    fn clear_gave_up(&self) {
        if self.phase() == Phase::GaveUp {
            self.publish(Phase::Idle, None, 0, None);
        }
    }
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    /// One sample of the session's VPN traffic; a suspicion is confirmed by one transfer through
    /// the session. `Some` = the stall stayed past the reactions' grace: the retries take it.
    async fn sample(&self, w: &mut Watch, cancel: &CancellationToken) -> Option<(String, Trigger)> {
        let Some(s) = self.coord.session().filter(|s| s.kind.server()) else {
            *w = Watch::default();
            return None;
        };
        let id = s.profile_id.clone()?;
        if w.run != Some(s.runtime_id) || w.server.as_deref() != Some(id.as_str()) {
            *w = Watch::of(s.runtime_id, Some(id.clone()));
        }
        // After the user's Disconnect or Cancel nothing automatic runs until they connect again;
        // an operation in flight (a switch, a restart) is no stall; an episode (after a failed
        // launch) is in charge of its own sessions.
        let episode = self.episode.try_lock().is_err();
        let acts = self.acts();
        if w.settled || episode || acts.stopped || self.coord.busy() {
            w.detector.reset();
            return None;
        }
        let counters = self.host.counters().await?;
        let now = Instant::now();
        if w.detector.push(now, counters) == Suspicion::None
            || w.next_confirm.is_some_and(|at| now < at)
        {
            return None;
        }
        self.publish(Phase::Confirming, self.name_of(&id), 0, None);
        let user = self.until_user_acts(acts.seq, cancel);
        let result = self.host.confirm(&id, user.token()).await;
        self.publish(Phase::Idle, None, 0, None);
        // The user acted (the transfer was cut short), or the session moved meanwhile: the
        // result is about a moment that is gone.
        let moved = self.coord.session().map(|now| now.runtime_id) != Some(s.runtime_id);
        if user.gone() || moved {
            return None;
        }
        let now = Instant::now();
        w.detector.reset();
        match result {
            Confirmation::Passed => {
                let pause = (w.false_alarm).map_or(FALSE_ALARM.0, |p| (p * 2).min(FALSE_ALARM.1));
                w.false_alarm = Some(pause);
                w.next_confirm = Some(now + pause);
            }
            Confirmation::Deferred => w.next_confirm = Some(now + stall::WINDOW),
            // Data moved: never a reason to switch (a connection-count freeze lifts by itself).
            Confirmation::Inconclusive => w.next_confirm = Some(now + INCONCLUSIVE),
            Confirmation::Frozen | Confirmation::NoTraffic => {
                let seq = acts.seq;
                match w.reported {
                    None => {
                        w.reported = Some((now, seq));
                        self.host.report(stall_report(&id, result));
                    }
                    // The reactions had their chance and the session still carries nothing:
                    // the retries, unless the user acted since or keeps the server by hand.
                    Some((at, seen)) if now >= at + REACT_GRACE => {
                        w.settled = true;
                        let allowed = seen == seq && self.host.allowed().switch;
                        return allowed.then_some((id, Trigger::Stall(s.runtime_id)));
                    }
                    Some(_) => {}
                }
                w.next_confirm = Some(now + REACT_GRACE);
            }
        }
        None
    }
}

/// A confirmed stall as the reactions read it: frozen (switch, another transport or site first)
/// or offline (switch).
fn stall_report(id: &str, result: Confirmation) -> Report {
    let verdict = match result {
        Confirmation::Frozen => CheckVerdict::Frozen,
        _ => CheckVerdict::Offline,
    };
    Report {
        profile_id: id.to_owned(),
        verdict,
        reaction: CheckReaction::SwitchServer,
    }
}
