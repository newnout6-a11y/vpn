//! [`AutoPick`]: the launch connect, the session watch (stall detection) and the candidate
//! warm-up as one service; the retries after a failure live in `rescue`.
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::UnixMs;
use vpnte_core::store::Store;

use super::network::NetSession;
use super::proof::Unproven;
use super::{AutoPickConfig, LaunchChoice, LaunchPick, Phase, PickHost, PickStatus, UserActs};
use super::{LaunchSource, launch_pick, launch_source};
use crate::adaptive::reaction::Verdicts;
use crate::coordinator::Coordinator;
use crate::scheduler::SchedulerStatus;

/// The automatic server choice of this process (one instance; the app spawns [`AutoPick::run`]
/// and [`AutoPick::launch`]).
pub struct AutoPick<C: Coordinator, H: PickHost> {
    pub(super) coord: Arc<C>,
    pub(super) host: Arc<H>,
    pub(super) config: Arc<Store<AutoPickConfig>>,
    status: watch::Sender<PickStatus>,
    schedule: Option<watch::Receiver<SchedulerStatus>>,
    /// One retry episode at a time (a launch failure and a session fault never overlap).
    pub(super) episode: Mutex<()>,
    /// Servers that had their episode on this network: one each, so a stop the episode caused
    /// itself, or a server that fails again at once, never starts a chain of episodes. A network
    /// change clears it (a new network deserves a new try).
    pub(super) spent: parking_lot::Mutex<HashSet<String>>,
    /// Servers whose exit proof failed in this app session: the rescue rounds skip them.
    pub(super) unproven: Unproven,
    /// The reactions' network memory (UDP cut, mobile whitelist, servers ruled out here).
    pub(super) verdicts: Option<Arc<Verdicts>>,
    /// This network's tag and the whitelist proofs already noted on it.
    pub(super) net: parking_lot::Mutex<NetSession>,
}

impl<C: Coordinator, H: PickHost> AutoPick<C, H> {
    pub fn new(
        coord: Arc<C>,
        host: Arc<H>,
        config: Arc<Store<AutoPickConfig>>,
        schedule: Option<watch::Receiver<SchedulerStatus>>,
    ) -> Self {
        Self {
            coord,
            host,
            config,
            status: watch::Sender::new(PickStatus::default()),
            schedule,
            episode: Mutex::new(()),
            spent: parking_lot::Mutex::new(HashSet::new()),
            unproven: Unproven::default(),
            verdicts: None,
            net: parking_lot::Mutex::new(NetSession::default()),
        }
    }

    /// Ranks by the reactions' network memory (hand it `Reactions::verdicts`), and learns which
    /// servers pass a mobile whitelist.
    #[must_use]
    pub fn with_verdicts(mut self, verdicts: Arc<Verdicts>) -> Self {
        self.verdicts = Some(verdicts);
        self
    }

    /// The status line's snapshot (what traffic does is not in it: the page reads that live).
    pub fn status(&self) -> watch::Receiver<PickStatus> {
        self.status.subscribe()
    }

    /// The user's choice as stored (`None`: never chosen).
    pub fn choice(&self) -> Option<LaunchChoice> {
        self.config.read(|c| c.launch)
    }

    /// Stores the user's choice for the next launches (an explicit Off too: it always wins).
    pub fn set_choice(&self, choice: LaunchChoice) -> AppResult<()> {
        self.config.update(|c| c.launch = Some(choice))
    }

    /// What a launch would do now and who decided it (the page shows the default rule's
    /// answer while the user has not chosen).
    pub fn launch_rule(&self) -> (Option<LaunchPick>, LaunchSource) {
        let last = self.host.last_used();
        let word = last.as_deref().and_then(|id| self.host.provider_word(id));
        let choice = self.choice();
        (launch_pick(choice, word), launch_source(choice, word))
    }

    /// The document's generation: re-read [`AutoPick::launch_rule`] when it moves.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.config.subscribe()
    }

    pub(super) fn publish(
        &self,
        phase: Phase,
        server: Option<String>,
        round: u8,
        at: Option<UnixMs>,
    ) {
        self.status.send_replace(PickStatus {
            phase,
            server,
            round,
            retry_at: at,
        });
    }

    pub(super) fn phase(&self) -> Phase {
        self.status.borrow().phase
    }

    /// Waits for the scheduler's first pass; `false` while a schedule run holds the launch.
    pub(super) async fn schedule_settled(&self, cancel: &CancellationToken) -> bool {
        let Some(mut status) = self.schedule.clone() else {
            return true;
        };
        tokio::select! {
            () = cancel.cancelled() => false,
            s = status.wait_for(|s| s.ready) => s.is_ok_and(|s| s.run.is_none() && !s.connecting),
        }
    }

    /// The task: the session watch and the candidate warm-up, until `cancel`.
    pub async fn run(&self, cancel: CancellationToken) {
        tokio::join!(self.watch(cancel.clone()), self.warm(cancel));
    }

    /// The user's actions from `seen` on: an automatic path that holds it gives up the moment
    /// the user acts again, and what it has in flight (a measurement, a slot wait, a pause) is
    /// cancelled at once rather than at its next check.
    pub(super) fn until_user_acts(&self, seen: u64, parent: &CancellationToken) -> UserWatch {
        let token = parent.child_token();
        let acts = self.host.user_acts();
        let (mut changes, watcher) = (acts.clone(), token.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = watcher.cancelled() => {}
                _ = changes.wait_for(|a| a.seq != seen) => watcher.cancel(),
            }
        });
        UserWatch { token, acts, seen }
    }

    /// The user's actions now.
    pub(super) fn acts(&self) -> UserActs {
        *self.host.user_acts().borrow()
    }

    pub(super) fn name_of(&self, id: &str) -> Option<String> {
        (self.host.servers().into_iter())
            .find(|c| c.id == id)
            .map(|c| c.name)
    }
}

/// [`AutoPick::until_user_acts`]: dropping it ends the watcher task.
pub(super) struct UserWatch {
    token: CancellationToken,
    acts: watch::Receiver<UserActs>,
    seen: u64,
}

impl UserWatch {
    /// The user acted (or the service stops): give up now.
    pub(super) fn gone(&self) -> bool {
        self.token.is_cancelled() || self.acts.borrow().seq != self.seen
    }

    /// A token for one step in flight, cancelled when the user acts.
    pub(super) fn token(&self) -> CancellationToken {
        self.token.child_token()
    }

    /// Resolves when the user acts (or the service stops).
    pub(super) async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}

impl Drop for UserWatch {
    fn drop(&mut self) {
        self.token.cancel();
    }
}

/// How long a stop counts as the user's own doing after their last action: a Cancel's stop, a
/// lost switch to a server they picked, a settings restart that failed. A lane operation's
/// budget is 120 s; the user always wins, so a fault inside this window starts nothing.
pub(super) const USER_GRACE: Duration = Duration::from_secs(150);
