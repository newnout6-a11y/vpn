//! Tests of the automatic server choice with a fake host and the fake coordinator (paused time).
mod launch;
mod pure;
mod rescue;
mod stall;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_core::store::Store;

use super::*;
use crate::coordinator::testing::FakeCoordinator;
use crate::test_support::TempDir;

/// A list server for the tests: group `g`, never checked.
pub(super) fn server(id: &str, group: &str) -> Candidate {
    Candidate {
        id: id.to_owned(),
        group: group.to_owned(),
        name: format!("name-{id}"),
        alive: None,
        checked_at: None,
        latency_ms: None,
    }
}

/// The host as the tests script it; every call is recorded.
#[derive(Default)]
pub(super) struct FakeHost {
    pub servers: Mutex<Vec<Candidate>>,
    pub last_used: Mutex<Option<String>>,
    pub provider: Mutex<Option<ProviderWord>>,
    /// `true`: the user's upstream is a local proxy (no server requests).
    pub local_proxy: Mutex<bool>,
    /// The capture cannot run here (the TUN without the rights): every request is refused.
    pub refused: Mutex<Option<Msg>>,
    /// What the settings allow (`new`: everything, as the defaults do).
    pub allowed: Mutex<Allowed>,
    /// Check results by id (absent: alive, no latency); every checked id in order.
    pub check_results: Mutex<HashMap<String, Option<Checked>>>,
    pub checks: Mutex<Vec<String>>,
    pub counters: Mutex<Option<Counters>>,
    /// Scripted confirmations (exhausted: passed); every confirmed id in order.
    pub confirm_results: Mutex<VecDeque<Confirmation>>,
    pub confirms: Mutex<Vec<String>>,
    /// What a refresh answers (`None`: not a subscription); every refreshed id in order.
    pub fresh: Mutex<Option<Vec<String>>>,
    pub refreshes: Mutex<Vec<String>>,
    /// Ids whose slot is refused; every slot asked for in order.
    pub no_slot: Mutex<Vec<String>>,
    pub slots: Mutex<Vec<String>>,
    pub exposure: Mutex<Exposure>,
    pub acts: Mutex<Option<watch::Sender<UserActs>>>,
    pub reports: Mutex<Vec<Report>>,
    /// The user acts while a check or a slot of this id is asked for (`true`: a Disconnect or
    /// Cancel, `false`: another action): a race with a measurement or a slot wait.
    pub act_at: Mutex<Option<(String, bool)>>,
}

impl FakeHost {
    pub(super) fn new(servers: Vec<Candidate>) -> Arc<Self> {
        let host = Self::default();
        *host.servers.lock() = servers;
        *host.acts.lock() = Some(watch::Sender::new(UserActs::default()));
        *host.allowed.lock() = Allowed {
            reconnect: true,
            switch: true,
        };
        Arc::new(host)
    }

    fn act(&self, stopped: Option<bool>) {
        if let Some(tx) = self.acts.lock().as_ref() {
            tx.send_modify(|a| {
                a.seq += 1;
                a.stopped = stopped.unwrap_or(a.stopped);
            });
        }
    }

    /// The user changed a setting (or picked a server by hand).
    pub(super) fn user_acts_now(&self) {
        self.act(None);
    }

    /// The user pressed Disconnect, or Cancel of a connect or switch in flight.
    pub(super) fn user_stops(&self) {
        self.act(Some(true));
    }

    /// The user pressed Connect.
    pub(super) fn user_connects(&self) {
        self.act(Some(false));
    }

    fn race(&self, id: &str) {
        let at = self.act_at.lock().take_if(|(at, _)| at == id);
        match at {
            Some((_, true)) => self.user_stops(),
            Some((_, false)) => self.user_acts_now(),
            None => {}
        }
    }
}

impl PickHost for FakeHost {
    fn servers(&self) -> Vec<Candidate> {
        self.servers.lock().clone()
    }

    fn last_used(&self) -> Option<String> {
        self.last_used.lock().clone()
    }

    fn provider_word(&self, _id: &str) -> Option<ProviderWord> {
        *self.provider.lock()
    }

    fn request(&self, id: &str) -> Result<ConnectRequest, NoRequest> {
        if *self.local_proxy.lock() {
            return Err(NoRequest::LocalProxy);
        }
        if let Some(reason) = self.refused.lock().clone() {
            return Err(NoRequest::Refused(reason));
        }
        Ok(ConnectRequest::Direct {
            profile_id: id.to_owned(),
        })
    }

    fn allowed(&self) -> Allowed {
        *self.allowed.lock()
    }

    async fn check(&self, id: &str, _cancel: CancellationToken) -> Option<Checked> {
        self.checks.lock().push(id.to_owned());
        self.race(id);
        let scripted = self.check_results.lock().get(id).copied();
        scripted.unwrap_or(Some(Checked {
            alive: true,
            latency_ms: None,
        }))
    }

    async fn counters(&self) -> Option<Counters> {
        *self.counters.lock()
    }

    async fn confirm(&self, id: &str, _cancel: CancellationToken) -> Confirmation {
        self.confirms.lock().push(id.to_owned());
        let next = self.confirm_results.lock().pop_front();
        next.unwrap_or(Confirmation::Passed)
    }

    async fn refresh(&self, id: &str, _cancel: CancellationToken) -> Option<Vec<String>> {
        self.refreshes.lock().push(id.to_owned());
        self.fresh.lock().clone()
    }

    async fn slot(&self, id: &str, _wait: Duration, _cancel: CancellationToken) -> bool {
        self.slots.lock().push(id.to_owned());
        self.race(id);
        !self.no_slot.lock().iter().any(|n| n == id)
    }

    fn exposure(&self) -> Exposure {
        *self.exposure.lock()
    }

    fn user_acts(&self) -> watch::Receiver<UserActs> {
        let acts = self.acts.lock();
        acts.as_ref().map_or_else(
            || watch::channel(UserActs::default()).1,
            watch::Sender::subscribe,
        )
    }

    fn report(&self, report: Report) {
        self.reports.lock().push(report);
    }
}

/// An [`AutoPick`] over the fakes with its document in a throw-away directory.
pub(super) struct Rig {
    pub coord: Arc<FakeCoordinator>,
    pub host: Arc<FakeHost>,
    pub pick: Arc<AutoPick<FakeCoordinator, FakeHost>>,
    _dir: TempDir,
}

pub(super) fn rig(servers: Vec<Candidate>) -> Rig {
    let dir = TempDir::new("autopick");
    let coord = FakeCoordinator::new();
    let host = FakeHost::new(servers);
    let config = Arc::new(Store::<AutoPickConfig>::open(dir.path()));
    let pick = Arc::new(AutoPick::new(coord.clone(), host.clone(), config, None));
    Rig {
        coord,
        host,
        pick,
        _dir: dir,
    }
}
