//! The decision table (pure) and the reaction task, with a fake host and the shared fake
//! coordinator. No network, no engine: verdicts are scripted.
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use super::*;
use crate::coordinator::testing::FakeCoordinator;
use crate::test_support::TempDir;

mod table;
mod task;

/// A server on `host` with `transport`; name = upper-case id, everything else unknown.
fn srv(id: &str, host: &str, transport: Transport) -> ServerFacts {
    ServerFacts {
        id: id.into(),
        name: id.to_uppercase(),
        host: host.into(),
        transport,
        reality: false,
        fingerprint: None,
        verdict: None,
        latency_ms: None,
    }
}

fn reality(mut s: ServerFacts, fingerprint: Option<&str>) -> ServerFacts {
    s.reality = true;
    s.fingerprint = fingerprint.map(str::to_owned);
    s
}

fn report(id: &str, verdict: CheckVerdict, reaction: CheckReaction) -> Report {
    Report {
        profile_id: id.into(),
        verdict,
        reaction,
    }
}

fn ids(list: &[ServerFacts]) -> Vec<&str> {
    list.iter().map(|s| s.id.as_str()).collect()
}

/// The app side: a server list, the probes budget (refusals scripted per id) and the
/// fingerprint override knob, every call recorded.
#[derive(Default)]
struct FakeHost {
    servers: Mutex<Vec<ServerFacts>>,
    refuse: Mutex<HashSet<String>>,
    slots: Mutex<Vec<(String, Duration)>>,
    overrides: Mutex<Vec<(String, Option<&'static str>)>>,
}

impl FakeHost {
    fn new(servers: Vec<ServerFacts>) -> Arc<Self> {
        let host = Self::default();
        *host.servers.lock() = servers;
        Arc::new(host)
    }

    fn slot_ids(&self) -> Vec<String> {
        self.slots.lock().iter().map(|(id, _)| id.clone()).collect()
    }
}

impl ReactionHost for FakeHost {
    fn server(&self, id: &str) -> Option<ServerFacts> {
        self.servers.lock().iter().find(|s| s.id == id).cloned()
    }

    fn servers(&self) -> Vec<ServerFacts> {
        self.servers.lock().clone()
    }

    async fn handshake_slot(&self, id: &str, max_wait: Duration, _: CancellationToken) -> bool {
        self.slots.lock().push((id.to_owned(), max_wait));
        !self.refuse.lock().contains(id)
    }

    fn override_fingerprint(&self, id: &str, fingerprint: Option<&'static str>) {
        self.overrides.lock().push((id.to_owned(), fingerprint));
    }
}

/// A reaction service over the fakes with default settings (adaptive bypass and server
/// fallback on).
struct Rig {
    coord: Arc<FakeCoordinator>,
    host: Arc<FakeHost>,
    settings: Arc<Store<Settings>>,
    reactions: Arc<Reactions<FakeCoordinator, FakeHost>>,
    _dir: TempDir,
}

impl Rig {
    fn new(servers: Vec<ServerFacts>) -> Self {
        let dir = TempDir::new("reaction");
        let coord = FakeCoordinator::new();
        let host = FakeHost::new(servers);
        let settings = Arc::new(Store::<Settings>::open(dir.path()));
        let reactions = Arc::new(Reactions::new(
            coord.clone(),
            host.clone(),
            settings.clone(),
        ));
        Self {
            coord,
            host,
            settings,
            reactions,
            _dir: dir,
        }
    }

    /// A Direct session on `id`, owned by the user.
    fn running(&self, id: &str) {
        let kind = crate::coordinator::SessionKind::Direct;
        self.coord
            .set_session(kind, vpnte_base::types::Owner::Manual, Some(id));
    }

    async fn feed(&self, id: &str, verdict: CheckVerdict, reaction: CheckReaction) {
        let cancel = CancellationToken::new();
        self.reactions
            .handle(report(id, verdict, reaction), &cancel)
            .await;
    }
}
