//! What the resolver learned survives a restart (RU audit item 10): the last good addresses of
//! VPN server names and, per network, the upstream that answered last. Server IPs are rotated
//! within hours to days in Nov 2026, so entries older than a week are dropped; a cold start in a
//! network whose DNS is cut then still has an address to dial, and a network where only the
//! Russian-reachable resolver answers asks it first instead of waiting out four foreign ones.
//! The document is sealed with DPAPI: server names and addresses say which VPN the user runs.
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};

use crate::secret::Secret;
use crate::store::{Document, Store};

/// Entries older than this are forgotten.
pub const MEMORY_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Networks remembered at most (the oldest winner goes first).
const NETWORKS: usize = 32;
/// How often the process memory is compared with the document (and written when it changed).
const SAVE_EVERY: Duration = Duration::from_secs(30);

/// `cache/resolver.json`: the sealed [`Learned`] payload.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolverMemoryDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed: Option<Secret>,
}

impl Document for ResolverMemoryDoc {
    const FILE: &'static str = "cache/resolver.json";
    const VERSION: u32 = 1;
}

/// The plaintext inside the seal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Learned {
    /// Oldest first.
    #[serde(default)]
    pub names: Vec<NameEntry>,
    #[serde(default)]
    pub winners: Vec<Winner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NameEntry {
    pub name: String,
    pub addrs: Vec<IpAddr>,
    pub at: UnixMs,
}

/// The upstream (its [`super::chain::Upstream::key`]) that answered last on a network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Winner {
    pub network: String,
    pub upstream: String,
    pub at: UnixMs,
}

impl Learned {
    /// Drops what is older than [`MEMORY_TTL`] at `now` and keeps the newest [`NETWORKS`] winners.
    pub(super) fn pruned(mut self, now: UnixMs) -> Self {
        let fresh = |at: UnixMs| super::server::fresh(at, now);
        self.names.retain(|n| fresh(n.at) && !n.addrs.is_empty());
        self.winners.retain(|w| fresh(w.at));
        // Newest first; the name settles ties, so the same knowledge always compares equal.
        self.winners
            .sort_by(|a, b| b.at.cmp(&a.at).then_with(|| a.network.cmp(&b.network)));
        self.winners.truncate(NETWORKS);
        self
    }
}

/// An unchanged winner is stamped again only when its stamp is a day old: a network in use is
/// never forgotten after [`MEMORY_TTL`], and a quiet one causes no write.
const REFRESH: UnixMs = 24 * 60 * 60 * 1000;

/// The network the chain currently learns for, since when, and the winners per network.
#[derive(Debug, Default)]
pub(super) struct Networks {
    pub(super) current: Option<String>,
    /// When the machine moved to `current`: a win before it belongs to the network before.
    pub(super) since: UnixMs,
    pub(super) winners: HashMap<String, (String, UnixMs)>,
}

/// The chain's last win: the upstream's key and when it answered.
pub(super) type Win = (String, UnixMs);

impl Networks {
    /// Credits `win` to the current network when it was won there (`since <= at < until`),
    /// with the time it was won: only a new winner or a day-old stamp changes anything.
    pub(super) fn credit(&mut self, win: Option<&Win>, until: Option<UnixMs>) {
        let (Some(network), Some((upstream, at))) = (self.current.as_ref(), win) else {
            return;
        };
        if *at < self.since || until.is_some_and(|until| *at >= until) {
            return;
        }
        let known = self.winners.get(network).is_some_and(|(stored, stamped)| {
            stored == upstream && at.saturating_sub(*stamped) < REFRESH
        });
        if !known {
            self.winners
                .insert(network.clone(), (upstream.clone(), *at));
        }
    }

    /// The machine moved to `key` at `at`: a win before the move stays with the network it was
    /// won on. Returns the upstream to ask first now: a win since the move (the freshest
    /// evidence there), else the network's remembered winner, else none (production order).
    pub(super) fn switch(
        &mut self,
        key: Option<String>,
        at: UnixMs,
        win: Option<&Win>,
    ) -> Option<String> {
        self.credit(win, Some(at));
        self.current = key;
        self.since = at;
        self.credit(win, None);
        let network = self.current.as_ref()?;
        self.winners
            .get(network)
            .map(|(upstream, _)| upstream.clone())
    }
}

static NETWORKS_STATE: LazyLock<Mutex<Networks>> = LazyLock::new(Mutex::default);

/// The machine moved to network `key` (a stable identity of the physical uplink, `None` when
/// unknown) at `at` (when the move happened, as close as the caller knows): what the chain won
/// stays with the network it was won on, and the upstream [`Networks::switch`] names is asked
/// first. The same network again only takes in the latest win.
pub fn set_network(key: Option<String>, at: UnixMs) {
    let chain = super::chain();
    let win = last_win();
    let mut state = NETWORKS_STATE.lock();
    if state.current == key {
        state.credit(win.as_ref(), None);
        return;
    }
    let preferred = state.switch(key, at, win.as_ref());
    chain.prefer(preferred.as_deref());
}

fn last_win() -> Option<Win> {
    super::chain()
        .last_win()
        .map(|(upstream, at)| (upstream.key(), at))
}

/// Loads `cache/resolver.json` under `root`, seeds the process-wide resolver with it and writes
/// what the resolver learns back every 30 s (when it changed) and once more when `cancel`
/// fires. `network` = the current network's key, read just before: its winner is asked first
/// from the very first lookup. Call once at start, inside the tokio runtime, before the first
/// connect.
pub fn persist(root: &Path, network: Option<String>, cancel: CancellationToken) {
    let store = Arc::new(Store::<ResolverMemoryDoc>::open(root));
    let loaded = load(&store).pruned(now_ms());
    seed(&loaded);
    set_network(network, now_ms());
    tokio::spawn(save_loop(store, loaded, cancel));
}

/// The stored payload; a missing, locked (another account / PC) or damaged seal is empty.
fn load(store: &Store<ResolverMemoryDoc>) -> Learned {
    let sealed = store.read(|doc| doc.sealed.clone());
    match sealed.map(|s| s.expose_json::<Learned>()) {
        Some(Ok(learned)) => learned,
        Some(Err(err)) => {
            tracing::info!(error = %err, "resolver memory unreadable; starting empty");
            Learned::default()
        }
        None => Learned::default(),
    }
}

fn seed(learned: &Learned) {
    let names = learned
        .names
        .iter()
        .map(|n| (n.name.clone(), n.addrs.clone(), n.at))
        .collect();
    super::last_known().seed(names);
    let mut state = NETWORKS_STATE.lock();
    for w in &learned.winners {
        state
            .winners
            .entry(w.network.clone())
            .or_insert_with(|| (w.upstream.clone(), w.at));
    }
}

/// What the process knows now, pruned. Equal to the last save unless something was learned:
/// winners carry the time they won, not the time of the look.
fn current() -> Learned {
    let win = last_win();
    let mut state = NETWORKS_STATE.lock();
    state.credit(win.as_ref(), None);
    let winners = state
        .winners
        .iter()
        .map(|(network, (upstream, at))| Winner {
            network: network.clone(),
            upstream: upstream.clone(),
            at: *at,
        })
        .collect();
    drop(state);
    let names = super::last_known()
        .entries()
        .into_iter()
        .map(|(name, addrs, at)| NameEntry { name, addrs, at })
        .collect();
    Learned { names, winners }.pruned(now_ms())
}

/// Writes the memory whenever it differs from what was written last (a fresh seal differs in
/// bytes every time, so the comparison is on the plaintext).
async fn save_loop(
    store: Arc<Store<ResolverMemoryDoc>>,
    mut saved: Learned,
    cancel: CancellationToken,
) {
    loop {
        let last = tokio::select! {
            () = cancel.cancelled() => true,
            () = tokio::time::sleep(SAVE_EVERY) => false,
        };
        let now = current();
        if now != saved {
            match Secret::from_json(&now) {
                Ok(sealed) => match store.update(|doc| doc.sealed = Some(sealed)) {
                    Ok(()) => saved = now,
                    Err(err) => tracing::warn!(error = %err, "resolver memory not saved"),
                },
                Err(err) => tracing::warn!(error = %err, "resolver memory not sealed"),
            }
        }
        if last {
            return;
        }
    }
}

#[cfg(test)]
mod tests;
