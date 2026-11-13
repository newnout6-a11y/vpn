//! The automatic server choice of RU networks, Nov 2026 (research items 7 and 8): connect at
//! launch to the last-used or lowest-delay server, notice a session whose engine runs but carries
//! nothing, keep the next failover candidates checked, and when everything fails refresh the
//! failed server's subscription before retrying the other groups with a backoff.
//!
//! Every connect or switch goes through the [`Coordinator`] as a low owner (`Autopilot` for
//! connects, `AdaptiveRetry` for switches), so the user, a schedule and a rotation always win;
//! every dial takes a slot of the probes' handshake budget first (more than ~3 TLS handshakes a
//! minute to one server name freeze it for ~2 min on Russian networks). The user's own action
//! (Connect, Disconnect, Cancel, a server picked by hand, a changed setting) ends every automatic
//! path at once, and the user's opt-outs (no restarts after a crash, no server switching) hold.
//!
//! [`Coordinator`]: crate::coordinator::Coordinator
mod config;
mod launch;
mod network;
mod rank;
mod rescue;
mod session;
mod stall;
mod status;
mod task;
mod warm;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use crate::adaptive::reaction::Report;
use crate::coordinator::ConnectRequest;

pub use config::{
    AutoPickConfig, LaunchChoice, LaunchPick, LaunchSource, ProviderWord, launch_pick,
    launch_source,
};
pub use launch::Launched;
pub use network::{WHITELIST_PROOF, network_tag};
pub use rank::{Network, rank};
pub use stall::{Detector, Suspicion};
pub use status::{Exposure, Phase, PickStatus};
pub use task::AutoPick;
pub use warm::{WARM_COUNT, WARM_TICK, next_to_warm};

/// A list server as the automatic choice sees it (never logged: names only in notices).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    /// Its group (a subscription or the manual group).
    pub group: String,
    /// Display name, for notices and the status line.
    pub name: String,
    /// What the stored evidence says: `Some(false)` = a check found it dead or blocked.
    pub alive: Option<bool>,
    /// When it was last checked (health or verdict), if ever.
    pub checked_at: Option<UnixMs>,
    /// Round trip of the last check that reached it.
    pub latency_ms: Option<u32>,
    /// Its transport rides on UDP (Hysteria2, TUIC, WireGuard, QUIC): dead where UDP is cut.
    pub udp: bool,
    /// Its entry looks Russian: a host name or an entry address the probes classify as Russian.
    pub ru_entry: bool,
    /// What says it passes a mobile whitelist.
    pub whitelist: WhitelistFacts,
}

/// What says a server passes a mobile whitelist (the list keeps it per server).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WhitelistFacts {
    /// The user marked it «Работает в белых списках».
    pub marked: bool,
    /// The networks ([`network_tag`]) on which it carried [`WHITELIST_PROOF`] in whitelist
    /// mode; `None` = a network whose tag was not known.
    pub worked_on: Vec<Option<String>>,
}

impl WhitelistFacts {
    /// It carried data in whitelist mode on the network tagged `tag`.
    pub fn here(&self, tag: Option<&str>) -> bool {
        tag.is_some_and(|t| self.worked_on.iter().any(|w| w.as_deref() == Some(t)))
    }

    /// The user's mark or evidence from any network.
    pub fn ready(&self) -> bool {
        self.marked || !self.worked_on.is_empty()
    }
}

/// One check of a server that is not running (the app: a probe engine and a 64 KiB transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checked {
    pub alive: bool,
    pub latency_ms: Option<u32>,
}

/// The running session's engine counters (totals of the session) and its upstream watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub up: u64,
    pub down: u64,
    /// The runtime's watchdog says the upstream stopped answering.
    pub proxy_down: bool,
}

/// What one transfer through a session proved (the probes' classification of a transfer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// The whole transfer arrived: a false alarm (or, after a dial, the new session works).
    Passed,
    /// It stalled inside the freeze band of a foreign data centre: the server is frozen.
    Frozen,
    /// Nothing came back at all: the session carries nothing.
    NoTraffic,
    /// Data came back and then stopped outside the freeze band, or an answer came and the
    /// exchange then failed: the path carries data, its volume is unproven (a connection-count
    /// freeze looks like this and lifts within minutes). Never a reason to switch.
    Inconclusive,
    /// No handshake slot (or cancelled): not checked.
    Deferred,
}

/// The user's own actions as the automatic choice counts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UserActs {
    /// Bumped by each action: Connect, Disconnect, Cancel, a server picked by hand, a changed
    /// setting. An automatic path that saw another value gives up at once.
    pub seq: u64,
    /// The last start-or-stop action was a stop (Disconnect, Cancel of a connect or switch):
    /// nothing automatic runs until the user connects again.
    pub stopped: bool,
}

/// What the user's settings allow the automatic paths to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Allowed {
    /// «Restart the engine after a crash»: reconnects after a session ended on its own.
    pub reconnect: bool,
    /// «Try a neighbouring server» (with the adaptive bypass on): another server than the
    /// failed one, and any change of a running session.
    pub switch: bool,
}

/// Why no server session can start now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoRequest {
    /// The user's upstream is a local proxy: its sessions are not ours to start.
    LocalProxy,
    /// The capture the settings ask for cannot run in this process (the TUN without the rights).
    Refused(Msg),
}

/// What the automatic choice asks from the rest of the app; implemented by the app over the
/// server list, the probes, the tunnel and the reactions. Futures are `Send` (spawned tasks).
pub trait PickHost: Send + Sync + 'static {
    /// Usable list servers (not archived, readable on this PC), in store order.
    fn servers(&self) -> Vec<Candidate>;
    /// The server the user used last (the selection), when usable.
    fn last_used(&self) -> Option<String>;
    /// The provider's `subscription-autoconnect` for the group of `id`, when it sent one.
    fn provider_word(&self, id: &str) -> Option<ProviderWord>;
    /// How the user's settings connect server `id` now (TUN or system proxy).
    fn request(&self, id: &str) -> Result<ConnectRequest, NoRequest>;
    /// What the user's settings allow, read now.
    fn allowed(&self) -> Allowed;
    /// One check of a server that is not running, behind its handshake budget, recorded in the
    /// server list; `None` = not checked (deferred, cancelled, unreadable).
    fn check(
        &self,
        id: &str,
        cancel: CancellationToken,
    ) -> impl Future<Output = Option<Checked>> + Send;
    /// The running session's VPN traffic now (flows through the server only: direct-routed
    /// flows would hide a dead server); `None` without a session or while unreadable.
    fn counters(&self) -> impl Future<Output = Option<Counters>> + Send;
    /// One 64 KiB transfer through the running session's own exit, behind the budget of `id`.
    fn confirm(
        &self,
        id: &str,
        cancel: CancellationToken,
    ) -> impl Future<Output = Confirmation> + Send;
    /// Refreshes the subscription of `id`'s group: the ids of its keys that are new or whose
    /// key changed; `None` = not a subscription, or the refresh failed.
    fn refresh(
        &self,
        id: &str,
        cancel: CancellationToken,
    ) -> impl Future<Output = Option<Vec<String>>> + Send;
    /// Reserves one handshake to `id`'s endpoint; `false` = deferred or cancelled.
    fn slot(
        &self,
        id: &str,
        max_wait: Duration,
        cancel: CancellationToken,
    ) -> impl Future<Output = bool> + Send;
    /// What the user's traffic does right now (read from the live state on every call).
    fn exposure(&self) -> Exposure;
    /// The user's own actions (Connect, Disconnect, Cancel, a server picked by hand, a changed
    /// setting): automation that started before gives up (it never acts against the user).
    fn user_acts(&self) -> watch::Receiver<UserActs>;
    /// Hands a verdict about a server to the check-verdict reactions.
    fn report(&self, report: Report);
    /// The one-way tag of the network the PC is on now ([`network_tag`]); `None` = unknown.
    fn network(&self) -> impl Future<Output = Option<String>> + Send;
    /// Server `id` carried [`WHITELIST_PROOF`] while the network tagged `network` was in
    /// whitelist mode: the list keeps that as evidence (never blocks the caller).
    fn worked_under_whitelist(&self, id: &str, network: Option<String>);
}
