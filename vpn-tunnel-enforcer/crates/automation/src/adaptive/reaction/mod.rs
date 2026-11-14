//! Reactions to the server checks' verdicts during a session (RU networks, Nov 2026): a banned IP
//! or a freezing connection moves the session to another server, a REALITY server that rejects
//! the handshake gets one retry with another allowed uTLS fingerprint, a network that cuts UDP
//! makes TCP-based profiles preferred until the network changes.
//!
//! The verdicts come from `vpnte_probes::discipline::classify` (this crate cannot depend on the
//! probes): the app maps each finished check to a [`Report`] and hands it to
//! [`Reactions::report`]. Every reaction is admitted by the [`Coordinator`] as
//! `Owner::AdaptiveRetry` (the lowest owner: it never pre-empts the user, a schedule or a
//! rotation), takes a slot of the probes' handshake budget before it dials, and is tried at most
//! once per server and network session.
//!
//! [`Coordinator`]: crate::coordinator::Coordinator
mod decide;
mod memory;
mod task;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

pub use memory::Verdicts;
pub use task::Reactions;

/// The uTLS fingerprints current Xray servers (≥ 26.9.8) accept for REALITY, in retry order;
/// `edge`, `ios`, `qq` and `random` are refused there, `android` and `360` work nowhere.
pub const ALLOWED_FINGERPRINTS: [&str; 3] = ["chrome", "firefox", "safari"];

/// The probes' classifier verdict (`vpnte_probes::discipline::Verdict`, same wire names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckVerdict {
    Healthy,
    Frozen,
    Stalled,
    HandshakeFailed,
    KeyRejected,
    IpBanned,
    UdpBlocked,
    Offline,
    Deferred,
    NotVerified,
}

/// The classifier's advice (`vpnte_probes::discipline::Reaction`, same wire names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckReaction {
    None,
    SwitchServer,
    TryAnotherFingerprint,
    PreferTcpTransport,
    RetryLater,
}

/// One finished check of a stored server profile, as the app reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub profile_id: String,
    pub verdict: CheckVerdict,
    pub reaction: CheckReaction,
}

/// The stream transport of a profile: what a freeze or a UDP block depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Plain TCP (no stream transport), including REALITY over raw TCP.
    Tcp,
    Ws,
    Grpc,
    Http,
    HttpUpgrade,
    /// Xray XHTTP: many short HTTP exchanges instead of one long stream.
    Xhttp,
    /// Carried over UDP: Hysteria2, TUIC, WireGuard or a QUIC transport.
    Udp,
}

impl Transport {
    /// The transport rides UDP (cut on mobile white-list days and some networks).
    pub fn udp(self) -> bool {
        self == Transport::Udp
    }
}

/// What reactions need to know about a stored server profile; the app fills it from the typed
/// profile and the server list (never logged).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFacts {
    pub id: String,
    /// Display name, for notices.
    pub name: String,
    /// The server address as stored, lower case: an IP literal or a domain.
    pub host: String,
    pub transport: Transport,
    /// TLS with REALITY.
    pub reality: bool,
    /// The uTLS fingerprint the engine uses for it, an override included (`None`: the engine
    /// default, Chrome).
    pub fingerprint: Option<String>,
    /// The verdict the server list stores for it, if any (may come from another network).
    pub verdict: Option<CheckVerdict>,
    /// Last measured latency.
    pub latency_ms: Option<u32>,
}

/// What reactions ask from the rest of the app (server list, probes budget, tunnel); implemented
/// by the app. Futures are `Send` because the task runs under `tokio::spawn`.
pub trait ReactionHost: Send + Sync + 'static {
    /// Facts of a stored profile; `None` when it is gone or cannot be read.
    fn server(&self, id: &str) -> Option<ServerFacts>;

    /// Usable server profiles a reaction may switch to (enabled, not archived, connectable), in
    /// store order.
    fn servers(&self) -> Vec<ServerFacts>;

    /// Reserves one TLS handshake to the profile's endpoint in the probes' shared budget
    /// (`discipline::budget().acquire(&Endpoint::of(&profile), max_wait, &cancel)`), so the
    /// reaction's dial never adds a burst to the checks' ones. `false`: deferred or cancelled.
    fn handshake_slot(
        &self,
        id: &str,
        max_wait: Duration,
        cancel: CancellationToken,
    ) -> impl Future<Output = bool> + Send;

    /// Overrides the uTLS fingerprint of `id` for the engine starts of this app run (never
    /// stored: the user's profile stays as imported); `None` removes the override.
    fn override_fingerprint(&self, id: &str, fingerprint: Option<&'static str>);
}
