//! Adaptive bypass: after every tunnel start, prove that the tunnel really reaches the internet
//! (20 s settle, then 2 of 3 HTTPS probes) and, when it does not, escalate baseline → TLS record
//! fragmentation → TUN MTU 1280 → up to two sibling servers; remember per (network, profile) what
//! worked for 30 days.
//!
//! The engine knobs themselves live where the configs are built: TUN MTU in
//! `vpnte_engine::singbox_config::select_mtu`, TLS compatibility (`record_fragment` + uTLS rotation)
//! in `vpnte_profiles::EmitPolicy::tls_compat`. This module only decides the [`AdaptiveMode`] and
//! asks the [`Coordinator`](crate::coordinator::Coordinator) for protected restarts.
mod controller;
pub mod identity;
pub mod learning;
mod window;

#[cfg(test)]
mod tests;

use std::future::Future;
use std::time::Duration;

use serde_json::Value;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, ClientDevice, Engine, UnixMs};
use vpnte_base::{AppResult, Msg};

use crate::coordinator::SessionKind;

pub use controller::Adaptive;
pub use identity::NetworkSnapshot;
pub use learning::{AdaptiveDoc, LearnedRecord};

/// At most this many sibling servers are tried per connection (owner decision, spec §8 item 7).
pub const MAX_SIBLINGS: usize = 2;

/// What adaptive bypass needs to know about a server profile; the app fills it from
/// `vpnte_profiles` (never logged: the outbound carries credentials).
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileView {
    pub id: String,
    /// The outbound as `emit_singbox` produces it with `EmitPolicy::default()` (a chain is a JSON
    /// array): the fingerprint input and the source of the TLS / Reality / transport facts.
    pub outbound: Value,
    /// The client device the user picked for this profile, if any.
    pub client_device: Option<ClientDevice>,
    /// The uTLS fingerprint the profile names, if any.
    pub client_fingerprint: Option<String>,
    /// The engine that runs this profile's upstream (TLS compatibility is a no-op on Xray: A2).
    pub engine: Engine,
}

/// A sibling candidate: a usable profile of the active profile's group (enabled, not archived,
/// not known offline, has an outbound), in profile-store order.
#[derive(Debug, Clone, PartialEq)]
pub struct Sibling {
    pub profile: ProfileView,
    /// Last measured latency.
    pub latency_ms: Option<u32>,
}

/// Which compatibility knobs can help the running session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// TLS record fragmentation can change the handshake (sing-box upstream, TLS without Reality).
    pub tls: bool,
    /// A smaller TUN MTU can be tried (every Direct session).
    pub mtu: bool,
    /// The upstream belongs to an external local proxy: nothing to adapt, nothing to probe.
    pub external: bool,
    /// Why a knob is unavailable, for the UI.
    pub reason: Option<Msg>,
}

impl Capabilities {
    /// `mode` is applicable to this session.
    pub fn allows(&self, mode: AdaptiveMode) -> bool {
        match mode {
            AdaptiveMode::Baseline => true,
            AdaptiveMode::TlsCompatibility => self.tls,
            AdaptiveMode::MtuCompatibility => self.mtu,
        }
    }
}

/// Capabilities of a session (AB:156-179 with fixes A2 and A7).
pub fn capabilities(kind: SessionKind, profile: Option<&ProfileView>) -> Capabilities {
    if kind != SessionKind::Direct {
        return Capabilities {
            tls: false,
            mtu: false,
            external: true,
            reason: Some(Msg::new("automation.adaptive.reason.external")),
        };
    }
    let tls = profile
        .and_then(|p| p.outbound.get("tls"))
        .filter(|t| t.is_object());
    // A7: `tls: {enabled: false}` is plain text; fragmenting it would be a wasted restart.
    let tls_on = tls.is_some_and(|t| t.get("enabled") != Some(&Value::Bool(false)));
    let reality = tls
        .and_then(|t| t.get("reality"))
        .is_some_and(|r| r.is_object() && r.get("enabled") != Some(&Value::Bool(false)));
    let xray = profile.is_some_and(|p| p.engine == Engine::Xray);
    let reason = if tls_on && reality {
        Some(Msg::new("automation.adaptive.reason.reality"))
    } else if tls_on && xray {
        Some(Msg::new("automation.adaptive.reason.xray"))
    } else {
        None
    };
    Capabilities {
        tls: tls_on && !reality && !xray,
        mtu: true,
        external: false,
        reason,
    }
}

/// The next compatibility mode to try (AB:181-190).
pub fn next_mode(mode: AdaptiveMode, caps: &Capabilities) -> Option<AdaptiveMode> {
    if caps.external {
        return None;
    }
    match mode {
        AdaptiveMode::Baseline if caps.tls => Some(AdaptiveMode::TlsCompatibility),
        AdaptiveMode::Baseline | AdaptiveMode::TlsCompatibility if caps.mtu => {
            Some(AdaptiveMode::MtuCompatibility)
        }
        _ => None,
    }
}

/// Protocol family of an outbound: type, Reality flag and transport type. Siblings of another
/// family are tried first, since a block usually hits a protocol rather than one server (A5).
pub fn family(outbound: &Value) -> String {
    let o = outbound
        .as_array()
        .and_then(|a| a.first())
        .unwrap_or(outbound);
    let text = |path: &str| o.pointer(path).and_then(Value::as_str).unwrap_or("");
    let reality = o.pointer("/tls/reality/enabled") == Some(&Value::Bool(true));
    format!(
        "{}/{}/{}",
        text("/type"),
        if reality { "reality" } else { "" },
        text("/transport/type")
    )
}

/// Sibling order: another protocol family first, then the lowest known latency, then store
/// order (the sort is stable).
pub fn order_siblings(active: &ProfileView, mut candidates: Vec<Sibling>) -> Vec<Sibling> {
    let own = family(&active.outbound);
    candidates.retain(|c| c.profile.id != active.id);
    candidates.sort_by_key(|c| {
        (
            family(&c.profile.outbound) == own,
            c.latency_ms.map_or(u64::MAX, u64::from),
        )
    });
    candidates
}

/// Where adaptive bypass stands for the current session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Idle,
    Connecting,
    Verifying,
    Adapting,
    Connected,
    Failed,
}

/// Status for the UI (watch snapshot).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveStatus {
    pub phase: Phase,
    /// Engine mode of the running (or starting) session.
    pub mode: AdaptiveMode,
    /// The session runs through an external local proxy (old mode `external-managed`).
    pub external: bool,
    /// Restarts made by adaptive bypass for this connection (compatibility modes and siblings).
    pub attempts: u8,
    pub message: Msg,
    /// Why it failed (or a capability note), for the UI.
    pub reason: Option<Msg>,
    pub updated_at: UnixMs,
}

impl AdaptiveStatus {
    /// The idle status «Готово к подключению».
    pub fn idle(now: UnixMs) -> Self {
        Self {
            phase: Phase::Idle,
            mode: AdaptiveMode::Baseline,
            external: false,
            attempts: 0,
            message: Msg::new("automation.adaptive.status.idle"),
            reason: None,
            updated_at: now,
        }
    }
}

/// What adaptive bypass asks from the rest of the app (profiles, probes, tunnel); implemented by
/// the app. Futures are `Send` because the task runs under `tokio::spawn`.
pub trait AdaptiveHost: Send + Sync + 'static {
    /// The profile a `Direct` session runs, `None` if it is unknown.
    fn profile(&self, id: &str) -> Option<ProfileView>;

    /// Usable profiles of the same group as `id` (enabled, not archived, not known offline, with
    /// an outbound), in profile-store order, `id` itself excluded.
    fn siblings(&self, id: &str) -> Vec<Sibling>;

    /// One tunnel HTTPS probe through the OS stack (captured by the TUN, never the engine's SOCKS
    /// inbound): `vpnte_probes` tunnel probe with cache skipped and one retry. `Some(latency)` on
    /// success; must return promptly once `cancel` fires.
    fn probe(&self, cancel: CancellationToken) -> impl Future<Output = Option<Duration>> + Send;

    /// Commits a sibling that passed verification as the selected profile.
    fn select(&self, id: &str) -> AppResult<()>;

    /// Ends a session whose provisional sibling failed verification: stops the engine but keeps
    /// the kill switch / leak protection engaged (tunnel `stop` with `preserve_protection`), so
    /// an unproven server is never shown as connected. Emits `Stopped { cause: Fault }`.
    fn abandon(&self) -> impl Future<Output = ()> + Send;

    /// Identity of the current physical network; the default reads it through Win32.
    fn network_identity(&self) -> impl Future<Output = Option<NetworkSnapshot>> + Send {
        identity::read()
    }
}
