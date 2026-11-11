//! Key health (servers §2.10, §3.11): start a temporary engine for one profile (sing-box or
//! Xray, config on stdin, authenticated loopback inbound, kill-on-close Job), race three HTTPS
//! destinations through it, and turn the outcome into a verdict. A key that does not work is a
//! verdict (`online: false` + [`HealthReason`]); a probe that could not be set up (no free port,
//! engine missing, cancelled) is an error, never "offline". Used by the server list, the
//! tunnel's post-trial failover (one candidate at a time) and the live check.
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Engine, EnginePref, Loopback, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_engine::xray_config::select_engine;
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::model::{Kind, Profile};

use crate::ping::NetPath;

mod classify;
mod config;
mod destinations;
mod engine;
#[cfg(test)]
mod tests;

pub use classify::{classify_failure, parse_trace};
pub use config::{DIRECT_TAG, INBOUND_TAG, PROXY_TAG, ProbeRoute, probe_config};

use destinations::{DESTINATIONS, Destination, Race};
use engine::{Running, Start};

/// Probes running at once in a batch.
pub const CONCURRENCY: usize = 5;
/// Deadline of a batch (a group check).
pub const BATCH_DEADLINE: Duration = Duration::from_secs(600);

/// Why a key is offline (the old `healthReason` strings; same wire names as the server list's).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthReason {
    NoOutbound,
    ConfigFailed,
    TlsFailed,
    AuthFailed,
    Timeout,
    HandshakeFailed,
    Hy2ConfigFailed,
    Hy2AuthFailed,
    Hy2UdpBlocked,
    Hy2TlsFailed,
    Hy2HandshakeFailed,
}

impl HealthReason {
    /// User-facing explanation (`probes.keyHealth.reason.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            HealthReason::NoOutbound => "probes.keyHealth.reason.noOutbound",
            HealthReason::ConfigFailed => "probes.keyHealth.reason.configFailed",
            HealthReason::TlsFailed => "probes.keyHealth.reason.tlsFailed",
            HealthReason::AuthFailed => "probes.keyHealth.reason.authFailed",
            HealthReason::Timeout => "probes.keyHealth.reason.timeout",
            HealthReason::HandshakeFailed => "probes.keyHealth.reason.handshakeFailed",
            HealthReason::Hy2ConfigFailed => "probes.keyHealth.reason.hy2ConfigFailed",
            HealthReason::Hy2AuthFailed => "probes.keyHealth.reason.hy2AuthFailed",
            HealthReason::Hy2UdpBlocked => "probes.keyHealth.reason.hy2UdpBlocked",
            HealthReason::Hy2TlsFailed => "probes.keyHealth.reason.hy2TlsFailed",
            HealthReason::Hy2HandshakeFailed => "probes.keyHealth.reason.hy2HandshakeFailed",
        })
    }
}

/// What a probe needs from the app (a snapshot taken when the check starts).
#[derive(Debug, Clone)]
pub struct ProbeCtx {
    /// Bundled engines (`<resources>\sing-box.exe`, `<resources>\xray.exe`).
    pub singbox_exe: PathBuf,
    /// Must be the executable the running tunnel routes `direct-out` (its `engine_paths`):
    /// while our TUN runs, Xray probe dials rely on that process rule to bypass the tunnel.
    pub xray_exe: PathBuf,
    /// `Settings::proxy_engine`.
    pub engine_pref: EnginePref,
    /// Client device of the profile's group (default uTLS fingerprint, Xray translation).
    pub device: ClientDevice,
    /// Tunnel state: `tun_direct` is sing-box's `mixed-direct-in` while our TUN runs.
    pub net: NetPath,
    /// The running sing-box's `dns-bootstrap-in` (slot mode), for Xray name resolution.
    pub dns_bootstrap_in: Option<SocketAddr>,
}

/// The verdict of one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyHealth {
    pub online: bool,
    pub at: UnixMs,
    /// SOCKS readiness to the first 2xx (not engine start-up, S-14).
    pub rtt_ms: Option<u32>,
    pub reason: Option<HealthReason>,
    /// Public exit address and its country from the Cloudflare trace (a `health-trace` source).
    pub egress_ip: Option<IpAddr>,
    pub country: Option<Iso2>,
    /// The engine that ran the probe (`None` when none could be configured).
    pub engine: Option<Engine>,
}

impl KeyHealth {
    /// An offline verdict.
    pub fn offline(reason: HealthReason, engine: Option<Engine>) -> Self {
        Self {
            online: false,
            at: now_ms(),
            rtt_ms: None,
            reason: Some(reason),
            egress_ip: None,
            country: None,
            engine,
        }
    }
}

/// A running probe engine with its authenticated loopback SOCKS inbound (also for the live
/// check). Dropping it kills the process; [`ProbeEngine::stop`] also waits for the exit.
pub struct ProbeEngine {
    running: Box<Running>,
    socks: Loopback,
    engine: Engine,
}

impl ProbeEngine {
    /// The inbound to send probe traffic through (`socks5h://user:pass@127.0.0.1:port`).
    pub fn socks(&self) -> &Loopback {
        &self.socks
    }

    pub fn engine(&self) -> Engine {
        self.engine
    }

    /// Recent engine output (redacted), the input of [`classify_failure`].
    pub fn output(&self) -> String {
        self.running.output()
    }

    /// Stops the engine and waits for its exit.
    pub async fn stop(self) {
        (*self.running).stop().await;
    }
}

/// How a probe engine start ended.
pub enum Started {
    Ready(ProbeEngine),
    /// The engine rejected the profile, exited or never served its port: a key verdict.
    Offline(KeyHealth),
}

fn is_hysteria2(p: &Profile) -> bool {
    matches!(p.kind, Kind::Hysteria2 { .. })
}

/// Starts the engine `ctx.engine_pref` selects for `p` and waits for its local SOCKS port.
pub async fn start_probe_engine(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> AppResult<Started> {
    let hy2 = is_hysteria2(p);
    let Ok(engine) = select_engine(p, ctx.engine_pref).engine() else {
        return Ok(Started::Offline(KeyHealth::offline(
            classify::config_failed(hy2),
            None,
        )));
    };
    let start = match engine {
        Engine::SingBox => engine::start_singbox(p, ctx, cancel).await?,
        Engine::Xray => engine::start_xray(p, ctx, cancel).await?,
    };
    Ok(match start {
        Start::Ready(running, socks) => Started::Ready(ProbeEngine {
            running,
            socks,
            engine,
        }),
        Start::Failed(text) => Started::Offline(KeyHealth::offline(
            classify_failure(hy2, &text, ""),
            Some(engine),
        )),
        Start::Invalid => Started::Offline(KeyHealth::offline(
            classify::config_failed(hy2),
            Some(engine),
        )),
        // Both starts retry a lost port once and then fail themselves; never a verdict.
        Start::PortLost(_) => return Err(vpnte_engine::ports::PortsExhausted.into()),
    })
}

/// Checks one key: engine up, destinations raced (first 2xx wins, the trace may add the exit IP
/// and country), engine stopped. `Err` only for setup failures and cancellation.
pub async fn check_profile(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> AppResult<KeyHealth> {
    probe_with(p, ctx, &DESTINATIONS, |b| b, cancel).await
}

/// [`check_profile`] with the destinations and the HTTP client settings given (test seam).
pub(crate) async fn probe_with(
    p: &Profile,
    ctx: &ProbeCtx,
    destinations: &[Destination],
    tune: fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder,
    cancel: &CancellationToken,
) -> AppResult<KeyHealth> {
    let probe = match start_probe_engine(p, ctx, cancel).await? {
        Started::Ready(probe) => probe,
        Started::Offline(verdict) => return Ok(verdict),
    };
    let client = destinations::builder(probe.socks())
        .map(tune)
        .and_then(destinations::build);
    let raced = match client {
        Ok(client) => destinations::race(&client, destinations, cancel).await,
        Err(err) => Err(err),
    };
    let verdict = match raced {
        Ok(Race::Online {
            rtt_ms,
            egress_ip,
            country,
        }) => Ok(KeyHealth {
            online: true,
            at: now_ms(),
            rtt_ms: Some(rtt_ms),
            reason: None,
            egress_ip,
            country,
            engine: Some(probe.engine()),
        }),
        Ok(Race::Offline(errors)) => {
            let reason = classify_failure(is_hysteria2(p), &probe.output(), &errors);
            Ok(KeyHealth::offline(reason, Some(probe.engine())))
        }
        Err(err) => Err(err),
    };
    probe.stop().await;
    if let Ok(health) = &verdict {
        tracing::debug!(online = health.online, reason = ?health.reason, "key probe finished");
    }
    verdict
}

/// Why a batch produced no results.
#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    /// Nothing to check (the external proxy API answers 404).
    #[error("group not found or empty")]
    GroupNotFoundOrEmpty,
    #[error("health check cancelled")]
    Cancelled,
    #[error("health check deadline passed")]
    Timeout,
    /// Every probe failed to set up (engine missing or blocked, no free port).
    #[error("no probe could be started")]
    Setup(#[source] AppError),
}

impl From<HealthError> for AppError {
    fn from(err: HealthError) -> Self {
        match err {
            HealthError::GroupNotFoundOrEmpty => {
                AppError::validation(Msg::new("probes.keyHealth.groupEmpty"))
            }
            HealthError::Cancelled => AppError::cancelled(),
            HealthError::Timeout => AppError::timeout(),
            HealthError::Setup(err) => err,
        }
    }
}

/// Checks a batch (a group's keys; `None` = the row's profile is unreadable here → `no-outbound`)
/// with [`CONCURRENCY`] probes at a time under [`BATCH_DEADLINE`]. Results come in completion
/// order; a key whose probe could not be set up gets no result (not checked), and when that
/// happened to every key the first setup error is returned.
pub async fn check_many<K: Send>(
    items: Vec<(K, Option<Profile>)>,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> Result<Vec<(K, KeyHealth)>, HealthError> {
    if items.is_empty() {
        return Err(HealthError::GroupNotFoundOrEmpty);
    }
    let total = items.len();
    let checks = stream::iter(items)
        .map(|(key, profile)| async move {
            let result = match &profile {
                Some(p) => check_profile(p, ctx, cancel).await,
                None => Ok(KeyHealth::offline(HealthReason::NoOutbound, None)),
            };
            (key, result)
        })
        .buffer_unordered(CONCURRENCY)
        .collect::<Vec<_>>();
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => return Err(HealthError::Cancelled),
        outcome = tokio::time::timeout(BATCH_DEADLINE, checks) => outcome,
    };
    let Ok(outcome) = outcome else {
        return Err(HealthError::Timeout);
    };
    let mut results = Vec::with_capacity(total);
    let mut first_error = None;
    for (key, result) in outcome {
        match result {
            Ok(health) => results.push((key, health)),
            Err(err) if err.kind == vpnte_base::ErrorKind::Cancelled => {
                return Err(HealthError::Cancelled);
            }
            Err(err) => {
                tracing::warn!(error = %err, "key probe not set up");
                first_error.get_or_insert(err);
            }
        }
    }
    match first_error {
        Some(err) if results.is_empty() => Err(HealthError::Setup(err)),
        _ => Ok(results),
    }
}
