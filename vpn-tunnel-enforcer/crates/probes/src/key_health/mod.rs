//! Key health (servers §2.10, §3.11): start a temporary engine for one profile (sing-box or
//! Xray, config on stdin, authenticated loopback inbound, kill-on-close Job), push one transfer
//! through it and turn the outcome into a verdict. A key that does not work is a verdict
//! (`online: false` + [`HealthReason`], plus the classifier's [`Classification`]); a probe that
//! could not be set up (no free port, engine missing, cancelled, handshake budget deferred) is
//! an error, never "offline". Used by the server list, the tunnel's post-trial failover (one
//! candidate at a time) and the live check.
//! RU discipline (Nov 2026): one budgeted handshake per check (the old three parallel requests
//! were a burst to one server name), and "online" needs more than the ~16 KB freeze threshold:
//! the trace and [`TRANSFER_BYTES`](crate::discipline::TRANSFER_BYTES) go over that one
//! connection.
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, Engine, EnginePref, Loopback, UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_engine::xray_config::{Decision, Reject, select_engine};
use vpnte_profiles::countries::Iso2;
use vpnte_profiles::model::{Kind, Profile};

use crate::discipline::{
    self, Classification, Endpoint, FREEZE_BACKOFF, Limits, Observations, Reach, Reaction, Seen,
    Transfer, TransferReport, Verdict, classify, real_certificate,
};
use crate::live::wire::{Dial, Wire};
use crate::ping::{NetPath, PingTarget};

mod classify;
mod config;
mod engine;
#[cfg(test)]
mod tests;

pub use classify::{classify_failure, parse_trace};
pub use config::{DIRECT_TAG, INBOUND_TAG, PROXY_TAG, Uplink, probe_config};

use engine::{Running, Start};

/// Probes running at once in a batch.
pub const CONCURRENCY: usize = 5;
/// Deadline of a batch (a group check).
pub const BATCH_DEADLINE: Duration = Duration::from_secs(600);
/// Longest wait of one key for its handshake slot: just over one budget window, so the 4th–6th
/// key behind one server name are still checked and later ones are deferred.
pub const KEY_WAIT: Duration = Duration::from_secs(65);
/// The engine logs a failed dial asynchronously: give its last lines a moment to arrive.
const LOG_SETTLE: Duration = Duration::from_millis(150);

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
    /// The engine setting (the app's or the server's own) does not run this key: an engine
    /// verdict, the key itself was never tried (ENGINE-GAPS decision 3).
    EngineSetting,
    /// The TCP connect to the key's port was reset (by the server or a filter on the way),
    /// unlike a silent timeout.
    ConnectionRefused,
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
            HealthReason::EngineSetting => "probes.keyHealth.reason.engineSetting",
            HealthReason::ConnectionRefused => "probes.keyHealth.reason.connectionRefused",
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

/// The verdict of a key the engine setting refused: the setting, not the server, so never a
/// "dead key" (it is stored as `engine-setting` and classified `not-verified`).
fn refused(reject: Reject) -> KeyCheck {
    tracing::debug!(reason = %reject.msg().key, "probe refused by the engine setting");
    KeyCheck {
        health: KeyHealth::offline(HealthReason::EngineSetting, None),
        verdict: Classification {
            verdict: Verdict::NotVerified,
            reaction: Reaction::None,
        },
    }
}

/// Starts the engine `ctx.engine_pref` selects for `p` and waits for its local SOCKS port.
pub async fn start_probe_engine(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> AppResult<Started> {
    let hy2 = is_hysteria2(p);
    let engine = match select_engine(p, ctx.engine_pref) {
        Decision::Selected { engine, .. } => engine,
        Decision::Rejected(reject) => return Ok(Started::Offline(refused(reject).health)),
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

/// One key's verdict and what the classifier made of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyCheck {
    pub health: KeyHealth,
    pub verdict: Classification,
}

/// Checks one key: [`check_profile_verdict`] without the classification.
pub async fn check_profile(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> AppResult<KeyHealth> {
    Ok(check_profile_verdict(p, ctx, cancel).await?.health)
}

/// Checks one key: a handshake slot of its endpoint (waits up to [`KEY_WAIT`], else `Err`
/// "deferred"), engine up, the trace and the transfer on one connection, the reach probe when
/// the dial failed, engine stopped. `Err` only for setup failures, deferral and cancellation.
pub async fn check_profile_verdict(
    p: &Profile,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> AppResult<KeyCheck> {
    let wire = Wire::verified().map_err(AppError::internal)?;
    probe_with(p, ctx, &wire, Limits::STANDARD, cancel).await
}

/// [`check_profile_verdict`] with the connection maker and the timing given (test seam).
pub(crate) async fn probe_with(
    p: &Profile,
    ctx: &ProbeCtx,
    wire: &Wire,
    limits: Limits,
    cancel: &CancellationToken,
) -> AppResult<KeyCheck> {
    // Before the handshake budget: a refused key makes no handshake, so it spends no slot.
    if let Decision::Rejected(reject) = select_engine(p, ctx.engine_pref) {
        return Ok(refused(reject));
    }
    let endpoint = Endpoint::of(p);
    if let Some(endpoint) = &endpoint {
        discipline::budget()
            .acquire(endpoint, KEY_WAIT, cancel)
            .await?;
    }
    let udp_transport = PingTarget::of(p).udp_only;
    let probe = match start_probe_engine(p, ctx, cancel).await? {
        Started::Ready(probe) => probe,
        Started::Offline(health) => {
            let seen = Observations {
                udp_transport,
                failure: health.reason,
                ..Observations::default()
            };
            let verdict = classify(&seen);
            return Ok(KeyCheck { health, verdict });
        }
    };
    let dial = Dial::Socks(probe.socks());
    let report = discipline::transfer_check(wire, dial, true, limits, cancel).await;
    let report = match report {
        Ok(report) => report,
        Err(err) => {
            probe.stop().await;
            return Err(err);
        }
    };
    let online = answered(&report);
    if !online {
        tokio::time::sleep(LOG_SETTLE).await;
    }
    let log = if online {
        String::new()
    } else {
        probe.output()
    };
    let engine = probe.engine();
    probe.stop().await;
    if let Some(endpoint) = &endpoint
        && report.transfer.frozen()
    {
        discipline::budget().hold(endpoint, FREEZE_BACKOFF);
    }
    let failure = (!online).then(|| failure_of(is_hysteria2(p), &log, &report.transfer));
    let reach = if needs_reach(&report.transfer, failure) {
        discipline::reach(
            &p.server.to_string(),
            p.port,
            udp_transport,
            &ctx.net,
            cancel,
        )
        .await
    } else {
        Reach::default()
    };
    let failure = refined(failure, udp_transport, reach.tcp);
    let verdict = classify(&Observations {
        udp_transport,
        deferred: false,
        transfer: Some(report.transfer.clone()),
        failure,
        real_certificate: real_certificate(&log),
        icmp: reach.icmp,
        tcp: reach.tcp,
    });
    let (egress_ip, country) = report.trace.unwrap_or_default();
    let health = KeyHealth {
        online,
        at: now_ms(),
        rtt_ms: if online { report.answer_ms } else { None },
        reason: failure,
        egress_ip,
        country,
        engine: Some(engine),
    };
    tracing::debug!(online, verdict = ?verdict.verdict, "key probe finished");
    Ok(KeyCheck { health, verdict })
}

/// The tunnel works end to end: the whole transfer came, or the destination answered with an
/// HTTP status through it (the volume is then unproven: the verdict says so).
fn answered(report: &TransferReport) -> bool {
    match &report.transfer {
        Transfer::Complete { .. } => true,
        Transfer::Failed { error, .. } => {
            report.answer_ms.is_some() && error.starts_with("http status")
        }
        _ => false,
    }
}

/// The failure class: a stall is the data timing out; otherwise the engine's log and the error.
fn failure_of(hysteria2: bool, log: &str, transfer: &Transfer) -> HealthReason {
    match transfer {
        Transfer::Stalled { .. } => HealthReason::Timeout,
        Transfer::Failed { error, .. } => classify_failure(hysteria2, log, error),
        Transfer::NoData | Transfer::Complete { .. } => classify_failure(hysteria2, log, "timeout"),
    }
}

/// The reach probe's reset outranks the engine's wording: a dial into a closed port often
/// surfaces in the engine log only as a generic timeout or nothing at all. UDP transports keep
/// their own class (a TCP reset there proves the address is up, not that the key's port is shut).
fn refined(failure: Option<HealthReason>, udp_transport: bool, tcp: Seen) -> Option<HealthReason> {
    match failure {
        Some(HealthReason::Timeout | HealthReason::HandshakeFailed)
            if !udp_transport && tcp == Seen::Refused =>
        {
            Some(HealthReason::ConnectionRefused)
        }
        other => other,
    }
}

/// The plain probes only matter when nothing came back and the failure is not the key itself.
fn needs_reach(transfer: &Transfer, failure: Option<HealthReason>) -> bool {
    let silent = matches!(
        transfer,
        Transfer::NoData | Transfer::Failed { bytes: 0, .. }
    );
    let decisive = matches!(
        failure,
        Some(
            HealthReason::AuthFailed
                | HealthReason::Hy2AuthFailed
                | HealthReason::ConfigFailed
                | HealthReason::Hy2ConfigFailed
                | HealthReason::NoOutbound
        )
    );
    silent && !decisive
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
    /// Every probe failed to set up (engine missing or blocked, no free port) or was deferred by
    /// the handshake budget (`probes.discipline.deferred`).
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

/// [`check_many_verdicts`] without the classifications.
pub async fn check_many<K: Send>(
    items: Vec<(K, Option<Profile>)>,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> Result<Vec<(K, KeyHealth)>, HealthError> {
    let checked = check_many_verdicts(items, ctx, cancel).await?;
    Ok(checked.into_iter().map(|(k, c)| (k, c.health)).collect())
}

/// Checks a batch (a group's keys; `None` = the row's profile is unreadable here → `no-outbound`)
/// with [`CONCURRENCY`] probes at a time under [`BATCH_DEADLINE`], each behind its endpoint's
/// handshake budget. Results come in completion order; a key whose probe could not be set up
/// or was deferred gets no result (not checked), and when that happened to every key the first
/// such error is returned.
pub async fn check_many_verdicts<K: Send>(
    items: Vec<(K, Option<Profile>)>,
    ctx: &ProbeCtx,
    cancel: &CancellationToken,
) -> Result<Vec<(K, KeyCheck)>, HealthError> {
    if items.is_empty() {
        return Err(HealthError::GroupNotFoundOrEmpty);
    }
    let total = items.len();
    let checks = stream::iter(items)
        .map(|(key, profile)| async move {
            let result = match &profile {
                Some(p) => check_profile_verdict(p, ctx, cancel).await,
                None => Ok(unreadable()),
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
            Ok(check) => results.push((key, check)),
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

/// The verdict of a row whose profile cannot be opened here.
fn unreadable() -> KeyCheck {
    let health = KeyHealth::offline(HealthReason::NoOutbound, None);
    let verdict = classify(&Observations {
        failure: health.reason,
        ..Observations::default()
    });
    KeyCheck { health, verdict }
}
