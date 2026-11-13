//! The tunnel runtime: one owner task (actor) that starts, supervises, switches and stops the
//! engines of a session, and the [`TunnelHandle`] that implements [`crate::api::Runtime`].
//!
//! The actor may run in another process than the UI (the privileged helper service): every
//! input arrives through [`RuntimeDeps`] and the [`StartRequest`], every output leaves as plain
//! data on the status watch, the event broadcast and the return values.
//!
//! The one seam between "what is captured how" and everything else is [`Capture`] (TUN or
//! loopback proxy, chosen per start): supervision, crash policy, watchdog scheduling,
//! compensation, protected restart and the upstream switch never name the TUN, WFP or adapters.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::KillSwitchLevel;
use vpnte_engine::routing::dns::DnsAddr;
use vpnte_engine::routing::domain::DomainRule;
use vpnte_engine::routing::process::{InactiveApp, InactiveReason, ResolvedSplit};

use crate::api::{CaptureKind, StartRequest, VpnProfile};

mod actor;
mod capture;
mod compensate;
mod config;
mod crash;
mod engines;
mod handle;
#[cfg(feature = "lab")]
mod mihomo;
mod pin;
mod recovery;
mod spawn;
mod start;
mod stop;
mod switch_ops;
mod watchdog;

#[cfg(test)]
pub(crate) mod tests;

pub use capture::{
    Capture, CaptureCheck, CapturePlan, CaptureProof, EngineParts, ProxyCapture, TunCapture,
    TunForm, tun_form,
};
pub use engines::{
    CoreProc, EngineExes, EngineFeed, EngineStarts, Engines, HandshakeGate, RealEngines, Slots,
    Started,
};
pub use handle::TunnelHandle;

/// The inputs of one start that live in the user's stores, as one plain serialisable snapshot
/// (in-process the app reads its stores; in the service the client sends it).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UserInputs {
    pub smart_ru: bool,
    pub smart_ru_maps_direct: bool,
    /// Directory holding both Smart RU `.srs` files; `None` = Smart RU off for this run.
    pub rule_set_dir: Option<PathBuf>,
    /// The user's domain rules in priority order.
    pub domain_rules: Vec<DomainRule>,
    /// Split tunnel, already resolved (`process_path_regex` values) by the store owner.
    pub split_direct: Vec<String>,
    pub split_vpn: Vec<String>,
    /// Split-tunnel entries whose file is unusable right now (each becomes a warning).
    pub split_inactive: Vec<InactiveSplit>,
    /// The active resolver; `None` = automatic (DoH through the tunnel).
    pub dns: Option<DnsAddr>,
    /// Current settings, applied by `restart_with_last` on top of the last start.
    pub kill_switch: KillSwitchLevel,
    pub public_wifi: bool,
    pub stealth: bool,
    /// Re-read when a crash restart is due.
    pub auto_restart_on_crash: bool,
}

/// A split-tunnel entry that produced no rule (serialisable mirror of the engine's type).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InactiveSplit {
    pub name: String,
    pub path: String,
    /// The file is gone (`false`: the path is not a regular file).
    pub missing: bool,
}

impl UserInputs {
    /// The split tunnel as the routing generator takes it.
    pub fn split(&self) -> ResolvedSplit {
        ResolvedSplit {
            direct: self.split_direct.clone(),
            vpn: self.split_vpn.clone(),
            inactive: self
                .split_inactive
                .iter()
                .map(|a| InactiveApp {
                    name: a.name.clone(),
                    path: a.path.clone(),
                    reason: if a.missing {
                        InactiveReason::FileMissing
                    } else {
                        InactiveReason::NotAFile
                    },
                })
                .collect(),
        }
    }
}

/// Where the actor gets [`UserInputs`]: read at every start and when a crash restart is due.
#[async_trait]
pub trait InputsSource: Send + Sync {
    /// The current inputs; an `Err` fails the start (and turns a due crash restart off).
    async fn snapshot(&self) -> AppResult<UserInputs>;
}

/// Post-trial failover (tunnel-core §3.14): a live sibling of an expired subscription's key.
#[async_trait]
pub trait Failover: Send + Sync {
    /// The next sibling that answered a health check, if any.
    async fn next_live_sibling(&self, cancel: &CancellationToken) -> Option<VpnProfile>;
    /// The sibling started: make it the active server.
    fn commit(&self, profile_id: &str);
}

/// Outside evidence that the tunnel carries traffic (a public-IP read or a tunnel probe that
/// succeeded recently); suppresses the direct-VPN watchdog's "proxy down".
pub trait Confirmations: Send + Sync {
    /// Such evidence is at most `age` old.
    fn confirmed_within(&self, age: Duration) -> bool;
}

/// Everything the actor needs, handed over once.
#[derive(Clone)]
pub struct RuntimeDeps {
    pub engines: Arc<dyn Engines>,
    /// TUN capture; `None` when the host cannot create adapters or WFP filters (not elevated):
    /// a [`crate::api::CaptureKind::Tun`] start then answers `Permission`.
    pub tun: Option<Arc<dyn Capture>>,
    /// Loopback proxy capture (Soft mode; needs no privileges, so always available).
    pub proxy: Arc<dyn Capture>,
    pub inputs: Arc<dyn InputsSource>,
    pub failover: Option<Arc<dyn Failover>>,
    pub confirmations: Option<Arc<dyn Confirmations>>,
    pub timings: Timings,
}

/// Deadlines and intervals (tunnel-core §2.10); tests shorten them.
#[derive(Debug, Clone)]
pub struct Timings {
    /// `sing-box started (` budget (first Wintun install takes seconds).
    pub ready: Duration,
    /// Capture readiness after sing-box reported ready (TUN adapter Up).
    pub capture_ready: Duration,
    /// Exit wait of a terminate.
    pub exit: Duration,
    /// Adapter disappearance after a full stop.
    pub release: Duration,
    /// Crash backoff before restart attempt 1, 2, 3.
    pub backoff: [Duration; 3],
    /// Paused kill switch after the budget (and the failover) are spent: the slow retries
    /// 1, 2, 5 minutes, then every 5 minutes (ks-a: no silent release; RU discipline: far
    /// below 3 handshakes a minute per server, never inside the freeze window).
    pub slow_retry: [Duration; 3],
    /// Quiet time of a crashed server with an outbound fault on record before a restart dials it
    /// again (RU freeze window ~120 s; the same value as the probes' `FREEZE_BACKOFF`).
    pub freeze: Duration,
    /// The shortest gap between two attempts on one server the user's «Подключить» may make
    /// (RU: a server name freezes after ~3 new handshakes within a minute).
    pub retry_spacing: Duration,
    /// A run this long resets the crash-restart budget.
    pub stable: Duration,
    /// Local-proxy watchdog period and TCP probe budget.
    pub proxy_watch: Duration,
    pub proxy_probe: Duration,
    /// Local-proxy listen probe at start (no listener = refuse: the TUN would blackhole).
    pub proxy_listen: Duration,
    /// Direct-VPN watchdog period and evidence age.
    pub egress_watch: Duration,
    pub evidence_age: Duration,
    /// Capture-specific checks (foreign / competing TUN).
    pub capture_watch: Duration,
    /// Fresh egress proof of a switch candidate / of the retained previous upstream.
    pub confirm_candidate: Duration,
    pub confirm_previous: Duration,
}

impl Default for Timings {
    fn default() -> Self {
        Self {
            ready: vpnte_engine::singbox_process::READY_TIMEOUT,
            capture_ready: Duration::from_secs(5),
            exit: vpnte_engine::singbox_process::STOP_TIMEOUT,
            release: Duration::from_secs(2),
            backoff: [2_000, 5_000, 10_000].map(Duration::from_millis),
            slow_retry: [60, 120, 300].map(Duration::from_secs),
            freeze: Duration::from_secs(130),
            retry_spacing: Duration::from_secs(20),
            stable: Duration::from_secs(30),
            proxy_watch: Duration::from_secs(5),
            proxy_probe: Duration::from_millis(1500),
            proxy_listen: Duration::from_secs(2),
            egress_watch: Duration::from_secs(15),
            evidence_age: Duration::from_secs(45),
            capture_watch: Duration::from_secs(15),
            confirm_candidate: Duration::from_secs(2),
            confirm_previous: Duration::from_secs(1),
        }
    }
}

/// Maximum number of automatic restarts after crashes (`restarting:n/3`).
pub const MAX_RESTARTS: u8 = 3;

/// The start request the next attempt uses: `restart_with_last` applies current settings. A
/// proxy session keeps its own kill switch, which the lifecycle keeps current
/// ([`crate::api::Runtime::set_kill_switch`]): next to another full-tunnel VPN it never pauses,
/// whatever level is stored (fix-ks a2). A TUN's filters enforce the level in force anyway.
pub(crate) fn with_current_settings(last: &StartRequest, now: &UserInputs) -> StartRequest {
    let kill_switch = match last.capture {
        CaptureKind::Proxy => last.kill_switch,
        CaptureKind::Tun => now.kill_switch,
    };
    StartRequest {
        kill_switch,
        public_wifi: now.public_wifi,
        stealth: now.stealth,
        ..last.clone()
    }
}
