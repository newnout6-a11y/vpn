//! The live session and the history rows that end it (lifecycle-app §3.5).
use std::time::Instant;

use vpnte_base::types::{AdaptiveMode, Owner, ProxyKind, UnixMs, now_ms};
use vpnte_core::ops::{CorrelationId, Source};

use super::SessionView;
use crate::api::{EngineRun, VpnProfile};
use crate::history::{History, NewEntry, Route, SessionMode};
use crate::outcome::{AdaptiveContext, Evidence, NetworkTransition, SessionOutcome};

/// Which profile a session runs: what history stores and what decides "same session".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SessionProfile {
    /// Server-list id or a synthetic id (L-04: never the display name).
    pub id: String,
    pub name: String,
    pub mode: SessionMode,
}

impl SessionProfile {
    /// Hard TUN through a local proxy. The name is data (the old rows' format) and names the
    /// upstream only: the history row's mode carries the mode name («Туннель» / «Прокси»).
    pub fn local_proxy(addr: &str) -> Self {
        Self {
            id: "local-proxy".into(),
            name: format!("Proxy {addr}"),
            mode: SessionMode::Hard,
        }
    }

    /// Soft mode: one id per proxy protocol, the address in the name (a changed address or
    /// protocol is a new session).
    pub fn soft(addr: &str, kind: ProxyKind) -> Self {
        let kind = match kind {
            ProxyKind::Socks5 => "socks5",
            ProxyKind::Http => "http",
        };
        Self {
            id: format!("local-proxy-soft-{kind}"),
            mode: SessionMode::Soft,
            ..Self::local_proxy(addr)
        }
    }

    /// A server of the server list.
    pub fn direct(server: &VpnProfile) -> Self {
        let name = server.profile.name.trim();
        Self {
            id: server.id.clone(),
            name: if name.is_empty() {
                "Direct VPN".into()
            } else {
                name.to_owned()
            },
            mode: SessionMode::Direct,
        }
    }

    /// Soft mode over a server of the server list (its id: switching servers splits sessions).
    pub fn soft_server(server: &VpnProfile) -> Self {
        Self {
            mode: SessionMode::Soft,
            ..Self::direct(server)
        }
    }

    /// A Direct VPN start that failed before a server was known.
    pub fn direct_unknown() -> Self {
        Self {
            id: "direct-vpn".into(),
            name: "Direct VPN".into(),
            mode: SessionMode::Direct,
        }
    }
}

/// Who and what a lane operation is about (provenance of the rows it writes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Provenance {
    pub owner: Owner,
    pub source: Source,
    pub correlation: CorrelationId,
}

/// A session that is up. Nothing is written while it lives; exactly one row ends it.
#[derive(Debug, Clone)]
pub(super) struct LiveSession {
    pub profile: SessionProfile,
    /// Who holds the session; restarts and switches keep it.
    pub holder: Owner,
    /// Provenance: the operation that opened it (`None`: the runtime brought it back alone).
    pub owner: Option<Owner>,
    pub source: Source,
    pub correlation: Option<CorrelationId>,
    pub started_at: UnixMs,
    pub started: Instant,
    pub generation: Option<u64>,
    pub adaptive: AdaptiveMode,
    /// The engine of the current run and why it was chosen.
    pub engine: Option<EngineRun>,
    /// Server country (egress evidence).
    pub country: Option<String>,
    pub leak_detected: bool,
    pub transition: Option<NetworkTransition>,
    /// The runtime reported the upstream down and it has not recovered since.
    pub proxy_down: bool,
}

impl LiveSession {
    /// A session opened by `by` (or by the runtime alone when `None`).
    pub fn open(profile: SessionProfile, by: Option<&Provenance>, holder: Owner) -> Self {
        Self {
            profile,
            holder,
            owner: by.map(|p| p.owner),
            source: by.map_or(Source::Runtime, |p| p.source),
            correlation: by.map(|p| p.correlation.clone()),
            started_at: now_ms(),
            started: Instant::now(),
            generation: None,
            adaptive: AdaptiveMode::Baseline,
            engine: None,
            country: None,
            leak_detected: false,
            transition: None,
            proxy_down: false,
        }
    }

    pub fn view(&self) -> SessionView {
        SessionView {
            owner: self.holder,
            profile_id: self.profile.id.clone(),
            profile_name: self.profile.name.clone(),
            mode: self.profile.mode,
            generation: self.generation,
            adaptive: self.adaptive,
            started_at: self.started_at,
            engine: self.engine,
        }
    }

    pub fn is_soft(&self) -> bool {
        self.profile.mode == SessionMode::Soft
    }

    /// Egress facts every outcome carries (old `egressEvidence`).
    pub fn egress(&self, egress_ip: Option<String>) -> Evidence {
        Evidence {
            egress_ip,
            egress_country: self.country.clone(),
            proxy_engine: self.engine.map(|run| run.kind),
            ..Evidence::default()
        }
    }

    /// Everything the session knows, for an unexpected end.
    pub fn facts(&self, egress_ip: Option<String>) -> Evidence {
        Evidence {
            // Soft sessions run the engine too, adaptive mode included.
            adaptive_mode: Some(AdaptiveContext::from(self.adaptive)),
            leak_detected_during_session: Some(self.leak_detected),
            network_transition: self.transition.clone(),
            ..self.egress(egress_ip)
        }
    }

    /// The row that ends this session now.
    pub fn row(&self, outcome: SessionOutcome, (down, up): (u64, u64)) -> NewEntry {
        let duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        NewEntry {
            correlation_id: self.correlation.clone(),
            source: self.source,
            owner: self.owner,
            route: if self.is_soft() {
                Route::SoftEnv
            } else {
                Route::Tun
            },
            started_at: self.started_at,
            // Wall clock for the end (a calendar correction shows), monotonic for the duration.
            ended_at: now_ms(),
            duration_ms,
            profile_name: self.profile.name.clone(),
            profile_id: self.profile.id.clone(),
            mode: self.profile.mode,
            bytes_down: down,
            bytes_up: up,
            outcome,
        }
    }
}

/// Zero-duration row of a start that never brought protection up.
pub(super) fn start_failure_row(
    profile: &SessionProfile,
    by: &Provenance,
    outcome: SessionOutcome,
) -> NewEntry {
    let now = now_ms();
    NewEntry {
        correlation_id: Some(by.correlation.clone()),
        source: by.source,
        owner: Some(by.owner),
        route: Route::Unconfirmed,
        started_at: now,
        ended_at: now,
        duration_ms: 0,
        profile_name: profile.name.clone(),
        profile_id: profile.id.clone(),
        mode: profile.mode,
        bytes_down: 0,
        bytes_up: 0,
        outcome,
    }
}

/// Writes a row off the actor's thread; a failure is only logged (the session is gone anyway).
pub(super) async fn write(history: &History, row: NewEntry) {
    let history = history.clone();
    let kind = row.outcome.kind;
    match tokio::task::spawn_blocking(move || history.add(row)).await {
        Ok(Ok(_)) => tracing::debug!(outcome = kind.as_str(), "connection history row written"),
        Ok(Err(e)) => tracing::warn!(error = %e, "failed to record connection history"),
        Err(e) => tracing::warn!(error = %e, "connection history writer failed"),
    }
}
