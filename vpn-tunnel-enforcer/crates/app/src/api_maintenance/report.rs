//! «Проверить»: the probes' system report (monitoring §3.7) with what only the app knows — the
//! tunnel, our engines' ports and pids, the engine log, the active profile, the local proxy a
//! local-proxy session would use and, while a session is up, the leak check's items in the
//! Routing group. Nothing here needs elevation; nothing changes system state.
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_core::logging::{self, LogFile};
use vpnte_core::settings::{ConnectionMode, Settings};
use vpnte_probes::diagnostics::{
    self, Category, CheckItem, ProfileFacts, ReportInputs, TunnelFacts,
};
use vpnte_probes::local_proxy::{self, LocalProxy, ScanOptions};
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::maintenance::{DiagCategory, DiagItem, SystemReport, TunnelPhase};

use super::{Shared, project};
use crate::services::TunnelOps;

/// Bytes of the engine log handed to the report (its log item reads the last lines).
const ENGINE_LOG_BYTES: usize = 64 * 1024;

/// Runs the report; cancellation wins at any point.
pub(crate) async fn run(shared: &Shared, cancel: CancellationToken) -> AppResult<SystemReport> {
    let backend = &shared.backend;
    let tunnel = backend.tunnel()?.clone();
    let settings = backend.settings.snapshot();
    let status = tunnel.runtime_status().borrow().clone();
    let session_up = project::live_phase(shared) == TunnelPhase::On;
    let (proxy, routing, local) = tokio::join!(
        local_proxy(&settings, &status),
        routing_items(tunnel.as_ref(), session_up, cancel.clone()),
        read_local(
            backend.dirs.logs.clone(),
            backend.servers.clone(),
            settings.connection_mode
        ),
    );
    let (engine_log, profile) = local;
    let tun = status.running && status.capture == Some(CaptureKind::Tun);
    let inputs = ReportInputs {
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        dirs: backend.dirs.clone(),
        settings,
        tunnel: TunnelFacts {
            running: tun,
            upstream: upstream(&status),
            luid: status
                .session
                .as_ref()
                .and_then(|s| s.tun_luid)
                .filter(|_| tun),
        },
        proxy,
        engine_log,
        profile,
        routing,
        extra: Vec::new(),
        own_pids: status.pid.into_iter().collect(),
    };
    let report = diagnostics::system_report(inputs, cancel).await?;
    *shared.last_report.lock() = serde_json::to_value(&report).ok();
    // A fresh run may have logged a new fault.
    shared.touch();
    Ok(to_view(report))
}

/// What the tunnel forwards to: `127.0.0.1:10808 (socks5)`, else the profile's protocol.
fn upstream(status: &TunStatus) -> Option<String> {
    match (&status.proxy_addr, status.proxy_type) {
        (Some(addr), Some(kind)) => Some(format!("{addr} ({})", kind_label(kind))),
        (Some(addr), None) => Some(addr.clone()),
        _ => status.protocol.clone(),
    }
}

fn kind_label(kind: vpnte_base::types::ProxyKind) -> &'static str {
    match kind {
        vpnte_base::types::ProxyKind::Socks5 => "socks5",
        vpnte_base::types::ProxyKind::Http => "http",
    }
}

/// In local-proxy mode: the proxy a session would use, found the way the wizard finds it
/// (our own engine's ports and process are never taken for it).
async fn local_proxy(settings: &Settings, status: &TunStatus) -> Option<LocalProxy> {
    if settings.connection_mode != ConnectionMode::LocalProxy {
        return None;
    }
    let mut skip_ports = Vec::new();
    if let Some(s) = &status.session {
        skip_ports.extend([s.clash_port, s.direct.port]);
        skip_ports.extend(s.probe.as_ref().map(|p| p.port));
        skip_ports.extend(s.proxy_port);
    }
    local_proxy::scan(ScanOptions {
        skip_ports,
        skip_pids: status.pid.into_iter().collect(),
    })
    .await
}

/// The leak check's items (Routing group) while a session is up; nothing otherwise.
async fn routing_items(
    tunnel: &dyn TunnelOps,
    session_up: bool,
    cancel: CancellationToken,
) -> Vec<CheckItem> {
    if !session_up {
        return Vec::new();
    }
    match tunnel.leak_check(cancel).await {
        Ok(report) => report
            .items
            .into_iter()
            .map(|item| CheckItem {
                id: item.id.to_owned(),
                category: Category::Routing,
                label: item.label,
                verdict: item.status.verdict(),
                value: item.value,
                details: Vec::new(),
                notes: item.details,
            })
            .collect(),
        Err(err) => {
            tracing::info!(error = %err, "maintenance: leak check not part of the report");
            Vec::new()
        }
    }
}

/// The engine log tail and the active profile's facts, read on a blocking thread (file read,
/// DPAPI to open the stored profile).
async fn read_local(
    logs: std::path::PathBuf,
    servers: Arc<Servers>,
    mode: ConnectionMode,
) -> (Vec<String>, Option<ProfileFacts>) {
    tokio::task::spawn_blocking(move || {
        let log = logging::tail(&logs, &LogFile::engine("sing-box"), ENGINE_LOG_BYTES)
            .map(|snap| snap.content.lines().map(str::to_owned).collect())
            .unwrap_or_default();
        // Local-proxy sessions use the other client's server, not one of ours.
        let profile = (mode == ConnectionMode::DirectVpn)
            .then(|| profile_facts(&servers))
            .flatten();
        (log, profile)
    })
    .await
    .unwrap_or_default()
}

/// The facts of the server a direct session would use; `None` without one (or when its key
/// cannot be opened on this account).
fn profile_facts(servers: &Servers) -> Option<ProfileFacts> {
    let active = servers.active()?;
    let profile = active.row.profile().ok()?;
    let caps = vpnte_profiles::caps::capabilities(&profile);
    Some(ProfileFacts {
        name: active.row.name.clone(),
        protocol: caps.protocol.to_owned(),
        stealth: format!("{:?}", caps.stealth).to_lowercase(),
        tls: caps.tls,
        ech: caps.ech,
        hy2: None,
        warnings: caps.notes,
    })
}

/// The page's view of a finished report (same rows, same order).
pub(crate) fn to_view(report: diagnostics::SystemReport) -> SystemReport {
    SystemReport {
        ran_at: report.ran_at,
        items: report
            .items
            .into_iter()
            .map(|i| DiagItem {
                id: i.id,
                category: category(i.category),
                label: i.label,
                verdict: i.verdict,
                value: i.value,
                details: i.details,
                notes: i.notes,
            })
            .collect(),
    }
}

fn category(c: Category) -> DiagCategory {
    match c {
        Category::App => DiagCategory::App,
        Category::Tun => DiagCategory::Tun,
        Category::Proxy => DiagCategory::Proxy,
        Category::Network => DiagCategory::Network,
        Category::Internet => DiagCategory::Internet,
        Category::Windows => DiagCategory::Windows,
        Category::Logs => DiagCategory::Logs,
        Category::Routing => DiagCategory::Routing,
        Category::Profile => DiagCategory::Profile,
    }
}
