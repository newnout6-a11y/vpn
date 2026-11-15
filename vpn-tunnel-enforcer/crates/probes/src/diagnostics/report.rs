//! The full health-check report (old "Health check"): every group read in parallel, items in the
//! old order, warn / fail findings logged at info level (report data, not a new app fault), and
//! the summary rule of [`summarize`](super::summarize).
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, now_ms};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::paths::DataDirs;
use vpnte_core::settings::{ConnectionMode, Settings};
use vpnte_winnet::adapters::{self, Adapter, Family, Route};

use super::checks::{self, ProxyState};
pub use super::checks::{Hy2Facts, ProfileFacts};
use super::listeners::{CLIENT_PROCESS, proxy_listeners};
use super::sysinfo::{self, OsInfo, ProcessRow, ServiceRow};
use super::{CheckItem, SystemReport, endpoints, summarize};
use crate::local_proxy::{ListenerRow, LocalProxy, SystemProxy, listener_rows};

/// The tunnel as the runtime reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelFacts {
    pub running: bool,
    /// What the TUN forwards to (`127.0.0.1:10808 (socks5)` or the profile's protocol).
    pub upstream: Option<String>,
    /// LUID of our TUN while it runs.
    pub luid: Option<u64>,
}

/// What the report needs from the app besides the machine itself.
#[derive(Debug, Clone)]
pub struct ReportInputs {
    pub app_version: String,
    pub dirs: DataDirs,
    pub settings: Settings,
    pub tunnel: TunnelFacts,
    /// The proxy Hard mode would use (a probed override or the detector's result).
    pub proxy: Option<LocalProxy>,
    /// Lines of the current engine log session, oldest first.
    pub engine_log: Vec<String>,
    pub profile: Option<ProfileFacts>,
    /// Leak-check items, copied into the Routing group (a failure there is critical).
    pub routing: Vec<CheckItem>,
    /// Items owned by other crates (rule sets, traffic capture), appended as given.
    pub extra: Vec<CheckItem>,
    /// The app's own processes (engines): never listed as a client.
    pub own_pids: Vec<u32>,
}

/// Engine files that must ship next to the app.
pub const ENGINE_FILES: [&str; 4] = ["sing-box.exe", "xray.exe", "wintun.dll", "libcronet.dll"];
/// Name the DNS check resolves.
pub const DNS_PROBE_HOST: &str = "example.com";
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Machine state read on a blocking thread.
struct Machine {
    os: OsInfo,
    elevated: bool,
    adapters: Result<Vec<Adapter>, String>,
    routes: Result<Vec<Route>, String>,
    listeners: Vec<ListenerRow>,
    processes: Vec<ProcessRow>,
    core_services: Vec<ServiceRow>,
    other_services: Vec<ServiceRow>,
    system_proxy: SystemProxy,
    external_tunnel: bool,
    best_via_tun: Option<bool>,
}

fn read_machine(tun_luid: Option<u64>) -> Machine {
    let routes = adapters::routes(Family::V4)
        .map_err(|e| e.to_string())
        .map(|mut v4| {
            v4.extend(adapters::routes(Family::V6).unwrap_or_default());
            v4
        });
    let aliases = adapters::alias::all_aliases();
    let own: Vec<&str> = aliases.iter().map(String::as_str).collect();
    let external_tunnel =
        adapters::foreign_tun::detect(tun_luid, &own).is_ok_and(|f| !f.is_empty());
    let best_via_tun = tun_luid.map(|luid| {
        adapters::best_route(IpAddr::from([1, 1, 1, 1])).is_ok_and(|best| best.luid == luid)
    });
    Machine {
        os: sysinfo::os_info(),
        elevated: vpnte_winnet::elevation::is_elevated(),
        adapters: adapters::inventory().map_err(|e| e.to_string()),
        routes,
        listeners: listener_rows().unwrap_or_default(),
        processes: sysinfo::processes().unwrap_or_default(),
        core_services: checks::CORE_SERVICES
            .iter()
            .map(|s| sysinfo::service(s))
            .collect(),
        other_services: checks::OTHER_SERVICES
            .iter()
            .map(|s| sysinfo::service(s))
            .collect(),
        system_proxy: SystemProxy::read(),
        external_tunnel,
        best_via_tun,
    }
}

async fn resolve_probe() -> Result<Vec<IpAddr>, String> {
    let lookup = tokio::net::lookup_host((DNS_PROBE_HOST, 443));
    let addrs = tokio::time::timeout(DNS_TIMEOUT, lookup)
        .await
        .map_err(|_| "timeout".to_owned())?
        .map_err(|e| e.to_string())?;
    let mut ips: Vec<IpAddr> = Vec::new();
    for ip in addrs.map(|a| a.ip()) {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// `<engine> version` through the engine crate, so an elevated app checks the release pins first
/// like for every other engine run. A refusal or failure is shown as such, never as "not run".
async fn engine_version(engine: Engine, exe: &Path) -> String {
    let version = match engine {
        Engine::SingBox => vpnte_engine::singbox_process::engine_version(exe).await,
        Engine::Xray => vpnte_engine::xray_process::engine_version(exe).await,
        #[cfg(feature = "lab")]
        Engine::Mihomo => vpnte_engine::mihomo_process::engine_version(exe).await,
    };
    match version {
        Ok((major, minor, patch)) => format!("{major}.{minor}.{patch}"),
        Err(err) => format!("failed ({err})"),
    }
}

pub(super) async fn binaries(resources: &Path) -> CheckItem {
    let files: Vec<(&str, Option<u64>)> = ENGINE_FILES
        .iter()
        .map(|name| {
            (
                *name,
                std::fs::metadata(resources.join(name))
                    .ok()
                    .filter(|m| m.is_file())
                    .map(|m| m.len()),
            )
        })
        .collect();
    let mut versions = Vec::new();
    for (exe, engine) in [
        ("sing-box.exe", Engine::SingBox),
        ("xray.exe", Engine::Xray),
    ] {
        let path = resources.join(exe);
        let version = match path.is_file() {
            true => Some(engine_version(engine, &path).await),
            false => None,
        };
        versions.push((exe, version));
    }
    checks::binaries_item(&files, &versions)
}

async fn tcp_open(addr: SocketAddr) -> bool {
    matches!(
        tokio::time::timeout(PROXY_PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await,
        Ok(Ok(_))
    )
}

/// Settings keys shown in `runtime-settings` (never `logKey` or the proxy credentials).
const SETTINGS_ROWS: [&str; 12] = [
    "routingMode",
    "killSwitch",
    "proxyEngine",
    "autopilot",
    "smartRuSplit",
    "smartRuMapsDirect",
    "publicWifiCompatibility",
    "stealthMode",
    "adaptiveBypass",
    "disableGeoLookup",
    "deepInspection",
    "autoRestartOnCrash",
];

pub(super) fn settings_item(settings: &Settings) -> CheckItem {
    let json = serde_json::to_value(settings).unwrap_or_default();
    let field = |k: &str| match json.get(k) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "-".to_owned(),
    };
    let mut rows: Vec<String> = SETTINGS_ROWS
        .iter()
        .map(|k| format!("{k}={}", field(k)))
        .collect();
    rows.push(format!(
        "proxyOverride={}",
        if settings.proxy_override.is_some() {
            "set"
        } else {
            "none"
        }
    ));
    let value = Msg::new("probes.diag.settings.value")
        .arg("mode", field("connectionMode"))
        .arg("proxyType", field("proxyType"))
        .arg("bootstrap", field("bootstrapRouteMode"))
        .arg("interval", settings.check_interval_ms);
    checks::settings_item(value, rows)
}

fn alias_lookup(adapters: &Result<Vec<Adapter>, String>) -> impl Fn(u64) -> String + '_ {
    move |luid| {
        adapters
            .as_ref()
            .ok()
            .and_then(|list| list.iter().find(|a| a.luid == luid))
            .map_or_else(|| format!("luid {luid:#x}"), |a| a.alias.clone())
    }
}

/// Runs the report. Cancellation wins at any point; nothing is logged as completed then.
pub async fn system_report(
    inputs: ReportInputs,
    cancel: CancellationToken,
) -> AppResult<SystemReport> {
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    tracing::info!("full system diagnostics started");
    let work = async {
        let luid = inputs.tunnel.luid;
        let machine = tokio::task::spawn_blocking(move || read_machine(luid));
        let proxy_open = async {
            match &inputs.proxy {
                Some(p) => Some(tcp_open(p.addr).await),
                None => None,
            }
        };
        let (machine, dns, endpoint_items, binaries, proxy_open) = tokio::join!(
            machine,
            resolve_probe(),
            endpoints::endpoint_items(),
            binaries(&inputs.dirs.resources),
            proxy_open
        );
        let m = machine.map_err(AppError::internal)?;
        Ok::<_, AppError>(build_items(
            &inputs,
            &m,
            dns,
            endpoint_items,
            binaries,
            proxy_open,
        ))
    };
    let items = tokio::select! {
        _ = cancel.cancelled() => return Err(AppError::cancelled()),
        items = work => items?,
    };
    let summary = summarize(&items);
    for f in checks::findings(&items) {
        tracing::info!(check = %f.check, status = ?f.status, value = %f.value, details = %f.details, "system diagnostic finding");
    }
    tracing::info!(summary = ?summary, items = items.len(), "full system diagnostics finished");
    Ok(SystemReport {
        ran_at: now_ms(),
        summary,
        items,
    })
}

fn build_items(
    inputs: &ReportInputs,
    m: &Machine,
    dns: Result<Vec<IpAddr>, String>,
    endpoint_items: Vec<CheckItem>,
    binaries: CheckItem,
    proxy_open: Option<bool>,
) -> Vec<CheckItem> {
    let direct_vpn = inputs.settings.connection_mode == ConnectionMode::DirectVpn;
    let mut skip = inputs.own_pids.clone();
    skip.push(std::process::id());
    let listeners = proxy_listeners(&m.listeners, &skip);
    let clients: Vec<ProcessRow> = m
        .processes
        .iter()
        .filter(|p| !skip.contains(&p.pid) && CLIENT_PROCESS.is_match(&p.name))
        .cloned()
        .collect();
    let proxy_state = match (&inputs.proxy, proxy_open) {
        _ if direct_vpn => ProxyState::DirectVpn(inputs.tunnel.running),
        (Some(p), Some(open)) => ProxyState::Probed {
            addr: p.label(),
            open,
        },
        _ => ProxyState::Missing {
            external_tunnel: m.external_tunnel,
            listeners: listeners.len(),
        },
    };
    let dirs = [
        ("dataDir", inputs.dirs.root.display().to_string()),
        ("logDir", inputs.dirs.logs.display().to_string()),
        ("resources", inputs.dirs.resources.display().to_string()),
    ];

    let mut items = vec![
        checks::app_item(&m.os, &inputs.app_version, m.elevated, &dirs),
        settings_item(&inputs.settings),
        checks::tun_item(inputs.tunnel.running, inputs.tunnel.upstream.as_deref()),
        binaries,
        checks::proxy_item(&proxy_state, checks::system_proxy_rows(&m.system_proxy)),
    ];
    items.extend(checks::adapter_items(&m.adapters));
    items.push(checks::routes_item(
        &m.routes,
        alias_lookup(&m.adapters),
        inputs.tunnel.luid,
        m.best_via_tun,
    ));
    items.push(checks::dns_item(&dns));
    items.extend(checks::client_items(&listeners, &clients, direct_vpn));
    items.extend(endpoint_items);
    items.extend(checks::service_items(&m.core_services, &m.other_services));
    items.push(checks::app_log_item(
        &vpnte_core::logging::recent_problems(),
        now_ms(),
    ));
    items.push(checks::tun_log_item(
        &inputs.engine_log,
        inputs.tunnel.running,
    ));
    items.extend(inputs.routing.iter().cloned().map(|mut i| {
        i.id = format!("routing-{}", i.id);
        i.category = super::Category::Routing;
        i
    }));
    items.push(checks::profile_item(inputs.profile.as_ref()));
    items.extend(inputs.extra.iter().cloned());
    items
}
