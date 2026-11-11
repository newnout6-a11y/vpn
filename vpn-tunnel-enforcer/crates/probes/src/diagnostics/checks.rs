//! Pure builders of the report items from plain data (the OS reads happen in `report.rs`).
use std::net::IpAddr;
use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::Msg;
use vpnte_base::types::Verdict;
use vpnte_winnet::adapters::{Adapter, AdapterStatus, Route};

use super::sysinfo::{OsInfo, ProcessRow, ServiceRow, ServiceStart};
use super::{Category, CheckItem};
use crate::local_proxy::SystemProxy;

static USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]*@").expect("static regex"));

/// A proxy URL without its `user:password@` part: credentials never reach the report.
pub fn strip_userinfo(url: &str) -> String {
    USERINFO.replace_all(url, "$1").into_owned()
}

/// `runtime-app`: OS, architecture, app version, elevation and directories.
pub fn app_item(os: &OsInfo, version: &str, elevated: bool, dirs: &[(&str, String)]) -> CheckItem {
    let os_label = match (&os.product, &os.build) {
        (Some(p), Some(b)) => format!("{p} ({b})"),
        (Some(p), None) => p.clone(),
        (None, Some(b)) => format!("Windows ({b})"),
        (None, None) => "Windows".to_owned(),
    };
    let mut rows = vec![format!("elevated={elevated}")];
    rows.extend(dirs.iter().map(|(k, v)| format!("{k}={v}")));
    let value = Msg::new("probes.diag.app.value")
        .arg("os", os_label)
        .arg("arch", os.arch)
        .arg("version", version);
    CheckItem::new(
        "runtime-app",
        Category::App,
        "probes.diag.app.label",
        None,
        value,
    )
    .details(rows, 12)
}

/// `runtime-settings`: the settings that shape routing, as `key=value` rows.
pub fn settings_item(summary: Msg, rows: Vec<String>) -> CheckItem {
    CheckItem::new(
        "runtime-settings",
        Category::App,
        "probes.diag.settings.label",
        None,
        summary,
    )
    .details(rows, 24)
}

/// `runtime-tun-status`: `Ok` while our TUN runs, informational when it is stopped.
pub fn tun_item(running: bool, upstream: Option<&str>) -> CheckItem {
    let (verdict, value) = match running {
        true => (
            Some(Verdict::Ok),
            Msg::new("probes.diag.tun.running").arg("upstream", upstream.unwrap_or("-")),
        ),
        false => (None, Msg::new("probes.diag.tun.stopped")),
    };
    CheckItem::new(
        "runtime-tun-status",
        Category::Tun,
        "probes.diag.tun.label",
        verdict,
        value,
    )
}

/// `binaries`: every bundled engine file present (sizes) plus the engines' own version lines.
pub fn binaries_item(
    files: &[(&str, Option<u64>)],
    versions: &[(&str, Option<String>)],
) -> CheckItem {
    let missing: Vec<&str> = files
        .iter()
        .filter(|(_, s)| s.is_none())
        .map(|(n, _)| *n)
        .collect();
    let mut rows: Vec<String> = files
        .iter()
        .map(|(name, size)| match size {
            Some(bytes) => format!("{name}: {} KB", bytes.div_ceil(1024)),
            None => format!("{name}: missing"),
        })
        .collect();
    rows.extend(
        versions
            .iter()
            .map(|(name, v)| format!("{name} version: {}", v.as_deref().unwrap_or("not run"))),
    );
    let (verdict, value) = match missing.is_empty() {
        true => (Verdict::Ok, Msg::new("probes.diag.binaries.present")),
        false => (
            Verdict::Fail,
            Msg::new("probes.diag.binaries.missing").arg("files", missing.join(", ")),
        ),
    };
    CheckItem::new(
        "binaries",
        Category::Tun,
        "probes.diag.binaries.label",
        Some(verdict),
        value,
    )
    .details(rows, 8)
}

/// Where the proxy for Hard mode stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyState {
    /// Direct VPN mode: no local proxy is used (`true` while connected).
    DirectVpn(bool),
    /// Local-proxy mode without a proxy: another VPN's tunnel is up / listeners exist / nothing.
    Missing {
        external_tunnel: bool,
        listeners: usize,
    },
    /// The proxy and whether it accepted a TCP connection.
    Probed { addr: String, open: bool },
}

/// System proxy settings as report rows (credentials stripped).
pub fn system_proxy_rows(sp: &SystemProxy) -> Vec<String> {
    let mut rows: Vec<String> = sp
        .env
        .iter()
        .map(|(k, v)| format!("env:{k}={}", strip_userinfo(v)))
        .collect();
    rows.push(match &sp.winhttp {
        Some(Some(p)) => format!("winhttp={}", strip_userinfo(p)),
        Some(None) => "winhttp=direct".to_owned(),
        None => "winhttp=unreadable".to_owned(),
    });
    match &sp.wininet {
        Some(w) => {
            let flag = |b: Option<bool>| b.map_or("-".to_owned(), |b| (b as u8).to_string());
            rows.push(format!(
                "wininet ProxyEnable={} AutoDetect={}",
                flag(w.proxy_enable),
                flag(w.auto_detect)
            ));
            if let Some(s) = &w.proxy_server {
                rows.push(format!("wininet ProxyServer={}", strip_userinfo(s)));
            }
            if let Some(s) = &w.auto_config_url {
                rows.push(format!("wininet AutoConfigURL={}", strip_userinfo(s)));
            }
        }
        None => rows.push("wininet=unreadable".to_owned()),
    }
    rows
}

/// `proxy-current`: the local proxy Hard mode uses (B: never a warning in Direct VPN mode).
pub fn proxy_item(state: &ProxyState, rows: Vec<String>) -> CheckItem {
    let (verdict, value) = match state {
        ProxyState::DirectVpn(true) => (None, Msg::new("probes.diag.proxy.directVpnUnused")),
        ProxyState::DirectVpn(false) => (None, Msg::new("probes.diag.proxy.directVpnIdle")),
        ProxyState::Missing {
            external_tunnel: true,
            ..
        } => (None, Msg::new("probes.diag.proxy.externalTunnel")),
        ProxyState::Missing { listeners, .. } if *listeners > 0 => (
            Some(Verdict::Warn),
            Msg::new("probes.diag.proxy.notSelected").arg("count", listeners),
        ),
        ProxyState::Missing { .. } => (
            Some(Verdict::Warn),
            Msg::new("probes.diag.proxy.notConfigured"),
        ),
        ProxyState::Probed { addr, open: true } => (
            Some(Verdict::Ok),
            Msg::new("probes.diag.proxy.open").arg("addr", addr),
        ),
        ProxyState::Probed { addr, open: false } => (
            Some(Verdict::Fail),
            Msg::new("probes.diag.proxy.closed").arg("addr", addr),
        ),
    };
    CheckItem::new(
        "proxy-current",
        Category::Proxy,
        "probes.diag.proxy.label",
        verdict,
        value,
    )
    .details(rows, 18)
}

fn speed(bps: u64) -> String {
    match bps {
        0 => "-".to_owned(),
        b if b >= 1_000_000_000 => format!("{} Gbps", b / 1_000_000_000),
        b if b >= 1_000_000 => format!("{} Mbps", b / 1_000_000),
        b => format!("{} Kbps", b / 1_000),
    }
}

fn status_word(s: &AdapterStatus) -> &'static str {
    match s {
        AdapterStatus::Up => "Up",
        AdapterStatus::Disconnected => "Disconnected",
        AdapterStatus::NotPresent => "NotPresent",
        AdapterStatus::Disabled => "Disabled",
    }
}

fn join_ips<T: ToString>(ips: impl IntoIterator<Item = T>) -> String {
    ips.into_iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// `adapters` and `ip-config` from the adapter inventory (the visible ones, as `Get-NetAdapter`).
pub fn adapter_items(inventory: &Result<Vec<Adapter>, String>) -> [CheckItem; 2] {
    let list = match inventory {
        Ok(list) => list,
        Err(e) => {
            let failed = |id, label| {
                CheckItem::new(
                    id,
                    Category::Network,
                    label,
                    Some(Verdict::Fail),
                    Msg::new("probes.diag.readFailed"),
                )
                .details(vec![e.clone()], 1)
            };
            return [
                failed("adapters", "probes.diag.adapters.label"),
                failed("ip-config", "probes.diag.ipConfig.label"),
            ];
        }
    };
    let visible: Vec<&Adapter> = list.iter().filter(|a| a.is_visible()).collect();
    let up: Vec<&&Adapter> = visible.iter().filter(|a| a.is_up()).collect();
    let rows = visible
        .iter()
        .map(|a| {
            format!(
                "{}:{}:{}:{}",
                a.alias,
                status_word(&a.status),
                a.description,
                speed(a.link_speed_bps)
            )
        })
        .collect();
    let adapters = CheckItem::new(
        "adapters",
        Category::Network,
        "probes.diag.adapters.label",
        Some(if up.is_empty() {
            Verdict::Fail
        } else {
            Verdict::Ok
        }),
        Msg::new("probes.diag.adapters.value")
            .arg("up", up.len())
            .arg("total", visible.len()),
    )
    .details(rows, 18);
    let configured: Vec<String> = up
        .iter()
        .filter(|a| !a.addresses.is_empty() || !a.gateways.is_empty() || !a.dns.is_empty())
        .map(|a| {
            let v4 = join_ips(a.addresses.iter().filter(|u| u.ip.is_ipv4()).map(|u| u.ip));
            let v6 = join_ips(a.addresses.iter().filter(|u| u.ip.is_ipv6()).map(|u| u.ip));
            format!(
                "{}: IPv4={v4} IPv6={v6} Gateway={} DNS={}",
                a.alias,
                join_ips(&a.gateways),
                join_ips(&a.dns)
            )
        })
        .collect();
    let ip_config = CheckItem::new(
        "ip-config",
        Category::Network,
        "probes.diag.ipConfig.label",
        Some(if configured.is_empty() {
            Verdict::Warn
        } else {
            Verdict::Ok
        }),
        Msg::new("probes.diag.ipConfig.value").arg("count", configured.len()),
    )
    .details(configured, 12);
    [adapters, ip_config]
}

/// Prefixes that capture all traffic (default and half-default routes).
pub const CAPTURE_PREFIXES: [&str; 6] = [
    "0.0.0.0/0",
    "::/0",
    "0.0.0.0/1",
    "128.0.0.0/1",
    "::/1",
    "8000::/1",
];

/// `routes`: default / half-default routes. While our TUN runs they (or the best route to the
/// Internet) must go through it; a TUN without them is a warning, not "fine".
pub fn routes_item(
    routes: &Result<Vec<Route>, String>,
    alias_of: impl Fn(u64) -> String,
    tun_luid: Option<u64>,
    best_via_tun: Option<bool>,
) -> CheckItem {
    let routes = match routes {
        Ok(r) => r,
        Err(e) => {
            return CheckItem::new(
                "routes",
                Category::Network,
                "probes.diag.routes.label",
                Some(Verdict::Fail),
                Msg::new("probes.diag.readFailed"),
            )
            .details(vec![e.clone()], 1);
        }
    };
    let capture: Vec<&Route> = routes
        .iter()
        .filter(|r| CAPTURE_PREFIXES.contains(&r.destination.to_string().as_str()))
        .collect();
    let rows = capture
        .iter()
        .map(|r| {
            let hop = r.next_hop.map_or("on-link".to_owned(), |h| h.to_string());
            format!(
                "{} -> {} {hop} metric={}",
                r.destination,
                alias_of(r.luid),
                r.metric
            )
        })
        .collect();
    let via_tun = tun_luid.is_some_and(|luid| capture.iter().any(|r| r.luid == luid))
        || best_via_tun == Some(true);
    let (verdict, value) = match (tun_luid.is_some(), via_tun) {
        (true, true) => (Some(Verdict::Ok), Msg::new("probes.diag.routes.viaTun")),
        (true, false) => (
            Some(Verdict::Warn),
            Msg::new("probes.diag.routes.notViaTun"),
        ),
        (false, _) => (
            None,
            Msg::new("probes.diag.routes.count").arg("count", capture.len()),
        ),
    };
    CheckItem::new(
        "routes",
        Category::Network,
        "probes.diag.routes.label",
        verdict,
        value,
    )
    .details(rows, 18)
}

/// `dns-resolve`: the OS resolver answers for `example.com` (A and AAAA count independently).
pub fn dns_item(answer: &Result<Vec<IpAddr>, String>) -> CheckItem {
    let (verdict, value, rows) = match answer {
        Ok(ips) if !ips.is_empty() => (
            Verdict::Ok,
            Msg::new("probes.diag.dns.records").arg("count", ips.len()),
            ips.iter()
                .map(|ip| format!("{} {ip}", if ip.is_ipv4() { "A" } else { "AAAA" }))
                .collect(),
        ),
        Ok(_) => (Verdict::Fail, Msg::new("probes.diag.dns.empty"), Vec::new()),
        Err(e) => (
            Verdict::Fail,
            Msg::new("probes.diag.dns.failed"),
            vec![e.clone()],
        ),
    };
    CheckItem::new(
        "dns-resolve",
        Category::Network,
        "probes.diag.dns.label",
        Some(verdict),
        value,
    )
    .details(rows, 8)
}

/// `proxy-listeners` / `proxy-processes`: clients found on this machine. Expected in local-proxy
/// mode (none = warning); informational in Direct VPN mode, where none is normal.
pub fn client_items(
    listeners: &[super::plan::ListenerInfo],
    processes: &[ProcessRow],
    direct_vpn: bool,
) -> [CheckItem; 2] {
    let judge = |n: usize| match (direct_vpn, n) {
        (true, _) => None,
        (false, 0) => Some(Verdict::Warn),
        (false, _) => Some(Verdict::Ok),
    };
    let l_rows = listeners
        .iter()
        .map(|l| format!("{}:{} pid={}", l.process, l.addr, l.pid))
        .collect();
    let p_rows = processes
        .iter()
        .map(|p| format!("{} pid={}", p.name, p.pid))
        .collect();
    [
        CheckItem::new(
            "proxy-listeners",
            Category::Proxy,
            "probes.diag.listeners.label",
            judge(listeners.len()),
            Msg::new("probes.diag.listeners.value").arg("count", listeners.len()),
        )
        .details(l_rows, 16),
        CheckItem::new(
            "proxy-processes",
            Category::Proxy,
            "probes.diag.processes.label",
            judge(processes.len()),
            Msg::new("probes.diag.processes.value").arg("count", processes.len()),
        )
        .details(p_rows, 16),
    ]
}

/// Services the kill switch, sing-box `strict_route` and name resolution depend on.
pub const CORE_SERVICES: [&str; 2] = ["BFE", "Dnscache"];
/// Other network services worth a look.
pub const OTHER_SERVICES: [&str; 5] = [
    "Dhcp",
    "iphlpsvc",
    "MpsSvc",
    "WinHttpAutoProxySvc",
    "Winmgmt",
];

fn service_row(s: &ServiceRow) -> String {
    let state = match (s.present, s.running) {
        (false, _) => "missing",
        (true, Some(true)) => "running",
        (true, Some(false)) => "stopped",
        (true, None) => "unknown",
    };
    let start = serde_json::to_value(s.start)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    format!("{}: {state}, start={start}", s.name)
}

/// `services-core` (Network, critical: BFE or Dnscache not running fails the report) and
/// `services` (Windows: a disabled or missing helper service is a warning; a stopped
/// demand-start one is normal). Windows Update / BITS / DO are not network-critical (B-SD-3).
pub fn service_items(core: &[ServiceRow], other: &[ServiceRow]) -> [CheckItem; 2] {
    let down = core
        .iter()
        .filter(|s| !s.present || s.running == Some(false))
        .count();
    let unknown = core.iter().any(|s| s.present && s.running.is_none());
    let core_verdict = match (down, unknown) {
        (0, false) => Verdict::Ok,
        (0, true) => Verdict::NotChecked,
        _ => Verdict::Fail,
    };
    let running = core.iter().filter(|s| s.running == Some(true)).count();
    let bad = other
        .iter()
        .filter(|s| !s.present || s.start == ServiceStart::Disabled)
        .count();
    [
        CheckItem::new(
            "services-core",
            Category::Network,
            "probes.diag.servicesCore.label",
            Some(core_verdict),
            Msg::new("probes.diag.servicesCore.value")
                .arg("running", running)
                .arg("total", core.len()),
        )
        .details(core.iter().map(service_row).collect(), 4),
        CheckItem::new(
            "services",
            Category::Windows,
            "probes.diag.services.label",
            Some(if bad == 0 { Verdict::Ok } else { Verdict::Warn }),
            Msg::new("probes.diag.services.value")
                .arg("bad", bad)
                .arg("total", other.len()),
        )
        .details(other.iter().map(service_row).collect(), 20),
    ]
}

static ENGINE_ERROR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(fatal|error|panic|failed|timeout|refused|denied)\b").expect("static regex")
});
static CLOSED_NOISE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bERROR\b.*connection (upload|download) closed\b.*(forcibly closed by the remote host|operation was canceled|context canceled)")
        .expect("static regex")
});

/// sing-box lines that look like errors but are routine (peer resets, cancelled streams, the
/// process lookup an unelevated run cannot do).
pub fn is_benign_engine_noise(line: &str) -> bool {
    CLOSED_NOISE.is_match(line)
        || line.contains("router: failed to search process: Access is denied")
}

/// Engine log lines that report a problem.
pub fn engine_errors<'a>(lines: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    lines
        .into_iter()
        .filter(|l| ENGINE_ERROR.is_match(l) && !is_benign_engine_noise(l))
        .collect()
}

fn last_redacted(lines: &[&str], n: usize, cut: usize) -> Vec<String> {
    let start = lines.len().saturating_sub(n);
    lines[start..]
        .iter()
        .map(|l| vpnte_core::redact::for_log(&l.chars().take(cut).collect::<String>()).into_owned())
        .collect()
}

/// `tun-log`: errors of the current engine session. A warning only while the TUN runs; with the
/// TUN stopped the lines are history and say nothing about the current route.
pub fn tun_log_item(lines: &[String], tun_running: bool) -> CheckItem {
    let errors = engine_errors(lines.iter().map(String::as_str));
    let (verdict, value) = match (tun_running, errors.len()) {
        (true, 0) => (Some(Verdict::Ok), Msg::new("probes.diag.tunLog.clean")),
        (true, n) => (
            Some(Verdict::Warn),
            Msg::new("probes.diag.tunLog.errors").arg("count", n),
        ),
        (false, n) => (
            None,
            Msg::new("probes.diag.tunLog.historical").arg("count", n),
        ),
    };
    CheckItem::new(
        "tun-log",
        Category::Logs,
        "probes.diag.tunLog.label",
        verdict,
        value,
    )
    .details(last_redacted(&errors, 8, 400), 8)
}

/// Window in which an app warning counts as current.
pub const FRESH_PROBLEM_MS: i64 = 15 * 60_000;

/// `app-log`: warnings / errors of this run within the last 15 minutes. Findings of this report
/// are logged at info level, so they never feed back into the next run.
pub fn app_log_item(problems: &[vpnte_core::logging::Problem], now: i64) -> CheckItem {
    let fresh: Vec<&vpnte_core::logging::Problem> = problems
        .iter()
        .filter(|p| now - p.at <= FRESH_PROBLEM_MS)
        .collect();
    let rows: Vec<String> = fresh
        .iter()
        .map(|p| {
            let ts = jiff::Timestamp::from_millisecond(p.at)
                .map(|t| t.to_string())
                .unwrap_or_default();
            format!(
                "{ts} {} {}: {}",
                p.level,
                p.target,
                p.msg.chars().take(180).collect::<String>()
            )
        })
        .collect();
    let rows: Vec<String> = rows
        .iter()
        .skip(rows.len().saturating_sub(8))
        .map(|r| vpnte_core::redact::for_log(r).into_owned())
        .collect();
    let (verdict, value) = match fresh.len() {
        0 => (Verdict::Ok, Msg::new("probes.diag.appLog.clean")),
        n => (
            Verdict::Warn,
            Msg::new("probes.diag.appLog.problems").arg("count", n),
        ),
    };
    CheckItem::new(
        "app-log",
        Category::Logs,
        "probes.diag.appLog.label",
        Some(verdict),
        value,
    )
    .details(rows, 8)
}

/// Facts of the active profile, taken by the app from `vpnte_profiles::caps::capabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFacts {
    pub name: String,
    /// Protocol label (`vless`, `hysteria2`, …).
    pub protocol: String,
    /// Stealth label (`reality`, `ech`, `naive`, …).
    pub stealth: String,
    pub tls: bool,
    pub ech: bool,
    /// Hysteria2 only.
    pub hy2: Option<Hy2Facts>,
    /// What the user should know before connecting, most important first.
    pub warnings: Vec<Msg>,
}

/// Hysteria2 transport facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hy2Facts {
    pub obfs: Option<String>,
    pub server_ports: Option<String>,
    pub hop_interval: Option<String>,
}

/// `active-profile-capabilities`: protocol, disguise and what to know (a warning if anything).
pub fn profile_item(profile: Option<&ProfileFacts>) -> CheckItem {
    let id = "active-profile-capabilities";
    let label = "probes.diag.profile.label";
    let Some(p) = profile else {
        return CheckItem::new(
            id,
            Category::Profile,
            label,
            None,
            Msg::new("probes.diag.profile.none"),
        );
    };
    let mut rows = vec![
        format!("name={}", vpnte_core::redact::text(&p.name)),
        format!("protocol={}", p.protocol),
        format!("stealthPreset={}", p.stealth),
        format!("tlsConfigured={}", p.tls),
        format!("echConfigured={}", p.ech),
    ];
    if let Some(h) = &p.hy2 {
        rows.push("hy2Transport=QUIC/UDP".to_owned());
        rows.extend(h.obfs.as_ref().map(|v| format!("hy2Obfs={v}")));
        rows.extend(
            h.server_ports
                .as_ref()
                .map(|v| format!("hy2ServerPorts={v}")),
        );
        rows.extend(
            h.hop_interval
                .as_ref()
                .map(|v| format!("hy2HopInterval={v}")),
        );
    }
    let value = Msg::new("probes.diag.profile.value")
        .arg("protocol", &p.protocol)
        .arg("stealth", &p.stealth)
        .arg("count", p.warnings.len());
    let verdict = (!p.warnings.is_empty()).then_some(Verdict::Warn);
    let mut item = CheckItem::new(id, Category::Profile, label, verdict, value).details(rows, 16);
    item.notes = p.warnings.clone();
    item
}

/// Longest details text in a logged finding.
pub const FINDING_DETAILS_MAX: usize = 4_000;

/// A warn / fail item as it goes to the log: redacted and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: String,
    pub status: Verdict,
    pub value: String,
    pub details: String,
}

/// The log rows of a report: one per warn / fail item, everything through the log redactor.
pub fn findings(items: &[CheckItem]) -> Vec<Finding> {
    items
        .iter()
        .filter_map(|i| {
            let status = i
                .verdict
                .filter(|v| matches!(v, Verdict::Warn | Verdict::Fail))?;
            let value = std::iter::once(i.value.key.to_string())
                .chain(i.value.args.iter().map(|(k, v)| format!("{k}={v}")))
                .collect::<Vec<_>>()
                .join(" ");
            let details: String = i
                .details
                .join(" | ")
                .chars()
                .take(FINDING_DETAILS_MAX)
                .collect();
            Some(Finding {
                check: i.id.clone(),
                status,
                value: vpnte_core::redact::for_log(&value).into_owned(),
                details: vpnte_core::redact::for_log(&details).into_owned(),
            })
        })
        .collect()
}
