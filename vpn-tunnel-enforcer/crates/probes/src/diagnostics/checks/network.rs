//! Network items: system proxy, adapters, routes, DNS answer, other VPN / proxy clients.
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::Verdict;
use vpnte_winnet::adapters::{Adapter, AdapterStatus, Route};

use super::strip_userinfo;
use crate::diagnostics::sysinfo::ProcessRow;
use crate::diagnostics::{Category, CheckItem};
use crate::local_proxy::SystemProxy;

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
    listeners: &[crate::diagnostics::plan::ListenerInfo],
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
