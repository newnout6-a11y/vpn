//! Loopback listeners that look like a VPN / proxy client (Happ, NekoBox, Clash, …), for the
//! report's client and proxy items: by process name or by the clients' default ports.
use std::net::SocketAddr;
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

use crate::local_proxy::ListenerRow;

/// A loopback listener that looks like a VPN / proxy client (display only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerInfo {
    pub process: String,
    pub addr: SocketAddr,
    pub pid: u32,
}

/// Process names of VPN / proxy clients.
pub static CLIENT_PROCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)happ|hiddify|nekoray|nekobox|v2ray|xray|sing-box|singbox|sing-tun|clash|flclash|mihomo|shadowsocks|ss-local|trojan|outline|wireguard|openvpn|karing|streisand|surfboard|vpn",
    )
    .expect("static regex")
});

/// Ports such clients use by default.
pub fn is_client_port(port: u16) -> bool {
    matches!(
        port,
        1080 | 1081
            | 1087
            | 10808
            | 10809
            | 7890
            | 7891
            | 7892
            | 7893
            | 7897
            | 8080
            | 2080
            | 2081
            | 6450
            | 6451
            | 9090
            | 20170
            | 20171
            | 8388
            | 17990..=17999
    )
}

/// Loopback / wildcard listeners of a client process or on a client port, unique by
/// (process, port); `skip_pids` = the app's own processes.
pub fn proxy_listeners(rows: &[ListenerRow], skip_pids: &[u32]) -> Vec<ListenerInfo> {
    let mut out: Vec<ListenerInfo> = Vec::new();
    for row in rows {
        let ip = row.local.ip();
        let process = row.process.clone().unwrap_or_default();
        if !(ip.is_loopback() || ip.is_unspecified())
            || skip_pids.contains(&row.pid)
            || !(CLIENT_PROCESS.is_match(&process) || is_client_port(row.local.port()))
            || out
                .iter()
                .any(|l| l.process == process && l.addr.port() == row.local.port())
        {
            continue;
        }
        out.push(ListenerInfo {
            process,
            addr: row.local,
            pid: row.pid,
        });
    }
    out
}
