//! Lab live-11 L11-2: the server addresses an Xray slot dials itself, kept out of the TUN's
//! routes. Without them every upstream dial of xray.exe (the selected server, a balancer's
//! members, the observatory's rounds through them) entered the TUN and came back out through
//! sing-box's `direct-out` by the process rule: one more trip through sing-box's stack, and after
//! every TUN start the same wait as the user's first packets.
use std::net::IpAddr;

use serde_json::Value;

use crate::xray_config::ProxyGraph;

/// At most this many addresses: sing-tun turns `route_address` minus `route_exclude_address`
/// into prefixes and adds each one as a route at every TUN start (a /32 cut out of a /1 costs up
/// to 31 more routes). Servers past the bound keep the process rule, which always works.
pub const MAX_XRAY_SERVERS: usize = 16;

/// Protocols whose outbound dials a server of its own. `dns`, `freedom`, `blackhole` and
/// `loopback` are left out: a `dns` outbound's address is a public resolver the user's own
/// traffic must keep reaching through the tunnel.
const SERVER_PROTOCOLS: [&str; 8] = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria",
    "wireguard",
    "socks",
    "http",
];

/// Every IP literal an Xray instance of `graph` dials directly, the selected outbound first, in
/// config order, unique, at most [`MAX_XRAY_SERVERS`]: the `settings.address` / `vnext` /
/// `servers` entries, an XHTTP split download's address and WireGuard peer endpoints. Call it
/// after `ProxyGraph::substitute`: a name that did not resolve stays a name and is skipped (Xray
/// looks it up itself through the bootstrap resolver). An outbound that dials through another
/// (`proxySettings`, `sockopt.dialerProxy`) is skipped: its server is reached inside that hop.
pub fn xray_servers(graph: &ProxyGraph) -> Vec<IpAddr> {
    let outbounds = match graph {
        ProxyGraph::Translated(outbound) => std::slice::from_ref(outbound),
        ProxyGraph::Native(compiled) => compiled.outbounds.as_slice(),
    };
    let mut found: Vec<IpAddr> = Vec::new();
    for outbound in outbounds.iter().filter(|o| dials_itself(o)) {
        for ip in addresses(outbound) {
            if found.len() == MAX_XRAY_SERVERS {
                return found;
            }
            if !found.contains(&ip) {
                found.push(ip);
            }
        }
    }
    found
}

/// A server protocol whose sockets Xray opens itself (no dialer hop).
fn dials_itself(outbound: &Value) -> bool {
    let protocol = outbound.get("protocol").and_then(Value::as_str);
    let chained = outbound.pointer("/proxySettings/tag").is_some()
        || outbound
            .pointer("/streamSettings/sockopt/dialerProxy")
            .and_then(Value::as_str)
            .is_some_and(|tag| !tag.trim().is_empty());
    protocol.is_some_and(|p| SERVER_PROTOCOLS.contains(&p)) && !chained
}

/// The IP literals `outbound` dials, in config order.
fn addresses(outbound: &Value) -> Vec<IpAddr> {
    let settings = outbound.get("settings");
    let mut holders: Vec<&Value> = Vec::new();
    if let Some(s) = settings {
        if s.get("address").is_some() {
            holders.push(s);
        } else {
            for list in ["vnext", "servers"] {
                holders.extend(s.get(list).and_then(Value::as_array).into_iter().flatten());
            }
        }
    }
    let download = ["xhttpSettings", "splithttpSettings"]
        .into_iter()
        .find_map(|k| outbound.pointer(&format!("/streamSettings/{k}/extra/downloadSettings")))
        .filter(|d| d.pointer("/sockopt/dialerProxy").is_none());
    holders.extend(download);
    let mut ips: Vec<IpAddr> = holders
        .iter()
        .filter_map(|h| literal(h.get("address")?.as_str()?))
        .collect();
    let peers = settings
        .and_then(|s| s.get("peers"))
        .and_then(Value::as_array);
    for endpoint in peers
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("endpoint"))
    {
        let host = endpoint
            .as_str()
            .and_then(|e| Some(e.trim().rsplit_once(':')?.0));
        ips.extend(host.and_then(literal));
    }
    ips
}

/// `host` as an IP (brackets of an IPv6 endpoint removed).
fn literal(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}
