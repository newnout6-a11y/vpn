//! The capture inbound (TUN or loopback proxy) and the app-owned loopback inbounds.
use std::net::IpAddr;

use serde_json::{Value, json};
use vpnte_base::types::Loopback;
use vpnte_winnet::adapters::{TUN_V4, TUN_V6};

use super::{Capture, ConfigError, ConfigInputs, TunParams, Upstream};
use crate::tags::{DIRECT_IN, DNS_BOOTSTRAP_IN, PROBE_IN, PROXY_IN, TUN_IN};

/// Never routed into the TUN: loopback, link-local, multicast. RFC 1918 stays in the TUN on
/// purpose: private destinations reach `ip_is_private -> direct-out` only after DNS hijack.
const EXCLUDE_V4: [&str; 3] = ["127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"];
const EXCLUDE_V6: [&str; 2] = ["fe80::/10", "ff00::/8"];

/// `tun-in`: split default routes (more specific than any physical default route),
/// `strict_route`, the TUN form decided by the caller, and the dialed servers excluded.
pub(super) fn tun(t: &TunParams, exclude: &[IpAddr]) -> Result<Value, ConfigError> {
    if t.alias.trim().is_empty() || t.alias.chars().any(char::is_control) {
        return Err(ConfigError::InvalidTun("empty or malformed alias"));
    }
    if t.mtu < 1280 {
        return Err(ConfigError::InvalidTun("MTU below 1280"));
    }
    if !t.ipv6 && !t.dns_hijack {
        // `native` leaves port 53 to the app's WFP DNS block, which always comes with its IPv6
        // block (dual stack); without it nothing would stop DNS on the physical adapters.
        return Err(ConfigError::InvalidTun("native DNS without the WFP guard"));
    }
    let mut address = vec![TUN_V4.to_string()];
    let mut route = vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()];
    let mut excluded: Vec<String> = EXCLUDE_V4.iter().map(|s| (*s).to_owned()).collect();
    if t.ipv6 {
        address.push(TUN_V6.to_string());
        route.extend(["::/1".to_owned(), "8000::/1".to_owned()]);
        excluded.extend(EXCLUDE_V6.iter().map(|s| (*s).to_owned()));
    }
    for ip in exclude {
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        match ip {
            IpAddr::V4(v4) => excluded.push(format!("{v4}/32")),
            // Without an IPv6 TUN address no IPv6 route points into the TUN.
            IpAddr::V6(v6) if t.ipv6 => excluded.push(format!("{v6}/128")),
            IpAddr::V6(_) => {}
        }
    }
    Ok(json!({
        "type": "tun",
        "tag": TUN_IN,
        "interface_name": t.alias,
        "address": address,
        "mtu": t.mtu,
        "auto_route": true,
        "strict_route": true,
        "dns_mode": if t.dns_hijack { "hijack" } else { "native" },
        "route_address": route,
        "route_exclude_address": excluded,
        // Windows' DNS client reuses one UDP/53 flow for a long time; an endless flow left
        // sing-box parsing stale datagrams ("bad question name" / "bad rdata").
        "udp_timeout": "30s",
        "stack": t.stack.as_str(),
    }))
}

/// `proxy-in`: HTTP + SOCKS for the programs the app points at it (system proxy, environment
/// variables, dev tools). No users: the system proxy cannot carry credentials, and every flow
/// still goes through the routing below. No `set_system_proxy`: the app owns that tweak.
pub(super) fn proxy(port: u16) -> Value {
    json!({
        "type": "mixed",
        "tag": PROXY_IN,
        "listen": "127.0.0.1",
        "listen_port": port,
    })
}

/// The authenticated mixed inbounds and the loopback DNS inbound, after checking that every
/// app-owned port of this start is set and distinct.
pub(super) fn listeners(i: &ConfigInputs) -> Result<Vec<Value>, ConfigError> {
    let l = &i.listeners;
    let mut ports = vec![l.clash_port, l.direct.port];
    ports.extend(l.probe.as_ref().map(|p| p.port));
    ports.extend(l.dns_bootstrap);
    if let Upstream::XraySlots { slots, .. } = &i.upstream {
        ports.extend(slots.iter().map(|s| s.port()));
    }
    if let Capture::Proxy { port } = i.capture {
        ports.push(port);
    }
    if ports.contains(&0) {
        return Err(ConfigError::InvalidListeners("port 0"));
    }
    if ports
        .iter()
        .enumerate()
        .any(|(n, p)| ports[..n].contains(p))
    {
        return Err(ConfigError::InvalidListeners("ports are not distinct"));
    }
    if l.clash_secret.is_empty() || l.clash_secret.chars().any(|c| c.is_whitespace()) {
        return Err(ConfigError::InvalidListeners("malformed controller secret"));
    }
    let mut out = vec![mixed(DIRECT_IN, &l.direct)?];
    if let Some(probe) = &l.probe {
        out.push(mixed(PROBE_IN, probe)?);
    }
    if let Some(port) = l.dns_bootstrap {
        out.push(json!({
            "type": "direct",
            "tag": DNS_BOOTSTRAP_IN,
            "listen": "127.0.0.1",
            "listen_port": port,
        }));
    }
    Ok(out)
}

/// A loopback mixed inbound with exactly one user: other local programs must not be able to
/// use it to leave the tunnel.
fn mixed(tag: &str, lb: &Loopback) -> Result<Value, ConfigError> {
    let valid = |s: &str| (1..=255).contains(&s.len());
    let creds = lb
        .creds
        .as_ref()
        .filter(|c| valid(&c.user) && valid(&c.pass))
        .ok_or(ConfigError::InvalidListeners(
            "mixed inbound without valid credentials",
        ))?;
    Ok(json!({
        "type": "mixed",
        "tag": tag,
        "listen": "127.0.0.1",
        "listen_port": lb.port,
        "users": [{ "username": creds.user, "password": creds.pass }],
    }))
}
