//! The `dns` section: routing's servers and rules plus the servers the upstream needs.
//! Upstream server names resolve direct, in the order of the app resolver
//! (`vpnte_core::resolve`, ru-2026 Ф9): DoH by IP literal first (no SNI to filter on), DNS over
//! TCP next, the ISP's resolver last; never plain UDP to a public resolver, which RU networks
//! redirect to the NSDI (forged NXDOMAIN for blocked names).
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};
use vpnte_winnet::adapters::TUN_V4;

use super::outbounds::UpstreamParts;
use super::{ConfigError, ConfigInputs, require_objects};
use crate::tags::{
    DNS_BOOTSTRAP, DNS_BOOTSTRAP_GOOGLE, DNS_BOOTSTRAP_IN, DNS_BOOTSTRAP_ISP, DNS_BOOTSTRAP_QUAD9,
    DNS_BOOTSTRAP_TCP, DNS_BOOTSTRAP_YANDEX, DNS_REMOTE, DNS_RESOLVER, PROXY_OUT,
};

/// Resolvers of the bootstrap order after `dns-bootstrap` (1.1.1.1): DoH by IP literal to Yandex,
/// Quad9 and Google, then DNS over TCP to Google; the physical adapter's resolver comes last, it
/// answers unblocked names when every public resolver is cut off (mobile whitelists).
/// Yandex is second: RU networks that cut foreign resolvers (whitelists included) leave it
/// reachable, and a step that late still fits Xray's 4 s after one blackholed step. Its
/// certificate carries the address (77.88.8.8 is an IP SAN), so no SNI is sent here either.
const YANDEX: &str = "77.88.8.8";
const QUAD9: &str = "9.9.9.9";
const GOOGLE: &str = "8.8.8.8";
/// Budget of one step of the bootstrap order: Xray gives a whole lookup 4 s, so two blackholed
/// steps must still leave room for the third.
const STEP_TIMEOUT: &str = "1500ms";
/// Tags the builder owns: routing must not define them.
const RESERVED: [&str; 7] = [
    DNS_RESOLVER,
    DNS_BOOTSTRAP,
    DNS_BOOTSTRAP_YANDEX,
    DNS_BOOTSTRAP_QUAD9,
    DNS_BOOTSTRAP_GOOGLE,
    DNS_BOOTSTRAP_TCP,
    DNS_BOOTSTRAP_ISP,
];

pub(super) fn section(i: &ConfigInputs, up: &UpstreamParts) -> Result<Value, ConfigError> {
    let r = &i.routing;
    require_objects(&r.dns_servers, "dns server")?;
    require_objects(&r.dns_rules, "dns rule")?;
    let mut servers = r.dns_servers.clone();
    let mut tags: Vec<&str> = Vec::new();
    for s in &r.dns_servers {
        let tag = s.get("tag").and_then(Value::as_str).unwrap_or_default();
        // The builder owns the resolver and bootstrap tags: a `dns-resolver` given by name
        // would resolve itself.
        if tag.is_empty() || RESERVED.contains(&tag) || tags.contains(&tag) {
            return Err(ConfigError::BadRouting(format!(
                "dns server tag {tag:?} is empty, reserved or repeated"
            )));
        }
        tags.push(tag);
    }
    if !tags.contains(&DNS_REMOTE) {
        // Cloudflare DoH through the tunnel: field diagnostics showed TCP over the tunnel
        // working while its UDP (DNS) timed out.
        servers.insert(0, doh_cloudflare(DNS_REMOTE));
    }
    // A tunnelled server given by name resolves it on `dns-resolver`: left to the outbound, a
    // WireGuard endpoint would look the name up on `dns-remote`, i.e. on itself.
    let mut need_resolver = false;
    for s in servers.iter_mut().filter(|s| needs_resolver(s)) {
        s["domain_resolver"] = json!(DNS_RESOLVER);
        need_resolver = true;
    }
    if need_resolver {
        servers.push(doh_cloudflare(DNS_RESOLVER));
    }
    let bootstrap_in = i.listeners.dns_bootstrap.is_some();
    if up.needs_bootstrap || bootstrap_in {
        // An outbound's `domain_resolver` names one server and bypasses the DNS rules (sing-box
        // 1.14 `dns/router.go` Lookup), so `dns-bootstrap` is the first step of the order.
        servers.push(doh_direct(DNS_BOOTSTRAP, "1.1.1.1"));
    }
    let mut rules = Vec::new();
    if bootstrap_in {
        let isp = usable_physical_dns(&i.phys_dns);
        servers.extend(bootstrap_servers(isp));
        rules.extend(bootstrap_rules(isp.is_some()));
    }
    rules.extend(r.dns_rules.iter().cloned());
    let mut dns = json!({ "servers": servers });
    if !rules.is_empty() {
        dns["rules"] = Value::Array(rules);
    }
    dns["final"] = json!(DNS_REMOTE);
    // Applies to hijacked queries too: AAAA answers are empty, apps connect over IPv4.
    dns["strategy"] = json!("ipv4_only");
    Ok(dns)
}

/// The bootstrap order after `dns-bootstrap`: all direct (no detour: the server's own dialer;
/// `type: local` would recurse into the TUN resolver, `detour: direct-out` is refused).
fn bootstrap_servers(isp: Option<Ipv4Addr>) -> Vec<Value> {
    let mut servers = vec![
        doh_direct(DNS_BOOTSTRAP_YANDEX, YANDEX),
        doh_direct(DNS_BOOTSTRAP_QUAD9, QUAD9),
        doh_direct(DNS_BOOTSTRAP_GOOGLE, GOOGLE),
        json!({ "type": "tcp", "tag": DNS_BOOTSTRAP_TCP, "server": GOOGLE }),
    ];
    servers.extend(
        isp.map(|ip| json!({ "type": "udp", "tag": DNS_BOOTSTRAP_ISP, "server": ip.to_string() })),
    );
    servers
}

/// Rules for queries of `dns-bootstrap-in` (Xray's server names), first in the list. Each step
/// is evaluated and its answer taken when it has an address or, over foreign DoH (TLS: not
/// forgeable on the path), when the name does not exist; an error, a timeout or an empty answer
/// moves on. Yandex's NXDOMAIN moves on as well: a domestic resolver may answer the blocking
/// registry rather than the zone. The last step's answer stands as it is: an honest failure,
/// never an empty success.
fn bootstrap_rules(isp: bool) -> Vec<Value> {
    let inbound = json!([DNS_BOOTSTRAP_IN]);
    let step = |action: &str, server: &str| json!({ "inbound": inbound, "action": action, "server": server, "timeout": STEP_TIMEOUT });
    let has_address = json!({
        "inbound": inbound, "match_response": true, "ip_accept_any": true, "action": "respond",
    });
    let no_such_name = json!({
        "inbound": inbound, "match_response": true, "response_rcode": "NXDOMAIN",
        "action": "respond",
    });
    let mut rules = Vec::new();
    for doh in [
        DNS_BOOTSTRAP,
        DNS_BOOTSTRAP_YANDEX,
        DNS_BOOTSTRAP_QUAD9,
        DNS_BOOTSTRAP_GOOGLE,
    ] {
        rules.extend([step("evaluate", doh), has_address.clone()]);
        if doh != DNS_BOOTSTRAP_YANDEX {
            rules.push(no_such_name.clone());
        }
    }
    if isp {
        rules.extend([step("evaluate", DNS_BOOTSTRAP_TCP), has_address]);
        rules.push(step("route", DNS_BOOTSTRAP_ISP));
    } else {
        rules.push(step("route", DNS_BOOTSTRAP_TCP));
    }
    rules
}

/// The first physical resolver that is not our TUN's, not loopback (a local resolver would
/// forward through the TUN it is meant to bypass) and not unspecified: the server of
/// `dns-direct` in `routing` and the last bootstrap step.
pub fn usable_physical_dns(physical: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    physical
        .iter()
        .copied()
        .find(|ip| !TUN_V4.contains(ip) && !ip.is_loopback() && !ip.is_unspecified())
}

/// A tunnelled (`detour`) server named by host name without its own resolver.
fn needs_resolver(server: &Value) -> bool {
    server.get("detour").is_some()
        && server.get("domain_resolver").is_none()
        && server
            .get("server")
            .and_then(Value::as_str)
            .is_some_and(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().is_err())
}

fn doh_cloudflare(tag: &str) -> Value {
    json!({
        "type": "https",
        "tag": tag,
        "server": "1.1.1.1",
        "path": "/dns-query",
        "detour": PROXY_OUT,
        "tls": { "server_name": "cloudflare-dns.com" },
    })
}

/// Direct DoH to an IP literal without `tls.server_name`: the TLS name is the address, so no
/// SNI is sent and the certificate must carry the address (it does for these services).
fn doh_direct(tag: &str, ip: &str) -> Value {
    json!({ "type": "https", "tag": tag, "server": ip, "path": "/dns-query" })
}

#[cfg(test)]
mod tests;
