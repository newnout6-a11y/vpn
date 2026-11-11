//! The `dns` section: routing's servers and rules plus the servers the upstream needs.
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};
use vpnte_winnet::adapters::TUN_V4;

use super::outbounds::UpstreamParts;
use super::{ConfigError, ConfigInputs, require_objects};
use crate::tags::{DNS_BOOTSTRAP, DNS_BOOTSTRAP_IN, DNS_REMOTE, DNS_RESOLVER, PROXY_OUT};

/// Public resolver of last resort for `dns-bootstrap` when no physical resolver is known.
const FALLBACK_BOOTSTRAP: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

pub(super) fn section(i: &ConfigInputs, up: &UpstreamParts) -> Result<Value, ConfigError> {
    let r = &i.routing;
    require_objects(&r.dns_servers, "dns server")?;
    require_objects(&r.dns_rules, "dns rule")?;
    let mut servers = r.dns_servers.clone();
    let mut tags: Vec<&str> = Vec::new();
    for s in &r.dns_servers {
        let tag = s.get("tag").and_then(Value::as_str).unwrap_or_default();
        // The builder owns these two: a `dns-resolver` given by name would resolve itself.
        let reserved = [DNS_RESOLVER, DNS_BOOTSTRAP].contains(&tag);
        if tag.is_empty() || reserved || tags.contains(&tag) {
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
        // No detour: the server's own direct dialer. `type: local` would recurse into the TUN
        // resolver, `detour: direct-out` is refused by sing-box.
        servers.push(json!({
            "type": "udp",
            "tag": DNS_BOOTSTRAP,
            "server": bootstrap_resolver(&i.phys_dns).to_string(),
        }));
    }
    let mut rules = Vec::new();
    if bootstrap_in {
        rules.push(json!({ "inbound": [DNS_BOOTSTRAP_IN], "server": DNS_BOOTSTRAP }));
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

/// The first physical resolver that is not our TUN's, not loopback (a local resolver would
/// forward through the TUN it is meant to bypass) and not unspecified: the server of
/// `dns-direct` in `routing`.
pub fn usable_physical_dns(physical: &[Ipv4Addr]) -> Option<Ipv4Addr> {
    physical
        .iter()
        .copied()
        .find(|ip| !TUN_V4.contains(ip) && !ip.is_loopback() && !ip.is_unspecified())
}

/// The direct resolver for upstream server names: the usable physical resolver, else 1.1.1.1.
/// Serves `dns-bootstrap` here and the bootstrap retry of `xray_config::resolve_hosts`.
pub fn bootstrap_resolver(physical: &[Ipv4Addr]) -> Ipv4Addr {
    usable_physical_dns(physical).unwrap_or(FALLBACK_BOOTSTRAP)
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
