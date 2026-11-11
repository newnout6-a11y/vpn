//! The `route` section: fixed rule order around routing's fragments.
use serde_json::{Value, json};

use super::outbounds::UpstreamParts;
use super::{Capture, ConfigError, ConfigInputs, require_objects};
use crate::tags::{DIRECT_IN, DIRECT_OUT, DNS_BOOTSTRAP_IN, DNS_REMOTE, PROBE_IN, PROXY_OUT};

/// Rule order (first match wins):
/// 1. loopback inbounds (bootstrap DNS, direct, live check);
/// 2. routing's process rules (own engines, third-party cores, split-tunnel apps); they match
///    proxy-capture clients too: sing-box looks up the owner of every loopback source, and on
///    Windows by the client socket's local address in the TCP / UDP tables;
/// 3. QUIC and IPv6 rejects, before `sniff` so they are decided at the first packet (pre-match):
///    a TCP SYN gets a reset instead of a locally completed handshake that is closed later;
/// 4. `sniff`, DNS hijack (TUN only), private destinations direct (after the hijack, so DNS sent
///    to an off-link private resolver is still answered by sing-box; on-link subnets never enter
///    the TUN, their resolvers are blocked by the WFP layers instead: review E-D5);
/// 5. the all-UDP drop (after the hijack: Windows' DNS probes must reach the resolver), the
///    STUN pin, then routing's domain rules; `final` is `proxy-out`.
pub(super) fn section(i: &ConfigInputs, up: &UpstreamParts) -> Result<Value, ConfigError> {
    let r = &i.routing;
    require_objects(&r.process_rules, "process rule")?;
    require_objects(&r.domain_rules, "route rule")?;
    require_objects(&r.rule_sets, "rule set")?;
    let tun = matches!(i.capture, Capture::Tun(_));
    // A proxy client may name an IPv6 literal; the tunnel refuses IPv6 egress in every form.
    let reject_ipv6 = match &i.capture {
        Capture::Tun(t) => t.ipv6,
        Capture::Proxy { .. } => true,
    };
    let mut rules = Vec::new();
    if i.listeners.dns_bootstrap.is_some() {
        rules.push(json!({ "inbound": DNS_BOOTSTRAP_IN, "action": "hijack-dns" }));
    }
    rules.push(json!({ "inbound": DIRECT_IN, "outbound": DIRECT_OUT }));
    if i.listeners.probe.is_some() {
        rules.push(json!({ "inbound": PROBE_IN, "outbound": PROXY_OUT }));
    }
    rules.extend(r.process_rules.iter().cloned());
    // `no_drop`: without it sing-box silently turns a reject into a drop after 50 hits in
    // 30 s, and clients then wait for their fallback timers.
    if up.block_quic {
        rules.push(json!({
            "network": "udp", "port": 443, "action": "reject", "method": "default", "no_drop": true,
        }));
    }
    if reject_ipv6 {
        // IPv6 egress is refused inside the tunnel (fast reset / ICMP, so clients fall back to
        // IPv4 at once); IPv6 LAN keeps working through the private-destination rule.
        rules.push(json!({
            "type": "logical",
            "mode": "and",
            "rules": [{ "ip_version": 6 }, { "ip_is_private": true, "invert": true }],
            "action": "reject",
            "method": "default",
            "no_drop": true,
        }));
    }
    rules.push(json!({ "action": "sniff" }));
    if tun {
        // The system resolver's queries enter the TUN; proxy clients hand over names instead.
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    rules.push(json!({ "ip_is_private": true, "outbound": DIRECT_OUT }));
    if up.drop_udp {
        rules.push(json!({ "network": "udp", "action": "reject", "method": "drop" }));
    }
    // STUN is pinned to the tunnel so WebRTC never learns the real address through direct-out.
    rules.push(json!({ "network": "udp", "port": [19302, 3478], "outbound": PROXY_OUT }));
    rules.extend(r.domain_rules.iter().cloned());
    let mut route = json!({ "rules": rules });
    if !r.rule_sets.is_empty() {
        route["rule_set"] = Value::Array(r.rule_sets.clone());
    }
    route["final"] = json!(PROXY_OUT);
    if tun {
        // Binds sing-box's own dials to the physical interface so they do not loop through the
        // TUN. Without a TUN the binding would only bypass routes another VPN client installed.
        route["auto_detect_interface"] = json!(true);
    }
    route["default_domain_resolver"] = json!(DNS_REMOTE);
    Ok(route)
}
