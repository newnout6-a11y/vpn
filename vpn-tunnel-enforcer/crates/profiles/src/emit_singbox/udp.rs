//! UDP / QUIC capability of a profile (tunnel-core §3.16), matching how the emitted outbound
//! behaves; the tunnel turns it into its UDP/443 and all-UDP reject rules.
use serde_json::Value;

use crate::model::{Kind, Profile};
use crate::xray_native::mux_rejects_udp443;

/// True when the profile relays UDP through the tunnel.
pub fn udp_capable(p: &Profile) -> bool {
    // Hysteria2 is QUIC: the emitter drops a legacy tcp-only `network` (see `outbound`).
    if !matches!(p.kind, Kind::Hysteria2 { .. })
        && !network_allows_udp(p.singbox_extra.get("network"))
    {
        return false;
    }
    match &p.kind {
        Kind::Http { .. } => false,
        // sing-box 1.14 anytls always relays UDP as UDP-over-TCP v2 (tunnel-core §3.16 still
        // listed it as TCP-only); naive does so only when `udp_over_tcp` is on.
        Kind::Anytls { .. } => true,
        Kind::Naive { .. } => uot_enabled(p.singbox_extra.get("udp_over_tcp")),
        Kind::Hysteria2 { .. } | Kind::Tuic { .. } | Kind::Wireguard(_) => true,
        // sing-box defaults VLESS to xudp; an explicitly empty encoding has no UDP tunnelling.
        Kind::Vless {
            packet_encoding, ..
        } => packet_encoding.as_deref().is_none_or(udp_encoding),
        // ShadowTLS is a TCP-only dialer: UDP survives only as UDP-over-TCP.
        Kind::Shadowsocks {
            shadowtls: Some(_),
            uot,
            ..
        } => uot.is_some(),
        Kind::Vmess { .. }
        | Kind::Trojan { .. }
        | Kind::Shadowsocks { .. }
        | Kind::Socks { .. } => true,
    }
}

/// True when UDP/443 should be rejected so that browsers fall back from QUIC to TCP at once
/// instead of waiting for a QUIC handshake the tunnel will not carry.
pub fn block_quic(p: &Profile) -> bool {
    // A provider Xray graph can route through any of its outbounds (Xray rejects UDP/443 on a
    // muxed one unless `xudpProxyUDP443` says otherwise).
    let graph_rejects = p.native_xray.as_ref().is_some_and(mux_rejects_udp443);
    if !udp_capable(p) || graph_rejects {
        return true;
    }
    // Some VLESS servers accept the TCP tunnel but do not relay XUDP reliably: QUIC stays on
    // the TCP fallback unless the profile explicitly opts into a known UDP packet encoding.
    match &p.kind {
        Kind::Vless {
            packet_encoding, ..
        } => !packet_encoding.as_deref().is_some_and(udp_encoding),
        _ => false,
    }
}

fn udp_encoding(encoding: &str) -> bool {
    let encoding = encoding.trim();
    encoding.eq_ignore_ascii_case("xudp") || encoding.eq_ignore_ascii_case("packetaddr")
}

/// sing-box `udp_over_tcp`: `true` or `{"enabled": true, …}`.
fn uot_enabled(uot: Option<&Value>) -> bool {
    match uot {
        Some(Value::Bool(on)) => *on,
        Some(Value::Object(o)) => o.get("enabled") == Some(&Value::Bool(true)),
        _ => false,
    }
}

/// A sing-box `network` (`"tcp"`, `"tcp,udp"`, `["tcp"]`) restricts the proxied networks;
/// UDP is off only when a list is present and excludes it.
pub(super) fn network_allows_udp(network: Option<&Value>) -> bool {
    let names: Vec<String> = match network {
        Some(Value::String(s)) => s
            .split(',')
            .map(|n| n.trim().to_ascii_lowercase())
            .collect(),
        Some(Value::Array(list)) => list
            .iter()
            .map(|n| n.as_str().unwrap_or_default().trim().to_ascii_lowercase())
            .collect(),
        _ => return true,
    };
    names.iter().any(|n| n == "udp")
}
