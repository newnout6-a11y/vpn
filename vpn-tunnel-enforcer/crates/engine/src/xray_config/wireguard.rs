//! WireGuard as Xray's `wireguard` outbound. On Windows Xray runs it on its built-in (gVisor)
//! stack: no adapter is created and no elevation is needed.
use std::net::IpAddr;

use serde_json::{Map, Value, json};
use vpnte_profiles::model::{Host, WgPeer, WireGuard};

/// The outbound of a WireGuard profile (without its tag). Xray keeps `reserved` per outbound,
/// not per peer: the first peer that sets it wins (WARP-style keys have one peer).
pub(super) fn outbound(wg: &WireGuard) -> Value {
    let mut s = Map::new();
    s.insert("secretKey".into(), json!(wg.private_key.trim()));
    if !wg.local_address.is_empty() {
        let addresses: Vec<String> = wg.local_address.iter().map(ToString::to_string).collect();
        s.insert("address".into(), json!(addresses));
    }
    s.insert(
        "peers".into(),
        Value::Array(wg.peers.iter().map(peer).collect()),
    );
    if let Some(mtu) = wg.mtu {
        s.insert("mtu".into(), json!(mtu));
    }
    if let Some(reserved) = wg.peers.iter().find_map(|p| p.reserved) {
        s.insert("reserved".into(), json!(reserved));
    }
    if !wg.dns.is_empty() {
        // Xray resolves proxied names itself, through the tunnel, with these servers (its
        // default is Cloudflare); the provider's resolver is the one meant for this tunnel.
        let dns: Vec<String> = wg.dns.iter().map(ToString::to_string).collect();
        s.insert("remoteDNS".into(), json!(dns));
    }
    json!({"protocol": "wireguard", "settings": s})
}

fn peer(peer: &WgPeer) -> Value {
    let host = match &peer.host {
        Host::Ip(IpAddr::V6(ip)) => format!("[{ip}]"),
        other => other.to_string(),
    };
    let mut o = Map::new();
    o.insert("endpoint".into(), json!(format!("{host}:{}", peer.port)));
    o.insert("publicKey".into(), json!(peer.public_key.trim()));
    if let Some(psk) = peer
        .pre_shared_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        o.insert("preSharedKey".into(), json!(psk));
    }
    if let Some(keepalive) = peer.keepalive_s.filter(|s| *s > 0) {
        o.insert("keepAlive".into(), json!(keepalive));
    }
    if !peer.allowed_ips.is_empty() {
        let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
        o.insert("allowedIPs".into(), json!(allowed));
    }
    Value::Object(o)
}
