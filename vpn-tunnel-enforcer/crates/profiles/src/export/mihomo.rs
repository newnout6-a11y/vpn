//! WireGuard and AmneziaWG profiles as a mihomo proxy: a `proxies:` document with one entry
//! (`amnezia-wg-option` for AmneziaWG) that mihomo runs and [`crate::clash`] reads back to the
//! same profile.
use std::fmt::Write;

use ipnet::IpNet;

use super::wireguard_parts;
use crate::awg::{AwgValue, pairs};
use crate::model::{AwgGeneration, Profile, WgPeer};

/// The mihomo document of a WireGuard or AmneziaWG profile. `None` for other kinds and for
/// what mihomo cannot express: TLS / transport / dial options, more than one local address
/// per family, or peers with different keepalives (mihomo keeps one per entry). mihomo has no
/// keepalive range: an AmneziaWG 3.x range is written as its lower bound, a value AmneziaWG
/// itself may pick.
pub fn export_mihomo(p: &Profile) -> Option<String> {
    let (wg, awg) = wireguard_parts(p)?;
    let (v4, v6): (Vec<&IpNet>, Vec<&IpNet>) =
        wg.local_address.iter().partition(|a| a.addr().is_ipv4());
    if v4.len() > 1 || v6.len() > 1 {
        return None;
    }
    let first = wg.peers.first()?;
    if wg
        .peers
        .iter()
        .any(|peer| peer.keepalive_s != first.keepalive_s)
    {
        return None;
    }
    let keepalive = match awg.and_then(|a| a.keepalive_range) {
        Some(range) => Some(range.min),
        None => first.keepalive_s.map(u32::from),
    };
    // mihomo ignores `allowed-ips` of the single-peer form: a peer with routes is listed.
    let listed = wg.peers.len() > 1 || !first.allowed_ips.is_empty();
    let mut y = Yaml(String::from("proxies:\n"));
    y.put(2, "- name", quote(&p.name));
    y.put(4, "type", "wireguard".into());
    if !listed {
        y.put(4, "server", quote(&first.host.to_string()));
        y.put(4, "port", first.port.to_string());
        y.peer(4, first);
    }
    if let Some(ip) = v4.first() {
        y.put(4, "ip", quote(&ip.to_string()));
    }
    if let Some(ip) = v6.first() {
        y.put(4, "ipv6", quote(&ip.to_string()));
    }
    y.put(4, "private-key", quote(&wg.private_key));
    if let Some(mtu) = wg.mtu {
        y.put(4, "mtu", mtu.to_string());
    }
    if !wg.dns.is_empty() {
        // mihomo uses `dns` only when it resolves through the tunnel.
        y.put(4, "remote-dns-resolve", "true".into());
        y.put(4, "dns", list(&wg.dns));
    }
    if let Some(keepalive) = keepalive {
        y.put(4, "persistent-keepalive", keepalive.to_string());
    }
    y.put(4, "udp", "true".into());
    if listed {
        y.put(4, "peers", String::new());
        for peer in &wg.peers {
            y.put(6, "- server", quote(&peer.host.to_string()));
            y.put(8, "port", peer.port.to_string());
            y.peer(8, peer);
            y.put(8, "allowed-ips", list(&peer.allowed_ips));
        }
    }
    if let Some(awg) = awg {
        y.put(4, "amnezia-wg-option", String::new());
        // Only 3 selects mihomo's 3.x implementation; every other version is the legacy one.
        if awg.generation == AwgGeneration::V3 {
            y.put(6, "version", "3".into());
        }
        for (field, value) in pairs(awg) {
            let value = match value {
                AwgValue::Number(n) => n.to_string(),
                AwgValue::Range(range) if !range.is_range() => range.min.to_string(),
                AwgValue::Range(range) => quote(&range.to_string()),
                AwgValue::Text(text) => quote(text),
                AwgValue::Switch(on) => on.to_string(),
            };
            y.put(6, &field.yaml_name(), value);
        }
    }
    Some(y.0)
}

/// Block YAML with JSON-quoted scalars (valid YAML) so that no name or key needs escaping rules
/// of its own.
struct Yaml(String);

impl Yaml {
    fn put(&mut self, indent: usize, key: &str, value: String) {
        let sep = if value.is_empty() { "" } else { " " };
        // Writing to a String cannot fail.
        let _ = writeln!(self.0, "{:indent$}{key}:{sep}{value}", "");
    }

    fn peer(&mut self, indent: usize, peer: &WgPeer) {
        self.put(indent, "public-key", quote(&peer.public_key));
        if let Some(psk) = &peer.pre_shared_key {
            self.put(indent, "pre-shared-key", quote(psk));
        }
        if let Some([a, b, c]) = peer.reserved {
            self.put(indent, "reserved", format!("[{a}, {b}, {c}]"));
        }
    }
}

fn quote(text: &str) -> String {
    serde_json::Value::from(text).to_string()
}

fn list<T: ToString>(items: &[T]) -> String {
    let items: Vec<String> = items.iter().map(|i| quote(&i.to_string())).collect();
    format!("[{}]", items.join(", "))
}
