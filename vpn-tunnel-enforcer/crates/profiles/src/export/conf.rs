//! WireGuard and AmneziaWG profiles as a wg-quick `.conf`: the file AmneziaVPN, the AmneziaWG
//! apps and WireGuard import, and that [`crate::wg_ini`] reads back to the same profile.
use std::fmt::Write;

use super::wireguard_parts;
use crate::awg::{AwgValue, pairs};
use crate::model::{Host, Profile};

/// The `.conf` of a WireGuard or AmneziaWG profile with every AmneziaWG parameter; `None` for
/// other kinds and for what a `.conf` cannot carry whole (TLS, transport, mux, dial options,
/// raw sing-box keys). A lone peer without routes gets `0.0.0.0/0, ::/0` written out: that is
/// what it carries here (K21), and other clients route nothing without it.
pub fn export_conf(p: &Profile) -> Option<String> {
    let (wg, awg) = wireguard_parts(p)?;
    let mut out = String::from("[Interface]\n");
    let mut line = |key: &str, value: &str| {
        // Writing to a String cannot fail.
        let _ = writeln!(out, "{key} = {value}");
    };
    line("PrivateKey", &wg.private_key);
    line("Address", &join(&wg.local_address));
    if !wg.dns.is_empty() {
        line("DNS", &join(&wg.dns));
    }
    if let Some(mtu) = wg.mtu {
        line("MTU", &mtu.to_string());
    }
    for (field, value) in awg.map(pairs).unwrap_or_default() {
        let value = match value {
            AwgValue::Number(n) => n.to_string(),
            AwgValue::Range(range) => range.to_string(),
            AwgValue::Text(text) => text.to_owned(),
            AwgValue::Switch(on) => if on { "on" } else { "off" }.to_owned(),
        };
        line(field.conf_name(), &value);
    }
    let keepalive_range = awg.and_then(|a| a.keepalive_range);
    for peer in &wg.peers {
        out.push_str("\n[Peer]\n");
        let mut line = |key: &str, value: &str| {
            let _ = writeln!(out, "{key} = {value}");
        };
        line("PublicKey", &peer.public_key);
        if let Some(psk) = &peer.pre_shared_key {
            line("PresharedKey", psk);
        }
        match peer.allowed_ips.is_empty() {
            true => line("AllowedIPs", "0.0.0.0/0, ::/0"),
            false => line("AllowedIPs", &join(&peer.allowed_ips)),
        }
        line("Endpoint", &endpoint(&peer.host, peer.port));
        let keepalive = keepalive_range.map(|r| r.to_string());
        if let Some(keepalive) = keepalive.or(peer.keepalive_s.map(|s| s.to_string())) {
            line("PersistentKeepalive", &keepalive);
        }
        if let Some([a, b, c]) = peer.reserved {
            line("Reserved", &format!("{a}, {b}, {c}"));
        }
    }
    Some(out)
}

fn join<T: ToString>(items: &[T]) -> String {
    let items: Vec<String> = items.iter().map(ToString::to_string).collect();
    items.join(", ")
}

/// `host:port`, an IPv6 address in brackets.
fn endpoint(host: &Host, port: u16) -> String {
    match host {
        Host::Ip(ip) if ip.is_ipv6() => format!("[{ip}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}
