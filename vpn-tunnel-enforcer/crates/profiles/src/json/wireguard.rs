//! WireGuard from sing-box JSON: the 1.13+ endpoint (`address`, `peers[]`) or the legacy outbound
//! the Electron app stored (`server`, `peer_public_key`, `local_address`, `dns_servers`).
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::{Map, Value};

use super::parts::DIAL_TYPED;
use super::scan::Scan;
use super::values::{list, port, positive_u32, text};
use crate::common::fields::parse_host;
use crate::common::wg::interface_address;
use crate::model::{Host, WgPeer, WireGuard};

const TYPED: &[&str] = &[
    "type",
    "tag",
    "server",
    "server_port",
    "address",
    "local_address",
    "private_key",
    "peers",
    "peer_public_key",
    "pre_shared_key",
    "reserved",
    "mtu",
    "dns_servers",
];
const EXTRA: &[&str] = &[
    "udp_timeout",
    "workers",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
];
const PEER_TYPED: &[&str] = &[
    "address",
    "server",
    "port",
    "server_port",
    "public_key",
    "pre_shared_key",
    "allowed_ips",
    "persistent_keepalive_interval",
    "reserved",
];

/// The tunnel plus the first peer's address, which stands for the profile's server.
pub(crate) fn import(
    o: &Map<String, Value>,
    scan: &mut Scan,
) -> Result<(Host, u16, WireGuard), String> {
    let mut typed = TYPED.to_vec();
    typed.extend_from_slice(DIAL_TYPED);
    // `system`, `name`, `listen_port` stay out on purpose: the app owns the only system interface,
    // and a profile must not make the elevated core create another one or open a listening port.
    scan.sort_keys(o, "", &typed, EXTRA);
    let private_key = text(o, &["private_key"]).ok_or("missing private_key")?;
    let address = o.get("address").or_else(|| o.get("local_address"));
    let local_address = address.map(prefixes).transpose()?.unwrap_or_default();
    if local_address.is_empty() {
        return Err("missing local address".into());
    }
    let peers = match o.get("peers").and_then(Value::as_array) {
        Some(raw) => {
            let only = raw.len() == 1;
            raw.iter()
                .map(|p| {
                    let p = p.as_object().ok_or("peer is not an object")?;
                    scan.sort_keys(p, "peers", PEER_TYPED, &[]);
                    peer(p, only, &["public_key"], scan)
                })
                .collect::<Result<Vec<_>, String>>()?
        }
        None => vec![peer(o, true, &["peer_public_key", "public_key"], scan)?],
    };
    let first = peers.first().ok_or("no peers")?;
    let (server, server_port) = (first.host.clone(), first.port);
    let dns = o
        .get("dns_servers")
        .map(list)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    let mtu = o
        .get("mtu")
        .and_then(positive_u32)
        .and_then(|m| u16::try_from(m).ok());
    Ok((
        server,
        server_port,
        WireGuard {
            private_key: private_key.to_owned(),
            local_address,
            mtu,
            dns,
            peers,
        },
    ))
}

/// One peer; `only` peers default to the full tunnel, several peers must say what each carries.
fn peer(
    p: &Map<String, Value>,
    only: bool,
    key_names: &[&str],
    scan: &mut Scan,
) -> Result<WgPeer, String> {
    let raw_host = text(p, &["address", "server"]).ok_or("peer without address")?;
    let peer_host = parse_host(raw_host.trim()).ok_or("invalid peer address")?;
    let peer_port = p
        .get("port")
        .or_else(|| p.get("server_port"))
        .and_then(port)
        .ok_or("peer without a valid port")?;
    let public_key = text(p, key_names).ok_or("peer without public key")?;
    let mut allowed_ips = match p.get("allowed_ips") {
        Some(v) => prefixes(v)?,
        None => Vec::new(),
    };
    if allowed_ips.is_empty() {
        if !only {
            return Err("peer without allowed_ips (required with several peers)".into());
        }
        allowed_ips = ["0.0.0.0/0", "::/0"]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
    }
    let reserved = match p.get("reserved") {
        None => None,
        Some(v) => {
            let bytes = reserved(v);
            if bytes.is_none() {
                scan.unsupported("reserved");
            }
            bytes
        }
    };
    Ok(WgPeer {
        host: peer_host,
        port: peer_port,
        public_key: public_key.to_owned(),
        pre_shared_key: text(p, &["pre_shared_key"]).map(str::to_owned),
        allowed_ips,
        keepalive_s: p
            .get("persistent_keepalive_interval")
            .and_then(positive_u32)
            .and_then(|k| u16::try_from(k).ok()),
        reserved,
    })
}

/// CIDR list; a bare address gets the host prefix (share links give `ip=10.0.0.2`).
fn prefixes(v: &Value) -> Result<Vec<IpNet>, String> {
    let items: Vec<&str> = match v {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a
            .iter()
            .map(|i| i.as_str().ok_or("address entry is not a string"))
            .collect::<Result<_, _>>()?,
        _ => return Err("address list has the wrong type".into()),
    };
    items
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| interface_address(s).ok_or_else(|| format!("invalid address {s}")))
        .collect()
}

/// Exactly three bytes, as a list (`[1, 22, 33]`) or base64 (Go encodes `[]uint8` that way).
fn reserved(v: &Value) -> Option<[u8; 3]> {
    let bytes: Vec<u8> = match v {
        Value::Array(a) => a
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect::<Option<_>>()?,
        Value::String(s) => return crate::common::wg::reserved(s),
        _ => return None,
    };
    bytes.try_into().ok()
}
