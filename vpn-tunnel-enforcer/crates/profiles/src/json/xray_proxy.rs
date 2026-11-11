//! Xray `socks`, `http` and `wireguard` outbounds -> typed profiles (sing-box runs them as they
//! are; the engine translates them for Xray). They used to vanish from an import silently.
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::{Map, Value};

use super::values::{list, positive_u32, text, text_or_number};
use crate::common::fields::{parse_host, parse_port};
use crate::common::wg::{interface_address, unrouted_peer};
use crate::model::{DialPrefs, Host, Kind, Note, Profile, SkipReason, Source, WgPeer, WireGuard};

/// Xray's interface addresses when a WireGuard outbound names none (`infra/conf/wireguard.go`).
const WG_DEFAULT_ADDRESS: [&str; 2] = ["10.0.0.1", "fd59:7153:2388:b5fd:0000:0000:0000:0001"];
/// WireGuard settings the model reads; `noKernelTun` only picks Xray's packet stack on Linux.
const WG_TYPED: &[&str] = &[
    "secretKey",
    "address",
    "peers",
    "mtu",
    "reserved",
    "remoteDNS",
    "noKernelTun",
];
const PEER_TYPED: &[&str] = &[
    "endpoint",
    "publicKey",
    "preSharedKey",
    "keepAlive",
    "allowedIPs",
];

/// SOCKS5 / HTTP credentials: Xray 26 writes `user` / `pass` next to the address, older configs
/// one entry of `servers[].users[]` (the caller hands in that entry).
pub(super) fn proxy_kind(proto: &str, user: &Map<String, Value>) -> Kind {
    let username = text_or_number(user, &["user", "username"]);
    let password = text_or_number(user, &["pass", "password"]);
    match proto {
        "socks" => Kind::Socks { username, password },
        _ => Kind::Http { username, password },
    }
}

/// One WireGuard profile from Xray's `settings` (the first peer's endpoint stands for the server).
pub(super) fn wireguard(
    settings: &Map<String, Value>,
    name: String,
) -> Result<Profile, SkipReason> {
    let invalid = |detail: &str| SkipReason::Invalid {
        scheme: "wireguard".into(),
        detail: detail.into(),
    };
    let mut notes: Vec<Note> = settings
        .keys()
        .filter(|k| !WG_TYPED.contains(&k.as_str()))
        .map(|k| Note::UnsupportedField(format!("settings.{k}")))
        .collect();
    let private_key = text(settings, &["secretKey"]).ok_or(SkipReason::MissingCredential)?;
    let local_address = match settings.get("address").map(list) {
        Some(items) if !items.is_empty() => items
            .iter()
            .map(|a| interface_address(a).ok_or_else(|| invalid("invalid interface address")))
            .collect::<Result<Vec<IpNet>, _>>()?,
        _ => WG_DEFAULT_ADDRESS
            .iter()
            .filter_map(|a| interface_address(a))
            .collect(),
    };
    // Xray applies `reserved` to every peer; all zero is WireGuard's own default.
    let reserved = match settings.get("reserved") {
        None => None,
        Some(v) => Some(reserved(v).ok_or_else(|| invalid("reserved must be three bytes"))?),
    }
    .filter(|r| *r != [0, 0, 0]);
    let raw_peers = settings.get("peers").and_then(Value::as_array);
    let mut peers = Vec::new();
    for raw in raw_peers.into_iter().flatten() {
        let p = raw
            .as_object()
            .ok_or_else(|| invalid("peer is not an object"))?;
        notes.extend(
            p.keys()
                .filter(|k| !PEER_TYPED.contains(&k.as_str()))
                .map(|k| Note::UnsupportedField(format!("settings.peers.{k}"))),
        );
        let (host, port) = text(p, &["endpoint"])
            .and_then(endpoint)
            .ok_or_else(|| invalid("peer without a valid endpoint"))?;
        let allowed_ips = match p.get("allowedIPs").map(list) {
            Some(items) => items
                .iter()
                .map(|a| interface_address(a).ok_or_else(|| invalid("invalid allowedIPs entry")))
                .collect::<Result<Vec<IpNet>, _>>()?,
            None => Vec::new(),
        };
        peers.push(WgPeer {
            host,
            port,
            public_key: text(p, &["publicKey"])
                .ok_or_else(|| invalid("peer without publicKey"))?
                .to_owned(),
            pre_shared_key: text(p, &["preSharedKey"]).map(str::to_owned),
            allowed_ips,
            keepalive_s: p
                .get("keepAlive")
                .and_then(positive_u32)
                .and_then(|k| u16::try_from(k).ok()),
            reserved,
        });
    }
    // Several peers must say what each carries; a lone one carries everything (Xray's default).
    if unrouted_peer(&peers) {
        return Err(invalid(
            "peer without allowedIPs (required with several peers)",
        ));
    }
    if let [only] = peers.as_mut_slice()
        && only.allowed_ips.is_empty()
    {
        only.allowed_ips = ["0.0.0.0/0", "::/0"]
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
    }
    let first = peers.first().ok_or_else(|| invalid("no peers"))?;
    let (server, server_port) = (first.host.clone(), first.port);
    let dns: Vec<IpAddr> = settings
        .get("remoteDNS")
        .map(list)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let wg = WireGuard {
        private_key: private_key.to_owned(),
        local_address,
        mtu: settings
            .get("mtu")
            .and_then(positive_u32)
            .and_then(|m| u16::try_from(m).ok()),
        dns,
        peers,
    };
    Ok(Profile {
        name,
        description: None,
        server,
        port: server_port,
        kind: Kind::Wireguard(wg),
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs::default(),
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes,
    })
}

/// `host:port` or `[v6]:port`.
fn endpoint(raw: &str) -> Option<(Host, u16)> {
    let (host, port) = raw.trim().rsplit_once(':')?;
    if host.contains(':') && !host.starts_with('[') {
        return None;
    }
    Some((parse_host(host.trim())?, parse_port(port.trim())?))
}

/// Exactly three bytes, as Xray writes them (`[0, 0, 0]`).
fn reserved(v: &Value) -> Option<[u8; 3]> {
    let bytes: Vec<u8> = v
        .as_array()?
        .iter()
        .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
        .collect::<Option<_>>()?;
    bytes.try_into().ok()
}
