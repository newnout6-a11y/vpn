//! `proxy-out` for each upstream kind, plus what the rest of the config needs to know about it.
use std::net::IpAddr;

use serde_json::{Map, Value, json};
use vpnte_base::types::{Creds, ProxyKind};
use vpnte_core::net::{Host, HostPort};
use vpnte_profiles::emit_singbox::SingBoxFragment;

use super::{ConfigError, Upstream};
use crate::slot::{Slot, SlotEndpoint};
use crate::tags::{DNS_BOOTSTRAP, PROXY_OUT, SLOT_TAGS};

/// The upstream as config pieces.
#[derive(Debug)]
pub(super) struct UpstreamParts {
    pub outbounds: Vec<Value>,
    pub endpoints: Vec<Value>,
    /// Dialed server IPs, excluded from the TUN routes.
    pub exclude: Vec<IpAddr>,
    /// A dialed server is a hostname: `dns-bootstrap` must exist.
    pub needs_bootstrap: bool,
    /// Reject UDP/443 (QUIC) before sniffing.
    pub block_quic: bool,
    /// Drop all remaining UDP (the upstream cannot relay it).
    pub drop_udp: bool,
}

pub(super) fn upstream(up: &Upstream) -> Result<UpstreamParts, ConfigError> {
    match up {
        Upstream::LocalProxy { addr, kind, creds } => Ok(local_proxy(addr, *kind, creds.as_ref())),
        Upstream::Native { fragment, udp } => {
            check_fragment(fragment)?;
            Ok(UpstreamParts {
                outbounds: fragment.outbounds().to_vec(),
                endpoints: fragment.endpoints().to_vec(),
                exclude: fragment.endpoint_ips(),
                needs_bootstrap: fragment.needs_bootstrap_dns(),
                block_quic: udp.block_quic,
                drop_udp: !udp.udp,
            })
        }
        Upstream::XraySlots { slots, active, udp } => {
            if slots[0].port() == slots[1].port() {
                return Err(ConfigError::InvalidSlots("both slots use one port"));
            }
            let mut outbounds = vec![json!({
                "type": "selector",
                "tag": PROXY_OUT,
                "outbounds": SLOT_TAGS,
                "default": active.tag(),
                "interrupt_exist_connections": true,
            })];
            outbounds.extend(Slot::BOTH.into_iter().zip(slots).map(slot_outbound));
            Ok(UpstreamParts {
                outbounds,
                endpoints: Vec::new(),
                // A permanent exclusion would keep the previous server outside the TUN after a
                // switch; the Xray process is bypassed by its path instead.
                exclude: Vec::new(),
                needs_bootstrap: false,
                block_quic: udp.block_quic,
                drop_udp: !udp.udp,
            })
        }
    }
}

/// An external client's proxy: QUIC is always rejected (a local listener says nothing about
/// the upstream's UDP), other UDP is left to the proxy.
fn local_proxy(addr: &HostPort, kind: ProxyKind, creds: Option<&Creds>) -> UpstreamParts {
    let mut o = Map::new();
    o.insert("type".into(), json!(proxy_type(kind)));
    o.insert("tag".into(), json!(PROXY_OUT));
    if kind == ProxyKind::Socks5 {
        o.insert("version".into(), json!("5"));
    }
    // sing-box resolves names only through DNS servers, and a public resolver need not know
    // "localhost": it is this machine's loopback, like for the proxy client listening there.
    let server = match addr.host() {
        Host::Name(name) if name == "localhost" => "127.0.0.1".to_owned(),
        host => host.to_string(),
    };
    let needs_bootstrap = server.parse::<IpAddr>().is_err();
    o.insert("server".into(), json!(server));
    o.insert("server_port".into(), json!(addr.port()));
    if let Some(c) = creds.filter(|c| !c.user.is_empty()) {
        o.insert("username".into(), json!(c.user));
        o.insert("password".into(), json!(c.pass));
    }
    if kind == ProxyKind::Socks5 {
        o.insert("udp_fragment".into(), json!(true));
    }
    if needs_bootstrap {
        o.insert(
            "domain_resolver".into(),
            json!({ "server": DNS_BOOTSTRAP, "strategy": "ipv4_only" }),
        );
    }
    UpstreamParts {
        outbounds: vec![Value::Object(o)],
        endpoints: Vec::new(),
        exclude: Vec::new(),
        needs_bootstrap,
        block_quic: true,
        drop_udp: false,
    }
}

fn proxy_type(kind: ProxyKind) -> &'static str {
    match kind {
        ProxyKind::Socks5 => "socks",
        ProxyKind::Http => "http",
    }
}

/// One authenticated Xray SOCKS slot on loopback (the endpoint is valid by construction).
fn slot_outbound((slot, ep): (Slot, &SlotEndpoint)) -> Value {
    json!({
        "type": "socks",
        "tag": slot.tag(),
        "version": "5",
        "server": "127.0.0.1",
        "server_port": ep.port(),
        "username": ep.creds().user,
        "password": ep.creds().pass,
        "udp_fragment": true,
    })
}

/// The fragment must be tagged `proxy-out`, and every entry that dials a hostname must resolve
/// it with `dns-bootstrap`: `route.default_domain_resolver` is `dns-remote`, which itself goes
/// through `proxy-out`, so such a server could never be reached.
fn check_fragment(f: &SingBoxFragment) -> Result<(), ConfigError> {
    let first = f.outbounds().first().or(f.endpoints().first());
    if first.and_then(|v| v.get("tag")).and_then(Value::as_str) != Some(PROXY_OUT) {
        return Err(ConfigError::BadUpstream("fragment is not tagged proxy-out"));
    }
    let dialers = f
        .outbounds()
        .iter()
        .filter(|o| o.get("detour").is_none())
        .chain(f.endpoints());
    for entry in dialers {
        if dials_hostname(entry) && resolver(entry) != Some(DNS_BOOTSTRAP) {
            return Err(ConfigError::BadUpstream(
                "hostname server without the bootstrap resolver",
            ));
        }
    }
    Ok(())
}

/// The outbound's `server`, or any WireGuard peer `address`, is not an IP literal.
fn dials_hostname(entry: &Value) -> bool {
    let is_name = |v: &Value| v.as_str().is_some_and(|h| h.parse::<IpAddr>().is_err());
    let peers = entry.get("peers").and_then(Value::as_array);
    entry.get("server").is_some_and(is_name)
        || peers.is_some_and(|ps| ps.iter().filter_map(|p| p.get("address")).any(is_name))
}

/// Server tag of `domain_resolver` (string or object form).
fn resolver(entry: &Value) -> Option<&str> {
    match entry.get("domain_resolver")? {
        Value::String(tag) => Some(tag),
        other => other.get("server").and_then(Value::as_str),
    }
}
