//! sing-box config of one slot (spec 6.6): an unauthenticated `mixed` inbound (HTTP + SOCKS) on
//! `127.0.0.1:<port>`, the upstream tagged [`PROXY_OUT_TAG`], localhost and private destinations
//! direct, anything else rejected. There is no `dns` block: the manager resolves the server name
//! itself and [`pin`]s the IP, so no plaintext bootstrap query leaves outside the tunnel (B-21).
//! `auto_detect_interface` stays off on purpose: the slot's sockets follow the OS routes, and the
//! main TUN hands the bundled engine's own traffic straight to `direct-out` (no double hop).
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Map, Value, json};
use vpnte_base::types::Creds;
use vpnte_profiles::emit_singbox::{EmitPolicy, SingBoxFragment, emit_singbox};
use vpnte_profiles::model::{DialPrefs, Host, Kind, Profile, Source};

use crate::model::ProxyError;

/// Tag of the slot's `mixed` inbound.
pub const INBOUND_TAG: &str = "external-mixed-in";
/// Tag the upstream fragment must carry (emit it with this tag).
pub const PROXY_OUT_TAG: &str = "proxy-out";
/// Tag of the direct outbound for localhost and private destinations.
pub const DIRECT_TAG: &str = "direct-out";

/// Builds the config of a slot listening on `port`. `upstream` is
/// `emit_singbox(&profile, PROXY_OUT_TAG, &EmitPolicy::default())` with its server pinned, or
/// [`xray_bridge`] for profiles that run on Xray. Dial keys that need a DNS server
/// (`domain_resolver`, `domain_strategy`) are dropped: the config has none.
pub fn build(upstream: &SingBoxFragment, port: u16) -> Result<Value, ProxyError> {
    if port == 0 {
        return Err(ProxyError::BadRequest("invalid port".into()));
    }
    let tagged = upstream
        .outbounds()
        .first()
        .or(upstream.endpoints().first())
        .and_then(|entry| entry.get("tag"))
        .and_then(Value::as_str);
    if tagged != Some(PROXY_OUT_TAG) {
        return Err(ProxyError::Engine(format!(
            "upstream is not tagged {PROXY_OUT_TAG}"
        )));
    }
    let mut outbounds: Vec<Value> = upstream.outbounds().iter().map(without_dns_keys).collect();
    outbounds.push(json!({ "type": "direct", "tag": DIRECT_TAG }));
    let mut config = json!({
        "log": { "level": "warn" },
        "inbounds": [{
            "type": "mixed",
            "tag": INBOUND_TAG,
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": outbounds,
    });
    if !upstream.endpoints().is_empty() {
        let endpoints: Vec<Value> = upstream.endpoints().iter().map(without_dns_keys).collect();
        config["endpoints"] = Value::Array(endpoints);
    }
    config["route"] = json!({
        "rules": [
            { "action": "sniff" },
            { "domain": ["localhost"], "outbound": DIRECT_TAG },
            { "domain_suffix": ["localhost"], "outbound": DIRECT_TAG },
            { "ip_cidr": ["127.0.0.0/8", "::1/128"], "outbound": DIRECT_TAG },
            // Private destinations must not reach the remote server's LAN.
            { "ip_is_private": true, "outbound": DIRECT_TAG },
            { "inbound": INBOUND_TAG, "outbound": PROXY_OUT_TAG },
            // Fail closed for anything unmatched (replaces the deprecated `block` outbound, B-2).
            { "action": "reject" },
        ],
        "auto_detect_interface": false,
    });
    Ok(config)
}

/// Upstream of a slot whose profile runs on Xray (B-27): SOCKS5 to the slot's own xray child
/// listening on `127.0.0.1:<xray_port>` with `creds`. Emitted through `emit_singbox` like
/// every other outbound.
pub fn xray_bridge(xray_port: u16, creds: &Creds) -> Result<SingBoxFragment, ProxyError> {
    let bridge = Profile {
        name: "xray-bridge".into(),
        description: None,
        server: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        port: xray_port,
        kind: Kind::Socks {
            username: Some(creds.user.clone()),
            password: Some(creds.pass.clone()),
        },
        tls: None,
        transport: None,
        mux: None,
        dial: DialPrefs {
            udp_fragment: Some(true),
            ..DialPrefs::default()
        },
        native_xray: None,
        singbox_extra: Map::new(),
        source: Source::Json,
        notes: Vec::new(),
    };
    emit_singbox(&bridge, PROXY_OUT_TAG, &EmitPolicy::default())
        .map_err(|e| ProxyError::Engine(format!("cannot build the xray bridge: {e:?}")))
}

fn without_dns_keys(entry: &Value) -> Value {
    let mut entry = entry.clone();
    if let Some(obj) = entry.as_object_mut() {
        obj.remove("domain_resolver");
        obj.remove("domain_strategy");
    }
    entry
}

/// Host names the engine would resolve to dial the upstream: outbound `server`s (a chain member
/// that dials through a `detour` does not dial) and WireGuard peer addresses, without duplicates.
pub fn hostnames(upstream: &SingBoxFragment) -> Vec<String> {
    let servers = upstream
        .outbounds()
        .iter()
        .filter(|o| o.get("detour").is_none())
        .filter_map(|o| o.get("server").and_then(Value::as_str));
    let peers = upstream
        .endpoints()
        .iter()
        .filter_map(|e| e.get("peers").and_then(Value::as_array))
        .flatten()
        .filter_map(|p| p.get("address").and_then(Value::as_str));
    let mut names: Vec<String> = Vec::new();
    for name in servers.chain(peers) {
        let bare = name.trim_start_matches('[').trim_end_matches(']');
        if bare.parse::<IpAddr>().is_err() && !names.iter().any(|n| n.eq_ignore_ascii_case(name)) {
            names.push(name.to_owned());
        }
    }
    names
}

/// Dials `ip` wherever the upstream dialed `host`, keeping the name where the server expects it
/// (spec 6.7, B-4): the TLS server name (SNI and certificate check; a Reality or provider SNI is
/// kept), the WebSocket `Host` header, the HTTPUpgrade host and the host of a plain-HTTP
/// transport. Without these, sing-box would send the IP and CDN-fronted servers reject it.
pub fn pin(upstream: &mut SingBoxFragment, host: &str, ip: IpAddr) {
    let entries: &mut [Value] = match upstream {
        SingBoxFragment::Outbound(entry) | SingBoxFragment::Endpoint(entry) => {
            std::slice::from_mut(entry)
        }
        SingBoxFragment::Chain(list) => list,
    };
    let is_host = |v: &Value| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(host));
    for entry in entries.iter_mut().filter_map(Value::as_object_mut) {
        if entry.get("server").is_some_and(is_host) {
            entry.insert("server".into(), ip.to_string().into());
            keep_server_name(entry, host);
        }
        if let Some(peers) = entry.get_mut("peers").and_then(Value::as_array_mut) {
            for peer in peers.iter_mut().filter_map(Value::as_object_mut) {
                if peer.get("address").is_some_and(is_host) {
                    peer.insert("address".into(), ip.to_string().into());
                }
            }
        }
    }
}

fn keep_server_name(outbound: &mut Map<String, Value>, host: &str) {
    let tls = outbound.get_mut("tls").and_then(Value::as_object_mut);
    let tls_on = tls
        .as_ref()
        .is_some_and(|t| t.get("enabled").and_then(Value::as_bool) == Some(true));
    // As before: any TLS object not explicitly disabled gets the name (ignored when TLS is off).
    if let Some(tls) = tls
        && tls.get("enabled").and_then(Value::as_bool) != Some(false)
        && tls
            .get("server_name")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        tls.insert("server_name".into(), host.into());
    }
    let Some(transport) = outbound.get_mut("transport").and_then(Value::as_object_mut) else {
        return;
    };
    match transport.get("type").and_then(Value::as_str) {
        Some("ws") => {
            let headers = transport.entry("headers").or_insert_with(|| json!({}));
            if let Some(headers) = headers.as_object_mut()
                && !headers.keys().any(|k| k.eq_ignore_ascii_case("host"))
            {
                headers.insert("Host".into(), host.into());
            }
        }
        Some("httpupgrade")
            if transport
                .get("host")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty) =>
        {
            transport.insert("host".into(), host.into());
        }
        // HTTP/2 over TLS sends a fixed default host; plain HTTP/1 would send the server address.
        Some("http")
            if !tls_on
                && transport
                    .get("host")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty) =>
        {
            transport.insert("host".into(), json!([host]));
        }
        _ => {}
    }
}

/// The address to pin from what the resolver returned: the first IPv4 address, else the first.
pub fn preferred_address(addrs: &[IpAddr]) -> Option<IpAddr> {
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .copied()
}

#[cfg(test)]
mod check;
#[cfg(test)]
mod tests;
