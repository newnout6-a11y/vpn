//! Native (sing-box) upstream: the app resolves the server name in the full order of
//! `vpnte_core::resolve::resolve_server` (direct DoH / TCP chain, the OS resolver, the last
//! known address) and sing-box dials the address. Left to sing-box, an outbound's
//! `domain_resolver` names exactly one DNS server (DoH 1.1.1.1), so a network that blocks
//! 1.1.1.1:443 would fail where the old UDP bootstrap worked. The name stays wherever the server
//! sees it, exactly as sing-box 1.14 sent it before: the TLS server name, the WebSocket and
//! plain HTTP-upgrade `Host` (`name:port`), the plain-HTTP host (`name`). A literal address
//! needs nothing; a name that cannot be pinned keeps sing-box's own lookup, with a warning.
use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_engine::xray_config::{ResolveFault, ResolvePath};
use vpnte_profiles::emit_singbox::SingBoxFragment;

use super::engines::Engines;

/// Resolves the names `fragment` dials and pins them; returns what the user must be told (a
/// last known address stands in, or a name stays with sing-box's lookup).
pub(super) async fn pin_native(
    engines: &dyn Engines,
    fragment: &mut SingBoxFragment,
    op: &CancellationToken,
) -> AppResult<Vec<Msg>> {
    let names = dialed_names(fragment);
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let resolved = match engines.resolve(&names, ResolvePath::Direct, op).await {
        Ok(resolved) => resolved,
        Err(ResolveFault::Cancelled) => return Err(AppError::cancelled()),
        Err(fault) => {
            tracing::warn!(error = %fault, "native server name not pre-resolved; sing-box looks it up over DoH");
            return Ok(vec![Msg::new("tunnel.runtime.serverNotPreResolved")]);
        }
    };
    let mut warnings: Vec<Msg> = resolved.warning.into_iter().collect();
    if !pin(fragment, &resolved.addrs) {
        tracing::warn!("a native server name keeps sing-box's own lookup");
        warnings.push(Msg::new("tunnel.runtime.serverNotPreResolved"));
    }
    Ok(warnings)
}

/// The host names the fragment's dialers connect to (deduplicated, in order).
pub(super) fn dialed_names(f: &SingBoxFragment) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let dialers = f
        .outbounds()
        .iter()
        .chain(f.endpoints())
        .filter(|e| dials(e));
    for entry in dialers {
        let server = entry.get("server").and_then(Value::as_str);
        let peers = entry
            .get("peers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        let addrs = server
            .into_iter()
            .chain(peers.filter_map(|p| p.get("address").and_then(Value::as_str)));
        for name in addrs.filter(|a| is_name(a)) {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_owned());
            }
        }
    }
    names
}

/// Puts the resolved address in place of every dialed name; false when some name stays (no
/// address, one the entry's resolver strategy would not dial, or a transport that would then
/// show the server the address instead of the name).
pub(super) fn pin(f: &mut SingBoxFragment, addrs: &HashMap<String, IpAddr>) -> bool {
    let entries: Vec<&mut Value> = match f {
        SingBoxFragment::Outbound(e) | SingBoxFragment::Endpoint(e) => vec![e],
        SingBoxFragment::Chain(list) => list.iter_mut().collect(),
    };
    let mut all = true;
    for entry in entries.into_iter().filter(|e| dials(e)) {
        all &= pin_entry(entry, addrs);
    }
    all
}

/// An entry with `detour` (the Shadowsocks half of a ShadowTLS chain) never dials its server.
fn dials(entry: &Value) -> bool {
    entry.get("detour").is_none()
}

fn is_name(addr: &str) -> bool {
    addr.parse::<IpAddr>().is_err()
}

/// One dialer: its `server`, then its WireGuard peers; `domain_resolver` goes once no name is
/// left (`dns-bootstrap` is not in a config whose upstream dials no name).
fn pin_entry(entry: &mut Value, addrs: &HashMap<String, IpAddr>) -> bool {
    let fits = |ip: IpAddr| match entry
        .pointer("/domain_resolver/strategy")
        .and_then(Value::as_str)
    {
        Some("ipv6_only") => ip.is_ipv6(),
        Some("prefer_ipv4" | "prefer_ipv6") => true,
        // The emitter's default and the tunnel's DNS strategy.
        _ => ip.is_ipv4(),
    };
    let address = |name: &str| addrs.get(name).copied().filter(|ip| fits(*ip));
    let server = entry
        .get("server")
        .and_then(Value::as_str)
        .filter(|s| is_name(s));
    let server = server.map(|name| (name.to_owned(), address(name)));
    let mut peers: Vec<(usize, Option<IpAddr>)> = Vec::new();
    if let Some(list) = entry.get("peers").and_then(Value::as_array) {
        for (i, peer) in list.iter().enumerate() {
            if let Some(name) = peer
                .get("address")
                .and_then(Value::as_str)
                .filter(|a| is_name(a))
            {
                peers.push((i, address(name)));
            }
        }
    }
    let mut all = true;
    if let Some((name, ip)) = server {
        match ip {
            Some(ip) if keep_name(entry, &name) => entry["server"] = json!(ip.to_string()),
            _ => all = false,
        }
    }
    for (i, ip) in peers {
        match ip {
            Some(ip) => entry["peers"][i]["address"] = json!(ip.to_string()),
            None => all = false,
        }
    }
    if all && let Some(o) = entry.as_object_mut() {
        o.remove("domain_resolver");
    }
    all
}

/// Keeps `name` where the server sees it once `server` holds the address (sing-box 1.14 derives
/// each of these from the dialed address when unset); false, untouched, when that is impossible:
/// gRPC without TLS takes its authority from the address, Shadowsocks' v2ray-plugin over TLS
/// without `host` its server name, and neither can be told otherwise.
fn keep_name(entry: &mut Value, name: &str) -> bool {
    let tls = entry.pointer("/tls/enabled").and_then(Value::as_bool) == Some(true);
    let kind = entry.pointer("/transport/type").and_then(Value::as_str);
    if kind == Some("grpc") && !tls {
        return false;
    }
    if entry.get("plugin").and_then(Value::as_str) == Some("v2ray-plugin") {
        let opts = entry.get("plugin_opts").and_then(Value::as_str);
        let has = |key: &str| {
            let mut keys = opts.unwrap_or_default().split(';');
            keys.any(|o| o.split('=').next().is_some_and(|k| k.trim() == key))
        };
        if has("tls") && !has("host") {
            return false;
        }
    }
    let with_port = match entry.get("server_port").and_then(Value::as_u64) {
        Some(port) => format!("{name}:{port}"),
        None => name.to_owned(),
    };
    let unset = |v: Option<&Value>| v.and_then(Value::as_str).is_none_or(str::is_empty);
    if tls && unset(entry.pointer("/tls/server_name")) {
        entry["tls"]["server_name"] = json!(name);
    }
    let Some(t) = entry.get_mut("transport") else {
        return true;
    };
    match t.get("type").and_then(Value::as_str) {
        // ws: `Host` from the headers (any case), else the dialed `host:port`.
        Some("ws") if !has_host_header(t) => t["headers"]["Host"] = json!(with_port),
        // httpupgrade: `host`, else the TLS server name, else the dialed `host:port`.
        Some("httpupgrade") if !tls && unset(t.get("host")) => t["host"] = json!(with_port),
        // http: `host`, else (HTTP/1, no TLS) the dialed host; with TLS a fixed placeholder.
        Some("http") if !tls && t.get("host").is_none_or(is_empty_list) => {
            t["host"] = json!([name]);
        }
        _ => {}
    }
    true
}

/// A non-empty `Host` header (sing-box takes a string or a list per header).
fn has_host_header(transport: &Value) -> bool {
    let headers = transport.get("headers").and_then(Value::as_object);
    headers.is_some_and(|h| {
        h.iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("host") && !is_empty_list(v) && !v.is_null())
    })
}

/// No value: an empty string or an empty list (sing-box's listable options take both).
fn is_empty_list(v: &Value) -> bool {
    v.as_array().is_some_and(Vec::is_empty) || v.as_str().is_some_and(str::is_empty)
}

#[cfg(test)]
mod tests;
