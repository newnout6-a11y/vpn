//! Pre-resolution support (xray-engine spec §3.4, pure part): the host names an Xray config
//! would otherwise resolve itself, and their substitution by IPs.
//!
//! Why: under the TUN, a lookup by Xray goes through the Windows DNS client, is hijacked by
//! sing-box and answered via `proxy-out` -> the same Xray, which waits for it (the old app's
//! "circular DNS deadlock"). So the app resolves first ([`super::resolve_hosts`]) and Xray only
//! gets IP literals.
use std::collections::HashMap;
use std::net::IpAddr;

use serde_json::{Map, Value};

use super::config::ProxyGraph;

impl ProxyGraph {
    /// Every server address that is a host name (VLESS / VMess `vnext`, Trojan / SS `servers`,
    /// the simple `settings.address` form, XHTTP `extra.downloadSettings.address`), unique, in
    /// config order.
    pub fn hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        for outbound in self.outbounds() {
            let download = download_settings(outbound).into_iter();
            let addresses = node_holders(outbound).chain(download);
            for host in addresses.filter_map(|h| h.get("address").and_then(Value::as_str)) {
                let host = host.trim();
                if !host.is_empty() && !is_literal(host) && !hosts.iter().any(|h| h == host) {
                    hosts.push(host.to_owned());
                }
            }
        }
        hosts
    }

    /// Replaces each address found in `resolved` by its IP and pins the names Xray would
    /// otherwise derive from it: TLS / REALITY `serverName` when empty, and without TLS the
    /// ws / httpupgrade / xhttp `host` or the gRPC `authority`. Explicit names are never touched
    /// (a REALITY server name is the camouflage). Hosts missing from `resolved` stay names.
    pub fn substitute(&mut self, resolved: &HashMap<String, IpAddr>) {
        for outbound in self.outbounds_mut() {
            let mut pinned = None;
            if let Some(settings) = outbound.get_mut("settings") {
                for holder in node_holders_mut(settings) {
                    if let Some(host) = replace_address(holder, resolved) {
                        pinned.get_or_insert(host);
                    }
                }
            }
            if let (Some(host), Some(stream)) = (pinned, outbound.get_mut("streamSettings")) {
                pin_names(stream, &host);
            }
            if let Some(download) = download_settings_mut(outbound)
                && let Some(host) = replace_address(download, resolved)
            {
                // `downloadSettings` is itself a stream object with its own security.
                pin_names(download, &host);
            }
        }
    }

    fn outbounds(&self) -> &[Value] {
        match self {
            ProxyGraph::Translated(outbound) => std::slice::from_ref(outbound),
            ProxyGraph::Native(graph) => &graph.outbounds,
        }
    }

    fn outbounds_mut(&mut self) -> &mut [Value] {
        match self {
            ProxyGraph::Translated(outbound) => std::slice::from_mut(outbound),
            ProxyGraph::Native(graph) => &mut graph.outbounds,
        }
    }
}

/// The objects of an outbound that carry a server `address`: the simple `settings.address`
/// form, else every `vnext` / `servers` entry.
fn node_holders(outbound: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    let Some(settings) = outbound.get("settings") else {
        return Box::new(std::iter::empty());
    };
    if settings.get("address").is_some() {
        return Box::new(std::iter::once(settings));
    }
    let lists = ["vnext", "servers"].into_iter();
    Box::new(lists.filter_map(|k| settings.get(k)?.as_array()).flatten())
}

fn node_holders_mut(settings: &mut Value) -> Vec<&mut Value> {
    if settings.get("address").is_some() {
        return vec![settings];
    }
    let Some(map) = settings.as_object_mut() else {
        return Vec::new();
    };
    map.iter_mut()
        .filter(|(k, _)| *k == "vnext" || *k == "servers")
        .filter_map(|(_, v)| v.as_array_mut())
        .flatten()
        .collect()
}

/// XHTTP split download (`xhttpSettings`, or the old `splithttpSettings`, `.extra.downloadSettings`).
fn download_settings(outbound: &Value) -> Option<&Value> {
    let stream = outbound.get("streamSettings")?;
    ["xhttpSettings", "splithttpSettings"]
        .into_iter()
        .find_map(|k| stream.get(k)?.get("extra")?.get("downloadSettings"))
        .filter(|d| d.is_object())
}

fn download_settings_mut(outbound: &mut Value) -> Option<&mut Value> {
    let stream = outbound.get_mut("streamSettings")?.as_object_mut()?;
    let key = ["xhttpSettings", "splithttpSettings"]
        .into_iter()
        .find(|k| {
            stream
                .get(*k)
                .and_then(|x| x.get("extra")?.get("downloadSettings"))
                .is_some()
        })?;
    let download = stream
        .get_mut(key)?
        .get_mut("extra")?
        .get_mut("downloadSettings")?;
    download.is_object().then_some(download)
}

/// Writes the IP of `holder.address` when it is a resolved host name; returns that name.
fn replace_address(holder: &mut Value, resolved: &HashMap<String, IpAddr>) -> Option<String> {
    let host = holder.get("address")?.as_str()?.trim().to_owned();
    let ip = resolved.get(&host)?;
    holder
        .as_object_mut()?
        .insert("address".into(), Value::String(ip.to_string()));
    Some(host)
}

/// Pins the names Xray would derive from the (now IP) dial address of `stream`.
fn pin_names(stream: &mut Value, host: &str) {
    let get = |k: &str| {
        stream
            .get(k)
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    let security = get("security").unwrap_or_default();
    // `method` is the newer spelling and wins when both are present.
    let network = get("method").or_else(|| get("network")).unwrap_or_default();
    let target: Option<(&str, &str)> = match (security.as_str(), network.as_str()) {
        ("tls", _) => Some(("tlsSettings", "serverName")),
        ("reality", _) => Some(("realitySettings", "serverName")),
        (_, "ws" | "websocket") if !ws_host_header(stream) => Some(("wsSettings", "host")),
        (_, "httpupgrade") => Some(("httpupgradeSettings", "host")),
        (_, "xhttp") => Some(("xhttpSettings", "host")),
        (_, "splithttp") => Some(("splithttpSettings", "host")),
        (_, "grpc") => Some(("grpcSettings", "authority")),
        _ => None,
    };
    let Some((object, key)) = target else {
        return;
    };
    let Some(stream) = stream.as_object_mut() else {
        return;
    };
    let settings = stream
        .entry(object)
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(settings) = settings.as_object_mut() {
        let empty = settings
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(|v| v.trim().is_empty());
        if empty {
            settings.insert(key.into(), Value::String(host.to_owned()));
        }
    }
}

/// A ws `headers.Host` already names the host (Xray: `host` > `headers` > address).
fn ws_host_header(stream: &Value) -> bool {
    stream
        .get("wsSettings")
        .and_then(|ws| ws.get("headers"))
        .and_then(Value::as_object)
        .is_some_and(|h| {
            h.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("host") && v.as_str().is_some_and(|v| !v.trim().is_empty())
            })
        })
}

fn is_literal(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}
