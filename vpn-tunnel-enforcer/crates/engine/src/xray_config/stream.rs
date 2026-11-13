//! `streamSettings` of a translated outbound: transport method and TLS / REALITY.
//!
//! Every name Xray would otherwise derive from the dial address (SNI, ws / httpupgrade / xhttp
//! Host, gRPC authority without TLS) is written out here, because pre-resolution later replaces
//! the address with an IP and CDN-fronted servers fail on an IP Host or SNI.
use serde_json::{Map, Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Host, Profile, Tls, Transport};
use vpnte_profiles::xray_native::NativeError;

use super::XrayConfigError;
use super::ech::config_list;
use super::fingerprint::fingerprint;
use super::select::SingBoxOnly;

/// The key's TLS tricks as a `finalmask` fragment (item 18).
mod tricks;

/// Xray reads WebSocket early data from `?ed=` in the path; 8192 is its documented maximum.
const MAX_EARLY_DATA: u32 = 8192;
/// Keys that make the (elevated) engine read or write a local file.
const FILE_KEYS: [&str; 5] = [
    "certificateFile",
    "keyFile",
    "echConfigListFile",
    "sessionTicketKeyFile",
    "masterKeyLog",
];
/// XHTTP connection reuse when the provider sets none (ru-2026 R3, XTLS discussion #4113): a few
/// long-lived connections instead of a handshake burst, which RU DPI answers with a freeze. Every
/// field is explicit because setting one drops all of Xray's defaults, and those changed between
/// releases (6 -> 3 connections in 26.7.28). `maxConcurrency` stays unset: it excludes
/// `maxConnections`.
fn default_xmux() -> Value {
    json!({
        "maxConnections": "4-6",
        "cMaxReuseTimes": "64-128",
        "hMaxRequestTimes": "600-900",
        "hMaxReusableSecs": "1800-3000",
        "hKeepAlivePeriod": 0,
    })
}

/// Transport and security of `p`; `flow_ok` says whether XTLS `flow` may be used.
pub(super) struct Stream {
    pub settings: Value,
    pub flow_ok: bool,
}

/// `streamSettings` of `p`: `network` + transport settings, then `security` + TLS / REALITY.
pub(super) fn stream(p: &Profile, device: ClientDevice) -> Result<Stream, XrayConfigError> {
    let mut s = Map::new();
    let plain = p.tls.is_none();
    let network = transport(p, &mut s)?;
    match &p.tls {
        None => {
            s.insert("security".into(), json!("none"));
        }
        Some(tls) => match &tls.reality {
            Some(reality) => {
                let mut r = Map::new();
                r.insert("serverName".into(), json!(sni(p, tls)));
                // The REALITY public key; Xray renamed `publicKey` to `password` (old name still read).
                r.insert("password".into(), json!(reality.public_key.trim()));
                r.insert("shortId".into(), json!(reality.short_id.trim()));
                if let Some(key) = reality.mldsa65_key() {
                    r.insert("mldsa65Verify".into(), json!(key));
                }
                r.insert("fingerprint".into(), json!(fingerprint(tls, device)));
                if let Some(spider) = non_empty(reality.spider_x.as_deref()) {
                    // Xray refuses a spiderX that does not start with `/`.
                    let spider = if spider.starts_with('/') {
                        spider.to_owned()
                    } else {
                        format!("/{spider}")
                    };
                    r.insert("spiderX".into(), json!(spider));
                }
                s.insert("security".into(), json!("reality"));
                s.insert("realitySettings".into(), Value::Object(r));
            }
            None => {
                let mut t = tls_common(p, tls);
                t.insert("fingerprint".into(), json!(fingerprint(tls, device)));
                if let Some(list) = tls.ech.as_ref().map(config_list).transpose()?.flatten() {
                    t.insert("echConfigList".into(), json!(list));
                }
                s.insert("security".into(), json!("tls"));
                s.insert("tlsSettings".into(), Value::Object(t));
            }
        },
    }
    if let Some(mask) = p
        .tls
        .as_ref()
        .and_then(|tls| tricks::finalmask(p, tls, network))
    {
        s.insert("finalmask".into(), mask);
    }
    let flow_ok =
        (network == "tcp" && !plain) || super::select::vless_encryption(&p.kind).is_some();
    Ok(Stream {
        settings: Value::Object(s),
        flow_ok,
    })
}

/// `tlsSettings` without uTLS and ECH, which a QUIC outbound has not. Never `allowInsecure`
/// (the bundled Xray refuses it): an insecure profile reaches Xray only with a pinned
/// certificate, which replaces the CA check, or with `verifyPeerCertByName`, which keeps the CA
/// check and moves the name check off the SNI.
pub(super) fn tls_common(p: &Profile, tls: &Tls) -> Map<String, Value> {
    let mut t = Map::new();
    t.insert("serverName".into(), json!(sni(p, tls)));
    let alpn: Vec<&str> = tls.alpn.iter().filter_map(|a| non_empty(Some(a))).collect();
    if !alpn.is_empty() {
        // Only an explicit ALPN: Xray's per-transport default (http/1.1 for ws) must stay.
        t.insert("alpn".into(), json!(alpn));
    }
    if let Some(pin) = non_empty(tls.cert_pin_sha256.as_deref()) {
        t.insert("pinnedPeerCertSha256".into(), json!(pin));
    }
    // The SNI stays `serverName`; the certificate is checked against these names instead.
    if let Some(names) = tls.cert_names() {
        t.insert("verifyPeerCertByName".into(), json!(names));
    }
    if let Some(pem) = non_empty(tls.certificate_pem.as_deref()) {
        // sing-box trusts only this certificate; Xray's equivalent is a `verify` root without
        // the system store.
        let lines: Vec<&str> = pem
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        t.insert(
            "certificates".into(),
            json!([{"usage": "verify", "certificate": lines}]),
        );
        t.insert("disableSystemRoot".into(), json!(true));
    }
    for (key, value) in [
        ("minVersion", &tls.min_version),
        ("maxVersion", &tls.max_version),
    ] {
        if let Some(v) = non_empty(value.as_deref()) {
            t.insert(key.into(), json!(v));
        }
    }
    t
}

/// Writes `network` and the transport's settings object; returns the network name.
fn transport(p: &Profile, s: &mut Map<String, Value>) -> Result<&'static str, XrayConfigError> {
    let (network, settings) = match &p.transport {
        None => ("tcp", None),
        Some(Transport::TcpHttpHeader { host, path }) => {
            let paths = list(path);
            let mut request = Map::new();
            request.insert(
                "path".into(),
                if paths.is_empty() {
                    json!(["/"])
                } else {
                    json!(paths)
                },
            );
            let hosts = list(host);
            if !hosts.is_empty() {
                request.insert("headers".into(), json!({ "Host": hosts }));
            }
            let header = json!({"header": {"type": "http", "request": request}});
            ("tcp", Some(("tcpSettings", header)))
        }
        Some(Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header,
        }) => {
            let mut ws = Map::new();
            let path = ws_path(path, *max_early_data, early_data_header.as_deref());
            ws.insert("path".into(), json!(path));
            // `wsSettings.host`, not `headers.Host` (deprecated in Xray, an error elsewhere).
            if let Some(name) = host_name(p, host.as_deref()) {
                ws.insert("host".into(), json!(name));
            }
            ("ws", Some(("wsSettings", Value::Object(ws))))
        }
        Some(Transport::Grpc {
            service_name,
            multi_mode,
        }) => {
            let mut grpc = Map::new();
            grpc.insert("serviceName".into(), json!(service_name));
            grpc.insert("multiMode".into(), json!(*multi_mode == Some(true)));
            // With TLS Xray takes `:authority` from serverName (pinned below); without TLS it
            // would become the resolved IP.
            if p.tls.is_none()
                && let Some(name) = host_name(p, None)
            {
                grpc.insert("authority".into(), json!(name));
            }
            ("grpc", Some(("grpcSettings", Value::Object(grpc))))
        }
        Some(Transport::HttpUpgrade { host, path }) => {
            let mut upgrade = Map::new();
            upgrade.insert("path".into(), json!(or_root(path)));
            if let Some(name) = host_name(p, Some(host)) {
                upgrade.insert("host".into(), json!(name));
            }
            (
                "httpupgrade",
                Some(("httpupgradeSettings", Value::Object(upgrade))),
            )
        }
        Some(Transport::Xhttp {
            host,
            path,
            mode,
            extra,
        }) => {
            let mut xhttp = Map::new();
            xhttp.insert("path".into(), json!(or_root(path)));
            let mut extra = extra.clone();
            // Xray refuses a Host header in XHTTP `headers` ("can't contain host").
            let header_host = extra.as_mut().and_then(take_host_header);
            let host = non_empty(Some(host)).map(str::to_owned).or(header_host);
            if let Some(name) = host_name(p, host.as_deref()) {
                xhttp.insert("host".into(), json!(name));
            }
            if let Some(mode) = non_empty(mode.as_deref()) {
                xhttp.insert("mode".into(), json!(mode));
            }
            // Xray rebuilds the settings from `extra` when it is present (only host, path and
            // mode survive from outside), so the connection reuse goes there.
            let mut extra = Value::Object(extra.unwrap_or_default());
            sanitize_extra(&mut extra)?;
            if let Some(extra) = extra.as_object_mut()
                && !extra.keys().any(|k| k.eq_ignore_ascii_case("xmux"))
            {
                extra.insert("xmux".into(), default_xmux());
            }
            xhttp.insert("extra".into(), extra);
            ("xhttp", Some(("xhttpSettings", Value::Object(xhttp))))
        }
        Some(Transport::Http { .. }) => {
            return Err(XrayConfigError::Feature(SingBoxOnly::H2Transport));
        }
        Some(Transport::Quic) => {
            return Err(XrayConfigError::Feature(SingBoxOnly::QuicTransport));
        }
    };
    s.insert("network".into(), json!(network));
    if let Some((key, value)) = settings {
        s.insert(key.into(), value);
    }
    Ok(network)
}

/// Explicit name, else the TLS / REALITY server name, else the server's host name.
fn host_name(p: &Profile, explicit: Option<&str>) -> Option<String> {
    non_empty(explicit)
        .or_else(|| {
            p.tls
                .as_ref()
                .and_then(|t| non_empty(t.server_name.as_deref()))
        })
        .or(match &p.server {
            Host::Domain(name) => non_empty(Some(name)),
            Host::Ip(_) => None,
        })
        .map(str::to_owned)
}

/// TLS / REALITY server name, else the server itself; Xray wants an IPv6 name in brackets.
pub(super) fn sni(p: &Profile, tls: &Tls) -> String {
    let server = p.server.to_string();
    let name = non_empty(tls.server_name.as_deref()).unwrap_or(server.trim());
    match name.parse::<std::net::Ipv6Addr>() {
        Ok(ip) => format!("[{ip}]"),
        Err(_) => name.to_owned(),
    }
}

/// WebSocket path with sing-box early data moved into `?ed=N` (Xray has no `maxEarlyData` key).
/// Only the `Sec-WebSocket-Protocol` header form exists in Xray: other header names lose 0-RTT
/// ([`early_data_dropped`] reports it).
fn ws_path(path: &str, max_early_data: Option<u32>, header: Option<&str>) -> String {
    let mut path = or_root(path).to_owned();
    let Some(n) = max_early_data.filter(|n| *n > 0) else {
        return path;
    };
    if has_ed_query(&path) || !protocol_header(header) {
        return path;
    }
    path.push(if path.contains('?') { '&' } else { '?' });
    path.push_str(&format!("ed={}", n.min(MAX_EARLY_DATA)));
    path
}

/// sing-box WebSocket early data that Xray cannot send (a header other than
/// `Sec-WebSocket-Protocol`, no `ed` in the path).
pub(super) fn early_data_dropped(transport: Option<&Transport>) -> bool {
    matches!(transport, Some(Transport::Ws {
        path,
        max_early_data: Some(n),
        early_data_header,
        ..
    }) if *n > 0 && !has_ed_query(path) && !protocol_header(early_data_header.as_deref()))
}

fn has_ed_query(path: &str) -> bool {
    path.split_once('?')
        .is_some_and(|(_, q)| q.split('&').any(|kv| kv.split('=').next() == Some("ed")))
}

fn protocol_header(header: Option<&str>) -> bool {
    non_empty(header).is_none_or(|h| h.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
}

/// Removes `Host` (any case) from XHTTP `extra.headers`, returning its value.
fn take_host_header(extra: &mut Map<String, Value>) -> Option<String> {
    let Some(Value::Object(headers)) = extra.get_mut("headers") else {
        return None;
    };
    let keys: Vec<String> = headers
        .keys()
        .filter(|k| k.eq_ignore_ascii_case("host"))
        .cloned()
        .collect();
    let mut host = None;
    for key in keys {
        if let Some(Value::String(value)) = headers.remove(&key) {
            host = host.or(non_empty(Some(&value)).map(str::to_owned));
        }
    }
    if headers.is_empty() {
        extra.remove("headers");
    }
    host
}

/// XHTTP `extra` is provider JSON handed to an elevated engine, checked like a native graph: no
/// local files, and certificate checks disabled only next to a pin or certificate names. Either
/// one verifies on its own and the bundled Xray refuses any `allowInsecure: true`, so the flag is
/// dropped.
/// Keys match case-insensitively because Xray's Go JSON decoder does.
fn sanitize_extra(value: &mut Value) -> Result<(), NativeError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                let truthy = !matches!(child, Value::Null | Value::Bool(false))
                    && child.as_str() != Some("");
                if truthy && FILE_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key)) {
                    return Err(NativeError::LocalFileReference);
                }
                if key.eq_ignore_ascii_case("tlsSettings")
                    && let Some(tls) = child.as_object_mut()
                {
                    let verified = tls.iter().any(|(k, v)| {
                        (k.eq_ignore_ascii_case("pinnedPeerCertSha256")
                            || k.eq_ignore_ascii_case("verifyPeerCertByName"))
                            && v.as_str()
                                .is_some_and(|v| v.split(',').any(|n| !n.trim().is_empty()))
                    });
                    let mut insecure = false;
                    tls.retain(|k, v| {
                        let flag = k.eq_ignore_ascii_case("allowInsecure");
                        insecure |= flag && *v == Value::Bool(true);
                        !flag
                    });
                    if insecure && !verified {
                        return Err(NativeError::InsecureWithoutPin);
                    }
                }
                sanitize_extra(child)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter_mut().try_for_each(sanitize_extra),
        _ => Ok(()),
    }
}

fn or_root(path: &str) -> &str {
    non_empty(Some(path)).unwrap_or("/")
}

fn list(items: &[String]) -> Vec<&str> {
    items.iter().filter_map(|s| non_empty(Some(s))).collect()
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}
