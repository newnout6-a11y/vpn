//! `streamSettings` of a translated outbound: transport method and TLS / REALITY.
//!
//! Every name Xray would otherwise derive from the dial address (SNI, ws / httpupgrade / xhttp
//! Host, gRPC authority without TLS) is written out here, because pre-resolution later replaces
//! the address with an IP and CDN-fronted servers fail on an IP Host or SNI.
use serde_json::{Map, Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::device::utls_fingerprint;
use vpnte_profiles::model::{Host, Profile, Tls, Transport};
use vpnte_profiles::xray_native::NativeError;

use super::XrayConfigError;
use super::select::SingBoxOnly;

/// uTLS presets the bundled Xray accepts (case-insensitive); other provider names fall back to
/// the default instead of failing the build with `unknown "fingerprint"`.
const XRAY_FINGERPRINTS: [&str; 12] = [
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "randomizednoalpn",
    "unsafe",
];
/// REALITY needs an X25519MLKEM768 key share; Xray guarantees it only for these presets.
const MLKEM_FINGERPRINTS: [&str; 3] = ["chrome", "firefox", "safari"];
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
                r.insert("fingerprint".into(), json!(fingerprint(tls, device, true)));
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
                s.insert("security".into(), json!("tls"));
                s.insert("tlsSettings".into(), tls_settings(p, tls, device));
            }
        },
    }
    let flow_ok =
        (network == "tcp" && !plain) || super::select::vless_encryption(&p.kind).is_some();
    Ok(Stream {
        settings: Value::Object(s),
        flow_ok,
    })
}

/// Never `allowInsecure` (the bundled Xray refuses it): an insecure profile reaches Xray only
/// with a pinned certificate, which replaces the CA check.
fn tls_settings(p: &Profile, tls: &Tls, device: ClientDevice) -> Value {
    let mut t = Map::new();
    t.insert("serverName".into(), json!(sni(p, tls)));
    t.insert("fingerprint".into(), json!(fingerprint(tls, device, false)));
    let alpn: Vec<&str> = tls.alpn.iter().filter_map(|a| non_empty(Some(a))).collect();
    if !alpn.is_empty() {
        // Only an explicit ALPN: Xray's per-transport default (http/1.1 for ws) must stay.
        t.insert("alpn".into(), json!(alpn));
    }
    if let Some(pin) = non_empty(tls.cert_pin_sha256.as_deref()) {
        t.insert("pinnedPeerCertSha256".into(), json!(pin));
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
    Value::Object(t)
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
            if let Some(extra) = extra {
                let mut extra = Value::Object(extra);
                sanitize_extra(&mut extra)?;
                xhttp.insert("extra".into(), extra);
            }
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
fn sni(p: &Profile, tls: &Tls) -> String {
    let server = p.server.to_string();
    let name = non_empty(tls.server_name.as_deref()).unwrap_or(server.trim());
    match name.parse::<std::net::Ipv6Addr>() {
        Ok(ip) => format!("[{ip}]"),
        Err(_) => name.to_owned(),
    }
}

/// The provider's fingerprint when Xray knows it, else the device default (for REALITY only
/// an MLKEM-capable one, else `chrome`).
fn fingerprint(tls: &Tls, device: ClientDevice, reality: bool) -> &'static str {
    let provider = tls
        .fingerprint
        .as_deref()
        .map(|f| f.trim().to_ascii_lowercase());
    let known = XRAY_FINGERPRINTS
        .iter()
        .find(|&&k| Some(k) == provider.as_deref() && !(reality && k == "unsafe"));
    if let Some(fp) = known {
        return fp;
    }
    let default = utls_fingerprint(device);
    if reality && !MLKEM_FINGERPRINTS.contains(&default) {
        "chrome"
    } else {
        default
    }
}

/// WebSocket path with sing-box early data moved into `?ed=N` (Xray has no `maxEarlyData` key).
/// Only the `Sec-WebSocket-Protocol` header form exists in Xray; other header names lose 0-RTT.
fn ws_path(path: &str, max_early_data: Option<u32>, header: Option<&str>) -> String {
    let mut path = or_root(path).to_owned();
    let Some(n) = max_early_data.filter(|n| *n > 0) else {
        return path;
    };
    let query = path.split_once('?').map(|(_, q)| q.to_owned());
    if query
        .as_deref()
        .is_some_and(|q| q.split('&').any(|kv| kv.split('=').next() == Some("ed")))
    {
        return path;
    }
    if non_empty(header).is_some_and(|h| !h.eq_ignore_ascii_case("Sec-WebSocket-Protocol")) {
        tracing::warn!(
            "xray: websocket early data needs the Sec-WebSocket-Protocol header; dropped"
        );
        return path;
    }
    path.push(if query.is_some() { '&' } else { '?' });
    path.push_str(&format!("ed={}", n.min(MAX_EARLY_DATA)));
    path
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
/// local files, and certificate checks disabled only next to a pin. The pin replaces the CA check
/// on its own and the bundled Xray refuses any `allowInsecure: true`, so the flag is dropped.
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
                    let pinned = tls.iter().any(|(k, v)| {
                        k.eq_ignore_ascii_case("pinnedPeerCertSha256")
                            && non_empty(v.as_str()).is_some()
                    });
                    let mut insecure = false;
                    tls.retain(|k, v| {
                        let flag = k.eq_ignore_ascii_case("allowInsecure");
                        insecure |= flag && *v == Value::Bool(true);
                        !flag
                    });
                    if insecure && !pinned {
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
