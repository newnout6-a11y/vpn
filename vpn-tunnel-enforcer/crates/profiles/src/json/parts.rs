//! sing-box option blocks shared by several outbound types: `tls`, `transport`, `multiplex`
//! (or a source `mux`) and the dial fields.
use serde_json::{Map, Value};

use super::scan::{Scan, join};
use super::values::{boolean, duration_secs, flag, list, positive_u32, text};
use crate::common::fields::{XHTTP_MODES, parse_host};
use crate::model::{DialPrefs, Ech, Mux, Reality, SkipReason, Tls, Transport};

const TLS_TYPED: &[&str] = &[
    "enabled",
    "server_name",
    "disable_sni",
    "insecure",
    "alpn",
    "min_version",
    "max_version",
    "certificate",
    "certificate_public_key_sha256",
    "ech",
    "utls",
    "reality",
];
/// Not here on purpose (they become Notes): `engine` (`apple` does not exist on Windows, and the
/// system engines refuse the uTLS the emitter adds) and `kernel_tx` / `kernel_rx` (Linux kTLS:
/// sing-box refuses the whole config elsewhere).
const TLS_EXTRA: &[&str] = &[
    "cipher_suites",
    "curve_preferences",
    "client_certificate",
    "client_key",
    "fragment",
    "fragment_fallback_delay",
    "record_fragment",
    "spoof",
    "spoof_method",
    "handshake_timeout",
];

/// `tls` of a sing-box outbound. `Ok(None)` when absent or not enabled (sing-box ignores it then).
pub(crate) fn tls(v: Option<&Value>, scan: &mut Scan) -> Result<Option<Tls>, &'static str> {
    let Some(v) = v else { return Ok(None) };
    let Some(o) = v.as_object() else {
        scan.unsupported("tls");
        return Ok(None);
    };
    if !flag(o, "enabled") {
        return Ok(None);
    }
    scan.sort_keys(o, "tls", TLS_TYPED, TLS_EXTRA);
    let mut tls = Tls {
        server_name: text(o, &["server_name"]).map(|s| unbracket(s).to_owned()),
        disable_sni: flag(o, "disable_sni"),
        insecure: flag(o, "insecure"),
        alpn: o.get("alpn").map(list).unwrap_or_default(),
        min_version: text(o, &["min_version"]).map(str::to_owned),
        max_version: text(o, &["max_version"]).map(str::to_owned),
        certificate_pem: o
            .get("certificate")
            .map(list_lines)
            .filter(|s| !s.is_empty()),
        spki_pin_sha256: o
            .get("certificate_public_key_sha256")
            .map(list)
            .unwrap_or_default(),
        ..Tls::default()
    };
    if let Some(ech) = o.get("ech").and_then(Value::as_object) {
        scan.sort_keys(
            ech,
            "tls.ech",
            &["enabled", "config", "query_server_name"],
            &["pq_signature_schemes_enabled"],
        );
        if flag(ech, "enabled") {
            tls.ech = Some(Ech {
                config_lines: ech.get("config").map(list_lines_vec).unwrap_or_default(),
                query_server_name: text(ech, &["query_server_name"]).map(str::to_owned),
            });
        }
    }
    if let Some(utls) = o.get("utls").and_then(Value::as_object) {
        scan.sort_keys(utls, "tls.utls", &["enabled", "fingerprint"], &[]);
        if flag(utls, "enabled") {
            tls.fingerprint = text(utls, &["fingerprint"]).map(str::to_owned);
        }
    }
    if let Some(reality) = o.get("reality").and_then(Value::as_object) {
        scan.sort_keys(
            reality,
            "tls.reality",
            &["enabled", "public_key", "short_id", "spider_x"],
            &[],
        );
        if flag(reality, "enabled") {
            let public_key = text(reality, &["public_key"]).ok_or("reality without public_key")?;
            tls.reality = Some(Reality {
                public_key: public_key.to_owned(),
                short_id: text(reality, &["short_id"]).unwrap_or_default().to_owned(),
                spider_x: text(reality, &["spider_x"]).map(str::to_owned),
                ..Reality::default()
            });
        }
    }
    Ok(Some(tls))
}

/// `[v6]` -> `v6` (old URI parsers bracketed IPv6 hosts everywhere, SNI included).
fn unbracket(s: &str) -> &str {
    s.strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s)
}

/// PEM text from a string or a list of lines (sing-box accepts both).
fn list_lines(v: &Value) -> String {
    list_lines_vec(v).join("\n")
}

fn list_lines_vec(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => s
            .lines()
            .map(str::to_owned)
            .filter(|l| !l.trim().is_empty())
            .collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// `transport` of a sing-box outbound (plus the XHTTP / gRPC multi-mode shapes the Electron app stored).
pub(crate) fn transport(
    v: Option<&Value>,
    scan: &mut Scan,
) -> Result<Option<Transport>, SkipReason> {
    let Some(v) = v else { return Ok(None) };
    let Some(o) = v.as_object() else {
        scan.unsupported("transport");
        return Ok(None);
    };
    let kind = text(o, &["type"])
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let path = || leading_slash(text(o, &["path"]).unwrap_or_default());
    let transport = match kind.as_str() {
        "ws" | "websocket" => {
            scan.sort_keys(
                o,
                "transport",
                &[
                    "type",
                    "path",
                    "headers",
                    "max_early_data",
                    "early_data_header_name",
                ],
                &[],
            );
            keep_other_headers(o, scan);
            Transport::Ws {
                path: path(),
                host: header_host(o),
                max_early_data: o.get("max_early_data").and_then(positive_u32),
                early_data_header: text(o, &["early_data_header_name"]).map(str::to_owned),
            }
        }
        "grpc" => {
            scan.sort_keys(
                o,
                "transport",
                &["type", "service_name", "multi_mode"],
                &["idle_timeout", "ping_timeout", "permit_without_stream"],
            );
            Transport::Grpc {
                service_name: text(o, &["service_name"]).unwrap_or_default().to_owned(),
                multi_mode: o.get("multi_mode").and_then(boolean),
            }
        }
        "http" | "h2" => {
            scan.sort_keys(
                o,
                "transport",
                &["type", "host", "path"],
                &["method", "headers", "idle_timeout", "ping_timeout"],
            );
            Transport::Http {
                hosts: o.get("host").map(list).unwrap_or_default(),
                path: path(),
            }
        }
        "httpupgrade" | "http-upgrade" => {
            scan.sort_keys(o, "transport", &["type", "host", "path", "headers"], &[]);
            keep_other_headers(o, scan);
            let host = text(o, &["host"])
                .map(str::to_owned)
                .or_else(|| header_host(o));
            Transport::HttpUpgrade {
                host: host.unwrap_or_default(),
                path: path(),
            }
        }
        "quic" => {
            scan.sort_keys(o, "transport", &["type"], &[]);
            Transport::Quic
        }
        "splithttp" | "xhttp" | "split-http" => {
            scan.sort_keys(
                o,
                "transport",
                &["type", "host", "path", "mode", "method", "extra", "headers"],
                &[],
            );
            // Clash imports kept the mode under `method`.
            xhttp(o, &["mode", "method"])?
        }
        other => return Err(SkipReason::UnsupportedTransport(other.to_owned())),
    };
    Ok(Some(transport))
}

/// XHTTP (Xray only): the mode must be one Xray knows, `extra` an object.
pub(crate) fn xhttp(o: &Map<String, Value>, mode_keys: &[&str]) -> Result<Transport, SkipReason> {
    let invalid = |detail: &str| SkipReason::Invalid {
        scheme: "xhttp".into(),
        detail: detail.into(),
    };
    let mode = text(o, mode_keys).map(|m| m.trim().to_ascii_lowercase());
    if mode.as_deref().is_some_and(|m| !XHTTP_MODES.contains(&m)) {
        return Err(invalid("unknown XHTTP mode"));
    }
    let extra = match o.get("extra") {
        None | Some(Value::Null) => None,
        Some(Value::Object(m)) => Some(m.clone()),
        Some(_) => return Err(invalid("XHTTP extra must be a JSON object")),
    };
    let host = text(o, &["host"])
        .map(str::to_owned)
        .or_else(|| header_host(o));
    Ok(Transport::Xhttp {
        host: host.unwrap_or_default(),
        path: leading_slash(text(o, &["path"]).unwrap_or_default()),
        mode,
        extra,
    })
}

/// `Host` from an HTTP header map (values may be a string or a list).
pub(crate) fn header_host(o: &Map<String, Value>) -> Option<String> {
    let headers = o.get("headers")?.as_object()?;
    let (_, v) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))?;
    list(v).into_iter().next()
}

/// Headers other than `Host` have no typed field: keep the whole map verbatim so the emitter
/// writes it back unchanged (the typed `host` is inside it as well).
fn keep_other_headers(o: &Map<String, Value>, scan: &mut Scan) {
    if let Some(headers) = o.get("headers").and_then(Value::as_object)
        && headers.keys().any(|k| !k.eq_ignore_ascii_case("host"))
    {
        scan.extra
            .insert(join("transport", "headers"), Value::Object(headers.clone()));
    }
}

/// `/` prefix; empty becomes `/`.
pub(crate) fn leading_slash(path: &str) -> String {
    if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    }
}

/// sing-box `multiplex`, or a source `mux` object (Xray/Clash shape, profiles spec K15).
/// A disabled block is dropped: it changes nothing.
pub(crate) fn multiplex(o: &Map<String, Value>, scan: &mut Scan) -> Option<Mux> {
    if let Some(m) = o.get("multiplex").and_then(Value::as_object) {
        if !flag(m, "enabled") {
            return None;
        }
        scan.sort_keys(
            m,
            "multiplex",
            &[
                "enabled",
                "protocol",
                "max_connections",
                "padding",
                "brutal",
            ],
            &["min_streams", "max_streams"],
        );
        return Some(Mux {
            enabled: true,
            protocol: text(m, &["protocol"]).map(str::to_owned),
            max_connections: m.get("max_connections").and_then(positive_u32),
            padding: flag(m, "padding"),
            brutal: brutal(m, "multiplex.brutal", scan),
        });
    }
    let m = o.get("mux")?.as_object()?;
    // The source `mux` meant "on" unless it said otherwise.
    if m.get("enabled").and_then(boolean) == Some(false) {
        return None;
    }
    scan.sort_keys(
        m,
        "mux",
        &["enabled", "concurrency", "protocol", "padding", "brutal"],
        &[],
    );
    Some(Mux {
        enabled: true,
        protocol: text(m, &["protocol"]).map(str::to_owned),
        max_connections: m.get("concurrency").and_then(positive_u32),
        padding: flag(m, "padding"),
        brutal: brutal(m, "mux.brutal", scan),
    })
}

fn brutal(m: &Map<String, Value>, path: &str, scan: &mut Scan) -> Option<(u32, u32)> {
    let b = m.get("brutal")?.as_object()?;
    scan.sort_keys(b, path, &["enabled", "up_mbps", "down_mbps"], &[]);
    if !flag(b, "enabled") {
        return None;
    }
    let rate = |k: &str| b.get(k).and_then(super::values::rounded_positive);
    Some((rate("up_mbps")?, rate("down_mbps")?))
}

/// Dial options kept from the provider; the rest are sorted by [`Scan::sort_keys`].
pub(crate) fn dial(o: &Map<String, Value>, scan: &mut Scan) -> DialPrefs {
    let resolver_strategy = match o.get("domain_resolver") {
        Some(Value::Object(r)) => {
            // `server` names a DNS server of the provider's config, which does not exist here.
            scan.sort_keys(r, "domain_resolver", &["server", "strategy"], &[]);
            text(r, &["strategy"])
        }
        _ => None,
    };
    DialPrefs {
        connect_timeout_s: o.get("connect_timeout").and_then(duration_secs),
        tcp_fast_open: flag(o, "tcp_fast_open"),
        tcp_multi_path: flag(o, "tcp_multi_path"),
        udp_fragment: o.get("udp_fragment").and_then(boolean),
        dns_strategy: resolver_strategy
            .or_else(|| text(o, &["domain_strategy"]))
            .map(str::to_owned),
    }
}

/// Top-level keys read by [`dial`].
pub(crate) const DIAL_TYPED: &[&str] = &[
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "domain_strategy",
    "domain_resolver",
];

/// `server` of an outbound, unbracketed.
pub(crate) fn server_host(o: &Map<String, Value>) -> Result<crate::model::Host, &'static str> {
    let raw = text(o, &["server"]).ok_or("missing server")?;
    parse_host(raw.trim()).ok_or("invalid server address")
}
