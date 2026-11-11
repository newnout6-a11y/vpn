//! Xray `streamSettings` -> typed TLS / transport. Xray-only shapes (XHTTP, gRPC multi mode, the
//! TCP HTTP header mask) are kept typed so the engine choice can see them.
use serde_json::{Map, Value};

use super::parts::{header_host, leading_slash, xhttp};
use super::values::{boolean, list, text};
use crate::model::{Ech, Reality, SkipReason, Tls, Transport};

/// Sub-object `key` of `o`, or an empty map.
pub(crate) fn sub<'a>(o: &'a Map<String, Value>, key: &str) -> &'a Map<String, Value> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    o.get(key).and_then(Value::as_object).unwrap_or(&EMPTY)
}

/// TLS or REALITY of an Xray stream; `Ok(None)` for `security: none` or absent.
pub(crate) fn tls(stream: &Map<String, Value>) -> Result<Option<Tls>, &'static str> {
    let security = text(stream, &["security"])
        .unwrap_or_default()
        .to_ascii_lowercase();
    let reality = security == "reality";
    if security != "tls" && !reality {
        return Ok(None);
    }
    let src = sub(
        stream,
        if reality {
            "realitySettings"
        } else {
            "tlsSettings"
        },
    );
    let owned = |keys: &[&str]| text(src, keys).map(str::to_owned);
    let mut tls = Tls {
        server_name: owned(&["serverName", "server_name"]),
        insecure: ["allowInsecure", "insecure"]
            .iter()
            .any(|k| src.get(*k).and_then(boolean) == Some(true)),
        alpn: src.get("alpn").map(list).unwrap_or_default(),
        fingerprint: owned(&["fingerprint", "fp"]).filter(|f| !f.eq_ignore_ascii_case("none")),
        min_version: owned(&["minVersion"]),
        max_version: owned(&["maxVersion"]),
        cert_pin_sha256: text(src, &["pinnedPeerCertSha256"]).and_then(first_pin),
        ech: text(src, &["echConfigList"]).map(ech),
        ..Tls::default()
    };
    if reality {
        let public_key = text(src, &["publicKey", "password", "public_key"])
            .ok_or("REALITY without publicKey")?;
        tls.reality = Some(Reality {
            public_key: public_key.to_owned(),
            short_id: owned(&["shortId", "short_id"]).unwrap_or_default(),
            spider_x: owned(&["spiderX", "spider_x", "spx"]),
        });
    }
    Ok(Some(tls))
}

/// First SHA-256 of a comma-joined `pinnedPeerCertSha256` (hex, colons allowed), lower-case.
fn first_pin(raw: &str) -> Option<String> {
    let hex: String = raw
        .split(',')
        .next()?
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// `echConfigList`: a base64 ECHConfigList, or a DNS query (`[domain+]udp://…`, `https://…`), which
/// leaves the config to be looked up.
fn ech(raw: &str) -> Ech {
    match raw.split_once("://") {
        Some((scheme, _)) => Ech {
            config_lines: Vec::new(),
            query_server_name: scheme.split_once('+').map(|(domain, _)| domain.to_owned()),
        },
        None => Ech {
            config_lines: vec![raw.trim().to_owned()],
            query_server_name: None,
        },
    }
}

/// Transport of an Xray stream. Transports the model cannot express are an error unless a
/// preserved graph (`graph`) carries the original stream to Xray.
pub(crate) fn transport(
    stream: &Map<String, Value>,
    graph: bool,
) -> Result<Option<Transport>, SkipReason> {
    let network = text(stream, &["method", "network"])
        .unwrap_or("raw")
        .to_ascii_lowercase();
    let path = |o: &Map<String, Value>| leading_slash(text(o, &["path"]).unwrap_or_default());
    let transport = match network.as_str() {
        "raw" | "tcp" => {
            let raw = match stream.get("rawSettings") {
                Some(_) => sub(stream, "rawSettings"),
                None => sub(stream, "tcpSettings"),
            };
            let header = sub(raw, "header");
            if text(header, &["type"]) != Some("http") {
                return Ok(None);
            }
            let request = sub(header, "request");
            let host = sub(request, "headers")
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"));
            Transport::TcpHttpHeader {
                host: host.map(|(_, v)| list(v)).unwrap_or_default(),
                path: request.get("path").map(list).unwrap_or_default(),
            }
        }
        "ws" | "websocket" => {
            let ws = sub(stream, "wsSettings");
            Transport::Ws {
                path: path(ws),
                host: text(ws, &["host"])
                    .map(str::to_owned)
                    .or_else(|| header_host(ws)),
                max_early_data: None,
                early_data_header: None,
            }
        }
        "grpc" | "gun" => {
            let grpc = sub(stream, "grpcSettings");
            Transport::Grpc {
                service_name: text(grpc, &["serviceName", "service_name"])
                    .unwrap_or_default()
                    .to_owned(),
                multi_mode: grpc.get("multiMode").and_then(boolean),
            }
        }
        "httpupgrade" | "http-upgrade" => {
            let hu = sub(stream, "httpupgradeSettings");
            Transport::HttpUpgrade {
                host: text(hu, &["host"]).unwrap_or_default().to_owned(),
                path: path(hu),
            }
        }
        "http" | "h2" => {
            let http = sub(stream, "httpSettings");
            Transport::Http {
                hosts: http.get("host").map(list).unwrap_or_default(),
                path: path(http),
            }
        }
        "xhttp" | "splithttp" | "split-http" => match stream.get("xhttpSettings") {
            Some(_) => xhttp(sub(stream, "xhttpSettings"), &["mode"])?,
            None => xhttp(sub(stream, "splithttpSettings"), &["mode"])?,
        },
        // The Hysteria protocol brings its own QUIC stream.
        "hysteria" => return Ok(None),
        _ if graph => return Ok(None),
        other => return Err(SkipReason::UnsupportedTransport(other.to_owned())),
    };
    Ok(Some(transport))
}
