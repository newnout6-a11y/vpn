//! TLS and stream transport of a Clash entry.
use std::cell::RefCell;

use serde_json::{Map, Value};

use super::yaml::Node;
use super::{Obj, Proto, TlsMode, invalid, parse_u32};
use crate::common::fields::{UTLS_FINGERPRINTS, XHTTP_MODES};
use crate::model::{Ech, Host, Note, Reality, SkipReason, Tls, Transport};

/// Keys that only describe TLS; read (and ignored) even when TLS ends up off.
const TLS_KEYS: &[&str] = &[
    "tls",
    "sni",
    "servername",
    "skip-cert-verify",
    "client-fingerprint",
    "fingerprint",
    "alpn",
    "ech-opts",
    "reality-opts",
];
/// mihomo TLS camouflage layers no engine of ours speaks: the server expects them, so skip.
const FOREIGN_LAYERS: &[&str] = &[
    "restls-opts",
    "jls-opts",
    "tlsmirror-opts",
    "shadow-tls-opts",
];
/// TLS settings of the entry; `Err` for a REALITY block without a public key or a foreign layer.
pub(super) fn read_tls(
    obj: &Obj,
    server: Option<&Host>,
    mode: TlsMode,
    notes: &mut Vec<Note>,
) -> Result<Option<Tls>, SkipReason> {
    if mode == TlsMode::Never {
        return Ok(None);
    }
    let reality = obj
        .node("reality-opts")
        .filter(|n| n.as_map().is_some_and(|m| !m.is_empty()));
    // `servername` alone never enables TLS (old bug, §2.8): only `tls: true` or REALITY do.
    let enabled = mode == TlsMode::Always || obj.bool("tls") == Some(true) || reality.is_some();
    if !enabled {
        for key in TLS_KEYS {
            obj.node(key);
        }
        return Ok(None);
    }
    for key in FOREIGN_LAYERS {
        if obj
            .node(key)
            .and_then(Node::as_map)
            .is_some_and(|m| !m.is_empty())
        {
            return Err(SkipReason::UnsupportedTransport((*key).to_owned()));
        }
    }
    obj.node("tls");
    let mut tls = Tls {
        // mihomo: an empty `sni` / `servername` means the `server` address.
        server_name: obj
            .first_str(&["servername", "sni"])
            .map(str::to_owned)
            .or_else(|| server.map(Host::to_string)),
        insecure: obj.bool("skip-cert-verify").unwrap_or(false),
        alpn: obj.list("alpn"),
        fingerprint: obj
            .str("client-fingerprint")
            .map(str::to_ascii_lowercase)
            .filter(|f| f != "none"),
        ..Tls::default()
    };
    if let Some(raw) = obj.str("fingerprint") {
        let lower = raw.to_ascii_lowercase();
        if let Some(pin) = cert_pin(raw) {
            tls.cert_pin_sha256 = Some(pin);
            notes.push(Note::CertPinNotEnforced);
        } else if UTLS_FINGERPRINTS.contains(&lower.as_str()) {
            // Old converters wrote uTLS names into `fingerprint` instead of a pin.
            tls.fingerprint.get_or_insert(lower);
        } else {
            notes.push(Note::UnsupportedField("fingerprint".to_owned()));
        }
    }
    if let Some(ech) = obj.node("ech-opts")
        && ech.get("enable").and_then(Node::as_bool) == Some(true)
    {
        tls.ech = Some(Ech {
            config_lines: ech
                .get("config")
                .and_then(Node::as_str)
                .map(ech_config)
                .into_iter()
                .collect(),
            query_server_name: ech
                .get("query-server-name")
                .and_then(Node::as_str)
                .map(str::to_owned),
        });
    }
    if let Some(reality) = reality {
        let field = |keys: [&str; 2]| {
            keys.iter()
                .find_map(|k| reality.get(k).and_then(Node::as_str))
        };
        let public_key = field(["public-key", "public_key"])
            .ok_or_else(|| invalid("reality-opts without public-key"))?;
        tls.reality = Some(Reality {
            public_key: public_key.to_owned(),
            short_id: field(["short-id", "short_id"])
                .unwrap_or_default()
                .to_owned(),
            spider_x: None,
        });
        // E.g. mihomo's `support-x25519mlkem768`: sing-box REALITY has only key and short id.
        let read = ["public-key", "public_key", "short-id", "short_id"];
        for (key, _) in reality.as_map().unwrap_or_default() {
            if !read.contains(&key.as_str()) {
                notes.push(Note::UnsupportedField(format!("reality-opts.{key}")));
            }
        }
    }
    notes.extend(Note::for_tls(Some(&tls)));
    Ok(Some(tls))
}

/// SHA-256 certificate pin: 64 hex digits, `:` separators allowed; lower-case hex out.
fn cert_pin(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|&c| c != ':').collect();
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

/// mihomo gives one base64 ECHConfigList; drop PEM armour and whitespace if a provider added them.
fn ech_config(raw: &str) -> String {
    raw.lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(|line| line.split_whitespace())
        .collect()
}

/// The stream transport (`network` + `*-opts`); only VLESS, VMess and Trojan carry one.
pub(super) fn read_transport(
    obj: &Obj,
    proto: Proto,
    notes: &mut Vec<Note>,
) -> Result<Option<Transport>, SkipReason> {
    let Some(network) = obj
        .str("network")
        .map(str::to_ascii_lowercase)
        .filter(|n| n != "tcp")
    else {
        return Ok(None);
    };
    if !matches!(proto, Proto::Vless | Proto::Vmess | Proto::Trojan) {
        notes.push(Note::UnsupportedField("network".to_owned()));
        return Ok(None);
    }
    let opts = match network.as_str() {
        "ws" | "httpupgrade" => Some("ws-opts"),
        "grpc" => Some("grpc-opts"),
        "h2" => Some("h2-opts"),
        "http" => Some("http-opts"),
        _ => None,
    };
    // Sub-keys of the network's `*-opts` map actually read; the rest are reported below.
    let read = RefCell::new(Vec::new());
    let opt = |opts: &'static str, key: &'static str| {
        read.borrow_mut().push(key);
        obj.node(opts).and_then(|o| o.get(key))
    };
    let text = |opts: &'static str, key: &'static str| opt(opts, key).and_then(Node::as_str);
    let transport = match network.as_str() {
        "ws" | "httpupgrade" => {
            let path = text("ws-opts", "path").unwrap_or("/").to_owned();
            let host =
                opt("ws-opts", "headers").and_then(|h| header(h, "host", notes, "ws-opts.headers"));
            let upgrade = network == "httpupgrade"
                || opt("ws-opts", "v2ray-http-upgrade").and_then(Node::as_bool) == Some(true);
            if upgrade {
                Transport::HttpUpgrade {
                    host: host.unwrap_or_default(),
                    path,
                }
            } else {
                Transport::Ws {
                    path,
                    host,
                    max_early_data: text("ws-opts", "max-early-data")
                        .and_then(parse_u32)
                        .filter(|&n| n > 0),
                    early_data_header: text("ws-opts", "early-data-header-name").map(str::to_owned),
                }
            }
        }
        "grpc" => Transport::Grpc {
            service_name: text("grpc-opts", "grpc-service-name")
                .unwrap_or_default()
                .to_owned(),
            multi_mode: None,
        },
        "h2" => Transport::Http {
            hosts: opt("h2-opts", "host")
                .map(Node::as_list)
                .unwrap_or_default(),
            path: text("h2-opts", "path").unwrap_or("/").to_owned(),
        },
        // TCP with an HTTP/1.1 header mask (Xray `tcpSettings.header`), not sing-box's HTTP transport.
        "http" => {
            let mut path = opt("http-opts", "path")
                .map(Node::as_list)
                .unwrap_or_default();
            if path.is_empty() {
                path.push("/".to_owned());
            }
            let host = opt("http-opts", "headers")
                .and_then(Node::as_map)
                .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")))
                .map(|(_, v)| v.as_list())
                .unwrap_or_default();
            Transport::TcpHttpHeader { host, path }
        }
        "xhttp" | "splithttp" => xhttp(obj, notes)?,
        other => return Err(SkipReason::UnsupportedTransport(other.to_owned())),
    };
    let read = read.into_inner();
    if let Some(opts) = opts {
        let pairs = obj.node(opts).and_then(Node::as_map).unwrap_or_default();
        for (key, _) in pairs.iter().filter(|(k, _)| !read.contains(&k.as_str())) {
            notes.push(Note::UnsupportedField(format!("{opts}.{key}")));
        }
    }
    Ok(Some(transport))
}

/// Value of header `name` (any case) in a `headers` map; other headers are noted as dropped.
fn header(headers: &Node, name: &str, notes: &mut Vec<Note>, field: &str) -> Option<String> {
    let pairs = headers.as_map()?;
    if pairs.iter().any(|(k, _)| !k.eq_ignore_ascii_case(name)) {
        notes.push(Note::UnsupportedField(field.to_owned()));
    }
    let (_, value) = pairs.iter().find(|(k, _)| k.eq_ignore_ascii_case(name))?;
    value.as_list().into_iter().next()
}

/// mihomo `xhttp-opts` -> Xray XHTTP. Only long-standing `extra` keys are translated; newer
/// mihomo knobs (padding obfuscation, session placement, download settings) are noted instead
/// of guessed, because a wrong Xray key makes `xray run` reject the whole config.
fn xhttp(obj: &Obj, notes: &mut Vec<Note>) -> Result<Transport, SkipReason> {
    let opts = obj
        .node("xhttp-opts")
        .or_else(|| obj.node("splithttp-opts"));
    let get = |key: &str| opts.and_then(|o| o.get(key)).and_then(Node::as_str);
    let mode = get("mode").map(str::to_ascii_lowercase);
    if let Some(mode) = &mode
        && !XHTTP_MODES.contains(&mode.as_str())
    {
        return Err(invalid(format!("unknown XHTTP mode {mode}")));
    }
    let mut extra = Map::new();
    for (key, value) in opts.and_then(Node::as_map).unwrap_or_default() {
        let translated = match key.as_str() {
            "path" | "host" | "mode" => continue,
            "headers" => value.as_map().map(|pairs| {
                let map: Map<String, Value> = pairs
                    .iter()
                    .filter_map(|(k, v)| Some((k.clone(), Value::from(v.as_str()?))))
                    .collect();
                ("headers", Value::Object(map))
            }),
            "no-grpc-header" => value.as_bool().map(|b| ("noGRPCHeader", Value::Bool(b))),
            "x-padding-bytes" => value.as_str().and_then(range).map(|v| ("xPaddingBytes", v)),
            "sc-max-each-post-bytes" => value
                .as_str()
                .and_then(range)
                .map(|v| ("scMaxEachPostBytes", v)),
            "sc-min-posts-interval-ms" => value
                .as_str()
                .and_then(range)
                .map(|v| ("scMinPostsIntervalMs", v)),
            "reuse-settings" => value
                .as_map()
                .map(|pairs| ("xmux", Value::Object(xmux(pairs, notes)))),
            _ => None,
        };
        match translated {
            Some((xray_key, value)) => {
                extra.insert(xray_key.to_owned(), value);
            }
            None => notes.push(Note::UnsupportedField(format!("xhttp-opts.{key}"))),
        }
    }
    Ok(Transport::Xhttp {
        host: get("host").unwrap_or_default().to_owned(),
        path: get("path").unwrap_or("/").to_owned(),
        mode,
        extra: (!extra.is_empty()).then_some(extra),
    })
}

/// XMUX (`reuse-settings`) with Xray's names; a value Xray would refuse is noted and dropped.
fn xmux(pairs: &[(String, Node)], notes: &mut Vec<Note>) -> Map<String, Value> {
    let mut out = Map::new();
    for (key, value) in pairs.iter().filter(|(_, v)| !v.is_null()) {
        let text = value.as_str();
        let translated = match key.as_str() {
            "max-concurrency" => text.and_then(range).map(|v| ("maxConcurrency", v)),
            "max-connections" => text.and_then(range).map(|v| ("maxConnections", v)),
            "c-max-reuse-times" => text.and_then(range).map(|v| ("cMaxReuseTimes", v)),
            "h-max-request-times" => text.and_then(range).map(|v| ("hMaxRequestTimes", v)),
            "h-max-reusable-secs" => text.and_then(range).map(|v| ("hMaxReusableSecs", v)),
            "h-keep-alive-period" => text
                .and_then(|v| v.trim().parse::<i64>().ok())
                .map(|n| ("hKeepAlivePeriod", n.into())),
            _ => None,
        };
        match translated {
            Some((xray_key, v)) => {
                out.insert(xray_key.to_owned(), v);
            }
            None => notes.push(Note::UnsupportedField(format!(
                "xhttp-opts.reuse-settings.{key}"
            ))),
        }
    }
    out
}

/// Xray `Int32Range`: `n` or `"from-to"` with `from <= to`; `None` for what Xray would refuse
/// (one bad value makes `xray run` reject the whole config).
fn range(raw: &str) -> Option<Value> {
    let num = |s: &str| parse_u32(s).and_then(|n| i32::try_from(n).ok());
    match raw.split_once('-') {
        None => num(raw).map(Value::from),
        Some((from, to)) => {
            let (from, to) = (num(from)?, num(to)?);
            (from <= to).then(|| Value::from(format!("{from}-{to}")))
        }
    }
}
