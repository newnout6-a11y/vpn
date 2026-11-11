//! TLS, transport and mux settings from query parameters (alias lists of the old importer).
use serde_json::Value;

use super::parts::{Params, falsy, truthy};
use super::{Fail, Res, bad};
use crate::common::b64::base64_bytes;
use crate::common::fields::XHTTP_MODES;
use crate::model::{Ech, Mux, Note, Reality, SkipReason, Tls, Transport};

const SNI: &[&str] = &["sni", "serverName", "peer", "host"];
const INSECURE: &[&str] = &[
    "allowInsecure",
    "insecure",
    "skip-cert-verify",
    "allow_insecure",
];

/// How a scheme treats the `security` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TlsMode {
    /// Off unless `security=tls|reality` (VLESS, VMess).
    Optional,
    /// On unless `security=none` (Trojan).
    DefaultOn,
    /// The protocol always runs over TLS (AnyTLS); `security=none` is ignored.
    Always,
    /// QUIC protocols and Naive: always TLS, and REALITY cannot apply.
    AlwaysNoReality,
}

/// TLS settings as the link states them; `None` when the link runs without TLS.
pub(super) fn tls(p: &Params, mode: TlsMode, notes: &mut Vec<Note>) -> Res<Option<Tls>> {
    let raw = p.get(&["security", "tls"]).unwrap_or_default();
    let security = match raw.trim().to_ascii_lowercase().as_str() {
        "" => Security::Unset,
        "tls" => Security::Tls,
        "reality" => Security::Reality,
        "none" => Security::None,
        v if truthy(v) => Security::Tls,
        v if falsy(v) => Security::None,
        _ => return bad("unknown security type"),
    };
    let enabled = match mode {
        TlsMode::Optional => matches!(security, Security::Tls | Security::Reality),
        TlsMode::DefaultOn => security != Security::None,
        TlsMode::Always | TlsMode::AlwaysNoReality => true,
    };
    if !enabled {
        return Ok(None);
    }
    let reality = match security {
        Security::Reality if mode == TlsMode::AlwaysNoReality => {
            return bad("REALITY is not available for this protocol");
        }
        Security::Reality => Some(reality(p)?),
        _ => None,
    };
    let cert_pin_sha256 = cert_pin(p)?;
    if cert_pin_sha256.is_some() {
        notes.push(Note::CertPinNotEnforced);
    }
    let tls = Tls {
        server_name: p.get(SNI).map(str::to_owned),
        disable_sni: p.flag(&["disable_sni", "disableSni"]),
        insecure: p.flag(INSECURE),
        alpn: p.csv(&["alpn"]),
        fingerprint: p
            .get(&["fp", "fingerprint"])
            .filter(|fp| !fp.eq_ignore_ascii_case("none"))
            .map(str::to_owned),
        reality,
        ech: ech(p, notes),
        cert_pin_sha256,
        ..Tls::default()
    };
    notes.extend(Note::for_tls(Some(&tls)));
    Ok(Some(tls))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Security {
    Unset,
    Tls,
    Reality,
    None,
}

fn reality(p: &Params) -> Res<Reality> {
    let Some(public_key) = p.get(&["pbk", "publicKey", "public_key"]) else {
        return bad("REALITY link without a public key (pbk)");
    };
    Ok(Reality {
        public_key: public_key.to_owned(),
        short_id: p
            .get(&["sid", "shortId", "short_id"])
            .unwrap_or_default()
            .to_owned(),
        spider_x: p.get(&["spx", "spider_x", "spiderX"]).map(str::to_owned),
    })
}

/// Hysteria2 `pinSHA256`: 64 hex digits, `:` separators allowed -> lower-case hex.
fn cert_pin(p: &Params) -> Res<Option<String>> {
    let Some(raw) = p.get(&["pinSHA256", "pin-sha256", "pin_sha256"]) else {
        return Ok(None);
    };
    let hex: String = raw.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return bad("pinSHA256 is not a SHA-256 hex digest");
    }
    Ok(Some(hex.to_ascii_lowercase()))
}

/// ECH settings. A local `echConfigPath` is dropped with a note: a link from a subscription must
/// not make the core read files on this machine.
fn ech(p: &Params, notes: &mut Vec<Note>) -> Option<Ech> {
    if p.get(&["echConfigPath", "ech_config_path", "ech-config-path"])
        .is_some()
    {
        notes.push(Note::FileReferenceDropped("echConfigPath".into()));
    }
    let mut config_lines = p.csv(&["echConfig", "ech_config", "ech-config"]);
    let mut query_server_name = p
        .get(&[
            "echQueryServerName",
            "ech_query_server_name",
            "ech-query-server-name",
        ])
        .map(str::to_owned);
    let mut enabled = false;
    // `echConfigList` is Xray's single-string value, never a CSV of configs.
    match p.get(&[
        "ech",
        "echConfigList",
        "echEnabled",
        "ech_enabled",
        "ech-enabled",
    ]) {
        None => {}
        Some(v) if truthy(v) => enabled = true,
        Some(v) if falsy(v) => {}
        // Xray links carry the `echConfigList` value itself: a DNS server URL, optionally
        // prefixed with the name to query (`example.com+https://1.1.1.1/dns-query`) ...
        Some(v) if v.contains("://") => {
            enabled = true;
            if let Some((name, server)) = v.split_once('+')
                && server.contains("://")
                && !name.is_empty()
                && !name.contains("://")
            {
                query_server_name.get_or_insert_with(|| name.to_owned());
            }
        }
        // ... or a base64 ECHConfigList.
        Some(v) if base64_bytes(v).is_some() => {
            enabled = true;
            config_lines.push(v.to_owned());
        }
        Some(_) => notes.push(Note::UnsupportedField("ech".into())),
    }
    let present = enabled || !config_lines.is_empty() || query_server_name.is_some();
    present.then_some(Ech {
        config_lines,
        query_server_name,
    })
}

/// Stream transport named by `type` (`net`); `None` for plain TCP.
pub(super) fn transport(p: &Params) -> Res<Option<Transport>> {
    let kind = p
        .get(&["type", "net"])
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let host = || p.get(&["host"]).map(str::to_owned);
    let path = || lead_slash(p.get(&["path"]));
    let transport = match kind.as_str() {
        "tcp" | "raw" => return tcp_header(p),
        "ws" | "websocket" => Transport::Ws {
            path: path(),
            host: host(),
            max_early_data: p
                .get(&["ed", "max_early_data"])
                .and_then(|v| v.trim().parse::<u32>().ok())
                .filter(|v| *v > 0),
            early_data_header: p.get(&["eh", "early_data_header_name"]).map(str::to_owned),
        },
        "grpc" => Transport::Grpc {
            service_name: p
                .get(&["serviceName", "service_name"])
                .unwrap_or_default()
                .to_owned(),
            multi_mode: grpc_multi_mode(p)?,
        },
        "httpupgrade" | "http-upgrade" => Transport::HttpUpgrade {
            host: host().unwrap_or_default(),
            path: path(),
        },
        "http" | "h2" => Transport::Http {
            hosts: p.csv(&["host"]),
            path: path(),
        },
        "xhttp" | "splithttp" | "split-http" => Transport::Xhttp {
            host: host().unwrap_or_default(),
            path: path(),
            mode: xhttp_mode(p)?,
            extra: xhttp_extra(p)?,
        },
        other => {
            let known = other.len() <= 24
                && other
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'));
            let name = if known { other } else { "unknown" };
            return Err(Fail::Skip(SkipReason::UnsupportedTransport(
                name.to_owned(),
            )));
        }
    };
    Ok(Some(transport))
}

/// Plain TCP, or TCP with an HTTP header mask (`headerType=http`, Xray only).
fn tcp_header(p: &Params) -> Res<Option<Transport>> {
    match p
        .get(&["headerType", "header_type"])
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("none") => Ok(None),
        Some("http") => Ok(Some(Transport::TcpHttpHeader {
            host: p.csv(&["host"]),
            path: p.csv(&["path"]),
        })),
        Some(_) => bad("unknown TCP header type"),
    }
}

fn lead_slash(path: Option<&str>) -> String {
    match path {
        Some(path) if path.starts_with('/') => path.to_owned(),
        Some(path) => format!("/{path}"),
        None => "/".to_owned(),
    }
}

/// gRPC `mode` (gun|multi) and `multiMode` (true|false|1|0); a contradiction is an error, not a
/// guess, because the wrong mode connects and then stalls.
fn grpc_multi_mode(p: &Params) -> Res<Option<bool>> {
    let mode = match p.get(&["mode"]).map(str::to_ascii_lowercase).as_deref() {
        None => None,
        Some("gun") => Some(false),
        Some("multi") => Some(true),
        Some(_) => return bad("unknown gRPC mode"),
    };
    let multi = match p
        .get(&["multiMode", "multi_mode"])
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None => None,
        Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) => return bad("invalid gRPC multiMode"),
    };
    match (mode, multi) {
        (Some(a), Some(b)) if a != b => bad("contradictory gRPC mode and multiMode"),
        _ => Ok(mode.or(multi)),
    }
}

fn xhttp_mode(p: &Params) -> Res<Option<String>> {
    match p.get(&["mode"]) {
        None => Ok(None),
        Some(mode) if XHTTP_MODES.contains(&mode) => Ok(Some(mode.to_owned())),
        Some(_) => bad("unknown XHTTP mode"),
    }
}

/// XHTTP `extra`: must be a JSON object (kept verbatim for Xray).
fn xhttp_extra(p: &Params) -> Res<Option<serde_json::Map<String, Value>>> {
    let Some(raw) = p.get(&["extra"]) else {
        return Ok(None);
    };
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(map)) => Ok(Some(map)),
        _ => bad("XHTTP extra must be a JSON object"),
    }
}

/// `mux` / `multiplex` / `padding` as the link states them; padding alone implies mux.
pub(super) fn mux(p: &Params) -> Option<Mux> {
    let mux = p.get(&["mux", "multiplex"]);
    let padding = p.get(&["padding"]);
    if mux.is_none() && padding.is_none() {
        return None;
    }
    Some(Mux {
        enabled: mux.is_none_or(truthy),
        padding: padding.is_some_and(truthy),
        ..Mux::default()
    })
}
