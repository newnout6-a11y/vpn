//! What of an Xray outbound the typed model does not carry. A lone outbound with nothing left
//! over becomes a typed profile that both engines run; anything else keeps its native graph,
//! which only Xray runs (engine audit: plain provider outbounds were Xray-only for no reason).
use serde_json::{Map, Value};

use super::scan::join;
use super::values::flag;
use crate::common::fields::sha256_pin;

/// Keys the importer reads in full, per object (dotted path from the outbound, array items
/// transparent). An object path listed here is walked; any other key is left over.
const TYPED: &[(&str, &[&str])] = &[
    ("", &["tag", "protocol", "remarks", "ps", "name"]),
    ("settings", SETTINGS),
    ("settings.vnext", SETTINGS),
    ("settings.vnext.users", SETTINGS),
    ("settings.servers", SETTINGS),
    ("streamSettings", &["network", "method", "security"]),
    (
        "streamSettings.tlsSettings",
        &[
            "serverName",
            "server_name",
            "allowInsecure",
            "insecure",
            "alpn",
            "fingerprint",
            "fp",
            "minVersion",
            "maxVersion",
            "pinnedPeerCertSha256",
            "echConfigList",
        ],
    ),
    (
        "streamSettings.realitySettings",
        &[
            "serverName",
            "server_name",
            "publicKey",
            "password",
            "public_key",
            "shortId",
            "short_id",
            "spiderX",
            "spider_x",
            "spx",
            "fingerprint",
            "fp",
            // Debug logging on the client: changes nothing on the wire.
            "show",
        ],
    ),
    ("streamSettings.rawSettings", &["header"]),
    ("streamSettings.tcpSettings", &["header"]),
    ("streamSettings.wsSettings", &["path", "host", "headers"]),
    (
        "streamSettings.grpcSettings",
        &["serviceName", "service_name", "multiMode"],
    ),
    ("streamSettings.httpupgradeSettings", &["host", "path"]),
    (
        "streamSettings.xhttpSettings",
        &["host", "path", "mode", "extra", "headers"],
    ),
    (
        "streamSettings.splithttpSettings",
        &["host", "path", "mode", "extra", "headers"],
    ),
    ("streamSettings.httpSettings", &["host", "path"]),
    // The transport reader refuses anything but plain QUIC (no packet key, no header mask).
    (
        "streamSettings.quicSettings",
        &["security", "key", "header"],
    ),
];

/// Server and user fields of VLESS / VMess / Trojan / Shadowsocks in every Xray shape (`vnext`,
/// `servers`, the flat Xray 26 `settings`). `level` and `email` only name a policy / stats user.
const SETTINGS: &[&str] = &[
    "vnext",
    "servers",
    "users",
    "address",
    "port",
    "id",
    "uuid",
    "flow",
    "encryption",
    "security",
    "alterId",
    "alter_id",
    "password",
    "method",
    "cipher",
    "uot",
    "UoTVersion",
    "level",
    "email",
];

/// Left-over paths of `outbound` in document order: empty when the typed profile says it all.
pub(super) fn untyped(outbound: &Map<String, Value>) -> Vec<String> {
    let mut out = Vec::new();
    walk(outbound, "", &mut out);
    out
}

fn walk(o: &Map<String, Value>, prefix: &str, out: &mut Vec<String>) {
    let typed = TYPED
        .iter()
        .find(|(path, _)| *path == prefix)
        .map_or(&[][..], |(_, keys)| *keys);
    for (key, value) in o {
        let path = join(prefix, key);
        if empty(value) {
            continue;
        }
        match key.as_str() {
            // Xray mux has no typed form; a disabled block changes nothing.
            "mux" if prefix.is_empty() => {
                if value.as_object().is_some_and(|m| flag(m, "enabled")) {
                    out.push(path);
                }
            }
            // The model keeps the first pin; Xray accepts any of a comma-joined list. A pin the
            // model cannot read stays with the graph: dropping it would leave an unverified key.
            "pinnedPeerCertSha256"
                if value
                    .as_str()
                    .is_none_or(|v| v.contains(',') || sha256_pin(v).is_none()) =>
            {
                out.push(path);
            }
            // The HTTP header mask keeps only host and path in the model.
            "header" if !prefix.ends_with("quicSettings") && !no_header(value) => out.push(path),
            // ws / XHTTP read `Host` from the headers; any other header is left over.
            "headers" if typed.contains(&"headers") => out.extend(
                value
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                    .map(|(name, _)| join(&path, name)),
            ),
            _ if TYPED.iter().any(|(p, _)| *p == path) => match value {
                Value::Object(m) => walk(m, &path, out),
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_object)
                    .for_each(|m| walk(m, &path, out)),
                _ => out.push(path),
            },
            k if typed.contains(&k) => {}
            _ => out.push(path),
        }
    }
}

/// `null`, `""`, `{}` or `[]`: carries nothing.
fn empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(m) => m.is_empty(),
        _ => false,
    }
}

/// A RAW header block that masks nothing (`type` absent or `none`).
fn no_header(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|t| t.eq_ignore_ascii_case("none"))
}
