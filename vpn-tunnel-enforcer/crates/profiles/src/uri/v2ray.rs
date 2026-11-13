//! VLESS, VMess (v2rayN base64 JSON and the Xray URI form) and Trojan.
use serde_json::{Map, Value};

use super::parts::{Link, Params, description, host_name, name, port, split_once};
use super::stream::{TlsMode, mux, tls, transport};
use super::tricks::link_tricks;
use super::{Meta, Res, bad, skip};
use crate::common::b64::base64_text;
use crate::model::{Host, Kind, Note, Profile, Reality, SkipReason, Tls};

pub(super) fn vless(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(None)?;
    // Any non-empty id: non-UUID strings are Xray "custom ids" mapped to a UUID by the engine.
    let (uuid, _) = link.user_password();
    if uuid.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let p = &link.params;
    // VLESS `encryption=mlkem768x25519plus…` (Xray only); `none` is the protocol default.
    let encryption = p
        .get(&["encryption"])
        .filter(|e| !e.eq_ignore_ascii_case("none"))
        .map(str::to_owned);
    let plaintext = encryption.is_none();
    let kind = Kind::Vless {
        uuid,
        flow: p.get(&["flow"]).map(str::to_owned),
        packet_encoding: p
            .get(&["packetEncoding", "packet_encoding"])
            .map(str::to_owned),
        encryption,
    };
    let mut profile = meta.profile(server, port, kind);
    stream(&mut profile, p, TlsMode::Optional)?;
    if plaintext && profile.tls.is_none() {
        profile.notes.push(Note::Unencrypted);
    }
    Ok(profile)
}

pub(super) fn trojan(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(None)?;
    // The whole userinfo is the password: a raw `:` belongs to it.
    let password = link.userinfo_whole();
    if password.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let mut profile = meta.profile(server, port, Kind::Trojan { password });
    stream(&mut profile, &link.params, TlsMode::DefaultOn)?;
    if profile.tls.is_none() {
        profile.notes.push(Note::Unencrypted);
    }
    Ok(profile)
}

/// `vmess://<uuid>@host:port?…` (Xray standard) or `vmess://<base64 JSON>[?…][#name]` (v2rayN).
pub(super) fn vmess(body: &str, meta: Meta) -> Res<Profile> {
    let (before_query, _) = split_once(body, '?');
    if before_query.contains('@') {
        return vmess_uri(body, meta);
    }
    vmess_json(before_query, meta)
}

fn vmess_uri(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(None)?;
    let (uuid, _) = link.user_password();
    let p = &link.params;
    // In the Xray share-link standard `encryption` is the VMess cipher.
    let security = p.get(&["encryption", "scy"]).unwrap_or("auto");
    let alter_id = p.get(&["aid", "alterId"]).map_or(0, alter_id);
    vmess_profile(meta, (server, port), uuid, security.to_owned(), alter_id, p)
}

/// v2rayN JSON: the query was cut off; a `#name` fragment names the key when `ps` is empty.
fn vmess_json(payload: &str, mut meta: Meta) -> Res<Profile> {
    let Some(text) = base64_text(payload) else {
        return bad("VMess link is neither base64 JSON nor id@host:port");
    };
    let Ok(Value::Object(raw)) = serde_json::from_str::<Value>(&text) else {
        return bad("VMess payload is not a JSON object");
    };
    let field = |names: &[&str]| names.iter().find_map(|n| json_text(raw.get(*n)));
    if let Some(name) = field(&["ps", "name"]).as_deref().and_then(name) {
        meta.name = Some(name);
    }
    if let Some(text) = field(&["serverDescription"])
        .as_deref()
        .and_then(description)
    {
        meta.description = Some(text);
    }
    let Some(address) = field(&["add", "server", "address"]) else {
        return bad("missing server address");
    };
    // `json_text` trims; brackets around an IPv6 address are optional here.
    let server = host_name(&address)?;
    let Some(raw_port) = field(&["port", "server_port"]) else {
        return bad("missing port");
    };
    let port = port(&raw_port)?;
    let uuid = field(&["id", "uuid"]).unwrap_or_default();
    let security = field(&["scy", "security"]).unwrap_or_else(|| "auto".to_owned());
    let alter_id = field(&["aid", "alterId"]).map_or(0, |v| alter_id(&v));
    let params = json_params(&raw);
    vmess_profile(meta, (server, port), uuid, security, alter_id, &params)
}

fn vmess_profile(
    meta: Meta,
    (server, port): (Host, u16),
    uuid: String,
    security: String,
    alter_id: u32,
    p: &Params,
) -> Res<Profile> {
    if uuid.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let plaintext = matches!(security.to_ascii_lowercase().as_str(), "none" | "zero");
    let kind = Kind::Vmess {
        uuid,
        security,
        global_padding: false,
        authenticated_length: false,
    };
    let mut profile = meta.profile(server, port, kind);
    // Legacy alterId > 0 (MD5 auth) is gone from modern servers; AEAD (0) is always accepted.
    if alter_id != 0 {
        profile.notes.push(Note::AlterIdNormalized(alter_id));
    }
    stream(&mut profile, p, TlsMode::Optional)?;
    if plaintext && profile.tls.is_none() {
        profile.notes.push(Note::Unencrypted);
    }
    Ok(profile)
}

/// Xray link parameters the profile model cannot carry (UDP noise, gRPC authority): noted so
/// the loss is visible.
const UNMODELED: &[&str] = &["noises", "authority"];

/// TLS, transport and mux of the V2Ray-family schemes.
fn stream(profile: &mut Profile, p: &Params, mode: TlsMode) -> Res<()> {
    profile.tls = tls(p, mode, &mut profile.notes)?;
    // Tricks cut the ClientHello: without TLS, or unreadable, the link's value is only noted.
    match (link_tricks(p), profile.tls.as_mut()) {
        (Some(Some(tricks)), Some(tls)) => tls.tricks = Some(tricks),
        (Some(_), _) => profile
            .notes
            .push(Note::UnsupportedField("fragment".into())),
        (None, _) => {}
    }
    xray_checks(profile, p)?;
    profile.transport = transport(p)?;
    profile.mux = mux(p);
    let unmodeled = UNMODELED.iter().filter(|name| p.get(&[name]).is_some());
    profile
        .notes
        .extend(unmodeled.map(|name| Note::UnsupportedField((*name).into())));
    Ok(())
}

/// Xray 26 checks on top of the shared TLS reader: `vcn` (`verifyPeerCertByName`) on TLS, `pqv`
/// (`mldsa65Verify`) on REALITY. On the other security they mean nothing: dropped with a note.
/// A malformed `pqv` fails the link, like a malformed pin: Xray refuses to start with it, and
/// dropping it would skip a check the provider asked for.
fn xray_checks(profile: &mut Profile, p: &Params) -> Res<()> {
    let mut names = p
        .get(&["vcn", "verifyPeerCertByName"])
        .and_then(Tls::parse_cert_names);
    let mut pq = p.get(&["pqv", "mldsa65Verify"]);
    if let Some(tls) = profile.tls.as_mut() {
        match tls.reality.as_mut() {
            Some(reality) => {
                if let Some(raw) = pq.take() {
                    let Some(key) = Reality::parse_mldsa65_key(raw) else {
                        return bad("REALITY ML-DSA-65 key (pqv) is not a valid public key");
                    };
                    reality.mldsa65_verify = Some(key);
                }
            }
            None => tls.verify_peer_cert_by_name = names.take(),
        }
    }
    let dropped = [("vcn", names.is_some()), ("pqv", pq.is_some())];
    profile.notes.extend(
        dropped
            .iter()
            .filter(|(_, lost)| *lost)
            .map(|(name, _)| Note::UnsupportedField((*name).into())),
    );
    Ok(())
}

/// Query-style parameters synthesised from the v2rayN JSON fields, so both VMess forms share
/// one TLS / transport reader.
fn json_params(raw: &Map<String, Value>) -> Params {
    let text = |key: &str| json_text(raw.get(key));
    let mut p = Params::default();
    let copied = [
        ("tls", "security"),
        ("sni", "sni"),
        ("fp", "fp"),
        ("net", "type"),
        ("type", "headerType"),
        ("host", "host"),
        ("path", "path"),
        ("mode", "mode"),
        ("multiMode", "multiMode"),
        ("allowInsecure", "allowInsecure"),
        ("insecure", "insecure"),
        ("skip-cert-verify", "skip-cert-verify"),
        ("pbk", "pbk"),
        ("sid", "sid"),
        ("spx", "spx"),
        ("pcs", "pcs"),
        ("vcn", "vcn"),
    ];
    for (json, param) in copied {
        if let Some(value) = text(json) {
            p.push(param, value);
        }
    }
    let alpn = match raw.get("alpn") {
        Some(Value::Array(items)) => {
            let items: Vec<String> = items.iter().filter_map(|i| json_text(Some(i))).collect();
            Some(items.join(","))
        }
        other => json_text(other),
    };
    if let Some(alpn) = alpn.filter(|a| !a.is_empty()) {
        p.push("alpn", alpn);
    }
    let net = text("net").unwrap_or_default().to_ascii_lowercase();
    // v2rayN and 3x-ui write the gRPC / XHTTP mode into `type` (elsewhere the TCP header type);
    // ignoring it would dial gRPC `multi` servers in `gun` mode, which connects and then stalls.
    if matches!(net.as_str(), "grpc" | "xhttp" | "splithttp")
        && text("mode").is_none()
        && let Some(mode) = text("type").filter(|t| !t.eq_ignore_ascii_case("none"))
    {
        p.push("mode", mode);
    }
    if let Some(service) = (net == "grpc")
        .then(|| text("serviceName").or_else(|| text("path")))
        .flatten()
    {
        p.push("serviceName", service);
    }
    match raw.get("extra") {
        None | Some(Value::Null) => {}
        Some(Value::String(extra)) => p.push("extra", extra.as_str()),
        Some(other) => p.push("extra", other.to_string()),
    }
    p
}

/// A JSON scalar as text: trimmed non-empty strings, numbers, booleans.
fn json_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.trim()).filter(|s| !s.is_empty()).map(str::to_owned),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Provider `alterId`; text that is not a number counts as 0 (AEAD).
fn alter_id(raw: &str) -> u32 {
    raw.trim().parse().unwrap_or(0)
}
