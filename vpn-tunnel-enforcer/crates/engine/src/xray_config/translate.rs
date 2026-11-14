//! Typed profile -> one Xray `OutboundObject` tagged `proxy`.
use serde_json::{Map, Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Kind, Profile};

use super::select::{singbox_only, vless_encryption, xray_protocol};
use super::stream::stream;
use super::{PROXY_TAG, XrayConfigError, hysteria, wireguard};

/// Translates the typed fields of `p` into an Xray outbound tagged `proxy`. `address` is the
/// profile's server as stored (host name or IP literal): endpoint pre-resolution replaces it
/// with an IP later, and every name Xray would derive from it (SNI, Host, gRPC authority) is
/// already written out. A provider graph (`native_xray`) is not looked at; [`super::proxy_graph`]
/// compiles it instead. `device` picks the default uTLS fingerprint. What the translation leaves
/// out is reported by [`super::warnings`].
pub fn translate(p: &Profile, device: ClientDevice) -> Result<Value, XrayConfigError> {
    if !xray_protocol(p) {
        return Err(XrayConfigError::Protocol(protocol_name(&p.kind)));
    }
    if let Some(feature) = singbox_only(p) {
        return Err(XrayConfigError::Feature(feature));
    }
    let mut outbound = match &p.kind {
        Kind::Hysteria2 { .. } => hysteria::outbound(p)?,
        // TLS, transport and mux mean nothing to WireGuard; sing-box ignores them too.
        Kind::Wireguard(wg) => wireguard::outbound(wg),
        kind => {
            let stream = stream(p, device)?;
            let settings = settings(kind, &p.server.to_string(), p.port, stream.flow_ok)?;
            json!({
                "protocol": kind.label(),
                "settings": settings,
                "streamSettings": stream.settings,
            })
        }
    };
    outbound["tag"] = json!(PROXY_TAG);
    Ok(outbound)
}

/// Exactly one `vnext` / `servers` entry with one user (Xray refuses more), or the simple
/// `address` / `port` form of SOCKS and HTTP.
fn settings(
    kind: &Kind,
    address: &str,
    port: u16,
    flow_ok: bool,
) -> Result<Value, XrayConfigError> {
    let node =
        |users: Value| json!({"vnext": [{"address": address, "port": port, "users": users}]});
    Ok(match kind {
        Kind::Vless { uuid, flow, .. } => {
            let mut user = Map::new();
            user.insert("id".into(), json!(uuid.trim()));
            user.insert(
                "encryption".into(),
                json!(vless_encryption(kind).unwrap_or("none")),
            );
            // XTLS Vision needs TLS / REALITY on RAW, or VLESS Encryption (any transport).
            let flow = flow.as_deref().map(str::trim).filter(|f| !f.is_empty());
            if let Some(flow) = flow.filter(|_| flow_ok) {
                user.insert("flow".into(), json!(flow));
            }
            node(json!([user]))
        }
        Kind::Vmess {
            uuid,
            security,
            authenticated_length,
            ..
        } => {
            // No `alterId`: Xray's VMess is AEAD-only. Global padding is always on in Xray.
            let security = match security.trim() {
                "" => "auto",
                s => s,
            };
            let mut user = Map::new();
            user.insert("id".into(), json!(uuid.trim()));
            user.insert("security".into(), json!(security));
            if *authenticated_length {
                user.insert("experiments".into(), json!("AuthenticatedLength"));
            }
            node(json!([user]))
        }
        Kind::Trojan { password } => {
            json!({"servers": [{"address": address, "port": port, "password": password}]})
        }
        Kind::Shadowsocks {
            method,
            password,
            uot,
            ..
        } => {
            let mut server = json!({
                "address": address,
                "port": port,
                "method": method.trim().to_ascii_lowercase(),
                "password": password,
            });
            // Selection lets UoT through only with a 2022 cipher, the only kind Xray applies it
            // to. sing-box's default version is 2.
            if let Some(version) = uot {
                server["uot"] = json!(true);
                server["UoTVersion"] = json!(if *version == 1 { 1 } else { 2 });
            }
            json!({"servers": [server]})
        }
        Kind::Socks { username, password } | Kind::Http { username, password } => {
            let mut s = Map::new();
            s.insert("address".into(), json!(address));
            s.insert("port".into(), json!(port));
            // Xray authenticates only with a user name; a lone password means no auth there.
            if let Some(user) = username.as_deref().filter(|u| !u.is_empty()) {
                s.insert("user".into(), json!(user));
                s.insert(
                    "pass".into(),
                    json!(password.as_deref().unwrap_or_default()),
                );
            }
            Value::Object(s)
        }
        // Hysteria2 and WireGuard have their own modules; selection keeps the rest away.
        other => return Err(XrayConfigError::Protocol(protocol_name(other))),
    })
}

/// Protocol label for errors; a Shadowsocks key behind ShadowTLS reads as `shadowtls`.
fn protocol_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Shadowsocks {
            shadowtls: Some(_), ..
        } => "shadowtls",
        other => other.label(),
    }
}
