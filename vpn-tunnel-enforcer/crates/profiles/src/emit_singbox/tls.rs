//! TLS at emit time (profiles §3.9, tunnel-core §3.15): provider values are kept, app defaults
//! (uTLS fingerprint, TUIC ALPN, the stealth tricks) are added per protocol family.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};

use super::{EmitError, EmitPolicy};
use crate::common::b64::base64_bytes;
use crate::common::fields::{UTLS_FINGERPRINTS, utls_fingerprint};
use crate::model::{Ech, Kind, Profile, ShadowTlsLayer, Tls, TlsTricks, Transport};

/// How sing-box treats the TLS of a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Family {
    /// TLS over TCP: uTLS fingerprint, the TLS tricks (not with Reality), Reality possible.
    TcpTls,
    /// The ShadowTLS dialer: TCP-TLS without the record fragment. The v3 server reads exactly one
    /// TLS record and checks its HMAC as the whole ClientHello (sing-shadowtls
    /// `extractFrame` / `verifyClientHello`): a split hello silently becomes a relay to the
    /// camouflage site. Its SNI is a whitelisted camouflage name anyway: nothing to hide.
    ShadowTls,
    /// QUIC (hysteria2, tuic, the v2ray QUIC transport): uTLS there is not ignored but breaks
    /// every dial (`unsupported usage for uTLS`), and fragments do not apply.
    Quic,
    /// naive: sing-box rejects every TLS option except `server_name`, `certificate`, `ech`.
    Naive,
}

/// Family of the TLS the emitted fragment carries; `None` for protocols without TLS.
pub(super) fn family(p: &Profile) -> Option<Family> {
    let quic_transport = matches!(p.transport, Some(Transport::Quic));
    match &p.kind {
        Kind::Hysteria2 { .. } | Kind::Tuic { .. } => Some(Family::Quic),
        Kind::Naive { .. } => Some(Family::Naive),
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. } if quic_transport => {
            Some(Family::Quic)
        }
        Kind::Vless { .. }
        | Kind::Vmess { .. }
        | Kind::Trojan { .. }
        | Kind::Anytls { .. }
        | Kind::Http { .. } => Some(Family::TcpTls),
        Kind::Shadowsocks {
            shadowtls: Some(_), ..
        } => Some(Family::ShadowTls),
        Kind::Shadowsocks { .. }
        | Kind::Socks { .. }
        | Kind::Wireguard(_)
        | Kind::Amneziawg { .. } => None,
    }
}

/// Protocols sing-box refuses to run without TLS (`C.ErrTLSRequired`): the emitter adds TLS when
/// a pasted or legacy outbound has no `tls` block.
pub(crate) fn tls_required(kind: &Kind) -> bool {
    matches!(
        kind,
        Kind::Hysteria2 { .. } | Kind::Tuic { .. } | Kind::Naive { .. } | Kind::Anytls { .. }
    ) || matches!(
        kind,
        Kind::Shadowsocks {
            shadowtls: Some(_),
            ..
        }
    )
}

/// The `tls` object of a single outbound; `None` when it runs without TLS.
pub(super) fn outbound_tls(p: &Profile, policy: &EmitPolicy) -> Result<Option<Value>, EmitError> {
    let Some(family) = family(p) else {
        return match p.tls {
            Some(_) => Err(EmitError::TlsUnsupported(p.kind.label())),
            None => Ok(None),
        };
    };
    let fallback;
    let tls = match &p.tls {
        Some(tls) => tls,
        None if tls_required(&p.kind) => {
            fallback = Tls::default();
            &fallback
        }
        None => return Ok(None),
    };
    build(tls, family, p, policy).map(Some)
}

/// The `tls` object of the ShadowTLS dialer: the layer's SNI over the profile's TLS options.
pub(super) fn layer_tls(
    p: &Profile,
    layer: &ShadowTlsLayer,
    policy: &EmitPolicy,
) -> Result<Value, EmitError> {
    let mut tls = p.tls.clone().unwrap_or_default();
    if !layer.server_name.trim().is_empty() {
        tls.server_name = Some(layer.server_name.clone());
    }
    build(&tls, Family::ShadowTls, p, policy)
}

fn build(tls: &Tls, family: Family, p: &Profile, policy: &EmitPolicy) -> Result<Value, EmitError> {
    let mut o = Map::new();
    o.insert("enabled".into(), Value::Bool(true));
    if family == Family::Naive {
        put_str(&mut o, "server_name", tls.server_name.as_deref());
        put_str(&mut o, "certificate", tls.certificate_pem.as_deref());
        if let Some(ech) = &tls.ech {
            o.insert("ech".into(), ech_object(ech)?);
        }
        return Ok(Value::Object(o));
    }
    let reality = tls.reality.as_ref();
    if reality.is_some() && family == Family::Quic {
        return Err(EmitError::RealityOverQuic);
    }
    if reality.is_some() && tls.ech.is_some() {
        return Err(EmitError::RealityWithEch);
    }
    // Reality always sends the camouflage SNI and verifies by key: `disable_sni` is an error
    // there and `insecure` meaningless.
    if tls.disable_sni && reality.is_none() {
        o.insert("disable_sni".into(), Value::Bool(true));
    }
    put_str(&mut o, "server_name", tls.server_name.as_deref());
    if tls.insecure && reality.is_none() {
        // sing-box 1.14 pins public keys only: `insecure` with a whole-certificate pin it cannot
        // check would connect without any verification (engine audit: Hysteria2 `pinSHA256`).
        // A blank pin is no pin, as in the engine's selection.
        let cert_pin = tls
            .cert_pin_sha256
            .as_deref()
            .is_some_and(|pin| !pin.trim().is_empty());
        if cert_pin && tls.spki_pin_sha256.is_empty() {
            return Err(EmitError::CertPinUnenforced);
        }
        o.insert("insecure".into(), Value::Bool(true));
    }
    // ALPN is never injected: ws/httpupgrade/grpc/hysteria2/QUIC fill their own only when it is
    // empty and a uTLS preset carries the browser's list. TUIC servers commonly expect `h3`.
    if !tls.alpn.is_empty() {
        o.insert("alpn".into(), json!(tls.alpn));
    } else if matches!(p.kind, Kind::Tuic { .. }) {
        o.insert("alpn".into(), json!(["h3"]));
    }
    put_str(&mut o, "min_version", tls.min_version.as_deref());
    put_str(&mut o, "max_version", tls.max_version.as_deref());
    put_str(&mut o, "certificate", tls.certificate_pem.as_deref());
    if !tls.spki_pin_sha256.is_empty() {
        if tls.certificate_pem.is_some() {
            return Err(EmitError::PinWithCertificate);
        }
        o.insert(
            "certificate_public_key_sha256".into(),
            json!(tls.spki_pin_sha256),
        );
    }
    // Reality authenticates inside the structure of its ClientHello: never fragment it.
    if family == Family::TcpTls && reality.is_none() {
        put_tricks(
            &mut o,
            TlsTricks::effective(p.own_tls_tricks(), policy.tls_compat),
        );
    }
    if let Some(ech) = &tls.ech {
        o.insert("ech".into(), ech_object(ech)?);
    }
    if matches!(family, Family::TcpTls | Family::ShadowTls) {
        let fp = fingerprint(tls.fingerprint.as_deref(), reality.is_some(), p, policy);
        o.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    if let Some(r) = reality {
        o.insert(
            "reality".into(),
            json!({ "enabled": true, "public_key": r.public_key, "short_id": r.short_id }),
        );
    }
    Ok(Value::Object(o))
}

/// sing-box 1.14 `record_fragment` / `fragment` + `fragment_fallback_delay`. sing-box cuts the
/// hello inside the SNI (no length knob) and waits for the ACK where it can see it (elevated);
/// elsewhere it waits the fallback delay, so the split's longest pause goes there. Zero would
/// read as "unset" and become sing-box's 500 ms.
fn put_tricks(o: &mut Map<String, Value>, tricks: TlsTricks) {
    if tricks.record() {
        o.insert("record_fragment".into(), Value::Bool(true));
    }
    if let Some(split) = tricks.hello() {
        let delay = format!("{}ms", split.interval_ms.max.max(1));
        o.insert("fragment".into(), Value::Bool(true));
        o.insert("fragment_fallback_delay".into(), Value::String(delay));
    }
}

/// The trick keys of pasted sing-box options: never re-emitted raw, the typed value decides
/// (`Profile::own_tls_tricks` lifts them), so a typed Off is off and REALITY / ShadowTLS stay whole.
pub(super) fn is_trick_key(path: &[&str]) -> bool {
    matches!(
        path,
        [
            "tls",
            "fragment" | "fragment_fallback_delay" | "record_fragment",
            ..
        ]
    )
}

fn put_str(o: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value.map(str::trim).filter(|v| !v.is_empty()) {
        o.insert(key.into(), Value::String(v.to_owned()));
    }
}

fn ech_object(ech: &Ech) -> Result<Value, EmitError> {
    let mut o = Map::new();
    o.insert("enabled".into(), Value::Bool(true));
    let lines: Vec<&str> = ech
        .config_lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();
    if !lines.is_empty() {
        o.insert("config".into(), json!(ech_pem(&lines)?));
    }
    put_str(
        &mut o,
        "query_server_name",
        ech.query_server_name.as_deref(),
    );
    Ok(Value::Object(o))
}

/// sing-box accepts exactly one `ECH CONFIGS` PEM block, while share links carry the bare
/// (often URL-safe, unpadded) base64 ECHConfigList: re-encode it into canonical PEM.
fn ech_pem(lines: &[&str]) -> Result<Vec<String>, EmitError> {
    if lines.iter().any(|l| l.starts_with("-----BEGIN")) {
        return Ok(lines.iter().map(|l| (*l).to_owned()).collect());
    }
    let joined = lines.concat();
    let bytes = base64_bytes(&joined).ok_or(EmitError::EchConfig)?;
    let body = STANDARD.encode(bytes);
    let mut pem = vec!["-----BEGIN ECH CONFIGS-----".to_owned()];
    pem.extend(
        body.as_bytes()
            .chunks(64)
            .map(|c| c.iter().map(|&b| char::from(b)).collect()),
    );
    pem.push("-----END ECH CONFIGS-----".to_owned());
    Ok(pem)
}

/// Provider fingerprint, else `chrome` for REALITY, else the device default, else (stealth) the
/// per-server rotation, else `chrome`. Without uTLS sing-box sends a Go-stdlib ClientHello, a
/// pattern Russian DPI rate-limits. REALITY servers since Xray 26.9.8 accept only chrome, firefox
/// and safari hellos (RU 2026 plan): the device defaults `android` / `ios` would never connect.
fn fingerprint(
    provider: Option<&str>,
    reality: bool,
    p: &Profile,
    policy: &EmitPolicy,
) -> &'static str {
    let provider = provider.map(|f| f.trim().to_ascii_lowercase());
    if let Some(fp) = UTLS_FINGERPRINTS
        .iter()
        .find(|&&k| Some(k) == provider.as_deref())
    {
        return fp;
    }
    if reality {
        return "chrome";
    }
    match policy.device {
        Some(device) => utls_fingerprint(device),
        None if policy.tls_compat => stealth_fingerprint(&rotation_seed(p)),
        None => "chrome",
    }
}

/// Deterministic Windows-plausible fingerprint for `seed` (`server:port:uuid|password`):
/// stable per server for sticky sessions, yet not one pattern across a whole provider.
/// Java string hash over UTF-16 units, exactly as the old app computed it.
pub fn stealth_fingerprint(seed: &str) -> &'static str {
    const ROTATION: [&str; 3] = ["chrome", "firefox", "edge"];
    let h = seed.encode_utf16().fold(0i32, |h, unit| {
        h.wrapping_mul(31).wrapping_add(i32::from(unit))
    });
    ROTATION[(h.unsigned_abs() % 3) as usize]
}

fn rotation_seed(p: &Profile) -> String {
    let port = if p.port == 0 {
        String::new()
    } else {
        p.port.to_string()
    };
    let credential = match &p.kind {
        Kind::Vless { uuid, .. } | Kind::Vmess { uuid, .. } => uuid.as_str(),
        Kind::Tuic { uuid, password, .. } => {
            if uuid.is_empty() {
                password
            } else {
                uuid
            }
        }
        Kind::Trojan { password }
        | Kind::Shadowsocks { password, .. }
        | Kind::Hysteria2 { password, .. }
        | Kind::Naive { password, .. }
        | Kind::Anytls { password, .. } => password,
        Kind::Socks { password, .. } | Kind::Http { password, .. } => {
            password.as_deref().unwrap_or("")
        }
        Kind::Wireguard(_) | Kind::Amneziawg { .. } => "",
    };
    format!("{}:{port}:{credential}", p.server)
}

/// The uTLS fingerprint the emitted config uses for `p`, `None` when it carries no uTLS
/// (no TLS, QUIC, naive). What the UI should show instead of a stored default.
pub fn effective_fingerprint(p: &Profile, policy: &EmitPolicy) -> Option<&'static str> {
    let utls = matches!(family(p)?, Family::TcpTls | Family::ShadowTls);
    if !utls || (p.tls.is_none() && !tls_required(&p.kind)) {
        return None;
    }
    let tls = p.tls.as_ref();
    let provider = tls.and_then(|t| t.fingerprint.as_deref());
    Some(fingerprint(
        provider,
        tls.is_some_and(|t| t.reality.is_some()),
        p,
        policy,
    ))
}
