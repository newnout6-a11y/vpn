//! Hysteria2 as Xray's `hysteria` outbound (version 2) over the `hysteria` QUIC transport, with
//! salamander / gecko obfuscation, port hopping and Brutal bandwidth in `finalmask`.
use serde_json::{Map, Value, json};
use vpnte_profiles::model::{Hy2Obfs, Kind, Profile, Tls};

use super::XrayConfigError;
use super::stream::tls_common;

/// BBR presets Xray knows; any other name fails the whole config ("unknown bbr profile").
const BBR_PROFILES: [&str; 3] = ["conservative", "standard", "aggressive"];
/// Xray's shortest port-hopping interval, in seconds.
const MIN_HOP_S: u32 = 5;
/// The hopping interval of Xray and sing-box when the profile sets only a maximum, in seconds.
const DEFAULT_HOP_S: u32 = 30;
/// sing-box's gecko packet sizes (`min_packet_size` / `max_packet_size` defaults, which the
/// profile cannot change); Xray's gecko is salamander with this range.
const GECKO_PACKET_SIZE: &str = "512-1200";

/// The outbound of a Hysteria2 profile (without its tag). TLS is always on (Xray requires it);
/// an insecure profile gets here only with a pinned certificate or certificate names (selection
/// checks first; see `tls_common`).
pub(super) fn outbound(p: &Profile) -> Result<Value, XrayConfigError> {
    let Kind::Hysteria2 {
        password,
        obfs,
        ports,
        hop_interval_s,
        hop_interval_max_s,
        up_mbps,
        down_mbps,
        bbr_profile,
    } = &p.kind
    else {
        return Err(XrayConfigError::Protocol(p.kind.label()));
    };
    let fallback = Tls::default();
    // No ALPN default: Xray's hysteria transport offers h3 itself (checked live against a
    // sing-box server); a provider ALPN is kept.
    let tls = tls_common(p, p.tls.as_ref().unwrap_or(&fallback));
    let mut quic = Map::new();
    for (key, mbps) in [("brutalUp", up_mbps), ("brutalDown", down_mbps)] {
        // 0 or unset: BBR, as on sing-box.
        if let Some(n) = mbps.filter(|n| *n > 0) {
            quic.insert(key.into(), json!(format!("{n} mbps")));
        }
    }
    if let Some(bbr) = bbr_profile.as_deref().and_then(bbr_preset) {
        quic.insert("bbrProfile".into(), json!(bbr));
    }
    if let Some(hop) = udp_hop(ports, *hop_interval_s, *hop_interval_max_s) {
        quic.insert("udpHop".into(), hop);
    }
    let mut mask = Map::new();
    if let Some(obfs) = obfs {
        mask.insert("udp".into(), json!([salamander(obfs)?]));
    }
    if !quic.is_empty() {
        mask.insert("quicParams".into(), Value::Object(quic));
    }
    let mut stream = json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": password},
    });
    if !mask.is_empty() {
        stream["finalmask"] = Value::Object(mask);
    }
    Ok(json!({
        "protocol": "hysteria",
        "settings": {"version": 2, "address": p.server.to_string(), "port": p.port},
        "streamSettings": stream,
    }))
}

/// The BBR preset Xray accepts for `raw`, if any (an unknown one is dropped with a warning).
pub(super) fn bbr_preset(raw: &str) -> Option<&'static str> {
    let raw = raw.trim();
    BBR_PROFILES
        .iter()
        .copied()
        .find(|b| b.eq_ignore_ascii_case(raw))
}

/// `udpHop` for the hopping ranges (sing-box drops a range starting at port 0, so does this);
/// a min / max interval becomes Xray's random range `"a-b"`.
fn udp_hop(ranges: &[(u16, u16)], min_s: Option<u32>, max_s: Option<u32>) -> Option<Value> {
    let ports: Vec<String> = ranges
        .iter()
        .map(|&(a, b)| (a.min(b), a.max(b)))
        .filter(|&(start, _)| start > 0)
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect();
    if ports.is_empty() {
        return None;
    }
    let mut hop = json!({"ports": ports.join(",")});
    if min_s.is_some() || max_s.is_some() {
        let min = min_s.unwrap_or(DEFAULT_HOP_S).max(MIN_HOP_S);
        hop["interval"] = match max_s.filter(|max| *max > min) {
            Some(max) => json!(format!("{min}-{max}")),
            None => json!(min),
        };
    }
    Some(hop)
}

/// One `finalmask.udp` layer; gecko is salamander with a packet size range in Xray.
fn salamander(obfs: &Hy2Obfs) -> Result<Value, XrayConfigError> {
    let kind = obfs.kind.trim().to_ascii_lowercase();
    if obfs.password.is_empty() || !matches!(kind.as_str(), "salamander" | "gecko") {
        return Err(XrayConfigError::Invalid("obfs"));
    }
    let mut settings = json!({"password": obfs.password});
    if kind == "gecko" {
        settings["packetSize"] = json!(GECKO_PACKET_SIZE);
    }
    Ok(json!({"type": "salamander", "settings": settings}))
}
