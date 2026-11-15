//! Xray Hysteria (Hysteria2) outbounds: Xray 26's `hysteria` protocol with `finalmask` and the
//! generic `servers[]` shape other clients write.
use serde_json::{Map, Value};

use super::singbox::{hy2_obfs, port_ranges};
use super::values::{duration_secs, port, rounded_positive, text, text_or_number};
use super::xray_stream::sub;
use crate::common::fields::port_range;
use crate::model::{Hy2Obfs, Kind, Note, SkipReason};

/// Hysteria2 from Xray's `hysteria` protocol (`settings.version: 2`, password in
/// `streamSettings.hysteriaSettings.auth`) or from the generic `servers[]` shape other clients write.
pub(super) fn hysteria2(
    raw: &Map<String, Value>,
    node: &Map<String, Value>,
    stream: &Map<String, Value>,
    extra: &mut Map<String, Value>,
    notes: &mut Vec<Note>,
) -> Result<(Kind, Option<u16>), SkipReason> {
    let is_xray = text(raw, &["protocol"]).is_some_and(|p| p.eq_ignore_ascii_case("hysteria"));
    if is_xray {
        if node.get("version").and_then(port) != Some(2) {
            return Err(SkipReason::Invalid {
                scheme: "hysteria".into(),
                detail: "only Hysteria version 2 is supported".into(),
            });
        }
        let auth = text_or_number(sub(stream, "hysteriaSettings"), &["auth"])
            .ok_or(SkipReason::MissingCredential)?;
        return Ok((
            finalmask(auth, sub(stream, "finalmask"), extra, notes)?,
            None,
        ));
    }
    let password = text_or_number(node, &["password"]).ok_or(SkipReason::MissingCredential)?;
    let obfs = hy2_obfs(node)?;
    let ports = match ["server_ports", "serverPorts", "mport"]
        .iter()
        .find_map(|k| node.get(*k))
    {
        None => Vec::new(),
        Some(v) => port_ranges(v).unwrap_or_else(|| {
            notes.push(Note::UnsupportedField("server_ports".into()));
            Vec::new()
        }),
    };
    let first = ports.first().map(|r| r.0);
    let rate = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| node.get(*k))
            .and_then(rounded_positive)
    };
    let kind = Kind::Hysteria2 {
        password,
        obfs,
        ports,
        hop_interval_s: ["hop_interval", "hopInterval"]
            .iter()
            .find_map(|k| node.get(*k))
            .and_then(duration_secs),
        hop_interval_max_s: None,
        up_mbps: rate(&["up_mbps", "upMbps", "upmbps"]),
        down_mbps: rate(&["down_mbps", "downMbps", "downmbps"]),
        bbr_profile: None,
    };
    Ok((kind, first))
}

/// Xray 26 Hysteria keeps obfuscation and port hopping in `streamSettings.finalmask`: Salamander
/// (Gecko when it has a `packetSize`) and `quicParams.udpHop` map to sing-box. Every other mask or
/// QUIC knob is a Note: dropped silently, it would leave a profile that cannot reach its server.
fn finalmask(
    password: String,
    mask: &Map<String, Value>,
    extra: &mut Map<String, Value>,
    notes: &mut Vec<Note>,
) -> Result<Kind, SkipReason> {
    let mut note = |path: String| notes.push(Note::UnsupportedField(path));
    let mut obfs = None;
    for layer in mask
        .get("udp")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mask_type = layer
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let settings = layer.get("settings").and_then(Value::as_object);
        let (Some(settings), "salamander", None) = (settings, mask_type, &obfs) else {
            note(format!("finalmask.udp.{mask_type}"));
            continue;
        };
        // Gecko's fragment size is an Int32Range (`512-1200`); sing-box takes the two bounds.
        let kind = match text(settings, &["packetSize"]).map(port_range) {
            None => "salamander",
            Some(Some((min, max))) => {
                extra.insert("obfs.min_packet_size".into(), min.into());
                extra.insert("obfs.max_packet_size".into(), max.into());
                "gecko"
            }
            Some(None) => {
                note("finalmask.udp.salamander.packetSize".into());
                continue;
            }
        };
        let password = text(settings, &["password"]).ok_or_else(|| SkipReason::Invalid {
            scheme: "hysteria".into(),
            detail: "Hysteria2 obfs without a password".into(),
        })?;
        obfs = Some(Hy2Obfs {
            kind: kind.into(),
            password: password.to_owned(),
        });
    }
    let quic = sub(mask, "quicParams");
    let hop = sub(quic, "udpHop");
    let ports = hop.get("ports").map(port_ranges);
    // `interval`: seconds, or a random range `5-10` = sing-box `hop_interval` .. `hop_interval_max`.
    let interval = hop.get("interval").map(|v| match v {
        Value::String(s) => port_range(s),
        _ => port(v).map(|s| (s, s)),
    });
    for (path, bad) in [
        ("ports", matches!(ports, Some(None))),
        ("interval", matches!(interval, Some(None))),
    ] {
        if bad {
            note(format!("finalmask.quicParams.udpHop.{path}"));
        }
    }
    let known = ["udp", "quicParams"];
    for key in mask.keys().filter(|k| !known.contains(&k.as_str())) {
        note(format!("finalmask.{key}"));
    }
    // Brutal as Xray's client runs it (`transport/internet/hysteria/dialer.go`): `brutalDown` is
    // always announced to the server (sing-box `down_mbps`); `brutalUp` paces the upload under
    // the default / `brutal` / `force-brutal` congestion (sing-box `up_mbps`), never under `bbr`.
    // sing-box has no Reno: BBR runs instead (noted).
    let congestion = text(quic, &["congestion"]).map(str::to_ascii_lowercase);
    let up_applies = match congestion.as_deref() {
        None | Some("" | "brutal" | "force-brutal") => true,
        Some("bbr") => false,
        Some(_) => {
            note("finalmask.quicParams.congestion".into());
            false
        }
    };
    let mut rate = |key: &str| {
        let bits = match quic.get(key)? {
            Value::Number(n) => n.as_f64(),
            raw => raw.as_str().and_then(xray_bits),
        };
        // `0` or empty is unset in Xray: nothing to carry, nothing dropped.
        if bits == Some(0.0) {
            return None;
        }
        let mbps = bits.and_then(mbps);
        if mbps.is_none() {
            note(format!("finalmask.quicParams.{key}"));
        }
        mbps
    };
    let up_mbps = rate("brutalUp").filter(|_| up_applies);
    let down_mbps = rate("brutalDown");
    let handled = [
        "udpHop",
        "bbrProfile",
        "congestion",
        "brutalUp",
        "brutalDown",
    ];
    for key in quic.keys().filter(|k| !handled.contains(&k.as_str())) {
        note(format!("finalmask.quicParams.{key}"));
    }
    let (hop_min, hop_max) = interval.flatten().unzip();
    Ok(Kind::Hysteria2 {
        password,
        obfs,
        ports: ports.flatten().unwrap_or_default(),
        hop_interval_s: hop_min.map(u32::from),
        hop_interval_max_s: hop_max.filter(|max| Some(*max) != hop_min).map(u32::from),
        up_mbps,
        down_mbps,
        bbr_profile: text(quic, &["bbrProfile"]).map(str::to_owned),
    })
}

/// Xray `Bandwidth` (`infra/conf/transport_method.go`) in bit/s: case-insensitive, always bits,
/// binary multiples (`100 mbps` = 100 * 2^20 bit/s); empty is 0, which Xray reads as unset.
fn xray_bits(raw: &str) -> Option<f64> {
    let s = raw.trim().to_ascii_lowercase();
    if s.is_empty() {
        return Some(0.0);
    }
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let value: f64 = s[..split].parse().ok()?;
    let power = match s[split..].trim() {
        "" | "b" | "bps" => 0,
        "k" | "kb" | "kbps" => 1,
        "m" | "mb" | "mbps" => 2,
        "g" | "gb" | "gbps" => 3,
        "t" | "tb" | "tbps" => 4,
        _ => return None,
    };
    Some(value * 1024f64.powi(power))
}

/// sing-box Mbps (10^6 bit/s, at least 1) of a positive rate.
fn mbps(bits: f64) -> Option<u32> {
    let mbps = (bits / 1e6).round().max(1.0);
    (bits > 0.0 && mbps <= f64::from(u32::MAX)).then_some(mbps as u32)
}
