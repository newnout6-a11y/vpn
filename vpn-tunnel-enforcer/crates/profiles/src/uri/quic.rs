//! QUIC protocols: Hysteria2 (`hysteria2://`, `hy2://`) and TUIC.
use super::parts::{Link, Params, duration_ms, host_port, secs};
use super::stream::{TlsMode, tls};
use super::{Meta, Res, bad, skip};
use crate::common::fields::{HY2_OBFS_TYPES, port_range};
use crate::model::{Hy2Obfs, Kind, Note, Profile, SkipReason};

/// Official Hysteria2 URI default when the authority has no port.
const HY2_DEFAULT_PORT: u16 = 443;

pub(super) fn hysteria2(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let p = &link.params;
    // The authority may carry a port-hopping list (`host:443,20000-30000`).
    let (server, raw_ports) = host_port(link.hostport)?;
    let authority = raw_ports.map(port_list).transpose()?.unwrap_or_default();
    let extra = p
        .get(&["mport", "ports", "server_ports", "serverPorts"])
        .map(port_list)
        .transpose()?;
    let extra = extra.unwrap_or_default();
    let port = authority
        .first()
        .or(extra.first())
        .map_or(HY2_DEFAULT_PORT, |range| range.0);
    // One authority port is just the dial port; a list or a range there is a hopping set.
    let hopping = authority.len() > 1 || authority.first().is_some_and(|(a, b)| a != b);
    let mut ports = if hopping { authority } else { Vec::new() };
    ports.extend(extra);
    // Official `userpass` auth is `user:pass` used as one password, so the whole userinfo counts.
    let password = Some(link.userinfo_whole())
        .filter(|v| !v.is_empty())
        .or_else(|| p.get(&["password", "auth"]).map(str::to_owned))
        .unwrap_or_default();
    if password.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let mut notes = Vec::new();
    let kind = Kind::Hysteria2 {
        password,
        obfs: obfs(p, &mut notes)?,
        ports,
        hop_interval_s: hop_interval(p, &mut notes),
        hop_interval_max_s: None,
        up_mbps: mbps(p, &["up_mbps", "upMbps", "upmbps", "up"], &mut notes),
        down_mbps: mbps(
            p,
            &["down_mbps", "downMbps", "downmbps", "down"],
            &mut notes,
        ),
        bbr_profile: None,
    };
    let mut profile = meta.profile(server, port, kind);
    profile.notes = notes;
    profile.tls = tls(p, TlsMode::AlwaysNoReality, &mut profile.notes)?;
    fingerprint_note(&mut profile);
    Ok(profile)
}

pub(super) fn tuic(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(None)?;
    let p = &link.params;
    let (user, pass) = link.user_password();
    let uuid = Some(user)
        .filter(|v| !v.is_empty())
        .or_else(|| p.get(&["uuid"]).map(str::to_owned))
        .unwrap_or_default();
    let password = pass
        .filter(|v| !v.is_empty())
        .or_else(|| p.get(&["password"]).map(str::to_owned))
        .unwrap_or_default();
    if uuid.is_empty() || password.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let mut notes = Vec::new();
    let congestion = p
        .get(&["congestion_control", "congestionControl", "congestion"])
        .map(|cc| cc.to_ascii_lowercase().replace("new-reno", "new_reno"));
    let heartbeat_s = match p.get(&["heartbeat"]) {
        None => None,
        Some(raw) => {
            let secs = duration_ms(raw, 1000).and_then(secs);
            if secs.is_none() {
                notes.push(Note::UnsupportedField("heartbeat".into()));
            }
            secs
        }
    };
    let kind = Kind::Tuic {
        uuid,
        password,
        congestion,
        udp_relay_mode: p
            .get(&["udp_relay_mode", "udpRelayMode"])
            .map(str::to_owned),
        zero_rtt: p.flag(&["reduce_rtt", "zero_rtt_handshake", "zeroRttHandshake"]),
        heartbeat_s,
    };
    let mut profile = meta.profile(server, port, kind);
    profile.notes = notes;
    profile.tls = tls(p, TlsMode::AlwaysNoReality, &mut profile.notes)?;
    fingerprint_note(&mut profile);
    Ok(profile)
}

/// A provider uTLS fingerprint cannot shape a QUIC handshake: keep it, but tell the user.
pub(super) fn fingerprint_note(profile: &mut Profile) {
    if profile
        .tls
        .as_ref()
        .is_some_and(|tls| tls.fingerprint.is_some())
    {
        profile.notes.push(Note::ProviderFpDroppedOnQuic);
    }
}

fn obfs(p: &Params, notes: &mut Vec<Note>) -> Res<Option<Hy2Obfs>> {
    let Some(kind) = p.get(&["obfs"]).map(str::to_ascii_lowercase) else {
        return Ok(None);
    };
    if kind == "none" {
        return Ok(None);
    }
    if !HY2_OBFS_TYPES.contains(&kind.as_str()) {
        return bad("unknown Hysteria2 obfs type");
    }
    let Some(password) = p.get(&["obfs-password", "obfs_password", "obfsPassword"]) else {
        return bad("Hysteria2 obfs without a password");
    };
    // sing-box 1.14 knows gecko packet sizes, the profile model does not: say so.
    for (field, aliases) in [
        (
            "obfs-min-packet-size",
            ["obfs-min-packet-size", "obfs_min_packet_size"],
        ),
        (
            "obfs-max-packet-size",
            ["obfs-max-packet-size", "obfs_max_packet_size"],
        ),
    ] {
        if p.get(&aliases).is_some() {
            notes.push(Note::UnsupportedField(field.into()));
        }
    }
    Ok(Some(Hy2Obfs {
        kind,
        password: password.to_owned(),
    }))
}

/// Hop interval in seconds: `hop_interval` (Go duration, bare integer = seconds as in mihomo)
/// or Happ's `mportHopInt` (seconds).
fn hop_interval(p: &Params, notes: &mut Vec<Note>) -> Option<u32> {
    let raw = p.get(&["hop_interval", "hopInterval", "hop-interval", "mportHopInt"])?;
    let secs = duration_ms(raw, 1000).and_then(secs);
    if secs.is_none() {
        notes.push(Note::UnsupportedField("hop_interval".into()));
    }
    secs
}

/// Bandwidth in whole Mbps (`80`, `80.4`, `80 Mbps`); zero, negative or garbage is noted.
fn mbps(p: &Params, aliases: &[&str], notes: &mut Vec<Note>) -> Option<u32> {
    let raw = p.get(aliases)?;
    let lower = raw.trim().to_ascii_lowercase();
    let number = lower.strip_suffix("mbps").unwrap_or(&lower).trim();
    let value = number
        .parse::<f64>()
        .ok()
        .filter(|v| (0.5..=f64::from(u32::MAX)).contains(v));
    if value.is_none() {
        notes.push(Note::UnsupportedField(aliases[0].into()));
    }
    // The range check above keeps the rounded value inside u32.
    value.map(|v| v.round() as u32)
}

/// `443,20000-30000` (ranges also as `a:b`), inclusive; empty items (a trailing comma) are
/// ignored, any other bad item rejects the link instead of silently turning hopping off.
fn port_list(raw: &str) -> Res<Vec<(u16, u16)>> {
    let ranges = raw
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(|item| port_range(item).map_or_else(|| bad("invalid port range"), Ok))
        .collect::<Res<Vec<_>>>()?;
    if ranges.is_empty() {
        return bad("invalid port");
    }
    Ok(ranges)
}
