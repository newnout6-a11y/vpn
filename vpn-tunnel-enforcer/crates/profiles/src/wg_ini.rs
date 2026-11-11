//! WireGuard `.conf` importer: `[Interface]` / `[Peer]` as written by wg-quick, the WireGuard
//! apps, wgcf (WARP) and AmneziaVPN. Also the WireGuard value parsers the Clash importer shares.
//!
//! Keys are matched case-insensitively (wg-quick lowercases them). AmneziaWG obfuscation keys
//! (`Jc`, `S1`, `H1`, …) cannot be honoured by plain WireGuard (AmneziaWG is a planned WP-12
//! feature): the profile is imported and a Note says whether the server can still be reached.
use std::net::IpAddr;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use crate::clash::parse_u32;
use crate::common::fields::{parse_host, parse_port};
use crate::common::wg::{amnezia_note, interface_address, is_amnezia_key, reserved, unrouted_peer};
use crate::model::{DialPrefs, Host, Kind, Note, Profile, SkipReason, Source, WgPeer, WireGuard};

/// Keys that only matter to wg-quick on Linux or to a server; dropping them changes nothing here.
const SILENT_KEYS: &[&str] = &["listenport", "saveconfig"];

/// `None` when the text is not a WireGuard config.
pub fn parse_wg_ini(text: &str) -> Option<Result<Profile, SkipReason>> {
    let ini = Ini::read(text)?;
    Some(ini.profile())
}

/// Sections of a `.conf`, keys as written, values trimmed.
struct Ini<'a> {
    interfaces: Vec<Vec<(&'a str, &'a str)>>,
    peers: Vec<Vec<(&'a str, &'a str)>>,
}

impl<'a> Ini<'a> {
    /// `None` without an `[Interface]` section.
    fn read(text: &'a str) -> Option<Self> {
        let mut ini = Ini {
            interfaces: Vec::new(),
            peers: Vec::new(),
        };
        let mut current: Option<&mut Vec<(&'a str, &'a str)>> = None;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                current = match name.trim().to_ascii_lowercase().as_str() {
                    "interface" => {
                        ini.interfaces.push(Vec::new());
                        ini.interfaces.last_mut()
                    }
                    "peer" => {
                        ini.peers.push(Vec::new());
                        ini.peers.last_mut()
                    }
                    _ => None,
                };
            } else if let (Some(section), Some((key, value))) =
                (current.as_deref_mut(), line.split_once('='))
            {
                // WireGuard keys are plain words: text pasted around a config (a link, prose)
                // is skipped, so none of it can end up in a Note.
                let key = key.trim();
                if !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    section.push((key, value.trim()));
                }
            }
        }
        (!ini.interfaces.is_empty()).then_some(ini)
    }

    fn profile(&self) -> Result<Profile, SkipReason> {
        if self.interfaces.len() > 1 {
            return Err(invalid("more than one [Interface] section"));
        }
        let interface = &self.interfaces[0];
        let mut notes = Vec::new();
        let mut amnezia = Vec::new();
        let (mut private_key, mut address, mut dns, mut mtu) = (None, Vec::new(), Vec::new(), None);
        for &(key, value) in interface {
            match key.to_ascii_lowercase().as_str() {
                "privatekey" => private_key = Some(value),
                "address" => {
                    for item in list(value) {
                        address.push(
                            interface_address(item).ok_or_else(|| invalid("invalid Address"))?,
                        );
                    }
                }
                // Non-IP entries are wg-quick search domains: nothing to apply them to.
                "dns" => dns.extend(list(value).filter_map(|d| d.parse::<IpAddr>().ok())),
                "mtu" => {
                    mtu = Some(
                        parse_u32(value)
                            .and_then(|n| u16::try_from(n).ok())
                            .filter(|&n| n > 0)
                            .ok_or_else(|| invalid("invalid MTU"))?,
                    )
                }
                lower if is_amnezia_key(lower) => amnezia.push((key, value)),
                lower if SILENT_KEYS.contains(&lower) => {}
                _ => notes.push(Note::UnsupportedField(key.to_owned())),
            }
        }
        let private_key = key(private_key)?;
        if address.is_empty() {
            return Err(invalid("[Interface] without Address"));
        }
        if self.peers.is_empty() {
            return Err(invalid("no [Peer] section"));
        }
        let peers = self
            .peers
            .iter()
            .map(|p| peer(p, &mut notes, &mut amnezia))
            .collect::<Result<Vec<_>, _>>()?;
        if unrouted_peer(&peers) {
            return Err(invalid("[Peer] without AllowedIPs next to other peers"));
        }
        notes.extend(amnezia_note(amnezia));
        let (server, port) = (peers[0].host.clone(), peers[0].port);
        Ok(Profile {
            name: "WireGuard".to_owned(),
            description: None,
            server,
            port,
            kind: Kind::Wireguard(WireGuard {
                private_key,
                local_address: address,
                mtu,
                dns,
                peers,
            }),
            tls: None,
            transport: None,
            mux: None,
            dial: DialPrefs::default(),
            native_xray: None,
            singbox_extra: serde_json::Map::new(),
            source: Source::WgIni,
            notes,
        })
    }
}

fn peer<'a>(
    pairs: &[(&'a str, &'a str)],
    notes: &mut Vec<Note>,
    amnezia: &mut Vec<(&'a str, &'a str)>,
) -> Result<WgPeer, SkipReason> {
    let (mut public_key, mut psk, mut allowed, mut endpoint, mut keepalive_s, mut reserved_bytes) =
        (None, None, Vec::new(), None, None, None);
    for &(name, value) in pairs {
        match name.to_ascii_lowercase().as_str() {
            "publickey" => public_key = Some(value),
            "presharedkey" => psk = Some(key(Some(value))?),
            "allowedips" => {
                for item in list(value) {
                    allowed.push(
                        interface_address(item).ok_or_else(|| invalid("invalid AllowedIPs"))?,
                    );
                }
            }
            "endpoint" => {
                endpoint = Some(parse_endpoint(value).ok_or_else(|| invalid("invalid Endpoint"))?)
            }
            "persistentkeepalive" => keepalive_s = keepalive(value),
            // Not wg-quick, but WARP exporters write it next to the peer.
            "reserved" => {
                reserved_bytes = Some(reserved(value).ok_or_else(|| invalid("invalid Reserved"))?)
            }
            lower if is_amnezia_key(lower) => amnezia.push((name, value)),
            _ => notes.push(Note::UnsupportedField(name.to_owned())),
        }
    }
    // The app dials out: a peer without an endpoint (server-side style) cannot be used.
    let (host, port) = endpoint.ok_or_else(|| invalid("[Peer] without Endpoint"))?;
    Ok(WgPeer {
        host,
        port,
        public_key: key(public_key)?,
        pre_shared_key: psk,
        // Kept as written: the emitter gives a lone peer everything (K21); several peers must
        // each name theirs (`common::wg::unrouted_peer`).
        allowed_ips: allowed,
        keepalive_s,
        reserved: reserved_bytes,
    })
}

fn invalid(detail: &str) -> SkipReason {
    SkipReason::Invalid {
        scheme: "wireguard".to_owned(),
        detail: detail.to_owned(),
    }
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// A WireGuard key: 32 bytes of base64, returned in the padded form the engines expect.
pub(crate) fn key(raw: Option<&str>) -> Result<String, SkipReason> {
    let raw = raw
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .ok_or(SkipReason::MissingCredential)?;
    let bytes = STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .ok()
        .filter(|b| b.len() == 32);
    bytes
        .map(|b| STANDARD.encode(b))
        .ok_or_else(|| invalid("key is not 32 bytes of base64"))
}

/// Seconds between keepalives; `off` / `0` mean none.
pub(crate) fn keepalive(raw: &str) -> Option<u16> {
    parse_u32(raw)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&n| n > 0)
}

/// `host:port` or `[v6]:port`.
fn parse_endpoint(raw: &str) -> Option<(Host, u16)> {
    let (host, port) = raw.trim().rsplit_once(':')?;
    if host.contains(':') && !host.starts_with('[') {
        return None;
    }
    Some((parse_host(host.trim())?, parse_port(port.trim())?))
}

#[cfg(test)]
mod tests;
