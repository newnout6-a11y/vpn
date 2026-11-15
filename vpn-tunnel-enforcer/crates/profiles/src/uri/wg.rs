//! WireGuard (`wireguard://`, `wg://`): one peer; parameter names in any case (Happ writes
//! `publickey`), addresses without a prefix become /32 or /128. AmneziaWG parameters (`jc`,
//! `s1`, `h1`, `header-protection-key`, …) that turn obfuscation on make an AmneziaWG profile.
use std::net::IpAddr;

use ipnet::IpNet;

use super::parts::{Link, Params, duration_ms};
use super::{Meta, Res, bad, skip};
use crate::awg::AwgReader;
use crate::common::wg::{interface_address, wireguard_kind};
use crate::model::{Note, Profile, SkipReason, WgPeer, WireGuard};

const DEFAULT_PORT: u16 = 51820;

pub(super) fn wireguard(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(Some(DEFAULT_PORT))?;
    let p = &link.params;
    let (user, pass) = link.user_password();
    let private_key = Some(user)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            p.get(&["privateKey", "private_key", "pk", "secretKey"])
                .map(str::to_owned)
        })
        .unwrap_or_default();
    // The compact form `wireguard://<private>:<peer public>@host:port` puts the peer key in the
    // password slot.
    let public_key = p
        .get(&[
            "publicKey",
            "public_key",
            "pubkey",
            "peerPublicKey",
            "peer_public_key",
        ])
        .map(str::to_owned)
        .or(pass.filter(|v| !v.is_empty()))
        .unwrap_or_default();
    if private_key.is_empty() || public_key.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let mut notes = Vec::new();
    let peer = WgPeer {
        host: server.clone(),
        port,
        public_key,
        pre_shared_key: p
            .get(&["presharedKey", "preshared_key", "pre_shared_key", "psk"])
            .map(str::to_owned),
        allowed_ips: nets(&p.csv(&["allowedIPs", "allowed_ips", "allowed-ips"]))?,
        keepalive_s: keepalive(p, &mut notes),
        reserved: reserved(p)?,
    };
    let config = WireGuard {
        private_key,
        local_address: nets(&p.csv(&["ip", "address", "localAddress", "local_address"]))?,
        mtu: mtu(p, &mut notes),
        dns: dns(p, &mut notes),
        peers: vec![peer],
    };
    let mut awg = AwgReader::default();
    for (key, value) in p.pairs() {
        awg.take(key, value);
    }
    let awg = match awg.finish() {
        Ok(awg) => awg,
        Err(invalid) => return skip(SkipReason::AwgInvalid(invalid)),
    };
    let mut profile = meta.profile(server, port, wireguard_kind(config, awg));
    profile.notes = notes;
    Ok(profile)
}

/// Networks from a list; a bare address gets the full prefix (WARP links give `10.0.0.2`).
fn nets(items: &[String]) -> Res<Vec<IpNet>> {
    items
        .iter()
        .map(|item| interface_address(item).map_or_else(|| bad("invalid WireGuard address"), Ok))
        .collect()
}

/// `reserved`: three bytes as `1,22,33` or base64 (`AQID`); WARP rejects anything else.
fn reserved(p: &Params) -> Res<Option<[u8; 3]>> {
    match p.get(&["reserved"]) {
        None => Ok(None),
        Some(raw) => crate::common::wg::reserved(raw).map_or_else(
            || bad("WireGuard reserved must be three bytes"),
            |r| Ok(Some(r)),
        ),
    }
}

fn keepalive(p: &Params, notes: &mut Vec<Note>) -> Option<u16> {
    let names = [
        "keepalive",
        "persistent_keepalive",
        "persistentKeepalive",
        "persistent-keepalive",
    ];
    let raw = p.get(&names)?;
    let secs = duration_ms(raw, 1000).and_then(|ms| u16::try_from(ms / 1000).ok());
    if secs.is_none() {
        notes.push(Note::UnsupportedField("keepalive".into()));
    }
    secs
}

fn mtu(p: &Params, notes: &mut Vec<Note>) -> Option<u16> {
    let raw = p.get(&["mtu"])?;
    let mtu = raw.trim().parse::<u16>().ok().filter(|v| *v > 0);
    if mtu.is_none() {
        notes.push(Note::UnsupportedField("mtu".into()));
    }
    mtu
}

/// DNS servers: IP addresses only; anything else is noted once and left out.
fn dns(p: &Params, notes: &mut Vec<Note>) -> Vec<IpAddr> {
    let items = p.csv(&["dns"]);
    let servers: Vec<IpAddr> = items.iter().filter_map(|i| i.parse().ok()).collect();
    if servers.len() != items.len() {
        notes.push(Note::UnsupportedField("dns".into()));
    }
    servers
}
