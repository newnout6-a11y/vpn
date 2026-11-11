//! WireGuard field values written the same way in share links, sing-box JSON, Clash YAML and
//! `.conf` files: interface / allowed addresses, WARP `reserved` bytes, AmneziaWG keys.
use std::net::IpAddr;

use ipnet::IpNet;

use super::b64::base64_bytes;
use crate::model::{Note, WgPeer};

/// Note key: AmneziaWG handshake obfuscation (`S1`-`S4`, `H1`-`H4`) the server requires.
pub const NOTE_AMNEZIA_INCOMPATIBLE: &str = "profiles.wgIni.amneziaIncompatible";
/// Note key: client-side AmneziaWG junk packets (`Jc`, `I1`-`I5`, `J1`-`J3`) are not sent.
pub const NOTE_AMNEZIA_JUNK: &str = "profiles.wgIni.amneziaJunkDropped";

/// Several peers and one of them names no AllowedIPs: wg-quick would route nothing to it and
/// an implicit full tunnel would make the peers fight over the same routes, so the emitter
/// refuses it and the importers skip such a file instead of storing a key that never connects.
/// A lone peer without routes carries everything (K21).
pub fn unrouted_peer(peers: &[WgPeer]) -> bool {
    peers.len() > 1 && peers.iter().any(|peer| peer.allowed_ips.is_empty())
}

/// `10.0.0.2` -> `10.0.0.2/32`, `fd00::2` -> `/128` (WARP links and old imports give bare
/// addresses, K21); an explicit prefix is kept as written.
pub fn interface_address(raw: &str) -> Option<IpNet> {
    let raw = raw.trim();
    if raw.contains('/') {
        raw.parse().ok()
    } else {
        raw.parse::<IpAddr>().ok().map(IpNet::from)
    }
}

/// WARP `reserved`: `1,22,33`, `[1, 22, 33]` or base64 of exactly three bytes (`AQID`).
pub fn reserved(raw: &str) -> Option<[u8; 3]> {
    let raw = raw.trim();
    let inner = raw
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(raw);
    let bytes: Vec<u8> = if inner.contains(',') {
        inner
            .split(',')
            .map(|n| {
                let n = n.trim();
                (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    .then(|| n.parse::<u8>().ok())
                    .flatten()
            })
            .collect::<Option<_>>()?
    } else {
        // Exporters disagree on padding; three bytes need none.
        base64_bytes(inner.trim_end_matches('='))?
    };
    bytes.try_into().ok()
}

/// AmneziaWG parameter names, lower case: `Jc`, `Jmin`, `Jmax`, `Itime`, `S1`-`S4`, `H1`-`H4`,
/// `I1`-`I5`, `J1`-`J3`.
pub fn is_amnezia_key(lower: &str) -> bool {
    matches!(lower, "jc" | "jmin" | "jmax" | "itime")
        || lower.len() == 2
            && matches!(
                lower.as_bytes(),
                [b's', b'1'..=b'4']
                    | [b'h', b'1'..=b'4']
                    | [b'i', b'1'..=b'5']
                    | [b'j', b'1'..=b'3']
            )
}

/// What AmneziaWG keys mean for a plain WireGuard dial (AmneziaWG itself is the planned WP-12
/// feature). `S1`-`S4` and `H1`-`H4` change the handshake the server accepts (defaults: `0` and
/// `1`..`4`); junk packets (`Jc`, `I1`-`I5`, `J1`-`J3`) are client-side only, so the server still
/// answers without them.
pub fn amnezia_note<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Option<Note> {
    let (mut incompatible, mut junk) = (false, false);
    for (key, value) in pairs {
        let (key, value) = (key.to_ascii_lowercase(), value.trim());
        let set = !value.is_empty() && value != "0";
        match key.as_bytes() {
            [b's', b'1'..=b'4'] => incompatible |= set,
            [b'h', n @ b'1'..=b'4'] => {
                incompatible |= !value.is_empty() && value.as_bytes() != [*n]
            }
            b"jc" | [b'i', b'1'..=b'5'] | [b'j', b'1'..=b'3'] => junk |= set,
            _ => {}
        }
    }
    if incompatible {
        Some(Note::Other(NOTE_AMNEZIA_INCOMPATIBLE.to_owned()))
    } else {
        junk.then(|| Note::Other(NOTE_AMNEZIA_JUNK.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_get_a_host_prefix() {
        assert_eq!(interface_address("10.0.0.2"), "10.0.0.2/32".parse().ok());
        assert_eq!(interface_address(" fd00::2 "), "fd00::2/128".parse().ok());
        assert_eq!(interface_address("10.0.0.2/24"), "10.0.0.2/24".parse().ok());
        assert_eq!(interface_address("10.0.0.300"), None);
        assert_eq!(interface_address("host.example"), None);
    }

    #[test]
    fn reserved_forms() {
        assert_eq!(reserved("1,22,33"), Some([1, 22, 33]));
        assert_eq!(reserved("[1, 22, 33]"), Some([1, 22, 33]));
        assert_eq!(reserved("AQID"), Some([1, 2, 3]));
        assert_eq!(reserved("AQID=="), Some([1, 2, 3]));
        assert_eq!(reserved("[209, 98, 59]"), Some([209, 98, 59]));
        assert_eq!(reserved("U4An"), Some([0x53, 0x80, 0x27]));
        assert_eq!(reserved("AAAAAA=="), None, "four bytes");
        for bad in ["1,2", "1,2,3,4", "1,2,256", "+1,2,3", "AQIDBA", "", "x"] {
            assert_eq!(reserved(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn amnezia_keys_are_classified() {
        let note = |pairs: &[(&str, &str)]| amnezia_note(pairs.iter().copied());
        let other = |key: &str| Some(Note::Other(key.to_owned()));
        assert_eq!(note(&[("Jc", "4"), ("H1", "1")]), other(NOTE_AMNEZIA_JUNK));
        assert_eq!(
            note(&[("S1", "15"), ("Jc", "4")]),
            other(NOTE_AMNEZIA_INCOMPATIBLE)
        );
        assert_eq!(note(&[("H2", "7")]), other(NOTE_AMNEZIA_INCOMPATIBLE));
        assert_eq!(note(&[("S1", "0"), ("H3", "3"), ("Jmin", "40")]), None);
        assert!(is_amnezia_key("jmax") && is_amnezia_key("i5") && !is_amnezia_key("i6"));
    }
}
