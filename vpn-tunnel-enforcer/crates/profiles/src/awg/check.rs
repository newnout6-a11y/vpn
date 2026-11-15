//! The checks of an AmneziaWG parameter set and the generation it implies. Run at import and
//! again before any start, so a profile stored by an older build or edited later is refused
//! with every bad field named instead of failing inside the engine.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use super::field::{AwgField, AwgInvalid};
use super::tags::{Dialect, chain_ok};
use crate::model::{Awg, AwgGeneration, AwgRange};

use AwgGeneration::{V1_0, V1_5, V2_0, V3};

/// WireGuard message sizes the `S1`-`S4` prefixes extend: init, response, cookie, transport.
const MESSAGE_SIZES: [u32; 4] = [148, 92, 64, 32];
/// wireguard-go `MaxSegmentSize`: a padded message or a junk packet must stay below it.
const MAX_SEGMENT: u32 = 65535;
/// The kernel module's limit for junk packets before each handshake.
const MAX_JC: u32 = 128;
/// Header protection takes its 12-byte nonce from the `S` prefix of every message.
const NONCE: u32 = 12;
/// WireGuard's own timers, used when a 3.x config overrides only one of the pair (seconds).
const REKEY_AFTER_TIME: u32 = 120;
const REJECT_AFTER_TIME: u32 = 180;

/// The lowest generation that has every parameter `awg` sets.
pub fn implied_generation(awg: &Awg) -> AwgGeneration {
    if has_v3(awg) {
        V3
    } else if awg.j.iter().any(Option::is_some) || awg.itime.is_some() {
        V1_5
    } else if awg.h.iter().flatten().any(|h| h.is_range()) || awg.s[2..].iter().any(Option::is_some)
    {
        V2_0
    } else if awg.i.iter().any(Option::is_some) {
        V1_5
    } else {
        V1_0
    }
}

/// Keys only 3.x has. Their presence counts, even `off`: only 3.x configs write them.
fn has_v3(awg: &Awg) -> bool {
    awg.header_protection_key.is_some()
        || awg.content_padding.is_some()
        || awg.timers.iter().any(Option::is_some)
        || awg.keepalive_range.is_some()
        || awg.random_trailers.is_some()
        || awg.disable_cookies.is_some()
}

/// Every bound and consistency rule of `awg` for its stored generation; `Err` names every
/// field that breaks one.
pub fn validate(awg: &Awg) -> Result<(), AwgInvalid> {
    let mut bad = Vec::new();
    junk(awg, &mut bad);
    paddings(awg, &mut bad);
    headers(awg, &mut bad);
    chains(awg, &mut bad);
    v3(awg, &mut bad);
    AwgInvalid::of(bad).map_or(Ok(()), Err)
}

fn junk(awg: &Awg, bad: &mut Vec<AwgField>) {
    if awg.jc.is_some_and(|jc| jc > MAX_JC) {
        bad.push(AwgField::Jc);
    }
    // An absent size is 0 to AmneziaWG, so `Jmin` alone is larger than its `Jmax`.
    let (min, max) = (awg.jmin.unwrap_or(0), awg.jmax.unwrap_or(0));
    if min > max {
        bad.extend([AwgField::Jmin, AwgField::Jmax]);
    }
    if max >= MAX_SEGMENT {
        bad.push(AwgField::Jmax);
    }
}

fn paddings(awg: &Awg, bad: &mut Vec<AwgField>) {
    let padded: Vec<u64> = MESSAGE_SIZES
        .iter()
        .zip(awg.s)
        .map(|(&size, s)| u64::from(size) + u64::from(s.unwrap_or(0)))
        .collect();
    let too_long = padded.iter().map(|&size| size >= u64::from(MAX_SEGMENT));
    bad.extend(
        AwgField::S
            .into_iter()
            .zip(too_long)
            .filter(|(_, long)| *long)
            .map(|(f, _)| f),
    );
    // mihomo marks S3 / S4 as 1.5 and later.
    if awg.generation == V1_0 {
        bad.extend(
            (2..4)
                .filter(|&n| awg.s[n].is_some())
                .map(|n| AwgField::S[n]),
        );
    }
    // Before 3.x the receiver tells the four messages apart by their padded size.
    if awg.generation < V3 {
        for a in 0..4 {
            for b in a + 1..4 {
                if padded[a] == padded[b] {
                    bad.extend([AwgField::S[a], AwgField::S[b]]);
                }
            }
        }
    }
}

fn headers(awg: &Awg, bad: &mut Vec<AwgField>) {
    // The legacy code takes a value whose start is up to 4 as the standard type (`Min > 4`
    // is custom), v3 only `0` / absent.
    let standard = |n: usize, h: Option<AwgRange>| match h {
        Some(h) if awg.generation < V3 && h.min <= 4 => AwgRange::single(n as u32 + 1),
        Some(AwgRange { min: 0, max: 0 }) | None => AwgRange::single(n as u32 + 1),
        Some(h) => h,
    };
    let effective: Vec<AwgRange> = (0..4).map(|n| standard(n, awg.h[n])).collect();
    for n in 0..4 {
        if awg.generation < V2_0 && awg.h[n].is_some_and(AwgRange::is_range) {
            bad.push(AwgField::H[n]);
        }
        for m in n + 1..4 {
            if effective[n].overlaps(effective[m]) {
                bad.extend([AwgField::H[n], AwgField::H[m]]);
            }
        }
    }
}

fn chains(awg: &Awg, bad: &mut Vec<AwgField>) {
    let dialect = match awg.generation {
        V3 => Dialect::V3,
        _ => Dialect::Legacy,
    };
    for (n, chain) in awg.i.iter().enumerate() {
        if let Some(chain) = chain
            && (awg.generation == V1_0 || !chain_ok(chain, dialect))
        {
            bad.push(AwgField::I[n]);
        }
    }
    for (n, chain) in awg.j.iter().enumerate() {
        if let Some(chain) = chain
            && (awg.generation != V1_5 || !chain_ok(chain, Dialect::Legacy))
        {
            bad.push(AwgField::J[n]);
        }
    }
    if awg.itime.is_some() && awg.generation != V1_5 {
        bad.push(AwgField::Itime);
    }
}

fn v3(awg: &Awg, bad: &mut Vec<AwgField>) {
    let set = [
        (
            AwgField::HeaderProtectionKey,
            awg.header_protection_key.is_some(),
        ),
        (
            AwgField::ContentPaddingAddition,
            awg.content_padding.is_some(),
        ),
        (AwgField::PersistentKeepalive, awg.keepalive_range.is_some()),
        (AwgField::RandomTrailers, awg.random_trailers.is_some()),
        (AwgField::DisableCookies, awg.disable_cookies.is_some()),
    ]
    .into_iter()
    .chain(
        AwgField::TIMERS
            .into_iter()
            .zip(awg.timers.map(|t| t.is_some())),
    );
    if awg.generation < V3 {
        bad.extend(set.filter(|(_, set)| *set).map(|(field, _)| field));
        return;
    }
    if let Some(key) = &awg.header_protection_key {
        if !protection_key(key) {
            bad.push(AwgField::HeaderProtectionKey);
        }
        bad.extend(
            (0..4)
                .filter(|&n| awg.s[n].unwrap_or(0) < NONCE)
                .map(|n| AwgField::S[n]),
        );
    }
    if awg
        .content_padding
        .is_some_and(|p| p.max > u32::from(u16::MAX))
    {
        bad.push(AwgField::ContentPaddingAddition);
    }
    // Keys rejected before the rekey is due would drop the session every few minutes.
    let [rekey_after, _, reject_after, ..] = awg.timers.map(|t| t.filter(|t| t.max > 0));
    if rekey_after.is_some() || reject_after.is_some() {
        let rekey = rekey_after.map_or(REKEY_AFTER_TIME, |t| t.max);
        let reject = reject_after.map_or(REJECT_AFTER_TIME, |t| t.min);
        if rekey >= reject {
            bad.extend(rekey_after.map(|_| AwgField::RekeyAfterTime));
            bad.extend(reject_after.map(|_| AwgField::RejectAfterTime));
        }
    }
}

/// Base64 (padded or not) of exactly 32 bytes, like a WireGuard key (`awg genkey` makes one).
pub(super) fn protection_key(raw: &str) -> bool {
    let raw = raw.trim();
    STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
        .is_ok_and(|bytes| bytes.len() == 32)
}
