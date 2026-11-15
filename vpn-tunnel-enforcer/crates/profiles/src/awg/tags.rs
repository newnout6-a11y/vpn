//! Syntax of the signature packet chains `I1`-`I5` and `J1`-`J3`: `<tag arg>` items separated
//! by nothing but spaces. Both implementations ignore text between tags; it is refused here
//! because it only appears when a tag lost a bracket in copying, and then the packet differs
//! from the provider's.

/// Which implementation reads the chain: the legacy 1.x / 2.0 code or amneziawg-go v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Dialect {
    Legacy,
    V3,
}

/// The chain parses as `dialect` parses it (tag names, arguments, their limits).
pub(super) fn chain_ok(chain: &str, dialect: Dialect) -> bool {
    let legacy = dialect == Dialect::Legacy;
    // The legacy code allows one counter and one timestamp per packet.
    let (mut counter, mut time) = (false, false);
    let mut rest = chain.trim();
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let Some((tag, tail)) = rest.strip_prefix('<').and_then(|r| r.split_once('>')) else {
            return false;
        };
        if tag.contains('<') {
            return false;
        }
        let mut parts = tag.split_whitespace();
        let (Some(name), arg, None) = (parts.next(), parts.next(), parts.next()) else {
            return false;
        };
        // Random runs: the legacy code refuses more than 1000 bytes, v3 has no limit of its
        // own but a packet cannot exceed a UDP datagram.
        let random_max = if legacy { 1000 } else { u32::from(u16::MAX) };
        let ok = match (name, arg) {
            ("b", Some(hex)) => hex_ok(hex, dialect),
            ("t", None) => !(legacy && std::mem::replace(&mut time, true)),
            ("r" | "rc" | "rd", Some(n)) => number(n).is_some_and(|n| n <= random_max),
            ("c", None) if legacy => !std::mem::replace(&mut counter, true),
            ("wt", Some(ms)) if legacy => number(ms).is_some_and(|ms| ms <= 5000),
            ("d" | "ds", None) if !legacy => true,
            ("dz", Some(n)) if !legacy => number(n).is_some(),
            _ => false,
        };
        if !ok {
            return false;
        }
        rest = tail.trim_start();
    }
    true
}

/// Static bytes: the legacy code needs `0x` / `0X` and pads an odd length; v3 takes an
/// optional `0x` and an even, non-empty run.
fn hex_ok(raw: &str, dialect: Dialect) -> bool {
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    match dialect {
        Dialect::Legacy => raw
            .strip_prefix("0x")
            .or_else(|| raw.strip_prefix("0X"))
            .is_some_and(hex),
        Dialect::V3 => {
            let digits = raw.strip_prefix("0x").unwrap_or(raw);
            !digits.is_empty() && digits.len().is_multiple_of(2) && hex(digits)
        }
    }
}

/// A plain decimal `u32` (no sign, no spaces).
pub(super) fn number(raw: &str) -> Option<u32> {
    raw.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| raw.parse().ok())
        .flatten()
}
