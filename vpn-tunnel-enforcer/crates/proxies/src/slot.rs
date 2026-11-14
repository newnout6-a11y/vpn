//! Slot numbers and their loopback ports: slot N listens on `127.0.0.1:(17990 + N - 1)`.
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::model::ProxyError;

/// Host of every slot listener and of the control API.
pub const CONTROL_HOST: &str = "127.0.0.1";
/// Preferred port of the control API.
pub const CONTROL_PORT: u16 = 17873;
/// Port of slot 1.
pub const BASE_PROXY_PORT: u16 = 17990;
/// Highest slot. Every default slot maps to a distinct valid TCP port: a transport boundary,
/// not a product limit (slot 100 is port 18089).
pub const MAX_SLOT: u16 = u16::MAX - BASE_PROXY_PORT + 1;

/// A proxy slot number, always in `1..=MAX_SLOT`. Serialized as a plain number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u64")]
pub struct Slot(u16);

impl Slot {
    /// Slot 1: what the API means when a request names no slot.
    pub const DEFAULT: Slot = Slot(1);

    /// Validates a slot number.
    pub fn new(n: u64) -> Result<Self, ProxyError> {
        match u16::try_from(n) {
            Ok(n) if (1..=MAX_SLOT).contains(&n) => Ok(Slot(n)),
            _ => Err(slot_out_of_range()),
        }
    }

    /// Parses a slot from query or JSON text the way the old API did (`Number(raw)`): surrounding
    /// blanks are ignored and `2.0` or `1e1` are integers. The caller maps an absent value to
    /// [`Slot::DEFAULT`].
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        integer(raw)
            .ok_or_else(slot_out_of_range)
            .and_then(Slot::new)
    }

    /// The slot number.
    pub fn get(self) -> u16 {
        self.0
    }

    /// Port the slot listens on unless the caller chose another one.
    pub fn default_port(self) -> u16 {
        // Cannot overflow: MAX_SLOT maps exactly to u16::MAX.
        BASE_PROXY_PORT + (self.0 - 1)
    }

    /// Every slot in ascending order (the allocation order of "first available slot").
    pub fn all() -> impl Iterator<Item = Slot> {
        (1..=MAX_SLOT).map(Slot)
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Slot> for u16 {
    fn from(slot: Slot) -> u16 {
        slot.0
    }
}

impl TryFrom<u64> for Slot {
    type Error = ProxyError;
    fn try_from(n: u64) -> Result<Self, ProxyError> {
        Slot::new(n)
    }
}

/// Parses a caller-chosen listen port: an integer in `1..=65535`. The old API silently fell
/// back to the slot's default port on bad input (B-12); this is a 400 now.
pub fn parse_port(raw: &str) -> Result<u16, ProxyError> {
    integer(raw)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|&port| port != 0)
        .ok_or_else(|| ProxyError::BadRequest("invalid port".into()))
}

/// `http://127.0.0.1:<port>`: the wire URL of a slot listener (its `mixed` inbound also speaks
/// SOCKS5 on the same port, so `socks5://` works as well) and of the control API.
pub fn loopback_url(port: u16) -> String {
    format!("http://{CONTROL_HOST}:{port}")
}

fn slot_out_of_range() -> ProxyError {
    ProxyError::BadRequest(format!(
        "external proxy slot must be between 1 and {MAX_SLOT}"
    ))
}

/// A non-negative integer written as decimal text, accepting what JavaScript's `Number()`
/// accepted from the old clients (`" 7 "`, `"7.0"`, `"7e0"`).
fn integer(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if let Ok(n) = raw.parse::<u64>() {
        return Some(n);
    }
    let f: f64 = raw.parse().ok()?;
    // u64::MAX as f64 rounds up, so `<` keeps the cast exact.
    (f.is_finite() && f >= 0.0 && f.fract() == 0.0 && f < u64::MAX as f64).then_some(f as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-02-007 (address parsing bounds); spec external-proxy §7.5: slot ports are distinct and
    /// the slot range is 1..=47546.
    #[test]
    fn slots_map_to_distinct_ports() {
        let port = |n| Slot::new(n).unwrap().default_port();
        assert_eq!(port(1), 17990);
        assert_eq!(port(10), 17999);
        assert_eq!(port(100), 18089);
        assert_eq!(port(u64::from(MAX_SLOT)), u16::MAX);
        let ports: std::collections::HashSet<u16> = (1..=100).map(port).collect();
        assert_eq!(ports.len(), 100);
        assert_eq!(MAX_SLOT, 47546);
        for bad in [0, 47547, u64::from(u16::MAX) + 2] {
            let err = Slot::new(bad).unwrap_err();
            assert_eq!(err.http_status(), 400);
            assert_eq!(
                err.detail(),
                "external proxy slot must be between 1 and 47546"
            );
        }
    }

    /// AT-02-007: slot and port text is read like the old `Number()` parse, never coerced.
    #[test]
    fn parses_slot_and_port_text() {
        assert_eq!(Slot::parse(" 2 ").unwrap().get(), 2);
        assert_eq!(Slot::parse("3.0").unwrap().get(), 3);
        assert_eq!(Slot::parse("1e1").unwrap().get(), 10);
        for bad in [
            "", " ", "0", "-1", "1.5", "abc", "NaN", "inf", "47547", "0x10",
        ] {
            assert!(Slot::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(parse_port("18000").unwrap(), 18000);
        assert_eq!(parse_port(" 65535 ").unwrap(), 65535);
        for bad in ["", "0", "65536", "abc", "-5", "80.5"] {
            assert_eq!(
                parse_port(bad).unwrap_err().detail(),
                "invalid port",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn slot_is_a_plain_number_on_the_wire() {
        let slot = Slot::new(7).unwrap();
        assert_eq!(serde_json::to_string(&slot).unwrap(), "7");
        assert_eq!(serde_json::from_str::<Slot>("7").unwrap(), slot);
        assert!(serde_json::from_str::<Slot>("0").is_err());
        assert_eq!(loopback_url(17990), "http://127.0.0.1:17990");
        assert_eq!(Slot::all().next(), Some(Slot::DEFAULT));
        assert_eq!(Slot::all().count(), usize::from(MAX_SLOT));
    }
}
