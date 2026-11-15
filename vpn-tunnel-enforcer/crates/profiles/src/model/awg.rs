//! AmneziaWG parameters of a [`super::Kind::Amneziawg`] profile, kept as the provider wrote them
//! (names of the AmneziaWG `.conf`); `crate::awg` reads, checks and writes them.
use std::fmt;

use serde::{Deserialize, Serialize};

/// The AmneziaWG generation the parameters imply ([`crate::awg::implied_generation`]).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum AwgGeneration {
    /// Junk packets (`Jc`, `Jmin`, `Jmax`), `S1` / `S2`, single `H1`-`H4`.
    #[default]
    #[serde(rename = "1.0")]
    V1_0,
    /// Signature packets `I1`-`I5`; `J1`-`J3` and `Itime` (dropped again in 2.0).
    #[serde(rename = "1.5")]
    V1_5,
    /// `S3` / `S4` and `H1`-`H4` ranges.
    #[serde(rename = "2.0")]
    V2_0,
    /// 3.0 / 3.1: header protection, content padding, timer ranges, random trailers, cookies.
    #[serde(rename = "3")]
    V3,
}

impl AwgGeneration {
    /// The version as AmneziaVPN names it.
    pub fn label(self) -> &'static str {
        match self {
            AwgGeneration::V1_0 => "1.0",
            AwgGeneration::V1_5 => "1.5",
            AwgGeneration::V2_0 => "2.0",
            AwgGeneration::V3 => "3.x",
        }
    }
}

/// A value AmneziaWG picks at random from `min..=max`; a single value has `min == max`.
/// Written `a` or `a-b`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct AwgRange {
    pub min: u32,
    pub max: u32,
}

impl AwgRange {
    /// One fixed value.
    pub fn single(value: u32) -> Self {
        Self {
            min: value,
            max: value,
        }
    }

    /// `a` or `a-b` with `a <= b` (spaces around the parts allowed); `None` otherwise.
    pub fn parse(raw: &str) -> Option<Self> {
        let number = |s: &str| {
            let s = s.trim();
            (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .then(|| s.parse::<u32>().ok())
                .flatten()
        };
        let range = match raw.split_once('-') {
            Some((min, max)) => Self {
                min: number(min)?,
                max: number(max)?,
            },
            None => Self::single(number(raw)?),
        };
        (range.min <= range.max).then_some(range)
    }

    /// More than one value.
    pub fn is_range(self) -> bool {
        self.min < self.max
    }

    /// Both ranges contain a common value.
    pub fn overlaps(self, other: AwgRange) -> bool {
        self.min <= other.max && other.min <= self.max
    }
}

impl fmt::Display for AwgRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.is_range() {
            true => write!(f, "{}-{}", self.min, self.max),
            false => write!(f, "{}", self.min),
        }
    }
}

impl From<AwgRange> for String {
    fn from(range: AwgRange) -> Self {
        range.to_string()
    }
}

impl TryFrom<String> for AwgRange {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        AwgRange::parse(&raw).ok_or_else(|| format!("not an AmneziaWG range: {raw:?}"))
    }
}

/// AmneziaWG obfuscation on top of WireGuard. Absent values are off (WireGuard behaviour);
/// `h` absent = the standard message type `n` of `Hn`. Sizes and counts are kept as written
/// (`u32`) so that an out-of-range value is reported by [`crate::awg::validate`] instead of
/// failing to load.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Awg {
    /// Set by the importer from the parameters (and mihomo's `version`), checked by `validate`.
    pub generation: AwgGeneration,
    /// `Jc`: junk packets before every handshake.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jc: Option<u32>,
    /// `Jmin` / `Jmax`: junk packet sizes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmin: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jmax: Option<u32>,
    /// `S1`-`S4`: random prefix of init, response, cookie and transport messages.
    #[serde(skip_serializing_if = "all_none")]
    pub s: [Option<u32>; 4],
    /// `H1`-`H4`: message type values (ranges from 2.0).
    #[serde(skip_serializing_if = "all_none")]
    pub h: [Option<AwgRange>; 4],
    /// `I1`-`I5`: signature packet tag chains (`<b 0x…><r 10>`).
    #[serde(skip_serializing_if = "all_none")]
    pub i: [Option<String>; 5],
    /// `J1`-`J3`: 1.5 only.
    #[serde(skip_serializing_if = "all_none")]
    pub j: [Option<String>; 3],
    /// `Itime` in seconds: 1.5 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub itime: Option<u32>,
    /// `HeaderProtectionKey`: base64 of 32 bytes (3.x).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_protection_key: Option<String>,
    /// `ContentPaddingAddition` (3.x).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_padding: Option<AwgRange>,
    /// `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout` in seconds and
    /// `MaxHandshakeAttempts` (3.x), in that order.
    #[serde(skip_serializing_if = "all_none")]
    pub timers: [Option<AwgRange>; 5],
    /// `PersistentKeepalive` written as a range `a-b` (3.x); a single value stays in the peer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_range: Option<AwgRange>,
    /// `RandomTrailers` (3.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_trailers: Option<bool>,
    /// `DisableCookies` (3.1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_cookies: Option<bool>,
}

fn all_none<T, const N: usize>(values: &[Option<T>; N]) -> bool {
    values.iter().all(Option::is_none)
}

impl fmt::Debug for Awg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The header protection key is shared with the server: whoever has it can strip the
        // protection, so it is hidden like a WireGuard key.
        let key = self.header_protection_key.as_ref().map(|_| "<hidden>");
        f.debug_struct("Awg")
            .field("generation", &self.generation)
            .field("jc", &self.jc)
            .field("jmin", &self.jmin)
            .field("jmax", &self.jmax)
            .field("s", &self.s)
            .field("h", &self.h)
            .field("i", &self.i)
            .field("j", &self.j)
            .field("itime", &self.itime)
            .field("header_protection_key", &key)
            .field("content_padding", &self.content_padding)
            .field("timers", &self.timers)
            .field("keepalive_range", &self.keepalive_range)
            .field("random_trailers", &self.random_trailers)
            .field("disable_cookies", &self.disable_cookies)
            .finish()
    }
}
