//! TLS tricks against DPI that reads the ClientHello (ru-2026 §6): cut it into several TLS
//! records, into several TCP segments, or both. FOCI 2025 measured the TSPU reassembling either
//! trick alone; only both together got through, hence the strong preset.
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Host, Kind, Profile, Transport};

/// An inclusive range of a trick parameter, written `min-max` (`100-200`) or as one number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Span {
    pub min: u16,
    pub max: u16,
}

impl Span {
    pub const fn new(min: u16, max: u16) -> Self {
        Self { min, max }
    }

    /// `"100-200"` or `"150"`; `None` when malformed or reversed.
    pub fn parse(raw: &str) -> Option<Span> {
        let raw = raw.trim();
        let (min, max) = raw.split_once('-').unwrap_or((raw, raw));
        let (min, max) = (min.trim().parse().ok()?, max.trim().parse().ok()?);
        (min <= max).then_some(Span { min, max })
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.min == self.max {
            write!(f, "{}", self.min)
        } else {
            write!(f, "{}-{}", self.min, self.max)
        }
    }
}

impl From<Span> for String {
    fn from(span: Span) -> String {
        span.to_string()
    }
}

impl TryFrom<String> for Span {
    type Error = String;
    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Span::parse(&raw).ok_or_else(|| format!("invalid range {raw:?}"))
    }
}

/// How the ClientHello is cut: piece length in bytes and the pause between pieces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloSplit {
    pub len: Span,
    pub interval_ms: Span,
}

impl HelloSplit {
    /// Hiddify's field values (2026-10): 100-200 B pieces, 10-20 ms apart.
    pub const PRESET: HelloSplit = HelloSplit {
        len: Span::new(100, 200),
        interval_ms: Span::new(10, 20),
    };
}

/// The TLS tricks of one server. `Tls::tricks = None` follows the app's default
/// ([`TlsTricks::effective`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum TlsTricks {
    Off,
    /// The ClientHello split into several TLS records, sent at once.
    Record,
    /// The ClientHello split into several TCP segments with a pause between them.
    Hello(HelloSplit),
    /// Both: the records are sent as separate segments with a pause between them.
    Both(HelloSplit),
}

impl TlsTricks {
    /// «Сильно»: both tricks with the preset split.
    pub const STRONG: TlsTricks = TlsTricks::Both(HelloSplit::PRESET);

    /// What a server runs with: its own value, else the strong preset when stealth or adaptive
    /// TLS compatibility is on, else nothing.
    pub fn effective(own: Option<TlsTricks>, tls_compat: bool) -> TlsTricks {
        match own {
            Some(own) => own,
            None if tls_compat => TlsTricks::STRONG,
            None => TlsTricks::Off,
        }
    }

    /// True when the ClientHello is cut into TLS records.
    pub fn record(self) -> bool {
        matches!(self, TlsTricks::Record | TlsTricks::Both(_))
    }

    /// The TCP-level split, when there is one.
    pub fn hello(self) -> Option<HelloSplit> {
        match self {
            TlsTricks::Hello(split) | TlsTricks::Both(split) => Some(split),
            TlsTricks::Off | TlsTricks::Record => None,
        }
    }
}

/// Readers of the providers' fragment vocabularies.
impl TlsTricks {
    /// sing-box 1.14 TLS keys of the tricks, as dotted `Profile::singbox_extra` paths.
    pub const SINGBOX_KEYS: [&str; 3] = [
        "tls.fragment",
        "tls.record_fragment",
        "tls.fragment_fallback_delay",
    ];

    /// Xray's fragment triple as share links (`fragment=tlshello,100-200,10-20`) and Happ /
    /// Hiddify provider keys (`fragmentation-packets` / `-length` / `-interval`) write it.
    /// `tlshello` cuts the hello into records, each sent after `interval` (0 or none: all in one
    /// write, records only); numeric packets cut the first writes into raw segments. `None` when
    /// it does not touch the ClientHello (packets not from 1) or a value is malformed.
    pub fn from_fragment(
        packets: &str,
        length: Option<&str>,
        interval: Option<&str>,
    ) -> Option<TlsTricks> {
        let span = |raw: Option<&str>, preset: Span| match raw.map(str::trim) {
            None | Some("") => Some(preset),
            Some(raw) => Span::parse(raw),
        };
        let len = span(length, HelloSplit::PRESET.len).filter(|len| len.min > 0)?;
        let interval_ms = span(interval, Span::new(0, 0))?;
        let split = HelloSplit { len, interval_ms };
        let packets = packets.trim().to_ascii_lowercase();
        if packets == "tlshello" {
            // A record split with the provider's own record size keeps that size (Xray's
            // `length`); a zero pause writes the records at once, as the provider asked.
            let own_len =
                length.is_some_and(|l| !l.trim().is_empty()) && len != HelloSplit::PRESET.len;
            return Some(if interval_ms.max == 0 && !own_len {
                TlsTricks::Record
            } else {
                TlsTricks::Both(split)
            });
        }
        let first = Span::parse(&packets)?;
        (first.min == 1).then_some(TlsTricks::Hello(split))
    }

    /// The `tls.fragment` / `tls.record_fragment` keys a pasted sing-box outbound left in
    /// `Profile::singbox_extra`, as flags with the preset split; `None` when neither is on.
    /// sing-box's `fragment_fallback_delay` is one wait at one cut inside the SNI, not a pause
    /// after every piece: carried over to Xray it cost seconds per connection, so it is not read.
    pub fn from_singbox(extra: &Map<String, Value>) -> Option<TlsTricks> {
        let on = |key: &str| extra.get(key).and_then(Value::as_bool) == Some(true);
        let hello = on(Self::SINGBOX_KEYS[0]).then_some(HelloSplit::PRESET);
        Some(TlsTricks::of(on(Self::SINGBOX_KEYS[1]), hello)).filter(|t| *t != TlsTricks::Off)
    }

    /// Both tricks of `self` and `other`; the split of `self` when both have one.
    pub fn with(self, other: TlsTricks) -> TlsTricks {
        TlsTricks::of(
            self.record() || other.record(),
            self.hello().or(other.hello()),
        )
    }

    fn of(record: bool, hello: Option<HelloSplit>) -> TlsTricks {
        match (record, hello) {
            (false, None) => TlsTricks::Off,
            (true, None) => TlsTricks::Record,
            (false, Some(split)) => TlsTricks::Hello(split),
            (true, Some(split)) => TlsTricks::Both(split),
        }
    }
}

impl Profile {
    /// The key's own tricks: the typed value (share link, the user's choice), else what pasted
    /// sing-box options carried. `None` = the app default applies.
    pub fn own_tls_tricks(&self) -> Option<TlsTricks> {
        let typed = self.tls.as_ref().and_then(|tls| tls.tricks);
        typed.or_else(|| TlsTricks::from_singbox(&self.singbox_extra))
    }

    /// What the key runs with when the app default is on (`tls_compat`: stealth or adaptive TLS
    /// compatibility -> «Сильно»). A typed value is taken as is; pasted sing-box keys only add
    /// to the default (they were merged into it before item 18). Nothing where the key cannot
    /// take tricks on both engines ([`Profile::takes_tls_tricks`]).
    pub fn tls_tricks_for(&self, tls_compat: bool) -> TlsTricks {
        let Some(tls) = self.tls.as_ref().filter(|_| self.takes_tls_tricks()) else {
            return TlsTricks::Off;
        };
        let default = TlsTricks::effective(None, tls_compat);
        match tls.tricks {
            Some(typed) => typed,
            None => TlsTricks::from_singbox(&self.singbox_extra)
                .map_or(default, |pasted| pasted.with(default)),
        }
    }

    /// True when both engines can cut this key's ClientHello: TLS over TCP with a server name in
    /// the hello (sing-box cuts inside it). Never REALITY (its hello names a whitelisted
    /// camouflage site, and sing-box never cut it), QUIC (hysteria2, TUIC, the QUIC transport,
    /// XHTTP over HTTP/3), naive, the ShadowTLS dialer or a provider's Xray graph.
    pub fn takes_tls_tricks(&self) -> bool {
        let Some(tls) = self.tls.as_ref() else {
            return false;
        };
        let tcp_kind = matches!(
            self.kind,
            Kind::Vless { .. }
                | Kind::Vmess { .. }
                | Kind::Trojan { .. }
                | Kind::Anytls { .. }
                | Kind::Http { .. }
        );
        let h3 = matches!(tls.alpn.as_slice(), [only] if only.eq_ignore_ascii_case("h3"));
        let quic = match &self.transport {
            Some(Transport::Quic) => true,
            Some(Transport::Xhttp { .. }) => h3,
            _ => false,
        };
        let named = !tls.disable_sni
            && (tls
                .server_name
                .as_deref()
                .is_some_and(|n| !n.trim().is_empty())
                || matches!(self.server, Host::Domain(_)));
        tcp_kind && !quic && named && tls.reality.is_none() && self.native_xray.is_none()
    }
}
