//! The typed VPN profile: the only form in which a server key is parsed, stored and passed
//! around. Engine JSON (sing-box, Xray) is generated from it and never stored.
//!
//! Written by the lead as the cross-package contract. Extend additively (new optional fields,
//! new enum variants, helper methods); do not rename or remove what is here.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// AmneziaWG parameters of [`Kind::Amneziawg`].
mod awg;
/// Redacting `Debug` for the types that hold credentials.
mod debug;
#[cfg(test)]
mod tests;

pub use awg::{Awg, AwgGeneration, AwgRange};

/// One server key, as the provider described it. Defaults (uTLS, ALPN, mux policy) are applied
/// when engine config is emitted, never here, so re-export stays faithful to the source.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Display name: trimmed, control characters replaced by spaces, at most 256 chars.
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub server: Host,
    pub port: u16,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<Tls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Mux>,
    #[serde(default, skip_serializing_if = "DialPrefs::is_default")]
    pub dial: DialPrefs,
    /// Provider-supplied Xray graph (balancers, chained outbounds); such a profile runs on Xray only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_xray: Option<NativeXray>,
    /// Allow-listed sing-box 1.14 option keys taken verbatim from pasted sing-box JSON
    /// (e.g. `tls.fragment`, `multiplex.min_streams`), re-emitted as they came.
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub singbox_extra: Map<String, Value>,
    pub source: Source,
    /// Things the user should know before connecting (a dropped option, an unenforced pin).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<Note>,
}

/// Server address. IPv6 is never bracketed here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(ip) => ip.fmt(f),
            Host::Domain(name) => f.write_str(name),
        }
    }
}

/// Protocol and its credentials.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum Kind {
    Vless {
        uuid: String,
        flow: Option<String>,
        packet_encoding: Option<String>,
        encryption: Option<String>,
    },
    /// `alter_id` is always 0 (AEAD); a non-zero provider value becomes [`Note::AlterIdNormalized`].
    Vmess {
        uuid: String,
        security: String,
        global_padding: bool,
        authenticated_length: bool,
    },
    Trojan {
        password: String,
    },
    Shadowsocks {
        method: String,
        password: String,
        plugin: Option<SsPlugin>,
        shadowtls: Option<ShadowTlsLayer>,
        uot: Option<u8>,
    },
    Hysteria2 {
        password: String,
        obfs: Option<Hy2Obfs>,
        /// Extra port ranges for port hopping, inclusive.
        ports: Vec<(u16, u16)>,
        hop_interval_s: Option<u32>,
        hop_interval_max_s: Option<u32>,
        up_mbps: Option<u32>,
        down_mbps: Option<u32>,
        bbr_profile: Option<String>,
    },
    Tuic {
        uuid: String,
        password: String,
        congestion: Option<String>,
        udp_relay_mode: Option<String>,
        zero_rtt: bool,
        heartbeat_s: Option<u32>,
    },
    Naive {
        username: String,
        password: String,
        quic: bool,
        extra_headers: Vec<(String, String)>,
        insecure_concurrency: Option<u32>,
    },
    Anytls {
        password: String,
        idle_check_s: Option<u32>,
        idle_timeout_s: Option<u32>,
        min_idle: Option<u32>,
    },
    Wireguard(WireGuard),
    /// AmneziaWG: WireGuard whose packets the server expects obfuscated by `awg`. No bundled
    /// engine dials it (mihomo can: a lab function, WP-12), so it never runs as plain WireGuard.
    Amneziawg {
        wg: WireGuard,
        awg: Box<Awg>,
    },
    Socks {
        username: Option<String>,
        password: Option<String>,
    },
    Http {
        username: Option<String>,
        password: Option<String>,
    },
}

impl Kind {
    /// Lower-case protocol label as shown in the UI and used in exports (`vless`, `hysteria2`, …).
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Vless { .. } => "vless",
            Kind::Vmess { .. } => "vmess",
            Kind::Trojan { .. } => "trojan",
            Kind::Shadowsocks { .. } => "shadowsocks",
            Kind::Hysteria2 { .. } => "hysteria2",
            Kind::Tuic { .. } => "tuic",
            Kind::Naive { .. } => "naive",
            Kind::Anytls { .. } => "anytls",
            Kind::Wireguard(_) => "wireguard",
            Kind::Amneziawg { .. } => "amneziawg",
            Kind::Socks { .. } => "socks",
            Kind::Http { .. } => "http",
        }
    }

    /// True when the protocol itself runs over UDP (QUIC or WireGuard): TCP probes say nothing about it.
    pub fn is_udp_transport(&self) -> bool {
        matches!(
            self,
            Kind::Hysteria2 { .. }
                | Kind::Tuic { .. }
                | Kind::Wireguard(_)
                | Kind::Amneziawg { .. }
                | Kind::Naive { quic: true, .. }
        )
    }

    /// The WireGuard part of a WireGuard or AmneziaWG profile (keys, addresses, peers). Never a
    /// reason to run AmneziaWG as WireGuard: match the kind for that.
    pub fn wireguard(&self) -> Option<&WireGuard> {
        match self {
            Kind::Wireguard(wg) | Kind::Amneziawg { wg, .. } => Some(wg),
            _ => None,
        }
    }

    /// [`Kind::wireguard`] for importers that complete a parsed entry.
    pub(crate) fn wireguard_mut(&mut self) -> Option<&mut WireGuard> {
        match self {
            Kind::Wireguard(wg) | Kind::Amneziawg { wg, .. } => Some(wg),
            _ => None,
        }
    }
}

/// SIP003 plugin of a Shadowsocks key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsPlugin {
    pub name: String,
    pub opts: String,
}

/// ShadowTLS wrapper around a Shadowsocks key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTlsLayer {
    pub version: u8,
    pub password: String,
    pub server_name: String,
}

/// Hysteria2 obfuscation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hy2Obfs {
    /// `salamander` (or `gecko` on sing-box 1.14).
    pub kind: String,
    pub password: String,
}

/// TLS settings exactly as the provider gave them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Tls {
    pub server_name: Option<String>,
    pub disable_sni: bool,
    pub insecure: bool,
    pub alpn: Vec<String>,
    /// uTLS fingerprint named by the provider; `None` lets the emitter pick the app default.
    pub fingerprint: Option<String>,
    pub reality: Option<Reality>,
    pub ech: Option<Ech>,
    /// SHA-256 of the server certificate (lower-case hex), e.g. Hysteria2 `pinSHA256`.
    pub cert_pin_sha256: Option<String>,
    /// sing-box `certificate_public_key_sha256` values (base64).
    pub spki_pin_sha256: Vec<String>,
    pub certificate_pem: Option<String>,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
}

/// uTLS fingerprints REALITY servers since Xray 26.9.8 refuse (`android` and `360` fail on every
/// version): field reports of the RU November 2026 plan. Only `chrome`, `firefox`, `safari` pass.
pub const REALITY_REFUSED_FINGERPRINTS: [&str; 6] =
    ["edge", "ios", "qq", "random", "android", "360"];

impl Tls {
    /// REALITY with a provider fingerprint that current REALITY servers refuse.
    pub fn refused_reality_fingerprint(&self) -> bool {
        self.reality.is_some()
            && self.fingerprint.as_deref().is_some_and(|fp| {
                let fp = fp.trim().to_ascii_lowercase();
                REALITY_REFUSED_FINGERPRINTS.contains(&fp.as_str())
            })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Reality {
    pub public_key: String,
    pub short_id: String,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Ech {
    pub config_lines: Vec<String>,
    pub query_server_name: Option<String>,
}

/// Stream transport under the protocol.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    Ws {
        path: String,
        host: Option<String>,
        max_early_data: Option<u32>,
        early_data_header: Option<String>,
    },
    /// `multi_mode: Some(_)` exists only in Xray.
    Grpc {
        service_name: String,
        multi_mode: Option<bool>,
    },
    Http {
        hosts: Vec<String>,
        path: String,
    },
    HttpUpgrade {
        host: String,
        path: String,
    },
    Quic,
    /// Xray only.
    Xhttp {
        host: String,
        path: String,
        mode: Option<String>,
        extra: Option<Map<String, Value>>,
    },
    /// TCP with an HTTP header mask; Xray only.
    TcpHttpHeader {
        host: Vec<String>,
        path: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Mux {
    pub enabled: bool,
    pub protocol: Option<String>,
    pub max_connections: Option<u32>,
    pub padding: bool,
    /// TCP Brutal (up, down) in Mbps.
    pub brutal: Option<(u32, u32)>,
}

/// Dial options a provider may set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DialPrefs {
    pub connect_timeout_s: Option<u32>,
    pub tcp_fast_open: bool,
    pub tcp_multi_path: bool,
    pub udp_fragment: Option<bool>,
    /// sing-box domain strategy (`prefer_ipv4`, `ipv4_only`, …).
    pub dns_strategy: Option<String>,
}

impl DialPrefs {
    pub fn is_default(&self) -> bool {
        *self == DialPrefs::default()
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WireGuard {
    pub private_key: String,
    pub local_address: Vec<ipnet::IpNet>,
    pub mtu: Option<u16>,
    pub dns: Vec<IpAddr>,
    pub peers: Vec<WgPeer>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WgPeer {
    pub host: Host,
    pub port: u16,
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<ipnet::IpNet>,
    pub keepalive_s: Option<u16>,
    pub reserved: Option<[u8; 3]>,
}

/// Provider Xray graph kept as data: outbounds with their own tags, plus the routing pieces that
/// tie them together. `vpnte_engine::xray` compiles it with namespaced tags.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeXray {
    /// Format version, currently 1.
    pub version: u8,
    pub selected_tag: String,
    pub entry: NativeEntry,
    pub outbounds: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<NativeRouting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observatory: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst_observatory: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Value>,
}

/// Where traffic enters the graph: exactly one of the two is set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NativeEntry {
    pub outbound_tag: Option<String>,
    pub balancer_tag: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NativeRouting {
    pub rules: Vec<Value>,
    pub balancers: Vec<Value>,
}

/// Where a profile came from. `Uri` keeps the exact imported line for lossless re-export.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "lowercase")]
pub enum Source {
    Uri(String),
    Json,
    Clash,
    WgIni,
    Legacy,
}

/// A fact about how a profile was read that the user should see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "note", content = "detail", rename_all = "kebab-case")]
pub enum Note {
    /// The naive protocol cannot skip certificate checks; `insecure` was kept but is not applied.
    NaiveInsecureIgnored,
    /// A certificate pin is stored but the engine cannot enforce it yet.
    CertPinNotEnforced,
    AlterIdNormalized(u32),
    /// A provider uTLS fingerprint does not apply to QUIC transports.
    ProviderFpDroppedOnQuic,
    UnsupportedField(String),
    FileReferenceDropped(String),
    DialFieldDropped(String),
    /// The key has no transport encryption.
    Unencrypted,
    MuxSingBoxOnly,
    /// Free-form note for cases without a dedicated variant (already localized by the importer is NOT allowed: use an i18n key).
    Other(String),
}

impl Note {
    /// [`Note::Other`] key: the REALITY key names a fingerprint current servers refuse.
    pub const REALITY_FINGERPRINT: &str = "profiles.import.realityFingerprint";
    /// [`Note::Other`] key: an Xray stream Xray 26 removed (HTTP/2, QUIC) now runs on sing-box.
    pub const XRAY_TRANSPORT_REMOVED: &str = "profiles.import.xrayTransportRemoved";
    /// [`Note::Other`] key: a NaiveProxy key pins a public key NaiveProxy cannot check (the
    /// certificate is still checked against the trusted CAs).
    pub const NAIVE_PIN_NOT_ENFORCED: &str = "profiles.import.naivePinNotEnforced";

    /// The note every importer adds for these TLS settings, if any (the REALITY fingerprint risk;
    /// it holds whichever engine runs the key).
    pub fn for_tls(tls: Option<&Tls>) -> Option<Note> {
        tls.filter(|t| t.refused_reality_fingerprint())
            .map(|_| Note::Other(Note::REALITY_FINGERPRINT.into()))
    }
}

/// Outcome of parsing a piece of text (pasted keys or a subscription body).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ParseReport {
    pub profiles: Vec<Profile>,
    pub skipped: Vec<Skipped>,
    pub meta: SubscriptionMeta,
}

/// An entry that looked like a key but was not imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Redacted excerpt, at most 80 chars, to help the user find the line.
    pub excerpt: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    UnknownScheme(String),
    /// Recognised scheme/format, but the entry is malformed; `detail` is an English diagnostic.
    Invalid {
        scheme: String,
        detail: String,
    },
    MissingCredential,
    ShadowTlsNeedsInner,
    UnsupportedPlugin(String),
    UnsupportedTransport(String),
    Duplicate,
    NativeGraphRejected(String),
    /// A protocol no engine of this app runs, named as users know it (`OpenVPN over Cloak`): a
    /// container of an AmneziaVPN key.
    UnsupportedProtocol(String),
    /// AmneziaWG parameters out of bounds or inconsistent; every such field is named.
    AwgInvalid(crate::awg::AwgInvalid),
}

/// Subscription metadata from body comment lines and response headers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SubscriptionMeta {
    pub upload: Option<u64>,
    pub download: Option<u64>,
    pub total: Option<u64>,
    pub expires_at: Option<vpnte_base::types::UnixMs>,
    /// Provider-recommended refresh interval in hours.
    pub refresh_hours: Option<u32>,
    pub title: Option<String>,
    pub web_page_url: Option<String>,
    pub support_url: Option<String>,
    pub announce: Option<String>,
}

/// The pasted input was larger than the import limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("input is too large")]
pub struct TooLarge;
