//! Which engine runs a profile. Pure: no I/O, no credentials in the result, recomputed on every
//! start and switch because the preference can change.
use serde::Serialize;
use vpnte_base::error::AppError;
use vpnte_base::msg::Msg;
use vpnte_base::types::{Engine, EnginePref};
use vpnte_profiles::model::{Host, Kind, Profile, Transport};

/// Shadowsocks ciphers the bundled Xray builds (checked with `xray run -test`; it refuses
/// `none`, `plain`, `aes-192-gcm` and the legacy stream ciphers sing-box still has).
const XRAY_SS_METHODS: [&str; 9] = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// Why the selected engine runs the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectReason {
    /// Nothing asks for Xray: sing-box is the main engine.
    Default,
    /// Xray has no outbound for the protocol (Hysteria2, TUIC, WireGuard, ShadowTLS, …).
    Protocol,
    /// The user forced this engine and the profile allows it.
    Preference,
    /// Current Xray REALITY servers reject the sing-box client (sing-box issue #4520).
    Reality,
    /// XHTTP, gRPC multi / explicit gun, VLESS Encryption or a RAW HTTP header mask.
    XrayTransport,
    /// Provider Xray graph (balancers, bridges, loopback reroutes).
    NativeXray,
    /// The profile uses something only sing-box can do.
    SingBoxOnly(SingBoxOnly),
}

/// A profile feature Xray refuses or cannot honour, in check order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SingBoxOnly {
    /// Xray v25+ removed the HTTP/2 transport.
    H2Transport,
    /// Xray v25+ removed the QUIC transport.
    QuicTransport,
    /// Xray refuses `allowInsecure`; only a pinned certificate may replace CA checks.
    InsecureWithoutPin,
    /// Xray ignores public-key (SPKI) pins: running there would silently drop the pin.
    SpkiPin,
    /// ECH (mapping the sing-box config lines to Xray `echConfigList` is not done).
    Ech,
    /// SIP003 plugins.
    ShadowsocksPlugin,
    /// The Xray Shadowsocks outbound has no UDP-over-TCP.
    ShadowsocksUdpOverTcp,
    /// A cipher the bundled Xray does not build.
    ShadowsocksMethod,
    /// "REALITY only supports RAW, XHTTP and gRPC for now."
    RealityTransport,
    /// VLESS / Trojan without TLS to a public server: refused by Xray 26.11.
    Plaintext,
}

impl SingBoxOnly {
    /// Locale key suffix shared by the `singBoxOnly.*` and `conflict.*` messages.
    fn key(self) -> &'static str {
        match self {
            SingBoxOnly::H2Transport => "h2Transport",
            SingBoxOnly::QuicTransport => "quicTransport",
            SingBoxOnly::InsecureWithoutPin => "insecureWithoutPin",
            SingBoxOnly::SpkiPin => "spkiPin",
            SingBoxOnly::Ech => "ech",
            SingBoxOnly::ShadowsocksPlugin => "shadowsocksPlugin",
            SingBoxOnly::ShadowsocksUdpOverTcp => "shadowsocksUdpOverTcp",
            SingBoxOnly::ShadowsocksMethod => "shadowsocksMethod",
            SingBoxOnly::RealityTransport => "realityTransport",
            SingBoxOnly::Plaintext => "plaintext",
        }
    }
}

/// Why no engine can run the profile with the current preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reject {
    /// A provider Xray graph under forced sing-box.
    NativeXray,
    /// An Xray-only transport or feature under forced sing-box.
    XrayTransport,
    /// A sing-box-only feature under forced Xray.
    SingBoxOnly(SingBoxOnly),
    /// The profile needs Xray and also uses something Xray refuses.
    Conflict(SingBoxOnly),
}

impl Reject {
    /// User-facing explanation (`engine.xray.*`).
    pub fn msg(&self) -> Msg {
        match self {
            Reject::NativeXray => Msg::new("engine.xray.reject.nativeXray"),
            Reject::XrayTransport => Msg::new("engine.xray.reject.xrayTransport"),
            Reject::SingBoxOnly(f) => Msg::new(format!("engine.xray.singBoxOnly.{}", f.key())),
            Reject::Conflict(f) => Msg::new(format!("engine.xray.conflict.{}", f.key())),
        }
    }
}

impl From<Reject> for AppError {
    fn from(reject: Reject) -> Self {
        AppError::validation(reject.msg())
    }
}

/// Outcome of [`select_engine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Run the profile on `engine`; record this engine (not the preference) in the history.
    Selected {
        engine: Engine,
        reason: SelectReason,
    },
    /// Neither engine may run it with the current preference.
    Rejected(Reject),
}

impl Decision {
    /// The engine to run, or why none can.
    pub fn engine(self) -> Result<Engine, Reject> {
        match self {
            Decision::Selected { engine, .. } => Ok(engine),
            Decision::Rejected(reject) => Err(reject),
        }
    }
}

/// Picks the engine for `p` under the user's preference (decision table of the xray-engine spec
/// §2.2, first match wins).
pub fn select_engine(p: &Profile, pref: EnginePref) -> Decision {
    if p.native_xray.is_some() {
        return match pref {
            EnginePref::SingBox => Decision::Rejected(Reject::NativeXray),
            EnginePref::Auto | EnginePref::Xray => xray(SelectReason::NativeXray),
        };
    }
    if !xray_protocol(&p.kind) {
        return sing_box(SelectReason::Protocol);
    }
    match (xray_only(p), singbox_only(p)) {
        (true, Some(f)) => return Decision::Rejected(Reject::Conflict(f)),
        (true, None) if pref == EnginePref::SingBox => {
            return Decision::Rejected(Reject::XrayTransport);
        }
        (true, None) => return xray(SelectReason::XrayTransport),
        (false, Some(f)) if pref == EnginePref::Xray => {
            return Decision::Rejected(Reject::SingBoxOnly(f));
        }
        (false, Some(f)) => return sing_box(SelectReason::SingBoxOnly(f)),
        (false, None) => {}
    }
    match pref {
        EnginePref::SingBox => sing_box(SelectReason::Preference),
        // Explicit gRPC "gun" runs on both engines; Auto keeps the old app's Xray choice.
        EnginePref::Auto if explicit_gun(p) => xray(SelectReason::XrayTransport),
        EnginePref::Auto if reality(p) => xray(SelectReason::Reality),
        EnginePref::Auto => sing_box(SelectReason::Default),
        EnginePref::Xray if explicit_gun(p) => xray(SelectReason::XrayTransport),
        EnginePref::Xray => xray(SelectReason::Preference),
    }
}

fn xray(reason: SelectReason) -> Decision {
    Decision::Selected {
        engine: Engine::Xray,
        reason,
    }
}

fn sing_box(reason: SelectReason) -> Decision {
    Decision::Selected {
        engine: Engine::SingBox,
        reason,
    }
}

/// VLESS, VMess, Trojan and plain Shadowsocks (a ShadowTLS layer is a protocol Xray lacks).
pub(super) fn xray_protocol(kind: &Kind) -> bool {
    match kind {
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. } => true,
        Kind::Shadowsocks { shadowtls, .. } => shadowtls.is_none(),
        _ => false,
    }
}

/// XHTTP, gRPC multi mode, RAW HTTP header mask or VLESS Encryption: sing-box has none of them.
fn xray_only(p: &Profile) -> bool {
    matches!(
        p.transport,
        Some(
            Transport::Xhttp { .. }
                | Transport::Grpc {
                    multi_mode: Some(true),
                    ..
                }
                | Transport::TcpHttpHeader { .. }
        )
    ) || vless_encryption(&p.kind).is_some()
}

fn explicit_gun(p: &Profile) -> bool {
    matches!(
        p.transport,
        Some(Transport::Grpc {
            multi_mode: Some(false),
            ..
        })
    )
}

/// REALITY lives inside enabled TLS in the typed model (old bug B22 cannot occur).
fn reality(p: &Profile) -> bool {
    p.tls.as_ref().is_some_and(|t| t.reality.is_some())
}

/// The VLESS Encryption string (`mlkem768x25519plus.…`) when set and not `none`.
pub(super) fn vless_encryption(kind: &Kind) -> Option<&str> {
    match kind {
        Kind::Vless {
            encryption: Some(e),
            ..
        } if !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("none") => Some(e.trim()),
        _ => None,
    }
}

/// The first feature of `p` that Xray refuses or cannot honour.
pub(super) fn singbox_only(p: &Profile) -> Option<SingBoxOnly> {
    match p.transport {
        Some(Transport::Http { .. }) => return Some(SingBoxOnly::H2Transport),
        Some(Transport::Quic) => return Some(SingBoxOnly::QuicTransport),
        _ => {}
    }
    let reality = reality(p);
    if let Some(tls) = p.tls.as_ref().filter(|_| !reality) {
        // REALITY has no CA check, so `insecure` and certificate pins mean nothing there. A blank
        // pin is not emitted, so it does not count.
        let pinned = tls
            .cert_pin_sha256
            .as_deref()
            .is_some_and(|p| !p.trim().is_empty());
        if tls.insecure && !pinned {
            return Some(SingBoxOnly::InsecureWithoutPin);
        }
        if !tls.spki_pin_sha256.is_empty() {
            return Some(SingBoxOnly::SpkiPin);
        }
    }
    if p.tls.as_ref().is_some_and(|t| t.ech.is_some()) {
        return Some(SingBoxOnly::Ech);
    }
    if let Kind::Shadowsocks {
        method,
        plugin,
        uot,
        ..
    } = &p.kind
    {
        if plugin.is_some() {
            return Some(SingBoxOnly::ShadowsocksPlugin);
        }
        if uot.is_some() {
            return Some(SingBoxOnly::ShadowsocksUdpOverTcp);
        }
        if !XRAY_SS_METHODS.contains(&method.trim().to_ascii_lowercase().as_str()) {
            return Some(SingBoxOnly::ShadowsocksMethod);
        }
    }
    if reality
        && matches!(
            p.transport,
            Some(Transport::Ws { .. } | Transport::HttpUpgrade { .. })
        )
    {
        return Some(SingBoxOnly::RealityTransport);
    }
    let bare = matches!(p.kind, Kind::Vless { .. } | Kind::Trojan { .. })
        && vless_encryption(&p.kind).is_none();
    if bare && p.tls.is_none() && !private_literal(&p.server) {
        return Some(SingBoxOnly::Plaintext);
    }
    None
}

/// A private, loopback or link-local IP literal: Xray's own exemption for unencrypted VLESS /
/// Trojan. Host names never count (Xray checks after our DNS substitution; keep the choice pure).
fn private_literal(host: &Host) -> bool {
    match host {
        Host::Ip(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
        }
        Host::Ip(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
        Host::Domain(_) => false,
    }
}
