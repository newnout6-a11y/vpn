//! Which engine runs a profile. Pure: no I/O, no credentials in the result, recomputed on every
//! start and switch because the preference can change.
use serde::Serialize;
use vpnte_base::error::AppError;
use vpnte_base::msg::Msg;
use vpnte_base::types::{Engine, EnginePref};
use vpnte_profiles::model::{Host, Kind, Profile, Reality, Tls, Transport};

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
    /// Xray has no outbound for the protocol or this form of it ([`XrayLacks`]); only under Auto
    /// or forced sing-box (forced Xray refuses the profile).
    Protocol,
    /// The user forced this engine and the profile allows it.
    Preference,
    /// Current Xray REALITY servers reject the sing-box client (sing-box issue #4520).
    Reality,
    /// XHTTP, gRPC multi / explicit gun, VLESS Encryption, a RAW HTTP header mask, certificate
    /// names or the REALITY ML-DSA-65 key.
    XrayTransport,
    /// Provider Xray graph (balancers, bridges, loopback reroutes).
    NativeXray,
    /// A pinned certificate hash: Xray enforces it, sing-box only pins public keys (a different
    /// value) and would run the profile without the pin.
    CertPin,
    /// A plain TLS key Xray runs with nothing lost: the bundled Xray's uTLS sends the current
    /// Chrome hello, sing-box's still Chrome 133, which the TSPU rate-limits (owner, 14.11.2026).
    TlsHello,
    /// The profile uses something only sing-box can do.
    SingBoxOnly(SingBoxOnly),
    /// AmneziaWG on the WP-12 lab engine mihomo (feature `lab`, lab record present).
    #[cfg(feature = "lab")]
    Amneziawg,
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
    /// ECH whose config must be looked up in DNS (Xray would ask a public resolver itself), ECH
    /// with REALITY (Xray has no ECH there) or over QUIC. A static TCP TLS config runs on Xray.
    Ech,
    /// SIP003 plugins.
    ShadowsocksPlugin,
    /// UDP-over-TCP with a pre-2022 cipher: Xray applies `uot` only to 2022 ciphers and would
    /// silently send native UDP instead.
    ShadowsocksUdpOverTcp,
    /// A cipher the bundled Xray does not build.
    ShadowsocksMethod,
    /// "REALITY only supports RAW, XHTTP and gRPC for now."
    RealityTransport,
    /// VLESS / Trojan without TLS to a public server: refused by Xray 26.11.
    Plaintext,
}

impl SelectReason {
    /// Short caption shown after the engine name («Xray · REALITY»), `engine.xray.reason.*`.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            SelectReason::Default => "engine.xray.reason.default",
            SelectReason::Protocol => "engine.xray.reason.protocol",
            SelectReason::Preference => "engine.xray.reason.preference",
            SelectReason::Reality => "engine.xray.reason.reality",
            SelectReason::XrayTransport => "engine.xray.reason.xrayTransport",
            SelectReason::NativeXray => "engine.xray.reason.nativeXray",
            SelectReason::CertPin => "engine.xray.reason.certPin",
            SelectReason::TlsHello => "engine.xray.reason.tlsHello",
            SelectReason::SingBoxOnly(_) => "engine.xray.reason.singBoxOnly",
            #[cfg(feature = "lab")]
            SelectReason::Amneziawg => "engine.lab.reason.amneziawg",
        })
    }
}

/// What Xray lacks to run a profile; the name is the protocol as users know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum XrayLacks {
    /// No outbound at all (`unknown config id`): TUIC, NaiveProxy, AnyTLS, ShadowTLS.
    Client(&'static str),
    /// The protocol exists in Xray, not in this form: a stream transport under Hysteria2 /
    /// WireGuard / SOCKS / HTTP, SOCKS over TLS.
    Form(&'static str),
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
    /// Forced Xray for a protocol Xray cannot run: a refusal, never a silent sing-box start
    /// (owner decision of 2026-11-11: both engines are first-class).
    XrayLacks(XrayLacks),
    /// AmneziaWG under any preference: neither engine dials it (mihomo does, a lab function of
    /// this build, WP-12), and plain WireGuard would only be dropped by the server.
    Amneziawg,
    /// Lab build: AmneziaWG for mihomo, but the lab record does not open the gate (AT-12-002).
    #[cfg(feature = "lab")]
    Lab(crate::lab::LabGap),
    /// Lab build: mihomo forced for a profile that is not AmneziaWG (the lab engine runs nothing
    /// else; never a silent switch to another engine).
    #[cfg(feature = "lab")]
    MihomoAwgOnly,
}

impl Reject {
    /// User-facing explanation (`engine.xray.*`).
    pub fn msg(&self) -> Msg {
        match self {
            Reject::NativeXray => Msg::new("engine.xray.reject.nativeXray"),
            Reject::XrayTransport => Msg::new("engine.xray.reject.xrayTransport"),
            Reject::SingBoxOnly(f) => Msg::new(format!("engine.xray.singBoxOnly.{}", f.key())),
            Reject::Conflict(f) => Msg::new(format!("engine.xray.conflict.{}", f.key())),
            Reject::XrayLacks(XrayLacks::Client(name)) => {
                Msg::new("engine.xray.reject.noXrayClient").arg("protocol", *name)
            }
            Reject::XrayLacks(XrayLacks::Form(name)) => {
                Msg::new("engine.xray.reject.xrayForm").arg("protocol", *name)
            }
            Reject::Amneziawg => Msg::new("engine.xray.reject.amneziawg"),
            #[cfg(feature = "lab")]
            Reject::Lab(gap) => gap.msg(),
            #[cfg(feature = "lab")]
            Reject::MihomoAwgOnly => Msg::new("engine.lab.reject.mihomoAwgOnly"),
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
    // Lab build: AmneziaWG goes to mihomo through the lab gate, forced mihomo runs nothing else.
    #[cfg(feature = "lab")]
    if let Some(decision) = crate::lab::select(p, pref, crate::lab::gate()) {
        return decision;
    }
    // Before every other rule: no preference may start AmneziaWG as plain WireGuard.
    if matches!(p.kind, Kind::Amneziawg { .. }) {
        return Decision::Rejected(Reject::Amneziawg);
    }
    if p.native_xray.is_some() {
        return match pref {
            EnginePref::SingBox => Decision::Rejected(Reject::NativeXray),
            EnginePref::Auto | EnginePref::Xray => xray(SelectReason::NativeXray),
            #[cfg(feature = "lab")]
            EnginePref::Mihomo => Decision::Rejected(Reject::MihomoAwgOnly),
        };
    }
    if let Some(lacks) = xray_lacks(p) {
        return match pref {
            EnginePref::Xray => Decision::Rejected(Reject::XrayLacks(lacks)),
            EnginePref::Auto | EnginePref::SingBox => sing_box(SelectReason::Protocol),
            #[cfg(feature = "lab")]
            EnginePref::Mihomo => Decision::Rejected(Reject::MihomoAwgOnly),
        };
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
        EnginePref::Auto if cert_pin(p).is_some() => xray(SelectReason::CertPin),
        EnginePref::Auto if plain_tls(p) => xray(SelectReason::TlsHello),
        EnginePref::Auto => sing_box(SelectReason::Default),
        EnginePref::Xray if explicit_gun(p) => xray(SelectReason::XrayTransport),
        EnginePref::Xray => xray(SelectReason::Preference),
        #[cfg(feature = "lab")]
        EnginePref::Mihomo => Decision::Rejected(Reject::MihomoAwgOnly),
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

/// The preference for one server: its own override (sing-box / Xray) wins, its `Auto` follows
/// the app setting. Tunnel, probes and proxy slots all apply it before [`select_engine`].
pub fn server_pref(setting: EnginePref, server: EnginePref) -> EnginePref {
    match server {
        EnginePref::Auto => setting,
        forced => forced,
    }
}

/// Kinds with an Xray outbound in the form `p` uses.
pub(super) fn xray_protocol(p: &Profile) -> bool {
    xray_lacks(p).is_none()
}

/// What Xray lacks for `p`. TUIC, Naive, AnyTLS and ShadowTLS have no outbound (`unknown config
/// id`). A stream transport under Hysteria2 / WireGuard / SOCKS / HTTP is refused by sing-box
/// too; SOCKS over TLS would send its UDP beside the TLS (Xray docs, transport.md).
fn xray_lacks(p: &Profile) -> Option<XrayLacks> {
    let form = |name| p.transport.is_some().then_some(XrayLacks::Form(name));
    match &p.kind {
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. } => None,
        Kind::Shadowsocks { shadowtls, .. } => shadowtls
            .is_some()
            .then_some(XrayLacks::Client("ShadowTLS")),
        Kind::Hysteria2 { .. } => form("Hysteria2"),
        Kind::Wireguard(_) => form("WireGuard"),
        Kind::Http { .. } => form("HTTP"),
        Kind::Socks { .. } if p.tls.is_some() => Some(XrayLacks::Form("SOCKS")),
        Kind::Socks { .. } => form("SOCKS"),
        Kind::Tuic { .. } => Some(XrayLacks::Client("TUIC")),
        Kind::Naive { .. } => Some(XrayLacks::Client("NaiveProxy")),
        Kind::Anytls { .. } => Some(XrayLacks::Client("AnyTLS")),
        // `select_engine` refuses it first; `translate` refuses it through this.
        Kind::Amneziawg { .. } => Some(XrayLacks::Client("AmneziaWG")),
    }
}

/// XHTTP, gRPC multi mode, RAW HTTP header mask, VLESS Encryption, certificate names
/// (`verifyPeerCertByName`) or the REALITY ML-DSA-65 key: sing-box has none of them, and running
/// a check-carrying profile there would quietly drop the check.
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
        || p.tls.as_ref().is_some_and(xray_checks)
}

/// Certificate names or the REALITY ML-DSA-65 key: checks only Xray makes.
fn xray_checks(tls: &Tls) -> bool {
    tls.cert_names().is_some()
        || tls
            .reality
            .as_ref()
            .and_then(Reality::mldsa65_key)
            .is_some()
}

/// VLESS / VMess / Trojan over TLS (not REALITY, not ECH) on RAW, WebSocket, HTTPUpgrade or gRPC
/// that Xray runs with nothing lost or to warn about: no mux, default dial options, no pasted
/// sing-box options, a fingerprint Xray keeps. sing-box 1.14.4 (utls 1.8.7) sends Chrome 133,
/// whose connections the TSPU limits (RPRX, 2026-10-13); Xray 26.11.9 sends Chrome 155. ECH stays:
/// Xray's hello with it is unmeasured.
fn plain_tls(p: &Profile) -> bool {
    let kind = matches!(
        p.kind,
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. }
    );
    let transport = matches!(
        p.transport,
        None | Some(Transport::Ws { .. } | Transport::HttpUpgrade { .. } | Transport::Grpc { .. })
    );
    let tls = p
        .tls
        .as_ref()
        .is_some_and(|t| t.reality.is_none() && t.ech.is_none());
    kind && transport && tls && super::warnings(p, false).is_empty()
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

/// The certificate pin of a TLS (not REALITY: no CA check there) profile. A blank pin is not
/// emitted, so it does not count.
pub(super) fn cert_pin(p: &Profile) -> Option<&str> {
    let tls = p.tls.as_ref().filter(|t| t.reality.is_none())?;
    let pin = tls.cert_pin_sha256.as_deref()?.trim();
    (!pin.is_empty()).then_some(pin)
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
        // Certificate names keep the CA check (against those names), so Xray needs no
        // `allowInsecure` for a provider that also set it for older clients.
        if tls.insecure && cert_pin(p).is_none() && tls.cert_names().is_none() {
            return Some(SingBoxOnly::InsecureWithoutPin);
        }
        if !tls.spki_pin_sha256.is_empty() {
            return Some(SingBoxOnly::SpkiPin);
        }
    }
    // Xray's ECH over QUIC (Hysteria2) is unproven; REALITY has no ECH at all.
    let ech = p.tls.as_ref().and_then(|t| t.ech.as_ref());
    let quic = matches!(p.kind, Kind::Hysteria2 { .. });
    if ech.is_some_and(|e| reality || quic || e.config_lines.iter().all(|l| l.trim().is_empty())) {
        return Some(SingBoxOnly::Ech);
    }
    if let Kind::Shadowsocks {
        method,
        plugin,
        uot,
        ..
    } = &p.kind
    {
        let method = method.trim().to_ascii_lowercase();
        if plugin.is_some() {
            return Some(SingBoxOnly::ShadowsocksPlugin);
        }
        if uot.is_some() && !method.starts_with("2022-") {
            return Some(SingBoxOnly::ShadowsocksUdpOverTcp);
        }
        if !XRAY_SS_METHODS.contains(&method.as_str()) {
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

// A lab build answers AmneziaWG through the lab gate (`crate::lab::tests` covers it there).
#[cfg(all(test, not(feature = "lab")))]
mod amneziawg_tests {
    use super::*;

    /// AmneziaWG is refused under every preference with its own reason and message, before any
    /// other rule: never a broken key, never a plain WireGuard start.
    #[test]
    fn amneziawg_is_refused_under_every_preference() {
        let conf = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.8.1.2/32\nJc = 4\nJmin = 40\nJmax = 70\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.7:51820\n";
        let p = vpnte_profiles::wg_ini::parse_wg_ini(conf)
            .expect("a .conf")
            .expect("valid");
        assert_eq!(p.kind.label(), "amneziawg");
        for pref in [EnginePref::Auto, EnginePref::SingBox, EnginePref::Xray] {
            assert_eq!(
                select_engine(&p, pref),
                Decision::Rejected(Reject::Amneziawg)
            );
        }
        assert!(!xray_protocol(&p), "translate refuses it too");
        let err: AppError = Reject::Amneziawg.into();
        assert_eq!(err.kind, vpnte_base::ErrorKind::Validation);
        crate::test_locales::assert_localized(&Reject::Amneziawg.msg().key);
    }
}
