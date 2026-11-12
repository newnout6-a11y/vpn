//! sing-box 1.14 emitter: typed [`Profile`] -> outbound, WireGuard endpoint or ShadowTLS chain.
//!
//! The one place where outbound normalisation lives (TLS / uTLS / ALPN defaults, multiplex,
//! UDP / QUIC capability, WireGuard endpoint rules). App defaults are applied here, at emit
//! time, and never written back into the profile; whatever the provider specified wins.
mod extra;
mod outbound;
mod tls;
mod udp;
mod wireguard;

// `check` also serves the importers' engine tests (`clash::check`).
#[cfg(test)]
pub(crate) mod check;
#[cfg(test)]
mod dial;
#[cfg(test)]
mod tests;

use std::net::IpAddr;

use serde_json::Value;
use vpnte_base::types::ClientDevice;
use vpnte_base::{AppError, Msg};

use crate::model::{Kind, Profile, Transport};

pub(crate) use tls::tls_required;
pub use tls::{effective_fingerprint, stealth_fingerprint};
pub use udp::{block_quic, udp_capable};

/// What the tunnel decides for one connection; the profile itself never carries these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitPolicy {
    /// Device the user picked; pins the default uTLS fingerprint (pc chrome, android android,
    /// ios ios, mac safari) of TCP-TLS outbounds whose provider named none.
    pub device: Option<ClientDevice>,
    /// Stealth mode or adaptive TLS compatibility: `record_fragment` on TCP-TLS without Reality
    /// and, when no device is pinned, a stable per-server fingerprint rotation.
    pub tls_compat: bool,
    /// Whether the profile's multiplex settings may be emitted.
    pub allow_mux: bool,
    /// Tag of the DNS server that resolves hostname servers (`domain_resolver`); `None` leaves
    /// resolution to `route.default_domain_resolver`.
    pub domain_resolver: Option<String>,
}

impl Default for EmitPolicy {
    fn default() -> Self {
        Self {
            device: None,
            tls_compat: false,
            allow_mux: true,
            domain_resolver: None,
        }
    }
}

/// Engine JSON for one profile, ready to be placed into a sing-box config.
#[derive(Debug, Clone, PartialEq)]
pub enum SingBoxFragment {
    /// One entry of `outbounds`.
    Outbound(Value),
    /// One entry of `endpoints` (WireGuard).
    Endpoint(Value),
    /// Shadowsocks over ShadowTLS: the Shadowsocks outbound tagged with the requested tag
    /// (`detour` points at the second one), then the ShadowTLS dialer.
    Chain(Vec<Value>),
}

impl SingBoxFragment {
    /// Entries for `outbounds`, the one carrying the requested tag first.
    pub fn outbounds(&self) -> &[Value] {
        match self {
            SingBoxFragment::Outbound(o) => std::slice::from_ref(o),
            SingBoxFragment::Chain(list) => list,
            SingBoxFragment::Endpoint(_) => &[],
        }
    }

    /// Entries for `endpoints`.
    pub fn endpoints(&self) -> &[Value] {
        match self {
            SingBoxFragment::Endpoint(e) => std::slice::from_ref(e),
            _ => &[],
        }
    }

    /// True when a server the engine dials is a hostname: the config then needs a direct
    /// bootstrap resolver (captured app DNS keeps going through the tunnel).
    pub fn needs_bootstrap_dns(&self) -> bool {
        self.dialed_hosts().any(|h| h.parse::<IpAddr>().is_err())
    }

    /// IP literals the engine dials (excluded from the TUN routes).
    pub fn endpoint_ips(&self) -> Vec<IpAddr> {
        let mut ips: Vec<IpAddr> = Vec::new();
        for ip in self.dialed_hosts().filter_map(|h| h.parse().ok()) {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        ips
    }

    /// Server addresses of the entries that dial themselves (a `detour` outbound does not).
    fn dialed_hosts(&self) -> impl Iterator<Item = &str> {
        let outbounds = self
            .outbounds()
            .iter()
            .filter(|o| o.get("detour").is_none())
            .filter_map(|o| o.get("server").and_then(Value::as_str));
        let peers = self
            .endpoints()
            .iter()
            .filter_map(|e| e.get("peers").and_then(Value::as_array))
            .flatten()
            .filter_map(|p| p.get("address").and_then(Value::as_str));
        outbounds.chain(peers)
    }
}

/// Why a profile cannot be expressed as sing-box 1.14 JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EmitError {
    /// The profile uses a feature only Xray implements (technical feature name).
    #[error("profile needs Xray: {0}")]
    XrayOnly(&'static str),
    /// Multiplex enabled on a protocol sing-box cannot multiplex (protocol label).
    #[error("multiplex is not supported on {0}")]
    MuxUnsupported(&'static str),
    /// TLS set on a protocol whose sing-box outbound has no TLS (protocol label).
    #[error("TLS is not supported on {0}")]
    TlsUnsupported(&'static str),
    /// A stream transport set on a protocol without transports (protocol label).
    #[error("transport is not supported on {0}")]
    TransportUnsupported(&'static str),
    #[error("Reality cannot be combined with ECH")]
    RealityWithEch,
    #[error("Reality cannot run over QUIC")]
    RealityOverQuic,
    #[error("public key pins cannot be combined with a trusted certificate")]
    PinWithCertificate,
    /// `insecure` next to a whole-certificate pin and no public-key pin: sing-box 1.14 cannot
    /// check that pin, so the server would not be verified at all (Xray enforces it).
    #[error("the certificate pin cannot be enforced while certificate checks are off")]
    CertPinUnenforced,
    #[error("ECH config is not valid base64 or PEM")]
    EchConfig,
    /// Shadowsocks plugin sing-box does not implement (plugin name).
    #[error("shadowsocks plugin {0:?} is not supported")]
    SsPlugin(String),
    /// Hysteria2 obfuscation sing-box does not implement, or without a password (obfs type).
    #[error("hysteria2 obfs {0:?} is not supported")]
    Hy2Obfs(String),
    #[error("wireguard: {0:?}")]
    WireGuard(WgProblem),
}

/// What is missing from a WireGuard profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgProblem {
    NoAddress,
    NoPeer,
    NoPrivateKey,
    NoPeerAddress,
    BadPeerPort,
    NoPublicKey,
    /// Several peers and one of them has no `allowed_ips`.
    AllowedIpsRequired,
}

impl From<EmitError> for AppError {
    fn from(err: EmitError) -> Self {
        let msg = match &err {
            EmitError::XrayOnly(feature) => {
                Msg::new("profiles.emit.xrayOnly").arg("feature", feature)
            }
            EmitError::MuxUnsupported(p) => {
                Msg::new("profiles.emit.muxUnsupported").arg("protocol", p)
            }
            EmitError::TlsUnsupported(p) => {
                Msg::new("profiles.emit.tlsUnsupported").arg("protocol", p)
            }
            EmitError::TransportUnsupported(p) => {
                Msg::new("profiles.emit.transportUnsupported").arg("protocol", p)
            }
            EmitError::RealityWithEch => Msg::new("profiles.emit.realityWithEch"),
            EmitError::RealityOverQuic => Msg::new("profiles.emit.realityOverQuic"),
            EmitError::PinWithCertificate => Msg::new("profiles.emit.pinWithCertificate"),
            EmitError::CertPinUnenforced => Msg::new("profiles.emit.certPinUnenforced"),
            EmitError::EchConfig => Msg::new("profiles.emit.echConfig"),
            EmitError::SsPlugin(name) => Msg::new("profiles.emit.ssPlugin").arg("plugin", name),
            EmitError::Hy2Obfs(kind) => Msg::new("profiles.emit.hy2Obfs").arg("obfs", kind),
            EmitError::WireGuard(problem) => Msg::new(match problem {
                WgProblem::NoAddress => "profiles.emit.wireguard.noAddress",
                WgProblem::NoPeer => "profiles.emit.wireguard.noPeer",
                WgProblem::NoPrivateKey => "profiles.emit.wireguard.noPrivateKey",
                WgProblem::NoPeerAddress => "profiles.emit.wireguard.noPeerAddress",
                WgProblem::BadPeerPort => "profiles.emit.wireguard.badPeerPort",
                WgProblem::NoPublicKey => "profiles.emit.wireguard.noPublicKey",
                WgProblem::AllowedIpsRequired => "profiles.emit.wireguard.allowedIpsRequired",
            }),
        };
        AppError::validation(msg).with_source(err)
    }
}

/// Builds the sing-box 1.14 JSON for `p` under `tag`. Only keys sing-box knows are written
/// (it decodes outbounds with DisallowUnknownFields); Xray-only features are refused.
pub fn emit_singbox(
    p: &Profile,
    tag: &str,
    policy: &EmitPolicy,
) -> Result<SingBoxFragment, EmitError> {
    if let Some(feature) = xray_only(p) {
        return Err(EmitError::XrayOnly(feature));
    }
    match &p.kind {
        Kind::Wireguard(wg) => {
            wireguard::endpoint(p, wg, tag, policy).map(SingBoxFragment::Endpoint)
        }
        Kind::Shadowsocks {
            shadowtls: Some(layer),
            ..
        } => outbound::shadowtls_chain(p, layer, tag, policy).map(SingBoxFragment::Chain),
        _ => outbound::outbound(p, tag, policy).map(SingBoxFragment::Outbound),
    }
}

/// The feature that keeps `p` off sing-box, if any (technical name shown to the user).
fn xray_only(p: &Profile) -> Option<&'static str> {
    if p.native_xray.is_some() {
        return Some("Xray JSON");
    }
    if let Kind::Vless {
        encryption: Some(e),
        ..
    } = &p.kind
    {
        let e = e.trim();
        if !e.is_empty() && !e.eq_ignore_ascii_case("none") {
            return Some("VLESS encryption");
        }
    }
    match &p.transport {
        Some(Transport::Xhttp { .. }) => Some("XHTTP"),
        Some(Transport::TcpHttpHeader { .. }) => Some("TCP header=http"),
        Some(Transport::Grpc {
            multi_mode: Some(true),
            ..
        }) => Some("gRPC multiMode"),
        _ => None,
    }
}
