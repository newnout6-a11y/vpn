//! What the Xray path leaves out of a profile, or keeps against field advice, as user-facing
//! warnings (`engine.xray.warn.*`) instead of debug logs. Pure: the caller shows them with the
//! other notices of a start.
use vpnte_base::msg::Msg;
use vpnte_profiles::model::{Kind, Profile, TlsTricks};

use super::config::xhttp_with_mux;
use super::fingerprint;
use super::hysteria::bbr_preset;
use super::stream::early_data_dropped;

/// Warnings for running `p` on Xray, in a stable order; empty when nothing is lost.
/// `tls_compat`: stealth / TLS compatibility is on, whose ClientHello fragmentation and
/// fingerprint rotation exist only in the sing-box emitter.
pub fn warnings(p: &Profile, tls_compat: bool) -> Vec<Msg> {
    let mut out = Vec::new();
    if let Some(graph) = &p.native_xray {
        if tls_compat {
            out.push(Msg::new("engine.xray.warn.stealth"));
        }
        if graph.outbounds.iter().any(xhttp_with_mux) {
            out.push(Msg::new("engine.xray.warn.xhttpMux"));
        }
        return out;
    }
    // QUIC and WireGuard have no TCP ClientHello: no uTLS, nothing to fragment.
    let tcp_tls = !matches!(p.kind, Kind::Hysteria2 { .. } | Kind::Wireguard(_));
    let tls = p.tls.as_ref().filter(|_| tcp_tls);
    // Only where the default would change what Xray runs: the tunnel resolves it into the
    // profile first (item 18), REALITY gets no tricks on either engine.
    let lost = p.tls_tricks_for(true) != p.tls_tricks_for(false);
    if tls_compat && tls.is_some() && lost {
        out.push(Msg::new("engine.xray.warn.stealth"));
    }
    if p.mux.as_ref().is_some_and(|m| m.enabled) {
        out.push(Msg::new("engine.xray.warn.mux"));
    }
    if !p.dial.is_default() {
        out.push(Msg::new("engine.xray.warn.dial"));
    }
    // Pasted trick keys reach Xray as the key's own tricks; only the rest is lost.
    let tricks = TlsTricks::SINGBOX_KEYS;
    if p.singbox_extra
        .keys()
        .any(|k| !tricks.contains(&k.as_str()))
    {
        out.push(Msg::new("engine.xray.warn.singboxExtra"));
    }
    if p.tls
        .as_ref()
        .is_some_and(|t| t.disable_sni && t.reality.is_none())
    {
        out.push(Msg::new("engine.xray.warn.disableSni"));
    }
    out.extend(tls.and_then(fingerprint::warning));
    if early_data_dropped(p.transport.as_ref()) {
        out.push(Msg::new("engine.xray.warn.earlyData"));
    }
    // An empty encoding means no UDP at all, which the sing-box front already enforces.
    if let Kind::Vless {
        packet_encoding: Some(encoding),
        ..
    } = &p.kind
        && !encoding.trim().is_empty()
        && !encoding.trim().eq_ignore_ascii_case("xudp")
    {
        out.push(Msg::new("engine.xray.warn.packetEncoding").arg("encoding", encoding.trim()));
    }
    if let Kind::Hysteria2 {
        bbr_profile: Some(bbr),
        ..
    } = &p.kind
        && !bbr.trim().is_empty()
        && bbr_preset(bbr).is_none()
    {
        out.push(Msg::new("engine.xray.warn.bbrProfile").arg("profile", bbr.trim()));
    }
    out
}
