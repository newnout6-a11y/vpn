//! Capability summary of a profile for server details and diagnostics: how the connection is
//! disguised and what the user should know before connecting (P-27: the old warnings were
//! English-only and shown in diagnostics alone).
use serde::Serialize;
use serde_json::Value;
use vpnte_base::Msg;

use crate::emit_singbox::tls_required;
use crate::model::{Kind, Note, Profile, SkipReason, Transport};

/// How a profile disguises its traffic, strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stealth {
    /// REALITY: the handshake of a real site.
    Reality,
    /// TLS with Encrypted Client Hello (config from the link, or from DNS on sing-box 1.14).
    Ech,
    /// NaïveProxy: Chromium's own network stack.
    Naive,
    /// Obfuscated stream: Hysteria2 obfs, a Shadowsocks SIP003 plugin.
    Obfs,
    /// TLS with a browser fingerprint (uTLS): the provider's, else the app default.
    Utls,
    /// TLS where uTLS cannot apply (QUIC protocols and the QUIC transport).
    Tls,
    /// No camouflage.
    Plain,
}

impl Stealth {
    /// Short user-facing label.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Stealth::Reality => "profiles.caps.stealth.reality",
            Stealth::Ech => "profiles.caps.stealth.ech",
            Stealth::Naive => "profiles.caps.stealth.naive",
            Stealth::Obfs => "profiles.caps.stealth.obfs",
            Stealth::Utls => "profiles.caps.stealth.utls",
            Stealth::Tls => "profiles.caps.stealth.tls",
            Stealth::Plain => "profiles.caps.stealth.plain",
        })
    }
}

/// What [`capabilities`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    /// Protocol label (`vless`, `hysteria2`, …), always the real protocol (the old summary saw
    /// the stored label `sing-box` for pasted JSON and missed every naive / HY2 fact).
    pub protocol: &'static str,
    /// How the traffic is disguised.
    pub stealth: Stealth,
    /// The connection runs TLS: the profile's own, or the TLS that Hysteria2, TUIC, naive,
    /// AnyTLS and a ShadowTLS wrapper always carry (the emitter adds it).
    pub tls: bool,
    /// Encrypted Client Hello is on.
    pub ech: bool,
    /// What to know before connecting, most important first.
    pub notes: Vec<Msg>,
}

/// The capability summary of `p`, predicted from the profile and the emitter's fixed policy
/// (uTLS default on TCP TLS, never on QUIC; naive never gets `insecure`).
pub fn capabilities(p: &Profile) -> Capabilities {
    let tls = p.tls.as_ref();
    let naive = matches!(p.kind, Kind::Naive { .. });
    let stealth = stealth(p);

    let mut notes = p.notes.clone();
    let mut derive = |note: Note| {
        if !notes.contains(&note) {
            notes.push(note);
        }
    };
    if naive && tls.is_some_and(|t| t.insecure) {
        derive(Note::NaiveInsecureIgnored);
    }
    if tls.is_some_and(|t| t.cert_pin_sha256.is_some()) {
        derive(Note::CertPinNotEnforced);
    }
    if over_quic(p) && tls.is_some_and(|t| t.fingerprint.is_some()) {
        derive(Note::ProviderFpDroppedOnQuic);
    }
    if unencrypted(p) {
        derive(Note::Unencrypted);
    }

    let mut msgs = Vec::new();
    // Naive gets its own note above; REALITY verifies by key, so the emitter drops `insecure`.
    if !naive && tls.is_some_and(|t| t.insecure && t.reality.is_none()) {
        msgs.push(Msg::new("profiles.caps.insecure"));
    }
    if p.kind.is_udp_transport()
        && p.singbox_extra.get("network").and_then(Value::as_str) == Some("tcp")
    {
        msgs.push(Msg::new("profiles.caps.udpOnTcpOnly"));
    }
    msgs.extend(notes.iter().map(note_msg));
    if matches!(stealth, Stealth::Reality | Stealth::Utls)
        && tls.is_none_or(|t| t.fingerprint.is_none())
    {
        msgs.push(Msg::new("profiles.caps.defaultFingerprint"));
    }

    Capabilities {
        protocol: p.kind.label(),
        stealth,
        tls: has_tls(p),
        ech: tls.is_some_and(|t| t.ech.is_some()),
        notes: msgs,
    }
}

/// The user-facing text of an import note. `Note::Other` already carries an i18n key.
pub fn note_msg(note: &Note) -> Msg {
    match note {
        Note::NaiveInsecureIgnored => Msg::new("profiles.caps.note.naiveInsecureIgnored"),
        Note::CertPinNotEnforced => Msg::new("profiles.caps.note.certPinNotEnforced"),
        Note::AlterIdNormalized(id) => {
            Msg::new("profiles.caps.note.alterIdNormalized").arg("alterId", id)
        }
        Note::ProviderFpDroppedOnQuic => Msg::new("profiles.caps.note.fingerprintDroppedOnQuic"),
        Note::UnsupportedField(field) => {
            Msg::new("profiles.caps.note.unsupportedField").arg("field", field)
        }
        Note::FileReferenceDropped(field) => {
            Msg::new("profiles.caps.note.fileReferenceDropped").arg("field", field)
        }
        Note::DialFieldDropped(field) => {
            Msg::new("profiles.caps.note.dialFieldDropped").arg("field", field)
        }
        Note::Unencrypted => Msg::new("profiles.caps.note.unencrypted"),
        Note::MuxSingBoxOnly => Msg::new("profiles.caps.note.muxSingBoxOnly"),
        Note::Other(key) => Msg::new(key.clone()),
    }
}

/// The user-facing text of a skipped entry. `Invalid.detail` and `NativeGraphRejected` carry a
/// short English diagnostic (never a credential), shown as an argument.
pub fn skip_msg(reason: &SkipReason) -> Msg {
    match reason {
        SkipReason::UnknownScheme(scheme) if scheme.is_empty() => {
            Msg::new("profiles.caps.skip.notAKey")
        }
        SkipReason::UnknownScheme(scheme) => {
            Msg::new("profiles.caps.skip.unknownScheme").arg("scheme", scheme)
        }
        SkipReason::Invalid { scheme, detail } => Msg::new("profiles.caps.skip.invalid")
            .arg("scheme", scheme)
            .arg("detail", detail),
        SkipReason::MissingCredential => Msg::new("profiles.caps.skip.missingCredential"),
        SkipReason::ShadowTlsNeedsInner => Msg::new("profiles.caps.skip.shadowTlsNeedsInner"),
        SkipReason::UnsupportedPlugin(plugin) => {
            Msg::new("profiles.caps.skip.unsupportedPlugin").arg("plugin", plugin)
        }
        SkipReason::UnsupportedTransport(transport) => {
            Msg::new("profiles.caps.skip.unsupportedTransport").arg("transport", transport)
        }
        SkipReason::Duplicate => Msg::new("profiles.caps.skip.duplicate"),
        SkipReason::NativeGraphRejected(reason) => {
            Msg::new("profiles.caps.skip.nativeGraphRejected").arg("reason", reason)
        }
    }
}

fn stealth(p: &Profile) -> Stealth {
    let tls = p.tls.as_ref();
    if tls.is_some_and(|t| t.reality.is_some()) {
        return Stealth::Reality;
    }
    if tls.is_some_and(|t| t.ech.is_some()) {
        return Stealth::Ech;
    }
    match &p.kind {
        Kind::Naive { .. } => return Stealth::Naive,
        Kind::Hysteria2 { obfs: Some(_), .. } => return Stealth::Obfs,
        // The ShadowTLS hop gets the device fingerprint like any TCP TLS.
        Kind::Shadowsocks {
            shadowtls: Some(_), ..
        } => return Stealth::Utls,
        Kind::Shadowsocks {
            plugin: Some(_), ..
        } => return Stealth::Obfs,
        _ => {}
    }
    if !has_tls(p) {
        Stealth::Plain
    } else if over_quic(p) {
        Stealth::Tls
    } else {
        Stealth::Utls
    }
}

/// TLS on the wire, also where the emitter adds it ([`tls_required`]).
fn has_tls(p: &Profile) -> bool {
    p.tls.is_some() || tls_required(&p.kind)
}

/// QUIC underneath: uTLS cannot apply (with it every sing-box 1.14 Hysteria2 dial failed, P-01).
fn over_quic(p: &Profile) -> bool {
    p.kind.is_udp_transport() || matches!(p.transport, Some(Transport::Quic))
}

/// Nothing encrypts the traffic: plain proxies, TLS-less Trojan / VLESS, `none` ciphers.
fn unencrypted(p: &Profile) -> bool {
    match &p.kind {
        // ShadowTLS disguises only the handshake; the data is the inner Shadowsocks stream.
        Kind::Shadowsocks { method, .. } => matches!(method.as_str(), "none" | "plain"),
        _ if has_tls(p) => false,
        Kind::Socks { .. } | Kind::Http { .. } | Kind::Trojan { .. } => true,
        Kind::Vless { encryption, .. } => encryption
            .as_deref()
            .is_none_or(|e| e.is_empty() || e == "none"),
        Kind::Vmess { security, .. } => matches!(security.as_str(), "none" | "zero"),
        Kind::Hysteria2 { .. }
        | Kind::Tuic { .. }
        | Kind::Naive { .. }
        | Kind::Anytls { .. }
        | Kind::Wireguard(_) => false,
    }
}

#[cfg(test)]
mod tests;
