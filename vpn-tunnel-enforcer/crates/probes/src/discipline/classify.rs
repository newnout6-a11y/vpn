//! The classifier: what the checks of one server observed → one verdict with a message and a
//! suggested reaction. Field signatures (Nov 2026): a banned IP still answers ICMP while TCP and
//! UDP to it are dropped (Habr 1105268), a hosting freeze lets ~16 KB through and then goes
//! silent without RST, a REALITY / fingerprint / version mismatch gets the real certificate of
//! the cover site back (sing-box #4520), mobile networks cut UDP while TCP 443 still passes.
//! Unsure → `not-verified`, never a success that was not observed.
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use vpnte_base::Msg;

use super::transfer::Transfer;
use crate::key_health::HealthReason;

/// What the checks concluded about a server (same wire names as the server list's stored
/// `ServerVerdict`, so the app maps them 1:1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// More than the freeze threshold went through the server.
    Healthy,
    /// Data stopped after the first ~12–24 KB without a reset: this network freezes the
    /// server's hosting.
    Frozen,
    /// Data stopped at another volume: no known signature.
    Stalled,
    /// TCP connects, the TLS / REALITY handshake fails or hangs, or the cover site's real
    /// certificate comes back.
    HandshakeFailed,
    /// The server refused the key.
    KeyRejected,
    /// ICMP answers while TCP and UDP time out: the address is banned on this network.
    IpBanned,
    /// QUIC / Hysteria / TUIC fail while TCP to the server works.
    UdpBlocked,
    /// Nothing answers.
    Offline,
    /// Not checked now: the server's handshake budget is used up.
    Deferred,
    /// The evidence does not single out a cause.
    NotVerified,
}

/// What the user (or the automation) should do about a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reaction {
    None,
    SwitchServer,
    TryAnotherFingerprint,
    PreferTcpTransport,
    RetryLater,
}

impl Verdict {
    /// Headline for the UI (`probes.verdict.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            Verdict::Healthy => "probes.verdict.healthy",
            Verdict::Frozen => "probes.verdict.frozen",
            Verdict::Stalled => "probes.verdict.stalled",
            Verdict::HandshakeFailed => "probes.verdict.handshakeFailed",
            Verdict::KeyRejected => "probes.verdict.keyRejected",
            Verdict::IpBanned => "probes.verdict.ipBanned",
            Verdict::UdpBlocked => "probes.verdict.udpBlocked",
            Verdict::Offline => "probes.verdict.offline",
            Verdict::Deferred => "probes.verdict.deferred",
            Verdict::NotVerified => "probes.verdict.notVerified",
        })
    }
}

impl Reaction {
    /// Advice for the UI (`probes.reaction.*`); `None` for [`Reaction::None`].
    pub fn msg(self) -> Option<Msg> {
        let key = match self {
            Reaction::None => return None,
            Reaction::SwitchServer => "probes.reaction.switchServer",
            Reaction::TryAnotherFingerprint => "probes.reaction.tryAnotherFingerprint",
            Reaction::PreferTcpTransport => "probes.reaction.preferTcpTransport",
            Reaction::RetryLater => "probes.reaction.retryLater",
        };
        Some(Msg::new(key))
    }
}

/// How a plain probe of the server's address went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Seen {
    /// Not probed (no clean path, cancelled, or not needed).
    #[default]
    NotRun,
    /// An answer: echo reply, or the TCP handshake completed.
    Answered,
    /// TCP reset: the address is reachable, nothing listens on the port.
    Refused,
    /// No answer within the limit (a ban drops packets silently).
    Silent,
}

/// Everything the checks of one server saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observations {
    /// The profile's transport runs over UDP (QUIC, Hysteria2, TUIC, WireGuard).
    pub udp_transport: bool,
    /// The handshake budget did not allow the engine check: nothing was dialled.
    pub deferred: bool,
    /// The transfer through the engine; `None` when the engine did not get that far.
    pub transfer: Option<Transfer>,
    /// Failure class of the engine dial (its log and the error), when it failed.
    pub failure: Option<HealthReason>,
    /// The engine log says the cover site's real certificate came back / REALITY verification
    /// failed.
    pub real_certificate: bool,
    /// ICMP echo to the server's address.
    pub icmp: Seen,
    /// Plain TCP connect to the server's own port.
    pub tcp: Seen,
}

/// A verdict with its reaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Classification {
    pub verdict: Verdict,
    pub reaction: Reaction,
}

impl Classification {
    fn of(verdict: Verdict, reaction: Reaction) -> Self {
        Classification { verdict, reaction }
    }
}

/// The engine log shows the server answering with the cover site's real certificate (a REALITY
/// / fingerprint / server version mismatch: sing-box #4520, Xray `minClientVer`).
pub fn real_certificate(log: &str) -> bool {
    static REAL: LazyLock<Regex> = LazyLock::new(|| {
        // Constant pattern, compiled by the tests.
        Regex::new(r"(?i)real certificate|reality verification failed").expect("static regex")
    });
    REAL.is_match(log)
}

/// One verdict from what the checks saw, in order of certainty: an observed transfer first,
/// then explicit engine failures, then the plain reach of the address.
pub fn classify(o: &Observations) -> Classification {
    use Reaction as R;
    use Verdict as V;
    if o.deferred {
        return Classification::of(V::Deferred, R::RetryLater);
    }
    match &o.transfer {
        Some(Transfer::Complete { .. }) => return Classification::of(V::Healthy, R::None),
        Some(t) if t.frozen() => return Classification::of(V::Frozen, R::SwitchServer),
        // Data moved, then stopped outside the freeze band: a connection-count freeze also
        // looks like this and lifts after ~2 minutes.
        Some(Transfer::Stalled { .. }) => return Classification::of(V::Stalled, R::RetryLater),
        // An answer came through the server and then the exchange failed (HTTP error, reset):
        // the server passes data, the volume is unproven.
        Some(Transfer::Failed { bytes, .. }) if *bytes > 0 => {
            return Classification::of(V::NotVerified, R::RetryLater);
        }
        _ => {}
    }
    match o.failure {
        Some(HealthReason::AuthFailed | HealthReason::Hy2AuthFailed) => {
            return Classification::of(V::KeyRejected, R::SwitchServer);
        }
        // No working probe could be built: nothing is known about the server.
        Some(
            HealthReason::ConfigFailed | HealthReason::Hy2ConfigFailed | HealthReason::NoOutbound,
        ) => {
            return Classification::of(V::NotVerified, R::None);
        }
        _ => {}
    }
    if o.real_certificate {
        return Classification::of(V::HandshakeFailed, R::TryAnotherFingerprint);
    }
    if o.udp_transport {
        return udp(o);
    }
    tcp(o)
}

/// A UDP transport failed (QUIC handshake never completed).
fn udp(o: &Observations) -> Classification {
    use Reaction as R;
    use Verdict as V;
    // A TLS failure inside QUIC means the datagrams got through: the handshake itself fails
    // (sing-box's Chrome QUIC parrot against an Ed25519 certificate, a pinned certificate).
    if o.failure == Some(HealthReason::Hy2TlsFailed) {
        return Classification::of(V::HandshakeFailed, R::TryAnotherFingerprint);
    }
    match (o.tcp, o.icmp) {
        // The address answers TCP (a reset counts): only UDP is cut on this network.
        (Seen::Answered | Seen::Refused, _) => {
            Classification::of(V::UdpBlocked, R::PreferTcpTransport)
        }
        (Seen::Silent, Seen::Answered) => Classification::of(V::IpBanned, R::SwitchServer),
        (Seen::Silent, Seen::Silent) => Classification::of(V::Offline, R::SwitchServer),
        _ if o.failure == Some(HealthReason::Hy2UdpBlocked) => {
            Classification::of(V::UdpBlocked, R::PreferTcpTransport)
        }
        _ => Classification::of(V::NotVerified, R::RetryLater),
    }
}

/// A TCP transport failed before data came back.
fn tcp(o: &Observations) -> Classification {
    use Reaction as R;
    use Verdict as V;
    let explicit = matches!(
        o.failure,
        Some(HealthReason::TlsFailed | HealthReason::HandshakeFailed)
    );
    match (o.tcp, o.icmp) {
        // TCP connects: the handshake on top of it is what fails. A hang is waited out (a burst
        // freeze lasts ~120 s and changing the fingerprint inside it is reported to extend it).
        (Seen::Answered, _) if explicit => {
            Classification::of(V::HandshakeFailed, R::TryAnotherFingerprint)
        }
        (Seen::Answered, _) => Classification::of(V::HandshakeFailed, R::RetryLater),
        // The host is up, nothing listens on the key's port.
        (Seen::Refused, _) => Classification::of(V::Offline, R::SwitchServer),
        // Changing port or transport will not help against an address ban.
        (Seen::Silent, Seen::Answered) => Classification::of(V::IpBanned, R::SwitchServer),
        (Seen::Silent, Seen::Silent) => Classification::of(V::Offline, R::SwitchServer),
        // No clean reach evidence: a TLS failure still implies TCP got through.
        _ if explicit => Classification::of(V::HandshakeFailed, R::TryAnotherFingerprint),
        _ => Classification::of(V::NotVerified, R::RetryLater),
    }
}
