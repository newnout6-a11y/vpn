//! Network mode (RU audit item 9): what kind of network this PC is on, named in plain words.
//! Mobile networks in Russia may let only whitelisted Russian hosts through, cut QUIC / UDP,
//! filter DoH by its server name, ban single server addresses (ICMP still answers, TCP and UDP
//! are dropped) or freeze foreign transfers after ~16 KB. The check runs the stages in order —
//! DNS, TCP, TLS, bytes after 16 KB, UDP (and the user's servers) — against reference hosts
//! ([`refs`]); [`classify`] turns what they saw into [`Mode`]s. Nothing here leaves through a
//! VPN: while our TUN runs the probes use the session's direct-out ([`LiveProbe`]).
mod canary;
mod classify;
mod live;
mod quic;
pub mod refs;
mod stun;
#[cfg(test)]
mod tests;
mod udp;

use std::future::Future;
use std::net::SocketAddr;

use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, Msg};
use vpnte_core::resolve::DohByName;

pub use canary::{CANARY_NAMES, Canary, CanaryLookup, WireLookup, dns_canary};
pub use classify::{Facts, HostFacts, classify, steps, udp_evidence};
pub use live::LiveProbe;

use crate::discipline::{Reach, Transfer};

/// How one probe went.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Outcome {
    /// Not run: no address, an earlier stage failed, or not asked.
    #[default]
    NotRun,
    /// An answer, a connection, a completed handshake.
    Ok,
    /// Reset: a TCP RST at connect, or the connection cut during the handshake.
    Reset,
    /// Silence until the limit (bans and whitelists drop packets silently).
    Silent,
    /// Any other failure (no such name, a forged answer, a TLS alert).
    Failed,
}

/// A restriction the check found (several may hold at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Only whitelisted Russian hosts are reachable (mobile whitelist).
    Whitelist,
    /// Foreign TCP works, UDP does not: neither QUIC on 443 nor STUN on other ports answers.
    UdpBlocked,
    /// DoH to a foreign resolver by name fails while the system resolver answers.
    DohBlocked,
    /// A server of the list answers ICMP while TCP to it is dropped: its address is banned.
    ServerBlocked,
    /// A foreign transfer stalls after ~12–24 KB (the hosting freeze).
    Freeze,
}

impl Mode {
    /// The mode's name for the user (`probes.netmode.mode.*`).
    pub fn msg(self) -> Msg {
        Msg::new(format!("probes.netmode.mode.{}", self.key()))
    }

    /// What helps in this mode (`probes.netmode.advice.*`).
    pub fn advice(self) -> Msg {
        Msg::new(format!("probes.netmode.advice.{}", self.key()))
    }

    fn key(self) -> &'static str {
        match self {
            Mode::Whitelist => "whitelist",
            Mode::UdpBlocked => "udpBlocked",
            Mode::DohBlocked => "dohBlocked",
            Mode::ServerBlocked => "serverBlocked",
            Mode::Freeze => "freeze",
        }
    }
}

/// The overall answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Summary {
    /// At least one [`Mode`] holds.
    Restricted,
    /// Foreign hosts, the transfer past the freeze band, QUIC and STUN all worked.
    Open,
    /// No reference host answered over HTTPS.
    Offline,
    /// No restriction proven, but not every check passed either.
    NotVerified,
}

/// What the UDP probes prove about UDP on this network (not about any server).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UdpEvidence {
    /// Foreign TCP works while every QUIC and every STUN probe met silence: UDP is dropped.
    Dropped,
    /// A QUIC or a STUN server answered: UDP passes (at least on some ports).
    Passes,
    /// Neither: probes not run, unclear errors, or nothing reachable at all.
    Unclear,
}

/// A stage of the check, in the order it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepKind {
    Dns,
    Tcp,
    Tls,
    Bytes,
    Udp,
    Servers,
}

/// How a stage went, for its mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StepStatus {
    Ok,
    Warn,
    Fail,
    NotRun,
}

/// One stage with its plain-words result.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub kind: StepKind,
    pub status: StepStatus,
    pub detail: Msg,
}

/// The finished check.
#[derive(Debug, Clone, PartialEq)]
pub struct NetReport {
    pub at: UnixMs,
    /// The probes left through the running session's direct-out (our TUN was up).
    pub via_session: bool,
    pub steps: Vec<Step>,
    pub modes: Vec<Mode>,
    pub summary: Summary,
    /// For the reactions' network memory: UDP dropped, passing, or unknown on this network.
    pub udp: UdpEvidence,
}

impl NetReport {
    /// A restriction holds: the start page shows its banner.
    pub fn restrictive(&self) -> bool {
        !self.modes.is_empty()
    }

    /// The verdict in one line: the first mode's name, else the summary's.
    pub fn headline(&self) -> Msg {
        match self.modes.first() {
            Some(mode) => mode.msg(),
            None => Msg::new(match self.summary {
                Summary::Open => "probes.netmode.summary.open",
                Summary::Offline => "probes.netmode.summary.offline",
                Summary::Restricted | Summary::NotVerified => "probes.netmode.summary.notVerified",
            }),
        }
    }
}

/// The measurements behind the check ([`LiveProbe`] on the real network, fakes in tests).
pub trait NetProbe: Send + Sync {
    /// The Windows resolver for `name`.
    fn system_dns(&self, name: &str) -> impl Future<Output = Outcome> + Send;
    /// One DoH-by-name upstream for `name`.
    fn doh(&self, resolver: DohByName, name: &str) -> impl Future<Output = Outcome> + Send;
    /// TCP connect to `host:443`, then a TLS handshake with its name.
    fn https(&self, host: &str) -> impl Future<Output = HostFacts> + Send;
    /// 64 KiB from a foreign data centre (`None`: could not be started).
    fn transfer(&self) -> impl Future<Output = Option<Transfer>> + Send;
    /// A QUIC version-negotiation probe to `host:443`.
    fn quic(&self, host: &str) -> impl Future<Output = Outcome> + Send;
    /// A STUN Binding Request to `host:port` (plain UDP on another port than 443).
    fn stun(&self, host: &str, port: u16) -> impl Future<Output = Outcome> + Send;
    /// ICMP echo and a TCP connect to a server of the list (its address: no lookup here).
    fn reach(&self, dst: SocketAddr) -> impl Future<Output = Reach> + Send;
}

/// Runs the stages in order (the probes of one stage at once) and gathers what they saw;
/// `servers` are addresses of the user's servers to test for an address ban (resolved by the
/// caller: this check never looks a server name up). `Err` only when `cancel` fires.
pub async fn gather<P: NetProbe>(
    probe: &P,
    servers: &[SocketAddr],
    cancel: &CancellationToken,
) -> Result<Facts, AppError> {
    let stages = async {
        let (system_dns, doh_foreign, doh_ru) = tokio::join!(
            probe.system_dns(refs::DNS_NAME),
            probe.doh(DohByName::Cloudflare, refs::DNS_NAME),
            probe.doh(DohByName::Yandex, refs::DNS_NAME),
        );
        let (ru, foreign) = tokio::join!(
            join_all(refs::RU_HOSTS.iter().map(|h| probe.https(h))),
            join_all(refs::FOREIGN_HOSTS.iter().map(|h| probe.https(h))),
        );
        // The freeze is a property of foreign transfers: without a foreign handshake there is
        // nothing to measure (a whitelist already explains the failure).
        let transfer = if foreign.iter().any(|h| h.tls == Outcome::Ok) {
            probe.transfer().await
        } else {
            None
        };
        let (quic, stun) = tokio::join!(
            join_all(refs::QUIC_HOSTS.iter().map(|h| probe.quic(h))),
            join_all(refs::STUN_HOSTS.iter().map(|(h, p)| probe.stun(h, *p))),
        );
        let servers = join_all(servers.iter().map(|dst| probe.reach(*dst))).await;
        Facts {
            system_dns,
            doh_foreign,
            doh_ru,
            ru,
            foreign,
            transfer,
            quic,
            stun,
            servers,
        }
    };
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(AppError::cancelled()),
        facts = stages => Ok(facts),
    }
}

/// The report of `facts` gathered now; `via_session`: our TUN was up (the probes left through
/// its direct-out, and the system resolver they asked was the tunnel's).
pub fn report(facts: &Facts, via_session: bool) -> NetReport {
    let (modes, summary) = classify(facts);
    NetReport {
        at: now_ms(),
        via_session,
        steps: steps(facts, via_session),
        modes,
        summary,
        udp: udp_evidence(facts),
    }
}
