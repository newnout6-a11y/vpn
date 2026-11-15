//! What the stages saw → the network's modes and the per-stage lines. Never a success that was
//! not observed: a stage whose probes did not run is "not run", and without clean evidence of a
//! restriction (and without a clean pass) the summary is "not verified".
use vpnte_base::Msg;

use super::{Mode, Outcome, Step, StepKind, StepStatus, Summary, UdpEvidence};
use crate::discipline::{Reach, Seen, Transfer};

/// One HTTPS reference: the TCP connect, then the TLS handshake on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostFacts {
    pub tcp: Outcome,
    pub tls: Outcome,
}

/// Everything the stages saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// The Windows resolver for the DNS reference name.
    pub system_dns: Outcome,
    /// DoH by name to the foreign resolver (`cloudflare-dns.com`).
    pub doh_foreign: Outcome,
    /// DoH by name to the Russian resolver (Yandex).
    pub doh_ru: Outcome,
    /// The Russian whitelisted references.
    pub ru: Vec<HostFacts>,
    /// The foreign references.
    pub foreign: Vec<HostFacts>,
    /// 64 KiB from a foreign data centre; `None` when it was not run.
    pub transfer: Option<Transfer>,
    /// QUIC probes (UDP 443).
    pub quic: Vec<Outcome>,
    /// STUN probes (UDP on other ports).
    pub stun: Vec<Outcome>,
    /// Reach of the user's servers.
    pub servers: Vec<Reach>,
}

impl Facts {
    fn ru_ok(&self) -> bool {
        self.ru.iter().any(|h| h.tls == Outcome::Ok)
    }

    fn foreign_ok(&self) -> bool {
        self.foreign.iter().any(|h| h.tls == Outcome::Ok)
    }

    fn foreign_ran(&self) -> bool {
        self.foreign.iter().any(|h| h.tcp != Outcome::NotRun)
    }

    fn banned_servers(&self) -> usize {
        self.servers
            .iter()
            .filter(|r| r.icmp == Seen::Answered && r.tcp == Seen::Silent)
            .count()
    }
}

/// The modes that hold, most limiting first, and the summary.
pub fn classify(f: &Facts) -> (Vec<Mode>, Summary) {
    let (ru_ok, foreign_ok) = (f.ru_ok(), f.foreign_ok());
    let mut modes = Vec::new();
    if ru_ok && !foreign_ok && f.foreign_ran() {
        modes.push(Mode::Whitelist);
    }
    // The rest needs foreign TCP to work: under a whitelist they would only repeat it.
    if foreign_ok {
        if f.transfer.as_ref().is_some_and(Transfer::frozen) {
            modes.push(Mode::Freeze);
        }
        if f.banned_servers() > 0 {
            modes.push(Mode::ServerBlocked);
        }
        if udp_evidence(f) == UdpEvidence::Dropped {
            modes.push(Mode::UdpBlocked);
        }
        let doh_cut = !matches!(f.doh_foreign, Outcome::Ok | Outcome::NotRun);
        if doh_cut && f.system_dns == Outcome::Ok {
            modes.push(Mode::DohBlocked);
        }
    }
    let summary = if !modes.is_empty() {
        Summary::Restricted
    } else if !ru_ok && !foreign_ok {
        Summary::Offline
    } else if foreign_ok
        && f.transfer.as_ref().is_some_and(Transfer::complete)
        && (probes(&f.quic), probes(&f.stun)) == (Probes::Answered, Probes::Answered)
    {
        Summary::Open
    } else {
        Summary::NotVerified
    };
    (modes, summary)
}

/// What the UDP probes prove about the network: dropped only when foreign
/// TCP works and both kinds were silent (QUIC on 443 alone may be a QUIC or port filter, under
/// which other UDP still passes); any answer proves UDP passes.
pub fn udp_evidence(f: &Facts) -> UdpEvidence {
    match (probes(&f.quic), probes(&f.stun)) {
        (Probes::Answered, _) | (_, Probes::Answered) => UdpEvidence::Passes,
        (Probes::Silent, Probes::Silent) if f.foreign_ok() => UdpEvidence::Dropped,
        _ => UdpEvidence::Unclear,
    }
}

/// One kind of UDP probe, taken together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Probes {
    /// At least one answered.
    Answered,
    /// At least one ran, and every one that ran met silence.
    Silent,
    /// None ran.
    NotRun,
    /// Errors or resets without an answer: proves nothing.
    Unclear,
}

fn probes(list: &[Outcome]) -> Probes {
    let ran: Vec<Outcome> = list
        .iter()
        .copied()
        .filter(|o| *o != Outcome::NotRun)
        .collect();
    if ran.contains(&Outcome::Ok) {
        Probes::Answered
    } else if ran.is_empty() {
        Probes::NotRun
    } else if ran.iter().all(|o| *o == Outcome::Silent) {
        Probes::Silent
    } else {
        Probes::Unclear
    }
}

/// The stages as the page lists them; `via_session`: the system resolver was our tunnel's.
pub fn steps(f: &Facts, via_session: bool) -> Vec<Step> {
    let mut out = vec![
        dns(f, via_session),
        counts(f, StepKind::Tcp),
        counts(f, StepKind::Tls),
    ];
    out.push(bytes(f.transfer.as_ref()));
    out.push(udp(f));
    if !f.servers.is_empty() {
        out.push(servers(f));
    }
    out
}

fn step(kind: StepKind, status: StepStatus, key: &str) -> Step {
    Step {
        kind,
        status,
        detail: Msg::new(format!("probes.netmode.step.{key}")),
    }
}

/// In a TUN session our tunnel answers the system's queries: the line says so (its own keys),
/// instead of describing the network's resolver it never reached.
fn dns(f: &Facts, via_session: bool) -> Step {
    use StepStatus as S;
    let ok = |o: Outcome| o == Outcome::Ok;
    let (system, foreign, ru) = (ok(f.system_dns), ok(f.doh_foreign), ok(f.doh_ru));
    let (status, key) = match (system, foreign, ru) {
        _ if f.system_dns == Outcome::NotRun => (S::NotRun, "notRun"),
        (true, true, _) => (S::Ok, "ok"),
        (true, false, true) => (S::Warn, "dohForeignCut"),
        (true, false, false) => (S::Warn, "dohCut"),
        (false, true, _) | (false, _, true) => (S::Warn, "systemFailed"),
        (false, false, false) => (S::Fail, "failed"),
    };
    let set = if via_session { "dnsTun" } else { "dns" };
    step(StepKind::Dns, status, &format!("{set}.{key}"))
}

/// TCP or TLS: how many Russian and foreign references passed.
fn counts(f: &Facts, kind: StepKind) -> Step {
    let pick = |h: &HostFacts| if kind == StepKind::Tcp { h.tcp } else { h.tls };
    let passed = |list: &[HostFacts]| list.iter().filter(|h| pick(h) == Outcome::Ok).count();
    let ran = |list: &[HostFacts]| list.iter().filter(|h| pick(h) != Outcome::NotRun).count();
    let (ru, foreign) = (passed(&f.ru), passed(&f.foreign));
    let status = if ran(&f.ru) + ran(&f.foreign) == 0 {
        StepStatus::NotRun
    } else if ru == f.ru.len() && foreign == f.foreign.len() {
        StepStatus::Ok
    } else if ru + foreign == 0 {
        StepStatus::Fail
    } else {
        StepStatus::Warn
    };
    let key = if kind == StepKind::Tcp { "tcp" } else { "tls" };
    let mut s = step(kind, status, key);
    s.detail = s
        .detail
        .arg("ru", ru)
        .arg("ruTotal", f.ru.len())
        .arg("foreign", foreign)
        .arg("foreignTotal", f.foreign.len());
    s
}

fn kib(bytes: u64) -> u64 {
    bytes / 1024
}

fn bytes(transfer: Option<&Transfer>) -> Step {
    use StepStatus as S;
    let (status, key, got) = match transfer {
        None => (S::NotRun, "bytes.notRun", 0),
        Some(Transfer::Complete { bytes, .. }) => (S::Ok, "bytes.ok", *bytes),
        Some(t @ Transfer::Stalled { bytes }) if t.frozen() => (S::Fail, "bytes.frozen", *bytes),
        Some(Transfer::Stalled { bytes }) => (S::Warn, "bytes.stalled", *bytes),
        Some(Transfer::NoData) => (S::Warn, "bytes.noData", 0),
        Some(Transfer::Failed { bytes, .. }) => (S::Warn, "bytes.failed", *bytes),
    };
    let mut s = step(StepKind::Bytes, status, key);
    s.detail = s.detail.arg("kb", kib(got));
    s
}

/// QUIC on 443 and STUN on other ports, said apart: a QUIC-only cut is not a UDP block.
fn udp(f: &Facts) -> Step {
    use Probes as P;
    use StepStatus as S;
    let (status, key) = match (probes(&f.quic), probes(&f.stun)) {
        (P::Answered, P::Answered) => (S::Ok, "udp.ok"),
        (P::Silent, P::Silent) => (S::Fail, "udp.blocked"),
        (P::Silent, P::Answered) => (S::Warn, "udp.quicCut"),
        (P::Answered, P::Silent) => (S::Warn, "udp.quicOnly"),
        (P::NotRun, P::NotRun) => (S::NotRun, "udp.notRun"),
        _ => (S::Warn, "udp.unclear"),
    };
    step(StepKind::Udp, status, key)
}

fn servers(f: &Facts) -> Step {
    let banned = f.banned_servers();
    let answered = f.servers.iter().filter(|r| r.tcp == Seen::Answered).count();
    let status = if banned > 0 {
        StepStatus::Fail
    } else if answered > 0 {
        StepStatus::Ok
    } else if f.servers.iter().all(|r| r.tcp == Seen::NotRun) {
        StepStatus::NotRun
    } else {
        StepStatus::Warn
    };
    let mut s = step(StepKind::Servers, status, "servers");
    s.detail = s
        .detail
        .arg("banned", banned)
        .arg("answered", answered)
        .arg("total", f.servers.len());
    s
}
