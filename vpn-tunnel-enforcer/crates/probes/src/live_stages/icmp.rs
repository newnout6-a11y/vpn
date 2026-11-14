//! ICMP stages over `vpnte_winnet::icmp`: traceroute (TTL 1..=8 fan-out, about one second
//! instead of tracert's 9.6 s worst case) and path-MTU discovery with the DF bit (B-12, B-13).
use std::future::Future;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::Instant;

use futures_util::stream::{FuturesUnordered, StreamExt};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_winnet::icmp::{self, EchoReply, EchoRequest, EchoStatus, IcmpError};

use super::{
    CANCELLED, NotCheckedReason, ProbePath, ProbeRoute, Text, Timed, TimedStatus, elapsed_ms,
    timeouts,
};

/// Hops probed by the traceroute.
pub const MAX_HOPS: u8 = 8;

/// Traceroute result (`route` in the row).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteTrace {
    #[serde(flatten)]
    pub timed: Timed,
    /// Number of hop lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hops: Option<u32>,
    /// An echo reply came from the target itself (never inferred from anything else).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reached_target: Option<bool>,
    /// Every probe got its answer or timeout (false after a cancel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_finished: Option<bool>,
    /// One line per hop in the sanitised tracert form: `3 14 ms 10.0.0.1`, `4 * Request timed out.`
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hop_details: Vec<String>,
    /// `icmp` (native) or `tracert` (imported rows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_method: Option<String>,
}

/// Traces the path to `dst` with one echo per TTL, all sent at once, 1 s each.
pub async fn trace_route(dst: IpAddr, path: &ProbePath, cancel: &CancellationToken) -> RouteTrace {
    let src = path.source_for(dst);
    trace_with(dst, icmp_route(src), cancel, move |ttl| {
        icmp::echo(EchoRequest {
            src,
            ttl,
            timeout: timeouts::TRACE_HOP,
            ..EchoRequest::new(dst)
        })
    })
    .await
}

/// ICMP is pinned by its source address: without a physical address of the target's family the
/// echo follows the OS route, and the row says so.
fn icmp_route(src: Option<IpAddr>) -> ProbeRoute {
    if src.is_some() {
        ProbeRoute::Physical
    } else {
        ProbeRoute::Os
    }
}

async fn trace_with<F, Fut>(
    dst: IpAddr,
    route: ProbeRoute,
    cancel: &CancellationToken,
    echo: F,
) -> RouteTrace
where
    F: Fn(u8) -> Fut,
    Fut: Future<Output = Result<EchoReply, IcmpError>>,
{
    if cancel.is_cancelled() {
        return RouteTrace {
            timed: Timed::cancelled(),
            ..RouteTrace::default()
        };
    }
    let start = Instant::now();
    let mut pending: FuturesUnordered<_> = (1..=MAX_HOPS)
        .map(|ttl| {
            let probe = echo(ttl);
            async move { (ttl, probe.await) }
        })
        .collect();
    let mut answers: Vec<(u8, Result<EchoReply, IcmpError>)> = Vec::new();
    let finished = loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break false,
            next = pending.next() => match next {
                Some(answer) => answers.push(answer),
                None => break true,
            },
        }
    };
    drop(pending);
    answers.sort_by_key(|(ttl, _)| *ttl);
    let reached_at = answers.iter().find_map(|(ttl, r)| match r {
        Ok(EchoReply {
            status: EchoStatus::Success,
            from: Some(from),
            ..
        }) if *from == dst => Some(*ttl),
        _ => None,
    });
    let last = reached_at.unwrap_or(MAX_HOPS);
    let lines: Vec<String> = answers
        .iter()
        .filter(|(ttl, _)| *ttl <= last)
        .filter_map(|(ttl, r)| r.as_ref().ok().map(|reply| hop_line(*ttl, reply)))
        .collect();
    let os_error = answers
        .iter()
        .find_map(|(_, r)| r.as_ref().err().map(ToString::to_string));
    let timed = match (finished, lines.is_empty(), os_error) {
        (false, _, _) => Timed {
            route: Some(route),
            duration_ms: elapsed_ms(start),
            ..Timed::cancelled()
        },
        (true, true, Some(error)) => {
            Timed::done(TimedStatus::Error, elapsed_ms(start), Some(error), route)
        }
        _ => Timed::done(TimedStatus::Ok, elapsed_ms(start), None, route),
    };
    RouteTrace {
        timed,
        hops: u32::try_from(lines.len()).ok().filter(|n| *n > 0),
        reached_target: Some(reached_at.is_some()),
        command_finished: Some(finished),
        hop_details: lines,
        route_method: Some("icmp".into()),
    }
}

/// One hop in the sanitised tracert form.
fn hop_line(ttl: u8, reply: &EchoReply) -> String {
    let rtt = match reply.rtt_ms {
        Some(0) | None => "<1".to_owned(),
        Some(ms) => ms.to_string(),
    };
    match (reply.status, reply.from) {
        (EchoStatus::TimedOut, _) | (_, None) => format!("{ttl} * Request timed out."),
        (EchoStatus::Success | EchoStatus::TtlExpired, Some(from)) => {
            format!("{ttl} {rtt} ms {from}")
        }
        (EchoStatus::Unreachable, Some(from)) => format!("{ttl} {from} Destination unreachable."),
        (_, Some(from)) => format!("{ttl} {rtt} ms {from} (unexpected reply)"),
    }
}

/// Cleans an imported tracert hop line (Russian `мс`, OEM-codepage mojibake, localized timeout)
/// into the form new rows use. For legacy `hopDetails` only.
pub fn sanitize_hop_line(line: &str) -> String {
    static RTT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)([<>]?\s*\d+)\s*(?:мс|ms|\x{FFFD}+)").expect("valid regex")
    });
    static ROGUE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\x{FFFD}+").expect("valid regex"));
    static TIMEOUT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)Превышен интервал ожидания для запроса\.?").expect("valid regex")
    });
    static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t]+").expect("valid regex"));
    let line = RTT.replace_all(line, "$1 ms");
    let line = ROGUE.replace_all(&line, "");
    let line = TIMEOUT.replace_all(&line, "Request timed out.");
    SPACES.replace_all(&line, " ").trim().to_owned()
}

/// PMTU verdict vocabulary of the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PmtuStatus {
    /// The accepted / too-big boundary is within 8 bytes.
    Ok,
    LowerBound,
    BlackholeSuspected,
    IcmpBlocked,
    Skipped,
    #[default]
    NotChecked,
}

/// How the PMTU figure was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PmtuMethod {
    IcmpDf,
    InterfaceNlmtu,
    #[default]
    Fallback,
}

/// Path-MTU result (`pmtu` in the row). Sizes are whole IP packets (payload + 28 / 48 bytes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pmtu {
    pub status: PmtuStatus,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub destination: String,
    /// 4 or 6.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface_alias: Option<String>,
    #[serde(default)]
    pub method: PmtuMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_tested: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tested: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ProbeRoute>,
}

/// DF payload ladders (old PowerShell script): IPv4 tops at 1472 + 28 = 1500, IPv6 at 1452 + 48.
pub const LADDER_V4: [u16; 7] = [1472, 1464, 1440, 1400, 1360, 1280, 1252];
/// IPv6 ladder: 1452 + 48 = 1500.
pub const LADDER_V6: [u16; 7] = [1452, 1444, 1420, 1380, 1340, 1260, 1232];

/// Final outcome of one ladder rung (a timeout is retried once before it counts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RungOutcome {
    Accepted,
    TooBig,
    TimedOut,
    Other,
}

/// What the ICMP layer saw; `None` in [`classify_pmtu`] = the ICMP layer itself failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmtuObservation {
    /// The 32-byte control ping was answered.
    pub control_ok: bool,
    pub rungs: Vec<(u16, RungOutcome)>,
}

/// Verdict fields of a [`Pmtu`] (status, method, sizes, explanation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PmtuVerdict {
    pub status: PmtuStatus,
    pub method: PmtuMethod,
    pub pmtu: Option<u32>,
    pub min_tested: Option<u32>,
    pub max_tested: Option<u32>,
    pub detail: Msg,
}

fn msg(name: &str) -> Msg {
    Msg::new(format!("probes.liveStages.pmtu.{name}"))
}

/// Classifies a ladder run (§3.19) with the B-12 rule: some rung accepted, every larger rung
/// silent twice and no PacketTooBig at all = blackhole suspected.
pub fn classify_pmtu(v6: bool, obs: Option<&PmtuObservation>, if_mtu: Option<u32>) -> PmtuVerdict {
    use PmtuStatus as S;
    let overhead: u32 = if v6 { 48 } else { 28 };
    let top = u32::from(if v6 { LADDER_V6[0] } else { LADDER_V4[0] });
    let verdict = |status, method, pmtu, min_tested, max_tested, detail| PmtuVerdict {
        status,
        method,
        pmtu,
        min_tested,
        max_tested,
        detail,
    };
    let iface_method = if if_mtu.is_some() {
        PmtuMethod::InterfaceNlmtu
    } else {
        PmtuMethod::Fallback
    };
    let interface_only = || match if_mtu {
        Some(mtu) => verdict(
            S::LowerBound,
            iface_method,
            Some(mtu),
            None,
            None,
            msg("interfaceOnly").arg("mtu", mtu),
        ),
        None => verdict(
            S::Skipped,
            iface_method,
            None,
            None,
            None,
            msg("undetermined"),
        ),
    };
    let Some(obs) = obs else {
        return interface_only();
    };
    if !obs.control_ok {
        return verdict(
            S::IcmpBlocked,
            iface_method,
            if_mtu,
            None,
            None,
            msg("icmpBlocked"),
        );
    }
    let sizes = |want: RungOutcome| {
        obs.rungs
            .iter()
            .filter(move |(_, r)| *r == want)
            .map(|(p, _)| u32::from(*p))
    };
    let (timeouts, too_big) = (
        sizes(RungOutcome::TimedOut).count(),
        sizes(RungOutcome::TooBig).count(),
    );
    let Some(largest) = sizes(RungOutcome::Accepted).max() else {
        if timeouts > 0 && too_big == 0 {
            return verdict(
                S::BlackholeSuspected,
                iface_method,
                if_mtu,
                None,
                None,
                msg("blackhole"),
            );
        }
        return interface_only();
    };
    let total = largest + overhead;
    if largest >= top {
        let detail = msg("atLeast").arg("top", largest);
        return verdict(
            S::LowerBound,
            PmtuMethod::IcmpDf,
            Some(total),
            Some(total),
            None,
            detail,
        );
    }
    let mut larger = obs
        .rungs
        .iter()
        .filter(|(p, _)| u32::from(*p) > largest)
        .peekable();
    let silent_above = larger.peek().is_some() && larger.all(|(_, r)| *r == RungOutcome::TimedOut);
    if too_big == 0 && silent_above {
        return verdict(
            S::BlackholeSuspected,
            PmtuMethod::IcmpDf,
            Some(total),
            Some(total),
            None,
            msg("blackhole"),
        );
    }
    let smallest_too_big = sizes(RungOutcome::TooBig).filter(|s| *s > largest).min();
    let exact = smallest_too_big.is_some_and(|s| s - largest <= 8) && timeouts == 0;
    let max = smallest_too_big.map_or(top + overhead, |s| s + overhead);
    let (status, detail) = if exact {
        (
            S::Ok,
            msg("confirmed").arg("pmtu", total).arg("rejected", max),
        )
    } else {
        (
            S::LowerBound,
            msg("range").arg("pmtu", total).arg("max", max),
        )
    };
    verdict(
        status,
        PmtuMethod::IcmpDf,
        Some(total),
        Some(total),
        Some(max),
        detail,
    )
}

/// Path MTU to `dst` with DF pings (TTL 64) from the probe path. `iface` = (LUID, alias) of the
/// interface the probes leave through: its MTU is the fallback figure.
pub async fn probe_pmtu(
    dst: IpAddr,
    path: &ProbePath,
    iface: Option<(u64, &str)>,
    cancel: &CancellationToken,
) -> Pmtu {
    let family = vpnte_winnet::adapters::Family::of(dst);
    let if_mtu = iface.and_then(|(luid, _)| {
        vpnte_winnet::adapters::interface_mtu(luid, family)
            .ok()
            .flatten()
    });
    let alias = iface.map(|(_, alias)| alias.to_owned());
    let src = path.source_for(dst);
    let echo = move |payload, timeout| {
        icmp::echo(EchoRequest {
            src,
            ttl: 64,
            df: true,
            payload,
            timeout,
            ..EchoRequest::new(dst)
        })
    };
    pmtu_with(dst, if_mtu, alias, icmp_route(src), cancel, echo).await
}

async fn pmtu_with<F, Fut>(
    dst: IpAddr,
    if_mtu: Option<u32>,
    alias: Option<String>,
    route: ProbeRoute,
    cancel: &CancellationToken,
    echo: F,
) -> Pmtu
where
    F: Fn(u16, std::time::Duration) -> Fut,
    Fut: Future<Output = Result<EchoReply, IcmpError>>,
{
    let base = Pmtu {
        destination: dst.to_string(),
        family: Some(if dst.is_ipv6() { 6 } else { 4 }),
        interface_alias: alias,
        route: Some(route),
        ..Pmtu::default()
    };
    if cancel.is_cancelled() {
        return Pmtu {
            status: PmtuStatus::Skipped,
            error: Some(CANCELLED.into()),
            ..base
        };
    }
    let start = Instant::now();
    let ladder: &[u16] = if dst.is_ipv6() {
        &LADDER_V6
    } else {
        &LADDER_V4
    };
    let observed = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let ms = elapsed_ms(start);
            return Pmtu { status: PmtuStatus::Skipped, duration_ms: ms, error: Some(CANCELLED.into()), ..base };
        }
        o = observe(&echo, ladder) => o,
    };
    let v = classify_pmtu(dst.is_ipv6(), observed.as_ref().ok(), if_mtu);
    Pmtu {
        status: v.status,
        duration_ms: elapsed_ms(start),
        method: v.method,
        pmtu: v.pmtu,
        min_tested: v.min_tested,
        max_tested: v.max_tested,
        detail: Some(v.detail.into()),
        error: observed.err(),
        ..base
    }
}

/// Control ping, then every rung at once; rungs that stayed silent are asked once more.
async fn observe<F, Fut>(echo: &F, ladder: &[u16]) -> Result<PmtuObservation, String>
where
    F: Fn(u16, std::time::Duration) -> Fut,
    Fut: Future<Output = Result<EchoReply, IcmpError>>,
{
    let control = echo(32, timeouts::PMTU_CONTROL)
        .await
        .map_err(|e| e.to_string())?;
    if control.status != EchoStatus::Success {
        return Ok(PmtuObservation {
            control_ok: false,
            rungs: Vec::new(),
        });
    }
    let outcome = |r: Result<EchoReply, IcmpError>| match r.map(|r| r.status) {
        Ok(EchoStatus::Success) => RungOutcome::Accepted,
        Ok(EchoStatus::PacketTooBig) => RungOutcome::TooBig,
        Ok(EchoStatus::TimedOut) => RungOutcome::TimedOut,
        _ => RungOutcome::Other,
    };
    let send_all = |sizes: Vec<u16>| {
        futures_util::future::join_all(
            sizes
                .into_iter()
                .map(|p| async move { (p, outcome(echo(p, timeouts::PMTU_RUNG).await)) }),
        )
    };
    let mut rungs = send_all(ladder.to_vec()).await;
    let silent: Vec<u16> = rungs
        .iter()
        .filter(|(_, o)| *o == RungOutcome::TimedOut)
        .map(|(p, _)| *p)
        .collect();
    for (p, again) in send_all(silent).await {
        if let Some(rung) = rungs.iter_mut().find(|(q, _)| *q == p) {
            rung.1 = again;
        }
    }
    Ok(PmtuObservation {
        control_ok: true,
        rungs,
    })
}

#[cfg(test)]
mod tests;
