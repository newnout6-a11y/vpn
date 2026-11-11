//! The system-resolver side of the stage: records, CNAME chain, literal targets, PTR names.
use std::net::IpAddr;
use std::time::Instant;

use tokio_util::sync::CancellationToken;

use super::{
    Answer, AnswerData, DnsBackend, DnsDiagnostics, DnsRecordEntry, DnsRecordType,
    DnsResolverComparison, DnsTransport, ResolverStatus,
};
use crate::live_stages::{ProbeRoute, Timed, TimedStatus, elapsed_ms, timeouts};

pub(super) const SYSTEM: &str = "system";
pub(super) const NO_RECORDS: &str = "DNS lookup failed: no records";
pub(super) const QUERY_TIMEOUT: &str = "DNS query timeout";
/// CNAME hops followed at most.
const MAX_CNAME_DEPTH: usize = 5;

pub(super) fn system_record(
    name: &str,
    kind: DnsRecordType,
    value: String,
    ttl: Option<u32>,
) -> DnsRecordEntry {
    DnsRecordEntry {
        name: name.to_owned(),
        kind,
        value,
        ttl,
        resolver_id: SYSTEM.into(),
        transport: DnsTransport::System,
    }
}

pub(super) fn done(status: TimedStatus, start: Instant, error: Option<String>) -> Timed {
    Timed::done(status, elapsed_ms(start), error, ProbeRoute::Os)
}

/// Follows CNAMEs from `host` (at most 5 hops, loops stop): (owner, target, ttl) per hop.
pub(super) fn cname_chain(host: &str, aliases: &[&Answer]) -> Vec<(String, String, u32)> {
    let mut chain: Vec<(String, String, u32)> = Vec::new();
    let mut current = host.to_ascii_lowercase();
    let mut seen = vec![current.clone()];
    while chain.len() < MAX_CNAME_DEPTH {
        let next = aliases.iter().find_map(|a| match &a.data {
            AnswerData::Cname(target) if a.name.eq_ignore_ascii_case(&current) => {
                Some((target.to_ascii_lowercase(), a.ttl))
            }
            _ => None,
        });
        let Some((target, ttl)) = next.filter(|(t, _)| !t.is_empty() && !seen.contains(t)) else {
            break;
        };
        seen.push(target.clone());
        chain.push((current, target.clone(), ttl));
        current = target;
    }
    chain
}

/// An IP literal skips forward DNS: one synthetic system record, PTR only (2.5 s, errors ignored).
pub(super) async fn literal<B: DnsBackend>(
    backend: &B,
    ip: IpAddr,
    cancel: &CancellationToken,
    start: Instant,
) -> (DnsDiagnostics, Vec<String>) {
    let reverse = if cancel.is_cancelled() {
        Vec::new()
    } else {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Vec::new(),
            r = tokio::time::timeout(timeouts::DNS_QUERY, backend.reverse(ip)) => {
                r.ok().and_then(Result::ok).unwrap_or_default()
            }
        }
    };
    let kind = if ip.is_ipv6() {
        DnsRecordType::Aaaa
    } else {
        DnsRecordType::A
    };
    let record = system_record(&ip.to_string(), kind, ip.to_string(), None);
    let (a, aaaa) = if ip.is_ipv6() {
        (Vec::new(), vec![ip.to_string()])
    } else {
        (vec![ip.to_string()], Vec::new())
    };
    let system = DnsResolverComparison {
        resolver_id: SYSTEM.into(),
        status: ResolverStatus::Ok,
        duration_ms: 0,
        authenticated_data: None,
        records: vec![record.clone()],
        truncated: None,
        rcode: None,
        error: None,
        a_status: None,
        aaaa_status: None,
    };
    let dns = DnsDiagnostics {
        timed: done(TimedStatus::Ok, start, None),
        a,
        aaaa,
        records: vec![record],
        resolvers: vec![system],
        ..DnsDiagnostics::default()
    };
    (dns, dedup(reverse))
}

/// PTR names of every resolved address, in parallel, 1.2 s each, errors ignored.
pub(super) async fn reverse_names<B: DnsBackend>(
    backend: &B,
    dns: &DnsDiagnostics,
    cancel: &CancellationToken,
) -> Vec<String> {
    let ips: Vec<IpAddr> = dns
        .a
        .iter()
        .chain(&dns.aaaa)
        .filter_map(|s| s.parse().ok())
        .collect();
    if ips.is_empty() || cancel.is_cancelled() {
        return Vec::new();
    }
    let lookups = futures_util::future::join_all(ips.into_iter().map(|ip| async move {
        tokio::time::timeout(timeouts::DNS_PTR, backend.reverse(ip))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    }));
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Vec::new(),
        names = lookups => dedup(names.into_iter().flatten().collect()),
    }
}

/// Drops repeats and empties, keeping the first occurrence.
pub(super) fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
    }
    out
}
