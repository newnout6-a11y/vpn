//! The DoH comparison (extended mode, public names): Google and Cloudflare answers per family
//! against the system resolver's; evidence only.
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;

use super::system::dedup;
use super::{
    DnsBackend, DnsDiagnostics, DnsRecordEntry, DnsRecordType, DnsResolverComparison, DnsTransport,
    DohResolver, DohResponse, FamilyStatus, ResolverStatus,
};
use crate::live_stages::{elapsed_ms, timeouts};

/// Classifies one family's DoH outcome: (status, error text, records).
fn doh_family(
    resolver: DohResolver,
    response: &Result<DohResponse, String>,
    v6: bool,
) -> (FamilyStatus, Option<String>, Vec<DnsRecordEntry>) {
    let family = if v6 { "AAAA" } else { "A" };
    let resp = match response {
        Ok(resp) => resp,
        Err(e) if e.to_ascii_lowercase().contains("timeout") => {
            return (FamilyStatus::Timeout, Some(e.clone()), Vec::new());
        }
        Err(e) if e.is_empty() => {
            return (
                FamilyStatus::Error,
                Some(format!("{family} lookup failed")),
                Vec::new(),
            );
        }
        Err(e) => return (FamilyStatus::Error, Some(e.clone()), Vec::new()),
    };
    let rcode = resp.status.unwrap_or(0);
    if rcode != 0 {
        let (text, status) = match rcode {
            3 => ("NXDOMAIN".to_owned(), FamilyStatus::Nxdomain),
            2 => ("SERVFAIL".to_owned(), FamilyStatus::Servfail),
            5 => ("REFUSED".to_owned(), FamilyStatus::Refused),
            n => (format!("RCODE_{n}"), FamilyStatus::Error),
        };
        return (status, Some(format!("DNS {family}: {text}")), Vec::new());
    }
    let mut records: Vec<DnsRecordEntry> = Vec::new();
    for ans in &resp.answer {
        let name = ans.name.trim_end_matches('.').to_owned();
        let value = ans.data.trim_end_matches('.').to_owned();
        let kind = match (v6, ans.rtype) {
            (false, 1) if value.parse::<Ipv4Addr>().is_ok() => DnsRecordType::A,
            (false, 5) => DnsRecordType::Cname,
            (true, 28) if value.parse::<Ipv6Addr>().is_ok() => DnsRecordType::Aaaa,
            _ => continue,
        };
        if records.iter().any(|r| r.kind == kind && r.value == value) {
            continue;
        }
        records.push(DnsRecordEntry {
            name,
            kind,
            value,
            ttl: ans.ttl,
            resolver_id: resolver.id().into(),
            transport: DnsTransport::Doh,
        });
    }
    (FamilyStatus::Ok, None, records)
}

/// One DoH resolver's comparison entry from its A and AAAA outcomes (old queryDoH rules).
pub fn classify_doh(
    resolver: DohResolver,
    a: Result<DohResponse, String>,
    aaaa: Result<DohResponse, String>,
    duration_ms: u64,
) -> DnsResolverComparison {
    let (a_status, a_error, mut records) = doh_family(resolver, &a, false);
    let (aaaa_status, aaaa_error, more) = doh_family(resolver, &aaaa, true);
    records.extend(more);
    let responses = [a.as_ref().ok(), aaaa.as_ref().ok()];
    let rcode = responses.iter().flatten().find_map(|r| r.status);
    let ad = responses.iter().flatten().find_map(|r| r.ad);
    let tc = responses.iter().flatten().find_map(|r| r.tc);
    let (a_ok, aaaa_ok) = (
        a_status == FamilyStatus::Ok,
        aaaa_status == FamilyStatus::Ok,
    );
    let errors: Vec<String> = [a_error, aaaa_error].into_iter().flatten().collect();
    let (status, error) = if a_ok && aaaa_ok && !records.is_empty() {
        (ResolverStatus::Ok, None)
    } else if (a_ok || aaaa_ok) && !records.is_empty() {
        (ResolverStatus::Partial, errors.first().cloned())
    } else if errors.is_empty() {
        (
            ResolverStatus::Error,
            Some("No records returned".to_owned()),
        )
    } else {
        (ResolverStatus::Error, Some(errors.join("; ")))
    };
    DnsResolverComparison {
        resolver_id: resolver.id().into(),
        status,
        duration_ms,
        authenticated_data: ad,
        records,
        truncated: tc,
        rcode,
        error,
        a_status: Some(a_status),
        aaaa_status: Some(aaaa_status),
    }
}

/// Google and Cloudflare DoH in parallel (A + AAAA each, 3 s per request) and the discrepancies.
pub(super) async fn compare_doh<B: DnsBackend>(
    backend: &B,
    host: &str,
    dns: &mut DnsDiagnostics,
    cancel: &CancellationToken,
) {
    let one = |resolver: DohResolver| async move {
        let t = Instant::now();
        let query = |v6: bool| async move {
            tokio::time::timeout(timeouts::DOH, backend.doh(resolver, host, v6))
                .await
                .unwrap_or_else(|_| Err("DoH request timeout".into()))
        };
        let (a, aaaa) = tokio::join!(query(false), query(true));
        classify_doh(resolver, a, aaaa, elapsed_ms(t))
    };
    let (google, cloudflare) = tokio::select! {
        biased;
        _ = cancel.cancelled() => return,
        r = async { tokio::join!(one(DohResolver::Google), one(DohResolver::Cloudflare)) } => r,
    };
    let addrs = |records: &[DnsRecordEntry]| -> Vec<String> {
        records
            .iter()
            .filter(|r| matches!(r.kind, DnsRecordType::A | DnsRecordType::Aaaa))
            .map(|r| r.value.clone())
            .collect()
    };
    let system = addrs(&dns.records);
    let (g, c) = (addrs(&google.records), addrs(&cloudflare.records));
    let doh: Vec<String> = dedup(g.iter().chain(&c).cloned().collect());
    let disjoint = |x: &[String], y: &[String]| {
        !x.is_empty() && !y.is_empty() && !x.iter().any(|v| y.contains(v))
    };
    if disjoint(&system, &doh) {
        dns.discrepancies
            .push(system_vs_doh(&dedup(system), &doh).into());
    }
    if disjoint(&g, &c) {
        dns.discrepancies.push(google_vs_cloudflare(&g, &c).into());
    }
    for cmp in [google, cloudflare] {
        dns.records.extend(cmp.records.iter().cloned());
        dns.resolvers.push(cmp);
    }
}

/// "System DNS does not match public DoH" (address lists joined with `, `).
pub(crate) fn system_vs_doh(system: &[String], doh: &[String]) -> Msg {
    Msg::new("probes.liveStages.dns.systemVsDoh")
        .arg("system", system.join(", "))
        .arg("doh", doh.join(", "))
}

/// "Google DoH and Cloudflare DoH returned different addresses".
pub(crate) fn google_vs_cloudflare(google: &[String], cloudflare: &[String]) -> Msg {
    Msg::new("probes.liveStages.dns.googleVsCloudflare")
        .arg("google", google.join(", "))
        .arg("cloudflare", cloudflare.join(", "))
}
