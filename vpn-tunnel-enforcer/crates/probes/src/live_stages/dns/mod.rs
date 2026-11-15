//! DNS stage: system resolver (A + AAAA, CNAME chain, TTL, PTR) and, in extended mode for public
//! names, a Google / Cloudflare DoH comparison. DoH answers are evidence only: they never feed
//! `a` / `aaaa` or the status (a poisoned or split-horizon system DNS is shown, not "fixed").
mod doh;
mod system;

use std::future::Future;
use std::net::IpAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;

use super::target::is_public_fqdn;
use super::{CANCELLED, Text, Timed, TimedStatus, elapsed_ms, timeouts};

pub use doh::classify_doh;
use doh::compare_doh;
#[cfg(test)]
pub(crate) use doh::{google_vs_cloudflare, system_vs_doh};
use system::{
    NO_RECORDS, QUERY_TIMEOUT, SYSTEM, cname_chain, done, literal, reverse_names, system_record,
};

/// Record type of a [`DnsRecordEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "CNAME")]
    Cname,
    #[serde(rename = "PTR")]
    Ptr,
}

/// Which path answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsTransport {
    System,
    Doh,
}

/// One answer as stored in the row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsRecordEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: DnsRecordType,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// `system`, `google-doh` or `cloudflare-doh` (the UI names them).
    pub resolver_id: String,
    pub transport: DnsTransport,
}

/// Overall status of one resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResolverStatus {
    Ok,
    Partial,
    Error,
    Timeout,
    Skipped,
}

/// Outcome of one record family at one resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FamilyStatus {
    Ok,
    Nxdomain,
    Servfail,
    Refused,
    Timeout,
    Error,
}

/// One resolver's view (`dns.resolvers[]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsResolverComparison {
    pub resolver_id: String,
    pub status: ResolverStatus,
    #[serde(default)]
    pub duration_ms: u64,
    /// DNSSEC-validated (`AD` flag of a DoH answer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticated_data: Option<bool>,
    #[serde(default)]
    pub records: Vec<DnsRecordEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a_status: Option<FamilyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaaa_status: Option<FamilyStatus>,
}

/// Per-family durations of the system queries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsTimings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aaaa_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cname_ms: Option<u64>,
}

/// DNS stage result (`dns` in the row). `a` / `aaaa` come from the system resolver only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsDiagnostics {
    #[serde(flatten)]
    pub timed: Timed,
    #[serde(default)]
    pub a: Vec<String>,
    #[serde(default)]
    pub aaaa: Vec<String>,
    #[serde(default)]
    pub cname_chain: Vec<String>,
    /// Smallest TTL of the system address answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<DnsRecordEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<DnsResolverComparison>,
    /// System vs DoH / Google vs Cloudflare disagreements (informative, not a verdict).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discrepancies: Vec<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timings: Option<DnsTimings>,
}

impl DnsDiagnostics {
    /// The address the other stages probe: first A, else first AAAA.
    pub fn primary_ip(&self) -> Option<IpAddr> {
        self.a.iter().chain(&self.aaaa).find_map(|s| s.parse().ok())
    }
}

/// One record of a system answer section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Owner name, lowercase, no trailing dot.
    pub name: String,
    pub data: AnswerData,
    pub ttl: u32,
}

/// Payload of an [`Answer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerData {
    Addr(IpAddr),
    /// Alias target, lowercase, no trailing dot.
    Cname(String),
}

/// Public DoH resolvers of the comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DohResolver {
    Google,
    Cloudflare,
}

impl DohResolver {
    /// Row id of the resolver.
    pub fn id(self) -> &'static str {
        match self {
            DohResolver::Google => "google-doh",
            DohResolver::Cloudflare => "cloudflare-doh",
        }
    }
    /// JSON API endpoint (`?name=…&type=A|AAAA`, `Accept: application/dns-json`).
    pub fn url(self) -> &'static str {
        match self {
            DohResolver::Google => "https://dns.google/resolve",
            DohResolver::Cloudflare => "https://cloudflare-dns.com/dns-query",
        }
    }
}

/// UI label of a resolver id stored in a row (`system`, `google-doh`, `cloudflare-doh`).
pub fn resolver_label(id: &str) -> Text {
    let key = match id {
        SYSTEM => "probes.liveStages.dns.resolver.system",
        "google-doh" => "probes.liveStages.dns.resolver.googleDoh",
        "cloudflare-doh" => "probes.liveStages.dns.resolver.cloudflareDoh",
        other => return Text::Legacy(other.to_owned()),
    };
    Text::Msg(Msg::new(key))
}

/// The fields of a DoH JSON answer the comparison reads.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct DohResponse {
    #[serde(rename = "Status")]
    pub status: Option<i64>,
    #[serde(rename = "AD")]
    pub ad: Option<bool>,
    #[serde(rename = "TC")]
    pub tc: Option<bool>,
    #[serde(rename = "Answer", default)]
    pub answer: Vec<DohAnswer>,
}

/// One `Answer[]` entry of a DoH JSON answer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DohAnswer {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: u16,
    #[serde(rename = "TTL")]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub data: String,
}

/// Where the DNS stage gets its answers ([`super::SystemDns`] in production, fakes in tests).
/// Errors are technical text; the stage applies its own timeouts.
pub trait DnsBackend: Sync {
    /// System resolver query for A (`v6 == false`) or AAAA: the answer section incl. CNAMEs.
    fn lookup(
        &self,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<Vec<Answer>, String>> + Send;
    /// PTR names of an address.
    fn reverse(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, String>> + Send;
    /// One DoH JSON query (A or AAAA) over the OS route.
    fn doh(
        &self,
        resolver: DohResolver,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<DohResponse, String>> + Send;
}

/// Runs the DNS stage for `host` (a name or an IP literal). Returns the diagnostics and the
/// reverse names of the resolved addresses (`reverseDns` in the row).
pub async fn probe_dns<B: DnsBackend>(
    backend: &B,
    host: &str,
    extended: bool,
    cancel: &CancellationToken,
) -> (DnsDiagnostics, Vec<String>) {
    let start = Instant::now();
    let host = host.trim().trim_end_matches('.');
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return literal(backend, ip, cancel, start).await;
    }
    if cancel.is_cancelled() {
        return (
            DnsDiagnostics {
                timed: Timed::cancelled(),
                ..DnsDiagnostics::default()
            },
            Vec::new(),
        );
    }
    let query = |v6: bool| async move {
        let t = Instant::now();
        let r = tokio::time::timeout(timeouts::DNS_QUERY, backend.lookup(host, v6))
            .await
            .unwrap_or_else(|_| Err(QUERY_TIMEOUT.into()));
        (r, elapsed_ms(t))
    };
    // A cancel mid-query discards whatever arrives later: no addresses, `error: Cancelled`.
    let ((a_res, a_ms), (aaaa_res, aaaa_ms)) = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            let timed = done(TimedStatus::Error, start, Some(CANCELLED.into()));
            return (DnsDiagnostics { timed, ..DnsDiagnostics::default() }, Vec::new());
        }
        r = async { tokio::join!(query(false), query(true)) } => r,
    };
    let mut dns = DnsDiagnostics {
        timings: Some(DnsTimings {
            a_ms: Some(a_ms),
            aaaa_ms: Some(aaaa_ms),
            cname_ms: None,
        }),
        ..DnsDiagnostics::default()
    };
    let mut aliases: Vec<&Answer> = Vec::new();
    for (res, v6) in [(&a_res, false), (&aaaa_res, true)] {
        for ans in res.iter().flatten() {
            match &ans.data {
                AnswerData::Addr(ip) if ip.is_ipv6() == v6 => {
                    let kind = if v6 {
                        DnsRecordType::Aaaa
                    } else {
                        DnsRecordType::A
                    };
                    dns.records
                        .push(system_record(host, kind, ip.to_string(), Some(ans.ttl)));
                    dns.ttl = Some(dns.ttl.map_or(ans.ttl, |t| t.min(ans.ttl)));
                    let list = if v6 { &mut dns.aaaa } else { &mut dns.a };
                    if !list.contains(&ip.to_string()) {
                        list.push(ip.to_string());
                    }
                }
                AnswerData::Cname(_) => aliases.push(ans),
                AnswerData::Addr(_) => {}
            }
        }
    }
    for (name, target, ttl) in cname_chain(host, &aliases) {
        dns.cname_chain.push(target.clone());
        dns.records.push(system_record(
            &name,
            DnsRecordType::Cname,
            target,
            Some(ttl),
        ));
    }
    // AAAA failures are normal (IPv4-only names); only the A error explains an empty answer.
    let primary_error = a_res.err();
    let has_records = !dns.a.is_empty() || !dns.aaaa.is_empty();
    dns.resolvers.push(DnsResolverComparison {
        resolver_id: SYSTEM.into(),
        status: if has_records {
            ResolverStatus::Ok
        } else {
            ResolverStatus::Error
        },
        duration_ms: a_ms,
        authenticated_data: None,
        records: dns.records.clone(),
        truncated: None,
        rcode: None,
        error: if has_records {
            None
        } else {
            primary_error.clone()
        },
        a_status: None,
        aaaa_status: None,
    });
    if extended && is_public_fqdn(host) {
        compare_doh(backend, host, &mut dns, cancel).await;
    }
    let reverse = reverse_names(backend, &dns, cancel).await;
    let error = (!has_records).then(|| primary_error.unwrap_or_else(|| NO_RECORDS.into()));
    let status = if has_records {
        TimedStatus::Ok
    } else {
        TimedStatus::Error
    };
    dns.timed = done(status, start, error);
    (dns, reverse)
}

#[cfg(test)]
mod tests;
