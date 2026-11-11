//! DNS stage: system resolver (A + AAAA, CNAME chain, TTL, PTR) and, in extended mode for public
//! names, a Google / Cloudflare DoH comparison. DoH answers are evidence only: they never feed
//! `a` / `aaaa` or the status (a poisoned or split-horizon system DNS is shown, not "fixed").
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;

use super::target::is_public_fqdn;
use super::{CANCELLED, ProbeRoute, Text, Timed, TimedStatus, elapsed_ms, timeouts};

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

const SYSTEM: &str = "system";
const NO_RECORDS: &str = "DNS lookup failed: no records";
const QUERY_TIMEOUT: &str = "DNS query timeout";
/// CNAME hops followed at most.
const MAX_CNAME_DEPTH: usize = 5;

fn system_record(
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

fn done(status: TimedStatus, start: Instant, error: Option<String>) -> Timed {
    Timed::done(status, elapsed_ms(start), error, ProbeRoute::Os)
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

/// Follows CNAMEs from `host` (at most 5 hops, loops stop): (owner, target, ttl) per hop.
fn cname_chain(host: &str, aliases: &[&Answer]) -> Vec<(String, String, u32)> {
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
async fn literal<B: DnsBackend>(
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

/// Google and Cloudflare DoH in parallel (A + AAAA each, 3 s per request) and the discrepancies.
async fn compare_doh<B: DnsBackend>(
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

/// PTR names of every resolved address, in parallel, 1.2 s each, errors ignored.
async fn reverse_names<B: DnsBackend>(
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
fn dedup(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for item in items {
        if !item.is_empty() && !out.contains(&item) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use parking_lot::Mutex;

    use super::*;

    type Lookup = Result<Vec<Answer>, String>;

    /// Scripted backend; unknown names answer empty, `slow` names answer after 3 s.
    #[derive(Default)]
    struct Fake {
        a: HashMap<&'static str, Lookup>,
        aaaa: HashMap<&'static str, Lookup>,
        ptr: HashMap<IpAddr, Result<Vec<String>, String>>,
        doh: HashMap<(&'static str, bool), Result<DohResponse, String>>,
        slow: bool,
        calls: Mutex<Vec<String>>,
    }

    impl DnsBackend for Fake {
        fn lookup(&self, name: &str, v6: bool) -> impl Future<Output = Lookup> + Send {
            self.calls
                .lock()
                .push(format!("{} {name}", if v6 { "AAAA" } else { "A" }));
            let table = if v6 { &self.aaaa } else { &self.a };
            let answer = table.get(name).cloned().unwrap_or(Ok(Vec::new()));
            let slow = self.slow;
            async move {
                if slow {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                answer
            }
        }
        fn reverse(&self, ip: IpAddr) -> impl Future<Output = Result<Vec<String>, String>> + Send {
            self.calls.lock().push(format!("PTR {ip}"));
            let answer = self.ptr.get(&ip).cloned().unwrap_or(Ok(Vec::new()));
            async move { answer }
        }
        fn doh(
            &self,
            r: DohResolver,
            name: &str,
            v6: bool,
        ) -> impl Future<Output = Result<DohResponse, String>> + Send {
            self.calls
                .lock()
                .push(format!("DOH {} {name} {v6}", r.id()));
            let answer = self
                .doh
                .get(&(r.id(), v6))
                .cloned()
                .unwrap_or(Ok(DohResponse::default()));
            async move { answer }
        }
    }

    fn addr(name: &str, ip: &str, ttl: u32) -> Answer {
        Answer {
            name: name.into(),
            data: AnswerData::Addr(ip.parse().unwrap()),
            ttl,
        }
    }

    fn doh_ok(rtype: u16, values: &[&str]) -> Result<DohResponse, String> {
        let answer = values
            .iter()
            .map(|v| DohAnswer {
                name: "h.example.".into(),
                rtype,
                ttl: Some(300),
                data: (*v).into(),
            })
            .collect();
        Ok(DohResponse {
            status: Some(0),
            ad: Some(false),
            tc: Some(false),
            answer,
        })
    }

    /// AT-05-001: an IP literal gets PTR only, no forward queries (§7.1).
    #[tokio::test]
    async fn ip_literal_skips_forward_dns() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let fake = Fake {
            ptr: HashMap::from([(ip, Ok(vec!["node1.vpnprovider.net".into()]))]),
            ..Fake::default()
        };
        let (dns, reverse) = probe_dns(&fake, "1.2.3.4", true, &CancellationToken::new()).await;
        assert_eq!(dns.timed.status, TimedStatus::Ok);
        assert_eq!(
            (dns.a.clone(), dns.aaaa.len()),
            (vec!["1.2.3.4".to_owned()], 0)
        );
        assert_eq!(reverse, ["node1.vpnprovider.net"]);
        assert_eq!(fake.calls.lock().clone(), ["PTR 1.2.3.4"]);
        assert_eq!(dns.resolvers[0].resolver_id, "system");
        assert_eq!(dns.records[0].kind, DnsRecordType::A);
        // Pre-cancelled literal: still ok, but no PTR.
        let cancel = CancellationToken::new();
        cancel.cancel();
        let fake = Fake::default();
        let (dns, reverse) = probe_dns(&fake, "[2001:db8::1]", false, &cancel).await;
        assert_eq!(
            (dns.timed.status, dns.aaaa.clone()),
            (TimedStatus::Ok, vec!["2001:db8::1".to_owned()])
        );
        assert!(reverse.is_empty() && fake.calls.lock().is_empty());
    }

    /// AT-05-001: CNAME chain, min TTL, timings and the DoH comparison (§7.1).
    #[tokio::test]
    async fn resolves_with_cname_and_doh() {
        let host = "myvpn.example.com";
        let cname = Answer {
            name: host.into(),
            data: AnswerData::Cname("edge.cloudflare.com".into()),
            ttl: 300,
        };
        let fake = Fake {
            a: HashMap::from([(
                host,
                Ok(vec![
                    cname,
                    addr("edge.cloudflare.com", "104.21.5.10", 300),
                    addr("edge.cloudflare.com", "104.21.5.11", 120),
                ]),
            )]),
            aaaa: HashMap::from([(
                host,
                Ok(vec![addr("edge.cloudflare.com", "2606:4700::1", 300)]),
            )]),
            doh: HashMap::from([
                (("google-doh", false), doh_ok(1, &["104.21.5.10"])),
                (("cloudflare-doh", false), doh_ok(1, &["104.21.5.11"])),
            ]),
            ..Fake::default()
        };
        let (dns, _) = probe_dns(&fake, host, true, &CancellationToken::new()).await;
        assert_eq!(dns.timed.status, TimedStatus::Ok);
        assert_eq!(dns.a, ["104.21.5.10", "104.21.5.11"]);
        assert_eq!(dns.aaaa, ["2606:4700::1"]);
        assert_eq!(dns.cname_chain, ["edge.cloudflare.com"]);
        assert_eq!(dns.ttl, Some(120));
        assert!(dns.timings.as_ref().unwrap().a_ms.is_some());
        let ids: Vec<&str> = dns
            .resolvers
            .iter()
            .map(|r| r.resolver_id.as_str())
            .collect();
        assert_eq!(ids, ["system", "google-doh", "cloudflare-doh"]);
        assert!(dns.records.iter().any(|r| r.transport == DnsTransport::Doh));
        // Google and Cloudflare disagree with each other but each overlaps the system answer.
        assert_eq!(dns.discrepancies.len(), 1);
        assert_eq!(dns.primary_ip(), Some("104.21.5.10".parse().unwrap()));
    }

    /// AT-05-001: PTR NXDOMAIN leaves reverseDns empty; AAAA empty is fine (§7.1).
    #[tokio::test]
    async fn missing_ptr_is_not_an_error() {
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        let fake = Fake {
            a: HashMap::from([(
                "one.one.one.one",
                Ok(vec![addr("one.one.one.one", "1.1.1.1", 60)]),
            )]),
            ptr: HashMap::from([(ip, Err("ENOTFOUND".into()))]),
            ..Fake::default()
        };
        let (dns, reverse) =
            probe_dns(&fake, "one.one.one.one", false, &CancellationToken::new()).await;
        assert_eq!(dns.timed.status, TimedStatus::Ok);
        assert!(reverse.is_empty());
        assert!(
            !fake.calls.lock().iter().any(|c| c.starts_with("DOH")),
            "basic mode has no DoH"
        );
    }

    /// AT-00-003: pre-cancelled -> skipped, no resolver touched; cancel mid-query discards
    /// late answers (§7.1, §7.7).
    #[tokio::test]
    async fn cancellation() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let fake = Fake::default();
        let (dns, _) = probe_dns(&fake, "probe.example", true, &cancel).await;
        assert_eq!(dns.timed.status, TimedStatus::Skipped);
        assert!(dns.timed.error.as_deref().unwrap().contains("Cancelled"));
        assert!(fake.calls.lock().is_empty());

        let fake = Fake {
            slow: true,
            a: HashMap::from([("h.example", Ok(vec![addr("h.example", "192.0.2.7", 60)]))]),
            ..Fake::default()
        };
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            token.cancel();
        });
        let (dns, _) = probe_dns(&fake, "h.example", false, &cancel).await;
        assert_eq!(dns.timed.status, TimedStatus::Error);
        assert_eq!(dns.timed.error.as_deref(), Some(CANCELLED));
        assert!(dns.a.is_empty() && dns.aaaa.is_empty());
    }

    /// AT-00-003: answers after the 2.5 s query timeout are discarded (§7.7).
    #[tokio::test]
    async fn late_answers_are_discarded() {
        let fake = Fake {
            slow: true,
            a: HashMap::from([("h.example", Ok(vec![addr("h.example", "192.0.2.7", 60)]))]),
            ..Fake::default()
        };
        let (dns, _) = probe_dns(&fake, "h.example", false, &CancellationToken::new()).await;
        assert_eq!(dns.timed.status, TimedStatus::Error);
        assert_eq!(dns.timed.error.as_deref(), Some(QUERY_TIMEOUT));
        assert!(dns.a.is_empty());
    }

    /// An unknown name: error from the A query, system resolver marked error.
    #[tokio::test]
    async fn nxdomain() {
        let fake = Fake {
            a: HashMap::from([("gone.example", Err("ENOTFOUND".into()))]),
            aaaa: HashMap::from([("gone.example", Err("ENOTFOUND".into()))]),
            ..Fake::default()
        };
        let (dns, _) = probe_dns(&fake, "gone.example", false, &CancellationToken::new()).await;
        assert_eq!(
            (dns.timed.status, dns.timed.error.as_deref()),
            (TimedStatus::Error, Some("ENOTFOUND"))
        );
        assert_eq!(dns.resolvers[0].status, ResolverStatus::Error);
        let empty = Fake::default();
        let (dns, _) = probe_dns(&empty, "empty.example", false, &CancellationToken::new()).await;
        assert_eq!(dns.timed.error.as_deref(), Some(NO_RECORDS));
    }

    /// Discrepancy texts: system vs all DoH, Google vs Cloudflare; private names skip DoH.
    #[tokio::test]
    async fn discrepancies() {
        let fake = Fake {
            a: HashMap::from([(
                "vpn.example.com",
                Ok(vec![addr("vpn.example.com", "10.0.0.1", 60)]),
            )]),
            doh: HashMap::from([
                (("google-doh", false), doh_ok(1, &["198.51.100.1"])),
                (("cloudflare-doh", false), doh_ok(1, &["198.51.100.2"])),
            ]),
            ..Fake::default()
        };
        let (dns, _) = probe_dns(&fake, "vpn.example.com", true, &CancellationToken::new()).await;
        let keys: Vec<String> = dns
            .discrepancies
            .iter()
            .map(|t| match t {
                Text::Msg(m) => format!(
                    "{}|{}",
                    m.key,
                    m.args
                        .iter()
                        .map(|(_, v)| v.as_str())
                        .collect::<Vec<_>>()
                        .join("|")
                ),
                Text::Legacy(s) => s.clone(),
            })
            .collect();
        assert_eq!(
            keys,
            [
                "probes.liveStages.dns.systemVsDoh|10.0.0.1|198.51.100.1, 198.51.100.2",
                "probes.liveStages.dns.googleVsCloudflare|198.51.100.1|198.51.100.2"
            ]
        );
        let private = Fake::default();
        let _ = probe_dns(&private, "nas.internal", true, &CancellationToken::new()).await;
        assert!(!private.calls.lock().iter().any(|c| c.starts_with("DOH")));
    }

    fn doh_json(json: &str) -> Result<DohResponse, String> {
        Ok(serde_json::from_str(json).unwrap())
    }

    /// AT-05-001: queryDoH classification vectors (§7.2, §7.15).
    #[test]
    fn classifies_doh_answers() {
        let a = doh_json(
            r#"{"Status":0,"AD":true,"Answer":[{"name":"vpn.example.com.","type":1,"TTL":300,"data":"198.51.100.1"},{"name":"vpn.example.com.","type":1,"TTL":300,"data":"198.51.100.2"}]}"#,
        );
        let aaaa = doh_json(
            r#"{"Status":0,"AD":true,"Answer":[{"name":"vpn.example.com.","type":28,"TTL":600,"data":"2001:db8::1"}]}"#,
        );
        let r = classify_doh(DohResolver::Google, a, aaaa, 12);
        assert_eq!(
            (r.status, r.authenticated_data),
            (ResolverStatus::Ok, Some(true))
        );
        let values: Vec<(&str, Option<u32>)> = r
            .records
            .iter()
            .map(|x| (x.value.as_str(), x.ttl))
            .collect();
        assert_eq!(
            values,
            [
                ("198.51.100.1", Some(300)),
                ("198.51.100.2", Some(300)),
                ("2001:db8::1", Some(600))
            ]
        );
        assert_eq!(r.records[0].name, "vpn.example.com");

        let down = || Err::<DohResponse, _>("Network unreachable".to_owned());
        let r = classify_doh(DohResolver::Cloudflare, down(), down(), 5);
        assert_eq!(r.status, ResolverStatus::Error);
        assert!(r.error.as_deref().unwrap().contains("Network unreachable"));
        assert!(r.records.is_empty());

        let servfail = || doh_json(r#"{"Status":2}"#);
        let r = classify_doh(DohResolver::Google, servfail(), servfail(), 5);
        assert_eq!((r.status, r.rcode), (ResolverStatus::Error, Some(2)));
        assert!(r.error.as_deref().unwrap().contains("SERVFAIL"));

        let one = r#"{"Status":0,"Answer":[{"name":"h.example.","type":1,"TTL":60,"data":"198.51.100.9"}]}"#;
        let r = classify_doh(
            DohResolver::Google,
            doh_json(one),
            doh_json(r#"{"Status":3}"#),
            5,
        );
        assert_eq!(r.status, ResolverStatus::Partial);
        assert_eq!(
            (r.a_status, r.aaaa_status),
            (Some(FamilyStatus::Ok), Some(FamilyStatus::Nxdomain))
        );

        let r = classify_doh(DohResolver::Google, doh_json(one), servfail(), 5);
        assert_eq!((r.status, r.records.len()), (ResolverStatus::Partial, 1));
        assert_eq!(r.records[0].kind, DnsRecordType::A);
        assert!(r.error.as_deref().unwrap().contains("AAAA: SERVFAIL"));

        let timeout = Err::<DohResponse, _>("DoH request timeout".to_owned());
        let r = classify_doh(DohResolver::Google, timeout, doh_json(r#"{"Status":0}"#), 5);
        assert_eq!(
            (r.a_status, r.status),
            (Some(FamilyStatus::Timeout), ResolverStatus::Error)
        );
        assert_eq!(r.error.as_deref(), Some("DoH request timeout"));

        let empty = classify_doh(DohResolver::Google, doh_json("{}"), doh_json("{}"), 5);
        assert_eq!(
            (empty.status, empty.error.as_deref()),
            (ResolverStatus::Error, Some("No records returned"))
        );
    }

    /// Old rows deserialise: unknown legacy fields are ignored, `unavailable` reads as not checked.
    #[test]
    fn reads_legacy_rows() {
        let row = r#"{"status":"ok","durationMs":40,"a":["198.51.100.1"],"aaaa":[],"cnameChain":[],
            "ttl":300,"resolverUsed":"x","records":[{"name":"h","type":"A","value":"198.51.100.1","ttl":300,
            "observedAt":"2026-01-01T00:00:00.000Z","resolverId":"system","transport":"system"}],
            "resolvers":[{"resolverId":"google-doh","resolverName":"Google Public DNS (DoH)","endpoint":"<redacted-url>",
            "status":"partial","durationMs":30,"records":[],"aStatus":"ok","aaaaStatus":"nxdomain"}],
            "discrepancies":["Системный DNS ([a]) не совпадает с публичными DoH ([b])"],"timings":{"aMs":12}}"#;
        let dns: DnsDiagnostics = serde_json::from_str(row).unwrap();
        assert_eq!(dns.timed.status, TimedStatus::Ok);
        assert_eq!(dns.resolvers[0].status, ResolverStatus::Partial);
        assert!(matches!(&dns.discrepancies[0], Text::Legacy(s) if s.starts_with("Системный")));
        let back = serde_json::to_value(&dns).unwrap();
        assert_eq!(back["cnameChain"], serde_json::json!([]));
        assert!(back.get("resolverUsed").is_none());
    }
}
