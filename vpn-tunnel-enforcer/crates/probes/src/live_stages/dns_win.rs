//! Production [`DnsBackend`]: the Windows DNS client (`DnsQuery_W`: cache, hosts file and the
//! configured servers, which while our tunnel is up means sing-box's DNS) plus DoH over reqwest
//! following the OS route.
use std::ffi::c_void;
use std::fmt::Write as _;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use vpnte_base::{AppError, AppResult};
use windows::Win32::Foundation::{
    DNS_ERROR_RCODE_NAME_ERROR, DNS_ERROR_RCODE_REFUSED, DNS_ERROR_RCODE_SERVER_FAILURE,
    DNS_INFO_NO_RECORDS, ERROR_SUCCESS, ERROR_TIMEOUT, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::Dns::{
    DNS_QUERY_OPTIONS, DNS_QUERY_STANDARD, DNS_QUERY_WIRE_ONLY, DNS_RECORDA, DNS_RECORDW, DNS_TYPE,
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_PTR, DnsFree, DnsFreeRecordList, DnsQuery_W,
};
use windows::core::PCWSTR;

use super::dns::{Answer, AnswerData, DnsBackend, DohResolver, DohResponse};
use super::timeouts;

/// The system resolver and a DoH client (no system proxy).
#[derive(Debug, Clone)]
pub struct SystemDns {
    client: reqwest::Client,
}

impl SystemDns {
    /// Builds the DoH client (no system proxy, 3 s per request).
    pub fn new() -> AppResult<Self> {
        let client = vpnte_base::http::client_builder(timeouts::DOH)
            .build()
            .map_err(AppError::internal)?;
        Ok(SystemDns { client })
    }
}

impl DnsBackend for SystemDns {
    fn lookup(
        &self,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<Vec<Answer>, String>> + Send {
        let name = name.to_owned();
        let rtype = if v6 { DNS_TYPE_AAAA } else { DNS_TYPE_A };
        async move {
            let records = blocking_query(name, rtype).await?;
            Ok(records
                .into_iter()
                .filter_map(|r| {
                    let data = match (r.rtype, r.value) {
                        (1 | 28, Raw::Addr(ip)) => AnswerData::Addr(ip),
                        (5, Raw::Name(target)) => AnswerData::Cname(target),
                        _ => return None,
                    };
                    Some(Answer {
                        name: r.name,
                        data,
                        ttl: r.ttl,
                    })
                })
                .collect())
        }
    }

    async fn reverse(&self, ip: IpAddr) -> Result<Vec<String>, String> {
        let records = blocking_query(reverse_name(ip), DNS_TYPE_PTR).await?;
        Ok(records
            .into_iter()
            .filter_map(|r| match (r.rtype, r.value) {
                (12, Raw::Name(host)) => Some(host),
                _ => None,
            })
            .collect())
    }

    fn doh(
        &self,
        resolver: DohResolver,
        name: &str,
        v6: bool,
    ) -> impl Future<Output = Result<DohResponse, String>> + Send {
        let rtype = if v6 { "AAAA" } else { "A" };
        let url = url::Url::parse_with_params(resolver.url(), [("name", name), ("type", rtype)]);
        async move {
            let url = url.map_err(|e| e.to_string())?;
            let resp = self
                .client
                .get(url)
                .header(reqwest::header::ACCEPT, "application/dns-json")
                .send()
                .await
                .map_err(request_error)?;
            let status = resp.status();
            if !status.is_success() {
                let reason = status.canonical_reason().unwrap_or_default();
                return Err(format!("HTTP {} {reason}", status.as_u16()));
            }
            resp.json::<DohResponse>().await.map_err(request_error)
        }
    }
}

fn request_error(err: reqwest::Error) -> String {
    if err.is_timeout() {
        "DoH request timeout".into()
    } else {
        err.without_url().to_string()
    }
}

/// `4.3.2.1.in-addr.arpa` / nibble-reversed `….ip6.arpa`.
fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                let _ = write!(name, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
            }
            name + "ip6.arpa"
        }
    }
}

/// Payload of a record we read.
enum Raw {
    Addr(IpAddr),
    Name(String),
}

/// One record of a `DnsQuery_W` answer (owner name lowercase, no trailing dot).
struct RawRecord {
    name: String,
    rtype: u16,
    value: Raw,
    ttl: u32,
}

/// Runs the synchronous query on the blocking pool; the caller's timeout drops a late answer.
async fn blocking_query(name: String, rtype: DNS_TYPE) -> Result<Vec<RawRecord>, String> {
    tokio::task::spawn_blocking(move || query(&name, rtype, DNS_QUERY_STANDARD))
        .await
        .map_err(|_| "DNS query task failed".to_owned())?
}

/// A / AAAA addresses of `name` from the network only (`DNS_QUERY_WIRE_ONLY`: no cache, no
/// hosts file), exactly as the Windows DNS client sends the query to its configured servers.
/// The DNS canary relies on it: a cached answer would say nothing about where queries go now.
pub(crate) async fn wire_addrs(name: String, v6: bool) -> Result<Vec<IpAddr>, String> {
    let rtype = if v6 { DNS_TYPE_AAAA } else { DNS_TYPE_A };
    let records = tokio::task::spawn_blocking(move || query(&name, rtype, DNS_QUERY_WIRE_ONLY))
        .await
        .map_err(|_| "DNS query task failed".to_owned())??;
    Ok(records
        .into_iter()
        .filter_map(|r| match (r.rtype, r.value) {
            (1 | 28, Raw::Addr(ip)) => Some(ip),
            _ => None,
        })
        .collect())
}

fn query(
    name: &str,
    rtype: DNS_TYPE,
    options: DNS_QUERY_OPTIONS,
) -> Result<Vec<RawRecord>, String> {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut list: *mut DNS_RECORDA = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call; `list` receives a record list
    // owned by us and freed below.
    let status =
        unsafe { DnsQuery_W(PCWSTR(wide.as_ptr()), rtype, options, None, &mut list, None) };
    let records = if list.is_null() {
        Vec::new()
    } else {
        // SAFETY: the W variant fills the list with `DNS_RECORDW` items (the metadata types the
        // out-parameter as the A variant); the list stays valid until `DnsFree`.
        let records = unsafe { read_records(list.cast::<DNS_RECORDW>()) };
        // SAFETY: frees the list `DnsQuery_W` allocated, exactly once.
        unsafe { DnsFree(Some(list.cast::<c_void>().cast_const()), DnsFreeRecordList) };
        records
    };
    match status {
        s if s == ERROR_SUCCESS || s.0 == DNS_INFO_NO_RECORDS as u32 => Ok(records),
        s => Err(status_text(s)),
    }
}

/// c-ares style codes the old rows carry (`ENOTFOUND`, …).
fn status_text(status: WIN32_ERROR) -> String {
    match status {
        DNS_ERROR_RCODE_NAME_ERROR => "ENOTFOUND".into(),
        DNS_ERROR_RCODE_SERVER_FAILURE => "ESERVFAIL".into(),
        DNS_ERROR_RCODE_REFUSED => "EREFUSED".into(),
        ERROR_TIMEOUT => "ETIMEOUT".into(),
        other => format!("DNS query failed ({})", other.0),
    }
}

/// Walks a `DNS_RECORDW` list, keeping answer-section A / AAAA / CNAME / PTR records.
///
/// # Safety
/// `cur` must be null or the head of a valid record list returned by `DnsQuery_W`.
unsafe fn read_records(mut cur: *const DNS_RECORDW) -> Vec<RawRecord> {
    let mut out = Vec::new();
    // SAFETY (whole loop): every node of the list is a valid DNS_RECORDW until DnsFree; the
    // union member read matches `wType`.
    while let Some(rec) = unsafe { cur.as_ref() } {
        cur = rec.pNext;
        // Flags.Section: 0 question, 1 answer (cache and hosts entries read as answers).
        let section = unsafe { rec.Flags.DW } & 0x3;
        if section > 1 {
            continue;
        }
        let value = match rec.wType {
            1 => Raw::Addr(IpAddr::V4(Ipv4Addr::from(
                unsafe { rec.Data.A.IpAddress }.to_ne_bytes(),
            ))),
            28 => Raw::Addr(IpAddr::V6(Ipv6Addr::from(unsafe {
                rec.Data.AAAA.Ip6Address.IP6Byte
            }))),
            5 | 12 => match unsafe { rec.Data.PTR.pNameHost.to_string() } {
                Ok(host) => Raw::Name(normalize(&host)),
                Err(_) => continue,
            },
            _ => continue,
        };
        let Ok(name) = (unsafe { rec.pName.to_string() }) else {
            continue;
        };
        out.push(RawRecord {
            name: normalize(&name),
            rtype: rec.wType,
            value,
            ttl: rec.dwTtl,
        });
    }
    out
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name(IpAddr::from([192, 0, 2, 1])),
            "1.2.0.192.in-addr.arpa"
        );
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            reverse_name(v6),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    /// The Windows resolver answers `localhost` without the network.
    #[tokio::test]
    async fn resolves_localhost() {
        let dns = SystemDns::new().unwrap();
        let answers = dns.lookup("localhost", false).await.unwrap();
        assert!(
            answers
                .iter()
                .any(|a| a.data == AnswerData::Addr(IpAddr::from([127, 0, 0, 1]))),
            "{answers:?}"
        );
    }

    /// Live DoH + system lookup of a public name (needs internet).
    #[tokio::test]
    #[ignore = "needs internet"]
    async fn live_public_name() {
        let dns = SystemDns::new().unwrap();
        let resp = dns
            .doh(DohResolver::Cloudflare, "one.one.one.one", false)
            .await
            .unwrap();
        assert_eq!(resp.status, Some(0));
        assert!(!resp.answer.is_empty());
        assert!(
            !dns.lookup("one.one.one.one", false)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
