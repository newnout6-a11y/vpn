//! ASN / geo of the server address (ipapi.co, fallback ipwho.is on 429 / 5xx / timeout / network
//! failure, 10-minute cache, 60 s back-off after a 429) and the `infrastructure` row section.
use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, Msg};

use super::{NotCheckedReason, ProbeRoute, Text, TimedStatus, timeouts};

/// ASN / network / country of an address (`asn` in the row).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsnInfo {
    /// `AS13335`, or `unknown`.
    #[serde(default)]
    pub asn: String,
    #[serde(default)]
    pub org: String,
    #[serde(default)]
    pub network: String,
    /// Country name as the provider spells it (`Germany`).
    #[serde(default)]
    pub country: String,
    /// ISO 3166 alpha-2 (`DE`); absent in imported rows. Compare countries by this (B-08).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
}

/// Field-by-field change flags against the previous good check (filled by the diff in `live`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangesFromPrevious {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_spike: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmtu_changed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_changed: Option<bool>,
}

/// What is in front of the server (`infrastructure` in the row). The old profile-cache egress
/// fields are gone (B-08): the fresh egress lives in the engine probe's `egress` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Infrastructure {
    pub status: TimedStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Text>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<NotCheckedReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<AsnInfo>,
    /// Geo country of the server address, else the country the server list knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_country: Option<String>,
    /// Other profiles whose cached address shares this server's IPv4 /24.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_cidr_with_profiles: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changes_from_previous: Option<ChangesFromPrevious>,
    /// Geo requests follow the OS route (their vantage point does not matter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ProbeRoute>,
}

/// Another saved profile, for the shared-/24 hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherProfile {
    pub name: String,
    pub server: String,
    /// The server list's cached resolution of `server`.
    pub resolved_ip: Option<IpAddr>,
}

/// Names of the other profiles (`server != host`, case-sensitive like the old code) whose cached
/// IPv4 shares `ip`'s /24.
pub fn shared_cidr(ip: IpAddr, host: &str, others: &[OtherProfile]) -> Vec<String> {
    let IpAddr::V4(v4) = ip else {
        return Vec::new();
    };
    let prefix = &v4.octets()[..3];
    others
        .iter()
        .filter(|p| p.server != host)
        .filter(|p| matches!(p.resolved_ip, Some(IpAddr::V4(o)) if &o.octets()[..3] == prefix))
        .map(|p| {
            if p.name.is_empty() {
                p.server.clone()
            } else {
                p.name.clone()
            }
        })
        .collect()
}

/// How long an answer is reused.
const CACHE_TTL: Duration = Duration::from_secs(600);
/// How long a provider that answered 429 is left alone.
const BACKOFF: Duration = Duration::from_secs(60);

/// Geo providers, in order of use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Provider {
    IpApi,
    IpWhoIs,
}

impl Provider {
    fn url(self, ip: IpAddr) -> String {
        match self {
            Provider::IpApi => format!("https://ipapi.co/{ip}/json/"),
            Provider::IpWhoIs => format!("https://ipwho.is/{ip}"),
        }
    }
}

/// Raw result of one provider request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fetch {
    Timeout,
    /// Connection-level failure (DNS, refused, reset, TLS).
    Network(String),
    /// Any HTTP answer: status and body.
    Http(u16, String),
}

/// What one provider answer means.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Found(AsnInfo),
    /// Worth asking the next provider (rate limit, outage, timeout).
    Retry(String),
    Fail(String),
}

/// The geo HTTP client with its cache and per-provider back-off. One per app (cheap to share).
#[derive(Debug)]
pub struct GeoCache {
    client: reqwest::Client,
    answers: Mutex<HashMap<IpAddr, (AsnInfo, Instant)>>,
    backoff: Mutex<HashMap<Provider, Instant>>,
}

impl GeoCache {
    /// Client without the system proxy, 4 s per request.
    pub fn new() -> AppResult<Self> {
        let client = vpnte_base::http::client_builder(timeouts::GEO)
            .build()
            .map_err(AppError::internal)?;
        Ok(GeoCache {
            client,
            answers: Mutex::default(),
            backoff: Mutex::default(),
        })
    }

    fn cached(&self, ip: IpAddr) -> Option<AsnInfo> {
        let answers = self.answers.lock();
        answers
            .get(&ip)
            .filter(|(_, at)| at.elapsed() < CACHE_TTL)
            .map(|(info, _)| info.clone())
    }

    fn backing_off(&self, provider: Provider) -> bool {
        self.backoff
            .lock()
            .get(&provider)
            .is_some_and(|until| Instant::now() < *until)
    }

    async fn fetch(&self, provider: Provider, ip: IpAddr) -> Fetch {
        let resp = match self.client.get(provider.url(ip)).send().await {
            Ok(resp) => resp,
            Err(e) if e.is_timeout() => return Fetch::Timeout,
            Err(e) => return Fetch::Network(e.without_url().to_string()),
        };
        let status = resp.status().as_u16();
        match resp.text().await {
            Ok(body) => Fetch::Http(status, body),
            Err(e) if e.is_timeout() => Fetch::Timeout,
            Err(e) => Fetch::Network(e.without_url().to_string()),
        }
    }
}

fn text(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// ipapi.co: `{asn, org, network, country_name, country_code}` or `{error: true, reason}`.
fn parse_ipapi(fetch: Fetch) -> Outcome {
    let body = match fetch {
        Fetch::Timeout => return Outcome::Retry("timeout".into()),
        Fetch::Network(e) => return Outcome::Retry(e),
        Fetch::Http(s, _) if s == 429 || s >= 500 => return Outcome::Retry(format!("HTTP {s}")),
        Fetch::Http(s, _) if !(200..300).contains(&s) => return Outcome::Fail(format!("HTTP {s}")),
        Fetch::Http(_, body) => body,
    };
    let Ok(v) = serde_json::from_str::<Value>(&body) else {
        return Outcome::Fail("invalid geo response".into());
    };
    if v.get("error").and_then(Value::as_bool) == Some(true) {
        let why = text(&v, "reason")
            .or_else(|| text(&v, "message"))
            .unwrap_or_else(|| "Geo lookup error".into());
        return if RATE_LIMIT.is_match(&why) {
            Outcome::Retry(why)
        } else {
            Outcome::Fail(why)
        };
    }
    Outcome::Found(AsnInfo {
        asn: text(&v, "asn").unwrap_or_else(|| "unknown".into()),
        org: text(&v, "org").unwrap_or_else(|| "unknown".into()),
        network: text(&v, "network").unwrap_or_default(),
        country: text(&v, "country_name")
            .or_else(|| text(&v, "country"))
            .unwrap_or_default(),
        country_code: text(&v, "country_code"),
    })
}

/// ipwho.is: `{success, country, country_code, connection: {asn, isp, org}}`.
fn parse_ipwho(fetch: Fetch) -> Outcome {
    let body = match fetch {
        Fetch::Timeout => return Outcome::Fail("timeout".into()),
        Fetch::Network(e) => return Outcome::Fail(e),
        Fetch::Http(s, _) if !(200..300).contains(&s) => return Outcome::Fail(format!("HTTP {s}")),
        Fetch::Http(_, body) => body,
    };
    let Ok(v) = serde_json::from_str::<Value>(&body) else {
        return Outcome::Fail("invalid geo response".into());
    };
    if v.get("success").and_then(Value::as_bool) == Some(false) {
        return Outcome::Fail(text(&v, "message").unwrap_or_else(|| "ASN lookup failed".into()));
    }
    let conn = v.get("connection").cloned().unwrap_or(Value::Null);
    let asn = text(&conn, "asn").map_or_else(
        || "unknown".into(),
        |a| {
            if a.starts_with("AS") {
                a
            } else {
                format!("AS{a}")
            }
        },
    );
    Outcome::Found(AsnInfo {
        asn,
        org: text(&conn, "isp")
            .or_else(|| text(&conn, "org"))
            .unwrap_or_else(|| "unknown".into()),
        network: String::new(),
        country: text(&v, "country").unwrap_or_default(),
        country_code: text(&v, "country_code"),
    })
}

static RATE_LIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)429|too many requests|ratelimited|rate.?limit|quota").expect("valid regex")
});
static UNREACHABLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ETIMEDOUT|Network Error|timed out|timeout|connect|dns error")
        .expect("valid regex")
});
static CANCELLED_TEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)aborted|cancell?ed").expect("valid regex"));

/// User-facing message of a geo failure (old formatInfrastructureError, as message keys).
pub fn geo_error_msg(error: &str) -> Msg {
    let key = if RATE_LIMIT.is_match(error) {
        "probes.liveStages.geo.rateLimited"
    } else if UNREACHABLE.is_match(error) {
        "probes.liveStages.geo.unreachable"
    } else if CANCELLED_TEXT.is_match(error) {
        "probes.liveStages.geo.cancelled"
    } else {
        return Msg::new("probes.liveStages.geo.failed").arg("detail", error.trim());
    };
    Msg::new(key)
}

/// ASN / geo of `ip`: cache, then ipapi.co, then ipwho.is when ipapi is rate-limited, down or
/// slow. The error is technical text ([`geo_error_msg`] turns it into a message); a cancelled
/// lookup is never cached and reads `Cancelled`.
pub async fn lookup_asn(
    cache: &GeoCache,
    ip: IpAddr,
    cancel: &CancellationToken,
) -> Result<AsnInfo, String> {
    lookup_with(cache, ip, cancel, |provider, ip| cache.fetch(provider, ip)).await
}

async fn lookup_with<F, Fut>(
    cache: &GeoCache,
    ip: IpAddr,
    cancel: &CancellationToken,
    fetch: F,
) -> Result<AsnInfo, String>
where
    F: Fn(Provider, IpAddr) -> Fut,
    Fut: Future<Output = Fetch>,
{
    if let Some(hit) = cache.cached(ip) {
        return Ok(hit);
    }
    let mut last = String::from("ASN lookup failed");
    for provider in [Provider::IpApi, Provider::IpWhoIs] {
        if cache.backing_off(provider) {
            last = "rate limited (backing off)".into();
            continue;
        }
        let fetched = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(super::CANCELLED.into()),
            f = fetch(provider, ip) => f,
        };
        if matches!(fetched, Fetch::Http(429, _)) {
            cache
                .backoff
                .lock()
                .insert(provider, Instant::now() + BACKOFF);
        }
        let outcome = match provider {
            Provider::IpApi => parse_ipapi(fetched),
            Provider::IpWhoIs => parse_ipwho(fetched),
        };
        match outcome {
            Outcome::Found(info) => {
                cache
                    .answers
                    .lock()
                    .insert(ip, (info.clone(), Instant::now()));
                return Ok(info);
            }
            Outcome::Retry(why) => last = why,
            Outcome::Fail(why) => return Err(why),
        }
    }
    Err(last)
}

/// The `infrastructure` section. `geo = None` when the user turned geo lookups off; `ip = None`
/// when DNS gave nothing. `known_country` = the server list's country for this server.
pub async fn infrastructure(
    geo: Option<&GeoCache>,
    ip: Option<IpAddr>,
    host: &str,
    known_country: Option<String>,
    others: &[OtherProfile],
    cancel: &CancellationToken,
) -> Infrastructure {
    let looked_up = match (geo, ip) {
        (Some(geo), Some(ip)) => Some(lookup_asn(geo, ip, cancel).await),
        _ => None,
    };
    assemble(geo.is_some(), looked_up, ip, host, known_country, others)
}

fn assemble(
    geo_enabled: bool,
    looked_up: Option<Result<AsnInfo, String>>,
    ip: Option<IpAddr>,
    host: &str,
    known_country: Option<String>,
    others: &[OtherProfile],
) -> Infrastructure {
    let base = Infrastructure {
        shared_cidr_with_profiles: ip
            .map(|ip| shared_cidr(ip, host, others))
            .unwrap_or_default(),
        endpoint_country: known_country.filter(|c| !c.is_empty()),
        ..Infrastructure::default()
    };
    match looked_up {
        None => Infrastructure {
            status: TimedStatus::NotChecked,
            reason: (!geo_enabled).then_some(NotCheckedReason::GeoDisabled),
            ..base
        },
        Some(Ok(asn)) => Infrastructure {
            status: TimedStatus::Ok,
            endpoint_country: Some(asn.country.clone())
                .filter(|c| !c.is_empty())
                .or(base.endpoint_country.clone()),
            asn: Some(asn),
            route: Some(ProbeRoute::Os),
            ..base
        },
        Some(Err(e)) => Infrastructure {
            status: if e == super::CANCELLED {
                TimedStatus::Skipped
            } else {
                TimedStatus::Error
            },
            error: Some(Text::Msg(geo_error_msg(&e))),
            route: Some(ProbeRoute::Os),
            ..base
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::live_stages::CANCELLED;

    const IPAPI_OK: &str = r#"{"ip":"198.51.100.10","asn":"AS64500","org":"Example Hosting","network":"198.51.100.0/24","country":"DE","country_name":"Germany","country_code":"DE"}"#;
    const IPWHO_OK: &str = r#"{"success":true,"country":"Netherlands","country_code":"NL","connection":{"asn":64501,"org":"Org","isp":"Example ISP"}}"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_providers() {
        let Outcome::Found(info) = parse_ipapi(Fetch::Http(200, IPAPI_OK.into())) else {
            panic!("ipapi answer not parsed")
        };
        assert_eq!(
            (
                info.asn.as_str(),
                info.country.as_str(),
                info.country_code.as_deref()
            ),
            ("AS64500", "Germany", Some("DE"))
        );
        assert_eq!(info.network, "198.51.100.0/24");
        assert!(matches!(
            parse_ipapi(Fetch::Http(429, String::new())),
            Outcome::Retry(_)
        ));
        assert!(matches!(
            parse_ipapi(Fetch::Http(503, String::new())),
            Outcome::Retry(_)
        ));
        assert!(matches!(parse_ipapi(Fetch::Timeout), Outcome::Retry(_)));
        assert!(matches!(
            parse_ipapi(Fetch::Network("dns error".into())),
            Outcome::Retry(_)
        ));
        assert_eq!(
            parse_ipapi(Fetch::Http(404, String::new())),
            Outcome::Fail("HTTP 404".into())
        );
        let reserved = r#"{"error":true,"reason":"Reserved IP Address"}"#;
        assert_eq!(
            parse_ipapi(Fetch::Http(200, reserved.into())),
            Outcome::Fail("Reserved IP Address".into())
        );
        let limited = r#"{"error":true,"reason":"RateLimited"}"#;
        assert!(matches!(
            parse_ipapi(Fetch::Http(200, limited.into())),
            Outcome::Retry(_)
        ));
        let Outcome::Found(info) = parse_ipwho(Fetch::Http(200, IPWHO_OK.into())) else {
            panic!("ipwho answer not parsed")
        };
        assert_eq!(
            (
                info.asn.as_str(),
                info.org.as_str(),
                info.country_code.as_deref()
            ),
            ("AS64501", "Example ISP", Some("NL"))
        );
        let failed = r#"{"success":false,"message":"Invalid IP address"}"#;
        assert_eq!(
            parse_ipwho(Fetch::Http(200, failed.into())),
            Outcome::Fail("Invalid IP address".into())
        );
    }

    /// AT-05-001 / B-28: fallback after a rate limit, answers cached, a 429 backs the provider off.
    #[tokio::test]
    async fn falls_back_caches_and_backs_off() {
        let cache = GeoCache::new().unwrap();
        let calls = AtomicU32::new(0);
        let cancel = CancellationToken::new();
        let fetch = |p: Provider, _ip: IpAddr| {
            calls.fetch_add(1, Ordering::Relaxed);
            async move {
                match p {
                    Provider::IpApi => Fetch::Http(429, "Too Many Requests".into()),
                    Provider::IpWhoIs => Fetch::Http(200, IPWHO_OK.into()),
                }
            }
        };
        let info = lookup_with(&cache, ip("198.51.100.10"), &cancel, fetch)
            .await
            .unwrap();
        assert_eq!(info.asn, "AS64501");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        lookup_with(&cache, ip("198.51.100.10"), &cancel, fetch)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2, "cached");
        lookup_with(&cache, ip("198.51.100.11"), &cancel, fetch)
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            3,
            "ipapi skipped while backing off"
        );
    }

    /// B-28: a definite ipapi failure is final; a cancelled lookup is never cached.
    #[tokio::test]
    async fn final_failures_and_cancel() {
        let cache = GeoCache::new().unwrap();
        let calls = AtomicU32::new(0);
        let cancel = CancellationToken::new();
        let err = lookup_with(&cache, ip("198.51.100.10"), &cancel, |_, _| {
            calls.fetch_add(1, Ordering::Relaxed);
            async { Fetch::Http(404, String::new()) }
        })
        .await
        .unwrap_err();
        assert_eq!(
            (err.as_str(), calls.load(Ordering::Relaxed)),
            ("HTTP 404", 1)
        );
        cancel.cancel();
        let ok = |_, _| async { Fetch::Http(200, IPAPI_OK.into()) };
        let err = lookup_with(&cache, ip("198.51.100.10"), &cancel, ok)
            .await
            .unwrap_err();
        assert_eq!(err, CANCELLED);
        assert!(cache.cached(ip("198.51.100.10")).is_none());
    }

    /// formatInfrastructureError vectors, as message keys (§7.12).
    #[test]
    fn geo_error_messages() {
        let key = |e: &str| geo_error_msg(e).key.into_owned();
        assert_eq!(
            key("Request failed with status code 429"),
            "probes.liveStages.geo.rateLimited"
        );
        assert_eq!(key("RateLimited"), "probes.liveStages.geo.rateLimited");
        assert_eq!(
            key("getaddrinfo ENOTFOUND ipapi.co"),
            "probes.liveStages.geo.unreachable"
        );
        assert_eq!(key("User aborted probe"), "probes.liveStages.geo.cancelled");
        let other = geo_error_msg("Reserved IP Address");
        assert_eq!(other.key, "probes.liveStages.geo.failed");
        assert_eq!(other.args[0].1, "Reserved IP Address");
    }

    /// The /24 hint skips the same host and IPv6 and names an unnamed profile by its server.
    #[test]
    fn shared_cidr_hint() {
        let other = |name: &str, server: &str, addr: &str| OtherProfile {
            name: name.into(),
            server: server.into(),
            resolved_ip: Some(ip(addr)),
        };
        let others = [
            other("Frankfurt 2", "fra2.example", "198.51.100.20"),
            other("", "fra3.example", "198.51.100.30"),
            other("Same host", "fra1.example", "198.51.100.10"),
            other("Elsewhere", "ams.example", "203.0.113.5"),
        ];
        let hint = shared_cidr(ip("198.51.100.10"), "fra1.example", &others);
        assert_eq!(hint, ["Frankfurt 2", "fra3.example"]);
        assert!(shared_cidr(ip("2001:db8::1"), "fra1.example", &others).is_empty());
    }

    #[test]
    fn assembles_the_section() {
        let addr = Some(ip("198.51.100.10"));
        let off = assemble(false, None, addr, "h", Some("DE".into()), &[]);
        assert_eq!(
            (off.status, off.reason),
            (TimedStatus::NotChecked, Some(NotCheckedReason::GeoDisabled))
        );
        assert_eq!(off.endpoint_country.as_deref(), Some("DE"));
        let asn = AsnInfo {
            country: "Germany".into(),
            ..AsnInfo::default()
        };
        let ok = assemble(
            true,
            Some(Ok(asn)),
            addr,
            "h",
            Some("Deutschland".into()),
            &[],
        );
        assert_eq!(
            (ok.status, ok.endpoint_country.as_deref()),
            (TimedStatus::Ok, Some("Germany"))
        );
        let failed = assemble(true, Some(Err("timeout".into())), None, "h", None, &[]);
        assert_eq!(failed.status, TimedStatus::Error);
        assert!(
            matches!(failed.error, Some(Text::Msg(ref m)) if m.key == "probes.liveStages.geo.unreachable")
        );
        let cancelled = assemble(true, Some(Err(CANCELLED.into())), None, "h", None, &[]);
        assert_eq!(cancelled.status, TimedStatus::Skipped);
    }

    /// Imported rows: the dropped profile-cache egress fields are ignored.
    #[test]
    fn reads_legacy_infrastructure() {
        let row = r#"{"status":"ok","asn":{"asn":"AS1","org":"o","network":"","country":"Germany"},
            "egressSource":"profile-cache","egressObservedAt":null,"egressIp":"198.51.100.1",
            "activeTunnelMatchesProfile":true,"sharedCidrWithProfiles":["x"],
            "changesFromPrevious":{"ipChanged":true,"pmtuChanged":false}}"#;
        let infra: Infrastructure = serde_json::from_str(row).unwrap();
        assert_eq!(infra.asn.unwrap().country_code, None);
        assert_eq!(infra.changes_from_previous.unwrap().ip_changed, Some(true));
        assert_eq!(infra.shared_cidr_with_profiles, ["x"]);
    }
}
