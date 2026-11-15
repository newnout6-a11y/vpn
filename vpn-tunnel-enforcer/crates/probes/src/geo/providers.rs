//! Geo providers (servers §2.7, §3.9): request URLs, answer parsing, the vote, the 429 backoff
//! and the HTTPS JSON fetch over the app's request routes.
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use reqwest::StatusCode;
use reqwest::header::{ACCEPT, HeaderMap, RETRY_AFTER};
use serde_json::Value;
use tokio::time::Instant;
use vpnte_core::net::{Route, client_for};
use vpnte_profiles::countries::Iso2;

/// Country providers in tie-break priority (S-25: completion order made the result random).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Provider {
    GeoJs,
    IpInfoIo,
    IpWhoIs,
    /// ASN only (server details).
    IpApiCo,
}

/// The three country voters, best first.
pub(crate) const VOTERS: [Provider; 3] = [Provider::GeoJs, Provider::IpInfoIo, Provider::IpWhoIs];

impl Provider {
    /// The lookup URL for `ip` (always `https:`: the request lists the user's VPN servers).
    pub(crate) fn url(self, ip: IpAddr) -> String {
        match self {
            Provider::GeoJs => format!("https://get.geojs.io/v1/ip/country.json?ip={ip}"),
            Provider::IpInfoIo => format!("https://ipinfo.io/{ip}/json"),
            Provider::IpWhoIs => format!("https://ipwho.is/{ip}"),
            Provider::IpApiCo => format!("https://ipapi.co/{ip}/json/"),
        }
    }

    /// Per-request cap (old: geojs 10 s, others 5 s), always within the caller's deadline.
    pub(crate) fn timeout(self) -> Duration {
        match self {
            Provider::GeoJs => Duration::from_secs(10),
            Provider::IpApiCo => Duration::from_secs(6),
            Provider::IpInfoIo | Provider::IpWhoIs => Duration::from_secs(5),
        }
    }

    /// The provider's country answer for `ip`; `None` = no vote.
    pub(crate) fn country(self, ip: IpAddr, body: &Value) -> Option<Iso2> {
        let code = match self {
            Provider::GeoJs => {
                // A comma list returns an array (rows matched by the echoed `ip`), one IP may
                // return the row itself.
                let row = match body {
                    Value::Array(rows) => rows.iter().find(|r| echoes(r, ip))?,
                    row => row,
                };
                if row.get("ip").is_some() && !echoes(row, ip) {
                    return None;
                }
                row.get("country")?.as_str()?
            }
            Provider::IpInfoIo => body.get("country")?.as_str()?,
            Provider::IpWhoIs => {
                if body.get("success").and_then(Value::as_bool) == Some(false) {
                    return None;
                }
                body.get("country_code")?.as_str()?
            }
            Provider::IpApiCo => return None,
        };
        Iso2::new(code)
    }
}

fn echoes(row: &Value, ip: IpAddr) -> bool {
    row.get("ip")
        .and_then(Value::as_str)
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        == Some(ip)
}

/// Lookup URLs must be `https://host/…` (servers vector 25; the old `http://ip-api.com/batch`
/// leaked every server address in plaintext).
pub(crate) fn is_https_geo_url(url: &str) -> bool {
    url::Url::parse(url)
        .is_ok_and(|u| u.scheme() == "https" && u.host_str().is_some_and(|h| !h.is_empty()))
}

/// Majority of the votes; a tie goes to the provider listed first in `answers` (callers pass
/// them in [`VOTERS`] order).
pub(crate) fn vote(answers: &[(Provider, Option<Iso2>)]) -> Option<Iso2> {
    let mut best: Option<(Iso2, usize)> = None;
    for (_, code) in answers {
        let Some(code) = code else { continue };
        let count = answers
            .iter()
            .filter(|(_, c)| c.as_ref() == Some(code))
            .count();
        if best.is_none_or(|(_, n)| count > n) {
            best = Some((*code, count));
        }
    }
    best.map(|(code, _)| code)
}

/// Retry-After cap: a hostile or broken header must not silence a provider for days.
const RETRY_AFTER_CAP: Duration = Duration::from_secs(3600);

/// Backoff after the `failures`-th consecutive 429: `min(15 min, 60 s·2^min(failures-1, 4))`,
/// at least the server's `Retry-After` (capped at one hour).
pub(crate) fn backoff(failures: u32, retry_after: Option<Duration>) -> Duration {
    let exp = failures.saturating_sub(1).min(4);
    let base = Duration::from_secs(60 * (1 << exp)).min(Duration::from_secs(15 * 60));
    base.max(retry_after.unwrap_or_default().min(RETRY_AFTER_CAP))
}

/// `Retry-After` as delta seconds or an HTTP-date; anything else is `None` (base backoff).
pub(crate) fn parse_retry_after(value: &str, now: jiff::Timestamp) -> Option<Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = jiff::fmt::rfc2822::parse(value).ok()?.timestamp();
    let delta = at.duration_since(now);
    Duration::try_from(delta).ok()
}

/// Why a provider gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// HTTP 429 (with the parsed `Retry-After`): back off, try no other route.
    RateLimited(Option<Duration>),
    /// Transport errors on every route, an HTTP error, a non-JSON body or the deadline.
    Failed,
}

/// JSON `GET` over the request routes (a seam for tests; production is [`HttpGet`]).
pub(crate) trait JsonGet: Send + Sync {
    /// GET `url`, trying `routes` in order until one carries an HTTP answer, all before
    /// `deadline`.
    fn get<'a>(
        &'a self,
        url: String,
        routes: &'a [Route],
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Value, Fault>>;
}

/// Largest JSON answer read from a provider.
const BODY_CAP: usize = 64 * 1024;
/// Client-level cap; each request gets the tighter of its provider cap and the deadline.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The production fetcher: one reqwest client per route (no implicit system proxy, no
/// redirects), reused across lookups.
#[derive(Default)]
pub(crate) struct HttpGet {
    clients: Mutex<HashMap<String, reqwest::Client>>,
}

impl HttpGet {
    fn client(&self, route: &Route) -> Option<reqwest::Client> {
        let key = route.label();
        if let Some(client) = self.clients.lock().get(&key) {
            return Some(client.clone());
        }
        let client = client_for(route, CLIENT_TIMEOUT).ok()?;
        self.clients.lock().insert(key, client.clone());
        Some(client)
    }

    async fn fetch(
        &self,
        url: String,
        routes: &[Route],
        deadline: Instant,
    ) -> Result<Value, Fault> {
        if !is_https_geo_url(&url) {
            return Err(Fault::Failed);
        }
        for route in routes {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Some(client) = self.client(route) else {
                continue;
            };
            let request = client
                .get(&url)
                .header(ACCEPT, "application/json")
                .timeout(remaining);
            // A transport failure (dead local proxy, DNS, TLS) moves on to the next route.
            let Ok(mut response) = request.send().await else {
                continue;
            };
            let status = response.status();
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(Fault::RateLimited(retry_after(response.headers())));
            }
            if !status.is_success() {
                continue;
            }
            let mut body = Vec::new();
            while let Ok(Some(chunk)) = response.chunk().await {
                body.extend_from_slice(&chunk);
                if body.len() > BODY_CAP {
                    return Err(Fault::Failed);
                }
            }
            return serde_json::from_slice(&body).map_err(|_| Fault::Failed);
        }
        Err(Fault::Failed)
    }
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    parse_retry_after(value, jiff::Timestamp::now())
}

impl JsonGet for HttpGet {
    fn get<'a>(
        &'a self,
        url: String,
        routes: &'a [Route],
        deadline: Instant,
    ) -> BoxFuture<'a, Result<Value, Fault>> {
        Box::pin(self.fetch(url, routes, deadline))
    }
}
