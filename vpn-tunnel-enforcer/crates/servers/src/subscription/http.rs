//! One subscription attempt over one route: GET with manual redirects (servers §2.5 "Redirects",
//! profiles §3.7 `request`), a capped body and a transport-failure class. Redirects are followed by
//! hand because panels point `Location` at app deep links, keys or malformed `URL: https://…`
//! values that an automatic redirect policy would reject before we could look at them.
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

use reqwest::header::{HeaderMap, LOCATION};
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_core::net::is_public_ip;
use vpnte_profiles::{deeplink, text};

use super::MAX_REQUESTS;
use super::policy::{self, Refusal};
use crate::common::http_url;
use crate::model::{FetchOutcome, NetFail};

/// Largest response body read (old curl cap, also the decoder's output cap).
pub(super) const BODY_CAP: usize = text::MAX_BODY_BYTES;
/// Budget of the system lookup that checks a redirect target.
const HOP_LOOKUP: Duration = Duration::from_secs(3);

/// What one attempt brought back.
#[derive(Debug)]
pub(super) enum Answer {
    /// A body to parse, with the headers of the response that carried it.
    Body {
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// HTTP status >= 400.
    Status(u16),
    /// The panel answered, but nothing usable can come of it (the reason is for the log).
    Unusable(&'static str),
}

/// Why an attempt ended without an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Abort {
    /// Transport failure (`Network(_)` or `Timeout`): the route does not work.
    Transport(FetchOutcome),
    Cancelled,
}

/// How a route reaches the target, for the redirect checks.
#[derive(Debug, Clone, Copy)]
pub(super) struct Hops {
    /// Names are resolved here (direct route), not by a proxy.
    pub local_dns: bool,
    /// Known publicness of the origin (`Some(true)` for a DoH-pinned public address).
    pub origin_public: Option<bool>,
}

/// GET `url` with `headers`, following at most five redirects.
pub(super) async fn get(
    client: &reqwest::Client,
    url: &Url,
    headers: &HeaderMap,
    hops: Hops,
    cancel: &CancellationToken,
) -> Result<Answer, Abort> {
    let proxied = !hops.local_dns;
    let mut current = url.clone();
    let mut visited: Vec<Url> = Vec::new();
    let mut origin_public = hops.origin_public;
    for _ in 0..MAX_REQUESTS {
        if visited.contains(&current) {
            return Ok(Answer::Unusable("redirect loop"));
        }
        visited.push(current.clone());
        let request = client.get(current.clone()).headers(headers.clone()).send();
        let response = cancellable(cancel, request)
            .await?
            .map_err(|e| Abort::Transport(classify(&e, proxied)))?;
        let status = response.status().as_u16();
        if !(300..400).contains(&status) {
            if status >= 400 {
                return Ok(Answer::Status(status));
            }
            let headers = header_pairs(response.headers());
            return Ok(match read_body(response, cancel, proxied).await? {
                Some(body) => Answer::Body { headers, body },
                None => Answer::Unusable("body over the size limit"),
            });
        }
        let Some(location) = response
            .headers()
            .get(LOCATION)
            .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        else {
            return Ok(Answer::Unusable("redirect without Location"));
        };
        let Some(next) = policy::normalize_redirect(&location, &current) else {
            return Ok(Answer::Unusable("redirect without a usable Location"));
        };
        let target = match deeplink::unwrap_deeplink(&next) {
            Ok(Some(inner)) => inner,
            _ => next,
        };
        if let Some(next_url) = http_url(target.trim()) {
            let public = match origin_public {
                Some(known) => known,
                None => {
                    let public = cancellable(cancel, is_public_origin(url, hops.local_dns)).await?;
                    *origin_public.insert(public)
                }
            };
            let resolve = hops.local_dns && public;
            let addrs = cancellable(cancel, target_addrs(&next_url, resolve)).await?;
            match policy::refuse_hop(&current, &next_url, public, &addrs) {
                Some(Refusal::Downgrade) => return Ok(Answer::Unusable("https to http redirect")),
                Some(Refusal::PrivateTarget) => {
                    return Ok(Answer::Unusable("redirect into a private network"));
                }
                None => current = next_url,
            }
            continue;
        }
        let headers_seen = header_pairs(response.headers());
        if text::is_uri_line(target.trim()) {
            // The panel redirected straight to a key: that key is the subscription.
            return Ok(Answer::Body {
                headers: headers_seen,
                body: target.trim().as_bytes().to_vec(),
            });
        }
        return Ok(match read_body(response, cancel, proxied).await? {
            Some(body) if !body.iter().all(u8::is_ascii_whitespace) => Answer::Body {
                headers: headers_seen,
                body,
            },
            _ => Answer::Unusable("unsupported redirect target"),
        });
    }
    Ok(Answer::Unusable("too many redirects"))
}

/// Response headers as (lower-case name, value) pairs; raw UTF-8 values (titles) are kept.
fn header_pairs(map: &HeaderMap) -> Vec<(String, String)> {
    map.iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            (name.as_str().to_owned(), value)
        })
        .collect()
}

/// The body, or `None` when it exceeds [`BODY_CAP`] (counted after transfer decoding, so a
/// compressed bomb stops at the cap as well, S-28).
async fn read_body(
    mut response: reqwest::Response,
    cancel: &CancellationToken,
    proxied: bool,
) -> Result<Option<Vec<u8>>, Abort> {
    if response
        .content_length()
        .is_some_and(|n| n > BODY_CAP as u64)
    {
        return Ok(None);
    }
    let mut body = Vec::new();
    while let Some(chunk) = cancellable(cancel, response.chunk())
        .await?
        .map_err(|e| Abort::Transport(classify(&e, proxied)))?
    {
        if body.len() + chunk.len() > BODY_CAP {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// Runs `fut` unless `cancel` fires first.
async fn cancellable<T>(
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Result<T, Abort> {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(Abort::Cancelled),
        out = fut => Ok(out),
    }
}

/// Whether the URL the user gave is public: IP literals and `localhost` by their address, names by
/// the system resolver on a direct route; behind a proxy the proxy resolves, so a name counts as
/// public (the strict side).
async fn is_public_origin(url: &Url, local_dns: bool) -> bool {
    if policy::is_local_name(url) {
        return false;
    }
    if let Some(ip) = policy::literal_ip(url) {
        return is_public_ip(ip);
    }
    if !local_dns {
        return true;
    }
    lookup(url).await.iter().all(|ip| is_public_ip(*ip))
}

/// Addresses of a redirect target: its IP literal, or (when `resolve`) the system resolver's answer.
async fn target_addrs(url: &Url, resolve: bool) -> Vec<IpAddr> {
    if let Some(ip) = policy::literal_ip(url) {
        return vec![ip];
    }
    if resolve {
        lookup(url).await
    } else {
        Vec::new()
    }
}

/// System lookup of the URL host; empty on failure or after [`HOP_LOOKUP`] (the request itself
/// will then fail or succeed on its own).
async fn lookup(url: &Url) -> Vec<IpAddr> {
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return Vec::new();
    };
    match tokio::time::timeout(HOP_LOOKUP, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
        _ => Vec::new(),
    }
}

/// Failure class of a transport error (servers §6 `NetFail`). The top-level error is skipped
/// when reading messages: its text carries the URL.
pub(super) fn classify(err: &reqwest::Error, proxied: bool) -> FetchOutcome {
    if err.is_timeout() {
        return FetchOutcome::Timeout;
    }
    let mut source = std::error::Error::source(err);
    while let Some(e) = source {
        if let Some(outcome) = class_of(e) {
            return outcome;
        }
        source = e.source();
    }
    FetchOutcome::Network(match (err.is_connect(), proxied) {
        (true, true) => NetFail::Proxy,
        (true, false) => NetFail::Connect,
        (false, _) => NetFail::Reset,
    })
}

/// Class of one error in the chain; `io::Error` wrappers are opened (their `source` skips the
/// wrapped error, where rustls and the resolver put the reason).
fn class_of(e: &(dyn std::error::Error + 'static)) -> Option<FetchOutcome> {
    if let Some(io) = e.downcast_ref::<io::Error>() {
        // WSAHOST_NOT_FOUND, WSATRY_AGAIN, WSANO_RECOVERY, WSANO_DATA.
        if io
            .raw_os_error()
            .is_some_and(|code| (11001..=11004).contains(&code))
        {
            return Some(FetchOutcome::Network(NetFail::Dns));
        }
        match io.kind() {
            io::ErrorKind::TimedOut => return Some(FetchOutcome::Timeout),
            // tokio-rustls reports every handshake / certificate failure as InvalidData.
            io::ErrorKind::InvalidData => return Some(FetchOutcome::Network(NetFail::Tls)),
            io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::BrokenPipe => return Some(FetchOutcome::Network(NetFail::Reset)),
            _ => {}
        }
        if let Some(inner) = io.get_ref() {
            return class_of(inner);
        }
    }
    let text = e.to_string().to_ascii_lowercase();
    if text.contains("dns error") || text.contains("failed to lookup address") {
        return Some(FetchOutcome::Network(NetFail::Dns));
    }
    if ["tls", "certificate", "handshake"]
        .iter()
        .any(|w| text.contains(w))
    {
        return Some(FetchOutcome::Network(NetFail::Tls));
    }
    None
}
