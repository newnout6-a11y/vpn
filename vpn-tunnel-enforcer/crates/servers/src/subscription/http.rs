//! One subscription attempt over one route: GET with manual redirects (servers §2.5 "Redirects",
//! profiles §3.7 `request`), a capped body and a transport-failure class. Redirects are followed by
//! hand because panels point `Location` at app deep links, keys or malformed `URL: https://…`
//! values that an automatic redirect policy would reject before we could look at them.
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::header::{HeaderMap, LOCATION};
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_core::net::is_public_ip;
use vpnte_profiles::{deeplink, text};

use super::MAX_REQUESTS;
use super::hwid::BODY_PREFIX;
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
        /// Where the leading run of 301 / 308 redirects pointed: the subscription's permanent new
        /// address (a 302 / 307 after it is temporary and does not count).
        moved: Option<Url>,
    },
    /// HTTP status >= 400, with its headers and (403 only) the start of its body: the panel may
    /// say there why it refused this device (see `hwid::refusal`).
    Status {
        code: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
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

/// Builds a direct client whose lookups of a host answer exactly the given addresses: a linked
/// fetch's redirect goes where the hop check looked, never where a second lookup points
/// (phones-a11, fix-ks a5).
pub(super) type Pin<'a> = &'a (dyn Fn(&str, &[SocketAddr]) -> Option<reqwest::Client> + Sync);

/// The headers of one attempt: the URL's own host gets `own`; once a redirect leaves that host
/// the rest of the chain gets `elsewhere` (no identity, no user headers), even if it comes back.
/// Hosts, not origins: an `http` -> `https` upgrade on the panel's own host keeps the HWID that
/// HWID-bound panels need, while a CDN or paste host never sees a token.
#[derive(Clone, Copy)]
pub(super) struct Sends<'a> {
    pub own: &'a HeaderMap,
    pub elsewhere: &'a HeaderMap,
}

/// GET `url` with `sends`, following at most five redirects. With `pin` (a linked direct fetch)
/// every hop to a name is resolved once, refused unless the answer is public and not empty,
/// and requested through a client pinned to that answer.
pub(super) async fn get(
    client: &reqwest::Client,
    url: &Url,
    sends: Sends<'_>,
    hops: Hops,
    pin: Option<Pin<'_>>,
    cancel: &CancellationToken,
) -> Result<Answer, Abort> {
    let proxied = !hops.local_dns;
    let mut hop_client: Option<reqwest::Client> = None;
    let mut current = url.clone();
    let mut visited: Vec<Url> = Vec::new();
    let mut origin_public = hops.origin_public;
    // The target of the leading run of permanent hops; `permanent` ends the run.
    let mut moved: Option<Url> = None;
    let mut permanent = true;
    let mut same_host = true;
    for _ in 0..MAX_REQUESTS {
        if visited.contains(&current) {
            return Ok(Answer::Unusable("redirect loop"));
        }
        visited.push(current.clone());
        let headers = if same_host {
            sends.own
        } else {
            sends.elsewhere
        };
        let via = hop_client.as_ref().unwrap_or(client);
        let request = via.get(current.clone()).headers(headers.clone()).send();
        let response = cancellable(cancel, request)
            .await?
            .map_err(|e| Abort::Transport(classify(&e, proxied)))?;
        let status = response.status().as_u16();
        if !(300..400).contains(&status) {
            if status >= 400 {
                let headers = header_pairs(response.headers());
                // Only a 403 may carry the reason in its body; a short prefix is enough.
                let body = match status {
                    403 => read_prefix(response, BODY_PREFIX, cancel).await?,
                    _ => Vec::new(),
                };
                return Ok(Answer::Status {
                    code: status,
                    headers,
                    body,
                });
            }
            let headers = header_pairs(response.headers());
            return Ok(match read_body(response, cancel, proxied).await? {
                Some(body) => Answer::Body {
                    headers,
                    body,
                    moved,
                },
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
        // The hop policy below judges the carried URL by this redirect's origin and the
        // resolved addresses, so the deep-link rule "internet hosts only" does not apply here.
        let target = match deeplink::unwrap_redirect(&next) {
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
                None => {
                    if let Some(pin) = pin
                        && let Some(url::Host::Domain(name)) = next_url.host()
                    {
                        let port = next_url.port_or_known_default().unwrap_or(443);
                        let to: Vec<SocketAddr> =
                            addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
                        // An empty answer proves nothing public: a late or failed lookup is a
                        // refusal here, not a pass.
                        match pin(name, &to).filter(|_| !to.is_empty()) {
                            Some(pinned) => hop_client = Some(pinned),
                            None => return Ok(Answer::Unusable("redirect target not resolved")),
                        }
                    }
                    permanent &= matches!(status, 301 | 308);
                    if permanent {
                        moved = Some(next_url.clone());
                    }
                    same_host &= next_url.host() == current.host();
                    current = next_url;
                }
            }
            continue;
        }
        let headers_seen = header_pairs(response.headers());
        if text::is_uri_line(target.trim()) {
            // The panel redirected straight to a key: that key is the subscription.
            return Ok(Answer::Body {
                headers: headers_seen,
                body: target.trim().as_bytes().to_vec(),
                moved: None,
            });
        }
        return Ok(match read_body(response, cancel, proxied).await? {
            Some(body) if !body.iter().all(u8::is_ascii_whitespace) => Answer::Body {
                headers: headers_seen,
                body,
                moved: None,
            },
            _ => Answer::Unusable("unsupported redirect target"),
        });
    }
    Ok(Answer::Unusable("too many redirects"))
}

/// Whether the subscription at `base` may move to (or fall back on, or name as a provider)
/// `target`: the rules of a redirect hop (no `https` -> `http`: the device headers would travel in
/// clear text; a public subscription never points into a private network). Names are resolved
/// by the system only when `local_dns` (the answer came direct, as [`get`] does): behind a proxy
/// a lookup would send them to the local resolver the plan avoids, so names then count as public
/// and only IP literals and `localhost` are checked.
pub(super) async fn vet_relocation(base: &Url, target: &Url, local_dns: bool) -> bool {
    let public = is_public_origin(base, local_dns).await;
    let addrs = target_addrs(target, local_dns && public).await;
    policy::refuse_hop(base, target, public, &addrs).is_none()
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

/// Up to `cap` bytes of the body; a transport failure while reading ends it early (the status
/// already said the panel refused, the prefix only adds the reason).
async fn read_prefix(
    mut response: reqwest::Response,
    cap: usize,
    cancel: &CancellationToken,
) -> Result<Vec<u8>, Abort> {
    let mut body = Vec::new();
    while body.len() < cap {
        match cancellable(cancel, response.chunk()).await? {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk[..chunk.len().min(cap - body.len())]),
            Ok(None) | Err(_) => break,
        }
    }
    Ok(body)
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
pub(super) async fn lookup(url: &Url) -> Vec<IpAddr> {
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
pub(super) fn class_of(e: &(dyn std::error::Error + 'static)) -> Option<FetchOutcome> {
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
    // hyper-util's SOCKS errors read "SOCKS error: io error during SOCKS handshake" (no source):
    // the proxy failed, not TLS to the subscription host.
    if text.contains("socks") {
        return Some(FetchOutcome::Network(NetFail::Proxy));
    }
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
