//! The probe destinations, raced through the probe engine's local SOCKS port (keyHealthChecker.ts
//! :44-48, §3.11): certificate verification on, any 2xx; the Cloudflare trace stays DNS-free
//! (`https://1.1.1.1/…`, its certificate carries the IP) and also yields the exit IP / country.
use std::net::IpAddr;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use reqwest::header::CONNECTION;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use vpnte_base::AppError;
use vpnte_base::types::Loopback;
use vpnte_profiles::countries::Iso2;

use super::classify::parse_trace;
use crate::egress::rtt_ms;

/// One destination: URL and whether it is the trace.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Destination {
    pub url: &'static str,
    pub trace: bool,
}

pub(crate) const DESTINATIONS: [Destination; 3] = [
    Destination {
        url: "https://1.1.1.1/cdn-cgi/trace",
        trace: true,
    },
    Destination {
        url: "https://yandex.ru/favicon.ico",
        trace: false,
    },
    Destination {
        url: "https://www.gstatic.com/generate_204",
        trace: false,
    },
];

/// SOCKS CONNECT + TCP through the engine (old: 8 s timer).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// TLS + request after the connect (old: a second 8 s timer, so ≤ 16 s per destination).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(16);
/// Trace body after its status line.
const TRACE_BODY_WAIT: Duration = Duration::from_millis(600);
/// How long a winning non-trace destination waits for the trace (exit IP / country, S-16).
const TRACE_GRACE: Duration = Duration::from_secs(1);
/// Largest trace body read.
const TRACE_CAP: usize = 16 * 1024;

/// What the race established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Race {
    /// First 2xx after `rtt_ms` (measured from SOCKS readiness), plus the trace when it came.
    Online {
        rtt_ms: u32,
        egress_ip: Option<IpAddr>,
        country: Option<Iso2>,
    },
    /// Every destination failed; the error texts for the classifier.
    Offline(String),
}

type Trace = (Option<IpAddr>, Option<Iso2>);

/// Races `destinations` with `client` (built on [`builder`]); `Err` only on cancellation.
pub(crate) async fn race(
    client: &reqwest::Client,
    destinations: &[Destination],
    cancel: &CancellationToken,
) -> Result<Race, AppError> {
    let started = Instant::now();
    let mut pending: FuturesUnordered<_> = destinations
        .iter()
        .map(|d| {
            let client = client.clone();
            async move { (d.trace, fetch(&client, *d).await) }
        })
        .collect();
    let mut errors = Vec::new();
    loop {
        let next = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(AppError::cancelled()),
            next = pending.next() => next,
        };
        let Some((trace, result)) = next else {
            return Ok(Race::Offline(errors.join("\n")));
        };
        match result {
            Ok(found) => {
                let rtt_ms = rtt_ms(started.elapsed());
                let (egress_ip, country) = match found {
                    Some(found) => found,
                    None if trace => (None, None),
                    None => trace_grace(&mut pending).await,
                };
                return Ok(Race::Online {
                    rtt_ms,
                    egress_ip,
                    country,
                });
            }
            Err(text) => errors.push(text),
        }
    }
}

/// After a non-trace win: the trace result if it arrives within [`TRACE_GRACE`].
async fn trace_grace<F>(pending: &mut FuturesUnordered<F>) -> Trace
where
    F: Future<Output = (bool, Result<Option<Trace>, String>)>,
{
    let until = Instant::now() + TRACE_GRACE;
    while let Ok(Some((trace, result))) = timeout_at(until, pending.next()).await {
        if let (true, Ok(Some(found))) = (trace, result) {
            return found;
        }
    }
    (None, None)
}

/// Client settings whose every connection goes through the probe's SOCKS port with remote name
/// resolution (`socks5h`), never pooled across attempts.
pub(crate) fn builder(socks: &Loopback) -> Result<reqwest::ClientBuilder, AppError> {
    let auth = socks
        .creds
        .as_ref()
        .map(|c| format!("{}:{}@", encode(&c.user), encode(&c.pass)))
        .unwrap_or_default();
    let proxy = reqwest::Proxy::all(format!("socks5h://{auth}127.0.0.1:{}", socks.port))
        .map_err(|err| AppError::internal(err.without_url()))?;
    Ok(vpnte_base::http::client_builder(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_max_idle_per_host(0)
        .proxy(proxy))
}

/// The client of [`builder`].
pub(crate) fn build(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, AppError> {
    builder
        .build()
        .map_err(|err| AppError::internal(err.without_url()))
}

fn encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// One destination: `Ok(Some(trace))` for a trace with a public IP, `Ok(None)` for another 2xx,
/// `Err(text)` (error chain, for the classifier) otherwise.
async fn fetch(client: &reqwest::Client, d: Destination) -> Result<Option<Trace>, String> {
    let response = client
        .get(d.url)
        .header(CONNECTION, "close")
        .send()
        .await
        .map_err(|err| chain(&err.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("http status {}", status.as_u16()));
    }
    if !d.trace {
        return Ok(None);
    }
    let body = timeout(TRACE_BODY_WAIT, read_capped(response))
        .await
        .map_err(|_| "trace body timeout".to_owned())?;
    match parse_trace(&body) {
        (Some(ip), country) => Ok(Some((Some(ip), country))),
        (None, _) => Err("trace without a public ip".to_owned()),
    }
}

async fn read_capped(mut response: reqwest::Response) -> String {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() >= TRACE_CAP {
            break;
        }
    }
    String::from_utf8_lossy(&body).into_owned()
}

/// The error and its causes on one line (reqwest's own text names only the request).
fn chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
