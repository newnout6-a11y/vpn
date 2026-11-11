//! Data-plane probe of one slot (spec 2.20, 6.4, B-5): asks public IP services for the egress IP
//! THROUGH the slot's listener, the way consumers use it (HTTP CONNECT for `https://`), so a pass
//! proves the whole route: listener, engine, upstream server and the exit to the Internet.
use std::error::Error as StdError;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use vpnte_base::types::ProxyKind;
use vpnte_core::net::{HostPort, Route, builder_for};

use crate::slot::CONTROL_HOST;

/// Deadline of one request (old `DEFAULT_PROBE_TIMEOUT_MS`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline of a whole probe: the old probe's worst case (two IP services, 10 s each).
pub const PROBE_BUDGET: Duration = Duration::from_secs(20);

/// How a service reports the caller's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Text with an `ip=<addr>` line (Cloudflare trace).
    Trace,
    /// A JSON object with a string `ip` (ipify, myip).
    Json,
}

/// One IP service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub url: String,
    pub answer: Answer,
}

/// The services asked, in order (the first valid IP wins), and the deadlines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    pub targets: Vec<Target>,
    pub request_timeout: Duration,
    pub budget: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        let target = |url: &str, answer| Target {
            url: url.into(),
            answer,
        };
        Self {
            targets: vec![
                target("https://www.cloudflare.com/cdn-cgi/trace", Answer::Trace),
                target("https://api.ipify.org?format=json", Answer::Json),
                target("https://api.myip.com", Answer::Json),
            ],
            request_timeout: REQUEST_TIMEOUT,
            budget: PROBE_BUDGET,
        }
    }
}

/// A route that answered: its public exit address and the time the winning request took
/// (CONNECT + TLS + request through the route).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOk {
    pub egress_ip: IpAddr,
    pub latency_ms: u32,
}

/// Why a probe found no egress IP, classified by the stage that failed (B-5: the old code
/// matched message text, so a dead upstream behind the proxy, HTTP 502, never counted and the
/// slot flapped forever). The text is English and becomes the slot's `lastError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The slot's own listener refused the connection: the engine is gone or broken.
    #[error("{0}")]
    LocalInbound(String),
    /// Requests through the route failed (tunnel, TLS, reset, timeout, the proxy's own 5xx)
    /// and nothing answered: the only kind that counts toward the auto-disable budget.
    #[error("{0}")]
    Transport(String),
    /// The route answered, but no service gave a usable IP (an HTTP error of the service, a
    /// body without an address).
    #[error("{0}")]
    Service(String),
}

/// Probes the slot listening on `127.0.0.1:<port>`.
pub async fn probe(port: u16, config: &ProbeConfig) -> Result<ProbeOk, ProbeError> {
    let client = HostPort::new(CONTROL_HOST, port)
        .ok()
        .map(|addr| Route::proxy(ProxyKind::Http, &addr, None))
        .and_then(|route| builder_for(&route, config.request_timeout).ok())
        .and_then(|b| b.pool_max_idle_per_host(0).build().ok())
        .ok_or_else(|| ProbeError::Service(format!("no probe client for port {port}")))?;
    let deadline = Instant::now() + config.budget;
    let (mut transport, mut service, mut answered) = (None, None, false);
    for target in &config.targets {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let started = Instant::now();
        let limit = left.min(config.request_timeout);
        let outcome = tokio::time::timeout(limit, fetch(&client, target))
            .await
            .unwrap_or_else(|_| Err(Fail::Transport(format!("{}: timed out", host(target)))));
        match outcome {
            Ok(egress_ip) => {
                let latency_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
                return Ok(ProbeOk {
                    egress_ip,
                    latency_ms,
                });
            }
            Err(Fail::Refused(text)) => return Err(ProbeError::LocalInbound(text)),
            Err(Fail::Transport(text)) => {
                transport.get_or_insert(text);
            }
            Err(Fail::Answered(text)) => {
                answered = true;
                service.get_or_insert(text);
            }
        }
    }
    Err(match (transport, service) {
        (Some(text), _) if !answered => ProbeError::Transport(text),
        (transport, service) => ProbeError::Service(
            service
                .or(transport)
                .unwrap_or_else(|| "no IP service answered".into()),
        ),
    })
}

/// Outcome of one failed request.
enum Fail {
    /// Connecting to the slot listener itself was refused.
    Refused(String),
    /// Nothing usable came back through the route.
    Transport(String),
    /// A service answered through the route (the route works), but without a usable IP.
    Answered(String),
}

async fn fetch(client: &reqwest::Client, target: &Target) -> Result<IpAddr, Fail> {
    let name = host(target);
    let response = client
        .get(&target.url)
        .send()
        .await
        .map_err(|err| request_failure(&name, err))?;
    let status = response.status().as_u16();
    if status >= 400 {
        let tunnelled = response.url().scheme() == "https";
        return Err(status_failure(&name, status, tunnelled));
    }
    // 3xx is accepted like before (redirects are not followed); its body rarely holds an IP.
    let body = response
        .text()
        .await
        .map_err(|err| request_failure(&name, err))?;
    egress_ip_from(target.answer, &body)
        .ok_or_else(|| Fail::Answered(format!("{name}: the answer holds no IP address")))
}

/// What an HTTP error status through the route means (B-5). Over plain HTTP the proxy answers
/// for the service, so a 5xx is typically its own "bad gateway": the route is down. Over HTTPS
/// the proxy only tunnels (a refused tunnel is a request error), so any status came from the
/// service itself through a working route.
fn status_failure(name: &str, status: u16, tunnelled: bool) -> Fail {
    let text = format!("{name}: HTTP {status}");
    if status >= 500 && !tunnelled {
        Fail::Transport(text)
    } else {
        Fail::Answered(text)
    }
}

fn request_failure(name: &str, err: reqwest::Error) -> Fail {
    let mut refused = false;
    let mut parts = Vec::new();
    let mut cause = StdError::source(&err);
    while let Some(next) = cause {
        refused |= next
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::ConnectionRefused);
        parts.push(next.to_string());
        cause = next.source();
    }
    let mut text = err.without_url().to_string();
    for part in parts {
        if !text.contains(&part) {
            text = format!("{text}: {part}");
        }
    }
    // Only our own hop can refuse: the engine dials the upstream, not this process.
    if refused {
        Fail::Refused(format!("proxy listener refused the connection: {text}"))
    } else {
        Fail::Transport(format!("{name}: {text}"))
    }
}

/// The host of a target URL, for error texts (the URLs are public services, never secrets).
fn host(target: &Target) -> String {
    url::Url::parse(&target.url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_else(|| "IP service".into())
}

/// The address a service reported, if the body holds a valid one.
pub fn egress_ip_from(answer: Answer, body: &str) -> Option<IpAddr> {
    let raw = match answer {
        Answer::Trace => body
            .lines()
            .find_map(|line| line.trim().strip_prefix("ip="))?
            .to_owned(),
        Answer::Json => serde_json::from_str::<serde_json::Value>(body)
            .ok()?
            .get("ip")?
            .as_str()?
            .to_owned(),
    };
    raw.trim().parse().ok()
}

/// What probes a slot; the manager's tests script it.
#[async_trait::async_trait]
pub(crate) trait Prober: Send + Sync {
    async fn probe(&self, port: u16) -> Result<ProbeOk, ProbeError>;
}

#[async_trait::async_trait]
impl Prober for ProbeConfig {
    async fn probe(&self, port: u16) -> Result<ProbeOk, ProbeError> {
        probe(port, self).await
    }
}

#[cfg(test)]
pub(crate) mod tests;
