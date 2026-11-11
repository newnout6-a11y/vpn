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

/// Why a probe found no egress IP. The text is English and becomes the slot's `lastError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The slot's own listener refused the connection: the engine is gone or broken.
    #[error("{0}")]
    LocalInbound(String),
    /// Requests through the route failed (tunnel, TLS, reset, timeout, 5xx) and nothing answered.
    #[error("{0}")]
    Transport(String),
    /// The route answered, but no service gave a usable IP (HTTP 4xx, unparsable body).
    #[error("{0}")]
    Service(String),
}

impl ProbeError {
    /// Whether the failure counts toward the auto-disable budget: only a route that carried
    /// nothing at all does. Old code classified by message text, so a dead upstream behind the
    /// proxy (HTTP 502) never counted and the slot flapped forever (B-5).
    pub fn counts(&self) -> bool {
        matches!(self, ProbeError::Transport(_))
    }
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
    // A 5xx through a proxy is typically the proxy's own "bad gateway": the route is down (B-5).
    if status >= 500 {
        return Err(Fail::Transport(format!("{name}: HTTP {status}")));
    }
    if status >= 400 {
        return Err(Fail::Answered(format!("{name}: HTTP {status}")));
    }
    // 3xx is accepted like before (redirects are not followed); its body rarely holds an IP.
    let body = response
        .text()
        .await
        .map_err(|err| request_failure(&name, err))?;
    egress_ip_from(target.answer, &body)
        .ok_or_else(|| Fail::Answered(format!("{name}: the answer holds no IP address")))
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
pub(crate) mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// What the stub answers for requests whose request line contains the key: `Some((status,
    /// body))`, or `None` to close the connection without an answer (EOF).
    pub(crate) type Routes = Vec<(&'static str, Option<(u16, &'static str)>)>;

    /// A plain-HTTP forward proxy stub on 127.0.0.1 that answers absolute-form requests itself
    /// and records every request line it saw.
    pub(crate) async fn stub_proxy(routes: Routes) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (routes, log) = (routes.clone(), log.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&head);
                    let line = text.lines().next().unwrap_or_default().to_owned();
                    log.lock().push(line.clone());
                    let reply = routes.iter().find(|(key, _)| line.contains(key));
                    if let Some((status, body)) = reply.and_then(|(_, r)| *r) {
                        let answer = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = sock.write_all(answer.as_bytes()).await;
                    }
                });
            }
        });
        (port, seen)
    }

    /// Plain-HTTP stand-ins for the three services, in the production order.
    pub(crate) fn test_config() -> ProbeConfig {
        let target = |url: &str, answer| Target {
            url: url.into(),
            answer,
        };
        ProbeConfig {
            targets: vec![
                target("http://trace.test/cdn-cgi/trace", Answer::Trace),
                target("http://ipify.test/?format=json", Answer::Json),
                target("http://myip.test/", Answer::Json),
            ],
            request_timeout: Duration::from_secs(3),
            budget: Duration::from_secs(6),
        }
    }

    /// Spec external-proxy §7.12: the egress IP comes back through the proxy at 127.0.0.1:<port>
    /// (absolute-form requests reach the proxy), and a service without an IP is skipped.
    #[tokio::test]
    async fn requires_an_ip_through_the_supplied_proxy() {
        let (port, seen) = stub_proxy(vec![
            ("http://trace.test", Some((200, "fl=1\n"))),
            (
                "http://ipify.test",
                Some((200, r#"{"ip":"198.51.100.77"}"#)),
            ),
        ])
        .await;
        let ok = probe(port, &test_config()).await.unwrap();
        assert_eq!(ok.egress_ip, "198.51.100.77".parse::<IpAddr>().unwrap());
        assert!(ok.latency_ms < 3_000);
        let seen = seen.lock().clone();
        assert_eq!(
            seen,
            [
                "GET http://trace.test/cdn-cgi/trace HTTP/1.1",
                "GET http://ipify.test/?format=json HTTP/1.1"
            ]
        );
    }

    /// Spec external-proxy §7.12: one provider outage is not a proxy outage; the backup answers.
    #[tokio::test]
    async fn uses_the_backup_ip_service() {
        let (port, seen) = stub_proxy(vec![
            ("http://trace.test", Some((200, "fl=1\n"))),
            ("http://ipify.test", None),
            (
                "http://myip.test",
                Some((200, r#"{"ip":"203.0.113.91","cc":"NL"}"#)),
            ),
        ])
        .await;
        let ok = probe(port, &test_config()).await.unwrap();
        assert_eq!(ok.egress_ip, "203.0.113.91".parse::<IpAddr>().unwrap());
        assert!(seen.lock().iter().any(|l| l.contains("http://myip.test/")));
    }

    /// Spec external-proxy §7.12 / B-5: a route that carries nothing counts toward the failure
    /// budget (EOF, 5xx bad gateway); an answered request (HTTP 429) does not; a refused
    /// listener is the engine's problem, not the route's.
    #[tokio::test]
    async fn classifies_failures_by_stage() {
        let (port, _) = stub_proxy(vec![("http://", None)]).await;
        let err = probe(port, &test_config()).await.unwrap_err();
        assert!(
            matches!(err, ProbeError::Transport(_)) && err.counts(),
            "{err:?}"
        );

        let (port, _) = stub_proxy(vec![("http://", Some((502, "bad gateway")))]).await;
        let err = probe(port, &test_config()).await.unwrap_err();
        assert_eq!(err, ProbeError::Transport("trace.test: HTTP 502".into()));

        let (port, _) = stub_proxy(vec![
            ("http://trace.test", Some((429, "slow down"))),
            ("http://", None),
        ])
        .await;
        let err = probe(port, &test_config()).await.unwrap_err();
        assert_eq!(err, ProbeError::Service("trace.test: HTTP 429".into()));
        assert!(!err.counts());

        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = closed.local_addr().unwrap().port();
        drop(closed);
        let err = probe(port, &test_config()).await.unwrap_err();
        assert!(matches!(err, ProbeError::LocalInbound(_)), "{err:?}");
        assert!(!err.counts());
    }

    #[test]
    fn parses_service_answers() {
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        let trace = "fl=1\nh=www.cloudflare.com\nip=198.51.100.7\nts=1\n";
        assert_eq!(egress_ip_from(Answer::Trace, trace), ip("198.51.100.7"));
        assert_eq!(
            egress_ip_from(Answer::Trace, "ip=2001:db8::5"),
            ip("2001:db8::5")
        );
        assert_eq!(egress_ip_from(Answer::Trace, "fl=1"), None);
        let json = r#"{"ip":" 203.0.113.9 "}"#;
        assert_eq!(egress_ip_from(Answer::Json, json), ip("203.0.113.9"));
        for bad in [r#"{"ip":"not-an-ip"}"#, r#"{"ip":7}"#, "<html>", "[]", ""] {
            assert_eq!(egress_ip_from(Answer::Json, bad), None, "{bad}");
        }
    }
}
