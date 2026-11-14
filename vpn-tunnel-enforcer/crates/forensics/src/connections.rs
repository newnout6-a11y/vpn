//! Poller of the engine's Clash API `GET /connections` (sing-box `experimental.clash_api`): the
//! authoritative source of visited sites, because sing-box sniffs every flow and reports the TLS
//! SNI / HTTP Host / QUIC name as `metadata.host`, plus per-connection byte counters.
//!
//! `/connections` lists only the flows open right now, so it is polled every 1.5 s; flows that
//! open and close between two polls are missed (accepted). The endpoint and its per-run secret
//! come from the engine runtime; this crate does not depend on the engine crate.
use std::fmt;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, Msg, http};

/// Time between the end of one poll and the start of the next.
pub const POLL_INTERVAL: Duration = Duration::from_millis(1500);
/// Deadline of one poll.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(4);
/// Failed polls in a row after which the history source is reported unavailable (F-089).
pub const FAILURE_LIMIT: u32 = 3;
/// Larger answers are refused rather than buffered (a few thousand flows are about 2 MB).
const MAX_BODY: usize = 16 * 1024 * 1024;

/// Where the engine's Clash API listens. The secret is generated per engine run and never
/// persisted or logged.
#[derive(Clone, PartialEq, Eq)]
pub struct ClashEndpoint {
    pub port: u16,
    pub secret: String,
}

impl fmt::Debug for ClashEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClashEndpoint(127.0.0.1:{})", self.port)
    }
}

/// The part of a `/connections` answer the history uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClashSnapshot {
    pub connections: Vec<ClashConn>,
}

/// One open flow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ClashConn {
    pub id: String,
    pub metadata: ClashMeta,
    /// Cumulative bytes of this flow.
    #[serde(deserialize_with = "lenient_u64")]
    pub upload: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub download: u64,
    /// Reversed outbound chain: the last element is the outbound the route rules picked.
    #[serde(deserialize_with = "null_as_empty")]
    pub chains: Vec<String>,
}

/// Flow metadata: `host` is the sniffed domain, else the requested FQDN, else empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ClashMeta {
    #[serde(deserialize_with = "null_as_empty")]
    pub host: String,
    #[serde(rename = "destinationIP", deserialize_with = "null_as_empty")]
    pub destination_ip: String,
}

/// Why a poll gave no snapshot.
#[derive(Debug, thiserror::Error)]
pub enum PollError {
    #[error("Clash API unreachable")]
    Transport(#[source] reqwest::Error),
    #[error("Clash API answered HTTP {0}")]
    Status(u16),
    #[error("Clash API answer is not a connections snapshot")]
    Schema,
}

/// Any JSON number as a non-negative integer (negative, fractional or non-numbers give 0 or
/// truncate) so one odd counter never discards the whole snapshot.
fn lenient_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(match Value::deserialize(d)? {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f > 0.0)
                    .map(|f| f as u64)
            })
            .unwrap_or(0),
        _ => 0,
    })
}

/// Go marshals a nil slice or an absent string as `null`.
fn null_as_empty<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Parses a `/connections` body: an object whose `connections` is an array (or `null`, which Go
/// sends for "none"). Elements that are not connection objects are skipped.
pub fn parse_snapshot(body: &[u8]) -> Result<ClashSnapshot, PollError> {
    let Ok(Value::Object(mut root)) = serde_json::from_slice::<Value>(body) else {
        return Err(PollError::Schema);
    };
    let items = match root.remove("connections") {
        Some(Value::Array(items)) => items,
        Some(Value::Null) => Vec::new(),
        _ => return Err(PollError::Schema),
    };
    let connections = items
        .into_iter()
        .filter_map(|item| serde_json::from_value::<ClashConn>(item).ok())
        .collect();
    Ok(ClashSnapshot { connections })
}

/// HTTP client for one engine run's Clash API.
pub struct ClashClient {
    client: reqwest::Client,
    url: String,
    auth: HeaderValue,
}

impl ClashClient {
    /// Client with the app defaults: never through a system or env proxy (the app itself may
    /// have set one while the tunnel is up), no redirects, 4 s deadline.
    pub fn new(endpoint: &ClashEndpoint) -> AppResult<Self> {
        let client = http::client_builder(REQUEST_TIMEOUT)
            .build()
            .map_err(AppError::internal)?;
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", endpoint.secret))
            .map_err(AppError::internal)?;
        auth.set_sensitive(true);
        Ok(Self {
            client,
            url: format!("http://127.0.0.1:{}/connections", endpoint.port),
            auth,
        })
    }

    /// One `GET /connections`; only HTTP 200 with a snapshot-shaped body counts.
    pub async fn connections(&self) -> Result<ClashSnapshot, PollError> {
        let mut resp = self
            .client
            .get(&self.url)
            .header(AUTHORIZATION, self.auth.clone())
            .send()
            .await
            .map_err(PollError::Transport)?;
        if resp.status() != StatusCode::OK {
            return Err(PollError::Status(resp.status().as_u16()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(PollError::Transport)? {
            if body.len() + chunk.len() > MAX_BODY {
                return Err(PollError::Schema);
            }
            body.extend_from_slice(&chunk);
        }
        parse_snapshot(&body)
    }
}

/// Health of the connections source, shown on the history page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceHealth {
    /// No engine run is polled, or no poll of the current run has succeeded yet.
    #[default]
    Idle,
    /// The last poll succeeded.
    Ok,
    /// [`FAILURE_LIMIT`] polls in a row failed: the history is not being fed.
    Unavailable,
}

impl SourceHealth {
    /// The warning to show, if any.
    pub fn warning(self) -> Option<Msg> {
        (self == SourceHealth::Unavailable).then(|| Msg::new("forensics.history.sourceUnavailable"))
    }
}

/// Consecutive-failure tracker of one engine run's polls.
#[derive(Debug, Default)]
pub struct FailureCounter {
    streak: u32,
}

impl FailureCounter {
    /// Records one poll outcome. Returns the health it establishes: `Ok` on success,
    /// `Unavailable` from the [`FAILURE_LIMIT`]th failure in a row, `None` (keep the current
    /// value) for fewer failures, so a run that never succeeded is never shown as fine.
    pub fn record(&mut self, ok: bool) -> Option<SourceHealth> {
        if ok {
            self.streak = 0;
            return Some(SourceHealth::Ok);
        }
        self.streak = self.streak.saturating_add(1);
        (self.streak >= FAILURE_LIMIT).then_some(SourceHealth::Unavailable)
    }
}

/// A running poll loop for one engine run; stops on [`ClashPoller::stop`] or drop.
pub struct ClashPoller {
    cancel: CancellationToken,
}

impl ClashPoller {
    /// Polls at once and then [`POLL_INTERVAL`] after each poll settles (never two at a time),
    /// handing every outcome to `on_poll`. Must run inside a tokio runtime.
    pub fn spawn(
        endpoint: &ClashEndpoint,
        interval: Duration,
        mut on_poll: impl FnMut(Result<ClashSnapshot, PollError>) + Send + 'static,
    ) -> AppResult<Self> {
        let client = ClashClient::new(endpoint)?;
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        tokio::spawn(async move {
            loop {
                let outcome = tokio::select! {
                    () = token.cancelled() => return,
                    outcome = client.connections() => outcome,
                };
                if let Err(err) = &outcome {
                    tracing::debug!(error = %err, "Clash /connections poll failed");
                }
                on_poll(outcome);
                tokio::select! {
                    () = token.cancelled() => return,
                    () = tokio::time::sleep(interval) => {}
                }
            }
        });
        Ok(Self { cancel })
    }

    /// Stops polling; an in-flight request is abandoned and its outcome dropped.
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

impl Drop for ClashPoller {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A sing-box 1.14 `/connections` answer (keys of `experimental/clashapi/connections.go`).
    const BODY: &str = r#"{"downloadTotal":10,"uploadTotal":5,"connections":[{"id":"c1",
        "metadata":{"network":"tcp","type":"tun/tun-in","sourceIP":"172.19.0.1",
        "destinationIP":"198.51.100.7","sourcePort":"50123","destinationPort":"443",
        "host":"github.com","dnsMode":"normal","processPath":""},"upload":100,"download":900,
        "start":"2026-11-11T07:00:00+03:00","chains":["proxy-out-a","proxy-out"],
        "rule":"final","rulePayload":""}],"memory":1024}"#;

    #[test]
    fn parses_the_sing_box_shape() {
        let s = parse_snapshot(BODY.as_bytes()).unwrap();
        let c = &s.connections[0];
        assert_eq!((c.id.as_str(), c.upload, c.download), ("c1", 100, 900));
        assert_eq!(c.metadata.host, "github.com");
        assert_eq!(c.metadata.destination_ip, "198.51.100.7");
        assert_eq!(c.chains.last().map(String::as_str), Some("proxy-out"));
    }

    /// trafficConnections.test.ts: `{connections: null}` is an empty snapshot; F-089: anything
    /// that is not a snapshot is a schema failure, never silently "no traffic".
    #[test]
    fn schema_rules() {
        let empty = parse_snapshot(br#"{"connections":null}"#).unwrap();
        assert!(empty.connections.is_empty());
        for bad in ["null", "[]", "{}", r#"{"connections":5}"#, "not json", ""] {
            assert!(
                matches!(parse_snapshot(bad.as_bytes()), Err(PollError::Schema)),
                "{bad}"
            );
        }
        let odd = br#"{"connections":[5,{"id":"a","upload":-5,"download":12.7,
            "metadata":{"host":null},"chains":null},{"id":7}]}"#;
        let s = parse_snapshot(odd).unwrap();
        assert_eq!(s.connections.len(), 1);
        let c = &s.connections[0];
        assert_eq!(
            (c.upload, c.download, c.metadata.host.as_str()),
            (0, 12, "")
        );
    }

    #[test]
    fn third_failure_in_a_row_reports_unavailable() {
        let mut counter = FailureCounter::default();
        assert_eq!(counter.record(false), None);
        assert_eq!(counter.record(false), None);
        assert_eq!(counter.record(false), Some(SourceHealth::Unavailable));
        assert!(SourceHealth::Unavailable.warning().is_some());
        assert_eq!(counter.record(true), Some(SourceHealth::Ok));
        assert_eq!(counter.record(false), None);
        assert_eq!(SourceHealth::Ok.warning(), None);
        assert_eq!(SourceHealth::Idle.warning(), None);
    }

    /// Serves one canned HTTP answer and returns the request head it received.
    async fn serve_once(answer: String) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.ends_with(b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                assert!(n > 0, "client closed early");
                head.extend_from_slice(&buf[..n]);
            }
            sock.write_all(answer.as_bytes()).await.unwrap();
            String::from_utf8(head).unwrap()
        });
        (port, task)
    }

    fn answer(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn client_sends_the_bearer_secret_and_parses_200() {
        let (port, server) = serve_once(answer("200 OK", BODY)).await;
        let endpoint = ClashEndpoint {
            port,
            secret: "00112233445566778899aabbccddeeff".into(),
        };
        assert!(!format!("{endpoint:?}").contains("0011"));
        let snapshot = ClashClient::new(&endpoint)
            .unwrap()
            .connections()
            .await
            .unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        let head = server.await.unwrap().to_ascii_lowercase();
        assert!(head.starts_with("get /connections http/1.1\r\n"), "{head}");
        assert!(head.contains("authorization: bearer 00112233445566778899aabbccddeeff\r\n"));
    }

    #[tokio::test]
    async fn non_200_is_a_failure() {
        let (port, server) = serve_once(answer("401 Unauthorized", "{}")).await;
        let endpoint = ClashEndpoint {
            port,
            secret: "x".into(),
        };
        let err = ClashClient::new(&endpoint)
            .unwrap()
            .connections()
            .await
            .unwrap_err();
        assert!(matches!(err, PollError::Status(401)), "{err:?}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn poller_polls_at_once_and_stops() {
        let (port, server) = serve_once(answer("200 OK", BODY)).await;
        let endpoint = ClashEndpoint {
            port,
            secret: "x".into(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let poller = ClashPoller::spawn(&endpoint, Duration::from_secs(60), move |outcome| {
            let _ = tx.send(outcome.map(|s| s.connections.len()));
        })
        .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap();
        assert_eq!(first.unwrap().unwrap(), 1);
        poller.stop();
        server.await.unwrap();
        // The loop ended: its sender was dropped.
        assert!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .is_none()
        );
    }
}
