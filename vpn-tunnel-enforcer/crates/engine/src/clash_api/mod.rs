//! Client of sing-box's Clash API (`experimental.clash_api` on `127.0.0.1:<port>`, Bearer secret
//! per run): readiness / identity (`/version`), the protected selector switch (`PUT` + exact
//! read-back of `/proxies/<group>`), the open-connections snapshot and the traffic rate.
//!
//! Never through a proxy (the app itself may have set the user's proxy while the tunnel is up),
//! no redirects, small bounded answers. The endpoint is main-process state: never logged or sent
//! to the UI.
use std::fmt;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use reqwest::{Response, StatusCode, Url};
use serde::Deserialize;
use serde_json::Value;
use vpnte_base::{AppError, ErrorKind, Msg, http};

use crate::ports::{self, PortsExhausted};

#[cfg(test)]
mod tests;

/// One deadline for a control exchange (`/version`, the selector `PUT` + read-back together).
pub const CONTROL_TIMEOUT: Duration = Duration::from_secs(1);
/// Deadline of a `/connections` snapshot.
pub const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(4);
/// `/traffic` emits one line per second: wait a little longer for the first.
pub const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(3);
/// Answer size caps: control answers are tiny; thousands of open flows are a few MB.
/// One lookup through the engine's DNS router (speed3 S3-05): its first exchange through the
/// tunnel dials the DoH server.
pub const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_CONTROL_ANSWER: usize = 16 * 1024;
const MAX_SNAPSHOT_ANSWER: usize = 16 * 1024 * 1024;
/// Group and member tags are short engine tags; this also keeps the PUT body under 1 KiB.
const MAX_TAG_LEN: usize = 256;

/// Where the Clash API of one sing-box run listens.
#[derive(Clone, PartialEq, Eq)]
pub struct ClashEndpoint {
    pub port: u16,
    /// 32 hex chars, fresh per run.
    pub secret: String,
}

impl fmt::Debug for ClashEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClashEndpoint(127.0.0.1:{})", self.port)
    }
}

impl ClashEndpoint {
    /// A free port outside `taken` and a fresh secret.
    pub fn allocate(taken: &[u16]) -> Result<Self, PortsExhausted> {
        Ok(Self {
            port: ports::alloc_port(false, taken)?,
            secret: ports::secret(),
        })
    }

    /// Port 1..=65535 and a secret of 32 hex chars: anything else is refused before any request.
    pub fn is_valid(&self) -> bool {
        self.port != 0
            && self.secret.len() == 32
            && self.secret.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// Why a Clash API call gave no answer. After a failed [`ClashApi::select`] the selection is
/// unknown (a PUT can take effect even when its answer or the read-back fails): restore it.
#[derive(Debug, thiserror::Error)]
pub enum ClashError {
    #[error("invalid Clash API controller or argument")]
    Invalid,
    #[error("Clash API unreachable")]
    Transport(#[source] reqwest::Error),
    #[error("Clash API did not answer in time")]
    Timeout,
    #[error("Clash API answered HTTP {0}")]
    Status(u16),
    #[error("Clash API answer is malformed or too large")]
    Schema,
    #[error("the selector does not show the requested member")]
    NotConfirmed,
}

impl From<ClashError> for AppError {
    fn from(err: ClashError) -> Self {
        let (kind, key) = match &err {
            ClashError::Invalid => (ErrorKind::Validation, "engine.clash.invalid"),
            ClashError::Transport(_) | ClashError::Timeout => {
                (ErrorKind::Network, "engine.clash.unreachable")
            }
            ClashError::Status(_) | ClashError::Schema => {
                (ErrorKind::Internal, "engine.clash.badAnswer")
            }
            ClashError::NotConfirmed => (ErrorKind::Conflict, "engine.clash.notConfirmed"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// A selector as `GET /proxies/<group>` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// Clash type name (`Selector`, `URLTest`, `Direct`, …).
    pub kind: String,
    /// Currently selected member (empty for non-groups).
    pub now: String,
    /// Members in config order.
    pub all: Vec<String>,
}

/// Bytes per second over the whole engine, from one `/traffic` tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct Traffic {
    #[serde(default)]
    pub up: u64,
    #[serde(default)]
    pub down: u64,
}

/// `GET /connections`: totals and the currently open flows (DNS flows are filtered by sing-box).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Connections {
    /// Bytes since the engine started, all flows (closed ones included).
    pub download_total: u64,
    pub upload_total: u64,
    pub connections: Vec<Connection>,
}

/// One open flow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct Connection {
    #[serde(deserialize_with = "null_as_default")]
    pub id: String,
    pub metadata: ConnMeta,
    /// Cumulative bytes of this flow.
    #[serde(deserialize_with = "lenient_u64")]
    pub upload: u64,
    #[serde(deserialize_with = "lenient_u64")]
    pub download: u64,
    /// RFC 3339 start time.
    #[serde(deserialize_with = "null_as_default")]
    pub start: String,
    /// Reversed outbound chain: the last element is the outbound the route rules picked.
    #[serde(deserialize_with = "null_as_default")]
    pub chains: Vec<String>,
    /// `<rule> => <action>`, or `final`.
    #[serde(deserialize_with = "null_as_default")]
    pub rule: String,
}

/// Flow metadata. Ports are strings on the wire; `host` is the sniffed domain, else the
/// requested FQDN, else empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConnMeta {
    #[serde(deserialize_with = "null_as_default")]
    pub network: String,
    /// `<inbound type>/<inbound tag>`.
    #[serde(rename = "type", deserialize_with = "null_as_default")]
    pub inbound: String,
    #[serde(rename = "sourceIP", deserialize_with = "null_as_default")]
    pub source_ip: String,
    #[serde(deserialize_with = "null_as_default")]
    pub source_port: String,
    #[serde(rename = "destinationIP", deserialize_with = "null_as_default")]
    pub destination_ip: String,
    #[serde(deserialize_with = "null_as_default")]
    pub destination_port: String,
    #[serde(deserialize_with = "null_as_default")]
    pub host: String,
    #[serde(deserialize_with = "null_as_default")]
    pub process_path: String,
}

/// Go marshals nil slices and absent strings as `null`.
fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Any JSON number as a non-negative integer, so one odd counter never discards a snapshot.
fn lenient_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    Ok(number(&Value::deserialize(d)?))
}

fn number(v: &Value) -> u64 {
    match v {
        Value::Number(n) => n
            .as_u64()
            .or_else(|| {
                n.as_f64()
                    .filter(|f| f.is_finite() && *f > 0.0)
                    .map(|f| f as u64)
            })
            .unwrap_or(0),
        _ => 0,
    }
}

/// Parses a `/connections` answer: an object whose `connections` is an array (or `null` for
/// none); elements that are not connection objects are skipped.
pub fn parse_connections(body: &[u8]) -> Result<Connections, ClashError> {
    let Ok(Value::Object(mut root)) = serde_json::from_slice::<Value>(body) else {
        return Err(ClashError::Schema);
    };
    let items = match root.remove("connections") {
        Some(Value::Array(items)) => items,
        Some(Value::Null) => Vec::new(),
        _ => return Err(ClashError::Schema),
    };
    Ok(Connections {
        download_total: root.get("downloadTotal").map_or(0, number),
        upload_total: root.get("uploadTotal").map_or(0, number),
        connections: items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect(),
    })
}

/// Parses a `GET /proxies/<group>` answer.
pub fn parse_selection(body: &[u8]) -> Result<Selection, ClashError> {
    let Ok(Value::Object(root)) = serde_json::from_slice::<Value>(body) else {
        return Err(ClashError::Schema);
    };
    let text = |key: &str| root.get(key).and_then(Value::as_str).map(str::to_owned);
    let all = match root.get("all") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or(ClashError::Schema)?,
        None | Some(Value::Null) => Vec::new(),
        Some(_) => return Err(ClashError::Schema),
    };
    Ok(Selection {
        kind: text("type").ok_or(ClashError::Schema)?,
        now: text("now").unwrap_or_default(),
        all,
    })
}

/// The read-back after a select must show exactly what was asked: a `Selector` whose `now` is
/// `member` and whose members are exactly `members` (distinct, any order).
pub fn confirms(selection: &Selection, member: &str, members: &[&str]) -> bool {
    let mut seen: Vec<&str> = Vec::with_capacity(selection.all.len());
    for m in &selection.all {
        if seen.contains(&m.as_str()) {
            return false;
        }
        seen.push(m);
    }
    selection.kind == "Selector"
        && selection.now == member
        && seen.len() == members.len()
        && members.iter().all(|m| seen.contains(m))
        && seen.iter().all(|s| members.contains(s))
}

/// HTTP client for one sing-box run's Clash API.
pub struct ClashApi {
    http: reqwest::Client,
    base: Url,
    auth: HeaderValue,
}

impl fmt::Debug for ClashApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClashApi({})", self.base)
    }
}

impl ClashApi {
    /// Validates the endpoint (no request) and builds the client.
    pub fn new(ep: &ClashEndpoint) -> Result<Self, ClashError> {
        if !ep.is_valid() {
            return Err(ClashError::Invalid);
        }
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", ep.secret))
            .map_err(|_| ClashError::Invalid)?;
        auth.set_sensitive(true);
        let base = Url::parse(&format!("http://127.0.0.1:{}/", ep.port))
            .map_err(|_| ClashError::Invalid)?;
        let http = http::client_builder(SNAPSHOT_TIMEOUT)
            .build()
            .map_err(ClashError::Transport)?;
        Ok(Self { http, base, auth })
    }

    /// `GET /version`: the engine's version string (`sing-box 1.14.4`); proves the controller
    /// answers with our secret.
    pub async fn version(&self) -> Result<String, ClashError> {
        within(CONTROL_TIMEOUT, async {
            let resp = self.send(self.http.get(self.url(&["version"]))).await?;
            let body = expect_ok(resp, MAX_CONTROL_ANSWER).await?;
            let value: Value = serde_json::from_slice(&body).map_err(|_| ClashError::Schema)?;
            value
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ClashError::Schema)
        })
        .await
    }

    /// `GET /proxies/<group>`.
    pub async fn selection(&self, group: &str) -> Result<Selection, ClashError> {
        valid_tag(group)?;
        within(CONTROL_TIMEOUT, self.read_selection(group)).await
    }

    /// Selects `member` in the selector `group` and confirms it by reading it back: `members`
    /// must be exactly the group's members (for the protected switch: both slot tags). One
    /// deadline covers both requests. Any error leaves the selection unknown.
    pub async fn select(
        &self,
        group: &str,
        member: &str,
        members: &[&str],
    ) -> Result<(), ClashError> {
        valid_tag(group)?;
        valid_tag(member)?;
        within(CONTROL_TIMEOUT, async {
            let put = self
                .http
                .put(self.url(&["proxies", group]))
                .json(&serde_json::json!({ "name": member }));
            let resp = self.send(put).await?;
            if !matches!(resp.status(), StatusCode::NO_CONTENT | StatusCode::OK) {
                return Err(ClashError::Status(resp.status().as_u16()));
            }
            let selection = self.read_selection(group).await?;
            if confirms(&selection, member, members) {
                Ok(())
            } else {
                Err(ClashError::NotConfirmed)
            }
        })
        .await
    }

    /// `GET /connections`: the open flows right now (only 200 with a snapshot-shaped body counts).
    pub async fn connections(&self) -> Result<Connections, ClashError> {
        within(SNAPSHOT_TIMEOUT, async {
            let resp = self.send(self.http.get(self.url(&["connections"]))).await?;
            parse_connections(&expect_ok(resp, MAX_SNAPSHOT_ANSWER).await?)
        })
        .await
    }

    /// One tick of the `GET /traffic` stream (bytes in the last second), then the stream is
    /// closed. Takes about a second: the engine writes its first line after one tick.
    pub async fn traffic(&self) -> Result<Traffic, ClashError> {
        within(TRAFFIC_TIMEOUT, async {
            let mut resp = self.send(self.http.get(self.url(&["traffic"]))).await?;
            if resp.status() != StatusCode::OK {
                return Err(ClashError::Status(resp.status().as_u16()));
            }
            let mut line = Vec::new();
            while !line.contains(&b'\n') {
                let chunk = resp.chunk().await.map_err(ClashError::Transport)?;
                let chunk = chunk.ok_or(ClashError::Schema)?;
                line.extend_from_slice(&chunk);
                if line.len() > MAX_CONTROL_ANSWER {
                    return Err(ClashError::Schema);
                }
            }
            let end = line.iter().position(|b| *b == b'\n').unwrap_or(line.len());
            serde_json::from_slice(&line[..end]).map_err(|_| ClashError::Schema)
        })
        .await
    }

    /// `GET /dns/query?name=<name>&type=<qtype>`: one lookup through the engine's own DNS router
    /// (its rules and `final` server, no inbound), read to the end. `Ok` = the router answered
    /// (an empty answer too). The answer is never returned or logged.
    pub async fn dns_query(&self, name: &str, qtype: &str) -> Result<(), ClashError> {
        within(DNS_QUERY_TIMEOUT, async {
            let mut url = self.url(&["dns", "query"]);
            url.query_pairs_mut()
                .append_pair("name", name)
                .append_pair("type", qtype);
            let resp = self.send(self.http.get(url)).await?;
            let body = expect_ok(resp, MAX_CONTROL_ANSWER).await?;
            serde_json::from_slice::<Value>(&body).map_err(|_| ClashError::Schema)?;
            Ok(())
        })
        .await
    }

    async fn read_selection(&self, group: &str) -> Result<Selection, ClashError> {
        let resp = self
            .send(self.http.get(self.url(&["proxies", group])))
            .await?;
        parse_selection(&expect_ok(resp, MAX_CONTROL_ANSWER).await?)
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        if let Ok(mut path) = url.path_segments_mut() {
            path.pop_if_empty().extend(segments);
        }
        url
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Response, ClashError> {
        let resp = req.header(AUTHORIZATION, self.auth.clone()).send().await;
        resp.map_err(|e| {
            if e.is_timeout() {
                ClashError::Timeout
            } else {
                ClashError::Transport(e)
            }
        })
    }
}

fn valid_tag(tag: &str) -> Result<(), ClashError> {
    let ok = !tag.is_empty() && tag.len() <= MAX_TAG_LEN && !tag.chars().any(char::is_control);
    ok.then_some(()).ok_or(ClashError::Invalid)
}

async fn within<T>(
    limit: Duration,
    fut: impl Future<Output = Result<T, ClashError>>,
) -> Result<T, ClashError> {
    tokio::time::timeout(limit, fut)
        .await
        .unwrap_or(Err(ClashError::Timeout))
}

/// The body of a 200 answer, refused when larger than `limit`.
async fn expect_ok(mut resp: Response, limit: usize) -> Result<Vec<u8>, ClashError> {
    if resp.status() != StatusCode::OK {
        return Err(ClashError::Status(resp.status().as_u16()));
    }
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Err(ClashError::Schema);
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(ClashError::Transport)? {
        if body.len() + chunk.len() > limit {
            return Err(ClashError::Schema);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
