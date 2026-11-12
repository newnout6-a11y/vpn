//! Request pipeline of the control API (old order kept: Host guard, OPTIONS, method, token,
//! body) and the endpoints over [`ProxyOps`].
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::{Map, Value};

use super::files::ControlToken;
use super::http::{Head, Response};
use crate::model::{
    Action, ControlError, ProfileList, ProfileRow, ProxyError, ProxyOps, StartRequest, StopReason,
    prewarm_count,
};
use crate::slot::{CONTROL_HOST, CONTROL_PORT, Slot, loopback_url, parse_port};

/// Header carrying the control token (alternative: `Authorization: Bearer <token>`).
pub const TOKEN_HEADER: &str = "x-vpnte-control-token";
/// Optional prefix of every path (`/api/external-proxy/status` = `/status`).
const PATH_PREFIX: &str = "/api/external-proxy";
/// Paths that change state: POST only.
const MUTATION_PATHS: [&str; 10] = [
    "/start",
    "/rotate",
    "/connect",
    "/connect-profiles",
    "/trigger",
    "/stop",
    "/healthcheck",
    "/profiles/healthcheck",
    "/instances/prewarm",
    "/instances/status-batch",
];
/// Read-only paths: GET only, but authenticated like everything else.
const READ_PATHS: [&str; 4] = ["/status", "/", "/instances", "/list"];
/// At most one "unauthorized" warning per this interval (B-24).
const UNAUTHORIZED_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// What every connection task shares.
pub(super) struct Shared {
    pub ops: Arc<dyn ProxyOps>,
    pub token: ControlToken,
    /// The port the listener actually bound (the Host guard compares against it).
    pub port: u16,
    unauthorized: Mutex<AuthLog>,
}

#[derive(Default)]
struct AuthLog {
    last: Option<Instant>,
    suppressed: u32,
}

impl Shared {
    pub fn new(ops: Arc<dyn ProxyOps>, token: ControlToken, port: u16) -> Self {
        Self {
            ops,
            token,
            port,
            unauthorized: Mutex::new(AuthLog::default()),
        }
    }

    fn log_unauthorized(&self, path: &str) {
        let now = Instant::now();
        let mut log = self.unauthorized.lock();
        if log
            .last
            .is_some_and(|t| now.duration_since(t) < UNAUTHORIZED_LOG_INTERVAL)
        {
            log.suppressed += 1;
            return;
        }
        let suppressed = std::mem::take(&mut log.suppressed);
        log.last = Some(now);
        drop(log);
        tracing::warn!(path, suppressed, "control request unauthorized");
    }
}

/// True for the paths that change state (POST only).
pub fn is_mutation_path(path: &str) -> bool {
    MUTATION_PATHS.contains(&path)
}

/// DNS-rebinding defence: the Host header must name the loopback endpoint with the bound port,
/// exactly `127.0.0.1:<port>` or `localhost:<port>` (case-insensitive). A Host without the
/// port, `[::1]` or a decimal IP is refused.
pub fn is_trusted_host(host: Option<&str>, port: u16) -> bool {
    let Some(host) = host else { return false };
    let host = host.trim().to_ascii_lowercase();
    port != 0 && (host == format!("{CONTROL_HOST}:{port}") || host == format!("localhost:{port}"))
}

/// The token a request carries: the token header (trimmed) or `Authorization: Bearer <token>`.
pub(super) fn request_token(head: &Head) -> Option<&str> {
    if let Some(token) = head.header(TOKEN_HEADER).filter(|t| !t.is_empty()) {
        return Some(token);
    }
    let auth = head.header("authorization")?;
    let (scheme, rest) = auth.split_at_checked(6)?;
    let token = rest.trim();
    (scheme.eq_ignore_ascii_case("bearer")
        && rest.starts_with(char::is_whitespace)
        && !token.is_empty())
    .then_some(token)
}

/// A request that passed the gate: its normalized path and query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Route {
    /// Path without the optional `/api/external-proxy` prefix.
    pub path: String,
    /// `?format=text` or `?text=1`: plain-text answers.
    pub text: bool,
    /// Decoded query pairs in order.
    pub query: Vec<(String, String)>,
    pub post: bool,
}

/// Outcome of the checks that need no body.
#[derive(Debug)]
pub(super) enum Gate {
    Respond(Response),
    Proceed(Route),
}

/// Host guard, OPTIONS, method and token checks (old order).
pub(super) fn gate(shared: &Shared, head: &Head) -> Gate {
    let host = match head.all("host").collect::<Vec<_>>()[..] {
        [one] => Some(one),
        _ => None,
    };
    if !is_trusted_host(host, shared.port) {
        tracing::warn!(
            reason = "untrusted-host",
            status = "error",
            "control request rejected"
        );
        let body = ControlError::new(
            "untrusted-host",
            "Host header must target the loopback control endpoint",
        );
        return Gate::Respond(Response::json(421, &body));
    }
    if head.method == "OPTIONS" {
        return Gate::Respond(Response::text(204, ""));
    }
    let base = loopback_url(CONTROL_PORT);
    let Ok(url) = url::Url::parse(&base).and_then(|b| b.join(&head.target)) else {
        let err = ProxyError::BadRequest("invalid request target".into());
        return Gate::Respond(Response::json(400, &ControlError::from(&err)));
    };
    let path = url.path();
    let path = path.strip_prefix(PATH_PREFIX).unwrap_or(path).to_owned();
    let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
    let first = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let text = first("format") == Some("text") || first("text") == Some("1");

    let (get, post) = (head.method == "GET", head.method == "POST");
    let mutation = is_mutation_path(&path);
    let needs_token = mutation || READ_PATHS.contains(&path.as_str());
    if (mutation && !post) || (!mutation && !get) {
        return Gate::Respond(plain_error(405, "method-not-allowed", text));
    }
    if needs_token && !request_token(head).is_some_and(|t| shared.token.matches(t)) {
        shared.log_unauthorized(&path);
        return Gate::Respond(plain_error(401, "unauthorized", text));
    }
    Gate::Proceed(Route {
        path,
        text,
        query,
        post,
    })
}

/// The old `controlError(code)` answers: the code is also the detail (or the whole text body).
fn plain_error(status: u16, code: &str, text: bool) -> Response {
    if text {
        Response::text(status, code)
    } else {
        Response::json(status, &ControlError::new(code, code))
    }
}

/// A failed operation: its status and code, the detail as JSON or as the whole text body.
pub(super) fn error_response(path: &str, err: &ProxyError, text: bool) -> Response {
    tracing::warn!(path, error = err.detail(), "control request failed");
    if text {
        Response::text(err.http_status(), err.detail())
    } else {
        Response::json(err.http_status(), &ControlError::from(err))
    }
}

/// Body of a POST: blank = `{}`; anything but a JSON object is a 400 (the old API silently used
/// `{}` for broken JSON and crashed with a 500 on `null`, B-12).
pub(super) fn parse_body(raw: &[u8]) -> Result<Map<String, Value>, ProxyError> {
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Ok(Map::new());
    }
    match serde_json::from_slice::<Value>(raw) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(ProxyError::BadRequest("JSON body must be an object".into())),
        Err(_) => Err(ProxyError::BadRequest("invalid JSON body".into())),
    }
}

/// Request parameters: the query string first (even when empty), else a string or number field
/// of the JSON body, as the old `param(name)`.
struct Params<'a> {
    query: &'a [(String, String)],
    body: &'a Map<String, Value>,
}

impl Params<'_> {
    fn get(&self, name: &str) -> Option<String> {
        if let Some((_, v)) = self.query.iter().find(|(k, _)| k == name) {
            return Some(v.clone());
        }
        match self.body.get(name)? {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(number_text(n)),
            _ => None,
        }
    }

    /// A parameter trimmed, absent when blank.
    fn text(&self, name: &str) -> Option<String> {
        self.get(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    }

    /// `slot`; absent or empty means slot 1 (old default).
    fn slot(&self) -> Result<Slot, ProxyError> {
        match self.get("slot") {
            Some(raw) if !raw.is_empty() => Slot::parse(&raw),
            _ => Ok(Slot::DEFAULT),
        }
    }
}

/// JSON number as JavaScript's `String(n)` would print it (integers without a fraction).
fn number_text(n: &serde_json::Number) -> String {
    match (n.as_u64(), n.as_i64(), n.as_f64()) {
        (Some(u), _, _) => u.to_string(),
        (_, Some(i), _) => i.to_string(),
        (_, _, Some(f)) => f.to_string(),
        _ => n.to_string(),
    }
}

/// JavaScript `Number(text)` for decimal input: blank is 0, garbage is NaN.
fn js_number(raw: &str) -> f64 {
    let raw = raw.trim();
    if raw.is_empty() {
        return 0.0;
    }
    raw.parse().unwrap_or(f64::NAN)
}

/// Runs the endpoint of a request that passed the gate.
pub(super) async fn dispatch(
    shared: &Shared,
    route: &Route,
    body: &Map<String, Value>,
) -> Response {
    let params = Params {
        query: &route.query,
        body,
    };
    match endpoint(shared.ops.as_ref(), &route.path, &params, body).await {
        Ok(Some(Reply { json, text })) => {
            if route.text {
                Response::text(200, text)
            } else {
                Response {
                    status: 200,
                    text: false,
                    body: json,
                }
            }
        }
        // Unknown paths are always a JSON 404 (also in text mode, as before).
        Ok(None) => Response::json(404, &ControlError::new("not-found", "not-found")),
        Err(err) => error_response(&route.path, &err, route.text),
    }
}

/// Both renderings of a successful answer.
struct Reply {
    json: String,
    text: String,
}

impl Reply {
    fn new<T: serde::Serialize>(payload: &T, text: impl Into<String>) -> Self {
        Self {
            json: Response::json(200, payload).body,
            text: text.into(),
        }
    }
}

/// One endpoint; `None` for an unknown path.
async fn endpoint(
    ops: &dyn ProxyOps,
    path: &str,
    p: &Params<'_>,
    body: &Map<String, Value>,
) -> Result<Option<Reply>, ProxyError> {
    let reply = match path {
        "/status" | "/" => {
            let s = ops.status(p.slot()?).await;
            let text = s
                .instance
                .proxy_url
                .clone()
                .unwrap_or_else(|| "stopped".into());
            Reply::new(&s, text)
        }
        "/instances" => {
            let all = ops.instances().await;
            let lines: Vec<String> = all
                .instances
                .iter()
                .filter(|i| i.running)
                .filter_map(|i| Some(format!("{}\t{}", i.slot, i.proxy_url.as_deref()?)))
                .collect();
            let text = if lines.is_empty() {
                "stopped".to_owned()
            } else {
                lines.join("\n")
            };
            Reply::new(&all, text)
        }
        "/healthcheck" => {
            let s = ops.check_health(p.slot()?).await;
            Reply::new(&s, wire_name(&s.health))
        }
        "/list" => {
            let profiles = ops.list(p.text("country")).await;
            let text = profile_lines(&profiles);
            Reply::new(&ProfileList { profiles }, text)
        }
        "/profiles/healthcheck" => {
            let group = p
                .text("groupId")
                .ok_or_else(|| ProxyError::BadRequest("groupId is required".into()))?;
            let r = ops.check_group_health(group).await?;
            Reply::new(&r, format!("{}/{}", r.alive(), r.results.len()))
        }
        "/connect-profiles" => {
            let ids: Vec<String> = match body.get("profileIds") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            };
            if ids.is_empty() {
                return Err(ProxyError::BadRequest(
                    "profileIds must be a non-empty array of profile IDs".into(),
                ));
            }
            let r = ops.start_profiles(ids).await;
            let urls: Vec<&str> = r
                .started
                .iter()
                .filter_map(|i| i.proxy_url.as_deref())
                .collect();
            Reply::new(&r, urls.join("\n"))
        }
        "/instances/prewarm" => {
            let raw = p
                .get("count")
                .ok_or_else(|| ProxyError::BadRequest("count is required".into()))?;
            let n = js_number(&raw);
            // Not a whole number: same 400 as an out-of-range count.
            let n = if n.fract() == 0.0 && (0.0..=f64::from(u16::MAX)).contains(&n) {
                n as u64
            } else {
                0
            };
            let count = prewarm_count(n)?;
            let r = ops.prewarm(u64::from(count), p.text("country")).await?;
            Reply::new(&r, r.aggregate.ready.to_string())
        }
        "/instances/status-batch" => {
            let slots = match body.get("slots") {
                Some(Value::Array(items)) => Some(
                    items
                        .iter()
                        .map(slot_value)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                _ => None,
            };
            let r = ops.status_batch(slots).await;
            Reply::new(&r, r.aggregate.ready.to_string())
        }
        "/start" | "/rotate" | "/connect" | "/trigger" => {
            let s = ops.start(start_request(path, p)?).await?;
            let text = s.instance.proxy_url.clone().unwrap_or_default();
            Reply::new(&s, text)
        }
        "/stop" => {
            let s = ops.stop(p.slot()?, StopReason::Api).await?;
            Reply::new(&s, "stopped")
        }
        _ => return Ok(None),
    };
    Ok(Some(reply))
}

/// `/start`, `/rotate`, `/connect`, `/trigger`.
fn start_request(path: &str, p: &Params<'_>) -> Result<StartRequest, ProxyError> {
    let profile_id = p
        .get("profileId")
        .or_else(|| p.get("id"))
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty());
    // A port is a choice only when given (the old API ignored an empty one).
    let port = match p.get("port") {
        Some(raw) if !raw.is_empty() => Some(parse_port(&raw)?),
        _ => None,
    };
    Ok(StartRequest {
        slot: Some(p.slot()?),
        country: p.text("country"),
        profile_id,
        port,
        action: Action::parse(path.trim_start_matches('/')).unwrap_or_default(),
        idempotency_key: p.text("idempotencyKey"),
        rotate_reason: p.text("reason"),
    })
}

/// One element of `/instances/status-batch` `slots` (old: `null` and `""` meant slot 1).
fn slot_value(value: &Value) -> Result<Slot, ProxyError> {
    match value {
        Value::Null => Ok(Slot::DEFAULT),
        Value::String(s) if s.is_empty() => Ok(Slot::DEFAULT),
        Value::String(s) => Slot::parse(s),
        Value::Number(n) => Slot::parse(&number_text(n)),
        // Slot 0 is out of range: the same 400 as any other bad slot.
        _ => Slot::new(0),
    }
}

/// Text form of `/list`: one TAB-separated line per profile (id, country, protocol,
/// server:port, status, lastCheckedAt, `active`, name).
fn profile_lines(rows: &[ProfileRow]) -> String {
    rows.iter()
        .map(|r| {
            [
                r.id.clone(),
                r.country.clone().unwrap_or_default(),
                r.protocol.clone(),
                format!("{}:{}", r.server, r.port),
                wire_name(&r.status),
                r.last_checked_at.map(|t| t.to_string()).unwrap_or_default(),
                if r.active { "active" } else { "" }.to_owned(),
                r.name.clone(),
            ]
            .join("\t")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The serde name of a unit enum value (`healthy`, `online`, …).
fn wire_name<T: serde::Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(s)) => s,
        _ => String::new(),
    }
}
