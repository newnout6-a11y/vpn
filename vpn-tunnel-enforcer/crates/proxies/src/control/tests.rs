//! Control API tests: pure pipeline checks and real HTTP over an ephemeral loopback port.
//! Discovery files go to a throw-away temp dir, never to the real data dir or port 17873.
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use vpnte_base::ErrorKind;

use super::client::{self, ControlUrl, Reply};
use super::http::Head;
use super::router::{self, Gate};
use super::*;
use crate::model::{
    Aggregate, BatchStartResult, GroupHealth, Health, InstanceStatus, Instances, InstancesBatch,
    KeyHealth, PrewarmResult, ProfileRow, ProxyError, ProxyStatus, Released, Reservation,
    ReserveRequest, ServerStatus, StartRequest, StopReason, StopScope, Unlimited,
};
use crate::slot::{Slot, loopback_url};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// What the fake was asked to do.
#[derive(Debug, Clone, PartialEq)]
enum Call {
    Status(Slot),
    Instances,
    Batch(Option<Vec<Slot>>),
    Check(Slot),
    List(Option<String>),
    Group(String),
    Start(StartRequest),
    StartProfiles(Vec<String>),
    Prewarm(u64, Option<String>),
    Stop(Slot, StopReason),
    Reserve(ReserveRequest),
    Renew(String, Option<f64>),
    Release(String),
}

/// Records calls and answers with canned data; `error` makes fallible operations fail.
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<Call>>,
    control_port: Mutex<Option<u16>>,
    error: Mutex<Option<ProxyError>>,
}

impl Fake {
    fn record(&self, call: Call) {
        self.calls.lock().push(call);
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }

    fn fail_with(&self, err: ProxyError) {
        *self.error.lock() = Some(err);
    }

    fn outcome(&self) -> Result<(), ProxyError> {
        self.error.lock().clone().map_or(Ok(()), Err)
    }
}

/// A running, healthy slot on its default port.
fn running(slot: Slot) -> InstanceStatus {
    let port = slot.default_port();
    InstanceStatus {
        running: true,
        process_running: true,
        ready: true,
        health: Health::Healthy,
        port: Some(port),
        proxy_url: Some(loopback_url(port)),
        ..InstanceStatus::stopped(slot)
    }
}

fn status_of(instance: InstanceStatus) -> ProxyStatus {
    ProxyStatus {
        instance: instance.clone(),
        control_host: crate::slot::CONTROL_HOST.into(),
        control_port: Some(17873),
        control_url: Some("http://127.0.0.1:17873".into()),
        max_instances: Unlimited,
        instances: vec![instance],
        aggregate: Aggregate::default(),
    }
}

fn reservation(token: &str) -> Reservation {
    let instance = running(Slot::DEFAULT);
    Reservation {
        lease_token: token.into(),
        owner: "buyer-worker-1".into(),
        expires_at: 1_762_800_000_000,
        slot: Slot::DEFAULT,
        proxy_url: instance.proxy_url.clone(),
        egress_ip: Some("198.51.100.2".parse().unwrap()),
        generation: 1,
        instance,
    }
}

#[async_trait::async_trait]
impl ProxyOps for Fake {
    fn set_control_port(&self, port: u16) {
        *self.control_port.lock() = Some(port);
    }
    async fn status(&self, slot: Slot) -> ProxyStatus {
        self.record(Call::Status(slot));
        status_of(InstanceStatus::stopped(slot))
    }
    async fn instances(&self) -> Instances {
        self.record(Call::Instances);
        let (a, b) = (running(Slot::DEFAULT), running(Slot::new(2).unwrap()));
        let mut stopped = InstanceStatus::stopped(Slot::new(3).unwrap());
        stopped.proxy_url = Some(loopback_url(17992));
        Instances {
            max_instances: Unlimited,
            instances: vec![a, b, stopped],
            aggregate: Aggregate::default(),
            control_url: None,
        }
    }
    async fn status_batch(&self, slots: Option<Vec<Slot>>) -> InstancesBatch {
        self.record(Call::Batch(slots));
        InstancesBatch {
            instances: Vec::new(),
            aggregate: Aggregate {
                ready: 2,
                ..Aggregate::default()
            },
        }
    }
    async fn check_health(&self, slot: Slot) -> InstanceStatus {
        self.record(Call::Check(slot));
        running(slot)
    }
    async fn list(&self, country: Option<String>) -> Vec<ProfileRow> {
        self.record(Call::List(country));
        vec![ProfileRow {
            id: "profile-1".into(),
            name: "sample".into(),
            country: Some("Netherlands".into()),
            protocol: "vless".into(),
            server: "203.0.113.10".into(),
            port: 443,
            group_id: None,
            status: ServerStatus::Unknown,
            ping_ms: None,
            health_latency_ms: None,
            health_reason: None,
            last_checked_at: Some(1_762_800_000_000),
            selected_for_vpn: false,
            active: true,
            active_slots: vec![Slot::DEFAULT],
        }]
    }
    async fn check_group_health(&self, group_id: String) -> Result<GroupHealth, ProxyError> {
        self.record(Call::Group(group_id));
        self.outcome()?;
        let key = |id: &str, online| KeyHealth {
            profile_id: id.into(),
            online,
            latency_ms: None,
            reason: None,
            egress_ip: None,
            country: None,
        };
        Ok(GroupHealth {
            ok: true,
            results: vec![key("a", true), key("b", false), key("c", true)],
        })
    }
    async fn start(&self, req: StartRequest) -> Result<ProxyStatus, ProxyError> {
        self.record(Call::Start(req.clone()));
        self.outcome()?;
        let slot = req.slot.unwrap_or(Slot::DEFAULT);
        let mut instance = running(slot);
        if let Some(port) = req.port {
            instance.port = Some(port);
            instance.proxy_url = Some(loopback_url(port));
        }
        Ok(status_of(instance))
    }
    async fn add(&self, _profile_id: String) -> Result<ProxyStatus, ProxyError> {
        unreachable!("the control API has no add endpoint")
    }
    async fn start_profiles(&self, profile_ids: Vec<String>) -> BatchStartResult {
        self.record(Call::StartProfiles(profile_ids.clone()));
        BatchStartResult {
            requested: profile_ids.len() as u32,
            started: vec![running(Slot::DEFAULT), running(Slot::new(2).unwrap())],
            ..BatchStartResult::default()
        }
    }
    async fn prewarm(
        &self,
        count: u64,
        country: Option<String>,
    ) -> Result<PrewarmResult, ProxyError> {
        self.record(Call::Prewarm(count, country));
        self.outcome()?;
        Ok(PrewarmResult {
            requested: count as u32,
            started: Vec::new(),
            instances: Vec::new(),
            aggregate: Aggregate {
                ready: 3,
                ..Aggregate::default()
            },
            ready: false,
        })
    }
    async fn stop(&self, slot: Slot, reason: StopReason) -> Result<ProxyStatus, ProxyError> {
        self.record(Call::Stop(slot, reason));
        self.outcome()?;
        Ok(status_of(InstanceStatus::stopped(slot)))
    }
    async fn stop_all(&self, _scope: StopScope, _reason: StopReason) -> ProxyStatus {
        unreachable!("the control API has no stop-all endpoint")
    }
    async fn reserve(&self, req: ReserveRequest) -> Result<Reservation, ProxyError> {
        self.record(Call::Reserve(req));
        self.outcome()?;
        Ok(reservation("lease-token-1"))
    }
    async fn renew(&self, token: String, ttl: Option<f64>) -> Result<Reservation, ProxyError> {
        self.record(Call::Renew(token.clone(), ttl));
        self.outcome()?;
        Ok(reservation(&token))
    }
    async fn release(&self, token: String) -> Result<Released, ProxyError> {
        self.record(Call::Release(token));
        self.outcome()?;
        Ok(Released {
            released: true,
            slot: Slot::DEFAULT,
        })
    }
}

fn fake() -> Arc<Fake> {
    Arc::new(Fake::default())
}

fn shared(fake: &Arc<Fake>) -> Shared {
    Shared::new(fake.clone(), ControlToken::fixed(TOKEN), 17873)
}

fn head(method: &str, target: &str, headers: &[(&str, &str)]) -> Head {
    Head {
        method: method.into(),
        target: target.into(),
        headers: headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), (*v).to_owned()))
            .collect(),
    }
}

/// Gate, body and endpoint, as the server runs them, for an authenticated loopback request.
async fn call(shared: &Shared, method: &str, target: &str, body: &str) -> Response {
    let head = head(
        method,
        target,
        &[("Host", "127.0.0.1:17873"), (TOKEN_HEADER, TOKEN)],
    );
    match router::gate(shared, &head) {
        Gate::Respond(response) => response,
        Gate::Proceed(route) => match router::parse_body(body.as_bytes()) {
            Ok(body) => router::dispatch(shared, &route, &body).await,
            Err(err) => router::error_response(&route.path, &err, route.text),
        },
    }
}

fn json_of(response: &Response) -> Value {
    serde_json::from_str(&response.body).unwrap()
}

fn gate_response(shared: &Shared, head: &Head) -> Response {
    match router::gate(shared, head) {
        Gate::Respond(response) => response,
        Gate::Proceed(route) => panic!("expected an answer, got {route:?}"),
    }
}

/// AT-01-005 (spec §7.14): only `127.0.0.1:<bound>` / `localhost:<bound>` pass the Host guard.
#[test]
fn trusted_host_vectors() {
    assert!(is_trusted_host(Some("127.0.0.1:17873"), 17873));
    assert!(is_trusted_host(Some("localhost:17873"), 17873));
    assert!(is_trusted_host(Some(" LocalHost:17873 "), 17873));
    assert!(!is_trusted_host(Some("attacker.example:17873"), 17873));
    assert!(!is_trusted_host(Some("127.0.0.1:9999"), 17873));
    assert!(!is_trusted_host(None, 17873));
    assert!(!is_trusted_host(Some("127.0.0.1"), 17873));
    assert!(!is_trusted_host(Some("127.0.0.1:0"), 0));
}

/// Spec §7.10: the mutation paths (POST only).
#[test]
fn mutation_paths() {
    for path in [
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
        "/instances/reserve",
        "/instances/renew",
        "/instances/release",
    ] {
        assert!(is_mutation_path(path), "{path}");
    }
    for path in ["/status", "/list", "/", "/instances"] {
        assert!(!is_mutation_path(path), "{path}");
    }
}

/// Spec §7.10: token comparison (empty never matches).
#[test]
fn token_compare() {
    let token = ControlToken::fixed("abc123");
    assert!(token.matches("abc123"));
    assert!(!token.matches("abc124"));
    assert!(!token.matches(""));
    assert!(!token.matches("abc1234"));
    assert!(!ControlToken::fixed("").matches("abc123"));
    let fresh = ControlToken::generate().unwrap();
    assert_eq!(fresh.as_str().len(), 64);
    assert!(
        fresh
            .as_str()
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_ne!(fresh, ControlToken::generate().unwrap());
    assert_eq!(format!("{fresh:?}"), "ControlToken(..)");
}

/// The token comes from the token header or `Authorization: Bearer`.
#[test]
fn token_extraction() {
    let with = |headers: &[(&str, &str)]| {
        let h = head("GET", "/status", headers);
        router::request_token(&h).map(str::to_owned)
    };
    assert_eq!(with(&[(TOKEN_HEADER, "abc")]).as_deref(), Some("abc"));
    assert_eq!(
        with(&[("X-VPNTE-Control-Token", "abc")]).as_deref(),
        Some("abc")
    );
    assert_eq!(
        with(&[("Authorization", "bearer   abc ")]).as_deref(),
        Some("abc")
    );
    assert_eq!(
        with(&[(TOKEN_HEADER, ""), ("Authorization", "Bearer x")]).as_deref(),
        Some("x")
    );
    assert_eq!(with(&[("Authorization", "Bearer")]), None);
    assert_eq!(with(&[("Authorization", "Bearerabc")]), None);
    assert_eq!(with(&[("Authorization", "Basic abc")]), None);
    assert_eq!(with(&[]), None);
}

/// AT-01-005: untrusted or missing Host headers get 421 with the old body, before anything else.
#[test]
fn untrusted_hosts_get_421() {
    let fake = fake();
    let shared = shared(&fake);
    let expected = json!({
        "ok": false,
        "error": "untrusted-host",
        "detail": "Host header must target the loopback control endpoint"
    });
    let cases: [&[(&str, &str)]; 6] = [
        &[("Host", "evil.attacker.tld:17873")],
        &[("Host", "2130706433:17873")],
        &[("Host", "[::1]:17873")],
        &[("Host", "127.0.0.1")],
        &[],
        &[("Host", "127.0.0.1:17873"), ("Host", "evil:17873")],
    ];
    for headers in cases {
        let r = gate_response(&shared, &head("OPTIONS", "/status", headers));
        assert_eq!(
            (r.status, json_of(&r)),
            (421, expected.clone()),
            "{headers:?}"
        );
    }
    assert!(fake.calls().is_empty());
}

/// OPTIONS is answered (204, CORS headers, no body) for any path before method and token checks.
#[test]
fn options_answers_204() {
    let fake = fake();
    let r = gate_response(
        &shared(&fake),
        &head("OPTIONS", "/nope", &[("Host", "localhost:17873")]),
    );
    assert_eq!(r.status, 204);
    let wire = String::from_utf8(r.to_bytes()).unwrap();
    assert!(wire.starts_with("HTTP/1.1 204 No Content\r\n"), "{wire}");
    assert!(wire.contains("Access-Control-Allow-Origin: http://127.0.0.1\r\n"));
    assert!(wire.contains("Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"));
    assert!(wire.contains(
        "Access-Control-Allow-Headers: Content-Type, x-vpnte-control-token, Authorization\r\n"
    ));
    assert!(wire.contains("Vary: Origin\r\n"));
    assert!(!wire.contains("Content-Length"));
    assert!(wire.ends_with("\r\n\r\n"));
}

/// Response framing: pretty JSON without a trailing newline, text with one, always a length.
#[test]
fn response_framing() {
    let r = Response::json(200, &json!({"a": 1}));
    let wire = String::from_utf8(r.to_bytes()).unwrap();
    assert!(
        wire.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n")
    );
    assert!(
        wire.ends_with("Content-Length: 12\r\nConnection: close\r\n\r\n{\n  \"a\": 1\n}"),
        "{wire}"
    );
    let wire = String::from_utf8(Response::text(409, "busy").to_bytes()).unwrap();
    assert!(
        wire.starts_with("HTTP/1.1 409 Conflict\r\nContent-Type: text/plain; charset=utf-8\r\n")
    );
    assert!(
        wire.ends_with("Content-Length: 5\r\nConnection: close\r\n\r\nbusy\n"),
        "{wire}"
    );
}

/// Old pipeline: mutations are POST only, reads GET only, every real endpoint needs the token,
/// unknown GETs are a JSON 404 even in text mode.
#[tokio::test]
async fn methods_tokens_and_unknown_paths() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(&shared, "GET", "/start", "").await;
    assert_eq!(
        (r.status, json_of(&r)),
        (
            405,
            json!({"ok": false, "error": "method-not-allowed", "detail": "method-not-allowed"})
        )
    );
    let r = call(&shared, "GET", "/start?format=text", "").await;
    assert_eq!(
        (r.status, r.text, r.body.as_str()),
        (405, true, "method-not-allowed")
    );
    assert_eq!(call(&shared, "GET", "/healthcheck", "").await.status, 405);
    assert_eq!(call(&shared, "POST", "/status", "").await.status, 405);
    assert_eq!(call(&shared, "POST", "/nope", "").await.status, 405);
    let r = call(&shared, "GET", "/nope?format=text", "").await;
    assert_eq!(
        (r.status, r.text, json_of(&r)),
        (
            404,
            false,
            json!({"ok": false, "error": "not-found", "detail": "not-found"})
        )
    );

    let anonymous = head("GET", "/status", &[("Host", "127.0.0.1:17873")]);
    let r = gate_response(&shared, &anonymous);
    assert_eq!(
        (r.status, json_of(&r)),
        (
            401,
            json!({"ok": false, "error": "unauthorized", "detail": "unauthorized"})
        )
    );
    let r = gate_response(
        &shared,
        &head(
            "GET",
            "/list?text=1",
            &[("Host", "127.0.0.1:17873"), (TOKEN_HEADER, "wrong")],
        ),
    );
    assert_eq!((r.status, r.body.as_str()), (401, "unauthorized"));
    let bearer = head(
        "GET",
        "/status",
        &[
            ("Host", "127.0.0.1:17873"),
            ("Authorization", &format!("Bearer {TOKEN}")),
        ],
    );
    assert!(matches!(router::gate(&shared, &bearer), Gate::Proceed(_)));
    assert!(fake.calls().is_empty());
}

/// `/status` and `/` (optional `/api/external-proxy` prefix), JSON and text; bad slots are 400.
#[tokio::test]
async fn status_endpoint() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(&shared, "GET", "/api/external-proxy/status?slot=2", "").await;
    let body = json_of(&r);
    assert_eq!(
        (r.status, &body["slot"], &body["maxInstances"]),
        (200, &json!(2), &Value::Null)
    );
    assert_eq!(body["controlUrl"], "http://127.0.0.1:17873");
    let r = call(&shared, "GET", "/?format=text&slot=", "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "stopped"));
    let r = call(&shared, "GET", "/status?slot=0", "").await;
    assert_eq!(
        (r.status, json_of(&r)["detail"].as_str()),
        (400, Some("external proxy slot must be between 1 and 47546"))
    );
    assert_eq!(
        fake.calls(),
        [
            Call::Status(Slot::new(2).unwrap()),
            Call::Status(Slot::DEFAULT)
        ]
    );
}

/// `/instances` text lists only running instances with a URL (`<slot>\t<url>`).
#[tokio::test]
async fn instances_endpoint() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(&shared, "GET", "/instances?format=text", "").await;
    assert_eq!(
        r.body,
        "1\thttp://127.0.0.1:17990\n2\thttp://127.0.0.1:17991"
    );
    let r = call(&shared, "GET", "/instances", "").await;
    let body = json_of(&r);
    assert_eq!(
        (
            &body["maxInstances"],
            body["instances"].as_array().map(Vec::len)
        ),
        (&Value::Null, Some(3))
    );
}

/// Start parameters: query first, then body; `profileId` before `id`; trigger = connect.
#[tokio::test]
async fn start_parameters() {
    let fake = fake();
    let shared = shared(&fake);
    let body = r#"{"slot": 3, "country": " de ", "id": "p-9", "port": 18000, "idempotencyKey": "k1", "reason": "test"}"#;
    let r = call(&shared, "POST", "/start?slot=2", body).await;
    assert_eq!((r.status, json_of(&r)["port"].as_u64()), (200, Some(18000)));
    let r = call(
        &shared,
        "POST",
        "/trigger?profileId=p-1&id=p-2&port=&format=text",
        "",
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (200, "http://127.0.0.1:17990"));
    let calls = fake.calls();
    assert_eq!(
        calls[0],
        Call::Start(StartRequest {
            slot: Some(Slot::new(2).unwrap()),
            country: Some("de".into()),
            profile_id: Some("p-9".into()),
            port: Some(18000),
            action: crate::model::Action::Start,
            idempotency_key: Some("k1".into()),
            rotate_reason: Some("test".into()),
        })
    );
    assert_eq!(
        calls[1],
        Call::Start(StartRequest {
            slot: Some(Slot::DEFAULT),
            profile_id: Some("p-1".into()),
            action: crate::model::Action::Connect,
            ..StartRequest::default()
        })
    );
}

/// B-12: bad input is a precise 400 instead of a silent default or a 500.
#[tokio::test]
async fn bad_input_is_400() {
    let fake = fake();
    let shared = shared(&fake);
    let detail = |r: &Response| json_of(r)["detail"].as_str().unwrap_or_default().to_owned();
    let r = call(&shared, "POST", "/start?port=abc", "").await;
    assert_eq!(
        (r.status, json_of(&r)["error"].as_str(), detail(&r).as_str()),
        (400, Some("external-proxy-error"), "invalid port")
    );
    let r = call(&shared, "POST", "/start?port=0&format=text", "").await;
    assert_eq!((r.status, r.body.as_str()), (400, "invalid port"));
    let r = call(&shared, "POST", "/instances/reserve", "{owner").await;
    assert_eq!((r.status, detail(&r).as_str()), (400, "invalid JSON body"));
    for body in ["null", "[1]", "\"x\""] {
        let r = call(&shared, "POST", "/instances/reserve", body).await;
        assert_eq!(
            (r.status, detail(&r).as_str()),
            (400, "JSON body must be an object")
        );
    }
    let r = call(&shared, "POST", "/instances/prewarm", " \n").await;
    assert_eq!((r.status, detail(&r).as_str()), (400, "count is required"));
    for count in ["abc", "0", "1.5", "47547"] {
        let r = call(
            &shared,
            "POST",
            &format!("/instances/prewarm?count={count}"),
            "",
        )
        .await;
        assert_eq!(
            (r.status, detail(&r).as_str()),
            (400, "count must be between 1 and 47546"),
            "{count}"
        );
    }
    let r = call(
        &shared,
        "POST",
        "/instances/reserve?owner=w&preferredEgressIp=not-an-ip",
        "",
    )
    .await;
    assert_eq!(
        (r.status, detail(&r).as_str()),
        (400, "preferredEgressIp must be an IP address")
    );
    let r = call(&shared, "POST", "/instances/reserve?owner=w&slot=", "").await;
    assert_eq!(r.status, 400);
    assert!(fake.calls().is_empty(), "{:?}", fake.calls());
}

/// AT-00-004 (spec §7.1): group health failures keep their category as the HTTP status and
/// expose only the generic message (JSON and text); a missing group id is a 400.
#[tokio::test]
async fn group_health_mapping() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(
        &shared,
        "POST",
        "/profiles/healthcheck?groupId=g&format=text",
        "",
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (200, "2/3"));
    for (kind, status, code) in [
        (ErrorKind::Conflict, 409, "conflict"),
        (ErrorKind::Permission, 403, "forbidden"),
        (ErrorKind::Validation, 404, "external-proxy-error"),
        (ErrorKind::Timeout, 504, "external-proxy-error"),
    ] {
        let err = ProxyError::group_health(kind);
        fake.fail_with(err.clone());
        let r = call(&shared, "POST", "/profiles/healthcheck?groupId=g", "").await;
        assert_eq!(
            (r.status, json_of(&r)),
            (
                status,
                json!({"ok": false, "error": code, "detail": err.detail()})
            )
        );
        let r = call(
            &shared,
            "POST",
            "/profiles/healthcheck?groupId=g&format=text",
            "",
        )
        .await;
        assert_eq!((r.status, r.body.as_str()), (status, err.detail()));
    }
    let r = call(
        &shared,
        "POST",
        "/profiles/healthcheck",
        r#"{"groupId": "  "}"#,
    )
    .await;
    assert_eq!(
        (r.status, json_of(&r)["detail"].as_str()),
        (400, Some("groupId is required"))
    );
    assert_eq!(fake.calls().first(), Some(&Call::Group("g".into())));
}

/// `/connect-profiles` takes `profileIds` from the body only (trimmed strings).
#[tokio::test]
async fn connect_profiles() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(
        &shared,
        "POST",
        "/connect-profiles?format=text",
        r#"{"profileIds": [" a ", "", 5, "b"]}"#,
    )
    .await;
    assert_eq!(
        (r.status, r.body.as_str()),
        (200, "http://127.0.0.1:17990\nhttp://127.0.0.1:17991")
    );
    for body in ["", r#"{"profileIds": []}"#, r#"{"profileIds": "a"}"#] {
        let r = call(&shared, "POST", "/connect-profiles?profileIds=a", body).await;
        assert_eq!(
            (r.status, json_of(&r)["detail"].as_str()),
            (
                400,
                Some("profileIds must be a non-empty array of profile IDs")
            )
        );
    }
    assert_eq!(
        fake.calls(),
        [Call::StartProfiles(vec!["a".into(), "b".into()])]
    );
}

/// Prewarm and status-batch answer `aggregate.ready` in text mode.
#[tokio::test]
async fn prewarm_and_status_batch() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(
        &shared,
        "POST",
        "/instances/prewarm?format=text",
        r#"{"count": 30, "country": "nl"}"#,
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (200, "3"));
    let r = call(&shared, "POST", "/instances/prewarm?count=2.0", "").await;
    assert_eq!(json_of(&r)["requested"], 2);
    let r = call(
        &shared,
        "POST",
        "/instances/status-batch?text=1",
        r#"{"slots": [1, "2", null, ""]}"#,
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (200, "2"));
    call(
        &shared,
        "POST",
        "/instances/status-batch",
        r#"{"slots": true}"#,
    )
    .await;
    call(&shared, "POST", "/instances/status-batch", "").await;
    let r = call(
        &shared,
        "POST",
        "/instances/status-batch",
        r#"{"slots": [0]}"#,
    )
    .await;
    assert_eq!(r.status, 400);
    let r = call(
        &shared,
        "POST",
        "/instances/status-batch",
        r#"{"slots": [{}]}"#,
    )
    .await;
    assert_eq!(r.status, 400);
    let (one, two) = (Slot::DEFAULT, Slot::new(2).unwrap());
    assert_eq!(
        fake.calls(),
        [
            Call::Prewarm(30, Some("nl".into())),
            Call::Prewarm(2, None),
            Call::Batch(Some(vec![one, two, one, one])),
            Call::Batch(None),
            Call::Batch(None),
        ]
    );
}

/// Reserve parameters; `allowFallback` is off only for `false` / `"false"`, body first.
#[tokio::test]
async fn reserve_parameters() {
    let fake = fake();
    let shared = shared(&fake);
    let query = "/instances/reserve?format=text&owner=w1&ttlSeconds=120&preferredEgressIp=198.51.100.2&preferredSlot=2&slot=3";
    let r = call(&shared, "POST", query, "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "http://127.0.0.1:17990"));
    let fallback = [
        ("", r#"{"owner": "w"}"#, true),
        ("", r#"{"owner": "w", "allowFallback": false}"#, false),
        ("", r#"{"owner": "w", "allowFallback": "FALSE"}"#, false),
        ("&allowFallback=false", "", false),
        ("&allowFallback=false", r#"{"allowFallback": null}"#, false),
        ("&allowFallback=false", r#"{"allowFallback": true}"#, true),
        ("", r#"{"owner": "w", "allowFallback": 0}"#, true),
    ];
    for (q, body, _) in fallback {
        let r = call(
            &shared,
            "POST",
            &format!("/instances/reserve?owner=w{q}"),
            body,
        )
        .await;
        assert_eq!(r.status, 200);
    }
    let calls = fake.calls();
    assert_eq!(
        calls[0],
        Call::Reserve(ReserveRequest {
            owner: "w1".into(),
            ttl_secs: Some(120.0),
            preferred_egress_ip: Some("198.51.100.2".parse().unwrap()),
            preferred_slot: Some(Slot::new(2).unwrap()),
            slot: Some(Slot::new(3).unwrap()),
            allow_fallback: true,
        })
    );
    for (call, (q, body, expected)) in calls[1..].iter().zip(fallback) {
        let Call::Reserve(req) = call else {
            panic!("{call:?}")
        };
        assert_eq!(req.allow_fallback, expected, "{q} {body}");
        assert_eq!(
            (req.owner.as_str(), req.ttl_secs, req.preferred_egress_ip),
            ("w", None, None)
        );
    }
    let r = call(
        &shared,
        "POST",
        "/instances/reserve",
        r#"{"owner": "w", "ttlSeconds": "abc"}"#,
    )
    .await;
    assert_eq!(r.status, 200);
    let Some(Call::Reserve(req)) = fake.calls().pop() else {
        panic!()
    };
    assert!(
        req.ttl_secs.is_some_and(f64::is_nan),
        "unparsable TTL goes to the lease book as NaN"
    );
}

/// Renew / release take the lease token from the query or the body; lease errors keep codes.
#[tokio::test]
async fn renew_and_release() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(
        &shared,
        "POST",
        "/instances/renew",
        r#"{"leaseToken": "t1", "ttlSeconds": 60}"#,
    )
    .await;
    assert_eq!(
        (r.status, json_of(&r)["leaseToken"].as_str()),
        (200, Some("t1"))
    );
    let r = call(
        &shared,
        "POST",
        "/instances/release?leaseToken=t1&format=text",
        "",
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (200, "released"));
    let r = call(&shared, "POST", "/instances/release", "").await;
    assert_eq!(json_of(&r), json!({"released": true, "slot": 1}));
    fake.fail_with(ProxyError::Forbidden(
        "Unknown or expired lease token".into(),
    ));
    let r = call(&shared, "POST", "/instances/release?leaseToken=wrong", "").await;
    assert_eq!(
        (r.status, json_of(&r)["error"].as_str()),
        (403, Some("forbidden"))
    );
    fake.fail_with(ProxyError::Conflict("Leased route is down".into()));
    let r = call(
        &shared,
        "POST",
        "/instances/renew?leaseToken=t1&format=text",
        "",
    )
    .await;
    assert_eq!((r.status, r.body.as_str()), (409, "Leased route is down"));
    let r = call(&shared, "POST", "/start", "").await;
    assert_eq!(
        (r.status, json_of(&r)["error"].as_str()),
        (409, Some("conflict"))
    );
    fake.fail_with(ProxyError::Engine("cannot resolve vpn.example.test".into()));
    let r = call(&shared, "POST", "/stop", "").await;
    assert_eq!(
        (r.status, json_of(&r)["error"].as_str()),
        (500, Some("external-proxy-error"))
    );
    assert_eq!(
        &fake.calls()[..3],
        [
            Call::Renew("t1".into(), Some(60.0)),
            Call::Release("t1".into()),
            Call::Release(String::new()),
        ]
    );
}

/// Stop (reason `api`), forced health check and the profile list in both renderings.
#[tokio::test]
async fn stop_healthcheck_and_list() {
    let fake = fake();
    let shared = shared(&fake);
    let r = call(&shared, "POST", "/stop?slot=2&format=text", "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "stopped"));
    let r = call(&shared, "POST", "/healthcheck?slot=2&format=text", "").await;
    assert_eq!((r.status, r.body.as_str()), (200, "healthy"));
    let r = call(&shared, "GET", "/list?format=text&country=nl", "").await;
    assert_eq!(
        r.body,
        "profile-1\tNetherlands\tvless\t203.0.113.10:443\tunknown\t1762800000000\tactive\tsample"
    );
    let r = call(&shared, "GET", "/list?country=", "").await;
    assert_eq!(json_of(&r)["profiles"][0]["activeSlots"], json!([1]));
    let two = Slot::new(2).unwrap();
    assert_eq!(
        fake.calls(),
        [
            Call::Stop(two, StopReason::Api),
            Call::Check(two),
            Call::List(Some("nl".into())),
            Call::List(None),
        ]
    );
}

/// `VPNTE_CONTROL_PORT`: a valid port disables the fallback; unset, blank or invalid = 17873
/// with the fallback.
#[test]
fn control_port_override() {
    let dir = PathBuf::from("data");
    let config = |raw| ControlConfig::with_override(dir.clone(), raw);
    let default = ControlConfig {
        dir: dir.clone(),
        port: 17873,
        fallback: true,
    };
    assert_eq!(config(None), default);
    assert_eq!(config(Some(" ")), default);
    assert_eq!(config(Some("abc")), default);
    assert_eq!(config(Some("0")), default);
    assert_eq!(
        config(Some(" 18000 ")),
        ControlConfig {
            dir: dir.clone(),
            port: 18000,
            fallback: false
        }
    );
    assert_eq!(ControlConfig::from_env(&dir).dir, dir);
}

/// A throw-away directory under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut suffix = [0u8; 4];
        getrandom::fill(&mut suffix).unwrap();
        let name = format!(
            "vpnte-control-{tag}-{}-{}",
            std::process::id(),
            hex::encode(suffix)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A server on an ephemeral port writing its files to `dir`.
async fn start_server(fake: &Arc<Fake>, dir: &TempDir) -> (ControlServer, CancellationToken) {
    let cancel = CancellationToken::new();
    let config = ControlConfig {
        dir: dir.0.clone(),
        port: 0,
        fallback: false,
    };
    let server = ControlServer::start(fake.clone(), config, cancel.clone())
        .await
        .unwrap();
    (server, cancel)
}

/// Sends raw bytes to 127.0.0.1:`port` and reads the answer (blocking I/O off the runtime).
async fn send(port: u16, raw: Vec<u8>) -> Reply {
    tokio::task::spawn_blocking(move || {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(&raw).unwrap();
        client::read_reply(&mut stream).unwrap()
    })
    .await
    .unwrap()
}

/// Spec §7.11 + §2.8: token and endpoint files in the given dir (the actual bound port), the
/// bound port reported to the manager, authenticated status over real HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_http_and_writes_discovery_files() {
    let (fake, dir) = (fake(), TempDir::new("files"));
    let (server, cancel) = start_server(&fake, &dir).await;
    let port = server.port();
    assert_ne!(port, 0);
    assert_eq!(*fake.control_port.lock(), Some(port));
    assert_eq!(server.url(), format!("http://127.0.0.1:{port}"));

    assert_eq!(server.token_file(), dir.0.join(TOKEN_FILE));
    let raw = std::fs::read_to_string(server.token_file()).unwrap();
    assert!(raw.ends_with('\n') && raw.len() == 65, "{raw:?}");
    let token = read_token(server.token_file()).unwrap();
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));

    let endpoint_file = server.endpoint_file().unwrap();
    assert_eq!(endpoint_file, dir.0.join(ENDPOINT_FILE));
    let text = std::fs::read_to_string(endpoint_file).unwrap();
    assert!(
        text.ends_with("}\n") && text.contains("\n  \"host\": \"127.0.0.1\",\n"),
        "{text}"
    );
    let endpoint: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(endpoint["port"], port);
    assert_eq!(endpoint["url"], format!("http://127.0.0.1:{port}"));
    assert_eq!(
        endpoint["tokenFile"].as_str().map(PathBuf::from),
        Some(dir.0.join(TOKEN_FILE))
    );
    assert!(
        endpoint["updatedAt"]
            .as_i64()
            .is_some_and(|t| t > 1_700_000_000_000)
    );
    assert_eq!(
        client::discover(endpoint_file),
        ControlUrl::parse(&server.url())
    );
    assert!(
        std::fs::read_dir(&dir.0).unwrap().count() == 2,
        "no temp files left behind"
    );

    let url = ControlUrl::parse(&server.url()).unwrap();
    let reply = tokio::task::spawn_blocking(move || {
        let ok = url.request(
            "GET",
            "/status?format=text",
            Some(&token),
            Duration::from_secs(5),
        );
        let anonymous = url.request("POST", "/stop", None, Duration::from_secs(5));
        (ok.unwrap(), anonymous.unwrap())
    })
    .await
    .unwrap();
    assert_eq!(
        reply.0,
        Reply {
            status: 200,
            body: "stopped\n".into()
        }
    );
    assert_eq!(reply.1.status, 401);
    assert_eq!(fake.calls(), [Call::Status(Slot::DEFAULT)]);

    cancel.cancel();
    server.join().await;
    let refused = std::net::TcpStream::connect(("127.0.0.1", port));
    assert!(refused.is_err(), "the listener is closed after cancel");
}

/// AT-01-005; F-038 (spec §7.13): Host allow-list over real HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_allow_list_over_http() {
    let (fake, dir) = (fake(), TempDir::new("hosts"));
    let (server, cancel) = start_server(&fake, &dir).await;
    let port = server.port();
    let request = |host: Option<String>| {
        let host = host.map(|h| format!("Host: {h}\r\n")).unwrap_or_default();
        format!("POST /api/external-proxy/start HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n")
            .into_bytes()
    };
    for host in ["evil.attacker.tld", "2130706433", "[::1]"] {
        let reply = send(port, request(Some(format!("{host}:{port}")))).await;
        assert_eq!(reply.status, 421, "{host}");
        assert!(
            reply.body.contains("untrusted-host")
                && !reply
                    .body
                    .contains(&read_token(server.token_file()).unwrap())
        );
    }
    assert_eq!(send(port, request(None)).await.status, 421);
    for host in ["localhost", "127.0.0.1"] {
        assert_eq!(
            send(port, request(Some(format!("{host}:{port}"))))
                .await
                .status,
            401,
            "{host}"
        );
    }
    assert!(fake.calls().is_empty());
    cancel.cancel();
}

/// AT-00-004 (spec §7.1) over real HTTP with the token read from the written token file; the
/// same request without the token is a 401 and never reaches the group health check.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn group_health_over_http() {
    let (fake, dir) = (fake(), TempDir::new("group"));
    let (server, cancel) = start_server(&fake, &dir).await;
    let port = server.port();
    let token = read_token(server.token_file()).unwrap();
    let request = |format: &str, token: Option<&str>| {
        let token = token
            .map(|t| format!("x-vpnte-control-token: {t}\r\n"))
            .unwrap_or_default();
        format!(
            "POST /profiles/healthcheck?groupId=g&format={format} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{token}Content-Length: 0\r\n\r\n"
        )
        .into_bytes()
    };
    let conflict = ProxyError::group_health(ErrorKind::Conflict);
    fake.fail_with(conflict.clone());
    for format in ["json", "text"] {
        let reply = send(port, request(format, Some(&token))).await;
        assert_eq!(reply.status, 409);
        assert!(reply.body.contains(conflict.detail()), "{}", reply.body);
    }
    let permission = ProxyError::group_health(ErrorKind::Permission);
    fake.fail_with(permission.clone());
    let reply = send(port, request("json", Some(&token))).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains(permission.detail()));
    assert!(!reply.body.contains("FAKE-SECRET") && !reply.body.contains("private"));
    fake.fail_with(ProxyError::group_health(ErrorKind::Validation));
    assert_eq!(send(port, request("json", Some(&token))).await.status, 404);
    let calls = fake.calls().len();
    assert_eq!(send(port, request("json", None)).await.status, 401);
    assert_eq!(
        fake.calls().len(),
        calls,
        "no group check without the token"
    );
    cancel.cancel();
}

/// Bodies: over 64 KiB is a 413 (B-13), chunked bodies and `Expect: 100-continue` work,
/// garbage is a 400.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_bodies_over_http() {
    let (fake, dir) = (fake(), TempDir::new("bodies"));
    let (server, cancel) = start_server(&fake, &dir).await;
    let port = server.port();
    let head = |extra: &str| {
        format!(
            "POST /instances/reserve HTTP/1.1\r\nHost: localhost:{port}\r\n{TOKEN_HEADER}: {}\r\n{extra}\r\n",
            read_token(server.token_file()).unwrap()
        )
    };
    let mut big = head(&format!("Content-Length: {}\r\n", 64 * 1024 + 1)).into_bytes();
    big.extend(std::iter::repeat_n(b' ', 64 * 1024 + 1));
    let reply = send(port, big).await;
    assert_eq!(reply.status, 413);
    assert!(reply.body.contains("payload-too-large"));

    let body = r#"{"owner": "chunky"}"#;
    let chunked = format!(
        "{}{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        head("Transfer-Encoding: chunked\r\n"),
        5,
        &body[..5],
        body.len() - 5,
        &body[5..]
    );
    assert_eq!(send(port, chunked.into_bytes()).await.status, 200);
    let expect = format!(
        "{}{body}",
        head(&format!(
            "Expect: 100-continue\r\nContent-Length: {}\r\n",
            body.len()
        ))
    );
    let reply = send(port, expect.into_bytes()).await;
    assert_eq!(reply.status, 100, "the interim answer comes first");
    let smuggle = format!(
        "{}{body}",
        head(&format!(
            "Transfer-Encoding: chunked\r\nContent-Length: {}\r\n",
            body.len()
        ))
    );
    assert_eq!(send(port, smuggle.into_bytes()).await.status, 400);
    assert_eq!(send(port, b"NONSENSE\r\n\r\n".to_vec()).await.status, 400);
    let owners: Vec<String> = fake
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::Reserve(req) => Some(req.owner),
            _ => None,
        })
        .collect();
    assert_eq!(owners, ["chunky", "chunky"]);
    cancel.cancel();
}

/// B-23 / §2.18: the listener is exclusive; a busy preferred port falls back to an ephemeral
/// one unless the port was chosen explicitly (then the start fails with a bind error).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn busy_port_fallback() {
    let (fake, dir) = (fake(), TempDir::new("busy"));
    let (first, cancel) = start_server(&fake, &dir).await;
    let busy = first.port();
    let config = |fallback| ControlConfig {
        dir: dir.0.clone(),
        port: busy,
        fallback,
    };
    let second = ControlServer::start(fake.clone(), config(true), cancel.clone())
        .await
        .unwrap();
    assert_ne!(second.port(), busy);
    assert_eq!(*fake.control_port.lock(), Some(second.port()));
    let err = ControlServer::start(fake.clone(), config(false), cancel.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, ServeError::Bind { port, .. } if port == busy),
        "{err}"
    );
    let app: vpnte_base::AppError = err.into();
    assert_eq!(app.user_msg().key, "proxies.control.bindFailed");
    cancel.cancel();
    first.join().await;
    second.join().await;
}

/// Spec §7.16 (and B-20): the CLI only talks to (and only sends the token to) loopback `http`
/// URLs on 127.0.0.1 / localhost; `[::1]` is refused because the server never listens there.
#[test]
fn control_url_validation() {
    let ok = ControlUrl::parse("http://127.0.0.1:17873").unwrap();
    assert_eq!(
        (ok.to_string(), ok.port()),
        ("http://127.0.0.1:17873".into(), 17873)
    );
    let ok = ControlUrl::parse(" http://LOCALHOST:5000/ ").unwrap();
    assert_eq!(ok.to_string(), "http://localhost:5000");
    let ok = ControlUrl::parse("http://127.0.0.1:17873/api/external-proxy//").unwrap();
    assert_eq!(ok.to_string(), "http://127.0.0.1:17873/api/external-proxy");
    assert_eq!(
        ControlUrl::parse("http://localhost").map(|u| u.port()),
        Some(80)
    );
    assert_eq!(
        ControlUrl::local_default().to_string(),
        "http://127.0.0.1:17873"
    );
    for bad in [
        "https://127.0.0.1:17873",
        "http://evil.example:17873",
        "http://127.0.0.1:0",
        "http://[::1]:17873",
        "http://127.0.0.2:17873",
        "http://user:pw@127.0.0.1:17873",
        "http://127.0.0.1:17873/?x=1",
        "127.0.0.1:17873",
        "",
    ] {
        assert_eq!(ControlUrl::parse(bad), None, "{bad}");
    }
}

/// Endpoint discovery: `url` if valid, else `host` + `port`, never a non-loopback address.
#[test]
fn endpoint_discovery() {
    let dir = TempDir::new("discover");
    let file = dir.0.join(ENDPOINT_FILE);
    let discover = |json: &str| {
        std::fs::write(&file, json).unwrap();
        client::discover(&file).map(|u| u.to_string())
    };
    assert_eq!(
        discover(r#"{"url": "http://127.0.0.1:50000/", "port": 1}"#).as_deref(),
        Some("http://127.0.0.1:50000")
    );
    assert_eq!(
        discover(
            "\u{feff}{\"url\": \"http://evil.example:1\", \"host\": \"localhost\", \"port\": 50001}"
        )
        .as_deref(),
        Some("http://localhost:50001")
    );
    assert_eq!(
        discover(r#"{"url": "http://evil.example:1", "host": "evil.example", "port": 2}"#),
        None
    );
    assert_eq!(discover("not json"), None);
    assert_eq!(client::discover(&dir.0.join("missing.json")), None);
    std::fs::write(dir.0.join(TOKEN_FILE), "  abc \r\n").unwrap();
    assert_eq!(read_token(&dir.0.join(TOKEN_FILE)).as_deref(), Some("abc"));
    std::fs::write(dir.0.join(TOKEN_FILE), "\n").unwrap();
    assert_eq!(read_token(&dir.0.join(TOKEN_FILE)), None);
}

/// Answer parsing: `Content-Length` bounds the body even when the peer keeps the connection
/// open; without a length the body runs to EOF.
#[test]
fn reply_parsing() {
    let mut open =
        std::io::Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA".to_vec());
    assert_eq!(
        client::read_reply(&mut open).unwrap(),
        Reply {
            status: 200,
            body: "ok".into()
        }
    );
    let mut eof = std::io::Cursor::new(b"HTTP/1.0 503 Busy\r\n\r\nlater".to_vec());
    assert_eq!(
        client::read_reply(&mut eof).unwrap(),
        Reply {
            status: 503,
            body: "later".into()
        }
    );
    let mut garbage = std::io::Cursor::new(b"SSH-2.0-OpenSSH\r\n\r\n".to_vec());
    assert!(client::read_reply(&mut garbage).is_err());
}

/// The app's wiring (API.md): the real manager behind the real control server. The bound port
/// reaches the manager's statuses and snapshot, and the answers come from the manager (its own
/// validation, the lease book, the group-health mapping). No engine starts: there are no servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_manager_behind_the_control_server() {
    use crate::manager::{EngineChoice, ProfileSource, ProxyManager, ProxyProfile};

    struct NoServers;
    #[async_trait::async_trait]
    impl ProfileSource for NoServers {
        fn profiles(&self) -> Vec<ProxyProfile> {
            Vec::new()
        }
        fn active_vpn_profile_id(&self) -> Option<String> {
            None
        }
        fn engine_choice(&self) -> EngineChoice {
            EngineChoice::default()
        }
        async fn check_group_health(&self, _group: &str) -> vpnte_base::AppResult<GroupHealth> {
            Err(vpnte_base::AppError::new(ErrorKind::Validation))
        }
    }

    let dir = TempDir::new("wiring");
    let manager = ProxyManager::new(Arc::new(NoServers), &dir.0);
    let ops: Arc<dyn ProxyOps> = Arc::new(manager.clone());
    let cancel = CancellationToken::new();
    let config = ControlConfig {
        dir: dir.0.clone(),
        port: 0,
        fallback: false,
    };
    let server = ControlServer::start(ops, config, cancel.clone())
        .await
        .unwrap();
    assert_eq!(manager.snapshot().borrow().control_url, Some(server.url()));
    let url = ControlUrl::parse(&server.url()).unwrap();
    let token = read_token(server.token_file()).unwrap();
    let call = |method: &'static str, path: &'static str| {
        let (url, token) = (url.clone(), token.clone());
        tokio::task::spawn_blocking(move || {
            let timeout = Duration::from_secs(10);
            url.request(method, path, Some(&token), timeout).unwrap()
        })
    };

    let status = call("GET", "/status").await.unwrap();
    assert_eq!(status.status, 200);
    let body: Value = serde_json::from_str(&status.body).unwrap();
    assert_eq!(body["controlPort"], server.port());
    assert_eq!(body["controlUrl"], server.url());
    assert_eq!(body["slot"], 1);
    let connect = call("POST", "/connect?slot=2&format=text").await.unwrap();
    assert_eq!(
        (connect.status, connect.body.trim()),
        (400, "profileId is required for connect/trigger")
    );
    let reserve = call("POST", "/instances/reserve?owner=bot").await.unwrap();
    assert_eq!(reserve.status, 503);
    let group = call("POST", "/profiles/healthcheck?groupId=g")
        .await
        .unwrap();
    let body: Value = serde_json::from_str(&group.body).unwrap();
    assert_eq!(
        (group.status, &body["detail"]),
        (404, &json!("Группа не найдена или пуста"))
    );

    cancel.cancel();
    server.join().await;
    manager.shutdown().await;
}
