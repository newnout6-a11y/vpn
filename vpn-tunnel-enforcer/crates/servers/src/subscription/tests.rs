//! Tests of the subscription fetcher. HTTP runs against a loopback server started by each test;
//! nothing here touches the network, the user's proxies or real data. Credentials are fakes.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::{ClientDevice, ProxyKind};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::{BootstrapRouteMode, ProxyOverride, Settings};
use vpnte_profiles::device::MachineIdentity;

use super::policy::{Refusal, refuse_hop};
use super::*;

/// The synthetic machine of the spec's HWID vectors (servers §7 "HWID / UA").
pub(crate) fn machine() -> MachineIdentity {
    MachineIdentity {
        host_name: "HOST-1".into(),
        user_name: "alice".into(),
        user_domain: "WORKGROUP".into(),
    }
}

pub(crate) const KEY_A: &str = "vless://11111111-1111-4111-8111-111111111111@a.example:443?security=tls&sni=a.example&type=tcp#A";
pub(crate) const KEY_B: &str = "vless://22222222-2222-4222-8222-222222222222@b.example:443?security=tls&sni=b.example&type=tcp#B";

/// One request as the loopback server saw it (header names lower case).
#[derive(Debug, Clone)]
pub(crate) struct Seen {
    pub(crate) path: String,
    headers: Vec<(String, String)>,
}

impl Seen {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the server does with a request: `Some(bytes)` = write them and close, `None` = hold the
/// connection open without answering.
type Handler = Arc<dyn Fn(&Seen) -> Option<Vec<u8>> + Send + Sync>;

/// A loopback HTTP/1.1 server; every connection answers one request and closes.
pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    accepted: Arc<Mutex<usize>>,
    /// Applied before every answer (a slow panel).
    delay: Arc<Mutex<Duration>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    pub(crate) async fn start(
        handler: impl Fn(&Seen) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self::start_with(None, Arc::new(handler)).await
    }

    /// `greeting`: bytes written at once on accept, before reading anything (a non-TLS peer).
    async fn start_with(greeting: Option<&'static [u8]>, handler: Handler) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(0));
        let delay = Arc::new(Mutex::new(Duration::ZERO));
        let (log, count, pause) = (seen.clone(), accepted.clone(), delay.clone());
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                *count.lock() += 1;
                let (log, handler, pause) = (log.clone(), handler.clone(), pause.clone());
                tokio::spawn(async move {
                    if let Some(bytes) = greeting {
                        if !bytes.is_empty() {
                            // Read the client's first flight: closing with unread data sends a
                            // reset on Windows, which would hide what the client makes of `bytes`.
                            let mut first = [0u8; 4096];
                            let _ = socket.read(&mut first).await;
                            let _ = socket.write_all(bytes).await;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                        return;
                    }
                    let Some(req) = read_request(&mut socket).await else {
                        return;
                    };
                    log.lock().push(req.clone());
                    let wait = *pause.lock();
                    tokio::time::sleep(wait).await;
                    match handler(&req) {
                        Some(bytes) => {
                            let _ = socket.write_all(&bytes).await;
                            let _ = socket.shutdown().await;
                        }
                        None => tokio::time::sleep(Duration::from_secs(60)).await,
                    }
                });
            }
        });
        Self {
            addr,
            seen,
            accepted,
            delay,
            task,
        }
    }

    pub(crate) fn url(&self, path: &str) -> Url {
        Url::parse(&format!("http://{}{path}", self.addr)).unwrap()
    }

    pub(crate) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }

    /// Answers from now on after `delay`.
    pub(crate) fn set_delay(&self, delay: Duration) {
        *self.delay.lock() = delay;
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() > 64 * 1024 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some(Seen { path, headers })
}

/// An HTTP/1.1 response with `content-length` and `connection: close`.
pub(crate) fn reply(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Option<Vec<u8>> {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    ));
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    Some(bytes)
}

pub(crate) fn fetcher(routes: Vec<Route>) -> SubscriptionFetcher {
    SubscriptionFetcher::with_plan(
        Hwids::of(&machine(), None),
        RoutePlan { routes, doh: false },
    )
}

fn direct() -> SubscriptionFetcher {
    fetcher(vec![Route::Direct])
}

async fn fetch(f: &SubscriptionFetcher, url: &Url) -> Result<ParseReport, FetchError> {
    f.fetch(url, ClientDevice::Pc, &CancellationToken::new())
        .await
}

/// A port nothing listens on (bound, then released).
pub(crate) async fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Servers §7 #14 (S-20): every form of one subscription maps to one canonical URL.
#[test]
fn canonical_source_unwraps_every_form() {
    let want = "https://example.com/sub/abc";
    for input in [
        "https://example.com/sub/abc",
        "  https://example.com/sub/abc#My%20VPN ",
        "happ://add/https://example.com/sub/abc",
        "happ://add/https%3A%2F%2Fexample.com%2Fsub%2Fabc",
        "happ://add/aHR0cHM6Ly9leGFtcGxlLmNvbS9zdWIvYWJj",
        "mantaray://add/https://example.com/sub/abc",
    ] {
        assert_eq!(
            canonical_source(input).map(String::from).as_deref(),
            Some(want),
            "{input}"
        );
    }
    for input in [
        "",
        "example.com/sub",
        "ftp://example.com/sub",
        "https:example.com",
        KEY_A,
        "https://a.example/x\nhttps://b.example/y",
        "happ://add/vless://11111111-1111-4111-8111-111111111111@a.example:443#A",
    ] {
        assert_eq!(canonical_source(input), None, "{input}");
    }
}

/// Servers §7 #19: `Location` values panels really send.
#[test]
fn redirect_targets_are_normalised() {
    let base = Url::parse("https://a.test/s").unwrap();
    for loc in [
        "<https://b.test/x>",
        "\"https://b.test/x\"",
        "URL: https://b.test/x",
        "url=https://b.test/x",
        "https%3A%2F%2Fb.test%2Fx",
        "  https://b.test/x  ",
    ] {
        assert_eq!(
            normalize_redirect(loc, &base).as_deref(),
            Some("https://b.test/x"),
            "{loc}"
        );
    }
    let norm = |loc| normalize_redirect(loc, &base);
    assert_eq!(norm("//cdn.test/x").as_deref(), Some("https://cdn.test/x"));
    assert_eq!(norm("/y").as_deref(), Some("https://a.test/y"));
    assert_eq!(
        norm("happ://add/https://b.test/x").as_deref(),
        Some("happ://add/https://b.test/x")
    );
    assert_eq!(norm("100%.txt").as_deref(), Some("https://a.test/100%.txt"));
    assert_eq!(norm("   "), None);
}

/// Servers §7 #19 (new, S-29): no https -> http downgrade, no public -> private hop.
#[test]
fn redirect_policy_refuses_downgrade_and_private_targets() {
    let from = Url::parse("https://a.test/s").unwrap();
    let http = Url::parse("http://b.test/x").unwrap();
    assert_eq!(
        refuse_hop(&from, &http, true, &[]),
        Some(Refusal::Downgrade)
    );
    assert_eq!(
        refuse_hop(&from, &http, false, &[]),
        Some(Refusal::Downgrade)
    );
    let private = Url::parse("https://10.0.0.1/").unwrap();
    let ip = policy::literal_ip(&private).unwrap();
    assert_eq!(
        refuse_hop(&from, &private, true, &[ip]),
        Some(Refusal::PrivateTarget)
    );
    // A subscription the user typed in the LAN may redirect inside the LAN.
    assert_eq!(refuse_hop(&from, &private, false, &[ip]), None);
    let local = Url::parse("https://api.localhost/x").unwrap();
    assert_eq!(
        refuse_hop(&from, &local, true, &[]),
        Some(Refusal::PrivateTarget)
    );
    let public = Url::parse("https://cdn.test/x").unwrap();
    let addrs = ["93.184.216.34".parse().unwrap()];
    assert_eq!(refuse_hop(&from, &public, true, &addrs), None);
    let poisoned = [
        "93.184.216.34".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
    ];
    assert_eq!(
        refuse_hop(&from, &public, true, &poisoned),
        Some(Refusal::PrivateTarget)
    );
    let plain = Url::parse("http://a.test/s").unwrap();
    assert_eq!(refuse_hop(&plain, &http, true, &[]), None);
}

/// Servers §7 #4 / #13 (S-23): what an answer without profiles was.
#[test]
fn bodies_without_profiles_are_classified() {
    use crate::model::BodyKind::*;
    let unparseable = FetchOutcome::Unparseable;
    assert_eq!(classify_body(""), FetchOutcome::EmptyList);
    assert_eq!(classify_body(" \r\n\r\n "), FetchOutcome::EmptyList);
    assert_eq!(
        classify_body("#profile-title: X\n#subscription-userinfo: upload=1\n"),
        FetchOutcome::EmptyList
    );
    assert_eq!(
        classify_body("<html>Subscription expired</html>"),
        unparseable(Html)
    );
    assert_eq!(
        classify_body("{\"error\":\"user not found\"}"),
        unparseable(Json)
    );
    assert_eq!(
        classify_body("callback({'outbounds' : []})"),
        unparseable(Json)
    );
    assert_eq!(classify_body(&"QUFB".repeat(20)), unparseable(Base64));
    assert_eq!(classify_body("ssr://unsupported-entry"), unparseable(Uris));
    assert_eq!(classify_body("Forbidden"), unparseable(Other));
}

/// Servers §7 "HWID / UA": the Electron HWIDs bit for bit; one HWID in UA and header (S-44).
#[test]
fn hwids_and_identity_headers_match_the_vectors() {
    let ids = Hwids::of(&machine(), None);
    assert_eq!(ids.get(ClientDevice::Pc), "99c6d48e9a5a5e32");
    assert_eq!(ids.get(ClientDevice::Android), "2ed2387177b3e714");
    assert_eq!(ids.get(ClientDevice::Ios), "00ba16f6d8390831");
    assert_eq!(ids.get(ClientDevice::Mac), "887fdec7a9d12def");
    assert_eq!(format!("{ids:?}"), "Hwids(..)");
    let fixed = Hwids::of(&machine(), Some("abc".into()));
    for device in DEVICES {
        assert_eq!(fixed.get(device), "abc");
    }
    let agents = vpnte_profiles::device::user_agents(ClientDevice::Pc, fixed.get(ClientDevice::Pc));
    assert_eq!(agents[0], "Happ/3.22.1/Windows/abc");
    let mac = vpnte_profiles::device::user_agents(ClientDevice::Mac, ids.get(ClientDevice::Mac));
    assert_eq!(
        mac.len(),
        4,
        "the old duplicate sing-box agent is gone (S-30)"
    );
}

/// Old `bootstrapRoute.ts`: auto = direct + the user's proxy + Happ's two local proxies, deduped.
#[test]
fn route_plan_follows_the_bootstrap_setting() {
    let labels = |plan: &RoutePlan| plan.routes.iter().map(Route::label).collect::<Vec<_>>();
    let mut settings = Settings::default();
    let plan = route_plan(&settings);
    assert_eq!(
        labels(&plan),
        [
            "direct",
            "socks5h://127.0.0.1:10808",
            "http://127.0.0.1:10809"
        ]
    );
    assert!(plan.doh);

    settings.proxy_override = Some(ProxyOverride::parse("127.0.0.1:2080").unwrap().0);
    settings.proxy_type = ProxyKind::Http;
    let plan = route_plan(&settings);
    assert_eq!(
        labels(&plan),
        [
            "direct",
            "http://127.0.0.1:2080",
            "socks5h://127.0.0.1:10808",
            "http://127.0.0.1:10809"
        ]
    );

    settings.bootstrap_route_mode = BootstrapRouteMode::Direct;
    assert_eq!(labels(&route_plan(&settings)), ["direct"]);

    settings.bootstrap_route_mode = BootstrapRouteMode::LocalProxy;
    settings.proxy_override = Some(ProxyOverride::parse("127.0.0.1:10808").unwrap().0);
    settings.proxy_type = ProxyKind::Socks5;
    let plan = route_plan(&settings);
    assert_eq!(
        labels(&plan),
        ["socks5h://127.0.0.1:10808", "http://127.0.0.1:10809"]
    );
    assert!(!plan.doh, "local-proxy mode never goes out directly");
    // Constructing a route plan touches nothing: no request is made here.
    let _ = HostPort::parse("127.0.0.1:1").unwrap();
}

/// Fetch failures become `AppError`s with a message per outcome, one sentence per body and
/// network class (the keys themselves are checked by `test_locales`).
#[test]
fn outcomes_map_to_errors_and_messages() {
    use crate::model::{BodyKind, NetFail};
    let err = AppError::from(FetchError::Failed(FetchOutcome::EmptyList));
    assert_eq!(err.kind, ErrorKind::Validation);
    assert_eq!(err.user_msg().key, "servers.fetch.emptyList");
    let err = AppError::from(FetchError::Failed(FetchOutcome::Http(503)));
    assert_eq!(
        (err.kind, err.user_msg()),
        (
            ErrorKind::Network,
            Msg::new("servers.fetch.http").arg("code", 503)
        )
    );
    assert_eq!(
        AppError::from(FetchError::Failed(FetchOutcome::Timeout)).kind,
        ErrorKind::Timeout
    );
    assert_eq!(
        AppError::from(FetchError::Cancelled).kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        AppError::from(FetchError::InvalidUrl).kind,
        ErrorKind::Validation
    );
    let kinds = [
        BodyKind::Html,
        BodyKind::Json,
        BodyKind::Base64,
        BodyKind::Uris,
        BodyKind::Other,
    ];
    let nets = [
        NetFail::Dns,
        NetFail::Connect,
        NetFail::Tls,
        NetFail::Proxy,
        NetFail::Reset,
    ];
    let outcomes: Vec<FetchOutcome> = kinds
        .map(FetchOutcome::Unparseable)
        .into_iter()
        .chain(nets.map(FetchOutcome::Network))
        .collect();
    let keys: std::collections::HashSet<_> =
        outcomes.into_iter().map(|o| outcome_msg(o).key).collect();
    assert_eq!(
        keys.len(),
        kinds.len() + nets.len(),
        "one sentence per class"
    );
}

/// AT-04-012, servers §2.5: the first request is the Happ agent with the HWID headers ("Sosa
/// Connect and similar panels return an EMPTY 200 OK when the header is missing").
#[tokio::test]
async fn first_request_carries_the_happ_identity() {
    let list = format!("{KEY_A}\n{KEY_B}\n");
    let server = Server::start(move |req| match req.header("x-hwid") {
        Some(_) => reply("200 OK", &[], list.as_bytes()),
        None => reply("200 OK", &[], b""),
    })
    .await;
    let report = fetch(&direct(), &server.url("/sub/token")).await.unwrap();
    assert_eq!(report.profiles.len(), 2);
    assert!(is_complete(&report));
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    let first = &seen[0];
    assert_eq!(first.path, "/sub/token");
    assert_eq!(
        first.header("user-agent"),
        Some("Happ/3.22.1/Windows/99c6d48e9a5a5e32")
    );
    assert_eq!(first.header("x-hwid"), Some("99c6d48e9a5a5e32"));
    assert_eq!(first.header("x-device-os"), Some("Windows"));
    assert_eq!(first.header("x-ver-os"), Some("11"));
    assert_eq!(first.header("x-device-model"), Some("Windows PC"));
}

/// Profiles §3.7: on a route that answers, the other User-Agents are tried in order (panels gate
/// by client name with 403 / 404 / 406 or an empty 200).
#[tokio::test]
async fn other_agents_are_tried_on_a_route_that_answers() {
    let server = Server::start(|req| match req.header("user-agent") {
        Some(ua) if ua.starts_with("v2rayN/") => reply("200 OK", &[], KEY_A.as_bytes()),
        _ => reply("403 Forbidden", &[], b"no"),
    })
    .await;
    let report = fetch(&direct(), &server.url("/s")).await.unwrap();
    assert_eq!(report.profiles.len(), 1);
    let agents: Vec<String> = server
        .seen()
        .iter()
        .map(|s| {
            s.header("user-agent")
                .unwrap_or_default()
                .split('/')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    assert_eq!(agents, ["Happ", "sing-box", "v2RayTun", "v2rayN"]);
}

/// AT-00-005, servers §6 / S-08: 404 to every identified request ends the plan (no anonymous
/// retries); 429 stops at once; other statuses go through every variant, then report the status.
#[tokio::test]
async fn statuses_end_the_plan_as_the_spec_says() {
    let gone = Server::start(|_| reply("404 Not Found", &[], b"")).await;
    let err = fetch(&direct(), &gone.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::Http(404)));
    let seen = gone.seen();
    assert_eq!(seen.len(), 4, "one request per Happ-set agent");
    assert!(seen.iter().all(|s| s.header("x-hwid").is_some()));

    let limited =
        Server::start(|_| reply("429 Too Many Requests", &[("retry-after", "60")], b"")).await;
    let err = fetch(&direct(), &limited.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::Http(429)));
    assert_eq!(limited.seen().len(), 1);

    let broken = Server::start(|_| reply("500 Internal Server Error", &[], b"oops")).await;
    let err = fetch(&direct(), &broken.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::Http(500)));
    let seen = broken.seen();
    assert_eq!(seen.len(), 8, "four agents with the HWID, then without");
    assert!(seen[4..].iter().all(|s| s.header("x-hwid").is_none()));
}

/// Servers §7 #4 / #13: an empty answer is the provider's empty list; an HTML page is unusable.
#[tokio::test]
async fn unusable_bodies_are_typed() {
    let html = Server::start(|_| reply("200 OK", &[], b"<html>Subscription expired</html>")).await;
    let err = fetch(&direct(), &html.url("/s")).await.unwrap_err();
    assert_eq!(
        err,
        FetchError::Failed(FetchOutcome::Unparseable(crate::model::BodyKind::Html))
    );
    let empty = Server::start(|_| reply("200 OK", &[], b"")).await;
    let err = fetch(&direct(), &empty.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::EmptyList));
    // The empty list is the strongest evidence even when the panel also answered with errors.
    let mixed = Server::start(|req| match req.header("x-hwid") {
        Some(_) => reply("503 Service Unavailable", &[], b""),
        None => reply("200 OK", &[], b"\r\n"),
    })
    .await;
    let err = fetch(&direct(), &mixed.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::EmptyList));
}

/// Servers §7 #15d (S-43): a CRLF body with blank lines keeps every key and the headers.
#[tokio::test]
async fn crlf_body_with_blank_lines_keeps_keys_and_headers() {
    let body = format!("{KEY_A}\r\n\r\n{KEY_B}\r\n\r\n");
    let server = Server::start(move |_| {
        reply(
            "200 OK",
            &[("subscription-userinfo", "upload=1; download=2; total=3")],
            body.as_bytes(),
        )
    })
    .await;
    let report = fetch(&direct(), &server.url("/s")).await.unwrap();
    assert_eq!(report.profiles.len(), 2);
    assert_eq!(
        (report.meta.upload, report.meta.download, report.meta.total),
        (Some(1), Some(2), Some(3))
    );
}

/// Servers §7 #16-#18: userinfo, titles, links and the interval; headers win over body lines,
/// body lines fill gaps, a literal `%` in a file name is kept (S-07).
#[tokio::test]
async fn metadata_comes_from_headers_and_body_lines() {
    let body = format!("#profile-title: Name VPN\n#support-url: https://t.me/body\n{KEY_A}\n");
    let server = Server::start(move |req| match req.path.as_str() {
        "/full" => reply(
            "200 OK",
            &[
                (
                    "subscription-userinfo",
                    "upload=0; download=2153701362; total=0; expire=1790951622",
                ),
                ("profile-title", "base64:QUxMIFZQTg=="),
                ("profile-update-interval", "12"),
                ("support-url", "https://t.me/x"),
                ("profile-web-page-url", "null"),
            ],
            body.as_bytes(),
        ),
        "/file" => reply(
            "200 OK",
            &[("content-disposition", "attachment; filename=\"100%.txt\"")],
            KEY_A.as_bytes(),
        ),
        _ => reply("200 OK", &[], body.as_bytes()),
    })
    .await;
    let meta = fetch(&direct(), &server.url("/full")).await.unwrap().meta;
    assert_eq!(
        (meta.upload, meta.download, meta.total),
        (Some(0), Some(2_153_701_362), Some(0))
    );
    assert_eq!(meta.expires_at, Some(1_790_951_622_000));
    assert_eq!(meta.title.as_deref(), Some("ALL VPN"));
    assert_eq!(meta.refresh_hours, Some(12));
    assert_eq!(meta.support_url.as_deref(), Some("https://t.me/x"));
    assert_eq!(meta.web_page_url, None);
    let meta = fetch(&direct(), &server.url("/plain")).await.unwrap().meta;
    assert_eq!(meta.title.as_deref(), Some("Name VPN"));
    assert_eq!(meta.support_url.as_deref(), Some("https://t.me/body"));
    let meta = fetch(&direct(), &server.url("/file")).await.unwrap().meta;
    assert_eq!(meta.title.as_deref(), Some("100%"));
}

/// Servers §2.5 / §7 #19: redirects are followed by hand, into deep links and keys too.
#[tokio::test]
async fn redirects_are_followed_by_hand() {
    let server = Server::start(|req| {
        let host = req.header("host").unwrap_or_default().to_owned();
        match req.path.as_str() {
            "/real" => reply("200 OK", &[], KEY_A.as_bytes()),
            "/angle" => reply(
                "302 Found",
                &[("location", &format!("<http://{host}/real>"))],
                b"",
            ),
            "/label" => reply("301 Moved", &[("location", "URL: /real")], b""),
            "/happ" => reply(
                "302 Found",
                &[("location", &format!("happ://add/http://{host}/real"))],
                b"",
            ),
            "/key" => reply("302 Found", &[("location", KEY_B)], b""),
            "/loop" => reply("302 Found", &[("location", "/loop")], b""),
            "/bare" => reply("302 Found", &[], b""),
            p if p.starts_with("/chain") => {
                let n: u32 = p["/chain".len()..].parse().unwrap_or(0);
                reply(
                    "302 Found",
                    &[("location", &format!("/chain{}", n + 1))],
                    b"",
                )
            }
            _ => reply("404 Not Found", &[], b""),
        }
    })
    .await;
    let f = direct();
    for path in ["/angle", "/label", "/happ"] {
        let report = fetch(&f, &server.url(path)).await.unwrap();
        assert_eq!(report.profiles[0].name, "A", "{path}");
    }
    let report = fetch(&f, &server.url("/key")).await.unwrap();
    assert_eq!(report.profiles[0].name, "B");
    let unusable = Err(FetchError::Failed(FetchOutcome::Unparseable(
        crate::model::BodyKind::Other,
    )));
    for path in ["/loop", "/bare", "/chain"] {
        assert_eq!(
            fetch(&f, &server.url(path)).await.map(|r| r.profiles.len()),
            unusable,
            "{path}"
        );
    }
    let chain = server
        .seen()
        .iter()
        .filter(|s| s.path.starts_with("/chain"))
        .count();
    assert_eq!(
        chain,
        8 * MAX_REQUESTS,
        "at most five redirects per attempt"
    );
}

/// AT-00-004 / AT-00-005, servers §7 #9 / #13: transport failures are classified and leave the
/// route at once (S-08).
#[tokio::test]
async fn transport_failures_are_classified() {
    let closed = closed_port().await;
    let url = Url::parse(&format!("http://127.0.0.1:{closed}/s")).unwrap();
    let net = |fail| Err(FetchError::Failed(FetchOutcome::Network(fail)));
    assert_eq!(
        fetch(&direct(), &url).await.map(|_| ()),
        net(NetFail::Connect)
    );

    let plain = Server::start_with(
        Some(b"HTTP/1.1 400 Bad Request\r\n\r\n"),
        Arc::new(|_| None),
    )
    .await;
    let tls = Url::parse(&format!("https://127.0.0.1:{}/s", plain.addr.port())).unwrap();
    assert_eq!(fetch(&direct(), &tls).await.map(|_| ()), net(NetFail::Tls));
    assert_eq!(
        *plain.accepted.lock(),
        1,
        "a TLS failure is not retried with other agents"
    );

    let hangup = Server::start_with(Some(b""), Arc::new(|_| None)).await;
    assert_eq!(
        fetch(&direct(), &hangup.url("/s")).await.map(|_| ()),
        net(NetFail::Reset)
    );
    assert_eq!(*hangup.accepted.lock(), 1);

    let silent = Server::start(|_| None).await;
    let quick = direct().with_request_timeout(Duration::from_millis(300));
    let err = fetch(&quick, &silent.url("/s")).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::Timeout));
}

/// Profiles §3.7: a dead route gives way to the next one; an HTTP proxy route sends the request
/// in absolute form (the loopback server plays the proxy).
#[tokio::test]
async fn next_route_is_tried_after_a_dead_one() {
    let proxy = Server::start(|_| reply("200 OK", &[], KEY_A.as_bytes())).await;
    let proxy_addr = HostPort::parse(&proxy.addr.to_string()).unwrap();
    let dead = HostPort::new("127.0.0.1", closed_port().await).unwrap();
    let f = fetcher(vec![
        Route::proxy(ProxyKind::Socks5, &dead, None),
        Route::Direct,
        Route::proxy(ProxyKind::Http, &proxy_addr, None),
    ]);
    let target = Url::parse(&format!("http://127.0.0.1:{}/feed", closed_port().await)).unwrap();
    let report = fetch(&f, &target).await.unwrap();
    assert_eq!(report.profiles.len(), 1);
    let seen = proxy.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, target.as_str());
}

/// AT-00-003: a pre-cancelled token sends nothing; a cancel during a request returns promptly.
#[tokio::test]
async fn cancellation_is_prompt() {
    let server = Server::start(|_| None).await;
    let f = direct();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let err = f
        .fetch(&server.url("/s"), ClientDevice::Pc, &cancel)
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Cancelled);
    assert_eq!(*server.accepted.lock(), 0);
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    });
    let started = Instant::now();
    let err = f
        .fetch(&server.url("/s"), ClientDevice::Pc, &cancel)
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Cancelled);
    assert!(started.elapsed() < Duration::from_millis(900));
}

/// Servers §2.4 / S-28: a body over 16 MiB is refused unread; a non-http URL sends nothing.
#[tokio::test]
async fn limits_and_invalid_urls() {
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 17000000\r\n\r\n";
    let big = Server::start(|_| Some(head.to_vec())).await;
    let err = fetch(&direct(), &big.url("/s")).await.unwrap_err();
    let unusable = FetchOutcome::Unparseable(crate::model::BodyKind::Other);
    assert_eq!(err, FetchError::Failed(unusable));
    let ftp = Url::parse("ftp://127.0.0.1/s").unwrap();
    assert_eq!(
        fetch(&direct(), &ftp).await.unwrap_err(),
        FetchError::InvalidUrl
    );
}
