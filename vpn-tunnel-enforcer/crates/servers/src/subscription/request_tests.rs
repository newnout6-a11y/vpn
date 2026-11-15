//! Tests of one group's fetch (ru-2026 items 1 and 3): HWID switch, extra headers, the session
//! route, the borrowed slot, the fallback URL, permanent moves, Mihomo providers and controls.
//! Every server is a loopback stand-in; URLs, tokens and keys are fakes.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::types::{ClientDevice, ProxyKind};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::settings::{BootstrapRouteMode, Settings};
use vpnte_profiles::text::Relocation;

use super::request::relocation;
use super::tests::{KEY_A, KEY_B, Server, closed_port, machine, reply};
use super::*;

/// What the fake app lends: an optional session route and an optional spare route.
#[derive(Default)]
struct FakeRelays {
    session: Option<Route>,
    spare: Option<Route>,
    asked: AtomicUsize,
    released: Arc<AtomicBool>,
}

impl Relays for FakeRelays {
    fn session_route(&self) -> Option<Route> {
        self.session.clone()
    }

    fn spare_route(&self, _cancel: CancellationToken) -> SpareFuture<'_> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let released = self.released.clone();
        let spare = self
            .spare
            .clone()
            .map(|route| Spare::new(route, move || released.store(true, Ordering::SeqCst)));
        // A real slot takes a moment to start (engine spawn, first probe).
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            spare
        })
    }
}

fn proxy_route(server: &Server) -> Route {
    let addr = HostPort::new("127.0.0.1", server.addr.port()).unwrap();
    Route::proxy(ProxyKind::Http, &addr, None)
}

fn plan_fetcher(routes: Vec<Route>, relay: bool) -> SubscriptionFetcher {
    let plan = RoutePlan {
        routes,
        doh: false,
        relay,
    };
    SubscriptionFetcher::with_plan(Hwids::of(&machine(), None), plan)
}

async fn dead_url(path: &str) -> Url {
    Url::parse(&format!("http://127.0.0.1:{}{path}", closed_port().await)).unwrap()
}

async fn run(f: &SubscriptionFetcher, req: &FetchRequest) -> Result<Fetched, FetchError> {
    f.fetch_request(req, &CancellationToken::new()).await
}

fn list() -> Vec<u8> {
    format!("{KEY_A}\n{KEY_B}\n").into_bytes()
}

/// ru-2026 item 1: without the switch no request carries the HWID (headers or User-Agent); with
/// it the identified variants go first. Every request asks caches for a fresh copy.
#[tokio::test]
async fn hwid_switch_decides_the_identity() {
    let server = Server::start(|_| reply("404 Not Found", &[], b"")).await;
    let url = server.url("/sub/token");
    let f = plan_fetcher(vec![Route::Direct], false);
    let mut req = FetchRequest::new(url, ClientDevice::Pc);
    assert!(run(&f, &req).await.is_err());
    let off = server.seen();
    assert_eq!(off.len(), 5, "five agents, no identified pass");
    assert_eq!(off[0].header("user-agent"), Some("Happ/4.7.2/Windows"));
    assert!(off.iter().all(|s| s.header("x-hwid").is_none()));
    assert!(off.iter().all(|s| s.header("x-device-os").is_none()));
    assert!(
        off.iter()
            .all(|s| s.header("cache-control") == Some("no-store"))
    );
    req.send_hwid = true;
    assert!(run(&f, &req).await.is_err());
    let on = &server.seen()[5..];
    assert_eq!(on[0].header("x-hwid"), Some("99c6d48e9a5a5e32"));
    assert_eq!(
        on[0].header("user-agent"),
        Some("Happ/4.7.2/Windows/99c6d48e9a5a5e32")
    );
}

/// The user's headers go on last and win; their User-Agent replaces the rotation.
#[tokio::test]
async fn extra_headers_go_last_and_win() {
    let server = Server::start(|_| reply("403 Forbidden", &[], b"")).await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let mut req = FetchRequest::new(server.url("/s"), ClientDevice::Pc);
    req.send_hwid = true;
    req.headers =
        parse_headers("User-Agent: v2rayN/7.25.1\nX-Panel-Token: fake-123\nx-hwid: own").unwrap();
    assert!(run(&f, &req).await.is_err());
    let seen = server.seen();
    assert_eq!(
        seen.len(),
        2,
        "one agent, with and without the device headers"
    );
    for s in &seen {
        assert_eq!(s.header("user-agent"), Some("v2rayN/7.25.1"));
        assert_eq!(s.header("x-panel-token"), Some("fake-123"));
        assert_eq!(s.header("x-hwid"), Some("own"));
    }
}

#[test]
fn headers_are_checked() {
    let ok = parse_headers("  A-B: c d \n\nX-Y:z").unwrap();
    assert_eq!(
        ok,
        [("A-B".into(), "c d".into()), ("X-Y".into(), "z".into())]
    );
    assert_eq!(stored_headers(&ok).as_deref(), Some("A-B: c d\nX-Y: z"));
    assert_eq!(header_names("A-B: c\nX-Y: z"), ["A-B", "X-Y"]);
    assert_eq!(stored_headers(&[]), None);
    let key = |text: &str| parse_headers(text).unwrap_err().user_msg().key.clone();
    assert_eq!(key("A: b\nno colon"), "servers.headers.invalid");
    assert_eq!(key("Bad Name: x"), "servers.headers.invalid");
    assert_eq!(key("A: line\u{7}bell"), "servers.headers.invalid");
    assert_eq!(key("Host: evil.example"), "servers.headers.reserved");
    assert_eq!(key("proxy-authorization: x"), "servers.headers.reserved");
    let many: String = (0..=MAX_HEADERS).map(|i| format!("H{i}: v\n")).collect();
    assert_eq!(key(&many), "servers.headers.tooMany");
}

/// ru-2026 item 3: the session's route comes right after direct, never twice. subs-b5: only in
/// "auto": "local proxy only" and "direct only" mean what their labels say (the session's engine
/// would send Smart RU hosts direct, a borrowed slot dials a VPN server).
#[test]
fn session_route_follows_direct() {
    let session = Route::proxy(
        ProxyKind::Socks5,
        &HostPort::parse("127.0.0.1:20999").unwrap(),
        None,
    );
    let mut settings = Settings::default();
    let auto = route_plan(&settings).with_session(Some(session.clone()));
    assert_eq!(auto.routes[0], Route::Direct);
    assert_eq!(auto.routes[1], session);
    assert!(auto.relay);
    let again = auto.clone().with_session(Some(session.clone()));
    assert_eq!(again, auto);
    settings.bootstrap_route_mode = BootstrapRouteMode::LocalProxy;
    let local = route_plan(&settings);
    assert!(!local.relay);
    assert_eq!(local.clone().with_session(Some(session.clone())), local);
    assert!(local.routes.iter().all(|r| *r != Route::Direct));
    settings.bootstrap_route_mode = BootstrapRouteMode::Direct;
    let direct = route_plan(&settings);
    assert!(!direct.relay);
    assert_eq!(
        direct.clone().with_session(Some(session)).routes,
        [Route::Direct]
    );
    assert_eq!(auto.clone().with_session(None), auto);
}

/// Direct fails (closed port), the session's mixed inbound answers: the fetcher asks the relays
/// at every fetch and takes that route second.
#[tokio::test]
async fn blocked_direct_goes_through_the_session() {
    let inbound = Server::start(|_| reply("200 OK", &[], &list())).await;
    let f = plan_fetcher(vec![Route::Direct], true);
    f.set_relays(Arc::new(FakeRelays {
        session: Some(proxy_route(&inbound)),
        ..FakeRelays::default()
    }));
    assert_eq!(f.plan().routes[1], proxy_route(&inbound));
    let url = dead_url("/sub/token").await;
    let got = run(&f, &FetchRequest::new(url.clone(), ClientDevice::Pc))
        .await
        .unwrap();
    assert_eq!(got.report.profiles.len(), 2);
    assert_eq!(inbound.seen()[0].path, url.as_str(), "proxied absolute URI");
}

/// Every route failed: one slot is borrowed for one more try and handed back afterwards; with
/// "direct only" no slot is asked for.
#[tokio::test]
async fn spare_slot_is_the_last_try_and_is_returned() {
    let slot = Server::start(|_| reply("200 OK", &[], &list())).await;
    let relays = Arc::new(FakeRelays {
        spare: Some(proxy_route(&slot)),
        ..FakeRelays::default()
    });
    let f = plan_fetcher(vec![Route::Direct], true);
    f.set_relays(relays.clone());
    let url = dead_url("/sub").await;
    let got = run(&f, &FetchRequest::new(url.clone(), ClientDevice::Pc))
        .await
        .unwrap();
    assert_eq!(got.report.profiles.len(), 2);
    assert_eq!(relays.asked.load(Ordering::SeqCst), 1);
    assert!(relays.released.load(Ordering::SeqCst), "slot handed back");

    let strict = plan_fetcher(vec![Route::Direct], false);
    let none = Arc::new(FakeRelays {
        spare: Some(proxy_route(&slot)),
        ..FakeRelays::default()
    });
    strict.set_relays(none.clone());
    let err = run(&strict, &FetchRequest::new(url, ClientDevice::Pc)).await;
    assert!(matches!(err, Err(FetchError::Failed(_))));
    assert_eq!(none.asked.load(Ordering::SeqCst), 0);
}

/// Happ's fallback URL answers when the URL fails (a refused connection here; the 9 s rule is
/// tested with a paused clock in `fallback.rs`).
#[tokio::test]
async fn fallback_url_answers_for_a_dead_url() {
    let mirror = Server::start(|_| reply("200 OK", &[], &list())).await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let mut req = FetchRequest::new(dead_url("/sub").await, ClientDevice::Pc);
    req.fallback = Some(mirror.url("/mirror/token"));
    let got = run(&f, &req).await.unwrap();
    assert!(got.via_fallback);
    assert_eq!(got.report.profiles.len(), 2);
    assert_eq!(got.moved_to, None, "a fallback answer moves nothing");
    let status = Server::start(|_| reply("503 Service Unavailable", &[], b"")).await;
    req.url = status.url("/sub");
    let got = run(&f, &req).await.unwrap();
    assert!(got.via_fallback, "an answer of 300-599 hands over too");
}

/// A followed 301 / 308 of an HTTPS URL is its permanent new address; a 302 is not, and a 302
/// after a 301 keeps the 301's target. Over plain `http` a redirect moves nothing (subs-b1).
#[tokio::test]
async fn permanent_redirects_move_the_url() {
    let handler = |seen: &super::tests::Seen| match seen.path.as_str() {
        "/old" => reply("301 Moved Permanently", &[("location", "/new")], b""),
        "/temp" => reply("302 Found", &[("location", "/new")], b""),
        "/perm308" => reply("308 Permanent Redirect", &[("location", "/mid")], b""),
        "/mid" => reply("302 Found", &[("location", "/new")], b""),
        _ => reply("200 OK", &[], &list()),
    };
    let server = Server::start_tls(handler).await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let moved = |url: Url| {
        let req = FetchRequest::new(url, ClientDevice::Pc);
        let f = &f;
        async move { run(f, &req).await.unwrap().moved_to }
    };
    assert_eq!(moved(server.url("/old")).await, Some(server.url("/new")));
    assert_eq!(moved(server.url("/temp")).await, None);
    assert_eq!(
        moved(server.url("/perm308")).await,
        Some(server.url("/mid"))
    );
    assert_eq!(moved(server.url("/new")).await, None);
    let plain = Server::start(handler).await;
    assert_eq!(
        moved(plain.url("/old")).await,
        None,
        "cleartext: anyone could say it"
    );
}

/// The panel at `/hint` names a new address and a fallback URL in headers, `/lines` in a body
/// line; both point at the same server.
fn hinting(seen: &super::tests::Seen, scheme: &str) -> Option<Vec<u8>> {
    let host = seen.header("host").unwrap_or_default().to_owned();
    let next = format!("{scheme}://{host}/next/token");
    let fallback = format!("{scheme}://127.0.0.2:9/fb");
    match seen.path.as_str() {
        "/hint" => reply(
            "200 OK",
            &[
                ("new-url", next.as_str()),
                ("fallback-url", fallback.as_str()),
            ],
            &list(),
        ),
        "/lines" => {
            let body = format!("//moved-permanently-to: {next}\n{KEY_A}\n");
            reply("200 OK", &[], body.as_bytes())
        }
        _ => reply("200 OK", &[("fallback-url", "not a url")], &list()),
    }
}

/// `new-url` / `moved-permanently-to` / `new-domain` name the new address; `fallback-url` is
/// handed back for the group to keep.
#[tokio::test]
async fn relocation_hints_come_back_vetted() {
    let server = Server::start_tls(|seen| hinting(seen, "https")).await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let req = FetchRequest::new(server.url("/hint"), ClientDevice::Pc);
    let got = run(&f, &req).await.unwrap();
    assert_eq!(got.moved_to, Some(server.url("/next/token")));
    assert_eq!(
        got.fallback,
        Some(Url::parse("https://127.0.0.2:9/fb").unwrap())
    );
    assert!(!format!("{got:?}").contains("token"));
    let req = FetchRequest::new(server.url("/lines"), ClientDevice::Pc);
    assert_eq!(
        run(&f, &req).await.unwrap().moved_to,
        Some(server.url("/next/token"))
    );
    let req = FetchRequest::new(server.url("/plain"), ClientDevice::Pc);
    let got = run(&f, &req).await.unwrap();
    assert_eq!((got.moved_to, got.fallback), (None, None));
}

/// subs-b1: only an HTTPS answer of the subscription's own URL on the user's routes re-points
/// it. A plain `http` answer (any hop may rewrite it), an answer through a borrowed slot (a third
/// party's server) and an answer of the fallback URL move nothing; the fallback answer may still
/// name a new fallback URL.
#[tokio::test]
async fn untrusted_answers_relocate_nothing() {
    let plain = Server::start(|seen| hinting(seen, "http")).await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let got = run(&f, &FetchRequest::new(plain.url("/hint"), ClientDevice::Pc))
        .await
        .unwrap();
    assert_eq!((got.moved_to, got.fallback), (None, None), "plain http");
    let got = run(
        &f,
        &FetchRequest::new(plain.url("/lines"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(got.moved_to, None, "plain http body line");

    let tls = Server::start_tls(|seen| hinting(seen, "https")).await;
    let tunnel = super::tests::Tunnel::start().await;
    let relays = Arc::new(FakeRelays {
        spare: Some(tunnel.route()),
        ..FakeRelays::default()
    });
    let dead_proxy = Route::proxy(
        ProxyKind::Socks5,
        &HostPort::new("127.0.0.1", closed_port().await).unwrap(),
        None,
    );
    let through_slot = plan_fetcher(vec![dead_proxy], true);
    through_slot.set_relays(relays.clone());
    let got = run(
        &through_slot,
        &FetchRequest::new(tls.url("/hint"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(relays.asked.load(Ordering::SeqCst), 1);
    assert!(tunnel.opened() > 0, "the answer came through the slot");
    assert_eq!((got.moved_to, got.fallback), (None, None), "borrowed slot");

    let mut req = FetchRequest::new(dead_tls_url("/sub/token").await, ClientDevice::Pc);
    req.fallback = Some(tls.url("/hint"));
    let got = run(&f, &req).await.unwrap();
    assert!(got.via_fallback);
    assert_eq!(got.moved_to, None, "a fallback answer moves nothing");
    assert_eq!(
        got.fallback,
        Some(Url::parse("https://127.0.0.2:9/fb").unwrap())
    );
}

async fn dead_tls_url(path: &str) -> Url {
    Url::parse(&format!("https://127.0.0.1:{}{path}", closed_port().await)).unwrap()
}

#[test]
fn new_domain_keeps_the_path() {
    let url = Url::parse("https://old.example/sub/TOKEN?x=1").unwrap();
    let hints = |domain: &str| Relocation {
        new_domain: Some(domain.into()),
        ..Relocation::default()
    };
    let next = relocation(&url, &hints("new.example"), None).unwrap();
    assert_eq!(next.as_str(), "https://new.example/sub/TOKEN?x=1");
    let next = relocation(&url, &hints("new.example:8443"), None).unwrap();
    assert_eq!(next.as_str(), "https://new.example:8443/sub/TOKEN?x=1");
    let redirect = Url::parse("https://r.example/s").unwrap();
    let explicit = Relocation {
        new_url: Some("https://n.example/s".into()),
        new_domain: Some("d.example".into()),
        ..Relocation::default()
    };
    let next = relocation(&url, &explicit, Some(redirect.clone())).unwrap();
    assert_eq!(next.as_str(), "https://n.example/s", "new-url wins");
    let none = Relocation::default();
    assert_eq!(
        relocation(&url, &none, Some(redirect.clone())),
        Some(redirect)
    );
}

/// ru-2026 item 1: a Mihomo document's `type: http` providers are fetched like the subscription
/// and merged; a provider that fails makes the answer partial (its keys are not "removed").
#[tokio::test]
async fn mihomo_providers_are_fetched_and_merged() {
    let server = Server::start(|seen| {
        let host = seen.header("host").unwrap_or_default().to_owned();
        match seen.path.as_str() {
            "/clash" => {
                let doc = format!(
                    "proxies:\n  - {{name: SS, type: ss, server: ss.example, port: 8388, cipher: aes-128-gcm, password: fake}}\nproxy-providers:\n  Main:\n    type: http\n    url: http://{host}/p1\n  Broken:\n    type: http\n    url: http://{host}/p2\n"
                );
                reply("200 OK", &[("hide-settings", "1")], doc.as_bytes())
            }
            "/only" => {
                let doc = format!("proxies: []\nproxy-providers:\n  Main: {{type: http, url: 'http://{host}/p1'}}\n");
                reply("200 OK", &[], doc.as_bytes())
            }
            "/p1" => reply("200 OK", &[], &list()),
            _ => reply("404 Not Found", &[], b""),
        }
    })
    .await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let got = run(
        &f,
        &FetchRequest::new(server.url("/clash"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(got.report.profiles.len(), 3);
    let names: Vec<(&str, usize)> = got
        .providers
        .iter()
        .map(|p| (p.name.as_str(), p.servers))
        .collect();
    assert_eq!(names, [("Main", 2), ("Broken", 0)]);
    assert_eq!(
        got.providers[1].failed,
        Some(ProviderFailure::Fetch(FetchOutcome::Http(404)))
    );
    assert!(!got.complete());
    assert!(got.controls.hides_settings());
    let only = run(
        &f,
        &FetchRequest::new(server.url("/only"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(only.report.profiles.len(), 2);
    assert!(only.complete());
}

/// Speed audit ops7: providers on two hosts are fetched side by side (each answer takes 1 s
/// here; `localhost` adds the happy-eyeballs wait after `::1`), and merged in their own order:
/// one after another would take over 3.3 s.
#[tokio::test]
async fn providers_on_two_hosts_are_fetched_side_by_side() {
    let server = Server::start(|seen| {
        let port = seen
            .header("host")
            .and_then(|h| h.rsplit(':').next())
            .unwrap_or_default()
            .to_owned();
        match seen.path.as_str() {
            "/clash" => {
                let doc = format!(
                    "proxies: []
proxy-providers:
  One: {{type: http, url: 'http://127.0.0.1:{port}/p1'}}
  Two: {{type: http, url: 'http://localhost:{port}/p2'}}
"
                );
                reply("200 OK", &[], doc.as_bytes())
            }
            "/p1" | "/p2" => reply("200 OK", &[], &list()),
            _ => reply("404 Not Found", &[], b""),
        }
    })
    .await;
    server.set_delay(std::time::Duration::from_millis(1000));
    let f = plan_fetcher(vec![Route::Direct], false);
    let started = std::time::Instant::now();
    let got = run(
        &f,
        &FetchRequest::new(server.url("/clash"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    let names: Vec<&str> = got.providers.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["One", "Two"]);
    let took = started.elapsed();
    assert!(took < std::time::Duration::from_millis(2800), "{took:?}");
}

/// A move, a fallback URL and a provider URL obey the redirect rules (S-29): no `https` ->
/// `http`, and a public subscription never points into a private network. IP literals only: no
/// lookup leaves the machine.
#[tokio::test]
async fn relocations_follow_the_redirect_rules() {
    let vet = |base: &str, target: &str| {
        let (base, target) = (Url::parse(base).unwrap(), Url::parse(target).unwrap());
        async move { super::http::vet_relocation(&base, &target, true).await }
    };
    assert!(vet("https://8.8.8.8/sub", "https://1.1.1.1/next").await);
    assert!(!vet("https://8.8.8.8/sub", "http://1.1.1.1/next").await);
    assert!(!vet("https://8.8.8.8/sub", "https://192.168.1.1/next").await);
    assert!(!vet("https://8.8.8.8/sub", "https://localhost/next").await);
    assert!(vet("http://192.168.1.10/sub", "http://192.168.1.11/next").await);
}

/// subs-b4: names are resolved by the system only for an answer that came direct; behind a proxy
/// (or "local proxy only") a lookup would hand them to the local resolver the plan avoids. This
/// machine's own name resolves locally to its LAN / link-local addresses: refused when resolved,
/// not looked up (and so not refused) otherwise.
#[tokio::test]
async fn vetting_resolves_names_only_for_direct_answers() {
    let Ok(name) = std::env::var("COMPUTERNAME") else {
        return;
    };
    let local = tokio::net::lookup_host((name.as_str(), 443)).await;
    let private =
        local.is_ok_and(|mut addrs| addrs.any(|a| !vpnte_core::net::is_public_ip(a.ip())));
    if !private {
        return;
    }
    let base = Url::parse("https://8.8.8.8/sub").unwrap();
    let target = Url::parse(&format!("https://{name}/next")).unwrap();
    assert!(!super::http::vet_relocation(&base, &target, true).await);
    assert!(super::http::vet_relocation(&base, &target, false).await);
    let lan = Url::parse("https://192.168.1.1/next").unwrap();
    assert!(
        !super::http::vet_relocation(&base, &lan, false).await,
        "literals still count"
    );
}

/// subs-b8: the HWID, the device headers and the user's headers stay on the subscription's host.
/// A redirect to another host (a CDN, a paste host) gets the plain client and nothing private,
/// also after the chain comes back; a redirect within the host keeps them.
#[tokio::test]
async fn private_headers_stay_on_the_subscriptions_host() {
    let cdn = Server::start(|_| reply("200 OK", &[], &list())).await;
    let elsewhere = format!("http://localhost:{}/list", cdn.addr.port());
    let panel = Server::start(move |seen| match seen.path.as_str() {
        "/away" => reply("302 Found", &[("location", elsewhere.as_str())], b""),
        "/here" => reply("302 Found", &[("location", "/list")], b""),
        _ => reply("200 OK", &[], &list()),
    })
    .await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let mut req = FetchRequest::new(panel.url("/away"), ClientDevice::Pc);
    req.send_hwid = true;
    req.headers = parse_headers("X-Panel-Token: fake-secret").unwrap();
    run(&f, &req).await.unwrap();
    let first = &panel.seen()[0];
    assert_eq!(first.header("x-hwid"), Some("99c6d48e9a5a5e32"));
    assert_eq!(first.header("x-panel-token"), Some("fake-secret"));
    let moved = &cdn.seen()[0];
    assert_eq!(moved.header("x-hwid"), None);
    assert_eq!(moved.header("x-device-model"), None);
    assert_eq!(moved.header("x-panel-token"), None);
    assert_eq!(moved.header("user-agent"), Some("Happ/4.7.2/Windows"));

    req.url = panel.url("/here");
    run(&f, &req).await.unwrap();
    let same = panel.seen().pop().unwrap();
    assert_eq!(same.path, "/list");
    assert_eq!(same.header("x-hwid"), Some("99c6d48e9a5a5e32"));
    assert_eq!(same.header("x-panel-token"), Some("fake-secret"));
}

/// subs-b2: a Mihomo provider on the subscription's host is asked like the subscription; one on
/// another host gets no HWID, no device headers and none of the user's headers (Mihomo itself
/// never sends a subscription's headers to its providers).
#[tokio::test]
async fn providers_elsewhere_get_no_identity() {
    let server = Server::start(|seen| {
        let port = seen.header("host").unwrap_or_default().rsplit(':').next().unwrap_or_default().to_owned();
        match seen.path.as_str() {
            "/clash" => {
                let doc = format!(
                    "proxies: []\nproxy-providers:\n  Own: {{type: http, url: 'http://127.0.0.1:{port}/own'}}\n  Other: {{type: http, url: 'http://localhost:{port}/other'}}\n"
                );
                reply("200 OK", &[], doc.as_bytes())
            }
            "/own" => reply("200 OK", &[], format!("{KEY_A}\n").as_bytes()),
            _ => reply("200 OK", &[], format!("{KEY_B}\n").as_bytes()),
        }
    })
    .await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let mut req = FetchRequest::new(server.url("/clash"), ClientDevice::Pc);
    req.send_hwid = true;
    req.headers = parse_headers("Authorization: Bearer fake-token").unwrap();
    let got = run(&f, &req).await.unwrap();
    assert_eq!(got.report.profiles.len(), 2);
    let seen = server.seen();
    let at = |path: &str| seen.iter().find(|s| s.path == path).unwrap().clone();
    let own = at("/own");
    assert_eq!(own.header("x-hwid"), Some("99c6d48e9a5a5e32"));
    assert_eq!(own.header("authorization"), Some("Bearer fake-token"));
    let other = at("/other");
    assert_eq!(other.header("x-hwid"), None);
    assert_eq!(other.header("x-device-os"), None);
    assert_eq!(other.header("authorization"), None);
    assert_eq!(other.header("user-agent"), Some("Happ/4.7.2/Windows"));
}

/// subs-a2 / subs-b6: a panel that said enough (429; 404 / 410 to every identified request) is
/// not asked again through a borrowed slot; a refusal that a CDN gives some countries (403), or
/// a dead route, still is. With a fallback URL only the URL that did not stop is retried.
#[tokio::test]
async fn no_spare_slot_after_the_panel_said_stop() {
    let slot = Server::start(|_| reply("200 OK", &[], &list())).await;
    let try_with = |status: &'static str, hwid: bool| {
        let slot = &slot;
        async move {
            let panel = Server::start(move |_| reply(status, &[], b"")).await;
            let relays = Arc::new(FakeRelays {
                spare: Some(proxy_route(slot)),
                ..FakeRelays::default()
            });
            let f = plan_fetcher(vec![Route::Direct], true);
            f.set_relays(relays.clone());
            let mut req = FetchRequest::new(panel.url("/sub"), ClientDevice::Pc);
            req.send_hwid = hwid;
            let ok = run(&f, &req).await.is_ok();
            (ok, relays.asked.load(Ordering::SeqCst))
        }
    };
    assert_eq!(try_with("429 Too Many Requests", false).await, (false, 0));
    assert_eq!(try_with("404 Not Found", true).await, (false, 0));
    assert_eq!(try_with("410 Gone", true).await, (false, 0));
    assert_eq!(
        try_with("403 Forbidden", true).await,
        (true, 1),
        "a CDN's 403"
    );

    let limited = Server::start(|_| reply("429 Too Many Requests", &[], b"")).await;
    let before = slot.seen().len();
    let relays = Arc::new(FakeRelays {
        spare: Some(proxy_route(&slot)),
        ..FakeRelays::default()
    });
    let f = plan_fetcher(vec![Route::Direct], true);
    f.set_relays(relays.clone());
    let mut req = FetchRequest::new(limited.url("/sub"), ClientDevice::Pc);
    req.fallback = Some(dead_url("/mirror").await);
    let got = run(&f, &req).await.unwrap();
    assert!(got.via_fallback, "the slot retried the fallback URL only");
    assert_eq!(limited.seen().len(), 1, "the limited panel was asked once");
    let through_slot = slot.seen().split_off(before);
    assert!(!through_slot.is_empty());
    assert!(through_slot.iter().all(|s| s.path.ends_with("/mirror")));
}

/// subs-a5: when the provider merge reaches the 5000-key cap, the answer is marked as cut like
/// the parser marks a long list: the keys it did not take are not "removed by the provider".
#[tokio::test]
async fn a_merge_cut_at_the_cap_is_incomplete() {
    use crate::parse::MAX_PROFILES;
    let proxies: String = (1..MAX_PROFILES)
        .map(|i| format!("  - {{name: S{i}, type: ss, server: h{i}.example, port: 8388, cipher: aes-128-gcm, password: fake}}\n"))
        .collect();
    let server = Server::start(move |seen| {
        let host = seen.header("host").unwrap_or_default().to_owned();
        match seen.path.as_str() {
            "/clash" => {
                let doc = format!(
                    "proxies:\n{proxies}proxy-providers:\n  More: {{type: http, url: 'http://{host}/more'}}\n"
                );
                reply("200 OK", &[], doc.as_bytes())
            }
            _ => reply("200 OK", &[], &list()),
        }
    })
    .await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let got = run(
        &f,
        &FetchRequest::new(server.url("/clash"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(got.report.profiles.len(), MAX_PROFILES);
    assert_eq!(got.providers[0].servers, 1);
    assert!(!got.complete(), "one provider key was left out");
}

/// subs-b10: a provider URL the redirect rules refuse (`http` under an `https` subscription) is
/// reported as refused, not as an unusable answer it never gave.
#[tokio::test]
async fn a_refused_provider_is_reported_as_refused() {
    let server = Server::start_tls(|_| {
        let doc = "proxies:\n  - {name: SS, type: ss, server: ss.example, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-providers:\n  Lan: {type: http, url: 'http://127.0.0.1:9/list'}\n";
        reply("200 OK", &[], doc.as_bytes())
    })
    .await;
    let f = plan_fetcher(vec![Route::Direct], false);
    let got = run(
        &f,
        &FetchRequest::new(server.url("/clash"), ClientDevice::Pc),
    )
    .await
    .unwrap();
    assert_eq!(got.providers[0].failed, Some(ProviderFailure::Refused));
    assert!(!got.complete());
}
