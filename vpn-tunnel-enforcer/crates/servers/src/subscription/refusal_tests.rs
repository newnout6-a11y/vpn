//! p-subs: what a panel says about the device (Remnawave's open HWID scheme, recorded answers)
//! and subscriptions that came from outside (phones-a11). Loopback stand-ins, fake keys.
use tokio_util::sync::CancellationToken;
use url::Url;
use vpnte_base::AppError;
use vpnte_base::types::{ClientDevice, ProxyKind};
use vpnte_core::net::{HostPort, Route};

use super::tests::{KEY_A, Server, closed_port, machine, reply};
use super::*;
use crate::model::FetchOutcome;

const NOT_SENT: [(&str, &str); 2] = [("x-hwid-active", "true"), ("x-hwid-not-supported", "true")];
const LIMIT: [(&str, &str); 3] = [
    ("x-hwid-active", "true"),
    ("x-hwid-max-devices-reached", "true"),
    ("x-hwid-limit", "true"),
];

fn direct() -> SubscriptionFetcher {
    let plan = RoutePlan {
        routes: vec![Route::Direct],
        doh: false,
        relay: false,
    };
    SubscriptionFetcher::with_plan(Hwids::of(&machine(), None), plan)
}

fn request(url: Url, send_hwid: bool) -> FetchRequest {
    FetchRequest {
        send_hwid,
        ..FetchRequest::new(url, ClientDevice::Pc)
    }
}

async fn run(req: &FetchRequest) -> Result<Fetched, FetchError> {
    direct().fetch_request(req, &CancellationToken::new()).await
}

/// A Remnawave panel with the device limit on: without `x-hwid` it answers 404 with the scheme's
/// headers; with one it serves the list, or (`full`) refuses as every slot is taken.
async fn remnawave(full: bool) -> Server {
    Server::start(move |seen| match seen.header("x-hwid") {
        None => reply("404 Not Found", &NOT_SENT, b""),
        Some(_) if full => reply("404 Not Found", &LIMIT, b""),
        Some(_) => reply("200 OK", &[("x-hwid-active", "true")], KEY_A.as_bytes()),
    })
    .await
}

/// 404 + `x-hwid-not-supported`: one request, then the plan stops with the typed reason; the
/// same subscription with the HWID on is served.
#[tokio::test]
async fn a_panel_that_needs_the_hwid_says_so() {
    let panel = remnawave(false).await;
    let err = run(&request(panel.url("/sub/token"), false))
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::HwidRequired));
    assert_eq!(panel.seen().len(), 1, "no other agent is asked");
    assert_eq!(
        AppError::from(err).user_msg().key,
        "servers.fetch.hwidRequired"
    );
    let fetched = run(&request(panel.url("/sub/token"), true)).await.unwrap();
    assert_eq!(fetched.report.profiles.len(), 1);
}

/// `x-hwid-max-devices-reached`: a plain reason, and the plan stops at once.
#[tokio::test]
async fn a_full_device_limit_is_its_own_reason() {
    let panel = remnawave(true).await;
    let err = run(&request(panel.url("/sub/token"), true))
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::DeviceLimit));
    assert_eq!(panel.seen().len(), 1);
    assert_eq!(
        AppError::from(err).user_msg().key,
        "servers.fetch.deviceLimit"
    );
}

/// 403 "Device fingerprint required", an empty 200 that names the reason in its headers, and a
/// 404 to a request that carried the HWID (the subscription is gone, not the device unknown).
#[tokio::test]
async fn other_shapes_of_the_same_answer() {
    let body = br#"{"message":"Device fingerprint required","statusCode":403}"#;
    let gated = Server::start(move |_| reply("403 Forbidden", &[], body)).await;
    let err = run(&request(gated.url("/s"), false)).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::HwidRequired));
    let empty = Server::start(|_| reply("200 OK", &NOT_SENT, b"")).await;
    let err = run(&request(empty.url("/s"), false)).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::HwidRequired));
    let gone = Server::start(|_| reply("404 Not Found", &[("x-hwid-active", "true")], b"")).await;
    let err = run(&request(gone.url("/s"), true)).await.unwrap_err();
    assert_eq!(err, FetchError::Failed(FetchOutcome::Http(404)));
}

/// A reset ID replaces this PC's in the header and in the Happ User-Agent.
#[tokio::test]
async fn a_subscription_sends_its_own_id() {
    let panel = Server::start(|_| reply("200 OK", &[], KEY_A.as_bytes())).await;
    let mut req = request(panel.url("/s"), true);
    req.hwid = Some("0123456789abcdef".into());
    run(&req).await.unwrap();
    let first = &panel.seen()[0];
    assert_eq!(first.header("x-hwid"), Some("0123456789abcdef"));
    assert!(
        first
            .header("user-agent")
            .is_some_and(|ua| ua.ends_with("/0123456789abcdef"))
    );
}

/// phones-a11: a subscription that came from outside is not requested in the local network,
/// nothing is sent; typed by hand, the same address works.
#[tokio::test]
async fn a_linked_subscription_never_reaches_the_lan() {
    let panel = Server::start(|_| reply("200 OK", &[], KEY_A.as_bytes())).await;
    let mut req = request(panel.url("/sub"), false);
    req.from_link = true;
    assert_eq!(run(&req).await.unwrap_err(), FetchError::LocalTarget);
    assert!(panel.seen().is_empty(), "nothing was sent");
    let err = AppError::from(FetchError::LocalTarget);
    assert_eq!(err.user_msg().key, "profiles.deeplink.localTarget");
    req.from_link = false;
    assert_eq!(run(&req).await.unwrap().report.profiles.len(), 1);
}

/// phones-a11: a local literal or `localhost` needs no lookup, so it is refused on every plan,
/// "local proxy only" included (no route is asked).
#[tokio::test]
async fn a_linked_literal_is_refused_on_every_route() {
    let proxy = HostPort::new("127.0.0.1", closed_port().await).unwrap();
    let plan = RoutePlan {
        routes: vec![Route::proxy(ProxyKind::Http, &proxy, None)],
        doh: false,
        relay: false,
    };
    let f = SubscriptionFetcher::with_plan(Hwids::of(&machine(), None), plan);
    for url in ["http://192.168.1.10/sub", "http://localhost:8080/sub"] {
        let mut req = request(Url::parse(url).unwrap(), false);
        req.from_link = true;
        let err = f.fetch_request(&req, &CancellationToken::new()).await;
        assert_eq!(err.unwrap_err(), FetchError::LocalTarget, "{url}");
    }
}

/// phones-a11: a name counts by the addresses the system resolves it to. This PC's own name
/// resolves to its LAN / link-local addresses (skipped quietly where it does not).
#[tokio::test]
async fn a_linked_name_resolving_into_the_lan_is_refused() {
    let Ok(name) = std::env::var("COMPUTERNAME") else {
        return;
    };
    let local = tokio::net::lookup_host((name.as_str(), 80)).await;
    if !local.is_ok_and(|mut a| a.any(|a| !vpnte_core::net::is_public_ip(a.ip()))) {
        return;
    }
    let port = closed_port().await;
    let url = Url::parse(&format!("http://{name}:{port}/sub")).unwrap();
    let mut req = request(url, false);
    req.from_link = true;
    assert_eq!(run(&req).await.unwrap_err(), FetchError::LocalTarget);
}
