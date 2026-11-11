//! Availability checks against loopback servers (no Internet): native stages, the direct
//! inbound through a fake SOCKS5 server, geo-block marking, cancellation and the history.
use std::net::{IpAddr, Ipv4Addr};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::{Creds, Loopback};
use vpnte_core::ops::{OperationRegistry, RunOpts};

use super::*;
use crate::speedtest::testsrv::{Reply, Request, Server};

/// Russian text of a key of this package's locale fragment (independent of the global
/// catalog other tests may initialise).
pub(crate) fn ru(key: &str) -> String {
    let doc: Value = serde_json::from_str(include_str!("../../locales/probes-web.ru.json"))
        .expect("valid ru fragment");
    key.split('.')
        .try_fold(&doc, |v, part| v.get(part))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing ru key {key}"))
        .to_owned()
}

const PAGE: &str = "<html><head><title>Loop</title></head><body><p>a normal page with plenty of content</p></body></html>";

fn site(req: &Request) -> Reply {
    let html = |status: u16, body: &str| {
        Reply::Full(
            status,
            vec![("content-type", "text/html".into())],
            body.as_bytes().to_vec(),
        )
    };
    match req.target.split('?').next().unwrap_or_default() {
        "/page" => html(200, PAGE),
        "/geo" => html(
            200,
            "<html><body>This service is not available in your country.</body></html>",
        ),
        "/legal" => html(451, "<html><body>blocked</body></html>"),
        "/denied" => html(403, "<html><body>forbidden</body></html>"),
        "/head-refused" if req.method == "HEAD" => html(405, ""),
        "/head-refused" => html(206, "x"),
        "/broken" => Reply::Close,
        _ => html(404, "missing"),
    }
}

fn direct_env() -> CheckEnv {
    CheckEnv {
        paths: Paths::Direct,
        geo: None,
    }
}

fn target(server: &Server, path: &str) -> ProbeTarget {
    ProbeTarget::parse(server.url(path).as_str()).unwrap()
}

async fn check(env: &CheckEnv, target: &ProbeTarget) -> AvailabilityResult {
    check_url(env, target, &CancellationToken::new())
        .await
        .unwrap()
}

/// Requests that carried an HTTP request line.
fn http_requests(server: &Server) -> Vec<Request> {
    server
        .requests()
        .into_iter()
        .filter(|r| !r.method.is_empty())
        .collect()
}

/// A free loopback port nobody listens on.
fn dead_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// AT-07-003: with the tunnel off the native probe is the direct path; every stage is
/// reported and the history keeps the normalised URL only.
#[tokio::test]
async fn native_path_reaches_a_site() {
    let server = Server::start(site).await;
    let result = check(
        &direct_env(),
        &ProbeTarget::parse(&format!("http://u:p@{}/page?token=1#x", server.addr)).unwrap(),
    )
    .await;
    assert_eq!(result.url, format!("http://{}/page", server.addr));
    assert!(!result.tunnel_active && result.protected.is_none());
    let direct = result.direct.as_ref().unwrap();
    assert!(direct.measured && direct.available, "{direct:?}");
    assert_eq!(direct.source, PathSource::Native);
    assert_eq!(
        direct.dns.as_ref().unwrap().ips,
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    );
    assert!(direct.tcp.as_ref().unwrap().connected);
    assert!(direct.tls.is_none());
    assert_eq!(direct.http.as_ref().unwrap().status, Some(200));
    assert!(!direct.geo_blocked && direct.summary().is_none());
    assert_eq!(result.verdict, AvailabilityVerdict::WorksBoth);
    assert_eq!(result.recommendation, Recommendation::ReachableWithoutVpn);
    // The TCP stage connects and closes without a request.
    let methods: Vec<String> = http_requests(&server)
        .iter()
        .map(|r| r.method.clone())
        .collect();
    assert_eq!(
        methods,
        ["HEAD", "GET"],
        "status probe, then the page fetch"
    );
    let json = serde_json::to_string(&result).unwrap();
    assert!(!json.contains("token") && !json.contains("u:p"));
}

/// HEAD refused (405) falls back to a ranged GET; 403 is a refusal, not "works" (B-UA-4).
#[tokio::test]
async fn head_fallback_and_refusal() {
    let server = Server::start(site).await;
    let result = check(&direct_env(), &target(&server, "/head-refused")).await;
    assert_eq!(
        result
            .direct
            .as_ref()
            .unwrap()
            .http
            .as_ref()
            .unwrap()
            .status,
        Some(206)
    );
    let requests = http_requests(&server);
    assert_eq!(
        (requests[0].method.as_str(), requests[1].method.as_str()),
        ("HEAD", "GET")
    );
    let result = check(&direct_env(), &target(&server, "/denied")).await;
    assert_eq!(result.verdict, AvailabilityVerdict::AuthRequired);
    assert!(result.direct.as_ref().unwrap().refused());
}

/// §3.10 single-page scoring applied to the direct page; 451 is a geo block by itself.
#[tokio::test]
async fn geo_blocks_are_marked() {
    let server = Server::start(site).await;
    let result = check(&direct_env(), &target(&server, "/geo")).await;
    let direct = result.direct.as_ref().unwrap();
    assert!(direct.geo_blocked && !direct.available);
    assert!(direct.geo_reasons.contains(&GeoReason::ShortPageMarker));
    assert_eq!(
        direct.summary().unwrap().key,
        "probes.availability.fail.geoBlock"
    );
    assert_eq!(result.verdict, AvailabilityVerdict::Unknown);
    let result = check(&direct_env(), &target(&server, "/legal")).await;
    let direct = result.direct.as_ref().unwrap();
    assert!(direct.geo_blocked && direct.geo_reasons.contains(&GeoReason::Http451));
    assert_eq!(
        direct.summary().unwrap().key,
        "probes.availability.fail.legal"
    );
}

/// The stages stop at the first failure and name it with a sanitised code.
#[tokio::test]
async fn stage_failures() {
    let port = dead_port();
    let refused = ProbeTarget::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let report = check(&direct_env(), &refused).await.direct.unwrap();
    assert_eq!(
        (report.error_stage, report.error),
        (Some(Stage::Tcp), Some(ErrorCode::ConnRefused))
    );
    assert!(report.failed_in_network());

    // A TLS server that hangs up at once: the TLS stage fails, TCP succeeded.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let tls = ProbeTarget::parse(&format!("https://{addr}/")).unwrap();
    let report = check(&direct_env(), &tls).await.direct.unwrap();
    assert!(report.tcp.as_ref().unwrap().connected);
    assert_eq!(report.error_stage, Some(Stage::Tls));
    assert!(
        report.error.is_some_and(ErrorCode::is_network),
        "{:?}",
        report.error
    );

    let server = Server::start(site).await;
    let report = check(&direct_env(), &target(&server, "/broken"))
        .await
        .direct
        .unwrap();
    assert_eq!(report.error_stage, Some(Stage::Http));
    assert_eq!(report.error, Some(ErrorCode::Closed));
}

/// A minimal SOCKS5 server standing in for the engine's `mixed-direct-in` (user / password
/// when `auth`, CONNECT only).
async fn socks_inbound(auth: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                s.read_exact(&mut head).await?;
                let mut methods = vec![0u8; usize::from(head[1])];
                s.read_exact(&mut methods).await?;
                if auth {
                    s.write_all(&[5, 2]).await?;
                    let mut ver_len = [0u8; 2];
                    s.read_exact(&mut ver_len).await?;
                    let mut user = vec![0u8; usize::from(ver_len[1])];
                    s.read_exact(&mut user).await?;
                    let mut len = [0u8; 1];
                    s.read_exact(&mut len).await?;
                    let mut pass = vec![0u8; usize::from(len[0])];
                    s.read_exact(&mut pass).await?;
                    let ok = user == b"fake-user" && pass == b"fake-pass";
                    s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
                } else {
                    s.write_all(&[5, 0]).await?;
                }
                let mut req = [0u8; 4];
                s.read_exact(&mut req).await?;
                let host = match req[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        s.read_exact(&mut a).await?;
                        Ipv4Addr::from(a).to_string()
                    }
                    3 => {
                        let mut len = [0u8; 1];
                        s.read_exact(&mut len).await?;
                        let mut name = vec![0u8; usize::from(len[0])];
                        s.read_exact(&mut name).await?;
                        String::from_utf8_lossy(&name).into_owned()
                    }
                    _ => return Ok(()),
                };
                let mut port = [0u8; 2];
                s.read_exact(&mut port).await?;
                match TcpStream::connect((host.as_str(), u16::from_be_bytes(port))).await {
                    Ok(mut upstream) => {
                        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await?;
                        tokio::io::copy_bidirectional(&mut s, &mut upstream).await?;
                    }
                    Err(_) => s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await?,
                }
                Ok::<(), std::io::Error>(())
            });
        }
    });
    port
}

fn tunnel_env(inbound: Option<Loopback>) -> CheckEnv {
    CheckEnv {
        paths: Paths::Tunnel {
            tun_v4: None,
            tun_v6: None,
            direct_inbound: inbound,
        },
        geo: None,
    }
}

fn creds() -> Option<Creds> {
    Some(Creds {
        user: "fake-user".into(),
        pass: "fake-pass".into(),
    })
}

/// B-UA-2: with the tunnel up the direct side is the same HTTP probe through the direct
/// inbound (credentials included), so both sides carry real statuses.
#[tokio::test]
async fn direct_side_goes_through_the_inbound() {
    let server = Server::start(site).await;
    let port = socks_inbound(true).await;
    let env = tunnel_env(Some(Loopback {
        port,
        creds: creds(),
    }));
    let result = check(&env, &target(&server, "/page")).await;
    assert!(result.tunnel_active);
    let direct = result.direct.as_ref().unwrap();
    assert_eq!(direct.source, PathSource::DirectInbound);
    assert!(direct.measured && direct.available, "{direct:?}");
    assert!(direct.dns.is_none() && direct.tcp.is_none());
    assert_eq!(
        result.protected.as_ref().unwrap().source,
        PathSource::Native
    );
    assert_eq!(result.verdict, AvailabilityVerdict::WorksBoth);
}

/// B-UA-3 (C-05): a missing or dead inbound is "not measured" and the verdict is Unknown,
/// never "the provider blocks it".
#[tokio::test]
async fn unmeasured_direct_side_is_unknown() {
    let server = Server::start(site).await;
    for inbound in [
        None,
        Some(Loopback {
            port: dead_port(),
            creds: None,
        }),
    ] {
        let result = check(&tunnel_env(inbound), &target(&server, "/page")).await;
        let direct = result.direct.as_ref().unwrap();
        assert!(!direct.measured);
        assert_eq!(direct.error, Some(ErrorCode::ProxyFailed));
        assert!(result.protected.as_ref().unwrap().available);
        assert_eq!(result.verdict, AvailabilityVerdict::Unknown);
        assert_eq!(result.recommendation, Recommendation::PathNotMeasured);
    }
}

/// urlAvailabilityOperation.test.ts: an already-cancelled call makes no request; success
/// commits one row at the front; two checks commit separately; a bad URL is refused before
/// admission.
#[tokio::test]
async fn operation_and_history() {
    let server = Server::start(site).await;
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let err = check_url(&direct_env(), &target(&server, "/page"), &cancelled)
        .await
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(server.requests().is_empty());

    let root = crate::speedtest::tests::TempRoot::new();
    let history = root.store::<UrlChecks>();
    let mut earlier = check(&direct_env(), &target(&server, "/page")).await;
    earlier.id = "earlier".into();
    history.update(|doc| doc.push(earlier)).unwrap();
    let ops = OperationRegistry::new();
    let url = server.url("/page").to_string();
    let (a, b) = tokio::join!(
        run_check(
            &ops,
            history.clone(),
            direct_env(),
            &url,
            RunOpts::default()
        ),
        run_check(
            &ops,
            history.clone(),
            direct_env(),
            &url,
            RunOpts::default()
        ),
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    let ids: Vec<String> = history
        .snapshot()
        .history
        .iter()
        .map(|r| r.id.clone())
        .collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.contains(&a.id) && ids.contains(&b.id));
    assert_eq!(ids[2], "earlier");

    let err = run_check(
        &ops,
        history.clone(),
        direct_env(),
        "ftp://example.test",
        RunOpts::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::Validation);
    assert_eq!(history.snapshot().history.len(), 3);
}

/// Flattened `key → text` of a fragment.
fn flatten(json: &str) -> std::collections::BTreeMap<String, String> {
    fn walk(prefix: &str, v: &Value, out: &mut std::collections::BTreeMap<String, String>) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    walk(&key, v, out);
                }
            }
            Value::String(s) => {
                out.insert(prefix.to_owned(), s.clone());
            }
            other => panic!("{prefix}: not a string: {other}"),
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(
        "",
        &serde_json::from_str(json).expect("valid JSON fragment"),
        &mut out,
    );
    out
}

/// CONTRACT §3.2: the fragments are valid JSON under `probes`, with the same keys and
/// placeholders in ru and en, and every key the code names exists.
#[test]
fn locale_fragments_cover_every_key() {
    let ru = flatten(include_str!("../../locales/probes-web.ru.json"));
    let en = flatten(include_str!("../../locales/probes-web.en.json"));
    assert_eq!(ru.keys().collect::<Vec<_>>(), en.keys().collect::<Vec<_>>());
    let placeholder = regex::Regex::new(r"\{\{(\w+)\}\}").unwrap();
    let vars = |s: &str| {
        placeholder
            .captures_iter(s)
            .map(|c| c[1].to_owned())
            .collect::<Vec<_>>()
    };
    for (key, text) in &ru {
        assert!(key.starts_with("probes."), "{key}");
        assert_eq!(vars(text), vars(&en[key]), "{key}");
    }
    let sources = [
        include_str!("mod.rs"),
        include_str!("target.rs"),
        include_str!("report.rs"),
        include_str!("verdict.rs"),
        include_str!("geo_block.rs"),
        include_str!("probe.rs"),
        include_str!("history.rs"),
        include_str!("../speedtest/mod.rs"),
        include_str!("../speedtest/maths.rs"),
        include_str!("../speedtest/rounds.rs"),
        include_str!("../speedtest/history.rs"),
    ];
    let literal = regex::Regex::new(r#""(probes\.[A-Za-z0-9_.]+)""#).unwrap();
    let mut used = 0;
    for source in sources {
        for key in literal.captures_iter(source) {
            used += 1;
            assert!(ru.contains_key(&key[1]), "missing locale key {}", &key[1]);
        }
    }
    assert!(used > 60, "the scan found the keys ({used})");
}
