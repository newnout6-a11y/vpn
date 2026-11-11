use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::net::is_public_ip;

/// What a fake endpoint saw: number of requests and the questions `(name, type, accept)`.
#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    questions: Mutex<Vec<(String, String, String)>>,
}

/// Plain-HTTP DoH endpoint on loopback; `answer(type)` gives `(status, body)`.
async fn endpoint(answer: fn(&str) -> (u16, String)) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/dns-query", listener.local_addr().unwrap());
    let seen = Arc::new(Seen::default());
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).await.unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
                let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
                let query = Url::parse(&format!("http://x{path}")).unwrap();
                let param = |key: &str| {
                    let mut pairs = query.query_pairs();
                    pairs
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default()
                };
                let accept = head
                    .lines()
                    .find_map(|line| line.strip_prefix("accept: "))
                    .unwrap_or_default()
                    .to_owned();
                let rtype = param("type");
                log.requests.fetch_add(1, Ordering::SeqCst);
                log.questions
                    .lock()
                    .push((param("name"), rtype.clone(), accept));
                let (status, body) = answer(&rtype);
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/dns-json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(response.as_bytes()).await;
            });
        }
    });
    (url, seen)
}

fn reply(status: u32, answers: &[(u16, &str)]) -> String {
    let answers: Vec<_> = answers
        .iter()
        .map(|(record, data)| serde_json::json!({"name": "x.", "type": record, "TTL": 60, "data": data}))
        .collect();
    serde_json::json!({"Status": status, "Answer": answers}).to_string()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn any(_: IpAddr) -> bool {
    true
}

/// A and AAAA merged, IPv4 first; CNAME steps, malformed data and wrong families skipped; the
/// filter drops private answers; the JSON accept header is sent (profiles §3.7, S-29).
#[tokio::test]
async fn doh_merges_a_and_aaaa() {
    let (url, seen) = endpoint(|rtype| match rtype {
        "a" => (
            200,
            reply(
                0,
                &[
                    (5, "alias.example.net."),
                    (1, "93.184.216.34"),
                    (1, "10.0.0.1"),
                    (1, "999.1.1.1"),
                    (1, "2001:4860::1"),
                ],
            ),
        ),
        _ => (
            200,
            reply(0, &[(28, "2606:2800:220:1::1"), (28, "93.184.216.35")]),
        ),
    })
    .await;
    let found = doh(&[url.as_str()], "example.com", &is_public_ip).await;
    assert_eq!(
        found,
        Ok(vec![ip("93.184.216.34"), ip("2606:2800:220:1::1")])
    );
    let mut questions = seen.questions.lock().clone();
    questions.sort();
    assert_eq!(
        questions,
        [
            (
                "example.com".into(),
                "a".into(),
                "application/dns-json".into()
            ),
            (
                "example.com".into(),
                "aaaa".into(),
                "application/dns-json".into()
            ),
        ]
    );
}

/// S-29: a poisoned DoH answer (`127.0.0.1`) is never returned.
#[tokio::test]
async fn doh_poisoned_answers_are_filtered() {
    let (first, _) = endpoint(|_| (200, reply(0, &[(1, "127.0.0.1"), (28, "::1")]))).await;
    let (second, _) = endpoint(|_| (200, reply(0, &[(1, "0.0.0.0")]))).await;
    let found = doh(
        &[first.as_str(), second.as_str()],
        "example.com",
        &is_public_ip,
    )
    .await;
    assert_eq!(found, Err(ResolveError::Filtered));
}

#[tokio::test]
async fn doh_first_endpoint_with_answers_wins() {
    let (first, _) = endpoint(|_| (200, reply(0, &[(1, "1.1.1.1")]))).await;
    let (second, seen) = endpoint(|_| (200, reply(0, &[(1, "8.8.8.8")]))).await;
    let found = doh(&[first.as_str(), second.as_str()], "example.com", &any).await;
    assert_eq!(found, Ok(vec![ip("1.1.1.1")]));
    assert_eq!(seen.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn doh_falls_back_on_errors() {
    let (broken, _) = endpoint(|_| (500, String::new())).await;
    let (garbage, _) = endpoint(|_| (200, "<html>blocked</html>".into())).await;
    let (good, _) = endpoint(|rtype| match rtype {
        "a" => (200, reply(0, &[(1, "8.8.4.4")])),
        _ => (200, reply(3, &[])),
    })
    .await;
    let endpoints = [broken.as_str(), garbage.as_str(), good.as_str()];
    let found = doh(&endpoints, "example.com", &any).await;
    assert_eq!(found, Ok(vec![ip("8.8.4.4")]));
}

#[tokio::test]
async fn doh_error_precedence() {
    let (nxdomain, _) = endpoint(|_| (200, reply(3, &[]))).await;
    let (empty, _) = endpoint(|_| (200, reply(0, &[]))).await;
    let (broken, _) = endpoint(|_| (502, String::new())).await;
    let unreachable = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}/dns-query", listener.local_addr().unwrap())
    };
    let found = doh(&[nxdomain.as_str(), broken.as_str()], "nope.example", &any).await;
    assert_eq!(found, Err(ResolveError::NotFound));
    let found = doh(&[empty.as_str()], "nope.example", &any).await;
    assert_eq!(found, Err(ResolveError::NotFound));
    let found = doh(
        &[broken.as_str(), unreachable.as_str()],
        "nope.example",
        &any,
    )
    .await;
    assert_eq!(found, Err(ResolveError::Failed));
}

/// Oversized replies are refused instead of being buffered without limit.
#[tokio::test]
async fn doh_body_is_capped() {
    let (huge, _) = endpoint(|_| {
        let filler = "x".repeat(DOH_BODY_CAP);
        (
            200,
            format!(r#"{{"Status":0,"Answer":[],"pad":"{filler}"}}"#),
        )
    })
    .await;
    let found = doh(&[huge.as_str()], "example.com", &any).await;
    assert_eq!(found, Err(ResolveError::Failed));
}

#[tokio::test]
async fn literals_and_invalid_names() {
    let found = resolve_host("1.1.1.1", How::Doh, is_public_ip).await;
    assert_eq!(found, Ok(vec![ip("1.1.1.1")]));
    let found = resolve_host(" [2001:db8::1] ", How::System, any).await;
    assert_eq!(found, Ok(vec![ip("2001:db8::1")]));
    let found = resolve_host("127.0.0.1", How::System, is_public_ip).await;
    assert_eq!(found, Err(ResolveError::Filtered));
    for bad in ["", "a b", "8.8.8.8 & calc", "999.1.1.1", "host:443"] {
        let found = resolve_host(bad, How::Doh, any).await;
        assert_eq!(found, Err(ResolveError::InvalidName), "{bad:?}");
    }
}

/// The OS resolver answers `localhost` from its built-in table (no network involved).
#[tokio::test]
async fn system_resolves_localhost() {
    let found = resolve_host("localhost", How::System, any).await.unwrap();
    assert!(found.iter().all(|ip| ip.is_loopback()), "{found:?}");
    if found.len() > 1 {
        assert!(found[0].is_ipv4(), "IPv4 first: {found:?}");
    }
    let found = resolve_host("LocalHost", How::System, is_public_ip).await;
    assert_eq!(found, Err(ResolveError::Filtered));
}

#[test]
fn ordering_and_error_mapping() {
    let addrs = vec![
        ip("2001:4860::1"),
        ip("8.8.8.8"),
        ip("2001:4860::1"),
        ip("1.1.1.1"),
    ];
    let ordered = filtered(addrs, &any).unwrap();
    assert_eq!(ordered, [ip("8.8.8.8"), ip("1.1.1.1"), ip("2001:4860::1")]);
    assert_eq!(filtered(Vec::new(), &any), Err(ResolveError::NotFound));
    assert_eq!(
        lookup_error(&io::Error::from_raw_os_error(11001)),
        ResolveError::NotFound
    );
    assert_eq!(
        lookup_error(&io::Error::from_raw_os_error(11004)),
        ResolveError::NotFound
    );
    assert_eq!(
        lookup_error(&io::Error::from_raw_os_error(10060)),
        ResolveError::Failed
    );
    let err = AppError::from(ResolveError::InvalidName);
    assert_eq!(err.kind, ErrorKind::Validation);
    let err = AppError::from(ResolveError::Filtered);
    assert_eq!(
        (err.kind, err.user_msg().key),
        (ErrorKind::Network, "core.net.resolveFiltered".into())
    );
}

/// Live check of both real endpoints (IP-literal TLS, JSON shape). Run by hand:
/// `cargo test -p vpnte-core --no-default-features --features core-net -- --ignored live_doh`.
#[tokio::test]
#[ignore = "needs internet access"]
async fn live_doh_endpoints() {
    for endpoint in DOH_ENDPOINTS {
        let found = doh(&[endpoint], "example.com", &is_public_ip).await;
        assert!(
            found.as_ref().is_ok_and(|a| !a.is_empty()),
            "{endpoint}: {found:?}"
        );
    }
    let found = resolve_host("example.com", How::Doh, is_public_ip).await;
    assert!(found.is_ok(), "{found:?}");
}
