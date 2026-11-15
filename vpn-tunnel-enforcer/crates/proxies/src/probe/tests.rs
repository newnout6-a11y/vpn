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
    assert!(matches!(err, ProbeError::Transport(_)), "{err:?}");

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

    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let err = probe(port, &test_config()).await.unwrap_err();
    assert!(matches!(err, ProbeError::LocalInbound(_)), "{err:?}");
}

/// B-5: a 5xx counts against the route only where the proxy answers for the service (plain
/// HTTP); through an HTTPS tunnel it came from the service, so the route works.
#[test]
fn a_tunnelled_5xx_is_the_service_answering() {
    assert!(matches!(
        status_failure("a", 502, false),
        Fail::Transport(_)
    ));
    assert!(matches!(status_failure("a", 502, true), Fail::Answered(_)));
    for tunnelled in [false, true] {
        assert!(matches!(
            status_failure("a", 429, tunnelled),
            Fail::Answered(_)
        ));
    }
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
