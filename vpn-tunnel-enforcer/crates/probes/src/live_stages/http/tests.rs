use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::net::TcpListener;

use super::*;
use crate::live_stages::{CANCELLED, ProbeRoute};

type Log = Arc<Mutex<Vec<String>>>;
/// (response bytes, then dribble the rest of a 40-byte body one byte per 100 ms).
type Handler = fn(&str, &str, u16) -> (Vec<u8>, bool);

fn reply(head: &str, body: &[u8]) -> (Vec<u8>, bool) {
    let mut bytes = head.replace('\n', "\r\n").into_bytes();
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(body);
    (bytes, false)
}

/// Loopback server (TLS when `tls`) logging `METHOD target host` per request.
async fn serve(handler: Handler, tls: bool) -> (SocketAddr, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log: Log = Arc::default();
    let seen = log.clone();
    let acceptor =
        tokio_rustls::TlsAcceptor::from(crate::live_stages::tls::tests::server_config(&[]));
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (seen, acceptor) = (seen.clone(), acceptor.clone());
            tokio::spawn(async move {
                let mut io: Box<dyn Io> = if tls {
                    Box::new(acceptor.accept(sock).await.unwrap())
                } else {
                    Box::new(sock)
                };
                let mut buf = Vec::new();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if fill(&mut io, &mut buf).await.is_err() {
                        return;
                    }
                }
                let text = String::from_utf8_lossy(&buf).into_owned();
                let mut words = text.split_whitespace();
                let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
                let host = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Host: "))
                    .unwrap_or("");
                seen.lock().push(format!("{method} {target} {host}"));
                let (bytes, dribble) = handler(method, target, addr.port());
                let _ = io.write_all(&bytes).await;
                if dribble {
                    for _ in 0..40 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        if io.write_all(b"x").await.is_err() {
                            return;
                        }
                    }
                }
                let _ = io.shutdown().await;
            });
        }
    });
    (addr, log)
}

async fn probe(addr: SocketAddr, authority: &str, tls: bool) -> HttpInfo {
    probe_http(
        addr,
        tls,
        authority,
        None,
        &ProbePath::Os,
        &CancellationToken::new(),
    )
    .await
}

/// AT-05-001: HEAD banner (§7.1).
#[tokio::test]
async fn head_banner() {
    let (addr, log) = serve(
            |_, _, _| reply("HTTP/1.1 200 OK\nServer: test-server/1.0\nVia: 1.1 test-proxy\nContent-Length: 0\n", b""),
            false,
        )
        .await;
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
    assert_eq!(info.status_code, Some(200));
    assert_eq!(info.server_header.as_deref(), Some("test-server/1.0"));
    assert_eq!(info.via_header.as_deref(), Some("1.1 test-proxy"));
    assert_eq!(info.protocol.as_deref(), Some("HTTP/1.1"));
    assert_eq!((info.target_port, info.is_tls), (addr.port(), false));
    assert_eq!(info.timed.route, Some(ProbeRoute::Os));
    assert_eq!(
        log.lock().clone(),
        [format!("HEAD / 127.0.0.1:{}", addr.port())]
    );
}

/// AT-00-003: 405 on HEAD retries GET; the body is counted (§7.5).
#[tokio::test]
async fn head_405_retries_get() {
    let (addr, log) = serve(
        |m, _, _| match m {
            "HEAD" => reply("HTTP/1.1 405 Method Not Allowed\nContent-Length: 0\n", b""),
            _ => reply(
                "HTTP/1.1 200 OK\nContent-Type: text/plain\nContent-Length: 4\n",
                b"body",
            ),
        },
        false,
    )
    .await;
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(
        (info.status_code, info.body_size),
        (Some(200), Some(4)),
        "{info:?}"
    );
    assert_eq!(info.content_type.as_deref(), Some("text/plain"));
    let methods: Vec<String> = log.lock().iter().map(|l| l[..4].to_owned()).collect();
    assert_eq!(methods, ["HEAD", "GET "]);
}

/// AT-05-001 (audit 275-290): same-origin redirect keeps method, query and the original
/// authority + port in Host; 405 then GET; final 204 (§7.5, §7.11).
#[tokio::test]
async fn follows_same_origin_redirects() {
    let (addr, log) = serve(
        |m, t, _| match (m, t) {
            ("HEAD", "/") => reply(
                "HTTP/1.1 302 Found\nLocation: /next?value=1\nContent-Length: 0\n",
                b"",
            ),
            ("HEAD", _) => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
            _ => reply("HTTP/1.1 204 No Content\n", b""),
        },
        false,
    )
    .await;
    let info = probe(addr, "audit.example", false).await;
    assert_eq!(info.status_code, Some(204), "{info:?}");
    assert_eq!(info.target_port, addr.port());
    let host = format!("audit.example:{}", addr.port());
    assert_eq!(
        log.lock().clone(),
        [
            format!("HEAD / {host}"),
            format!("HEAD /next?value=1 {host}"),
            format!("GET /next?value=1 {host}")
        ]
    );
}

/// B-06 guard: a cross-origin redirect is reported, never followed; the stored Location
/// has no query, fragment or userinfo.
#[tokio::test]
async fn cross_origin_redirect_is_not_followed() {
    let (addr, log) = serve(
            |_, _, _| reply("HTTP/1.1 302 Found\nLocation: http://user:pw@other.example/target?token=secret123#frag\nContent-Length: 0\n", b""),
            false,
        )
        .await;
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(info.status_code, Some(302));
    assert_eq!(
        info.location_header.as_deref(),
        Some("http://other.example/target")
    );
    assert_eq!(log.lock().len(), 1);
}

/// At most 3 redirects; the last 3xx is the result.
#[tokio::test]
async fn redirect_cap() {
    let (addr, log) = serve(
            |_, _, port| reply(&format!("HTTP/1.1 301 Moved\nLocation: http://127.0.0.1:{port}/loop?x=1\nContent-Length: 0\n"), b""),
            false,
        )
        .await;
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(info.status_code, Some(301));
    let expected = format!("http://127.0.0.1:{}/loop", addr.port());
    assert_eq!(info.location_header.as_deref(), Some(expected.as_str()));
    assert_eq!(log.lock().len(), 4);
}

/// AT-00-003: body cap 8192 (Content-Length and chunked) (§7.5).
#[tokio::test]
async fn body_is_capped() {
    let (addr, _) = serve(
        |m, _, _| match m {
            "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
            _ => reply("HTTP/1.1 200 OK\nContent-Length: 9000\n", &[b'a'; 9000]),
        },
        false,
    )
    .await;
    assert_eq!(probe(addr, "127.0.0.1", false).await.body_size, Some(8192));
    let chunked = serve(
        |m, _, _| match m {
            "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
            _ => reply(
                "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n",
                b"4\r\nbody\r\n2;x=y\r\nok\r\n0\r\n\r\n",
            ),
        },
        false,
    )
    .await;
    assert_eq!(
        probe(chunked.0, "127.0.0.1", false).await.body_size,
        Some(6)
    );
}

/// AT-00-003 (audit second review): the 3.5 s deadline covers a dribbling body.
#[tokio::test]
async fn deadline_covers_the_body() {
    let (addr, _) = serve(
        |m, _, _| match m {
            "HEAD" => reply("HTTP/1.1 405 No\nContent-Length: 0\n", b""),
            _ => (
                b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n".to_vec(),
                true,
            ),
        },
        false,
    )
    .await;
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(info.timed.status, TimedStatus::Error);
    assert!(info.timed.error.as_deref().unwrap().contains("deadline"));
    assert!(info.timed.duration_ms < 4100, "{}", info.timed.duration_ms);
}

/// AT-00-003: cancelled before start -> skipped, no request; early close -> error.
#[tokio::test]
async fn cancel_and_early_close() {
    let (addr, log) = serve(|_, _, _| (Vec::new(), false), false).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let info = probe_http(addr, false, "127.0.0.1", None, &ProbePath::Os, &cancel).await;
    assert_eq!(info.timed.status, TimedStatus::Skipped);
    assert_eq!(info.timed.error.as_deref(), Some(CANCELLED));
    assert!(log.lock().is_empty());
    let info = probe(addr, "127.0.0.1", false).await;
    assert_eq!(info.timed.status, TimedStatus::Error);
    assert_eq!(
        info.timed.error.as_deref(),
        Some("HTTP response closed before completion")
    );
}

/// HTTPS against a self-signed certificate still answers (we inspect, not trust).
#[tokio::test]
async fn https_banner() {
    let (addr, log) = serve(
        |_, _, _| {
            reply(
                "HTTP/1.1 200 OK\nServer: tls-test\nContent-Length: 0\n",
                b"",
            )
        },
        true,
    )
    .await;
    let info = probe_http(
        addr,
        true,
        "unrelated.example",
        None,
        &ProbePath::Os,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(info.timed.status, TimedStatus::Ok, "{info:?}");
    assert_eq!(
        (info.server_header.as_deref(), info.is_tls),
        (Some("tls-test"), true)
    );
    assert_eq!(
        log.lock()[0],
        format!("HEAD / unrelated.example:{}", addr.port())
    );
}
