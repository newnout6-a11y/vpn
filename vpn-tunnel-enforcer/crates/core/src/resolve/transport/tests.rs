use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vpnte_base::http;

use super::*;

/// What the fake DoH server saw: request line, headers (lowercase) and body.
#[derive(Default, Debug)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

/// A one-shot plain-HTTP server on loopback answering `status` with `body`.
async fn doh_server(status: u16, body: Vec<u8>) -> (String, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/dns-query", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    let log = seen.clone();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).await.unwrap_or(0) == 1 {
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length: "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mut request = vec![0u8; len];
        s.read_exact(&mut request).await.unwrap();
        *log.lock() = Seen {
            head,
            body: request,
        };
        let reply = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/dns-message\r\n\
             content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        let _ = s.write_all(reply.as_bytes()).await;
        let _ = s.write_all(&body).await;
    });
    (url, seen)
}

fn client() -> reqwest::Client {
    http::client_builder(Duration::from_secs(5))
        .build()
        .unwrap()
}

/// RFC 8484 POST: the question is the body, both content headers name the DNS message type.
#[tokio::test]
async fn doh_posts_the_wire_question() {
    let (url, seen) = doh_server(200, b"\x12\x34reply".to_vec()).await;
    let reply = doh(&client(), &url, b"\x12\x34question").await.unwrap();
    assert_eq!(reply, b"\x12\x34reply");
    let seen = seen.lock();
    assert!(
        seen.head.starts_with("post /dns-query http/1.1"),
        "{}",
        seen.head
    );
    assert!(
        seen.head.contains("accept: application/dns-message"),
        "{}",
        seen.head
    );
    assert!(
        seen.head.contains("content-type: application/dns-message"),
        "{}",
        seen.head
    );
    assert_eq!(seen.body, b"\x12\x34question");
}

/// Every refusal is an error that says why, with the cause chain (what the debug log shows).
#[tokio::test]
async fn doh_refuses_errors_and_oversized_bodies() {
    let why = |r: anyhow::Result<Vec<u8>>| format!("{:#}", r.unwrap_err());
    let (url, _) = doh_server(502, b"busy".to_vec()).await;
    assert!(why(doh(&client(), &url, b"q").await).contains("HTTP 502"));
    let (url, _) = doh_server(200, vec![0u8; BODY_CAP + 1]).await;
    assert!(why(doh(&client(), &url, b"q").await).contains("over 65536 bytes"));
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        format!("http://{}/dns-query", listener.local_addr().unwrap())
    };
    let refused = why(doh(&client(), &closed, b"q").await);
    assert!(refused.starts_with("error sending request: "), "{refused}");
    assert!(
        !refused.contains("127.0.0.1"),
        "no URL in the error: {refused}"
    );
}

/// RFC 1035 §4.2.2: two-byte length prefix both ways.
#[tokio::test]
async fn tcp_frames_the_question_and_the_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await.unwrap();
        let mut question = vec![0u8; usize::from(u16::from_be_bytes(len))];
        s.read_exact(&mut question).await.unwrap();
        s.write_all(&[0, 5]).await.unwrap();
        s.write_all(b"reply").await.unwrap();
        question
    });
    let reply = tcp(addr, None, b"question").await.unwrap();
    assert_eq!(reply, b"reply");
    assert_eq!(server.await.unwrap(), b"question");
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    assert!(tcp(closed, None, b"question").await.is_err());
}
