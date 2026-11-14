use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::*;

fn creds(user: &str, pass: &str) -> Creds {
    Creds {
        user: user.into(),
        pass: pass.into(),
    }
}

fn slot_creds() -> Creds {
    creds("slot-user", "slot-password")
}

fn auth_bytes(user: &str, pass: &str) -> Vec<u8> {
    let mut out = vec![1, user.len() as u8];
    out.extend_from_slice(user.as_bytes());
    out.push(pass.len() as u8);
    out.extend_from_slice(pass.as_bytes());
    out
}

async fn bind() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn proxy(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

async fn expect(stream: &mut TcpStream, bytes: &[u8]) {
    let mut buf = vec![0u8; bytes.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(buf, bytes);
}

/// Writes byte by byte with pauses so the client sees fragmented replies.
async fn write_fragmented(stream: &mut TcpStream, bytes: &[u8]) {
    for byte in bytes {
        stream.write_all(&[*byte]).await.unwrap();
        stream.flush().await.unwrap();
        sleep(Duration::from_millis(5)).await;
    }
}

/// True once the client has closed its end without sending anything more.
async fn closed_by_client(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(stream.read(&mut byte).await, Ok(0) | Err(_))
}

/// One-shot server: for each step, checks the client's bytes and answers; then waits for EOF.
async fn scripted(steps: Vec<(Vec<u8>, Vec<u8>)>) -> (u16, JoinHandle<()>) {
    let (listener, port) = bind().await;
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        for (want, answer) in steps {
            expect(&mut s, &want).await;
            s.write_all(&answer).await.unwrap();
        }
        let mut sink = Vec::new();
        let _ = s.read_to_end(&mut sink).await;
    });
    (port, server)
}

/// Accepts connections forever, counting them; `close` drops each at once, else they are held.
async fn counting(close: bool) -> (u16, Arc<AtomicUsize>) {
    let (listener, port) = bind().await;
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            if !close {
                held.push(s);
            }
        }
    });
    (port, accepted)
}

fn target(s: &str) -> HostPort {
    HostPort::parse(s).unwrap()
}

/// AT-02-002 (xraySlots.test.ts): RFC 1929 request bytes and input limits.
#[test]
fn auth_request_bytes_and_limits() {
    let mut want = vec![1, 9];
    want.extend_from_slice(b"slot-user");
    want.push(13);
    want.extend_from_slice(b"slot-password");
    assert_eq!(encode_auth(&slot_creds()).unwrap(), want);
    assert_eq!(
        encode_auth(&creds("", "secret")),
        Err(SocksError::InvalidInput)
    );
    let long = "я".repeat(128); // 256 bytes
    assert_eq!(
        encode_auth(&creds("user", &long)),
        Err(SocksError::InvalidInput)
    );
    assert!(encode_auth(&creds("u", &"p".repeat(255))).is_ok());
}

/// B24 + socksPing.test.ts: ATYP 1 for IPv4, 4 for IPv6 (also IPv4-mapped → 1), 3 for names.
#[test]
fn connect_request_bytes() {
    let v4 = encode_connect(&target("1.2.3.4:80"));
    assert_eq!(v4, [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    let v6 = encode_connect(&target("[2001:db8::1]:443"));
    let mut want = vec![5, 1, 0, 4];
    want.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    want.extend_from_slice(&[1, 187]);
    assert_eq!(v6, want);
    let mapped = encode_connect(&target("[::ffff:1.2.3.4]:80"));
    assert_eq!(mapped, [5, 1, 0, 1, 1, 2, 3, 4, 0, 80]);
    let name = encode_connect(&target("example.com:443"));
    let mut want = vec![5, 1, 0, 3, 11];
    want.extend_from_slice(b"example.com");
    want.extend_from_slice(&[1, 187]);
    assert_eq!(name, want);
}

/// AT-02-002 (xraySlots.test.ts): readiness bytes with fragmented replies; socket closed once.
#[tokio::test]
async fn readiness_with_fragmented_auth_replies() {
    let (listener, port) = bind().await;
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        expect(&mut s, &[5, 1, 2]).await;
        write_fragmented(&mut s, &[5, 2]).await;
        expect(&mut s, &auth_bytes("slot-user", "slot-password")).await;
        write_fragmented(&mut s, &[1, 0]).await;
        closed_by_client(&mut s).await
    });
    let cancel = CancellationToken::new();
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(2), &cancel).await;
    assert_eq!(ready, Ok(()));
    assert!(
        server.await.unwrap(),
        "the probe socket is closed after success"
    );
}

/// AT-02-004: a listener that picks NoAuth is not our authenticated slot; no retry loop.
#[tokio::test]
async fn readiness_refuses_an_unauthenticated_listener() {
    let (port, _server) = scripted(vec![(vec![5, 1, 2], vec![5, 0])]).await;
    let started = Instant::now();
    let cancel = CancellationToken::new();
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(3), &cancel).await;
    assert_eq!(ready, Err(SocksError::AuthRequired));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "definite answers are not retried"
    );
}

#[tokio::test]
async fn readiness_reports_rejected_credentials() {
    let steps = vec![
        (vec![5, 1, 2], vec![5, 2]),
        (auth_bytes("slot-user", "slot-password"), vec![1, 1]),
    ];
    let (port, _server) = scripted(steps).await;
    let cancel = CancellationToken::new();
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(3), &cancel).await;
    assert_eq!(ready, Err(SocksError::AuthRejected));
}

#[tokio::test]
async fn readiness_rejects_a_non_socks_server() {
    let (port, _server) = scripted(vec![(vec![5, 1, 2], vec![4, 2])]).await;
    let cancel = CancellationToken::new();
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(3), &cancel).await;
    assert_eq!(ready, Err(SocksError::Malformed));
}

/// Without credentials an accepted connection is enough and nothing is sent.
#[tokio::test]
async fn readiness_without_credentials_is_a_tcp_accept() {
    let (listener, port) = bind().await;
    let server = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        closed_by_client(&mut s).await
    });
    let cancel = CancellationToken::new();
    assert_eq!(
        wait_ready(port, None, Duration::from_secs(2), &cancel).await,
        Ok(())
    );
    assert!(server.await.unwrap());
}

/// AT-00-003 (xraySocksCancellation.test.ts): a held attempt is cancelled immediately.
#[tokio::test]
async fn held_attempt_is_cancelled_immediately() {
    let (port, accepted) = counting(false).await;
    let cancel = CancellationToken::new();
    let canceller = cancel.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(50)).await;
        canceller.cancel();
    });
    let started = Instant::now();
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(3), &cancel).await;
    assert_eq!(ready, Err(SocksError::Cancelled));
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

/// AT-00-003: cancel during the retry pause → no further connection attempt.
#[tokio::test]
async fn cancel_during_the_pause_stops_attempts() {
    let (port, accepted) = counting(true).await;
    let cancel = CancellationToken::new();
    let canceller = cancel.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(40)).await;
        canceller.cancel();
    });
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(3), &cancel).await;
    assert_eq!(ready, Err(SocksError::Cancelled));
    let seen = accepted.load(Ordering::SeqCst);
    sleep(Duration::from_millis(300)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), seen);
    assert_eq!(seen, 1);
}

/// AT-00-007 (old "refused connects with 350 ms budget → 4 attempts"): attempts start every
/// ~100 ms; Windows timer granularity may push the fourth past the budget.
#[tokio::test]
async fn budget_bounds_the_attempts() {
    let (port, accepted) = counting(true).await;
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let total = Duration::from_millis(350);
    let ready = wait_ready(port, Some(&slot_creds()), total, &cancel).await;
    let elapsed = started.elapsed();
    assert_eq!(ready, Err(SocksError::Closed));
    assert!(
        (3..=4).contains(&accepted.load(Ordering::SeqCst)),
        "{accepted:?}"
    );
    assert!(
        elapsed >= total && elapsed < Duration::from_millis(600),
        "{elapsed:?}"
    );
}

/// Nothing listens: the deadline still holds (Windows retries refused loopback SYNs for ~2 s).
#[tokio::test]
async fn closed_port_respects_the_deadline() {
    let (listener, port) = bind().await;
    drop(listener);
    let cancel = CancellationToken::new();
    let started = Instant::now();
    let ready = wait_ready(port, None, Duration::from_millis(300), &cancel).await;
    assert!(
        matches!(ready, Err(SocksError::Connect(_) | SocksError::Timeout)),
        "{ready:?}"
    );
    assert!(started.elapsed() < Duration::from_millis(600));
}

/// A pre-cancelled token and invalid input never touch the network.
#[tokio::test]
async fn no_io_when_cancelled_or_invalid() {
    let (port, accepted) = counting(false).await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let ready = wait_ready(port, None, Duration::from_secs(1), &cancel).await;
    assert_eq!(ready, Err(SocksError::Cancelled));
    let fresh = CancellationToken::new();
    let bad = creds("", "secret");
    let ready = wait_ready(port, Some(&bad), Duration::from_secs(1), &fresh).await;
    assert_eq!(ready, Err(SocksError::InvalidInput));
    let ready = wait_ready(0, None, Duration::from_secs(1), &fresh).await;
    assert_eq!(ready, Err(SocksError::InvalidInput));
    sleep(Duration::from_millis(50)).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}

/// Connects through a scripted server whose CONNECT reply is `reply`, then reads the payload
/// sent right after it: getting it intact proves the reply was consumed to the exact byte.
async fn connect_with_reply(target_addr: &str, reply: Vec<u8>) -> Result<Vec<u8>, SocksError> {
    let target = target(target_addr);
    let mut answer = reply;
    answer.extend_from_slice(b"payload");
    let steps = vec![
        (vec![5, 1, 0], vec![5, 0]),
        (encode_connect(&target), answer),
    ];
    let (port, _server) = scripted(steps).await;
    let mut stream = connect(proxy(port), None, &target, Duration::from_secs(2)).await?;
    let mut payload = vec![0u8; 7];
    stream.read_exact(&mut payload).await.unwrap();
    Ok(payload)
}

/// socksPing.test.ts: `05 00` then `05 00 00 01 7F 00 00 01 00 50` → connected to example.com.
#[tokio::test]
async fn connects_by_name() {
    let reply = vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 80];
    let payload = connect_with_reply("example.com:443", reply).await.unwrap();
    assert_eq!(payload, b"payload");
}

/// servers §7 #23 (socksPing.ts:14-20): reply length by ATYP — 1 → 10, 4 → 22, 3 → 7 + len.
#[tokio::test]
async fn reply_length_follows_the_address_type() {
    let mut v6 = vec![5, 0, 0, 4];
    v6.extend_from_slice(&[0u8; 16]);
    v6.extend_from_slice(&[0, 80]);
    assert_eq!(v6.len(), 22);
    let mut named = vec![5, 0, 0, 3, 9];
    named.extend_from_slice(b"bound.lan");
    named.extend_from_slice(&[0, 80]);
    assert_eq!(named.len(), 7 + 9);
    for reply in [v6, named] {
        let payload = connect_with_reply("[2001:db8::1]:443", reply)
            .await
            .unwrap();
        assert_eq!(payload, b"payload");
    }
    let bad_atyp = vec![5, 0, 0, 7, 0, 0];
    let err = connect_with_reply("1.2.3.4:443", bad_atyp)
        .await
        .unwrap_err();
    assert_eq!(err, SocksError::Malformed);
}

/// socksPing.test.ts: reply code 5 (connection refused) is a typed rejection.
#[tokio::test]
async fn upstream_rejection_keeps_the_code() {
    let reply = vec![5, 5, 0, 1, 0, 0, 0, 0, 0, 0];
    let err = connect_with_reply("example.com:443", reply)
        .await
        .unwrap_err();
    assert_eq!(err, SocksError::UpstreamRejected(5));
}

/// xray §2.10 (new): with credentials only `05 01 02` is offered, RFC 1929 follows, and a
/// server that picks NoAuth is refused.
#[tokio::test]
async fn credentials_offer_only_user_pass() {
    let user = creds("u", "p");
    let target = target("example.com:443");
    let steps = vec![
        (vec![5, 1, 2], vec![5, 2]),
        (auth_bytes("u", "p"), vec![1, 0]),
        (encode_connect(&target), vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
    ];
    let (port, server) = scripted(steps).await;
    let stream = connect(proxy(port), Some(&user), &target, Duration::from_secs(2));
    drop(stream.await.unwrap());
    server.await.unwrap();

    let (port, _server) = scripted(vec![(vec![5, 1, 2], vec![5, 0])]).await;
    let result = connect(proxy(port), Some(&user), &target, Duration::from_secs(2));
    assert_eq!(result.await.unwrap_err(), SocksError::AuthRequired);
}

/// Without credentials a server demanding them (`05 FF`) is "authentication required".
#[tokio::test]
async fn no_acceptable_method() {
    let (port, _server) = scripted(vec![(vec![5, 1, 0], vec![5, 0xff])]).await;
    let dst = target("1.2.3.4:80");
    let result = connect(proxy(port), None, &dst, Duration::from_secs(2));
    assert_eq!(result.await.unwrap_err(), SocksError::AuthRequired);
}

/// One total deadline per attempt (B24): a server that never answers.
#[tokio::test]
async fn connect_has_one_deadline() {
    let (port, _accepted) = counting(false).await;
    let started = Instant::now();
    let dst = target("1.2.3.4:80");
    let result = connect(proxy(port), None, &dst, Duration::from_millis(200));
    assert_eq!(result.await.unwrap_err(), SocksError::Timeout);
    assert!(started.elapsed() < Duration::from_millis(500));
}

/// A closed connection mid-handshake and invalid credentials (checked before any I/O).
#[tokio::test]
async fn closed_and_invalid() {
    let (port, _accepted) = counting(true).await;
    let dst = target("1.2.3.4:80");
    let result = connect(proxy(port), None, &dst, Duration::from_secs(2));
    assert_eq!(result.await.unwrap_err(), SocksError::Closed);
    let (unused, _) = bind().await;
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let bad = creds("user", &"я".repeat(128));
    let result = connect(proxy(port), Some(&bad), &dst, Duration::from_secs(2));
    assert_eq!(result.await.unwrap_err(), SocksError::InvalidInput);
    // socksPing.test.ts: proxy port 0 → refused without I/O.
    let result = connect(proxy(0), None, &dst, Duration::from_secs(2));
    assert_eq!(result.await.unwrap_err(), SocksError::InvalidInput);
}

/// AT-00-003 (xraySocksCancellation.test.ts): a cancel racing a successful attempt wins.
#[tokio::test]
async fn cancel_racing_success_wins() {
    let (listener, port) = bind().await;
    let cancel = CancellationToken::new();
    let canceller = cancel.clone();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        expect(&mut s, &[5, 1, 2]).await;
        s.write_all(&[5, 2]).await.unwrap();
        expect(&mut s, &auth_bytes("slot-user", "slot-password")).await;
        canceller.cancel();
        s.write_all(&[1, 0]).await.unwrap();
        closed_by_client(&mut s).await
    });
    let ready = wait_ready(port, Some(&slot_creds()), Duration::from_secs(2), &cancel).await;
    assert_eq!(ready, Err(SocksError::Cancelled));
}

#[test]
fn maps_to_app_errors() {
    use vpnte_base::ErrorKind;
    assert_eq!(AppError::from(SocksError::Timeout).kind, ErrorKind::Timeout);
    assert_eq!(
        AppError::from(SocksError::Cancelled).kind,
        ErrorKind::Cancelled
    );
    assert_eq!(
        AppError::from(SocksError::InvalidInput).kind,
        ErrorKind::Validation
    );
    let rejected = AppError::from(SocksError::UpstreamRejected(5));
    assert_eq!(rejected.kind, ErrorKind::Network);
    assert_eq!(
        rejected.user_msg(),
        Msg::new("core.net.socksUpstreamRejected").arg("code", 5)
    );
    let refused = AppError::from(SocksError::Connect(io::ErrorKind::ConnectionRefused));
    assert_eq!(refused.user_msg().key, "core.net.socksUnreachable");
}
