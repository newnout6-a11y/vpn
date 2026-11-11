//! Egress probe and SOCKS latency tests against loopback fake SOCKS5 servers (AT-00-003,
//! AT-02-004, AT-10-004, AT-07-003; socksUpstreamProbe.test.ts, socksPing.test.ts).
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, Loopback};

use super::https::Wrap;
use super::*;

const CA: &[u8] = include_bytes!("testdata/ca.der");
const LEAF: &[u8] = include_bytes!("testdata/leaf.der");
const LEAF_KEY: &[u8] = include_bytes!("testdata/leaf.key.der");

fn creds() -> Creds {
    Creds {
        user: "probe-user".into(),
        pass: "fake-pass-123".into(),
    }
}

/// What the fake server does after a successful CONNECT to `host`.
#[derive(Clone)]
enum Then {
    /// Raw HTTP response bytes, sent after `delay` once the request arrived.
    Http(Vec<u8>, Duration),
    /// Garbage instead of a TLS ServerHello.
    Garbage,
    /// Never answers.
    Hang,
}

/// Behaviour of the fake SOCKS5 server.
#[derive(Clone)]
struct Script {
    /// Method the server selects (0x02 user/password, 0x00 no-auth).
    method: u8,
    /// Expected credentials; others are rejected with `01 01`.
    creds: Option<Creds>,
    /// CONNECT reply code (0 = success).
    rep: u8,
    /// Serve TLS with the test leaf certificate after CONNECT.
    tls: bool,
    respond: Arc<dyn Fn(&str) -> Then + Send + Sync>,
}

/// What clients sent, for assertions.
#[derive(Default)]
struct Seen {
    greetings: AtomicUsize,
    connects: Mutex<Vec<Vec<u8>>>,
    requests: Mutex<Vec<String>>,
    auth: Mutex<Vec<Vec<u8>>>,
}

fn http(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn serve(script: Script) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let out = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(session(stream, script.clone(), seen.clone()));
        }
    });
    (port, out)
}

async fn session(mut s: TcpStream, script: Script, seen: Arc<Seen>) -> std::io::Result<()> {
    let mut head = [0; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0; head[1] as usize];
    s.read_exact(&mut methods).await?;
    seen.greetings.fetch_add(1, Ordering::SeqCst);
    // Fragmented on purpose: the client must reassemble the method reply.
    s.write_all(&[5]).await?;
    s.flush().await?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    s.write_all(&[script.method]).await?;
    if script.method == 2 {
        let mut auth = vec![0; 2];
        s.read_exact(&mut auth).await?;
        let mut user = vec![0; auth[1] as usize];
        s.read_exact(&mut user).await?;
        let mut plen = [0; 1];
        s.read_exact(&mut plen).await?;
        let mut pass = vec![0; plen[0] as usize];
        s.read_exact(&mut pass).await?;
        let ok = script
            .creds
            .as_ref()
            .is_some_and(|c| c.user.as_bytes() == user && c.pass.as_bytes() == pass);
        seen.auth
            .lock()
            .push([auth, user, plen.to_vec(), pass].concat());
        s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            return Ok(());
        }
    }
    let (request, host) = read_connect(&mut s).await?;
    seen.connects.lock().push(request);
    s.write_all(&[5, script.rep, 0, 1, 127, 0, 0, 1, 0, 80])
        .await?;
    if script.rep != 0 {
        return Ok(());
    }
    let then = (script.respond)(&host);
    if script.tls {
        if let Then::Garbage = then {
            s.write_all(b"definitely not a TLS server hello\r\n")
                .await?;
            return Ok(());
        }
        let tls = acceptor().accept(s).await?;
        let (_, conn) = tls.get_ref();
        let alpn = conn
            .alpn_protocol()
            .map(|a| String::from_utf8_lossy(a).into_owned());
        let sni = conn.server_name().map(str::to_owned);
        seen.requests
            .lock()
            .push(format!("tls sni={sni:?} alpn={alpn:?}"));
        answer(tls, then, &seen).await
    } else {
        answer(s, then, &seen).await
    }
}

/// Reads `05 01 00 ATYP ADDR PORT`; returns the raw request and the host it names.
async fn read_connect(s: &mut TcpStream) -> std::io::Result<(Vec<u8>, String)> {
    let mut head = [0; 4];
    s.read_exact(&mut head).await?;
    let mut request = head.to_vec();
    let host = match head[3] {
        1 => {
            let mut a = [0; 4];
            s.read_exact(&mut a).await?;
            request.extend_from_slice(&a);
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0; 16];
            s.read_exact(&mut a).await?;
            request.extend_from_slice(&a);
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let mut len = [0; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0; len[0] as usize];
            s.read_exact(&mut name).await?;
            request.push(len[0]);
            request.extend_from_slice(&name);
            String::from_utf8_lossy(&name).into_owned()
        }
    };
    let mut port = [0; 2];
    s.read_exact(&mut port).await?;
    request.extend_from_slice(&port);
    Ok((request, host))
}

async fn answer<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    then: Then,
    seen: &Seen,
) -> std::io::Result<()> {
    let mut buf = vec![0; 4096];
    let mut request = Vec::new();
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..n]);
    }
    seen.requests
        .lock()
        .push(String::from_utf8_lossy(&request).into_owned());
    match then {
        Then::Http(bytes, delay) => {
            tokio::time::sleep(delay).await;
            s.write_all(&bytes).await?;
            s.shutdown().await
        }
        Then::Garbage => Ok(()),
        Then::Hang => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        }
    }
}

fn acceptor() -> tokio_rustls::TlsAcceptor {
    vpnte_base::http::init_tls();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(LEAF_KEY.to_vec()));
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(LEAF.to_vec())], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// TLS trusting only the test CA.
fn test_tls() -> Wrap {
    vpnte_base::http::init_tls();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(CA.to_vec())).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Wrap::with_config(config)
}

fn script(respond: impl Fn(&str) -> Then + Send + Sync + 'static) -> Script {
    Script {
        method: 2,
        creds: Some(creds()),
        rep: 0,
        tls: false,
        respond: Arc::new(respond),
    }
}

fn ep(port: u16) -> Loopback {
    Loopback {
        port,
        creds: Some(creds()),
    }
}

fn index_of(host: &str) -> usize {
    PROVIDERS.iter().position(|p| p.host == host).unwrap()
}

async fn run_plain(s: Script, budget: Duration) -> (Result<Ipv4Addr, EgressError>, Arc<Seen>) {
    let (port, seen) = serve(s).await;
    let out = race(
        &ep(port),
        &PROVIDERS,
        &Wrap::Plain,
        budget,
        &CancellationToken::new(),
    )
    .await;
    (out, seen)
}

/// Provider body formats: trace line, JSON `ip`, plain body.
#[test]
fn body_formats() {
    assert_eq!(
        parse_body("fl=1\nip=8.8.8.8\nts=1\n"),
        Some(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(
        parse_body(r#"{"ip":"8.8.8.8"}"#),
        Some(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(
        parse_body(r#"{"ip":" 8.8.8.8 "}"#),
        Some(Ipv4Addr::new(8, 8, 8, 8))
    );
    assert_eq!(parse_body("8.8.8.8\n"), Some(Ipv4Addr::new(8, 8, 8, 8)));
    for bad in [
        "",
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "::1",
        "2001:db8::1",
        "8.8.8.8 garbage",
        "[8.8.8.8]",
        "2606:4700:4700::1111",
    ] {
        assert_eq!(parse_body(bad), None, "{bad}");
        assert_eq!(parse_body(&format!("ip={bad}\n")), None, "{bad}");
        assert_eq!(parse_body(&format!(r#"{{"ip":"{bad}"}}"#)), None, "{bad}");
    }
}

/// Each provider format confirms `8.8.8.8` when it is the only one answering.
#[tokio::test]
async fn every_provider_format_is_read() {
    for winner in 0..PROVIDERS.len() {
        let s = script(move |host| match index_of(host) {
            i if i != winner => Then::Http(http("503 Service Unavailable", ""), Duration::ZERO),
            0 => Then::Http(http("200 OK", "fl=1\nip=8.8.8.8\n"), Duration::ZERO),
            2 => Then::Http(http("200 OK", "8.8.8.8\n"), Duration::ZERO),
            _ => Then::Http(http("200 OK", r#"{"ip":"8.8.8.8"}"#), Duration::ZERO),
        });
        let (out, _) = run_plain(s, Duration::from_secs(2)).await;
        assert_eq!(out, Ok(Ipv4Addr::new(8, 8, 8, 8)), "provider {winner}");
    }
}

/// Provider 0 → 503, provider 1 → 8.8.4.4: success; all four negotiations started; the request
/// is exactly the documented GET and never carries the password.
#[tokio::test]
async fn one_failing_provider_does_not_decide() {
    let s = script(|host| match index_of(host) {
        1 => Then::Http(
            http("200 OK", r#"{"ip":"8.8.4.4"}"#),
            Duration::from_millis(50),
        ),
        _ => Then::Http(http("503 Service Unavailable", ""), Duration::ZERO),
    });
    let (out, seen) = run_plain(s, Duration::from_secs(2)).await;
    assert_eq!(out, Ok(Ipv4Addr::new(8, 8, 4, 4)));
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 4);
    let connects = seen.connects.lock().clone();
    let trace = [&[5u8, 1, 0, 3, 14][..], b"cloudflare.com", &[1, 187]].concat();
    assert!(
        connects.contains(&trace),
        "domain CONNECT to cloudflare.com:443"
    );
    let requests = seen.requests.lock().clone();
    let first = requests
        .iter()
        .find(|r| r.contains("Host: cloudflare.com"))
        .unwrap();
    assert_eq!(
        first,
        "GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nAccept: text/plain\r\nConnection: close\r\n\r\n"
    );
    assert!(requests.iter().all(|r| !r.contains("fake-pass-123")));
}

/// IPv6 echoes never confirm; a later IPv4 answer still wins.
#[tokio::test]
async fn ipv6_answers_are_refused() {
    let v6 = |_: &str| Then::Http(http("200 OK", "2606:4700:4700::1111"), Duration::ZERO);
    assert_eq!(
        run_plain(script(v6), Duration::from_secs(2)).await.0,
        Err(EgressError::Network)
    );
    let s = script(|host| match index_of(host) {
        0 => Then::Http(http("200 OK", "ip=2606:4700:4700::1111\n"), Duration::ZERO),
        1 => Then::Http(
            http("200 OK", r#"{"ip":"8.8.4.4"}"#),
            Duration::from_millis(80),
        ),
        _ => Then::Hang,
    });
    assert_eq!(
        run_plain(s, Duration::from_secs(2)).await.0,
        Ok(Ipv4Addr::new(8, 8, 4, 4))
    );
}

/// Redirects are not followed; a 4097-byte body is refused, a chunked body is read.
#[tokio::test]
async fn redirects_and_large_bodies_are_refused() {
    let redirect = |_: &str| {
        let r =
            b"HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n";
        Then::Http(r.to_vec(), Duration::ZERO)
    };
    assert_eq!(
        run_plain(script(redirect), Duration::from_secs(2)).await.0,
        Err(EgressError::Network)
    );
    let big = |_: &str| Then::Http(http("200 OK", &"8".repeat(4097)), Duration::ZERO);
    assert_eq!(
        run_plain(script(big), Duration::from_secs(2)).await.0,
        Err(EgressError::Network)
    );
    let eof = |_: &str| {
        Then::Http(
            format!("HTTP/1.1 200 OK\r\n\r\n{}", "1".repeat(4097)).into_bytes(),
            Duration::ZERO,
        )
    };
    assert_eq!(
        run_plain(script(eof), Duration::from_secs(2)).await.0,
        Err(EgressError::Network)
    );
    let chunked = |host: &str| {
        match index_of(host) {
        2 => Then::Http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n8.8.\r\n4\r\n8.8\n\r\n0\r\n\r\n".to_vec(), Duration::ZERO),
        _ => Then::Hang,
    }
    };
    assert_eq!(
        run_plain(script(chunked), Duration::from_secs(2)).await.0,
        Ok(Ipv4Addr::new(8, 8, 8, 8))
    );
}

/// One shared deadline: an early failure does not extend it; hung providers end as `Timeout`.
#[tokio::test]
async fn one_shared_deadline() {
    let s = script(|host| match index_of(host) {
        0 => Then::Http(
            http("503 Service Unavailable", ""),
            Duration::from_millis(190),
        ),
        _ => Then::Hang,
    });
    let started = std::time::Instant::now();
    let (out, _) = run_plain(s, Duration::from_millis(400)).await;
    assert_eq!(out, Err(EgressError::Timeout));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(390) && took < Duration::from_millis(1500),
        "{took:?}"
    );
}

/// A server selecting no-auth (sent fragmented) is refused before TLS or HTTP; a wrong password
/// is rejected at the SOCKS stage.
#[tokio::test]
async fn socks_authentication_is_enforced() {
    let mut s = script(|_| Then::Http(http("200 OK", "8.8.8.8"), Duration::ZERO));
    s.method = 0;
    let (out, seen) = run_plain(s, Duration::from_secs(2)).await;
    assert_eq!(out, Err(EgressError::Network));
    assert!(seen.connects.lock().is_empty() && seen.requests.lock().is_empty());
    let mut s = script(|_| Then::Http(http("200 OK", "8.8.8.8"), Duration::ZERO));
    s.creds = Some(Creds {
        user: "probe-user".into(),
        pass: "other".into(),
    });
    let (out, seen) = run_plain(s, Duration::from_secs(2)).await;
    assert_eq!(out, Err(EgressError::Network));
    assert!(seen.connects.lock().is_empty());
    let auth = seen.auth.lock()[0].clone();
    assert_eq!(
        auth,
        [&[1u8, 10][..], b"probe-user", &[13], b"fake-pass-123"].concat()
    );
}

/// Port 0 and a 256-byte password are refused without a socket; a cancelled token wins.
#[tokio::test]
async fn validation_and_cancellation() {
    let cancel = CancellationToken::new();
    let zero = Loopback {
        port: 0,
        creds: Some(creds()),
    };
    assert_eq!(
        race(&zero, &PROVIDERS, &Wrap::Plain, EGRESS_DEADLINE, &cancel).await,
        Err(EgressError::Validation)
    );
    let (port, seen) = serve(script(|_| Then::Hang)).await;
    let long = Loopback {
        port,
        creds: Some(Creds {
            user: "u".into(),
            pass: "я".repeat(128),
        }),
    };
    assert_eq!(
        race(&long, &PROVIDERS, &Wrap::Plain, EGRESS_DEADLINE, &cancel).await,
        Err(EgressError::Validation)
    );
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 0);
    let gone = CancellationToken::new();
    gone.cancel();
    assert_eq!(
        race(&ep(port), &PROVIDERS, &Wrap::Plain, EGRESS_DEADLINE, &gone).await,
        Err(EgressError::Cancelled)
    );
    let later = CancellationToken::new();
    let trigger = later.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    assert_eq!(
        race(&ep(port), &PROVIDERS, &Wrap::Plain, EGRESS_DEADLINE, &later).await,
        Err(EgressError::Cancelled)
    );
}

/// Real TLS: SNI = provider host, ALPN `http/1.1`, certificate verified against the roots.
#[tokio::test]
async fn tls_carries_sni_and_alpn() {
    let mut s = script(|host| match index_of(host) {
        0 => Then::Http(http("200 OK", "fl=1\nip=8.8.8.8\n"), Duration::ZERO),
        _ => Then::Hang,
    });
    s.tls = true;
    let (port, seen) = serve(s).await;
    let out = race(
        &ep(port),
        &PROVIDERS,
        &test_tls(),
        Duration::from_secs(3),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(out, Ok(Ipv4Addr::new(8, 8, 8, 8)));
    let requests = seen.requests.lock().clone();
    assert!(
        requests.contains(&r#"tls sni=Some("cloudflare.com") alpn=Some("http/1.1")"#.to_owned()),
        "{requests:?}"
    );
}

/// An untrusted certificate (the Windows store does not know the test CA) and a peer that does
/// not speak TLS both fail at the TLS stage.
#[tokio::test]
async fn untrusted_or_missing_tls_fails() {
    let mut s = script(|_| Then::Http(http("200 OK", "8.8.8.8"), Duration::ZERO));
    s.tls = true;
    let (port, seen) = serve(s).await;
    let wrap = Wrap::tls().unwrap();
    let out = race(
        &ep(port),
        &PROVIDERS,
        &wrap,
        Duration::from_secs(3),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(out, Err(EgressError::Network));
    assert!(seen.requests.lock().iter().all(|r| !r.starts_with("GET")));
    let mut s = script(|_| Then::Garbage);
    s.tls = true;
    let (port, _) = serve(s).await;
    let out = race(
        &ep(port),
        &PROVIDERS,
        &test_tls(),
        Duration::from_secs(3),
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(out, Err(EgressError::Network));
}

/// Stage / code mapping of SOCKS failures (log codes of the old probe).
#[test]
fn socks_failure_codes() {
    assert_eq!(
        socks_code(SocksError::AuthRequired),
        Code::SocksAuthRequired
    );
    assert_eq!(
        socks_code(SocksError::AuthRejected),
        Code::SocksAuthRejected
    );
    assert_eq!(socks_code(SocksError::Closed), Code::SocksClosed);
    assert_eq!(
        socks_code(SocksError::UpstreamRejected(5)),
        Code::SocksUpstreamRejected
    );
    assert_eq!(socks_code(SocksError::Malformed), Code::SocksFailed);
    assert_eq!(Code::InvalidPublicIp.as_str(), "INVALID_PUBLIC_IP");
    assert_eq!(Stage::TlsHandshake.as_str(), "tls-handshake");
}

fn no_auth(rep: u8) -> Script {
    Script {
        method: 0,
        creds: None,
        rep,
        tls: false,
        respond: Arc::new(|_| Then::Hang),
    }
}

/// `05 00` then a success reply → a latency; reply code 5 → `None` (socksPing.test.ts).
#[tokio::test]
async fn socks_latency_reads_the_connect_reply() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    let ms = socks_connect_latency(&proxy, "example.com", 443, Duration::from_secs(2)).await;
    assert!(ms.is_some_and(|ms| ms >= 1));
    assert_eq!(
        seen.connects.lock()[0],
        [&[5u8, 1, 0, 3, 11][..], b"example.com", &[1, 187]].concat()
    );
    let (port, _) = serve(no_auth(5)).await;
    let refused = Loopback { port, creds: None };
    assert_eq!(
        socks_connect_latency(&refused, "example.com", 443, Duration::from_secs(2)).await,
        None
    );
}

/// Invalid input is `None` without any I/O.
#[tokio::test]
async fn socks_latency_refuses_invalid_input() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    let limit = Duration::from_secs(1);
    assert_eq!(
        socks_connect_latency(&proxy, "example.com", 0, limit).await,
        None
    );
    assert_eq!(socks_connect_latency(&proxy, "", 443, limit).await, None);
    assert_eq!(
        socks_connect_latency(&proxy, "example.com", 443, Duration::ZERO).await,
        None
    );
    let zero = Loopback {
        port: 0,
        creds: None,
    };
    assert_eq!(
        socks_connect_latency(&zero, "example.com", 443, limit).await,
        None
    );
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 0);
}

/// IPv6 targets use ATYP 4; with credentials only user/password is offered, and a server that
/// answers no-auth is refused.
#[tokio::test]
async fn socks_latency_encodings_and_auth() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    assert!(
        socks_connect_latency(&proxy, "2001:db8::1", 8443, Duration::from_secs(2))
            .await
            .is_some()
    );
    let mut expected = vec![5u8, 1, 0, 4];
    expected.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    expected.extend_from_slice(&8443u16.to_be_bytes());
    assert_eq!(seen.connects.lock()[0], expected);

    let mut s = no_auth(0);
    s.method = 2;
    s.creds = Some(creds());
    let (port, seen) = serve(s).await;
    let authed = Loopback {
        port,
        creds: Some(creds()),
    };
    assert!(
        socks_connect_latency(&authed, "1.2.3.4", 443, Duration::from_secs(2))
            .await
            .is_some()
    );
    assert_eq!(
        seen.auth.lock()[0],
        [&[1u8, 10][..], b"probe-user", &[13], b"fake-pass-123"].concat()
    );
    assert_eq!(
        seen.connects.lock()[0],
        vec![5, 1, 0, 1, 1, 2, 3, 4, 1, 187]
    );

    let (port, _) = serve(no_auth(0)).await;
    let wants_auth = Loopback {
        port,
        creds: Some(creds()),
    };
    assert_eq!(
        socks_connect_latency(&wants_auth, "1.2.3.4", 443, Duration::from_secs(2)).await,
        None
    );
}

/// Three parallel samples reduce to the median; all failing → `None`.
#[tokio::test]
async fn reliable_latency_takes_the_median() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    assert!(
        reliable_socks_latency(&proxy, "example.com", 443, Duration::from_secs(2), 3)
            .await
            .is_some()
    );
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 3);
    let (port, _) = serve(no_auth(1)).await;
    let failing = Loopback { port, creds: None };
    assert_eq!(
        reliable_socks_latency(&failing, "example.com", 443, Duration::from_secs(2), 3).await,
        None
    );
}
