//! Protocol probes on a local port: does it answer HTTP CONNECT or a SOCKS5 greeting, and does
//! a request through it reach the Internet. Every probe owns its socket: dropping the future
//! (timeout, cancel) closes it.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use vpnte_base::types::ProxyKind;
use vpnte_core::net::{self, HostPort, Route};

use super::candidates::Candidate;

/// Budget of one classification attempt (connect + greeting) on a local port.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(700);
/// Candidates classified at the same time.
pub const PARALLEL: usize = 16;
/// Host named in the HTTP CONNECT probe and answering the verification request.
pub const CHECK_HOST: &str = "api.ipify.org";
/// Plain-text IP echo fetched through the winner.
pub const ECHO_URL: &str = "https://api.ipify.org/";

/// Outcome of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// The port answered the protocol's greeting.
    Speaks,
    /// Something listens but answered otherwise (or too late).
    Other,
    /// Nothing accepted the connection in time.
    Closed,
}

/// Connects to `addr` and speaks `kind`'s greeting within `limit`.
pub async fn attempt(addr: SocketAddr, kind: ProxyKind, limit: Duration) -> Attempt {
    let deadline = Instant::now() + limit;
    let Ok(Ok(mut stream)) = timeout_at(deadline, TcpStream::connect(addr)).await else {
        return Attempt::Closed;
    };
    let spoke = match kind {
        ProxyKind::Http => timeout_at(deadline, http_connect(&mut stream)).await,
        // An auth-only SOCKS server is unusable as an anonymous upstream: `AuthRequired` = Other.
        ProxyKind::Socks5 => {
            timeout_at(deadline, async {
                vpnte_core::socks5::negotiate(&mut stream, None)
                    .await
                    .is_ok()
            })
            .await
        }
    };
    if spoke == Ok(true) {
        Attempt::Speaks
    } else {
        Attempt::Other
    }
}

/// `CONNECT <check host>:443` must be answered `HTTP/1.x 200` (local clients answer before they
/// dial upstream, so this is a local check; a web server answers 400 / 405 and is skipped).
async fn http_connect(stream: &mut TcpStream) -> bool {
    let request = format!("CONNECT {CHECK_HOST}:443 HTTP/1.1\r\nHost: {CHECK_HOST}:443\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    let mut len = 0;
    while len < buf.len() {
        match stream.read(&mut buf[len..]).await {
            Ok(0) | Err(_) => break,
            Ok(n) => len += n,
        }
        if buf[..len].windows(2).any(|w| w == b"\r\n") {
            break;
        }
    }
    is_http_200(&buf[..len])
}

/// True for a status line `HTTP/1.0 200 …` / `HTTP/1.1 200 …`.
pub fn is_http_200(head: &[u8]) -> bool {
    let line = head
        .split(|&b| b == b'\r' || b == b'\n')
        .next()
        .unwrap_or_default();
    let mut parts = line.split(|&b| b == b' ');
    matches!(parts.next(), Some(b"HTTP/1.0" | b"HTTP/1.1")) && parts.next() == Some(b"200")
}

/// The protocol `addr` speaks: the hinted one first, otherwise HTTP first (the old
/// `verifyCandidate` order: a mixed port is reported as HTTP, which TUN upstreams handle best).
pub async fn classify(addr: SocketAddr, hint: Option<ProxyKind>) -> Option<ProxyKind> {
    let order = match hint {
        Some(ProxyKind::Socks5) => [ProxyKind::Socks5, ProxyKind::Http],
        _ => [ProxyKind::Http, ProxyKind::Socks5],
    };
    for kind in order {
        match attempt(addr, kind, PROBE_TIMEOUT).await {
            Attempt::Speaks => return Some(kind),
            Attempt::Closed => return None,
            Attempt::Other => {}
        }
    }
    None
}

/// The first candidate in priority order that speaks a proxy protocol (up to [`PARALLEL`]
/// probes in flight; the rest are dropped as soon as the winner is known).
pub async fn pick(candidates: Vec<Candidate>) -> Option<(Candidate, ProxyKind)> {
    let mut results = stream::iter(candidates)
        .map(|c| async move {
            let kind = classify(c.addr, c.hint).await;
            (c, kind)
        })
        .buffered(PARALLEL);
    while let Some((c, kind)) = results.next().await {
        if let Some(kind) = kind {
            return Some((c, kind));
        }
    }
    None
}

/// Public IP seen through the proxy (TLS to the echo service): `Some` proves the proxy reaches
/// the Internet. Any failure is `None`.
pub async fn verify(addr: SocketAddr, kind: ProxyKind, limit: Duration) -> Option<IpAddr> {
    let hp = HostPort::try_from(addr).ok()?;
    let client = net::client_for(&Route::proxy(kind, &hp, None), limit).ok()?;
    let response = client.get(ECHO_URL).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let body = response.text().await.ok()?;
    body.trim().parse::<IpAddr>().ok()
}
