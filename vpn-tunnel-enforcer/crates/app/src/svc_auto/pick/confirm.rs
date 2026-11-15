//! One 64 KiB transfer through the running session's own exit (the TUN, or the mixed inbound of
//! a proxy capture), judged as the probes judge theirs: only bytes after the first ~16-20 KB
//! prove the path on Russian networks (the freeze of foreign data centres passes TCP connects and
//! TLS handshakes), and the freeze band is raw bytes below the inner TLS, so those are counted.
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use vpnte_automation::autopick::Confirmation;
use vpnte_core::net::HostPort;
use vpnte_core::socks5;
use vpnte_probes::discipline::{FREEZE_BAND, Limits, TRANSFER_BYTES, TRANSFER_HOST};
use vpnte_probes::public_ip::IpRoute;
use vpnte_profiles::model::Profile;
use vpnte_tunnel::runtime::HandshakeGate;

use crate::svc_tunnel::BudgetGate;

/// Largest response head read.
const HEAD_CAP: usize = 16 * 1024;

/// How the exchange ended (the bytes are counted apart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    /// The whole body arrived.
    Complete,
    /// The far side went silent: nothing for `first_byte`, a `gap` after data, or the deadline.
    Silent,
    /// Refused, closed early, TLS or an HTTP error status.
    Failed,
}

/// Behind `server`'s handshake slot (one connection through the session is one new handshake
/// with it), one download over `route`.
pub(super) async fn through_session(
    server: &Profile,
    route: &IpRoute,
    cancel: &CancellationToken,
) -> Confirmation {
    // Not through the session: proves nothing about it.
    if matches!(route, IpRoute::Direct) || BudgetGate.admit(server, cancel).await.is_err() {
        return Confirmation::Deferred;
    }
    let Some(tls) = tls() else {
        return Confirmation::Deferred;
    };
    let raw = Arc::new(AtomicU64::new(0));
    let limits = Limits::STANDARD;
    let exchange = async {
        let Ok(stream) = open(route, limits.first_byte).await else {
            return Outcome::Failed;
        };
        let counted = Counted {
            inner: stream,
            raw: raw.clone(),
        };
        let Ok(name) = ServerName::try_from(TRANSFER_HOST) else {
            return Outcome::Failed;
        };
        match tls.connect(name, counted).await {
            Ok(mut stream) => download(&mut stream).await,
            Err(_) => Outcome::Failed,
        }
    };
    measure(exchange, &raw, limits, cancel).await
}

/// Runs `exchange` while `raw` counts the far side's bytes, within `limits`.
pub(super) async fn measure(
    exchange: impl Future<Output = Outcome>,
    raw: &AtomicU64,
    limits: Limits,
    cancel: &CancellationToken,
) -> Confirmation {
    let started = Instant::now();
    let outcome = tokio::select! {
        biased;
        () = cancel.cancelled() => return Confirmation::Deferred,
        outcome = exchange => outcome,
        () = silence(raw, limits) => Outcome::Silent,
        () = tokio::time::sleep_until(started + limits.deadline) => Outcome::Silent,
    };
    judge(outcome, raw.load(Ordering::Relaxed))
}

/// The probes' classification of a transfer by the raw bytes the far side delivered: complete
/// = passed; nothing at all = no traffic; a stall inside the freeze band = frozen; data that
/// stopped outside it, or an answer that then failed = inconclusive (the path carries data).
pub(super) fn judge(outcome: Outcome, raw: u64) -> Confirmation {
    match outcome {
        Outcome::Complete => Confirmation::Passed,
        _ if raw == 0 => Confirmation::NoTraffic,
        Outcome::Silent if FREEZE_BAND.contains(&raw) => Confirmation::Frozen,
        Outcome::Silent | Outcome::Failed => Confirmation::Inconclusive,
    }
}

/// Completes once the far side has been silent for too long: `first_byte` before anything
/// came, `gap` after.
async fn silence(raw: &AtomicU64, limits: Limits) {
    const TICK: Duration = Duration::from_millis(100);
    let mut seen = raw.load(Ordering::Relaxed);
    let mut since = Instant::now();
    loop {
        tokio::time::sleep(TICK).await;
        let now = raw.load(Ordering::Relaxed);
        if now != seen {
            (seen, since) = (now, Instant::now());
            continue;
        }
        let quiet = if seen == 0 {
            limits.first_byte
        } else {
            limits.gap
        };
        if since.elapsed() >= quiet {
            return;
        }
    }
}

/// The GET and its body up to [`TRANSFER_BYTES`]; the head and any chunk framing count as raw
/// bytes anyway (the point is the volume, not the payload).
pub(super) async fn download<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Outcome {
    let request = format!(
        "GET /__down?bytes={TRANSFER_BYTES} HTTP/1.1\r\nHost: {TRANSFER_HOST}\r\n\
         User-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return Outcome::Failed;
    }
    let mut buf = vec![0u8; 16 * 1024];
    let mut head = Vec::new();
    let body_at = loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return Outcome::Failed,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if head.len() > HEAD_CAP {
            return Outcome::Failed;
        }
    };
    if !success(&head) {
        return Outcome::Failed;
    }
    let mut got = (head.len() - body_at) as u64;
    while got < TRANSFER_BYTES {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return Outcome::Failed,
            Ok(n) => got += n as u64,
        }
    }
    Outcome::Complete
}

/// The status line says 2xx.
fn success(head: &[u8]) -> bool {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let code = String::from_utf8_lossy(line);
    (code.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .is_some_and(|c| (200..300).contains(&c))
}

/// A connection over the session's exit. Through the TUN: a socket bound to the TUN address (it
/// can only leave through the TUN) to an IPv4 address of the host, so no socket of the other
/// family escapes that binding. Through a proxy capture: SOCKS5 to the loopback mixed inbound
/// (the name resolves at the exit).
async fn open(route: &IpRoute, limit: Duration) -> io::Result<TcpStream> {
    match route {
        IpRoute::Tun { v4, .. } => {
            let found = tokio::net::lookup_host((TRANSFER_HOST, 443)).await?;
            let addr = (found.into_iter().find(SocketAddr::is_ipv4))
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let socket = TcpSocket::new_v4()?;
            socket.bind(SocketAddr::new(IpAddr::V4(*v4), 0))?;
            tokio::time::timeout(limit, socket.connect(addr)).await?
        }
        IpRoute::Loopback(lo) => {
            let target = HostPort::new(TRANSFER_HOST, 443).map_err(io::Error::other)?;
            let proxy = SocketAddr::from(([127, 0, 0, 1], lo.port));
            let connected = socks5::connect(proxy, lo.creds.as_ref(), &target, limit).await;
            connected.map_err(io::Error::other)
        }
        IpRoute::Direct => Err(io::Error::from(io::ErrorKind::Unsupported)),
    }
}

/// TLS verified against the Windows trust store (a censor's block page must not count as the
/// far side), ALPN `http/1.1`; built once.
fn tls() -> Option<TlsConnector> {
    static CONFIG: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        use rustls_platform_verifier::BuilderVerifierExt;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .with_platform_verifier()
            .ok()?
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Arc::new(config))
    });
    config.clone().map(TlsConnector::from)
}

/// Counts what the far side delivered below the inner TLS: the probes' raw bytes.
pub(super) struct Counted<S> {
    pub(super) inner: S,
    pub(super) raw: Arc<AtomicU64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.inner).poll_read(cx, buf);
        let read = buf.filled().len().saturating_sub(before);
        this.raw.fetch_add(read as u64, Ordering::Relaxed);
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
