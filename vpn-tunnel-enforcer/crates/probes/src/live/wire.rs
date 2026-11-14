//! Sockets of the engine stage: SOCKS5 CONNECT through a loopback inbound (the target name goes
//! to the proxy, so DNS resolves at the exit), TLS with certificate verification, and a small
//! HTTP/1.1 response reader. Hand-written like `egress`: a few requests do not justify a client.
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::TlsConnector;
use vpnte_base::types::Loopback;
use vpnte_core::net::HostPort;
use vpnte_core::socks5::{self, SocksError};

use crate::live_stages::ProbePath;
use crate::live_stages::http::Io;

/// A byte stream through the tunnel (TLS, or plain TCP in tests).
pub(crate) type Stream = Box<dyn Io>;

/// Where a connection starts.
#[derive(Clone, Copy)]
pub(crate) enum Dial<'a> {
    /// SOCKS5 CONNECT through a loopback inbound (the target name resolves at the exit).
    Socks(&'a Loopback),
    /// A plain TCP connection to `addr` along `path` (the network-mode check, no engine).
    Direct {
        addr: SocketAddr,
        path: &'a ProbePath,
    },
}

/// How the engine stage opens its connections.
#[derive(Clone)]
pub(crate) struct Wire {
    /// `None`: plain TCP after CONNECT (tests only: fake servers have no trusted certificate).
    tls: Option<TlsConnector>,
}

impl Wire {
    /// TLS verified against the Windows trust store (B-04 needs real servers on the far side:
    /// a censor's block page must not count as an answer), ALPN `http/1.1`.
    pub(crate) fn verified() -> Result<Self, rustls::Error> {
        let config = crate::tls_client::verified(&[b"http/1.1".as_slice()])?;
        Ok(Wire {
            tls: Some(TlsConnector::from(config)),
        })
    }

    #[cfg(test)]
    pub(crate) fn plain() -> Self {
        Wire { tls: None }
    }

    /// CONNECT `host:port` through `proxy`, then TLS with SNI `sni`. Returns the stream and the
    /// negotiated TLS version (`TLSv1.3`). One deadline is the caller's (B-35).
    pub(crate) async fn open(
        &self,
        proxy: &Loopback,
        host: &str,
        port: u16,
        sni: &str,
    ) -> Result<(Stream, Option<String>), WireError> {
        let raw = Arc::new(AtomicU64::new(0));
        self.open_counted(Dial::Socks(proxy), host, port, sni, &raw)
            .await
    }

    /// [`Wire::open`] that adds every byte the far side delivers (after the CONNECT reply, TLS
    /// records included) to `raw`, also while the TLS handshake is still running: the transfer
    /// check judges a freeze by what the server sent, not by what TLS decrypted.
    pub(crate) async fn open_counted(
        &self,
        dial: Dial<'_>,
        host: &str,
        port: u16,
        sni: &str,
        raw: &Arc<AtomicU64>,
    ) -> Result<(Stream, Option<String>), WireError> {
        let tcp = match dial {
            Dial::Socks(proxy) => {
                let target = HostPort::new(host, port)
                    .map_err(|_| WireError::Socks(SocksError::InvalidInput))?;
                let local = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy.port));
                // The caller's timeout bounds the whole step; this limit only has to be longer.
                socks5::connect(
                    local,
                    proxy.creds.as_ref(),
                    &target,
                    Duration::from_secs(60),
                )
                .await
                .map_err(WireError::Socks)?
            }
            Dial::Direct { addr, path } => {
                crate::live_stages::connect(addr, path, Duration::from_secs(60))
                    .await
                    .map_err(WireError::Direct)?
            }
        };
        let tcp = Counted {
            inner: tcp,
            read: raw.clone(),
        };
        let Some(connector) = &self.tls else {
            return Ok((Box::new(tcp), None));
        };
        let name =
            ServerName::try_from(sni.to_owned()).map_err(|e| WireError::Tls(e.to_string()))?;
        let tls = connector
            .connect(name, tcp)
            .await
            .map_err(|e| WireError::Tls(tls_text(&e)))?;
        let version = tls
            .get_ref()
            .1
            .protocol_version()
            .and_then(|v| v.as_str())
            .map(|v| v.replace('_', "."));
        Ok((Box::new(tls), version))
    }
}

/// A stream that counts the bytes read from it.
struct Counted<S> {
    inner: S,
    read: Arc<AtomicU64>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            let n = buf.filled().len().saturating_sub(before);
            self.read.fetch_add(n as u64, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Why opening a connection failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WireError {
    Socks(SocksError),
    /// A direct connect failed (Node-style code: `ECONNREFUSED`, `ETIMEDOUT`, …).
    Direct(String),
    Tls(String),
}

impl WireError {
    /// English text for rows and the failure classifier (`timeout`, `connection refused`, …).
    pub(crate) fn text(&self) -> String {
        match self {
            WireError::Socks(e) => socks_text(*e),
            WireError::Direct(code) => format!("connect: {code}"),
            WireError::Tls(e) => format!("tls: {e}"),
        }
    }

    /// The exit cannot reach the address family at all (SOCKS replies 3 / 4 / 8, B-17).
    pub(crate) fn unsupported_family(&self) -> bool {
        matches!(
            self,
            WireError::Socks(SocksError::UpstreamRejected(3 | 4 | 8))
        )
    }
}

/// SOCKS failure wording: reply codes by their RFC 1928 names (the classifier keys on them).
fn socks_text(e: SocksError) -> String {
    match e {
        SocksError::UpstreamRejected(code) => {
            let name = match code {
                1 => "general failure",
                2 => "connection not allowed",
                3 => "network unreachable",
                4 => "host unreachable",
                5 => "connection refused",
                6 => "ttl expired",
                7 => "command not supported",
                8 => "address type not supported",
                _ => "unknown reply",
            };
            format!("socks reply {code}: {name}")
        }
        SocksError::Timeout => "timeout".into(),
        SocksError::Closed => "SOCKS transport closed".into(),
        SocksError::Cancelled => "Cancelled".into(),
        other => format!("socks: {other:?}"),
    }
}

/// Response head cap (old: 65536 bytes for media and throughput heads).
pub(crate) const HEAD_CAP: usize = 64 * 1024;

/// Why no usable response head arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeadError {
    /// The stream ended before the head was complete.
    Closed,
    /// `HEAD_CAP` bytes without the end of the head.
    TooLarge,
    Io(String),
    Malformed,
}

impl HeadError {
    pub(crate) fn text(&self) -> String {
        match self {
            HeadError::Closed => "probe destination closed without HTTP response".into(),
            HeadError::TooLarge => "response headers too large".into(),
            HeadError::Io(e) => e.clone(),
            HeadError::Malformed => "malformed HTTP response".into(),
        }
    }
}

/// A parsed response head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Head {
    pub status: u16,
    pub content_length: Option<u64>,
    pub chunked: bool,
}

/// Writes `request` and reads the response head. Returns the head and the body bytes that
/// arrived with it.
pub(crate) async fn exchange_head(
    stream: &mut Stream,
    request: &str,
) -> Result<(Head, Vec<u8>), HeadError> {
    let io = |e: std::io::Error| {
        if closed(&e) {
            HeadError::Closed
        } else {
            HeadError::Io(io_text(&e))
        }
    };
    stream.write_all(request.as_bytes()).await.map_err(io)?;
    stream.flush().await.map_err(io)?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // A peer closing without TLS close_notify is an end of stream here.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(io(e)),
        };
        if n == 0 {
            return Err(HeadError::Closed);
        }
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find(&buf[from..], b"\r\n\r\n").map(|i| from + i + 4) {
            let head = parse_head(&buf[..end])?;
            return Ok((head, buf.split_off(end)));
        }
        if buf.len() >= HEAD_CAP {
            return Err(HeadError::TooLarge);
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn parse_head(bytes: &[u8]) -> Result<Head, HeadError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => return Err(HeadError::Malformed),
    }
    let status = response.code.ok_or(HeadError::Malformed)?;
    let mut head = Head {
        status,
        content_length: None,
        chunked: false,
    };
    for h in response.headers.iter() {
        let value = String::from_utf8_lossy(h.value);
        if h.name.eq_ignore_ascii_case("content-length") {
            head.content_length = value.trim().parse().ok();
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            head.chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    Ok(head)
}

/// The rest of a small body (Content-Length, chunked or close-delimited), at most `cap` bytes.
pub(crate) async fn read_body(
    stream: &mut Stream,
    head: &Head,
    mut body: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, String> {
    let mut chunk = [0u8; 4096];
    loop {
        let done = match head.content_length {
            Some(len) => body.len() as u64 >= len,
            None => head.chunked && find(&body, b"0\r\n\r\n").is_some(),
        };
        if done || body.len() > cap {
            break;
        }
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(io_text(&e)),
        }
    }
    if body.len() > cap {
        return Err("response body too large".into());
    }
    if let Some(len) = head.content_length {
        body.truncate(usize::try_from(len).unwrap_or(usize::MAX));
    }
    Ok(if head.chunked { dechunk(&body) } else { body })
}

/// Joins the data of a chunked body (sizes in hex, extensions and trailers ignored).
fn dechunk(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(eol) = find(rest, b"\r\n") {
        let line = String::from_utf8_lossy(&rest[..eol]);
        let size = line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(size, 16) else {
            break;
        };
        rest = &rest[eol + 2..];
        if size == 0 || rest.len() < size {
            out.extend_from_slice(&rest[..size.min(rest.len())]);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    out
}

/// The peer went away: for the verdict that is "no response", whatever the socket said.
fn closed(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(
        e.kind(),
        K::ConnectionAborted | K::BrokenPipe | K::UnexpectedEof
    )
}

/// English text of an I/O error. Windows' own messages are localised; rows store the text
/// and the failure classifier matches English words.
pub(crate) fn io_text(e: &std::io::Error) -> String {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionReset => "connection reset".into(),
        K::ConnectionAborted => "connection aborted".into(),
        K::ConnectionRefused => "connection refused".into(),
        K::BrokenPipe => "broken pipe".into(),
        K::TimedOut => "timeout".into(),
        K::UnexpectedEof => "unexpected end of stream".into(),
        other => format!("io: {other:?}"),
    }
}

/// A TLS failure: rustls' own (English) text, or the socket's kind.
fn tls_text(e: &std::io::Error) -> String {
    if e.raw_os_error().is_some() {
        io_text(e)
    } else {
        e.to_string()
    }
}
