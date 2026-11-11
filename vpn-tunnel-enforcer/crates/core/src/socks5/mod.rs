//! SOCKS5 client (RFC 1928, user/password per RFC 1929): the one implementation behind engine
//! readiness, slot egress probes and SOCKS pings (xray-engine §2.8, §2.10, B24, B27).
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Creds;
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::net::{Host, HostPort, unmap};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0x00;
const USER_PASS: u8 = 0x02;
const AUTH_VERSION: u8 = 1;
const CMD_CONNECT: u8 = 1;
const ATYP_V4: u8 = 1;
const ATYP_NAME: u8 = 3;
const ATYP_V6: u8 = 4;

/// Cap of one readiness attempt and the pause between attempts (old `waitForLocalSocks`).
const READY_ATTEMPT: Duration = Duration::from_millis(250);
const READY_PAUSE: Duration = Duration::from_millis(100);

/// Why a SOCKS5 exchange failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SocksError {
    /// The TCP connection to the SOCKS server failed.
    #[error("cannot connect to the SOCKS server: {0:?}")]
    Connect(io::ErrorKind),
    /// Reading or writing failed after connecting (other than the peer closing).
    #[error("SOCKS I/O error: {0:?}")]
    Io(io::ErrorKind),
    /// The server closed the connection mid-handshake.
    #[error("SOCKS server closed the connection")]
    Closed,
    /// The server did not select the offered method: user/password when we have credentials
    /// (an unauthenticated listener on an app-owned port is not ours), no-auth otherwise.
    #[error("SOCKS authentication required")]
    AuthRequired,
    /// The server refused the credentials.
    #[error("SOCKS authentication failed")]
    AuthRejected,
    /// The CONNECT reply carried a failure code (RFC 1928: 1 general failure … 8 bad address type).
    #[error("SOCKS server refused the connection (code {0})")]
    UpstreamRejected(u8),
    /// The server does not speak SOCKS5.
    #[error("malformed SOCKS reply")]
    Malformed,
    /// Port 0 or credentials outside 1..=255 bytes.
    #[error("invalid SOCKS parameters")]
    InvalidInput,
    /// The deadline passed before the exchange finished.
    #[error("SOCKS deadline passed")]
    Timeout,
    /// The caller's token was cancelled.
    #[error("SOCKS operation cancelled")]
    Cancelled,
}

impl SocksError {
    /// An answer from a live SOCKS server that a retry cannot change.
    fn is_definite(self) -> bool {
        matches!(
            self,
            SocksError::AuthRequired | SocksError::AuthRejected | SocksError::Malformed
        )
    }
}

impl From<SocksError> for AppError {
    fn from(err: SocksError) -> Self {
        let (kind, key) = match err {
            SocksError::Connect(_) | SocksError::Io(_) | SocksError::Closed => {
                (ErrorKind::Network, "core.net.socksUnreachable")
            }
            SocksError::Malformed => (ErrorKind::Network, "core.net.socksMalformed"),
            SocksError::AuthRequired => (ErrorKind::Network, "core.net.socksAuthRequired"),
            SocksError::AuthRejected => (ErrorKind::Network, "core.net.socksAuthRejected"),
            SocksError::UpstreamRejected(code) => {
                let msg = Msg::new("core.net.socksUpstreamRejected").arg("code", code);
                return AppError::msg(ErrorKind::Network, msg).with_source(err);
            }
            SocksError::InvalidInput => (ErrorKind::Validation, "core.net.socksInvalidInput"),
            SocksError::Timeout => return AppError::timeout().with_source(err),
            SocksError::Cancelled => return AppError::cancelled(),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Greeting and, with credentials, user/password authentication. With credentials only method
/// 0x02 is offered: an app-owned listener must never be usable without them.
pub async fn negotiate<S>(stream: &mut S, creds: Option<&Creds>) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let auth = creds.map(encode_auth).transpose()?;
    let method = if auth.is_some() { USER_PASS } else { NO_AUTH };
    send(stream, &[VERSION, 1, method]).await?;
    let [version, chosen] = recv::<2>(stream).await?;
    if version != VERSION {
        return Err(SocksError::Malformed);
    }
    if chosen != method {
        return Err(SocksError::AuthRequired);
    }
    if let Some(auth) = auth {
        send(stream, &auth).await?;
        let [version, status] = recv::<2>(stream).await?;
        if status != 0 {
            return Err(SocksError::AuthRejected);
        }
        if version != AUTH_VERSION {
            return Err(SocksError::Malformed);
        }
    }
    Ok(())
}

/// [`negotiate`], then CONNECT to `target`; afterwards the stream carries the tunnelled bytes.
pub async fn handshake<S>(
    stream: &mut S,
    creds: Option<&Creds>,
    target: &HostPort,
) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate(stream, creds).await?;
    send(stream, &encode_connect(target)).await?;
    read_connect_reply(stream).await
}

/// TCP connection to `proxy` plus [`handshake`] to `target`, all within one deadline (`limit`).
pub async fn connect(
    proxy: SocketAddr,
    creds: Option<&Creds>,
    target: &HostPort,
    limit: Duration,
) -> Result<TcpStream, SocksError> {
    if proxy.port() == 0 {
        return Err(SocksError::InvalidInput);
    }
    if let Some(creds) = creds {
        encode_auth(creds)?;
    }
    let attempt = async {
        let mut stream = TcpStream::connect(proxy)
            .await
            .map_err(|err| SocksError::Connect(err.kind()))?;
        // Handshake messages are tiny request/response pairs; never let Nagle hold one back.
        let _ = stream.set_nodelay(true);
        handshake(&mut stream, creds, target).await?;
        Ok(stream)
    };
    timeout(limit, attempt)
        .await
        .unwrap_or(Err(SocksError::Timeout))
}

/// Polls `127.0.0.1:port` until a SOCKS5 server answers (with `creds`: accepts them) or `total`
/// passes. Refused, closed or slow attempts are retried every 100 ms; a definite protocol answer
/// (method refused, credentials rejected, not SOCKS) returns at once since retrying cannot
/// change it. Otherwise the error is the last attempt's, or `Timeout` when none finished.
/// Without credentials an accepted TCP connection means ready.
pub async fn wait_ready(
    port: u16,
    creds: Option<&Creds>,
    total: Duration,
    cancel: &CancellationToken,
) -> Result<(), SocksError> {
    if port == 0 {
        return Err(SocksError::InvalidInput);
    }
    if let Some(creds) = creds {
        encode_auth(creds)?;
    }
    let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let deadline = Instant::now() + total;
    let mut last = SocksError::Timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if cancel.is_cancelled() {
            return Err(SocksError::Cancelled);
        }
        if remaining.is_zero() {
            return Err(last);
        }
        let attempt = timeout(remaining.min(READY_ATTEMPT), probe(proxy, creds));
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SocksError::Cancelled),
            outcome = attempt => outcome.unwrap_or(Err(SocksError::Timeout)),
        };
        match outcome {
            // A cancel that raced the successful attempt still wins.
            Ok(()) if cancel.is_cancelled() => return Err(SocksError::Cancelled),
            Ok(()) => return Ok(()),
            Err(err) if err.is_definite() => return Err(err),
            Err(err) => last = err,
        }
        let pause = deadline
            .saturating_duration_since(Instant::now())
            .min(READY_PAUSE);
        tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(SocksError::Cancelled),
            () = sleep(pause) => {}
        }
    }
}

/// One readiness attempt; the socket is closed when it returns.
async fn probe(proxy: SocketAddr, creds: Option<&Creds>) -> Result<(), SocksError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|err| SocksError::Connect(err.kind()))?;
    if creds.is_some() {
        negotiate(&mut stream, creds).await?;
    }
    Ok(())
}

/// Reads the CONNECT reply including the bound address, whose size depends on its type:
/// 10 bytes in total for IPv4, 22 for IPv6, 7 + length for a name.
async fn read_connect_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(), SocksError> {
    let [version, code, _reserved, atyp] = recv::<4>(stream).await?;
    if version != VERSION {
        return Err(SocksError::Malformed);
    }
    if code != 0 {
        return Err(SocksError::UpstreamRejected(code));
    }
    let rest = match atyp {
        ATYP_V4 => 4 + 2,
        ATYP_V6 => 16 + 2,
        ATYP_NAME => usize::from(recv::<1>(stream).await?[0]) + 2,
        _ => return Err(SocksError::Malformed),
    };
    let mut bound = [0u8; 255 + 2];
    stream
        .read_exact(&mut bound[..rest])
        .await
        .map_err(io_error)?;
    Ok(())
}

/// RFC 1929 request: `01 ulen user plen pass`, both fields 1..=255 bytes.
fn encode_auth(creds: &Creds) -> Result<Vec<u8>, SocksError> {
    let (user, pass) = (creds.user.as_bytes(), creds.pass.as_bytes());
    let len = |field: &[u8]| {
        u8::try_from(field.len())
            .ok()
            .filter(|&n| n > 0)
            .ok_or(SocksError::InvalidInput)
    };
    let (ulen, plen) = (len(user)?, len(pass)?);
    let mut out = Vec::with_capacity(3 + user.len() + pass.len());
    out.extend_from_slice(&[AUTH_VERSION, ulen]);
    out.extend_from_slice(user);
    out.push(plen);
    out.extend_from_slice(pass);
    Ok(out)
}

/// CONNECT request; IPv6 literals go as ATYP 4, never as a name (B24).
fn encode_connect(target: &HostPort) -> Vec<u8> {
    let mut out = vec![VERSION, CMD_CONNECT, 0];
    match target.host() {
        Host::Ip(ip) => match unmap(*ip) {
            IpAddr::V4(v4) => {
                out.push(ATYP_V4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(ATYP_V6);
                out.extend_from_slice(&v6.octets());
            }
        },
        Host::Name(name) => {
            // HostPort names are 1..=253 bytes, so the length always fits the byte.
            out.extend_from_slice(&[ATYP_NAME, name.len() as u8]);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), SocksError> {
    stream.write_all(bytes).await.map_err(io_error)?;
    stream.flush().await.map_err(io_error)
}

async fn recv<const N: usize>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<[u8; N], SocksError> {
    let mut buf = [0u8; N];
    stream.read_exact(&mut buf).await.map_err(io_error)?;
    Ok(buf)
}

fn io_error(err: io::Error) -> SocksError {
    use io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match err.kind() {
        UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe => SocksError::Closed,
        kind => SocksError::Io(kind),
    }
}

#[cfg(test)]
mod tests;
