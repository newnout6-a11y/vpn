//! Probes through an app-owned loopback SOCKS endpoint (an engine inbound, an Xray slot, an
//! external proxy slot): CONNECT latency of a target (the ping's `mixed-direct-in` path) and the
//! public IPv4 the endpoint egresses from (xray-engine §2.9, §2.10, §3.8).
//!
//! Every byte goes through the owned SOCKS socket: no HTTP proxy environment, no direct
//! fallback, and nothing about providers, addresses or credentials reaches the log.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, Loopback};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::net::{HostPort, is_public_ip};
use vpnte_core::socks5::{self, SocksError};

mod https;
#[cfg(test)]
mod tests;

use https::{HttpFail, Wrap};

/// Shared deadline of one egress race (old 2 s; xray-engine §4 B20 decided 4 s).
pub const EGRESS_DEADLINE: Duration = Duration::from_secs(4);
/// Largest provider body accepted.
const BODY_CAP: usize = 4096;

/// Why no egress IPv4 was confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EgressError {
    /// Port 0 or credentials outside 1..=255 bytes: refused before any socket.
    #[error("invalid SOCKS endpoint")]
    Validation,
    #[error("egress probe cancelled")]
    Cancelled,
    /// The shared deadline passed before any provider confirmed an address.
    #[error("egress probe deadline passed")]
    Timeout,
    /// Every provider failed (refused, TLS, HTTP status, no public IPv4, ...).
    #[error("no provider confirmed a public IPv4")]
    Network,
}

impl From<EgressError> for AppError {
    fn from(err: EgressError) -> Self {
        match err {
            EgressError::Validation => {
                AppError::msg(ErrorKind::Validation, Msg::new("probes.egress.invalid"))
            }
            EgressError::Cancelled => AppError::cancelled(),
            EgressError::Timeout => AppError::timeout().with_source(err),
            EgressError::Network => {
                AppError::msg(ErrorKind::Network, Msg::new("probes.egress.failed")).with_source(err)
            }
        }
    }
}

/// `max(1, round(ms))`: a measured round trip is never reported as 0.
pub(crate) fn rtt_ms(elapsed: Duration) -> u32 {
    let ms = (elapsed.as_secs_f64() * 1000.0).round();
    (ms as u32).max(1)
}

fn proxy_addr(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Credentials a SOCKS5 server can accept (RFC 1929: 1..=255 bytes each).
fn creds_valid(creds: Option<&Creds>) -> bool {
    creds.is_none_or(|c| (1..=255).contains(&c.user.len()) && (1..=255).contains(&c.pass.len()))
}

/// Time from socket creation to the complete CONNECT reply for `host:port` through the loopback
/// SOCKS5 endpoint, as `max(1, round(ms))`. With credentials only user/password is offered (a
/// server choosing no-auth is refused). Invalid input (port 0, empty host, zero timeout) is
/// `None` without any I/O; so is every failure.
pub async fn socks_connect_latency(
    proxy: &Loopback,
    host: &str,
    port: u16,
    limit: Duration,
) -> Option<u32> {
    if port == 0 || proxy.port == 0 || limit.is_zero() || !creds_valid(proxy.creds.as_ref()) {
        return None;
    }
    // IPv4 literals go as ATYP 1, IPv6 as ATYP 4, names as ATYP 3 (resolved by the proxy).
    let target = HostPort::new(host, port).ok()?;
    let started = Instant::now();
    socks5::connect(proxy_addr(proxy.port), proxy.creds.as_ref(), &target, limit)
        .await
        .ok()?;
    Some(rtt_ms(started.elapsed()))
}

/// `attempts` parallel [`socks_connect_latency`] samples reduced by [`crate::ping::median`]
/// ("ignore one dropped SYN or one cold-route spike"); `None` when no attempt succeeded.
pub async fn reliable_socks_latency(
    proxy: &Loopback,
    host: &str,
    port: u16,
    limit: Duration,
    attempts: usize,
) -> Option<u32> {
    let samples =
        join_all((0..attempts.max(1)).map(|_| socks_connect_latency(proxy, host, port, limit)))
            .await;
    crate::ping::median(&samples)
}

/// One egress identity service: SNI and SOCKS domain (port 443) and path.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Provider {
    pub host: &'static str,
    pub path: &'static str,
}

/// Raced in parallel (socksUpstreamProbe.ts:22-27); the index is the only identity in logs.
/// Domain names on purpose: the exit resolves them (SOCKS domain CONNECT), unlike the
/// family-pinned endpoints of `public_ip::PROVIDERS`.
const PROVIDERS: [Provider; 4] = [
    Provider {
        host: "cloudflare.com",
        path: "/cdn-cgi/trace",
    },
    Provider {
        host: "api.ipify.org",
        path: "/?format=json",
    },
    Provider {
        host: "icanhazip.com",
        path: "/",
    },
    Provider {
        host: "api.myip.com",
        path: "/",
    },
];

/// The address in a provider body, if it is a public IPv4. IPv6 echoes are refused: the
/// retained tunnel confirmation compares IPv4 samples.
pub(crate) fn parse_body(body: &str) -> Option<Ipv4Addr> {
    match crate::ip_echo::parse_provider_body(body)? {
        IpAddr::V4(ip) if is_public_ip(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

/// Where a provider attempt ended (log field `stage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    LocalConnect,
    SocksHandshake,
    TlsHandshake,
    HttpsResponse,
    ResponseBody,
}

impl Stage {
    fn as_str(self) -> &'static str {
        match self {
            Stage::LocalConnect => "local-connect",
            Stage::SocksHandshake => "socks-handshake",
            Stage::TlsHandshake => "tls-handshake",
            Stage::HttpsResponse => "https-response",
            Stage::ResponseBody => "response-body",
        }
    }
}

/// Log code of a provider attempt (socksUpstreamProbe.ts:30-33, minus the Node-only
/// `SOCKET_CLOSE_UNCONFIRMED`: dropping a Rust socket closes it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Code {
    ConnectFailed,
    SocksFailed,
    SocksAuthRequired,
    SocksAuthRejected,
    SocksUpstreamRejected,
    SocksClosed,
    TlsFailed,
    HttpsFailed,
    HttpStatus,
    ResponseTooLarge,
    InvalidPublicIp,
    Deadline,
}

impl Code {
    fn as_str(self) -> &'static str {
        match self {
            Code::ConnectFailed => "CONNECT_FAILED",
            Code::SocksFailed => "SOCKS_FAILED",
            Code::SocksAuthRequired => "SOCKS_AUTH_REQUIRED",
            Code::SocksAuthRejected => "SOCKS_AUTH_REJECTED",
            Code::SocksUpstreamRejected => "SOCKS_UPSTREAM_REJECTED",
            Code::SocksClosed => "SOCKS_CLOSED",
            Code::TlsFailed => "TLS_FAILED",
            Code::HttpsFailed => "HTTPS_FAILED",
            Code::HttpStatus => "HTTP_STATUS",
            Code::ResponseTooLarge => "RESPONSE_TOO_LARGE",
            Code::InvalidPublicIp => "INVALID_PUBLIC_IP",
            Code::Deadline => "DEADLINE",
        }
    }
}

/// A failed provider attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fail {
    pub stage: Stage,
    pub code: Code,
}

impl Fail {
    fn new(stage: Stage, code: Code) -> Self {
        Self { stage, code }
    }
}

fn socks_code(err: SocksError) -> Code {
    match err {
        SocksError::AuthRequired => Code::SocksAuthRequired,
        SocksError::AuthRejected => Code::SocksAuthRejected,
        SocksError::Closed => Code::SocksClosed,
        SocksError::UpstreamRejected(_) => Code::SocksUpstreamRejected,
        SocksError::Timeout => Code::Deadline,
        _ => Code::SocksFailed,
    }
}

/// One provider through the endpoint, everything before `deadline`.
async fn attempt(
    provider: Provider,
    ep: &Loopback,
    wrap: &Wrap,
    deadline: Instant,
) -> Result<Ipv4Addr, Fail> {
    let late = |stage| move |_| Fail::new(stage, Code::Deadline);
    let mut stream = timeout_at(deadline, TcpStream::connect(proxy_addr(ep.port)))
        .await
        .map_err(late(Stage::LocalConnect))?
        .map_err(|_| Fail::new(Stage::LocalConnect, Code::ConnectFailed))?;
    let _ = stream.set_nodelay(true);
    let target = HostPort::new(provider.host, 443)
        .map_err(|_| Fail::new(Stage::SocksHandshake, Code::SocksFailed))?;
    timeout_at(
        deadline,
        socks5::handshake(&mut stream, ep.creds.as_ref(), &target),
    )
    .await
    .map_err(late(Stage::SocksHandshake))?
    .map_err(|e| Fail::new(Stage::SocksHandshake, socks_code(e)))?;
    let body = timeout_at(
        deadline,
        wrap.get(stream, provider.host, provider.path, BODY_CAP),
    )
    .await
    .map_err(late(Stage::HttpsResponse))?
    .map_err(|fail| match fail {
        HttpFail::Tls => Fail::new(Stage::TlsHandshake, Code::TlsFailed),
        HttpFail::Io => Fail::new(Stage::HttpsResponse, Code::HttpsFailed),
        HttpFail::Status(_) => Fail::new(Stage::HttpsResponse, Code::HttpStatus),
        HttpFail::TooLarge => Fail::new(Stage::ResponseBody, Code::ResponseTooLarge),
        HttpFail::BodyIo => Fail::new(Stage::ResponseBody, Code::HttpsFailed),
    })?;
    let text = String::from_utf8_lossy(&body);
    parse_body(&text).ok_or(Fail::new(Stage::ResponseBody, Code::InvalidPublicIp))
}

/// The four fields of a provider log line (plus the index); never names, addresses or text.
fn log_attempt(index: usize, started: Instant, result: &Result<Ipv4Addr, Fail>) {
    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(_) => tracing::debug!(
            provider_index = index,
            stage = Stage::ResponseBody.as_str(),
            outcome = "success",
            code = "OK",
            duration_ms,
            "egress provider"
        ),
        Err(fail) => tracing::warn!(
            provider_index = index,
            stage = fail.stage.as_str(),
            outcome = if fail.code == Code::Deadline {
                "timeout"
            } else {
                "network"
            },
            code = fail.code.as_str(),
            duration_ms,
            "egress provider"
        ),
    }
}

/// The public IPv4 the loopback SOCKS endpoint `ep` egresses from: four providers raced over
/// SOCKS5 (domain CONNECT to port 443) + TLS (SNI = provider, ALPN http/1.1, certificates
/// verified against the Windows store) + one `GET`, first public IPv4 wins, all within
/// [`EGRESS_DEADLINE`]. With credentials the server must select user/password.
pub async fn probe_egress_ipv4(
    ep: &Loopback,
    cancel: &CancellationToken,
) -> Result<Ipv4Addr, EgressError> {
    let wrap = Wrap::tls().map_err(|_| EgressError::Network)?;
    race(ep, &PROVIDERS, &wrap, EGRESS_DEADLINE, cancel).await
}

/// The race behind [`probe_egress_ipv4`] (providers and transport injectable for tests).
pub(crate) async fn race(
    ep: &Loopback,
    providers: &[Provider],
    wrap: &Wrap,
    budget: Duration,
    cancel: &CancellationToken,
) -> Result<Ipv4Addr, EgressError> {
    if ep.port == 0 || !creds_valid(ep.creds.as_ref()) {
        return Err(EgressError::Validation);
    }
    if cancel.is_cancelled() {
        return Err(EgressError::Cancelled);
    }
    let started = Instant::now();
    let deadline = started + budget;
    let mut pending: FuturesUnordered<_> = providers
        .iter()
        .enumerate()
        .map(|(index, provider)| async move {
            let result = attempt(*provider, ep, wrap, deadline).await;
            log_attempt(index, started, &result);
            result
        })
        .collect();
    let mut timed_out = false;
    loop {
        let next = tokio::select! {
            biased;
            () = cancel.cancelled() => return Err(EgressError::Cancelled),
            next = pending.next() => next,
        };
        match next {
            Some(Ok(ip)) => return Ok(ip),
            Some(Err(fail)) => timed_out |= fail.code == Code::Deadline,
            None if timed_out => return Err(EgressError::Timeout),
            None => return Err(EgressError::Network),
        }
    }
}
