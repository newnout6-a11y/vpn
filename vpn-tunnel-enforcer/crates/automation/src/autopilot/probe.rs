//! Proxy handshake probes (AP:23-83). Both only prove "this port speaks the protocol": many SOCKS
//! inbounds answer success before they dial the upstream. Real egress is proven afterwards by
//! adaptive verification, so nothing more is checked here.
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vpnte_base::types::{Creds, ProxyKind};
use vpnte_core::net::{Host, HostPort};
use vpnte_core::socks5;

use crate::coordinator::ProxyEndpoint;

/// Probe deadlines.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Bare TCP connect before any handshake (AP:72).
    pub tcp: Duration,
    /// Each protocol handshake, connect included (AP:23-63).
    pub handshake: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            tcp: Duration::from_millis(1200),
            handshake: Duration::from_millis(3000),
        }
    }
}

/// The CONNECT target of both probes (the old probes used it too).
const TARGET: (&str, u16) = ("api.ipify.org", 443);

/// Opens a TCP connection to `addr` (a name is resolved by the OS), bounded by `limit`.
async fn connect(addr: &HostPort, limit: Duration) -> Option<TcpStream> {
    let dial = async {
        match addr.host() {
            Host::Ip(ip) => TcpStream::connect(SocketAddr::new(*ip, addr.port())).await,
            Host::Name(name) => TcpStream::connect((name.as_str(), addr.port())).await,
        }
    };
    tokio::time::timeout(limit, dial).await.ok()?.ok()
}

/// SOCKS5 greeting + CONNECT to the target (name, ATYP 3) answered with success.
pub(super) async fn socks5_ok(addr: &HostPort, creds: Option<&Creds>, limit: Duration) -> bool {
    let Ok(target) = HostPort::new(TARGET.0, TARGET.1) else {
        return false;
    };
    let attempt = async {
        let mut stream = connect(addr, limit).await?;
        socks5::handshake(&mut stream, creds, &target).await.ok()
    };
    // The stream is dropped (closed) on every path, a late answer included.
    tokio::time::timeout(limit, attempt)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// HTTP `CONNECT` to the target answered with any 2xx (parity with the old axios tunnel, P7).
pub(super) async fn http_ok(addr: &HostPort, creds: Option<&Creds>, limit: Duration) -> bool {
    static STATUS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^HTTP/1\.[01] 2\d\d\b").expect("valid regex"));
    let attempt = async {
        let mut stream = connect(addr, limit).await?;
        let mut request = format!(
            "CONNECT {0}:{1} HTTP/1.1\r\nHost: {0}:{1}\r\n",
            TARGET.0, TARGET.1
        );
        if let Some(c) = creds {
            let token = STANDARD.encode(format!("{}:{}", c.user, c.pass));
            request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut head = Vec::with_capacity(64);
        let mut buf = [0u8; 256];
        while !head.contains(&b'\n') && head.len() < 1024 {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        Some(STATUS.is_match(&String::from_utf8_lossy(&head)))
    };
    tokio::time::timeout(limit, attempt).await.ok().flatten() == Some(true)
}

/// A process name that looks like a proxy core speaks SOCKS first (AP:74-76).
fn prefers_socks(process: &str) -> bool {
    static CORE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)xray|v2ray|sing|happ|hiddify|nekoray|shadowsocks|trojan")
            .expect("valid regex")
    });
    CORE.is_match(process)
}

/// The endpoint of a listener that accepts TCP and answers a SOCKS5 or HTTP handshake.
pub(super) async fn verify_listener(
    addr: &HostPort,
    process: &str,
    timing: Timing,
) -> Option<ProxyEndpoint> {
    connect(addr, timing.tcp).await?;
    let order = if prefers_socks(process) {
        [ProxyKind::Socks5, ProxyKind::Http]
    } else {
        [ProxyKind::Http, ProxyKind::Socks5]
    };
    for kind in order {
        if handshake_ok(addr, kind, None, timing.handshake).await {
            return Some(ProxyEndpoint {
                addr: addr.clone(),
                kind,
                creds: None,
            });
        }
    }
    None
}

/// A configured endpoint (settings override, detection): TCP, then its own protocol only.
pub(super) async fn verify_endpoint(ep: &ProxyEndpoint, timing: Timing) -> bool {
    connect(&ep.addr, timing.tcp).await.is_some()
        && handshake_ok(&ep.addr, ep.kind, ep.creds.as_ref(), timing.handshake).await
}

async fn handshake_ok(
    addr: &HostPort,
    kind: ProxyKind,
    creds: Option<&Creds>,
    limit: Duration,
) -> bool {
    match kind {
        ProxyKind::Socks5 => socks5_ok(addr, creds, limit).await,
        ProxyKind::Http => http_ok(addr, creds, limit).await,
    }
}
