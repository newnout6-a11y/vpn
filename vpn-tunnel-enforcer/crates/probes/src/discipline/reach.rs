//! The reach probe: ICMP echo and one plain TCP connect to the server's own port, the evidence
//! that separates an address ban (ICMP answers, TCP silent) from a dead server and from a
//! handshake problem. Same field rules as `ping`: never a TLS ClientHello, never another port (a
//! port fan looks like a scan), a remote SYN-ACK within 3 ms is spoofed by a local client, and
//! while our TUN runs only a physical source address measures the server (an unbound socket
//! would measure the TUN). Not counted by the handshake budget.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use vpnte_winnet::icmp::{self, EchoRequest, EchoStatus};

use super::classify::Seen;
use crate::ping::{self, NetPath, icmp_rtt, physical_sources, plausible, resolve_target, rtt_ms};

/// TCP connect limit: longer than a ping's, a slow mobile link must not read as "silent".
pub const TCP_LIMIT: Duration = Duration::from_secs(3);
/// Echo attempts: one lost packet must not read as "silent".
const ECHOES: usize = 2;

/// What the plain probes of a server address saw.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reach {
    pub icmp: Seen,
    /// `NotRun` for a UDP-only port (no SYN to a port that only speaks UDP).
    pub tcp: Seen,
}

/// Probes `host:port` from a clean path; anything without one stays `NotRun`.
pub async fn reach(
    host: &str,
    port: u16,
    udp_only: bool,
    net: &NetPath,
    cancel: &CancellationToken,
) -> Reach {
    tokio::select! {
        biased;
        () = cancel.cancelled() => Reach::default(),
        reach = probe(host, port, udp_only, net) => reach,
    }
}

async fn probe(host: &str, port: u16, udp_only: bool, net: &NetPath) -> Reach {
    if port == 0 || ping::is_loopback_host(host) {
        return Reach::default();
    }
    let Some(ip) = resolve_target(host).await else {
        return Reach::default();
    };
    let dst = SocketAddr::new(ip, port);
    let source = physical_sources()
        .await
        .into_iter()
        .find(|s| s.is_ipv4() == ip.is_ipv4());
    // Our TUN captures unbound sockets: without a physical source there is no clean path.
    if source.is_none() && net.tunnel_running() {
        return Reach::default();
    }
    let tcp = async {
        if udp_only {
            Seen::NotRun
        } else {
            tcp(source, dst).await
        }
    };
    let (icmp, tcp) = tokio::join!(echo(source, ip), tcp);
    Reach { icmp, tcp }
}

/// One connect (SYN / SYN-ACK, dropped right after, no bytes sent).
async fn tcp(src: Option<IpAddr>, dst: SocketAddr) -> Seen {
    let socket = if dst.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    };
    let Ok(socket) = socket else {
        return Seen::NotRun;
    };
    if let Some(src) = src
        && socket.bind(SocketAddr::new(src, 0)).is_err()
    {
        return Seen::NotRun;
    }
    let started = Instant::now();
    match timeout(TCP_LIMIT, socket.connect(dst)).await {
        Ok(Ok(_)) if plausible(rtt_ms(started.elapsed()), dst.ip().is_loopback()) => Seen::Answered,
        // A SYN-ACK this fast came from a local client, not from the server.
        Ok(Ok(_)) => Seen::NotRun,
        Ok(Err(e)) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => Seen::Refused,
            std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable => Seen::Silent,
            _ => Seen::NotRun,
        },
        Err(_) => Seen::Silent,
    }
}

/// Up to [`ECHOES`] echoes; any plausible reply from the server itself is an answer.
async fn echo(src: Option<IpAddr>, dst: IpAddr) -> Seen {
    let mut seen = Seen::NotRun;
    for _ in 0..ECHOES {
        let request = EchoRequest {
            src,
            timeout: ping::ICMP_TIMEOUT,
            ..EchoRequest::new(dst)
        };
        let Ok(reply) = icmp::echo(request).await else {
            continue;
        };
        if icmp_rtt(&reply, dst).is_some() {
            return Seen::Answered;
        }
        if matches!(reply.status, EchoStatus::TimedOut | EchoStatus::Unreachable) {
            seen = Seen::Silent;
        }
    }
    seen
}
