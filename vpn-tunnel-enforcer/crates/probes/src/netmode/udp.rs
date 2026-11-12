//! One UDP request / answer exchange, shared by the QUIC and the STUN probe. A client flow: the
//! socket binds port 0 on the uplink's address, connects to the server and sends first (never a
//! listener). Without an uplink address there is no probe: an unbound socket follows whatever
//! route is on top (our TUN, another client's), which would measure that tunnel, not the network.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::Outcome;

/// Datagrams sent before giving up (UDP is lossy; one loss must not read as a block).
const ATTEMPTS: u32 = 2;

/// Sends `packet` to `dst` from `source` up to [`ATTEMPTS`] times, waiting `limit` for a datagram
/// `answers` accepts. Loopback targets (tests) are probed from loopback.
pub(super) async fn exchange(
    dst: SocketAddr,
    source: Option<IpAddr>,
    limit: Duration,
    packet: &[u8],
    answers: impl Fn(&[u8]) -> bool,
) -> Outcome {
    let bind = match (dst.ip().is_loopback(), source) {
        (true, _) if dst.is_ipv4() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        (true, _) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        (false, Some(src)) if src.is_ipv4() == dst.is_ipv4() => src,
        (false, _) => return Outcome::NotRun,
    };
    let Ok(socket) = UdpSocket::bind(SocketAddr::new(bind, 0)).await else {
        return Outcome::NotRun;
    };
    if socket.connect(dst).await.is_err() {
        return Outcome::NotRun;
    }
    let mut buf = [0u8; 1500];
    for _ in 0..ATTEMPTS {
        if socket.send(packet).await.is_err() {
            return Outcome::Failed;
        }
        match timeout(limit, socket.recv(&mut buf)).await {
            Ok(Ok(n)) if answers(&buf[..n]) => return Outcome::Ok,
            // Not the answer to this probe (a stray or forged datagram): proves nothing.
            Ok(Ok(_)) | Err(_) => {}
            // Windows reports an ICMP port-unreachable as a reset of the connected socket.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionReset => return Outcome::Reset,
            Ok(Err(_)) => return Outcome::Failed,
        }
    }
    Outcome::Silent
}
