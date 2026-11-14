//! CONNECT latency through an app-owned loopback SOCKS5 endpoint (the ping's `mixed-direct-in`
//! path; xray-engine §2.9, §3.8 `socks_connect_latency`). Only the CONNECT goes out: the proxy
//! dials the target with plain TCP, no TLS ever reaches the server.
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::future::join_all;
use tokio::time::Instant;
use vpnte_base::types::{Creds, Loopback};
use vpnte_core::net::HostPort;
use vpnte_core::socks5;

#[cfg(test)]
mod tests;

/// `max(1, round(ms))`: a measured round trip is never reported as 0.
pub(crate) fn rtt_ms(elapsed: Duration) -> u32 {
    let ms = (elapsed.as_secs_f64() * 1000.0).round();
    (ms as u32).max(1)
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
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, proxy.port));
    let started = Instant::now();
    socks5::connect(local, proxy.creds.as_ref(), &target, limit)
        .await
        .ok()?;
    Some(rtt_ms(started.elapsed()))
}

/// `attempts` parallel [`socks_connect_latency`] samples reduced by [`super::median`] ("ignore
/// one dropped SYN or one cold-route spike"); `None` when no attempt succeeded.
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
    super::median(&samples)
}
