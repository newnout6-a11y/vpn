//! Server reachability without touching the VPN front (servers §2.8, §3.7). Field rules kept:
//! never a TLS ClientHello with the profile's SNI from the user's network (TSPU blackholes the
//! IP for ~10 minutes), only the profile's own port (no port fans), round trips of 3 ms or less
//! to a remote host are a locally spoofed SYN-ACK, and while our TUN runs an unbound socket is
//! captured by sing-box and measures nothing: then the ping goes through `mixed-direct-in`
//! (routed `direct-out`) or from a physical source address. Pings are never persisted.
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use futures_util::future::join_all;
use futures_util::stream::{self, Stream, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Loopback;
use vpnte_core::resolve::{self, How};
use vpnte_profiles::model::{Host, Profile};
use vpnte_winnet::icmp::{self, EchoReply, EchoRequest, EchoStatus};

use crate::egress::{reliable_socks_latency, rtt_ms};

#[cfg(test)]
mod tests;

/// Per TCP sample (SOCKS or plain connect).
pub const TCP_TIMEOUT: Duration = Duration::from_millis(1800);
/// Per ICMP echo.
pub const ICMP_TIMEOUT: Duration = Duration::from_millis(1500);
/// Parallel TCP samples per measurement.
pub const SAMPLES: usize = 3;
/// Name resolution before a bound / unbound probe.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_millis(2500);
/// Sliding window of [`ping_all`].
pub const PING_ALL_WINDOW: usize = 6;
/// A non-empty physical source list is reused this long; an empty one is re-read every time.
const SOURCES_TTL: Duration = Duration::from_secs(10);

/// How probes reach the network right now (a snapshot from the tunnel runtime).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetPath {
    /// `Some` while our TUN captures traffic: sing-box's authenticated `mixed-direct-in`
    /// (routed `direct-out`). Unbound sockets would be captured by the TUN.
    pub tun_direct: Option<Loopback>,
}

impl NetPath {
    /// True while our TUN captures unbound sockets.
    pub fn tunnel_running(&self) -> bool {
        self.tun_direct.is_some()
    }
}

/// How a ping sample was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PingPath {
    /// SOCKS CONNECT through `mixed-direct-in` → `direct-out` (tunnel running).
    DirectOutSocks,
    /// TCP connect (SYN / SYN-ACK only), bound to a physical source or unbound.
    Tcp,
    /// ICMP echo (UDP-only protocols, or when TCP gave nothing).
    Icmp,
}

/// One measured round trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingSample {
    pub ms: u32,
    pub path: PingPath,
}

/// What to ping: the profile's server and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingTarget {
    /// Host name or IP literal (IPv6 unbracketed).
    pub host: String,
    pub port: u16,
    /// hysteria2 / TUIC / WireGuard / naive-QUIC: no SYNs to a UDP port, ICMP only.
    pub udp_only: bool,
}

impl PingTarget {
    /// The target of a profile.
    pub fn of(p: &Profile) -> Self {
        let host = match &p.server {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(name) => name.trim().to_owned(),
        };
        Self {
            host,
            port: p.port,
            udp_only: p.kind.is_udp_transport(),
        }
    }

    fn loopback(&self) -> bool {
        is_loopback_host(&self.host)
    }
}

/// `127.x`, `::1` or `localhost`: the only hosts allowed a round trip of 3 ms or less.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The middle sample, or the rounded mean of the two middle ones; failed samples are ignored.
pub fn median(samples: &[Option<u32>]) -> Option<u32> {
    let mut ok: Vec<u32> = samples.iter().flatten().copied().collect();
    if ok.is_empty() {
        return None;
    }
    ok.sort_unstable();
    let mid = ok.len() / 2;
    if ok.len() % 2 == 1 {
        Some(ok[mid])
    } else {
        Some((u64::from(ok[mid - 1]) + u64::from(ok[mid])).div_ceil(2) as u32)
    }
}

/// Mobile / TSPU networks spoof the SYN-ACK of port 443 locally in 1-3 ms: such a round trip to a
/// remote host is not the server's.
pub fn plausible(ms: u32, loopback: bool) -> bool {
    loopback || ms > 3
}

/// The round trip of an echo reply, if it is really the destination answering: status success,
/// reply address = destination, `0 ms` only for loopback (a LAN hop otherwise), plausible.
pub(crate) fn icmp_rtt(reply: &EchoReply, dst: IpAddr) -> Option<u32> {
    if reply.status != EchoStatus::Success || reply.from != Some(dst) {
        return None;
    }
    let loopback = dst.is_loopback();
    let rtt = reply.rtt_ms?;
    if rtt == 0 && !loopback {
        return None;
    }
    let rtt = rtt.max(1);
    plausible(rtt, loopback).then_some(rtt)
}

/// One rung of the ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// SOCKS CONNECT through `mixed-direct-in` (TCP protocols, tunnel running).
    DirectSocks,
    /// TCP (unless UDP-only) and ICMP from each physical source address: these bypass our TUN
    /// and other VPNs' TUNs that own the default route.
    Physical,
    /// Plain TCP connect (tunnel down only).
    UnboundTcp,
    /// Plain ICMP echo (tunnel down only).
    UnboundIcmp,
}

/// The ladder for a target: never an unbound socket while our TUN runs (it would measure the
/// TUN), never a SYN to a UDP-only port.
pub(crate) fn plan(tunnel_running: bool, udp_only: bool) -> Vec<Step> {
    let tcp = !udp_only;
    let mut steps = Vec::with_capacity(3);
    if tunnel_running {
        if tcp {
            steps.push(Step::DirectSocks);
        }
        steps.push(Step::Physical);
    } else {
        steps.push(Step::Physical);
        if tcp {
            steps.push(Step::UnboundTcp);
        }
        steps.push(Step::UnboundIcmp);
    }
    steps
}

/// Pings `target` along the ladder (servers §3.7); `None` when no rung produced a plausible
/// round trip or `cancel` fired. Works in both tunnel states.
pub async fn ping(
    target: &PingTarget,
    net: &NetPath,
    cancel: &CancellationToken,
) -> Option<PingSample> {
    if target.port == 0 || target.host.is_empty() {
        return None;
    }
    tokio::select! {
        biased;
        () = cancel.cancelled() => None,
        sample = ladder(target, net) => sample,
    }
}

async fn ladder(target: &PingTarget, net: &NetPath) -> Option<PingSample> {
    let loopback = target.loopback();
    let mut dst: Option<Option<IpAddr>> = None;
    for step in plan(net.tunnel_running(), target.udp_only) {
        if step == Step::DirectSocks {
            let sample = direct_socks(net.tun_direct.as_ref()?, target, loopback).await;
            if sample.is_some() {
                return sample;
            }
            continue;
        }
        // Resolved once, and only when a rung needs an address.
        if dst.is_none() {
            dst = Some(resolve_target(&target.host).await);
        }
        let ip = (*dst.as_ref()?)?;
        let addr = SocketAddr::new(ip, target.port);
        let sample = match step {
            Step::Physical => physical(addr, target.udp_only).await,
            Step::UnboundTcp => tcp_median(None, addr)
                .await
                .filter(|&ms| plausible(ms, ip.is_loopback()))
                .map(|ms| PingSample {
                    ms,
                    path: PingPath::Tcp,
                }),
            Step::UnboundIcmp => echo(None, ip).await.map(|ms| PingSample {
                ms,
                path: PingPath::Icmp,
            }),
            Step::DirectSocks => None,
        };
        if sample.is_some() {
            return sample;
        }
    }
    None
}

/// [`SAMPLES`] SOCKS CONNECTs through `mixed-direct-in`. This relies on sing-box answering the
/// CONNECT only after its `direct-out` dial (otherwise every value would be about 1 ms). The old
/// code had no 3 ms gate here; a spoofed SYN-ACK is just as possible behind `direct-out`, so the
/// gate applies to this path too.
pub(crate) async fn direct_socks(
    direct: &Loopback,
    target: &PingTarget,
    loopback: bool,
) -> Option<PingSample> {
    let ms = reliable_socks_latency(direct, &target.host, target.port, TCP_TIMEOUT, SAMPLES).await;
    ms.filter(|&ms| plausible(ms, loopback))
        .map(|ms| PingSample {
            ms,
            path: PingPath::DirectOutSocks,
        })
}

/// The address to probe: the literal itself, else the first OS-resolver answer (IPv4 first).
async fn resolve_target(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        return Some(ip);
    }
    let answers = timeout(
        RESOLVE_TIMEOUT,
        resolve::resolve_host(host, How::System, |_| true),
    )
    .await
    .ok()?
    .ok()?;
    answers.first().copied()
}

/// From each physical source of the target's family in turn: TCP (unless UDP-only) and ICMP at
/// the same time; a plausible TCP result wins over ICMP.
async fn physical(dst: SocketAddr, udp_only: bool) -> Option<PingSample> {
    let loopback = dst.ip().is_loopback();
    for src in physical_sources().await {
        if src.is_ipv4() != dst.is_ipv4() {
            continue;
        }
        let tcp = async {
            if udp_only {
                return None;
            }
            tcp_median(Some(src), dst)
                .await
                .filter(|&ms| plausible(ms, loopback))
        };
        let (tcp, icmp) = tokio::join!(tcp, echo(Some(src), dst.ip()));
        if let Some(ms) = tcp {
            return Some(PingSample {
                ms,
                path: PingPath::Tcp,
            });
        }
        if let Some(ms) = icmp {
            return Some(PingSample {
                ms,
                path: PingPath::Icmp,
            });
        }
    }
    None
}

/// [`SAMPLES`] parallel connects, reduced by [`median`].
async fn tcp_median(src: Option<IpAddr>, dst: SocketAddr) -> Option<u32> {
    let samples = join_all((0..SAMPLES).map(|_| tcp_once(src, dst))).await;
    median(&samples)
}

/// One TCP connect (SYN / SYN-ACK; the socket is dropped right after, no bytes sent).
async fn tcp_once(src: Option<IpAddr>, dst: SocketAddr) -> Option<u32> {
    let socket = if dst.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .ok()?;
    if let Some(src) = src {
        socket.bind(SocketAddr::new(src, 0)).ok()?;
    }
    let started = Instant::now();
    timeout(TCP_TIMEOUT, socket.connect(dst)).await.ok()?.ok()?;
    Some(rtt_ms(started.elapsed()))
}

/// One ICMP echo (optionally from `src`), judged by [`icmp_rtt`].
async fn echo(src: Option<IpAddr>, dst: IpAddr) -> Option<u32> {
    let request = EchoRequest {
        src,
        timeout: ICMP_TIMEOUT,
        ..EchoRequest::new(dst)
    };
    let reply = icmp::echo(request).await.ok()?;
    icmp_rtt(&reply, dst)
}

/// Unicast addresses of the physical adapters (IPv4 without 169.254/16, global IPv6), in adapter
/// order. A non-empty list is cached briefly; an empty one is re-read so that bound probes come
/// back as soon as the network does (the old 60 s cache of an empty answer kept them off).
async fn physical_sources() -> Vec<IpAddr> {
    /// When the list was read, and the list.
    type Sources = (Instant, Vec<IpAddr>);
    static CACHE: LazyLock<Mutex<Option<Sources>>> = LazyLock::new(Mutex::default);
    if let Some((at, sources)) = CACHE.lock().as_ref()
        && at.elapsed() < SOURCES_TTL
    {
        return sources.clone();
    }
    let read = tokio::task::spawn_blocking(|| {
        vpnte_winnet::adapters::physical_adapters()
            .map(|list| {
                list.iter()
                    .flat_map(|a| {
                        let v4 = a.source_v4().into_iter().map(IpAddr::V4);
                        v4.chain(a.global_v6().into_iter().map(IpAddr::V6))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    if !read.is_empty() {
        *CACHE.lock() = Some((Instant::now(), read.clone()));
    }
    read
}

/// Pings every target with at most [`PING_ALL_WINDOW`] in flight; each result is yielded as soon
/// as it is known (the caller records it in memory and notifies the UI per row).
pub fn ping_all<K: Send + 'static>(
    targets: Vec<(K, PingTarget)>,
    net: NetPath,
    cancel: CancellationToken,
) -> impl Stream<Item = (K, Option<PingSample>)> + Send {
    stream::iter(targets)
        .map(move |(key, target)| {
            let (net, cancel) = (net.clone(), cancel.clone());
            async move {
                let sample = ping(&target, &net, &cancel).await;
                (key, sample)
            }
        })
        .buffer_unordered(PING_ALL_WINDOW)
}
