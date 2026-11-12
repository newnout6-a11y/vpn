//! Pre-resolution of server names before an engine dials them (xray-engine spec §3.4): Xray
//! must never resolve them itself (under the TUN its lookup would be hijacked and answered
//! through the very instance that waits for it). Lookups run in the app: while the TUN is down
//! with `vpnte_core::resolve::resolve_server` (the direct DoH / TCP chain that survives the
//! 2026 Russian DNS blocking, then the OS resolver, then the name's last known address), while
//! it is up as plain UDP DNS to sing-box's `dns-bootstrap-in` (the old upstream is often the
//! thing that died). At most 4 lookups in flight; any failure or a block-page answer fails the
//! whole plan, so the graph is substituted completely or not at all.
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use futures_util::stream::{self, StreamExt, TryStreamExt};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::resolve::{ResolveError, ServerAddrs, resolve_server};

/// Budget of one lookup at `dns-bootstrap-in` (`resolve_server` bounds itself).
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);
/// Lookups in flight at once.
const PARALLEL: usize = 4;
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// Where the names are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvePath {
    /// TUN down: `resolve_server` (direct chain -> OS resolver -> last known address, the last
    /// reported to the user). Worst case about 11 s per name, typically under 1 s.
    Direct,
    /// TUN up: UDP DNS to sing-box's loopback `dns-bootstrap-in` (4 s per name).
    ViaSingBox(SocketAddr),
}

/// The addresses of every host, ready for [`super::ProxyGraph::substitute`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Resolved {
    pub addrs: HashMap<String, IpAddr>,
    /// What the user must be told: some name was unresolvable and the address it had last time
    /// stands in (`ServerAddrs::warning`, `core.net.resolveLastKnown`). Never silent.
    pub warning: Option<Msg>,
}

/// Why the plan failed (no host name in the error: diagnostics stay free of server names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResolveFault {
    #[error("a server name could not be resolved")]
    Failed,
    /// Only block-page addresses came back (unspecified, loopback, link-local, multicast,
    /// broadcast, `0.0.0.0/8`): dialing them would hit a local service.
    #[error("a server name resolved only to a blocked address")]
    Sinkhole,
    /// Every answer was forged (NXDOMAIN with AA, block-page addresses) and no trustworthy
    /// resolver was reachable.
    #[error("the DNS answers for a server name were forged")]
    Poisoned,
    #[error("server name resolution cancelled")]
    Cancelled,
}

impl From<ResolveFault> for AppError {
    fn from(err: ResolveFault) -> Self {
        let key = match err {
            ResolveFault::Cancelled => return AppError::cancelled(),
            ResolveFault::Failed => "engine.xray.resolve.failed",
            ResolveFault::Sinkhole => "engine.xray.resolve.sinkhole",
            ResolveFault::Poisoned => "engine.xray.resolve.poisoned",
        };
        AppError::msg(ErrorKind::Network, Msg::new(key)).with_source(err)
    }
}

/// One resolved host: its address and the warning that came with it.
type Found = (IpAddr, Option<Msg>);

/// An address a server may have. Private and CGNAT answers are fine (LAN / lab servers; Xray
/// exempts private addresses from its TLS rule too), block-page answers are not, also when
/// written as IPv4-mapped IPv6 (Windows dials `::ffff:127.0.0.1` as loopback).
pub(super) fn dialable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => dialable(IpAddr::V4(v4)),
            None => {
                let link_local = v6.segments()[0] & 0xffc0 == 0xfe80;
                !(v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() || link_local)
            }
        },
    }
}

/// A DNS question for `name` (`qtype` A or AAAA, recursion desired) with message id `id`.
pub(super) fn query(name: &str, qtype: u16, id: u16) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    Some(q)
}

/// The `qtype` addresses of an answer to message `id`; `None` for anything that is not that
/// answer (another id, a query, truncated or malformed); empty on NXDOMAIN or no data.
pub(super) fn parse_answer(msg: &[u8], id: u16, qtype: u16) -> Option<Vec<IpAddr>> {
    let u16_at = |at: usize| Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]));
    if u16_at(0)? != id || msg.get(2)? & 0x80 == 0 {
        return None;
    }
    if msg.get(3)? & 0x0f != 0 {
        return Some(Vec::new());
    }
    let (questions, answers) = (u16_at(4)?, u16_at(6)?);
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(msg, at)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..answers {
        at = skip_name(msg, at)?;
        let (rtype, class, len) = (u16_at(at)?, u16_at(at + 2)?, usize::from(u16_at(at + 8)?));
        let data = msg.get(at + 10..at + 10 + len)?;
        at += 10 + len;
        match (rtype, class, data.len()) {
            (QTYPE_A, 1, 4) if qtype == QTYPE_A => {
                out.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?));
            }
            (QTYPE_AAAA, 1, 16) if qtype == QTYPE_AAAA => {
                out.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?));
            }
            _ => {}
        }
    }
    Some(out)
}

/// Past a (possibly compressed) name starting at `at`.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        match len {
            0 => return Some(at + 1),
            l if l & 0xc0 == 0xc0 => return Some(at + 2),
            l if l & 0xc0 == 0 => at += 1 + usize::from(l),
            _ => return None,
        }
    }
}

/// Resolves every host to its first dialable address (IPv4 first). Hosts the caller already
/// knows (a fresh server-list address) are left out of `hosts` and merged by the caller.
pub async fn resolve_hosts(
    hosts: &[String],
    path: ResolvePath,
    cancel: &CancellationToken,
) -> Result<Resolved, ResolveFault> {
    match path {
        ResolvePath::Direct => {
            let lookup = |host: String| async move { first(resolve_server(&host, dialable).await) };
            resolve_all(hosts, lookup, cancel).await
        }
        ResolvePath::ViaSingBox(server) => {
            let lookup = move |host: String| async move {
                udp_lookup(server, &host).await.map(|ip| (ip, None))
            };
            resolve_all(hosts, lookup, cancel).await
        }
    }
}

/// The plan over any lookup: literals answered in place, at most [`PARALLEL`] lookups in
/// flight, the first failure (or `cancel`) ends it.
pub(super) async fn resolve_all<F, Fut>(
    hosts: &[String],
    lookup: F,
    cancel: &CancellationToken,
) -> Result<Resolved, ResolveFault>
where
    F: Fn(String) -> Fut,
    Fut: Future<Output = Result<Found, ResolveFault>>,
{
    let lookup = &lookup;
    let lookups = stream::iter(hosts.iter().cloned())
        .map(|host| async move {
            let found = match literal(&host) {
                Some(found) => found?,
                None => lookup(host.clone()).await?,
            };
            Ok::<_, ResolveFault>((host, found))
        })
        .buffer_unordered(PARALLEL)
        // The first failure drops the stream and with it every lookup still in flight.
        .try_fold(
            Resolved::default(),
            |mut acc, (host, (ip, warning))| async move {
                acc.addrs.insert(host, ip);
                acc.warning = acc.warning.or(warning);
                Ok(acc)
            },
        );
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(ResolveFault::Cancelled),
        result = lookups => result,
    }
}

/// An IP literal needs no lookup: dialable, or a sinkhole.
fn literal(host: &str) -> Option<Result<Found, ResolveFault>> {
    let ip = host.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
    Some(if dialable(ip) {
        Ok((ip, None))
    } else {
        Err(ResolveFault::Sinkhole)
    })
}

/// The first address of a `resolve_server` answer, with its last-known warning.
pub(super) fn first(found: Result<ServerAddrs, ResolveError>) -> Result<Found, ResolveFault> {
    match found {
        Ok(found) => {
            let warning = found.warning();
            let ip = found.addrs.first().copied().ok_or(ResolveFault::Failed)?;
            Ok((ip, warning))
        }
        Err(ResolveError::Filtered) => Err(ResolveFault::Sinkhole),
        Err(ResolveError::Poisoned) => Err(ResolveFault::Poisoned),
        Err(ResolveError::InvalidName | ResolveError::NotFound | ResolveError::Failed) => {
            Err(ResolveFault::Failed)
        }
    }
}

/// A, then AAAA, at `server` over UDP, both within one [`LOOKUP_TIMEOUT`].
async fn udp_lookup(server: SocketAddr, host: &str) -> Result<IpAddr, ResolveFault> {
    let attempt = async {
        let mut blocked = false;
        for qtype in [QTYPE_A, QTYPE_AAAA] {
            match exchange(server, host, qtype).await {
                Ok(addrs) => match addrs.iter().copied().find(|ip| dialable(*ip)) {
                    Some(ip) => return Ok(ip),
                    None => blocked |= !addrs.is_empty(),
                },
                Err(err) => tracing::debug!(%err, qtype, "UDP DNS query failed"),
            }
        }
        Err(if blocked {
            ResolveFault::Sinkhole
        } else {
            ResolveFault::Failed
        })
    };
    tokio::time::timeout(LOOKUP_TIMEOUT, attempt)
        .await
        .unwrap_or(Err(ResolveFault::Failed))
}

/// One question and its answer over a connected UDP socket.
async fn exchange(server: SocketAddr, name: &str, qtype: u16) -> io::Result<Vec<IpAddr>> {
    // Only a spoofing defence: the socket is connected to the resolver anyway.
    let id = getrandom::u32().map_or(0x5a5a, |r| r as u16);
    let q = query(name, qtype, id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a DNS name"))?;
    // `dns-bootstrap-in` is a loopback inbound and the socket binds loopback too: a wildcard
    // bind (0.0.0.0 / [::]) would make Windows Firewall ask the user about every build of the
    // app. A loopback socket cannot reach any other resolver, so anything else is a caller bug.
    if !server.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not the loopback bootstrap inbound",
        ));
    }
    let local = match server {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(server).await?;
    sock.send(&q).await?;
    let mut buf = [0u8; 1500];
    loop {
        let n = sock.recv(&mut buf).await?;
        if let Some(addrs) = parse_answer(&buf[..n], id, qtype) {
            return Ok(addrs);
        }
    }
}
