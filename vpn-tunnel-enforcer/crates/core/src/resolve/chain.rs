//! The ordered resolver chain behind `How::Doh` and `resolve_server` (ru-2026 Ф9: DoT is cut,
//! DoH is cut by SNI, plain UDP/53 to public resolvers is redirected to the NSDI, which answers
//! blocked names with NXDOMAIN + AA; TCP/53 is left alone). Upstreams are asked in order; the
//! next one also starts when the previous failed or after a short head start, so a blackholed
//! endpoint costs the head start, not its timeout. The upstream that answered last goes first.
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::time::{Instant, timeout_at};

use super::wire::{self, NOERROR, NXDOMAIN, Record, Reply};
use super::{ResolveError, filtered};
use crate::net;

/// One resolver of the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Upstream {
    /// DNS-over-HTTPS (RFC 8484, POST) at this URL.
    Doh(&'static str),
    /// DNS over TCP (RFC 7766) at this address.
    Tcp(SocketAddr),
}

const fn tcp53(a: u8, b: u8, c: u8, d: u8) -> Upstream {
    Upstream::Tcp(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(a, b, c, d),
        53,
    )))
}

/// Production order. IP-literal DoH first: it needs no DNS of its own and sends no SNI to filter
/// on (each certificate carries the address; Quad9 answers over HTTP/2 only). DoH by name next:
/// other addresses, and Yandex stays reachable from RU networks. TCP/53 last: plaintext, but
/// left alone by the 2026 redirect.
pub(super) const UPSTREAMS: [Upstream; 9] = [
    Upstream::Doh("https://1.1.1.1/dns-query"),
    Upstream::Doh("https://9.9.9.9/dns-query"),
    Upstream::Doh("https://8.8.8.8/dns-query"),
    Upstream::Doh("https://94.140.14.140/dns-query"),
    Upstream::Doh("https://common.dot.dns.yandex.net/dns-query"),
    Upstream::Doh("https://cloudflare-dns.com/dns-query"),
    tcp53(8, 8, 8, 8),
    tcp53(1, 1, 1, 1),
    tcp53(77, 88, 8, 8),
];
/// Head start of an upstream before the next one is asked as well.
pub(super) const STAGGER: Duration = Duration::from_millis(700);
/// Budget of one upstream for both records.
pub(super) const UPSTREAM_LIMIT: Duration = Duration::from_secs(3);
/// How long the second record type may lag once the first one brought addresses.
const GRACE: Duration = Duration::from_millis(300);

/// Sends one wire-format question; the raw reply, or `None` on any transport failure (the
/// transport logs why).
pub(super) trait Transport: Sync {
    fn exchange(
        &self,
        upstream: Upstream,
        query: &[u8],
    ) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// Upstreams in order, the transport that reaches them and the remembered winner.
pub(super) struct Chain<T> {
    upstreams: Vec<Upstream>,
    transport: T,
    stagger: Duration,
    limit: Duration,
    last_good: AtomicUsize,
}

impl<T: Transport> Chain<T> {
    pub(super) fn new(
        upstreams: Vec<Upstream>,
        transport: T,
        stagger: Duration,
        limit: Duration,
    ) -> Self {
        Chain {
            upstreams,
            transport,
            stagger,
            limit,
            last_good: AtomicUsize::new(0),
        }
    }

    /// The first usable answer in chain order: deduplicated, IPv4 first, no block-page address,
    /// only addresses `keep` accepts. Never an empty success; when every upstream misses, the
    /// most telling miss (`Filtered` > `NotFound` > `Poisoned` > `Failed`).
    pub(super) async fn resolve(
        &self,
        name: &str,
        keep: &impl Fn(IpAddr) -> bool,
    ) -> Result<Vec<IpAddr>, ResolveError> {
        let count = self.upstreams.len();
        let first = self
            .last_good
            .load(Ordering::Relaxed)
            .min(count.saturating_sub(1));
        let mut queue = std::iter::once(first)
            .chain((0..count).filter(move |i| *i != first))
            .filter(move |i| *i < count)
            .peekable();
        let mut running = FuturesUnordered::new();
        let mut worst = ResolveError::Failed;
        loop {
            if running.is_empty() {
                let Some(index) = queue.next() else {
                    return Err(worst);
                };
                running.push(self.ask(index, name, keep));
            }
            let more = queue.peek().is_some();
            tokio::select! {
                Some((index, answer)) = running.next() => match answer {
                    Ok(addrs) => {
                        self.last_good.store(index, Ordering::Relaxed);
                        return Ok(addrs);
                    }
                    Err(miss) => {
                        worst = more_telling(worst, miss);
                        if let Some(next) = queue.next() {
                            running.push(self.ask(next, name, keep));
                        }
                    }
                },
                () = tokio::time::sleep(self.stagger), if more => {
                    if let Some(next) = queue.next() {
                        running.push(self.ask(next, name, keep));
                    }
                }
                else => return Err(worst),
            }
        }
    }

    /// A and AAAA from one upstream within the per-upstream budget, judged together.
    async fn ask(
        &self,
        index: usize,
        name: &str,
        keep: &impl Fn(IpAddr) -> bool,
    ) -> (usize, Result<Vec<IpAddr>, ResolveError>) {
        let Some(&upstream) = self.upstreams.get(index) else {
            return (index, Err(ResolveError::Failed));
        };
        let verdict = judge(self.both(upstream, name).await, keep);
        if let Err(miss) = verdict {
            tracing::debug!(?upstream, ?miss, "resolver gave no usable address");
        }
        (index, verdict)
    }

    /// `[A, AAAA]` asked at once. Once one family brought addresses the other gets only a short
    /// grace (RFC 8305 §3): paths that drop AAAA (seen on a VPN client's DNS interception) must
    /// not stall the lookup, nor cost the answer already in hand.
    async fn both(&self, upstream: Upstream, name: &str) -> [Option<Reply>; 2] {
        let deadline = Instant::now() + self.limit;
        let a = self.question(upstream, name, Record::A);
        let aaaa = self.question(upstream, name, Record::Aaaa);
        tokio::pin!(a, aaaa);
        let first = timeout_at(deadline, async {
            tokio::select! {
                reply = &mut a => (true, reply),
                reply = &mut aaaa => (false, reply),
            }
        });
        let Ok((a_first, first)) = first.await else {
            return [None, None];
        };
        let until = match &first {
            Some(reply) if !reply.addrs.is_empty() => deadline.min(Instant::now() + GRACE),
            _ => deadline,
        };
        if a_first {
            [first, timeout_at(until, aaaa).await.ok().flatten()]
        } else {
            [timeout_at(until, a).await.ok().flatten(), first]
        }
    }

    async fn question(&self, upstream: Upstream, name: &str, record: Record) -> Option<Reply> {
        // A fresh id per question: on plaintext TCP/53 the reply must answer this very query.
        let query = wire::query(fastrand::u16(..), name, record)?;
        let raw = self.transport.exchange(upstream, &query).await?;
        let reply = wire::parse(&raw, &query, record);
        if reply.is_none() {
            tracing::debug!(?upstream, "not a DNS reply to our question");
        }
        reply
    }
}

/// The verdict on the two replies of one upstream. Poisoned (NXDOMAIN with AA, or nothing but
/// block-page addresses in a reply) beats everything else of that upstream: its path lies.
fn judge(
    replies: [Option<Reply>; 2],
    keep: &impl Fn(IpAddr) -> bool,
) -> Result<Vec<IpAddr>, ResolveError> {
    let mut addrs = Vec::new();
    let (mut answered, mut poisoned) = (false, false);
    for reply in replies.into_iter().flatten() {
        match reply.rcode {
            NXDOMAIN if reply.authoritative => poisoned = true,
            NXDOMAIN => answered = true,
            NOERROR => {
                answered = true;
                poisoned |= !reply.addrs.is_empty() && reply.addrs.iter().all(|ip| block_page(*ip));
                addrs.extend(reply.addrs.into_iter().filter(|ip| !block_page(*ip)));
            }
            _ => {}
        }
    }
    if poisoned {
        return Err(ResolveError::Poisoned);
    }
    match filtered(addrs, keep) {
        Err(ResolveError::NotFound) if !answered => Err(ResolveError::Failed),
        verdict => verdict,
    }
}

/// The miss the final error reports: an answer the caller refused, then a name that does not
/// exist, then forged answers, then plain failure.
fn more_telling(a: ResolveError, b: ResolveError) -> ResolveError {
    let rank = |e: ResolveError| match e {
        ResolveError::Failed => 0,
        ResolveError::Poisoned => 1,
        ResolveError::NotFound => 2,
        ResolveError::Filtered => 3,
        ResolveError::InvalidName => 4,
    };
    if rank(b) > rank(a) { b } else { a }
}

/// Addresses resolvers hand out instead of the real one (ISP block pages, sinkholes): never a
/// server. Private and CGNAT answers stay possible (LAN and lab servers).
pub(super) fn block_page(ip: IpAddr) -> bool {
    match net::unmap(ip) {
        IpAddr::V4(v4) => {
            let first = v4.octets()[0];
            // 0/8, loopback, multicast and class E (with broadcast).
            first == 0 || first == 127 || first >= 224 || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
        }
    }
}

#[cfg(test)]
mod tests;
