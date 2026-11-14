use std::collections::HashMap;
use std::net::IpAddr;

use parking_lot::Mutex;

use super::chain::{Transport, Upstream};
use super::*;
use crate::net::is_public_ip;

/// What a fake upstream does with every question.
#[derive(Debug, Clone)]
pub(super) enum Act {
    /// Replies with this rcode, AA flag and the addresses of the asked family.
    Answer {
        rcode: u8,
        aa: bool,
        addrs: Vec<IpAddr>,
    },
    /// Transport failure (refused, reset, TLS or HTTP error).
    Fail,
    /// Never replies (a blackholed endpoint).
    Hang,
    /// Answers A with these addresses and never answers AAAA (seen on a VPN client's DNS
    /// interception of TCP/53).
    DropsAaaa(Vec<IpAddr>),
    /// Replies to some other question (wrong id).
    Stray,
}

/// The fake transport: upstreams by name, each with its act, and the order they were asked.
pub(super) struct Fake {
    acts: HashMap<Upstream, Act>,
    asked: Mutex<Vec<Upstream>>,
}

impl Fake {
    pub(super) fn new(acts: &[(&'static str, Act)]) -> Fake {
        let acts = acts
            .iter()
            .map(|(name, act)| (up(name), act.clone()))
            .collect();
        Fake {
            acts,
            asked: Mutex::default(),
        }
    }

    /// Upstreams in the order of their first question.
    pub(super) fn asked(&self) -> Vec<Upstream> {
        let mut order: Vec<Upstream> = Vec::new();
        for upstream in self.asked.lock().iter() {
            if !order.contains(upstream) {
                order.push(*upstream);
            }
        }
        order
    }
}

impl Transport for Fake {
    async fn exchange(&self, upstream: Upstream, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.asked.lock().push(upstream);
        let act = self.acts.get(&upstream).cloned();
        match act.ok_or_else(|| anyhow::anyhow!("unknown fake upstream"))? {
            Act::Answer { rcode, aa, addrs } => Ok(answer(query, rcode, aa, &addrs)),
            Act::Fail => anyhow::bail!("fake transport failure"),
            Act::Hang => std::future::pending().await,
            Act::DropsAaaa(addrs) => match query[query.len() - 3] {
                28 => std::future::pending().await,
                _ => Ok(answer(query, wire::NOERROR, false, &addrs)),
            },
            Act::Stray => {
                let mut reply = answer(query, 0, false, &addrs_of(&["203.0.113.66"]));
                reply[0] ^= 0xff;
                Ok(reply)
            }
        }
    }
}

/// A fake upstream address (never dialled: only the fake transport sees it).
pub(super) fn up(name: &'static str) -> Upstream {
    Upstream::Doh(name)
}

pub(super) fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

pub(super) fn addrs_of(list: &[&str]) -> Vec<IpAddr> {
    list.iter().map(|s| ip(s)).collect()
}

/// A NOERROR answer with these addresses (each question gets the ones of its family).
pub(super) fn answers(list: &[&str]) -> Act {
    Act::Answer {
        rcode: wire::NOERROR,
        aa: false,
        addrs: addrs_of(list),
    }
}

/// The reply a resolver would send to `query`: same id and question, QR + RA, `rcode`, the
/// AA flag, and one compressed A / AAAA record per address of the asked family.
pub(super) fn answer(query: &[u8], rcode: u8, aa: bool, addrs: &[IpAddr]) -> Vec<u8> {
    let qtype = u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
    let fits = |ip: &&IpAddr| (qtype == 1) == ip.is_ipv4();
    let records: Vec<&IpAddr> = addrs.iter().filter(fits).collect();
    let mut reply = query[..2].to_vec();
    reply.push(0x81 | if aa { 0x04 } else { 0 });
    reply.push(0x80 | rcode);
    reply.extend_from_slice(&[0, 1]);
    reply.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    reply.extend_from_slice(&[0, 0, 0, 0]);
    reply.extend_from_slice(&query[12..]);
    for ip in records {
        let data = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&qtype.to_be_bytes());
        reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        reply.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        reply.extend_from_slice(&data);
    }
    reply
}

fn any(_: IpAddr) -> bool {
    true
}

#[tokio::test]
async fn literals_and_invalid_names() {
    let found = resolve_host("1.1.1.1", How::Doh, is_public_ip).await;
    assert_eq!(found, Ok(vec![ip("1.1.1.1")]));
    let found = resolve_host(" [2001:db8::1] ", How::System, any).await;
    assert_eq!(found, Ok(vec![ip("2001:db8::1")]));
    let found = resolve_host("127.0.0.1", How::System, is_public_ip).await;
    assert_eq!(found, Err(ResolveError::Filtered));
    for bad in ["", "a b", "8.8.8.8 & calc", "999.1.1.1", "host:443"] {
        let found = resolve_host(bad, How::Doh, any).await;
        assert_eq!(found, Err(ResolveError::InvalidName), "{bad:?}");
        let found = resolve_server(bad, any).await;
        assert_eq!(found, Err(ResolveError::InvalidName), "{bad:?}");
    }
    // A server given by address needs no DNS and is never a "last known" answer.
    let found = resolve_server("203.0.113.5", any).await;
    assert_eq!(
        found,
        Ok(ServerAddrs {
            addrs: vec![ip("203.0.113.5")],
            last_known: false
        })
    );
    assert_eq!(found.unwrap().warning(), None);
    let found = resolve_server("[::1]", is_public_ip).await;
    assert_eq!(found, Err(ResolveError::Filtered));
}

/// The OS resolver answers `localhost` from its built-in table (no network involved).
#[tokio::test]
async fn system_resolves_localhost() {
    let found = resolve_host("localhost", How::System, any).await.unwrap();
    assert!(found.iter().all(|ip| ip.is_loopback()), "{found:?}");
    if found.len() > 1 {
        assert!(found[0].is_ipv4(), "IPv4 first: {found:?}");
    }
    let found = resolve_host("LocalHost", How::System, is_public_ip).await;
    assert_eq!(found, Err(ResolveError::Filtered));
}

#[test]
fn ordering_and_error_mapping() {
    let addrs = addrs_of(&["2001:4860::1", "8.8.8.8", "2001:4860::1", "1.1.1.1"]);
    let ordered = filtered(addrs, &any).unwrap();
    assert_eq!(ordered, addrs_of(&["8.8.8.8", "1.1.1.1", "2001:4860::1"]));
    assert_eq!(filtered(Vec::new(), &any), Err(ResolveError::NotFound));
    for (code, expected) in [
        (11001, ResolveError::NotFound),
        (11004, ResolveError::NotFound),
        (10060, ResolveError::Failed),
    ] {
        assert_eq!(lookup_error(&io::Error::from_raw_os_error(code)), expected);
    }
    let err = AppError::from(ResolveError::InvalidName);
    assert_eq!(err.kind, ErrorKind::Validation);
    for (err, key) in [
        (ResolveError::Filtered, "core.net.resolveFiltered"),
        (ResolveError::Poisoned, "core.net.resolvePoisoned"),
        (ResolveError::Failed, "core.net.resolveFailed"),
    ] {
        let err = AppError::from(err);
        assert_eq!(
            (err.kind, err.user_msg().key),
            (ErrorKind::Network, key.into())
        );
    }
}

/// Every production upstream on its own (IP-literal TLS, HTTP/2 for Quad9, TCP framing), then
/// the whole chain and the server path. Run by hand (set `VPNTE_RESOLVER_AUDIT=1` to also
/// require every single upstream to answer from this network):
/// `cargo test -p vpnte-core -- --ignored live_resolvers --nocapture`.
#[tokio::test]
#[ignore = "needs internet access"]
async fn live_resolvers() {
    let mut dead = Vec::new();
    for upstream in chain::UPSTREAMS {
        let one = Chain::new(vec![upstream], Net::new(), STAGGER, UPSTREAM_LIMIT);
        let found = one.resolve("example.com", &is_public_ip).await;
        println!("{upstream:?}: {found:?}");
        if found.is_err() {
            dead.push(upstream);
        }
    }
    let found = resolve_host("example.com", How::Doh, is_public_ip).await;
    assert!(found.is_ok(), "{found:?}");
    let found = resolve_server("example.com", is_public_ip).await;
    assert!(found.as_ref().is_ok_and(|s| !s.last_known), "{found:?}");
    // Every single upstream answering is a fact about this network, not about the code: the CI
    // runner (abroad) once could not reach Yandex DoH while the chain resolved fine. Audit the
    // upstreams one by one only when asked.
    if std::env::var_os("VPNTE_RESOLVER_AUDIT").is_some() {
        assert!(dead.is_empty(), "unreachable from here: {dead:?}");
    }
}

/// Lab F11 (p-follow3): a server name kept for the running session is answered from the kept
/// addresses by every lookup (the OS resolver's too) without leaving the PC, the caller's filter
/// still applied; the session's end forgets it.
#[tokio::test]
async fn a_kept_session_name_never_leaves_the_pc() {
    let ip: IpAddr = "203.0.113.7".parse().expect("ip");
    let name = "vpn.p-follow3.invalid";
    session::keep_for_test(1_000, name, vec![ip]);
    assert!(session::running());
    assert_eq!(
        resolve_host(name, How::System, |_| true).await,
        Ok(vec![ip])
    );
    let server = resolve_server(name, |_| true).await.expect("kept");
    assert_eq!((server.addrs, server.last_known), (vec![ip], false));
    let refused = resolve_host(name, How::Doh, |_| false).await;
    assert_eq!(refused, Err(ResolveError::Filtered));
    // A new session start forgets the names of the one before.
    session::keep_for_test(2_000, "other.p-follow3.invalid", vec![ip]);
    assert_eq!(session::kept(name), None);
    end_session();
    assert!(!session::running());
    assert_eq!(session::kept("other.p-follow3.invalid"), None);
}
