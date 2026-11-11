use std::net::IpAddr;
use std::time::Duration;

use super::*;
use crate::net::is_public_ip;
use crate::resolve::tests::{Act, Fake, addrs_of, answers, ip, up};
use crate::resolve::wire::NXDOMAIN;

fn chain(act: Act) -> Chain<Fake> {
    Chain::new(
        vec![up("a")],
        Fake::new(&[("a", act)]),
        Duration::from_millis(40),
        Duration::from_secs(5),
    )
}

fn any(_: IpAddr) -> bool {
    true
}

async fn os(answer: Result<Vec<IpAddr>, ResolveError>) -> Result<Vec<IpAddr>, ResolveError> {
    answer
}

fn never_asked() -> std::future::Ready<Result<Vec<IpAddr>, ResolveError>> {
    panic!("the OS resolver must not be asked when the chain answered")
}

/// A live answer is remembered; when DNS later fails (chain and OS resolver), the remembered
/// addresses bridge it, flagged `last_known` with a warning for the user.
#[tokio::test]
async fn last_known_bridges_a_failing_dns() {
    let cache = LastKnown::default();
    let good = chain(answers(&["203.0.113.10", "2001:db8::10"]));
    let found = server("vpn.example", &any, &good, &cache, never_asked)
        .await
        .unwrap();
    assert_eq!(
        found,
        ServerAddrs {
            addrs: addrs_of(&["203.0.113.10", "2001:db8::10"]),
            last_known: false
        }
    );
    assert_eq!(found.warning(), None);

    let dead = chain(Act::Fail);
    let found = server("vpn.example", &any, &dead, &cache, || {
        os(Err(ResolveError::Failed))
    })
    .await
    .unwrap();
    assert_eq!(
        found,
        ServerAddrs {
            addrs: addrs_of(&["203.0.113.10", "2001:db8::10"]),
            last_known: true
        }
    );
    assert_eq!(
        found.warning().map(|m| m.key),
        Some("core.net.resolveLastKnown".into())
    );

    // Poisoned DNS (NXDOMAIN + AA) is bridged the same way; an unknown name is not.
    let forged = chain(Act::Answer {
        rcode: NXDOMAIN,
        aa: true,
        addrs: Vec::new(),
    });
    let found = server("vpn.example", &any, &forged, &cache, || {
        os(Err(ResolveError::NotFound))
    })
    .await;
    assert!(found.is_ok_and(|s| s.last_known));
    let found = server("other.example", &any, &forged, &cache, || {
        os(Err(ResolveError::NotFound))
    })
    .await;
    assert_eq!(
        found,
        Err(ResolveError::Poisoned),
        "the chain's verdict beats the OS NotFound"
    );
}

/// The OS resolver steps in when every public resolver is cut off; its answer is remembered.
/// A block-page-only OS answer is poisoning, never a server.
#[tokio::test]
async fn os_resolver_after_the_chain() {
    let cache = LastKnown::default();
    let dead = chain(Act::Fail);
    let found = server("isp.example", &any, &dead, &cache, || {
        os(Ok(addrs_of(&["127.0.0.1", "198.51.100.4"])))
    })
    .await;
    assert_eq!(
        found,
        Ok(ServerAddrs {
            addrs: addrs_of(&["198.51.100.4"]),
            last_known: false
        })
    );
    assert_eq!(
        cache.recall("isp.example", &any),
        Some(addrs_of(&["198.51.100.4"]))
    );

    let found = server("stub.example", &any, &dead, &cache, || {
        os(Ok(addrs_of(&["0.0.0.0"])))
    })
    .await;
    assert_eq!(found, Err(ResolveError::Poisoned));
    let found = server("gone.example", &any, &dead, &cache, || {
        os(Err(ResolveError::NotFound))
    })
    .await;
    assert_eq!(found, Err(ResolveError::NotFound));
}

/// An answer the caller refuses is a real answer, not a DNS failure: no bridge. Recalled
/// addresses still pass the caller's own filter.
#[tokio::test]
async fn refused_answers_are_not_bridged() {
    let cache = LastKnown::default();
    cache.remember("lan.example", &[ip("10.0.0.5")]);
    cache.remember("mixed.example", &[ip("10.0.0.6"), ip("93.184.215.14")]);
    let private = chain(answers(&["10.0.0.5"]));
    let found = server("lan.example", &is_public_ip, &private, &cache, || {
        os(Ok(addrs_of(&["10.0.0.5"])))
    })
    .await;
    assert_eq!(found, Err(ResolveError::Filtered));
    let dead = chain(Act::Fail);
    let found = server("lan.example", &is_public_ip, &dead, &cache, || {
        os(Err(ResolveError::Failed))
    })
    .await;
    assert_eq!(found, Err(ResolveError::Failed));
    let found = server("mixed.example", &is_public_ip, &dead, &cache, || {
        os(Err(ResolveError::Failed))
    })
    .await;
    assert_eq!(
        found,
        Ok(ServerAddrs {
            addrs: addrs_of(&["93.184.215.14"]),
            last_known: true
        })
    );
}

#[test]
fn capacity_forgets_the_oldest() {
    let cache = LastKnown::default();
    for n in 0..CAPACITY {
        cache.remember(&format!("s{n}.example"), &[ip("203.0.113.1")]);
    }
    cache.remember("s0.example", &[ip("203.0.113.2")]);
    cache.remember("new.example", &[ip("203.0.113.3")]);
    assert_eq!(cache.names.lock().len(), CAPACITY);
    assert_eq!(cache.recall("s1.example", &any), None, "the oldest went");
    assert_eq!(
        cache.recall("s0.example", &any),
        Some(vec![ip("203.0.113.2")]),
        "refreshed"
    );
    assert_eq!(
        cache.recall("new.example", &any),
        Some(vec![ip("203.0.113.3")])
    );
}
