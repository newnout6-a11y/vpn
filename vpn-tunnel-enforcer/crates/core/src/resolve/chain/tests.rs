use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::*;
use crate::net::is_public_ip;
use crate::resolve::tests::{Act, Fake, addrs_of, answers, up};
use crate::resolve::wire::{NOERROR, NXDOMAIN};

const STAGGER: Duration = Duration::from_millis(40);
const LIMIT: Duration = Duration::from_secs(5);

fn chain(acts: &[(&'static str, Act)]) -> Chain<Fake> {
    let order = acts.iter().map(|(name, _)| up(name)).collect();
    Chain::new(order, Fake::new(acts), STAGGER, LIMIT)
}

fn any(_: IpAddr) -> bool {
    true
}

fn nxdomain(aa: bool) -> Act {
    Act::Answer {
        rcode: NXDOMAIN,
        aa,
        addrs: Vec::new(),
    }
}

fn asked(c: &Chain<Fake>) -> Vec<Upstream> {
    c.transport.asked()
}

/// In order: a failing upstream hands over at once, the first usable answer wins and later
/// upstreams are never asked; the winner is asked first next time.
#[tokio::test]
async fn order_and_remembered_winner() {
    let c = chain(&[
        ("a", Act::Fail),
        ("b", answers(&["203.0.113.7", "2001:db8::7"])),
        ("c", answers(&["198.51.100.1"])),
    ]);
    let found = c.resolve("example.com", &any).await;
    assert_eq!(found, Ok(addrs_of(&["203.0.113.7", "2001:db8::7"])));
    assert_eq!(asked(&c), [up("a"), up("b")]);
    assert_eq!(c.last_good.load(Ordering::Relaxed), 1);
    let again = c.resolve("example.org", &any).await;
    assert_eq!(again, Ok(addrs_of(&["203.0.113.7", "2001:db8::7"])));
    assert_eq!(
        asked(&c),
        [up("a"), up("b")],
        "b went first, a was not asked again"
    );
}

/// A blackholed upstream costs its head start, not its timeout.
#[tokio::test]
async fn hanging_upstream_costs_only_the_head_start() {
    let c = chain(&[("a", Act::Hang), ("b", answers(&["203.0.113.8"]))]);
    let started = Instant::now();
    let found = c.resolve("example.com", &any).await;
    assert_eq!(found, Ok(addrs_of(&["203.0.113.8"])));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(c.last_good.load(Ordering::Relaxed), 1);
}

/// The per-upstream budget ends a hang: an honest failure, not a wait forever.
#[tokio::test]
async fn upstream_budget_ends_a_hang() {
    let fake = Fake::new(&[("a", Act::Hang)]);
    let c = Chain::new(vec![up("a")], fake, STAGGER, Duration::from_millis(100));
    let found = tokio::time::timeout(Duration::from_secs(3), c.resolve("example.com", &any)).await;
    assert_eq!(found, Ok(Err(ResolveError::Failed)));
}

/// An upstream that drops AAAA keeps its A answer and costs only the grace, not its budget.
#[tokio::test]
async fn dropped_aaaa_costs_only_the_grace() {
    let c = chain(&[("a", Act::DropsAaaa(addrs_of(&["203.0.113.11"])))]);
    let started = Instant::now();
    let found = c.resolve("example.com", &any).await;
    assert_eq!(found, Ok(addrs_of(&["203.0.113.11"])));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

/// NXDOMAIN with AA (the NSDI redirect) and block-page-only answers are failures that move on.
#[tokio::test]
async fn poisoned_answers_move_on() {
    let c = chain(&[
        ("nsdi", nxdomain(true)),
        ("stub", answers(&["127.0.0.1", "::"])),
        ("zero", answers(&["0.0.0.0"])),
        ("real", answers(&["203.0.113.9"])),
    ]);
    let found = c.resolve("blocked.example", &any).await;
    assert_eq!(found, Ok(addrs_of(&["203.0.113.9"])));
    assert_eq!(asked(&c), [up("nsdi"), up("stub"), up("zero"), up("real")]);
}

/// Nothing but forged answers: an honest `Poisoned`, never an empty success.
#[tokio::test]
async fn only_forged_answers_are_reported() {
    let c = chain(&[("nsdi", nxdomain(true)), ("stub", answers(&["224.0.0.1"]))]);
    assert_eq!(
        c.resolve("x.example", &any).await,
        Err(ResolveError::Poisoned)
    );
}

/// Block-page addresses are dropped next to real ones; private and CGNAT answers stay.
#[tokio::test]
async fn real_addresses_survive_next_to_block_pages() {
    let c = chain(&[(
        "a",
        answers(&[
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "fe80::1",
            "2001:db8::2",
            "10.1.2.3",
        ]),
    )]);
    let found = c.resolve("lab.example", &any).await;
    assert_eq!(
        found,
        Ok(addrs_of(&["10.1.2.3", "100.64.0.1", "2001:db8::2"]))
    );
}

/// The final error says the most: refused by the caller, then "does not exist", then forged,
/// then failed. A NOERROR answer without addresses is "does not exist", never `Ok(vec![])`.
#[tokio::test]
async fn final_error_precedence() {
    let empty = Act::Answer {
        rcode: NOERROR,
        aa: false,
        addrs: Vec::new(),
    };
    let servfail = Act::Answer {
        rcode: 2,
        aa: false,
        addrs: addrs_of(&["203.0.113.1"]),
    };
    let cases: [(&[(&'static str, Act)], ResolveError); 6] = [
        (
            &[("a", nxdomain(true)), ("b", nxdomain(false))],
            ResolveError::NotFound,
        ),
        (
            &[("a", empty.clone()), ("b", Act::Fail)],
            ResolveError::NotFound,
        ),
        (
            &[("a", answers(&["10.0.0.1"])), ("b", nxdomain(true))],
            ResolveError::Filtered,
        ),
        (
            &[("a", Act::Fail), ("b", nxdomain(true))],
            ResolveError::Poisoned,
        ),
        (
            &[("a", Act::Fail), ("b", Act::Stray), ("c", servfail)],
            ResolveError::Failed,
        ),
        (&[], ResolveError::Failed),
    ];
    for (acts, expected) in cases {
        let c = chain(acts);
        assert_eq!(
            c.resolve("x.example", &is_public_ip).await,
            Err(expected),
            "{acts:?}"
        );
    }
}

#[test]
fn block_pages() {
    for s in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.53",
        "169.254.1.1",
        "224.0.0.1",
        "240.0.0.1",
    ] {
        assert!(block_page(s.parse().unwrap()), "{s}");
    }
    for s in [
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(block_page(s.parse().unwrap()), "{s}");
    }
    for s in [
        "10.0.0.1",
        "100.64.0.1",
        "192.168.1.1",
        "203.0.113.1",
        "2001:db8::1",
        "fd00::1",
    ] {
        assert!(!block_page(s.parse().unwrap()), "{s}");
    }
}

/// speed3 S3-09 (c): an address to dial takes the A answer at once; AAAA gets no grace after it
/// (a plain lookup still waits its 300 ms for the second family).
#[tokio::test(start_paused = true)]
async fn a_dial_does_not_wait_for_aaaa_after_a() {
    let c = chain(&[("a", Act::DropsAaaa(addrs_of(&["203.0.113.12"])))]);
    let started = tokio::time::Instant::now();
    let found = c.resolve_dial("example.com", &any).await;
    assert_eq!(found, Ok(addrs_of(&["203.0.113.12"])));
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "{:?}",
        started.elapsed()
    );
    let started = tokio::time::Instant::now();
    c.resolve("example.com", &any).await.unwrap();
    assert!(started.elapsed() >= GRACE, "{:?}", started.elapsed());
}

/// S3-09 (b) (security review): the lookups before the click take the four foreign IP-literal
/// DoH resolvers only: no DoH by name (Yandex, Cloudflare) and no TCP/53.
#[test]
fn the_lookup_ahead_takes_only_ip_literal_doh() {
    let foreign: Vec<Upstream> = UPSTREAMS.into_iter().filter(ip_literal_doh).collect();
    assert_eq!(foreign, UPSTREAMS[..4].to_vec());
    assert!(!foreign.contains(&YANDEX_DOH) && !foreign.contains(&CLOUDFLARE_DOH));
}
