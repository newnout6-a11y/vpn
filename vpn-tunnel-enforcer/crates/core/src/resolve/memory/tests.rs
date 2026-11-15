use std::net::IpAddr;

use super::*;
use crate::resolve::chain::{CLOUDFLARE_DOH, YANDEX_DOH};
use crate::resolve::server::LastKnown;

const DAY: UnixMs = 24 * 60 * 60 * 1000;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn name(n: &str, at: UnixMs) -> NameEntry {
    NameEntry {
        name: n.into(),
        addrs: vec![ip("203.0.113.7")],
        at,
    }
}

fn winner(network: &str, at: UnixMs) -> Winner {
    Winner {
        network: network.into(),
        upstream: YANDEX_DOH.key(),
        at,
    }
}

/// RU audit item 10: a week-old address is dropped (server IPs rotate within days), empty
/// entries never survive, and only the newest 32 networks keep their winner.
#[test]
fn pruning_keeps_a_week() {
    let now = 100 * DAY;
    let mut winners: Vec<Winner> = (0..40)
        .map(|n| winner(&format!("net{n}"), now - n))
        .collect();
    winners.push(winner("old", now - 8 * DAY));
    let learned = Learned {
        names: vec![
            name("fresh.example", now - 6 * DAY),
            name("stale.example", now - 8 * DAY),
            NameEntry {
                addrs: Vec::new(),
                ..name("empty.example", now)
            },
        ],
        winners,
    }
    .pruned(now);
    let names: Vec<&str> = learned.names.iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["fresh.example"]);
    assert_eq!(learned.winners.len(), NETWORKS);
    assert_eq!(learned.winners[0].network, "net0", "newest first");
    assert!(learned.winners.iter().all(|w| w.network != "old"));
}

/// The sealed document reads back what was written; a locked or foreign seal reads as empty.
#[test]
fn sealed_document_round_trip() {
    let root = std::env::temp_dir().join(format!("vpnte-resolver-memory-{}", fastrand::u64(..)));
    let learned = Learned {
        names: vec![name("vpn.example", now_ms())],
        winners: vec![winner("home", now_ms())],
    };
    {
        let store = Store::<ResolverMemoryDoc>::open(&root);
        let sealed = Secret::from_json(&learned).unwrap();
        store.update(|doc| doc.sealed = Some(sealed)).unwrap();
        let text = std::fs::read_to_string(store.path()).unwrap();
        assert!(!text.contains("vpn.example"), "never in plaintext: {text}");
    }
    let store = Store::<ResolverMemoryDoc>::open(&root);
    assert_eq!(load(&store), learned);
    store
        .update(|doc| doc.sealed = Some(Secret::from_stored("dpapi:v1:AAAA".into())))
        .unwrap();
    assert_eq!(load(&store), Learned::default());
    let _ = std::fs::remove_dir_all(&root);
}

/// Seeding keeps what this run already learned and the stored order.
#[test]
fn seeding_last_known() {
    let cache = LastKnown::default();
    cache.remember("live.example", &[ip("198.51.100.1")]);
    let now = now_ms();
    cache.seed(vec![
        ("live.example".into(), vec![ip("203.0.113.1")], now - 5),
        ("old.example".into(), vec![ip("203.0.113.2")], now - 7),
    ]);
    let any = |_: IpAddr| true;
    assert_eq!(
        cache.recall("live.example", &any),
        Some(vec![ip("198.51.100.1")])
    );
    assert_eq!(
        cache.recall("old.example", &any),
        Some(vec![ip("203.0.113.2")])
    );
    let order: Vec<String> = cache.entries().into_iter().map(|e| e.0).collect();
    assert_eq!(order, ["live.example", "old.example"]);
}

/// The winner stays with the network it won on: back on that network it is asked first, on
/// an unknown one the production order applies.
#[test]
fn winners_follow_the_network() {
    let (yandex, cloudflare) = (YANDEX_DOH.key(), CLOUDFLARE_DOH.key());
    let mut nets = Networks::default();
    assert_eq!(nets.switch(Some("tethering".into()), 10, None), None);
    let won = (yandex.clone(), 20);
    assert_eq!(nets.switch(Some("home".into()), 30, Some(&won)), None);
    let won = (cloudflare.clone(), 40);
    assert_eq!(
        nets.switch(Some("tethering".into()), 50, Some(&won)),
        Some(yandex.clone())
    );
    assert_eq!(
        nets.switch(Some("home".into()), 60, Some(&won)),
        Some(cloudflare)
    );
    assert_eq!(nets.switch(None, 70, Some(&won)), None);
}

/// Review a3: a win is credited to the network it was won on. A win after the move (the chain
/// answered before the watch noticed) belongs to the new network and is asked first there,
/// instead of being credited to the old one and replaced by the production order.
#[test]
fn a_win_belongs_to_the_network_it_was_won_on() {
    let yandex = YANDEX_DOH.key();
    let mut nets = Networks::default();
    nets.switch(Some("home".into()), 0, None);
    // Tethering from t=100; the chain won with Yandex at t=103, the watch reports it at t=105.
    let won = (yandex.clone(), 103);
    assert_eq!(
        nets.switch(Some("tethering".into()), 100, Some(&won)),
        Some(yandex.clone())
    );
    assert_eq!(nets.winners.get("tethering"), Some(&(yandex.clone(), 103)));
    assert_eq!(nets.winners.get("home"), None, "never won at home");
    // A win before the move stays with the network it was won on.
    let mut nets = Networks::default();
    nets.switch(Some("home".into()), 0, None);
    let won = (yandex.clone(), 50);
    assert_eq!(nets.switch(Some("tethering".into()), 100, Some(&won)), None);
    assert_eq!(nets.winners.get("home"), Some(&(yandex, 50)));
}

/// Review a4: the same winner again changes nothing (no write every 30 s); a new winner or a
/// day-old stamp does.
#[test]
fn an_unchanged_winner_changes_nothing() {
    let yandex = YANDEX_DOH.key();
    let mut nets = Networks::default();
    nets.switch(Some("home".into()), 0, None);
    nets.credit(Some(&(yandex.clone(), 10)), None);
    nets.credit(Some(&(yandex.clone(), 5_000)), None);
    assert_eq!(nets.winners.get("home"), Some(&(yandex.clone(), 10)));
    nets.credit(Some(&(yandex.clone(), 10 + DAY)), None);
    assert_eq!(
        nets.winners.get("home"),
        Some(&(yandex, 10 + DAY)),
        "refreshed"
    );
    nets.credit(Some(&(CLOUDFLARE_DOH.key(), 20 + DAY)), None);
    assert_eq!(
        nets.winners.get("home"),
        Some(&(CLOUDFLARE_DOH.key(), 20 + DAY))
    );
}
