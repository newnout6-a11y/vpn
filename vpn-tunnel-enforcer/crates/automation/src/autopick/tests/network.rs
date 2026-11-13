//! The network-aware order and the whitelist evidence (RU re-check item 23, p-net-aware): what
//! the reactions' network memory knows decides the order, and a server that carries data on a
//! whitelist network is handed to the list as evidence, once per network.
use vpnte_base::types::AdaptiveMode;

use super::*;
use crate::adaptive::reaction::Verdicts;
use crate::coordinator::{LifecycleEvent, SessionKind};

fn ids<'a>(ranked: &[&'a Candidate]) -> Vec<&'a str> {
    ranked.iter().map(|c| c.id.as_str()).collect()
}

fn net(udp_blocked: bool, whitelist: bool, tag: Option<&str>, avoided: &[&str]) -> Network {
    Network {
        udp_blocked,
        whitelist,
        tag: tag.map(str::to_owned),
        avoided: avoided.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// UDP cut: TCP-based servers first whatever a check said; a server ruled out here goes last.
#[test]
fn udp_cut_puts_tcp_first_and_ruled_out_last() {
    let mut hy2 = server("hy2", "g");
    (hy2.udp, hy2.alive, hy2.latency_ms) = (true, Some(true), Some(20));
    let mut reality = server("reality", "g");
    (reality.alive, reality.latency_ms) = (Some(true), Some(90));
    let mut banned = server("banned", "g");
    (banned.alive, banned.latency_ms) = (Some(true), Some(10));
    let ws = server("ws", "g");
    let all = [hy2, reality, banned, ws];
    let plain = rank(&all, &Network::default(), |_| false);
    assert_eq!(ids(&plain), ["banned", "hy2", "reality", "ws"]);
    let cut = rank(&all, &net(true, false, None, &["banned"]), |_| false);
    assert_eq!(ids(&cut), ["reality", "ws", "hy2", "banned"]);
}

/// A mobile whitelist: proof from this network, then the user's mark or proof from elsewhere,
/// then a Russian entry, the rest last; inside each step the usual evidence and latency.
#[test]
fn a_whitelist_puts_proven_then_marked_then_russian_entries_first() {
    let mut foreign = server("foreign", "g");
    (foreign.alive, foreign.latency_ms) = (Some(true), Some(15));
    let mut ru = server("ru", "g");
    ru.ru_entry = true;
    let mut marked = server("marked", "g");
    marked.whitelist.marked = true;
    let mut elsewhere = server("elsewhere", "g");
    elsewhere.whitelist.worked_on = vec![Some("other".into())];
    (elsewhere.alive, elsewhere.latency_ms) = (Some(true), Some(40));
    let mut here = server("here", "g");
    here.whitelist.worked_on = vec![None, Some("mts".into())];
    let all = [foreign, ru, marked, elsewhere, here];
    let order = rank(&all, &net(false, true, Some("mts"), &[]), |_| false);
    assert_eq!(
        ids(&order),
        ["here", "elsewhere", "marked", "ru", "foreign"]
    );
    // An unknown network: no proof is «here».
    let order = rank(&all, &net(false, true, None, &[]), |_| false);
    assert_eq!(
        ids(&order),
        ["elsewhere", "marked", "here", "ru", "foreign"]
    );
    // Ruled out on this network: last even with proof.
    let order = rank(&all, &net(false, true, Some("mts"), &["here"]), |_| false);
    assert_eq!(
        ids(&order),
        ["elsewhere", "marked", "ru", "foreign", "here"]
    );
}

/// Back on a network where a server passed the whitelist, before the network check ran again:
/// that server goes first, everything else keeps the plain order.
#[test]
fn proof_from_this_network_counts_before_its_check() {
    let mut fast = server("fast", "g");
    (fast.alive, fast.latency_ms) = (Some(true), Some(10));
    let mut marked = server("marked", "g");
    marked.whitelist.marked = true;
    let mut proven = server("proven", "g");
    proven.whitelist.worked_on = vec![Some("beeline".into())];
    let all = [fast, marked, proven];
    let order = rank(&all, &net(false, false, Some("beeline"), &[]), |_| false);
    assert_eq!(ids(&order), ["proven", "fast", "marked"]);
    let order = rank(&all, &net(false, false, Some("home"), &[]), |_| false);
    assert_eq!(ids(&order), ["fast", "marked", "proven"]);
}

/// The memory reaches the rank: the tag is read only when a server has proof from a known
/// network, and once per network session.
#[tokio::test(start_paused = true)]
async fn the_network_comes_from_the_memory() {
    let verdicts = Arc::new(Verdicts::scripted(true, &["b"]));
    verdicts.network_whitelist(true);
    let rig = rig_with(vec![server("a", "g"), server("b", "g")], Some(verdicts));
    *rig.host.tag.lock() = Some("mts".into());
    let servers = rig.host.servers();
    let seen = rig.pick.network(&servers).await;
    assert_eq!(seen, net(true, true, None, &["b"]));
    assert_eq!(*rig.host.tag_reads.lock(), 0, "nothing needs the tag");
    let mut proven = servers.clone();
    proven[0].whitelist.worked_on = vec![Some("mts".into())];
    for _ in 0..2 {
        assert_eq!(rig.pick.network(&proven).await.tag.as_deref(), Some("mts"));
    }
    assert_eq!(*rig.host.tag_reads.lock(), 1);
    rig.pick.forget_network();
    rig.pick.network(&proven).await;
    assert_eq!(*rig.host.tag_reads.lock(), 2, "a new network is read again");
    // Without the memory: the plain order, nothing read.
    let plain = rig_with(vec![server("a", "g")], None);
    assert_eq!(plain.pick.network(&proven).await, Network::default());
}

/// A session start on the server list, the watch running.
fn running(rig: &Rig, id: &str) -> CancellationToken {
    rig.coord
        .start(SessionKind::SoftDirect, Some(id), AdaptiveMode::Baseline);
    let cancel = CancellationToken::new();
    let (pick, c) = (rig.pick.clone(), cancel.clone());
    tokio::spawn(async move { pick.run(c).await });
    cancel
}

/// Five-second samples whose download grows by `step` bytes each, for `secs` seconds.
async fn flowing(host: &FakeHost, down: &mut u64, step: u64, secs: u64) {
    for _ in 0..secs / 5 {
        *down += step;
        *host.counters.lock() = Some(Counters {
            up: *down / 10,
            down: *down,
            proxy_down: false,
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// p-net-aware: 64 KiB received through the server while the network is in whitelist mode is
/// evidence, counted from the first sample in that mode (not the session's earlier traffic), and
/// handed to the list once per network; nothing outside whitelist mode.
#[tokio::test(start_paused = true)]
async fn traffic_on_a_whitelist_network_is_evidence() {
    let verdicts = Arc::new(Verdicts::new());
    let rig = rig_with(vec![server("a", "g")], Some(verdicts.clone()));
    *rig.host.tag.lock() = Some("mts".into());
    let cancel = running(&rig, "a");
    let mut down = 0;
    flowing(&rig.host, &mut down, 200 * 1024, 20).await;
    assert!(
        rig.host.whitelist_proofs.lock().is_empty(),
        "no whitelist yet"
    );
    verdicts.network_whitelist(true);
    flowing(&rig.host, &mut down, 20 * 1024, 15).await;
    assert!(
        rig.host.whitelist_proofs.lock().is_empty(),
        "the earlier megabyte does not count"
    );
    flowing(&rig.host, &mut down, 20 * 1024, 15).await;
    let want = [("a".to_owned(), Some("mts".to_owned()))];
    assert_eq!(*rig.host.whitelist_proofs.lock(), want);
    flowing(&rig.host, &mut down, 200 * 1024, 30).await;
    assert_eq!(
        rig.host.whitelist_proofs.lock().len(),
        1,
        "once per network"
    );
    // A new network starts over (the identity already reads the new one): its own proof.
    *rig.host.tag.lock() = Some("beeline".into());
    rig.coord.emit(LifecycleEvent::NetworkChanged);
    flowing(&rig.host, &mut down, 40 * 1024, 30).await;
    let proofs = rig.host.whitelist_proofs.lock().clone();
    assert_eq!(
        proofs.last(),
        Some(&("a".to_owned(), Some("beeline".to_owned())))
    );
    cancel.cancel();
}
