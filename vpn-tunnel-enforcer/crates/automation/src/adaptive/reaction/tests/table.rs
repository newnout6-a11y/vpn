//! The decision table: verdict × running server × network memory → reaction.
use super::*;
use crate::adaptive::reaction::decide::{
    Allowed, Cause, Decision, MAX_RESTARTS, candidates, decide, next_fingerprint, site,
};
use crate::adaptive::reaction::memory::{Attempt, Memory};

const ON: Allowed = Allowed {
    fingerprint: true,
    switch: true,
};

/// `a` runs; the others share its address, its /24, or neither.
fn pool() -> Vec<ServerFacts> {
    let mut c = srv("c", "203.0.113.5", Transport::Tcp);
    c.latency_ms = Some(40);
    let mut x = srv("x", "198.51.100.8", Transport::Xhttp);
    x.verdict = Some(CheckVerdict::Healthy);
    vec![
        srv("a", "198.51.100.7", Transport::Tcp),
        srv("a-ws", "198.51.100.7", Transport::Ws),
        srv("b", "198.51.100.9", Transport::Tcp),
        c,
        x,
        srv("h", "192.0.2.1", Transport::Udp),
    ]
}

fn find(servers: &[ServerFacts], id: &str) -> ServerFacts {
    servers.iter().find(|s| s.id == id).unwrap().clone()
}

/// Learn, then decide, the way the task does it.
fn react(memory: &mut Memory, servers: &[ServerFacts], rep: &Report, active: bool) -> Decision {
    let server = find(servers, &rep.profile_id);
    memory.learn(rep, &server, servers);
    decide(rep, &server, active, memory, servers, ON)
}

fn switch_to(decision: Decision) -> (Cause, Vec<String>) {
    match decision {
        Decision::Switch { cause, candidates } => {
            (cause, candidates.into_iter().map(|s| s.id).collect())
        }
        other => panic!("expected a switch, got {other:?}"),
    }
}

/// ip-banned: never another port or transport on the banned address; healthy first, then
/// latency.
#[test]
fn ip_banned_switches_off_the_address() {
    let (servers, mut m) = (pool(), Memory::default());
    let rep = report("a", CheckVerdict::IpBanned, CheckReaction::SwitchServer);
    let (cause, to) = switch_to(react(&mut m, &servers, &rep, true));
    assert_eq!((cause, to), (Cause::IpBanned, vec!["x".into(), "c".into()]));
    assert!(m.avoid.contains_key("a") && m.avoid.contains_key("a-ws"));
}

/// frozen: XHTTP first, then another data centre; never the frozen transport towards the
/// same data centre; another transport on the same address is the last resort.
#[test]
fn frozen_prefers_xhttp_then_another_data_centre() {
    let servers = pool();
    let rep = report("a", CheckVerdict::Frozen, CheckReaction::SwitchServer);
    let mut m = Memory::default();
    let (cause, to) = switch_to(react(&mut m, &servers, &rep, true));
    assert_eq!((cause, to), (Cause::Frozen, vec!["x".into(), "c".into()]));
    assert!(m.avoid.contains_key("b"), "same /24, same transport");
    assert!(!m.avoid.contains_key("a-ws"), "another transport may pass");
    let all = candidates(Cause::Frozen, &servers[0], &servers, &Memory::default());
    assert_eq!(ids(&all), ["x", "c"], "capped at MAX_CANDIDATES");
    // An XHTTP server that freezes: another data centre first.
    let rep = report("x", CheckVerdict::Frozen, CheckReaction::SwitchServer);
    let (_, to) = switch_to(react(&mut Memory::default(), &servers, &rep, true));
    assert_eq!(to, ["c", "h"]);
}

/// handshake-failed on REALITY: one retry with the next allowed fingerprint, then the server is
/// given up (switch); without REALITY a switch at once; a hang inside a freeze changes nothing.
#[test]
fn reality_handshake_gets_one_fingerprint_retry() {
    let mut servers = pool();
    servers.push(reality(
        srv("r", "203.0.113.20", Transport::Tcp),
        Some("chrome"),
    ));
    let rep = report(
        "r",
        CheckVerdict::HandshakeFailed,
        CheckReaction::TryAnotherFingerprint,
    );
    let mut m = Memory::default();
    assert_eq!(
        react(&mut m, &servers, &rep, true),
        Decision::Fingerprint("firefox")
    );
    m.tried.insert(("r".into(), Attempt::Fingerprint));
    let (cause, to) = switch_to(react(&mut m, &servers, &rep, true));
    assert_eq!((cause, to.len()), (Cause::HandshakeFailed, 2));
    assert!(!to.contains(&"r".to_owned()));
    // Not REALITY (a Hysteria2 TLS failure): give up on the server right away.
    let rep = report(
        "h",
        CheckVerdict::HandshakeFailed,
        CheckReaction::TryAnotherFingerprint,
    );
    let (cause, _) = switch_to(react(&mut Memory::default(), &servers, &rep, true));
    assert_eq!(cause, Cause::HandshakeFailed);
    let hang = report(
        "r",
        CheckVerdict::HandshakeFailed,
        CheckReaction::RetryLater,
    );
    let mut m = Memory::default();
    assert!(matches!(
        react(&mut m, &servers, &hang, true),
        Decision::Nothing(_)
    ));
    assert!(m.avoid.is_empty(), "a freeze is temporary");
}

/// udp-blocked: a UDP server moves to a TCP-based one; afterwards TCP goes first in every pick
/// of this network session; a TCP server is left alone.
#[test]
fn udp_blocked_prefers_tcp_for_the_network_session() {
    let servers = pool();
    let rep = report(
        "h",
        CheckVerdict::UdpBlocked,
        CheckReaction::PreferTcpTransport,
    );
    let mut m = Memory::default();
    let (cause, to) = switch_to(react(&mut m, &servers, &rep, true));
    assert_eq!(
        (cause, to),
        (Cause::UdpBlocked, vec!["x".into(), "c".into()])
    );
    assert!(
        m.udp_blocked && !m.avoid.contains_key("h"),
        "a preference, not a ban"
    );
    let on_tcp = report(
        "a",
        CheckVerdict::UdpBlocked,
        CheckReaction::PreferTcpTransport,
    );
    assert!(matches!(
        react(&mut m, &servers, &on_tcp, true),
        Decision::Nothing(_)
    ));
    // Later, any switch puts the UDP server behind the TCP ones.
    let mut fast_udp = servers.clone();
    fast_udp[5].verdict = Some(CheckVerdict::Healthy);
    let picks = candidates(Cause::KeyRejected, &fast_udp[0], &fast_udp, &m);
    assert_eq!(ids(&picks), ["x", "c"]);
    let fresh = candidates(
        Cause::KeyRejected,
        &fast_udp[0],
        &fast_udp,
        &Memory::default(),
    );
    assert_eq!(
        ids(&fresh),
        ["x", "h"],
        "without the UDP cut a healthy UDP server is fine"
    );
}

/// A verdict about a server that does not run the session only teaches the memory.
#[test]
fn other_servers_only_teach_the_memory() {
    let servers = pool();
    let mut m = Memory::default();
    let rep = report("a", CheckVerdict::IpBanned, CheckReaction::SwitchServer);
    assert!(matches!(
        react(&mut m, &servers, &rep, false),
        Decision::Nothing(_)
    ));
    // The banned address is out of later picks, whatever its transport.
    let rep = report("c", CheckVerdict::Offline, CheckReaction::SwitchServer);
    let (cause, to) = switch_to(react(&mut m, &servers, &rep, true));
    assert_eq!((cause, to), (Cause::Offline, vec!["x".into(), "b".into()]));
}

/// Gates: one switch reaction per server and network session, the user's settings, the
/// restart cap.
#[test]
fn reactions_are_gated() {
    let servers = pool();
    let rep = report("a", CheckVerdict::KeyRejected, CheckReaction::SwitchServer);
    let a = find(&servers, "a");
    let mut m = Memory::default();
    m.tried.insert(("a".into(), Attempt::Switch));
    assert!(matches!(
        decide(&rep, &a, true, &m, &servers, ON),
        Decision::Nothing(_)
    ));
    let m = Memory {
        restarts: MAX_RESTARTS,
        ..Memory::default()
    };
    assert_eq!(
        decide(&rep, &a, true, &m, &servers, ON),
        Decision::Paused(Cause::KeyRejected)
    );
    let off = Allowed {
        fingerprint: true,
        switch: false,
    };
    let m = Memory::default();
    assert_eq!(
        decide(&rep, &a, true, &m, &servers, off),
        Decision::Manual(Cause::KeyRejected)
    );
    // With adaptive bypass off the REALITY retry is off too.
    let r = reality(srv("r", "203.0.113.20", Transport::Tcp), None);
    let rep = report(
        "r",
        CheckVerdict::HandshakeFailed,
        CheckReaction::TryAnotherFingerprint,
    );
    let none = Allowed {
        fingerprint: false,
        switch: false,
    };
    assert_eq!(
        decide(&rep, &r, true, &m, &servers, none),
        Decision::Manual(Cause::HandshakeFailed)
    );
    for quiet in [
        CheckVerdict::Healthy,
        CheckVerdict::Stalled,
        CheckVerdict::Deferred,
        CheckVerdict::NotVerified,
    ] {
        let rep = report("a", quiet, CheckReaction::RetryLater);
        assert!(matches!(
            decide(&rep, &a, true, &m, &servers, ON),
            Decision::Nothing(_)
        ));
    }
}

/// A healthy verdict is direct evidence: the server and its address are usable again.
#[test]
fn healthy_lifts_the_ban_of_the_address() {
    let servers = pool();
    let mut m = Memory::default();
    let banned = report("a", CheckVerdict::IpBanned, CheckReaction::SwitchServer);
    react(&mut m, &servers, &banned, false);
    let frozen = report("c", CheckVerdict::Frozen, CheckReaction::SwitchServer);
    react(&mut m, &servers, &frozen, false);
    let fine = report("a-ws", CheckVerdict::Healthy, CheckReaction::None);
    react(&mut m, &servers, &fine, false);
    assert!(!m.avoid.contains_key("a") && !m.avoid.contains_key("a-ws"));
    assert!(m.avoid.contains_key("c"), "another server's freeze stays");
}

#[test]
fn fingerprints_rotate_inside_the_allowed_set() {
    let cases = [
        (None, "firefox"),
        (Some("chrome"), "firefox"),
        (Some("Chrome"), "firefox"),
        (Some("firefox"), "chrome"),
        (Some("safari"), "chrome"),
        (Some("edge"), "chrome"),
        (Some("random"), "chrome"),
    ];
    for (current, next) in cases {
        assert_eq!(next_fingerprint(current), next, "{current:?}");
        assert!(ALLOWED_FINGERPRINTS.contains(&next));
    }
}

#[test]
fn sites_group_addresses_by_data_centre() {
    assert_eq!(site("198.51.100.7"), site("198.51.100.200"));
    assert_ne!(site("198.51.100.7"), site("198.51.101.7"));
    assert_eq!(site("[2001:db8:1::5]"), site("2001:db8:1:ff::9"));
    assert_ne!(site("2001:db8:1::5"), site("2001:db8:2::5"));
    assert_eq!(site("VPN.Example.org"), "vpn.example.org");
}
