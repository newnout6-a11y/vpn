//! The decision table: what a verdict about the running server calls for, and which servers a
//! switch tries, best first. Pure (no I/O, no clock), so the whole table is unit-tested.
use std::net::IpAddr;

use super::memory::{Attempt, Memory};
use super::{ALLOWED_FINGERPRINTS, CheckReaction, CheckVerdict, Report, ServerFacts, Transport};

/// Servers one reaction tries at most: each is a protected restart and a handshake.
pub(super) const MAX_CANDIDATES: usize = 2;
/// Tunnel restarts reactions may make per network session; past it they only learn. Several
/// servers failing in a row means the network, not the servers, is the problem.
pub(super) const MAX_RESTARTS: u8 = 4;

/// Why the session leaves its server (the notice's title).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cause {
    IpBanned,
    Frozen,
    Offline,
    KeyRejected,
    HandshakeFailed,
    UdpBlocked,
}

/// What to do about one report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Decision {
    /// Nothing; the label goes to the log.
    Nothing(&'static str),
    /// Restart the running REALITY server once with this fingerprint.
    Fingerprint(&'static str),
    /// Move the session away; `candidates` best first (empty: nothing suitable).
    Switch {
        cause: Cause,
        candidates: Vec<ServerFacts>,
    },
    /// The user turned automatic switching off: tell, change nothing.
    Manual(Cause),
    /// The network session used up its restarts: tell once, change nothing.
    Paused(Cause),
}

/// The reactions the settings allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Allowed {
    /// `adaptive_bypass`.
    pub(super) fingerprint: bool,
    /// `adaptive_bypass && adaptive_bypass_server_fallback`.
    pub(super) switch: bool,
}

/// The reaction to `report` about `server`; `active`: it runs the Direct session right now.
/// Reports about other servers only teach the memory (done by the caller).
pub(super) fn decide(
    report: &Report,
    server: &ServerFacts,
    active: bool,
    memory: &Memory,
    servers: &[ServerFacts],
    allowed: Allowed,
) -> Decision {
    if !active {
        return Decision::Nothing("not the running server");
    }
    let tried = |attempt| memory.tried.contains(&(server.id.clone(), attempt));
    let cause = match (report.verdict, report.reaction) {
        (CheckVerdict::IpBanned, _) => Cause::IpBanned,
        (CheckVerdict::Frozen, _) => Cause::Frozen,
        (CheckVerdict::Offline, _) => Cause::Offline,
        (CheckVerdict::KeyRejected, _) => Cause::KeyRejected,
        // A hang inside a freeze: changing the fingerprint now is reported to extend it.
        (CheckVerdict::HandshakeFailed, CheckReaction::RetryLater) => {
            return Decision::Nothing("handshake hangs: wait out the freeze");
        }
        (CheckVerdict::HandshakeFailed, _) => {
            if server.reality && allowed.fingerprint && !tried(Attempt::Fingerprint) {
                return if memory.restarts >= MAX_RESTARTS {
                    gate(
                        Cause::HandshakeFailed,
                        tried(Attempt::Switch),
                        allowed,
                        memory,
                    )
                } else {
                    Decision::Fingerprint(next_fingerprint(server.fingerprint.as_deref()))
                };
            }
            Cause::HandshakeFailed
        }
        (CheckVerdict::UdpBlocked, _) if server.transport.udp() => Cause::UdpBlocked,
        _ => return Decision::Nothing("no reaction needed"),
    };
    match gate(cause, tried(Attempt::Switch), allowed, memory) {
        Decision::Switch { cause, .. } => Decision::Switch {
            cause,
            candidates: candidates(cause, server, servers, memory),
        },
        other => other,
    }
}

/// Whether a switch may happen at all (candidates are filled in by the caller).
fn gate(cause: Cause, tried: bool, allowed: Allowed, memory: &Memory) -> Decision {
    if tried {
        Decision::Nothing("already reacted to this server on this network")
    } else if !allowed.switch {
        Decision::Manual(cause)
    } else if memory.restarts >= MAX_RESTARTS {
        Decision::Paused(cause)
    } else {
        Decision::Switch {
            cause,
            candidates: Vec::new(),
        }
    }
}

/// The servers a switch away from `from` tries, best first, at most [`MAX_CANDIDATES`]. Never
/// `from`, never a server this network ruled out; per cause never a server that shares the
/// failure (the banned address, the frozen transport towards the same data centre, UDP).
pub(super) fn candidates(
    cause: Cause,
    from: &ServerFacts,
    servers: &[ServerFacts],
    memory: &Memory,
) -> Vec<ServerFacts> {
    let place = site(&from.host);
    let mut list: Vec<&ServerFacts> = servers
        .iter()
        .filter(|s| s.id != from.id && !memory.avoid.contains_key(&s.id))
        .filter(|s| match cause {
            // Another port or transport on a banned address will not help.
            Cause::IpBanned => s.host != from.host,
            Cause::Frozen => !(s.transport == from.transport && site(&s.host) == place),
            Cause::UdpBlocked => !s.transport.udp(),
            Cause::Offline | Cause::KeyRejected | Cause::HandshakeFailed => true,
        })
        .collect();
    // Stable: equal keys keep the store order.
    list.sort_by_key(|s| {
        (
            memory.udp_blocked && s.transport.udp(),
            if cause == Cause::Frozen {
                frozen_rank(s, from, &place)
            } else {
                0
            },
            s.host == from.host,
            stored_rank(s.verdict),
            s.latency_ms.unwrap_or(u32::MAX),
        )
    });
    list.into_iter().take(MAX_CANDIDATES).cloned().collect()
}

/// After a freeze: XHTTP first (its short exchanges stay under the freeze threshold), then
/// another data centre, then another transport in the same one.
fn frozen_rank(s: &ServerFacts, from: &ServerFacts, place: &str) -> u8 {
    if s.transport == Transport::Xhttp && from.transport != Transport::Xhttp {
        0
    } else if site(&s.host) != place {
        1
    } else {
        2
    }
}

/// The stored verdict as evidence: healthy first, no evidence next, a bad verdict last (it may
/// come from another network, so it does not exclude).
fn stored_rank(verdict: Option<CheckVerdict>) -> u8 {
    match verdict {
        Some(CheckVerdict::Healthy) => 0,
        None | Some(CheckVerdict::Stalled | CheckVerdict::Deferred | CheckVerdict::NotVerified) => {
            1
        }
        Some(_) => 2,
    }
}

/// Where a server lives, for "another data centre": the /24 of an IPv4 address, the /48 of an
/// IPv6 one, else the host name itself (a name says nothing about the data centre behind it).
pub(super) fn site(host: &str) -> String {
    match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let [a, b, c, _] = v4.octets();
            format!("{a}.{b}.{c}")
        }
        Ok(IpAddr::V6(v6)) => {
            let [a, b, c, ..] = v6.segments();
            format!("{a:x}:{b:x}:{c:x}")
        }
        Err(_) => host.to_ascii_lowercase(),
    }
}

/// The fingerprint for the one REALITY retry: the first allowed one that differs from the
/// current (none = the engines' default, Chrome).
pub(super) fn next_fingerprint(current: Option<&str>) -> &'static str {
    let current = current.map_or_else(|| "chrome".to_owned(), str::to_ascii_lowercase);
    ALLOWED_FINGERPRINTS
        .into_iter()
        .find(|f| *f != current)
        .unwrap_or(ALLOWED_FINGERPRINTS[0])
}
