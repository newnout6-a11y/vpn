//! What one network session has learned from verdicts. A ban, a freeze, a UDP cut or a mobile
//! whitelist is a fact about the path from this network; after the physical network changes it
//! proves nothing, so the memory starts over (`LifecycleEvent::NetworkChanged`).
use std::collections::{HashMap, HashSet};

use parking_lot::Mutex;

use super::decide::site;
use super::{CheckReaction, CheckVerdict, Report, ServerFacts};

/// A reaction kind, tried at most once per server and network session (never a loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Attempt {
    /// The REALITY retry with another fingerprint.
    Fingerprint,
    /// Moving the session away from the server (also covers "nothing to switch to").
    Switch,
}

/// A profile ruled out for automatic picks on this network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Avoided {
    pub(super) verdict: CheckVerdict,
    pub(super) host: String,
}

/// The network session's state (one lock, held briefly, never across `.await`).
#[derive(Debug, Default)]
pub(super) struct Memory {
    pub(super) udp_blocked: bool,
    /// The network check found a mobile whitelist: only whitelisted Russian addresses pass.
    pub(super) whitelist: bool,
    pub(super) avoid: HashMap<String, Avoided>,
    pub(super) tried: HashSet<(String, Attempt)>,
    /// Tunnel restarts made by reactions on this network.
    pub(super) restarts: u8,
    /// The "switching paused" notice was shown on this network.
    pub(super) paused_told: bool,
}

impl Memory {
    /// Takes in what a check of `server` found; `servers` (every usable server) extends a
    /// verdict about an address to the other profiles on it.
    pub(super) fn learn(&mut self, report: &Report, server: &ServerFacts, servers: &[ServerFacts]) {
        let all = || std::iter::once(server).chain(servers);
        match (report.verdict, report.reaction) {
            (CheckVerdict::Healthy, _) => {
                // Direct evidence: this server works here, so its address is not banned either.
                self.avoid.remove(&server.id);
                self.avoid
                    .retain(|_, a| !(a.verdict == CheckVerdict::IpBanned && a.host == server.host));
            }
            // A ban drops every port and transport of the address.
            (CheckVerdict::IpBanned, _) => {
                self.avoid_all(
                    CheckVerdict::IpBanned,
                    all().filter(|s| s.host == server.host),
                );
            }
            // The freeze hits a transport towards a data centre: the same pair freezes too.
            (CheckVerdict::Frozen, _) => {
                let place = site(&server.host);
                let same =
                    |s: &&ServerFacts| s.transport == server.transport && site(&s.host) == place;
                self.avoid_all(CheckVerdict::Frozen, all().filter(same));
            }
            // Inside a freeze the handshake hangs: temporary, nothing to rule out.
            (CheckVerdict::HandshakeFailed, CheckReaction::RetryLater) => {}
            (
                CheckVerdict::Offline | CheckVerdict::KeyRejected | CheckVerdict::HandshakeFailed,
                _,
            ) => {
                self.avoid_all(report.verdict, std::iter::once(server));
            }
            (CheckVerdict::UdpBlocked, _) => self.udp_blocked = true,
            // Stalled, deferred, not verified: temporary or no evidence.
            _ => {}
        }
    }

    fn avoid_all<'a>(
        &mut self,
        verdict: CheckVerdict,
        servers: impl Iterator<Item = &'a ServerFacts>,
    ) {
        for s in servers {
            let host = s.host.clone();
            self.avoid.insert(s.id.clone(), Avoided { verdict, host });
        }
    }
}

/// The network session's memory, shared by [`Reactions`](super::Reactions) (the writer; the
/// app's network check sets only the network marks, through [`Verdicts::network_udp`] and
/// [`Verdicts::network_whitelist`]), rotation, the sibling fallback of adaptive bypass and the
/// automatic server choice (readers).
#[derive(Debug, Default)]
pub struct Verdicts {
    memory: Mutex<Memory>,
}

impl Verdicts {
    /// An empty memory (a new network session).
    pub fn new() -> Self {
        Self::default()
    }

    /// A check saw UDP cut on this network: TCP-based profiles go first in automatic picks.
    pub fn udp_blocked(&self) -> bool {
        self.memory.lock().udp_blocked
    }

    /// `id` got a verdict on this network that rules it out for automatic picks (its address is
    /// banned, its transport freezes towards its data centre, it is offline or refuses us).
    pub fn avoided(&self, id: &str) -> bool {
        self.memory.lock().avoid.contains_key(id)
    }

    /// A check of the network itself (not of a server) measured UDP: `true` = UDP is dropped,
    /// TCP-based profiles go first in automatic picks; `false` = UDP answered, so an earlier
    /// mark is lifted. No session is switched by it: only a server's own check does that.
    pub fn network_udp(&self, blocked: bool) {
        self.memory.lock().udp_blocked = blocked;
    }

    /// The network check found a mobile whitelist here: servers known to pass one, then those
    /// with a Russian entry, go first in automatic picks.
    pub fn whitelist(&self) -> bool {
        self.memory.lock().whitelist
    }

    /// A check of the network itself decided about the whitelist: `true` = only whitelisted
    /// Russian addresses pass; `false` = foreign hosts answer, an earlier mark is lifted. Like
    /// the UDP mark it switches no session.
    pub fn network_whitelist(&self, on: bool) {
        self.memory.lock().whitelist = on;
    }

    /// Forgets everything (the physical network changed).
    pub(super) fn reset(&self) {
        *self.memory.lock() = Memory::default();
    }

    /// Runs `f` under the lock (never across `.await`).
    pub(super) fn with<R>(&self, f: impl FnOnce(&mut Memory) -> R) -> R {
        f(&mut self.memory.lock())
    }
}

#[cfg(test)]
impl Verdicts {
    /// A network memory as the rotation and sibling tests need it.
    pub(crate) fn scripted(udp_blocked: bool, avoid: &[&str]) -> Self {
        let verdicts = Self::new();
        verdicts.with(|m| {
            m.udp_blocked = udp_blocked;
            for id in avoid {
                let avoided = Avoided {
                    verdict: CheckVerdict::IpBanned,
                    host: format!("{id}.example"),
                };
                m.avoid.insert((*id).to_owned(), avoided);
            }
        });
        verdicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// p-net-aware: the network check sets and lifts the whitelist mark beside the UDP mark; a
    /// new network starts without either.
    #[test]
    fn the_network_marks_come_and_go() {
        let verdicts = Verdicts::new();
        assert!(!verdicts.whitelist());
        verdicts.network_whitelist(true);
        verdicts.network_udp(true);
        assert!(verdicts.whitelist() && verdicts.udp_blocked());
        verdicts.network_whitelist(false);
        assert!(!verdicts.whitelist());
        assert!(verdicts.udp_blocked(), "the marks are independent");
        verdicts.network_whitelist(true);
        verdicts.reset();
        assert!(!verdicts.whitelist() && !verdicts.udp_blocked());
    }
}
