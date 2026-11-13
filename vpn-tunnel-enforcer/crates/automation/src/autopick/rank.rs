//! The order the automatic choice tries servers in. First what the network memory knows: a
//! server that worked on this very network in whitelist mode; on a mobile whitelist then the
//! servers known to pass one (the user's mark, evidence from another network), then those with
//! a Russian entry, the rest after them; a server a verdict ruled out here always last. Then,
//! while UDP is cut, TCP-based servers before UDP ones. Then what a check found alive, the
//! unknown, the ones found dead; then the lower latency; then store order.
use std::collections::HashSet;

use super::Candidate;

/// What the network memory knows about the network the PC is on (nothing: the plain order).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Network {
    /// A check saw UDP cut here.
    pub udp_blocked: bool,
    /// The network check found a mobile whitelist here.
    pub whitelist: bool,
    /// This network's one-way tag ([`network_tag`](super::network_tag)), when known.
    pub tag: Option<String>,
    /// Servers a verdict ruled out on this network (banned address, freezing transport,
    /// offline, refused key).
    pub avoided: HashSet<String>,
}

/// `servers` without the ids `skip` names, best first on `net`.
pub fn rank<'a>(
    servers: &'a [Candidate],
    net: &Network,
    skip: impl Fn(&str) -> bool,
) -> Vec<&'a Candidate> {
    let mut found: Vec<(usize, &Candidate)> = (servers.iter().enumerate())
        .filter(|(_, c)| !skip(&c.id))
        .collect();
    found.sort_by_key(|(i, c)| {
        let evidence = match c.alive {
            Some(true) => 0,
            None => 1,
            Some(false) => 2,
        };
        let udp_cut = net.udp_blocked && c.udp;
        let latency = c.latency_ms.unwrap_or(u32::MAX);
        (place(c, net), udp_cut, evidence, latency, *i)
    });
    found.into_iter().map(|(_, c)| c).collect()
}

/// The candidate's place by what the network memory knows (lower first).
fn place(c: &Candidate, net: &Network) -> u8 {
    if net.avoided.contains(&c.id) {
        return 4;
    }
    // Proof from this very network counts even before its check ran again (start, a return).
    if c.whitelist.here(net.tag.as_deref()) {
        return 0;
    }
    match (net.whitelist, c.whitelist.ready(), c.ru_entry) {
        (false, ..) | (true, true, _) => 1,
        (true, false, true) => 2,
        (true, false, false) => 3,
    }
}
