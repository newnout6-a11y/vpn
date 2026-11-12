//! The order the automatic choice tries servers in: what a check found alive first, then the
//! unknown, the ones found dead last; then the lower latency; then store order.
use super::Candidate;

/// `servers` without the ids `skip` names, best first.
pub fn rank(servers: &[Candidate], skip: impl Fn(&str) -> bool) -> Vec<&Candidate> {
    let mut found: Vec<(usize, &Candidate)> = (servers.iter().enumerate())
        .filter(|(_, c)| !skip(&c.id))
        .collect();
    found.sort_by_key(|(i, c)| {
        let evidence = match c.alive {
            Some(true) => 0,
            None => 1,
            Some(false) => 2,
        };
        (evidence, c.latency_ms.unwrap_or(u32::MAX), *i)
    });
    found.into_iter().map(|(_, c)| c).collect()
}
