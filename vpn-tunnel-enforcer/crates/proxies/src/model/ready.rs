//! Readiness at read time (spec 3.2, 3.26, 3.27). Freshness depends on the wall clock, so it is
//! derived whenever a status is read, never cached: a slot whose probes stall stops being ready.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use vpnte_base::types::UnixMs;

use super::{Aggregate, Health, InstanceStatus, Lifecycle};

/// How long a confirmed egress IP counts as fresh (wire contract; the manager re-probes sooner).
pub const FRESH_WINDOW_MS: UnixMs = 60_000;

fn fresh(at: Option<UnixMs>, now: UnixMs) -> bool {
    at.is_some_and(|t| now - t < FRESH_WINDOW_MS)
}

/// A healthy route at `now`: its engine runs, it is `ready` + `healthy` and its egress IP was
/// confirmed less than [`FRESH_WINDOW_MS`] ago. Readiness adds uniqueness on top; the manager's
/// duplicate check (`health::Route::is_healthy`) uses this rule as it is.
pub(crate) fn is_healthy_route(
    running: bool,
    state: Lifecycle,
    health: Health,
    egress_ip: Option<IpAddr>,
    last_success_at: Option<UnixMs>,
    now: UnixMs,
) -> bool {
    running
        && state == Lifecycle::Ready
        && health == Health::Healthy
        && egress_ip.is_some()
        && fresh(last_success_at, now)
}

fn healthy_route(i: &InstanceStatus, now: UnixMs) -> bool {
    is_healthy_route(
        i.process_running,
        i.state,
        i.health,
        i.egress_ip,
        i.last_success_at,
        now,
    )
}

/// Sets `ready` and `running` of every instance at `now`. A route is ready when its engine runs,
/// it is `ready` + `healthy`, its egress IP was confirmed less than [`FRESH_WINDOW_MS`] ago and
/// no other healthy route exits through the same IP: two slots with one public IP are useless
/// to a consumer that wants distinct identities, so both lose readiness. `instances` must hold
/// every slot that may have a running engine.
pub fn derive_readiness(instances: &mut [InstanceStatus], now: UnixMs) {
    let mut healthy_by_ip: HashMap<IpAddr, u32> = HashMap::new();
    for ip in instances
        .iter()
        .filter(|i| healthy_route(i, now))
        .filter_map(|i| i.egress_ip)
    {
        *healthy_by_ip.entry(ip).or_default() += 1;
    }
    for i in instances.iter_mut() {
        let unique = i
            .egress_ip
            .is_some_and(|ip| healthy_by_ip.get(&ip) == Some(&1));
        i.ready = healthy_route(i, now) && unique;
        i.running = i.process_running && i.ready;
    }
}

impl Aggregate {
    /// Counters over `instances` at `now`, exactly the old rules; `ready` must be derived first.
    /// `duplicate_egress` counts fresh collisions of every running instance (a quarantined slot
    /// included): it signals that a collision exists.
    pub fn of(instances: &[InstanceStatus], now: UnixMs) -> Self {
        let mut fresh_groups: HashMap<IpAddr, u32> = HashMap::new();
        for i in instances {
            if let Some(ip) = i.egress_ip
                && i.process_running
                && fresh(i.egress_checked_at, now)
            {
                *fresh_groups.entry(ip).or_default() += 1;
            }
        }
        let count = |pred: &dyn Fn(&InstanceStatus) -> bool| {
            instances.iter().filter(|i| pred(i)).count() as u32
        };
        let unique: HashSet<IpAddr> = instances
            .iter()
            .filter(|i| i.ready)
            .filter_map(|i| i.egress_ip)
            .collect();
        Aggregate {
            total: instances.len() as u32,
            running: count(&|i| i.process_running),
            ready: count(&|i| i.ready),
            healthy: count(&|i| i.health == Health::Healthy && i.ready),
            unique_egress: unique.len() as u32,
            duplicate_egress: fresh_groups.values().map(|n| n - 1).sum(),
            starting: count(&|i| matches!(i.state, Lifecycle::Starting | Lifecycle::Rotating)),
            degraded: count(&|i| matches!(i.state, Lifecycle::Degraded | Lifecycle::Failed)),
            quarantined: count(&|i| i.state == Lifecycle::Quarantined),
        }
    }

    /// Prewarm success: `count` ready routes with distinct egress IPs and no collision.
    pub fn covers(&self, count: u32) -> bool {
        self.ready >= count && self.unique_egress >= count && self.duplicate_egress == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Degradation;
    use crate::test_support::healthy_instance;

    const NOW: UnixMs = 1_762_800_000_000;

    /// Spec external-proxy §7.7: 30 distinct fresh egress IPs make 30 ready routes, and the
    /// aggregate counts all of them.
    #[test]
    fn capacity_counts_distinct_fresh_routes() {
        let mut list: Vec<_> = (1..=30)
            .map(|n| healthy_instance(n, &format!("198.51.100.{n}"), NOW))
            .collect();
        derive_readiness(&mut list, NOW);
        assert!(list.iter().all(|i| i.ready && i.running));
        let agg = Aggregate::of(&list, NOW);
        let expected = Aggregate {
            total: 30,
            running: 30,
            ready: 30,
            healthy: 30,
            unique_egress: 30,
            duplicate_egress: 0,
            starting: 0,
            degraded: 0,
            quarantined: 0,
        };
        assert_eq!(agg, expected);
        assert!(agg.covers(30));
        assert!(!agg.covers(31));
    }

    /// Spec external-proxy §7.9 phase 1: the second slot on the same IP is quarantined; the
    /// first stays ready and the aggregate still reports the collision.
    #[test]
    fn duplicate_egress_is_reported_and_quarantined_slot_is_not_ready() {
        let mut list = vec![
            healthy_instance(1, "198.51.100.10", NOW),
            healthy_instance(2, "198.51.100.10", NOW),
        ];
        list[1].health = Health::Quarantined;
        list[1].state = Lifecycle::Quarantined;
        list[1].degradation_reason = Some(Degradation::DuplicateEgressIp);
        derive_readiness(&mut list, NOW);
        assert!(list[0].ready);
        assert!(!list[1].ready && !list[1].running);
        let agg = Aggregate::of(&list, NOW);
        assert_eq!(
            (
                agg.ready,
                agg.unique_egress,
                agg.duplicate_egress,
                agg.quarantined
            ),
            (1, 1, 1, 1)
        );
    }

    /// Spec external-proxy §3.2: two healthy routes on one IP both lose readiness.
    #[test]
    fn colliding_healthy_routes_are_both_not_ready() {
        let mut list = vec![
            healthy_instance(1, "198.51.100.7", NOW),
            healthy_instance(2, "198.51.100.7", NOW),
            healthy_instance(3, "198.51.100.8", NOW),
        ];
        derive_readiness(&mut list, NOW);
        let ready: Vec<bool> = list.iter().map(|i| i.ready).collect();
        assert_eq!(ready, [false, false, true]);
        assert_eq!(Aggregate::of(&list, NOW).duplicate_egress, 1);
    }

    /// Spec external-proxy §6.3 / B-30: freshness is judged at read time; a route whose last
    /// success is a full window old is no longer ready, and `running` needs a live process.
    #[test]
    fn readiness_follows_the_clock_and_the_process() {
        let mut list = vec![healthy_instance(1, "198.51.100.1", NOW)];
        list[0].last_success_at = Some(NOW - FRESH_WINDOW_MS + 1);
        derive_readiness(&mut list, NOW);
        assert!(list[0].ready);
        derive_readiness(&mut list, NOW + 1);
        assert!(!list[0].ready && !list[0].running);

        let mut list = vec![healthy_instance(1, "198.51.100.1", NOW)];
        list[0].process_running = false;
        derive_readiness(&mut list, NOW);
        assert!(!list[0].ready && !list[0].running);
        let mut starting = healthy_instance(2, "198.51.100.2", NOW);
        starting.state = Lifecycle::Starting;
        starting.health = Health::Starting;
        let mut list = vec![starting];
        derive_readiness(&mut list, NOW);
        let agg = Aggregate::of(&list, NOW);
        assert_eq!((agg.ready, agg.running, agg.starting), (0, 1, 1));
    }
}
