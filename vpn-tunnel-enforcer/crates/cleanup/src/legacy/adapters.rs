//! Adapter leftovers of the old lockdown (spec §2.5, §6.6 step 5): IPv6 bindings it turned
//! off and static DNS it pinned to the TUN resolver, per adapter and per field independently
//! (a removed USB NIC must not strand another NIC's DNS). Only what the journal proves is
//! restored, and only while the adapter still shows the old app's state: a DNS list the user
//! changed since is left alone.
use std::net::{IpAddr, Ipv4Addr};

use vpnte_winnet::adapters::{self, AdapterStatus};

use super::journal::{AdapterJournal, AdapterRecord, DnsSource, Journals, Slot, Transition};
use super::netcfg;
use super::report::{Outcome, StepId, StepRecord};

/// The old TUN's addresses: never a user's original DNS (B13, B15).
pub(crate) const TUN_RESOLVERS: [Ipv4Addr; 2] = [
    Ipv4Addr::new(192, 168, 250, 253),
    Ipv4Addr::new(192, 168, 250, 254),
];

/// What the journal asks for one adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterPlan {
    pub enable_ipv6: bool,
    /// Static IPv4 DNS to restore (`[]` = DHCP); `None` = DNS was not forced.
    pub dns: Option<Vec<Ipv4Addr>>,
}

pub(crate) fn plan_adapter(r: &AdapterRecord) -> AdapterPlan {
    let dns = r.forced_dns_to.as_ref().filter(|f| !f.is_empty()).map(|_| {
        let mut servers: Vec<Ipv4Addr> = Vec::new();
        for ip in &r.dns_servers {
            if let IpAddr::V4(v4) = ip
                && !TUN_RESOLVERS.contains(v4)
                && !servers.contains(v4)
            {
                servers.push(*v4);
            }
        }
        match r.dns_source {
            DnsSource::Static if !servers.is_empty() => servers,
            _ => Vec::new(),
        }
    });
    AdapterPlan {
        enable_ipv6: r.forced_ipv6_off && r.ipv6_enabled,
        dns,
    }
}

/// Whether to write `target` given the adapter's `current` static list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DnsAction {
    /// Already as recorded.
    Nothing,
    /// Still pinned by the old app: write the target.
    Set,
    /// Changed since the lockdown (by the user or the old boot task): left alone.
    Changed,
}

/// Act only while every current server is one the old app forced (or a TUN resolver).
pub(crate) fn dns_action(
    target: &[Ipv4Addr],
    forced: &[IpAddr],
    current: &[Ipv4Addr],
) -> DnsAction {
    if current == target {
        return DnsAction::Nothing;
    }
    let pinned = |ip: &Ipv4Addr| TUN_RESOLVERS.contains(ip) || forced.contains(&IpAddr::V4(*ip));
    match !current.is_empty() && current.iter().all(pinned) {
        true => DnsAction::Set,
        false => DnsAction::Changed,
    }
}

/// Teredo / 6to4 / ISATAP are not restored: that needs `netsh`, which the app never runs.
/// The recorded prior states are reported so they can be restored by hand.
fn transition_note(t: &Transition) -> Option<String> {
    let states: Vec<String> = [
        ("teredo", &t.teredo),
        ("6to4", &t.six_to_four),
        ("isatap", &t.isatap),
    ]
    .into_iter()
    .filter_map(|(name, state)| state.as_ref().map(|s| format!("{name}={s}")))
    .collect();
    (!states.is_empty()).then(|| {
        format!(
            "transition technologies left as is (recorded before: {})",
            states.join(", ")
        )
    })
}

/// A step's record plus whether its journal may now be deleted.
pub(crate) struct Replayed {
    pub record: StepRecord,
    pub journal_done: bool,
}

/// Step 5 (writes need elevation): the adapter journal, or without a usable one the decided
/// heuristic (physical adapters whose static DNS is only the TUN resolver go back to DHCP).
pub(crate) fn restore(journals: &Journals) -> Replayed {
    match &journals.adapters {
        Slot::Valid(journal) => replay(journal),
        _ => heuristic(),
    }
}

#[derive(Default)]
struct Tally {
    lines: Vec<String>,
    changed: bool,
    dns_changed: bool,
    failed: bool,
}

impl Tally {
    fn ok(&mut self, line: String, changed: bool) {
        self.changed |= changed;
        self.lines.push(line);
    }
    fn fail(&mut self, line: String) {
        self.failed = true;
        self.lines.push(line);
    }
    fn finish(self, journal_done: bool) -> Replayed {
        if self.dns_changed {
            netcfg::flush_resolver_cache();
        }
        let outcome = match self.failed {
            true => Outcome::Failed,
            false => Outcome::Done,
        };
        let detail = match self.lines.is_empty() {
            true => "nothing to restore".to_string(),
            false => self.lines.join("; "),
        };
        Replayed {
            record: StepRecord::new(StepId::Adapters, outcome, detail).changed(self.changed),
            journal_done: journal_done && !self.failed,
        }
    }
}

fn replay(journal: &AdapterJournal) -> Replayed {
    let mut t = Tally::default();
    for r in &journal.adapters {
        let name = &r.alias;
        if !netcfg::present(r.guid) {
            // H-06: a removed NIC has nothing left to restore.
            t.ok(format!("{name}: adapter gone"), false);
            continue;
        }
        let plan = plan_adapter(r);
        if plan.enable_ipv6 {
            match netcfg::enable_ipv6(r.guid) {
                Ok(true) => t.ok(format!("{name}: IPv6 re-enabled"), true),
                Ok(false) => t.ok(format!("{name}: IPv6 already enabled"), false),
                Err(e) => t.fail(format!("{name}: IPv6 not re-enabled: {e}")),
            }
        }
        if let Some(target) = &plan.dns {
            let forced = r.forced_dns_to.as_deref().unwrap_or_default();
            dns(&mut t, name, r.guid, target, forced);
        }
    }
    let note = transition_note(&journal.transition);
    t.lines.extend(note.clone());
    t.lines
        .extend(journal.skipped.iter().map(|s| format!("{s}: skipped")));
    t.finish(note.is_none() && journal.skipped.is_empty())
}

fn dns(
    t: &mut Tally,
    name: &str,
    guid: windows::core::GUID,
    target: &[Ipv4Addr],
    forced: &[IpAddr],
) {
    let current = match netcfg::static_dns(guid) {
        Ok(current) => current,
        Err(e) => return t.fail(format!("{name}: DNS unreadable: {e}")),
    };
    match dns_action(target, forced, &current) {
        DnsAction::Nothing => t.ok(format!("{name}: DNS already as recorded"), false),
        DnsAction::Changed => t.ok(format!("{name}: DNS changed since, left as is"), false),
        DnsAction::Set => match netcfg::set_static_dns(guid, target) {
            Ok(()) => {
                t.dns_changed = true;
                let what = if target.is_empty() {
                    "back to DHCP"
                } else {
                    "static list restored"
                };
                t.ok(format!("{name}: DNS {what}"), true);
            }
            Err(e) => t.fail(format!("{name}: DNS not restored: {e}")),
        },
    }
}

fn heuristic() -> Replayed {
    let mut t = Tally::default();
    match adapters::inventory() {
        Ok(list) => {
            for a in list.iter().filter(|a| a.physical && a.ipv4_enabled) {
                dns(&mut t, &a.alias, a.guid, &[], &[]);
            }
            // Only adapters that were actually pinned are worth a line.
            t.lines
                .retain(|l| !l.ends_with("already as recorded") && !l.ends_with("left as is"));
        }
        Err(e) => t.fail(format!("adapters unreadable: {e}")),
    }
    t.finish(true)
}

/// The old Wintun adapter of `tun-owner.json`, report only: an enabled one is reused by
/// sing-tun, a disabled one is a leftover of the old boot task (B32) that the user can remove
/// in Device Manager (no device removal here).
pub(crate) fn tun_leftover(journals: &Journals) -> Replayed {
    let step = StepId::TunAdapter;
    let Some(owner) = journals.tun_owner.valid() else {
        let detail = match journals.tun_owner {
            Slot::Absent => "no old TUN record",
            _ => "old TUN record unusable",
        };
        let record = StepRecord::new(step, Outcome::Done, detail);
        return Replayed {
            record,
            journal_done: false,
        };
    };
    // An unreadable inventory is "not checked" (retried), never a guess about the adapter.
    let listed = match adapters::inventory() {
        Ok(list) => list.into_iter().find(|a| a.guid == owner.guid),
        Err(e) => {
            return Replayed {
                record: StepRecord::new(step, Outcome::Failed, format!("adapters unreadable: {e}")),
                journal_done: false,
            };
        }
    };
    let alias = &owner.alias;
    let (outcome, detail) = match listed {
        Some(a) if a.status == AdapterStatus::Disabled => (
            Outcome::Skipped,
            format!("disabled leftover adapter {alias}: remove it in Device Manager"),
        ),
        Some(_) => (
            Outcome::Done,
            format!("adapter {alias} present and enabled"),
        ),
        None if netcfg::present(owner.guid) => (
            Outcome::Skipped,
            format!("inactive leftover adapter {alias}: remove it in Device Manager"),
        ),
        None => (Outcome::Done, format!("adapter {alias} gone")),
    };
    Replayed {
        journal_done: outcome == Outcome::Done,
        record: StepRecord::new(step, outcome, detail),
    }
}

#[cfg(test)]
mod tests {
    use windows::core::GUID;

    use super::*;

    fn record(source: DnsSource, servers: &[&str], forced: Option<&[&str]>) -> AdapterRecord {
        let ips = |list: &[&str]| {
            list.iter()
                .map(|s| s.parse().unwrap())
                .collect::<Vec<IpAddr>>()
        };
        AdapterRecord {
            guid: GUID::from_u128(1),
            alias: "Wi-Fi".into(),
            ipv6_enabled: true,
            dns_servers: ips(servers),
            dns_source: source,
            forced_dns_to: forced.map(ips),
            forced_ipv6_off: true,
        }
    }

    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// §6.6 step 5: IPv4 entries only, TUN resolvers removed (B13, B15); static + non-empty
    /// restores the list, anything else goes back to DHCP; DNS untouched when not forced.
    #[test]
    fn plans_per_adapter() {
        let forced: &[&str] = &["192.168.250.254"];
        let p = plan_adapter(&record(
            DnsSource::Static,
            &[
                "192.0.2.53",
                "2001:db8::53",
                "192.168.250.254",
                "192.0.2.53",
                "198.51.100.1",
            ],
            Some(forced),
        ));
        assert!(p.enable_ipv6);
        assert_eq!(p.dns, Some(vec![v4("192.0.2.53"), v4("198.51.100.1")]));
        let p = plan_adapter(&record(
            DnsSource::Static,
            &["192.168.250.253"],
            Some(forced),
        ));
        assert_eq!(p.dns, Some(vec![]));
        let p = plan_adapter(&record(DnsSource::Dhcp, &["192.0.2.53"], Some(forced)));
        assert_eq!(p.dns, Some(vec![]));
        let p = plan_adapter(&record(DnsSource::Unknown, &["192.0.2.53"], Some(forced)));
        assert_eq!(p.dns, Some(vec![]));
        assert_eq!(
            plan_adapter(&record(DnsSource::Static, &["192.0.2.53"], None)).dns,
            None
        );
        assert_eq!(
            plan_adapter(&record(DnsSource::Static, &["192.0.2.53"], Some(&[]))).dns,
            None
        );
        let mut cellular = record(DnsSource::Dhcp, &[], None);
        cellular.forced_ipv6_off = false;
        assert!(!plan_adapter(&cellular).enable_ipv6);
        let mut was_off = record(DnsSource::Dhcp, &[], None);
        was_off.ipv6_enabled = false;
        assert!(!plan_adapter(&was_off).enable_ipv6);
    }

    /// Only a list still pinned by the old app is rewritten; the heuristic (no journal) is
    /// the same rule with an empty target and nothing forced.
    #[test]
    fn dns_only_while_still_pinned() {
        let forced: Vec<IpAddr> = vec!["192.168.250.254".parse().unwrap()];
        let target = [v4("192.0.2.53")];
        assert_eq!(
            dns_action(&target, &forced, &[v4("192.168.250.254")]),
            DnsAction::Set
        );
        assert_eq!(dns_action(&target, &forced, &target), DnsAction::Nothing);
        assert_eq!(dns_action(&target, &forced, &[]), DnsAction::Changed);
        assert_eq!(
            dns_action(&target, &forced, &[v4("1.1.1.1")]),
            DnsAction::Changed
        );
        assert_eq!(
            dns_action(&target, &forced, &[v4("192.168.250.254"), v4("1.1.1.1")]),
            DnsAction::Changed
        );
        assert_eq!(
            dns_action(&[], &[], &[v4("192.168.250.253"), v4("192.168.250.254")]),
            DnsAction::Set
        );
        assert_eq!(dns_action(&[], &[], &[]), DnsAction::Nothing);
        assert_eq!(
            dns_action(&[], &[], &[v4("192.168.1.1")]),
            DnsAction::Changed
        );
    }

    #[test]
    fn transition_states_are_reported_not_restored() {
        assert_eq!(transition_note(&Transition::default()), None);
        let t = Transition {
            teredo: Some("client".into()),
            six_to_four: None,
            isatap: Some("default".into()),
        };
        let note = transition_note(&t).unwrap();
        assert!(note.contains("teredo=client") && note.contains("isatap=default"));
    }
}
