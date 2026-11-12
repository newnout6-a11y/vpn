//! Which filters are active (firewall-recovery §6.4): a pure function of the protection state.
//!
//! In strict the dynamic `tun` / `dns` filters share our sublayer with the persistent set, so
//! weights alone order them and no filter is ever installed twice.
//!
//! Review D1 / D5: the `dns` block is in force for the whole session (from `connect_begin`, also
//! after a drop); `public_wifi_compat` only keeps LAN resolvers reachable while no session exists.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;
use vpnte_base::types::KillSwitchLevel;

use super::model::Conn;
use super::spec::{self, AppId, FilterSpec};

/// Everything [`desired`] depends on, with app IDs already resolved.
#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    /// The level in force (a stored `strict` already reads as `standard` without the service).
    pub level: KillSwitchLevel,
    /// A TUN of this session was up: only then does `standard` block everything (ks-a).
    pub armed: bool,
    pub leak_protection: bool,
    pub public_wifi_compat: bool,
    pub allow_lan: bool,
    pub conn: Conn,
    pub tun_luid: Option<u64>,
    /// Fixed local addresses of our TUN, permitted until its LUID is known.
    pub tun_addrs: Vec<IpAddr>,
    /// Static engines (sing-box, xray, external proxy) whose files exist.
    pub engines: Vec<Arc<AppId>>,
    /// Our own exe.
    pub own: Option<Arc<AppId>>,
    /// Per-session programs (local-proxy owners); never persistent.
    pub session: Vec<Arc<AppId>>,
    /// App exceptions whose files exist.
    pub exception_apps: Vec<Arc<AppId>>,
    pub exception_nets: Vec<IpNet>,
}

/// The two filter sets: owned by the dynamic session, and persistent (strict only).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Desired {
    pub dynamic: Vec<FilterSpec>,
    pub persistent: Vec<FilterSpec>,
}

/// Filters installed in one session, with their runtime IDs.
pub(crate) type Installed = Vec<(FilterSpec, u64)>;

/// One transaction: the IDs to delete, the specs to add, and the installed filters that stay.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Change {
    pub delete: Vec<u64>,
    pub add: Vec<FilterSpec>,
    pub keep: Installed,
}

impl Change {
    /// Turns `installed` into `want` touching only what differs (review R2): fewer policy
    /// changes for BFE, and a filter that stays keeps its ID.
    pub(crate) fn between(installed: &[(FilterSpec, u64)], want: &[FilterSpec]) -> Self {
        let mut pool: HashMap<&FilterSpec, Vec<u64>> = HashMap::new();
        for (spec, id) in installed {
            pool.entry(spec).or_default().push(*id);
        }
        let mut change = Change::default();
        for spec in want {
            match pool.get_mut(spec).and_then(Vec::pop) {
                Some(id) => change.keep.push((spec.clone(), id)),
                None => change.add.push(spec.clone()),
            }
        }
        change.delete = pool.into_values().flatten().collect();
        change
    }

    /// Deletes all of `installed` and adds all of `want` (when what is installed is in doubt).
    pub(crate) fn replace(installed: &[(FilterSpec, u64)], want: &[FilterSpec]) -> Self {
        Change {
            delete: installed.iter().map(|(_, id)| *id).collect(),
            add: want.to_vec(),
            keep: Vec::new(),
        }
    }

    pub(crate) fn is_noop(&self) -> bool {
        self.delete.is_empty() && self.add.is_empty()
    }

    /// The installed set once the transaction gave `ids` to `add`.
    pub(crate) fn installed(self, ids: Vec<u64>) -> Installed {
        self.keep
            .into_iter()
            .chain(self.add.into_iter().zip(ids))
            .collect()
    }
}

pub(crate) fn desired(p: &Plan) -> Desired {
    let session = p.conn.in_session();
    let strict = p.level == KillSwitchLevel::Strict;
    // "If the VPN drops" pauses a session that has started: a first connect that never came
    // up leaves the internet alone (owner decision 12.11.2026, research killswitch §5.3).
    let ks = p.level == KillSwitchLevel::Standard && session && p.armed;
    let lp = p.leak_protection && session && !ks && !strict;

    // The TUN-address permit is provisional: from `connect_begin` until `tun_up` brings the
    // LUID permit (a LAN that gave this PC the same address must not stay open after that).
    let sess = || -> Vec<FilterSpec> {
        let provisional = match p.conn {
            Conn::Connecting => p.tun_addrs.as_slice(),
            _ => &[],
        };
        let programs = if session { p.session.as_slice() } else { &[] };
        programs
            .iter()
            .flat_map(|id| spec::program("session", id))
            .chain(provisional.iter().flat_map(|a| spec::tun_addr(*a)))
            .collect()
    };
    let tun = || p.tun_luid.map(spec::tun).unwrap_or_default();
    // Programs, loopback and user exceptions sit above the DNS block, so they are installed on
    // both families even by leak protection (a v4 resolver exception must outrank `dns`).
    let base = || {
        let mut out: Vec<FilterSpec> = p
            .engines
            .iter()
            .flat_map(|id| spec::program("engine", id))
            .collect();
        out.extend(p.own.iter().flat_map(|id| spec::program("self", id)));
        out.extend(spec::loopback());
        out.extend(p.exception_apps.iter().flat_map(spec::exception_app));
        out.extend(
            p.exception_nets
                .iter()
                .flat_map(|net| spec::exception_ip(*net)),
        );
        out
    };
    let full = || {
        let mut out = base();
        out.extend(spec::lan(p.allow_lan, p.allow_lan));
        for group in [
            spec::dhcp(),
            spec::dhcp6(),
            spec::ntp(),
            spec::ndp(),
            spec::block4(),
            spec::block6(),
        ] {
            out.extend(group);
        }
        out
    };
    let v6only = || {
        let mut out = base();
        out.extend(spec::lan(false, p.allow_lan));
        for group in [spec::dhcp6(), spec::ndp(), spec::block6()] {
            out.extend(group);
        }
        out
    };
    let dns_when = |on: bool| if on { spec::dns() } else { Vec::new() };

    if strict {
        let mut persistent = full();
        persistent.extend(dns_when(!p.public_wifi_compat));
        let mut dynamic = sess();
        dynamic.extend(tun());
        dynamic.extend(dns_when(session && p.public_wifi_compat));
        return Desired {
            dynamic,
            persistent,
        };
    }
    // `ks` and `lp` imply a session, so both always carry the `dns` block.
    let mut dynamic = if ks {
        full()
    } else if lp {
        v6only()
    } else {
        return Desired::default();
    };
    dynamic.extend(sess());
    dynamic.extend(tun());
    dynamic.extend(spec::dns());
    Desired {
        dynamic,
        persistent: Vec::new(),
    }
}

#[cfg(test)]
mod tests;
