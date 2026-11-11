//! Identity column facts: the exit IP as the monitor reports it, the user's real (home) address
//! captured in memory only, and the server ping / health rules shared by the node line and the
//! servers panel.
use std::collections::HashSet;
use std::net::IpAddr;

use vpnte_base::types::Verdict;

use crate::swiss::ConnView;

/// Geolocation of an exit IP (looked up once per verified exit IP by the backend).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Geo {
    pub country: Option<String>,
    pub city: Option<String>,
}

/// What the IP monitor knows about the public address.
///
/// `verdict` uses the shared vocabulary: `Ok` = passed, `Warn` = indeterminate (the IP changed and
/// needs verification), `Fail` = failed, `NotChecked` = no check yet.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitIp {
    /// The public address as seen from outside right now.
    pub ip: Option<IpAddr>,
    /// The confirmed exit address of the tunnel.
    pub vpn_ip: Option<IpAddr>,
    pub verdict: Verdict,
    /// The public address is the real one while protection should be on.
    pub leak: bool,
    /// Geo keyed by the address it was looked up for, so a rotated exit IP never shows the
    /// previous country.
    pub geo: Option<(IpAddr, Geo)>,
}

impl ExitIp {
    /// Geo of the current public address, if it was looked up for this very address.
    pub fn current_geo(&self) -> Option<&Geo> {
        match (&self.geo, self.ip) {
            (Some((at, geo)), Some(ip)) if *at == ip => Some(geo),
            _ => None,
        }
    }
}

/// A leak the user should see: a server switch legitimately changes the IP, so no leak is shown
/// mid-switch.
pub fn visible_leak(conn: &ConnView, exit: &ExitIp) -> bool {
    exit.leak && conn.switching.is_none()
}

/// The user's real address. Memory only: never persisted, gone when the app closes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HomeIp {
    last: Option<IpAddr>,
    /// Every address seen as the exit while protected; never mistaken for the home IP.
    exits: HashSet<IpAddr>,
}

impl HomeIp {
    /// Nothing captured yet (app start).
    pub fn new() -> Self {
        Self::default()
    }

    /// The real address captured so far («—» until the first IP check while off).
    pub fn get(&self) -> Option<IpAddr> {
        self.last
    }

    /// Feeds the current facts and returns the real address. It is captured only when the
    /// connection is settled OFF (no connect / disconnect / switch in flight) and the address was
    /// never seen as an exit while protected, so a stale VPN IP right after a disconnect is
    /// ignored. A confirmed leak while protected is the real address too. Idempotent.
    pub fn observe(&mut self, conn: &ConnView, exit: &ExitIp) -> Option<IpAddr> {
        if let Some(vpn) = exit.vpn_ip {
            self.exits.insert(vpn);
        }
        let Some(public) = exit.ip else {
            return self.last;
        };
        let connected = conn.connected();
        if connected && !exit.leak {
            self.exits.insert(public);
            return self.last;
        }
        let settled_off = !connected && conn.busy().is_none() && conn.switching.is_none();
        let leaking = connected && exit.leak;
        if (settled_off || leaking) && exit.vpn_ip != Some(public) && !self.exits.contains(&public)
        {
            self.last = Some(public);
        }
        self.last
    }
}

/// Health of a server as the servers backend reports it (`healthStatus ?? status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ServerHealth {
    Online,
    Offline,
    #[default]
    Unknown,
}

/// A ping measured from the servers panel in this route generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalPing {
    /// A measurement is in flight.
    Pinging,
    /// Finished; `None` = the server did not answer.
    Done(Option<u32>),
}

/// The ping to show for a server: a local measurement wins (an in-flight one shows nothing),
/// else the stored ping, else the health checker's latency.
pub fn ping_of(
    local: Option<LocalPing>,
    ping: Option<u32>,
    health_latency: Option<u32>,
) -> Option<u32> {
    match local {
        Some(LocalPing::Pinging) => None,
        Some(LocalPing::Done(ms)) => ms,
        None => ping.or(health_latency),
    }
}

/// Index of the best server: the lowest ping among servers that are not offline; ties go to the
/// first in list order.
pub fn best_index(rows: impl IntoIterator<Item = (Option<u32>, ServerHealth)>) -> Option<usize> {
    rows.into_iter()
        .enumerate()
        .filter(|(_, (_, health))| *health != ServerHealth::Offline)
        .filter_map(|(i, (ms, _))| ms.map(|ms| (i, ms)))
        .min_by_key(|&(i, ms)| (ms, i))
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swiss::{Mode, Transition, TunnelState};

    const HOME: &str = "203.0.113.47";
    const EXIT: &str = "198.51.100.23";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn off() -> ConnView {
        ConnView::default()
    }

    fn on() -> ConnView {
        ConnView {
            state: TunnelState::Connected,
            mode: Some(Mode::Tun),
            ..ConnView::default()
        }
    }

    fn seen(public: Option<&str>, vpn: Option<&str>, leak: bool) -> ExitIp {
        ExitIp {
            ip: public.map(ip),
            vpn_ip: vpn.map(ip),
            leak,
            ..ExitIp::default()
        }
    }

    /// ui-dashboard §3.5 (`SwissIdentity.ts:15-45`): captured only while settled off.
    #[test]
    fn home_ip_is_captured_only_when_settled_off() {
        let mut home = HomeIp::new();
        assert_eq!(home.get(), None);
        assert_eq!(home.observe(&off(), &seen(None, None, false)), None);
        let connecting = ConnView {
            transition: Some(Transition::Connecting),
            ..off()
        };
        assert_eq!(
            home.observe(&connecting, &seen(Some(HOME), None, false)),
            None
        );
        let switching = ConnView {
            switching: Some("Riga-2".into()),
            ..off()
        };
        assert_eq!(
            home.observe(&switching, &seen(Some(HOME), None, false)),
            None
        );
        let cancelling = ConnView {
            cancelling: true,
            ..off()
        };
        assert_eq!(
            home.observe(&cancelling, &seen(Some(HOME), None, false)),
            None
        );
        assert_eq!(
            home.observe(&off(), &seen(Some(HOME), None, false)),
            Some(ip(HOME))
        );
        // Idempotent, and a missing sample keeps the last value.
        assert_eq!(
            home.observe(&off(), &seen(Some(HOME), None, false)),
            Some(ip(HOME))
        );
        assert_eq!(
            home.observe(&off(), &seen(None, None, false)),
            Some(ip(HOME))
        );
    }

    /// A stale VPN exit right after a disconnect is never mistaken for the home IP.
    #[test]
    fn exits_seen_while_protected_are_never_home() {
        let mut home = HomeIp::new();
        home.observe(&off(), &seen(Some(HOME), None, false));
        assert_eq!(
            home.observe(&on(), &seen(Some(EXIT), Some(EXIT), false)),
            Some(ip(HOME))
        );
        // Disconnected, but the monitor still reports the old exit address.
        assert_eq!(
            home.observe(&off(), &seen(Some(EXIT), None, false)),
            Some(ip(HOME))
        );
        // The confirmed VPN IP alone also marks an exit.
        let other = "198.51.100.99";
        home.observe(&off(), &seen(None, Some(other), false));
        assert_eq!(
            home.observe(&off(), &seen(Some(other), None, false)),
            Some(ip(HOME))
        );
        // The public address equal to the VPN IP is not the home address either.
        let mut fresh = HomeIp::new();
        assert_eq!(
            fresh.observe(&off(), &seen(Some(EXIT), Some(EXIT), false)),
            None
        );
    }

    /// A confirmed leak while protected is the real address too.
    #[test]
    fn a_leak_while_protected_reveals_the_home_ip() {
        let mut home = HomeIp::new();
        assert_eq!(
            home.observe(&on(), &seen(Some(HOME), Some(EXIT), true)),
            Some(ip(HOME))
        );
        // A transition is not "connected": no capture while reconnecting.
        let mut other = HomeIp::new();
        let reconnecting = ConnView {
            transition: Some(Transition::Reconnecting),
            ..on()
        };
        assert_eq!(
            other.observe(&reconnecting, &seen(Some(HOME), None, true)),
            None
        );
    }

    #[test]
    fn leak_is_hidden_mid_switch_and_geo_is_keyed_by_ip() {
        let exit = seen(Some(EXIT), Some(EXIT), true);
        assert!(visible_leak(&on(), &exit));
        let switching = ConnView {
            switching: Some("Riga-2".into()),
            ..on()
        };
        assert!(!visible_leak(&switching, &exit));
        let geo = Geo {
            country: Some("Netherlands".into()),
            city: Some("Amsterdam".into()),
        };
        let mut exit = ExitIp {
            geo: Some((ip(EXIT), geo.clone())),
            ..exit
        };
        assert_eq!(exit.current_geo(), Some(&geo));
        exit.ip = Some(ip("198.51.100.24"));
        assert_eq!(exit.current_geo(), None);
    }

    /// ui-dashboard §3.6 (`SwissPanels.tsx:151-164`): pingOf and the best-ping chip.
    #[test]
    fn ping_of_and_best_server() {
        assert_eq!(ping_of(Some(LocalPing::Pinging), Some(40), Some(30)), None);
        assert_eq!(
            ping_of(Some(LocalPing::Done(None)), Some(40), Some(30)),
            None
        );
        assert_eq!(
            ping_of(Some(LocalPing::Done(Some(55))), Some(40), None),
            Some(55)
        );
        assert_eq!(ping_of(None, Some(0), Some(30)), Some(0));
        assert_eq!(ping_of(None, None, Some(30)), Some(30));
        assert_eq!(ping_of(None, None, None), None);

        use ServerHealth::*;
        let rows = [
            (Some(38), Online),
            (Some(12), Offline),
            (None, Online),
            (Some(31), Unknown),
        ];
        assert_eq!(best_index(rows), Some(3));
        // Ties go to the first row.
        assert_eq!(
            best_index([(Some(31), Online), (Some(31), Online)]),
            Some(0)
        );
        assert_eq!(best_index([(Some(5), Offline), (None, Online)]), None);
        assert_eq!(best_index(Vec::new()), None);
    }
}
