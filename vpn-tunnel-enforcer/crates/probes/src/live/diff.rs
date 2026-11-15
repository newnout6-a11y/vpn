//! Comparison with the previous good check (liveServerHistory.ts:313-440) and the baseline rule
//! (B-18). Pure functions.
use serde::Serialize;
use vpnte_base::types::UnixMs;

use super::model::{HandshakeStatus, LiveCheck};
use crate::live_stages::geo::ChangesFromPrevious;
use crate::live_stages::tcp::PortState;
use crate::live_stages::{NotCheckedReason, TimedStatus};

/// What changed since the previous good check (previous / current values for the UI).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryDiff {
    pub previous_started_at: UnixMs,
    pub ip_changed: bool,
    pub previous_ips: Vec<String>,
    pub current_ips: Vec<String>,
    pub tls_cert_changed: bool,
    pub previous_tls_fingerprint: Option<String>,
    pub current_tls_fingerprint: Option<String>,
    pub asn_changed: bool,
    pub previous_asn: Option<String>,
    pub current_asn: Option<String>,
    pub country_changed: bool,
    pub previous_country: Option<String>,
    pub current_country: Option<String>,
    pub latency_spike: bool,
    pub previous_avg_latency: Option<u64>,
    pub current_avg_latency: Option<u64>,
    pub ports_changed: bool,
    pub closed_ports: Vec<u16>,
    pub new_open_ports: Vec<u16>,
    pub handshake_changed: bool,
    pub previous_handshake_status: Option<HandshakeStatus>,
    pub current_handshake_status: Option<HandshakeStatus>,
    pub egress_changed: bool,
    pub previous_exit_ip: Option<String>,
    pub current_exit_ip: Option<String>,
    pub pmtu_changed: bool,
    pub previous_pmtu: Option<u32>,
    pub current_pmtu: Option<u32>,
    pub throughput_changed: bool,
    pub previous_median_throughput: Option<f64>,
    pub current_median_throughput: Option<f64>,
}

impl HistoryDiff {
    /// The ten flags stored in `infrastructure.changesFromPrevious`.
    pub fn flags(&self) -> ChangesFromPrevious {
        ChangesFromPrevious {
            ip_changed: Some(self.ip_changed),
            asn_changed: Some(self.asn_changed),
            tls_cert_changed: Some(self.tls_cert_changed),
            country_changed: Some(self.country_changed),
            ports_changed: Some(self.ports_changed),
            latency_spike: Some(self.latency_spike),
            handshake_changed: Some(self.handshake_changed),
            egress_changed: Some(self.egress_changed),
            pmtu_changed: Some(self.pmtu_changed),
            throughput_changed: Some(self.throughput_changed),
        }
    }
}

/// Whether `row` may serve as the comparison baseline: not cancelled, same port (when given), and
/// the server answered — TCP reachability ok, or for UDP transports an ok handshake (B-18: a
/// check where only DNS worked is no baseline).
pub fn is_baseline(row: &LiveCheck, port: Option<u16>) -> bool {
    if row.cancelled || port.is_some_and(|p| p != row.port) {
        return false;
    }
    let reach = &row.reachability.timed;
    reach.status == TimedStatus::Ok
        || (reach.reason == Some(NotCheckedReason::UdpTransport)
            && row
                .handshake
                .as_ref()
                .is_some_and(|h| h.status == HandshakeStatus::Ok))
}

fn ips(check: &LiveCheck) -> Vec<String> {
    let mut all: Vec<String> = check.dns.a.iter().chain(&check.dns.aaaa).cloned().collect();
    all.sort();
    all.dedup();
    all
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A handshake verdict that was measured (skipped / not checked say nothing about the server).
fn measured(status: HandshakeStatus) -> bool {
    !matches!(
        status,
        HandshakeStatus::Skipped | HandshakeStatus::NotChecked
    )
}

/// Compares `cur` with the previous good check `prev`.
pub fn diff(cur: &LiveCheck, prev: &LiveCheck) -> HistoryDiff {
    let (previous_ips, current_ips) = (ips(prev), ips(cur));
    let ip_changed =
        !previous_ips.is_empty() && !current_ips.is_empty() && previous_ips != current_ips;

    let fingerprint =
        |c: &LiveCheck| non_empty(c.tls.as_ref().and_then(|t| t.fingerprint.as_deref()));
    let (prev_fp, cur_fp) = (fingerprint(prev), fingerprint(cur));
    let tls_cert_changed = matches!((&prev_fp, &cur_fp), (Some(a), Some(b)) if a != b);

    let asn = |c: &LiveCheck| non_empty(c.asn.as_ref().map(|a| a.asn.as_str()));
    let (prev_asn, cur_asn) = (asn(prev), asn(cur));
    let asn_changed = matches!((&prev_asn, &cur_asn), (Some(a), Some(b)) if a != b);

    // ISO codes when both rows have them (new rows), else the country names (imported rows).
    let code = |c: &LiveCheck| non_empty(c.asn.as_ref().and_then(|a| a.country_code.as_deref()));
    let name = |c: &LiveCheck| non_empty(c.asn.as_ref().map(|a| a.country.as_str()));
    let (previous_country, current_country) = match (code(prev), code(cur)) {
        (Some(a), Some(b)) => (Some(a), Some(b)),
        _ => (name(prev), name(cur)),
    };
    let country_changed = matches!((&previous_country, &current_country),
        (Some(a), Some(b)) if !a.eq_ignore_ascii_case(b));

    let avg = |c: &LiveCheck| c.latency.as_ref().map(|l| l.avg);
    let (previous_avg_latency, current_avg_latency) = (avg(prev), avg(cur));
    let latency_spike = match (previous_avg_latency, current_avg_latency) {
        (Some(p), Some(c)) => c as f64 > p as f64 * 1.5 && c.saturating_sub(p) > 50,
        _ => false,
    };

    let (mut closed_ports, mut new_open_ports) = (Vec::new(), Vec::new());
    if let (Some(prev_ports), Some(cur_ports)) = (&prev.open_ports, &cur.open_ports) {
        for c in cur_ports {
            let Some(p) = prev_ports.iter().find(|p| p.port == c.port) else {
                continue;
            };
            // open -> timeout / filtered is a lost probe, not a closed port.
            if p.open && c.state == PortState::Closed {
                closed_ports.push(c.port);
            } else if !p.open && c.open {
                new_open_ports.push(c.port);
            }
        }
    }
    let ports_changed = !closed_ports.is_empty() || !new_open_ports.is_empty();

    let status = |c: &LiveCheck| c.handshake.as_ref().map(|h| h.status);
    let (previous_handshake_status, current_handshake_status) = (status(prev), status(cur));
    let handshake_changed = matches!((previous_handshake_status, current_handshake_status),
        (Some(a), Some(b)) if measured(a) && measured(b) && a != b);

    let exit = |c: &LiveCheck, v6: bool| {
        let e = c.egress.as_ref()?;
        non_empty(if v6 {
            e.exit_ipv6.as_deref()
        } else {
            e.exit_ipv4.as_deref()
        })
    };
    let differs =
        |a: Option<String>, b: Option<String>| matches!((a, b), (Some(a), Some(b)) if a != b);
    let egress_changed =
        differs(exit(prev, false), exit(cur, false)) || differs(exit(prev, true), exit(cur, true));

    let (pmtu_changed, previous_pmtu, current_pmtu) = match (&prev.pmtu, &cur.pmtu) {
        (Some(p), Some(c)) => match (p.pmtu, c.pmtu) {
            (Some(pv), Some(cv))
                if p.family == c.family
                    && p.method == c.method
                    && (p.destination.is_empty()
                        || c.destination.is_empty()
                        || p.destination == c.destination) =>
            {
                (pv != cv, Some(pv), Some(cv))
            }
            _ => (false, None, None),
        },
        _ => (false, None, None),
    };

    let median = |c: &LiveCheck| c.throughput.as_ref().and_then(|t| t.median_mbps);
    let (previous_median_throughput, current_median_throughput) = (median(prev), median(cur));
    let throughput_changed = matches!((previous_median_throughput, current_median_throughput),
        (Some(p), Some(c)) if c < p * 0.65);

    HistoryDiff {
        previous_started_at: prev.started_at,
        ip_changed,
        previous_ips,
        current_ips,
        tls_cert_changed,
        previous_tls_fingerprint: prev_fp,
        current_tls_fingerprint: cur_fp,
        asn_changed,
        previous_asn: prev_asn,
        current_asn: cur_asn,
        country_changed,
        previous_country,
        current_country,
        latency_spike,
        previous_avg_latency,
        current_avg_latency,
        ports_changed,
        closed_ports,
        new_open_ports,
        handshake_changed,
        previous_handshake_status,
        current_handshake_status,
        egress_changed,
        previous_exit_ip: exit(prev, false),
        current_exit_ip: exit(cur, false),
        pmtu_changed,
        previous_pmtu,
        current_pmtu,
        throughput_changed,
        previous_median_throughput,
        current_median_throughput,
    }
}
