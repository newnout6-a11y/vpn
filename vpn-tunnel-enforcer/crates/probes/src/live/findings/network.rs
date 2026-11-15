//! Rules over the direct network stages and the server's network: open ports, TCP reachability,
//! latency and loss, ASN, shared /24, exit vs server country, resolver discrepancies.

use super::{
    HIGH_JITTER_WARNING_MS, HIGH_LATENCY_ERROR_MS, HIGH_LATENCY_WARNING_MS, LOSS_ERROR,
    LOSS_WARNING, Out, detail,
};
use crate::live::diff::HistoryDiff;
use crate::live::model::{Evidence, FindingCode as C, LiveCheck, Severity};
use crate::live_stages::TimedStatus;

pub(super) fn network_rules(cur: &LiveCheck, d: Option<&HistoryDiff>, out: &mut Out) {
    if let Some(ports) = &cur.open_ports {
        // The server's own port being open is the expected state, not news (B-14).
        let open: Vec<String> = ports
            .iter()
            .filter(|p| p.open && p.port != cur.port)
            .map(|p| match &p.service {
                Some(s) => format!("{} ({s})", p.port),
                None => p.port.to_string(),
            })
            .collect();
        if !open.is_empty() {
            out.push(
                C::PortOpen,
                Severity::Info,
                "portOpen",
                detail("portOpen").arg("ports", open.join(", ")),
                [("openPortsCount", (open.len() as u64).into())],
            );
        }
    }
    // The TCP verdict must not live only in a stage colour (B-03); UDP transports never get here
    // (their TCP stages are not run).
    if cur.reachability.timed.status == TimedStatus::Error {
        let error = cur
            .reachability
            .timed
            .error
            .clone()
            .unwrap_or_else(|| "—".into());
        out.push(
            C::TcpUnreachable,
            Severity::Error,
            "tcpUnreachable",
            detail("tcpUnreachable")
                .arg("host", &cur.host)
                .arg("port", cur.port)
                .arg("error", error),
            [
                ("host", cur.host.as_str().into()),
                ("port", Evidence::Num(f64::from(cur.port))),
            ],
        );
    }
    if let Some(lat) = &cur.latency {
        let pct = (lat.loss * 100.0).round();
        let loss = [("lossPct", Evidence::Num(pct))];
        if lat.loss >= LOSS_ERROR {
            let msg = detail("packetLossHigh").arg("pct", pct);
            out.push(C::PacketLoss, Severity::Error, "packetLossHigh", msg, loss);
        } else if lat.loss >= LOSS_WARNING {
            let msg = detail("packetLoss").arg("pct", pct);
            out.push(C::PacketLoss, Severity::Warning, "packetLoss", msg, loss);
        }
        let avg = [("avgMs", lat.avg.into())];
        if lat.avg >= HIGH_LATENCY_ERROR_MS {
            let msg = detail("latencyCritical").arg("avg", lat.avg);
            out.push(C::LatencyHigh, Severity::Error, "latencyCritical", msg, avg);
        } else if lat.avg >= HIGH_LATENCY_WARNING_MS {
            let msg = detail("latencyHigh").arg("avg", lat.avg);
            out.push(C::LatencyHigh, Severity::Warning, "latencyHigh", msg, avg);
        }
        if lat.jitter >= HIGH_JITTER_WARNING_MS {
            out.push(
                C::JitterHigh,
                Severity::Warning,
                "jitterHigh",
                detail("jitterHigh").arg("jitter", lat.jitter),
                [("jitterMs", lat.jitter.into())],
            );
        }
    }
    if let Some(d) = d.filter(|d| d.asn_changed) {
        let (previous, current) = (
            d.previous_asn.clone().unwrap_or_default(),
            d.current_asn.clone().unwrap_or_default(),
        );
        let org = cur.asn.as_ref().map(|a| a.org.clone()).unwrap_or_default();
        out.push(
            C::AsnChanged,
            Severity::Warning,
            "asnChanged",
            detail("asnChanged")
                .arg("previous", &previous)
                .arg("current", &current)
                .arg("org", org),
            [
                ("currentAsn", current.into()),
                ("previousAsn", previous.into()),
            ],
        );
    }
    let shared = cur
        .infrastructure
        .as_ref()
        .map(|i| i.shared_cidr_with_profiles.as_slice())
        .unwrap_or_default();
    if !shared.is_empty() {
        out.push(
            C::CidrSharedWithProfile,
            Severity::Info,
            "cidrShared",
            detail("cidrShared").arg(
                "names",
                shared
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            [("sharedCount", (shared.len() as u64).into())],
        );
    }
    // Fresh exit country (Cloudflare `loc`, ISO2) against the server's geo country (ISO2), for
    // every profile (B-08: the old rule compared unlike formats and could never fire).
    let exit = cur.egress.as_ref().and_then(|e| e.country.clone());
    let server = cur.asn.as_ref().and_then(|a| a.country_code.clone());
    if let (Some(exit), Some(server)) = (exit, server)
        && !exit.trim().eq_ignore_ascii_case(server.trim())
    {
        out.push(
            C::EgressCountryMismatch,
            Severity::Warning,
            "egressCountryMismatch",
            detail("egressCountryMismatch")
                .arg("egress", &exit)
                .arg("endpoint", &server),
            [("egress", exit.into()), ("endpoint", server.into())],
        );
    }
    for discrepancy in &cur.dns.discrepancies {
        out.push(
            C::DnsResolverDiscrepancy,
            Severity::Info,
            "dnsResolverDiscrepancy",
            discrepancy.clone(),
            [("host", cur.host.as_str().into())],
        );
    }
}
