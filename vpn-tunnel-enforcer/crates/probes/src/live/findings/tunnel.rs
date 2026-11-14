//! Rules over the engine stage (handshake, egress, throughput, media), PMTU and the split-tunnel
//! snapshot, in the order of the old table.

use super::{LOW_PMTU, Out, detail, detail_or_error};
use crate::live::diff::HistoryDiff;
use crate::live::model::{
    EgressStatus, Evidence, FindingCode as C, HandshakeStatus, LiveCheck, MediaStatus, Severity,
    SplitTunnelStatus, ThroughputStatus,
};
use crate::live_stages::Text;
use crate::live_stages::icmp::PmtuStatus;

pub(super) fn tunnel_rules(cur: &LiveCheck, d: Option<&HistoryDiff>, out: &mut Out) {
    if let Some(h) = &cur.handshake
        && !matches!(
            h.status,
            HandshakeStatus::Ok | HandshakeStatus::Skipped | HandshakeStatus::NotChecked
        )
    {
        let status = serde_json::to_value(h.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let protocol = h.protocol.clone().unwrap_or_else(|| "VPN".into());
        out.push(
            C::TunnelHandshakeFailed,
            Severity::Error,
            "handshakeFailed",
            detail("handshakeFailed")
                .arg("protocol", protocol.to_uppercase())
                .arg("error", h.error.clone().unwrap_or_else(|| status.clone())),
            [("protocol", protocol.into()), ("status", status.into())],
        );
    }
    if let Some(e) = &cur.egress {
        let status = |s: &str| [("status", Evidence::from(s))];
        match e.status {
            EgressStatus::Error => out.push(
                C::EgressVerificationFailed,
                Severity::Error,
                "egressFailed",
                detail_or_error("egressFailed", e.error.as_deref()),
                status("error"),
            ),
            EgressStatus::Partial => {
                let text: Text = match &e.discrepancy {
                    Some(why) => why.clone(),
                    None => detail_or_error("egressPartial", e.error.as_deref()).into(),
                };
                out.push(
                    C::EgressPartial,
                    Severity::Warning,
                    "egressPartial",
                    text,
                    status("partial"),
                );
            }
            _ => {}
        }
        if e.status == EgressStatus::Ok
            && let Some(exit) = &e.exit_ipv4
            && e.matches_endpoint == Some(false)
        {
            let endpoint = e.endpoint_ip.clone().unwrap_or_else(|| cur.host.clone());
            out.push(
                C::EgressDiffersFromEndpoint,
                Severity::Info,
                "egressDiffers",
                detail("egressDiffers")
                    .arg("endpoint", &endpoint)
                    .arg("exit", exit)
                    .arg("country", e.country.clone().unwrap_or_else(|| "—".into())),
                [
                    ("endpoint", endpoint.into()),
                    ("exit", exit.as_str().into()),
                ],
            );
        }
    }
    if let Some(p) = &cur.pmtu {
        if p.status == PmtuStatus::BlackholeSuspected {
            let text = p
                .detail
                .clone()
                .unwrap_or_else(|| detail("pmtuBlackhole").into());
            out.push(
                C::PmtuBlackholeSuspected,
                Severity::Warning,
                "pmtuBlackhole",
                text,
                [
                    ("destination", p.destination.as_str().into()),
                    ("status", "blackhole_suspected".into()),
                ],
            );
        }
        if let Some(mtu) = p.pmtu.filter(|m| *m < LOW_PMTU) {
            out.push(
                C::LowPmtu,
                Severity::Warning,
                "lowPmtu",
                detail("lowPmtu").arg("pmtu", mtu),
                [("pmtu", Evidence::Num(f64::from(mtu)))],
            );
        }
    }
    throughput_rules(cur, d, out);
    media_split_rules(cur, out);
}

fn throughput_rules(cur: &LiveCheck, d: Option<&HistoryDiff>, out: &mut Out) {
    let Some(t) = &cur.throughput else {
        return;
    };
    let endpoint = t.endpoint.clone().unwrap_or_default();
    match t.status {
        ThroughputStatus::Error => out.push(
            C::ThroughputProbeFailed,
            Severity::Warning,
            "throughputFailed",
            detail_or_error("throughputFailed", t.error.as_deref()),
            [("endpoint", endpoint.into())],
        ),
        ThroughputStatus::Warning => {
            let num = |v: Option<f64>| Evidence::Num(v.unwrap_or(0.0));
            out.push(
                C::ThroughputUnstable,
                Severity::Warning,
                "throughputUnstable",
                detail("throughputUnstable")
                    .arg("spread", t.variability_pct.unwrap_or(0))
                    .arg("stalls", t.stall_count.unwrap_or(0))
                    .arg("gap", t.max_inter_chunk_gap_ms.unwrap_or(0)),
                [
                    ("medianMbps", num(t.median_mbps)),
                    ("minMbps", num(t.min_mbps)),
                    ("maxMbps", num(t.max_mbps)),
                    ("variabilityPct", num(t.variability_pct.map(f64::from))),
                    ("stallCount", num(t.stall_count.map(f64::from))),
                    (
                        "maxInterChunkGapMs",
                        num(t.max_inter_chunk_gap_ms.map(|g| g as f64)),
                    ),
                ],
            );
        }
        _ => {}
    }
    // `throughput_changed` needs both medians, i.e. both rows measured throughput.
    if let Some(d) = d.filter(|d| d.throughput_changed) {
        let (p, c) = (
            d.previous_median_throughput.unwrap_or(0.0),
            d.current_median_throughput.unwrap_or(0.0),
        );
        out.push(
            C::ThroughputDegradedFromPrevious,
            Severity::Warning,
            "throughputDegraded",
            detail("throughputDegraded")
                .arg("previous", p)
                .arg("current", c),
            [
                ("previousMedianMbps", p.into()),
                ("currentMedianMbps", c.into()),
            ],
        );
    }
}

fn media_split_rules(cur: &LiveCheck, out: &mut Out) {
    if let Some(m) = &cur.media_stream {
        let flag = |v: Option<bool>| Evidence::Bool(v.unwrap_or(false));
        if m.error2000_risk == Some(true) {
            out.push(
                C::TwitchMediaError2000Risk,
                Severity::Warning,
                "twitchRisk",
                detail("twitchRisk"),
                [
                    ("error2000Risk", true.into()),
                    ("quicFallbackGuarded", flag(m.quic_fallback_guarded)),
                    ("twitchHlsReachable", flag(m.twitch_hls_reachable)),
                ],
            );
        } else if m.twitch_hls_reachable == Some(true) && m.quic_fallback_guarded == Some(true) {
            out.push(
                C::TwitchHlsOk,
                Severity::Info,
                "twitchOk",
                detail("twitchOk"),
                [
                    ("quicFallbackGuarded", true.into()),
                    ("twitchHlsReachable", true.into()),
                ],
            );
        } else if m.twitch_hls_reachable == Some(false) && m.status == MediaStatus::Error {
            out.push(
                C::TwitchMediaUnreachable,
                Severity::Warning,
                "twitchUnreachable",
                detail_or_error("twitchUnreachable", m.error.as_deref()),
                [("twitchHlsReachable", false.into())],
            );
        }
    }
    if let Some(s) = &cur.split_tunnel {
        match s.status {
            SplitTunnelStatus::Warning => {
                let text = s
                    .detail
                    .clone()
                    .unwrap_or_else(|| detail("splitConflict").into());
                out.push(
                    C::SplitTunnelRuleConflict,
                    Severity::Warning,
                    "splitConflict",
                    text,
                    [
                        (
                            "duplicateProcessNames",
                            s.duplicate_process_names.join(", ").into(),
                        ),
                        (
                            "directRuleCount",
                            Evidence::Num(f64::from(s.direct_rule_count)),
                        ),
                        ("vpnRuleCount", Evidence::Num(f64::from(s.vpn_rule_count))),
                    ],
                );
            }
            SplitTunnelStatus::Error => out.push(
                C::SplitTunnelDiagnosticsFailed,
                Severity::Warning,
                "splitFailed",
                detail_or_error("splitFailed", s.error.as_deref()),
                [],
            ),
            _ => {}
        }
    }
}
