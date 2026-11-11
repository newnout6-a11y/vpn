//! The boxes of the stages measured through the tunnel: handshake, egress, path, PMTU, media
//! stream, throughput and split routing.
use super::*;
use crate::servers::live_model::{HandshakeStatus, LiveCheck, StageStatus};
use crate::servers::live_present::{
    AliasText, Dot, interface_alias, pmtu_verdict, throughput_checklist, throughput_route_key,
};
use crate::t;
use crate::widgets::{Badge, Tone};

#[component]
pub(super) fn HandshakeBox(check: LiveCheck) -> Element {
    let Some(h) = check.handshake else {
        return rsx! {};
    };
    let (label, tone) = match h.status {
        HandshakeStatus::Ok => (t!("ui.servers.live.hs.ok"), Tone::Ok),
        HandshakeStatus::AuthFailed => (t!("ui.servers.live.hs.authFailed"), Tone::Fail),
        HandshakeStatus::TransportFailed => (t!("ui.servers.live.hs.transportFailed"), Tone::Warn),
        HandshakeStatus::Timeout => (t!("ui.servers.live.hs.timeout"), Tone::Warn),
        HandshakeStatus::Skipped => (t!("ui.servers.live.hs.skipped"), Tone::Unknown),
        HandshakeStatus::Unsupported => (t!("ui.servers.live.hs.unsupported"), Tone::Unknown),
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.handshake"), dot: Dot::from(h.status), duration_ms: h.duration_ms,
            Kv { label: t!("ui.servers.live.protocol"), mono: true,
                {h.protocol.as_deref().map_or_else(|| "—".to_owned(), str::to_uppercase)}
            }
            Kv { label: t!("ui.servers.live.hsStatus"), Badge { tone, "{label}" } }
            if let Some(ms) = h.duration_ms {
                div { class: "srv-kv-line", title: t!("liveCheck.handshakeProbeDurationTitle"),
                    span { class: "srv-kv-label", {t!("liveCheck.handshakeProbeDurationLabel")} }
                    span { class: "srv-kv-value swiss-mono", "{ms} ms" }
                }
                p { class: "srv-diag-foot", {t!("liveCheck.handshakeProbeDurationNote")} }
            }
            if let Some(evidence) = &h.evidence {
                Kv { label: t!("ui.servers.live.evidence"), mono: true, span { class: "srv-evidence", "{evidence}" } }
            }
            if let Some(err) = &h.error {
                p { class: "srv-diag-fail", "{err}" }
            }
        }
    }
}

#[component]
pub(super) fn EgressBox(check: LiveCheck) -> Element {
    let Some(e) = check.egress else {
        return rsx! {};
    };
    let none = || t!("ui.servers.live.unknownIp");
    let v6 = e.exit_ipv6.clone().unwrap_or_else(|| {
        if e.ipv6_unsupported {
            t!("ui.servers.live.v6Unsupported")
        } else {
            none()
        }
    });
    let underlay = e.underlay.as_deref().filter(|u| *u != "unknown").map(|u| {
        if u == "route-selected" {
            t!("ui.servers.live.underlayOs")
        } else {
            u.to_owned()
        }
    });
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.egress"), dot: Dot::from(e.status), duration_ms: e.duration_ms,
            Kv { label: "Egress IPv4:".to_owned(), mono: true, strong { {e.exit_ipv4.clone().unwrap_or_else(none)} } }
            Kv { label: "Egress IPv6:".to_owned(), mono: true, "{v6}" }
            if let Some(country) = &e.country {
                Kv { label: t!("ui.servers.live.exitCountry"), "{country}" }
            }
            if let Some(matches) = e.matches_endpoint {
                Kv { label: t!("ui.servers.live.vsEndpoint"),
                    if matches {
                        Badge { tone: Tone::Ok, {t!("ui.servers.live.sameAsEndpoint")} }
                    } else {
                        Badge { tone: Tone::Neutral, {t!("ui.servers.live.dualHop")} }
                    }
                }
            }
            if let Some(u) = underlay {
                Kv { label: t!("ui.servers.live.underlay"), "{u}" }
            }
            if !e.reflectors.is_empty() {
                p { class: "srv-diag-sub swiss-label", {t!("ui.servers.live.reflectors")} }
                for r in e.reflectors.iter() {
                    div { key: "{r.source}", class: "srv-kv-line",
                        span { class: "srv-kv-label", "{r.source}" }
                        span { class: "srv-kv-value swiss-mono",
                            {r.ip.clone().or_else(|| r.error.clone()).unwrap_or_else(|| t!("ui.servers.live.noData"))}
                            if let Some(c) = &r.country { " ({c})" }
                        }
                    }
                }
            }
            if let Some(err) = &e.error {
                p { class: "srv-diag-fail", "{err}" }
            }
        }
    }
}

#[component]
pub(super) fn PathBox(check: LiveCheck) -> Element {
    let Some(p) = check.path else {
        return rsx! {};
    };
    let (alias, alias_title) =
        match interface_alias(p.interface_alias.as_deref(), p.interface_index) {
            AliasText::Index(i) => (
                t!(
                    "ui.servers.live.alias.index",
                    index = i.map_or_else(|| "—".to_owned(), |i| i.to_string())
                ),
                None,
            ),
            AliasText::Corrupted => (
                t!("ui.servers.live.alias.corrupted"),
                Some(t!("ui.servers.live.alias.corruptedTitle")),
            ),
            AliasText::Name(name) => (name.to_owned(), None),
        };
    let (kind, tone) = if p.status != StageStatus::Ok {
        (t!("ui.servers.live.routeUnknown"), Tone::Warn)
    } else if p.is_tun {
        (t!("ui.servers.live.routeTun"), Tone::Neutral)
    } else {
        (t!("ui.servers.live.routePhysical"), Tone::Neutral)
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.path"), dot: Dot::from(p.status),
            Kv { label: t!("ui.servers.live.interface"), span { title: alias_title, "{alias}" } }
            Kv { label: t!("ui.servers.live.routeKind"), Badge { tone, "{kind}" } }
            p { class: "srv-diag-foot", {t!("ui.servers.live.pathNote")} }
            if let Some(hop) = &p.next_hop { Kv { label: t!("ui.servers.live.nextHop"), mono: true, "{hop}" } }
            if let Some(ip) = &p.local_ip { Kv { label: t!("ui.servers.live.localIp"), mono: true, "{ip}" } }
            if let Some(err) = &p.error { p { class: "srv-diag-warn", "{err}" } }
        }
    }
}

#[component]
pub(super) fn PmtuBox(check: LiveCheck) -> Element {
    let Some(p) = check.pmtu else {
        return rsx! {};
    };
    let (key, tone) = pmtu_verdict(&p);
    let pmtu_text = p.pmtu.map_or_else(|| "—".to_owned(), |v| v.to_string());
    let method = match &p.method {
        crate::servers::live_model::PmtuMethod::IcmpDf => t!("ui.servers.live.pmtuIcmp"),
        crate::servers::live_model::PmtuMethod::InterfaceMtu => t!("ui.servers.live.pmtuInterface"),
        crate::servers::live_model::PmtuMethod::Other(raw) => raw.clone(),
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.pmtu"), dot: Dot::from(p.status),
            Kv { label: t!("ui.servers.live.pmtuValue"), mono: true,
                {p.pmtu.map_or_else(|| t!("ui.servers.live.unknownIp"), |v| format!("{v} B"))}
            }
            if let (Some(lo), Some(hi)) = (p.min_tested, p.max_tested) {
                Kv { label: t!("ui.servers.live.pmtuRange"), mono: true, "[{lo} .. {hi}] B" }
            }
            Kv { label: t!("ui.servers.live.pmtuMethod"), "{method}" }
            Kv { label: t!("ui.servers.live.pmtuStatus"), Badge { tone, {t!(key, pmtu = pmtu_text)} } }
            if let Some(d) = &p.detail { p { class: "srv-diag-foot", "{d}" } }
            if let Some(err) = &p.error { p { class: "srv-diag-fail", "{err}" } }
        }
    }
}

#[component]
pub(super) fn MediaBox(check: LiveCheck) -> Element {
    let Some(m) = check.media else {
        return rsx! {};
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.media"), dot: Dot::from(m.status),
            Kv { label: "Twitch HLS CDN:".to_owned(),
                if m.hls_reachable {
                    Badge { tone: Tone::Ok, {t!("ui.servers.live.hlsOk")} }
                } else {
                    Badge { tone: Tone::Fail, {t!("ui.servers.live.hlsFail")} }
                }
            }
            Kv { label: t!("ui.servers.live.quicGuard"),
                if m.quic_guarded {
                    Badge { tone: Tone::Ok, {t!("ui.servers.live.quicOn")} }
                } else {
                    Badge { tone: Tone::Warn, {t!("ui.servers.live.quicOff")} }
                }
            }
            if m.error_2000_risk {
                Kv { label: t!("ui.servers.live.risk2000"), Badge { tone: Tone::Fail, {t!("ui.servers.live.riskHigh")} } }
            }
            for ep in m.endpoints.iter() {
                Kv { key: "{ep.endpoint}", label: format!("{}:", ep.endpoint), mono: true,
                    if ep.reachable {
                        {format!("{} ms (OK)", ep.latency_ms.map_or_else(|| "—".to_owned(), |v| v.to_string()))}
                    } else {
                        {ep.error.clone().unwrap_or_else(|| t!("ui.servers.live.failed"))}
                    }
                }
            }
            if let Some(d) = &m.detail { p { class: "srv-diag-foot", "{d}" } }
            if let Some(err) = &m.error { p { class: "srv-diag-fail", "{err}" } }
        }
    }
}

#[component]
pub(super) fn ThroughputBox(check: LiveCheck) -> Element {
    let Some(t) = check.throughput else {
        return rsx! {};
    };
    let route = throughput_route_key(t.route, false).map_or_else(|| "—".to_owned(), |k| t!(k));
    let checks = throughput_checklist(&t);
    let labels = [
        t!("ui.servers.live.tpSpread"),
        t!("ui.servers.live.tpStalls"),
        t!("ui.servers.live.tpGap"),
        t!("ui.servers.live.tpComplete"),
    ];
    let ttfb: Vec<String> = t
        .samples
        .iter()
        .map(|s| s.ttfb_ms.map_or_else(|| "—".to_owned(), |v| v.to_string()))
        .collect();
    let range = match (t.min_mbps, t.max_mbps) {
        (Some(lo), Some(hi)) => format!("{lo:.1}–{hi:.1} Mbps"),
        _ => "—".to_owned(),
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.throughput"), dot: Dot::from(t.status),
            Kv { label: t!("ui.servers.live.tpMedian"), mono: true,
                {t.median_mbps.map_or_else(|| t!("ui.servers.live.noData"), |v| format!("{v:.2} Mbps"))}
            }
            Kv { label: t!("ui.servers.live.tpRange"), mono: true, "{range}" }
            Kv { label: t!("ui.servers.live.tpVariability"), mono: true,
                {t.variability_pct.map_or_else(|| "—".to_owned(), |v| format!("{v:.1}%"))}
            }
            Kv { label: t!("ui.servers.live.tpStallsGap"), mono: true,
                {format!("{} / {} ms", t.stall_count.unwrap_or(0), t.max_gap_ms.unwrap_or(0))}
            }
            Kv { label: t!("ui.servers.live.tpRoute"), "{route}" }
            if !t.samples.is_empty() {
                Kv { label: t!("ui.servers.live.tpTtfb"), mono: true, {format!("{} ms", ttfb.join(" / "))} }
                table { class: "srv-samples swiss-mono",
                    thead {
                        tr {
                            for h in ["#", "Mbps", "MiB", "ms", "TTFB", "Stall", t!("ui.servers.live.tpPause").as_str()] {
                                th { key: "{h}", "{h}" }
                            }
                        }
                    }
                    tbody {
                        for (i , s) in t.samples.iter().enumerate() {
                            tr { key: "{i}",
                                td { "#{i + 1}" }
                                td { {format!("{:.2}", s.mbps)} }
                                td { {format!("{:.2}", s.bytes as f64 / 1024.0 / 1024.0)} }
                                td { "{s.duration_ms}" }
                                td { {s.ttfb_ms.map_or_else(|| "—".to_owned(), |v| v.to_string())} }
                                td { "{s.stalls}" }
                                td { "{s.max_gap_ms}" }
                            }
                        }
                    }
                }
            }
            if t.status != StageStatus::Skipped {
                div { class: "srv-checklist",
                    for (label , value) in labels.into_iter().zip(checks) {
                        div { key: "{label}", class: "srv-kv-line",
                            span { class: "srv-kv-label", "{label}" }
                            span { class: "srv-kv-value", class: if value == Some(false) { "is-alert" }, {yes_no(value)} }
                        }
                    }
                }
            }
            if let Some(d) = &t.detail { p { class: "srv-diag-foot", "{d}" } }
            if let Some(err) = &t.error { p { class: "srv-diag-fail", "{err}" } }
        }
    }
}

#[component]
pub(super) fn SplitBox(check: LiveCheck) -> Element {
    let Some(s) = check.split_tunnel else {
        return rsx! {};
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.split"), dot: Dot::from(s.status),
            Kv { label: t!("ui.servers.live.splitState"),
                if s.enabled { {t!("ui.servers.live.on")} } else { {t!("ui.servers.live.off")} }
            }
            Kv { label: "Direct process_name:".to_owned(), mono: true, "{s.direct.len()}" }
            Kv { label: "VPN process_name:".to_owned(), mono: true, "{s.vpn.len()}" }
            Kv { label: "Default outbound:".to_owned(), mono: true, "{s.default_outbound}" }
            if !s.duplicates.is_empty() {
                p { class: "srv-diag-warn", {t!("ui.servers.live.duplicates", list = s.duplicates.join(", "))} }
            }
            if let Some(d) = &s.detail { p { class: "srv-diag-foot", "{d}" } }
            if let Some(err) = &s.error { p { class: "srv-diag-fail", "{err}" } }
        }
    }
}
