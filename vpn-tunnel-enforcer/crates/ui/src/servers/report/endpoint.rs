//! The boxes of the stages that probe the server endpoint: DNS, latency, TLS, HTTP, ports, route
//! and infrastructure.
use super::*;
use crate::servers::live_model::{LiveCheck, PortStatus, StageStatus};
use crate::servers::live_present::{
    Dot, handshake_change_key, loss_text, route_status, sanitize_hop_line, tls_days_tone,
};
use crate::t;
use crate::widgets::{Badge, Tone};

#[component]
pub(super) fn DnsBox(check: LiveCheck) -> Element {
    let dns = check.dns;
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.dns"), dot: Dot::from(dns.status), duration_ms: dns.duration_ms,
            Kv { label: "IPv4 (A):".to_owned(), mono: true, {if dns.a.is_empty() { "—".to_owned() } else { dns.a.join(", ") }} }
            if !dns.aaaa.is_empty() {
                Kv { label: "IPv6 (AAAA):".to_owned(), mono: true, {dns.aaaa.join(", ")} }
            }
            if !dns.cname_chain.is_empty() {
                Kv { label: "CNAME:".to_owned(), mono: true, {dns.cname_chain.join(" → ")} }
            }
            if let Some(ttl) = dns.ttl {
                Kv { label: "TTL:".to_owned(), mono: true, "{ttl}s" }
            }
            if !dns.reverse_dns.is_empty() {
                Kv { label: t!("ui.servers.live.reverseDns"), mono: true, {dns.reverse_dns.join(", ")} }
            }
            if !dns.resolvers.is_empty() {
                p { class: "srv-diag-sub swiss-label", {t!("ui.servers.live.resolvers")} }
                for r in dns.resolvers.iter() {
                    div { key: "{r.name}", class: "srv-kv-line",
                        span { class: "srv-kv-label",
                            "{r.name}"
                            if r.authenticated {
                                Badge { tone: Tone::Ok, title: t!("ui.servers.live.adTitle"), "AD" }
                            }
                            if r.status == StageStatus::Warning {
                                Badge { tone: Tone::Warn, title: r.error.clone().unwrap_or_default(), {t!("ui.servers.live.partial")} }
                            }
                        }
                        span { class: "srv-kv-value swiss-mono", title: r.records.join(", "),
                            if r.status == StageStatus::Error {
                                {r.error.clone().unwrap_or_default()}
                            } else {
                                {resolver_line(r.duration_ms, &r.records)}
                            }
                        }
                    }
                }
            }
            for d in dns.discrepancies.iter() {
                p { key: "{d}", class: "srv-diag-warn", "{d}" }
            }
        }
    }
}

/// `38ms 198.51.100.1, 198.51.100.2 +3`.
fn resolver_line(duration_ms: u32, records: &[String]) -> String {
    let shown = records
        .iter()
        .take(2)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let more = records.len().saturating_sub(2);
    if more > 0 {
        format!("{duration_ms}ms {shown} +{more}")
    } else {
        format!("{duration_ms}ms {shown}")
    }
}

#[component]
pub(super) fn LatencyBox(check: LiveCheck) -> Element {
    let reach = check.reachability;
    let tun = match check.tunnel_running {
        Some(true) => t!("ui.servers.live.tunOn"),
        Some(false) => t!("ui.servers.live.tunOff"),
        None => t!("ui.servers.live.tunUnknown"),
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.latency"), dot: Dot::from(reach.status), duration_ms: reach.duration_ms,
            if let Some(l) = check.latency {
                div { class: "srv-latency",
                    for (label , value , main) in [
                        (t!("ui.servers.live.latMin"), l.min, false),
                        (t!("ui.servers.live.latAvg"), l.avg, true),
                        (t!("ui.servers.live.latMedian"), l.median, false),
                        (t!("ui.servers.live.latMax"), l.max, false),
                    ] {
                        div { key: "{label}", class: "srv-latency-stat", class: if main { "is-main" },
                            span { class: "swiss-label", "{label}" }
                            span { class: "swiss-mono", "{value} ms" }
                        }
                    }
                }
                Kv { label: t!("ui.servers.live.jitter"), mono: true, "{l.jitter} ms" }
                div { class: "srv-kv-line",
                    span { class: "srv-kv-label", {t!("ui.servers.live.tcpFailures")} }
                    span { class: "srv-kv-value swiss-mono", class: if l.loss > 0.0 { "is-alert" }, {loss_text(&l)} }
                }
                Kv { label: t!("ui.servers.live.path"),
                    Badge { tone: Tone::Neutral, {t!("ui.servers.live.osRoute", tun = tun)} }
                }
            } else {
                p { class: "srv-detail-note",
                    {reach.error.clone().unwrap_or_else(|| t!("ui.servers.live.noLatency"))}
                }
            }
        }
    }
}

#[component]
pub(super) fn TlsBox(check: LiveCheck) -> Element {
    let Some(tls) = check.tls else {
        return rsx! {};
    };
    let valid_to = tls.valid_to.clone().unwrap_or_default();
    let date = valid_to.split('T').next().unwrap_or(&valid_to).to_owned();
    let dash = || "—".to_owned();
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.tls"), dot: Dot::from(tls.status), duration_ms: tls.duration_ms,
            Kv { label: "Subject:".to_owned(), mono: true, span { class: "w-trunc", title: tls.subject.clone(), {tls.subject.clone().unwrap_or_else(dash)} } }
            Kv { label: "Issuer:".to_owned(), mono: true, span { class: "w-trunc", title: tls.issuer.clone(), {tls.issuer.clone().unwrap_or_else(dash)} } }
            if let Some(days) = tls.days_remaining {
                Kv { label: t!("ui.servers.live.validity"),
                    Badge { tone: tls_days_tone(days), {t!("ui.servers.live.daysLeft", days = days, date = date)} }
                }
            }
            if tls.protocol.is_some() || tls.cipher.is_some() {
                Kv { label: t!("ui.servers.live.protocolCipher"), mono: true,
                    {format!("{} ({})", tls.protocol.clone().unwrap_or_else(dash), tls.cipher.clone().unwrap_or_else(dash))}
                }
            }
            if let Some(alpn) = &tls.alpn {
                Kv { label: "ALPN:".to_owned(), mono: true, "{alpn}" }
            }
            if let Some(verified) = tls.hostname_verified {
                Kv { label: t!("ui.servers.live.sanMatch"),
                    if verified {
                        Badge { tone: Tone::Ok, {t!("ui.servers.live.sanOk")} }
                    } else {
                        Badge { tone: Tone::Fail, {t!("ui.servers.live.sanBad")} }
                    }
                }
            }
            if tls.authorized == Some(false) {
                Kv { label: t!("ui.servers.live.chain"),
                    Badge { tone: Tone::Warn, {tls.authorization_error.clone().unwrap_or_else(|| t!("ui.servers.live.untrusted"))} }
                }
            }
            if let Some(fp) = &tls.fingerprint {
                Kv { label: "SHA-256:".to_owned(), mono: true, span { class: "selectable srv-fp", "{fp}" } }
            }
            p { class: "srv-diag-foot", {t!("ui.servers.live.realityNote")} }
        }
    }
}

#[component]
pub(super) fn HttpBox(check: LiveCheck) -> Element {
    let Some(http) = check.http else {
        return rsx! {};
    };
    let (status_text, tone) = match http.status_code {
        Some(code) if code < 400 => (format!("HTTP {code}"), Tone::Ok),
        Some(code) if code < 500 => (format!("HTTP {code}"), Tone::Warn),
        Some(code) => (format!("HTTP {code}"), Tone::Neutral),
        None => (t!("ui.servers.live.noAnswer"), Tone::Neutral),
    };
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.http"), dot: Dot::from(http.status), duration_ms: http.duration_ms,
            Kv { label: t!("ui.servers.live.httpStatus"), Badge { tone, "{status_text}" } }
            if let Some(port) = http.target_port {
                Kv { label: t!("ui.servers.live.httpPort"), mono: true,
                    {format!("{port} ({})", if http.is_tls { "HTTPS" } else { "HTTP" })}
                }
            }
            if let Some(v) = &http.server_header { Kv { label: "Server:".to_owned(), mono: true, "{v}" } }
            if let Some(v) = &http.via_header { Kv { label: "Via:".to_owned(), mono: true, "{v}" } }
            if let Some(v) = &http.location_header {
                Kv { label: "Location:".to_owned(), mono: true, span { class: "w-trunc", title: "{v}", "{v}" } }
            }
            p { class: "srv-diag-foot", {t!("ui.servers.live.httpNote")} }
        }
    }
}

#[component]
pub(super) fn PortsBox(check: LiveCheck) -> Element {
    if check.open_ports.is_empty() {
        return rsx! {};
    }
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.ports"), dot: Dot::Ok,
            div { class: "srv-chips",
                for p in check.open_ports.iter() {
                    Badge {
                        key: "{p.port}",
                        tone: if p.state == PortStatus::Open { Tone::Ok } else { Tone::Neutral },
                        {port_text(p.port, p.service.as_deref(), p.state)}
                    }
                }
            }
            p { class: "srv-diag-foot", {t!("ui.servers.live.portsNote")} }
        }
    }
}

fn port_text(port: u16, service: Option<&str>, state: PortStatus) -> String {
    let state = t!(match state {
        PortStatus::Open => "ui.servers.live.port.open",
        PortStatus::Closed => "ui.servers.live.port.closed",
        PortStatus::Filtered => "ui.servers.live.port.filtered",
        PortStatus::Timeout => "ui.servers.live.port.timeout",
    });
    match service {
        Some(s) => format!("{port} ({s}): {state}"),
        None => format!("{port}: {state}"),
    }
}

#[component]
pub(super) fn RouteBox(check: LiveCheck) -> Element {
    let Some(route) = check.route else {
        return rsx! {};
    };
    let lines: Vec<String> = route
        .hop_lines
        .iter()
        .map(|l| sanitize_hop_line(l))
        .collect();
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.route"), dot: Dot::from(route_status(&route)), duration_ms: route.duration_ms,
            Kv { label: t!("ui.servers.live.hops"), mono: true, {route.hops.map_or_else(|| "—".to_owned(), |h| h.to_string())} }
            if let Some(reached) = route.reached_target {
                Kv { label: t!("ui.servers.live.target"),
                    if reached {
                        Badge { tone: Tone::Ok, {t!("ui.servers.live.reached")} }
                    } else {
                        Badge { tone: Tone::Warn, {t!("ui.servers.live.notFinished")} }
                    }
                }
            }
            if !lines.is_empty() {
                p { class: "srv-diag-sub swiss-label", {t!("ui.servers.live.hopLines")} }
                pre { class: "srv-hops swiss-mono", {lines.join("\n")} }
            }
            if let Some(err) = &route.error {
                p { class: "srv-diag-warn", "{err}" }
            }
        }
    }
}

#[component]
pub(super) fn InfraBox(check: LiveCheck) -> Element {
    let Some(infra) = check.infrastructure else {
        return rsx! {};
    };
    let c = infra.changes;
    let handshake = check.handshake.as_ref().map(|h| h.status);
    let badges: Vec<(String, Tone)> = [
        (c.ip, t!("ui.servers.live.diff.ip"), Tone::Warn),
        (c.tls_cert, t!("ui.servers.live.diff.tlsCert"), Tone::Warn),
        (c.asn, t!("ui.servers.live.diff.asn"), Tone::Warn),
        (c.country, t!("ui.servers.live.diff.country"), Tone::Warn),
        (
            c.latency_spike,
            t!("ui.servers.live.diff.latencySpike"),
            Tone::Fail,
        ),
        (c.ports, t!("ui.servers.live.diff.ports"), Tone::Neutral),
        (c.handshake, t!(handshake_change_key(handshake)), Tone::Warn),
        (c.egress, t!("ui.servers.live.diff.egress"), Tone::Warn),
        (c.pmtu, t!("ui.servers.live.diff.pmtu"), Tone::Neutral),
        (
            c.throughput,
            t!("ui.servers.live.diff.throughput"),
            Tone::Fail,
        ),
    ]
    .into_iter()
    .filter(|(on, _, _)| *on)
    .map(|(_, label, tone)| (label, tone))
    .collect();
    rsx! {
        DiagBox { title: t!("ui.servers.live.box.infrastructure"), dot: Dot::Ok,
            if let Some(asn) = &infra.asn {
                Kv { label: "ASN / Org:".to_owned(), mono: true, {format!("{} {}", asn.asn, asn.org)} }
            }
            if let Some(country) = &infra.endpoint_country {
                Kv { label: t!("ui.servers.live.endpointCountry"), "{country}" }
            }
            if infra.active_tunnel_matches_profile && let Some(country) = &infra.egress_country {
                Kv { label: t!("ui.servers.live.egressCountry"), {t!("ui.servers.live.egressFromProfile", country = country)} }
            }
            if !infra.shared_cidr.is_empty() {
                p { class: "srv-diag-warn", {t!("ui.servers.live.sharedCidr", count = infra.shared_cidr.len())} }
            }
            if !badges.is_empty() {
                div { class: "srv-chips",
                    for (label , tone) in badges {
                        Badge { key: "{label}", tone, "{label}" }
                    }
                }
            }
        }
    }
}
