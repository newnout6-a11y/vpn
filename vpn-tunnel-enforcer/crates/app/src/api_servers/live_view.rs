//! A stored live check (`vpnte_probes::live::LiveCheck`) as the Servers page renders it. Texts
//! the probes keep as `Msg` (notes, details, discrepancies) are rendered in the UI language where
//! the page wants plain strings; finding titles and details stay `Msg`. Imported rows carry
//! literal texts (`Text::Legacy`), shown as they are.
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_probes::live::{self as live, CheckMode, EngineRoute, TunnelState};
use vpnte_probes::live_stages::dns::{
    DnsRecordType, DnsResolverComparison, ResolverStatus, resolver_label,
};
use vpnte_probes::live_stages::tcp::PortState;
use vpnte_probes::live_stages::{self as stages, Text, TimedStatus};
use vpnte_ui::servers as ui;

/// The page's receipt of `c`.
pub(super) fn check(c: &live::LiveCheck, lang: Lang) -> ui::LiveCheck {
    let self_probe = c
        .handshake
        .as_ref()
        .is_some_and(|h| h.route == Some(EngineRoute::ActiveTunnel));
    let deferred = deferred_note(c);
    ui::LiveCheck {
        id: c.id.clone(),
        profile_id: c.profile_id.clone(),
        host: c.host.clone(),
        port: c.port,
        mode: match c.mode {
            CheckMode::Basic => ui::LiveMode::Basic,
            CheckMode::Extended => ui::LiveMode::Extended,
        },
        started_at: c.started_at,
        finished_at: c.finished_at,
        duration_ms: ms(c.duration_ms),
        cancelled: c.cancelled,
        tunnel_running: c.tunnel.map(|t| t.state == TunnelState::Up),
        dns: dns(&c.dns, &c.reverse_dns, lang),
        reachability: ui::Reachability {
            status: timed(c.reachability.timed.status),
            duration_ms: ms(c.reachability.timed.duration_ms),
            tcp_reachable: c.reachability.tcp_reachable,
            error: c.reachability.timed.error.clone(),
        },
        latency: c.latency.as_ref().map(latency),
        tls: c.tls.as_ref().map(tls),
        http: c.http.as_ref().map(|h| ui::HttpDiag {
            status: timed(h.timed.status),
            duration_ms: ms(h.timed.duration_ms),
            status_code: h.status_code,
            target_port: Some(h.target_port),
            is_tls: h.is_tls,
            server_header: h.server_header.clone(),
            via_header: h.via_header.clone(),
            location_header: h.location_header.clone(),
        }),
        open_ports: c.open_ports.iter().flatten().map(port).collect(),
        ports_error: c.ports_error.clone(),
        route: c.route.as_ref().map(|r| ui::RouteDiag {
            status: timed(r.timed.status),
            duration_ms: ms(r.timed.duration_ms),
            hops: r.hops,
            reached_target: r.reached_target,
            hop_lines: r.hop_details.clone(),
            error: r.timed.error.clone(),
        }),
        infrastructure: c
            .infrastructure
            .as_ref()
            .map(|i| infrastructure(i, c.asn.as_ref(), self_probe, c.egress.as_ref(), lang)),
        handshake: c.handshake.as_ref().map(|h| handshake(h, lang)),
        egress: c.egress.as_ref().map(|e| egress(e, deferred.is_some())),
        path: c.path_diagnostics.as_ref().map(|p| path(p, lang)),
        pmtu: c.pmtu.as_ref().map(|p| pmtu(p, lang)),
        media: c.media_stream.as_ref().map(|m| media(m, lang)),
        throughput: c.throughput.as_ref().map(|t| throughput(t, lang)),
        split_tunnel: c.split_tunnel.as_ref().map(|s| split(s, lang)),
        deferred: deferred.map(|t| text(t, lang)),
        findings: c.findings.iter().map(finding).collect(),
    }
}

/// The probes' note that counts the requests the server's handshake budget left out.
const DEFERRED_NOTE: &str = "probes.discipline.liveDeferred";

fn is_deferred(t: &Text) -> bool {
    matches!(t, Text::Msg(m) if m.key == DEFERRED_NOTE)
}

/// The budget note wherever the probes put it: the handshake's note, or the media box's detail
/// when no media request was made.
fn deferred_note(c: &live::LiveCheck) -> Option<&Text> {
    let handshake = c.handshake.as_ref().and_then(|h| h.note.as_ref());
    let media = c.media_stream.as_ref().and_then(|m| m.detail.as_ref());
    handshake
        .filter(|t| is_deferred(t))
        .or(media.filter(|t| is_deferred(t)))
}

/// Durations are shown in milliseconds; a `u64` beyond `u32` is not a real measurement.
pub(super) fn ms(v: u64) -> u32 {
    u32::try_from(v).unwrap_or(u32::MAX)
}

pub(super) fn timed(s: TimedStatus) -> ui::StageStatus {
    match s {
        TimedStatus::Ok => ui::StageStatus::Ok,
        TimedStatus::Error => ui::StageStatus::Error,
        TimedStatus::Skipped => ui::StageStatus::Skipped,
        TimedStatus::NotChecked => ui::StageStatus::NotChecked,
    }
}

/// A stored text as a plain string in `lang`.
pub(super) fn text(t: &Text, lang: Lang) -> String {
    match t {
        Text::Msg(m) => m.render(lang),
        Text::Legacy(s) => s.clone(),
    }
}

/// A stored text as a `Msg` (imported rows: the literal through `app.live.text`).
pub(super) fn msg(t: &Text) -> Msg {
    match t {
        Text::Msg(m) => m.clone(),
        Text::Legacy(s) => Msg::new("app.live.text").arg("text", s),
    }
}

fn dns(d: &stages::DnsDiagnostics, reverse: &[String], lang: Lang) -> ui::DnsDiag {
    ui::DnsDiag {
        status: timed(d.timed.status),
        duration_ms: ms(d.timed.duration_ms),
        a: d.a.clone(),
        aaaa: d.aaaa.clone(),
        cname_chain: d.cname_chain.clone(),
        ttl: d.ttl,
        reverse_dns: reverse.to_vec(),
        resolvers: d.resolvers.iter().map(|r| resolver(r, lang)).collect(),
        discrepancies: d.discrepancies.iter().map(|t| text(t, lang)).collect(),
    }
}

fn resolver(r: &DnsResolverComparison, lang: Lang) -> ui::ResolverAnswer {
    ui::ResolverAnswer {
        name: text(&resolver_label(&r.resolver_id), lang),
        status: match r.status {
            ResolverStatus::Ok => ui::StageStatus::Ok,
            ResolverStatus::Partial => ui::StageStatus::Warning,
            ResolverStatus::Error => ui::StageStatus::Error,
            ResolverStatus::Timeout => ui::StageStatus::Timeout,
            ResolverStatus::Skipped => ui::StageStatus::Skipped,
        },
        authenticated: r.authenticated_data.unwrap_or(false),
        duration_ms: ms(r.duration_ms),
        records: r
            .records
            .iter()
            .map(|e| {
                let kind = match e.kind {
                    DnsRecordType::A => "A",
                    DnsRecordType::Aaaa => "AAAA",
                    DnsRecordType::Cname => "CNAME",
                    DnsRecordType::Ptr => "PTR",
                };
                format!("{kind} {}", e.value)
            })
            .collect(),
        error: r.error.clone(),
    }
}

fn latency(l: &stages::LatencyStats) -> ui::LatencyStats {
    ui::LatencyStats {
        min: ms(l.min),
        avg: ms(l.avg),
        median: ms(l.median),
        max: ms(l.max),
        jitter: ms(l.jitter),
        loss: l.loss,
        samples: l.samples.iter().map(|&s| ms(s)).collect(),
        attempted: Some(l.samples_attempted),
        succeeded: u32::try_from(l.samples.len()).ok(),
    }
}

fn tls(t: &stages::TlsInfo) -> ui::TlsDiag {
    ui::TlsDiag {
        status: timed(t.timed.status),
        duration_ms: ms(t.timed.duration_ms),
        subject: t.subject.clone(),
        issuer: t.issuer.clone(),
        valid_to: t.valid_to.clone(),
        days_remaining: t.days_remaining,
        protocol: t.protocol.clone(),
        cipher: t.cipher.clone(),
        alpn: t.alpn.clone(),
        hostname_verified: t.hostname_verified,
        authorized: t.authorized,
        authorization_error: t.authorization_error.clone(),
        fingerprint: t.fingerprint.clone(),
    }
}

fn port(p: &stages::PortItem) -> ui::PortProbe {
    ui::PortProbe {
        port: p.port,
        service: p.service.clone(),
        state: match p.state {
            PortState::Open => ui::PortStatus::Open,
            PortState::Closed => ui::PortStatus::Closed,
            PortState::Filtered => ui::PortStatus::Filtered,
            PortState::Timeout => ui::PortStatus::Timeout,
        },
    }
}

/// ASN, countries and the diff. The exit country is shown only when the active tunnel runs the
/// checked profile (the self-probe measured exactly that exit).
fn infrastructure(
    i: &stages::Infrastructure,
    asn: Option<&stages::AsnInfo>,
    self_probe: bool,
    egress: Option<&live::Egress>,
    lang: Lang,
) -> ui::Infrastructure {
    let changes = i.changes_from_previous.clone().unwrap_or_default();
    let flag = |v: Option<bool>| v.unwrap_or(false);
    ui::Infrastructure {
        asn: i.asn.as_ref().or(asn).map(|a| ui::AsnInfo {
            asn: a.asn.clone(),
            org: a.org.clone(),
            network: Some(a.network.clone()).filter(|n| !n.is_empty()),
            country: a
                .country_code
                .clone()
                .or_else(|| Some(a.country.clone()).filter(|c| !c.is_empty())),
        }),
        endpoint_country: i.endpoint_country.clone(),
        egress_country: egress
            .filter(|_| self_probe)
            .and_then(|e| e.country.clone()),
        active_tunnel_matches_profile: self_probe,
        shared_cidr: i.shared_cidr_with_profiles.clone(),
        changes: ui::Changes {
            ip: flag(changes.ip_changed),
            tls_cert: flag(changes.tls_cert_changed),
            asn: flag(changes.asn_changed),
            country: flag(changes.country_changed),
            latency_spike: flag(changes.latency_spike),
            ports: flag(changes.ports_changed),
            handshake: flag(changes.handshake_changed),
            egress: flag(changes.egress_changed),
            pmtu: flag(changes.pmtu_changed),
            throughput: flag(changes.throughput_changed),
        },
        error: i.error.as_ref().map(|t| text(t, lang)),
    }
}

fn handshake(h: &live::Handshake, lang: Lang) -> ui::Handshake {
    use live::HandshakeStatus as S;
    let status = match h.status {
        S::Ok => ui::HandshakeStatus::Ok,
        S::AuthFailed => ui::HandshakeStatus::AuthFailed,
        S::TransportFailed => ui::HandshakeStatus::TransportFailed,
        S::Timeout => ui::HandshakeStatus::Timeout,
        S::Unsupported => ui::HandshakeStatus::Unsupported,
        S::Skipped | S::NotChecked => ui::HandshakeStatus::Skipped,
    };
    let ran = !matches!(h.status, S::Skipped | S::NotChecked);
    ui::Handshake {
        status,
        duration_ms: ran.then(|| ms(h.duration_ms)),
        protocol: h.protocol.clone(),
        // The budget note has its own line in the receipt: it is not evidence of a handshake.
        evidence: h
            .evidence
            .as_ref()
            .and_then(|e| e.detail.clone())
            .or_else(|| {
                let note = h.note.as_ref().filter(|t| !is_deferred(t));
                note.map(|t| text(t, lang))
            }),
        error: h.error.clone(),
    }
}

/// `deferred`: the budget left requests of this check out. No reflector row then means none was
/// dialled: skipped, not an error of the server.
fn egress(e: &live::Egress, deferred: bool) -> ui::Egress {
    use live::EgressStatus as S;
    ui::Egress {
        status: match e.status {
            _ if deferred && e.reflectors.is_empty() => ui::StageStatus::Skipped,
            S::Ok => ui::StageStatus::Ok,
            S::Partial => ui::StageStatus::Warning,
            S::Error => ui::StageStatus::Error,
            S::Skipped => ui::StageStatus::Skipped,
            S::Timeout => ui::StageStatus::Timeout,
            S::NotChecked => ui::StageStatus::NotChecked,
        },
        duration_ms: ms(e.duration_ms),
        exit_ipv4: e.exit_ipv4.clone(),
        exit_ipv6: e.exit_ipv6.clone(),
        ipv6_unsupported: e.ipv6_status == Some(live::Ipv6Status::Unsupported),
        country: e.country.clone(),
        matches_endpoint: e.matches_endpoint,
        // The probes do not tell the underlay apart (`unknown` is not shown).
        underlay: None,
        reflectors: e
            .reflectors
            .iter()
            .map(|r| ui::Reflector {
                source: r.source.clone(),
                ip: r.ip.clone(),
                country: r.country.clone(),
                error: r.error.clone(),
            })
            .collect(),
        error: e.error.clone(),
    }
}

fn path(p: &stages::PathInfo, lang: Lang) -> ui::PathDiag {
    use stages::path::PathStatus as S;
    ui::PathDiag {
        status: match p.status {
            S::Ok => ui::StageStatus::Ok,
            S::Error => ui::StageStatus::Error,
            S::Skipped => ui::StageStatus::Skipped,
            S::NotChecked => ui::StageStatus::NotChecked,
        },
        interface_alias: p.active_interface_alias.clone(),
        interface_index: p.active_interface_index,
        is_tun: p.is_tun_interface,
        next_hop: p.next_hop.clone(),
        local_ip: p.active_local_ip.clone(),
        error: p.error.as_ref().map(|t| text(t, lang)),
    }
}

fn pmtu(p: &stages::Pmtu, lang: Lang) -> ui::PmtuDiag {
    use stages::icmp::{PmtuMethod as M, PmtuStatus as S};
    ui::PmtuDiag {
        status: match p.status {
            S::Ok => ui::PmtuStatus::Ok,
            S::LowerBound => ui::PmtuStatus::LowerBound,
            S::BlackholeSuspected => ui::PmtuStatus::BlackholeSuspected,
            S::IcmpBlocked => ui::PmtuStatus::IcmpBlocked,
            S::Skipped | S::NotChecked => ui::PmtuStatus::Skipped,
        },
        pmtu: p.pmtu,
        min_tested: p.min_tested,
        max_tested: p.max_tested,
        method: match p.method {
            M::IcmpDf => ui::PmtuMethod::IcmpDf,
            M::InterfaceNlmtu => ui::PmtuMethod::InterfaceMtu,
            M::Fallback => ui::PmtuMethod::Other("fallback".into()),
        },
        detail: p.detail.as_ref().map(|t| text(t, lang)),
        error: p.error.clone(),
    }
}

fn media(m: &live::MediaStream, lang: Lang) -> ui::MediaDiag {
    use live::MediaStatus as S;
    ui::MediaDiag {
        status: match m.status {
            S::Ok => ui::StageStatus::Ok,
            S::Warning => ui::StageStatus::Warning,
            S::Error => ui::StageStatus::Error,
            S::Skipped => ui::StageStatus::Skipped,
            S::NotChecked => ui::StageStatus::NotChecked,
        },
        hls_reachable: m.twitch_hls_reachable.unwrap_or(false),
        quic_guarded: m.quic_fallback_guarded.unwrap_or(false),
        error_2000_risk: m.error2000_risk.unwrap_or(false),
        endpoints: m
            .tested_endpoints
            .iter()
            .map(|e| ui::MediaEndpoint {
                endpoint: e.endpoint.clone(),
                reachable: e.reachable,
                latency_ms: e.latency_ms.map(ms),
                error: e.error.clone(),
            })
            .collect(),
        detail: m.detail.as_ref().map(|t| text(t, lang)),
        error: m.error.clone(),
    }
}

fn throughput(t: &live::Throughput, lang: Lang) -> ui::Throughput {
    use live::ThroughputStatus as S;
    ui::Throughput {
        status: match t.status {
            S::Ok => ui::StageStatus::Ok,
            S::Warning => ui::StageStatus::Warning,
            S::Error => ui::StageStatus::Error,
            S::Skipped => ui::StageStatus::Skipped,
            S::NotChecked => ui::StageStatus::NotChecked,
        },
        route: t.route.map(|r| match r {
            EngineRoute::PhysicalDirect => ui::ThroughputRoute::PhysicalDirect,
            EngineRoute::ActiveTunnelDirectDetour => ui::ThroughputRoute::DirectDetour,
            EngineRoute::ActiveTunnel => ui::ThroughputRoute::ActiveProfileSelf,
        }),
        median_mbps: t.median_mbps,
        min_mbps: t.min_mbps,
        max_mbps: t.max_mbps,
        variability_pct: t.variability_pct.map(f64::from),
        stall_count: t.stall_count,
        max_gap_ms: t.max_inter_chunk_gap_ms.map(ms),
        samples: t
            .samples
            .iter()
            .map(|s| ui::ThroughputSample {
                mbps: s.throughput_mbps,
                bytes: s.bytes,
                duration_ms: ms(s.duration_ms),
                ttfb_ms: s.ttfb_ms.map(ms),
                stalls: s.stall_count,
                max_gap_ms: ms(s.max_inter_chunk_gap_ms),
            })
            .collect(),
        detail: t.detail.as_ref().map(|d| text(d, lang)),
        error: t.error.clone(),
    }
}

fn split(s: &live::SplitTunnel, lang: Lang) -> ui::SplitTunnelDiag {
    use live::SplitTunnelStatus as S;
    ui::SplitTunnelDiag {
        status: match s.status {
            S::Ok => ui::StageStatus::Ok,
            S::Warning => ui::StageStatus::Warning,
            S::Error => ui::StageStatus::Error,
            S::Skipped => ui::StageStatus::Skipped,
        },
        enabled: s.enabled,
        direct: s.direct_process_names.clone(),
        vpn: s.vpn_process_names.clone(),
        duplicates: s.duplicate_process_names.clone(),
        default_outbound: s.default_outbound.clone(),
        detail: s.detail.as_ref().map(|t| text(t, lang)),
        error: s.error.clone(),
    }
}

fn finding(f: &live::Finding) -> ui::Finding {
    ui::Finding {
        // The stored code string (`TCP_UNREACHABLE`, ...): its serde name.
        code: match serde_json::to_value(f.code) {
            Ok(serde_json::Value::String(code)) => code,
            _ => "OTHER".into(),
        },
        severity: match f.severity {
            live::Severity::Info => ui::Severity::Info,
            live::Severity::Warning => ui::Severity::Warning,
            live::Severity::Error => ui::Severity::Error,
        },
        title: msg(&f.title),
        detail: msg(&f.detail),
    }
}
