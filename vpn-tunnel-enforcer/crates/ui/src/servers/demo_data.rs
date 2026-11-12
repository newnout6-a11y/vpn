//! Fake data of the demo: three groups, a recovered orphan, servers in every state, and live-check
//! receipts with every box filled. Hosts and addresses are documentation ranges (never real).
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;

use vpnte_base::Msg;
use vpnte_base::types::{ClientDevice, Engine, EnginePref, UnixMs};

use super::live_model::*;
use super::model::*;

const MIN: i64 = 60_000;
const DAY: i64 = 24 * 60 * MIN;
const GB: u64 = 1024 * 1024 * 1024;

/// A test-net address `198.51.100.n` (RFC 5737).
pub(crate) fn test_ip(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
}

/// What Auto would run for a demo protocol (the backend decides this for real rows).
fn demo_plan(protocol: &str) -> EnginePlan {
    let (engine, reason) = match protocol {
        "vless" => (Engine::Xray, "engine.xray.reason.reality"),
        _ => (Engine::SingBox, "engine.xray.reason.default"),
    };
    EnginePlan::Runs {
        engine,
        reason: Msg::new(reason),
    }
}

/// One fake server: id (its first two letters are the country), display name, protocol, last
/// octet of its address, base ping, camouflage, group.
pub(crate) struct Seed {
    pub id: &'static str,
    pub name: &'static str,
    pub protocol: &'static str,
    pub octet: u8,
    pub ping: Option<u32>,
    pub stealth: Option<Stealth>,
    pub group: Option<&'static str>,
}

pub(crate) const SEEDS: [Seed; 11] = [
    seed(
        "fr-par",
        "France · Paris",
        "trojan",
        19,
        Some(44),
        Some(Stealth::Tls),
        Some("keys"),
    ),
    seed(
        "pl-waw",
        "Poland · Warsaw",
        "hysteria2",
        72,
        Some(47),
        Some(Stealth::Obfs),
        Some("sub"),
    ),
    seed(
        "fi-hel",
        "Finland · Helsinki",
        "trojan",
        57,
        Some(54),
        Some(Stealth::Tls),
        Some("sub"),
    ),
    seed(
        "nl-ams",
        "Netherlands · Amsterdam",
        "vless",
        23,
        Some(38),
        Some(Stealth::Reality),
        Some("sub"),
    ),
    seed(
        "de-fra",
        "Germany · Frankfurt",
        "vless",
        41,
        Some(31),
        Some(Stealth::Reality),
        Some("sub"),
    ),
    seed(
        "se-sto",
        "Sweden · Stockholm",
        "vless",
        88,
        None,
        Some(Stealth::Reality),
        Some("sub"),
    ),
    seed(
        "lv-rix",
        "Latvia · Riga",
        "vless",
        64,
        Some(29),
        Some(Stealth::Reality),
        Some("sub"),
    ),
    seed(
        "tr-ist",
        "Turkey · Istanbul",
        "vmess",
        90,
        Some(96),
        Some(Stealth::Plain),
        Some("trial"),
    ),
    seed(
        "us-nyc",
        "USA · New York",
        "shadowsocks",
        120,
        None,
        None,
        Some("keys"),
    ),
    seed(
        "jp-tyo",
        "Japan · Tokyo",
        "vless",
        133,
        Some(212),
        Some(Stealth::Utls),
        Some("keys"),
    ),
    seed(
        "kz-ala",
        "Kazakhstan · Almaty",
        "trojan",
        151,
        Some(78),
        Some(Stealth::Tls),
        Some("gone"),
    ),
];

const fn seed(
    id: &'static str,
    name: &'static str,
    protocol: &'static str,
    octet: u8,
    ping: Option<u32>,
    stealth: Option<Stealth>,
    group: Option<&'static str>,
) -> Seed {
    Seed {
        id,
        name,
        protocol,
        octet,
        ping,
        stealth,
        group,
    }
}

impl Seed {
    /// Fake host: `nl-ams.vpn.example.net`.
    pub(crate) fn host(&self) -> String {
        format!("{}.vpn.example.net", self.id)
    }

    fn server(&self, now: UnixMs) -> ServerView {
        let online = self.ping.is_some();
        ServerView {
            id: self.id.into(),
            name: self.name.into(),
            protocol: self.protocol.into(),
            host: self.host(),
            port: if self.protocol == "shadowsocks" {
                8388
            } else {
                443
            },
            resolved_ip: Some(test_ip(self.octet)),
            country: self.id.get(..2).map(str::to_ascii_uppercase),
            exit_ip: None,
            device: ClientDevice::Pc,
            engine: EnginePref::Auto,
            engine_plan: Some(demo_plan(self.protocol)),
            fingerprint: None,
            has_outbound: true,
            stealth: self.stealth,
            ping_ms: self.ping,
            status: if online {
                OnlineStatus::Online
            } else {
                OnlineStatus::Offline
            },
            health: None,
            verdict: None,
            group_id: self.group.map(Into::into),
            last_seen_in_subscription_at: Some(now - 30 * MIN),
            archived: None,
            enabled: true,
        }
    }
}

/// A classifier verdict as the app projects it (the sentences are the probes' keys).
pub(crate) fn demo_verdict(
    kind: VerdictKind,
    advice: Option<VerdictAdvice>,
    at: UnixMs,
) -> CheckVerdict {
    let detail = match kind {
        VerdictKind::Healthy => "probes.verdict.healthy",
        VerdictKind::Frozen => "probes.verdict.frozen",
        VerdictKind::KeyRejected => "probes.verdict.keyRejected",
        VerdictKind::IpBanned => "probes.verdict.ipBanned",
        _ => "probes.verdict.notVerified",
    };
    CheckVerdict {
        kind,
        advice,
        detail: Msg::new(detail),
        advice_detail: advice.map(|_| Msg::new("probes.reaction.switchServer")),
        checked_at: at,
    }
}

/// The demo store at `now`.
pub(crate) fn demo_view(now: UnixMs) -> ServersView {
    let mut servers: Vec<ServerView> = SEEDS.iter().map(|s| s.server(now)).collect();
    for s in &mut servers {
        match s.id.as_str() {
            // the exit is a different address than the entry bridge (relay)
            "nl-ams" => s.exit_ip = Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 47))),
            "lv-rix" => {
                s.archived = Some(Archive {
                    reason: ArchiveReason::Provider,
                    at: now - 2 * DAY,
                    purge_at: now + 28 * DAY,
                })
            }
            // removed by the user three days ago: restorable until the purge
            "fr-par" => {
                s.archived = Some(Archive {
                    reason: ArchiveReason::User,
                    at: now - 3 * DAY,
                    purge_at: now + 27 * DAY,
                })
            }
            "jp-tyo" => s.enabled = false,
            "us-nyc" => {
                s.health = Some(KeyHealth {
                    online: false,
                    latency_ms: None,
                    reason: Some(KeyHealthReason::AuthFailed),
                    checked_at: now - 3 * 60 * MIN,
                });
                s.verdict = Some(demo_verdict(
                    VerdictKind::KeyRejected,
                    None,
                    now - 3 * 60 * MIN,
                ));
                s.device = ClientDevice::Android;
            }
            "de-fra" => {
                s.health = Some(KeyHealth {
                    online: true,
                    latency_ms: Some(420),
                    reason: None,
                    checked_at: now - 50 * MIN,
                });
                s.verdict = Some(demo_verdict(VerdictKind::Healthy, None, now - 50 * MIN));
            }
            // the RU network discipline in the list: a frozen host and a banned address
            "se-sto" => {
                let advice = Some(VerdictAdvice::SwitchServer);
                s.verdict = Some(demo_verdict(VerdictKind::Frozen, advice, now - 12 * MIN));
            }
            "tr-ist" => {
                let advice = Some(VerdictAdvice::SwitchServer);
                s.verdict = Some(demo_verdict(VerdictKind::IpBanned, advice, now - 40 * MIN));
            }
            _ => {}
        }
    }
    ServersView {
        loaded: true,
        servers,
        groups: demo_groups(now),
        active_id: Some("nl-ams".into()),
        switching_to: None,
        tunnel_running: true,
        tunnel_busy: false,
        foreign_vpn: false,
        geo_lookup_disabled: false,
    }
}

fn demo_groups(now: UnixMs) -> Vec<GroupView> {
    vec![
        GroupView {
            id: "sub".into(),
            name: "Demo subscription".into(),
            source: GroupSource::Subscription,
            status: GroupStatus::Active,
            imported_at: now - 40 * DAY,
            last_fetched_at: Some(now - 30 * MIN),
            last_fetch_attempt_at: Some(now - 30 * MIN),
            last_fetch_error: None,
            traffic_used: Some(48 * GB + GB / 3),
            traffic_total: Some(200 * GB),
            expires_at: Some(now + 19 * DAY),
            web_page_url: Some("https://panel.example.net/account".into()),
            refresh_minutes: None,
        },
        GroupView {
            id: "trial".into(),
            name: "Trial VPN".into(),
            source: GroupSource::Subscription,
            status: GroupStatus::Expired,
            imported_at: now - 9 * DAY,
            last_fetched_at: Some(now - 2 * DAY),
            last_fetch_attempt_at: Some(now - 2 * 60 * MIN),
            last_fetch_error: Some(FetchError::Empty),
            traffic_used: Some(11 * GB),
            traffic_total: Some(10 * GB),
            expires_at: Some(now - 2 * DAY),
            web_page_url: None,
            refresh_minutes: NonZeroU32::new(120),
        },
        GroupView {
            id: "keys".into(),
            name: "Ручные ключи".into(),
            source: GroupSource::Manual,
            status: GroupStatus::Unknown,
            imported_at: now - 60 * DAY,
            ..GroupView::default()
        },
    ]
}

/// A receipt for `server` as the probe would return it (`n` varies the numbers per run).
pub(crate) fn demo_check(server: &ServerView, mode: LiveMode, n: u64, now: UnixMs) -> LiveCheck {
    let extended = mode == LiveMode::Extended;
    let base = server.ping_ms.unwrap_or(60) + (n % 7) as u32;
    let ip = server
        .resolved_ip
        .map_or_else(|| "198.51.100.9".to_owned(), |ip| ip.to_string());
    let reality = server.stealth == Some(Stealth::Reality);
    let duration_ms = if extended { 14_200 } else { 4_100 };
    LiveCheck {
        id: format!("op_demo{n:04}"),
        profile_id: Some(server.id.clone()),
        host: server.host.clone(),
        port: server.port,
        mode,
        started_at: now - i64::from(duration_ms),
        finished_at: now,
        duration_ms,
        cancelled: false,
        tunnel_running: Some(true),
        dns: DnsDiag {
            status: StageStatus::Ok,
            duration_ms: 45,
            a: vec![ip.clone()],
            aaaa: Vec::new(),
            cname_chain: if extended { vec![format!("edge-{}.cdn.example.net", server.id)] } else { Vec::new() },
            ttl: Some(300),
            reverse_dns: vec![format!("static-{}.hoster.example", ip.replace('.', "-"))],
            resolvers: vec![
                ResolverAnswer { name: "System".into(), status: StageStatus::Ok, authenticated: false, duration_ms: 12, records: vec![ip.clone()], error: None },
                ResolverAnswer { name: "Cloudflare DoH".into(), status: StageStatus::Ok, authenticated: true, duration_ms: 38, records: vec![ip.clone()], error: None },
                ResolverAnswer { name: "Quad9 DoH".into(), status: StageStatus::Warning, authenticated: false, duration_ms: 97, records: Vec::new(), error: Some("AAAA timed out".into()) },
            ],
            discrepancies: Vec::new(),
        },
        reachability: Reachability { status: StageStatus::Ok, duration_ms: 80, tcp_reachable: true, error: None },
        latency: Some(LatencyStats {
            min: base - 4,
            avg: base,
            median: base - 1,
            max: base + 7,
            jitter: 4,
            loss: if n.is_multiple_of(3) { 0.2 } else { 0.0 },
            samples: vec![base - 4, base - 1, base, base + 3, base + 7],
            attempted: Some(5),
            succeeded: Some(if n.is_multiple_of(3) { 4 } else { 5 }),
        }),
        tls: Some(TlsDiag {
            status: StageStatus::Ok,
            duration_ms: 120,
            subject: Some(if reality { "CN=www.microsoft.com".into() } else { format!("CN={}", server.host) }),
            issuer: Some("C=US, O=Example Trust Services, CN=Example TLS RSA CA G1".into()),
            valid_to: Some("2027-02-19".into()),
            days_remaining: Some(100),
            protocol: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            alpn: Some("h2".into()),
            hostname_verified: Some(!reality),
            authorized: Some(true),
            authorization_error: None,
            fingerprint: Some("5E:21:9A:0C:44:7B:DE:13:90:AF:62:18:C3:7D:0B:E4:91:2A:6F:58:33:C1:07:9E:AB:4D:12:F0:66:8E:25:B7".into()),
        }),
        http: Some(HttpDiag { status: StageStatus::Ok, duration_ms: 210, status_code: Some(200), target_port: Some(443), is_tls: true, server_header: Some("nginx".into()), via_header: None, location_header: None }),
        open_ports: if extended {
            vec![
                PortProbe { port: 80, service: Some("HTTP".into()), state: PortStatus::Closed },
                PortProbe { port: 443, service: Some("HTTPS".into()), state: PortStatus::Open },
                PortProbe { port: 2053, service: None, state: PortStatus::Filtered },
            ]
        } else {
            Vec::new()
        },
        ports_error: None,
        route: extended.then(|| RouteDiag {
            status: StageStatus::Ok,
            duration_ms: 6_100,
            hops: Some(4),
            reached_target: Some(n.is_multiple_of(2)),
            hop_lines: vec![
                "1 <1 ms <1 ms <1 ms 192.168.1.1".into(),
                "2 4 ms 3 ms 4 ms 10.20.0.1".into(),
                "3 12 ms 11 ms 13 ms 203.0.113.9".into(),
                format!("4 {base} ms {} ms {base} ms {ip}", base + 2),
            ],
            error: None,
        }),
        infrastructure: Some(Infrastructure {
            asn: Some(AsnInfo { asn: "AS64500".into(), org: "Example Hosting B.V.".into(), network: Some("198.51.100.0/24".into()), country: server.country.clone() }),
            endpoint_country: server.country.clone(),
            egress_country: server.country.clone(),
            active_tunnel_matches_profile: true,
            shared_cidr: vec!["de-fra".into(), "se-sto".into()],
            changes: Changes { tls_cert: n % 2 == 1, latency_spike: n % 4 == 3, ..Changes::default() },
            error: (n % 5 == 4).then(|| "Request failed with status code 429".into()),
        }),
        handshake: Some(Handshake {
            status: HandshakeStatus::Ok,
            duration_ms: Some(1_426),
            protocol: Some(server.protocol.clone()),
            evidence: Some("CONNECT 1.1.1.1:443 via 127.0.0.1:2080 → 200".into()),
            error: None,
        }),
        egress: Some(Egress {
            status: StageStatus::Ok,
            duration_ms: 900,
            exit_ipv4: Some("203.0.113.47".into()),
            exit_ipv6: None,
            ipv6_unsupported: true,
            country: server.country.clone(),
            matches_endpoint: Some(false),
            underlay: Some("route-selected".into()),
            reflectors: vec![
                Reflector { source: "ipify".into(), ip: Some("203.0.113.47".into()), country: server.country.clone(), error: None },
                Reflector { source: "ifconfig.co".into(), ip: Some("203.0.113.47".into()), country: None, error: None },
            ],
            error: None,
        }),
        path: Some(PathDiag {
            status: StageStatus::Ok,
            interface_alias: Some(if n.is_multiple_of(2) { "Ethernet".into() } else { "Ethernet\u{FFFD}".into() }),
            interface_index: Some(12),
            is_tun: false,
            next_hop: Some("192.168.1.1".into()),
            local_ip: Some("192.168.1.34".into()),
            error: None,
        }),
        pmtu: extended.then_some(PmtuDiag {
            status: PmtuStatus::LowerBound,
            pmtu: Some(1452),
            min_tested: Some(1280),
            max_tested: Some(1500),
            method: PmtuMethod::IcmpDf,
            detail: None,
            error: None,
        }),
        media: Some(MediaDiag {
            status: StageStatus::Ok,
            hls_reachable: true,
            quic_guarded: true,
            error_2000_risk: false,
            endpoints: vec![MediaEndpoint { endpoint: "usher.ttvnw.net (HLS Origin)".into(), reachable: true, latency_ms: Some(45), error: None }],
            detail: None,
            error: None,
        }),
        throughput: extended.then(|| demo_throughput(n)),
        split_tunnel: None,
        deferred: None,
        findings: demo_findings(n),
    }
}

fn demo_throughput(n: u64) -> Throughput {
    let median = 38.0 + (n % 9) as f64 * 6.5;
    let shaky = n % 4 == 1;
    Throughput {
        status: if shaky {
            StageStatus::Warning
        } else {
            StageStatus::Ok
        },
        route: Some(ThroughputRoute::PhysicalDirect),
        median_mbps: Some(median),
        min_mbps: Some(median * 0.8),
        max_mbps: Some(median * if shaky { 1.6 } else { 1.15 }),
        variability_pct: Some(if shaky { 47.0 } else { 12.5 }),
        stall_count: Some(u32::from(shaky)),
        max_gap_ms: Some(if shaky { 910 } else { 220 }),
        samples: (0..3)
            .map(|i| ThroughputSample {
                mbps: median + f64::from(i) * 1.7 - 1.7,
                bytes: 8 * 1024 * 1024,
                duration_ms: 1_700 + i * 40,
                ttfb_ms: Some(140 + i * 12),
                stalls: u32::from(shaky && i == 1),
                max_gap_ms: if shaky && i == 1 { 910 } else { 180 + i * 20 },
            })
            .collect(),
        detail: None,
        error: None,
    }
}

fn demo_findings(n: u64) -> Vec<Finding> {
    let mut out = vec![Finding {
        code: "DNS_MULTI_RESOLVER".into(),
        severity: Severity::Info,
        title: Msg::new("ui.servers.demo.finding.dnsTitle"),
        detail: Msg::new("ui.servers.demo.finding.dnsDetail"),
    }];
    if n % 2 == 1 {
        out.push(Finding {
            code: "TLS_CERT_CHANGED".into(),
            severity: Severity::Warning,
            title: Msg::new("ui.servers.demo.finding.certTitle"),
            detail: Msg::new("ui.servers.demo.finding.certDetail"),
        });
    }
    out
}
