//! The demo's fake data per scene: protection, capture, legacy state, the system report, leak
//! and route test results, repair step outcomes.
use vpnte_base::Msg;
use vpnte_base::types::{KillSwitchLevel, Verdict, now_ms};

use super::*;

pub(super) fn demo(key: &str) -> Msg {
    Msg::new(format!("ui.maintenance.demo.{key}"))
}

/// A language-neutral technical value (addresses, versions, HTTP codes).
pub(super) fn raw(text: impl ToString) -> Msg {
    demo("raw").arg("text", text)
}

pub(super) fn protection(scene: Scene) -> ProtectionView {
    let connected = scene.connected();
    let mut p = ProtectionView {
        level: KillSwitchLevel::Standard,
        kill_switch: if connected {
            KillSwitchState::Engaged
        } else {
            KillSwitchState::Armed
        },
        leak_protection_active: connected,
        dynamic_filters: if connected { 14 } else { 0 },
        persistent_filters: 0,
        bfe_running: true,
        firewall_blocks: Vec::new(),
        last_verified: Some(now_ms() - 40_000),
    };
    if scene == Scene::Problems {
        p.bfe_running = false;
        p.persistent_filters = 6;
        p.firewall_blocks = vec![
            FirewallBlock {
                profile: FwProfile::Private,
                active: true,
            },
            FirewallBlock {
                profile: FwProfile::Domain,
                active: false,
            },
        ];
    }
    p
}

pub(super) fn counted(rows: &[(&str, u64)]) -> Vec<Counted> {
    rows.iter()
        .map(|(name, count)| Counted {
            name: (*name).into(),
            count: *count,
        })
        .collect()
}

pub(super) fn capture(scene: Scene) -> CaptureView {
    let now = now_ms();
    match scene {
        Scene::Problems => CaptureView {
            available: true,
            enabled: true,
            cleanup_pending: true,
            last_error: Some(demo("captureStopError")),
            etl_bytes: Some(96 * 1024 * 1024),
            artifact_count: 7,
            ..CaptureView::default()
        },
        _ if scene.connected() => CaptureView {
            available: true,
            enabled: true,
            running: true,
            engine: Some("pktmon".into()),
            etl_bytes: Some(41_300_000),
            live_snapshot_at: Some(now - 12_000),
            artifact_count: 5,
            etw: Some(EtwView {
                running: true,
                engine: Some("etw-inproc".into()),
                data_events: 18_342,
                categories: counted(&[
                    ("udp", 2_104),
                    ("tcp", 9_870),
                    ("dns", 4_402),
                    ("wfp", 911),
                    ("afd", 640),
                    ("kernel-net", 415),
                ]),
                wfp_blocks: 37,
                top_domains: counted(&[
                    ("www.youtube.com", 412),
                    ("api.github.com", 233),
                    ("telegram.org", 190),
                    ("example.org", 61),
                ]),
                top_remotes: counted(&[
                    ("203.0.113.40:443", 812),
                    ("198.51.100.7:443", 344),
                    ("192.0.2.18:853", 120),
                ]),
                last_event_at: Some(now - 2_000),
                ..EtwView::default()
            }),
            ..CaptureView::default()
        },
        _ => CaptureView {
            available: true,
            enabled: true,
            artifact_count: 3,
            etl_bytes: Some(12_800_000),
            ..CaptureView::default()
        },
    }
}

pub(super) fn legacy(scene: Scene) -> LegacyView {
    match scene {
        Scene::Problems => LegacyView {
            data_dir: Some(LegacyDir {
                path: r"C:\Users\Demo\AppData\Roaming\vpn-tunnel-enforcer".into(),
                bytes: Some(214_000_000),
                plaintext_files: 2,
            }),
            secrets_pending: true,
            corrupt: vec![CorruptStore {
                id: "profiles".into(),
                name: demo("storeProfiles"),
                file: "profiles.json".into(),
            }],
            cleanup_failures: vec![demo("cleanupTask"), demo("cleanupAdapter")],
        },
        Scene::Default => LegacyView {
            data_dir: Some(LegacyDir {
                path: r"C:\Users\Demo\AppData\Roaming\vpn-tunnel-enforcer".into(),
                bytes: Some(38_500_000),
                plaintext_files: 0,
            }),
            ..LegacyView::default()
        },
        _ => LegacyView::default(),
    }
}

pub(super) fn initial_state(scene: Scene) -> MaintenanceState {
    MaintenanceState {
        tunnel: if scene.connected() {
            TunnelPhase::On
        } else {
            TunnelPhase::Off
        },
        protection: Some(protection(scene)),
        repair: RepairView::default(),
        capture: capture(scene),
        fault: (scene == Scene::Problems).then(|| FaultView {
            at: now_ms() - 3_600_000,
            code: "engine-exit".into(),
            detail: "sing-box exited with code 1: inbound/tun[tun-in]: configure tun interface: Access is denied.".into(),
        }),
        export: ExportView::default(),
        legacy: legacy(scene),
    }
}

pub(super) fn item(
    id: &str,
    category: DiagCategory,
    verdict: Option<Verdict>,
    value: Msg,
) -> DiagItem {
    DiagItem {
        id: id.into(),
        category,
        label: demo(&format!("label.{id}")),
        verdict,
        value,
        details: Vec::new(),
        notes: Vec::new(),
    }
}

pub(super) fn with_details(mut item: DiagItem, rows: &[&str]) -> DiagItem {
    item.details = rows.iter().map(|r| (*r).to_owned()).collect();
    item
}

/// The checklist of monitoring §3.7 as a healthy, connected machine reports it; `problems`
/// breaks DNS, an endpoint and BFE, `off` shows the stopped tunnel.
pub(in crate::maintenance) fn report(scene: Scene) -> SystemReport {
    use DiagCategory::*;
    let ok = Some(Verdict::Ok);
    let connected = scene.connected();
    let broken = scene == Scene::Problems;
    let mut items = vec![
        with_details(
            item(
                "runtime-app",
                App,
                None,
                raw("Windows 11 26300 / x64 · 2.0.0"),
            ),
            &[
                "elevated=true",
                r"dataDir=%APPDATA%\VPN Tunnel Enforcer",
                r"logDir=%APPDATA%\VPN Tunnel Enforcer\logs",
            ],
        ),
        with_details(
            item("binaries", Tun, ok, raw("sing-box 1.14.4 · xray 26.11.9")),
            &[
                "sing-box.exe 41 233 KB",
                "xray.exe 33 870 KB",
                "wintun.dll 427 KB",
                "libcronet.dll 7 912 KB",
            ],
        ),
        item(
            "runtime-tun-status",
            Tun,
            connected.then_some(Verdict::Ok),
            demo(if connected {
                "value.tunRunning"
            } else {
                "value.tunStopped"
            }),
        ),
        item("proxy-current", Proxy, None, demo("value.directVpn")),
        with_details(
            item(
                "proxy-listeners",
                Proxy,
                ok,
                demo("value.listeners").arg("count", 2),
            ),
            &[
                "xray.exe:127.0.0.1:10808 pid=4120",
                "xray.exe:127.0.0.1:10809 pid=4120",
            ],
        ),
        with_details(
            item("adapters", Network, ok, raw("2/5")),
            &[
                "Wi-Fi:Up:Intel(R) Wi-Fi 6E AX211:866 Mbps",
                "vpnte-tun:Up:Wintun Userspace Tunnel:100 Gbps",
                "Ethernet:Disconnected:Realtek PCIe GbE:0 bps",
            ],
        ),
        with_details(
            item(
                "routes",
                Network,
                connected.then_some(Verdict::Ok),
                demo(if connected {
                    "value.routesTun"
                } else {
                    "value.routesDirect"
                }),
            ),
            &[
                "0.0.0.0/0 -> Wi-Fi 192.168.1.1 metric=35",
                "0.0.0.0/1 -> vpnte-tun 172.19.0.1 metric=0",
                "128.0.0.0/1 -> vpnte-tun 172.19.0.1 metric=0",
            ],
        ),
        if broken {
            item(
                "dns-resolve",
                Network,
                Some(Verdict::Fail),
                demo("value.noAnswer"),
            )
        } else {
            with_details(
                item(
                    "dns-resolve",
                    Network,
                    ok,
                    demo("value.records").arg("count", 2),
                ),
                &[
                    "A:93.184.215.14",
                    "AAAA:2606:2800:21f:cb07:6820:80da:af6b:8b2c",
                ],
            )
        },
        item(
            "endpoint-cloudflare",
            Internet,
            ok,
            raw("HTTP 200 104.16.123.96"),
        ),
        if broken {
            with_details(
                item(
                    "endpoint-google",
                    Internet,
                    Some(Verdict::Fail),
                    demo("value.noConnection"),
                ),
                &[
                    "url=https://www.google.com/generate_204 | curl=28 | stderr=Connection timed out after 12001 milliseconds",
                ],
            )
        } else {
            item(
                "endpoint-google",
                Internet,
                ok,
                raw("HTTP 204 142.250.74.36"),
            )
        },
        item(
            "endpoint-msft",
            Internet,
            if broken { Some(Verdict::Warn) } else { ok },
            raw(if broken {
                "HTTP 503 23.215.0.136"
            } else {
                "HTTP 200 23.215.0.136"
            }),
        ),
        if broken {
            item(
                "services",
                Network,
                Some(Verdict::Fail),
                demo("value.bfeStopped"),
            )
        } else {
            item("services", Network, ok, demo("value.servicesOk"))
        },
        item(
            "event-dns-client",
            Windows,
            None,
            demo("value.events").arg("count", 3),
        ),
        item(
            "app-log",
            Logs,
            if broken { Some(Verdict::Warn) } else { ok },
            raw("1 204 · 312 KB"),
        ),
        item(
            "active-profile-capabilities",
            Profile,
            None,
            raw("vless, stealth=reality"),
        ),
        item(
            "traffic-forensics",
            Network,
            if broken { Some(Verdict::Warn) } else { ok },
            demo(if broken {
                "value.captureUnconfirmed"
            } else {
                "value.captureRunning"
            }),
        ),
    ];
    if broken && let Some(services) = items.iter_mut().find(|i| i.id == "services") {
        services.notes.push(demo("note.bfe"));
    }
    SystemReport {
        ran_at: now_ms(),
        items,
    }
}

pub(super) fn probe(
    alias: &str,
    local: &str,
    reach: ProbeReach,
    stderr: Option<&str>,
) -> AdapterProbe {
    AdapterProbe {
        alias: alias.into(),
        local: Some(local.into()),
        reach,
        stderr_tail: stderr.map(str::to_owned),
    }
}

pub(super) fn leak_result(scene: Scene) -> LeakTestView {
    let tun_ip = Some("203.0.113.40".to_owned());
    let blocked = |code| ProbeReach::NotReached { curl_exit: code };
    match scene {
        Scene::Leak => LeakTestView {
            at: now_ms(),
            verdict: LeakVerdict::Leak,
            cancelled: false,
            headline: demo("leak.leak")
                .arg("alias", "Wi-Fi")
                .arg("ip", "198.51.100.23"),
            tun_ip,
            adapters: vec![
                probe(
                    "Wi-Fi",
                    "192.168.1.34",
                    ProbeReach::Reached {
                        public_ip: "198.51.100.23".into(),
                    },
                    None,
                ),
                probe(
                    "Ethernet 2",
                    "10.0.0.15",
                    blocked(7),
                    Some(
                        "Failed to connect to 1.1.1.1 port 443 after 3 ms: Could not connect to server",
                    ),
                ),
            ],
            disagreement: None,
        },
        Scene::Inconclusive => LeakTestView {
            at: now_ms(),
            verdict: LeakVerdict::Inconclusive,
            cancelled: false,
            headline: demo("leak.unproven"),
            tun_ip,
            adapters: vec![probe(
                "Wi-Fi",
                "192.168.1.34",
                ProbeReach::Unknown {
                    curl_exit: Some(35),
                    why: demo("leak.whyTls"),
                },
                Some("schannel: failed to receive handshake, SSL/TLS connection failed"),
            )],
            disagreement: Some(
                demo("leak.disagree")
                    .arg("other", "198.51.100.23")
                    .arg("default", "203.0.113.40"),
            ),
        },
        _ => LeakTestView {
            at: now_ms(),
            verdict: LeakVerdict::Ok,
            cancelled: false,
            headline: demo("leak.ok"),
            tun_ip,
            adapters: vec![
                probe(
                    "Wi-Fi",
                    "192.168.1.34",
                    blocked(28),
                    Some("Connection timed out after 4002 milliseconds"),
                ),
                probe("Ethernet 2", "10.0.0.15", blocked(7), None),
            ],
            disagreement: None,
        },
    }
}

pub(super) fn route_result(scene: Scene) -> RouteTestView {
    if scene.connected() {
        RouteTestView {
            verdict: RouteVerdict::Ok,
            message: demo("route.ok")
                .arg("vpn", "203.0.113.40")
                .arg("direct", "198.51.100.23"),
        }
    } else {
        RouteTestView {
            verdict: RouteVerdict::TunnelOff,
            message: demo("route.off"),
        }
    }
}

/// What each repair step reports in `scene`.
pub(super) fn step_outcome(scene: Scene, step: RepairStep) -> StepOutcome {
    match (scene, step) {
        (Scene::Problems, RepairStep::Filters) => StepOutcome {
            message: Some(demo("steps.filtersRemoved").arg("count", 6)),
            ..StepOutcome::done(Vec::new())
        },
        (Scene::Problems, RepairStep::Legacy) => StepOutcome::failed(demo("steps.legacyPartial")),
        (_, RepairStep::Legacy) => StepOutcome::done(vec![r"\VPNTE\BootRecoveryTask".into()]),
        (Scene::Off, RepairStep::Engines) => StepOutcome::failed(
            demo("steps.enginesPartial")
                .arg("killed", 1)
                .arg("total", 2),
        ),
        _ => StepOutcome::done(Vec::new()),
    }
}
