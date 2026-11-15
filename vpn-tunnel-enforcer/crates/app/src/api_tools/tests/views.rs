//! Pure parts: the probes' records as the pages show them (monitoring §6.5 / §6.6 mapping of
//! ui-tools), the Soft side swap (NOADMIN §2), the session kinds and the history notice.
use std::net::IpAddr;

use vpnte_base::Msg;
use vpnte_base::types::Loopback;
use vpnte_core::store::Store;
use vpnte_probes::availability::{
    AvailabilityResult, AvailabilityVerdict, DnsStage, ErrorCode, GeoInfo, HttpStage, PathReport,
    PathSource, Recommendation, Stage, TcpStage, TlsStage, UrlChecks,
};
use vpnte_probes::diagnostics::{RoutingResult, RoutingVerdict, SmartRuCheck};
use vpnte_probes::speedtest::{self as probe, Egress, TransportWarning};
use vpnte_tunnel::api::{CaptureKind, ProxyEndpoint, SessionEndpoints, TunStatus};
use vpnte_ui::availability as ui;
use vpnte_ui::speedtest as ui_speed;

use super::super::Session;
use super::super::availability::soft_sides;
use super::super::project::{
    availability_state, routing_report, speed_progress, speed_result, url_check,
};
use crate::api_settings::test_support::TempDir;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

/// A native measurement that reached the origin over HTTPS.
fn native_ok() -> PathReport {
    PathReport {
        available: true,
        total_ms: Some(120),
        dns: Some(DnsStage {
            resolved: true,
            ips: vec![ip("203.0.113.5"), ip("2001:db8::5")],
            ms: Some(3),
            poisoned: false,
        }),
        tcp: Some(TcpStage {
            connected: true,
            ms: Some(10),
        }),
        tls: Some(TlsStage {
            handshake_ok: true,
            ms: Some(20),
            protocol: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_128_GCM_SHA256".into()),
        }),
        http: Some(HttpStage {
            status: Some(200),
            ms: Some(40),
            server: Some("gws".into()),
        }),
        geo: Some(GeoInfo {
            country: Some("NL".into()),
            org: None,
        }),
        ..PathReport::new(PathSource::Native)
    }
}

/// A native measurement whose TLS handshake was cut (DPI by SNI).
fn native_tls_cut() -> PathReport {
    PathReport {
        available: false,
        total_ms: Some(30),
        error_stage: Some(Stage::Tls),
        error: Some(ErrorCode::ConnReset),
        tls: Some(TlsStage {
            handshake_ok: false,
            ms: None,
            protocol: None,
            cipher: None,
        }),
        http: None,
        geo: None,
        ..native_ok()
    }
}

/// One HTTP request through a loopback inbound that answered 200.
fn inbound_ok() -> PathReport {
    PathReport {
        available: true,
        total_ms: Some(90),
        http: Some(HttpStage {
            status: Some(200),
            ms: Some(90),
            server: Some("cloudflare".into()),
        }),
        ..PathReport::new(PathSource::DirectInbound)
    }
}

fn result(protected: Option<PathReport>, direct: Option<PathReport>) -> AvailabilityResult {
    AvailabilityResult {
        id: "c-1".into(),
        url: "https://example.com/".into(),
        tested_at: 1_700_000_000_000,
        tunnel_active: protected.is_some(),
        protected,
        direct,
        verdict: AvailabilityVerdict::Unknown,
        recommendation: Recommendation::Incomplete,
    }
}

/// AT-07-003 / B-UA-3: every stage reaches the page; a failed side carries the probes'
/// sentence, an unmeasured one says so (never "blocked"); geo parts the provider did not give
/// are a dash.
#[test]
fn a_check_maps_stage_by_stage() {
    let mut r = result(
        Some(native_ok()),
        Some(PathReport::unmeasured(
            PathSource::DirectInbound,
            ErrorCode::ProxyFailed,
        )),
    );
    r.verdict = AvailabilityVerdict::Unknown;
    r.recommendation = Recommendation::PathNotMeasured;
    let check = url_check(&r);
    assert_eq!(
        (check.id.as_str(), check.url.as_str(), check.tested_at),
        ("c-1", "https://example.com/", 1_700_000_000_000)
    );
    assert!(check.tunnel_active);
    assert_eq!(check.verdict, ui::UrlVerdict::Unknown);
    assert_eq!(
        check.recommendation,
        Msg::new("probes.availability.rec.pathNotMeasured")
    );
    let protected = check.protected.expect("protected side");
    assert_eq!(protected.source, ui::PathSource::Native);
    assert!(protected.measured && protected.available && protected.message.is_none());
    let dns = protected.dns.expect("dns stage");
    assert_eq!(dns.ips, ["203.0.113.5", "2001:db8::5"]);
    assert!(protected.tls.expect("tls stage").ok);
    assert_eq!(protected.http.expect("http stage").status, Some(200));
    let geo = protected.geo.expect("geo");
    assert_eq!((geo.country.as_str(), geo.org.as_str()), ("NL", "—"));
    let direct = check.direct.expect("direct side");
    assert_eq!(direct.source, ui::PathSource::DirectInbound);
    assert!(!direct.measured && !direct.available);
    assert_eq!(
        direct.message,
        Some(Msg::new("probes.availability.fail.notMeasured"))
    );
    let failed = url_check(&result(Some(native_tls_cut()), None));
    assert_eq!(
        failed.protected.and_then(|p| p.message),
        Some(Msg::new("probes.availability.fail.tls"))
    );
}

/// NOADMIN §2: in a Soft session the probes measure the OS route natively (the real direct
/// path) and the system proxy's inbound over HTTP (the protected path) in each other's slots.
/// After the swap a site the provider cuts by SNI reads "only with VPN", not the reverse.
#[test]
fn soft_sides_swap_and_are_judged_again() {
    let measured = result(Some(native_tls_cut()), Some(inbound_ok()));
    let soft = soft_sides(measured);
    assert_eq!(soft.protected, Some(inbound_ok()));
    assert_eq!(soft.direct, Some(native_tls_cut()));
    assert_eq!(
        (soft.verdict, soft.recommendation),
        (
            AvailabilityVerdict::WorksOnlyWithVpn,
            Recommendation::ProviderBlocks
        )
    );
    assert!(soft.tunnel_active, "the session was up");
    // A dead inbound leaves the protected side "not measured", never "blocked" (B-UA-3).
    let dead = PathReport::unmeasured(PathSource::DirectInbound, ErrorCode::ProxyFailed);
    let soft = soft_sides(result(Some(native_ok()), Some(dead.clone())));
    assert_eq!(soft.protected, Some(dead));
    assert_eq!(
        (soft.verdict, soft.recommendation),
        (
            AvailabilityVerdict::Unknown,
            Recommendation::PathNotMeasured
        )
    );
}

fn endpoints(proxy_port: Option<u16>) -> SessionEndpoints {
    SessionEndpoints {
        clash_port: 9090,
        clash_secret: "0".repeat(32),
        direct: ProxyEndpoint {
            port: 2080,
            user: "fake-user".into(),
            pass: "fake-pass".into(),
        },
        probe: None,
        tun_luid: None,
        tun_alias: None,
        proxy_port,
        logs: Vec::new(),
    }
}

/// The session kinds the measurements choose their paths by.
#[test]
fn session_kinds_follow_the_runtime_status() {
    assert_eq!(Session::of(&TunStatus::default()), Session::Off);
    let tun = TunStatus {
        running: true,
        capture: Some(CaptureKind::Tun),
        profile_name: Some("Netherlands".into()),
        session: Some(endpoints(None)),
        ..TunStatus::default()
    };
    let Session::Tun { direct, profile } = Session::of(&tun) else {
        panic!("a TUN session");
    };
    let direct: Loopback = direct.expect("mixed-direct-in");
    assert_eq!(direct.port, 2080);
    assert_eq!(direct.creds.map(|c| c.user).as_deref(), Some("fake-user"));
    assert_eq!(profile.as_deref(), Some("Netherlands"));
    let soft = TunStatus {
        capture: Some(CaptureKind::Proxy),
        session: Some(endpoints(Some(7890))),
        ..tun.clone()
    };
    assert!(matches!(
        Session::of(&soft),
        Session::Proxy {
            proxy: Some(7890),
            direct: Some(_)
        }
    ));
    assert!(Session::of(&soft).running());
    // A run without a known capture cannot be measured as either kind.
    let unknown = TunStatus {
        capture: None,
        ..tun.clone()
    };
    assert_eq!(Session::of(&unknown), Session::Off);
    let stopped = TunStatus {
        running: false,
        ..tun
    };
    assert!(!Session::of(&stopped).running());
}

/// B-ST-1 / B-ST-4: egress and transport warnings reach the page; an unknown profile is a dash.
#[test]
fn a_speed_result_maps_its_warnings() {
    let row = probe::SpeedResult {
        id: "s-1".into(),
        timestamp: 5,
        download_mbps: 87.4,
        upload_mbps: None,
        latency_ms: 38,
        server_name: "OVH".into(),
        profile_used: None,
        egress: Egress::Changed {
            seen: Some(ip("198.51.100.77")),
        },
        transport_warning: Some(TransportWarning::PlainHttp),
    };
    let shown = speed_result(&row);
    assert_eq!((shown.id.as_str(), shown.timestamp), ("s-1", 5));
    assert_eq!((shown.download_mbps, shown.upload_mbps), (87.4, None));
    assert_eq!(shown.latency_ms, 38);
    assert_eq!(shown.server_name, "OVH");
    assert_eq!(shown.profile_used, "—");
    assert_eq!(
        shown.egress,
        ui_speed::Egress::Changed {
            seen: Some(ip("198.51.100.77"))
        }
    );
    assert!(shown.plain_http);
    let plain = probe::SpeedResult {
        profile_used: Some("Germany".into()),
        egress: Egress::Direct {
            seen: ip("203.0.113.9"),
        },
        transport_warning: None,
        ..row.clone()
    };
    let shown = speed_result(&plain);
    assert_eq!(shown.profile_used, "Germany");
    assert!(!shown.plain_http);
    assert_eq!(
        shown.egress,
        ui_speed::Egress::Direct {
            seen: ip("203.0.113.9")
        }
    );
    for (egress, expected) in [
        (Egress::Match, ui_speed::Egress::Match),
        (Egress::NotChecked, ui_speed::Egress::NotChecked),
    ] {
        let row = probe::SpeedResult {
            egress,
            ..row.clone()
        };
        assert_eq!(speed_result(&row).egress, expected);
    }
}

/// The page's bar has no error phase: the failed run's error is the answer.
#[test]
fn progress_frames_map_to_the_page_phases() {
    let frame = |percent, phase| probe::SpeedProgress { percent, phase };
    assert_eq!(
        speed_progress(frame(30, probe::SpeedPhase::Download)),
        Some(ui_speed::SpeedProgress {
            percent: 30,
            phase: ui_speed::SpeedPhase::Download,
        })
    );
    for (phase, shown) in [
        (probe::SpeedPhase::Latency, ui_speed::SpeedPhase::Latency),
        (probe::SpeedPhase::Upload, ui_speed::SpeedPhase::Upload),
        (probe::SpeedPhase::Complete, ui_speed::SpeedPhase::Complete),
    ] {
        assert_eq!(
            speed_progress(frame(100, phase)).map(|p| p.phase),
            Some(shown)
        );
    }
    assert_eq!(speed_progress(frame(0, probe::SpeedPhase::Error)), None);
    assert_eq!(
        speed_progress(frame(250, probe::SpeedPhase::Upload)).map(|p| p.percent),
        Some(100)
    );
}

/// The routing self-test keeps the probes' sentence and every address it saw.
#[test]
fn a_routing_result_maps_with_its_smart_ru_echo() {
    let r = RoutingResult {
        ran_at: 9,
        tunnel_active: true,
        vpn_ip: Some(ip("198.51.100.23")),
        direct_ip: Some(ip("203.0.113.47")),
        split_works: true,
        smart_ru: SmartRuCheck {
            enabled: true,
            ru_host_ip: Some(ip("203.0.113.47")),
            ru_goes_direct: Some(true),
        },
        verdict: RoutingVerdict::Ok,
        message: Msg::new("probes.routing.smartOk")
            .arg("vpn", "198.51.100.23")
            .arg("direct", "203.0.113.47"),
    };
    let shown = routing_report(&r);
    assert_eq!(shown.ran_at, 9);
    assert_eq!(shown.verdict, ui::RoutingVerdict::Ok);
    assert_eq!(shown.message, r.message);
    assert_eq!(
        (shown.vpn_ip, shown.direct_ip, shown.ru_ip),
        (r.vpn_ip, r.direct_ip, Some(ip("203.0.113.47")))
    );
    assert!(shown.smart_ru);
    for (verdict, expected) in [
        (RoutingVerdict::Partial, ui::RoutingVerdict::Partial),
        (RoutingVerdict::Leak, ui::RoutingVerdict::Leak),
        (RoutingVerdict::TunnelOff, ui::RoutingVerdict::TunnelOff),
        (
            RoutingVerdict::Inconclusive,
            ui::RoutingVerdict::Inconclusive,
        ),
    ] {
        let r = RoutingResult {
            verdict,
            ..r.clone()
        };
        assert_eq!(routing_report(&r).verdict, expected);
    }
}

/// U-06: a history the app cannot write (newer file) says so instead of "no checks yet"; a
/// normal one carries no note.
#[test]
fn an_unreadable_history_is_shown_as_such() {
    let dir = TempDir::new("tools-history-note");
    let fresh = Store::<UrlChecks>::open(&dir.0);
    let state = availability_state(true, &fresh);
    assert!(state.tunnel_running && state.history.is_empty());
    assert_eq!(state.history_error, None);
    let file = dir.0.join("history").join("url-checks.json");
    std::fs::create_dir_all(file.parent().expect("parent")).expect("history dir");
    std::fs::write(&file, r#"{"schemaVersion": 99, "history": []}"#).expect("newer file");
    let newer = Store::<UrlChecks>::open(&dir.0);
    let state = availability_state(false, &newer);
    assert_eq!(
        state.history_error.map(|m| m.key),
        Some("core.store.newerVersion".into())
    );
}
