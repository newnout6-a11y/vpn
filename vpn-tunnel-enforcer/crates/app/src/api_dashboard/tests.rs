//! Projections of the start page and the tray as pure functions (spec vectors tagged `AT-*`).
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use vpnte_base::i18n::Lang;
use vpnte_base::types::{ClientDevice, KillSwitchLevel, Level, Owner, Verdict};
use vpnte_core::ops::{CorrelationId, OpId, OpKind, OpMeta, OpStatus, Source};
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::ip_monitor::{IpEvidence, IpVerdict};
use vpnte_probes::leak::{CheckReport, CheckStatus};
use vpnte_probes::public_ip::IpSample;
use vpnte_profiles::countries::Iso2;
use vpnte_servers::model::{
    ArchiveReason, Archived, GroupId, HealthRecord, Origin, Ping, ProfileId, ServerSummary,
};
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::{
    Health, ProcessState, ProxyStatus, Transition, TunnelMode, TunnelSnapshot, TunnelState,
};
use vpnte_ui::tray::{TrayItemId, TrayModel, TrayState, TrayStatus};
use vpnte_view::identity::ServerHealth;
use vpnte_view::labels::{self, FwState};
use vpnte_view::swiss::{self, Busy};
use vpnte_winnet::wfp::{
    Conn, KillSwitchState, ProtectionError, ProtectionSettings, ProtectionStatus,
};

use super::project::{self, Clock, ConnLocal};
use crate::services::KillSwitchStatus;

const HOME: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const EXIT: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
const OTHER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));

fn clock() -> Clock {
    Clock::now()
}

/// A settled snapshot in `state` (connected ones run our engine with the TUN).
fn snap(state: TunnelState) -> TunnelSnapshot {
    let connected = state == TunnelState::Connected;
    TunnelSnapshot {
        state,
        mode: connected.then_some(TunnelMode::Tun),
        process_state: if connected {
            ProcessState::Running
        } else {
            ProcessState::Stopped
        },
        proxy_status: if connected {
            ProxyStatus::Running
        } else {
            ProxyStatus::Stopped
        },
        started_at: connected.then_some(1_700_000_000_000),
        cleanup_required: connected,
        ..TunnelSnapshot::default()
    }
}

fn op(kind: OpKind, status: OpStatus, started_at: i64, deadline: Option<i64>) -> OpMeta {
    OpMeta {
        id: OpId::next(),
        correlation: CorrelationId::new(),
        owner: Owner::Manual,
        source: Source::Ui,
        kind,
        started_at,
        deadline,
        status,
        category: None,
    }
}

fn evidence(verdict: IpVerdict, last: Option<IpAddr>, baseline: Option<IpAddr>) -> IpEvidence {
    IpEvidence {
        baseline,
        real_ip: Some(HOME),
        last: last.map(|ip| IpSample {
            ip,
            provider: 0,
            at: 1_700_000_000_000,
        }),
        fresh: true,
        verdict,
    }
}

#[test]
fn idle_snapshot_projects_to_a_settled_off_connection() {
    let conn = project::conn_view(
        &TunnelSnapshot::default(),
        &TunStatus::default(),
        &ConnLocal::default(),
        &clock(),
    );
    assert_eq!(conn, swiss::ConnView::default());
    assert_eq!(labels::status_label(&conn).key, "dashboard.disconnected");
}

#[test]
fn connected_tun_snapshot_keeps_mode_start_and_flags() {
    let mut s = snap(TunnelState::Connected);
    s.health = Some(Health::Degraded);
    s.competing_tun = Some("happ-tun (172.18.0.1)".into());
    let conn = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &clock());
    assert_eq!(conn.state, swiss::TunnelState::Connected);
    assert_eq!(conn.mode, Some(swiss::Mode::Tun));
    assert!(conn.tun_running() && conn.degraded && conn.cleanup_required);
    assert_eq!(conn.started_at, Some(1_700_000_000_000));
    assert_eq!(conn.competing_tun_banner(), Some("happ-tun (172.18.0.1)"));
    assert!(project::tun_running(&s));

    s.mode = Some(TunnelMode::Soft);
    let soft = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &clock());
    assert_eq!(soft.mode, Some(swiss::Mode::Soft));
    assert!(!soft.tun_running() && !project::tun_running(&s));
}

/// D-23: «proxy down» is the backend's flag, not a UI heuristic.
#[test]
fn proxy_down_comes_from_the_snapshot() {
    let mut s = snap(TunnelState::Connected);
    s.proxy_status = ProxyStatus::ProxyDown;
    let conn = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &clock());
    assert!(conn.proxy_down);
    assert_eq!(labels::status_label(&conn).key, "view.status.proxyDown");
}

/// A crash restart (a reconnect no lane operation started) shows its attempt; a switch or a
/// settings restart (a running lane operation) does not.
#[test]
fn restart_progress_only_for_a_crash_restart() {
    let mut s = snap(TunnelState::Connected);
    s.transition = Some(Transition::Reconnecting);
    let status = TunStatus {
        restart_attempt: 2,
        ..TunStatus::default()
    };
    let conn = project::conn_view(&s, &status, &ConnLocal::default(), &clock());
    assert_eq!(conn.restarting, Some((2, 3)));
    assert_eq!(conn.busy(), Some(Busy::Connecting));

    s.operation = Some(op(OpKind::Rotation, OpStatus::Running, 1, None));
    let conn = project::conn_view(&s, &status, &ConnLocal::default(), &clock());
    assert_eq!(conn.restarting, None);

    // a stable run keeps no restart even if the counter was not reset yet
    let settled = snap(TunnelState::Connected);
    let conn = project::conn_view(&settled, &status, &ConnLocal::default(), &clock());
    assert_eq!(conn.restarting, None);
}

/// The ruler follows the running lane operation's wall-clock window; a finished one draws none.
#[test]
fn running_operation_maps_to_a_stable_window() {
    let c = clock();
    let mut s = snap(TunnelState::Disconnected);
    s.transition = Some(Transition::Connecting);
    s.operation = Some(op(
        OpKind::Connect,
        OpStatus::Running,
        c.wall - 1_000,
        Some(c.wall + 119_000),
    ));
    let conn = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &c);
    let window = conn.operation.expect("a running operation");
    assert_eq!(c.at - window.started, Duration::from_secs(1));
    assert_eq!(window.deadline, Some(c.at + Duration::from_secs(119)));
    // equal facts project to an equal view: no spurious pushes
    assert_eq!(
        conn,
        project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &c)
    );

    s.operation = Some(op(OpKind::Connect, OpStatus::Success, c.wall, None));
    let conn = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &c);
    assert_eq!(conn.operation, None);
}

/// AT-00-003 / AT-00-008: a cancel keeps the connection busy across terminal snapshots until
/// it is explicitly finished.
#[test]
fn cancelling_stays_busy_until_released() {
    let local = ConnLocal {
        cancelling: true,
        switching: None,
    };
    for state in [TunnelState::Disconnected, TunnelState::Unknown] {
        let conn = project::conn_view(&snap(state), &TunStatus::default(), &local, &clock());
        assert_eq!(conn.busy(), Some(Busy::Disconnecting));
        assert_eq!(labels::status_label(&conn).key, "dashboard.cancelling");
        assert!(labels::power_button(&conn).waiting);
    }
    let released = project::conn_view(
        &snap(TunnelState::Disconnected),
        &TunStatus::default(),
        &ConnLocal::default(),
        &clock(),
    );
    assert_eq!(released.busy(), None);
    assert_eq!(
        labels::status_label(&released).key,
        "dashboard.disconnected"
    );
}

/// AT-00-008 'shows the selected server during canonical reconnecting'.
#[test]
fn switch_started_here_shows_the_target() {
    let mut s = snap(TunnelState::Connected);
    s.transition = Some(Transition::Reconnecting);
    s.operation = Some(op(OpKind::Rotation, OpStatus::Running, 1, None));
    let local = ConnLocal {
        cancelling: false,
        switching: Some("Norway".into()),
    };
    let conn = project::conn_view(&s, &TunStatus::default(), &local, &clock());
    let status = labels::status_label(&conn);
    assert_eq!(status.key, "dashboard.switchingServer");
    assert_eq!(status.args[0].1, "Norway");
    assert_eq!(
        labels::cancel_label(&conn).map(|m| m.key),
        Some("dashboard.cancelServerSwitch".into())
    );
}

/// Settled off the monitor's last sample is the previous session's exit: the page shows the
/// home address measured before that connect, unverified, with no leak and no country.
#[test]
fn settled_off_shows_the_home_address() {
    let ev = evidence(IpVerdict::NotChecked, Some(EXIT), Some(EXIT));
    let geo = Some((EXIT, Iso2::new("NL").expect("NL")));
    let (exit, country) = project::exit_ip(&snap(TunnelState::Disconnected), &ev, geo, Lang::En);
    assert_eq!(exit.ip, Some(HOME));
    assert_eq!(exit.vpn_ip, None);
    assert_eq!(exit.verdict, Verdict::NotChecked);
    assert!(!exit.leak && exit.geo.is_none() && country.is_none());
}

#[test]
fn passed_exit_gets_the_country_looked_up_for_it() {
    let s = snap(TunnelState::Connected);
    let ev = evidence(IpVerdict::Passed, Some(EXIT), Some(EXIT));
    let nl = Iso2::new("nl").expect("NL");
    let (exit, country) = project::exit_ip(&s, &ev, Some((EXIT, nl)), Lang::En);
    assert_eq!((exit.ip, exit.vpn_ip), (Some(EXIT), Some(EXIT)));
    assert_eq!(exit.verdict, Verdict::Ok);
    assert_eq!(country.as_deref(), Some("NL"));
    let geo = exit.current_geo().expect("geo of this address");
    assert_eq!(geo.country.as_deref(), Some("Netherlands"));
    let (ru, _) = project::exit_ip(&s, &ev, Some((EXIT, nl)), Lang::Ru);
    assert_eq!(
        ru.current_geo().and_then(|g| g.country.as_deref()),
        Some("Нидерланды")
    );

    // a rotated exit never shows the previous country
    let (exit, country) = project::exit_ip(&s, &ev, Some((OTHER, nl)), Lang::En);
    assert!(exit.geo.is_none() && country.is_none());
}

/// AT-07-001: a failed check is the explicit leak alarm; an unverified change is not.
#[test]
fn monitor_verdicts_reach_the_exit_line() {
    let s = snap(TunnelState::Connected);
    let conn = project::conn_view(&s, &TunStatus::default(), &ConnLocal::default(), &clock());
    let leak = evidence(IpVerdict::Failed, Some(HOME), Some(EXIT));
    let (exit, _) = project::exit_ip(&s, &leak, None, Lang::Ru);
    assert!(exit.leak);
    assert_eq!(exit.verdict, Verdict::Fail);
    assert_eq!(
        labels::exit_line(&conn, &exit).sub.text.key,
        "dashboard.swissIpLeak"
    );

    for (verdict, key) in [
        (IpVerdict::Indeterminate, "dashboard.ipChangedUnverified"),
        (IpVerdict::NotChecked, "dashboard.ipNotChecked"),
    ] {
        let (exit, _) = project::exit_ip(
            &s,
            &evidence(verdict, Some(OTHER), Some(EXIT)),
            None,
            Lang::Ru,
        );
        assert!(!exit.leak);
        assert_eq!(labels::exit_line(&conn, &exit).sub.text.key, key);
    }
}

/// The country is looked up only for the adopted exit of a running TUN after a passed check:
/// never for a leak (the real address), a Soft session, or mid-transition.
#[test]
fn geo_lookup_gate() {
    let on = snap(TunnelState::Connected);
    let passed = evidence(IpVerdict::Passed, Some(EXIT), Some(EXIT));
    assert_eq!(project::geo_target(&on, &passed), Some(EXIT));

    let failed = evidence(IpVerdict::Failed, Some(HOME), Some(EXIT));
    assert_eq!(project::geo_target(&on, &failed), None);
    let not_adopted = evidence(IpVerdict::Passed, Some(OTHER), Some(EXIT));
    assert_eq!(project::geo_target(&on, &not_adopted), None);

    let mut soft = on.clone();
    soft.mode = Some(TunnelMode::Soft);
    assert_eq!(project::geo_target(&soft, &passed), None);
    let mut switching = on.clone();
    switching.transition = Some(Transition::Reconnecting);
    assert_eq!(project::geo_target(&switching, &passed), None);
    assert_eq!(
        project::geo_target(&snap(TunnelState::Disconnected), &passed),
        None
    );
}

/// The foreign-VPN notice shows only while our TUN is not up.
#[test]
fn foreign_vpn_only_without_our_tun() {
    let raw = Some("happ-tun (172.18.0.1)");
    let on = project::conn_view(
        &snap(TunnelState::Connected),
        &TunStatus::default(),
        &ConnLocal::default(),
        &clock(),
    );
    assert_eq!(project::foreign_vpn(&on, raw), None);
    let off = swiss::ConnView::default();
    assert_eq!(
        project::foreign_vpn(&off, raw).as_deref(),
        Some("happ-tun (172.18.0.1)")
    );
    let soft = swiss::ConnView {
        mode: Some(swiss::Mode::Soft),
        ..on
    };
    assert!(project::foreign_vpn(&soft, raw).is_some());
}

#[test]
fn leak_check_summary_and_tray_notice_level() {
    let report = |summary| CheckReport {
        ran_at: 0,
        summary,
        headline: vpnte_base::Msg::new("probes.leak.check.summary.ok"),
        items: Vec::new(),
    };
    for (summary, verdict, level) in [
        (CheckStatus::Ok, Verdict::Ok, Level::Success),
        (CheckStatus::Warn, Verdict::Warn, Level::Warn),
        (CheckStatus::Fail, Verdict::Fail, Level::Error),
        (CheckStatus::NotChecked, Verdict::NotChecked, Level::Info),
        (CheckStatus::Info, Verdict::NotChecked, Level::Info),
    ] {
        assert_eq!(project::leak_verdict(&report(summary)), verdict);
        assert_eq!(project::check_level(summary), level);
    }
}

#[test]
fn traffic_sample_maps_rates_and_session() {
    let stats = TrafficStats {
        ts_ms: 42,
        running: true,
        down_bps: 1_000.0,
        up_bps: 200.0,
        smooth_down_bps: 900.0,
        smooth_up_bps: 150.0,
        session_down: 5_000_000,
        started_at_ms: Some(7),
        ..TrafficStats::default()
    };
    let s = project::traffic_sample(&stats);
    assert_eq!((s.ts, s.running, s.started_at), (42, true, Some(7)));
    assert_eq!((s.download_bps, s.upload_bps), (1_000.0, 200.0));
    assert_eq!((s.down_bps(), s.up_bps()), (900.0, 150.0));
    assert_eq!(s.session_download_bytes, 5_000_000);
}

#[test]
fn clock_maps_wall_time_both_ways() {
    let c = clock();
    assert_eq!(c.instant(c.wall), c.at);
    assert_eq!(
        c.instant(c.wall + 2_500),
        c.at + Duration::from_millis(2_500)
    );
    assert_eq!(
        c.at - c.instant(c.wall - 1_500),
        Duration::from_millis(1_500)
    );
    // far in the past (a wrong clock): clamped, never a panic
    let _ = c.instant(i64::MIN);
    let _ = c.instant(i64::MAX);
}

fn wfp(kill_switch: KillSwitchState) -> ProtectionStatus {
    ProtectionStatus {
        level: KillSwitchLevel::Standard,
        conn: Conn::default(),
        kill_switch,
        last_error: None,
        leak_protection_active: false,
        dynamic_filters: Some(0),
        persistent_filters: Some(0),
        sublayer_weight: None,
        bfe_running: Some(true),
        last_verified: None,
        skipped_exceptions: Vec::new(),
        windows_firewall_outbound_block: None,
        hyperv_switch_present: None,
    }
}

fn ks(wfp: Option<ProtectionStatus>) -> KillSwitchStatus {
    KillSwitchStatus {
        settings: ProtectionSettings::default(),
        wfp,
    }
}

/// AT-03-001 / AT-03-003: only a read-back of our installed filters reads «Держит»; an
/// unconfirmed state is Unknown (an alert), never protected.
#[test]
fn kill_switch_fact_from_the_read_back() {
    for (state, expected, engaged) in [
        (KillSwitchState::Off, FwState::Inactive, false),
        (KillSwitchState::Armed, FwState::Inactive, false),
        (KillSwitchState::Engaged, FwState::Verified, true),
        (KillSwitchState::Blocking, FwState::Verified, true),
        (KillSwitchState::Failed, FwState::Unknown, false),
    ] {
        let status = ks(Some(wfp(state)));
        let fw = project::firewall(&status);
        assert_eq!((fw.state, fw.checking), (expected, false), "{state:?}");
        assert_eq!(project::kill_switch_engaged(&status), engaged, "{state:?}");
    }
    let mut failed_apply = wfp(KillSwitchState::Engaged);
    failed_apply.last_error = Some(ProtectionError::AccessDenied);
    assert_eq!(
        project::firewall(&ks(Some(failed_apply))).state,
        FwState::Unknown
    );
}

/// NOADMIN §0: unelevated this process installs no filters, so the fact reads «Снят» and no
/// kill-switch banner appears while off (Soft's proxy hold is never presented as «Держит»).
#[test]
fn unelevated_kill_switch_is_off_without_a_banner() {
    let fw = project::firewall(&ks(None));
    assert_eq!(fw.state, FwState::Inactive);
    assert!(!project::kill_switch_engaged(&ks(None)));
    assert_eq!(labels::kill_switch_fact(&fw).text.key, "swiss.ksOff");
    assert!(labels::kill_switch_banner(&swiss::ConnView::default(), &fw).is_none());
}

/// NOADMIN §2 (ui-unslop): unelevated, the saved level decides what can hold: standard is Soft's
/// proxy hold («Через прокси», a needs-admin alert in Hard mode), strict needs administrator
/// rights; neither raises the WFP banner.
#[test]
fn unelevated_kill_switch_names_what_can_hold() {
    let at = |level| {
        let mut status = ks(None);
        status.settings.level = level;
        project::firewall(&status)
    };
    let proxy = at(KillSwitchLevel::Standard);
    assert_eq!(proxy.state, FwState::ProxyHold);
    assert_eq!(
        labels::kill_switch_fact(&proxy.in_mode(true)).text.key,
        "view.fact.ksProxy"
    );
    assert_eq!(proxy.in_mode(false).state, FwState::NeedsAdmin);
    let strict = at(KillSwitchLevel::Strict);
    assert_eq!(strict.state, FwState::NeedsAdmin);
    let fact = labels::kill_switch_fact(&strict.in_mode(true));
    assert_eq!(
        (&*fact.text.key, fact.alert),
        ("view.fact.ksNeedsAdmin", true)
    );
    for fw in [proxy, strict] {
        assert!(labels::kill_switch_banner(&swiss::ConnView::default(), &fw).is_none());
    }
}

fn summary(id: &str, archived: Option<ArchiveReason>) -> ServerSummary {
    ServerSummary {
        id: ProfileId::from(id),
        group_id: GroupId::from("g1"),
        origin: Origin::Manual,
        name: format!("Server {id}"),
        protocol: "vless".into(),
        server: "vpn.example.invalid".into(),
        port: 443,
        device: ClientDevice::Pc,
        country: Iso2::new("de"),
        country_verified: false,
        missing_since: None,
        archived: archived.map(|reason| Archived { at: 1, reason }),
        purge_at: None,
        health: None,
        ping: None,
        locked: false,
        selected: false,
    }
}

/// Servers removed by the user or from their subscription are left out of the panel.
#[test]
fn server_rows_leave_out_archived_and_map_health() {
    let mut online = summary("a", None);
    online.health = Some(HealthRecord {
        online: true,
        at: 100,
        rtt_ms: Some(48),
        reason: None,
        egress_ip: None,
    });
    online.ping = Some(Ping {
        rtt_ms: Some(37),
        at: 120,
    });
    let mut offline = summary("b", None);
    offline.protocol = String::new();
    offline.health = Some(HealthRecord {
        online: false,
        at: 200,
        rtt_ms: None,
        reason: None,
        egress_ip: None,
    });
    let rows = project::server_rows(&[
        online,
        offline,
        summary("c", Some(ArchiveReason::User)),
        summary("d", Some(ArchiveReason::Provider)),
        summary("e", None),
    ]);
    let ids: Vec<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, ["a", "b", "e"]);
    let a = &rows[0];
    assert_eq!(a.country.as_deref(), Some("DE"));
    assert_eq!(a.protocol.as_deref(), Some("vless"));
    assert_eq!(
        (a.ping, a.health_latency, a.checked_at),
        (Some(37), Some(48), Some(100))
    );
    assert_eq!(a.health, ServerHealth::Online);
    assert_eq!(
        (rows[1].health, rows[1].protocol.as_deref()),
        (ServerHealth::Offline, None)
    );
    assert_eq!(
        (rows[2].health, rows[2].ping),
        (ServerHealth::Unknown, None)
    );
}

fn tray(
    s: &TunnelSnapshot,
    status: &TunStatus,
    ev: &IpEvidence,
    kill_switch: bool,
    traffic: &TrafficStats,
) -> TrayState {
    let conn = project::conn_view(s, status, &ConnLocal::default(), &clock());
    project::tray_state(s, status, ev, &conn, kill_switch, traffic, true)
}

/// lifecycle-app §3.14: the tray's status, menu and enable rules over the projected facts.
#[test]
fn tray_status_from_the_lifecycle_snapshot() {
    let idle = IpEvidence::default();
    let quiet = TrafficStats::default();
    let status = TunStatus::default();
    let of = |s: &TunnelSnapshot, ev: &IpEvidence, ks: bool| {
        TrayStatus::of(&tray(s, &status, ev, ks, &quiet))
    };
    let on = snap(TunnelState::Connected);
    let passed = evidence(IpVerdict::Passed, Some(EXIT), Some(EXIT));
    assert_eq!(of(&on, &passed, true), TrayStatus::Protected);
    let leak = evidence(IpVerdict::Failed, Some(HOME), Some(EXIT));
    assert_eq!(of(&on, &leak, true), TrayStatus::Leak);
    let mut down = on.clone();
    down.proxy_status = ProxyStatus::ProxyDown;
    assert_eq!(of(&down, &passed, false), TrayStatus::ProxyDown);
    let mut degraded = on.clone();
    degraded.health = Some(Health::Degraded);
    assert_eq!(of(&degraded, &passed, false), TrayStatus::Unknown);
    assert_eq!(
        of(&snap(TunnelState::Blocked), &idle, false),
        TrayStatus::KillSwitch
    );
    assert_eq!(
        of(&snap(TunnelState::Disconnected), &idle, true),
        TrayStatus::KillSwitch
    );
    assert_eq!(
        of(&snap(TunnelState::Error), &idle, false),
        TrayStatus::Error
    );
    assert_eq!(
        of(&snap(TunnelState::Disconnected), &idle, false),
        TrayStatus::Off
    );
    for (transition, expected) in [
        (Transition::Connecting, TrayStatus::Starting),
        (Transition::Disconnecting, TrayStatus::Stopping),
        (Transition::Reconnecting, TrayStatus::Restarting),
    ] {
        let mut busy = on.clone();
        busy.transition = Some(transition);
        assert_eq!(of(&busy, &leak, false), expected);
    }

    let enabled = |s: &TunnelSnapshot, id: TrayItemId| {
        TrayModel::build(&tray(s, &status, &idle, false, &quiet), false)
            .item(id)
            .enabled
    };
    let off = snap(TunnelState::Disconnected);
    assert!(enabled(&off, TrayItemId::Start) && !enabled(&off, TrayItemId::Stop));
    assert!(!enabled(&on, TrayItemId::Start) && enabled(&on, TrayItemId::Stop));
}

#[test]
fn tray_facts_ip_proxy_and_speed() {
    let on = snap(TunnelState::Connected);
    let status = TunStatus {
        running: true,
        proxy_addr: Some("socks5://user:secret@127.0.0.1:10808".into()),
        ..TunStatus::default()
    };
    let traffic = TrafficStats {
        running: true,
        down_bps: 2_000.0,
        up_bps: 100.0,
        smooth_down_bps: 1_500.5,
        ..TrafficStats::default()
    };
    let passed = evidence(IpVerdict::Passed, Some(EXIT), Some(EXIT));
    let state = tray(&on, &status, &passed, false, &traffic);
    assert_eq!(state.public_ip.as_deref(), Some("198.51.100.1"));
    assert_eq!(state.proxy_addr.as_deref(), Some("127.0.0.1:10808"));
    assert_eq!((state.down_bps, state.up_bps), (1_500, 100));
    assert!(state.engine_running && state.minimize_to_tray && !state.leak);

    // unverified exit, stopped engine, idle sampler: nothing claimed
    let unverified = evidence(IpVerdict::Indeterminate, Some(OTHER), Some(EXIT));
    let stopped = TunStatus {
        running: false,
        ..status
    };
    let idle = TrafficStats {
        running: false,
        ..traffic
    };
    let state = tray(&on, &stopped, &unverified, false, &idle);
    assert_eq!((state.public_ip, state.proxy_addr), (None, None));
    assert_eq!((state.down_bps, state.up_bps), (0, 0));
}

/// The fragments are valid JSON with identical key sets, and every key this package emits exists.
#[test]
fn locale_fragments_pair_up() {
    fn keys(prefix: &str, v: &serde_json::Value, out: &mut Vec<String>) {
        if let Some(map) = v.as_object() {
            for (k, child) in map {
                keys(&format!("{prefix}{k}."), child, out);
            }
        } else {
            out.push(prefix.trim_end_matches('.').to_owned());
        }
    }
    let parse = |text: &str| {
        let v: serde_json::Value = serde_json::from_str(text).expect("valid JSON");
        let mut out = Vec::new();
        keys("", &v, &mut out);
        out.sort();
        out
    };
    let ru = parse(include_str!("../../locales/app-dashboard.ru.json"));
    let en = parse(include_str!("../../locales/app-dashboard.en.json"));
    assert_eq!(ru, en);
    for key in [
        "app.dashboard.routeCheck",
        "app.dashboard.proxiesUnavailable",
        "app.dashboard.restoreFailed",
    ] {
        assert!(ru.iter().any(|k| k == key), "{key} missing");
    }
}

/// One anchor per lane operation: its window stays put while it runs; the next one re-anchors.
#[test]
fn op_clock_is_anchored_once_per_operation() {
    let mut local = super::Local::default();
    let mut s = snap(TunnelState::Disconnected);
    s.operation = Some(op(OpKind::Connect, OpStatus::Running, 1, None));
    let first = local.clock_for(&s);
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(local.clock_for(&s).at, first.at);
    s.operation = Some(op(OpKind::Disconnect, OpStatus::Running, 2, None));
    assert!(local.clock_for(&s).at > first.at);
}
