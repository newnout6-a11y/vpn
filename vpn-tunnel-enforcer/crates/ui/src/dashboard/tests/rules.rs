//! Pure rules: the power click rule, banners, the node line, ruler labels.
use std::net::IpAddr;

use vpnte_base::types::Verdict;
use vpnte_view::identity::{ExitIp, LocalPing, ServerHealth};
use vpnte_view::labels::{FirewallStatus, FwState};
use vpnte_view::swiss::{ConnView, Mode, Transition, TunnelState};

use super::super::demo::{HOME_IP, VPN_IP};
use super::super::model::*;
use super::super::*;
use crate::panels::{LocalPings, ServerRowView, ServersView};

fn connected() -> ConnView {
    ConnView {
        state: TunnelState::Connected,
        mode: Some(Mode::Tun),
        cleanup_required: true,
        ..ConnView::default()
    }
}

fn connecting() -> ConnView {
    ConnView {
        transition: Some(Transition::Connecting),
        cleanup_required: true,
        ..ConnView::default()
    }
}

/// Power-button click rule: nothing installed → connect; installed → disconnect at once (owner,
/// 12.11.2026: no confirmation for an action the next press undoes).
#[test]
fn power_click_connects_or_disconnects() {
    assert_eq!(
        power_click(&ConnView::default(), false),
        PowerAction::Connect
    );
    assert_eq!(power_click(&connected(), false), PowerAction::Disconnect);
}

/// AT-00-008 (spec §7.8 #1): a faulted tunnel with our protection still installed offers the
/// cleanup (disconnect), never a second start on top.
#[test]
fn faulted_tunnel_with_leftovers_disconnects() {
    let fault = ConnView {
        state: TunnelState::Unknown,
        cleanup_required: true,
        ..ConnView::default()
    };
    assert_eq!(power_click(&fault, false), PowerAction::Disconnect);
    let cleaned = ConnView {
        cleanup_required: false,
        ..fault
    };
    assert_eq!(power_click(&cleaned, false), PowerAction::Connect);
}

/// AT-00-003 / AT-00-007: while a transition, a switch or a cancellation is in flight the button
/// does nothing (it is disabled too), and neither does a second press of our own command.
#[test]
fn power_click_ignores_presses_in_flight() {
    assert_eq!(power_click(&connecting(), false), PowerAction::Ignore);
    let switching = ConnView {
        switching: Some("Norway".into()),
        ..connected()
    };
    assert_eq!(power_click(&switching, false), PowerAction::Ignore);
    let cancelling = ConnView {
        cancelling: true,
        ..connected()
    };
    assert_eq!(power_click(&cancelling, false), PowerAction::Ignore);
    assert_eq!(power_click(&ConnView::default(), true), PowerAction::Ignore);
}

fn view(conn: ConnView) -> DashboardView {
    DashboardView {
        conn,
        exit: ExitIp {
            ip: Some(VPN_IP),
            vpn_ip: Some(VPN_IP),
            verdict: Verdict::Ok,
            ..ExitIp::default()
        },
        firewall: FirewallStatus {
            state: FwState::Inactive,
            checking: false,
        },
        ..DashboardView::default()
    }
}

#[test]
fn restart_and_competing_tun_banners() {
    let restarting = ConnView {
        restarting: Some((1, 3)),
        cleanup_required: true,
        ..ConnView::default()
    };
    assert_eq!(banners(&view(restarting)).restart.as_deref(), Some("1/3"));
    let second_tun = ConnView {
        competing_tun: Some("happ-tun (172.19.0.1)".into()),
        ..connected()
    };
    let shown = banners(&view(second_tun.clone()));
    assert_eq!(
        shown.competing_tun.as_deref(),
        Some("happ-tun (172.19.0.1)")
    );
    // only while our own TUN runs (Soft mode routes nothing through an adapter)
    let soft = ConnView {
        mode: Some(Mode::Soft),
        ..second_tun
    };
    assert_eq!(banners(&view(soft)).competing_tun, None);
}

fn firewall(state: FwState, checking: bool) -> FirewallStatus {
    FirewallStatus { state, checking }
}

/// AT-03-001 (spec §7.8 #7): no cleanup alert before the read-back has completed.
#[test]
fn kill_switch_banner_waits_for_the_read_back() {
    let leftover = ConnView {
        state: TunnelState::Error,
        cleanup_required: true,
        ..ConnView::default()
    };
    let mut v = view(leftover);
    v.firewall = firewall(FwState::Unknown, true);
    assert_eq!(banners(&v).kill_switch, None);
}

/// AT-03-001 / AT-03-003 (spec §7.8 #8, #9): an unconfirmed read-back shows the «not confirmed»
/// banner, never the verified one; a verified policy shows the verified one; nothing of ours
/// installed shows none.
#[test]
fn kill_switch_banner_says_what_was_established() {
    let leftover = ConnView {
        state: TunnelState::Unknown,
        cleanup_required: true,
        ..ConnView::default()
    };
    let mut v = view(leftover);
    v.firewall = firewall(FwState::Unknown, false);
    let banner = banners(&v).kill_switch.expect("shown");
    assert_eq!(banner.title.key, "dashboard.firewallUnknownTitle");
    assert_eq!(banner.body.key, "dashboard.firewallUnknownBody");
    v.firewall = firewall(FwState::Verified, false);
    let banner = banners(&v).kill_switch.expect("shown");
    assert_eq!(banner.title.key, "dashboard.firewallVerifiedTitle");
    v.firewall = firewall(FwState::Inactive, false);
    assert_eq!(banners(&v).kill_switch, None, "recheck established absence");
    // a running tunnel or a transition never shows it
    let mut up = view(connected());
    up.firewall = firewall(FwState::Verified, false);
    assert_eq!(banners(&up).kill_switch, None);
    let mut busy = view(connecting());
    busy.firewall = firewall(FwState::Unknown, false);
    assert_eq!(banners(&busy).kill_switch, None);
}

/// AT-07-001 (spec §7.8 #15): an explicit leak verdict shows the leak card; a server switch
/// legitimately changes the address, so it is not shown mid-switch.
#[test]
fn leak_card_follows_the_visible_leak() {
    let mut v = view(connected());
    v.exit = ExitIp {
        ip: Some(HOME_IP),
        vpn_ip: Some(VPN_IP),
        verdict: Verdict::Fail,
        leak: true,
        geo: None,
    };
    assert!(banners(&v).leak);
    v.conn.switching = Some("Norway".into());
    assert!(!banners(&v).leak);
}

/// AT-07-001 / AT-07-006 (spec §7.8 #14): an unverified or unchecked exit address is no leak.
#[test]
fn unverified_exit_is_no_leak() {
    for verdict in [Verdict::Warn, Verdict::NotChecked] {
        let mut v = view(connected());
        v.exit.verdict = verdict;
        v.exit.ip = Some(IpAddr::from([13, 143, 217, 2]));
        assert!(!banners(&v).leak, "{verdict:?}");
    }
}

/// Spec §2.12 / §7.5: the notice names the product, only while our own tunnel is down.
#[test]
fn foreign_vpn_notice_while_our_tunnel_is_down() {
    let mut v = view(ConnView::default());
    v.foreign_vpn = Some("happ-tun (172.18.0.1)".into());
    assert_eq!(banners(&v).foreign_vpn.as_deref(), Some("Happ"));
    v.foreign_vpn = Some("mystery-tun (10.1.2.3)".into());
    assert_eq!(banners(&v).foreign_vpn.as_deref(), Some("mystery-tun"));
    v.conn = connected();
    assert_eq!(banners(&v).foreign_vpn, None);
    assert_eq!(banners(&view(ConnView::default())).foreign_vpn, None);
}

fn row(id: &str, ping: Option<u32>, health: ServerHealth) -> ServerRowView {
    ServerRowView {
        id: id.into(),
        name: format!("{id} name"),
        country: Some("NL".into()),
        protocol: Some("vless".into()),
        ping,
        health_latency: Some(70),
        health,
        checked_at: None,
    }
}

/// Spec §3.1 node line: the active server's name and flag, «VLESS · 38 мс»; the panel's own
/// measurement wins over the stored ping, the health latency is the last resort.
#[test]
fn node_line_reads_the_active_server() {
    let servers = ServersView {
        rows: vec![
            row("a", Some(31), ServerHealth::Online),
            row("b", Some(38), ServerHealth::Online),
        ],
        active_id: Some("b".into()),
        ..ServersView::default()
    };
    let mut local = LocalPings::default();
    let node = node_line(&servers, &local).expect("active");
    assert_eq!(node.name, "b name");
    assert_eq!(node.country.as_deref(), Some("NL"));
    assert_eq!(node.meta.key, "view.identity.metaPing");
    assert_eq!(
        node.meta.args,
        [
            ("protocol".into(), "VLESS".to_owned()),
            ("ms".into(), "38".to_owned())
        ]
    );
    let route = local.begin("b");
    local.finish("b", route, Some(12));
    assert_eq!(local.get("b"), Some(LocalPing::Done(Some(12))));
    let node = node_line(&servers, &local).expect("active");
    assert!(node.meta.args.contains(&("ms".into(), "12".to_owned())));
    let unpinged = ServersView {
        rows: vec![row("c", None, ServerHealth::Offline)],
        active_id: Some("c".into()),
        ..ServersView::default()
    };
    let node = node_line(&unpinged, &LocalPings::default()).expect("active");
    assert!(
        node.meta.args.contains(&("ms".into(), "70".to_owned())),
        "health latency"
    );
}

#[test]
fn node_line_without_an_active_server() {
    let none = ServersView {
        rows: vec![row("a", Some(31), ServerHealth::Online)],
        ..ServersView::default()
    };
    assert_eq!(node_line(&none, &LocalPings::default()), None);
    let gone = ServersView {
        active_id: Some("removed".into()),
        ..none
    };
    assert_eq!(node_line(&gone, &LocalPings::default()), None);
}

#[test]
fn ruler_cells_are_numbered_from_01() {
    let labels: Vec<String> = (0..vpnte_view::swiss::RULER_CELLS)
        .map(|i| crate::pages::nav_number(usize::from(i)))
        .collect();
    assert_eq!(labels.first().map(String::as_str), Some("01"));
    assert_eq!(labels.last().map(String::as_str), Some("10"));
    assert_eq!(labels.len(), 10);
}

/// ENGINE-GAPS decision 2: the identity column names the running engine and, when a choice was
/// made, why («Xray · REALITY»); a local upstream proxy shows the engine alone.
#[test]
fn engine_caption_names_engine_and_reason() {
    use vpnte_base::types::Engine;
    let xray = EngineLine {
        engine: Engine::Xray,
        reason: Some(Msg::new("engine.xray.reason.reality")),
    };
    assert_eq!(
        engine_caption(&xray, Some("REALITY".into())),
        "Xray · REALITY"
    );
    let local = EngineLine {
        engine: Engine::SingBox,
        reason: None,
    };
    assert_eq!(engine_caption(&local, None), "sing-box");
    assert_eq!(engine_caption(&local, Some(String::new())), "sing-box");
}

/// ks-b: another program holds the system proxy our session set: the line shows, also while
/// paused (the user can take it back either way).
#[test]
fn proxy_taken_line_follows_the_read_back() {
    let mut taken = view(connected());
    assert!(!banners(&taken).proxy_taken);
    taken.proxy_taken = true;
    assert!(banners(&taken).proxy_taken);
    taken.pause = Some(PauseLine {
        next_attempt: None,
        manual: false,
        key_rejected: false,
    });
    assert!(banners(&taken).proxy_taken);
}

/// fix-ks a3: the paused strip says «переподключается» only while something retries; with
/// auto-restart off it asks for «Подключить», and a rejected key is named first.
#[test]
fn the_pause_line_says_whether_anything_retries() {
    use super::super::banners::pause_key;
    let line = |next_attempt, manual, key_rejected| PauseLine {
        next_attempt,
        manual,
        key_rejected,
    };
    let key = |l: &PauseLine| pause_key(l).rsplit('.').next().unwrap_or_default();
    assert_eq!(key(&line(None, false, false)), "reconnecting");
    assert_eq!(key(&line(Some(1), false, false)), "nextAttempt");
    assert_eq!(key(&line(None, true, false)), "manual");
    assert_eq!(key(&line(None, true, true)), "keyRejected");
}
