use super::*;

fn disconnected() -> TrayState {
    TrayState::default()
}

fn connected() -> TrayState {
    TrayState {
        tunnel: TunnelState::Connected,
        proxy: ProxyStatus::Running,
        engine_running: true,
        ..TrayState::default()
    }
}

fn enabled(state: &TrayState, id: TrayItemId) -> bool {
    TrayModel::build(state, false).item(id).enabled
}

/// AT-00-008 (trayState.test.ts «retains leak and confirmed firewall warnings while
/// disconnected»).
#[test]
fn disconnected_keeps_leak_and_kill_switch_warnings() {
    let fw = TrayState {
        kill_switch: true,
        ..disconnected()
    };
    assert_eq!(TrayStatus::of(&fw), TrayStatus::KillSwitch);
    let leak = TrayState {
        leak: true,
        ..disconnected()
    };
    assert_eq!(TrayStatus::of(&leak), TrayStatus::Leak);
    assert_eq!(TrayStatus::of(&disconnected()), TrayStatus::Off);
}

/// AT-00-008 (trayState.test.ts «distinguishes degraded competing-interface evidence from a
/// failed server»), as the sequence of snapshots the FSM publishes.
#[test]
fn degraded_evidence_is_not_a_failed_server() {
    let starting = TrayState {
        transition: Some(Transition::Connecting),
        ..disconnected()
    };
    assert_eq!(TrayStatus::of(&starting), TrayStatus::Starting);
    assert_eq!(TrayStatus::of(&connected()), TrayStatus::Protected);
    let competing = TrayState {
        degraded: true,
        ..connected()
    };
    assert_eq!(TrayStatus::of(&competing), TrayStatus::Unknown);
    let down = TrayState {
        proxy: ProxyStatus::ProxyDown,
        ..connected()
    };
    assert_eq!(TrayStatus::of(&down), TrayStatus::ProxyDown);
    let leak = TrayState { leak: true, ..down };
    assert_eq!(TrayStatus::of(&leak), TrayStatus::Leak);
    let blocked = TrayState {
        tunnel: TunnelState::Blocked,
        engine_running: false,
        ..disconnected()
    };
    assert_eq!(TrayStatus::of(&blocked), TrayStatus::KillSwitch);
    // a later runtimeChanged('running') keeps the FSM blocked, so the tray stays killswitch
    let running = TrayState {
        engine_running: true,
        proxy: ProxyStatus::Running,
        ..blocked
    };
    assert_eq!(TrayStatus::of(&running), TrayStatus::KillSwitch);
}

/// AT-00-008 (traySource.test.ts «treats an active firewall kill-switch as active
/// protection»): with the kill switch engaged «Выключить» is offered and «Включить» is not.
#[test]
fn engaged_kill_switch_is_active_protection() {
    let fw = TrayState {
        kill_switch: true,
        ..disconnected()
    };
    assert!(!enabled(&fw, TrayItemId::Start));
    assert!(enabled(&fw, TrayItemId::Stop));
    let blocked = TrayState {
        tunnel: TunnelState::Blocked,
        ..disconnected()
    };
    assert!(!enabled(&blocked, TrayItemId::Start));
    assert!(enabled(&blocked, TrayItemId::Stop));
}

/// AT-00-008: speed format derived from `tray.ts:104-108`.
#[test]
fn speed_format() {
    assert_eq!(format_speed(0), "0 Kbps");
    assert_eq!(format_speed(1_000), "8 Kbps");
    assert_eq!(format_speed(125_000), "1.0 Mbps");
    assert_eq!(format_speed(2_000_000), "16 Mbps");
    // edges: 999 992 bit/s still Kbps; an exact tie rounds up like JS
    assert_eq!(format_speed(124_999), "1000 Kbps");
    assert_eq!(format_speed(156_250), "1.3 Mbps");
    assert_eq!(format_speed(1_249_999), "10.0 Mbps");
    assert_eq!(format_speed(1_250_000), "10 Mbps");
    assert_eq!(format_speed(u64::MAX), "18446744073709 Mbps");
}
#[test]
fn transitions_win_over_everything() {
    for (transition, status) in [
        (Transition::Connecting, TrayStatus::Starting),
        (Transition::Disconnecting, TrayStatus::Stopping),
        (Transition::Reconnecting, TrayStatus::Restarting),
    ] {
        let state = TrayState {
            transition: Some(transition),
            leak: true,
            kill_switch: true,
            ..connected()
        };
        assert_eq!(TrayStatus::of(&state), status);
    }
    let error = TrayState {
        tunnel: TunnelState::Error,
        ..disconnected()
    };
    assert_eq!(TrayStatus::of(&error), TrayStatus::Error);
    // a confirmed kill switch outranks the error (firewallActive && state != connected)
    let error_fw = TrayState {
        kill_switch: true,
        ..error
    };
    assert_eq!(TrayStatus::of(&error_fw), TrayStatus::KillSwitch);
    // while connected the kill switch is the normal companion of protection
    let connected_fw = TrayState {
        kill_switch: true,
        ..connected()
    };
    assert_eq!(TrayStatus::of(&connected_fw), TrayStatus::Protected);
}

#[test]
fn enable_rules_per_status() {
    let off = disconnected();
    assert!(enabled(&off, TrayItemId::Start));
    assert!(!enabled(&off, TrayItemId::Stop));
    let protected = connected();
    assert!(!enabled(&protected, TrayItemId::Start));
    assert!(enabled(&protected, TrayItemId::Stop));
    for transition in [Transition::Connecting, Transition::Reconnecting] {
        let state = TrayState {
            transition: Some(transition),
            ..disconnected()
        };
        assert!(!enabled(&state, TrayItemId::Start), "{transition:?}");
        assert!(enabled(&state, TrayItemId::Stop), "{transition:?}");
    }
    let stopping = TrayState {
        transition: Some(Transition::Disconnecting),
        ..connected()
    };
    assert!(!enabled(&stopping, TrayItemId::Start));
    assert!(!enabled(&stopping, TrayItemId::Stop));
    // error / unknown: «Выключить» cleans up, «Включить» waits for it
    for tunnel in [TunnelState::Error, TunnelState::Unknown] {
        let state = TrayState {
            tunnel,
            ..disconnected()
        };
        assert!(!enabled(&state, TrayItemId::Start), "{tunnel:?}");
        assert!(enabled(&state, TrayItemId::Stop), "{tunnel:?}");
    }
    // a stray engine process counts as active even when the FSM says disconnected
    let stray = TrayState {
        engine_running: true,
        ..disconnected()
    };
    assert!(!enabled(&stray, TrayItemId::Start));
    assert!(enabled(&stray, TrayItemId::Stop));
    // the info lines are never clickable, the rest always (outside a quit)
    let model = TrayModel::build(&protected, false);
    for item in &model.items {
        let info = matches!(
            item.id,
            TrayItemId::Status | TrayItemId::Ip | TrayItemId::Proxy | TrayItemId::Speed
        );
        if info {
            assert!(!item.enabled, "{:?}", item.id);
        } else if item.id != TrayItemId::Start {
            assert!(item.enabled, "{:?}", item.id);
        }
    }
}

#[test]
fn quitting_leaves_only_show_window() {
    for state in [disconnected(), connected()] {
        let model = TrayModel::build(&state, true);
        let usable: Vec<TrayItemId> = model
            .items
            .iter()
            .filter(|item| item.enabled)
            .map(|item| item.id)
            .collect();
        assert_eq!(usable, [TrayItemId::Show]);
    }
}
#[test]
fn tooltip_and_info_lines() {
    let off = TrayModel::build(&disconnected(), false);
    assert_eq!(off.tooltip, [Msg::new("ui.tray.tip.off")]);
    assert_eq!(off.tooltip_speed, None);
    assert_eq!(
        off.item(TrayItemId::Status).label,
        Msg::new("ui.tray.menu.status.off")
    );
    assert_eq!(
        off.item(TrayItemId::Ip).label,
        Msg::new("ui.tray.ipUnknown")
    );
    assert_eq!(
        off.item(TrayItemId::Proxy).label,
        Msg::new("ui.tray.proxyNone")
    );
    let on = TrayState {
        public_ip: Some("198.51.100.7".into()),
        proxy_addr: Some("127.0.0.1:2080".into()),
        down_bps: 125_000,
        up_bps: 1_000,
        ..connected()
    };
    let model = TrayModel::build(&on, false);
    let ip = Msg::new("ui.tray.ip").arg("ip", "198.51.100.7");
    let proxy = Msg::new("ui.tray.proxy").arg("addr", "127.0.0.1:2080");
    assert_eq!(
        model.tooltip,
        [Msg::new("ui.tray.tip.protected"), ip.clone(), proxy.clone()]
    );
    assert_eq!(
        model.tooltip_speed,
        Some(
            Msg::new("ui.tray.tip.speed")
                .arg("down", "1.0 Mbps")
                .arg("up", "8 Kbps")
        )
    );
    assert_eq!(model.item(TrayItemId::Ip).label, ip);
    assert_eq!(model.item(TrayItemId::Proxy).label, proxy);
    assert_eq!(
        model.item(TrayItemId::Speed).label,
        Msg::new("ui.tray.menu.speed")
            .arg("down", "1.0 Mbps")
            .arg("up", "8 Kbps")
    );
    let restarting = TrayState {
        transition: Some(Transition::Reconnecting),
        restart: Some((2, 5)),
        ..connected()
    };
    let model = TrayModel::build(&restarting, false);
    assert_eq!(
        model.tooltip[0],
        Msg::new("ui.tray.tip.restartingProgress")
            .arg("n", 2)
            .arg("max", 5)
    );
    let bare = TrayState {
        restart: None,
        ..restarting
    };
    assert_eq!(
        TrayModel::build(&bare, false)
            .item(TrayItemId::Status)
            .label,
        Msg::new("ui.tray.menu.status.restarting")
    );
}

#[test]
fn menu_ids_round_trip_and_separators() {
    for id in TrayItemId::ALL {
        assert_eq!(TrayItemId::from_menu_id(id.menu_id()), Some(id));
    }
    assert_eq!(TrayItemId::from_menu_id("dioxus-float-top"), None);
    let separated: Vec<TrayItemId> = TrayItemId::ALL
        .into_iter()
        .filter(|id| id.separator_after())
        .collect();
    assert_eq!(separated, [TrayItemId::Speed, TrayItemId::OpenLogs]);
    let model = TrayModel::build(&disconnected(), false);
    let order: Vec<TrayItemId> = model.items.iter().map(|item| item.id).collect();
    assert_eq!(order, TrayItemId::ALL);
}

#[test]
fn badges_follow_the_old_palette() {
    let badge = |s: TrayStatus| s.badge();
    assert_eq!(badge(TrayStatus::Protected), Badge::Green);
    assert_eq!(badge(TrayStatus::Leak), Badge::Red);
    assert_eq!(badge(TrayStatus::KillSwitch), Badge::Red);
    assert_eq!(badge(TrayStatus::Off), Badge::Off);
    for status in [
        TrayStatus::Starting,
        TrayStatus::ProxyDown,
        TrayStatus::Restarting,
        TrayStatus::Stopping,
        TrayStatus::Error,
        TrayStatus::Unknown,
    ] {
        assert_eq!(badge(status), Badge::Amber, "{status:?}");
    }
}

#[test]
fn tooltip_fits_the_shell_limit() {
    let short = vec!["VPN Tunnel Enforcer — Off".to_owned()];
    assert_eq!(fit_tooltip(&short), "VPN Tunnel Enforcer — Off");
    let lines = vec![
        "VPN Tunnel Enforcer — Ошибка защиты — повторите восстановление".to_owned(),
        "IP: 2001:db8:85a3:8d3:1319:8a2e:370:7348".to_owned(),
        "Proxy: proxy.example.net:443".to_owned(),
        "↓ 12.3 Mbps / ↑ 1.2 Mbps".to_owned(),
    ];
    let fitted = fit_tooltip(&lines);
    assert_eq!(fitted.encode_utf16().count(), TOOLTIP_MAX);
    assert!(fitted.ends_with('…'));
    assert!(fitted.starts_with("VPN Tunnel Enforcer — Ошибка"));
    // a cut right after a line break does not leave the break dangling
    let mut exact = vec!["x".repeat(TOOLTIP_MAX - 2)];
    exact.push("tail".to_owned());
    assert_eq!(
        fit_tooltip(&exact),
        format!("{}…", "x".repeat(TOOLTIP_MAX - 2))
    );
}

/// The close button follows «Сворачивать в трей», connected or not; no question (owner,
/// 12.11.2026).
#[test]
fn close_requests() {
    let mut state = disconnected();
    assert_eq!(state.close_action(), CloseAction::Quit);
    state.minimize_to_tray = true;
    assert_eq!(state.close_action(), CloseAction::Hide);
    let connected_tray = TrayState {
        minimize_to_tray: true,
        ..connected()
    };
    assert_eq!(connected_tray.close_action(), CloseAction::Hide);
    let connected_quit = TrayState {
        minimize_to_tray: false,
        ..connected()
    };
    assert_eq!(connected_quit.close_action(), CloseAction::Quit);
    let connecting = TrayState {
        transition: Some(Transition::Connecting),
        ..disconnected()
    };
    assert_eq!(connecting.close_action(), CloseAction::Quit);
}
