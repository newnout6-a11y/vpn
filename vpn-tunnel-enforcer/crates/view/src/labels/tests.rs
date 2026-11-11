use super::*;
use crate::identity::Geo;
use crate::swiss::{Mode, Transition};

fn key(m: &Msg) -> &str {
    &m.key
}

fn on() -> ConnView {
    ConnView {
        state: TunnelState::Connected,
        mode: Some(Mode::Tun),
        cleanup_required: true,
        started_at: Some(1),
        ..ConnView::default()
    }
}

fn with(f: impl FnOnce(&mut ConnView)) -> ConnView {
    let mut c = on();
    f(&mut c);
    c
}

/// ui-dashboard §3.1 (`Dashboard.tsx:522-534`) priority order, plus the D-03 degraded branch.
#[test]
fn status_label_priority() {
    let cases: [(ConnView, &str); 12] = [
        (with(|c| c.cancelling = true), "dashboard.cancelling"),
        (
            with(|c| c.switching = Some("Riga-2".into())),
            "dashboard.switchingServer",
        ),
        (
            with(|c| c.transition = Some(Transition::Connecting)),
            "dashboard.connecting",
        ),
        (
            with(|c| c.restarting = Some((1, 3))),
            "dashboard.connecting",
        ),
        (
            with(|c| c.transition = Some(Transition::Disconnecting)),
            "dashboard.disconnecting",
        ),
        (
            with(|c| c.state = TunnelState::Blocked),
            "dashboard.tunnelBlocked",
        ),
        (
            with(|c| c.state = TunnelState::Unknown),
            "dashboard.tunnelUnknown",
        ),
        (
            with(|c| c.state = TunnelState::Error),
            "dashboard.tunnelError",
        ),
        (
            with(|c| {
                c.proxy_down = true;
                c.degraded = true;
            }),
            "view.status.proxyDown",
        ),
        (with(|c| c.degraded = true), "view.status.degraded"),
        (on(), "dashboard.connected"),
        (ConnView::default(), "dashboard.disconnected"),
    ];
    for (conn, expected) in cases {
        assert_eq!(key(&status_label(&conn)), expected, "{conn:?}");
    }
    let switching = status_label(&with(|c| c.switching = Some("Riga-2".into())));
    assert_eq!(
        switching,
        Msg::new("dashboard.switchingServer").arg("name", "Riga-2")
    );
    let competing = status_label(&with(|c| c.competing_tun = Some("wg0".into())));
    assert_eq!(
        competing,
        Msg::new("view.status.degradedTun").arg("name", "wg0")
    );
    // Proxy down is only believed while connected.
    let off = ConnView {
        proxy_down: true,
        ..ConnView::default()
    };
    assert_eq!(key(&status_label(&off)), "dashboard.disconnected");
}

/// ui-dashboard §2.1 (`Dashboard.tsx:862-915`): label, tooltip, look and wait state.
#[test]
fn power_button_states() {
    let idle = power_button(&ConnView::default());
    assert_eq!(key(&idle.label), "dashboard.swissEnable");
    assert_eq!(key(&idle.title), "dashboard.swissEnable");
    assert_eq!((idle.look, idle.waiting), (PowerLook::Plain, false));
    let connected = power_button(&on());
    assert_eq!(key(&connected.label), "dashboard.swissDisable");
    assert_eq!(connected.look, PowerLook::On);
    // A blocked tunnel still has our resources installed: the action is "turn off", and the
    // button is enabled (§7.8 #2: a fault is not a transition).
    let blocked = power_button(&with(|c| c.state = TunnelState::Blocked));
    assert_eq!(key(&blocked.label), "dashboard.swissDisable");
    assert_eq!((blocked.look, blocked.waiting), (PowerLook::Plain, false));
    let switching = power_button(&with(|c| c.switching = Some("Riga-2".into())));
    assert_eq!(key(&switching.label), "dashboard.switchingServer");
    assert_eq!(
        (switching.look, switching.waiting),
        (PowerLook::Switching, true)
    );
    let cancelling = power_button(&with(|c| {
        c.cancelling = true;
        c.transition = Some(Transition::Connecting);
    }));
    assert_eq!(key(&cancelling.label), "dashboard.cancelling");
    assert_eq!(
        (cancelling.look, cancelling.waiting),
        (PowerLook::Cancelling, true)
    );
    let connecting = power_button(&ConnView {
        transition: Some(Transition::Connecting),
        ..ConnView::default()
    });
    assert_eq!(key(&connecting.label), "dashboard.connecting");
    assert_eq!(key(&connecting.title), "dashboard.swissEnable");
    assert!(connecting.waiting);
}

#[test]
fn cancel_button_label() {
    assert_eq!(cancel_label(&on()), None);
    let connecting = ConnView {
        transition: Some(Transition::Connecting),
        ..ConnView::default()
    };
    assert_eq!(
        cancel_label(&connecting).unwrap().key,
        "dashboard.cancelConnection"
    );
    let switching = with(|c| c.switching = Some("Riga-2".into()));
    assert_eq!(
        cancel_label(&switching).unwrap().key,
        "dashboard.cancelServerSwitch"
    );
    let cancelling = ConnView {
        cancelling: true,
        ..switching
    };
    assert_eq!(
        cancel_label(&cancelling).unwrap().key,
        "dashboard.cancelling"
    );
    let closing = with(|c| c.transition = Some(Transition::Disconnecting));
    assert_eq!(cancel_label(&closing), None);
}

/// AT-00-008 (ui-dashboard §7.8 #5): during a canonical reconnect the selected server is shown
/// and the switch can be cancelled.
#[test]
fn switch_during_reconnect() {
    let conn = with(|c| {
        c.transition = Some(Transition::Reconnecting);
        c.switching = Some("Norway".into());
    });
    assert_eq!(
        status_label(&conn),
        Msg::new("dashboard.switchingServer").arg("name", "Norway")
    );
    assert_eq!(
        cancel_label(&conn).map(|m| m.key),
        Some("dashboard.cancelServerSwitch".into())
    );
    assert!(power_button(&conn).waiting);
}

/// ui-dashboard §2.4 (`SwissFactsStrip.tsx:56-64`) value tables and emphasis.
#[test]
fn facts_strip_values() {
    assert_eq!(key(&mode_fact(false).text), "swiss.modeHard");
    assert_eq!(key(&mode_fact(true).text), "swiss.modeSoft");
    let smart = smart_fact(true);
    assert_eq!(
        (
            key(&smart.value.text),
            key(&smart.action),
            key(&smart.action_aria)
        ),
        ("swiss.on", "swiss.turnOff", "swiss.smartTurnOff")
    );
    assert!(!smart.value.dim);
    let smart = smart_fact(false);
    assert_eq!(key(&smart.value.text), "swiss.off");
    assert!(smart.value.dim);

    let fw = |state, checking| kill_switch_fact(&FirewallStatus { state, checking });
    let checking = kill_switch_fact(&FirewallStatus::default());
    assert_eq!(
        (key(&checking.text), checking.alert),
        ("swiss.ksChecking", false)
    );
    let holding = fw(FwState::Verified, false);
    assert_eq!(
        (key(&holding.text), holding.alert, holding.dim),
        ("swiss.ksHolding", false, false)
    );
    let off = fw(FwState::Inactive, false);
    assert_eq!((key(&off.text), off.dim), ("swiss.ksOff", true));
    let unknown = fw(FwState::Unknown, false);
    assert_eq!(
        (key(&unknown.text), unknown.alert),
        ("swiss.ksUnknown", true)
    );

    let none = leak_fact(Verdict::NotChecked, false);
    assert_eq!(
        (key(&none.text), none.dim, none.alert),
        ("view.dash", true, false)
    );
    let running = leak_fact(Verdict::NotChecked, true);
    assert_eq!(
        (key(&running.text), running.dim),
        ("swiss.leakChecking", false)
    );
    assert_eq!(key(&leak_fact(Verdict::Ok, false).text), "swiss.leakNone");
    assert_eq!(key(&leak_fact(Verdict::Warn, false).text), "swiss.leakWarn");
    let found = leak_fact(Verdict::Fail, false);
    assert_eq!((key(&found.text), found.alert), ("swiss.leakFound", true));
}

fn exit(ip: Option<&str>, verdict: Verdict, leak: bool) -> ExitIp {
    ExitIp {
        ip: ip.map(|s| s.parse().unwrap()),
        verdict,
        leak,
        ..ExitIp::default()
    }
}

/// AT-07-001 / AT-07-006 (ui-dashboard §7.8 #14-15; `Dashboard.tsx:779-794` sub-line branches),
/// plus the D-29 busy line. An unverified exit IP is shown with «— » + the reason, never as a leak.
#[test]
fn exit_line_branches() {
    let vpn = "13.143.217.2";
    let leak = exit_line(&on(), &exit(Some(vpn), Verdict::Fail, true));
    assert_eq!(
        (key(&leak.sub.text), leak.sub.dash, leak.sub.alert),
        ("dashboard.swissIpLeak", true, true)
    );
    let unverified = exit_line(&on(), &exit(Some(vpn), Verdict::NotChecked, false));
    assert_eq!(
        (key(&unverified.sub.text), unverified.sub.dash),
        ("dashboard.ipNotChecked", true)
    );
    assert_eq!(unverified.ip, Some(vpn.parse().unwrap()));
    assert!(!unverified.dim && !unverified.sub.alert);
    let changed = exit_line(&on(), &exit(Some(vpn), Verdict::Warn, false));
    assert_eq!(key(&changed.sub.text), "dashboard.ipChangedUnverified");
    assert!(changed.sub.dash && !changed.sub.alert);
    let mut verified = exit(Some(vpn), Verdict::Ok, false);
    assert_eq!(
        key(&exit_line(&on(), &verified).sub.text),
        "dashboard.swissViaVpn"
    );
    verified.geo = Some((
        vpn.parse().unwrap(),
        Geo {
            country: Some("Netherlands".into()),
            city: Some("Amsterdam".into()),
        },
    ));
    let geo = exit_line(&on(), &verified);
    assert_eq!(
        geo.sub.text,
        Msg::new("view.identity.countryCity")
            .arg("country", "Netherlands")
            .arg("city", "Amsterdam")
    );
    assert_eq!(geo.sub.flag.as_deref(), Some("Netherlands"));
    assert!(!geo.dim);
    let detecting = exit_line(&on(), &exit(None, Verdict::NotChecked, false));
    assert_eq!(key(&detecting.sub.text), "dashboard.swissIpDetecting");
    assert!(detecting.dim);
    let isp = exit_line(
        &ConnView::default(),
        &exit(Some("203.0.113.47"), Verdict::NotChecked, false),
    );
    assert_eq!(key(&isp.sub.text), "dashboard.swissIpYourIsp");
    // D-29: mid-switch the old exit IP is dim with the neutral status, never «ваш провайдер».
    let switching = with(|c| {
        c.switching = Some("Riga-2".into());
        c.transition = Some(Transition::Reconnecting);
    });
    let busy = exit_line(&switching, &verified);
    assert!(busy.dim && !busy.sub.alert && busy.sub.flag.is_none());
    assert_eq!(key(&busy.sub.text), "dashboard.switchingServer");
    // A faulted tunnel proves nothing about the exit either (word ALERT, not EXPOSED): the fault
    // text, dim, no «ваш провайдер»; a reported leak still shows.
    let home_ip = exit(Some("203.0.113.47"), Verdict::NotChecked, false);
    for (state, text) in [
        (TunnelState::Blocked, "dashboard.tunnelBlocked"),
        (TunnelState::Unknown, "dashboard.tunnelUnknown"),
        (TunnelState::Error, "dashboard.tunnelError"),
    ] {
        let faulted = ConnView {
            state,
            ..ConnView::default()
        };
        let line = exit_line(&faulted, &home_ip);
        assert_eq!((key(&line.sub.text), line.dim), (text, true), "{state:?}");
        let leaking = exit_line(&faulted, &exit(Some(vpn), Verdict::Fail, true));
        assert_eq!(key(&leaking.sub.text), "dashboard.swissIpLeak");
        assert!(leaking.sub.alert && !leaking.dim);
    }
}

/// D-29: exposure wording only for a settled off state or a visible leak.
#[test]
fn real_line_looks() {
    let home = Some("203.0.113.47".parse().unwrap());
    let clean = exit(Some("198.51.100.23"), Verdict::Ok, false);
    let hidden = real_line(&on(), &clean, home);
    assert!(hidden.struck() && hidden.sub().is_none());
    assert!(!real_line(&on(), &clean, None).struck());
    let leaking = real_line(
        &on(),
        &exit(Some("203.0.113.47"), Verdict::Fail, true),
        home,
    );
    assert_eq!(leaking.look, RealLook::Exposed);
    assert_eq!(
        leaking.sub().unwrap().text.key,
        "dashboard.swissExposedToAll"
    );
    let off = real_line(&ConnView::default(), &clean, home);
    assert_eq!(off.look, RealLook::Exposed);
    assert!(!off.struck());
    for conn in [
        with(|c| c.transition = Some(Transition::Connecting)),
        with(|c| c.cancelling = true),
        with(|c| c.state = TunnelState::Blocked),
        ConnView {
            state: TunnelState::Unknown,
            ..ConnView::default()
        },
    ] {
        let line = real_line(&conn, &clean, home);
        assert_eq!(line.look, RealLook::Neutral, "{conn:?}");
        assert!(!line.struck() && line.sub().is_none());
    }
    // A leak reported while the tunnel is faulted is still the real address seen by sites.
    let faulted = ConnView {
        state: TunnelState::Error,
        ..ConnView::default()
    };
    let leak = exit(Some("203.0.113.47"), Verdict::Fail, true);
    assert_eq!(real_line(&faulted, &leak, home).look, RealLook::Exposed);
}

/// ui-dashboard §3.1 (`Dashboard.tsx:579-597`): «VLESS · 38 мс» and its fallbacks.
#[test]
fn node_meta_variants() {
    use ServerHealth::*;
    assert_eq!(
        node_meta(Some("vless"), Some(38), Online),
        Msg::new("view.identity.metaPing")
            .arg("protocol", "VLESS")
            .arg("ms", 38)
    );
    assert_eq!(
        node_meta(None, Some(38), Online),
        Msg::new("view.identity.ping").arg("ms", 38)
    );
    assert_eq!(
        node_meta(Some("trojan"), None, Offline),
        Msg::new("view.identity.metaOffline").arg("protocol", "TROJAN")
    );
    assert_eq!(
        node_meta(Some(""), None, Offline),
        Msg::new("dashboard.swissOffline")
    );
    assert_eq!(
        node_meta(Some("hy2"), None, Unknown),
        Msg::new("view.identity.metaUnchecked").arg("protocol", "HY2")
    );
    assert_eq!(
        node_meta(None, None, Online),
        Msg::new("dashboard.swissUnchecked")
    );
    // A ping wins over an offline health mark, as before.
    assert_eq!(
        key(&node_meta(None, Some(5), Offline)),
        "view.identity.ping"
    );
}

/// ui-dashboard §2.5 (`SwissPanels.tsx:249-253`).
#[test]
fn server_health_labels() {
    use ServerHealth::*;
    assert_eq!(health_label(Offline, Some(3)), Msg::new("swiss.offline"));
    assert_eq!(health_label(Unknown, None), Msg::new("swiss.unchecked"));
    assert_eq!(health_label(Online, None), Msg::new("swiss.online"));
    assert_eq!(health_label(Online, Some(0)), Msg::new("swiss.justNow"));
    assert_eq!(
        health_label(Online, Some(7)),
        Msg::new("swiss.minAgo").arg("n", 7)
    );
}

/// AT-03-001 / AT-03-003 (ui-dashboard §7.8 #7-8; `Dashboard.tsx:421-431`) without the dead
/// suppression timer (D-28): no banner while the read-back runs, «not confirmed» when it failed.
#[test]
fn kill_switch_banner_visibility() {
    let held = FirewallStatus {
        state: FwState::Verified,
        checking: false,
    };
    let off = ConnView::default();
    let banner = kill_switch_banner(&off, &held).unwrap();
    assert_eq!(key(&banner.title), "dashboard.firewallVerifiedTitle");
    assert_eq!(key(&banner.body), "dashboard.firewallVerifiedBody");
    let unknown = FirewallStatus {
        state: FwState::Unknown,
        checking: false,
    };
    assert_eq!(
        key(&kill_switch_banner(&off, &unknown).unwrap().title),
        "dashboard.firewallUnknownTitle"
    );
    assert!(kill_switch_banner(&off, &FirewallStatus::default()).is_none());
    let inactive = FirewallStatus {
        state: FwState::Inactive,
        checking: false,
    };
    assert!(kill_switch_banner(&off, &inactive).is_none());
    for conn in [
        on(),
        ConnView {
            transition: Some(Transition::Connecting),
            ..off.clone()
        },
        ConnView {
            switching: Some("Riga-2".into()),
            ..off.clone()
        },
        ConnView {
            restarting: Some((2, 3)),
            ..off.clone()
        },
    ] {
        assert!(kill_switch_banner(&conn, &held).is_none(), "{conn:?}");
    }
    // Soft mode runs no TUN: a held kill switch is shown.
    let soft = with(|c| c.mode = Some(Mode::Soft));
    assert!(kill_switch_banner(&soft, &held).is_some());
}

/// ui-dashboard §7.5 (`useForeignVpn.test.ts:11-45`).
#[test]
fn foreign_vpn_friendly_names() {
    let cases: [(&str, &str); 13] = [
        ("happ-tun (172.18.0.1)", "Happ"),
        ("Happ-TUN (172.18.0.2)", "Happ"),
        ("hiddify-tunnel (10.0.0.1)", "Hiddify"),
        ("WireGuard Tunnel (10.2.0.2)", "WireGuard"),
        ("wg0 (10.7.0.1)", "WireGuard"),
        ("OpenVPN TAP-Windows6 (10.8.0.6)", "OpenVPN"),
        ("tap-windows adapter (10.8.0.1)", "OpenVPN"),
        ("xray-tun (198.18.0.1)", "Xray/V2Ray"),
        ("v2ray-tun (198.18.0.2)", "Xray/V2Ray"),
        ("singbox-tun (198.18.0.3)", "Xray/V2Ray"),
        ("mystery-tun (10.1.2.3)", "mystery-tun"),
        ("Some Adapter", "Some Adapter"),
        ("(10.1.2.3)", "(10.1.2.3)"),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            foreign_vpn_friendly_name(Some(raw)).as_deref(),
            Some(expected),
            "{raw}"
        );
    }
    assert_eq!(foreign_vpn_friendly_name(None), None);
    assert_eq!(foreign_vpn_friendly_name(Some("")), None);
}

/// The `\bwg\d*\b` token and the `\s*\(.*\)\s*$` suffix rules of the old regexes.
#[test]
fn regex_ports() {
    for yes in ["wg", "wg0", "my-wg2 (x)", "x wg12", "яwg"] {
        assert!(has_wg_token(yes), "{yes}");
    }
    for no in ["wgx", "swg", "wg0x", "_wg", "awg1"] {
        assert!(!has_wg_token(no), "{no}");
    }
    assert_eq!(strip_paren_suffix("name (a) b (c)  "), "name");
    assert_eq!(strip_paren_suffix("name (a)\n"), "name");
    assert_eq!(strip_paren_suffix("one (a)\ntwo (b)"), "one (a)\ntwo");
    assert_eq!(strip_paren_suffix("name (a) b"), "name (a) b");
    assert_eq!(strip_paren_suffix("name)"), "name)");
    // U+2028 / U+2029 end a line for `.` too, and they are three bytes long.
    assert_eq!(
        strip_paren_suffix("one (a)\u{2028}two (b)"),
        "one (a)\u{2028}two"
    );
    assert_eq!(strip_paren_suffix("name\u{2029}(a)"), "name");
    assert_eq!(
        foreign_vpn_friendly_name(Some("tun\u{2028}x (10.0.0.1)")).as_deref(),
        Some("tun\u{2028}x")
    );
}

/// Every message this package emits must resolve in both languages (base UI strings plus the
/// crate's fragments), and every `{{placeholder}}` of the template must be supplied.
#[test]
fn every_emitted_key_resolves_in_both_languages() {
    let catalogs = crate::test_locales::catalogs();
    for msg in emitted() {
        crate::test_locales::assert_resolves(&msg, &catalogs);
    }
}

fn emitted() -> Vec<Msg> {
    use crate::swiss::SwissState::{self, *};
    use crate::traffic::{HISTORY, TrafficHistory};
    let words = [
        Cancel, Switch, Linking, Closing, Restart, Leak, Alert, Blocked, Degraded, Verify, Secure,
        Exposed,
    ];
    let mut out: Vec<Msg> = words.into_iter().map(SwissState::word).collect();
    let conns = [
        ConnView::default(),
        ConnView {
            transition: Some(Transition::Connecting),
            ..ConnView::default()
        },
        on(),
        with(|c| c.cancelling = true),
        with(|c| c.switching = Some("Riga-2".into())),
        with(|c| c.transition = Some(Transition::Disconnecting)),
        with(|c| c.state = TunnelState::Blocked),
        with(|c| c.state = TunnelState::Unknown),
        with(|c| c.state = TunnelState::Error),
        with(|c| c.proxy_down = true),
        with(|c| c.degraded = true),
        with(|c| c.competing_tun = Some("wg0".into())),
    ];
    let ip = "198.51.100.23";
    let geo = |city: Option<&str>| ExitIp {
        geo: Some((
            ip.parse().unwrap(),
            Geo {
                country: Some("Netherlands".into()),
                city: city.map(Into::into),
            },
        )),
        ..exit(Some(ip), Verdict::Ok, false)
    };
    let exits = [
        exit(None, Verdict::NotChecked, false),
        exit(Some(ip), Verdict::NotChecked, false),
        exit(Some(ip), Verdict::Warn, false),
        exit(Some(ip), Verdict::Ok, false),
        exit(Some(ip), Verdict::Fail, true),
        geo(Some("Amsterdam")),
        geo(None),
    ];
    let firewalls =
        [FwState::Verified, FwState::Inactive, FwState::Unknown].map(|state| FirewallStatus {
            state,
            checking: false,
        });
    for conn in &conns {
        out.push(status_label(conn));
        let power = power_button(conn);
        out.extend([power.label, power.title]);
        out.extend(cancel_label(conn));
        for e in &exits {
            out.push(exit_line(conn, e).sub.text);
            out.extend(real_line(conn, e, None).sub().map(|s| s.text));
        }
        for fw in &firewalls {
            out.extend(
                kill_switch_banner(conn, fw)
                    .into_iter()
                    .flat_map(|b| [b.title, b.body]),
            );
        }
    }
    for flag in [false, true] {
        let smart = smart_fact(flag);
        out.extend([
            mode_fact(flag).text,
            smart.value.text,
            smart.action,
            smart.action_aria,
        ]);
    }
    for fw in firewalls.into_iter().chain([FirewallStatus::default()]) {
        out.push(kill_switch_fact(&fw).text);
    }
    for summary in [
        Verdict::Ok,
        Verdict::Warn,
        Verdict::Fail,
        Verdict::NotChecked,
    ] {
        out.extend([
            leak_fact(summary, false).text,
            leak_fact(summary, true).text,
        ]);
    }
    use ServerHealth::*;
    for health in [Online, Offline, Unknown] {
        for (protocol, ping) in [
            (Some("vless"), Some(38)),
            (None, Some(38)),
            (Some("vless"), None),
            (None, None),
        ] {
            out.push(node_meta(protocol, ping, health));
        }
        for ago in [None, Some(0), Some(4)] {
            out.push(health_label(health, ago));
        }
    }
    out.extend(TrafficHistory::new().hover_msg(HISTORY - 1));
    out
}
