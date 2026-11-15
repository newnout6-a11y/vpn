use std::time::Duration;

use super::*;

fn live() -> SwissInput {
    SwissInput {
        connected: true,
        tunnel_state: TunnelState::Connected,
        verdict: Verdict::Ok,
        ..SwissInput::default()
    }
}

/// ui-dashboard §7.1 (`swissState.test.ts:4-32`): the whole precedence table. The old test
/// used `tunnelState: 'running'`; the real snapshot value is `connected` (same behaviour).
#[test]
fn derive_swiss_state_table() {
    use SwissState::*;
    let idle = SwissInput::default();
    let cases: [(&str, SwissInput, SwissState); 15] = [
        ("nothing running", idle, Exposed),
        (
            "a leak only counts while connected",
            SwissInput { leak: true, ..idle },
            Exposed,
        ),
        (
            "an unknown tunnel alerts even when not connected",
            SwissInput {
                tunnel_state: TunnelState::Unknown,
                ..idle
            },
            Alert,
        ),
        ("connected, healthy, IP verified", live(), Secure),
        (
            "connected, IP not verified yet",
            SwissInput {
                verdict: Verdict::NotChecked,
                ..live()
            },
            Verify,
        ),
        (
            "connected, IP indeterminate",
            SwissInput {
                verdict: Verdict::Warn,
                ..live()
            },
            Verify,
        ),
        (
            "degraded beats verify",
            SwissInput {
                verdict: Verdict::NotChecked,
                degraded: true,
                ..live()
            },
            Degraded,
        ),
        (
            "blocked beats degraded",
            SwissInput {
                degraded: true,
                proxy_down: true,
                ..live()
            },
            Blocked,
        ),
        (
            "alert beats blocked",
            SwissInput {
                proxy_down: true,
                tunnel_state: TunnelState::Blocked,
                ..live()
            },
            Alert,
        ),
        (
            "leak beats alert",
            SwissInput {
                tunnel_state: TunnelState::Error,
                leak: true,
                ..live()
            },
            Leak,
        ),
        (
            "restart beats a leak",
            SwissInput {
                leak: true,
                restarting: true,
                ..live()
            },
            Restart,
        ),
        (
            "closing beats restart",
            SwissInput {
                restarting: true,
                disconnecting: true,
                ..live()
            },
            Closing,
        ),
        (
            "linking beats closing",
            SwissInput {
                disconnecting: true,
                connecting: true,
                ..idle
            },
            Linking,
        ),
        (
            "switch beats linking",
            SwissInput {
                connecting: true,
                switching: true,
                ..live()
            },
            Switch,
        ),
        (
            "cancel beats everything",
            SwissInput {
                leak: true,
                switching: true,
                connecting: true,
                cancelling: true,
                ..live()
            },
            Cancel,
        ),
    ];
    for (name, input, expected) in cases {
        assert_eq!(derive_swiss_state(&input), expected, "{name}");
    }
}

#[test]
fn words_flags_and_phase() {
    assert_eq!(SwissState::Secure.word().key, "dashboard.swissWordSecure");
    assert_eq!(SwissState::Exposed.word().key, "dashboard.swissWordExposed");
    assert!(SwissState::Secure.is_on() && !SwissState::Verify.is_on());
    for s in [
        SwissState::Leak,
        SwissState::Alert,
        SwissState::Blocked,
        SwissState::Degraded,
    ] {
        assert!(s.is_alert(), "{s:?}");
        assert_eq!(swiss_phase(s, true), MascotPhase::Alert);
    }
    assert!(!SwissState::Verify.is_alert());
    // A live tunnel waiting for its IP check is not reconnecting.
    assert_eq!(swiss_phase(SwissState::Verify, false), MascotPhase::On);
    assert_eq!(swiss_phase(SwissState::Secure, false), MascotPhase::On);
    assert_eq!(
        swiss_phase(SwissState::Linking, true),
        MascotPhase::Connecting
    );
    assert_eq!(
        swiss_phase(SwissState::Cancel, true),
        MascotPhase::Connecting
    );
    assert_eq!(swiss_phase(SwissState::Exposed, false), MascotPhase::Off);
}

/// The store projection of the busy flags (`store.ts:253-270, 361-365`).
#[test]
fn conn_view_projection() {
    let off = ConnView::default();
    assert_eq!(off.busy(), None);
    assert!(!off.connected() && !off.swiss_busy());
    let linking = ConnView {
        state: TunnelState::Connected,
        transition: Some(Transition::Reconnecting),
        mode: Some(Mode::Tun),
        started_at: Some(5),
        ..ConnView::default()
    };
    assert_eq!(linking.busy(), Some(Busy::Connecting));
    assert!(!linking.connected() && linking.circle_busy());
    assert_eq!(linking.tun_started_at(), None);
    let cancelling = ConnView {
        cancelling: true,
        transition: Some(Transition::Connecting),
        ..ConnView::default()
    };
    assert_eq!(cancelling.busy(), Some(Busy::Disconnecting));
    let restarting = ConnView {
        restarting: Some((1, 3)),
        ..ConnView::default()
    };
    assert_eq!(restarting.busy(), Some(Busy::Connecting));
    let on = ConnView {
        transition: None,
        ..linking.clone()
    };
    assert!(on.connected() && on.tun_running() && !on.swiss_busy());
    assert_eq!(on.uptime_since(), Some(5));
    let switching = ConnView {
        switching: Some("Riga-2".into()),
        ..on.clone()
    };
    assert!(switching.circle_busy() && switching.uptime_since().is_none());
    // Soft mode has no TUN: no uptime label, no competing-TUN banner.
    let soft = ConnView {
        mode: Some(Mode::Soft),
        competing_tun: Some("happ-tun".into()),
        ..on.clone()
    };
    assert_eq!(soft.uptime_since(), None);
    assert_eq!(soft.competing_tun_banner(), None);
    assert!(soft.degraded_any());
    let competing = ConnView {
        competing_tun: Some("happ-tun".into()),
        ..on
    };
    assert_eq!(competing.competing_tun_banner(), Some("happ-tun"));
}

/// The dashboard's derive input: a leak is suppressed mid-switch, a competing TUN degrades.
#[test]
fn swiss_input_from_view() {
    let on = ConnView {
        state: TunnelState::Connected,
        mode: Some(Mode::Tun),
        ..ConnView::default()
    };
    let exit = ExitIp {
        verdict: Verdict::Ok,
        leak: true,
        ..ExitIp::default()
    };
    assert_eq!(
        derive_swiss_state(&SwissInput::new(&on, &exit)),
        SwissState::Leak
    );
    let switching = ConnView {
        switching: Some("Riga-2".into()),
        ..on.clone()
    };
    let input = SwissInput::new(&switching, &exit);
    assert!(!input.leak && input.switching);
    let clean = ExitIp {
        leak: false,
        ..exit
    };
    let competing = ConnView {
        competing_tun: Some("wg0".into()),
        ..on
    };
    assert_eq!(
        derive_swiss_state(&SwissInput::new(&competing, &clean)),
        SwissState::Degraded
    );
}

/// The big word of the reference scenes (`.tmp/rewrite/ref/ui/dashboard`), from the projection:
/// an auto-restart still reads LINKING (`restart-legacy`), a switch SWITCH, and so on.
#[test]
fn reference_scene_words() {
    use SwissState::*;
    let on = ConnView {
        state: TunnelState::Connected,
        mode: Some(Mode::Tun),
        cleanup_required: true,
        ..ConnView::default()
    };
    let passed = ExitIp {
        verdict: Verdict::Ok,
        ..ExitIp::default()
    };
    let with = |f: fn(&mut ConnView)| {
        let mut c = on.clone();
        f(&mut c);
        c
    };
    let scenes: [(&str, ConnView, ExitIp, SwissState); 12] = [
        (
            "disconnected",
            ConnView::default(),
            ExitIp::default(),
            Exposed,
        ),
        ("connected", on.clone(), passed.clone(), Secure),
        ("verify", on.clone(), ExitIp::default(), Verify),
        (
            "restart-legacy",
            ConnView {
                restarting: Some((1, 3)),
                ..ConnView::default()
            },
            ExitIp::default(),
            Linking,
        ),
        (
            "reconnecting",
            with(|c| c.transition = Some(Transition::Reconnecting)),
            ExitIp::default(),
            Linking,
        ),
        (
            "switching",
            with(|c| {
                c.transition = Some(Transition::Reconnecting);
                c.switching = Some("Germany · Frankfurt".into());
            }),
            passed.clone(),
            Switch,
        ),
        (
            "cancelling",
            ConnView {
                cancelling: true,
                transition: Some(Transition::Connecting),
                ..ConnView::default()
            },
            ExitIp::default(),
            Cancel,
        ),
        (
            "closing",
            with(|c| c.transition = Some(Transition::Disconnecting)),
            ExitIp::default(),
            Closing,
        ),
        (
            "competing-tun",
            with(|c| c.competing_tun = Some("happ-tun (172.18.0.1)".into())),
            passed.clone(),
            Degraded,
        ),
        (
            "proxy-down",
            with(|c| c.proxy_down = true),
            passed.clone(),
            Blocked,
        ),
        (
            "tunnel-blocked",
            with(|c| c.state = TunnelState::Blocked),
            ExitIp::default(),
            Alert,
        ),
        (
            "leak",
            on.clone(),
            ExitIp {
                verdict: Verdict::Fail,
                leak: true,
                ..ExitIp::default()
            },
            Leak,
        ),
    ];
    for (scene, conn, exit, word) in scenes {
        assert_eq!(
            derive_swiss_state(&SwissInput::new(&conn, &exit)),
            word,
            "{scene}"
        );
    }
}

/// ui-dashboard §7.2 (`FitWord.tsx:25-31`).
#[test]
fn fit_word_vectors() {
    let size = fit_word(400.0, 600.0, 1000.0, None).unwrap();
    assert!((size - 147.0).abs() < 1e-9, "{size}");
    assert_eq!(fit_word(400.0, 600.0, 600.0, None), Some(90.0));
    assert_eq!(fit_word(0.0, 600.0, 1000.0, Some(96.0)), Some(96.0));
    assert_eq!(fit_word(0.0, 600.0, 1000.0, None), None);
    assert_eq!(fit_word(400.0, 50.0, 1000.0, None), Some(WORD_MIN_PX));
    assert_eq!(fit_word(400.0, 600.0, 1000.0, Some(147.2)), Some(147.2));
    assert_eq!(fit_word(400.0, 600.0, 1000.0, Some(146.0)), Some(147.0));
    assert_eq!(fit_word(100.0, 2000.0, 2000.0, None), Some(WORD_MAX_PX));
}

/// ui-dashboard §2.5 (`SwissProgress.tsx`): cells fill by elapsed time against the deadline.
#[test]
fn ruler_fills_by_time() {
    let t0 = Instant::now();
    let op = OpWindow {
        started: t0,
        deadline: Some(t0 + Duration::from_secs(10)),
    };
    assert_eq!(ruler(Some(&op), false, t0), Ruler::default());
    assert_eq!(ruler(Some(&op), true, t0).lit, 0);
    let at = |ms| ruler(Some(&op), true, t0 + Duration::from_millis(ms));
    assert_eq!(
        at(2_500),
        Ruler {
            lit: 3,
            indeterminate: false
        }
    );
    assert_eq!(
        at(9_400),
        Ruler {
            lit: 9,
            indeterminate: false
        }
    );
    assert_eq!(at(60_000).lit, RULER_CELLS);
    let stripes = Ruler {
        lit: 0,
        indeterminate: true,
    };
    assert_eq!(ruler(None, true, t0), stripes);
    let open = OpWindow {
        deadline: None,
        ..op
    };
    assert_eq!(ruler(Some(&open), true, t0), stripes);
    let empty = OpWindow {
        deadline: Some(t0),
        ..op
    };
    assert_eq!(ruler(Some(&empty), true, t0), stripes);
}
