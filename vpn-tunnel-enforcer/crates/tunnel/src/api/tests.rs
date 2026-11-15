//! Tests of the shared runtime types: wire strings, receipts, errors, object safety.
use serde_json::{Value, json};
use vpnte_base::ErrorKind;

use super::*;

/// Every typed warning has a message in both languages; `Other` passes its message through.
/// A receipt message maps back to its typed warning, so events stay typed (fsm review).
#[test]
fn warnings_are_localized() {
    for w in [
        TunWarning::ForeignTunUnverified,
        TunWarning::ReleaseUnverified,
    ] {
        assert!(crate::test_locales::has_key(&w.msg().key), "{w:?}");
        assert_eq!(TunWarning::from_msg(w.msg()), w);
    }
    let other = Msg::new("engine.process.exited");
    assert_eq!(TunWarning::Other(other.clone()).msg(), other);
    assert_eq!(
        TunWarning::from_msg(other.clone()),
        TunWarning::Other(other)
    );
}

/// The typed statuses keep the old bus strings in logs (lifecycle-app §3.1 contract).
#[test]
fn status_kinds_render_the_old_wire_strings() {
    let cases = [
        (TunStatusKind::Stopping, "stopping"),
        (TunStatusKind::Adapting, "adapting"),
        (TunStatusKind::Stopped, "stopped"),
        (TunStatusKind::Running, "running"),
        (TunStatusKind::KillSwitchActive, "killswitch-active"),
        (
            TunStatusKind::Restarting { attempt: 1, max: 3 },
            "restarting:1/3",
        ),
        (
            TunStatusKind::ProxyDown {
                reason: Msg::new("x"),
            },
            "proxy-down",
        ),
        (
            TunStatusKind::Error {
                warning: Msg::new("x"),
            },
            "error",
        ),
        (
            TunStatusKind::PostTrialFailover {
                name: "nl-1".into(),
            },
            "post-trial-failover:nl-1",
        ),
        (
            TunStatusKind::CompetingTun { name: "wg0".into() },
            "competing-tun:wg0",
        ),
        (TunStatusKind::CompetingTunCleared, "competing-tun-cleared"),
    ];
    for (kind, wire) in cases {
        assert_eq!(kind.to_string(), wire);
    }
}

/// Only a full stop with every rollback step confirmed certifies the cleanup.
#[test]
fn stop_receipt_confirms_only_complete_cleanup() {
    let full = StopReceipt {
        operation_id: format!("stop_{}", "a".repeat(32)),
        ok: true,
        runtime_stopped: true,
        forced: true,
        protection_released: Some(true),
        baseline_restored: Some(true),
        adapter_gone: false,
        warnings: Vec::new(),
    };
    assert!(full.confirms_cleanup());
    let preserved = StopReceipt {
        protection_released: None,
        baseline_restored: None,
        ..full.clone()
    };
    assert!(!preserved.confirms_cleanup());
    assert!(
        !StopReceipt {
            baseline_restored: Some(false),
            ..full.clone()
        }
        .confirms_cleanup()
    );
    assert!(
        !StopReceipt {
            runtime_stopped: false,
            ..full
        }
        .confirms_cleanup()
    );
}

/// AT-02-002: a switch is verified only on the candidate's success or a preserved previous
/// upstream, never after ownership was lost; the initial receipt is a failure.
#[test]
fn switch_receipt_verification() {
    let failed = SwitchReceipt::default();
    assert_eq!(
        (failed.outcome, failed.active_slot),
        (SwitchOutcome::Failed, None)
    );
    assert!(!failed.verified());
    let preserved = SwitchReceipt {
        previous_preserved: true,
        active_slot: Some(Slot::A),
        ..SwitchReceipt::default()
    };
    assert!(preserved.verified());
    let success = SwitchReceipt {
        outcome: SwitchOutcome::Success,
        committed: true,
        active_slot: Some(Slot::B),
        ..SwitchReceipt::default()
    };
    assert!(success.verified());
    assert!(
        !SwitchReceipt {
            ownership_lost: true,
            ..success
        }
        .verified()
    );
    assert_eq!(Slot::A.other(), Slot::B);
    assert_eq!(Slot::B.other(), Slot::A);
}

/// Wire names match the old strings (`localProxy`, `confirm-previous`, `a`, …).
#[test]
fn wire_names() {
    let v = json!([
        ModeKind::LocalProxy,
        ModeKind::DirectVpn,
        Origin::Recovery,
        Slot::A,
        SwitchOutcome::Cancelled,
        SwitchPhase::ConfirmPrevious,
        SwitchPhase::StopCandidate,
    ]);
    assert_eq!(
        v,
        json!([
            "localProxy",
            "directVpn",
            "recovery",
            "a",
            "cancelled",
            "confirm-previous",
            "stop-candidate"
        ])
    );
    let status = serde_json::to_value(TunStatus::default()).unwrap();
    assert_eq!(status["proxyReachable"], true);
    assert_eq!(status["restartAttempt"], 0);
    assert_eq!(status["mode"], Value::Null);
    let mode = Mode::LocalProxy {
        addr: "127.0.0.1:10808".into(),
        kind: ProxyKind::Socks5,
    };
    assert_eq!(mode.kind(), ModeKind::LocalProxy);
}

/// Session secrets (controller secret, proxy credentials) never leave through `Serialize` or
/// `Debug` of the status (CONTRACT §4.9); the serialized status keeps the old shape.
#[test]
fn status_never_exposes_session_secrets() {
    let proxy = |port, pass: &str| ProxyEndpoint {
        port,
        user: "FAKE-user".into(),
        pass: pass.into(),
    };
    let status = TunStatus {
        running: true,
        session: Some(SessionEndpoints {
            clash_port: 20001,
            clash_secret: "FAKE-clash-secret".into(),
            direct: proxy(20002, "FAKE-direct-pass"),
            probe: Some(proxy(20003, "FAKE-probe-pass")),
            tun_luid: Some(7),
            tun_alias: Some("vpnte-tun".into()),
            proxy_port: None,
            logs: Vec::new(),
        }),
        ..TunStatus::default()
    };
    let json = serde_json::to_value(&status).unwrap();
    assert!(json.get("session").is_none());
    let mut keys: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "mode",
            "pid",
            "profileName",
            "protocol",
            "proxyAddr",
            "proxyReachable",
            "proxyType",
            "restartAttempt",
            "running",
            "startedAt",
            "warning"
        ]
    );
    let debug = format!("{status:?}");
    assert!(debug.contains("20001"));
    for secret in [
        "FAKE-clash-secret",
        "FAKE-direct-pass",
        "FAKE-probe-pass",
        "FAKE-user",
    ] {
        assert!(!debug.contains(secret), "{secret}");
    }
}

/// `TunError` carries the category and message and converts both ways with `AppError`.
#[test]
fn tun_error_round_trip() {
    let err = TunError::new(
        ErrorKind::Conflict,
        Msg::new("tunnel.runtime.alreadyRunning"),
    )
    .with_warning(Msg::new("tunnel.warning.releaseUnverified"));
    assert_eq!(err.kind(), ErrorKind::Conflict);
    assert_eq!(err.user_msg().key, "tunnel.runtime.alreadyRunning");
    assert_eq!(err.warnings.len(), 1);
    let app: AppError = err.into();
    assert_eq!(app.kind, ErrorKind::Conflict);
    let back = TunError::from(AppError::timeout());
    assert_eq!(back.user_msg().key, "errors.timeout");
    assert!(back.warnings.is_empty());
    assert_eq!(
        RestartOptions::default().release_timeout,
        Duration::from_secs(5)
    );
}

/// `Runtime` is usable as a shared trait object across tasks.
#[test]
fn runtime_is_object_safe_and_shareable() {
    fn assert_send_sync<T: Send + Sync + ?Sized>() {}
    assert_send_sync::<dyn Runtime>();
    let none: Option<Arc<dyn Runtime>> = None;
    assert!(none.is_none());
}
