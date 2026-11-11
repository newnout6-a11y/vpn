//! Outcome tests (lifecycle-app §7.9) and the test renderer the history tests share.
use super::*;

/// Renders a message against the crate's own fragments (`crate::test_locales`), like
/// `vpnte_base::i18n` would: plural form by `count`, then `{{var}}` interpolation.
pub(crate) fn text(msg: &Msg, lang: Lang) -> String {
    if let Some(text) = verbatim_text(msg) {
        return text.to_owned();
    }
    let leaf = |key: &str| crate::test_locales::template(lang, key);
    let count = msg.args.iter().find(|(k, _)| k == "count");
    let template = count
        .and_then(|(_, n)| {
            let n: f64 = n.parse().ok()?;
            let category = vpnte_base::i18n::plural_category(lang, n);
            leaf(&format!("{}_{category}", msg.key))
        })
        .or_else(|| leaf(&msg.key))
        .unwrap_or_else(|| panic!("missing key {}", msg.key));
    msg.args.iter().fold(template.to_owned(), |out, (k, v)| {
        out.replace(&format!("{{{{{k}}}}}"), v)
    })
}

fn ru(kind: OutcomeKind, evidence: Evidence) -> String {
    text(&headline(kind, &evidence), Lang::Ru)
}

/// AT-00-005: every kind maps to one of the five legacy buckets.
#[test]
fn buckets() {
    use DisconnectReason as R;
    for kind in [
        OutcomeKind::UserStop,
        OutcomeKind::AppQuit,
        OutcomeKind::ServerSwitch,
    ] {
        assert_eq!(kind.bucket(), R::User, "{kind:?}");
    }
    assert_eq!(OutcomeKind::Rotation.bucket(), R::Rotation);
    assert_eq!(OutcomeKind::Schedule.bucket(), R::Schedule);
    assert_eq!(OutcomeKind::Killswitch.bucket(), R::Crash);
    let errors = OutcomeKind::ALL
        .iter()
        .filter(|k| k.bucket() == R::Error)
        .count();
    assert_eq!(errors, 9);
}

/// AT-00-005: confidence per kind (all 15).
#[test]
fn confidence_per_kind() {
    for kind in OutcomeKind::ALL {
        let expected = match kind {
            OutcomeKind::Unknown => Confidence::Indeterminate,
            OutcomeKind::UserStop
            | OutcomeKind::AppQuit
            | OutcomeKind::ServerSwitch
            | OutcomeKind::Rotation
            | OutcomeKind::Schedule
            | OutcomeKind::StartFailed => Confidence::Observed,
            _ => Confidence::Inferred,
        };
        assert_eq!(kind.confidence(), expected, "{kind:?}");
    }
}

#[test]
fn wire_names_match_serde() {
    for kind in OutcomeKind::ALL {
        let json = serde_json::to_value(kind).unwrap();
        assert_eq!(json, kind.as_str());
        assert_eq!(serde_json::from_value::<OutcomeKind>(json).unwrap(), kind);
    }
    assert!(serde_json::from_str::<OutcomeKind>("\"future-outcome\"").is_err());
}

/// AT-00-005 (sessionOutcome.test.ts): exit code and retry count folded in, deterministic.
#[test]
fn crash_headline_folds_code_and_restarts() {
    let ev = Evidence {
        singbox_exit_code: Some(1),
        auto_restart_attempts: Some(3),
        ..Evidence::default()
    };
    let a = ru(OutcomeKind::SingboxCrash, ev.clone());
    assert_eq!(a, ru(OutcomeKind::SingboxCrash, ev));
    assert_eq!(
        a,
        "Ядро VPN (sing-box) неожиданно завершилось (код 1) после 3 попыток авто-перезапуска"
    );
    let plain = ru(OutcomeKind::SingboxCrash, Evidence::default());
    assert_eq!(plain, "Ядро VPN (sing-box) неожиданно завершилось");
}

/// AT-00-005: «после N …» takes the genitive (CLDR: 21 is singular, as Russian wants).
#[test]
fn restart_attempts_pluralise() {
    let crash = |n| {
        let ev = Evidence {
            auto_restart_attempts: Some(n),
            ..Evidence::default()
        };
        ru(OutcomeKind::SingboxCrash, ev)
    };
    assert!(crash(1).contains("после 1 попытки авто"));
    assert!(crash(2).contains("после 2 попыток авто"));
    assert!(crash(5).contains("после 5 попыток авто"));
    assert!(crash(21).contains("после 21 попытки авто"));
    let ks = Evidence {
        auto_restart_attempts: Some(2),
        ..Evidence::default()
    };
    assert_eq!(
        ru(OutcomeKind::Killswitch, ks),
        "Kill-switch удержал трафик после обрыва туннеля после 2 попыток авто-перезапуска."
    );
    assert_eq!(
        ru(OutcomeKind::Killswitch, Evidence::default()),
        "Kill-switch удержал трафик после обрыва туннеля."
    );
}

/// AT-00-005: the outbound fault and the network transition are named.
#[test]
fn names_fault_and_transition() {
    let fault = |f| Evidence {
        outbound_fault: Some(f),
        ..Evidence::default()
    };
    let rejected = ru(
        OutcomeKind::ServerRejectedKey,
        fault(OutboundFault::RealityKeyMismatch),
    );
    assert!(rejected.contains("ключ REALITY"), "{rejected}");
    let down = ru(
        OutcomeKind::ServerDown,
        fault(OutboundFault::UpstreamUnreachable),
    );
    assert!(down.contains("недоступен"), "{down}");
    // A pair the classifier never makes gets the plain sentence.
    assert_eq!(
        ru(
            OutcomeKind::ServerDown,
            fault(OutboundFault::TlsHandshakeFailed)
        ),
        "Узел недоступен — соединение отклонено или истёк тайм-аут"
    );
    let lost = Evidence {
        network_transition: Some(NetworkTransition::parse("адаптер отключился")),
        ..Evidence::default()
    };
    let lost = ru(OutcomeKind::NetworkLost, lost);
    assert!(lost.contains("адаптер отключился"), "{lost}");
    let other = Evidence {
        network_transition: Some(NetworkTransition::parse("Wi-Fi → Ethernet")),
        ..Evidence::default()
    };
    assert_eq!(
        ru(OutcomeKind::NetworkLost, other),
        "Сеть изменилась под туннелем: Wi-Fi → Ethernet"
    );
}

/// AT-00-005: every kind has a sentence in both languages.
#[test]
fn every_kind_has_a_sentence() {
    for kind in OutcomeKind::ALL {
        for lang in [Lang::Ru, Lang::En] {
            let line = text(&headline(kind, &Evidence::default()), lang);
            assert!(line.chars().count() > 5, "{kind:?} {lang:?}: {line}");
            assert!(!line.contains("{{"), "{kind:?} {lang:?}: {line}");
        }
    }
}

/// AT-00-005: empty evidence is stripped (`false` and `0` stay); nothing left → no evidence.
#[test]
fn strips_empty_evidence() {
    let ev = Evidence {
        egress_ip: None,
        egress_country: Some(String::new()),
        leak_detected_during_session: Some(false),
        ..Evidence::default()
    };
    let o = SessionOutcome::new(OutcomeKind::UserStop, ev);
    assert_eq!(text(&o.headline, Lang::Ru), "Вы отключили защиту");
    let json = serde_json::to_value(&o).unwrap();
    assert_eq!(
        json["evidence"],
        serde_json::json!({ "leakDetectedDuringSession": false })
    );
    let quit = SessionOutcome::new(OutcomeKind::AppQuit, Evidence::default());
    assert!(
        serde_json::to_value(&quit)
            .unwrap()
            .get("evidence")
            .is_none()
    );
}

/// AT-00-005: a headline override is used verbatim (trimmed); a blank one is ignored.
#[test]
fn headline_override() {
    let o = SessionOutcome::with_headline(
        OutcomeKind::Unknown,
        Evidence::default(),
        verbatim("  Прокси 127.0.0.1:1080 не отвечает "),
    );
    assert_eq!(
        text(&o.headline, Lang::En),
        "Прокси 127.0.0.1:1080 не отвечает"
    );
    let blank =
        SessionOutcome::with_headline(OutcomeKind::Unknown, Evidence::default(), verbatim(" "));
    assert_eq!(
        text(&blank.headline, Lang::Ru),
        "Туннель завершился по неизвестной причине"
    );
}

/// AT-00-005: protected-restart reasons that move the session to another node.
#[test]
fn node_switch_reasons() {
    assert_eq!(
        node_switch_kind("profile rotation to Netherlands #2"),
        Some(OutcomeKind::Rotation)
    );
    assert_eq!(
        node_switch_kind("Profile Rotation To x"),
        Some(OutcomeKind::Rotation)
    );
    assert_eq!(
        node_switch_kind("server switch"),
        Some(OutcomeKind::ServerSwitch)
    );
    assert_eq!(
        node_switch_kind("adaptive transition to mtu-compatibility: probe failed"),
        None
    );
    assert_eq!(node_switch_kind("config change: split tunnel"), None);
    assert_eq!(node_switch_kind("server switch now"), None);
}

fn secs(s: u64) -> Option<Duration> {
    Some(Duration::from_secs(s))
}

fn crash_exit() -> Option<EngineExit> {
    Some(EngineExit {
        since: Duration::from_secs(2),
        code: Some(1),
        ..EngineExit::default()
    })
}

/// Classification vectors of lifecycle §7.9 (derived from `index.ts:318-332`).
#[test]
fn classification_vectors() {
    use OutboundFault as F;
    let cases = [
        (
            EndSignals {
                since_resume: secs(10),
                outbound_fault: Some(F::RealityKeyMismatch),
                since_network_change: secs(5),
                kill_switch_active: true,
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::SystemSleep,
        ),
        (
            EndSignals {
                outbound_fault: Some(F::TlsHandshakeFailed),
                since_network_change: secs(5),
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::ServerRejectedKey,
        ),
        (
            EndSignals {
                outbound_fault: Some(F::UpstreamUnreachable),
                ..EndSignals::default()
            },
            OutcomeKind::ServerDown,
        ),
        (
            EndSignals {
                since_network_change: secs(14),
                kill_switch_active: true,
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::NetworkLost,
        ),
        (
            EndSignals {
                since_network_change: secs(16),
                kill_switch_active: true,
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::Killswitch,
        ),
        (
            EndSignals {
                proxy_unreachable: true,
                warning: Some(verbatim("Прокси 127.0.0.1:1080 не отвечает")),
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::ProxyUnreachable,
        ),
        (
            EndSignals {
                engine_exit: crash_exit(),
                ..EndSignals::default()
            },
            OutcomeKind::SingboxCrash,
        ),
    ];
    for (i, (signals, kind)) in cases.iter().enumerate() {
        assert_eq!(classify_end(signals), *kind, "case {i}");
    }
    // Not a crash: our own stop, or an exit older than 30 s; a resume 25 s ago no longer counts.
    let mut own = EndSignals {
        engine_exit: crash_exit(),
        since_resume: secs(25),
        ..EndSignals::default()
    };
    if let Some(exit) = own.engine_exit.as_mut() {
        exit.user_initiated = true;
    }
    assert_eq!(classify_end(&own), OutcomeKind::Unknown);
    let old = EndSignals {
        engine_exit: Some(EngineExit {
            since: Duration::from_secs(30),
            ..EngineExit::default()
        }),
        ..EndSignals::default()
    };
    assert_eq!(classify_end(&old), OutcomeKind::Unknown);
}

/// Last §7.9 vector: an unclassified end keeps the runtime's warning as its headline.
#[test]
fn unknown_end_uses_the_warning() {
    let signals = EndSignals {
        warning: Some(verbatim("что-то")),
        ..EndSignals::default()
    };
    let o = unexpected_end(&signals, Evidence::default());
    assert_eq!(o.kind, OutcomeKind::Unknown);
    assert_eq!(text(&o.headline, Lang::Ru), "что-то");
    // A classified end ignores the warning.
    let crash = EndSignals {
        warning: Some(verbatim("что-то")),
        engine_exit: crash_exit(),
        restart_attempts: 3,
        ..EndSignals::default()
    };
    let o = unexpected_end(&crash, Evidence::default());
    assert_eq!(
        text(&o.headline, Lang::Ru),
        "Ядро VPN (sing-box) неожиданно завершилось (код 1) после 3 попыток авто-перезапуска"
    );
}

/// Evidence assembly of `recordUnexpectedSessionEnd` (index.ts:340-351).
#[test]
fn unexpected_end_evidence() {
    let signals = EndSignals {
        kill_switch_active: false,
        engine_exit: Some(EngineExit {
            since: Duration::from_secs(90),
            user_initiated: false,
            code: Some(-1),
            stderr_tail: Some("FATAL[0000] start service: tun".into()),
        }),
        ..EndSignals::default()
    };
    let session = Evidence {
        egress_ip: Some("198.51.100.7".into()),
        egress_country: Some("NL".into()),
        proxy_engine: Some(Engine::SingBox),
        adaptive_mode: Some(AdaptiveMode::TlsCompatibility.into()),
        adaptive_attempts: Some(0),
        leak_detected_during_session: Some(false),
        network_transition: Some(NetworkTransition::AdapterAdded),
        ..Evidence::default()
    };
    let o = unexpected_end(&signals, session);
    assert_eq!(o.kind, OutcomeKind::Unknown);
    let json = serde_json::to_value(&o.evidence).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "singboxExitCode": -1,
            "singboxStderrTail": "FATAL[0000] start service: tun",
            "adaptiveMode": "tls-compatibility",
            "killSwitchEngaged": false,
            "networkTransition": "adapter-added",
            "egressCountry": "NL",
            "egressIp": "198.51.100.7",
            "proxyEngine": "sing-box"
        })
    );
}

/// L-14: Wintun / route / DNS failures are `tun-setup-failed`; hints are kept and shown.
#[test]
fn start_failures() {
    let tun = SessionOutcome::start_failure(true, Some(Msg::new("x.y")), Evidence::default());
    assert_eq!(tun.kind, OutcomeKind::TunSetupFailed);
    assert_eq!(
        text(&tun.headline, Lang::Ru),
        "Не удалось поднять сетевой туннель (Wintun, маршруты или DNS)"
    );
    assert_eq!(tun.evidence.hint, Some(Msg::new("x.y")));
    let keyed = SessionOutcome::start_failure(false, Some(Msg::new("x.y")), Evidence::default());
    assert_eq!(keyed.kind, OutcomeKind::StartFailed);
    assert_eq!(keyed.headline, Msg::new("x.y"));
    let quoted =
        SessionOutcome::start_failure(false, Some(verbatim("порт занят")), Evidence::default());
    assert_eq!(
        text(&quoted.headline, Lang::Ru),
        "Не удалось запустить: порт занят"
    );
    let bare = SessionOutcome::start_failure(false, Some(verbatim("")), Evidence::default());
    assert_eq!(text(&bare.headline, Lang::En), "Could not start protection");
    assert!(bare.evidence.is_empty());
}
