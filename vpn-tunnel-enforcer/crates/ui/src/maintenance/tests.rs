//! Ported vectors of ui-pages §7.6 / §7.8 / §7.9 / §7.10 (the pure rules), new-design vectors of
//! the protection read-back (firewall-recovery §6.5) and the locale gate.
use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, Verdict};
use vpnte_base::{ErrorKind, Msg};

use super::model::*;
use super::rules::*;
use crate::widgets::{Tone, UiError};

fn item(id: &str, category: DiagCategory, verdict: Option<Verdict>) -> DiagItem {
    DiagItem {
        id: id.into(),
        category,
        label: Msg::new("ui.maintenance.demo.label.adapters"),
        verdict,
        value: Msg::new("ui.maintenance.demo.raw").arg("text", "v"),
        details: Vec::new(),
        notes: Vec::new(),
    }
}

fn report(items: Vec<DiagItem>) -> SystemReport {
    SystemReport { ran_at: 1, items }
}

fn healthy() -> ProtectionView {
    ProtectionView {
        level: KillSwitchLevel::Standard,
        kill_switch: KillSwitchState::Engaged,
        leak_protection_active: true,
        dynamic_filters: 12,
        persistent_filters: 0,
        bfe_running: true,
        firewall_blocks: Vec::new(),
        last_verified: Some(1),
    }
}

fn keys(outcome: &Outcome) -> Vec<String> {
    outcome.parts.iter().map(|m| m.key.to_string()).collect()
}

/// AT-00-005: a Network warning with the protection fine → «есть пункты для внимания», logged
/// at warn; a failure → error; both fine → «no critical problems» at info.
#[test]
fn health_summary_levels() {
    let warn = report(vec![item("ip", DiagCategory::Network, Some(Verdict::Warn))]);
    let o = health_outcome(Some(&healthy()), &warn);
    assert_eq!(o.verdict, Verdict::Warn);
    assert_eq!(keys(&o), ["ui.maintenance.health.attention"]);
    assert_eq!(journal_level(o.verdict), tracing::Level::WARN);

    let fail = report(vec![item("ip", DiagCategory::Network, Some(Verdict::Fail))]);
    let o = health_outcome(Some(&healthy()), &fail);
    assert_eq!(
        (o.verdict, journal_level(o.verdict)),
        (Verdict::Fail, tracing::Level::ERROR)
    );

    let ok = report(vec![item(
        "adapters",
        DiagCategory::Network,
        Some(Verdict::Ok),
    )]);
    let o = health_outcome(Some(&healthy()), &ok);
    assert_eq!(keys(&o), ["ui.maintenance.health.ok"]);
    assert_eq!(journal_level(o.verdict), tracing::Level::INFO);
}

/// §7.6 `systemSummary`: none → not checked; only App ok → ok; a Proxy warn → warn; only
/// non-critical categories count for nothing.
#[test]
fn system_summary_counts_critical_categories_only() {
    assert_eq!(system_summary(None), Verdict::NotChecked);
    let app_ok = report(vec![item("app", DiagCategory::App, Some(Verdict::Ok))]);
    assert_eq!(system_summary(Some(&app_ok)), Verdict::Ok);
    let proxy_warn = report(vec![
        item("app", DiagCategory::App, Some(Verdict::Ok)),
        item("proxy", DiagCategory::Proxy, Some(Verdict::Warn)),
    ]);
    assert_eq!(system_summary(Some(&proxy_warn)), Verdict::Warn);
    let windows_only = report(vec![
        item("svc", DiagCategory::Windows, Some(Verdict::Fail)),
        item("info", DiagCategory::Tun, None),
    ]);
    assert_eq!(system_summary(Some(&windows_only)), Verdict::NotChecked);
}

/// §7.6 `importantItems([{App,fail},{App,warn},{Proxy,warn},{Security,fail}])` → `[App fail,
/// Proxy warn]` (Rust has no Security group; Windows is the non-critical stand-in); at most 8.
#[test]
fn important_items_filter_and_limit() {
    let r = report(vec![
        item("a", DiagCategory::App, Some(Verdict::Fail)),
        item("b", DiagCategory::App, Some(Verdict::Warn)),
        item("c", DiagCategory::Proxy, Some(Verdict::Warn)),
        item("d", DiagCategory::Windows, Some(Verdict::Fail)),
    ]);
    let ids: Vec<&str> = important_items(&r).iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, ["a", "c"]);
    let many = report(
        (0..12)
            .map(|i| item(&format!("n{i}"), DiagCategory::Network, Some(Verdict::Fail)))
            .collect(),
    );
    assert_eq!(important_items(&many).len(), IMPORTANT_LIMIT);
}

/// §7.6 `stepStatus`: blocked → warn; success false → fail; warning → warn; otherwise ok.
#[test]
fn step_status_vectors() {
    let m = Msg::new("x");
    assert_eq!(step_status(&StepOutcome::blocked(m.clone())), Verdict::Warn);
    assert_eq!(step_status(&StepOutcome::failed(m)), Verdict::Fail);
    let warned = StepOutcome {
        warning: true,
        ..StepOutcome::done(Vec::new())
    };
    assert_eq!(step_status(&warned), Verdict::Warn);
    assert_eq!(step_status(&StepOutcome::done(Vec::new())), Verdict::Ok);
}

/// §7.6 `resultDetail` (Rust shape): own message wins; no changes → «Изменений не
/// потребовалось»; changes → «Изменено: …»; nothing reported → «Готово».
#[test]
fn step_detail_vectors() {
    let own = StepOutcome {
        message: Some(Msg::new("m")),
        ..StepOutcome::done(vec!["x".into()])
    };
    assert_eq!(step_detail(&own), Msg::new("m"));
    assert_eq!(
        step_detail(&StepOutcome::done(Vec::new())).key,
        "ui.maintenance.steps.noChanges"
    );
    let changed = step_detail(&StepOutcome::done(vec!["Ethernet".into()]));
    assert_eq!(
        changed,
        Msg::new("ui.maintenance.steps.changed").arg("items", "Ethernet")
    );
    let silent = StepOutcome {
        changes: None,
        ..StepOutcome::done(Vec::new())
    };
    assert_eq!(step_detail(&silent).key, "ui.maintenance.steps.done");
}

fn steps(outcomes: [StepState; 3]) -> Vec<(RepairStep, StepState)> {
    RepairStep::ALL.into_iter().zip(outcomes).collect()
}

fn ok() -> StepState {
    StepState::Done(StepOutcome::done(Vec::new()))
}

/// AT-00-004/008 auto-repair honesty: a refusal is a warning (no error); a partial runtime
/// cleanup and a partial rollback are failures that keep their evidence; all fine → done; a step
/// without an outcome never reads as done.
#[test]
fn repair_outcome_is_honest() {
    let refused = StepState::Done(StepOutcome::blocked(Msg::new("conflict")));
    let o = repair_outcome(&steps([ok(), refused, ok()]));
    assert_eq!(
        (o.verdict, keys(&o)),
        (
            Verdict::Warn,
            vec!["ui.maintenance.repair.warned".to_owned()]
        )
    );

    let partial = StepOutcome::failed(
        Msg::new("ui.maintenance.demo.steps.enginesPartial")
            .arg("killed", 1)
            .arg("total", 2),
    );
    let o = repair_outcome(&steps([ok(), ok(), StepState::Done(partial.clone())]));
    assert_eq!(keys(&o), ["ui.maintenance.repair.failed"]);
    assert_eq!(step_status(&partial), Verdict::Fail);
    assert!(
        step_detail(&partial)
            .args
            .iter()
            .any(|(k, v)| k == "killed" && v == "1")
    );

    let rollback = StepState::Done(StepOutcome::failed(Msg::new("errors.permission")));
    assert_eq!(
        repair_outcome(&steps([ok(), rollback, ok()])).verdict,
        Verdict::Fail
    );

    let o = repair_outcome(&steps([ok(), ok(), ok()]));
    assert_eq!(
        (o.verdict, keys(&o)),
        (Verdict::Ok, vec!["ui.maintenance.repair.done".to_owned()])
    );

    assert_eq!(
        repair_outcome(&steps([ok(), StepState::Idle, ok()])).verdict,
        Verdict::Warn
    );
}

fn leak(verdict: LeakVerdict, headline: Msg) -> LeakTestView {
    LeakTestView {
        at: 1,
        verdict,
        cancelled: false,
        headline,
        tun_ip: Some("1.2.3.4".into()),
        adapters: Vec::new(),
        disagreement: None,
    }
}

fn test_of(leak_verdict: LeakVerdict, route_verdict: RouteVerdict) -> ProtectionTest {
    ProtectionTest {
        leak: leak(leak_verdict, Msg::new("leak.headline")),
        route: RouteTestView {
            verdict: route_verdict,
            message: Msg::new("route.message"),
        },
    }
}

/// AT-00-008 evidence (§7.6): only Ok + Ok passes; an inconclusive or possible leak is a warning
/// and never says «пройдена»; a leak in either half fails; both halves' sentences follow.
#[test]
fn protection_outcome_vectors() {
    use LeakVerdict as L;
    use RouteVerdict as R;
    let passed = protection_outcome(&test_of(L::Ok, R::Ok));
    assert_eq!(passed.verdict, Verdict::Ok);
    assert_eq!(
        keys(&passed),
        [
            "ui.maintenance.protectionTest.passed",
            "leak.headline",
            "route.message"
        ]
    );
    let warnings = [
        (L::Inconclusive, R::Ok),
        (L::PossibleLeak, R::Ok),
        (L::Ok, R::Partial),
        (L::Ok, R::Inconclusive),
    ];
    for (l, r) in warnings {
        let o = protection_outcome(&test_of(l, r));
        assert_eq!(o.verdict, Verdict::Warn, "{l:?} / {r:?}");
        assert_eq!(o.parts[0].key, "ui.maintenance.protectionTest.inconclusive");
        assert!(!keys(&o).iter().any(|k| k.ends_with(".passed")));
    }
    for (l, r) in [
        (L::Leak, R::Ok),
        (L::Ok, R::Leak),
        (L::Inconclusive, R::Leak),
    ] {
        let o = protection_outcome(&test_of(l, r));
        assert_eq!(o.verdict, Verdict::Fail);
        assert_eq!(o.parts[0].key, "ui.maintenance.protectionTest.failed");
    }
}

/// §7.6 "evidence retained": the leaked address, the services' disagreement and «Тест отменён»
/// reach the result line (and with it the toast and the log).
#[test]
fn protection_outcome_keeps_the_evidence() {
    let has_arg = |o: &Outcome, value: &str| {
        o.parts
            .iter()
            .any(|m| m.args.iter().any(|(_, v)| v == value))
    };
    let mut t = test_of(LeakVerdict::Leak, RouteVerdict::Ok);
    t.leak.headline = Msg::new("leak.reached").arg("ip", "5.6.7.8");
    assert!(has_arg(&protection_outcome(&t), "5.6.7.8"));

    let mut t = test_of(LeakVerdict::PossibleLeak, RouteVerdict::Ok);
    t.leak.disagreement = Some(Msg::new("leak.disagree").arg("other", "5.6.7.8"));
    assert!(has_arg(&protection_outcome(&t), "5.6.7.8"));

    let mut t = test_of(LeakVerdict::Inconclusive, RouteVerdict::Ok);
    t.leak.cancelled = true;
    t.leak.headline = Msg::new("probes.leak.selfTest.cancelled");
    let o = protection_outcome(&t);
    assert_eq!(o.verdict, Verdict::Warn);
    assert_eq!(o.parts[1].key, "probes.leak.selfTest.cancelled");
}

/// AT-08-004/005, F-198 (§7.9): an unconfirmed stop wins over everything; a legacy leftover
/// shows its own localized sentence (never the raw backend text); an unreadable status is never
/// "stopped"; otherwise the backend's reason is the alert.
#[test]
fn capture_badge_vectors() {
    let legacy = CaptureView {
        cleanup_pending: true,
        legacy_cleanup_required: true,
        ..CaptureView::default()
    };
    let b = capture_badge(&legacy);
    assert_eq!(b.label.key, "diagnosticsCapture.pendingLabel");
    assert_eq!(
        b.alert,
        Some(Msg::new("diagnosticsCapture.legacyCleanupRequired"))
    );

    let unreadable = CaptureView {
        status_unavailable: true,
        ..CaptureView::default()
    };
    let b = capture_badge(&unreadable);
    assert_eq!(b.label.key, "diagnosticsCapture.pendingLabel");
    assert_eq!(
        b.alert,
        Some(Msg::new("diagnosticsCapture.statusUnavailable"))
    );

    let why = Msg::new("forensics.capture.stopUnconfirmed").arg("detail", "pktmon exit 1");
    for running in [true, false] {
        let pending = CaptureView {
            running,
            cleanup_pending: true,
            last_error: Some(why.clone()),
            ..CaptureView::default()
        };
        let b = capture_badge(&pending);
        assert_eq!(b.label.key, "diagnosticsCapture.pendingLabel");
        assert_eq!(b.alert.as_ref(), Some(&why));
    }
    let bare = CaptureView {
        cleanup_pending: true,
        ..CaptureView::default()
    };
    let alert = capture_badge(&bare).alert;
    assert_eq!(alert, Some(Msg::new("diagnosticsCapture.stopUnconfirmed")));

    let running = capture_badge(&CaptureView {
        running: true,
        ..CaptureView::default()
    });
    assert_eq!(running.label.key, "diagnosticsCapture.runningLabel");
    assert_eq!((running.tone, running.alert), (Tone::Ok, None));
    let failed = capture_badge(&CaptureView {
        start_failed: true,
        ..CaptureView::default()
    });
    assert_eq!(failed.label.key, "diagnosticsCapture.failedLabel");
    assert_eq!(failed.title.key, "diagnosticsCapture.startFailed");
    let stopped = capture_badge(&CaptureView::default());
    assert_eq!(stopped.label.key, "diagnosticsCapture.stoppedLabel");
}

/// New design (firewall-recovery §6.5): BFE down, a failed apply or a strict level without its
/// persistent set fail; leftovers, a standard block after a drop and an active Windows Firewall
/// outbound block warn; strict blocking outside the VPN is intended.
#[test]
fn protection_read_back_vectors() {
    assert_eq!(protection_verdict(&healthy()), Verdict::Ok);
    let strict_blocking = |p: &mut ProtectionView| {
        p.level = KillSwitchLevel::Strict;
        p.persistent_filters = 9;
        p.kill_switch = KillSwitchState::Blocking;
    };
    type Change<'a> = &'a dyn Fn(&mut ProtectionView);
    let cases: [(Change, Verdict); 8] = [
        (&|p| p.bfe_running = false, Verdict::Fail),
        (
            &|p| p.kill_switch = KillSwitchState::Failed(Msg::new("x")),
            Verdict::Fail,
        ),
        (&|p| p.level = KillSwitchLevel::Strict, Verdict::Fail),
        (&|p| p.persistent_filters = 3, Verdict::Warn),
        (
            &|p| p.kill_switch = KillSwitchState::Blocking,
            Verdict::Warn,
        ),
        (&strict_blocking, Verdict::Ok),
        (
            &|p| {
                p.firewall_blocks = vec![FirewallBlock {
                    profile: FwProfile::Public,
                    active: true,
                }]
            },
            Verdict::Warn,
        ),
        (
            &|p| {
                p.firewall_blocks = vec![FirewallBlock {
                    profile: FwProfile::Domain,
                    active: false,
                }]
            },
            Verdict::Ok,
        ),
    ];
    for (i, (change, expected)) in cases.into_iter().enumerate() {
        let mut p = healthy();
        change(&mut p);
        assert_eq!(protection_verdict(&p), expected, "case {i}");
    }
    let mut p = healthy();
    p.firewall_blocks = vec![FirewallBlock {
        profile: FwProfile::Private,
        active: true,
    }];
    let lines = protection_lines(&p);
    assert!(
        lines
            .iter()
            .any(|l| l.text.key == "ui.maintenance.protection.fwBlockActive.private")
    );
}

/// Unelevated, our filters cannot be enumerated (`last_verified: None`): no «0 / 0» count line
/// that would read as a verified clean state; the state line says why.
#[test]
fn unread_filter_counts_are_not_shown() {
    let unread = ProtectionView {
        kill_switch: KillSwitchState::Failed(Msg::new("app.base.needsAdmin")),
        last_verified: None,
        ..healthy()
    };
    let lines = protection_lines(&unread);
    assert!(
        lines.iter().all(
            |l| !l.text.key.starts_with("ui.maintenance.protection.filters")
                && l.text.key != "ui.maintenance.protection.strictMissing"
        ),
        "{lines:?}"
    );
    assert!(lines.iter().any(|l| l.text.key == "app.base.needsAdmin"));
    let counted = protection_lines(&healthy());
    assert!(
        counted
            .iter()
            .any(|l| l.text.key == "ui.maintenance.protection.filters")
    );
}

/// The badge stays «not checked» until a report exists, and nothing unverified reads as Ok.
#[test]
fn health_summary_needs_a_report() {
    assert_eq!(health_summary(Some(&healthy()), None), Verdict::NotChecked);
    let ok = report(vec![item("a", DiagCategory::Network, Some(Verdict::Ok))]);
    assert_eq!(health_summary(None, Some(&ok)), Verdict::NotChecked);
    assert_eq!(health_summary(Some(&healthy()), Some(&ok)), Verdict::Ok);
    assert_eq!(
        combine(Verdict::Ok, Verdict::NotChecked),
        Verdict::NotChecked
    );
    assert_eq!(combine(Verdict::Warn, Verdict::NotChecked), Verdict::Warn);
    assert_eq!(combine(Verdict::Fail, Verdict::Warn), Verdict::Fail);
}

/// §7.10: a permission error adds where to save; other errors do not.
#[test]
fn export_failure_hint_only_for_permission() {
    let perm = UiError {
        kind: ErrorKind::Permission,
        msg: Msg::new("errors.permission"),
    };
    assert_eq!(
        keys(&export_failure(&perm)),
        [
            "ui.maintenance.export.failed",
            "errors.permission",
            "ui.maintenance.export.permissionHint"
        ]
    );
    let net = UiError {
        kind: ErrorKind::Network,
        msg: Msg::new("errors.network"),
    };
    assert_eq!(
        keys(&export_failure(&net)),
        ["ui.maintenance.export.failed", "errors.network"]
    );
}

/// DiagnosticsCard facts kept: category order, engine labels, the restart line.
#[test]
fn capture_helpers() {
    let c = |n: &str, k| Counted {
        name: n.into(),
        count: k,
    };
    let ordered = ordered_categories(&[
        c("zz", 5),
        c("udp", 1),
        c("tcp", 2),
        c("aa", 9),
        c("dns", 3),
    ]);
    let names: Vec<&str> = ordered.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["tcp", "dns", "udp", "aa", "zz"]);
    let label = |e| etw_engine_label(Some(e)).key;
    assert_eq!(label("etw-inproc"), "ui.maintenance.capture.etwRealtime");
    assert_eq!(
        label("ferrisetw-realtime"),
        "ui.maintenance.capture.etwRealtime"
    );
    assert_eq!(
        label("powershell-poller"),
        "ui.maintenance.capture.etwPoller"
    );
    let restarted = capture_restart_outcome(&CaptureView {
        running: true,
        ..CaptureView::default()
    });
    assert_eq!(keys(&restarted), ["ui.maintenance.capture.restarted"]);
    let idle = capture_restart_outcome(&CaptureView::default());
    assert_eq!(idle.verdict, Verdict::Warn);
    assert_eq!(
        keys(&idle),
        [
            "ui.maintenance.capture.notRestarted",
            "ui.maintenance.capture.noSession"
        ]
    );
}

const RU: &str = include_str!("../../locales/ui-maintenance.ru.json");

/// Every `ui.maintenance.*` key the code names exists (a family prefix must name an object).
#[test]
fn every_key_the_code_uses_exists() {
    let keys: Vec<String> = crate::test_locales::flatten(RU).into_keys().collect();
    let exists = |key: &str| {
        keys.iter()
            .any(|k| k == key || k.starts_with(&format!("{key}.")))
    };
    let sources = [
        include_str!("../maintenance.rs"),
        include_str!("ctl.rs"),
        include_str!("rules.rs"),
        include_str!("model.rs"),
        include_str!("view.rs"),
        include_str!("capture.rs"),
        include_str!("legacy.rs"),
    ];
    for source in sources {
        for chunk in source.split("\"ui.maintenance.").skip(1) {
            let key = format!("ui.maintenance.{}", chunk.split('"').next().unwrap_or(""));
            assert!(exists(&key), "missing {key}");
        }
    }
    for chunk in include_str!("demo.rs").split("demo(\"").skip(1) {
        let key = format!(
            "ui.maintenance.demo.{}",
            chunk.split('"').next().unwrap_or("")
        );
        assert!(exists(&key), "missing {key}");
    }
    for step in RepairStep::ALL {
        assert!(exists(step.label_key()));
    }
    for category in DiagCategory::ALL {
        assert!(exists(category.label_key()));
    }
    for profile in [FwProfile::Domain, FwProfile::Private, FwProfile::Public] {
        assert!(exists(&format!(
            "ui.maintenance.protection.fwBlock.{}",
            profile.id()
        )));
        assert!(exists(&format!(
            "ui.maintenance.protection.fwBlockActive.{}",
            profile.id()
        )));
    }
    for scene in ["default", "off", "problems"] {
        for item in super::demo::report(super::demo::Scene::parse(scene)).items {
            assert!(exists(&item.label.key), "missing {}", item.label.key);
            assert!(exists(&item.value.key), "missing {}", item.value.key);
        }
    }
}

/// The outcome's parts in `lang` through the catalog as the app registers it (old strings, every
/// UI fragment, the canonical errors).
fn render(lang: Lang, outcome: &Outcome) -> String {
    crate::test_locales::init_locales();
    outcome
        .parts
        .iter()
        .map(|m| m.render(lang))
        .collect::<Vec<_>>()
        .join(" ")
}

/// §7.10 "permission rejection → «Недостаточно прав для операции» and «Выберите локальную
/// личную папку»"; §7.6 "leak probe rejects (network) → «Сетевая операция не выполнена»".
#[test]
fn rendered_error_lines() {
    let perm = UiError::from(vpnte_base::AppError::new(ErrorKind::Permission));
    let text = render(Lang::Ru, &export_failure(&perm));
    assert!(
        text.starts_with("Не удалось создать архив: Недостаточно прав для операции"),
        "{text}"
    );
    assert!(text.contains("Выберите локальную личную папку"), "{text}");
    let net = UiError::from(vpnte_base::AppError::new(ErrorKind::Network));
    assert_eq!(
        render(Lang::Ru, &Outcome::error(&net)),
        "Сетевая операция не выполнена"
    );
    assert_eq!(
        render(Lang::En, &Outcome::error(&net)),
        "Network operation failed"
    );
}

/// §7.9: the legacy alert is the localized sentence in either language, never the backend text.
#[test]
fn legacy_capture_alert_is_localized() {
    let view = CaptureView {
        cleanup_pending: true,
        legacy_cleanup_required: true,
        ..CaptureView::default()
    };
    let alert = capture_badge(&view).alert.expect("alert");
    let as_outcome = Outcome::new(Verdict::Warn, alert);
    assert!(render(Lang::Ru, &as_outcome).starts_with("Остановка захвата старого клиента"));
    assert!(render(Lang::En, &as_outcome).starts_with("Stopping the old client's capture"));
}
