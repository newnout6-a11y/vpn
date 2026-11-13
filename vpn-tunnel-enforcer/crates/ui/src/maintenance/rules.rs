//! Pure rules of the Maintenance page (ui-pages §3.12, §3.16; firewall-recovery §6.5): summaries,
//! step statuses, the protection-test conclusion, the capture badge. Every sentence is a [`Msg`],
//! so a language switch re-renders it.
use vpnte_base::types::{KillSwitchLevel, Verdict};
use vpnte_base::{ErrorKind, Msg};

use super::model::{
    CaptureView, Counted, DiagItem, EtwView, KillSwitchState, LeakVerdict, ProtectionTest,
    ProtectionView, RepairStep, RouteVerdict, StepOutcome, StepState, SystemReport,
};
use crate::helper::{Ability, Capability};
use crate::widgets::{Tone, UiError};

/// Important items shown in the results panel at most.
pub const IMPORTANT_LIMIT: usize = 8;

/// The result of an action as the page shows it: a verdict and the sentences that explain it
/// (joined with a space, the old `lastResult` string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub parts: Vec<Msg>,
}

impl Outcome {
    /// One sentence.
    pub fn new(verdict: Verdict, msg: Msg) -> Self {
        Self {
            verdict,
            parts: vec![msg],
        }
    }
    /// An action error: its own message (or the canonical one of its kind).
    pub fn error(err: &UiError) -> Self {
        Self::new(Verdict::Fail, err.msg.clone())
    }
}

fn rank(v: Verdict) -> u8 {
    match v {
        Verdict::Ok => 0,
        Verdict::NotChecked => 1,
        Verdict::Warn => 2,
        Verdict::Fail => 3,
    }
}

/// The worse of two verdicts; "not checked" is worse than "ok", so nothing unverified reads as
/// fine.
pub fn combine(a: Verdict, b: Verdict) -> Verdict {
    if rank(a) >= rank(b) { a } else { b }
}

/// The page's system summary: only App, TUN, Proxy, Network, Internet and Routing count; any
/// failure → Fail, any warning → Warn, any judged Ok → Ok, otherwise not checked.
pub fn system_summary(report: Option<&SystemReport>) -> Verdict {
    let Some(report) = report else {
        return Verdict::NotChecked;
    };
    let judged: Vec<Verdict> = report
        .items
        .iter()
        .filter(|i| i.category.is_critical())
        .filter_map(|i| i.verdict)
        .collect();
    [Verdict::Fail, Verdict::Warn, Verdict::Ok]
        .into_iter()
        .find(|v| judged.contains(v))
        .unwrap_or(Verdict::NotChecked)
}

/// Failures in the critical categories and route warnings, at most [`IMPORTANT_LIMIT`].
pub fn important_items(report: &SystemReport) -> Vec<&DiagItem> {
    report
        .items
        .iter()
        .filter(|i| match i.verdict {
            Some(Verdict::Fail) => i.category.is_critical(),
            Some(Verdict::Warn) => i.category.is_route(),
            _ => false,
        })
        .take(IMPORTANT_LIMIT)
        .collect()
}

/// One line of the protection block: what it says and how it is judged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionLine {
    pub verdict: Verdict,
    pub text: Msg,
}

fn level_key(level: KillSwitchLevel) -> &'static str {
    match level {
        KillSwitchLevel::Off => "ui.maintenance.protection.level.off",
        KillSwitchLevel::Standard => "ui.maintenance.protection.level.standard",
        KillSwitchLevel::Strict => "ui.maintenance.protection.level.strict",
    }
}

/// The protection block, line by line (firewall-recovery §6.5 status), with a verdict each.
pub fn protection_lines(p: &ProtectionView) -> Vec<ProtectionLine> {
    let line = |verdict, key: &'static str| ProtectionLine {
        verdict,
        text: Msg::new(key),
    };
    let mut lines = vec![line(Verdict::Ok, level_key(p.level))];
    lines.push(match &p.kill_switch {
        KillSwitchState::Off => line(Verdict::Ok, "ui.maintenance.protection.state.off"),
        KillSwitchState::Armed => line(Verdict::Ok, "ui.maintenance.protection.state.armed"),
        KillSwitchState::Engaged => line(Verdict::Ok, "ui.maintenance.protection.state.engaged"),
        // Strict blocks outside the VPN by design; standard blocks only after a drop.
        KillSwitchState::Blocking if p.level == KillSwitchLevel::Strict => line(
            Verdict::Ok,
            "ui.maintenance.protection.state.blockingStrict",
        ),
        KillSwitchState::Blocking => {
            line(Verdict::Warn, "ui.maintenance.protection.state.blocking")
        }
        KillSwitchState::Failed(why) => ProtectionLine {
            verdict: Verdict::Fail,
            text: why.clone(),
        },
        // Nothing of ours was read back: not checked, never a failure.
        KillSwitchState::ProxyOnly => line(
            Verdict::NotChecked,
            "ui.maintenance.protection.state.proxyOnly",
        ),
    });
    lines.push(if p.bfe_running {
        line(Verdict::Ok, "ui.maintenance.protection.bfeRunning")
    } else {
        line(Verdict::Fail, "ui.maintenance.protection.bfeStopped")
    });
    // Counts that were not read back (unelevated: BFE lets only administrators enumerate
    // filters) are not shown: «0 / 0» would read as a verified clean state.
    if p.last_verified.is_some() {
        lines.push(match (p.level, p.persistent_filters) {
            (KillSwitchLevel::Strict, 0) => {
                line(Verdict::Fail, "ui.maintenance.protection.strictMissing")
            }
            (KillSwitchLevel::Strict, _) | (_, 0) => ProtectionLine {
                verdict: Verdict::Ok,
                text: Msg::new("ui.maintenance.protection.filters")
                    .arg("dynamic", p.dynamic_filters)
                    .arg("persistent", p.persistent_filters),
            },
            (_, n) => ProtectionLine {
                verdict: Verdict::Warn,
                text: Msg::new("ui.maintenance.protection.leftoverFilters").arg("n", n),
            },
        });
    }
    for block in &p.firewall_blocks {
        let (verdict, family) = if block.active {
            (Verdict::Warn, "ui.maintenance.protection.fwBlockActive")
        } else {
            (Verdict::Ok, "ui.maintenance.protection.fwBlock")
        };
        lines.push(ProtectionLine {
            verdict,
            text: Msg::new(format!("{family}.{}", block.profile.id())),
        });
    }
    lines
}

/// The protection verdict: the worst line.
pub fn protection_verdict(p: &ProtectionView) -> Verdict {
    protection_lines(p)
        .iter()
        .fold(Verdict::Ok, |acc, l| combine(acc, l.verdict))
}

/// The state badge: not checked until a health check produced a report; then the worse of the
/// protection and the system summary.
pub fn health_summary(
    protection: Option<&ProtectionView>,
    report: Option<&SystemReport>,
) -> Verdict {
    if report.is_none() {
        return Verdict::NotChecked;
    }
    let protection = protection.map_or(Verdict::NotChecked, protection_verdict);
    combine(protection, system_summary(report))
}

/// The health check's result line: «no critical problems» only when both halves are Ok.
pub fn health_outcome(protection: Option<&ProtectionView>, report: &SystemReport) -> Outcome {
    let verdict = health_summary(protection, Some(report));
    let key = if verdict == Verdict::Ok {
        "ui.maintenance.health.ok"
    } else {
        "ui.maintenance.health.attention"
    };
    Outcome::new(verdict, Msg::new(key))
}

/// Log level of a result: Fail → error, Warn → warn, otherwise info (AT-00-005).
pub fn journal_level(verdict: Verdict) -> tracing::Level {
    match verdict {
        Verdict::Fail => tracing::Level::ERROR,
        Verdict::Warn => tracing::Level::WARN,
        Verdict::Ok | Verdict::NotChecked => tracing::Level::INFO,
    }
}

/// What keeps a repair step from running here, said before any run (p-noadmin-ui): our filters
/// come with the helper service; the old version's leftovers need an elevated app, which this
/// version never is by itself. `None` without a helper backend in context.
pub fn step_up_front(step: RepairStep, cap: Option<&Capability>) -> Option<&'static str> {
    let cap = cap?;
    match step {
        RepairStep::Filters if cap.kill_switch == Ability::NeedsService => {
            Some("ui.helper.viaService")
        }
        RepairStep::Legacy if !cap.elevated => Some("ui.helper.notInVersion"),
        _ => None,
    }
}

/// Status of a finished step: refused → Warn, failed → Fail, remarks → Warn, else Ok.
pub fn step_status(o: &StepOutcome) -> Verdict {
    if o.blocked {
        Verdict::Warn
    } else if !o.success {
        Verdict::Fail
    } else if o.warning {
        Verdict::Warn
    } else {
        Verdict::Ok
    }
}

/// Detail line of a finished step: its own sentence, else what changed, else «Готово».
pub fn step_detail(o: &StepOutcome) -> Msg {
    if let Some(msg) = &o.message {
        return msg.clone();
    }
    match o.changes.as_deref() {
        Some([]) => Msg::new("ui.maintenance.steps.noChanges"),
        Some(items) => Msg::new("ui.maintenance.steps.changed").arg("items", items.join(", ")),
        None => Msg::new("ui.maintenance.steps.done"),
    }
}

/// Verdict of a step row; a step without an outcome after a run is not confirmed.
fn row_status(state: &StepState) -> Verdict {
    match state {
        StepState::Done(o) => step_status(o),
        StepState::Idle | StepState::Pending | StepState::Running => Verdict::NotChecked,
    }
}

/// The repair's result line: errors, warnings (an unconfirmed step counts as one) or done.
pub fn repair_outcome(steps: &[(RepairStep, StepState)]) -> Outcome {
    let statuses: Vec<Verdict> = steps.iter().map(|(_, s)| row_status(s)).collect();
    let (verdict, key) = if statuses.contains(&Verdict::Fail) {
        (Verdict::Fail, "ui.maintenance.repair.failed")
    } else if statuses.iter().any(|v| *v != Verdict::Ok) {
        (Verdict::Warn, "ui.maintenance.repair.warned")
    } else {
        (Verdict::Ok, "ui.maintenance.repair.done")
    };
    Outcome::new(verdict, Msg::new(key))
}

/// The protection test's conclusion (§3.12): a leak in either half fails it; anything not Ok is
/// inconclusive; the evidence of both halves follows the verdict sentence.
pub fn protection_outcome(t: &ProtectionTest) -> Outcome {
    let failed = t.leak.verdict == LeakVerdict::Leak || t.route.verdict == RouteVerdict::Leak;
    let inconclusive =
        !failed && (t.route.verdict != RouteVerdict::Ok || t.leak.verdict != LeakVerdict::Ok);
    let (verdict, key) = if failed {
        (Verdict::Fail, "ui.maintenance.protectionTest.failed")
    } else if inconclusive {
        (Verdict::Warn, "ui.maintenance.protectionTest.inconclusive")
    } else {
        (Verdict::Ok, "ui.maintenance.protectionTest.passed")
    };
    let mut parts = vec![Msg::new(key), t.leak.headline.clone()];
    parts.extend(t.leak.disagreement.clone());
    parts.push(t.route.message.clone());
    Outcome { verdict, parts }
}

/// The export's failure line; a permission error adds where to save instead.
pub fn export_failure(err: &UiError) -> Outcome {
    let mut parts = vec![Msg::new("ui.maintenance.export.failed"), err.msg.clone()];
    if err.kind == ErrorKind::Permission {
        parts.push(Msg::new("ui.maintenance.export.permissionHint"));
    }
    Outcome {
        verdict: Verdict::Fail,
        parts,
    }
}

/// The capture badge (§3.16 priority) and the alert / tooltip under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureBadge {
    pub label: Msg,
    pub tone: Tone,
    /// Shown as `role=alert` (stop not confirmed).
    pub alert: Option<Msg>,
    /// Tooltip of the badge.
    pub title: Msg,
}

/// Badge priority: stop not confirmed (also when the status is unreadable) → capturing →
/// start failed → stopped; the raw backend text of a legacy leftover is never shown.
pub fn capture_badge(c: &CaptureView) -> CaptureBadge {
    if c.cleanup_pending || c.status_unavailable || c.legacy_cleanup_required {
        let alert = if c.status_unavailable {
            Msg::new("diagnosticsCapture.statusUnavailable")
        } else if c.legacy_cleanup_required {
            Msg::new("diagnosticsCapture.legacyCleanupRequired")
        } else {
            c.last_error
                .clone()
                .unwrap_or_else(|| Msg::new("diagnosticsCapture.stopUnconfirmed"))
        };
        return CaptureBadge {
            label: Msg::new("diagnosticsCapture.pendingLabel"),
            tone: Tone::Fail,
            title: alert.clone(),
            alert: Some(alert),
        };
    }
    let (label, tone, title) = if c.running {
        (
            "diagnosticsCapture.runningLabel",
            Tone::Ok,
            Msg::new("diagnosticsCapture.running"),
        )
    } else if c.start_failed {
        let why = c
            .last_error
            .clone()
            .unwrap_or_else(|| Msg::new("diagnosticsCapture.startFailed"));
        ("diagnosticsCapture.failedLabel", Tone::Warn, why)
    } else {
        (
            "diagnosticsCapture.stoppedLabel",
            Tone::Neutral,
            Msg::new("diagnosticsCapture.stopped"),
        )
    };
    CaptureBadge {
        label: Msg::new(label),
        tone,
        alert: None,
        title,
    }
}

/// ETW categories in the old card's order (tcp, dns, wfp, afd, webio, udp), then the rest by
/// count, largest first.
pub fn ordered_categories(categories: &[Counted]) -> Vec<Counted> {
    const FIRST: [&str; 6] = ["tcp", "dns", "wfp", "afd", "webio", "udp"];
    let mut known: Vec<Counted> = FIRST
        .iter()
        .filter_map(|name| categories.iter().find(|c| c.name == *name).cloned())
        .collect();
    let mut rest: Vec<Counted> = categories
        .iter()
        .filter(|c| !FIRST.contains(&c.name.as_str()))
        .cloned()
        .collect();
    rest.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    known.append(&mut rest);
    known
}

/// Engine label of the ETW consumer.
pub fn etw_engine_label(engine: Option<&str>) -> Msg {
    match engine {
        Some("etw-inproc" | "ferrisetw-realtime") | None => {
            Msg::new("ui.maintenance.capture.etwRealtime")
        }
        Some("powershell-poller") => Msg::new("ui.maintenance.capture.etwPoller"),
        Some(other) => Msg::new("ui.maintenance.capture.engineRaw").arg("name", other),
    }
}

/// «прогрев | работает | выключен · N data».
pub fn etw_state(e: &EtwView) -> Msg {
    let key = if !e.running {
        "ui.maintenance.capture.etwOff"
    } else if e.warming_up {
        "ui.maintenance.capture.etwWarming"
    } else {
        "ui.maintenance.capture.etwRunning"
    };
    Msg::new(key).arg("count", e.data_events)
}

/// Whether the ETW detail block is worth showing (running or has data).
pub fn show_etw_detail(e: &EtwView) -> bool {
    e.running || e.data_events > 0
}

/// The capture panel's line after «Перезапустить сбор»: restarted, or why it did not start.
pub fn capture_restart_outcome(c: &CaptureView) -> Outcome {
    if c.running {
        return Outcome::new(Verdict::Ok, Msg::new("ui.maintenance.capture.restarted"));
    }
    let why = c
        .last_error
        .clone()
        .unwrap_or_else(|| Msg::new("ui.maintenance.capture.noSession"));
    Outcome {
        verdict: Verdict::Warn,
        parts: vec![Msg::new("ui.maintenance.capture.notRestarted"), why],
    }
}
