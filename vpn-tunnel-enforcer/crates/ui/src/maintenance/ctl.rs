//! The Maintenance page's actions and page-held results, separate from the markup so the
//! request-lifetime and honesty rules (ui-pages §7.6, §7.8, §7.10) are tested on the code the
//! page runs.
use std::rc::Rc;

use dioxus::prelude::*;
use futures_util::future::try_join;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Verdict;
use vpnte_base::{AppResult, ErrorKind, Msg};

use super::MaintenanceApi;
use super::model::{MaintenanceState, ProtectionTest, ProtectionView, SystemReport, TunnelPhase};
use super::rules::{self, Outcome};
use crate::lang::tr;
use crate::widgets::{JobSlot, ToastKind, Toasts, UiError};

/// Page state and jobs (Copy handles owned by the page root, so they die with it).
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Controller {
    api: CopyValue<Rc<dyn MaintenanceApi>>,
    pub state: Signal<MaintenanceState>,
    pub health: JobSlot<()>,
    pub repair: JobSlot<()>,
    pub protect: JobSlot<()>,
    pub export: JobSlot<()>,
    pub capture: JobSlot<()>,
    pub legacy: JobSlot<()>,
    /// The state panel's result line (health check, repair, protection test, ZIP).
    pub outcome: Signal<Option<Outcome>>,
    /// The last system report («Проверить» or the re-check after a repair).
    pub report: Signal<Option<SystemReport>>,
    /// The last finished protection test (leak result panel).
    pub test: Signal<Option<ProtectionTest>>,
    pub capture_outcome: Signal<Option<Outcome>>,
    pub legacy_outcome: Signal<Option<Outcome>>,
}

/// The controller of the calling component.
pub(crate) fn use_controller(
    api: Rc<dyn MaintenanceApi>,
    state: Signal<MaintenanceState>,
) -> Controller {
    use_hook(move || Controller {
        api: CopyValue::new(api),
        state,
        health: JobSlot::new(),
        repair: JobSlot::new(),
        protect: JobSlot::new(),
        export: JobSlot::new(),
        capture: JobSlot::new(),
        legacy: JobSlot::new(),
        outcome: Signal::new(None),
        report: Signal::new(None),
        test: Signal::new(None),
        capture_outcome: Signal::new(None),
        legacy_outcome: Signal::new(None),
    })
}

/// Shows a toast when the app provides the queue (bare demos and tests may not).
fn toast(kind: ToastKind, title_key: &str, outcome: &Outcome) {
    if let Some(toasts) = try_consume_context::<Toasts>() {
        toasts.push(kind, crate::t!(title_key), Some(render(outcome)));
    }
}

/// The outcome as one line in the current language.
pub(crate) fn render(outcome: &Outcome) -> String {
    join_sentences(outcome.parts.iter().map(tr))
}

/// Joins sentences with a space, closing a part that ends without punctuation with a period
/// (backend sentences such as «В IPv4-проверке утечек не обнаружено» carry none).
fn join_sentences(parts: impl IntoIterator<Item = String>) -> String {
    let mut line = String::new();
    for part in parts.into_iter().map(|p| p.trim().to_owned()) {
        if part.is_empty() {
            continue;
        }
        if !line.is_empty() {
            if !line.ends_with(['.', '!', '?', ':', ';', '…']) {
                line.push('.');
            }
            line.push(' ');
        }
        line.push_str(&part);
    }
    line
}

/// Toast kind of a result: Fail → error, Warn → warning, otherwise success.
fn toast_kind(verdict: Verdict) -> ToastKind {
    match verdict {
        Verdict::Fail => ToastKind::Error,
        Verdict::Warn | Verdict::NotChecked => ToastKind::Warning,
        Verdict::Ok => ToastKind::Success,
    }
}

/// Writes a result to the log at the level of its verdict (log lines stay English).
fn journal(verdict: Verdict, what: &str) {
    match rules::journal_level(verdict) {
        tracing::Level::ERROR => tracing::error!(target: "ui", "maintenance: {what}"),
        tracing::Level::WARN => tracing::warn!(target: "ui", "maintenance: {what}"),
        _ => tracing::info!(target: "ui", "maintenance: {what}"),
    }
}

/// The health check proper: the report and the protection read-back, in parallel.
async fn run_health(
    api: &dyn MaintenanceApi,
    token: CancellationToken,
) -> AppResult<(SystemReport, ProtectionView)> {
    try_join(api.system_report(token), api.verify_protection()).await
}

impl Controller {
    fn api(self) -> Rc<dyn MaintenanceApi> {
        self.api.read().clone()
    }

    /// Whether any state-panel action runs (here or, for the ZIP and the repair, anywhere in
    /// the app); subscribes the caller.
    pub fn busy(self) -> bool {
        let state = self.state.read();
        self.health.running()
            || self.repair.running()
            || self.protect.running()
            || self.export.running()
            || state.export.running
            || state.repair.running
    }

    fn set_outcome(self, outcome: Outcome) {
        let mut slot = self.outcome;
        slot.set(Some(outcome));
    }

    /// «Проверить»: report + protection; the result line and the log say whether anything needs
    /// attention (`health-check-summary`, AT-00-005).
    pub fn health_check(self) {
        if self.busy() {
            return;
        }
        tracing::info!(target: "ui", "maintenance: health check started");
        let api = self.api();
        let mut report = self.report;
        self.health.start(move |token| async move {
            match run_health(&*api, token).await {
                Ok((r, protection)) => {
                    let outcome = rules::health_outcome(Some(&protection), &r);
                    log_health(outcome.verdict);
                    report.set(Some(r));
                    self.set_outcome(outcome);
                }
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::error!(target: "ui", error = %err, "maintenance: health check failed");
                    let outcome = Outcome {
                        verdict: Verdict::Fail,
                        parts: vec![Msg::new("ui.maintenance.health.failed"), err.user_msg()],
                    };
                    toast(ToastKind::Error, "ui.maintenance.title", &outcome);
                    self.set_outcome(outcome);
                }
            }
            Ok(())
        });
    }
}

/// The summary line of a health check, with the event code the app-log scan skips.
fn log_health(verdict: Verdict) {
    let summary = match verdict {
        Verdict::Ok => "ok",
        Verdict::Warn => "warn",
        Verdict::Fail => "fail",
        Verdict::NotChecked => "not-checked",
    };
    match rules::journal_level(verdict) {
        tracing::Level::ERROR => {
            tracing::error!(target: "ui", event_code = "health-check-summary", summary, "maintenance: health check finished with failures")
        }
        tracing::Level::WARN => {
            tracing::warn!(target: "ui", event_code = "health-check-summary", summary, "maintenance: health check finished: items need attention")
        }
        _ => {
            tracing::info!(target: "ui", event_code = "health-check-summary", summary, "maintenance: health check finished")
        }
    }
}

/// A refusal is a warning, anything else a failure.
fn error_verdict(err: &UiError) -> Verdict {
    if err.kind == ErrorKind::Conflict {
        Verdict::Warn
    } else {
        Verdict::Fail
    }
}

/// Whether the tunnel lets the auto-repair run.
fn repair_allowed(tunnel: TunnelPhase) -> bool {
    tunnel == TunnelPhase::Off
}

impl Controller {
    /// «Починить» (after the confirmation): refused here while a session exists; otherwise the
    /// backend runs the steps, then the health check runs again. Every path ends in a result
    /// line (U-13).
    pub fn repair(self) {
        if self.busy() {
            return;
        }
        if !repair_allowed(self.state.peek().tunnel) {
            let outcome = Outcome::new(
                Verdict::Warn,
                Msg::new("ui.maintenance.repair.disconnectFirst"),
            );
            journal(outcome.verdict, "auto-repair refused: a session is active");
            toast(ToastKind::Warning, "ui.maintenance.title", &outcome);
            self.set_outcome(outcome);
            return;
        }
        tracing::warn!(target: "ui", "maintenance: auto-repair started");
        let api = self.api();
        let mut report = self.report;
        self.repair.start(move |token| async move {
            let view = match api.repair().await {
                Ok(view) => view,
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    let err = UiError::from(err);
                    let outcome = Outcome::new(error_verdict(&err), err.msg.clone());
                    journal(outcome.verdict, &format!("auto-repair not run: {}", err.msg.key));
                    toast(toast_kind(outcome.verdict), "ui.maintenance.title", &outcome);
                    self.set_outcome(outcome);
                    return Ok(());
                }
            };
            for (step, state) in &view.steps {
                if let super::StepState::Done(o) = state {
                    let detail = rules::step_detail(o);
                    journal(rules::step_status(o), &format!("repair step {}: {}", step.id(), detail.key));
                }
            }
            let mut outcome = rules::repair_outcome(&view.steps);
            match run_health(&*api, token).await {
                Ok((r, _)) => report.set(Some(r)),
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::warn!(target: "ui", error = %err, "maintenance: re-check after repair failed");
                    outcome.parts.push(Msg::new("ui.maintenance.repair.recheckFailed"));
                    outcome.parts.push(err.user_msg());
                }
            }
            journal(outcome.verdict, "auto-repair finished");
            let kind = if outcome.verdict == Verdict::Ok {
                ToastKind::Success
            } else {
                ToastKind::Warning
            };
            toast(kind, "ui.maintenance.title", &outcome);
            self.set_outcome(outcome);
            Ok(())
        });
    }

    /// «Проверить защиту»: the leak and routing self-tests in parallel with their own tokens
    /// (children of the run's token: leaving the page cancels both; one failure cancels the
    /// other); only with an active session.
    pub fn protection_test(self) {
        if self.busy() {
            return;
        }
        if self.state.peek().tunnel != TunnelPhase::On {
            let outcome = Outcome::new(
                Verdict::Warn,
                Msg::new("ui.maintenance.protectionTest.needsVpn"),
            );
            journal(outcome.verdict, "protection test needs an active session");
            self.set_outcome(outcome);
            return;
        }
        tracing::info!(target: "ui", "maintenance: protection test started");
        let api = self.api();
        let mut test = self.test;
        self.protect.start(move |token| async move {
            let (leak_t, route_t) = (token.child_token(), token.child_token());
            let leak = async {
                let r = api.leak_self_test(leak_t.clone()).await;
                if r.is_err() {
                    route_t.cancel();
                }
                r
            };
            let route = async {
                let r = api.routing_self_test(route_t.clone()).await;
                if r.is_err() {
                    leak_t.cancel();
                }
                r
            };
            match try_join(leak, route).await {
                Ok((leak, route)) => {
                    let t = ProtectionTest { leak, route };
                    let outcome = rules::protection_outcome(&t);
                    journal(outcome.verdict, &format!("protection test: leak {} / route {:?}", t.leak.verdict.name(), t.route.verdict));
                    toast(toast_kind(outcome.verdict), "ui.maintenance.protectionTest.title", &outcome);
                    test.set(Some(t));
                    self.set_outcome(outcome);
                }
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::error!(target: "ui", error = %err, "maintenance: protection test failed");
                    let outcome = Outcome::error(&UiError::from(err));
                    toast(ToastKind::Error, "ui.maintenance.protectionTest.title", &outcome);
                    self.set_outcome(outcome);
                }
            }
            Ok(())
        });
    }

    /// «ZIP»: one export app-wide; a dismissed save dialog is only logged.
    pub fn export_zip(self) {
        if self.busy() {
            return;
        }
        tracing::info!(target: "ui", "maintenance: diagnostics export started");
        let api = self.api();
        self.export.start(move |token| async move {
            match api.export_diagnostics(token).await {
                Ok(Some(done)) => {
                    tracing::info!(target: "ui", path = %done.path, "maintenance: diagnostics archive created");
                    let outcome = Outcome::new(
                        Verdict::Ok,
                        Msg::new("ui.maintenance.export.saved").arg("path", &done.path),
                    );
                    toast(ToastKind::Success, "ui.maintenance.export.title", &outcome);
                    if done.cleanup_failed {
                        tracing::warn!(target: "ui", "maintenance: diagnostics temp files were not removed");
                        let note = Outcome::new(Verdict::Warn, Msg::new("ui.maintenance.export.cleanupFailedBody"));
                        toast(ToastKind::Warning, "ui.maintenance.export.cleanupFailed", &note);
                    }
                    self.set_outcome(outcome);
                }
                Ok(None) => tracing::info!(target: "ui", "maintenance: diagnostics export cancelled by the user"),
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::error!(target: "ui", error = %err, "maintenance: diagnostics export failed");
                    let outcome = rules::export_failure(&UiError::from(err));
                    toast(ToastKind::Error, "ui.maintenance.export.title", &outcome);
                    self.set_outcome(outcome);
                }
            }
            Ok(())
        });
    }
}

impl Controller {
    fn set_capture_outcome(self, outcome: Outcome) {
        let mut slot = self.capture_outcome;
        slot.set(Some(outcome));
    }

    fn set_legacy_outcome(self, outcome: Outcome) {
        let mut slot = self.legacy_outcome;
        slot.set(Some(outcome));
    }

    /// «Перезапустить сбор»: restarted, or why it did not start.
    pub fn restart_capture(self) {
        tracing::info!(target: "ui", "maintenance: restarting packet capture and ETW");
        let api = self.api();
        self.capture.start(move |_| async move {
            match api.restart_capture().await {
                Ok(view) => {
                    let outcome = rules::capture_restart_outcome(&view);
                    journal(outcome.verdict, "packet capture restart finished");
                    self.set_capture_outcome(outcome);
                }
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::error!(target: "ui", error = %err, "maintenance: packet capture restart failed");
                    self.set_capture_outcome(failure("ui.maintenance.capture.restartFailed", err.user_msg()));
                }
            }
            Ok(())
        });
    }

    /// «Папка со снимками».
    pub fn open_snapshots(self) {
        let api = self.api();
        self.capture.start(move |_| async move {
            match api.open_snapshots_folder().await {
                Ok(()) => {}
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => {
                    tracing::warn!(target: "ui", error = %err, "maintenance: snapshots folder did not open");
                    self.set_capture_outcome(failure("ui.maintenance.capture.folderFailed", err.user_msg()));
                }
            }
            Ok(())
        });
    }

    /// «Удалить данные старой версии» (after the confirmation).
    pub fn delete_legacy(self) {
        let api = self.api();
        self.legacy.start(move |_| async move {
            let outcome = match api.delete_legacy_data().await {
                Ok(()) => Outcome::new(Verdict::Ok, Msg::new("ui.maintenance.legacy.deleted")),
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => failure("ui.maintenance.legacy.deleteFailed", err.user_msg()),
            };
            journal(outcome.verdict, "old version data removal finished");
            self.set_legacy_outcome(outcome);
            Ok(())
        });
    }

    /// «Повторить импорт ключей из старой версии».
    pub fn retry_secrets(self) {
        let api = self.api();
        self.legacy.start(move |_| async move {
            let outcome = match api.retry_secrets_import().await {
                Ok(r) if r.pending => Outcome {
                    verdict: Verdict::Warn,
                    parts: vec![
                        Msg::new("ui.maintenance.legacy.secretsRestored").arg("count", r.restored),
                        Msg::new("ui.maintenance.legacy.secretsStillPending"),
                    ],
                },
                Ok(r) => Outcome::new(
                    Verdict::Ok,
                    Msg::new("ui.maintenance.legacy.secretsRestored").arg("count", r.restored),
                ),
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => failure("ui.maintenance.legacy.secretsFailed", err.user_msg()),
            };
            journal(outcome.verdict, "old version key import retried");
            self.set_legacy_outcome(outcome);
            Ok(())
        });
    }

    /// «Отложить повреждённый файл и начать с пустого списка».
    pub fn set_aside(self, id: String) {
        let api = self.api();
        self.legacy.start(move |_| async move {
            let outcome = match api.set_aside_corrupt(id).await {
                Ok(()) => Outcome::new(Verdict::Ok, Msg::new("ui.maintenance.legacy.setAsideDone")),
                Err(err) if err.kind == ErrorKind::Cancelled => return Err(err),
                Err(err) => failure("ui.maintenance.legacy.setAsideFailed", err.user_msg()),
            };
            journal(outcome.verdict, "corrupt document set aside");
            self.set_legacy_outcome(outcome);
            Ok(())
        });
    }
}

/// «<what failed>: <why>».
fn failure(key: &'static str, why: Msg) -> Outcome {
    Outcome {
        verdict: Verdict::Fail,
        parts: vec![Msg::new(key), why],
    }
}

#[cfg(test)]
mod tests;
