//! Instant preferences of the Settings page (no draft): language, theme, autostart, the kill
//! switch, notifications, the Smart RU refresh and the logs folder. Each applies at once and
//! reports its own result.
use std::sync::Arc;

use vpnte_base::i18n::Lang;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::settings::NotificationPrefs;
use vpnte_engine::routing::rulesets::{RefreshFault, RefreshOutcome, RefreshSettings};
use vpnte_ui::settings as ui;
use vpnte_ui::theme::Theme;
use vpnte_winnet::autostart::{self, AutostartOs, AutostartState};
use vpnte_winnet::toast::{self, NotifySetting};

use super::project::{core_notify_method, theme_exists, wfp_exception_kind};
use super::{Shared, blocking, detached};

/// Stores the language the page already switched to.
pub async fn set_language(shared: &Arc<Shared>, lang: Lang) -> AppResult<()> {
    let shared = shared.clone();
    detached(async move {
        let _writes = shared.writes.lock().await;
        shared.backend.settings.update(|s| s.locale = Some(lang))
    })
    .await
}

/// Stores the active theme id and returns the theme to show; an id that names no theme is
/// refused (the old app fell back to System silently).
pub async fn set_theme(shared: &Arc<Shared>, id: String) -> AppResult<Theme> {
    let shared = shared.clone();
    detached(async move {
        let backend = &shared.backend;
        if !backend.themes.read(|t| theme_exists(t, &id)) {
            return Err(AppError::validation(Msg::new("app.settings.themeUnknown")));
        }
        let _writes = shared.writes.lock().await;
        backend
            .settings
            .update(|s| s.active_theme_id = id.clone())?;
        Ok(backend.themes.read(|t| t.theme(&id)))
    })
    .await
}

/// Writes or deletes the per-user `Run` value (never a task, never elevation), reads it back
/// and persists the setting; returns the state Windows reports now. An entry the user switched
/// off in Task Manager stays off: that switch is theirs, and the error says where it is.
pub async fn set_autostart(shared: &Arc<Shared>, on: bool) -> AppResult<bool> {
    let shared = shared.clone();
    detached(async move {
        let _writes = shared.writes.lock().await;
        apply_autostart(&shared, on).await
    })
    .await
}

/// [`set_autostart`] for a caller that already holds `Shared::writes` (the wizard).
pub async fn apply_autostart(shared: &Arc<Shared>, on: bool) -> AppResult<bool> {
    let worker = shared.clone();
    let state = blocking(move || {
        let settings = &worker.backend.settings;
        let previous = settings.read(|s| s.autostart);
        let os = Os(worker.autostart.as_ref());
        autostart::set_checked(&os, previous, on, |value| {
            settings.update(|s| s.autostart = value)
        })?;
        os.read().map_err(|err| {
            AppError::msg(
                ErrorKind::Internal,
                Msg::new("winnet.autostart.stateUnknown"),
            )
            .with_source(err)
        })
    })
    .await;
    let shown = state.as_ref().ok().map(|s| effective(*s));
    shared.touch(|l| l.autostart = shown);
    match state? {
        s @ AutostartState::DisabledByUser { .. } if on => Err(AppError::msg(
            ErrorKind::Conflict,
            s.hint()
                .unwrap_or_else(|| Msg::new("winnet.autostart.disabledByUser")),
        )),
        s => Ok(effective(s)),
    }
}

/// Reads the `Run` value for the page (on the blocking pool); `None` when unreadable.
pub async fn read_autostart(shared: &Arc<Shared>) -> Option<bool> {
    let os = shared.autostart.clone();
    let state = blocking(move || {
        os.read()
            .map_err(|err| AppError::internal(anyhow::anyhow!("autostart read: {err}")))
    })
    .await;
    match state {
        Ok(state) => Some(effective(state)),
        Err(err) => {
            tracing::warn!(error = %err, "autostart state unknown");
            None
        }
    }
}

/// Autostart counts as on only when the value starts this exe and the user has not switched it
/// off in Task Manager.
fn effective(state: AutostartState) -> bool {
    state == AutostartState::Present { matches_exe: true }
}

/// `set_checked` takes a sized `AutostartOs`; the shared one is a trait object.
struct Os<'a>(&'a (dyn AutostartOs + Send + Sync));

impl AutostartOs for Os<'_> {
    fn apply(&self, enabled: bool) -> windows::core::Result<()> {
        self.0.apply(enabled)
    }
    fn read(&self) -> windows::core::Result<AutostartState> {
        self.0.read()
    }
    fn remove_legacy_task(&self) -> windows::core::Result<bool> {
        self.0.remove_legacy_task()
    }
}

/// Applies, verifies and persists the level through the tunnel (WFP when elevated, Soft's
/// off / standard otherwise); the section is re-read either way.
pub async fn set_kill_switch_level(shared: &Arc<Shared>, level: KillSwitchLevel) -> AppResult<()> {
    let shared = shared.clone();
    detached(async move {
        let result = shared.backend.tunnel()?.set_kill_switch_level(level).await;
        shared.dirty.notify_one();
        result
    })
    .await
}

/// Validates, applies and persists a new exception (`Permission` without WFP).
pub async fn add_exception(
    shared: &Arc<Shared>,
    kind: ui::ExceptionKind,
    value: String,
    label: String,
) -> AppResult<()> {
    let shared = shared.clone();
    detached(async move {
        let tunnel = shared.backend.tunnel()?;
        let result = tunnel
            .add_exception(wfp_exception_kind(kind), value, label)
            .await;
        shared.dirty.notify_one();
        result.map(drop)
    })
    .await
}

pub async fn remove_exception(shared: &Arc<Shared>, id: String) -> AppResult<()> {
    let shared = shared.clone();
    detached(async move {
        let result = shared.backend.tunnel()?.remove_exception(id).await;
        shared.dirty.notify_one();
        result
    })
    .await
}

/// One notification control (one field per call: no lost updates).
pub async fn set_notification(
    shared: &Arc<Shared>,
    change: ui::NotificationChange,
) -> AppResult<()> {
    let shared = shared.clone();
    detached(async move {
        let _writes = shared.writes.lock().await;
        shared.backend.settings.update(|s| match change {
            ui::NotificationChange::Enabled(on) => s.desktop_notifications = on,
            ui::NotificationChange::Event(event, on) => {
                *event_flag(&mut s.notifications, event) = on
            }
            ui::NotificationChange::Method(method) => {
                s.notifications.method = core_notify_method(method);
            }
            ui::NotificationChange::Sound(on) => s.notifications.sound = on,
        })
    })
    .await
}

fn event_flag(prefs: &mut NotificationPrefs, event: ui::NotifyEvent) -> &mut bool {
    match event {
        ui::NotifyEvent::VpnConnect => &mut prefs.vpn_connect,
        ui::NotifyEvent::VpnDisconnect => &mut prefs.vpn_disconnect,
        ui::NotifyEvent::LeakDetected => &mut prefs.leak_detected,
        ui::NotifyEvent::ProfileRotation => &mut prefs.profile_rotation,
        ui::NotifyEvent::ScheduleTriggered => &mut prefs.schedule_triggered,
        ui::NotifyEvent::ConnectionError => &mut prefs.connection_error,
    }
}

/// Re-reads whether Windows lets the app show toasts and publishes it.
pub async fn check_os_notifications(shared: &Arc<Shared>) -> AppResult<()> {
    let read = blocking(|| toast::notification_setting(toast::app_aumid())).await;
    let os = match read {
        Ok(setting) => os_state(setting),
        Err(err) => ui::OsNotifications::CheckFailed(err.user_msg()),
    };
    shared.touch(|l| l.os_notifications = os);
    Ok(())
}

pub fn os_state(setting: NotifySetting) -> ui::OsNotifications {
    match setting {
        NotifySetting::Enabled => ui::OsNotifications::Allowed,
        // No toast seen yet or no Start-menu link: Windows has not decided anything.
        NotifySetting::Unregistered => ui::OsNotifications::Unknown,
        NotifySetting::DisabledForApplication
        | NotifySetting::DisabledForUser
        | NotifySetting::DisabledByGroupPolicy
        | NotifySetting::DisabledByManifest => ui::OsNotifications::Blocked,
    }
}

/// «Снять блокировку Windows»: clears the per-app switch of this app and of the old Electron
/// ids (a per-user value), then reads the state again.
pub async fn reset_os_notification_block(shared: &Arc<Shared>) -> AppResult<ui::ResetReport> {
    let report = blocking(|| {
        let mut ids = vec![toast::app_aumid()];
        ids.extend_from_slice(toast::LEGACY_AUMIDS);
        Ok(toast::reset_os_block(&ids))
    })
    .await?;
    check_os_notifications(shared).await?;
    Ok(ui::ResetReport {
        cleared: u32::try_from(report.cleared.len()).unwrap_or(u32::MAX),
        errors: report
            .errors
            .iter()
            .map(|(_, err)| err.user_msg())
            .collect(),
    })
}

/// Forced download of the Smart RU lists with the saved settings (never the draft, U-02).
/// Runs on the caller's task: the service's future is not `Send` (see the progress file), so it
/// cannot be spawned. Dropping it cancels the download, which the service leaves clean (a
/// generation is promoted whole or not at all).
pub async fn refresh_rule_sets(shared: &Arc<Shared>) -> AppResult<()> {
    let backend = &shared.backend;
    let cfg = backend.settings.read(RefreshSettings::from_settings);
    shared.touch(|l| {
        l.rule_sets_refreshing = true;
        l.rule_sets_error = None;
    });
    let refreshing = Refreshing(shared.clone());
    let cancel = backend.shutdown.child_token();
    let outcome = backend.rule_sets.refresh(&cfg, true, &cancel).await;
    drop(refreshing);
    if let Some(notice) = outcome.notice() {
        backend.notifier.notify(notice, None);
    }
    match outcome {
        RefreshOutcome::Fresh | RefreshOutcome::Updated { .. } => Ok(()),
        RefreshOutcome::Cancelled => Err(AppError::cancelled()),
        RefreshOutcome::Failed(fault) => {
            shared.touch(|l| l.rule_sets_error = Some(fault.msg()));
            let kind = match fault {
                RefreshFault::Download { .. } => ErrorKind::Network,
                _ => ErrorKind::Internal,
            };
            Err(AppError::msg(kind, fault.msg()))
        }
    }
}

/// Clears the page's "refreshing" flag however the refresh ends (dropped included).
struct Refreshing(Arc<Shared>);

impl Drop for Refreshing {
    fn drop(&mut self) {
        self.0.touch(|l| l.rule_sets_refreshing = false);
    }
}

/// The folder with `app.log` and the engine logs.
pub async fn open_logs_folder(shared: &Arc<Shared>) -> AppResult<()> {
    vpnte_winnet::shell::open_folder(&shared.backend.dirs.logs).await
}
