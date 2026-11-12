//! The Settings page and the first-run wizard over the backend (work package `app-settings`):
//! [`SettingsApi`] and [`WizardApi`], plus [`contexts`], which also hands out the Logs page's
//! [`LogsApi`](vpnte_ui::logs::LogsApi) from `crate::api_logs`.
//!
//! The page renders pushed snapshots only: one task re-projects every section whenever a
//! store or the tunnel changes (`pump`). Actions run as backend tasks, so a page that unmounts
//! mid-call never leaves a half-done change behind. Privileged features exist only when the
//! process is elevated (NOADMIN §0); features this build does not wire (rotation, browser
//! hardening, location privacy, config transfer, packet capture, diagnostics export) answer
//! with an honest "not available" error and never pretend to work.
mod actions;
mod project;
mod pump;
mod rules;
mod save;
mod service;
mod wizard;

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

use std::any::Any;
use std::rc::Rc;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use vpnte_base::Msg;
use vpnte_ui::logs::LogsApi;
use vpnte_ui::settings::{
    DnsView, DomainsView, KillSwitchView, NotificationsView, OsNotifications, RotationView,
    SettingsApi, SettingsState,
};
use vpnte_ui::wizard::{WizardApi, WizardState};
use vpnte_winnet::autostart::{AutostartOs, RunValue};

use crate::services::Backend;
pub use wizard::WizardService;

/// The UI contexts of this package for `vpnte_ui::launch`: `Rc<dyn SettingsApi>`,
/// `Rc<dyn WizardApi>` and `Rc<dyn LogsApi>`. Call it inside the tokio runtime (the projection
/// tasks start here, stopped by `backend.shutdown`) after `backend.tunnel` was set.
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    // Never fails on Windows in practice; an unknown path makes the autostart read-back fail
    // honestly instead of writing a broken value silently.
    let exe = std::env::current_exe().unwrap_or_else(|err| {
        tracing::warn!(%err, "own executable path unknown");
        std::path::PathBuf::new()
    });
    let shared = Shared::start(backend.clone(), Arc::new(RunValue { exe }));
    let settings: Rc<dyn SettingsApi> = Rc::new(SettingsService(shared.clone()));
    let wizard: Rc<dyn WizardApi> = Rc::new(WizardService(shared));
    let logs: Rc<dyn LogsApi> = Rc::new(crate::api_logs::LogsService::start(backend.clone()));
    vec![Box::new(settings), Box::new(wizard), Box::new(logs)]
}

/// The Windows `Run` value as the autostart toggle drives it (a fake in tests).
pub(crate) type Autostart = Arc<dyn AutostartOs + Send + Sync>;

/// [`SettingsApi`] over the backend.
pub struct SettingsService(Arc<Shared>);

/// State shared by both APIs, their actions and the projection task.
pub(crate) struct Shared {
    pub backend: Arc<Backend>,
    pub autostart: Autostart,
    pub state: watch::Sender<SettingsState>,
    pub kill: watch::Sender<KillSwitchView>,
    pub rotation: watch::Sender<RotationView>,
    pub dns: watch::Sender<DnsView>,
    pub domains: watch::Sender<DomainsView>,
    pub notifications: watch::Sender<NotificationsView>,
    pub wizard: watch::Sender<WizardState>,
    /// Facts no store holds: read from Windows or produced by an action of this package.
    pub local: Mutex<Local>,
    /// Wakes the projection task for a change without a store event (`local`).
    pub dirty: Notify,
    /// Serialises the settings writes of `save`, the wizard and the instant preferences, so
    /// the `old` handed to `apply_settings_change` is the value the write replaced.
    pub writes: tokio::sync::Mutex<()>,
}

/// See [`Shared::local`].
#[derive(Default)]
pub(crate) struct Local {
    /// Autostart as Windows reported it last (`None`: not read yet or unreadable).
    pub autostart: Option<bool>,
    pub os_notifications: OsNotifications,
    /// A forced Smart RU refresh of this page is running.
    pub rule_sets_refreshing: bool,
    /// Why the last refresh started here did not complete.
    pub rule_sets_error: Option<Msg>,
    /// The domain list picked for import, waiting for the user's action choice.
    pub domain_list: Option<rules::PickedList>,
}

impl Shared {
    /// Publishes the first snapshots and starts the projection task.
    pub fn start(backend: Arc<Backend>, autostart: Autostart) -> Arc<Self> {
        let shared = Arc::new(Self {
            backend,
            autostart,
            state: watch::Sender::new(SettingsState::default()),
            kill: watch::Sender::new(KillSwitchView::default()),
            rotation: watch::Sender::new(RotationView::default()),
            dns: watch::Sender::new(DnsView::default()),
            domains: watch::Sender::new(DomainsView::default()),
            notifications: watch::Sender::new(NotificationsView::default()),
            wizard: watch::Sender::new(WizardState::default()),
            local: Mutex::new(Local::default()),
            dirty: Notify::new(),
            writes: tokio::sync::Mutex::new(()),
        });
        pump::spawn(&shared);
        shared
    }

    /// Records a change of `local` and wakes the projection.
    pub fn touch(&self, f: impl FnOnce(&mut Local)) {
        f(&mut self.local.lock());
        self.dirty.notify_one();
    }
}
