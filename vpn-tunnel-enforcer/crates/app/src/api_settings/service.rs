//! [`SettingsApi`] for [`SettingsService`]: thin dispatch to the modules that do the work.
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::AppResult;
use vpnte_ui::settings::*;

use super::{SettingsService, Shared, actions, rules, save, wizard};
use crate::services::Backend;
use crate::support::files::pick_program;
use crate::support::{blocking, detached, unavailable};

impl SettingsService {
    /// Runs a blocking store change on the blocking pool with a backend handle.
    async fn store<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Backend) -> AppResult<T> + Send + 'static,
    ) -> AppResult<T> {
        let backend = self.0.backend.clone();
        blocking(move || work(&backend)).await
    }

    fn shared(&self) -> &Arc<Shared> {
        &self.0
    }
}

#[async_trait(?Send)]
impl SettingsApi for SettingsService {
    fn state(&self) -> watch::Receiver<SettingsState> {
        self.0.state.subscribe()
    }
    fn kill_switch(&self) -> watch::Receiver<KillSwitchView> {
        self.0.kill.subscribe()
    }
    fn rotation(&self) -> watch::Receiver<RotationView> {
        self.0.rotation.subscribe()
    }
    fn dns(&self) -> watch::Receiver<DnsView> {
        self.0.dns.subscribe()
    }
    fn domains(&self) -> watch::Receiver<DomainsView> {
        self.0.domains.subscribe()
    }
    fn notifications(&self) -> watch::Receiver<NotificationsView> {
        self.0.notifications.subscribe()
    }

    async fn save(&self, patch: SettingsPatch) -> AppResult<SaveReport> {
        detached(save::save(self.0.clone(), patch)).await
    }

    async fn set_language(&self, lang: Lang) -> AppResult<()> {
        actions::set_language(self.shared(), lang).await
    }

    async fn set_theme(&self, id: String) -> AppResult<()> {
        let theme = actions::set_theme(self.shared(), id).await?;
        // Back on the UI thread: the frame applies the signal to the page and the window.
        *vpnte_ui::theme::THEME.write() = theme;
        Ok(())
    }

    async fn set_autostart(&self, on: bool) -> AppResult<bool> {
        actions::set_autostart(self.shared(), on).await
    }

    async fn set_location_privacy(&self, _on: bool) -> AppResult<LocationOutcome> {
        Err(unavailable("app.settings.locationUnavailable"))
    }

    async fn apply_browser_protection(&self) -> AppResult<BrowserView> {
        Err(unavailable("app.settings.browserUnavailable"))
    }

    async fn rollback_browser_protection(&self) -> AppResult<BrowserView> {
        Err(unavailable("app.settings.browserUnavailable"))
    }

    async fn retry_adaptive(&self) -> AppResult<bool> {
        Err(unavailable("app.settings.adaptiveUnavailable"))
    }

    async fn reset_adaptive_learning(&self) -> AppResult<()> {
        Err(unavailable("app.settings.adaptiveUnavailable"))
    }

    async fn refresh_rule_sets(&self) -> AppResult<()> {
        actions::refresh_rule_sets(self.shared()).await
    }

    async fn open_wizard(&self) -> AppResult<()> {
        wizard::open(self.shared()).await;
        Ok(())
    }

    async fn open_logs_folder(&self) -> AppResult<()> {
        actions::open_logs_folder(self.shared()).await
    }

    async fn export_diagnostics(&self) -> AppResult<DiagnosticsExport> {
        Err(unavailable("app.settings.diagnosticsUnavailable"))
    }

    async fn clear_captures(&self) -> AppResult<()> {
        Err(unavailable("app.settings.captureUnavailable"))
    }

    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        actions::set_kill_switch_level(self.shared(), level).await
    }

    async fn add_exception(
        &self,
        kind: ExceptionKind,
        value: String,
        label: String,
    ) -> AppResult<()> {
        actions::add_exception(self.shared(), kind, value, label).await
    }

    async fn remove_exception(&self, id: String) -> AppResult<()> {
        actions::remove_exception(self.shared(), id).await
    }

    async fn pick_app(&self) -> AppResult<Option<PickedApp>> {
        let picked = pick_program(self.0.backend.lang()).await?;
        Ok(picked.map(|path| PickedApp {
            name: path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path: path.to_string_lossy().into_owned(),
        }))
    }

    async fn set_rotation(&self, _patch: RotationPatch) -> AppResult<()> {
        Err(unavailable("app.settings.rotationUnavailable"))
    }

    async fn set_rotation_profile(&self, _id: String, _included: bool) -> AppResult<()> {
        Err(unavailable("app.settings.rotationUnavailable"))
    }

    async fn rotate_now(&self) -> AppResult<RotationOutcome> {
        Err(unavailable("app.settings.rotationUnavailable"))
    }

    async fn validate_dns(&self, address: String) -> AppResult<DnsKind> {
        rules::validate_dns(&address)
    }

    async fn create_dns(&self, name: String, address: String) -> AppResult<()> {
        self.store(move |b| rules::create_dns(b, &name, &address))
            .await
    }

    async fn delete_dns(&self, id: String) -> AppResult<()> {
        self.store(move |b| rules::delete_dns(b, &id)).await
    }

    async fn select_dns(&self, id: Option<String>) -> AppResult<()> {
        self.store(move |b| rules::select_dns(b, id.as_deref()))
            .await
    }

    async fn add_domain_rule(&self, pattern: String, action: DomainAction) -> AppResult<()> {
        self.store(move |b| rules::add_domain_rule(b, &pattern, action))
            .await
    }

    async fn update_domain_rule(
        &self,
        id: String,
        pattern: String,
        action: DomainAction,
    ) -> AppResult<()> {
        self.store(move |b| rules::update_domain_rule(b, &id, &pattern, action))
            .await
    }

    async fn delete_domain_rule(&self, id: String) -> AppResult<()> {
        self.store(move |b| rules::delete_domain_rule(b, &id)).await
    }

    async fn reorder_domain_rules(&self, ids: Vec<String>) -> AppResult<()> {
        self.store(move |b| rules::reorder_domain_rules(b, &ids))
            .await
    }

    async fn pick_domain_list(&self) -> AppResult<Option<DomainImportPreview>> {
        rules::pick_domain_list(self.shared()).await
    }

    async fn import_domain_list(&self, action: DomainAction) -> AppResult<DomainImportReport> {
        let shared = self.0.clone();
        blocking(move || rules::import_domain_list(&shared, action)).await
    }

    async fn discard_domain_list(&self) {
        self.0.touch(|l| l.domain_list = None);
    }

    async fn set_notification(&self, change: NotificationChange) -> AppResult<()> {
        actions::set_notification(self.shared(), change).await
    }

    async fn check_os_notifications(&self) -> AppResult<()> {
        actions::check_os_notifications(self.shared()).await
    }

    async fn reset_os_notification_block(&self) -> AppResult<ResetReport> {
        actions::reset_os_notification_block(self.shared()).await
    }

    async fn open_windows_notification_settings(&self) -> AppResult<()> {
        vpnte_winnet::shell::open_notification_settings().await
    }

    async fn export_config(&self, _mode: ExportMode) -> AppResult<()> {
        Err(unavailable("app.settings.transferUnavailable"))
    }

    async fn pick_config_import(&self) -> AppResult<Option<ImportPreview>> {
        Err(unavailable("app.settings.transferUnavailable"))
    }

    async fn apply_config_import(
        &self,
        _sections: Vec<ConfigSection>,
        _mode: ImportMode,
    ) -> AppResult<()> {
        Err(unavailable("app.settings.transferUnavailable"))
    }

    /// Nothing is ever picked in this build (config transfer is not wired).
    async fn discard_config_import(&self) {}
}
