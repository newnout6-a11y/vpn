//! [`SettingsApi`]: what the Settings page needs from the backend. The app implements it over
//! the services; [`super::demo::DemoSettingsApi`] is the fake used by `demo_settings`.
//!
//! Pushed state comes as `watch` receivers (one snapshot per section, so a change made anywhere
//! — wizard, config import, automatic rotation, the rule-set updater — shows at once, U-33).
//! Actions return `AppResult`; `ErrorKind::Cancelled` (a dismissed dialog) is never shown.
use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::AppResult;

use super::model::*;

/// Backend of the Settings page (handed to it as `Rc<dyn SettingsApi>` context).
#[async_trait(?Send)]
pub trait SettingsApi: 'static {
    // ── pushed state ──
    /// Live draft fields, instant preferences, adaptive / rule-set / browser status.
    fn state(&self) -> watch::Receiver<SettingsState>;
    fn kill_switch(&self) -> watch::Receiver<KillSwitchView>;
    fn rotation(&self) -> watch::Receiver<RotationView>;
    fn dns(&self) -> watch::Receiver<DnsView>;
    fn domains(&self) -> watch::Receiver<DomainsView>;
    fn notifications(&self) -> watch::Receiver<NotificationsView>;

    // ── draft ──
    /// Applies the changed fields only (merge + normalise + side effects: tunnel restart, rule
    /// set refresh trigger, IP monitor interval).
    async fn save(&self, patch: SettingsPatch) -> AppResult<SaveReport>;

    // ── instant preferences ──
    /// Persists the language (the page has already switched the UI).
    async fn set_language(&self, lang: Lang) -> AppResult<()>;
    /// Activates a theme by id (and switches the window to it).
    async fn set_theme(&self, id: String) -> AppResult<()>;
    /// Writes or removes the per-user `Run` value; returns the state read back from Windows.
    async fn set_autostart(&self, on: bool) -> AppResult<bool>;
    async fn set_location_privacy(&self, on: bool) -> AppResult<LocationOutcome>;
    async fn apply_browser_protection(&self) -> AppResult<BrowserView>;
    async fn rollback_browser_protection(&self) -> AppResult<BrowserView>;
    /// `false`: no session to re-check (U-08).
    async fn retry_adaptive(&self) -> AppResult<bool>;
    async fn reset_adaptive_learning(&self) -> AppResult<()>;
    /// Forced download of the Smart RU lists with the SAVED settings (never the draft, U-02).
    async fn refresh_rule_sets(&self) -> AppResult<()>;
    /// Shows the first-run wizard now (U-20).
    async fn open_wizard(&self) -> AppResult<()>;
    /// Opens the folder with `app.log` and the engine logs.
    async fn open_logs_folder(&self) -> AppResult<()>;
    /// Save dialog + ZIP (single-flight app-wide); a dismissed dialog is `Cancelled`.
    async fn export_diagnostics(&self) -> AppResult<DiagnosticsExport>;
    /// Deletes the stored capture sessions.
    async fn clear_captures(&self) -> AppResult<()>;

    // ── kill switch ──
    /// Applies, verifies and persists the level; on failure the level stays as it was.
    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()>;
    /// Validates strictly (the error says why) and applies.
    async fn add_exception(
        &self,
        kind: ExceptionKind,
        value: String,
        label: String,
    ) -> AppResult<()>;
    async fn remove_exception(&self, id: String) -> AppResult<()>;
    /// Open dialog for an `.exe`; `None` = dismissed.
    async fn pick_app(&self) -> AppResult<Option<PickedApp>>;

    // ── rotation ──
    async fn set_rotation(&self, patch: RotationPatch) -> AppResult<()>;
    /// Adds or removes one server inside the service (U-16: no list computed from a stale copy).
    async fn set_rotation_profile(&self, id: String, included: bool) -> AppResult<()>;
    async fn rotate_now(&self) -> AppResult<RotationOutcome>;

    // ── DNS ──
    /// Parses an address; the error message says what is wrong.
    async fn validate_dns(&self, address: String) -> AppResult<DnsKind>;
    async fn create_dns(&self, name: String, address: String) -> AppResult<()>;
    async fn delete_dns(&self, id: String) -> AppResult<()>;
    /// `None` = the automatic entry.
    async fn select_dns(&self, id: Option<String>) -> AppResult<()>;

    // ── domain rules ──
    async fn add_domain_rule(&self, pattern: String, action: DomainAction) -> AppResult<()>;
    async fn update_domain_rule(
        &self,
        id: String,
        pattern: String,
        action: DomainAction,
    ) -> AppResult<()>;
    async fn delete_domain_rule(&self, id: String) -> AppResult<()>;
    /// The full new order (ids); the service ignores unknown and repeated ids.
    async fn reorder_domain_rules(&self, ids: Vec<String>) -> AppResult<()>;
    /// Open dialog + read + check a domain list; `None` = dismissed. Replaces an earlier pick.
    async fn pick_domain_list(&self) -> AppResult<Option<DomainImportPreview>>;
    /// Imports the picked list with one action for all its domains.
    async fn import_domain_list(&self, action: DomainAction) -> AppResult<DomainImportReport>;
    /// Forgets the picked list.
    async fn discard_domain_list(&self);

    // ── notifications ──
    async fn set_notification(&self, change: NotificationChange) -> AppResult<()>;
    /// Re-reads the Windows block state (window focus, «Повторить»); the result is pushed.
    async fn check_os_notifications(&self) -> AppResult<()>;
    async fn reset_os_notification_block(&self) -> AppResult<ResetReport>;
    async fn open_windows_notification_settings(&self) -> AppResult<()>;

    // ── config transfer ──
    /// Consent (secrets) + save dialog + write; a dismissed dialog is `Cancelled`.
    async fn export_config(&self, mode: ExportMode) -> AppResult<()>;
    /// Open dialog + read + validate; `None` = dismissed. Replaces an earlier pick.
    async fn pick_config_import(&self) -> AppResult<Option<ImportPreview>>;
    /// Applies the picked file once; the pick is consumed even when this fails.
    async fn apply_config_import(
        &self,
        sections: Vec<ConfigSection>,
        mode: ImportMode,
    ) -> AppResult<()>;
    async fn discard_config_import(&self);
}
