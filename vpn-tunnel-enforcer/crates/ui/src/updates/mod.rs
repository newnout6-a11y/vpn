//! Updates of the app and its engines (p-updates; research/updates.md §4.5): the quiet banner
//! on the start page, the Settings section «Обновления» and its «Движки» block. Short calm
//! texts, no forcing: a security update gets one tray notice and loses «Пропустить», «Позже»
//! always stays.
//!
//! The UI talks to the backend only through [`UpdatesApi`], handed down as
//! `Rc<dyn UpdatesApi>` in context; every piece renders nothing when no API is provided (demos
//! of other pages). [`demo::DemoUpdates`] is the fake for `demo_updates` and the tests.
use tokio::sync::watch;
use vpnte_base::AppResult;

mod banner;
pub mod demo;
mod format;
mod model;
mod section;

pub use banner::UpdateBanner;
pub use format::{day_label, notes_for};
pub use model::{
    AppOffer, CheckLine, CheckResult, EngineOffer, EngineRow, Note, Progress, ServiceLine,
    ServiceState, UpdateOutcome, UpdatesView,
};
pub use section::UpdatesSection;

/// What the update UI needs from the backend (implemented by the app's `svc_update`).
#[async_trait::async_trait(?Send)]
pub trait UpdatesApi: 'static {
    /// The whole view, pushed on every change.
    fn state(&self) -> watch::Receiver<UpdatesView>;
    /// «Проверить сейчас».
    async fn check_now(&self) -> AppResult<()>;
    /// «Обновить»: download, verify, hand over to the installer (the app then exits).
    async fn update_app(&self) -> AppResult<()>;
    /// «Вернуть версию …»: the same with the feed's rollback installer.
    async fn rollback_app(&self) -> AppResult<()>;
    /// «Позже» on the app banner: hidden until the next start.
    async fn later_app(&self) -> AppResult<()>;
    /// «Пропустить эту версию».
    async fn skip_app(&self) -> AppResult<()>;
    /// «Установить» on an engine offer.
    async fn install_engine(&self, id: String) -> AppResult<()>;
    /// «Позже» on an engine offer: hidden until the next start.
    async fn later_engine(&self, id: String) -> AppResult<()>;
    /// «Вернуть предыдущую».
    async fn revert_previous(&self, id: String) -> AppResult<()>;
    /// «Вернуть встроенную».
    async fn revert_bundled(&self, id: String) -> AppResult<()>;
    /// «Проверять автоматически».
    async fn set_auto_check(&self, on: bool) -> AppResult<()>;
    /// «Скачивать заранее».
    async fn set_download_ahead(&self, on: bool) -> AppResult<()>;
    /// «Сбросить» the skipped versions.
    async fn reset_skipped(&self) -> AppResult<()>;
    /// After a failed update: run the kept installer again.
    async fn retry_installer(&self) -> AppResult<()>;
    /// Hides the outcome line and the note.
    async fn dismiss(&self) -> AppResult<()>;
    /// «Сейчас» on an engine switch: the running session reconnects on the new engine.
    async fn switch_engine_now(&self) -> AppResult<()>;
}
