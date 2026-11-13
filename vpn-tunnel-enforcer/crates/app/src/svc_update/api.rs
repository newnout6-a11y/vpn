//! [`UpdatesApi`] over the update channel.
use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_ui::updates::{UpdatesApi, UpdatesView};
use vpnte_update::pending::Outcome;
use vpnte_update::policy;

use super::Updates;
use super::actions::engine_name;
use super::view::newer_release;

/// The UI's handle (`Rc<dyn UpdatesApi>` in the root context).
pub(super) struct Handle(pub Arc<Updates>);

impl Handle {
    /// Applies `f` to the document and refreshes the view.
    fn edit(&self, f: impl FnOnce(&mut super::doc::UpdatesDoc)) -> AppResult<()> {
        self.0.doc.update(f)?;
        self.0.refresh();
        Ok(())
    }

    /// An engine switch done by hand takes effect at the next start.
    fn switched(&self, id: &str, result: std::io::Result<bool>) -> AppResult<()> {
        match result {
            Ok(true) => {
                let msg = Msg::new("app.update.engineSwitched").arg("name", engine_name(id));
                self.0.note(msg, false);
                Ok(())
            }
            Ok(false) => Err(AppError::conflict(Msg::new("app.update.nothingToRestore"))),
            Err(err) => Err(AppError::from(err)),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl UpdatesApi for Handle {
    fn state(&self) -> watch::Receiver<UpdatesView> {
        self.0.view.subscribe()
    }

    async fn check_now(&self) -> AppResult<()> {
        if !policy::keys_ready() {
            return Err(AppError::conflict(Msg::new("app.update.notReady")));
        }
        self.0.now.notify_one();
        Ok(())
    }

    async fn update_app(&self) -> AppResult<()> {
        self.0.update_app()
    }

    async fn rollback_app(&self) -> AppResult<()> {
        self.0.rollback_app()
    }

    async fn later_app(&self) -> AppResult<()> {
        self.0.inner.lock().hidden_app = true;
        self.0.refresh();
        Ok(())
    }

    async fn skip_app(&self) -> AppResult<()> {
        let version = {
            let inner = self.0.inner.lock();
            let feed = inner.feed.as_ref().map(|s| &s.feed);
            feed.and_then(|f| newer_release(f, policy::app_version()))
                .map(|r| r.version.to_string())
        };
        let Some(version) = version else {
            return Ok(());
        };
        self.edit(|d| {
            if !d.skipped.contains(&version) {
                d.skipped.push(version);
            }
        })
    }

    async fn install_engine(&self, id: String) -> AppResult<()> {
        self.0.install_engine(&id)
    }

    async fn later_engine(&self, id: String) -> AppResult<()> {
        self.0.inner.lock().hidden_engines.push(id);
        self.0.refresh();
        Ok(())
    }

    async fn revert_previous(&self, id: String) -> AppResult<()> {
        let result = self.0.store.revert_previous(&id);
        self.switched(&id, result)
    }

    async fn revert_bundled(&self, id: String) -> AppResult<()> {
        let result = self.0.store.revert_bundled(&id).map(|()| true);
        self.switched(&id, result)
    }

    async fn set_auto_check(&self, on: bool) -> AppResult<()> {
        self.edit(|d| d.auto_check = on)
    }

    async fn set_download_ahead(&self, on: bool) -> AppResult<()> {
        self.edit(|d| d.download_ahead = on)?;
        if on {
            self.0.clone().download_ahead();
        }
        Ok(())
    }

    async fn reset_skipped(&self) -> AppResult<()> {
        self.edit(|d| d.skipped.clear())
    }

    async fn retry_installer(&self) -> AppResult<()> {
        // The kept installer is reused when it still matches the feed's SHA-256.
        if matches!(self.0.inner.lock().outcome, Some(Outcome::Failed { .. })) {
            self.0.inner.lock().outcome = None;
        }
        self.0.update_app()
    }

    async fn dismiss(&self) -> AppResult<()> {
        {
            let mut inner = self.0.inner.lock();
            inner.outcome = None;
            inner.note = None;
        }
        self.0.refresh();
        Ok(())
    }
}
