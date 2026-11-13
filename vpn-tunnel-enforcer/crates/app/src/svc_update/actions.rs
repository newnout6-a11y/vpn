//! What the buttons do. Long work (downloads, installs, the installer start) runs in a task of
//! its own, one at a time; progress and the outcome reach the view, so the UI call returns at once.
use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_update::download::{
    DownloadError, Verified, Wanted, download, open_held, parse_sha, sha256_of,
};
use vpnte_update::feed::{EngineEntry, FileEntry};
use vpnte_update::pending::{self, INSTALLER_ARGS, Pending};
use vpnte_update::policy;
use vpnte_update::store::InstallError;
use vpnte_update::version::Version;

use super::checks::AppCheck;
use super::launch::{self, LaunchError};
use super::view::{ENGINES, newer_release, rollback};
use super::{Progress, Updates};

impl Updates {
    /// «Обновить»: the newest release's installer.
    pub(super) fn update_app(self: &Arc<Self>) -> AppResult<()> {
        let release = {
            let inner = self.inner.lock();
            let feed = inner.feed.as_ref().map(|s| &s.feed);
            feed.and_then(|f| newer_release(f, policy::app_version()))
                .cloned()
        };
        let release = release.ok_or_else(|| conflict("app.update.nothingNew"))?;
        self.run(move |this| async move { this.install_app(&release.file, release.version).await })
    }

    /// «Вернуть версию …»: the feed's rollback installer, the same way.
    pub(super) fn rollback_app(self: &Arc<Self>) -> AppResult<()> {
        let target = {
            let inner = self.inner.lock();
            let feed = inner.feed.as_ref().map(|s| &s.feed);
            feed.and_then(|f| {
                let to = rollback(f, policy::app_version())?;
                Some((f.app.stable.as_ref()?.rollback_file.clone()?, to))
            })
        };
        let (file, to) = target.ok_or_else(|| conflict("app.update.nothingNew"))?;
        self.run(move |this| async move { this.install_app(&file, to).await })
    }

    /// «Установить» on an engine offer.
    pub(super) fn install_engine(self: &Arc<Self>, id: &str) -> AppResult<()> {
        let found = {
            let inner = self.inner.lock();
            inner.feed.as_ref().and_then(|s| {
                let entry = s.feed.engine(id)?.clone();
                Some((entry, s.bytes.clone(), s.sig.clone()))
            })
        };
        let (entry, bytes, sig) = found.ok_or_else(|| conflict("app.update.nothingNew"))?;
        self.run(move |this| async move { this.install_engine_from(entry, bytes, sig).await })
    }

    /// Runs `job` in its own task unless another one runs (`Conflict`); its error becomes the
    /// note.
    fn run<F, Fut>(self: &Arc<Self>, job: F) -> AppResult<()>
    where
        F: FnOnce(Arc<Self>) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), Msg>> + Send,
    {
        {
            let mut inner = self.inner.lock();
            if inner.busy {
                return Err(conflict("app.update.busy"));
            }
            inner.busy = true;
            inner.note = None;
        }
        self.refresh();
        let this = self.clone();
        tokio::spawn(async move {
            let result = job(this.clone()).await;
            {
                let mut inner = this.inner.lock();
                inner.busy = false;
                inner.progress = None;
            }
            match result {
                Ok(()) => this.refresh(),
                Err(msg) => this.note(msg, true),
            }
        });
        Ok(())
    }

    /// Download (or reuse), write `pending.json`, start the installer as the user. The app is
    /// then asked to exit by the installer's own gate (`--setup await-shutdown`).
    async fn install_app(&self, file: &FileEntry, to: Version) -> Result<(), Msg> {
        let what = format!("VPN Tunnel Enforcer {to}");
        let verified = self.fetch(file, &what).await?;
        let pending = Pending {
            from: policy::app_version(),
            to,
            at: now_ms(),
            installer: verified.path.clone(),
        };
        pending::write(&self.updates_dir, &pending)
            .map_err(|_| Msg::new("app.update.fileError"))?;
        match launch::run_unelevated(&verified.path, &INSTALLER_ARGS) {
            Ok(()) => {
                tracing::info!(%to, "installer started");
                let mut inner = self.inner.lock();
                inner.held = Some(verified.file);
                // The installer now asks this app to exit; the offer has done its job.
                inner.hidden_app = true;
                Ok(())
            }
            Err(err) => {
                tracing::warn!(%err, "installer not started");
                let _ = pending::take(&self.updates_dir, policy::app_version());
                Err(match err {
                    LaunchError::NoShell => Msg::new("app.update.noShell"),
                    LaunchError::Failed(_) => Msg::new("app.update.launchFailed"),
                })
            }
        }
    }

    /// Download the engine's archive, then the store installs it (with our config checks).
    async fn install_engine_from(
        self: Arc<Self>,
        entry: EngineEntry,
        bytes: Vec<u8>,
        sig: String,
    ) -> Result<(), Msg> {
        let name = engine_name(&entry.id);
        let archive = FileEntry {
            name: format!("{}-{}.zip", entry.id, entry.version),
            size: entry.archive.size,
            sha256: entry.archive.sha256.clone(),
            urls: vec![entry.archive.url.clone()],
        };
        let verified = self
            .fetch(&archive, &format!("{name} {}", entry.version))
            .await?;
        let check = AppCheck(self.backend.clone());
        match self
            .store
            .install(&entry, &bytes, &sig, verified, &check)
            .await
        {
            Ok(done) => {
                let restart = Msg::new("app.update.engineInstalled")
                    .arg("name", name)
                    .arg("version", done.version);
                self.engine_switched(&entry.id, restart);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(engine = %entry.id, %err, "engine not installed");
                Err(install_msg(&err, name))
            }
        }
    }

    /// The verified file of `file`: a copy downloaded ahead (or kept) when it still matches,
    /// else a download through the session first, with progress.
    async fn fetch(&self, file: &FileEntry, what: &str) -> Result<Verified, Msg> {
        if let Some(kept) = self.kept(file) {
            return Ok(kept);
        }
        self.inner.lock().progress = Some(Progress {
            what: what.to_owned(),
            done: 0,
            total: file.size,
        });
        self.refresh();
        let (tx, mut rx) = watch::channel(0u64);
        let wanted = Wanted {
            urls: &file.urls,
            size: file.size,
            sha256: &file.sha256,
            name: &file.name,
        };
        let ways = self.ways();
        let cancel = self.backend.shutdown.child_token();
        let transfer = download(&wanted, &ways, &self.updates_dir, Some(&tx), &cancel);
        tokio::pin!(transfer);
        // A chunk arrives every few milliseconds: the view follows at most four times a second.
        let mut shown = std::time::Instant::now();
        let result = loop {
            tokio::select! {
                result = &mut transfer => break result,
                Ok(()) = rx.changed() => {
                    let done = *rx.borrow_and_update();
                    if let Some(p) = self.inner.lock().progress.as_mut() {
                        p.done = done;
                    }
                    if shown.elapsed() >= std::time::Duration::from_millis(250) {
                        shown = std::time::Instant::now();
                        self.refresh();
                    }
                }
            }
        };
        result.map_err(|err| {
            tracing::warn!(%err, "download failed");
            download_msg(&err)
        })
    }

    /// A file already in `updates\` with the feed's SHA-256, held from now on.
    fn kept(&self, file: &FileEntry) -> Option<Verified> {
        if file.name.contains(['/', '\\', ':']) || file.name.starts_with('.') {
            return None;
        }
        let path = self.updates_dir.join(&file.name);
        let mut held = open_held(&path).ok()?;
        let matches = sha256_of(&mut held).ok()? == parse_sha(&file.sha256)?;
        matches.then_some(Verified { path, file: held })
    }

    /// «Скачивать заранее»: after a check, the newest installer is fetched in the background
    /// (never installed without the click).
    pub(super) fn download_ahead(self: Arc<Self>) {
        if !self.doc.read(|d| d.download_ahead) {
            return;
        }
        let release = {
            let inner = self.inner.lock();
            let feed = inner.feed.as_ref().map(|s| &s.feed);
            feed.and_then(|f| newer_release(f, policy::app_version()))
                .cloned()
        };
        let Some(release) = release else { return };
        if self.kept(&release.file).is_some() {
            return;
        }
        let _ = self.run(move |this| async move {
            let what = format!("VPN Tunnel Enforcer {}", release.version);
            this.fetch(&release.file, &what).await.map(drop)
        });
    }
}

fn conflict(key: &'static str) -> AppError {
    AppError::conflict(Msg::new(key))
}

/// The display name of engine `id`.
pub(super) fn engine_name(id: &str) -> &'static str {
    ENGINES
        .iter()
        .find(|(i, _)| *i == id)
        .map_or("engine", |(_, name)| name)
}

fn download_msg(err: &DownloadError) -> Msg {
    Msg::new(match err {
        DownloadError::Unreachable | DownloadError::Cancelled => "app.update.downloadFailed",
        DownloadError::TooLarge | DownloadError::Mismatch => "app.update.downloadInvalid",
        DownloadError::Io(_) => "app.update.fileError",
    })
}

fn install_msg(err: &InstallError, name: &str) -> Msg {
    match err {
        InstallError::Unknown(_) | InstallError::NotAllowed(_) => {
            Msg::new("app.update.engineNotAllowed").arg("name", name)
        }
        InstallError::Feed | InstallError::Member(_) => Msg::new("app.update.downloadInvalid"),
        InstallError::VersionMismatch { got, want } => Msg::new("app.update.engineVersion")
            .arg("name", name)
            .arg("got", got)
            .arg("want", want),
        InstallError::ConfigRefused(why) => Msg::new("app.update.engineRefused")
            .arg("name", name)
            .arg("reason", why),
        InstallError::Io(_) => Msg::new("app.update.fileError"),
    }
}
