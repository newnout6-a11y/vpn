//! «Журнал» over the backend (p-logs; was the Logs page of `app-settings`): the event journal
//! (`svc_journal`) and the connection history (rows projected from `history/connections.json`;
//! the page filters, sorts and counts) pushed as one snapshot, CSV / JSON export through the
//! native Save dialog, one clear per tab, the technical logs (app.log, the engine logs of the
//! current or last session wherever it ran, the helper service's lines for this user), the
//! logs folder and the clipboard.
mod events;
mod rows;
mod sources;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::logging;
use vpnte_core::store::{Mode, ReadOnlyReason};
use vpnte_tunnel::api::CaptureKind;
use vpnte_ui::logs::{
    ArtifactReport, ExportFormat, LogSource, LogTail, LogsApi, LogsSnapshot, TailNote,
};
use vpnte_ui::widgets::{Load, UiError};

use crate::services::Backend;
use crate::support::files::{SaveFile, save_file};
use crate::support::{blocking, detached};
use crate::svc_journal::{self, Journal};

pub use sources::{
    Folders, PipeServiceLogs, ServiceAnswer, ServiceLogs, ask_service, engine_place,
};

/// [`LogsApi`] over the backend.
pub struct LogsService {
    shared: Arc<Shared>,
    service_logs: Arc<dyn ServiceLogs>,
}

struct Shared {
    backend: Arc<Backend>,
    journal: Arc<Journal>,
    folders: Folders,
    snapshot: watch::Sender<LogsSnapshot>,
    /// The capture of the session this app saw run last (the engine log to show while idle).
    last_capture: Mutex<Option<CaptureKind>>,
}

impl LogsService {
    /// Publishes the journal and the history at once and keeps them current until
    /// `backend.shutdown`; starts the journal's feeds (call it inside the tokio runtime, after
    /// `backend.tunnel` was set).
    pub fn start(backend: Arc<Backend>) -> Self {
        let folders = Folders::of(backend.dirs.logs.clone());
        Self::start_with(backend, folders, Arc::new(PipeServiceLogs))
    }

    /// [`LogsService::start`] with the folders and the service's lines given (tests).
    pub fn start_with(
        backend: Arc<Backend>,
        folders: Folders,
        service_logs: Arc<dyn ServiceLogs>,
    ) -> Self {
        let journal = Journal::open(&backend.dirs.root);
        journal.seed(&backend.history.list());
        svc_journal::spawn_feeds(journal.clone(), &backend);
        let last = sources::last_capture(&backend.history.list());
        let shared = Arc::new(Shared {
            snapshot: watch::Sender::new(LogsSnapshot::default()),
            last_capture: Mutex::new(last),
            journal,
            folders,
            backend,
        });
        publish(&shared);
        tokio::spawn(pump(shared.clone()));
        Self {
            shared,
            service_logs,
        }
    }
}

/// Re-projects on every change of the history (a session ended, a clear, an import) or of the
/// journal (an event, a clear).
async fn pump(shared: Arc<Shared>) {
    let mut history = shared.backend.history.subscribe();
    let mut journal = shared.journal.subscribe();
    let shutdown = shared.backend.shutdown.clone();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = history.changed() => if changed.is_err() { break },
            changed = journal.changed() => if changed.is_err() { break },
        }
        publish(&shared);
    }
}

/// The rows as stored, or why they could not be read (a file held open or denied at start
/// stays unreadable for this session; the next start reads it again).
fn publish(shared: &Shared) {
    let history = &shared.backend.history;
    let rows = match history.store().mode() {
        Mode::ReadOnly(ReadOnlyReason::Unreadable) => Load::Failed(UiError {
            kind: ErrorKind::Internal,
            msg: history
                .store()
                .notice()
                .unwrap_or_else(|| Msg::new("app.logs.historyUnreadable")),
        }),
        _ => {
            let lang = shared.backend.lang();
            Load::Ready(history.list().iter().map(|e| rows::row(e, lang)).collect())
        }
    };
    let events = Load::Ready(shared.journal.records().iter().map(events::row).collect());
    shared.snapshot.send_replace(LogsSnapshot {
        history: rows,
        events,
    });
}

#[async_trait::async_trait(?Send)]
impl LogsApi for LogsService {
    fn snapshot(&self) -> watch::Receiver<LogsSnapshot> {
        self.shared.snapshot.subscribe()
    }

    async fn reload_history(&self) -> AppResult<()> {
        // One in-process copy of each document: "reading again" re-projects it.
        publish(&self.shared);
        Ok(())
    }

    async fn export_history(&self, format: ExportFormat, file_name: String) -> AppResult<String> {
        let backend = self.shared.backend.clone();
        let lang = backend.lang();
        let (label, pattern) = match format {
            ExportFormat::Csv => ("app.logs.dialog.csv", "*.csv"),
            ExportFormat::Json => ("app.logs.dialog.json", "*.json"),
        };
        let req = SaveFile::new(
            Msg::new("app.logs.dialog.export"),
            file_name,
            format.extension(),
        )
        .filter(Msg::new(label), pattern);
        let Some(path) = save_file(req, lang).await? else {
            return Err(AppError::cancelled());
        };
        blocking(move || {
            let body = match format {
                ExportFormat::Csv => backend.history.export_csv(lang),
                ExportFormat::Json => backend.history.export_json(lang)?,
            };
            vpnte_core::store::write_atomic(&path, body.as_bytes()).map_err(|err| {
                let io = AppError::from(err);
                AppError::msg(io.kind, Msg::new("app.logs.exportFailed")).with_source(io)
            })?;
            Ok(path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default())
        })
        .await
    }

    async fn clear_events(&self) -> AppResult<()> {
        let journal = self.shared.journal.clone();
        detached(async move { blocking(move || journal.clear()).await }).await
    }

    async fn clear_history(&self) -> AppResult<()> {
        let backend = self.shared.backend.clone();
        detached(async move { blocking(move || backend.history.clear()).await }).await
    }

    async fn clear_technical(&self) -> AppResult<ArtifactReport> {
        let dir = self.shared.folders.user.clone();
        detached(async move {
            let report = blocking(move || Ok(logging::clear(&dir))).await?;
            Ok(ArtifactReport {
                cleared: report.cleared,
                absent: report.absent,
                failed: report.errors,
            })
        })
        .await
    }

    async fn read_log(&self, source: LogSource) -> AppResult<LogTail> {
        let (stem, (dir, note)) = match source {
            LogSource::App => ("app", (self.shared.folders.user.clone(), TailNote::None)),
            LogSource::SingBox => ("sing-box", self.engine_folder()),
            LogSource::Xray => ("xray", self.engine_folder()),
            LogSource::Service => {
                let answer = self.service_logs.read().await?;
                return Ok(sources::service_tail(answer));
            }
        };
        blocking(move || sources::read_tail(&dir, stem, note)).await
    }

    async fn open_log_folder(&self, source: LogSource) -> AppResult<()> {
        let dir = match source {
            LogSource::SingBox | LogSource::Xray => self.engine_folder().0,
            LogSource::App | LogSource::Service => self.shared.folders.user.clone(),
        };
        vpnte_winnet::shell::open_folder(&dir).await
    }

    async fn copy_text(&self, text: String) -> AppResult<()> {
        let backend = self.shared.backend.clone();
        // The blocking pool runs inside the runtime, which the clipboard's first start needs.
        blocking(move || backend.clipboard().copy(&text).map(drop)).await
    }
}

impl LogsService {
    /// The folder of the engine log to show and the calm line about it: the running session's
    /// capture, else the last one this app saw (or the newest stored session's).
    fn engine_folder(&self) -> (PathBuf, TailNote) {
        let shared = &self.shared;
        let (running, service) = match shared.backend.tunnel() {
            Ok(tunnel) => (
                tunnel.runtime_status().borrow().capture,
                tunnel.service_installed(),
            ),
            Err(_) => (None, false),
        };
        let capture = {
            let mut last = shared.last_capture.lock();
            if running.is_some() {
                *last = running;
            }
            *last
        };
        shared.folders.engine(capture, service)
    }
}
