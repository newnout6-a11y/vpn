//! The Logs page over the backend (work package `app-settings`): the connection history with
//! explained outcomes (rows projected from `history/connections.json`; the page filters,
//! sorts and counts), CSV / JSON export through the native Save dialog, the full cleanup with a
//! per-part report, the app and engine log tails, the logs folder and the clipboard.
mod rows;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::logging::{self, LogFile};
use vpnte_core::store::{Mode, ReadOnlyReason};
use vpnte_ui::logs::{
    ArtifactReport, ClearReport, ExportFormat, LogSource, LogTail, LogsApi, LogsSnapshot,
};
use vpnte_ui::widgets::{Load, UiError};

use crate::services::Backend;
use crate::support::files::{SaveFile, save_file};
use crate::support::{blocking, detached};

/// [`LogsApi`] over the backend.
pub struct LogsService {
    shared: Arc<Shared>,
}

struct Shared {
    backend: Arc<Backend>,
    history: watch::Sender<LogsSnapshot>,
}

impl LogsService {
    /// Publishes the history at once and keeps it current until `backend.shutdown` (call it
    /// inside the tokio runtime).
    pub fn start(backend: Arc<Backend>) -> Self {
        let shared = Arc::new(Shared {
            history: watch::Sender::new(LogsSnapshot::default()),
            backend,
        });
        publish(&shared);
        tokio::spawn(pump(shared.clone()));
        Self { shared }
    }
}

/// Re-projects the rows on every history change (a session ended, a clear, an import).
async fn pump(shared: Arc<Shared>) {
    let mut changes = shared.backend.history.subscribe();
    let shutdown = shared.backend.shutdown.clone();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = changes.changed() => if changed.is_err() { break },
        }
        publish(&shared);
    }
}

/// The rows as stored, or why they could not be read (a file held open or denied at start
/// stays unreadable for this session; the next start reads it again).
fn publish(shared: &Shared) {
    let history = &shared.backend.history;
    let snapshot = match history.store().mode() {
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
    shared
        .history
        .send_replace(LogsSnapshot { history: snapshot });
}

#[async_trait::async_trait(?Send)]
impl LogsApi for LogsService {
    fn history(&self) -> watch::Receiver<LogsSnapshot> {
        self.shared.history.subscribe()
    }

    async fn reload_history(&self) -> AppResult<()> {
        // One in-process copy of the document: "reading again" re-projects it.
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

    async fn clear_all(&self) -> AppResult<ClearReport> {
        let backend = self.shared.backend.clone();
        detached(async move { Ok(clear_all(&backend).await) }).await
    }

    async fn read_log(&self, source: LogSource) -> AppResult<LogTail> {
        let dir = self.shared.backend.dirs.logs.clone();
        blocking(move || read_log(&dir, source)).await
    }

    async fn open_log_folder(&self) -> AppResult<()> {
        vpnte_winnet::shell::open_folder(&self.shared.backend.dirs.logs).await
    }

    async fn copy_text(&self, text: String) -> AppResult<()> {
        let backend = self.shared.backend.clone();
        // The blocking pool runs inside the runtime, which the clipboard's first start needs.
        blocking(move || backend.clipboard().copy(&text).map(drop)).await
    }
}

/// Every part on its own, so one failure does not keep the others (AT-00-004 / 008: a partial
/// cleanup is never shown as a full success). Packet capture is not part of this build, so
/// there is no capture to stop and no capture file of ours to delete.
async fn clear_all(backend: &Arc<Backend>) -> ClearReport {
    let history = {
        let backend = backend.clone();
        blocking(move || backend.history.clear()).await
    };
    let traffic = match backend.tunnel() {
        Ok(tunnel) => tunnel.clear_traffic_history().await,
        Err(err) => Err(err),
    };
    let artifacts = {
        let dir = backend.dirs.logs.clone();
        blocking(move || Ok(logging::clear(&dir))).await
    };
    let report = ClearReport {
        history: history.map_err(|e| UiError::from(&e)),
        traffic: traffic.map_err(|e| UiError::from(&e)),
        artifacts: artifacts
            .map(|r| ArtifactReport {
                cleared: r.cleared,
                absent: r.absent,
                failed: r.errors,
            })
            .map_err(|e| UiError::from(&e)),
    };
    tracing::info!(
        history = report.history.is_ok(),
        traffic = report.traffic.is_ok(),
        artifacts_failed = report.artifacts.as_ref().map_or(0, |a| a.failed.len()),
        "logs cleared"
    );
    report
}

/// The end of one log file: whole lines, oldest first (the logger redacted them on write).
fn read_log(dir: &std::path::Path, source: LogSource) -> AppResult<LogTail> {
    let file = match source {
        LogSource::App => LogFile::app(),
        LogSource::SingBox => LogFile::engine("sing-box"),
        LogSource::Xray => LogFile::engine("xray"),
    };
    let snap = logging::tail(dir, &file, logging::TAIL_MAX_BYTES)?;
    Ok(LogTail {
        lines: snap.content.lines().map(str::to_owned).collect(),
        exists: snap.exists,
        truncated: snap.truncated,
    })
}
