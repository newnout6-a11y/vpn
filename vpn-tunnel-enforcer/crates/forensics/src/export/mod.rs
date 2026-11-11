//! «Отправить логи разработчику»: the diagnostics ZIP (§3.9), streamed into a partial file next to
//! the destination with every entry redacted before it is written, then renamed over the
//! destination. Progress is pushed per entry; cancellation is checked between entries and while
//! streaming; any failure leaves the previous destination untouched.
//!
//! The export runs as the `export` operation on resource `diagnostics:export` (a second export
//! while one runs is `Conflict`), with a 10-minute work budget. The save dialog belongs to the UI:
//! it runs before [`export`] (or through `Lease::wait_for_user`), so its wait is not counted.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::watch;
use vpnte_base::types::{Level, Notice, UnixMs};
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::{FeatureKind, OperationRegistry, RunOpts, Source};
use vpnte_core::settings::Settings;

use crate::capture::Capture;
use crate::summary::SummaryCtx;

mod archive;
mod build;
mod redaction;
mod system;
mod texts;

/// Operation resource: one export at a time.
pub const RESOURCE: &str = "diagnostics:export";
/// Work budget after the save dialog (DX:148-174).
pub const BUDGET: Duration = Duration::from_secs(600);

/// Where the export's in-app notifications go (the app's notification list).
pub type NoticeSink = Arc<dyn Fn(Notice) + Send + Sync>;

/// A recovery-state document as the owning crate's validated reader returned it.
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryRead {
    /// Read and validated; written redacted.
    Trusted(Value),
    /// No such document.
    Absent,
    /// The reader failed or did not trust the file; nothing of it is exported.
    Untrusted,
}

/// One recovery-state document (kill switch / protection records, boot recovery result).
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveryArtifact {
    /// Name reported in `recovery-artifacts-status.json` (the source document).
    pub artifact: String,
    /// File name inside the archive (`killswitch-manifest.json`).
    pub file: String,
    pub read: RecoveryRead,
}

/// Everything the archive is built from. Crates this one does not depend on hand their parts
/// over as plain data (CONTRACT §2): probes (system diagnostics), engine / tunnel (the last
/// generated configs, held in memory only), firewall recovery (validated documents).
#[derive(Clone, Default)]
pub struct ExportInputs {
    pub app_version: String,
    /// `(name, version)`, e.g. `("sing-box", "1.14.4")`.
    pub engine_versions: Vec<(String, String)>,
    pub settings: Settings,
    /// The logs directory (`DataDirs::logs`): tails into `app-log.json`, engine logs in full.
    pub logs_dir: Option<PathBuf>,
    /// `system-diagnostics.json` (monitoring); `None` when it failed (skipped, logged).
    pub system_diagnostics: Option<Value>,
    /// `(engine, config)` → `runtime-<engine>.json`.
    pub engine_configs: Vec<(String, Value)>,
    pub recovery: Vec<RecoveryArtifact>,
    /// The monitoring snapshots directory (`snapshots/` of the archive).
    pub snapshots_dir: Option<PathBuf>,
    /// The capture service: live refresh of a running session and the latest session.
    pub capture: Option<Capture>,
    pub summary_ctx: SummaryCtx,
    /// Current Windows user name to mask literally; `None` = `%USERNAME%`.
    pub user_name: Option<String>,
}

/// Section of the archive being written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ExportStage {
    #[default]
    Preparing,
    Settings,
    Logs,
    System,
    Runtime,
    Recovery,
    Snapshots,
    Forensics,
    Finishing,
}

impl ExportStage {
    /// Number of stages (for a step indicator).
    pub const COUNT: u8 = 9;

    /// 1-based position.
    pub fn step(self) -> u8 {
        self as u8 + 1
    }

    /// Label for the UI (`forensics.export.stage.*`).
    pub fn label(self) -> Msg {
        Msg::new(match self {
            ExportStage::Preparing => "forensics.export.stage.preparing",
            ExportStage::Settings => "forensics.export.stage.settings",
            ExportStage::Logs => "forensics.export.stage.logs",
            ExportStage::System => "forensics.export.stage.system",
            ExportStage::Runtime => "forensics.export.stage.runtime",
            ExportStage::Recovery => "forensics.export.stage.recovery",
            ExportStage::Snapshots => "forensics.export.stage.snapshots",
            ExportStage::Forensics => "forensics.export.stage.forensics",
            ExportStage::Finishing => "forensics.export.stage.finishing",
        })
    }
}

/// Pushed while the archive is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportProgress {
    pub stage: ExportStage,
    /// Entries started so far.
    pub entries: u32,
    /// Uncompressed bytes written so far.
    pub bytes: u64,
}

/// One export.
pub struct ExportRequest {
    /// The file chosen in the save dialog (replaced only by a complete archive).
    pub dest: PathBuf,
    pub inputs: ExportInputs,
    pub source: Source,
    pub progress: watch::Sender<ExportProgress>,
    /// Receives the «Очистка диагностики не завершена» notice when a failed or cancelled export
    /// cannot remove its partial file.
    pub notices: Option<NoticeSink>,
}

/// A committed archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportResult {
    pub path: PathBuf,
    /// Entries written.
    pub entries: usize,
    /// Archive names left out (raw captures, non-text files).
    pub excluded: Vec<String>,
    /// The forensics session included, if any.
    pub forensics_session: Option<String>,
}

impl ExportResult {
    /// «Диагностика сохранена: <file>».
    pub fn saved_msg(&self) -> Msg {
        let name = self
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Msg::new("forensics.export.saved").arg("name", name)
    }
}

/// Default file name: `vpn-tunnel-enforcer-diagnostics-<UTC ISO, ':' and '.' → '-'>.zip`.
pub fn default_file_name(now: UnixMs) -> String {
    let iso = crate::etw::writer::rfc3339_ms(now).replace([':', '.'], "-");
    format!("vpn-tunnel-enforcer-diagnostics-{iso}.zip")
}

/// Builds the archive and replaces `request.dest` with it. Errors: `Conflict` (`core.ops.busy`)
/// while another export runs, `Cancelled`, `Timeout`, I/O kinds (`Permission` for an unwritable
/// destination). The destination is untouched unless the result is `Ok`.
pub async fn export(ops: &OperationRegistry, request: ExportRequest) -> AppResult<ExportResult> {
    let ExportRequest {
        dest,
        inputs,
        source,
        progress,
        notices,
    } = request;
    let opts = RunOpts {
        source,
        resource: Some(RESOURCE.into()),
        timeout: Some(BUDGET),
        ..Default::default()
    };
    ops.run(FeatureKind::Export, opts, move |lease| async move {
        let live = match inputs.capture.clone() {
            Some(capture) => {
                lease
                    .wait(async move { capture.live_refresh().await })
                    .await?
            }
            None => None,
        };
        let token = lease.token().clone();
        let target = dest.clone();
        let job = tokio::task::spawn_blocking(move || {
            build::write(&target, inputs, live, progress, notices, token)
        });
        let (partial, result) = lease.wait(job).await?.map_err(AppError::internal)??;
        lease.commit(move || partial.commit(&dest).map(|()| result))
    })
    .await
}

/// The cleanup notice of a failed or cancelled export (owner §10.6 «A», F-178).
fn cleanup_notice() -> Notice {
    Notice::new(Level::Warn, "forensics.export.cleanupFailed.title")
        .body("forensics.export.cleanupFailed.body")
}

#[cfg(test)]
mod tests;
