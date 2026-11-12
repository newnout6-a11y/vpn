//! «ZIP»: the diagnostics archive. The Save dialog asks where (`forensics.export.dialogTitle`,
//! `vpn-tunnel-enforcer-diagnostics-<timestamp>.zip`), then the forensics export packs it as
//! one operation of the registry (single flight app-wide, resource `diagnostics:export`) while
//! its stages are published in `state.export`. The archive is written next to the destination
//! and renamed over it only when complete; the token stops it (`Cancelled`, shown silently).
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::Source;
use vpnte_forensics::export::{
    self, ExportInputs, ExportProgress, ExportRequest, ExportStage, NoticeSink, RESOURCE,
};
use vpnte_ui::maintenance::{ExportDone, ExportView};

use super::{Shared, refused};
use crate::support::detached;
use crate::support::files::{SaveFile, StartFolder, save_file};

/// Asks for the destination and packs the archive; `Ok(None)` = the dialog was dismissed.
pub(crate) async fn run(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportDone>> {
    // One export app-wide: refused before the user is asked where to save it.
    if shared.backend.ops.is_busy(RESOURCE) || shared.state.borrow().export.running {
        return Err(refused("core.ops.busy"));
    }
    let backend = &shared.backend;
    let lang = backend.lang();
    let file = SaveFile::new(
        Msg::new("forensics.export.dialogTitle"),
        export::default_file_name(now_ms()),
        "zip",
    )
    .filter(Msg::new("forensics.export.zipFilter"), "*.zip")
    .in_folder(StartFolder::Desktop);
    let Some(dest) = save_file(file, lang).await? else {
        return Ok(None);
    };
    // Its own task: a page that goes away without cancelling does not stop the archive.
    detached(pack(shared, dest, cancel)).await.map(Some)
}

async fn pack(
    shared: Arc<Shared>,
    dest: PathBuf,
    cancel: CancellationToken,
) -> AppResult<ExportDone> {
    let (progress, mut stages) = watch::channel(ExportProgress::default());
    // The only notice the export sends: its temporary files could not be removed.
    let cleanup_failed = Arc::new(AtomicBool::new(false));
    let flag = cleanup_failed.clone();
    let notices: NoticeSink = Arc::new(move |_| flag.store(true, Ordering::Relaxed));
    let request = ExportRequest {
        dest,
        inputs: inputs(&shared),
        source: Source::Ui,
        progress,
        notices: Some(notices),
    };
    publish(&shared, Some(ExportProgress::default()));
    let state = shared.clone();
    let forward = tokio::spawn(async move {
        while stages.changed().await.is_ok() {
            let stage = *stages.borrow_and_update();
            publish(&state, Some(stage));
        }
    });
    let result = tokio::select! {
        () = cancel.cancelled() => Err(AppError::cancelled()),
        result = export::export(&shared.backend.ops, request) => result,
    };
    forward.abort();
    let _ = forward.await;
    publish(&shared, None);
    let done = result?;
    tracing::info!(
        entries = done.entries,
        excluded = done.excluded.len(),
        "maintenance: diagnostics archive written"
    );
    Ok(ExportDone {
        path: done.path.display().to_string(),
        cleanup_failed: cleanup_failed.load(Ordering::Relaxed),
    })
}

/// What goes into the archive besides the logs: settings, the last system report, snapshots.
fn inputs(shared: &Shared) -> ExportInputs {
    let backend = &shared.backend;
    ExportInputs {
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        settings: backend.settings.snapshot(),
        logs_dir: Some(backend.dirs.logs.clone()),
        system_diagnostics: shared.last_report.lock().clone(),
        snapshots_dir: Some(vpnte_probes::diagnostics::snapshot::dir(&backend.dirs.root)),
        ..ExportInputs::default()
    }
}

fn publish(shared: &Shared, progress: Option<ExportProgress>) {
    let view = export_view(progress);
    shared.state.send_if_modified(|s| {
        let modified = s.export != view;
        s.export = view;
        modified
    });
}

/// The progress line: the stage being packed and the share of stages already done.
pub(crate) fn export_view(progress: Option<ExportProgress>) -> ExportView {
    match progress {
        None => ExportView::default(),
        Some(p) => ExportView {
            running: true,
            progress: Some(
                f64::from(p.stage.step().saturating_sub(1)) / f64::from(ExportStage::COUNT),
            ),
            stage: Some(p.stage.label()),
        },
    }
}
