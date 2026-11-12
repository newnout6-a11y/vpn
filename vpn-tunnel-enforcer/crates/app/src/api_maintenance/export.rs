//! «ZIP»: the diagnostics archive. The Save dialog asks where (`forensics.export.dialogTitle`,
//! `vpn-tunnel-enforcer-diagnostics-<timestamp>.zip`), then the forensics export packs it as
//! one operation of the registry (single flight app-wide, resource `diagnostics:export`) while
//! its stages are published in `state.export`. The archive is written next to the destination
//! and renamed over it only when complete; the token stops it (`Cancelled`, shown silently).
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::tweaks::{self, Feature};
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::Source;
use vpnte_core::settings::Settings;
use vpnte_core::store::{Document, Mode, Store};
use vpnte_engine::{singbox_process, xray_process};
use vpnte_forensics::capture::{
    Capture, CaptureConfig, CapturePrefs, WindowsSystem, store as capture_store,
};
use vpnte_forensics::export::{
    self, ExportInputs, ExportProgress, ExportRequest, ExportStage, NoticeSink, RESOURCE,
    RecoveryArtifact, RecoveryRead,
};
use vpnte_tunnel::runtime::EngineFeed;
use vpnte_ui::maintenance::{ExportDone, ExportView};

use super::{Shared, refused};
use crate::services::Engines;
use crate::support::detached;
use crate::support::files::{SaveFile, StartFolder, save_file};

/// What only the tunnel side holds for the archive (pages built without a tunnel have none).
pub(crate) struct ExportSources {
    pub feed: EngineFeed,
    pub journal: Arc<tweaks::Journal>,
}

/// One export from the first click to the end of packing (the Save dialog included); released
/// on every exit path, a dismissed dialog and an error too.
pub(crate) struct ExportClaim(Arc<Shared>);

impl ExportClaim {
    pub(crate) fn take(shared: Arc<Shared>) -> Option<Self> {
        shared
            .export_claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self(shared))
    }
}

impl Drop for ExportClaim {
    fn drop(&mut self) {
        self.0.export_claim.store(false, Ordering::Release);
    }
}

/// Runs `work` in its own task that holds `claim` until the work ends: a page that goes away
/// without cancelling stops neither the archive nor the claim, so a second export stays refused
/// until this one is done (before the pack registers its operation, nothing else marks it busy).
pub(crate) async fn in_background<T, Fut>(claim: ExportClaim, work: Fut) -> AppResult<T>
where
    T: Send + 'static,
    Fut: Future<Output = AppResult<T>> + Send + 'static,
{
    detached(async move {
        let _claim = claim;
        work.await
    })
    .await
}

/// Asks for the destination and packs the archive; `Ok(None)` = the dialog was dismissed.
pub(crate) async fn run(
    shared: Arc<Shared>,
    cancel: CancellationToken,
) -> AppResult<Option<ExportDone>> {
    // One export app-wide: refused before the user is asked where to save it. The claim also
    // covers the Save dialog: an owner-less dialog leaves the window clickable, and a second click
    // must not open a second dialog only to be refused after a file was chosen.
    if shared.backend.ops.is_busy(RESOURCE) || shared.state.borrow().export.running {
        return Err(refused("core.ops.busy"));
    }
    let Some(claim) = ExportClaim::take(shared.clone()) else {
        return Err(refused("core.ops.busy"));
    };
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
    in_background(claim, pack(shared, dest, cancel))
        .await
        .map(Some)
}

pub(crate) async fn pack(
    shared: Arc<Shared>,
    dest: PathBuf,
    cancel: CancellationToken,
) -> AppResult<ExportDone> {
    // Running from the first moment, and Cancel works from it: gathering the inputs runs the
    // engines' `version` (each bounded, sing-box 10 s and Xray 5 s, in parallel).
    publish(&shared, Some(ExportProgress::default()));
    let inputs = tokio::select! {
        biased;
        () = cancel.cancelled() => None,
        inputs = inputs(&shared) => Some(inputs),
    };
    let Some(inputs) = inputs else {
        publish(&shared, None);
        return Err(AppError::cancelled());
    };
    let (progress, mut stages) = watch::channel(ExportProgress::default());
    // The only notice the export sends: its temporary files could not be removed.
    let cleanup_failed = Arc::new(AtomicBool::new(false));
    let flag = cleanup_failed.clone();
    let notices: NoticeSink = Arc::new(move |_| flag.store(true, Ordering::Relaxed));
    let request = ExportRequest {
        dest,
        inputs,
        source: Source::Ui,
        progress,
        notices: Some(notices),
    };
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

/// What goes into the archive besides the logs: settings, the last system report, the engines'
/// versions and the last engine config (redacted by the export's config policy), the recovery
/// state, snapshots, and the newest stored capture session if an earlier run left one.
async fn inputs(shared: &Shared) -> ExportInputs {
    let backend = &shared.backend;
    let settings = backend.settings.snapshot();
    let sources = shared.sources.as_ref();
    let mut recovery = vec![
        stored("protection", &backend.protection),
        stored("legacy-network-cleanup", &backend.cleanup),
    ];
    recovery.extend(sources.map(|s| journal(&s.journal)));
    ExportInputs {
        app_version: env!("CARGO_PKG_VERSION").to_owned(),
        engine_versions: engine_versions(&backend.engines).await,
        capture: capture(&settings),
        settings,
        logs_dir: Some(backend.dirs.logs.clone()),
        system_diagnostics: shared.last_report.lock().clone(),
        engine_configs: sources.map(|s| engine_configs(&s.feed)).unwrap_or_default(),
        recovery,
        snapshots_dir: Some(vpnte_probes::diagnostics::snapshot::dir(&backend.dirs.root)),
        ..ExportInputs::default()
    }
}

/// `1.14.4` per engine, through the engine crate's pinned one-shot `version` runs; `missing`
/// without the file, `failed (<why>)` when the run did not answer.
pub(crate) async fn engine_versions(engines: &Engines) -> Vec<(String, String)> {
    let (singbox, xray) = tokio::join!(
        version_of(
            &engines.singbox,
            singbox_process::engine_version(&engines.singbox)
        ),
        version_of(&engines.xray, xray_process::engine_version(&engines.xray)),
    );
    vec![("sing-box".into(), singbox), ("xray".into(), xray)]
}

async fn version_of(exe: &Path, run: impl Future<Output = io::Result<(u16, u16, u16)>>) -> String {
    if !exe.is_file() {
        return "missing".into();
    }
    match run.await {
        Ok((major, minor, patch)) => format!("{major}.{minor}.{patch}"),
        Err(e) => format!("failed ({e})"),
    }
}

/// The config of the last core started in this run (held in memory only).
pub(crate) fn engine_configs(feed: &EngineFeed) -> Vec<(String, Value)> {
    let Some(bytes) = feed.last_config() else {
        return Vec::new();
    };
    match serde_json::from_slice(&bytes) {
        Ok(config) => vec![("sing-box".into(), config)],
        Err(e) => {
            tracing::warn!(error = %e, "diagnostics export: engine config not JSON, skipped");
            Vec::new()
        }
    }
}

/// A recovery document as its store holds it: a read-only store (newer, corrupt, unreadable)
/// is not trusted, a file never written is absent.
pub(crate) fn stored<T: Document + Serialize>(
    artifact: &str,
    store: &Store<T>,
) -> RecoveryArtifact {
    let read = match store.mode() {
        Mode::ReadOnly(_) => RecoveryRead::Untrusted,
        Mode::Writable if !store.path().is_file() => RecoveryRead::Absent,
        Mode::Writable => store
            .read(|doc| serde_json::to_value(doc))
            .map_or(RecoveryRead::Untrusted, RecoveryRead::Trusted),
    };
    RecoveryArtifact {
        artifact: artifact.into(),
        file: T::FILE.rsplit('/').next().unwrap_or(T::FILE).into(),
        read,
    }
}

/// Which system tweaks are still held and how many changes each holds. No values or targets:
/// a baseline can be the user's own proxy with its credentials.
pub(crate) fn journal(journal: &tweaks::Journal) -> RecoveryArtifact {
    const FEATURES: [Feature; 7] = [
        Feature::SoftProxy,
        Feature::SoftEnv,
        Feature::DevGit,
        Feature::DevGradle,
        Feature::DevStudio,
        Feature::BrowserWebRtc,
        Feature::LocationPrivacy,
    ];
    let read = if journal.notice().is_some() {
        RecoveryRead::Untrusted
    } else {
        let held: Vec<Value> = FEATURES
            .iter()
            .map(|&feature| (feature, journal.records(feature).len()))
            .filter(|(_, n)| *n > 0)
            .map(|(feature, n)| json!({ "feature": feature, "records": n }))
            .collect();
        RecoveryRead::Trusted(json!({ "held": held }))
    };
    RecoveryArtifact {
        artifact: "tweak-journal".into(),
        file: "tweaks.json".into(),
        read,
    }
}

/// The capture root as an idle capture: this build starts no capture (a service-hosted
/// feature), but a session an earlier run stored there is packed with its summary.
fn capture(settings: &Settings) -> Option<Capture> {
    let root = capture_store::default_root()?;
    let config = CaptureConfig::new(settings, &CapturePrefs::default());
    Some(Capture::new(
        root,
        watch::channel(config).1,
        Arc::new(WindowsSystem),
    ))
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
