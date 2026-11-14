//! The capture service: every transition runs under one async mutex, the status is pushed on a
//! `watch` channel, app events go to the running session's `app-events.ndjson`.
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::now_ms;

use super::manifest::{EtwState, PktmonState, SessionManifest};
use super::pktmon;
use super::status::{self, CaptureStatus, Health};
use super::store::{self, ClearReport, SessionEntry};
use super::system::{Etw, System};
use super::{
    APP_EVENTS_MAX, CaptureConfig, CaptureError, ForensicEvent, LIVE_COUNTERS_FILE, RecoveryReport,
    START_FAILED, SessionCtx, StopReason,
};

/// Status refresh period while a session runs.
const TICK: Duration = Duration::from_secs(5);
/// ETW state of a consumer whose processing ended on its own while the session ran.
pub(super) const ETW_ENDED: &str = "ETW processing ended";

/// One capture session in memory (its manifest is the on-disk copy).
pub(super) struct Session {
    pub(super) manifest: SessionManifest,
    pub(super) dir: PathBuf,
    pub(super) etw: Option<Box<dyn Etw>>,
    /// We started (or may have started) the pktmon capture and the marker is on disk.
    pub(super) owns_pktmon: bool,
    pub(super) quota_reached: bool,
}

pub(super) enum State {
    Idle,
    Running(Session),
    /// The stop was not confirmed: pktmon may still be writing (ETW is already stopped).
    StopUnconfirmed(Session),
    Stopped(Session),
}

pub(super) struct Inner {
    pub(super) state: State,
    /// Context of the last start, for `restart` (TF:1147-1161).
    pub(super) last_ctx: Option<SessionCtx>,
    pub(super) ticker: Option<CancellationToken>,
    /// Bytes of the sessions on disk other than the one in `state`, rescanned on transitions only
    /// so the 5 s ticks list one directory, not the whole root (B-30).
    pub(super) stored_bytes: u64,
}

/// Open `app-events.ndjson` of the running session.
pub(super) struct AppEvents {
    pub(super) file: std::fs::File,
    pub(super) rows: u32,
    pub(super) dropped: u64,
}

pub(super) struct Shared {
    pub(super) root: PathBuf,
    pub(super) cfg: watch::Receiver<CaptureConfig>,
    pub(super) system: Arc<dyn System>,
    pub(super) inner: tokio::sync::Mutex<Inner>,
    pub(super) status: watch::Sender<CaptureStatus>,
    pub(super) events: parking_lot::Mutex<Option<AppEvents>>,
}

/// The capture service. Cheap to clone.
#[derive(Clone)]
pub struct Capture {
    shared: Arc<Shared>,
}

impl Capture {
    /// `root` is normally [`store::default_root`]; `cfg` follows the settings.
    pub fn new(
        root: PathBuf,
        cfg: watch::Receiver<CaptureConfig>,
        system: Arc<dyn System>,
    ) -> Self {
        let status = CaptureStatus {
            enabled: cfg.borrow().enabled,
            max_size_mb: cfg.borrow().max_size_mb,
            ..Default::default()
        };
        Self {
            shared: Arc::new(Shared {
                root,
                cfg,
                system,
                inner: tokio::sync::Mutex::new(Inner {
                    state: State::Idle,
                    last_ctx: None,
                    ticker: None,
                    stored_bytes: 0,
                }),
                status: watch::channel(status).0,
                events: parking_lot::Mutex::new(None),
            }),
        }
    }

    /// The forensics root.
    pub fn root(&self) -> &Path {
        &self.shared.root
    }

    /// Pushed status (refreshed on every transition and every 5 s while a session runs).
    pub fn status(&self) -> watch::Receiver<CaptureStatus> {
        self.shared.status.subscribe()
    }

    /// Starts a session for a protection session. Disabled: `Ok` with `enabled: false`;
    /// already running: the current status. Call once protection is established, not on engine
    /// auto-restarts (B-09).
    pub async fn start(&self, ctx: SessionCtx) -> Result<CaptureStatus, CaptureError> {
        let shared = self.shared.clone();
        detached(async move {
            let mut inner = shared.inner.lock().await;
            inner.last_ctx = Some(ctx.clone());
            let result = shared.start_locked(&mut inner, ctx).await;
            spawn_ticker(&shared, &mut inner);
            shared.publish(&mut inner);
            result.map(|()| shared.status.borrow().clone())
        })
        .await
    }

    /// Ends the session. A protection end (`VpnStop`, `Shutdown`, `KillSwitch`, other) forgets the
    /// context; manual reasons keep it for [`restart`](Self::restart). Not confirmed:
    /// [`CaptureError::StopUnconfirmed`] and the status stays `cleanup_pending`; call again.
    pub async fn stop(&self, reason: StopReason) -> Result<CaptureStatus, CaptureError> {
        let shared = self.shared.clone();
        detached(async move {
            let mut inner = shared.inner.lock().await;
            if !matches!(reason, StopReason::ManualRestart | StopReason::ManualClear) {
                inner.last_ctx = None;
            }
            let result = shared.stop_locked(&mut inner, reason.as_str()).await;
            shared.publish(&mut inner);
            result.map(|()| shared.status.borrow().clone())
        })
        .await
    }

    /// «Перезапустить сбор»: stop, then start again with the last context (nothing to start
    /// without one).
    pub async fn restart(&self) -> Result<CaptureStatus, CaptureError> {
        let shared = self.shared.clone();
        detached(async move {
            let mut inner = shared.inner.lock().await;
            let reason = StopReason::ManualRestart;
            let mut result = shared.stop_locked(&mut inner, reason.as_str()).await;
            if result.is_ok()
                && let Some(ctx) = inner.last_ctx.clone()
            {
                result = shared.start_locked(&mut inner, ctx).await;
            }
            spawn_ticker(&shared, &mut inner);
            shared.publish(&mut inner);
            result.map(|()| shared.status.borrow().clone())
        })
        .await
    }

    /// Elevated app start, before any new capture and whatever the setting: stops a pktmon
    /// capture our marker or an old app's hint says may still run (AT-08-004; a hint only once),
    /// closes manifests a crash left "running" and reclaims an orphaned ETW session. Never blocks
    /// later starts; an unconfirmed stop becomes the `cleanup_pending` session. `legacy_electron`
    /// is the old Electron data dir (hints only: nothing in them is executed or trusted).
    pub async fn recover_on_boot(&self, legacy_electron: Option<&Path>) -> RecoveryReport {
        let shared = self.shared.clone();
        let legacy_electron = legacy_electron.map(Path::to_path_buf);
        detached(async move {
            let mut inner = shared.inner.lock().await;
            let report = shared
                .recover_locked(&mut inner, legacy_electron.as_deref())
                .await;
            shared.publish(&mut inner);
            report
        })
        .await
    }

    /// Appends an app event to the running session (≤ [`APP_EVENTS_MAX`] rows, then counted).
    /// Events of the engine teardown arrive after the capture stopped and are dropped (B-33).
    pub fn record(&self, ev: ForensicEvent) {
        #[derive(Serialize)]
        struct Row<'a> {
            timestamp: String,
            source: &'static str,
            #[serde(flatten)]
            ev: &'a ForensicEvent,
        }
        let mut guard = self.shared.events.lock();
        let Some(log) = guard.as_mut() else {
            return;
        };
        if log.rows >= APP_EVENTS_MAX {
            log.dropped += 1;
            return;
        }
        let row = Row {
            timestamp: crate::etw::writer::rfc3339_ms(now_ms()),
            source: ev.kind.source(),
            ev: &ev,
        };
        let written = serde_json::to_vec(&row).ok().is_some_and(|mut line| {
            line.push(b'\n');
            log.file.write_all(&line).is_ok()
        });
        if written {
            log.rows += 1;
        } else {
            log.dropped += 1;
        }
    }

    /// «Очистить диагностику»: stops a running session (`manual diagnostics artifact clear`) and
    /// deletes every session directory. Refused while a stop is unconfirmed.
    pub async fn clear(&self) -> Result<ClearReport, CaptureError> {
        let shared = self.shared.clone();
        detached(async move {
            let mut inner = shared.inner.lock().await;
            let reason = StopReason::ManualClear;
            let result = shared.stop_locked(&mut inner, reason.as_str()).await;
            let report = match result {
                Ok(()) => {
                    inner.state = State::Idle;
                    // Gigabytes of captures: deleting them is no work for a runtime thread.
                    let root = shared.root.clone();
                    tokio::task::spawn_blocking(move || store::remove_sessions(&root))
                        .await
                        .map_err(|e| CaptureError::Io(io::Error::other(e)))
                }
                Err(e) => Err(e),
            };
            shared.publish(&mut inner);
            report
        })
        .await
    }

    /// Recomputes the status now (the ticker does it every 5 s while a session runs).
    pub async fn refresh(&self) {
        let mut inner = self.shared.inner.lock().await;
        self.shared.publish(&mut inner);
    }

    /// Fresh artefacts of a running session for a diagnostics export: `pktmon counters --json` →
    /// `pktmon-live-counters.json` and `network-live.json` / `sockets-live.json` (the ETW writer
    /// flushes every 250 ms anyway). Never copies the ETL (B-26). Returns the session directory, or
    /// `None` when nothing runs. Best effort: failures are logged.
    pub async fn live_refresh(&self) -> Option<PathBuf> {
        let inner = self.shared.inner.lock().await;
        let State::Running(s) = &inner.state else {
            return None;
        };
        if s.manifest.pktmon == PktmonState::Running {
            let out = self
                .shared
                .system
                .pktmon(pktmon::counters_args(false), pktmon::COLLECT_TIMEOUT)
                .await;
            match out {
                Ok(o) if o.success() => {
                    if let Err(e) = std::fs::write(s.dir.join(LIVE_COUNTERS_FILE), &o.stdout) {
                        tracing::warn!("cannot write live pktmon counters: {e}");
                    }
                }
                Ok(o) => tracing::warn!("pktmon counters failed: {}", o.detail()),
                Err(e) => tracing::warn!("pktmon counters failed: {e}"),
            }
        }
        self.shared.system.snapshot(s.dir.clone(), "live").await;
        Some(s.dir.clone())
    }

    /// Every session on disk, oldest first (for the export and the size display). Blocking.
    pub fn sessions(&self) -> Vec<SessionEntry> {
        store::list_sessions(&self.shared.root)
    }
}

impl State {
    fn session(&self) -> Option<&Session> {
        match self {
            State::Idle => None,
            State::Running(s) | State::StopUnconfirmed(s) | State::Stopped(s) => Some(s),
        }
    }
}

impl Shared {
    /// Publishes after a transition, rescanning the sizes of the other sessions first.
    fn publish(&self, inner: &mut Inner) {
        let current = inner.state.session().map(|s| s.dir.as_path());
        inner.stored_bytes = store::total_bytes(&self.root, current);
        self.status.send_replace(self.build_status(inner));
    }

    fn build_status(&self, inner: &Inner) -> CaptureStatus {
        let cfg = self.cfg.borrow().clone();
        let session = inner.state.session();
        let running = matches!(inner.state, State::Running(_) | State::StopUnconfirmed(_));
        let files = session.map_or_else(Vec::new, |s| store::list_artifacts(&s.dir));
        let base = CaptureStatus {
            enabled: cfg.enabled,
            max_size_mb: cfg.max_size_mb,
            total_bytes: inner.stored_bytes + files.iter().map(|f| f.size).sum::<u64>(),
            ..Default::default()
        };
        // A stopped session is not surfaced while capture is off (trafficForensics.test.ts).
        let Some(s) = session.filter(|_| cfg.enabled || running) else {
            return base;
        };
        let m = &s.manifest;
        let etw = match (&m.etw, &s.etw) {
            (EtwState::Running, Some(e)) if !e.is_running() => EtwState::Failed(ETW_ENDED.into()),
            (state, _) => state.clone(),
        };
        let digest = s
            .etw
            .as_ref()
            .map(|e| e.digest())
            .or_else(|| m.etw_stats.as_ref().map(|st| st.digest.clone()));
        let loss = s
            .etw
            .as_ref()
            .and_then(|e| e.loss())
            .or_else(|| m.etw_stats.as_ref().and_then(|st| st.loss));
        let size_of = |name: &str| files.iter().find(|f| f.name == name).map(|f| f.size);
        let etl_bytes = size_of(pktmon::ETL_FILE);
        let (warming_up, only_lifecycle, warnings) =
            status::liveness_and_warnings(&status::HealthInput {
                enabled: cfg.enabled,
                etw: &etw,
                digest: digest.as_ref(),
                loss,
                pktmon: &m.pktmon,
                etl_bytes,
                started_at: Some(m.started_at),
                now: now_ms(),
                quota_reached: s.quota_reached,
            });
        let last_error = if let PktmonState::StopUnconfirmed(_) = m.pktmon {
            Some(Msg::new("forensics.capture.error.stopUnconfirmed"))
        } else if m.stop_reason.as_deref() == Some(START_FAILED) {
            Some(Msg::new("forensics.capture.error.startFailed"))
        } else {
            None
        };
        CaptureStatus {
            running,
            cleanup_pending: matches!(inner.state, State::StopUnconfirmed(_)),
            session_id: Some(m.session_id.clone()),
            session_dir: Some(s.dir.clone()),
            mode: m.mode,
            target: m.target.clone(),
            started_at: Some(m.started_at),
            stopped_at: m.stopped_at,
            max_size_mb: m.max_size_mb,
            stop_reason: m.stop_reason.clone(),
            last_error,
            pktmon: m.pktmon.clone(),
            etw,
            digest,
            health: Health {
                artifact_count: files.len(),
                etl_bytes: etl_bytes.unwrap_or(0),
                events_bytes: size_of(crate::etw::EVENTS_FILE).unwrap_or(0),
                etw_warming_up: warming_up,
                etw_only_lifecycle: only_lifecycle,
            },
            warnings,
            ..base
        }
    }
}

/// Refreshes the status every [`TICK`] while a session runs (skips a tick while a transition holds
/// the lock).
fn spawn_ticker(shared: &Arc<Shared>, inner: &mut Inner) {
    if inner.ticker.is_some() || !matches!(inner.state, State::Running(_)) {
        return;
    }
    let token = CancellationToken::new();
    inner.ticker = Some(token.clone());
    let weak = Arc::downgrade(shared);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(TICK);
        tick.tick().await;
        loop {
            tokio::select! {
                () = token.cancelled() => break,
                _ = tick.tick() => {}
            }
            let Some(shared) = weak.upgrade() else { break };
            if let Ok(inner) = shared.inner.try_lock() {
                shared.status.send_replace(shared.build_status(&inner));
            }
        }
    });
}

/// Runs a transition on its own task: a caller that gives up (the shutdown timeout, a closed
/// page) must not cancel it halfway, losing the session while pktmon still writes.
async fn detached<F>(transition: F) -> F::Output
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    match tokio::spawn(transition).await {
        Ok(out) => out,
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            // Only a runtime shutting down cancels the task; the caller goes down with it.
            Err(_) => std::future::pending().await,
        },
    }
}
