//! Session transitions, always under the capture lock: start (manifest and marker written before
//! pktmon is launched, then ETW and the start snapshot), the confirmed stop and the best-effort
//! collection after it.
use std::io::{self, Write};
use std::path::Path;

use vpnte_base::types::now_ms;

use super::manifest::{self, EtwState, LEGACY_DONE_FILE, PktmonState, SessionManifest};
use super::pktmon::{self, Outcome};
use super::service::{AppEvents, ETW_ENDED, Inner, Session, Shared, State};
use super::{
    APP_EVENTS_FILE, CaptureError, RECOVERED_AT_STARTUP, RecoveryReport, START_FAILED,
    STOP_ERRORS_FILE, SessionCtx, store,
};

impl Shared {
    pub(super) async fn start_locked(
        &self,
        inner: &mut Inner,
        ctx: SessionCtx,
    ) -> Result<(), CaptureError> {
        let cfg = self.cfg.borrow().clone();
        if !cfg.enabled {
            return Ok(());
        }
        if cfg.consent_at.is_none() {
            return Err(CaptureError::ConsentRequired);
        }
        match std::mem::replace(&mut inner.state, State::Idle) {
            State::Running(s) => {
                inner.state = State::Running(s);
                return Ok(());
            }
            // Never start over a provider whose stop was not confirmed (old: zombie-recovery).
            State::StopUnconfirmed(s) => {
                let reason = s.manifest.stop_reason.clone().unwrap_or_default();
                self.finish_stop(inner, s, &reason).await?;
            }
            other => inner.state = other,
        }
        store::ensure_root(&self.root)?;
        let quota_reached = store::quota_reached(
            store::total_bytes(&self.root, None),
            store::free_bytes(&self.root),
            cfg.max_size_mb,
            cfg.quota_mb,
        );
        let now = now_ms();
        let id = manifest::session_id(now);
        let dir = manifest::session_dir(&self.root, &id);
        std::fs::create_dir(&dir)?;
        let mut session = Session {
            manifest: SessionManifest {
                schema_version: manifest::SCHEMA_VERSION,
                app_version: env!("CARGO_PKG_VERSION").to_string(),
                session_id: id.clone(),
                running: true,
                engine: (!quota_reached).then(|| "pktmon".to_string()),
                mode: Some(ctx.mode),
                target: Some(ctx.target),
                started_at: now,
                stopped_at: None,
                max_size_mb: cfg.max_size_mb,
                stop_reason: None,
                last_error: None,
                pktmon: PktmonState::NotStarted,
                etw: EtwState::NotStarted,
                etw_stats: None,
                warnings: Vec::new(),
                app_events_dropped: 0,
            },
            dir: dir.clone(),
            etw: None,
            owns_pktmon: false,
            quota_reached,
        };
        // Write-ahead: manifest and marker reach the disk before pktmon is launched.
        manifest::write_manifest(&dir, &session.manifest)?;
        if quota_reached {
            session.manifest.pktmon = PktmonState::Unavailable("storage quota reached".into());
            session
                .manifest
                .warnings
                .push("forensics storage quota reached".into());
        } else {
            manifest::write_marker(&self.root, &id)?;
            session.owns_pktmon = true;
            self.start_pktmon(&mut session, cfg.max_size_mb).await;
        }
        tracing::info!(
            "capture session {id} started: pktmon {:?} (whole packets, ring {} MB)",
            session.manifest.pktmon,
            cfg.max_size_mb
        );
        match self.system.start_etw(dir.clone(), id.clone()).await {
            Ok(etw) => {
                session.etw = Some(etw);
                session.manifest.etw = EtwState::Running;
            }
            Err(e) => {
                tracing::warn!("etw consumer did not start: {e}");
                session.manifest.etw = EtwState::Failed(e);
            }
        }
        self.system.snapshot(dir.clone(), "start").await;
        if session.manifest.pktmon != PktmonState::Running && session.etw.is_none() {
            let detail = format!(
                "pktmon: {:?} | etw: {:?}",
                session.manifest.pktmon, session.manifest.etw
            );
            session.manifest.last_error = Some(detail.clone());
            if session.owns_pktmon {
                // A timed-out pktmon start may still be capturing: keep it stoppable.
                session.manifest.stop_reason = Some(START_FAILED.into());
                manifest::write_manifest(&dir, &session.manifest)?;
                inner.state = State::StopUnconfirmed(session);
            } else {
                session.manifest.running = false;
                session.manifest.stopped_at = Some(now_ms());
                session.manifest.stop_reason = Some(START_FAILED.into());
                manifest::write_manifest(&dir, &session.manifest)?;
                inner.state = State::Stopped(session);
            }
            return Err(CaptureError::StartFailed(detail));
        }
        manifest::write_manifest(&dir, &session.manifest)?;
        self.open_app_events(&dir);
        inner.state = State::Running(session);
        Ok(())
    }

    /// Runs `pktmon start`; exit 0 = Running. A refusal leaves the session ETW-only and drops the
    /// marker; a timeout keeps it, since the capture may have started after all.
    async fn start_pktmon(&self, session: &mut Session, max_size_mb: u32) {
        let etl = session.dir.join(pktmon::ETL_FILE);
        let args = pktmon::start_args(&etl, max_size_mb);
        let state = match self.system.pktmon(args, pktmon::START_TIMEOUT).await {
            Ok(out) if out.success() => PktmonState::Running,
            Ok(out) => {
                session.owns_pktmon = false;
                PktmonState::Unavailable(out.detail())
            }
            Err(e) => {
                session.owns_pktmon = e.kind() == io::ErrorKind::TimedOut;
                PktmonState::Unavailable(e.to_string())
            }
        };
        if !session.owns_pktmon
            && let Err(e) = manifest::remove_marker(&self.root)
        {
            tracing::warn!("cannot remove the capture marker: {e}");
        }
        if let PktmonState::Unavailable(detail) = &state {
            tracing::warn!("pktmon did not start, ETW only: {detail}");
            session.manifest.engine = None;
        }
        session.manifest.pktmon = state;
    }

    pub(super) async fn stop_locked(
        &self,
        inner: &mut Inner,
        reason: &str,
    ) -> Result<(), CaptureError> {
        match std::mem::replace(&mut inner.state, State::Idle) {
            State::Running(s) => {
                // Lifecycle stops the capture before engine teardown, so this shows the protected
                // state (the old app took it after teardown, B-06). Retries of an unconfirmed
                // stop already have it.
                self.system.snapshot(s.dir.clone(), "stop").await;
                self.finish_stop(inner, s, reason).await
            }
            State::StopUnconfirmed(s) => self.finish_stop(inner, s, reason).await,
            other => {
                inner.state = other;
                Ok(())
            }
        }
    }

    /// Stops ETW (a consumer failure never marks the packet capture stopped), then pktmon; the
    /// session counts as stopped only after `pktmon stop` exits 0 or the ETL is observed released.
    async fn finish_stop(
        &self,
        inner: &mut Inner,
        mut s: Session,
        reason: &str,
    ) -> Result<(), CaptureError> {
        if let Some(t) = inner.ticker.take() {
            t.cancel();
        }
        if let Some(log) = self.events.lock().take() {
            s.manifest.app_events_dropped = log.dropped;
        }
        s.manifest.stop_reason = Some(reason.to_string());
        if let Some(etw) = s.etw.take() {
            let ended_early = !etw.is_running();
            let why = reason.to_string();
            match tokio::task::spawn_blocking(move || etw.stop(&why)).await {
                Ok(stats) => s.manifest.etw_stats = Some(stats),
                Err(e) => tracing::warn!("etw stop panicked: {e}"),
            }
            if s.manifest.etw == EtwState::Running {
                s.manifest.etw = if ended_early {
                    EtwState::Failed(ETW_ENDED.into())
                } else {
                    EtwState::Stopped
                };
            }
        }
        if s.owns_pktmon {
            let etl = s.dir.join(pktmon::ETL_FILE);
            let out = self
                .system
                .pktmon(pktmon::stop_args(), pktmon::STOP_TIMEOUT)
                .await;
            let (code, detail) = match &out {
                Ok(o) => (o.code, o.detail()),
                Err(e) => (None, e.to_string()),
            };
            let exited_ok = out.as_ref().is_ok_and(Outcome::success);
            if !exited_ok && !self.system.etl_released(&etl) {
                tracing::warn!("pktmon stop not confirmed ({code:?}): {detail}");
                s.manifest.pktmon = PktmonState::StopUnconfirmed(detail.clone());
                s.manifest.running = true;
                s.manifest.stopped_at = None;
                s.manifest.last_error = Some(format!("CaptureStopUnconfirmed: {detail}"));
                self.save(&s);
                inner.state = State::StopUnconfirmed(s);
                return Err(CaptureError::StopUnconfirmed { code, detail });
            }
            if !exited_ok {
                tracing::warn!("pktmon stop exited {code:?}, but the ETL is released: stopped");
            }
            if let Err(e) = manifest::remove_marker(&self.root) {
                tracing::warn!("cannot remove the capture marker: {e}");
            }
            s.owns_pktmon = false;
            if matches!(
                s.manifest.pktmon,
                PktmonState::Running | PktmonState::StopUnconfirmed(_)
            ) {
                s.manifest.pktmon = PktmonState::Stopped;
                self.collect(&s.dir).await;
            }
        }
        if s.manifest
            .last_error
            .as_deref()
            .is_some_and(|e| e.starts_with("CaptureStopUnconfirmed:"))
        {
            s.manifest.last_error = None;
        }
        s.manifest.running = false;
        s.manifest.stopped_at = Some(now_ms());
        self.save(&s);
        tracing::info!(
            "capture session {} stopped: {reason}",
            s.manifest.session_id
        );
        inner.state = State::Stopped(s);
        Ok(())
    }

    /// Boot recovery, see [`Capture::recover_on_boot`](super::Capture::recover_on_boot).
    pub(super) async fn recover_locked(
        &self,
        inner: &mut Inner,
        legacy_electron: Option<&Path>,
    ) -> RecoveryReport {
        let mut report = RecoveryReport::default();
        let marker = manifest::read_marker(&self.root);
        let marked_id = marker.clone().flatten();
        let legacy = self.legacy_capture_pending(legacy_electron);
        let mut unconfirmed = None;
        if marker.is_some() || legacy {
            report.orphan_suspected = true;
            let out = self
                .system
                .pktmon(pktmon::stop_args(), pktmon::STOP_TIMEOUT)
                .await;
            let etl = marked_id
                .as_ref()
                .map(|id| manifest::session_dir(&self.root, id).join(pktmon::ETL_FILE));
            report.pktmon_stopped = out.as_ref().is_ok_and(Outcome::success)
                || etl.is_some_and(|p| self.system.etl_released(&p));
            tracing::warn!(
                "orphaned packet capture stopped at startup (confirmed: {}, legacy hint: {legacy})",
                report.pktmon_stopped
            );
            if legacy && out.is_ok() {
                // Old hints never change (the legacy dir is never written): their capture gets
                // one stop, not one per start that would also end the user's own captures (B-27).
                let done = store::ensure_root(&self.root).and_then(|()| {
                    vpnte_core::store::write_atomic(&self.root.join(LEGACY_DONE_FILE), b"")
                });
                if let Err(e) = done {
                    tracing::warn!("cannot record the legacy capture stop: {e}");
                }
            }
            if report.pktmon_stopped {
                if let Err(e) = manifest::remove_marker(&self.root) {
                    tracing::warn!("cannot remove the capture marker: {e}");
                }
            } else {
                unconfirmed = marked_id;
            }
        }
        for entry in store::list_sessions(&self.root) {
            let Some(mut m) = entry.manifest.filter(|m| m.running) else {
                continue;
            };
            m.stop_reason = Some(RECOVERED_AT_STARTUP.into());
            if unconfirmed.as_deref() == Some(entry.id.as_str()) {
                m.pktmon = PktmonState::StopUnconfirmed("recovery stop not confirmed".into());
                let s = Session {
                    manifest: m,
                    dir: entry.dir,
                    etw: None,
                    owns_pktmon: true,
                    quota_reached: false,
                };
                self.save(&s);
                inner.state = State::StopUnconfirmed(s);
                continue;
            }
            if m.pktmon == PktmonState::Running {
                m.pktmon = PktmonState::Stopped;
            }
            if m.etw == EtwState::Running {
                m.etw = EtwState::Stopped;
            }
            m.running = false;
            m.stopped_at = Some(now_ms());
            if manifest::write_manifest(&entry.dir, &m).is_ok() {
                report.sessions_closed += 1;
            }
        }
        if self.system.reclaim_etw() {
            tracing::warn!(
                "reclaimed orphaned ETW session {}",
                crate::etw::SESSION_NAME
            );
            report.etw_reclaimed = true;
        }
        report
    }

    /// An old app's hint says its capture may still run, and it has not had its stop yet.
    fn legacy_capture_pending(&self, legacy_electron: Option<&Path>) -> bool {
        let (Some(legacy), Some(program_data)) = (legacy_electron, std::env::var_os("ProgramData"))
        else {
            return false;
        };
        !self.root.join(LEGACY_DONE_FILE).exists()
            && manifest::legacy_hint_paths(legacy, Path::new(&program_data))
                .iter()
                .any(|h| manifest::legacy_hint_pending(h))
    }

    /// Best-effort artefacts after a confirmed stop; failures go to `stop-errors.txt`.
    async fn collect(&self, dir: &Path) {
        let mut errors = Vec::new();
        for (label, drop_reason, file) in [
            ("pktmon-counters", false, pktmon::COUNTERS_FILE),
            ("pktmon-drop-counters", true, pktmon::DROP_COUNTERS_FILE),
        ] {
            let args = pktmon::counters_args(drop_reason);
            match self.system.pktmon(args, pktmon::COLLECT_TIMEOUT).await {
                Ok(o) if o.success() => {
                    if let Err(e) = std::fs::write(dir.join(file), &o.stdout) {
                        errors.push(format!("[{label}] {e}"));
                    }
                }
                Ok(o) => errors.push(format!("[{label}] exit={:?} {}", o.code, o.detail())),
                Err(e) => errors.push(format!("[{label}] {e}")),
            }
        }
        let etl = dir.join(pktmon::ETL_FILE);
        if etl.exists() {
            let args = pktmon::etl2pcap_args(&etl, &dir.join(pktmon::PCAPNG_FILE));
            match self.system.pktmon(args, pktmon::COLLECT_TIMEOUT).await {
                Ok(o) if o.success() => {}
                Ok(o) => errors.push(format!(
                    "[pktmon-etl2pcap] exit={:?} {}",
                    o.code,
                    o.detail()
                )),
                Err(e) => errors.push(format!("[pktmon-etl2pcap] {e}")),
            }
        }
        if !errors.is_empty() {
            let appended = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join(STOP_ERRORS_FILE))
                .and_then(|mut f| f.write_all(format!("{}\n", errors.join("\n")).as_bytes()));
            if let Err(e) = appended {
                tracing::warn!("cannot record stop errors: {e}");
            }
        }
    }

    /// Writes the manifest; a failure is logged (the in-memory state stays authoritative).
    pub(super) fn save(&self, s: &Session) {
        if let Err(e) = manifest::write_manifest(&s.dir, &s.manifest) {
            tracing::warn!("cannot write the capture manifest: {e}");
        }
    }

    fn open_app_events(&self, dir: &Path) {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(APP_EVENTS_FILE));
        match file {
            Ok(file) => {
                *self.events.lock() = Some(AppEvents {
                    file,
                    rows: 0,
                    dropped: 0,
                })
            }
            Err(e) => tracing::warn!("cannot open app events of the capture: {e}"),
        }
    }
}
