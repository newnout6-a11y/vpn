//! The service's WFP watchdog runs while the kill switch holds a session's filters, and only then
//! (an idle service has no timer). "Holds" is recorded at the capture seam: from a `begin` that
//! succeeded (protection up before the engines start) until a `release` that succeeded. An engine
//! crash (`lost`), a preserved stop and the paused "kill switch active" state keep the block, so
//! the watchdog keeps re-applying it after a BFE restart (review service-a6); the runtime's status
//! reads idle in exactly those states and is no gauge.
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_engine::singbox_config::ConfigError;
use vpnte_tunnel::api::StartRequest;
use vpnte_tunnel::runtime::{
    Capture, CaptureCheck, CapturePlan, CaptureProof, EngineExes, EngineParts,
};

/// A capture that records whether its protection holds a session's filters.
pub struct Engaged<C> {
    inner: C,
    holds: watch::Sender<bool>,
    /// The engine files sessions start now and those the protection permits anyway
    /// ([`Engaged::with_engines`]).
    engines: Option<(watch::Receiver<EngineExes>, Vec<PathBuf>)>,
}

impl<C: Capture> Engaged<C> {
    pub fn new(inner: C) -> Self {
        Self {
            inner,
            holds: watch::channel(false).0,
            engines: None,
        }
    }

    /// Every session also permits the engine files `exes` names at its start, unless they are
    /// among `permitted` (the protection's own engine permits, fixed when it was built): a version
    /// the updater installed while the service runs gets through from its first session on
    /// (p-svc-update).
    #[must_use]
    pub fn with_engines(
        mut self,
        exes: watch::Receiver<EngineExes>,
        permitted: Vec<PathBuf>,
    ) -> Self {
        self.engines = Some((exes, permitted));
        self
    }

    /// `true` while a session's filters are held.
    pub fn holds(&self) -> watch::Receiver<bool> {
        self.holds.subscribe()
    }
}

#[async_trait]
impl<C: Capture> Capture for Engaged<C> {
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan> {
        self.inner.prepare(req, avoid).await
    }

    fn config(
        &self,
        plan: &CapturePlan,
        parts: &EngineParts,
    ) -> Result<(Value, [u8; 32]), ConfigError> {
        self.inner.config(plan, parts)
    }

    async fn begin(&self, plan: &CapturePlan, session_programs: &[PathBuf]) -> AppResult<()> {
        let mut programs = session_programs.to_vec();
        if let Some((exes, permitted)) = &self.engines {
            let exes = exes.borrow().clone();
            for exe in [exes.singbox, exes.xray] {
                if !permitted.contains(&exe) && !programs.contains(&exe) {
                    programs.push(exe);
                }
            }
        }
        // A failed begin leaves the record as it was: a reconnect keeps the earlier hold.
        self.inner.begin(plan, &programs).await?;
        self.holds.send_replace(true);
        Ok(())
    }

    async fn ready(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        self.inner.ready(plan, timeout, cancel).await
    }

    async fn routes_ok(&self, proof: &CaptureProof) -> bool {
        self.inner.routes_ok(proof).await
    }

    async fn lost(&self) -> AppResult<()> {
        self.inner.lost().await
    }

    async fn release(&self) -> AppResult<()> {
        // A failed release leaves the filters in doubt: still watched.
        self.inner.release().await?;
        self.holds.send_replace(false);
        Ok(())
    }

    async fn wait_gone(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> bool {
        self.inner.wait_gone(plan, timeout, cancel).await
    }

    async fn check(&self, proof: &CaptureProof) -> CaptureCheck {
        self.inner.check(proof).await
    }
}

/// Calls `start` with a fresh child token of `stop` when `holds` turns true and cancels that
/// token when it turns false, until `stop`.
pub async fn run(
    mut holds: watch::Receiver<bool>,
    start: impl Fn(CancellationToken),
    stop: CancellationToken,
) {
    let mut ticking: Option<CancellationToken> = None;
    loop {
        let held = *holds.borrow_and_update();
        match (held, ticking.as_ref()) {
            (true, None) => {
                let token = stop.child_token();
                start(token.clone());
                ticking = Some(token);
            }
            (false, Some(token)) => {
                token.cancel();
                ticking = None;
            }
            _ => {}
        }
        tokio::select! {
            () = stop.cancelled() => break,
            changed = holds.changed() => if changed.is_err() { break },
        }
    }
}

#[cfg(test)]
mod tests;
