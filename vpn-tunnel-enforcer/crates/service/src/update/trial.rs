//! The trial of a fresh engine version, judged like the app's (svcupd-a5 / b6): the outcome of
//! each start the host asks the runtime for settles it. A start that ran ends the trial, one that
//! failed counts against the engine files it started, and one the user cancelled (or another
//! start replaced) says nothing about the engine. The runtime's own crash restarts are not asked
//! for here and settle nothing.
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::{AdaptiveMode, KillSwitchLevel, OutboundFault};
use vpnte_tunnel::api::{
    ExitInfo, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest, StopOptions,
    StopReceipt, SwitchReceipt, TunError, TunStatus, TunnelEvent, VpnProfile,
};
use vpnte_tunnel::runtime::EngineStarts;

use super::engines::ServiceEngines;

/// The host's runtime: every call goes through unchanged; the outcomes of starts reach the
/// engines' trial with what the runtime started for them.
pub struct Judged {
    inner: Arc<dyn Runtime>,
    engines: Arc<ServiceEngines>,
    starts: watch::Receiver<EngineStarts>,
}

impl Judged {
    pub fn new(
        inner: Arc<dyn Runtime>,
        engines: Arc<ServiceEngines>,
        starts: watch::Receiver<EngineStarts>,
    ) -> Self {
        Self {
            inner,
            engines,
            starts,
        }
    }

    /// Settles the trial with a start that ended with `result` (`started`: whether a receipt
    /// means a session runs).
    fn settle<T>(&self, result: &Result<T, TunError>, started: impl Fn(&T) -> bool) {
        let now = self.starts.borrow().clone();
        self.engines.settled(&now, verdict(result, started));
    }
}

/// What a start's end says about its engines: it runs, it failed, or nothing (cancelled by the
/// user or replaced by another start, or nothing was started).
fn verdict<T>(result: &Result<T, TunError>, started: impl Fn(&T) -> bool) -> Option<bool> {
    match result {
        Ok(receipt) => started(receipt).then_some(true),
        Err(err) if err.kind() == ErrorKind::Cancelled => None,
        Err(_) => Some(false),
    }
}

#[async_trait]
impl Runtime for Judged {
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        let result = self.inner.start(req, cancel).await;
        self.settle(&result, |_| true);
        result
    }

    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        self.inner.stop(opts).await
    }

    async fn restart_protected(
        &self,
        reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        let result = self.inner.restart_protected(reason, next, opts).await;
        self.settle(&result, |_| true);
        result
    }

    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError> {
        let result = self.inner.restart_with_last(reason).await;
        self.settle(&result, Option::is_some);
        result
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        let result = self.inner.restart_adaptive(mode, reason, profile).await;
        self.settle(&result, |_| true);
        result
    }

    async fn switch_upstream(
        &self,
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        self.inner.switch_upstream(next, cancel, is_owner).await
    }

    async fn retry_now(&self) -> bool {
        self.inner.retry_now().await
    }

    async fn set_kill_switch(&self, level: KillSwitchLevel) {
        self.inner.set_kill_switch(level).await;
    }

    fn status(&self) -> watch::Receiver<TunStatus> {
        self.inner.status()
    }

    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.inner.subscribe()
    }

    fn last_exit(&self) -> Option<ExitInfo> {
        self.inner.last_exit()
    }

    fn recent_fault(&self) -> Option<OutboundFault> {
        self.inner.recent_fault()
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::{AppError, Msg};

    use super::*;

    /// svcupd-a5: a cancelled start is no failure of the engine; a refused one is, a running
    /// one ends the trial, and a restart with nothing to restart says nothing.
    #[test]
    fn only_settled_starts_judge_the_engine() {
        let failed = |kind| -> Result<(), TunError> {
            Err(AppError::msg(kind, Msg::new("tunnel.test")).into())
        };
        assert_eq!(verdict(&failed(ErrorKind::Cancelled), |_| true), None);
        assert_eq!(verdict(&failed(ErrorKind::Network), |_| true), Some(false));
        assert_eq!(verdict(&Ok::<(), TunError>(()), |_| true), Some(true));
        assert_eq!(
            verdict(&Ok::<Option<()>, TunError>(None), Option::is_some),
            None
        );
    }
}
