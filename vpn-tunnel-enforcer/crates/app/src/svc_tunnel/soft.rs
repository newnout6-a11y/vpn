//! [`SoftProxy`] over the automation crate's journalled Soft tweaks (NOADMIN §2): the per-user
//! system proxy, the proxy variables and the opted-in dev targets of `soft.json`.
use std::sync::Arc;

use async_trait::async_trait;
use vpnte_automation::tweaks::{Feature, Journal, ProxyOwner, Soft, sysproxy};
use vpnte_base::types::{Level, Notice, ProxyKind};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use vpnte_tunnel::lifecycle::SoftProxy;

use crate::svc_core::docs::SoftDoc;
use crate::svc_core::notify::Notifier;

/// The Soft tweaks of this process (one journal, opened once by `build`).
pub(super) struct SoftTweaks {
    pub soft: Soft,
    pub journal: Arc<Journal>,
    pub doc: Arc<Store<SoftDoc>>,
    pub notifier: Arc<Notifier>,
}

impl SoftTweaks {
    /// Restores every Soft value still journalled; `Err` keeps the rest journalled for a retry.
    /// Values the user changed since are kept, and the user is told so.
    pub async fn restore(&self) -> AppResult<()> {
        let report = self.soft.rollback().await?;
        if let Some(kept) = report.kept_msg() {
            self.notifier.notify(Notice::new(Level::Info, kept), None);
        }
        match report.failure_msg() {
            Some(msg) => Err(AppError::msg(ErrorKind::Internal, msg)),
            None => Ok(()),
        }
    }
}

fn host_port(addr: &str) -> AppResult<HostPort> {
    HostPort::parse(addr).map_err(|e| {
        AppError::validation(Msg::new("tunnel.runtime.proxyAddressInvalid")).with_source(e)
    })
}

#[async_trait]
impl SoftProxy for SoftTweaks {
    fn applied(&self) -> Option<bool> {
        // The journal holds exactly what Soft wrote and has not restored yet: the obligation the
        // state machine tracks. The value itself is read back by `is_configured`.
        Some(self.soft.is_applied())
    }

    async fn apply(&self, addr: &str, kind: ProxyKind) -> AppResult<()> {
        let addr = host_port(addr)?;
        let dev = self.doc.read(|d| d.dev_targets);
        let report = self.soft.apply(addr, kind, dev).await?;
        if !report.not_detected.is_empty() {
            tracing::info!(skipped = ?report.not_detected, "soft: selected dev tools not installed");
        }
        if !report.dropped.is_complete() {
            tracing::warn!(
                failed = report.dropped.failed.len(),
                "soft: deselected dev tools not restored"
            );
        }
        Ok(())
    }

    async fn rollback(&self) -> AppResult<()> {
        self.restore().await
    }

    async fn is_configured(&self, addr: &str, _kind: ProxyKind) -> AppResult<bool> {
        // Proof of Soft (NOADMIN §2): the system proxy still holds the value we journalled, and
        // that value points at this `addr` (WinINet takes the mixed inbound for every protocol).
        let want = sysproxy::encode(&sysproxy::applied(&host_port(addr)?));
        let status = self.soft.status().await?;
        let points_here = self
            .journal
            .records(Feature::SoftProxy)
            .iter()
            .any(|r| r.applied == want);
        Ok(status.system_proxy == ProxyOwner::Ours && points_here)
    }
}
