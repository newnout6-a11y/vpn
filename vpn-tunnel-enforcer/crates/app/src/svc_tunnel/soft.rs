//! [`SoftProxy`] over the automation crate's journalled Soft tweaks (NOADMIN §2): the per-user
//! system proxy, the proxy variables and the opted-in dev targets of `soft.json`.
//!
//! While the journal holds Soft values two guards run (ks-b): the crash watcher
//! ([`crate::crash_watch`]), which rolls them back if the app dies without doing so, and the
//! system-proxy watch ([`taken`]), which notices another program taking the proxy over.
use std::sync::Arc;

use async_trait::async_trait;
use vpnte_automation::tweaks::{Feature, Journal, ProxyOwner, Soft, sysproxy};
use vpnte_base::types::{Level, Notice, ProxyKind};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use vpnte_tunnel::lifecycle::SoftProxy;

use crate::crash_watch;
use crate::svc_core::docs::SoftDoc;
use crate::svc_core::notify::Notifier;

pub(crate) mod taken;

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
        self.follow_journal().await;
        if let Some(kept) = report.kept_msg() {
            self.notifier.notify(Notice::new(Level::Info, kept), None);
        }
        match report.failure_msg() {
            Some(msg) => Err(AppError::msg(ErrorKind::Internal, msg)),
            None => Ok(()),
        }
    }

    /// «Вернуть»: points the system proxy at the session's port again after another program
    /// took it; the user's original setting still comes back when the session ends.
    pub async fn reclaim(&self) -> AppResult<()> {
        if self.soft.reclaim_proxy().await? {
            tracing::info!("soft: system proxy taken back from another program");
        }
        self.read_back().await;
        Ok(())
    }

    /// The guards end once nothing of the session is journalled any more; failed values keep
    /// them, so a crash still finds a watcher for the retry.
    async fn follow_journal(&self) {
        if self.soft.is_applied() {
            return;
        }
        // Both stops wait briefly (a thread join, a process exit): off the async workers.
        let stopped = tokio::task::spawn_blocking(|| {
            taken::stop();
            crash_watch::disarm();
        });
        if stopped.await.is_err() {
            tracing::warn!("session guards stop panicked");
        }
    }

    /// Starts the system-proxy watch of this session (a no-op while it runs).
    fn watch_proxy(&self) {
        let (soft, journal) = (self.soft.clone(), self.journal.clone());
        taken::start(move || taken::publish(is_taken(&soft, &journal)));
    }

    /// Publishes the "taken" read-back at once (after an apply or «Вернуть»), not only on the
    /// next registry change.
    async fn read_back(&self) {
        let (soft, journal) = (self.soft.clone(), self.journal.clone());
        if let Ok(taken) = tokio::task::spawn_blocking(move || is_taken(&soft, &journal)).await {
            taken::publish(taken);
        }
    }
}

/// Our session journalled a system proxy and the setting now holds another one.
fn is_taken(soft: &Soft, journal: &Journal) -> bool {
    journal.is_applied(Feature::SoftProxy) && soft.proxy_owner_blocking() == ProxyOwner::User
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
        // Before the first write, so a crash halfway through is covered as well.
        if tokio::task::spawn_blocking(crash_watch::arm).await.is_err() {
            tracing::warn!("crash watcher start panicked");
        }
        let dev = self.doc.read(|d| d.dev_targets);
        let report = match self.soft.apply(addr, kind, dev).await {
            Ok(report) => report,
            Err(e) => {
                self.follow_journal().await;
                return Err(e);
            }
        };
        if !report.not_detected.is_empty() {
            tracing::info!(skipped = ?report.not_detected, "soft: selected dev tools not installed");
        }
        if !report.dropped.is_complete() {
            tracing::warn!(
                failed = report.dropped.failed.len(),
                "soft: deselected dev tools not restored"
            );
        }
        self.watch_proxy();
        self.read_back().await;
        Ok(())
    }

    async fn rollback(&self) -> AppResult<()> {
        self.restore().await
    }

    async fn is_configured(&self, addr: &str, _kind: ProxyKind) -> AppResult<bool> {
        // Proof of Soft (NOADMIN §2): the system proxy still holds the value we journalled, and
        // that value points at this `addr` (WinINet takes the mixed inbound for every protocol).
        let want = sysproxy::encode(&sysproxy::applied(&host_port(addr)?));
        let owner = self.soft.proxy_owner().await?;
        let points_here = self
            .journal
            .records(Feature::SoftProxy)
            .iter()
            .any(|r| r.applied == want);
        Ok(owner == ProxyOwner::Ours && points_here)
    }

    async fn taken(&self) -> bool {
        // The ks-b watch's own test: an unreadable value is not "taken" (a restart then writes
        // it again and reads it back).
        let (soft, journal) = (self.soft.clone(), self.journal.clone());
        tokio::task::spawn_blocking(move || is_taken(&soft, &journal))
            .await
            .unwrap_or(false)
    }
}
