//! [`SoftProxy`] over the automation crate's journalled Soft tweaks (NOADMIN §2): the per-user
//! system proxy, the proxy variables and the opted-in dev targets of `soft.json`.
//!
//! While the journal holds Soft values two guards run (ks-b): the crash watcher
//! ([`crate::crash_watch`]), which rolls them back if the app dies without doing so, and the
//! system-proxy watch ([`taken`]), which notices another program taking the proxy over.
//!
//! The session follows «Не через прокси» ([`follow`]): the engine re-reads the rules at every
//! restart, crash restarts included, so an entry the rules no longer justify is taken out of the
//! running session at once instead of at the next connection (owner answer 4, pbypass-a1).
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use vpnte_automation::tweaks::{
    DevTargets, Feature, Journal, ProxyOwner, Soft, Target, Val, env, sysproxy,
};
use vpnte_base::types::{Level, Notice, ProxyKind};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_core::store::Store;
use vpnte_tunnel::lifecycle::SoftProxy;

use crate::crash_watch;
use crate::svc_core::docs::SoftDoc;
use crate::svc_core::notify::Notifier;

pub(crate) mod taken;

/// One Soft write at a time in this process (apply, rollback, «Вернуть», the read-back and the
/// list follower): a follower write after the session's rollback would point the proxy at a
/// port nothing listens on.
static WRITES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The running session as applied, for the follower: one per process, like the system proxy.
static SESSION: Mutex<Option<Applied>> = Mutex::new(None);

/// The follower task (started with the first session; again after its runtime ended).
static FOLLOWER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

#[derive(Clone)]
struct Applied {
    soft: Soft,
    journal: Arc<Journal>,
    addr: HostPort,
    kind: ProxyKind,
    dev: DevTargets,
}

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
        let _writes = WRITES.lock().await;
        // The session ends (or pauses) here, also when a value stays journalled for a retry:
        // only the lifecycle's next apply may point the proxy at a port again.
        *SESSION.lock() = None;
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
        let _writes = WRITES.lock().await;
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

/// Starts the list follower unless it runs.
fn follow() {
    let mut slot = FOLLOWER.lock();
    if slot.as_ref().is_none_or(JoinHandle::is_finished) {
        *slot = Some(tokio::spawn(follow_list(sysproxy::changes())));
    }
}

/// Brings the running session up to date at once and after every change of the list.
async fn follow_list(mut changes: tokio::sync::watch::Receiver<u64>) {
    loop {
        catch_up().await;
        if changes.changed().await.is_err() {
            return;
        }
    }
}

/// Brings the running session up to date and publishes its read-back.
async fn catch_up() {
    let _writes = WRITES.lock().await;
    let Some(s) = SESSION.lock().clone() else {
        return;
    };
    if bring_up_to_date(&s).await {
        let (soft, journal) = (s.soft, s.journal);
        if let Ok(taken) = tokio::task::spawn_blocking(move || is_taken(&soft, &journal)).await {
            taken::publish(taken);
        }
    }
}

/// Applies `s` again when its journalled values hold another list than the next one; `true` =
/// applied. A session that ended is left to its rollback, another program's proxy to the user
/// («Вернуть», ks-b).
async fn bring_up_to_date(s: &Applied) -> bool {
    let next = sysproxy::next();
    let mut want = vec![(
        Feature::SoftProxy,
        Target::SystemProxy,
        sysproxy::encode(&sysproxy::applied_with(&s.addr, &next)),
    )];
    want.extend(env::plan_with(&s.addr, s.kind, &next));
    let held = |(feature, target, value): &(Feature, Target, Val)| {
        s.journal
            .records(*feature)
            .iter()
            .any(|r| r.target == *target && r.applied == *value)
    };
    if !s.soft.is_applied() || want.iter().all(held) {
        return false;
    }
    if !matches!(s.soft.proxy_owner().await, Ok(ProxyOwner::Ours)) {
        return false;
    }
    match s.soft.apply(s.addr.clone(), s.kind, s.dev).await {
        Ok(_) => tracing::info!("soft: the running session took the changed bypass list"),
        Err(e) => tracing::warn!(error = %e, "soft: changed bypass list not applied"),
    }
    true
}

fn host_port(addr: &str) -> AppResult<HostPort> {
    HostPort::parse(addr).map_err(|e| {
        AppError::validation(Msg::new("tunnel.runtime.proxyAddressInvalid")).with_source(e)
    })
}

#[cfg(test)]
mod tests;

#[async_trait]
impl SoftProxy for SoftTweaks {
    fn applied(&self) -> Option<bool> {
        // The journal holds exactly what Soft wrote and has not restored yet: the obligation the
        // state machine tracks. The value itself is read back by `is_configured`.
        Some(self.soft.is_applied())
    }

    async fn apply(&self, addr: &str, kind: ProxyKind) -> AppResult<()> {
        let addr = host_port(addr)?;
        let _writes = WRITES.lock().await;
        // Before the first write, so a crash halfway through is covered as well.
        if tokio::task::spawn_blocking(crash_watch::arm).await.is_err() {
            tracing::warn!("crash watcher start panicked");
        }
        let dev = self.doc.read(|d| d.dev_targets);
        let report = match self.soft.apply(addr.clone(), kind, dev).await {
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
        *SESSION.lock() = Some(Applied {
            soft: self.soft.clone(),
            journal: self.journal.clone(),
            addr,
            kind,
            dev,
        });
        follow();
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
        // Under the write lock: the follower changes the list and the value together.
        let _writes = WRITES.lock().await;
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
