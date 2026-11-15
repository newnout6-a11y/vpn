//! The OS side of a capture: pktmon runs, the ETL release check, the ETW consumer and the
//! network / socket snapshots. Tests replace it with a fake.
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::future::BoxFuture;

use super::pktmon::{self, Outcome};
use super::snapshot;
use crate::etw::{DigestSnapshot, EtwConsumer, EtwStopStats, LossStats};

/// The OS side of a capture; [`WindowsSystem`] is the real one, tests use a fake.
pub trait System: Send + Sync + 'static {
    /// Runs `pktmon.exe <args>`.
    fn pktmon(
        &self,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> BoxFuture<'static, io::Result<Outcome>>;
    /// `true` when no writer holds the ETL any more (see [`pktmon::etl_released`]).
    fn etl_released(&self, etl: &Path) -> bool;
    /// Starts the ETW consumer of a session.
    fn start_etw(
        &self,
        dir: PathBuf,
        session: String,
    ) -> BoxFuture<'static, Result<Box<dyn Etw>, String>>;
    /// Stops an orphaned ETW session; `true` when one existed.
    fn reclaim_etw(&self) -> bool;
    /// Writes `network-<phase>.json` and `sockets-<phase>.json` into `dir` (best effort).
    fn snapshot(&self, dir: PathBuf, phase: &'static str) -> BoxFuture<'static, ()>;
}

/// A running ETW consumer as the capture sees it.
pub trait Etw: Send + Sync {
    /// Live counters and top lists.
    fn digest(&self) -> DigestSnapshot;
    /// `false` once event processing ended on its own.
    fn is_running(&self) -> bool;
    /// Events / buffers the kernel reports lost so far.
    fn loss(&self) -> Option<LossStats>;
    /// Blocking stop (about five seconds at most); called on a blocking thread.
    fn stop(self: Box<Self>, reason: &str) -> EtwStopStats;
}

impl Etw for EtwConsumer {
    fn digest(&self) -> DigestSnapshot {
        EtwConsumer::digest(self).snapshot()
    }
    fn is_running(&self) -> bool {
        EtwConsumer::is_running(self)
    }
    fn loss(&self) -> Option<LossStats> {
        crate::etw::session::query_loss()
    }
    fn stop(self: Box<Self>, reason: &str) -> EtwStopStats {
        EtwConsumer::stop(*self, reason)
    }
}

/// pktmon, ETW and snapshots on this machine (needs elevation to capture).
pub struct WindowsSystem;

impl System for WindowsSystem {
    fn pktmon(
        &self,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> BoxFuture<'static, io::Result<Outcome>> {
        Box::pin(pktmon::run(args, timeout))
    }

    fn etl_released(&self, etl: &Path) -> bool {
        pktmon::etl_released(etl)
    }

    fn start_etw(
        &self,
        dir: PathBuf,
        session: String,
    ) -> BoxFuture<'static, Result<Box<dyn Etw>, String>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                EtwConsumer::start(&dir, &session)
                    .map(|c| Box::new(c) as Box<dyn Etw>)
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| e.to_string())?
        })
    }

    fn reclaim_etw(&self) -> bool {
        crate::etw::reclaim_orphan()
    }

    fn snapshot(&self, dir: PathBuf, phase: &'static str) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let _ = tokio::task::spawn_blocking(move || snapshot::write(&dir, phase)).await;
        })
    }
}
