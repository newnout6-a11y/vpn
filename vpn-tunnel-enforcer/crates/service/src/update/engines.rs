//! Engines for Tunnel mode (task point 3, decisions D-S1 / D-S7): the engine store over
//! `<install>\engines` with the install folder as the bundled set. A verified version goes into a
//! version folder of its own (the signed feed next to it, so the engine crate's elevated pin check
//! accepts it); every engine start of a session reads the paths current then ([`exes`]); the
//! previous version stays for one rollback, and a fresh one that fails three starts in a row goes
//! back by itself (the store's trial, fed from the runtime's starts here).
//!
//! [`exes`]: ServiceEngines::exes
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_tunnel::api::TunnelEvent;
use vpnte_tunnel::runtime::{EngineExes, EngineStarts, Started};
use vpnte_update::download::{Verified, sha256_of};
use vpnte_update::feed::{EngineEntry, Feed};
use vpnte_update::policy::{self, SINGBOX, XRAY, bundled_version, engine_allowed};
use vpnte_update::store::{EngineStore, InstallError, Installed, Origin, exe_name};
use vpnte_update::version::Version;

use super::checks::{Checks, Dyn};
use crate::install::pins;

/// The engines the feed may update here.
const IDS: [&str; 2] = [SINGBOX, XRAY];

/// The service's engines: the store, the checks of a new version and the paths sessions start.
pub struct ServiceEngines {
    store: EngineStore,
    install: PathBuf,
    checks: Arc<dyn Checks>,
    exes: watch::Sender<EngineExes>,
    /// Why a version folder may not run (`crate::sddl::untrusted_reason`; tests: temp folders).
    vet: fn(&Path) -> Option<String>,
}

impl ServiceEngines {
    /// The engines of the install folder `install` (compiled feed keys, real engine checks).
    pub fn open(install: &Path) -> Self {
        let store = EngineStore::new(install.join("engines"), install.to_owned());
        let checks = Arc::new(super::checks::EngineChecks);
        Self::with(install, store, checks, crate::sddl::untrusted_reason)
    }

    /// Over `store` (tests: throw-away keys), `checks` and the folder vetting `vet`.
    pub(crate) fn with(
        install: &Path,
        store: EngineStore,
        checks: Arc<dyn Checks>,
        vet: fn(&Path) -> Option<String>,
    ) -> Self {
        let store = store.not_below_bundled();
        for id in IDS {
            store.tidy(id);
        }
        let this = Self {
            store,
            install: install.to_owned(),
            checks,
            vet,
            exes: watch::channel(EngineExes {
                singbox: PathBuf::new(),
                xray: PathBuf::new(),
            })
            .0,
        };
        this.exes.send_replace(this.resolve());
        this
    }

    /// The engine files a session start uses (read at every engine start).
    pub fn exes(&self) -> watch::Receiver<EngineExes> {
        self.exes.subscribe()
    }

    /// Re-reads the store (after an install or a rollback).
    fn refresh(&self) {
        let now = self.resolve();
        self.exes.send_if_modified(|exes| {
            let changed = *exes != now;
            *exes = now;
            changed
        });
    }

    fn resolve(&self) -> EngineExes {
        EngineExes {
            singbox: self.exe(SINGBOX),
            xray: self.exe(XRAY),
        }
    }

    /// A downloaded version only from a folder users cannot change (it is created inside the
    /// admin-only install folder; checked anyway, as the install folder is at every start);
    /// otherwise the bundled file.
    fn exe(&self, id: &str) -> PathBuf {
        let resolved = self.store.resolve(id);
        if let Origin::Downloaded { version, .. } = resolved.origin {
            let dir = resolved.exe.parent().unwrap_or(Path::new(""));
            let fault = [dir, resolved.exe.as_path()].into_iter().find_map(self.vet);
            match fault {
                None => return resolved.exe,
                Some(reason) => {
                    tracing::error!(engine = id, %version, %reason, "downloaded engine not used")
                }
            }
        }
        self.install.join(exe_name(id).unwrap_or_default())
    }

    /// The version Tunnel mode runs for `id`: the downloaded one, else the bundled one while its
    /// files match this build's pins (after an exe swap they are the previous release's).
    pub(crate) fn current(&self, id: &str) -> Option<Version> {
        match self.store.resolve(id).origin {
            Origin::Downloaded { version, .. } => Some(version),
            Origin::Bundled => bundled_version(id).filter(|_| self.bundled_pinned(id)),
        }
    }

    fn bundled_pinned(&self, id: &str) -> bool {
        let names: &[&str] = match id {
            SINGBOX => &["sing-box.exe", "libcronet.dll"],
            _ => &["xray.exe"],
        };
        names.iter().all(|name| {
            let sha =
                std::fs::File::open(self.install.join(name)).and_then(|mut f| sha256_of(&mut f));
            sha.ok().is_some_and(|sha| pins::pin(name) == Some(sha))
        })
    }

    /// The engine entries of `feed` to install: allowed by this build, meant for this version,
    /// and newer than what Tunnel mode runs (or what it runs no longer passes the pins).
    pub(crate) fn wanted<'a>(&self, feed: &'a Feed) -> Vec<&'a EngineEntry> {
        let own = policy::app_version();
        IDS.iter()
            .filter_map(|&id| {
                let entry = feed.engine(id)?;
                let fits = engine_allowed(id, entry.version) && entry.app.contains(own);
                let floor = bundled_version(id).is_none_or(|b| entry.version >= b);
                let newer = self.current(id).map_or(floor, |c| entry.version > c);
                (fits && newer).then_some(entry)
            })
            .collect()
    }

    /// Installs `entry` from the verified `archive` (`feed` / `sig`: the signed feed listing
    /// it, stored with the version); sessions use it from their next engine start.
    pub(crate) async fn install(
        &self,
        entry: &EngineEntry,
        feed: &[u8],
        sig: &str,
        archive: Verified,
    ) -> Result<Installed, InstallError> {
        let checks = Dyn(self.checks.as_ref());
        let done = self.store.install(entry, feed, sig, archive, &checks).await;
        self.refresh();
        done
    }

    /// The trial of a fresh version, fed from the runtime: each start that ran a downloaded
    /// version on trial counts for it (`StartFinished { ok }`); the third failure in a row goes
    /// back to the previous version for the next start.
    pub async fn follow_starts(
        self: Arc<Self>,
        mut events: broadcast::Receiver<TunnelEvent>,
        starts: watch::Receiver<EngineStarts>,
        stop: CancellationToken,
    ) {
        let mut before = starts.borrow().clone();
        loop {
            let event = tokio::select! {
                () = stop.cancelled() => return,
                event = events.recv() => event,
            };
            match event {
                Ok(TunnelEvent::StartBegan { .. }) => before = starts.borrow().clone(),
                Ok(TunnelEvent::StartFinished { ok, .. }) => {
                    let after = starts.borrow().clone();
                    self.count(SINGBOX, &before.singbox, &after.singbox, ok);
                    self.count(XRAY, &before.xray, &after.xray, ok);
                    before = after;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    }

    fn count(&self, id: &str, before: &Started, after: &Started, ok: bool) {
        let resolved = self.store.resolve(id);
        let ran_it = after.count > before.count && after.exe.as_ref() == Some(&resolved.exe);
        if !ran_it || resolved.origin == Origin::Bundled {
            return;
        }
        match self.store.record_start(id, ok) {
            Ok(Some(back)) => {
                tracing::warn!(engine = id, from = %back.from, to = %back.to, "engine trial failed: switched back");
                self.refresh();
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(engine = id, %err, "engine trial not recorded"),
        }
    }
}

#[cfg(test)]
mod tests;
