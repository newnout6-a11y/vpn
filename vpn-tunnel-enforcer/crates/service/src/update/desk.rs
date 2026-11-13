//! The updater (task points 2, 4, 5): the feed check at start (after 2-5 minutes), then daily and
//! when the app asks; engines first, then the service exe, which waits staged until no session
//! runs (or the next start of the service, or the app's `Take`) and then swaps in.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_tunnel::api::TunStatus;
use vpnte_update::download::Wanted;
use vpnte_update::feed::{FEED_FILE, PublicKey, SIG_FILE};
use vpnte_update::fetch::{FetchError, Fetched};
use vpnte_update::version::Version;

use super::UpdateDesk;
use super::engines::ServiceEngines;
use super::source::Source;
use super::swap::{self, SwapFiles};
use crate::proto::{ServiceUpdateWire, UpdateAsk, UpdatePhase};

/// The swap waits this long after it answered, so the answer reaches the app before the restart.
const ANSWER_GRACE: Duration = Duration::from_secs(1);
/// A `Take` within this time of the last check uses that check (many asks never mean many
/// feed reads).
const RECENT: Duration = Duration::from_secs(60);
/// How long a `Take` stands: past it, a release staged later waits for idle like any other.
const ASKED_FOR: Duration = Duration::from_secs(180);

/// A check's end: the phase and target it left, and whether it succeeded.
type Outcome = ((UpdatePhase, Option<Version>), bool);

/// The app's `Take`: the release it is about to install, and whether the service may restart
/// for it right away (judged when it asked).
#[derive(Debug, Clone, Copy)]
struct Asked {
    version: Version,
    may_restart: bool,
    until: Instant,
}

/// What the updater keeps across restarts (`service\update.json`, private): the newest feed it
/// accepted (an older one is never taken again) and when.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Record {
    max_seq: u64,
    checked_at: Option<UnixMs>,
}

/// Everything the updater uses.
pub struct UpdatesDeps {
    /// The running service.
    pub own: Version,
    /// The compiled feed keys (tests: throw-away ones); none: the updater never checks.
    pub keys: &'static [PublicKey],
    pub source: Arc<dyn Source>,
    pub engines: Arc<ServiceEngines>,
    pub files: SwapFiles,
    /// `service\update.json`.
    pub record: PathBuf,
    /// The runtime's status and whether the kill switch holds a session's filters: idle is
    /// neither.
    pub status: watch::Receiver<TunStatus>,
    pub holds: watch::Receiver<bool>,
    /// Ends the service for the SCM to start the exe now in place.
    pub restart: Arc<dyn Fn() + Send + Sync>,
}

/// The service's updater.
pub struct Updates {
    deps: UpdatesDeps,
    state: Mutex<(UpdatePhase, Option<Version>)>,
    record: Mutex<Record>,
    /// One check at a time (the schedule and `Take` share it).
    job: tokio::sync::Mutex<()>,
    /// When the last check ended, with its outcome (what a stand-in reports again).
    checked: Mutex<Option<(Instant, Outcome)>>,
    asked: Mutex<Option<Asked>>,
    /// A check now (the app's `Take` runs its own; this one serves the schedule loop).
    now: Arc<Notify>,
    /// A new exe was staged: the idle watch looks again.
    staged: Notify,
}

impl Updates {
    pub fn new(deps: UpdatesDeps) -> Arc<Self> {
        let record = std::fs::read(&deps.record)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let phase = if deps.keys.is_empty() {
            UpdatePhase::Off
        } else {
            UpdatePhase::Idle
        };
        Arc::new(Self {
            deps,
            state: Mutex::new((phase, None)),
            record: Mutex::new(record),
            job: tokio::sync::Mutex::new(()),
            checked: Mutex::new(None),
            asked: Mutex::new(None),
            now: Arc::new(Notify::new()),
            staged: Notify::new(),
        })
    }

    /// The schedule and the idle swaps until `stop`; nothing runs without keys.
    pub async fn run(self: Arc<Self>, stop: CancellationToken) {
        if self.deps.keys.is_empty() {
            return;
        }
        tokio::spawn(self.clone().swap_when_idle(stop.clone()));
        let this = self.clone();
        let check = move |_| this.clone().check(false);
        vpnte_update::check::run(check, self.now.clone(), stop).await;
    }

    fn phase(&self) -> UpdatePhase {
        self.state.lock().0
    }

    fn set(&self, phase: UpdatePhase, target: Option<Version>) {
        *self.state.lock() = (phase, target);
    }

    /// No session runs and no session's filters are held.
    fn idle(&self) -> bool {
        let status = self.deps.status.borrow();
        !status.running && status.capture.is_none() && !*self.deps.holds.borrow()
    }

    /// The staged exe that may go in now, if any.
    fn ready(&self) -> Option<(PathBuf, Version)> {
        swap::ready(&self.deps.files, self.deps.keys, self.deps.own)
    }

    /// Idle or Waiting, from what is staged.
    fn settle(&self) {
        match self.ready() {
            Some((_, version)) => {
                self.set(UpdatePhase::Waiting, Some(version));
                self.staged.notify_one();
            }
            None => self.set(UpdatePhase::Idle, None),
        }
    }
}

impl Updates {
    /// One check (`recent_will_do`: a check that ended within [`RECENT`] stands in for it), then
    /// an asked-for release goes in when it may. `true` = the feed was read and every wanted
    /// engine went in.
    async fn check(self: Arc<Self>, recent_will_do: bool) -> bool {
        let _job = self.job.lock().await;
        if self.phase() == UpdatePhase::Restarting {
            return true;
        }
        let last = *self.checked.lock();
        let ok = match last {
            Some((at, (outcome, ok))) if recent_will_do && at.elapsed() < RECENT => {
                *self.state.lock() = outcome;
                ok
            }
            _ => {
                let ok = self.read_feed().await;
                let outcome = *self.state.lock();
                *self.checked.lock() = Some((Instant::now(), (outcome, ok)));
                ok
            }
        };
        self.take_if_asked();
        ok
    }

    /// The feed, the engines it lists, then the service exe (staged only once the engines are in
    /// place: a new exe must find engine files its pins accept).
    async fn read_feed(&self) -> bool {
        self.set(UpdatePhase::Working, None);
        let max_seq = self.record.lock().max_seq;
        let fetched = match self.deps.source.feed(self.deps.keys, max_seq).await {
            Ok(fetched) if !fetched.stale => fetched,
            Ok(_) | Err(FetchError::Older) => {
                self.settle();
                return true;
            }
            Err(err) => {
                tracing::warn!(%err, "update feed not read");
                self.set(UpdatePhase::Failed, None);
                return false;
            }
        };
        self.accepted(&fetched);
        let engines = self.engines(&fetched).await;
        if engines {
            self.stage(&fetched).await;
        }
        self.settle();
        engines
    }

    fn accepted(&self, fetched: &Fetched) {
        let mut record = self.record.lock();
        record.max_seq = record.max_seq.max(fetched.feed.seq);
        record.checked_at = Some(now_ms());
        let saved = serde_json::to_vec(&*record)
            .map_err(std::io::Error::other)
            .and_then(|bytes| crate::paths::write_synced(&self.deps.record, &bytes));
        if let Err(err) = saved {
            tracing::warn!(%err, "update record not saved");
        }
    }

    /// Every engine the feed has for Tunnel mode, each checked into its own version folder.
    async fn engines(&self, fetched: &Fetched) -> bool {
        let mut all = true;
        for entry in self.deps.engines.wanted(&fetched.feed) {
            let name = format!("{}-{}.zip", entry.id, entry.version);
            let wanted = Wanted {
                urls: std::slice::from_ref(&entry.archive.url),
                size: entry.archive.size,
                sha256: &entry.archive.sha256,
                name: &name,
            };
            let staging = &self.deps.files.staging;
            let done = match self.deps.source.download(&wanted, staging).await {
                Ok(archive) => {
                    let installed =
                        self.deps
                            .engines
                            .install(entry, &fetched.bytes, &fetched.sig, archive);
                    installed.await.map_err(|e| e.to_string())
                }
                Err(err) => Err(err.to_string()),
            };
            match done {
                Ok(done) => {
                    tracing::info!(engine = %done.id, version = %done.version, "engine installed for Tunnel mode")
                }
                Err(err) => {
                    tracing::warn!(engine = %entry.id, version = %entry.version, %err, "engine not installed");
                    all = false;
                }
            }
        }
        all
    }

    /// The feed's service exe above this one (and not failed here before), downloaded into the
    /// staging folder with the signed feed that lists it.
    async fn stage(&self, fetched: &Fetched) {
        let Some(entry) = fetched.feed.service.as_ref() else {
            return;
        };
        let files = &self.deps.files;
        if entry.version <= self.deps.own || swap::failed_before(files, entry.version) {
            return;
        }
        if self.ready().is_some_and(|(_, v)| v == entry.version) {
            return;
        }
        let path = files.staged(entry.version);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let wanted = Wanted {
            urls: &entry.urls,
            size: entry.size,
            sha256: &entry.sha256,
            name: &name,
        };
        swap::drop_staged_except(files, &name);
        let staged = match self.deps.source.download(&wanted, &files.staging).await {
            Ok(held) => held,
            Err(err) => {
                return tracing::warn!(version = %entry.version, %err, "service update not downloaded");
            }
        };
        drop(staged.file);
        let kept = std::fs::write(files.staging.join(FEED_FILE), &fetched.bytes)
            .and_then(|()| std::fs::write(files.staging.join(SIG_FILE), &fetched.sig));
        match kept {
            Ok(()) => tracing::info!(version = %entry.version, "service update staged"),
            Err(err) => tracing::warn!(%err, "service update feed not kept"),
        }
    }
}

impl Updates {
    /// Puts the staged exe in place and restarts the service shortly after (the answer to a
    /// `Take` goes out first). `false` when nothing verified is staged or the swap failed.
    fn swap_now(&self) -> bool {
        let Some((staged, version)) = self.ready() else {
            return false;
        };
        if let Err(err) = swap::swap_in(&self.deps.files, &staged, self.deps.own, version) {
            tracing::error!(%version, %err, "service update not swapped in");
            self.set(UpdatePhase::Failed, None);
            return false;
        }
        tracing::info!(%version, "service update swapped in: restarting");
        self.set(UpdatePhase::Restarting, Some(version));
        let restart = self.deps.restart.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ANSWER_GRACE).await;
            restart();
        });
        true
    }

    /// A staged exe goes in once no session runs (a session is never ended for an update).
    async fn swap_when_idle(self: Arc<Self>, stop: CancellationToken) {
        let (mut status, mut holds) = (self.deps.status.clone(), self.deps.holds.clone());
        // A closed watch never changes again (no TUN in an untrusted folder: nothing held).
        let (mut status_open, mut holds_open) = (true, true);
        loop {
            if self.phase() == UpdatePhase::Waiting && self.idle() && self.swap_now() {
                return;
            }
            tokio::select! {
                () = stop.cancelled() => return,
                changed = status.changed(), if status_open => status_open = changed.is_ok(),
                changed = holds.changed(), if holds_open => holds_open = changed.is_ok(),
                () = self.staged.notified() => {}
            }
        }
    }

    /// The app is about to run the installer of `version`: that release's service is taken from
    /// the feed first, at once when `may_restart`, else once idle. Answered right away: the check
    /// runs on its own task (one at a time; a recent one stands in) and the app reads the state.
    fn take(self: &Arc<Self>, version: &str, may_restart: bool) {
        let Ok(version) = version.parse::<Version>() else {
            return;
        };
        if version <= self.deps.own || self.deps.keys.is_empty() {
            return;
        }
        let until = Instant::now() + ASKED_FOR;
        *self.asked.lock() = Some(Asked {
            version,
            may_restart,
            until,
        });
        if self.take_if_asked() || self.phase() == UpdatePhase::Restarting {
            return;
        }
        self.set(UpdatePhase::Working, None);
        tokio::spawn(self.clone().check(true));
    }

    /// The release the app asked for goes in now when it is staged and the ask allowed a restart
    /// (and still stands); `true` when it went in.
    fn take_if_asked(&self) -> bool {
        let asked = *self.asked.lock();
        let Some(asked) = asked.filter(|a| a.may_restart && Instant::now() < a.until) else {
            return false;
        };
        let staged = self.ready().is_some_and(|(_, v)| v == asked.version);
        staged && self.phase() != UpdatePhase::Restarting && self.swap_now()
    }

    /// What the pipe reports.
    fn wire(&self) -> ServiceUpdateWire {
        let (phase, target) = *self.state.lock();
        ServiceUpdateWire {
            version: self.deps.own.to_string(),
            phase,
            target: target.map(|v| v.to_string()),
            checked_at: self.record.lock().checked_at,
        }
    }
}

#[async_trait]
impl UpdateDesk for Arc<Updates> {
    async fn answer(&self, ask: UpdateAsk, may_restart: bool) -> ServiceUpdateWire {
        if let UpdateAsk::Take { version } = ask {
            tracing::info!(%version, may_restart, "the app asks for a service update");
            self.take(&version, may_restart);
        }
        self.wire()
    }
}

#[cfg(test)]
mod tests;
