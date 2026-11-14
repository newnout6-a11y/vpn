//! The updater (task points 4, 5; review svcupd): a check when an app asks (`Take`, right before
//! a release's installer runs: the user's «Обновить»), never on a schedule of its own; engines
//! first, then the service exe, which goes in at once when the restart ends nothing but the
//! asker's own session, else waits staged until no session runs (or the service's next start).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_tunnel::api::{CaptureKind, TunStatus, TunnelEvent};
use vpnte_update::download::Wanted;
use vpnte_update::feed::{FEED_FILE, PublicKey, SIG_FILE, ServiceEntry};
use vpnte_update::fetch::{FetchError, Fetched};
use vpnte_update::version::Version;

use super::engines::ServiceEngines;
use super::source::Source;
use super::swap::{self, SwapFiles};
use super::{OwnSession, UpdateDesk};
use crate::proto::{ServiceUpdateWire, UpdateAsk, UpdatePhase};

/// The swap waits this long after it answered, so the answer reaches the app before the restart.
const ANSWER_GRACE: Duration = Duration::from_secs(1);
/// A `Take` within this time of a check for the same release uses that check (many asks never
/// mean many feed reads).
const RECENT: Duration = Duration::from_secs(60);
/// How long a `Take` may restart the service: past it, a release staged later waits for idle.
const ASKED_FOR: Duration = Duration::from_secs(180);

/// The app's `Take`: the release it is about to install, and who may lose a session to the
/// restart (asked again whenever the restart comes closer).
#[derive(Clone)]
struct Asked {
    version: Version,
    own: OwnSession,
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

impl Record {
    fn read(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

/// The `seq` of the newest feed the updater accepted (`record`: `service\update.json`): a staged
/// release from an older feed is not taken (svcupd-a3).
pub fn accepted_seq(record: &Path) -> u64 {
    Record::read(record).max_seq
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
    /// The runtime's status, its events (a start in flight reads idle in the status until the
    /// session runs) and whether the kill switch holds a session's filters: idle is none of them.
    pub status: watch::Receiver<TunStatus>,
    pub events: broadcast::Receiver<TunnelEvent>,
    pub holds: watch::Receiver<bool>,
    /// "Always" is in force: its block stays while no session runs.
    pub always: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Whether a staged exe starts on this Windows ([`swap::probe`]; tests: a stand-in).
    pub probe: fn(&Path) -> std::io::Result<()>,
    /// Ends the service for the SCM to start the exe now in place.
    pub restart: Arc<dyn Fn() + Send + Sync>,
    /// The service's stop.
    pub stop: CancellationToken,
}

/// The service's updater.
pub struct Updates {
    deps: UpdatesDeps,
    state: Mutex<(UpdatePhase, Option<Version>)>,
    record: Mutex<Record>,
    /// One check at a time (asks share it).
    job: tokio::sync::Mutex<()>,
    /// When the last check ended, for which release, and whether it succeeded.
    checked: Mutex<Option<(Instant, Version, bool)>>,
    asked: Mutex<Option<Asked>>,
    /// A session start is in flight (from the runtime's events).
    starting: watch::Sender<bool>,
    /// A new exe was staged: the idle watch looks again.
    staged: Notify,
}

impl Updates {
    pub fn new(deps: UpdatesDeps) -> Arc<Self> {
        let record = Record::read(&deps.record);
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
            starting: watch::Sender::new(false),
            staged: Notify::new(),
        })
    }

    /// Follows the session starts and swaps a staged release in once idle, until the stop;
    /// nothing runs without keys. No schedule: a check runs only when an app asks.
    pub async fn run(self: Arc<Self>) {
        if self.deps.keys.is_empty() {
            return;
        }
        tokio::spawn(self.clone().follow_starts());
        self.swap_when_idle().await;
    }

    fn phase(&self) -> UpdatePhase {
        self.state.lock().0
    }

    fn set(&self, phase: UpdatePhase, target: Option<Version>) {
        *self.state.lock() = (phase, target);
    }

    /// No session runs or starts and no session's filters are held.
    fn idle(&self) -> bool {
        let status = self.deps.status.borrow();
        let busy = status.running || status.capture.is_some();
        !busy && !*self.starting.borrow() && !*self.deps.holds.borrow()
    }

    /// A restart now ends no one else's session: idle, or the session is the asker's (`own`).
    fn free(&self, own: Option<&OwnSession>) -> bool {
        self.idle() || own.is_some_and(|own| own())
    }

    /// The kill switch blocks this machine's traffic with no tunnel running ("Always" without a
    /// session, or a held block after a drop): the service's own requests would pass that block
    /// through its program permit, so it makes none (svcupd-b7).
    fn closed(&self) -> bool {
        let status = self.deps.status.borrow();
        let tunnel = status.running && status.capture == Some(CaptureKind::Tun);
        !tunnel && (*self.deps.holds.borrow() || (self.deps.always)())
    }

    /// The staged exe that may go in now, if any.
    fn ready(&self) -> Option<(PathBuf, Version)> {
        let max_seq = self.record.lock().max_seq;
        swap::ready(&self.deps.files, self.deps.keys, self.deps.own, max_seq)
    }

    /// Waiting when a verified release is staged (the idle watch looks), else Idle after a
    /// check that went through and Failed after one that did not.
    fn settle(&self, ok: bool) {
        match self.ready() {
            Some((_, version)) => {
                self.set(UpdatePhase::Waiting, Some(version));
                self.staged.notify_one();
            }
            None if ok => self.set(UpdatePhase::Idle, None),
            None => self.set(UpdatePhase::Failed, None),
        }
    }
}

impl Updates {
    /// One check for release `version` (a check for it that ended within [`RECENT`] stands in),
    /// then the release goes in when it may. `true` = it went through: the feed was read, every
    /// wanted engine went in and the release was staged or is the installer's to bring.
    async fn check(self: Arc<Self>, version: Version) -> bool {
        let _job = self.job.lock().await;
        if self.phase() == UpdatePhase::Restarting {
            return true;
        }
        let last = *self.checked.lock();
        let ok = match last {
            Some((at, asked, ok)) if asked == version && at.elapsed() < RECENT => ok,
            _ => {
                self.set(UpdatePhase::Working, None);
                let ok = self.read_feed(version).await;
                *self.checked.lock() = Some((Instant::now(), version, ok));
                ok
            }
        };
        // A stand-in settles from what is staged too, so the idle watch hears of it (svcupd-a12).
        self.settle(ok);
        self.take_if_asked();
        ok
    }

    /// The feed, then for release `version` its engines and its exe (staged only once the
    /// engines are in place: a new exe must find engine files its pins accept).
    async fn read_feed(&self, version: Version) -> bool {
        if self.closed() {
            tracing::info!(
                "the kill switch blocks with no tunnel: the release installer updates the service"
            );
            return true;
        }
        let max_seq = self.record.lock().max_seq;
        let fetched = match self.deps.source.feed(self.deps.keys, max_seq).await {
            Ok(fetched) if !fetched.stale => fetched,
            // Never "up to date" from a feed that could not be confirmed (svcupd-a10).
            Ok(_) | Err(FetchError::Older) => {
                tracing::warn!("only an outdated update feed answered");
                return false;
            }
            Err(err) => {
                tracing::warn!(%err, "update feed not read");
                return false;
            }
        };
        self.accepted(&fetched);
        let Some(entry) = self.target(&fetched, version) else {
            swap::drop_staged(&self.deps.files);
            return true;
        };
        if !self.engines(&fetched).await {
            return false;
        }
        if !self.deps.engines.ready_for(&fetched.feed, entry.version) {
            tracing::info!(version = %entry.version, "the release's engines are not in place here: its installer brings it");
            swap::drop_staged(&self.deps.files);
            return true;
        }
        self.stage(&fetched, entry).await
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

    /// The feed's service entry when it is release `version` itself (the installer of that
    /// release runs next and would undo any other), above this service, not failed here, and its
    /// engines are ones this build can check (svcupd-a6).
    fn target<'a>(&self, fetched: &'a Fetched, version: Version) -> Option<&'a ServiceEntry> {
        let entry = fetched.feed.service.as_ref()?;
        let new = entry.version == version && entry.version > self.deps.own;
        let usable = new && !swap::failed_before(&self.deps.files, entry.version);
        if !usable {
            return None;
        }
        if !self.deps.engines.meant_for(&fetched.feed, entry.version) {
            tracing::info!(%version, "the release's engines are not for this build: its installer brings it");
            return None;
        }
        Some(entry)
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

    /// `entry`'s exe, downloaded into the staging folder with the signed feed that lists it, once
    /// it starts on this Windows (svcupd-a9); one that does not is never staged again. `false`
    /// when it did not arrive or does not start.
    async fn stage(&self, fetched: &Fetched, entry: &ServiceEntry) -> bool {
        if self.ready().is_some_and(|(_, v)| v == entry.version) {
            return true;
        }
        let files = &self.deps.files;
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
        swap::drop_staged(files);
        let staged = match self.deps.source.download(&wanted, &files.staging).await {
            Ok(held) => held,
            Err(err) => {
                tracing::warn!(version = %entry.version, %err, "service update not downloaded");
                return false;
            }
        };
        drop(staged.file);
        let (probe, exe) = (self.deps.probe, path.clone());
        let started = tokio::task::spawn_blocking(move || probe(&exe)).await;
        if let Err(err) = started.unwrap_or_else(|e| Err(std::io::Error::other(e))) {
            tracing::error!(version = %entry.version, %err, "service update does not start here: not taken");
            swap::refuse(files, self.deps.own, entry.version);
            swap::drop_staged(files);
            return false;
        }
        let kept = std::fs::write(files.staging.join(FEED_FILE), &fetched.bytes)
            .and_then(|()| std::fs::write(files.staging.join(SIG_FILE), &fetched.sig));
        match kept {
            Ok(()) => {
                tracing::info!(version = %entry.version, "service update staged");
                true
            }
            Err(err) => {
                tracing::warn!(%err, "service update feed not kept");
                false
            }
        }
    }
}

impl Updates {
    /// Puts the staged exe in place; the service restarts once that ends no one else's session
    /// (`own`: the asker's, judged again then). `false` when nothing verified is staged or the
    /// swap failed.
    fn swap_now(self: &Arc<Self>, own: Option<OwnSession>) -> bool {
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
        tokio::spawn(self.clone().restart_when_free(own));
        true
    }

    /// The restart after a swap: the answers go out first, then it waits while it would end
    /// someone else's session (a start that came in meanwhile keeps this process until that
    /// session ends: svcupd-a11). The next start of the service runs the new exe in any case.
    async fn restart_when_free(self: Arc<Self>, own: Option<OwnSession>) {
        tokio::select! {
            () = self.deps.stop.cancelled() => return,
            () = tokio::time::sleep(ANSWER_GRACE) => {}
        }
        let mut changes = self.changes();
        while !self.free(own.as_ref()) {
            if !changes.next(&self.deps.stop, &self.staged).await {
                return;
            }
        }
        (self.deps.restart)();
    }

    /// A staged exe goes in once no session runs (a session is never ended for an update).
    async fn swap_when_idle(self: Arc<Self>) {
        let mut changes = self.changes();
        loop {
            if self.phase() == UpdatePhase::Waiting && self.idle() && self.swap_now(None) {
                return;
            }
            if !changes.next(&self.deps.stop, &self.staged).await {
                return;
            }
        }
    }

    /// A start in flight is not idle: the status reads idle until its session runs.
    async fn follow_starts(self: Arc<Self>) {
        let mut events = self.deps.events.resubscribe();
        loop {
            let event = tokio::select! {
                () = self.deps.stop.cancelled() => return,
                event = events.recv() => event,
            };
            match event {
                Ok(TunnelEvent::StartBegan { .. }) => self.starting.send_replace(true),
                // Lagged: the status is the gauge again (never stuck busy).
                Ok(TunnelEvent::StartFinished { .. }) | Err(RecvError::Lagged(_)) => {
                    self.starting.send_replace(false)
                }
                Ok(_) => continue,
                Err(RecvError::Closed) => return,
            };
        }
    }

    fn changes(&self) -> Changes {
        Changes {
            status: self.deps.status.clone(),
            holds: self.deps.holds.clone(),
            starting: self.starting.subscribe(),
            open: [true; 3],
        }
    }

    /// The app is about to run the installer of `version`: that release's service is taken from
    /// the feed first. Answered right away: the check runs on its own task (one at a time; a
    /// recent one stands in) and the app reads the state.
    fn take(self: &Arc<Self>, version: Version, own: OwnSession) {
        if version <= self.deps.own || self.deps.keys.is_empty() {
            return;
        }
        let until = Instant::now() + ASKED_FOR;
        *self.asked.lock() = Some(Asked {
            version,
            own,
            until,
        });
        if self.phase() == UpdatePhase::Restarting || self.take_if_asked() {
            return;
        }
        self.set(UpdatePhase::Working, None);
        tokio::spawn(self.clone().check(version));
    }

    /// The release the app asked for goes in now when it is staged, the ask still stands and
    /// the restart ends no one else's session, judged now (svcupd-a2); `true` when it went in.
    fn take_if_asked(self: &Arc<Self>) -> bool {
        let asked = self.asked.lock().clone();
        let Some(asked) = asked.filter(|a| Instant::now() < a.until) else {
            return false;
        };
        let staged = self.ready().is_some_and(|(_, v)| v == asked.version);
        let restarting = self.phase() == UpdatePhase::Restarting;
        staged && !restarting && self.free(Some(&asked.own)) && self.swap_now(Some(asked.own))
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

/// The next change of what idle reads (a closed watch never changes again).
struct Changes {
    status: watch::Receiver<TunStatus>,
    holds: watch::Receiver<bool>,
    starting: watch::Receiver<bool>,
    open: [bool; 3],
}

impl Changes {
    /// `false` once `stop` came; `staged` wakes it too.
    async fn next(&mut self, stop: &CancellationToken, staged: &Notify) -> bool {
        let [status, holds, starting] = &mut self.open;
        tokio::select! {
            () = stop.cancelled() => return false,
            changed = self.status.changed(), if *status => *status = changed.is_ok(),
            changed = self.holds.changed(), if *holds => *holds = changed.is_ok(),
            changed = self.starting.changed(), if *starting => *starting = changed.is_ok(),
            () = staged.notified() => {}
        }
        true
    }
}

#[async_trait]
impl UpdateDesk for Arc<Updates> {
    async fn answer(&self, ask: UpdateAsk, own: OwnSession) -> ServiceUpdateWire {
        if let UpdateAsk::Take { version } = ask {
            // Parsed before anything logs it: a client's text never reaches the log (svcupd-b3).
            match version.parse::<Version>() {
                Ok(version) => {
                    tracing::info!(%version, "the app asks for a service update");
                    self.take(version, own);
                }
                Err(_) => tracing::info!("an update ask without a valid version: ignored"),
            }
        }
        self.wire()
    }
}

#[cfg(test)]
mod tests;
