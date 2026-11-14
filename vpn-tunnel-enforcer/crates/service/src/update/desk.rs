//! The updater (task points 4, 5; review svcupd): a check when an app asks (`Take`, right before
//! a release's installer runs: the user's «Обновить»), never on a schedule of its own; engines
//! first, then the service exe, which goes in at once when the restart ends nothing but the
//! asker's own session, else waits staged until no session runs (or the service's next start).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
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
use super::in_flight::{InFlight, Quiet};
use super::source::Source;
use super::swap::{self, Staged, SwapFiles};
use super::{OwnSession, UpdateDesk};
use crate::proto::{ServiceUpdateWire, UpdateAsk, UpdatePhase};

/// The swap waits this long after it answered, so the answer reaches the app before the restart.
const ANSWER_GRACE: Duration = Duration::from_secs(1);
/// A `Take` within this time of a check uses it: the result of a check for the same release, the
/// feed it read for any other (many asks never mean many feed reads: svcfix-b2).
const RECENT: Duration = Duration::from_secs(60);
/// While a check runs, "Always" is read again this often (the status and the held filters wake
/// it at once): a block that begins mid-check ends its requests (svcfix-a3 / b1).
const BLOCK_POLL: Duration = Duration::from_secs(1);
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

/// The last check: when it ended, for which release, whether it went through, and the feed it
/// read (none: it read none).
#[derive(Clone)]
struct Checked {
    at: Instant,
    version: Version,
    ok: bool,
    feed: Option<Arc<Fetched>>,
}

/// The asks waiting for the one check task: the latest release asked, and whether the task runs.
#[derive(Default)]
struct Queue {
    next: Option<Version>,
    running: bool,
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
    /// The host's calls in flight (a start before the runtime's `StartBegan`: svcfix-a4).
    pub in_flight: InFlight,
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
    checked: Mutex<Option<Checked>>,
    queue: Mutex<Queue>,
    asked: Mutex<Option<Asked>>,
    /// Asks of a release at or below the running service (rollbacks) so far: one that comes
    /// during a check drops what that check staged (svcfix-a2).
    backs: AtomicU64,
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
            queue: Mutex::new(Queue::default()),
            asked: Mutex::new(None),
            backs: AtomicU64::new(0),
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
        let held = *self.deps.holds.borrow();
        blocks(&self.deps.status.borrow(), held, &*self.deps.always)
    }

    /// The staged release that may go in now ([`staged_release`]).
    fn ready(&self) -> Option<Staged> {
        let max_seq = self.record.lock().max_seq;
        let d = &self.deps;
        staged_release(&d.files, d.keys, d.own, max_seq, &d.engines)
    }

    /// Waiting when a verified release is staged (the idle watch looks), else Idle after a
    /// check that went through and Failed after one that did not.
    fn settle(&self, ok: bool) {
        match self.ready() {
            Some(staged) => {
                self.set(UpdatePhase::Waiting, Some(staged.version));
                self.staged.notify_one();
            }
            None if ok => self.set(UpdatePhase::Idle, None),
            None => self.set(UpdatePhase::Failed, None),
        }
    }
}

/// The kill switch blocks this machine's traffic with no tunnel running.
fn blocks(status: &TunStatus, held: bool, always: &(dyn Fn() -> bool + Send + Sync)) -> bool {
    let tunnel = status.running && status.capture == Some(CaptureKind::Tun);
    !tunnel && (held || always())
}

/// `fetched` lists release `version` as its service.
fn offers(fetched: &Fetched, version: Version) -> bool {
    fetched
        .feed
        .service
        .as_ref()
        .is_some_and(|e| e.version == version)
}

/// Cancels `cut` once the kill switch blocks with no tunnel; the status and the held filters
/// wake it at once, "Always" is read again every [`BLOCK_POLL`]. Ends with `cut`.
async fn cut_when_blocked(
    (mut status, mut holds, always): (
        watch::Receiver<TunStatus>,
        watch::Receiver<bool>,
        Arc<dyn Fn() -> bool + Send + Sync>,
    ),
    cut: CancellationToken,
) {
    let mut open = [true; 2];
    loop {
        let held = *holds.borrow();
        if blocks(&status.borrow(), held, &*always) {
            tracing::info!("the kill switch now blocks with no tunnel: the update check stops");
            return cut.cancel();
        }
        let [on_status, on_holds] = &mut open;
        tokio::select! {
            () = cut.cancelled() => return,
            changed = status.changed(), if *on_status => *on_status = changed.is_ok(),
            changed = holds.changed(), if *on_holds => *on_holds = changed.is_ok(),
            () = tokio::time::sleep(BLOCK_POLL) => {}
        }
    }
}

/// The release staged for the service `own` ([`swap::ready`]) while its engines are what Tunnel
/// mode runs now: judged again at every swap, as the engines' trial may have gone back since it
/// was staged (svcfix-a1). Such a release is dropped: its exe would refuse the engine files there
/// are, and nothing here brings it the ones it needs (its installer does).
pub fn staged_release(
    files: &SwapFiles,
    keys: &[PublicKey],
    own: Version,
    max_seq: u64,
    engines: &ServiceEngines,
) -> Option<Staged> {
    let staged = swap::ready(files, keys, own, max_seq)?;
    if engines.ready_for(&staged.feed, staged.version) {
        return Some(staged);
    }
    tracing::warn!(version = %staged.version, "the staged service update no longer fits the engines here: its installer brings it");
    swap::drop_staged(files);
    None
}

impl Updates {
    /// The one check task: checks the latest release asked until no ask waits (a burst of asks
    /// leaves one check behind, never one per ask: svcfix-b2).
    async fn work(self: Arc<Self>) {
        loop {
            let next = {
                let mut queue = self.queue.lock();
                let next = queue.next.take();
                queue.running = next.is_some();
                next
            };
            let Some(version) = next else {
                return;
            };
            self.clone().check(version).await;
        }
    }

    /// One check for release `version`, then the release goes in when it may. Within [`RECENT`]
    /// of the last check its result stands in for the same release, and the feed it read for any
    /// other. `true` = it went through: the feed was read, every wanted engine went in and the
    /// release was staged or is the installer's to bring.
    async fn check(self: Arc<Self>, version: Version) -> bool {
        let _job = self.job.lock().await;
        if self.phase() == UpdatePhase::Restarting {
            return true;
        }
        let backs = self.backs.load(Ordering::SeqCst);
        let last = self.checked.lock().clone();
        let last = last.filter(|c| c.at.elapsed() < RECENT);
        let ok = match last {
            Some(c) if c.version == version => c.ok,
            // The feed just read offers another release: nothing to read again for this one.
            Some(Checked {
                feed: Some(feed), ..
            }) if !offers(&feed, version) => true,
            last => {
                self.set(UpdatePhase::Working, None);
                let (ok, feed) = self.read_feed(version, last.and_then(|c| c.feed)).await;
                let at = Instant::now();
                *self.checked.lock() = Some(Checked {
                    at,
                    version,
                    ok,
                    feed,
                });
                ok
            }
        };
        if self.backs.load(Ordering::SeqCst) != backs {
            // The app went back meanwhile: nothing newer goes in by itself (svcfix-a2).
            swap::drop_staged(&self.deps.files);
            *self.checked.lock() = None;
        }
        // Another ask waits: its check settles (the app reads Working until then).
        if self.queue.lock().next.is_none() {
            // A stand-in settles from what is staged too, so the idle watch hears of it (a12).
            self.settle(ok);
        }
        self.take_if_asked();
        ok
    }

    /// The feed (the one read within [`RECENT`] when `cached`), then for release `version` its
    /// engines and its exe. Returns whether it went through and the feed it read.
    async fn read_feed(
        &self,
        version: Version,
        cached: Option<Arc<Fetched>>,
    ) -> (bool, Option<Arc<Fetched>>) {
        if self.closed() {
            tracing::info!(
                "the kill switch blocks with no tunnel: the release installer updates the service"
            );
            return (true, None);
        }
        let cut = self.requests();
        let _done = cut.clone().drop_guard();
        let Some(fetched) = self.feed(cached, &cut).await else {
            return (false, None);
        };
        let ok = self.take_release(&fetched, version, &cut).await;
        (ok, Some(fetched))
    }

    /// The token of one check's requests: cancelled at the service's stop, and as soon as the
    /// kill switch blocks with no tunnel (svcfix-a3 / b1: the requests would pass that block
    /// through the service's own permit).
    fn requests(&self) -> CancellationToken {
        let cut = self.deps.stop.child_token();
        let d = &self.deps;
        let watch = (d.status.clone(), d.holds.clone(), d.always.clone());
        tokio::spawn(cut_when_blocked(watch, cut.clone()));
        cut
    }

    /// `cached`, else the newest feed read now (accepted: an older one is never taken again);
    /// `None` when none was taken (logged).
    async fn feed(
        &self,
        cached: Option<Arc<Fetched>>,
        cut: &CancellationToken,
    ) -> Option<Arc<Fetched>> {
        if cached.is_some() {
            return cached;
        }
        let max_seq = self.record.lock().max_seq;
        let read = tokio::select! {
            () = cut.cancelled() => return None,
            read = self.deps.source.feed(self.deps.keys, max_seq) => read,
        };
        match read {
            Ok(fetched) if !fetched.stale => {
                self.accepted(&fetched);
                Some(Arc::new(fetched))
            }
            // Never "up to date" from a feed that could not be confirmed (svcupd-a10).
            Ok(_) | Err(FetchError::Older) => {
                tracing::warn!("only an outdated update feed answered");
                None
            }
            Err(err) => {
                tracing::warn!(%err, "update feed not read");
                None
            }
        }
    }

    /// Release `version` from the accepted feed: what is staged stays only while the feed still
    /// lists it (svcfix-b3), then the release's engines and its exe (staged only once the engines
    /// are in place: a new exe must find engine files its pins accept).
    async fn take_release(
        &self,
        fetched: &Fetched,
        version: Version,
        cut: &CancellationToken,
    ) -> bool {
        let (files, own) = (&self.deps.files, self.deps.own);
        let service = fetched.feed.service.as_ref();
        swap::keep_listed(files, own, service, &fetched.bytes, &fetched.sig);
        let Some(entry) = self.target(fetched, version) else {
            return true;
        };
        if !self.engines(fetched, cut).await {
            return false;
        }
        if !self.deps.engines.ready_for(&fetched.feed, entry.version) {
            tracing::info!(version = %entry.version, "the release's engines are not in place here: its installer brings it");
            swap::drop_staged(files);
            return true;
        }
        self.stage(fetched, entry, cut).await
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
    async fn engines(&self, fetched: &Fetched, cut: &CancellationToken) -> bool {
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
            let done = match self.deps.source.download(&wanted, staging, cut).await {
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
    async fn stage(
        &self,
        fetched: &Fetched,
        entry: &ServiceEntry,
        cut: &CancellationToken,
    ) -> bool {
        if self.ready().is_some_and(|s| s.version == entry.version) {
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
        let staged = match self
            .deps
            .source
            .download(&wanted, &files.staging, cut)
            .await
        {
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
        let Some(Staged {
            exe: staged,
            version,
            ..
        }) = self.ready()
        else {
            // Nothing verified is staged, or its engines went back meanwhile (svcfix-a1).
            if self.phase() == UpdatePhase::Waiting {
                self.set(UpdatePhase::Idle, None);
            }
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
    /// session ends: svcupd-a11) or cut a host call: a start the host accepted is one from its
    /// first step on, long before the runtime says so (svcfix-a4). The next start of the service
    /// runs the new exe in any case.
    async fn restart_when_free(self: Arc<Self>, own: Option<OwnSession>) {
        tokio::select! {
            () = self.deps.stop.cancelled() => return,
            () = tokio::time::sleep(ANSWER_GRACE) => {}
        }
        let mut changes = self.changes();
        loop {
            let quiet = self.deps.in_flight.quiet();
            let went_on = match quiet {
                Quiet::Settling(left) => tokio::select! {
                    () = self.deps.stop.cancelled() => false,
                    () = tokio::time::sleep(left) => true,
                },
                Quiet::Yes if self.free(own.as_ref()) => {
                    // A task woken before this decision (a start's first step) runs first.
                    tokio::task::yield_now().await;
                    if self.deps.in_flight.quiet() == Quiet::Yes && self.free(own.as_ref()) {
                        break;
                    }
                    true
                }
                Quiet::Busy | Quiet::Yes => changes.next(&self.deps.stop, &self.staged).await,
            };
            if !went_on {
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
            calls: self.deps.in_flight.subscribe(),
            open: [true; 4],
        }
    }

    /// The app is about to run the installer of `version`: that release's service is taken from
    /// the feed first. Answered right away: the check runs on the one check task (a recent one
    /// stands in) and the app reads the state. An older or equal release is a rollback.
    fn take(self: &Arc<Self>, version: Version, own: OwnSession) {
        if self.deps.keys.is_empty() {
            return;
        }
        if version <= self.deps.own {
            return self.back(version);
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
        let start = {
            let mut queue = self.queue.lock();
            queue.next = Some(version);
            !std::mem::replace(&mut queue.running, true)
        };
        if start {
            tokio::spawn(self.clone().work());
        }
    }

    /// The app goes back to `version` (its rollback, or the release this service runs): its
    /// installer brings that service, and nothing newer goes in by itself (svcupd-a7, svcfix-a2:
    /// a release staged earlier is dropped, also one a check running now stages).
    fn back(&self, version: Version) {
        tracing::info!(%version, "the app goes back: no newer service goes in by itself");
        self.backs.fetch_add(1, Ordering::SeqCst);
        self.queue.lock().next = None;
        *self.asked.lock() = None;
        *self.checked.lock() = None;
        swap::drop_staged(&self.deps.files);
        if self.phase() == UpdatePhase::Waiting {
            self.set(UpdatePhase::Idle, None);
        }
    }

    /// The release the app asked for goes in now when it is staged, the ask still stands and
    /// the restart ends no one else's session, judged now (svcupd-a2); `true` when it went in.
    fn take_if_asked(self: &Arc<Self>) -> bool {
        let asked = self.asked.lock().clone();
        let Some(asked) = asked.filter(|a| Instant::now() < a.until) else {
            return false;
        };
        let staged = self.ready().is_some_and(|s| s.version == asked.version);
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
    calls: watch::Receiver<usize>,
    open: [bool; 4],
}

impl Changes {
    /// `false` once `stop` came; `staged` wakes it too.
    async fn next(&mut self, stop: &CancellationToken, staged: &Notify) -> bool {
        let [status, holds, starting, calls] = &mut self.open;
        tokio::select! {
            () = stop.cancelled() => return false,
            changed = self.status.changed(), if *status => *status = changed.is_ok(),
            changed = self.holds.changed(), if *holds => *holds = changed.is_ok(),
            changed = self.starting.changed(), if *starting => *starting = changed.is_ok(),
            changed = self.calls.changed(), if *calls => *calls = changed.is_ok(),
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
