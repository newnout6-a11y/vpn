use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use sha2::{Digest, Sha256};
use vpnte_update::download::{DownloadError, Verified, open_held};
use vpnte_update::feed::{Feed, verify};
use vpnte_update::net::Via;
use vpnte_update::policy::{SINGBOX, XRAY, bundled_version};
use vpnte_update::store::EngineStore;

use super::*;
use crate::update::testkit::{FolderChecks, TempDir, TestKey, engine, feed, service_entry};

const OWN: Version = Version(2, 0, 0);
const NEXT: Version = Version(2, 0, 1);
/// The engines' app range: this build and the next release alike.
const SERIES: &str = ">=2.0.0 <3.0.0";

/// The feed and the files, from memory (what a mirror would serve, signed or not), checked
/// against the size and SHA-256 asked for, as the real download does. A download whose URL
/// holds `pause` waits until the test lets it go.
#[derive(Default)]
struct Memory {
    feed: Mutex<Option<(Vec<u8>, String)>>,
    files: Mutex<HashMap<String, Vec<u8>>>,
    reads: AtomicUsize,
    pause: Mutex<Option<&'static str>>,
    reached: Notify,
    release: Notify,
}

#[async_trait]
impl Source for Memory {
    async fn feed(&self, keys: &[PublicKey], max_seq: u64) -> Result<Fetched, FetchError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let (bytes, sig) = self.feed.lock().clone().ok_or(FetchError::Unreachable)?;
        let feed = verify(&bytes, &sig, keys).map_err(FetchError::Refused)?;
        if feed.seq < max_seq {
            return Err(FetchError::Older);
        }
        let source = vpnte_update::fetch::Source {
            host: "memory".into(),
            via: Via::Direct,
        };
        let stale = false;
        Ok(Fetched {
            feed,
            bytes,
            sig,
            source,
            stale,
        })
    }

    async fn download(&self, wanted: &Wanted<'_>, dir: &Path) -> Result<Verified, DownloadError> {
        let url = wanted.urls.first().cloned().unwrap_or_default();
        let paused = *self.pause.lock();
        if paused.is_some_and(|p| url.contains(p)) {
            self.reached.notify_one();
            self.release.notified().await;
        }
        let body = self.files.lock().get(&url).cloned();
        let body = body.ok_or(DownloadError::Unreachable)?;
        if body.len() as u64 != wanted.size || hex::encode(Sha256::digest(&body)) != wanted.sha256 {
            return Err(DownloadError::Mismatch);
        }
        std::fs::create_dir_all(dir)?;
        let path = dir.join(wanted.name);
        std::fs::write(&path, body)?;
        let file = open_held(&path)?;
        Ok(Verified { path, file })
    }
}

struct Setup {
    _dir: TempDir,
    key: TestKey,
    memory: Arc<Memory>,
    updates: Arc<Updates>,
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    holds: watch::Sender<bool>,
    always: Arc<AtomicBool>,
    restarted: Arc<AtomicBool>,
    files: SwapFiles,
    engines: Arc<ServiceEngines>,
}

fn setup(with_keys: bool) -> Setup {
    setup_probing(with_keys, |_| Ok(()))
}

/// `probe`: whether a staged exe starts here.
fn setup_probing(with_keys: bool, probe: fn(&Path) -> std::io::Result<()>) -> Setup {
    let dir = TempDir::new("desk");
    let install = dir.path().join("install");
    std::fs::create_dir_all(install.join("update")).expect("install");
    std::fs::write(install.join("vpnte-service.exe"), b"running exe").expect("exe");
    let key = TestKey::new();
    let keys = if with_keys { key.keys() } else { &[] };
    let store = EngineStore::with_keys(install.join("engines"), install.clone(), keys);
    let engines = ServiceEngines::with(&install, store, Arc::new(FolderChecks), |_| None);
    let engines = Arc::new(engines);
    let memory = Arc::new(Memory::default());
    let status = watch::Sender::new(TunStatus::default());
    let holds = watch::Sender::new(false);
    let events = broadcast::Sender::new(16);
    let always = Arc::new(AtomicBool::new(false));
    let restarted = Arc::new(AtomicBool::new(false));
    let (blocks, flag) = (always.clone(), restarted.clone());
    let files = SwapFiles::unvetted(&install.join("vpnte-service.exe"));
    let updates = Updates::new(UpdatesDeps {
        own: OWN,
        keys,
        source: memory.clone(),
        engines: engines.clone(),
        files: files.clone(),
        record: dir.path().join("update.json"),
        status: status.subscribe(),
        events: events.subscribe(),
        holds: holds.subscribe(),
        always: Arc::new(move || blocks.load(Ordering::SeqCst)),
        probe,
        restart: Arc::new(move || flag.store(true, Ordering::SeqCst)),
        stop: CancellationToken::new(),
    });
    Setup {
        _dir: dir,
        key,
        memory,
        updates,
        status,
        events,
        holds,
        always,
        restarted,
        files,
        engines,
    }
}

/// The judge of an asker whose session it never is (or always is).
fn own(mine: bool) -> OwnSession {
    Arc::new(move || mine)
}

impl Setup {
    /// Publishes `feed` signed with the test key, `exe` at its service entry's URL and the
    /// archives of its engines.
    fn publish(&self, feed: &Feed, exe: &[u8]) {
        let bytes = serde_json::to_vec(feed).expect("json");
        *self.memory.feed.lock() = Some((bytes.clone(), self.key.sign(&bytes)));
        let mut files = self.memory.files.lock();
        if let Some(entry) = &feed.service {
            files.insert(entry.urls[0].clone(), exe.to_vec());
        }
        for e in &feed.engines {
            files.insert(e.archive.url.clone(), engine(&e.id, e.version, SERIES).1);
        }
    }

    /// A release feed: the service entry `service` and the bundled engines meant for `app`.
    fn release(&self, seq: u64, service: Option<(Version, &[u8])>, app: &str) -> Feed {
        let mut feed = feed(seq, service.map(|(v, exe)| service_entry(v, exe)));
        for id in [SINGBOX, XRAY] {
            let version = bundled_version(id).expect("bundled");
            feed.engines.push(engine(id, version, app).0);
        }
        feed
    }

    /// The next release (2.0.1, engines of this series) published with `exe` as its service.
    fn publish_next(&self, seq: u64, exe: &[u8]) {
        self.publish(&self.release(seq, Some((NEXT, exe)), SERIES), exe);
    }

    async fn ask(&self, ask: UpdateAsk, mine: bool) -> ServiceUpdateWire {
        self.updates.answer(ask, own(mine)).await
    }

    fn exe(&self) -> Vec<u8> {
        std::fs::read(&self.files.exe).expect("exe")
    }

    fn restarted(&self) -> bool {
        self.restarted.load(Ordering::SeqCst)
    }

    /// A TUN session runs (or no longer does).
    fn tunnel(&self, on: bool) {
        self.status.send_modify(|st| {
            st.running = on;
            st.capture = on.then_some(CaptureKind::Tun);
        });
    }

    /// The state once the check a `Take` started has ended (within 5 s).
    async fn settled(&self) -> ServiceUpdateWire {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = self.ask(UpdateAsk::State, false).await;
            if state.phase != UpdatePhase::Working || Instant::now() > deadline {
                return state;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits up to 2 s for `done`.
    async fn until(&self, done: impl Fn(&Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done(self) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        done(self)
    }
}

fn take(version: Version) -> UpdateAsk {
    UpdateAsk::Take {
        version: version.to_string(),
    }
}

fn phase(state: &ServiceUpdateWire) -> (UpdatePhase, Option<&str>) {
    (state.phase, state.target.as_deref())
}

/// Point 5: the app's `Take` of the next release, with no session in the way: the answer comes
/// at once (a check runs), the release's engines go in first, then the service stages the
/// listed exe, swaps it in and restarts after a grace for the answers.
#[tokio::test]
async fn a_take_swaps_the_release_in_and_restarts() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    let passed_over = s.files.staging.join("vpnte-service-2.0.0.exe");
    std::fs::write(&passed_over, b"an older staged exe").expect("stale");
    let first = s.ask(take(NEXT), false).await;
    assert_eq!(
        (first.version.as_str(), first.phase),
        ("2.0.0", UpdatePhase::Working)
    );
    let answer = s.settled().await;
    assert_eq!(phase(&answer), (UpdatePhase::Restarting, Some("2.0.1")));
    assert!(answer.checked_at.is_some());
    for id in [SINGBOX, XRAY] {
        assert_eq!(s.engines.current(id), bundled_version(id), "{id} first");
    }
    assert!(!passed_over.exists(), "only the staged release stays");
    assert_eq!(s.exe(), b"next exe");
    assert_eq!(
        swap::marker(&s.files).map(|m| (m.from, m.to)),
        Some((OWN, NEXT))
    );
    assert!(!s.restarted(), "the answers go out first");
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(300)).await;
    assert!(s.restarted());
}

/// D-S10: another user's session runs: the release is staged, not swapped; it goes in once the
/// session ended and its filters are gone.
#[tokio::test]
async fn another_users_session_waits_for_idle() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    s.tunnel(true);
    s.holds.send_replace(true);
    let watcher = tokio::spawn(s.updates.clone().run());
    s.ask(take(NEXT), false).await;
    let answer = s.settled().await;
    assert_eq!(phase(&answer), (UpdatePhase::Waiting, Some("2.0.1")));
    assert_eq!(s.exe(), b"running exe");
    s.tunnel(false);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.exe(), b"running exe", "the filters are still held");
    s.holds.send_replace(false);
    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .expect("swapped")
        .expect("task");
    assert_eq!(s.exe(), b"next exe");
}

/// svcupd-a1: another user's session crashed (or paused) and its kill switch still blocks: the
/// runtime reads idle, the held filters do not. A Take never restarts over that block.
#[tokio::test]
async fn held_filters_of_another_session_keep_the_service() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    s.tunnel(true);
    s.holds.send_replace(true);
    s.ask(take(NEXT), false).await;
    assert_eq!(
        phase(&s.settled().await),
        (UpdatePhase::Waiting, Some("2.0.1"))
    );
    // The engine crashed: the status reads idle, the block is held.
    s.tunnel(false);
    s.ask(take(NEXT), false).await;
    assert_eq!(
        phase(&s.settled().await),
        (UpdatePhase::Waiting, Some("2.0.1"))
    );
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(200)).await;
    assert_eq!(s.exe(), b"running exe");
    assert!(!s.restarted());
    // The asker's own held session may go: its app runs the installer next anyway.
    s.ask(take(NEXT), true).await;
    assert!(s.until(|s| s.exe() == b"next exe").await);
}

/// svcupd-a2: the ask is judged again right before the swap. A session another user starts
/// while the release downloads keeps the service; the release waits for idle.
#[tokio::test]
async fn a_session_that_starts_during_the_download_keeps_the_service() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    *s.memory.pause.lock() = Some("vpnte-service-");
    s.ask(take(NEXT), false).await;
    tokio::time::timeout(Duration::from_secs(5), s.memory.reached.notified())
        .await
        .expect("downloading");
    s.tunnel(true);
    s.memory.release.notify_one();
    assert_eq!(
        phase(&s.settled().await),
        (UpdatePhase::Waiting, Some("2.0.1"))
    );
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(200)).await;
    assert_eq!(s.exe(), b"running exe");
    assert!(!s.restarted());
}

/// svcupd-a11: after the swap the restart waits while a start that came in meanwhile is in
/// flight or its session runs; the new exe is in place and goes in once it ended.
#[tokio::test]
async fn a_start_within_the_grace_keeps_the_service_until_it_ends() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    let _runs = tokio::spawn(s.updates.clone().run());
    tokio::time::sleep(Duration::from_millis(20)).await;
    s.ask(take(NEXT), false).await;
    assert_eq!(phase(&s.settled().await).0, UpdatePhase::Restarting);
    s.events
        .send(TunnelEvent::StartBegan { generation: 1 })
        .expect("sent");
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(300)).await;
    assert!(!s.restarted(), "a start is in flight");
    s.tunnel(true);
    s.events
        .send(TunnelEvent::StartFinished {
            generation: 1,
            ok: true,
        })
        .expect("sent");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!s.restarted(), "its session runs");
    s.tunnel(false);
    assert!(s.until(Setup::restarted).await, "restarted once it ended");
}

/// svcupd-a12: a recent check stands in for a second ask; it settles from what is staged, so a
/// release that waited for another user's session goes in once that session ended, also when
/// the session ended while the second ask was being answered.
#[tokio::test]
async fn a_stand_in_check_lets_the_staged_release_go_in() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    s.tunnel(true);
    let _runs = tokio::spawn(s.updates.clone().run());
    s.ask(take(NEXT), false).await;
    assert_eq!(phase(&s.settled().await).0, UpdatePhase::Waiting);
    let job = s.updates.job.lock().await;
    s.ask(take(NEXT), false).await;
    s.tunnel(false);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.exe(), b"running exe", "the second ask's check is pending");
    drop(job);
    assert!(s.until(|s| s.exe() == b"next exe").await);
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 1, "one feed read");
}

/// Bytes that are not the listed ones never go in, an older or equal release is never taken,
/// and a feed under another key is refused: the exe stays and nothing restarts. A check that
/// could not do its part never reads as "up to date" (svcupd-a10).
#[tokio::test]
async fn only_a_verified_newer_release_is_taken() {
    let tampered = setup(true);
    let mut listed = tampered.release(9, Some((NEXT, b"next exe")), SERIES);
    tampered.publish(&listed, b"tampered");
    tampered.ask(take(NEXT), false).await;
    assert_eq!(tampered.settled().await.phase, UpdatePhase::Failed);
    let no_engine = setup(true);
    listed.engines[0].archive.sha256 = "00".repeat(32);
    no_engine.publish(&listed, b"next exe");
    no_engine.ask(take(NEXT), false).await;
    assert_eq!(no_engine.settled().await.phase, UpdatePhase::Failed);
    let same = setup(true);
    same.publish(&same.release(10, Some((OWN, b"same")), SERIES), b"same");
    assert_eq!(
        same.ask(take(OWN), false).await.phase,
        UpdatePhase::Idle,
        "nothing to do"
    );
    assert_eq!(same.memory.reads.load(Ordering::SeqCst), 0);
    let foreign = setup(true);
    let bytes =
        serde_json::to_vec(&foreign.release(11, Some((NEXT, b"next exe")), SERIES)).expect("json");
    *foreign.memory.feed.lock() = Some((bytes.clone(), TestKey::new().sign(&bytes)));
    foreign.ask(take(NEXT), false).await;
    assert_eq!(foreign.settled().await.phase, UpdatePhase::Failed);
    // Asked again within a minute: the failed check stands in, reported as it ended.
    foreign.ask(take(NEXT), false).await;
    assert_eq!(foreign.settled().await.phase, UpdatePhase::Failed);
    assert_eq!(foreign.memory.reads.load(Ordering::SeqCst), 1);
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(300)).await;
    for s in [&tampered, &no_engine, &same, &foreign] {
        assert_eq!(s.exe(), b"running exe");
        assert!(!s.restarted());
    }
}

/// Many asks at once read the feed once; a feed older than the one accepted is never used and
/// is no "up to date" either (svcupd-a10).
#[tokio::test]
async fn asks_share_one_check_and_an_older_feed_is_not_taken() {
    let s = setup(true);
    s.publish(&s.release(20, None, SERIES), b"");
    for _ in 0..5 {
        s.ask(take(NEXT), false).await;
    }
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 1);
    s.publish_next(19, b"next exe");
    *s.updates.checked.lock() = None;
    assert!(!s.updates.clone().check(NEXT).await);
    assert_eq!(s.settled().await.phase, UpdatePhase::Failed);
    assert_eq!(s.exe(), b"running exe");
}

/// svcupd-a3: a release staged from a feed the owner has since replaced by one that no longer
/// offers it is dropped, and never goes in.
#[tokio::test]
async fn a_withdrawn_release_never_goes_in() {
    let s = setup(true);
    s.publish_next(10, b"next exe");
    s.tunnel(true);
    s.ask(take(NEXT), false).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Waiting);
    s.publish(&s.release(11, None, SERIES), b"");
    *s.updates.checked.lock() = None;
    assert!(s.updates.clone().check(NEXT).await);
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    assert!(!s.files.staged(NEXT).exists(), "dropped");
    s.tunnel(false);
    assert!(!s.updates.take_if_asked());
    assert_eq!(s.exe(), b"running exe");
}

/// Without update keys the service never reads a feed and says so.
#[tokio::test]
async fn without_keys_nothing_is_checked() {
    let s = setup(false);
    s.publish_next(9, b"next exe");
    let answer = s.ask(take(NEXT), false).await;
    assert_eq!(answer.phase, UpdatePhase::Off);
    s.updates.clone().run().await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 0);
}

/// svcupd-b4: the service has no schedule of its own: a day and more after its start it has read
/// no feed and downloaded nothing (the user's update switches decide when the app asks).
#[tokio::test(start_paused = true)]
async fn nothing_is_checked_unless_an_app_asks() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    let _runs = tokio::spawn(s.updates.clone().run());
    tokio::time::sleep(Duration::from_secs(26 * 3600)).await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 0);
    assert_eq!(s.exe(), b"running exe");
}

/// svcupd-a7: a rollback asks for an older release (ignored: its installer brings that service),
/// and a release the feed does not list as its service is not taken either: the installer of
/// the asked version would otherwise replace what the service took.
#[tokio::test]
async fn only_the_asked_release_is_taken() {
    let s = setup(true);
    s.publish(
        &s.release(9, Some((Version(2, 0, 2), b"later")), SERIES),
        b"later",
    );
    assert_eq!(
        s.ask(take(Version(1, 9, 0)), true).await.phase,
        UpdatePhase::Idle
    );
    assert_eq!(
        s.memory.reads.load(Ordering::SeqCst),
        0,
        "a rollback asks nothing"
    );
    s.ask(take(NEXT), true).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    assert!(!s.files.staged(Version(2, 0, 2)).exists());
    assert_eq!(s.exe(), b"running exe");
}

/// svcupd-a6: the engines of a release for another minor series are not this build's to judge;
/// its installer brings it (nothing installed, nothing staged).
#[tokio::test]
async fn a_release_of_another_series_goes_through_its_installer() {
    let s = setup(true);
    let minor = Version(9, 1, 0);
    s.publish(
        &s.release(9, Some((minor, b"minor exe")), ">=9.1.0 <9.2.0"),
        b"minor exe",
    );
    s.ask(take(minor), true).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    assert!(!s.files.staged(minor).exists());
    assert_eq!(s.engines.current(SINGBOX), None, "nothing installed");
    assert_eq!(s.exe(), b"running exe");
}

/// svcupd-b7: while the kill switch blocks the machine with no tunnel ("Always" without a
/// session, or a held block after a drop) the service makes no request past its own permit; with
/// a TUN session running it asks through it.
#[tokio::test]
async fn a_blocking_kill_switch_without_a_tunnel_keeps_the_service_quiet() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    s.always.store(true, Ordering::SeqCst);
    s.ask(take(NEXT), true).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    let held = setup(true);
    held.publish_next(9, b"next exe");
    held.holds.send_replace(true);
    held.ask(take(NEXT), true).await;
    assert_eq!(held.settled().await.phase, UpdatePhase::Idle);
    for quiet in [&s, &held] {
        assert_eq!(quiet.memory.reads.load(Ordering::SeqCst), 0);
    }
    let tunnel = setup(true);
    tunnel.publish_next(9, b"next exe");
    tunnel.always.store(true, Ordering::SeqCst);
    tunnel.status.send_modify(|st| {
        st.running = true;
        st.capture = Some(CaptureKind::Tun);
    });
    tunnel.ask(take(NEXT), true).await;
    tunnel.settled().await;
    assert_eq!(tunnel.memory.reads.load(Ordering::SeqCst), 1);
}

/// svcupd-b3: a `Take` whose version does not parse is dropped before anything logs it.
#[tokio::test]
async fn a_take_without_a_valid_version_is_ignored() {
    let s = setup(true);
    s.publish_next(9, b"next exe");
    let forged = UpdateAsk::Take {
        version: format!("2.0.1\n{}", "x".repeat(16_000)),
    };
    assert_eq!(s.ask(forged, true).await.phase, UpdatePhase::Idle);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 0);
}

/// svcupd-a9: a staged exe that does not start on this Windows is never swapped in, and never
/// taken again (its installer is the way).
#[tokio::test]
async fn a_release_that_does_not_start_here_is_never_taken() {
    let s = setup_probing(true, |_| Err(std::io::ErrorKind::NotFound.into()));
    s.publish_next(9, b"next exe");
    s.ask(take(NEXT), true).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Failed);
    assert!(swap::failed_before(&s.files, NEXT));
    *s.updates.checked.lock() = None;
    s.ask(take(NEXT), true).await;
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    assert_eq!(s.exe(), b"running exe");
    assert!(!s.restarted());
}
