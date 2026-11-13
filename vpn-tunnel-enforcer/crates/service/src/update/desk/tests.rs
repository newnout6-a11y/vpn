use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vpnte_update::download::{DownloadError, Verified, open_held};
use vpnte_update::feed::{Feed, verify};
use vpnte_update::net::Via;
use vpnte_update::store::EngineStore;

use super::*;
use crate::update::checks::Checks;
use crate::update::testkit::{TempDir, TestKey, feed, service_entry};

const OWN: Version = Version(2, 0, 0);
const NEXT: Version = Version(2, 0, 1);

/// The feed and the files, from memory (what a mirror would serve, signed or not).
#[derive(Default)]
struct Memory {
    feed: Mutex<Option<(Vec<u8>, String)>>,
    files: Mutex<HashMap<String, Vec<u8>>>,
    reads: AtomicUsize,
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
        let body = self.files.lock().get(&url).cloned();
        let body = body.ok_or(DownloadError::Unreachable)?;
        std::fs::create_dir_all(dir)?;
        let path = dir.join(wanted.name);
        std::fs::write(&path, body)?;
        let file = open_held(&path)?;
        Ok(Verified { path, file })
    }
}

struct NoChecks;

#[async_trait]
impl Checks for NoChecks {
    async fn version(&self, _: &str, _: &Path) -> std::io::Result<Version> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    async fn configs(&self, _: &str, _: &Path) -> Result<(), String> {
        Ok(())
    }
}

struct Setup {
    _dir: TempDir,
    key: TestKey,
    memory: Arc<Memory>,
    updates: Arc<Updates>,
    status: watch::Sender<TunStatus>,
    holds: watch::Sender<bool>,
    restarted: Arc<AtomicBool>,
    files: SwapFiles,
}

fn setup(with_keys: bool) -> Setup {
    let dir = TempDir::new("desk");
    let install = dir.path().join("install");
    std::fs::create_dir_all(install.join("update")).expect("install");
    std::fs::write(install.join("vpnte-service.exe"), b"running exe").expect("exe");
    let key = TestKey::new();
    let keys = if with_keys { key.keys() } else { &[] };
    let store = EngineStore::with_keys(install.join("engines"), install.clone(), keys);
    let engines = ServiceEngines::with(&install, store, Arc::new(NoChecks), |_| None);
    let memory = Arc::new(Memory::default());
    let (status, holds) = (
        watch::Sender::new(TunStatus::default()),
        watch::Sender::new(false),
    );
    let restarted = Arc::new(AtomicBool::new(false));
    let flag = restarted.clone();
    let files = SwapFiles::unvetted(&install.join("vpnte-service.exe"));
    let updates = Updates::new(UpdatesDeps {
        own: OWN,
        keys,
        source: memory.clone(),
        engines: Arc::new(engines),
        files: files.clone(),
        record: dir.path().join("update.json"),
        status: status.subscribe(),
        holds: holds.subscribe(),
        restart: Arc::new(move || flag.store(true, Ordering::SeqCst)),
    });
    Setup {
        _dir: dir,
        key,
        memory,
        updates,
        status,
        holds,
        restarted,
        files,
    }
}

impl Setup {
    /// Publishes `feed` signed with the test key, and `exe` at its service entry's URL.
    fn publish(&self, feed: &Feed, exe: &[u8]) {
        let bytes = serde_json::to_vec(feed).expect("json");
        *self.memory.feed.lock() = Some((bytes.clone(), self.key.sign(&bytes)));
        if let Some(entry) = &feed.service {
            self.memory
                .files
                .lock()
                .insert(entry.urls[0].clone(), exe.to_vec());
        }
    }

    async fn ask(&self, ask: UpdateAsk, may_restart: bool) -> ServiceUpdateWire {
        self.updates.answer(ask, may_restart).await
    }

    fn exe(&self) -> Vec<u8> {
        std::fs::read(&self.files.exe).expect("exe")
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
}

fn take(version: Version) -> UpdateAsk {
    UpdateAsk::Take {
        version: version.to_string(),
    }
}

/// Point 5: the app's `Take` of the next release, with no session in the way: the answer comes
/// at once (a check runs), then the service stages the listed exe, swaps it in and restarts
/// after a grace for the answers.
#[tokio::test]
async fn a_take_swaps_the_release_in_and_restarts() {
    let s = setup(true);
    s.publish(
        &feed(9, Some(service_entry(NEXT, b"next exe"))),
        b"next exe",
    );
    let passed_over = s.files.staging.join("vpnte-service-2.0.0.exe");
    std::fs::write(&passed_over, b"an older staged exe").expect("stale");
    let first = s.ask(take(NEXT), true).await;
    assert_eq!(
        (first.version.as_str(), first.phase),
        ("2.0.0", UpdatePhase::Working)
    );
    let answer = s.settled().await;
    assert_eq!(
        (answer.phase, answer.target.as_deref()),
        (UpdatePhase::Restarting, Some("2.0.1"))
    );
    assert!(answer.checked_at.is_some());
    assert!(!passed_over.exists(), "only the staged release stays");
    assert_eq!(s.exe(), b"next exe");
    assert_eq!(
        swap::marker(&s.files).map(|m| (m.from, m.to)),
        Some((OWN, NEXT))
    );
    assert!(
        !s.restarted.load(Ordering::SeqCst),
        "the answers go out first"
    );
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(300)).await;
    assert!(s.restarted.load(Ordering::SeqCst));
}

/// D-S10: another user's session runs: the release is staged, not swapped; it goes in once the
/// session ended and its filters are gone.
#[tokio::test]
async fn another_users_session_waits_for_idle() {
    let s = setup(true);
    s.publish(
        &feed(9, Some(service_entry(NEXT, b"next exe"))),
        b"next exe",
    );
    s.status.send_modify(|st| st.running = true);
    s.holds.send_replace(true);
    let watcher = tokio::spawn(s.updates.clone().swap_when_idle(CancellationToken::new()));
    s.ask(take(NEXT), false).await;
    let answer = s.settled().await;
    assert_eq!(
        (answer.phase, answer.target.as_deref()),
        (UpdatePhase::Waiting, Some("2.0.1"))
    );
    assert_eq!(s.exe(), b"running exe");
    s.status.send_modify(|st| st.running = false);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.exe(), b"running exe", "the filters are still held");
    s.holds.send_replace(false);
    tokio::time::timeout(Duration::from_secs(2), watcher)
        .await
        .expect("swapped")
        .expect("task");
    assert_eq!(s.exe(), b"next exe");
}

/// Bytes that are not the listed ones never go in, an older or equal release is never taken,
/// and a feed under another key is refused: the exe stays and nothing restarts.
#[tokio::test]
async fn only_a_verified_newer_release_is_taken() {
    let tampered = setup(true);
    tampered.publish(
        &feed(9, Some(service_entry(NEXT, b"next exe"))),
        b"tampered",
    );
    tampered.ask(take(NEXT), true).await;
    assert_eq!(tampered.settled().await.phase, UpdatePhase::Idle);
    let same = setup(true);
    same.publish(&feed(10, Some(service_entry(OWN, b"same"))), b"same");
    assert_eq!(
        same.ask(take(OWN), true).await.phase,
        UpdatePhase::Idle,
        "nothing to do"
    );
    assert!(same.updates.clone().check(false).await);
    assert_eq!(same.settled().await.phase, UpdatePhase::Idle);
    let foreign = setup(true);
    let bytes =
        serde_json::to_vec(&feed(11, Some(service_entry(NEXT, b"next exe")))).expect("json");
    *foreign.memory.feed.lock() = Some((bytes.clone(), TestKey::new().sign(&bytes)));
    let url = service_entry(NEXT, b"").urls[0].clone();
    foreign
        .memory
        .files
        .lock()
        .insert(url, b"next exe".to_vec());
    foreign.ask(take(NEXT), true).await;
    assert_eq!(foreign.settled().await.phase, UpdatePhase::Failed);
    // Asked again within a minute: the failed check stands in, reported as it ended.
    foreign.ask(take(NEXT), true).await;
    assert_eq!(foreign.settled().await.phase, UpdatePhase::Failed);
    assert_eq!(foreign.memory.reads.load(Ordering::SeqCst), 1);
    tokio::time::sleep(ANSWER_GRACE + Duration::from_millis(300)).await;
    for s in [&tampered, &same, &foreign] {
        assert_eq!(s.exe(), b"running exe");
        assert!(!s.restarted.load(Ordering::SeqCst));
    }
}

/// Many asks at once read the feed once; a feed older than the one accepted is never used.
#[tokio::test]
async fn asks_share_one_check_and_an_older_feed_is_not_taken() {
    let s = setup(true);
    s.publish(&feed(20, None), b"");
    for _ in 0..5 {
        s.ask(take(NEXT), true).await;
    }
    s.settled().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 1);
    s.publish(
        &feed(19, Some(service_entry(NEXT, b"next exe"))),
        b"next exe",
    );
    assert!(s.updates.clone().check(false).await);
    assert_eq!(s.settled().await.phase, UpdatePhase::Idle);
    assert_eq!(s.exe(), b"running exe");
}

/// Without update keys the service never reads a feed and says so.
#[tokio::test]
async fn without_keys_nothing_is_checked() {
    let s = setup(false);
    s.publish(
        &feed(9, Some(service_entry(NEXT, b"next exe"))),
        b"next exe",
    );
    let answer = s.ask(take(NEXT), true).await;
    assert_eq!(answer.phase, UpdatePhase::Off);
    s.updates.clone().run(CancellationToken::new()).await;
    assert_eq!(s.memory.reads.load(Ordering::SeqCst), 0);
}
