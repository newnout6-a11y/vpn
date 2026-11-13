use std::io::Write as _;

use async_trait::async_trait;
use tokio::sync::{broadcast, watch};
use vpnte_update::download::open_held;
use vpnte_update::feed::{ArchiveEntry, MemberEntry};

use super::*;
use crate::update::testkit::{TempDir, TestKey, feed, sha};

/// sing-box one patch above the bundled one (inside the compiled range).
fn next() -> Version {
    let b = bundled_version(SINGBOX).expect("bundled sing-box");
    Version(b.0, b.1, b.2 + 1)
}

/// The engine checks, faked: the reported version is the asked one.
struct Fake;

#[async_trait]
impl Checks for Fake {
    async fn version(&self, _: &str, exe: &Path) -> std::io::Result<Version> {
        let folder = exe
            .parent()
            .and_then(|d| d.file_name())
            .expect("version folder");
        Ok(folder
            .to_string_lossy()
            .parse()
            .expect("named after the version"))
    }

    async fn configs(&self, _: &str, _: &Path) -> Result<(), String> {
        Ok(())
    }
}

/// An install folder with bundled files that are not the release's (as after an exe swap),
/// a signed feed listing sing-box `version` in an archive next to it, and the engines over it.
struct Setup {
    dir: TempDir,
    engines: Arc<ServiceEngines>,
    feed: Vec<u8>,
    sig: String,
    archive: PathBuf,
    keys: &'static [vpnte_update::feed::PublicKey],
}

fn setup(version: Version) -> Setup {
    let dir = TempDir::new("engines");
    let install = dir.path().join("install");
    std::fs::create_dir_all(&install).expect("install");
    for name in ["sing-box.exe", "libcronet.dll", "wintun.dll", "xray.exe"] {
        std::fs::write(install.join(name), b"an older release").expect("bundled");
    }
    let members = [
        ("sing-box.exe", b"exe".as_slice()),
        ("libcronet.dll", b"dll"),
    ];
    let archive = dir.path().join("sing-box.zip");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).expect("zip"));
    for (name, body) in members {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file(format!("pkg/{name}"), options)
            .expect("member");
        zip.write_all(body).expect("body");
    }
    zip.finish().expect("zip done");
    let zipped = std::fs::read(&archive).expect("zip bytes");
    let mut signed = feed(7, None);
    signed.engines.push(EngineEntry {
        id: SINGBOX.into(),
        version,
        app: ">=2.0.0 <3.0.0".parse().expect("range"),
        severity: Default::default(),
        notes: Default::default(),
        tested_on: None,
        tested: None,
        archive: ArchiveEntry {
            url: "https://example.invalid/sing-box.zip".into(),
            size: zipped.len() as u64,
            sha256: sha(&zipped),
        },
        files: members
            .iter()
            .map(|(name, body)| MemberEntry {
                path: format!("pkg/{name}"),
                name: (*name).into(),
                sha256: sha(body),
            })
            .collect(),
    });
    let bytes = serde_json::to_vec(&signed).expect("json");
    let key = TestKey::new();
    let sig = key.sign(&bytes);
    let keys = key.keys();
    let store = EngineStore::with_keys(install.join("engines"), install.clone(), keys);
    let engines = ServiceEngines::with(&install, store, Arc::new(Fake), |_| None);
    Setup {
        dir,
        engines: Arc::new(engines),
        feed: bytes,
        sig,
        archive,
        keys,
    }
}

impl Setup {
    fn feed(&self) -> Feed {
        serde_json::from_slice(&self.feed).expect("feed")
    }

    async fn install(&self) -> Result<Installed, InstallError> {
        let feed = self.feed();
        let entry = feed.engine(SINGBOX).expect("entry");
        let archive = Verified {
            path: self.archive.clone(),
            file: open_held(&self.archive).expect("held"),
        };
        self.engines
            .install(entry, &self.feed, &self.sig, archive)
            .await
    }

    fn version_exe(&self, version: Version) -> PathBuf {
        let dir = self
            .dir
            .path()
            .join("install")
            .join("engines")
            .join(SINGBOX);
        dir.join(version.to_string()).join("sing-box.exe")
    }
}

/// A verified newer engine goes into its version folder and the next session start reads it;
/// bundled files the pins refuse count as nothing, so even the bundled version is wanted.
#[tokio::test]
async fn a_verified_engine_is_what_the_next_start_runs() {
    let s = setup(next());
    let exes = s.engines.exes();
    assert_eq!(s.engines.current(SINGBOX), None, "not the release's files");
    assert_eq!(s.engines.wanted(&s.feed()).len(), 1);
    s.install().await.expect("installed");
    assert_eq!(exes.borrow().singbox, s.version_exe(next()));
    assert_eq!(s.engines.current(SINGBOX), Some(next()));
    assert!(s.engines.wanted(&s.feed()).is_empty(), "nothing newer left");
    let bundled = setup(bundled_version(SINGBOX).expect("bundled"));
    assert_eq!(bundled.engines.wanted(&bundled.feed()).len(), 1);
    bundled
        .install()
        .await
        .expect("the bundled version from the feed");
}

/// A version folder that fails the vetting is not run: the bundled file is.
#[tokio::test]
async fn an_untrusted_version_folder_is_not_run() {
    let s = setup(next());
    s.install().await.expect("installed");
    let install = s.dir.path().join("install");
    let store = EngineStore::with_keys(install.join("engines"), install.clone(), s.keys);
    let refused = ServiceEngines::with(&install, store, Arc::new(Fake), |_| {
        Some("a user may write here".into())
    });
    assert_eq!(
        refused.exes().borrow().singbox,
        install.join("sing-box.exe")
    );
}

/// Three failed session starts in a row that ran the fresh version: the next start runs the
/// previous one (here the bundled file). Starts of other files do not count.
#[tokio::test]
async fn three_failed_starts_of_a_fresh_engine_go_back() {
    let s = setup(next());
    s.install().await.expect("installed");
    let (events, rx) = broadcast::channel(16);
    let starts = watch::Sender::new(EngineStarts::default());
    let stop = CancellationToken::new();
    let task = tokio::spawn(
        s.engines
            .clone()
            .follow_starts(rx, starts.subscribe(), stop.clone()),
    );
    let exes = s.engines.exes();
    let fresh = s.version_exe(next());
    for (n, exe) in [&fresh, &PathBuf::from("other.exe"), &fresh, &fresh]
        .iter()
        .enumerate()
    {
        let generation = n as u64;
        events
            .send(TunnelEvent::StartBegan { generation })
            .expect("sent");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        starts.send_modify(|s| {
            s.singbox.count += 1;
            s.singbox.exe = Some(exe.to_path_buf());
        });
        let ok = false;
        events
            .send(TunnelEvent::StartFinished { generation, ok })
            .expect("sent");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        exes.borrow().singbox,
        s.dir.path().join("install").join("sing-box.exe")
    );
    stop.cancel();
    task.await.expect("ended");
}
