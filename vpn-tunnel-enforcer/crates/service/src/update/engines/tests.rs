use std::path::PathBuf;

use vpnte_update::download::open_held;
use vpnte_update::feed::PublicKey;

use super::*;
use crate::update::testkit::{FolderChecks, TempDir, TestKey, engine, feed};

/// The app range of the test feeds: this build's.
const SERIES: &str = ">=2.0.0 <3.0.0";

/// sing-box `n` patches above the bundled one (inside the compiled range).
fn above(n: u16) -> Version {
    let b = bundled_version(SINGBOX).expect("bundled sing-box");
    Version(b.0, b.1, b.2 + n)
}

/// An install folder with bundled files that are not the release's (as after an exe swap),
/// the engines over it, and the key that signs the feeds of the test.
struct Setup {
    dir: TempDir,
    key: TestKey,
    engines: Arc<ServiceEngines>,
}

fn setup() -> Setup {
    let dir = TempDir::new("engines");
    let install = dir.path().join("install");
    std::fs::create_dir_all(&install).expect("install");
    for name in ["sing-box.exe", "libcronet.dll", "wintun.dll", "xray.exe"] {
        std::fs::write(install.join(name), b"an older release").expect("bundled");
    }
    let key = TestKey::new();
    let engines = Arc::new(over(&install, key.keys(), |_| None));
    Setup { dir, key, engines }
}

fn over(
    install: &Path,
    keys: &'static [PublicKey],
    vet: fn(&Path) -> Option<String>,
) -> ServiceEngines {
    let store = EngineStore::with_keys(install.join("engines"), install.to_owned(), keys);
    ServiceEngines::with(install, store, Arc::new(FolderChecks), vet)
}

impl Setup {
    fn install_dir(&self) -> PathBuf {
        self.dir.path().join("install")
    }

    /// A signed feed listing sing-box `version` for the apps in `app`, and that engine's archive.
    fn feed(&self, version: Version, app: &str) -> (Feed, Vec<u8>, String, Vec<u8>) {
        let (entry, zipped) = engine(SINGBOX, version, app);
        let mut signed = feed(7, None);
        signed.engines.push(entry);
        let bytes = serde_json::to_vec(&signed).expect("json");
        let sig = self.key.sign(&bytes);
        (signed, bytes, sig, zipped)
    }

    async fn install(&self, version: Version) -> Result<Installed, InstallError> {
        let (feed, bytes, sig, zipped) = self.feed(version, SERIES);
        let path = self.dir.path().join(format!("sing-box-{version}.zip"));
        std::fs::write(&path, zipped).expect("archive");
        let archive = Verified {
            file: open_held(&path).expect("held"),
            path,
        };
        let entry = feed.engine(SINGBOX).expect("entry");
        self.engines.install(entry, &bytes, &sig, archive).await
    }

    fn version_exe(&self, version: Version) -> PathBuf {
        let dir = self.install_dir().join("engines").join(SINGBOX);
        dir.join(version.to_string()).join("sing-box.exe")
    }

    /// One start the host asked for that ran `exe` and ended with `ok`.
    fn start(&self, starts: &mut EngineStarts, exe: &Path, ok: Option<bool>) {
        starts.singbox.count += 1;
        starts.singbox.exe = Some(exe.to_path_buf());
        self.engines.settled(starts, ok);
    }
}

/// A verified newer engine goes into its version folder and the next session start reads it;
/// bundled files the pins refuse count as nothing, so even the bundled version is wanted.
#[tokio::test]
async fn a_verified_engine_is_what_the_next_start_runs() {
    let s = setup();
    let exes = s.engines.exes();
    assert_eq!(s.engines.current(SINGBOX), None, "not the release's files");
    assert_eq!(s.engines.wanted(&s.feed(above(1), SERIES).0).len(), 1);
    s.install(above(1)).await.expect("installed");
    assert_eq!(exes.borrow().singbox, s.version_exe(above(1)));
    assert_eq!(s.engines.current(SINGBOX), Some(above(1)));
    assert!(
        s.engines.wanted(&s.feed(above(1), SERIES).0).is_empty(),
        "nothing newer left"
    );
    let bundled = setup();
    let version = bundled_version(SINGBOX).expect("bundled");
    assert_eq!(
        bundled
            .engines
            .wanted(&bundled.feed(version, SERIES).0)
            .len(),
        1
    );
    bundled
        .install(version)
        .await
        .expect("the bundled version from the feed");
}

/// A version folder that fails the vetting is not run: the bundled file is.
#[tokio::test]
async fn an_untrusted_version_folder_is_not_run() {
    let s = setup();
    s.install(above(1)).await.expect("installed");
    let refused = over(&s.install_dir(), s.key.keys(), |_| {
        Some("a user may write here".into())
    });
    assert_eq!(
        refused.exes().borrow().singbox,
        s.install_dir().join("sing-box.exe")
    );
}

/// Three failed starts in a row that ran the fresh version: the next start runs the previous
/// one. Starts of other files do not count, and the version that failed is never wanted again
/// (svcupd-a4).
#[tokio::test]
async fn three_failed_starts_of_a_fresh_engine_go_back_for_good() {
    let s = setup();
    s.install(above(1)).await.expect("previous");
    s.install(above(2)).await.expect("fresh");
    let (exes, fresh) = (s.engines.exes(), s.version_exe(above(2)));
    let mut starts = EngineStarts::default();
    for exe in [&fresh, &PathBuf::from("other.exe"), &fresh, &fresh] {
        s.start(&mut starts, exe, Some(false));
    }
    assert_eq!(exes.borrow().singbox, s.version_exe(above(1)));
    assert!(s.engines.wanted(&s.feed(above(2), SERIES).0).is_empty());
    assert_eq!(s.engines.wanted(&s.feed(above(3), SERIES).0).len(), 1);
}

/// svcupd-a5: starts the user cancelled (or another start replaced) say nothing about the
/// engine; a start that ran ends the trial.
#[tokio::test]
async fn cancelled_starts_do_not_count() {
    let s = setup();
    s.install(above(1)).await.expect("previous");
    s.install(above(2)).await.expect("fresh");
    let fresh = s.version_exe(above(2));
    let mut starts = EngineStarts::default();
    for _ in 0..5 {
        s.start(&mut starts, &fresh, None);
    }
    s.start(&mut starts, &fresh, Some(false));
    s.start(&mut starts, &fresh, Some(true));
    for _ in 0..3 {
        s.start(&mut starts, &fresh, Some(false));
    }
    assert_eq!(s.engines.exes().borrow().singbox, fresh, "proven: kept");
}

/// svcupd-b6: when the only thing to go back to is bundled files this build's pins refuse (as
/// after an exe swap), failed starts switch nothing: that would end Tunnel mode, not save it.
#[tokio::test]
async fn no_switch_back_to_files_this_build_refuses() {
    let s = setup();
    s.install(above(1)).await.expect("fresh");
    let fresh = s.version_exe(above(1));
    let mut starts = EngineStarts::default();
    for _ in 0..3 {
        s.start(&mut starts, &fresh, Some(false));
    }
    assert_eq!(s.engines.exes().borrow().singbox, fresh);
    assert_eq!(s.engines.current(SINGBOX), Some(above(1)));
}

/// svcupd-a6: a release's engines are this build's to judge only within its minor series and
/// ranges, and are in place only when Tunnel mode runs exactly the listed versions.
#[tokio::test]
async fn a_release_is_ready_only_with_the_engines_it_runs() {
    let s = setup();
    let own = vpnte_update::policy::app_version();
    let next = Version(own.0, own.1, own.2 + 1);
    let minor = Version(own.0, own.1 + 1, 0);
    let range = |m: u16| format!(">={}.{m}.0 <{}.{}.0", own.0, own.0, m + 1);
    let release = |app: &str| {
        let mut f = feed(7, None);
        f.engines.push(engine(SINGBOX, above(1), app).0);
        let xray = bundled_version(XRAY).expect("bundled xray");
        f.engines.push(engine(XRAY, xray, app).0);
        f
    };
    let series = release(&range(own.1));
    assert!(s.engines.meant_for(&series, next));
    assert!(!s.engines.meant_for(&release(&range(own.1 + 1)), minor));
    assert!(
        !s.engines.meant_for(&series, minor),
        "not for the next series"
    );
    let mut lone = series.clone();
    lone.engines.pop();
    assert!(!s.engines.meant_for(&lone, next), "every engine listed");
    assert!(!s.engines.ready_for(&series, next), "nothing runs yet");
    s.install(above(1)).await.expect("sing-box");
    assert!(
        !s.engines.ready_for(&series, next),
        "xray's bundled files are refused"
    );
}
