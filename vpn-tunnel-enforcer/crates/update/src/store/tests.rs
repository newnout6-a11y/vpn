use std::io::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::*;

/// The bundled sing-box (from the compiled manifest: an engine bump keeps these tests valid).
fn bundled() -> Version {
    bundled_version("sing-box").unwrap()
}

/// A version newer than the bundled one, inside the compiled range.
fn next() -> Version {
    let b = bundled();
    Version(b.0, b.1, b.2 + 1)
}

/// Yet another one (a wrong version report).
fn after_next() -> Version {
    let n = next();
    Version(n.0, n.1, n.2 + 1)
}
use crate::download::open_held;
use crate::feed::{ArchiveEntry, EngineEntry, MemberEntry};
use crate::test_support::{TempDir, TestKey, sample_feed};

/// The checks the app runs, faked: the reported version and the config verdict.
struct Fake {
    version: Version,
    refuse: Option<&'static str>,
}

impl EngineCheck for Fake {
    async fn version(&self, _: &str, exe: &Path) -> std::io::Result<Version> {
        assert!(
            exe.is_file(),
            "checked in its version folder: {}",
            exe.display()
        );
        Ok(self.version)
    }
    async fn check_configs(&self, _: &str, _: &Path) -> Result<(), String> {
        self.refuse.map_or(Ok(()), |r| Err(r.to_owned()))
    }
}

struct Setup {
    _dir: TempDir,
    store: EngineStore,
    entry: EngineEntry,
    feed: Vec<u8>,
    sig: String,
    archive: PathBuf,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A sing-box `version` archive with two members, a feed listing it, signed by a test key.
fn setup(version: Version) -> Setup {
    let dir = TempDir::new("store");
    let resources = dir.path().join("resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(resources.join("wintun.dll"), b"wintun").unwrap();
    let archive = dir.path().join(format!("sing-box-{version}.zip"));
    let members = [
        ("sing-box.exe", b"exe bytes".as_slice()),
        ("libcronet.dll", b"dll bytes".as_slice()),
    ];
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&archive).unwrap());
    for (name, body) in members {
        zip.start_file(
            format!("pkg/{name}"),
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(body).unwrap();
    }
    zip.finish().unwrap();
    let bytes = std::fs::read(&archive).unwrap();
    let mut feed = sample_feed(3);
    let entry = EngineEntry {
        version,
        archive: ArchiveEntry {
            url: "u".into(),
            size: bytes.len() as u64,
            sha256: sha(&bytes),
        },
        files: members
            .iter()
            .map(|(name, body)| MemberEntry {
                path: format!("pkg/{name}"),
                name: (*name).into(),
                sha256: sha(body),
            })
            .collect(),
        ..feed.engines[0].clone()
    };
    feed.engines[0] = entry.clone();
    let feed = serde_json::to_vec(&feed).unwrap();
    let key = TestKey::new();
    let sig = key.sign(&feed);
    let keys: &'static [_] = Box::leak(vec![key.public()].into_boxed_slice());
    let store = EngineStore::with_keys(dir.path().join("engines"), resources, keys);
    Setup {
        _dir: dir,
        store,
        entry,
        feed,
        sig,
        archive,
    }
}

impl Setup {
    async fn install(&self, check: &Fake) -> Result<Installed, InstallError> {
        let held = crate::download::Verified {
            path: self.archive.clone(),
            file: open_held(&self.archive).unwrap(),
        };
        self.store
            .install(&self.entry, &self.feed, &self.sig, held, check)
            .await
    }
}

/// Install: only the listed members, each checked, plus Wintun and the signed feed; the version
/// becomes active on trial with the bundled engine as previous, and resolves to its exe.
#[tokio::test]
async fn an_install_switches_the_engine_on_trial() {
    let s = setup(next());
    assert_eq!(s.store.resolve("sing-box").origin, Origin::Bundled);
    let done = s
        .install(&Fake {
            version: next(),
            refuse: None,
        })
        .await
        .unwrap();
    assert_eq!((done.version, done.previous), (next(), Choice::Bundled));
    let dir = s.store.version_dir("sing-box", next());
    for file in [
        "sing-box.exe",
        "libcronet.dll",
        "wintun.dll",
        "update.json",
        "update.json.minisig",
    ] {
        assert!(dir.join(file).is_file(), "{file}");
    }
    assert!(
        !s.archive.exists(),
        "the archive is removed after the install"
    );
    let record = s.store.state().engine("sing-box").cloned().unwrap();
    assert_eq!(
        (record.active, record.trial),
        (Choice::Downloaded(next()), Some(0))
    );
    let resolved = s.store.resolve("sing-box");
    assert_eq!(resolved.exe, dir.join("sing-box.exe"));
    assert!(
        matches!(resolved.origin, Origin::Downloaded { version, on } if version == next() && on > 0)
    );
    assert_eq!(s.store.resolve("xray").origin, Origin::Bundled);
}

/// A refusal of our config, a wrong reported version or a changed member installs nothing:
/// no version folder left, the record still says bundled.
#[tokio::test]
async fn any_refusal_installs_nothing() {
    let nothing_left = |s: &Setup| {
        assert_eq!(s.store.state(), StoreState::default());
        let id_dir = s.store.version_dir("sing-box", next());
        let parent = id_dir.parent().unwrap().to_owned();
        let left: Vec<_> = std::fs::read_dir(&parent)
            .map(|d| d.flatten().count())
            .into_iter()
            .collect();
        assert!(left.iter().all(|n| *n == 0), "{left:?}");
    };
    let s = setup(next());
    let err = s
        .install(&Fake {
            version: next(),
            refuse: Some("dns_mode unknown"),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&err, InstallError::ConfigRefused(r) if r == "dns_mode unknown"),
        "{err:?}"
    );
    nothing_left(&s);
    let s = setup(next());
    let err = s
        .install(&Fake {
            version: after_next(),
            refuse: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, InstallError::VersionMismatch { .. }),
        "{err:?}"
    );
    nothing_left(&s);
    let mut s = setup(next());
    s.entry.files[1].sha256 = "00".repeat(32);
    let err = s
        .install(&Fake {
            version: next(),
            refuse: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, InstallError::Feed),
        "the stored feed must list the entry: {err:?}"
    );
    nothing_left(&s);
}

/// A member whose bytes differ from the signed feed is refused while extracting.
#[test]
fn a_changed_member_is_refused() {
    let s = setup(next());
    let out = TempDir::new("extract");
    let mut members = s.entry.files.clone();
    members[0].sha256 = sha(b"other bytes");
    let mut file = open_held(&s.archive).unwrap();
    let err = install::extract(&mut file, &members, out.path()).unwrap_err();
    assert!(
        matches!(&err, InstallError::Member(name) if name == "sing-box.exe"),
        "{err:?}"
    );
    let out = TempDir::new("extract-ok");
    install::extract(&mut file, &s.entry.files, out.path()).unwrap();
    assert_eq!(
        std::fs::read(out.path().join("libcronet.dll")).unwrap(),
        b"dll bytes"
    );
}

/// Versions outside the compiled range, or not newer than the bundled one, are refused.
#[tokio::test]
async fn versions_outside_the_range_are_refused() {
    for version in [Version(1, 15, 0), bundled(), Version(1, 13, 9)] {
        let s = setup(version);
        let err = s
            .install(&Fake {
                version,
                refuse: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, InstallError::NotAllowed(v) if v == version),
            "{version}"
        );
    }
}

/// The trial: a successful start ends it; three failed starts in a row go back by themselves.
#[tokio::test]
async fn a_failed_trial_goes_back() {
    let s = setup(next());
    s.install(&Fake {
        version: next(),
        refuse: None,
    })
    .await
    .unwrap();
    assert_eq!(s.store.record_start("sing-box", false).unwrap(), None);
    assert_eq!(s.store.record_start("sing-box", false).unwrap(), None);
    assert_eq!(s.store.fallback("sing-box").origin, Origin::Bundled);
    let rolled = s.store.record_start("sing-box", false).unwrap().unwrap();
    assert_eq!((rolled.from, rolled.to), (next(), Choice::Bundled));
    assert_eq!(s.store.resolve("sing-box").origin, Origin::Bundled);
    // svcupd-a4: the version that failed is remembered; the switch back runs what it said.
    let record = s.store.state().engine("sing-box").cloned().unwrap();
    assert_eq!(record.failed, vec![next()]);
    assert!(matches!(
        s.store.fallback("sing-box").origin,
        Origin::Downloaded { version, .. } if version == next()
    ));
    // Proven: no more automatic switching.
    assert!(s.store.revert_previous("sing-box").unwrap());
    assert_eq!(s.store.record_start("sing-box", false).unwrap(), None);
    let s = setup(next());
    s.install(&Fake {
        version: next(),
        refuse: None,
    })
    .await
    .unwrap();
    assert_eq!(s.store.record_start("sing-box", true).unwrap(), None);
    for _ in 0..3 {
        assert_eq!(s.store.record_start("sing-box", false).unwrap(), None);
    }
}

/// «Вернуть встроенную» / «Вернуть предыдущую», and a feed that no longer verifies is ignored.
#[tokio::test]
async fn reverting_by_hand() {
    let s = setup(next());
    s.install(&Fake {
        version: next(),
        refuse: None,
    })
    .await
    .unwrap();
    s.store.revert_bundled("sing-box").unwrap();
    assert_eq!(s.store.resolve("sing-box").origin, Origin::Bundled);
    assert!(s.store.revert_previous("sing-box").unwrap());
    assert!(matches!(
        s.store.resolve("sing-box").origin,
        Origin::Downloaded { .. }
    ));
    let dir = s.store.version_dir("sing-box", next());
    std::fs::write(dir.join("update.json"), b"{}").unwrap();
    assert_eq!(s.store.resolve("sing-box").origin, Origin::Bundled);
    s.store.tidy("sing-box");
    assert_eq!(
        s.store.state().engine("sing-box").map(|r| r.active),
        Some(Choice::Bundled)
    );
    assert!(!dir.exists(), "an unusable version is removed");
}

/// D-S7 (p-svc-update): the app's store installs only versions past the bundled one; the helper
/// service's store (`not_below_bundled`) also takes the bundled version from the signed feed,
/// keeps it through `tidy` and runs it, so a swapped service exe finds engines its pins accept.
#[tokio::test]
async fn the_service_store_takes_the_bundled_version_from_the_feed() {
    let check = Fake {
        version: bundled(),
        refuse: None,
    };
    let s = setup(bundled());
    let err = s.install(&check).await.unwrap_err();
    assert!(
        matches!(err, InstallError::NotAllowed(v) if v == bundled()),
        "{err:?}"
    );
    let mut s = setup(bundled());
    s.store = s.store.clone().not_below_bundled();
    let done = s.install(&check).await.unwrap();
    assert_eq!(done.version, bundled());
    s.store.tidy("sing-box");
    let resolved = s.store.resolve("sing-box");
    assert_eq!(
        resolved.exe,
        s.store
            .version_dir("sing-box", bundled())
            .join("sing-box.exe")
    );
    assert!(matches!(resolved.origin, Origin::Downloaded { version, .. } if version == bundled()));
}
