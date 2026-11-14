use std::process::{Command, Stdio};

use super::*;
use crate::update::testkit::{TempDir, TestKey, feed, service_entry};

const OLD: Version = Version(2, 0, 0);
const NEW: Version = Version(2, 0, 1);

/// An install folder with an "exe" (plain bytes) and its staging folder.
fn install(tag: &str) -> (TempDir, SwapFiles) {
    let dir = TempDir::new(tag);
    let files = SwapFiles::unvetted(&dir.path().join("vpnte-service.exe"));
    std::fs::create_dir_all(&files.staging).expect("staging");
    std::fs::write(&files.exe, b"old exe").expect("old exe");
    std::fs::write(files.staged(NEW), b"new exe").expect("staged exe");
    (dir, files)
}

/// [`ready`] as `(exe, version)`.
fn staged_at(
    files: &SwapFiles,
    keys: &[vpnte_update::feed::PublicKey],
    own: Version,
    max_seq: u64,
) -> Option<(PathBuf, Version)> {
    ready(files, keys, own, max_seq).map(|s| (s.exe, s.version))
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

/// D-S3, checked on this machine: the entry of a running exe cannot be replaced while the image
/// has one name (error 5), and can once it has a second one; the process runs on, the old bytes
/// stay reachable under that second name.
#[test]
fn a_running_exe_is_replaced_through_its_second_name() {
    let (_dir, files) = install("running");
    let system = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    let ping = std::fs::read(system.join("System32").join("PING.EXE")).expect("ping.exe");
    std::fs::write(&files.exe, &ping).expect("exe copy");
    // Loopback only, a few seconds: nothing listens, nothing leaves the machine.
    let mut child = Command::new(&files.exe)
        .args(["-n", "20", "127.0.0.1"])
        .stdout(Stdio::null())
        .spawn()
        .expect("started");
    let plain = replace(&files.staged(NEW), &files.exe).expect_err("one name: refused");
    assert_eq!(plain.raw_os_error(), Some(5), "{plain:?}");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    assert_eq!(read(&files.exe), b"new exe");
    assert_eq!(
        read(&files.prev()),
        ping,
        "the running image keeps its second name"
    );
    assert!(child.try_wait().expect("state").is_none(), "still running");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(
        marker(&files),
        Some(Marker {
            from: OLD,
            to: NEW,
            starts: 0
        })
    );
}

/// Three starts of the new exe that never ran [`TRIAL_RUN`]: the fourth puts the previous exe
/// back and asks for a restart; the old exe's start then keeps the spent marker as the record
/// that the version failed, and removes the failed exe's second name.
#[test]
fn three_failed_starts_bring_the_previous_exe_back() {
    let (_dir, files) = install("trial");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    for n in 1..=TRIAL_STARTS {
        assert_eq!(at_start(&files, NEW).expect("start"), AtStart::Trial(n));
    }
    assert_eq!(
        at_start(&files, NEW).expect("start"),
        AtStart::RolledBack(OLD)
    );
    assert_eq!(read(&files.exe), b"old exe");
    assert_eq!(read(&files.failed()), b"new exe");
    // svcfix-b4: the rollback is reported once, by the first start after it.
    assert_eq!(
        at_start(&files, OLD).expect("old start"),
        AtStart::After(NEW)
    );
    assert!(failed_before(&files, NEW));
    assert!(!files.failed().exists() && !files.prev().exists());
    assert_eq!(at_start(&files, OLD).expect("again"), AtStart::Normal);
    assert!(failed_before(&files, NEW), "the record stays");
}

/// A start that ran long enough ends the trial: no marker, no previous exe, nothing skipped.
#[test]
fn a_settled_trial_leaves_nothing_behind() {
    let (_dir, files) = install("settled");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    assert_eq!(at_start(&files, NEW).expect("start"), AtStart::Trial(1));
    settled(&files);
    assert_eq!(marker(&files), None);
    assert!(!files.prev().exists());
    assert_eq!(at_start(&files, NEW).expect("next start"), AtStart::Normal);
    assert!(!failed_before(&files, NEW));
}

/// Power lost between the steps: the next start always finds an exe and goes on from there.
#[test]
fn every_power_loss_state_leaves_an_exe_that_goes_on() {
    let pending = Marker {
        from: OLD,
        to: NEW,
        starts: 0,
    };
    // Marker written, nothing else: the old exe drops it (the staged file stays for a retry).
    let (_dir, files) = install("loss-marker");
    write_marker(&files, &pending).expect("marker");
    assert_eq!(at_start(&files, OLD).expect("start"), AtStart::Normal);
    assert_eq!(
        (marker(&files), read(&files.exe)),
        (None, b"old exe".to_vec())
    );
    assert!(files.staged(NEW).exists());
    // Marker and second name, entry not replaced: the same, and the link goes.
    let (_dir, files) = install("loss-link");
    write_marker(&files, &pending).expect("marker");
    std::fs::hard_link(&files.exe, files.prev()).expect("link");
    assert_eq!(at_start(&files, OLD).expect("start"), AtStart::Normal);
    assert!(marker(&files).is_none() && !files.prev().exists());
    // Entry replaced: the new exe counts its trial.
    let (_dir, files) = install("loss-replaced");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    assert_eq!(at_start(&files, NEW).expect("start"), AtStart::Trial(1));
    // A rollback cut after the failing exe got its second name: the repeat skips the link.
    let (_dir, files) = install("loss-rollback");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    let spent = Marker {
        starts: TRIAL_STARTS,
        ..pending
    };
    write_marker(&files, &spent).expect("spent");
    std::fs::hard_link(&files.exe, files.failed()).expect("second name");
    assert_eq!(
        at_start(&files, NEW).expect("start"),
        AtStart::RolledBack(OLD)
    );
    assert_eq!(read(&files.exe), b"old exe");
    // An installer put a third version in place: every leftover goes, nothing is skipped.
    let (_dir, files) = install("loss-installer");
    swap_in(&files, &files.staged(NEW), OLD, NEW).expect("swapped");
    assert_eq!(
        at_start(&files, Version(2, 0, 2)).expect("start"),
        AtStart::Normal
    );
    assert!(marker(&files).is_none() && !files.prev().exists());
}

/// Only a staged exe that the signed feed next to it lists, above the running version, with the
/// listed size and hash, and not failed here before, may go in.
#[test]
fn only_a_verified_newer_exe_is_ready() {
    let (_dir, files) = install("ready");
    let key = TestKey::new();
    let put_feed = |entry_bytes: &[u8], version: Version, key: &TestKey| {
        let bytes =
            serde_json::to_vec(&feed(5, Some(service_entry(version, entry_bytes)))).expect("json");
        std::fs::write(files.staging.join(FEED_FILE), &bytes).expect("feed");
        std::fs::write(files.staging.join(SIG_FILE), key.sign(&bytes)).expect("sig");
    };
    put_feed(b"new exe", NEW, &key);
    assert_eq!(
        staged_at(&files, key.keys(), OLD, 0),
        Some((files.staged(NEW), NEW))
    );
    assert_eq!(
        staged_at(&files, key.keys(), NEW, 0),
        None,
        "not above the running one"
    );
    assert_eq!(
        staged_at(&files, TestKey::new().keys(), OLD, 0),
        None,
        "another key"
    );
    put_feed(b"other bytes", NEW, &key);
    assert_eq!(
        staged_at(&files, key.keys(), OLD, 0),
        None,
        "the file is not the listed one"
    );
    put_feed(b"new exe", NEW, &key);
    let spent = Marker {
        from: OLD,
        to: NEW,
        starts: TRIAL_STARTS,
    };
    write_marker(&files, &spent).expect("record");
    assert_eq!(
        staged_at(&files, key.keys(), OLD, 0),
        None,
        "failed here before"
    );
}

/// svcupd-a3: a staged release from a feed older than the newest one accepted stays out (the
/// owner may have withdrawn it since).
#[test]
fn a_staged_release_from_an_older_feed_is_not_ready() {
    let (_dir, files) = install("seq");
    let key = TestKey::new();
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    assert!(
        staged_at(&files, key.keys(), OLD, 5).is_some(),
        "seq 5 itself"
    );
    assert_eq!(staged_at(&files, key.keys(), OLD, 6), None);
    drop_staged(&files);
    assert!(!files.staged(NEW).exists() && !files.staging.join(FEED_FILE).exists());
}

/// svcfix-b3: a newer feed that still lists the staged exe byte for byte keeps it (with that
/// feed, so the newer `max_seq` still takes it) and drops any other staged exe; a feed that
/// lists other bytes, another version or no service drops what is staged.
#[test]
fn only_what_the_newest_feed_lists_stays_staged() {
    let (_dir, files) = install("keep");
    let key = TestKey::new();
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    let other = files.staged(Version(2, 0, 2));
    std::fs::write(&other, b"older pick").expect("other");
    let newer = |entry: Option<ServiceEntry>| {
        let bytes = serde_json::to_vec(&feed(6, entry)).expect("json");
        let sig = key.sign(&bytes);
        (bytes, sig)
    };
    let (bytes, sig) = newer(Some(service_entry(NEW, b"new exe")));
    let listed = service_entry(NEW, b"new exe");
    keep_listed(&files, OLD, Some(&listed), &bytes, &sig);
    assert_eq!(
        staged_at(&files, key.keys(), OLD, 6),
        Some((files.staged(NEW), NEW))
    );
    assert!(!other.exists(), "only the listed exe stays");
    let changed = service_entry(NEW, b"rebuilt exe");
    let (bytes, sig) = newer(Some(changed.clone()));
    keep_listed(&files, OLD, Some(&changed), &bytes, &sig);
    assert!(!files.staged(NEW).exists(), "other bytes: dropped");
    assert!(!files.staging.join(FEED_FILE).exists());
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    let (bytes, sig) = newer(None);
    keep_listed(&files, OLD, None, &bytes, &sig);
    assert!(!files.staged(NEW).exists(), "no service listed: dropped");
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    let (bytes, sig) = newer(Some(listed.clone()));
    keep_listed(&files, NEW, Some(&listed), &bytes, &sig);
    assert!(!files.staged(NEW).exists(), "not above the running one");
}

/// svcupd-a7 / a9 / a8: an installer's exe forgets everything the feed staged or swapped; a
/// release that does not start here is recorded as failed; a fresh exe on trial that cannot work
/// here gives its trial up and the previous exe is back.
#[test]
fn installer_refusal_and_give_up_records() {
    let (_dir, files) = install("records");
    let key = TestKey::new();
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    refuse(&files, OLD, NEW);
    assert!(failed_before(&files, NEW));
    // svcfix-b4: a release refused before it ran was never rolled back: no start reports it.
    for _ in 0..2 {
        assert_eq!(at_start(&files, OLD).expect("start"), AtStart::Normal);
    }
    assert!(failed_before(&files, NEW), "still never taken");
    forget(&files);
    assert_eq!(marker(&files), None);
    assert!(!files.staged(NEW).exists() && !files.staging.join(SIG_FILE).exists());
    let staged = files.staged(NEW);
    std::fs::write(&staged, b"new exe").expect("staged");
    swap_in(&files, &staged, OLD, NEW).expect("swapped");
    assert_eq!(at_start(&files, NEW).expect("trial"), AtStart::Trial(1));
    assert_eq!(give_up(&files).expect("given up"), OLD);
    assert_eq!(read(&files.exe), b"old exe");
    assert!(failed_before(&files, NEW));
    assert_eq!(
        at_start(&files, OLD).expect("old start"),
        AtStart::After(NEW)
    );
    assert!(failed_before(&files, NEW), "the record stays");
}

/// A signed feed and the listed exe staged in `files.staging` with `write` (a plain write, or
/// one born owned by Administrators as the service's own files are).
fn stage_signed(
    files: &SwapFiles,
    key: &TestKey,
    write: impl Fn(&Path, &[u8]) -> std::io::Result<()>,
) {
    let bytes = serde_json::to_vec(&feed(5, Some(service_entry(NEW, b"new exe")))).expect("json");
    write(&files.staging.join(FEED_FILE), &bytes).expect("feed");
    write(&files.staging.join(SIG_FILE), key.sign(&bytes).as_bytes()).expect("sig");
    let staged = files.staged(NEW);
    let _ = std::fs::remove_file(&staged);
    write(&staged, b"new exe").expect("staged exe");
}

/// The staged exe runs as SYSTEM later: in a folder users can write (any temp folder) it is
/// never used, however well it verifies.
#[test]
fn a_staged_exe_users_could_change_is_never_used() {
    let dir = TempDir::new("vetted");
    let files = SwapFiles::new(&dir.path().join("vpnte-service.exe"));
    std::fs::create_dir_all(&files.staging).expect("staging");
    let key = TestKey::new();
    stage_signed(&files, &key, |path, bytes| std::fs::write(path, bytes));
    assert_eq!(staged_at(&files, key.keys(), OLD, 0), None);
    let unvetted = SwapFiles::unvetted(&files.exe);
    assert_eq!(
        staged_at(&unvetted, key.keys(), OLD, 0),
        Some((files.staged(NEW), NEW))
    );
}

/// CI (elevated): a staging folder users could change is re-created admin-only before a
/// download, and an exe staged there owned by Administrators (as the service's files are) passes
/// the same vetting the swap applies.
#[test]
#[ignore = "needs elevation"]
fn elevated_the_staging_folder_is_recreated_admin_only() {
    assert!(vpnte_winnet::elevation::is_elevated(), "run elevated");
    let dir = TempDir::new("staging-acl");
    let files = SwapFiles::new(&dir.path().join("vpnte-service.exe"));
    std::fs::create_dir_all(&files.staging).expect("a planted, user-owned folder");
    assert!(!crate::sddl::path_admin_only(&files.staging));
    crate::paths::secure_dir(&files.staging).expect("re-created");
    assert!(crate::sddl::path_admin_only(&files.staging));
    let key = TestKey::new();
    stage_signed(&files, &key, |path, bytes| {
        let mut file = crate::sddl::create_admin_owned(path)?;
        std::io::Write::write_all(&mut file, bytes)
    });
    assert_eq!(
        staged_at(&files, key.keys(), OLD, 0),
        Some((files.staged(NEW), NEW))
    );
}
