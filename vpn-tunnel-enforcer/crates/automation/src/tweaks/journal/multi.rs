//! Several processes on one journal (the app, its crash watcher, the next start): each one is a
//! `Journal` with its own copy and its own [`Writer`], as in production.
use std::sync::Arc;

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::test_support::Fake;

const APP: Writer = Writer {
    pid: 4100,
    started: 1,
};
const NEXT: Writer = Writer {
    pid: 4200,
    started: 2,
};
const WATCHER: Writer = Writer {
    pid: 4300,
    started: 3,
};

fn var() -> Target {
    Target::Env {
        var: EnvVar::HttpProxy,
    }
}

fn sz(s: &str) -> Val {
    Val::Sz(s.into())
}

fn plan(url: &str) -> Vec<(Feature, Target, Val)> {
    vec![(Feature::SoftEnv, var(), sz(url))]
}

fn open(dir: &TempDir, me: Writer) -> Journal {
    Journal::open_as(dir.path(), no_registry, me)
}

/// The crash watcher's call: the env feature, left by `app`.
fn left_by(journal: &Journal, app: Writer, backend: &dyn Backend) -> Option<RollbackReport> {
    journal.rollback_left(backend, &[Feature::SoftEnv], |w| w == app, |_| {})
}

/// The watcher rolls back what its dead app left; the next start, whose copy was read before
/// that, finds nothing left to do and writes nothing (its stale records are not replayed).
#[test]
fn a_rollback_repeated_by_another_process_changes_nothing() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), sz("http://corp:8080"))]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let next = open(&dir, NEXT);
    assert!(
        next.is_applied(Feature::SoftEnv),
        "copy read before the watcher ran"
    );

    let report = left_by(&open(&dir, WATCHER), APP, &fake);
    assert_eq!(report.map(|r| r.restored), Some(vec![var()]));
    assert_eq!(fake.get(&var()), sz("http://corp:8080"));
    let writes = fake.write_count();

    let again = next.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(again, RollbackReport::default());
    assert_eq!(fake.write_count(), writes);
    assert!(!next.is_applied(Feature::SoftEnv));
}

/// A watcher that wakes after the next start already recovered and connected leaves that new
/// session alone: the journal is no longer its app's.
#[test]
fn a_late_watcher_leaves_the_next_session_alone() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), sz("http://corp:8080"))]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let next = open(&dir, NEXT);
    assert!(next.rollback(&fake, &[Feature::SoftEnv]).is_complete());
    next.apply(&fake, &plan("http://127.0.0.1:20809")).unwrap();

    let late = left_by(&open(&dir, WATCHER), APP, &fake);
    assert_eq!(late, None);
    assert_eq!(fake.get(&var()), sz("http://127.0.0.1:20809"));
    assert!(open(&dir, NEXT).is_applied(Feature::SoftEnv));
}

/// A journal no process of this version changed (an older build's) is left to the next start.
#[test]
fn a_watcher_never_rolls_back_a_journal_it_cannot_attribute() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), Val::Absent)]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    Store::<TweakDoc>::open(dir.path())
        .update(|d| d.writer = None)
        .unwrap();
    let watcher = open(&dir, WATCHER);
    assert_eq!(left_by(&watcher, APP, &fake), None);
    assert_eq!(fake.get(&var()), sz("http://127.0.0.1:10809"));
}

/// A copy read before another process rolled back must not bring the old baseline back: the
/// value the user set after that rollback is the new session's baseline.
#[test]
fn a_stale_copy_journals_the_value_found_now() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), sz("http://corp:8080"))]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let next = open(&dir, NEXT);
    left_by(&open(&dir, WATCHER), APP, &fake);
    fake.set(&var(), sz("http://home:3128"));

    next.apply(&fake, &plan("http://127.0.0.1:20809")).unwrap();
    assert_eq!(
        next.records(Feature::SoftEnv)[0].baseline,
        sz("http://home:3128")
    );
    assert!(next.rollback(&fake, &[Feature::SoftEnv]).is_complete());
    assert_eq!(fake.get(&var()), sz("http://home:3128"));
}

/// Two processes rolling back at the same moment: every value is restored once, nothing stays
/// journalled.
#[test]
fn simultaneous_rollbacks_restore_each_value_once() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Arc::new(Fake::with(&[(var(), sz("http://corp:8080"))]));
    open(&dir, APP)
        .apply(&*fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let before = fake.write_count();
    let (watcher, next) = (open(&dir, WATCHER), open(&dir, NEXT));
    let other = fake.clone();
    let thread = std::thread::spawn(move || left_by(&watcher, APP, &*other));
    next.rollback(&*fake, &[Feature::SoftEnv]);
    thread.join().unwrap();

    assert_eq!(fake.write_count(), before + 1);
    assert_eq!(fake.get(&var()), sz("http://corp:8080"));
    assert!(!open(&dir, NEXT).is_applied(Feature::SoftEnv));
}

/// Dropping records outside the allow-list at open is housekeeping: the journal stays the app's.
#[test]
fn housekeeping_at_open_keeps_the_writer() {
    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), Val::Absent)]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let foreign = Record {
        feature: Feature::BrowserWebRtc,
        target: Target::Reg {
            hive: RegHive::Hkcu,
            key: r"Software\Policies\Example".into(),
            name: "Value".into(),
        },
        baseline: Val::Absent,
        applied: Val::Dword(1),
        created: false,
    };
    Store::<TweakDoc>::open(dir.path())
        .update(|d| d.records.push(foreign))
        .unwrap();
    let watcher = open(&dir, WATCHER);
    let report = left_by(&watcher, APP, &fake);
    assert!(report.is_some_and(|r| r.is_complete()));
    assert_eq!(fake.get(&var()), Val::Absent);
}

/// `after` sees the report while the journal is still locked against every other process (the
/// logon value follows it there); a writer `left` does not accept gets neither.
#[test]
fn after_runs_under_the_lock_and_only_for_an_accepted_writer() {
    use std::fs::{OpenOptions, TryLockError};

    let dir = TempDir::new("tweaks-multi");
    let fake = Fake::with(&[(var(), sz("http://corp:8080"))]);
    open(&dir, APP)
        .apply(&fake, &plan("http://127.0.0.1:10809"))
        .unwrap();
    let watcher = open(&dir, WATCHER);

    let refused = watcher.rollback_left(
        &fake,
        &[Feature::SoftEnv],
        |w| w == NEXT,
        |_| panic!("after must not run for a refused writer"),
    );
    assert_eq!(refused, None);

    let mut seen = None;
    let report = watcher.rollback_left(
        &fake,
        &[Feature::SoftEnv],
        |w| w == APP,
        |r| {
            let probe = OpenOptions::new()
                .write(true)
                .open(dir.path().join(LOCK_FILE))
                .unwrap();
            assert!(matches!(probe.try_lock(), Err(TryLockError::WouldBlock)));
            seen = Some(r.clone());
        },
    );
    assert!(report.as_ref().is_some_and(RollbackReport::is_complete));
    assert_eq!(seen, report);
}
