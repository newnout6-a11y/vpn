use std::sync::Arc;

use vpnte_base::{ErrorKind, Msg};

use super::*;
use crate::hardening::admit;
use crate::hardening::fake::{Fake, reg};
use crate::test_support::TempDir;
use crate::tweaks::journal::Record;

struct Setup {
    _dir: TempDir,
    fake: Arc<Fake>,
    journal: Arc<Journal>,
    location: Location,
}

fn setup(fake: Fake) -> Setup {
    let dir = TempDir::new("hardening");
    let fake = Arc::new(fake);
    let journal = Arc::new(Journal::open(&dir.0, admit));
    let location = Location::new(journal.clone(), fake.clone());
    Setup {
        _dir: dir,
        fake,
        journal,
        location,
    }
}

fn consent() -> Target {
    reg(CONSENT.0, CONSENT.1, CONSENT.2)
}

fn policy(name: &str) -> Target {
    reg(RegHive::Hklm, POLICY_KEY, name)
}

fn deny() -> Val {
    Val::Sz("Deny".into())
}

/// `locationPrivacy.test.ts`: `Value = Deny` → denied (by the user, not by us: L3); nothing set
/// → all false; an unreadable value → not checked.
#[test]
fn status_reports_os_state_apart_from_ours() {
    let s = setup(Fake::default());
    let status = s.location.status_blocking();
    let clean = LocationStatus {
        ours: TweakState::Off,
        user_denied: Some(false),
        policy_disabled: Some(false),
    };
    assert_eq!(status, clean);
    assert_eq!(status.os_denied(), Some(false));

    s.fake.set(&consent(), deny());
    let status = s.location.status_blocking();
    assert_eq!(status.user_denied, Some(true));
    assert_eq!(status.os_denied(), Some(true));
    assert_eq!(status.ours, TweakState::Off);

    s.fake
        .set(&policy("DisableWindowsLocationProvider"), Val::Dword(1));
    assert_eq!(s.location.status_blocking().policy_disabled, Some(true));
    s.fake.fail_read.lock().insert(consent());
    assert_eq!(s.location.status_blocking().user_denied, None);
}

/// `locationPrivacy.test.ts`: apply → HKCU `Value=Deny`. NOADMIN §3: the machine policies are not
/// written any more (per user, no elevation).
#[test]
fn apply_denies_the_user_consent_only() {
    let s = setup(Fake::default());
    let status = s.location.apply_blocking().unwrap();
    assert_eq!(s.fake.get(&consent()), deny());
    for name in POLICY_VALUES {
        assert_eq!(s.fake.get(&policy(name)), Val::Absent);
    }
    assert_eq!(s.fake.write_count(), 1);
    assert_eq!(status.ours, TweakState::On);
    assert_eq!(status.os_denied(), Some(true));
    assert!(s.location.is_applied());
}

/// `locationPrivacy.test.ts:150-183`: unreadable prior state → abort with no write.
#[test]
fn unreadable_prior_state_aborts_without_writes() {
    let fake = Fake::default();
    fake.fail_read.lock().insert(consent());
    let s = setup(fake);
    let err = s.location.apply_blocking().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Permission);
    let msg = Msg::new("automation.hardening.location.unreadable").arg("hive", "HKCU");
    assert_eq!(err.user_msg(), msg);
    assert_eq!(s.fake.write_count(), 0);
    assert!(!s.location.is_applied());
}

/// `locationPrivacy.test.ts`: an absent baseline → rollback deletes `Value` and leaves the rest of
/// the key alone (L1: per value, no `.reg` import).
#[test]
fn rollback_deletes_absent_baselines_and_keeps_unrelated() {
    let fake = Fake::default();
    fake.set(&policy("Unrelated"), Val::Dword(5));
    let unrelated = reg(CONSENT.0, CONSENT.1, "Unrelated");
    fake.set(&unrelated, Val::Sz("x".into()));
    let s = setup(fake);
    s.location.apply_blocking().unwrap();
    let report = s.location.rollback_blocking();
    assert!(report.is_complete());
    assert_eq!(report.restored, vec![consent()]);
    assert_eq!(rollback_failure_msg(&report), None);
    assert_eq!(s.fake.get(&consent()), Val::Absent);
    assert_eq!(s.fake.get(&unrelated), Val::Sz("x".into()));
    assert_eq!(s.fake.get(&policy("Unrelated")), Val::Dword(5));
    assert!(!s.location.is_applied());
}

/// `locationPrivacy.test.ts`: a failing delete keeps its record; the next rollback finishes.
#[test]
fn failing_delete_keeps_the_record() {
    let s = setup(Fake::default());
    s.location.apply_blocking().unwrap();
    s.fake.fail_write.lock().insert(consent());
    let report = s.location.rollback_blocking();
    assert_eq!(report.failed, vec![consent()]);
    let failure = Msg::new("automation.hardening.location.rollbackFailed");
    assert_eq!(rollback_failure_msg(&report), Some(failure));
    assert_eq!(s.journal.records(Feature::LocationPrivacy).len(), 1);
    assert_eq!(s.fake.get(&consent()), deny());
    s.fake.fail_write.lock().clear();
    assert!(s.location.rollback_blocking().is_complete());
    assert_eq!(s.fake.get(&consent()), Val::Absent);
    assert!(!s.location.is_applied());
}

/// Re-applying keeps the original baseline; rollback brings back the user's own choice and never
/// touches the machine policy.
#[test]
fn reapply_keeps_the_original_baseline() {
    let fake = Fake::default();
    fake.set(&consent(), Val::Sz("Allow".into()));
    fake.set(&policy("DisableLocation"), Val::Dword(0));
    let s = setup(fake);
    s.location.apply_blocking().unwrap();
    s.location.apply_blocking().unwrap();
    assert!(s.location.rollback_blocking().is_complete());
    assert_eq!(s.fake.get(&consent()), Val::Sz("Allow".into()));
    assert_eq!(s.fake.get(&policy("DisableLocation")), Val::Dword(0));
}

/// A refused write leaves nothing behind; nothing is journalled.
#[test]
fn failed_write_leaves_nothing() {
    let fake = Fake::default();
    fake.fail_write.lock().insert(consent());
    let s = setup(fake);
    let err = s.location.apply_blocking().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Permission);
    let failed = Msg::new("automation.hardening.location.failed");
    assert_eq!(err.user_msg(), failed);
    assert_eq!(s.fake.get(&consent()), Val::Absent);
    assert!(!s.location.is_applied());
}

/// AT-09-001 semantics: the user re-allowing location while connected is kept by the rollback.
#[test]
fn user_change_is_kept_by_the_rollback() {
    let s = setup(Fake::default());
    s.location.apply_blocking().unwrap();
    s.fake.set(&consent(), Val::Sz("Allow".into()));
    assert_eq!(s.location.status_blocking().ours, TweakState::Drifted);
    let report = s.location.rollback_blocking();
    assert_eq!(report.kept_user_value, vec![consent()]);
    assert_eq!(s.fake.get(&consent()), Val::Sz("Allow".into()));
}

/// Spec E3: as another administrator the HKCU consent would land in the wrong profile.
#[test]
fn other_user_is_refused() {
    let s = setup(Fake {
        other_user: true,
        ..Fake::default()
    });
    let err = s.location.apply_blocking().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg(), Msg::new("automation.tweaks.otherUser"));
    assert_eq!(s.fake.write_count(), 0);
}

/// NOADMIN §3: location privacy is per user and works without elevation.
#[test]
fn unelevated_apply_denies_the_consent() {
    let s = setup(Fake {
        unelevated: true,
        ..Fake::default()
    });
    assert_eq!(s.location.apply_blocking().unwrap().ours, TweakState::On);
    assert_eq!(s.fake.get(&consent()), deny());
    assert!(s.location.rollback_blocking().is_complete());
    assert_eq!(s.fake.get(&consent()), Val::Absent);
}

/// Machine policies journalled by the old version stay obligations: rolled back where the write
/// is allowed (elevated), kept for a retry with the failure reported where it is refused.
#[test]
fn old_policy_records_are_still_rolled_back() {
    let fake = Fake::default();
    for name in POLICY_VALUES {
        fake.set(&policy(name), Val::Dword(1));
    }
    fake.fail_write.lock().insert(policy("DisableLocation"));
    let s = setup(fake);
    let records = POLICY_VALUES.map(|name| Record {
        feature: Feature::LocationPrivacy,
        target: policy(name),
        baseline: Val::Absent,
        applied: Val::Dword(1),
        created: false,
    });
    assert_eq!(s.journal.adopt_legacy(records.to_vec()).unwrap(), 2);
    let report = s.location.rollback_blocking();
    assert_eq!(report.failed, vec![policy("DisableLocation")]);
    assert!(rollback_failure_msg(&report).is_some());
    assert_eq!(
        s.fake.get(&policy("DisableWindowsLocationProvider")),
        Val::Absent
    );
    s.fake.fail_write.lock().clear();
    assert!(s.location.rollback_blocking().is_complete());
    assert_eq!(s.fake.get(&policy("DisableLocation")), Val::Absent);
    assert!(!s.location.is_applied());
}

/// b1: unelevated, the old version's machine policies are neither written (every attempt
/// would be refused) nor reported as a failed rollback (no notice per start, stop or toggle):
/// their records wait for an elevated process. They do not count as "applied" either, so the
/// user's own consent is applied and rolled back as usual next to them.
#[test]
fn unelevated_old_policies_wait_without_blocking_the_consent() {
    let fake = Fake {
        unelevated: true,
        ..Fake::default()
    };
    for name in POLICY_VALUES {
        fake.set(&policy(name), Val::Dword(1));
    }
    let s = setup(fake);
    let records = POLICY_VALUES.map(|name| Record {
        feature: Feature::LocationPrivacy,
        target: policy(name),
        baseline: Val::Absent,
        applied: Val::Dword(1),
        created: false,
    });
    assert_eq!(s.journal.adopt_legacy(records.to_vec()).unwrap(), 2);
    assert!(
        !s.location.is_applied(),
        "machine leftovers hold nothing up"
    );
    let report = s.location.rollback_blocking();
    assert!(report.is_complete() && rollback_failure_msg(&report).is_none());
    assert_eq!(s.fake.write_count(), 0, "no machine write tried");
    assert_eq!(s.journal.records(Feature::LocationPrivacy).len(), 2);
    s.location.apply_blocking().unwrap();
    assert!(s.location.is_applied());
    assert_eq!(s.fake.get(&consent()), deny());
    assert!(s.location.rollback_blocking().is_complete());
    assert_eq!(s.fake.get(&consent()), Val::Absent);
    assert!(!s.location.is_applied());
    assert_eq!(s.fake.get(&policy("DisableLocation")), Val::Dword(1));
}

/// A current value the journal could not record (consent as a DWORD) is refused, not written.
#[test]
fn foreign_value_type_is_refused() {
    let fake = Fake::default();
    fake.set(&consent(), Val::Dword(0));
    let s = setup(fake);
    let err = s.location.apply_blocking().unwrap_err();
    assert_eq!(err.kind, ErrorKind::Conflict);
    let foreign = Msg::new("automation.hardening.location.foreignValue");
    assert_eq!(err.user_msg(), foreign);
    assert_eq!(s.fake.write_count(), 0);
}

/// The async API runs on the blocking pool.
#[tokio::test]
async fn async_api() {
    let s = setup(Fake::default());
    assert_eq!(s.location.apply().await.unwrap().ours, TweakState::On);
    assert_eq!(s.location.status().await.unwrap().ours, TweakState::On);
    assert!(s.location.rollback().await.unwrap().is_complete());
    assert_eq!(s.location.status().await.unwrap().ours, TweakState::Off);
}
