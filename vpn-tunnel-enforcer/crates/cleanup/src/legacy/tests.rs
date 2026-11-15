use vpnte_base::types::KillSwitchLevel;

use super::journal::{FirewallJournal, Slot, TunOwner};
use super::*;
use crate::test_support::{TempDir, package_keys};

const STEPS: [StepId; 10] = [
    StepId::Processes,
    StepId::Journals,
    StepId::Firewall,
    StepId::SingTunRules,
    StepId::LegacyWfp,
    StepId::Adapters,
    StepId::DnsPolicy,
    StepId::TunAdapter,
    StepId::Tasks,
    StepId::Files,
];

fn ctx() -> Context {
    Context {
        resources: PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources")),
        level: KillSwitchLevel::Off,
        strict_ready: false,
    }
}

/// Unelevated (development, automated checks) nothing is attempted and the marker is not
/// written. Never run against this machine elevated.
#[test]
fn unelevated_calls_change_nothing() {
    if vpnte_winnet::elevation::is_elevated() {
        return;
    }
    let dir = TempDir::new("run");
    let marker = Store::<CleanupMarker>::open(dir.path());
    for mode in [Mode::Startup, Mode::Again] {
        let err = run(&marker, &ctx(), mode).unwrap_err();
        assert_eq!(err.kind, ErrorKind::Permission);
        assert_eq!(err.user_msg().key, "cleanup.legacy.needsAdmin");
    }
    assert!(!dir.path().join("legacy-network-cleanup.json").exists());
    assert_eq!(marker.snapshot(), CleanupMarker::default());
    assert_eq!(uninstall(&ctx()).unwrap_err().kind, ErrorKind::Permission);
}

/// Read-only: the root comes from the ProgramData known folder.
#[test]
fn root_is_under_program_data() {
    let root = vpnte_root().unwrap();
    assert!(root.ends_with("VPNTE"));
    assert!(root.parent().is_some_and(Path::is_dir));
}

fn record(step: StepId, outcome: Outcome) -> StepRecord {
    StepRecord::new(step, outcome, "")
}

fn journals() -> Journals {
    Journals {
        dir_problem: None,
        firewall: Slot::Valid(FirewallJournal {
            strict_mode: false,
            profiles: Vec::new(),
            skipped: Vec::new(),
        }),
        adapters: Slot::Absent,
        policy: Slot::Valid(true),
        tun_owner: Slot::Valid(TunOwner {
            alias: "Ethernet 5".into(),
            guid: windows::core::GUID::from_u128(7),
        }),
    }
}

/// A journal is deleted only when it was used and its own replay finished.
#[test]
fn journals_deleted_only_after_their_replay() {
    let j = journals();
    let mut report = CleanupReport::default();
    report.push(record(StepId::Firewall, Outcome::Done));
    report.push(record(StepId::LegacyWfp, Outcome::Done));
    report.push(record(StepId::DnsPolicy, Outcome::Done));
    assert_eq!(
        finished_journals(&j, &report, true, true),
        [journal::FIREWALL, journal::POLICY, journal::TUN_OWNER]
    );
    assert_eq!(
        finished_journals(&j, &report, true, false),
        [journal::FIREWALL, journal::POLICY]
    );

    let mut report = CleanupReport::default();
    report.push(record(StepId::Firewall, Outcome::Done));
    report.push(record(StepId::LegacyWfp, Outcome::Failed));
    assert_eq!(
        finished_journals(&j, &report, false, false),
        [journal::POLICY]
    );

    let mut report = CleanupReport::default();
    report.push(record(StepId::Firewall, Outcome::Failed));
    report.push(record(StepId::LegacyWfp, Outcome::Done));
    assert!(finished_journals(&j, &report, false, false).is_empty());

    let mut rejected = journals();
    rejected.firewall = Slot::Rejected("corrupt JSON".into());
    let mut report = CleanupReport::default();
    report.push(record(StepId::Firewall, Outcome::Done));
    report.push(record(StepId::LegacyWfp, Outcome::Done));
    assert_eq!(
        finished_journals(&rejected, &report, false, false),
        [journal::POLICY]
    );

    // A salvaged firewall.json stays unless strict evidence made its saved values irrelevant.
    let mut salvaged = journals();
    if let Slot::Valid(f) = &mut salvaged.firewall {
        f.skipped.push("firewall Public: no valid snapshot".into());
    }
    assert_eq!(
        finished_journals(&salvaged, &report, false, false),
        [journal::FIREWALL, journal::POLICY]
    );
    salvaged.policy = Slot::Valid(false);
    assert_eq!(
        finished_journals(&salvaged, &report, false, false),
        [journal::POLICY]
    );
}

/// Every key the code emits exists in this package's fragment, which holds only
/// `cleanup.legacy.*` keys (validity and ru / en parity: `test_support`).
#[test]
fn emitted_keys_exist() {
    let known = package_keys("cleanup-legacy");
    assert!(known.iter().all(|k| k.starts_with("cleanup.legacy.")));
    let mut used: Vec<String> = Vec::new();
    for step in STEPS {
        for outcome in [Outcome::Done, Outcome::Skipped, Outcome::Failed] {
            used.push(record(step, outcome).msg().key.into_owned());
        }
    }
    let mut report = CleanupReport {
        firewall_reset: true,
        firewall_allow_all: true,
        ..CleanupReport::default()
    };
    report.push(record(StepId::Files, Outcome::Failed).changed(true));
    for notice in report.notices() {
        used.push(notice.title.key.into_owned());
        used.extend(notice.body.map(|b| b.key.into_owned()));
    }
    report.steps[0].outcome = Outcome::Done;
    used.extend(
        report
            .notices()
            .into_iter()
            .map(|n| n.title.key.into_owned()),
    );
    used.push(needs_admin().user_msg().key.into_owned());
    for key in used {
        assert!(known.contains(&key), "missing {key}");
    }
}
