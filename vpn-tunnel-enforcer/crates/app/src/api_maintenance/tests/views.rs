//! Pure mappings: tunnel phase, protection read-back, repair outcomes, export progress, leak
//! evidence, capture and fault views.
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use vpnte_base::types::{KillSwitchLevel, Verdict};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_cleanup::legacy::{CleanupReport, Outcome, Run, StepId, StepRecord};
use vpnte_forensics::export::{ExportProgress, ExportStage};
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot, TunnelState};
use vpnte_ui::maintenance::{FwProfile, KillSwitchState, StepOutcome, TunnelPhase};
use vpnte_winnet::process::{OwnedProc, SweepReport, UnknownProc, UnknownReason};
use vpnte_winnet::wfp::{
    self, Conn, FwProfileBlock, KillSwitchState as WfpState, ProtectionError, ProtectionStatus,
    RemoveReport,
};

use crate::api_maintenance::export::export_view;
use crate::api_maintenance::project::phase;
use crate::api_maintenance::protection::{Machine, from_status, unelevated};
use crate::api_maintenance::repair::{engines_outcome, filters_outcome, legacy_outcome};

fn snap(state: TunnelState, transition: Option<Transition>) -> TunnelSnapshot {
    TunnelSnapshot {
        state,
        transition,
        ..TunnelSnapshot::default()
    }
}

/// AT-00-008: a transition is never shown as a settled state. A transition wins; a held kill
/// switch or an open session counts as "on"; a settled failure without a session lets the
/// repair run (it is how stale filters get removed).
#[test]
fn tunnel_phase_gates_the_page() {
    use TunnelState::*;
    assert_eq!(
        phase(&snap(Connected, Some(Transition::Disconnecting)), true),
        TunnelPhase::Busy
    );
    assert_eq!(
        phase(&snap(Disconnected, Some(Transition::Connecting)), false),
        TunnelPhase::Busy
    );
    assert_eq!(phase(&snap(Connected, None), true), TunnelPhase::On);
    assert_eq!(phase(&snap(Blocked, None), false), TunnelPhase::On);
    assert_eq!(phase(&snap(Error, None), true), TunnelPhase::On);
    assert_eq!(phase(&snap(Error, None), false), TunnelPhase::Off);
    assert_eq!(phase(&snap(Unknown, None), false), TunnelPhase::Off);
    assert_eq!(phase(&snap(Disconnected, None), false), TunnelPhase::Off);
}

fn status(
    kill_switch: WfpState,
    dynamic: Option<u32>,
    persistent: Option<u32>,
) -> ProtectionStatus {
    ProtectionStatus {
        level: KillSwitchLevel::Standard,
        conn: Conn::Up,
        kill_switch,
        last_error: None,
        leak_protection_active: true,
        dynamic_filters: dynamic,
        persistent_filters: persistent,
        sublayer_weight: Some(0xFFFF),
        bfe_running: None,
        last_verified: Some(42),
        skipped_exceptions: Vec::new(),
        windows_firewall_outbound_block: None,
        hyperv_switch_present: Some(false),
    }
}

fn machine(bfe: Option<bool>) -> Machine {
    Machine {
        bfe_running: bfe,
        firewall_blocks: Some(vec![FwProfileBlock {
            profile: wfp::FwProfile::Public,
            active: true,
        }]),
    }
}

/// AT-03-005 (no false success; firewall-recovery §6.5 status): the read-back maps state,
/// counts, BFE and the firewall profiles; a count that could not be read is a failure line,
/// never a verified 0.
#[test]
fn protection_read_back_is_mapped_honestly() {
    let view = from_status(
        &status(WfpState::Engaged, Some(7), Some(0)),
        &machine(Some(true)),
    );
    assert_eq!(view.kill_switch, KillSwitchState::Engaged);
    assert_eq!((view.dynamic_filters, view.persistent_filters), (7, 0));
    assert!(view.bfe_running, "BFE falls back to the service read");
    assert!(view.leak_protection_active);
    assert_eq!(view.last_verified, Some(42));
    assert_eq!(view.firewall_blocks.len(), 1);
    assert_eq!(view.firewall_blocks[0].profile, FwProfile::Public);
    assert!(view.firewall_blocks[0].active);

    let unread = from_status(&status(WfpState::Off, None, Some(0)), &machine(Some(true)));
    assert_eq!(
        unread.kill_switch,
        KillSwitchState::Failed(Msg::new("app.maintenance.protection.unreadable"))
    );

    let mut failed = status(WfpState::Failed, Some(0), Some(0));
    failed.last_error = Some(ProtectionError::AccessDenied);
    let view = from_status(&failed, &machine(None));
    assert_eq!(
        view.kill_switch,
        KillSwitchState::Failed(ProtectionError::AccessDenied.msg())
    );
    assert!(
        !view.bfe_running,
        "an unread BFE state is never shown as running"
    );
}

/// NOADMIN §0, p-noadmin-ui: without the service and unelevated there are no filters of ours;
/// the state line says the protection acts through the system proxy (calm, not a failure) and
/// nothing claims a verification.
#[test]
fn unelevated_protection_says_it_acts_through_the_proxy() {
    let view = unelevated(KillSwitchLevel::Off, &machine(Some(true)));
    assert_eq!(view.kill_switch, KillSwitchState::ProxyOnly);
    assert_eq!(view.last_verified, None);
    assert!(!view.leak_protection_active);
    assert!(view.bfe_running);
    assert_eq!(view.firewall_blocks.len(), 1);
    assert!(!unelevated(KillSwitchLevel::Off, &machine(None)).bfe_running);
}

/// AT-03-007 (each step reported on its own). Repair step 1: nothing to remove, removed
/// filters, refusals and failures.
#[test]
fn filter_step_outcomes() {
    let none = RemoveReport {
        filters: 0,
        sublayer: false,
        provider: false,
    };
    assert_eq!(filters_outcome(Ok(none)), StepOutcome::done(Vec::new()));
    let some = filters_outcome(Ok(RemoveReport {
        filters: 6,
        sublayer: true,
        provider: true,
    }));
    assert!(some.success && !some.blocked);
    assert_eq!(
        some.message,
        Some(Msg::new("app.maintenance.repair.filtersRemoved").arg("count", 6))
    );
    let denied = filters_outcome(Err(crate::svc_core::needs_admin()));
    assert!(denied.blocked && !denied.success);
    assert_eq!(denied.message, Some(Msg::new("app.base.needsAdmin")));
    assert!(filters_outcome(Err(AppError::new(ErrorKind::Conflict))).blocked);
    let broken = filters_outcome(Err(AppError::new(ErrorKind::Internal)));
    assert!(!broken.success && !broken.blocked);
}

fn record(step: StepId, outcome: Outcome, changed: bool) -> StepRecord {
    StepRecord {
        step,
        outcome,
        changed,
        detail: String::new(),
    }
}

/// Repair step 2: the old version's cleanup run again — deferred and unelevated runs are
/// refusals, a failed step fails the row with the cleanup's own summary.
#[test]
fn legacy_step_outcomes() {
    assert!(legacy_outcome(Ok(Run::Deferred)).blocked);
    let denied = legacy_outcome(Err(AppError::msg(
        ErrorKind::Permission,
        Msg::new("cleanup.legacy.needsAdmin"),
    )));
    assert!(denied.blocked);
    assert_eq!(denied.message, Some(Msg::new("cleanup.legacy.needsAdmin")));
    assert_eq!(
        legacy_outcome(Ok(Run::NotDue)),
        StepOutcome::done(Vec::new())
    );
    let clean = CleanupReport {
        steps: vec![record(StepId::Tasks, Outcome::Done, false)],
        ..CleanupReport::default()
    };
    assert_eq!(
        legacy_outcome(Ok(Run::Finished(clean))),
        StepOutcome::done(Vec::new())
    );
    let partial = CleanupReport {
        steps: vec![
            record(StepId::Firewall, Outcome::Done, true),
            record(StepId::LegacyWfp, Outcome::Failed, false),
        ],
        ..CleanupReport::default()
    };
    let row = legacy_outcome(Ok(Run::Finished(partial)));
    assert!(!row.success && !row.blocked);
    assert_eq!(
        row.message,
        Some(
            Msg::new("cleanup.legacy.notice.summary")
                .arg("changed", 1)
                .arg("failed", 1)
        )
    );
    let reset = CleanupReport {
        steps: vec![record(StepId::Firewall, Outcome::Done, true)],
        firewall_reset: true,
        ..CleanupReport::default()
    };
    let row = legacy_outcome(Ok(Run::Finished(reset)));
    assert!(row.success && row.warning);
}

fn owned(pid: u32) -> OwnedProc {
    OwnedProc {
        pid,
        path: PathBuf::from(r"C:\Fake\resources\sing-box.exe"),
    }
}

/// Repair step 3: survivors fail the row, unknown ownership is a warning (never "clean"),
/// stopped orphans are counted.
#[test]
fn engine_step_outcomes() {
    assert_eq!(
        engines_outcome(Ok(SweepReport::default())),
        StepOutcome::done(Vec::new())
    );
    let stopped = engines_outcome(Ok(SweepReport {
        stopped: vec![owned(10), owned(11)],
        ..SweepReport::default()
    }));
    assert!(stopped.success && !stopped.warning);
    assert_eq!(
        stopped.message,
        Some(Msg::new("winnet.process.sweep.stopped").arg("count", 2))
    );
    let unknown = engines_outcome(Ok(SweepReport {
        unknown: vec![UnknownProc {
            pid: 12,
            name: "xray.exe".into(),
            reason: UnknownReason::OpenFailed,
        }],
        ..SweepReport::default()
    }));
    assert!(unknown.success && unknown.warning);
    let survived = engines_outcome(Ok(SweepReport {
        stopped: vec![owned(10)],
        survived: vec![owned(13)],
        ..SweepReport::default()
    }));
    assert!(!survived.success && !survived.blocked);
    assert_eq!(
        survived.message,
        Some(Msg::new("winnet.process.sweep.survived").arg("count", 1))
    );
    assert!(!engines_outcome(Err(AppError::new(ErrorKind::Internal))).success);
}

/// AT-00-003: the export's stages become the progress line; idle clears it.
#[test]
fn export_progress_is_published_per_stage() {
    assert_eq!(
        export_view(None),
        vpnte_ui::maintenance::ExportView::default()
    );
    let start = export_view(Some(ExportProgress::default()));
    assert!(start.running);
    assert_eq!(start.progress, Some(0.0));
    assert_eq!(start.stage, Some(ExportStage::Preparing.label()));
    let last = export_view(Some(ExportProgress {
        stage: ExportStage::Finishing,
        entries: 9,
        bytes: 1,
    }));
    let expected = f64::from(ExportStage::COUNT - 1) / f64::from(ExportStage::COUNT);
    assert_eq!(last.progress, Some(expected));
}

/// The leak panel is built from the evidence: verdict, per-address reach, the tunnel's exit
/// and the services' disagreement.
#[test]
fn leak_evidence_becomes_the_panel() {
    use vpnte_probes::leak::{AddrProbe, Disagreement, Reach, SelfTestResult, Why};
    use vpnte_ui::maintenance::{LeakVerdict, ProbeReach};
    let local = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
    let result = SelfTestResult {
        at: 7,
        kill_switch: KillSwitchLevel::Standard,
        default_v4: Some(Ipv4Addr::new(203, 0, 113, 9)),
        probes: vec![
            AddrProbe {
                alias: "Ethernet".into(),
                local,
                reach: Reach::Reached {
                    ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
                },
                stderr_tail: None,
            },
            AddrProbe {
                alias: "Wi-Fi".into(),
                local,
                reach: Reach::Inconclusive {
                    curl_exit: Some(6),
                    why: Why::Dns,
                },
                stderr_tail: Some("Could not resolve host".into()),
            },
        ],
        inspection_complete: true,
        services_disagree: Some(Disagreement {
            other_service_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)),
            default_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        }),
        cancelled: false,
        default_direct: false,
    };
    let view = crate::api_maintenance::selftest::leak_view(&result);
    assert_eq!(
        view.verdict,
        LeakVerdict::Leak,
        "reach with the kill switch on"
    );
    assert_eq!(view.headline, Msg::new("probes.leak.selfTest.leak"));
    assert_eq!(view.tun_ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(
        view.adapters[0].reach,
        ProbeReach::Reached {
            public_ip: "198.51.100.4".into()
        }
    );
    assert_eq!(view.adapters[0].local.as_deref(), Some("192.168.1.20"));
    assert_eq!(
        view.adapters[1].reach,
        ProbeReach::Unknown {
            curl_exit: Some(6),
            why: Why::Dns.label()
        }
    );
    assert!(view.disagreement.is_some());
    let soft = SelfTestResult {
        kill_switch: KillSwitchLevel::Off,
        ..result
    };
    assert_eq!(
        crate::api_maintenance::selftest::leak_view(&soft).verdict,
        LeakVerdict::PossibleLeak
    );
}

/// NOADMIN §0: nothing captures in this build, elevated or not, and the helper service does not
/// carry it: the first warning says «not in this version» (never «needs the service»), and
/// nothing reads as "status unavailable" or "stop not confirmed".
#[test]
fn capture_view_says_why_nothing_captures() {
    use crate::api_maintenance::project::{capture_refusal, capture_view};
    let view = capture_view();
    assert!(!view.running && !view.enabled && !view.status_unavailable && !view.cleanup_pending);
    // The page disables «restart» up front.
    assert!(!view.available);
    let why = Msg::new("app.maintenance.capture.unavailable");
    assert_eq!(view.warnings, vec![why.clone()]);
    assert_eq!(view.last_error, Some(why));
    assert_eq!(capture_refusal().kind, ErrorKind::Conflict);
}

/// The fault box shows the last error of a backend crate; UI action lines and warnings are left
/// out.
#[test]
fn last_fault_is_the_newest_backend_error() {
    use vpnte_core::logging::Problem;
    let problem = |at, level, target: &str, msg: &str| Problem {
        at,
        level,
        target: target.into(),
        msg: msg.into(),
    };
    let problems = vec![
        problem(
            1,
            tracing::Level::ERROR,
            "vpnte_tunnel::lifecycle",
            "engine exited",
        ),
        problem(2, tracing::Level::WARN, "vpnte_engine::xray", "slow start"),
        problem(3, tracing::Level::ERROR, "ui", "maintenance: export failed"),
    ];
    let fault = crate::api_maintenance::project::last_fault(&problems).expect("a fault");
    assert_eq!(fault.at, 1);
    assert_eq!(fault.code, "tunnel::lifecycle");
    assert_eq!(fault.detail, "engine exited");
    assert!(crate::api_maintenance::project::last_fault(&problems[1..]).is_none());
}

/// Only a damaged server list (it holds keys) is offered for setting aside; the old cleanup's
/// failed steps are listed with their own sentences.
#[test]
fn legacy_panel_lists_corrupt_stores_and_failed_cleanup_steps() {
    use crate::api_maintenance::legacy::{cleanup_failures, corrupt_stores};
    use vpnte_cleanup::legacy::CleanupMarker;
    use vpnte_core::store::{Mode, ReadOnlyReason};
    assert!(corrupt_stores(Mode::Writable).is_empty());
    assert!(corrupt_stores(Mode::ReadOnly(ReadOnlyReason::NewerVersion(9))).is_empty());
    let corrupt = corrupt_stores(Mode::ReadOnly(ReadOnlyReason::Corrupt));
    assert_eq!(corrupt.len(), 1);
    assert_eq!(corrupt[0].id, "profiles");
    assert_eq!(corrupt[0].file, "profiles.json");
    let marker = CleanupMarker {
        steps: vec![
            record(StepId::Firewall, Outcome::Done, true),
            record(StepId::Tasks, Outcome::Failed, false),
        ],
        ..CleanupMarker::default()
    };
    assert_eq!(cleanup_failures(&marker), vec![marker.steps[1].msg()]);
}

/// The report keeps its rows and order; categories map one to one.
#[test]
fn system_report_rows_are_kept() {
    use vpnte_probes::diagnostics::{Category, CheckItem, SystemReport};
    use vpnte_ui::maintenance::DiagCategory;
    let report = SystemReport {
        ran_at: 5,
        summary: Verdict::Warn,
        items: vec![
            CheckItem::new(
                "adapters",
                Category::Network,
                "probes.diag.adapters.label",
                Some(Verdict::Ok),
                Msg::new("x"),
            ),
            CheckItem::new(
                "routing-ipv4",
                Category::Routing,
                "probes.diag.x",
                None,
                Msg::new("y"),
            )
            .note(Msg::new("z")),
        ],
    };
    let view = crate::api_maintenance::report::to_view(report);
    assert_eq!(view.ran_at, 5);
    assert_eq!(view.items.len(), 2);
    assert_eq!(view.items[0].category, DiagCategory::Network);
    assert_eq!(view.items[0].verdict, Some(Verdict::Ok));
    assert_eq!(view.items[1].category, DiagCategory::Routing);
    assert_eq!(view.items[1].notes, vec![Msg::new("z")]);
}

/// The sweep looks under the folders the engines are launched from, each folder once.
#[test]
fn engine_sweep_covers_each_engine_folder_once() {
    use crate::api_maintenance::repair::engine_dirs;
    use crate::services::Engines;
    let together = Engines {
        singbox: PathBuf::from(r"C:\App\resources\sing-box.exe"),
        xray: PathBuf::from(r"C:\App\resources\xray.exe"),
    };
    assert_eq!(
        engine_dirs(&together),
        vec![PathBuf::from(r"C:\App\resources")]
    );
    let apart = Engines {
        singbox: PathBuf::from(r"C:\App\resources\sing-box.exe"),
        xray: PathBuf::from(r"D:\Engines\xray.exe"),
    };
    assert_eq!(
        engine_dirs(&apart),
        vec![
            PathBuf::from(r"C:\App\resources"),
            PathBuf::from(r"D:\Engines")
        ]
    );
}

/// The archive's recovery state: a document never written is absent, a written one is packed
/// as its store holds it; the tweak journal says which features still hold changes (no values).
#[test]
fn recovery_state_for_the_archive() {
    use vpnte_automation::{hardening, tweaks};
    use vpnte_core::store::Store;
    use vpnte_forensics::export::RecoveryRead;

    use crate::api_maintenance::export::{journal, stored};
    use crate::api_settings::test_support::TempDir;
    use crate::svc_core::docs::ProtectionDoc;

    let dir = TempDir::new("maint-recovery");
    let store = Store::<ProtectionDoc>::open(&dir.0);
    let absent = stored("protection", &store);
    assert_eq!(absent.file, "protection.json");
    assert!(matches!(absent.read, RecoveryRead::Absent));
    store
        .update(|d| d.settings.level = KillSwitchLevel::Standard)
        .expect("written");
    let RecoveryRead::Trusted(doc) = stored("protection", &store).read else {
        panic!("a written document is packed");
    };
    assert_eq!(doc["level"], "standard");

    let tweaks = journal(&tweaks::Journal::open(&dir.0, hardening::admit));
    let RecoveryRead::Trusted(held) = tweaks.read else {
        panic!("an empty journal is a fact too");
    };
    assert_eq!(held, serde_json::json!({ "held": [] }));
}

/// fixfollow-b3: the archive names the files the running proxy session's engines came from apart
/// from the next start's: sing-box always, Xray only for a session on it; a Tunnel session (the
/// helper service's engines) and no session name none of this process's files as running.
#[test]
fn the_running_engines_are_the_started_files() {
    use crate::api_maintenance::export::started_by;
    use vpnte_base::types::Engine;
    use vpnte_tunnel::api::{CaptureKind, EngineRun, TunStatus};
    use vpnte_tunnel::runtime::{EngineStarts, Started};

    let old = |name: &str| Some(PathBuf::from(format!(r"C:\Engines\1.14.4\{name}")));
    let starts = EngineStarts {
        singbox: Started {
            count: 2,
            exe: old("sing-box.exe"),
        },
        xray: Started {
            count: 1,
            exe: old("xray.exe"),
        },
    };
    let session = |capture, kind| TunStatus {
        running: true,
        capture: Some(capture),
        engine: Some(EngineRun { kind, reason: None }),
        ..TunStatus::default()
    };
    let names = |status: &TunStatus| -> Vec<&str> {
        started_by(status, &starts)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    };
    assert_eq!(
        names(&session(CaptureKind::Proxy, Engine::Xray)),
        ["sing-box", "xray"]
    );
    assert_eq!(
        names(&session(CaptureKind::Proxy, Engine::SingBox)),
        ["sing-box"]
    );
    assert!(names(&session(CaptureKind::Tun, Engine::SingBox)).is_empty());
    assert!(names(&TunStatus::default()).is_empty());
    let (_, exe) = started_by(&session(CaptureKind::Proxy, Engine::SingBox), &starts)
        .pop()
        .expect("sing-box");
    assert_eq!(Some(exe), old("sing-box.exe"));
}

/// Engine versions come from the engines' own one-shot `version` runs; a missing binary is named
/// so without starting anything. The last config is absent before any core ran.
#[tokio::test]
async fn engine_facts_for_the_archive() {
    use crate::api_maintenance::export::{engine_configs, engine_versions};
    use crate::services::Engines;

    let missing = Engines {
        singbox: PathBuf::from(r"C:\nowhere\sing-box.exe"),
        xray: PathBuf::from(r"C:\nowhere\xray.exe"),
    };
    let versions = engine_versions(&missing).await;
    assert_eq!(
        versions,
        [
            ("sing-box".to_owned(), "missing".to_owned()),
            ("xray".to_owned(), "missing".to_owned())
        ]
    );
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let bundled = Engines {
        singbox: resources.join("sing-box.exe"),
        xray: resources.join("xray.exe"),
    };
    if bundled.singbox.is_file() {
        let versions = engine_versions(&bundled).await;
        assert!(versions[0].1.starts_with("1.14."), "{versions:?}");
    }
    let feed = vpnte_tunnel::runtime::RealEngines::new(
        bundled.singbox.clone(),
        bundled.xray.clone(),
        None,
    )
    .feed();
    assert!(engine_configs(&feed).is_empty());
}
