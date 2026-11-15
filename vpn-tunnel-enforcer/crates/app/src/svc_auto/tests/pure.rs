//! The pure rules: session mapping, owner admission, stop causes, verdict mapping, failover pick.
use vpnte_automation::adaptive::reaction::{CheckReaction, CheckVerdict};
use vpnte_automation::coordinator::{
    ConnectRequest, LifecycleEvent, OpError, RuntimeId, SessionInfo, SessionKind, StopCause,
};
use vpnte_base::types::{AdaptiveMode, ClientDevice, Owner};
use vpnte_probes::live::{Handshake, HandshakeEvidence, HandshakeStatus, LiveCheck};
use vpnte_servers::model::{
    GroupId, HealthRecord, Origin, ProfileId, ServerReaction, ServerRow, ServerVerdict,
    VerdictRecord,
};
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::{SessionEvent, SessionView};
use vpnte_tunnel::outcome::OutcomeKind;

use crate::svc_auto::decide::{self, Admit};
use crate::svc_auto::events::{lifecycle_event, stop_cause};
use crate::svc_auto::failover::candidates;
use crate::svc_auto::feed::{live_report, stored_report};

pub fn view(mode: SessionMode, id: &str, owner: Owner, generation: u64) -> SessionView {
    SessionView {
        owner,
        profile_id: id.into(),
        profile_name: id.into(),
        mode,
        generation: Some(generation),
        adaptive: AdaptiveMode::Baseline,
        started_at: 0,
        engine: None,
    }
}

fn info(kind: SessionKind, id: Option<&str>, owner: Owner) -> SessionInfo {
    SessionInfo {
        kind,
        owner,
        profile_id: id.map(str::to_owned),
        runtime_id: RuntimeId(1),
        mode: AdaptiveMode::Baseline,
    }
}

/// NOADMIN §2: the lane's Soft session over a list server is a session over a server for
/// automation; over a local proxy it is not, and the synthetic ids never become profile ids.
#[test]
fn lane_sessions_map_to_capture_and_upstream() {
    let cases = [
        (
            SessionMode::Direct,
            "srv-a",
            SessionKind::Direct,
            Some("srv-a"),
        ),
        (
            SessionMode::Soft,
            "srv-a",
            SessionKind::SoftDirect,
            Some("srv-a"),
        ),
        (
            SessionMode::Soft,
            "local-proxy-soft-http",
            SessionKind::Soft,
            None,
        ),
        (
            SessionMode::Hard,
            "local-proxy",
            SessionKind::LocalProxyHard,
            None,
        ),
        (SessionMode::Direct, "direct-vpn", SessionKind::Direct, None),
    ];
    for (mode, id, kind, profile) in cases {
        let s = decide::session_info(&view(mode, id, Owner::Schedule, 7));
        assert_eq!(
            (s.kind, s.profile_id.as_deref()),
            (kind, profile),
            "{mode:?} {id}"
        );
        assert_eq!((s.owner, s.runtime_id), (Owner::Schedule, RuntimeId(7)));
    }
}

/// The `Coordinator` contract: the very session → already connected (a higher caller adopts
/// it); another session only for an owner at least as high; another server of the same kind
/// is a switch, another kind a replacement.
#[test]
fn connect_admission_follows_the_owner_order() {
    let direct = |id: &str| ConnectRequest::Direct {
        profile_id: id.into(),
    };
    let proxy = |id: &str| ConnectRequest::SoftDirect {
        profile_id: id.into(),
    };
    let running = info(SessionKind::SoftDirect, Some("a"), Owner::Schedule);
    let admit = |owner, req: &ConnectRequest| decide::admit_connect(Some(&running), owner, req);
    assert_eq!(
        decide::admit_connect(None, Owner::AdaptiveRetry, &direct("a")),
        Admit::Start
    );
    assert_eq!(
        admit(Owner::Manual, &proxy("a")),
        Admit::Already { adopt: true }
    );
    assert_eq!(
        admit(Owner::Rotation, &proxy("a")),
        Admit::Already { adopt: false }
    );
    assert_eq!(admit(Owner::Schedule, &proxy("b")), Admit::Switch);
    assert_eq!(admit(Owner::Autopilot, &proxy("b")), Admit::Refuse);
    assert_eq!(admit(Owner::Schedule, &direct("a")), Admit::Replace);
    assert_eq!(admit(Owner::Rotation, &direct("a")), Admit::Refuse);
    let soft = ConnectRequest::Soft { endpoint: None };
    assert_eq!(admit(Owner::Manual, &soft), Admit::Replace);
}

/// A lower owner never stops a higher owner's session; no session is a quiet success.
#[test]
fn disconnect_admission_follows_the_owner_order() {
    let running = info(SessionKind::Direct, Some("a"), Owner::Manual);
    assert!(matches!(
        decide::admit_disconnect(Some(&running), Owner::Schedule),
        Err(OpError::Conflict)
    ));
    assert!(matches!(
        decide::admit_disconnect(Some(&running), Owner::Recovery),
        Ok(true)
    ));
    assert!(matches!(
        decide::admit_disconnect(None, Owner::AdaptiveRetry),
        Ok(false)
    ));
}

/// The row of a session another run replaces is no end; a switch that lost the tunnel is (a2:
/// the scheduler's crash retry and the location rollback hang on it); a stop names who asked
/// for it, else it is a fault.
#[test]
fn session_ends_map_to_stop_causes() {
    let ended = |outcome, continues| SessionEvent::Ended {
        session: view(SessionMode::Soft, "a", Owner::Schedule, 3),
        outcome,
        continues,
    };
    assert_eq!(
        lifecycle_event(&ended(OutcomeKind::ServerSwitch, true), None),
        None
    );
    assert_eq!(
        lifecycle_event(&ended(OutcomeKind::Rotation, true), None),
        None
    );
    for lost in [OutcomeKind::Rotation, OutcomeKind::ServerSwitch] {
        assert_eq!(
            lifecycle_event(&ended(lost, false), None),
            Some(LifecycleEvent::Stopped {
                owner: Owner::Schedule,
                runtime_id: RuntimeId(3),
                cause: StopCause::Fault,
            })
        );
    }
    assert_eq!(
        lifecycle_event(&ended(OutcomeKind::UserStop, false), None),
        Some(LifecycleEvent::Stopped {
            owner: Owner::Schedule,
            runtime_id: RuntimeId(3),
            cause: StopCause::Requested(Owner::Manual),
        })
    );
    assert_eq!(stop_cause(OutcomeKind::AppQuit, None), StopCause::Shutdown);
    assert_eq!(
        stop_cause(OutcomeKind::Unknown, Some(Owner::Autopilot)),
        StopCause::Requested(Owner::Autopilot)
    );
    assert_eq!(
        stop_cause(OutcomeKind::SingboxCrash, None),
        StopCause::Fault
    );
    let up = SessionEvent::Up(view(SessionMode::Soft, "a", Owner::Manual, 4));
    assert!(matches!(
        lifecycle_event(&up, None),
        Some(LifecycleEvent::Started {
            kind: SessionKind::SoftDirect,
            runtime_id: RuntimeId(4),
            ..
        })
    ));
}

/// Stored verdicts keep their wire meaning; unknown names are no report.
#[test]
fn stored_verdicts_become_reports() {
    let record = |verdict, reaction| VerdictRecord {
        verdict,
        reaction,
        at: 1,
    };
    let id = ProfileId::from("a");
    let banned = record(ServerVerdict::IpBanned, ServerReaction::SwitchServer);
    let report = stored_report(&id, &banned).expect("report");
    assert_eq!(
        (report.profile_id.as_str(), report.verdict, report.reaction),
        ("a", CheckVerdict::IpBanned, CheckReaction::SwitchServer)
    );
    let unknown = record(ServerVerdict::Unknown, ServerReaction::None);
    assert!(stored_report(&id, &unknown).is_none());
}

/// A live check reports only what its handshake stage proves.
#[test]
fn live_checks_report_what_the_handshake_proves() {
    let check = |status, detail: Option<&str>| LiveCheck {
        profile_id: Some("a".into()),
        handshake: Some(Handshake {
            status,
            evidence: Some(HandshakeEvidence {
                detail: detail.map(str::to_owned),
                ..HandshakeEvidence::default()
            }),
            ..Handshake::default()
        }),
        ..serde_json::from_value(serde_json::json!({
            "id": "c", "host": "h", "port": 443, "startedAt": 1, "finishedAt": 2,
            "dns": {"status": "ok"}, "reachability": {"status": "ok"}
        }))
        .expect("minimal live check")
    };
    let verdict = |c: &LiveCheck| live_report(c).map(|r| (r.verdict, r.reaction));
    assert_eq!(
        verdict(&check(HandshakeStatus::Ok, None)),
        Some((CheckVerdict::Healthy, CheckReaction::None))
    );
    assert_eq!(
        verdict(&check(HandshakeStatus::AuthFailed, None)),
        Some((CheckVerdict::KeyRejected, CheckReaction::SwitchServer))
    );
    assert_eq!(
        verdict(&check(
            HandshakeStatus::TransportFailed,
            Some("hy2-udp-blocked")
        )),
        Some((CheckVerdict::UdpBlocked, CheckReaction::PreferTcpTransport))
    );
    assert_eq!(verdict(&check(HandshakeStatus::Timeout, None)), None);
}

fn row(id: &str, group: &str, host: &str) -> ServerRow {
    let uri = format!(
        "vless://00000000-0000-4000-8000-000000000001@{host}:443?security=tls&sni={id}.test&type=tcp#{id}"
    );
    let profile = vpnte_profiles::uri::parse_uri(&uri).expect("fake key parses");
    let mut row = ServerRow::new(
        &profile,
        GroupId::from(group),
        Origin::Manual,
        ClientDevice::Pc,
        1,
    )
    .expect("row");
    row.id = ProfileId::from(id);
    row
}

fn health(row: &mut ServerRow, online: bool, rtt_ms: Option<u32>, at: i64) {
    row.health = Some(HealthRecord {
        online,
        at,
        rtt_ms,
        reason: None,
        egress_ip: None,
    });
}

/// The failover's pick: same group only, never the crashed one, a skipped (tried / ruled out)
/// or known-dead sibling never; healthy before unknown, then latency, then store order. A
/// verdict older than the last health record is superseded by it.
#[test]
fn failover_picks_live_siblings_best_first() {
    let base = row("base", "g", "198.51.100.1");
    let mut slow = row("slow", "g", "198.51.100.2");
    health(&mut slow, true, Some(300), 10);
    let mut fast = row("fast", "g", "198.51.100.3");
    health(&mut fast, true, Some(40), 10);
    let unknown = row("unknown", "g", "198.51.100.4");
    let mut dead = row("dead", "g", "198.51.100.5");
    health(&mut dead, false, None, 10);
    let mut banned = row("banned", "g", "198.51.100.6");
    banned.verdict = Some(VerdictRecord {
        verdict: ServerVerdict::IpBanned,
        reaction: ServerReaction::SwitchServer,
        at: 20,
    });
    let mut recovered = row("recovered", "g", "198.51.100.7");
    recovered.verdict = Some(VerdictRecord {
        verdict: ServerVerdict::Offline,
        reaction: ServerReaction::SwitchServer,
        at: 5,
    });
    health(&mut recovered, true, Some(100), 10);
    let other_group = row("elsewhere", "h", "198.51.100.8");
    let tried = row("tried", "g", "198.51.100.9");
    let rows = [
        base.clone(),
        slow,
        unknown,
        fast,
        dead,
        banned,
        recovered,
        other_group,
        tried,
    ];
    let picked: Vec<_> = candidates(&rows, &base, |id| id == "tried")
        .into_iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(picked, ["fast", "recovered", "slow", "unknown"]);
}
