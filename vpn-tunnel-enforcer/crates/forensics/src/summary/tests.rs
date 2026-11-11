use std::path::Path;

use serde_json::{Value, json};

use super::*;
use crate::capture::manifest::{SessionManifest, write_manifest};
use crate::capture::{EtwState, PktmonState};
use crate::etw::{EtwStopStats, LossStats};
use crate::test_support::TempDir;

const ID: &str = "2026-11-11T07-20-30-123Z";

fn manifest(pktmon: PktmonState) -> SessionManifest {
    SessionManifest {
        schema_version: 2,
        app_version: "2.0.0".into(),
        session_id: ID.into(),
        running: false,
        engine: Some("pktmon".into()),
        mode: Some(ConnectionMode::DirectVpn),
        target: Some("Fake profile".into()),
        started_at: 1,
        stopped_at: Some(2),
        max_size_mb: 512,
        stop_reason: Some("vpn-stop".into()),
        last_error: None,
        pktmon,
        etw: EtwState::Stopped,
        etw_stats: None,
        warnings: Vec::new(),
        app_events_dropped: 0,
    }
}

/// A session directory with a stopped pktmon + ETW manifest.
fn session(tag: &str) -> TempDir {
    let dir = TempDir::new(tag);
    write_manifest(dir.path(), &manifest(PktmonState::Stopped)).unwrap();
    dir
}

fn ndjson(dir: &Path, name: &str, rows: &[Value]) {
    let text: String = rows.iter().map(|r| format!("{r}\n")).collect();
    std::fs::write(dir.join(name), text).unwrap();
}

fn tcp(reason: &str) -> Value {
    json!({"provider":"Microsoft-Windows-TCPIP","category":"tcp","event":"x","reason":reason,
           "remoteAddress":"93.184.216.34","remotePort":443,"ts":"2026-11-11T07:20:31.000Z"})
}

fn run(dir: &TempDir) -> Summary {
    summarize(dir.path(), &SummaryCtx::default()).unwrap()
}

/// Kept vector ('bridges app lifecycle events…'): an engine start failure and a failing leak self
/// test are evidence from `app-events.ndjson`.
#[test]
fn app_events_are_evidence() {
    let dir = session("sum-app");
    ndjson(
        dir.path(),
        "app-events.ndjson",
        &[
            json!({"timestamp":"t","source":"tun","event":"engine-start-failed",
                   "details":{"message":"sing-box did not start within timeout","stderr":"FATAL dial failed"}}),
            json!({"timestamp":"t","source":"leak-self-test","event":"leak-self-test-result",
                   "details":{"physicalAdapterReached":true,"publicIpMismatch":true,"dnsLeakDetected":true}}),
        ],
    );
    let s = run(&dir);
    for check in [
        Check::SingBoxFailureLikely,
        Check::TrafficLeakDetected,
        Check::DnsLeakDetected,
    ] {
        assert_eq!(s.finding(check), Finding::Detected, "{check:?}");
        assert_eq!(s.evidence[&check][0].artifact, "app-events.ndjson");
    }
    assert_eq!(s.evidence[&Check::SingBoxFailureLikely][0].line, Some(1));
    assert_eq!(s.counts.app_events, 2);
}

/// B-33: a user-initiated engine exit is not a failure; an unexpected one is.
#[test]
fn user_stop_is_not_an_engine_failure() {
    let dir = session("sum-userstop");
    let exited = |user: bool| json!({"timestamp":"t","source":"tun","event":"engine-exited","userInitiated":user,"details":{}});
    ndjson(dir.path(), "app-events.ndjson", &[exited(true)]);
    assert_eq!(
        run(&dir).finding(Check::SingBoxFailureLikely),
        Finding::NotDetected
    );
    ndjson(
        dir.path(),
        "app-events.ndjson",
        &[exited(true), exited(false)],
    );
    assert_eq!(
        run(&dir).finding(Check::SingBoxFailureLikely),
        Finding::Detected
    );
}

/// Kept + changed vectors (B-06): adapter DNS servers and default routes are configuration, not
/// evidence, whether on the TUN or on Wi-Fi; a passed leak test is.
#[test]
fn configuration_is_not_leak_evidence() {
    let dir = session("sum-config");
    let network = json!({"takenAt":1,"adapters":[
        {"alias":"Ethernet 7","description":"Wintun Userspace Tunnel","physical":false,
         "addresses":["192.168.250.253/30"],"dns":["192.168.250.254"]},
        {"alias":"Wi-Fi","description":"Intel Wi-Fi","physical":true,
         "addresses":["192.168.1.20/24"],"dns":["8.8.8.8","1.1.1.1"]}],
        "routes":[{"ifIndex":12,"destination":"0.0.0.0/0","nextHop":"192.168.1.1","metric":25}]});
    std::fs::write(dir.path().join("network-stop.json"), network.to_string()).unwrap();
    let s = run(&dir);
    assert_eq!(s.finding(Check::DnsLeakDetected), Finding::Unknown);
    assert_eq!(s.finding(Check::TrafficLeakDetected), Finding::Unknown);
    assert!(s.warnings.contains(&SummaryWarning::NoLeakTest));

    ndjson(
        dir.path(),
        "app-events.ndjson",
        &[json!({"event":"leak-self-test-result","details":{
            "physicalAdapterReached":false,"publicIpMismatch":false,"dnsLeakDetected":false}})],
    );
    let s = run(&dir);
    assert_eq!(s.finding(Check::DnsLeakDetected), Finding::NotDetected);
    assert_eq!(s.finding(Check::TrafficLeakDetected), Finding::NotDetected);
}

/// Leak diagnostics items: failing traffic / DNS ids are evidence, passing ones answer "no".
#[test]
fn leak_diagnostics_items() {
    let dir = session("sum-diag");
    let item = |id: &str, status: &str| json!({"id":id,"label":id,"status":status});
    ndjson(
        dir.path(),
        "app-events.ndjson",
        &[
            json!({"event":"leak-diagnostics-result","details":{"items":[
            item("direct-public-ip", "fail"), item("dns-servers", "pass")]}}),
        ],
    );
    let s = run(&dir);
    assert_eq!(s.finding(Check::TrafficLeakDetected), Finding::Detected);
    assert_eq!(
        s.evidence[&Check::TrafficLeakDetected][0].reason,
        "leak-diagnostics:direct-public-ip"
    );
    assert_eq!(s.finding(Check::DnsLeakDetected), Finding::NotDetected);
}

/// Changed vector ('ingests sidecar events.ndjson…'): a DNS row's verdict text is not evidence,
/// WFP `block` rows are not drops, one reset stays below the threshold, three are detected, and
/// consumer-reported loss makes the summary insufficient.
#[test]
fn etw_rows_with_thresholds() {
    let dir = session("sum-etw");
    let rows = [
        json!({"provider":"sidecar","category":"lifecycle","event":"started","engine":"etw-inproc"}),
        json!({"provider":"Microsoft-Windows-DNS-Client","category":"dns","event":"query",
               "queryName":"tracker.example.org","verdict":"leak-outside-tunnel"}),
        json!({"provider":"Microsoft-Windows-WFP","category":"wfp","event":"block",
               "reason":"wfp-block-observed"}),
        tcp("reset-observed"),
        json!({"provider":"sidecar","category":"health","event":"stopped","eventsLost":4}),
    ];
    ndjson(dir.path(), "events.ndjson", &rows);
    let s = run(&dir);
    assert_eq!(s.finding(Check::DnsLeakDetected), Finding::Unknown);
    assert_eq!(
        s.finding(Check::WindowsFirewallBlockedTraffic),
        Finding::Unknown
    );
    assert_eq!(s.finding(Check::RemoteResetLikely), Finding::NotDetected);
    assert!(!s.evidence.contains_key(&Check::RemoteResetLikely));
    assert_eq!(s.counts.events, 5);
    assert_eq!(s.counts.data_events, 3);
    assert_eq!(s.counts.wfp_block_rows, 1);
    assert_eq!(s.counts.resets, 1);
    assert_eq!(s.counts.events_lost, 4);
    assert!(s.insufficient_evidence);
    assert!(s.warnings.contains(&SummaryWarning::EtwEventsLost));
    assert_eq!(s.top.domains[0].name, "tracker.example.org");
    assert_eq!(s.top.remotes[0].name, "93.184.216.34:443");

    // The older generation is read too: three resets in total reach the threshold.
    ndjson(
        dir.path(),
        "events.prev.ndjson",
        &[tcp("reset-observed"), tcp("reset-observed")],
    );
    let s = run(&dir);
    assert_eq!(s.finding(Check::RemoteResetLikely), Finding::Detected);
    assert_eq!(s.evidence[&Check::RemoteResetLikely].len(), 3);
    assert_eq!(
        s.evidence[&Check::RemoteResetLikely][0].artifact,
        "events.prev.ndjson"
    );
    assert_eq!(s.finding(Check::MtuIssueLikely), Finding::NotDetected);
}

/// Loss reported in the manifest's ETW stop stats counts as well.
#[test]
fn manifest_loss_counts() {
    let dir = TempDir::new("sum-loss");
    let mut m = manifest(PktmonState::Stopped);
    m.etw_stats = Some(EtwStopStats {
        writer: Default::default(),
        digest: Default::default(),
        loss: Some(LossStats {
            events_lost: 0,
            buffers_lost: 0,
        }),
        clean: true,
    });
    m.etw_stats.as_mut().unwrap().digest.backpressure_dropped = 7;
    write_manifest(dir.path(), &m).unwrap();
    let s = run(&dir);
    assert_eq!(s.counts.rows_dropped, 7);
    assert!(s.warnings.contains(&SummaryWarning::EtwEventsLost));
}

/// Packet-metrics vector ('normalizes pktmon packet and drop counters…', B-32 / B-04 / B-05):
/// categories from key names, the TUN path confirmed by Wintun packets, drops do not imply
/// loss; the same with a UTF-8 BOM.
#[test]
fn packet_metrics_and_tun_path() {
    for bom in ["", "\u{feff}"] {
        let dir = session("sum-counters");
        let counters = json!({"adapters":[
            {"name":"Wintun Userspace Tunnel","packets":120,"bytes":65536,"errors":0},
            {"name":"Intel Wi-Fi","packets":5,"bytes":500}]});
        let drops = json!({"dropCounters":{"wfpBlocked":2,"checksumDiscarded":1}});
        std::fs::write(
            dir.path().join("pktmon-counters.json"),
            format!("{bom}{counters}"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("pktmon-drop-counters.json"),
            format!("{bom}{drops}"),
        )
        .unwrap();
        let s = run(&dir);
        assert_eq!(s.packet_metrics.len(), 7);
        assert_eq!(s.counts.packet_metrics, 7);
        let count = |c: MetricCategory| s.packet_metrics.iter().filter(|m| m.category == c).count();
        assert_eq!(count(MetricCategory::Packet), 2);
        assert_eq!(count(MetricCategory::Byte), 2);
        assert_eq!(count(MetricCategory::Error), 1);
        assert_eq!(count(MetricCategory::Drop), 2);
        assert!(
            s.packet_metrics
                .iter()
                .any(|m| m.path == "dropCounters.wfpBlocked")
        );
        assert_eq!(s.finding(Check::TunPathConfirmed), Finding::Detected);
        let ev = &s.evidence[&Check::TunPathConfirmed][0];
        assert_eq!(ev.artifact, "pktmon-counters.json");
        assert_eq!(
            ev.matched.as_deref(),
            Some("Wintun Userspace Tunnel: 120 packets")
        );
        assert_ne!(
            s.finding(Check::TimeoutOrPacketLossLikely),
            Finding::Detected
        );
        assert!(!s.warnings.contains(&SummaryWarning::ArtifactUnreadable));
    }
}

/// B-04: a session whose TUN component counted nothing confirms nothing; a disguised alias given
/// by the app is matched exactly.
#[test]
fn tun_path_needs_packets_on_the_tun() {
    let dir = session("sum-tunzero");
    let counters = json!([{"Name":"Ethernet 7","Counters":{"Packets":0}},
                          {"Name":"Ethernet 70","Counters":{"Packets":9}}]);
    std::fs::write(
        dir.path().join("pktmon-counters.json"),
        counters.to_string(),
    )
    .unwrap();
    let ctx = SummaryCtx {
        tun_alias: Some("Ethernet 7".into()),
    };
    let s = summarize(dir.path(), &ctx).unwrap();
    assert_eq!(s.finding(Check::TunPathConfirmed), Finding::Unknown);

    let counters = json!([{"Name":"Ethernet 7","Inbound":{"Packets":3},"Outbound":{"Packets":4}}]);
    std::fs::write(
        dir.path().join("pktmon-counters.json"),
        counters.to_string(),
    )
    .unwrap();
    let s = summarize(dir.path(), &ctx).unwrap();
    assert_eq!(s.finding(Check::TunPathConfirmed), Finding::Detected);
}

/// ETW-only sessions: a connection whose local end is our TUN address confirms the path.
#[test]
fn tun_path_from_etw_local_address() {
    let dir = TempDir::new("sum-tunetw");
    write_manifest(
        dir.path(),
        &manifest(PktmonState::Unavailable("quota".into())),
    )
    .unwrap();
    let mut row = tcp("");
    row["localAddress"] = json!("192.168.250.253");
    ndjson(dir.path(), "events.ndjson", &[row]);
    let s = run(&dir);
    assert_eq!(s.finding(Check::TunPathConfirmed), Finding::Detected);
    assert_eq!(
        s.evidence[&Check::TunPathConfirmed][0].reason,
        "tun-local-address"
    );
    assert!(s.warnings.contains(&SummaryWarning::PktmonNotRun));
    assert!(s.insufficient_evidence);
}

/// 'stops capture and stages artifacts…': a fresh session with no evidence confirms nothing.
#[test]
fn empty_session_confirms_nothing() {
    let dir = session("sum-empty");
    let s = run(&dir);
    assert!(s.insufficient_evidence);
    assert_eq!(s.schema_version, 2);
    assert_eq!(s.session_id, ID);
    assert!(s.detected().is_empty());
    assert!(s.evidence.is_empty());
    for check in Check::ALL {
        assert_ne!(s.finding(check), Finding::Detected, "{check:?}");
    }
    assert!(s.warnings.contains(&SummaryWarning::EtwNotRun));
    // A directory without anything at all: still a summary, flagged.
    let bare = TempDir::new("sum-bare");
    let s = run(&bare);
    assert!(s.warnings.contains(&SummaryWarning::ManifestMissing));
    assert_eq!(s.finding(Check::SingBoxFailureLikely), Finding::Unknown);
    assert!(summarize(&bare.path().join("missing"), &SummaryCtx::default()).is_err());
}

/// A kill-switch stop reason is evidence of blocked traffic (TFS:863-868).
#[test]
fn killswitch_stop_reason() {
    let dir = TempDir::new("sum-ks");
    let mut m = manifest(PktmonState::Stopped);
    m.stop_reason = Some("killswitch-active".into());
    write_manifest(dir.path(), &m).unwrap();
    let s = run(&dir);
    assert_eq!(
        s.finding(Check::KillSwitchBlockedTraffic),
        Finding::Detected
    );
    assert_eq!(
        s.evidence[&Check::KillSwitchBlockedTraffic][0].artifact,
        "session-manifest.json"
    );
}

/// Truncated, non-JSON and non-UTF-8 lines are counted, never fatal; a BOM and blank lines are
/// tolerated.
#[test]
fn malformed_lines_are_counted() {
    let dir = session("sum-malformed");
    let mut bytes = b"\xEF\xBB\xBF".to_vec();
    bytes.extend_from_slice(format!("{}\r\n\r\n", tcp("reset-observed")).as_bytes());
    bytes.extend_from_slice(b"not json\n\xff\xfe{\"a\":1}\n{\"ts\":2,\"peer\":\"198.51");
    std::fs::write(dir.path().join("events.ndjson"), bytes).unwrap();
    let s = run(&dir);
    assert_eq!(s.counts.events, 1);
    assert_eq!(s.counts.resets, 1);
    assert_eq!(s.counts.malformed_lines, 3);
    assert!(s.warnings.contains(&SummaryWarning::MalformedLines));
}

/// Evidence is bounded and its text clipped.
#[test]
fn evidence_is_bounded() {
    let dir = session("sum-bound");
    let mut row = tcp("timeout-or-retransmit-observed");
    row["taskName"] = json!("x".repeat(2000));
    ndjson(dir.path(), "events.ndjson", &vec![row; 30]);
    let s = run(&dir);
    let list = &s.evidence[&Check::TimeoutOrPacketLossLikely];
    assert_eq!(list.len(), EVIDENCE_MAX);
    assert_eq!(
        list[0].matched.as_ref().unwrap().chars().count(),
        MATCH_MAX_CHARS
    );
    assert_eq!(s.counts.losses, 30);
}

/// The written files parse back; verdicts serialize as kebab-case, checks as camelCase.
#[test]
fn written_summary_round_trips() {
    let dir = session("sum-write");
    let s = summarize_and_write(dir.path(), &SummaryCtx::default()).unwrap();
    let text = std::fs::read_to_string(dir.path().join(SUMMARY_FILE)).unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schemaVersion"], 2);
    assert_eq!(v["verdicts"]["trafficLeakDetected"], "unknown");
    assert_eq!(v["verdicts"]["singBoxFailureLikely"], "unknown");
    assert_eq!(v["insufficientEvidence"], true);
    assert!(v.get("packetMetrics").is_none());
    let back: Summary = serde_json::from_str(&text).unwrap();
    assert_eq!(back.verdicts, s.verdicts);
    let metrics = std::fs::read_to_string(dir.path().join(PACKET_METRICS_FILE)).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&metrics).unwrap(), json!([]));
}
