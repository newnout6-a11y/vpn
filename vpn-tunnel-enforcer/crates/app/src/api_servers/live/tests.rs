//! The live check of the Servers page: a stored row as the page's receipt, the stage and batch
//! progress events, the soft stop, and the runner over an unknown server (no network).
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_engine::routing::RulesDoc;
use vpnte_probes::live::{ItemProgress, ItemState, LiveCheck, ProgressSnapshot, ProgressStatus};
use vpnte_probes::live_stages::Text;
use vpnte_servers::store::Servers;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::TunnelSnapshot;
use vpnte_ui::servers as ui;

use super::*;
use crate::services::Engines;
use crate::svc_live::AppLiveEnv;

/// A throw-away data dir under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-wire-page-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A self-probe row (the checked server is the active one) with engine sections.
fn stored() -> LiveCheck {
    let mut row: LiveCheck = serde_json::from_value(json!({
        "id": "lc_00000000000000000000000000000001", "profileId": "srv-1",
        "host": "203.0.113.20", "port": 443, "mode": "extended",
        "startedAt": 1_700_000_000_000_u64, "finishedAt": 1_700_000_005_000_u64, "durationMs": 5000,
        "tunnel": {"state": "up"},
        "dns": {"status": "ok", "durationMs": 12, "a": ["203.0.113.20"]},
        "reachability": {"status": "ok", "durationMs": 30, "tcpReachable": true, "port": 443},
        "latency": {"min": 20, "avg": 25, "median": 24, "max": 40, "jitter": 5, "loss": 0.25,
                    "samples": [20, 24, 40], "samplesAttempted": 4},
        "infrastructure": {"status": "ok", "endpointCountry": "DE",
                           "sharedCidrWithProfiles": ["Fake B"],
                           "changesFromPrevious": {"ipChanged": true}},
        "handshake": {"status": "ok", "durationMs": 840, "protocol": "vless",
                      "route": "active-tunnel"},
        "egress": {"status": "partial", "durationMs": 900, "exitIpv4": "198.51.100.9",
                   "ipv6Status": "unsupported", "country": "NL",
                   "reflectors": [{"source": "cloudflare", "ip": "198.51.100.9",
                                   "durationMs": 100, "status": "ok"}]},
        "throughput": {"status": "warning", "durationMs": 9000, "route": "active-tunnel",
                       "samples": [{"index": 0, "bytes": 4_194_304, "durationMs": 2000,
                                    "throughputMbps": 16.7, "stallCount": 1,
                                    "maxInterChunkGapMs": 800, "complete": true}],
                       "medianMbps": 16.7, "variabilityPct": 12},
        "findings": [{"code": "TCP_UNREACHABLE", "severity": "warning",
                      "title": "Imported title", "detail": "Imported detail"}],
    }))
    .unwrap();
    row.findings[0].detail = Text::Msg(Msg::new("probes.live.finding.x.detail"));
    row
}

/// The page's receipt keeps the measurements; imported texts become `app.live.text`; the exit
/// country shows because the check probed the active tunnel itself.
#[test]
fn a_stored_row_becomes_the_page_receipt() {
    let c = live_view::check(&stored(), Lang::En);
    assert_eq!(
        (c.mode, c.tunnel_running),
        (ui::LiveMode::Extended, Some(true))
    );
    assert_eq!((c.duration_ms, c.dns.a.len()), (5000, 1));
    let latency = c.latency.expect("latency");
    assert_eq!((latency.attempted, latency.succeeded), (Some(4), Some(3)));
    let infra = c.infrastructure.expect("infrastructure");
    assert!(infra.active_tunnel_matches_profile && infra.changes.ip && !infra.changes.asn);
    assert_eq!(infra.egress_country.as_deref(), Some("NL"));
    let hs = c.handshake.expect("handshake");
    assert_eq!(
        (hs.status, hs.duration_ms),
        (ui::HandshakeStatus::Ok, Some(840))
    );
    let egress = c.egress.expect("egress");
    assert_eq!(egress.status, ui::StageStatus::Warning);
    assert!(egress.ipv6_unsupported && egress.reflectors.len() == 1);
    let tp = c.throughput.expect("throughput");
    assert_eq!(tp.route, Some(ui::ThroughputRoute::ActiveProfileSelf));
    assert_eq!((tp.variability_pct, tp.samples[0].stalls), (Some(12.0), 1));
    let f = &c.findings[0];
    assert_eq!(
        (f.code.as_str(), f.severity),
        ("TCP_UNREACHABLE", ui::Severity::Warning)
    );
    assert_eq!(
        f.title,
        Msg::new("app.live.text").arg("text", "Imported title")
    );
    assert_eq!(f.detail.key, "probes.live.finding.x.detail");
}

fn item(state: ItemState, stages: &[(StageId, ProgressStatus)]) -> ItemProgress {
    let mut item = ItemProgress {
        profile_id: Some("srv-1".into()),
        state,
        ..ItemProgress::default()
    };
    for &(id, status) in stages {
        item.stages[id as usize] = Some(status);
    }
    item.completed = stages
        .iter()
        .filter(|(_, s)| *s != ProgressStatus::Running)
        .count() as u8;
    item
}

/// One event per stage change, in stage order, with the step count over every stage.
#[test]
fn stage_events_follow_the_changes() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut seen = [None; StageId::ALL.len()];
    let first = item(
        ItemState::Running,
        &[(StageId::Dns, ProgressStatus::Running)],
    );
    send_stages(&first, &mut seen, &tx);
    send_stages(&first, &mut seen, &tx);
    let next = item(
        ItemState::Running,
        &[
            (StageId::Dns, ProgressStatus::Completed),
            (StageId::Reachability, ProgressStatus::Running),
        ],
    );
    send_stages(&next, &mut seen, &tx);
    let got: Vec<(ui::Stage, ui::ProgressStatus, u8, u8)> =
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|p| (p.stage, p.status, p.completed, p.total))
            .collect();
    assert_eq!(
        got,
        [
            (ui::Stage::Dns, ui::ProgressStatus::Running, 0, 13),
            (ui::Stage::Dns, ui::ProgressStatus::Completed, 1, 13),
            (ui::Stage::Reachability, ui::ProgressStatus::Running, 1, 13),
        ]
    );
}
/// Batch events: pending items stay silent, a cut-short item reads as skipped, a repeated
/// snapshot sends nothing.
#[test]
fn batch_events_per_item_change() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut sent = Vec::new();
    let snap = ProgressSnapshot {
        items: vec![
            item(
                ItemState::Completed,
                &[(StageId::Dns, ProgressStatus::Completed)],
            ),
            item(
                ItemState::Running,
                &[(StageId::Throughput, ProgressStatus::Running)],
            ),
            item(ItemState::Pending, &[]),
        ],
        current: Some(1),
        ..ProgressSnapshot::default()
    };
    send_items(&snap, &mut sent, &tx);
    send_items(&snap, &mut sent, &tx);
    let mut cut = snap.clone();
    cut.items[1].state = ItemState::Cancelled;
    send_items(&cut, &mut sent, &tx);
    let got: Vec<(u16, ui::ProgressStatus, Option<ui::Stage>)> =
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|p| (p.index, p.status, p.stage))
            .collect();
    assert_eq!(
        got,
        [
            (0, ui::ProgressStatus::Completed, None),
            (1, ui::ProgressStatus::Running, Some(ui::Stage::Throughput)),
            (1, ui::ProgressStatus::Skipped, None),
        ]
    );
}

/// B-2: the soft stop waits for the server being checked, never for the queued ones.
#[test]
fn the_soft_stop_lets_the_current_server_finish() {
    let mut snap = ProgressSnapshot {
        items: vec![item(ItemState::Running, &[]), item(ItemState::Pending, &[])],
        current: Some(0),
        ..ProgressSnapshot::default()
    };
    assert!(finished(&snap, None), "nothing was running");
    assert!(!finished(&snap, Some(0)), "still measuring");
    snap.items[0].state = ItemState::Completed;
    assert!(finished(&snap, Some(0)));
    snap.items[0].state = ItemState::Running;
    snap.current = Some(1);
    assert!(finished(&snap, Some(0)), "the run moved on");
}

/// The runner over the app's env: an unknown server is answered without a row or a network
/// call, alone and in a batch.
#[tokio::test]
async fn unknown_servers_are_answered_without_a_check() {
    let dir = TempDir::new("runner");
    let servers = Arc::new(Servers::open(&dir.0));
    let resources = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    let env = AppLiveEnv {
        servers: servers.clone(),
        settings: Arc::new(Store::<Settings>::open(&dir.0)),
        rules: Arc::new(Store::<RulesDoc>::open(&dir.0)),
        engines: Engines {
            singbox: resources.join("sing-box.exe"),
            xray: resources.join("xray.exe"),
        },
        status: watch::channel(TunStatus::default()).1,
        snapshot: watch::channel(TunnelSnapshot::default()).1,
        session: watch::channel(None).1,
    };
    let service = crate::svc_live::start(Arc::new(env), &dir.0, &servers).expect("runner");
    let (tx, _rx) = mpsc::unbounded_channel();
    let one = single(
        service.clone(),
        "no-such-server".into(),
        ui::LiveMode::Basic,
        Lang::En,
        tx,
        CancellationToken::new(),
    );
    let err = tokio::time::timeout(std::time::Duration::from_secs(10), one)
        .await
        .expect("answered")
        .unwrap_err();
    assert_eq!(err.user_msg().key, "probes.live.profileNotFound");

    let (tx, _rx) = mpsc::unbounded_channel();
    let ids = vec!["gone-1".to_owned(), "gone-2".to_owned()];
    let run = batch(
        service.clone(),
        ids,
        CancellationToken::new(),
        Lang::En,
        tx,
        CancellationToken::new(),
    );
    let done = tokio::time::timeout(std::time::Duration::from_secs(10), run)
        .await
        .expect("answered")
        .unwrap();
    assert!(done.results.is_empty() && !done.cancelled);
    let failed: Vec<&str> = done.errors.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(failed, ["gone-1", "gone-2"]);
    assert!(history(&service, "gone-1", Lang::En).is_empty());
    service.shutdown().await;
}
