//! The demo's probe, geo lookup and live checks: staged progress with realistic delays,
//! results from `demo_data`.
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::*;
use crate::servers::demo_data::{demo_check, test_ip};

impl DemoServersApi {
    pub(super) async fn demo_probe(&self, id: &str) -> AppResult<ProbeReport> {
        delay(1_200).await;
        let server = self.known(id)?;
        let ip = server.resolved_ip.unwrap_or_else(|| test_ip(9));
        let base = server.ping_ms.unwrap_or(70);
        let tunnel = self.state.borrow().tunnel_running;
        Ok(ProbeReport {
            resolved_ips: vec![ip],
            reverse_dns: vec![format!(
                "static-{}.hoster.example",
                ip.to_string().replace('.', "-")
            )],
            asn: Some(AsnInfo {
                asn: "AS64500".into(),
                org: "Example Hosting B.V.".into(),
                network: Some("198.51.100.0/24".into()),
                country: server.country.clone(),
            }),
            latency: (!tunnel).then(|| LatencyStats {
                min: base - 3,
                avg: base,
                median: base,
                max: base + 9,
                jitter: 3,
                loss: 0.0,
                samples: vec![base - 3, base + 1, base, base + 9, base - 1],
                attempted: Some(5),
                succeeded: Some(5),
            }),
            open_ports: vec![OpenPort {
                port: server.port,
                service: Some("HTTPS".into()),
            }],
        })
    }

    pub(super) async fn demo_geo(&self, id: &str) -> AppResult<Option<GeoInfo>> {
        delay(600).await;
        let server = self.known(id)?;
        if self.state.borrow().geo_lookup_disabled {
            return Ok(None);
        }
        Ok(Some(GeoInfo {
            ip: server.resolved_ip,
            country: server.country.clone(),
            city: server.name.split(" · ").nth(1).map(Into::into),
            region: None,
            org: Some("Example Hosting B.V.".into()),
            timezone: Some("Europe/Amsterdam".into()),
        }))
    }

    pub(super) async fn demo_live_check(
        &self,
        id: &str,
        mode: LiveMode,
        progress: mpsc::UnboundedSender<LiveProgress>,
    ) -> AppResult<LiveCheck> {
        let server = self.known(id)?;
        let stages: &[Stage] = match mode {
            LiveMode::Basic => &BASIC_STAGES,
            LiveMode::Extended => &EXTENDED_STAGES,
        };
        let total = u8::try_from(stages.len()).unwrap_or(u8::MAX);
        let started = tokio::time::Instant::now();
        for (i, &stage) in stages.iter().enumerate() {
            let completed = u8::try_from(i).unwrap_or(u8::MAX);
            let elapsed_ms = || u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
            let event = |status, completed| LiveProgress {
                stage,
                status,
                completed,
                total,
                elapsed_ms: elapsed_ms(),
            };
            let _ = progress.send(event(ProgressStatus::Running, completed));
            delay(260 + fastrand::u64(0..320)).await;
            if stage == Stage::Handshake && server.ping_ms.is_none() {
                let _ = progress.send(event(ProgressStatus::Failed, completed));
                return Err(AppError::timeout());
            }
            let _ = progress.send(event(ProgressStatus::Completed, completed + 1));
        }
        let check = demo_check(&server, mode, self.next_run(), now_ms());
        let mut history = self.history.borrow_mut();
        let list = history.entry(server.id).or_default();
        list.insert(0, check.clone());
        list.truncate(20);
        Ok(check)
    }

    pub(super) async fn demo_live_history(&self, id: &str) -> AppResult<Vec<LiveCheck>> {
        delay(300).await;
        // Fails once for Helsinki, so the history-load failure and its retry can be seen.
        if id == "fi-hel" && !self.history_failed.replace(true) {
            return Err(AppError::new(ErrorKind::Network));
        }
        Ok(self.history.borrow().get(id).cloned().unwrap_or_default())
    }

    pub(super) async fn demo_live_batch(
        &self,
        ids: Vec<String>,
        stop: CancellationToken,
        progress: mpsc::UnboundedSender<BatchProgress>,
    ) -> AppResult<BatchResult> {
        if ids.is_empty() || ids.len() > 12 {
            return Err(AppError::validation(Msg::new("ui.servers.demo.batchSize")));
        }
        let total = u16::try_from(ids.len()).unwrap_or(u16::MAX);
        let mut out = BatchResult::default();
        for (i, id) in ids.into_iter().enumerate() {
            // A soft stop takes effect between servers: the current one is finished.
            if stop.is_cancelled() {
                out.cancelled = true;
                break;
            }
            let index = u16::try_from(i).unwrap_or(u16::MAX);
            let Some(server) = self.server(&id) else {
                out.errors
                    .push((id, Msg::new("ui.servers.demo.unknownServer")));
                continue;
            };
            if server.archived.is_some() || !server.enabled {
                out.errors
                    .push((id, Msg::new("ui.servers.demo.batchSkipped")));
                continue;
            }
            let event = |status, stage, median_mbps| BatchProgress {
                profile_id: id.clone(),
                index,
                total,
                status,
                stage,
                median_mbps,
            };
            for stage in [
                Stage::Dns,
                Stage::Handshake,
                Stage::Egress,
                Stage::Throughput,
            ] {
                let _ = progress.send(event(ProgressStatus::Running, Some(stage), None));
                delay(350 + fastrand::u64(0..350)).await;
            }
            if server.ping_ms.is_none() {
                let _ = progress.send(event(ProgressStatus::Failed, Some(Stage::Handshake), None));
                out.errors
                    .push((id, Msg::new("ui.servers.demo.batchFailed")));
                continue;
            }
            let check = demo_check(&server, LiveMode::Extended, self.next_run(), now_ms());
            let median = check.throughput.as_ref().and_then(|t| t.median_mbps);
            let _ = progress.send(event(
                ProgressStatus::Completed,
                Some(Stage::Throughput),
                median,
            ));
            self.history
                .borrow_mut()
                .entry(id)
                .or_default()
                .insert(0, check.clone());
            out.results.push(check);
        }
        Ok(out)
    }
}

const BASIC_STAGES: [Stage; 9] = [
    Stage::Dns,
    Stage::Reachability,
    Stage::Tls,
    Stage::Http,
    Stage::Infrastructure,
    Stage::Handshake,
    Stage::Egress,
    Stage::MediaStream,
    Stage::Path,
];

const EXTENDED_STAGES: [Stage; 13] = [
    Stage::Dns,
    Stage::Reachability,
    Stage::Tls,
    Stage::Http,
    Stage::Ports,
    Stage::Route,
    Stage::Infrastructure,
    Stage::Handshake,
    Stage::Egress,
    Stage::MediaStream,
    Stage::Throughput,
    Stage::Path,
    Stage::Pmtu,
];
