//! The demo's key check in numbers (p-check-live): five probes at a time, one server name held
//! by its handshake budget for a few seconds, a failed handshake, and «Отменить» that keeps what
//! landed. Fake data only.
use vpnte_base::AppResult;
use vpnte_base::types::{Engine, now_ms};

use super::*;
use crate::servers::api::CheckWatch;
use crate::servers::check_model::{CheckAnswer, CheckKey, CheckStage};

impl DemoServersApi {
    /// The keys of the servers `pick` takes, with whether each works in the demo.
    pub(super) fn demo_keys(&self, pick: impl Fn(&ServerView) -> bool) -> Vec<(CheckKey, bool)> {
        (self.view().servers.iter())
            .filter(|s| pick(s))
            .map(|s| {
                let key = CheckKey {
                    id: s.id.clone(),
                    tag: s.key_tag,
                };
                (key, s.ping_ms.is_some() || s.id == "se-sto")
            })
            .collect()
    }

    /// Checks `ids` (with whether each key works) and tells every stage on `watch`.
    pub(super) async fn staged_check(
        &self,
        ids: Vec<(CheckKey, bool)>,
        watch: CheckWatch,
    ) -> AppResult<HealthReport> {
        let CheckWatch {
            results,
            stages,
            stop,
        } = watch;
        let tell = |key: &CheckKey, stage| {
            let _ = stages.send((key.clone(), stage));
        };
        ids.iter().for_each(|(id, _)| tell(id, CheckStage::Queued));
        // The last two keys share a server name whose budget is spent for a while: they go last.
        let (free, held) = ids.split_at(ids.len().saturating_sub(2));
        let wait = 8_000;
        let until = now_ms() + i64::from(wait);
        held.iter()
            .for_each(|(id, _)| tell(id, CheckStage::Waiting { until }));
        let mut batches: Vec<(u32, &[(CheckKey, bool)])> = free.chunks(5).map(|c| (0, c)).collect();
        batches.push((wait, held));
        let started = std::time::Instant::now();
        let mut done = Vec::new();
        for (wait, chunk) in batches {
            let gone = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let left = u64::from(wait).saturating_sub(gone);
            tokio::select! {
                () = stop.cancelled() => break,
                () = delay(left) => {}
            }
            for (id, _) in chunk {
                tell(
                    id,
                    CheckStage::Starting {
                        engine: Engine::Xray,
                    },
                );
            }
            let engine_ms = 600 + fastrand::u32(0..400);
            tokio::select! {
                () = stop.cancelled() => break,
                () = delay(u64::from(engine_ms)) => {}
            }
            for (id, _) in chunk {
                let since = now_ms();
                tell(
                    id,
                    CheckStage::Requesting {
                        engine: Engine::Xray,
                        engine_ms,
                        since,
                    },
                );
            }
            tokio::select! {
                () = stop.cancelled() => break,
                () = delay(1_200 + fastrand::u64(0..900)) => {}
            }
            let now = now_ms();
            for (id, online) in chunk {
                let ms = 180 + fastrand::u32(0..300);
                let (answer, reason) = if *online {
                    (CheckAnswer::Http { status: 200, ms }, None)
                } else {
                    let reason = KeyHealthReason::HandshakeFailed;
                    (CheckAnswer::Failed(reason.clone()), Some(reason))
                };
                tell(id, CheckStage::Done(answer));
                let health = KeyHealth {
                    online: *online,
                    latency_ms: online.then_some(ms),
                    reason,
                    checked_at: now,
                };
                self.edit_server(&id.id, |s| s.health = Some(health.clone()));
                let _ = results.send((id.clone(), health.clone()));
                done.push((id.id.clone(), health));
            }
        }
        let missing = ids.len() - done.len();
        Ok(HealthReport {
            results: done,
            not_checked: u32::try_from(missing).unwrap_or(u32::MAX),
        })
    }
}
