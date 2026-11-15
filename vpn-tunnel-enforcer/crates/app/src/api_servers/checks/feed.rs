//! What a key check tells the page and the log (p-check-live): each key's stage as the page
//! shows it (wall-clock stamps for its countdowns), its verdict as it lands, both naming the row
//! and the key probed (b2), and one INFO line per key with its stage times and result. The log
//! names the key by its place in the run and the run's tag (`key=#7/23 run=3f9a`, b5): row ids
//! are UUIDs, which the log's redaction masks, and never a server name, an address or a key.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use vpnte_base::types::{Engine, now_ms};
use vpnte_probes::key_health::{KeyAnswer, KeyCheck, KeyStage};
use vpnte_ui::servers::{CheckAnswer, CheckKey, CheckStage, KeyHealth, KeyHealthReason};

use super::{Key, key_health_view};
use crate::api_servers::project::{key_tag, reason_code};

/// What the log keeps of one key until its line is written.
#[derive(Debug)]
struct Timeline {
    /// Its place in the run and the run's size (the log's handle: `#7/23`).
    place: (usize, usize),
    queued: Instant,
    waited: Duration,
    engine: Option<(Engine, u32)>,
    answer: Option<KeyAnswer>,
}

/// The page's channels of one check (either may be gone: a group check without a page), the
/// run's tag and the timelines of its keys.
pub(in crate::api_servers) struct Feed {
    results: Option<mpsc::UnboundedSender<(CheckKey, KeyHealth)>>,
    stages: Option<mpsc::UnboundedSender<(CheckKey, CheckStage)>>,
    /// Tells this run's lines from another run's (four hex digits, random).
    run: String,
    times: Mutex<HashMap<String, Timeline>>,
}

impl Feed {
    pub(in crate::api_servers) fn new(
        results: Option<mpsc::UnboundedSender<(CheckKey, KeyHealth)>>,
        stages: Option<mpsc::UnboundedSender<(CheckKey, CheckStage)>>,
    ) -> Self {
        let mut run = uuid::Uuid::new_v4().simple().to_string();
        run.truncate(4);
        Self {
            results,
            stages,
            run,
            times: Mutex::new(HashMap::new()),
        }
    }

    /// The run's keys in its order: each gets its place (the log's handle) and its timeline.
    pub(super) fn begin<'a>(&self, ids: impl ExactSizeIterator<Item = &'a str>) {
        let (total, now) = (ids.len(), Instant::now());
        let mut times = self.times.lock();
        for (at, id) in ids.enumerate() {
            let t = Timeline {
                place: (at + 1, total),
                queued: now,
                waited: Duration::ZERO,
                engine: None,
                answer: None,
            };
            times.insert(id.to_owned(), t);
        }
    }

    /// A key's stage: to the page as it shows it, into the key's timeline.
    pub(super) fn stage(&self, key: &Key, stage: KeyStage) {
        self.note(key.0.as_str(), stage);
        if let Some(view) = view(stage)
            && let Some(stages) = &self.stages
        {
            let _ = stages.send((checked(key), view));
        }
    }

    /// A key's verdict: to the page, and the key's log line.
    pub(super) fn result(&self, key: &Key, check: &KeyCheck) {
        if let Some(results) = &self.results {
            let _ = results.send((checked(key), key_health_view(&check.health)));
        }
        let timeline = self.times.lock().remove(key.0.as_str());
        let line = result_line(&self.run, timeline.as_ref(), check);
        tracing::info!("key check: {line}");
    }

    /// The connected session's own server: its traffic proves it, no probe was spent.
    pub(super) fn credited(&self, key: &Key, check: &KeyCheck) {
        if let Some(stages) = &self.stages {
            let _ = stages.send((checked(key), CheckStage::Done(CheckAnswer::Session)));
        }
        self.result(key, check);
    }

    /// The run is over: one line for each key left without a result (stopped, its time ran out,
    /// deferred, the probe could not start).
    pub(super) fn finish(&self) {
        for (_, t) in self.times.lock().drain() {
            let line = times_line(&self.run, Some(&t));
            tracing::info!("key check: {line} result=not-checked");
        }
    }

    fn note(&self, id: &str, stage: KeyStage) {
        let mut times = self.times.lock();
        let Some(t) = times.get_mut(id) else {
            return;
        };
        match stage {
            KeyStage::Waiting { wait } => t.waited += wait,
            KeyStage::Requesting { engine, engine_ms } => t.engine = Some((engine, engine_ms)),
            KeyStage::Done(answer) => t.answer = Some(answer),
            KeyStage::Queued
            | KeyStage::Starting { .. }
            | KeyStage::Asked { .. }
            | KeyStage::Unchecked => {}
        }
    }
}

/// The row and the key a stage or result is about, as the page matches them.
fn checked(key: &Key) -> CheckKey {
    CheckKey {
        id: key.0.to_string(),
        tag: key_tag(key.1),
    }
}

/// A stage as the page shows it: waits and requests stamped on the wall clock for its counters.
fn view(stage: KeyStage) -> Option<CheckStage> {
    Some(match stage {
        KeyStage::Queued => CheckStage::Queued,
        KeyStage::Waiting { wait } => CheckStage::Waiting {
            until: now_ms().saturating_add(i64::try_from(wait.as_millis()).unwrap_or(i64::MAX)),
        },
        KeyStage::Starting { engine } => CheckStage::Starting { engine },
        KeyStage::Requesting { engine, engine_ms } => CheckStage::Requesting {
            engine,
            engine_ms,
            since: now_ms(),
        },
        KeyStage::Asked {
            engine,
            engine_ms,
            asked_ms,
        } => CheckStage::Asked {
            engine,
            engine_ms,
            asked_ms,
        },
        KeyStage::Done(answer) => CheckStage::Done(answer_view(answer)?),
        KeyStage::Unchecked => CheckStage::NotChecked,
    })
}

/// What came back, as the page names it (a failure by the server list's reason code).
fn answer_view(answer: KeyAnswer) -> Option<CheckAnswer> {
    Some(match answer {
        KeyAnswer::Http { status, ms } => CheckAnswer::Http { status, ms },
        KeyAnswer::Stalled { bytes } => CheckAnswer::Stalled { bytes },
        KeyAnswer::Silent { ms } => CheckAnswer::Silent { ms },
        KeyAnswer::Failed(reason) => {
            CheckAnswer::Failed(KeyHealthReason::from_code(&reason_code(reason)?))
        }
    })
}

/// The engine and its start time for a log line ("-" / 0 before the engine served its port).
fn engine_fields(engine: Option<(Engine, u32)>) -> (&'static str, u32) {
    match engine {
        Some((Engine::SingBox, ms)) => ("sing-box", ms),
        Some((Engine::Xray, ms)) => ("xray", ms),
        #[cfg(feature = "lab")]
        Some((Engine::Mihomo, ms)) => ("mihomo", ms),
        None => ("-", 0),
    }
}

/// The key's handle (its place in run `run`), how long it took, how long it waited for its
/// server name, the engine and its start time.
fn times_line(run: &str, t: Option<&Timeline>) -> String {
    let (at, of) = t.map_or((0, 0), |t| t.place);
    let total_ms = t.map_or(0, |t| t.queued.elapsed().as_millis());
    let waited_s = t.map_or(0, |t| t.waited.as_secs());
    let (engine, engine_ms) = engine_fields(t.and_then(|t| t.engine));
    let handle = format!("key=#{at}/{of} run={run}");
    format!(
        "{handle} total_ms={total_ms} waited_s={waited_s} engine={engine} engine_ms={engine_ms}"
    )
}

/// The key's log line: its times, what came back and the verdict.
fn result_line(run: &str, t: Option<&Timeline>, check: &KeyCheck) -> String {
    let answer = match t.and_then(|t| t.answer) {
        Some(KeyAnswer::Http { status, ms }) => format!("http {status} in {ms} ms"),
        Some(KeyAnswer::Stalled { bytes }) => format!("data stopped after {bytes} bytes"),
        Some(KeyAnswer::Silent { ms }) => format!("no answer in {ms} ms"),
        Some(KeyAnswer::Failed(reason)) => reason_code(reason).unwrap_or_default(),
        // The session's own server, answered without a probe.
        None if check.health.online => "proven by the session".to_owned(),
        None => "no probe".to_owned(),
    };
    let verdict = reason_code(check.verdict.verdict).unwrap_or_default();
    let online = check.health.online;
    let times = times_line(run, t);
    format!("{times} answer=\"{answer}\" online={online} verdict={verdict}")
}

#[cfg(test)]
mod tests;
