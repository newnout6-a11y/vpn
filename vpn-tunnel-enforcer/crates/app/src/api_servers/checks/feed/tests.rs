//! p-check-live: the page sees each key's stage with wall-clock stamps for its counters, its
//! verdict as it lands, the session's own server as proven, each naming the row and the key
//! probed (p-fix-checklive b2); the log line of a key carries its numbers and its place in the
//! run (b5), never the row id.
use std::time::{Duration, Instant};

use vpnte_base::types::{Engine, now_ms};
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::{HealthReason, KeyHealth as Probed};
use vpnte_servers::model::ProfileId;

use super::*;

fn key(id: &str) -> Key {
    (ProfileId::from(id), None)
}

fn healthy() -> KeyCheck {
    let health = Probed {
        online: true,
        at: 1,
        rtt_ms: Some(312),
        reason: None,
        egress_ip: None,
        country: None,
        engine: Some(Engine::Xray),
    };
    let verdict = Classification {
        verdict: Verdict::Healthy,
        reaction: Reaction::None,
    };
    KeyCheck { health, verdict }
}

fn drain<T>(rx: &mut mpsc::UnboundedReceiver<(CheckKey, T)>) -> Vec<(CheckKey, T)> {
    std::iter::from_fn(|| rx.try_recv().ok()).collect()
}

#[test]
fn the_page_sees_each_stage_in_numbers() {
    let (results, mut landed) = mpsc::unbounded_channel();
    let (stages, mut staged) = mpsc::unbounded_channel();
    let feed = Feed::new(Some(results), Some(stages));
    let identity = [7; 16];
    let k = (ProfileId::from("row-1"), Some(identity));
    feed.begin(["row-1", "row-2", "row-3", "row-4"].into_iter());
    let before = now_ms();
    feed.stage(&k, KeyStage::Queued);
    let wait = Duration::from_secs(41);
    feed.stage(&k, KeyStage::Waiting { wait });
    let engine = Engine::Xray;
    feed.stage(
        &k,
        KeyStage::Requesting {
            engine,
            engine_ms: 840,
        },
    );
    let asked = KeyStage::Asked {
        engine,
        engine_ms: 840,
        asked_ms: 1_200,
    };
    feed.stage(&k, asked);
    feed.stage(
        &k,
        KeyStage::Done(KeyAnswer::Http {
            status: 200,
            ms: 312,
        }),
    );
    feed.result(&k, &healthy());
    let after = now_ms();
    let staged_now = drain(&mut staged);
    let tag = key_tag(Some(identity));
    assert_ne!(tag, 0);
    let row_1 = CheckKey {
        id: "row-1".into(),
        tag,
    };
    assert!(
        staged_now.iter().all(|(k, _)| *k == row_1),
        "{staged_now:?}"
    );
    let seen: Vec<CheckStage> = staged_now.into_iter().map(|(_, s)| s).collect();
    assert_eq!(seen[0], CheckStage::Queued);
    let CheckStage::Waiting { until } = seen[1] else {
        panic!("{seen:?}");
    };
    assert!(
        (before + 41_000..=after + 41_000).contains(&until),
        "{seen:?}"
    );
    let CheckStage::Requesting {
        engine_ms: 840,
        since,
        ..
    } = seen[2]
    else {
        panic!("{seen:?}");
    };
    assert!((before..=after).contains(&since));
    let asked = CheckStage::Asked {
        engine,
        engine_ms: 840,
        asked_ms: 1_200,
    };
    assert_eq!(seen[3], asked);
    let http = CheckAnswer::Http {
        status: 200,
        ms: 312,
    };
    assert_eq!(seen[4], CheckStage::Done(http));
    let landed = drain(&mut landed);
    assert_eq!(landed.len(), 1);
    let (to, health) = &landed[0];
    assert_eq!(
        (to, health.online, health.latency_ms),
        (&row_1, true, Some(312))
    );

    // A failure by the server list's code, the session's own server, a key its chain dropped.
    let refused = KeyAnswer::Failed(HealthReason::ConnectionRefused);
    feed.stage(&key("row-2"), KeyStage::Done(refused));
    feed.credited(&key("row-3"), &healthy());
    feed.stage(&key("row-4"), KeyStage::Unchecked);
    let rest = drain(&mut staged);
    assert!(rest.iter().all(|(k, _)| k.tag == 0), "an unreadable key");
    let rest: Vec<CheckStage> = rest.into_iter().map(|(_, s)| s).collect();
    let code = KeyHealthReason::from_code("connection-refused");
    let expected = [
        CheckStage::Done(CheckAnswer::Failed(code)),
        CheckStage::Done(CheckAnswer::Session),
        CheckStage::NotChecked,
    ];
    assert_eq!(rest, expected);
    feed.finish();
    assert!(feed.times.lock().is_empty(), "every key had its line");
}

/// b5: the per-key line names its key by its place in the run and the run's tag, a handle the
/// log's redaction leaves as it is (row ids are UUIDs, which it masks: every line read
/// `key=<redacted-uuid>`) and that names nobody.
#[test]
fn the_log_line_names_the_key_by_its_place_in_the_run() {
    let ids = [
        "6f1c2a9e-3b4d-4e5f-8a7b-9c0d1e2f3a4b",
        "0b8e7d6c-5a4f-4e3d-9c2b-1a0f9e8d7c6b",
    ];
    let feed = Feed::new(None, None);
    feed.begin(ids.into_iter());
    let k = key(ids[1]);
    let wait = Duration::from_secs(41);
    feed.stage(&k, KeyStage::Waiting { wait });
    let engine = Engine::Xray;
    feed.stage(
        &k,
        KeyStage::Requesting {
            engine,
            engine_ms: 840,
        },
    );
    let http = KeyAnswer::Http {
        status: 200,
        ms: 312,
    };
    feed.stage(&k, KeyStage::Done(http));
    let t = feed.times.lock().remove(ids[1]).expect("begun");
    let line = result_line(&feed.run, Some(&t), &healthy());
    let logged = vpnte_core::redact::for_log(&line);
    let parts = [
        format!("key=#2/2 run={} ", feed.run),
        "waited_s=41 ".to_owned(),
        "engine=xray engine_ms=840 ".to_owned(),
        "answer=\"http 200 in 312 ms\" ".to_owned(),
        "online=true verdict=healthy".to_owned(),
    ];
    for part in &parts {
        assert!(logged.contains(part.as_str()), "{part:?} in {logged}");
    }
    assert!(!logged.contains("redacted"), "{logged}");
    assert!(!logged.contains(ids[1]), "{logged}");
    assert_eq!(feed.run.len(), 4);

    let silent = Timeline {
        answer: Some(KeyAnswer::Silent { ms: 10_000 }),
        engine: None,
        queued: Instant::now(),
        ..t
    };
    let line = result_line(&feed.run, Some(&silent), &healthy());
    assert!(
        line.contains("engine=- engine_ms=0 answer=\"no answer in 10000 ms\""),
        "{line}"
    );
    let credited = result_line(&feed.run, None, &healthy());
    assert!(
        credited.contains("answer=\"proven by the session\""),
        "{credited}"
    );
}
