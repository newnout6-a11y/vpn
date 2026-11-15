//! The list-wide check's scheduling with a fake probe (paused clock): chains per server name,
//! the shared probe limit, the budget's freeze hold, stop and deadline.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine;
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_profiles::model::Profile;
use vpnte_profiles::uri::parse_uri;

use super::*;
use crate::discipline::FREEZE_BACKOFF;
use crate::key_health::KEY_WAIT;

/// A server name no other test uses (the budget is process-wide).
fn name(tag: &str) -> String {
    format!("{tag}-{}.example.net", uuid::Uuid::new_v4().simple())
}

/// Key `id` on its own host behind the TLS server name `sni`.
fn key(id: &str, sni: &str) -> (String, Option<Profile>) {
    let link = format!("trojan://fake-pass@{id}.example.com:443?sni={sni}#{id}");
    (id.to_owned(), Some(parse_uri(&link).unwrap()))
}

/// What the fake probe saw: each start (key, time), the most probes at once overall and behind
/// one name.
#[derive(Default)]
struct Seen {
    starts: Mutex<Vec<(String, Instant)>>,
    running: Mutex<HashMap<String, usize>>,
    peak: AtomicUsize,
    peak_per_name: AtomicUsize,
}

impl Seen {
    fn start(&self, id: String, sni: String) {
        self.starts.lock().push((id, Instant::now()));
        let mut running = self.running.lock();
        *running.entry(sni.clone()).or_default() += 1;
        let total: usize = running.values().sum();
        self.peak.fetch_max(total, Ordering::SeqCst);
        self.peak_per_name
            .fetch_max(running[&sni], Ordering::SeqCst);
    }

    fn end(&self, sni: &str) {
        if let Some(n) = self.running.lock().get_mut(sni) {
            *n -= 1;
        }
    }

    fn started(&self, id: &str) -> Option<Instant> {
        let starts = self.starts.lock();
        starts.iter().find(|(k, _)| k == id).map(|(_, at)| *at)
    }
}

/// What a fake probe answers.
type Probed = std::pin::Pin<Box<dyn Future<Output = AppResult<KeyCheck>> + Send>>;

/// A probe that takes `secs(id)` and fails the keys in `fail`.
fn probe(
    seen: &Arc<Seen>,
    secs: impl Fn(&str) -> u64 + Send + Sync,
    fail: &'static [&'static str],
) -> impl Fn(&String, Profile, CancellationToken, Stages) -> Probed + Send + Sync {
    let seen = seen.clone();
    move |_: &String, p: Profile, _cancel, _stages| {
        let id = p.name.clone();
        let sni = p
            .tls
            .as_ref()
            .and_then(|t| t.server_name.clone())
            .unwrap_or_default();
        let (seen, wait) = (seen.clone(), Duration::from_secs(secs(&id)));
        Box::pin(async move {
            seen.start(id.clone(), sni.clone());
            tokio::time::sleep(wait).await;
            seen.end(&sni);
            if fail.contains(&id.as_str()) {
                return Err(AppError::new(ErrorKind::Internal));
            }
            Ok(unreadable())
        })
    }
}

fn ids(done: &[(String, KeyCheck)]) -> Vec<String> {
    let mut ids: Vec<String> = done.iter().map(|(k, _)| k.clone()).collect();
    ids.sort();
    ids
}

/// p-small (RU-2026 item 6): keys behind one server name go one at a time in list order, the
/// other names use the free probes (never more than [`CONCURRENCY`] at once), an unreadable row
/// is answered without a probe, and every result is reported as it lands.
#[tokio::test(start_paused = true)]
async fn keys_behind_one_name_go_one_at_a_time() {
    let (a, b) = (name("a"), name("b"));
    let mut items = vec![key("a1", &a), key("b1", &b), key("a2", &a), key("a3", &a)];
    items.push(key("b2", &b));
    items.extend((1..=6).map(|n| key(&format!("c{n}"), &name("c"))));
    items.push(("u".to_owned(), None));
    let seen = Arc::new(Seen::default());
    let reported = AtomicUsize::new(0);
    let done = run_chains(
        items,
        Instant::now() + Duration::from_secs(3600),
        &CancellationToken::new(),
        |_, _| {
            reported.fetch_add(1, Ordering::SeqCst);
        },
        |_, _| {},
        probe(&seen, |_| 2, &[]),
    )
    .await
    .0;
    assert_eq!(done.len(), 12);
    assert_eq!(reported.load(Ordering::SeqCst), 12);
    assert!(ids(&done).contains(&"u".to_owned()));
    assert_eq!(
        seen.starts.lock().len(),
        11,
        "no probe for the unreadable row"
    );
    assert_eq!(seen.peak_per_name.load(Ordering::SeqCst), 1);
    assert_eq!(seen.peak.load(Ordering::SeqCst), CONCURRENCY);
    let (a1, a2, a3) = (seen.started("a1"), seen.started("a2"), seen.started("a3"));
    assert!(a1 < a2 && a2 < a3, "list order inside a chain");
}

/// A server name in its freeze hold (130 s after a freeze verdict) holds back only its own chain,
/// without taking one of the probes meanwhile.
#[tokio::test(start_paused = true)]
async fn a_frozen_name_holds_back_only_its_chain() {
    let (a, b) = (name("a"), name("b"));
    budget().hold(&Endpoint::server_name(&a), FREEZE_BACKOFF);
    let t0 = Instant::now();
    let seen = Arc::new(Seen::default());
    let items = vec![key("a1", &a), key("b1", &b), key("b2", &b)];
    let until = t0 + Duration::from_secs(3600);
    let done = run_chains(
        items,
        until,
        &CancellationToken::new(),
        |_, _| {},
        |_, _| {},
        probe(&seen, |_| 2, &[]),
    )
    .await
    .0;
    assert_eq!(ids(&done), ["a1", "b1", "b2"]);
    assert!(seen.started("b1").unwrap() - t0 < Duration::from_secs(1));
    assert!(seen.started("b2").unwrap() - t0 < Duration::from_secs(5));
    assert!(seen.started("a1").unwrap() - t0 >= FREEZE_BACKOFF);
}

/// A stop or the deadline ends the run: probes in flight are dropped (not checked), what
/// finished is kept; a key that could not be checked ends its chain, the others go on.
#[tokio::test(start_paused = true)]
async fn stop_deadline_and_failures_keep_what_finished() {
    let (a, b) = (name("a"), name("b"));
    let slow = |id: &str| if id == "b1" { 60 } else { 2 };
    let items = || vec![key("a1", &a), key("a2", &a), key("b1", &b)];
    let stop = CancellationToken::new();
    let later = stop.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        later.cancel();
    });
    let seen = Arc::new(Seen::default());
    let far = Instant::now() + Duration::from_secs(3600);
    let (done, _) = run_chains(
        items(),
        far,
        &stop,
        |_, _| {},
        |_, _| {},
        probe(&seen, slow, &[]),
    )
    .await;
    assert_eq!(ids(&done), ["a1"], "a2 and b1 were in flight");

    let seen = Arc::new(Seen::default());
    let soon = Instant::now() + Duration::from_secs(3);
    let token = CancellationToken::new();
    let (done, _) = run_chains(
        items(),
        soon,
        &token,
        |_, _| {},
        |_, _| {},
        probe(&seen, slow, &[]),
    )
    .await;
    assert_eq!(ids(&done), ["a1"]);

    let seen = Arc::new(Seen::default());
    let (done, error) = run_chains(
        items(),
        far,
        &token,
        |_, _| {},
        |_, _| {},
        probe(&seen, slow, &["a1"]),
    )
    .await;
    assert_eq!(ids(&done), ["b1"], "a2 is not knocked after a1 failed");
    assert!(seen.started("a2").is_none());
    // psmall-a4: the reason a key could not be checked is kept for the answer.
    assert_eq!(error.map(|e| e.kind), Some(ErrorKind::Internal));
}

/// Lab live-9 L9-7: the names the budget lets through go first, the longest chain first; a name
/// held back says so for each of its keys (with the wait) before it waits, and is checked last.
#[tokio::test(start_paused = true)]
async fn ready_names_go_first_and_held_ones_say_they_wait() {
    let (held, short, long) = (name("held"), name("short"), name("long"));
    budget().hold(&Endpoint::server_name(&held), FREEZE_BACKOFF);
    let mut items = vec![key("h1", &held), key("s1", &short), key("h2", &held)];
    items.extend((1..=3).map(|n| key(&format!("l{n}"), &long)));
    let seen = Arc::new(Seen::default());
    let waits = Mutex::new(Vec::new());
    let until = Instant::now() + Duration::from_secs(3600);
    let (done, _) = run_chains(
        items,
        until,
        &CancellationToken::new(),
        |_, _| {},
        |k: &String, stage| {
            if let KeyStage::Waiting { wait } = stage {
                waits.lock().push((k.clone(), wait));
            }
        },
        probe(&seen, |_| 2, &[]),
    )
    .await;
    assert_eq!(done.len(), 6);
    let order: Vec<String> = seen.starts.lock().iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(
        order[..2],
        ["l1", "s1"],
        "the longest ready chain first: {order:?}"
    );
    assert_eq!(order[4..], ["h1", "h2"], "the held name last: {order:?}");
    let waits = waits.into_inner();
    let named: Vec<&str> = waits.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(named, ["h1", "h2"]);
    assert!(
        waits
            .iter()
            .all(|(_, w)| *w > FREEZE_BACKOFF - Duration::from_secs(1))
    );
}

/// What a run told, in order: each key's stages and its result.
#[derive(Debug, Clone, PartialEq)]
enum Told {
    Stage(String, KeyStage),
    Result(String),
}

/// A probe that tells two stages of its own, one second apart.
fn telling() -> impl Fn(&String, Profile, CancellationToken, Stages) -> Probed + Send + Sync {
    |_: &String, _, _, stages: Stages| {
        Box::pin(async move {
            stages.send(KeyStage::Starting {
                engine: Engine::SingBox,
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
            stages.send(KeyStage::Done(KeyAnswer::Http {
                status: 200,
                ms: 40,
            }));
            Ok(unreadable())
        })
    }
}

/// p-check-live: every key is queued at once; a key whose server name is held is told the
/// budget's own wait (the page counts it down), and the keys behind it on that name their own
/// turn (p-fix-checklive a3: one probe later); when its wait ends it is queued again, and so is
/// the next key at its turn; a probe's stages all come before its result.
#[tokio::test(start_paused = true)]
async fn a_waiting_key_tells_its_countdown() {
    let (held, free) = (name("held"), name("free"));
    budget().hold(&Endpoint::server_name(&held), FREEZE_BACKOFF);
    let items = vec![key("h1", &held), key("f1", &free), key("h2", &held)];
    let told = Mutex::new(Vec::new());
    let until = Instant::now() + Duration::from_secs(3600);
    run_chains(
        items,
        until,
        &CancellationToken::new(),
        |k: &String, _: &KeyCheck| told.lock().push(Told::Result(k.clone())),
        |k: &String, stage| told.lock().push(Told::Stage(k.clone(), stage)),
        telling(),
    )
    .await;
    let told = told.into_inner();
    let of = |id: &str| -> Vec<Told> {
        let mine = |t: &&Told| matches!(t, Told::Stage(k, _) | Told::Result(k) if k == id);
        told.iter().filter(mine).cloned().collect()
    };
    let stage = |id: &str, s| Told::Stage(id.to_owned(), s);
    let started = stage(
        "h1",
        KeyStage::Starting {
            engine: Engine::SingBox,
        },
    );
    let answered = KeyStage::Done(KeyAnswer::Http {
        status: 200,
        ms: 40,
    });
    let h1 = of("h1");
    let Told::Stage(_, KeyStage::Waiting { wait }) = h1[1] else {
        panic!("h1 waits first: {h1:?}");
    };
    assert!(wait > FREEZE_BACKOFF - Duration::from_secs(1) && wait <= FREEZE_BACKOFF);
    let waiting = |id: &str| stage(id, KeyStage::Waiting { wait });
    assert_eq!(
        h1,
        [
            stage("h1", KeyStage::Queued),
            waiting("h1"),
            stage("h1", KeyStage::Queued),
            started,
            stage("h1", answered),
            Told::Result("h1".into()),
        ]
    );
    let h2 = of("h2");
    let behind = KeyStage::Waiting {
        wait: wait + PROBE_TIME,
    };
    assert_eq!(
        h2[..3],
        [
            stage("h2", KeyStage::Queued),
            stage("h2", behind),
            stage("h2", KeyStage::Queued)
        ]
    );
    assert_eq!(h2.last(), Some(&Told::Result("h2".into())));
    let f1 = of("f1");
    assert!(
        !f1.iter()
            .any(|t| matches!(t, Told::Stage(_, KeyStage::Waiting { .. }))),
        "{f1:?}"
    );
}

/// The probe's own wait for a slot (another check took the name's budget meanwhile) is named
/// before it sleeps, from the budget's reservation itself.
#[tokio::test(start_paused = true)]
async fn the_budget_names_its_own_wait() {
    let busy = Endpoint::server_name(&name("busy"));
    let cancel = CancellationToken::new();
    for _ in 0..crate::discipline::MAX_PER_WINDOW {
        budget().acquire(&busy, KEY_WAIT, &cancel).await.unwrap();
    }
    let heard = Mutex::new(None);
    let t0 = Instant::now();
    let note = |wait| *heard.lock() = Some(wait);
    budget()
        .acquire_noting(&busy, KEY_WAIT, &cancel, note)
        .await
        .unwrap();
    let heard = heard.into_inner().expect("the wait is named");
    assert!(
        heard > Duration::from_secs(55) && heard <= crate::discipline::WINDOW,
        "{heard:?}"
    );
    assert!(t0.elapsed() >= heard);
}

/// A probe that takes its name's handshake slot like the real one, then runs `secs`.
fn budgeted(secs: u64) -> impl Fn(&String, Profile, CancellationToken, Stages) -> Probed {
    move |_: &String, p: Profile, cancel: CancellationToken, _| {
        Box::pin(async move {
            let endpoint = Endpoint::of(&p).expect("a named key");
            budget().acquire(&endpoint, KEY_WAIT, &cancel).await?;
            tokio::time::sleep(Duration::from_secs(secs)).await;
            Ok(unreadable())
        })
    }
}

/// p-fix-checklive a3: nine keys behind one name (3 a minute): each key behind the held one is
/// told its own turn (the 7thвЂ“9th wait for the window after next), not the first held key's
/// wait, which ran out and started again for them; every wait told holds to the second.
#[tokio::test(start_paused = true)]
async fn keys_behind_a_held_name_hear_their_own_turn() {
    let shared = name("turns");
    let items: Vec<_> = (1..=9).map(|n| key(&format!("k{n}"), &shared)).collect();
    let t0 = Instant::now();
    let told = Mutex::new(Vec::new());
    let starts = Mutex::new(HashMap::new());
    let on_stage = |k: &String, stage| {
        if let KeyStage::Waiting { wait } = stage {
            told.lock().push((k.clone(), Instant::now() + wait));
        }
    };
    let probe = budgeted(3);
    let check = |k: &String, p: Profile, cancel, stages| {
        starts.lock().insert(k.clone(), Instant::now());
        probe(k, p, cancel, stages)
    };
    let until = t0 + Duration::from_secs(3600);
    let stop = CancellationToken::new();
    let (done, _) = run_chains(items, until, &stop, |_, _| {}, on_stage, check).await;
    assert_eq!(done.len(), 9);
    let (told, starts) = (told.into_inner(), starts.into_inner());
    let secs = |at: Instant| at.duration_since(t0).as_secs_f64();
    let first = |id: &str| told.iter().find(|(k, _)| k == id).map(|(_, at)| secs(*at));
    assert_eq!(first("k3"), None, "the first window needs no wait");
    for (id, slot) in [("k4", 60.0), ("k6", 66.0), ("k7", 120.0), ("k9", 126.0)] {
        let at = first(id).unwrap_or_else(|| panic!("{id} is told its turn: {told:?}"));
        assert!((at - slot).abs() < 1.0, "{id}: told {at}, its slot {slot}");
    }
    for (id, at) in &told {
        // The probe takes what the scheduler waited for (the paced dial inside it adds less
        // than a second), so the slot it was told is when it really started.
        let started = secs(starts[id]);
        assert!(
            started >= secs(*at) - 1.0 && started - secs(*at) < 4.0,
            "{id}: {told:?}"
        );
    }
}

/// p-fix-checklive a5: В«РћС‚РјРµРЅРёС‚СЊВ» lands while a probe waits in the budget for a slot another
/// check took meanwhile; the budget answers `Cancelled` in the same poll, before anything
/// landed. A stop is no reason a key could not be checked: the run names none (psmall-a4), so
/// the app commits and the page says the check stopped instead of showing an error.
#[tokio::test(start_paused = true)]
async fn a_stop_while_a_probe_waits_for_its_slot_is_no_reason() {
    let items = vec![key("w1", &name("taken"))];
    let waiting = |_: &String, p: Profile, cancel: CancellationToken, _| -> Probed {
        Box::pin(async move {
            let endpoint = Endpoint::of(&p).expect("a named key");
            for _ in 0..crate::discipline::MAX_PER_WINDOW {
                budget()
                    .reserve_at(&endpoint, Instant::now(), KEY_WAIT)
                    .expect("another check takes the window");
            }
            let pressed = |_| cancel.cancel();
            budget()
                .acquire_noting(&endpoint, KEY_WAIT, &cancel, pressed)
                .await?;
            Ok(unreadable())
        })
    };
    let told = Mutex::new(Vec::new());
    let on_stage = |_: &String, stage| told.lock().push(stage);
    let stop = CancellationToken::new();
    let until = Instant::now() + Duration::from_secs(3600);
    let (done, unchecked) = run_chains(items, until, &stop, |_, _| {}, on_stage, waiting).await;
    assert!(stop.is_cancelled());
    assert!(done.is_empty(), "nothing landed");
    assert!(unchecked.is_none(), "a stop is no reason: {unchecked:?}");
    assert_eq!(told.into_inner().last(), Some(&KeyStage::Unchecked));
}
