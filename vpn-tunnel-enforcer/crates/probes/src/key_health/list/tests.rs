//! The list-wide check's scheduling with a fake probe (paused clock): chains per server name,
//! the shared probe limit, the budget's freeze hold, stop and deadline.
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_profiles::model::Profile;
use vpnte_profiles::uri::parse_uri;

use super::*;
use crate::discipline::FREEZE_BACKOFF;

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

/// A probe that takes `secs(id)` and fails the keys in `fail`.
fn probe(
    seen: &Arc<Seen>,
    secs: impl Fn(&str) -> u64 + Send + Sync,
    fail: &'static [&'static str],
) -> impl Fn(
    &String,
    Profile,
    CancellationToken,
) -> std::pin::Pin<Box<dyn Future<Output = AppResult<KeyCheck>> + Send>>
+ Send
+ Sync {
    let seen = seen.clone();
    move |_: &String, p: Profile, _cancel| {
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
    let done = run_chains(items, until, &CancellationToken::new(), |_, _| {}, {
        probe(&seen, |_| 2, &[])
    })
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
    let (done, _) = run_chains(items(), far, &stop, |_, _| {}, probe(&seen, slow, &[])).await;
    assert_eq!(ids(&done), ["a1"], "a2 and b1 were in flight");

    let seen = Arc::new(Seen::default());
    let soon = Instant::now() + Duration::from_secs(3);
    let token = CancellationToken::new();
    let (done, _) = run_chains(items(), soon, &token, |_, _| {}, probe(&seen, slow, &[])).await;
    assert_eq!(ids(&done), ["a1"]);

    let seen = Arc::new(Seen::default());
    let (done, error) =
        run_chains(items(), far, &token, |_, _| {}, probe(&seen, slow, &["a1"])).await;
    assert_eq!(ids(&done), ["b1"], "a2 is not knocked after a1 failed");
    assert!(seen.started("a2").is_none());
    // psmall-a4: the reason a key could not be checked is kept for the answer.
    assert_eq!(error.map(|e| e.kind), Some(ErrorKind::Internal));
}
