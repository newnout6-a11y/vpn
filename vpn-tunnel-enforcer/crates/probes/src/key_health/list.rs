//! The list-wide check (RU-2026 item 6): every key of the server list through its own server,
//! under the handshake budget. Keys are chained per endpoint, one probe at a time in list order,
//! and a chain waits out its endpoint's budget (3 handshakes a minute, the 130 s quiet time after
//! a freeze) before it takes one of the [`CONCURRENCY`] probes: a busy or frozen server name holds
//! back only its own chain while the other chains use the free probes. A key that cannot be
//! checked (deferred, the probe did not start) ends its chain: the rest would knock again.
//! p-check-live: every key's stage is told as it happens ([`KeyStage`]), so the page shows the
//! wait for a name as a countdown instead of a silent minute; each key behind a held name hears
//! its own turn (p-fix-checklive a3), not the first key's.
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind};
use vpnte_profiles::model::Profile;

use super::stage::Stages;
use super::{
    CONCURRENCY, HealthReason, KeyAnswer, KeyCheck, KeyStage, ProbeCtx, check_profile_staged,
    unreadable,
};
use crate::discipline::{Endpoint, budget};

/// Longest list-wide check: one server name shared by many keys (a REALITY camouflage name) is
/// checked at 3 a minute, so a long list needs minutes; what is left at the end is not checked.
pub const LIST_DEADLINE: Duration = Duration::from_secs(20 * 60);
/// How long one probe of a working key takes (engine start, handshake, test request, stop): the
/// pace of a chain in the estimate of each key's turn. A slower probe only makes the estimate
/// early; the next key at the chain's head is estimated again.
const PROBE_TIME: Duration = Duration::from_secs(3);

/// The keys of one probe context (a client device and engine choice of the list).
pub type ListGroup<K> = (ProbeCtx, Vec<(K, Option<Profile>)>);

/// What a list-wide check found.
#[derive(Debug)]
pub struct ListOutcome<K> {
    /// The results, in completion order.
    pub done: Vec<(K, KeyCheck)>,
    /// The first reason a probe could not run (the engine missing, no free port, the budget
    /// deferring): a run where nothing could be checked says why (psmall-a4).
    pub unchecked: Option<AppError>,
}

/// Checks every key of `groups` (`None` = the row's profile is unreadable here: `no-outbound`
/// without a probe) until all are done, `until` passes or `stop` fires; probes in flight then are
/// dropped (not checked; their engines end with them) and the finished results are kept. All
/// groups run at once behind the one probe limit, so a slow name in one group never starves
/// another (psmall-a1/b5). `on_result` sees each result as it lands; `on_stage` hears each key's
/// stages as they happen, in order and before its result: [`KeyStage::Queued`] for every key at
/// once, a name's wait for its keys before the wait (lab live-9 L9-7), the probe's own stages.
pub async fn check_list<K: Send>(
    groups: Vec<ListGroup<K>>,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
    on_stage: impl Fn(&K, KeyStage) + Send + Sync,
) -> ListOutcome<K> {
    let mut ctxs = Vec::with_capacity(groups.len());
    let mut items = Vec::new();
    for (ctx, keys) in groups {
        let group = ctxs.len();
        ctxs.push(ctx);
        items.extend(keys.into_iter().map(|(key, p)| ((key, group), p)));
    }
    let ctxs = &ctxs;
    let check = |(_, group): &(K, usize), p: Profile, cancel: CancellationToken, stages: Stages| {
        let ctx = &ctxs[*group];
        async move { check_profile_staged(&p, ctx, &cancel, &stages).await }
    };
    let report = |(key, _): &(K, usize), check: &KeyCheck| on_result(key, check);
    let stage = |(key, _): &(K, usize), stage: KeyStage| on_stage(key, stage);
    let (done, unchecked) = run_chains(items, until, stop, report, stage, check).await;
    let done = done.into_iter().map(|((key, _), c)| (key, c)).collect();
    ListOutcome { done, unchecked }
}

/// [`check_list`] with the probe given (test seam): the results and the first probe error.
pub(crate) async fn run_chains<K, F, Fut>(
    items: Vec<(K, Option<Profile>)>,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
    on_stage: impl Fn(&K, KeyStage) + Send + Sync,
    check: F,
) -> (Vec<(K, KeyCheck)>, Option<AppError>)
where
    K: Send,
    F: Fn(&K, Profile, CancellationToken, Stages) -> Fut + Send + Sync,
    Fut: Future<Output = AppResult<KeyCheck>> + Send,
{
    (items.iter()).for_each(|(key, _)| on_stage(key, KeyStage::Queued));
    let probes = Semaphore::new(CONCURRENCY);
    let done = Mutex::new(Vec::new());
    let first_error = Mutex::new(None);
    let (on_stage, check) = (&on_stage, &check);
    let chains = by_readiness(chains(items)).into_iter().map(|chain| async {
        let mut chain = chain.into_iter();
        let mut told_waits = false;
        while let Some((key, profile)) = chain.next() {
            let result = match profile {
                None => {
                    let failed = KeyAnswer::Failed(HealthReason::NoOutbound);
                    on_stage(&key, KeyStage::Done(failed));
                    unreadable()
                }
                Some(p) => {
                    let behind = chain.as_slice();
                    let waits = Endpoint::of(&p).map_or_else(Vec::new, |e| {
                        budget().waits_in_turn(&e, 1 + behind.len(), PROBE_TIME)
                    });
                    // A turn told before may have changed (a slot given back): tell it again.
                    if told_waits || waits.iter().any(Option::is_some) {
                        told_waits = tell_turns(on_stage, &key, behind, &waits);
                    }
                    if let Some(Some(wait)) = waits.first() {
                        tokio::time::sleep(*wait).await;
                        on_stage(&key, KeyStage::Queued);
                    }
                    let Ok(_probe) = probes.acquire().await else {
                        return;
                    };
                    match probed(&key, p, stop, on_stage, check).await {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::warn!(error = %err, "list check: a chain ends unchecked");
                            tell(on_stage, &key, chain.as_slice(), KeyStage::Unchecked);
                            // A stop is no reason a key could not be checked (psmall-a4).
                            if err.kind != ErrorKind::Cancelled {
                                first_error.lock().get_or_insert(err);
                            }
                            return;
                        }
                    }
                }
            };
            on_result(&key, &result);
            done.lock().push((key, result));
        }
    });
    tokio::select! {
        () = stop.cancelled() => {}
        () = tokio::time::sleep_until(until) => {}
        _ = join_all(chains) => {}
    }
    (done.into_inner(), first_error.into_inner())
}

/// Tells `key` and each key behind it on its server name its own turn (`waits`, in chain order):
/// the budget's wait, else queued behind the keys before it. Whether any wait was told.
fn tell_turns<K>(
    on_stage: &impl Fn(&K, KeyStage),
    key: &K,
    behind: &[(K, Option<Profile>)],
    waits: &[Option<Duration>],
) -> bool {
    let keys = std::iter::once(key).chain(behind.iter().map(|(k, _)| k));
    for (k, wait) in keys.zip(waits.iter().chain(std::iter::repeat(&None))) {
        on_stage(
            k,
            wait.map_or(KeyStage::Queued, |wait| KeyStage::Waiting { wait }),
        );
    }
    waits.iter().any(Option::is_some)
}

/// Tells `stage` of `key` and of the keys behind it on its server name.
fn tell<K>(
    on_stage: &impl Fn(&K, KeyStage),
    key: &K,
    behind: &[(K, Option<Profile>)],
    stage: KeyStage,
) {
    on_stage(key, stage);
    behind.iter().for_each(|(k, _)| on_stage(k, stage));
}

/// One probe whose stages are handed on in order, all of them before its result.
async fn probed<K, F, Fut>(
    key: &K,
    p: Profile,
    stop: &CancellationToken,
    on_stage: &impl Fn(&K, KeyStage),
    check: &F,
) -> AppResult<KeyCheck>
where
    F: Fn(&K, Profile, CancellationToken, Stages) -> Fut,
    Fut: Future<Output = AppResult<KeyCheck>>,
{
    let (stages, mut told) = Stages::channel();
    let probe = check(key, p, stop.clone(), stages);
    tokio::pin!(probe);
    let result = loop {
        tokio::select! {
            biased;
            Some(stage) = told.recv() => on_stage(key, stage),
            result = &mut probe => break result,
        }
    };
    while let Ok(stage) = told.try_recv() {
        on_stage(key, stage);
    }
    result
}

/// The keys grouped by the endpoint their probe dials (list order kept inside a chain); a key
/// without one (unreadable, a loopback proxy) is a chain of its own.
fn chains<K>(items: Vec<(K, Option<Profile>)>) -> Vec<Vec<(K, Option<Profile>)>> {
    let mut chains: Vec<Vec<(K, Option<Profile>)>> = Vec::new();
    let mut by_endpoint: HashMap<Endpoint, usize> = HashMap::new();
    for item in items {
        let at = match item.1.as_ref().and_then(Endpoint::of) {
            Some(endpoint) => *by_endpoint.entry(endpoint).or_insert_with(|| {
                chains.push(Vec::new());
                chains.len() - 1
            }),
            None => {
                chains.push(Vec::new());
                chains.len() - 1
            }
        };
        chains[at].push(item);
    }
    chains
}

/// Lab live-9 L9-7: the names the budget lets through now first, the longest chain first (its
/// later keys need the most windows, so its first window should open soonest); then the names
/// held back, the shortest wait first. Every chain still runs at once: this orders who gets the
/// free probes first.
fn by_readiness<K>(mut chains: Vec<Vec<(K, Option<Profile>)>>) -> Vec<Vec<(K, Option<Profile>)>> {
    chains.sort_by_cached_key(|chain| {
        let first = chain.first().and_then(|(_, p)| p.as_ref());
        let wait = first.and_then(Endpoint::of).map(|e| budget().wait_for(&e));
        (wait.unwrap_or_default(), std::cmp::Reverse(chain.len()))
    });
    chains
}

#[cfg(test)]
mod tests;
