//! The list-wide check (RU-2026 item 6): every key of the server list through its own server,
//! under the handshake budget. Keys are chained per endpoint, one probe at a time in list order,
//! and a chain waits out its endpoint's budget (3 handshakes a minute, the 130 s quiet time after
//! a freeze) before it takes one of the [`CONCURRENCY`] probes: a busy or frozen server name holds
//! back only its own chain while the other chains use the free probes. A key that cannot be
//! checked (deferred, the probe did not start) ends its chain: the rest would knock again.
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult};
use vpnte_profiles::model::Profile;

use super::{CONCURRENCY, KeyCheck, ProbeCtx, check_profile_verdict, unreadable};
use crate::discipline::{Endpoint, budget};

/// Longest list-wide check: one server name shared by many keys (a REALITY camouflage name) is
/// checked at 3 a minute, so a long list needs minutes; what is left at the end is not checked.
pub const LIST_DEADLINE: Duration = Duration::from_secs(20 * 60);

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
/// dropped (not checked) and the finished results are kept. All groups run at once behind the
/// one probe limit, so a slow name in one group never starves another (psmall-a1/b5).
/// `on_result` sees each result as it lands; `on_wait` hears of each key whose check waits for
/// its server name's handshake budget (how long), before the wait (lab live-9 L9-7: the page
/// says so instead of a silent minute).
pub async fn check_list<K: Send>(
    groups: Vec<ListGroup<K>>,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
    on_wait: impl Fn(&K, Duration) + Send + Sync,
) -> ListOutcome<K> {
    let mut ctxs = Vec::with_capacity(groups.len());
    let mut items = Vec::new();
    for (ctx, keys) in groups {
        let group = ctxs.len();
        ctxs.push(ctx);
        items.extend(keys.into_iter().map(|(key, p)| ((key, group), p)));
    }
    let ctxs = &ctxs;
    let check = |(_, group): &(K, usize), p: Profile, cancel: CancellationToken| {
        let ctx = &ctxs[*group];
        async move { check_profile_verdict(&p, ctx, &cancel).await }
    };
    let report = |(key, _): &(K, usize), check: &KeyCheck| on_result(key, check);
    let wait = |(key, _): &(K, usize), wait: Duration| on_wait(key, wait);
    let (done, unchecked) = run_chains(items, until, stop, report, wait, check).await;
    let done = done.into_iter().map(|((key, _), c)| (key, c)).collect();
    ListOutcome { done, unchecked }
}

/// [`check_list`] with the probe given (test seam): the results and the first probe error.
pub(crate) async fn run_chains<K, F, Fut>(
    items: Vec<(K, Option<Profile>)>,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
    on_wait: impl Fn(&K, Duration) + Send + Sync,
    check: F,
) -> (Vec<(K, KeyCheck)>, Option<AppError>)
where
    K: Send,
    F: Fn(&K, Profile, CancellationToken) -> Fut + Send + Sync,
    Fut: Future<Output = AppResult<KeyCheck>> + Send,
{
    let probes = Semaphore::new(CONCURRENCY);
    let done = Mutex::new(Vec::new());
    let first_error = Mutex::new(None);
    let chains = by_readiness(chains(items)).into_iter().map(|chain| async {
        let mut chain = chain.into_iter();
        while let Some((key, profile)) = chain.next() {
            let result = match profile {
                None => unreadable(),
                Some(p) => {
                    if let Some(endpoint) = Endpoint::of(&p) {
                        let wait = budget().wait_for(&endpoint);
                        if !wait.is_zero() {
                            // The keys behind it in the chain wait for the same budget.
                            on_wait(&key, wait);
                            chain.as_slice().iter().for_each(|(k, _)| on_wait(k, wait));
                        }
                        tokio::time::sleep(wait).await;
                    }
                    let Ok(_probe) = probes.acquire().await else {
                        return;
                    };
                    match check(&key, p, stop.clone()).await {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::warn!(error = %err, "list check: a chain ends unchecked");
                            first_error.lock().get_or_insert(err);
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
