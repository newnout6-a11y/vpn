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
use vpnte_base::AppResult;
use vpnte_profiles::model::Profile;

use super::{CONCURRENCY, KeyCheck, ProbeCtx, check_profile_verdict, unreadable};
use crate::discipline::{Endpoint, budget};

/// Longest list-wide check: one server name shared by many keys (a REALITY camouflage name) is
/// checked at 3 a minute, so a long list needs minutes; what is left at the end is not checked.
pub const LIST_DEADLINE: Duration = Duration::from_secs(20 * 60);

/// Checks every key of `items` (`None` = the row's profile is unreadable here: `no-outbound`
/// without a probe) until all are done, `until` passes or `stop` fires; probes in flight then are
/// dropped (not checked) and the finished results are kept. `on_result` sees each result as it
/// lands; the answer holds them in completion order.
pub async fn check_list<K: Send>(
    items: Vec<(K, Option<Profile>)>,
    ctx: &ProbeCtx,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
) -> Vec<(K, KeyCheck)> {
    let check = |p: Profile, cancel: CancellationToken| async move {
        check_profile_verdict(&p, ctx, &cancel).await
    };
    run_chains(items, until, stop, on_result, check).await
}

/// [`check_list`] with the probe given (test seam).
pub(crate) async fn run_chains<K, F, Fut>(
    items: Vec<(K, Option<Profile>)>,
    until: Instant,
    stop: &CancellationToken,
    on_result: impl Fn(&K, &KeyCheck) + Send + Sync,
    check: F,
) -> Vec<(K, KeyCheck)>
where
    K: Send,
    F: Fn(Profile, CancellationToken) -> Fut + Send + Sync,
    Fut: Future<Output = AppResult<KeyCheck>> + Send,
{
    let probes = Semaphore::new(CONCURRENCY);
    let done = Mutex::new(Vec::new());
    let chains = chains(items).into_iter().map(|chain| async {
        for (key, profile) in chain {
            let result = match profile {
                None => unreadable(),
                Some(p) => {
                    if let Some(endpoint) = Endpoint::of(&p) {
                        tokio::time::sleep(budget().wait_for(&endpoint)).await;
                    }
                    let Ok(_probe) = probes.acquire().await else {
                        return;
                    };
                    match check(p, stop.clone()).await {
                        Ok(result) => result,
                        Err(err) => {
                            tracing::debug!(error = %err, "list check: a chain ends unchecked");
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
    done.into_inner()
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

#[cfg(test)]
mod tests;
