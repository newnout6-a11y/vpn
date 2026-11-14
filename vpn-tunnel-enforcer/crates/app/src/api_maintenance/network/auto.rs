//! The automatic network checks: once after start, then after each change of the physical
//! network (queued behind a running check, never refused), and the resolver memory kept on the
//! current network.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::identity;
use vpnte_base::types::now_ms;
use vpnte_core::resolve;
use vpnte_winnet::adapters::{self, NetChange};

use super::super::Shared;
use super::{Flight, Scope, network_changed, run};

/// The automatic check waits this long after start: the autoconnect goes first.
const START_DELAY: Duration = Duration::from_secs(30);
/// And this long after a network change: addresses and routes settle.
const CHANGE_DELAY: Duration = Duration::from_secs(5);
/// Debounce of the network-change watch.
const NET_SETTLE: Duration = Duration::from_millis(1500);

/// Starts the automatic checks (once after start, then after each physical network change),
/// keeps the resolver memory on the current network and the running session's server name
/// kept for the session; ends with the app.
pub(crate) fn spawn(shared: &Arc<Shared>) {
    let cancel = shared.backend.shutdown.child_token();
    tokio::spawn(super::session::follow(shared.clone(), cancel.clone()));
    tokio::spawn(watch_network(shared.clone(), cancel));
}

async fn watch_network(shared: Arc<Shared>, cancel: CancellationToken) {
    let mut changes = adapters::watch_network(NET_SETTLE, cancel.clone())
        .inspect_err(
            |err| tracing::warn!(%err, "no network-change watch: network checked at start only"),
        )
        .ok();
    let mut network = identity::read().await;
    resolve::set_network(network_key().await, now_ms());
    // Its own task: the identity reads below never pause a check in flight.
    let mut auto = tokio::spawn(automatic(shared.clone(), START_DELAY, cancel.clone()));
    loop {
        let change = tokio::select! {
            () = cancel.cancelled() => break,
            change = next_change(&mut changes) => change,
        };
        if change.is_none() {
            changes = None;
            continue;
        }
        // The debounce reports a burst after its last event: the network moved then.
        let moved = now_ms().saturating_sub(settle_ms());
        // Our own TUN coming and going changes the adapter list too: only another physical
        // network (gateway, adapter) counts.
        let now = identity::read().await;
        if now.is_some() && now == network {
            continue;
        }
        network = now;
        resolve::set_network(network_key().await, moved);
        network_changed(&shared.epoch, &shared.state);
        // An automatic check of the old network, waiting or running, goes with it.
        auto.abort();
        auto = tokio::spawn(automatic(shared.clone(), CHANGE_DELAY, cancel.clone()));
    }
    auto.abort();
}

fn settle_ms() -> i64 {
    i64::try_from(NET_SETTLE.as_millis()).unwrap_or(0)
}

async fn next_change(changes: &mut Option<mpsc::Receiver<NetChange>>) -> Option<NetChange> {
    match changes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// The automatic check after `delay`. It waits for a running check to end (queued, never
/// refused) and runs unless a check of this network finished meanwhile (the button).
async fn automatic(shared: Arc<Shared>, delay: Duration, cancel: CancellationToken) {
    if !pause(delay, &cancel).await {
        return;
    }
    let Some(flight) = Flight::queued(&shared.state, &cancel).await else {
        return;
    };
    // A change clears `last`, so a result here is this network's own.
    if shared.state.borrow().network.last.is_some() {
        return;
    }
    match run(&shared, flight, Scope::Automatic, cancel.child_token()).await {
        Ok(view) => tracing::info!(modes = ?view.modes, "network check finished"),
        Err(err) => tracing::info!(error = %err, "automatic network check gave no result"),
    }
}

/// Sleeps `span`; false when the app is quitting.
async fn pause(span: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = cancel.cancelled() => false,
        () = tokio::time::sleep(span) => true,
    }
}

/// A stable name of the physical network for the resolver memory (`None` when nothing is up).
async fn network_key() -> Option<String> {
    tokio::task::spawn_blocking(network_key_now)
        .await
        .ok()
        .flatten()
}

/// [`network_key`] now (blocking: one adapter-table walk, 7-20 ms): the up physical adapters
/// with a gateway, by adapter id and gateways. Two networks behind the same adapter and gateway
/// address read as one: acceptable for a resolver preference.
pub(crate) fn network_key_now() -> Option<String> {
    let adapters = adapters::physical_adapters().ok()?;
    let mut parts: Vec<String> = adapters
        .iter()
        .filter(|a| a.is_up() && !a.gateways.is_empty())
        .map(|a| {
            let gateways: Vec<String> = a.gateways.iter().map(ToString::to_string).collect();
            format!("{:?}|{}", a.guid, gateways.join(","))
        })
        .collect();
    parts.sort();
    (!parts.is_empty()).then(|| parts.join(";"))
}
