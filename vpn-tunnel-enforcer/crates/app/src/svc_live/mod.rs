//! The live server check (`vpnte_probes::live`) in the app: its history at the data root (rows of
//! servers that are gone dropped at start), the FIFO runner over [`AppLiveEnv`], and its stop at
//! app exit (`LiveCheckService::shutdown`, called by the tunnel's exit cleanup). Nothing here
//! needs elevation: probe engines listen on loopback, stages use plain sockets and ICMP helpers.
mod env;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use vpnte_probes::live::{HistoryStore, LiveCheckService, LiveEnv};
use vpnte_servers::store::Servers;

pub(crate) use env::AppLiveEnv;

/// Opens the history under `root`, drops the rows of servers no longer in the list and starts
/// the runner. `None` (logged) when the runner cannot start: the Servers page then reports the
/// check as unavailable instead of pretending to run it.
pub fn start(
    env: Arc<dyn LiveEnv>,
    root: &Path,
    servers: &Servers,
) -> Option<Arc<LiveCheckService>> {
    let history = Arc::new(HistoryStore::open(root));
    // Archived rows still exist (and may be restored): only purged servers lose their history.
    let known: HashSet<String> =
        servers.read(|doc| doc.profiles.iter().map(|r| r.id.0.clone()).collect());
    if let Err(e) = history.prune(&known) {
        tracing::warn!(error = %e, "live-check history not pruned");
    }
    match LiveCheckService::new(env, history) {
        Ok(service) => Some(Arc::new(service)),
        Err(e) => {
            tracing::error!(error = %e, "live check not available");
            None
        }
    }
}
