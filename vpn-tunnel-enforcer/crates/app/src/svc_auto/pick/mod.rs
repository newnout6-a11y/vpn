//! The automatic server choice in the product (work package `w7-autopick`, RU research items 7
//! and 8): the automation crate's [`AutoPick`] over the server list, the probes, the tunnel and
//! the check-verdict reactions. Started once the backend is complete (it needs the tunnel's
//! probe context and counters); its launch run waits for the scheduler's first pass, which
//! itself follows the start-up recovery.
mod confirm;
mod host;
mod meter;
mod provide;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use vpnte_automation::autopick::{AutoPick, AutoPickConfig, Launched};
use vpnte_core::store::Store;

pub use host::AutoHost;
pub use provide::traffic_exposure;

use super::{AppCoordinator, Automation};
use crate::services::Backend;

pub type AppPick = AutoPick<AppCoordinator, AutoHost>;

/// Builds the automatic choice, hands it to `automation.autopick` and starts its tasks under
/// the backend's shutdown token.
pub fn spawn_autopick(backend: &Arc<Backend>, automation: &Arc<Automation>) {
    let host = Arc::new(AutoHost::new(backend.clone(), automation));
    let config = Arc::new(Store::<AutoPickConfig>::open(&backend.dirs.root));
    let pick = Arc::new(AutoPick::new(
        automation.coord.clone(),
        host,
        config,
        Some(automation.scheduler.status()),
    ));
    if automation.autopick.set(pick.clone()).is_err() {
        tracing::warn!("automatic server choice started twice; the second one is dropped");
        return;
    }
    let cancel = backend.shutdown.child_token();
    tokio::spawn({
        let (pick, cancel) = (pick.clone(), cancel.clone());
        async move { pick.run(cancel).await }
    });
    tokio::spawn(async move {
        let outcome = match pick.launch(cancel).await {
            Launched::Skipped => "skipped",
            Launched::UserFirst => "the user acted first",
            Launched::Connected { .. } => "connected",
            Launched::Failed { .. } => "failed",
        };
        tracing::info!(outcome, "launch connect");
    });
}
