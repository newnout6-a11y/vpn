//! External loopback proxy slots (`vpnte-proxies`) in the app: the manager over the server list,
//! the local control API on 127.0.0.1, the main-VPN stop hook and the stop at app exit (spec
//! external-proxy §3.28: the control API runs while the app runs; a VPN disconnect stops the
//! unleased slots; app exit stops every slot). Nothing here needs elevation: slots and the API
//! listen on loopback and the engines run as the user.
mod health;
mod source;
#[cfg(test)]
mod tests;

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use vpnte_proxies::control::{ControlConfig, ControlServer};
use vpnte_proxies::manager::{ProfileSource, ProxyManager, ProxySnapshot};
use vpnte_proxies::model::{ProxyOps, StopReason, StopScope};

pub(crate) use source::{ProbeCtxFn, ServerProfiles};

/// The slots as the UI uses them: the operations and the pushed state.
#[derive(Clone)]
pub struct ProxySlots {
    pub ops: Arc<dyn ProxyOps>,
    /// Readiness expires with the clock: render `ProxySnapshot::refreshed(now)`.
    pub state: watch::Receiver<ProxySnapshot>,
}

/// The running service: the manager and the task that owns the control server.
pub struct Proxies {
    manager: ProxyManager,
    /// Child of the app's shutdown token: ends the control server.
    cancel: CancellationToken,
    control: Mutex<Option<JoinHandle<Option<ControlServer>>>>,
}

impl Proxies {
    /// Builds the manager over `source` and starts the control server described by `config`
    /// under a child of `shutdown`. Call it inside the tokio runtime (the manager starts its
    /// lease-expiry timer there).
    pub fn start(
        source: Arc<dyn ProfileSource>,
        resources: &Path,
        config: ControlConfig,
        shutdown: &CancellationToken,
    ) -> Arc<Self> {
        let manager = ProxyManager::new(source, resources);
        let cancel = shutdown.child_token();
        let ops: Arc<dyn ProxyOps> = Arc::new(manager.clone());
        let token = cancel.clone();
        let control = tokio::spawn(async move {
            match ControlServer::start(ops, config, token).await {
                Ok(server) => {
                    tracing::info!(port = server.port(), "external-proxy control API listening");
                    Some(server)
                }
                // Only automation clients and the CLI lose the API; the slots work without it.
                Err(err) => {
                    tracing::warn!(error = %err, "external-proxy control API not started");
                    None
                }
            }
        });
        Arc::new(Self {
            manager,
            cancel,
            control: Mutex::new(Some(control)),
        })
    }

    /// Operations and state for the UI.
    pub fn slots(&self) -> ProxySlots {
        ProxySlots {
            ops: Arc::new(self.manager.clone()),
            state: self.manager.snapshot(),
        }
    }

    /// The main VPN stopped: every slot without a lease stops, leased slots keep serving.
    pub async fn vpn_stopped(&self) {
        self.manager
            .stop_all(StopScope::Unleased, StopReason::VpnStop)
            .await;
    }

    /// App exit: every slot stops (leases notwithstanding) and the control server closes.
    /// Idempotent.
    pub async fn shutdown(&self) {
        self.manager.shutdown().await;
        self.cancel.cancel();
        let control = self.control.lock().take();
        if let Some(task) = control
            && let Ok(Some(server)) = task.await
        {
            server.join().await;
        }
    }
}
