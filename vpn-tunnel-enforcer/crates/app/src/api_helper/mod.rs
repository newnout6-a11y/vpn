//! The capability view (p-noadmin-ui): what the helper service and this process's rights allow,
//! one watch for every page — published at start, after an install from the app and whenever
//! the service's version becomes known (a link to it). The facts come from the tunnel (the
//! service's registration as the tunnel uses it, the protocol of its link, Tunnel mode here) and
//! the process; the derivation is pure ([`derive`]). The real service is reached only through
//! `boot::service` (its gate keeps tests away from a service installed on this PC).
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::AppResult;
use vpnte_service::proto::{PROTOCOL, SCOPE_PROTOCOL};
use vpnte_ui::helper::{Ability, Capability, HelperApi, Lack, Service};

use crate::services::Backend;
use crate::support::{blocking, changed_opt, detached};

#[cfg(test)]
mod tests;

/// No event says when the service's version becomes known (the start-up attach, a re-link
/// after the service restarted to update itself): while one may be due the view is re-read this
/// often, for at most [`LINK_WAIT`] (the re-link after a restart takes up to about 40 s).
const POLL: Duration = Duration::from_secs(2);
const LINK_WAIT: Duration = Duration::from_secs(60);

/// What the view is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Facts {
    /// The service is registered, as the tunnel uses it.
    pub installed: bool,
    /// The protocol of its last link; `None` before the first one.
    pub protocol: Option<u32>,
    /// This process runs elevated (development, CI).
    pub elevated: bool,
    /// Tunnel mode can run here: through the service, or in this elevated process.
    pub tun: bool,
}

impl Facts {
    /// The facts right now (atomics and the guard's flags: cheap, never blocking).
    pub(crate) fn now(backend: &Backend) -> Self {
        let tunnel = backend.tunnel().ok();
        Self {
            installed: tunnel.is_some_and(|t| t.service_present()),
            protocol: tunnel.and_then(|t| t.service_protocol()),
            elevated: backend.elevated,
            tun: tunnel.is_some_and(|t| t.tun_available()),
        }
    }
}

/// The view of `facts` in this build: the service carries Tunnel mode and the WFP kill switch;
/// browser policies run in an elevated app only (the service has no registry primitive yet);
/// packet capture is not built.
pub(crate) fn derive(f: Facts) -> Capability {
    let service = match (f.installed, f.protocol) {
        (false, _) => Service::Missing,
        (true, Some(p)) if p < PROTOCOL => Service::Older { lacks: lacks(p) },
        (true, _) => Service::Installed,
    };
    // One owner of the TUN and our WFP objects: the service when it is installed, also when
    // this process happens to be elevated (the guard's rule).
    let privileged = if f.installed {
        Ability::Service
    } else if f.tun {
        Ability::InProcess
    } else {
        Ability::NeedsService
    };
    Capability {
        service,
        elevated: f.elevated,
        tunnel: privileged,
        kill_switch: privileged,
        policies: if f.elevated {
            Ability::InProcess
        } else {
            Ability::NotInVersion
        },
        capture: Ability::NotInVersion,
    }
}

/// What a service speaking `protocol` does not do yet, as the user would notice it.
fn lacks(protocol: u32) -> Vec<Lack> {
    let mut lacks = Vec::new();
    if protocol < SCOPE_PROTOCOL {
        lacks.push(Lack::AppScope);
    }
    lacks
}

/// The capability view right now (the pages that read it at an action, not live).
pub(crate) fn capability_now(backend: &Backend) -> Capability {
    derive(Facts::now(backend))
}

/// [`HelperApi`] over the backend: the one capability view and the service's install.
#[derive(Clone)]
pub struct HelperService(Arc<Shared>);

struct Shared {
    backend: Arc<Backend>,
    state: watch::Sender<Capability>,
}

impl Shared {
    /// Re-derives the view and publishes it when it differs.
    fn refresh(&self) {
        let next = capability_now(&self.backend);
        self.state.send_if_modified(|cap| {
            let changed = *cap != next;
            *cap = next;
            changed
        });
    }
}

impl HelperService {
    /// Publishes the first view at once and starts the task that keeps it current until
    /// `backend.shutdown`.
    pub fn start(backend: Arc<Backend>) -> Self {
        let state = watch::Sender::new(capability_now(&backend));
        let shared = Arc::new(Shared { backend, state });
        tokio::spawn(follow(shared.clone()));
        Self(shared)
    }

    /// A receiver of the view (the Settings projection follows it).
    pub fn subscribe(&self) -> watch::Receiver<Capability> {
        self.0.state.subscribe()
    }
}

#[async_trait(?Send)]
impl HelperApi for HelperService {
    fn capability(&self) -> watch::Receiver<Capability> {
        self.0.state.subscribe()
    }

    async fn install_service(&self) -> AppResult<bool> {
        let shared = self.0.clone();
        // A backend task: leaving the page while Windows asks never loses the outcome.
        detached(async move {
            // The one elevated step the app may ask for: Windows runs the service's own install
            // verb after its prompt (owner decision 12.11.2026).
            let installed = blocking(crate::boot::service::request_install).await?;
            let tunnel = shared.backend.tunnel().ok().cloned();
            let ready = installed && tunnel.is_some_and(|t| t.service_installed());
            shared.refresh();
            Ok(ready)
        })
        .await
    }
}

/// Keeps the view current: at every change of the session and of the link to the service, and
/// in the windows where the service's version may become known with no event of its own.
async fn follow(shared: Arc<Shared>) {
    let tunnel = shared.backend.tunnel().ok().cloned();
    let mut snapshot = tunnel.as_ref().map(|t| t.snapshot());
    let mut status = tunnel.as_ref().map(|t| t.runtime_status());
    let mut losses = tunnel.as_ref().and_then(|t| t.service_losses());
    let shutdown = shared.backend.shutdown.clone();
    // From the start: the start-up attach links to an installed service.
    let mut window = Duration::ZERO;
    loop {
        shared.refresh();
        let polling = window < LINK_WAIT && shared.state.borrow().service != Service::Missing;
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = changed_opt(&mut snapshot) => {}
            () = changed_opt(&mut status) => {}
            () = changed_opt(&mut losses) => window = Duration::ZERO,
            () = tokio::time::sleep(POLL), if polling => window += POLL,
        }
    }
}
