//! Starting the kept session again with no client (ks-d, research killswitch §5.3, §5.4): after
//! the service's own crash while a drop was held (its static block is still there), and at each
//! start of the service while "Always" is in force (connect at Windows start). The session then
//! waits for its user's app to take it over, like one kept after the app's window crashed.
use std::net::SocketAddr;
use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use super::requests::start_request;
use super::{Host, memory};
use crate::pipe::ClientInfo;
use crate::proto::{AdaptiveRestart, TunnelStart, Upstream};
use crate::validate;

/// The take-over key of a start: `(server id, local proxy)`.
pub(super) fn upstream_of(start: &TunnelStart) -> (Option<String>, Option<SocketAddr>) {
    match &start.upstream {
        Upstream::Server(server) => (Some(server.id.clone()), None),
        Upstream::LocalProxy { addr, .. } => (None, Some(*addr)),
    }
}

impl Host {
    /// Keeps each started session in `path` (the service's private folder) for
    /// [`Host::resume`]. Not called: nothing is kept (tests, the idle example).
    pub fn keep_sessions_in(&self, path: PathBuf) {
        if self.memory.set(path).is_err() {
            tracing::warn!("session memory set twice; the first one stays");
        }
    }

    /// `client` started `start`: kept for a resume.
    pub(super) fn remember(&self, client: &ClientInfo, start: &TunnelStart) {
        if let Some(path) = self.memory.get() {
            let mut start = start.clone();
            if let Upstream::Server(server) = &mut start.upstream {
                // One-request facts never outlive their request (speed3 H2).
                server.without_facts();
            }
            let session = memory::Remembered {
                user: client.user.clone(),
                start,
            };
            memory::save(path, &session);
        }
    }

    /// An adaptive restart moved `client`'s session (another mode, maybe a sibling server): the
    /// take-over key and the remembered start follow it, so a resume brings back what runs now
    /// and the app's take-over names that server (fixfollow-b1).
    pub(super) fn follow_adaptive(&self, client: &ClientInfo, restart: &AdaptiveRestart) {
        if self.session_user.lock().as_deref() != Some(client.user.as_str()) {
            return;
        }
        if let Some(server) = &restart.server {
            *self.upstream.lock() = Some((Some(server.id.clone()), None));
        }
        let Some(path) = self.memory.get() else {
            return;
        };
        let Some(mut kept) = memory::load(path).filter(|k| k.user == client.user) else {
            return;
        };
        kept.start.adaptive = restart.mode;
        if let Some(server) = &restart.server {
            let mut server = server.clone();
            server.without_facts();
            kept.start.upstream = Upstream::Server(Box::new(server));
        }
        memory::save(path, &kept);
    }

    /// Drops the kept session: `user`'s only (he leaves; its upstream key is his), or with
    /// `None` whoever's (another user took the machine, the last user left).
    pub(super) fn forget_session(&self, user: Option<&str>) {
        let Some(path) = self.memory.get() else {
            return;
        };
        if user.is_none_or(|u| memory::load(path).is_some_and(|kept| kept.user == u)) {
            memory::forget(path);
        }
    }

    /// Starts the kept session again for its user's app to take over; `false` when there is
    /// none, the tunnel is refused here, or the start failed or was cancelled (the runtime then
    /// released its capture, a held block included). `cancel`: the service is stopping.
    pub async fn resume(&self, cancel: CancellationToken) -> bool {
        let Some(kept) = self.memory.get().and_then(|path| memory::load(path)) else {
            return false;
        };
        if self.deps.refuse_tunnel.is_some() {
            return false;
        }
        if let Err(e) = validate::start(&kept.start) {
            tracing::warn!(error = %e, "the last session is no longer accepted");
            return false;
        }
        let level = self.deps.kill_switch.level();
        {
            let _state = self.state.lock().await;
            self.deps.inputs.set(&kept.start.routing, level, &kept.user);
        }
        *self.session_user.lock() = Some(kept.user.clone());
        *self.upstream.lock() = Some(upstream_of(&kept.start));
        let req = start_request(&kept.start, level);
        match self.deps.runtime.start(req, cancel).await {
            Ok(_) => {
                tracing::info!("the last session started again");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "the last session did not start again");
                false
            }
        }
    }
}
