//! The running session's server name for the resolver (lab F11, p-follow3): resolved once per
//! session start over the direct chain and kept for the session (`resolve::keep_for_session`), so
//! the app's own lookups of it (pings, key checks, the server detail, a restart's pin in this
//! process) never leave the PC as clear-text DNS past the tunnel.
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::UnixMs;
use vpnte_core::resolve;
use vpnte_tunnel::api::{ModeKind, TunStatus};

use super::super::Shared;
use crate::svc_tunnel::scope::run_start;

/// What the resolver keeps for `status`: the session's start and its server's host (`None`:
/// nothing runs, or the upstream is a local proxy, which has no server name of ours).
pub(super) fn session_key(
    status: &TunStatus,
    host: impl FnOnce() -> Option<String>,
) -> Option<(UnixMs, String)> {
    let started = run_start(status)?;
    let host = (status.mode == Some(ModeKind::DirectVpn))
        .then(host)
        .flatten()?;
    Some((started, host))
}

/// Keeps the resolver on the running session's server until the app closes.
pub(super) async fn follow(shared: Arc<Shared>, cancel: CancellationToken) {
    let Ok(tunnel) = shared.backend.tunnel().cloned() else {
        return;
    };
    let mut status = tunnel.runtime_status();
    let active_host = || shared.backend.servers.active().map(|a| a.row.server);
    let mut held: Option<(UnixMs, String)> = None;
    loop {
        let key = session_key(&status.borrow_and_update(), active_host);
        if key != held {
            match &key {
                Some((started, host)) => {
                    resolve::keep_for_session(*started, std::slice::from_ref(host)).await;
                }
                None => resolve::end_session(),
            }
            held = key;
        }
        tokio::select! {
            () = cancel.cancelled() => break,
            changed = status.changed() => if changed.is_err() { break },
        }
    }
    resolve::end_session();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lab F11 (p-follow3): a running server session keeps its server's host for the resolver,
    /// from the session's start; nothing runs, or a local proxy upstream, keeps nothing.
    #[test]
    fn the_session_keeps_its_servers_name() {
        let host = || Some("vpn.example".to_owned());
        let mut status = TunStatus {
            running: true,
            started_at: Some(1_000),
            mode: Some(ModeKind::DirectVpn),
            ..TunStatus::default()
        };
        assert_eq!(
            session_key(&status, host),
            Some((1_000, "vpn.example".to_owned()))
        );
        status.mode = Some(ModeKind::LocalProxy);
        assert_eq!(session_key(&status, host), None);
        status.mode = Some(ModeKind::DirectVpn);
        status.running = false;
        assert_eq!(session_key(&status, host), None);
    }
}
