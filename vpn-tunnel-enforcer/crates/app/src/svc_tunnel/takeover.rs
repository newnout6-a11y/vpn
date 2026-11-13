//! Taking over a session the helper service kept (owner question 23: this app's window
//! crashed; p-follow: the service restarted and resumed it), and the re-attach after a lost
//! link that leads there (pfollow-a1: a held drop adopts the resumed run, nothing stops it
//! without the block while the kill switch's level holds).
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::ops::Source;
use vpnte_service::proto::KeptSession;
use vpnte_tunnel::api::StopOptions;
use vpnte_tunnel::lifecycle::{ConnError, ConnectTarget, Done, Lifecycle};

use super::remote;
use crate::svc_auto::Automation;

/// Decisions [`take_over`] makes before it stops a session nobody took over.
const TAKE_OVER_TRIES: u32 = 5;
/// The longest wait for an operation in flight before [`take_over`] decides again.
const TAKE_OVER_WAIT: Duration = Duration::from_secs(30);

/// A session the service kept (this app's window crashed, owner question 23; or a restarted
/// service brought it back) joins the lifecycle. A drop the lifecycle holds paused takes it as
/// that session's recovery (the pause ends as after an engine restart); otherwise the
/// lifecycle's own connect of the same upstream takes it over, so it shows as connected again
/// with its history and notices. An operation in flight decides first: it takes the parked
/// session over, replaces it with a protected restart or stops it. A connect that did not run
/// through (failed, cancelled) stops it here, and the kill switch keeps blocking while its level
/// holds: a lost take-over never sends programs around the VPN (pfollow-a1).
pub(super) async fn take_over<F, Fut>(
    remote: &remote::Remote,
    lifecycle: &Lifecycle,
    kept: KeptSession,
    connect: F,
) where
    F: Fn(ConnectTarget) -> Fut,
    Fut: Future<Output = Result<Done, ConnError>>,
{
    let Some(target) = target_of(remote, &kept) else {
        return;
    };
    for _ in 0..TAKE_OVER_TRIES {
        if lifecycle.busy() {
            let _ = tokio::time::timeout(TAKE_OVER_WAIT, lifecycle.idle()).await;
        }
        if remote.parked().is_none() {
            return;
        }
        if lifecycle.kill_switch().borrow().pause.is_some() {
            if !remote.adopt().await {
                tracing::info!("the resumed session ended before it joined the pause");
            }
            return;
        }
        match connect(target.clone()).await {
            Ok(_) => return,
            // Not admitted now (busy, paused meanwhile): look again.
            Err(ConnError::Refused(msg)) => {
                tracing::info!(error = %msg.key, "take-over not admitted yet");
            }
            // Cancelled (a stop, the user's «Отмена»), timed out or failed: no second try.
            Err(err) => {
                tracing::info!(error = %err.user_msg().key, "take-over did not run through");
                break;
            }
        }
    }
    // The operation that cancelled it (a stop) goes first; it may end the parked session itself.
    if lifecycle.busy() {
        let _ = tokio::time::timeout(TAKE_OVER_WAIT, lifecycle.idle()).await;
    }
    if remote.parked().is_none() {
        return;
    }
    let opts = StopOptions {
        preserve_protection: remote.holds(),
        preserve_last: false,
    };
    tracing::warn!(
        keep = opts.preserve_protection,
        "kept session not taken over: stopped"
    );
    let receipt = vpnte_tunnel::api::Runtime::stop(remote, opts).await;
    tracing::info!(ok = receipt.ok, "kept session stopped");
}

/// The lifecycle's connect of a kept session's upstream; `None` when it names none.
fn target_of(remote: &remote::Remote, kept: &KeptSession) -> Option<ConnectTarget> {
    match (&kept.server_id, kept.local_proxy) {
        (Some(id), _) => Some(ConnectTarget::DirectVpn {
            profile_id: Some(id.clone()),
        }),
        (None, Some(addr)) => Some(ConnectTarget::LocalProxy {
            addr: addr.to_string(),
            kind: (remote.parked().and_then(|s| s.proxy_type)).unwrap_or(ProxyKind::Socks5),
        }),
        (None, None) => None,
    }
}

/// The coordinator's start of a kept session (the adaptive bypass picks its mode as for any).
pub(super) async fn connect_kept(
    automation: &Automation,
    target: ConnectTarget,
) -> Result<Done, ConnError> {
    automation
        .coord
        .start(target, Owner::Manual, Source::Lifecycle)
        .await
}

/// A link to the helper service lost without the app asking (the service restarted; the session
/// shows as ended or paused meanwhile): the session the restarted service resumes is taken over
/// as at start-up, once per loss.
pub(super) async fn reattach(
    remote: &remote::Remote,
    lifecycle: &Lifecycle,
    automation: &Automation,
    mut losses: watch::Receiver<u64>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = losses.changed() => if changed.is_err() { return },
        }
        tracing::info!("helper service link lost: re-attaching");
        if let Some(kept) = remote.reattach().await {
            take_over(remote, lifecycle, kept, |t| connect_kept(automation, t)).await;
        }
    }
}
