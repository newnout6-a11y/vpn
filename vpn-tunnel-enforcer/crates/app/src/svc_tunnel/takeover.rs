//! Taking over a session the helper service kept (owner question 23: this app's window
//! crashed; p-follow: the service restarted and resumed it), and the re-attach after a lost
//! link that leads there (pfollow-a1: a held drop adopts the resumed run, nothing stops it
//! without the block while the kill switch's level holds; fixfollow-a1: a held drop the
//! restarted service did not bring back ends as a drop, not as a pause that blocks nothing).
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::ops::Source;
use vpnte_service::proto::KeptSession;
use vpnte_tunnel::lifecycle::{
    ConnError, ConnectTarget, DisconnectReq, Done, Lifecycle, StopCause,
};

use super::remote::{self, Split};
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
/// through (failed, cancelled) ends it through the lifecycle ([`end_kept`]).
pub(super) async fn take_over<F, Fut>(
    split: &Split,
    lifecycle: &Lifecycle,
    kept: KeptSession,
    connect: F,
) where
    F: Fn(ConnectTarget) -> Fut,
    Fut: Future<Output = Result<Done, ConnError>>,
{
    let remote = split.remote();
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
            return rejoin(remote, lifecycle, &kept).await;
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
    end_kept(split, lifecycle).await;
}

/// The resumed run joins the paused session as its recovery. A run of another server than the
/// paused session's (the service remembered the server before an adaptive restart moved the
/// session to a sibling) is moved there at once by a protected restart in the session's mode,
/// the block held in between, so the screen never names a server that does not run
/// (fixfollow-b1).
async fn rejoin(remote: &remote::Remote, lifecycle: &Lifecycle, kept: &KeptSession) {
    let paused = lifecycle.session().borrow().clone();
    if !remote.adopt().await {
        tracing::info!("the resumed session ended before it joined the pause");
        return;
    }
    let Some(session) = paused else {
        return;
    };
    let Some(id) = session.server_id().map(str::to_owned) else {
        return;
    };
    if kept.server_id.as_deref().is_none_or(|kept| kept == id) {
        return;
    }
    tracing::warn!("the resumed run is another server than the paused session's: moving it");
    // The adopted run's events reach the lifecycle on their own task: a restart is admitted
    // once it reads connected again.
    let mut snapshot = lifecycle.snapshot();
    let connected = snapshot.wait_for(|s| s.state == vpnte_tunnel::fsm::TunnelState::Connected);
    let _ = tokio::time::timeout(TAKE_OVER_WAIT, connected).await;
    let moved = lifecycle
        .restart_adaptive(session.adaptive, Some(id), Owner::Recovery)
        .await;
    if let Err(err) = moved {
        tracing::warn!(error = %err.user_msg().key, "the resumed run was not moved");
    }
}

/// Ends a kept session no take-over could run through (fixfollow-a2). The stop goes through the
/// lifecycle, so its state follows: while the kill switch's level holds, the block stays and
/// reads `blocked` (the user sees it and ends it with a connect or a disconnect); with the kill
/// switch off it is a plain full stop. A stop past the lifecycle would leave the service's
/// runtime holding a block the screen never shows, or the lifecycle stuck in «reconnecting».
async fn end_kept(split: &Split, lifecycle: &Lifecycle) {
    split.remote().reveal_parked();
    split.drive_service();
    let mut req = DisconnectReq::new(StopCause::Failed, Owner::Manual, Source::Lifecycle);
    req.keep_protection = true;
    match lifecycle.disconnect(req).await {
        Ok(_) => tracing::warn!("kept session not taken over: stopped"),
        Err(err) => tracing::warn!(error = %err.user_msg().key, "kept session stop failed"),
    }
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
    split: &Split,
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
        after_loss(split, lifecycle, |t| connect_kept(automation, t)).await;
    }
}

/// One re-attach: the resumed session is taken over; none came back while a drop is held
/// paused, the pause is checked against what the service still holds ([`end_lost_pause`]).
pub(super) async fn after_loss<F, Fut>(split: &Split, lifecycle: &Lifecycle, connect: F)
where
    F: Fn(ConnectTarget) -> Fut,
    Fut: Future<Output = Result<Done, ConnError>>,
{
    match split.remote().reattach().await {
        Some(kept) => take_over(split, lifecycle, kept, connect).await,
        None => end_lost_pause(split.remote(), lifecycle).await,
    }
}

/// fixfollow-a1: the restarted service brought no session back (its resume failed, or there
/// was nothing to resume) while the lifecycle holds a drop paused. When the service holds
/// neither a run nor a block any more, the paused run is over: the lifecycle hears it as a stop,
/// so the pause ends with its notice instead of showing «Интернет на паузе» while programs go
/// direct. A block the service still holds (a resume still starting, «Всегда») keeps the pause:
/// its outcome arrives as events.
async fn end_lost_pause(remote: &remote::Remote, lifecycle: &Lifecycle) {
    if lifecycle.kill_switch().borrow().pause.is_none() || lifecycle.busy() {
        return;
    }
    if remote.holds_run().await {
        return;
    }
    tracing::warn!("the restarted service holds nothing of the paused session: it ended");
    remote.announce_stopped();
}
