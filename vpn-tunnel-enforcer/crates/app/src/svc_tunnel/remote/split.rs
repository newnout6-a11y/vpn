//! One runtime for the lifecycle over two hosts: Tunnel mode in the helper service ([`Remote`],
//! while it is installed), proxy mode — and an elevated app's own Tunnel mode — in this process.
//! The lifecycle's contract holds across both: one status and one event stream from the host it
//! drives now, generations that keep increasing when the host changes, the status before its
//! event, and every event of an operation out before the call returns (a flush through the
//! forwarder after each call).
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, KillSwitchLevel, OutboundFault};
use vpnte_tunnel::api::{
    CaptureKind, ExitInfo, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest,
    StopOptions, StopReceipt, SwitchReceipt, TunError, TunStatus, TunnelEvent, VpnProfile,
};

use super::Remote;
use super::gens::Gens;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Host {
    Local,
    Service,
}

/// The lifecycle's runtime.
#[derive(Clone)]
pub(in crate::svc_tunnel) struct Split(Arc<Inner>);

struct Inner {
    local: Arc<dyn Runtime>,
    remote: Remote,
    /// The host the lifecycle drives now and the generations handed out so far.
    active: Mutex<(Host, Gens)>,
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    flush: mpsc::Sender<oneshot::Sender<()>>,
}

impl Split {
    pub(in crate::svc_tunnel) fn spawn(
        local: Arc<dyn Runtime>,
        remote: Remote,
        cancel: CancellationToken,
    ) -> Self {
        let (flush, flushes) = mpsc::channel(8);
        let status = watch::channel(local.status().borrow().clone()).0;
        let inner = Arc::new(Inner {
            local,
            remote,
            active: Mutex::new((Host::Local, Gens::default())),
            status,
            events: broadcast::channel(256).0,
            flush,
        });
        // Subscribed here, before any call can run: nothing a host sends is missed.
        let sources = [
            (Host::Local, inner.local.subscribe(), inner.local.status()),
            (
                Host::Service,
                inner.remote.subscribe(),
                inner.remote.status(),
            ),
        ];
        tokio::spawn(forward(inner.clone(), sources, flushes, cancel));
        Self(inner)
    }

    pub(in crate::svc_tunnel) fn remote(&self) -> &Remote {
        &self.0.remote
    }

    /// The lifecycle drives the helper service from now on: its stop of a session the service
    /// kept must reach the service, also when the connect that failed never got there.
    pub(in crate::svc_tunnel) fn drive_service(&self) {
        self.activate(Host::Service);
        // At once, not through the forwarder: the lifecycle's next stop reads it.
        let now = self.0.remote.status().borrow().clone();
        self.0.status.send_replace(now);
    }

    /// Where a start of `capture` runs: Tunnel mode in the service while it is installed.
    fn host_for(&self, capture: CaptureKind) -> Host {
        match capture {
            CaptureKind::Tun if self.0.remote.installed() => Host::Service,
            _ => Host::Local,
        }
    }

    fn runtime(&self, host: Host) -> &dyn Runtime {
        match host {
            Host::Local => self.0.local.as_ref(),
            Host::Service => &self.0.remote,
        }
    }

    fn active(&self) -> &dyn Runtime {
        self.runtime(self.0.active.lock().0)
    }

    /// The lifecycle drives `host` from now on.
    fn activate(&self, host: Host) -> &dyn Runtime {
        let mut active = self.0.active.lock();
        if active.0 != host {
            tracing::info!(?host, "tunnel host changed");
            active.0 = host;
            active.1.relink();
            self.0
                .status
                .send_replace(self.runtime(host).status().borrow().clone());
        }
        self.runtime(host)
    }

    /// Returns once the forwarder passed on every event the hosts sent so far.
    async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.0.flush.send(tx).await.is_ok() {
            let _ = rx.await;
        }
    }

    fn receipt(&self, mut receipt: StartReceipt) -> StartReceipt {
        receipt.generation = self.0.active.lock().1.native(receipt.generation);
        receipt
    }
}

/// Mirrors the active host's status and events into the split's own.
/// A host's event stream and status watch, as the forwarder follows them.
type Source = (
    Host,
    broadcast::Receiver<TunnelEvent>,
    watch::Receiver<TunStatus>,
);

async fn forward(
    inner: Arc<Inner>,
    mut events: [Source; 2],
    mut flushes: mpsc::Receiver<oneshot::Sender<()>>,
    cancel: CancellationToken,
) {
    loop {
        let [(_, local, local_status), (_, remote, remote_status)] = &mut events;
        tokio::select! {
            biased;
            () = cancel.cancelled() => return,
            // A host whose stream closed is gone (its actor ended): nothing more to mirror.
            e = local.recv() => if !inner.pass(Host::Local, e, local_status) { return },
            e = remote.recv() => if !inner.pass(Host::Service, e, remote_status) { return },
            Ok(()) = local_status.changed() => inner.mirror(Host::Local, local_status),
            Ok(()) = remote_status.changed() => inner.mirror(Host::Service, remote_status),
            Some(ack) = flushes.recv() => {
                // Everything sent before the flush was asked for is queued here: pass it first.
                for (host, rx, status) in &mut events {
                    loop {
                        let e = match rx.try_recv() {
                            Ok(e) => Ok(e),
                            Err(TryRecvError::Lagged(n)) => Err(RecvError::Lagged(n)),
                            Err(_) => break,
                        };
                        inner.pass(*host, e, status);
                    }
                }
                let _ = ack.send(());
            }
        }
    }
}

impl Inner {
    fn is_active(&self, host: Host) -> bool {
        self.active.lock().0 == host
    }

    fn mirror(&self, host: Host, status: &mut watch::Receiver<TunStatus>) {
        let now = status.borrow_and_update().clone();
        if self.is_active(host) {
            self.status.send_replace(now);
        }
    }

    /// Passes one event of `host` on when it is the active one; `false` when its stream closed.
    fn pass(
        &self,
        host: Host,
        event: Result<TunnelEvent, RecvError>,
        status: &mut watch::Receiver<TunStatus>,
    ) -> bool {
        if matches!(event, Err(RecvError::Closed)) {
            return false;
        }
        if !self.is_active(host) {
            return true;
        }
        // The status first: the host changed it before this event.
        if status.has_changed().unwrap_or(false) {
            self.mirror(host, status);
        }
        match event {
            Ok(e) => {
                let e = self.active.lock().1.event(e);
                let _ = self.events.send(e);
            }
            // The lifecycle resyncs from the status, sent again.
            Err(_) => self.mirror(host, status),
        }
        true
    }
}

#[async_trait]
impl Runtime for Split {
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        let host = self.host_for(req.capture);
        let started = self.activate(host).start(req, cancel).await;
        self.flush().await;
        started.map(|r| self.receipt(r))
    }

    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        let receipt = self.active().stop(opts).await;
        self.flush().await;
        receipt
    }

    async fn restart_protected(
        &self,
        reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        let host = self.host_for(next.capture);
        let started = self
            .activate(host)
            .restart_protected(reason, next, opts)
            .await;
        self.flush().await;
        started.map(|r| self.receipt(r))
    }

    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError> {
        let started = self.active().restart_with_last(reason).await;
        self.flush().await;
        started.map(|r| r.map(|r| self.receipt(r)))
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        let started = self.active().restart_adaptive(mode, reason, profile).await;
        self.flush().await;
        started.map(|r| self.receipt(r))
    }

    async fn switch_upstream(
        &self,
        next: StartRequest,
        cancel: CancellationToken,
        is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        let switched = self.active().switch_upstream(next, cancel, is_owner).await;
        self.flush().await;
        switched
    }

    async fn retry_now(&self) -> bool {
        let retried = self.active().retry_now().await;
        self.flush().await;
        retried
    }

    async fn set_kill_switch(&self, level: KillSwitchLevel) {
        self.active().set_kill_switch(level).await;
    }

    fn status(&self) -> watch::Receiver<TunStatus> {
        self.0.status.subscribe()
    }

    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.0.events.subscribe()
    }

    fn last_exit(&self) -> Option<ExitInfo> {
        self.active().last_exit()
    }

    fn recent_fault(&self) -> Option<OutboundFault> {
        self.active().recent_fault()
    }
}
