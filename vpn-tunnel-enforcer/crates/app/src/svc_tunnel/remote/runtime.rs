//! [`Remote`] as the tunnel's `Runtime`: each call is one typed request; the service runs the
//! runtime itself. Starts carry the app's routing inputs and kill-switch settings; restarts of
//! the last start send fresh inputs first (the app's settings may have changed since).
use async_trait::async_trait;
use tokio::sync::{broadcast, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, OutboundFault};
use vpnte_base::{AppError, Msg};
use vpnte_service::pipe::client::CallError;
use vpnte_service::proto::{
    AdaptiveRestart, KeptSession, Reply, Request, StopTunnel, TunnelStart, Upstream,
};
use vpnte_tunnel::api::{
    ExitInfo, Origin, OwnerCheck, RestartOptions, Runtime, StartReceipt, StartRequest, StopOptions,
    StopReceipt, SwitchReceipt, TunError, TunStatus, TunStatusKind, TunnelEvent, VpnProfile,
};

use super::{Remote, start, tun_error, unexpected};

/// The names `start` carries hints for.
fn hinted(start: &TunnelStart) -> Vec<String> {
    match &start.upstream {
        Upstream::Server(server) => server.hints.iter().map(|h| h.name.clone()).collect(),
        Upstream::LocalProxy { .. } => Vec::new(),
    }
}

/// The upstream a kept session runs is the one asked for: the take-over keeps it running.
fn same_upstream(kept: &KeptSession, upstream: &Upstream) -> bool {
    match upstream {
        Upstream::Server(server) => kept.server_id.as_deref() == Some(server.id.as_str()),
        Upstream::LocalProxy { addr, .. } => kept.local_proxy == Some(*addr),
    }
}

impl Remote {
    /// The service's start from `req`, with the warnings only the app can give (`cancel`: the
    /// request is called off; it goes without waiting for a hint).
    async fn tunnel_start(
        &self,
        req: &StartRequest,
        cancel: &CancellationToken,
    ) -> Result<(TunnelStart, Vec<Msg>), TunError> {
        let inputs = self.0.inputs.snapshot().await?;
        let protection = self.0.protection.read(|d| d.settings.clone());
        let notes = start::inactive_warnings(&inputs, self.protocol());
        let mut start = start::tunnel_start(req, &inputs, protection)?;
        // S3-09 (b), lab L12-5: the addresses of every name the server's graph dials, resolved
        // before the click (a lookup still in flight then is joined, up to a second), for this
        // request only (the service filters them like looked-up answers; a service older than
        // the hints never sees them).
        if let (Upstream::Server(server), Some(ahead)) = (&mut start.upstream, self.0.ahead.get()) {
            let device = server.device.unwrap_or_default();
            let names = crate::svc_tunnel::warm::graph_hosts(&server.profile, device);
            server.hints = tokio::select! {
                () = cancel.cancelled() => Vec::new(),
                hints = ahead.hints(&names) => hints,
            };
        }
        Ok((start, notes))
    }

    /// A request that carried hints for `names` failed: they go (S3-09 (e), speed3-a1), the next
    /// request asks the resolvers.
    fn failed_with(&self, names: &[String]) {
        if let Some(ahead) = self.0.ahead.get() {
            for name in names {
                ahead.forget(name);
            }
        }
    }

    /// The start-like reply to `request` (`hinted`: the names it carries hints for, dropped when
    /// it fails; a cancelled request proves nothing).
    async fn started_with(
        &self,
        request: Request,
        cancel: &CancellationToken,
        notes: Vec<Msg>,
        hinted: &[String],
    ) -> Result<Option<StartReceipt>, TunError> {
        let receipt = self.started(request, cancel, notes).await;
        if let Err(err) = &receipt
            && err.error.kind != vpnte_base::ErrorKind::Cancelled
        {
            self.failed_with(hinted);
        }
        receipt
    }

    /// The service's routing inputs from the app's current settings; the warnings only the app
    /// can give.
    async fn send_inputs(&self) -> Result<Vec<Msg>, TunError> {
        let inputs = self.0.inputs.snapshot().await?;
        let routing = Box::new(start::routing(&inputs));
        self.call(Request::Inputs(routing))
            .await
            .map_err(tun_error)?;
        Ok(start::inactive_warnings(&inputs, self.protocol()))
    }

    /// A start-like request, its receipt's warnings followed by `notes`; a cancelled `cancel`
    /// answers at once (the lane's stop follows and cancels it in the service).
    async fn started(
        &self,
        request: Request,
        cancel: &CancellationToken,
        notes: Vec<Msg>,
    ) -> Result<Option<StartReceipt>, TunError> {
        let reply = tokio::select! {
            () = cancel.cancelled() => return Err(AppError::cancelled().into()),
            reply = self.call(request) => reply.map_err(tun_error)?,
        };
        match reply {
            Reply::Started(receipt) => Ok(receipt.map(|wire| {
                let mut receipt = StartReceipt::from(wire);
                receipt.generation = self.0.state.lock().gens.native(receipt.generation);
                receipt.warnings.extend(notes);
                receipt
            })),
            other => Err(tun_error(unexpected(&other))),
        }
    }

    /// Takes the kept session over: fresh numbers (it may have restarted since the connect),
    /// its status shown, and the start events the lifecycle expects of a run it started (or of
    /// one the runtime brought back by itself: [`Remote::adopt`]).
    pub(super) async fn take_over(&self) -> Result<StartReceipt, TunError> {
        let reply = self.refresh().await.map_err(tun_error)?;
        let Some(kept) = reply.kept else {
            self.unpark();
            return Err(AppError::msg(
                vpnte_base::ErrorKind::Conflict,
                Msg::new("tunnel.runtime.notRunning"),
            )
            .into());
        };
        let generation = {
            let mut st = self.0.state.lock();
            st.kept = None;
            st.parked = None;
            st.gens.native(kept.receipt.generation)
        };
        tracing::info!(generation, "kept session taken over");
        let events = &self.0.events;
        let _ = events.send(TunnelEvent::StartBegan { generation });
        self.0.status.send_replace(reply.tunnel.into());
        let _ = events.send(TunnelEvent::Status(TunStatusKind::Running));
        let _ = events.send(TunnelEvent::StartFinished {
            generation,
            ok: true,
        });
        let mut receipt = StartReceipt::from(kept.receipt);
        receipt.generation = generation;
        Ok(receipt)
    }
}

/// A stop the service could not be asked for: nothing is confirmed.
fn unconfirmed_stop(err: &CallError) -> StopReceipt {
    StopReceipt {
        operation_id: format!("stop_{}", uuid::Uuid::new_v4().simple()),
        ok: false,
        runtime_stopped: false,
        forced: false,
        protection_released: None,
        baseline_restored: None,
        adapter_gone: false,
        warnings: vec![tun_error_msg(err)],
    }
}

fn tun_error_msg(err: &CallError) -> Msg {
    match err {
        CallError::Service(wire) => wire.msg.clone(),
        CallError::Pipe(err) => err.user_msg(),
    }
}

#[async_trait]
impl Runtime for Remote {
    async fn start(
        &self,
        req: StartRequest,
        cancel: CancellationToken,
    ) -> Result<StartReceipt, TunError> {
        // A new connection parks a session the service kept for this user (a crashed window).
        self.link().await.map_err(tun_error)?;
        let (start, notes) = self.tunnel_start(&req, &cancel).await?;
        let kept = self.0.state.lock().kept.clone();
        let hinted = hinted(&start);
        let request = match kept {
            Some(kept) if same_upstream(&kept, &start.upstream) => return self.take_over().await,
            // Another upstream: the kept run is replaced, its kill switch held in between.
            Some(_) => {
                self.unpark();
                Request::Restart(Box::new(start))
            }
            // The app's own start ends a wait for a resumed session (`reattach`).
            None => {
                self.unpark();
                Request::Start(Box::new(start))
            }
        };
        let receipt = self.started_with(request, &cancel, notes, &hinted).await?;
        receipt.ok_or_else(|| AppError::internal(std::io::Error::other("no receipt")).into())
    }

    async fn stop(&self, opts: StopOptions) -> StopReceipt {
        self.unpark();
        let request = Request::Stop(StopTunnel {
            preserve_protection: opts.preserve_protection,
            preserve_last: opts.preserve_last,
        });
        match self.call(request).await {
            Ok(Reply::Stopped(wire)) => wire.into(),
            Ok(other) => unconfirmed_stop(&unexpected(&other)),
            Err(err) => unconfirmed_stop(&err),
        }
    }

    async fn restart_protected(
        &self,
        _reason: String,
        next: StartRequest,
        opts: RestartOptions,
    ) -> Result<StartReceipt, TunError> {
        self.unpark();
        let (start, notes) = self.tunnel_start(&next, &opts.cancel).await?;
        let hinted = hinted(&start);
        let request = Request::Restart(Box::new(start));
        let receipt = self
            .started_with(request, &opts.cancel, notes, &hinted)
            .await?;
        receipt.ok_or_else(|| AppError::internal(std::io::Error::other("no receipt")).into())
    }

    async fn restart_with_last(&self, reason: String) -> Result<Option<StartReceipt>, TunError> {
        let notes = self.send_inputs().await?;
        let never = CancellationToken::new();
        self.started(Request::RestartWithLast { reason }, &never, notes)
            .await
    }

    async fn restart_adaptive(
        &self,
        mode: AdaptiveMode,
        reason: String,
        profile: Option<VpnProfile>,
    ) -> Result<StartReceipt, TunError> {
        let notes = self.send_inputs().await?;
        let restart = AdaptiveRestart {
            mode,
            reason,
            server: profile.as_ref().map(start::server),
        };
        let never = CancellationToken::new();
        let receipt = self
            .started(Request::RestartAdaptive(Box::new(restart)), &never, notes)
            .await?;
        receipt.ok_or_else(|| AppError::internal(std::io::Error::other("no receipt")).into())
    }

    async fn switch_upstream(
        &self,
        next: StartRequest,
        cancel: CancellationToken,
        _is_owner: OwnerCheck,
    ) -> Option<SwitchReceipt> {
        let (mut start, notes) = self.tunnel_start(&next, &cancel).await.ok()?;
        // speed3 S3-07: the user's own switch to a server a young, fast key check found online
        // selects first and proves once after, on the same evidence the in-process runtime reads
        // through `Failover::fresh`. Never an automatic switch (a service before protocol 5
        // never sees the field: `Request::speak`).
        if next.origin == Origin::User
            && let (Upstream::Server(server), Some(servers)) =
                (&mut start.upstream, self.0.servers.get())
        {
            server.fresh = crate::svc_auto::fresh_server(servers, &server.id);
        }
        let hinted = hinted(&start);
        let reply = tokio::select! {
            () = cancel.cancelled() => return None,
            reply = self.call(Request::Switch(Box::new(start))) => reply,
        };
        match reply {
            Ok(Reply::Switched(receipt)) => receipt.map(|wire| {
                let mut receipt = SwitchReceipt::from(wire);
                if vpnte_tunnel::runtime::dial_failed(&receipt) {
                    self.failed_with(&hinted);
                }
                receipt.warnings.extend(notes);
                receipt
            }),
            Ok(other) => {
                tracing::warn!(?other, "unexpected switch reply");
                None
            }
            Err(err) => {
                tracing::warn!(error = %err, "switch through the service failed");
                None
            }
        }
    }

    /// The held session's recovery start at once: the service restarts its last start. `false`
    /// when nothing of ours is held (the caller then connects plainly).
    async fn retry_now(&self) -> bool {
        if self.0.status.borrow().capture.is_none() {
            return false;
        }
        !matches!(self.restart_with_last("retry now".into()).await, Ok(None))
    }

    fn status(&self) -> watch::Receiver<TunStatus> {
        self.0.status.subscribe()
    }

    fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.0.events.subscribe()
    }

    fn last_exit(&self) -> Option<ExitInfo> {
        self.0.state.lock().last_exit.clone()
    }

    fn recent_fault(&self) -> Option<OutboundFault> {
        self.0.state.lock().recent_fault
    }
}
