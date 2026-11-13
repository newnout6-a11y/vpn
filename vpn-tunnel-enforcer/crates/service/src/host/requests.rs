//! One request of the controlling client -> one call into the runtime / kill switch.
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_tunnel::api::{
    CaptureKind, Mode, RestartOptions, StartRequest, StopOptions, TunError, VpnProfile,
};

use super::Host;
use crate::pipe::ClientInfo;
use crate::proto::{
    ErrorCode, ExitWire, KeptSession, Reply, Request, ServerUpstream, StartReceiptWire,
    StatusReply, StatusWire, StopReceiptWire, SwitchReceiptWire, TunnelStart, Upstream, WireError,
};
use crate::validate;

fn refused(err: AppError) -> WireError {
    WireError {
        code: ErrorCode::Refused,
        ..WireError::failed(&err)
    }
}

fn tunnel_failed(err: TunError) -> WireError {
    WireError {
        code: ErrorCode::Failed,
        kind: err.kind(),
        msg: err.user_msg(),
        warnings: err.warnings,
    }
}

fn vpn_profile(server: &ServerUpstream) -> VpnProfile {
    VpnProfile {
        id: server.id.clone(),
        profile: Arc::new(server.profile.clone()),
        device: server.device,
        engine: server.engine,
    }
}

pub(super) fn start_request(start: &TunnelStart, level: KillSwitchLevel) -> StartRequest {
    let mode = match &start.upstream {
        Upstream::LocalProxy { addr, kind } => Mode::LocalProxy {
            addr: addr.to_string(),
            kind: *kind,
        },
        Upstream::Server(server) => Mode::DirectVpn {
            profile: vpn_profile(server),
        },
    };
    StartRequest {
        mode,
        // The service exists for the TUN; the proxy capture runs unprivileged in the app.
        capture: CaptureKind::Tun,
        kill_switch: level,
        public_wifi: start.routing.public_wifi,
        stealth: start.routing.stealth,
        adaptive: start.adaptive,
        engine: start.engine,
        origin: start.origin,
    }
}

impl Host {
    /// Runs `op` under the state lock, on a task of its own: it finishes even when its request is
    /// dropped (the client left mid-request), and the next state change and the stop after the
    /// client left see its result (reviews service-a1 / a10).
    async fn serialized<T: Send + 'static>(
        &self,
        op: impl Future<Output = AppResult<T>> + Send + 'static,
    ) -> Result<T, WireError> {
        let guard = self.state.clone().lock_owned().await;
        let task = tokio::spawn(async move {
            let done = op.await;
            drop(guard);
            done
        });
        match task.await {
            Ok(done) => done.map_err(|e| WireError::failed(&e)),
            Err(e) => Err(WireError::failed(&AppError::internal(e))),
        }
    }

    /// Waits for the state changes already asked for; nothing new starts while held.
    pub(super) async fn settled(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.state.lock().await
    }

    /// Validates a start / restart / switch, applies its kill-switch settings and inputs, and
    /// returns the runtime's request.
    async fn prepare(&self, start: &TunnelStart) -> Result<StartRequest, WireError> {
        if let Some(msg) = &self.deps.refuse_tunnel {
            return Err(refused(AppError::msg(ErrorKind::Permission, msg.clone())));
        }
        validate::start(start).map_err(refused)?;
        let settings = validate::protection(&start.protection).map_err(refused)?;
        let level = settings.level;
        let (kill_switch, inputs) = (self.deps.kill_switch.clone(), self.deps.inputs.clone());
        let routing = start.routing.clone();
        self.serialized(async move {
            kill_switch.apply(settings).await?;
            inputs.set(&routing, level);
            Ok(())
        })
        .await?;
        Ok(start_request(start, level))
    }

    pub(super) async fn handle(
        &self,
        client: &ClientInfo,
        request: Request,
        cancel: &CancellationToken,
    ) -> Result<Reply, WireError> {
        let runtime = &self.deps.runtime;
        match request {
            Request::Hello(_) => Err(WireError::new(
                ErrorCode::BadRequest,
                ErrorKind::Validation,
                "service.pipe.badRequest",
            )),
            Request::Start(start) => {
                let req = self.prepare(&start).await?;
                self.owns_session(client, &start);
                let receipt = runtime.start(req, cancel.clone()).await;
                let receipt = receipt.map_err(tunnel_failed)?;
                self.remember(client, &start);
                Ok(Reply::Started(Some(StartReceiptWire::from(&receipt))))
            }
            Request::Restart(start) => {
                let req = self.prepare(&start).await?;
                self.owns_session(client, &start);
                let reason = "restart requested by the app".to_owned();
                let opts = RestartOptions {
                    cancel: cancel.child_token(),
                    ..RestartOptions::default()
                };
                let receipt = runtime.restart_protected(reason, req, opts).await;
                let receipt = receipt.map_err(tunnel_failed)?;
                self.remember(client, &start);
                Ok(Reply::Started(Some(StartReceiptWire::from(&receipt))))
            }
            Request::RestartWithLast { reason } => {
                validate::text(&reason, "reason").map_err(refused)?;
                let receipt = runtime.restart_with_last(reason).await;
                let receipt = receipt.map_err(tunnel_failed)?;
                Ok(Reply::Started(receipt.as_ref().map(StartReceiptWire::from)))
            }
            Request::RestartAdaptive(restart) => {
                validate::text(&restart.reason, "reason").map_err(refused)?;
                if let Some(server) = &restart.server {
                    validate::server(server).map_err(refused)?;
                }
                let profile = restart.server.as_ref().map(vpn_profile);
                let receipt = runtime
                    .restart_adaptive(restart.mode, restart.reason, profile)
                    .await;
                let receipt = receipt.map_err(tunnel_failed)?;
                Ok(Reply::Started(Some(StartReceiptWire::from(&receipt))))
            }
            Request::Switch(start) => {
                let req = self.prepare(&start).await?;
                self.owns_session(client, &start);
                let owner = cancel.clone();
                let is_owner = Arc::new(move || !owner.is_cancelled());
                let receipt = runtime.switch_upstream(req, cancel.clone(), is_owner).await;
                if receipt.is_some() {
                    self.remember(client, &start);
                }
                Ok(Reply::Switched(
                    receipt.as_ref().map(SwitchReceiptWire::from),
                ))
            }
            Request::Stop(stop) => {
                let opts = StopOptions {
                    preserve_protection: stop.preserve_protection,
                    preserve_last: stop.preserve_last,
                };
                let receipt = runtime.stop(opts).await;
                Ok(Reply::Stopped(StopReceiptWire::from(&receipt)))
            }
            Request::Inputs(routing) => {
                validate::routing(&routing).map_err(refused)?;
                let (kill_switch, inputs) =
                    (self.deps.kill_switch.clone(), self.deps.inputs.clone());
                self.serialized(async move {
                    inputs.set(&routing, kill_switch.level());
                    Ok(())
                })
                .await?;
                Ok(Reply::Done { removing: false })
            }
            Request::Status => Ok(Reply::Status(Box::new(self.status(client).await))),
            Request::KillSwitch(settings) => {
                let settings = validate::protection(&settings).map_err(refused)?;
                let (kill_switch, inputs) =
                    (self.deps.kill_switch.clone(), self.deps.inputs.clone());
                self.serialized(async move {
                    let level = settings.level;
                    kill_switch.apply(settings).await?;
                    inputs.set_level(level);
                    Ok(())
                })
                .await?;
                Ok(Reply::Done { removing: false })
            }
            Request::Cleanup => {
                let kill_switch = self.deps.kill_switch.clone();
                let report = self
                    .serialized(async move { kill_switch.cleanup().await })
                    .await?;
                Ok(Reply::Cleaned {
                    filters: report.filters,
                    sublayer: report.sublayer,
                    provider: report.provider,
                })
            }
            Request::ForgetMe => self.forget(client).await,
            Request::Update(ask) => self.update(&client.user, ask).await,
            Request::ServiceLog => self.service_log(client).await,
        }
    }

    /// The caller's lines of the service log (p-logs): the service-wide ones and those of his
    /// own sessions, never another user's ([`crate::logs`]).
    pub(super) async fn service_log(&self, client: &ClientInfo) -> Result<Reply, WireError> {
        let user = client.user.clone();
        match tokio::task::spawn_blocking(move || crate::logs::for_user(&user)).await {
            Ok(Ok(log)) => Ok(Reply::ServiceLog(log)),
            Ok(Err(err)) => Err(WireError::failed(&AppError::from(err))),
            Err(err) => Err(WireError::failed(&AppError::internal(err))),
        }
    }

    /// Whom a service log line concerns now (p-logs): the user of the session the runtime runs or
    /// ran last, else the controller's. Asked without waiting: a line logged while one of these
    /// locks is held is nobody's (a re-entrant lock would deadlock the logger).
    pub(crate) fn log_owner(&self) -> crate::logs::Owner {
        let (Some(session), Some(controller)) =
            (self.session_user.try_lock(), self.controller.try_lock())
        else {
            return crate::logs::Owner::Busy;
        };
        let controller = controller.as_ref().map(|(_, user)| user.as_str());
        crate::logs::owner_of(session.as_deref(), controller)
    }

    /// Removes the caller's SID; `removing` when he was the last user. The last user's leave first
    /// stops the tunnel and removes our WFP objects; when that fails nothing else changes (he
    /// stays recorded, so his retry repeats it) and the uninstaller is told so: strict filters
    /// must never outlive the service that can remove them (review 4555679938).
    pub(super) async fn forget(&self, client: &ClientInfo) -> Result<Reply, WireError> {
        if self.deps.users.is_last(&client.user) {
            let receipt = self.deps.runtime.stop(StopOptions::default()).await;
            tracing::info!(ok = receipt.ok, "the last user leaves: tunnel stopped");
            let kill_switch = self.deps.kill_switch.clone();
            self.serialized(async move {
                let removed = kill_switch.remove_all().await;
                removed.map_err(crate::install::flow::filters_kept)
            })
            .await?;
            self.forget_session(None);
        }
        let removing = self
            .deps
            .users
            .remove(&client.user)
            .map_err(|e| WireError::failed(&AppError::internal(e)))?;
        self.forget_session(Some(&client.user));
        Ok(Reply::Done { removing })
    }

    /// The runtime's last exit and fault (an engine's stderr tail, a server's error) go only to
    /// the user whose start they came from (review service-b2).
    async fn status(&self, client: &ClientInfo) -> StatusReply {
        let runtime = &self.deps.runtime;
        let mut tunnel = StatusWire::from(&*runtime.status().borrow());
        tunnel.self_test = self.self_test_for(&client.user, &tunnel);
        let own = self.session_user.lock().as_deref() == Some(client.user.as_str());
        let kept = own.then(|| self.kept(&tunnel)).flatten();
        StatusReply {
            tunnel,
            last_exit: own
                .then(|| runtime.last_exit().as_ref().map(ExitWire::from))
                .flatten(),
            recent_fault: own.then(|| runtime.recent_fault()).flatten(),
            protection: self.deps.kill_switch.status().await,
            kept,
        }
    }

    /// The running session as a take-over: its current generation, pid, start and engine.
    fn kept(&self, tunnel: &StatusWire) -> Option<KeptSession> {
        let (server_id, local_proxy) = self.upstream.lock().clone()?;
        if !tunnel.running {
            return None;
        }
        Some(KeptSession {
            receipt: StartReceiptWire {
                generation: self.generation.load(Ordering::Relaxed),
                pid: tunnel.pid?,
                started_at: tunnel.started_at?,
                engine: tunnel.engine.clone()?,
                warnings: Vec::new(),
            },
            server_id,
            local_proxy,
        })
    }

    /// `client` now owns what the runtime reports about its session, started for `start`.
    fn owns_session(&self, client: &ClientInfo, start: &TunnelStart) {
        *self.session_user.lock() = Some(client.user.clone());
        *self.upstream.lock() = Some(super::resume::upstream_of(start));
    }
}

/// The message of a refused tunnel start when the service folder is user-writable.
pub fn untrusted_folder() -> Msg {
    Msg::new("service.folder.untrusted")
}
