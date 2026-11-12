//! One request of the controlling client -> one call into the runtime / kill switch.
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_tunnel::api::{
    CaptureKind, Mode, RestartOptions, StartRequest, StopOptions, TunError, VpnProfile,
};

use super::Host;
use crate::pipe::ClientInfo;
use crate::proto::{
    ErrorCode, ExitWire, Reply, Request, ServerUpstream, StartReceiptWire, StatusReply, StatusWire,
    StopReceiptWire, SwitchReceiptWire, TunnelStart, Upstream, WireError,
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

fn start_request(start: &TunnelStart, level: KillSwitchLevel) -> StartRequest {
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
    /// Validates a start / restart / switch, applies its kill-switch settings and inputs, and
    /// returns the runtime's request.
    async fn prepare(&self, start: &TunnelStart) -> Result<StartRequest, WireError> {
        if let Some(msg) = &self.deps.refuse_tunnel {
            return Err(refused(AppError::msg(ErrorKind::Permission, msg.clone())));
        }
        validate::start(start).map_err(refused)?;
        let settings = validate::protection(&start.protection).map_err(refused)?;
        let level = settings.level;
        self.deps
            .kill_switch
            .apply(settings)
            .await
            .map_err(|e| WireError::failed(&e))?;
        self.deps.inputs.set(&start.routing, level);
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
                let receipt = runtime.start(req, cancel.clone()).await;
                let receipt = receipt.map_err(tunnel_failed)?;
                Ok(Reply::Started(Some(StartReceiptWire::from(&receipt))))
            }
            Request::Restart(start) => {
                let req = self.prepare(&start).await?;
                let reason = "restart requested by the app".to_owned();
                let opts = RestartOptions {
                    cancel: cancel.child_token(),
                    ..RestartOptions::default()
                };
                let receipt = runtime.restart_protected(reason, req, opts).await;
                let receipt = receipt.map_err(tunnel_failed)?;
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
                let owner = cancel.clone();
                let is_owner = Arc::new(move || !owner.is_cancelled());
                let receipt = runtime.switch_upstream(req, cancel.clone(), is_owner).await;
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
                let level = self.deps.kill_switch.level();
                self.deps.inputs.set(&routing, level);
                Ok(Reply::Done { removing: false })
            }
            Request::Status => Ok(Reply::Status(Box::new(self.status().await))),
            Request::KillSwitch(settings) => {
                let settings = validate::protection(&settings).map_err(refused)?;
                let level = settings.level;
                self.deps
                    .kill_switch
                    .apply(settings)
                    .await
                    .map_err(|e| WireError::failed(&e))?;
                self.deps.inputs.set_level(level);
                Ok(Reply::Done { removing: false })
            }
            Request::Cleanup => {
                let report = self.deps.kill_switch.cleanup().await;
                let report = report.map_err(|e| WireError::failed(&e))?;
                Ok(Reply::Cleaned {
                    filters: report.filters,
                    sublayer: report.sublayer,
                    provider: report.provider,
                })
            }
            Request::ForgetMe => {
                let removing = self
                    .deps
                    .users
                    .remove(&client.user)
                    .map_err(|e| WireError::failed(&AppError::internal(e)))?;
                Ok(Reply::Done { removing })
            }
        }
    }

    async fn status(&self) -> StatusReply {
        let runtime = &self.deps.runtime;
        let tunnel = StatusWire::from(&*runtime.status().borrow());
        StatusReply {
            tunnel,
            last_exit: runtime.last_exit().as_ref().map(ExitWire::from),
            recent_fault: runtime.recent_fault(),
            protection: self.deps.kill_switch.status().await,
        }
    }
}

/// The message of a refused tunnel start when the service folder is user-writable.
pub fn untrusted_folder() -> Msg {
    Msg::new("service.folder.untrusted")
}
