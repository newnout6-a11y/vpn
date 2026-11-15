//! The kill switch through the helper service: the app keeps `protection.json` and
//! `Settings::kill_switch` as the model (the guard persists what the service accepted), the
//! service applies the filters and keeps "Always" across app exits and reboots. Blocking calls,
//! for the guard's blocking thread.
use vpnte_base::{AppError, AppResult};
use vpnte_service::pipe::client::CallError;
use vpnte_service::proto::{Reply, Request};
use vpnte_winnet::wfp::{ProtectionSettings, ProtectionStatus, RemoveReport};

use super::{Remote, unexpected};

fn app_error(err: CallError) -> AppError {
    match err {
        CallError::Service(wire) => AppError::msg(wire.kind, wire.msg),
        CallError::Pipe(err) => err,
    }
}

fn block_on<T>(f: impl Future<Output = Result<T, CallError>>) -> AppResult<T> {
    tokio::runtime::Handle::current()
        .block_on(f)
        .map_err(app_error)
}

impl Remote {
    /// Applies `settings` in the service (it validates them again and saves its own copy).
    pub(in crate::svc_tunnel) fn apply_protection(
        &self,
        settings: ProtectionSettings,
    ) -> AppResult<()> {
        block_on(async {
            match self.call(Request::KillSwitch(Box::new(settings))).await? {
                Reply::Done { .. } => Ok(()),
                other => Err(unexpected(&other)),
            }
        })
    }

    /// What the service's filters enforce right now.
    pub(in crate::svc_tunnel) fn protection_status(&self) -> AppResult<ProtectionStatus> {
        block_on(async { Ok(self.refresh().await?.protection.to_status()) })
    }

    /// Removes every filter of ours (the service refuses it while a session runs).
    pub(in crate::svc_tunnel) fn cleanup(&self) -> AppResult<RemoveReport> {
        block_on(async {
            match self.call(Request::Cleanup).await? {
                Reply::Cleaned {
                    filters,
                    sublayer,
                    provider,
                } => Ok(RemoveReport {
                    filters,
                    sublayer,
                    provider,
                }),
                other => Err(unexpected(&other)),
            }
        })
    }
}
