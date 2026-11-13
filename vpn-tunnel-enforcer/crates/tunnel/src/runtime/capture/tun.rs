//! TUN capture: sing-box's Wintun adapter with `auto_route` + `strict_route`, guarded by the WFP
//! layer of `vpnte_winnet::wfp::Protection` (needs an elevated process).
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::singbox_config::{self, ConfigError, ConfigInputs, TunParams, TunStack};
use vpnte_winnet::adapters::{self, OwnedTun, Release, alias, foreign_tun};
use vpnte_winnet::wfp::{self, Protection};

use super::{Capture, CaptureCheck, CapturePlan, CaptureProof, EngineParts, tun_form};
use crate::api::{StartRequest, TunWarning};

/// The whole machine through our TUN (see the module doc).
pub struct TunCapture {
    protection: Arc<Protection>,
    /// The adapter of the running session, kept for route proofs and competing checks.
    current: parking_lot::Mutex<Option<OwnedTun>>,
}

impl TunCapture {
    /// `protection` is the app's (or the service's) one WFP handle, already `startup()`-ed.
    pub fn new(protection: Arc<Protection>) -> Self {
        Self {
            protection,
            current: parking_lot::Mutex::new(None),
        }
    }
}

/// Blocking Win32 / BFE work off the async threads.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> AppResult<T> + Send + 'static,
) -> AppResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(AppError::internal)?
}

/// A TUN bring-up step failed: the key starts with [`crate::api::TUN_SETUP_KEY_PREFIX`] (the
/// history classifies it as a TUN setup failure); a cancellation stays a cancellation.
fn setup_failed(key: &'static str, cause: AppError) -> AppError {
    if cause.kind == ErrorKind::Cancelled {
        return cause;
    }
    tracing::warn!(step = key, error = %cause, "TUN setup failed");
    AppError::msg(cause.kind, Msg::new(key)).with_source(cause)
}

const SETUP_ADAPTER: &str = "tunnel.runtime.tunSetup.adapter";
const SETUP_PROTECTION: &str = "tunnel.runtime.tunSetup.protection";
const SETUP_ROUTES: &str = "tunnel.runtime.tunSetup.routes";

#[async_trait]
impl Capture for TunCapture {
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan> {
        let protection = self.protection.clone();
        let avoid = avoid.to_vec();
        let req_level = req.kill_switch;
        let mtu = singbox_config::select_mtu(req.stealth, req.adaptive, req.public_wifi);
        blocking(move || {
            let mut warnings = Vec::new();
            let own = alias::all_aliases();
            let own: Vec<&str> = own.iter().map(String::as_str).collect();
            match foreign_tun::detect(None, &own) {
                Ok(found) => foreign_tun::refuse_on_conflict(&found)?,
                Err(e) => {
                    tracing::warn!(error = %e, "adapter list unreadable: foreign TUN not ruled out");
                    warnings.push(TunWarning::ForeignTunUnverified.msg());
                }
            }
            let mut names = alias::connection_names().map_err(AppError::internal)?;
            names.extend(avoid);
            let alias = alias::choose(&names)?;
            let settings = protection.settings();
            if settings.level != req_level {
                tracing::warn!(requested = ?req_level, enforced = ?settings.level,
                    "kill-switch level of the request differs from the protection in force");
            }
            // D4: keep the field-proven mixed stack unless Windows Firewall makes the system
            // stack's inbound path unusable; an unreadable policy takes the stack that always works.
            let gvisor = wfp::tun_inbound_blocked().unwrap_or_else(|e| {
                tracing::warn!(error = %e, "firewall policy unreadable: using the gvisor stack");
                true
            });
            Ok(CapturePlan {
                alias: Some(alias),
                form: tun_form(settings.level, settings.leak_protection),
                stack: if gvisor {
                    TunStack::Gvisor
                } else {
                    TunStack::Mixed
                },
                mtu,
                guard: settings.level,
                warnings,
            })
        })
        .await
    }

    fn config(
        &self,
        plan: &CapturePlan,
        parts: &EngineParts,
    ) -> Result<(Value, [u8; 32]), ConfigError> {
        tun_config(plan, parts)
    }

    async fn begin(&self, plan: &CapturePlan, session_programs: &[PathBuf]) -> AppResult<()> {
        let protection = self.protection.clone();
        let programs = session_programs.to_vec();
        // R1: the provisional permit by the TUN's fixed local addresses is part of connect_begin,
        // so traffic routed into the TUN before `tun_up` is not refused.
        let mut addrs: Vec<IpAddr> = vec![adapters::TUN_V4.addr().into()];
        if plan.form.dual_stack {
            addrs.push(adapters::TUN_V6.addr().into());
        }
        blocking(move || Ok(protection.connect_begin(&programs, &addrs)?)).await
    }

    async fn ready(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<CaptureProof> {
        let alias = plan.alias.clone().unwrap_or_default();
        let v6 = plan.form.dual_stack.then_some(adapters::TUN_V6);
        let tun = adapters::wait_owned_tun(&alias, adapters::TUN_V4, v6, timeout, cancel)
            .await
            .map_err(|e| setup_failed(SETUP_ADAPTER, e.into()))?;
        let (protection, luid) = (self.protection.clone(), tun.luid);
        blocking(move || Ok(protection.tun_up(luid)?))
            .await
            .map_err(|e| setup_failed(SETUP_PROTECTION, e))?;
        let probe = tun.clone();
        let proven = blocking(move || adapters::route_proof(&probe).map_err(AppError::internal))
            .await
            .map_err(|e| setup_failed(SETUP_ROUTES, e))?;
        if !proven {
            let cause = AppError::new(ErrorKind::Network);
            return Err(setup_failed(SETUP_ROUTES, cause));
        }
        let proof = CaptureProof {
            luid: Some(tun.luid),
            alias: Some(tun.alias.clone()),
            port: None,
        };
        *self.current.lock() = Some(tun);
        Ok(proof)
    }

    async fn routes_ok(&self, _proof: &CaptureProof) -> bool {
        let Some(tun) = self.current.lock().clone() else {
            return false;
        };
        blocking(move || adapters::route_proof(&tun).map_err(AppError::internal))
            .await
            .unwrap_or(false)
    }

    async fn lost(&self) -> AppResult<()> {
        self.current.lock().take();
        let protection = self.protection.clone();
        blocking(move || Ok(protection.tun_lost()?)).await
    }

    async fn release(&self) -> AppResult<()> {
        self.current.lock().take();
        let protection = self.protection.clone();
        blocking(move || Ok(protection.disconnected()?)).await
    }

    async fn wait_gone(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> bool {
        let Some(alias) = plan.alias.clone() else {
            return true;
        };
        let v6 = plan.form.dual_stack.then_some(adapters::TUN_V6);
        adapters::wait_released(&[alias], v6, timeout, cancel).await == Release::Released
    }

    async fn check(&self, proof: &CaptureProof) -> CaptureCheck {
        let own_luid = proof.luid;
        let found = blocking(move || {
            let own = alias::all_aliases();
            let own: Vec<&str> = own.iter().map(String::as_str).collect();
            foreign_tun::detect(own_luid, &own).map_err(AppError::internal)
        })
        .await;
        match found {
            Ok(found) => found
                .first()
                .map_or(CaptureCheck::Clear, |f| CaptureCheck::Competing(f.label())),
            Err(e) => {
                tracing::debug!(error = %e, "competing TUN check failed");
                CaptureCheck::Unknown
            }
        }
    }

    /// The filters follow a level change at once (the app's guard or the helper service sets
    /// it live); the crash policy reads the same level.
    fn guard(&self, _plan: &CapturePlan) -> KillSwitchLevel {
        self.protection.level_in_force()
    }
}

/// The sing-box config of a TUN session and its compatibility key.
pub(crate) fn tun_config(
    plan: &CapturePlan,
    parts: &EngineParts,
) -> Result<(Value, [u8; 32]), ConfigError> {
    let inputs = ConfigInputs {
        upstream: parts.upstream.clone(),
        capture: singbox_config::Capture::Tun(TunParams {
            alias: plan.alias.clone().unwrap_or_default(),
            mtu: plan.mtu,
            ipv6: plan.form.dual_stack,
            dns_hijack: plan.form.dns_hijack,
            stack: plan.stack,
        }),
        listeners: parts.listeners.clone(),
        routing: parts.routing.clone(),
        phys_dns: parts.phys_dns.clone(),
    };
    Ok((
        singbox_config::build(&inputs)?,
        singbox_config::compat_key(&inputs),
    ))
}
