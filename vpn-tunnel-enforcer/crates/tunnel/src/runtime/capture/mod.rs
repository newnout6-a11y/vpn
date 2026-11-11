//! THE seam between what is captured how and everything else. A [`Capture`] owns exactly the
//! capture-specific steps of a session: its part of the engine config, protection before the
//! engines start, the readiness proof, loss and release, and its periodic checks.
//!
//! [`TunCapture`] captures the whole machine through a sing-box TUN guarded by the WFP layer
//! (needs elevation). A second strategy (loopback proxy capture, follow-up package) implements
//! the same trait: its plan carries no alias / TUN form, `begin` / `lost` / `release` do nothing,
//! `ready` proves the loopback inbound answers, and `config` emits a mixed inbound instead of
//! the TUN; the actor stays unchanged.
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_base::{AppResult, Msg};
use vpnte_engine::singbox_config::{ConfigError, Listeners, RoutingParts, TunStack, Upstream};

use crate::api::StartRequest;

mod tun;

pub use tun::TunCapture;
#[cfg(test)]
pub(crate) use tun::tun_config;

/// How the TUN and the WFP layer agree (review winnet-wfp D1 / D2, engine-config E-D3 / E-D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunForm {
    /// Dual-stack TUN (the IPv6 reject rule inside); IPv4-only lets sing-tun add its own hard
    /// "block IPv6" filter.
    pub dual_stack: bool,
    /// `dns_mode: hijack` (sing-tun's hard port-53 block) instead of `native`.
    pub dns_hijack: bool,
}

/// The decision table: our WFP layer blocks non-TUN IPv6 and DNS whenever the kill switch is
/// standard / strict or leak protection is on. Then sing-tun's own hard blocks would only
/// override our LAN / DHCPv6 / exception permits, so the TUN is dual-stack with `native` DNS;
/// with no WFP guard sing-tun's blocks are the only guard: IPv4-only with `hijack`.
pub fn tun_form(level: KillSwitchLevel, leak_protection: bool) -> TunForm {
    let guarded = level != KillSwitchLevel::Off || leak_protection;
    TunForm {
        dual_stack: guarded,
        dns_hijack: !guarded,
    }
}

/// What a capture decided for one start, before any effect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlan {
    /// Identity of the capture interface (the TUN alias), if it has one.
    pub alias: Option<String>,
    pub form: TunForm,
    pub stack: TunStack,
    pub mtu: u16,
    /// Kill-switch level the protection enforces in this session (drives the crash policy).
    pub guard: KillSwitchLevel,
    /// Non-fatal findings (e.g. a foreign TUN could not be ruled out).
    pub warnings: Vec<Msg>,
}

/// The capture proved up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureProof {
    /// Adapter LUID and alias (the app counts interface bytes by LUID).
    pub luid: Option<u64>,
    pub alias: Option<String>,
}

/// One periodic capture check while running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureCheck {
    Clear,
    /// Another tunnel competes for the routes (display label).
    Competing(String),
    /// The check could not run (nothing changes).
    Unknown,
}

/// The capture-independent parts of the engine config.
#[derive(Debug, Clone)]
pub struct EngineParts {
    pub upstream: Upstream,
    pub listeners: Listeners,
    pub routing: RoutingParts,
    pub phys_dns: Vec<Ipv4Addr>,
}

/// Capture-specific steps of a session (see the module doc).
#[async_trait]
pub trait Capture: Send + Sync {
    /// Refuses on a conflicting capture, picks the identity (never one of `avoid`) and the
    /// config form. No effect on the machine.
    async fn prepare(&self, req: &StartRequest, avoid: &[String]) -> AppResult<CapturePlan>;
    /// The complete engine config of `plan` and its compatibility key (equal keys: a running
    /// config can serve another upstream).
    fn config(
        &self,
        plan: &CapturePlan,
        parts: &EngineParts,
    ) -> Result<(Value, [u8; 32]), ConfigError>;
    /// Protection before any engine starts (`session_programs` = canonical paths of local-proxy
    /// owners). An error refuses the start.
    async fn begin(&self, plan: &CapturePlan, session_programs: &[PathBuf]) -> AppResult<()>;
    /// After the core reported ready: the capture exists, protection follows it, routes go
    /// through it. Errors carry `tunnel.runtime.tunSetup.*` messages.
    async fn ready(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> AppResult<CaptureProof>;
    /// Fresh route proof of the running capture.
    async fn routes_ok(&self, proof: &CaptureProof) -> bool;
    /// The core died unexpectedly: protection keeps blocking.
    async fn lost(&self) -> AppResult<()>;
    /// End of the session's protection (full stop, failed start).
    async fn release(&self) -> AppResult<()>;
    /// After the core's exit was proven: the capture interface disappeared within `timeout`.
    async fn wait_gone(
        &self,
        plan: &CapturePlan,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> bool;
    /// Periodic check while running.
    async fn check(&self, proof: &CaptureProof) -> CaptureCheck;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review D1 / D2 / E-D3 / E-D4: the TUN form follows what our WFP layer blocks; the
    /// cross-slice vector "standard, leak protection off ⇒ dual-stack" included.
    #[test]
    fn tun_form_follows_the_wfp_guard() {
        use KillSwitchLevel::{Off, Standard, Strict};
        let cases = [
            (Off, false, false, true),
            (Off, true, true, false),
            (Standard, false, true, false),
            (Standard, true, true, false),
            (Strict, false, true, false),
            (Strict, true, true, false),
        ];
        for (level, leak, dual_stack, dns_hijack) in cases {
            let form = tun_form(level, leak);
            assert_eq!(form.dual_stack, dual_stack, "{level:?} leak={leak}");
            assert_eq!(form.dns_hijack, dns_hijack, "{level:?} leak={leak}");
        }
    }
}
