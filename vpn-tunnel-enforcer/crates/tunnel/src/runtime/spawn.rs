//! The sing-box spawn loop (one retry on our own excluded ports) and entering the running state.
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult};
use vpnte_engine::singbox_config::{UdpPolicy, Upstream};
use vpnte_engine::singbox_process::StartError;
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_process::XrayEvent;

use super::actor::{Actor, Phase, Session};
use super::capture::{CapturePlan, EngineParts};
use super::config;
use super::engines::CoreProc;
use super::start::{Planned, Work};
use crate::api::{Mode, TunStatus, TunStatusKind};

/// Inputs of the sing-box spawn loop.
pub(super) struct Parts<'a> {
    pub(super) plan: &'a CapturePlan,
    pub(super) planned: &'a Planned,
    pub(super) routing: vpnte_engine::singbox_config::RoutingParts,
    pub(super) phys_dns: Vec<std::net::Ipv4Addr>,
    pub(super) direct_vpn: bool,
}

pub(super) type Ready = (
    Arc<dyn CoreProc>,
    vpnte_engine::clash_api::ClashEndpoint,
    vpnte_engine::singbox_config::Listeners,
    [u8; 32],
);

impl Actor {
    /// Spawns sing-box until it reports ready. One retry with fresh ports when it died on one
    /// of OUR loopback ports (Hyper-V / WSL excluded port ranges surface as WSAEACCES).
    pub(super) async fn spawn_ready(
        &self,
        p: &Parts<'_>,
        op: &CancellationToken,
        work: &mut Work,
    ) -> AppResult<Ready> {
        let slot_eps = work.slots.as_ref().map(|s| s.endpoints.clone());
        let taken: Vec<u16> = slot_eps.iter().flatten().map(SlotEndpoint::port).collect();
        // WP-12 lab: the mihomo run already up (held by the start) is chained with each core,
        // and its ports stay out of sing-box's listeners.
        #[cfg(feature = "lab")]
        let held = work.core.clone();
        #[cfg(feature = "lab")]
        let taken = super::mihomo::taken(p.planned, taken);
        let mut retried = false;
        loop {
            let (clash, listeners) = config::listeners(p.direct_vpn, slot_eps.is_some(), &taken)?;
            let upstream = match (p.planned, &slot_eps) {
                (Planned::Local { addr, kind, .. }, _) => Upstream::LocalProxy {
                    addr: addr.clone(),
                    kind: *kind,
                    creds: None,
                },
                (Planned::Native(upstream), _) => upstream.clone(),
                (Planned::Xray { profile, .. }, Some(eps)) => Upstream::XraySlots {
                    slots: eps.clone(),
                    active: Slot::A,
                    udp: UdpPolicy::of(&profile.profile),
                },
                (Planned::Xray { .. }, None) => {
                    return Err(AppError::internal(std::io::Error::other(
                        "slot upstream without slots",
                    )));
                }
                #[cfg(feature = "lab")]
                (Planned::Mihomo(plan), _) => super::mihomo::upstream(plan),
            };
            let parts = EngineParts {
                upstream,
                listeners: listeners.clone(),
                routing: p.routing.clone(),
                phys_dns: p.phys_dns.clone(),
            };
            let (json, compat) = self.capture.config(p.plan, &parts)?;
            let core = self
                .deps
                .engines
                .spawn_core(json.to_string().as_bytes())
                .map_err(|e| AppError::from(StartError::Spawn(e)))?;
            #[cfg(feature = "lab")]
            let core = super::mihomo::chain(core, held.clone());
            work.core = Some(core.clone());
            match core.wait_ready(self.deps.timings.ready, op).await {
                Ok(()) => return Ok((core, clash, listeners, compat)),
                Err(StartError::Exited(info))
                    if !retried && info.binds_any(&config::own_ports(&listeners)) =>
                {
                    tracing::warn!(ports = ?info.bind_failures,
                        "sing-box could not bind an own loopback port: one retry with fresh ports");
                    self.record_exit(&info);
                    work.core = None;
                    // The held mihomo run (never touched: the pair was not armed) stays in the
                    // compensation's hands for the retry.
                    #[cfg(feature = "lab")]
                    {
                        work.core = held.clone();
                    }
                    retried = true;
                }
                #[cfg(feature = "lab")]
                Err(e) => return Err(super::mihomo::start_error(e, held.as_ref())),
                #[cfg(not(feature = "lab"))]
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Keeps the last engine exit for history and diagnostics.
    pub(super) fn record_exit(&self, info: &vpnte_engine::singbox_process::ExitInfo) {
        let at = info
            .at
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        *self.shared.last_exit.lock() = Some(crate::api::ExitInfo {
            at,
            code: info.code,
            stderr_tail: info.stderr_tail.clone(),
            user_initiated: info.user_initiated,
            graceful: info.graceful,
        });
    }

    /// Publishes a confirmed session and starts its supervision.
    pub(super) fn enter_running(
        &mut self,
        s: Box<Session>,
        events: Option<mpsc::Receiver<XrayEvent>>,
    ) {
        self.exit = Some(s.core.exit_watch());
        self.xray_rx = events;
        *self.shared.core.lock() = Some(s.core.clone());
        self.last = Some(s.req.clone());
        self.stable_at = Some(tokio::time::Instant::now() + self.deps.timings.stable);
        self.spawn_watchdogs(&s);
        let status = running_status(&s, self.attempt);
        self.publish(|st| *st = status);
        self.announce(TunStatusKind::Running);
        self.phase = Phase::Running(s);
    }
}

/// The status of a running session.
pub(super) fn running_status(s: &Session, attempt: u8) -> TunStatus {
    let (proxy_addr, proxy_type, profile_name, protocol) = match &s.req.mode {
        Mode::LocalProxy { addr, kind } => (Some(addr.clone()), Some(*kind), None, None),
        Mode::DirectVpn { profile } => (
            None,
            None,
            Some(profile.profile.name.clone()),
            Some(profile.profile.kind.label().to_owned()),
        ),
    };
    TunStatus {
        running: true,
        mode: Some(s.req.mode.kind()),
        proxy_addr,
        proxy_type,
        profile_name,
        protocol,
        pid: Some(s.core.pid()),
        warning: None,
        proxy_reachable: true,
        started_at: Some(s.started_at),
        restart_attempt: attempt,
        capture: Some(s.req.capture),
        engine: Some(s.engine),
        session: Some(s.endpoints.clone()),
    }
}
