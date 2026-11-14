//! WP-12 lab engine (feature `lab`): an AmneziaWG session is mihomo, the AmneziaWG hop, chained
//! behind the session's sing-box over a keyed loopback hop (Shadowsocks 2022, UDP over TCP);
//! sing-box keeps the loopback inbound, routing, DNS, statistics and the live check (engine API
//! "WP-12"). mihomo's authenticated SOCKS5 listener serves only the app's own proof.
//! The session is published only after bytes came back through mihomo's tunnel: mihomo confirms
//! a SOCKS CONNECT before it dials, so readiness alone proves nothing (AT-12-003 step 2).
use std::sync::{Arc, Weak};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::OutboundFault;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::core_adapter::capabilities;
use vpnte_engine::mihomo_config::{Compiled, HopEndpoint, Listen, hosts, preflight, translate};
use vpnte_engine::mihomo_process::{MihomoError, MihomoProcess};
use vpnte_engine::singbox_config::Upstream;
use vpnte_engine::singbox_process::{ExitInfo, StartError, StopError};
use vpnte_engine::slot::SlotEndpoint;
use vpnte_engine::xray_config::ResolvePath;

use super::actor::Actor;
use super::engines::{CoreProc, EchoFailure, Engines, echo_failure};
use super::start::{Planned, Work};
use crate::api::{CaptureKind, EngineRun, StartRequest, VpnProfile};

/// The upstream of an AmneziaWG session, decided before any effect.
pub(super) struct MihomoPlan {
    pub compiled: Compiled,
    pub socks: SlotEndpoint,
    pub hop: HopEndpoint,
    pub controller: ClashEndpoint,
    pub profile: VpnProfile,
}

/// Refuses, before any effect, what the chosen engine cannot carry: mihomo has no TUN chain
/// (`core_adapter` capability), so Tunnel mode refuses AmneziaWG instead of leaking around it.
pub(super) fn admit(run: &EngineRun, req: &StartRequest) -> AppResult<()> {
    if req.capture == CaptureKind::Tun && !capabilities(run.kind).tun_capture {
        return Err(AppError::validation(Msg::new(
            "tunnel.runtime.mihomo.tunUnavailable",
        )));
    }
    Ok(())
}

/// Checks the key (bounds and preflight: AT-12-003 step 1, AT-12-004), resolves its peer names
/// directly (mihomo never resolves them itself), allocates the loopback listeners and
/// translates. Returns the plan and the warnings of the lookup.
pub(super) async fn plan(
    engines: &dyn Engines,
    profile: &VpnProfile,
    held: &[u16],
    op: &CancellationToken,
) -> AppResult<(MihomoPlan, Vec<Msg>)> {
    let p = &profile.profile;
    preflight(p)?;
    let resolved = engines.resolve(&hosts(p), ResolvePath::Direct, op).await?;
    // `held`: the capture's own listener (L9-1), never handed to mihomo.
    let socks = SlotEndpoint::allocate(held)?;
    let hop = HopEndpoint::allocate(&[held, &[socks.port()]].concat())?;
    let controller = ClashEndpoint::allocate(&[held, &[socks.port(), hop.port()]].concat())?;
    let listen = Listen {
        socks: &socks,
        hop: &hop,
        controller: &controller,
    };
    let compiled = translate(p, &resolved.addrs, &listen)?;
    tracing::info!(applied = ?compiled.applied, "mihomo config compiled");
    let plan = MihomoPlan {
        compiled,
        socks,
        hop,
        controller,
        profile: profile.clone(),
    };
    Ok((plan, resolved.warning.into_iter().collect()))
}

/// sing-box's upstream: the run's keyed hop (UDP over TCP inside it).
pub(super) fn upstream(plan: &MihomoPlan) -> Upstream {
    plan.hop.upstream()
}

/// `taken` plus mihomo's own ports when `planned` is a mihomo session: kept out of sing-box's
/// listener allocation.
pub(super) fn taken(planned: &Planned, mut taken: Vec<u16>) -> Vec<u16> {
    if let Planned::Mihomo(plan) = planned {
        taken.extend([plan.socks.port(), plan.hop.port(), plan.controller.port]);
    }
    taken
}

impl Actor {
    /// Starts mihomo (ready, held in `work` for the compensation), then proves the tunnel: the
    /// egress echo through its listener, under the app's handshake budget. Any answer that came
    /// back through the tunnel is the proof, an echo service's error page included (audit
    /// mihomo-b3); only a peer that sent nothing back, or answered too late, fails the start
    /// with `noTraffic`, and a run that died meanwhile is named as such.
    pub(super) async fn start_mihomo(
        &self,
        plan: &MihomoPlan,
        op: &CancellationToken,
        work: &mut Work,
    ) -> AppResult<()> {
        let engines = &*self.deps.engines;
        let (socks, controller) = (plan.socks.clone(), plan.controller.clone());
        let run = engines
            .start_mihomo(&plan.compiled, socks, controller, op)
            .await?;
        work.core = Some(run.clone());
        let creds = plan.socks.creds();
        let probe = engines
            .egress_via(&plan.profile.profile, plan.socks.port(), creds, None, op)
            .await;
        let err = match probe {
            Ok(_) => {
                tracing::info!("AmneziaWG tunnel passed traffic");
                return Ok(());
            }
            Err(err) => err,
        };
        match echo_failure(&err) {
            Some(EchoFailure::NoAddress) => {
                tracing::info!("AmneziaWG tunnel passed traffic (the echo gave no address)");
                Ok(())
            }
            Some(EchoFailure::NoReply) => {
                let died = run.exit_watch().borrow().clone();
                if let Some(info) = died {
                    return Err(MihomoError::Exited(info).into());
                }
                let msg = Msg::new("tunnel.runtime.mihomo.noTraffic");
                Err(AppError::msg(ErrorKind::Network, msg).with_source(err))
            }
            // Cancelled, or the handshake budget said "not now": nothing was proven either way.
            None => Err(err),
        }
    }
}

/// Starts one mihomo run and waits for its readiness; a failed start stops it before returning.
pub(super) async fn start_run(
    exe: &std::path::Path,
    runs: &std::path::Path,
    logs: Option<&std::path::Path>,
    config: &Compiled,
    socks: SlotEndpoint,
    controller: ClashEndpoint,
    cancel: &CancellationToken,
) -> AppResult<Arc<dyn CoreProc>> {
    let run = MihomoProcess::spawn(exe, runs, config, socks, controller, logs)?;
    let ready = run
        .wait_ready(vpnte_engine::mihomo_process::READY_TIMEOUT, cancel)
        .await;
    if let Err(e) = ready {
        if let Err(stop) = run
            .terminate(vpnte_engine::mihomo_process::STOP_TIMEOUT)
            .await
        {
            tracing::warn!(error = %stop, "failed mihomo start: exit not proven");
        }
        return Err(e.into());
    }
    Ok(Arc::new(run))
}

#[async_trait]
impl CoreProc for MihomoProcess {
    fn pid(&self) -> u32 {
        MihomoProcess::pid(self)
    }
    /// Readiness was proven by [`start_run`]; this only maps a late check for the trait.
    async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError> {
        MihomoProcess::wait_ready(self, timeout, cancel)
            .await
            .map_err(|e| match e {
                MihomoError::Exited(info) => StartError::Exited(info),
                MihomoError::Timeout => StartError::Timeout,
                MihomoError::Cancelled => StartError::Cancelled,
                other => StartError::Spawn(std::io::Error::other(other)),
            })
    }
    async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError> {
        MihomoProcess::terminate(self, within).await
    }
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        MihomoProcess::exit_watch(self)
    }
    fn recent_fault(&self) -> Option<OutboundFault> {
        MihomoProcess::recent_fault(self)
    }
}

/// `core` (the session's sing-box) chained with `upstream` (its mihomo run), or `core` alone.
/// The actor then supervises one core: a stop ends both, either one dying is the session's
/// crash, and the fault of the AmneziaWG hop is the one that counts. The pair is supervised
/// only from the moment sing-box is ready (audit mihomo-a1): a sing-box that dies on a port race
/// leaves the mihomo run untouched for the retry with fresh ports.
pub(super) fn chain(
    core: Arc<dyn CoreProc>,
    upstream: Option<Arc<dyn CoreProc>>,
) -> Arc<dyn CoreProc> {
    let Some(upstream) = upstream else {
        return core;
    };
    let (tx, exit) = watch::channel(None);
    Arc::new(Chained {
        core,
        upstream,
        exit,
        unarmed: Mutex::new(Some(tx)),
    })
}

/// The error that ended a chained start: mihomo's own exit when the run behind sing-box died
/// (its message names mihomo, not sing-box), else `err`.
pub(super) fn start_error(err: StartError, upstream: Option<&Arc<dyn CoreProc>>) -> AppError {
    let died = upstream.and_then(|up| up.exit_watch().borrow().clone());
    match (err, died) {
        (StartError::Exited(_), Some(info)) => MihomoError::Exited(info).into(),
        (err, _) => err.into(),
    }
}

/// Unreachable in practice (`wait_for(is_some)` returned): an empty exit, never a panic.
fn gone() -> ExitInfo {
    ExitInfo {
        at: std::time::SystemTime::now(),
        code: None,
        stderr_tail: String::new(),
        user_initiated: false,
        graceful: false,
        bind_failures: Vec::new(),
        access_denied: false,
    }
}

struct Chained {
    core: Arc<dyn CoreProc>,
    upstream: Arc<dyn CoreProc>,
    exit: watch::Receiver<Option<ExitInfo>>,
    /// The exit sender until the pair is supervised ([`Chained::arm`]).
    unarmed: Mutex<Option<watch::Sender<Option<ExitInfo>>>>,
}

impl Chained {
    /// Starts the supervision once: the first exit of either half ends the other half too (one
    /// half alone cannot carry the session) and is published as the pair's exit.
    fn arm(&self) {
        let Some(tx) = self.unarmed.lock().take() else {
            return;
        };
        let (mut a, mut b) = (self.core.exit_watch(), self.upstream.exit_watch());
        // Weak: the watcher must never keep a dropped pair alive (a drop is the kill).
        let (weak_core, weak_up) = (Arc::downgrade(&self.core), Arc::downgrade(&self.upstream));
        tokio::spawn(async move {
            let (first, other): (ExitInfo, Weak<dyn CoreProc>) = tokio::select! {
                Ok(info) = a.wait_for(Option::is_some) => (info.clone().unwrap_or_else(gone), weak_up),
                Ok(info) = b.wait_for(Option::is_some) => (info.clone().unwrap_or_else(gone), weak_core),
                else => return,
            };
            if let Some(other) = other.upgrade()
                && other.exit_watch().borrow().is_none()
            {
                let _ = other.terminate(Duration::from_secs(3)).await;
            }
            tx.send_replace(Some(first));
        });
    }
}

#[async_trait]
impl CoreProc for Chained {
    fn pid(&self) -> u32 {
        self.core.pid()
    }
    /// sing-box's readiness raced with the mihomo run's exit; ready arms the supervision.
    async fn wait_ready(
        &self,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), StartError> {
        let mut upstream = self.upstream.exit_watch();
        let ready = tokio::select! {
            biased;
            Ok(info) = upstream.wait_for(Option::is_some) => {
                Err(StartError::Exited(info.clone().unwrap_or_else(gone)))
            }
            ready = self.core.wait_ready(timeout, cancel) => ready,
        };
        if ready.is_ok() {
            self.arm();
        }
        ready
    }
    /// sing-box first (its inbound closes before the hop behind it), then mihomo; the exit of
    /// both must be proven.
    async fn terminate(&self, within: Duration) -> Result<ExitInfo, StopError> {
        let core = self.core.terminate(within).await;
        let upstream = self.upstream.terminate(within).await;
        upstream?;
        core
    }
    fn exit_watch(&self) -> watch::Receiver<Option<ExitInfo>> {
        self.exit.clone()
    }
    fn recent_fault(&self) -> Option<OutboundFault> {
        self.upstream
            .recent_fault()
            .or_else(|| self.core.recent_fault())
    }
}
