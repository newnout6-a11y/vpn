//! Start: admission, bring-up in the decided order (tunnel-core §3.2) and the one compensation
//! function (§3.4). Nothing is published as running before the capture proof and, for the Xray
//! slots, the confirmed selector.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Engine, ProxyKind, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_engine::singbox_config::{self, Upstream};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::xray_config::{self, ProxyGraph, ResolvePath, Resolved};
use vpnte_engine::xray_process::{SlotLaunch, XrayEvent};
use vpnte_profiles::emit_singbox::EmitPolicy;

use super::actor::{Actor, Phase, Retained, Session, SlotSession};
use super::capture::CapturePlan;
use super::config;
use super::engines::{CoreProc, Engines};
use super::spawn::Parts;
use crate::api::{
    CaptureKind, Mode, Origin, StartReceipt, StartRequest, TunError, TunStatusKind, TunnelEvent,
    VpnProfile,
};

/// Effects of a start in progress: exactly what the compensation must undo.
#[derive(Default)]
pub(super) struct Work {
    /// Protection held before this start (preserved stop, crash): a failed start keeps it.
    pub prior: Option<CapturePlan>,
    pub plan: Option<CapturePlan>,
    /// `Capture::begin` ran: this start engaged the protection.
    pub began: bool,
    pub core: Option<Arc<dyn CoreProc>>,
    pub slots: Option<SlotSession>,
    pub events: Option<mpsc::Receiver<XrayEvent>>,
    pub warnings: Vec<Msg>,
}

/// The upstream decided before any effect.
pub(super) enum Planned {
    Local {
        addr: HostPort,
        kind: ProxyKind,
        owner: Option<PathBuf>,
    },
    Native(Upstream),
    Xray {
        graph: ProxyGraph,
        resolved: Resolved,
        profile: VpnProfile,
    },
}

pub(super) fn cancelled_if(op: &CancellationToken) -> AppResult<()> {
    if op.is_cancelled() {
        return Err(AppError::cancelled());
    }
    Ok(())
}

impl Actor {
    /// A start from the lane: admission, then the start.
    pub(super) async fn cmd_start(
        &mut self,
        req: StartRequest,
        cancel: CancellationToken,
        stops: u64,
    ) -> Result<StartReceipt, TunError> {
        // A stop issued after this start was requested wins, even if it was queued first.
        if self.shared.stops.load(Ordering::SeqCst) != stops || cancel.is_cancelled() {
            return Err(AppError::cancelled().into());
        }
        if matches!(self.phase, Phase::Running(_)) {
            let msg = Msg::new("tunnel.runtime.alreadyRunning");
            return Err(TunError::new(ErrorKind::Conflict, msg));
        }
        let op = cancel.child_token();
        self.guard_op(&op);
        let result = self.start_run(req, &op, &[]).await;
        self.clear_op();
        result
    }

    /// Leaves a crashed or faulted state before anything new exists. A retained run whose exit
    /// still cannot be proven refuses the start.
    pub(super) async fn retire(&mut self) -> Result<(), TunError> {
        match std::mem::replace(&mut self.phase, Phase::Idle) {
            Phase::Crashed(c) => {
                self.restart_due = None;
                // A recovery start allocates fresh slots, ports and credentials.
                if let Some(mut slots) = c.slots
                    && let Err(e) = slots.slots.stop_all().await
                {
                    tracing::warn!(error = %e, "crashed run's Xray did not stop");
                    let warning = Msg::new("tunnel.runtime.cleanup.xray");
                    self.phase = Phase::Faulted(Box::new(Retained {
                        core: None,
                        slots: Some(slots),
                        plan: Some(c.plan),
                    }));
                    self.publish(|s| s.warning = Some(warning.clone()));
                    self.announce(TunStatusKind::Error { warning });
                    return Err(previous_not_stopped());
                }
                self.phase = Phase::Adapting(c.plan);
                Ok(())
            }
            Phase::Faulted(mut r) => {
                if let Some(core) = r.core.take()
                    && let Err(e) = core.terminate(self.deps.timings.exit).await
                {
                    tracing::warn!(error = %e, "retained sing-box still not proven gone");
                    r.core = Some(core);
                    self.phase = Phase::Faulted(r);
                    return Err(previous_not_stopped());
                }
                if let Some(mut slots) = r.slots.take()
                    && let Err(e) = slots.slots.stop_all().await
                {
                    tracing::warn!(error = %e, "retained Xray still not proven gone");
                    r.slots = Some(slots);
                    self.phase = Phase::Faulted(r);
                    return Err(previous_not_stopped());
                }
                self.phase = match r.plan {
                    Some(plan) => Phase::Adapting(plan),
                    None => {
                        // Held with no plan to continue it: the next full stop releases it.
                        self.protection_dirty = true;
                        Phase::Idle
                    }
                };
                Ok(())
            }
            other => {
                self.phase = other;
                Ok(())
            }
        }
    }
}

fn previous_not_stopped() -> TunError {
    TunError::new(
        ErrorKind::Conflict,
        Msg::new("tunnel.runtime.previousNotStopped"),
    )
}

impl Actor {
    /// Makes `kind` the strategy of the next session. A strategy the host did not supply (TUN
    /// without elevation) answers `Permission`. Protection the previous strategy still holds
    /// (preserved stop, blocking crash outcome, failed release) is released first: two
    /// strategies never share a session; a failed release refuses the start.
    async fn adopt_strategy(&mut self, kind: CaptureKind) -> Result<(), TunError> {
        let next = match kind {
            CaptureKind::Tun => self.deps.tun.clone().ok_or_else(|| {
                let msg = Msg::new("tunnel.runtime.tunUnavailable");
                TunError::new(ErrorKind::Permission, msg)
            })?,
            CaptureKind::Proxy => self.deps.proxy.clone(),
        };
        if kind == self.strategy {
            return Ok(());
        }
        if matches!(self.phase, Phase::Adapting(_)) || self.protection_dirty {
            if let Err(e) = self.capture.release().await {
                tracing::error!(error = %e, "previous strategy's protection not released");
                self.protection_dirty = true;
                let msg = Msg::new("tunnel.runtime.cleanup.protection");
                return Err(TunError::new(e.kind, msg));
            }
            self.protection_dirty = false;
            self.phase = Phase::Idle;
        }
        tracing::info!(strategy = ?kind, "capture strategy changed");
        self.capture = next;
        self.strategy = kind;
        Ok(())
    }
}

impl Actor {
    /// One start under `op`: a new native generation, `StartBegan` / `StartFinished` exactly
    /// once, compensation of every effect on failure. `avoid` = capture identities not to reuse.
    pub(super) async fn start_run(
        &mut self,
        req: StartRequest,
        op: &CancellationToken,
        avoid: &[String],
    ) -> Result<StartReceipt, TunError> {
        self.retire().await?;
        self.adopt_strategy(req.capture).await?;
        if req.origin != Origin::Recovery {
            // Every start but a crash recovery (protected restarts included) reopens the
            // auto-restart window (§3.5 (d)).
            self.restart_due = None;
            self.attempt = 0;
            self.failover_tried = false;
        }
        let prior = match &self.phase {
            Phase::Adapting(plan) => Some(plan.clone()),
            _ => None,
        };
        self.generation += 1;
        let generation = self.generation;
        self.emit(TunnelEvent::StartBegan { generation });
        let mut work = Work {
            prior,
            ..Work::default()
        };
        let result = self.bring_up(&req, op, avoid, &mut work).await;
        match result {
            Ok(session) => {
                let receipt = StartReceipt {
                    generation,
                    pid: session.core.pid(),
                    started_at: session.started_at,
                    engine: session.engine,
                    warnings: std::mem::take(&mut work.warnings),
                };
                for w in &receipt.warnings {
                    self.warn(crate::api::TunWarning::from_msg(w.clone()));
                }
                self.enter_running(session, work.events.take());
                self.emit(TunnelEvent::StartFinished {
                    generation,
                    ok: true,
                });
                Ok(receipt)
            }
            Err(cause) => {
                tracing::warn!(error = %cause, generation, "tunnel start failed");
                let err = self.compensate(work, cause).await;
                self.emit(TunnelEvent::StartFinished {
                    generation,
                    ok: false,
                });
                Err(err)
            }
        }
    }

    /// The upstream as far as it can be decided without effects (Xray names are resolved here,
    /// before the protection blocks the system resolver).
    async fn plan_upstream(
        &self,
        req: &StartRequest,
        phys_dns: &[std::net::Ipv4Addr],
        op: &CancellationToken,
        work: &mut Work,
    ) -> AppResult<Planned> {
        match &req.mode {
            Mode::LocalProxy { addr, kind } => {
                let addr = config::proxy_addr(addr)?;
                let owner = self
                    .deps
                    .engines
                    .local_proxy(&addr, self.deps.timings.proxy_listen)
                    .await?;
                Ok(Planned::Local {
                    addr,
                    kind: *kind,
                    owner,
                })
            }
            Mode::DirectVpn { profile } => {
                let engine = xray_config::select_engine(&profile.profile, req.engine).engine()?;
                if engine == Engine::SingBox {
                    let policy = EmitPolicy {
                        device: profile.device,
                        tls_compat: req.stealth
                            || req.adaptive == vpnte_base::types::AdaptiveMode::TlsCompatibility,
                        ..EmitPolicy::default()
                    };
                    let upstream = Upstream::native(&profile.profile, &policy).map_err(|e| {
                        AppError::validation(Msg::new("tunnel.runtime.profileUnusable"))
                            .with_source(e)
                    })?;
                    return Ok(Planned::Native(upstream));
                }
                let device = profile.device.unwrap_or_default();
                let mut graph = xray_config::proxy_graph(&profile.profile, device)?;
                let bootstrap =
                    SocketAddr::from((singbox_config::bootstrap_resolver(phys_dns), 53));
                let path = ResolvePath::System { bootstrap };
                let resolved = self.deps.engines.resolve(&graph.hosts(), path, op).await?;
                work.warnings.extend(resolved.warning());
                graph.substitute(&resolved.addrs);
                Ok(Planned::Xray {
                    graph,
                    resolved,
                    profile: profile.clone(),
                })
            }
        }
    }
}

impl Actor {
    /// Every step of a start; each effect is recorded in `work` before the next await.
    async fn bring_up(
        &mut self,
        req: &StartRequest,
        op: &CancellationToken,
        avoid: &[String],
        work: &mut Work,
    ) -> AppResult<Box<Session>> {
        let user = self.deps.inputs.snapshot().await?;
        let plan = self.capture.prepare(req, avoid).await?;
        work.warnings.extend(plan.warnings.iter().cloned());
        work.plan = Some(plan.clone());
        cancelled_if(op)?;
        let phys_dns = self.deps.engines.physical_dns().await;
        let planned = self.plan_upstream(req, &phys_dns, op, work).await?;
        cancelled_if(op)?;
        let (programs, own): (Vec<PathBuf>, Vec<PathBuf>) = match &planned {
            Planned::Local { owner, .. } => (
                owner.iter().cloned().collect(),
                owner.iter().cloned().collect(),
            ),
            Planned::Native(_) => (Vec::new(), Vec::new()),
            Planned::Xray { .. } => (Vec::new(), vec![self.deps.engines.xray_exe()]),
        };
        let engine_paths = direct_engines(&*self.deps.engines, req.capture, own);
        let hostname = match &req.mode {
            Mode::DirectVpn { profile } => config::endpoint_is_hostname(&profile.profile),
            Mode::LocalProxy { .. } => false,
        };
        self.capture.begin(&plan, &programs).await?;
        work.began = true;
        cancelled_if(op)?;
        if let Planned::Xray {
            graph,
            resolved,
            profile,
        } = &planned
        {
            self.start_slot_a(graph, resolved, profile, op, work)
                .await?;
        }
        let local = matches!(planned, Planned::Local { .. });
        let (routing, warnings) = config::routing(&user, &engine_paths, local, &phys_dns, hostname);
        work.warnings.extend(warnings);
        let parts = Parts {
            plan: &plan,
            planned: &planned,
            routing,
            phys_dns,
            direct_vpn: !local,
        };
        let (core, clash, listeners, compat) = self.spawn_ready(&parts, op, work).await?;
        let proof = self
            .capture
            .ready(&plan, self.deps.timings.capture_ready, op)
            .await?;
        if let Some(slots) = work.slots.as_mut() {
            // A config default is not read-back proof: select explicitly and read it back.
            self.deps.engines.select(&clash, Slot::A).await?;
            slots.slots.activate(Slot::A)?;
            slots.dns_bootstrap = listeners.dns_bootstrap.unwrap_or_default();
        }
        cancelled_if(op)?;
        let logs = self.deps.engines.log_files(work.slots.is_some());
        let endpoints = config::endpoints(&clash, &listeners, &proof, logs);
        let engine = if work.slots.is_some() {
            Engine::Xray
        } else {
            Engine::SingBox
        };
        Ok(Box::new(Session {
            generation: self.generation,
            req: req.clone(),
            plan,
            proof,
            core,
            slots: work.slots.take(),
            clash,
            listeners,
            compat,
            engine,
            started_at: now_ms(),
            endpoints,
            watch: CancellationToken::new(),
            competing: None,
        }))
    }

    /// Slot A of a cold start: its own SOCKS readiness and an egress proof before any route
    /// points into the tunnel.
    async fn start_slot_a(
        &self,
        graph: &ProxyGraph,
        resolved: &Resolved,
        profile: &VpnProfile,
        op: &CancellationToken,
        work: &mut Work,
    ) -> AppResult<()> {
        let a = SlotEndpoint::allocate(&[])?;
        let b = SlotEndpoint::allocate(&[a.port()])?;
        let (tx, rx) = mpsc::channel(8);
        work.events = Some(rx);
        let launch = SlotLaunch {
            config: xray_config::build_config(graph, &a)
                .to_string()
                .into_bytes(),
            dial_target: resolved
                .addrs
                .values()
                .next()
                .map(|ip| SocketAddr::new(*ip, profile.profile.port)),
        };
        let mut session = SlotSession {
            slots: self.deps.engines.slots(tx),
            endpoints: [a.clone(), b],
            active: Slot::A,
            egress: [None, None],
            dns_bootstrap: 0,
            suspect: false,
            restarts: Vec::new(),
        };
        let started = session.slots.start(Slot::A, a.clone(), launch, op).await;
        work.slots = Some(session);
        started?;
        let ip = self
            .deps
            .engines
            .egress_via(a.port(), a.creds(), op)
            .await?;
        if let Some(s) = work.slots.as_mut() {
            s.egress[Slot::A.index()] = Some(ip);
        }
        Ok(())
    }
}

/// Engines whose own traffic leaves directly: `own` (the session's Xray or local-proxy owner)
/// and, while our TUN captures the machine, the bundled sing-box and Xray images. The main
/// sing-box dials from the physical interface and never enters its own TUN, so that rule matches
/// only the other processes of these images: external proxy slots and probe engines, whose
/// traffic would otherwise loop through the tunnel (spec external-proxy §3.28, decision 5).
pub(super) fn direct_engines(
    engines: &dyn Engines,
    capture: CaptureKind,
    mut own: Vec<PathBuf>,
) -> Vec<PathBuf> {
    if capture == CaptureKind::Tun {
        own.extend([engines.singbox_exe(), engines.xray_exe()]);
    }
    own
}
