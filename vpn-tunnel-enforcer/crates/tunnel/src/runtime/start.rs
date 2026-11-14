//! Start: admission, bring-up in the decided order (tunnel-core §3.2) and the one compensation
//! function (§3.4). Nothing is published as running before the capture proof and, for the Xray
//! slots, the confirmed selector.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, Engine, EnginePref, KillSwitchLevel, ProxyKind, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::HostPort;
use vpnte_engine::clash_api::ClashEndpoint;
use vpnte_engine::singbox_config::{Listeners, Upstream};
use vpnte_engine::slot::{Slot, SlotEndpoint};
use vpnte_engine::tags::DNS_DIRECT;
use vpnte_engine::xray_config::{self, Decision, ProxyGraph, Reject, ResolvePath, Resolved};
use vpnte_engine::xray_process::{SlotLaunch, XrayEvent};
use vpnte_profiles::emit_singbox::EmitPolicy;
use vpnte_profiles::model::Profile;
use vpnte_winnet::adapters::{TUN_V4, TUN_V6};

use super::actor::{Actor, Phase, Retained, Session, SlotSession};
use super::capture::{Capture, CapturePlan};
use super::engines::{CoreProc, EchoFailure, Engines, WARM_NAME, echo_failure};
use super::pin::pin_native;
use super::spawn::Parts;
use super::{UserInputs, config};
use crate::api::{
    CaptureKind, EngineRun, Mode, NameHint, Origin, StartReceipt, StartRequest, TunError,
    TunStatusKind, TunnelEvent, VpnProfile,
};

/// The engine `server` runs on under its own choice and the app setting, with the reason; a
/// profile the chosen engine cannot run is refused, never moved to the other engine.
pub(super) fn choose(server: &VpnProfile, setting: EnginePref) -> Result<EngineRun, Reject> {
    let pref = xray_config::server_pref(setting, server.engine);
    match xray_config::select_engine(&server.profile, pref) {
        Decision::Selected { engine, reason } => Ok(EngineRun {
            kind: engine,
            reason: Some(reason),
        }),
        Decision::Rejected(reject) => Err(reject),
    }
}

/// The engine run of `req` before any effect (a local upstream proxy is forwarded by sing-box).
fn run_of(req: &StartRequest) -> Result<EngineRun, Reject> {
    match &req.mode {
        Mode::LocalProxy { .. } => Ok(EngineRun {
            kind: Engine::SingBox,
            reason: None,
        }),
        Mode::DirectVpn { profile } => choose(profile, req.engine),
    }
}

/// Stealth or adaptive TLS compatibility: the app default of TLS tricks is «Сильно».
fn tls_compat(req: &StartRequest) -> bool {
    req.stealth || req.adaptive == AdaptiveMode::TlsCompatibility
}

/// `profile` as Xray runs it under `req`: `proxy_graph` has no stealth input, so the app's
/// default TLS tricks are resolved into the key's own value first (item 18), the same rule as
/// the sing-box emitter's.
pub(super) fn xray_profile(profile: &Profile, req: &StartRequest) -> Profile {
    let mut run = profile.clone();
    let tricks = run.tls_tricks_for(tls_compat(req));
    if let Some(tls) = run.tls.as_mut() {
        tls.tricks = Some(tricks);
    }
    run
}

/// What Xray drops of `profile` under `req` (stealth / TLS compatibility included): shown with
/// the start and the server switch (engine API: call it whenever Xray runs the profile, with
/// the profile [`xray_profile`] made).
pub(super) fn xray_warnings(profile: &Profile, req: &StartRequest) -> Vec<Msg> {
    xray_config::warnings(profile, tls_compat(req))
}

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
    /// The server names this start looked up itself, with their answers: kept for the session
    /// once it runs, dropped from the resolver's memory when the start fails (speed3 S3-09).
    pub names: Vec<(String, Vec<IpAddr>)>,
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
    /// WP-12 lab: AmneziaWG on mihomo, chained behind sing-box.
    #[cfg(feature = "lab")]
    Mihomo(Box<super::mihomo::MihomoPlan>),
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
    /// The capture of `kind`; a strategy the host did not supply (TUN without elevation)
    /// answers `Permission`, before anything runs.
    fn supplied(&self, kind: CaptureKind) -> Result<Arc<dyn Capture>, TunError> {
        match kind {
            CaptureKind::Tun => self.deps.tun.clone().ok_or_else(|| {
                let msg = Msg::new("tunnel.runtime.tunUnavailable");
                TunError::new(ErrorKind::Permission, msg)
            }),
            CaptureKind::Proxy => Ok(self.deps.proxy.clone()),
        }
    }

    /// Makes `next` (of `kind`) the strategy of the next session. Protection the previous
    /// strategy still holds (preserved stop, blocking crash outcome, failed release) is released
    /// first: two strategies never share a session; a failed release refuses the start.
    async fn adopt_strategy(
        &mut self,
        kind: CaptureKind,
        next: Arc<dyn Capture>,
    ) -> Result<(), TunError> {
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
        let capture = self.supplied(req.capture)?;
        self.retire().await?;
        self.adopt_strategy(req.capture, capture).await?;
        if req.origin != Origin::Recovery {
            // Every start but a crash recovery (protected restarts included) reopens the
            // auto-restart window (§3.5 (d)).
            self.restart_due = None;
            self.attempt = 0;
            self.failover_tried = false;
            self.slow = 0;
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
                let started_at = session.started_at;
                self.enter_running(session, work.events.take());
                // After the status shows the session: whoever ends sessions by it never takes
                // these names for the end of a session that did not run yet.
                vpnte_core::resolve::keep_resolved(started_at, &work.names);
                if let Some((profile_id, cause)) = self.failing_over.take() {
                    // Before the finish: whoever judges the run must know which server it is.
                    self.emit(TunnelEvent::FailedOver {
                        generation,
                        profile_id,
                        cause,
                    });
                }
                self.emit(TunnelEvent::StartFinished {
                    generation,
                    ok: true,
                });
                Ok(receipt)
            }
            Err(cause) => {
                self.failing_over = None;
                tracing::warn!(error = %cause, generation, "tunnel start failed");
                if cause.kind != ErrorKind::Cancelled {
                    // S3-09 (e): a remembered answer may be what failed; the next start asks.
                    let names: Vec<String> = work.names.iter().map(|(n, _)| n.clone()).collect();
                    vpnte_core::resolve::drop_names(&names);
                }
                let err = self.compensate(work, cause).await;
                self.emit(TunnelEvent::StartFinished {
                    generation,
                    ok: false,
                });
                Err(err)
            }
        }
    }

    /// The upstream as far as it can be decided without effects. Server names are resolved here
    /// (Xray's always, a native profile's to pin its address), before the protection blocks
    /// the system resolver.
    async fn plan_upstream(
        &self,
        req: &StartRequest,
        engine: Engine,
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
                #[cfg(feature = "lab")]
                if engine == Engine::Mihomo {
                    let engines = &*self.deps.engines;
                    let held = work.plan.as_ref().map(|p| self.capture.ports(p));
                    let held = held.unwrap_or_default();
                    let (plan, warnings) = super::mihomo::plan(engines, profile, &held, op).await?;
                    work.warnings.extend(warnings);
                    return Ok(Planned::Mihomo(Box::new(plan)));
                }
                if engine == Engine::SingBox {
                    let policy = EmitPolicy {
                        device: profile.device,
                        tls_compat: tls_compat(req),
                        ..EmitPolicy::default()
                    };
                    let mut upstream =
                        Upstream::native(&profile.profile, &policy).map_err(|e| {
                            AppError::validation(Msg::new("tunnel.runtime.profileUnusable"))
                                .with_source(e)
                        })?;
                    if let Upstream::Native { fragment, .. } = &mut upstream {
                        // Audit item 18: a TLS spoof needs an elevated sing-box; never start a
                        // config that needs rights this process does not have.
                        let elevated = vpnte_winnet::elevation::is_elevated();
                        if vpnte_engine::singbox_config::gate_spoof(fragment, elevated) {
                            let name = profile.profile.name.as_str();
                            let msg = Msg::new("tunnel.runtime.spoofDropped").arg("name", name);
                            work.warnings.push(msg);
                        }
                        let engines = &*self.deps.engines;
                        work.warnings
                            .extend(pin_native(engines, fragment, op).await?);
                    }
                    if let vpnte_profiles::model::Host::Domain(name) = &profile.profile.server {
                        // Its pin looked the name up (S3-09 (e): dropped if the start fails).
                        work.names = vec![(name.to_string(), Vec::new())];
                    }
                    return Ok(Planned::Native(upstream));
                }
                let device = profile.device.unwrap_or_default();
                let run = xray_profile(&profile.profile, req);
                let mut graph = xray_config::proxy_graph(&run, device)?;
                work.warnings.extend(xray_warnings(&run, req));
                // S3-09 (b): the app's own answers for this start only (read once).
                let facts = self.deps.inputs.server_facts(&profile.id);
                let (hinted, ask) = hinted(&graph.hosts(), &facts.hints);
                let mut resolved = Resolved {
                    addrs: HashMap::new(),
                    warning: None,
                };
                if !ask.is_empty() {
                    let path = ResolvePath::Direct;
                    resolved = self.deps.engines.resolve(&ask, path, op).await?;
                }
                work.names = (ask.iter())
                    .map(|n| {
                        (
                            n.clone(),
                            resolved.addrs.get(n).copied().into_iter().collect(),
                        )
                    })
                    .collect();
                if !hinted.is_empty() {
                    tracing::info!(names = hinted.len(), "server names from the app's hints");
                }
                resolved.addrs.extend(hinted);
                work.warnings.extend(resolved.warning.clone());
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
        // Lab live-9 L9-2: the helper service checks a handed-over Smart RU set inside this
        // snapshot (4.7 s of a first connect); only the sing-box config needs it, so it is read
        // beside the capture, the upstream plan and slot A, and awaited at the config.
        let inputs = self.deps.inputs.clone();
        let mut user = Snapshot(tokio::spawn(async move { inputs.snapshot().await }));
        // Decided once, before any effect: the run, the receipt and the status show this engine.
        let engine = run_of(req)?;
        #[cfg(feature = "lab")]
        super::mihomo::admit(&engine, req)?;
        let step = Instant::now();
        let plan = self.capture.prepare(req, avoid).await?;
        tracing::info!(ms = ms_since(step), "capture prepared");
        work.warnings.extend(plan.warnings.iter().cloned());
        work.plan = Some(plan.clone());
        cancelled_if(op)?;
        let step = Instant::now();
        let phys_dns = self.deps.engines.physical_dns().await;
        // S3-09 (d): its own line inside «upstream planned» (ms only, never the resolvers).
        tracing::info!(ms = ms_since(step), "physical dns read");
        let planned = self.plan_upstream(req, engine.kind, op, work).await?;
        tracing::info!(ms = ms_since(step), "upstream planned");
        cancelled_if(op)?;
        let (programs, own): (Vec<PathBuf>, Vec<PathBuf>) = match &planned {
            Planned::Local { owner, .. } => (
                owner.iter().cloned().collect(),
                owner.iter().cloned().collect(),
            ),
            Planned::Native(_) => (Vec::new(), Vec::new()),
            Planned::Xray { .. } => (Vec::new(), vec![self.deps.engines.xray_exe()]),
            // sing-box dials loopback only; mihomo's own traffic is the Proxy-mode case (no TUN).
            #[cfg(feature = "lab")]
            Planned::Mihomo(_) => (Vec::new(), Vec::new()),
        };
        let engine_paths = direct_engines(&*self.deps.engines, req.capture, own);
        let hostname = match &req.mode {
            Mode::DirectVpn { profile } => config::endpoint_is_hostname(&profile.profile),
            Mode::LocalProxy { .. } => false,
        };
        // The app resolved mihomo's peer names itself: sing-box dials only loopback.
        #[cfg(feature = "lab")]
        let hostname = hostname && !matches!(planned, Planned::Mihomo(_));
        let step = Instant::now();
        self.capture.begin(&plan, &programs).await?;
        tracing::info!(ms = ms_since(step), "capture began");
        work.began = true;
        cancelled_if(op)?;
        let slot_a = match &planned {
            Planned::Xray {
                graph,
                resolved,
                profile,
            } => {
                let held = self.capture.ports(&plan);
                let settle = self
                    .start_slot_a(graph, resolved, profile, &held, op, work)
                    .await?;
                let a = work
                    .slots
                    .as_ref()
                    .map(|s| s.endpoints[Slot::A.index()].clone());
                a.map(|a| (profile, a, settle))
            }
            _ => None,
        };
        let guard = self.capture.guard(&plan);
        let beside = runs_beside(
            req,
            self.failing_over.is_some(),
            work.prior.is_some(),
            guard,
        );
        // Lab live-10 L10-2: a crash recovery's server carried this user's traffic until the
        // crash, and the programs reconnect through the new core (the system proxy and the
        // TUN's routes stay): bytes back through slot A prove it as well as an echo does.
        let own_traffic = beside && req.origin == Origin::Recovery && self.failing_over.is_none();
        let (core_up, core_seen) = oneshot::channel();
        let mut core_seen = own_traffic.then_some(core_seen);
        let mut proving = None;
        if let Some((profile, a, settle)) = &slot_a {
            self.proving(engine);
            let proof = self.prove_exit_a(profile, a, *settle, req.origin, core_seen.take(), op);
            if beside {
                proving = Some(proof);
            } else {
                let ip = proof.await?;
                record_exit_a(work, ip);
            }
        }
        #[cfg(feature = "lab")]
        if let Planned::Mihomo(plan) = &planned {
            self.start_mihomo(plan, op, work).await?;
        }
        let local = matches!(planned, Planned::Local { .. });
        // speed3 S3-03 (feasibility review): the inputs and the routing are part of the core's
        // way up, so a proof beside it runs from the moment slot A accepts, not after them.
        let up = async {
            let step = Instant::now();
            let user = (&mut user.0).await.map_err(AppError::internal)??;
            tracing::info!(ms = ms_since(step), "routing inputs ready");
            let (routing, warnings) =
                config::routing(&user, &engine_paths, local, &phys_dns, hostname);
            work.warnings.extend(warnings);
            let warm = req.capture == CaptureKind::Tun && warms_through_tunnel(&routing.dns_rules);
            let parts = Parts {
                plan: &plan,
                planned: &planned,
                routing,
                phys_dns,
                direct_vpn: !local,
            };
            let step = Instant::now();
            let ready = self.spawn_ready(&parts, op, work).await?;
            tracing::info!(ms = ms_since(step), "sing-box ready");
            if warm {
                // S3-05: one per TUN start; option W off (owner default 5): «Подключено» never
                // waits for it, and a dropped request would cancel the dial inside sing-box.
                let (engines, clash) = (self.deps.engines.clone(), ready.1.clone());
                tokio::spawn(async move { engines.warm_dns(&clash).await });
            }
            // From here the traffic of a recovery can be read (L10-2).
            let _ = core_up.send(ready.1.clone());
            let step = Instant::now();
            let timeout = self.deps.timings.capture_ready;
            let proof = self.capture.ready(&plan, timeout, op).await?;
            tracing::info!(ms = ms_since(step), "capture ready");
            AppResult::Ok((ready, proof))
        };
        let ((core, clash, listeners, compat), proof) = match proving {
            Some(proving) => {
                let (exit, up) = tokio::join!(proving, up);
                // The proof's failure is the cause; the core it started meanwhile is compensated.
                let ip = exit?;
                let up = up?;
                record_exit_a(work, ip);
                up
            }
            None => up.await?,
        };
        if let Some(slots) = work.slots.as_mut() {
            // A config default is not read-back proof: select explicitly and read it back.
            self.deps.engines.select(&clash, Slot::A).await?;
            slots.slots.activate(Slot::A)?;
            slots.dns_bootstrap = listeners.dns_bootstrap.unwrap_or_default();
        }
        if let (Planned::Native(_), Mode::DirectVpn { profile }) = (&planned, &req.mode) {
            self.prove_native(&profile.profile, &listeners, engine, op)
                .await?;
        }
        cancelled_if(op)?;
        let logs = self.deps.engines.log_files(work.slots.is_some());
        let endpoints = config::endpoints(&clash, &listeners, &proof, logs);
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
            carried: Arc::default(),
        }))
    }

    /// Lab F-4 (p-live2): a native start is published only after traffic went through its
    /// server: an echo through the engine's probe inbound (`live-check-in`, always to the
    /// upstream whatever the user's rules say; loopback, so neither the TUN's routes nor the kill
    /// switch's filters stand in the way). A placeholder or a dead server fails the start here,
    /// it never reads as connected.
    async fn prove_native(
        &self,
        server: &Profile,
        listeners: &Listeners,
        engine: EngineRun,
        op: &CancellationToken,
    ) -> AppResult<()> {
        let probe = listeners.probe.as_ref();
        let Some((port, creds)) = probe.and_then(|p| Some((p.port, p.creds.as_ref()?))) else {
            // The config of a direct start always has it: without it nothing proves the exit.
            return Err(AppError::internal(std::io::Error::other(
                "no probe inbound to prove the exit",
            )));
        };
        self.proving(engine);
        let step = Instant::now();
        let proof = self
            .deps
            .engines
            .egress_via(server, port, creds, None, op)
            .await;
        tracing::info!(ms = ms_since(step), ok = proof.is_ok(), "native exit proof");
        match proof {
            Ok(_) => Ok(()),
            // Answers came back through the server: the traffic is proven, only the address
            // is unknown (the start page's exit check reads it later).
            Err(e) if echo_failure(&e) == Some(EchoFailure::NoAddress) => Ok(()),
            Err(e) => Err(exit_unproven(e)),
        }
    }

    /// The exit of the start in progress is being proven: its engine runs, the session is not
    /// published yet (the start page says «Проверяем выход…»).
    fn proving(&self, engine: EngineRun) {
        self.publish(|s| s.engine = Some(engine));
    }

    /// Slot A of a cold start up to its own SOCKS readiness; its exit proof is
    /// [`Actor::prove_slot_a`]. Returns the proof's settle point ([`settle_of`]).
    async fn start_slot_a(
        &self,
        graph: &ProxyGraph,
        resolved: &Resolved,
        profile: &VpnProfile,
        held: &[u16],
        op: &CancellationToken,
        work: &mut Work,
    ) -> AppResult<Option<Duration>> {
        // `held`: the capture's own listener (L9-1), never handed to a slot.
        let a = SlotEndpoint::allocate(held)?;
        let b = SlotEndpoint::allocate(&[held, &[a.port()]].concat())?;
        let settle = settle_of(graph);
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
            balanced: [settle.is_some(), false],
            dns_bootstrap: 0,
            suspect: false,
            restarts: Vec::new(),
        };
        let step = Instant::now();
        let started = session.slots.start(Slot::A, a.clone(), launch, op).await;
        work.slots = Some(session);
        started?;
        tracing::info!(ms = ms_since(step), "slot A accepts");
        Ok(settle)
    }

    /// The exit proof of slot A (`a`): traffic through its server before the session counts.
    async fn prove_slot_a(
        &self,
        profile: &VpnProfile,
        a: &SlotEndpoint,
        settle: Option<Duration>,
        origin: Origin,
        op: &CancellationToken,
    ) -> AppResult<std::net::IpAddr> {
        // Which start the echo's «handshake slot» wait belongs to (lab L10-2).
        tracing::info!(start = ?origin, "slot A exit proof begins");
        let step = Instant::now();
        let ip = self
            .deps
            .engines
            .egress_via(&profile.profile, a.port(), a.creds(), settle, op)
            .await
            .map_err(exit_unproven)?;
        tracing::info!(ms = ms_since(step), "slot A exit proven");
        Ok(ip)
    }

    /// Slot A's exit proof; `core` (a crash recovery of this server, L10-2) brings the new
    /// core's Clash API, and bytes back through slot A prove the exit as well. When the server
    /// name's handshake budget has no slot at once, the traffic gets [`OWN_TRAFFIC`] first and
    /// the echo waits for its slot only after it. `None` = proven by the traffic.
    async fn prove_exit_a(
        &self,
        profile: &VpnProfile,
        a: &SlotEndpoint,
        settle: Option<Duration>,
        origin: Origin,
        core: Option<oneshot::Receiver<ClashEndpoint>>,
        op: &CancellationToken,
    ) -> AppResult<Option<IpAddr>> {
        let Some(core) = core else {
            return self
                .prove_slot_a(profile, a, settle, origin, op)
                .await
                .map(Some);
        };
        let step = Instant::now();
        let free = self.deps.engines.handshake_ready(&profile.profile);
        let echo = async {
            if !free {
                tracing::info!("recovery: no handshake slot free now, its traffic proves it first");
                // A balanced graph's members carry traffic once its observatory judged them.
                let first = settle.unwrap_or_default() + OWN_TRAFFIC;
                tokio::select! {
                    () = op.cancelled() => return Err(AppError::cancelled()),
                    () = tokio::time::sleep(first) => {}
                }
            }
            self.prove_slot_a(profile, a, settle, origin, op).await
        };
        let traffic = async {
            match core.await {
                Ok(clash) => self.carried(&clash).await,
                // No core came up: the echo alone decides (the start fails anyway).
                Err(_) => std::future::pending().await,
            }
        };
        tokio::select! {
            ip = echo => ip.map(Some),
            () = traffic => {
                tracing::info!(ms = ms_since(step), "slot A proven by its traffic");
                Ok(None)
            }
        }
    }

    /// Returns once a connection through slot A of the core behind `clash` brought bytes back:
    /// the far side answered through the server (the switch's `confirm_by_traffic` rule).
    async fn carried(&self, clash: &ClashEndpoint) {
        loop {
            let seen = self.deps.engines.slot_downloads(clash, Slot::A).await;
            if seen.is_ok_and(|c| c.iter().any(|(_, down)| *down > 0)) {
                return;
            }
            tokio::time::sleep(TRAFFIC_POLL).await;
        }
    }
}

/// How long a recovery's own traffic may take to prove its server before the echo waits for a
/// handshake slot (L10-2; the switch's proof by traffic gets the same).
const OWN_TRAFFIC: Duration = Duration::from_secs(3);
/// How often the Clash API is read for that traffic (loopback; a fresh core holds few
/// connections).
const TRAFFIC_POLL: Duration = Duration::from_millis(100);

/// The core and its capture start beside slot A's exit proof (speed3 S3-03, S3-08). Under a kill
/// switch that holds the block (a recovery, a protected restart) traffic waits either way
/// (conn5). A Proxy start reaches nobody before its system proxy is written after the start; a
/// crash recovery's server carried this user's traffic until the crash; under «Строгий» the
/// block holds everything without a session, so a TUN start changes nothing for the user but
/// its speed (S3-08, first commit: «Стандартный» and «Выкл» wait for the owner, question 32).
/// A failover's sibling never carried this user's traffic: with the kill switch Off it keeps
/// the order, nobody is routed into an unproven server.
fn runs_beside(
    req: &StartRequest,
    failing_over: bool,
    prior: bool,
    guard: KillSwitchLevel,
) -> bool {
    let strict_tun = req.capture == CaptureKind::Tun && guard == KillSwitchLevel::Strict;
    let own = req.capture == CaptureKind::Proxy || req.origin == Origin::Recovery || strict_tun;
    (!failing_over && own) || (prior && guard != KillSwitchLevel::Off)
}

/// The session's DNS rules leave [`WARM_NAME`] on `dns-remote`, the DoH through the tunnel: no
/// rule sends it to the local network's resolver (S3-05, security review condition 1). A rule
/// this cannot read (a regex) counts as one that might.
pub(super) fn warms_through_tunnel(dns_rules: &[Value]) -> bool {
    let names_it = |rule: &Value| {
        let list = |key: &str| {
            let values = rule
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten();
            values
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
        };
        let suffix = |s: String| {
            let s = s.trim_start_matches('.');
            WARM_NAME == s || WARM_NAME.ends_with(&format!(".{s}"))
        };
        list("domain").any(|d| d == WARM_NAME)
            || list("domain_suffix").any(suffix)
            || list("domain_keyword").any(|k| WARM_NAME.contains(k.as_str()))
            || rule.get("domain_regex").is_some()
    };
    let direct = |rule: &&Value| rule.get("server").and_then(Value::as_str) == Some(DNS_DIRECT);
    !dns_rules.iter().filter(direct).any(names_it)
}

/// The app's hints for `hosts` (S3-09 (b), this start only): per hinted name the address a
/// lookup here could have answered (`may_be_server`, never our TUN's own networks), IPv4
/// first; the other names are asked. A hint names its host: it never stands in for another.
fn hinted(hosts: &[String], hints: &[NameHint]) -> (HashMap<String, IpAddr>, Vec<String>) {
    let usable = |ip: &&IpAddr| {
        let ours = match ip {
            IpAddr::V4(v4) => TUN_V4.contains(v4),
            IpAddr::V6(v6) => TUN_V6.contains(v6),
        };
        vpnte_core::resolve::may_be_server(**ip) && !ours
    };
    let mut found = HashMap::new();
    let mut ask = Vec::new();
    for host in hosts {
        let hint = hints.iter().find(|h| h.name.eq_ignore_ascii_case(host));
        let ip = hint.and_then(|h| h.addrs.iter().filter(usable).min_by_key(|ip| ip.is_ipv6()));
        match ip {
            Some(ip) => {
                found.insert(host.clone(), *ip);
            }
            None => ask.push(host.clone()),
        }
    }
    (found, ask)
}

/// Slot A's proven exit, kept for the switch's comparison (`None`: proven by its traffic, no
/// address read).
fn record_exit_a(work: &mut Work, ip: Option<IpAddr>) {
    if let Some(s) = work.slots.as_mut() {
        s.egress[Slot::A.index()] = ip;
    }
}

/// The inputs snapshot a start reads beside its first steps (lab live-9 L9-2). Review
/// speed2-b5: only the start that consumes the snapshot lets it finish. A start that returns
/// before (a failed plan, a cancel) aborts it, so a snapshot left running never writes its
/// rule-set report over a later start's: the helper service writes that report at the end.
struct Snapshot(tokio::task::JoinHandle<AppResult<UserInputs>>);

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Milliseconds since `at`, for the per-step timing lines (speed audit conn1: one lab run shows
/// where the seconds of a start go).
pub(super) fn ms_since(at: Instant) -> u64 {
    u64::try_from(at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Xray's burst observatory ping timeout when the provider sets none.
const OBSERVATORY_TIMEOUT: Duration = Duration::from_secs(5);
/// A provider's longer timeout still leaves the proof room for one request after it.
const SETTLE_CAP: Duration = Duration::from_secs(10);
/// The proof starts a little after Xray and its observatory's first round.
const SETTLE_MARGIN: Duration = Duration::from_millis(500);

/// When the balancer of a provider graph has judged its members, counted from the proof's start;
/// `None` when no balancer picks the route. Xray's observatory pings every member at start and a
/// member is "best" until its ping has failed (after the ping timeout), so a dead member may take
/// the first connections (lab live-7 F1: both echo requests went to a member that never
/// answered, and the start failed on a working server).
pub(super) fn settle_of(graph: &ProxyGraph) -> Option<Duration> {
    let ProxyGraph::Native(g) = graph else {
        return None;
    };
    g.entry.get("balancerTag")?;
    let timeout = g
        .burst_observatory
        .as_ref()
        .and_then(|o| o.pointer("/pingConfig/timeout"))
        .and_then(serde_json::Value::as_str)
        .and_then(go_duration)
        .unwrap_or(OBSERVATORY_TIMEOUT);
    Some(timeout.min(SETTLE_CAP) + SETTLE_MARGIN)
}

/// A Go duration as Xray configs write them (`5s`, `1m30s`, `500ms`); `None` when malformed.
fn go_duration(text: &str) -> Option<Duration> {
    let mut rest = text.trim();
    let mut total = Duration::ZERO;
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let value: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let seconds = match &rest[..unit] {
            "ms" => value / 1000.0,
            "s" => value,
            "m" => value * 60.0,
            "h" => value * 3600.0,
            _ => return None,
        };
        total += Duration::try_from_secs_f64(seconds).ok()?;
        rest = &rest[unit..];
    }
    Some(total).filter(|d| !d.is_zero())
}

/// A start's exit proof that got nothing back says what it means for the user: the server
/// carried no traffic (lab F-4: «через туннель» was wrong in Proxy mode, and the address was
/// never the point). Any other failure (a deferred handshake, a cancel) stays as it is.
fn exit_unproven(err: AppError) -> AppError {
    match echo_failure(&err) {
        Some(EchoFailure::NoReply) => {
            AppError::msg(ErrorKind::Network, Msg::new("tunnel.runtime.exitSilent"))
                .with_source(EchoFailure::NoReply)
        }
        _ => err,
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

#[cfg(test)]
mod proof_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::mpsc;
    use vpnte_base::types::{Creds, EnginePref};
    use vpnte_core::net::HostPort;
    use vpnte_engine::clash_api::ClashEndpoint;
    use vpnte_engine::xray_config::ResolveFault;

    use super::super::engines::{Slots, echo_failed};
    use super::super::tests::{FakeEngines, NATIVE_KEY, World, XRAY_KEY, deps, drain, vpn_req};
    use super::*;
    use crate::api::{Runtime, TunStatusKind};
    use crate::runtime::TunnelHandle;

    /// The test engines with the exit proof's answer set: `None` = the fake's address; `noisy`:
    /// the Xray slots' log reads as an unreachable server (what the core's death leaves there).
    struct Probed {
        inner: FakeEngines,
        answer: Option<EchoFailure>,
        noisy: bool,
    }

    /// Slots whose log says "unreachable" (the burst of closed connections a dead core leaves).
    struct NoisySlots(Box<dyn Slots>);

    #[async_trait]
    impl Slots for NoisySlots {
        async fn start(
            &mut self,
            slot: Slot,
            ep: SlotEndpoint,
            launch: SlotLaunch,
            cancel: &CancellationToken,
        ) -> Result<(), vpnte_engine::xray_process::XrayError> {
            self.0.start(slot, ep, launch, cancel).await
        }
        async fn restart(
            &mut self,
            slot: Slot,
            cancel: &CancellationToken,
        ) -> Result<(), vpnte_engine::xray_process::XrayError> {
            self.0.restart(slot, cancel).await
        }
        async fn stop(&mut self, slot: Slot) -> Result<(), vpnte_engine::xray_process::XrayError> {
            self.0.stop(slot).await
        }
        async fn stop_all(&mut self) -> Result<(), vpnte_engine::xray_process::XrayError> {
            self.0.stop_all().await
        }
        fn activate(&mut self, slot: Slot) -> Result<(), vpnte_engine::xray_process::XrayError> {
            self.0.activate(slot)
        }
        fn running(&self, slot: Slot) -> bool {
            self.0.running(slot)
        }
        fn recent_fault(&self, _slot: Slot) -> Option<vpnte_base::types::OutboundFault> {
            Some(vpnte_base::types::OutboundFault::UpstreamUnreachable)
        }
    }

    #[async_trait]
    impl Engines for Probed {
        fn spawn_core(&self, config: &[u8]) -> std::io::Result<Arc<dyn CoreProc>> {
            self.inner.spawn_core(config)
        }
        fn slots(&self, events: mpsc::Sender<XrayEvent>) -> Box<dyn Slots> {
            let slots = self.inner.slots(events);
            if self.noisy {
                return Box::new(NoisySlots(slots));
            }
            slots
        }
        fn singbox_exe(&self) -> PathBuf {
            self.inner.singbox_exe()
        }
        fn xray_exe(&self) -> PathBuf {
            self.inner.xray_exe()
        }
        fn log_files(&self, slots: bool) -> Vec<PathBuf> {
            self.inner.log_files(slots)
        }
        async fn select(&self, clash: &ClashEndpoint, slot: Slot) -> AppResult<()> {
            self.inner.select(clash, slot).await
        }
        async fn upstream_downloads(&self, c: &ClashEndpoint) -> AppResult<Vec<(String, u64)>> {
            self.inner.upstream_downloads(c).await
        }
        async fn slot_downloads(
            &self,
            c: &ClashEndpoint,
            slot: Slot,
        ) -> AppResult<Vec<(String, u64)>> {
            self.inner.slot_downloads(c, slot).await
        }
        fn handshake_ready(&self, server: &Profile) -> bool {
            self.inner.handshake_ready(server)
        }
        async fn resolve(
            &self,
            hosts: &[String],
            path: ResolvePath,
            cancel: &CancellationToken,
        ) -> Result<Resolved, ResolveFault> {
            self.inner.resolve(hosts, path, cancel).await
        }
        async fn egress_via(
            &self,
            server: &Profile,
            port: u16,
            creds: &Creds,
            settle: Option<Duration>,
            cancel: &CancellationToken,
        ) -> AppResult<IpAddr> {
            let ip = self
                .inner
                .egress_via(server, port, creds, settle, cancel)
                .await;
            match self.answer {
                Some(failure) => Err(echo_failed(failure)),
                None => ip,
            }
        }
        async fn egress(
            &self,
            via: Option<u16>,
            t: Duration,
            c: &CancellationToken,
        ) -> AppResult<IpAddr> {
            self.inner.egress(via, t, c).await
        }
        async fn local_proxy(&self, a: &HostPort, l: Duration) -> AppResult<Option<PathBuf>> {
            self.inner.local_proxy(a, l).await
        }
        async fn physical_dns(&self) -> Vec<Ipv4Addr> {
            self.inner.physical_dns().await
        }
        #[cfg(feature = "lab")]
        async fn start_mihomo(
            &self,
            config: &vpnte_engine::mihomo_config::Compiled,
            socks: SlotEndpoint,
            controller: ClashEndpoint,
            cancel: &CancellationToken,
        ) -> AppResult<Arc<dyn CoreProc>> {
            self.inner
                .start_mihomo(config, socks, controller, cancel)
                .await
        }
    }

    fn runtime(world: &Arc<World>, answer: Option<EchoFailure>) -> TunnelHandle {
        let mut d = deps(world);
        d.engines = Arc::new(Probed {
            inner: FakeEngines(world.clone()),
            answer,
            noisy: false,
        });
        TunnelHandle::spawn(d)
    }

    /// Lab F-11 (p-live2): killed engines of a slot session come back after the plain backoff.
    /// The dead core leaves Xray's log reading "unreachable"; that is no frozen server, so no
    /// freeze window delays the restart.
    #[tokio::test]
    async fn a_dead_core_of_a_slot_session_restarts_at_the_backoff() {
        let w = World::new();
        let mut d = deps(&w);
        d.timings.freeze = Duration::from_secs(30);
        d.engines = Arc::new(Probed {
            inner: FakeEngines(w.clone()),
            answer: None,
            noisy: true,
        });
        let h = TunnelHandle::spawn(d);
        let mut events = h.subscribe();
        h.start(
            vpn_req(XRAY_KEY, EnginePref::Xray),
            CancellationToken::new(),
        )
        .await
        .expect("start");
        drain(&mut events);
        w.core(0).crash();
        let back = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await {
                    Ok(TunnelEvent::StartFinished { generation: 2, ok }) => return ok,
                    Ok(_) => {}
                    Err(e) => panic!("{e}"),
                }
            }
        })
        .await
        .expect("restarted well inside the 30 s freeze window");
        assert!(back, "the recovery start succeeded");
    }

    /// Lab F-4 (p-live2): a native start proves its exit through the probe inbound after the
    /// capture is up and before anything is published as running.
    #[tokio::test]
    async fn a_native_start_is_running_only_after_its_exit_proof() {
        let w = World::new();
        let h = runtime(&w, None);
        h.start(
            vpn_req(NATIVE_KEY, EnginePref::Auto),
            CancellationToken::new(),
        )
        .await
        .expect("start");
        assert!(
            w.at("ready") < w.at("egress-via:203.0.113.12"),
            "{:?}",
            w.log()
        );
        assert!(h.status().borrow().running);
    }

    /// A dead server (a provider's placeholder, a server that carries nothing) fails the start
    /// with a calm, mode-neutral line; nothing is published as running.
    #[tokio::test]
    async fn a_silent_server_fails_the_start() {
        for key in [NATIVE_KEY, XRAY_KEY] {
            let w = World::new();
            let h = runtime(&w, Some(EchoFailure::NoReply));
            let mut events = h.subscribe();
            let err = h
                .start(vpn_req(key, EnginePref::Auto), CancellationToken::new())
                .await
                .unwrap_err();
            assert_eq!(err.user_msg().key, "tunnel.runtime.exitSilent", "{key}");
            let status = h.status().borrow().clone();
            assert!(!status.running && status.engine.is_none(), "{key}");
            let seen = drain(&mut events);
            assert!(!seen.contains(&TunnelEvent::Status(TunStatusKind::Running)));
        }
    }

    /// Answers without an address came through the server: a native start counts that as
    /// traffic.
    #[tokio::test]
    async fn answers_without_an_address_prove_a_native_exit() {
        let w = World::new();
        let h = runtime(&w, Some(EchoFailure::NoAddress));
        h.start(
            vpn_req(NATIVE_KEY, EnginePref::Auto),
            CancellationToken::new(),
        )
        .await
        .expect("traffic came back");
        assert!(h.status().borrow().running);
    }
}

#[cfg(test)]
mod settle_tests {
    use serde_json::{Value, json};
    use vpnte_engine::xray_config::ProxyGraph;
    use vpnte_profiles::xray_native::CompiledGraph;

    use super::{go_duration, settle_of};

    fn graph(entry: Value, burst: Option<Value>) -> ProxyGraph {
        ProxyGraph::Native(Box::new(CompiledGraph {
            outbounds: Vec::new(),
            rules: Vec::new(),
            balancers: Vec::new(),
            entry,
            observatory: None,
            burst_observatory: burst,
            policy: None,
        }))
    }

    /// Go durations as provider configs write them.
    #[test]
    fn go_durations_parse() {
        let cases = [
            ("5s", Some(5_000)),
            ("1m30s", Some(90_000)),
            ("500ms", Some(500)),
            ("2.5s", Some(2_500)),
            ("", None),
            ("0s", None),
            ("10", None),
            ("5x", None),
        ];
        for (text, want) in cases {
            let got = go_duration(text).map(|d| u64::try_from(d.as_millis()).unwrap());
            assert_eq!(got, want, "{text}");
        }
    }

    /// Lab live-7 F1: a balanced entry settles after the observatory's ping timeout (Xray's 5 s
    /// by default, capped at 10 s) plus a margin; a plain outbound entry never waits.
    #[test]
    fn a_balanced_graph_settles_after_its_ping_timeout() {
        let balanced = json!({"balancerTag": "vpnte-balancer:b"});
        let burst = |t: &str| Some(json!({"pingConfig": {"timeout": t}}));
        let ms = |g: &ProxyGraph| settle_of(g).map(|d| d.as_millis());
        assert_eq!(ms(&graph(balanced.clone(), None)), Some(5_500));
        assert_eq!(ms(&graph(balanced.clone(), burst("8s"))), Some(8_500));
        assert_eq!(ms(&graph(balanced.clone(), burst("1m"))), Some(10_500));
        let plain = graph(json!({"outboundTag": "proxy"}), burst("8s"));
        assert_eq!(settle_of(&plain), None);
        let translated = ProxyGraph::Translated(json!({"tag": "proxy"}));
        assert_eq!(settle_of(&translated), None);
    }
}
