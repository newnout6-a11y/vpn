//! The lane's effects: async work run as child tasks of the actor. They touch the engines and
//! the system, never the state machine; they ask the actor to confirm through [`Confirmer`] and
//! report one result back.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, Engine, Owner, ProxyKind};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::ops::OpId;

use super::actor::Cmd;
use super::session::SessionProfile;
use super::{ConnError, LifecycleDeps, ServerChoice, key};
use crate::api::{
    Mode, Origin, OwnerCheck, RestartOptions, StartRequest, StopOptions, StopReceipt,
    SwitchOutcome, SwitchReceipt, TUN_SETUP_KEY_PREFIX, TunError, VpnProfile,
};
use crate::outcome::{Evidence, OutcomeKind, SessionOutcome};

/// No leak alarms while a tunnel comes up (old `suppressLeakSelfTestsFor(20_000)`).
const LEAK_QUIET: Duration = Duration::from_secs(20);

/// What protection a start must prove before it is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
    Tun,
    Soft,
}

/// Asks the actor whether the state machine accepts the start of `op` (old `canConfirmStart`).
pub(super) struct Confirmer {
    pub tx: mpsc::UnboundedSender<Cmd>,
    pub op: OpId,
}

impl Confirmer {
    async fn check(&self, want: Want) -> bool {
        let (reply, rx) = oneshot::channel();
        let asked = self.tx.send(Cmd::Confirm {
            op: self.op,
            want,
            reply,
        });
        asked.is_ok() && rx.await.unwrap_or(false)
    }
}

/// What one start-type effect needs.
pub(super) struct Ctx {
    pub deps: Arc<LifecycleDeps>,
    pub token: CancellationToken,
    pub confirm: Confirmer,
    pub owner: Owner,
}

/// Protection a start brought up.
#[derive(Debug)]
pub(super) enum Up {
    /// A tunnel on `profile` (connect, switch, restart onto a sibling).
    Tun {
        profile: SessionProfile,
        country: Option<String>,
        /// New engine run; `None` = the same run continues (in-place upstream switch).
        generation: Option<u64>,
        /// `None` = unchanged.
        engine: Option<Engine>,
        adaptive: AdaptiveMode,
        warnings: Vec<Msg>,
    },
    /// The same profile on a new engine run (settings or adaptive restart).
    Restarted {
        generation: u64,
        engine: Engine,
        /// New adaptive mode; `None` = unchanged.
        adaptive: Option<AdaptiveMode>,
        warnings: Vec<Msg>,
    },
    Soft {
        addr: String,
        kind: ProxyKind,
    },
    /// Nothing was running, so nothing had to change (restart / rotation while disconnected).
    Idle,
}

/// A start that did not succeed, and what it left behind.
#[derive(Debug)]
pub(super) struct Failure {
    pub error: ConnError,
    /// The previous protection was read back unchanged (failed Soft refresh, preserved upstream).
    pub kept_previous: bool,
    /// The previous tunnel was torn down or changed (a switch or restart got past its start).
    pub touched: bool,
    /// A failed Soft refresh could not prove the previous proxy: that session is lost.
    pub soft_lost: bool,
    /// Zero-duration history row of the failed start.
    pub row: Option<Box<(SessionProfile, SessionOutcome)>>,
}

impl Failure {
    fn new(error: ConnError) -> Self {
        Self {
            error,
            kept_previous: false,
            touched: false,
            soft_lost: false,
            row: None,
        }
    }

    fn row(mut self, profile: SessionProfile, outcome: SessionOutcome) -> Self {
        self.row = Some(Box::new((profile, outcome)));
        self
    }

    fn touched(mut self) -> Self {
        self.touched = true;
        self
    }

    /// Refused before anything was touched: the previous state stands (old
    /// `confirmRetainedRotation`), never "error" over a healthy tunnel.
    fn kept(error: ConnError) -> Self {
        Self {
            kept_previous: true,
            ..Self::new(error)
        }
    }
}

/// Session facts read right before something stops: stopping zeroes the counters and makes the
/// monitor forget the VPN IP.
#[derive(Debug, Clone, Default)]
pub(super) struct Captured {
    pub bytes: (u64, u64),
    pub egress_ip: Option<String>,
}

impl Captured {
    pub fn now(deps: &LifecycleDeps) -> Self {
        Self {
            bytes: deps.forensics.session_bytes(),
            egress_ip: deps.monitor.egress_ip(),
        }
    }
}

/// The report of a start-type effect.
#[derive(Debug)]
pub(super) struct StartReport {
    pub result: Result<Up, Failure>,
    /// The other mode was ended first (Soft rolled back before a TUN, a TUN stopped before Soft):
    /// its session closes as a mode switch with these facts.
    pub mode_switch: Option<Captured>,
}

impl StartReport {
    fn done(result: Result<Up, Failure>) -> Self {
        Self {
            result,
            mode_switch: None,
        }
    }

    /// The effect panicked: nothing about the tunnel is proven any more.
    pub fn panicked() -> Self {
        let error = ConnError::Failed(AppError::new(ErrorKind::Internal).into());
        Self::done(Err(Failure::new(error).touched()))
    }
}

fn cancelled() -> Failure {
    Failure::new(ConnError::Cancelled(Msg::new(key::START_CANCELLED)))
}

fn failed(kind: ErrorKind, msg: &'static str) -> ConnError {
    ConnError::Failed(TunError::new(kind, Msg::new(msg)))
}

/// Start origin of an owner (every origin but `Recovery` resets the crash-restart budget).
pub(super) fn origin(owner: Owner) -> Origin {
    match owner {
        Owner::Manual | Owner::Autopilot => Origin::User,
        Owner::Schedule => Origin::Schedule,
        Owner::Rotation => Origin::Rotation,
        Owner::AdaptiveRetry => Origin::Adaptive,
        Owner::Recovery => Origin::Recovery,
    }
}

/// History outcome of a failed start (L-14: TUN bring-up failures are their own kind).
fn start_failed(deps: &LifecycleDeps, error: &TunError) -> SessionOutcome {
    let tun_setup = error
        .error
        .msg
        .as_ref()
        .is_some_and(|m| m.key.starts_with(TUN_SETUP_KEY_PREFIX));
    let evidence = Evidence {
        outbound_fault: deps.runtime.recent_fault(),
        ..Evidence::default()
    };
    SessionOutcome::start_failure(tun_setup, Some(error.user_msg()), evidence)
}

/// Start failure that never reached the runtime (no server, Soft rollback refused, …).
fn refused_outcome(hint: Msg) -> SessionOutcome {
    SessionOutcome::start_failure(false, Some(hint), Evidence::default())
}

/// What a Hard start runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TunTarget {
    Proxy {
        addr: String,
        kind: ProxyKind,
    },
    /// A server of the server list; `None` = the active selection.
    Direct(Option<String>),
}

impl TunTarget {
    /// Session profile, once the server is known (`server`) or as far as the request tells.
    fn profile(&self, server: Option<&VpnProfile>) -> SessionProfile {
        match (self, server) {
            (_, Some(server)) => SessionProfile::direct(server),
            (TunTarget::Proxy { addr, .. }, None) => SessionProfile::local_proxy(addr),
            (TunTarget::Direct(Some(id)), None) => SessionProfile {
                id: id.clone(),
                ..SessionProfile::direct_unknown()
            },
            (TunTarget::Direct(None), None) => SessionProfile::direct_unknown(),
        }
    }
}

/// Hard start: Soft rolled back first (modes never overlap), then the runtime start.
pub(super) async fn connect_tun(
    ctx: Ctx,
    target: TunTarget,
    adaptive: AdaptiveMode,
) -> StartReport {
    let deps = &ctx.deps;
    let mut mode_switch = None;
    if deps.soft.applied() != Some(false) {
        let ending = Captured::now(deps);
        if let Err(e) = deps.soft.rollback().await {
            // L-15: a refused rollback is a failed start with a row, not a raw error.
            tracing::warn!(error = %e, "soft rollback before a tunnel start failed");
            let hint = Msg::new(key::SOFT_ROLLBACK_BEFORE_START);
            let error = ConnError::Failed(TunError::from(AppError::msg(e.kind, hint.clone())));
            let row = (target.profile(None), refused_outcome(hint));
            return StartReport::done(Err(Failure::new(error).row(row.0, row.1)));
        }
        mode_switch = Some(ending);
    }
    deps.monitor.suppress_leak_tests(LEAK_QUIET);
    let (mode, choice) = match &target {
        TunTarget::Proxy { addr, kind } => {
            let mode = Mode::LocalProxy {
                addr: addr.clone(),
                kind: *kind,
            };
            (mode, None)
        }
        TunTarget::Direct(id) => match deps.profiles.resolve(id.as_deref()) {
            Some(choice) => {
                let mode = Mode::DirectVpn {
                    profile: choice.server.clone(),
                };
                (mode, Some(choice))
            }
            None => {
                return StartReport {
                    result: Err(no_server(&target)),
                    mode_switch,
                };
            }
        },
    };
    let profile = target.profile(choice.as_ref().map(|c| &c.server));
    let req = start_request(deps, mode, adaptive, ctx.owner);
    StartReport {
        result: run_start(&ctx, req, profile, choice, adaptive).await,
        mode_switch,
    }
}

/// No server selected, or the requested one is not in the list (old Conflict + start-failed row).
fn no_server(target: &TunTarget) -> Failure {
    let msg = Msg::new(match target {
        TunTarget::Direct(Some(_)) => key::SERVER_UNAVAILABLE,
        _ => key::NO_SERVER,
    });
    Failure::new(ConnError::NoServer(msg.clone())).row(target.profile(None), refused_outcome(msg))
}

/// The start request for `mode` with the current settings.
fn start_request(
    deps: &LifecycleDeps,
    mode: Mode,
    adaptive: AdaptiveMode,
    owner: Owner,
) -> StartRequest {
    deps.settings.read(|s| StartRequest {
        mode,
        kill_switch: s.kill_switch,
        public_wifi: s.public_wifi_compatibility,
        stealth: s.stealth_mode,
        adaptive,
        engine: s.proxy_engine,
        origin: origin(owner),
    })
}

/// `runtime.start` of a new server or proxy, then the actor's confirmation.
async fn run_start(
    ctx: &Ctx,
    req: StartRequest,
    profile: SessionProfile,
    choice: Option<ServerChoice>,
    adaptive: AdaptiveMode,
) -> Result<Up, Failure> {
    let deps = &ctx.deps;
    if ctx.token.is_cancelled() {
        return Err(cancelled());
    }
    match deps.runtime.start(req, ctx.token.clone()).await {
        Ok(receipt) => {
            let up = Up::Tun {
                profile,
                country: choice.and_then(|c| c.country),
                generation: Some(receipt.generation),
                engine: Some(receipt.engine),
                adaptive,
                warnings: receipt.warnings,
            };
            confirm_tun(ctx, up).await
        }
        Err(_) if ctx.token.is_cancelled() => Err(cancelled()),
        Err(e) => {
            let outcome = start_failed(deps, &e);
            Err(Failure::new(ConnError::Failed(e)).row(profile, outcome))
        }
    }
}

/// Publishes `up` only once the state machine accepts it; otherwise the tunnel this owner
/// started is stopped here, so no process is abandoned ("Connection confirmation missing").
async fn confirm_tun(ctx: &Ctx, up: Up) -> Result<Up, Failure> {
    if ctx.confirm.check(Want::Tun).await {
        return Ok(up);
    }
    if ctx.token.is_cancelled() {
        // Aborted: the lane's compensating stop cleans up, exactly once.
        return Err(cancelled().touched());
    }
    let stop = ctx.deps.runtime.stop(StopOptions::default()).await;
    tracing::warn!(
        stopped = stop.runtime_stopped,
        "tunnel start not confirmed; compensated"
    );
    Err(Failure::new(failed(ErrorKind::Internal, key::CONFIRMATION_MISSING)).touched())
}

/// Soft start: a running TUN gets the full stop first (modes never overlap; its forensics and
/// external proxies go with it), then the proxy is applied.
/// `previous`: endpoint of the Soft session this start refreshes.
pub(super) async fn connect_soft(
    ctx: Ctx,
    addr: String,
    kind: ProxyKind,
    previous: Option<(String, ProxyKind)>,
) -> StartReport {
    let deps = &ctx.deps;
    let profile = SessionProfile::soft(&addr, kind);
    let mut mode_switch = None;
    let tun_running = deps.runtime.status().borrow().running;
    if tun_running {
        let ending = Captured::now(deps);
        if !stop(ctx.deps.clone(), false).await.runtime_gone() {
            let msg = Msg::new(key::CLEANUP_UNCONFIRMED);
            let error = ConnError::Failed(TunError::new(ErrorKind::Internal, msg.clone()));
            let failure = Failure::new(error)
                .touched()
                .row(profile, refused_outcome(msg));
            return StartReport::done(Err(failure));
        }
        mode_switch = Some(ending);
    }
    deps.monitor.suppress_leak_tests(LEAK_QUIET);
    let result = if ctx.token.is_cancelled() {
        Err(cancelled())
    } else {
        match deps.soft.apply(&addr, kind).await {
            Ok(()) if ctx.confirm.check(Want::Soft).await => Ok(Up::Soft { addr, kind }),
            Ok(()) if ctx.token.is_cancelled() => Err(cancelled().touched()),
            Ok(()) => {
                if let Err(e) = deps.soft.rollback().await {
                    tracing::warn!(error = %e, "unconfirmed soft start: rollback failed");
                }
                Err(Failure::new(failed(ErrorKind::Internal, key::CONFIRMATION_MISSING)).touched())
            }
            Err(_) if ctx.token.is_cancelled() => Err(cancelled()),
            Err(e) => Err(soft_failure(&ctx, e, profile, previous).await),
        }
    };
    StartReport {
        result,
        mode_switch,
    }
}

/// A failed apply. On a refresh the previous endpoint is read back: still configured → the
/// previous session is kept; not readable or changed → it is lost. A cancellation during the
/// read-back writes nothing (no late history).
async fn soft_failure(
    ctx: &Ctx,
    e: AppError,
    profile: SessionProfile,
    previous: Option<(String, ProxyKind)>,
) -> Failure {
    tracing::warn!(error = %e, "soft proxy apply failed");
    let hint = e
        .msg
        .clone()
        .unwrap_or_else(|| Msg::new(key::SOFT_APPLY_FAILED));
    let error = ConnError::Failed(TunError::from(AppError::msg(e.kind, hint.clone())));
    let mut failure = Failure::new(error).row(profile, refused_outcome(hint));
    if let Some((addr, kind)) = previous {
        let still = ctx.deps.soft.is_configured(&addr, kind).await;
        if ctx.token.is_cancelled() {
            return cancelled();
        }
        match still {
            Ok(true) => failure.kept_previous = true,
            Ok(false) | Err(_) => failure.soft_lost = true,
        }
    }
    failure
}

/// What a full stop achieved.
#[derive(Debug)]
pub(super) struct StopReport {
    pub receipt: StopReceipt,
    /// Soft rollback result; `None`: not attempted because the runtime did not prove its exit.
    pub soft: Option<Result<(), AppError>>,
    pub capture_stopped: bool,
}

impl StopReport {
    /// The runtime proved its exit (or that nothing ran).
    pub fn runtime_gone(&self) -> bool {
        self.receipt.ok || self.receipt.runtime_stopped
    }

    /// The effect panicked: nothing was proven, so protection counts as retained.
    pub fn panicked() -> Self {
        Self {
            receipt: StopReceipt {
                operation_id: String::new(),
                ok: false,
                runtime_stopped: false,
                forced: false,
                protection_released: None,
                baseline_restored: None,
                adapter_gone: false,
                warnings: Vec::new(),
            },
            soft: None,
            capture_stopped: false,
        }
    }
}

/// Full stop (old `stopProtectionEffects`): the runtime first; when its exit is not proven,
/// nothing else is touched (protection retained) unless the app quits (H-06: the kill-on-close
/// job ends the engines with the process, so the rest is cleaned up now). Then Soft rollback,
/// forensics, external proxies and monitoring, each independent of the others.
pub(super) async fn stop(deps: Arc<LifecycleDeps>, quitting: bool) -> StopReport {
    let reason = if quitting { "shutdown" } else { "vpn-stop" };
    let receipt = deps.runtime.stop(StopOptions::default()).await;
    if !receipt.ok && !receipt.runtime_stopped && !quitting {
        return StopReport {
            receipt,
            soft: None,
            capture_stopped: false,
        };
    }
    let soft = if deps.soft.applied() == Some(false) {
        Ok(())
    } else {
        deps.soft.rollback().await
    };
    let capture_stopped = deps.forensics.stop_session(reason).await;
    // External proxies are tied to the runtime: they go only once its exit is proven (or on quit).
    deps.proxies.stop_all(reason).await;
    deps.monitor.stop();
    StopReport {
        receipt,
        soft: Some(soft),
        capture_stopped,
    }
}

mod rotate;

pub(super) use rotate::{restart_adaptive, restart_last, switch};
