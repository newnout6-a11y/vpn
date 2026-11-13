//! The lane's effects: async work run as child tasks of the actor. They touch the engines and
//! the system, never the state machine; they ask the actor to confirm through [`Confirmer`] and
//! report one result back.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{AdaptiveMode, KillSwitchLevel, Owner, ProxyKind};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::ops::OpId;

use super::actor::Cmd;
use super::pause::SessionGuard;
use super::session::SessionProfile;
use super::{ConnError, LifecycleDeps, ServerChoice, key};
use crate::api::{
    CaptureKind, EngineRun, Mode, Origin, OwnerCheck, RestartOptions, StartRequest, StopOptions,
    StopReceipt, SwitchOutcome, SwitchReceipt, TUN_SETUP_KEY_PREFIX, TunError, VpnProfile,
};
use crate::history::SessionMode;
use crate::outcome::{Evidence, OutcomeKind, SessionOutcome};

/// No leak alarms while a tunnel comes up (old `suppressLeakSelfTestsFor(20_000)`).
const LEAK_QUIET: Duration = Duration::from_secs(20);

/// What protection a start must prove before it is published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
    /// Our engine runs with the TUN capture.
    Tun,
    /// Our engine runs with the proxy capture and the user-level tweaks point at it.
    Soft,
}

impl Want {
    pub fn of(capture: CaptureKind) -> Self {
        match capture {
            CaptureKind::Tun => Want::Tun,
            CaptureKind::Proxy => Want::Soft,
        }
    }
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
    /// The live session's kill switch: switches and restarts keep it.
    pub guard: SessionGuard,
}

/// Protection a start brought up.
#[derive(Debug)]
pub(super) enum Up {
    /// An engine run on `profile` (connect, switch, restart onto a sibling), Hard or Soft.
    Run {
        profile: SessionProfile,
        country: Option<String>,
        /// New engine run; `None` = the same run continues (in-place upstream switch).
        generation: Option<u64>,
        /// `None` = unchanged.
        engine: Option<EngineRun>,
        adaptive: AdaptiveMode,
        warnings: Vec<Msg>,
        /// A connect decides the session's kill switch; `None` = unchanged.
        guard: Option<SessionGuard>,
    },
    /// The same profile on a new engine run (settings or adaptive restart).
    Restarted {
        generation: u64,
        engine: EngineRun,
        /// New adaptive mode; `None` = unchanged.
        adaptive: Option<AdaptiveMode>,
        warnings: Vec<Msg>,
    },
    /// Nothing was running, so nothing had to change (restart / rotation while disconnected).
    Idle,
}

/// A start that did not succeed, and what it left behind.
#[derive(Debug)]
pub(super) struct Failure {
    pub error: ConnError,
    /// The previous protection was read back unchanged (refused switch, preserved upstream).
    pub kept_previous: bool,
    /// The previous tunnel was torn down or changed (a switch or restart got past its start).
    pub touched: bool,
    /// Zero-duration history row of the failed start.
    pub row: Option<Box<(SessionProfile, SessionOutcome)>>,
}

impl Failure {
    fn new(error: ConnError) -> Self {
        Self {
            error,
            kept_previous: false,
            touched: false,
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

/// The upstream a connect runs (either capture).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Target {
    Proxy {
        addr: String,
        kind: ProxyKind,
    },
    /// A server of the server list; `None` = the active selection.
    Direct(Option<String>),
}

impl Target {
    /// Session profile, once the server is known (`server`) or as far as the request tells.
    fn profile(&self, server: Option<&VpnProfile>, capture: CaptureKind) -> SessionProfile {
        let soft = capture == CaptureKind::Proxy;
        match (self, server) {
            (_, Some(server)) if soft => SessionProfile::soft_server(server),
            (_, Some(server)) => SessionProfile::direct(server),
            (Target::Proxy { addr, kind }, None) if soft => SessionProfile::soft(addr, *kind),
            (Target::Proxy { addr, .. }, None) => SessionProfile::local_proxy(addr),
            (Target::Direct(id), None) => SessionProfile {
                id: id.clone().unwrap_or_else(|| "direct-vpn".into()),
                mode: if soft {
                    SessionMode::Soft
                } else {
                    SessionMode::Direct
                },
                ..SessionProfile::direct_unknown()
            },
        }
    }
}

/// Connect in either mode (NOADMIN.md §2). Leftovers of an earlier run end first (modes never
/// overlap): Soft tweaks go before a Hard start (a refused rollback refuses it, L-15), a running
/// engine gets the full stop; a Soft start keeps leftover tweaks blocking until it re-points
/// them. Then the runtime starts with `capture` and, in Soft, the tweaks point at the session's
/// mixed port.
pub(super) async fn connect(
    ctx: Ctx,
    target: Target,
    capture: CaptureKind,
    adaptive: AdaptiveMode,
) -> StartReport {
    let deps = &ctx.deps;
    let soft = capture == CaptureKind::Proxy;
    let mut mode_switch = None;
    if !soft && deps.soft.applied() != Some(false) {
        let ending = Captured::now(deps);
        if let Err(e) = deps.soft.rollback().await {
            // L-15: a refused rollback is a failed start with a row, not a raw error; nothing
            // else was touched yet.
            tracing::warn!(error = %e, "soft rollback before a tunnel start failed");
            let hint = Msg::new(key::SOFT_ROLLBACK_BEFORE_START);
            let error = ConnError::Failed(TunError::from(AppError::msg(e.kind, hint.clone())));
            let row = (target.profile(None, capture), refused_outcome(hint));
            return StartReport::done(Err(Failure::new(error).row(row.0, row.1)));
        }
        mode_switch = Some(ending);
    }
    if deps.runtime.status().borrow().running {
        let ending = mode_switch.take().unwrap_or_else(|| Captured::now(deps));
        if !stop(deps.clone(), false, Keep::Nothing)
            .await
            .runtime_gone()
        {
            let msg = Msg::new(key::CLEANUP_UNCONFIRMED);
            let error = ConnError::Failed(TunError::new(ErrorKind::Internal, msg.clone()));
            let failure = Failure::new(error)
                .touched()
                .row(target.profile(None, capture), refused_outcome(msg));
            return StartReport::done(Err(failure));
        }
        mode_switch = Some(ending);
    }
    deps.monitor.suppress_leak_tests(LEAK_QUIET);
    let (mode, choice) = match &target {
        Target::Proxy { addr, kind } => {
            let mode = Mode::LocalProxy {
                addr: addr.clone(),
                kind: *kind,
            };
            (mode, None)
        }
        Target::Direct(id) => match deps.profiles.resolve(id.as_deref()) {
            Some(choice) => {
                let mode = Mode::DirectVpn {
                    profile: choice.server.clone(),
                };
                (mode, Some(choice))
            }
            None => {
                return StartReport {
                    result: Err(no_server(&target, capture)),
                    mode_switch,
                };
            }
        },
    };
    let profile = target.profile(choice.as_ref().map(|c| &c.server), capture);
    let guard = session_guard(deps, soft).await;
    let req = start_request(deps, mode, capture, adaptive, ctx.owner, guard.level);
    StartReport {
        result: run_start(&ctx, req, profile, choice, adaptive, guard).await,
        mode_switch,
    }
}

/// The kill switch of a session, as it is now. Proxy mode is where another VPN may carry the
/// default route (Tunnel mode refuses such a connect): then nothing pauses this session.
pub(super) async fn session_guard(deps: &LifecycleDeps, soft: bool) -> SessionGuard {
    let level = deps.kill_switch();
    let foreign = match soft && level != KillSwitchLevel::Off {
        true => {
            let check = deps.foreign_vpn.clone();
            tokio::task::spawn_blocking(move || check.full_tunnel())
                .await
                .unwrap_or_default()
        }
        false => None,
    };
    SessionGuard::new(level, soft, foreign)
}

/// No server selected, or the requested one is not in the list (old Conflict + start-failed row).
fn no_server(target: &Target, capture: CaptureKind) -> Failure {
    let msg = Msg::new(match target {
        Target::Direct(Some(_)) => key::SERVER_UNAVAILABLE,
        _ => key::NO_SERVER,
    });
    let profile = target.profile(None, capture);
    Failure::new(ConnError::NoServer(msg.clone())).row(profile, refused_outcome(msg))
}

/// The start request for `mode` with the current settings and the session's kill switch.
pub(super) fn start_request(
    deps: &LifecycleDeps,
    mode: Mode,
    capture: CaptureKind,
    adaptive: AdaptiveMode,
    owner: Owner,
    kill_switch: KillSwitchLevel,
) -> StartRequest {
    deps.settings.read(|s| StartRequest {
        mode,
        capture,
        kill_switch,
        public_wifi: s.public_wifi_compatibility,
        stealth: s.stealth_mode,
        adaptive,
        engine: s.proxy_engine,
        origin: origin(owner),
    })
}

/// `runtime.start` of a new server or proxy, then (Soft) the tweaks, then the actor's
/// confirmation.
async fn run_start(
    ctx: &Ctx,
    req: StartRequest,
    profile: SessionProfile,
    choice: Option<ServerChoice>,
    adaptive: AdaptiveMode,
    guard: SessionGuard,
) -> Result<Up, Failure> {
    let deps = &ctx.deps;
    if ctx.token.is_cancelled() {
        return Err(cancelled());
    }
    let capture = req.capture;
    match deps.runtime.start(req, ctx.token.clone()).await {
        Ok(receipt) => {
            if capture == CaptureKind::Proxy
                && let Err(failure) = point_tweaks(ctx, None).await
            {
                let hint = failure.error.user_msg();
                return Err(failure.row(profile, refused_outcome(hint)));
            }
            let up = Up::Run {
                profile,
                country: choice.and_then(|c| c.country),
                generation: Some(receipt.generation),
                engine: Some(receipt.engine),
                adaptive,
                warnings: receipt.warnings,
                guard: Some(guard),
            };
            confirm(ctx, up).await
        }
        Err(_) if ctx.token.is_cancelled() => Err(cancelled()),
        Err(e) => {
            let outcome = start_failed(deps, &e);
            Err(Failure::new(ConnError::Failed(e)).row(profile, outcome))
        }
    }
}

/// `127.0.0.1:<port>`: where the Soft tweaks point.
pub(super) fn soft_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

/// The mixed port of the running proxy-capture session.
pub(super) fn session_port(deps: &LifecycleDeps) -> Option<u16> {
    let status = deps.runtime.status();
    let s = status.borrow();
    s.session.as_ref().and_then(|e| e.proxy_port)
}

/// Soft: points the user-level tweaks at the session's mixed port (HTTP: what WinINet and the
/// `*_PROXY` variables take; the inbound also serves SOCKS5) and reads them back. `applied` =
/// the port they already point at (a restart): kept while the read-back still shows it, and
/// left alone when another program took the system proxy since (ks-b): the start page's
/// «Вернуть» lets the user decide, a restart never takes it back silently. A failure is
/// `touched`: the lane's recovery stop then rolls back whatever was applied and stops the
/// engine (no tweak left behind).
async fn point_tweaks(ctx: &Ctx, applied: Option<u16>) -> Result<(), Failure> {
    let deps = &ctx.deps;
    let result = match session_port(deps) {
        Some(port) => {
            let addr = soft_addr(port);
            let read_back = if applied == Some(port) {
                Some(deps.soft.is_configured(&addr, ProxyKind::Http).await)
            } else {
                None
            };
            // Still journalled as ours, yet another program's value holds now: taken. A
            // read-back that merely is not ours (an unreadable proxy) proves nothing: written
            // again and read back, so it fails closed (pfollow-a3).
            let taken = match read_back {
                Some(Ok(false)) if deps.soft.applied() == Some(true) => deps.soft.taken().await,
                _ => false,
            };
            match read_back {
                Some(Ok(true)) => Ok(()),
                _ if taken => {
                    tracing::info!("system proxy taken by another program: left alone");
                    Ok(())
                }
                _ => apply_and_read_back(deps, &addr).await,
            }
        }
        // A proxy-capture session always publishes its port; without it nothing can be pointed.
        None => Err(AppError::new(ErrorKind::Internal)),
    };
    match result {
        Ok(()) => Ok(()),
        Err(_) if ctx.token.is_cancelled() => Err(cancelled().touched()),
        Err(e) => {
            tracing::warn!(error = %e, "soft tweaks not applied");
            let hint = e.msg.unwrap_or_else(|| Msg::new(key::SOFT_APPLY_FAILED));
            let error = ConnError::Failed(TunError::from(AppError::msg(e.kind, hint)));
            Err(Failure::new(error).touched())
        }
    }
}

/// Applies the tweaks for `addr`; Soft counts as applied only once the system reads back `addr`.
pub(super) async fn apply_and_read_back(deps: &LifecycleDeps, addr: &str) -> Result<(), AppError> {
    deps.soft.apply(addr, ProxyKind::Http).await?;
    if deps.soft.is_configured(addr, ProxyKind::Http).await? {
        Ok(())
    } else {
        tracing::warn!("soft tweaks applied but not read back");
        Err(AppError::msg(
            ErrorKind::Internal,
            Msg::new(key::SOFT_APPLY_FAILED),
        ))
    }
}

/// Publishes `up` only once the state machine accepts it (Hard: the TUN run; Soft: the run
/// plus the applied tweaks); otherwise what this owner started is undone here, so no process
/// or tweak is abandoned ("Connection confirmation missing").
async fn confirm(ctx: &Ctx, up: Up) -> Result<Up, Failure> {
    let capture = ctx.deps.runtime.status().borrow().capture;
    let want = Want::of(capture.unwrap_or(CaptureKind::Tun));
    if ctx.confirm.check(want).await {
        return Ok(up);
    }
    if ctx.token.is_cancelled() {
        // Aborted: the lane's compensating stop cleans up, exactly once.
        return Err(cancelled().touched());
    }
    let stopped = undo_start(&ctx.deps).await;
    tracing::warn!(stopped, "start not confirmed; compensated");
    Err(Failure::new(failed(ErrorKind::Internal, key::CONFIRMATION_MISSING)).touched())
}

/// Undoes a start that will not be published: the tweaks first (they would point at a dead
/// port), then the engine. `true` = the engine's exit is proven.
async fn undo_start(deps: &LifecycleDeps) -> bool {
    if deps.soft.applied() != Some(false)
        && let Err(e) = deps.soft.rollback().await
    {
        tracing::warn!(error = %e, "unconfirmed start: soft rollback failed");
    }
    deps.runtime
        .stop(StopOptions::default())
        .await
        .runtime_stopped
}

/// What a stop leaves blocking (`DisconnectReq::keep_protection` with the kill switch on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Keep {
    /// A full stop.
    Nothing,
    /// Soft: the tweaks stay on the dead port, so programs that honour them stay blocked.
    Tweaks,
    /// TUN: the runtime keeps its firewall block (a preserved stop).
    Block,
}

/// What a stop achieved.
#[derive(Debug)]
pub(super) struct StopReport {
    pub receipt: StopReceipt,
    /// Soft rollback result (it runs before the engine stops); `None`: not attempted (the
    /// tweaks were kept on purpose, or the effect panicked).
    pub soft: Option<Result<(), AppError>>,
    pub capture_stopped: bool,
    pub kept: Keep,
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
            kept: Keep::Nothing,
        }
    }
}

/// Full stop (old `stopProtectionEffects`): Soft tweaks first (NOADMIN.md §2: they must not
/// point at an engine that is going away), then the runtime; when its exit is not proven,
/// nothing else is touched (protection retained) unless the app quits (H-06: the kill-on-close
/// job ends the engines with the process, so the rest is cleaned up now). Then forensics,
/// external proxies and monitoring, each independent of the others. `keep`: what stays
/// blocking instead (the engines go either way).
pub(super) async fn stop(deps: Arc<LifecycleDeps>, quitting: bool, keep: Keep) -> StopReport {
    let reason = if quitting { "shutdown" } else { "vpn-stop" };
    let soft = if deps.soft.applied() == Some(false) {
        Some(Ok(()))
    } else if keep == Keep::Tweaks {
        None
    } else {
        Some(deps.soft.rollback().await)
    };
    let opts = StopOptions {
        preserve_protection: keep == Keep::Block,
        preserve_last: false,
    };
    let receipt = deps.runtime.stop(opts).await;
    if !receipt.ok && !receipt.runtime_stopped && !quitting {
        return StopReport {
            receipt,
            soft,
            capture_stopped: false,
            kept: Keep::Nothing,
        };
    }
    let capture_stopped = deps.forensics.stop_session(reason).await;
    // External proxies are tied to the runtime: they go only once its exit is proven (or on quit).
    deps.proxies.stop_all(reason).await;
    deps.monitor.stop();
    StopReport {
        receipt,
        soft,
        capture_stopped,
        kept: keep,
    }
}

mod rotate;

pub(super) use rotate::{restart_adaptive, restart_last, switch};
