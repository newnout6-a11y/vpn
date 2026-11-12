//! Xray supervision: two authenticated loopback SOCKS slots (A / B) that sing-box's `proxy-out`
//! selector switches between, so an upstream change never tears the TUN down. Each slot runs
//! `xray run -config stdin:` in its own kill-on-close Job; readiness is the authenticated SOCKS
//! handshake (a foreign listener on the port that answers NoAuth or refuses our credentials is
//! never taken for ours), raced against the child's exit so an early exit is reported at once.
//!
//! The supervisor is owned by the tunnel actor (`&mut self`, not shared). Exit events of
//! running slots go to the channel given at construction; restart policy and backoff live in
//! the tunnel FSM.
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant, SystemTime};

use regex::Regex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, Engine, OutboundFault};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::socks5::{self, SocksError};

use crate::singbox_process::child::{self, EngineChild, GRACEFUL_STOP, Scrubber, Spec, exited};
use crate::singbox_process::{code_text, re, spawn_error};
use crate::slot::{Slot, SlotEndpoint};

#[cfg(test)]
mod tests;

/// Authenticated SOCKS readiness budget (old `waitForLocalSocks`, 3500 ms).
pub const READY_TIMEOUT: Duration = Duration::from_millis(3500);
/// Exit confirmation after the kill (a stop first waits up to
/// [`crate::singbox_process::GRACEFUL_STOP`] for Xray's own exit after CTRL_BREAK).
pub const STOP_TIMEOUT: Duration = Duration::from_millis(1000);
/// Deadline of `check_config`.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Xray exit code for a config it refused to build.
pub const EXIT_CONFIG_REJECTED: i32 = 23;
/// Faults older than this are ignored by [`XraySupervisor::recent_fault`].
pub const FAULT_MAX_AGE: Duration = Duration::from_secs(120);
const FAULT_WINDOW: usize = 500;
/// Prefix of Xray's start failure line (printed on stdout, may trail the exit).
const FAILED_TO_START: &str = "Failed to start:";

/// What a slot runs: the Xray JSON built for its endpoint (`xray_config`), plus the dial target
/// the failure diagnostics probe. Holds credentials: never logged.
#[derive(Clone)]
pub struct SlotLaunch {
    pub config: Vec<u8>,
    pub dial_target: Option<SocketAddr>,
}

impl std::fmt::Debug for SlotLaunch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SlotLaunch({} bytes)", self.config.len())
    }
}

/// A slot as the coordinator and the diagnostics see it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlotStatus {
    /// Readiness confirmed and the process has not exited.
    pub running: bool,
    pub port: Option<u16>,
    pub pid: Option<u32>,
    pub started_at: Option<SystemTime>,
    /// Only while running.
    pub dial_target: Option<SocketAddr>,
}

/// Exit of a slot whose readiness had been confirmed. `expected` = we stopped it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XrayEvent {
    Exited {
        slot: Slot,
        pid: u32,
        code: Option<i32>,
        expected: bool,
        /// Xray ended by itself after our CTRL_BREAK (no kill was needed).
        graceful: bool,
        /// Redacted last output lines.
        tail: String,
    },
}

/// Why a slot operation failed. Texts carried here are redacted engine output.
#[derive(Debug, thiserror::Error)]
pub enum XrayError {
    #[error("xray could not be started")]
    Spawn(#[source] io::Error),
    #[error("xray rejected the config: {0}")]
    ConfigRejected(String),
    #[error("xray exited before it was ready (code {code:?})")]
    ExitedEarly { code: Option<i32>, tail: String },
    #[error("xray SOCKS port {port} did not answer")]
    NotReady {
        port: u16,
        #[source]
        cause: SocksError,
    },
    #[error("the slot already runs an xray instance")]
    SlotOccupied,
    #[error("the port belongs to the other slot")]
    PortOwnedByOtherSlot,
    #[error("the slot is not running")]
    NotRunning,
    #[error("the slot has no launch to restart")]
    NotStarted,
    #[error("xray exit was not confirmed")]
    ExitNotConfirmed,
    #[error("xray start cancelled")]
    Cancelled,
}

impl From<XrayError> for AppError {
    fn from(err: XrayError) -> Self {
        let (kind, msg) = match &err {
            XrayError::Cancelled => return AppError::cancelled(),
            XrayError::Spawn(io) => spawn_error("Xray", io),
            XrayError::ConfigRejected(_) => (
                ErrorKind::Validation,
                Msg::new("engine.process.configRejected").arg("engine", "Xray"),
            ),
            XrayError::ExitedEarly { code, .. } => (
                ErrorKind::Internal,
                Msg::new("engine.process.xray.exited").arg("code", code_text(*code)),
            ),
            XrayError::NotReady { port, .. } => (
                ErrorKind::Network,
                Msg::new("engine.process.xray.socksNotReady").arg("port", port),
            ),
            XrayError::ExitNotConfirmed => (
                ErrorKind::Internal,
                Msg::new("engine.process.stopUnconfirmed").arg("engine", "Xray"),
            ),
            XrayError::SlotOccupied => (
                ErrorKind::Conflict,
                Msg::new("engine.process.xray.slotOccupied"),
            ),
            XrayError::PortOwnedByOtherSlot => (
                ErrorKind::Conflict,
                Msg::new("engine.process.xray.portTaken"),
            ),
            XrayError::NotRunning => (
                ErrorKind::Conflict,
                Msg::new("engine.process.xray.notRunning"),
            ),
            XrayError::NotStarted => (
                ErrorKind::Conflict,
                Msg::new("engine.process.xray.notStarted"),
            ),
        };
        AppError::msg(kind, msg).with_source(err)
    }
}

/// Instance states, shared with the exit forwarder. Its `swap(EXITED)` and the start's
/// `STARTING -> RUNNING` exchange decide exactly once who reports an exit: an event for an
/// instance that reached RUNNING, `start`'s own error otherwise (a failed start stays STARTING).
const STARTING: u8 = 0;
const RUNNING: u8 = 1;
/// A running instance we are stopping: its exit is expected.
const STOPPING: u8 = 2;
/// The forwarder has seen the exit.
const EXITED: u8 = 3;

/// One slot's process.
struct Instance {
    child: EngineChild,
    started_at: SystemTime,
    state: Arc<AtomicU8>,
}

impl Instance {
    fn alive(&self) -> bool {
        self.child.exited().is_none()
    }

    fn running(&self) -> bool {
        self.state.load(Ordering::SeqCst) == RUNNING && self.alive()
    }
}

/// The two Xray slots of one tunnel session.
pub struct XraySupervisor {
    exe: PathBuf,
    logs: Option<PathBuf>,
    slots: [Option<Instance>; 2],
    /// What each slot was last started from: `restart` reuses it, also after a failed attempt,
    /// until `stop` forgets it.
    launches: [Option<(SlotEndpoint, SlotLaunch)>; 2],
    active: Option<Slot>,
    events: mpsc::Sender<XrayEvent>,
}

impl XraySupervisor {
    /// `exe` = the bundled Xray (also the path routing sends direct: `RoutingInputs::engine_paths`);
    /// `logs` = the logs dir for `xray-a.log` / `xray-b.log`.
    pub fn new(exe: PathBuf, logs: Option<PathBuf>, events: mpsc::Sender<XrayEvent>) -> Self {
        Self {
            exe,
            logs,
            slots: [None, None],
            launches: [None, None],
            active: None,
            events,
        }
    }

    /// Starts `slot` and waits for its authenticated SOCKS readiness (runtime). A slot whose
    /// process already exited is reaped first (restart after a crash); a live one is refused.
    /// On any failure the new process is stopped again before returning.
    pub async fn start(
        &mut self,
        slot: Slot,
        ep: SlotEndpoint,
        launch: SlotLaunch,
        cancel: &CancellationToken,
    ) -> Result<SlotStatus, XrayError> {
        let (i, o) = (slot.index(), slot.other().index());
        if self.slots[i].as_ref().is_some_and(Instance::alive) {
            return Err(XrayError::SlotOccupied);
        }
        let other_port = self.launches[o].as_ref().map(|(e, _)| e.port());
        if self.slots[o].as_ref().is_some_and(Instance::alive) && other_port == Some(ep.port()) {
            return Err(XrayError::PortOwnedByOtherSlot);
        }
        self.slots[i] = None;
        let (port, creds) = (ep.port(), ep.creds().clone());
        // Recorded before the spawn: `restart` retries what the caller asked for last.
        let launch = &self.launches[i].insert((ep, launch)).1;
        let child = EngineChild::spawn(Spec {
            engine: Engine::Xray,
            exe: &self.exe,
            args: &["run", "-config", "stdin:"],
            config: &launch.config,
            log: self.logs.as_deref().map(|dir| (dir, slot.log_stem())),
            marker: None,
            scrub: Scrubber::new(&launch.config, &[&creds.user, &creds.pass]),
        })
        .map_err(XrayError::Spawn)?;
        let state = Arc::new(AtomicU8::new(STARTING));
        forward_exit(slot, &child, state.clone(), self.events.clone());
        tracing::info!(slot = slot.log_stem(), pid = child.pid(), "xray spawned");
        let inst = self.slots[i].insert(Instance {
            child,
            started_at: SystemTime::now(),
            state: state.clone(),
        });
        let outcome = match ready(&inst.child, port, &creds, cancel).await {
            // Fails only when the exit landed right after the readiness check (forwarder: EXITED).
            Ok(()) => state
                .compare_exchange(STARTING, RUNNING, Ordering::SeqCst, Ordering::SeqCst)
                .map(drop)
                .map_err(|_| early_exit(&inst.child)),
            err => err,
        };
        if let Err(err) = outcome {
            if let Err(stop) = self.reap(slot).await {
                tracing::warn!(slot = slot.log_stem(), error = %stop, "failed slot not stopped");
            }
            return Err(err);
        }
        Ok(self.status(slot))
    }

    /// Starts `slot` again from its last launch (same port and credentials, so sing-box needs
    /// no change), also after a failed attempt (the tunnel's backoff retries). A live instance
    /// is stopped first; the active mark is kept.
    pub async fn restart(
        &mut self,
        slot: Slot,
        cancel: &CancellationToken,
    ) -> Result<SlotStatus, XrayError> {
        let Some((ep, launch)) = self.launches[slot.index()].clone() else {
            return Err(XrayError::NotStarted);
        };
        self.reap(slot).await?;
        self.start(slot, ep, launch, cancel).await
    }

    /// Terminates `slot` and waits for the exit (idempotent), then forgets its launch and the
    /// active mark. An unconfirmed exit keeps everything so the stop can be retried.
    pub async fn stop(&mut self, slot: Slot) -> Result<(), XrayError> {
        self.reap(slot).await?;
        self.launches[slot.index()] = None;
        if self.active == Some(slot) {
            self.active = None;
        }
        Ok(())
    }

    /// Stops the slot's process and waits for the exit; an unconfirmed exit keeps the instance.
    async fn reap(&mut self, slot: Slot) -> Result<(), XrayError> {
        let Some(inst) = &self.slots[slot.index()] else {
            return Ok(());
        };
        let _ = inst
            .state
            .compare_exchange(RUNNING, STOPPING, Ordering::SeqCst, Ordering::SeqCst);
        let stopped = inst.child.stop_and_wait(GRACEFUL_STOP, STOP_TIMEOUT).await;
        if stopped.is_none() {
            return Err(XrayError::ExitNotConfirmed);
        }
        self.slots[slot.index()] = None;
        Ok(())
    }

    /// Stops both slots at the same time (both are attempted), so a slot that ignores CTRL_BREAK
    /// costs its grace period once, not once per slot; the first error is returned.
    pub async fn stop_all(&mut self) -> Result<(), XrayError> {
        for inst in self.slots.iter().flatten() {
            let _ =
                inst.state
                    .compare_exchange(RUNNING, STOPPING, Ordering::SeqCst, Ordering::SeqCst);
        }
        let reap = |slot: Slot| {
            let inst = self.slots[slot.index()].as_ref();
            async move {
                match inst {
                    Some(inst) => inst
                        .child
                        .stop_and_wait(GRACEFUL_STOP, STOP_TIMEOUT)
                        .await
                        .is_some(),
                    None => true,
                }
            }
        };
        let (a, b) = tokio::join!(reap(Slot::A), reap(Slot::B));
        let mut first = Ok(());
        for (slot, stopped) in [(Slot::A, a), (Slot::B, b)] {
            if stopped {
                self.slots[slot.index()] = None;
                self.launches[slot.index()] = None;
                if self.active == Some(slot) {
                    self.active = None;
                }
            } else if first.is_ok() {
                first = Err(XrayError::ExitNotConfirmed);
            }
        }
        first
    }

    /// Marks `slot` as the one sing-box's selector points at (after the Clash API select).
    pub fn activate(&mut self, slot: Slot) -> Result<(), XrayError> {
        if !self.slots[slot.index()]
            .as_ref()
            .is_some_and(Instance::running)
        {
            return Err(XrayError::NotRunning);
        }
        self.active = Some(slot);
        Ok(())
    }

    /// The slot last activated (cleared when it is stopped; kept across a crash and failed
    /// restarts, since the selector still points at it).
    pub fn active(&self) -> Option<Slot> {
        self.active
    }

    /// What `slot` runs right now (all `None` / `false` when empty).
    pub fn status(&self, slot: Slot) -> SlotStatus {
        let i = slot.index();
        let (Some(inst), Some((ep, launch))) = (&self.slots[i], &self.launches[i]) else {
            return SlotStatus::default();
        };
        let running = inst.running();
        SlotStatus {
            running,
            port: Some(ep.port()),
            pid: Some(inst.child.pid()),
            started_at: Some(inst.started_at),
            dial_target: launch.dial_target.filter(|_| running),
        }
    }

    /// Port and credentials of `slot`'s process: main-process only (failure diagnostics).
    pub fn endpoint(&self, slot: Slot) -> Option<&SlotEndpoint> {
        let i = slot.index();
        self.slots[i]
            .as_ref()
            .and(self.launches[i].as_ref())
            .map(|(ep, _)| ep)
    }

    /// The dominant upstream fault in the slot's output of the last two minutes.
    pub fn recent_fault(&self, slot: Slot) -> Option<OutboundFault> {
        let inst = self.slots[slot.index()].as_ref()?;
        let since = Instant::now().checked_sub(FAULT_MAX_AGE);
        let lines = inst.child.raw_lines(since);
        classify_xray_fault(lines.iter().map(|l| &**l))
    }

    /// The slot's recent output (≤ 256 KiB, Xray's own timestamps), redacted.
    pub fn log_tail(&self, slot: Slot) -> String {
        self.slots[slot.index()]
            .as_ref()
            .map(|i| i.child.tail(child::RING_LINES).join("\n"))
            .unwrap_or_default()
    }
}

/// Authenticated SOCKS readiness raced against the exit and the caller's cancel.
async fn ready(
    child: &EngineChild,
    port: u16,
    creds: &Creds,
    cancel: &CancellationToken,
) -> Result<(), XrayError> {
    let mut exit = child.exit_watch();
    tokio::select! {
        biased;
        () = cancel.cancelled() => Err(XrayError::Cancelled),
        Some(_) = exited(&mut exit) => Err(early_exit(child)),
        res = socks5::wait_ready(port, Some(creds), READY_TIMEOUT, cancel) => match res {
            Ok(()) if child.exited().is_some() => Err(early_exit(child)),
            Ok(()) => Ok(()),
            Err(SocksError::Cancelled) => Err(XrayError::Cancelled),
            Err(cause) => Err(XrayError::NotReady { port, cause }),
        },
    }
}

/// The error for a child that exited before readiness. Exit 23 = config refused (the reason is
/// the `Failed to start:` line on stdout); `-1` = `server.Start()` failed, typically the SOCKS
/// port could not be bound.
fn early_exit(child: &EngineChild) -> XrayError {
    let Some(info) = child.exited() else {
        // Callers know the exit was published; never claim a reason we did not see.
        return XrayError::ExitedEarly {
            code: None,
            tail: String::new(),
        };
    };
    if info.code == Some(EXIT_CONFIG_REJECTED) {
        let line = child.find_line(|l| l.starts_with(FAILED_TO_START));
        return XrayError::ConfigRejected(line.unwrap_or(info.stderr_tail));
    }
    XrayError::ExitedEarly {
        code: info.code,
        tail: info.stderr_tail,
    }
}

/// Turns the exit of a slot that had been running (or that we stopped) into an [`XrayEvent`].
fn forward_exit(
    slot: Slot,
    child: &EngineChild,
    state: Arc<AtomicU8>,
    events: mpsc::Sender<XrayEvent>,
) {
    let (pid, mut exit) = (child.pid(), child.exit_watch());
    tokio::spawn(async move {
        let Some(info) = exited(&mut exit).await else {
            return;
        };
        let expected = match state.swap(EXITED, Ordering::SeqCst) {
            RUNNING => info.user_initiated,
            STOPPING => true,
            // Exit before or instead of readiness: `start` reports it as its own error.
            _ => return,
        };
        if !expected {
            tracing::warn!(slot = slot.log_stem(), pid, code = ?info.code, "xray exited unexpectedly");
        }
        let event = XrayEvent::Exited {
            slot,
            pid,
            code: info.code,
            expected,
            graceful: info.graceful,
            tail: info.stderr_tail,
        };
        // A closed channel only means nobody listens any more.
        let _ = events.send(event).await;
    });
}

static LEVEL: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\[(Info|Warning|Error)\]"));
static REALITY: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)reality verification failed|reality:.*invalid connection|bad reality")
});
static TLS: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(x509|bad certificate|tls: handshake failure|remote error: tls)\b")
});
static NO_DESTINATION: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)failed to find an available destination|failed to process outbound traffic|",
        r"all retry attempts failed",
    ))
});
static DIAL_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)\b(connection refused|i/o timeout|no route to host|network is unreachable|",
        r"context deadline exceeded|dial tcp)\b",
    ))
});
static CONNECTION_ENDS: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bconnection ends\b"));
static ENDS_ON_FAILURE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)dial tcp|refused|timeout|reset"));

/// Outbound fault of Xray output: of the last 500 lines only `[Info]` / `[Warning]` /
/// `[Error]` lines count (Xray logs dial and handshake failures at Info), each classified as
/// reality, else tls, else unreachable; thresholds 2 / 2 / 3, checked in that priority.
/// `connection ends` counts only with a dial / refused / timeout / reset cause: routine closes
/// are not failures. Caveat kept from the old code: Xray's client log cannot tell "server
/// rejected my REALITY" from "server unreachable" (both read `failed to find an available
/// destination`), so an incompatible REALITY server reads as unreachable, which still drives
/// server fallback.
pub fn classify_xray_fault<'a>(lines: impl IntoIterator<Item = &'a str>) -> Option<OutboundFault> {
    let lines: Vec<&str> = lines.into_iter().collect();
    let (mut reality, mut tls, mut unreachable) = (0, 0, 0);
    for line in &lines[lines.len().saturating_sub(FAULT_WINDOW)..] {
        if !LEVEL.is_match(line) {
            continue;
        }
        if REALITY.is_match(line) {
            reality += 1;
        } else if TLS.is_match(line) {
            tls += 1;
        } else if NO_DESTINATION.is_match(line)
            || DIAL_FAILURE.is_match(line)
            || (CONNECTION_ENDS.is_match(line) && ENDS_ON_FAILURE.is_match(line))
        {
            unreachable += 1;
        }
    }
    if reality >= 2 {
        Some(OutboundFault::RealityKeyMismatch)
    } else if tls >= 2 {
        Some(OutboundFault::TlsHandshakeFailed)
    } else if unreachable >= 3 {
        Some(OutboundFault::UpstreamUnreachable)
    } else {
        None
    }
}

/// `exe run -test -config stdin:` (tests and diagnostics): Xray builds the config without
/// starting it and prints `Configuration OK.` with exit 0; a refused config exits 23.
pub async fn check_config(exe: &Path, config: &[u8]) -> Result<(), XrayError> {
    let args = ["run", "-test", "-config", "stdin:"];
    let out = child::run_once(Engine::Xray, exe, &args, Some(config), CHECK_TIMEOUT)
        .await
        .map_err(XrayError::Spawn)?;
    if out.status.success() {
        return Ok(());
    }
    let scrub = Scrubber::new(config, &[]);
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let code = out.status.code();
    if code == Some(EXIT_CONFIG_REJECTED) {
        let reason = lines.iter().find(|l| l.starts_with(FAILED_TO_START));
        let reason = reason
            .or(lines.last())
            .map(|l| scrub.clean(l))
            .unwrap_or_default();
        return Err(XrayError::ConfigRejected(reason));
    }
    Err(XrayError::ExitedEarly {
        code,
        tail: scrub.tail(&lines),
    })
}
