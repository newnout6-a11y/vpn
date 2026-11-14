//! Tunnel mode through the helper service (owner decision 12.11.2026). [`Remote`] is the tunnel
//! runtime over the service's pipe — the same `Runtime` the lifecycle, the automation and the UI
//! already drive, so none of them changes — and [`Split`] puts it next to this process's own
//! runtime: Tunnel-mode starts go to the service, proxy-mode starts stay here.
//!
//! The pipe's server must run the installed service exe (research `service.md` §3: a pipe someone
//! else created is refused before anything is sent). A session the service kept after this app's
//! window crashed (owner question 23) is parked at connect: it is not shown as running until the
//! lifecycle's own connect of the same upstream takes it over (`start`), so nothing stops it on
//! the way; Quit and Disconnect send a stop as before. A link lost without the app asking (the
//! service restarted and resumes its session) is shown as ended, then re-attached the same way
//! (`reattach`, p-follow); a drop the kill switch held stays paused meanwhile, and the resumed
//! run joins that pause as its recovery (`adopt`, fix-follow).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{broadcast, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Notice, OutboundFault};
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::store::Store;
use vpnte_probes::leak::SelfTestResult;
use vpnte_service::pipe::client::{CallError, Client, Frames, Incoming, Requests, ServerCheck};
use vpnte_service::proto::{
    Event, KeptSession, KillSwitchStateWire, Reply, Request, RuleSetsWire, StatusReply, StatusWire,
    TunnelEventWire, WireError,
};
use vpnte_tunnel::api::{ExitInfo, TunError, TunStatus, TunStatusKind, TunWarning, TunnelEvent};
use vpnte_tunnel::runtime::InputsSource;

use crate::boot::service::Presence;
use crate::svc_core::docs::ProtectionDoc;

#[cfg(test)]
mod elevated;
mod failover;
mod gens;
pub(super) mod guard;
#[cfg(test)]
mod presence_tests;
mod runtime;
mod split;
mod start;
#[cfg(test)]
mod tests;

pub(super) use split::Split;

/// How long a connect waits for a busy pipe.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one call waits for a service the SCM reports as starting or running but whose pipe
/// is not there yet: after a Windows restart the app's autostart runs at sign-in, in parallel
/// with the automatic services (p-live-fix). The pauses double from the first to the last.
const START_WAIT: Duration = Duration::from_secs(45);
const START_PAUSES: (Duration, Duration) = (Duration::from_millis(500), Duration::from_secs(4));
/// A service the SCM did not know is looked for again at most this often (it may have been out
/// of reach, or installed meanwhile): "missing" is never kept for the whole run.
const LOOK_AGAIN: Duration = Duration::from_secs(30);
/// Start-up connects to the service (`attach`), and the pause between them.
const ATTACH_TRIES: u32 = 5;
const ATTACH_PAUSE: Duration = Duration::from_secs(2);
/// Connects after a lost link (`reattach`): Windows restarts a crashed service after 5 s, then
/// 10 s; a third crash (60 s) is left to the next connect, which parks the session as well.
const REATTACH_TRIES: u32 = 12;
/// Status reads after the re-link while the restarted service may still be starting the session
/// it resumes (it is offered for a take-over once its engine runs).
const RESUME_TRIES: u32 = 5;

/// The tunnel runtime in the helper service.
#[derive(Clone)]
pub(crate) struct Remote(Arc<Inner>);

struct Inner {
    /// The service is installed (read at start and after an install from Settings).
    installed: AtomicBool,
    /// The SCM says it is coming up and its pipe is not answering yet (p-live-fix).
    starting: AtomicBool,
    /// When the SCM was last asked while the service was not installed.
    looked: Mutex<Option<std::time::Instant>>,
    /// What the SCM "says" about a private test pipe's service (`None`: stopped).
    #[cfg(test)]
    test_presence: Mutex<Option<Presence>>,
    /// The protocol the last link speaks (0: no link yet); the apps page says when an older
    /// service cannot carry its scope (p-app-split).
    protocol: AtomicU32,
    /// A private test pipe served by anyone; `None` = the service's pipe, served by its exe.
    test_pipe: Option<String>,
    inputs: Arc<dyn InputsSource>,
    protection: Arc<Store<ProtectionDoc>>,
    status: watch::Sender<TunStatus>,
    events: broadcast::Sender<TunnelEvent>,
    /// Kill-switch notices of the service (blocked traffic, skipped exceptions).
    notices: broadcast::Sender<Notice>,
    /// The service's latest leak self-test of the shown session (protocol 2, p-svc-recheck).
    self_test: watch::Sender<Option<SelfTestResult>>,
    /// Counts links lost without the app asking (the service restarted): each one re-attaches.
    losses: watch::Sender<u64>,
    link: tokio::sync::Mutex<Option<Link>>,
    pending: Mutex<HashMap<u64, oneshot::Sender<Result<Reply, WireError>>>>,
    state: Mutex<State>,
    shutdown: CancellationToken,
}

/// A live connection: its writing half and a token cancelled when its reader ends.
struct Link {
    requests: Requests,
    gone: CancellationToken,
}

#[derive(Default)]
struct State {
    last_exit: Option<ExitInfo>,
    recent_fault: Option<OutboundFault>,
    /// A session the service kept for this user, not taken over yet; its status waits here.
    kept: Option<KeptSession>,
    parked: Option<TunStatus>,
    /// A new connection whose first view is not in yet: nothing is shown meanwhile.
    attaching: bool,
    /// Re-attached after a lost link: what the restarted service starts by itself (the session
    /// it resumes) waits for the take-over; any operation of the app ends the wait.
    waiting: bool,
    gens: gens::Gens,
    /// The Smart RU lists the service's last start ran (protocol 4, psmart-b2).
    rule_sets: Option<RuleSetsWire>,
}

fn lost() -> CallError {
    CallError::Pipe(AppError::msg(
        ErrorKind::Network,
        Msg::new("service.pipe.lost"),
    ))
}

/// The pipe client's "nobody serves the pipe" (no service, or one not up yet).
const PIPE_ABSENT: &str = "service.pipe.unavailable";

/// A failed connect as one true, calm line (p-live-fix): the pipe that is not there says why
/// from the SCM's state, a refused server says another program answers; anything else (busy,
/// denied) keeps the pipe client's own sentence.
fn truthful(err: AppError, presence: Presence) -> AppError {
    let key = match err.msg.as_ref().map(|m| m.key.as_ref()) {
        Some(PIPE_ABSENT) => match presence {
            Presence::Missing => "app.service.missing",
            Presence::Starting | Presence::Running => "app.service.starting",
            Presence::Stopped | Presence::Stopping => "app.service.stopped",
        },
        Some("service.pipe.notOurs") => "app.service.refused",
        _ => return err,
    };
    AppError {
        msg: Some(Msg::new(key)),
        ..err
    }
}

/// A failed call as the runtime's error: the service's own message, or the pipe's.
fn tun_error(err: CallError) -> TunError {
    match err {
        CallError::Service(wire) => TunError {
            error: AppError::msg(wire.kind, wire.msg),
            warnings: wire.warnings,
        },
        CallError::Pipe(err) => TunError::from(err),
    }
}

fn unexpected(reply: &Reply) -> CallError {
    tracing::warn!(?reply, "unexpected service reply");
    CallError::Pipe(AppError::msg(
        ErrorKind::Internal,
        Msg::new("service.pipe.badReply"),
    ))
}

impl Remote {
    pub(super) fn new(
        inputs: Arc<dyn InputsSource>,
        protection: Arc<Store<ProtectionDoc>>,
        shutdown: CancellationToken,
    ) -> Self {
        let remote = Self::build(None, inputs, protection, shutdown);
        remote.recheck();
        remote
    }

    /// A remote runtime over a private test pipe, taken as installed.
    #[cfg(test)]
    fn on_pipe(
        name: &str,
        inputs: Arc<dyn InputsSource>,
        protection: Arc<Store<ProtectionDoc>>,
    ) -> Self {
        let remote = Self::build(
            Some(name.into()),
            inputs,
            protection,
            CancellationToken::new(),
        );
        remote.0.installed.store(true, Ordering::Relaxed);
        remote
    }

    /// No service: the guard and the split keep everything in this process (tests).
    #[cfg(test)]
    pub(super) fn absent(protection: Arc<Store<ProtectionDoc>>) -> Self {
        let inputs = Arc::new(tests::NoInputs);
        Self::build(None, inputs, protection, CancellationToken::new())
    }

    fn build(
        test_pipe: Option<String>,
        inputs: Arc<dyn InputsSource>,
        protection: Arc<Store<ProtectionDoc>>,
        shutdown: CancellationToken,
    ) -> Self {
        Self(Arc::new(Inner {
            installed: AtomicBool::new(false),
            starting: AtomicBool::new(false),
            looked: Mutex::new(None),
            #[cfg(test)]
            test_presence: Mutex::new(None),
            protocol: AtomicU32::new(0),
            test_pipe,
            inputs,
            protection,
            status: watch::channel(TunStatus::default()).0,
            events: broadcast::channel(256).0,
            notices: broadcast::channel(16).0,
            self_test: watch::channel(None).0,
            losses: watch::channel(0).0,
            link: tokio::sync::Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            state: Mutex::new(State::default()),
            shutdown,
        }))
    }

    /// The protocol the service's last link speaks; `None` before the first link.
    pub(crate) fn protocol(&self) -> Option<u32> {
        Some(self.0.protocol.load(Ordering::Relaxed)).filter(|p| *p > 0)
    }

    /// The service is installed: Tunnel mode and the kill switch go through it. A service the
    /// SCM did not know at the last look is looked for again every [`LOOK_AGAIN`].
    pub(crate) fn installed(&self) -> bool {
        if self.0.installed.load(Ordering::Relaxed) {
            return true;
        }
        if self.0.test_pipe.is_some() {
            return false;
        }
        let due = {
            let mut looked = self.0.looked.lock();
            let due = looked.is_none_or(|at| at.elapsed() >= LOOK_AGAIN);
            if due {
                *looked = Some(std::time::Instant::now());
            }
            due
        };
        due && self.recheck()
    }

    /// Reads the SCM again (start, and after an install from Settings); the new answer.
    pub(crate) fn recheck(&self) -> bool {
        let installed = crate::boot::service::installed();
        self.0.installed.store(installed, Ordering::Relaxed);
        *self.0.looked.lock() = Some(std::time::Instant::now());
        installed
    }

    /// The SCM reports the service coming up while its pipe does not answer yet (after a Windows
    /// restart): the page says «Служба-помощник запускается…», not "not installed".
    pub(crate) fn starting(&self) -> bool {
        self.0.starting.load(Ordering::Relaxed)
    }

    /// The service's state now (the SCM; a private test pipe has none: what the test set, else
    /// stopped, so nothing waits for it). Keeps `installed` and `starting` in step.
    fn observe(&self) -> Presence {
        if self.0.test_pipe.is_some() {
            #[cfg(test)]
            let presence = self.0.test_presence.lock().unwrap_or(Presence::Stopped);
            #[cfg(not(test))]
            let presence = Presence::Stopped;
            self.0.starting.store(presence.coming(), Ordering::Relaxed);
            return presence;
        }
        let presence = crate::boot::service::presence();
        self.0
            .installed
            .store(presence != Presence::Missing, Ordering::Relaxed);
        self.0.starting.store(presence.coming(), Ordering::Relaxed);
        *self.0.looked.lock() = Some(std::time::Instant::now());
        presence
    }

    pub(super) fn notices(&self) -> broadcast::Receiver<Notice> {
        self.0.notices.subscribe()
    }

    /// The service's leak self-tests of the shown TUN session, as they arrive.
    pub(super) fn self_tests(&self) -> watch::Receiver<Option<SelfTestResult>> {
        self.0.self_test.subscribe()
    }

    /// Changes once per link lost without the app asking (the service restarted).
    pub(super) fn losses(&self) -> watch::Receiver<u64> {
        self.0.losses.subscribe()
    }

    /// The current connection, or a new one (the pipe's server checked first). A service the
    /// SCM reports as starting or running gets [`START_WAIT`] to open its pipe; a failure says
    /// what is true: not installed, still starting, stopped, or another program on its pipe.
    async fn link(&self) -> Result<Requests, CallError> {
        let mut slot = self.0.link.lock().await;
        if let Some(link) = slot.as_ref().filter(|l| !l.gone.is_cancelled()) {
            return Ok(link.requests.clone());
        }
        let deadline = tokio::time::Instant::now() + START_WAIT;
        let mut pause = START_PAUSES.0;
        let mut client = loop {
            let err = match self.open().await {
                Ok(client) => break client,
                Err(err) => err,
            };
            let presence = self.observe();
            let absent = err.msg.as_ref().is_some_and(|m| m.key == PIPE_ABSENT);
            let wait = absent
                && presence.coming()
                && tokio::time::Instant::now() + pause < deadline
                && self.pause_for(pause).await;
            if !wait {
                return Err(CallError::Pipe(truthful(err, presence)));
            }
            tracing::debug!(
                ?presence,
                "helper service starting: its pipe is not there yet"
            );
            pause = (pause * 2).min(START_PAUSES.1);
        };
        self.0.starting.store(false, Ordering::Relaxed);
        let (protocol, _) = client.hello(env!("CARGO_PKG_VERSION")).await?;
        self.0.protocol.store(protocol, Ordering::Relaxed);
        let (requests, frames) = client.split().await?;
        let gone = CancellationToken::new();
        {
            let mut st = self.0.state.lock();
            st.gens.relink();
            // Nothing is shown until the service's view is in (`settle`).
            st.attaching = true;
        }
        tokio::spawn(dispatch(self.0.clone(), frames, gone.clone()));
        let view = self.send(&requests, Request::Status).await;
        self.settle(view);
        *slot = Some(Link {
            requests: requests.clone(),
            gone,
        });
        Ok(requests)
    }

    /// The first view of a new connection: a session the service kept for this user (his app's
    /// window crashed) is parked for a take-over instead of shown — the lifecycle's connect would
    /// stop a running one first; otherwise what arrived meanwhile is shown.
    fn settle(&self, view: Result<Reply, CallError>) {
        let mut st = self.0.state.lock();
        st.attaching = false;
        if let Ok(Reply::Status(reply)) = view {
            absorb(&mut st, &reply);
            if reply.kept.is_some() {
                tracing::info!(
                    "the service kept a session for this user: waiting for the take-over"
                );
                st.kept = reply.kept;
                st.parked = Some(reply.tunnel.into());
                st.waiting = false;
                return;
            }
        }
        if st.waiting {
            return;
        }
        if let Some(status) = st.parked.take() {
            drop(st);
            self.0.status.send_replace(status);
        }
    }

    /// One request and its answer; the events it caused are published before it returns.
    async fn call(&self, request: Request) -> Result<Reply, CallError> {
        let requests = self.link().await?;
        self.send(&requests, request).await
    }

    async fn send(&self, requests: &Requests, request: Request) -> Result<Reply, CallError> {
        let id = requests.id();
        let (tx, rx) = oneshot::channel();
        self.0.pending.lock().insert(id, tx);
        if let Err(err) = requests.send(id, request).await {
            self.0.pending.lock().remove(&id);
            return Err(err);
        }
        match rx.await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(wire)) => Err(CallError::Service(wire)),
            Err(_) => Err(lost()),
        }
    }

    /// Status, last exit and fault from the service.
    async fn refresh(&self) -> Result<StatusReply, CallError> {
        let reply = match self.call(Request::Status).await? {
            Reply::Status(reply) => *reply,
            other => return Err(unexpected(&other)),
        };
        absorb(&mut self.0.state.lock(), &reply);
        Ok(reply)
    }

    /// Connects and learns a kept session; the session to take over, if any (start-up).
    /// A crashed window's last connection may still be closing (`busySelf`): a few tries, a few
    /// seconds apart, then the next connect parks it. A service Windows is still starting is
    /// waited for inside each try ([`START_WAIT`]) while the SCM says it is coming up.
    pub(super) async fn attach(&self) -> Option<KeptSession> {
        if !self.installed() {
            return None;
        }
        for attempt in 1..=ATTACH_TRIES {
            match self.link().await {
                Ok(_) => return self.0.state.lock().kept.clone(),
                Err(err) => {
                    tracing::info!(attempt, error = %err, "helper service not reached at start");
                }
            }
            if !self.pause().await {
                return None;
            }
        }
        None
    }

    /// After a lost link (the service restarted): connects again as at start-up, then gives the
    /// restarted service a few seconds to bring back the session it resumes (it is offered for a
    /// take-over once its engine runs; until then its own events are held back). The session to
    /// take over, if any.
    pub(super) async fn reattach(&self) -> Option<KeptSession> {
        if !self.installed() {
            return None;
        }
        self.0.state.lock().waiting = true;
        let kept = self.resumed_session().await;
        self.stop_waiting();
        kept
    }

    async fn resumed_session(&self) -> Option<KeptSession> {
        let mut tries = 1;
        while let Err(err) = self.link().await {
            tracing::debug!(tries, error = %err, "helper service not reached again yet");
            if tries == REATTACH_TRIES || !self.pause().await {
                return None;
            }
            tries += 1;
        }
        for _ in 0..RESUME_TRIES {
            {
                let st = self.0.state.lock();
                if st.kept.is_some() || !st.waiting {
                    return st.kept.clone();
                }
            }
            if !self.pause().await {
                return None;
            }
            let reply = self.refresh().await.ok()?;
            let mut st = self.0.state.lock();
            // Not after an operation of the app began: its own start's events must flow.
            if reply.kept.is_some() && st.waiting {
                st.kept = reply.kept;
                st.parked = Some(reply.tunnel.into());
                st.waiting = false;
            }
        }
        self.0.state.lock().kept.clone()
    }

    /// The wait after a re-link is over: unless a session waits for its take-over (or the app
    /// acted meanwhile), what arrived is shown.
    fn stop_waiting(&self) {
        let mut st = self.0.state.lock();
        if !std::mem::take(&mut st.waiting) || st.kept.is_some() {
            return;
        }
        if let Some(status) = st.parked.take() {
            drop(st);
            self.0.status.send_replace(status);
        }
    }

    /// One pause between tries; `false` when the app is closing.
    async fn pause(&self) -> bool {
        self.pause_for(ATTACH_PAUSE).await
    }

    async fn pause_for(&self, pause: Duration) -> bool {
        tokio::select! {
            () = self.0.shutdown.cancelled() => false,
            () = tokio::time::sleep(pause) => true,
        }
    }

    /// Opens the pipe: the installed service's, served by the service itself, or the private
    /// test pipe. A service the SCM does not know is "absent" like a pipe that is not there.
    async fn open(&self) -> Result<Client, AppError> {
        let (pipe, check) = match &self.0.test_pipe {
            Some(name) => (name.as_str(), ServerCheck::Any),
            None => match crate::boot::service::installed_binary() {
                Ok(Some(exe)) => (vpnte_service::sddl::PIPE_NAME, ServerCheck::Image(exe)),
                _ => return Err(AppError::msg(ErrorKind::Network, Msg::new(PIPE_ABSENT))),
            },
        };
        Client::connect(pipe, &check, CONNECT_TIMEOUT).await
    }

    /// The parked session's status (local proxy kind, name) for the take-over's target.
    pub(super) fn parked(&self) -> Option<TunStatus> {
        self.0.state.lock().parked.clone()
    }

    /// The Smart RU lists the service's last start ran, as it reported them (protocol 4).
    pub(super) fn rule_sets(&self) -> Option<RuleSetsWire> {
        self.0.state.lock().rule_sets.clone()
    }

    /// Shows the parked session's status while it stays parked: a stop of the lifecycle then
    /// sees the run it ends (a take-over that could not run, fixfollow-a2).
    pub(super) fn reveal_parked(&self) {
        let status = self.0.state.lock().parked.clone();
        if let Some(status) = status {
            self.0.status.send_replace(status);
        }
    }

    /// The parked session joins the lifecycle's paused one (a drop the kill switch held when
    /// the service restarted): the start events of a run the runtime brought back by itself, so
    /// the pause ends as after an engine restart. `false`: it ended meanwhile.
    pub(super) async fn adopt(&self) -> bool {
        self.take_over().await.is_ok()
    }

    /// The service still holds something of this app's session: a run, or the kill switch's
    /// block. Out of reach counts as nothing: no engine runs without the service, and a block
    /// that cannot be seen is not claimed.
    pub(super) async fn holds_run(&self) -> bool {
        match self.refresh().await {
            Ok(reply) => {
                reply.tunnel.running
                    || reply.protection.kill_switch == KillSwitchStateWire::Blocking
            }
            Err(err) => {
                tracing::info!(error = %err, "helper service not reached after the re-link");
                false
            }
        }
    }

    /// The run the lifecycle holds paused is over (fixfollow-a1): its end, as a stop reads.
    pub(super) fn announce_stopped(&self) {
        let _ = self
            .0
            .events
            .send(TunnelEvent::Status(TunStatusKind::Stopped));
    }

    /// Forgets a parked session (and ends a wait for one): what comes next replaces or stops it.
    fn unpark(&self) {
        let mut st = self.0.state.lock();
        st.kept = None;
        st.parked = None;
        st.waiting = false;
    }
}

/// The last exit and fault of a status reply (the service sends them to the session's user
/// only), and the lists report.
fn absorb(st: &mut State, reply: &StatusReply) {
    if let Some(exit) = &reply.last_exit {
        st.last_exit = Some(exit.clone().into());
    }
    st.recent_fault = reply.recent_fault;
    st.rule_sets = reply.tunnel.rule_sets.clone();
}

/// Reads the connection until it ends: events are published in order, each answer reaches its
/// caller after the events before it.
async fn dispatch(inner: Arc<Inner>, mut frames: Frames, gone: CancellationToken) {
    loop {
        let next = tokio::select! {
            () = inner.shutdown.cancelled() => break,
            next = frames.next() => next,
        };
        match next {
            Ok(Incoming::Answer { id, result }) => {
                if let Some(tx) = inner.pending.lock().remove(&id) {
                    let _ = tx.send(result);
                }
            }
            Ok(Incoming::Event(Event::Status(wire))) => on_status(&inner, *wire),
            Ok(Incoming::Event(Event::Tunnel(wire))) => on_tunnel(&inner, wire),
            Ok(Incoming::Event(Event::Notice(notice))) => {
                let _ = inner.notices.send(notice);
            }
            Err(err) => {
                tracing::warn!(error = %err, "helper service connection ended");
                break;
            }
        }
    }
    gone.cancel();
    on_lost(&inner);
}

fn on_status(inner: &Inner, mut wire: StatusWire) {
    let mut st = inner.state.lock();
    if let Some(exit) = wire.last_exit.take() {
        st.last_exit = Some(exit.into());
    }
    st.recent_fault = wire.recent_fault.take();
    st.rule_sets = wire.rule_sets.take();
    let self_test = wire.self_test.take();
    let status = TunStatus::from(wire);
    if st.attaching || st.waiting || st.kept.is_some() {
        st.parked = Some(status);
        return;
    }
    drop(st);
    // The service pushes its status with every leak self-test (30 s while the kill switch is on):
    // an unchanged status wakes nobody.
    inner.status.send_if_modified(|shown| {
        let changed = *shown != status;
        if changed {
            *shown = status;
        }
        changed
    });
    // Every status carries the service's latest run; the leak forwarder keeps the new ones.
    if self_test.is_some() {
        inner.self_test.send_replace(self_test);
    }
}

fn on_tunnel(inner: &Inner, wire: TunnelEventWire) {
    let mut st = inner.state.lock();
    let event = st.gens.event(TunnelEvent::from(wire));
    // A parked session's own events wait for its take-over (its status is kept meanwhile).
    if !st.attaching && !st.waiting && st.kept.is_none() {
        drop(st);
        let _ = inner.events.send(event);
    }
}

/// The connection is gone: callers still waiting hear so, and a session shown as running is
/// shown as ended (the service is out of reach; it never reads as running). Unless the app is
/// closing, the loss is counted: the tunnel re-attaches (`reattach`).
fn on_lost(inner: &Inner) {
    inner.pending.lock().clear();
    {
        let mut st = inner.state.lock();
        st.kept = None;
        st.parked = None;
    }
    let running = inner.status.borrow().running;
    if running {
        let warning = Msg::new("service.pipe.lost");
        inner.status.send_replace(TunStatus {
            warning: Some(warning.clone()),
            ..TunStatus::default()
        });
        let _ = inner
            .events
            .send(TunnelEvent::Warning(TunWarning::Other(warning)));
        let _ = inner
            .events
            .send(TunnelEvent::Status(TunStatusKind::Stopped));
    }
    if !inner.shutdown.is_cancelled() {
        inner.losses.send_modify(|n| *n += 1);
    }
}
