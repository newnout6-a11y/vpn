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
//! (`reattach`, p-follow).
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    Event, KeptSession, Reply, Request, StatusReply, StatusWire, TunnelEventWire, WireError,
};
use vpnte_service::scm::manage;
use vpnte_tunnel::api::{ExitInfo, TunError, TunStatus, TunStatusKind, TunWarning, TunnelEvent};
use vpnte_tunnel::runtime::InputsSource;

use crate::svc_core::docs::ProtectionDoc;

#[cfg(test)]
mod elevated;
mod gens;
pub(super) mod guard;
mod runtime;
mod split;
mod start;
#[cfg(test)]
mod tests;

pub(super) use split::Split;

/// How long a connect waits for a busy pipe.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
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
}

fn lost() -> CallError {
    CallError::Pipe(AppError::msg(
        ErrorKind::Network,
        Msg::new("service.pipe.lost"),
    ))
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

    /// The service is installed: Tunnel mode and the kill switch go through it.
    pub(crate) fn installed(&self) -> bool {
        self.0.installed.load(Ordering::Relaxed)
    }

    /// Reads the SCM again (start, and after an install from Settings); the new answer.
    pub(crate) fn recheck(&self) -> bool {
        let installed = crate::boot::service::installed();
        self.0.installed.store(installed, Ordering::Relaxed);
        installed
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

    /// The current connection, or a new one (the pipe's server checked first).
    async fn link(&self) -> Result<Requests, CallError> {
        let mut slot = self.0.link.lock().await;
        if let Some(link) = slot.as_ref().filter(|l| !l.gone.is_cancelled()) {
            return Ok(link.requests.clone());
        }
        let (pipe, check) = match &self.0.test_pipe {
            Some(name) => (name.as_str(), ServerCheck::Any),
            None => match manage::installed_binary() {
                Ok(Some(exe)) => (vpnte_service::sddl::PIPE_NAME, ServerCheck::Image(exe)),
                _ => {
                    return Err(CallError::Pipe(AppError::msg(
                        ErrorKind::Network,
                        Msg::new("service.pipe.unavailable"),
                    )));
                }
            },
        };
        let mut client = Client::connect(pipe, &check, CONNECT_TIMEOUT)
            .await
            .map_err(CallError::Pipe)?;
        client.hello(env!("CARGO_PKG_VERSION")).await?;
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
    /// A crashed window's last connection may still be closing (`busySelf`) or the service still
    /// starting with Windows: a few tries, a few seconds apart, then the next connect parks it.
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
        tokio::select! {
            () = self.0.shutdown.cancelled() => false,
            () = tokio::time::sleep(ATTACH_PAUSE) => true,
        }
    }

    /// The parked session's status (local proxy kind, name) for the take-over's target.
    pub(super) fn parked(&self) -> Option<TunStatus> {
        self.0.state.lock().parked.clone()
    }

    /// Forgets a parked session (and ends a wait for one): what comes next replaces or stops it.
    fn unpark(&self) {
        let mut st = self.0.state.lock();
        st.kept = None;
        st.parked = None;
        st.waiting = false;
    }
}

/// The last exit and fault of a status reply (the service sends them to the session's user only).
fn absorb(st: &mut State, reply: &StatusReply) {
    if let Some(exit) = &reply.last_exit {
        st.last_exit = Some(exit.clone().into());
    }
    st.recent_fault = reply.recent_fault;
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
