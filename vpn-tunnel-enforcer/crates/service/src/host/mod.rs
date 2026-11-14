//! The session host: one runtime and one kill switch for the machine, driven by one
//! controlling client at a time over the pipe. A session outlives a connection that drops without
//! a `Stop` (owner question 23: the app window crashed): it keeps running, and the same Windows
//! user's app takes it over at its next start; another user's app ends it first (its secrets and
//! its last exit are its user's). Quit and Disconnect send a `Stop`.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::{Semaphore, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::KillSwitchLevel;
use vpnte_probes::leak::SelfTestResult;
use vpnte_tunnel::api::{CaptureKind, Runtime, StopOptions, TunnelEvent};

use crate::pipe::{ClientCheck, Listener};
use crate::proto::{ErrorCode, Reply, StatusWire, UpdateAsk, WireError};
use crate::update::{OwnSession, UpdateDesk};
use crate::users::Users;

mod conn;
mod inputs;
pub mod killswitch;
mod memory;
mod requests;
mod resume;

#[cfg(test)]
mod tests;

pub use inputs::SharedInputs;
pub use killswitch::{KillSwitch, WfpKillSwitch, load_settings};
pub use requests::untrusted_folder;

/// How long a new connection may take to send its `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections that have not said `Hello` yet: each holds at most one small first frame
/// ([`crate::proto::frame::FIRST_FRAME_MAX`]) for at most [`HELLO_TIMEOUT`] (review service-a4).
pub const MAX_UNIDENTIFIED: usize = 16;

/// Everything the host drives.
#[derive(Clone)]
pub struct HostDeps {
    pub runtime: Arc<dyn Runtime>,
    pub kill_switch: Arc<dyn KillSwitch>,
    pub inputs: Arc<SharedInputs>,
    pub users: Arc<Users>,
    pub check: ClientCheck,
    /// Called once, after the reply, when the last user left: the service removes itself.
    pub on_last_user: Arc<dyn Fn() + Send + Sync>,
    pub service_version: String,
    /// Set when the service must not run engines (its folder is user-writable): every tunnel
    /// start is refused with this message; status, kill switch and cleanup still work.
    pub refuse_tunnel: Option<Msg>,
}

/// The host (shared by every connection).
pub struct Host {
    deps: HostDeps,
    /// The controlling connection and its user.
    controller: Mutex<Option<(u64, String)>>,
    next_conn: AtomicU64,
    /// State changes (kill-switch settings, routing inputs, cleanup) run one at a time in arrival
    /// order, each to its end even when its request is dropped, and the stop after the client
    /// left waits for them (reviews service-a1 / a10).
    state: Arc<tokio::sync::Mutex<()>>,
    unidentified: Arc<Semaphore>,
    /// The user whose start the runtime's last exit and fault belong to: nobody else reads them.
    /// Shared with the updater, which asks whose session it is right before it restarts.
    session_user: Arc<Mutex<Option<String>>>,
    /// The upstream of the last start: `(server id, local proxy)`, for a take-over.
    upstream: Mutex<Option<(Option<String>, Option<SocketAddr>)>>,
    /// The runtime's current native generation (its last `StartBegan`), for a take-over.
    generation: Arc<AtomicU64>,
    /// Where the last started session is kept for a resume ([`Host::keep_sessions_in`]).
    memory: OnceLock<PathBuf>,
    /// The service's leak self-tests ([`Host::report_self_tests`]).
    self_tests: OnceLock<watch::Receiver<Option<SelfTestResult>>>,
    /// The service's own updater ([`Host::serve_updates`]).
    updates: OnceLock<Arc<dyn UpdateDesk>>,
}

impl Host {
    pub fn new(deps: HostDeps) -> Arc<Self> {
        Arc::new(Self {
            deps,
            controller: Mutex::new(None),
            next_conn: AtomicU64::new(1),
            state: Arc::default(),
            unidentified: Arc::new(Semaphore::new(MAX_UNIDENTIFIED)),
            session_user: Arc::default(),
            upstream: Mutex::new(None),
            generation: Arc::default(),
            memory: OnceLock::new(),
            self_tests: OnceLock::new(),
            updates: OnceLock::new(),
        })
    }

    /// `Request::Update` is answered by `desk` (set once, at start-up; without it the request is
    /// a bad one, as for an older service).
    pub fn serve_updates(&self, desk: Arc<dyn UpdateDesk>) {
        let _ = self.updates.set(desk);
    }

    /// `user`'s `Update`. The updater may restart the service only while nothing runs or is
    /// held, or while the session is the caller's own: another Windows user's session never ends
    /// for an update. Whose session it is, is asked again at every step (svcupd-a1 / a2).
    async fn update(&self, user: &str, ask: UpdateAsk) -> Result<Reply, WireError> {
        let Some(desk) = self.updates.get().cloned() else {
            let error = WireError::new(
                ErrorCode::BadRequest,
                vpnte_base::ErrorKind::Validation,
                "service.pipe.badRequest",
            );
            return Err(error);
        };
        let (owner, user) = (self.session_user.clone(), user.to_owned());
        let own: OwnSession = Arc::new(move || owner.lock().as_deref() == Some(user.as_str()));
        Ok(Reply::Update(desk.answer(ask, own).await))
    }

    /// The status carries the latest of these self-test results (set once, at start-up).
    pub fn report_self_tests(&self, results: watch::Receiver<Option<SelfTestResult>>) {
        let _ = self.self_tests.set(results);
    }

    /// The latest self-test for `user`'s running TUN session; nobody else's (it names the
    /// machine's adapters and the session's exit address).
    fn self_test_for(&self, user: &str, tunnel: &StatusWire) -> Option<SelfTestResult> {
        let own = self.session_user.lock().as_deref() == Some(user);
        let tun = tunnel.running && tunnel.capture == Some(CaptureKind::Tun);
        if !(own && tun) {
            return None;
        }
        // Only the listed apps use the VPN: the run's default-route read went around it.
        let listed_only = self.deps.inputs.get().only_listed.is_some();
        let result = self.self_tests.get()?.borrow().clone()?;
        Some(result.with_scope(listed_only))
    }

    /// Accepts connections until `cancel`; each runs on its own task.
    pub async fn serve(self: Arc<Self>, mut listener: Listener, cancel: CancellationToken) {
        // Everything this process asks over HTTPS (DoH, exit proofs) may run under the kill
        // switch's DNS block, where Windows' online certificate check stalls (lab F-3).
        vpnte_base::http::verify_offline();
        tokio::spawn(track_generation(
            self.deps.runtime.subscribe(),
            self.generation.clone(),
            cancel.clone(),
        ));
        loop {
            let accepted = tokio::select! {
                () = cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok(pipe) => {
                    // Full: closed at once (a local user flooding the pipe gets nothing held).
                    let Ok(permit) = self.unidentified.clone().try_acquire_owned() else {
                        tracing::debug!("too many connections without a hello; closed");
                        continue;
                    };
                    let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
                    let conn = conn::run(self.clone(), id, pipe, permit, cancel.child_token());
                    tokio::spawn(conn);
                }
                Err(err) => {
                    // Creating the next instance can fail under memory pressure; retrying at
                    // once would spin. Only an error path sleeps.
                    tracing::warn!(error = %err, "pipe accept failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Makes `conn` (of `user`) the controlling client unless another one is: `Err(true)` when
    /// that one is the same Windows user (his app's previous connection, still closing).
    fn claim(&self, conn: u64, user: &str) -> Result<(), bool> {
        let mut slot = self.controller.lock();
        match &*slot {
            Some((_, holder)) => Err(holder == user),
            None => {
                *slot = Some((conn, user.to_owned()));
                Ok(())
            }
        }
    }

    /// A new controller: a session kept for another Windows user ends first ("Always" in force
    /// keeps its block); the same user's app takes his over.
    async fn admit(&self, user: &str) {
        let other = self.session_user.lock().clone();
        if other.is_none_or(|u| u == user) {
            return;
        }
        let keep_block = self.deps.kill_switch.level_in_force() == KillSwitchLevel::Strict;
        let receipt = self
            .deps
            .runtime
            .stop(StopOptions {
                preserve_protection: keep_block,
                preserve_last: false,
            })
            .await;
        tracing::info!(
            ok = receipt.ok,
            keep_block,
            "another user's kept session ended"
        );
        *self.session_user.lock() = None;
        *self.upstream.lock() = None;
        self.forget_session(None);
    }

    fn release(&self, conn: u64) {
        let mut slot = self.controller.lock();
        if slot.as_ref().is_some_and(|(id, _)| *id == conn) {
            *slot = None;
        }
    }
}

/// Follows the runtime's native generation while the service runs. Waits on the event stream
/// only: no timer, nothing to do while idle.
async fn track_generation(
    mut events: tokio::sync::broadcast::Receiver<TunnelEvent>,
    generation: Arc<AtomicU64>,
    cancel: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            () = cancel.cancelled() => return,
            event = events.recv() => event,
        };
        match event {
            Ok(TunnelEvent::StartBegan { generation: g }) => {
                generation.fetch_max(g, Ordering::Relaxed);
            }
            Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}
