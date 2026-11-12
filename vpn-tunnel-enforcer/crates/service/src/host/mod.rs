//! The session host: one runtime and one kill switch for the machine, driven by one
//! controlling client at a time over the pipe. A session belongs to its connection: when the
//! controlling client goes away the tunnel stops (a `strict` kill switch keeps blocking, as its
//! filters are persistent by design).
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_tunnel::api::Runtime;

use crate::pipe::{ClientCheck, Listener};
use crate::users::Users;

mod conn;
mod inputs;
pub mod killswitch;
mod requests;

#[cfg(test)]
mod tests;

pub use inputs::SharedInputs;
pub use killswitch::{KillSwitch, WfpKillSwitch, load_settings};
pub use requests::untrusted_folder;

/// How long a new connection may take to send its `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

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
    controller: Mutex<Option<u64>>,
    next_conn: AtomicU64,
}

impl Host {
    pub fn new(deps: HostDeps) -> Arc<Self> {
        Arc::new(Self {
            deps,
            controller: Mutex::new(None),
            next_conn: AtomicU64::new(1),
        })
    }

    /// Accepts connections until `cancel`; each runs on its own task.
    pub async fn serve(self: Arc<Self>, mut listener: Listener, cancel: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                () = cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok(pipe) => {
                    let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(conn::run(self.clone(), id, pipe, cancel.child_token()));
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

    /// Makes `conn` the controlling client unless another one is.
    fn claim(&self, conn: u64) -> bool {
        let mut slot = self.controller.lock();
        match *slot {
            Some(_) => false,
            None => {
                *slot = Some(conn);
                true
            }
        }
    }

    fn release(&self, conn: u64) {
        let mut slot = self.controller.lock();
        if *slot == Some(conn) {
            *slot = None;
        }
    }
}
