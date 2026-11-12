//! The reaction task: the only writer of the network-session memory, fed by the app's reports
//! and the coordinator's lifecycle events. One reaction at a time; a network change or shutdown
//! abandons the one in flight (dropping a coordinator future cancels it natively).
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;

use super::decide::{self, Allowed, Decision};
use super::memory::Attempt;
use super::{ReactionHost, Report, ServerFacts, Verdicts};
use crate::coordinator::{Coordinator, LifecycleEvent};

mod act;

/// A switch candidate waits this long for a handshake slot of its endpoint; a busier one is
/// skipped (the next candidate usually has a free budget).
const SWITCH_SLOT_WAIT: Duration = Duration::from_secs(10);
/// The fingerprint retry dials the endpoint the check has just used: one full budget window
/// plus margin always yields a slot, unless a freeze hold keeps the endpoint quiet.
const RETRY_SLOT_WAIT: Duration = Duration::from_secs(65);
/// Reports queued while a reaction runs (checks are budgeted: a handful per minute).
const INBOX: usize = 32;

/// Reactions to check verdicts: [`Reactions::run`] is the task, [`Reactions::report`] its inbox.
pub struct Reactions<C: Coordinator, H: ReactionHost> {
    coord: Arc<C>,
    host: Arc<H>,
    settings: Arc<Store<Settings>>,
    verdicts: Arc<Verdicts>,
    tx: mpsc::Sender<Report>,
    rx: Mutex<Option<mpsc::Receiver<Report>>>,
}

impl<C: Coordinator, H: ReactionHost> Reactions<C, H> {
    /// Nothing runs until [`Reactions::run`]; reports queue up meanwhile.
    pub fn new(coord: Arc<C>, host: Arc<H>, settings: Arc<Store<Settings>>) -> Self {
        let (tx, rx) = mpsc::channel(INBOX);
        Self {
            coord,
            host,
            settings,
            verdicts: Arc::new(Verdicts::new()),
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    /// The network session's memory, for rotation and the sibling fallback of adaptive bypass.
    pub fn verdicts(&self) -> Arc<Verdicts> {
        self.verdicts.clone()
    }

    /// Hands over a finished check; never blocks (a full inbox drops the report with a log line).
    pub fn report(&self, report: Report) {
        if self.tx.try_send(report).is_err() {
            tracing::warn!("reactions: inbox full or closed, check report dropped");
        }
    }

    /// The task: learns from every report and reacts to those about the running server, until
    /// `cancel` fires. A second runner returns at once.
    pub async fn run(&self, cancel: CancellationToken) {
        let Some(mut inbox) = self.rx.lock().take() else {
            tracing::warn!("reactions: a second runner was refused");
            return;
        };
        let mut events = self.coord.events();
        loop {
            let report = tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                event = events.recv() => match self.on_event(event) {
                    Flow::Closed => return,
                    Flow::Reset | Flow::Other => continue,
                },
                report = inbox.recv() => match report {
                    Some(report) => report,
                    None => return,
                },
            };
            let reaction = self.handle(report, &cancel);
            tokio::pin!(reaction);
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return,
                    event = events.recv() => match self.on_event(event) {
                        Flow::Closed => return,
                        Flow::Reset => {
                            tracing::info!("reactions: network changed, reaction abandoned");
                            break;
                        }
                        Flow::Other => {}
                    },
                    () = &mut reaction => break,
                }
            }
        }
    }

    /// A network change (or a lagged stream that may hide one) starts a new network session.
    pub(super) fn on_event(&self, event: Result<LifecycleEvent, RecvError>) -> Flow {
        match event {
            Ok(LifecycleEvent::NetworkChanged) | Err(RecvError::Lagged(_)) => {
                self.verdicts.reset();
                Flow::Reset
            }
            Ok(_) => Flow::Other,
            Err(RecvError::Closed) => Flow::Closed,
        }
    }
}

/// What a lifecycle event means for the task.
pub(super) enum Flow {
    Reset,
    Other,
    Closed,
}
