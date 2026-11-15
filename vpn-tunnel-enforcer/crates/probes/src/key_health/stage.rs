//! The stages of one key's check as they happen (p-check-live: the owner read a silent minute of
//! the list check as a hung process). The probe itself tells where it is: queued, waiting for
//! its server name's handshake budget (how long), the engine starting, the engine ready (after
//! how long) with the handshake and the test request running, and what came back.
use std::time::Duration;

use tokio::sync::mpsc;
use vpnte_base::types::Engine;

use super::HealthReason;

/// One step of a key's check in a list or group check, sent as it happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStage {
    /// In the run: a free probe or its server name's turn comes first.
    Queued,
    /// Its server name takes no new connection for `wait` (the handshake budget's own wait: at
    /// most three new connections a minute to one name, so that the network does not freeze it).
    Waiting { wait: Duration },
    /// The probe engine starts.
    Starting { engine: Engine },
    /// The engine served its local port after `engine_ms`: the handshake and the test request run.
    Requesting { engine: Engine, engine_ms: u32 },
    /// The test request ended after `asked_ms`; the answer follows once the engine has stopped
    /// (and, for a key that failed, the server's reach was probed), so the page stops counting
    /// the request here (p-fix-checklive b4).
    Asked {
        engine: Engine,
        engine_ms: u32,
        asked_ms: u32,
    },
    /// The check ended with this answer.
    Done(KeyAnswer),
    /// Not checked: its name's budget deferred it or its probe could not start (and so are the
    /// keys behind it on that name: they would knock again).
    Unchecked,
}

/// What came back through the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAnswer {
    /// An HTTP answer through the key: its status and the time from the request's start.
    Http { status: u16, ms: u32 },
    /// Data came, then stopped after `bytes` without a reset (inside the freeze band: a freeze).
    Stalled { bytes: u64 },
    /// Nothing came back within `ms`.
    Silent { ms: u32 },
    /// The key failed for this reason (handshake, refused, rejected, configuration) or was not
    /// tried (`EngineSetting`, `NoOutbound`).
    Failed(HealthReason),
}

/// Where one probe tells its stages: the chain that runs it drains them in order before the
/// key's result. A single check outside a list has none.
#[derive(Debug, Clone, Default)]
pub(crate) struct Stages(Option<mpsc::UnboundedSender<KeyStage>>);

impl Stages {
    /// A sink and the receiver its chain drains.
    pub(crate) fn channel() -> (Self, mpsc::UnboundedReceiver<KeyStage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self(Some(tx)), rx)
    }

    pub(crate) fn send(&self, stage: KeyStage) {
        if let Some(tx) = &self.0 {
            // The run may be over (stopped): nobody listens any more.
            let _ = tx.send(stage);
        }
    }
}

#[cfg(test)]
mod tests;
