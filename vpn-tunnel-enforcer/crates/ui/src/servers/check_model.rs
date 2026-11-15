//! What a running key check tells the page about each key, as it happens (p-check-live): the
//! owner read a silent minute of «Проверить все» as a hung process. Display data only.
use vpnte_base::types::{Engine, UnixMs};

use super::model::KeyHealthReason;

/// The row a check's stage or result is about, and a digest of the key it probed
/// ([`ServerView::key_tag`](super::model::ServerView::key_tag)): a refresh may give the row
/// another key while the check runs, and then that stage or result is not the row's (b2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CheckKey {
    pub id: String,
    pub tag: u64,
}

/// One step of a key's check, in numbers.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckStage {
    /// In the run: a free probe or its server name's turn comes first.
    Queued,
    /// Its next connection to the server is at `until` (wall clock): the app's own pacing, at
    /// most three new connections a minute to one server, so that the network does not block it.
    Waiting { until: UnixMs },
    /// The probe engine starts.
    Starting { engine: Engine },
    /// The engine was ready after `engine_ms`; the handshake and the test request run since `since`.
    Requesting {
        engine: Engine,
        engine_ms: u32,
        since: UnixMs,
    },
    /// The request ended after `asked_ms`; its answer follows once the engine has stopped.
    Asked {
        engine: Engine,
        engine_ms: u32,
        asked_ms: u32,
    },
    /// What came back.
    Done(CheckAnswer),
    /// The run ended without this key's result (stopped, its time ran out, its server's budget
    /// deferred it, or the probe could not start).
    NotChecked,
}

impl CheckStage {
    /// The key's check is over (with or without a result).
    pub fn is_final(&self) -> bool {
        matches!(self, CheckStage::Done(_) | CheckStage::NotChecked)
    }
}

/// What came back through the key.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckAnswer {
    /// An HTTP answer through the key: its status and the time to it.
    Http { status: u16, ms: u32 },
    /// Data came, then stopped after `bytes`.
    Stalled { bytes: u64 },
    /// Nothing came back within `ms`.
    Silent { ms: u32 },
    /// The key failed for this reason (or was not tried: the engine setting, an unreadable key).
    Failed(KeyHealthReason),
    /// The connected session runs over this key: its own traffic proves it (no probe spent).
    Session,
}

impl CheckAnswer {
    /// A failure of the key (shown red); an HTTP answer, the session's proof and the engine
    /// setting are not.
    pub fn is_failure(&self) -> bool {
        match self {
            CheckAnswer::Http { .. } | CheckAnswer::Session => false,
            CheckAnswer::Failed(reason) => *reason != KeyHealthReason::EngineSetting,
            CheckAnswer::Stalled { .. } | CheckAnswer::Silent { .. } => true,
        }
    }
}
