//! Noticing a session whose engine runs but carries nothing (a freeze, a silent block) from what
//! costs no handshake: the engine's own counters and the runtime's upstream watchdog.
use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use super::Counters;

/// How often the counters are read.
pub const SAMPLE: Duration = Duration::from_secs(5);
/// How long the upload must grow while the download stays flat.
pub const WINDOW: Duration = Duration::from_secs(30);
/// The user sent this much in the window: real requests, not a keep-alive.
const MIN_UP: u64 = 4 * 1024;
/// ...and got at most this much back: every request through a working tunnel gets an answer.
const MAX_DOWN: u64 = 1024;

/// What the counters say now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suspicion {
    /// Traffic flows, or nobody uses the network (no reason to spend a handshake).
    None,
    /// The upload grew for a whole window while the download stayed flat.
    Stalled,
    /// The runtime's watchdog says the upstream stopped answering.
    ProxyDown,
}

/// The counter samples of one session within the window (pure; the task feeds it).
#[derive(Debug, Default)]
pub struct Detector {
    samples: VecDeque<(Instant, Counters)>,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets the samples (a new engine run, a false alarm, a confirmation).
    pub fn reset(&mut self) {
        self.samples.clear();
    }

    /// Adds a sample taken at `at` and judges the window ending there.
    pub fn push(&mut self, at: Instant, now: Counters) -> Suspicion {
        // Totals that went back belong to a new engine run: its window starts over.
        if self
            .samples
            .back()
            .is_some_and(|(_, last)| now.up < last.up || now.down < last.down)
        {
            self.reset();
        }
        self.samples.push_back((at, now));
        // Keep one sample at or before the window's start as its base.
        while self.samples.len() > 1 && self.samples[1].0 + WINDOW <= at {
            self.samples.pop_front();
        }
        if now.proxy_down {
            return Suspicion::ProxyDown;
        }
        let Some((since, base)) = self.samples.front() else {
            return Suspicion::None;
        };
        if *since + WINDOW > at {
            return Suspicion::None;
        }
        let sent = now.up.saturating_sub(base.up);
        let received = now.down.saturating_sub(base.down);
        if sent >= MIN_UP && received <= MAX_DOWN {
            Suspicion::Stalled
        } else {
            Suspicion::None
        }
    }
}
