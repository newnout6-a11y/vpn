//! One handshake budget per server endpoint, shared by every check that makes an engine dial the
//! server (key health, the live check's engine stage, transfer checks). Field reports (Habr
//! 1044396 / 1047442, Nov 2026): more than ~3 TLS handshakes to one server name within a minute,
//! less than ~350–400 ms apart, freeze that server for the client for ~120 s, and retry storms
//! extend the freeze. So: at most [`MAX_PER_WINDOW`] new handshakes per [`WINDOW`] per endpoint,
//! [`MIN_GAP`] apart; a caller waits for its slot or is told "deferred", it never bursts. Plain
//! TCP connects without TLS (pings, the reach probe) are not counted.
use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_profiles::model::{Host, Profile};

/// Length of the sliding window.
pub const WINDOW: Duration = Duration::from_secs(60);
/// New handshakes allowed per endpoint within any [`WINDOW`].
pub const MAX_PER_WINDOW: usize = 3;
/// Least spacing between two handshakes to one endpoint.
pub const MIN_GAP: Duration = Duration::from_millis(400);
/// Quiet time after a freeze verdict: the freeze lasts ~120 s and redialling inside it extends
/// it, so the next handshake waits a little longer than that.
pub const FREEZE_BACKOFF: Duration = Duration::from_secs(130);

/// What the budget counts by: the TLS server name when the profile sends one (the freeze is keyed
/// on the name), else `host:port`. Lower case; not a secret.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint(String);

impl Endpoint {
    /// The endpoint a profile's engine dials; `None` for a loopback server (a local proxy: no
    /// network in between that could freeze it).
    pub fn of(p: &Profile) -> Option<Self> {
        let host = match &p.server {
            Host::Domain(d) => Some(d.as_str()),
            Host::Ip(_) => None,
        };
        if crate::ping::is_loopback_host(&p.server.to_string()) {
            return None;
        }
        let name = p.tls.as_ref().filter(|t| !t.disable_sni).and_then(|t| {
            t.server_name
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .or(host)
        });
        Some(match name {
            Some(name) => Endpoint::server_name(name),
            None => Endpoint::host_port(&p.server.to_string(), p.port),
        })
    }

    /// A TLS server name.
    pub fn server_name(name: &str) -> Self {
        Endpoint(format!("sni:{}", name.trim().to_ascii_lowercase()))
    }

    /// A plain `host:port` (no TLS, or no name sent).
    pub fn host_port(host: &str, port: u16) -> Self {
        Endpoint(format!("{}:{port}", host.trim().to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why no slot was granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// The next free slot starts after the caller's wait limit.
    #[error("handshake budget exhausted, next slot in {retry_after:?}")]
    Deferred { retry_after: Duration },
    #[error("cancelled while waiting for a handshake slot")]
    Cancelled,
}

impl From<BudgetError> for AppError {
    fn from(err: BudgetError) -> Self {
        match err {
            BudgetError::Deferred { retry_after } => AppError::msg(
                ErrorKind::Conflict,
                Msg::new("probes.discipline.deferred").arg("seconds", retry_after.as_secs().max(1)),
            ),
            BudgetError::Cancelled => AppError::cancelled(),
        }
    }
}

/// Reservations of one endpoint that can still share a window with a new one, oldest first.
/// Pruned by time, not by count: a cancelled wait gives its slot back, and the reservations
/// before it must then still count.
#[derive(Debug, Default)]
struct Slots {
    at: VecDeque<Instant>,
    hold_until: Option<Instant>,
}

impl Slots {
    /// The earliest instant at or after `now` at which one more handshake keeps every window
    /// within the limits.
    fn next_free(&self, now: Instant) -> Instant {
        let mut t = now;
        if let Some(hold) = self.hold_until {
            t = t.max(hold);
        }
        if let Some(&last) = self.at.back() {
            t = t.max(last + MIN_GAP);
        }
        if self.at.len() >= MAX_PER_WINDOW {
            // Reservations are taken in time order, so this is the oldest one that would still
            // share a window with `t`.
            let oldest = self.at[self.at.len() - MAX_PER_WINDOW];
            t = t.max(oldest + WINDOW);
        }
        t
    }

    /// Drops reservations that no window starting at `now` or later contains.
    fn prune(&mut self, now: Instant) {
        while self.at.front().is_some_and(|&s| s + WINDOW <= now) {
            self.at.pop_front();
        }
    }
}

/// The per-endpoint budget. One process-wide instance: [`budget`].
#[derive(Debug, Default)]
pub struct HandshakeBudget {
    slots: Mutex<HashMap<Endpoint, Slots>>,
}

/// The budget every check shares.
pub fn budget() -> &'static HandshakeBudget {
    static BUDGET: LazyLock<HandshakeBudget> = LazyLock::new(HandshakeBudget::default);
    &BUDGET
}

impl HandshakeBudget {
    /// Takes one handshake slot for `endpoint`: returns at once when one is free, sleeps until
    /// the reserved slot when it starts within `max_wait`, else `Deferred` (nothing reserved).
    /// A cancelled wait gives its slot back.
    pub async fn acquire(
        &self,
        endpoint: &Endpoint,
        max_wait: Duration,
        cancel: &CancellationToken,
    ) -> Result<(), BudgetError> {
        let at = self.reserve_at(endpoint, Instant::now(), max_wait)?;
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                self.release(endpoint, at);
                Err(BudgetError::Cancelled)
            }
            () = tokio::time::sleep_until(at) => Ok(()),
        }
    }

    /// Reserves the next free slot as seen at `now` (the clock is the caller's, so tests drive
    /// time by hand).
    pub(crate) fn reserve_at(
        &self,
        endpoint: &Endpoint,
        now: Instant,
        max_wait: Duration,
    ) -> Result<Instant, BudgetError> {
        let mut map = self.slots.lock();
        // Endpoints whose window and hold are over carry no state any more.
        map.retain(|_, s| {
            s.hold_until.is_some_and(|h| h > now) || s.at.back().is_some_and(|&l| l + WINDOW > now)
        });
        let slots = map.entry(endpoint.clone()).or_default();
        slots.prune(now);
        let at = slots.next_free(now);
        let wait = at.saturating_duration_since(now);
        if wait > max_wait {
            return Err(BudgetError::Deferred { retry_after: wait });
        }
        slots.at.push_back(at);
        Ok(at)
    }

    /// Keeps `endpoint` quiet for `quiet` from now (after a freeze verdict: redialling inside a
    /// freeze extends it). A longer hold already set stays.
    pub fn hold(&self, endpoint: &Endpoint, quiet: Duration) {
        self.hold_at(endpoint, Instant::now(), quiet);
    }

    pub(crate) fn hold_at(&self, endpoint: &Endpoint, now: Instant, quiet: Duration) {
        let mut map = self.slots.lock();
        let slots = map.entry(endpoint.clone()).or_default();
        let until = now + quiet;
        slots.hold_until = Some(slots.hold_until.map_or(until, |h| h.max(until)));
    }

    /// How long a new handshake to `endpoint` would wait right now (zero = free; nothing is
    /// reserved). The list-wide check waits this out before it takes one of its probes.
    pub fn wait_for(&self, endpoint: &Endpoint) -> Duration {
        let now = Instant::now();
        let map = self.slots.lock();
        map.get(endpoint).map_or(Duration::ZERO, |s| {
            s.next_free(now).saturating_duration_since(now)
        })
    }

    fn release(&self, endpoint: &Endpoint, at: Instant) {
        if let Some(slots) = self.slots.lock().get_mut(endpoint) {
            slots.at.retain(|&s| s != at);
        }
    }
}
