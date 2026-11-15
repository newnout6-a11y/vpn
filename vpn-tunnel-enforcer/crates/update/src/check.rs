//! When the feed is checked (research §4.4): 2-5 minutes after start (the connection is up by
//! then), then every 24 h plus a random offset of up to an hour (owner decision D-75: not more
//! than once a day), plus «Проверить сейчас». A failed check retries after 1 h, then 3 h, then
//! the next day.
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

const MINUTE: u64 = 60;
const HOUR: u64 = 3600;
const DAY: Duration = Duration::from_secs(24 * HOUR);
/// Retries after a failure; past the last one the daily rhythm resumes.
const RETRIES: [Duration; 2] = [Duration::from_secs(HOUR), Duration::from_secs(3 * HOUR)];

/// What started a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// The schedule (skipped by the caller when automatic checks are off).
    Timer,
    /// «Проверить сейчас».
    Manual,
}

/// The delays between checks.
#[derive(Debug, Default)]
pub struct Schedule {
    failures: usize,
}

impl Schedule {
    /// The first check after start: 2-5 minutes.
    pub fn first() -> Duration {
        Duration::from_secs(fastrand::u64(2 * MINUTE..=5 * MINUTE))
    }

    /// The wait after a check that succeeded (`ok`) or failed.
    pub fn next(&mut self, ok: bool) -> Duration {
        if ok {
            self.failures = 0;
        } else if let Some(&retry) = RETRIES.get(self.failures) {
            self.failures += 1;
            return retry;
        } else {
            self.failures = 0;
        }
        DAY + Duration::from_secs(fastrand::u64(0..=HOUR))
    }
}

/// Runs `check` on the schedule until `cancel`; a `now` notification runs it at once (and the
/// schedule restarts from that check). `check` returns whether it succeeded.
pub async fn run<F, Fut>(mut check: F, now: Arc<Notify>, cancel: CancellationToken)
where
    F: FnMut(Trigger) -> Fut,
    Fut: Future<Output = bool>,
{
    let mut schedule = Schedule::default();
    let mut wait = Schedule::first();
    loop {
        let trigger = tokio::select! {
            () = tokio::time::sleep(wait) => Trigger::Timer,
            () = now.notified() => Trigger::Manual,
            () = cancel.cancelled() => return,
        };
        let ok = tokio::select! {
            ok = check(trigger) => ok,
            () = cancel.cancelled() => return,
        };
        wait = schedule.next(ok);
    }
}

#[cfg(test)]
mod tests;
