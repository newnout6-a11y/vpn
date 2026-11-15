//! Lab live-11 L11-1: a fresh TUN passes packets only some time after sing-box's started line
//! (0.6-1.0 s in the sandbox, the bare sing-box too). Every SYN or DNS question sent before is
//! resent by Windows only after its 1 s retransmit timer, so «Подключено» on the started line
//! was early, and the first page came 1.6-2.0 s after it. The start now waits until a probe
//! through the capture is answered.
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult};

/// One probe through a capture: resolves `true` once the capture answered it, `false` when it
/// ended without an answer (a local refusal); stays pending while nothing processes it.
pub type PassProbe = Pin<Box<dyn Future<Output = bool> + Send>>;

/// A fresh probe this often: a lost one is resent by Windows only after 1 s.
pub const PROBE_EVERY: Duration = Duration::from_millis(20);
/// The longest wait. Past it the start goes on as before: the probe alone never fails a start.
pub const PROBE_BOUND: Duration = Duration::from_secs(3);

/// What the wait saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Passing {
    /// The capture has no probe: it passes packets once ready (the proxy capture).
    NoProbe,
    /// A probe was answered after this long.
    Answered(Duration),
    /// Nothing answered within [`PROBE_BOUND`].
    Silent,
}

/// Starts a `probe` (a capture's [`super::Capture::probe`]) every [`PROBE_EVERY`] until one is
/// answered or [`PROBE_BOUND`] passes. Probes still pending are dropped with the wait.
pub async fn wait_passing(
    probe: impl Fn() -> Option<PassProbe>,
    cancel: &CancellationToken,
) -> AppResult<Passing> {
    let Some(first) = probe() else {
        return Ok(Passing::NoProbe);
    };
    let start = Instant::now();
    let mut probes = FuturesUnordered::new();
    probes.push(first);
    let mut tick = tokio::time::interval_at(start + PROBE_EVERY, PROBE_EVERY);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let bound = tokio::time::sleep_until(start + PROBE_BOUND);
    tokio::pin!(bound);
    loop {
        tokio::select! {
            () = cancel.cancelled() => return Err(AppError::cancelled()),
            () = &mut bound => return Ok(Passing::Silent),
            Some(answered) = probes.next(), if !probes.is_empty() => {
                if answered {
                    return Ok(Passing::Answered(start.elapsed()));
                }
            }
            _ = tick.tick() => probes.extend(probe()),
        }
    }
}

/// Windows resends an unanswered SYN after this long (its initial retransmit timer).
#[cfg(test)]
const RESEND: Duration = Duration::from_secs(1);

/// A fresh TUN as the lab measured it (test model): a probe sent at `t` is answered at once when
/// the TUN passes packets by then, at `t` + 1 s (the resent SYN) when it passes by that time, else
/// never. `None`: the TUN never passes.
#[cfg(test)]
pub(crate) fn model_probe(passes_at: Option<Instant>) -> PassProbe {
    let sent = Instant::now();
    Box::pin(async move {
        let Some(at) = passes_at else {
            return std::future::pending().await;
        };
        let answer = if sent >= at { sent } else { sent + RESEND };
        if answer < at {
            return std::future::pending().await;
        }
        tokio::time::sleep_until(answer).await;
        true
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    fn ms(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    /// Lab live-11: the TUN passes 700 ms after it is ready. The probes sent before are lost
    /// until their resend; the first one sent after it is answered at once, on the 20 ms grid.
    #[tokio::test(start_paused = true)]
    async fn the_first_probe_after_the_window_is_answered_at_once() {
        let at = Instant::now() + Duration::from_millis(700);
        let sent = AtomicU32::new(0);
        let probe = || {
            sent.fetch_add(1, Ordering::SeqCst);
            Some(model_probe(Some(at)))
        };
        let seen = wait_passing(probe, &CancellationToken::new()).await;
        assert_eq!(
            seen.map(|p| matches!(p, Passing::Answered(d) if ms(d) == 700))
                .ok(),
            Some(true)
        );
        assert_eq!(
            sent.load(Ordering::SeqCst),
            36,
            "one probe at 0 ms and every 20 ms after"
        );
    }

    /// A TUN that never passes holds the start for the bound only; a probe refused locally
    /// does not end the wait.
    #[tokio::test(start_paused = true)]
    async fn a_silent_capture_ends_the_wait_at_the_bound() {
        let start = Instant::now();
        let refused = || Some(Box::pin(async { false }) as PassProbe);
        let seen = wait_passing(refused, &CancellationToken::new()).await;
        assert_eq!(seen.ok(), Some(Passing::Silent));
        assert_eq!(start.elapsed(), PROBE_BOUND);
    }

    /// No probe: no wait. A cancelled start stops waiting at once.
    #[tokio::test(start_paused = true)]
    async fn no_probe_means_no_wait_and_a_cancel_ends_it() {
        let start = Instant::now();
        let none = wait_passing(|| None, &CancellationToken::new()).await;
        assert_eq!(none.ok(), Some(Passing::NoProbe));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let never = || Some(model_probe(None));
        let err = wait_passing(never, &cancel).await.expect_err("cancelled");
        assert_eq!(err.kind, vpnte_base::ErrorKind::Cancelled);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
