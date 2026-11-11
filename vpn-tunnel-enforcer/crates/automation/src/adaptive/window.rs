//! The stability window (AV:11-29). A fresh tunnel often "works" for its first seconds and then
//! stalls, one sample is not evidence, and flapping probes must not cause oscillation: wait 20 s,
//! then 3 probes 2.5 s apart, at least 2 must succeed.
use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

/// Probes per window.
pub(crate) const PROBES: usize = 3;
/// Successful probes a window needs.
pub(crate) const NEEDED: usize = 2;

/// Window timing (tests shrink it; there is no paused clock in this crate's test setup).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timing {
    pub settle: Duration,
    pub gap: Duration,
}

impl Timing {
    pub(crate) const REAL: Timing = Timing {
        settle: Duration::from_secs(20),
        gap: Duration::from_millis(2500),
    };
}

/// Waits `settle`, then runs [`PROBES`] probes `gap` apart (no pause after the last). `None` once
/// `cancel` fires at any boundary — a superseded window never yields samples, so stale results
/// cannot drive a fallback; otherwise the latencies of the probes that succeeded.
pub(crate) async fn stability_window<F, Fut>(
    timing: Timing,
    cancel: &CancellationToken,
    mut probe: F,
) -> Option<Vec<Duration>>
where
    F: FnMut(CancellationToken) -> Fut,
    Fut: Future<Output = Option<Duration>>,
{
    cancel
        .run_until_cancelled(tokio::time::sleep(timing.settle))
        .await?;
    let mut samples = Vec::with_capacity(PROBES);
    for i in 0..PROBES {
        if i > 0 {
            cancel
                .run_until_cancelled(tokio::time::sleep(timing.gap))
                .await?;
        }
        let sample = cancel
            .run_until_cancelled(probe(cancel.child_token()))
            .await?;
        if cancel.is_cancelled() {
            return None;
        }
        samples.extend(sample);
    }
    Some(samples)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    const FAST: Timing = Timing {
        settle: Duration::from_millis(20),
        gap: Duration::from_millis(5),
    };

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// AT-10-003: probes `[10, null, 20]` → samples `[10, 20]` after exactly 3 probes.
    #[tokio::test]
    async fn keeps_the_successful_samples() {
        let calls = Arc::new(AtomicUsize::new(0));
        let script = [Some(ms(10)), None, Some(ms(20))];
        let cancel = CancellationToken::new();
        let c = calls.clone();
        let out = stability_window(FAST, &cancel, move |_| {
            let i = c.fetch_add(1, Ordering::SeqCst);
            async move { script[i] }
        })
        .await;
        assert_eq!(out, Some(vec![ms(10), ms(20)]));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// AT-10-006: an abort during the 20 s settle yields `None` without a single probe.
    #[tokio::test]
    async fn abort_during_settle_runs_no_probe() {
        let calls = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let slow = Timing {
            settle: Duration::from_secs(20),
            gap: ms(5),
        };
        let stopper = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ms(10)).await;
            stopper.cancel();
        });
        let c = calls.clone();
        let started = std::time::Instant::now();
        let out = stability_window(slow, &cancel, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            async { Some(ms(1)) }
        })
        .await;
        assert_eq!(out, None);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// AT-10-006: a cancel inside probe k (1..=3) yields `None` after exactly k probes, also when
    /// the superseded probe still reports a (late) success or failure.
    #[tokio::test]
    async fn cancel_inside_a_probe_discards_the_window() {
        for k in 1..=3usize {
            for late in [Some(ms(7)), None] {
                let calls = Arc::new(AtomicUsize::new(0));
                let cancel = CancellationToken::new();
                let (c, token) = (calls.clone(), cancel.clone());
                let out = stability_window(FAST, &cancel, move |_| {
                    let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                    let token = token.clone();
                    async move {
                        if n == k {
                            token.cancel();
                            return late;
                        }
                        Some(ms(1))
                    }
                })
                .await;
                assert_eq!(out, None, "k={k}");
                assert_eq!(calls.load(Ordering::SeqCst), k, "k={k}");
            }
        }
    }
}
