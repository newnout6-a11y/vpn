//! Happ's fallback rule: the fallback URL is tried when the URL fails (any failure, an answer of
//! 300-599 included) or has not answered after 9 s; then both run and the first success wins.
use std::future::Future;
use std::time::Duration;

use super::FetchError;
use super::fetch::rank;

/// Which URL answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Source {
    Main,
    Fallback,
}

/// Runs `main`; `fallback` (not polled before) starts when `main` fails or after `after`. A
/// cancel ends everything; when both fail, the stronger evidence wins.
pub(super) async fn with_fallback<T>(
    main: impl Future<Output = Result<T, FetchError>>,
    fallback: Option<impl Future<Output = Result<T, FetchError>>>,
    after: Duration,
) -> Result<(T, Source), FetchError> {
    let Some(fallback) = fallback else {
        return main.await.map(|got| (got, Source::Main));
    };
    tokio::pin!(main);
    let early = tokio::select! {
        out = &mut main => Some(out),
        () = tokio::time::sleep(after) => None,
    };
    let mut main_failed = match early {
        Some(Ok(got)) => return Ok((got, Source::Main)),
        Some(Err(FetchError::Failed(outcome))) => Some(FetchError::Failed(outcome)),
        Some(Err(other)) => return Err(other),
        None => None,
    };
    tokio::pin!(fallback);
    let mut fallback_failed = None;
    loop {
        tokio::select! {
            out = &mut main, if main_failed.is_none() => match out {
                Ok(got) => return Ok((got, Source::Main)),
                Err(FetchError::Failed(o)) => main_failed = Some(FetchError::Failed(o)),
                Err(other) => return Err(other),
            },
            out = &mut fallback, if fallback_failed.is_none() => match out {
                Ok(got) => return Ok((got, Source::Fallback)),
                Err(FetchError::Failed(o)) => fallback_failed = Some(FetchError::Failed(o)),
                Err(other) => return Err(other),
            },
        }
        if let (Some(a), Some(b)) = (main_failed, fallback_failed) {
            return Err(stronger(a, b));
        }
    }
}

/// The failure with the stronger evidence (servers §6 order); `a` on a tie.
pub(super) fn stronger(a: FetchError, b: FetchError) -> FetchError {
    match (a, b) {
        (FetchError::Failed(x), FetchError::Failed(y)) if rank(y) < rank(x) => b,
        _ => a,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use tokio::time::{Instant, sleep};

    use super::*;
    use crate::model::{FetchOutcome, NetFail};

    const AFTER: Duration = super::super::FALLBACK_AFTER;

    /// A fake fetch that answers `out` after `delay` and notes when it was first polled.
    async fn fake(
        delay: Duration,
        out: Result<&'static str, FetchError>,
        started: Arc<AtomicU64>,
        t0: Instant,
    ) -> Result<&'static str, FetchError> {
        started.store(t0.elapsed().as_millis() as u64 + 1, Ordering::SeqCst);
        sleep(delay).await;
        out
    }

    fn failed(outcome: FetchOutcome) -> Result<&'static str, FetchError> {
        Err(FetchError::Failed(outcome))
    }

    async fn run(
        main: (u64, Result<&'static str, FetchError>),
        fallback: (u64, Result<&'static str, FetchError>),
    ) -> (Result<(&'static str, Source), FetchError>, Option<u64>) {
        let t0 = Instant::now();
        let (m, f) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
        let main = fake(Duration::from_secs(main.0), main.1, m, t0);
        let fb = fake(Duration::from_secs(fallback.0), fallback.1, f.clone(), t0);
        let out = with_fallback(main, Some(fb), AFTER).await;
        let started = f.load(Ordering::SeqCst);
        (out, (started > 0).then(|| (started - 1) / 1000))
    }

    /// ru-2026 item 3 (Happ: > 9 s): an answer at 8 s keeps the fallback untouched.
    #[tokio::test(start_paused = true)]
    async fn main_within_nine_seconds_wins() {
        let (out, started) = run((8, Ok("main")), (0, Ok("fallback"))).await;
        assert_eq!(out.unwrap(), ("main", Source::Main));
        assert_eq!(started, None);
    }

    /// Main silent past 9 s: the fallback starts at 9 s and answers first.
    #[tokio::test(start_paused = true)]
    async fn slow_main_hands_over_at_nine_seconds() {
        let (out, started) = run((30, Ok("main")), (1, Ok("fallback"))).await;
        assert_eq!(out.unwrap(), ("fallback", Source::Fallback));
        assert_eq!(started, Some(9));
    }

    /// After 9 s both run: a main that answers before the fallback still wins.
    #[tokio::test(start_paused = true)]
    async fn main_may_still_win_the_race() {
        let (out, started) = run((10, Ok("main")), (5, Ok("fallback"))).await;
        assert_eq!(out.unwrap(), ("main", Source::Main));
        assert_eq!(started, Some(9));
    }

    /// A failure (an HTTP 503 here) hands over at once; both failing keeps the stronger one.
    #[tokio::test(start_paused = true)]
    async fn failures_hand_over_at_once() {
        let (out, started) = run((1, failed(FetchOutcome::Http(503))), (1, Ok("fallback"))).await;
        assert_eq!(out.unwrap(), ("fallback", Source::Fallback));
        assert_eq!(started, Some(1));
        let net = FetchOutcome::Network(NetFail::Connect);
        let (out, _) = run((1, failed(FetchOutcome::Http(503))), (1, failed(net))).await;
        assert_eq!(
            out.unwrap_err(),
            FetchError::Failed(FetchOutcome::Http(503))
        );
        let (out, _) = run((20, failed(net)), (2, failed(FetchOutcome::EmptyList))).await;
        assert_eq!(
            out.unwrap_err(),
            FetchError::Failed(FetchOutcome::EmptyList)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_and_no_fallback() {
        let (out, _) = run((1, Err(FetchError::Cancelled)), (0, Ok("fallback"))).await;
        assert_eq!(out.unwrap_err(), FetchError::Cancelled);
        let main = async { Ok::<_, FetchError>("main") };
        let none: Option<std::future::Ready<Result<&str, FetchError>>> = None;
        let out = with_fallback(main, none, AFTER).await;
        assert_eq!(out.unwrap(), ("main", Source::Main));
    }
}
