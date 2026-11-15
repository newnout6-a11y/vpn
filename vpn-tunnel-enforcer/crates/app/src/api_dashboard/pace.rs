//! Cadence of the live feeds (speed, traffic, connection lists, probe results): one feed reaches
//! the page at most twice a second. Every pushed view is a full snapshot in a `watch` (the latest
//! value wins), so a skipped intermediate state loses nothing from a list; the page just diffs
//! and paints less (dioxus-desktop re-renders and sends an edit batch to WebView2 per push).
use std::time::Duration;

use tokio::time::Instant;

/// Shortest gap between two pushes of one live feed.
pub(crate) const LIVE_GAP: Duration = Duration::from_millis(500);

/// Spaces the pushes of one feed: a change after a quiet spell goes out at once, the rest of a
/// burst waits for the gap and goes out as one push of the state at that moment.
#[derive(Debug)]
pub(crate) struct Pace {
    gap: Duration,
    last: Option<Instant>,
}

impl Pace {
    /// A pace with [`LIVE_GAP`].
    pub(crate) fn live() -> Self {
        Self {
            gap: LIVE_GAP,
            last: None,
        }
    }

    /// Waits until the next push may go out and books it: call it right before projecting, so
    /// the push carries everything that changed during the wait.
    pub(crate) async fn ready(&mut self) {
        if let Some(last) = self.last {
            tokio::time::sleep_until(last + self.gap).await;
        }
        self.last = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_first_push_is_free_and_the_next_waits_for_the_gap() {
        let start = Instant::now();
        let mut pace = Pace::live();
        pace.ready().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        pace.ready().await;
        assert_eq!(start.elapsed(), LIVE_GAP);
        // a quiet spell longer than the gap: the next push goes out at once
        tokio::time::sleep(Duration::from_secs(3)).await;
        let quiet = Instant::now();
        pace.ready().await;
        assert_eq!(quiet.elapsed(), Duration::ZERO);
    }
}
