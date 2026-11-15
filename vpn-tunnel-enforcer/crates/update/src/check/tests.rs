use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::time::Instant;

use super::*;

/// The retry ladder: 1 h, 3 h, then a day (+ up to an hour); a success resets it.
#[test]
fn failures_retry_after_one_then_three_hours() {
    let mut s = Schedule::default();
    assert_eq!(s.next(false), Duration::from_secs(HOUR));
    assert_eq!(s.next(false), Duration::from_secs(3 * HOUR));
    let day = s.next(false);
    assert!(
        day >= DAY && day <= DAY + Duration::from_secs(HOUR),
        "{day:?}"
    );
    assert_eq!(s.next(false), Duration::from_secs(HOUR));
    let ok = s.next(true);
    assert!(ok >= DAY && ok <= DAY + Duration::from_secs(HOUR));
    assert_eq!(s.next(false), Duration::from_secs(HOUR));
    for _ in 0..50 {
        let first = Schedule::first();
        assert!(first >= Duration::from_secs(120) && first <= Duration::from_secs(300));
    }
}

/// On a paused clock: the first check 2-5 min after start, the next a day later; «Проверить
/// сейчас» runs at once; a failure retries after an hour; cancel stops the loop.
#[tokio::test(start_paused = true)]
async fn the_checker_follows_the_schedule() {
    let start = Instant::now();
    let runs = Arc::new(parking_lot::Mutex::new(Vec::<(Duration, Trigger)>::new()));
    let fail_next = Arc::new(AtomicUsize::new(0));
    let (now, cancel) = (Arc::new(Notify::new()), CancellationToken::new());
    let task = tokio::spawn({
        let (runs, fail_next, now, cancel) =
            (runs.clone(), fail_next.clone(), now.clone(), cancel.clone());
        run(
            move |trigger| {
                runs.lock().push((start.elapsed(), trigger));
                let ok = fail_next.swap(0, Ordering::SeqCst) == 0;
                async move { ok }
            },
            now,
            cancel,
        )
    });
    tokio::time::sleep(Duration::from_secs(301)).await;
    let first = runs.lock()[0];
    assert!(
        first.0 >= Duration::from_secs(120) && first.0 <= Duration::from_secs(300),
        "{first:?}"
    );
    assert_eq!(first.1, Trigger::Timer);

    fail_next.store(1, Ordering::SeqCst);
    now.notify_one();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(runs.lock().len(), 2);
    assert_eq!(runs.lock()[1].1, Trigger::Manual);
    let manual_at = runs.lock()[1].0;

    tokio::time::sleep(Duration::from_secs(HOUR)).await;
    assert_eq!(runs.lock().len(), 3, "a failure retries after an hour");
    assert_eq!(runs.lock()[2].0 - manual_at, Duration::from_secs(HOUR));

    tokio::time::sleep(DAY + Duration::from_secs(HOUR + 1)).await;
    assert_eq!(runs.lock().len(), 4, "then once a day");
    cancel.cancel();
    task.await.unwrap();
}
