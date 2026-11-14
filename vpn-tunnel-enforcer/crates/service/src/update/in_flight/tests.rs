use tokio::sync::Notify;

use super::*;
use crate::proto::KillSwitchStateWire;

/// A kill switch whose `apply` waits until the test lets it go.
#[derive(Default)]
struct Slow {
    reached: Notify,
    release: Notify,
}

#[async_trait]
impl KillSwitch for Arc<Slow> {
    async fn apply(&self, _settings: ProtectionSettings) -> AppResult<()> {
        self.reached.notify_one();
        self.release.notified().await;
        Ok(())
    }

    fn level(&self) -> KillSwitchLevel {
        KillSwitchLevel::Off
    }

    fn level_in_force(&self) -> KillSwitchLevel {
        KillSwitchLevel::Off
    }

    async fn status(&self) -> ProtectionWire {
        ProtectionWire {
            level: KillSwitchLevel::Off,
            kill_switch: KillSwitchStateWire::Off,
            leak_protection_active: false,
            dynamic_filters: None,
            persistent_filters: None,
            bfe_running: None,
            last_verified: None,
            last_error: None,
            skipped_exceptions: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn notices(&self) -> broadcast::Receiver<Notice> {
        broadcast::channel(1).1
    }

    async fn cleanup(&self) -> AppResult<RemoveReport> {
        Ok(RemoveReport::default())
    }

    async fn remove_all(&self) -> AppResult<()> {
        Ok(())
    }
}

/// svcfix-a4: the first step of a start the host accepted (its kill-switch apply) counts as in
/// flight for as long as it runs, and for [`SETTLE`] after it ended (the runtime's start follows
/// on another task); then all is quiet.
#[tokio::test(start_paused = true)]
async fn a_kill_switch_apply_counts_until_it_settled() {
    let slow = Arc::new(Slow::default());
    let in_flight = InFlight::default();
    let counted = Arc::new(Counted::new(slow.clone(), in_flight.clone()));
    assert_eq!(in_flight.quiet(), Quiet::Yes);
    let changes = in_flight.subscribe();
    let apply = tokio::spawn({
        let counted = counted.clone();
        async move { counted.apply(ProtectionSettings::default()).await }
    });
    slow.reached.notified().await;
    assert_eq!(in_flight.quiet(), Quiet::Busy);
    assert!(changes.has_changed().expect("open"), "the restart wakes");
    slow.release.notify_one();
    apply.await.expect("task").expect("applied");
    assert_eq!(in_flight.quiet(), Quiet::Settling(SETTLE));
    tokio::time::sleep(SETTLE / 2).await;
    assert_eq!(in_flight.quiet(), Quiet::Settling(SETTLE / 2));
    tokio::time::sleep(SETTLE / 2).await;
    assert_eq!(in_flight.quiet(), Quiet::Yes);
    // Reads pass straight through and count nothing.
    assert_eq!(counted.level(), KillSwitchLevel::Off);
    let _ = counted.status().await;
    assert_eq!(in_flight.quiet(), Quiet::Yes);
}

/// Two calls at once: busy until the last one ended.
#[test]
fn the_count_holds_until_the_last_call_ends() {
    let in_flight = InFlight::default();
    let first = in_flight.enter();
    let second = in_flight.enter();
    drop(first);
    assert_eq!(in_flight.quiet(), Quiet::Busy);
    drop(second);
    assert!(matches!(in_flight.quiet(), Quiet::Settling(_)));
}
