//! p-svc-update: `Update` is answered as a first frame without the controller slot (the app asks
//! on a connection of its own while its tunnel holds the slot) and after `Hello` alike; a host
//! without an updater answers `badRequest`, as an older service does. A `Take` may restart the
//! service at once only while no session runs or the session is the caller's own.
use crate::proto::{ServiceUpdateWire, UpdateAsk, UpdatePhase};
use crate::update::UpdateDesk;

use super::*;

/// Records what it was asked and whether it could restart.
#[derive(Default)]
struct Desk {
    asks: Mutex<Vec<(UpdateAsk, bool)>>,
}

#[async_trait]
impl UpdateDesk for Desk {
    async fn answer(&self, ask: UpdateAsk, may_restart: bool) -> ServiceUpdateWire {
        self.asks.lock().push((ask, may_restart));
        ServiceUpdateWire {
            version: "2.0.0".into(),
            phase: UpdatePhase::Idle,
            target: None,
            checked_at: None,
        }
    }
}

fn take() -> Request {
    Request::Update(UpdateAsk::Take {
        version: "2.0.1".into(),
    })
}

#[tokio::test]
async fn update_needs_no_slot_and_never_ends_another_users_session() {
    let h = harness();
    let mut first = connect(&h).await;
    let err = first
        .call(Request::Update(UpdateAsk::State))
        .await
        .expect_err("no desk");
    assert_eq!(code(err), ErrorCode::BadRequest);
    let desk = Arc::new(Desk::default());
    h.host.serve_updates(desk.clone());
    // Another connection holds the slot: the first-frame ask is answered anyway.
    let mut controller = connect(&h).await;
    controller.hello("2.0.0").await.expect("hello");
    let mut asker = connect(&h).await;
    let reply = asker
        .call(Request::Update(UpdateAsk::State))
        .await
        .expect("answered");
    assert!(
        matches!(reply, Reply::Update(ref s) if s.version == "2.0.0"),
        "{reply:?}"
    );
    // Idle: a take may restart.
    connect(&h).await.call(take()).await.expect("take");
    // The controller's own session runs: its take may restart, after `Hello` too.
    controller
        .call(local_start(KillSwitchLevel::Off))
        .await
        .expect("started");
    h.runtime.status.send_modify(|s| s.running = true);
    controller.call(take()).await.expect("own take");
    connect(&h)
        .await
        .call(take())
        .await
        .expect("same user, first frame");
    // Another Windows user's session: never restarted for an update.
    *h.host.session_user.lock() = Some("S-1-5-21-0-0-0-1001".into());
    connect(&h).await.call(take()).await.expect("take");
    let restarts: Vec<bool> = desk
        .asks
        .lock()
        .iter()
        .skip(1)
        .map(|(_, may)| *may)
        .collect();
    assert_eq!(restarts, vec![true, true, true, false]);
    assert_eq!(desk.asks.lock()[0], (UpdateAsk::State, true));
}
