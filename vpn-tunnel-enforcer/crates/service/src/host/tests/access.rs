//! Who may do what before and without the controller slot, and how much a client may hold
//! (reviews service-a4 / a7 / b2 / b7).
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

use super::*;
use crate::host::MAX_UNIDENTIFIED;
use crate::host::conn::MAX_PENDING;

/// Review service-a7: an uninstaller's `ForgetMe` is answered while another connection holds
/// the slot.
#[tokio::test]
async fn forget_me_needs_no_controller_slot() {
    let h = harness();
    let mut app = connect(&h).await;
    app.hello("2.0.0").await.expect("hello");
    let mut uninstaller = connect(&h).await;
    assert_eq!(
        uninstaller.call(Request::ForgetMe).await.expect("forget"),
        Reply::Done { removing: true }
    );
    wait_for("removal", || h.removed.load(Ordering::SeqCst) == 1).await;
}

/// Review service-b7: the same Windows user's second connection is told that his own previous
/// connection still holds the service, not that another user does.
#[tokio::test]
async fn the_same_user_is_not_told_another_user_is_connected() {
    let h = harness();
    let mut first = connect(&h).await;
    first.hello("2.0.0").await.expect("first hello");
    let mut second = connect(&h).await;
    match second.hello("2.0.0").await.expect_err("busy") {
        CallError::Service(e) => {
            assert_eq!(e.code, ErrorCode::Busy);
            assert_eq!(e.msg.key, "service.pipe.busySelf");
        }
        CallError::Pipe(e) => panic!("pipe error: {e:?}"),
    }
}

/// Review service-a4: a first frame larger than a greeting is refused before anything is read
/// or held for it.
#[tokio::test]
async fn a_big_first_frame_is_refused_at_once() {
    let h = harness();
    let mut pipe = ClientOptions::new().open(&h.name).expect("open");
    let prefix = u32::try_from(1usize << 20).expect("len").to_le_bytes();
    pipe.write_all(&prefix).await.expect("prefix");
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), pipe.read(&mut byte)).await;
    assert!(
        matches!(read, Ok(Ok(0) | Err(_))),
        "closed, not waiting for 1 MiB: {read:?}"
    );
}

/// Review service-a4: connections that never say hello are bounded; the next one is closed at
/// once, and the slots come back when they go.
#[tokio::test]
async fn connections_without_a_hello_are_bounded() {
    let h = harness();
    let mut silent = Vec::new();
    for _ in 0..MAX_UNIDENTIFIED {
        silent.push(open(&h).await);
    }
    let mut extra = open(&h).await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut byte)).await;
    assert!(matches!(read, Ok(Ok(0) | Err(_))), "closed: {read:?}");
    drop(silent);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("a slot is free again");
}

/// Opens the pipe, waiting while the server creates its next instance.
async fn open(h: &Harness) -> tokio::net::windows::named_pipe::NamedPipeClient {
    for _ in 0..200 {
        match ClientOptions::new().open(&h.name) {
            Ok(pipe) => return pipe,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("the pipe never had a free instance");
}

/// Review service-b2: what the runtime reports about a session (an engine's stderr, a server's
/// fault) goes only to the user who started it; a controller that started nothing sees none.
#[tokio::test]
async fn the_last_fault_goes_only_to_the_user_who_started_the_session() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    let status = |reply| match reply {
        Reply::Status(s) => s.recent_fault,
        other => panic!("{other:?}"),
    };
    let before = c.call(Request::Status).await.expect("status");
    assert_eq!(status(before), None, "nobody's session yet");
    c.call(local_start(KillSwitchLevel::Off))
        .await
        .expect("start");
    let after = c.call(Request::Status).await.expect("status");
    assert_eq!(status(after), Some(OutboundFault::TlsHandshakeFailed));
}

/// Review service-a4: the controller has at most `MAX_PENDING` requests in flight; its further
/// frames wait unread until one finishes, then every request is answered.
#[tokio::test]
async fn requests_in_flight_are_bounded() {
    let h = harness();
    let mut c = Raw::open(&h).await;
    h.kill.gate.send_replace(false);
    let total = MAX_PENDING as u64 + 8;
    for id in 0..total {
        c.send(id + 2, Request::Status).await;
    }
    let bound = MAX_PENDING as u32;
    wait_for("the bound is reached", || {
        h.kill.asking.load(Ordering::SeqCst) == bound
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        h.kill.asking.load(Ordering::SeqCst),
        bound,
        "no more at once"
    );
    h.kill.gate.send_replace(true);
    let mut answered = 0;
    while answered < total {
        if let ServerFrame::Reply { .. } = c.next().await {
            answered += 1;
        }
    }
    assert_eq!(h.kill.asking.load(Ordering::SeqCst), total as u32);
}
