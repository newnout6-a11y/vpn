//! p-live-fix 3a / 3c: a service Windows is still starting is waited for (the SCM says
//! START_PENDING or RUNNING, its pipe is not there yet), and every failed connect says what is
//! true in one line. A private test pipe stands in for the service; the SCM's answer is set by
//! the test (`Inner::test_presence`), so the real service is never reached.
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_core::store::Store;

use super::tests::{NEXT, NoInputs, pipe_name, restarted};
use super::{CallError, Presence, Remote, truthful};
use crate::api_settings::test_support::TempDir;
use crate::svc_core::docs::ProtectionDoc;

fn absent() -> AppError {
    AppError::msg(ErrorKind::Network, Msg::new("service.pipe.unavailable"))
}

fn key(err: &AppError) -> &str {
    err.msg.as_ref().map_or("", |m| m.key.as_ref())
}

/// A remote over a fresh private pipe nobody serves yet, the SCM saying `presence`.
fn remote(presence: Presence) -> (Remote, String, TempDir) {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("remote-presence-{n}")));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
    *r.0.test_presence.lock() = Some(presence);
    (r, pipe, dir)
}

#[test]
fn a_failed_connect_says_what_is_true() {
    let cases = [
        (Presence::Missing, "app.service.missing"),
        (Presence::Starting, "app.service.starting"),
        (Presence::Running, "app.service.starting"),
        (Presence::Stopped, "app.service.stopped"),
        (Presence::Stopping, "app.service.stopped"),
    ];
    for (presence, expected) in cases {
        let err = truthful(absent(), presence);
        assert_eq!((key(&err), err.kind), (expected, ErrorKind::Network));
    }
    let refused = AppError::msg(ErrorKind::Permission, Msg::new("service.pipe.notOurs"));
    let err = truthful(refused, Presence::Running);
    assert_eq!(
        (key(&err), err.kind),
        ("app.service.refused", ErrorKind::Permission)
    );
    // Anything else keeps the pipe client's own sentence.
    let denied = AppError::msg(ErrorKind::Network, Msg::new("service.pipe.denied"));
    assert_eq!(
        key(&truthful(denied, Presence::Running)),
        "service.pipe.denied"
    );
}

/// After a Windows restart: the SCM says the service is starting and its pipe appears a moment
/// later. The call waits for it instead of failing, says «запускается» meanwhile, and links.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_still_starting_is_waited_for() {
    let (r, pipe, dir) = remote(Presence::Starting);
    let path = dir.0.clone();
    let up = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1200)).await;
        restarted(&pipe, &path).await
    });
    let watch = tokio::spawn({
        let r = r.clone();
        async move {
            for _ in 0..200 {
                if r.starting() {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            false
        }
    });
    let reply = r.refresh().await;
    assert!(reply.is_ok(), "linked once the pipe was there: {reply:?}");
    assert!(watch.await.expect("watch"), "«starting» while waiting");
    assert!(!r.starting(), "no longer starting once linked");
    let (_host, _runtime, stop) = up.await.expect("service");
    stop.cancel();
}

/// A stopped or missing service is not waited for: the call fails at once with its line.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_or_missing_service_fails_at_once() {
    for (presence, expected) in [
        (Presence::Stopped, "app.service.stopped"),
        (Presence::Missing, "app.service.missing"),
    ] {
        let (r, _pipe, _dir) = remote(presence);
        let started = std::time::Instant::now();
        let err = r.refresh().await.expect_err("nobody serves the pipe");
        assert!(started.elapsed() < Duration::from_secs(2), "{presence:?}");
        let text = err.to_string();
        let CallError::Pipe(err) = err else {
            panic!("a pipe failure: {text}");
        };
        assert_eq!(key(&err), expected);
    }
}

/// A service that never opens its pipe: the wait is bounded and then says it is still starting.
#[tokio::test(start_paused = true)]
async fn the_wait_for_a_starting_service_is_bounded() {
    let (r, _pipe, _dir) = remote(Presence::Starting);
    let started = tokio::time::Instant::now();
    let err = r.refresh().await.expect_err("never served");
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(30) && waited <= super::START_WAIT,
        "{waited:?}"
    );
    let CallError::Pipe(err) = err else {
        panic!("a pipe failure");
    };
    assert_eq!(key(&err), "app.service.starting");
    assert!(r.starting(), "still starting as far as anyone knows");
}

/// Lab F8 (p-follow3): the service was stopped when the app started (no link). When it runs
/// again the idle app links to it by itself, so its next stop is a counted loss (the views
/// read the SCM at once) instead of going unnoticed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_back_while_idle_is_linked_again() {
    let (r, pipe, dir) = remote(Presence::Stopped);
    tokio::spawn(r.clone().keep_linked());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        r.live_link().await.is_none(),
        "nothing to link while it is stopped"
    );
    let (_host, _runtime, stop) = restarted(&pipe, &dir.0).await;
    *r.0.test_presence.lock() = Some(Presence::Running);
    let mut linked = false;
    for _ in 0..100 {
        if r.live_link().await.is_some() {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(linked, "linked once it ran again");
    // Its next stop: the link drops and the loss is counted. The stopped test host lets go of
    // the pipe at the next request its reader takes.
    let losses = r.losses();
    stop.cancel();
    *r.0.test_presence.lock() = Some(Presence::Stopped);
    let lost = async {
        while !losses.has_changed().unwrap_or(true) {
            let _ = r.refresh().await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), lost)
        .await
        .expect("the stop is a loss");
    r.0.shutdown.cancel();
}
