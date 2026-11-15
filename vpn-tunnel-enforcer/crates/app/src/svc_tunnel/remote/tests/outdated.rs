//! Review wire5-a1: a helper service two protocol versions back (the owner's 2.0.0 spoke 3)
//! refuses this app's Hello. The app shows it as too old to speak to and says its update helps,
//! never "update the app" (the newer side) and never a current service.
use vpnte_base::{ErrorKind, Msg};
use vpnte_service::proto::{
    ClientFrame, ErrorCode, PROTOCOL, ServerFrame, WireError, frame, negotiate,
};

use super::*;

/// A service speaking `protocol` on `pipe`: it answers every Hello as its `negotiate` does, so
/// one two versions apart is refused with `Version`.
fn old_service(pipe: &str, protocol: u32) {
    let mut listener = Listener::bind(&pipe_config(pipe)).expect("private pipe");
    tokio::spawn(async move {
        while let Ok(mut conn) = listener.accept().await {
            let Ok(body) = frame::read_frame(&mut conn).await else {
                continue;
            };
            let Ok(ClientFrame { id, request }) = frame::decode::<ClientFrame>(&body) else {
                continue;
            };
            let Request::Hello(hello) = request else {
                continue;
            };
            assert_eq!(negotiate(hello.protocol, protocol), None, "refused");
            let error = WireError {
                code: ErrorCode::Version,
                kind: ErrorKind::Validation,
                msg: Msg::new("service.pipe.version"),
                warnings: Vec::new(),
            };
            let _ = frame::write_frame(&mut conn, &ServerFrame::Failed { id, error }).await;
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_two_versions_back_is_outdated_not_current() {
    assert_eq!(PROTOCOL, 5);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("remote-old-{n}")));
    old_service(&pipe, 3);
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
    let err = r
        .start(tun_request(), CancellationToken::new())
        .await
        .expect_err("a refused link starts nothing");
    let msg = err.error.user_msg();
    assert_eq!(msg.key.as_ref(), "app.service.outdated", "{err:?}");
    assert!(r.outdated());
    assert_eq!(r.protocol(), None, "no link, no protocol");
    // «Обновить службу-помощник» approved: the app's own service replaced it.
    r.reinstalled();
    assert!(!r.outdated(), "no update offered over the new service");
}
