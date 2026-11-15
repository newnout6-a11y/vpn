//! Review wire5-a1: a helper service two protocol versions back (the owner's 2.0.0 spoke 3)
//! refuses this app's Hello. The app shows it as too old to speak to and says its update helps,
//! never "update the app" (the newer side) and never a current service. p-fix-review8: a service
//! two versions ahead names its protocol in the refusal; then this app is the old side and says
//! «Обновите приложение», never that the service is outdated.
use vpnte_base::{ErrorKind, Msg};
use vpnte_service::proto::{
    ClientFrame, ErrorCode, PROTOCOL, ServerFrame, WireError, frame, negotiate,
};

use super::*;

/// A service speaking `protocol` on `pipe`: it answers every Hello as its `negotiate` does, so
/// one two versions apart is refused with `Version`; `names`: the refusal names its protocol (a
/// service from p-fix-review8 on), else it names none (protocol 3 to 5).
fn refusing_service(pipe: &str, protocol: u32, names: bool) {
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
            let error = if names {
                WireError::version(protocol)
            } else {
                WireError {
                    code: ErrorCode::Version,
                    kind: ErrorKind::Validation,
                    msg: Msg::new("service.pipe.version"),
                    warnings: Vec::new(),
                }
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
    refusing_service(&pipe, 3, false);
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

/// The refused link of `r` and what it says.
async fn refused(r: &Remote) -> String {
    let err = r
        .start(tun_request(), CancellationToken::new())
        .await
        .expect_err("a refused link starts nothing");
    err.error.user_msg().key.to_string()
}

/// p-fix-review8, both directions over a private pipe: a service whose refusal names a lower
/// protocol is outdated (its update helps); one naming a higher protocol is the newer side: the
/// app says «Обновите приложение» (the service's own message) and offers no service update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_an_older_service_is_outdated() {
    for (theirs, outdated) in [(PROTOCOL - 2, true), (PROTOCOL + 2, false)] {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let (pipe, dir) = (pipe_name(n), TempDir::new(&format!("remote-side-{n}")));
        refusing_service(&pipe, theirs, true);
        let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
        let r = Remote::on_pipe(&pipe, Arc::new(NoInputs), protection);
        let key = refused(&r).await;
        assert_eq!(r.outdated(), outdated, "service protocol {theirs}");
        let says = if outdated {
            "app.service.outdated"
        } else {
            "service.pipe.version"
        };
        assert_eq!(key, says, "service protocol {theirs}");
    }
    vpnte_base::i18n::init(&crate::svc_core::locale_layers());
    let update = Msg::new("service.pipe.version").render(vpnte_base::i18n::Lang::Ru);
    assert!(update.ends_with("Обновите приложение."), "{update}");
}
