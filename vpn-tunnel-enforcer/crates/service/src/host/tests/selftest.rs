//! The service's leak self-test in the status (p-svc-recheck): its session's user reads it in
//! protocol 2, pushed and answered; a version-1 client and other users never get the field.
use vpnte_base::types::UnixMs;
use vpnte_probes::leak::SelfTestResult;
use vpnte_tunnel::api::CaptureKind;

use super::*;

fn sample(at: UnixMs) -> SelfTestResult {
    SelfTestResult {
        at,
        kill_switch: KillSwitchLevel::Standard,
        default_v4: Some("198.51.100.7".parse().expect("ip")),
        probes: Vec::new(),
        inspection_complete: true,
        services_disagree: None,
        cancelled: false,
    }
}

/// A started TUN session of the connected client, and a self-test channel the host reports.
async fn tun_session(h: &Harness, c: &mut Raw) -> watch::Sender<Option<SelfTestResult>> {
    let results = watch::channel(None).0;
    h.host.report_self_tests(results.subscribe());
    c.send(2, local_start(KillSwitchLevel::Standard)).await;
    assert!(matches!(c.answer(2).await, ServerFrame::Reply { .. }));
    h.runtime
        .status
        .send_modify(|s| s.capture = Some(CaptureKind::Tun));
    results
}

/// The next pushed status that carries a self-test, within 5 s.
async fn pushed_self_test(c: &mut Raw) -> SelfTestResult {
    loop {
        if let ServerFrame::Event { event } = c.next().await
            && let Event::Status(status) = *event
            && let Some(result) = status.self_test
        {
            return result;
        }
    }
}

async fn status_reply(c: &mut Raw, id: u64) -> crate::proto::StatusReply {
    c.send(id, Request::Status).await;
    match c.answer(id).await {
        ServerFrame::Reply { reply, .. } => match *reply {
            Reply::Status(status) => *status,
            other => panic!("not a status: {other:?}"),
        },
        other => panic!("refused: {other:?}"),
    }
}

/// RU audit item 11: a new result is pushed at once with the status and is in the answer to
/// `Status`; the app shows it as it shows its own runs.
#[tokio::test]
async fn the_self_test_reaches_its_sessions_user() {
    let h = harness();
    let mut c = Raw::open(&h).await;
    let results = tun_session(&h, &mut c).await;
    results.send_replace(Some(sample(7)));
    assert_eq!(pushed_self_test(&mut c).await.at, 7);
    let reply = status_reply(&mut c, 3).await;
    assert_eq!(reply.tunnel.self_test.map(|r| r.at), Some(7));
    // Not a TUN session any more (proxy capture): nothing to show.
    h.runtime
        .status
        .send_modify(|s| s.capture = Some(CaptureKind::Proxy));
    assert_eq!(status_reply(&mut c, 4).await.tunnel.self_test, None);
}

/// Protocol compatibility one version back: a version-1 app refuses unknown fields, so it never
/// gets `selfTest`, neither pushed nor answered.
#[tokio::test]
async fn a_version_1_client_never_gets_the_self_test() {
    let h = harness();
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&h.name)
        .expect("open");
    let mut c = Raw(pipe);
    let hello = Hello {
        protocol: 1,
        app_version: "2.0.0".into(),
    };
    c.send(1, Request::Hello(hello)).await;
    match c.answer(1).await {
        ServerFrame::Reply { reply, .. } => {
            assert!(matches!(*reply, Reply::Welcome { protocol: 1, .. }));
        }
        other => panic!("refused: {other:?}"),
    }
    let results = tun_session(&h, &mut c).await;
    results.send_replace(Some(sample(9)));
    c.send(3, Request::Status).await;
    // Every frame up to the answer, as bytes: what a version-1 decoder would read.
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), frame::read_frame(&mut c.0));
        let body = read.await.expect("a frame in time").expect("frame");
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("selfTest"), "{text}");
        if let ServerFrame::Reply { id: 3, reply } = frame::decode(&body).expect("decode") {
            assert!(matches!(*reply, Reply::Status(s) if s.tunnel.running));
            break;
        }
    }
}
