//! ks-d (research killswitch §5.3, §5.4): the last started session is kept for a resume (the
//! service's own crash with a held drop, "Always" at the service's start) and dropped when it is
//! no one's any more.
use super::*;
use crate::host::memory::{self, Remembered};

fn kept(h: &Harness) -> Option<Remembered> {
    memory::load(&h.dir.join("session.json"))
}

fn start_of(request: Request) -> TunnelStart {
    match request {
        Request::Start(start) => *start,
        other => panic!("not a start: {other:?}"),
    }
}

/// A start is kept with its user; a stop keeps it ("Always" connects it at the next start); the
/// last user's leave drops it.
#[tokio::test]
async fn a_started_session_is_kept_until_its_user_leaves() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    assert!(kept(&h).is_none());
    c.call(local_start(KillSwitchLevel::Standard))
        .await
        .expect("start");
    let session = kept(&h).expect("kept");
    assert!(session.user.starts_with("S-1-"), "{}", session.user);
    assert_eq!(
        session.start,
        start_of(local_start(KillSwitchLevel::Standard))
    );
    c.call(Request::Stop(StopTunnel::default()))
        .await
        .expect("stop");
    assert!(kept(&h).is_some(), "a stop keeps it");
    c.call(Request::ForgetMe).await.expect("forget");
    assert!(kept(&h).is_none(), "the last user's leave drops it");
}

/// A restarted service starts the kept session again for its user: the same upstream, the
/// user's take-over key in place, and the kept routing inputs.
#[tokio::test]
async fn a_restarted_service_resumes_the_kept_session_for_its_user() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    c.call(local_start(KillSwitchLevel::Standard))
        .await
        .expect("start");
    let user = kept(&h).expect("kept").user;

    let runtime = FakeRuntime::new();
    let restarted = Host::new(HostDeps {
        runtime: runtime.clone(),
        kill_switch: h.kill.clone(),
        inputs: Arc::new(SharedInputs::new(None)),
        users: Arc::new(Users::open(&h.dir.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    assert!(
        !restarted.resume(CancellationToken::new()).await,
        "nothing kept here yet"
    );
    restarted.keep_sessions_in(h.dir.join("session.json"));
    assert!(restarted.resume(CancellationToken::new()).await);
    let starts = runtime.starts.lock().clone();
    assert!(
        matches!(&starts[..], [StartRequest { mode: vpnte_tunnel::api::Mode::LocalProxy { addr, .. }, .. }] if addr == "127.0.0.1:10808"),
        "{starts:?}"
    );
    assert_eq!(
        restarted.session_user.lock().as_deref(),
        Some(user.as_str())
    );
    let proxy = "127.0.0.1:10808".parse().expect("addr");
    assert_eq!(*restarted.upstream.lock(), Some((None, Some(proxy))));
}

/// Nothing starts when the folder is not trusted, and another user's app ends and forgets a
/// kept session of someone else.
#[tokio::test]
async fn refused_or_foreign_sessions_are_not_resumed() {
    let h = harness();
    let path = h.dir.join("session.json");
    let session = Remembered {
        user: "S-1-5-21-1-2-3-1001".into(),
        start: start_of(local_start(KillSwitchLevel::Standard)),
    };
    memory::save(&path, &session);
    let refused = Host::new(HostDeps {
        runtime: FakeRuntime::new(),
        kill_switch: h.kill.clone(),
        inputs: Arc::new(SharedInputs::new(None)),
        users: Arc::new(Users::open(&h.dir.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: Some(untrusted_folder()),
    });
    refused.keep_sessions_in(path.clone());
    assert!(!refused.resume(CancellationToken::new()).await);

    *h.host.session_user.lock() = Some(session.user.clone());
    h.host.admit("S-1-5-21-1-2-3-1002").await;
    assert!(kept(&h).is_none(), "another user's app forgets it");
    assert_eq!(h.runtime.stops.lock().len(), 1);
}

/// fixfollow-b1: an adaptive restart onto a sibling moves the session: the take-over key and
/// the remembered start follow it (server and mode), so a resume brings back what runs now and
/// the app's take-over names that server. Another user's restart changes nothing.
#[tokio::test]
async fn an_adaptive_restart_onto_a_sibling_is_remembered() {
    let h = harness();
    let mut c = connect(&h).await;
    c.hello("2.0.0").await.expect("hello");
    c.call(local_start(KillSwitchLevel::Standard))
        .await
        .expect("start");
    let user = kept(&h).expect("kept").user;
    let link = "trojan://fake-pass@sibling.example.com:443?sni=sibling.example.com#sibling";
    let restart = crate::proto::AdaptiveRestart {
        mode: vpnte_base::types::AdaptiveMode::TlsCompatibility,
        reason: "adaptive bypass".into(),
        server: Some(crate::proto::ServerUpstream {
            id: "sibling".into(),
            profile: vpnte_profiles::uri::parse_uri(link).expect("link"),
            device: None,
            engine: vpnte_base::types::EnginePref::Auto,
        }),
    };
    let client = |user: &str| crate::pipe::ClientInfo {
        pid: 1,
        session: 1,
        user: user.into(),
        image: None,
    };
    h.host
        .follow_adaptive(&client("S-1-5-21-0-0-0-1001"), &restart);
    assert!(matches!(
        kept(&h).expect("kept").start.upstream,
        Upstream::LocalProxy { .. }
    ));

    h.host.follow_adaptive(&client(&user), &restart);
    let start = kept(&h).expect("kept").start;
    assert!(matches!(&start.upstream, Upstream::Server(s) if s.id == "sibling"));
    assert_eq!(start.adaptive, restart.mode);
    assert_eq!(
        *h.host.upstream.lock(),
        Some((Some("sibling".into()), None))
    );
}
