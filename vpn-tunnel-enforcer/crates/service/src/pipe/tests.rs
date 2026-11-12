//! Pipe tests on private pipes: first-instance protection, client identity, server check.
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use super::client::{Client, ServerCheck};
use super::*;
use crate::proto::frame;

/// Grants every authenticated user full access (see host tests: the unelevated test process
/// must be able to create further instances of its own pipe).
const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)";

static NEXT: AtomicU32 = AtomicU32::new(0);

fn config() -> PipeConfig {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    PipeConfig {
        name: format!(r"\\.\pipe\vpnte-pipe-test-{}-{n}", std::process::id()),
        sddl: TEST_SDDL.into(),
    }
}

#[tokio::test]
async fn a_second_listener_on_the_same_name_is_refused() {
    let config = config();
    let _first = Listener::bind(&config).expect("first");
    assert!(
        Listener::bind(&config).is_err(),
        "FILE_FLAG_FIRST_PIPE_INSTANCE: nobody else may serve our name"
    );
}

#[tokio::test]
async fn the_server_identifies_its_client() {
    let config = config();
    let mut listener = Listener::bind(&config).expect("bind");
    let name = config.name.clone();
    let client = tokio::spawn(async move {
        let mut pipe = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .expect("open");
        frame::write_frame(&mut pipe, &"hello")
            .await
            .expect("write");
        // Keep the pipe open until the server is done.
        tokio::time::sleep(Duration::from_millis(500)).await;
    });
    let mut server = listener.accept().await.expect("accept");
    frame::read_frame(&mut server).await.expect("frame");
    let info = ident::client(&server).expect("identity");
    assert_eq!(info.pid, std::process::id());
    assert!(info.user.starts_with("S-1-5-"), "{}", info.user);
    assert_eq!(
        info.image.as_deref().and_then(|p| p.file_name()),
        std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(|p| p.file_name())
    );
    client.await.expect("client task");
}

#[tokio::test]
async fn the_client_refuses_a_server_that_is_not_the_expected_exe() {
    let config = config();
    let mut listener = Listener::bind(&config).expect("bind");
    let accept = tokio::spawn(async move {
        for _ in 0..2 {
            let _ = listener.accept().await;
        }
        listener
    });
    let own = std::env::current_exe().expect("own exe");
    let own = std::fs::canonicalize(&own).expect("canonical");
    let own = std::path::PathBuf::from(own.to_string_lossy().trim_start_matches(r"\\?\"));
    let ok = Client::connect(
        &config.name,
        &ServerCheck::Image(own),
        Duration::from_secs(5),
    )
    .await;
    assert!(ok.is_ok(), "the test process serves the pipe");
    let other = ServerCheck::Image(
        r"C:\Program Files\VPN Tunnel Enforcer Service\vpnte-service.exe".into(),
    );
    let err = Client::connect(&config.name, &other, Duration::from_secs(5))
        .await
        .err()
        .expect("refused");
    assert_eq!(err.user_msg().key, "service.pipe.notOurs");
    drop(accept.await.expect("accept task"));
}

#[tokio::test]
async fn a_missing_pipe_reads_as_service_unavailable() {
    let err = Client::connect(
        r"\\.\pipe\vpnte-no-such-pipe",
        &ServerCheck::Any,
        Duration::from_millis(100),
    )
    .await
    .err()
    .expect("no pipe");
    assert_eq!(err.user_msg().key, "service.pipe.unavailable");
}

/// A connected client and the server end of its pipe.
async fn pair() -> (Client, tokio::net::windows::named_pipe::NamedPipeServer) {
    let config = config();
    let mut listener = Listener::bind(&config).expect("bind");
    let server = tokio::spawn(async move { listener.accept().await.expect("accept") });
    let client = Client::connect(&config.name, &ServerCheck::Any, Duration::from_secs(5))
        .await
        .expect("connect");
    (client, server.await.expect("server task"))
}

fn status_event() -> Vec<u8> {
    let status = crate::proto::StatusWire::from(&vpnte_tunnel::api::TunStatus::default());
    let event = crate::proto::ServerFrame::Event {
        event: Box::new(crate::proto::Event::Status(Box::new(status))),
    };
    frame::encode(&event).expect("encode")
}

/// Review service-a12: a read dropped in the middle of a frame (a `select!` that picked another
/// branch) loses nothing; the frame is whole at the next read.
#[tokio::test]
async fn a_read_dropped_mid_frame_loses_nothing() {
    use tokio::io::AsyncWriteExt;
    let (mut client, mut server) = pair().await;
    let bytes = status_event();
    server.write_all(&bytes[..6]).await.expect("half a frame");
    let first = tokio::time::timeout(Duration::from_millis(200), client.next_event()).await;
    assert!(first.is_err(), "nothing whole yet");
    server.write_all(&bytes[6..]).await.expect("the rest");
    server.write_all(&bytes).await.expect("one more");
    for _ in 0..2 {
        let event = client.next_event().await.expect("a whole event");
        assert!(matches!(event, crate::proto::Event::Status(_)));
    }
}

/// Review service-b7: a frame this build cannot read and a broken connection are named for what
/// they are, not "the service is not running".
#[tokio::test]
async fn a_foreign_reply_and_a_lost_connection_say_so() {
    use tokio::io::AsyncWriteExt;
    let (mut client, mut server) = pair().await;
    let foreign = br#"{"future":true}"#;
    let mut raw = u32::try_from(foreign.len())
        .expect("len")
        .to_le_bytes()
        .to_vec();
    raw.extend_from_slice(foreign);
    server.write_all(&raw).await.expect("write");
    let key = |err| match err {
        super::client::CallError::Pipe(e) => e.user_msg().key,
        other => panic!("{other:?}"),
    };
    let err = client.next_event().await.expect_err("not ours");
    assert_eq!(key(err), "service.pipe.badReply");
    drop(server);
    let err = client.next_event().await.expect_err("gone");
    assert_eq!(key(err), "service.pipe.lost");
}
