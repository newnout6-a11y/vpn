//! Re-check item 12a: the app's Smart RU lists cross the pipe (protocol 3; a version-2 service
//! never sees them) and the service uses them only after its own checks, else its pinned files.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use vpnte_engine::routing::smart_ru::RULE_SETS;

use super::*;
use crate::pipe::client::{Client, ServerCheck};
use crate::pipe::{Listener, PipeConfig};
use crate::proto::{ClientFrame, Reply, Request, ServerFrame, frame};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
/// Every authenticated user may open further instances (the test process is not elevated).
const TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)";

static NEXT: AtomicU32 = AtomicU32::new(0);

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpnte-inputs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// A copy of the bundled set in `dir`.
fn copy_set(dir: &Path) {
    std::fs::create_dir_all(dir).expect("dir");
    for (_, file, _) in RULE_SETS {
        std::fs::copy(Path::new(RESOURCES).join(file), dir.join(file)).expect("copy");
    }
}

/// The bundled set with a blocked-sites list compiled afresh (a newer list the service has not
/// seen; it still passes the canaries).
fn fresher_set(t: &Path) -> RuleSetFiles {
    let dir = t.join("fresher");
    copy_set(&dir);
    let source = t.join("sites.json");
    std::fs::write(
        &source,
        r#"{"version":3,"rules":[{"domain_suffix":["rutracker.org","linkedin.com","fresh.example"]}]}"#,
    )
    .expect("source");
    let out = std::process::Command::new(Path::new(RESOURCES).join("sing-box.exe"))
        .args(["rule-set", "compile", "--output"])
        .arg(dir.join("geosite-ru-blocked.srs"))
        .arg(&source)
        .output()
        .expect("sing-box ran");
    assert!(out.status.success(), "{out:?}");
    RuleSetFiles::read(&dir).expect("a full set")
}

fn routing(rule_sets: Option<RuleSetFiles>) -> RoutingInputs {
    RoutingInputs {
        smart_ru: true,
        rule_sets,
        ..RoutingInputs::default()
    }
}

/// `routing` sent by the real client to a fake service that speaks `protocol`; what it got.
async fn over_the_pipe(protocol: u32, routing: RoutingInputs) -> RoutingInputs {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let config = PipeConfig {
        name: format!(r"\\.\pipe\vpnte-inputs-test-{}-{n}", std::process::id()),
        sddl: TEST_SDDL.into(),
    };
    let mut listener = Listener::bind(&config).expect("bind");
    let service = tokio::spawn(async move {
        let mut pipe = listener.accept().await.expect("accept");
        let body = frame::read_frame(&mut pipe).await.expect("hello");
        let hello: ClientFrame = frame::decode(&body).expect("decode");
        let welcome = Reply::Welcome {
            protocol,
            service_version: "test".into(),
        };
        let reply = ServerFrame::Reply {
            id: hello.id,
            reply: Box::new(welcome),
        };
        frame::write_frame(&mut pipe, &reply)
            .await
            .expect("welcome");
        let body = frame::read_frame(&mut pipe).await.expect("inputs");
        let request: ClientFrame = frame::decode(&body).expect("a version-2 service reads it");
        let done = ServerFrame::Reply {
            id: request.id,
            reply: Box::new(Reply::Done { removing: false }),
        };
        frame::write_frame(&mut pipe, &done).await.expect("done");
        match request.request {
            Request::Inputs(r) => *r,
            other => panic!("{other:?}"),
        }
    });
    let mut client = Client::connect(&config.name, &ServerCheck::Any, Duration::from_secs(5))
        .await
        .expect("connect");
    assert_eq!(client.hello("test").await.expect("hello").0, protocol);
    let request = Request::Inputs(Box::new(routing));
    client.call(request).await.expect("answered");
    service.await.expect("fake service")
}

/// Protocol 3: a fresher set crosses the pipe, passes the service's own checks and is used from
/// its store (the same set again needs no second check); protocol 2: the field never reaches a
/// version-2 service, which keeps its pinned files.
#[tokio::test]
async fn the_lists_cross_the_pipe_and_are_used_after_the_service_checks_them() {
    let pinned = Path::new(RESOURCES);
    if !pinned.join("sing-box.exe").is_file() {
        return;
    }
    let t = temp("pipe");
    let store = t.join("store");
    let inputs = SharedInputs::with_store(Some(pinned.to_owned()), Some(store.clone()));
    let set = fresher_set(&t);

    let got = over_the_pipe(3, routing(Some(set.clone()))).await;
    assert_eq!(got.rule_sets.as_ref(), Some(&set));
    inputs.set(&got, KillSwitchLevel::Off);
    let dir = inputs.snapshot().await.expect("inputs").rule_set_dir;
    let dir = dir.expect("a rule-set folder");
    assert!(dir.starts_with(&store), "{dir:?}");
    assert_eq!(
        std::fs::read(dir.join("geosite-ru-blocked.srs")).expect("stored"),
        std::fs::read(t.join("fresher").join("geosite-ru-blocked.srs")).expect("sent")
    );
    let again = inputs.snapshot().await.expect("inputs").rule_set_dir;
    assert_eq!(again.as_ref(), Some(&dir));

    let got = over_the_pipe(2, routing(Some(set))).await;
    assert_eq!(got.rule_sets, None, "stripped for a version-2 service");
    inputs.set(&got, KillSwitchLevel::Off);
    let dir = inputs.snapshot().await.expect("inputs").rule_set_dir;
    assert_eq!(dir.as_deref(), Some(pinned));
    let _ = std::fs::remove_dir_all(&t);
}

/// A set that fails its canaries keeps the pinned files (nothing stored); the pinned set itself
/// is used in place; Smart RU off needs no folder; an incomplete install folder gives none.
#[tokio::test]
async fn a_failing_set_keeps_the_pinned_files() {
    let pinned = Path::new(RESOURCES);
    if !pinned.join("sing-box.exe").is_file() {
        return;
    }
    let t = temp("refused");
    let store = t.join("store");
    let inputs = SharedInputs::with_store(Some(pinned.to_owned()), Some(store.clone()));
    let bad = t.join("bad");
    copy_set(&bad);
    std::fs::copy(
        pinned.join("geoip-ru.srs"),
        bad.join("geoip-ru-blocked.srs"),
    )
    .expect("swap");
    for set in [RuleSetFiles::read(&bad), RuleSetFiles::read(pinned)] {
        inputs.set(&routing(set), KillSwitchLevel::Off);
        let dir = inputs.snapshot().await.expect("inputs").rule_set_dir;
        assert_eq!(dir.as_deref(), Some(pinned));
    }
    let stored = std::fs::read_dir(&store).map(|d| d.count()).unwrap_or(0);
    assert_eq!(stored, 0, "nothing stored");

    let mut off = routing(RuleSetFiles::read(pinned));
    off.smart_ru = false;
    inputs.set(&off, KillSwitchLevel::Off);
    assert_eq!(inputs.snapshot().await.expect("inputs").rule_set_dir, None);

    let partial = t.join("install");
    std::fs::create_dir_all(&partial).expect("dir");
    std::fs::copy(pinned.join("geoip-ru.srs"), partial.join("geoip-ru.srs")).expect("copy");
    let incomplete = SharedInputs::with_store(Some(partial), Some(store));
    incomplete.set(&routing(None), KillSwitchLevel::Off);
    assert_eq!(incomplete.get().rule_set_dir, None);
    let _ = std::fs::remove_dir_all(&t);
}
