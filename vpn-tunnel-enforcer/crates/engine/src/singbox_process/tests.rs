use std::net::{Ipv4Addr, TcpListener};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::types::OutboundFault;

use super::testkit::singbox_config;
use super::*;
use crate::ports;
use crate::test_support::{TempDir, singbox_exe};

const REALITY_LINE: &str = "+0300 2026-09-02 10:54:31 ERROR [123 200ms] connection: open connection to 1.1.1.1:443 using outbound/vless[proxy-out]: reality verification failed";
const TLS_LINE: &str = "+0300 2026-09-02 10:54:31 ERROR [1 100ms] connection: open connection to proxy-out: remote error: tls: handshake failure";
const DIAL_LINE: &str =
    "+0300 2026-09-02 10:54:31 ERROR [1 4s] connection: dial tcp 203.0.113.7:443: i/o timeout";
const STARTED_LINE: &str = "+0300 2026-09-02 10:54:30 INFO sing-box started (0.40s)";

/// AT-04-007 (tunnel-core 7.13): the fault classifier vectors.
#[test]
fn fault_classifier_vectors() {
    assert_eq!(
        classify_fault([REALITY_LINE; 5]),
        Some(OutboundFault::RealityKeyMismatch)
    );
    let one = [STARTED_LINE, REALITY_LINE, STARTED_LINE, STARTED_LINE];
    assert_eq!(classify_fault(one), None);
    assert_eq!(
        classify_fault([TLS_LINE; 4]),
        Some(OutboundFault::TlsHandshakeFailed)
    );
    assert_eq!(
        classify_fault([DIAL_LINE; 3]),
        Some(OutboundFault::UpstreamUnreachable)
    );
    assert_eq!(classify_fault([STARTED_LINE; 20]), None);
    assert_eq!(classify_fault(std::iter::empty()), None);
}

/// Priority reality > tls > unreachable, INFO lines ignored, only the last 500 lines count.
#[test]
fn fault_classifier_priority_and_window() {
    let mut lines = vec![DIAL_LINE; 5];
    lines.extend([TLS_LINE; 3]);
    assert_eq!(
        classify_fault(lines.clone()),
        Some(OutboundFault::TlsHandshakeFailed)
    );
    lines.extend([REALITY_LINE; 3]);
    assert_eq!(
        classify_fault(lines),
        Some(OutboundFault::RealityKeyMismatch)
    );
    let info = DIAL_LINE.replace("ERROR", "INFO");
    assert_eq!(classify_fault([info.as_str(); 5]), None);
    let mut old = vec![REALITY_LINE; 3];
    old.extend([STARTED_LINE; 500]);
    assert_eq!(classify_fault(old), None);
}

#[test]
fn version_parsing_and_gate() {
    let full =
        "sing-box version 1.14.4\n\nEnvironment: go1.25.4 windows/amd64\nTags: with_gvisor\n";
    assert_eq!(parse_version(full), Some((1, 14, 4)));
    assert_eq!(
        parse_version("sing-box version 1.14.0-rc.2\n"),
        Some((1, 14, 0))
    );
    assert_eq!(parse_version("1.14.4\n"), None);
    assert_eq!(parse_version("sing-box version x.y\n"), None);
    assert_eq!(parse_version(""), None);
    assert!(version_supported((1, 14, 4)) && version_supported((1, 14, 0)));
    assert!(!version_supported((1, 13, 13)) && !version_supported((1, 15, 0)));
}

#[test]
fn errors_map_to_app_errors() {
    let e = AppError::from(StartError::Timeout);
    assert_eq!(
        (e.kind, e.user_msg().key.as_ref()),
        (ErrorKind::Timeout, "engine.process.singboxNotReady")
    );
    assert_eq!(
        AppError::from(StartError::Cancelled).kind,
        ErrorKind::Cancelled
    );
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    assert_eq!(
        AppError::from(StartError::Spawn(denied)).kind,
        ErrorKind::Permission
    );
    let e = AppError::from(StopError::ExitNotConfirmed);
    assert_eq!(e.user_msg().key, "engine.process.stopUnconfirmed");
    assert_eq!(
        AppError::from(CheckError::Rejected("x".into())).kind,
        ErrorKind::Validation
    );
}

fn start(exe: &Path, logs: Option<&Path>) -> (SingBoxProcess, u16) {
    let port = ports::alloc_port(false, &[]).unwrap();
    let config = singbox_config(port, &ports::creds(), None);
    (SingBoxProcess::spawn(exe, &config, logs).unwrap(), port)
}

/// AT-02-001 / AT-02-004: the real engine starts from stdin, reports readiness, logs the session
/// (secrets never reach the file) and stops with an observed, user-initiated exit.
#[tokio::test]
async fn real_engine_starts_and_stops() {
    let Some(exe) = singbox_exe() else { return };
    let logs = TempDir::new("sb-run");
    let creds = ports::creds();
    let port = ports::alloc_port(false, &[]).unwrap();
    let config = singbox_config(port, &creds, None);
    let sb = SingBoxProcess::spawn(&exe, &config, Some(logs.path())).unwrap();
    let mut lines = sb.subscribe_lines();
    sb.wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap();
    assert!(sb.pid() > 0 && sb.exit_info().is_none());
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
    );
    assert!(sb.tail(50).iter().any(|l| l.contains(READY_MARKER)));
    assert_eq!(sb.recent_fault(), None);
    let seen = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(line) = lines.recv().await {
            if line.contains(READY_MARKER) {
                return true;
            }
        }
        false
    });
    assert!(seen.await.unwrap());

    let info = sb.terminate(STOP_TIMEOUT).await.unwrap();
    assert!(info.user_initiated);
    assert_eq!(info.code, Some(KILL_CODE));
    assert_eq!(
        sb.terminate(STOP_TIMEOUT).await.unwrap(),
        info,
        "idempotent"
    );
    assert!(
        TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port released"
    );
    let log = std::fs::read_to_string(logs.path().join("sing-box.log")).unwrap();
    assert!(log.contains("sing-box started"));
    assert!(!log.contains(&creds.pass) && !log.contains(&creds.user));
}

/// tunnel-core 3.21: `sing-box.log` holds the current session; the previous one is `.1.log`.
#[tokio::test]
async fn each_start_rotates_the_session_log() {
    let Some(exe) = singbox_exe() else { return };
    let logs = TempDir::new("sb-rotate");
    for _ in 0..2 {
        let (sb, _) = start(&exe, Some(logs.path()));
        sb.wait_ready(READY_TIMEOUT, &CancellationToken::new())
            .await
            .unwrap();
        sb.terminate(STOP_TIMEOUT).await.unwrap();
        drop(sb);
        // The pumps hold the writer until they have drained the closed pipes.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let count = |name: &str| {
        let text = std::fs::read_to_string(logs.path().join(name)).unwrap();
        text.matches("sing-box started").count()
    };
    assert_eq!(count("sing-box.log"), 1);
    assert_eq!(count("sing-box.1.log"), 1);
}

/// tunnel-core 3.3 / B-17: an early exit is reported at once with its tail, and a port that is
/// already bound is recognised so the caller can retry with fresh ports.
#[tokio::test]
async fn early_exit_reports_the_bind_failure() {
    let Some(exe) = singbox_exe() else { return };
    let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = held.local_addr().unwrap().port();
    let config = singbox_config(port, &ports::creds(), None);
    let sb = SingBoxProcess::spawn(&exe, &config, None).unwrap();
    let started = std::time::Instant::now();
    let err = sb
        .wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "no readiness timeout wait"
    );
    let StartError::Exited(info) = err else {
        panic!("expected an exit, got {err:?}")
    };
    assert!(!info.user_initiated && info.code.is_some_and(|c| c != 0));
    assert!(info.binds_any(&[port]), "tail: {}", info.stderr_tail);
    assert!(!info.stderr_tail.is_empty());
    assert!(sb.exit_watch().borrow().is_some());
}

/// A config sing-box cannot decode exits before readiness (no TUN, nothing to clean up).
#[tokio::test]
async fn undecodable_config_exits_early() {
    let Some(exe) = singbox_exe() else { return };
    let sb = SingBoxProcess::spawn(&exe, br#"{"inbounds": 42}"#, None).unwrap();
    let err = sb
        .wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, StartError::Exited(ref i) if !i.binds_any(&[1])),
        "{err:?}"
    );
}

/// Cancellation wins over readiness; dropping the process kills the engine (its Job closes).
#[tokio::test]
async fn cancel_and_drop() {
    let Some(exe) = singbox_exe() else { return };
    let (sb, port) = start(&exe, None);
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(matches!(
        sb.wait_ready(READY_TIMEOUT, &cancel).await,
        Err(StartError::Cancelled)
    ));
    sb.wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap();
    let mut exit = sb.exit_watch();
    drop(sb);
    let info = tokio::time::timeout(Duration::from_secs(5), exit.wait_for(Option::is_some))
        .await
        .unwrap()
        .unwrap()
        .clone()
        .unwrap();
    assert!(info.user_initiated);
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
}

#[tokio::test]
async fn spawn_of_a_missing_exe_fails_at_once() {
    let missing = std::env::temp_dir().join("vpnte-no-such-engine.exe");
    let err = SingBoxProcess::spawn(&missing, b"{}", None).err().unwrap();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}

#[tokio::test]
async fn bundled_engine_version_is_supported() {
    let Some(exe) = singbox_exe() else { return };
    let version = engine_version(&exe).await.unwrap();
    assert!(version_supported(version), "{version:?}");
}

/// The config check accepts a good config and explains a bad one without leaking its secrets.
#[tokio::test]
async fn check_config_accepts_and_rejects() {
    let Some(exe) = singbox_exe() else { return };
    let creds = ports::creds();
    check_config(&exe, &singbox_config(20000, &creds, None))
        .await
        .unwrap();
    let bad = format!(
        r#"{{"outbounds":[{{"type":"no-such-type","tag":"x","password":"{}"}}]}}"#,
        creds.pass
    );
    let err = check_config(&exe, bad.as_bytes()).await.unwrap_err();
    let CheckError::Rejected(reason) = err else {
        panic!("{err:?}")
    };
    assert!(
        !reason.is_empty() && !reason.contains(&creds.pass),
        "{reason}"
    );
}

#[test]
fn futures_are_send() {
    fn send<T: Send>(_: &T) {}
    let exe = Path::new("sing-box.exe");
    send(&engine_version(exe));
    send(&check_config(exe, b"{}"));
    let api = crate::clash_api::ClashApi::new(&crate::clash_api::ClashEndpoint {
        port: 1,
        secret: "0".repeat(32),
    })
    .unwrap();
    send(&api.select("proxy-out", "a", &["a", "b"]));
    send(&api.connections());
    send(&api.traffic());
}
