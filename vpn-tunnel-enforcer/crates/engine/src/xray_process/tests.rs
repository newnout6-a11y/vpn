use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::OutboundFault;

use super::*;
use crate::ports;
use crate::singbox_process::testkit::xray_config;
use crate::test_support::{TempDir, console_free, xray_exe};

const NO_DESTINATION: &str = "2026/09/02 10:54:31.123456 [Info] [1234567] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > common/retry: [dial tcp 1.2.3.4:443: i/o timeout] > common/retry: all retry attempts failed";

/// AT-04-007 (xray-engine 7): the Xray fault classifier vectors.
#[test]
fn fault_classifier_vectors() {
    let reality = [
        "2026/09/02 10:54:31 [Warning] [12345] proxy: REALITY: processed invalid connection",
        "2026/09/02 10:54:31 [Warning] [12345] proxy: REALITY verification failed",
    ];
    assert_eq!(
        classify_xray_fault(reality),
        Some(OutboundFault::RealityKeyMismatch)
    );
    assert_eq!(
        classify_xray_fault([NO_DESTINATION; 3]),
        Some(OutboundFault::UpstreamUnreachable)
    );
    let refused = NO_DESTINATION.replace("i/o timeout", "connectex: connection refused");
    assert_eq!(
        classify_xray_fault([refused.as_str(); 3]),
        Some(OutboundFault::UpstreamUnreachable)
    );
    assert_eq!(classify_xray_fault([NO_DESTINATION; 2]), None);
    let closes = "2026/09/02 10:54:31 [Info] [42] app/proxyman/inbound: connection ends > io: read/write on closed pipe";
    assert_eq!(classify_xray_fault([closes; 10]), None);
    let reset = "2026/09/02 10:54:31 [Info] [42] app/proxyman/inbound: connection ends > read: connection reset by peer";
    assert_eq!(
        classify_xray_fault([reset; 3]),
        Some(OutboundFault::UpstreamUnreachable)
    );
    let tls =
        "2026/09/02 10:54:31 [Info] [7] transport/internet/tls: remote error: tls: bad certificate";
    assert_eq!(
        classify_xray_fault([tls; 2]),
        Some(OutboundFault::TlsHandshakeFailed)
    );
    let no_level = "proxy: REALITY verification failed";
    assert_eq!(classify_xray_fault([no_level; 5]), None);
    assert_eq!(classify_xray_fault(std::iter::empty()), None);
}

#[test]
fn errors_map_to_app_errors() {
    let busy = AppError::from(XrayError::SlotOccupied);
    assert_eq!(
        (busy.kind, busy.user_msg().key.as_ref()),
        (ErrorKind::Conflict, "engine.process.xray.slotOccupied")
    );
    let not_ready = AppError::from(XrayError::NotReady {
        port: 25551,
        cause: SocksError::AuthRequired,
    });
    assert_eq!(
        not_ready.user_msg(),
        Msg::new("engine.process.xray.socksNotReady").arg("port", 25551)
    );
    assert_eq!(
        AppError::from(XrayError::Cancelled).kind,
        ErrorKind::Cancelled
    );
    let early = AppError::from(XrayError::ExitedEarly {
        code: Some(-1),
        tail: String::new(),
    });
    assert_eq!(
        early.user_msg(),
        Msg::new("engine.process.xray.exited").arg("code", -1)
    );
}

fn launch(ep: &SlotEndpoint) -> SlotLaunch {
    SlotLaunch {
        config: xray_config(ep.port(), ep.creds()),
        dial_target: Some("192.0.2.2:443".parse().unwrap()),
    }
}

fn supervisor(exe: PathBuf, logs: Option<&Path>) -> (XraySupervisor, mpsc::Receiver<XrayEvent>) {
    let (tx, rx) = mpsc::channel(16);
    (
        XraySupervisor::new(exe, logs.map(Path::to_path_buf), tx),
        rx,
    )
}

async fn next_event(rx: &mut mpsc::Receiver<XrayEvent>) -> XrayEvent {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

/// AT-00-002 / AT-02-002: a slot starts from stdin, passes the authenticated readiness, logs
/// its session, activates, and stops with an expected exit event.
#[tokio::test]
async fn slot_starts_activates_and_stops() {
    let Some(exe) = xray_exe() else { return };
    let logs = TempDir::new("xray-run");
    let (mut sup, mut events) = supervisor(exe, Some(logs.path()));
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    let status = sup
        .start(Slot::A, ep.clone(), launch(&ep), &CancellationToken::new())
        .await
        .unwrap();
    assert!(status.running && status.pid.is_some_and(|p| p > 0));
    assert_eq!(status.port, Some(ep.port()));
    assert_eq!(status.dial_target, Some("192.0.2.2:443".parse().unwrap()));
    assert_eq!(sup.endpoint(Slot::A), Some(&ep));
    assert!(matches!(sup.activate(Slot::B), Err(XrayError::NotRunning)));
    sup.activate(Slot::A).unwrap();
    assert_eq!(sup.active(), Some(Slot::A));
    assert_eq!(sup.recent_fault(Slot::A), None);

    sup.stop(Slot::A).await.unwrap();
    assert_eq!(sup.status(Slot::A), SlotStatus::default());
    assert_eq!(sup.active(), None);
    let XrayEvent::Exited { slot, expected, .. } = next_event(&mut events).await;
    assert_eq!((slot, expected), (Slot::A, true));
    sup.stop(Slot::A).await.unwrap();
    let log = std::fs::read_to_string(logs.path().join("xray-a.log")).unwrap();
    assert!(!log.is_empty() && !log.contains(&ep.creds().pass));
}

/// AT-02-009: a stop asks first. The real Xray (authenticated loopback SOCKS inbound) ends by
/// itself on CTRL_BREAK with its own clean exit inside the grace period: no kill, and the exit
/// event says so.
#[tokio::test]
async fn graceful_stop_needs_no_kill() {
    let Some(exe) = xray_exe() else { return };
    if !console_free() {
        return;
    }
    let (mut sup, mut events) = supervisor(exe, None);
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    sup.start(Slot::A, ep.clone(), launch(&ep), &CancellationToken::new())
        .await
        .unwrap();
    let started = Instant::now();
    sup.stop(Slot::A).await.unwrap();
    let took = started.elapsed();
    eprintln!("xray stopped gracefully in {took:?}");
    let XrayEvent::Exited {
        expected,
        graceful,
        code,
        ..
    } = next_event(&mut events).await;
    assert!(expected && graceful, "code {code:?}");
    // Xray's own exit, not a kill: 0 once its handler runs, or STATUS_CONTROL_C_EXIT when the
    // break lands between its «started» line (the S3-02 readiness) and its signal.Notify, a few
    // ms of GC: Go's default console handler then ends it on our CTRL_BREAK (14.11.2026: seen
    // under load in the lead's verify run). A kill is KILL_CODE.
    const STATUS_CONTROL_C_EXIT: i32 = 0xC000_013A_u32 as i32;
    assert!(
        matches!(code, Some(0) | Some(STATUS_CONTROL_C_EXIT)),
        "code {code:?}: not Xray's own exit (a kill is {})",
        child::KILL_CODE
    );
    assert!(took < GRACEFUL_STOP, "took {took:?}");
}

/// AT-02-002 (xray-engine 7): staging B never stops A; B on A's port is refused without a
/// spawn; a live slot is never overwritten; `stop(A)` stops A only.
#[tokio::test]
async fn two_slots_are_independent() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, _events) = supervisor(exe, None);
    let cancel = CancellationToken::new();
    let a = SlotEndpoint::allocate(&[]).unwrap();
    let pid_a = sup
        .start(Slot::A, a.clone(), launch(&a), &cancel)
        .await
        .unwrap()
        .pid;

    let clash = SlotEndpoint::new(a.port(), ports::creds()).unwrap();
    let err = sup
        .start(Slot::B, clash.clone(), launch(&clash), &cancel)
        .await
        .unwrap_err();
    assert!(matches!(err, XrayError::PortOwnedByOtherSlot), "{err:?}");
    assert_eq!(sup.status(Slot::B), SlotStatus::default());
    let again = sup
        .start(Slot::A, a.clone(), launch(&a), &cancel)
        .await
        .unwrap_err();
    assert!(matches!(again, XrayError::SlotOccupied));
    assert_eq!(sup.status(Slot::A).pid, pid_a);

    let b = SlotEndpoint::allocate(&[a.port()]).unwrap();
    sup.start(Slot::B, b.clone(), launch(&b), &cancel)
        .await
        .unwrap();
    sup.activate(Slot::B).unwrap();
    assert!(sup.status(Slot::A).running, "staging B kept A");
    sup.stop(Slot::A).await.unwrap();
    assert!(!sup.status(Slot::A).running && sup.status(Slot::B).running);
    assert_eq!(sup.active(), Some(Slot::B));
    sup.stop_all().await.unwrap();
    assert_eq!(sup.status(Slot::B), SlotStatus::default());
}

/// AT-02-003: an unexpected exit of a running slot is an event within 3 s; `restart` reaps the
/// dead instance and starts on the same port with the same credentials, keeping it active.
#[tokio::test]
async fn crash_is_reported_and_restart_reuses_the_endpoint() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, mut events) = supervisor(exe, None);
    let cancel = CancellationToken::new();
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    let first = sup
        .start(Slot::A, ep.clone(), launch(&ep), &cancel)
        .await
        .unwrap();
    sup.activate(Slot::A).unwrap();
    sup.slots[0].as_ref().unwrap().child.crash();
    let XrayEvent::Exited {
        slot,
        pid,
        code,
        expected,
        ..
    } = next_event(&mut events).await;
    assert_eq!(
        (slot, Some(pid), code, expected),
        (Slot::A, first.pid, Some(77), false)
    );
    assert!(!sup.status(Slot::A).running);
    assert_eq!(sup.active(), Some(Slot::A));

    let second = sup.restart(Slot::A, &cancel).await.unwrap();
    assert!(second.running && second.pid != first.pid);
    assert_eq!(sup.endpoint(Slot::A), Some(&ep));
    assert_eq!(sup.active(), Some(Slot::A));
    assert!(matches!(
        sup.restart(Slot::B, &cancel).await,
        Err(XrayError::NotStarted)
    ));
    sup.stop_all().await.unwrap();
}

/// A REALITY outbound whose key Xray refuses at config build (exit 23).
fn bad_reality(ep: &SlotEndpoint, key: &str) -> Vec<u8> {
    let mut config: serde_json::Value =
        serde_json::from_slice(&xray_config(ep.port(), ep.creds())).unwrap();
    config["outbounds"] = serde_json::json!([{
        "protocol": "vless", "tag": "proxy",
        "settings": { "vnext": [{ "address": "192.0.2.10", "port": 443,
            "users": [{ "id": "6f1c7e0a-52b8-4d55-9c36-2a8fd1d3c001", "encryption": "none" }] }] },
        "streamSettings": { "network": "raw", "security": "reality",
            "realitySettings": { "serverName": "www.example.org", "fingerprint": "chrome",
                                 "publicKey": key, "shortId": "a1b2c3d4" } }
    }]);
    serde_json::to_vec(&config).unwrap()
}

/// xray-engine 7 (new): exit 23 is `ConfigRejected` with the `Failed to start:` reason at once
/// (no 3.5 s wait), and the reason never carries the config's secrets.
#[tokio::test]
async fn refused_config_is_reported_at_once_and_redacted() {
    let Some(exe) = xray_exe() else { return };
    let logs = TempDir::new("xray-refused");
    let (mut sup, _events) = supervisor(exe.clone(), Some(logs.path()));
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    // Xray echoes it: `… Failed to build REALITY config. > infra/conf: invalid "password": <key>`.
    let key = "SECRETkeyNOTbase64-value-0123";
    let bad = SlotLaunch {
        config: bad_reality(&ep, key),
        dial_target: None,
    };
    let started = std::time::Instant::now();
    let err = sup
        .start(Slot::A, ep.clone(), bad, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        started.elapsed() < Duration::from_millis(3000),
        "{:?}",
        started.elapsed()
    );
    let XrayError::ConfigRejected(reason) = err else {
        panic!("{err:?}")
    };
    assert!(reason.starts_with("Failed to start:"), "{reason}");
    assert!(
        !reason.contains(key) && !reason.contains(&ep.creds().pass),
        "{reason}"
    );
    assert_eq!(sup.status(Slot::A), SlotStatus::default());
    let log = std::fs::read_to_string(logs.path().join("xray-a.log")).unwrap();
    assert!(
        log.contains("Failed to start:") && !log.contains(key),
        "{log}"
    );

    let checked = check_config(&exe, &bad_reality(&ep, key))
        .await
        .unwrap_err();
    let XrayError::ConfigRejected(reason) = checked else {
        panic!("{checked:?}")
    };
    assert!(!reason.contains(key), "{reason}");
    check_config(&exe, &xray_config(ep.port(), ep.creds()))
        .await
        .unwrap();
}

/// xray-engine 7 (new): a SOCKS port that is already bound makes `server.Start()` fail: exit -1.
#[tokio::test]
async fn bound_port_exits_with_minus_one() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, mut events) = supervisor(exe, None);
    let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let ep = SlotEndpoint::new(held.local_addr().unwrap().port(), ports::creds()).unwrap();
    let err = sup
        .start(Slot::B, ep.clone(), launch(&ep), &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(err, XrayError::ExitedEarly { code: Some(-1), .. }),
        "{err:?}"
    );
    assert_eq!(sup.status(Slot::B), SlotStatus::default());
    // A start failure is `start`'s own error, never also an exit event.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(events.try_recv().is_err());
}

/// xray-engine 7: a foreign listener answering NoAuth is never taken for the slot; the slot is
/// stopped again and cannot be activated.
#[tokio::test]
async fn no_auth_listener_is_not_ready() {
    let Some(exe) = xray_exe() else { return };
    let fake = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = fake.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = fake.accept().await {
            let mut greeting = [0u8; 3];
            if sock.read_exact(&mut greeting).await.is_ok() {
                let _ = sock.write_all(&[5, 0]).await;
            }
        }
    });
    let (mut sup, _events) = supervisor(exe, None);
    let ep = SlotEndpoint::new(port, ports::creds()).unwrap();
    let real = SlotEndpoint::allocate(&[port]).unwrap();
    let launch = SlotLaunch {
        config: xray_config(real.port(), ep.creds()),
        dial_target: None,
    };
    let err = sup
        .start(Slot::B, ep, launch, &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            XrayError::NotReady {
                cause: SocksError::AuthRequired,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(matches!(sup.activate(Slot::B), Err(XrayError::NotRunning)));
    assert_eq!(sup.status(Slot::B).pid, None);
}

/// xray-engine 7: a cancelled start stops the candidate and leaves no instance; a missing exe
/// fails at once.
#[tokio::test]
async fn cancelled_start_and_missing_exe() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, _events) = supervisor(exe, None);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    let err = sup
        .start(Slot::B, ep.clone(), launch(&ep), &cancel)
        .await
        .unwrap_err();
    assert!(matches!(err, XrayError::Cancelled));
    assert_eq!(sup.status(Slot::B).pid, None);

    let (mut missing, _events) = supervisor(std::env::temp_dir().join("vpnte-no-xray.exe"), None);
    let err = missing
        .start(Slot::A, ep.clone(), launch(&ep), &CancellationToken::new())
        .await;
    assert!(matches!(err, Err(XrayError::Spawn(_))));
}

/// xray-engine 7: cancelling a candidate whose readiness is still pending returns at once,
/// stops the candidate (no instance left) and leaves the running slot alone.
#[tokio::test]
async fn cancel_during_readiness_keeps_the_running_slot() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, _events) = supervisor(exe, None);
    let a = SlotEndpoint::allocate(&[]).unwrap();
    let pid_a = sup
        .start(Slot::A, a.clone(), launch(&a), &CancellationToken::new())
        .await
        .unwrap()
        .pid;
    // Xray listens elsewhere, so nothing ever answers on the candidate's port.
    let b = SlotEndpoint::allocate(&[a.port()]).unwrap();
    let elsewhere = ports::alloc_port(false, &[a.port(), b.port()]).unwrap();
    let held = SlotLaunch {
        config: xray_config(elsewhere, b.creds()),
        dial_target: None,
    };
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(400)).await;
        trigger.cancel();
    });
    let started = std::time::Instant::now();
    let err = sup.start(Slot::B, b, held, &cancel).await.unwrap_err();
    assert!(matches!(err, XrayError::Cancelled), "{err:?}");
    assert!(started.elapsed() < READY_TIMEOUT, "{:?}", started.elapsed());
    assert_eq!(sup.status(Slot::B), SlotStatus::default());
    let a_now = sup.status(Slot::A);
    assert!(a_now.running && a_now.pid == pid_a);
    sup.stop_all().await.unwrap();
}

/// xray-engine 3.6: the tunnel retries `restart` with backoff, so a failed attempt keeps the
/// stored launch and the active mark; the next attempt starts on the same endpoint.
#[tokio::test]
async fn failed_restart_can_be_retried() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, mut events) = supervisor(exe, None);
    let cancel = CancellationToken::new();
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    sup.start(Slot::A, ep.clone(), launch(&ep), &cancel)
        .await
        .unwrap();
    sup.activate(Slot::A).unwrap();
    sup.slots[0].as_ref().unwrap().child.crash();
    next_event(&mut events).await;
    // A foreign listener takes the port: Xray cannot bind it (exit -1).
    let squatter = std::net::TcpListener::bind(("127.0.0.1", ep.port())).unwrap();
    let err = sup.restart(Slot::A, &cancel).await.unwrap_err();
    assert!(
        matches!(err, XrayError::ExitedEarly { code: Some(-1), .. }),
        "{err:?}"
    );
    assert_eq!(sup.status(Slot::A), SlotStatus::default());
    assert_eq!(sup.active(), Some(Slot::A));
    drop(squatter);
    let again = sup.restart(Slot::A, &cancel).await.unwrap();
    assert!(again.running && again.port == Some(ep.port()));
    assert_eq!(sup.endpoint(Slot::A), Some(&ep));
    // `stop` forgets the launch: nothing left to restart.
    sup.stop(Slot::A).await.unwrap();
    assert!(matches!(
        sup.restart(Slot::A, &cancel).await,
        Err(XrayError::NotStarted)
    ));
}

/// The tunnel actor holds these across awaits in spawned tasks: they and their futures are Send.
#[test]
fn types_and_futures_are_send() {
    fn send<T: Send>(_: &T) {}
    fn send_sync<T: Send + Sync>() {}
    send_sync::<crate::singbox_process::SingBoxProcess>();
    send_sync::<crate::clash_api::ClashApi>();
    send_sync::<XraySupervisor>();
    let (mut sup, _events) = supervisor(PathBuf::from("xray.exe"), None);
    let cancel = CancellationToken::new();
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    send(&sup.start(Slot::A, ep.clone(), launch(&ep), &cancel));
    send(&sup.restart(Slot::A, &cancel));
    send(&sup.stop_all());
    send(&check_config(Path::new("xray.exe"), b"{}"));
    send(&engine_version(Path::new("xray.exe")));
}

#[test]
fn version_parsing() {
    let full = "Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 windows/amd64)\n\
                A unified platform for anti-censorship.\n";
    assert_eq!(parse_version(full), Some((26, 11, 9)));
    assert_eq!(
        parse_version("Xray 26.12.0-beta (Xray)\n"),
        Some((26, 12, 0))
    );
    assert_eq!(parse_version("26.11.9\n"), None);
    assert_eq!(parse_version("sing-box version 1.14.4\n"), None);
    assert_eq!(parse_version("Xray x.y\n"), None);
    assert_eq!(parse_version(""), None);
}

/// The bundled engine answers through the pinned one-shot path (skips without the binary).
#[tokio::test]
async fn bundled_engine_version() {
    let Some(exe) = xray_exe() else { return };
    let version = engine_version(&exe).await.unwrap();
    assert!(version >= (26, 9, 8), "{version:?}");
}

#[tokio::test]
async fn missing_exe_has_no_version() {
    let missing = std::env::temp_dir().join("vpnte-no-xray.exe");
    assert!(engine_version(&missing).await.is_err());
}

/// speed3 S3-02: Xray's verbatim start line (lab, Xray 26.11.9) marks it ready; its launch
/// banner, its `listening` line and a line that only mentions the words do not.
#[test]
fn only_the_started_line_marks_xray_ready() {
    let started = "2026/11/13 23:03:59.861752 [Warning] core: Xray 26.11.9 started";
    let banner = "Xray 26.11.9 (Xray, Penetrates Everything.) 676eaf6 (go1.27.3 windows/amd64)";
    let listening = "2026/11/13 23:03:59.861752 [Info] transport/internet/tcp: listening tcp on \
                     127.0.0.1:22686";
    let other = "2026/11/13 23:04:00.000001 [Info] core: Xray 26.11.9 started a task";
    assert!(STARTED.matches(started));
    assert!(!STARTED.matches(banner));
    assert!(!STARTED.matches(listening));
    assert!(!STARTED.matches(other));
}

/// speed3 S3-02 (lab live-9/live-10: the poll put every start at 355-395 ms): the real Xray is
/// ready on its own started line plus one authenticated answer, spawn -> ready within 200 ms
/// (the best of three: the first start of a file may wait for a virus scan).
#[tokio::test]
async fn xray_is_ready_right_after_its_started_line() {
    let Some(exe) = xray_exe() else { return };
    let (mut sup, _events) = supervisor(exe, None);
    let mut best = Duration::MAX;
    for _ in 0..3 {
        let ep = SlotEndpoint::allocate(&[]).unwrap();
        let started = Instant::now();
        sup.start(Slot::A, ep.clone(), launch(&ep), &CancellationToken::new())
            .await
            .unwrap();
        best = best.min(started.elapsed());
        sup.stop(Slot::A).await.unwrap();
    }
    assert!(
        best <= Duration::from_millis(200),
        "spawn -> ready {best:?}"
    );
}

/// A stand-in engine (PowerShell, no pin check) that prints `line` (if any) and lives ~6 s.
fn stand_in(line: Option<&str>) -> EngineChild {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let shell = Path::new(&root)
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");
    let print = line.map_or(String::new(), |l| format!("Write-Output '{l}'; "));
    let script = format!("{print}Start-Sleep -Seconds 6");
    EngineChild::launch(Spec {
        engine: Engine::Xray,
        exe: &shell,
        args: &["-NoProfile", "-NonInteractive", "-Command", &script],
        config: b"",
        log: None,
        marker: Some(STARTED),
        scrub: Scrubber::default(),
    })
    .unwrap()
}

/// A loopback SOCKS5 server that takes `creds` (greeting and username/password only, as the
/// readiness probe asks).
async fn socks_with(creds: Creds) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let expected = creds.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 2];
                sock.read_exact(&mut head).await?;
                let mut methods = vec![0u8; usize::from(head[1])];
                sock.read_exact(&mut methods).await?;
                sock.write_all(&[5, 2]).await?;
                let mut ver_len = [0u8; 2];
                sock.read_exact(&mut ver_len).await?;
                let mut user = vec![0u8; usize::from(ver_len[1])];
                sock.read_exact(&mut user).await?;
                let mut len = [0u8; 1];
                sock.read_exact(&mut len).await?;
                let mut pass = vec![0u8; usize::from(len[0])];
                sock.read_exact(&mut pass).await?;
                let ok = user == expected.user.as_bytes() && pass == expected.pass.as_bytes();
                sock.write_all(&[1, u8::from(!ok)]).await?;
                std::io::Result::Ok(())
            });
        }
    });
    port
}

/// S3-02 (security review): the started line alone is never readiness. With nothing that
/// answers SOCKS on the slot's port the start is refused after the poll's budget.
#[tokio::test]
async fn the_started_line_alone_is_not_ready() {
    let child = stand_in(Some(
        "2026/11/13 23:03:59.861752 [Warning] core: Xray 26.11.9 started",
    ));
    let mut seen = child.ready_watch();
    let line = tokio::time::timeout(Duration::from_secs(20), seen.wait_for(|s| *s));
    assert!(
        line.await.is_ok_and(|r| r.is_ok()),
        "the stand-in printed its line"
    );
    let free = SlotEndpoint::allocate(&[]).unwrap();
    let token = CancellationToken::new();
    let err = ready(&child, free.port(), free.creds(), &token)
        .await
        .unwrap_err();
    assert!(matches!(err, XrayError::NotReady { .. }), "{err:?}");
}

/// S3-02: an engine that never prints the line is still found ready by the poll, and the line
/// path answers right after the line when the slot's server takes the credentials.
#[tokio::test]
async fn readiness_comes_by_the_line_or_by_the_poll() {
    let creds = ports::creds();
    let port = socks_with(creds.clone()).await;
    let token = CancellationToken::new();
    let silent = stand_in(None);
    let by = ready(&silent, port, &creds, &token).await.unwrap();
    assert_eq!(by, "poll");
    let marked = stand_in(Some(
        "2026/11/13 23:03:59.861752 [Warning] core: Xray 26.11.9 started",
    ));
    let mut seen = marked.ready_watch();
    let line = tokio::time::timeout(Duration::from_secs(20), seen.wait_for(|s| *s));
    assert!(
        line.await.is_ok_and(|r| r.is_ok()),
        "the stand-in printed its line"
    );
    let by = ready(&marked, port, &creds, &token).await.unwrap();
    assert!(["line", "poll"].contains(&by), "{by}");
}
