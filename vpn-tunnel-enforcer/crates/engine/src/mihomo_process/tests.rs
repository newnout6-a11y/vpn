use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};

use super::*;
use crate::mihomo_config::{Listen, translate};
use crate::test_support::awg_samples::V1_0;
use crate::test_support::{
    TempDir, awg_profile, console_free, mihomo_endpoints, mihomo_exe, open_lab_gate,
};

/// The V1_0 sample's S1 and H1: the handshake initiation is `S1` random bytes, then the
/// 148-byte message whose type field carries `H1`.
const S1: usize = 15;
const H1: u32 = 1_020_325_451;

/// A peer that never answers: a UDP socket on 127.0.0.1 that only reads.
fn silent_peer() -> UdpSocket {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    peer
}

fn spawn_run(exe: &Path, runs: &Path, logs: Option<&Path>, peer: u16) -> MihomoProcess {
    let p = awg_profile(V1_0, &format!("127.0.0.1:{peer}"));
    let (socks, hop, controller) = mihomo_endpoints();
    let listen = Listen {
        socks: &socks,
        hop: &hop,
        controller: &controller,
    };
    let config = translate(&p, &HashMap::new(), &listen).unwrap();
    MihomoProcess::spawn(exe, runs, &config, socks, controller, logs).unwrap()
}

/// AT-12-001 (start / health / stats / stop) and AT-12-003 step 2 (no answer): the pinned mihomo
/// runs from stdin with fake keys, listens on 127.0.0.1 only, answers its controller, sends
/// AmneziaWG (junk packets, padded initiation with the H1 header) to a peer that never answers,
/// passes no traffic, and stops with an observed exit; its run dir and the secrets leave nothing.
#[tokio::test]
async fn real_mihomo_runs_on_loopback_and_never_fakes_a_tunnel() {
    let Some(exe) = mihomo_exe() else {
        eprintln!("skipped: no resources/mihomo.exe (cargo xtask engines)");
        return;
    };
    open_lab_gate();
    let (runs, logs) = (TempDir::new("mihomo-runs"), TempDir::new("mihomo-logs"));
    let peer = silent_peer();
    let peer_port = peer.local_addr().unwrap().port();
    let run = spawn_run(&exe, runs.path(), Some(logs.path()), peer_port);
    let cancel = CancellationToken::new();
    run.wait_ready(READY_TIMEOUT, &cancel).await.unwrap();

    // Listeners: every TCP listener and bound UDP socket of the process is loopback.
    let rows = vpnte_winnet::process::socket_table().unwrap();
    let own: Vec<_> = rows.iter().filter(|r| r.pid == run.pid()).collect();
    assert!(own.iter().any(|r| r.local.port() == run.socks().port()));
    for row in &own {
        let listening =
            row.remote.is_none() || row.state == Some(vpnte_winnet::process::TcpState::Listen);
        assert!(!listening || row.local.ip().is_loopback(), "{row:?}");
    }

    // Health and stats through the Clash API of the run.
    let api = ClashApi::new(run.controller()).unwrap();
    assert_eq!(api.version().await.unwrap(), "v1.19.34");
    assert!(api.connections().await.is_ok());
    assert!(api.traffic().await.is_ok());

    // A request through the tunnel: the peer never answers, so not one byte may come back.
    // mihomo confirms a SOCKS CONNECT before it dials, so only an answer proves a tunnel.
    let exchange = async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", run.socks().port())).await?;
        let target = vpnte_core::net::HostPort::new("203.0.113.80", 80).unwrap();
        socks5::handshake(&mut tcp, Some(run.socks().creds()), &target)
            .await
            .map_err(io::Error::other)?;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tcp.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
        let mut answer = [0u8; 64];
        tcp.read(&mut answer).await
    };
    let passed = tokio::time::timeout(Duration::from_secs(12), exchange).await;
    assert!(
        !matches!(passed, Ok(Ok(n)) if n > 0),
        "no handshake answer, yet bytes came back: {passed:?}"
    );

    // What reached the peer is AmneziaWG: junk packets of Jmin..=Jmax bytes, then the padded
    // initiation carrying H1.
    let mut sizes = Vec::new();
    let mut initiation = None;
    let mut buf = [0u8; 2048];
    while let Ok(n) = peer.recv(&mut buf) {
        if n == S1 + 148 {
            initiation = Some(u32::from_le_bytes(buf[S1..S1 + 4].try_into().unwrap()));
            break;
        }
        sizes.push(n);
    }
    assert!(
        sizes.len() >= 4 && sizes.iter().all(|n| (40..=70).contains(n)),
        "{sizes:?}"
    );
    assert_eq!(initiation, Some(H1), "padded initiation with the H1 header");

    let info = run.terminate(STOP_TIMEOUT).await.unwrap();
    assert!(info.user_initiated, "{info:?}");
    drop(run);
    assert_eq!(
        std::fs::read_dir(runs.path()).unwrap().count(),
        0,
        "run dir removed"
    );
    let log = std::fs::read_to_string(logs.path().join("mihomo.log")).unwrap_or_default();
    assert!(
        !log.contains("AQEBAQEBAQEBAQEB"),
        "the private key never reaches the log"
    );
}

/// AT-02-009 for the lab engine: CTRL_BREAK ends mihomo by itself (SIGINT -> shutdown), no kill.
#[tokio::test]
async fn graceful_stop_needs_no_kill() {
    let Some(exe) = mihomo_exe() else { return };
    if !console_free() {
        return;
    }
    open_lab_gate();
    let runs = TempDir::new("mihomo-stop");
    let peer = silent_peer();
    let run = spawn_run(&exe, runs.path(), None, peer.local_addr().unwrap().port());
    run.wait_ready(READY_TIMEOUT, &CancellationToken::new())
        .await
        .unwrap();
    let port = run.socks().port();
    let info = run.terminate(STOP_TIMEOUT).await.unwrap();
    assert!(info.graceful && info.user_initiated, "{info:?}");
    assert!(
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
        "port released"
    );
}

#[tokio::test]
async fn bundled_version_is_the_pin() {
    let Some(exe) = mihomo_exe() else { return };
    assert_eq!(engine_version(&exe).await.unwrap(), (1, 19, 34));
}

#[test]
fn version_and_faults_parse() {
    let v = "Mihomo Meta v1.19.34 windows amd64 with go1.26.11 Wed Nov 11 06:53:02 UTC 2026\n";
    assert_eq!(parse_version(v), Some((1, 19, 34)));
    assert_eq!(parse_version("sing-box version 1.14.4"), None);
    assert_eq!(classify_fault(["level=info msg=\"i/o timeout\""; 5]), None);
}

/// One line of mihomo's dial log for `dst` failing with `err`.
fn dial(dst: &str, err: &str) -> String {
    format!(
        "time=\"x\" level=warning msg=\"[TCP] dial awg (match Match/) 127.0.0.1:50000 --> {dst} error: {err}\""
    )
}

/// Audit mihomo-a3: only a dead hop is the server's fault. One silent site retried ten times,
/// refused ports (the refusal came back through the tunnel) and an unreachable IPv6 network are
/// per-destination errors; several sites getting nothing back, or the device failing to send to
/// the peer, are the hop.
#[test]
fn only_a_dead_hop_is_a_server_fault() {
    let classify = |lines: &[String]| classify_fault(lines.iter().map(String::as_str));
    let timeout = "dial tcp 203.0.113.9:443: i/o timeout";
    let one_site = vec![dial("blocked.example:443", timeout); 10];
    assert_eq!(classify(&one_site), None, "one silent site");
    let refused: Vec<String> = (1..=5)
        .map(|n| {
            dial(
                &format!("site{n}.example:443"),
                "connect: connection refused",
            )
        })
        .collect();
    assert_eq!(
        classify(&refused),
        None,
        "refusals came back through the tunnel"
    );
    let v6: Vec<String> = (1..=5)
        .map(|n| {
            dial(
                &format!("[2001:db8::{n}]:443"),
                "connect: network is unreachable",
            )
        })
        .collect();
    assert_eq!(classify(&v6), None, "no IPv6 in the tunnel");

    let mut sites: Vec<String> = (1..=2)
        .map(|n| dial(&format!("site{n}.example:443"), "context deadline exceeded"))
        .collect();
    assert_eq!(classify(&sites), None, "two sites");
    sites.push(dial("site3.example:443", timeout));
    let dead = Some(OutboundFault::UpstreamUnreachable);
    assert_eq!(
        classify(&sites),
        dead,
        "three unrelated sites got nothing back"
    );

    let send = "time=\"x\" level=error msg=\"[WG](awg) peer(AgIC…AgIC) - Failed to send handshake initiation: write udp4 0.0.0.0:50001->203.0.113.7:51820: wsasendto: The requested address is not valid in its context.\"";
    assert_eq!(
        classify(&vec![send.to_owned(); 2]),
        None,
        "below the threshold"
    );
    assert_eq!(
        classify(&vec![send.to_owned(); 3]),
        dead,
        "the peer is unreachable"
    );
}

/// AT-12-002: a closed gate is a refusal that names the gap (kind Permission), and a stale run
/// dir is swept at start-up.
#[test]
fn closed_gate_and_sweep() {
    let err: AppError = MihomoError::Inactive(crate::lab::LabGap::Missing).into();
    assert_eq!(err.kind, ErrorKind::Permission);
    assert_eq!(err.user_msg().key, "engine.lab.gap.missing");
    let runs = TempDir::new("mihomo-sweep");
    std::fs::create_dir_all(runs.path().join("mihomo-0123456789abcdef")).unwrap();
    std::fs::create_dir_all(runs.path().join("keep-me")).unwrap();
    sweep_homes(runs.path());
    let left: Vec<String> = std::fs::read_dir(runs.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["keep-me"]);
    for key in ["engine.lab.process.exited", "engine.lab.process.notReady"] {
        crate::test_locales::assert_localized(key);
    }
}
