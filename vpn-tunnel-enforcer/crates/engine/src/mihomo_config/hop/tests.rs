//! The hop against the real engines (skipped quietly without them): UDP passes sing-box ->
//! hop -> mihomo as UDP over TCP, and a datagram without the key reaches nobody.
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use vpnte_core::socks5;

use super::*;
use crate::mihomo_config::{Listen, translate};
use crate::mihomo_process::{MihomoProcess, READY_TIMEOUT, STOP_TIMEOUT};
use crate::singbox_process::SingBoxProcess;
use crate::test_support::awg_samples::V1_0;
use crate::test_support::{
    TempDir, awg_profile, mihomo_endpoints, mihomo_exe, open_lab_gate, singbox_exe,
};

/// A SOCKS5 UDP datagram (RFC 1928 §7) for `to` carrying `payload`.
fn socks_udp(to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let SocketAddr::V4(v4) = to else {
        unreachable!("loopback IPv4 only")
    };
    let mut d = vec![0, 0, 0, 1];
    d.extend(v4.ip().octets());
    d.extend(v4.port().to_be_bytes());
    d.extend(payload);
    d
}

/// UDP ASSOCIATE on an unauthenticated SOCKS5 listener: the control stream (keep it open) and
/// the relay address.
async fn associate(port: u16) -> (TcpStream, SocketAddr) {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socks5::negotiate(&mut tcp, None).await.unwrap();
    tcp.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..4], [5, 0, 0, 1], "associate accepted");
    let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let relay_port = u16::from_be_bytes([reply[8], reply[9]]);
    (tcp, SocketAddr::from((ip, relay_port)))
}

/// The first datagram `sock` gets within `within`. Errors are skipped: Windows reports the ICMP
/// "port unreachable" of an earlier send as a failed receive, which must not end the wait early.
async fn recv(sock: &UdpSocket, within: Duration) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + within;
    let mut buf = [0u8; 2048];
    loop {
        match tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => return Some(buf[..n].to_vec()),
            Ok(Err(_)) => continue,
            Err(_) => return None,
        }
    }
}

/// A UDP echo on 127.0.0.1 that keeps every payload it got.
async fn echo() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>) {
    let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = sock.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            log.lock().push(buf[..n].to_vec());
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    (addr, seen)
}

/// Audit mihomo-a4/a5: sing-box carries UDP to mihomo inside the keyed hop (UDP over TCP), and
/// no port of the run relays a datagram that comes without the key (mihomo's SOCKS5 UDP relay
/// checks no credentials). mihomo routes to DIRECT here so the datagrams can reach a local echo
/// (the AmneziaWG peer is a fake that never answers).
#[tokio::test]
async fn udp_passes_only_through_the_keyed_hop() {
    let (Some(mihomo), Some(singbox)) = (mihomo_exe(), singbox_exe()) else {
        eprintln!("skipped: no resources/mihomo.exe or sing-box.exe");
        return;
    };
    open_lab_gate();
    let (echo_addr, seen) = echo().await;
    let runs = TempDir::new("mihomo-hop");
    let (socks, hop, controller) = mihomo_endpoints();
    let listen = Listen {
        socks: &socks,
        hop: &hop,
        controller: &controller,
    };
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let peer = peer.local_addr().unwrap();
    let mut config = translate(
        &awg_profile(V1_0, &peer.to_string()),
        &HashMap::new(),
        &listen,
    )
    .unwrap();
    config.text = config.text.replace("[\"MATCH,awg\"]", "[\"MATCH,DIRECT\"]");
    assert!(config.text.contains("MATCH,DIRECT"));
    let ports = [socks.port(), hop.port(), controller.port];
    let run = MihomoProcess::spawn(&mihomo, runs.path(), &config, socks, controller, None);
    let run = run.unwrap();
    let cancel = CancellationToken::new();
    run.wait_ready(READY_TIMEOUT, &cancel).await.unwrap();

    // sing-box with an open SOCKS5 inbound and the hop as `proxy-out`.
    let inbound = crate::ports::alloc_port(false, &ports).unwrap();
    let Upstream::Native { fragment, udp } = hop.upstream() else {
        panic!("the hop is a native outbound")
    };
    assert!(udp.udp && udp.block_quic);
    let sb = json!({
        "log": { "level": "warn" },
        "inbounds": [{ "type": "socks", "tag": "in", "listen": "127.0.0.1",
                       "listen_port": inbound }],
        "outbounds": [fragment.outbounds()[0].clone()],
        "route": { "final": PROXY_OUT },
    });
    let sb = SingBoxProcess::spawn(&singbox, sb.to_string().as_bytes(), None).unwrap();
    socks5::wait_ready(inbound, None, Duration::from_secs(10), &cancel)
        .await
        .unwrap();

    // Through sing-box and the hop the echo answers.
    let (_control, relay) = associate(inbound).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let datagram = socks_udp(echo_addr, b"through-the-hop");
    client.send_to(&datagram, relay).await.unwrap();
    let answer = recv(&client, Duration::from_secs(5)).await;
    assert!(
        answer.is_some_and(|a| a.ends_with(b"through-the-hop")),
        "UDP through the hop"
    );

    // Without the key nothing goes anywhere: not through the SOCKS port, not through the hop.
    let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for port in [ports[0], ports[1]] {
        let to = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let _ = stranger.send_to(&socks_udp(echo_addr, b"no-key"), to).await;
    }
    assert_eq!(recv(&stranger, Duration::from_secs(1)).await, None);
    assert!(
        !seen.lock().iter().any(|d| d == b"no-key"),
        "a datagram without the key was relayed"
    );

    sb.terminate(STOP_TIMEOUT).await.unwrap();
    run.terminate(STOP_TIMEOUT).await.unwrap();
}
