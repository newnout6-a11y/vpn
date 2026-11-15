//! The slot inbound's UDP against the real pinned Xray (skipped quietly without it): what an
//! unauthenticated local program can and cannot push through a slot.
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Creds;
use vpnte_core::socks5;

use crate::slot::{Slot, SlotEndpoint};
use crate::test_support::xray_exe;
use crate::xray_config::{PROXY_TAG, ProxyGraph, build_config};
use crate::xray_process::{SlotLaunch, XraySupervisor};

/// A SOCKS5 UDP datagram (RFC 1928 §7) for the IPv4 `to` carrying `payload`.
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

/// UDP ASSOCIATE as sing-box sends it (0.0.0.0:0): the control stream (keep it open) and the
/// relay address.
async fn associate(port: u16, creds: &Creds) -> (TcpStream, SocketAddr) {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    socks5::negotiate(&mut tcp, Some(creds)).await.unwrap();
    tcp.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[..4], [5, 0, 0, 1], "associate accepted");
    let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    (
        tcp,
        SocketAddr::from((ip, u16::from_be_bytes([reply[8], reply[9]]))),
    )
}

/// The first datagram `sock` gets within `within`. Errors are skipped: Windows reports the ICMP
/// "port unreachable" of an earlier send as a failed receive.
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

/// p-left 2 (Xray 26.11.9, proxy/socks): the slot listens for UDP nowhere by itself; every UDP
/// ASSOCIATE needs the password and gets its own relay socket, which serves only the sender of
/// its first datagram. So a local program without the credentials relays nothing: not through
/// the slot port, not through a live association of the slot's client.
#[tokio::test]
async fn slot_udp_serves_only_the_authenticated_client() {
    let Some(exe) = xray_exe() else {
        eprintln!("skipped: no resources/xray.exe");
        return;
    };
    let (echo_addr, seen) = echo().await;
    let ep = SlotEndpoint::allocate(&[]).unwrap();
    let graph = ProxyGraph::Translated(json!({"tag": PROXY_TAG, "protocol": "freedom"}));
    let launch = SlotLaunch {
        config: build_config(&graph, &ep).to_string().into_bytes(),
        dial_target: None,
    };
    let (tx, _events) = mpsc::channel(16);
    let mut sup = XraySupervisor::new(exe, None, tx);
    let cancel = CancellationToken::new();
    sup.start(Slot::A, ep.clone(), launch, &cancel)
        .await
        .unwrap();

    let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let slot_port = SocketAddr::from((Ipv4Addr::LOCALHOST, ep.port()));
    let _ = stranger
        .send_to(&socks_udp(echo_addr, b"to-the-slot-port"), slot_port)
        .await;
    let mut anonymous = TcpStream::connect(slot_port).await.unwrap();
    assert!(socks5::negotiate(&mut anonymous, None).await.is_err());

    let (_control, relay) = associate(ep.port(), ep.creds()).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    for payload in [&b"client-1"[..], b"client-2"] {
        client
            .send_to(&socks_udp(echo_addr, payload), relay)
            .await
            .unwrap();
        let answer = recv(&client, Duration::from_secs(5)).await;
        assert!(
            answer.is_some_and(|a| a.ends_with(payload)),
            "UDP of the client"
        );
        if payload == b"client-1" {
            // The association is bound to the client now: a stranger's datagram goes nowhere.
            let _ = stranger
                .send_to(&socks_udp(echo_addr, b"stranger"), relay)
                .await;
            assert_eq!(recv(&stranger, Duration::from_secs(1)).await, None);
        }
    }
    let seen = seen.lock().clone();
    assert!(
        !seen
            .iter()
            .any(|d| d == b"stranger" || d == b"to-the-slot-port"),
        "a datagram without the credentials was relayed"
    );
    sup.stop_all().await.unwrap();
}
