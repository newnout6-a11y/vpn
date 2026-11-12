//! The app side of the automatic choice: the transfer verdicts by raw bytes (over a loopback far
//! side), the VPN-only traffic meter, what traffic does in each live state, the provider's word.
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use vpnte_automation::autopick::{Confirmation, Exposure, LaunchPick, ProviderWord};
use vpnte_base::types::KillSwitchLevel;
use vpnte_engine::clash_api::{ClashEndpoint, Connection};
use vpnte_probes::discipline::Limits;
use vpnte_profiles::text::AutoconnectPick;
use vpnte_tunnel::fsm::TunnelState;

use super::confirm::{Counted, download, measure};
use super::host::word;
use super::meter::Meter;
use super::provide::traffic_exposure;

/// What the far side does after the request: `head`, then `sent` body bytes, then silence (a
/// freeze sends no FIN / RST) or, with `close`, a reset of the exchange.
struct FarSide {
    head: String,
    sent: usize,
    close: bool,
}

impl FarSide {
    /// A 200 answer whose head is padded to `pad` bytes: the inner TLS handshake and the head
    /// come before the body through a real session, and count as raw bytes there.
    fn ok(pad: usize, sent: usize) -> Self {
        let filler = "x".repeat(pad);
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: 65536\r\nX-Pad: {filler}\r\n\r\n");
        Self {
            head,
            sent,
            close: false,
        }
    }
}

/// A loopback far side for one exchange; its address.
async fn far_side(plan: FarSide) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = sock.read(&mut request).await;
        let _ = sock.write_all(plan.head.as_bytes()).await;
        let _ = sock.write_all(&vec![b'x'; plan.sent]).await;
        if !plan.close {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });
    addr
}

fn quick() -> Limits {
    Limits {
        first_byte: Duration::from_secs(2),
        gap: Duration::from_millis(300),
        deadline: Duration::from_secs(5),
    }
}

/// One exchange with the far side, counted as the session's check counts it.
async fn verdict(plan: FarSide) -> Confirmation {
    let addr = far_side(plan).await;
    let raw = Arc::new(AtomicU64::new(0));
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut counted = Counted {
        inner: stream,
        raw: raw.clone(),
    };
    let cancel = CancellationToken::new();
    measure(download(&mut counted), &raw, quick(), &cancel).await
}

/// RU item 7 with review fixes a6/b12: the freeze band is raw bytes (the handshake and the head
/// count), a transfer that moved data is never "nothing came back", a whole one is a false alarm.
#[tokio::test]
async fn the_transfer_is_judged_by_raw_bytes_like_the_probes() {
    // 6 KiB before the body + 8 KiB of body: frozen at 14 KiB raw, though under 12 KiB of body.
    assert_eq!(
        verdict(FarSide::ok(6 * 1024, 8 * 1024)).await,
        Confirmation::Frozen
    );
    // Data moved, then stopped outside the band: inconclusive, never offline.
    let moved = verdict(FarSide::ok(0, 40 * 1024)).await;
    assert_eq!(moved, Confirmation::Inconclusive);
    // An answer, then the exchange ended early: the path carries data, the volume is unproven.
    let reset = FarSide {
        close: true,
        ..FarSide::ok(0, 2048)
    };
    assert_eq!(verdict(reset).await, Confirmation::Inconclusive);
    let refused = FarSide {
        head: "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n".into(),
        sent: 0,
        close: true,
    };
    assert_eq!(verdict(refused).await, Confirmation::Inconclusive);
    let nothing = FarSide {
        head: String::new(),
        sent: 0,
        close: false,
    };
    assert_eq!(verdict(nothing).await, Confirmation::NoTraffic);
    assert_eq!(
        verdict(FarSide::ok(0, 64 * 1024)).await,
        Confirmation::Passed
    );
}

fn flow(id: &str, up: u64, down: u64, out: &str) -> Connection {
    Connection {
        id: id.into(),
        upload: up,
        download: down,
        chains: vec![out.into()],
        ..Connection::default()
    }
}

/// Review fix a11: only flows through the server count (a direct-routed download hides
/// nothing); a flow that closed keeps what it carried; a new engine run starts from zero.
#[test]
fn the_meter_counts_only_traffic_through_the_server() {
    let run = ClashEndpoint {
        port: 9090,
        secret: "a".repeat(32),
    };
    let mut meter = Meter::default();
    let first = [
        flow("v", 100, 10, "proxy-out"),
        flow("d", 9, 90_000, "direct-out"),
    ];
    assert_eq!(meter.add(&run, &first), (100, 10));
    let later = [
        flow("v", 300, 20, "proxy-out"),
        flow("w", 50, 5, "proxy-out"),
    ];
    assert_eq!(meter.add(&run, &later), (350, 25));
    assert_eq!(
        meter.add(&run, &[]),
        (350, 25),
        "closed flows keep their bytes"
    );
    let next = ClashEndpoint {
        port: 9091,
        secret: "b".repeat(32),
    };
    assert_eq!(meter.add(&next, &[flow("v", 7, 1, "proxy-out")]), (7, 1));
}

/// Review fixes a8/b7/b10: what traffic does follows the live state, the capture and the
/// kill-switch level; with the kill switch off and the session gone it goes direct.
#[test]
fn what_traffic_does_in_each_live_state() {
    use KillSwitchLevel::{Off, Standard};
    use TunnelState as S;
    let cases = [
        (S::Disconnected, false, Standard, Exposure::Direct),
        (S::Unknown, false, Off, Exposure::Direct),
        (S::Error, true, Off, Exposure::Direct),
        (S::Unknown, false, Standard, Exposure::Unknown),
        (S::Blocked, false, Standard, Exposure::Blocked),
        (S::Blocked, true, Standard, Exposure::ProxyBlocked),
        (S::Connected, false, Off, Exposure::Tunnel),
        (S::Connected, true, Standard, Exposure::ProxyTunnel),
    ];
    for (state, proxy, level, want) in cases {
        let got = traffic_exposure(state, proxy, level);
        assert_eq!(got, want, "{state:?} proxy={proxy} {level:?}");
    }
}

#[test]
fn the_providers_autoconnect_and_its_type() {
    assert_eq!(word(None, Some(AutoconnectPick::Random)), None);
    assert_eq!(word(Some(false), None), Some(ProviderWord::Off));
    assert_eq!(
        word(Some(true), None),
        Some(ProviderWord::On(LaunchPick::LastUsed))
    );
    assert_eq!(
        word(Some(true), Some(AutoconnectPick::LowestDelay)),
        Some(ProviderWord::On(LaunchPick::LowestDelay))
    );
}
