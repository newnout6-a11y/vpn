//! Ping ladder tests (serverPickerProbe.test.ts, serverPickerPingPoisoning.test.ts; servers §7
//! vectors 20-24).
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{Creds, Loopback};
use vpnte_core::net::Host as NetHost;
use vpnte_winnet::icmp::{EchoReply, EchoStatus};

use super::*;

fn reply(status: EchoStatus, from: &str, rtt: Option<u32>) -> EchoReply {
    EchoReply {
        status,
        from: Some(from.parse().unwrap()),
        rtt_ms: rtt,
    }
}

/// AT-00-003 vector 20: median of the successful samples.
#[test]
fn median_vectors() {
    assert_eq!(median(&[None, Some(64)]), Some(64));
    assert_eq!(median(&[Some(115), Some(24), Some(25)]), Some(25));
    assert_eq!(median(&[Some(40), Some(44)]), Some(42));
    assert_eq!(median(&[None, None]), None);
    assert_eq!(median(&[]), None);
    assert_eq!(median(&[Some(41), Some(44)]), Some(43));
}

/// Vector 21: the host gate (no shell any more, but garbage never reaches DNS or a socket).
#[test]
fn host_gate() {
    for ok in [
        "8.8.8.8",
        "192.168.0.1",
        "sub.feodorn.com",
        "a-b.example.org",
        "2001:db8::1",
        "::1",
        "8.8.8.8 ",
    ] {
        assert!(NetHost::parse(ok).is_ok(), "{ok}");
    }
    let long = "a".repeat(300);
    for bad in [
        "8.8.8.8 & calc",
        "8.8.8.8 && shutdown /s",
        "8.8.8.8 | whoami",
        "$(calc)",
        "`calc`",
        "a.com; rm -rf /",
        "a.com\nb.com",
        "",
        "  ",
        "8 8",
        &long,
    ] {
        assert!(NetHost::parse(bad).is_err(), "{bad:?}");
    }
}

/// Vector 22: ICMP plausibility on `ICMP_ECHO_REPLY` data.
#[test]
fn icmp_plausibility() {
    let remote: IpAddr = "46.243.142.239".parse().unwrap();
    assert_eq!(
        icmp_rtt(
            &reply(EchoStatus::Success, "46.243.142.239", Some(53)),
            remote
        ),
        Some(53)
    );
    assert_eq!(
        icmp_rtt(
            &reply(EchoStatus::Success, "46.243.142.239", Some(0)),
            remote
        ),
        None
    );
    let local: IpAddr = Ipv4Addr::LOCALHOST.into();
    assert_eq!(
        icmp_rtt(&reply(EchoStatus::Success, "127.0.0.1", Some(0)), local),
        Some(1)
    );
    assert_eq!(
        icmp_rtt(&reply(EchoStatus::Unreachable, "192.168.0.1", None), remote),
        None
    );
    let timeout = EchoReply {
        status: EchoStatus::TimedOut,
        from: None,
        rtt_ms: None,
    };
    assert_eq!(icmp_rtt(&timeout, remote), None);
    assert_eq!(
        icmp_rtt(
            &reply(EchoStatus::Success, "46.243.142.239", Some(41)),
            remote
        ),
        Some(41)
    );
    assert_eq!(
        icmp_rtt(
            &reply(EchoStatus::Success, "46.243.142.239", Some(3)),
            remote
        ),
        None
    );
    assert_eq!(
        icmp_rtt(
            &reply(EchoStatus::Success, "46.243.142.1", Some(40)),
            remote
        ),
        None
    );
}

/// The 3 ms anti-spoofing gate and the loopback exemption.
#[test]
fn plausibility_gate() {
    assert!(!plausible(3, false) && plausible(4, false) && plausible(1, true));
    for host in [
        "127.0.0.1",
        "127.8.9.10",
        "::1",
        "[::1]",
        "localhost",
        "LocalHost",
    ] {
        assert!(is_loopback_host(host), "{host}");
    }
    for host in ["8.8.8.8", "localhost.example.com", "10.0.0.1"] {
        assert!(!is_loopback_host(host), "{host}");
    }
}

/// Vector 24: while the tunnel runs a ping never uses an unbound socket; UDP-only protocols get
/// no SYNs at all.
#[test]
fn ladder_plan() {
    assert_eq!(plan(true, false), [Step::DirectSocks, Step::Physical]);
    assert_eq!(plan(true, true), [Step::Physical]);
    assert_eq!(
        plan(false, false),
        [Step::Physical, Step::UnboundTcp, Step::UnboundIcmp]
    );
    assert_eq!(plan(false, true), [Step::Physical, Step::UnboundIcmp]);
    for running in [true, false] {
        for udp in [true, false] {
            let steps = plan(running, udp);
            if running {
                assert!(!steps.contains(&Step::UnboundTcp) && !steps.contains(&Step::UnboundIcmp));
            }
            if udp {
                assert!(!steps.contains(&Step::DirectSocks) && !steps.contains(&Step::UnboundTcp));
            }
        }
    }
}

/// UDP transports are ICMP-only targets; IPv6 servers stay unbracketed.
#[test]
fn targets_of_profiles() {
    let vless: vpnte_profiles::model::Profile =
        vpnte_profiles::uri::parse_uri("vless://11111111-2222-4333-8444-555555555555@[2001:db8::7]:443?security=tls&sni=example.com#v6")
            .unwrap();
    let t = PingTarget::of(&vless);
    assert_eq!(
        (t.host.as_str(), t.port, t.udp_only),
        ("2001:db8::7", 443, false)
    );
    let hy2 = vpnte_profiles::uri::parse_uri(
        "hysteria2://fake-pass@hy.example.com:8443?sni=hy.example.com#hy",
    )
    .unwrap();
    let t = PingTarget::of(&hy2);
    assert_eq!(
        (t.host.as_str(), t.port, t.udp_only),
        ("hy.example.com", 8443, true)
    );
}

/// A fake `mixed-direct-in` that answers every CONNECT at once (as a TSPU spoof would).
async fn instant_socks(creds: &Creds) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (user, pass) = (creds.user.clone(), creds.pass.clone());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let (user, pass) = (user.clone(), pass.clone());
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(&[5, 2]).await;
                let n = s.read(&mut buf).await.unwrap_or(0);
                let expected = [
                    &[1, user.len() as u8][..],
                    user.as_bytes(),
                    &[pass.len() as u8],
                    pass.as_bytes(),
                ]
                .concat();
                let ok = buf[..n] == expected[..];
                let _ = s.write_all(&[1, if ok { 0 } else { 1 }]).await;
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80]).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });
    port
}

/// Vector 24 (new): a ≤3 ms SOCKS-path round trip to a remote host is rejected; loopback passes.
#[tokio::test]
async fn direct_socks_applies_the_gate() {
    let creds = Creds {
        user: "direct-user".into(),
        pass: "fake-direct-pass".into(),
    };
    let direct = Loopback {
        port: instant_socks(&creds).await,
        creds: Some(creds),
    };
    let remote = PingTarget {
        host: "203.0.113.5".into(),
        port: 443,
        udp_only: false,
    };
    assert_eq!(direct_socks(&direct, &remote, false).await, None);
    let local = PingTarget {
        host: "127.0.0.1".into(),
        port: 443,
        udp_only: false,
    };
    let sample = direct_socks(&direct, &local, true).await.unwrap();
    assert_eq!(sample.path, PingPath::DirectOutSocks);
    assert!(sample.ms >= 1);
}

/// Tunnel down: a loopback listener is reached by TCP (bound or unbound), ICMP never needed.
#[tokio::test]
async fn loopback_target_is_reached_by_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let target = PingTarget {
        host: "127.0.0.1".into(),
        port,
        udp_only: false,
    };
    let sample = ping(&target, &NetPath::default(), &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(sample.path, PingPath::Tcp);
}

/// Cancellation ends a ping at once; invalid targets are `None` without I/O.
#[tokio::test]
async fn cancel_and_invalid_targets() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let target = PingTarget {
        host: "127.0.0.1".into(),
        port: 9,
        udp_only: false,
    };
    assert_eq!(ping(&target, &NetPath::default(), &cancel).await, None);
    let empty = PingTarget {
        host: String::new(),
        port: 443,
        udp_only: false,
    };
    assert_eq!(
        ping(&empty, &NetPath::default(), &CancellationToken::new()).await,
        None
    );
}

/// `ping_all` yields one result per target.
#[tokio::test]
async fn ping_all_yields_every_row() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let targets: Vec<(usize, PingTarget)> = (0..8)
        .map(|i| {
            (
                i,
                PingTarget {
                    host: "127.0.0.1".into(),
                    port,
                    udp_only: false,
                },
            )
        })
        .collect();
    let mut rows: Vec<(usize, Option<PingSample>)> =
        ping_all(targets, NetPath::default(), CancellationToken::new())
            .collect()
            .await;
    rows.sort_by_key(|r| r.0);
    assert_eq!(rows.len(), 8);
    assert!(rows.iter().all(|(_, s)| s.is_some()));
}
