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
/// no SYNs at all (no SOCKS rung, and the TCP half of `both` stays idle for them).
#[test]
fn ladder_plan() {
    assert_eq!(plan(true, false), [Step::DirectSocks, Step::Physical]);
    assert_eq!(plan(true, true), [Step::Physical]);
    assert_eq!(plan(false, false), [Step::Physical, Step::Unbound]);
    assert_eq!(plan(false, true), [Step::Physical, Step::Unbound]);
    for udp in [true, false] {
        assert!(!plan(true, udp).contains(&Step::Unbound));
    }
}

/// A UDP-only target gets no SYN: a loopback listener sees no connection.
#[tokio::test]
async fn udp_only_targets_get_no_syn() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tcp, _) = both(None, addr, true).await;
    assert_eq!(tcp, None);
    let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(accepted.is_err(), "no connection for a UDP-only target");
}

async fn after<T>(ms: u64, value: T) -> T {
    tokio::time::sleep(Duration::from_millis(ms)).await;
    value
}

fn sample(ms: u32, path: PingPath) -> Option<PingSample> {
    Some(PingSample { ms, path })
}

/// `elapsed` is `ms` of virtual time (the timer wheel rounds to whole milliseconds).
fn assert_took(elapsed: Duration, ms: u64) {
    let want = Duration::from_millis(ms);
    assert!(
        elapsed >= want && elapsed < want + Duration::from_millis(5),
        "{elapsed:?}"
    );
}

/// ops6 (virtual time): a dead server costs the physical probe's 1.8 s plus the 0.4 s head start,
/// not the sum of the steps (physical 1.8 + unbound TCP 1.8 + unbound ICMP 1.5 = 5.1 s before); a
/// physical answer keeps the unbound probe off and wins over an earlier unbound one; an empty
/// physical step hands over at once.
#[tokio::test(start_paused = true)]
async fn the_unbound_probe_races_the_physical_one() {
    let t = Instant::now();
    assert_eq!(race(after(1800, None), || after(1800, None)).await, None);
    assert_took(t.elapsed(), 2200);

    let (tcp, icmp, late) = (
        sample(40, PingPath::Tcp),
        sample(90, PingPath::Icmp),
        sample(20, PingPath::Tcp),
    );
    let started = std::cell::Cell::new(false);
    let t = Instant::now();
    let got = race(after(40, tcp), || {
        started.set(true);
        after(1, None)
    })
    .await;
    assert_eq!((got, started.get()), (tcp, false));
    assert_took(t.elapsed(), 40);

    let t = Instant::now();
    assert_eq!(race(after(1500, icmp), || after(10, late)).await, icmp);
    assert_took(t.elapsed(), 1500);
    let t = Instant::now();
    assert_eq!(race(after(1800, None), || after(10, late)).await, late);
    assert_took(t.elapsed(), 1800);
    let t = Instant::now();
    assert_eq!(race(after(0, None), || after(100, late)).await, late);
    assert_took(t.elapsed(), 100);
}

/// ops6 (virtual time): the physical sources run at once; the first TCP answer wins without
/// waiting for a silent source (one after another it took 1.5 s and gave the first source's
/// ICMP), ICMP only when no source has TCP.
#[tokio::test(start_paused = true)]
async fn the_first_tcp_answer_of_any_source_wins() {
    let t = Instant::now();
    let got = pick([after(1500, (None, Some(30))), after(25, (Some(25), None))]).await;
    assert_eq!(got, sample(25, PingPath::Tcp));
    assert_took(t.elapsed(), 25);
    let t = Instant::now();
    let got = pick([after(1800, (None, None)), after(60, (None, Some(60)))]).await;
    assert_eq!(got, sample(60, PingPath::Icmp));
    assert_took(t.elapsed(), 1800);
    let none: [std::future::Ready<(Option<u32>, Option<u32>)>; 0] = [];
    assert_eq!(pick(none).await, None);
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
