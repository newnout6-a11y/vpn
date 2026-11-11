//! Pre-resolution (xray-engine spec §3.4): DNS wire format, the sinkhole filter, and the whole
//! plan against a fake loopback DNS server (the sing-box `dns-bootstrap-in` stand-in).
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind};

use crate::xray_config::resolve::{dialable, parse_answer, query};
use crate::xray_config::{ResolveFault, ResolvePath, resolve_hosts};

/// An answer to `q` with the given records (`(type, rdata)`, owner name compressed to the
/// question) and response code.
fn answer(q: &[u8], records: &[(u16, &[u8])], rcode: u8) -> Vec<u8> {
    let mut a = q.to_vec();
    a[2] = 0x81;
    a[3] = 0x80 | rcode;
    a[6..8].copy_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
    for (rtype, data) in records {
        a.extend_from_slice(&[0xc0, 12]);
        a.extend_from_slice(&rtype.to_be_bytes());
        a.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        a.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        a.extend_from_slice(data);
    }
    a
}

#[test]
fn query_and_answer_wire_format() {
    let q = query("nl.example.", 1, 0x1234).unwrap();
    let mut want = vec![
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 2, b'n', b'l', 7,
    ];
    want.extend_from_slice(b"example");
    want.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(q, want);
    assert!(query("a..example", 1, 1).is_none());
    assert!(query(&format!("{}.example", "x".repeat(64)), 1, 1).is_none());

    // A CNAME before the A record; AAAA data in an A answer is ignored.
    let cname: &[u8] = &[3, b'c', b'd', b'n', 0xc0, 12];
    let a = answer(&q, &[(5, cname), (1, &[203, 0, 113, 7]), (28, &[0; 16])], 0);
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    assert_eq!(parse_answer(&a, 0x1234, 1), Some(vec![ip]));
    assert_eq!(parse_answer(&a, 0x1235, 1), None, "another id");
    assert_eq!(parse_answer(&q, 0x1234, 1), None, "a query, not an answer");
    assert_eq!(
        parse_answer(&a[..a.len() - 2], 0x1234, 1),
        None,
        "truncated"
    );
    let nx = answer(&q, &[], 3);
    assert_eq!(parse_answer(&nx, 0x1234, 1), Some(Vec::new()));
    let q6 = query("nl.example", 28, 7).unwrap();
    let v6: IpAddr = "2001:db8::7".parse().unwrap();
    let IpAddr::V6(bytes) = v6 else {
        unreachable!()
    };
    let a6 = answer(&q6, &[(28, &bytes.octets())], 0);
    assert_eq!(parse_answer(&a6, 7, 28), Some(vec![v6]));
}

/// Block-page answers are refused; private / CGNAT servers are legitimate.
#[test]
fn dialable_addresses() {
    for bad in [
        "0.0.0.0",
        "0.1.2.3",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
    ] {
        assert!(!dialable(bad.parse().unwrap()), "{bad}");
    }
    for good in [
        "1.2.3.4",
        "10.0.0.1",
        "100.64.0.1",
        "192.168.1.10",
        "2001:db8::1",
        "::ffff:203.0.113.7",
    ] {
        assert!(dialable(good.parse().unwrap()), "{good}");
    }
}

/// A fake resolver on loopback: `a.example` -> 203.0.113.7, `fallback.invalid` -> 203.0.113.9,
/// `v6.example` -> AAAA only, `blocked.example` -> 127.0.0.1, no data for other names, and
/// NXDOMAIN for names containing `missing`.
async fn fake_dns() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let q = &buf[..n];
            let name = String::from_utf8_lossy(&q[13..n - 5]).to_string();
            let qtype = u16::from_be_bytes([q[n - 4], q[n - 3]]);
            let reply = match (name.as_str(), qtype) {
                ("a\u{7}example", 1) => answer(q, &[(1, &[203, 0, 113, 7])], 0),
                ("v6\u{7}example", 28) => answer(
                    q,
                    &[(
                        28,
                        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6],
                    )],
                    0,
                ),
                ("blocked\u{7}example", 1) => answer(q, &[(1, &[127, 0, 0, 1])], 0),
                ("fallback\u{7}invalid", 1) => answer(q, &[(1, &[203, 0, 113, 9])], 0),
                (_, 1 | 28) if !name.contains("missing") => answer(q, &[], 0),
                _ => answer(q, &[], 3),
            };
            let _ = sock.send_to(&reply, peer).await;
        }
    });
    addr
}

/// TUN up: every host through `dns-bootstrap-in` (A, else AAAA); literals pass through.
#[tokio::test]
async fn via_sing_box_resolves_every_host() {
    let path = ResolvePath::ViaSingBox(fake_dns().await);
    let cancel = CancellationToken::new();
    let hosts = [
        "a.example".to_owned(),
        "v6.example".into(),
        "192.0.2.1".into(),
    ];
    let r = resolve_hosts(&hosts, path, &cancel).await.unwrap();
    assert_eq!(r.addrs.len(), 3);
    assert_eq!(
        r.addrs["a.example"],
        "203.0.113.7".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        r.addrs["v6.example"],
        "2001:db8::6".parse::<IpAddr>().unwrap()
    );
    assert_eq!(r.addrs["192.0.2.1"], "192.0.2.1".parse::<IpAddr>().unwrap());
    assert!(!r.bootstrap_used && r.warning().is_none());
}

/// One failure fails the plan (no partial map): NXDOMAIN, a block-page answer, a block-page
/// literal; cancellation wins.
#[tokio::test]
async fn failures_fail_the_whole_plan() {
    let path = ResolvePath::ViaSingBox(fake_dns().await);
    let cancel = CancellationToken::new();
    let plan = |hosts: &[&str]| hosts.iter().map(|h| (*h).to_owned()).collect::<Vec<_>>();
    let missing = resolve_hosts(&plan(&["a.example", "missing.example"]), path, &cancel).await;
    assert_eq!(missing, Err(ResolveFault::Failed));
    let blocked = resolve_hosts(&plan(&["blocked.example"]), path, &cancel).await;
    assert_eq!(blocked, Err(ResolveFault::Sinkhole));
    let literal = resolve_hosts(&plan(&["127.0.0.1"]), path, &cancel).await;
    assert_eq!(literal, Err(ResolveFault::Sinkhole));
    cancel.cancel();
    let cancelled = resolve_hosts(&plan(&["a.example"]), path, &cancel).await;
    assert_eq!(cancelled, Err(ResolveFault::Cancelled));

    let err = AppError::from(ResolveFault::Sinkhole);
    assert_eq!(
        (err.kind, err.user_msg().key.as_ref()),
        (ErrorKind::Network, "engine.xray.resolve.sinkhole")
    );
    assert_eq!(
        AppError::from(ResolveFault::Cancelled).kind,
        ErrorKind::Cancelled
    );
}

/// Spec §7 "Endpoint plan": at most 4 lookups in flight; a cancelled plan returns at once and
/// admits nothing more. The fake resolver answers only after 150 ms without a new query, so it
/// sees each wave of concurrent lookups whole.
#[tokio::test]
async fn at_most_four_lookups_in_flight() {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = sock.local_addr().unwrap();
    let (waves_tx, mut waves) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut held: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_millis(150), sock.recv_from(&mut buf)).await {
                Ok(Ok((n, peer))) => held.push((buf[..n].to_vec(), peer)),
                Ok(Err(_)) => return,
                Err(_) if held.is_empty() => {}
                Err(_) => {
                    let _ = waves_tx.send(held.len());
                    for (q, peer) in held.drain(..) {
                        let a = answer(&q, &[(1, &[203, 0, 113, 7])], 0);
                        let _ = sock.send_to(&a, peer).await;
                    }
                }
            }
        }
    });
    let hosts: Vec<String> = (1..=6).map(|i| format!("h{i}.example")).collect();
    let never = CancellationToken::new();
    let r = resolve_hosts(&hosts, ResolvePath::ViaSingBox(server), &never).await;
    assert_eq!(r.map(|r| r.addrs.len()), Ok(6));
    assert_eq!((waves.recv().await, waves.recv().await), (Some(4), Some(2)));

    // Nobody answers: cancellation wins at once, and only the first wave was ever sent.
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        trigger.cancel();
    });
    let started = Instant::now();
    let path = ResolvePath::ViaSingBox(silent.local_addr().unwrap());
    assert_eq!(
        resolve_hosts(&hosts, path, &cancel).await,
        Err(ResolveFault::Cancelled)
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let mut buf = [0u8; 512];
    let mut sent = 0;
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(50), silent.recv_from(&mut buf)).await
    {
        sent += 1;
    }
    assert_eq!(sent, 4);
}

/// TUN down: a name the system resolver cannot answer (reserved `.invalid` TLD) is retried at
/// the bootstrap resolver, and the result says so.
#[tokio::test]
async fn system_failure_retries_at_the_bootstrap_resolver() {
    let path = ResolvePath::System {
        bootstrap: fake_dns().await,
    };
    let hosts = ["fallback.invalid".to_owned()];
    let cancel = CancellationToken::new();
    // `.invalid` never exists in public DNS (RFC 2606), so the system lookup fails.
    let r = resolve_hosts(&hosts, path, &cancel).await.unwrap();
    assert_eq!(
        r.addrs["fallback.invalid"],
        "203.0.113.9".parse::<IpAddr>().unwrap()
    );
    assert!(r.bootstrap_used);
    assert_eq!(
        r.warning().map(|m| m.key.into_owned()),
        Some("engine.xray.resolve.bootstrapFallback".to_owned())
    );
    let gone = ["missing.invalid".to_owned()];
    assert_eq!(
        resolve_hosts(&gone, path, &cancel).await,
        Err(ResolveFault::Failed)
    );
}
