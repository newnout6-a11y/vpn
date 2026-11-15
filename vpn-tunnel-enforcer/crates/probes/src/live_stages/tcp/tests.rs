use std::sync::atomic::AtomicU32;

use super::*;

/// AT-05-001: basic latency against a local accept-and-close server (§7.1).
#[tokio::test]
async fn latency_against_local_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            drop(sock);
        }
    });
    let cancel = CancellationToken::new();
    let (reach, stats) = sample_latency(addr, false, &ProbePath::Os, &cancel).await;
    assert_eq!(reach.timed.status, TimedStatus::Ok);
    assert!(reach.tcp_reachable);
    assert_eq!(reach.port, addr.port());
    let stats = stats.unwrap();
    assert_eq!(stats.samples.len(), 5);
    assert_eq!(stats.loss, 0.0);
    assert_eq!(stats.samples_attempted, 5);
    assert_eq!(stats.route, Some(ProbeRoute::Os));
}

/// AT-05-001: a refusing server is tried exactly 5 times in basic mode (§7.1).
#[tokio::test]
async fn refused_connects_are_counted() {
    let calls = AtomicU32::new(0);
    let cancel = CancellationToken::new();
    let (reach, stats) = sample_with(443, false, ProbeRoute::Os, &cancel, |_| {
        calls.fetch_add(1, Ordering::Relaxed);
        async { Err::<u64, _>("ECONNREFUSED".to_owned()) }
    })
    .await;
    assert_eq!(calls.load(Ordering::Relaxed), 5);
    assert_eq!(reach.timed.status, TimedStatus::Error);
    assert_eq!(reach.timed.error.as_deref(), Some("ECONNREFUSED"));
    assert!(!reach.tcp_reachable);
    assert!(stats.is_none());
}

/// AT-00-003: RTT is the connect time (§7.7); extended takes 10 samples.
#[tokio::test]
async fn samples_are_connect_times() {
    let cancel = CancellationToken::new();
    let (_, stats) = sample_with(443, true, ProbeRoute::Physical, &cancel, |_| async {
        Ok(10)
    })
    .await;
    let stats = stats.unwrap();
    assert_eq!(stats.samples, vec![10; 10]);
    assert_eq!((stats.avg, stats.median, stats.jitter), (10, 10, 0));
    assert_eq!(stats.route, Some(ProbeRoute::Physical));
}

/// AT-00-003: a cancelled stage sends nothing and reads `skipped`.
#[tokio::test]
async fn pre_cancelled_latency_is_skipped() {
    let cancel = CancellationToken::new();
    cancel.cancel();
    let calls = AtomicU32::new(0);
    let (reach, stats) = sample_with(443, false, ProbeRoute::Os, &cancel, |_| {
        calls.fetch_add(1, Ordering::Relaxed);
        async { Ok(1) }
    })
    .await;
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert_eq!(reach.timed.status, TimedStatus::Skipped);
    assert_eq!(reach.timed.error.as_deref(), Some(CANCELLED));
    assert!(stats.is_none());
}

#[test]
fn statistics() {
    let s = latency_stats(vec![450, 200, 310], 4).unwrap();
    assert_eq!((s.min, s.avg, s.median, s.max), (200, 320, 310, 450));
    assert_eq!(s.samples, vec![200, 310, 450]);
    assert_eq!(s.loss, 0.25);
    assert_eq!(s.jitter, 102);
    let even = latency_stats(vec![10, 11, 20, 21], 4).unwrap();
    assert_eq!((even.median, even.avg, even.loss), (16, 16, 0.0));
    let third = latency_stats(vec![5, 5], 3).unwrap();
    assert_eq!(third.loss, 0.33);
    assert!(latency_stats(Vec::new(), 5).is_none());
}

/// AT-05-001: port lists and states (§3.7, §7.1).
#[test]
fn port_lists_and_states() {
    assert_eq!(ports_to_scan(8443, false), vec![8443, 443]);
    assert_eq!(ports_to_scan(443, false), vec![443]);
    let ext = ports_to_scan(443, true);
    assert_eq!(ext, RESTRICTED_PORTS.to_vec());
    assert_eq!(ports_to_scan(9000, true).len(), 9);
    assert_eq!(port_state(&Ok(())), PortState::Open);
    assert_eq!(port_state(&Err("ETIMEDOUT".into())), PortState::Timeout);
    assert_eq!(port_state(&Err("ECONNREFUSED".into())), PortState::Closed);
    assert_eq!(port_state(&Err("ECONNRESET".into())), PortState::Filtered);
    assert_eq!(port_state(&Err(CANCELLED.into())), PortState::Filtered);
}

/// AT-05-001: basic scan sees a local listening port open.
#[tokio::test]
async fn scan_sees_local_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let cancel = CancellationToken::new();
    let ip = IpAddr::from([127, 0, 0, 1]);
    let items = scan_ports(ip, port, false, &ProbePath::Os, &cancel).await;
    let own = items.iter().find(|i| i.port == port).unwrap();
    assert!(own.open);
    assert_eq!(own.state, PortState::Open);
    assert_eq!(own.service, None);
    assert!(items.iter().any(|i| i.port == 443));
}

/// Extended scan covers the 8 restricted ports once each, sorted, with service hints.
#[tokio::test]
async fn extended_scan_has_no_duplicates() {
    let cancel = CancellationToken::new();
    let items = scan_with(ports_to_scan(443, true), &cancel, |p| async move {
        if p == 443 {
            Ok(())
        } else {
            Err("ECONNREFUSED".to_owned())
        }
    })
    .await;
    let ports: Vec<u16> = items.iter().map(|i| i.port).collect();
    let mut sorted = RESTRICTED_PORTS.to_vec();
    sorted.sort_unstable();
    assert_eq!(ports, sorted);
    assert_eq!(items.iter().filter(|i| i.open).count(), 1);
    assert_eq!(items[0].service.as_deref(), Some("HTTP"));
}

/// AT-00-003: after a cancel no new port starts; the in-flight ones read `filtered`.
#[tokio::test]
async fn cancelled_scan_is_partial() {
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let items = scan_with(ports_to_scan(443, true), &cancel, |_| {
        token.cancel();
        std::future::pending::<Result<(), String>>()
    })
    .await;
    assert!(items.len() <= 3, "{items:?}");
    assert!(items.iter().all(|i| i.state == PortState::Filtered));
}
