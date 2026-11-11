//! TCP stages: reachability + latency / jitter / loss from sequential connects, and the port scan.
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::{
    CANCELLED, ProbePath, ProbeRoute, RESTRICTED_PORTS, Timed, TimedStatus, elapsed_ms, net,
    service_hint, timeouts,
};

/// Direct TCP reachability of the server port (`reachability` in the row).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reachability {
    #[serde(flatten)]
    pub timed: Timed,
    #[serde(default)]
    pub tcp_reachable: bool,
    #[serde(default)]
    pub port: u16,
}

/// TCP connect-time statistics (`latency`), only when at least one sample succeeded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyStats {
    pub min: u64,
    pub avg: u64,
    pub median: u64,
    pub max: u64,
    /// Population standard deviation around the rounded mean.
    pub jitter: u64,
    /// Failed share of the attempted samples, two decimals.
    pub loss: f64,
    /// Successful connect times, ascending.
    pub samples: Vec<u64>,
    pub samples_attempted: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<ProbeRoute>,
}

/// Outcome of one scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Timeout,
}

/// One row of `openPorts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortItem {
    pub port: u16,
    pub open: bool,
    pub state: PortState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

/// Fallback error when every sample failed without a cause.
const NO_CONNECT: &str = "Connection refused or timed out";

/// Sequential connect samples (5 basic / 10 extended) inside a 6 / 9 s stage deadline, 60 ms apart.
/// Loss counts only samples actually attempted; RTT is the connect time, not the close.
pub async fn sample_latency(
    addr: SocketAddr,
    extended: bool,
    path: &ProbePath,
    cancel: &CancellationToken,
) -> (Reachability, Option<LatencyStats>) {
    let path = *path;
    sample_with(
        addr.port(),
        extended,
        path.route(),
        cancel,
        move |limit| async move {
            let start = Instant::now();
            net::connect(addr, &path, limit)
                .await
                .map(|_stream| elapsed_ms(start))
        },
    )
    .await
}

async fn sample_with<F, Fut>(
    port: u16,
    extended: bool,
    route: ProbeRoute,
    cancel: &CancellationToken,
    mut connect: F,
) -> (Reachability, Option<LatencyStats>)
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = Result<u64, String>>,
{
    let reach = |timed: Timed, ok: bool| Reachability {
        timed,
        tcp_reachable: ok,
        port,
    };
    if cancel.is_cancelled() {
        return (reach(Timed::cancelled(), false), None);
    }
    let (target, budget) = if extended {
        (10, timeouts::LATENCY_EXTENDED)
    } else {
        (5, timeouts::LATENCY_BASIC)
    };
    let start = Instant::now();
    let deadline = start + budget;
    let (mut durations, mut attempted, mut first_error) = (Vec::new(), 0u32, None::<String>);
    for i in 0..target {
        let now = Instant::now();
        if cancel.is_cancelled() || now >= deadline {
            break;
        }
        attempted += 1;
        let limit = timeouts::TCP_CONNECT.min(deadline - now);
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(CANCELLED.to_owned()),
            r = connect(limit) => r,
        };
        match result {
            Ok(ms) => durations.push(ms),
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
        let last = i + 1 == target;
        if !last && Instant::now() + timeouts::SAMPLE_GAP < deadline {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = tokio::time::sleep(timeouts::SAMPLE_GAP) => {}
            }
        }
    }
    let ok = !durations.is_empty();
    let timed = if ok {
        Timed::done(TimedStatus::Ok, elapsed_ms(start), None, route)
    } else {
        let error = first_error.unwrap_or_else(|| NO_CONNECT.to_owned());
        Timed::done(TimedStatus::Error, elapsed_ms(start), Some(error), route)
    };
    let stats = latency_stats(durations, attempted).map(|s| LatencyStats {
        route: Some(route),
        ..s
    });
    (reach(timed, ok), stats)
}

/// Statistics of the successful samples (`None` when there are none).
pub fn latency_stats(mut durations: Vec<u64>, attempted: u32) -> Option<LatencyStats> {
    if durations.is_empty() {
        return None;
    }
    durations.sort_unstable();
    let n = durations.len();
    let sum: u64 = durations.iter().sum();
    let avg = (sum as f64 / n as f64).round() as u64;
    let median = if n.is_multiple_of(2) {
        ((durations[n / 2 - 1] + durations[n / 2]) as f64 / 2.0).round() as u64
    } else {
        durations[n / 2]
    };
    let variance = durations
        .iter()
        .map(|d| (*d as f64 - avg as f64).powi(2))
        .sum::<f64>()
        / n as f64;
    let attempted = attempted.max(n as u32);
    let lost = attempted - n as u32;
    Some(LatencyStats {
        min: durations[0],
        avg,
        median,
        max: durations[n - 1],
        jitter: variance.sqrt().round() as u64,
        loss: (f64::from(lost) / f64::from(attempted) * 100.0).round() / 100.0,
        samples: durations,
        samples_attempted: attempted,
        route: None,
    })
}

/// Ports to scan: basic = the server port (+ 443); extended = [`RESTRICTED_PORTS`] ∪ the server port.
pub fn ports_to_scan(known: u16, extended: bool) -> Vec<u16> {
    let mut ports = if extended {
        RESTRICTED_PORTS.to_vec()
    } else {
        vec![known]
    };
    for extra in [known, 443] {
        if !ports.contains(&extra) && (extended || extra == 443) {
            ports.push(extra);
        }
    }
    ports
}

/// Port state from a connect outcome: refused = closed, our timeout = timeout, anything else
/// (reset, unreachable, cancelled) = filtered.
fn port_state(outcome: &Result<(), String>) -> PortState {
    match outcome {
        Ok(()) => PortState::Open,
        Err(e) if e == "ETIMEDOUT" => PortState::Timeout,
        Err(e) if e.contains("REFUSED") => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}

/// Scans with 3 workers, 1.2 s per port, sorted by port. After a cancel no new port is started,
/// so a cancelled scan returns a partial list (an in-flight port reads `filtered`).
pub async fn scan_ports(
    ip: IpAddr,
    known: u16,
    extended: bool,
    path: &ProbePath,
    cancel: &CancellationToken,
) -> Vec<PortItem> {
    let path = *path;
    scan_with(
        ports_to_scan(known, extended),
        cancel,
        move |port| async move {
            let addr = SocketAddr::new(ip, port);
            net::connect(addr, &path, timeouts::PORT).await.map(drop)
        },
    )
    .await
}

async fn scan_with<F, Fut>(ports: Vec<u16>, cancel: &CancellationToken, probe: F) -> Vec<PortItem>
where
    F: Fn(u16) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    // Three workers pull from one shared index (old PORT_SCAN_CONCURRENCY).
    let next = AtomicUsize::new(0);
    let worker = || async {
        let mut found = Vec::new();
        while !cancel.is_cancelled() {
            let Some(&port) = ports.get(next.fetch_add(1, Ordering::Relaxed)) else {
                break;
            };
            let outcome = tokio::select! {
            biased;
                _ = cancel.cancelled() => Err(CANCELLED.to_owned()),
                r = probe(port) => r,
            };
            let state = port_state(&outcome);
            found.push(PortItem {
                port,
                open: state == PortState::Open,
                state,
                service: service_hint(port).map(str::to_owned),
            });
        }
        found
    };
    let (a, b, c) = tokio::join!(worker(), worker(), worker());
    let mut items: Vec<PortItem> = a.into_iter().chain(b).chain(c).collect();
    items.sort_by_key(|i| i.port);
    items
}

#[cfg(test)]
mod tests {
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
}
