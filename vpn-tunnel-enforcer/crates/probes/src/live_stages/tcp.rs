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
mod tests;
