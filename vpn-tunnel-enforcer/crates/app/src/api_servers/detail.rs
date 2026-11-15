//! The server detail's reads: the passive probe (addresses, network owner, TCP latency to the
//! server's own port) and the location of its address. Never a TLS or HTTP request to the
//! endpoint (a ClientHello with a VPN front's SNI gets the address throttled by DPI boxes).
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_core::net::is_public_ip;
use vpnte_core::resolve::{How, resolve_host};
use vpnte_probes::geo::{LookupOwner, VerifyReject};
use vpnte_probes::ping::{PingPath, PingTarget, RESOLVE_TIMEOUT, median, ping};
use vpnte_servers::model::{ProfileId, ServerRow};
use vpnte_ui::servers::{AsnInfo, GeoInfo, LatencyStats, OpenPort, ProbeReport};

use super::checks::lookup_routes;
use super::import::count;
use super::{Shared, server_not_found};

/// The whole probe stays inside the page's 10 s wait (servers §3.12: 9 s).
const PROBE_BUDGET: Duration = Duration::from_millis(8_500);
/// TCP latency samples to the server's own port.
const LATENCY_SAMPLES: usize = 5;

/// A lookup owned by the detail dialog: wanted until its token is cancelled.
struct Wanted(CancellationToken);

impl LookupOwner for Wanted {
    fn is_current(&self) -> bool {
        !self.0.is_cancelled()
    }
}

/// Every address of the server, refused when one of them is local or private (the answers would
/// describe this network, not the server).
async fn addresses(row: &ServerRow) -> AppResult<Vec<IpAddr>> {
    let lookup = resolve_host(&row.server, How::System, |_| true);
    let ips = match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
        Ok(Ok(ips)) if !ips.is_empty() => ips,
        _ => {
            let msg = VerifyReject::ResolveFailed.msg();
            return Err(AppError::msg(ErrorKind::Network, msg));
        }
    };
    if ips.iter().any(|ip| !is_public_ip(*ip)) {
        return Err(AppError::validation(Msg::new(
            "app.servers.probe.privateTarget",
        )));
    }
    Ok(ips)
}

/// Passive facts about server `id`. Reverse DNS is not available here (no resolver for PTR
/// records in the libraries): the list stays empty and the page hides it.
pub(super) async fn probe(
    shared: Arc<Shared>,
    id: ProfileId,
    cancel: CancellationToken,
) -> AppResult<ProbeReport> {
    let deadline = Instant::now() + PROBE_BUDGET;
    let row = shared
        .backend
        .servers
        .get(&id)
        .ok_or_else(server_not_found)?;
    let ips = addresses(&row).await?;
    let tunnel = shared.backend.tunnel()?.clone();
    let net = tunnel.probe_ctx(row.device).net;
    let routes = lookup_routes(&shared, row.device)?;
    // Measure only the vetted address: never a second resolution of the name.
    let target = PingTarget {
        host: ips[0].to_string(),
        port: row.port,
        udp_only: row.profile().is_ok_and(|p| p.kind.is_udp_transport()),
    };
    let asn = async {
        let found = shared.backend.geo.asn(ips[0], &routes, &cancel);
        tokio::time::timeout_at(deadline, found)
            .await
            .ok()
            .flatten()
    };
    let latency = async {
        let mut samples = Vec::with_capacity(LATENCY_SAMPLES);
        let mut port_open = false;
        for _ in 0..LATENCY_SAMPLES {
            let Ok(sample) = tokio::time::timeout_at(deadline, ping(&target, &net, &cancel)).await
            else {
                break;
            };
            port_open |= sample.is_some_and(|s| s.path != PingPath::Icmp);
            samples.push(sample.map(|s| s.ms));
        }
        (samples, port_open)
    };
    let (asn, (samples, port_open)) = tokio::join!(asn, latency);
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    Ok(ProbeReport {
        resolved_ips: ips,
        reverse_dns: Vec::new(),
        asn: asn.map(|a| AsnInfo {
            asn: a.asn.unwrap_or_default(),
            org: a.org.unwrap_or_default(),
            network: a.network,
            country: a.country,
        }),
        latency: latency_stats(&samples),
        open_ports: if port_open {
            vec![OpenPort {
                port: row.port,
                service: None,
            }]
        } else {
            Vec::new()
        },
    })
}

/// Statistics of ping samples (`None` = no answer); `None` when nothing answered.
pub(super) fn latency_stats(samples: &[Option<u32>]) -> Option<LatencyStats> {
    let ok: Vec<u32> = samples.iter().flatten().copied().collect();
    let (min, max) = (*ok.iter().min()?, *ok.iter().max()?);
    let n = ok.len() as f64;
    let avg = ok.iter().map(|&v| f64::from(v)).sum::<f64>() / n;
    let variance = ok
        .iter()
        .map(|&v| (f64::from(v) - avg).powi(2))
        .sum::<f64>()
        / n;
    Some(LatencyStats {
        min,
        avg: avg.round() as u32,
        median: median(samples)?,
        max,
        jitter: variance.sqrt().round() as u32,
        loss: (samples.len() - ok.len()) as f64 / samples.len() as f64,
        attempted: Some(count(samples.len())),
        succeeded: Some(count(ok.len())),
        samples: ok,
    })
}

/// Country of the server's address; `None` when lookups are off or nothing is known.
pub(super) async fn geo(
    shared: Arc<Shared>,
    id: ProfileId,
    cancel: CancellationToken,
) -> AppResult<Option<GeoInfo>> {
    let backend = &shared.backend;
    let row = backend.servers.get(&id).ok_or_else(server_not_found)?;
    if !backend.geo.enabled() {
        return Ok(None);
    }
    // A name that does not resolve or a private address: nothing to locate.
    let Ok(ips) = addresses(&row).await else {
        return Ok(None);
    };
    let ip = ips[0];
    let routes = lookup_routes(&shared, row.device)?;
    let owner = Arc::new(Wanted(cancel.clone()));
    let country = backend.geo.country(ip, routes, owner).await;
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    Ok(country.map(|c| GeoInfo {
        ip: Some(ip),
        country: Some(c.as_str().to_owned()),
        ..GeoInfo::default()
    }))
}
