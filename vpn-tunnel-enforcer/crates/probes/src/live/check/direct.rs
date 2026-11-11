//! The direct stages of one check (no engine): reachability, ports, TLS, HTTP, infrastructure,
//! path and PMTU, run concurrently under the check's token.
use std::net::{IpAddr, SocketAddr};

use tokio_util::sync::CancellationToken;

use super::progress::{path_progress, pmtu_progress, timed_progress};
use super::{Facts, Reporter, Stages};
use crate::live::CheckMode;
use crate::live::runner::{ProgressStatus, StageId};
use crate::live_stages::dns::DnsBackend;
use crate::live_stages::geo::{Infrastructure, OtherProfile, infrastructure};
use crate::live_stages::http::{HttpInfo, probe_http};
use crate::live_stages::icmp::{Pmtu, RouteTrace, probe_pmtu, trace_route};
use crate::live_stages::path::{PathInfo, path_info};
use crate::live_stages::tcp::{LatencyStats, PortItem, Reachability, sample_latency, scan_ports};
use crate::live_stages::tls::{TlsInfo, inspect_tls};
use crate::live_stages::{NotCheckedReason, ProbePath, Timed, TimedStatus};

/// Results of the direct stages.
pub(crate) struct Direct {
    pub reachability: Reachability,
    pub latency: Option<LatencyStats>,
    pub tls: Option<TlsInfo>,
    pub http: Option<HttpInfo>,
    pub ports: Option<Vec<PortItem>>,
    pub route: Option<RouteTrace>,
    pub infra: Infrastructure,
    pub path: Option<PathInfo>,
    pub pmtu: Option<Pmtu>,
}

/// Inputs of the infrastructure stage.
pub(crate) struct InfraInput {
    pub geo: bool,
    pub country: Option<String>,
    pub others: Vec<OtherProfile>,
}

impl Direct {
    /// Every direct stage `not_checked` (tunnel switching) or failed for want of an address.
    pub(super) fn without_address(
        facts: &Facts,
        reason: Option<NotCheckedReason>,
        country: Option<String>,
    ) -> Self {
        let timed = match reason {
            Some(r) => Timed::not_checked(r),
            // TCP is never probed for a UDP transport (B-03): no false "unreachable over TCP".
            None if facts.udp => Timed::not_checked(NotCheckedReason::UdpTransport),
            None => Timed {
                status: TimedStatus::Error,
                error: Some("no address resolved".into()),
                ..Timed::default()
            },
        };
        Direct {
            reachability: Reachability {
                timed,
                tcp_reachable: false,
                port: facts.port,
            },
            latency: None,
            tls: None,
            http: None,
            ports: None,
            route: None,
            infra: Infrastructure {
                status: TimedStatus::NotChecked,
                reason,
                endpoint_country: country,
                ..Infrastructure::default()
            },
            path: None,
            pmtu: None,
        }
    }
}

/// What the direct stages probe.
pub(crate) struct DirectPlan<'a> {
    pub facts: &'a Facts,
    pub mode: CheckMode,
    pub ip: IpAddr,
    pub path: &'a ProbePath,
    pub tun_luid: Option<u64>,
    pub infra: InfraInput,
}

/// The direct stages against `ip`, concurrently (§6.3 stage 2), each reporting when it ends.
pub(super) async fn direct_stages<B: DnsBackend>(
    stages: &Stages<B>,
    plan: DirectPlan<'_>,
    token: &CancellationToken,
    report: &Reporter<'_>,
) -> Direct {
    use StageId as S;
    let DirectPlan {
        facts,
        mode,
        ip,
        path,
        tun_luid,
        infra,
    } = plan;
    let extended = mode.extended();
    let addr = SocketAddr::new(ip, facts.port);
    let identity = facts.sni.clone().unwrap_or_else(|| {
        if facts.host.parse::<IpAddr>().is_ok() {
            ip.to_string()
        } else {
            facts.host.clone()
        }
    });
    // Direct TLS and HTTP share their gate (B-05).
    let skip = facts.tls_skip(mode);
    report.running(&[
        S::Reachability,
        S::Tls,
        S::Http,
        S::Ports,
        S::Infrastructure,
        S::Path,
        S::Pmtu,
    ]);
    if extended {
        report.set(S::Route, ProgressStatus::Running);
    } else {
        report.set(S::Route, ProgressStatus::Skipped);
    }
    let reach = async {
        let r = if facts.udp {
            let timed = Timed::not_checked(NotCheckedReason::UdpTransport);
            (
                Reachability {
                    timed,
                    tcp_reachable: false,
                    port: facts.port,
                },
                None,
            )
        } else {
            sample_latency(addr, extended, path, token).await
        };
        report.set(S::Reachability, timed_progress(r.0.timed.status));
        r
    };
    let tls = async {
        let r = match (facts.tls_applicable, skip) {
            (false, _) => None,
            (true, Some(reason)) => Some(TlsInfo {
                timed: Timed::not_checked(reason),
                ..TlsInfo::default()
            }),
            (true, None) => Some(inspect_tls(addr, &identity, path, token).await),
        };
        report.set(
            S::Tls,
            r.as_ref()
                .map_or(ProgressStatus::Skipped, |t| timed_progress(t.timed.status)),
        );
        r
    };
    let http = async {
        let r = match skip {
            Some(reason) => HttpInfo {
                timed: Timed::not_checked(reason),
                target_port: facts.port,
                is_tls: facts.tls_applicable,
                ..HttpInfo::default()
            },
            None => {
                probe_http(
                    addr,
                    facts.tls_applicable,
                    &facts.host,
                    facts.sni.as_deref(),
                    path,
                    token,
                )
                .await
            }
        };
        report.set(S::Http, timed_progress(r.timed.status));
        Some(r)
    };
    let ports = async {
        let r = if facts.udp {
            None
        } else {
            Some(scan_ports(ip, facts.port, extended, path, token).await)
        };
        report.set(
            S::Ports,
            if r.is_some() {
                ProgressStatus::Completed
            } else {
                ProgressStatus::Skipped
            },
        );
        r
    };
    let route = async {
        if !extended {
            return None;
        }
        let r = trace_route(ip, path, token).await;
        report.set(S::Route, timed_progress(r.timed.status));
        Some(r)
    };
    let infrastructure = async {
        let geo = infra.geo.then_some(&stages.geo);
        let r = infrastructure(
            geo,
            Some(ip),
            &facts.host,
            infra.country.clone(),
            &infra.others,
            token,
        )
        .await;
        report.set(S::Infrastructure, timed_progress(r.status));
        r
    };
    let path_pmtu = async {
        let info = path_info(ip, tun_luid);
        report.set(S::Path, path_progress(info.status));
        let iface = info.luid.zip(info.active_interface_alias.clone());
        let pmtu = probe_pmtu(
            ip,
            path,
            iface.as_ref().map(|(l, a)| (*l, a.as_str())),
            token,
        )
        .await;
        report.set(S::Pmtu, pmtu_progress(pmtu.status));
        (info, pmtu)
    };
    let ((reachability, latency), tls, http, ports, route, infra, (path, pmtu)) =
        tokio::join!(reach, tls, http, ports, route, infrastructure, path_pmtu);
    Direct {
        reachability,
        latency,
        tls,
        http,
        ports,
        route,
        infra,
        path: Some(path),
        pmtu: Some(pmtu),
    }
}

/// Reports the direct stages of a result that did not run them.
pub(super) fn report_direct(d: &Direct, report: &Reporter<'_>) {
    use StageId as S;
    report.set(S::Reachability, timed_progress(d.reachability.timed.status));
    for s in [S::Tls, S::Http, S::Ports, S::Route, S::Path, S::Pmtu] {
        report.set(s, ProgressStatus::Skipped);
    }
    report.set(S::Infrastructure, timed_progress(d.infra.status));
}
