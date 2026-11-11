//! One check (live-probe §6.3): target, DNS, the direct stages concurrently, the engine stage,
//! the split-tunnel snapshot, diff with the baseline, findings, sanitising, then the history
//! write. Cancellation and the deadline reach every stage through one token, so the engine is
//! reaped before the check returns; a check that was cancelled or hit its deadline is never
//! stored (AT-00-003 / AT-00-005). Once the history write started it completes and the check is
//! returned even if a cancel lands meanwhile (old commit rule).
mod direct;
mod progress;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, Msg};

use super::diff::diff;
use super::engine_probe::{EngineInput, EngineStage, run_engine_probe};
use super::env::{LiveEnv, ProfileTarget, TunnelState, TunnelView};
use super::findings::evaluate_findings;
use super::history::HistoryStore;
use super::model::{LiveCheck, TunnelContext};
use super::runner::{ProgressStatus, StageId};
use super::sanitize::sanitize;
use super::split::{split_tunnel_failed, summarize_split_tunnel};
use super::wire::Wire;
use super::{BASIC_DEADLINE, CheckMode, CheckRequest, CheckTarget, EXTENDED_DEADLINE, ms};
use crate::live_stages::dns::{DnsBackend, DnsDiagnostics, probe_dns};
use crate::live_stages::geo::GeoCache;
use crate::live_stages::path::physical_uplink;
use crate::live_stages::target::{
    TargetClass, classify_target, normalize_host_port, refused_error, require_host, tls_applicable,
};
use crate::live_stages::{CANCELLED, NotCheckedReason, ProbePath, Timed};
use direct::{Direct, DirectPlan, InfraInput, direct_stages, report_direct};
use progress::{engine_progress, timed_progress};

/// Whole-check deadlines (configurable so tests need not wait 25 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Budget {
    pub(crate) basic: Duration,
    pub(crate) extended: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            basic: BASIC_DEADLINE,
            extended: EXTENDED_DEADLINE,
        }
    }
}

impl Budget {
    /// The samples alone may take 3 × 8 s: a check that measures throughput gets the extended
    /// budget in any mode, else a throttled server (what the samples exist to show) would always
    /// hit the basic deadline and the whole check would be lost.
    pub(crate) fn of(&self, mode: CheckMode, throughput: bool) -> Duration {
        if mode.extended() || throughput {
            self.extended
        } else {
            self.basic
        }
    }
}

/// Long-lived stage resources (one per service).
pub(crate) struct Stages<B> {
    pub dns: B,
    pub geo: GeoCache,
    pub wire: Wire,
    pub budget: Budget,
}

/// Progress sink of one check; silent once the job is cancelled (no event after a cancel).
pub(crate) struct Reporter<'a> {
    pub cancel: &'a CancellationToken,
    pub sink: &'a (dyn Fn(StageId, ProgressStatus) + Send + Sync),
}

impl Reporter<'_> {
    pub(crate) fn set(&self, stage: StageId, status: ProgressStatus) {
        if !self.cancel.is_cancelled() {
            (self.sink)(stage, status);
        }
    }

    fn running(&self, stages: &[StageId]) {
        for s in stages {
            self.set(*s, ProgressStatus::Running);
        }
    }
}

/// What the profile (or the bare endpoint) says about which probes make sense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Facts {
    pub host: String,
    pub port: u16,
    /// QUIC / WireGuard: TCP, TLS and HTTP probes say nothing about the server (B-03).
    pub udp: bool,
    /// REALITY front: its certificate is the camouflage site's and a direct ClientHello risks
    /// a block (B-05).
    pub reality: bool,
    pub tls_applicable: bool,
    pub sni: Option<String>,
}

impl Facts {
    pub(crate) fn of_profile(t: &ProfileTarget) -> Self {
        let p = &t.profile;
        let tls = p.tls.as_ref();
        Facts {
            host: p.server.to_string(),
            port: p.port,
            udp: p.kind.is_udp_transport(),
            reality: tls.is_some_and(|t| t.reality.is_some()),
            tls_applicable: tls.is_some(),
            sni: tls
                .and_then(|t| t.server_name.clone())
                .filter(|s| !s.trim().is_empty()),
        }
    }

    /// Why the direct TLS / HTTP probes do not run, `None` when they do (extended mode only: a
    /// ClientHello with the front's SNI is exactly what a censor watches for, B-05).
    pub(crate) fn tls_skip(&self, mode: CheckMode) -> Option<NotCheckedReason> {
        if self.udp {
            Some(NotCheckedReason::UdpTransport)
        } else if self.reality {
            Some(NotCheckedReason::Reality)
        } else if !mode.extended() {
            Some(NotCheckedReason::BasicMode)
        } else {
            None
        }
    }
}

/// Where the direct stages' sockets go: the OS route with our tunnel down, the physical uplink
/// while it is up (B-02), nothing while it switches.
async fn probe_path(tunnel: &TunnelView) -> Option<ProbePath> {
    match tunnel.state {
        TunnelState::Down => Some(ProbePath::Os),
        TunnelState::Transition => None,
        TunnelState::Up => {
            let uplink = tokio::task::spawn_blocking(physical_uplink).await;
            match uplink {
                Ok(Ok((path, _alias))) => Some(path),
                _ => {
                    // Rare (no physical adapter listed): the sockets follow the OS route, i.e.
                    // our TUN, and every stage records `route: os` so the row says so.
                    tracing::warn!(
                        "live check: no physical uplink; direct stages use the OS route"
                    );
                    Some(ProbePath::Os)
                }
            }
        }
    }
}

/// The target of a request: the profile (if any) and the facts.
pub(crate) fn resolve_target(
    env: &dyn LiveEnv,
    target: &CheckTarget,
) -> AppResult<(Option<ProfileTarget>, Facts)> {
    match target {
        CheckTarget::Profile(id) => {
            let t = env
                .profile(id)
                .ok_or_else(|| AppError::validation(Msg::new("probes.live.profileNotFound")))?;
            let facts = Facts::of_profile(&t);
            Ok((Some(t), facts))
        }
        CheckTarget::Endpoint { host, port } => {
            require_host(host)?;
            let n = normalize_host_port(host, *port);
            let tls_applicable = tls_applicable(n.port, false);
            Ok((
                None,
                Facts {
                    host: n.host,
                    port: n.port,
                    udp: false,
                    reality: false,
                    tls_applicable,
                    sni: None,
                },
            ))
        }
    }
}

/// Runs one check and stores it. `cancel` is the job's token; the deadline of the mode cancels a
/// child token, so stages wind down (and the engine is reaped) in both cases.
pub(crate) async fn run_check<B: DnsBackend>(
    stages: &Stages<B>,
    env: &dyn LiveEnv,
    history: &Arc<HistoryStore>,
    req: &CheckRequest,
    cancel: &CancellationToken,
    report: &Reporter<'_>,
) -> AppResult<LiveCheck> {
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    let (profile, facts) = resolve_target(env, &req.target)?;
    let started_at = now_ms();
    let start = Instant::now();
    let token = cancel.child_token();
    let timer = {
        let token = token.clone();
        let budget = stages.budget.of(req.mode, req.throughput);
        tokio::spawn(async move {
            tokio::time::sleep(budget).await;
            token.cancel();
        })
    };
    let deadline = start + stages.budget.of(req.mode, req.throughput);
    let outcome = measure_all(
        stages,
        env,
        req,
        profile.as_ref(),
        &facts,
        deadline,
        &token,
        report,
    )
    .await;
    timer.abort();
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    if token.is_cancelled() {
        return Err(AppError::timeout());
    }
    let mut check = outcome?;
    check.started_at = started_at;
    check.finished_at = now_ms();
    check.duration_ms = ms(start.elapsed());
    let prev = history.baseline(check.profile_id.as_deref(), &check.host, check.port);
    let changes = prev.as_ref().map(|p| diff(&check, p).flags());
    if let (Some(changes), Some(infra)) = (changes, &mut check.infrastructure) {
        // Attached before the row is stored (old order).
        infra.changes_from_previous = Some(changes);
    }
    check.findings = evaluate_findings(&check, prev.as_ref());
    sanitize(&mut check);
    let row = check.clone();
    let history = history.clone();
    tokio::task::spawn_blocking(move || history.insert(row))
        .await
        .map_err(AppError::internal)??;
    Ok(check)
}

/// A new row id (no dashes: free-text redaction masks UUID-shaped tokens, B-33).
fn new_id() -> String {
    format!("lc_{}", uuid::Uuid::new_v4().simple())
}

/// Every stage of the check, without timestamps, diff, findings or storage. `deadline` is the
/// check's: the engine stage plans its budgeted dials against it.
#[allow(clippy::too_many_arguments)]
async fn measure_all<B: DnsBackend>(
    stages: &Stages<B>,
    env: &dyn LiveEnv,
    req: &CheckRequest,
    profile: Option<&ProfileTarget>,
    facts: &Facts,
    deadline: Instant,
    token: &CancellationToken,
    report: &Reporter<'_>,
) -> AppResult<LiveCheck> {
    use StageId as S;
    let mode = req.mode;
    let tunnel = env.tunnel();
    let path = probe_path(&tunnel).await;
    report.set(S::Dns, ProgressStatus::Running);
    let (dns, reverse_dns) = match &path {
        Some(_) => probe_dns(&stages.dns, &facts.host, mode.extended(), token).await,
        None => {
            let timed = Timed::not_checked(NotCheckedReason::TunnelTransition);
            (
                DnsDiagnostics {
                    timed,
                    ..DnsDiagnostics::default()
                },
                Vec::new(),
            )
        }
    };
    report.set(S::Dns, timed_progress(dns.timed.status));
    let ip = dns
        .primary_ip()
        .or_else(|| facts.host.trim_matches(['[', ']']).parse().ok());
    // No socket to a loopback / link-local / multicast address (B-06).
    if let Some(ip) = ip
        && classify_target(ip) == TargetClass::Refused
    {
        return Err(refused_error(ip));
    }
    let direct = match (&path, ip) {
        (Some(path), Some(ip)) if !token.is_cancelled() => {
            let infra = InfraInput {
                geo: env.geo_enabled(),
                country: profile.and_then(|p| p.country.clone()),
                others: env.other_profiles(profile.map(|p| p.id.as_str())),
            };
            let plan = DirectPlan {
                facts,
                mode,
                ip,
                path,
                tun_luid: tunnel.tun_luid,
                infra,
            };
            direct_stages(stages, plan, token, report).await
        }
        (None, _) => {
            let d = Direct::without_address(facts, Some(NotCheckedReason::TunnelTransition), None);
            report_direct(&d, report);
            d
        }
        _ => {
            let d = Direct::without_address(facts, None, profile.and_then(|p| p.country.clone()));
            report_direct(&d, report);
            d
        }
    };
    report.running(&[S::Handshake, S::Egress, S::MediaStream]);
    let throughput_state = if req.throughput {
        ProgressStatus::Running
    } else {
        ProgressStatus::Skipped
    };
    report.set(S::Throughput, throughput_state);
    let engine = match (profile, &path) {
        (Some(t), _) if token.is_cancelled() => EngineStage::not_run(
            t.profile.kind.label(),
            None,
            None,
            Some(CANCELLED.into()),
            None,
            req.throughput,
        ),
        (Some(t), Some(_)) => {
            let setup = env.engine_setup();
            let input = EngineInput {
                target: t,
                tunnel: &tunnel,
                setup: &setup,
                wire: &stages.wire,
                endpoint_ip: ip,
                throughput: req.throughput,
                deadline: Some(deadline),
            };
            run_engine_probe(input, token).await
        }
        (Some(t), None) => EngineStage::not_run(
            t.profile.kind.label(),
            None,
            None,
            None,
            Some(NotCheckedReason::TunnelTransition),
            req.throughput,
        ),
        (None, _) => {
            let note = Msg::new("probes.live.engine.noProfile");
            let mut stage = EngineStage::not_run("", None, Some(note), None, None, false);
            stage.handshake.protocol = None;
            stage
        }
    };
    engine_progress(&engine, report);
    let split_tunnel = mode.extended().then(|| match env.split_tunnel() {
        Ok(rules) => summarize_split_tunnel(&rules),
        Err(error) => split_tunnel_failed(error),
    });
    Ok(LiveCheck {
        id: new_id(),
        profile_id: profile.map(|p| p.id.clone()),
        host: facts.host.clone(),
        port: facts.port,
        mode,
        started_at: 0,
        finished_at: 0,
        duration_ms: 0,
        cancelled: false,
        tunnel: Some(TunnelContext {
            state: tunnel.state,
        }),
        asn: direct.infra.asn.clone(),
        dns,
        reverse_dns,
        reachability: direct.reachability,
        latency: direct.latency,
        tls: direct.tls,
        http: direct.http,
        open_ports: direct.ports,
        ports_error: None,
        route: direct.route,
        infrastructure: Some(direct.infra),
        handshake: Some(engine.handshake),
        egress: Some(engine.egress),
        media_stream: Some(engine.media),
        throughput: engine.throughput,
        path_diagnostics: direct.path,
        pmtu: direct.pmtu,
        split_tunnel,
        findings: Vec::new(),
    })
}
