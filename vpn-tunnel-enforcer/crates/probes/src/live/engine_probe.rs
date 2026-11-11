//! The engine stage (live-probe §3.14, §6.4): an end-to-end probe through the checked profile.
//! The running tunnel's own probe inbound when the profile is the active one (never a second
//! proxy process for it), else a temporary engine with the config on stdin
//! (`key_health::start_probe_engine`: kill-on-close Job, authenticated inbound) dialling the server
//! through the tunnel's bypass inbound or bound to the physical adapter. Reflectors and media run
//! concurrently, throughput after them; the engine is stopped and reaped before the stage returns.
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use vpnte_base::types::Loopback;
use vpnte_base::{AppError, ErrorKind, Msg};
use vpnte_profiles::emit_singbox::{block_quic, udp_capable};
use vpnte_profiles::model::{Kind, Profile};

use super::env::{EngineSetup, ProfileTarget, TunnelView};
use super::model::{
    Egress, EgressStatus, EngineRoute, Handshake, HandshakeEvidence, HandshakeStatus, MediaStatus,
    MediaStream, Throughput, ThroughputStatus,
};
use super::ms;
use super::reflect::{
    Attempt, MEDIA, REFLECTORS, aggregate_egress, media_endpoint, reflector, summarize_media,
};
use super::throughput::probe_throughput;
use super::wire::Wire;
use crate::key_health::{HealthReason, Started, classify_failure, start_probe_engine};
use crate::live_stages::{CANCELLED, NotCheckedReason};

/// The engine logs a failed dial asynchronously; give its last lines a moment to arrive before
/// they decide auth vs transport.
const LOG_SETTLE: Duration = Duration::from_millis(150);

/// Handshake, egress, media and (when asked) throughput of one check.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EngineStage {
    pub handshake: Handshake,
    pub egress: Egress,
    pub media: MediaStream,
    pub throughput: Option<Throughput>,
}

/// What the stage needs.
pub(crate) struct EngineInput<'a> {
    pub target: &'a ProfileTarget,
    pub tunnel: &'a TunnelView,
    pub setup: &'a EngineSetup,
    pub wire: &'a Wire,
    /// The address the direct stages probed (for `egress.matchesEndpoint`).
    pub endpoint_ip: Option<IpAddr>,
    pub throughput: bool,
}

impl EngineStage {
    /// Nothing ran: every part `skipped` (or `not_checked` with `reason`) with one note.
    pub(crate) fn not_run(
        protocol: &str,
        route: Option<EngineRoute>,
        note: Option<Msg>,
        error: Option<String>,
        reason: Option<NotCheckedReason>,
        throughput: bool,
    ) -> Self {
        let not_checked = reason.is_some();
        let note = note.map(Into::into);
        EngineStage {
            handshake: Handshake {
                status: if not_checked {
                    HandshakeStatus::NotChecked
                } else {
                    HandshakeStatus::Skipped
                },
                protocol: Some(protocol.to_owned()),
                error: error.clone(),
                note: note.clone(),
                reason,
                route,
                ..Handshake::default()
            },
            egress: Egress {
                status: if not_checked {
                    EgressStatus::NotChecked
                } else {
                    EgressStatus::Skipped
                },
                error: error.clone(),
                note: note.clone(),
                reason,
                ..Egress::default()
            },
            media: MediaStream {
                status: if not_checked {
                    MediaStatus::NotChecked
                } else {
                    MediaStatus::Skipped
                },
                detail: note,
                error,
                reason,
                ..MediaStream::default()
            },
            throughput: throughput.then(|| Throughput {
                status: if not_checked {
                    ThroughputStatus::NotChecked
                } else {
                    ThroughputStatus::Skipped
                },
                route,
                reason,
                ..Throughput::default()
            }),
        }
    }
}

fn cancelled(protocol: &str, throughput: bool) -> EngineStage {
    EngineStage::not_run(
        protocol,
        None,
        None,
        Some(CANCELLED.into()),
        None,
        throughput,
    )
}

/// Wire name of a failure class (`auth-failed`, `hy2-udp-blocked`, …).
fn code(reason: HealthReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Handshake status of a failure class: auth → `auth_failed`, timeout → `timeout`, else transport.
pub(crate) fn status_of(reason: HealthReason) -> HandshakeStatus {
    match reason {
        HealthReason::AuthFailed | HealthReason::Hy2AuthFailed => HandshakeStatus::AuthFailed,
        HealthReason::Timeout => HandshakeStatus::Timeout,
        _ => HandshakeStatus::TransportFailed,
    }
}

/// What went through the inbound.
pub(crate) struct Measured {
    pub reflectors: Vec<(super::model::Reflector, Attempt)>,
    pub media: Vec<(super::model::MediaEndpoint, Attempt)>,
    pub throughput: Option<Throughput>,
    /// Reflectors and media (they run together).
    pub probes_ms: u64,
    pub total_ms: u64,
}

impl Measured {
    /// Reflector attempts first, then media (the order the first error is taken in).
    fn attempts(&self) -> impl Iterator<Item = &Attempt> {
        let r = self.reflectors.iter().map(|(_, a)| a);
        r.chain(self.media.iter().map(|(_, a)| a))
    }
}

/// Reflectors and media concurrently (B-29), then the throughput samples when asked. Throughput
/// is not gated on the reflectors: an exit that blocks them but reaches the speed host still
/// yields a speed and the handshake proof.
pub(crate) async fn measure(
    wire: &Wire,
    socks: &Loopback,
    throughput: Option<EngineRoute>,
    cancel: &CancellationToken,
) -> Measured {
    let start = Instant::now();
    let [cf, ipify, ipify6] = REFLECTORS;
    let (r1, r2, r3, m1, m2) = tokio::join!(
        reflector(wire, socks, cf, cancel),
        reflector(wire, socks, ipify, cancel),
        reflector(wire, socks, ipify6, cancel),
        media_endpoint(wire, socks, MEDIA[0], cancel),
        media_endpoint(wire, socks, MEDIA[1], cancel),
    );
    let probes_ms = ms(start.elapsed());
    let throughput = match throughput {
        Some(route) if !cancel.is_cancelled() => {
            Some(probe_throughput(wire, socks, route, cancel).await)
        }
        _ => None,
    };
    Measured {
        reflectors: vec![r1, r2, r3],
        media: vec![m1, m2],
        throughput,
        probes_ms,
        total_ms: ms(start.elapsed()),
    }
}

/// Turns the measurements into the stage. `log` = the probe engine's output ("" for the
/// running tunnel, whose log is not ours to read here).
pub(crate) fn assemble(
    m: Measured,
    profile: &Profile,
    endpoint_ip: Option<IpAddr>,
    route: EngineRoute,
    inbound_port: u16,
    log: &str,
) -> EngineStage {
    let protocol = profile.kind.label().to_owned();
    let attempts: Vec<&Attempt> = m.attempts().collect();
    let proof_ms = attempts.iter().filter(|a| a.proof).map(|a| a.ms).min();
    let body_seen = m
        .throughput
        .as_ref()
        .is_some_and(|t| t.samples.iter().any(|s| s.bytes > 0));
    let mut evidence = HandshakeEvidence {
        transport: Some(protocol.clone()),
        alpn: profile.tls.as_ref().and_then(|t| t.alpn.first().cloned()),
        detail: None,
        inbound_port: Some(inbound_port),
        socks_connect_ok: Some(attempts.iter().any(|a| a.socks_ok)),
    };
    let mut handshake = Handshake {
        status: HandshakeStatus::Ok,
        duration_ms: proof_ms.unwrap_or(m.total_ms),
        protocol: Some(protocol),
        route: Some(route),
        ..Handshake::default()
    };
    if proof_ms.is_none() && !body_seen {
        let err = attempts
            .iter()
            .find_map(|a| a.error.clone())
            .unwrap_or_else(|| "No successful TCP connection through the tunnel".into());
        let reason = classify_failure(matches!(profile.kind, Kind::Hysteria2 { .. }), log, &err);
        handshake.status = status_of(reason);
        handshake.duration_ms = m.total_ms;
        handshake.error = Some(err);
        evidence.detail = Some(code(reason));
    }
    handshake.evidence = Some(evidence);
    let egress = aggregate_egress(
        m.reflectors.into_iter().map(|(r, _)| r).collect(),
        endpoint_ip,
        m.probes_ms,
    );
    let media = summarize_media(
        m.media.into_iter().map(|(e, _)| e).collect(),
        udp_capable(profile),
        block_quic(profile),
        m.probes_ms,
    );
    EngineStage {
        handshake,
        egress,
        media,
        throughput: m.throughput,
    }
}

/// Runs the stage for a profile (the check's cancel token also carries its deadline).
pub(crate) async fn run_engine_probe(
    input: EngineInput<'_>,
    cancel: &CancellationToken,
) -> EngineStage {
    let profile = &input.target.profile;
    let protocol = profile.kind.label();
    let tunnel = input.tunnel;
    if cancel.is_cancelled() {
        return cancelled(protocol, input.throughput);
    }
    if tunnel.up() && tunnel.active_profile_id.as_deref() == Some(input.target.id.as_str()) {
        let route = EngineRoute::ActiveTunnel;
        let Some(inbound) = &tunnel.live_check_in else {
            let note = Msg::new("probes.live.engine.noProbePort");
            return EngineStage::not_run(
                protocol,
                Some(route),
                Some(note),
                None,
                None,
                input.throughput,
            );
        };
        let m = measure(
            input.wire,
            inbound,
            input.throughput.then_some(route),
            cancel,
        )
        .await;
        if cancel.is_cancelled() {
            return cancelled(protocol, input.throughput);
        }
        return assemble(m, profile, input.endpoint_ip, route, inbound.port, "");
    }
    let route = if tunnel.up() && tunnel.mixed_direct_in.is_some() {
        EngineRoute::ActiveTunnelDirectDetour
    } else {
        EngineRoute::PhysicalDirect
    };
    let ctx = input.setup.ctx(input.target.device, tunnel);
    let engine = match start_probe_engine(profile, &ctx, cancel).await {
        Ok(Started::Ready(engine)) => engine,
        Ok(Started::Offline(health)) => {
            // The engine refused the profile or died before serving its port: a verdict.
            let reason = health.reason.unwrap_or(HealthReason::HandshakeFailed);
            let note = Msg::new("probes.live.engine.handshakeFailed").arg("reason", code(reason));
            let mut stage = EngineStage::not_run(
                protocol,
                Some(route),
                Some(note),
                None,
                None,
                input.throughput,
            );
            stage.handshake.status = status_of(reason);
            stage.handshake.note = None;
            // Old rule: the failure class stands in for the missing error text.
            stage.handshake.error = Some(code(reason));
            stage.handshake.evidence = Some(HandshakeEvidence {
                transport: Some(protocol.to_owned()),
                detail: Some(code(reason)),
                ..HandshakeEvidence::default()
            });
            return stage;
        }
        Err(e) if e.kind == ErrorKind::Cancelled || cancel.is_cancelled() => {
            return cancelled(protocol, input.throughput);
        }
        Err(e) => return not_started(protocol, route, &e, input.throughput),
    };
    let socks = engine.socks().clone();
    let m = measure(
        input.wire,
        &socks,
        input.throughput.then_some(route),
        cancel,
    )
    .await;
    let stage = if cancel.is_cancelled() {
        cancelled(protocol, input.throughput)
    } else {
        let proved = m.attempts().any(|a| a.proof);
        if !proved {
            tokio::time::sleep(LOG_SETTLE).await;
        }
        assemble(
            m,
            profile,
            input.endpoint_ip,
            route,
            socks.port,
            &engine.output(),
        )
    };
    engine.stop().await;
    stage
}

/// The probe engine could not be set up (missing executable, no free port): nothing about the
/// server is known.
fn not_started(protocol: &str, route: EngineRoute, e: &AppError, throughput: bool) -> EngineStage {
    tracing::warn!(error = %e, "live check probe engine not started");
    EngineStage::not_run(
        protocol,
        Some(route),
        Some(e.user_msg()),
        Some(e.to_string()),
        None,
        throughput,
    )
}
