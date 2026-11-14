//! The pushed snapshots of both pages and the pure mapping of the probes' records into the
//! UI's view models (display data only; every sentence stays a `Msg` of the probes).
use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_core::store::{Document, Mode, Store};
use vpnte_probes::availability::{
    self as probe, AvailabilityResult, AvailabilityVerdict, PathSource, UrlChecks,
};
use vpnte_probes::diagnostics::{RoutingResult, RoutingVerdict as ProbeRouting};
use vpnte_probes::speedtest::{
    self as speed, Egress as ProbeEgress, SpeedPhase as ProbePhase, SpeedTests, TransportWarning,
};
use vpnte_tunnel::api::TunStatus;
use vpnte_ui::availability::{
    AvailabilityState, DnsStage, GeoInfo, HttpStage, PathReport, PathSource as UiSource,
    RoutingReport, RoutingVerdict, TcpStage, TlsStage, UrlCheck, UrlVerdict,
};
use vpnte_ui::speedtest::{Egress, SpeedPhase, SpeedProgress, SpeedResult, SpeedTestState};

use super::Shared;
use crate::api_dashboard::pace::Pace;

/// Starts the task that re-projects both pages on every tunnel status and history change
/// (stopped by `backend.shutdown`). Without a tunnel the first snapshots stay. The channels are
/// subscribed here, before the caller's first publish: a change in between must not be lost
/// until the next one (a receiver made inside the task would count it as already seen).
pub(super) fn spawn(shared: &Arc<Shared>) {
    let Ok(tunnel) = shared.backend.tunnel() else {
        return;
    };
    let status = tunnel.runtime_status();
    let checks = shared.url_checks.subscribe();
    let tests = shared.speed_tests.subscribe();
    let stop = shared.backend.shutdown.child_token();
    let shared = shared.clone();
    tokio::spawn(follow(status, checks, tests, stop, move || {
        shared.publish()
    }));
}

/// The loop of [`spawn`]: `publish` after every status or history change. A «check all» lands
/// one result per site in a quick run: the pages get at most two pushes a second, each with
/// everything so far.
pub(super) async fn follow(
    mut status: watch::Receiver<TunStatus>,
    mut checks: watch::Receiver<u64>,
    mut tests: watch::Receiver<u64>,
    stop: CancellationToken,
    publish: impl Fn(),
) {
    let mut pace = Pace::live();
    loop {
        let changed = tokio::select! {
            () = stop.cancelled() => return,
            changed = status.changed() => changed,
            changed = checks.changed() => changed,
            changed = tests.changed() => changed,
        };
        if changed.is_err() {
            return;
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = pace.ready() => {}
        }
        status.mark_unchanged();
        checks.mark_unchanged();
        tests.mark_unchanged();
        publish();
    }
}

/// Replaces `slot` when `next` differs (the `send_if_modified` body: equal facts never push).
pub(super) fn replace<T: PartialEq>(slot: &mut T, next: T) -> bool {
    if *slot == next {
        return false;
    }
    *slot = next;
    true
}

/// The Availability page: session flag and the saved checks, newest first.
pub(super) fn availability_state(running: bool, store: &Store<UrlChecks>) -> AvailabilityState {
    let history: Vec<UrlCheck> = store.read(|doc| doc.history.iter().map(url_check).collect());
    AvailabilityState {
        tunnel_running: running,
        history_error: history_error(store, history.is_empty()),
        history,
    }
}

/// The Speed test page: session flag and the saved results, newest first.
pub(super) fn speed_state(running: bool, store: &Store<SpeedTests>) -> SpeedTestState {
    let history: Vec<SpeedResult> =
        store.read(|doc| doc.history.iter().map(speed_result).collect());
    SpeedTestState {
        tunnel_running: running,
        history_error: history_error(store, history.is_empty()),
        history,
    }
}

/// Why the saved history is not what the file held: a read-only store always says so; a file
/// that was set aside as corrupt only until new rows replace the lost ones (the Speed test page
/// shows the note instead of its rows).
fn history_error<T: Document>(store: &Store<T>, empty: bool) -> Option<Msg> {
    match store.mode() {
        Mode::ReadOnly(_) => store.notice(),
        Mode::Writable if empty => store.notice(),
        Mode::Writable => None,
    }
}

/// One saved or fresh check as the page shows it.
pub(super) fn url_check(r: &AvailabilityResult) -> UrlCheck {
    UrlCheck {
        id: r.id.clone(),
        url: r.url.clone(),
        tested_at: r.tested_at,
        tunnel_active: r.tunnel_active,
        protected: r.protected.as_ref().map(path),
        direct: r.direct.as_ref().map(path),
        verdict: verdict(r.verdict),
        recommendation: r.recommendation.msg(),
    }
}

fn verdict(v: AvailabilityVerdict) -> UrlVerdict {
    match v {
        AvailabilityVerdict::WorksBoth => UrlVerdict::WorksBoth,
        AvailabilityVerdict::WorksOnlyWithVpn => UrlVerdict::WorksOnlyWithVpn,
        AvailabilityVerdict::WorksOnlyWithoutVpn => UrlVerdict::WorksOnlyWithoutVpn,
        AvailabilityVerdict::BlockedEverywhere => UrlVerdict::BlockedEverywhere,
        AvailabilityVerdict::AuthRequired => UrlVerdict::AuthRequired,
        AvailabilityVerdict::Unknown => UrlVerdict::Unknown,
    }
}

/// One path; `message` = the probes' sentence on why it failed (`None` when it worked).
fn path(p: &probe::PathReport) -> PathReport {
    PathReport {
        source: match p.source {
            PathSource::Native => UiSource::Native,
            PathSource::DirectInbound => UiSource::DirectInbound,
        },
        measured: p.measured,
        available: p.available,
        geo_blocked: p.geo_blocked,
        total_ms: p.total_ms,
        message: p.summary(),
        dns: p.dns.as_ref().map(|d| DnsStage {
            resolved: d.resolved,
            ips: d.ips.iter().map(ToString::to_string).collect(),
            poisoned: d.poisoned,
            ms: d.ms,
        }),
        tcp: p.tcp.as_ref().map(|t| TcpStage {
            connected: t.connected,
            ms: t.ms,
        }),
        tls: p.tls.as_ref().map(|t| TlsStage {
            ok: t.handshake_ok,
            protocol: t.protocol.clone(),
            cipher: t.cipher.clone(),
            ms: t.ms,
        }),
        http: p.http.as_ref().map(|h| HttpStage {
            status: h.status,
            server: h.server.clone(),
            ms: h.ms,
        }),
        geo: p.geo.as_ref().map(|g| GeoInfo {
            // The page joins both parts with " · "; a part the provider did not give is a dash.
            country: g.country.clone().unwrap_or_else(|| DASH.to_owned()),
            org: g.org.clone().unwrap_or_else(|| DASH.to_owned()),
        }),
    }
}

/// Stands for a value the backend does not know (language-neutral).
const DASH: &str = "—";

/// The routing self-test as the page shows it.
pub(super) fn routing_report(r: &RoutingResult) -> RoutingReport {
    RoutingReport {
        ran_at: r.ran_at,
        verdict: match r.verdict {
            ProbeRouting::Ok => RoutingVerdict::Ok,
            ProbeRouting::Partial => RoutingVerdict::Partial,
            ProbeRouting::Leak => RoutingVerdict::Leak,
            ProbeRouting::TunnelOff => RoutingVerdict::TunnelOff,
            ProbeRouting::Inconclusive => RoutingVerdict::Inconclusive,
        },
        message: r.message.clone(),
        vpn_ip: r.vpn_ip,
        direct_ip: r.direct_ip,
        smart_ru: r.smart_ru.enabled,
        ru_ip: r.smart_ru.ru_host_ip,
    }
}

/// One saved or fresh speed test as the page shows it.
pub(super) fn speed_result(r: &speed::SpeedResult) -> SpeedResult {
    SpeedResult {
        id: r.id.clone(),
        timestamp: r.timestamp,
        download_mbps: r.download_mbps,
        upload_mbps: r.upload_mbps,
        latency_ms: r.latency_ms,
        server_name: r.server_name.clone(),
        profile_used: r.profile_used.clone().unwrap_or_else(|| DASH.to_owned()),
        egress: match r.egress {
            ProbeEgress::Match => Egress::Match,
            ProbeEgress::Changed { seen } => Egress::Changed { seen },
            ProbeEgress::Direct { seen } => Egress::Direct { seen },
            ProbeEgress::NotChecked => Egress::NotChecked,
        },
        plain_http: r.transport_warning == Some(TransportWarning::PlainHttp),
    }
}

/// A progress frame for the page; the probes' `Error` frame has no place there (the failed
/// run's error is the answer).
pub(super) fn speed_progress(p: speed::SpeedProgress) -> Option<SpeedProgress> {
    let phase = match p.phase {
        ProbePhase::Latency => SpeedPhase::Latency,
        ProbePhase::Download => SpeedPhase::Download,
        ProbePhase::Upload => SpeedPhase::Upload,
        ProbePhase::Complete => SpeedPhase::Complete,
        ProbePhase::Error => return None,
    };
    Some(SpeedProgress {
        percent: p.percent.min(100),
        phase,
    })
}
