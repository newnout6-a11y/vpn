//! Pure projections of the backend's published state into the start page's and the tray's view
//! models. No I/O, no clock reads: callers pass every fact (unit-tested in `tests.rs`).
use std::net::IpAddr;
use std::time::Instant;

use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, ProxyKind, UnixMs, Verdict};
use vpnte_core::net::{HostPort, Route};
use vpnte_core::ops::OpStatus;
use vpnte_core::settings::Settings;
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::geo::geo_routes;
use vpnte_probes::ip_monitor::{IpEvidence, IpVerdict};
use vpnte_probes::leak::{CheckReport, CheckStatus};
use vpnte_profiles::countries::{self, Iso2};
use vpnte_servers::model::ServerSummary;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::{self, Health, ProcessState, TunnelMode, TunnelSnapshot};
use vpnte_tunnel::lifecycle::KillSwitchView;
use vpnte_tunnel::runtime::MAX_RESTARTS;
use vpnte_ui::dashboard::{EngineLine, PauseLine, PickLine};
use vpnte_ui::panels::ServerRowView;
use vpnte_ui::tray;
use vpnte_view::identity::{ExitIp, Geo, ServerHealth};
use vpnte_view::labels::{FirewallStatus, FwState};
use vpnte_view::swiss::{self, ConnView, OpWindow};
use vpnte_view::traffic::TrafficSample;
use vpnte_winnet::wfp::KillSwitchState;

use crate::services::KillSwitchStatus;

/// A fixed pair of clocks: turns the snapshot's wall-clock times into `Instant`s the same way on
/// every projection, so an unchanged snapshot projects to an equal view (no spurious pushes).
#[derive(Debug, Clone, Copy)]
pub(super) struct Clock {
    pub at: Instant,
    pub wall: UnixMs,
}

impl Clock {
    /// Now.
    pub fn now() -> Self {
        Self {
            at: Instant::now(),
            wall: vpnte_base::types::now_ms(),
        }
    }

    /// The `Instant` of wall-clock time `ms` (clamped to the representable range).
    pub fn instant(&self, ms: UnixMs) -> Instant {
        let delta = std::time::Duration::from_millis(ms.abs_diff(self.wall));
        if ms >= self.wall {
            self.at.checked_add(delta).unwrap_or(self.at)
        } else {
            self.at.checked_sub(delta).unwrap_or(self.at)
        }
    }
}

/// App-side facts of the connection that the lifecycle does not publish.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ConnLocal {
    /// The user asked to cancel; held until the cancelled operation is over.
    pub cancelling: bool,
    /// Target name of a server switch started from the start page.
    pub switching: Option<String>,
}

/// The connection as the start page renders it: the lifecycle snapshot, the runtime's restart
/// attempt and the app-side cancel / switch facts.
pub(super) fn conn_view(
    snap: &TunnelSnapshot,
    status: &TunStatus,
    local: &ConnLocal,
    clock: &Clock,
) -> ConnView {
    let lane_op = snap
        .operation
        .as_ref()
        .filter(|op| op.status == OpStatus::Running);
    // A crash restart is a reconnect that no lane operation started (a switch or a settings
    // restart runs as an operation); the attempt counter alone stays set until the run is stable.
    let restarting = (snap.transition == Some(fsm::Transition::Reconnecting)
        && lane_op.is_none()
        && status.restart_attempt > 0)
        .then_some((status.restart_attempt, MAX_RESTARTS));
    ConnView {
        state: match snap.state {
            fsm::TunnelState::Disconnected => swiss::TunnelState::Disconnected,
            fsm::TunnelState::Connected => swiss::TunnelState::Connected,
            fsm::TunnelState::Error => swiss::TunnelState::Error,
            fsm::TunnelState::Blocked => swiss::TunnelState::Blocked,
            fsm::TunnelState::Unknown => swiss::TunnelState::Unknown,
        },
        transition: snap.transition.map(|t| match t {
            fsm::Transition::Connecting => swiss::Transition::Connecting,
            fsm::Transition::Disconnecting => swiss::Transition::Disconnecting,
            fsm::Transition::Reconnecting => swiss::Transition::Reconnecting,
        }),
        mode: snap.mode.map(|m| match m {
            TunnelMode::Tun => swiss::Mode::Tun,
            TunnelMode::Soft => swiss::Mode::Soft,
        }),
        cancelling: local.cancelling,
        switching: local.switching.clone(),
        restarting,
        degraded: snap.health == Some(Health::Degraded),
        competing_tun: snap.competing_tun.clone(),
        proxy_down: snap.proxy_status == fsm::ProxyStatus::ProxyDown,
        cleanup_required: snap.cleanup_required,
        started_at: snap.started_at,
        operation: lane_op.map(|op| OpWindow {
            started: clock.instant(op.started_at),
            deadline: op.deadline.map(|d| clock.instant(d)),
        }),
    }
}

/// A connect in flight proves its exit (lab F-4): the runtime runs the session's engine but has
/// not published the session (nothing is claimed before traffic went through the server).
pub(super) fn proving_exit(snap: &TunnelSnapshot, status: &TunStatus) -> bool {
    snap.transition == Some(fsm::Transition::Connecting)
        && status.engine.is_some()
        && !status.running
}

/// Settled off: no session, nothing in flight (the IP monitor then keeps only stale samples).
pub(super) fn settled_off(snap: &TunnelSnapshot) -> bool {
    snap.state == fsm::TunnelState::Disconnected && snap.transition.is_none()
}

/// Our TUN capture is up and settled (the old `tunRunning`).
pub(super) fn tun_running(snap: &TunnelSnapshot) -> bool {
    snap.state == fsm::TunnelState::Connected
        && snap.transition.is_none()
        && snap.mode == Some(TunnelMode::Tun)
}

/// Another VPN's adapter, shown only while our TUN is not up: its adapter answers every ping
/// locally, and while ours runs the competing-TUN banner speaks instead.
pub(super) fn foreign_vpn(conn: &ConnView, found: Option<&str>) -> Option<String> {
    found.filter(|_| !conn.tun_running()).map(str::to_owned)
}

/// The paused kill switch's line (ks-a): the next automatic attempt and the key reason.
pub(super) fn pause_line(view: &KillSwitchView) -> Option<PauseLine> {
    view.pause.as_ref().map(|p| PauseLine {
        next_attempt: p.next_attempt,
        manual: p.manual,
        key_rejected: p.key_rejected,
    })
}

/// The engine of the running session and why it was chosen, for the identity column (nothing
/// while no engine runs: the caption never outlives the session).
pub(super) fn engine_line(status: &TunStatus) -> Option<EngineLine> {
    let run = status.engine.filter(|_| status.running)?;
    Some(EngineLine {
        engine: run.kind,
        reason: run.reason.map(|reason| reason.msg()),
    })
}

/// The exit address from the IP monitor, plus the country of `geo` when it was looked up for
/// this very address. Settled off, the monitor's last sample is the previous session's exit:
/// the public address is then the home address it measured before that connect.
pub(super) fn exit_ip(
    snap: &TunnelSnapshot,
    ev: &IpEvidence,
    geo: Option<(IpAddr, Iso2)>,
    lang: Lang,
) -> (ExitIp, Option<String>) {
    if settled_off(snap) {
        let exit = ExitIp {
            ip: ev.real_ip,
            ..ExitIp::default()
        };
        return (exit, None);
    }
    let ip = ev.last.map(|s| s.ip);
    let geo = geo.filter(|(at, _)| Some(*at) == ip);
    let exit = ExitIp {
        ip,
        vpn_ip: ev.baseline,
        verdict: ev.verdict.verdict(),
        leak: ev.verdict == IpVerdict::Failed,
        geo: geo.map(|(at, code)| {
            let country = Some(countries::name(code, lang).to_owned());
            (
                at,
                Geo {
                    country,
                    city: None,
                },
            )
        }),
    };
    (exit, geo.map(|(_, code)| code.as_str().to_owned()))
}

/// The exit equals the address measured without our VPN while another VPN works on this PC
/// (p-live2, the owner's Happ on the same provider): the address check proves nothing then, so the
/// page says so in one calm line instead of a leak. Without another VPN in sight the same match
/// stays a leak, and the leak self-test keeps its own verdict either way.
pub(super) fn other_vpn_exit(snap: &TunnelSnapshot, ev: &IpEvidence, other_vpn: bool) -> bool {
    let settled_on = snap.state == fsm::TunnelState::Connected && snap.transition.is_none();
    let same = ev.real_ip.is_some() && ev.last.map(|s| s.ip) == ev.real_ip;
    other_vpn && settled_on && same
}

/// `exit` as the page shows it when [`other_vpn_exit`]: not checked, never a leak.
pub(super) fn calm_exit(exit: ExitIp) -> ExitIp {
    ExitIp {
        leak: false,
        verdict: Verdict::Warn,
        ..exit
    }
}

/// The exit address worth a country lookup: a passed check of the adopted exit of our running,
/// settled session, never while a leak shows (the lookup must not geolocate the user's real
/// address).
pub(super) fn geo_target(snap: &TunnelSnapshot, ev: &IpEvidence) -> Option<IpAddr> {
    let ip = ev.last.map(|s| s.ip)?;
    let settled_on = snap.state == fsm::TunnelState::Connected && snap.transition.is_none();
    (settled_on && ev.verdict == IpVerdict::Passed && ev.baseline == Some(ip)).then_some(ip)
}

/// Where the exit's lookup leaves: under the TUN the configured geo routes (they ride it);
/// under the proxy capture only the session's mixed inbound, because the app's requests never
/// take the system proxy and the physical route would tie the user's own address to the exit.
pub(super) fn geo_route(
    snap: &TunnelSnapshot,
    status: &TunStatus,
    settings: &Settings,
) -> Option<Vec<Route>> {
    match snap.mode? {
        TunnelMode::Tun => Some(geo_routes(settings, true)),
        TunnelMode::Soft => {
            let port = status.session.as_ref()?.proxy_port?;
            let addr = HostPort::new("127.0.0.1", port).ok()?;
            Some(vec![Route::proxy(ProxyKind::Socks5, &addr, None)])
        }
    }
}

/// The kill-switch fact from a read-back. Without WFP here or in the helper service nothing of
/// ours can be installed, so the saved level decides what can hold: off reads «Снят», "If the
/// VPN drops" is the proxy mode's system-proxy hold «Через прокси» (never «Держит»: it cannot
/// be read back); the view turns the hold into «Нужна служба-помощник» in Hard mode
/// (`FirewallStatus::in_mode`). A stored "Always" reads «Нужна служба-помощник» in both modes
/// (fix-ks a6): it is not in force, and the persistent filters an earlier elevated run left
/// keep blocking until the service (or one elevated start) removes them.
pub(super) fn firewall(ks: &KillSwitchStatus) -> FirewallStatus {
    let state = match &ks.wfp {
        None => match ks.settings.level {
            KillSwitchLevel::Off => FwState::Inactive,
            KillSwitchLevel::Standard => FwState::ProxyHold,
            KillSwitchLevel::Strict => FwState::NeedsAdmin,
        },
        Some(status) => match status.kill_switch {
            KillSwitchState::Off | KillSwitchState::Armed => FwState::Inactive,
            KillSwitchState::Engaged | KillSwitchState::Blocking if status.last_error.is_none() => {
                FwState::Verified
            }
            _ => FwState::Unknown,
        },
    };
    FirewallStatus {
        state,
        checking: false,
    }
}

/// The WFP kill switch currently holds traffic (tray «Kill-switch»).
pub(super) fn kill_switch_engaged(ks: &KillSwitchStatus) -> bool {
    ks.wfp.as_ref().is_some_and(|s| {
        matches!(
            s.kill_switch,
            KillSwitchState::Engaged | KillSwitchState::Blocking
        )
    })
}

/// The leak fact's verdict of a finished check (`Info`-only cards have none).
pub(super) fn leak_verdict(report: &CheckReport) -> Verdict {
    report.summary.verdict().unwrap_or(Verdict::NotChecked)
}

/// A severity for the tray's check result notice.
pub(super) fn check_level(summary: CheckStatus) -> vpnte_base::types::Level {
    use vpnte_base::types::Level;
    match summary {
        CheckStatus::Ok => Level::Success,
        CheckStatus::Warn => Level::Warn,
        CheckStatus::Fail => Level::Error,
        CheckStatus::Info | CheckStatus::NotChecked => Level::Info,
    }
}

/// One traffic sample as the panel draws it (bytes per second, once a second).
pub(super) fn traffic_sample(s: &TrafficStats) -> TrafficSample {
    TrafficSample {
        ts: s.ts_ms,
        running: s.running,
        download_bps: s.down_bps,
        upload_bps: s.up_bps,
        smoothed_download_bps: s.smooth_down_bps,
        smoothed_upload_bps: s.smooth_up_bps,
        session_download_bytes: s.session_down,
        started_at: s.started_at_ms,
    }
}

/// The servers panel's rows: archived servers (removed by the user or from their subscription)
/// are left out.
pub(super) fn server_rows(servers: &[ServerSummary]) -> Vec<ServerRowView> {
    servers
        .iter()
        .filter(|s| s.archived.is_none())
        .map(|s| ServerRowView {
            id: s.id.as_str().to_owned(),
            name: s.name.clone(),
            country: s.country.map(|c| c.as_str().to_owned()),
            protocol: Some(s.protocol.clone()).filter(|p| !p.is_empty()),
            ping: s.ping.and_then(|p| p.rtt_ms),
            health_latency: s.health.and_then(|h| h.rtt_ms),
            health: match s.health {
                Some(h) if h.online => ServerHealth::Online,
                Some(_) => ServerHealth::Offline,
                None => ServerHealth::Unknown,
            },
            checked_at: s.health.map(|h| h.at),
        })
        .collect()
}

/// What the tray shows; its status, menu and enable rules are `vpnte_ui::tray`'s
/// (`TrayStatus::of`, `TrayModel::build`) over these facts.
pub(super) fn tray_state(
    snap: &TunnelSnapshot,
    status: &TunStatus,
    ev: &IpEvidence,
    conn: &ConnView,
    kill_switch: bool,
    traffic: &TrafficStats,
    minimize_to_tray: bool,
) -> tray::TrayState {
    let settled_on = snap.state == fsm::TunnelState::Connected && snap.transition.is_none();
    let sample = traffic_sample(traffic);
    let running = traffic.running;
    tray::TrayState {
        tunnel: match snap.state {
            fsm::TunnelState::Disconnected => tray::TunnelState::Disconnected,
            fsm::TunnelState::Connected => tray::TunnelState::Connected,
            fsm::TunnelState::Error => tray::TunnelState::Error,
            fsm::TunnelState::Blocked => tray::TunnelState::Blocked,
            fsm::TunnelState::Unknown => tray::TunnelState::Unknown,
        },
        transition: snap.transition.map(|t| match t {
            fsm::Transition::Connecting => tray::Transition::Connecting,
            fsm::Transition::Disconnecting => tray::Transition::Disconnecting,
            fsm::Transition::Reconnecting => tray::Transition::Reconnecting,
        }),
        degraded: snap.health == Some(Health::Degraded),
        proxy: match snap.proxy_status {
            fsm::ProxyStatus::Running => tray::ProxyStatus::Running,
            fsm::ProxyStatus::ProxyDown => tray::ProxyStatus::ProxyDown,
            fsm::ProxyStatus::Stopped => tray::ProxyStatus::Stopped,
        },
        engine_running: snap.process_state == ProcessState::Running,
        leak: ev.verdict == IpVerdict::Failed,
        kill_switch,
        restart: conn
            .restarting
            .map(|(n, max)| (u32::from(n), u32::from(max))),
        public_ip: ev
            .last
            .filter(|_| settled_on && ev.verdict == IpVerdict::Passed)
            .map(|s| s.ip.to_string()),
        proxy_addr: status
            .proxy_addr
            .as_deref()
            .filter(|_| status.running)
            .map(host_port)
            .filter(|a| !a.is_empty()),
        down_bps: if running { rate(sample.down_bps()) } else { 0 },
        up_bps: if running { rate(sample.up_bps()) } else { 0 },
        minimize_to_tray,
        // The lifecycle's pause is a separate watch: the caller fills it in.
        paused: false,
    }
}

/// `host:port` without any `user:pass@` part (the tray never shows credentials).
fn host_port(addr: &str) -> String {
    let addr = addr.split_once("://").map_or(addr, |(_, rest)| rest);
    addr.rsplit_once('@').map_or(addr, |(_, hp)| hp).to_owned()
}

/// A rate in whole bytes per second (negative or non-finite reads as 0).
fn rate(bps: f64) -> u64 {
    if bps.is_finite() && bps > 0.0 {
        bps as u64
    } else {
        0
    }
}

/// The automatic server choice's strip: its step, and what traffic does right now (`exposure`:
/// read from the live state).
pub(super) fn pick_line(
    status: &vpnte_automation::autopick::PickStatus,
    exposure: vpnte_automation::autopick::Exposure,
) -> Option<PickLine> {
    Some(PickLine {
        title: status.headline()?,
        body: status.exposure_line(exposure),
    })
}
