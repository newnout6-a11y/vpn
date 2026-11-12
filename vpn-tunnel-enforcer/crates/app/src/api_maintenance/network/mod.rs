//! «Режим сети» over the backend (RU audit items 9 and 11): the network-mode check with the DNS
//! canary, published in the page snapshot (the start page's banner reads it too); what it proves
//! about UDP goes to the reactions' network memory, never as a verdict about a server. The check
//! also runs on its own after start and after every change of the physical network (the
//! resolver memory learns per network from the same change). A result never outlives the
//! network it describes: a change drops the check in flight, and a result is published only
//! while the network it began on is still the current one.
mod auto;

use std::future::Future;
use std::net::SocketAddr;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::adaptive::identity;
use vpnte_automation::adaptive::reaction::Verdicts;
use vpnte_base::types::{Creds, Loopback, Verdict};
use vpnte_base::{AppError, AppResult};
use vpnte_core::net::is_public_ip;
use vpnte_core::resolve;
use vpnte_probes::netmode::{
    self, Canary, Facts, LiveProbe, Mode, NetProbe, NetReport, StepKind, StepStatus, Summary,
    UdpEvidence, WireLookup, dns_canary,
};
use vpnte_probes::ping::{PingTarget, is_loopback_host};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::maintenance::{MaintenanceState, NetCheckView, NetStepKind, NetStepView};
use vpnte_view::netmode::NetMode;

pub(crate) use auto::{network_key_now, spawn};

use super::{Shared, refused};

/// One check at a time (the button and the automatic runs): the flag lives in the snapshot,
/// so the page shows it, and is cleared however the run ends.
pub(super) struct Flight<'a>(&'a watch::Sender<MaintenanceState>);

impl<'a> Flight<'a> {
    pub(super) fn begin(state: &'a watch::Sender<MaintenanceState>) -> AppResult<Self> {
        let mut started = false;
        state.send_if_modified(|s| {
            started = !s.network.running;
            s.network.running = true;
            started
        });
        if started {
            Ok(Flight(state))
        } else {
            Err(refused("app.maintenance.network.busy"))
        }
    }

    /// Waits until no check runs, then begins one: the automatic runs queue behind the button's
    /// instead of being refused. `None` when `cancel` fires first.
    pub(super) async fn queued(
        state: &'a watch::Sender<MaintenanceState>,
        cancel: &CancellationToken,
    ) -> Option<Self> {
        let mut rx = state.subscribe();
        loop {
            if let Ok(flight) = Self::begin(state) {
                return Some(flight);
            }
            // The snapshot's read guard ends inside the block: `begin` takes the write lock.
            let idle = async { rx.wait_for(|s| !s.network.running).await.map(|_| ()) };
            tokio::select! {
                () = cancel.cancelled() => return None,
                idle = idle => idle.ok()?,
            }
        }
    }
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.0.send_modify(|s| s.network.running = false);
    }
}

/// The current physical network's token: a change cancels it, which drops the check in flight
/// (its result would describe the network that is gone).
#[derive(Default)]
pub(crate) struct NetEpoch(Mutex<CancellationToken>);

impl NetEpoch {
    pub(super) fn current(&self) -> CancellationToken {
        self.0.lock().clone()
    }

    fn advance(&self) {
        std::mem::take(&mut *self.0.lock()).cancel();
    }
}

/// The physical network changed: the check in flight is dropped and the old verdict goes (the
/// banner disappears until a check of the new network finishes).
pub(super) fn network_changed(epoch: &NetEpoch, state: &watch::Sender<MaintenanceState>) {
    epoch.advance();
    state.send_modify(|s| s.network.last = None);
}

/// What a run probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope {
    /// The button: also the selected server's address-ban check, which the user asked for.
    Button,
    /// After start and after a network change: the network only. The user's server is never
    /// looked up or sent a packet from the real address unasked.
    Automatic,
}

/// Runs the check now (the button), publishes and feeds its result.
pub(crate) async fn check(shared: &Shared, cancel: CancellationToken) -> AppResult<NetCheckView> {
    let flight = Flight::begin(&shared.state)?;
    run(shared, flight, Scope::Button, cancel).await
}

fn changed() -> AppError {
    refused("app.maintenance.network.changed")
}

async fn run(
    shared: &Shared,
    _flight: Flight<'_>,
    scope: Scope,
    cancel: CancellationToken,
) -> AppResult<NetCheckView> {
    let epoch = shared.epoch.current();
    let measured = async {
        let network = identity::read().await;
        let status = shared.backend.tunnel()?.runtime_status().borrow().clone();
        let capture = status.running.then_some(status.capture).flatten();
        let own_tun = status.session.as_ref().and_then(|s| s.tun_luid);
        let probe = LiveProbe::new(direct_out(&status), own_tun).await?;
        let facts = measure(&probe, scope, || server_address(shared), &cancel).await?;
        let canary = match capture {
            Some(CaptureKind::Tun) => Some(dns_canary(&WireLookup).await),
            // Proxy mode takes no DNS: say so, never run a check that could read as protection.
            Some(CaptureKind::Proxy) => Some(Canary::NotCaptured),
            None => None,
        };
        // The watch sees a change only after its debounce: compare the network itself.
        if identity::read().await != network {
            return Err(changed());
        }
        Ok((netmode::report(&facts, probe.via_session()), canary))
    };
    let (report, canary) = tokio::select! {
        biased;
        () = epoch.cancelled() => return Err(changed()),
        measured = measured => measured?,
    };
    if cancel.is_cancelled() {
        return Err(AppError::cancelled());
    }
    publish(
        &shared.state,
        shared.verdicts.as_deref(),
        &epoch,
        &report,
        canary,
    )
}

/// The facts of one run. The button also tests the selected server for an address ban
/// (`server` resolves it); the automatic runs never call `server`, so its name is never looked
/// up and the server never gets a packet from the real address the user did not ask for.
pub(super) async fn measure<P, F>(
    probe: &P,
    scope: Scope,
    server: impl FnOnce() -> F,
    cancel: &CancellationToken,
) -> AppResult<Facts>
where
    P: NetProbe,
    F: Future<Output = Vec<SocketAddr>>,
{
    let servers = match scope {
        Scope::Button => server().await,
        Scope::Automatic => Vec::new(),
    };
    netmode::gather(probe, &servers, cancel).await
}

/// The selected server's address, when it speaks TCP (a UDP-only server would read as banned:
/// nothing listens on its TCP port by design). The name goes through the DoH chain as a
/// connect's does (`resolve_server`), never first through the plaintext system resolver, and
/// only public addresses count (a forged or local answer is no server to judge).
async fn server_address(shared: &Shared) -> Vec<SocketAddr> {
    let Some(active) = shared.backend.servers.active() else {
        return Vec::new();
    };
    let Ok(profile) = active.row.profile() else {
        return Vec::new();
    };
    let target = PingTarget::of(&profile);
    if target.udp_only || is_loopback_host(&target.host) {
        return Vec::new();
    }
    match resolve::resolve_server(&target.host, is_public_ip).await {
        Ok(found) => found
            .addrs
            .first()
            .map(|ip| vec![SocketAddr::new(*ip, target.port)])
            .unwrap_or_default(),
        Err(err) => {
            tracing::debug!(error = %err, "server address for the ban check not found");
            Vec::new()
        }
    }
}

/// The running TUN session's `mixed-direct-in`: the probes leave through it, never through the
/// tunnel (our own executable's sockets would enter the TUN). Soft and idle: direct.
pub(super) fn direct_out(status: &TunStatus) -> Option<Loopback> {
    let session = status.session.as_ref()?;
    (status.running && status.capture == Some(CaptureKind::Tun)).then(|| Loopback {
        port: session.direct.port,
        creds: Some(Creds {
            user: session.direct.user.clone(),
            pass: session.direct.pass.clone(),
        }),
    })
}

/// Publishes `report` and feeds what it proved about UDP, unless the network changed since
/// `epoch` was taken. Checked under the snapshot's lock: a change's clearing of `last` can
/// never be overwritten by the old network's result.
pub(super) fn publish(
    state: &watch::Sender<MaintenanceState>,
    verdicts: Option<&Verdicts>,
    epoch: &CancellationToken,
    report: &NetReport,
    canary: Option<Canary>,
) -> AppResult<NetCheckView> {
    let view = view(report, canary);
    let mut current = false;
    state.send_if_modified(|s| {
        current = !epoch.is_cancelled();
        if current {
            s.network.last = Some(view.clone());
        }
        current
    });
    if !current {
        return Err(changed());
    }
    if let Some(verdicts) = verdicts {
        feed(verdicts, report.udp);
    }
    Ok(view)
}

/// The network memory learns what the probes proved about UDP here: dropped puts TCP profiles
/// first in automatic picks, an answer lifts that mark, no proof leaves it. Never a report about
/// a server: a running session is switched only by its own server's checks.
pub(super) fn feed(verdicts: &Verdicts, udp: UdpEvidence) {
    match udp {
        UdpEvidence::Dropped => verdicts.network_udp(true),
        UdpEvidence::Passes => verdicts.network_udp(false),
        UdpEvidence::Unclear => {}
    }
}

/// The page's form of a report (and of the canary, when it ran).
pub(super) fn view(report: &NetReport, canary: Option<Canary>) -> NetCheckView {
    let mut steps: Vec<NetStepView> = report
        .steps
        .iter()
        .map(|s| NetStepView {
            kind: step_kind(s.kind),
            verdict: verdict(s.status),
            detail: s.detail.clone(),
        })
        .collect();
    steps.extend(canary.map(|c| NetStepView {
        kind: NetStepKind::DnsCapture,
        verdict: c.verdict(),
        detail: c.msg(),
    }));
    NetCheckView {
        at: report.at,
        via_session: report.via_session,
        verdict: overall(report.summary),
        steps,
        modes: report.modes.iter().map(|m| net_mode(*m)).collect(),
        headline: report.headline(),
        advice: report.modes.iter().map(|m| m.advice()).collect(),
    }
}

/// The result's colour: only a clean pass is a pass; no internet is a failure, and a check that
/// proved nothing either way is "not verified", never the success colour.
fn overall(summary: Summary) -> Verdict {
    match summary {
        Summary::Open => Verdict::Ok,
        Summary::Restricted => Verdict::Warn,
        Summary::Offline => Verdict::Fail,
        Summary::NotVerified => Verdict::NotChecked,
    }
}

fn step_kind(kind: StepKind) -> NetStepKind {
    match kind {
        StepKind::Dns => NetStepKind::Dns,
        StepKind::Tcp => NetStepKind::Tcp,
        StepKind::Tls => NetStepKind::Tls,
        StepKind::Bytes => NetStepKind::Bytes,
        StepKind::Udp => NetStepKind::Udp,
        StepKind::Servers => NetStepKind::Servers,
    }
}

fn verdict(status: StepStatus) -> Verdict {
    match status {
        StepStatus::Ok => Verdict::Ok,
        StepStatus::Warn => Verdict::Warn,
        StepStatus::Fail => Verdict::Fail,
        StepStatus::NotRun => Verdict::NotChecked,
    }
}

fn net_mode(mode: Mode) -> NetMode {
    match mode {
        Mode::Whitelist => NetMode::Whitelist,
        Mode::UdpBlocked => NetMode::UdpBlocked,
        Mode::DohBlocked => NetMode::DohBlocked,
        Mode::ServerBlocked => NetMode::ServerBlocked,
        Mode::Freeze => NetMode::Freeze,
    }
}
