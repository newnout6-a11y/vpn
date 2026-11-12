//! The start page and the tray over the backend (work package `app-dashboard`): implements
//! `vpnte_ui`'s [`DashboardApi`], [`PanelsApi`] and [`TrayApi`] over [`Backend`] / [`TunnelOps`].
//!
//! One shared [`Hub`] owns the pushed state: a `watch` channel per view, fed by the backend's own
//! subscriptions (lifecycle snapshot, runtime status, IP monitor, traffic, settings, server list,
//! network changes) and by the actions, which publish what they changed before they return. Every
//! view is a pure projection (`project`) of the latest facts, so equal facts never re-render.
//! Nothing here needs elevation: privileged answers (`Permission`) come from the tunnel as they are.
mod actions;
mod feeds;
#[cfg(test)]
mod flows;
mod project;
mod proxies;
#[cfg(test)]
mod tests;
mod traits;

use std::any::Any;
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_automation::autopick::PickStatus;
use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{KillSwitchLevel, Verdict};
use vpnte_core::ops::OpId;
use vpnte_core::settings::RoutingMode;
use vpnte_forensics::traffic::TrafficStats;
use vpnte_probes::ip_monitor::IpEvidence;
use vpnte_profiles::countries::Iso2;
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_tunnel::fsm::{Transition, TunnelSnapshot, TunnelState};
use vpnte_tunnel::lifecycle::KillSwitchView;
use vpnte_ui::dashboard::{DashboardApi, DashboardView};
use vpnte_ui::panels::{PanelsApi, ProxiesView, ServersView};
use vpnte_ui::tray::{TrayApi, TrayState};
use vpnte_view::labels::FirewallStatus;
use vpnte_view::traffic::TrafficSample;

use crate::services::{Backend, TunnelOps};
use crate::svc_auto::{Automation, traffic_exposure};
use crate::svc_proxies::ProxySlots;
use project::{Clock, ConnLocal};

/// The start page's and the tray's API objects as root contexts for `vpnte_ui::launch`:
/// `Rc<dyn DashboardApi>`, `Rc<dyn PanelsApi>`, `Rc<dyn TrayApi>`. Call it inside the tokio
/// runtime, after the tunnel was stored in `backend.tunnel`: it starts the feed tasks (stopped by
/// `backend.shutdown`).
pub fn contexts(backend: &Arc<Backend>, automation: &Automation) -> Vec<Box<dyn Any>> {
    let pick = automation.autopick.get().map(|p| p.status());
    let hub = Hub::new(backend.clone(), pick);
    feeds::spawn(&hub);
    proxies::spawn_feed(&hub);
    vec![
        Box::new(Rc::new(traits::Dashboard(hub.clone())) as Rc<dyn DashboardApi>),
        Box::new(Rc::new(traits::Panels(hub.clone())) as Rc<dyn PanelsApi>),
        Box::new(Rc::new(traits::Tray(hub)) as Rc<dyn TrayApi>),
    ]
}

/// Shared state of the three APIs and the feed tasks.
pub(crate) struct Hub {
    backend: Arc<Backend>,
    /// The tunnel's published state; `None` when the tunnel was not built (a start-order bug:
    /// the views then show settings only and every lane action fails with `tunnelMissing`).
    watches: Option<Watches>,
    /// The external proxy slots the tunnel hosts (`None`: the column stays empty).
    slots: Option<ProxySlots>,
    /// The automatic server choice's status (`None`: not started, the strip stays hidden).
    pick: Option<watch::Receiver<PickStatus>>,
    local: Mutex<Local>,
    dash: watch::Sender<DashboardView>,
    servers: watch::Sender<ServersView>,
    traffic: watch::Sender<TrafficSample>,
    proxies: watch::Sender<ProxiesView>,
    tray: watch::Sender<TrayState>,
    /// Lane calls started here and not finished yet (a cancel waits for them).
    inflight: watch::Sender<u32>,
}

/// Receivers of the tunnel's published state (read with `borrow`, never across an await).
struct Watches {
    tunnel: Arc<dyn TunnelOps>,
    snapshot: watch::Receiver<TunnelSnapshot>,
    status: watch::Receiver<TunStatus>,
    evidence: watch::Receiver<IpEvidence>,
    traffic: watch::Receiver<TrafficStats>,
    /// The paused kill switch and the "another VPN" line.
    kill_switch: watch::Receiver<KillSwitchView>,
}

/// App-side facts the backend does not publish itself.
#[derive(Default)]
struct Local {
    conn: ConnLocal,
    /// Optimistic selection while a `select_server` runs.
    pending_active: Option<String>,
    firewall: FirewallStatus,
    /// The WFP kill switch holds traffic (tray).
    kill_switch: bool,
    /// Sequence of kill-switch read-backs: only the latest one lands.
    firewall_seq: u64,
    /// Summary of the last leak check (cleared by every transition).
    leak: Verdict,
    /// Bumped by every transition: a check that started before it does not land.
    epoch: u64,
    /// Last seen `(state, transition)` of the snapshot.
    phase: Option<(TunnelState, Option<Transition>)>,
    /// Country of an exit address, looked up for that address.
    geo: Option<(IpAddr, Iso2)>,
    /// The lookup in flight and the address it is for.
    geo_job: Option<(IpAddr, CancellationToken)>,
    /// Another VPN's adapter (`name (ip)`), from the last scan.
    foreign: Option<String>,
    /// Warnings of lane calls that ended while a cancel was pending (the cancel's answer).
    cancel_warnings: Vec<Msg>,
    /// Clock anchor of the snapshot's lane operation, taken when it was first seen.
    op_clock: Option<(OpId, Clock)>,
}

impl Local {
    /// The clock that maps the snapshot operation's wall-clock window to `Instant`s. Anchored
    /// once per operation: its window stays equal across projections (no spurious pushes), and a
    /// machine sleep that put the monotonic clock behind the wall clock cannot skew it.
    fn clock_for(&mut self, snap: &TunnelSnapshot) -> Clock {
        let Some(id) = snap.operation.as_ref().map(|op| op.id) else {
            return Clock::now();
        };
        match self.op_clock {
            Some((seen, clock)) if seen == id => clock,
            _ => {
                let clock = Clock::now();
                self.op_clock = Some((id, clock));
                clock
            }
        }
    }
}

/// The settings the start page and the tray show.
struct Prefs {
    soft_mode: bool,
    smart_ru: bool,
    minimize_to_tray: bool,
    lang: Lang,
    kill_switch: KillSwitchLevel,
}

impl Hub {
    fn new(backend: Arc<Backend>, pick: Option<watch::Receiver<PickStatus>>) -> Arc<Self> {
        let watches = match backend.tunnel() {
            Ok(tunnel) => Some(Watches {
                tunnel: tunnel.clone(),
                snapshot: tunnel.snapshot(),
                status: tunnel.runtime_status(),
                evidence: tunnel.ip_evidence(),
                traffic: tunnel.traffic(),
                kill_switch: tunnel.kill_switch_view(),
            }),
            Err(err) => {
                tracing::error!(%err, "start page built without a tunnel");
                None
            }
        };
        let mut local = Local::default();
        if watches.is_none() {
            // No read-back will ever come: not «Проверяем» forever.
            local.firewall = FirewallStatus {
                state: vpnte_view::labels::FwState::Unknown,
                checking: false,
            };
        }
        let hub = Arc::new(Self {
            slots: watches.as_ref().and_then(|w| w.tunnel.proxies()),
            pick,
            backend,
            watches,
            local: Mutex::new(local),
            dash: watch::Sender::new(DashboardView::default()),
            servers: watch::Sender::new(ServersView::default()),
            traffic: watch::Sender::new(TrafficSample::default()),
            proxies: watch::Sender::new(ProxiesView::default()),
            tray: watch::Sender::new(TrayState::default()),
            inflight: watch::Sender::new(0),
        });
        hub.publish_all();
        hub.publish_traffic();
        hub.publish_proxies();
        hub
    }

    fn prefs(&self) -> Prefs {
        self.backend.settings.read(|s| Prefs {
            soft_mode: s.routing_mode == RoutingMode::Soft,
            smart_ru: s.smart_ru_split,
            minimize_to_tray: s.minimize_to_tray,
            lang: s.locale.unwrap_or_else(vpnte_ui::lang::os_lang),
            kill_switch: s.kill_switch,
        })
    }

    /// Publishes the start page, the servers panel and the tray from the latest facts.
    fn publish_all(&self) {
        self.publish_dashboard();
        self.publish_servers();
        self.publish_tray();
    }

    fn publish_dashboard(&self) {
        let prefs = self.prefs();
        let mut local = self.local.lock();
        let view = match &self.watches {
            Some(w) => {
                let snap = w.snapshot.borrow();
                let clock = local.clock_for(&snap);
                let status = w.status.borrow();
                // What traffic does is read from the live state on every projection (never a
                // claim stored with the automatic choice's step).
                let proxy = (status.capture).map_or(prefs.soft_mode, |c| c == CaptureKind::Proxy);
                let exposure = traffic_exposure(snap.state, proxy, prefs.kill_switch);
                let autopick =
                    (self.pick.as_ref()).and_then(|p| project::pick_line(&p.borrow(), exposure));
                let conn = project::conn_view(&snap, &status, &local.conn, &clock);
                let (exit, exit_country) =
                    project::exit_ip(&snap, &w.evidence.borrow(), local.geo, prefs.lang);
                let kill_switch = w.kill_switch.borrow();
                DashboardView {
                    foreign_vpn: project::foreign_vpn(&conn, local.foreign.as_deref()),
                    engine: project::engine_line(&status),
                    conn,
                    exit,
                    exit_country,
                    firewall: local.firewall,
                    leak: local.leak,
                    soft_mode: prefs.soft_mode,
                    smart_ru: prefs.smart_ru,
                    autopick,
                    pause: project::pause_line(&kill_switch),
                    no_pause_vpn: kill_switch.foreign_vpn.clone(),
                }
            }
            None => DashboardView {
                firewall: local.firewall,
                leak: local.leak,
                soft_mode: prefs.soft_mode,
                smart_ru: prefs.smart_ru,
                ..DashboardView::default()
            },
        };
        drop(local);
        set(&self.dash, view);
    }

    fn publish_servers(&self) {
        let list = self.backend.servers.view();
        let local = self.local.lock();
        let (tun_running, transition) = self.watches.as_ref().map_or((false, false), |w| {
            let snap = w.snapshot.borrow();
            (project::tun_running(&snap), snap.transition.is_some())
        });
        let view = ServersView {
            rows: project::server_rows(&list.servers),
            active_id: local
                .pending_active
                .clone()
                .or_else(|| list.active.map(|id| id.0)),
            tun_running,
            locked: transition
                || local.conn.cancelling
                || local.conn.switching.is_some()
                || local.pending_active.is_some(),
        };
        drop(local);
        set(&self.servers, view);
    }

    fn publish_traffic(&self) {
        if let Some(w) = &self.watches {
            let sample = project::traffic_sample(&w.traffic.borrow());
            set(&self.traffic, sample);
        }
    }

    fn publish_tray(&self) {
        let Some(w) = &self.watches else {
            return;
        };
        let prefs = self.prefs();
        let mut local = self.local.lock();
        let snap = w.snapshot.borrow();
        let status = w.status.borrow();
        let clock = local.clock_for(&snap);
        let conn = project::conn_view(&snap, &status, &local.conn, &clock);
        let mut state = project::tray_state(
            &snap,
            &status,
            &w.evidence.borrow(),
            &conn,
            local.kill_switch,
            &w.traffic.borrow(),
            prefs.minimize_to_tray,
        );
        state.paused = w.kill_switch.borrow().pause.is_some();
        drop((snap, status, local));
        set(&self.tray, state);
    }
}

/// Sends `next` only when it differs from the published value (equal facts never re-render).
fn set<T: PartialEq>(tx: &watch::Sender<T>, next: T) {
    tx.send_if_modified(|cur| {
        if *cur == next {
            return false;
        }
        *cur = next;
        true
    });
}
